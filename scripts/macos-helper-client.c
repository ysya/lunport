// Disposable macOS CI only. All credential data is a fixed public test value.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef CLIENT_VERSION
#define CLIENT_VERSION "1"
#endif
#ifndef LUNPORT_CREDENTIAL_SERVICE
#define LUNPORT_CREDENTIAL_SERVICE "SSHelter Development"
#endif
static const char fixture[] = "public-immutable-helper-upgrade-fixture";
static int transfer(int fd, void *buffer, size_t length, int writing) {
  unsigned char *cursor = buffer;
  while (length) {
    ssize_t count = writing ? write(fd, cursor, length) : read(fd, cursor, length);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return 0;
    cursor += count; length -= (size_t)count;
  }
  return 1;
}

// Only this disposable fixture writer changes ACLs, to simulate the user's
// one-time Always Allow grant. Production helper code never changes an ACL.
static OSStatus grant(SecKeychainItemRef item, const char *helper) {
  SecAccessRef access = NULL;
  SecTrustedApplicationRef app = NULL;
  SecStaticCodeRef code = NULL;
  CFDictionaryRef info = NULL;
  CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)helper, strlen(helper), false);
  OSStatus status = SecKeychainItemCopyAccess(item, &access);
  if (!status) status = SecTrustedApplicationCreateFromPath(helper, &app);
  if (!status) status = SecStaticCodeCreateWithPath(url, 0, &code);
  if (!status) status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
  CFArrayRef acls = NULL;
  if (!status) status = SecAccessCopyACLList(access, &acls);
  for (CFIndex i = 0; !status && i < CFArrayGetCount(acls); i++) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
    CFArrayRef applications = NULL;
    CFStringRef description = NULL;
    SecKeychainPromptSelector selector = 0;
    status = SecACLCopyContents(acl, &applications, &description, &selector);
    CFArrayRef authorizations = SecACLCopyAuthorizations(acl);
    if (!status && CFArrayContainsValue(authorizations, CFRangeMake(0, CFArrayGetCount(authorizations)), kSecACLAuthorizationPartitionID)) {
      CFDataRef hash = CFDictionaryGetValue(info, kSecCodeInfoUnique);
      char text[128] = "cdhash:";
      for (CFIndex j = 0; j < CFDataGetLength(hash); j++) snprintf(text + 7 + 2*j, 3, "%02x", CFDataGetBytePtr(hash)[j]);
      CFStringRef partition = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
      // Preserve the writer's existing partition as well as adding the helper.
      char existing[4096];
      if (!CFStringGetCString(description, existing, sizeof(existing), kCFStringEncodingUTF8)) return errSecParam;
      size_t n = strlen(existing) / 2;
      UInt8 bytes[2048];
      for (size_t j = 0; j < n; j++) { unsigned value; if (sscanf(existing + 2*j, "%2x", &value) != 1) return errSecParam; bytes[j] = value; }
      CFDataRef encoded = CFDataCreate(NULL, bytes, n);
      CFMutableDictionaryRef plist = (CFMutableDictionaryRef)CFPropertyListCreateWithData(NULL, encoded, kCFPropertyListMutableContainers, NULL, NULL);
      CFRelease(encoded);
      if (!plist) return errSecParam;
      CFMutableArrayRef partitions = (CFMutableArrayRef)CFDictionaryGetValue(plist, CFSTR("Partitions"));
      CFArrayAppendValue(partitions, partition);
      CFDataRef xml = CFPropertyListCreateData(NULL, plist, kCFPropertyListXMLFormat_v1_0, 0, NULL);
      char *hex = calloc(2 * CFDataGetLength(xml) + 1, 1);
      for (CFIndex j = 0; j < CFDataGetLength(xml); j++) snprintf(hex + 2*j, 3, "%02x", CFDataGetBytePtr(xml)[j]);
      CFStringRef replacement = CFStringCreateWithCString(NULL, hex, kCFStringEncodingUTF8);
      status = SecACLSetContents(acl, applications, replacement, selector);
      free(hex); CFRelease(replacement); CFRelease(xml); CFRelease(plist); CFRelease(partition);
    } else if (!status && applications) {
      CFMutableArrayRef trusted = CFArrayCreateMutableCopy(NULL, 0, applications);
      CFArrayAppendValue(trusted, app);
      status = SecACLSetContents(acl, trusted, description, selector);
      CFRelease(trusted);
    }
    if (applications) CFRelease(applications);
    if (description) CFRelease(description);
    if (authorizations) CFRelease(authorizations);
  }
  if (!status) status = SecKeychainItemSetAccess(item, access);
  if (acls) CFRelease(acls);
  if (info) CFRelease(info);
  if (code) CFRelease(code);
  if (app) CFRelease(app);
  if (access) CFRelease(access);
  CFRelease(url);
  return status;
}

static int legacy(const char *mode, const char *helper, const char *account) {
  SecKeychainRef keychain = NULL;
  OSStatus status = SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &keychain);
  if (status) return 81;
  SecKeychainItemRef item = NULL;
  UInt32 length = 0;
  void *data = NULL;
  if (!strcmp(mode, "legacy-create")) {
    CFStringRef a = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFDataRef value = CFDataCreate(NULL, (const UInt8 *)fixture, sizeof(fixture)-1);
    const void *keys[] = {kSecClass,kSecAttrService,kSecAttrAccount,kSecValueData,kSecUseKeychain};
    const void *values[] = {kSecClassGenericPassword,CFSTR(LUNPORT_CREDENTIAL_SERVICE),a,value,keychain};
    CFDictionaryRef attrs = CFDictionaryCreate(NULL,keys,values,5,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    status = SecItemAdd(attrs,NULL);
    CFRelease(attrs); CFRelease(value); CFRelease(a);
  } else {
    int verify = !strcmp(mode,"legacy-verify");
    status = SecKeychainFindGenericPassword(keychain, sizeof(LUNPORT_CREDENTIAL_SERVICE)-1,LUNPORT_CREDENTIAL_SERVICE,
      (UInt32)strlen(account),account,verify?&length:NULL,verify?&data:NULL,&item);
    if (!status && verify && (length != sizeof(fixture)-1 || memcmp(data,fixture,length))) status = errSecDecode;
    if (!status && !strcmp(mode,"legacy-grant")) status = grant(item,helper);
    if (!status && !strcmp(mode,"legacy-delete")) status = SecKeychainItemDelete(item);
  }
  if (item) CFRelease(item);
  if (data) SecKeychainItemFreeContent(NULL,data);
  CFRelease(keychain);
  if (status) fprintf(stderr,"fixture %s: %d\n",mode,(int)status);
  return status ? 82 : 0;
}

int main(int argc, char **argv) {
  if (argc != 4 || !getenv("GITHUB_ACTIONS") || strcmp(getenv("GITHUB_ACTIONS"),"true") ||
      strncmp(argv[3],"lunport-ci-helper-",18)) return 64;
  signal(SIGPIPE,SIG_IGN);
  alarm(25);
  SecKeychainSetUserInteractionAllowed(false);
  const char *mode = argv[1], *helper = argv[2], *account = argv[3];
  if (!strncmp(mode,"legacy-",7)) return legacy(mode,helper,account);
  int sockets[2];
  if (socketpair(AF_UNIX,SOCK_STREAM,0,sockets)) return 70;
  pid_t pid = fork();
  if (pid < 0) return 70;
  if (!pid) {
    close(sockets[0]);
    dup2(sockets[1],STDIN_FILENO); dup2(sockets[1],STDOUT_FILENO);
    close(sockets[1]);
    execl(helper,helper,(char *)NULL);
    _exit(71);
  }
  close(sockets[1]);
  unsigned char header[18] = {'L','P','K','C','0','0','0','1',1,1};
  int writing = !strcmp(mode,"set") || !strcmp(mode,"replace");
  if (writing) header[8] = 2;
  if (!strcmp(mode,"delete")) header[8] = 3;
  if (!strcmp(mode,"contains") || !strcmp(mode,"missing")) header[8] = 4;
  if (!strcmp(mode,"bad-op")) header[8] = 255;
  if (!strcmp(mode,"bad-magic")) header[0] = 'X';
  uint32_t n = htonl((uint32_t)strlen(account)); memcpy(header+10,&n,4);
  n = htonl(writing ? sizeof(fixture)-1 : 0); memcpy(header+14,&n,4);
  if (!strcmp(mode,"oversized")) { n=htonl(1048577); memcpy(header+14,&n,4); }
  transfer(sockets[0],header,!strcmp(mode,"truncated")?5:sizeof(header),1);
  transfer(sockets[0],(void *)account,strlen(account),1);
  if (writing) transfer(sockets[0],(void *)fixture,sizeof(fixture)-1,1);
  shutdown(sockets[0],SHUT_WR);
  uint32_t response[2];
  int received = transfer(sockets[0],response,sizeof(response),0);
  unsigned char output[1024];
  uint32_t length = received ? ntohl(response[1]) : 0;
  if (length > sizeof(output) || (received && !transfer(sockets[0],output,length,0))) return 72;
  close(sockets[0]);
  int exit_status;
  waitpid(pid,&exit_status,0);
  int rejected = !strcmp(mode,"rejected") || !strcmp(mode,"bad-op") || !strcmp(mode,"bad-magic") || !strcmp(mode,"oversized") || !strcmp(mode,"truncated");
  if (rejected) {
    if (received || !WIFEXITED(exit_status) || !WEXITSTATUS(exit_status)) return 73;
  } else {
    if (!received || !WIFEXITED(exit_status) || WEXITSTATUS(exit_status)) return 74;
    OSStatus status = (OSStatus)ntohl(response[0]);
    if (!strcmp(mode,"denied")) {
      if ((status != errSecInteractionNotAllowed && status != errSecAuthFailed) || length) return 75;
    } else if (!strcmp(mode,"missing")) {
      if (status != errSecItemNotFound || length) return 76;
    } else if ((status && !(status == errSecItemNotFound && !strcmp(mode,"delete"))) ||
               (!strcmp(mode,"get") && (length != sizeof(fixture)-1 || memcmp(output,fixture,length)))) {
      fprintf(stderr,"helper operation %s: %d\n",mode,(int)status); return 78;
    }
  }
  printf("client %s: %s passed\n",CLIENT_VERSION,mode);
  return 0;
}
