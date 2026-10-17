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
extern int lunport_validate_credential_peer(int fd, int expected_pid, const char *required);
#ifndef LUNPORT_HELPER_REQUIREMENT
#define LUNPORT_HELPER_REQUIREMENT "identifier \"org.homelab.sshelter.credential-helper.v1\""
#endif
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
  OSStatus status = SecKeychainItemCopyAccess(item, &access);
  if (!status) status = SecTrustedApplicationCreateFromPath(helper, &app);
  CFArrayRef acls = status ? NULL : SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
  if (!status && (!acls || !CFArrayGetCount(acls))) status = errSecParam;
  for (CFIndex i = 0; !status && i < CFArrayGetCount(acls); i++) {
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
    CFArrayRef applications = NULL;
    CFStringRef description = NULL;
    SecKeychainPromptSelector selector = 0;
    status = SecACLCopyContents(acl, &applications, &description, &selector);
    if (!status && !applications) status = errSecParam;
    if (!status) {
      CFMutableArrayRef trusted = CFArrayCreateMutableCopy(NULL, 0, applications);
      CFArrayAppendValue(trusted, app);
      status = SecACLSetContents(acl, trusted, description, selector);
      CFRelease(trusted);
    }
    if (applications) CFRelease(applications);
    if (description) CFRelease(description);
  }
  if (!status) status = SecKeychainItemSetAccess(item, access);
  if (acls) CFRelease(acls);
  if (app) CFRelease(app);
  if (access) CFRelease(access);
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
  else printf("client %s: %s passed\n",CLIENT_VERSION,mode);
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
  unsigned char hello[8];
  int greeted = transfer(sockets[0],hello,sizeof(hello),0) && !memcmp(hello,"LPKC0001",8);
  int trusted = greeted && lunport_validate_credential_peer(sockets[0],pid,LUNPORT_HELPER_REQUIREMENT);
  if (!trusted) {
    close(sockets[0]); kill(pid,SIGKILL); waitpid(pid,NULL,0);
    if (!strcmp(mode,"rejected") || !strcmp(mode,"helper-rejected")) {
      printf("client %s: %s passed before sending any request\n",CLIENT_VERSION,mode); return 0;
    }
    fprintf(stderr,"helper authentication failed (hello=%d)\n",greeted); return 79;
  }
  if (!strcmp(mode,"helper-rejected")) { close(sockets[0]); kill(pid,SIGKILL); waitpid(pid,NULL,0); return 80; }
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
