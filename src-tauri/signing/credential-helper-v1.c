// Frozen protocol-v1 Keychain owner. Ordinary App releases embed the same signed
// executable bytes; rebuilding this helper is a deliberate credential migration.
// No listener, argv secrets, environment configuration, cache or log output.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <arpa/inet.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Overrides are for separately built disposable CI fixtures, never the frozen artifact.
#ifndef LUNPORT_CLIENT_REQUIREMENT
#define LUNPORT_CLIENT_REQUIREMENT "identifier \"org.homelab.sshelter\" and certificate leaf = H\"a346b47b8dccb4faeac8aec1ea997535809aeec9\""
#endif
#ifndef LUNPORT_CREDENTIAL_SERVICE
#define LUNPORT_CREDENTIAL_SERVICE "SSHelter"
#endif

#define MAX_ACCOUNT 4096u
#define MAX_SECRET (1024u * 1024u)
static const unsigned char MAGIC[8] = {'L','P','K','C','0','0','0','1'};

static void clear(void *buffer, size_t length) {
  volatile unsigned char *cursor = buffer;
  while (length--) *cursor++ = 0;
}

static int transfer(int fd, void *buffer, size_t length, int writing) {
  unsigned char *cursor = buffer;
  while (length) {
    ssize_t count = writing ? write(fd, cursor, length) : read(fd, cursor, length);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return 0;
    cursor += count;
    length -= (size_t)count;
  }
  return 1;
}

// Bind authorization to the kernel's audit token, including PID version, rather
// than accepting a claimed PID/path from the request. Only our direct parent may
// use this inherited anonymous socket. It must remain a valid hardened process.
static int authorized_parent(void) {
  audit_token_t token;
  socklen_t length = sizeof(token);
  uid_t uid;
  gid_t gid;
  if (getuid() != geteuid() || getgid() != getegid() ||
      getpeereid(STDIN_FILENO, &uid, &gid) != 0 || uid != geteuid() ||
      getsockopt(STDIN_FILENO, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) != 0 ||
      length != sizeof(token) || audit_token_to_euid(token) != geteuid() ||
      audit_token_to_pid(token) != getppid()) return 0;

  CFDataRef audit = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
  const void *keys[] = { kSecGuestAttributeAudit };
  const void *values[] = { audit };
  CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  SecCodeRef code = NULL;
  SecRequirementRef requirement = NULL;
  CFDictionaryRef info = NULL;
  int valid = 0;
  if (SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code) != errSecSuccess ||
      SecRequirementCreateWithString(CFSTR(LUNPORT_CLIENT_REQUIREMENT), kSecCSDefaultFlags, &requirement) != errSecSuccess ||
      SecCodeCheckValidity(code, kSecCSStrictValidate, requirement) != errSecSuccess ||
      SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSDynamicInformation, &info) != errSecSuccess) goto done;
  uint32_t flags = 0, status = 0;
  CFNumberRef flags_value = CFDictionaryGetValue(info, kSecCodeInfoFlags);
  CFNumberRef status_value = CFDictionaryGetValue(info, kSecCodeInfoStatus);
  if (!flags_value || CFGetTypeID(flags_value) != CFNumberGetTypeID() ||
      !status_value || CFGetTypeID(status_value) != CFNumberGetTypeID() ||
      !CFNumberGetValue(flags_value, kCFNumberSInt32Type, &flags) ||
      !CFNumberGetValue(status_value, kCFNumberSInt32Type, &status) ||
      !(flags & kSecCodeSignatureRuntime) || !(status & kSecCodeStatusValid) ||
      (status & kSecCodeStatusDebugged)) goto done;
  CFDictionaryRef entitlements = CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
  if (entitlements) {
    if (CFGetTypeID(entitlements) != CFDictionaryGetTypeID()) goto done;
    const CFStringRef forbidden[] = {
      CFSTR("com.apple.security.get-task-allow"),
      CFSTR("com.apple.security.cs.disable-library-validation"),
      CFSTR("com.apple.security.cs.allow-dyld-environment-variables"),
      CFSTR("com.apple.security.cs.allow-unsigned-executable-memory")
    };
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
      const void *value = CFDictionaryGetValue(entitlements, forbidden[i]);
      if (value && value != kCFBooleanFalse) goto done;
    }
  }
  valid = 1;
done:
  if (info) CFRelease(info);
  if (requirement) CFRelease(requirement);
  if (code) CFRelease(code);
  CFRelease(attributes);
  CFRelease(audit);
  return valid;
}

static OSStatus find(SecKeychainRef keychain, const char *account, UInt32 account_length,
                     UInt32 *length, void **data, SecKeychainItemRef *item) {
  return SecKeychainFindGenericPassword(keychain, sizeof(LUNPORT_CREDENTIAL_SERVICE) - 1,
      LUNPORT_CREDENTIAL_SERVICE, account_length, account, length, data, item);
}

static OSStatus create(SecKeychainRef keychain, CFStringRef account, const void *data, UInt32 length) {
  CFDataRef secret = CFDataCreate(NULL, data, length);
  const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData, kSecUseKeychain};
  const void *values[] = {kSecClassGenericPassword, CFSTR(LUNPORT_CREDENTIAL_SERVICE), account, secret, keychain};
  CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 5,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  OSStatus status = SecItemAdd(attributes, NULL);
  CFRelease(attributes);
  CFRelease(secret);
  return status;
}

int main(int argc, char **argv) {
  (void)argv;
  signal(SIGPIPE, SIG_IGN);
  alarm(300); // Also terminate if the parent disappears during a system dialog.
  if (argc != 1 || !authorized_parent()) return 77;
  unsigned char header[18]; // magic, operation, flags, account length, data length
  if (!transfer(STDIN_FILENO, header, sizeof(header), 0) || memcmp(header, MAGIC, 8)) return 64;
  uint32_t account_length, input_length;
  memcpy(&account_length, header + 10, 4);
  memcpy(&input_length, header + 14, 4);
  account_length = ntohl(account_length);
  input_length = ntohl(input_length);
  unsigned char operation = header[8], flags = header[9];
  if (operation < 1 || operation > 4 || flags > 1 || !account_length ||
      account_length > MAX_ACCOUNT || input_length > MAX_SECRET ||
      (operation != 2 && input_length)) return 64;
  char *account = calloc(account_length + 1, 1);
  unsigned char *input = calloc(input_length + 1, 1);
  if (!account || !input) { free(account); free(input); return 71; }
  int result = 74;
  CFStringRef account_string = NULL;
  SecKeychainRef keychain = NULL;
  SecKeychainItemRef item = NULL;
  void *output = NULL;
  UInt32 output_length = 0;
  if (!transfer(STDIN_FILENO, account, account_length, 0) ||
      !transfer(STDIN_FILENO, input, input_length, 0)) goto done;
  // Require an exact single frame and no embedded-NUL or invalid UTF-8 account.
  unsigned char trailing;
  if (read(STDIN_FILENO, &trailing, 1) != 0 || memchr(account, 0, account_length)) goto done;
  account_string = CFStringCreateWithBytes(NULL, (UInt8 *)account, account_length, kCFStringEncodingUTF8, false);
  if (!account_string || !authorized_parent()) goto done;
  // This optional flag can only suppress UI, never weaken authorization. Native
  // CI uses it to prove denied migration and upgrade behavior without a prompt.
  if (flags && SecKeychainSetUserInteractionAllowed(false) != errSecSuccess) goto done;
  OSStatus status = SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &keychain);
  if (status == errSecSuccess) {
    status = find(keychain, account, account_length,
        operation == 1 ? &output_length : NULL,
        operation == 1 ? &output : NULL,
        operation == 2 || operation == 3 ? &item : NULL);
    if (operation == 2) {
      if (status == errSecItemNotFound) status = create(keychain, account_string, input, input_length);
      else if (status == errSecSuccess) status = SecKeychainItemModifyAttributesAndData(item, NULL, input_length, input);
    } else if (operation == 3 && status == errSecSuccess) status = SecKeychainItemDelete(item);
  }
  if (output_length > MAX_SECRET || !authorized_parent()) goto done;
  uint32_t response[2] = {htonl((uint32_t)status), htonl(status == errSecSuccess ? output_length : 0)};
  if (!transfer(STDOUT_FILENO, response, sizeof(response), 1) ||
      (status == errSecSuccess && !transfer(STDOUT_FILENO, output, output_length, 1))) goto done;
  result = 0;
done:
  if (output) { clear(output, output_length); SecKeychainItemFreeContent(NULL, output); }
  if (item) CFRelease(item);
  if (keychain) CFRelease(keychain);
  if (account_string) CFRelease(account_string);
  clear(input, input_length);
  free(input);
  free(account);
  return result;
}
