// Authenticate the executed helper before the App sends an account or secret.
// Checking a path before exec is insufficient: a same-user process can replace
// it between verification and launch. The audit token identifies the live child.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int lunport_validate_credential_peer(int fd, int expected_pid, const char *required) {
  audit_token_t token;
  socklen_t length = sizeof(token);
  uid_t uid;
  gid_t gid;
  if (getpeereid(fd, &uid, &gid) || uid != geteuid() ||
      getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) ||
      length != sizeof(token) || audit_token_to_euid(token) != geteuid() ||
      audit_token_to_pid(token) != expected_pid) return 0;
  CFDataRef audit = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
  const void *keys[] = {kSecGuestAttributeAudit};
  const void *values[] = {audit};
  CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFStringRef text = CFStringCreateWithCString(NULL, required, kCFStringEncodingUTF8);
  SecCodeRef code = NULL;
  SecRequirementRef requirement = NULL;
  int valid = text &&
      SecCodeCopyGuestWithAttributes(NULL, attributes, 0, &code) == errSecSuccess &&
      SecRequirementCreateWithString(text, 0, &requirement) == errSecSuccess &&
      SecCodeCheckValidity(code, kSecCSStrictValidate, requirement) == errSecSuccess;
  if (requirement) CFRelease(requirement);
  if (code) CFRelease(code);
  if (text) CFRelease(text);
  CFRelease(attributes);
  CFRelease(audit);
  return valid;
}
