// Frozen protocol-v2 Keychain owner. Ordinary App releases embed the same signed
// executable bytes; rebuilding this helper is a deliberate credential migration.
// No listener, argv secrets, environment configuration, cache or log output.
//
// Wire protocol 2 keeps the framing of protocol 1 byte for byte. Only the 8-byte magic
// carries the new number, so neither helper version accepts a frame meant for the other.
//
//   Channel   The parent passes one end of a connected AF_UNIX stream socketpair as both
//             stdin and stdout and starts the helper with no arguments. The helper checks
//             its parent before writing or reading anything and exits 77 if the check fails.
//   Parent    The kernel audit token of the socket peer must be the direct parent (its pid
//             is getppid()) under this user's effective uid, valid under kSecCSStrictValidate
//             against LUNPORT_CLIENT_REQUIREMENT, with hardened runtime, not debugged, and
//             without an entitlement that permits code injection. The check is repeated
//             after the request has been read and again before the response is written.
//   Hello     helper -> parent: "LPKC0002". The parent then checks the live helper over
//             LOCAL_PEERTOKEN against its pinned requirement (identifier, project certificate
//             leaf, code hashes) and sends nothing to a helper that fails it.
//   Request   parent -> helper, exactly one frame, then the parent shuts down its writing side:
//               magic "LPKC0002" (8) | operation (1) | flags (1) | account length (4)
//               | data length (4) | account (UTF-8, no NUL, 1..4096 bytes) | data
//             Integers are big-endian. flags is 0, or 1 to forbid any authorization UI. Only
//             set carries data (0..1 MiB); every other operation sends a data length of 0.
//   Response  helper -> parent: status (4, Keychain OSStatus) | length (4) | data
//             length is non-zero only for a successful get. The helper then exits 0.
//   Operations on the user's default keychain, service LUNPORT_CREDENTIAL_SERVICE:
//             1 get, 2 set (create, or replace the data of an existing item), 3 delete,
//             4 exists (reads no data), 5 adopt (below). -25300 errSecItemNotFound means
//             there is no such item.
//   Adopt     Moves the one item with this exact account from LUNPORT_ADOPT_SERVICE, where
//             every item saved before this helper existed lives, to LUNPORT_CREDENTIAL_SERVICE:
//             it reads the old item, stores the bytes exactly as set creates an item, reads
//             the new item back and compares, and only then deletes the old item. The secret
//             never leaves this process; the response carries only the status:
//               0                              moved: the new item held the same bytes when
//                                              read back, and the old item is gone
//               -25300 errSecItemNotFound      the old service has no item for this account
//               -128 errSecUserCanceled,       refused: the user, or flags 1, did not allow
//               -25293 errSecAuthFailed,       access to an item
//               -25308 errSecInteractionNotAllowed
//               -25299 errSecDuplicateItem     the new service already holds an item for this
//                                              account that this helper cannot confirm holds
//                                              the same bytes; both items are kept as they are
//               -25302 errSecDataTooLarge      the old item holds more than 1 MiB
//               -67808 errSecVerifyFailed      the new item did not read back identically
//               -50 errSecParam                this build names one service for both sides
//               any other status               failed
//             Adopt never changes or deletes an item under the new service, and it deletes
//             the old item only as its last step, so for every status except 0 the old item
//             is unchanged. A copy this request made stays under the new service if a later
//             step fails; it holds the old item's bytes unless something else saved this
//             account meanwhile. Repeating the request then completes the move over an
//             identical copy, or reports the conflict and keeps both.
//   Exit      0 answered; 64 malformed request; 71 out of memory; 74 I/O failure or the
//             parent failed a later check (no response); 77 parent not authorized (no hello).
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
#define LUNPORT_CLIENT_REQUIREMENT "identifier \"dev.ysya.lunport\" and certificate leaf = H\"66f062921154fb6fe72e7ee0dfe99d7d804efb03\""
#endif
#ifndef LUNPORT_CREDENTIAL_SERVICE
#define LUNPORT_CREDENTIAL_SERVICE "Lunport"
#endif
#ifndef LUNPORT_ADOPT_SERVICE
// frozen-identity: the service of every item saved before 2.0.0, which adopt moves from
#define LUNPORT_ADOPT_SERVICE "SSHelter"
#endif

#define MAX_ACCOUNT 4096u
#define MAX_SECRET (1024u * 1024u)
static const unsigned char MAGIC[8] = {'L','P','K','C','0','0','0','2'};

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

// The same lookup in the service that items saved before this helper live under.
static OSStatus find_adoptable(SecKeychainRef keychain, const char *account, UInt32 account_length,
                               UInt32 *length, void **data, SecKeychainItemRef *item) {
  return SecKeychainFindGenericPassword(keychain, sizeof(LUNPORT_ADOPT_SERVICE) - 1,
      LUNPORT_ADOPT_SERVICE, account_length, account, length, data, item);
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

static int same(const void *a, UInt32 a_length, const void *b, UInt32 b_length) {
  return a_length == b_length && (!a_length || !memcmp(a, b, a_length));
}

// Move one item under its exact account from the old service to ours (protocol notes
// above). Only the old item is ever deleted, and only after the new item read back with
// identical bytes. A copy made here is never removed again: by the time a later step
// fails it may already hold a value that the app saved meanwhile.
static OSStatus adopt(SecKeychainRef keychain, const char *account, UInt32 account_length,
                      CFStringRef account_string) {
  // With one service on both sides the old item would be its own copy, and deleting it
  // would delete the only one.
  if (!strcmp(LUNPORT_ADOPT_SERVICE, LUNPORT_CREDENTIAL_SERVICE)) return errSecParam;
  UInt32 old_length = 0, new_length = 0;
  void *old_data = NULL, *new_data = NULL;
  SecKeychainItemRef old_item = NULL, new_item = NULL;
  OSStatus status = find_adoptable(keychain, account, account_length, &old_length, &old_data, &old_item);
  if (status != errSecSuccess) goto done;
  if (old_length > MAX_SECRET) { status = errSecDataTooLarge; goto done; }
  status = find(keychain, account, account_length, &new_length, &new_data, &new_item);
  if (status == errSecItemNotFound) {
    status = create(keychain, account_string, old_data, old_length);
    if (status != errSecSuccess) goto done;
    status = find(keychain, account, account_length, &new_length, &new_data, &new_item);
    // -25300 is reserved for a missing old item; a copy that vanished is a failed check.
    if (status == errSecItemNotFound ||
        (status == errSecSuccess && !same(new_data, new_length, old_data, old_length))) status = errSecVerifyFailed;
    if (status != errSecSuccess) goto done;
  } else if (status != errSecSuccess || !same(new_data, new_length, old_data, old_length)) {
    // An earlier request may have stopped after its copy; only identical bytes count as one.
    status = errSecDuplicateItem;
    goto done;
  }
  status = SecKeychainItemDelete(old_item);
  // Removed by someone else meanwhile: the old item is gone either way.
  if (status == errSecItemNotFound || status == errSecInvalidItemRef) status = errSecSuccess;
done:
  if (new_data) { clear(new_data, new_length); SecKeychainItemFreeContent(NULL, new_data); }
  if (old_data) { clear(old_data, old_length); SecKeychainItemFreeContent(NULL, old_data); }
  if (new_item) CFRelease(new_item);
  if (old_item) CFRelease(old_item);
  return status;
}

int main(int argc, char **argv) {
  (void)argv;
  signal(SIGPIPE, SIG_IGN);
  alarm(300); // Also terminate if the parent disappears during a system dialog.
  if (argc != 1 || !authorized_parent()) return 77;
  // Writing first lets the parent identify this live helper over LOCAL_PEERTOKEN
  // and validate its frozen code hash before transmitting any secret.
  if (!transfer(STDOUT_FILENO, (void *)MAGIC, sizeof(MAGIC), 1)) return 74;
  unsigned char header[18]; // magic, operation, flags, account length, data length
  if (!transfer(STDIN_FILENO, header, sizeof(header), 0) || memcmp(header, MAGIC, 8)) return 64;
  uint32_t account_length, input_length;
  memcpy(&account_length, header + 10, 4);
  memcpy(&input_length, header + 14, 4);
  account_length = ntohl(account_length);
  input_length = ntohl(input_length);
  unsigned char operation = header[8], flags = header[9];
  if (operation < 1 || operation > 5 || flags > 1 || !account_length ||
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
  if (status == errSecSuccess && operation == 5) {
    status = adopt(keychain, account, account_length, account_string);
  } else if (status == errSecSuccess) {
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
