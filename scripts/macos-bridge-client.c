// Disposable validation only (scripts/validate-macos-bridge.sh). Plays the app's part
// towards helper v2 and towards the bridge -> helper v1 chain, using public fixture values.
// It refuses to run unless the user's default keychain is the disposable keychain named by
// LUNPORT_VALIDATION_KEYCHAIN, never accepts a keychain in the user's own Keychains folder
// except on a disposable CI runner (whose login keychain the partition checks need), and
// every request it sends forbids authorization UI, so on a developer Mac it can neither
// reach nor prompt for a real keychain item.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// The pinned requirements of the programs under test, as the app pins them.
#ifndef LUNPORT_HELPER_REQUIREMENT
#error "Define LUNPORT_HELPER_REQUIREMENT, the pinned requirement of helper v2"
#endif
#ifndef LUNPORT_BRIDGE_REQUIREMENT
#error "Define LUNPORT_BRIDGE_REQUIREMENT, the pinned requirement of the bridge"
#endif

extern int lunport_validate_credential_peer(int fd, int expected_pid, const char *required);

static const unsigned char HELPER_MAGIC[8] = {'L','P','K','C','0','0','0','2'};
static const unsigned char V1_MAGIC[8] = {'L','P','K','C','0','0','0','1'};
static const unsigned char BRIDGE_MAGIC[8] = {'L','P','K','B','0','0','0','1'};
static const char fixture[] = "public-bridge-validation-fixture";
static const char other[] = "public-bridge-validation-other";
enum { GET = 1, SET = 2, DELETE = 3, EXISTS = 4, ADOPT = 5 };

struct outcome {
  int greeted, trusted, answered, exit_code; // exit_code is -1 after a signal
  OSStatus status;
  uint32_t length;
  unsigned char data[256];
};

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

static int finish(pid_t pid) {
  int status = 0;
  while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -2;
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Start the program as the app does (one socketpair as stdin and stdout), check its hello and
// its pinned identity, and only then send the request and collect the response.
static void run(const char *program, const unsigned char magic[8], const char *requirement,
                const unsigned char *request, size_t request_length, struct outcome *out) {
  memset(out, 0, sizeof(*out));
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) { out->exit_code = -3; return; }
  pid_t pid = fork();
  if (pid < 0) { out->exit_code = -3; return; }
  if (!pid) {
    close(sockets[0]);
    dup2(sockets[1], STDIN_FILENO);
    dup2(sockets[1], STDOUT_FILENO);
    close(sockets[1]);
    execl(program, program, (char *)NULL);
    _exit(127);
  }
  close(sockets[1]);
  unsigned char hello[8];
  out->greeted = transfer(sockets[0], hello, sizeof(hello), 0) && !memcmp(hello, magic, 8);
  out->trusted = out->greeted && lunport_validate_credential_peer(sockets[0], pid, requirement) == 1;
  if (!out->trusted) {
    close(sockets[0]);
    kill(pid, SIGKILL);
    out->exit_code = finish(pid);
    return;
  }
  transfer(sockets[0], (void *)request, request_length, 1);
  shutdown(sockets[0], SHUT_WR);
  uint32_t response[2];
  if (transfer(sockets[0], response, sizeof(response), 0)) {
    out->status = (OSStatus)ntohl(response[0]);
    out->length = ntohl(response[1]);
    out->answered = out->length <= sizeof(out->data) && transfer(sockets[0], out->data, out->length, 0);
  }
  close(sockets[0]);
  out->exit_code = finish(pid);
}

// One request frame in the helper wire format. Every request forbids authorization UI.
static size_t frame(unsigned char *out, const unsigned char magic[8], unsigned char operation,
                    const char *account, const char *data) {
  uint32_t account_length = (uint32_t)strlen(account), data_length = data ? (uint32_t)strlen(data) : 0;
  memcpy(out, magic, 8);
  out[8] = operation;
  out[9] = 1;
  uint32_t value = htonl(account_length);
  memcpy(out + 10, &value, 4);
  value = htonl(data_length);
  memcpy(out + 14, &value, 4);
  memcpy(out + 18, account, account_length);
  if (data_length) memcpy(out + 18 + account_length, data, data_length);
  return 18 + account_length + data_length;
}

// The bridge envelope: its magic, the helper path, then one helper v1 frame.
static size_t envelope(unsigned char *out, const char *helper, const unsigned char *inner, size_t inner_length) {
  uint32_t path_length = (uint32_t)strlen(helper), value = htonl(path_length);
  memcpy(out, BRIDGE_MAGIC, 8);
  memcpy(out + 8, &value, 4);
  memcpy(out + 12, helper, path_length);
  memcpy(out + 12 + path_length, inner, inner_length);
  return 12 + path_length + inner_length;
}

static int holds(const struct outcome *out, const char *value) {
  return out->answered && out->status == errSecSuccess && out->length == strlen(value) &&
         !memcmp(out->data, value, out->length);
}

static int refused(OSStatus status) {
  return status == errSecAuthFailed || status == errSecInteractionNotAllowed || status == errSecUserCanceled;
}

static int report(int passed, const char *target, const char *mode, const struct outcome *out) {
  if (passed) {
    printf("%s %s: passed\n", target, mode);
    return 0;
  }
  if (out)
    fprintf(stderr, "%s %s: FAILED (greeted %d, trusted %d, answered %d, status %d, length %u, exit %d)\n",
            target, mode, out->greeted, out->trusted, out->answered, (int)out->status,
            (unsigned)out->length, out->exit_code);
  else
    fprintf(stderr, "%s %s: FAILED\n", target, mode);
  return 1;
}

// A program that refused its parent wrote nothing and exited 77.
static int was_rejected(const struct outcome *out) {
  return !out->greeted && !out->answered && out->exit_code == 77;
}

// A request a program refused as malformed got no response and a non-zero exit status.
static int was_malformed(const struct outcome *out, int expected_exit) {
  return out->trusted && !out->answered && out->exit_code == expected_exit;
}

static int helper_mode(const char *mode, const char *helper, const char *account) {
  unsigned char request[8192];
  size_t length = 0;
  struct outcome out;
  int passed = 0;
  if (!strcmp(mode, "set") || !strcmp(mode, "set-other")) {
    length = frame(request, HELPER_MAGIC, SET, account, strcmp(mode, "set") ? other : fixture);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = out.answered && out.status == errSecSuccess && !out.length && !out.exit_code;
  } else if (!strcmp(mode, "get") || !strcmp(mode, "get-other")) {
    length = frame(request, HELPER_MAGIC, GET, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = holds(&out, strcmp(mode, "get") ? other : fixture) && !out.exit_code;
  } else if (!strcmp(mode, "contains")) {
    length = frame(request, HELPER_MAGIC, EXISTS, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = out.answered && out.status == errSecSuccess && !out.length && !out.exit_code;
  } else if (!strcmp(mode, "missing")) {
    length = frame(request, HELPER_MAGIC, GET, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = out.answered && out.status == errSecItemNotFound && !out.length && !out.exit_code;
  } else if (!strcmp(mode, "delete")) {
    length = frame(request, HELPER_MAGIC, DELETE, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = out.answered && (out.status == errSecSuccess || out.status == errSecItemNotFound) && !out.exit_code;
  } else if (!strncmp(mode, "adopt", 5) && strcmp(mode, "adopt-with-data")) {
    length = frame(request, HELPER_MAGIC, ADOPT, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    int answered = out.answered && !out.length && !out.exit_code;
    if (!strcmp(mode, "adopt")) passed = answered && out.status == errSecSuccess;
    else if (!strcmp(mode, "adopt-refused")) passed = answered && refused(out.status);
    else if (!strcmp(mode, "adopt-missing")) passed = answered && out.status == errSecItemNotFound;
    else if (!strcmp(mode, "adopt-conflict")) passed = answered && out.status == errSecDuplicateItem;
    else if (!strcmp(mode, "adopt-oversized")) passed = answered && out.status == errSecDataTooLarge;
    else if (!strcmp(mode, "adopt-one-service")) passed = answered && out.status == errSecParam;
    else return report(0, "helper", mode, NULL);
  } else if (!strcmp(mode, "rejected")) {
    length = frame(request, HELPER_MAGIC, GET, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = was_rejected(&out);
  } else if (!strcmp(mode, "bad-magic")) { // a protocol-1 frame
    length = frame(request, V1_MAGIC, GET, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = was_malformed(&out, 64);
  } else if (!strcmp(mode, "bad-op")) {
    length = frame(request, HELPER_MAGIC, 6, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = was_malformed(&out, 64);
  } else if (!strcmp(mode, "adopt-with-data")) {
    length = frame(request, HELPER_MAGIC, ADOPT, account, fixture);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = was_malformed(&out, 64);
  } else if (!strcmp(mode, "oversized")) {
    length = frame(request, HELPER_MAGIC, SET, account, fixture);
    uint32_t value = htonl(1024u * 1024u + 1u);
    memcpy(request + 14, &value, 4);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, length, &out);
    passed = was_malformed(&out, 64);
  } else if (!strcmp(mode, "truncated")) {
    frame(request, HELPER_MAGIC, GET, account, NULL);
    run(helper, HELPER_MAGIC, LUNPORT_HELPER_REQUIREMENT, request, 5, &out);
    passed = was_malformed(&out, 64);
  } else {
    return report(0, "helper", mode, NULL);
  }
  return report(passed, "helper", mode, &out);
}

static int bridge_mode(const char *mode, const char *bridge, const char *helper, const char *account) {
  unsigned char inner[8192], request[8192 + PATH_MAX + 16];
  size_t inner_length = 0, length = 0;
  struct outcome out;
  int passed = 0;
  if (!strcmp(mode, "set")) {
    inner_length = frame(inner, V1_MAGIC, SET, account, fixture);
  } else if (!strcmp(mode, "delete")) {
    inner_length = frame(inner, V1_MAGIC, DELETE, account, NULL);
  } else if (!strcmp(mode, "bad-op")) { // exists is not relayed
    inner_length = frame(inner, V1_MAGIC, EXISTS, account, NULL);
  } else if (!strcmp(mode, "bad-helper-magic")) {
    inner_length = frame(inner, HELPER_MAGIC, GET, account, NULL);
  } else if (!strcmp(mode, "oversized")) {
    inner_length = frame(inner, V1_MAGIC, SET, account, fixture);
    uint32_t value = htonl(1024u * 1024u + 1u);
    memcpy(inner + 14, &value, 4);
  } else {
    inner_length = frame(inner, V1_MAGIC, GET, account, NULL);
  }
  length = envelope(request, !strcmp(mode, "relative-path") ? helper + 1 : helper, inner, inner_length);
  if (!strcmp(mode, "bad-magic")) request[0] = 'X';
  if (!strcmp(mode, "trailing")) request[length++] = 0;
  if (!strcmp(mode, "truncated")) length = 10;
  run(bridge, BRIDGE_MAGIC, LUNPORT_BRIDGE_REQUIREMENT, request, length, &out);
  int relayed = out.answered && !out.exit_code;
  if (!strcmp(mode, "set")) passed = relayed && out.status == errSecSuccess && !out.length;
  else if (!strcmp(mode, "get")) passed = relayed && holds(&out, fixture);
  else if (!strcmp(mode, "missing")) passed = relayed && out.status == errSecItemNotFound && !out.length;
  else if (!strcmp(mode, "denied")) passed = relayed && refused(out.status) && !out.length;
  else if (!strcmp(mode, "delete")) passed = relayed && (out.status == errSecSuccess || out.status == errSecItemNotFound);
  else if (!strcmp(mode, "rejected")) passed = was_rejected(&out);
  else if (!strcmp(mode, "helper-unavailable")) passed = was_malformed(&out, 69);
  else if (!strcmp(mode, "helper-refuses")) passed = was_malformed(&out, 75);
  else if (!strcmp(mode, "helper-unpinned")) passed = was_malformed(&out, 78);
  else if (!strcmp(mode, "bad-magic") || !strcmp(mode, "bad-op") || !strcmp(mode, "bad-helper-magic") ||
           !strcmp(mode, "oversized") || !strcmp(mode, "relative-path") || !strcmp(mode, "trailing") ||
           !strcmp(mode, "truncated")) passed = was_malformed(&out, 64);
  else return report(0, "bridge", mode, NULL);
  return report(passed, "bridge", mode, &out);
}

// The item's decrypt access names exactly one program, the one at this path. In a new keychain,
// which keeps no partition list, this is how an item records the program that created it.
static int owned_by(SecKeychainItemRef item, const char *program) {
  char expected[PATH_MAX], actual[PATH_MAX], path[PATH_MAX] = {0};
  SecAccessRef access = NULL;
  if (!realpath(program, expected) || SecKeychainItemCopyAccess(item, &access) != errSecSuccess) return 0;
  int owned = 0;
  CFArrayRef acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
  CFArrayRef applications = NULL;
  CFStringRef description = NULL;
  CFDataRef data = NULL;
  SecKeychainPromptSelector selector = 0;
  if (acls && CFArrayGetCount(acls) == 1 &&
      SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(acls, 0), &applications, &description, &selector) == errSecSuccess &&
      applications && CFArrayGetCount(applications) == 1 &&
      SecTrustedApplicationCopyData((SecTrustedApplicationRef)CFArrayGetValueAtIndex(applications, 0), &data) == errSecSuccess &&
      data && CFDataGetLength(data) > 0 && CFDataGetLength(data) < PATH_MAX) {
    memcpy(path, CFDataGetBytePtr(data), (size_t)CFDataGetLength(data));
    owned = realpath(path, actual) && !strcmp(actual, expected);
  }
  if (data) CFRelease(data);
  if (description) CFRelease(description);
  if (applications) CFRelease(applications);
  if (acls) CFRelease(acls);
  CFRelease(access);
  return owned;
}

// Items made directly by this client: the creator is always trusted, and create-granted also
// trusts one more program, as an item looks after the user chose Always Allow for it. The
// oversized variant holds one byte more than the helpers accept (1 MiB).
static int fixture_mode(const char *mode, const char *service, const char *account, const char *program) {
  SecKeychainRef keychain = NULL;
  OSStatus status = SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &keychain);
  if (status) return report(0, "fixture", mode, NULL);
  SecKeychainItemRef item = NULL;
  UInt32 length = 0;
  void *data = NULL;
  int passed = 0, oversized = !strcmp(mode, "create-granted-oversized");
  const char *trusted = !strncmp(mode, "create-granted", 14) ? program : NULL;
  if ((!strcmp(mode, "create") && !program) || (trusted && (oversized || !strcmp(mode, "create-granted")))) {
    CFStringRef service_string = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef account_string = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFIndex value_length = oversized ? 1024 * 1024 + 1 : (CFIndex)sizeof(fixture) - 1;
    UInt8 *bytes = calloc((size_t)value_length, 1);
    if (!bytes) return report(0, "fixture", mode, NULL);
    if (oversized) memset(bytes, 'x', (size_t)value_length);
    else memcpy(bytes, fixture, sizeof(fixture) - 1);
    CFDataRef value = CFDataCreate(NULL, bytes, value_length);
    free(bytes);
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attributes, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(attributes, kSecAttrService, service_string);
    CFDictionarySetValue(attributes, kSecAttrAccount, account_string);
    CFDictionarySetValue(attributes, kSecValueData, value);
    CFDictionarySetValue(attributes, kSecUseKeychain, keychain);
    SecAccessRef access = NULL;
    SecTrustedApplicationRef self = NULL, granted = NULL;
    if (trusted) {
      status = SecTrustedApplicationCreateFromPath(NULL, &self);
      if (!status) status = SecTrustedApplicationCreateFromPath(trusted, &granted);
      const void *applications[] = {self, granted};
      CFArrayRef list = status ? NULL : CFArrayCreate(NULL, applications, 2, &kCFTypeArrayCallBacks);
      if (!status) status = SecAccessCreate(CFSTR("public-bridge-validation-fixture"), list, &access);
      if (!status) CFDictionarySetValue(attributes, kSecAttrAccess, access);
      if (list) CFRelease(list);
    }
    if (!status) status = SecItemAdd(attributes, NULL);
    passed = status == errSecSuccess;
    if (access) CFRelease(access);
    if (self) CFRelease(self);
    if (granted) CFRelease(granted);
    CFRelease(attributes);
    CFRelease(value);
    CFRelease(account_string);
    CFRelease(service_string);
  } else if ((!program && (!strcmp(mode, "verify") || !strcmp(mode, "denied") || !strcmp(mode, "present") ||
                           !strcmp(mode, "absent") || !strcmp(mode, "delete"))) ||
             (program && !strcmp(mode, "owner"))) {
    int reading = !strcmp(mode, "verify") || !strcmp(mode, "denied");
    status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service,
        (UInt32)strlen(account), account, reading ? &length : NULL, reading ? &data : NULL, &item);
    if (!strcmp(mode, "verify")) passed = !status && length == sizeof(fixture) - 1 && !memcmp(data, fixture, length);
    else if (!strcmp(mode, "denied")) passed = refused(status) && !data; // an item another program owns
    else if (!strcmp(mode, "present")) passed = status == errSecSuccess; // reads no data
    else if (!strcmp(mode, "absent")) passed = status == errSecItemNotFound;
    else if (!strcmp(mode, "owner")) passed = !status && owned_by(item, program);
    else passed = status == errSecItemNotFound || (!status && SecKeychainItemDelete(item) == errSecSuccess);
  }
  if (data) SecKeychainItemFreeContent(NULL, data);
  if (item) CFRelease(item);
  CFRelease(keychain);
  if (!passed) fprintf(stderr, "fixture %s: status %d\n", mode, (int)status);
  return report(passed, "fixture", mode, NULL);
}

static int ci_runner(void) {
  const char *actions = getenv("GITHUB_ACTIONS"), *system = getenv("RUNNER_OS");
  return actions && !strcmp(actions, "true") && system && !strcmp(system, "macOS");
}

// Proceed only when the default keychain is the disposable one the validation named, and never
// with a keychain in the user's own Keychains folder unless this is a disposable CI runner.
static int disposable_keychain(void) {
  const char *expected = getenv("LUNPORT_VALIDATION_KEYCHAIN"), *home = getenv("HOME");
  struct passwd *user = getpwuid(getuid());
  char wanted[PATH_MAX], actual[PATH_MAX], path[PATH_MAX], keychains[PATH_MAX], own[PATH_MAX];
  UInt32 length = sizeof(path) - 1;
  SecKeychainRef keychain = NULL;
  if (!expected || !home || !user || !strcmp(home, user->pw_dir) || !realpath(expected, wanted)) return 0;
  snprintf(keychains, sizeof(keychains), "%s/Library/Keychains", user->pw_dir);
  if (realpath(keychains, own) && !strncmp(wanted, own, strlen(own)) && wanted[strlen(own)] == '/' && !ci_runner())
    return 0;
  if (SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &keychain) != errSecSuccess) return 0;
  int same = SecKeychainGetPath(keychain, &length, path) == errSecSuccess &&
             (path[length] = 0, realpath(path, actual)) && !strcmp(actual, wanted);
  CFRelease(keychain);
  return same;
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  alarm(60);
  if (SecKeychainSetUserInteractionAllowed(false) != errSecSuccess || !disposable_keychain()) {
    fprintf(stderr, "Refusing: the default keychain is not the disposable validation keychain.\n");
    return 70;
  }
  if (argc == 5 && !strcmp(argv[1], "helper")) return helper_mode(argv[2], argv[3], argv[4]);
  if (argc == 6 && !strcmp(argv[1], "bridge")) return bridge_mode(argv[2], argv[3], argv[4], argv[5]);
  if ((argc == 5 || argc == 6) && !strcmp(argv[1], "fixture"))
    return fixture_mode(argv[2], argv[3], argv[4], argc == 6 ? argv[5] : NULL);
  fprintf(stderr, "usage: %s helper <mode> <helper v2> <account>\n"
                  "       %s bridge <mode> <bridge> <helper v1> <account>\n"
                  "       %s fixture <create|verify|denied|present|absent|delete> <service> <account>\n"
                  "       %s fixture <create-granted|create-granted-oversized|owner> <service> <account> <program>\n",
          argv[0], argv[0], argv[0], argv[0]);
  return 64;
}
