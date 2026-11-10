// One-time bridge from Lunport 2.0 to the frozen credential helper v1. The helper accepts
// only a parent signed as the app was before 2.0.0 (identifier org.homelab.sshelter and the
// previous project certificate), which the renamed app no longer is. This program is signed
// that way, accepts only the renamed app as its parent, and relays exactly one request per
// process to the helper. It stores nothing: no listener, argv secrets, environment
// configuration, files, cache or log output.
//
// Wire protocol, framed like helper v1 so that the app reuses its v1 request and response code:
//
//   Channel   The parent passes one end of a connected AF_UNIX stream socketpair as both
//             stdin and stdout and starts the bridge with no arguments. The bridge checks its
//             parent before writing or reading anything and exits 77 if the check fails.
//   Parent    Exactly helper v1's check: the kernel audit token of the socket peer must be the
//             direct parent (its pid is getppid()) under this user's effective uid, valid under
//             kSecCSStrictValidate against LUNPORT_CLIENT_REQUIREMENT, with hardened runtime,
//             not debugged, and without an entitlement that permits code injection. The bridge
//             also requires the last three of itself. Both checks are repeated after the
//             request has been read and again before the response is written.
//   Hello     bridge -> parent: "LPKB0001". The parent then checks the live bridge over
//             LOCAL_PEERTOKEN against its pinned requirement (identifier, previous project
//             certificate leaf, the bridge's code hashes) and sends nothing to a bridge that
//             fails it.
//   Request   parent -> bridge, exactly one frame, then the parent shuts down its writing side:
//               magic "LPKB0001" (8) | helper path length (4)
//               | helper path (absolute, no NUL, 1..1023 bytes)
//               | one complete helper v1 request frame:
//                   magic "LPKC0001" (8) | operation (1) | flags (1) | account length (4)
//                   | data length (4) | account (no NUL, 1..4096 bytes) | data
//             Integers are big-endian. Operations: 1 get, 2 set, 3 delete; set exists only so
//             that CI can create helper-owned fixtures, and the app never sends it. Only set
//             carries data (0..1 MiB). flags is 0, or 1 to forbid any authorization UI.
//   Relay     The bridge starts the program at the helper path with no arguments, an empty
//             environment, a new socketpair as stdin and stdout, /dev/null as stderr and no
//             other descriptor. It reads the helper's hello "LPKC0001", checks the live helper
//             over LOCAL_PEERTOKEN against LUNPORT_HELPER_REQUIREMENT (identifier, previous
//             certificate leaf, the two frozen code hashes), and only then forwards the v1
//             frame unchanged.
//   Response  bridge -> parent: the helper's v1 response unchanged, after the helper exited 0:
//               status (4, Keychain OSStatus) | length (4) | data
//             length is non-zero only for a successful get. The bridge then exits 0.
//   Timing    Towards the helper each read waits at most 10 seconds when flags is 1 and 305
//             seconds otherwise (the helper itself gives up after 300), each write at most 5,
//             and the bridge ends itself after 310 seconds. The parent should wait for the
//             response more than 15 seconds when flags is 1, so that a silent helper is
//             reported by the bridge rather than by the parent's own timeout, and more than
//             310 seconds otherwise; writing the request needs no more than 5 seconds.
//   Exit      0  the helper's response was relayed, whatever its status
//             64 malformed request; no helper was started
//             69 the helper could not be started from that path
//             71 out of memory or process resources
//             74 I/O with the parent failed, or a repeated check of the parent or of this
//                bridge failed; nothing was relayed
//             75 the helper refused this bridge as its parent
//             76 the helper broke the protocol or stopped without a complete response
//             77 the parent, or this bridge itself, failed the first check; nothing was read
//             78 the program at that path is not the pinned helper v1; nothing was forwarded
//             With any exit status but 0 the parent receives nothing after the hello.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <arpa/inet.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

// Overrides are for separately built disposable CI fixtures, never the frozen artifact.
#ifndef LUNPORT_CLIENT_REQUIREMENT
#define LUNPORT_CLIENT_REQUIREMENT "identifier \"dev.ysya.lunport\" and certificate leaf = H\"66f062921154fb6fe72e7ee0dfe99d7d804efb03\""
#endif
#ifndef LUNPORT_HELPER_REQUIREMENT
#define LUNPORT_HELPER_REQUIREMENT "identifier \"org.homelab.sshelter.credential-helper.v1\" and certificate leaf = H\"a346b47b8dccb4faeac8aec1ea997535809aeec9\" and (cdhash H\"b81014e67d632acee792ce51572884d585544241\" or cdhash H\"dd91d3bea5c08b4e639fb3b0944fdb43520b2127\")"
#endif
// A fixture names a throwaway HOME so that its helper can reach only a disposable keychain.
// The frozen artifact starts the helper with an empty environment, as the app does.
#ifdef LUNPORT_FIXTURE_HELPER_HOME
static char *helper_environment[] = {"HOME=" LUNPORT_FIXTURE_HELPER_HOME, NULL};
#else
static char *helper_environment[] = {NULL};
#endif

#define MAX_ACCOUNT 4096u
#define MAX_SECRET (1024u * 1024u)
#define MAX_PATH 1023u
static const unsigned char MAGIC[8] = {'L','P','K','B','0','0','0','1'};
static const unsigned char HELPER_MAGIC[8] = {'L','P','K','C','0','0','0','1'};

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

// The conditions the helper requires of this bridge, required by the bridge of itself as
// well: secrets pass through this process, and a debugger that attached after the helper's
// last check must still stop the relay.
static int trusted_self(void) {
  SecCodeRef code = NULL;
  CFDictionaryRef info = NULL;
  int valid = 0;
  if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess ||
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
  if (code) CFRelease(code);
  return valid;
}

// Authenticate the live helper before forwarding an account or secret, as the app
// authenticates the helpers it starts. Checking the path before launch would race a
// same-user replacement; the audit token identifies the running child.
static int pinned_helper(int fd, pid_t expected) {
  audit_token_t token;
  socklen_t length = sizeof(token);
  uid_t uid;
  gid_t gid;
  if (getpeereid(fd, &uid, &gid) != 0 || uid != geteuid() ||
      getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) != 0 ||
      length != sizeof(token) || audit_token_to_euid(token) != geteuid() ||
      audit_token_to_pid(token) != expected) return 0;
  CFDataRef audit = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
  const void *keys[] = { kSecGuestAttributeAudit };
  const void *values[] = { audit };
  CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  SecCodeRef code = NULL;
  SecRequirementRef requirement = NULL;
  int valid = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code) == errSecSuccess &&
      SecRequirementCreateWithString(CFSTR(LUNPORT_HELPER_REQUIREMENT), kSecCSDefaultFlags, &requirement) == errSecSuccess &&
      SecCodeCheckValidity(code, kSecCSStrictValidate, requirement) == errSecSuccess;
  if (requirement) CFRelease(requirement);
  if (code) CFRelease(code);
  CFRelease(attributes);
  CFRelease(audit);
  return valid;
}

// Start the helper with only the channel as stdin and stdout, /dev/null as stderr, default
// signal handling and the fixed environment above. Returns 0 or an errno value.
static int start_helper(const char *path, int channel, pid_t *helper) {
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  int error = posix_spawn_file_actions_init(&actions);
  if (error) return error;
  error = posix_spawnattr_init(&attributes);
  if (error) { posix_spawn_file_actions_destroy(&actions); return error; }
  sigset_t defaults, mask;
  sigemptyset(&defaults);
  sigaddset(&defaults, SIGPIPE);
  sigemptyset(&mask);
  char *arguments[] = {(char *)path, NULL};
  if (!(error = posix_spawn_file_actions_adddup2(&actions, channel, STDIN_FILENO)) &&
      !(error = posix_spawn_file_actions_adddup2(&actions, channel, STDOUT_FILENO)) &&
      !(error = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)) &&
      !(error = posix_spawnattr_setflags(&attributes,
          POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)) &&
      !(error = posix_spawnattr_setsigdefault(&attributes, &defaults)) &&
      !(error = posix_spawnattr_setsigmask(&attributes, &mask)))
    error = posix_spawn(helper, path, &actions, &attributes, arguments, helper_environment);
  posix_spawnattr_destroy(&attributes);
  posix_spawn_file_actions_destroy(&actions);
  return error;
}

static int reap(pid_t helper) {
  int status = 0;
  while (waitpid(helper, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(int argc, char **argv) {
  (void)argv;
  signal(SIGPIPE, SIG_IGN);
  // Outlasts the helper's own 300-second limit; also ends a request whose parent went away.
  alarm(310);
  if (argc != 1 || !trusted_self() || !authorized_parent()) return 77;
  // Writing first lets the parent identify this live bridge over LOCAL_PEERTOKEN
  // and validate its frozen code hash before transmitting any request.
  if (!transfer(STDOUT_FILENO, (void *)MAGIC, sizeof(MAGIC), 1)) return 74;
  unsigned char envelope[12]; // magic, helper path length
  if (!transfer(STDIN_FILENO, envelope, sizeof(envelope), 0) || memcmp(envelope, MAGIC, 8)) return 64;
  uint32_t path_length;
  memcpy(&path_length, envelope + 8, 4);
  path_length = ntohl(path_length);
  if (!path_length || path_length > MAX_PATH) return 64;
  char path[MAX_PATH + 1] = {0};
  unsigned char header[18]; // the helper's magic, operation, flags, account length, data length
  if (!transfer(STDIN_FILENO, path, path_length, 0) || path[0] != '/' || memchr(path, 0, path_length) ||
      !transfer(STDIN_FILENO, header, sizeof(header), 0) || memcmp(header, HELPER_MAGIC, 8)) return 64;
  uint32_t account_length, input_length;
  memcpy(&account_length, header + 10, 4);
  memcpy(&input_length, header + 14, 4);
  account_length = ntohl(account_length);
  input_length = ntohl(input_length);
  unsigned char operation = header[8], flags = header[9];
  if (operation < 1 || operation > 3 || flags > 1 || !account_length ||
      account_length > MAX_ACCOUNT || input_length > MAX_SECRET ||
      (operation != 2 && input_length)) return 64;
  size_t request_length = sizeof(header) + account_length + input_length;
  unsigned char *request = calloc(request_length, 1);
  if (!request) return 71;
  memcpy(request, header, sizeof(header));
  int result = 64, sockets[2] = {-1, -1};
  pid_t helper = 0;
  unsigned char *output = NULL;
  uint32_t output_length = 0;
  unsigned char trailing;
  // Require an exact single frame and no embedded NUL in the account, as the helper does.
  if (!transfer(STDIN_FILENO, request + sizeof(header), account_length + input_length, 0) ||
      read(STDIN_FILENO, &trailing, 1) != 0 || memchr(request + sizeof(header), 0, account_length)) goto done;
  result = 74;
  if (!trusted_self() || !authorized_parent()) goto done;
  result = 71;
  // The app's limits for a helper it starts: 10 seconds for an answer when no UI may
  // appear, otherwise 305 (the helper gives up after 300); 5 seconds for each write.
  struct timeval receive = {flags ? 10 : 305, 0}, send = {5, 0};
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) goto done;
  if (setsockopt(sockets[0], SOL_SOCKET, SO_RCVTIMEO, &receive, sizeof(receive)) != 0 ||
      setsockopt(sockets[0], SOL_SOCKET, SO_SNDTIMEO, &send, sizeof(send)) != 0) goto done;
  int error = start_helper(path, sockets[1], &helper);
  close(sockets[1]);
  sockets[1] = -1;
  if (error) {
    helper = 0;
    result = error == ENOMEM || error == EAGAIN ? 71 : 69;
    goto done;
  }
  unsigned char hello[8];
  if (!transfer(sockets[0], hello, sizeof(hello), 0)) {
    // No hello: normally the helper refused this parent and exited 77. A helper that is
    // already exiting keeps that status; anything still running is stopped here.
    kill(helper, SIGKILL);
    int code = reap(helper);
    helper = 0;
    result = code == 77 ? 75 : 76;
    goto done;
  }
  result = 76;
  if (memcmp(hello, HELPER_MAGIC, sizeof(hello))) goto done;
  result = 78;
  if (!pinned_helper(sockets[0], helper)) goto done;
  result = 76;
  if (!transfer(sockets[0], request, request_length, 1) || shutdown(sockets[0], SHUT_WR) != 0) goto done;
  uint32_t response[2];
  if (!transfer(sockets[0], response, sizeof(response), 0)) goto done;
  int32_t status = (int32_t)ntohl(response[0]);
  output_length = ntohl(response[1]);
  if (output_length > MAX_SECRET || (status != 0 && output_length) || (operation != 1 && output_length)) {
    output_length = 0;
    goto done;
  }
  result = 71;
  if (!(output = calloc(output_length + 1, 1))) goto done;
  result = 76;
  if (!transfer(sockets[0], output, output_length, 0) || read(sockets[0], &trailing, 1) != 0) goto done;
  close(sockets[0]);
  sockets[0] = -1;
  int code = reap(helper);
  helper = 0;
  if (code != 0) goto done;
  result = 74;
  if (!trusted_self() || !authorized_parent()) goto done;
  if (!transfer(STDOUT_FILENO, response, sizeof(response), 1) ||
      !transfer(STDOUT_FILENO, output, output_length, 1)) goto done;
  result = 0;
done:
  if (sockets[0] >= 0) close(sockets[0]);
  if (helper > 0) {
    kill(helper, SIGKILL);
    reap(helper);
  }
  if (output) { clear(output, output_length); free(output); }
  clear(request, request_length);
  free(request);
  return result;
}
