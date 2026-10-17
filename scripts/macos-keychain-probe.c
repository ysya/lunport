// Disposable CI credentials only. UI stays disabled throughout the process.
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

#ifndef PROBE_VERSION
#define PROBE_VERSION "1"
#endif

int main(int argc, char **argv) {
  if (argc != 5) return 64;
  const char *mode = argv[1], *service = argv[3], *account = argv[4];
  const char fixture[] = "public-keychain-upgrade-fixture";
  SecKeychainRef keychain = NULL;
  OSStatus status = SecKeychainSetUserInteractionAllowed(false);
  if (status != errSecSuccess) return 65;
  status = SecKeychainOpen(argv[2], &keychain);
  if (status != errSecSuccess) return 66;
  if (strcmp(mode, "write") == 0) {
    status = SecKeychainAddGenericPassword(keychain, (UInt32)strlen(service), service,
      (UInt32)strlen(account), account, sizeof(fixture) - 1, fixture, NULL);
    if (status != errSecSuccess) { fprintf(stderr, "fixture creation: %d\n", (int)status); return 67; }
  } else {
    UInt32 length = 0;
    void *data = NULL;
    status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service,
      (UInt32)strlen(account), account, &length, &data, NULL);
    if (strcmp(mode, "denied") == 0) {
      if (data) SecKeychainItemFreeContent(NULL, data);
      if (status != errSecInteractionNotAllowed && status != errSecAuthFailed) {
        fprintf(stderr, "different signer was not rejected by authorization: %d\n", (int)status); return 68;
      }
    } else if (strcmp(mode, "read") == 0) {
      if (status != errSecSuccess) { fprintf(stderr, "credential read: %d\n", (int)status); return 69; }
      int matches = length == sizeof(fixture) - 1 && memcmp(data, fixture, length) == 0;
      SecKeychainItemFreeContent(NULL, data);
      if (!matches) return 70;
    } else return 64;
  }
  CFRelease(keychain);
  printf("probe %s: %s passed without interaction\n", PROBE_VERSION, mode);
  return 0;
}
