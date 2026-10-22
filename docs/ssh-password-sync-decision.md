# SSH password synchronization

Status: approved and implemented.

## Intended behavior

Saving an SSH password includes it in the same optional encrypted library sync as managed SSH private keys. Another signed-in device unlocks the library with the existing sync password and can use the saved SSH password. Local use still works without signing in. One-time connection answers and temporary deployment passwords remain temporary unless the user explicitly saves them.

The host editor explains encrypted password sync rather than claiming passwords never sync. Users can replace or remove a saved password; removal synchronizes. No extra per-host synchronization switch is introduced. Public host/Group exports, SSH config files, logs, ordinary host DTOs and MCP responses never contain a password.

## Implementation boundary

- Add a distinct `password` record to the existing signed, versioned and end-to-end encrypted Vault record pipeline. Keep password material out of `HostPayload` and its public projection. Use a native secret type without Debug or a frontend serialization path; clear temporary secret buffers.
- Bind every password to its host ID and scope, account/Vault, and the effective SSH endpoint and user. Reuse existing local host-key confirmation before releasing a password to SSH. A changed endpoint/user, different account/server or conflicting host must not reuse the previous credential.
- Reuse protected OS credentials and the existing ciphertext persistence/atomic publication boundaries. Persist only authenticated encrypted password content in sync state. Background work must use noninteractive credential APIs and report an unlock requirement if unavailable.
- Include password create/change/delete operations in existing retry, concurrency, history verification, key rotation and device recovery. A missing local credential must not be treated as a user-requested deletion. Conflicts must retain both versions for native resolution without exposing values in public review data.
- Integrate already-saved credentials for live hosts through a native, resumable adoption step when encrypted sync is unlocked. Preserve original local credentials until encrypted state is durably verified. Old unbound device-only entries require an exact locally approved account/server/endpoint/user before adoption; otherwise re-save the password in the editor to establish that binding. Do not scan unrelated OS credential entries or adopt temporary passwords.
- Extend the common relay record validation used by Cloudflare and Docker. The server receives ciphertext only and does not learn the SSH password. No new dependencies or deployment topology.

## Compatibility and validation

All participating apps and the server must support the new record kind. Old apps must fail closed on an unknown secret record and must not erase or rewrite it.

Verify with isolated synthetic data: two-device password creation/use, update and deletion, offline retry and lost acknowledgements, concurrent changes, account/server/endpoint/user isolation, locally confirmed host keys, sign-out/locked/revoked device restrictions, key rotation/device recovery, and absence of passwords from public exports/DTOs/MCP/errors. Run focused native/frontend checks first, then the required macOS, Windows and Linux CI checks before considering a release.

## Upgrade order

Update the server before enabling password sync in a new app. Both deployment variants advertise `ssh-password-sync-v1`; a client retains pending ciphertext and explains an older server's missing support. Update every participating app before relying on the new secret record. Existing apps cannot interpret that record and fail closed while retaining their state.

Local validation includes two-device creation/update/delete, unbound legacy credential isolation, ciphertext conflicts and stale editor rejection, destination changes, noninteractive reads, the existing three device-recovery variants with passwords, public export exclusion, shared Worker storage checks, and disposable Docker/virtual-Passkey peer decryption and epoch rotation. No real account, credential, or deployment data is used by these tests.
