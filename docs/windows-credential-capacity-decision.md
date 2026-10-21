# Windows credential capacity

Status: architecture approved by the user on 2026-10-21; official Microsoft guidance checked before implementation.

## Reproduction and corrected units

Windows Credential Manager accepts at most **2,560 bytes** per generic credential. The current password API uses UTF-16, limiting a saved value to **1,280 code units**. The dependency labels its byte limit as “chars”; the preliminary diagnosis and fixture incorrectly treated 2,560 as a UTF-16 unit count. Both Microsoft documentation and the locked SDK constant confirmed the byte limit before implementation.

Synthetic first-device password setup writes a bootstrap intent of 5,078 UTF-16 units. Second-device automatic host/key sync writes a source-adoption state of 2,738 units after unlock, before completing the merge. Both exceed the true byte limit. Original local state remains intact when these writes fail. The former native memory fixture accepted unlimited sizes.

## Approved implementation

Extend the Windows credential adapter for larger values:

- Use native DPAPI (CryptProtectData / CryptUnprotectData) in current-user scope with UI forbidden and NULL prompts. Never use machine-wide protection. Add no dependencies.
- Keep an 81-byte authoritative descriptor in Credential Manager: format, fresh per-write secret optional entropy, exact ciphertext digest and bounded lengths.
- Store the larger value in an immutable, owner-only encrypted file under this app profile. Reuse verified Windows atomic file operations. Bind DPAPI optional entropy to the service, account, format and fresh secret.
- Write and verify ciphertext before committing the OS entry; verify the exact entry by protected readback before success. Before that commit, failures preserve the previous credential. On an ambiguous OS commit/readback, retain both ciphertexts for a safe cold retry.
- Retain the current digest outside restorable workspace files. Missing, swapped, corrupt or replayed ciphertext fails closed without resetting trust or local data. Replacing the descriptor forgets the old per-write entropy before best-effort old ciphertext cleanup. Forgetting a credential deletes the OS descriptor first.
- Preserve legacy small UTF-16 credentials, including non-BMP text and exact native byte boundaries. Large descriptors have a fixed odd byte length, distinct from every valid legacy UTF-16 value.
- Bound values to 1 MiB and ciphertext to that plus 64 KiB. Never use a plaintext fallback or recreate missing authority.

Cloudflare/Docker protocols, account identity, cross-device end-to-end encryption, sync passwords and local host data remain unchanged. Older Windows clients cannot read newly stored large descriptors.

## Verification before release

Cover first setup and second-device host/key sync against a physical 2,560-byte entry limit; Unicode boundaries; old credential compatibility; interrupted writes/deletes and lost replies; corruption, ciphertext replay/swap, and profile binding. Run the actual Windows Credential Manager / DPAPI path with uniquely scoped synthetic credentials and owned temporary files, then the applicable platform CI.

## Official guidance versus project requirements

- [Handling Passwords](https://learn.microsoft.com/en-us/windows/win32/secbp/handling-passwords): Credential Manager for credentials and DPAPI for persisted local secrets.
- [CREDENTIALW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw): blob size is bytes, at most 5 * 512.
- [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata): current-user protection, noninteractive operation and optional entropy.
- [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata): recommends additional application-level integrity checks.

DPAPI provides local encryption, not sync rollback prevention. Keeping the exact current digest in Credential Manager is this project's additional restore/security requirement. DPAPI is only used for Windows local persistence; it does not replace cross-device encryption.
