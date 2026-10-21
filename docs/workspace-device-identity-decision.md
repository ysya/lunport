# Device recovery in the same library

Approved by the user on 2026-10-22: keep one active library and recover its device identity in place. This replaces the earlier proposal to open another empty library and manually export/import.

## Flow

1. Sign in to the library’s existing account using its normal browser/Passkey flow. A different account or server cannot adopt this library’s records or trust anchor.
2. Enter the existing sync password in the App. The native recovery path journals one operation and creates an independent OS-protected device credential. The archive key is reserved during this explicit foreground action; subsequent background credential reads and updates cannot prompt or unlock the OS store. Retries reuse that operation; the old slot, files, Groups, hosts, keys and encrypted outbox remain intact.
3. Verify the account root, strongest saved membership highwater, authorization epoch, complete encrypted history and cross-epoch checkpoint proofs. Only a completed native read can sign the additive password `Unlock` enrollment. Login tokens alone cannot approve a device.
4. Re-register and verify the accepted enrollment. A lost reply or restart resumes the same credential and signed confirmation. A further complete active-device read is checked against the latest original owner, including edits made during verification.
5. Archive the exact original Core under an independent protected OS key, with durable file/key readback. The existing typed replacement publication alone may switch the selected identity. Ordinary state writers still cannot forge or replace selectors.
6. Review retained local history in the existing reconciliation screen, then merge and verify readback before automatic uploads resume. No export, empty library, account reset, pairing code or second App runtime is needed for device recovery.

## Retained history and credentials

When the original credential is available, the existing device-signed history capture retains supported historical images and epochs. If that credential has already been lost, a fully verified password replacement read can reopen same-epoch signed local envelopes and verify the original projection/material receipts. A versioned local history witness is signed by the independently approved replacement device and binds the exact original state, its staged password `Unlock` confirmation, original root and highwater. This is passive history, never write authority. Original files remain archived.

Content keys from an unavailable older epoch cannot be recreated from a Passkey or current sync password. If such retained content cannot be authenticated/decrypted, recovery fails closed and keeps the old owner, outbox and archive bytes. The UI explains the missing original credentials and retains public host/Group export. It does not claim a complete merge or discard unreadable content.

Old credential slots are never overwritten or deleted. Password enrollment preserves other approved devices; an old identity still approved on the server can be revoked in device settings. Previously revoked identities stay revoked and are never reused. Pending revocation/key rotation must finish on an authorized device before password enrollment.

## Boundaries and validation

Cloudflare and Docker use the existing account-unlock, enrollment, recovery-read/source-proof and signed-history endpoints; the server protocol and deployment topology do not change. Recovery never changes the process-selected library path. Switching account/server remains a separate explicit action.

Validate lost and refused credentials, wrong passwords, complete local data plus unsent changes, original slot preservation, lost enrollment replies/restart, late corrupt history, rollback floors and interrupted durable publication. Run relevant native/foreground UI tests, production build and all three platform CI jobs before merge/release.
