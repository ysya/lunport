# Records Migration UI Plan

Standing autonomous authorization and approved migration spec apply. Ownership: records frontend components/lib/tests, narrow App/Legacy landing integration, this plan/ledger. Root owns native commands and runtime; do not edit other workers' files.

Goal: explicit read-only preview -> old-client consent -> confirm -> status/receipt/pending recovery. Paused Legacy must offer migration without mounting legacy hooks. Failed account join retains code and offers an older-account migration preview without guessing schema from an error string.

- [x] RED tests for exact optional-code RPC args, consent enforcement, no secret/token query cache, partial receipt display/recovery, failure retention and lazy Legacy landing.
- [x] Direct typed client and component-only migration draft/controller, public pending query, cancelled-preview cleanup.
- [x] Migration panel/paused landing/failed-join entry; narrow active-Legacy migration entry. Confirm/resume cache only native public status after cancelling stale mode queries; do not infer activation.
- [x] Focused frontend tests and tsc; exact owned index-lock commit. No actual migration/vault/Keychain/relay/app execution. Root native migration currently being implemented; mocked contracts are not live acceptance.

Leave/rotation await actual implementation/DTO from compatibility worker. The worker confirmed they are not implemented yet; no invented RPC or success state.

Native pause seam: active Legacy toolbar first requires saved-editor acknowledgment, then records_pause_legacy() stops writers through the native barrier and returns public status. Only the paused landing offers authoritative preview. Read-only preview never pauses runtime itself. Existing editor stays mounted behind the acknowledgment until the native pause succeeds.

Verification: focused 73 records UI tests and tsc GREEN. Final complete frontend passed 61 files / 926 tests and the Vite production build. Native migration wrappers are registered and match DTOs; frontend tests use mocks, not real credentials or migration.
