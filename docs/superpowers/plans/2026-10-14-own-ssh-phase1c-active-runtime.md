# Own SSH phase 1c active runtime and record directory

Standing authorization: finish autonomous implementation while the user rests. Binding design is the 2026-10-14 migration spec. Foundation review fixes precede actual app launch. Keep existing Production legacy mode until an explicit migration confirmation; new users start in records mode.

## Ownership and contracts

- Runtime worker: new sync/record_runtime.rs and tests, narrowly add active records and explicit RuntimeFormat to existing SyncCore after compatibility worker releases runtime.rs. One core owner, no second mutable repository. Root owns module registration, engine startup/worker dispatch and native commands.
- Root: new session/record_directory.rs and tests; extend HostDirectory with endpoint-aware pin/read methods and default Legacy behavior; update session/connect calls and app adapter; minimum records UI and --id launch.
- Record-sync worker: new typed account/space merge+round+account/key lifecycle modules. Reuse crypto/reconcile/RelayApi, never old file/slot writers. Root owns dispatch.
- Import/migration worker: finalized read-only previews then durable journal and confirmed staged publication. No actual user migration; tests use temp files/MemKeychain/FakeRelay.
- Vault worker: truly read-only bounded reader with no repair/archive/key creation for preview and broker.

## Runtime

1. Probe bounded local bytes before the legacy loader. Missing file produces fresh version3 records; v1/v2 remain Legacy pending confirmation; valid3 activates Records; malformed or unsupported future bytes stay original and initialize Blocked mode with no credentials/network/writes. No automatic v1 upgrade in this mode switch.
2. All fields, generation and account keys remain under SyncCore. Normal tests default Legacy. Core records and legacy state are mutually exclusive; active records save never falls through state_v2::save. Blocked prevents both models from mutating.
3. Snapshot and immutable candidate mutations enforce expected generation under core, validate shape, atomic-save BEFORE replacing memory/generation. A failed user save preserves old state. Background partially accepted remote push acknowledgments persist against exact record revision and ciphertext; unsaved state retries before further network.
4. Native mode/snapshot/host CRUD/move/pin adapters use this runtime, not independent persistence. UI revisions survive failed save/conflict and revalidation cannot replace unsaved input.

## Directory and broker

1. Resolve ID or unique alias and every hop from one records snapshot. Enforce readiness for every hop, including actual vault material/public identity; no ssh -G, file Includes or private file fallback.
2. Build engine Hop from saved endpoint/auth/timeouts/pin. Empty user comes from verified OS identity via a source callback; failure refuses.
3. Pins remain host-record payloads. Add endpoint-aware directory methods accepting resolved HopRef; Legacy defaults retain existing behavior. Records compares endpoint and previous public key identity in durable candidate commit before accepting. Endpoint changes while host-key confirmation is open must refuse instead of pinning the new endpoint with the old key.
4. Password account is host:<id>; existing directory trait already supplies the correct namespace. Account public key metadata wins over local metadata; broker material identity check remains in place.
5. Test alias ambiguity, inactive/missing spaces, all-hop missing key, metadata conflicts, imported review, cycles/depth, real fixture engine, endpoint change during prompt, pin save failure and password IDs. No real credentials or hosts.

## Typed sync, accounts and keys

1. v3 account meta accepts3, gates4+ before any space apply/push. Known secret kinds stay sealed in disk state. Keep unknown envelopes to allow future decoder upgrades; reject malformed typed material without treating it as deletion.
2. Pull selected space records directly, preserve LWW/revisions/dirty/seq; no space config generation, agent refresh, slot links or retire files. Initial baseline from seq0 before outgoing writes. Freeze/rotation remain mutually exclusive with migration.
3. New account creation/join and space operations have durable pending operation steps for remote/Keychain/save partial failures, and deterministic retry identities. Joining old schema2 directs users to migration; never silently writes gate3.
4. Keys local by default. Only explicit sync seals private KeyPayload into account chain. Private text never enters public state/DTO/journal/logs. Material arrival is validated against account public metadata before local vault activation. Key/vault/state multi-file changes are staged and journaled; failures leave recoverable copies.

## Confirmed import and migration

Preview in memory only; confirm source digest and selected copies before creating journal. Journal prepared→account-gated→publishing→active stores public mapping/digests/receipts only. Original state/vault/config/pins remain backed up and untouched until staged activation; selected files copied, never moved/deleted. No rollback claim after relay writes. Capacity preflight includes retained old alias rows. Gate publication requires updated/stopped old-client confirmation. State/vault publication is resumable per file, not multi-file atomic.

## UI and cutover

Root App chooses Records/Legacy/Blocked before mounting legacy hooks. Records workspace offers stable-ID host list/edit/create/delete/move/connect, key import/generate/local vs sync, chain code join/create, spaces/select and import confirmation/retry. Record mode MCP/deploy remain explicitly unavailable until phase2. Preserve legacy mode's existing features and data; remove obsolete consumers only after new integrated flows pass. Final checklist distinguishes implemented/local checks/CI/real migration/release.

## Verification

TDD targeted regressions, full safe Rust/Vitest/typecheck/build, normal-library debug/release/dev-feature profile matrix, macOS/Linux/Windows CI through new draft feature PR. Independent immutable review of final active integration, not a repeat of the foundation review plan. No merge/release/real migration without later direct authorization.
