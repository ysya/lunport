# Record Repository Ledger

Pre-flight: read binding sections 5 and 8; verified LocalRecord, Record, AccountState, SealedRecord and v3 exports. Root owns registration/runtime and record_types owns records_v3.
Ruling: immutable clone transforms leave lock/generation/save-before-replace with SyncCore; a failed save discards candidate — avoids a second mutable owner — cost if wrong: adapter integration changes.
Ruling: KeyStatus::Available proves coherent public metadata and vault reference only; adapter verifies actual material before engine — preserves no-I/O boundary — cost if wrong: adapter must report NeedsKey.
Ruling: new IDs reserve all caches including inactive spaces/tombstones; moves reuse tombstones with seq and ordering preserved — avoids latent duplicate identities — cost if wrong: user generates a new ID.

Ruling: valid remote missing jumps, cross-record cycles and alias/ID conflicts remain visible as NeedsReview; malformed individual records still fail decode — permits convergence and repair without engine access — cost if wrong: adapters must enforce hop readiness.
Ruling: imported missing references persist only with an existing requires_review annotation, ordinary new broken edits fail — preserves importer provenance — cost if wrong: importer needs an unsupported directive instead.
Ruling: global duplicate ID prevents get/alias/route selection even when an alias is unique — no arbitrary endpoint or pin choice — cost if wrong: await convergence or explicit scoped repair.
RED: initial API stubs, all 17 behavior tests failed by unimplemented operation. GREEN: 17/17 harness.
RED: invalid account-host cache accepted; reject wrong kind/chain IDs. GREEN: 23/23 harness.
RED: unique alias selected one duplicate global ID; enforce unique ID. GREEN: 24/24 harness.
Official root integration: cargo focused record_repository suite 24/24 passed, 2092 filtered, log /private/tmp/sshelter-record-repository-integration.log. Final shared whole-suite gate remains root-owned after all modules integrate.
Final verification: CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --manifest-path src-tauri/Cargo.toml --offline --lib sync::record_repository:: → 24 passed, 0 failed, 2092 filtered. Log: /private/tmp/sshelter-record-repo-final-focused.log.
Owned review: checked cache kind/id and revision, endpoint/previous-pin CAS, move ordering, no I/O/private-material access, and all mutation error paths. Root owns independent integration review and whole-suite gate.
Task 1: pure repository implementation verified; source/tests/plan/ledger staged exactly under the shared index lock. Registration belongs to root's integration commit.
