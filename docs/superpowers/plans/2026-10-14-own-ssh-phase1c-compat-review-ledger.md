# Legacy compatibility review fix ledger

Scope: immutable review findings 2 and 4, plus finding 5 caller integration. One fix pass; no repeat review. No real home, vault, Keychain, relay, app launch, push or merge.

## Behavioral RED

- Five material commands waiting on runtime.vault still succeeded after authenticated schema 3 publication: delete_copy, delivery in both directions, pick, use_synced. Log /private/tmp/sshelter-review-material-red-all.log.
- start_rotation encountered a confined state symlink only after two Keychain calls. Log /private/tmp/sshelter-review-rotation-red.log.
- An observer delayed by an active transaction dropped authenticated schema 3 after that transaction changed generation. Log /private/tmp/sshelter-review-delayed-observer-red.log.
- Prior retirement caller ordering changed encrypted vault bytes before rejecting the escaping planned .pub destination (both pick and delivery). Reversible try/finally harness restored GREEN source. Log /private/tmp/sshelter-review-retirement-red.log. Initial fixture hit unrelated tilde Include expansion; corrected scoped temp-home plus exact denied-destination assertion before accepting RED evidence.

## Implementation and rulings

- Explicit MaterialTransaction owns vault -> format_publication through filesystem/Keychain materials and final state commit. It checks the latest core format only after both locks. Observer takes publication -> core; no doc/core is held when starting a transaction. Nested helpers receive a token and use Vault::open directly under the already-held vault lock. Store open/save/missing-key/archive behavior is unchanged for allowed legacy writes.
- A waiting vault command cannot block observation. An already-started transaction linearizes at its latest-format check and completes before a later observer publishes a gate. Cost: format publication waits for that active transaction, including its Keychain access. This is client-local serialization; it provides no server atomic migration guarantee.
- Delayed authenticated newer-format evidence is monotonic across generation changes only for the same latest legacy account chain and exact relay. It updates gate/error only, retains latest complete caches/cursors/dirty/pending content, rejects replaced/absent state, and causes subsequent material commands to refuse. Future active records mode must also reject legacy publication; root owns that cutover after this handoff.
- Regular mutate/commit reject the latest read-only format before invoking their closure. Account-only observation has a separate narrow gate/error commit so repeated polling remains possible.
- Shared token coverage: pick/use_synced/set_mode/delete_copy/set_delivery; local key add/import/restore and source-file move; setup/create/reuse/adopt/land/cleanup; background local and synced slot maintenance. Batch move uses guarded per-slot delivery. Agent refresh and blocking applied/notices callbacks happen after token release; existing wake counts are retained after release.
- Entry start_rotation calls saves_allowed before credentials, relay, generated progress or mutation. Confined state denial gives zero Keychain/relay calls and unchanged state/generation/sentinel.
- OwnKey retirement is planned before vault replacement/passphrase deletion; the same plan executes after those effects. Writer helper owns suffix selection and collision refusal. Cost: a filesystem collision after preflight may still stop a started transaction; the existing recovery contract retains original material.
- Existing unrelated save_blocked recovery/harmless-no-commit contracts are preserved; local_snapshot/mutate/saves_allowed keep their prior checks. Token is specifically the latest-format boundary.
- Preserve original clock sampling positions. A test-only probe signals the actual vault-wait boundary without a production timing change. One existing same-thread Clock/with_vault reentry fixture now models an external process using direct Vault::open; original changed/lost key rejection assertions remain intact.

## Verification

Focused only, offline and locked, no OS credential tests selected:
CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib sync::<module>::tests

Final module logs /private/tmp/sshelter-review-final-<module>.log. Final GREEN: runtime 8, slots 232 (includes seven deterministic wait races and two retirement boundaries), local_keys 68, slot_setup 73, rotation 49, round 58; total 488/488. Compiled worktree base HEAD 59beff4636ab1e5fbc16bc48cde48a957845bea3. Root owns latest integrated safe suite/profile matrix. git diff --check clean; no unrelated formatting changes.
