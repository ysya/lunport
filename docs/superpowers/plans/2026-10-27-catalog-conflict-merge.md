# Catalog Conflict Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A central-sync Catalog conflict keeps both devices' changes. Changes to different items merge on their own in the same round, and only items both devices changed differently are reviewed, in plain words.

**Architecture:**
- **The rule.** A pure three-way merge (`catalog_merge.rs`) compares the common, this device's and the synced Catalog item by item, and fits the result into one record.
- **The state transition.** `catalog_conflict.rs` reads the merged Catalog into this device's rows with the delta projection's reader. It then replaces the Catalog's pending draft through the review's existing retire path, confirmed on the synced version.
- **Where it runs.** The central dispatch's prepare runs the transition automatically when nothing collides. The review runs it with a side chosen for the colliding items.
- **A refused push.** A push the relay refuses with 409 `revision_conflict` makes the round pull again instead of failing.

**Tech Stack:** Rust (Tauri 2 backend, `src-tauri/src/sync/central`), React + TypeScript (vitest, `renderToStaticMarkup`).

**Spec:** `docs/superpowers/specs/2026-10-27-catalog-conflict-merge-design.md` (approved by Frank 2026-10-27, both open questions as recommended: a collision keeps the whole Catalog waiting; calls 8–13 accepted).

## Global Constraints

- **No wire change.** No change to the relay, the wire format, `Catalog`'s shape or its limits (`Catalog::validate`: 256 routes `MAX_ROUTES`, 256 tunnels, 256 collections, 257 group orders, 4096 ordered groups; `catalog_fits`: `MAX_PLAINTEXT_BYTES`, 64 KiB).
- **Stack.** The sync path already nears the debug-build stack. Every new function that returns a whole state returns `Box<SyncStateV3>` (or takes and returns it by value through existing helpers), and holds at most one full state per frame. The re-pull is a `continue` of `active_cycle::with_budget`'s loop, never recursion.
- **Background sync.** The automatic merge takes no recovery snapshot and shows no notice. Review choices keep today's snapshot (`conflicts::resolve`).
- **Write gates.** Both the automatic merge and a review choice respect the library's write gates: `records_v3::account_writes_blocked`, `migration_flow::refresh_edit_gate`, and `central_migration_frozen`.
- **Test data.** Tests use synthetic values only: project `acme-dev-654321`, account `frank@example.com`, hosts `*.invalid`. Never a real project id or account.
- **UI copy** is English, with typographic apostrophes (’) as the existing conflict UI uses. Exact strings are in Tasks 2 and 8.
- **Commits** follow Conventional Commits, with no attribution lines.
- **Before committing**, revert ts-rs binding noise (`git checkout -- src/bindings/`) unless a task adds a binding, and run `git diff --check`.

## Review Focus

1. **The first route arriving through a merge.** A device at `CENTRAL_STATE_VERSION` (no routes yet) merges the other device's first route. The merge's ordinary save must raise the state to `transports::SYNC_STATE_VERSION` and succeed. Test in Task 5.
2. **A route whose host this device deleted.** "Removed here, edited there" collides. The review names the host by its id, because its alias is gone. Test in Task 8.
3. **A second Catalog choice on the same device.** The recovery snapshot reuses its per-record operation key, so a later Catalog conflict on the same device must still resolve. Test in Task 7.
4. **A library frozen for an encrypted migration.** No automatic merge runs, and the conflict waits. Test in Task 5.
5. **A third device pushing during the merge round.** The round pulls and merges again until its bound, then fails as today, and nothing is lost. Test in Task 6.

---

## Before Task 1: the base

This work starts once PR #93 (`claude/google-tunnel-ui-design-c3a057`) is on `main`. Then, in the worktree `/Users/ysya/project/sideproj/lunport/.claude/worktrees/stoic-snyder-8c0e08`:

```bash
git fetch origin
git rebase --onto origin/main f6a5ff56
```

This keeps the spec and plan commits on the new `main` and drops the base merge. Then check:

- `git log --oneline origin/main..HEAD` shows only the docs commits;
- `.cargo/config.toml` (the test stack, `RUST_MIN_STACK`) is present.

In the commands below, `$CARGO` stands for `cargo test --manifest-path /Users/ysya/project/sideproj/lunport/.claude/worktrees/stoic-snyder-8c0e08/src-tauri/Cargo.toml --locked --lib --`.

---

### Task 1: The merge rule

**Files:**
- Create: `src-tauri/src/sync/central/catalog_merge.rs` (with its `#[cfg(test)] mod tests`)
- Modify: `src-tauri/src/sync/central/mod.rs` (add `mod catalog_merge;`)

**Interfaces:**
- Produces:
  - `pub enum Side { Local, Remote }` (`Clone, Copy, Debug, PartialEq, Eq`).
  - `pub enum Collision`, with `#[derive(Clone, Debug, PartialEq, Serialize)]` and `#[serde(tag = "kind", rename_all = "snake_case")]`. Variants:
    - `Tunnel { id: String, local: Option<TunnelRule>, remote: Option<TunnelRule> }`
    - `Route { host_id: String, local: Option<HostTransport>, remote: Option<HostTransport> }`
    - `Collection { id: String, local: Option<String>, remote: Option<String> }` (the names)
    - `GroupOrder { scope: HostScope, local: Option<Vec<String>>, remote: Option<Vec<String>> }`
  - `pub struct Merged { pub catalog: Catalog, pub collisions: Vec<Collision>, pub new_routes: Vec<String> }`. `new_routes` holds the host ids of routes absent from both the common and the synced Catalog and present in this device's.
  - `pub fn merge(common: Option<&Catalog>, local: &Catalog, remote: &Catalog, keep: &BTreeSet<String>, side: Option<Side>) -> Merged`

- [ ] **Step 1: Write the failing tests** in `catalog_merge.rs`. Build Catalogs from small helpers: a tunnel `tunnel(id, port)` on host `"0000000000000001"`, a route `route(host, zone)` with project `acme-dev-654321`, and collections with 64-hex ids.

```rust
#[test] fn different_items_from_both_devices_all_survive()
// common: tunnels [a], routes [h1]; local: + tunnel b, + route h2; remote: + tunnel c, + route h3
// merged tunnel ids == {a, b, c}; route hosts == {h1, h2, h3}; collisions empty; new_routes == [h2]
#[test] fn a_change_on_one_side_takes_that_change()
// remote changes tunnel a's port, local untouched -> remote's a; local changes route h1's zone, remote untouched -> local's h1
#[test] fn the_same_change_on_both_sides_does_not_collide()
// both remove tunnel a -> absent; both add an identical route h4 -> present; collisions empty
#[test] fn different_changes_to_one_item_collide()
// tunnel a: two different ports -> Collision::Tunnel { id: a, local: Some(..), remote: Some(..) }
// route h1: removed here, zone changed there -> Collision::Route { local: None, remote: Some(..) }
// a collection renamed to "Work" here and "Clients" there -> Collision::Collection { local: Some("Work"), remote: Some("Clients") }
// the Local group order reordered both ways -> Collision::GroupOrder { scope: HostScope::Local, .. }
// tunnel e renamed here and re-ported there -> collides (an item is the smallest unit)
// route h4 added on both sides with different zones -> Collision::Route { local: Some(..), remote: Some(..) }
#[test] fn a_side_settles_every_collision()
// merge(.., Some(Side::Local)) -> collided items hold local's values, collisions empty; Some(Side::Remote) -> remote's
#[test] fn without_a_common_version_every_difference_collides()
// common None: identical items merge, a tunnel only this device has collides (local Some, remote None)
#[test] fn a_kept_collection_stays_with_its_order()
// remote removed collection X and its Space group order; keep = {X} -> merged keeps X (local's name) and its order;
// keep empty -> X and its order are gone
#[test] fn the_merged_order_is_the_synced_order_then_this_devices_new_items()
```

- [ ] **Step 2: Run them and see them fail**

Run: `$CARGO sync::central::catalog_merge`
Expected: FAIL to compile (`merge` not defined).

- [ ] **Step 3: Implement `merge`**

For every key in any of the three lists of each kind, with c/t/s the common, local and synced value (`None` when absent; when `common` is `None`, c is unknown and only t = s merges):

```
t == c  -> s        s == c -> t        t == s -> t        else -> collision: side's value, or s when side is None
```

Further rules:
- A collection in `keep` that the synced side removed takes this device's value, and so does its Space group order.
- Space group orders whose collection is absent from the merged collections are dropped.
- Order: synced items in synced order, then items only this device has, in its order.

- [ ] **Step 4: Run the tests and see them pass**

Run: `$CARGO sync::central::catalog_merge`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync/central/catalog_merge.rs src-tauri/src/sync/central/mod.rs
git commit -m "feat(central): merge two Catalogs item by item against their common version"
```

---

### Task 2: Room for the merged Catalog

**Files:**
- Modify: `src-tauri/src/sync/central/catalog_merge.rs`

**Interfaces:**
- Consumes: `Merged` (Task 1), `payload::catalog_fits`.
- Produces:
  - `pub enum Over { Tunnels(usize), Collections(usize), GroupOrders, Size }` (`Clone, Debug, PartialEq, Eq`).
  - `impl Over { pub fn sentence(&self) -> String }`.
  - `pub struct Fitted { pub catalog: Catalog, pub stay_local: Vec<HostTransport> }`.
  - `pub fn fit(merged: Merged) -> Result<Fitted, Over>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn a_merge_that_fits_keeps_everything()            // stay_local empty, catalog == merged.catalog
#[test] fn this_devices_new_routes_that_do_not_fit_stay_local_in_host_id_order()
// synced Catalog near the record limit (routes at their longest, as payload.rs's tests build them);
// this device's new routes h5 < h6 < h7, only h5 fits -> catalog holds h5; stay_local == [h6, h7]
#[test] fn too_many_tunnels_is_over_with_their_count()
// 262 tunnels -> Err(Over::Tunnels(262)), and its sentence is exactly:
// "Together, both devices’ changes hold 262 tunnels; a library holds at most 256. Remove some tunnels or routes on this device; Lunport combines both devices’ changes on the next sync."
#[test] fn too_many_collections_is_over_with_their_count()  // 257 -> Over::Collections(257)
#[test] fn a_catalog_over_one_record_is_over_by_size()
// 256 tunnels with names at their longest and routes at their longest -> Over::Size, sentence:
// "Together, both devices’ changes are more than one library record holds (64 KB). Remove some tunnels or routes on this device; Lunport combines both devices’ changes on the next sync."
```

- [ ] **Step 2: Run them and see them fail**

Run: `$CARGO sync::central::catalog_merge`
Expected: FAIL to compile (`fit` not defined).

- [ ] **Step 3: Implement `fit` and `Over::sentence`**

`fit` takes `new_routes` out first. It then checks, in this order:
1. tunnels > 256 → `Tunnels(n)`;
2. collections > 256 → `Collections(n)`;
3. group orders > 257, or their ids together > 4096 → `GroupOrders`;
4. `!catalog_fits` → `Size`.

It then adds this device's new routes back in host-id order while `catalog_fits` holds. The first one that does not fit, and every one after it, goes to `stay_local`. The remaining sentences:
- `Collections`: "Together, both devices’ changes hold {n} collections; a library holds at most 256. Remove some collections on this device; Lunport combines both devices’ changes on the next sync."
- `GroupOrders`: "Together, both devices’ changes order more groups than one library holds (4096). Remove some groups on this device; Lunport combines both devices’ changes on the next sync."

- [ ] **Step 4: Run the tests and see them pass**

Run: `$CARGO sync::central::catalog_merge`
Expected: PASS (13 tests).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync/central/catalog_merge.rs
git commit -m "feat(central): fit a merged Catalog into one record and leave this device's extra routes local"
```

---

### Task 3: A long conflict cannot stop sync

**Files:**
- Modify: `src-tauri/src/sync/central/replica.rs` (`validate` at the conflicts loop; `prepare_page` where it pushes a `Conflict`)
- Modify: `src-tauri/src/sync/central/projection_capture.rs` (`public_candidate` where it pushes a `Conflict`)
- Modify: `src-tauri/src/sync/central/controller.rs` (`status`, the `conflicts` count)

**Interfaces:**
- Produces:
  - `pub const MAX_CONFLICT_ENTRIES: usize = 16;` in `replica.rs`.
  - `pub(super) fn keep_latest(entries: &mut Vec<Conflict>)`, which drops the oldest entries beyond the cap.

- [ ] **Step 1: Write the failing tests**

```rust
// replica.rs tests
#[test] fn a_conflicted_record_keeps_its_16_latest_entries()
// a pending record, then 17 newer remote versions through prepare_page -> 16 entries, the oldest gone, validate() Ok
// projection_capture.rs tests
#[test] fn local_edits_while_in_conflict_keep_the_entries_bounded()
// a host conflict, then 17 different local aliases each captured -> entries <= 16, public_candidate Ok
// controller status (beside conflicts.rs's status test, same fixture)
#[test] fn the_status_counts_records_in_conflict_not_their_entries()
// one host record with 3 entries -> status.conflicts == 1
```

- [ ] **Step 2: Run them and see them fail**

Run: `$CARGO sync::central::replica sync::central::projection_capture sync::central::conflicts`
Expected: FAIL. The first two err on `validate`, and the count is 3.

- [ ] **Step 3: Implement**

- `keep_latest` runs after each push at both sites.
- `validate` uses `MAX_CONFLICT_ENTRIES`.
- `status` counts `r.conflicts.len()`.

- [ ] **Step 4: Run them and see them pass**

Run: the same command. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync/central/replica.rs src-tauri/src/sync/central/projection_capture.rs src-tauri/src/sync/central/controller.rs
git commit -m "fix(central): keep a conflict's 16 latest entries and count conflicted records"
```

---

### Task 4: Merging a conflicted Catalog into this device's state

**Files:**
- Create: `src-tauri/src/sync/central/catalog_conflict.rs` (with tests); add `mod catalog_conflict;` to `central/mod.rs`
- Modify: `src-tauri/src/sync/central/conflicts.rs`:
  - make `open` and `settled` `pub(super)`;
  - extract `retire_conflict` from the tail of `candidate`, from `let owner = next.local.central.as_mut()` to `records_v3::validate_state`.
- Modify: `src-tauri/src/sync/central/projection_capture.rs` (make `basis_of` `pub(super)`)
- Modify: `src-tauri/src/sync/central/projection_delta.rs`:
  - make `catalog` `pub(super)`;
  - extract `holds_local` from `Delta::prepare`'s `loses_local_or_live` and use it there.
- Modify: `src-tauri/src/sync/transports.rs` (add `keep_on_this_device`)

**Interfaces:**
- Consumes: `merge`, `fit`, `Side`, `Collision`, `Over` (Tasks 1–2).
- Produces:
  - `pub(super) fn retire_conflict(state: SyncStateV3, keys: &VaultKeys, signer: &DeviceKeys, id: &str, draft: Option<(&Identity, &Data)>, remote: &Base) -> Result<SyncStateV3, AppError>`. `candidate` calls it with `None` for `Choice::Remote` and with this device's identity and data otherwise; its behaviour does not change.
  - `pub(super) fn holds_local(state: &SyncStateV3, ledger: &Ledger, replica: &Replica, space_id: &str) -> bool`.
  - `pub(crate) fn keep_on_this_device(state: &SyncStateV3, route: HostTransport, now: u64) -> Result<SyncStateV3, RepositoryError>`. It writes the route to `local.transports`, as the private `write` does.
  - In `catalog_conflict.rs`:
    - `pub(super) struct Versions { pub opaque: String, pub common: Option<Catalog>, pub local: Catalog, pub remote: Catalog, pub remote_base: Base, pub keep: BTreeSet<String> }`
    - `pub(super) fn versions(state: &SyncStateV3, keys: &VaultKeys) -> Result<Option<Versions>, AppError>`. It returns `None` when the Catalog has no conflict. `common` comes from `basis_of`, opened with `conflicts::open`; it is `None` when that fails. `local` is `catalog_of(state, &ledger.catalog)`. `keep` holds the collections the synced Catalog removed that `holds_local`.
    - `pub(super) enum Outcome { Merged(Box<SyncStateV3>), Collides(Vec<Collision>), Over(Over) }`
    - `pub(super) fn apply(state: &SyncStateV3, keys: &VaultKeys, signer: &DeviceKeys, side: Option<Side>, now: u64) -> Result<Outcome, AppError>`

- [ ] **Step 1: Write the failing tests** in `catalog_conflict.rs`.

Build the conflict the way `projection_capture`'s `the_publish_step_waits_…` test does:
- start from `projection_state::tests::initial()`;
- write this device's change as account rows (`tunnel_rules::wire_id`, `transports::wire_id`);
- run `capture_public`;
- add the other device's Catalog with `projection_delta::tests::append`;
- run `capture_public` again.

```rust
#[test] fn a_merge_reads_both_devices_items_into_this_devices_rows()
// here: tunnel b + route h2; there: tunnel c + route h3 -> Outcome::Merged(next):
// tunnel_rules::view(&next) has b and c; transports::get(&next, h2/h3) are Some and synced;
// the Catalog has no conflict entry; its pending draft decodes to catalog_of(&next, ledger.catalog),
// expects the current revision and is confirmed on the current version; capture_public(&next) == *next
#[test] fn a_collision_changes_nothing_and_is_reported()
// tunnel a changed both ways -> Outcome::Collides([Collision::Tunnel { .. }])
#[test] fn an_edit_not_yet_captured_is_merged_not_overwritten()
// after the conflict, add tunnel d to the rows without capturing -> next has d
#[test] fn a_collection_the_other_device_removed_stays_while_this_device_has_hosts_in_it()
#[test] fn this_devices_routes_that_do_not_fit_stay_on_this_device()
// -> next.local.transports holds them, transports::synced is false, transports::local_routes(&next).no_room has them
#[test] fn a_catalog_over_its_room_is_not_merged()      // -> Outcome::Over(Over::Tunnels(n)), state untouched
#[test] fn a_chosen_side_settles_the_collision()      // apply(.., Some(Side::Local)) -> Merged; the tunnel is local's
```

- [ ] **Step 2: Run them and see them fail**

Run: `$CARGO sync::central::catalog_conflict`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `versions` and `apply`**

`apply` runs:
1. `merge` with `side`. Collisions with `side` `None` → `Collides`.
2. `fit`. `Err` → `Over`.
3. On a clone, `projection_delta::catalog` with the fitted Catalog. Its `Receipt` is built from `remote_base`: `kind` `"meta"`, `id` `"catalog"`, the version's revision, sequence, digest, author, membership head and epoch, and the semantic hash of the synced Catalog.
4. `keep_on_this_device` for each `stay_local` route.
5. `retire_conflict` with `Data::Catalog(catalog_of(&next, &ledger.catalog))` against `remote_base`.

Box the result.

- [ ] **Step 4: Run them and see them pass**

Run: `$CARGO sync::central::catalog_conflict sync::central::conflicts sync::central::projection_delta sync::transports`
Expected: PASS. The `conflicts` and `projection_delta` suites stay green through the refactors.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync/central/catalog_conflict.rs src-tauri/src/sync/central/mod.rs src-tauri/src/sync/central/conflicts.rs src-tauri/src/sync/central/projection_capture.rs src-tauri/src/sync/central/projection_delta.rs src-tauri/src/sync/transports.rs
git commit -m "feat(central): merge a conflicted Catalog into this device's rows and draft"
```

---

### Task 5: The automatic merge in the dispatch

**Files:**
- Modify: `src-tauri/src/sync/central/catalog_conflict.rs` (add `merge_automatically` with its tests)
- Modify: `src-tauri/src/sync/central/active_dispatch.rs` (add `merge_catalog`, called in `prepare` before `publish_local_routes`)
- Test: `src-tauri/src/sync/central/active_cycle_tests.rs`

**Interfaces:**
- Consumes: `apply`, `conflicts::settled` (Task 4).
- Produces:
  - `pub(super) fn merge_automatically(state: &SyncStateV3, keys: &VaultKeys, signer: &DeviceKeys, now: u64) -> Result<Option<Box<SyncStateV3>>, AppError>`. It returns `None` when:
    - `account_writes_blocked(state)`, or
    - after `capture_public(state)`, the Catalog has no conflict or it is not `settled`, or
    - `apply(captured, .., None, now)` is not `Merged`.
  - `fn merge_catalog(env: &SyncEnv, state: &SyncStateV3, keys: &VaultKeys, signer: &DeviceKeys) -> Result<bool, AppError>`, shaped like `publish_local_routes`:
    - it uses the same gates;
    - it saves through `record_runtime::mutate_records`, which recomputes on the latest state;
    - when it saves, `prepare` re-snapshots and re-checks `fresh`.

- [ ] **Step 1: Write the failing tests**

```rust
// catalog_conflict.rs
#[test] fn the_automatic_merge_waits_for_a_settled_conflict()   // a claimed receipt on the Catalog -> None
#[test] fn the_automatic_merge_leaves_a_collision_for_review()  // -> None
#[test] fn the_automatic_merge_leaves_a_library_that_refuses_edits() // account_writes_blocked -> None
// active_cycle_tests.rs (the round fixture; the other device through remote_catalog)
#[test] fn a_tunnel_saved_while_another_device_changed_the_catalog_merges_in_one_round()
// round once; save tunnel b on this device (not yet captured); remote_catalog adds tunnel c; round::sync_once Ok ->
// tunnel_rules::view has b and c; no Catalog conflict or pending; the ledger's Catalog (what the library holds) has b and c;
// status error None
#[test] fn the_first_route_a_merge_brings_raises_the_state_version()
// device at CENTRAL_STATE_VERSION saves tunnel b; remote_catalog adds a route -> after the round, version == transports::SYNC_STATE_VERSION
#[test] fn a_library_frozen_for_migration_keeps_its_catalog_conflict()
// central_migration_frozen = true during the round -> the conflict stays, rows unchanged
#[test] fn a_catalog_over_its_room_merges_once_this_device_removes_a_tunnel()
// remote_catalog with 250 tunnels; this device saves 10 more -> the round leaves the conflict (Over::Tunnels(260));
// this device removes 4 of its own -> the next round merges, and the library holds 256
```

- [ ] **Step 2: Run them and see them fail**

Run: `$CARGO sync::central::catalog_conflict sync::central::device_tests::active_cycle_tests`
Expected: FAIL: `merge_automatically` is undefined, and the round ends with the Catalog in conflict.

- [ ] **Step 3: Implement** `merge_automatically` and `merge_catalog`, and call it in `prepare`.

- [ ] **Step 4: Run them and see them pass**

Run: the same command. Expected: PASS, with the rest of `active_cycle_tests` still green.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync/central/catalog_conflict.rs src-tauri/src/sync/central/active_dispatch.rs src-tauri/src/sync/central/active_cycle_tests.rs
git commit -m "feat(central): merge a Catalog conflict without collisions before the capture"
```

---

### Task 6: A refused push pulls again (the done criterion)

**Files:**
- Modify: `src-tauri/src/sync/central/api.rs` (add `Reply::refused_revision`, with a test)
- Modify: `src-tauri/src/sync/central/active_cycle.rs` (`with_budget`)
- Modify: `src-tauri/src/sync/central/device_tests.rs` (`Account` gains `race: Vec<super::rekey::Version>`, of which each push takes the first, and `refuse_pushes: Vec<&'static str>`)
- Modify: `src-tauri/src/sync/central/active_cycle_tests.rs`:
  - `install_push`;
  - split `remote_catalog` into `remote_catalog_version(f, edit) -> rekey::Version`, plus the push;
  - add `remote_host_version(f, id, alias) -> rekey::Version`, built as `a_local_b_during_http…` builds its row.

**Interfaces:**
- Produces:
  - `pub fn refused_revision(&self) -> bool`: true for status 409 with body `error` `"revision_conflict"`.
  - `const MAX_REFUSED_PUSHES: usize = 3;` in `active_cycle.rs`.
- The fake push decides once per request, shared between its status and body closures:
  1. it first appends the first version of `race` to the history, if any;
  2. it answers 409 `{"error": <first of refuse_pushes>}` when that list is non-empty;
  3. it answers 409 `{"error":"revision_conflict","conflicts":[…]}` and writes nothing when any row's expected revision is stale, as `relay/src/v2/store.ts` does. Today it asserts instead.

- [ ] **Step 1: Write the failing tests**

```rust
// api.rs
#[test] fn only_a_revision_conflict_is_a_refused_revision()
// 409 {"error":"revision_conflict","conflicts":[]} -> true; 409 {"error":"retry"} -> false; 200 -> false
// active_cycle_tests.rs
#[test] fn two_devices_racing_catalog_pushes_both_keep_their_tunnels_and_routes()
// Hosts h_a, h_b in the library (created, one round). This device: tunnel b on h_b, route on h_b (transports::set).
// The other device: race = remote_catalog_version(+ tunnel a on h_a, + route on h_a) — its push lands just before this one.
// One round::sync_once -> Ok, and in that one call: two pushes recorded (the refused one, then the merged one);
// tunnel_rules::view has a and b; transports::get(h_a) and (h_b) are Some and synced;
// no Catalog conflict or pending; the ledger's Catalog (the library's latest) holds both tunnels and both routes;
// central_user_action is None and central_poll.retry_at is None
#[test] fn a_host_race_reaches_review_in_the_refused_round()
// this device renames host h; race = remote_host_version(h, "other-name") -> Ok; status.conflicts == 1; error None; retry_at None
#[test] fn a_push_refused_for_another_reason_still_fails_the_round()
// refuse_pushes = ["retry"] -> Err; central_user_action Some
#[test] fn a_round_stops_pulling_again_after_three_refusals()
// refuse_pushes = 4 × "revision_conflict" -> Err after 4 pushes; nothing lost: the pending draft remains
#[test] fn a_third_device_pushing_during_the_merge_round_is_merged_too()           // Review Focus 5
// race = [v1 (+ tunnel a), v2 (+ tunnel c, computed on the history after v1)]; this device saves tunnel b ->
// one round Ok; the library's Catalog holds a, b and c; no conflict, no error status
```

- [ ] **Step 2: Run them and see them fail**

Run: `$CARGO sync::central::api sync::central::device_tests::active_cycle_tests`
Expected: FAIL. `refused_revision` is undefined, and the race round errs with "The account or record changed."

- [ ] **Step 3: Implement**

In `with_budget`, after the 401/403 renewal check:
- if `reply.refused_revision()` and fewer than `MAX_REFUSED_PUSHES` refusals have been seen this round, count it and `continue`;
- otherwise call `round::require_success` as today.

- [ ] **Step 4: Run them and see them pass**

Run: the same command. Expected: PASS, with every existing `active_cycle_tests` and `device_tests` test still green.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync/central/api.rs src-tauri/src/sync/central/active_cycle.rs src-tauri/src/sync/central/device_tests.rs src-tauri/src/sync/central/active_cycle_tests.rs
git commit -m "feat(central): pull again in the same round when the relay refuses a stale revision"
```

---

### Task 7: The review of a Catalog collision (backend)

**Files:**
- Modify: `src-tauri/src/sync/central/catalog_conflict.rs` (add `CatalogReview` and `review`)
- Modify: `src-tauri/src/sync/central/conflicts.rs` (`View`, `views`, `candidate`)

**Interfaces:**
- Consumes: `apply`, `versions` (Task 4).
- Produces:
  - `#[derive(Serialize)] pub struct CatalogReview { pub items: Vec<Collision>, pub over: Option<String>, pub can_local: bool, pub can_remote: bool }`.
  - `pub(super) fn review(state: &SyncStateV3, keys: &VaultKeys) -> Result<Option<CatalogReview>, AppError>`:
    - `items` holds the collisions of `merge(.., None)`;
    - `can_local` and `can_remote` say whether `fit` succeeds with that side;
    - `over` holds a sentence when there are no items and the merge does not fit, or when neither side fits.
  - `View` gains `catalog: Option<CatalogReview>`. It is set only for the Catalog. The Catalog row's `can_remote` is `can_resolve && review.can_remote`.
  - `candidate` routes a Catalog choice through `apply(.., Some(side), now)`:
    - `Choice::Local` → `Side::Local`, `Choice::Remote` → `Side::Remote`;
    - `Choice::CopyRemote` → `Err(invalid())`;
    - `Outcome::Over(o)` → `Err(AppError::Other(o.sentence()))`.

- [ ] **Step 1: Write the failing tests** in `conflicts.rs`, with Task 4's conflict builder exposed as `pub(in crate::sync::central)`.

```rust
#[test] fn a_catalog_conflict_lists_only_the_colliding_items()
// tunnel a changed both ways, plus a route each side added -> catalog.items == [Collision::Tunnel { id: a, .. }];
// can_local && can_remote; local/remote JSON are not needed by the UI for this row
#[test] fn each_catalog_choice_keeps_every_other_change()
// Choice::Local -> tunnel a is this device's, both routes present; Choice::Remote -> tunnel a is the synced one, both routes present
#[test] fn a_catalog_choice_that_does_not_fit_is_not_offered()
// only the local side overflows tunnels -> can_local false, can_remote true; candidate(Local) errs with the Tunnels sentence
#[test] fn a_collision_free_catalog_conflict_waits_for_the_next_sync()
// -> items empty, over None, can_local and can_remote false
#[test] fn a_collision_free_catalog_conflict_over_its_room_says_so()
// 262 tunnels together -> items empty, over == Over::Tunnels(262).sentence(), no choices
#[test] fn keeping_both_is_refused_for_the_catalog()        // candidate(CopyRemote) -> Err
#[cfg(any(unix, windows))] #[test]
fn catalog_choices_are_durable_and_a_later_one_still_resolves()
// as native_resolution_is_durable_and_rejects_replayed_reviews: resolve a Catalog collision (snapshot kept),
// then raise a second Catalog collision on the same device and resolve it too
```

- [ ] **Step 2: Run them and see them fail**

Run: `$CARGO sync::central::conflicts sync::central::catalog_conflict`
Expected: FAIL to compile (`catalog` is not a field of `View`).

- [ ] **Step 3: Implement** `review`, the `View` field and the `candidate` routing.

- [ ] **Step 4: Run them and see them pass**

Run: the same command. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync/central/catalog_conflict.rs src-tauri/src/sync/central/conflicts.rs
git commit -m "feat(central): review only the Catalog items both devices changed"
```

---

### Task 8: The Catalog row in Central conflicts (frontend)

**Files:**
- Modify: `src/lib/central-sync.ts` (types)
- Create: `src/components/records/CatalogConflict.tsx`
- Modify: `src/components/records/CentralConflicts.tsx`
- Test: `src/components/records/catalog-conflict.test.tsx`

**Interfaces:**
- Consumes: the JSON of `CatalogReview` (Task 7). `HostScope` is `{ kind: "local" } | { kind: "space"; space_id: string }` (`src/lib/records.ts`).
- Produces, in `central-sync.ts`:
  - `export type CatalogCollision`, a union on `kind`:
    - `"tunnel"` with `id` and `local`/`remote` as `TunnelRule | null`;
    - `"route"` with `host_id` and `HostTransport | null`;
    - `"collection"` with `id` and `string | null`;
    - `"group_order"` with `scope: HostScope` and `string[] | null`.
  - `export type CatalogReview = { items: CatalogCollision[]; over: string | null; can_local: boolean; can_remote: boolean }`.
  - `CentralConflict` gains `catalog: CatalogReview | null`.
- Produces, in `CatalogConflict.tsx`:
  - `collisionLabel(item: CatalogCollision, overview?: RecordOverview): string`
  - `collisionValue(item: CatalogCollision, side: "local" | "remote", overview?: RecordOverview): string`
  - `catalogChoiceTitle(choice: "local" | "remote"): string`
  - `CATALOG_CHOICE_NOTE`
  - `CatalogConflictView({ review, overview, disabled, choose }: { review: CatalogReview; overview?: RecordOverview; disabled: boolean; choose: (choice: "local" | "remote") => void })`

Exact copy:

| Where | Text |
|---|---|
| Row title | Tunnels, routes and collections |
| Collision sentence | Another device changed the same items at the same time. When you choose, Lunport keeps every other change from both devices. Until then, changes to tunnels, routes and collections wait on this device. |
| No items and no `over` | Lunport combines both devices’ changes on the next sync. |
| Buttons | Keep this device’s versions… · Use the synced versions… |
| Dialog titles | Keep this device’s versions of these items? · Use the synced versions of these items? |
| `CATALOG_CHOICE_NOTE` | Every other change from both devices stays. Previous versions are kept in an encrypted local recovery snapshot on this device. |
| Labels | Tunnel “{name}” · Google Cloud route of “{host alias}” · Name of collection “{name}” · Group order · Group order in “{collection name}” |
| A side's `null` | Removed |

Labels name the item by this device's version when it has one, else by the synced version. Unknown hosts, groups and collections show their id.

Values:

| Item | Value |
|---|---|
| Tunnel | `tunnelRoute(rule)` + ` through {host alias}`, prefixed with `“{name}” · ` when the two names differ |
| Route | `iapTarget(kind)` + ` · {zone}`, then `, account {account}`, `, OS Login`, `, PAM {entitlements, comma-separated}` for whichever is set |
| Collection | its name |
| Group order | the group names, comma-separated |

- [ ] **Step 1: Write the failing tests** (`renderToStaticMarkup`, as `google-cloud.test.tsx` does).

```tsx
it("names each colliding item and its two versions in plain words")
// a tunnel on "prod-jump" (127.0.0.1:15432 vs :15433), a route of "prod-jump" (acme-dev-654321 / jumpbox · asia-east1-b vs null),
// a collection "Work" vs "Clients", the Local group order -> the markup contains each label, both values, and "Removed"
it("names a route whose host is gone by its id")          // Review Focus 2
it("offers only the choices that fit")                     // can_local false -> no "Keep this device’s versions…"
it("says the merge waits for the next sync when nothing collides")
it("shows the room sentence instead of choices")           // over set, items present, neither side fits
it("words the confirmation for the chosen side")           // catalogChoiceTitle + CATALOG_CHOICE_NOTE
it("keeps the host comparison for a host conflict")        // CentralConflicts with a host row renders ConflictComparison as before
```

- [ ] **Step 2: Run them and see them fail**

Run: `pnpm exec vitest run src/components/records/catalog-conflict.test.tsx`
Expected: FAIL (the module is not found).

- [ ] **Step 3: Implement**

`CentralConflicts.tsx` renders a row with `catalog` as follows:
- the title, then `CatalogConflictView` in place of `ConflictComparison`, the generic notes and the generic buttons;
- the dialog's title and description come from `catalogChoiceTitle` and `CATALOG_CHOICE_NOTE` when `selection.catalog` is set.

Host, group, key and password rows are unchanged.

- [ ] **Step 4: Run them and see them pass**

Run: `pnpm exec vitest run src/components/records/catalog-conflict.test.tsx src/components/records/CentralConflicts*`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/central-sync.ts src/components/records/CatalogConflict.tsx src/components/records/CentralConflicts.tsx src/components/records/catalog-conflict.test.tsx
git commit -m "feat(ui): show a Catalog collision as its items in plain words"
```

---

### Task 9: Documentation and the full suites

**Files:**
- Modify: `docs/development.md` (the routes paragraph: the merge, the re-pull, and the 16-entry cap, with file names)
- Modify: `docs/superpowers/specs/2026-10-26-iap-connect-via-design.md` (the "Conflicts" paragraph gains: "Replaced by `2026-10-27-catalog-conflict-merge-design.md`: different items merge, and only items both devices changed are reviewed.")

- [ ] **Step 1: Write the documentation changes.**

- [ ] **Step 2: Run the Rust suites**

Run, one at a time:

```bash
cargo test --manifest-path /Users/ysya/project/sideproj/lunport/.claude/worktrees/stoic-snyder-8c0e08/src-tauri/Cargo.toml --locked --lib -- --test-threads=2 --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none --skip ssh::engine_tests::login_methods::pam
```

```bash
cargo test --manifest-path /Users/ysya/project/sideproj/lunport/.claude/worktrees/stoic-snyder-8c0e08/src-tauri/Cargo.toml --locked --test app_profile_build
```

Expected: 0 failed in both.

- [ ] **Step 3: Run the frontend**

Run: `pnpm test`, then `pnpm build`. Expected: all tests pass, and the build exits 0.

- [ ] **Step 4: Check the tree**

Run: `git checkout -- src/bindings/`, then `git diff --check` and `git status --short`. Expected: no whitespace errors, and only the documentation is left to commit.

- [ ] **Step 5: Commit**

```bash
git add docs/development.md docs/superpowers/specs/2026-10-26-iap-connect-via-design.md
git commit -m "docs: describe how a Catalog conflict merges both devices' changes"
```
