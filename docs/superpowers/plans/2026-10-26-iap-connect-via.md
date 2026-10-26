# Connect via: IAP Routes in the Host Editor, Synced Through Central — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move a host's Google Cloud IAP route into the host editor as a Connect via choice, sync it through the central Catalog, show it on cards and details with a Check through IAP, and turn the Google Cloud page into a Google sign-in and access-grant status page.

**Architecture:** The route keeps its record shape (`transport:<host-id>`, `{ "schema": 1, "transport": … }`). In central mode it is written as a dirty `account.records` row and gathered into a new `Catalog.transports` field, the way tunnel rules are; device-local routes reach the Catalog through the same capture once the device is on central, while they fit in the 64 KiB record. Grant memory moves to a device-local map so requests never edit the library. The frontend gets pure route-draft helpers, one combined host+route save, and new read commands for gcloud accounts, PAM grants per entitlement and an IAP probe.

**Tech Stack:** Rust (Tauri 2, serde, ts-rs 10, tokio), React 19 + TypeScript (vitest), TanStack Query, Radix UI.

**Spec:** `docs/superpowers/specs/2026-10-26-iap-connect-via-design.md` (commit `a28bd88d`). Read it before any task; this plan argues from it.

## Global Constraints

- `HostPayload` does not change. The route record shape inside Lunport does not change: Meta id `transport:<host-id>`, payload `{ "schema": 1, "transport": HostTransport }`.
- Routes sync only when the library uses central sync (`state.local.central` with `control.cutover`). With no account, or a chain-mode account, routes stay in `local.transports`, as today.
- A Catalog without routes serializes exactly as before (`transports` is `#[serde(default, skip_serializing_if = "Vec::is_empty")]`).
- At most 256 routes per Catalog. Every Catalog-growing write in central mode is refused with: "This library has no room for more routes or tunnels: together they would exceed what one sync record holds. Remove a route or a tunnel, then try again." Removing never fails that check.
- `pam.justification` is always `null` inside the Catalog. Grant requests write only the device-local grant memory, never a route.
- The route compare-and-set sentence is: "The host's route changed while you were editing; reload and try again."
- Every Google call is bounded by 20 s and never waits for a person. MCP and the identity probe never ask.
- No team's names, projects or entitlements are built into the product (placeholders only).
- UI sentences quoted in the spec are used verbatim. User-facing words say "Connect via" / "route"; MCP tool names (`set_transport`, `remove_transport`) keep "transport".
- Rust commands run from the worktree root with `--locked --manifest-path src-tauri/Cargo.toml`. Never run two cargo commands at once (they block on the build lock). macOS has no `timeout`; bound long runs with the tool's own timeout.
- Running Rust tests regenerates `src/bindings/`. Revert unrelated churn (`git checkout -- src/bindings/ForwardSpec.ts src/bindings/ForwardStatus.ts src/bindings/HostKeyRequest.ts src/bindings/KnownHostEntry.ts`) and strip trailing whitespace from new binding files (`sed -i '' -e 's/[[:space:]]*$//' <file>`) before committing. A tagged serde enum needs the tag repeated in its `ts(…)` attribute.
- Commits use Conventional Commits and carry no attribution lines.

## Review Focus

1. Two devices each saved a 1.12 local route for the same host: the library's route wins and the other device's local copy is dropped by the projection, not published over it (test in Task 6).
2. A route names a Google account this computer has never signed in: the editor keeps it selected and marked "not signed in on this computer", and the Google Cloud page adds a "Not signed in on this computer" row with `gcloud auth login <account>` (tests in Tasks 13 and 15).
3. A host deleted on another device while its route is still in the Catalog: the projection keeps the orphan row without failing, and the Google Cloud page does not list it (tests in Tasks 6 and 15).
4. gcloud's directory missing, or a `legacy_credentials` folder holding a `service_account` file: `gcp_accounts` answers `config_found: false` / skips the folder, never errors (test in Task 9).
5. A Catalog already over the limit (tunnels filled it): removing a route or a tunnel still succeeds, and saving one more is refused with the sentence (test in Task 5).

---

### Task 1: Start from a clean tree with the PAM fix

**Files:** none edited by hand.

- [ ] **Step 1: Park the throwaway spike on its own branch**

```bash
git switch -c claude/iap-connect-via-spike
git add src
git commit -m "chore(spike): throwaway Connect via mockup, not for merge"
git switch claude/google-tunnel-ui-design-c3a057
git status --short
```
Expected: `git status --short` prints nothing. The spike stays on `claude/iap-connect-via-spike` for reference (its `iap` preview scenario is reused in Task 16).

- [ ] **Step 2: Bring in the PAM host-id fix**

If `git branch --contains 6bfea97e main` lists `main`, run `git merge main`; otherwise run `git cherry-pick 6bfea97e`.

- [ ] **Step 3: Run its test**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib the_grant_commands_take_the_bare_host_id_the_panel_sends -- --test-threads=2`
Expected: 1 passed.

---

### Task 2: Device-local grant memory and state version 10

**Files:**
- Modify: `src-tauri/src/sync/records_v3/types.rs` (constants)
- Modify: `src-tauri/src/sync/records_v3/state.rs` (`LocalState`, both version lists ~148-156 and ~292-304, validation ~372-380)
- Modify: `src-tauri/src/sync/record_repository.rs:102-107` (`validate_header` list)
- Modify: `src-tauri/src/sync/record_runtime.rs:727-728,937-938` (version guards)
- Modify: `src-tauri/src/sync/transports.rs` (`GrantMemory`, `remember_grant_request`, helpers)
- Modify: every fixture written as `TRANSPORT_STATE_VERSION + 1` (find with `git grep -n "TRANSPORT_STATE_VERSION + 1" src-tauri`)
- Test: `src-tauri/src/sync/transports_tests.rs`, `src-tauri/src/sync/records_v3/` tests that pin version lists

**Interfaces:**
- Produces: `records_v3::TRANSPORT_SYNC_STATE_VERSION: u32 = 10`; `transports::SYNC_STATE_VERSION: u32` (= that constant); `LocalState.transport_grants: BTreeMap<String, transports::GrantMemory>` keyed by host id (`#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]`); `pub struct GrantMemory { pub justification: String, pub duration_secs: u32 }` (`Serialize, Deserialize`, `deny_unknown_fields`, ts-rs export); `pub fn grant_memory(state: &SyncStateV3, host_id: &str) -> Option<GrantMemory>`; `pub fn needs_sync_version(state: &SyncStateV3) -> bool` (true when `transport_grants` is non-empty or `account.records` holds a `transport:` row); `remember_grant_request` keeps its signature.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn remember_grant_request_writes_device_memory_not_the_route() {
    let state = set(&state(), HOST, None, Some(with_pam(HOST)), 1).unwrap();
    let next = remember_grant_request(&state, HOST, "Deploy hotfix", 45 * 60, 2).unwrap();
    assert_eq!(get(&next, HOST), get(&state, HOST), "the route is untouched");
    assert_eq!(grant_memory(&next, HOST), Some(GrantMemory { justification: "Deploy hotfix".into(), duration_secs: 2700 }));
    assert!(next.version >= SYNC_STATE_VERSION);
}

#[test]
fn grant_memory_below_version_ten_is_refused() {
    let mut state = remember_grant_request(&set(&state(), HOST, None, Some(with_pam(HOST)), 1).unwrap(), HOST, "x", 60, 2).unwrap();
    state.version = records_v3::TRANSPORT_STATE_VERSION;
    assert!(records_v3::validate_state(&state).is_err());
}
```
Also replace `remember_grant_request_keeps_everything_else_and_needs_a_pam_check` so it asserts a route without PAM still refuses ("This transport requires no grant.") and a host without a route refuses ("This host has no transport.").

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib transports::tests -- --test-threads=2`
Expected: FAIL (`grant_memory` / `GrantMemory` / `SYNC_STATE_VERSION` not found).

- [ ] **Step 3: Implement**

Add the constant, the `LocalState` field and its validation (non-empty requires version ≥ 10; each key `records_v3::is_host_id`; justification non-empty, ≤ `MAX_JUSTIFICATION_CHARS`, no control characters; duration `60..=MAX_DURATION_SECS`, a multiple of 60). Add 10 to both lists in `state.rs` and to `validate_header`. `remember_grant_request` checks as today, then writes `transport_grants[host_id]` and raises the version to 10. Both runtime guards add `if transports::needs_sync_version(&candidate) { candidate.version = candidate.version.max(transports::SYNC_STATE_VERSION); }`. Bump the "newer than anything known" fixtures to `TRANSPORT_SYNC_STATE_VERSION + 1`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib transports:: records_v3:: record_runtime -- --test-threads=2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync src/bindings/GrantMemory.ts
git commit -m "feat(sync): keep PAM grant memory on this device under state version 10"
```

---

### Task 3: Routes in the central Catalog payload

**Files:**
- Modify: `src-tauri/src/sync/central/payload.rs:162-196` (`Catalog`, `Catalog::validate`)
- Test: the `payload.rs` test module

**Interfaces:**
- Produces: `Catalog.transports: Vec<crate::sync::transports::HostTransport>`; `Catalog` derives `Default` (the empty Catalog); `pub fn catalog_fits(catalog: &Catalog) -> bool` (true when `encode(&Identity { kind: "meta".into(), id: "catalog".into(), scope: None }, &Data::Catalog(catalog.clone()))` succeeds); `transports::MAX_ROUTES: usize = 256` (declare it in `sync/transports.rs`).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_catalog_without_routes_serializes_as_before() {
    let catalog = Catalog { collections: vec![], group_orders: vec![], tunnels: vec![], transports: vec![] };
    assert_eq!(serde_json::to_string(&catalog).unwrap(), r#"{"collections":[],"group_orders":[]}"#);
}

#[test]
fn catalog_routes_are_capped_unique_validated_and_carry_no_justification() {
    let mut catalog = empty_catalog();
    catalog.transports = (0..257).map(|n| route(&format!("{n:016x}"))).collect();
    assert!(catalog.validate().is_err(), "257 routes");
    catalog.transports = vec![route(HOST), route(HOST)];
    assert!(catalog.validate().is_err(), "two routes for one host");
    let mut remembered = route_with_pam(HOST);
    if let TransportKind::GcpIap { pam: Some(pam), .. } = &mut remembered.kind { pam.justification = Some("x".into()) }
    catalog.transports = vec![remembered];
    assert!(catalog.validate().is_err(), "a justification inside the Catalog");
}

#[test]
fn catalog_fits_follows_the_plaintext_limit() {
    let mut catalog = empty_catalog();
    assert!(catalog_fits(&catalog));
    catalog.tunnels = (0..256).map(|n| long_tunnel(n)).collect(); // names at their maximum length
    catalog.transports = (0..256).map(|n| long_route(n)).collect(); // 8 entitlements of 63 characters
    assert!(!catalog_fits(&catalog));
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib central::payload -- --test-threads=2`
Expected: FAIL (no field `transports`, no `catalog_fits`).

- [ ] **Step 3: Implement** the field and `catalog_fits`; extend `Catalog::validate` (≤ `MAX_ROUTES`, unique `host_id`, `HostTransport::validate`, `justification.is_none()`). Fix every `Catalog { … }` literal the compiler flags with `transports: vec![]`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib central:: -- --test-threads=2`
Expected: PASS (all central tests, not only the new ones).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync
git commit -m "feat(central): carry host routes in the library catalog"
```

---

### Task 4: Build the Catalog's routes from local state

**Files:**
- Modify: `src-tauri/src/sync/central/projection_local.rs:16-212` (`public_rows`)
- Modify: `src-tauri/src/sync/records_v3/` (add `central_cutover` next to `account_writes_blocked`)
- Test: `projection_local.rs` test module (or the central projection tests it already has)

**Interfaces:**
- Consumes: `Catalog.transports`, `catalog_fits`, `transports::decode/valid/is_id/PREFIX`, `record_repository::get_host`.
- Produces: `pub fn records_v3::central_cutover(state: &SyncStateV3) -> bool` (`state.local.central.as_ref().is_some_and(|c| c.control.cutover)`); `pub(crate) fn catalog_of(state: &SyncStateV3, original: &Catalog, local_routes: bool) -> Result<Catalog, AppError>` returning collections, group orders, tunnels and routes exactly as `public_rows` builds them today plus routes. `public_rows` calls `catalog_of(state, original, true)`.

Routes in `catalog_of`: every live `account.records` row with a `transport:` id, always; then, when `local_routes && central_cutover(state)`, each live `local.transports` route whose host `get_host(state, host_id)` finds and that has no account row, in host-id order, added only while `catalog_fits` holds. Every route copied in has `pam.justification = None`. Order: `original.transports` order first, then new ones by host id (as tunnels do). The match in `public_rows` gains `RecordKind::Meta if transports::is_id(&row.record.id) => {}`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn local_routes_enter_the_catalog_only_once_the_device_is_on_central() {
    let state = with_host_and_local_route(base_central_state(false), HOST); // cutover off
    assert!(catalog_of(&state, &empty(), true).unwrap().transports.is_empty());
    let state = with_host_and_local_route(base_central_state(true), HOST);
    let routes = catalog_of(&state, &empty(), true).unwrap().transports;
    assert_eq!(routes.iter().map(|t| t.host_id.as_str()).collect::<Vec<_>>(), [HOST]);
    assert!(routes.iter().all(|t| matches!(&t.kind, TransportKind::GcpIap { pam, .. } if pam.as_ref().is_none_or(|p| p.justification.is_none()))));
}

#[test]
fn a_local_route_without_its_host_or_without_room_stays_out() {
    let state = with_local_route_only(base_central_state(true), HOST); // no such host
    assert!(catalog_of(&state, &empty(), true).unwrap().transports.is_empty());
    let state = filled_to_the_limit_with_tunnels(with_host_and_local_route(base_central_state(true), HOST));
    assert!(catalog_of(&state, &empty(), true).unwrap().transports.is_empty());
}
```
Build `base_central_state(cutover)` from `crate::sync::central::workspace::tests::enrolled()` as `record_runtime_tests/mod.rs:361` does, with an `account` present.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib projection_local -- --test-threads=2`
Expected: FAIL (`catalog_of` not found).

- [ ] **Step 3: Implement** `central_cutover`, extract `catalog_of` from `public_rows` and add routes as described.

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib central:: -- --test-threads=2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync
git commit -m "feat(central): publish routes in the catalog while they fit"
```

---

### Task 5: Route storage in central mode, with the room check

**Files:**
- Modify: `src-tauri/src/sync/transports.rs` (`set`, `get`, `view`, new helpers, constants)
- Modify: `src-tauri/src/sync/tunnel_rules.rs:127-212` (room check on save in central mode)
- Modify: `src-tauri/src/mcp/management.rs` only if a new error needs mapping (it surfaces `transports::set` errors)
- Test: `src-tauri/src/sync/transports_tests.rs`, `src-tauri/src/sync/tunnel_rules_tests.rs`, `src-tauri/src/mcp/management_tests.rs`

**Interfaces:**
- Consumes: `central_cutover`, `catalog_of`, `catalog_fits`.
- Produces: `pub const NO_ROOM: &str` (the Global Constraints sentence) and `pub const ROUTE_CHANGED: &str` (the compare-and-set sentence, now `set`'s mismatch text); `pub fn synced(state: &SyncStateV3, host_id: &str) -> bool`; `get`/`view` return the live account row for a host when there is one, else the local one.

`set` in central mode: refuses with `RepositoryError::ReadOnlyAccount` when `records_v3::account_writes_blocked(state)`, writes a dirty (`dirty: true`) `account.records` row instead of the local map, and, when the write saves a route, refuses with `NO_ROOM` if `catalog_fits(&catalog_of(&next, &Catalog::default(), false)?)` is false. Outside central mode `set` behaves as today. `tunnel_rules::set` gets the same room check in central mode when it saves a rule.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn in_central_mode_a_route_is_a_dirty_account_row_and_reads_back_from_there() {
    let state = central_with_host(HOST);
    let next = set(&state, HOST, None, Some(iap(HOST)), 1).unwrap();
    assert!(next.local.transports.is_empty());
    let row = &next.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, &wire_id(HOST))];
    assert!(row.dirty);
    assert_eq!(get(&next, HOST), Some(iap(HOST)));
    assert!(synced(&next, HOST));
}

#[test]
fn a_chain_mode_account_keeps_routes_on_this_device() {
    let next = set(&chain_account_with_host(HOST), HOST, None, Some(iap(HOST)), 1).unwrap();
    assert!(next.local.transports.contains_key(&record_key(RecordKind::Meta, &wire_id(HOST))));
    assert!(!synced(&next, HOST));
}

#[test]
fn a_full_catalog_refuses_one_more_route_but_always_allows_removal() {
    let state = set(&central_with_host(HOST), HOST, None, Some(iap(HOST)), 1).unwrap();
    let full = filled_past_the_limit_with_tunnels(central_with_host(OTHER));
    assert_eq!(set(&full, OTHER, None, Some(iap(OTHER)), 2).unwrap_err().to_string(), NO_ROOM);
    let crowded = filled_past_the_limit_with_tunnels(state);
    assert!(set(&crowded, HOST, Some(&iap(HOST)), None, 3).is_ok(), "removal never fails the check");
}

#[test]
fn a_blocked_library_refuses_route_edits() {
    let state = blocked(central_with_host(HOST));
    assert!(matches!(set(&state, HOST, None, Some(iap(HOST)), 1), Err(RepositoryError::ReadOnlyAccount)));
}
```
In `tunnel_rules_tests.rs`: `a_full_catalog_refuses_one_more_tunnel_in_central_mode` asserting the `NO_ROOM` text. In `management_tests.rs`, if `TestDevice` can be put in central mode (cutover fixture as above), add `set_transport_refuses_a_route_that_does_not_fit` expecting the `NO_ROOM` sentence and no approval window; if it cannot, note it in the commit message and rely on the unit tests.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib transports:: tunnel_rules:: -- --test-threads=2`
Expected: FAIL.

- [ ] **Step 3: Implement** as described. Keep the local-map path byte-for-byte as today outside central mode.

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib transports:: tunnel_rules:: mcp:: -- --test-threads=2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync src-tauri/src/mcp
git commit -m "feat(sync): store routes with the central library and check its room"
```

---

### Task 6: Project routes from the Catalog into local state

**Files:**
- Modify: `src-tauri/src/sync/central/projection_cache.rs:118-130`
- Modify: `src-tauri/src/sync/central/projection_delta.rs:139-165`
- Test: the tests of those modules (or `central/projection.rs` tests)

**Interfaces:**
- Consumes: `Catalog.transports`, `transports::wire_id`.
- Produces: after either projection, `account.records` holds exactly one `transport:` row per `catalog.transports` entry (payload `{"schema":1,"transport":…}`), rows the Catalog no longer has are gone, and every `local.transports` entry whose host id the Catalog holds is removed.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn routes_round_trip_through_both_projections() {
    let catalog = Catalog { transports: vec![iap(HOST)], ..Catalog::default() };
    for next in [project_initial(&cache_with_host(HOST), &catalog), project_delta(&cache_with_host(HOST), &catalog)] {
        assert_eq!(transports::get(&next, HOST), Some(iap(HOST)));
        assert!(!next.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, &wire_id(HOST))].dirty);
    }
}

#[test]
fn a_route_removed_from_the_catalog_leaves_the_rows() {
    let with = project_delta(&cache_with_host(HOST), &Catalog { transports: vec![iap(HOST)], ..Catalog::default() });
    let without = project_delta(&with, &Catalog::default());
    assert_eq!(transports::get(&without, HOST), None);
}

#[test]
fn the_librarys_route_replaces_a_different_local_route_for_the_same_host() {
    let local = with_local_route(cache_with_host(HOST), with_zone(iap(HOST), "asia-east1-a"));
    let next = project_delta(&local, &Catalog { transports: vec![iap(HOST)], ..Catalog::default() });
    assert_eq!(transports::get(&next, HOST), Some(iap(HOST)));
    assert!(next.local.transports.is_empty());
}

#[test]
fn an_orphan_route_in_the_catalog_does_not_fail_the_projection() {
    let next = project_delta(&cache_with_host(HOST), &Catalog { transports: vec![iap(OTHER)], ..Catalog::default() });
    assert_eq!(transports::get(&next, OTHER), Some(iap(OTHER)));
}
```
`project_initial`, `project_delta`, `cache_with_host` and `with_local_route` are thin wrappers over the fixtures those modules' tunnel tests already use (search them for `tunnels:`).

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib central::projection -- --test-threads=2`
Expected: FAIL.

- [ ] **Step 3: Implement** both projections, mirroring their `tunnel:` handling, plus the local cleanup.

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib central:: -- --test-threads=2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync/central
git commit -m "feat(central): project library routes and retire superseded local ones"
```

---

### Task 7: Keep routes through first publication, adoption and leave

**Files:**
- Modify: `src-tauri/src/sync/central/initial_projection.rs:125-160,252-` (stop clearing; restore after the version-8 stage)
- Modify: `src-tauri/src/sync/central/adoption/merge.rs:48` (expose the host id rewrite) and the adoption code that commits the adopting device's state (`src-tauri/src/sync/central/adoption.rs`; find it from the callers of `merge::` and of `InitialProjection::prepare`)
- Modify: `src-tauri/src/sync/transports.rs` (`rekey_local`, `preserve_on_leave`)
- Test: `src-tauri/src/sync/central/adoption/tests.rs` (around 2240-2277), `transports_tests.rs`, `record_leave_tests.rs`

**Interfaces:**
- Produces: `pub(crate) fn adopted_host_id(operation: &str, old_scope: &HostScope, id: &str) -> Result<String, AppError>` (the existing private `host`); `pub fn rekey_local(state: &mut SyncStateV3, host_ids: &BTreeMap<String, String>, now: u64) -> Result<(), RepositoryError>` (rewrites keys and `host_id`s of `local.transports`; ids not in the map keep theirs).

The initial projection forces version 8 and `validate_state` refuses a populated `local.transports` below 9 (`records_v3/state.rs:372-374`; `record_import/central_stage/initial_publish.rs:75` expects exactly 8): take `local.transports` out of the shadow before forcing 8 and put it back, raising the version to at least 9, once that stage is past (`finish`). Adoption re-keys the kept routes with `adopted_host_id`, and its Catalog merge (`merge.rs`, before `merged.validate()`) refuses with `transports::NO_ROOM` when the merged Catalog does not `catalog_fits`. `preserve_on_leave` already reads `view(before)`, which now includes synced rows; make sure the leave result has no `transport:` account rows.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn first_publication_keeps_the_devices_routes_local_for_the_next_capture() {
    // Replaces the assertion near adoption/tests.rs:2240-2277 that the map is cleared.
    let projected = initial_projection_of(with_local_route(source_with_host(HOST), iap(HOST)));
    assert_eq!(transports::get(&projected, HOST), Some(iap(HOST)));
    assert!(projected.version >= transports::STATE_VERSION);
}

#[test]
fn adoption_rekeys_local_routes_to_the_adopted_host_ids() {
    let adopted = adopt(with_local_route(source_with_host(HOST), iap(HOST)), OPERATION);
    let new_id = adopted_host_id(OPERATION, &HostScope::Local, HOST).unwrap();
    assert_eq!(transports::get(&adopted, &new_id).map(|t| t.kind), Some(iap(HOST).kind));
    assert_eq!(transports::get(&adopted, HOST), None);
}

#[test]
fn an_adoption_merge_that_would_not_fit_is_refused() {
    let error = merge_overflowing_tunnels(OPERATION).unwrap_err();
    assert_eq!(error.to_string(), transports::NO_ROOM);
}

#[test]
fn leaving_keeps_a_synced_route_of_a_preserved_host_as_a_local_route() {
    let central = transports::set(&central_with_host(HOST), HOST, None, Some(iap(HOST)), 1).unwrap();
    let left = leave_preserving(&central, &[(HOST, NEW)]);
    assert_eq!(transports::get(&left, NEW).map(|t| t.kind), Some(iap(HOST).kind));
    assert!(left.account.is_none() || !left.account.as_ref().unwrap().records.keys().any(|k| k.contains("transport:")));
}
```
`initial_projection_of`, `adopt`, `merge_overflowing_tunnels` and `leave_preserving` wrap the fixtures the adoption and leave tests already use.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib adoption record_leave transports:: -- --test-threads=2`
Expected: FAIL.

- [ ] **Step 3: Implement** as described.

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib central:: record_leave transports:: -- --test-threads=2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync
git commit -m "feat(central): keep this device's routes through publication, adoption and leave"
```

---

### Task 8: Save a host and its route in one edit

**Files:**
- Modify: `src-tauri/src/sync/transports.rs` (`RouteChange`, `apply_route_change`)
- Modify: `src-tauri/src/sync/record_commands.rs:543-605` (`records_host_create`, `records_host_update`, `records_host_delete`), `:98-132,270-282` (`RecordOverview`)
- Modify: `src-tauri/src/session/transports.rs` (remove `transports_save`, `transports_delete`, `edit`), `src-tauri/src/lib.rs:423-424`
- Test: `transports_tests.rs`, `record_commands.rs` tests

**Interfaces:**
- Produces: `#[derive(Clone, Debug, Deserialize)] #[serde(deny_unknown_fields)] pub struct RouteChange { pub expected: Option<HostTransport>, pub kind: Option<TransportKind> }` (ts-rs export); `pub fn apply_route_change(state: &SyncStateV3, host_id: &str, change: &RouteChange, now: u64) -> Result<SyncStateV3, RepositoryError>` (= `set(state, host_id, change.expected.as_ref(), change.kind.clone().map(|kind| HostTransport { host_id: host_id.into(), kind }), now)`); both host commands take `route: Option<RouteChange>` and apply it inside the same `edit` closure after the host write (create uses the new id); `records_host_delete` removes the host's route in the same closure; `RecordOverview` gains `transport_sync: Vec<TransportSyncView { host_id: String, synced: bool }>` and `grant_memory: Vec<GrantMemoryView { host_id: String, justification: String, duration_secs: u32 }>` (ts-rs exports), `transports` unchanged.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_route_change_saves_removes_or_refuses_on_a_stale_expected_value() {
    let state = with_local_host(state(), HOST);
    let saved = apply_route_change(&state, HOST, &RouteChange { expected: None, kind: Some(iap(HOST).kind) }, 1).unwrap();
    assert_eq!(get(&saved, HOST), Some(iap(HOST)));
    let stale = RouteChange { expected: None, kind: Some(with_zone(iap(HOST), "asia-east1-a").kind) };
    assert_eq!(apply_route_change(&saved, HOST, &stale, 2).unwrap_err().to_string(), ROUTE_CHANGED);
    let removed = apply_route_change(&saved, HOST, &RouteChange { expected: Some(iap(HOST)), kind: None }, 3).unwrap();
    assert_eq!(get(&removed, HOST), None);
}
```
In `record_commands.rs` tests: `creating_a_host_with_an_invalid_route_saves_neither` (the whole closure errors and no host is created), `deleting_a_host_removes_its_route`, and `the_overview_reports_route_sync_and_grant_memory`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib transports:: record_commands -- --test-threads=2`
Expected: FAIL.

- [ ] **Step 3: Implement** as described; delete the two commands and their registration.

- [ ] **Step 4: Run the tests to see them pass**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib transports:: record_commands session:: -- --test-threads=2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src src/bindings/RouteChange.ts src/bindings/TransportSyncView.ts src/bindings/GrantMemoryView.ts
git commit -m "feat(records): save a host and its route together"
```

---

### Task 9: List gcloud's accounts and whether each sign-in works

**Files:**
- Modify: `src-tauri/src/gcp/auth.rs` (`credentialed_accounts`)
- Modify: `src-tauri/src/gcp/rest.rs` (`RestClient::tokens`)
- Modify: `src-tauri/src/session/transports.rs` (view types, `account_state`, command), `src-tauri/src/lib.rs`
- Test: `auth.rs` and `session/transports.rs` test modules

**Interfaces:**
- Produces: `pub fn credentialed_accounts(config_dir: &Path) -> Vec<String>` (sorted; each `legacy_credentials/<dir>/adc.json` whose `type` is `authorized_user`; the account is the folder name with a Windows device-name dot prefix removed, the reverse of `legacy_credentials_path`); `pub fn tokens(&self) -> Arc<dyn TokenSource>`; `GcloudAccountsView { config_found: bool, active: Option<String>, accounts: Vec<GcloudAccountView> }`, `GcloudAccountView { account: String, state: String /* "signed_in" | "expired" | "unknown" */, message: Option<String> }` (ts-rs); `pub fn account_state(tokens: &dyn TokenSource, account: &str) -> GcloudAccountView` (Ok → `signed_in`; `AuthError::SignInExpired` → `expired`; anything else → `unknown` with its sentence); `#[tauri::command] async fn gcp_accounts(window) -> Result<GcloudAccountsView, String>` (main window only; runs the checks off the async runtime; 20 s overall bound).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn credentialed_accounts_lists_user_folders_and_skips_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "legacy_credentials/frank@example.com/adc.json", &authorized_user("frank@example.com", "r1"));
    write(dir.path(), "legacy_credentials/ops@example.com/adc.json", &authorized_user("ops@example.com", "r2"));
    write(dir.path(), "legacy_credentials/robot/adc.json", r#"{"type":"service_account"}"#);
    assert_eq!(credentialed_accounts(dir.path()), ["frank@example.com", "ops@example.com"]);
    assert!(credentialed_accounts(&dir.path().join("missing")).is_empty()); // Review Focus 4
}

#[test]
fn account_state_maps_token_outcomes() {
    assert_eq!(account_state(&Answers::ok(), "a@example.com").state, "signed_in");
    assert_eq!(account_state(&Answers::err(AuthError::SignInExpired { account: "a@example.com".into() }), "a@example.com").state, "expired");
    let unknown = account_state(&Answers::err(AuthError::Network("offline".into())), "a@example.com");
    assert_eq!((unknown.state.as_str(), unknown.message.is_some()), ("unknown", true));
}
```
(`write` and `authorized_user` exist in `auth.rs` tests; `Answers` is a small fake `TokenSource` in the test.)

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib gcp::auth session::transports -- --test-threads=2`
Expected: FAIL.

- [ ] **Step 3: Implement** as described; `config_found` is whether gcloud's config directory exists.

- [ ] **Step 4: Run the tests to see them pass** (same command). Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src src/bindings/GcloudAccountsView.ts src/bindings/GcloudAccountView.ts
git commit -m "feat(gcp): list gcloud accounts on this computer with their sign-in state"
```

---

### Task 10: Grants per entitlement, and requesting a chosen entitlement

**Files:**
- Modify: `src-tauri/src/session/transports.rs` (`pam_grants`, `gcp_pam_grants`, `pam_request`, `pam_request_with`, `transports_pam_request`), `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/session/app.rs:162-164` only if the grant-memory call changes (it should not)
- Test: `session/transports.rs` test module

**Interfaces:**
- Produces: `PamGrantView { account: Option<String>, project: String, location: String, entitlement: String, state: String, active_until_ms: Option<u64>, message: Option<String>, host_ids: Vec<String> }` (ts-rs); `pub fn pam_grants(gcp: &dyn GcpClient, active: Option<&str>, transports: &[HostTransport]) -> Vec<PamGrantView>` (one row per distinct (resolved account, project, location, entitlement); a route's `None` account resolves to `active`; state from `pam::in_flight` as `pam_status` decides it; `error` with the API sentence when the lookup fails); `#[tauri::command] async fn gcp_pam_grants(app, window) -> Result<Vec<PamGrantView>, String>`; `pam_request_with` and `pam_request` take `entitlement: Option<&str>` (must be listed by the route, else `Err("This transport does not list that entitlement.")`; `None` = the first); `transports_pam_request(…, entitlement: Option<String>)`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn grants_are_one_row_per_entitlement_across_routes() {
    let routes = [pam_route("0000000000000001", None, &["prod-operate", "prod-admin"]), pam_route("0000000000000002", Some("frank@example.com"), &["prod-operate"])];
    let rows = pam_grants(&FakeGcp::active_on("prod-operate"), Some("frank@example.com"), &routes);
    let operate = rows.iter().find(|r| r.entitlement == "prod-operate").unwrap();
    assert_eq!(operate.host_ids, ["0000000000000001", "0000000000000002"]);
    assert_eq!(operate.state, "active");
    assert_eq!(rows.iter().filter(|r| r.entitlement == "prod-admin").count(), 1);
}

#[test]
fn a_request_asks_for_the_chosen_listed_entitlement() {
    let route = pam_route("0000000000000001", None, &["prod-operate", "prod-admin"]);
    let view = pam_request_with(&FakeGcp::grants_at_once(), &|_, _| Ok(()), &route, "Deploy hotfix", 1800, Some("prod-admin"), &|| false, Duration::ZERO, Duration::from_secs(1)).unwrap();
    assert_eq!(view.entitlement.as_deref(), Some("prod-admin"));
    assert!(pam_request_with(&FakeGcp::grants_at_once(), &|_, _| Ok(()), &route, "x", 1800, Some("other"), &|| false, Duration::ZERO, Duration::from_secs(1)).is_err());
}
```
(Build `FakeGcp` on the fake `GcpClient` the existing `pam_request_with` tests use.)

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib session::transports -- --test-threads=2`
Expected: FAIL.

- [ ] **Step 3: Implement** as described; update existing `pam_request_with` callers with `None`.

- [ ] **Step 4: Run the tests to see them pass** (same command). Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src src/bindings/PamGrantView.ts
git commit -m "feat(gcp): show grants per entitlement and request the one chosen"
```

---

### Task 11: Check a route through IAP

**Files:**
- Modify: `src-tauri/src/session/transports.rs` (`IapProbeView`, `probe_iap`, `transports_iap_probe`)
- Modify: `src-tauri/src/connection_probe.rs:15` (`pub(crate) static CHECKS`), `src-tauri/src/lib.rs`
- Test: `session/transports.rs` test module (async tests with `gcp::testing::FakeRelay`)

**Interfaces:**
- Consumes: `ssh::IapTarget` and `IapTarget::endpoint(port)` (`ssh/types.rs:136-162`), `gcp::iap::open`, `gcp::auth::user_agent`, `RestClient::tokens`.
- Produces: `IapProbeView { status: String /* "reachable" | "denied" | "unreachable" */, latency_ms: Option<u64>, elapsed_ms: u64, checked_at_ms: u64, message: Option<String> }` (ts-rs); `pub async fn probe_iap(target: &IapTarget, port: u16, tokens: Arc<dyn TokenSource>, deadline: Duration) -> IapProbeView`; `#[tauri::command] async fn transports_iap_probe(app, window, host_id: String) -> Result<IapProbeView, String>` (main window; `checked_host_id`; the host's effective port; `CHECKS.try_acquire()` with the port check's message; deadline 20 s).

Mapping: `Ok(tunnel)` → `reachable` (drop the tunnel at once); `IapError::Refused { status: 403 }` or `Closed { code: 4033, .. }` → `denied` ("IAP refused this Google account", and for a route with a PAM check add "Request a grant, then check again."); `IapError::Credentials(e)` → `denied` with `e`'s sentence; anything else, timeout included → `unreachable` with the error's text (for 4003 that is "the relay closed the tunnel (4003: failed to connect to backend)").

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn the_probe_reports_reachable_denied_and_unreachable() {
    let relay = FakeRelay::start().await;
    let target = |relay: &FakeRelay| IapTarget { project: "p-123456".into(), zone: "asia-east1-b".into(), instance: "jumpbox".into(), interface: "nic0".into(), account: None, url_root: Some(relay.url_root()) };
    assert_eq!(probe_iap(&target(&relay), 22, tokens(), Duration::from_secs(5)).await.status, "reachable");
    relay.set(Behaviour::RefuseHandshake(403));
    assert_eq!(probe_iap(&target(&relay), 22, tokens(), Duration::from_secs(5)).await.status, "denied");
    relay.set(Behaviour::CloseAfter(0, 4033, "not authorized"));
    assert_eq!(probe_iap(&target(&relay), 22, tokens(), Duration::from_secs(5)).await.status, "denied");
    relay.set(Behaviour::CloseAfter(0, 4003, "failed to connect to backend"));
    let unreachable = probe_iap(&target(&relay), 22, tokens(), Duration::from_secs(5)).await;
    assert_eq!(unreachable.status, "unreachable");
    assert!(unreachable.message.unwrap().contains("4003"));
}
```
(Use the `FakeRelay` setup and fake token source the `gcp::iap` tests use; match their helper names.)

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test --locked --manifest-path src-tauri/Cargo.toml --lib the_probe_reports_reachable_denied_and_unreachable -- --test-threads=2`
Expected: FAIL.

- [ ] **Step 3: Implement** as described.

- [ ] **Step 4: Run it to see it pass** (same command). Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src src/bindings/IapProbeView.ts
git commit -m "feat(gcp): check a host's route through IAP"
```

---

### Task 12: Frontend data layer and route-draft helpers

**Files:**
- Modify: `src/lib/transports.ts`, `src/lib/transports.test.ts`
- Modify: `src/lib/records.ts:131-140,255-285`
- Create: `src/components/records/route.ts`, `src/components/records/route.test.ts`
- Modify: `src/components/records/editor.ts:151-162` (`submitEditor`)

**Interfaces:**
- Consumes: bindings from Tasks 2 and 8-11.
- Produces (in `src/lib/transports.ts`): `listGcloudAccounts(): Promise<GcloudAccountsView>` (`gcp_accounts`); `listPamGrants(): Promise<PamGrantView[]>` (`gcp_pam_grants`); `probeIap(hostId: string): Promise<IapProbeView>` (`transports_iap_probe`); `requestPamGrant(hostId, justification, durationSecs, entitlement?: string)`; `iapTarget(kind: TransportKind): string` (`project / instance`); `grantStateLine(grant: { state: string; active_until_ms: number | null }): string` ("Active until HH:MM" / "Activating…" / "No active grant"); `routeSynced(overview, hostId): boolean`; `grantMemoryFor(overview, hostId): GrantMemoryView | null`. `saveTransport` and `deleteTransport` are removed.
- Produces (in `src/lib/records.ts`): `createRecordHost(scope, payload, upgradeConfirmed?, route?: RouteChange)`, `updateRecordHost(id, revision, payload, upgradeConfirmed?, route?: RouteChange)` (send `route` only when given); `RecordOverview.transport_sync?: TransportSyncView[]`, `grant_memory?: GrantMemoryView[]`.
- Produces (in `route.ts`): `type Via = "address" | "iap"`; `type RouteDraft = { via: Via; iap: TransportKind }`; `beginRoute(saved: TransportKind | null, initialVia?: Via): RouteDraft`; `draftRoute(draft): TransportKind | null`; `routeProblem(draft): string | null` (`transportProblem`'s sentences, `null` for Address); `routeEdited(draft, saved: TransportKind | null): boolean` (false for an untouched new IAP draft); `routeChange(draft, saved: HostTransport | null): RouteChange | undefined` (`undefined` when unchanged); `withRouteHostname(payload: HostPayload, draft): HostPayload` (in IAP mode an empty hostname becomes the instance name).
- Produces (in `editor.ts`): `submitEditor(state, upgradeConfirmed?, route?: RouteChange)`.

- [ ] **Step 1: Write the failing tests**

```ts
it("starts from the saved route and remembers IAP fields across switches", () => {
  const draft = beginRoute(null, "iap");
  const typed = { ...draft, iap: { ...draft.iap, instance: "jumpbox" } };
  expect(draftRoute({ ...typed, via: "address" })).toBeNull();
  expect(draftRoute({ ...typed, via: "iap" })?.instance).toBe("jumpbox");
});
it("reports no change, a save or a removal", () => {
  const saved = iap("0000000000000001");
  expect(routeChange(beginRoute(saved.kind), saved)).toBeUndefined();
  expect(routeChange({ ...beginRoute(saved.kind), via: "address" }, saved)).toEqual({ expected: saved, kind: null });
  expect(routeChange(beginRoute(null, "address"), null)).toBeUndefined();
});
it("does not flag an untouched new IAP route", () => {
  expect(routeEdited(beginRoute(null, "iap"), null)).toBe(false);
  expect(routeProblem(beginRoute(null, "iap"))).toBe("Enter the Google Cloud project id.");
});
it("gives a new IAP host the instance name as its hostname", () => {
  const draft = { ...beginRoute(null, "iap"), iap: { ...newIapTransport("").kind, instance: "jumpbox" } };
  expect(withRouteHostname(hostPayload({ hostname: "" }), draft).hostname).toBe("jumpbox");
  expect(withRouteHostname(hostPayload({ hostname: "10.0.0.8" }), draft).hostname).toBe("10.0.0.8");
});
```
In `transports.test.ts`, replace the save/delete invoke assertions with ones for `gcp_accounts`, `gcp_pam_grants`, `transports_iap_probe` and `transports_pam_request` with and without `entitlement`.

- [ ] **Step 2: Run them to see them fail**

Run: `pnpm test -- src/components/records/route.test.ts src/lib/transports.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement** as described.

- [ ] **Step 4: Run them to see them pass** (same command). Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib src/components/records/route.ts src/components/records/route.test.ts src/components/records/editor.ts
git commit -m "feat(ui): add route drafts and the new Google Cloud calls"
```

---

### Task 13: The Connect via block in the host editor

**Files:**
- Create: `src/components/records/IapRouteFields.tsx`
- Delete: `src/components/records/TransportFields.tsx`
- Modify: `src/components/records/HostEditor.tsx` (Connection section ~319-390, state, save ~139-173, discard/reload, Save button)
- Test: create `src/components/records/connect-via.test.tsx`

**Interfaces:**
- Consumes: `route.ts`, `submitEditor(…, route)`, `listGcloudAccounts`, `fetchOsLoginProfile`, `osLoginOutcome`, `routeSynced`.
- Produces: `RecordHostEditor` prop `initialVia?: Via`; `IapRouteFields({ kind, onChange, disabled, port }: { kind: TransportKind; onChange: (next: TransportKind) => void; disabled: boolean; port: ReactNode })`.

Layout and copy follow the spec's "Host editor: Connect via" section exactly: Group; Alias beside Username; the bordered Connect via block with a two-option radio-group control ("Address", "Google Cloud IAP"); Address = Hostname or IP (2/3) + Port (1/3); IAP = Instance (2/3) + Port, then Project + Zone, then the collapsed "Google Cloud options" with its summary line. The description is "The hostname or IP address this host is dialed at." for Address, and for IAP "Saved with the host, so it syncs wherever the host does." when the library uses central sync, else "Saved on this computer only.". "Use OS Login username" fills Username in the draft (no write). The status line uses `routeEdited` so an untouched new IAP route shows nothing; Save submits `withRouteHostname(…)` and `routeChange(…)`; Discard and Reload reset the draft with `beginRoute(saved)`. A duplicate starts from the source host's route.

- [ ] **Step 1: Write the failing tests**

Render with the patterns of `transport.test.tsx` and `markup.test.tsx` (mock `tauriInvoke`; read the fixture overview's route from `transports`).

```ts
it("puts the instance where the hostname was and keeps the port", () => {
  const html = renderEditor(iapHost); // a host with a saved route
  expect(html).toContain("Instance");
  expect(html).not.toContain("Hostname or IP");
  expect(html).toContain("Saved with the host, so it syncs wherever the host does."); // central fixture
});
it("opens a new IAP host without a validation sentence", () => {
  const html = renderEditor(null, { initialVia: "iap" });
  expect(html).not.toContain("Enter the Google Cloud project id.");
});
it("offers gcloud's accounts and keeps one this computer lacks", async () => {
  const options = await accountOptions(hostWithAccount("ops@example.com")); // gcp_accounts answers frank@ (active) and old@ (expired)
  expect(options).toEqual(["gcloud's active account (frank@example.com)", "frank@example.com", "old@example.com · sign-in expired", "ops@example.com · not signed in on this computer"]);
});
it("fills the OS Login username without saving the host", async () => {
  await clickUseOsLoginUsername(iapHost); // transports_oslogin_profile answers frank_example_com
  expect(usernameField()).toBe("frank_example_com");
  expect(invoked("records_host_update")).toBe(false);
});
it("removes the route when saved with Address", async () => {
  await switchToAddressAndSave(iapHost);
  expect(lastInvoke("records_host_update").route).toEqual({ expected: savedRoute(iapHost), kind: null });
});
```
The helpers (`renderEditor`, `accountOptions`, `clickUseOsLoginUsername`, `switchToAddressAndSave`, `invoked`, `lastInvoke`) are small test utilities built on those patterns.

- [ ] **Step 2: Run them to see them fail**

Run: `pnpm test -- src/components/records/connect-via.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement** as described.

- [ ] **Step 4: Run them to see them pass**

Run: `pnpm test -- src/components/records/connect-via.test.tsx src/components/records/editor.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/components/records
git commit -m "feat(ui): choose how a host is reached in its editor"
```

---

### Task 14: Cards, details and the connection check

**Files:**
- Modify: `src/components/records/HostList.tsx:355-445`
- Modify: `src/components/records/HostPreview.tsx`
- Modify: `src/components/records/ConnectionCheck.tsx`
- Modify: `src/components/records/GrantRequestDialog.tsx` (props and defaults)
- Test: `src/components/records/trust-and-probe.test.tsx`, `src/components/records/markup.test.tsx`

**Interfaces:**
- Consumes: `transportFor`, `iapTarget`, `grantStateLine`, `fetchPamStatus`, `probeIap`, `grantMemoryFor`.
- Produces: `ConnectionCheck({ host, transport }: { host: RecordHostView; transport?: HostTransport | null })`; `GrantRequestDialog` props add `entitlement?: string` and `memory: GrantMemoryView | null`; `grantRequestDefaults(transport, memory)` returns the memory's justification and minutes, else `""` and the route's `pam.duration_secs` in minutes.

Follow the spec's "Host list and details" and "Check through IAP" sections: card line `IAP · user` with a cloud icon and the `Google Cloud IAP · project / instance` tooltip; the details pane's IAP header and Connection rows (no Address); the Access grant section (read on open and every minute, "Request grant…" disabled while active); the IAP check's description and "Check through IAP" button, with result labels "Reachable through IAP · N ms" or the denied/unreachable sentence.

- [ ] **Step 1: Write the failing tests**

```ts
it("marks an IAP host's card", () => {
  const html = renderHostList(overviewWith(iapHost));
  expect(html).toContain("IAP · deploy");
  expect(html).toContain("Google Cloud IAP · acme-prod-123456 / web-1");
});
it("leads the details with the IAP target and drops the address", () => {
  const html = renderPreview(iapHost);
  expect(html).toContain("acme-prod-123456 / web-1");
  expect(html).not.toContain(">Address<");
});
it("shows the grant and disables Request grant while it is active", async () => {
  const view = await renderPreviewSettled(pamHost); // transports_pam_status: prod-operate active until 10:00 local
  expect(view.text).toContain("prod-operate · Active until 10:00");
  expect(view.button("Request grant…").disabled).toBe(true);
});
it("checks an IAP host through IAP", async () => {
  const view = await clickCheck(iapHost); // transports_iap_probe answers reachable, 182 ms
  expect(invoked("transports_iap_probe")).toBe(true);
  expect(view.text).toContain("Reachable through IAP · 182 ms");
});
it("prefills a request from this computer's memory, else the route's default length", () => {
  expect(grantRequestDefaults(pamRoute(1800), { host_id: HOST, justification: "Deploy hotfix", duration_secs: 2700 })).toEqual({ justification: "Deploy hotfix", minutes: "45" });
  expect(grantRequestDefaults(pamRoute(1800), null)).toEqual({ justification: "", minutes: "30" });
});
```

- [ ] **Step 2: Run them to see them fail**

Run: `pnpm test -- src/components/records/trust-and-probe.test.tsx src/components/records/markup.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement** as described.

- [ ] **Step 4: Run them to see them pass** (same command). Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/components/records
git commit -m "feat(ui): show a host's IAP route on cards and in its details"
```

---

### Task 15: The Google Cloud page

**Files:**
- Create: `src/components/records/GoogleCloudPanel.tsx`
- Delete: `src/components/records/TransportsPanel.tsx`, `src/components/records/transport.test.tsx`
- Modify: `src/components/records/RecordsWorkspace.tsx` (~189-215 `createIapHost`, ~514 panel, ~668-690 `initialVia`), `src/components/records/selection.ts` (`via?: "iap"` on the `new` variant), `src/components/records/LibraryNavigation.tsx:246` (no count)
- Keep: `src/components/records/transports.css` (rename the class if you rename the page's root)
- Test: create `src/components/records/google-cloud.test.tsx`

**Interfaces:**
- Consumes: `listGcloudAccounts`, `listPamGrants`, `iapTarget`, `grantStateLine`, `routeSynced`, `GrantRequestDialog` (`entitlement`, `memory`).
- Produces: `GoogleCloudPanel({ overview, createIapHost, editHost }: { overview: RecordOverview; createIapHost: () => void; editHost: (id: string) => void })`.

Sections, copy and states follow the spec's "The Google Cloud page" section verbatim (header sentence and "New IAP host"; Google sign-in rows with signed in / expired / could not be checked, "gcloud active", route counts, the `gcloud auth login <account>` command, the "Not signed in on this computer" row and the missing-gcloud sentence; Access grants rows per entitlement with Request grant for that entitlement; Hosts through IAP rows opening the editor and the empty sentence). Routes that do not sync in a central library appear under "Saved on this computer only" with "the library has no room for this route" when the host is in the library, and are left out when it is not. Routes whose host is missing are not listed (Review Focus 3).

- [ ] **Step 1: Write the failing tests**

```ts
it("lists this computer's gcloud accounts with their state", async () => {
  const text = await renderPageText(overviewWith(iapHost, pamHost, routeFor("ops@example.com"))); // gcp_accounts: frank@ active+signed in, old@ expired
  expect(text).toContain("gcloud active");
  expect(text).toContain("gcloud auth login old@example.com");
  expect(text).toContain("Not signed in on this computer"); // Review Focus 2: ops@ is named by a route only
});
it("says when gcloud is missing", async () => {
  expect(await renderPageText(overviewWith(iapHost), { gcpAccounts: { config_found: false, active: null, accounts: [] } }))
    .toContain("gcloud was not found on this computer. Install the Google Cloud CLI, then run gcloud auth login.");
});
it("lists grants per entitlement and requests the one clicked", async () => {
  const view = await renderPage(overviewWith(pamHost)); // gcp_pam_grants: prod-operate active, prod-admin none
  expect(view.text).toContain("Privileged Access Manager grants your hosts require. A grant ends on its own; Lunport never revokes one.");
  await view.click("Request grant", { row: "prod-admin" });
  expect(view.dialogText).toContain("prod-admin");
});
it("opens a host from the list, creates a new IAP host, and skips orphans", async () => {
  const props = { createIapHost: vi.fn(), editHost: vi.fn() };
  const view = await renderPage(overviewWith(iapHost, orphanRoute()), props); // Review Focus 3
  expect(view.text).not.toContain(orphanRoute().host_id);
  await view.click(iapHost.payload.alias);
  expect(props.editHost).toHaveBeenCalledWith(iapHost.id);
  await view.click("New IAP host");
  expect(props.createIapHost).toHaveBeenCalled();
});
it("says when no host connects through IAP", async () => {
  expect(await renderPageText(overviewWith())).toContain("No host connects through IAP yet. Open a host and choose Google Cloud IAP under Connect via, or create one with New IAP host.");
});
```

- [ ] **Step 2: Run them to see them fail**

Run: `pnpm test -- src/components/records/google-cloud.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement** the page and the wiring.

- [ ] **Step 4: Run the frontend suite**

Run: `pnpm test`
Expected: PASS (no reference to the deleted files remains).

- [ ] **Step 5: Commit**

```bash
git add src/components/records
git commit -m "feat(ui): turn the Google Cloud page into sign-in and grant status"
```

---

### Task 16: Interface preview, documentation and the full check

**Files:**
- Modify: `src/dev/interface-preview.tsx` (an `iap` scenario; start from `git show claude/iap-connect-via-spike:src/dev/interface-preview.tsx` and change the fakes to the real shapes from Tasks 2 and 8-11)
- Modify: `docs/usage.md:67-75`, `docs/development.md:58`

- [ ] **Step 1: Add the `iap` scenario** with a central library (`includeFixtureLibrary`, aliases without spaces), two IAP hosts (one with a PAM check), one active and one inactive grant, two gcloud accounts (one expired), and fakes for `gcp_accounts`, `gcp_pam_grants`, `transports_pam_status`, `transports_pam_request` (with `entitlement`), `transports_iap_probe`, `transports_oslogin_profile` and the `route` argument of `records_host_create` / `records_host_update`.

- [ ] **Step 2: Look at it**

Run `pnpm exec vite` and open `http://localhost:1420/dev-preview.html?scenario=iap`. Check the card markers, the editor's Connect via in both modes, the details pane's Access grant and Check through IAP, and the Google Cloud page's three sections.

- [ ] **Step 3: Rewrite the documentation**: `usage.md`'s IAP section for Connect via, sync through central only, Check through IAP and the Google Cloud page, including: "Devices running Lunport 1.12 or earlier stop syncing a library once it holds a route, until they are updated." Remove the sentences about device-local transports and adopting central sync. `development.md:58` describes the synced rows, the Catalog field, version 10 and the device-local grant memory.

- [ ] **Step 4: Run every check**

```bash
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib -- --test-threads=2 --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none --skip ssh::engine_tests::login_methods::pam
cargo test --locked --manifest-path src-tauri/Cargo.toml --test app_profile_build
pnpm test
pnpm build
git diff --check
```
Expected: every command passes; `git diff --check` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add src/dev docs
git commit -m "docs: describe Connect via, route sync and the Google Cloud page"
```

When release-please opens the release PR, add the older-release sentence from Step 3 to that release's changelog entry.
