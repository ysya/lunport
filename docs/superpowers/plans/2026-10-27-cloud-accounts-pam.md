# Cloud accounts and standalone PAM — implementation plan

> Steps use checkbox (`- [ ]`) syntax for tracking. Built task by task in one session (Frank's choice, 2026-10-27), one commit per task.

**Goal:** gcloud account actions in the app (sign in again, add, remove, make active), a Privileged Access Manager area that stands on its own (search scopes, every requestable entitlement, request per entitlement, approval entitlements), a Cloud section in the sidebar, synced search scopes and per-entitlement grant memory, entitlement suggestions in the host editor, and the double divider fixed.

**Spec:** `docs/superpowers/specs/2026-10-27-cloud-accounts-pam-design.md` (approved by Frank 2026-10-27).

**Architecture:**
- **gcloud.** `gcp::cli` finds the executable (`locate`) and runs it with an argument list (`run`), bounded, cancellable, one at a time. `session::gcloud` holds the Tauri commands for the four account actions.
- **PAM client.** `GcpClient`'s grant calls take an entitlement's full name (`projects|folders|organizations/…/locations/…/entitlements/…`), and the client gains `search_entitlements`. `pam::Entitlement` becomes `{ account, name }`.
- **Sync.** `sync::pam_library` (new) holds `PamScope`, `GrantRequestMemory`, their `Meta` records (`pam_scope:<id>`, `pam_request:<id>`), their reads and writes: account rows under central sync, `local.pam_scopes` / `local.pam_requests` otherwise, with a publish step that moves local rows into a central library. The Catalog gains `pam_scopes` and `pam_requests`, the projections and `catalog_of` read and write them, the merge treats them as items (memory collisions take the synced version). Local state version 11.
- **Commands.** `session::transports` gains `gcp_pam_overview`, `gcp_pam_request`, `gcp_pam_scope_save`, `gcp_pam_scope_remove`, `gcp_pam_suggestions`; `gcp_pam_grants` goes. The connect gate reads per-entitlement memory first.
- **UI.** `src/lib/cloud.ts` (providers), a Cloud heading in `LibraryNavigation`, tabs on `GoogleCloudPanel` (Accounts, Access, IAP hosts), the dialogs, suggestions in `IapRouteFields`.

**Tech Stack:** Rust (Tauri 2, `google-cloud-privilegedaccessmanager-v1` 1.16, mockito), React 19 + TypeScript (vitest, `renderToStaticMarkup`), ts-rs bindings.

## Global constraints

- Start from `origin/main` (`3b6d7567`); branch `claude/busy-edison-m78qbs`.
- Cargo: `--locked --manifest-path src-tauri/Cargo.toml`, one cargo command at a time. CI's lib suite: `cargo test --locked --lib -- --test-threads=2 --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none --skip ssh::engine_tests::login_methods::pam`, then `--test app_profile_build`.
- Bindings: a task that adds or changes an exported type regenerates its binding and keeps only that file; every other `src/bindings/` change is reverted (`git checkout -- src/bindings/`).
- Test data is synthetic: `acme-dev-654321`, `acme-prod-123456`, `frank@example.com`, `ops@example.com`, folder `123456789012`, organization `987654321098`.
- Stack: functions on the sync path that return whole states keep at most one full state per frame (as the Catalog merge did).
- Commits: Conventional Commits, no attribution lines. `git diff --check` before each.
- Every gcloud account argument passes `transports::is_email` before spawning; gcloud output is never logged.

## Review focus

1. A delta projection that brings the first `pam_*` rows raises the state to 11 and the save accepts it (`record_runtime` "raised" rule).
2. A central library whose Catalog has no scopes or memories serializes byte for byte as before.
3. A memory write never fails a grant request: no room, blocked writes, or a non-central library all fall through.
4. `gcp_pam_request` refuses an entitlement the overview would not list.
5. An approval entitlement is requested and not waited for; a grant awaiting approval is never access at connect time.

---

### Task 1: The double divider

**Files:** `src/styles/app-layout.css`, `src/components/records/ImportPanel.tsx` (check), a vitest of the rule's presence if the project tests CSS, else none.

- [ ] Add `.app-form-section:has(+ .app-form-section) > .app-review-list:last-child { border-bottom-width: 0; }` beside `.app-review-list`.
- [ ] Check `ImportPanel.tsx`'s review sections: the same selector covers them when they are `FormSection`s; where a list is followed by a section without being its last child, give it the same treatment.
- [ ] Look at it in the interface preview (Playwright screenshot of the Google Cloud page and the import review) before and after.
- [ ] Commit `fix(ui): draw one divider between page sections`.

### Task 2: `gcp::cli` — find and run gcloud

**Files:** create `src-tauri/src/gcp/cli.rs`; modify `src-tauri/src/gcp/mod.rs`.

- [ ] `pub fn locate_in(env: &dyn Fn(&str) -> Option<String>, home: Option<&Path>, windows: bool, shell: &dyn Fn() -> Option<PathBuf>) -> Option<PathBuf>`: `PATH` directories, then the known places of the spec, then (not Windows) `shell()`. Executable check: a regular file and, on Unix, any execute bit. Windows names `gcloud.cmd`, `gcloud.exe`.
- [ ] `fn login_shell_lookup(shell: &Path, bound: Duration) -> Option<PathBuf>`: `shell -l -c 'command -v gcloud'`, stdin null, stdout piped, killed at the bound; accepts exactly one absolute path whose file name is `gcloud` and that is executable.
- [ ] `pub fn locate() -> Option<PathBuf>` with a process-wide cache (`Mutex<Option<PathBuf>>`) dropped when the file is gone; `pub fn relocate()` clears it.
- [ ] `pub struct Run { pub path: PathBuf, pub args: Vec<String>, pub bound: Duration }` and `pub fn run(run: &Run, cancel: &AtomicBool, on_line: &mut dyn FnMut(&str)) -> Result<Output, CliError>`: spawn with `CLOUDSDK_CORE_DISABLE_PROMPTS=1`, stdin null, a stderr reader thread feeding lines to a channel (`on_line` sees each), stdout collected; the loop waits with `try_wait` every 100 ms, kills on cancel or bound. On Windows set `CREATE_NO_WINDOW`.
- [ ] `CliError { Busy, Cancelled, TimedOut { minutes }, Failed { line }, Spawn(String) }` with `sentence(action)`: the spec's sentences. `failure_line(stderr)`: last `ERROR:` line, else last non-empty line, ≤ 300 chars.
- [ ] One action at a time: a static `AtomicBool` guard taken by `run`, `Busy` if held.
- [ ] `pub fn sign_in_url(line: &str) -> Option<String>`: the first `https://accounts.google.com/` token of a line.
- [ ] Tests (Unix, `#[cfg(unix)]` where scripts are written): found on PATH; in a known place under a fake home; from a fake shell script; nothing; a non-executable file skipped; a shell answer that is relative or two lines ignored; `run` success with stdout; `ERROR:` line chosen; timeout kills (a `sleep 5` script with a 200 ms bound); cancel kills; lines streamed; busy guard; `sign_in_url`.
- [ ] Commit `feat(gcp): find and run the gcloud CLI`.

### Task 3: Account action commands

**Files:** create `src-tauri/src/session/gcloud.rs`; modify `src-tauri/src/session/mod.rs`, `src-tauri/src/lib.rs` (command registration), `src-tauri/src/gcp/auth.rs` (`TokenSource::forget`), `src-tauri/src/session/transports.rs` (`GcloudAccountsView.cli`).

- [ ] `pub enum AccountAction { SignIn { account: String }, Add, Activate { account: String }, Remove { account: String } }` with `args()` (spec's argument lists: `auth login <a> --force --no-activate --brief`, `auth login --no-activate --brief`, `config set account <a>`, `auth revoke <a>`), `bound()` (5 min, 5 min, 30 s, 60 s) and `verb()` for sentences; `args` refuses a non-email account.
- [ ] `TokenSource::forget(&self, account: Option<&str>)` default no-op; `FileStore` drops cached tokens (all when `None`).
- [ ] Commands: `gcp_cli_status() -> { path: Option<String> }` (`locate`), `gcp_cli_locate_again()`, `gcp_account_action(action) -> AccountActionView { account: Option<String>, message: String }` (spawn_blocking; streams sign-in URLs as the Tauri event `gcp-sign-in-url` to the main window; after success `forget` and, for Add, the new account found by diffing `credentialed_accounts` before and after, else the "You are now logged in as [x]" line), `gcp_account_cancel()` (sets the cancel flag of the running action). All `main_only`.
- [ ] `GcloudAccountsView` gains `cli: Option<String>` (the located path), filled by `gcp_accounts`.
- [ ] Tests: argument lists; non-email refused; the new-account diff; `forget` empties the cache (a refresh is asked again); a fake gcloud script run end to end through the action runner (Unix).
- [ ] Bindings: `AccountAction`, `AccountActionView`, `GcloudAccountsView`.
- [ ] Commit `feat(gcp): sign in, add, remove and activate gcloud accounts from the app`.

### Task 4: PAM client by entitlement name, and entitlement search

**Files:** `src-tauri/src/gcp/rest.rs`, `src-tauri/src/gcp/pam.rs`, `src-tauri/src/session/transports.rs`, `src-tauri/src/session/record_directory.rs`, every `GcpClient` fake (`grep -rn "impl GcpClient for"`).

- [ ] `pam::EntitlementName { parent, location, id }` with `parse(&str)` and `full()`: parent `projects/<id>` (project ids as the route validates them, plus an optional `domain:` prefix), `folders/<digits>`, `organizations/<digits>`; location and id as resource names. `pam::Entitlement { account: Option<&str>, name: &str }`.
- [ ] `GcpClient::grants(account, entitlement_name)`, `create_grant(account, entitlement_name, duration, justification)`; callers build the name from a route with `EntitlementName::of_route(project, location, id)`.
- [ ] `GcpClient::search_entitlements(account, parent, location) -> Result<Vec<EntitlementInfo>, GcpError>`: SDK `search_entitlements().set_parent(format!("{parent}/locations/{location}")).set_caller_access_type(GrantRequester)`, every page. `EntitlementInfo { name, max_duration_secs: Option<u32>, needs_approval: bool, roles: Vec<(String, String)> }` from the SDK's `Entitlement` (`max_request_duration`, `approval_workflow.is_some()`, `privileged_access.gcp_iam_access.{resource, role_bindings[].role}`).
- [ ] `pam::pending(grants)`: `APPROVAL_AWAITED`. `request_and_wait` gains `wait_for_approval: bool` behaviour: when the created grant is `APPROVAL_AWAITED` and the caller allows it, return it (`RequestOutcome::AwaitingApproval(grant)`) instead of `NotActive`. The connect keeps today's behaviour.
- [ ] Tests (mockito): `entitlements:search` with `callerAccessType=GRANT_REQUESTER`, two pages, a folder parent, the info fields; grant search/create with a folder entitlement name; name parsing (good and bad parents); `pending`.
- [ ] Commit `feat(pam): search requestable entitlements and address grants by entitlement name`.

### Task 5: Scopes and grant memory as library records

**Files:** create `src-tauri/src/sync/pam_library.rs` and `pam_library_tests.rs`; modify `sync/mod.rs`, `sync/records_v3/{types.rs,state.rs}`, `sync/record_repository.rs` (`validate_header` version list), `sync/record_runtime.rs` (version raises, the "raised" permit), `sync/central/payload.rs` (Catalog fields, limits, validation), `sync/central/projection_local.rs` (`public_rows` arms, `catalog_of`), `sync/central/projection_cache.rs` and `projection_delta.rs` (rows from the Catalog), `sync/central/initial_projection.rs` (keep the local maps, as `transports`), `sync/central/projection_capture.rs` (publish step beside `transports::publish_local`), `sync/central/catalog_merge.rs` (two lists; memory never collides), `sync/central/catalog_conflict.rs` / `conflicts.rs` (a scope collision kind), `sync/record_leave.rs` (keep rows as local), `sync/central/adoption/merge.rs` (carry local maps), `src/components/records/CatalogConflict.tsx` (words).

- [ ] Types: `PamScope { id, parent, location, account }` (validate as the spec), `GrantRequestMemory { name, justification, duration_secs }` (validate: `EntitlementName::parse`, today's memory rules), `memory_id(name)` (first 16 hex of SHA-256). Payloads `{schema:1, scope}` / `{schema:1, request}`; `is_scope_id`, `is_request_id`, `decode_*`, `valid(record)`.
- [ ] `PAM_STATE_VERSION = 11` in `records_v3::types`; `decode_state`, `validate_state` (local maps need 11; account `pam_*` rows need 11 and must be valid), `validate_header` accept it. `LocalState.pam_scopes`, `LocalState.pam_requests` (`BTreeMap<String, LocalRecord>`, skip when empty).
- [ ] Reads: `scopes(state) -> Vec<PamScope>` (account rows, else local), `memories(state)`, `memory(state, name)`.
- [ ] Writes: `save_scope(state, scope, now)` (unique per parent/location/account; under central the write gate and the room check with `NO_SCOPE_ROOM`; else local), `remove_scope(state, id, now)` (tombstone), `remember(state, name, justification, duration, legacy_host: Option<&str>, now) -> SyncStateV3` (never fails: on a blocked library or no room returns the state with only the legacy entry removed; keeps 32 by `updated_at_ms`, dropping the least recent as tombstones; under central the room loop drops the oldest until it fits).
- [ ] Catalog: `pam_scopes`, `pam_requests` with `skip_serializing_if = "Vec::is_empty"`; limits 64 and 32; each validated; projections rebuild the account rows (as routes, removing rows the Catalog no longer has); `catalog_of` gathers them (original order, new by id); `public_rows` skips their ids.
- [ ] Publish step: `publish_local` moves local rows into account rows in a central library whose Catalog is settled (scopes while they fit, memories while they fit, rest dropped for memories / kept local for scopes).
- [ ] Merge: scopes as items keyed by id (`Collision::PamScope`); memories keyed by name with `pick`'s collision replaced by the synced value. Conflict row words: `Search scope <parent> · <location>`.
- [ ] Version raises in `record_runtime` (`has_data` → 11) and the delta "raised" permit for the first library `pam_*` rows.
- [ ] Leave: the library's rows become local rows. Adoption: local maps carried as-is (no host ids).
- [ ] Tests: the spec's sync list (round trips through capture and both projections; byte-for-byte Catalog without them; limits; eviction; room refusal and removal; memory collision silent, scope collision reviewed; version 11 raised and refused below; non-central keeps rows local; leave keeps them; validation of bad rows).
- [ ] Commit `feat(sync): sync PAM search scopes and per-entitlement grant memory`.

### Task 6: PAM commands and the connect gate

**Files:** `src-tauri/src/session/transports.rs`, `src-tauri/src/session/record_directory.rs`, `src-tauri/src/session/app.rs`, `src-tauri/src/lib.rs`, `src-tauri/src/sync/record_commands.rs` (overview fields).

- [ ] `PamScopeView { id: Option<String>, parent, location, account, from_routes: bool, host_ids, message }` and `PamEntitlementView` as the spec; `pam_overview(gcp, active, routes, scopes, memories) -> PamOverview` pure (fake client in tests), with bounded parallel calls (four at once, 60 s overall through a channel and `recv_timeout`).
- [ ] `gcp_pam_request(account, name, justification, duration_secs)`: checks the name is listed (route scope, added scope parent/location match, or route-named), requests (approval allowed), remembers through `pam_library::remember` (with no legacy host), answers `PamStatusView` (`approval_awaited` new state).
- [ ] `gcp_pam_scope_save(parent, location, account)` → new id; `gcp_pam_scope_remove(id)`; `gcp_pam_suggestions(account, project, location) -> Vec<String>`.
- [ ] `transports_pam_request` remembers per entitlement and clears the host's legacy entry; the broker's `with_grant_memory` callback (`session/app.rs:163`) does the same; `RecordDirectory::prepare` reads `pam_library::memory(state, name)` then `transports::grant_memory(state, host)`.
- [ ] `RecordOverview` gains `pam_scopes: Vec<PamScope>` and `pam_requests: Vec<GrantRequestMemory>`.
- [ ] Remove `gcp_pam_grants` and `PamGrantView` (and the binding).
- [ ] Tests: aggregation (route scopes resolved to the active account, added scopes, route-named entitlements kept on search failure, de-duplication by account and name, approval state); request refusals and memory; the connect gate's memory order.
- [ ] Commit `feat(pam): a standalone entitlement overview and requests by entitlement`.

### Task 7: Frontend

**Files:** create `src/lib/cloud.ts`, `src/components/records/GoogleAccountsTab.tsx`, `src/components/records/PamAccessTab.tsx`, `src/components/records/PamScopeDialog.tsx`, `src/components/records/GcloudActionDialog.tsx`; modify `LibraryNavigation.tsx`, `GoogleCloudPanel.tsx`, `GrantRequestDialog.tsx`, `HostPreview.tsx`, `TunnelsPanel.tsx`, `IapRouteFields.tsx`, `src/lib/transports.ts`, `src/lib/records.ts`, `src/dev/interface-preview.tsx` (fakes), tests beside them.

- [ ] `cloud.ts`: `CLOUD_PROVIDERS = [{ id: "gcp", label: "Google Cloud", panel: "transports" }]`; the navigation renders a "Cloud" heading and one row per provider.
- [ ] `GoogleCloudPanel`: header, then `Tabs` Accounts / Access / IAP hosts (tab kept in component state per session).
- [ ] Accounts tab: the gcloud line and Check again; rows with actions and the row menu; Add account; confirmations (`AlertDialog`) with the spec's words; the sign-in dialog listening to `gcp-sign-in-url`; disabled actions and command text without gcloud; refetch `gcloudAccountsKey` after each action.
- [ ] Access tab: Where Lunport looks (route scopes, added scopes, Add scope…, Remove), entitlement rows with roles, Up to, Needs approval, Used by, state (`approval_awaited` → "Awaiting approval"), Request grant disabled while held or pending; `pamOverviewQuery` (60 s refresh while shown).
- [ ] `GrantRequestDialog` takes `{ account, name, entitlement id, project label, maxMinutes, memory, defaultMinutes }` and a `request` function, so the Access tab, host details and Tunnels share it; the approval answer sentence.
- [ ] `IapRouteFields`: suggestions from `gcp_pam_suggestions` under the Entitlements field (click adds the id).
- [ ] `grantMemoryFor` reads `pam_requests` by the route's first entitlement name, then the legacy `grant_memory`.
- [ ] Tests: each item of the spec's frontend list.
- [ ] Commit `feat(ui): a Cloud section with Google accounts, access grants and IAP hosts tabs`.

### Task 8: Documentation, full checks, PR

- [ ] `docs/usage.md` (Google Cloud section), `docs/development.md` (gcp::cli, records, Catalog fields, version 11), with the older-release note.
- [ ] Full checks: CI's lib suite, `--test app_profile_build`, `pnpm test`, `pnpm build`, `git diff --check`; revert binding churn.
- [ ] Interface preview screenshots of the three tabs (Playwright).
- [ ] Commit `docs: Cloud accounts and access grants`; push; open the PR to `main` listing what is unverified live (the spec's Live list).
