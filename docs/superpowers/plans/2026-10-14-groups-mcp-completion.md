# Groups and Records MCP Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Finish Groups, Records MCP execution and public-key deployment, then release the next Beta.

**Architecture:** Extend the immutable Records repository with raw/effective Group resolution and guarded format upgrades. Connect MCP and deployment to the existing OS-authenticated broker/own SSH engine, with explicit local policy, native questions and public audit metadata.

**Tech Stack:** Existing Rust/Tauri/russh, React/TypeScript, Vitest and native GitHub Actions. No new production dependencies.

**Spec:** `docs/superpowers/specs/2026-10-14-groups-mcp-completion-design.md` is binding; read the sections relevant to the assigned task. User delegates design/workflow choices and explicitly authorizes merge/publish.

## Global Constraints

- Baseline `0e9c727f35f6f704e443d694c1c62f08432ca389`; work in the clean `codex/groups-mcp-beta3` checkout, preserving the attached phase-1c worktree.
- English Conventional Commits, Traditional Chinese replies. Never commit secrets or operate real user hosts/data/permissions.
- Stable identities, immutable candidates, CAS, persist-before-runtime-replace, generation and unknown-record protections remain authoritative.
- Old state 3 and ungrouped host schema 2 remain readable; Group state 4, host schema 3, group schema 1; account supported range 3..4. Future formats fail closed and retain bytes.
- Inherited defaults: port 22, OS user, password/no key, no jumps, keepalive 30 seconds/3 misses, connect timeout 15 seconds. Maximum Group ancestry 32.
- MCP defaults Ask; approval 120 seconds, command 16,384 bytes, exec 1..300 seconds/default 60, combined output 128 KiB. Auto-log never prompts/pins.
- Persistent audit 1000 entries; AI Access shows latest 10; clientInfo fields sanitized to 100 characters.
- No lifecycle lock across waits/SSH/audit; no secret or output in audit/preview/state. Deployment sends only canonical public keys to POSIX hosts.
- Observe meaningful RED before GREEN. Tests exercise behavior, not source strings, mock presence or repeated implementation logic.

## Review Focus

1. Inherited port/route/key changes after a user approves must not reach a different target or reuse an old pin (Tasks 1 and 3).
2. Unknown winning Group/host records and failed account gating must not let an older cache upload or connect (Task 1).
3. Scope moves, deletion and leaving/rotation must preserve effective settings without dangling Group/jump identities (Task 1).
4. Cancel/disable/revoke while native authentication or exec is blocked must stay responsive and release all questions/sessions (Tasks 3 and 4).
5. Duplicate deploy, path symlink, stale destination/public key and missing exit status must not overwrite content or report a false success (Task 5).

---

### Task 1: Group records, effective resolution and lifecycle

**Ownership:** Rust Group feature only: `sync/records_v3/{types,state,validate,mod,tests}.rs`, new `sync/record_groups.rs` and tests, repository, merge/round/account/rotation/leave/import/migration/runtime compatibility paths, `session/record_directory.rs` and tests, command DTOs/Group commands and their `lib.rs` registration. Existing test-fixture updates in these areas are included. Do not edit frontend product code or MCP.

**Consumes:** Existing `SyncStateV3`, `RecordRevision`, `HostPayload`, SyncCore persistence and encrypted record merge.

**Produces:** Exported Group payload/defaults/record/view types; `RecordOverview.groups`, format-upgrade flags; `HostView.effective_payload`, `inherited_from`, `group_error`; repository Group CRUD and effective resolution; `records_group_create(scope,payload,upgrade_confirmed)`, `records_group_update(id,revision,payload)`, `records_group_delete(id,revision)` returning overview. Existing host create/update add optional `upgrade_confirmed: Option<bool>` (missing means false) and use the same protected promotion path for first inheritance. `HostPayload.group_id` and `inherit` use the spec's names. Detail any justified API adjustment in the task report before frontend implementation.

- [x] Step 1: Add behavioral tests using JSON fixtures so existing Rust literals are not needed for RED. Assert literal effective values/provenance for parent user `ops`, child port `2222`, host override keepalive `10`. Test missing/opaque ancestor, cycles and same-scope validation. Run `cargo test --offline --locked --lib group` and retain RED log; a missing function/field is an expected feature failure, unrelated syntax/type errors are not evidence.

```rust
// Desired boundary contract, implemented in record_groups.rs:
// resolve_effective(state: &SyncStateV3, host: &HostRecord)
//     -> Result<EffectiveHost, RepositoryError>
// EffectiveHost { payload: HostPayload, inherited_from: BTreeMap<String,String> }
// Assert payload.user == "ops", port == 2222 and keepalive_secs == 10.
// Mutating inheritance precedence or flattening raw host values must fail this test.
```

- [x] Step 2: Implement Group types/codec/validation and old/new format support. Add Group kind and Local groups, schema-2 omission, schema-3 host membership. Keep raw/effective values separate; reject missing parents and unsafe authentication combinations. Use strict known fields and preserve future envelopes.
- [x] Step 3: Extend snapshot/readiness/routes and directory effective endpoint/pin CAS. Tests: a parent port changing from 22 to 2222 clears the descendant pin; using an old endpoint to pin fails; an unrelated host pin remains. Group auth resolves key ID atomically and never falls back to a conflicted same-ID key.
- [x] Step 4: Add pure CRUD candidates, revision checks and native commands. Before state-3 promotion require upgrade confirmation and protected source backup. Before shared uploads promote account metadata and prove a failed schema-gate push yields zero Group/host-schema-3 child pushes. Tests reject unconfirmed promotion, stale revision, cross-scope parent and invalid effective jump route. Deletion preserves literal effective payload/ID/credential references.
- [x] Step 5: Integrate encrypted merge, unknown shadows, round trips, rotation and leave journals. Use the existing fake-relay fixtures to assert two clients resolve the same literal nested defaults after sync. Assert leave remaps Group/host/jump IDs without changing effective values, and rotation preserves all Group/tombstone rows. Unreadable selected Group sources prevent a destructive detach.
- [x] Step 6: Run focused repository/Group/directory/round/lifecycle tests and the full safe Rust suite (the three actual OS credential tests may be excluded as before). Update generated binding/fixture code only as necessary and report exact counts/errors. Commit only owned paths as `feat(records): add nested groups and inherited settings`.

### Task 2: Group workspace and inheritance editor

**Ownership:** `src/lib/records.ts`, `src/components/records/{RecordsWorkspace,HostList,HostEditor,editor,selection,fixtures}.tsx/ts` and tests; new Group editor/tree helpers/tests. Do not change Rust or MCP UI.

**Consumes:** Task-1 overview/API/types; report records exact shape. **Produces:** Local/Space → nested Group → host browsing, create/edit/delete, raw inheritance controls, format confirmation, dirty-draft preservation.

- [x] Step 1: Write RED tests for a grouped host using raw `user:"fallback"` but effective `user:"ops"`, proving editor save preserves raw values and selected inherit field rather than flattening. Test search reveals ancestors and stable-ID selection. Use real component/helper behavior and literal expected results.
```ts
// A host with inherit:["user"] must save raw user:"fallback" and inherit:["user"].
// Its visible effective user/source must be "ops" / the parent Group.
// Clearing Use group default must save the user's explicit value and inherit:[] for user.
```
- [x] Step 2: Extend frontend types/wrappers from Task 1. Build a focused tree helper with stable ordering, cycle/missing diagnostics, scope roots and Ungrouped. Keep search and actions outside scrolling content. Do not invent Group grants or bulk execution.
- [x] Step 3: Implement GroupEditor with explicit scope, parent/defaults, affected host counts, upgrade confirmation and delete preservation notice. Reuse dirty/busy selection guards and Keep editing default focus for host/group switches. Test API payload selection with correct IDs/revisions and failed save retaining drafts.
- [x] Step 4: Add host Group dropdown and per-field inheritance, source labels, effective preview and new-host-in-selected-Group behavior. Check atomic authentication/key handling, scope moves, drafts across tabs and error recovery.
- [x] Step 5: Run frontend suite, TypeScript and Vite; inspect actual real-component layouts in light/dark and minimum-size states when integration is available. Commit `feat(ui): add group browsing and settings inheritance`.

### Task 3: Records MCP IPC, execution, policy and audit backend

**Ownership:** `src-tauri/src/mcp.rs`, new focused MCP modules/tests, `session/{protocol,broker,app,mod,connect,auth}.rs` as necessary, IPC adapter helpers, AppState/lib registration, auth-question hub/capability/backend, public generated bindings. Preserve Task-1 APIs. No frontend UI product edits.

**Consumes:** Effective Records directory and existing connector/keychain/material/host-key hub; OS-verified peer PID/process chain. **Produces:** broker-backed Records metadata and exec; Ask/auto-log policy, native auth hub commands, persistent session log/status DTOs; adapter sanitizes clientInfo and propagates cancellation.

- [x] Step 1: Read approved own-SSH spec section 8 and completion spec section 5. Record chosen IPC frames/version in the report. Add RED tests against real dispatch/policy with FakeEngine/temporary public state: allowed ID reaches engine; denied ID never reaches it; old `run` returns rename error; spoofed clientInfo/PID never replaces OS attribution.
```rust
// A scripted FakeEngine exec returns Ended::Disconnected and exit_code:None.
// The MCP result must retain disconnected/null, not successful/0.
// A Group-derived endpoint changes while approval is pending: no exec call occurs.
```
- [x] Step 2: Extend MCP broker IPC, thin stdio adapter and lifecycle/cancel behavior. Keep Legacy mode usable. Do not expose a new unauthenticated port; Records must not depend on TCP/runtime-token files. Test protocol mismatch, EOF and cancellation before registration/approval/auth/exec. Bound request concurrency and serialized output frames.
- [x] Step 3: Implement Ask/auto-log, responsive revoke/disable, resolved-target rechecks and native questions. Default Ask, risk acknowledgement on auto-log change; no auto-log pin/auth prompts. Tests cover every interactive category, changed route/key/port after approval, output cap and all endings. Never hold lifecycle locks across waits.
- [x] Step 4: Persist/load/bound the public-only 1000-entry session log and include requester/clientInfo/mode/outcome in status. Test restart, cap, malformed trailing line, I/O failure visibility and no auth/output secret sentinel. Integrate app quit with cancellation/drain; produce auth-question command DTOs for Task 4.
- [x] Step 5: Run focused MCP/broker/auth/audit tests, safe Rust suite and binding exports. Check existing revocation and profile guard regressions. Commit `feat(mcp): execute records commands through the session broker` and document exact UI API/DTO interfaces.

### Task 4: MCP approval, auth window and AI Access UI

**Ownership:** `src/lib/mcp.ts`, `src/components/AiAccess*`/actual settings AI component, `McpApproval*`, new native auth-window component/routes and tests, Tauri frontend window entry wiring, generated frontend bindings where needed. No Rust backend edits except a controller-approved interface repair.

**Consumes:** Task-3 mode/status/question/log commands and DTOs. **Produces:** usable Ask/auto-log control, attribution, native auth questions and recent public audit view.

- [x] Step 1: Add RED tests: auto-log is not applied until acknowledgement; switching back to Ask is immediate; requester/clientInfo labels remain distinct; cancel/refuse default focus; echoed versus concealed prompt fields; expired questions remove inputs and never resubmit secrets.
- [x] Step 2: Implement controls and concrete auto-log warning using existing Dialog primitives. Show individually permitted host IDs/Group paths without Group grants, most recent 10 outcomes and explicit nullable exit status. Replace metadata-only limitations only when actual backend capability is ready.
- [x] Step 3: Build compact native auth window with escaped server labels, request/hop attribution, expiry, no clipboard/secret persistence, cancellable inputs and clearly abandoned retry state. Do not autofocus Allow on command or key questions. Preserve full command visibility.
- [x] Step 4: Run frontend suite, TypeScript/Vite and actual-component visual checks at normal/minimum size. Report any native interaction limits. Commit `feat(ui): add records MCP approval and authentication flows`.

### Task 5: Human-confirmed Records public-key deployment

**Ownership:** new `src-tauri/src/session/deploy.rs` or focused records deployment module/tests, native deploy commands and registrations, `src/components/records/KeysPanel.tsx`, focused deploy dialog/API/helper/tests. Reuse Task-3 auth/execution interfaces, do not modify MCP grants.

**Consumes:** Authoritative public key metadata, effective target, own connector and native authentication hub. **Produces:** preview/confirm/cancel deployment APIs and Keys workflow for POSIX remote accounts.

- [x] Step 1: Add RED behavioral tests using a temporary HOME and running the actual generated POSIX script locally: existing authorized_keys content survives; duplicate deployment is a no-op; symlinks are refused; only canonical public text appears in the command. No test may write actual user ~/.ssh.
```rust
// Run the generated script twice with a public fixture key and a TempDir HOME.
// Assert the original sentinel line survives and the fixture algorithm/blob occurs once.
// A symlink authorized_keys leaves the target bytes unchanged and returns failure.
```
- [x] Step 2: Add preview with stable target/key identity and effective route snapshot; confirmation checks snapshot unchanged and explicit authorization, then connects/executes without invoking OS ssh/askpass. Test stale Group endpoint/key preview, unavailable key metadata, refusal/cancel/timeout/unknown ending.
- [x] Step 3: Implement bounded lock/secure permissions/idempotent append, distinct outcomes and public-only audit. Remote POSIX limitation is shown before confirmation; Windows clients still support POSIX deployment. Never set auth mode/key ID on a host automatically as a side effect of installing a public key.
- [x] Step 4: Add Keys deploy dialog target/fingerprint/authorization preview, progress/cancel, durable success/error state and stale-preview refresh. Run focused tests and complete frontend/safe Rust integration as necessary; commit `feat(keys): deploy public keys to records hosts`.

### Task 6: Integration, review, native validation and Beta publication

**Ownership:** Controller integration fixes, CI fixture extensions when needed, release notes/checklist/validation. No speculative feature expansion.

- [x] Step 1: Review combined APIs, generated bindings, legacy/profile boundaries and actual UI flows. Add disposable real SSH integration coverage for own-engine exec endings/cancel/auth and public deployment where the existing CI fixtures permit it; never operate real user hosts.
- [x] Step 2: Run full safe Rust, all frontend tests, TypeScript/Vite, Development bundle and independent final branch review. Correct consequential findings and scoped re-review only new repairs. Capture screenshots of Group/MCP/deployment without granting real permissions.
- [x] Step 3: Write Beta notes describing actual compatibility upgrade and remote-POSIX limit; remove completed backlog items, retain honest device/runtime limitations. Merge only reviewed code into next/own-ssh, push and wait for exact-source macOS/Linux/frontend/PAM and Windows CI.
- [ ] Step 4: Use beta.yml with the next unoccupied 1.0.0 suffix. After all four installer jobs and Beta manifest succeed, independently check exact tag/source, complete assets/platforms/signatures, canonical manifests and Stable unchanged. Save receipt/checklist and commit docs only. Do not update the installed Production app.
- [ ] Step 5: Persist this plan's ledger in repository documentation and clean only its git-ignored scratch. Final response includes Beta link, actual completed features, verification and material remaining limits, with screenshots and memory citation if used.
