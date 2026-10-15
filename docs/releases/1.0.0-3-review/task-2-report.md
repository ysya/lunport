# Task 2: Group workspace and inheritance editor

Status: DONE; ready for controller task-scoped review. Base: `f6bcf98edc56f3b99591649330dc9175e7dc1464`. Branch: `codex/groups-mcp-beta3`.

## Changes

- Added exact native Group/default/inheritance/effective-host/format-upgrade DTOs and Group CRUD wrappers. Host create/update optionally forward `upgradeConfirmed`; ordinary schema-2 arguments remain unchanged. Revisions remain strings.
- Added stable scope-root/nested-Group/Ungrouped tree construction. Local first, selected Spaces and retained missing-scope rows remain inspectable; groups/hosts sort by name/alias then stable ID. Search covers host alias/endpoint/tags/Group path and reveals ancestor rows, including broken Group ancestor diagnostics. Expansion state remains separate from search. Duplicate Group/host IDs remain visible and cannot select an arbitrary row.
- Added Group editor with explicit immutable saved scope, parent validation, optional defaults, atomic authentication/key selection, ordered jump defaults, effective/default-source preview, descendant/host counts and host-preserving subtree-delete confirmation. CAS revisions and dirty drafts survive native failures, remote changes and row removal. New Group/first inheritance use requires the applicable Local/Space format confirmation; Keep editing receives default focus.
- Added scope-filtered host Group selection and per-field inheritance. Inherited fields display disabled effective controls with source labels, while raw values remain in the draft and submitted payload. Clearing inheritance restores the raw override; app-default username uses the OS-username sentinel. Authentication and key resolve as one pair; available keys use their display names.
- Inline inheritance controls sit beside Port/Username/Auth and Advanced jump/keepalive/timeout settings. Alias/Hostname/Group remain near the top. New host inside a selected Group has that membership without silently selecting inheritance. Moving between scopes explains materialization and membership removal.
- Host/Group/new transitions share busy and dirty guards. Both editors stay mounted while workspace sections hide them. CommandPalette includes Group path in host display/search, preserving existing stable-ID actions. The controller approved the minimal `operations.ts` `group_error` connection guard, so stale readiness cannot bypass Group diagnostics through another entry point.
- Presentation-only draft preview does not treat saved `effective_payload` as preview of a changed Group/inheritance selection. Rust remains authoritative on save/connect. Group diagnostics prevent showing effective fallback as usable and disable connecting.

No Rust, MCP product UI, Keys/Account flows, dependencies, production state, real hosts, credential stores, release workflows, pushes or releases changed.

## Meaningful RED to GREEN evidence

Commands use existing `node_modules/.bin/vitest`; all logs are under `/private/tmp`.

1. `vitest run src/components/records/editor.test.ts`: `sshelter-task2-editor-red.log` showed **1 failed / 10 passed**, literal `expected undefined to be null` for absent Group membership. Normalization plus schema-2 omission fixed it; final suite passes.
2. Feature tests initially imported missing Group helper modules (`sshelter-task2-red.log`); this is a feature-boundary import failure, not claimed as behavioral RED. Once helpers existed, `sshelter-task2-green1.log` showed **1 failed / 18 passed** because real HostEditor markup lacked `ops` and the source Group. Preview/helpers and component controls then passed **31 tests / 3 files** (`sshelter-task2-green2.log`). Group editor component absence was also recorded in `sshelter-task2-ui-red.log`, not counted as a behavioral assertion.
3. `vitest run src/components/records/groups.test.tsx`: `sshelter-task2-safety-red.log` showed **2 failed / 12 passed**. The behavioral RED was a diagnostic host with stale ready status incorrectly resolving connection and sending IPC. The second failure, `recordHostSearchText is not a function`, was a feature-boundary failure and is not counted as behavioral search RED. Added the approved shared connection guard and shared path search; final search assertions verify literal Group-path contents. Focused helpers/component/selection/workspace regression passed **50 tests / 5 files** (`sshelter-task2-green4.log`).
4. Controller actual-component check identified a separate seven-row inheritance card obscuring normal fields. Updated the observable input assertion before implementation: `sshelter-task2-inline-red.log` failed because no disabled `value="ops"` control existed. Inline controls fixed this, passing **29 tests / 2 files** (`sshelter-task2-inline-green.log`). The same test still asserts exact IPC save of raw `user:"fallback"` and `inherit:["user"]`. Additional real-component markup verifies inherited key auth/reference controls disabled with Work key selected, and clearing inheritance restores enabled `fallback` input.
5. `sshelter-task2-controls-red.log`: **1 failed / 20 passed**, selected duplicate Group ID had no selected option and looked Ungrouped. Added unavailable selected membership/parent options. Focused regression passed **57 tests / 5 files** (`sshelter-task2-controls-green.log`).
6. Controller accessibility check requested distinct field names. `sshelter-task2-a11y-red.log`: **1 failed / 20 passed**, missing `aria-label="Username: Use group default"`. Added field-specific names; `sshelter-task2-a11y-green.log`: **21 passed**. An intermediate missing import caused **5 errors** and a TypeScript error; it was corrected immediately and is not counted as meaningful RED or passing validation.
7. Final self-review found diagnostic ancestors hidden while searching their host: `sshelter-task2-diagnostic-search-red.log` **1 failed / 20 passed**, literal expected Fleet/Operations IDs versus `[]`. Added matching-host ancestor IDs to diagnostics. Final full suite below includes the passing regression.

Tests also cover literal all-seven app defaults, nearest ancestor user/port, authentication pair/raw retention, changed unsaved Group choices, exact Group scope/parent/trimmed-name/upgrade arguments, frozen deletion revision, CAS failure immutability, remote/removed draft recovery, cycles/orphans/duplicates, cross-scope/self-descendant parent rejection, malformed auth default rejection, stable ordering and separate Local/shared format gates.

## Final verification

All final checks ran after the last behavior and accessibility change; no implementation changes followed them before commit.

- `node_modules/.bin/vitest run`: **66 files passed / 972 tests passed / 0 failed**, duration 1.36s. `sshelter-task2-full-frontend.log`, start 2026-10-15 00:01:43 Asia/Taipei.
- `node_modules/.bin/tsc --noEmit`: **exit 0**, no diagnostics. `sshelter-task2-tsc-final.log`.
- `node_modules/.bin/vite build`: **exit 0**, 2132 modules transformed, built in 13.94s. `sshelter-task2-vite-final.log`. Vite reports the >500 kB chunk-size advisory; bundle is 974.16 kB / gzip 284.71 kB. No build error or new dependency.
- `git diff --check`: **passed**.
- Formatting used an already-installed Prettier binary from another local checkout; no installation or dependency-file change.

Controller performed preview-only real-component checks during iteration. The updated 800×560 inline layout shows Alias/Hostname/Port/User/Auth on the first screen with effective 2222/ops/key and Operations key name; Group draft survives Keys→Hosts; host/Group discard dialog focuses Keep editing. The initial 1100×720 check caused the card-to-inline correction. Final normal/minimum light/dark screenshot capture and native integration remain the controller's integration work. This report does not claim an installed native app or real production data was exercised.

## Files

- `src/lib/records.ts`
- `src/components/records/RecordsWorkspace.tsx`
- `src/components/records/HostList.tsx`
- `src/components/records/HostEditor.tsx`
- `src/components/records/CommandPalette.tsx`
- `src/components/records/operations.ts`
- `src/components/records/editor.ts`
- `src/components/records/editor.test.ts`
- `src/components/records/selection.ts`
- `src/components/records/fixtures.ts`
- `src/components/records/FormatUpgradeReview.tsx`
- `src/components/records/GroupEditor.tsx`
- `src/components/records/group-editor.ts`
- `src/components/records/group-tree.ts`
- `src/components/records/inheritance.ts`
- `src/components/records/groups.test.tsx`

## Self-review and concerns

- Reviewed raw/effective separation: only cloned presentation fields receive defaults; save uses raw draft, stripping pins as before. Authentication resolution assigns auth and key together, and UI auth changes clear key for non-key methods. No credential or key material is introduced into Group/default/preview DTOs.
- Reviewed selection ambiguity and current removed IDs: selectors return null for duplicate identities, rows stay visible, unavailable editors do not become create forms. Hidden sections preserve the mounted editor; pending mutations block replacement. Scope moves continue using the native materialization command.
- Reviewed upgrade flags/casing: Local checks local flag; Space checks either flag; existing schema-2 host commands omit optional consent and empty extensions. Group update does not accept scope/upgrade arguments.
- Reviewed failures/refresh: native failure catches update only the error, not payload/revision; dirty refresh retains draft/CAS and surfaces conflicts. Delete notices/counts state host preservation rather than claiming remote execution.
- Presentation-only preview shares documented literal precedence but is not an execution resolver; native save and Records directory remain authoritative. No native-interface gap identified.
- Remaining concerns: Vite chunk-size advisory; controller final visual screenshots/native integration and independent task review are pending. No known blocking frontend issue.

## Commit

`f071333f8889f690e455c277e775e717937d588a` — `feat(ui): add group browsing and settings inheritance`. Commit held `/private/tmp/sshelter-index.lock`, verified preexisting index empty, and staged exactly the 16 paths above. Post-commit `git status --short` is clean.


## Task 2 fix round 1 — Important I1/I2 and Windows select theme

Review base: `f071333f8889f690e455c277e775e717937d588a`. Formal review: `task-2-review.md`; native-select diagnosis: `windows-select-diagnosis.md`.

### Verified causes and changes

- **I1 immutable Group deletion candidate:** the original boolean delete state let pristine refresh replace `state.revision` while the review was open. GroupEditor now captures an immutable `{ id, revision, counts }` when opening. Revision and counts are cloned and frozen; the dialog renders candidate counts; confirmation submits only candidate ID/revision. Current editor identity/availability is checked without substituting its newer token. A stale revision is left to native CAS, and the normal failure path retains draft and candidate. Closing and reopening creates a fresh review.
- **I2 saved connection diagnosis versus changed draft:** the original HostEditor overwrote the draft preview diagnostic unconditionally with saved `group_error`. It now calls `previewHostDraft`: same-scope/same-Group dependency retains the authoritative saved winning-record diagnosis even when a stale readable Group row exists, while a replacement/detached dependency is resolved from the actual draft. A changed still-invalid Group reports its own missing/conflict diagnostic. Valid replacement uses `ops`/Operations; detach uses empty OS-username sentinel/`default`; raw `fallback` and selected inheritance remain in the saved payload. The saved host diagnosis and readiness still block Connect until a successful persisted repair.
- **Windows native select:** added exactly `:root { color-scheme: light; }` and `.dark { color-scheme: dark; }` within their existing rules. This follows app-selected Light/Dark, including manual Light under a dark OS preference; it retains native controls and existing custom colors. No mirrored CSS/string test or new dependency was added. The provided baseline demonstrated root/select computed `normal` in both app modes; controller handles fresh computed-style/local-popup checks and records the Windows-platform limit.
- Corrected the earlier feature-boundary search RED classification: missing `recordHostSearchText` was not a behavioral failure.

### RED/GREEN and final focused checks

Existing frontend tests use `react-dom/server` and no DOM environment/test renderer. `renderToStaticMarkup` does not mount effects or rerender interactive state. Per controller instruction, production helpers were extracted and wired into the actual components; extraction first preserved the original submit-current-revision/unconditional-diagnostic behavior, then the regression tests observed failures before the fixes. No test-only input/debug prop, hook mocks, source-string assertions or new dependency was introduced. Controller's actual-component fixture supplies the review-open → overview-refresh → confirm interaction check; these helper tests do not claim mounted UI coverage.

1. `node_modules/.bin/vitest run src/components/records/group-review-fixes.test.ts` after behavior-preserving extraction: **4 failed / 2 passed**, `sshelter-task2-fix1-red.log`.
   - Refreshed pristine editor holds revision `999`; old helper sent that new revision, incorrectly resolving deletion instead of the expected old-candidate CAS conflict.
   - Valid Group replacement calculated `ops` with Group ID `0000000000000010` but retained error `Opaque winning Group` instead of null.
   - Detach calculated empty OS-username/default provenance but retained the same old error instead of null.
   - Changed invalid Group returned the old opaque diagnosis rather than the new missing/conflicting diagnosis.
2. Final focused command:
   `node_modules/.bin/vitest run src/components/records/group-review-fixes.test.ts src/components/records/groups.test.tsx src/components/records/editor.test.ts src/components/records/markup.test.tsx src/components/records/selection.test.ts src/components/records/workspace.test.tsx`
   **6 files / 63 tests passed / 0 failed**, duration 497 ms. `sshelter-task2-fix1-green.log`. Added regressions assert literal old revision/counts, clone isolation from source mutation, CAS rejection, raw override/inheritance preservation, valid/detached draft values/provenance, unchanged winning-record protection and zero Connect IPC from the saved diagnostic.
3. `node_modules/.bin/tsc --noEmit`: **exit 0**, no diagnostics; `sshelter-task2-fix1-tsc.log` explicitly records `tsc exit_code=0` using a subprocess exit-code capture.
4. `node_modules/.bin/vite build`: **built successfully in 15.49s**, CSS 102.03 kB/gzip 16.56 kB, JS 974.69 kB/gzip 284.87 kB; `sshelter-task2-fix1-vite.log`. The existing >500 kB advisory remains.
5. `git diff --check`: **passed**. No broad suite repeated; the previous 66-file/972-test run applies to the base Task 2 commit, while final whole-branch integration remains Task 6.

### Scoped files and self-review

`GroupEditor.tsx`, `group-editor.ts`, `HostEditor.tsx`, `inheritance.ts`, new `group-review-fixes.test.ts`, and the two-declaration `src/index.css` change. Reviewed that saved diagnostic continues to block Connect, invalid new ancestry still cannot display effective fallback, raw values/provenance stay distinct, and neither source mutation nor fresh overview can replace the reviewed revision/counts. No Rust/native DTO, MCP UI, real state/host/credential, dependency, or unrelated editor behavior changed.

Remaining limitations: automated tests cover actual production helper transitions, not a mounted component refresh race; controller will verify that race, computed themes/popups and final native/Windows integration. No known remaining blocker in this scoped fix. Vite chunk-size advisory remains.

Fix round 1 commit: `a3ce927276769d544e1e2ca749730e572a4d44bc` — `fix(ui): preserve reviewed group deletion and repair previews`. Held the shared index lock, verified empty preexisting index, and staged exactly the six scoped paths.
