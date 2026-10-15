# Task 4 — Records MCP approval, authentication and AI Access UI

Status: implemented; frontend validation passed. Commit and final controller visual evidence will be appended below. Branch `codex/groups-mcp-beta3`, starting BASE `e8b8da06faeaa70d840a04b329015aaebd13ae8b`. No Rust/native contract changes, dependencies, real permissions, credential reads, real SSH connections, relay calls, push, merge or release.

## Scope and implementation

- `SettingsDialog.tsx` actual `McpPane` now describes Records execution, uses effective destination/user/port plus stable host ID and full nested Group path, and never creates a Group grant. `mcp_set_host_allowed` still receives `{alias:host.id,allowed}` for Records. Legacy retains individual alias grants and Ask/Allow once; Auto-log controls are Records-only.
- Ask returns directly through the mode mutation. Selecting Auto-log only opens the existing AlertDialog; no policy call occurs before the concrete risk checkbox is acknowledged. Cancel is the default Radix alert-dialog action. Warning explains arbitrary shell commands, file/data deletion, service changes/data transmission, no per-command review, and that logs cannot undo actions. The native call passes the explicit acknowledgement.
- Platform notice is displayed directly from the authoritative `noninteractive_credentials_notice` beside mode controls. Auto-log never opens authentication/trust UI or supplies missing credentials/2FA/pins. Hidden-launch copy conditionally directs the user to tray/normal launch when background sync is unavailable; it does not claim the superseded Space-pin limitation.
- The advanced Records pane no longer claims MCP metadata-only or unavailable execution. It describes currently ready MCP/auth behavior; it does not prematurely claim Task5 public-key deployment.
- Public persistent audit renders only the latest 10, explicit `client` connect/mcp/deploy labels and approval mode/outcome, actual `ended`, nullable exit as **unknown**, nullable signal as **none reported**, host ID, and distinct requester attribution. `allowed` is authorization, without a success color or exit0 inference. Audit persistence errors are visible; completed execution is never automatically retried. Command output/answers are never displayed in this audit view.
- `McpAttribution` presents OS-observed process chain/requester independently of **Self-reported client** name/title/version. Missing attribution is Unknown. App display applies `revealHidden` and clips clientInfo again to 100 Unicode codepoints before revealing hidden characters.
- `McpApprovalDialog` now mounts in the Records branch as well as Legacy. Both the dialog content and review card are keyed by immutable request ID. The review card captures the initial candidate, so polling cannot swap its command/target beneath the reviewed Allow handler. Deny receives focus on every ID transition. Allow is initially held for the existing 700ms review guard, and disabled on expiry/busy. Complete command stays in a wrapping scrollable pre; endpoint/stable host/route/process/clientInfo stay with that reviewed candidate. Native stale-target/expiry checks remain authoritative.
- `main.tsx` routes window label `authentication` to `AuthenticationWindow` while preserving approval/hostkey/main routing.
- `AuthenticationWindow` registers `authentication://requests` before fetching `auth_pending`; any later event invalidates an older in-flight fetch. Every received snapshot captures wall/monotonic clocks, and each question ID gets its own card. No process-wide secret store, clipboard, logs, URLs or persistence are used for answers.
- Authentication shows trusted request/question/hop IDs, alias, endpoint separately from escaped server prompt. `echo` controls text/password, completion/spelling/autocorrection are disabled. Cancel receives focus; Submit uses the existing 700ms guard and Enter obeys guard/composition/expiry. Empty interactive responses remain valid.
- Relative `remaining_ms` is capped at 120000 and interpreted at snapshot receipt, with paired wall/monotonic bounds. Same-ID refreshes only shorten deadlines and cannot renew them. Either clock expiry clears answer/removes input. New IDs remount with no old answer. Answers are consumed and cleared **before** native invoke, and marked abandoned so failures never resubmit old input. Failure copy is generic and never echoes native error/answer. Cancel invokes null. The response area is fixed above the footer so even a 4096-character challenge leaves answer/Cancel/Submit visible at 480×360; full public context/prompt remains scrollable.

## Exact consumed API / unchanged backend

| Invoke | Arguments | Result |
|---|---|---|
| `mcp_status` | none | existing generated McpStatus |
| `mcp_set_enabled` | `{enabled}` | McpStatus |
| `mcp_set_host_allowed` | `{alias:stableHostId,allowed}` in Records | McpStatus |
| `mcp_set_approval_mode` | `{approvalMode:"ask"|"auto_log",riskAcknowledged:boolean}` | McpStatus |
| `mcp_resolve_request` | `{requestId:reviewed.id,allow}` | void |
| `auth_pending` | none | existing generated AuthRequest[] |
| `auth_resolve` | `{requestId:question.id,value:string|null}` | void |

DTO fields remain snake_case, invoke args camelCase. No generated binding edits. Events unchanged: `mcp://approval-requested` and `authentication://requests`. Native authentication builder/capability inspected: label authentication, 480×360, core defaults; no frontend dimension override or new permissions.

## Meaningful RED → GREEN evidence

All commands used the existing Vitest SSR/testing infrastructure. External native invocations/events were stubbed at the IPC/event boundary; real component rendering, mode control, deadline/answer state and feed behavior remained under test. No DOM dependency added.

| Round / exact command | Observed result | Evidence |
|---|---|---|
| `npm test -- src/components/McpPane.test.tsx` (RED) | 3 failed: absent Auto-log/capability, absent audit error/nullable ending, absent visible stable ID | `/private/tmp/sshelter-task4-red-pane.log` |
| `npm test -- src/lib/mcp-flow.test.ts` (RED) | 4 failed: selection incorrectly lacked confirmation, expiry Infinity, same-ID refresh bound absent, answer not cleared/replay permitted | `/private/tmp/sshelter-task4-red-flow.log` |
| `npm test -- src/components/McpPane.test.tsx src/lib/mcp-flow.test.ts` (GREEN) | 7 passed | `/private/tmp/sshelter-task4-green-controls.log` |
| `npm test -- src/components/McpQuestions.test.tsx` (RED) | 5 failed: required review/auth content/default focus absent, echo/expiry/guard absent | `/private/tmp/sshelter-task4-red-questions.log` |
| `npm test -- src/components/McpQuestions.test.tsx src/components/McpPane.test.tsx src/lib/mcp-flow.test.ts src/components/records/settings-boundary.test.tsx` (GREEN) | 13 passed | `/private/tmp/sshelter-task4-green-focused.log` |
| `npm test -- src/components/McpQuestions.test.tsx src/lib/mcp-flow.test.ts` (controller UX+snapshot expiry RED) | 2 failed / 9 passed: input still inside long-prompt scroll body; zero-remaining refresh retained answer | `/private/tmp/sshelter-task4-red-footer-expiry.log` |
| same command (GREEN) | 11 passed | `/private/tmp/sshelter-task4-green-footer-expiry.log` |
| `npm test -- src/components/McpPane.test.tsx src/components/McpQuestions.test.tsx src/lib/mcp.test.ts src/lib/mcp-flow.test.ts src/components/records/settings-boundary.test.tsx` (final focused) | 5 files / 20 passed | `/private/tmp/sshelter-task4-focused-final.log` |
| `npm test` (final full suite) | 71 files / 997 passed / 0 failed | `/private/tmp/sshelter-task4-full-suite-final.log` |
| `npx tsc --noEmit` | exit 0, no diagnostics | `/private/tmp/sshelter-task4-tsc-final.log` |
| `npm run build` | tsc + Vite success; >500kB chunk warning remains | `/private/tmp/sshelter-task4-build-final.log` |
| `git diff --check` | exit 0 | checked before commit |

The initial missing new-function/view exports were scaffolded with empty/no-op implementations so RED executed user-visible behavior/state assertions, not unresolved imports. During first question GREEN run, DialogTitle correctly required its Dialog context; the SSR fixture was corrected to supply the actual Dialog primitive (not counted as meaningful RED). The existing Records settings compatibility test was updated because it intentionally asserted the obsolete metadata-only description; its fake status now includes all current capability/mode fields. Additional consumer regressions verify effective inherited endpoint/Group path, no Group switches, latest10 real ended/null exit, native acknowledgement payload/cache result, null cancellation by question ID, and event-over-older-fetch ordering.

## Controller mounted visual checks and limits

Root owns the preview-only actual-component harness `.superpowers/sdd/2026-10-14-groups-mcp-completion/mcp-ui-review.html`, Vite 10496/IAB tab4. No production/native grant or credential action is needed. Root's initial auth480×360 long-prompt check found input below the fold despite header/footer visibility, escaped prompt and no horizontal overflow; fixed response section as described above with observed additional RED/GREEN. Final root checks pending at report preparation; append concrete evidence below after controller response.

SSR alone verifies rendered behavior/structure; it cannot prove browser focus transitions, real native window closing, platform credential prompts, SSH authentication, Windows OS behavior or actual suspend/resume. Mounted browser preview is still not a real native OS credential/SSH integration test. JS answer references are cleared and dropped before IPC/unmount; frontend does not claim JavaScript string zeroization guarantees (backend uses its own zeroizing handling).

## Self-review and owned files

Checked: mode acknowledgement cannot be bypassed by opening/selecting; Ask immediate; platform/Legacy capability accuracy; stable-ID grants and nested effective destination; request-ID/candidate/focus binding; full command and scroll bounds; attribution origin; audit missing-status outcomes; listener/fetch and unmount races; no auth value in errors/clipboard/stores/URL/logs; single-consume answer and paired expiry; default receipt is stable across card re-renders (fixed self-review render-loop risk); no automatic retry of failed answer/execution. Input-change handler refuses updates after expiry/consumption.

Exact owned paths (14):

```text
src/App.tsx
src/main.tsx
src/lib/mcp.ts
src/lib/mcp-flow.ts
src/lib/mcp-flow.test.ts
src/lib/authentication.ts
src/lib/mcp.test.ts
src/components/SettingsDialog.tsx
src/components/McpApprovalDialog.tsx
src/components/AuthenticationWindow.tsx
src/components/McpAttribution.tsx
src/components/McpPane.test.tsx
src/components/McpQuestions.test.tsx
src/components/records/settings-boundary.test.tsx
```

No index.css, Group editor/workspace CSS, native/backend or dependency edits. This report remains ignored; no force-add.

## Component exports for root fixtures

- `SettingsDialog.tsx`: `SettingsCategoryPane` (same props) and exported `McpPane({hosts,records?})`; hosts allow `{id,alias,hostname,user,port?,groupPath?}`.
- `McpApprovalDialog.tsx`: `McpApprovalDialog()` actual native-status UI; `McpApprovalCard({request,busy,onAnswer:(requestId,allow)=>void})`; `McpApprovalCardView({request,busy,armed,expired?,onAnswer:(allow)=>void})` requires existing Dialog context for its title/description.
- `AuthenticationWindow.tsx`: default `AuthenticationWindow()` actual event/fetch UI; `AuthenticationCard({request,receivedAt?:{wall,monotonic},onResolve?:(requestId,value:string|null)=>Promise<void>})`; `AuthenticationCardView({request,busy,armed,remainingMs,answer,abandoned?,error?,onChange,onAnswer})` standalone compact view. The actual window keys by question.id; external fixtures should also key by ID when substituting requests.
- `McpAttribution.tsx`: `McpAttribution({requestedBy,requesterId,clientInfo})`.

## Commit

`246bd5677094fca25da3631878673ec3eafa38b9` — `feat(ui): add records MCP approval and authentication flows` (14 exact owned files, 842 insertions / 121 deletions). Held `/private/tmp/sshelter-index.lock` via fcntl, asserted expected branch/BASE and empty preexisting index, staged exact manifest, asserted staged-set equality, ran staged diff check, committed. Post-commit worktree clean; no push/merge/release. Exact committed-HEAD frontend rerun: 71 files / 997 tests passed, TypeScript no diagnostics. Root independent review/remaining mounted visual verification remains controller-owned.

## Controller final mounted receipt

Actual component/React interaction checks at committed246bd567 completed: compact dark480x360 long auth prompt + fixed visible input/footer, echo input/newIDclear+Cancelfocus, failed-answer abandonment, same-IDexpiry input removal, Cancel empty state; main800x560approval full180-line command actualscrollbottom/fixedfooter, request1→request2Denyfocus; risk dialog uncheckeddisabled/Canceldefault, mockAutoLogack→selected thenAsk immediate no dialog, effectiveendpoint/GroupPath/stableID/attribution/unknownexit/auditnotice. Full receipt task-4-visual-verification.md, with screenshots and nativeOS limitations. No actual grants/credentials/SSH/relay/Production operation.
