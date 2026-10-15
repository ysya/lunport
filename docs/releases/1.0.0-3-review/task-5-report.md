# Task 5 implementation report

BASE: `246bd5677094fca25da3631878673ec3eafa38b9`; branch `codex/groups-mcp-beta3`.
Commit: `f292b462db23d190d7f7a4bf52fd18d782d3965a` — `feat(keys): deploy public keys to records hosts`.

Commit held `fcntl.flock` on `/private/tmp/sshelter-index.lock`, verified exact BASE/branch/empty index, staged only the listed 15 files, checked staged-set equality and whitespace, then committed. Post-commit worktree was clean.

## Result and native API

Human Records Keys deployment now has public preview, explicit confirmation, cancellation, native authentication, public-only audit, and durable outcomes. It does not consult or mutate MCP enable/allowlists/approval mode and never changes saved host authentication/key ID. Host-key trust is the existing native two-phase confirmation/CAS path.

Commands registered in `src-tauri/src/lib.rs`:
- `records_deploy_preview({hostId,keyId}) -> DeployPreview`
- `records_deploy_confirm({previewId,authorized}) -> DeployResult`
- `records_deploy_cancel({previewId}) -> void`

`DeployPreview` / TS `RecordDeployPreview`: `id,host_id,key_id,alias,hostname,port,user,route:string[],key_name,fingerprint,public_key`. The backend captures canonical authoritative selected public identity plus `ApprovedTarget` (effective route, endpoint, auth, independent auth-key public identities). Pending backend previews are bounded at 32, expire after 120 seconds with the shared UTC/monotonic deadline, and are single use. The caller cannot provide target endpoint or public bytes on confirmation. Cancellation is atomic across preview→active handoff. Rechecks run before connect, inside the shared CheckedEngine, during confirmed-pin guard, and again before exec. Changed same-ID selected key, ancestor Group endpoint, or auth-key identity cannot execute.

`DeployResult` / TS `RecordDeployResult`: `outcome` (added, already_present, stale_preview, denied, canceled, timed_out, auth_abandoned, host_key_refused, unsupported_shell, remote_failed, connection_failed, unknown) and nullable `audit_error`. Known success requires `Ended::Exited`, exit 0, no signal/truncation/stderr, and exactly the recognized installer marker. Missing status, output ambiguity, disconnect, signal and truncation never become success. Typed engine timeouts and native authentication abandonment/timeout are distinguished. The existing host-key confirmer returns a single None for refusal/expiry, so its outcome/UI explicitly covers both.

The installer is generated from the checked-in POSIX template, invoked as remote `sh -c` with proper static-shell quoting. Only canonical algorithm/base64 enter the command. It preserves content and unterminated last lines, detects actual plain/options-prefixed identity without comment/quoted-command false positives, rejects symlink/dangling .ssh and authorized_keys, requires ordinary directory/file paths, applies 0700/0600, and uses an exclusive mkdir lock (five attempts, four one-second sleeps). A stale lock fails rather than deleting another deployment's lock. Exec is bounded at 60 seconds and 8192 combined output bytes. No OS ssh, ssh-copy-id, askpass, or new dependency is used by this path.

## Integration and lifecycle

- New `SessionRuntime.deployments` stores only public reviewed data and cancellation tokens.
- Clone the broker Arc out of AppState before work; the broker mutex is released immediately.
- Controller-approved visibility-only change shares Task3 `PublicDirectory` and `CheckedEngine` from `mcp::records`. Deployment supplies its own guard and never uses MCP grants.
- PublicDirectory avoids the old human resolve/material callback. The Records AppKeyStore reads private material outside lifecycle; tests assert lifecycle is available during private authentication and panic if material preflight is entered. The inherited ordinary CLI/human FormatDirectory.resolve path remains unchanged; this task does not claim to repair that baseline path globally.
- Broker `DeploymentRegistration` participates in has_sessions/end_all/quit; cancellation closes the actual returned Session during exec. Registration remains until cleanup (including audit); quit waits within its existing bound. Native auth questions drain on quit. A synchronous in-progress engine connect cannot be forcibly interrupted before it yields a Session; existing bounded engine behavior and cancellation after return are retained.
- Controller-approved `McpRuntime.record_result` returns this request's write result while serializing audit writes. Existing record keeps its unit-returning/global-error behavior. Human record_deployment returns the specific write error, not a later or stale global error. Completed execution is never retried after audit failure. Audit contains only client deploy, public host ID/alias/fingerprint summary and outcome, never output/private material/auth replies.
- Task3 M4: production deployment consumes exported ExecResult. Final cargo check has 15 warnings and no unused ExecResult export warning (previous report had 16). M1 bounded audit read and M3 unrelated formatting remain deferred and unchanged.

## Frontend and controller visual handoff

`RecordsKeysPanel` adds Deploy public key for authoritative available key metadata and keeps existing import/generate/copy/sync behavior. `RecordsDeployKeyDialog({overview,keyId,onClose})` is exported from `src/components/records/DeployKeyDialog.tsx`; `RecordsDeployContent` is a pure render export used by focused markup tests. API wrappers/types live in records.ts; outcome text is in records-deploy.ts.

The dialog requires saved target → backend preview → explicit account authorization → Confirm. The effective destination and fingerprint precede full route. POSIX remote requirement and unsupported remote Windows limitation are shown before confirmation; Windows clients remain supported. Refresh clears prior consent. Running cancel stays visible and awaits final outcome; results/errors remain until explicit close/refresh, without automatic retries.

Controller's preliminary actual browser QA found the original long-route footer offscreen. Fixed header/footer (authorization, status/errors, Cancel/Close/Confirm) now surround an independently scrolling details body. Controller rechecked working-tree 800x560 dark + 16 hops: dialog 15..545, footer controls 500..530, body client300/scroll593, fingerprint top310, no horizontal overflow. This is controller-reported working-tree evidence, not final-HEAD/backend/Windows runtime acceptance. Root owns complete visual fixture QA and Task6 real native SSH integration.

## RED / GREEN evidence

All Cargo commands use repository root and prefix:
`cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib`

| Exact filter / command | Meaningful RED | GREEN / log |
|---|---|---|
| `session::deploy::` initial script | 1 passed / 5 failed; stub `exit 1` failed actual TempDir HOME installer behavior | Script 6/6 GREEN inside subsequent service run. `/private/tmp/sshelter-task5-script-red.log`, `/private/tmp/sshelter-task5-service-red.log` |
| `session::deploy::` service | 6 passed / 4 failed; missing preview/confirm returned not implemented, successful ending classifier returned Unknown | 10 passed before broker implementation; `/private/tmp/sshelter-task5-service-red.log`, `/private/tmp/sshelter-task5-broker-red.log` |
| `session::deploy::` broker | 10 passed / 1 failed; register_deployment stub rejected | 11/11 GREEN, `/private/tmp/sshelter-task5-service-green.log` |
| `deployment_audit_returns` | 0/1; successful current write incorrectly returned old global error | 1/1, `/private/tmp/sshelter-task5-audit-red.log`, `/private/tmp/sshelter-task5-audit-green.log` |
| `session::deploy::` auth boundary | 18 passed / 1 failed; fake connector success after canceled auth reached exec and returned Unknown | 19/19 after post-connect auth-outcome guard; `/private/tmp/sshelter-task5-auth-red.log`, `/private/tmp/sshelter-task5-expanded-green.log` |
| `cancellation_denial_missing_metadata` | 0/1; cancel before active handoff reported stale | final deployment suite passes, `/private/tmp/sshelter-task5-cancel-red.log` |
| `connection_timeout_has_a_distinct` | 0/1; typed timeout reported connection_failed | final deployment suite passes, `/private/tmp/sshelter-task5-timeout-red.log` |
| `npm test -- src/lib/records-deploy.test.ts` | 2 failed; stub sent no commands and returned empty outcome text | 2/2, `/private/tmp/sshelter-task5-ui-red.log`, `/private/tmp/sshelter-task5-ui-green.log` |
| `npm test -- src/components/records/deploy-markup.test.tsx` | 2 failed; no independently scrolling details/fixed actions | 2/2 with API tests total 4/4, `/private/tmp/sshelter-task5-layout-red.log`, `/private/tmp/sshelter-task5-layout-green.log` |

Final affected checks:
- `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib session::deploy::` → **20 passed / 0 failed**, `/private/tmp/sshelter-task5-final-deploy.log`.
- Same prefix `mcp::` → **41 passed / 0 failed**, `/private/tmp/sshelter-task5-final-mcp.log`.
- Same prefix `session::broker::` → **43 passed / 0 failed**, `/private/tmp/sshelter-task5-final-broker.log`.
- Same prefix `session::connect::` → **43 passed / 0 failed**, `/private/tmp/sshelter-task5-final-connect.log`.
- Same prefix `session::auth_window::` → **9 passed / 0 failed**, `/private/tmp/sshelter-task5-final-auth.log`.
- Same prefix `session::format_directory::` → **3 passed / 0 failed**, `/private/tmp/sshelter-task5-final-format.log`.
- `cargo check --offline --locked --manifest-path src-tauri/Cargo.toml --lib` → **success, 15 warnings**, `/private/tmp/sshelter-task5-check.log`; test builds report the existing 3 warnings.
- `npm test` → **73 files / 1001 tests passed**, `/private/tmp/sshelter-task5-frontend-all.log`.
- `npx tsc --noEmit` → exit 0, `/private/tmp/sshelter-task5-tsc.log`.
- `git diff --check` → exit 0.

Broker/connect checks used approved escalation solely for existing disposable loopback fixtures. Script tests use env_clear, fixed PATH and TempDir HOME, never user ~/.ssh. One expanded test iteration had compile error E0046 for a missing test-double password_account method; corrected before meaningful runtime tests. No environment denial is presented as RED. No full Rust suite repeated because Task6 owns safe final integration and actual native SSH acceptance; no real user host, OS credential, existing user .ssh or permission was accessed/modified.

## Self review and limits

Checked authoritative ID boundaries, same-ID public identity, inherited Group resolution, one-use review/expiry/cancel transition, guard forwarding into two-phase pin, lifecycle freedom during material/auth/SSH/audit, quit registration cleanup, real session close on cancel, POSIX parsing/preservation/lock/perms, strict success classification and no retry on audit/output ambiguity. No known blocking issue remains in owned scope; independent controller review is still required. Remote installers cannot guarantee whether bytes were appended if the transport dies/cancellation happens after command dispatch; UI explicitly reports uncertain outcomes. This task does not claim Windows device testing, real native host deployment, or final complete visual acceptance.

Exact owned manifest (15 files):
- src-tauri/src/lib.rs
- src-tauri/src/mcp.rs
- src-tauri/src/mcp/records.rs
- src-tauri/src/mcp/deployment_audit_tests.rs
- src-tauri/src/session/broker.rs
- src-tauri/src/session/mod.rs
- src-tauri/src/session/deploy.rs
- src-tauri/src/session/deploy_tests.rs
- src-tauri/src/session/deploy-script.sh
- src/components/records/KeysPanel.tsx
- src/components/records/DeployKeyDialog.tsx
- src/components/records/deploy-markup.test.tsx
- src/lib/records.ts
- src/lib/records-deploy.ts
- src/lib/records-deploy.test.ts

The report remains ignored and is not force-added. No push, merge, release, actual hosts or credentials.


## Fix round1 — I1 / I2 (2026-10-15)

Base: `f292b462db23d190d7f7a4bf52fd18d782d3965a`; fix commit: `85a902e21bd0bb2d27efbedd6bd03bf4145c355f` (`fix(keys): bind deployment targets and preserve CRLF keys`).

Read the complete task-5-review.md and reproduced both Important findings before production changes. Controller authorized the minimal shared ApprovedTarget / PublicDirectory / CheckedEngine repair and its two callers; no broader Connector refactor or frontend change.

### I1: CRLF parsing and byte preservation

The installer now removes one terminal CR only from awk's in-memory record before tokenization. This is a parsing extension, not a file conversion: existing authorized_keys bytes are not rewritten. Four actual generated-script tests use disposable TempDir HOME and assert SSHELTER_PRESENT plus exact original bytes for plain and restricted CRLF entries, each with and without comments. The restricted fixture includes `restrict,from="192.0.2.0/24"`. Prior duplicate behavior can widen conditional authorization when a from/expiry-constrained entry does not apply; OpenSSH accepts the first applicable entry, so this report does not claim a restrict-only applicable entry is immediately bypassed.

### I2: bind actual resolved and connected targets

- `PublicDirectory` validates the exact resolved snapshot with `ApprovedTarget::check_resolved` before returning it to Connector. Current-directory checks remain strict, including auth and same-ID public key identity, with pins excluded as before.
- `CheckedEngine` now passes its actual `&Target` to the supplied guard. Both MCP and deployment combine current-state validation with `check_connected(actual)`, then apply that same actual-target guard to `Connected.target` immediately before exec.
- The only additional connected-target normalization is same-position Interactive → Password, matching Connector's existing explicit human password-answer retry at connect.rs:249–258. Endpoint/user/port/route/key/auth changes otherwise remain rejected. Initial directory Interactive → Password drift is rejected strictly, so it cannot masquerade as the legitimate Connector adaptation. Pins may legitimately be added, replaced after confirmation, or cleared for the existing host-key algorithm retry; the existing confirmed-pin guard/policy remains authoritative.
- Deterministic MCP and deployment tests return A at preview/preflight, B at Connector resolution, then A again. Each runs endpoint drift and auth drift variants; B never reaches inner engine or exec. A separate CheckedEngine test rejects hostname/port/user/route/key/auth argument drift while current state remains A. Legitimate new-pin and explicit Interactive → Password fallback fixtures execute once through both real Connector flows and leave stored auth unchanged.
- Deployment maps binding failures to stale preview. Existing cancellation, MCP policy, audit and two-phase confirmed-pin behavior is retained. No grants, host auth records, actual credentials or real hosts are changed. The prior legacy human CLI material-resolution limitation remains unchanged.

### Exact RED / GREEN evidence

Every test command below uses this exact prefix from repository root:
`cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib`

| Filter | Result | Exit code | Log |
|---|---|---|---|
| `crlf_` (RED) | 7 passed / 2 failed; new no-comment plain/restricted cases returned ADDED, not PRESENT | 101 | `/private/tmp/sshelter-task5-fix1-crlf-red.log` |
| `crlf_` (GREEN) | 9 passed / 0 failed; includes four new byte-preserving actual-script cases and five existing matches | 0 | `/private/tmp/sshelter-task5-fix1-crlf-green.log` |
| `aba_resolve` (RED) | 0 passed / 2 failed; both inner engines received unreviewed.example | 101 | `/private/tmp/sshelter-task5-fix1-aba-red.log` |
| `aba_resolve` (GREEN) | 2 passed / 0 failed | 0 | `/private/tmp/sshelter-task5-fix1-aba-green.log` |
| `target_binding_tests` | 4 passed / 0 failed; engine drift / strict auth / MCP pin and password fallback | 0 | `/private/tmp/sshelter-task5-fix1-binding.log` |
| `deployment_legitimate_new_pin` | 1 passed / 0 failed; key and interactive/password fixtures | 0 | `/private/tmp/sshelter-task5-fix1-deploy-adaptation.log` |
| `session::deploy::` (final, including endpoint and auth ABA variants) | 26 passed / 0 failed | 0 | `/private/tmp/sshelter-task5-fix1-final-deploy.log` |
| `mcp::` (final, including endpoint and auth ABA variants) | 45 passed / 0 failed | 0 | `/private/tmp/sshelter-task5-fix1-final-mcp.log` |

`cargo check --offline --locked --manifest-path src-tauri/Cargo.toml --lib` → exit **0**, existing **15 warnings**, `/private/tmp/sshelter-task5-fix1-check.log`. Test builds retain the existing 3 warnings. `git diff --check` → exit **0**, `/private/tmp/sshelter-task5-fix1-diff-check.log`. All listed logs contain explicit EXIT_CODE markers. Frontend was unchanged and not rerun; Root/Task6 owns full final integration, real isolated SSH and mounted visual acceptance.

### Self-review / exact owned manifest

Verified both production wrapper call sites; strict initial snapshot versus documented connected adaptation; actual connected target checked before exec; public identity comparison and confirmed pin guards retained; no caller-created endpoint or key bytes; no lifecycle/policy lock added around SSH or audit. The shared production dependency remains deployment → existing mcp::records helpers, with no duplicated guard. The new test-only module shares deterministic doubles with deployment tests. Existing M1 audit reader and M3 formatting remain deferred. No new known blocker in this focused repair; independent re-review remains required.

Exact staged manifest (5 files):
- `src-tauri/src/mcp/records.rs`
- `src-tauri/src/mcp/target_binding_tests.rs`
- `src-tauri/src/session/deploy-script.sh`
- `src-tauri/src/session/deploy.rs`
- `src-tauri/src/session/deploy_tests.rs`

This ignored report is not force-added. Root's untracked `docs/releases/1.0.0-3.md` is preserved and excluded. No push, merge or release.

Commit verified under `/private/tmp/sshelter-index.lock`: expected base/branch and empty index asserted; staged exactly the five-file manifest; staged diff check passed. After commit, only Root release drafts `docs/releases/1.0.0-3.md` and `docs/releases/1.0.0-3-review-checklist.md` remain untracked; neither was staged.
