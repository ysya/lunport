# Task 3 — Records MCP backend

狀態：實作完成且驗證通過；commit 結果見本文末段。工作分支 `codex/groups-mcp-beta3`；本任務接續 BASE `a3ce927276769d544e1e2ca749730e572a4d44bc`。未修改 frontend product UI、依賴、真實 hosts/state/credentials/policy grants/relay；未 push/release。Task 4 的 UI 接線仍為後續工作。

## Implementation and compatibility

- Records 的 stdio adapter 經既有 OS-authenticated session Unix socket／Windows named pipe 呼叫 app broker；不直接取得 credentials、不開 SSH、不依賴 TCP/token runtime file。OS peer PID 由 listener 提供；process chain 是觀察到的 attribution，不是可抵抗同帳戶惡意 process 的額外安全邊界。無可用 PID 時顯示 `Unknown`。clientInfo 僅 name/title/version，各去控制及 deceptive Unicode 並限制 100 characters，不能提供 requester identity。
- Session IPC protocol **2**：`hello {client:"mcp",version:2,client_info}` → `mcp_call {method,params}` → `mcp_result {result,error}`。既有 length/type framed transport 不變。一條 IPC connection 一次 request；Close、EOF、額外 frame 都取消該 request；answers 絕不由 MCP IPC 接收。每個 broker 最多 16 MCP requests；stdio 同樣限制 16 concurrent IDs，duplicate ID 不覆蓋原 cancel handle；stdout serialized；已完成 worker handles 會回收。
- Session protocol **1 Connect** 完整保留，包含 shell/data/question framing；protocol1 MCP 仍拒絕；unsupported versions（含 MCP3/99、Connect2）仍拒絕。既有 unsupported-version regression 的 MCP2 fixture 改為 MCP3，因 MCP2 現已是受支援版本；另有真正 protocol2 → FakeEngine exec regression。更新前 Connect CLI 可繼續用 protocol1。
- Broker 明確回答 Legacy 才 lazy-start 舊 loopback bridge；Legacy 模式仍沿用舊 runner／transport。Legacy TCP dispatch 在 lifecycle 內再次 require_legacy，已移除舊 raw Records branches，避免 mode 切換時落入 Records metadata。Blocked/Unknown 不猜 workspace。
- Records tools：`list_hosts`、`get_host`、`ssh_exec`；`get_effective_config` 是 get_host 相容 alias。舊 `run` 產生 JSON-RPC `-32601`，訊息精確為 `run was renamed to ssh_exec`。alias 參數可為 stable host ID 或精確 alias，grant 僅以 stable ID 比對。metadata 用 Task 1 effective repository，包含 effective destination/port/auth/key/jumps、group path、inherited fields，不暴露 notes/imported/pin blobs/private material。
- Ask 預設，120 秒，完整 command/effective destination/route/requester。command 最多 16384 bytes；timeout integer 1..300/default60；non-PTY exec combined output 128KiB。所有 engine endings、nullable exit/signal/truncation 保留，無 status 不製造 0。
- Approval snapshot 是解析後整條 Target（pin 另走可信 host-key hub）加每個 key ID 的 authoritative public bytes。核准後、每次 connect/reconnect 前、exec 前重查；Group ancestor 改 port、route/auth/key、同 key ID 換 public identity 都失效。revoke/disable/mode-change 取消 active tokens；等待 approval/auth 與 exec 期間均觀察取消；exec watcher closes session。
- public-only audit：`<app data>/session-log.jsonl` mode0600 atomic replacement，1000 entries，status 最新10；Connect 與 MCP 使用同 writer。partial trailing/corrupt entries/load size/I/O errors 可見。detail 從 memory 與 disk audit 一律移除，避免 Legacy error 帶 remote text；stdout/stderr/auth answers 不記錄。完成的 execution 不因 audit failure 重跑。quit 把 MCP 納入 broker has_sessions/end_all drain。

## Noninteractive credentials and startup

正式支援邊界：**Windows stored credentials 可非互動 Auto-log；macOS/Linux credential-dependent requests 必須 Ask。** FakeCredential success 只驗證協議，不代表跨平台 OS 支援。

- `Keychain::get_noninteractive` 與 `KeyStore::private_text_noninteractive` 預設 fail closed，絕不呼叫 interactive fallback。
- Windows 既有 keyring4.1.5 → windows-native-keyring-store1.1.0 `utils.rs:read_credential` 呼叫 `CredReadW(...,0,...)`，無 CredUI。官方 [CredReadW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw) 說明讀取目前 logon token credential set，失敗為 ERROR_NOT_FOUND／ERROR_NO_SUCH_LOGON_SESSION 等；既有 provider source 與 API 一起確認這條 read path 不開 consent/unlock UI。本機未做 Windows OS integration test，也未讀真實 credential。
- macOS/Linux 目前 provider 無已驗證 per-call no-interaction 保證，因此不嘗試 OS read。未使用 process-global OS UI flags、isolated helper、新 dependency 或預先解鎖 material bypass。
- Per-call `NonInteractiveKeychain` 禁止 writes/deletes；MCP credential view 記錄安全錯誤分類，不把 provider raw error/auth text寫入 audit。`needs interaction:` 分為 provider 不支援、missing/locked/unavailable credentials/vault、authentication input、unpinned/confirmation-required host key。
- MCP public route resolution 不呼叫 RecordSources.material；private vault material 僅在 connector authentication 使用對應 KeyStore route。Auto-log 重新讀 readonly vault + noninteractive master key，不用全球 unlocked cache。Ask 是實際核准後的 human auth，使用 NativeOwner／既有 host-key hub。
- `run_app(host && start_hidden)` 在 sync.initialize **之前**設置 AppState.background_credentials_only。startup account derivation 用 per-call noninteractive wrapper；with_env 在 gate 開啟時同樣只給 noninteractive source；background worker 在 gate 開啟時跳過 sync rounds。agent startup 只建立 listener/janitor，不先讀 secrets；agent 的 env 讀取也受 wrapper 控制。
- 只有 native human entry points 解除 gate：非 --host 的第二次 app launch、macOS Dock/Finder Reopen、tray Open。`show_main_window`／程式觸發 focus／MCP approval 自動開主視窗 **不解除**。正常手動 app 啟動一開始為 human mode。Ask 已核准的 connector 可使用自己的 explicit human reads，但不因此開放所有背景流程。
- 具體測試：`noninteractive_vault_and_credentials_never_fall_back_to_interactive_reads` 的 interactive methods panic；`hidden_host_startup_account_and_vault_reads_fail_closed_without_os_prompts` 使用 Fake locked source，同時驗證 account derivation 及 readonly vault master source 不碰 interactive get，原 vault bytes 保留；`a_missing_material_on_a_jump_refuses_the_whole_target` 亦驗證 resolve_public 不要求 private material。

### Hidden --host availability

已載入的 Records snapshot 可提供 allowed list_hosts/get_host/effective metadata，無需先解除 gate、無需讀 OS credential。Ask 的核准視窗會正常開啟；核准後的 NativeOwner 與 connector 使用 explicit human authentication，因此已有可信 pin 的連線可在 gate 尚開啟時詢問 password/passphrase/2FA。這個核准不會把所有背景流程改成人工模式。

macOS/Linux Auto-log 的 credential-dependent execution 明確 needs interaction；不應寫成跨平台完整支援。需要背景 sync/account-code read 或 Space host-key pin 的 fresh-account gate 時，hidden with_env 仍 fail closed；使用者須透過 tray Open、Dock/Finder Reopen 或再次正常啟動 app 來解除 gate，再重試。單純 MCP 自動顯示或 focus 主視窗不算解除。Local host-key pin 的既有持久化不要求 account credential；Space pin 的 fresh-account gate 會讀當前 sync code，不能由 MCP 自動代替 human activation。UI 應清楚區分 metadata 可用、Ask 明確互動、Auto-log 平台能力及背景操作限制。

## Task 4 exact native contract

Tauri invoke arguments 為 camelCase，DTO 欄位為以下 snake_case；generated bindings 是 authoritative types。

| Command | Arguments | Result |
|---|---|---|
| mcp_status | none | McpStatus |
| mcp_set_enabled | `{enabled:boolean}` | McpStatus |
| mcp_set_host_allowed | `{alias:string,allowed:boolean}` (`alias` 必須傳 Records stable host ID) | McpStatus |
| mcp_set_approval_mode | `{approvalMode:"ask"|"auto_log",riskAcknowledged:boolean}` | McpStatus |
| mcp_resolve_request | `{requestId:pending.id,allow:boolean}` | void/error if expired/disconnected |
| auth_pending | none | AuthRequest[] |
| auth_resolve | `{requestId:question.id,value:string|null}` | void/error if expired; null cancels |

`auto_log` 從 ask 進入必須 riskAcknowledged=true；回 ask 不需。set-mode／disable 取消目前 requests。命令先持久化 policy 再換 runtime，save failure 保留舊設定。

Native authentication window label `authentication`；URL `index.html`，Task4 必須在 frontend entry route；event `authentication://requests` payload `AuthRequest[]`。mount 後 `auth_pending` 補齊 event race；最後一個 pending 完成會 destroy window，使用者關閉 native window deny_all。MCP approval event `mcp://approval-requested` payload McpPendingRequest，status.pending 可補齊。Task4 仍需掛載 Records approval UI（目前僅 Legacy 有）並更新文案。

AuthRequest.remaining_ms 是**取得 pending/event snapshot 當下的相對剩餘毫秒**，上限120000，重新取得時計算最新剩餘值；不是 epoch timestamp。Backend deadline authoritative，晚到答案不使用。`kind` 實際值 password/passphrase/interactive；echo 控制顯示／遮蔽。text 是 escaped server prompt（最多4096 characters）。`hop` 是可信 connector context：host_id/alias/hostname/user/port，與不可信 text 分離。passphrase 也走 Owner.ask_at，不需從文字猜 hop；CLI Owner default ask_at 委派舊 ask，保留協議。

```ts
export type ApprovalMode = "ask" | "auto_log";
```

```ts
export type McpClientInfo = { name: string | null, title: string | null, version: string | null, };
```

```ts
export type McpPendingRequest = { host_id: string | null, route: Array<string>, requested_by: Array<string>, requester_id: string | null, client_info: McpClientInfo, id: string, alias: string, command: string, hostname: string | null, user: string | null, port: string | null, requested_at_ms: number, };
```

```ts
export type McpAuditEntry = { client: string, host_id: string | null, ended: string | null, signal: string | null, mode: ApprovalMode, requested_by: Array<string>, requester_id: string | null, client_info: McpClientInfo, at_ms: number, id: string, alias: string, command: string, outcome: string, exit_code: number | null, detail: string | null, completed_at_ms: number, };
```

```ts
export type McpStatus = { noninteractive_credentials_supported: boolean, noninteractive_credentials_notice: string, approval_mode: ApprovalMode, audit_error: string | null, enabled: boolean, bridge_active: boolean, allowed_hosts: Array<string>, pending: Array<McpPendingRequest>, recent: Array<McpAuditEntry>, executable: string, last_client_at_ms: number | null, };
```

```ts
export type AuthHop = { host_id: string, alias: string, hostname: string, user: string, port: number, };
```

```ts
export type AuthRequest = { id: string, request_id: string, hop: AuthHop | null, kind: string, text: string, echo: boolean, remaining_ms: number, };
```

`noninteractive_credentials_supported` 僅 Windows true；notice 是對平台支援邊界的說明，Task4 應在切換處顯示。`bridge_active` 在 Records 表示 session broker Running（保留欄位名相容），不是 TCP listener。recent 的 client 值 connect/mcp，預留 deploy；mode 是 ask/auto_log；at_ms、requested_at_ms、completed_at_ms 均 absolute Unix epoch milliseconds。

## Task 5 reusable human deployment contract

- `state.session.broker.lock().clone()` 後立即放鎖，持有 Arc<Broker>，再 `broker.connector()` 取得 borrowed `Connector`。此 helper 提供相同 engine/directory/keys/keychain/confirmer，**不查 MCP enable/allowlist/approval mode**。Task5 自行管理 human preview/approval/cancellation/quit registration。
- Preview 用 `connector.directory.resolve_public(&HostQuery::Id(...))`，不讀 vault；`mcp::records::ApprovedTarget::capture(&Target,connector.keys)`／`.check(&connector,&query)` 可重用 endpoint/route/auth/public-key identity recheck。部署要另捕獲欲寫入 authorized_keys 的 selected public key identity。
- Construct `NativeOwner {hub:state.session.auth_questions.clone(),surface:Arc::new(TauriAuthSurface{app}),request_id:unique_deployment_id,cancel:CancelToken}`，再 `connector.connect(&query,&owner,&cancel)`；取得 `Connected {target,session}`；`Session::exec(command,Duration,combined_output_cap)` 回 ExecResult。在 plain thread／spawn_blocking 呼叫；不是 async runtime thread直接 block。
- Session::close 支援 cancel watcher；exec 的 ended/nullable exit/signal/truncated 必須保留，unknown 不能視為成功。command只含 canonical public key。NativeOwner 借用 shared question hub，但不借 MCP grants。
- `state.mcp.record(McpAuditEntry {client:"deploy",...})` 是可重用 public log writer，會移除 detail；只傳公共 metadata，不傳 output/auth。不要跨 lifecycle lock呼叫 SSH/auth/audit。

## RED → GREEN evidence

所有命令在 repository root；使用 `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib <FILTER>`。

| RED filter / log | Observed RED | GREEN evidence |
|---|---|---|
| records_policy_defaults_to_ask_and_rejects_control_commands / /private/tmp/sshelter-task3-red-policy.log | serialized mode Null vs expected ask | focused suite and final safe suite |
| allowed_id_executes_without_pty_and_preserves_disconnected_null_status / /private/tmp/sshelter-task3-red-exec.log | execution stub returned Records execution unavailable | FakeEngine exec reached; disconnected/null retained |
| denied_host_never_reaches_engine_and_is_audited / /private/tmp/sshelter-task3-red-denied-audit.log | empty recent index0, denial not audited | denial recorded, engine untouched |
| mcp:: / /private/tmp/sshelter-task3-red-noninteractive.log | 29 pass/1 fail: FakeEngine accepted after forbidden credential access flagged | successful-connect path also checks denied interaction; subsequent focused30/31/33 pass |

Focused meaningful regressions include: protocol_two_reaches_exec_with_os_context_and_protocol_one_mcp_is_refused; eof_and_quit_cancel_waiting_requests_and_drain_broker_table; duplicate_rpc_ids_preserve_original_handle_and_cancel_before_ipc_registration; group_derived_port_change_during_approval_cancels_without_changing_host_revision; replacing_public_identity_under_same_key_id_invalidates_approval; cancellation_and_revoke_during_exec_close_session_and_audit_once; all_auto_log_interactions_fail_without_asking_or_pinning; saved_password_auto_log_never_prompts_and_persists_no_secret_output; approval_timeout_and_denial_never_connect_and_are_audited; all_engine_endings_and_combined_cap_are_retained; audit_restart_cap_partial_tail_and_failure_are_visible_without_output_or_auth; passphrase_question_carries_trusted_hop_separately_from_server_text; connect_audit_preserves_exit_status_without_terminal_output.

First broker sandbox invocation returned fixture EPERM and is **invalid test-environment evidence**, not implementation RED. Correct elevated disposable-fixture invocation exposed one old MCP2-as-unsupported expectation; fixture changed to MCP3 and protocol2 support separately tested. `/private/tmp/sshelter-task3-broker-final.log`: **43 passed,0 failed**,3.04s. Native initial focused **2 passed**; expanded native attribution/exports included in final suite. Pre-final MCP focused `/private/tmp/sshelter-task3-focused-final.log`: **33 passed,0 failed**,0.17s.

## Final checks / self review

- Reviewed IPC trust source, duplicate-ID handle ownership, revocation/quit drain, public target/key rechecks, no-interaction fallback, native answer lifetime, secret-free memory/disk audit and Legacy profile isolation.
- New focused modules formatted with rustfmt; existing modules retain surrounding project formatting to avoid unrelated churn. `git diff --check` passed before commit.
- No new dependency/Cargo manifest/lockfile change. No secret tests run; fixture mnemonic/password/private keys are disposable test data only.
- Source-level macOS/Linux credential denial is deliberate; Windows API path is source/documentation verified, not Windows GUI/OS tested. No frontend native-window visual smoke in this backend task; Task4 owns actual UI rendering.
- Existing normal human `FormatDirectory.resolve` holds lifecycle while RecordSources.material may read OS credentials. MCP bypasses that via public resolution and its Records AppKeyStore releases lifecycle before vault read; this inherited human Connect/deployment concern is surfaced to controller rather than changing Task1 atomicity here. Likewise pin persistence uses the existing directory/hub contract.
- SSH connect cancellation can only complete when the bounded engine connect returns; exec cancellation actively closes the returned session. No transport retry after execution/audit error.
- Source change after full suite started: removed unreachable/racy Legacy TCP Records branches and cleared Legacy detail in runtime audit as well as disk. These receive focused MCP rerun plus production cargo check; full suite is not repeated without unrelated new concerns.

### Exact final commands and output

```sh
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none
# test result: ok. 2501 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 137.93s
# /private/tmp/sshelter-task3-safe-suite.log
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib session::broker::tests::
# test result: ok. 43 passed; 0 failed; 0 ignored; 0 measured; 2461 filtered out; finished in 3.04s
# /private/tmp/sshelter-task3-broker-final.log
```

Safe suite 同時執行所有 ts-rs export tests，產生 ApprovalMode/AuthHop/AuthRequest/McpClientInfo/McpPendingRequest/McpAuditEntry/McpStatus bindings。這不是 real OS credential 測試；三個禁止項目確實 filtered out。

RED 原文摘錄：policy `left: Null / right: "ask"`；exec `called Result::unwrap() on an Err value: "Records execution is not available yet"`；denial `index out of bounds: the len is 0 but the index is 0`；noninteractive `called Result::unwrap_err() on an Ok value: ... ended:"exited", exit_code:0`。對應 exact command 是上表 cargo base + 各 RED filter。

### Owned files

```text
src-tauri/src/cli/mod.rs
src-tauri/src/lib.rs
src-tauri/src/mcp.rs
src-tauri/src/mcp/adapter.rs
src-tauri/src/mcp/records.rs
src-tauri/src/session/app.rs
src-tauri/src/session/auth.rs
src-tauri/src/session/auth_window.rs
src-tauri/src/session/broker.rs
src-tauri/src/session/connect.rs
src-tauri/src/session/directory.rs
src-tauri/src/session/format_directory.rs
src-tauri/src/session/mod.rs
src-tauri/src/session/protocol.rs
src-tauri/src/session/record_directory.rs
src-tauri/src/session/record_directory_tests.rs
src-tauri/src/session/testing.rs
src-tauri/src/ssh/mod.rs
src-tauri/src/state.rs
src-tauri/src/sync/engine.rs
src-tauri/src/sync/env.rs
src-tauri/src/sync/testkit.rs
src-tauri/src/tray.rs
src-tauri/capabilities/authentication.json
src/bindings/ApprovalMode.ts
src/bindings/AuthHop.ts
src/bindings/AuthRequest.ts
src/bindings/McpClientInfo.ts
src/bindings/McpAuditEntry.ts
src/bindings/McpPendingRequest.ts
src/bindings/McpStatus.ts
```

報告保留在 .superpowers 工作記錄（repository ignore），不 force-add。只有以上31個明列檔案可進入本任務 commit。

Final self-review also preserved a received Connect exit/signal when the client closes immediately afterwards; cancellation must not relabel an already-known remote exit as canceled. The Connect audit regression asserts outcome=allowed with exit_code=7.

### Final post-review validation

```sh
cargo check --offline --locked --manifest-path src-tauri/Cargo.toml --lib
# Finished dev profile [unoptimized + debuginfo] target(s) in 7m 41s
# 16 warnings, no errors; /private/tmp/sshelter-task3-check.log
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib mcp::
# test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 2469 filtered out; finished in 0.18s
# /private/tmp/sshelter-task3-postreview-mcp.log
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib connect_audit_preserves_exit_status_without_terminal_output
# test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2503 filtered out; finished in 0.02s
# /private/tmp/sshelter-task3-connect-audit-final.log
git diff --check
# exit 0, no output
```

Production check 的 warnings 含現有 dead-code warnings 及提供 Task5 的 ExecResult re-export 尚無 production explicit import；沒有新增 dependency 或 suppression。最後 MCP 回歸是在 Legacy dispatch/audit 清理後；最後 Connect regression 在 outcome race修正後。全套只跑一次，其後針對實際更動重新驗證相關範圍。

## Commit and handoff

Commit: `66acc1cde84fbbc888438ce7de4a2d3bbed0eb93` — `feat(mcp): execute records commands through the session broker`。
31 owned files，2684 insertions/157 deletions。取得 `/private/tmp/sshelter-index.lock` 後確認 preexisting index 空、branch 正確，僅明列 files git add，staged set equality 及 staged diff --check 通過才 commit。四個 final cargo sessions 均已 exit0，無持鎖 background cargo 遺留。未 push/release。Report 為 ignored 工作記錄，未強制納入 commit。

## Review fix round 1 (2026-10-15; BASE 66acc1c)

### Resolution and internal interfaces

I1 fixed: Connector now calls `HostDirectory::pin_confirmed(hop, previous, key, cancel, guard)` after native host-key trust. Its default preserves Legacy/CLI `pin_for` / `replace_pin_for` behavior. Production RecordDirectory installs `with_confirmed_pin` and delegates to `session::record_pin::confirm`; PublicDirectory supplies the existing approved-target/key/policy guard. FormatDirectory selects the Records adapter under lifecycle, releases it, then enters the helper. All caller guards run outside lifecycle (they may reenter FormatDirectory); the final section uses pure repository resolution of the captured/current Records snapshot, never arbitrary callbacks.

The helper performs preflight + capture under a short lifecycle lock; credential reads and relay pull use that captured snapshot outside the lock. It then reacquires lifecycle, verifies no pending migration, unchanged full snapshot/generation, cancellation, and prepared generation. The authenticated account result is published under the existing format_publication → core discipline with an atomic expected-generation check. Current device/workspace, relay/account identity, scope/effective route/public-key metadata and stored-pin CAS are checked before the final `commit_candidate`, with another cancellation check immediately before commit. Unrelated generation changes during preparation conservatively reject and require a retry/review. Local→Space cannot skip fresh account preparation. Cancellation/revoke/disable can be set while credential/relay IO is waiting; an already-started synchronous external call may finish, but its canceled preparation cannot publish a pin or execute.

Shared sync API: `fresh_account_gate(env)` retains its original wrapper behavior for existing lifecycle-owning callers. Internally it preflights/captures then calls `prepare_account_gate(env, credentials, snapshot, generation)` and `publish_prepared_account_gate(env, prepared, expected_generation)`. Preparation performs credential/network work only, with no account publication. `expected_generation: Some(g)` uses new `record_runtime::mutate_records_at_generation` (check + pure transform + durable publication under one core lock); the existing wrapper uses `None` to preserve its concurrent local-cache merge behavior. Task5 may reuse Connector + native owner as before; native pin now inherits this safe contract, independently of MCP grants. Human resolve/material lifecycle work remains Task5's separate scope.

I2 fixed: PendingApproval stores a monotonic `Instant` deadline, created before insertion/window publication. `resolve_approval` checks expiry while holding the pending mutex, removes the question, returns an expired error, and signals TimedOut. The waiting side checks the same deadline after receiving a queued answer. Legacy approval also stores/checks its deadline. The actual Records pending-wait regression uses a short injected deadline and paused publication to prove late resolve fails, no engine event occurs, and the outcome is `timed_out`; the queued-Allow test uses a controlled monotonic clock to exercise the post-receive check.

M2 fixed: AuthHub.resolve rejects an expired Waiting under its mutex before sending a secret, signals TimedOut, and returns an expired error. The existing native-owner post-receive deadline check remains. The regression installs an expired pending question to simulate a suspended waiter and verifies no Answer is delivered and no false success is reported.

### Task4/Task5 handoff and hidden-host semantics

No native command, IPC version, frontend DTO, or generated binding change in this round. `remaining_ms` remains relative remaining time in each snapshot; `noninteractive_credentials_supported` and its notice retain the accepted Windows-only provider support boundary. Auth/MCP binding export tests ran as part of focused tests and produced no binding diff.

This paragraph supersedes the original report's statement that hidden-host Space pin necessarily requires reopening the main window: explicit native host-key trust now authorizes **one per-call OsKeychain read** for the Space account proof. It does not clear `background_credentials_only`, does not change env's background credential provider, and does not enable background sync or Auto-log interaction. Code trace: session/app.rs confirmed-pin closure passes `&OsKeychain` explicitly → prepare reads only that injected provider; engine.with_env still retains the original background gate. Cached public metadata remains available under hidden `--host`; Ask can show its approval and native questions and can complete this explicitly authorized pin. Actual human activation (tray Open, non-host second launch, Dock Reopen) is still required to enable general background credential/sync activity; generic window focus/MCP show does not qualify. Missing cached account/Space prerequisites or provider errors still fail closed. Auto-log cannot enter this pin helper (NoPin + existing unpinned-path refusal); credential-dependent macOS/Linux requests still require Ask. No claim of live native window/OS integration was added.

### Exact RED/GREEN evidence

All test commands use this exact prefix:

```sh
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib
```

| Appended filter | Result | Log |
|---|---|---|
| `approval_deadline_tests` (RED) | 0 passed / 2 failed; `late resolve must fail at the command boundary`, queued Allow failed TimedOut assertion | `/private/tmp/sshelter-task3-fix1-deadline-red.log` |
| `expired_auth_deadline` (RED) | 0 passed / 1 failed; expired hub.resolve incorrectly succeeded | `/private/tmp/sshelter-task3-fix1-auth-red.log` |
| `space_pin_credential_and_relay` (RED) | 0 passed / 1 failed; `credential/relay wait must not own lifecycle` | `/private/tmp/sshelter-task3-fix1-pin-red.log` |
| `space_pin_credential_and_relay` (first GREEN) | 1 passed / 0 failed | `/private/tmp/sshelter-task3-fix1-pin-green.log` |
| `confirmed_pin_tests` (first GREEN) | 1 passed / 0 failed; allow/revoke/disable scenarios | `/private/tmp/sshelter-task3-fix1-mcp-pin.log` |
| `mcp::` (final GREEN) | 40 passed / 0 failed | `/private/tmp/sshelter-task3-fix1-mcp-green.log` |
| `session::auth_window::` (final GREEN) | 9 passed / 0 failed | `/private/tmp/sshelter-task3-fix1-auth-green.log` |
| `session::connect::` (GREEN; escalated disposable loopback) | 43 passed / 0 failed | `/private/tmp/sshelter-task3-fix1-connect-green.log` |
| `session::record_directory::` (GREEN; escalated disposable loopback) | 11 passed / 0 failed | `/private/tmp/sshelter-task3-fix1-record-directory-green.log` |
| `session::format_directory::` (GREEN) | 3 passed / 0 failed | `/private/tmp/sshelter-task3-fix1-format-directory.log` |
| `sync::record_round::tests` (final GREEN) | 30 passed / 0 failed | `/private/tmp/sshelter-task3-fix1-record-round.log` |

The pin RED reproduced the old lock-owning credential/relay path in the factored helper before splitting preparation/commit. Additional regressions: `pin_preparation_rejects_changed_generation_scope_account_endpoint_and_public_key`, `local_to_space_during_external_guard_cannot_bypass_fresh_account_preparation`, `native_space_pin_wait_releases_lifecycle_and_revoke_disable_prevent_pin_and_exec`, `expired_pending_allow_is_rejected_without_connect_and_audited_timed_out`, `queued_allow_after_deadline_is_not_consumed`, `expired_auth_deadline_rejects_answer_before_reporting_success`.

The full record_round filter also covers existing `fresh_gate_does_not_clear_or_publish_while_relay_is_unreachable`, `delayed_authenticated_gate_survives_a_local_generation_change_and_keeps_latest_local_cache`, `compatible_full_account_proof_clears_only_the_explicit_shared_gate`, migration/schema gates and durable publication failures. Early connect / record-directory attempts hit sandbox EPERM when binding their toy server; those are invalid environmental attempts, not RED evidence, and were replaced by the successful escalated logs above. A new stale-account fixture initially removed account while retaining Spaces and failed validation; corrected to a valid alternate chain identity before GREEN. No actual credentials, real hosts, or real relay were used.

Final compilation: `cargo check --offline --locked --manifest-path src-tauri/Cargo.toml --lib` → success, 16 warnings, `/private/tmp/sshelter-task3-fix1-check.log`. Test builds retain the 3 previously documented warnings. No warning-free claim or fresh BASE comparison. `git diff --check` → exit 0. No full suite repeated; Task6 owns the final integration suite.

### Self-review, remaining ledger, and owned files

Self-review checked guard reentrancy, lock order, strict preparation generation, original fresh-account merge compatibility, final endpoint/public-key/scope/CAS checks, cancellation before commit, unchanged Auto-log NoPin and hidden gate, and monotonic deadline checks on both sides. Preparation was tightened during self-review to use the captured snapshot and keep preflight/journal inspection in the short lifecycle section. No further correctness concern found in this scope; controller independent review remains required.

M1 bounded audit reader remains deferred (32 MiB check currently follows full read). M3 older stdio/broker concurrency formatting remains deferred; new fix methods/helper/tests were formatted without a whole-file churn. M4 ExecResult re-export warning remains Task5 follow-up. These are explicit minor follow-ups, not claimed fixed.

Owned fix files (15): `src-tauri/src/mcp.rs`, `src-tauri/src/mcp/records.rs`, `src-tauri/src/session/app.rs`, `src-tauri/src/session/auth_window.rs`, `src-tauri/src/session/connect.rs`, `src-tauri/src/session/directory.rs`, `src-tauri/src/session/format_directory.rs`, `src-tauri/src/session/mod.rs`, `src-tauri/src/session/record_directory.rs`, new `src-tauri/src/session/record_pin.rs`, new `src-tauri/src/session/deadline.rs`, `src-tauri/src/sync/record_round.rs`, `src-tauri/src/sync/record_round_tests.rs`, `src-tauri/src/sync/record_runtime.rs`, `src-tauri/src/sync/testkit.rs`. No product frontend or dependency edits. This report stays ignored, not force-added.


### Paired clock correction before commit

Controller identified the official [Rust Instant contract](https://doc.rust-lang.org/std/time/struct.Instant.html): suspend-time accounting is not specified across platforms/Rust versions. The final implementation therefore uses `session::deadline::InteractionDeadline { monotonic: Instant, utc: SystemTime }`, superseding the monotonic-only description above. It pairs an absolute wall-clock expiry with the monotonic bound. Remaining duration is their minimum; either expiry refuses resolve/consumption. Forward wall-clock adjustments conservatively expire early; backward adjustments cannot extend the monotonic bound. Native `remaining_ms` follows the same paired bound. MCP/native waiting loops recheck on wake and after receiving answers; native cleanup also rechecks before returning an answer. No dependency, serialized timestamp, or DTO changes.

Exact additional RED: `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib wall_expiry` → **0 passed / 5 failed**, `/private/tmp/sshelter-task3-fix1-wall-red.log`. With monotonic-only remaining, wall-expired late Allow incorrectly succeeds; queued Allow and queued secret are consumed; expired native resolve succeeds; native remaining incorrectly reports ~120 seconds. Exact GREEN: same command → **5 passed / 0 failed**, `/private/tmp/sshelter-task3-fix1-wall-green.log`. Tests inject expired UTC with a live Instant and controlled wall-clock advance; they do not sleep/suspend the machine. `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib session::deadline::` → **1 passed / 0 failed**, `/private/tmp/sshelter-task3-fix1-deadline-green.log`, `a_backward_wall_clock_cannot_extend_the_monotonic_bound`.

Final affected reruns: MCP **40/40**, native auth **9/9**, production compilation successful (16 existing/classified warnings). Other focused suites above were not rerun after the clock-only change. Real suspend/resume/native platform verification remains Task6; controlled-clock behavior and the documented dual-clock policy are the evidence here.

Fix commit: `e8b8da06faeaa70d840a04b329015aaebd13ae8b` — `fix(mcp): release pin waits and enforce approval deadlines` (15 files, 1173 insertions / 93 deletions). Held `/private/tmp/sshelter-index.lock`, asserted BASE/branch and preexisting empty index, staged only the exact owned manifest, verified staged-set equality and `git diff --cached --check`, then committed. Post-commit worktree clean; report remains ignored. Final cargo runner exited 0, with all affected checks complete; no push/release or real credential access.
