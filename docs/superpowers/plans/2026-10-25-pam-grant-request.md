# Requesting a PAM grant from Lunport: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A connect to a host whose transport requires a Privileged Access Manager grant asks the person once (justification and duration, prefilled), requests the grant, waits for it, absorbs IAP's delay and connects; the Google Cloud panel shows the grant's state and can request one.

**Architecture:** The PAM calls move to Google's official Rust client (`google-cloud-privilegedaccessmanager-v1`) behind the existing `GcpClient` trait, with Lunport's gcloud-file token source plugged in through a `CredentialsProvider`. `RecordDirectory::prepare` reports a missing grant as `DirectoryError::GrantNeeded`; the broker's `Connector` asks through a new question kind (`QuestionKind::Grant`, rendered by Lunport's authentication window as a Request-a-grant form), calls `HostDirectory::request_grant`, shares one question per grant across concurrent connections, and retries a 4033 tunnel refusal for two minutes after a fresh grant. Two Tauri commands feed the panel's state line and its Request grant dialog.

**Tech Stack:** Rust (tokio, serde, mockito for tests), `google-cloud-privilegedaccessmanager-v1` 1.16 / `google-cloud-auth` 1.18 / `google-cloud-gax` 1.15, Tauri 2 commands with ts-rs bindings, React + vitest (static markup tests).

**Spec:** `docs/superpowers/specs/2026-10-25-pam-grant-request-design.md` (and, for the transport it extends, `docs/superpowers/specs/2026-10-25-gcp-iap-oslogin-design.md`).

## Global Constraints

- Every wait is bounded and cancellable: the question 5 minutes, the wait for `ACTIVE` 60 seconds (polling every 2 seconds), the IAP grace 2 minutes after the grant was given (retrying every 10 seconds), every HTTP call 20 seconds.
- Sentences are one sentence each, shown as written, values plain; the ones the spec fixes are copied verbatim below.
- A grant is requested only after a person answered the question (or pressed Request in the panel); MCP requests and the verification probe never ask. A justification is stored only in the device-local transport record and never logged.
- The transport record's schema stays 1; new `PamCheck` fields have serde defaults. Running any Rust test rewrites `src/bindings/`; revert unrelated binding changes and strip trailing whitespace from new ones before committing (`git checkout -- src/bindings/`, then keep only the files a task names).
- The SDK client is built with `.with_endpoint(...)` so mockito keeps serving the tests; no test talks to Google.
- No team-specific entitlement names or justifications in product text; test fixtures keep using `prod-operate` / `knowknow-prod`.

## Review Focus

1. A second grant with the same scope is refused by PAM: the connect re-checks the in-flight grants after the person answers and before it creates one; the panel's Request grant must do the same (Task 4 and Task 7 tests: a grant that appeared meanwhile is used, not requested again).
2. The person closes the grant window or walks away: the question cancels after 5 minutes and every connection waiting on the same gate fails with the refusal sentence, requesting nothing (Task 6 tests).
3. A grant time ahead of this clock, or a grant still `ACTIVATING` with no time yet: the IAP grace counts from now, never from a negative age (Task 4 test on `Prepared.granted_at`).
4. Several entitlements where only a later one holds the grant: the panel's state names that entitlement and disables Request grant; the connect asks nothing (Task 7 and Task 4 tests).
5. A duration above the entitlement's maximum, or an empty justification sent to PAM: PAM's own 400 message is shown, prefixed by the fixed sentence, and nothing hangs (Task 2 test).

---

### Task 1: The SDK and Lunport's credentials behind it

**Files:**
- Modify: `src-tauri/Cargo.toml` (dependencies after `rustls-native-certs`)
- Create: `src-tauri/src/gcp/credentials.rs`
- Modify: `src-tauri/src/gcp/mod.rs` (`pub mod credentials;`)

**Interfaces:**
- Consumes: `gcp::auth::{TokenSource, AuthError}` (`access_token(&self, account: Option<&str>) -> Result<Token, AuthError>`, `Token { value: Zeroizing<String>, account: String }`, `AuthError::is_retryable()`).
- Produces: `pub struct BearerCredentials { tokens: Arc<dyn TokenSource>, account: Option<String> }`, `BearerCredentials::new(tokens, account) -> Self`, `impl google_cloud_auth::credentials::CredentialsProvider for BearerCredentials` (`headers` answers `CacheableResource::New { entity_tag: EntityTag::new(), data }` with one `authorization: Bearer <token>` header marked sensitive; `universe_domain` answers `None`), `impl Debug` by hand (the account only). `pub fn credentials(tokens, account) -> google_cloud_auth::credentials::Credentials` (`Credentials::from(BearerCredentials::new(..))`).

- [ ] **Step 1: Add the dependencies**

In `Cargo.toml`, after the `rustls-native-certs` line, with a comment in the file's style ("Privileged Access Manager through Google's client library; the credentials stay Lunport's: gcp/credentials.rs."):

```toml
google-cloud-privilegedaccessmanager-v1 = "1.16"
google-cloud-auth = "1.18"
google-cloud-gax = "1.15"
http = "1"
```

Run: `cd src-tauri && cargo check --tests 2>&1 | tail -3` (without `--locked`, once, so `Cargo.lock` takes the new crates; every later command uses `--locked`)
Expected: `Finished`; `git diff --stat Cargo.lock` shows additions only.

- [ ] **Step 2: Write the failing tests** in `credentials.rs`'s `mod tests` (a `#[tokio::test]` each; `StaticToken` and a `Scripted`-style failing source as in `gcp/iap.rs`'s tests):

```rust
#[tokio::test] async fn the_provider_answers_a_bearer_header_from_the_token_source() { /* credentials(Arc::new(StaticToken("t0k".into())), Some("frank@retower.io".into())).headers(Extensions::new()).await → CacheableResource::New { data, .. }; data["authorization"] == "Bearer t0k"; the value is_sensitive(); universe_domain().await == None */ }
#[tokio::test] async fn a_token_failure_is_a_credentials_error_that_says_why() { /* a source answering Err(AuthError::SignInExpired { account }) → headers() is Err; its Display contains "run `gcloud auth login frank@retower.io`" */ }
```

- [ ] **Step 3: Run them to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib -- gcp::credentials`
Expected: FAIL to compile (`credentials` module missing).

- [ ] **Step 4: Implement `credentials.rs`**

`headers` fetches the token on `tokio::task::spawn_blocking` (the source is synchronous), builds the header with `HeaderValue::from_str(&format!("Bearer {}", token.value.as_str()))` + `set_sensitive(true)`, maps an `AuthError` to `CredentialsError` with its sentence and `is_retryable()` as the transient flag. A doc comment says why this trait is implemented (the design's "Constraints" paragraph on `CredentialsProvider`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd src-tauri && cargo test --locked --lib -- gcp::credentials`
Expected: `test result: ok. 2 passed`.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/gcp/credentials.rs src-tauri/src/gcp/mod.rs
git commit -m "feat(gcp): plug Lunport's gcloud credentials into Google's Rust client library"
```

---

### Task 2: PAM calls through the client library

**Files:**
- Modify: `src-tauri/src/gcp/rest.rs` (`GcpError`, `GcpClient`, `RestClient`, the PAM methods, tests)
- Modify: `src-tauri/src/gcp/pam.rs` (`Grant` fields and helpers)
- Modify: `src-tauri/src/session/record_directory_tests.rs` (`FakeGcp` gains the two methods, answering `Err(GcpError::Http { api: "Privileged Access Manager", status: 501 })` for now)

**Interfaces:**
- Consumes: Task 1's `credentials(tokens, account)`.
- Produces, in `gcp::pam`: `Grant` gains `pub name: String` and `pub justification: Option<String>`; `impl From<google_cloud_privilegedaccessmanager_v1::model::Grant> for Grant`; `pub fn until(&self) -> Option<SystemTime>` (`access_grant_time + requested_duration`, `None` without either); `pub fn is_final(&self) -> bool` (every state but `ACTIVATING`, `ACTIVE`, `SCHEDULED`, `APPROVAL_AWAITED`… precisely: `ACTIVATING` and `SCHEDULED` are the only non-final, non-active states); `pub fn duration_text(secs: u32) -> String` (`"1800s"`); `parse_grants` reads `name` and `justification.unstructuredJustification` too.
- Produces, in `gcp::rest`: `GcpError::Refused { api: &'static str, message: String }` with Display `"{api} refused the request: {message}."`; `GcpClient` gains `fn create_grant(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str, duration_secs: u32, justification: &str) -> Result<Grant, GcpError>` and `fn get_grant(&self, account: Option<&str>, name: &str) -> Result<Grant, GcpError>`; `grants` keeps its signature and reads every page through the client library; `RestClient` owns a current-thread `tokio::runtime::Runtime` and a cache of one `PrivilegedAccessManager` client per account key (`account.unwrap_or("")`), built with `.with_credentials(credentials(tokens, account))` and `.with_endpoint(pam_base)`; `fn gax_error(api, account, error: google_cloud_gax::error::Error) -> GcpError` maps HTTP 401/403 → `Denied { api, status, account }`, 400 → `Refused { api, message }` (the RPC status message, or the error's text), other statuses → `Http { api, status }`, no status → `Network(text)`.

- [ ] **Step 1: Write the failing tests** in `rest.rs`'s `mod tests` (mockito, the existing `client(&server)` helper; the client library sends extra query parameters, so match with `Matcher::AllOf` of `UrlEncoded` pairs, never `Matcher::Exact`):

```rust
#[test] fn create_grant_sends_the_parent_duration_and_justification_and_answers_the_grant() { /* POST /v1/projects/knowknow-prod/locations/global/entitlements/prod-operate/grants, body json has requestedDuration "1800s" and justification.unstructuredJustification "restart app-api" (Matcher::PartialJson); answer {name, state: "ACTIVATING", requestedDuration, justification}; the Grant has name "projects/…/grants/42", state ACTIVATING, justification Some("restart app-api") */ }
#[test] fn a_400_from_pam_is_its_own_sentence() { /* POST answers 400 with {"error":{"message":"requested_duration exceeds the maximum"}} → Err(GcpError::Refused { api: "Privileged Access Manager", message }) whose Display is "Privileged Access Manager refused the request: requested_duration exceeds the maximum." */ }
#[test] fn get_grant_reads_a_grant_by_name() { /* GET /v1/projects/knowknow-prod/locations/global/entitlements/prod-operate/grants/42 → state ACTIVE, auditTrail.accessGrantTime parsed, until() == accessGrantTime + 1800 s */ }
```

and keep `grants_are_read_across_pages` and `grants_are_searched_as_the_caller_created_them_and_filtered_here` as they are (they now exercise the client library's pagination).

- [ ] **Step 2: Run them to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib -- gcp::rest gcp::pam`
Expected: FAIL to compile (`create_grant`, `get_grant`, `Refused` missing).

- [ ] **Step 3: Implement the `pam.rs` additions and the `rest.rs` client-library path**

`until()`: `parse_rfc3339(access_grant_time) + requested_duration` where the duration is the API's `"<n>s"` form. In `rest.rs`, the search request sets `caller_relationship` to the HAD_CREATED enum value and `page_size` 50, iterates `.by_item()` with `google_cloud_gax::paginator::ItemPaginator`, and stops after 10 pages as today.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd src-tauri && cargo test --locked --lib -- gcp:: session::record_directory`
Expected: all pass (`FakeGcp` compiles with the new methods).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/gcp/rest.rs src-tauri/src/gcp/pam.rs src-tauri/src/session/record_directory_tests.rs
git commit -m "feat(gcp): create and read PAM grants through Google's client library"
```

---

### Task 3: The transport remembers the grant's defaults

**Files:**
- Modify: `src-tauri/src/sync/transports.rs` (`PamCheck`, `validate`, a new write), `src-tauri/src/sync/transports_tests.rs`
- Modify: `src/lib/transports.ts` (`newIapTransport`, `transportProblem`), `src/lib/transports.test.ts`, `src/components/records/TransportFields.tsx` (a Default duration field), `src/components/records/transport.test.tsx`
- Bindings: `src/bindings/PamCheck.ts` (regenerated by the Rust tests; keep it)

**Interfaces:**
- Produces: `PamCheck { entitlements, location, #[serde(default = "default_duration")] duration_secs: u32 /* 1800 */, #[serde(default)] justification: Option<String> }`; `validate` sentences "Enter a grant duration between 1 and 480 minutes." (`duration_secs` outside 60..=28_800 or not a whole minute) and "Keep the justification under 512 characters on one line." (longer than 512 chars, or any control character); `pub fn remember_grant_request(state: &SyncStateV3, host_id: &str, justification: &str, duration_secs: u32, now: u64) -> Result<SyncStateV3, RepositoryError>` (the transport with those two fields replaced, written without a compare-and-set; `NotFound`-style `invalid` error when the host has no transport or no PAM check); TS `transportProblem` mirrors both sentences; `newIapTransport`'s `pam` stays `null`, and the PAM checkbox turns it into `{ entitlements: [], location: "global", duration_secs: 1800, justification: null }`.

- [ ] **Step 1: Write the failing Rust tests** in `transports_tests.rs`:

```rust
#[test] fn pam_defaults_decode_for_an_older_record_and_validate() { /* a record payload whose pam has only entitlements+location decodes with duration_secs 1800 and justification None; duration_secs 30 → "Enter a grant duration between 1 and 480 minutes."; 28_860 → same; justification of 513 chars → "Keep the justification under 512 characters on one line."; "a\nb" → same */ }
#[test] fn remember_grant_request_keeps_everything_else_and_needs_a_pam_check() { /* after set(iap with prod_pam), remember_grant_request(.., "restart app-api", 3600, now) → the view's pam has justification Some("restart app-api"), duration_secs 3600, entitlements unchanged, version STATE_VERSION; on a transport without pam → Err */ }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib -- sync::transports`
Expected: FAIL to compile (fields missing).

- [ ] **Step 3: Implement the Rust side; run the tests**

Run: `cd src-tauri && cargo test --locked --lib -- sync::transports session::transports`
Expected: all pass; `src/bindings/PamCheck.ts` now has `duration_secs: number, justification: string | null`.

- [ ] **Step 4: Write the failing frontend tests**

In `src/lib/transports.test.ts`'s validation test: `withKind({ pam: { entitlements: ["prod-operate"], location: "global", duration_secs: 30, justification: null } })` → "Enter a grant duration between 1 and 480 minutes."; a 513-character justification → "Keep the justification under 512 characters on one line.". In `transport.test.tsx`'s PAM-fields test: the markup with a PAM check contains `Default duration (minutes)` and `value="30"`.

- [ ] **Step 5: Run them to verify they fail, implement, run again**

Run: `pnpm test src/lib/transports.test.ts src/components/records/transport.test.tsx`
Expected: first FAIL (TS type errors / missing sentence), then PASS after `transports.ts` and `TransportFields.tsx` (the field edits `duration_secs = minutes * 60`).

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/sync/transports.rs src-tauri/src/sync/transports_tests.rs src/bindings/PamCheck.ts src/lib/transports.ts src/lib/transports.test.ts src/components/records/TransportFields.tsx src/components/records/transport.test.tsx
git commit -m "feat(records): remember a transport's grant duration and last justification"
```

---

### Task 4: The directory asks for a grant and can request one

**Files:**
- Modify: `src-tauri/src/session/directory.rs` (`DirectoryError::GrantNeeded`, `GrantNeed`, `GrantReceipt`, `Prepared.granted_at`, `HostDirectory::request_grant`)
- Modify: `src-tauri/src/session/record_directory.rs` (`RecordSources.remember_grant`, `prepare`, `request_grant`), `src-tauri/src/session/record_directory_tests.rs`
- Modify: `src-tauri/src/session/app.rs` (wire `remember_grant` as `pin` is wired, through `record_runtime` with `transports::remember_grant_request`)
- Modify: `src-tauri/src/mcp/records.rs` (`PublicDirectory::prepare` maps `GrantNeeded` to the refusal), `src-tauri/src/session/verify.rs` (`ProbeDirectory::prepare` likewise), `src-tauri/src/session/format_directory.rs` (forward `request_grant` outside the lifecycle lock, as `prepare` is)

**Interfaces:**
- Produces, in `session::directory`: `pub struct GrantNeed { pub host: HostId, pub account: Option<String>, pub project: String, pub location: String, pub entitlement: String, pub duration_secs: u32, pub justification: Option<String> }` with `pub fn refusal_sentence(&self) -> String` (today's sentence: "No active Privileged Access Manager grant for <entitlements joined by " or "> on <project>. Request one (for example gcloud pam grants create --entitlement=<first> --requested-duration=30m --justification=\"…\" --location=<location> --project=<project>) and connect again." — `GrantNeed` carries `pub entitlements: Vec<String>` for the join and `entitlement` is the first); `pub struct GrantReceipt { pub entitlement: String, pub granted_at: SystemTime, pub active_until: SystemTime }`; `DirectoryError::GrantNeeded(GrantNeed)` whose Display is the refusal sentence; `Prepared { recent_grant: bool, granted_at: Option<SystemTime> }`; `fn request_grant(&self, _need: &GrantNeed, _justification: &str, _duration_secs: u32, _cancel: &CancelToken) -> Result<GrantReceipt, DirectoryError> { Err(DirectoryError::Unsupported("Requesting a grant is not available here.".into())) }`.
- Produces, in `session::record_directory`: `RecordSources.remember_grant: Box<dyn Fn(&HostId, &str, u32) -> Result<(), DirectoryError> + Send + Sync>`; `prepare` answers `GrantNeeded` (instead of `Denied`) when no listed entitlement has an in-flight grant, and sets `Prepared.granted_at` to the in-flight grant's `access_grant_time` (parsed), or `now` when the grant is `ACTIVATING`/has no time, or `now` when the time is ahead of the clock; `request_grant`: re-checks in-flight grants on `need.entitlement` (found → a receipt from it), else `gcp.create_grant(..)`, then `remember_grant`, then polls `get_grant` every 2 s for up to 60 s (cancel between polls → `Failed("The connection was cancelled.")`) until `ACTIVE` → receipt (`granted_at` = the grant's time or now, `active_until` = `granted_at + duration`); `APPROVAL_AWAITED` → `Denied("The <e> grant did not become active (state: APPROVAL_AWAITED); Lunport does not wait for an approver.")`; another final state → `Denied("The <e> grant did not become active (state: <STATE>).")`; still not active after 60 s → `Denied("The <e> grant did not become active within a minute (state: <STATE>); try connecting again.")`; a `GcpError` → `Denied(error.to_string())`.
- Consumes: Task 2's `create_grant`/`get_grant`/`Grant::until`; Task 3's `remember_grant_request` (through `app.rs`).

- [ ] **Step 1: Write the failing tests** in `record_directory_tests.rs` (`mod gcp_transport`; `FakeGcp` gains `created: Mutex<Vec<(String, u32, String)>>` and `states: Mutex<VecDeque<&'static str>>` for successive `get_grant` answers; a `remember` closure recording into the fixture):

```rust
#[test] fn prepare_asks_for_a_grant_with_the_transports_defaults_when_none_is_in_flight() { /* grants [ENDED] → Err(GrantNeeded(need)) with entitlement "prod-operate", entitlements both, duration_secs 1800, justification None, project knowknow-prod; need.refusal_sentence() == today's sentence */ }
#[test] fn prepare_dates_a_fresh_grant_and_never_in_the_future() { /* ACTIVE given 60 s ago → granted_at within ±5 s of that; given 30 s in the future → granted_at ≈ now; ACTIVATING without time → ≈ now */ }
#[test] fn request_grant_creates_remembers_polls_and_answers_a_receipt() { /* states [ACTIVATING, ACTIVE] → created == [(parent of prod-operate, 1800, "restart app-api")], remembered == [(GATE, "restart app-api", 1800)], receipt.active_until == granted_at + 1800 s */ }
#[test] fn request_grant_reuses_a_grant_that_appeared_meanwhile() { /* grants answer [ACTIVE] on the re-check → no create call; receipt from that grant */ }
#[test] fn request_grant_names_a_state_that_will_not_activate_and_gives_up_after_a_minute() { /* states [APPROVAL_AWAITED] → Denied("The prod-operate grant did not become active (state: APPROVAL_AWAITED); Lunport does not wait for an approver."); a Backoff-free poll limit: with states [ACTIVATING×31] and a test clock? — instead: `request_grant_with(need, …, poll_every: Duration::ZERO, wait: Duration::from_millis(50))` (expose the two durations as an inner fn the trait method calls with 2 s / 60 s) → Denied("… within a minute (state: ACTIVATING); try connecting again.") */ }
#[test] fn the_non_interactive_directories_turn_a_needed_grant_into_the_refusal() { /* mcp::records::PublicDirectory and verify's ProbeDirectory over a directory whose prepare answers GrantNeeded → Err(Denied(refusal sentence)) */ }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib -- session::record_directory::tests::gcp_transport`
Expected: FAIL to compile (`GrantNeeded`, `request_grant` missing).

- [ ] **Step 3: Implement; run the tests**

Run: `cd src-tauri && cargo test --locked --lib -- session:: mcp::`
Expected: all pass (the wrappers forward; `Preparing` in `connect.rs`'s tests compiles with the default `request_grant`).

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/session/directory.rs src-tauri/src/session/record_directory.rs src-tauri/src/session/record_directory_tests.rs src-tauri/src/session/app.rs src-tauri/src/mcp/records.rs src-tauri/src/session/verify.rs src-tauri/src/session/format_directory.rs
git commit -m "feat(session): the directory reports a missing PAM grant and can request one"
```

---

### Task 5: The grant question and Lunport's Request-a-grant window

**Files:**
- Modify: `src-tauri/src/session/protocol.rs` (`QuestionKind::Grant`), `src-tauri/src/session/auth_window.rs` (`AuthRequest.grant: Option<GrantPrompt>`, the 5-minute deadline for `Grant`, kind `"grant"`), `src-tauri/src/session/broker.rs` (`SessionOwner::ask`/`ask_at` waiting line for `Grant`), `src-tauri/src/cli/client.rs` (a `Grant` question is shown as its waiting text, no prompt mode)
- Modify: `src/components/AuthenticationWindow.tsx`, `src/components/AuthenticationWindow.test.tsx` (or the existing test file for it), `src/lib/mcp-flow.ts` (`receiveAuthQuestion` caps at 300 000 ms for `kind === "grant"`)
- Bindings: `src/bindings/AuthRequest.ts`, new `src/bindings/GrantPrompt.ts`

**Interfaces:**
- Produces, in `session::protocol`: `QuestionKind::Grant`; `pub struct GrantPrompt { pub project: String, pub entitlement: String, pub minutes: u32, pub justification: Option<String> }` (`Serialize, Deserialize, ts-rs export`), `impl GrantPrompt { pub fn to_text(&self) -> String /* JSON */; pub fn from_text(text: &str) -> Option<GrantPrompt> }`; `pub struct GrantAnswer { pub minutes: u32, pub justification: String }` with `pub fn encode(&self) -> String` (`"<minutes>\n<justification>"`) and `pub fn decode(text: &str) -> Option<GrantAnswer>` (minutes 1..=480, justification trimmed and non-empty).
- Produces, in `session::auth_window`: `AuthRequest.grant: Option<GrantPrompt>` (set from `GrantPrompt::from_text(text)` when the kind is `Grant`; `text` is then the sentence `No active Privileged Access Manager grant for <entitlement> on <project>.`); the deadline for `Grant` is `min(deadline, now + 300 s)`; `kind` serialized `"grant"`.
- Produces, in the window: for `request.kind === "grant"`: title `Request a grant`, the sentence, inputs `Justification` (prefilled with `request.grant.justification ?? ""`, autofocus) and `Duration (minutes)` (prefilled with `request.grant.minutes`), buttons `Request` (disabled while the justification is empty or the minutes are not 1–480) and `Cancel`; Enter in either field submits `GrantAnswer.encode`; no "Server prompt" line and no "Server context" for this kind.
- Produces, in the broker and the CLI: the terminal's waiting line `Waiting for you to request a Privileged Access Manager grant in Lunport.`

- [ ] **Step 1: Write the failing Rust tests**

In `auth_window.rs`'s tests: `a_grant_question_carries_its_prompt_and_waits_five_minutes` (an `ask(QuestionKind::Grant, &GrantPrompt{..}.to_text(), true, None)` → the surface saw a request with `kind == "grant"`, `grant == Some(prompt)`, `remaining_ms` ≤ 300 000 and > 120 000). In `protocol.rs`'s tests: `a_grant_answer_round_trips_and_rejects_nonsense` (`decode("30\nrestart app-api")` → minutes 30; `decode("0\nx")`, `decode("30\n")`, `decode("thirty")` → None). In `broker.rs`'s tests: `a_grant_question_shows_the_waiting_line` (the terminal saw the waiting sentence). In `cli/client.rs`'s tests: `a_grant_question_is_a_notice_in_the_terminal` (`handle(question("q", QuestionKind::Grant, "…", true))` → `Action::Mode(Mode::Notice..)`/the existing notice action, never a prompt mode — follow how `HostKeyNotice` is handled at line ~575).

- [ ] **Step 2: Run them to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib -- session::auth_window session::protocol session::broker cli::client`
Expected: FAIL to compile (`Grant` variant missing).

- [ ] **Step 3: Implement the Rust side; run the tests; keep `src/bindings/AuthRequest.ts` and `src/bindings/GrantPrompt.ts`**

Run: `cd src-tauri && cargo test --locked --lib -- session::auth_window session::protocol session::broker cli::client`
Expected: all pass.

- [ ] **Step 4: Write the failing frontend test** (static markup, in the window's test file):

```ts
it("asks for a grant with its own form, prefilled, and answers both fields", () => { /* render with request { kind: "grant", text: "No active Privileged Access Manager grant for prod-operate on knowknow-prod.", grant: { project: "knowknow-prod", entitlement: "prod-operate", minutes: 30, justification: "restart app-api" }, … } → html contains "Request a grant", 'value="restart app-api"', 'value="30"', "Request", not "Server prompt"; receiveAuthQuestion caps a grant at 300000 */ });
```

- [ ] **Step 5: Run it to verify it fails, implement, run again**

Run: `pnpm test src/components/AuthenticationWindow.test.tsx src/lib/mcp-flow.test.ts`
Expected: FAIL (no form), then PASS.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/session/protocol.rs src-tauri/src/session/auth_window.rs src-tauri/src/session/broker.rs src-tauri/src/cli/client.rs src/bindings/AuthRequest.ts src/bindings/GrantPrompt.ts src/components/AuthenticationWindow.tsx src/components/AuthenticationWindow.test.tsx src/lib/mcp-flow.ts src/lib/mcp-flow.test.ts
git commit -m "feat(session): a Request-a-grant question of its own, shown by Lunport's window"
```

---

### Task 6: The connect asks once, requests, and rides out IAP's delay

**Files:**
- Create: `src-tauri/src/session/grants.rs` (the gate)
- Modify: `src-tauri/src/session/connect.rs` (`Connector` gains `grants: &'a GrantGates`; `connect_within`), `src-tauri/src/session/mod.rs` (`pub mod grants;`), every `Connector { .. }` construction (`session/app.rs`, `session/broker.rs`, `session/tunnels.rs`, `session/deploy.rs`, `session/verify.rs`, `mcp/records.rs`, tests) passes the app's shared `GrantGates`

**Interfaces:**
- Produces, in `session::grants`: `pub struct GrantGates` (`Default`, `Send + Sync`, a `Mutex<HashMap<GateKey, Outcome>>` + `Condvar`); `pub struct GateKey { account: Option<String>, project, location, entitlement }`; `pub enum Entry { Lead(Lease), Outcome(Result<GrantReceipt, String>) }`; `pub fn enter(&self, key: GateKey, cancel: &CancelToken, wait: Duration) -> Entry` (the first caller gets `Lead`; later callers block until the lead settles, `cancel` or `wait` (6 minutes) end the wait as `Outcome(Err(sentence))`); `Lease::settle(self, outcome: Result<GrantReceipt, String>)` (also on drop with `Err(refusal)` if never settled).
- Produces, in `session::connect`: after `prepare` answers `GrantNeeded(need)`: `enter` → as lead: `owner.ask(QuestionKind::Grant, &GrantPrompt { project, entitlement, minutes: need.duration_secs / 60, justification }.to_text(), true, Some(now + 300 s))`; `Reply::Answer(text)` decoded with `GrantAnswer::decode` (undecodable → treated as cancelled); `Cancelled | TimedOut | Gone` or no decode → settle `Err(need.refusal_sentence())` → `ConnectFailure::new(kinds::AUTH, sentence)`; else `directory.request_grant(&need, &answer.justification, answer.minutes * 60, cancel)` → `Ok(receipt)`: `owner.host_key_notice(&format!("Requested a {}-minute {} grant on {}; active until {}.", minutes, entitlement, project, local_hhmm(active_until)))`, settle `Ok`, run `prepare` again and go on; `Err(error)` → settle `Err(directory_failure(error).text)` and fail with it. As a waiter: `Outcome(Ok(_))` → `prepare` again (a second `GrantNeeded` → fail with the refusal); `Outcome(Err(sentence))` → fail with `kinds::AUTH` and that sentence. The IAP grace: a `ConnectError::Tunnel { code: Some(4033), .. }` while `prepared.granted_at` is within the last 120 s: once `owner.host_key_notice("IAP has not seen the grant yet; retrying for up to two minutes.")`, then wait 10 s in 250 ms steps checking `cancel` and `owner`'s presence, and try the round again without counting it; past the grace → today's `failure_of` with the note sentence. `pub fn local_hhmm(time: SystemTime) -> String` (local time, `HH:MM`, via `chrono`-free arithmetic: use `libc::localtime_r`? — no: use the `time` crate? Neither is a dependency; `std` cannot give local time, so add `chrono = { version = "0.4", default-features = false, features = ["clock"] }` in this task if `Cargo.lock` does not already resolve it (check `grep -n 'name = "chrono"' Cargo.lock`; if present, use it)).
- Consumes: Task 4's `GrantNeed`/`GrantReceipt`/`request_grant`, Task 5's `QuestionKind::Grant`, `GrantPrompt`, `GrantAnswer`.

- [ ] **Step 1: Write the failing tests** in `connect.rs`'s tests (the `Preparing` directory gains scripted `request_grant` answers and a list of calls; an owner that answers the grant question with a fixed `GrantAnswer`; a `FakeEngine` that fails `n` times with a given error then connects — add `FakeEngine::failing_times(n, error)` in `ssh/fake.rs` if there is none):

```rust
#[test] fn a_needed_grant_is_asked_once_requested_noticed_and_then_connected() { /* prepare answers GrantNeeded then Ok; owner answers "30\nrestart app-api"; request_grant called once with ("restart app-api", 1800); notices contain "Requested a 30-minute prod-operate grant on knowknow-prod; active until "; connected */ }
#[test] fn a_cancelled_grant_question_fails_with_the_refusal_and_requests_nothing() { /* owner answers Cancelled → failure(kinds::AUTH, need.refusal_sentence()); request_grant never called; engine attempts 0 */ }
#[test] fn two_connections_needing_the_same_grant_ask_once_and_both_connect() { /* two threads, one GrantGates; the owner counts questions == 1; both Ok */ }
#[test] fn a_cancelled_question_fails_the_waiting_connection_too() { /* lead cancels; the waiter fails with the same sentence and asked nothing */ }
#[test] fn a_4033_within_the_grace_is_retried_until_the_tunnel_opens() { /* prepared.granted_at = now; engine fails twice with Tunnel 4033 then connects; notices contain "IAP has not seen the grant yet; retrying for up to two minutes."; connected; attempts 3 */ }
#[test] fn the_grace_runs_out_with_the_note() { /* granted_at = now - 119 s… use a test knob: Connector::with_grace(Duration) — expose `grace: Duration` and `grace_step: Duration` on Connector with defaults 120 s / 10 s; grace 0 → the first 4033 fails with "…; the grant became active moments ago, and IAP can take about 1½ minutes to see it." */ }
#[test] fn no_interaction_never_asks_for_a_grant() { /* through mcp::records::NoInteraction (enabled) over a directory answering GrantNeeded → failure with the refusal; owner asked nothing */ }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib -- session::connect::tests`
Expected: FAIL to compile (`grants` field, `GrantGates` missing).

- [ ] **Step 3: Implement `grants.rs` and the connect changes; run the tests**

Run: `cd src-tauri && cargo test --locked --lib -- session:: mcp::`
Expected: all pass (every `Connector` construction updated).

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/session/grants.rs src-tauri/src/session/mod.rs src-tauri/src/session/connect.rs src-tauri/src/session/app.rs src-tauri/src/session/broker.rs src-tauri/src/session/tunnels.rs src-tauri/src/session/deploy.rs src-tauri/src/session/verify.rs src-tauri/src/mcp/records.rs src-tauri/src/ssh/fake.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "feat(session): ask once for a PAM grant, request it, and wait for IAP to see it"
```

---

### Task 7: The panel's grant state and Request grant

**Files:**
- Modify: `src-tauri/src/session/transports.rs` (`PamStatusView`, `transports_pam_status`, `transports_pam_request`, pure helpers + tests), `src-tauri/src/lib.rs` (register both commands)
- Modify: `src/lib/transports.ts` (`fetchPamStatus`, `requestPamGrant`, `pamStatusLine`), `src/components/records/TransportsPanel.tsx` (the state line, the Request grant button, the dialog), `src/components/records/transport.test.tsx`
- Create: `src/components/records/GrantRequestDialog.tsx`
- Bindings: `src/bindings/PamStatusView.ts`

**Interfaces:**
- Produces, in `session::transports`: `pub struct PamStatusView { pub entitlement: Option<String>, pub state: String /* "active" | "activating" | "none" | "error" */, pub active_until_ms: Option<u64>, pub message: Option<String> }` (ts-rs); `pub fn pam_status(gcp: &dyn GcpClient, transport: &HostTransport) -> PamStatusView` (searches every listed entitlement; `active` with the earliest `until` among active grants, else `activating` if any, else `none`; a `GcpError` → `error` with its sentence); `pub fn pam_request(gcp: &dyn GcpClient, remember: &dyn Fn(&str, u32) -> Result<(), String>, transport: &HostTransport, justification: &str, duration_secs: u32, cancel: &CancelToken) -> Result<PamStatusView, String>` (the same steps as `RecordDirectory::request_grant`, implemented once in `gcp/pam.rs` as `pub fn request_and_wait(gcp, parent fields, justification, duration, poll_every, wait, cancel) -> Result<Grant, GcpError-or-sentence>` and called by both); commands `transports_pam_status(app, window, host_id) -> Result<PamStatusView, String>` and `transports_pam_request(app, window, host_id, justification, duration_secs) -> Result<PamStatusView, String>` (main window only; the request remembers through `transports::remember_grant_request` on the runtime).
- Produces, in `src/lib/transports.ts`: `fetchPamStatus(hostId)`, `requestPamGrant(hostId, justification, durationSecs)`, `pamStatusLine(view: PamStatusView): string` (`"prod-admin · active until 11:07"`, `"prod-operate · activating…"`, `"no active grant"`, or the message).
- Produces, in the panel: under the Checks cell of a row with a PAM check, the status line (loaded on mount and after a request, refreshed every 60 s while mounted, via `setInterval` cleared on unmount); a `Request grant` button (disabled while the state is `active` or `activating`, or busy) opening `GrantRequestDialog` (fields Justification and Duration (minutes), prefilled from the transport's `pam.justification` / `pam.duration_secs`, a Request button disabled on an empty justification or minutes outside 1–480, the result line or error inside the dialog).

- [ ] **Step 1: Write the failing Rust tests** in `session/transports.rs`'s tests (the fake `GcpClient` there gains the two methods): `pam_status_names_the_entitlement_that_holds_the_grant_and_the_earliest_end`, `pam_status_reports_activating_none_and_the_apis_sentence`, `pam_request_requests_the_first_entitlement_remembers_and_waits_for_active`.
- [ ] **Step 2: Run to verify they fail; implement; run** — `cd src-tauri && cargo test --locked --lib -- session::transports gcp::pam`. Expected: pass; `src/bindings/PamStatusView.ts` written.
- [ ] **Step 3: Write the failing frontend tests** in `transport.test.tsx`: `pamStatusLine` for the four states; the panel renders `Request grant` for a transport with a PAM check and not for one without; the dialog markup contains `Justification`, `Duration (minutes)`, `value="30"` and the prefilled justification.
- [ ] **Step 4: Run to verify they fail; implement; run** — `pnpm test src/components/records/transport.test.tsx && pnpm exec tsc --noEmit`. Expected: pass.
- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/session/transports.rs src-tauri/src/lib.rs src-tauri/src/gcp/pam.rs src/bindings/PamStatusView.ts src/lib/transports.ts src/components/records/TransportsPanel.tsx src/components/records/GrantRequestDialog.tsx src/components/records/transport.test.tsx
git commit -m "feat(ui): show a transport's PAM grant and request one from the Google Cloud panel"
```

---

### Task 8: Documentation and whole-branch verification

**Files:**
- Modify: `docs/usage.md` (the PAM sentences of "Google Cloud IAP and OS Login"), `docs/development.md` (the client library, `gcp/credentials.rs`, mockito's endpoint override), `docs/superpowers/reviews/2026-10-25-gcp-iap-oslogin-review.md` (a line that the PAM request landed)

- [ ] **Step 1: Write the docs** — usage: the prompt (what it asks, Enter requests, Cancel keeps today's refusal), the panel's state line and Request grant, that AI and automated connections never request. Development: the three crates, why `CredentialsProvider` is implemented, `with_endpoint` in tests.
- [ ] **Step 2: Run the complete safe suites**

Run: `cd src-tauri && cargo test --locked --lib -- --test-threads=2 --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none --skip ssh::engine_tests::login_methods::pam 2>&1 | tail -3`, `cargo test --locked --test app_profile_build 2>&1 | tail -3`, `pnpm test 2>&1 | tail -4`, `pnpm build`, `cargo clippy --locked --tests 2>&1 | grep -E "src/gcp|src/session/(grants|connect|transports|record_directory|auth_window)"`.
Expected: all pass; no new clippy warnings in the files this plan touched.

- [ ] **Step 3: Commit and push**

```bash
git add docs/usage.md docs/development.md docs/superpowers/reviews/2026-10-25-gcp-iap-oslogin-review.md
git commit -m "docs: describe requesting a PAM grant from Lunport"
git push -u origin claude/project-thread-whbjuy
```
