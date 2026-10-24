# Google Cloud IAP tunnels and OS Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A saved host can be reached through an IAP TCP-forwarding WebSocket tunnel that Lunport opens itself (no `gcloud` process), logged in as the OS Login user, after an optional PAM grant check.

**Architecture:** A new `gcp` module holds the SSH Relay v4 codec, the WebSocket tunnel with reconnects, gcloud-file credentials, and REST clients for OS Login and PAM. The russh engine learns a `Transport` per hop and hands the tunnel stream to its existing handshake. A per-host `transport:<host-id>` record (device-local, tunnel-rule shaped) stores the settings; `RecordDirectory` maps it onto the first hop and resolves OS Login and PAM before the broker connects. The host editor gets a "Connect through" section.

**Tech Stack:** Rust (tokio, russh 0.64.1 unchanged, `tokio-tungstenite 0.30` + `rustls-tls-native-roots`, `reqwest 0.13` blocking, `url 2`, `serde_json`, `zeroize`, `mockito` in tests), React/TypeScript (vitest), ts-rs bindings.

**Spec:** `docs/superpowers/specs/2026-10-25-gcp-iap-oslogin-design.md`

## Global Constraints

- Never spawn `gcloud`; never read `credentials.db` or `access_tokens.db`; never write under gcloud's config directory.
- No access token, refresh token, client secret or login profile in logs, error texts, settings exports or sync records. Secrets are `Zeroizing`.
- `src-tauri/src/ssh/russh_engine.rs` stays the only file naming russh (`ssh::tests::russh_is_named_by_russh_engine_rs_and_by_no_other_file` enforces it).
- `HostPayload` and the account protocol schemas are unchanged. New record type: `Meta` record `transport:<host-id>`, payload `{ "schema": 1, "transport": … }`, stored in `local.transports` only, gated by `TRANSPORT_STATE_VERSION = 9`.
- Every engine wait is bounded by the hop's `connect_timeout` or a constant from this plan; nothing waits for a person inside the engine.
- Relay constants (from gcloud 590.0.0, Apache-2.0): host `tunnel.cloudproxy.app`, path root `/v4`, endpoints `connect` and `reconnect`, subprotocol `relay.tunnel.cloudproxy.app`, origin `bot:iap-tunneler`, tags `0x0001` CONNECT_SUCCESS_SID, `0x0002` RECONNECT_SUCCESS_ACK, `0x0004` DATA, `0x0007` ACK, max DATA payload 16 384 bytes, ACK owed when unacked received bytes exceed 2 × 16 384, at most 5 unsent frames queued, reconnect sleep 1.5 s × 1.1 per try capped at 20 s, 15 minutes in all, query parameter `newWebsocket=True`.
- Error sentences are the ones in the spec's "Error texts", verbatim; all user-facing text is printable (`session::auth::printable`).
- Cargo: `cargo test --locked` must pass, so `Cargo.lock` is committed with every dependency change. Dev tests must pass with `cargo test --locked --lib <filter>` from `src-tauri/`.
- Code and commit messages in English, conventional commits (`feat(gcp): …`, `feat(ssh): …`, `feat(records): …`, `feat(ui): …`, `docs: …`, `test: …`). No model identifiers in any artifact.
- The Apache License 2.0 notice for the ported gcloud code lives in `src-tauri/src/gcp/NOTICE.md` and is referenced from `gcp/relay.rs` and `gcp/iap.rs` headers.

## Review Focus

1. A server DATA frame longer than 16 384 bytes, or an absurd length prefix: the codec must cap at 1 MiB and fail as a protocol error, not allocate what the prefix says (Task 1 test `a_frame_longer_than_the_cap_is_a_protocol_error`).
2. A token refresh that fails with a network error while reconnecting: the tunnel keeps retrying within the 15-minute budget; only `invalid_grant` ends it (Task 3 test `a_transient_token_failure_during_reconnect_is_retried_and_invalid_grant_ends_the_tunnel`).
3. Bulk writes while the WebSocket is down: at most 5 frames queue, the writer is held back, and every byte arrives once and in order after the reconnect (Task 3 test `a_megabyte_written_across_a_drop_arrives_once_and_in_order`).
4. A gcloud config directory with no `active_config` or a `legacy_credentials` directory for another account only: a `NoCredentials` error naming the account and the directory, never a panic or a silent fallback to someone else's account (Task 2 test `a_missing_active_config_or_other_accounts_credentials_give_no_credentials`).
5. A host with a transport used as the second hop of another host's chain: `resolve` refuses with the spec's jump-host sentence; the engine's `check_chain` refuses the same shape independently (Task 7 test `a_transport_on_a_jump_target_is_refused`, Task 4 test `a_transport_on_a_later_hop_is_a_bad_jump_chain`).

---

### Task 1: `gcp` module, dependencies and the relay codec

**Files:**
- Modify: `src-tauri/Cargo.toml` (`[dependencies]`: `tokio-tungstenite = { version = "0.30", default-features = false, features = ["connect", "handshake", "rustls-tls-native-roots"] }`, `url = "2"`; both `rustls*`, `tokio-rustls`, `url` are already in `Cargo.lock` through reqwest; `cargo build` adds `tungstenite`/`tokio-tungstenite`), `src-tauri/Cargo.lock`
- Modify: `src-tauri/src/lib.rs:1-40` (add `mod gcp;` after `mod fsutil;`)
- Create: `src-tauri/src/gcp/mod.rs`, `src-tauri/src/gcp/relay.rs`, `src-tauri/src/gcp/NOTICE.md`
- Test: `src-tauri/src/gcp/relay.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces, in `gcp::relay`:
  - `pub const SUBPROTOCOL: &str`, `pub const ORIGIN: &str`, `pub const DEFAULT_URL_ROOT: &str = "wss://tunnel.cloudproxy.app/v4"`, `pub const MAX_DATA_FRAME: usize = 16384`, `pub const ACK_THRESHOLD: u64 = 32768`, `pub const MAX_UNSENT_FRAMES: usize = 5`, `pub const MAX_FRAME_BYTES: usize = 1024 * 1024`.
  - `pub struct Endpoint { pub project: String, pub zone: String, pub instance: String, pub interface: String, pub port: u16, pub url_root: Option<String> }` with `pub fn connect_url(&self) -> String` and `pub fn reconnect_url(&self, sid: &[u8], ack: u64) -> String`. Query pairs are form-encoded with `url::Url::query_pairs_mut().append_pair`, in this order: connect `project, port, newWebsocket=True, zone, instance, interface`; reconnect `sid, ack, newWebsocket=True, zone`. `url_root` replaces the scheme, host and path root (`ws://127.0.0.1:1234/v4` in tests).
  - `pub enum Frame { ConnectSuccess { sid: Vec<u8> }, ReconnectSuccess { ack: u64 }, Data(Vec<u8>), Ack(u64), Unknown(u16) }` (`Clone, Debug, PartialEq, Eq`).
  - `pub fn encode_data(payload: &[u8]) -> Vec<u8>` (`debug_assert!(payload.len() <= MAX_DATA_FRAME)`), `pub fn encode_ack(ack: u64) -> Vec<u8>`, `pub fn decode(frame: &[u8]) -> Result<Frame, RelayError>` (trailing bytes after a complete frame are ignored, as gcloud does).
  - `pub enum RelayError { Incomplete, Oversized(usize), OutOfOrderAck { ack: u64, confirmed: u64 }, AckBeyondSent { ack: u64, sent: u64 }, EarlyFrame(&'static str), DuplicateSuccess }` (`Debug, PartialEq, Eq`, `Display` one sentence each).
  - `#[derive(Default)] pub struct Bookkeeping` with `pub fn note_received(&mut self, len: usize)`, `pub fn ack_due(&self) -> Option<u64>` (`Some(total_received)` when `total_received - acked > ACK_THRESHOLD`), `pub fn mark_acked(&mut self, total: u64)`, `pub fn note_sent(&mut self, payload: Vec<u8>)` (pushes to the unconfirmed deque), `pub fn confirm(&mut self, ack: u64) -> Result<(), RelayError>` (gcloud's `_ConfirmData`: drops whole chunks, splits a partial one, errors on backwards or beyond-sent), `pub fn take_unconfirmed(&mut self) -> Vec<Vec<u8>>` (for resending after a reconnect), `pub fn total_received(&self) -> u64`, `pub fn total_confirmed(&self) -> u64`.

- [ ] **Step 1: Add the dependencies and the module skeleton**

`Cargo.toml` lines as above, with a comment in the style of the file: `# Google Cloud IAP tunnels (src/gcp/): the relay's WebSocket. rustls, tokio-rustls and the native roots are already in the lockfile through reqwest.` Create `src-tauri/src/gcp/mod.rs` with a module doc (the spec's first paragraph, condensed) and `pub mod relay;`. Create `NOTICE.md` naming the four gcloud files, "Copyright Google LLC, Apache License 2.0", and the SPDX link. Add `mod gcp;` to `lib.rs`.

- [ ] **Step 2: Build once to update `Cargo.lock`**

Run: `cd src-tauri && cargo check --tests 2>&1 | tail -3`
Expected: `Finished`; `git status --short Cargo.lock` shows it modified; `grep -c 'name = "tokio-tungstenite"' Cargo.lock` prints `1`.

- [ ] **Step 3: Write the failing codec tests**

In `relay.rs`, `mod tests` (all assert exact bytes; the Python `struct` formats `>H`, `>HI%ds`, `>HQ` are the oracle):

```rust
#[test] fn a_data_frame_is_tag_4_length_and_bytes() { assert_eq!(encode_data(b"hi"), [0, 4, 0, 0, 0, 2, b'h', b'i']); }
#[test] fn an_ack_frame_is_tag_7_and_a_big_endian_u64() { assert_eq!(encode_ack(0x0102030405060708), [0, 7, 1, 2, 3, 4, 5, 6, 7, 8]); }
#[test] fn every_frame_kind_decodes_and_trailing_bytes_are_ignored() { /* ConnectSuccess sid b"abc" from [0,1,0,0,0,3,b'a',b'b',b'c',9,9]; ReconnectSuccess 5 from [0,2,0,0,0,0,0,0,0,5]; Data; Ack; Unknown(0x0009) from [0,9] */ }
#[test] fn a_cut_frame_is_incomplete() { assert_eq!(decode(&[0, 4, 0, 0, 0, 5, 1, 2]), Err(RelayError::Incomplete)); assert_eq!(decode(&[0]), Err(RelayError::Incomplete)); }
#[test] fn a_frame_longer_than_the_cap_is_a_protocol_error() { /* length prefix 0xFFFF_FFFF → Err(Oversized(4294967295)); length 1 MiB + 1 with that many bytes → Oversized */ }
#[test] fn connect_and_reconnect_urls_match_gcloud() {
    let endpoint = Endpoint { project: "eng-dev-396409".into(), zone: "asia-east1-b".into(), instance: "jumpbox".into(), interface: "nic0".into(), port: 22, url_root: None };
    assert_eq!(endpoint.connect_url(), "wss://tunnel.cloudproxy.app/v4/connect?project=eng-dev-396409&port=22&newWebsocket=True&zone=asia-east1-b&instance=jumpbox&interface=nic0");
    assert_eq!(endpoint.reconnect_url(b"s id/1", 70000), "wss://tunnel.cloudproxy.app/v4/reconnect?sid=s+id%2F1&ack=70000&newWebsocket=True&zone=asia-east1-b");
}
#[test] fn a_url_root_override_replaces_scheme_host_and_path() { /* url_root Some("ws://127.0.0.1:4321/v4") → "ws://127.0.0.1:4321/v4/connect?project=…" */ }
#[test] fn an_ack_is_owed_only_past_twice_the_frame_size() { /* note_received(32768) → ack_due None; note_received(1) → Some(32769); mark_acked(32769) → None */ }
#[test] fn confirming_drops_whole_chunks_and_splits_a_partial_one() { /* note_sent(vec![1;10]); note_sent(vec![2;10]); confirm(15) → Ok, total_confirmed 15, take_unconfirmed == vec![vec![2;5]] */ }
#[test] fn a_backwards_or_oversized_ack_is_an_error() { /* confirm(5) then confirm(3) → OutOfOrderAck{ack:3,confirmed:5}; confirm(100) with 10 sent → AckBeyondSent{ack:100,sent:10} */ }
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib gcp::relay 2>&1 | tail -5`
Expected: compile errors for the missing items.

- [ ] **Step 5: Implement `gcp/relay.rs`**

Header comment: ported from gcloud's `iap_tunnel_websocket_utils.py` and `iap_tunnel_websocket.py` (`_ConfirmData`, `_MaybeSendAck`), see `NOTICE.md`. Frame length prefixes above `MAX_FRAME_BYTES` are `Oversized` before any allocation.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd src-tauri && cargo test --locked --lib gcp::relay 2>&1 | tail -3`
Expected: `test result: ok. 10 passed`.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/lib.rs src-tauri/src/gcp
git commit -m "feat(gcp): add the IAP relay v4 frame codec and URL builder"
```

---

### Task 2: Google credentials from gcloud's files

**Files:**
- Create: `src-tauri/src/gcp/auth.rs`
- Modify: `src-tauri/src/gcp/mod.rs` (`pub mod auth;`)
- Test: `src-tauri/src/gcp/auth.rs` (`mod tests`, mockito + `tempfile`)

**Interfaces:**
- Produces, in `gcp::auth`:
  - `pub struct Token { pub value: crate::ssh::Secret, pub account: String }`.
  - `pub trait TokenSource: Send + Sync { fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError>; }`.
  - `pub enum AuthError { NoCredentials { account: Option<String>, config_dir: PathBuf }, Unsupported { path: PathBuf, kind: String }, Malformed { path: PathBuf }, SignInExpired { account: String }, Http { status: u16 }, Network(String) }` (`Clone, Debug, PartialEq, Eq`), `impl Display` with the spec's sentences: `NoCredentials` → "No Google Cloud credentials for `<account>` were found under `<config dir>`; run `gcloud auth login <account>`." (without an account: "No Google Cloud credentials were found under `<dir>`; run `gcloud auth login`."), `SignInExpired` → "Google sign-in for `<account>` has expired or was revoked; run `gcloud auth login <account>` and connect again.", `Http` → "Google's token service answered `<code>`.", `Unsupported` → "`<path>` holds `<kind>` credentials, which Lunport does not use; sign in with `gcloud auth login`.", `Network(text)` → "Google's token service could not be reached: <text>.", `Malformed` → "`<path>` is not a credentials file Lunport can read."; `pub fn is_retryable(&self) -> bool` (true for `Network` and `Http` 5xx only).
  - `pub struct FileStore` with `pub fn from_environment() -> FileStore` (config dir from `std::env`, ADC override from `GOOGLE_APPLICATION_CREDENTIALS`, token URL `https://oauth2.googleapis.com/token`), `pub fn new(config_dir: PathBuf, adc_override: Option<PathBuf>, token_url: &str) -> FileStore`, `impl TokenSource for FileStore`.
  - `pub fn config_dir(var: &dyn Fn(&str) -> Option<String>, home: Option<&Path>, windows: bool) -> PathBuf` (gcloud's `_GetGlobalConfigDir`: `CLOUDSDK_CONFIG`, else `<home>/.config/gcloud`, on Windows `%APPDATA%\gcloud`, else `C:\gcloud` when `SystemDrive` is unset).
  - `pub fn active_account(config_dir: &Path) -> Option<String>` (`active_config` → `configurations/config_<name>` → `[core]` `account`).
  - `pub fn legacy_credentials_path(config_dir: &Path, account: &str) -> PathBuf` (`legacy_credentials/<account with ':' removed>/adc.json`).
  - `pub struct StaticToken(pub String)` implementing `TokenSource` (tests; account "static@example.com").
  - Private: `Credentials { client_id, client_secret: Secret, refresh_token: Secret, account }` parsed from an `authorized_user` file; `Cached { token: Secret, expires_at: Instant }`; refresh when under 5 minutes remain; `invalid_grant` in the JSON error body → `SignInExpired`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn the_config_dir_follows_gcloud() { /* CLOUDSDK_CONFIG wins; unix → home/.config/gcloud; windows → APPDATA\gcloud; windows without APPDATA → SystemDrive + \gcloud */ }
#[test] fn the_active_account_is_read_from_the_active_configuration() { /* tempdir: active_config "prod", configurations/config_prod "[core]\naccount = frank@re-tower.com\nproject = x\n" → Some("frank@re-tower.com") */ }
#[test] fn a_named_account_reads_its_legacy_file_and_refreshes_a_token() { /* mockito POST /token with form fields client_id, client_secret, refresh_token, grant_type=refresh_token → {"access_token":"ya29.x","expires_in":3599,"token_type":"Bearer"}; FileStore::new(dir, None, &server.url()).access_token(Some("frank@retower.io")) → Token { account: "frank@retower.io", value "ya29.x" } */ }
#[test] fn a_fresh_token_is_cached_until_five_minutes_before_expiry() { /* mock expects exactly 1 call (mockito `.expect(1)`), two access_token calls; then a file whose cached expiry is forced near → second refresh (use a `#[cfg(test)] fn force_expiry(&self, path, at)` helper on FileStore) */ }
#[test] fn without_an_account_the_adc_file_then_the_active_accounts_legacy_file_are_used() { /* GOOGLE_APPLICATION_CREDENTIALS override path first; then application_default_credentials.json; then legacy of active_account; assert Token.account comes from the file's "account" field */ }
#[test] fn a_missing_active_config_or_other_accounts_credentials_give_no_credentials() { /* dir with legacy_credentials/other@example.com only and no active_config: access_token(None) → Err(NoCredentials{account: None, config_dir}); access_token(Some("frank@retower.io")) → Err(NoCredentials{account: Some(..)}) */ }
#[test] fn invalid_grant_is_sign_in_expired_and_a_5xx_is_retryable() { /* 400 {"error":"invalid_grant","error_description":"Token has been expired or revoked."} → SignInExpired{account}; 503 → Http{status:503} with is_retryable() */ }
#[test] fn a_service_account_file_is_reported_as_unsupported() { /* {"type":"service_account",...} → Unsupported{kind:"service_account"} */ }
#[test] fn error_texts_name_no_secret() { /* Display of each variant does not contain "refresh" token values used in fixtures */ }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib gcp::auth 2>&1 | tail -3`
Expected: compile errors.

- [ ] **Step 3: Implement `gcp/auth.rs`**

`reqwest::blocking::Client` with a 20 s timeout and `user_agent(format!("lunport/{}", env!("CARGO_PKG_VERSION")))`. Parse the INI with a 20-line hand parser (sections in brackets, `key = value`, `#`/`;` comments). Resolution order and caching per the Interfaces block.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd src-tauri && cargo test --locked --lib gcp::auth 2>&1 | tail -3`
Expected: `test result: ok. 9 passed`.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/gcp
git commit -m "feat(gcp): read Google user credentials from gcloud's files and refresh access tokens"
```

---

### Task 3: The IAP tunnel stream with reconnects, and a fake relay for tests

**Files:**
- Create: `src-tauri/src/gcp/iap.rs`, `src-tauri/src/gcp/testing.rs` (`#[cfg(test)]`)
- Modify: `src-tauri/src/gcp/mod.rs` (`pub mod iap;`, `#[cfg(test)] pub mod testing;`)
- Test: `src-tauri/src/gcp/iap.rs` (`mod tests`, each test owns a small tokio runtime like `ssh/testing/proxy.rs` does)

**Interfaces:**
- Consumes: `relay::{Endpoint, Frame, Bookkeeping, encode_*, decode, SUBPROTOCOL, ORIGIN, constants}`, `auth::{TokenSource, Token, AuthError}`.
- Produces, in `gcp::iap`:
  - `pub enum IapError { Credentials(AuthError), Refused { status: u16 }, Closed { code: u16, reason: String }, Protocol(String), Io(String), TimedOut, ReconnectExhausted }` (`Clone, Debug, PartialEq, Eq`).
  - `pub struct Tunnel { pub stream: tokio::io::DuplexStream, pub guard: TunnelGuard }`.
  - `pub struct TunnelGuard` (holds `Option<tokio::task::AbortHandle>`; `pub fn release(self)`; `Drop` aborts the pump when not released).
  - `pub async fn open(endpoint: Endpoint, tokens: Arc<dyn TokenSource>, account: Option<String>, user_agent: String) -> Result<Tunnel, IapError>`: fetches a token on `spawn_blocking`, connects with `tokio_tungstenite::connect_async` and a request carrying `Authorization: Bearer`, `Origin`, `Sec-WebSocket-Protocol`, `User-Agent`; waits for `CONNECT_SUCCESS_SID`; spawns the pump; returns. The caller bounds the whole call with its own timeout (the engine does).
  - `pub const DUPLEX_BUFFER: usize = 64 * 1024`, `pub const RECONNECT_INITIAL: Duration = 1500 ms`, `pub const RECONNECT_MULTIPLIER: f64 = 1.1`, `pub const RECONNECT_CEILING: Duration = 20 s`, `pub const RECONNECT_BUDGET: Duration = 15 min`.
  - The pump (private `async fn pump(...)`): reads the duplex half in ≤ `MAX_DATA_FRAME` chunks, stops reading while `MAX_UNSENT_FRAMES` frames are unsent, sends DATA frames, sends ACKs when `ack_due`, decodes incoming frames (`Data` → write to the duplex; `Ack` → `confirm`; `Unknown` → ignore; a success frame after connect → `DuplicateSuccess` ends the tunnel). On a WebSocket error or close: `4003`, `4033`, and a close during the open end the tunnel; anything else (including `4004`) enters the reconnect loop: sleep per the backoff, fetch a fresh token, `GET reconnect_url(sid, total_received)`, expect `ReconnectSuccess { ack }` → `confirm(ack)`, resend `take_unconfirmed()` first; give up after `RECONNECT_BUDGET` (`ReconnectExhausted`) or on a non-retryable `AuthError`. Ending the tunnel drops the pump's duplex half, so the reader sees EOF.
- Produces, in `gcp::testing` (test-only):
  - `pub struct FakeRelay { pub url_root: String /* ws://127.0.0.1:<port>/v4 */, … }` with `pub fn start(target_port: u16, token: &str) -> FakeRelay`, `pub fn set(&self, behaviour: Behaviour)`, `pub fn connects(&self) -> usize`, `pub fn reconnects(&self) -> usize`, `pub fn last_headers(&self) -> Vec<(String, String)>`.
  - `pub enum Behaviour { Bridge, DropAfter(u64) /* bytes relayed either way, then the socket is cut without a close frame */, CloseWith(u16, &'static str), RefuseHandshake(u16), NeverSucceed /* accepts, sends nothing */ }`.
  - The fake checks `Sec-WebSocket-Protocol`, `Origin` and the bearer token (wrong token → HTTP 401), answers `/v4/connect` with `CONNECT_SUCCESS_SID` (sid = `"sid-<n>"`), bridges DATA frames to a TCP connection to `target_port`, sends ACKs every 32 KiB received, keeps the per-sid TCP connection across a `/v4/reconnect` (answers `RECONNECT_SUCCESS_ACK` with the bytes it received from the client), replays nothing it already delivered. It runs its own single-thread tokio runtime.

- [ ] **Step 1: Write the failing tunnel tests**

Each test starts a `tokio::net::TcpListener` echo server (or a byte-counting sink) on 127.0.0.1, a `FakeRelay` in front of it, and opens the tunnel with `StaticToken` and `url_root: Some(relay.url_root.clone())`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)] async fn bytes_flow_both_ways_through_the_relay() { /* write b"ping" → read b"ping" back from the echo; relay.last_headers() contains ("origin","bot:iap-tunneler"), ("sec-websocket-protocol","relay.tunnel.cloudproxy.app"), ("authorization","Bearer t0k") */ }
#[tokio::test(...)] async fn a_wrong_token_is_refused_with_the_http_status() { /* FakeRelay token "other" → Err(IapError::Refused{status:401}) */ }
#[tokio::test(...)] async fn close_codes_4003_and_4033_end_the_open_with_the_code() { /* CloseWith(4003,"failed to connect to backend") → Err(Closed{code:4003,..}); same for 4033 */ }
#[tokio::test(...)] async fn a_relay_that_never_sends_the_sid_times_out_under_the_callers_timeout() { /* NeverSucceed; tokio::time::timeout(2s, open(..)) → Err(elapsed) */ }
#[tokio::test(...)] async fn a_megabyte_written_across_a_drop_arrives_once_and_in_order() { /* DropAfter(300_000); write 1 MiB of a counter pattern to a sink that records bytes; eventually sink has exactly 1 MiB in order; relay.reconnects() == 1 */ }
#[tokio::test(...)] async fn a_4004_close_is_reconnected_with_a_fresh_token() { /* CloseWith(4004,"reauth") then Behaviour::Bridge on the next connect; a counting TokenSource was asked twice */ }
#[tokio::test(...)] async fn a_transient_token_failure_during_reconnect_is_retried_and_invalid_grant_ends_the_tunnel() { /* TokenSource fails twice with Network then succeeds → tunnel recovers; TokenSource returning SignInExpired → stream read returns 0 within 5 s */ }
#[tokio::test(...)] async fn dropping_the_guard_before_release_aborts_the_pump() { /* open, drop guard, stream read → 0 (EOF) */ }
```

Set `RECONNECT_INITIAL` small in tests through a `#[cfg(test)] pub(crate) fn with_backoff(initial: Duration, ceiling: Duration)` on an `OpenOptions`-style struct or an `AtomicU64` override; the chosen mechanism is the implementer's, but the production constants stay the spec's.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib gcp::iap 2>&1 | tail -3`
Expected: compile errors.

- [ ] **Step 3: Implement `gcp/testing.rs` (fake relay) then `gcp/iap.rs`**

Header of `iap.rs`: ported from gcloud's `iap_tunnel_websocket.py` and `iap_tunnel_websocket_helper.py`, see `NOTICE.md`. Use `tokio_tungstenite::tungstenite::client::IntoClientRequest` on the URL and add headers; `connect_async` returns the response whose status becomes `Refused` on a non-101 (`tungstenite::Error::Http(response)`). Split the socket with `futures_util::StreamExt::split` (add `futures-util = { version = "0.3", default-features = false }` to `Cargo.toml` if not already a direct dependency; it is in the lockfile).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd src-tauri && cargo test --locked --lib gcp::iap 2>&1 | tail -3`
Expected: `test result: ok. 8 passed`.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/gcp
git commit -m "feat(gcp): open IAP TCP-forwarding tunnels over WebSocket with reconnects"
```

---

### Task 4: `Transport` on a hop and the engine's IAP connect path

**Files:**
- Modify: `src-tauri/src/ssh/types.rs:124-170` (`Hop.transport`, `Hop::new` sets `Transport::Tcp`), `src-tauri/src/ssh/mod.rs:22-26` (re-export `Transport, IapTarget`)
- Modify: `src-tauri/src/ssh/russh_engine.rs:54-78` (`EngineOptions.gcp_tokens`, hand-written `Debug`), `:474-486` (`check_chain`), `:509-547` (`connect_hop`), plus a new `fn iap_failure(...)`
- Create: `src-tauri/src/ssh/engine_tests/iap.rs`; Modify: `src-tauri/src/ssh/engine_tests/mod.rs:3-12` (`mod iap;`)
- Test: `src-tauri/src/ssh/types.rs` tests, `src-tauri/src/ssh/engine_tests/iap.rs`

**Interfaces:**
- Produces, in `ssh::types`: `pub enum Transport { Tcp, GcpIap(IapTarget) }`, `pub struct IapTarget { pub project: String, pub zone: String, pub instance: String, pub interface: String, pub account: Option<String>, pub url_root: Option<String> }` (both `Clone, Debug, PartialEq, Eq`), `impl IapTarget { pub fn endpoint(&self, port: u16) -> crate::gcp::relay::Endpoint }`, `Hop.transport: Transport`.
- Produces, in `ssh::russh_engine`: `EngineOptions.gcp_tokens: Option<Arc<dyn crate::gcp::auth::TokenSource>>`, default `Some(Arc::new(FileStore::from_environment()))`; `ConnectError::BadJumpChain { why: "<alias> connects through Google Cloud IAP and cannot be reached through a jump host" }` for a `GcpIap` transport on any hop but the first; `ConnectError::Unreachable { hop, reason }` for `IapError`s with the spec's sentences (`Refused` → "Google Cloud IAP refused the tunnel to `<instance>` (HTTP `<code>`): check that `<account>` has `roles/iap.tunnelResourceAccessor` on the instance, and for production that a PAM grant is active."; `Closed{4003}` → "IAP could not reach port `<port>` on `<instance>`: nothing is listening, or the firewall does not allow `35.235.240.0/20`."; `Closed{4033}` → "`<account>` is not authorized to tunnel to `<instance>` through IAP."; `Closed{4004}` → "IAP asked for a fresh sign-in and the new token was refused."; `Credentials(e)` → `e.to_string()`; other `Closed{code, reason}` → "IAP closed the tunnel to `<instance>` (`<code>`: `<reason>`)."; `Io`/`Protocol` → the text; `gcp_tokens == None` → "Google Cloud credentials are not configured."); `ConnectError::Timeout { phase: Phase::Tcp }` when the open outlives the hop's connect timeout. `<account>` is the token's account, or the target's `account`, or "the active gcloud account".

- [ ] **Step 1: Write the failing type and chain tests**

In `types.rs` tests: `a_new_hop_connects_over_tcp` (`Hop::new(..).transport == Transport::Tcp`) and `an_iap_target_becomes_a_relay_endpoint_with_the_hops_port` (`IapTarget{..}.endpoint(22)` fields). In `engine_tests/iap.rs`:

```rust
fn iap_hop(server: &Server, relay: &FakeRelay, alias: &str, key_id: &str) -> Hop { let mut hop = server.hop(alias, key_id); hop.transport = Transport::GcpIap(IapTarget { project: "eng-dev-396409".into(), zone: "asia-east1-b".into(), instance: "jumpbox".into(), interface: "nic0".into(), account: Some("frank@retower.io".into()), url_root: Some(relay.url_root.clone()) }); hop }
fn engine_with(token: &str) -> RusshEngine { RusshEngine::with_options(EngineOptions { worker_threads: 2, gcp_tokens: Some(Arc::new(StaticToken(token.into()))), ..EngineOptions::default() }) }
#[test] fn a_shell_and_a_command_work_through_the_relay() { /* scratch sshd + FakeRelay::start(sshd.port, "t0k"); exec "echo hop-$((20+22))" → "hop-42"; a shell echoes a typed line */ }
#[test] fn output_survives_a_dropped_websocket() { /* DropAfter(200_000); exec "head -c 1000000 /dev/zero | tr '\0' x" with cap 2 MiB → stdout.len() == 1_000_000 and relay.reconnects() == 1 */ }
#[test] fn a_jump_through_an_iap_first_hop_reaches_a_second_server() { /* Pair-style: hop a via relay, hop b direct via a → exec on b */ }
#[test] fn a_transport_on_a_later_hop_is_a_bad_jump_chain() { /* hops [direct a, iap b] → Err(BadJumpChain{why}) containing "cannot be reached through a jump host" and "b" */ }
#[test] fn close_codes_and_a_refused_handshake_have_their_sentences() { /* 4003 → Unreachable reason contains "could not reach port"; 4033 → "is not authorized"; RefuseHandshake(403) → "(HTTP 403)" and "roles/iap.tunnelResourceAccessor"; wrong token → "(HTTP 401)" */ }
#[test] fn a_relay_that_never_answers_times_out_in_the_tcp_phase_and_leaves_no_task_behind() { /* NeverSucceed, connect_timeout 2 s → Timeout{phase: Tcp}; relay.open_connections() reaches 0 within 3 s (add `pub fn open_connections(&self) -> usize` to FakeRelay) */ }
#[test] fn an_engine_without_a_token_source_says_so() { /* gcp_tokens: None → Unreachable reason "Google Cloud credentials are not configured." */ }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib ssh::engine_tests::iap 2>&1 | tail -3`
Expected: compile errors (`transport` field, `gcp_tokens`).

- [ ] **Step 3: Implement the types, `check_chain`, `connect_hop` and the error mapping**

In `connect_hop`'s `via == None` branch match on `hop.transport`: `Tcp` keeps the existing code; `GcpIap(target)` calls `crate::gcp::iap::open(target.endpoint(hop.port), tokens, target.account.clone(), user_agent).await` inside the existing `tokio::time::timeout(budget, attempt)` (phase stays `Phase::Tcp` until the tunnel is up), then `handshake(tunnel.stream, …)` and `tunnel.guard.release()` after it. The `EngineOptions` `Debug` prints `gcp_tokens: Some("<token source>")`/`None`.

- [ ] **Step 4: Run the engine tests and the russh-boundary test**

Run: `cd src-tauri && cargo test --locked --lib ssh:: 2>&1 | tail -3`
Expected: all pass, including `ssh::tests::russh_is_named_by_russh_engine_rs_and_by_no_other_file` and the new 7.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/ssh
git commit -m "feat(ssh): connect a hop through a Google Cloud IAP tunnel"
```

---

### Task 5: OS Login and PAM REST clients

**Files:**
- Create: `src-tauri/src/gcp/oslogin.rs`, `src-tauri/src/gcp/pam.rs`, `src-tauri/src/gcp/rest.rs`
- Modify: `src-tauri/src/gcp/mod.rs`
- Test: each file's `mod tests` (mockito)

**Interfaces:**
- Produces, in `gcp::oslogin`: `pub struct LoginProfile { pub posix_accounts: Vec<PosixAccount>, pub ssh_public_keys: Vec<String> }`, `pub struct PosixAccount { pub username: String, pub primary: bool, pub operating_system_type: Option<String> }`, `impl LoginProfile { pub fn username(&self) -> Option<&str> /* primary, else first whose type is None or "LINUX" */; pub fn has_key(&self, line: &str) -> bool /* same algorithm and base64 blob, comments ignored */ }`, `pub fn parse_profile(value: &serde_json::Value) -> Result<LoginProfile, GcpError>`, `pub fn key_identity(line: &str) -> Option<(String, String)>`.
- Produces, in `gcp::pam`: `pub struct Grant { pub name: String, pub state: String, pub requested_duration: Option<String>, pub access_grant_time: Option<String> }`, `pub fn parse_grants(value: &serde_json::Value) -> Vec<Grant>`, `pub fn in_flight(grants: &[Grant]) -> Vec<&Grant>` (states `ACTIVE`, `ACTIVATING`, `SCHEDULED`), `pub fn granted_within(grant: &Grant, now: std::time::SystemTime, window: Duration) -> bool` (RFC 3339 `access_grant_time`; parse with a small hand parser or `httpdate`-free arithmetic: `YYYY-MM-DDTHH:MM:SS[.fff]Z` only).
- Produces, in `gcp::rest`: `pub enum GcpError { Auth(AuthError), Denied { api: &'static str, status: u16, account: String }, Http { api: &'static str, status: u16 }, Network(String), Malformed(String) }` (`Clone, Debug, PartialEq, Eq`, `Display`: `Denied` → "`<account>` may not call the <api> API (HTTP <status>)."; `Http` → "The <api> API answered <status>."); `pub trait GcpClient: Send + Sync { fn login_profile(&self, account: Option<&str>, project: &str) -> Result<LoginProfile, GcpError>; fn import_ssh_public_key(&self, account: Option<&str>, project: &str, key_line: &str) -> Result<LoginProfile, GcpError>; fn grants(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str) -> Result<Vec<Grant>, GcpError>; }`; `pub struct RestClient` with `pub fn new(tokens: Arc<dyn TokenSource>) -> RestClient` (bases `https://oslogin.googleapis.com`, `https://privilegedaccessmanager.googleapis.com`) and `pub fn with_bases(tokens, oslogin_base: &str, pam_base: &str) -> RestClient`; requests: `GET {oslogin}/v1/users/{account}/loginProfile?projectId={project}`, `POST {oslogin}/v1/users/{account}:importSshPublicKey?projectId={project}` with body `{"key": "<line>"}` (response `loginProfile`), `GET {pam}/v1/projects/{project}/locations/{location}/entitlements/{entitlement}/grants:search?callerRelationship=HAD_CREATED&pageSize=50`; 401/403 → `Denied`; the account in `Denied` is the token's.

- [ ] **Step 1: Write the failing tests**

```rust
// oslogin
#[test] fn the_username_is_the_primary_posix_account_else_the_first_linux_one() { /* fixtures with primary=false LINUX + primary=true; with WINDOWS first then LINUX; empty → None */ }
#[test] fn a_key_is_recognised_by_algorithm_and_blob_whatever_the_comment() { /* "ssh-ed25519 AAAA… frank@retower.pub" vs "ssh-ed25519 AAAA…" → has_key true; different blob → false */ }
#[test] fn a_login_profile_is_fetched_with_the_project_and_the_bearer_token() { /* mockito GET /v1/users/frank%40retower.io/loginProfile?projectId=eng-dev-396409 matching header authorization "Bearer t0k" → profile JSON with posixAccounts and sshPublicKeys map → username "frank_retower_io" */ }
#[test] fn a_key_import_posts_the_line_and_returns_the_profile() { /* POST …:importSshPublicKey?projectId=… body {"key":"ssh-ed25519 AAAA…"} → {"loginProfile":{…}} */ }
#[test] fn a_403_is_denied_naming_the_account_and_api() { /* → Denied{api:"OS Login",status:403,account:"frank@retower.io"} */ }
// pam
#[test] fn grants_are_searched_as_the_caller_created_them_and_filtered_here() { /* GET …/entitlements/prod-operate/grants:search?callerRelationship=HAD_CREATED&pageSize=50 → grants with states ENDED, ACTIVE, SCHEDULED → in_flight has 2 */ }
#[test] fn a_grant_active_for_under_two_minutes_is_recent() { /* accessGrantTime now-60s → true; now-600s → false; missing → false */ }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib 'gcp::' 2>&1 | tail -3`
Expected: compile errors in the new modules.

- [ ] **Step 3: Implement `oslogin.rs`, `pam.rs`, `rest.rs`**

One `reqwest::blocking::Client` (20 s timeout, the Lunport user agent) in `RestClient`; the account path segment is percent-encoded with `url::form_urlencoded::byte_serialize` (`@` → `%40`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd src-tauri && cargo test --locked --lib 'gcp::' 2>&1 | tail -3`
Expected: `test result: ok` with the 7 new tests.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/gcp
git commit -m "feat(gcp): add OS Login profile and PAM grant clients"
```

---

### Task 6: The `transport:<host-id>` record

**Files:**
- Create: `src-tauri/src/sync/transports.rs`, `src-tauri/src/sync/transports_tests.rs`
- Modify: `src-tauri/src/sync/mod.rs:83` (`pub mod transports;`), `src-tauri/src/sync/records_v3/types.rs:3-14` (`pub const TRANSPORT_STATE_VERSION: u32 = 9;`), `src-tauri/src/sync/records_v3/state.rs:62` (`pub transports: BTreeMap<String, LocalRecord>` after `tunnel_rules`), `:149` and `:291` (add `TRANSPORT_STATE_VERSION` to both version arms), `:360-366` (mirror the tunnel checks for `transports`)
- Test: `src-tauri/src/sync/transports_tests.rs`

**Interfaces:**
- Produces, in `sync::transports`:
  - `pub const PREFIX: &str = "transport:"`, `pub const STATE_VERSION: u32 = records_v3::TRANSPORT_STATE_VERSION`.
  - `pub struct HostTransport { pub host_id: String, pub kind: TransportKind }` and `#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)] pub enum TransportKind { GcpIap { project: String, zone: String, instance: String, #[serde(default = "default_interface")] interface: String, #[serde(default)] account: Option<String>, #[serde(default)] os_login: bool, #[serde(default)] pam: Option<PamCheck> } }`, `pub struct PamCheck { pub entitlements: Vec<String>, #[serde(default = "default_location")] pub location: String }`; all `Clone, Debug, PartialEq, Eq, Serialize, Deserialize`, `deny_unknown_fields`, `#[cfg_attr(test, derive(ts_rs::TS))]` + `ts(export, export_to = "../../src/bindings/")`.
  - `impl HostTransport { pub fn validate(&self) -> Result<(), String> }`: host id `is_host_id`; project `^[a-z][a-z0-9-]{4,28}[a-z0-9]$` or 6–20 digits; zone and instance `^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`; interface `^nic[0-7]$`; account, when set, has one `@`, no whitespace or control characters, ≤ 254 chars; `pam` entitlements 1–8 ids matching `^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`, location `global` or a region name of the same shape. Messages are one sentence each ("Enter the Google Cloud project id.", …).
  - `pub(crate) struct Payload { pub schema: u32, pub transport: HostTransport }`; `pub fn is_id(id: &str) -> bool`, `pub fn wire_id(host_id: &str) -> String`, `pub fn decode(record: &Record) -> Option<HostTransport>` (schema 1, `wire_id(host_id) == record.id`, validates), `pub fn valid(record: &Record) -> bool` (as `tunnel_rules::valid`), `pub fn view(state: &SyncStateV3) -> Vec<HostTransport>`, `pub fn get(state: &SyncStateV3, host_id: &str) -> Option<HostTransport>`, `pub fn set(state: &SyncStateV3, host_id: &str, expected: Option<&HostTransport>, transport: Option<HostTransport>, now: u64) -> Result<SyncStateV3, RepositoryError>` (compare-and-set against `get`; writes `next.local.transports` only; `None` writes a tombstone record; `next.version = next.version.max(STATE_VERSION)`), `pub fn has_data(state: &SyncStateV3) -> bool`.
  - Transports are device-local, so `set` never consults the account: no `account_writes_blocked` check, no opaque-shadow check (documented in the module header).

- [ ] **Step 1: Write the failing tests**

`transports_tests.rs` (reuse `tunnel_rules_tests::state()` by `pub(super)` visibility or copy the one-line fixture):

```rust
fn iap(host: &str) -> HostTransport { HostTransport { host_id: host.into(), kind: TransportKind::GcpIap { project: "eng-dev-396409".into(), zone: "asia-east1-b".into(), instance: "jumpbox".into(), interface: "nic0".into(), account: Some("frank@retower.io".into()), os_login: true, pam: None } } }
#[test] fn a_saved_transport_is_read_back_by_host_and_raises_the_state_version() { /* set(&state(), A, None, Some(iap(A)), 1) → get == Some(iap(A)); version == 9; view().len() == 1 */ }
#[test] fn saving_requires_the_displayed_value() { /* set with expected None when one exists → Err; expected Some(old) → Ok */ }
#[test] fn deleting_leaves_a_tombstone_and_no_view() { /* set(.., Some(&iap(A)), None, 2) → get None; local.transports has 1 tombstone record with deleted true */ }
#[test] fn an_empty_map_leaves_the_version_alone_and_a_populated_one_needs_version_9() { /* state() version 4 validates; a state with a transport and version 8 → validate_state Err; version 9 → Ok */ }
#[test] fn validation_rejects_bad_fields() { /* project "Eng", zone with spaces, interface "eth0", account "frank", 9 entitlements, location "Global" → Err each */ }
#[test] fn a_payload_with_an_unknown_field_or_schema_is_not_decoded() { /* schema 2 → None; extra field → None */ }
#[test] fn ts_bindings_are_exported() { /* the ts-rs derive's export test: assert that running the test wrote src/bindings/HostTransport.ts, TransportKind.ts, PamCheck.ts (ts_rs::TS::export_all) */ }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib sync::transports 2>&1 | tail -3`
Expected: compile errors.

- [ ] **Step 3: Implement the module and the state plumbing**

Module header: "Device-local for now: the record shape and wire id are the ones a later sync step will publish; see the spec's Storage section." `state.rs` validation mirrors lines 360–366 for `transports` with the error labels `"transport"`.

- [ ] **Step 4: Run the sync tests that touch state decoding**

Run: `cd src-tauri && cargo test --locked --lib sync::transports sync::records_v3 sync::tunnel_rules 2>&1 | tail -3`
Expected: all pass; `git status --short src/bindings` shows `HostTransport.ts`, `TransportKind.ts`, `PamCheck.ts` added.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/sync src/bindings/HostTransport.ts src/bindings/TransportKind.ts src/bindings/PamCheck.ts
git commit -m "feat(records): store a device-local transport record per host"
```

---

### Task 7: The directory maps transports onto hops and prepares OS Login and PAM

**Files:**
- Modify: `src-tauri/src/session/directory.rs:20-52` (`DirectoryError::Denied(String)`, `Display`), `:52-95` (`HostDirectory::prepare` default)
- Modify: `src-tauri/src/session/record_directory.rs:36-43` (`gcp: Option<Box<dyn GcpClient>>`), `:81-95` (`pub(crate) fn with_gcp`), `:144-237` (transport lookup), `:239-247` (`impl HostDirectory`: `prepare`)
- Modify: `src-tauri/src/session/connect.rs:196-200` (call `prepare`), `:162-164` (`directory_failure`: `Denied` → `kinds::AUTH`)
- Modify: `src-tauri/src/session/app.rs:140` (`.with_gcp(Box::new(RestClient::new(Arc::new(FileStore::from_environment()))))`)
- Test: `src-tauri/src/session/record_directory_tests.rs`, `src-tauri/src/session/connect.rs` tests

**Interfaces:**
- Consumes: `transports::get`, `gcp::rest::GcpClient`, `gcp::oslogin::LoginProfile`, `gcp::pam::{in_flight, granted_within}`, `ssh::{Transport, IapTarget}`.
- Produces: `DirectoryError::Denied(String)` ("the account may not connect: no PAM grant, OS Login refused"); `trait HostDirectory { … fn prepare(&self, _target: &mut Target, _public_key: &dyn Fn(&str) -> Option<String>, _cancel: &super::connect::CancelToken) -> Result<(), DirectoryError> { Ok(()) } }`; `RecordDirectory::with_gcp(mut self, client: Box<dyn GcpClient>) -> Self`; `resolve_material` sets `hops[0].transport = Transport::GcpIap(IapTarget { project, zone, instance, interface, account, url_root: None })` from `transports::get(&state, host_id)` and returns `DirectoryError::Unsupported(format!("{alias} connects through Google Cloud IAP and cannot be reached through a jump host."))` when a later hop has one; `prepare` for a first hop with `GcpIap`: (1) PAM when `pam` is set: `grants` for each entitlement; none `in_flight` → `Denied("No active Privileged Access Manager grant for <entitlements joined by \" or \"> on <project>. Request one (scripts/prod-access.sh operate --reason \"…\") and connect again.")`; (2) OS Login when `os_login`: `login_profile(account, project)`; `username()` → `hop.user`, `None` → `Denied("OS Login has no POSIX account for <account>; ask an administrator to enable OS Login for the project.")`; when `hop.auth` is `Key { key_id }` and `public_key(key_id)` is `Some(line)` and `!profile.has_key(&line)` → `import_ssh_public_key(account, project, &line)`; `GcpError` → `Denied(error.to_string())`; `cancel.is_cancelled()` between steps → `Failed("The connection was cancelled.")`. The `Connector` calls `self.directory.prepare(&mut target, &|key_id| self.keys.key(key_id).map(|key| key.public_key), cancel).map_err(directory_failure)?` right after `resolve`.

- [ ] **Step 1: Write the failing directory tests**

In `record_directory_tests.rs` (a `FakeGcp` implementing `GcpClient` with scripted answers and recorded calls):

```rust
#[test] fn a_transport_on_the_first_hop_becomes_an_iap_target() { /* state with host GATE + transports::set(.., GATE, ..) → resolve(GATE).hops[0].transport == GcpIap(IapTarget{project:"eng-dev-396409",…,account:Some("frank@retower.io"),url_root:None}) */ }
#[test] fn a_transport_on_a_jump_target_is_refused() { /* WEB jumps via GATE; transport on WEB → Err(Unsupported(text)) with "web connects through Google Cloud IAP and cannot be reached through a jump host." */ }
#[test] fn prepare_takes_the_os_login_username_and_imports_a_missing_key() { /* os_login true, auth Key k1 with public line L; FakeGcp profile username "frank_retower_io", keys [] → hop.user == "frank_retower_io"; import called once with (Some("frank@retower.io"), "eng-dev-396409", L) */ }
#[test] fn prepare_skips_the_import_when_the_key_is_registered() { /* keys [L + " comment"] → no import call */ }
#[test] fn prepare_refuses_without_an_in_flight_pam_grant_and_passes_with_one() { /* pam Some(["prod-operate","prod-admin"], "global"); grants ENDED only → Err(Denied(text)) containing "No active Privileged Access Manager grant for prod-operate or prod-admin on knowknow-prod"; grants ACTIVE → Ok */ }
#[test] fn prepare_does_nothing_for_a_direct_host_and_without_a_client() { /* no transport → FakeGcp never called; RecordDirectory without with_gcp and a transport with os_login → Err(Failed("Google Cloud access is not configured in this build.")) */ }
```

In `connect.rs` tests: `the_connector_prepares_the_target_before_unlocking_it` with a `FakeDirectory` subclass or a wrapper directory whose `prepare` records the call and sets `hops[0].user = "prepared"`; assert the engine saw `user == "prepared"`. `a_denied_preparation_is_an_auth_failure` → `ConnectFailure.kind == kinds::AUTH`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib session::record_directory_tests session::connect 2>&1 | tail -3`
Expected: compile errors (`prepare`, `with_gcp`, `Denied`).

- [ ] **Step 3: Implement**

`grep -rn "DirectoryError::" src/` for exhaustive matches on the enum and add the `Denied` arm wherever one exists. In `app.rs` build the `RestClient` over a `FileStore` once per `record_directory(app)` call.

- [ ] **Step 4: Run the session tests**

Run: `cd src-tauri && cargo test --locked --lib session:: 2>&1 | tail -3`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/session
git commit -m "feat(session): resolve IAP transports, OS Login users and PAM grants before connecting"
```

---

### Task 8: Tauri commands and the frontend API

**Files:**
- Create: `src-tauri/src/session/transports.rs`
- Modify: `src-tauri/src/session/mod.rs:39-41` (`pub mod transports;`), `src-tauri/src/lib.rs:417-421` (register `session::transports::transports_save`, `transports_delete`), `src-tauri/src/sync/record_commands.rs:103-127` and `:154-230` (`RecordOverview.transports: Vec<HostTransport>` from `transports::view`)
- Create: `src/lib/transports.ts`; Modify: `src/lib/records.ts:63-80,130-215` (`RecordOverview.transports?: HostTransport[]`), `src/components/records/fixtures.ts` (`transports: []` default)
- Test: `src-tauri/src/session/transports.rs` `mod tests` (the `edit` helper against an in-memory state, as `tunnels.rs:433-510` does), `src/lib/transports.test.ts`

**Interfaces:**
- Produces: `#[tauri::command] pub async fn transports_save(app, window, transport: HostTransport, expected: Option<HostTransport>) -> Result<RecordOverview, String>` and `transports_delete(app, window, expected: HostTransport) -> Result<RecordOverview, String>`, main window only (`main_only` as in `tunnels.rs:250`), through `crate::sync::record_commands::edit_records` with `transports::set`, returning the overview `edit_records` returns.
- Produces, in `src/lib/transports.ts`: `export type { HostTransport, TransportKind, PamCheck } from "@/bindings/…"`, `export const saveTransport = (transport: HostTransport, expected: HostTransport | null) => tauriInvoke<RecordOverview>("transports_save", { transport, expected })`, `export const deleteTransport = (expected: HostTransport) => tauriInvoke<RecordOverview>("transports_delete", { expected })`, `export function newIapTransport(hostId: string): HostTransport` (project/zone/instance "", interface "nic0", account null, os_login true, pam null), `export function transportFor(overview: RecordOverview, hostId: string | null): HostTransport | null`, `export function transportLabel(t: HostTransport): string` ("Google Cloud IAP · <project> / <zone> / <instance>"), `export function transportProblem(t: HostTransport): string | null` (the same rules as `HostTransport::validate`, same sentences), `export const pamDefaults = { entitlements: ["prod-operate", "prod-admin"], location: "global" }`.

- [ ] **Step 1: Write the failing tests**

Rust: `saving_then_deleting_a_transport_through_edit_returns_the_new_view` (as `tunnels.rs` tests do with `transports::set`). TS (`src/lib/transports.test.ts`): `transportFor finds the host's transport or null`, `transportProblem mirrors the backend rules` (project "Eng" → "Enter the Google Cloud project id."; interface "eth0" → "Enter a network interface such as nic0."), `saveTransport invokes transports_save with the expected value` (`stubBackend`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd src-tauri && cargo test --locked --lib session::transports 2>&1 | tail -3` and `pnpm test src/lib/transports.test.ts`
Expected: compile error / module not found.

- [ ] **Step 3: Implement the commands, the overview field and the TS module**

- [ ] **Step 4: Run the tests**

Run: `cd src-tauri && cargo test --locked --lib session::transports sync::record_commands 2>&1 | tail -3`; `pnpm test src/lib`
Expected: pass; `pnpm build` type-checks (`tsc`).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/session src-tauri/src/lib.rs src-tauri/src/sync/record_commands.rs src/lib/transports.ts src/lib/transports.test.ts src/lib/records.ts src/components/records/fixtures.ts
git commit -m "feat(records): save and delete host transports from the app"
```

---

### Task 9: The host editor's "Connect through" section

**Files:**
- Create: `src/components/records/TransportSection.tsx`, `src/components/records/transport.test.tsx`
- Modify: `src/components/records/HostEditor.tsx:91-113` (state `transportDraft`), `:139-171` (`save`: transport after the host), `:376-390` (Username field disabled with the OS Login note when the draft has `os_login`), after `:548` (`</details>` of Advanced SSH settings: render `<TransportSection …/>`), `:665-680` (`dirty` includes the draft)
- Modify: `src/components/records/HostPreview.tsx:73-85` (`field("Connect through", transportLabel(t))` when a transport exists)
- Test: `src/components/records/transport.test.tsx`

**Interfaces:**
- Consumes: `src/lib/transports.ts` from Task 8.
- Produces: `export function TransportSection({ hostId, value, onChange, disabled }: { hostId: string | null; value: HostTransport | null; onChange: (next: HostTransport | null) => void; disabled: boolean })`: a `FormSection` titled "Connect through" with a `<select aria-label="Connect through">` (`direct` | `gcp_iap`); for `gcp_iap`, `RecordField`s "Project", "Zone", "Instance", "Network interface", "Google account" (placeholder "gcloud's active account"), checkbox "Use the OS Login username", checkbox "Require an active PAM grant" revealing "Entitlements (comma-separated)" and "Location"; the validation sentence from `transportProblem` under the fields. In `HostEditor`: `const [transportDraft, setTransportDraft] = useState<HostTransport | null | undefined>(undefined)` (undefined = untouched); `dirty = state.dirty || passwordChange !== null || transportDraft !== undefined`; `save` after the host is saved and `id` is known: `const saved = transportFor(accepted, id)`; `transportDraft === null && saved → accept(await deleteTransport(saved))`; `transportDraft && → accept(await saveTransport({ ...transportDraft, host_id: id }, saved))`; then `setTransportDraft(undefined)`. The Save button is also disabled when `transportDraft && transportProblem(transportDraft)`.

- [ ] **Step 1: Write the failing tests**

`transport.test.tsx` (render with `renderToStaticMarkup` as `groups.test.tsx` does):

```ts
it("shows the IAP fields and the OS Login username note", () => { /* markup of RecordHostEditor with overview.transports [iap for host] contains "Connect through", "eng-dev-396409", and the Username input is disabled with text "Username comes from OS Login" */ });
it("saves the transport after the host with the displayed value as expected", async () => { /* stubBackend records calls; simulate save() through the editor's exported helper `saveHostAndTransport(state, draft, saved)` (export it from HostEditor.tsx or editor.ts) → calls[0][0] === "records_host_update", calls[1] === ["transports_save", { transport: {...draft, host_id}, expected: saved }] */ });
it("deletes the transport when Direct is chosen", async () => { /* draft null, saved present → ["transports_delete", { expected: saved }] */ });
it("keeps the Save button disabled while the transport is invalid", () => { /* draft with project "" → markup has the Save button disabled and the sentence "Enter the Google Cloud project id." */ });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm test src/components/records/transport.test.tsx`
Expected: FAIL (missing module / markup).

- [ ] **Step 3: Implement `TransportSection.tsx` and the `HostEditor`/`HostPreview` changes**

Extract the post-save transport step into `export async function saveTransportDraft(id: string, draft: HostTransport | null | undefined, overview: RecordOverview): Promise<RecordOverview | null>` in `src/components/records/editor.ts` so the test can drive it without React effects.

- [ ] **Step 4: Run the frontend suite and the type check**

Run: `pnpm test` and `pnpm build`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add src/components/records src/lib
git commit -m "feat(ui): choose a Google Cloud IAP transport in the host editor"
```

---

### Task 10: Documentation

**Files:**
- Modify: `docs/usage.md:43-66` (new subsection "Google Cloud IAP and OS Login" after the `ProxyJump` paragraph), `docs/development.md:33-45` (a "Google Cloud IAP" paragraph after "SSH forwarding": the `gcp` module, the fake relay, `cargo test --locked --lib gcp:: ssh::engine_tests::iap`, the Apache notice, that transports are device-local for now)
- Test: none (prose); `git diff --check`

- [ ] **Step 1: Write the usage subsection**

Cover: choosing **Connect through → Google Cloud IAP tunnel** in the host editor and the fields; that credentials come from `gcloud auth login` (which account, where the files are, `CLOUDSDK_CONFIG`); OS Login username and key registration; the PAM check and the sentence it shows; that a transport is saved per device for now; the firewall note (`35.235.240.0/20`) and that the port is the host's port.

- [ ] **Step 2: Write the development paragraph and run the checks**

Run: `git diff --check && pnpm build`
Expected: no output from `git diff --check`; build succeeds.

- [ ] **Step 3: Commit**

```bash
git add docs/usage.md docs/development.md
git commit -m "docs: describe Google Cloud IAP transports and OS Login"
```

---

### Task 11: Whole-branch verification

- [ ] **Step 1: Run the complete safe suites**

Run: `cd src-tauri && cargo test --locked --lib -- --test-threads=2 --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none --skip ssh::engine_tests::login_methods::pam 2>&1 | tail -5` and `cargo test --locked --test app_profile_build 2>&1 | tail -3`, then `pnpm test 2>&1 | tail -5` and `pnpm build`.
Expected: all pass (the engine tests print "skipped" only where OpenSSH tools are missing).

- [ ] **Step 2: Clippy on the new code**

Run: `cd src-tauri && cargo clippy --locked --tests 2>&1 | grep -E "src/gcp|transports|iap" | head`
Expected: no warnings in the new files.

- [ ] **Step 3: Push the branch**

```bash
git push -u origin claude/project-thread-whbjuy
```
