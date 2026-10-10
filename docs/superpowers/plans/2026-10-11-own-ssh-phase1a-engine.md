# Own SSH client — phase 1a: the engine inside the app — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sshelter_lib` contains a tested SSH engine behind the spec's `SshEngine`/`Session` traits — russh 0.64.1 in exactly one file, the scratch-sshd test harness in the app's test support code, integration tests that cover spec §12 (including the ones the phase-0 spike could not run), CI on macOS, Linux and Windows — and the throwaway `spike/` crate is gone. The app itself behaves exactly as today: the engine sits unused inside the library until plans 1b–1d consume it.

**Architecture:** A new module `src-tauri/src/ssh/` holds plain data types, errors and the five synchronous traits of spec §6.1 (no russh in them), a bounded output queue, a scripted `FakeEngine` for the later plans' tests, and `russh_engine.rs`, the only file that names russh. `RusshEngine` owns a small multi-thread tokio runtime and `block_on`s into it; the caller's borrowed `&dyn HostKeyPolicy`/`&dyn AuthSource` never leave the thread blocked in `connect` (host-key questions travel over a channel to that thread, signatures are made inline), and one `Connection` owns every hop of a jump chain. The test support (`ssh/testing/`, `ssh/engine_tests/`) is `#[cfg(test)]` code: a harness that starts a scratch `sshd` per test through `crate::process`, a TCP proxy that misbehaves on demand, doubles for the broker's policy and auth source over the real key vault, and an in-process russh server for the password and keyboard-interactive logins that a PAM-less sshd cannot do (a Docker container with a real PAM sshd runs the same tests in the Linux CI job).

**Tech Stack:** Rust 2021 (rustc 1.98 here; russh needs 1.89), russh `=0.64.1` (tokio, aws-lc-rs, `ssh-key =0.7.0-rc.11` next to the vault's `ssh-key` 0.6.7), tokio 1.52 (`rt-multi-thread`, `macros`, `net`, `io-util`, `time`, `sync`), the app's key vault (`vault::material`) behind `AuthSource::sign`, OpenSSH `sshd`/`ssh`/`ssh-keygen` as scratch servers, GitHub Actions (`macos-latest`, `ubuntu-latest` with an Ubuntu 24.04 PAM container, `windows-latest`), and a few small Python 3 snippets (the lock-file delta of Task 1, the two one-line edits of the mutation check in Task 7).

**Spec:** docs/superpowers/specs/2026-10-10-own-ssh-client-design.md (§4, §6, §11, §12, §15, §16) and docs/superpowers/specs/2026-10-10-own-ssh-spike-report.md

## Global Constraints

- **Where.** Repository `/Users/ysya/project/sideproj/sshelter`, branch `next/own-ssh` (planned at HEAD 1364716, from main f84c64c). Every task ends with a commit on that branch; nothing is pushed.
- **Starting state.** Branch `next/own-ssh` at 1364716 (or a later commit that changes documents only), `git status --short` prints nothing, and the whole lib suite passes with 1417 tests before this plan adds any.
- **Toolchain.** Every cargo command is prefixed `PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH` (Homebrew's cargo is broken on this machine; that toolchain is rustc/cargo 1.98.0, and russh 0.64.1 needs 1.89 or newer). It ships no clippy and no rustfmt, so the style is kept by hand: the code in this plan and the existing files (long lines, about 150 columns) are the reference.
- **The app's Rust tests.** From `src-tauri/`, exactly one `--`, all filters after it: `PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- <filters>`. A whole-suite run adds the two skips `--skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain` (they touch the real Keychain). Where a scratch sshd is needed the commands below put `SSHELTER_REQUIRE_OPENSSH=1` in front, so that missing OpenSSH tools fail the run instead of silently skipping tests.
- **Lock file.** `russh = "=0.64.1"`, exact. `src-tauri/Cargo.lock` is regenerated once, in Task 1 (`cargo metadata --offline`), and checked there with the lock-delta script. From then on every cargo command runs `--offline --locked` (CI runs `--locked`), and `git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock` must print nothing at the end of every later task. The whole lib suite stays green under the new lock, `vault::` in particular (zeroize moves from 1.8.2 to 1.9.1).
- **russh in one file.** Only `src-tauri/src/ssh/russh_engine.rs` names russh (spec §1 goal 5: the engine can be replaced one day); `ssh::tests::russh_is_named_by_russh_engine_rs_and_by_no_other_file` (Task 7) fails otherwise. No russh type appears in `types.rs`, `error.rs`, `traits.rs`, `channel.rs`, `fake.rs` or `testing/`; the in-process test server lives inside `russh_engine.rs` for that reason.
- **Nothing else changes.** Outside `src-tauri/src/ssh/` this plan edits `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, one line of `src-tauri/src/lib.rs` (`pub mod ssh;`), the workflows under `.github/workflows/`, the PAM container files under `src-tauri/tests/pam-sshd/`, one line of the design spec (Task 14) and the deletion of `spike/`. `vault/` is never modified; `agent/`, `config/`, `ipc/`, `mcp.rs`, `sync/` and the frontend are not touched.
- **Isolation.** Tests never touch the real `~/.ssh`, the Keychain, the running agent or the app's data directory, and never contact a real host. A scratch sshd lives in a temp directory on 127.0.0.1, logs in only the user running the tests and has `PermitUserRC no`; the system `ssh` the harness runs gets `-F /dev/null`. Never launch the app, never run `pnpm`/`npm`, never push.
- **A test that fails once.** The engine tests start real servers, and some wait for log lines or for intervals. Before this plan was written the final code was run 30 times in a row (the engine tests alone) and 4 times inside the whole suite on a loaded machine (load average 8 to 10 on 18 cores) without a failure; the three causes of intermittent failures that turned up are fixed in the code below (Task 5: keys the vault cannot read; Task 7: an engine dropped under a live connection; Task 9: leaving sshd too early). If a test that passed before fails once, run it alone three times (`... -- --exact <full test path>`, one `--`) before suspecting the code: three failures in three are real; one in three is a timing problem to report, and longer waits are not the answer.
- **Spawning.** `src-tauri/clippy.toml` forbids `std::process::Command::spawn`, `output` and `status`: code in `src-tauri/` starts processes with `crate::process::spawn` (the harness does; there is no clippy on this machine, so Task 14 greps for a direct call instead).
- **Commits.** Conventional commits in English, no attribution lines, files staged by path (never `git add -A`).
- **Comments.** The new files are commented in English, like `mcp.rs`, `config/` and the workflows; the Traditional Chinese rule of `agent/`, `sync/`, `vault/` and `ipc/` is not applied to `ssh/` (one of the decisions listed under "Decisions to confirm" at the end of this plan).
- **Reading the code blocks.** "Create" means a new file with exactly that content. "Insert above the `#[cfg(test)]` line" means the block goes at the very top of the file, followed by one empty line, in front of the tests that were written first. A `diff` block is a unified diff against the file as the earlier steps left it and is the complete change: run it from the repository root with `git apply` (paste it between `git apply <<'PATCH'` and `PATCH`) or make the same edits by hand.
- **Spec §6.1, as written.** `SshEngine::connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError>`; `Session::{shell(Pty) -> Result<Box<dyn ShellChannel>, SessionError>, exec(&str, Duration, output_cap: usize) -> Result<ExecResult, SessionError>, is_alive() -> bool, disconnect_reason() -> Option<DisconnectReason>, close()}`; `ShellChannel::{write, read, window_change, exited() -> Option<Exit>, close}`; `HostKeyPolicy::check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict`; `AuthSource::{sign(key_id, data, rsa_hash: Option<RsaHash>), password(hop) -> Option<Secret>, interactive(hop, prompts, deadline: Instant) -> Option<Vec<Secret>>}`; `Target { hops: Vec<Hop> }`; `Hop { id, alias, hostname, port, user, auth: AuthMethod, pinned: Option<HostKey>, connect_timeout, keepalive_every, keepalive_max_missed, nodelay }`; `HostKey { algorithm, public_key, fingerprint }`; `ConnectError::{BadJumpChain, Unreachable, Timeout{hop,phase}, HostKeyUnknown{hop,key}, HostKeyMismatch{hop,key,pinned}, NoCommonHostKeyAlgorithm{hop,ours,theirs}, AuthFailed{hop,tried,reason}, AuthAbandoned{hop,reason}, Protocol{hop,text}}`; `ExecResult { ended, exit_code, signal, stdout, stderr, truncated }`; `Ended::{Exited, Signaled, TimedOut, Disconnected}`; `Exit::{Code(u32), Signal(String), Disconnected}`. Three additions, listed in Task 2: `ShellChannel` is `Send + Sync`, `AuthSource` has `public_key(&self, key_id: &str) -> Option<String>` (both forced by russh), and `Ended` has a fifth variant, `Truncated`, for a command stopped at the output cap.
- **Timeouts and keepalive (spec §6.2).** TCP plus handshake of every hop is wrapped in `tokio::time::timeout(connect_timeout)`; every `authenticate_*` call is wrapped too; the wait for a keyboard-interactive answer is 4 × `connect_timeout`, at least 60 s. Keepalive is set explicitly from the host record (russh's default is off) and a dead link is noticed after (`keepalive_max_missed` + 1) × `keepalive_secs`. Defaults of a host record (spec §5.1): `connect_timeout_secs` 15, `keepalive_secs` 30, `keepalive_max_missed` 3.
- **Host keys (spec §6.2 step 3).** `check_server_key` never waits for a person: for `Unknown` and `Mismatch` the handler records the key and returns `false`, `connect` fails with `HostKeyUnknown`/`HostKeyMismatch` carrying the observed key, and the caller pins and connects again. A pinned host restricts `Config::preferred.key` to the pinned key's algorithm family.
- **Login (spec §6.2 step 4, §6.3 b).** The sequence is public key, password, keyboard-interactive, starting at `Hop::auth`; only a server refusal moves to the next method on the same connection. A signer error, an overdue or cancelled prompt, or a wrong number of answers drops the connection (`AuthAbandoned`); the engine never signs RSA with SHA-1 (an RSA key with no hash to use is refused without calling `AuthSource::sign`).
- **Algorithms (spec §6.3).** russh's defaults minus `ssh-rsa` (SHA-1) in `Config::preferred.key` (`Preferred::DEFAULT.key` without `Rsa { hash: None }`); no `sk-*` keys; no agent forwarding.
- **Channels (spec §6.3).** Every channel has its own reader task (a channel nobody reads stalls the whole connection); shell output goes through a bounded queue; exec output has a cap, reaching it closes the channel and the connection stays usable; `nodelay = true` on shell connections (jump sockets are set by the engine); output is raw bytes, never assuming `\n`.
- **Error text (spec §11).** `Display` of `ConnectError` is the sentence the user sees: `Could not reach {hostname}:{port} ({reason}).`, `Authentication failed for {user}@{alias} (tried: publickey, password).`, `Authentication for {alias} was abandoned ({reason}).`, `The host key of {alias} changed. Connection refused.`, `SSH error: {text}`; none of them carries a key or a password. The sentences that need `{n}` seconds or "while the command was running" are composed by the broker (plan 1b) from `Session::disconnect_reason` and `ExecResult`.
- **Facts checked on 2026-10-11 (they replace the corresponding wording of the spec).** (1) `src-tauri/Cargo.toml` has no direct tokio dependency (Tauri brings tokio 1.52.3 into the lock); Task 1 adds it with the features the engine uses. (2) The cargo registry on this machine already holds russh 0.64.1 and its dependencies (the phase-0 spike downloaded them), so `cargo metadata --offline` resolves the new lock without the network. (3) In `src-tauri/Cargo.lock` the russh dependencies add 92 package entries and replace nine versions — `zeroize` 1.8.2 → 1.9.1 **and** the eight `futures-*` crates 0.3.32 → 0.3.34 — where the spike report counted only zeroize (it measured the spike's own lock). (4) The one compiler warning in a test build, `function set_host_enabled is never used` in `src/config/edit.rs`, is old and is not this plan's; no task adds a warning. (5) A scratch sshd runs as a normal user on this Mac (OpenSSH 10.3p1) and offers public keys only; password and keyboard-interactive logins need PAM (the in-process server of Task 11 and the container of Task 12). (6) `ssh-key` 0.6.7, the vault's parser, cannot read about 1 in 256 of the ECDSA P-256 private keys that OpenSSH writes (Task 5 explains; the test harness works around it, the vault is not touched). (7) russh 0.64.1 asks the host-key question once, in the first key exchange, and never again in a rekey (measured; Tasks 7 and 8).

## Review Focus

The input classes and failure modes the spec implies that no happy path exercises, most likely first. Each has a test in the task named after it.

1. **A server that goes silent** (firewall DROP, a VPN that is down, a half-dead host) during the handshake or in the middle of the login: the user expects the failure to name the phase and to arrive after `connect_timeout`, with no thread left waiting and no socket left open. Pinned in Task 7: `a_handshake_that_never_gets_an_answer_times_out_after_the_connect_timeout` and `a_server_that_stops_answering_during_the_login_times_out_in_the_auth_phase`.
2. **A terminal that stops reading** (a paused or slow window) while the connection also carries other work: the user expects the connection and the other shells to stay responsive, memory to stay bounded, and the missing output to be announced in the stream rather than lost silently. Pinned in Task 3: `a_full_queue_drops_new_chunks_and_counts_them_instead_of_waiting` and `closing_announces_a_gap_that_nothing_followed_and_then_reports_closed`; in Task 8: `a_reader_that_stops_reading_does_not_hold_up_the_connection_and_the_gap_is_announced`.
3. **A command whose output is exactly the cap, far beyond it, or that never ends**: the user expects `truncated` to be true only when something was left unread, a command stopped at the cap to be reported as `Truncated` and never as a lost connection, the timeout to cut a command that outlives it, and the connection to be usable afterwards in every case. Pinned in Task 8: `output_that_exactly_fills_the_cap_is_not_truncated`, `output_beyond_the_cap_is_cut_off_and_the_connection_survives` and `a_command_that_outlives_its_timeout_is_cut_and_the_connection_survives`.
4. **A jump chain whose second hop presents an unknown key, has a closed port, or sits behind a jump host that does not allow forwarding**: the user expects the chain to stop at once, the first hop to be closed again, and the error to name the hop that is at fault (and to carry the key it presented). Pinned in Task 10: `an_unknown_key_on_the_second_hop_stops_the_chain_and_closes_the_first_hop`, `a_jump_to_a_closed_port_fails_cleanly_and_names_the_jump_host` and `a_jump_host_that_does_not_allow_forwarding_is_named_in_the_error`.
5. **A connection that sits idle** (a laptop lid closed, a NAT that forgets the flow) **and a login prompt that nobody answers**: the user expects the loss to be noticed within (`keepalive_max_missed` + 1) × `keepalive_secs` with the lost hop named, a healthy idle link to be kept alive, and neither an idle session nor a waiting login prompt to burn CPU. Pinned in Task 9: `keepalive_closes_a_silent_link_and_the_reason_says_so`, `a_link_that_answers_keeps_the_session_alive_across_several_intervals` and `an_authenticated_connection_that_idles_with_keepalive_does_not_burn_cpu`; in Task 11: `waiting_for_a_prompt_costs_no_cpu` and `a_prompt_that_runs_out_of_time_abandons_the_login_and_drops_the_connection`.

## File Structure

All paths under `src-tauri/src/ssh/` unless a path says otherwise. Everything the engine needs for its tests is `#[cfg(test)]` code and is compiled only in test builds.

- `mod.rs` — the front door of the module: declares the files, re-exports the interface (`crate::ssh::Session`, never `crate::ssh::traits::Session`), and holds the test that keeps russh in one file (Task 2, extended in Tasks 3–7).
- `types.rs` — the plain data that crosses the interface: `HostId`, `HopRef`, `HostKey`, `Hop`, `Target`, `AuthMethod`, `Pty`, `ExecResult`, `Exit`, `DisconnectReason` and the rest (Task 2).
- `error.rs` — `ConnectError`, `SessionError`, `AuthError`; their `Display` is the sentence of spec §11 (Task 2).
- `traits.rs` — the five synchronous traits of spec §6.1: `SshEngine`, `Session`, `ShellChannel`, `HostKeyPolicy`, `AuthSource` (Task 2).
- `channel.rs` — `ByteQueue` (bounded, the producer never waits), `ExitCell`, `ShellInput`, `QueuedShell`: the plumbing every engine's shells are made of (Task 3).
- `fake.rs` — `FakeEngine`, the scripted engine for the broker, MCP and CLI tests of plans 1b–1d (Task 4; `#[cfg(test)]`).
- `russh_engine.rs` — `RusshEngine`, the only file that names russh: runtime, handler, host-key flow, login, sessions, exec, shells, jump chains, liveness (Tasks 7–11); its test module holds the unit tests and the measurements about russh itself, and `toy_server`, a small in-process SSH server for the password and keyboard-interactive tests (Task 11).
- `testing/{mod,harness,proxy,fixture,doubles}.rs` — test support (`#[cfg(test)]`): the scratch-sshd harness on `crate::process` (Task 5), a TCP proxy that misbehaves on demand, the server fixture, and the doubles for the broker's host-key policy and auth source over the real vault (Task 6); helpers for waiting, measuring CPU in a child process and printing facts (Tasks 5, 7, 9).
- `engine_tests/{mod,connect,exec,shell,liveness,jump,login_methods,environment}.rs` — the integration tests of the russh engine against scratch servers, one file per topic of spec §12 (Tasks 7–11, 13).
- `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock` — the two dependencies and the regenerated lock file (Task 1).
- `src-tauri/src/lib.rs` — one line, `pub mod ssh;` (Task 2).
- `src-tauri/tests/pam-sshd/{Dockerfile,sshd_config.test}` — a real OpenSSH with PAM in a container, for the logins a scratch sshd cannot do (Task 12).
- `.github/workflows/test-engine.yml` — new: the engine and vault tests on macOS and Linux, and the PAM job (Task 12). `.github/workflows/test-windows.yml` — extended: the whole app built with russh, the engine tests, and the engine against the runner's OpenSSH server (Task 13). `.github/workflows/spike-windows.yml` and `spike/` — deleted (Task 14).
- `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` — the §16 line about the spike's lifetime, put in the past tense (Task 14).

## Tasks

1. russh and tokio into `src-tauri`, and what the lock file gains
2. The engine interface: types, errors and traits
3. The bounded shell output queue
4. `FakeEngine`, the scripted engine for the later plans' tests
5. The scratch-sshd harness on `crate::process`
6. The proxy, the server fixture and the policy and auth doubles
7. `RusshEngine::connect_chain`: host keys and public-key login through the vault
8. Commands and PTY shells over an established connection
9. Keepalive, closing, dropping, the stuck session and the idle CPU
10. Jump hosts, and the real cause of a chain's end
11. Password and keyboard-interactive logins, against an in-process server
12. CI on macOS and Linux, with OpenSSH and PAM in a container
13. Windows CI: build the app with russh and run the engine against the runner's OpenSSH
14. Delete the spike, check everything once more

## How the tasks are cut

The outline this plan started from had ten tasks; the plan has fourteen. The interface (2), the output queue (3), the fake engine (4), the harness (5) and the proxy, fixture and doubles (6) are separate deliverables that a reviewer can accept or reject on their own, and the engine is built in the order its tests can run: connect, host keys and public-key login (7); exec and shells (8); keepalive, closing and the measurements about russh (9); jumps (10); password and keyboard-interactive (11). CI is split into macOS and Linux with the PAM container (12) and the Windows leg (13). Mapping to the outline's ten: (1) → 1; (2) → 2, 3, 4; (3) → 5, 6; (4) → 7; (5) → 8; (6) → 7 (connect timeouts, a signer that fails), 9 (keepalive, liveness, the stuck session) and 11 (abandoned prompts); (7) → 10; (8) → 11 and 12; (9) → 13; (10) → 14.

Tasks 7 and 8 are longer than the roughly 400 lines per task that the outline set as a limit (the engine file is about 590 lines after Task 7 and 870 after Task 8, and each of the two tasks adds 300 to 400 lines of tests). They were not cut further because the connection layer can only be tested through `connect_chain` and the session layer only through `exec` and `shell`: any cut would leave code that nothing tests. The implementer pastes verified code and reads what the run says; the work is in the runs.

## What this plan could not check on this machine, and where it deals with it

- The Linux job (the scratch sshd as a non-root Linux user, `ubuntu-latest`'s `/usr/sbin/sshd`), building the PAM image (needs the network and a base image) and PAM's real behaviour (its failure delays, how many rounds it asks): Task 12 checks the files with actionlint and `docker build --check`, runs the macOS job's command here, and ends with a step that tells the user what to read in the first run on GitHub.
- The Windows build of the app with russh (`aws-lc-sys` needs the Windows SDK headers, so not even a cross-check works here) and the runner's OpenSSH server: Task 13 rehearses the environment test against a sshd started by hand, and ends with the user's checklist for the first Windows run.
- `cargo audit` (not installed, needs the advisory database): Task 1 records what to look at and that the plan neither runs it nor adds a CI job; that is a decision for the user.
- `Phase::Tcp` as a timeout: the engine wraps TCP connect and handshake in one timeout and reports the phase it was in, but the tests only reach `Handshake` and `Auth` (a black-holed TCP connect cannot be made with a local proxy; the proxy accepts the connection). `Timeout { phase: Tcp }` is therefore written but not exercised.
- The results are all measured on macOS with OpenSSH 10.3p1, as in the spike. Timings in the tests have wide bounds for that reason, and the first runs on Linux and Windows may still show a bound that is too tight.

---

### Task 1: russh and tokio into `src-tauri`, and what the lock file gains

**Files:**
- Modify: `src-tauri/Cargo.toml` (two dependency lines)
- Modify: `src-tauri/Cargo.lock` (written by cargo, not by hand)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `russh = "=0.64.1"` and `tokio = { version = "1.52", features = ["rt-multi-thread", "macros", "net", "io-util", "time", "sync"] }` as direct dependencies of the package `sshelter`; a committed `Cargo.lock` that every later task builds with `--offline --locked`.

What shapes this task:
- The manifest gets two lines. `russh` is pinned exactly (spec §6.3: the version is pinned and an upgrade is a task of its own that reruns the integration tests). `tokio` was not a direct dependency (the lock already holds 1.52.3 through Tauri and reqwest); the engine needs `rt-multi-thread` for its dedicated runtime (spec §4), `net`, `io-util`, `time` and `sync` for sockets, timeouts and channels, and `macros` for `select!`.
- The lock file is written by cargo, not typed. `cargo metadata --offline` resolves against the local registry cache, which holds russh 0.64.1 and everything it needs because the phase-0 spike downloaded them.
- russh brings a second generation of RustCrypto next to the vault's (`ssh-key` 0.7.0-rc.11 next to 0.6.7, `rsa` 0.10.0-rc.18 next to 0.9, and so on), and `zeroize` 1.9.1 is what `vault::` runs on afterwards. Phase 0 proved the two generations coexist in a build; this task proves the app's own suite is green under the new lock. The TLS crypto does not grow: `aws-lc-sys` 0.45.0 is already in the lock for rustls, and russh's default backend is the same `aws-lc-rs`.

- [ ] **Step 1: Add the two dependencies**

`src-tauri/Cargo.toml`: apply this patch

```diff
--- a/src-tauri/Cargo.toml
+++ b/src-tauri/Cargo.toml
@@ -50,6 +50,10 @@ rsa = { version = "0.9", features = ["sha2"] }
 sha1 = { version = "0.10", features = ["oid"] }
 rand_core = { version = "0.6", features = ["getrandom"] }
 signature = "2"
+# SSH engine (src/ssh/): russh is imported by src/ssh/russh_engine.rs only. Pinned to the exact version the phase-0 spike measured.
+russh = "=0.64.1"
+# russh runs on tokio. The engine owns a dedicated runtime (rt-multi-thread, net, time) and drives it with block_on; `macros` is for select!.
+tokio = { version = "1.52", features = ["rt-multi-thread", "macros", "net", "io-util", "time", "sync"] }
 
 [dev-dependencies]
 ts-rs = "10"
```

- [ ] **Step 2: Run the suite with `--locked` to see it fail**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL before anything is compiled, with `error: cannot update the lock file …/src-tauri/Cargo.lock because --locked was passed to prevent this` (exit code 101). The manifest names russh and the lock file does not yet.

- [ ] **Step 3: Let cargo write the new lock file**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo metadata --offline --format-version 1 > /dev/null
```

Expected: exit code 0 within a second or two and, on stderr, `Locking 101 packages to latest compatible versions` followed by 92 `Adding …` lines (the first is `Adding aead v0.6.1`, the last `Adding wnaf v0.14.1`) and these `Updating …` lines:

```
Updating futures-channel v0.3.32 -> v0.3.34
Updating futures-core v0.3.32 -> v0.3.34
Updating futures-executor v0.3.32 -> v0.3.34
Updating futures-io v0.3.32 -> v0.3.34
Updating futures-macro v0.3.32 -> v0.3.34
Updating futures-sink v0.3.32 -> v0.3.34
Updating futures-task v0.3.32 -> v0.3.34
Updating futures-util v0.3.32 -> v0.3.34
Updating zeroize v1.8.2 -> v1.9.1
```

Nothing is downloaded. If cargo says it cannot find a crate offline, the local registry cache lacks it: stop and ask the user before running the command without `--offline`, which downloads.

```bash
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
```

Expected:

```
 src-tauri/Cargo.lock | 1437 ++++++++++++++++++++++++++++++++++++++++++++------
 src-tauri/Cargo.toml |    4 +
 2 files changed, 1277 insertions(+), 164 deletions(-)
```

- [ ] **Step 4: Check what the lock file gained**

Python 3.11 or newer (`tomllib`). The script compares the lock file of `HEAD` with the new one by package name and version.

```bash
git show HEAD:src-tauri/Cargo.lock > "${TMPDIR:-/tmp}/lock-before.toml"
python3 -I - "${TMPDIR:-/tmp}/lock-before.toml" src-tauri/Cargo.lock <<'PY'
"""Compare two Cargo.lock files: python3 -I lock_delta.py OLD_LOCK NEW_LOCK
Prints what the new lock adds, replaces and removes, by package name and version."""
import sys
import tomllib
from collections import defaultdict


def packages(path):
    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    found = defaultdict(set)
    for package in data["package"]:
        found[package["name"]].add(package["version"])
    return found


old, new = packages(sys.argv[1]), packages(sys.argv[2])
new_crates = sorted(name for name in new if name not in old)
second_versions = sorted(name for name in new if name in old and new[name] - old[name] and old[name] <= new[name])
replaced = sorted(name for name in new if name in old and old[name] - new[name])
removed = sorted(name for name in old if name not in new)
added_versions = sum(len(new[name]) for name in new_crates) + sum(len(new[name] - old[name]) for name in second_versions)
pre_releases = sorted(f"{name} {version}" for name in new for version in new[name] if "-" in version.split("+")[0] and version not in old.get(name, set()))

print(f"new crates: {len(new_crates)}")
print(f"second versions of crates the app already had: {len(second_versions)}")
print(f"package entries added: {added_versions}")
print(f"versions replaced: {len(replaced)}")
for name in replaced:
    print(f"  {name}: {sorted(old[name] - new[name])} -> {sorted(new[name] - old[name])}")
print(f"packages removed: {len(removed)}")
print(f"new pre-release versions: {len(pre_releases)}")
for entry in pre_releases:
    print(f"  {entry}")
PY
rm -f "${TMPDIR:-/tmp}/lock-before.toml"
```

Expected, exactly:

```
new crates: 33
second versions of crates the app already had: 58
package entries added: 92
versions replaced: 9
  futures-channel: ['0.3.32'] -> ['0.3.34']
  futures-core: ['0.3.32'] -> ['0.3.34']
  futures-executor: ['0.3.32'] -> ['0.3.34']
  futures-io: ['0.3.32'] -> ['0.3.34']
  futures-macro: ['0.3.32'] -> ['0.3.34']
  futures-sink: ['0.3.32'] -> ['0.3.34']
  futures-task: ['0.3.32'] -> ['0.3.34']
  futures-util: ['0.3.32'] -> ['0.3.34']
  zeroize: ['1.8.2'] -> ['1.9.1']
packages removed: 0
new pre-release versions: 3
  pkcs1 0.8.0-rc.4
  rsa 0.10.0-rc.18
  ssh-key 0.7.0-rc.11
```

The spike report counted the same 92 entries and the same three pre-releases but only one replaced version (zeroize); the eight `futures-*` crates move too in `src-tauri`, because russh depends on `futures` and cargo takes the newest 0.3.x family it has. Any other difference means the registry state is not the one this plan was written against: stop and tell the user.

- [ ] **Step 5: Check the dependency graph**

```bash
cd src-tauri
PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo tree --offline --locked -i russh
PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo tree --offline --locked -i zeroize | head -1
```

Expected:

```
russh v0.64.1
└── sshelter v0.16.0 (…/src-tauri)
zeroize v1.9.1
```

(In the first output `…` stands for the path of your checkout.) `--locked` succeeding here is the proof that the lock file now agrees with the manifest.

- [ ] **Step 6: Run the whole lib suite under the new lock**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1417 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about two minutes. `vault::` runs under `zeroize` 1.9.1 here for the first time; a failure in it is a real finding, not a flake: stop and tell the user. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 7: `cargo audit`: a note, not a gate**

Spec §12 wants `cargo audit` in CI and §16 lists "what `cargo audit` says about two generations of RustCrypto" as unmeasured. `cargo-audit` is not installed on this machine and needs the advisory database from the network, so this plan neither runs it nor adds a CI job for it; that is a decision for the user (see "Decisions to confirm" at the end of this plan). Where it is installed, `cd src-tauri && cargo audit` is the check, and the crates to look at are the three pre-releases `pkcs1 0.8.0-rc.4`, `rsa 0.10.0-rc.18` and `ssh-key 0.7.0-rc.11` and the new `ed25519-dalek 3`, `curve25519-dalek 5`, `p256`/`p384`/`p521` 0.14.

- [ ] **Step 8: Commit**

```bash
git status --short
git add src-tauri/Cargo.lock src-tauri/Cargo.toml
git commit -m "build(deps): add russh =0.64.1 and tokio for the SSH engine"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else.

---

### Task 2: The engine interface: types, errors and traits

**Files:**
- Modify: `src-tauri/src/lib.rs` (one line: `pub mod ssh;`)
- Create: `src-tauri/src/ssh/error.rs` (with its tests)
- Create: `src-tauri/src/ssh/mod.rs`
- Create: `src-tauri/src/ssh/traits.rs`
- Create: `src-tauri/src/ssh/types.rs` (with its tests)

**Interfaces:**
- Consumes: `zeroize::Zeroizing` (the existing `zeroize` dependency) and `ssh_key::PublicKey` (the vault's `ssh-key` 0.6.7, used by `HostKey::from_openssh_line` to compute a fingerprint). Nothing from earlier tasks.
- Produces: the module `crate::ssh` (`pub mod ssh;` in `lib.rs`), which re-exports everything below. These are exact; plans 1b–1d and the later tasks use these names and nothing else.

```rust
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub const DEFAULT_KEEPALIVE_EVERY: Duration = Duration::from_secs(30);

pub const DEFAULT_KEEPALIVE_MAX_MISSED: u32 = 3;

pub type Secret = Zeroizing<String>;

pub struct HostId(pub String);

impl HostId {
    pub fn as_str(&self) -> &str;
}

pub struct HopRef {
    pub id: HostId,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
}

pub struct HostKey {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
}

impl HostKey {
    pub fn from_openssh_line(line: &str) -> Option<HostKey>;
}

pub enum HostKeyVerdict {
    Pinned,
    Unknown,
    Mismatch { pinned: HostKey },
}

pub enum RsaHash {
    Sha256,
    Sha512,
}

pub struct Signature(pub Vec<u8>);

pub struct Prompt {
    pub text: String,
    pub echo: bool,
}

pub enum AuthMethod {
    Key { key_id: String },
    Password,
    Interactive,
}

impl AuthMethod {
    pub fn name(&self) -> &'static str;
}

pub struct Hop {
    pub id: HostId,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    pub pinned: Option<HostKey>,
    pub connect_timeout: Duration,
    pub keepalive_every: Duration,
    pub keepalive_max_missed: u32,
    pub nodelay: bool,
}

impl Hop {
    pub fn new(id: &str, alias: &str, hostname: &str, port: u16, user: &str, auth: AuthMethod) -> Hop;
    pub fn reference(&self) -> HopRef;
    pub fn auth_sequence(&self) -> Vec<AuthMethod>;
}

pub struct Target {
    pub hops: Vec<Hop>,
}

pub struct Pty {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

pub enum Ended {
    Exited,
    Signaled,
    TimedOut,
    Truncated,
    Disconnected,
}

pub struct ExecResult {
    pub ended: Ended,
    pub exit_code: Option<u32>,
    pub signal: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

pub enum Exit {
    Code(u32),
    Signal(String),
    Disconnected,
}

pub enum Phase {
    Tcp,
    Handshake,
    Auth,
}

pub enum DisconnectKind {
    ClosedByUs,
    ClosedByPeer,
    KeepaliveTimeout,
    ConnectionLost,
    Other,
}

pub struct DisconnectReason {
    pub hop: HopRef,
    pub kind: DisconnectKind,
    pub detail: String,
}
```

```rust
pub enum ConnectError {
    BadJumpChain { why: String },
    Unreachable { hop: HopRef, reason: String },
    Timeout { hop: HopRef, phase: Phase },
    HostKeyUnknown { hop: HopRef, key: HostKey },
    HostKeyMismatch { hop: HopRef, key: HostKey, pinned: HostKey },
    NoCommonHostKeyAlgorithm { hop: HopRef, ours: Vec<String>, theirs: Vec<String> },
    AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String },
    AuthAbandoned { hop: HopRef, reason: String },
    Protocol { hop: HopRef, text: String },
}

pub enum SessionError {
    Closed,
    Channel(String),
}

pub enum AuthError {
    KeyUnavailable(String),
    Refused(String),
    Failed(String),
}
```

```rust
pub trait SshEngine: Send + Sync {
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError>;
}

pub trait Session: Send + Sync {
    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError>;

    fn exec(&self, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError>;

    fn is_alive(&self) -> bool;

    fn disconnect_reason(&self) -> Option<DisconnectReason>;

    fn close(&self);
}

pub trait ShellChannel: Send + Sync {
    fn write(&self, data: &[u8]) -> Result<(), SessionError>;

    fn read(&self, buf: &mut [u8]) -> Result<usize, SessionError>;

    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError>;

    fn exited(&self) -> Option<Exit>;

    fn close(&self);
}

pub trait HostKeyPolicy: Send + Sync {
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict;
}

pub trait AuthSource: Send + Sync {
    fn public_key(&self, key_id: &str) -> Option<String>;

    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError>;

    fn password(&self, hop: &HopRef) -> Option<Secret>;

    fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>>;
}
```

What shapes this task:
- The five traits are spec §6.1 as written. Three additions, which plans 1b–1d must know: `ShellChannel` is `Send + Sync` (the spec says `Send`; a shell is read on one thread while another writes, which needs a shared reference); `AuthSource` has `public_key(&self, key_id: &str) -> Option<String>` (russh's public-key login announces the public key before it asks for a signature, and neither `Hop` nor `sign` carries it; `None` skips the key method); and `Ended` has a fifth variant, `Truncated` (a command stopped at the output cap has an unknown exit status but the connection is alive, so it must not read as `Disconnected`, which a broker would show the user as a lost connection).
- `AuthSource::password` returning `None` means "no password: skip the method". Spec §6.2 step 4 says the broker asks the user when there is none; the engine supports that by calling `password` **before it opens the connection** for a hop that starts with the password method (Task 7), so the broker may ask a person there, and by calling it quickly as a fallback after a refused key (a person typing must not leave an unauthenticated connection waiting).
- `Secret` is `Zeroizing<String>`. `HostKey::from_openssh_line` is how the engine turns a key russh gives it into the stored form: only the OpenSSH text crosses between the two `ssh-key` generations, so no type of one appears in the other.
- The `Display` text of the errors is the sentence of spec §11 and none of them carries a key or a password. Sentences that need `{n}` seconds or "while the command was running" are composed by the broker (plan 1b) from `DisconnectReason` (`kind` plus a lowercase `detail` phrase for logs) and `ExecResult`; `Unreachable`'s `reason` names the jump host when a jump fails (Task 10 tests that), and spec §11's "Could not connect through {jump alias}" is the broker's wording of it.
- `ssh/mod.rs` declares the modules privately and re-exports the interface, so callers write `crate::ssh::Session`, never `crate::ssh::traits::Session`. Later tasks add their modules to it. `traits.rs` has no tests (it declares, it does not compute), so it is written in the implementation step.

- [ ] **Step 1: Write the tests**

`src-tauri/src/lib.rs`: apply this patch

```diff
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -14,6 +14,7 @@ pub mod mcp;
 mod process;
 mod secrets;
 mod settings_io;
+pub mod ssh;
 mod state;
 mod tray;
 mod updater_channel;
```

`src-tauri/src/ssh/mod.rs`: create

```rust
//! SSHelter's own SSH engine (own-ssh spec §4, §6): the interface the broker, the CLI and the MCP adapter use (`SshEngine`, `Session`,
//! `ShellChannel`, `HostKeyPolicy`, `AuthSource`), a fake for their tests, and the russh-backed engine behind the interface.
//!
//! russh is imported by exactly one file, `russh_engine.rs`; a test below keeps it that way. Swapping the engine later means replacing
//! that file.

mod error;
mod types;

pub use error::{AuthError, ConnectError, SessionError};
pub use types::{
    AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostId, HostKey, HostKeyVerdict, Phase, Prompt,
    Pty, RsaHash, Secret, Signature, Target, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY, DEFAULT_KEEPALIVE_MAX_MISSED,
};
```

`src-tauri/src/ssh/error.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::types::HostId;

    fn hop() -> HopRef {
        HopRef { id: HostId::from("h1"), alias: "web".into(), hostname: "web.example.com".into(), port: 2222, user: "deploy".into() }
    }

    fn key() -> HostKey {
        HostKey { algorithm: "ssh-ed25519".into(), public_key: vec![1, 2, 3], fingerprint: "SHA256:abc".into() }
    }

    /// The sentences are the ones in spec §11; the broker and the CLI show them as they are.
    #[test]
    fn connect_errors_read_like_the_messages_of_the_spec() {
        let cases = [
            (ConnectError::Unreachable { hop: hop(), reason: "connection refused".into() }, "Could not reach web.example.com:2222 (connection refused)."),
            (ConnectError::Timeout { hop: hop(), phase: Phase::Tcp }, "Could not reach web.example.com:2222 (timed out during the TCP connection)."),
            (ConnectError::Timeout { hop: hop(), phase: Phase::Handshake }, "Could not reach web.example.com:2222 (timed out during the SSH handshake)."),
            (ConnectError::Timeout { hop: hop(), phase: Phase::Auth }, "Could not reach web.example.com:2222 (timed out during login)."),
            (ConnectError::HostKeyMismatch { hop: hop(), key: key(), pinned: key() }, "The host key of web changed. Connection refused."),
            (ConnectError::HostKeyUnknown { hop: hop(), key: key() }, "The host key of web has not been confirmed yet."),
            (
                ConnectError::AuthFailed { hop: hop(), tried: vec![AuthMethod::Key { key_id: "k1".into() }, AuthMethod::Password], reason: String::new() },
                "Authentication failed for deploy@web (tried: publickey, password).",
            ),
            (ConnectError::AuthAbandoned { hop: hop(), reason: "the prompt timed out".into() }, "Authentication for web was abandoned (the prompt timed out)."),
            (ConnectError::Protocol { hop: hop(), text: "Key exchange failed".into() }, "SSH error: Key exchange failed"),
            (ConnectError::BadJumpChain { why: "web appears twice".into() }, "The jump chain cannot be used: web appears twice"),
        ];
        for (error, text) in cases {
            assert_eq!(error.to_string(), text);
        }
    }

    #[test]
    fn an_auth_failure_reason_follows_the_sentence() {
        let error = ConnectError::AuthFailed {
            hop: hop(),
            tried: vec![AuthMethod::Key { key_id: "k1".into() }],
            reason: "The server only accepts RSA keys signed with SHA-1, which SSHelter does not do.".into(),
        };
        assert_eq!(
            error.to_string(),
            "Authentication failed for deploy@web (tried: publickey). The server only accepts RSA keys signed with SHA-1, which SSHelter does not do."
        );
    }

    #[test]
    fn no_common_algorithm_names_both_lists_and_explains_ssh_rsa() {
        let plain = ConnectError::NoCommonHostKeyAlgorithm { hop: hop(), ours: vec!["ssh-ed25519".into()], theirs: vec!["ssh-dss".into()] };
        assert_eq!(plain.to_string(), "Could not agree on a host key algorithm with web: the server offers ssh-dss, SSHelter accepts ssh-ed25519.");
        let legacy = ConnectError::NoCommonHostKeyAlgorithm { hop: hop(), ours: vec!["ssh-ed25519".into(), "rsa-sha2-512".into()], theirs: vec!["ssh-rsa".into()] };
        assert_eq!(
            legacy.to_string(),
            "Could not agree on a host key algorithm with web: the server offers ssh-rsa, SSHelter accepts ssh-ed25519, rsa-sha2-512. SSHelter does not use ssh-rsa (SHA-1)."
        );
    }

    #[test]
    fn session_and_auth_errors_have_plain_messages() {
        assert_eq!(SessionError::Closed.to_string(), "The connection is closed.");
        assert_eq!(SessionError::Channel("channel open refused".into()).to_string(), "SSH error: channel open refused");
        assert_eq!(AuthError::Refused("the vault is locked".into()).to_string(), "the key was not released: the vault is locked");
        assert_eq!(AuthError::KeyUnavailable("no such key".into()).to_string(), "the key is not available: no such key");
        assert_eq!(AuthError::Failed("bad key".into()).to_string(), "signing failed: bad key");
    }
}
```

`src-tauri/src/ssh/types.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    #[test]
    fn a_host_key_is_read_from_an_openssh_line_with_its_sha256_fingerprint() {
        let key = HostKey::from_openssh_line(&format!("{} root@server\n", test_keys::PLAIN_PUBLIC)).expect("an ed25519 line");
        assert_eq!(key.algorithm, "ssh-ed25519");
        let blob = key.public_key.clone();
        assert_eq!(&blob[..4], &[0, 0, 0, 11], "the wire format starts with the length of the algorithm name");
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(key.fingerprint, test_keys::PLAIN_FINGERPRINT);

        let key = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).expect("an ecdsa line");
        assert_eq!((key.algorithm.as_str(), key.fingerprint.as_str()), ("ecdsa-sha2-nistp256", test_keys::ECDSA_FINGERPRINT));

        let key = HostKey::from_openssh_line(test_keys::RSA_PUBLIC).expect("an rsa line");
        assert_eq!((key.algorithm.as_str(), key.fingerprint.as_str()), ("ssh-rsa", test_keys::RSA_FINGERPRINT));
    }

    #[test]
    fn something_that_is_not_a_key_line_is_not_a_host_key() {
        assert_eq!(HostKey::from_openssh_line(""), None);
        assert_eq!(HostKey::from_openssh_line("ssh-ed25519"), None);
        assert_eq!(HostKey::from_openssh_line("ssh-ed25519 not-base64!"), None);
        assert_eq!(HostKey::from_openssh_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"), None, "a blob that is cut short");
    }

    #[test]
    fn a_hop_starts_with_the_defaults_of_a_host_record_and_names_itself() {
        let hop = Hop::new("id-web", "web", "web.example.com", 2222, "deploy", AuthMethod::Password);
        assert_eq!((hop.connect_timeout, hop.keepalive_every, hop.keepalive_max_missed, hop.nodelay), (Duration::from_secs(15), Duration::from_secs(30), 3, true));
        assert_eq!(hop.pinned, None);
        let reference = hop.reference();
        assert_eq!((reference.id.as_str(), reference.alias.as_str(), reference.hostname.as_str(), reference.port, reference.user.as_str()), ("id-web", "web", "web.example.com", 2222, "deploy"));
        assert_eq!(reference.id.to_string(), "id-web");
    }

    #[test]
    fn the_login_sequence_runs_from_the_start_method_to_the_end_of_key_password_interactive() {
        let hop = |auth| Hop::new("h", "h", "h", 22, "u", auth);
        let key = AuthMethod::Key { key_id: "k1".into() };
        assert_eq!(hop(key.clone()).auth_sequence(), vec![key, AuthMethod::Password, AuthMethod::Interactive]);
        assert_eq!(hop(AuthMethod::Password).auth_sequence(), vec![AuthMethod::Password, AuthMethod::Interactive]);
        assert_eq!(hop(AuthMethod::Interactive).auth_sequence(), vec![AuthMethod::Interactive]);
    }

    #[test]
    fn auth_methods_carry_their_protocol_names() {
        assert_eq!(AuthMethod::Key { key_id: "k".into() }.name(), "publickey");
        assert_eq!(AuthMethod::Password.name(), "password");
        assert_eq!(AuthMethod::Interactive.name(), "keyboard-interactive");
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate does not compile. The first error is `error[E0432]: unresolved import `crate::ssh::types::HostId``, and the run ends with `error: could not compile `sshelter` (lib test) due to 54 previous errors` (the number of errors depends on the compiler; what matters is that the errors name items that do not exist yet).

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/mod.rs
+++ b/src-tauri/src/ssh/mod.rs
@@ -5,9 +5,11 @@
 //! that file.
 
 mod error;
+mod traits;
 mod types;
 
 pub use error::{AuthError, ConnectError, SessionError};
+pub use traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
 pub use types::{
     AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostId, HostKey, HostKeyVerdict, Phase, Prompt,
     Pty, RsaHash, Secret, Signature, Target, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY, DEFAULT_KEEPALIVE_MAX_MISSED,
```

`src-tauri/src/ssh/error.rs`: insert this above the `#[cfg(test)]` line, at the very top of the file, and leave one empty line between it and that line

```rust
//! The engine's errors. Their `Display` text is the sentence the user sees (own-ssh spec §11); none of them carries a key or a password.

use std::fmt;

use super::types::{AuthMethod, HopRef, HostKey, Phase};

/// Why `SshEngine::connect` did not produce a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// The target has no hops, or lists a host twice (a jump loop).
    BadJumpChain { why: String },
    /// DNS or TCP failed, or the jump host could not open a connection to `hop`.
    Unreachable { hop: HopRef, reason: String },
    /// `hop` did not answer in time: its `connect_timeout` ran out during `phase`, or the server stopped answering the login.
    Timeout { hop: HopRef, phase: Phase },
    /// Nothing is pinned for `hop` and the server presented `key`. The caller asks the user, pins the key and connects again.
    HostKeyUnknown { hop: HopRef, key: HostKey },
    /// `hop` presented `key`, but `pinned` is on record.
    HostKeyMismatch { hop: HopRef, key: HostKey, pinned: HostKey },
    /// The two sides share no host key algorithm. `ours` and `theirs` are the lists.
    NoCommonHostKeyAlgorithm { hop: HopRef, ours: Vec<String>, theirs: Vec<String> },
    /// Every method was refused or could not be tried. `tried` lists the methods that were attempted; `reason` explains what the
    /// method list alone does not (for example that the server accepts RSA keys only with SHA-1); empty for a plain refusal.
    AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String },
    /// Login stopped on our side (signer failure, cancelled or overdue prompt) and the connection was dropped.
    AuthAbandoned { hop: HopRef, reason: String },
    /// Any other protocol or I/O failure, as text.
    Protocol { hop: HopRef, text: String },
}

fn phase_text(phase: Phase) -> &'static str {
    match phase {
        Phase::Tcp => "the TCP connection",
        Phase::Handshake => "the SSH handshake",
        Phase::Auth => "login",
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::BadJumpChain { why } => write!(f, "The jump chain cannot be used: {why}"),
            ConnectError::Unreachable { hop, reason } => write!(f, "Could not reach {}:{} ({reason}).", hop.hostname, hop.port),
            ConnectError::Timeout { hop, phase } => write!(f, "Could not reach {}:{} (timed out during {}).", hop.hostname, hop.port, phase_text(*phase)),
            ConnectError::HostKeyUnknown { hop, .. } => write!(f, "The host key of {} has not been confirmed yet.", hop.alias),
            ConnectError::HostKeyMismatch { hop, .. } => write!(f, "The host key of {} changed. Connection refused.", hop.alias),
            ConnectError::NoCommonHostKeyAlgorithm { hop, ours, theirs } => {
                write!(f, "Could not agree on a host key algorithm with {}: the server offers {}, SSHelter accepts {}.", hop.alias, theirs.join(", "), ours.join(", "))?;
                if theirs.iter().any(|name| name == "ssh-rsa") && !ours.iter().any(|name| name == "ssh-rsa") {
                    write!(f, " SSHelter does not use ssh-rsa (SHA-1).")?;
                }
                Ok(())
            }
            ConnectError::AuthFailed { hop, tried, reason } => {
                let names: Vec<&str> = tried.iter().map(AuthMethod::name).collect();
                write!(f, "Authentication failed for {}@{} (tried: {}).", hop.user, hop.alias, names.join(", "))?;
                if !reason.is_empty() {
                    write!(f, " {reason}")?;
                }
                Ok(())
            }
            ConnectError::AuthAbandoned { hop, reason } => write!(f, "Authentication for {} was abandoned ({reason}).", hop.alias),
            ConnectError::Protocol { text, .. } => write!(f, "SSH error: {text}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Why a call on a live session failed. A command that was cut short is not an error: it is an `ExecResult` with `Ended::TimedOut`, `Ended::Truncated` or `Ended::Disconnected`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The connection has ended; `Session::disconnect_reason` says why.
    Closed,
    /// A channel could not be opened or used (refused by the server, or the request failed).
    Channel(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Closed => write!(f, "The connection is closed."),
            SessionError::Channel(text) => write!(f, "SSH error: {text}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Why `AuthSource::sign` could not produce a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The key is not in the vault (any more) or has no private half on this computer.
    KeyUnavailable(String),
    /// The vault is locked, or the user refused to unlock it or to approve the use of the key.
    Refused(String),
    /// Signing itself failed.
    Failed(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::KeyUnavailable(why) => write!(f, "the key is not available: {why}"),
            AuthError::Refused(why) => write!(f, "the key was not released: {why}"),
            AuthError::Failed(why) => write!(f, "signing failed: {why}"),
        }
    }
}

impl std::error::Error for AuthError {}
```

`src-tauri/src/ssh/traits.rs`: create

```rust
//! The engine interface, as spec §6.1 writes it. Everything here is synchronous: the broker, the CLI and the MCP adapter run on plain
//! threads, and the engine hides its own runtime. Nothing in this file names russh.
//!
//! Two additions to the spec's block, both forced by the engine's job: `ShellChannel` is `Send + Sync` (a shell is read on one thread
//! while another writes, which needs a shared reference), and `AuthSource::public_key` exists (russh's public-key login announces the
//! public key before it asks for a signature, and neither `Hop` nor `sign` carries it).

use std::time::{Duration, Instant};

use super::error::{AuthError, ConnectError, SessionError};
use super::types::{DisconnectReason, ExecResult, Exit, HopRef, HostKey, HostKeyVerdict, Prompt, Pty, RsaHash, Secret, Signature, Target};

/// Opens connections. Implemented by the russh engine and by the fake used in broker, MCP and CLI tests.
pub trait SshEngine: Send + Sync {
    /// Connects to every hop of `target` in order, checks each hop's host key with `host_keys`, logs in with `auth`, and returns the
    /// session that owns the whole chain. Blocks until it is done or has failed; every wait inside is bounded.
    ///
    /// A host key that is not pinned never waits for the user: the call fails with `ConnectError::HostKeyUnknown` (or `HostKeyMismatch`)
    /// carrying the key the server presented, and the caller connects again once the user has decided (spec §6.2 step 3).
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError>;
}

/// One live connection (a whole jump chain), owned by whoever holds it. Dropping it closes it.
pub trait Session: Send + Sync {
    /// Opens a PTY shell on the destination host. Any number of channels can be open at once.
    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError>;

    /// Runs `command` without a PTY and collects its output, for at most `timeout`. Output beyond `output_cap` bytes (stdout and stderr
    /// together) is not read: the engine closes the channel, sets `truncated` and ends the result as `Ended::Truncated`. A command that ends without a
    /// status, a timeout and the cap are results, not errors, and the connection survives all three.
    fn exec(&self, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError>;

    /// Whether the connection (every hop of it) is still up, judged from the connection's own state and never from an error variant.
    fn is_alive(&self) -> bool;

    /// Why the connection ended, taken from the outermost hop that recorded a reason. `None` while it is alive.
    fn disconnect_reason(&self) -> Option<DisconnectReason>;

    /// Closes the connection: an explicit disconnect on every hop, innermost first. Safe to call twice.
    fn close(&self);
}

/// An open shell. `read` blocks, so a shell is read on one thread while another writes.
pub trait ShellChannel: Send + Sync {
    /// Sends keystrokes (or pasted text) to the shell's stdin.
    fn write(&self, data: &[u8]) -> Result<(), SessionError>;

    /// Reads terminal output (stdout and stderr arrive merged on a PTY) into `buf` and returns how many bytes it wrote. Blocks until
    /// there is something to read. 0 means the shell has ended and everything it wrote has been read; `buf` must not be empty.
    ///
    /// Reading is what keeps the connection healthy: the engine drains the channel on its own, into a bounded buffer, and when the
    /// reader falls so far behind that the buffer is full it drops the newest output and puts a one-line notice in the stream.
    fn read(&self, buf: &mut [u8]) -> Result<usize, SessionError>;

    /// The terminal was resized. Sent to the server right away; the server ignores a resize that arrives before the PTY exists, so a
    /// caller that has a size to apply sends it after `Session::shell` returns (the broker remembers the last one, spec §7.2).
    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError>;

    /// How the shell ended; `None` until it has. When `read` has returned 0 this is `Some`.
    fn exited(&self) -> Option<Exit>;

    /// Closes the channel (the connection stays up). A blocked `read` returns 0.
    fn close(&self);
}

/// Decides whether a server's host key is trusted.
pub trait HostKeyPolicy: Send + Sync {
    /// Called while the handshake is in progress, so it must be fast and must not block: a lookup, never a dialog.
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict;
}

/// Where the engine gets signatures and secrets. Implemented by the broker, which decides who is asked (spec §6.1, decision 7).
pub trait AuthSource: Send + Sync {
    /// The public half of the vault key `key_id` as an OpenSSH line (`<algorithm> <base64> [comment]`); `None` when there is no such key,
    /// in which case the key method is skipped.
    fn public_key(&self, key_id: &str) -> Option<String>;

    /// Signs `data` with the vault key `key_id` and returns the signature blob. For an RSA key `rsa_hash` is the hash to use; the engine
    /// never calls this for an RSA key it would have to sign with SHA-1. Must be quick: passphrases, vault unlocking and approvals are
    /// done before `connect` is called, because the connection waits for the answer without reading the socket.
    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError>;

    /// The password for `hop`, or `None` when there is none: the password method is then skipped. When a hop starts with the password
    /// method the engine calls this before it opens the connection, so asking the user here is fine; as a fallback after a refused key
    /// it is called during the login and must be quick.
    fn password(&self, hop: &HopRef) -> Option<Secret>;

    /// The answers to one keyboard-interactive round, one per prompt, given before `deadline`; `None` abandons the login and the engine
    /// drops the connection. An answer that arrives after the deadline is not used either.
    fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>>;
}
```

`src-tauri/src/ssh/types.rs`: insert this above the `#[cfg(test)]` line, at the very top of the file, and leave one empty line between it and that line

```rust
//! The data that crosses the engine interface (own-ssh spec §6.1). Plain data only: no russh type and no vault type appears here, so the
//! broker, the fake engine and a future hand-written engine can all use it.

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

/// The defaults of a host record (spec §5.1: `connect_timeout_secs` 15, `keepalive_secs` 30, `keepalive_max_missed` 3).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_KEEPALIVE_EVERY: Duration = Duration::from_secs(30);
pub const DEFAULT_KEEPALIVE_MAX_MISSED: u32 = 3;

/// A password, passphrase or answer. Zeroed when dropped.
pub type Secret = Zeroizing<String>;

/// The id of a stored host record. It survives renames; the broker looks hosts up by it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostId(pub String);

impl HostId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for HostId {
    fn from(id: &str) -> HostId {
        HostId(id.to_string())
    }
}

impl From<String> for HostId {
    fn from(id: String) -> HostId {
        HostId(id)
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which hop a callback or an error is about: enough to name it in a dialog or a message and to look it up again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopRef {
    pub id: HostId,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
}

/// A server's host key in the form a host record stores it (spec §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKey {
    /// The key type as OpenSSH names it: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa` (the key type, whatever hash the signature used).
    pub algorithm: String,
    /// The public key in SSH wire format (the bytes behind the base64 of an OpenSSH public key line).
    pub public_key: Vec<u8>,
    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
}

impl HostKey {
    /// From an OpenSSH public key line (`<algorithm> <base64> [comment]`). `None` when the line is not a key this app understands.
    pub fn from_openssh_line(line: &str) -> Option<HostKey> {
        let key = ssh_key::PublicKey::from_openssh(line.trim()).ok()?;
        Some(HostKey {
            algorithm: key.algorithm().to_string(),
            public_key: key.to_bytes().ok()?,
            fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        })
    }
}

/// What a `HostKeyPolicy` says about the key a server presented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// The key is the one pinned for this host: go on.
    Pinned,
    /// Nothing is pinned for this host yet.
    Unknown,
    /// Something is pinned and this is not it. `pinned` is the key on record.
    Mismatch { pinned: HostKey },
}

/// The hash an RSA login signature uses. There is no SHA-1 variant on purpose: the engine refuses to sign with it (spec §6.3 b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaHash {
    Sha256,
    Sha512,
}

/// A signature in the SSH wire form of the agent protocol: `string algorithm || string signature` (what `Material::sign` returns).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

/// One keyboard-interactive prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub text: String,
    /// Whether what the user types may be shown.
    pub echo: bool,
}

/// A way to log in. `Hop::auth` is the one a hop starts with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Public-key login with the vault key `key_id`.
    Key { key_id: String },
    Password,
    Interactive,
}

impl AuthMethod {
    /// The method's name in the SSH protocol and in messages.
    pub fn name(&self) -> &'static str {
        match self {
            AuthMethod::Key { .. } => "publickey",
            AuthMethod::Password => "password",
            AuthMethod::Interactive => "keyboard-interactive",
        }
    }
}

/// One connection of a chain: a stored host with everything the engine needs to reach it and log in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    pub id: HostId,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    /// Where the login sequence starts. The sequence is key, password, keyboard-interactive, in that order; it starts at `auth` and moves
    /// on to the next method only when the server refuses (see `Hop::auth_sequence`).
    pub auth: AuthMethod,
    /// The key on record for this host. When it is set the handshake offers only that key's algorithm family, so a server that later
    /// adds another key type is not mistaken for a changed key. Whether a presented key is trusted is `HostKeyPolicy`'s decision.
    pub pinned: Option<HostKey>,
    /// TCP connect plus handshake must finish within this.
    pub connect_timeout: Duration,
    /// How long the link may be silent before a keepalive is sent; `Duration::ZERO` turns keepalive off.
    pub keepalive_every: Duration,
    /// Unanswered keepalives tolerated: a dead link is noticed after (`keepalive_max_missed` + 1) × `keepalive_every`. 0 = never give up.
    pub keepalive_max_missed: u32,
    /// `TCP_NODELAY` on the socket of the first hop (set it for shells; Nagle delays keystroke echo).
    pub nodelay: bool,
}

impl Hop {
    /// A hop with the spec's default timeouts and `nodelay` on.
    pub fn new(id: &str, alias: &str, hostname: &str, port: u16, user: &str, auth: AuthMethod) -> Hop {
        Hop {
            id: HostId::from(id),
            alias: alias.to_string(),
            hostname: hostname.to_string(),
            port,
            user: user.to_string(),
            auth,
            pinned: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            keepalive_every: DEFAULT_KEEPALIVE_EVERY,
            keepalive_max_missed: DEFAULT_KEEPALIVE_MAX_MISSED,
            nodelay: true,
        }
    }

    pub fn reference(&self) -> HopRef {
        HopRef { id: self.id.clone(), alias: self.alias.clone(), hostname: self.hostname.clone(), port: self.port, user: self.user.clone() }
    }

    /// The methods to try, in order: from `auth` to the end of key, password, keyboard-interactive.
    pub fn auth_sequence(&self) -> Vec<AuthMethod> {
        match &self.auth {
            AuthMethod::Key { .. } => vec![self.auth.clone(), AuthMethod::Password, AuthMethod::Interactive],
            AuthMethod::Password => vec![AuthMethod::Password, AuthMethod::Interactive],
            AuthMethod::Interactive => vec![AuthMethod::Interactive],
        }
    }
}

/// A host record resolved for connecting: the jump chain and the destination, in the order they are connected. `hops` is never empty;
/// the last hop is the destination, every earlier one is a jump host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub hops: Vec<Hop>,
}

/// The terminal a shell is opened with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pty {
    /// `$TERM` of the user's terminal, e.g. `xterm-256color`.
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It ran to its end and reported an exit status.
    Exited,
    /// It was killed by a signal (`signal` says which); there is no exit status.
    Signaled,
    /// It was still running when the caller's timeout passed; the engine closed the channel (the connection stays usable).
    TimedOut,
    /// Its output reached the caller's cap and the engine closed the channel (`ExecResult::truncated` is true). Its exit status is
    /// unknown, and the connection is still alive and usable: this is not a lost connection.
    Truncated,
    /// The engine lost track of it: the channel ended without an exit status or a signal because the connection was lost.
    /// Never read this as exit code 0.
    Disconnected,
}

/// The result of `Session::exec`. Output is raw bytes: not decoded, line endings untouched (Windows OpenSSH ends lines with CRLF).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecResult {
    pub ended: Ended,
    pub exit_code: Option<u32>,
    /// The signal name without the `SIG` prefix (`KILL`, `TERM`, …) when `ended` is `Signaled`.
    pub signal: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The output reached the cap: `stdout` and `stderr` together are what fitted, the rest was not read. True exactly when `ended` is
    /// `Truncated`.
    pub truncated: bool,
}

/// How a shell ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Code(u32),
    /// Killed by this signal (name without the `SIG` prefix).
    Signal(String),
    /// The channel ended without a status: the connection was lost, or the server closed the channel.
    Disconnected,
}

/// Which part of connecting ran out of time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Tcp,
    Handshake,
    Auth,
}

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectKind {
    /// `Session::close` (or dropping the session).
    ClosedByUs,
    /// The server sent a disconnect message.
    ClosedByPeer,
    /// `keepalive_max_missed` + 1 keepalives went unanswered.
    KeepaliveTimeout,
    /// The link broke (reset, end of stream).
    ConnectionLost,
    /// Anything else (a protocol error, an internal failure).
    Other,
}

/// The first recorded end of a connection, taken from the outermost hop that recorded one (spec §6.2 step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisconnectReason {
    /// The hop that recorded it.
    pub hop: HopRef,
    pub kind: DisconnectKind,
    /// A sentence for logs; never contains a key or a password.
    pub detail: String,
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 9 passed; 0 failed`. The run takes about 11 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1426 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 106 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/lib.rs src-tauri/src/ssh/error.rs src-tauri/src/ssh/mod.rs src-tauri/src/ssh/traits.rs src-tauri/src/ssh/types.rs
git commit -m "feat(ssh): add the engine interface: types, errors and traits"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 3: The bounded shell output queue

**Files:**
- Create: `src-tauri/src/ssh/channel.rs` (with its tests)
- Modify: `src-tauri/src/ssh/mod.rs`

**Interfaces:**
- Consumes (Task 2): `crate::ssh::SessionError`, `crate::ssh::Exit` (`Code(u32)`, `Signal(String)`, `Disconnected`) and the trait `ShellChannel`:

```rust
pub trait ShellChannel: Send + Sync {
    fn write(&self, data: &[u8]) -> Result<(), SessionError>;
    fn read(&self, buf: &mut [u8]) -> Result<usize, SessionError>;
    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError>;
    fn exited(&self) -> Option<Exit>;
    fn close(&self);
}
```

- Produces (`crate::ssh::{ByteQueue, ExitCell, QueueRead, QueuedShell, ShellInput}`):

```rust
pub trait ShellInput: Send + Sync {
    fn write(&self, bytes: &[u8]) -> Result<(), SessionError>;
    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError>;
    fn close(&self);
}
```

  - `ssh/channel.rs`:
    - `pub enum QueueRead`
    - `pub struct ByteQueue`
    - (impl ByteQueue) `pub fn new(capacity: usize) -> Arc<ByteQueue>`
    - (impl ByteQueue) `pub fn push(&self, chunk: Vec<u8>) -> bool`
    - (impl ByteQueue) `pub fn close(&self)`
    - (impl ByteQueue) `pub fn read_until(&self, buf: &mut [u8], deadline: Option<Instant>) -> QueueRead`
    - (impl ByteQueue) `pub fn dropped_bytes(&self) -> u64`
    - `pub struct ExitCell`
    - (impl ExitCell) `pub fn new() -> Arc<ExitCell>`
    - (impl ExitCell) `pub fn set(&self, exit: Exit)`
    - (impl ExitCell) `pub fn get(&self) -> Option<Exit>`
    - `pub trait ShellInput: Send + Sync`
    - `pub struct QueuedShell`
    - (impl QueuedShell) `pub fn new(input: Box<dyn ShellInput>, output: Arc<ByteQueue>, exit: Arc<ExitCell>) -> QueuedShell`
    - (impl QueuedShell) `pub fn read_until(&self, buf: &mut [u8], deadline: Instant) -> QueueRead`

What shapes this task:
- Why this exists (spec §6.3): russh stalls the whole connection behind a channel nobody reads (the maintainer declined to change that). So every channel gets a reader task that moves output into a queue and **never waits for the consumer**; a terminal that is paused or slow must not hold up the connection or the other shells. The queue therefore has a hard size, and when it is full the newest chunk is dropped and counted; the next chunk that is kept is preceded by one line, `[SSHelter dropped N bytes of output because the terminal fell behind]`, so the user can see that something is missing. An empty queue accepts a chunk of any size, so progress is always possible.
- `QueuedShell` is the `ShellChannel` every engine builds from three parts: the engine's `ShellInput` (the write side), the `ByteQueue` its reader fills, and an `ExitCell` set **before** the queue is closed, so a `read` that returns 0 always finds `exited()` filled in. The russh engine (Task 8) and the fake (Task 4) both use it, which keeps their shells behaving the same.
- The queue is plain `std` (a `Mutex` and a `Condvar`), not tokio: the consumers are ordinary threads. `read_until` takes a deadline so that tests (and callers that must also watch something else) never block for ever.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/mod.rs
+++ b/src-tauri/src/ssh/mod.rs
@@ -4,10 +4,12 @@
 //! russh is imported by exactly one file, `russh_engine.rs`; a test below keeps it that way. Swapping the engine later means replacing
 //! that file.
 
+mod channel;
 mod error;
 mod traits;
 mod types;
 
+pub use channel::{ByteQueue, ExitCell, QueueRead, QueuedShell, ShellInput};
 pub use error::{AuthError, ConnectError, SessionError};
 pub use traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
 pub use types::{
```

`src-tauri/src/ssh/channel.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    fn soon() -> Option<Instant> {
        Some(Instant::now() + Duration::from_millis(50))
    }

    fn read_all(queue: &ByteQueue) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = [0u8; 64];
        while let QueueRead::Bytes(count) = queue.read_until(&mut buf, soon()) {
            all.extend_from_slice(&buf[..count]);
        }
        all
    }

    #[test]
    fn chunks_come_out_in_the_order_they_went_in_and_a_small_buffer_gets_part_of_a_chunk() {
        let queue = ByteQueue::new(1024);
        assert!(queue.push(b"hello world".to_vec()));
        assert!(queue.push(b"!".to_vec()));
        let mut buf = [0u8; 5];
        assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(5));
        assert_eq!(&buf, b"hello");
        assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(5));
        assert_eq!(&buf, b" worl");
        assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(1));
        assert_eq!(&buf[..1], b"d");
        assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(1));
        assert_eq!(&buf[..1], b"!");
        assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Timeout);
        assert_eq!(queue.read_until(&mut [], soon()), QueueRead::Bytes(0), "an empty buffer reads nothing and does not wait");
    }

    #[test]
    fn a_full_queue_drops_new_chunks_and_counts_them_instead_of_waiting() {
        let queue = ByteQueue::new(10);
        assert!(queue.push(vec![1; 6]));
        let started = Instant::now();
        assert!(!queue.push(vec![2; 6]), "6 + 6 bytes do not fit in 10");
        assert!(started.elapsed() < Duration::from_millis(500), "a full queue must not make the producer wait");
        assert_eq!(queue.dropped_bytes(), 6);
        assert!(queue.push(vec![3; 4]), "4 bytes still fit next to the 6 queued");
        assert_eq!(queue.dropped_bytes(), 6, "only the chunk that did not fit was counted");
    }

    #[test]
    fn an_empty_queue_takes_a_chunk_bigger_than_its_capacity() {
        let queue = ByteQueue::new(4);
        assert!(queue.push(vec![9; 100]));
        assert_eq!(queue.dropped_bytes(), 0);
        assert!(!queue.push(vec![9; 1]), "but nothing fits next to it");
        assert_eq!(queue.dropped_bytes(), 1);
    }

    #[test]
    fn the_stream_says_how_much_is_missing_before_the_next_chunk_it_keeps() {
        let queue = ByteQueue::new(8);
        assert!(queue.push(b"AAAAAA".to_vec()));
        assert!(!queue.push(b"BBBBBB".to_vec()));
        assert!(!queue.push(b"CCCC".to_vec()));
        assert_eq!(queue.dropped_bytes(), 10);
        let mut buf = [0u8; 64];
        assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(6), "the reader catches up");
        assert!(queue.push(b"DD".to_vec()));
        let rest = String::from_utf8(read_all(&queue)).unwrap();
        assert_eq!(rest, "\r\n[SSHelter dropped 10 bytes of output because the terminal fell behind]\r\nDD");
        assert!(queue.push(b"EE".to_vec()));
        assert_eq!(read_all(&queue), b"EE", "the gap is announced once");
    }

    #[test]
    fn closing_announces_a_gap_that_nothing_followed_and_then_reports_closed() {
        let queue = ByteQueue::new(4);
        queue.push(b"1234".to_vec());
        assert!(!queue.push(b"5678".to_vec()));
        queue.close();
        assert!(!queue.push(b"too late".to_vec()), "nothing is accepted after close");
        assert_eq!(queue.dropped_bytes(), 4, "a push after close is not a drop for lack of room");
        let mut buf = [0u8; 128];
        let mut all = Vec::new();
        loop {
            match queue.read_until(&mut buf, soon()) {
                QueueRead::Bytes(count) => all.extend_from_slice(&buf[..count]),
                QueueRead::Closed => break,
                QueueRead::Timeout => panic!("a closed queue must not time out"),
            }
        }
        assert_eq!(String::from_utf8(all).unwrap(), "1234\r\n[SSHelter dropped 4 bytes of output because the terminal fell behind]\r\n");
        assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Closed);
    }

    #[test]
    fn a_waiting_reader_wakes_when_a_chunk_arrives_and_when_the_queue_closes() {
        let queue = ByteQueue::new(1024);
        let producer = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                queue.push(b"hello".to_vec());
                std::thread::sleep(Duration::from_millis(100));
                queue.close();
            })
        };
        let started = Instant::now();
        let mut buf = [0u8; 16];
        assert_eq!(queue.read_until(&mut buf, None), QueueRead::Bytes(5));
        assert_eq!(queue.read_until(&mut buf, None), QueueRead::Closed);
        assert!(started.elapsed() < Duration::from_secs(5), "woken by the producer, not by a timeout");
        producer.join().unwrap();
    }

    #[test]
    fn the_first_exit_wins() {
        let cell = ExitCell::new();
        assert_eq!(cell.get(), None);
        cell.set(Exit::Code(3));
        cell.set(Exit::Signal("KILL".into()));
        assert_eq!(cell.get(), Some(Exit::Code(3)));
    }

    struct CountingInput {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        resizes: Arc<Mutex<Vec<(u16, u16)>>>,
        closes: Arc<AtomicUsize>,
    }

    impl ShellInput for CountingInput {
        fn write(&self, bytes: &[u8]) -> Result<(), SessionError> {
            locked(&self.writes).push(bytes.to_vec());
            Ok(())
        }
        fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
            locked(&self.resizes).push((cols, rows));
            Ok(())
        }
        fn close(&self) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_shell_forwards_to_its_input_reads_from_its_queue_and_finds_the_exit_when_the_read_ends() {
        let (writes, resizes, closes) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicUsize::new(0)));
        let input = CountingInput { writes: Arc::clone(&writes), resizes: Arc::clone(&resizes), closes: Arc::clone(&closes) };
        let (queue, cell) = (ByteQueue::new(1024), ExitCell::new());
        let shell = QueuedShell::new(Box::new(input), Arc::clone(&queue), Arc::clone(&cell));

        shell.write(b"ls\n").unwrap();
        shell.window_change(120, 40).unwrap();
        shell.close();
        assert_eq!(*locked(&writes), vec![b"ls\n".to_vec()]);
        assert_eq!(*locked(&resizes), vec![(120, 40)]);
        assert_eq!(closes.load(Ordering::SeqCst), 1);

        queue.push(b"prompt$ ".to_vec());
        let mut buf = [0u8; 32];
        assert_eq!(shell.read(&mut buf), Ok(8));
        assert_eq!(&buf[..8], b"prompt$ ");
        assert_eq!(shell.read_until(&mut buf, Instant::now() + Duration::from_millis(30)), QueueRead::Timeout);
        assert_eq!(shell.exited(), None);

        cell.set(Exit::Code(0));
        queue.close();
        assert_eq!(shell.read(&mut buf), Ok(0), "0 means the shell has ended");
        assert_eq!(shell.exited(), Some(Exit::Code(0)), "and the exit is there by then");
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate does not compile. The first error is `error[E0432]: unresolved imports `channel::ByteQueue`, `channel::ExitCell`, `channel::QueueRead`, `channel::QueuedShell`, `channel::ShellInput``, and the run ends with `error: could not compile `sshelter` (lib test) due to 60 previous errors` (the number of errors depends on the compiler; what matters is that the errors name items that do not exist yet).

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/channel.rs`: insert this above the `#[cfg(test)]` line, at the very top of the file, and leave one empty line between it and that line

```rust
//! The plumbing between an engine's channel reader and the thread that reads a shell (own-ssh spec §6.3): a bounded byte queue that
//! never holds the connection back, the cell that carries the shell's exit, and `QueuedShell`, the `ShellChannel` built from them.
//! Engine-neutral: the russh engine and the fake engine both fill the same pieces.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use super::error::SessionError;
use super::traits::ShellChannel;
use super::types::Exit;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What one read of the queue produced.
#[derive(Debug, PartialEq, Eq)]
pub enum QueueRead {
    /// This many bytes were copied into the caller's buffer.
    Bytes(usize),
    /// Nothing arrived before the deadline; the queue is still open.
    Timeout,
    /// The queue is closed and everything in it has been read.
    Closed,
}

struct QueueState {
    chunks: VecDeque<Vec<u8>>,
    /// How much of the first chunk has been read already.
    front_read: usize,
    /// Bytes queued and not read yet.
    bytes: usize,
    closed: bool,
    dropped: u64,
    /// Dropped bytes the stream does not mention yet.
    unannounced: u64,
}

/// A byte queue with a hard size. The producer (the engine's channel reader) must never wait: russh stalls the whole connection behind a
/// channel nobody reads. So when the reader is slower than the server (a paused terminal) and the queue is full, new chunks are
/// discarded and counted instead, and the connection keeps going. The stream says so: the next chunk that is kept is preceded by a
/// one-line notice that tells how many bytes are missing.
pub struct ByteQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
    capacity: usize,
}

impl ByteQueue {
    pub fn new(capacity: usize) -> Arc<ByteQueue> {
        Arc::new(ByteQueue {
            state: Mutex::new(QueueState { chunks: VecDeque::new(), front_read: 0, bytes: 0, closed: false, dropped: 0, unannounced: 0 }),
            ready: Condvar::new(),
            capacity,
        })
    }

    fn notice(bytes: u64) -> Vec<u8> {
        format!("\r\n[SSHelter dropped {bytes} bytes of output because the terminal fell behind]\r\n").into_bytes()
    }

    fn append(state: &mut QueueState, chunk: Vec<u8>) {
        state.bytes += chunk.len();
        state.chunks.push_back(chunk);
    }

    /// Appends `chunk` unless the queue is closed or would grow past its capacity. An empty queue accepts any chunk, so progress is always
    /// possible. Returns false when the chunk was not kept; a chunk dropped for lack of room is added to `dropped_bytes`.
    pub fn push(&self, chunk: Vec<u8>) -> bool {
        if chunk.is_empty() {
            return true;
        }
        let mut state = locked(&self.state);
        if state.closed {
            return false;
        }
        if state.bytes != 0 && state.bytes + chunk.len() > self.capacity {
            state.dropped += chunk.len() as u64;
            state.unannounced += chunk.len() as u64;
            return false;
        }
        if state.unannounced > 0 {
            let notice = ByteQueue::notice(state.unannounced);
            state.unannounced = 0;
            ByteQueue::append(&mut state, notice);
        }
        ByteQueue::append(&mut state, chunk);
        self.ready.notify_one();
        true
    }

    /// No more chunks will come. What is queued can still be read (after a notice, if bytes were dropped since the last one).
    pub fn close(&self) {
        let mut state = locked(&self.state);
        if state.closed {
            return;
        }
        if state.unannounced > 0 {
            let notice = ByteQueue::notice(state.unannounced);
            state.unannounced = 0;
            ByteQueue::append(&mut state, notice);
        }
        state.closed = true;
        self.ready.notify_all();
    }

    /// Copies queued bytes into `buf` (at most `buf.len()`, possibly part of a chunk), waiting until `deadline` for some to arrive; with
    /// no deadline it waits for as long as the queue is open and empty. An empty `buf` reads nothing.
    pub fn read_until(&self, buf: &mut [u8], deadline: Option<Instant>) -> QueueRead {
        if buf.is_empty() {
            return QueueRead::Bytes(0);
        }
        let mut state = locked(&self.state);
        loop {
            if let Some(front) = state.chunks.front() {
                let taken = (front.len() - state.front_read).min(buf.len());
                buf[..taken].copy_from_slice(&front[state.front_read..state.front_read + taken]);
                let finished = state.front_read + taken == front.len();
                state.bytes -= taken;
                if finished {
                    state.chunks.pop_front();
                    state.front_read = 0;
                } else {
                    state.front_read += taken;
                }
                return QueueRead::Bytes(taken);
            }
            if state.closed {
                return QueueRead::Closed;
            }
            state = match deadline {
                None => self.ready.wait(state).unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return QueueRead::Timeout;
                    }
                    self.ready.wait_timeout(state, deadline - now).unwrap_or_else(PoisonError::into_inner).0
                }
            };
        }
    }

    /// How many bytes were discarded because the reader fell behind.
    pub fn dropped_bytes(&self) -> u64 {
        locked(&self.state).dropped
    }
}

/// Holds how a shell ended, once. The first value set wins.
pub struct ExitCell {
    value: Mutex<Option<Exit>>,
}

impl ExitCell {
    pub fn new() -> Arc<ExitCell> {
        Arc::new(ExitCell { value: Mutex::new(None) })
    }

    pub fn set(&self, exit: Exit) {
        let mut value = locked(&self.value);
        if value.is_none() {
            *value = Some(exit);
        }
    }

    pub fn get(&self) -> Option<Exit> {
        locked(&self.value).clone()
    }
}

/// The write side of a shell, supplied by the engine.
pub trait ShellInput: Send + Sync {
    /// Sends `bytes` to the shell's stdin. May wait while the connection's flow control makes the engine wait; the engine bounds that.
    fn write(&self, bytes: &[u8]) -> Result<(), SessionError>;
    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError>;
    /// Closes the channel (the connection stays up).
    fn close(&self);
}

/// A `ShellChannel` made of an engine's `ShellInput`, the `ByteQueue` its channel reader fills and the `ExitCell` it sets. The reader
/// sets the exit first and closes the queue second, so a `read` that returns 0 always finds `exited()` filled in.
pub struct QueuedShell {
    input: Box<dyn ShellInput>,
    output: Arc<ByteQueue>,
    exit: Arc<ExitCell>,
}

impl QueuedShell {
    pub fn new(input: Box<dyn ShellInput>, output: Arc<ByteQueue>, exit: Arc<ExitCell>) -> QueuedShell {
        QueuedShell { input, output, exit }
    }

    /// `ShellChannel::read` with a deadline instead of an open end: for tests and for callers that must also watch something else.
    pub fn read_until(&self, buf: &mut [u8], deadline: Instant) -> QueueRead {
        self.output.read_until(buf, Some(deadline))
    }
}

impl ShellChannel for QueuedShell {
    fn write(&self, data: &[u8]) -> Result<(), SessionError> {
        self.input.write(data)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, SessionError> {
        match self.output.read_until(buf, None) {
            QueueRead::Bytes(count) => Ok(count),
            QueueRead::Closed | QueueRead::Timeout => Ok(0),
        }
    }

    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
        self.input.window_change(cols, rows)
    }

    fn exited(&self) -> Option<Exit> {
        self.exit.get()
    }

    fn close(&self) {
        self.input.close()
    }
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 17 passed; 0 failed`. The run takes about 10 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1434 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 104 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/channel.rs src-tauri/src/ssh/mod.rs
git commit -m "feat(ssh): add the bounded shell output queue and the queued shell"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 4: `FakeEngine`, the scripted engine for the later plans' tests

**Files:**
- Create: `src-tauri/src/ssh/fake.rs` (with its tests)
- Modify: `src-tauri/src/ssh/mod.rs`

**Interfaces:**
- Consumes (Tasks 2 and 3): every trait, type and error of the interface, `ByteQueue`, `ExitCell`, `QueuedShell`, `ShellInput`; and the existing `crate::sync::slot_rules::test_keys` (`PLAIN_PUBLIC`, a real Ed25519 public key line).
- Produces (test code only: `#[cfg(test)] pub mod fake;`, used as `crate::ssh::fake::…` by the tests of plans 1b–1d):

  - `ssh/fake.rs`:
    - `pub enum FakeLogin`
    - `pub enum FakeEvent`
    - `pub fn default_server_key() -> HostKey`
    - `pub struct FakeEngine`
    - (impl FakeEngine) `pub fn new() -> FakeEngine`
    - (impl FakeEngine) `pub fn with_host_key(self, key: HostKey) -> FakeEngine`
    - (impl FakeEngine) `pub fn with_host_key_for(self, alias: &str, key: HostKey) -> FakeEngine`
    - (impl FakeEngine) `pub fn with_login(self, login: FakeLogin) -> FakeEngine`
    - (impl FakeEngine) `pub fn with_login_for(self, alias: &str, login: FakeLogin) -> FakeEngine`
    - (impl FakeEngine) `pub fn failing_with(self, error: ConnectError) -> FakeEngine`
    - (impl FakeEngine) `pub fn with_exec(self, command: &str, result: ExecResult) -> FakeEngine`
    - (impl FakeEngine) `pub fn with_shell_output(self, chunk: &[u8]) -> FakeEngine`
    - (impl FakeEngine) `pub fn with_shell_exit(self, exit: Exit) -> FakeEngine`
    - (impl FakeEngine) `pub fn with_shell_ending_at_once(self) -> FakeEngine`
    - (impl FakeEngine) `pub fn disconnecting_with(self, reason: DisconnectReason) -> FakeEngine`
    - (impl FakeEngine) `pub fn events(&self) -> Vec<FakeEvent>`

What shapes this task:
- `FakeEngine` implements `SshEngine`, `Session` and `ShellChannel` with a script instead of a network, so the tests of the broker, the MCP adapter and the CLI never need an sshd. It is built with `with_*` methods; the defaults are a server that presents `default_server_key()`, accepts every login, runs every command to exit code 0 with no output, opens shells that print nothing and exit with code 0 when closed, and never drops.
- It behaves like the real engine where the callers can tell: a chain with no hops or a repeated host is `BadJumpChain`; each hop's key goes through the caller's `HostKeyPolicy` and becomes `HostKeyUnknown`/`HostKeyMismatch` with the key the script presented; a login really calls the caller's `AuthSource` (`sign`, `password`, `interactive`) and a refusal, a missing password or a cancelled prompt ends as `AuthFailed` or `AuthAbandoned` exactly as the real engine reports it (the broker's tests therefore exercise the same calls); `exec` returns the scripted result for exactly that command line, cut to the caller's `output_cap` with `truncated` set and `ended` changed to `Truncated`, as the real engine does; `events()` lists everything the code under test did, in order.
- A shell is a `QueuedShell` over the same `ByteQueue` and `ExitCell` as the real one, so ordering and the "exit is set before the queue closes" rule are the same.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/mod.rs
+++ b/src-tauri/src/ssh/mod.rs
@@ -6,6 +6,8 @@
 
 mod channel;
 mod error;
+#[cfg(test)]
+pub mod fake;
 mod traits;
 mod types;
 
```

`src-tauri/src/ssh/fake.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::error::AuthError;
    use crate::ssh::types::{HostId, Secret, Signature};
    use std::time::Instant;
    use zeroize::Zeroizing;

    const SHORT: Duration = Duration::from_millis(100);

    fn hop(alias: &str) -> Hop {
        Hop::new(&format!("id-{alias}"), alias, &format!("{alias}.example.com"), 22, "deploy", AuthMethod::Key { key_id: format!("key-{alias}") })
    }

    /// Pins one fingerprint; everything else is unknown, or a mismatch when `pinned` is set.
    struct Policy {
        accepted: Option<String>,
        pinned: Option<HostKey>,
    }

    impl HostKeyPolicy for Policy {
        fn check(&self, _hop: &HopRef, key: &HostKey) -> HostKeyVerdict {
            match (&self.accepted, &self.pinned) {
                (Some(fingerprint), _) if *fingerprint == key.fingerprint => HostKeyVerdict::Pinned,
                (_, Some(pinned)) => HostKeyVerdict::Mismatch { pinned: pinned.clone() },
                _ => HostKeyVerdict::Unknown,
            }
        }
    }

    fn trusting() -> Policy {
        Policy { accepted: Some(default_server_key().fingerprint), pinned: None }
    }

    /// Records what it was asked and answers from fixed values.
    #[derive(Default)]
    struct Auth {
        password: Option<String>,
        answers: Option<Vec<String>>,
        sign_fails: bool,
        asked: Mutex<Vec<String>>,
    }

    impl AuthSource for Auth {
        fn public_key(&self, key_id: &str) -> Option<String> {
            locked(&self.asked).push(format!("public_key {key_id}"));
            Some(test_keys::PLAIN_PUBLIC.to_string())
        }
        fn sign(&self, key_id: &str, _data: &[u8], _rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
            locked(&self.asked).push(format!("sign {key_id}"));
            if self.sign_fails {
                Err(AuthError::Refused("the vault is locked".into()))
            } else {
                Ok(Signature(vec![1, 2, 3]))
            }
        }
        fn password(&self, hop: &HopRef) -> Option<Secret> {
            locked(&self.asked).push(format!("password {}", hop.alias));
            self.password.clone().map(Zeroizing::new)
        }
        fn interactive(&self, hop: &HopRef, prompts: &[Prompt], _deadline: Instant) -> Option<Vec<Secret>> {
            locked(&self.asked).push(format!("interactive {} {}", hop.alias, prompts.len()));
            self.answers.clone().map(|answers| answers.into_iter().map(Zeroizing::new).collect())
        }
    }

    fn connect(engine: &FakeEngine, target: &Target, auth: &Auth) -> Result<Box<dyn Session>, ConnectError> {
        engine.connect(target, &trusting(), auth)
    }

    fn direct(alias: &str) -> Target {
        Target { hops: vec![hop(alias)] }
    }

    fn exec(session: &dyn Session, command: &str) -> ExecResult {
        session.exec(command, SHORT, 1024).unwrap()
    }

    #[test]
    fn by_default_everything_succeeds_and_the_calls_are_recorded() {
        let engine = FakeEngine::new();
        let session = connect(&engine, &direct("web"), &Auth::default()).expect("connects");
        assert!(session.is_alive());
        let result = session.exec("uptime", SHORT, 4096).unwrap();
        assert_eq!((result.ended, result.exit_code, result.truncated), (Ended::Exited, Some(0), false));
        assert!(result.stdout.is_empty() && result.stderr.is_empty());
        assert_eq!(
            engine.events(),
            vec![FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::Exec { command: "uptime".into(), timeout: SHORT, output_cap: 4096 }]
        );
    }

    #[test]
    fn a_scripted_exec_result_comes_back_for_exactly_that_command_and_is_cut_to_the_cap() {
        let killed = ExecResult { ended: Ended::Signaled, exit_code: None, signal: Some("KILL".into()), stdout: b"partial".to_vec(), stderr: vec![], truncated: false };
        let engine = FakeEngine::new().with_exec("sleep 99", killed.clone());
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        assert_eq!(exec(session.as_ref(), "sleep 99"), killed);
        assert_eq!(exec(session.as_ref(), "sleep 98").exit_code, Some(0));

        let cut = session.exec("sleep 99", SHORT, 4).unwrap();
        assert_eq!((cut.stdout.as_slice(), cut.truncated, cut.ended, cut.signal), (b"part".as_slice(), true, Ended::Truncated, None));
    }

    #[test]
    fn the_host_key_verdicts_become_the_connect_errors_the_real_engine_gives() {
        let engine = FakeEngine::new();
        let unknown = Policy { accepted: None, pinned: None };
        match engine.connect(&direct("web"), &unknown, &Auth::default()) {
            Err(ConnectError::HostKeyUnknown { hop, key }) => assert_eq!((hop.alias.as_str(), key), ("web", default_server_key())),
            other => panic!("expected HostKeyUnknown, got {:?}", other.err()),
        }
        let other_key = HostKey { algorithm: "ssh-ed25519".into(), public_key: vec![9], fingerprint: "SHA256:other".into() };
        let changed = Policy { accepted: None, pinned: Some(other_key.clone()) };
        match engine.connect(&direct("web"), &changed, &Auth::default()) {
            Err(ConnectError::HostKeyMismatch { key, pinned, .. }) => assert_eq!((key, pinned), (default_server_key(), other_key)),
            other => panic!("expected HostKeyMismatch, got {:?}", other.err()),
        }
        assert_eq!(engine.events(), vec![], "a failed connect leaves no event");
    }

    #[test]
    fn a_password_login_asks_the_auth_source_and_checks_the_answer() {
        let engine = FakeEngine::new().with_login(FakeLogin::Password("hunter2".into()));
        let right = Auth { password: Some("hunter2".into()), ..Auth::default() };
        assert!(connect(&engine, &direct("web"), &right).is_ok());
        assert_eq!(*locked(&right.asked), vec!["password web".to_string()]);

        let wrong = Auth { password: Some("letmein".into()), ..Auth::default() };
        assert!(matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { tried, .. }) if tried == [AuthMethod::Password]));

        let none = Auth::default();
        assert!(matches!(connect(&engine, &direct("web"), &none), Err(ConnectError::AuthFailed { tried, .. }) if tried.is_empty()), "no password: the method is skipped");
    }

    #[test]
    fn a_keyboard_interactive_login_sends_the_prompts_and_compares_the_answers() {
        let prompts = vec![Prompt { text: "Verification code: ".into(), echo: true }];
        let engine = FakeEngine::new().with_login(FakeLogin::Interactive { prompts, answers: vec!["123456".into()] });
        let right = Auth { answers: Some(vec!["123456".into()]), ..Auth::default() };
        assert!(connect(&engine, &direct("web"), &right).is_ok());
        assert_eq!(*locked(&right.asked), vec!["interactive web 1".to_string()]);
        let wrong = Auth { answers: Some(vec!["000000".into()]), ..Auth::default() };
        assert!(matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { .. })));
        assert!(matches!(connect(&engine, &direct("web"), &Auth::default()), Err(ConnectError::AuthAbandoned { .. })), "a cancelled prompt abandons the login");
    }

    #[test]
    fn a_signature_login_asks_for_the_key_of_the_hop_and_a_refusal_abandons_it() {
        let engine = FakeEngine::new().with_login(FakeLogin::Signature);
        let auth = Auth::default();
        assert!(connect(&engine, &direct("web"), &auth).is_ok());
        assert_eq!(*locked(&auth.asked), vec!["sign key-web".to_string()]);
        let locked_vault = Auth { sign_fails: true, ..Auth::default() };
        assert!(matches!(connect(&engine, &direct("web"), &locked_vault), Err(ConnectError::AuthAbandoned { .. })));
    }

    #[test]
    fn a_jump_chain_is_checked_hop_by_hop_and_each_hop_can_be_scripted() {
        let engine = FakeEngine::new().with_login_for("bastion", FakeLogin::Refuse);
        let target = Target { hops: vec![hop("bastion"), hop("db")] };
        match connect(&engine, &target, &Auth::default()) {
            Err(ConnectError::AuthFailed { hop, .. }) => assert_eq!(hop.alias, "bastion"),
            other => panic!("expected the bastion to refuse, got {:?}", other.err()),
        }
        let engine = FakeEngine::new();
        assert!(connect(&engine, &target, &Auth::default()).is_ok());
        assert_eq!(engine.events(), vec![FakeEvent::Connect { aliases: vec!["bastion".into(), "db".into()] }]);
    }

    #[test]
    fn a_chain_with_a_repeated_host_or_no_host_is_a_bad_jump_chain() {
        let engine = FakeEngine::new();
        let looping = Target { hops: vec![hop("web"), hop("web")] };
        assert!(matches!(connect(&engine, &looping, &Auth::default()), Err(ConnectError::BadJumpChain { .. })));
        assert!(matches!(connect(&engine, &Target { hops: vec![] }, &Auth::default()), Err(ConnectError::BadJumpChain { .. })));
    }

    #[test]
    fn a_scripted_connect_failure_is_returned_as_it_is() {
        let error = ConnectError::Unreachable { hop: hop("web").reference(), reason: "connection refused".into() };
        let engine = FakeEngine::new().failing_with(error.clone());
        assert_eq!(connect(&engine, &direct("web"), &Auth::default()).err(), Some(error));
    }

    fn read_some(shell: &dyn ShellChannel) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let count = shell.read(&mut buf).unwrap();
        buf[..count].to_vec()
    }

    #[test]
    fn a_shell_prints_its_script_records_the_input_and_ends_when_closed() {
        let engine = FakeEngine::new().with_shell_output(b"welcome\r\n").with_shell_exit(Exit::Code(7));
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        let shell = session.shell(Pty { term: "xterm-256color".into(), cols: 80, rows: 24 }).unwrap();
        assert_eq!(read_some(shell.as_ref()), b"welcome\r\n");
        shell.write(b"ls\n").unwrap();
        shell.window_change(100, 30).unwrap();
        assert_eq!(shell.exited(), None);
        shell.close();
        assert_eq!(read_some(shell.as_ref()), b"", "a closed shell reads 0");
        assert_eq!(shell.exited(), Some(Exit::Code(7)));
        assert_eq!(
            engine.events(),
            vec![
                FakeEvent::Connect { aliases: vec!["web".into()] },
                FakeEvent::ShellOpened { term: "xterm-256color".into(), cols: 80, rows: 24 },
                FakeEvent::ShellInput(b"ls\n".to_vec()),
                FakeEvent::WindowChange { cols: 100, rows: 30 },
                FakeEvent::ShellClosed,
            ]
        );
    }

    #[test]
    fn a_shell_that_ends_at_once_reports_its_exit_after_the_output() {
        let engine = FakeEngine::new().with_shell_output(b"bye\r\n").with_shell_exit(Exit::Signal("HUP".into())).with_shell_ending_at_once();
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        let shell = session.shell(Pty { term: "dumb".into(), cols: 80, rows: 24 }).unwrap();
        assert_eq!(read_some(shell.as_ref()), b"bye\r\n");
        assert_eq!(read_some(shell.as_ref()), b"");
        assert_eq!(shell.exited(), Some(Exit::Signal("HUP".into())));
    }

    #[test]
    fn a_scripted_disconnect_makes_every_call_fail_and_say_why() {
        let reason = DisconnectReason { hop: hop("web").reference(), kind: DisconnectKind::KeepaliveTimeout, detail: "no answer".into() };
        let engine = FakeEngine::new().disconnecting_with(reason.clone());
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        assert!(!session.is_alive());
        assert_eq!(session.disconnect_reason(), Some(reason));
        assert_eq!(session.exec("uptime", SHORT, 16), Err(SessionError::Closed));
        assert!(matches!(session.shell(Pty { term: "dumb".into(), cols: 80, rows: 24 }), Err(SessionError::Closed)));
    }

    #[test]
    fn closing_is_recorded_once() {
        let engine = FakeEngine::new();
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        assert!(session.is_alive() && session.disconnect_reason().is_none());
        session.close();
        session.close();
        assert!(!session.is_alive());
        let reason = session.disconnect_reason().expect("closed");
        assert_eq!((reason.kind, reason.hop.alias.as_str(), reason.hop.id), (DisconnectKind::ClosedByUs, "web", HostId::from("id-web")));
        assert_eq!(engine.events(), vec![FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::Closed]);
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate does not compile. The first error is `error[E0425]: cannot find type `Duration` in this scope`, and the run ends with `error: could not compile `sshelter` (lib test) due to 100 previous errors` (the number of errors depends on the compiler; what matters is that the errors name items that do not exist yet).

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/fake.rs`: insert this above the `#[cfg(test)]` line, at the very top of the file, and leave one empty line between it and that line

```rust
//! A scripted engine for the tests of the broker, the MCP adapter and the CLI (own-ssh spec §12). It implements the same traits as the
//! russh engine and touches no network: the "server" is a script, and what the code under test did is recorded for the assertions.
//! Test code only (`#[cfg(test)]` in `ssh/mod.rs`).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::channel::{ByteQueue, ExitCell, QueuedShell, ShellInput};
use super::error::{ConnectError, SessionError};
use super::traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
use super::types::{AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostKey, HostKeyVerdict, Prompt, Pty, RsaHash, Target};
use crate::sync::slot_rules::test_keys;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the fake server answers a login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeLogin {
    /// Every login succeeds; the auth source is not consulted.
    Accept,
    /// Every method is refused.
    Refuse,
    /// The hop's key method: the fake asks the auth source for a signature over a fixed challenge and accepts any signature it gets
    /// (it has no public key to verify with). A signing error abandons the login, as in the real engine.
    Signature,
    /// The fake asks `AuthSource::password` and accepts only `expected`. `None` skips the method, so nothing was tried and the login fails.
    Password(String),
    /// The fake sends `prompts` to `AuthSource::interactive` and accepts only `answers`. `None` abandons the login.
    Interactive { prompts: Vec<Prompt>, answers: Vec<String> },
}

/// Everything the code under test did to the fake, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeEvent {
    /// A successful connect: the alias of every hop, jumps first.
    Connect { aliases: Vec<String> },
    Exec { command: String, timeout: Duration, output_cap: usize },
    ShellOpened { term: String, cols: u16, rows: u16 },
    ShellInput(Vec<u8>),
    WindowChange { cols: u16, rows: u16 },
    ShellClosed,
    Closed,
}

/// The key a fake server presents unless the script says otherwise: the ed25519 key of `test_keys::plain()`.
pub fn default_server_key() -> HostKey {
    HostKey::from_openssh_line(test_keys::PLAIN_PUBLIC).expect("the test key parses")
}

struct Script {
    host_key: HostKey,
    host_keys: HashMap<String, HostKey>,
    login: FakeLogin,
    logins: HashMap<String, FakeLogin>,
    connect_error: Option<ConnectError>,
    exec: HashMap<String, ExecResult>,
    shell_output: Vec<Vec<u8>>,
    shell_exit: Exit,
    shell_ends_at_once: bool,
    disconnect: Option<DisconnectReason>,
}

struct Shared {
    script: Mutex<Script>,
    events: Mutex<Vec<FakeEvent>>,
}

impl Shared {
    fn record(&self, event: FakeEvent) {
        locked(&self.events).push(event);
    }
}

/// The scripted engine. Build it with the `with_*` methods; the defaults are: the server presents `default_server_key()`, every login
/// succeeds, every command exits 0 with no output, a shell prints nothing and exits with code 0 when it is closed, the connection never drops.
pub struct FakeEngine {
    shared: Arc<Shared>,
}

impl Default for FakeEngine {
    fn default() -> Self {
        FakeEngine::new()
    }
}

impl FakeEngine {
    pub fn new() -> FakeEngine {
        let script = Script {
            host_key: default_server_key(),
            host_keys: HashMap::new(),
            login: FakeLogin::Accept,
            logins: HashMap::new(),
            connect_error: None,
            exec: HashMap::new(),
            shell_output: Vec::new(),
            shell_exit: Exit::Code(0),
            shell_ends_at_once: false,
            disconnect: None,
        };
        FakeEngine { shared: Arc::new(Shared { script: Mutex::new(script), events: Mutex::new(Vec::new()) }) }
    }

    fn script(self, change: impl FnOnce(&mut Script)) -> FakeEngine {
        change(&mut locked(&self.shared.script));
        self
    }

    /// The key every fake server presents.
    pub fn with_host_key(self, key: HostKey) -> FakeEngine {
        self.script(|script| script.host_key = key)
    }

    /// The key the server of one host (by alias) presents, for jump chains.
    pub fn with_host_key_for(self, alias: &str, key: HostKey) -> FakeEngine {
        self.script(|script| {
            script.host_keys.insert(alias.to_string(), key);
        })
    }

    pub fn with_login(self, login: FakeLogin) -> FakeEngine {
        self.script(|script| script.login = login)
    }

    /// How the server of one host (by alias) answers a login, for jump chains.
    pub fn with_login_for(self, alias: &str, login: FakeLogin) -> FakeEngine {
        self.script(|script| {
            script.logins.insert(alias.to_string(), login);
        })
    }

    /// `connect` fails with this error before anything else happens.
    pub fn failing_with(self, error: ConnectError) -> FakeEngine {
        self.script(|script| script.connect_error = Some(error))
    }

    /// What `exec(command, …)` returns for exactly this command line (cut to the caller's `output_cap`, as the real engine does).
    pub fn with_exec(self, command: &str, result: ExecResult) -> FakeEngine {
        self.script(|script| {
            script.exec.insert(command.to_string(), result);
        })
    }

    /// A chunk the next shells print as soon as they open.
    pub fn with_shell_output(self, chunk: &[u8]) -> FakeEngine {
        self.script(|script| script.shell_output.push(chunk.to_vec()))
    }

    /// How shells end (when they are closed, or at once with `with_shell_ending_at_once`).
    pub fn with_shell_exit(self, exit: Exit) -> FakeEngine {
        self.script(|script| script.shell_exit = exit)
    }

    /// Shells end as soon as their scripted output has been produced, as a typed `exit` would.
    pub fn with_shell_ending_at_once(self) -> FakeEngine {
        self.script(|script| script.shell_ends_at_once = true)
    }

    /// Every session connects fine and is over right away, for this reason.
    pub fn disconnecting_with(self, reason: DisconnectReason) -> FakeEngine {
        self.script(|script| script.disconnect = Some(reason))
    }

    /// Everything the code under test has done so far.
    pub fn events(&self) -> Vec<FakeEvent> {
        locked(&self.shared.events).clone()
    }
}

fn check_chain(target: &Target) -> Result<(), ConnectError> {
    if target.hops.is_empty() {
        return Err(ConnectError::BadJumpChain { why: "the target has no hosts".to_string() });
    }
    let mut seen = HashSet::new();
    for hop in &target.hops {
        if !seen.insert(&hop.id) {
            return Err(ConnectError::BadJumpChain { why: format!("{} appears twice", hop.alias) });
        }
    }
    Ok(())
}

impl SshEngine for FakeEngine {
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
        check_chain(target)?;
        let (login_default, logins, key_default, keys, scripted_error) = {
            let script = locked(&self.shared.script);
            (script.login.clone(), script.logins.clone(), script.host_key.clone(), script.host_keys.clone(), script.connect_error.clone())
        };
        if let Some(error) = scripted_error {
            return Err(error);
        }
        for hop in &target.hops {
            let reference = hop.reference();
            let key = keys.get(&hop.alias).unwrap_or(&key_default).clone();
            match host_keys.check(&reference, &key) {
                HostKeyVerdict::Pinned => {}
                HostKeyVerdict::Unknown => return Err(ConnectError::HostKeyUnknown { hop: reference, key }),
                HostKeyVerdict::Mismatch { pinned } => return Err(ConnectError::HostKeyMismatch { hop: reference, key, pinned }),
            }
            fake_login(hop, logins.get(&hop.alias).unwrap_or(&login_default), auth)?;
        }
        self.shared.record(FakeEvent::Connect { aliases: target.hops.iter().map(|hop| hop.alias.clone()).collect() });
        let disconnect = locked(&self.shared.script).disconnect.clone();
        let destination = target.hops.last().map(Hop::reference).ok_or_else(|| ConnectError::BadJumpChain { why: "the target has no hosts".to_string() })?;
        Ok(Box::new(FakeSession { shared: Arc::clone(&self.shared), destination, closed: Mutex::new(disconnect) }))
    }
}

fn fake_login(hop: &Hop, login: &FakeLogin, auth: &dyn AuthSource) -> Result<(), ConnectError> {
    let reference = hop.reference();
    let refused = |tried: Vec<AuthMethod>| ConnectError::AuthFailed { hop: reference.clone(), tried, reason: String::new() };
    let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
    match login {
        FakeLogin::Accept => Ok(()),
        FakeLogin::Refuse => Err(refused(hop.auth_sequence())),
        FakeLogin::Signature => {
            let AuthMethod::Key { key_id } = &hop.auth else { return Err(refused(vec![])) };
            auth.sign(key_id, b"fake-challenge", Some(RsaHash::Sha512)).map(|_| ()).map_err(|error| abandoned(&error.to_string()))
        }
        FakeLogin::Password(expected) => match auth.password(&reference) {
            None => Err(refused(vec![])),
            Some(given) if given.as_str() == expected => Ok(()),
            Some(_) => Err(refused(vec![AuthMethod::Password])),
        },
        FakeLogin::Interactive { prompts, answers } => {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            match auth.interactive(&reference, prompts, deadline) {
                None => Err(abandoned("the prompt was cancelled")),
                Some(given) if given.iter().map(|answer| answer.as_str()).eq(answers.iter().map(String::as_str)) => Ok(()),
                Some(_) => Err(refused(vec![AuthMethod::Interactive])),
            }
        }
    }
}

struct FakeSession {
    shared: Arc<Shared>,
    destination: HopRef,
    closed: Mutex<Option<DisconnectReason>>,
}

struct FakeShellInput {
    shared: Arc<Shared>,
    queue: Arc<ByteQueue>,
    exit: Arc<ExitCell>,
}

impl ShellInput for FakeShellInput {
    fn write(&self, bytes: &[u8]) -> Result<(), SessionError> {
        self.shared.record(FakeEvent::ShellInput(bytes.to_vec()));
        Ok(())
    }

    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
        self.shared.record(FakeEvent::WindowChange { cols, rows });
        Ok(())
    }

    fn close(&self) {
        self.shared.record(FakeEvent::ShellClosed);
        self.exit.set(locked(&self.shared.script).shell_exit.clone());
        self.queue.close();
    }
}

/// `result` with its output cut to `cap` bytes (stdout first, then stderr); when something was cut, `truncated` is set and the command
/// ended as `Truncated`, as in the real engine.
fn capped(mut result: ExecResult, cap: usize) -> ExecResult {
    if result.stdout.len() + result.stderr.len() > cap {
        result.stdout.truncate(cap);
        result.stderr.truncate(cap - result.stdout.len());
        result.truncated = true;
        result.ended = Ended::Truncated;
        result.exit_code = None;
        result.signal = None;
    }
    result
}

impl Session for FakeSession {
    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
        if !self.is_alive() {
            return Err(SessionError::Closed);
        }
        self.shared.record(FakeEvent::ShellOpened { term: pty.term, cols: pty.cols, rows: pty.rows });
        let (output, exit, ends_at_once) = {
            let script = locked(&self.shared.script);
            (script.shell_output.clone(), script.shell_exit.clone(), script.shell_ends_at_once)
        };
        let (queue, cell) = (ByteQueue::new(1024 * 1024), ExitCell::new());
        for chunk in output {
            queue.push(chunk);
        }
        if ends_at_once {
            cell.set(exit);
            queue.close();
        }
        let input = FakeShellInput { shared: Arc::clone(&self.shared), queue: Arc::clone(&queue), exit: Arc::clone(&cell) };
        Ok(Box::new(QueuedShell::new(Box::new(input), queue, cell)))
    }

    fn exec(&self, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError> {
        if !self.is_alive() {
            return Err(SessionError::Closed);
        }
        self.shared.record(FakeEvent::Exec { command: command.to_string(), timeout, output_cap });
        let scripted = locked(&self.shared.script).exec.get(command).cloned();
        let result = scripted.unwrap_or(ExecResult {
            ended: Ended::Exited,
            exit_code: Some(0),
            signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
        });
        Ok(capped(result, output_cap))
    }

    fn is_alive(&self) -> bool {
        locked(&self.closed).is_none()
    }

    fn disconnect_reason(&self) -> Option<DisconnectReason> {
        locked(&self.closed).clone()
    }

    fn close(&self) {
        let mut closed = locked(&self.closed);
        if closed.is_none() {
            *closed = Some(DisconnectReason { hop: self.destination.clone(), kind: DisconnectKind::ClosedByUs, detail: "closed by the caller".to_string() });
            self.shared.record(FakeEvent::Closed);
        }
    }
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 30 passed; 0 failed`. The run takes about 10 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1447 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 104 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/fake.rs src-tauri/src/ssh/mod.rs
git commit -m "test(ssh): add the scripted FakeEngine for broker, MCP and CLI tests"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 5: The scratch-sshd harness on `crate::process`

**Files:**
- Modify: `src-tauri/src/ssh/mod.rs`
- Create: `src-tauri/src/ssh/testing/harness.rs` (with its tests)
- Create: `src-tauri/src/ssh/testing/mod.rs`

**Interfaces:**
- Consumes: the existing `crate::process::spawn(&mut Command) -> io::Result<Child>` (every spawn in `src-tauri/` goes through it, see `clippy.toml`).
- Produces (test code only; `#[cfg(test)] pub mod testing;`):

  - `ssh/testing/harness.rs`:
    - `pub(super) fn run_within(command: &mut Command, timeout: Duration) -> Result<Output, String>`
    - `pub struct Tools`
    - `pub fn tools() -> Option<Tools>`
    - `pub enum KeyKind`
    - `pub struct TestKey`
    - `pub fn generate_key(tools: &Tools, dir: &Path, name: &str, kind: KeyKind) -> TestKey`
    - `pub struct SshdOptions`
    - `pub struct Sshd`
    - (impl Sshd) `pub fn start(tools: &Tools, options: SshdOptions) -> Sshd`
    - (impl Sshd) `pub fn host_public_line(&self) -> &str`
    - (impl Sshd) `pub fn log(&self) -> String`
    - `pub fn system_ssh(tools: &Tools, sshd: &Sshd, identity: &Path, remote_command: &str) -> Output`
  - `ssh/testing/mod.rs`:
    - `pub mod harness;`
    - `pub fn fact(key: &str, value: impl std::fmt::Display)`

  `fact` prints `FACT <key> = <value>` to stderr, so that a run with `-- --nocapture` can be grepped for the numbers a report needs.

What shapes this task:
- This is the phase-0 spike's scratch-sshd harness (`spike/russh/src/harness.rs`, which the last task deletes), ported onto `crate::process` and into the app's test support. Each test starts its **own** sshd in a temp directory: free port first (a socket bound to port 0; `Port 0` in the config is rejected), a throwaway host key and `authorized_keys` made by `ssh-keygen`, a config that `sshd -t` checks, then `sshd -D -e -f <config>` as the current user with `PermitUserRC no`, `UsePAM no`, public-key login only and `LogLevel ERROR`. Nothing reads or writes the real `~/.ssh`; the system `ssh` client that `system_ssh` runs gets `-F /dev/null`.
- `tools()` looks for `sshd` (an absolute path is required because sshd re-executes itself; `/usr/sbin` is not on a normal user's `PATH`), `ssh` and `ssh-keygen`. Missing tools print `skipped` and the test returns early, unless `SSHELTER_REQUIRE_OPENSSH=1` (CI, and the commands in this plan) turns that into a failure. Windows never runs scratch-sshd tests (Win32-OpenSSH's sshd must run as a service); there the answer is always a skip (Task 13 tests the Windows server another way).
- The one real change from the spike is the bounded runner: the spike killed a tool that overran its deadline and then waited for its output pipes to reach end-of-file, which lasts as long as any grandchild that inherited them (the spike's "deferred Minor 2"). `run_within` here gives the readers `PIPE_GRACE` (2 s) after the kill and then uses what it has; `a_process_that_keeps_the_pipes_open_after_the_kill_does_not_hold_the_runner` is the test.
- **Keys the vault cannot read (found while testing this).** `ssh-key` 0.6.7, the parser behind `Material::open`, cannot read an ECDSA private key whose secret number starts with a zero byte: OpenSSH writes the number in its shortest form and the parser insists on the full length (`length invalid`, which `open` reports as `Unreadable`). Measured with ssh-keygen from OpenSSH 10.3p1: 5 of 1500 P-256 keys, 3 of 600 P-384 keys and 77 of 300 P-521 keys. A harness that signs with a freshly made ECDSA key through the vault would therefore fail one run in about 256 for a reason that has nothing to do with the engine, which is how it was found (a whole-suite run failed once in `an_ecdsa_p256_key_in_the_vault_logs_in` with `the vault opens the key: Unreadable`). `generate_key` throws such a key away and makes another (up to 20 times), and two tests pin that: a key the parser refuses is recognised (the test holds one that ssh-keygen made, no use anywhere else), and 150 keys in a row come out readable. **This is a gap in the vault itself** — the app's `agent_can_read` guard refuses such a key although it is valid — and `vault/` is not changed by this plan; it is reported with the plan (see Decisions to confirm).
- Spec §12 says a test that needs one sshd for a long loop sets `PerSourcePenalties no` (OpenSSH 9.8 or newer knows the keyword, older ones refuse the config, so it cannot be a default): `SshdOptions::extra_config` is where that goes. No test in this plan shares an sshd, so none sets it.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/mod.rs
+++ b/src-tauri/src/ssh/mod.rs
@@ -8,6 +8,8 @@ mod channel;
 mod error;
 #[cfg(test)]
 pub mod fake;
+#[cfg(test)]
+pub mod testing;
 mod traits;
 mod types;
 
```

`src-tauri/src/ssh/testing/mod.rs`: create

```rust
//! Test support for the SSH engine (own-ssh spec §12): a scratch OpenSSH server, a link that misbehaves on demand, and stand-ins for
//! the broker's policy and auth source. Test code only (`#[cfg(test)]` in `ssh/mod.rs`).

pub mod harness;

/// One measured fact, printed as `FACT <key> = <value>` so a run with `-- --nocapture` can be grepped for the numbers a report needs.
pub fn fact(key: &str, value: impl std::fmt::Display) {
    eprintln!("FACT {key} = {value}");
}
```

`src-tauri/src/ssh/testing/harness.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::*;

    /// A tool that outlives its deadline is killed instead of waited for, and the error names it and carries its stderr so far.
    /// (`exec` makes sleep replace sh, so killing it leaves no child holding the pipes; the stderr sentence is split by `printf`, so
    /// finding it whole in the message proves the pipe was really read.)
    #[cfg(unix)]
    #[test]
    fn a_tool_that_outlives_its_deadline_is_killed_and_named() {
        let started = Instant::now();
        let message = run_within(Command::new("sh").args(["-c", "printf 'no %s yet\\n' answer >&2; exec sleep 5"]), Duration::from_millis(500))
            .expect_err("a tool that outlives its deadline must be an error");
        assert!(message.contains("exec sleep 5"), "the message names the command: {message}");
        assert!(message.contains("did not finish within 500ms and was killed"), "the message says what happened: {message}");
        assert!(message.contains("no answer yet"), "the message carries the stderr so far: {message}");
        assert!(started.elapsed() < Duration::from_secs(4), "killed at the deadline, not waited for: {:?}", started.elapsed());
    }

    /// The spike's deferred Minor 2. The tool is killed at its deadline, but a background `sleep` it started still holds the output
    /// pipes. Waiting for end-of-file would take as long as that `sleep` lives; the runner must give up after `PIPE_GRACE` instead.
    #[cfg(unix)]
    #[test]
    fn a_process_that_keeps_the_pipes_open_after_the_kill_does_not_hold_the_runner() {
        let started = Instant::now();
        let message = run_within(Command::new("sh").args(["-c", "sleep 8 & printf 'partial\\n' >&2; exec sleep 30"]), Duration::from_millis(400))
            .expect_err("the tool outlives its deadline");
        let elapsed = started.elapsed();
        assert!(message.contains("did not finish within 400ms and was killed"), "{message}");
        assert!(message.contains("partial"), "the stderr read so far is kept: {message}");
        assert!(elapsed >= Duration::from_millis(400) + PIPE_GRACE - Duration::from_millis(200), "the readers were given their grace: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(6), "but not until the background sleep ended (8 s): {elapsed:?}");
    }

    #[test]
    fn a_tool_that_cannot_be_started_is_an_error_that_names_it() {
        let message = run_within(&mut Command::new("/nonexistent/sshelter-tool"), Duration::from_secs(5)).expect_err("there is no such tool");
        assert!(message.contains("cannot run") && message.contains("/nonexistent/sshelter-tool"), "{message}");
    }

    /// Four MiB on stdout and on stderr is far more than a pipe holds: the readers must keep up or the tool would block until the deadline.
    #[cfg(unix)]
    #[test]
    fn output_far_larger_than_a_pipe_arrives_complete_and_does_not_deadlock() {
        let started = Instant::now();
        let out = run_within(Command::new("sh").args(["-c", "head -c 4194304 /dev/zero; head -c 4194304 /dev/zero >&2"]), Duration::from_secs(20))
            .expect("the tool finishes");
        assert!(out.status.success());
        assert_eq!((out.stdout.len(), out.stderr.len()), (4_194_304, 4_194_304));
        assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
    }

    #[cfg(unix)]
    #[test]
    fn the_exit_code_and_both_streams_come_back_like_output_does() {
        let out = run_within(Command::new("sh").args(["-c", "printf out; printf err >&2; exit 3"]), Duration::from_secs(20)).expect("the tool finishes");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!((out.stdout.as_slice(), out.stderr.as_slice()), (b"out".as_slice(), b"err".as_slice()));
    }

    /// `Command::output()` closes stdin and so does `run_within`: a tool that reads it sees end-of-file at once instead of waiting for input.
    #[cfg(unix)]
    #[test]
    fn stdin_is_closed_so_a_tool_that_reads_it_does_not_wait() {
        let started = Instant::now();
        let out = run_within(&mut Command::new("cat"), Duration::from_secs(20)).expect("the tool finishes");
        assert!(out.status.success() && out.stdout.is_empty());
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    /// The scratch sshd works with the system ssh client, so a later failure is the engine's, not the harness's.
    #[test]
    fn the_system_ssh_client_logs_in_to_the_scratch_sshd_and_gets_the_exit_code() {
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let key = generate_key(&tools, keys.path(), "user", KeyKind::Ed25519);
        let sshd = Sshd::start(&tools, SshdOptions { authorized_keys: vec![key.public_line.clone()], ..SshdOptions::default() });

        let out = system_ssh(&tools, &sshd, &key.private_path, "echo harness-ok; exit 5");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "harness-ok\n",
            "ssh stderr: {}; sshd log: {}",
            String::from_utf8_lossy(&out.stderr),
            sshd.log()
        );
        assert_eq!(out.status.code(), Some(5));
    }

    /// The negative control: a key that is not in authorized_keys is refused, so the test above proves the server really checks keys.
    #[test]
    fn a_key_that_is_not_in_authorized_keys_is_refused() {
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let allowed = generate_key(&tools, keys.path(), "allowed", KeyKind::Ed25519);
        let stranger = generate_key(&tools, keys.path(), "stranger", KeyKind::Ed25519);
        let sshd = Sshd::start(&tools, SshdOptions { authorized_keys: vec![allowed.public_line.clone()], ..SshdOptions::default() });

        let out = system_ssh(&tools, &sshd, &stranger.private_path, "echo must-not-run");
        assert_eq!(out.status.code(), Some(255), "ssh exits 255 when it cannot log in");
        assert!(out.stdout.is_empty());
    }

    /// `ssh-key` 0.6.7 cannot read an ECDSA key whose secret number starts with a zero byte; this P-256 key, made by ssh-keygen, is one of
    /// them (`Material::open` says `Unreadable` for it). It has no use anywhere else.
    const KEY_THE_VAULT_CANNOT_READ: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n\
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSuW0Nk03fDQ13F6fng1wB9jKTOZRrA\n\
gvYrf2SP7Kb9Vme+68pkttmFg6RPsQzG79ZoRUz41uJ+GWc4IrB7xjCNAAAAoEqbIrdKmy\n\
K3AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK5bQ2TTd8NDXcXp\n\
+eDXAH2MpM5lGsCC9it/ZI/spv1WZ77rymS22YWDpE+xDMbv1mhFTPjW4n4ZZzgisHvGMI\n\
0AAAAfYEFcmxx3tGd8wan73CnFtcul1j9y5R24/F1yRgGWwgAAAAVwcm9iZQECAwQ=\n\
-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn a_key_the_vaults_parser_cannot_read_is_told_apart_from_one_it_can() {
        let error = ssh_key::PrivateKey::from_openssh(KEY_THE_VAULT_CANNOT_READ).err().expect("the parser refuses this key");
        assert!(error.to_string().contains("length"), "refused for its length, not for some other reason: {error}");
        assert!(!readable_by_the_vault(KEY_THE_VAULT_CANNOT_READ));
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let key = generate_key(&tools, keys.path(), "good", KeyKind::Ed25519);
        assert!(readable_by_the_vault(&key.private_text));
    }

    /// About one P-256 key in 256 is one the vault cannot read: of 150 keys the harness hands out, none may be.
    #[test]
    fn the_keys_the_harness_hands_out_can_all_be_read_by_the_vault() {
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        for index in 0..150 {
            let key = generate_key(&tools, keys.path(), &format!("p256-{index}"), KeyKind::EcdsaP256);
            assert!(readable_by_the_vault(&key.private_text), "key {index} cannot be read");
        }
    }

    /// A server can have several host keys; the first line of `host_public_lines` is the first `HostKey`.
    #[test]
    fn a_scratch_sshd_can_have_more_than_one_host_key() {
        let Some(tools) = tools() else { return };
        let sshd = Sshd::start(&tools, SshdOptions { host_keys: vec![KeyKind::Ed25519, KeyKind::Rsa3072], ..SshdOptions::default() });
        assert_eq!(sshd.host_public_lines.len(), 2);
        assert!(sshd.host_public_line().starts_with("ssh-ed25519 "), "{}", sshd.host_public_line());
        assert!(sshd.host_public_lines[1].starts_with("ssh-rsa "), "{}", sshd.host_public_lines[1]);
    }

    /// Dropping the server stops the listener, so a finished test leaves nothing behind on its port.
    #[test]
    fn dropping_the_scratch_sshd_closes_its_port() {
        let Some(tools) = tools() else { return };
        let sshd = Sshd::start(&tools, SshdOptions::default());
        let port = sshd.port;
        assert!(TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_secs(2)).is_ok());
        drop(sshd);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_millis(300)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("port {port} still accepts connections 5 s after the server was dropped");
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate does not compile. The first error is `error[E0425]: cannot find function `run_within` in this scope`, and the run ends with `error: could not compile `sshelter` (lib test) due to 47 previous errors` (the number of errors depends on the compiler; what matters is that the errors name items that do not exist yet).

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/testing/harness.rs`: insert this above the `#[cfg(test)]` line, at the very top of the file, and leave one empty line between it and that line

```rust
//! A scratch OpenSSH server for the engine's integration tests: a temp directory, a free localhost port, throwaway host keys and
//! authorized_keys, and `sshd -D -e -f <config>` run as the current user (no root, no PAM). Nothing here reads or writes the real
//! `~/.ssh`: the system `ssh` client used by `system_ssh` gets `-F /dev/null`.
//!
//! Ported from the phase-0 spike (`spike/russh/src/harness.rs`, checked on macOS with OpenSSH 10.3p1): `Port 0` is rejected ("Badly
//! formatted port number"), so the port is picked first; sshd prints one harmless line `BSM audit: ... setaudit_addr failed:
//! Operation not permitted`; password and keyboard-interactive login cannot work without PAM, so this sshd offers public keys only.
//! Every test starts its own sshd. A test that needs one sshd for a long loop adds `PerSourcePenalties no` to its `extra_config`
//! (OpenSSH 9.8 and later know the keyword, older ones refuse the config, so it cannot be a default).

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long one run of a helper tool (ssh-keygen, sshd -t, id, ssh) may take. A tool still running after that is killed and fails the
/// test, so a stuck one cannot hang CI.
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// After a tool was killed (or has exited) its pipes can stay open: a grandchild may have inherited them. The readers get this long to
/// reach end-of-file; after that the output collected so far is used and the readers are left to end on their own.
const PIPE_GRACE: Duration = Duration::from_secs(2);

/// `Command::output()` with a deadline of `TOOL_TIMEOUT`. A tool that cannot be started, or does not finish in time, fails the test.
fn run_bounded(command: &mut Command) -> Output {
    run_within(command, TOOL_TIMEOUT).unwrap_or_else(|message| panic!("{message}"))
}

/// One pipe, read on its own thread so a chatty tool cannot fill it and block. The bytes land in `buffer` as they arrive and `done`
/// fires at end-of-file.
struct PipeReader {
    buffer: Arc<Mutex<Vec<u8>>>,
    done: Receiver<()>,
}

fn read_in_background(pipe: Option<impl Read + Send + 'static>) -> PipeReader {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let (finished, done) = mpsc::channel();
    let sink = Arc::clone(&buffer);
    std::thread::spawn(move || {
        if let Some(mut pipe) = pipe {
            let mut chunk = [0u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => sink.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(&chunk[..count]),
                }
            }
        }
        let _ = finished.send(());
    });
    PipeReader { buffer, done }
}

impl PipeReader {
    /// Waits up to `grace` for end-of-file and returns what was read, and whether the pipe really ended.
    fn collect(&self, grace: Duration) -> (Vec<u8>, bool) {
        let ended = self.done.recv_timeout(grace).is_ok();
        (self.buffer.lock().unwrap_or_else(PoisonError::into_inner).clone(), ended)
    }
}

/// `Command::output()` with a deadline: stdin is closed, stdout and stderr are captured, and a tool still running after `timeout` is
/// killed. `Err` carries the command line and the tool's stderr so far. It returns the error instead of panicking so that the unit test
/// of the deadline leaves no "panicked at" line in the output of `--nocapture` runs.
///
/// The readers are bounded too: when a grandchild keeps the pipes open after the tool is gone, waiting for end-of-file would last as
/// long as the grandchild lives, so the readers get `PIPE_GRACE` and then the output so far is used (the spike's deferred Minor 2).
pub(super) fn run_within(command: &mut Command, timeout: Duration) -> Result<Output, String> {
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = crate::process::spawn(command).map_err(|error| format!("cannot run {command:?}: {error}"))?;
    let (stdout, stderr) = (read_in_background(child.stdout.take()), read_in_background(child.stderr.take()));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().map_err(|error| format!("cannot wait for {command:?}: {error}"))? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let (stderr, _) = stderr.collect(PIPE_GRACE);
                return Err(format!(
                    "{command:?} did not finish within {timeout:?} and was killed; its stderr so far: {}",
                    String::from_utf8_lossy(&stderr)
                ));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let ((stdout, stdout_ended), (stderr, stderr_ended)) = (stdout.collect(PIPE_GRACE), stderr.collect(PIPE_GRACE));
    if !(stdout_ended && stderr_ended) {
        eprintln!("{command:?} ended, but a process it started still holds its output pipes open; using the output read so far");
    }
    Ok(Output { status, stdout, stderr })
}

/// The OpenSSH programs the tests need.
pub struct Tools {
    pub sshd: PathBuf,
    pub ssh: PathBuf,
    pub ssh_keygen: PathBuf,
}

/// `Some` when sshd, ssh and ssh-keygen are all found. When they are not: `SSHELTER_REQUIRE_OPENSSH=1` (CI) makes that a failure on
/// Unix; anything else prints "skipped" and the caller returns early. Windows never runs the scratch-sshd tests (Win32-OpenSSH's sshd
/// must run as a service, which the workflow sets up), so there the answer is always a skip.
pub fn tools() -> Option<Tools> {
    let found = find_sshd().and_then(|sshd| Some(Tools { sshd, ssh: find_in_path("ssh")?, ssh_keygen: find_in_path("ssh-keygen")? }));
    if found.is_none() {
        let required = cfg!(unix) && std::env::var("SSHELTER_REQUIRE_OPENSSH").is_ok_and(|value| value == "1");
        assert!(!required, "sshd, ssh and ssh-keygen are required (SSHELTER_REQUIRE_OPENSSH=1)");
        eprintln!("skipped: sshd, ssh or ssh-keygen is not found (or this is not a Unix machine)");
    }
    found
}

/// sshd re-executes itself and insists on an absolute path, and a normal user rarely has it on PATH (Linux keeps it in /usr/sbin).
fn find_sshd() -> Option<PathBuf> {
    if !cfg!(unix) {
        return None;
    }
    ["/usr/sbin/sshd", "/usr/local/sbin/sshd", "/opt/homebrew/sbin/sshd", "/usr/bin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .or_else(|| find_in_path("sshd"))
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let file = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
    std::env::split_paths(&std::env::var_os("PATH")?).map(|dir| dir.join(&file)).find(|path| path.is_file())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519,
    EcdsaP256,
    Rsa3072,
}

impl KeyKind {
    fn keygen_args(self) -> &'static [&'static str] {
        match self {
            KeyKind::Ed25519 => &["-t", "ed25519"],
            KeyKind::EcdsaP256 => &["-t", "ecdsa", "-b", "256"],
            KeyKind::Rsa3072 => &["-t", "rsa", "-b", "3072"],
        }
    }
}

/// A key pair made by ssh-keygen, in the OpenSSH private key format the vault reads.
pub struct TestKey {
    pub kind: KeyKind,
    pub private_path: PathBuf,
    pub private_text: String,
    /// `<type> <base64> sshelter-test`: the authorized_keys form.
    pub public_line: String,
}

/// Whether the vault's parser (`ssh-key` 0.6.7, which `Material::open` uses) reads this OpenSSH private key.
fn readable_by_the_vault(private_text: &str) -> bool {
    ssh_key::PrivateKey::from_openssh(private_text).is_ok()
}

/// Makes a key pair with ssh-keygen. A key the vault's parser cannot read is thrown away and another is made: `ssh-key` 0.6.7 cannot
/// read an ECDSA private key whose secret number starts with a zero byte (OpenSSH then writes the number in its shortest form and the
/// parser insists on the full length). Measured with ssh-keygen from OpenSSH 10.3p1: 5 of 1500 P-256 keys, 3 of 600 P-384 keys and 77
/// of 300 P-521 keys. A test that signs with such a key through the vault would fail one run in 256 for a reason that has nothing to do
/// with the engine. (Reported with the plan as a gap in the vault: `Material::open` answers `Unreadable` for these keys.)
pub fn generate_key(tools: &Tools, dir: &Path, name: &str, kind: KeyKind) -> TestKey {
    let private_path = dir.join(name);
    let mut public_path = private_path.clone().into_os_string();
    public_path.push(".pub");
    for attempt in 1..=20 {
        let out = run_bounded(
            Command::new(&tools.ssh_keygen).args(["-q", "-N", "", "-C", "sshelter-test"]).args(kind.keygen_args()).arg("-f").arg(&private_path),
        );
        assert!(out.status.success(), "ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr));
        let private_text = std::fs::read_to_string(&private_path).expect("read the private key");
        if readable_by_the_vault(&private_text) {
            return TestKey {
                kind,
                private_text,
                public_line: std::fs::read_to_string(&public_path).expect("read the public key").trim().to_string(),
                private_path,
            };
        }
        eprintln!("ssh-keygen made a {kind:?} key that the vault's parser cannot read (attempt {attempt}); making another");
        let _ = std::fs::remove_file(&private_path);
        let _ = std::fs::remove_file(&public_path);
    }
    panic!("20 {kind:?} keys in a row could not be read by the vault's parser");
}

pub struct SshdOptions {
    /// The types of the host keys the server has, in the order of its `HostKey` lines.
    pub host_keys: Vec<KeyKind>,
    /// Lines for sshd_config. sshd keeps the FIRST value of a keyword, so these come before the defaults below and may override them.
    pub extra_config: Vec<String>,
    /// Public key lines for authorized_keys.
    pub authorized_keys: Vec<String>,
}

impl Default for SshdOptions {
    fn default() -> Self {
        SshdOptions { host_keys: vec![KeyKind::Ed25519], extra_config: Vec::new(), authorized_keys: Vec::new() }
    }
}

/// A running scratch sshd. Dropping it kills the listener (connections already open end when their client goes away).
pub struct Sshd {
    pub port: u16,
    /// The account sshd authenticates: the user running the tests (without root, sshd can only log in that user).
    pub user: String,
    /// The host keys in authorized_keys form, in the order of `SshdOptions::host_keys`.
    pub host_public_lines: Vec<String>,
    dir: tempfile::TempDir,
    child: Child,
}

impl Sshd {
    pub fn start(tools: &Tools, options: SshdOptions) -> Sshd {
        assert!(!options.host_keys.is_empty(), "a server needs at least one host key");
        // Asked before the first sshd starts: a panic in here must not leave a listener behind.
        let user = current_user();
        let dir = tempfile::Builder::new().prefix("sshelter-sshd-").tempdir().expect("temp dir");
        let host_keys: Vec<TestKey> =
            options.host_keys.iter().enumerate().map(|(index, kind)| generate_key(tools, dir.path(), &format!("hostkey{index}"), *kind)).collect();
        let authorized = dir.path().join("authorized_keys");
        let lines: String = options.authorized_keys.iter().map(|line| format!("{line}\n")).collect();
        std::fs::write(&authorized, lines).expect("write authorized_keys");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600)).expect("chmod authorized_keys");
        }
        let config_path = dir.path().join("sshd_config");
        let log_path = dir.path().join("sshd.log");
        let key_paths: Vec<&Path> = host_keys.iter().map(|key| key.private_path.as_path()).collect();
        for attempt in 1..=3 {
            let port = free_port();
            std::fs::write(&config_path, config_text(port, &key_paths, &authorized, &options.extra_config)).expect("write sshd_config");
            // `-t` checks the config and the keys without starting anything, so a typo fails here, in sshd's own words.
            let check = run_bounded(Command::new(&tools.sshd).arg("-t").arg("-f").arg(&config_path));
            assert!(
                check.status.success(),
                "sshd -t rejected the config:\n{}\n--- config:\n{}",
                String::from_utf8_lossy(&check.stderr),
                std::fs::read_to_string(&config_path).unwrap_or_default()
            );
            let log = std::fs::File::create(&log_path).expect("create sshd.log");
            let mut command = Command::new(&tools.sshd);
            command.args(["-D", "-e", "-f"]).arg(&config_path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::from(log));
            let mut child = crate::process::spawn(&mut command).expect("start sshd");
            if wait_for_banner(&mut child, port) {
                let host_public_lines = host_keys.iter().map(|key| key.public_line.clone()).collect();
                return Sshd { port, user, host_public_lines, dir, child };
            }
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("sshd did not come up on port {port} (attempt {attempt}); its log:\n{}", std::fs::read_to_string(&log_path).unwrap_or_default());
        }
        panic!("sshd did not start in 3 attempts");
    }

    /// The first host key in authorized_keys form.
    pub fn host_public_line(&self) -> &str {
        &self.host_public_lines[0]
    }

    /// What sshd wrote to stderr (`LogLevel ERROR` unless a test asks for more).
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("sshd.log")).unwrap_or_default()
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn config_text(port: u16, host_keys: &[&Path], authorized_keys: &Path, extra: &[String]) -> String {
    let mut lines: Vec<String> = extra.to_vec();
    lines.extend([format!("Port {port}"), "ListenAddress 127.0.0.1".to_string()]);
    lines.extend(host_keys.iter().map(|key| format!("HostKey \"{}\"", key.display())));
    lines.extend([
        "PidFile none".to_string(),
        "UsePAM no".to_string(),
        "PasswordAuthentication no".to_string(),
        "KbdInteractiveAuthentication no".to_string(),
        "PubkeyAuthentication yes".to_string(),
        format!("AuthorizedKeysFile \"{}\"", authorized_keys.display()),
        "StrictModes no".to_string(),
        // sshd runs ~/.ssh/rc by default, which would let the developer's real home directory into the test.
        "PermitUserRC no".to_string(),
        "LogLevel ERROR".to_string(),
    ]);
    lines.join("\n") + "\n"
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a free port").local_addr().expect("local address").port()
}

/// Waits (up to 10 s) for an SSH banner on `port` from a sshd that is still running; false when the child exits first or nothing greets.
fn wait_for_banner(child: &mut Child, port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        if let Ok(mut stream) = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_millis(500)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut banner = [0u8; 8];
            if stream.read_exact(&mut banner).is_ok() && &banner == b"SSH-2.0-" {
                // Somebody else may own the port (the pick can race with another test): ours must still be alive a moment later.
                std::thread::sleep(Duration::from_millis(200));
                return child.try_wait().ok().flatten().is_none();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn current_user() -> String {
    let out = run_bounded(Command::new("id").arg("-un"));
    assert!(out.status.success(), "id -un failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Runs the system `ssh` client against `sshd`. `-F /dev/null` keeps it from reading the real ~/.ssh/config; the agent and known_hosts are off.
/// It gives up connecting after 10 s (`ConnectTimeout`) and is killed, with the test failing, if the whole run takes longer than `TOOL_TIMEOUT`.
pub fn system_ssh(tools: &Tools, sshd: &Sshd, identity: &Path, remote_command: &str) -> Output {
    run_bounded(
        Command::new(&tools.ssh)
            .args(["-F", "/dev/null", "-p"])
            .arg(sshd.port.to_string())
            .arg("-i")
            .arg(identity)
            .args([
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "LogLevel=ERROR",
            ])
            .arg(format!("{}@127.0.0.1", sshd.user))
            .arg(remote_command),
    )
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 42 passed; 0 failed`. The run takes about 18 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1459 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 109 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/mod.rs src-tauri/src/ssh/testing/harness.rs src-tauri/src/ssh/testing/mod.rs
git commit -m "test(ssh): port the scratch-sshd harness onto crate::process"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 6: The proxy, the server fixture and the policy and auth doubles

**Files:**
- Create: `src-tauri/src/ssh/testing/doubles.rs` (with its tests)
- Create: `src-tauri/src/ssh/testing/fixture.rs`
- Modify: `src-tauri/src/ssh/testing/mod.rs`
- Create: `src-tauri/src/ssh/testing/proxy.rs` (with its tests)

**Interfaces:**
- Consumes: Task 5's `Tools`, `KeyKind`, `TestKey`, `generate_key`, `Sshd`, `SshdOptions`; Task 2's interface; the existing `crate::vault::material::{open, Material, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512}` and `crate::sync::slot_rules::test_keys`; `tokio::{net, sync::watch, io}`.
- Produces (test code only):

  - `ssh/testing/doubles.rs`:
    - `pub enum Unpinned`
    - `pub struct TestPolicy`
    - (impl TestPolicy) `pub fn new(unpinned: Unpinned) -> Arc<TestPolicy>`
    - (impl TestPolicy) `pub fn trusting() -> Arc<TestPolicy>`
    - (impl TestPolicy) `pub fn knowing_nothing() -> Arc<TestPolicy>`
    - (impl TestPolicy) `pub fn pin(&self, hop: &HopRef, key: HostKey)`
    - (impl TestPolicy) `pub fn seen(&self) -> Vec<(HopRef, HostKey)>`
    - `pub struct SignCall`
    - `pub struct VaultAuth`
    - (impl VaultAuth) `pub fn new() -> VaultAuth`
    - (impl VaultAuth) `pub fn with_key(mut self, key_id: &str, private_text: &str) -> VaultAuth`
    - (impl VaultAuth) `pub fn with_password(mut self, password: &str) -> VaultAuth`
    - (impl VaultAuth) `pub fn with_password_delay(mut self, delay: Duration) -> VaultAuth`
    - (impl VaultAuth) `pub fn with_answers(mut self, answers: &[&str]) -> VaultAuth`
    - (impl VaultAuth) `pub fn with_answer_delay(mut self, delay: Duration) -> VaultAuth`
    - (impl VaultAuth) `pub fn overrunning_the_deadline(mut self) -> VaultAuth`
    - (impl VaultAuth) `pub fn failing_to_sign(mut self, error: AuthError) -> VaultAuth`
    - (impl VaultAuth) `pub fn sign_calls(&self) -> Vec<SignCall>`
    - (impl VaultAuth) `pub fn password_asked_for(&self) -> Vec<HopRef>`
    - (impl VaultAuth) `pub fn prompts_seen(&self) -> Vec<Vec<Prompt>>`
  - `ssh/testing/fixture.rs`:
    - `pub struct Server`
    - (impl Server) `pub fn start(tools: &Tools, extra_config: &[&str]) -> Server`
    - (impl Server) `pub fn start_with(tools: &Tools, host_keys: &[KeyKind], user_key: KeyKind, extra_config: &[&str]) -> Server`
    - (impl Server) `pub fn host_key(&self) -> HostKey`
    - (impl Server) `pub fn host_keys(&self) -> Vec<HostKey>`
    - (impl Server) `pub fn hop_with(&self, alias: &str, port: u16, auth: AuthMethod) -> Hop`
    - (impl Server) `pub fn hop(&self, alias: &str, key_id: &str) -> Hop`
    - (impl Server) `pub fn target(&self, key_id: &str) -> Target`
    - (impl Server) `pub fn vault(&self, key_id: &str) -> super::doubles::VaultAuth`
  - `ssh/testing/mod.rs`:
    - `pub mod doubles;`
    - `pub mod fixture;`
    - `pub mod proxy;`
  - `ssh/testing/proxy.rs`:
    - `pub enum Mode`
    - `pub struct Proxy`
    - (impl Proxy) `pub fn start(target_port: u16) -> Proxy`
    - (impl Proxy) `pub fn set(&self, mode: Mode)`
    - (impl Proxy) `pub fn open_connections(&self) -> usize`
    - (impl Proxy) `pub fn accepted(&self) -> usize`

What shapes this task:
- `Proxy` is a TCP forwarder in front of a scratch sshd that can go silent (bytes held, sockets open: a dead Wi-Fi link) or cut every connection on demand. Keepalive, a connection that dies mid-command, a handshake that never answers and an abandoned login all need a link that misbehaves. It owns a small tokio runtime so the tests stay synchronous, and counts connections (`open_connections`, `accepted`) so a test can prove that nothing was left open.
- `TestPolicy` is a `HostKeyPolicy` with a table of pins by host id, like the broker's will be; `pin` models the user confirming a key (connect, get `HostKeyUnknown { key }`, pin that key, connect again with the same policy). `VaultAuth` is an `AuthSource` over **real vault entries**: `with_key` parses an OpenSSH private key with `Material` and signs with it, so the engine tests exercise the app's real signing code; passwords and keyboard-interactive answers come from a script, with delays and failures on request. Both record what they were asked.
- `Server` (fixture.rs) is a scratch sshd with an Ed25519 host key that accepts one fresh Ed25519 user key, plus the helpers that build the `Hop`/`Target` for it. It has no tests of its own; the engine tests of Task 7 are its first users, so it is written in the implementation step.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/testing/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/testing/mod.rs
+++ b/src-tauri/src/ssh/testing/mod.rs
@@ -1,7 +1,9 @@
 //! Test support for the SSH engine (own-ssh spec §12): a scratch OpenSSH server, a link that misbehaves on demand, and stand-ins for
 //! the broker's policy and auth source. Test code only (`#[cfg(test)]` in `ssh/mod.rs`).
 
+pub mod doubles;
 pub mod harness;
+pub mod proxy;
 
 /// One measured fact, printed as `FACT <key> = <value>` so a run with `-- --nocapture` can be grepped for the numbers a report needs.
 pub fn fact(key: &str, value: impl std::fmt::Display) {
```

`src-tauri/src/ssh/testing/doubles.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    fn hop(id: &str) -> HopRef {
        HopRef { id: HostId::from(id), alias: id.into(), hostname: "127.0.0.1".into(), port: 22, user: "tester".into() }
    }

    fn key(fingerprint: &str, algorithm: &str) -> HostKey {
        HostKey { algorithm: algorithm.into(), public_key: vec![1], fingerprint: fingerprint.into() }
    }

    #[test]
    fn the_policy_answers_from_its_pins_and_remembers_what_it_saw() {
        let policy = TestPolicy::knowing_nothing();
        let (web, db) = (hop("web"), hop("db"));
        assert_eq!(policy.check(&web, &key("SHA256:a", "ssh-ed25519")), HostKeyVerdict::Unknown);
        policy.pin(&web, key("SHA256:a", "ssh-ed25519"));
        assert_eq!(policy.check(&web, &key("SHA256:a", "ssh-ed25519")), HostKeyVerdict::Pinned);
        assert_eq!(
            policy.check(&web, &key("SHA256:b", "ssh-ed25519")),
            HostKeyVerdict::Mismatch { pinned: key("SHA256:a", "ssh-ed25519") }
        );
        assert_eq!(policy.check(&db, &key("SHA256:a", "ssh-ed25519")), HostKeyVerdict::Unknown, "pins are per host");
        assert_eq!(policy.seen().len(), 4);
        assert_eq!(TestPolicy::trusting().check(&db, &key("SHA256:z", "ssh-rsa")), HostKeyVerdict::Pinned);
    }

    #[test]
    fn the_vault_double_signs_with_the_hash_it_is_given_and_records_the_call() {
        let auth = VaultAuth::new().with_key("ed", &test_keys::plain()).with_key("rsa", &test_keys::rsa());
        assert_eq!(auth.public_key("ed").as_deref().map(|line| line.split(' ').next().unwrap_or_default().to_string()), Some("ssh-ed25519".to_string()));
        assert_eq!(auth.public_key("missing"), None);
        let signature = auth.sign("ed", b"challenge", None).unwrap();
        assert_eq!(algorithm_of(&signature.0).as_deref(), Some("ssh-ed25519"));
        let signature = auth.sign("rsa", b"challenge", Some(RsaHash::Sha256)).unwrap();
        assert_eq!(algorithm_of(&signature.0).as_deref(), Some("rsa-sha2-256"));
        assert_eq!(auth.sign("missing", b"x", None), Err(AuthError::KeyUnavailable("no key missing in the vault double".into())));
        assert_eq!(
            auth.sign_calls(),
            vec![
                SignCall { key_id: "ed".into(), rsa_hash: None, algorithm: Some("ssh-ed25519".into()) },
                SignCall { key_id: "rsa".into(), rsa_hash: Some(RsaHash::Sha256), algorithm: Some("rsa-sha2-256".into()) },
                SignCall { key_id: "missing".into(), rsa_hash: None, algorithm: None },
            ]
        );
    }

    #[test]
    fn the_vault_double_can_be_told_to_fail_and_to_answer_prompts() {
        let failing = VaultAuth::new().with_key("ed", &test_keys::plain()).failing_to_sign(AuthError::Refused("locked".into()));
        assert_eq!(failing.sign("ed", b"x", None), Err(AuthError::Refused("locked".into())));

        let auth = VaultAuth::new().with_password("pw").with_answers(&["one", "two"]);
        assert_eq!(auth.password(&hop("web")).as_deref().map(String::as_str), Some("pw"));
        let prompts = [Prompt { text: "Code: ".into(), echo: true }];
        let deadline = Instant::now() + Duration::from_secs(5);
        let answers = auth.interactive(&hop("web"), &prompts, deadline).unwrap();
        assert_eq!(answers.iter().map(|answer| answer.as_str()).collect::<Vec<_>>(), ["one", "two"]);
        assert_eq!(auth.password_asked_for(), vec![hop("web")]);
        assert_eq!(auth.prompts_seen(), vec![prompts.to_vec()]);

        let silent = VaultAuth::new();
        assert!(silent.password(&hop("web")).is_none() && silent.interactive(&hop("web"), &prompts, deadline).is_none());
    }

    #[test]
    fn a_slow_answer_is_given_up_at_the_deadline_unless_the_double_misbehaves_on_purpose() {
        let prompts = [Prompt { text: "Code: ".into(), echo: true }];
        let patient = VaultAuth::new().with_answers(&["late"]).with_answer_delay(Duration::from_secs(2));
        let started = Instant::now();
        assert!(patient.interactive(&hop("web"), &prompts, Instant::now() + Duration::from_millis(200)).is_none());
        assert!(started.elapsed() < Duration::from_secs(1), "it gave up at the deadline: {:?}", started.elapsed());

        let rude = VaultAuth::new().with_answers(&["late"]).with_answer_delay(Duration::from_millis(300)).overrunning_the_deadline();
        let answers = rude.interactive(&hop("web"), &prompts, Instant::now() + Duration::from_millis(50));
        assert_eq!(answers.map(|answers| answers.len()), Some(1), "a misbehaving source answers anyway");
    }
}
```

`src-tauri/src/ssh/testing/proxy.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    use super::{Mode, Proxy};

    /// A server that sends back every byte it receives. Returns its port.
    fn echo_server() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            while let Ok((mut socket, _)) = listener.accept() {
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 1024];
                    while let Ok(count) = socket.read(&mut buffer) {
                        if count == 0 || socket.write_all(&buffer[..count]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    fn connect(port: u16) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        // Bounded: if forwarding broke, the test must fail at a read instead of hanging the suite.
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream
    }

    fn round_trip(client: &mut TcpStream, bytes: &[u8]) -> Vec<u8> {
        client.write_all(bytes).unwrap();
        let mut reply = vec![0u8; bytes.len()];
        client.read_exact(&mut reply).unwrap();
        reply
    }

    fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for: {what}");
    }

    #[test]
    fn forward_passes_bytes_both_ways() {
        let proxy = Proxy::start(echo_server());
        let mut client = connect(proxy.port);
        assert_eq!(round_trip(&mut client, b"hello"), b"hello");
    }

    #[test]
    fn blackhole_holds_the_bytes_until_forward_releases_them() {
        let proxy = Proxy::start(echo_server());
        let mut client = connect(proxy.port);
        assert_eq!(round_trip(&mut client, b"warm"), b"warm");

        proxy.set(Mode::Blackhole);
        client.write_all(b"held").unwrap();
        client.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut reply = [0u8; 4];
        assert!(client.read_exact(&mut reply).is_err(), "nothing may arrive through a black hole");

        proxy.set(Mode::Forward);
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        client.read_exact(&mut reply).expect("released in time");
        assert_eq!(&reply, b"held");
    }

    #[test]
    fn cut_closes_open_connections_and_new_ones() {
        let proxy = Proxy::start(echo_server());
        let mut client = connect(proxy.port);
        assert_eq!(round_trip(&mut client, b"warm"), b"warm");

        proxy.set(Mode::Cut);
        let mut byte = [0u8; 1];
        let read = client.read(&mut byte);
        assert!(matches!(read, Ok(0) | Err(_)), "an open connection must end after a cut, got {read:?}");

        let mut late = connect(proxy.port);
        let read = late.read(&mut byte);
        assert!(matches!(read, Ok(0) | Err(_)), "a new connection must be closed on arrival, got {read:?}");
    }

    #[test]
    fn it_counts_the_connections_that_are_open_and_the_ones_it_accepted() {
        let proxy = Proxy::start(echo_server());
        assert_eq!((proxy.open_connections(), proxy.accepted()), (0, 0));
        let mut first = connect(proxy.port);
        let mut second = connect(proxy.port);
        assert_eq!(round_trip(&mut first, b"a"), b"a");
        assert_eq!(round_trip(&mut second, b"b"), b"b");
        assert_eq!((proxy.open_connections(), proxy.accepted()), (2, 2));
        drop(first);
        eventually("the first connection to be counted as closed", || proxy.open_connections() == 1);
        drop(second);
        eventually("the second connection to be counted as closed", || proxy.open_connections() == 0);
        assert_eq!(proxy.accepted(), 2, "closing does not undo the count of accepted connections");
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate does not compile. The first error is `error[E0432]: unresolved imports `super::Mode`, `super::Proxy``, and the run ends with `error: could not compile `sshelter` (lib test) due to 41 previous errors` (the number of errors depends on the compiler; what matters is that the errors name items that do not exist yet).

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/testing/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/testing/mod.rs
+++ b/src-tauri/src/ssh/testing/mod.rs
@@ -2,6 +2,7 @@
 //! the broker's policy and auth source. Test code only (`#[cfg(test)]` in `ssh/mod.rs`).
 
 pub mod doubles;
+pub mod fixture;
 pub mod harness;
 pub mod proxy;
 
```

`src-tauri/src/ssh/testing/doubles.rs`: insert this above the `#[cfg(test)]` line, at the very top of the file, and leave one empty line between it and that line

```rust
//! Stand-ins for what the broker will supply: a host key policy with a table of pins, and an auth source that signs with real vault
//! keys (`Material`), answers prompts from a script, and can be told to fail or to take its time. Both record what they were asked.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::ssh::{AuthError, AuthSource, HopRef, HostId, HostKey, HostKeyPolicy, HostKeyVerdict, Prompt, RsaHash, Secret, Signature};
use crate::vault::material::{open, Material, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a host that has no pin gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unpinned {
    /// `Unknown`: the engine must stop and report the key.
    Unknown,
    /// `Pinned`: any key is fine (for tests that are about something else).
    Trusted,
}

struct PolicyState {
    pins: HashMap<HostId, HostKey>,
    unpinned: Unpinned,
    seen: Vec<(HopRef, HostKey)>,
}

/// A `HostKeyPolicy` with a table of pins by host id, like the broker's will be. `pin` models the user confirming a key: a test connects,
/// gets `HostKeyUnknown { key }`, pins that key and connects again with the same policy.
pub struct TestPolicy {
    state: Mutex<PolicyState>,
}

impl TestPolicy {
    pub fn new(unpinned: Unpinned) -> Arc<TestPolicy> {
        Arc::new(TestPolicy { state: Mutex::new(PolicyState { pins: HashMap::new(), unpinned, seen: Vec::new() }) })
    }

    /// Every host is trusted, whatever key it presents.
    pub fn trusting() -> Arc<TestPolicy> {
        TestPolicy::new(Unpinned::Trusted)
    }

    /// Nothing is pinned: every key is `Unknown` until a test pins it.
    pub fn knowing_nothing() -> Arc<TestPolicy> {
        TestPolicy::new(Unpinned::Unknown)
    }

    pub fn pin(&self, hop: &HopRef, key: HostKey) {
        locked(&self.state).pins.insert(hop.id.clone(), key);
    }

    /// The (hop, key) pairs `check` was asked about, in order.
    pub fn seen(&self) -> Vec<(HopRef, HostKey)> {
        locked(&self.state).seen.clone()
    }
}

impl HostKeyPolicy for TestPolicy {
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict {
        let mut state = locked(&self.state);
        state.seen.push((hop.clone(), key.clone()));
        match state.pins.get(&hop.id) {
            Some(pinned) if pinned.fingerprint == key.fingerprint => HostKeyVerdict::Pinned,
            Some(pinned) => HostKeyVerdict::Mismatch { pinned: pinned.clone() },
            None if state.unpinned == Unpinned::Trusted => HostKeyVerdict::Pinned,
            None => HostKeyVerdict::Unknown,
        }
    }
}

/// One call of `AuthSource::sign`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignCall {
    pub key_id: String,
    pub rsa_hash: Option<RsaHash>,
    /// The algorithm named inside the signature that was returned (`ssh-ed25519`, `rsa-sha2-512`, …); `None` when signing failed.
    pub algorithm: Option<String>,
}

/// An `AuthSource` over real vault entries. Keys are registered under ids with `with_key`; passwords and answers come from the script.
pub struct VaultAuth {
    keys: HashMap<String, (Material, String)>,
    password: Option<String>,
    password_delay: Duration,
    answers: Option<Vec<String>>,
    answer_delay: Duration,
    overrun_deadline: bool,
    sign_error: Option<AuthError>,
    signs: Mutex<Vec<SignCall>>,
    password_asks: Mutex<Vec<HopRef>>,
    prompts: Mutex<Vec<Vec<Prompt>>>,
}

impl VaultAuth {
    pub fn new() -> VaultAuth {
        VaultAuth {
            keys: HashMap::new(),
            password: None,
            password_delay: Duration::ZERO,
            answers: None,
            answer_delay: Duration::ZERO,
            overrun_deadline: false,
            sign_error: None,
            signs: Mutex::new(Vec::new()),
            password_asks: Mutex::new(Vec::new()),
            prompts: Mutex::new(Vec::new()),
        }
    }

    /// Puts the OpenSSH private key `private_text` in the vault double under `key_id`.
    pub fn with_key(mut self, key_id: &str, private_text: &str) -> VaultAuth {
        let material = open(private_text, None).expect("the vault opens the key");
        let public_line = ssh_key::PublicKey::new(material.key_data(), "").to_openssh().expect("the public key has an OpenSSH form");
        self.keys.insert(key_id.to_string(), (material, public_line));
        self
    }

    /// `password` returns this (the user "typed" it). Without it `password` returns `None`.
    pub fn with_password(mut self, password: &str) -> VaultAuth {
        self.password = Some(password.to_string());
        self
    }

    /// `password` takes this long to answer (the user is typing).
    pub fn with_password_delay(mut self, delay: Duration) -> VaultAuth {
        self.password_delay = delay;
        self
    }

    /// `interactive` returns these answers. Without them it returns `None`, as a cancelled prompt does.
    pub fn with_answers(mut self, answers: &[&str]) -> VaultAuth {
        self.answers = Some(answers.iter().map(|answer| answer.to_string()).collect());
        self
    }

    /// `interactive` takes this long to answer. A source that behaves like the broker gives up at the deadline and returns `None`.
    pub fn with_answer_delay(mut self, delay: Duration) -> VaultAuth {
        self.answer_delay = delay;
        self
    }

    /// `interactive` ignores the deadline: it answers after its delay even when that is too late (a misbehaving source).
    pub fn overrunning_the_deadline(mut self) -> VaultAuth {
        self.overrun_deadline = true;
        self
    }

    /// `sign` fails with this error (a locked vault, a refused approval).
    pub fn failing_to_sign(mut self, error: AuthError) -> VaultAuth {
        self.sign_error = Some(error);
        self
    }

    pub fn sign_calls(&self) -> Vec<SignCall> {
        locked(&self.signs).clone()
    }

    pub fn password_asked_for(&self) -> Vec<HopRef> {
        locked(&self.password_asks).clone()
    }

    pub fn prompts_seen(&self) -> Vec<Vec<Prompt>> {
        locked(&self.prompts).clone()
    }
}

impl Default for VaultAuth {
    fn default() -> Self {
        VaultAuth::new()
    }
}

/// The first SSH string of a signature blob: the algorithm name.
fn algorithm_of(blob: &[u8]) -> Option<String> {
    let length = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    String::from_utf8(blob.get(4..4 + length)?.to_vec()).ok()
}

impl AuthSource for VaultAuth {
    fn public_key(&self, key_id: &str) -> Option<String> {
        self.keys.get(key_id).map(|(_, public_line)| public_line.clone())
    }

    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
        let record = |algorithm: Option<String>| locked(&self.signs).push(SignCall { key_id: key_id.to_string(), rsa_hash, algorithm });
        if let Some(error) = &self.sign_error {
            record(None);
            return Err(error.clone());
        }
        let Some((material, _)) = self.keys.get(key_id) else {
            record(None);
            return Err(AuthError::KeyUnavailable(format!("no key {key_id} in the vault double")));
        };
        let flags = match rsa_hash {
            Some(RsaHash::Sha512) => SSH_AGENT_RSA_SHA2_512,
            Some(RsaHash::Sha256) => SSH_AGENT_RSA_SHA2_256,
            None => 0,
        };
        match material.sign(data, flags) {
            Ok(blob) => {
                record(algorithm_of(&blob));
                Ok(Signature(blob))
            }
            Err(error) => {
                record(None);
                Err(AuthError::Failed(error.to_string()))
            }
        }
    }

    fn password(&self, hop: &HopRef) -> Option<Secret> {
        locked(&self.password_asks).push(hop.clone());
        std::thread::sleep(self.password_delay);
        self.password.clone().map(Zeroizing::new)
    }

    fn interactive(&self, _hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
        locked(&self.prompts).push(prompts.to_vec());
        if !self.overrun_deadline && Instant::now() + self.answer_delay > deadline {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            return None;
        }
        std::thread::sleep(self.answer_delay);
        self.answers.clone().map(|answers| answers.into_iter().map(Zeroizing::new).collect())
    }
}
```

`src-tauri/src/ssh/testing/fixture.rs`: create

```rust
//! Test setup shared by the engine tests: a scratch sshd that accepts one fresh user key, and the hops that reach it.

use super::harness::{generate_key, KeyKind, Sshd, SshdOptions, TestKey, Tools};
use crate::ssh::{AuthMethod, Hop, HostKey, Target};

pub struct Server {
    pub sshd: Sshd,
    /// The user key sshd accepts.
    pub key: TestKey,
    _keys: tempfile::TempDir,
}

impl Server {
    /// A scratch sshd with an Ed25519 host key, accepting one fresh Ed25519 user key. `extra_config` goes in front of the defaults.
    pub fn start(tools: &Tools, extra_config: &[&str]) -> Server {
        Server::start_with(tools, &[KeyKind::Ed25519], KeyKind::Ed25519, extra_config)
    }

    pub fn start_with(tools: &Tools, host_keys: &[KeyKind], user_key: KeyKind, extra_config: &[&str]) -> Server {
        let keys = tempfile::tempdir().expect("temp dir for the user key");
        let key = generate_key(tools, keys.path(), "user", user_key);
        let sshd = Sshd::start(
            tools,
            SshdOptions {
                host_keys: host_keys.to_vec(),
                extra_config: extra_config.iter().map(|line| line.to_string()).collect(),
                authorized_keys: vec![key.public_line.clone()],
            },
        );
        Server { sshd, key, _keys: keys }
    }

    /// The first host key, in the form a host record stores it.
    pub fn host_key(&self) -> HostKey {
        self.host_keys().remove(0)
    }

    /// Every host key the server has, in the order of its `HostKey` lines.
    pub fn host_keys(&self) -> Vec<HostKey> {
        self.sshd.host_public_lines.iter().map(|line| HostKey::from_openssh_line(line).expect("the host key line parses")).collect()
    }

    /// A hop to this server with the given login. `port` is the server's own, or a proxy's in front of it. The host id is `host-<alias>`.
    pub fn hop_with(&self, alias: &str, port: u16, auth: AuthMethod) -> Hop {
        Hop::new(&format!("host-{alias}"), alias, "127.0.0.1", port, &self.sshd.user, auth)
    }

    /// A hop that logs in with the vault key registered under `key_id` (the user key of this server), on the server's own port.
    pub fn hop(&self, alias: &str, key_id: &str) -> Hop {
        self.hop_with(alias, self.sshd.port, AuthMethod::Key { key_id: key_id.to_string() })
    }

    /// A direct target on the server's own port, logging in with the key registered under `key_id`.
    pub fn target(&self, key_id: &str) -> Target {
        Target { hops: vec![self.hop("server", key_id)] }
    }

    /// An auth source that holds this server's user key under `key_id`.
    pub fn vault(&self, key_id: &str) -> super::doubles::VaultAuth {
        super::doubles::VaultAuth::new().with_key(key_id, &self.key.private_text)
    }
}
```

`src-tauri/src/ssh/testing/proxy.rs`: insert this above the `#[cfg(test)]` line, at the very top of the file, and leave one empty line between it and that line

```rust
//! A TCP proxy in front of a scratch sshd that can go silent (bytes held, sockets open: a dead Wi-Fi link) or cut the connections.
//! Keepalive, a connection dropped mid-command, a handshake that never answers and an abandoned login all need a link that misbehaves
//! on demand. Ported from the spike's `proxy.rs`; the proxy owns a small tokio runtime, so tests stay synchronous.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Bytes flow both ways.
    Forward,
    /// Bytes are read and held, nothing is delivered, the sockets stay open.
    Blackhole,
    /// Every connection is closed now, and new ones are closed on arrival.
    Cut,
}

#[derive(Default)]
struct Stats {
    open: AtomicUsize,
    accepted: AtomicUsize,
}

/// Counts a client connection as open for as long as it lives.
struct OpenGuard(Arc<Stats>);

impl OpenGuard {
    fn new(stats: &Arc<Stats>) -> OpenGuard {
        stats.accepted.fetch_add(1, Ordering::SeqCst);
        stats.open.fetch_add(1, Ordering::SeqCst);
        OpenGuard(Arc::clone(stats))
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Proxy {
    /// Where clients connect (127.0.0.1).
    pub port: u16,
    mode: watch::Sender<Mode>,
    stats: Arc<Stats>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Proxy {
    pub fn start(target_port: u16) -> Proxy {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("the proxy's runtime");
        let listener = runtime.block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))).expect("bind the proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let (mode, watcher) = watch::channel(Mode::Forward);
        let stats = Arc::new(Stats::default());
        let counted = Arc::clone(&stats);
        runtime.spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let (watcher, stats) = (watcher.clone(), Arc::clone(&counted));
                tokio::spawn(async move {
                    let _open = OpenGuard::new(&stats);
                    if *watcher.borrow() == Mode::Cut {
                        return;
                    }
                    let Ok(server) = TcpStream::connect((Ipv4Addr::LOCALHOST, target_port)).await else { return };
                    let (client_read, client_write) = client.into_split();
                    let (server_read, server_write) = server.into_split();
                    let up = tokio::spawn(pipe(client_read, server_write, watcher.clone()));
                    let down = tokio::spawn(pipe(server_read, client_write, watcher));
                    let _ = tokio::join!(up, down);
                });
            }
        });
        Proxy { port, mode, stats, runtime: Some(runtime) }
    }

    pub fn set(&self, mode: Mode) {
        self.mode.send_replace(mode);
    }

    /// Client connections that are open right now (accepted and not yet finished).
    pub fn open_connections(&self) -> usize {
        self.stats.open.load(Ordering::SeqCst)
    }

    /// Client connections accepted so far, including the ones that were cut on arrival.
    pub fn accepted(&self) -> usize {
        self.stats.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

async fn pipe(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, mut mode: watch::Receiver<Mode>) {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = tokio::select! {
            read = from.read(&mut buffer) => read,
            _ = mode.wait_for(|mode| *mode == Mode::Cut) => break,
        };
        let count = match read {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        // Black hole: hold what was read until the link comes back (or is cut).
        loop {
            let current = *mode.borrow();
            match current {
                Mode::Forward => break,
                Mode::Cut => return,
                Mode::Blackhole => {}
            }
            if mode.changed().await.is_err() {
                return;
            }
        }
        if to.write_all(&buffer[..count]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 50 passed; 0 failed`. The run takes about 15 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1467 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 107 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/testing/doubles.rs src-tauri/src/ssh/testing/fixture.rs src-tauri/src/ssh/testing/mod.rs src-tauri/src/ssh/testing/proxy.rs
git commit -m "test(ssh): add the proxy, server fixture and policy/auth doubles for engine tests"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 7: `RusshEngine::connect_chain`: host keys and public-key login through the vault

**Files:**
- Create (tests): `src-tauri/src/ssh/engine_tests/connect.rs`
- Create (tests): `src-tauri/src/ssh/engine_tests/mod.rs`
- Modify: `src-tauri/src/ssh/mod.rs` (declares `engine_tests` and `russh_engine`, and holds the guard test that keeps russh in one file)
- Create: `src-tauri/src/ssh/russh_engine.rs` (with its tests)
- Modify: `src-tauri/src/ssh/testing/doubles.rs` (a way to announce one key and sign with another)
- Modify: `src-tauri/src/ssh/testing/mod.rs` (`eventually`)

**Interfaces:**
- Consumes (Tasks 2, 5 and 6; exact signatures):
  - Interface: `HostKeyPolicy::check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict`; `AuthSource::{public_key(&self, key_id: &str) -> Option<String>, sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError>, password(&self, hop: &HopRef) -> Option<Secret>}`; `Hop::{new(id: &str, alias: &str, hostname: &str, port: u16, user: &str, auth: AuthMethod) -> Hop, reference(&self) -> HopRef, auth_sequence(&self) -> Vec<AuthMethod>}`; `HostKey::from_openssh_line(line: &str) -> Option<HostKey>`; the `ConnectError`, `Phase`, `DisconnectKind` and `AuthMethod` variants.
  - Test support: `tools() -> Option<Tools>`, `generate_key(tools: &Tools, dir: &Path, name: &str, kind: KeyKind) -> TestKey`; `Server::{start(tools: &Tools, extra_config: &[&str]) -> Server, start_with(tools: &Tools, host_keys: &[KeyKind], user_key: KeyKind, extra_config: &[&str]) -> Server, target(&self, key_id: &str) -> Target, hop_with(&self, alias: &str, port: u16, auth: AuthMethod) -> Hop, vault(&self, key_id: &str) -> super::doubles::VaultAuth, host_key(&self) -> HostKey, host_keys(&self) -> Vec<HostKey>}`; `TestPolicy::{trusting() -> Arc<TestPolicy>, knowing_nothing() -> Arc<TestPolicy>, pin(&self, hop: &HopRef, key: HostKey), seen(&self) -> Vec<(HopRef, HostKey)>}`; `VaultAuth::{new(), with_key(self, key_id: &str, private_text: &str), with_password(self, password: &str), failing_to_sign(self, error: AuthError), sign_calls(&self) -> Vec<SignCall>, password_asked_for(&self) -> Vec<HopRef>}`; `Proxy::{start(target_port: u16) -> Proxy, set(&self, mode: Mode), open_connections(&self) -> usize, accepted(&self) -> usize}` with `Mode::{Forward, Blackhole, Cut}`; `fact(key: &str, value: impl Display)`.
  - Existing: `russh 0.64.1`, `tokio 1.52` (Task 1), `crate::sync::slot_rules::test_keys`.
- Produces (the connection layer; Task 8 puts `SshEngine` and `Session` on top of it):

  - `ssh/russh_engine.rs`:
    - `pub struct EngineOptions`
    - `pub struct RusshEngine`
    - (impl RusshEngine) `pub fn new() -> RusshEngine`
    - (impl RusshEngine) `pub fn with_options(options: EngineOptions) -> RusshEngine`
    - (impl RusshEngine) `pub fn connect_chain(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError>`
    - `pub struct Established`
    - `pub struct Connection`
    - (impl Connection) `pub fn hop_count(&self) -> usize`
    - (impl Connection) `pub fn is_open(&self) -> bool`
  - `ssh/testing/doubles.rs`:
    - (impl VaultAuth) `pub fn presenting_public_key(mut self, key_id: &str, public_line: &str) -> VaultAuth`
  - `ssh/testing/mod.rs`:
    - `pub fn eventually(what: &str, seconds: u64, mut condition: impl FnMut() -> bool)`
  - `EngineOptions { pub shell_queue_bytes: usize, pub worker_threads: usize }` (defaults 4 MiB and 2; Task 11 adds `prompt_wait`)
  - `testing/mod.rs`: `pub fn eventually(what: &str, seconds: u64, condition: impl FnMut() -> bool)` (polls a condition for at most `seconds` and panics naming `what`)

What shapes this task:
- **One dedicated runtime, synchronous callers.** `RusshEngine` owns a multi-thread tokio runtime (`EngineOptions::worker_threads`, default 2, thread name `sshelter-ssh`) and `block_on`s into it from the caller's thread, so everything the traits expose is synchronous (spec §4, §6.1). Never call it from inside an async task. `RuntimeOwner` ends the runtime with `shutdown_background()` because dropping a runtime the normal way panics when it happens on one of the runtime's own threads, which is where the last session can end up being dropped.
- **Borrowed references stay on the connect thread.** `&dyn HostKeyPolicy` and `&dyn AuthSource` cannot enter russh's `'static` tasks. The handler therefore holds only an `Arc<HopShared>` and a channel sender; `connect_hop` runs russh's `connect_stream` future inside a `tokio::select!` together with the receiving end (Task 10 moves this into `handshake`, generic over the stream), and answers each `KeyQuestion` with `host_keys.check(..)` right there, on the thread blocked in `connect`. The signer is a value that borrows the `AuthSource` and is passed by `&mut` to `authenticate_publickey_with`, which runs inside the same future, so `AuthSource::sign` also runs on that thread. This is what lets the traits stay plain borrowed `&dyn`.
- **Host keys never wait for a person (spec §6.2 step 3).** `check_server_key` asks the policy; for `Unknown` and `Mismatch` it records the key and the verdict in `HopShared::observed` and returns `false`, so the handshake fails with russh's `UnknownKey`, which is the same error for both cases; `handshake_error` reads the record and returns `HostKeyUnknown { key }` or `HostKeyMismatch { key, pinned }`. russh asks the question once, in the first key exchange, and reuses that key in every later one (measured with russh 0.64.1: the server's `RekeyLimit` and the client's own limits never ask again), so the question channel can be closed when `connect` returns; Task 8 has the test that fails if an upgrade changes that. The caller pins and connects again: `after_the_user_pins_the_key_the_same_policy_lets_the_next_connect_through`.
- **Algorithms (spec §6.3 a).** `host_key_algorithms` is russh's `Preferred::DEFAULT.key` without `Rsa { hash: None }` (`ssh-rsa`, SHA-1). For a pinned host it is cut down to the pinned key's family (an RSA pin keeps `rsa-sha2-512` and `rsa-sha2-256`), so a server that later adds another key type is not reported as a changed key (`a_pinned_key_narrows_the_handshake_to_its_algorithm_family` has the control: without the restriction the same server reports a mismatch). A server that offers nothing in common gives `NoCommonHostKeyAlgorithm { ours, theirs }`, and its `Display` explains `ssh-rsa`.
- **Never SHA-1 (spec §6.3 b).** `preferred.key` only governs host keys; the hash of a *login* signature is chosen by the caller of russh's `Signer`, and the default would sign SHA-1. Two layers: `choose_rsa_hash` decides from `Handle::best_supported_rsa_hash()` (called for RSA keys only; it waits up to a second for the server's `server-sig-algs`) and skips the key method with a reason when the server lists only `ssh-rsa`; and `EngineSigner::auth_sign` refuses to sign an RSA key whose `hash_alg` is `None` without calling `AuthSource::sign`. The signature is returned the way russh wants it: the buffer it gave, then `u32 length || blob` (spec §15).
- **Login (spec §6.2 step 4).** `authenticate` walks `Hop::auth_sequence()`. Only a server refusal (`AuthResult::Failure`) moves on to the next method on the same connection. A signer error ends the login with `AuthAbandoned` and the connection is dropped: after `sign` fails russh's session is stuck waiting for the signature, `authenticate_none` never answers and `disconnect()` does nothing (Task 9 measures it), so the only way out is to drop the `Handle`. Password and keyboard-interactive are written in Task 11; until then they are skipped like any method with nothing to offer.
- **Timeouts.** TCP plus handshake share `hop.connect_timeout` (at least one second) through `tokio::time::timeout`, and the error says which `Phase` it was in; every `authenticate_*` call is wrapped in the same limit and ends as `Timeout { phase: Auth }`. DNS and TCP failures are `Unreachable` with the OS error number removed (`describe_io`); `a_port_with_nothing_behind_it_is_unreachable_and_says_connection_refused` asserts the exact sentence on Unix only, because it needs no sshd and so also runs on the Windows runner, where the operating system words the refusal differently. `TCP_NODELAY` is set on the socket when `hop.nodelay` (the default; russh applies `Config::nodelay` only in its own `connect`, and the engine uses `connect_stream`).
- **Liveness is read from state.** `Connection::is_open` is true while no hop's `Handle` is closed (Task 8 adds a `closing` flag to it); the error that a call returned is never used to decide whether the connection is alive. Disconnect reasons are recorded by `Handler::disconnected` into `HopShared::ended` (`classify_end` turns russh's error into a `DisconnectKind` and a phrase).
- **One hop only, for now.** `connect_hop` refuses every hop after the first with `BadJumpChain { why: "jump hosts are not connected yet" }`; Task 10 replaces that line, and the red step of Task 10 shows the nine jump tests failing with exactly that error. (`check_chain` already rejects an empty chain and a host listed twice.)
- **The engine must outlive its connection.** A `Connection` does not own the runtime that drives it; the `RusshEngine` does (from Task 8 on a `RusshSession` holds it as well). A test that holds a `Connection` therefore keeps the engine in a variable: an engine that is a temporary, dropped at the end of its statement, shuts the runtime down and every hop ends a moment later. That is what made `an_ecdsa_p256_key_in_the_vault_logs_in` fail once in about thirty whole-suite runs before it was understood: `is_open()` was checked right after the connect, and under load the shutdown won the race. It is a mistake of the test, and the doc comment of `Connection` now says so.
- **Test servers.** The engine tests start a scratch sshd per test (`Server::start*`). `ssh::tests::russh_is_named_by_russh_engine_rs_and_by_no_other_file` is the guard of the global rule: it scans `src/` for `russh::`, `use russh` and `extern crate russh`, with the word assembled at run time so the test file does not contain it. `an_rsa_key_is_never_signed_with_sha1` can be skipped with `SSHELTER_SKIP_SHA1=1` on a machine whose OpenSSH cannot be told to accept `ssh-rsa` login signatures; it is not skipped anywhere this plan runs.

- [ ] **Step 1: Write the tests**

The tests are written first and, apart from the in-file unit tests of `russh_engine.rs`, live in `engine_tests/`. Every one that needs a scratch sshd returns early with `skipped` when the OpenSSH tools are missing; the commands here set `SSHELTER_REQUIRE_OPENSSH=1` so that never happens silently.

`src-tauri/src/ssh/engine_tests/mod.rs`: create

```rust
//! Integration tests of the russh engine against a scratch OpenSSH server (own-ssh spec §12). Each test starts its own sshd; a test
//! returns early, printing "skipped", where the OpenSSH tools are missing (`SSHELTER_REQUIRE_OPENSSH=1` turns that into a failure).

mod connect;

use super::russh_engine::{EngineOptions, RusshEngine};
use super::testing::fixture::Server;

/// An engine with a small runtime, one per test.
fn engine() -> RusshEngine {
    RusshEngine::with_options(EngineOptions { worker_threads: 2, ..EngineOptions::default() })
}

/// sshd logs accepted logins at INFO; the default of the harness is ERROR.
const LOG_LOGINS: &str = "LogLevel INFO";

/// How many public-key logins sshd has accepted (needs `LOG_LOGINS`).
fn accepted_logins(server: &Server) -> usize {
    server.sshd.log().lines().filter(|line| line.contains("Accepted publickey")).count()
}
```

`src-tauri/src/ssh/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/mod.rs
+++ b/src-tauri/src/ssh/mod.rs
@@ -5,9 +5,12 @@
 //! that file.
 
 mod channel;
+#[cfg(test)]
+mod engine_tests;
 mod error;
 #[cfg(test)]
 pub mod fake;
+pub mod russh_engine;
 #[cfg(test)]
 pub mod testing;
 mod traits;
@@ -20,3 +23,46 @@ pub use types::{
     AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostId, HostKey, HostKeyVerdict, Phase, Prompt,
     Pty, RsaHash, Secret, Signature, Target, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY, DEFAULT_KEEPALIVE_MAX_MISSED,
 };
+
+#[cfg(test)]
+mod tests {
+    use std::path::{Path, PathBuf};
+
+    /// Every `.rs` file under `dir` (recursively), sorted so that a failure message is the same every time.
+    fn rust_files(dir: &Path) -> Vec<PathBuf> {
+        let mut found = Vec::new();
+        for entry in std::fs::read_dir(dir).unwrap_or_else(|error| panic!("cannot list {}: {error}", dir.display())) {
+            let path = entry.unwrap_or_else(|error| panic!("cannot list {}: {error}", dir.display())).path();
+            if path.is_dir() {
+                found.extend(rust_files(&path));
+            } else if path.extension().is_some_and(|extension| extension == "rs") {
+                found.push(path);
+            }
+        }
+        found.sort();
+        found
+    }
+
+    /// The engine can be replaced one day (spec §1, goal 5), so the library that speaks SSH is named in one file only. The text searched
+    /// for is put together at run time, so that this file does not contain it.
+    #[test]
+    fn russh_is_named_by_russh_engine_rs_and_by_no_other_file() {
+        let source = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
+        let engine = source.join("ssh").join("russh_engine.rs");
+        let files = rust_files(source);
+        assert!(files.contains(&engine), "the scan did not find {}: it would pass without looking at anything", engine.display());
+
+        let name = ["rus", "sh"].concat();
+        let needles = [format!("{name}::"), format!("use {name}"), format!("extern crate {name}")];
+        let mut offenders = Vec::new();
+        for file in files.iter().filter(|file| **file != engine) {
+            let text = std::fs::read_to_string(file).unwrap_or_else(|error| panic!("cannot read {}: {error}", file.display()));
+            for (index, line) in text.lines().enumerate() {
+                if needles.iter().any(|needle| line.contains(needle.as_str())) {
+                    offenders.push(format!("{}:{}: {}", file.strip_prefix(source).unwrap_or(file).display(), index + 1, line.trim()));
+                }
+            }
+        }
+        assert!(offenders.is_empty(), "only ssh/russh_engine.rs may use {name}, but it is used in {} place(s):\n{}", offenders.len(), offenders.join("\n"));
+    }
+}
```

`src-tauri/src/ssh/testing/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/testing/mod.rs
+++ b/src-tauri/src/ssh/testing/mod.rs
@@ -10,3 +10,16 @@ pub mod proxy;
 pub fn fact(key: &str, value: impl std::fmt::Display) {
     eprintln!("FACT {key} = {value}");
 }
+
+/// Polls `condition` until it holds; panics naming `what` when it does not within `seconds`. For things that happen on another thread or
+/// in another process a moment after the call that caused them returned (a log line, a closed socket).
+pub fn eventually(what: &str, seconds: u64, mut condition: impl FnMut() -> bool) {
+    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
+    while std::time::Instant::now() < deadline {
+        if condition() {
+            return;
+        }
+        std::thread::sleep(std::time::Duration::from_millis(20));
+    }
+    panic!("timed out after {seconds} s waiting for: {what}");
+}
```

`src-tauri/src/ssh/engine_tests/connect.rs`: create

```rust
//! Connecting: host keys, login with vault keys, and the ways a connection attempt fails.

use std::time::{Duration, Instant};

use super::{accepted_logins, engine, LOG_LOGINS};
use crate::ssh::testing::doubles::{SignCall, TestPolicy, VaultAuth};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::{generate_key, tools, KeyKind};
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthError, AuthMethod, ConnectError, Hop, HostKey, Phase, RsaHash, Target};
use crate::sync::slot_rules::test_keys;

/// A policy that trusts everything, as a `&dyn`-able value.
fn trusting() -> std::sync::Arc<TestPolicy> {
    TestPolicy::trusting()
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Host keys (spec §6.2 step 3). The engine never waits for a person: an unpinned key fails the connect with the key that was seen.

#[test]
fn an_unknown_host_key_fails_fast_with_the_key_the_server_presented_and_leaves_no_connection_behind() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let proxy = Proxy::start(server.sshd.port);
    let hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    let policy = TestPolicy::knowing_nothing();

    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop.clone()] }, &*policy, &server.vault("k1")).err().expect("an unknown key stops the connect");
    assert!(started.elapsed() < Duration::from_secs(5), "no waiting for a person: {:?}", started.elapsed());
    match error {
        ConnectError::HostKeyUnknown { hop: seen, key } => {
            assert_eq!(seen.alias, "web");
            assert_eq!(key, server.host_key());
        }
        other => panic!("expected HostKeyUnknown, got {other:?}"),
    }
    assert_eq!(policy.seen().len(), 1, "the policy was asked once");
    eventually("the proxy to see the connection closed", 5, || proxy.open_connections() == 0);
    assert_eq!(accepted_logins(&server), 0, "nobody logged in");
}

#[test]
fn after_the_user_pins_the_key_the_same_policy_lets_the_next_connect_through() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let hop = server.hop("web", "k1");
    let target = Target { hops: vec![hop.clone()] };
    let policy = TestPolicy::knowing_nothing();
    let engine = engine();

    let ConnectError::HostKeyUnknown { key, .. } = engine.connect_chain(&target, &*policy, &server.vault("k1")).err().expect("first time") else {
        panic!("expected HostKeyUnknown");
    };
    policy.pin(&hop.reference(), key);
    let connection = engine.connect_chain(&target, &*policy, &server.vault("k1")).expect("second time, the key is pinned");
    assert!(connection.is_open());
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
}

#[test]
fn a_changed_host_key_is_a_mismatch_that_carries_the_observed_and_the_pinned_key() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let hop = server.hop("web", "k1");
    let policy = TestPolicy::knowing_nothing();
    let old = HostKey::from_openssh_line(test_keys::PLAIN_PUBLIC).expect("a key line");
    policy.pin(&hop.reference(), old.clone());

    match engine().connect_chain(&Target { hops: vec![hop] }, &*policy, &server.vault("k1")) {
        Err(ConnectError::HostKeyMismatch { key, pinned, .. }) => assert_eq!((key, pinned), (server.host_key(), old)),
        other => panic!("expected HostKeyMismatch, got {:?}", other.err()),
    }
}

/// `Hop::pinned` narrows the host key algorithms offered to the one family. The server has an ed25519 and an RSA key; the pin is the RSA one.
/// With the family restriction the handshake lands on the RSA key (a match); without it the client's first choice, ed25519, comes up
/// and would be reported as a changed key (the control).
#[test]
fn a_pinned_key_narrows_the_handshake_to_its_algorithm_family() {
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, &[KeyKind::Ed25519, KeyKind::Rsa3072], KeyKind::Ed25519, &[]);
    let rsa_key = server.host_keys().remove(1);
    assert_eq!(rsa_key.algorithm, "ssh-rsa");

    let mut hop = server.hop("web", "k1");
    let policy = TestPolicy::knowing_nothing();
    policy.pin(&hop.reference(), rsa_key.clone());

    // The engine owns the runtime that drives a connection: it must outlive the `Connection`, or the connection ends under the test.
    let engine = engine();
    let control = engine.connect_chain(&Target { hops: vec![hop.clone()] }, &*policy, &server.vault("k1"));
    assert!(matches!(control, Err(ConnectError::HostKeyMismatch { ref key, .. }) if key.algorithm == "ssh-ed25519"), "without the restriction: {:?}", control.err());

    hop.pinned = Some(rsa_key.clone());
    let connection = engine.connect_chain(&Target { hops: vec![hop] }, &*policy, &server.vault("k1")).expect("the RSA family was offered");
    assert!(connection.is_open());
    assert_eq!(policy.seen().last().map(|(_, key)| key.clone()), Some(rsa_key));
}

#[test]
fn a_server_that_only_has_an_ssh_rsa_host_key_has_nothing_in_common_and_the_message_says_why() {
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, &[KeyKind::Rsa3072], KeyKind::Ed25519, &["HostKeyAlgorithms ssh-rsa"]);
    let error = engine().connect_chain(&server.target("k1"), &*trusting(), &server.vault("k1")).err().expect("SHA-1 host keys are refused");
    fact("host_key.no_common_algorithm.error", format!("{error:?}"));
    match &error {
        ConnectError::NoCommonHostKeyAlgorithm { ours, theirs, .. } => {
            assert_eq!(theirs, &["ssh-rsa".to_string()]);
            assert!(!ours.iter().any(|name| name == "ssh-rsa") && ours.iter().any(|name| name == "ssh-ed25519"), "our list: {ours:?}");
        }
        other => panic!("expected NoCommonHostKeyAlgorithm, got {other:?}"),
    }
    assert!(error.to_string().contains("SHA-1"), "the sentence explains: {error}");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Login with vault keys (spec §6.3 b: the engine refuses to sign RSA with SHA-1).

fn log_in_with_a_key_of(kind: KeyKind) -> Option<Vec<SignCall>> {
    let tools = tools()?;
    let server = Server::start_with(&tools, &[KeyKind::Ed25519], kind, &[LOG_LOGINS]);
    let auth = server.vault("k1");
    // The engine owns the runtime that drives a connection: it must outlive the `Connection`, or the connection ends under the test.
    let engine = engine();
    let connection = engine.connect_chain(&server.target("k1"), &*trusting(), &auth).expect("the vault key logs in");
    assert_eq!(connection.hop_count(), 1);
    assert!(connection.is_open());
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
    Some(auth.sign_calls())
}

#[test]
fn an_ed25519_key_in_the_vault_logs_in() {
    let Some(calls) = log_in_with_a_key_of(KeyKind::Ed25519) else { return };
    assert_eq!(calls, vec![SignCall { key_id: "k1".into(), rsa_hash: None, algorithm: Some("ssh-ed25519".into()) }]);
}

#[test]
fn an_ecdsa_p256_key_in_the_vault_logs_in() {
    let Some(calls) = log_in_with_a_key_of(KeyKind::EcdsaP256) else { return };
    assert_eq!(calls, vec![SignCall { key_id: "k1".into(), rsa_hash: None, algorithm: Some("ecdsa-sha2-nistp256".into()) }]);
}

#[test]
fn an_rsa_3072_key_in_the_vault_logs_in_with_a_sha2_signature() {
    let Some(calls) = log_in_with_a_key_of(KeyKind::Rsa3072) else { return };
    assert_eq!(calls.len(), 1);
    let algorithm = calls[0].algorithm.clone().unwrap_or_default();
    fact("signer.rsa.algorithm_on_the_wire", &algorithm);
    assert!(algorithm == "rsa-sha2-512" || algorithm == "rsa-sha2-256", "a modern server gets a SHA-2 signature, got {algorithm}");
    assert!(matches!(calls[0].rsa_hash, Some(RsaHash::Sha512) | Some(RsaHash::Sha256)));
}

/// The server knows key A and is shown A's public key, but the vault signs with B: the server checks the signature and says no.
#[test]
fn a_signature_made_by_another_key_is_refused() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let other_dir = tempfile::tempdir().unwrap();
    let other = generate_key(&tools, other_dir.path(), "other", KeyKind::Ed25519);
    let auth = VaultAuth::new().with_key("k1", &other.private_text).presenting_public_key("k1", &server.key.public_line);

    let error = engine().connect_chain(&server.target("k1"), &*trusting(), &auth).err().expect("a wrong signature must not log in");
    assert!(matches!(&error, ConnectError::AuthFailed { tried, .. } if *tried == [AuthMethod::Key { key_id: "k1".into() }]), "{error:?}");
    assert_eq!(auth.sign_calls().len(), 1, "the server asked for the signature once and refused it");
    assert_eq!(accepted_logins(&server), 0);
}

/// A key the server does not list is refused before any signature is asked for.
#[test]
fn a_key_the_server_does_not_know_is_refused_without_a_signature() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let stranger_dir = tempfile::tempdir().unwrap();
    let stranger = generate_key(&tools, stranger_dir.path(), "stranger", KeyKind::Ed25519);
    let auth = VaultAuth::new().with_key("k1", &stranger.private_text);

    let error = engine().connect_chain(&server.target("k1"), &*trusting(), &auth).err().expect("an unknown key must not log in");
    assert!(matches!(error, ConnectError::AuthFailed { .. }), "{error:?}");
    assert!(auth.sign_calls().is_empty(), "the server never got as far as asking for a signature");
}

/// Review focus: SHA-1. The server accepts RSA login signatures only as `ssh-rsa` (SHA-1). The engine must refuse to make such a
/// signature: `sign` is never called, and the failure says why.
#[test]
fn an_rsa_key_is_never_signed_with_sha1() {
    if std::env::var("SSHELTER_SKIP_SHA1").is_ok_and(|value| value == "1") {
        eprintln!("skipped: SSHELTER_SKIP_SHA1=1");
        return;
    }
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, &[KeyKind::Ed25519], KeyKind::Rsa3072, &["PubkeyAcceptedAlgorithms ssh-rsa", LOG_LOGINS]);
    let auth = server.vault("k1");

    let error = engine().connect_chain(&server.target("k1"), &*trusting(), &auth).err().expect("a SHA-1-only server cannot be logged in to");
    match &error {
        ConnectError::AuthFailed { tried, reason, .. } => {
            assert_eq!(*tried, [AuthMethod::Key { key_id: "k1".into() }]);
            assert!(reason.contains("SHA-1"), "the reason names SHA-1: {reason}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert!(auth.sign_calls().is_empty(), "the vault was never asked to sign: {:?}", auth.sign_calls());
    assert_eq!(accepted_logins(&server), 0);
}

#[test]
fn a_key_that_is_not_in_the_vault_is_skipped_and_the_failure_says_so() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let error = engine().connect_chain(&server.target("missing"), &*trusting(), &VaultAuth::new()).err().expect("no key, no login");
    match error {
        ConnectError::AuthFailed { tried, reason, .. } => {
            assert!(tried.is_empty(), "nothing was tried: {tried:?}");
            assert!(reason.contains("missing"), "the reason names the key: {reason}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Failures to connect, and the login that is abandoned.

fn a_port_nobody_listens_on() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

#[test]
fn a_port_with_nothing_behind_it_is_unreachable_and_says_connection_refused() {
    let hop = Hop::new("h1", "gone", "127.0.0.1", a_port_nobody_listens_on(), "tester", AuthMethod::Password);
    let error = engine().connect_chain(&Target { hops: vec![hop.clone()] }, &*trusting(), &VaultAuth::new()).err().expect("nothing listens there");
    assert!(matches!(&error, ConnectError::Unreachable { reason, .. } if reason.contains("refused")), "{error:?}");
    let text = error.to_string();
    assert!(text.starts_with(&format!("Could not reach 127.0.0.1:{} (", hop.port)) && text.ends_with(").") && text.contains("refused"), "{text}");
    // The operating system's own words differ (Windows says "no connection could be made because the target machine actively refused it").
    #[cfg(unix)]
    assert_eq!(text, format!("Could not reach 127.0.0.1:{} (connection refused).", hop.port));
}

#[test]
fn a_name_that_does_not_resolve_is_unreachable() {
    let hop = Hop::new("h1", "nowhere", "does-not-exist.invalid", 22, "tester", AuthMethod::Password);
    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &VaultAuth::new()).err().expect("the name cannot be resolved");
    assert!(matches!(error, ConnectError::Unreachable { .. }), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10), "DNS failures are quick: {:?}", started.elapsed());
}

/// Review focus: a server that accepts the TCP connection and then says nothing. russh has no handshake timeout; the engine's is the
/// host record's `connect_timeout`.
#[test]
fn a_handshake_that_never_gets_an_answer_times_out_after_the_connect_timeout() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port);
    proxy.set(Mode::Blackhole);
    let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    hop.connect_timeout = Duration::from_secs(2);

    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &server.vault("k1")).err().expect("nothing answers");
    let waited = started.elapsed();
    fact("handshake_stall.waited_ms", waited.as_millis());
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Handshake, .. }), "{error:?}");
    assert!(waited >= Duration::from_millis(1800) && waited < Duration::from_secs(6), "waited {waited:?}");
}

/// The server accepts the connection and the handshake and then goes silent in the middle of the login. After the handshake the first
/// thing the engine asks the auth source is the public key, so this one turns the link into a black hole at that moment.
#[test]
fn a_server_that_stops_answering_during_the_login_times_out_in_the_auth_phase() {
    use crate::ssh::{AuthSource, HopRef, Prompt, Secret, Signature};
    use std::sync::Arc;

    struct GoesQuiet {
        inner: VaultAuth,
        proxy: Arc<Proxy>,
    }
    impl AuthSource for GoesQuiet {
        fn public_key(&self, key_id: &str) -> Option<String> {
            self.proxy.set(Mode::Blackhole);
            self.inner.public_key(key_id)
        }
        fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
            self.inner.sign(key_id, data, rsa_hash)
        }
        fn password(&self, hop: &HopRef) -> Option<Secret> {
            self.inner.password(hop)
        }
        fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
            self.inner.interactive(hop, prompts, deadline)
        }
    }

    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Arc::new(Proxy::start(server.sshd.port));
    let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    hop.connect_timeout = Duration::from_secs(2);
    let auth = GoesQuiet { inner: server.vault("k1"), proxy: Arc::clone(&proxy) };

    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &auth).err().expect("the server went quiet");
    let waited = started.elapsed();
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Auth, .. }), "{error:?}");
    assert!(waited >= Duration::from_millis(1800) && waited < Duration::from_secs(6), "waited {waited:?}");
    // A black hole holds the bytes of both directions and so keeps the proxy's connection open; letting them through shows that the
    // engine's side was closed, which the proxy then notices.
    proxy.set(Mode::Forward);
    eventually("the proxy to see the connection dropped", 5, || proxy.open_connections() == 0);
}

/// Review focus: the vault is locked. `sign` fails; the login is abandoned with a clear error, quickly, and the connection is dropped
/// (russh's session is stuck waiting for the signature, so it cannot be reused).
#[test]
fn a_signer_that_fails_abandons_the_login_and_drops_the_connection() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port);
    let hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    let auth = server.vault("k1").failing_to_sign(AuthError::Refused("the vault is locked".into()));

    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &auth).err().expect("the vault would not sign");
    assert!(started.elapsed() < Duration::from_secs(5), "no hang: {:?}", started.elapsed());
    assert!(matches!(&error, ConnectError::AuthAbandoned { reason, .. } if reason.contains("the vault is locked")), "{error:?}");
    assert!(error.to_string().starts_with("Authentication for web was abandoned"), "{error}");
    eventually("the proxy to see the connection closed", 5, || proxy.open_connections() == 0);
}

#[test]
fn an_empty_chain_and_a_chain_that_lists_a_host_twice_are_refused_before_anything_connects() {
    let engine = engine();
    let hop = Hop::new("h1", "web", "127.0.0.1", a_port_nobody_listens_on(), "tester", AuthMethod::Password);
    let empty = engine.connect_chain(&Target { hops: vec![] }, &*trusting(), &VaultAuth::new());
    assert!(matches!(empty, Err(ConnectError::BadJumpChain { .. })));
    let loop_ = engine.connect_chain(&Target { hops: vec![hop.clone(), hop] }, &*trusting(), &VaultAuth::new());
    assert!(matches!(loop_, Err(ConnectError::BadJumpChain { ref why }) if why.contains("web")), "{:?}", loop_.err());
}
```

`src-tauri/src/ssh/russh_engine.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use russh::keys::EcdsaCurve;
    use russh::Signer;

    use super::*;
    use crate::ssh::{AuthError, Prompt, Secret, Signature};
    use crate::sync::slot_rules::test_keys;

    #[test]
    fn io_errors_are_described_without_the_os_number_or_a_leading_capital() {
        let os = std::io::Error::new(std::io::ErrorKind::Other, "Connection refused (os error 61)");
        assert_eq!(describe_io(&os), "connection refused");
        let dns = std::io::Error::new(std::io::ErrorKind::Other, "DNS lookup failed");
        assert_eq!(describe_io(&dns), "DNS lookup failed", "an acronym keeps its capitals");
        let plain = std::io::Error::new(std::io::ErrorKind::Other, "failed to lookup address information");
        assert_eq!(describe_io(&plain), "failed to lookup address information");
    }

    #[test]
    fn a_connection_that_ended_is_described_by_the_error_that_ended_it() {
        assert_eq!(classify_end(&russh::Error::KeepaliveTimeout).0, DisconnectKind::KeepaliveTimeout);
        assert_eq!(classify_end(&russh::Error::Disconnect).0, DisconnectKind::ClosedByUs);
        assert_eq!(classify_end(&russh::Error::HUP).0, DisconnectKind::ClosedByPeer);
        let eof = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "early eof");
        assert_eq!(classify_end(&russh::Error::IO(eof)), (DisconnectKind::ConnectionLost, "early eof".to_string()));
        assert_eq!(classify_end(&russh::Error::Kex).0, DisconnectKind::Other);
    }

    fn key(algorithm: &str) -> HostKey {
        HostKey { algorithm: algorithm.into(), public_key: vec![], fingerprint: String::new() }
    }

    #[test]
    fn the_host_key_list_has_no_ssh_rsa_and_a_pinned_key_narrows_it_to_its_family() {
        let defaults = host_key_algorithms(None);
        assert!(!defaults.contains(&Algorithm::Rsa { hash: None }), "ssh-rsa (SHA-1) is not offered: {defaults:?}");
        assert!(defaults.contains(&Algorithm::Ed25519) && defaults.contains(&Algorithm::Rsa { hash: Some(HashAlg::Sha512) }));

        assert_eq!(host_key_algorithms(Some(&key("ssh-ed25519"))), vec![Algorithm::Ed25519]);
        assert_eq!(host_key_algorithms(Some(&key("ecdsa-sha2-nistp384"))), vec![Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }]);
        assert_eq!(
            host_key_algorithms(Some(&key("ssh-rsa"))),
            vec![Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }],
            "an RSA key is offered as rsa-sha2-512 and rsa-sha2-256, never as SHA-1"
        );
        assert_eq!(host_key_algorithms(Some(&key("sk-ssh-ed25519@openssh.com"))), defaults, "a type we do not offer restricts nothing");
        assert_eq!(host_key_algorithms(Some(&key("not-an-algorithm"))), defaults);
    }

    #[test]
    fn the_rsa_hash_is_what_the_server_lists_and_never_sha1() {
        assert_eq!(choose_rsa_hash(Some(Some(HashAlg::Sha512))), RsaChoice::Use(HashAlg::Sha512));
        assert_eq!(choose_rsa_hash(Some(Some(HashAlg::Sha256))), RsaChoice::Use(HashAlg::Sha256));
        assert_eq!(choose_rsa_hash(Some(None)), RsaChoice::Sha1Only, "the server lists only ssh-rsa");
        assert_eq!(choose_rsa_hash(None), RsaChoice::Use(HashAlg::Sha256), "a server that never announced its algorithms is tried with SHA-256");
    }

    /// Counts the calls to `sign` and the hash each one got.
    #[derive(Default)]
    struct Counting {
        signs: Mutex<Vec<Option<RsaHash>>>,
    }

    impl AuthSource for Counting {
        fn public_key(&self, _key_id: &str) -> Option<String> {
            None
        }
        fn sign(&self, _key_id: &str, _data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
            locked(&self.signs).push(rsa_hash);
            Ok(Signature(vec![7, 7]))
        }
        fn password(&self, _hop: &HopRef) -> Option<Secret> {
            None
        }
        fn interactive(&self, _hop: &HopRef, _prompts: &[Prompt], _deadline: std::time::Instant) -> Option<Vec<Secret>> {
            None
        }
    }

    /// The last line of defence for spec §6.3 b: even if the caller of the signer asked for SHA-1, an RSA key is never signed with it and
    /// `sign` is not called. For the other key types the hash means nothing and is not passed on.
    #[test]
    fn the_signer_never_asks_for_an_rsa_signature_with_sha1_and_appends_the_signature_to_what_russh_gave_it() {
        let rsa: AgentIdentity = PublicKey::from_openssh(test_keys::RSA_PUBLIC).expect("an rsa key").into();
        let ed25519: AgentIdentity = PublicKey::from_openssh(test_keys::PLAIN_PUBLIC).expect("an ed25519 key").into();
        let auth = Counting::default();
        let mut signer = EngineSigner { auth: &auth, key_id: "k1" };
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("a runtime");

        assert!(matches!(runtime.block_on(signer.auth_sign(&rsa, None, vec![1, 2, 3])), Err(SignerFailure::Sha1Refused)));
        assert!(locked(&auth.signs).is_empty(), "sign was not called for SHA-1");

        let signed = runtime.block_on(signer.auth_sign(&rsa, Some(HashAlg::Sha512), vec![1, 2, 3])).expect("signs with SHA-512");
        assert_eq!(signed, vec![1, 2, 3, 0, 0, 0, 2, 7, 7], "the buffer comes back unchanged, then the length and the signature blob");
        let signed = runtime.block_on(signer.auth_sign(&ed25519, None, vec![9])).expect("an ed25519 key has no hash");
        assert_eq!(signed, vec![9, 0, 0, 0, 2, 7, 7]);
        assert_eq!(*locked(&auth.signs), vec![Some(RsaHash::Sha512), None]);
    }
}
```

`src-tauri/src/ssh/testing/doubles.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/testing/doubles.rs
+++ b/src-tauri/src/ssh/testing/doubles.rs
@@ -85,6 +85,7 @@ pub struct SignCall {
 /// An `AuthSource` over real vault entries. Keys are registered under ids with `with_key`; passwords and answers come from the script.
 pub struct VaultAuth {
     keys: HashMap<String, (Material, String)>,
+    presented: HashMap<String, String>,
     password: Option<String>,
     password_delay: Duration,
     answers: Option<Vec<String>>,
@@ -100,6 +101,7 @@ impl VaultAuth {
     pub fn new() -> VaultAuth {
         VaultAuth {
             keys: HashMap::new(),
+            presented: HashMap::new(),
             password: None,
             password_delay: Duration::ZERO,
             answers: None,
@@ -120,6 +122,13 @@ impl VaultAuth {
         self
     }
 
+    /// `public_key(key_id)` answers `public_line` instead of the public half of the key registered under `key_id`: the login announces one
+    /// key and signs with another (the negative control of the signature check).
+    pub fn presenting_public_key(mut self, key_id: &str, public_line: &str) -> VaultAuth {
+        self.presented.insert(key_id.to_string(), public_line.to_string());
+        self
+    }
+
     /// `password` returns this (the user "typed" it). Without it `password` returns `None`.
     pub fn with_password(mut self, password: &str) -> VaultAuth {
         self.password = Some(password.to_string());
@@ -183,7 +192,7 @@ fn algorithm_of(blob: &[u8]) -> Option<String> {
 
 impl AuthSource for VaultAuth {
     fn public_key(&self, key_id: &str) -> Option<String> {
-        self.keys.get(key_id).map(|(_, public_line)| public_line.clone())
+        self.presented.get(key_id).cloned().or_else(|| self.keys.get(key_id).map(|(_, public_line)| public_line.clone()))
     }
 
     fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate does not compile. The first error is `error[E0432]: unresolved imports `super::russh_engine::EngineOptions`, `super::russh_engine::RusshEngine``, and the run ends with `error: could not compile `sshelter` (lib test) due to 62 previous errors` (the number of errors depends on the compiler; what matters is that the errors name items that do not exist yet). `ssh::tests::russh_is_named_by_russh_engine_rs_and_by_no_other_file` is among the tests that cannot run yet.

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/russh_engine.rs`: insert this above the `#[cfg(test)]` line, at the very top of the file, and leave one empty line between it and that line

```rust
//! The russh-backed engine (own-ssh spec §6): the only file in the app that imports russh (`ssh/mod.rs` has a test that keeps it so).
//!
//! The engine owns a dedicated tokio runtime and drives it with `block_on`, so everything on the `SshEngine` side is synchronous. The
//! caller's references (`&dyn HostKeyPolicy`, `&dyn AuthSource`) never leave the connect call: the connection tasks russh spawns see only
//! `'static` data, and the one question they must ask the caller (is this host key trusted?) travels over a channel to the thread that
//! is blocked in `connect`, which answers it.
//!
//! What the phase-0 spike taught, as rules (spec §6.2, §6.3): a handshake or a login call that waits for the application stalls the
//! whole connection, so nothing here waits for a person inside a callback; every wait is bounded; a failed or abandoned login drops the
//! connection instead of switching method on it; liveness is read from the connection's own state, never from an error variant.

use std::borrow::Cow;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use russh::client::{self, AuthResult, Config, Handle, Handler};
use russh::client::DisconnectReason as RusshDisconnect;
use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{AlgorithmKind, Disconnect, MethodKind, MethodSet, Preferred};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::error::{AuthError, ConnectError};
use super::traits::{AuthSource, HostKeyPolicy};
use super::types::{AuthMethod, DisconnectKind, Hop, HopRef, HostKey, HostKeyVerdict, Phase, RsaHash, Target};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Knobs of the engine that are not part of a host record. The defaults are what the app uses; tests turn some of them down.
#[derive(Clone, Debug)]
pub struct EngineOptions {
    /// Bytes of shell output kept between the channel reader and the thread that reads the shell (see `ByteQueue`).
    pub shell_queue_bytes: usize,
    /// Worker threads of the engine's runtime.
    pub worker_threads: usize,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions { shell_queue_bytes: 4 * 1024 * 1024, worker_threads: 2 }
    }
}

/// The engine's runtime, shut down without waiting when the last owner lets go (dropping a runtime the normal way panics when it
/// happens on one of the runtime's own threads, which is where the last session can end up being dropped).
struct RuntimeOwner {
    runtime: Option<tokio::runtime::Runtime>,
    handle: tokio::runtime::Handle,
}

impl RuntimeOwner {
    fn handle(&self) -> tokio::runtime::Handle {
        self.handle.clone()
    }
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// The russh engine. Cheap to create (it starts a small runtime), meant to live as long as the app.
pub struct RusshEngine {
    runtime: Arc<RuntimeOwner>,
}

impl Default for RusshEngine {
    fn default() -> Self {
        RusshEngine::new()
    }
}

impl RusshEngine {
    pub fn new() -> RusshEngine {
        RusshEngine::with_options(EngineOptions::default())
    }

    pub fn with_options(options: EngineOptions) -> RusshEngine {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(options.worker_threads.max(1))
            .thread_name("sshelter-ssh")
            .enable_all()
            .build()
            .expect("the SSH engine's runtime");
        let handle = runtime.handle().clone();
        RusshEngine { runtime: Arc::new(RuntimeOwner { runtime: Some(runtime), handle }) }
    }

    /// Connects every hop of `target` and logs in to each; the connection-level half of `SshEngine::connect`. Blocks the calling thread
    /// (never call it from inside an async task).
    pub fn connect_chain(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
        self.runtime.handle().block_on(connect_chain(target, host_keys, auth))
    }
}

/// What the handler and the engine both need to know about one hop's connection.
struct HopShared {
    /// The last host key the policy judged, and its verdict.
    observed: Mutex<Option<(HostKey, HostKeyVerdict)>>,
    /// Set by `Handler::disconnected`: how this hop's connection ended.
    ended: Mutex<Option<(DisconnectKind, String)>>,
}

impl HopShared {
    fn new() -> Arc<HopShared> {
        Arc::new(HopShared { observed: Mutex::new(None), ended: Mutex::new(None) })
    }
}

/// A host key waiting for the policy's verdict, sent from the connection's task to the thread blocked in `connect`.
struct KeyQuestion {
    key: HostKey,
    reply: oneshot::Sender<HostKeyVerdict>,
}

struct EngineHandler {
    shared: Arc<HopShared>,
    questions: mpsc::UnboundedSender<KeyQuestion>,
}

/// The host key in the form a host record stores it, through the OpenSSH text form (only bytes cross between the two `ssh-key` generations).
fn host_key_of(key: &PublicKey) -> Option<HostKey> {
    HostKey::from_openssh_line(&key.to_openssh().ok()?)
}

impl Handler for EngineHandler {
    type Error = russh::Error;

    /// Never waits for a person (spec §6.2 step 3): the policy answers from its table through the connect thread, and `Unknown` or
    /// `Mismatch` makes the handshake fail with `UnknownKey`, which `connect` turns into `HostKeyUnknown` or `HostKeyMismatch`.
    ///
    /// russh asks once, in the first key exchange; a later one (the server's `RekeyLimit`, the client's 1 GiB or one hour) reuses that key
    /// and does not ask again (measured with russh 0.64.1). The question channel is closed once `connect` has returned, so a question
    /// asked later could only be answered `false`; `a_connection_survives_the_key_exchanges_the_server_asks_for` fails if an upgrade of
    /// russh ever does that.
    async fn check_server_key(&mut self, server_public_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else { return Ok(false) };
        let Some(host_key) = host_key_of(key) else { return Ok(false) };
        let (reply, answer) = oneshot::channel();
        if self.questions.send(KeyQuestion { key: host_key.clone(), reply }).is_err() {
            return Ok(false);
        }
        let Ok(verdict) = answer.await else { return Ok(false) };
        let trusted = verdict == HostKeyVerdict::Pinned;
        *locked(&self.shared.observed) = Some((host_key, verdict));
        Ok(trusted)
    }

    async fn disconnected(&mut self, reason: RusshDisconnect<Self::Error>) -> Result<(), Self::Error> {
        let record = match &reason {
            RusshDisconnect::ReceivedDisconnect(info) => (DisconnectKind::ClosedByPeer, format!("the server closed the connection: {}", info.message)),
            RusshDisconnect::Error(error) => classify_end(error),
        };
        *locked(&self.shared.ended) = Some(record);
        match reason {
            RusshDisconnect::ReceivedDisconnect(_) => Ok(()),
            RusshDisconnect::Error(error) => Err(error),
        }
    }
}

/// How a connection that ended with this error is described. `Error::Disconnect` is what a disconnect we asked for looks like.
fn classify_end(error: &russh::Error) -> (DisconnectKind, String) {
    match error {
        russh::Error::KeepaliveTimeout => (DisconnectKind::KeepaliveTimeout, "the server stopped answering keepalive messages".to_string()),
        russh::Error::Disconnect => (DisconnectKind::ClosedByUs, "the connection was closed on our side".to_string()),
        russh::Error::HUP => (DisconnectKind::ClosedByPeer, "the server closed the connection".to_string()),
        russh::Error::IO(io) => (DisconnectKind::ConnectionLost, describe_io(io)),
        other => (DisconnectKind::Other, other.to_string()),
    }
}

/// An I/O error as a short lowercase phrase: no OS error number, no leading capital.
fn describe_io(error: &std::io::Error) -> String {
    let text = error.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text);
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(first), Some(second)) if first.is_ascii_uppercase() && second.is_ascii_lowercase() => format!("{}{}", first.to_ascii_lowercase(), &text[1..]),
        _ => text.to_string(),
    }
}

/// The host key algorithms offered to a server: russh's defaults without `ssh-rsa` (SHA-1), or, for a host with a pinned key, only that
/// key's family (spec §6.2 step 3, §6.3 a). An algorithm that is not in the default list (or that cannot be parsed) restricts nothing.
fn host_key_algorithms(pinned: Option<&HostKey>) -> Vec<Algorithm> {
    let defaults: Vec<Algorithm> = Preferred::DEFAULT.key.iter().filter(|algorithm| !matches!(algorithm, Algorithm::Rsa { hash: None })).cloned().collect();
    let Some(pinned) = pinned else { return defaults };
    let family: Vec<Algorithm> = match Algorithm::new(&pinned.algorithm) {
        Ok(Algorithm::Rsa { .. }) => vec![Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }],
        Ok(other) => vec![other],
        Err(_) => return defaults,
    };
    let restricted: Vec<Algorithm> = defaults.iter().filter(|algorithm| family.contains(algorithm)).cloned().collect();
    if restricted.is_empty() {
        defaults
    } else {
        restricted
    }
}

/// russh's `Config` for one hop: keepalive from the host record (russh's own default is off), the host key list above, and nothing else
/// changed from russh's defaults (mlkem768x25519, curve25519, chacha20-poly1305, aes-gcm, strict kex, rsa-sha2).
fn client_config(hop: &Hop) -> Config {
    Config {
        keepalive_interval: (!hop.keepalive_every.is_zero()).then_some(hop.keepalive_every),
        keepalive_max: hop.keepalive_max_missed as usize,
        preferred: Preferred { key: Cow::Owned(host_key_algorithms(hop.pinned.as_ref())), ..Preferred::DEFAULT },
        ..Config::default()
    }
}

/// A hop that is connected and logged in.
pub struct Established {
    handle: Handle<EngineHandler>,
}

/// The whole chain, outermost hop first. Owns every hop's `Handle`; a connection is closed by an explicit `disconnect()` on each hop,
/// because dropping the outer `Handle` ends nothing while an inner hop still holds one of its channels. It does not own the runtime that
/// drives it: when the engine that made it is dropped the runtime goes with it, and every hop ends.
pub struct Connection {
    hops: Vec<Established>,
}

impl Connection {
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// No hop's connection has ended.
    pub fn is_open(&self) -> bool {
        self.hops.iter().all(|established| !established.handle.is_closed())
    }

    /// Sends a disconnect on every hop, innermost first, and gives each a moment to leave before the next (outer) one goes.
    async fn disconnect_all(&self) {
        for established in self.hops.iter().rev() {
            let sent = tokio::time::timeout(Duration::from_secs(2), established.handle.disconnect(Disconnect::ByApplication, "", "en")).await;
            if matches!(sent, Ok(Ok(()))) {
                let gone = Instant::now() + Duration::from_millis(500);
                while !established.handle.is_closed() && Instant::now() < gone {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
}

async fn connect_chain(target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
    check_chain(target)?;
    let mut connection = Connection { hops: Vec::new() };
    for (index, hop) in target.hops.iter().enumerate() {
        match connect_one(index, hop, connection.hops.last(), host_keys, auth).await {
            Ok(established) => connection.hops.push(established),
            Err(error) => {
                connection.disconnect_all().await;
                return Err(error);
            }
        }
    }
    Ok(connection)
}

/// A chain needs at least one hop and may not list a host twice.
fn check_chain(target: &Target) -> Result<(), ConnectError> {
    if target.hops.is_empty() {
        return Err(ConnectError::BadJumpChain { why: "the target has no hosts".to_string() });
    }
    for (index, hop) in target.hops.iter().enumerate() {
        if target.hops[..index].iter().any(|earlier| earlier.id == hop.id) {
            return Err(ConnectError::BadJumpChain { why: format!("{} appears twice", hop.alias) });
        }
    }
    Ok(())
}

async fn connect_one(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Established, ConnectError> {
    let mut handle = connect_hop(index, hop, via, host_keys).await?;
    authenticate(hop, &mut handle, auth).await?;
    Ok(Established { handle })
}

async fn connect_hop(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy) -> Result<Handle<EngineHandler>, ConnectError> {
    let reference = hop.reference();
    if via.is_some() || index > 0 {
        return Err(ConnectError::BadJumpChain { why: "jump hosts are not connected yet".to_string() });
    }
    let shared = HopShared::new();
    let (questions_in, mut questions) = mpsc::unbounded_channel();
    let handler = EngineHandler { shared: Arc::clone(&shared), questions: questions_in };
    let config = Arc::new(client_config(hop));
    let phase = std::cell::Cell::new(Phase::Tcp);
    let attempt = async {
        let tcp = TcpStream::connect((hop.hostname.as_str(), hop.port)).await.map_err(|error| ConnectError::Unreachable { hop: reference.clone(), reason: describe_io(&error) })?;
        if hop.nodelay {
            let _ = tcp.set_nodelay(true);
        }
        phase.set(Phase::Handshake);
        let connecting = client::connect_stream(config, tcp, handler);
        tokio::pin!(connecting);
        let connected = loop {
            tokio::select! {
                connected = &mut connecting => break connected,
                Some(question) = questions.recv() => {
                    let verdict = host_keys.check(&reference, &question.key);
                    let _ = question.reply.send(verdict);
                }
            }
        };
        connected.map_err(|error| handshake_error(&reference, &shared, error))
    };
    let budget = hop.connect_timeout.max(Duration::from_secs(1));
    match tokio::time::timeout(budget, attempt).await {
        Ok(result) => result,
        Err(_) => Err(ConnectError::Timeout { hop: reference, phase: phase.get() }),
    }
}

/// Turns what russh said about a failed handshake into a `ConnectError`. A rejected host key is the same `UnknownKey` whether the key
/// was unknown or changed; the handler wrote down which.
fn handshake_error(hop: &HopRef, shared: &HopShared, error: russh::Error) -> ConnectError {
    match error {
        russh::Error::UnknownKey => match locked(&shared.observed).clone() {
            Some((key, HostKeyVerdict::Unknown)) => ConnectError::HostKeyUnknown { hop: hop.clone(), key },
            Some((key, HostKeyVerdict::Mismatch { pinned })) => ConnectError::HostKeyMismatch { hop: hop.clone(), key, pinned },
            _ => ConnectError::Protocol { hop: hop.clone(), text: "the server's host key was rejected".to_string() },
        },
        russh::Error::NoCommonAlgo { kind: AlgorithmKind::Key, ours, theirs } => ConnectError::NoCommonHostKeyAlgorithm { hop: hop.clone(), ours, theirs },
        russh::Error::IO(io) => ConnectError::Unreachable { hop: hop.clone(), reason: describe_io(&io) },
        russh::Error::HUP | russh::Error::Disconnect => ConnectError::Unreachable { hop: hop.clone(), reason: "the connection was closed during the handshake".to_string() },
        other => ConnectError::Protocol { hop: hop.clone(), text: other.to_string() },
    }
}

/// What to do about an RSA key, given `Handle::best_supported_rsa_hash`: `Some(Some(h))` = the server lists rsa-sha2 (best first),
/// `Some(None)` = it lists only `ssh-rsa`, `None` = it sent no `server-sig-algs` at all.
#[derive(Debug, PartialEq, Eq)]
enum RsaChoice {
    Use(HashAlg),
    Sha1Only,
}

fn choose_rsa_hash(best: Option<Option<HashAlg>>) -> RsaChoice {
    match best {
        Some(Some(hash)) => RsaChoice::Use(hash),
        Some(None) => RsaChoice::Sha1Only,
        // A server that never announced its signature algorithms: try SHA-256. One that does not know it refuses, and nothing was signed with SHA-1.
        None => RsaChoice::Use(HashAlg::Sha256),
    }
}

/// russh's `Signer` over the caller's `AuthSource`. `sign` is called right here, on the thread blocked in `connect`: it is quick by
/// contract, and the connection is waiting for the signature anyway.
struct EngineSigner<'a> {
    auth: &'a dyn AuthSource,
    key_id: &'a str,
}

#[derive(Debug)]
enum SignerFailure {
    /// russh's session is gone.
    SessionEnded,
    /// An RSA signature with SHA-1 was asked for: refused, `sign` was not called (spec §6.3 b).
    Sha1Refused,
    Auth(AuthError),
}

impl From<russh::SendError> for SignerFailure {
    fn from(_: russh::SendError) -> SignerFailure {
        SignerFailure::SessionEnded
    }
}

impl russh::Signer for EngineSigner<'_> {
    type Error = SignerFailure;

    /// `to_sign` is the session id and the login request without a signature; russh wants it back unchanged with the signature
    /// (`u32 length || blob`) appended, and cuts the session id off itself.
    async fn auth_sign(&mut self, key: &AgentIdentity, hash_alg: Option<HashAlg>, to_sign: Vec<u8>) -> Result<Vec<u8>, SignerFailure> {
        let rsa_hash = if key.public_key().algorithm().is_rsa() {
            match hash_alg {
                Some(HashAlg::Sha256) => Some(RsaHash::Sha256),
                Some(HashAlg::Sha512) => Some(RsaHash::Sha512),
                _ => return Err(SignerFailure::Sha1Refused),
            }
        } else {
            None
        };
        let signature = self.auth.sign(self.key_id, &to_sign, rsa_hash).map_err(SignerFailure::Auth)?;
        let mut signed = to_sign;
        signed.extend_from_slice(&(signature.0.len() as u32).to_be_bytes());
        signed.extend_from_slice(&signature.0);
        Ok(signed)
    }
}

fn method_kind(method: &AuthMethod) -> MethodKind {
    match method {
        AuthMethod::Key { .. } => MethodKind::PublicKey,
        AuthMethod::Password => MethodKind::Password,
        AuthMethod::Interactive => MethodKind::KeyboardInteractive,
    }
}

/// What one step of the login sequence came to, when it did not end the login.
enum Step {
    /// The server refused the method and listed the methods it would still take.
    Refused(MethodSet),
    /// The method was not tried (no key, no password, SHA-1 only): the server has not been asked anything.
    Skipped,
}

/// Logs in to a freshly connected hop. The methods of `hop.auth_sequence()` are tried in order, each only if the server still offers
/// it; a refusal moves to the next method on the same connection. A method that cannot be tried here is skipped, and then the server is
/// asked once what it does offer (`none`), so later methods are not sent blindly. Anything that is our fault (the signer failed, a
/// prompt was cancelled or ran late) or the server's silence abandons the login: the caller drops the connection (spec §6.2 step 4).
async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, auth: &dyn AuthSource) -> Result<(), ConnectError> {
    let reference = hop.reference();
    let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
    let timed_out = || ConnectError::Timeout { hop: reference.clone(), phase: Phase::Auth };
    let lost = |_: russh::Error| ConnectError::Unreachable { hop: reference.clone(), reason: "the connection was lost during login".to_string() };
    let call_limit = hop.connect_timeout.max(Duration::from_secs(1));
    let user = hop.user.as_str();
    let mut tried: Vec<AuthMethod> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut offered: Option<MethodSet> = None;

    for method in hop.auth_sequence() {
        if offered.as_ref().is_some_and(|offered| !offered.contains(&method_kind(&method))) {
            continue;
        }
        let step = match &method {
            AuthMethod::Key { key_id } => 'key: {
                let Some(line) = auth.public_key(key_id) else {
                    reasons.push(format!("The key {key_id} is not available on this computer."));
                    break 'key Step::Skipped;
                };
                let Ok(public) = PublicKey::from_openssh(&line) else {
                    reasons.push(format!("The key {key_id} is not a public key SSHelter can use."));
                    break 'key Step::Skipped;
                };
                let hash = if public.algorithm().is_rsa() {
                    let best = tokio::time::timeout(call_limit, handle.best_supported_rsa_hash()).await.map_err(|_| timed_out())?.map_err(lost)?;
                    match choose_rsa_hash(best) {
                        RsaChoice::Use(hash) => Some(hash),
                        RsaChoice::Sha1Only => {
                            tried.push(method.clone());
                            reasons.push("The server accepts RSA keys only with SHA-1 signatures, which SSHelter does not make.".to_string());
                            break 'key Step::Skipped;
                        }
                    }
                } else {
                    None
                };
                tried.push(method.clone());
                let mut signer = EngineSigner { auth, key_id };
                match tokio::time::timeout(call_limit, handle.authenticate_publickey_with(user, public, hash, &mut signer)).await {
                    Err(_) => return Err(timed_out()),
                    Ok(Err(SignerFailure::SessionEnded)) => return Err(lost(russh::Error::SendError)),
                    Ok(Err(SignerFailure::Sha1Refused)) => return Err(abandoned("an RSA signature with SHA-1 was asked for")),
                    Ok(Err(SignerFailure::Auth(error))) => return Err(abandoned(&error.to_string())),
                    Ok(Ok(AuthResult::Success)) => return Ok(()),
                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) => Step::Refused(remaining_methods),
                }
            }
            // Password and keyboard-interactive logins come in Task 11; until then these methods are skipped like any method with nothing to offer.
            AuthMethod::Password | AuthMethod::Interactive => Step::Skipped,
        };
        match step {
            Step::Refused(remaining) => offered = Some(remaining),
            Step::Skipped if offered.is_none() => {
                match tokio::time::timeout(call_limit, handle.authenticate_none(user)).await.map_err(|_| timed_out())?.map_err(lost)? {
                    AuthResult::Success => return Ok(()),
                    AuthResult::Failure { remaining_methods, .. } => offered = Some(remaining_methods),
                }
            }
            Step::Skipped => {}
        }
    }
    Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" ") })
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 74 passed; 0 failed`. The run takes about 15 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1491 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 108 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/engine_tests/connect.rs src-tauri/src/ssh/engine_tests/mod.rs src-tauri/src/ssh/mod.rs src-tauri/src/ssh/russh_engine.rs src-tauri/src/ssh/testing/doubles.rs src-tauri/src/ssh/testing/mod.rs
git commit -m "feat(ssh): connect, check host keys and log in with vault keys through russh"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

- [ ] **Step 7: Prove the two safety tests can fail (after the commit)**

A test that cannot fail proves nothing, and these two guard the rules the spec is most insistent about: never sign RSA with SHA-1, never trust a host key the policy did not pin. Break each rule by one line, watch the tests catch it, and put the file back with `git checkout`. The tree is clean after the commit, so the checkout restores exactly the committed file.

First, treat a server that lists only `ssh-rsa` as if SHA-256 would do:

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path("src-tauri/src/ssh/russh_engine.rs")
t = p.read_text()
old = "Some(None) => RsaChoice::Sha1Only,"
assert t.count(old) == 1
p.write_text(t.replace(old, "Some(None) => RsaChoice::Use(HashAlg::Sha256),"))
PY
```

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate compiles and 2 of the tests fail (`ssh::russh_engine::tests::the_rsa_hash_is_what_the_server_lists_and_never_sha1`, `ssh::engine_tests::connect::an_rsa_key_is_never_signed_with_sha1`); `test result: FAILED. 72 passed; 2 failed`.

Then restore the file, and break the host key rule instead (the handler trusts every key):

```bash
git checkout -- src-tauri/src/ssh/russh_engine.rs
```

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path("src-tauri/src/ssh/russh_engine.rs")
t = p.read_text()
old = "let trusted = verdict == HostKeyVerdict::Pinned;"
assert t.count(old) == 1
p.write_text(t.replace(old, "let trusted = true;"))
PY
```

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate compiles and 4 of the tests fail (`ssh::engine_tests::connect::a_changed_host_key_is_a_mismatch_that_carries_the_observed_and_the_pinned_key`, `ssh::engine_tests::connect::after_the_user_pins_the_key_the_same_policy_lets_the_next_connect_through`, `ssh::engine_tests::connect::an_unknown_host_key_fails_fast_with_the_key_the_server_presented_and_leaves_no_connection_behind`, `ssh::engine_tests::connect::a_pinned_key_narrows_the_handshake_to_its_algorithm_family`); `test result: FAILED. 70 passed; 4 failed`.

Restore the file and check that the tree is clean again:

```bash
git checkout -- src-tauri/src/ssh/russh_engine.rs
git status --short
```

Expected: no output.

---

### Task 8: Commands and PTY shells over an established connection

**Files:**
- Create (tests): `src-tauri/src/ssh/engine_tests/exec.rs`
- Modify: `src-tauri/src/ssh/engine_tests/mod.rs` (helpers for sessions and shells)
- Create (tests): `src-tauri/src/ssh/engine_tests/shell.rs`
- Modify: `src-tauri/src/ssh/russh_engine.rs` (the session layer: `SshEngine`, `Session`, shells and exec)

**Interfaces:**
- Consumes: Task 7's `RusshEngine`, `EngineOptions`, `Connection`, `Established`, `HopShared`, `connect_chain`; Task 3's `ByteQueue::new(capacity: usize) -> Arc<ByteQueue>`, `ExitCell::new() -> Arc<ExitCell>`, `ShellInput` and `QueuedShell::new(input: Box<dyn ShellInput>, output: Arc<ByteQueue>, exit: Arc<ExitCell>) -> QueuedShell`; Task 2's `SshEngine`, `Session`, `ShellChannel`, `ExecResult`, `Ended`, `Exit`, `Pty`, `DisconnectReason`, `SessionError`.
- Produces: `impl SshEngine for RusshEngine` (`connect` = `connect_chain` + a watcher + a session), `impl Session for RusshSession`, and the helpers of the engine tests (`open_session(engine: &RusshEngine, server: &Server) -> Box<dyn Session>`, `open_session_to(engine: &RusshEngine, target: &Target, auth: &VaultAuth) -> Box<dyn Session>`, `ShellProbe`, `SHELL_SERVER`):

  - `ssh/russh_engine.rs`:
    - `pub struct RusshSession`

What shapes this task:
- **What a session is.** `RusshSession` holds the runtime and the `Arc<Connection>`; every call is a `block_on` on the engine's runtime. `connect` is `connect_chain` wrapped in a session (Task 10 adds a watcher that tears a chain down when one hop ends); `Drop` and `close` set `closing` first so the reason is ours whatever order the hops notice in, and `disconnect_reason` is the record of the outermost hop that has one, with a 300 ms grace for a hop that is closed but has not recorded yet.
- **Exec (spec §6.1, §6.3).** One channel per command (`exec_on`), read until it ends, the cap is reached or the deadline passes. Output is raw bytes: nothing is decoded or reshaped (`a_command_has_no_pty_and_its_output_is_not_reshaped`; Windows OpenSSH ends lines with CRLF and the environment test of Task 13 sees it). `keep` counts stdout and stderr together against `output_cap`; at the cap `cut_off` closes the channel and returns `truncated: true`, `Ended::Truncated`, no exit code (the connection stays usable: the next command runs on it, and the result must not read as a lost connection, which is what `Disconnected` is for). A command that outlives `timeout` ends as `Ended::TimedOut`, also by closing the channel. A channel that ends with a signal is `Signaled` with the name without `SIG`; one that ends with neither a status nor a signal is `Disconnected` and is never read as exit code 0 (a connection cut mid-command looks exactly like that).
- **Shells.** `shell` opens a channel, requests the PTY and the shell with replies, and only then splits the channel: `read_shell` is the single reader task (spec §6.3: an unread channel stalls the connection) that moves data into the `ByteQueue`, records the exit (`Code`, `Signal`, or `Disconnected` for a channel that ended without a status or was refused) in the `ExitCell` and **then** closes the queue. `RusshShellInput` is the write side: writes are bounded by `SHELL_WRITE_LIMIT` (30 s, flow control can make a write wait) and a window change is sent at once. `shell` returns once the PTY and shell requests are on the wire (it does not wait for the server's answers, which the reader task ignores), and the server handles the requests of one channel in order, so a `window_change` sent right after `shell` returns arrives after the PTY exists and is applied (`a_window_change_sent_right_after_the_shell_opens_is_applied`). What the spike proved (report, item 11): a window change sent before the PTY exists is lost (the size stays 24 × 80), one sent after the PTY request is applied, even before the shell has printed its prompt. Through the trait the first window change cannot come earlier than that, because the caller has no channel before `shell` returns, so there is no engine-level test for the lost case; the broker keeps the last size and sends it after `shell` returns (spec §7.2).
- **Rekeying.** sshd can be told to start a new key exchange after every 512 KiB (`RekeyLimit 512K`); `a_connection_survives_the_key_exchanges_the_server_asks_for` makes it do so a dozen times during 4 MiB of output and checks that the output is complete and the session still works. It also guards the assumption Task 7 makes about the host key question: russh asks it once, and if an upgrade ever asked again after `connect` has returned, the only possible answer would be "no" and this test would see the connection die.
- **Closing a shell.** russh ignores the server's CLOSE for a channel that was closed locally and keeps a small channel record, so the reader would wait for ever. `RusshShellInput::close` (and its `Drop`, which must not block because it can run on a runtime thread) therefore sets a `watch` flag that the reader selects on; the reader ends, sets the exit and closes the queue. The other shells and the connection are untouched (`closing_a_shell_ends_its_reader_and_leaves_the_connection_and_other_shells_alone`).
- **The test server.** A PTY shell of the user's login shell would print the developer's own prompt, so the engine tests run `/bin/sh` through `ForceCommand`; `ForceCommand` replaces every requested command, so the wrapper hands a requested command on to `eval` to keep `exec` usable on the same server (`SHELL_SERVER` in `engine_tests/mod.rs`). `ShellProbe` reads a shell on its own thread, as the broker will, so a test can wait for text without ever blocking on the shell.
- **Why the red step is a compile error.** The new tests call `engine.connect(..)` through the `SshEngine` trait; until this task `RusshEngine` has only the inherent `connect_chain`.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/engine_tests/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/engine_tests/mod.rs
+++ b/src-tauri/src/ssh/engine_tests/mod.rs
@@ -2,9 +2,21 @@
 //! returns early, printing "skipped", where the OpenSSH tools are missing (`SSHELTER_REQUIRE_OPENSSH=1` turns that into a failure).
 
 mod connect;
+mod exec;
+mod shell;
+
+use std::sync::{Arc, Mutex, PoisonError};
+use std::time::{Duration, Instant};
 
 use super::russh_engine::{EngineOptions, RusshEngine};
+use super::testing::doubles::{TestPolicy, VaultAuth};
 use super::testing::fixture::Server;
+use super::{Session, ShellChannel, SshEngine, Target};
+
+/// The scratch sshd starts `/bin/sh` for a shell, so the interactive shell is the same POSIX sh on every machine and its prompt does not
+/// depend on the developer's zsh configuration. (`ForceCommand` runs through the user's login shell with `-c`, and it replaces every
+/// command, so it hands a requested command on to `eval` to keep `exec` usable on the same server.)
+const SHELL_SERVER: &[&str] = &["ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi"];
 
 /// An engine with a small runtime, one per test.
 fn engine() -> RusshEngine {
@@ -18,3 +30,90 @@ const LOG_LOGINS: &str = "LogLevel INFO";
 fn accepted_logins(server: &Server) -> usize {
     server.sshd.log().lines().filter(|line| line.contains("Accepted publickey")).count()
 }
+
+/// Connects to `server` through the trait, the way the broker will: a trusting policy and the server's user key under the id `k1`.
+fn open_session(engine: &RusshEngine, server: &Server) -> Box<dyn Session> {
+    open_session_to(engine, &server.target("k1"), &server.vault("k1"))
+}
+
+fn open_session_to(engine: &RusshEngine, target: &Target, auth: &VaultAuth) -> Box<dyn Session> {
+    engine.connect(target, &*TestPolicy::trusting(), auth).expect("the engine connects")
+}
+
+/// Reads a shell on a thread of its own, as the broker will, so a test can wait for text to show up without ever blocking on the shell.
+struct ShellProbe {
+    shell: Arc<dyn ShellChannel>,
+    seen: Arc<Mutex<Vec<u8>>>,
+}
+
+impl ShellProbe {
+    fn start(shell: Box<dyn ShellChannel>) -> ShellProbe {
+        let shell: Arc<dyn ShellChannel> = Arc::from(shell);
+        let seen = Arc::new(Mutex::new(Vec::new()));
+        let (reader, sink) = (Arc::clone(&shell), Arc::clone(&seen));
+        std::thread::spawn(move || {
+            let mut buf = [0u8; 4096];
+            while let Ok(count) = reader.read(&mut buf) {
+                if count == 0 {
+                    break;
+                }
+                sink.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(&buf[..count]);
+            }
+        });
+        ShellProbe { shell, seen }
+    }
+
+    fn text(&self) -> String {
+        String::from_utf8_lossy(&self.seen.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
+    }
+
+    /// Waits up to `seconds` until `find` returns something for everything read so far; `Err` carries the text read when time ran out.
+    fn wait_for<T>(&self, seconds: u64, find: impl Fn(&str) -> Option<T>) -> Result<T, String> {
+        let deadline = Instant::now() + Duration::from_secs(seconds);
+        loop {
+            let text = self.text();
+            if let Some(found) = find(&text) {
+                return Ok(found);
+            }
+            if Instant::now() >= deadline {
+                return Err(text);
+            }
+            std::thread::sleep(Duration::from_millis(20));
+        }
+    }
+
+    fn wait_for_text(&self, seconds: u64, needle: &str) -> Result<(), String> {
+        self.wait_for(seconds, |text| text.contains(needle).then_some(()))
+    }
+
+    /// Types `line` and presses Enter.
+    fn type_line(&self, line: &str) {
+        self.shell.write(format!("{line}\n").as_bytes()).expect("the shell takes input");
+    }
+
+    /// Asks the shell for the terminal size and returns "<rows> <cols>". The PTY echoes the command as `SIZE[%s]`, the answer reads
+    /// `SIZE[40 120]`: only the answer has two numbers between the brackets.
+    fn stty_size(&self) -> Result<String, String> {
+        let before = self.text().len();
+        self.type_line("printf 'SIZE[%s]\\n' \"$(stty size)\"");
+        self.wait_for(10, |text| size_in(&text[before..]))
+    }
+}
+
+fn size_in(output: &str) -> Option<String> {
+    output.split("SIZE[").skip(1).find_map(|rest| {
+        let inside = rest.split(']').next()?;
+        let numbers: Vec<&str> = inside.split(' ').collect();
+        let digits = |text: &&str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
+        (numbers.len() == 2 && numbers.iter().all(digits)).then(|| inside.to_string())
+    })
+}
+
+#[test]
+fn only_the_answer_counts_not_the_echoed_command() {
+    assert_eq!(size_in("printf 'SIZE[%s]\\n' \"$(stty size)\"\r\nSIZE[40 120]\r\n"), Some("40 120".to_string()));
+    assert_eq!(size_in("printf 'SIZE[%s]\\n' \"$(stty size)\"\r\n"), None);
+    assert_eq!(size_in("SIZE[0 0]"), Some("0 0".to_string()));
+    assert_eq!(size_in("SIZE[40]"), None);
+    assert_eq!(size_in("SIZE[40 12x]"), None);
+}
```

`src-tauri/src/ssh/engine_tests/exec.rs`: create

```rust
//! `Session::exec`: a command without a PTY, its output, how it ended, and what happens when it does not end by itself.

use std::time::{Duration, Instant};

use super::{engine, open_session, open_session_to};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthMethod, Ended, SessionError, Target};

const MIB: usize = 1024 * 1024;
const ENOUGH: Duration = Duration::from_secs(20);

#[test]
fn exec_returns_stdout_stderr_and_the_exit_code() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("printf out; printf err >&2; exit 7", ENOUGH, MIB).unwrap();
    assert_eq!((result.ended, result.exit_code, result.signal.as_deref()), (Ended::Exited, Some(7), None));
    assert_eq!((result.stdout.as_slice(), result.stderr.as_slice()), (b"out".as_slice(), b"err".as_slice()));
    assert!(!result.truncated);
}

/// The command has no terminal, and its output is bytes the engine does not touch: CRLF stays CRLF.
#[test]
fn a_command_has_no_pty_and_its_output_is_not_reshaped() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("tty; printf 'a\\r\\nb\\r\\n'", ENOUGH, MIB).unwrap();
    let text = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(text.starts_with("not a tty\n"), "no PTY was allocated: {text:?}");
    assert!(text.ends_with("a\r\nb\r\n"), "line endings are kept as the command wrote them: {text:?}");
}

/// Review focus: a command that ends without an exit status must not look like a success.
#[test]
fn a_command_killed_by_a_signal_has_no_exit_code_and_names_the_signal() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("exec sh -c 'kill -9 $$'", ENOUGH, MIB).unwrap();
    fact("exec.killed_by_signal", format!("{:?} {:?}", result.ended, result.signal));
    assert_eq!((result.ended, result.exit_code, result.signal.as_deref()), (Ended::Signaled, None, Some("KILL")));
}

/// Review focus: the same, when the connection is cut instead: `Disconnected`, no exit code, no hang.
#[test]
fn a_connection_cut_during_a_command_ends_it_as_disconnected() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port);
    let target = Target { hops: vec![server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() })] };
    let session = open_session_to(&engine(), &target, &server.vault("k1"));

    let cutter = std::thread::scope(|scope| {
        let cutting = scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(500));
            proxy.set(Mode::Cut);
        });
        let started = Instant::now();
        let result = session.exec("sleep 30", ENOUGH, MIB).unwrap();
        cutting.join().unwrap();
        (result, started.elapsed())
    });
    let (result, waited) = cutter;
    fact("cut_during_exec.ended_after_ms", waited.as_millis());
    assert_eq!((result.ended, result.exit_code, result.signal), (Ended::Disconnected, None, None));
    assert!(waited < Duration::from_secs(10), "the cut was noticed: {waited:?}");
    eventually("the session to notice that it is dead", 5, || !session.is_alive());
    assert_eq!(session.exec("echo never", Duration::from_secs(5), MIB), Err(SessionError::Closed));
}

/// 32 MiB is sixteen times russh's initial window (2 MiB): this only completes if the window adjustments keep up.
#[test]
fn thirty_two_mebibytes_of_output_arrive_complete() {
    const SIZE: usize = 32 * MIB;
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let started = Instant::now();
    let result = session.exec(&format!("head -c {SIZE} /dev/zero"), Duration::from_secs(120), 64 * MIB).unwrap();
    fact("exec.long_output.mib_per_second", format!("{:.1}", SIZE as f64 / 1_048_576.0 / started.elapsed().as_secs_f64()));
    assert_eq!((result.stdout.len(), result.ended, result.exit_code, result.truncated), (SIZE, Ended::Exited, Some(0), false));
}

/// Review focus: a command that never stops printing. The caller's cap stops it, the channel is closed, and the same connection
/// still serves the next command.
#[test]
fn output_beyond_the_cap_is_cut_off_and_the_connection_survives() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("yes sshelter", Duration::from_secs(30), MIB).unwrap();
    assert!(result.truncated);
    assert_eq!((result.ended, result.exit_code), (Ended::Truncated, None));
    assert_eq!(result.stdout.len() + result.stderr.len(), MIB, "exactly the cap was kept");
    assert!(result.stdout.starts_with(b"sshelter\nsshelter\n"));

    let started = Instant::now();
    let next = session.exec("echo alive", ENOUGH, MIB).unwrap();
    fact("exec.capped_reader.next_exec_ms", started.elapsed().as_millis());
    assert_eq!((next.stdout.as_slice(), next.ended), (b"alive\n".as_slice(), Ended::Exited));
    assert!(session.is_alive());
}

#[test]
fn output_that_exactly_fills_the_cap_is_not_truncated() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("printf 12345; printf 67890 >&2", ENOUGH, 10).unwrap();
    assert_eq!((result.truncated, result.ended, result.exit_code), (false, Ended::Exited, Some(0)));
    let over = session.exec("printf 12345; printf 678901 >&2", ENOUGH, 10).unwrap();
    assert_eq!((over.truncated, over.ended, over.stdout.len() + over.stderr.len()), (true, Ended::Truncated, 10));
}

/// russh has no command timeout; the engine's is a deadline on the read and a close of the channel. What the command printed before is kept.
#[test]
fn a_command_that_outlives_its_timeout_is_cut_and_the_connection_survives() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let started = Instant::now();
    let result = session.exec("echo started; sleep 30", Duration::from_secs(1), MIB).unwrap();
    let waited = started.elapsed();
    fact("exec.timeout.waited_ms", waited.as_millis());
    assert_eq!((result.ended, result.exit_code), (Ended::TimedOut, None));
    assert_eq!(result.stdout, b"started\n");
    assert!(waited >= Duration::from_millis(900) && waited < Duration::from_secs(5), "waited {waited:?}");

    let next = session.exec("echo alive", ENOUGH, MIB).unwrap();
    assert_eq!(next.stdout, b"alive\n");
}

#[test]
fn a_closed_session_refuses_commands() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);
    assert!(session.is_alive());
    session.close();
    assert!(!session.is_alive());
    assert_eq!(session.exec("echo no", ENOUGH, MIB), Err(SessionError::Closed));
}

/// Spec §16: long connections and rekeying were not measured in the spike. sshd is told to start a new key exchange after every 512 KiB,
/// so 4 MiB of output makes it ask a dozen times. russh asks the host key question once, in the first exchange; if an upgrade of russh
/// ever asked again, the answer could only be "no" (the thread that answers is gone after `connect`) and this connection would die in
/// the middle of the output.
#[test]
fn a_connection_survives_the_key_exchanges_the_server_asks_for() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &["RekeyLimit 512K", "LogLevel DEBUG1"]);
    let session = open_session(&engine(), &server);

    let result = session.exec("head -c 4194304 /dev/zero", Duration::from_secs(60), 8 * MIB).unwrap();
    assert_eq!((result.ended, result.exit_code, result.stdout.len(), result.truncated), (Ended::Exited, Some(0), 4 * MIB, false));
    let exchanges = server.sshd.log().matches("SSH2_MSG_KEXINIT sent").count();
    fact("rekey.key_exchanges_started_by_sshd", exchanges);
    assert!(exchanges >= 4, "sshd started {exchanges} key exchanges: it did not rekey as often as it was told to");
    assert!(session.is_alive());
    assert_eq!(session.exec("echo still-here", ENOUGH, MIB).unwrap().stdout, b"still-here\n");
}
```

`src-tauri/src/ssh/engine_tests/shell.rs`: create

```rust
//! `Session::shell`: a PTY shell, its size, and a reader that falls behind.

use std::time::{Duration, Instant};

use super::{engine, open_session, ShellProbe, SHELL_SERVER};
use crate::ssh::russh_engine::{EngineOptions, RusshEngine};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{Exit, Pty, SessionError};

const MIB: usize = 1024 * 1024;

fn pty(cols: u16, rows: u16) -> Pty {
    Pty { term: "xterm-256color".to_string(), cols, rows }
}

#[test]
fn a_pty_shell_prints_a_prompt_runs_a_command_and_reports_its_exit_status() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let started = Instant::now();
    let shell = session.shell(pty(80, 24)).unwrap();
    assert_eq!(shell.exited(), None);
    let probe = ShellProbe::start(shell);
    // A POSIX sh prompt ends in "$ " (dash: "$ ", macOS bash as sh: "sh-3.2$ ").
    probe.wait_for_text(20, "$ ").expect("a prompt");
    fact("shell.first_prompt_ms", started.elapsed().as_millis());

    // "$((6*7))" is typed, "42" is printed: the echo of the typed line does not contain SSHELTER_42.
    probe.type_line("echo SSHELTER_$((6*7))");
    probe.wait_for_text(10, "SSHELTER_42").expect("the command's output");

    probe.type_line("exit 3");
    eventually("the shell to report its exit", 10, || probe.shell.exited().is_some());
    assert_eq!(probe.shell.exited(), Some(Exit::Code(3)));
    assert!(session.is_alive(), "the shell ended, the connection did not");
}

#[test]
fn the_size_given_with_the_pty_request_is_the_initial_size() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let probe = ShellProbe::start(session.shell(pty(97, 31)).unwrap());
    probe.wait_for_text(20, "$ ").expect("a prompt");
    assert_eq!(probe.stty_size().expect("stty answers"), "31 97");
}

#[test]
fn a_window_change_while_the_shell_runs_is_applied() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let probe = ShellProbe::start(session.shell(pty(80, 24)).unwrap());
    probe.wait_for_text(20, "$ ").expect("a prompt");
    probe.shell.window_change(100, 30).unwrap();
    assert_eq!(probe.stty_size().expect("stty answers"), "30 100");
}

/// Review focus. The user resizes the terminal the moment `sshelter connect` starts: the broker has the size ready when `shell` returns
/// and sends it at once, before the prompt is even drawn (spec §7.2). It must not be lost and must not hurt the shell.
#[test]
fn a_window_change_sent_right_after_the_shell_opens_is_applied() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let shell = session.shell(pty(80, 24)).unwrap();
    shell.window_change(120, 40).unwrap();
    let probe = ShellProbe::start(shell);
    probe.wait_for_text(20, "$ ").expect("a prompt");
    assert_eq!(probe.stty_size().expect("stty answers"), "40 120");
}

#[test]
fn closing_a_shell_ends_its_reader_and_leaves_the_connection_and_other_shells_alone() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let first = ShellProbe::start(session.shell(pty(80, 24)).unwrap());
    let second = ShellProbe::start(session.shell(pty(80, 24)).unwrap());
    first.wait_for_text(20, "$ ").expect("a prompt in the first shell");
    second.wait_for_text(20, "$ ").expect("a prompt in the second shell");

    first.shell.close();
    eventually("the closed shell to report that it ended", 10, || first.shell.exited().is_some());
    assert!(session.is_alive());
    second.type_line("echo STILL_$((1+1))");
    second.wait_for_text(10, "STILL_2").expect("the second shell still works");
}

/// Review focus: the terminal is paused (or the CLI is busy) while the server keeps printing. The engine drains the channel anyway, into a
/// bounded queue; the connection is not held up (another command runs at once on it), the bytes that did not fit are dropped, and the
/// stream says so when the reader comes back.
#[test]
fn a_reader_that_stops_reading_does_not_hold_up_the_connection_and_the_gap_is_announced() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let small_queue = RusshEngine::with_options(EngineOptions { shell_queue_bytes: 64 * 1024, worker_threads: 2, ..EngineOptions::default() });
    let session = open_session(&small_queue, &server);

    let shell = session.shell(pty(80, 24)).unwrap();
    // Nobody reads yet. `yes` fills the queue in a moment and keeps going.
    shell.write(b"yes sshelter\n").unwrap();
    std::thread::sleep(Duration::from_secs(2));

    let started = Instant::now();
    let other = session.exec("echo alive", Duration::from_secs(10), MIB).unwrap();
    fact("shell.paused_reader.exec_ms", started.elapsed().as_millis());
    assert_eq!(other.stdout, b"alive\n");
    assert!(started.elapsed() < Duration::from_secs(5), "the connection was held up: {:?}", started.elapsed());

    let probe = ShellProbe::start(shell);
    probe.wait_for_text(20, "SSHelter dropped").expect("the stream announces the gap once the reader is back");
    let text = probe.text();
    assert!(text.contains("bytes of output because the terminal fell behind"), "{}", &text[text.len().saturating_sub(300)..]);
    probe.shell.close();
}

#[test]
fn a_closed_session_refuses_shells() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);
    session.close();
    assert!(matches!(session.shell(pty(80, 24)), Err(SessionError::Closed)));
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate does not compile. The first error is `error[E0599]: no method named `connect` found for reference `&RusshEngine` in the current scope`, and the run ends with `error: could not compile `sshelter` (lib test) due to 1 previous error` (the number of errors depends on the compiler; what matters is that the errors name items that do not exist yet).

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/russh_engine.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/russh_engine.rs
+++ b/src-tauri/src/ssh/russh_engine.rs
@@ -10,21 +10,25 @@
 //! connection instead of switching method on it; liveness is read from the connection's own state, never from an error variant.
 
 use std::borrow::Cow;
+use std::sync::atomic::{AtomicBool, Ordering};
 use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
 use std::time::Duration;
 
-use russh::client::{self, AuthResult, Config, Handle, Handler};
+use russh::client::{self, AuthResult, Config, Handle, Handler, Msg};
 use russh::client::DisconnectReason as RusshDisconnect;
 use russh::keys::agent::AgentIdentity;
 use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
-use russh::{AlgorithmKind, Disconnect, MethodKind, MethodSet, Preferred};
+use russh::{AlgorithmKind, Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect, MethodKind, MethodSet, Preferred, Sig};
 use tokio::net::TcpStream;
-use tokio::sync::{mpsc, oneshot};
+use tokio::sync::{mpsc, oneshot, watch};
 use tokio::time::Instant;
 
-use super::error::{AuthError, ConnectError};
-use super::traits::{AuthSource, HostKeyPolicy};
-use super::types::{AuthMethod, DisconnectKind, Hop, HopRef, HostKey, HostKeyVerdict, Phase, RsaHash, Target};
+use super::channel::{ByteQueue, ExitCell, QueuedShell, ShellInput};
+use super::error::{AuthError, ConnectError, SessionError};
+use super::traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
+use super::types::{
+    AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostKey, HostKeyVerdict, Phase, Pty, RsaHash, Target,
+};
 
 fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
     mutex.lock().unwrap_or_else(PoisonError::into_inner)
@@ -69,6 +73,7 @@ impl Drop for RuntimeOwner {
 /// The russh engine. Cheap to create (it starts a small runtime), meant to live as long as the app.
 pub struct RusshEngine {
     runtime: Arc<RuntimeOwner>,
+    options: EngineOptions,
 }
 
 impl Default for RusshEngine {
@@ -90,7 +95,7 @@ impl RusshEngine {
             .build()
             .expect("the SSH engine's runtime");
         let handle = runtime.handle().clone();
-        RusshEngine { runtime: Arc::new(RuntimeOwner { runtime: Some(runtime), handle }) }
+        RusshEngine { runtime: Arc::new(RuntimeOwner { runtime: Some(runtime), handle }), options }
     }
 
     /// Connects every hop of `target` and logs in to each; the connection-level half of `SshEngine::connect`. Blocks the calling thread
@@ -219,7 +224,9 @@ fn client_config(hop: &Hop) -> Config {
 
 /// A hop that is connected and logged in.
 pub struct Established {
+    hop: HopRef,
     handle: Handle<EngineHandler>,
+    shared: Arc<HopShared>,
 }
 
 /// The whole chain, outermost hop first. Owns every hop's `Handle`; a connection is closed by an explicit `disconnect()` on each hop,
@@ -227,16 +234,50 @@ pub struct Established {
 /// drives it: when the engine that made it is dropped the runtime goes with it, and every hop ends.
 pub struct Connection {
     hops: Vec<Established>,
+    /// Set when we are the ones closing it, so that the reason is ours whatever order the hops notice in.
+    closing: AtomicBool,
 }
 
 impl Connection {
+    fn new() -> Connection {
+        Connection { hops: Vec::new(), closing: AtomicBool::new(false) }
+    }
+
     pub fn hop_count(&self) -> usize {
         self.hops.len()
     }
 
-    /// No hop's connection has ended.
+    /// No hop's connection has ended, and nobody is closing it.
     pub fn is_open(&self) -> bool {
-        self.hops.iter().all(|established| !established.handle.is_closed())
+        !self.closing.load(Ordering::SeqCst) && self.hops.iter().all(|established| !established.handle.is_closed())
+    }
+
+    /// The hop the user asked for: the last one.
+    fn destination(&self) -> Result<&Established, SessionError> {
+        self.hops.last().ok_or(SessionError::Closed)
+    }
+
+    /// Why the connection ended: the record of the outermost hop that has one (a hop that dies after its carrier is gone records nothing
+    /// useful, spec §6.2 step 2), else ours when we closed it. A hop whose `Handle` is closed but has not recorded anything yet is about
+    /// to (russh closes the handle first and calls the handler a moment later), so it is given a short while before the fallback is used.
+    fn reason(&self) -> Option<DisconnectReason> {
+        let deadline = std::time::Instant::now() + Duration::from_millis(300);
+        loop {
+            for established in &self.hops {
+                if let Some((kind, detail)) = locked(&established.shared.ended).clone() {
+                    return Some(DisconnectReason { hop: established.hop.clone(), kind, detail });
+                }
+            }
+            if self.closing.load(Ordering::SeqCst) {
+                let hop = self.hops.last()?.hop.clone();
+                return Some(DisconnectReason { hop, kind: DisconnectKind::ClosedByUs, detail: "the connection was closed on our side".to_string() });
+            }
+            let Some(closed) = self.hops.iter().find(|established| established.handle.is_closed()) else { return None };
+            if std::time::Instant::now() >= deadline {
+                return Some(DisconnectReason { hop: closed.hop.clone(), kind: DisconnectKind::ConnectionLost, detail: "the connection ended".to_string() });
+            }
+            std::thread::sleep(Duration::from_millis(10));
+        }
     }
 
     /// Sends a disconnect on every hop, innermost first, and gives each a moment to leave before the next (outer) one goes.
@@ -255,7 +296,7 @@ impl Connection {
 
 async fn connect_chain(target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
     check_chain(target)?;
-    let mut connection = Connection { hops: Vec::new() };
+    let mut connection = Connection::new();
     for (index, hop) in target.hops.iter().enumerate() {
         match connect_one(index, hop, connection.hops.last(), host_keys, auth).await {
             Ok(established) => connection.hops.push(established),
@@ -282,12 +323,13 @@ fn check_chain(target: &Target) -> Result<(), ConnectError> {
 }
 
 async fn connect_one(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Established, ConnectError> {
-    let mut handle = connect_hop(index, hop, via, host_keys).await?;
+    let reference = hop.reference();
+    let (mut handle, shared) = connect_hop(index, hop, via, host_keys).await?;
     authenticate(hop, &mut handle, auth).await?;
-    Ok(Established { handle })
+    Ok(Established { hop: reference, handle, shared })
 }
 
-async fn connect_hop(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy) -> Result<Handle<EngineHandler>, ConnectError> {
+async fn connect_hop(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy) -> Result<(Handle<EngineHandler>, Arc<HopShared>), ConnectError> {
     let reference = hop.reference();
     if via.is_some() || index > 0 {
         return Err(ConnectError::BadJumpChain { why: "jump hosts are not connected yet".to_string() });
@@ -318,7 +360,7 @@ async fn connect_hop(index: usize, hop: &Hop, via: Option<&Established>, host_ke
     };
     let budget = hop.connect_timeout.max(Duration::from_secs(1));
     match tokio::time::timeout(budget, attempt).await {
-        Ok(result) => result,
+        Ok(result) => result.map(|handle| (handle, shared)),
         Err(_) => Err(ConnectError::Timeout { hop: reference, phase: phase.get() }),
     }
 }
@@ -487,6 +529,248 @@ async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, auth: &dyn
     Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" ") })
 }
 
+// ---------------------------------------------------------------------------------------------------------------------------------
+// The session: what a caller does with a connection.
+
+/// How long opening a channel, and the PTY and shell requests that follow it, may take.
+const CHANNEL_SETUP_LIMIT: Duration = Duration::from_secs(15);
+/// How long one write to a shell may wait for the connection's flow control.
+const SHELL_WRITE_LIMIT: Duration = Duration::from_secs(30);
+
+/// A live connection: the chain, the runtime that drives it, and what a caller does with it. Dropping it closes the connection.
+pub struct RusshSession {
+    runtime: Arc<RuntimeOwner>,
+    connection: Arc<Connection>,
+    options: EngineOptions,
+}
+
+impl SshEngine for RusshEngine {
+    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
+        let connection = Arc::new(self.connect_chain(target, host_keys, auth)?);
+        Ok(Box::new(RusshSession { runtime: Arc::clone(&self.runtime), connection, options: self.options.clone() }))
+    }
+}
+
+impl Drop for RusshSession {
+    /// Does not block (it may run on one of the runtime's own threads): the disconnect is sent by a task.
+    fn drop(&mut self) {
+        self.connection.closing.store(true, Ordering::SeqCst);
+        let connection = Arc::clone(&self.connection);
+        self.runtime.handle().spawn(async move { connection.disconnect_all().await });
+    }
+}
+
+/// russh's errors on a call that needs the session, as the session's: a gone session is `Closed`, anything else is the server's answer.
+fn channel_error(error: russh::Error) -> SessionError {
+    match error {
+        russh::Error::SendError | russh::Error::RecvError | russh::Error::Disconnect => SessionError::Closed,
+        other => SessionError::Channel(other.to_string()),
+    }
+}
+
+async fn open_channel(established: &Established, limit: Duration) -> Result<Channel<Msg>, SessionError> {
+    match tokio::time::timeout(limit, established.handle.channel_open_session()).await {
+        Err(_) => Err(SessionError::Channel("opening a channel timed out".to_string())),
+        Ok(Ok(channel)) => Ok(channel),
+        Ok(Err(error)) => Err(channel_error(error)),
+    }
+}
+
+/// The signal's name without the `SIG` prefix.
+fn signal_name(signal: &Sig) -> String {
+    match signal {
+        Sig::Custom(name) => name.clone(),
+        other => format!("{other:?}"),
+    }
+}
+
+impl Session for RusshSession {
+    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
+        if !self.is_alive() {
+            return Err(SessionError::Closed);
+        }
+        let destination = self.connection.destination()?;
+        let handle = self.runtime.handle();
+        handle.block_on(async {
+            let channel = open_channel(destination, CHANNEL_SETUP_LIMIT).await?;
+            let setup = async {
+                channel.request_pty(true, &pty.term, u32::from(pty.cols), u32::from(pty.rows), 0, 0, &[]).await?;
+                channel.request_shell(true).await
+            };
+            match tokio::time::timeout(CHANNEL_SETUP_LIMIT, setup).await {
+                Err(_) => return Err(SessionError::Channel("starting the shell timed out".to_string())),
+                Ok(Err(error)) => return Err(channel_error(error)),
+                Ok(Ok(())) => {}
+            }
+            let (read_half, write_half) = channel.split();
+            let write_half = Arc::new(write_half);
+            let (queue, exit) = (ByteQueue::new(self.options.shell_queue_bytes), ExitCell::new());
+            let (closed_by_us, closed) = watch::channel(false);
+            tokio::spawn(read_shell(read_half, Arc::clone(&write_half), Arc::clone(&queue), Arc::clone(&exit), closed));
+            let input = RusshShellInput { write_half, runtime: self.runtime.handle(), closed_by_us };
+            Ok(Box::new(QueuedShell::new(Box::new(input), queue, exit)) as Box<dyn ShellChannel>)
+        })
+    }
+
+    fn exec(&self, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError> {
+        if !self.is_alive() {
+            return Err(SessionError::Closed);
+        }
+        let destination = self.connection.destination()?;
+        self.runtime.handle().block_on(exec_on(destination, command, timeout, output_cap))
+    }
+
+    fn is_alive(&self) -> bool {
+        self.connection.is_open()
+    }
+
+    fn disconnect_reason(&self) -> Option<DisconnectReason> {
+        if self.is_alive() {
+            None
+        } else {
+            self.connection.reason()
+        }
+    }
+
+    fn close(&self) {
+        self.connection.closing.store(true, Ordering::SeqCst);
+        self.runtime.handle().block_on(self.connection.disconnect_all());
+    }
+}
+
+/// Runs one command on its own channel and reads the channel until it ends, the output reaches `output_cap` bytes or `timeout` is up.
+async fn exec_on(destination: &Established, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError> {
+    let deadline = Instant::now() + timeout;
+    let mut channel = open_channel(destination, CHANNEL_SETUP_LIMIT.max(timeout)).await?;
+    channel.exec(true, command).await.map_err(channel_error)?;
+    let mut result = ExecResult { ended: Ended::Disconnected, exit_code: None, signal: None, stdout: Vec::new(), stderr: Vec::new(), truncated: false };
+    loop {
+        let message = match tokio::time::timeout_at(deadline, channel.wait()).await {
+            Err(_) => {
+                let _ = channel.close().await;
+                result.ended = Ended::TimedOut;
+                return Ok(result);
+            }
+            Ok(None) => break,
+            Ok(Some(message)) => message,
+        };
+        match message {
+            ChannelMsg::Data { data } => {
+                if !keep(&mut result.stdout, result.stderr.len(), &data, output_cap) {
+                    return Ok(cut_off(&channel, result).await);
+                }
+            }
+            ChannelMsg::ExtendedData { data, ext: 1 } => {
+                if !keep(&mut result.stderr, result.stdout.len(), &data, output_cap) {
+                    return Ok(cut_off(&channel, result).await);
+                }
+            }
+            ChannelMsg::ExitStatus { exit_status } => result.exit_code = Some(exit_status),
+            ChannelMsg::ExitSignal { signal_name: signal, .. } => result.signal = Some(signal_name(&signal)),
+            ChannelMsg::Failure => return Err(SessionError::Channel("the server refused to run the command".to_string())),
+            _ => {}
+        }
+    }
+    result.ended = if result.signal.is_some() {
+        Ended::Signaled
+    } else if result.exit_code.is_some() {
+        Ended::Exited
+    } else {
+        Ended::Disconnected
+    };
+    Ok(result)
+}
+
+/// Appends as much of `data` to `stream` as the cap leaves room for (`other` is the length of the other stream); false when some of it did not fit.
+fn keep(stream: &mut Vec<u8>, other: usize, data: &[u8], output_cap: usize) -> bool {
+    let room = output_cap.saturating_sub(stream.len() + other);
+    let fitting = room.min(data.len());
+    stream.extend_from_slice(&data[..fitting]);
+    fitting == data.len()
+}
+
+/// The output hit the cap: the channel is closed (the connection stays usable) and what was read is the result.
+async fn cut_off(channel: &Channel<Msg>, mut result: ExecResult) -> ExecResult {
+    let _ = channel.close().await;
+    result.truncated = true;
+    result.ended = Ended::Truncated;
+    result.exit_code = None;
+    result.signal = None;
+    result
+}
+
+/// The write side of a shell, on the engine's runtime.
+struct RusshShellInput {
+    write_half: Arc<ChannelWriteHalf<Msg>>,
+    runtime: tokio::runtime::Handle,
+    /// Tells the reader task that the shell was closed from our side: russh never ends a channel's reads after the channel was closed
+    /// locally (it ignores the server's close for it), so without this the reader would wait for ever.
+    closed_by_us: watch::Sender<bool>,
+}
+
+impl ShellInput for RusshShellInput {
+    fn write(&self, bytes: &[u8]) -> Result<(), SessionError> {
+        // The timer is created inside the future: building it before `block_on` would need a runtime on this thread.
+        match self.runtime.block_on(async { tokio::time::timeout(SHELL_WRITE_LIMIT, self.write_half.data(bytes)).await }) {
+            Err(_) => Err(SessionError::Channel("the connection did not take the input in time".to_string())),
+            Ok(result) => result.map_err(channel_error),
+        }
+    }
+
+    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
+        self.runtime.block_on(self.write_half.window_change(u32::from(cols), u32::from(rows), 0, 0)).map_err(channel_error)
+    }
+
+    fn close(&self) {
+        let _ = self.closed_by_us.send(true);
+        let _ = self.runtime.block_on(async { tokio::time::timeout(Duration::from_secs(2), self.write_half.close()).await });
+    }
+}
+
+impl Drop for RusshShellInput {
+    /// A shell that is dropped without being closed is closed here; nothing blocks (this may run on one of the runtime's threads).
+    fn drop(&mut self) {
+        let _ = self.closed_by_us.send(true);
+        let write_half = Arc::clone(&self.write_half);
+        self.runtime.spawn(async move {
+            let _ = write_half.close().await;
+        });
+    }
+}
+
+/// The one task that reads a shell's channel (spec §6.3: every channel has a reader, or russh stalls the whole connection). It moves the
+/// output into the queue without ever waiting for the consumer, and when the channel ends it records how, then closes the queue, in
+/// that order, so a consumer that sees the end of the output finds the exit.
+async fn read_shell(mut read_half: ChannelReadHalf, write_half: Arc<ChannelWriteHalf<Msg>>, queue: Arc<ByteQueue>, exit: Arc<ExitCell>, mut closed_by_us: watch::Receiver<bool>) {
+    let (mut code, mut signal, mut refused) = (None, None, false);
+    loop {
+        let message = tokio::select! {
+            message = read_half.wait() => message,
+            _ = closed_by_us.wait_for(|closed| *closed) => None,
+        };
+        let Some(message) = message else { break };
+        match message {
+            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
+                queue.push(data.to_vec());
+            }
+            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
+            ChannelMsg::ExitSignal { signal_name: name, .. } => signal = Some(signal_name(&name)),
+            ChannelMsg::Failure => {
+                refused = true;
+                let _ = write_half.close().await;
+                break;
+            }
+            _ => {}
+        }
+    }
+    exit.set(match (signal, code) {
+        (Some(signal), _) => Exit::Signal(signal),
+        (None, Some(code)) if !refused => Exit::Code(code),
+        _ => Exit::Disconnected,
+    });
+    queue.close();
+}
+
 #[cfg(test)]
 mod tests {
     use russh::keys::EcdsaCurve;
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 92 passed; 0 failed`. The run takes about 15 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1509 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 109 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/engine_tests/exec.rs src-tauri/src/ssh/engine_tests/mod.rs src-tauri/src/ssh/engine_tests/shell.rs src-tauri/src/ssh/russh_engine.rs
git commit -m "feat(ssh): run commands and PTY shells over an established connection"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 9: Keepalive, closing, dropping, the stuck session and the idle CPU

**Files:**
- Create (tests): `src-tauri/src/ssh/engine_tests/liveness.rs`
- Modify: `src-tauri/src/ssh/engine_tests/mod.rs`
- Modify: `src-tauri/src/ssh/russh_engine.rs` (two measurements in its test module and one fix: `Drop for RusshSession`)
- Modify: `src-tauri/src/ssh/testing/mod.rs` (`cpu_time_ms`, `is_child`, `rerun_alone`, `fact_in`)

**Interfaces:**
- Consumes: Task 8's `RusshSession`, `Session`, `open_session`; Task 6's `Proxy`/`Mode`; Task 7's `eventually`, `fact`.
- Produces: test helpers in `testing/mod.rs` — `pub fn cpu_time_ms() -> u128` (Unix only: user plus system CPU time of this process, from `getrusage`), `pub fn is_child() -> bool`, `pub fn rerun_alone(name: &str) -> String` (runs one test alone in a child process of the test binary and returns its stderr), `pub fn fact_in(output: &str, key: &str) -> Option<String>`; the helper `fn settle(session: &dyn Session)` of `engine_tests/mod.rs` (runs `true` through the session, so that sshd has finished setting it up; Tasks 9 and 10 use it), and the one behaviour fix to `Drop for RusshSession` (the disconnect is sent before `drop` returns when the dropping thread is not one of the runtime's own).

What shapes this task:
- This task pins down how a connection lives and ends. Most of its tests pass the moment they are written, because Tasks 7 and 8 already behave this way: they are the evidence for spec §6.2 steps 2, 3 and 5 and for the "after phase 0" items of §12. One test fails first and shows a real bug (see below).
- **Keepalive.** russh's own default is off, so `client_config` sets it from the host record. Its meaning is "nothing received for this long": a silent link is noticed after (`keepalive_max_missed` + 1) × `keepalive_every` (the spike measured about 3 s for 1 s and 2 on macOS), and keepalive only counts once the login is done. `keepalive_closes_a_silent_link_and_the_reason_says_so` blackholes a proxy and checks the reason (`KeepaliveTimeout`, the lost hop named); `a_link_that_answers_keeps_the_session_alive_across_several_intervals` is the control.
- **Settle before you leave.** The tests that look for sshd's `Received disconnect` line (closing and dropping here, closing a chain in Task 10) first run a command that does nothing (`settle`). Without it they failed in about one run of seven on this machine, each time a different one of the three. The sshd log of a failing run read `Accepted publickey`, then `BSM audit: … setaudit_addr failed`, then `ssh_packet_send_debug: send DEBUG: Broken pipe`, and no disconnect line at all: sshd was still setting the session up (on macOS that includes BSM auditing, which fails for a normal user) when the client, which had seen the login logged, was already gone, and it gave up on the broken pipe before it read the disconnect message that was waiting in its socket. The engine had written that message (`close` waits until the session task is done); the test was racing the server. A round trip through the session proves the setup is over, and with it 30 consecutive runs of the engine tests passed.
- **Closing and dropping.** `close` sends a disconnect on every hop and the reason is `ClosedByUs`. Dropping the last handle of a session must do the same, and does not: `Drop` used to *spawn* the disconnect on the runtime, but when the session is the last owner of the engine's runtime (the engine was dropped first) the runtime dies with the spawned task unfinished and the server never sees a disconnect. The fix blocks, bounded to 3 s, when the dropping thread is not a runtime thread, and spawns only when it is one (blocking is not allowed there). `dropping_a_session_closes_the_connection_with_a_disconnect` is the test that fails first.
- **The stuck session (spec §12, §16).** `a_session_whose_signer_failed_is_stuck_and_only_dropping_the_handle_ends_it` uses a bare russh handler (not the engine) to document what the engine relies on: after the signer returns an error, `authenticate_none` on the same `Handle` never answers and `disconnect()` does nothing; dropping the `Handle` ends the connection. That is why Task 7 drops the connection on a signer error instead of trying another method.
- **The idle spin (spec §12, from reading russh's `client/mod.rs`).** `russh_spins_when_a_connection_idles_unauthenticated_past_the_keepalive_interval` measures it: with keepalive set, an *unauthenticated* connection that idles past the interval spins a CPU core (the elapsed timer is not reset), and without keepalive it does not. The test asserts the spin, on purpose: when a russh upgrade fixes it the test fails with "the unauthenticated-idle rule can be relaxed". The engine's rule follows from it: never let a login wait for a person while connected and unauthenticated (Task 11 asks for a password before connecting; a keyboard-interactive wait is inside a blocked russh loop and does not spin, which Task 11 measures). `an_authenticated_connection_that_idles_with_keepalive_does_not_burn_cpu` is the contract that matters.
- **Measuring CPU in a child process.** The CPU time of a process is only meaningful when nothing else runs in it, and `cargo test` runs many tests at once. `rerun_alone(name)` re-executes the test binary with `--exact <name> --nocapture --test-threads=1` and `SSHELTER_TEST_CHILD=1`, so the child does the measuring and prints `FACT <key> = <value>` lines; the parent reads them with `fact_in` and asserts. The child is bounded to two minutes.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/engine_tests/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/engine_tests/mod.rs
+++ b/src-tauri/src/ssh/engine_tests/mod.rs
@@ -3,6 +3,7 @@
 
 mod connect;
 mod exec;
+mod liveness;
 mod shell;
 
 use std::sync::{Arc, Mutex, PoisonError};
@@ -40,6 +41,13 @@ fn open_session_to(engine: &RusshEngine, target: &Target, auth: &VaultAuth) -> B
     engine.connect(target, &*TestPolicy::trusting(), auth).expect("the engine connects")
 }
 
+/// Runs a command that does nothing, so that sshd has finished setting the session up. A client that leaves while sshd is still busy with
+/// that (on macOS it takes a moment after the login has been logged: BSM auditing) makes sshd die on a broken pipe before it reads the
+/// disconnect message, and then no "Received disconnect" is ever logged: a test that looks for the message must settle first.
+fn settle(session: &dyn Session) {
+    session.exec("true", Duration::from_secs(20), 1024).expect("a command runs");
+}
+
 /// Reads a shell on a thread of its own, as the broker will, so a test can wait for text to show up without ever blocking on the shell.
 struct ShellProbe {
     shell: Arc<dyn ShellChannel>,
```

`src-tauri/src/ssh/testing/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/testing/mod.rs
+++ b/src-tauri/src/ssh/testing/mod.rs
@@ -23,3 +23,43 @@ pub fn eventually(what: &str, seconds: u64, mut condition: impl FnMut() -> bool)
     }
     panic!("timed out after {seconds} s waiting for: {what}");
 }
+
+/// CPU time (user plus system) this whole process has used so far, in milliseconds. Unix only.
+#[cfg(unix)]
+pub fn cpu_time_ms() -> u128 {
+    // SAFETY: `getrusage` only writes into the struct it is given, and `rusage` is plain data for which all-zero bytes are a valid value.
+    let usage = unsafe {
+        let mut usage: libc::rusage = std::mem::zeroed();
+        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
+        usage
+    };
+    let millis = |time: libc::timeval| time.tv_sec as u128 * 1000 + time.tv_usec as u128 / 1000;
+    millis(usage.ru_utime) + millis(usage.ru_stime)
+}
+
+/// The environment variable that tells a test it is the child that `rerun_alone` started.
+const CHILD_VARIABLE: &str = "SSHELTER_TEST_CHILD";
+
+/// True in the process `rerun_alone` started.
+pub fn is_child() -> bool {
+    std::env::var(CHILD_VARIABLE).is_ok_and(|value| value == "1")
+}
+
+/// Runs the test `name` (its full path, as `cargo test -- --list` prints it) alone in a fresh process of this test binary and returns what
+/// that process wrote to stderr. The process-wide CPU time is only meaningful when no other test is running, and `cargo test` runs many at
+/// once; a child with `--test-threads=1` is the only thing running. Panics when the child fails or takes more than two minutes.
+pub fn rerun_alone(name: &str) -> String {
+    let executable = std::env::current_exe().expect("the path of this test binary");
+    let mut command = std::process::Command::new(executable);
+    command.args(["--exact", name, "--nocapture", "--test-threads=1"]).env(CHILD_VARIABLE, "1");
+    let output = harness::run_within(&mut command, std::time::Duration::from_secs(120)).unwrap_or_else(|message| panic!("{message}"));
+    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
+    assert!(output.status.success(), "the child process failed:\n{stderr}");
+    stderr
+}
+
+/// The value of the line `FACT <key> = <value>` in `output`.
+pub fn fact_in(output: &str, key: &str) -> Option<String> {
+    let prefix = format!("FACT {key} = ");
+    output.lines().find_map(|line| line.strip_prefix(&prefix)).map(str::to_string)
+}
```

`src-tauri/src/ssh/engine_tests/liveness.rs`: create

```rust
//! How long a connection lives and how it ends: keepalive, a cut link, closing and dropping (spec §6.2 steps 2, 3 and 5).

use std::time::{Duration, Instant};

use super::{accepted_logins, engine, open_session, open_session_to, settle, LOG_LOGINS};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthMethod, DisconnectKind, SessionError, Target};

const MIB: usize = 1024 * 1024;

/// A server behind a proxy, a session through it, and the proxy to misbehave with.
fn session_through_a_proxy(server: &Server, keepalive_every: Duration, max_missed: u32) -> (Box<dyn crate::ssh::Session>, Proxy) {
    let proxy = Proxy::start(server.sshd.port);
    let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    hop.keepalive_every = keepalive_every;
    hop.keepalive_max_missed = max_missed;
    let session = open_session_to(&engine(), &Target { hops: vec![hop] }, &server.vault("k1"));
    (session, proxy)
}

/// russh's keepalive is "nothing received for this long", and a link that goes quiet is noticed after (max_missed + 1) × every; the
/// spike measured 3044 ms for 1 s and 2 on macOS. The bounds are wide, the point is the order of magnitude and the reason.
#[test]
fn keepalive_closes_a_silent_link_and_the_reason_says_so() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let (session, proxy) = session_through_a_proxy(&server, Duration::from_secs(1), 2);
    assert!(session.is_alive() && session.disconnect_reason().is_none());

    proxy.set(Mode::Blackhole);
    let silenced = Instant::now();
    eventually("keepalive to give up on the silent link", 20, || !session.is_alive());
    let noticed_after = silenced.elapsed();
    fact("keepalive.interval_1s_max_2.noticed_after_ms", noticed_after.as_millis());
    assert!(noticed_after >= Duration::from_secs(2) && noticed_after <= Duration::from_secs(10), "noticed after {noticed_after:?}");

    let reason = session.disconnect_reason().expect("a dead session says why");
    assert_eq!((reason.kind, reason.hop.alias.as_str()), (DisconnectKind::KeepaliveTimeout, "web"), "{reason:?}");
    assert_eq!(session.exec("echo never", Duration::from_secs(5), MIB), Err(SessionError::Closed));
}

#[test]
fn a_link_that_answers_keeps_the_session_alive_across_several_intervals() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let (session, _proxy) = session_through_a_proxy(&server, Duration::from_secs(1), 2);

    std::thread::sleep(Duration::from_secs(6));
    assert!(session.is_alive(), "the session was closed while the peer was answering: {:?}", session.disconnect_reason());
    assert_eq!(session.exec("echo still-here", Duration::from_secs(10), MIB).unwrap().stdout, b"still-here\n");
}

#[test]
fn a_link_that_is_cut_while_idle_is_noticed_as_a_lost_connection() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let (session, proxy) = session_through_a_proxy(&server, Duration::ZERO, 0);

    proxy.set(Mode::Cut);
    eventually("the cut to be noticed", 10, || !session.is_alive());
    let reason = session.disconnect_reason().expect("a dead session says why");
    fact("cut_while_idle.reason", format!("{:?} {}", reason.kind, reason.detail));
    assert_eq!(reason.kind, DisconnectKind::ConnectionLost, "{reason:?}");
}

#[test]
fn closing_a_session_sends_a_disconnect_and_the_reason_is_ours() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let session = open_session(&engine(), &server);
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
    settle(session.as_ref());

    session.close();
    session.close();
    assert!(!session.is_alive());
    let reason = session.disconnect_reason().expect("closed");
    assert_eq!(reason.kind, DisconnectKind::ClosedByUs);
    eventually("sshd to log a disconnect message (a dropped socket would not be one)", 5, || server.sshd.log().contains("Received disconnect"));
}

#[test]
fn dropping_a_session_closes_the_connection_with_a_disconnect() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let session = open_session(&engine(), &server);
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
    settle(session.as_ref());

    drop(session);
    eventually("sshd to log a disconnect message", 5, || server.sshd.log().contains("Received disconnect"));
}

/// Review focus: an idle connection must cost nothing. With a 1 s keepalive the session sends a probe every second and gets an answer;
/// that must not turn into a busy loop. The process-wide CPU time is only meaningful when nothing else runs, so a child process of the
/// test binary does the measuring.
#[cfg(unix)]
#[test]
fn an_authenticated_connection_that_idles_with_keepalive_does_not_burn_cpu() {
    use crate::ssh::testing::{cpu_time_ms, fact_in, is_child, rerun_alone};

    const NAME: &str = "ssh::engine_tests::liveness::an_authenticated_connection_that_idles_with_keepalive_does_not_burn_cpu";
    let Some(tools) = tools() else { return };
    if !is_child() {
        let output = rerun_alone(NAME);
        let used: u128 = fact_in(&output, "idle.authenticated.cpu_ms").expect("the child measured").parse().expect("a number");
        assert!(used < 500, "2.5 s of idling used {used} ms of CPU");
        return;
    }
    let server = Server::start(&tools, &[]);
    let (session, _proxy) = session_through_a_proxy(&server, Duration::from_secs(1), 3);
    std::thread::sleep(Duration::from_millis(1000));
    let before = cpu_time_ms();
    std::thread::sleep(Duration::from_millis(2500));
    fact("idle.authenticated.cpu_ms", cpu_time_ms() - before);
    assert!(session.is_alive());
}
```

`src-tauri/src/ssh/russh_engine.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/russh_engine.rs
+++ b/src-tauri/src/ssh/russh_engine.rs
@@ -851,6 +851,109 @@ mod tests {
         }
     }
 
+    /// A bare russh handler for the measurements: it trusts any host key and writes down how the connection ended.
+    struct Bare {
+        ended: Arc<Mutex<Option<String>>>,
+    }
+
+    impl Handler for Bare {
+        type Error = russh::Error;
+
+        async fn check_server_key(&mut self, _key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
+            Ok(true)
+        }
+
+        async fn disconnected(&mut self, reason: RusshDisconnect<Self::Error>) -> Result<(), Self::Error> {
+            *locked(&self.ended) = Some(format!("{reason:?}"));
+            match reason {
+                RusshDisconnect::ReceivedDisconnect(_) => Ok(()),
+                RusshDisconnect::Error(error) => Err(error),
+            }
+        }
+    }
+
+    fn runtime() -> tokio::runtime::Runtime {
+        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("a runtime")
+    }
+
+    /// Spec §6.2 step 4, read from russh's source and measured here for the first time. When the signer fails, russh's session is left
+    /// waiting for a signature that never comes: later calls get no answer, `disconnect()` is accepted and does nothing, and only
+    /// dropping the `Handle` ends it. That is why a failed login drops the connection and never tries another method on it.
+    #[test]
+    fn a_session_whose_signer_failed_is_stuck_and_only_dropping_the_handle_ends_it() {
+        use crate::ssh::testing::fact;
+        use crate::ssh::testing::fixture::Server;
+        use crate::ssh::testing::harness::tools;
+
+        let Some(tools) = tools() else { return };
+        let server = Server::start(&tools, &[]);
+        let failing = server.vault("k1").failing_to_sign(AuthError::Refused("the vault is locked".into()));
+        let public = PublicKey::from_openssh(&server.key.public_line).expect("the user key");
+        let ended = Arc::new(Mutex::new(None));
+
+        runtime().block_on(async {
+            let mut handle = client::connect(Arc::new(Config::default()), ("127.0.0.1", server.sshd.port), Bare { ended: Arc::clone(&ended) }).await.expect("connects");
+            let mut signer = EngineSigner { auth: &failing, key_id: "k1" };
+            let result = tokio::time::timeout(Duration::from_secs(5), handle.authenticate_publickey_with(server.sshd.user.as_str(), public, None, &mut signer)).await;
+            fact("signer_failure.login_call", format!("{result:?}"));
+            assert!(matches!(result, Ok(Err(SignerFailure::Auth(_)))), "the signer's error comes straight back: {result:?}");
+
+            let next = tokio::time::timeout(Duration::from_secs(2), handle.authenticate_none(server.sshd.user.as_str())).await;
+            fact("signer_failure.authenticate_none_within_2s", format!("{next:?}"));
+            assert!(next.is_err(), "a call on the stuck session got an answer: {next:?}");
+
+            let disconnect = handle.disconnect(Disconnect::ByApplication, "", "en").await;
+            tokio::time::sleep(Duration::from_secs(1)).await;
+            fact("signer_failure.disconnect_call", format!("{disconnect:?}"));
+            fact("signer_failure.is_closed_1s_after_disconnect", handle.is_closed());
+            assert!(disconnect.is_ok() && !handle.is_closed() && locked(&ended).is_none(), "disconnect() did something to a stuck session");
+
+            drop(handle);
+            let deadline = std::time::Instant::now() + Duration::from_secs(5);
+            while locked(&ended).is_none() && std::time::Instant::now() < deadline {
+                tokio::time::sleep(Duration::from_millis(20)).await;
+            }
+            fact("signer_failure.end_after_drop", format!("{:?}", locked(&ended)));
+            assert!(locked(&ended).is_some(), "dropping the handle did not end the session");
+        });
+    }
+
+    /// Review focus, read from russh's source (client/mod.rs, the keepalive branch of the session loop) and measured here: once the keepalive
+    /// timer has fired on a connection that is not logged in yet, nothing resets it and the loop spins. The engine never idles
+    /// unauthenticated (the password is fetched before connecting; a keyboard-interactive wait sits inside russh's blocked loop), so this
+    /// is not a bug of the engine; it is the reason for that rule, and the test turns red when a russh upgrade fixes it.
+    #[cfg(unix)]
+    #[test]
+    fn russh_spins_when_a_connection_idles_unauthenticated_past_the_keepalive_interval() {
+        use crate::ssh::testing::fixture::Server;
+        use crate::ssh::testing::harness::tools;
+        use crate::ssh::testing::{cpu_time_ms, fact, fact_in, is_child, rerun_alone};
+
+        const NAME: &str = "ssh::russh_engine::tests::russh_spins_when_a_connection_idles_unauthenticated_past_the_keepalive_interval";
+        let Some(tools) = tools() else { return };
+        if !is_child() {
+            let output = rerun_alone(NAME);
+            let cpu = |key: &str| -> u128 { fact_in(&output, key).expect("the child measured").parse().expect("a number") };
+            let (with_keepalive, without) = (cpu("idle.unauthenticated.keepalive_1s.cpu_ms"), cpu("idle.unauthenticated.no_keepalive.cpu_ms"));
+            // the design expected: an idle connection costs nothing, whatever its state
+            assert!(without < 200, "without keepalive an idle connection used {without} ms of CPU in 3 s");
+            assert!(with_keepalive > 1000, "russh no longer spins ({with_keepalive} ms of CPU in 3 s): the unauthenticated-idle rule can be relaxed");
+            return;
+        }
+        let server = Server::start(&tools, &[]);
+        runtime().block_on(async {
+            for (label, interval) in [("keepalive_1s", Some(Duration::from_secs(1))), ("no_keepalive", None)] {
+                let config = Config { keepalive_interval: interval, keepalive_max: 3, ..Config::default() };
+                let handle = client::connect(Arc::new(config), ("127.0.0.1", server.sshd.port), Bare { ended: Arc::default() }).await.expect("connects");
+                tokio::time::sleep(Duration::from_millis(200)).await;
+                let before = cpu_time_ms();
+                tokio::time::sleep(Duration::from_secs(3)).await;
+                fact(&format!("idle.unauthenticated.{label}.cpu_ms"), cpu_time_ms() - before);
+                assert!(!handle.is_closed());
+            }
+        });
+    }
+
     /// The last line of defence for spec §6.3 b: even if the caller of the signer asked for SHA-1, an RSA key is never signed with it and
     /// `sign` is not called. For the other key types the hash means nothing and is not passed on.
     #[test]
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::engine_tests::liveness::dropping_a_session_closes_the_connection_with_a_disconnect
```

Expected: FAIL, the crate compiles and 1 of the tests fails (`ssh::engine_tests::liveness::dropping_a_session_closes_the_connection_with_a_disconnect`); `test result: FAILED. 0 passed; 1 failed`. The other tests of the task pass already; only the dropping test shows the bug. It is run alone on purpose: the bug is a race between the shutdown of the runtime and a task that was spawned on it a moment before, and a machine that is idle loses that race every time (25 runs of 25) while inside a full run of the engine tests, with the runtime's threads busy, the test can pass by luck (it did once).

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/russh_engine.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/russh_engine.rs
+++ b/src-tauri/src/ssh/russh_engine.rs
@@ -552,11 +552,16 @@ impl SshEngine for RusshEngine {
 }
 
 impl Drop for RusshSession {
-    /// Does not block (it may run on one of the runtime's own threads): the disconnect is sent by a task.
+    /// Sends the disconnects before it returns when it can, because this session may be the last thing keeping the runtime alive and a
+    /// task spawned now would die with it. On one of the runtime's own threads blocking is not allowed, so there a task does it.
     fn drop(&mut self) {
         self.connection.closing.store(true, Ordering::SeqCst);
         let connection = Arc::clone(&self.connection);
-        self.runtime.handle().spawn(async move { connection.disconnect_all().await });
+        if tokio::runtime::Handle::try_current().is_err() {
+            let _ = self.runtime.handle().block_on(async { tokio::time::timeout(Duration::from_secs(3), connection.disconnect_all()).await });
+        } else {
+            self.runtime.handle().spawn(async move { connection.disconnect_all().await });
+        }
     }
 }
 
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 100 passed; 0 failed`. The run takes about 15 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1517 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 116 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/engine_tests/liveness.rs src-tauri/src/ssh/engine_tests/mod.rs src-tauri/src/ssh/russh_engine.rs src-tauri/src/ssh/testing/mod.rs
git commit -m "test(ssh): measure keepalive, closing and dropping, the stuck session and the idle CPU"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 10: Jump hosts, and the real cause of a chain's end

**Files:**
- Create (tests): `src-tauri/src/ssh/engine_tests/jump.rs`
- Modify: `src-tauri/src/ssh/engine_tests/mod.rs`
- Modify: `src-tauri/src/ssh/russh_engine.rs` (jump hosts and the real cause of a chain's end)

**Interfaces:**
- Consumes: Task 8's session layer; Task 7's `Connection`, `Established`, `connect_hop` (Task 10 factors its handshake out into `handshake`); Task 6's `Server`, `Proxy`, `TestPolicy`, `VaultAuth`.
- Produces: no new public item (`watch_connection` is private). Behaviour: `Target { hops }` with more than one hop connects through the chain; `Session::disconnect_reason` names the hop whose record is the real cause; closing disconnects every hop, innermost first.

What shapes this task:
- **How a hop is reached (spec §6.2 step 2).** The first hop is a `TcpStream` (with `TCP_NODELAY` set when `hop.nodelay`, because russh applies `Config::nodelay` only in its own `connect`, not in `connect_stream`); every later hop is a `direct-tcpip` channel opened on the previous hop's `Handle` (`channel_open_direct_tcpip` → `into_stream`) and handed to the same `handshake` function, which is generic over the stream. This is OpenSSH's ProxyJump done in process. One `Connection` owns every hop's `Handle`; dropping the outer `Handle` ends nothing while an inner hop still holds one of its channels, so closing is an explicit `disconnect()` on each hop, innermost first (`disconnect_all`).
- **Errors name the hop at fault.** `tunnel_error` turns a refused tunnel into `Unreachable { hop: <the hop being reached>, reason }` where the reason names the jump host (for a jump host `a`: "a could not connect to it", "a does not allow forwarding"); a host key problem on a later hop is the usual `HostKeyUnknown`/`HostKeyMismatch` with that hop's reference; when a later hop fails, `connect_chain` disconnects the hops already established so nothing lingers.
- **The cause of an end (spec §6.2 step 2, §16).** When the outer link dies, the inner hop only learns that its carrier is gone, and russh does not call `Handler::disconnected` for it; the outer hop's own record is the cause. When the *inner* hop ends first while the outer one is fine (not measured in the spike), russh does call the inner handler and its record is the cause. `find_reason` takes the outermost hop that recorded something, gives a closed-but-not-yet-recorded hop 300 ms (russh closes the handle first and calls the handler a moment later), and `reason()` freezes the answer the first time anybody looks, because the teardown that follows makes every hop record `ClosedByUs`. `watch_connection` is the new task that watches a connection for as long as it lives: when one hop has ended it asks for the reason **first** and only then disconnects the others, so the first look is the real one.
- **Closing a chain** (`closing_the_session_disconnects_every_hop`) looks for sshd's `Received disconnect` line on both servers, so it runs a command through the chain first (`settle`, Task 9): the destination's sshd must have finished setting the session up, or it dies on a broken pipe before it reads the disconnect.
- **Large output through two hops** (`a_large_output_crosses_a_jump_without_stalling`) is the flow-control check: sixteen times russh's 2 MiB window has to cross both hops.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/engine_tests/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/engine_tests/mod.rs
+++ b/src-tauri/src/ssh/engine_tests/mod.rs
@@ -3,6 +3,7 @@
 
 mod connect;
 mod exec;
+mod jump;
 mod liveness;
 mod shell;
 
```

`src-tauri/src/ssh/engine_tests/jump.rs`: create

```rust
//! Jump hosts: a chain of connections, each carried inside the one before it (spec §6.2 step 2).

use std::time::{Duration, Instant};

use super::{accepted_logins, engine, settle, ShellProbe, LOG_LOGINS, SHELL_SERVER};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::{tools, Tools};
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthMethod, ConnectError, DisconnectKind, Ended, Pty, Session, SshEngine, Target};

const MIB: usize = 1024 * 1024;

/// Two scratch servers, `a` (the jump host) and `b` (the destination), and one vault holding both user keys.
struct Pair {
    a: Server,
    b: Server,
    vault: VaultAuth,
}

fn pair(tools: &Tools, config_a: &[&str], config_b: &[&str]) -> Pair {
    let (a, b) = (Server::start(tools, config_a), Server::start(tools, config_b));
    let vault = VaultAuth::new().with_key("ka", &a.key.private_text).with_key("kb", &b.key.private_text);
    Pair { a, b, vault }
}

fn key(id: &str) -> AuthMethod {
    AuthMethod::Key { key_id: id.to_string() }
}

/// `a` reached on `port_a` (its own, or a proxy's), then `b` as `a` sees it, on `port_b`.
fn chain(pair: &Pair, port_a: u16, port_b: u16) -> Target {
    Target { hops: vec![pair.a.hop_with("a", port_a, key("ka")), pair.b.hop_with("b", port_b, key("kb"))] }
}

fn open(pair: &Pair, target: &Target) -> Box<dyn Session> {
    engine().connect(target, &*TestPolicy::trusting(), &pair.vault).expect("the chain connects")
}

#[test]
fn a_two_hop_jump_runs_a_command_on_the_second_host_and_checks_each_hops_own_host_key() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let policy = TestPolicy::trusting();
    let target = chain(&pair, pair.a.sshd.port, pair.b.sshd.port);

    let session = engine().connect(&target, &*policy, &pair.vault).expect("the chain connects");
    let result = session.exec("echo hop-$((20+22))", Duration::from_secs(20), MIB).unwrap();
    assert_eq!((result.stdout.as_slice(), result.ended), (b"hop-42\n".as_slice(), Ended::Exited));

    assert_ne!(pair.a.host_key(), pair.b.host_key());
    let seen: Vec<(String, _)> = policy.seen().into_iter().map(|(hop, key)| (hop.alias, key)).collect();
    assert_eq!(seen, vec![("a".to_string(), pair.a.host_key()), ("b".to_string(), pair.b.host_key())], "each hop was checked against its own key");
}

/// The destination's host key is unknown: the chain stops there with the key it presented, and the jump host's connection does not linger.
#[test]
fn an_unknown_key_on_the_second_hop_stops_the_chain_and_closes_the_first_hop() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let target = chain(&pair, proxy_a.port, pair.b.sshd.port);
    let policy = TestPolicy::knowing_nothing();
    policy.pin(&target.hops[0].reference(), pair.a.host_key());

    let error = engine().connect(&target, &*policy, &pair.vault).err().expect("b is not pinned");
    match error {
        ConnectError::HostKeyUnknown { hop, key } => assert_eq!((hop.alias.as_str(), key), ("b", pair.b.host_key())),
        other => panic!("expected HostKeyUnknown, got {other:?}"),
    }
    eventually("the proxy to see the first hop closed", 5, || proxy_a.open_connections() == 0);
}

/// Review focus: the jump host cannot reach the next host. The message names the jump host, comes quickly, and nothing lingers.
#[test]
fn a_jump_to_a_closed_port_fails_cleanly_and_names_the_jump_host() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let closed_port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let target = chain(&pair, proxy_a.port, closed_port);

    let started = Instant::now();
    let error = engine().connect(&target, &*TestPolicy::trusting(), &pair.vault).err().expect("nothing listens there");
    fact("jump.closed_port.after_ms", started.elapsed().as_millis());
    match &error {
        ConnectError::Unreachable { hop, reason } => assert_eq!((hop.alias.as_str(), reason.as_str()), ("b", "a could not connect to it")),
        other => panic!("expected Unreachable, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(10));
    eventually("the proxy to see the first hop closed", 5, || proxy_a.open_connections() == 0);
}

#[test]
fn a_jump_host_that_does_not_allow_forwarding_is_named_in_the_error() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &["AllowTcpForwarding no"], &[]);
    let target = chain(&pair, pair.a.sshd.port, pair.b.sshd.port);
    let error = engine().connect(&target, &*TestPolicy::trusting(), &pair.vault).err().expect("forwarding is off");
    assert!(matches!(&error, ConnectError::Unreachable { hop, reason } if hop.alias == "b" && reason == "a does not allow forwarding"), "{error:?}");
}

#[test]
fn closing_the_session_disconnects_every_hop() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[LOG_LOGINS], &[LOG_LOGINS]);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, pair.b.sshd.port));
    eventually("both servers to log the login", 3, || accepted_logins(&pair.a) == 1 && accepted_logins(&pair.b) == 1);
    settle(session.as_ref());

    session.close();
    eventually("the destination to log a disconnect message", 5, || pair.b.sshd.log().contains("Received disconnect"));
    eventually("the jump host to log a disconnect message", 5, || pair.a.sshd.log().contains("Received disconnect"));
}

/// The outer link dies: the reason is the outer hop's own record. The inner hop only learns that its carrier is gone (spec §6.2 step 2).
#[test]
fn when_the_outer_link_is_cut_the_reason_is_the_outer_hops() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let session = open(&pair, &chain(&pair, proxy_a.port, pair.b.sshd.port));
    assert!(session.is_alive());

    proxy_a.set(Mode::Cut);
    eventually("the cut to be noticed", 10, || !session.is_alive());
    let reason = session.disconnect_reason().expect("a dead session says why");
    fact("jump.outer_cut.reason", format!("{:?} {} {}", reason.kind, reason.hop.alias, reason.detail));
    assert_eq!((reason.hop.alias.as_str(), reason.kind), ("a", DisconnectKind::ConnectionLost), "{reason:?}");
}

/// Not measured in the spike (spec §16): the inner hop ends first while the outer one is fine. A proxy between `a` and `b` is cut. The
/// whole chain must come down, and the reason must be the inner hop's, not the "closed by us" that the teardown makes the outer hop record.
#[test]
fn when_the_inner_hop_ends_first_the_chain_comes_down_and_the_reason_is_the_inner_hops() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[LOG_LOGINS], &[]);
    let proxy_b = Proxy::start(pair.b.sshd.port);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, proxy_b.port));
    eventually("the jump host to log the login", 3, || accepted_logins(&pair.a) == 1);

    proxy_b.set(Mode::Cut);
    eventually("the loss of the inner hop to be noticed", 10, || !session.is_alive());
    let reason = session.disconnect_reason().expect("a dead session says why");
    fact("jump.inner_first.reason", format!("{:?} {} {}", reason.kind, reason.hop.alias, reason.detail));
    assert_eq!((reason.hop.alias.as_str(), reason.kind), ("b", DisconnectKind::ConnectionLost), "{reason:?}");
    eventually("the outer hop to be disconnected as well", 10, || pair.a.sshd.log().contains("Received disconnect"));
    assert_eq!(session.disconnect_reason().map(|again| again.hop.alias), Some("b".to_string()), "the reason does not change afterwards");
}

/// Review focus: flow control through a jump. Sixteen times russh's 2 MiB window of output has to cross two hops.
#[test]
fn a_large_output_crosses_a_jump_without_stalling() {
    const SIZE: usize = 32 * MIB;
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, pair.b.sshd.port));

    let started = Instant::now();
    let result = session.exec(&format!("head -c {SIZE} /dev/zero"), Duration::from_secs(120), 64 * MIB).unwrap();
    fact("jump.long_output.mib_per_second", format!("{:.1}", SIZE as f64 / 1_048_576.0 / started.elapsed().as_secs_f64()));
    assert_eq!((result.stdout.len(), result.ended, result.exit_code), (SIZE, Ended::Exited, Some(0)));
}

#[test]
fn a_shell_on_the_second_host_works_through_the_jump() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], SHELL_SERVER);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, pair.b.sshd.port));

    let probe = ShellProbe::start(session.shell(Pty { term: "xterm-256color".into(), cols: 100, rows: 30 }).unwrap());
    probe.wait_for_text(20, "$ ").expect("a prompt");
    assert_eq!(probe.stty_size().expect("stty answers"), "30 100");
    probe.type_line("exit 4");
    eventually("the shell to report its exit", 10, || probe.shell.exited().is_some());
    assert_eq!(probe.shell.exited(), Some(crate::ssh::Exit::Code(4)));
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate compiles and 9 of the tests fail (`ssh::engine_tests::jump::a_jump_host_that_does_not_allow_forwarding_is_named_in_the_error`, `ssh::engine_tests::jump::a_jump_to_a_closed_port_fails_cleanly_and_names_the_jump_host`, `ssh::engine_tests::jump::a_shell_on_the_second_host_works_through_the_jump`, `ssh::engine_tests::jump::a_large_output_crosses_a_jump_without_stalling`, `ssh::engine_tests::jump::a_two_hop_jump_runs_a_command_on_the_second_host_and_checks_each_hops_own_host_key`, `ssh::engine_tests::jump::an_unknown_key_on_the_second_hop_stops_the_chain_and_closes_the_first_hop`, `ssh::engine_tests::jump::closing_the_session_disconnects_every_hop`, `ssh::engine_tests::jump::when_the_inner_hop_ends_first_the_chain_comes_down_and_the_reason_is_the_inner_hops` and 1 more); `test result: FAILED. 100 passed; 9 failed`. All nine fail with `BadJumpChain { why: "jump hosts are not connected yet" }`, the line Task 7 left in `connect_hop`.

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/russh_engine.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/russh_engine.rs
+++ b/src-tauri/src/ssh/russh_engine.rs
@@ -18,7 +18,8 @@ use russh::client::{self, AuthResult, Config, Handle, Handler, Msg};
 use russh::client::DisconnectReason as RusshDisconnect;
 use russh::keys::agent::AgentIdentity;
 use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
-use russh::{AlgorithmKind, Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect, MethodKind, MethodSet, Preferred, Sig};
+use russh::{AlgorithmKind, Channel, ChannelMsg, ChannelOpenFailure, ChannelReadHalf, ChannelWriteHalf, Disconnect, MethodKind, MethodSet, Preferred, Sig};
+use tokio::io::{AsyncRead, AsyncWrite};
 use tokio::net::TcpStream;
 use tokio::sync::{mpsc, oneshot, watch};
 use tokio::time::Instant;
@@ -236,11 +237,14 @@ pub struct Connection {
     hops: Vec<Established>,
     /// Set when we are the ones closing it, so that the reason is ours whatever order the hops notice in.
     closing: AtomicBool,
+    /// Why the connection ended, written down the first time anybody sees that it has. Our own disconnects follow and make every hop
+    /// record `ClosedByUs`; this keeps the real cause.
+    ended: Mutex<Option<DisconnectReason>>,
 }
 
 impl Connection {
     fn new() -> Connection {
-        Connection { hops: Vec::new(), closing: AtomicBool::new(false) }
+        Connection { hops: Vec::new(), closing: AtomicBool::new(false), ended: Mutex::new(None) }
     }
 
     pub fn hop_count(&self) -> usize {
@@ -257,10 +261,19 @@ impl Connection {
         self.hops.last().ok_or(SessionError::Closed)
     }
 
-    /// Why the connection ended: the record of the outermost hop that has one (a hop that dies after its carrier is gone records nothing
-    /// useful, spec §6.2 step 2), else ours when we closed it. A hop whose `Handle` is closed but has not recorded anything yet is about
-    /// to (russh closes the handle first and calls the handler a moment later), so it is given a short while before the fallback is used.
+    /// Why the connection ended, once it has: written down at the first look, so that what the teardown does afterwards cannot change it.
     fn reason(&self) -> Option<DisconnectReason> {
+        let mut ended = locked(&self.ended);
+        if ended.is_none() {
+            *ended = self.find_reason();
+        }
+        ended.clone()
+    }
+
+    /// The record of the outermost hop that has one (a hop that dies after its carrier is gone records nothing useful, spec §6.2 step 2),
+    /// else ours when we closed it. A hop whose `Handle` is closed but has not recorded anything yet is about to (russh closes the handle
+    /// first and calls the handler a moment later), so it is given a short while before the fallback is used.
+    fn find_reason(&self) -> Option<DisconnectReason> {
         let deadline = std::time::Instant::now() + Duration::from_millis(300);
         loop {
             for established in &self.hops {
@@ -297,8 +310,8 @@ impl Connection {
 async fn connect_chain(target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
     check_chain(target)?;
     let mut connection = Connection::new();
-    for (index, hop) in target.hops.iter().enumerate() {
-        match connect_one(index, hop, connection.hops.last(), host_keys, auth).await {
+    for hop in &target.hops {
+        match connect_one(hop, connection.hops.last(), host_keys, auth).await {
             Ok(established) => connection.hops.push(established),
             Err(error) => {
                 connection.disconnect_all().await;
@@ -322,41 +335,40 @@ fn check_chain(target: &Target) -> Result<(), ConnectError> {
     Ok(())
 }
 
-async fn connect_one(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Established, ConnectError> {
+async fn connect_one(hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Established, ConnectError> {
     let reference = hop.reference();
-    let (mut handle, shared) = connect_hop(index, hop, via, host_keys).await?;
+    let (mut handle, shared) = connect_hop(hop, via, host_keys).await?;
     authenticate(hop, &mut handle, auth).await?;
     Ok(Established { hop: reference, handle, shared })
 }
 
-async fn connect_hop(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy) -> Result<(Handle<EngineHandler>, Arc<HopShared>), ConnectError> {
+async fn connect_hop(hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy) -> Result<(Handle<EngineHandler>, Arc<HopShared>), ConnectError> {
     let reference = hop.reference();
-    if via.is_some() || index > 0 {
-        return Err(ConnectError::BadJumpChain { why: "jump hosts are not connected yet".to_string() });
-    }
     let shared = HopShared::new();
     let (questions_in, mut questions) = mpsc::unbounded_channel();
     let handler = EngineHandler { shared: Arc::clone(&shared), questions: questions_in };
     let config = Arc::new(client_config(hop));
     let phase = std::cell::Cell::new(Phase::Tcp);
     let attempt = async {
-        let tcp = TcpStream::connect((hop.hostname.as_str(), hop.port)).await.map_err(|error| ConnectError::Unreachable { hop: reference.clone(), reason: describe_io(&error) })?;
-        if hop.nodelay {
-            let _ = tcp.set_nodelay(true);
-        }
-        phase.set(Phase::Handshake);
-        let connecting = client::connect_stream(config, tcp, handler);
-        tokio::pin!(connecting);
-        let connected = loop {
-            tokio::select! {
-                connected = &mut connecting => break connected,
-                Some(question) = questions.recv() => {
-                    let verdict = host_keys.check(&reference, &question.key);
-                    let _ = question.reply.send(verdict);
+        match via {
+            None => {
+                let tcp = TcpStream::connect((hop.hostname.as_str(), hop.port)).await.map_err(|error| ConnectError::Unreachable { hop: reference.clone(), reason: describe_io(&error) })?;
+                if hop.nodelay {
+                    let _ = tcp.set_nodelay(true);
                 }
+                phase.set(Phase::Handshake);
+                handshake(tcp, config, handler, &mut questions, host_keys, &reference, &shared).await
             }
-        };
-        connected.map_err(|error| handshake_error(&reference, &shared, error))
+            Some(previous) => {
+                let tunnel = previous
+                    .handle
+                    .channel_open_direct_tcpip(hop.hostname.as_str(), u32::from(hop.port), "127.0.0.1", 0)
+                    .await
+                    .map_err(|error| tunnel_error(&reference, &previous.hop, error))?;
+                phase.set(Phase::Handshake);
+                handshake(tunnel.into_stream(), config, handler, &mut questions, host_keys, &reference, &shared).await
+            }
+        }
     };
     let budget = hop.connect_timeout.max(Duration::from_secs(1));
     match tokio::time::timeout(budget, attempt).await {
@@ -365,6 +377,44 @@ async fn connect_hop(index: usize, hop: &Hop, via: Option<&Established>, host_ke
     }
 }
 
+/// The SSH handshake over `stream`. While it runs, the handler's host key questions are answered here, on the caller's thread, from `host_keys`.
+async fn handshake<R>(
+    stream: R,
+    config: Arc<Config>,
+    handler: EngineHandler,
+    questions: &mut mpsc::UnboundedReceiver<KeyQuestion>,
+    host_keys: &dyn HostKeyPolicy,
+    reference: &HopRef,
+    shared: &HopShared,
+) -> Result<Handle<EngineHandler>, ConnectError>
+where
+    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
+{
+    let connecting = client::connect_stream(config, stream, handler);
+    tokio::pin!(connecting);
+    let connected = loop {
+        tokio::select! {
+            connected = &mut connecting => break connected,
+            Some(question) = questions.recv() => {
+                let verdict = host_keys.check(reference, &question.key);
+                let _ = question.reply.send(verdict);
+            }
+        }
+    };
+    connected.map_err(|error| handshake_error(reference, shared, error))
+}
+
+/// Why the jump host `via` could not give us a connection to `hop`: it refused to open the tunnel, or it is gone.
+fn tunnel_error(hop: &HopRef, via: &HopRef, error: russh::Error) -> ConnectError {
+    let reason = match error {
+        russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed) => format!("{} could not connect to it", via.alias),
+        russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited) => format!("{} does not allow forwarding", via.alias),
+        russh::Error::ChannelOpenFailure(other) => format!("{} refused to open the connection ({other:?})", via.alias),
+        _ => format!("the connection to {} was lost", via.alias),
+    };
+    ConnectError::Unreachable { hop: hop.clone(), reason }
+}
+
 /// Turns what russh said about a failed handshake into a `ConnectError`. A rejected host key is the same `UnknownKey` whether the key
 /// was unknown or changed; the handler wrote down which.
 fn handshake_error(hop: &HopRef, shared: &HopShared, error: russh::Error) -> ConnectError {
@@ -547,10 +597,33 @@ pub struct RusshSession {
 impl SshEngine for RusshEngine {
     fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
         let connection = Arc::new(self.connect_chain(target, host_keys, auth)?);
+        watch_connection(&self.runtime, Arc::clone(&connection));
         Ok(Box::new(RusshSession { runtime: Arc::clone(&self.runtime), connection, options: self.options.clone() }))
     }
 }
 
+/// How often the watcher looks at a connection.
+const WATCH_EVERY: Duration = Duration::from_millis(100);
+
+/// Watches a connection for as long as it lives. When one hop ends (the server dropped it, its keepalive ran out, the hop in front of it
+/// went away) every other hop is disconnected too, so that a chain never lingers half open (spec §6.2 step 2). It stops when the
+/// session is closed or dropped.
+fn watch_connection(runtime: &RuntimeOwner, connection: Arc<Connection>) {
+    runtime.handle().spawn(async move {
+        loop {
+            tokio::time::sleep(WATCH_EVERY).await;
+            if connection.closing.load(Ordering::SeqCst) {
+                return;
+            }
+            if connection.hops.iter().any(|established| established.handle.is_closed()) {
+                let _ = connection.reason();
+                connection.disconnect_all().await;
+                return;
+            }
+        }
+    });
+}
+
 impl Drop for RusshSession {
     /// Sends the disconnects before it returns when it can, because this session may be the last thing keeping the runtime alive and a
     /// task spawned now would die with it. On one of the runtime's own threads blocking is not allowed, so there a task does it.
@@ -638,6 +711,9 @@ impl Session for RusshSession {
     }
 
     fn close(&self) {
+        if !self.connection.is_open() {
+            let _ = self.connection.reason();
+        }
         self.connection.closing.store(true, Ordering::SeqCst);
         self.runtime.handle().block_on(self.connection.disconnect_all());
     }
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 109 passed; 0 failed`. The run takes about 16 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1526 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 107 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/engine_tests/jump.rs src-tauri/src/ssh/engine_tests/mod.rs src-tauri/src/ssh/russh_engine.rs
git commit -m "feat(ssh): connect through jump hosts and keep the real cause of a chain's end"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 11: Password and keyboard-interactive logins, against an in-process server

**Files:**
- Modify: `src-tauri/src/ssh/engine_tests/connect.rs` (two more tests)
- Create (tests): `src-tauri/src/ssh/engine_tests/login_methods.rs`
- Modify: `src-tauri/src/ssh/engine_tests/mod.rs`
- Modify: `src-tauri/src/ssh/russh_engine.rs` (password, keyboard-interactive, `EngineOptions::prompt_wait`; the in-process test server `toy_server`)

**Interfaces:**
- Consumes: Task 7's `authenticate`, `Step`, `connect_one`; Task 6's `VaultAuth::{with_password(self, password: &str), with_password_delay(self, delay: Duration), with_answers(self, answers: &[&str]), with_answer_delay(self, delay: Duration), overrunning_the_deadline(self), password_asked_for(&self) -> Vec<HopRef>, prompts_seen(&self) -> Vec<Vec<Prompt>>}`; Task 9's `rerun_alone`, `fact_in`, `is_child`, `cpu_time_ms`.
- Produces: `EngineOptions { pub shell_queue_bytes: usize, pub prompt_wait: Option<Duration>, pub worker_threads: usize }` (`prompt_wait: None` means 4 × the hop's connect timeout, at least 60 s, spec §6.2 step 4); `#[cfg(test)] pub(crate) mod toy_server { ToyLogin { user, password, prompt }, ToyServer::start(login: ToyLogin) -> ToyServer, ToyServer.port }` inside `russh_engine.rs`; the password and keyboard-interactive arms of the login sequence.

What shapes this task:
- **Why an in-process server.** A scratch sshd runs as a normal user, has no PAM, and so cannot check a password or run keyboard-interactive. `toy_server` is a small SSH server on russh's own server side (public key refused, password and keyboard-interactive accepted for one user, every command prints `ok` and exits 0). It lives inside `russh_engine.rs` because russh may be named in no other file, and it is a fixture, not a model of a real server: Task 12 runs the very same test bodies against a real OpenSSH with PAM in a container (`login_methods.rs` runs each body twice, as `toy::…` and as `pam::…`, and the `pam` ones print `skipped` unless `SSHELTER_PAM_PORT`, `SSHELTER_PAM_USER` and `SSHELTER_PAM_PASSWORD` say where the container is; `SSHELTER_REQUIRE_PAM=1` turns a skip into a failure).
- **The login sequence, complete (spec §6.2 step 4).** A method is *tried* only if the server still offers it; a *refusal* moves to the next method on the same connection. A method that cannot be tried here (no key in the vault, no password) is *skipped*, and the first time that happens the engine asks the server once what it does offer (`authenticate_none`), so later methods are not sent blindly. A hop that starts with the password method asks `AuthSource::password` **before it opens the connection** (`a_password_is_asked_for_before_the_connection_is_opened`): a person typing would otherwise leave an unauthenticated connection waiting, the server's login grace time would run, and russh would spin (Task 9).
- **Keyboard-interactive.** Every round is shown to `AuthSource::interactive(hop, prompts, deadline)` with `deadline = now + prompt_wait`. `None` abandons the login (`AuthAbandoned`: "the prompt was cancelled"), an answer that arrives after the deadline is not believed ("answered after its deadline"), and a wrong number of answers is abandoned too; in all cases the connection is dropped. The wait for the server's reply to the answers is bounded by `prompt_wait` as well. While the engine waits for the person, russh's session is blocked inside its login call and does not spin: `waiting_for_a_prompt_costs_no_cpu` measures it in a child process.
- **What is not tested here.** The real OpenSSH's PAM behaviour — its failure delays, how many rounds PAM asks — can only be seen in the container of Task 12; the toy server answers at once.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/engine_tests/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/engine_tests/mod.rs
+++ b/src-tauri/src/ssh/engine_tests/mod.rs
@@ -5,6 +5,7 @@ mod connect;
 mod exec;
 mod jump;
 mod liveness;
+mod login_methods;
 mod shell;
 
 use std::sync::{Arc, Mutex, PoisonError};
```

`src-tauri/src/ssh/engine_tests/connect.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/engine_tests/connect.rs
+++ b/src-tauri/src/ssh/engine_tests/connect.rs
@@ -207,6 +207,35 @@ fn an_rsa_key_is_never_signed_with_sha1() {
     assert_eq!(accepted_logins(&server), 0);
 }
 
+#[test]
+fn the_other_login_methods_are_refused_by_a_key_only_server_and_only_offered_methods_are_tried() {
+    let Some(tools) = tools() else { return };
+    let server = Server::start(&tools, &[]);
+    let policy = trusting();
+
+    // A hop that starts with a password: the server refuses it; keyboard-interactive is not on its list, so it is not tried.
+    let auth = server.vault("k1").with_password("not-the-password").with_answers(&["unused"]);
+    let hop = server.hop_with("web", server.sshd.port, AuthMethod::Password);
+    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*policy, &auth).err().expect("no password login here");
+    assert!(matches!(&error, ConnectError::AuthFailed { tried, .. } if *tried == [AuthMethod::Password]), "{error:?}");
+    assert_eq!(auth.password_asked_for().len(), 1);
+    assert!(auth.prompts_seen().is_empty(), "keyboard-interactive was not tried");
+
+    // A hop that starts with keyboard-interactive: refused at once, no prompt ever shown.
+    let hop = server.hop_with("web", server.sshd.port, AuthMethod::Interactive);
+    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*policy, &auth).err().expect("no keyboard-interactive login here");
+    assert!(matches!(&error, ConnectError::AuthFailed { tried, .. } if *tried == [AuthMethod::Interactive]), "{error:?}");
+    assert!(auth.prompts_seen().is_empty());
+
+    // A hop that starts with a key the server refuses: password and keyboard-interactive are not offered, so neither is asked for.
+    let stranger_dir = tempfile::tempdir().unwrap();
+    let stranger = generate_key(&tools, stranger_dir.path(), "stranger", KeyKind::Ed25519);
+    let auth = VaultAuth::new().with_key("k1", &stranger.private_text).with_password("pw");
+    let error = engine().connect_chain(&server.target("k1"), &*policy, &auth).err().expect("the key is not authorized");
+    assert!(matches!(&error, ConnectError::AuthFailed { tried, .. } if *tried == [AuthMethod::Key { key_id: "k1".into() }]), "{error:?}");
+    assert!(auth.password_asked_for().is_empty(), "the server does not offer passwords, so none was asked for");
+}
+
 #[test]
 fn a_key_that_is_not_in_the_vault_is_skipped_and_the_failure_says_so() {
     let Some(tools) = tools() else { return };
@@ -221,6 +250,46 @@ fn a_key_that_is_not_in_the_vault_is_skipped_and_the_failure_says_so() {
     }
 }
 
+/// A hop that starts with the password method asks for the password before it opens the connection: a person typing must not leave an
+/// unauthenticated connection waiting (the server's grace time runs; russh's loop spins).
+#[test]
+fn a_password_is_asked_for_before_the_connection_is_opened() {
+    use crate::ssh::{AuthSource, HopRef, Prompt, Secret, Signature};
+    use std::sync::Arc;
+
+    struct Probe {
+        proxy: Arc<Proxy>,
+        accepted_when_asked: std::sync::Mutex<Option<usize>>,
+    }
+    impl AuthSource for Probe {
+        fn public_key(&self, _key_id: &str) -> Option<String> {
+            None
+        }
+        fn sign(&self, _key_id: &str, _data: &[u8], _rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
+            Err(AuthError::Refused("no keys here".into()))
+        }
+        fn password(&self, _hop: &HopRef) -> Option<Secret> {
+            *self.accepted_when_asked.lock().unwrap() = Some(self.proxy.accepted());
+            std::thread::sleep(Duration::from_millis(500));
+            Some(zeroize::Zeroizing::new("whatever".to_string()))
+        }
+        fn interactive(&self, _hop: &HopRef, _prompts: &[Prompt], _deadline: Instant) -> Option<Vec<Secret>> {
+            None
+        }
+    }
+
+    let Some(tools) = tools() else { return };
+    let server = Server::start(&tools, &[]);
+    let proxy = Arc::new(Proxy::start(server.sshd.port));
+    let probe = Probe { proxy: Arc::clone(&proxy), accepted_when_asked: std::sync::Mutex::new(None) };
+    let hop = server.hop_with("web", proxy.port, AuthMethod::Password);
+
+    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &probe).err().expect("the server refuses passwords");
+    assert!(matches!(error, ConnectError::AuthFailed { .. }), "{error:?}");
+    assert_eq!(*probe.accepted_when_asked.lock().unwrap(), Some(0), "nothing had connected when the password was asked for");
+    assert_eq!(proxy.accepted(), 1, "the connection was made afterwards");
+}
+
 // ---------------------------------------------------------------------------------------------------------------------------------
 // Failures to connect, and the login that is abandoned.
 
```

`src-tauri/src/ssh/engine_tests/login_methods.rs`: create

```rust
//! Logging in with a password and with keyboard-interactive, and what happens to a prompt that is cancelled, late or slow (spec §6.2
//! step 4). A scratch OpenSSH has no PAM and cannot do either, so the same test bodies run against two servers:
//! - `toy`: a small SSH server in process (`russh_engine::toy_server`), everywhere, always;
//! - `pam`: a real OpenSSH with PAM in a container (`src-tauri/tests/pam-sshd`), when `SSHELTER_PAM_PORT`, `SSHELTER_PAM_USER` and
//!   `SSHELTER_PAM_PASSWORD` say where it is. Without them the `pam` tests print "skipped" and pass, unless `SSHELTER_REQUIRE_PAM=1`
//!   (the Linux job of the CI) turns that into a failure.

use std::time::{Duration, Instant};

use super::{engine, open_session_to};
use crate::ssh::russh_engine::toy_server::{ToyLogin, ToyServer};
use crate::ssh::russh_engine::{EngineOptions, RusshEngine};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::harness::{generate_key, tools, KeyKind};
use crate::ssh::testing::proxy::Proxy;
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthMethod, ConnectError, Ended, Hop, SessionError, SshEngine, Target};

const MIB: usize = 1024 * 1024;

/// A server to log in to.
struct Subject {
    port: u16,
    user: String,
    password: String,
    /// Keeps an in-process server running for as long as the subject lives.
    _toy: Option<ToyServer>,
}

impl Subject {
    fn hop_on(&self, port: u16, auth: AuthMethod) -> Hop {
        Hop::new("host-login", "login", "127.0.0.1", port, &self.user, auth)
    }

    fn target_on(&self, port: u16, auth: AuthMethod) -> Target {
        Target { hops: vec![self.hop_on(port, auth)] }
    }
}

fn toy() -> Option<Subject> {
    let login = ToyLogin { user: "tester".to_string(), password: "correct horse battery staple".to_string(), prompt: "Password: ".to_string() };
    let server = ToyServer::start(login.clone());
    Some(Subject { port: server.port, user: login.user, password: login.password, _toy: Some(server) })
}

fn pam() -> Option<Subject> {
    let variable = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let (Some(port), Some(user), Some(password)) = (variable("SSHELTER_PAM_PORT"), variable("SSHELTER_PAM_USER"), variable("SSHELTER_PAM_PASSWORD")) else {
        let required = std::env::var("SSHELTER_REQUIRE_PAM").is_ok_and(|value| value == "1");
        assert!(!required, "SSHELTER_PAM_PORT, SSHELTER_PAM_USER and SSHELTER_PAM_PASSWORD are required (SSHELTER_REQUIRE_PAM=1)");
        eprintln!("skipped: SSHELTER_PAM_PORT, SSHELTER_PAM_USER and SSHELTER_PAM_PASSWORD are not all set");
        return None;
    };
    Some(Subject { port: port.parse().expect("SSHELTER_PAM_PORT is a port number"), user, password, _toy: None })
}

fn engine_with_prompt_wait(wait: Duration) -> RusshEngine {
    RusshEngine::with_options(EngineOptions { prompt_wait: Some(wait), worker_threads: 2, ..EngineOptions::default() })
}

fn ok_output(session: &dyn crate::ssh::Session) {
    let result = session.exec("echo ok", Duration::from_secs(20), MIB).expect("the session runs a command");
    assert_eq!((result.stdout.as_slice(), result.ended, result.exit_code), (b"ok\n".as_slice(), Ended::Exited, Some(0)));
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The test bodies, run by `toy` and by `pam` below.

fn password_login_succeeds(subject: &Subject) {
    let auth = VaultAuth::new().with_password(&subject.password);
    let session = open_session_to(&engine(), &subject.target_on(subject.port, AuthMethod::Password), &auth);
    ok_output(session.as_ref());
    assert_eq!(auth.password_asked_for().len(), 1);
    assert!(auth.prompts_seen().is_empty(), "keyboard-interactive was not needed");
}

/// A refused password is not the end: the sequence goes on to keyboard-interactive, which the server offers too.
fn a_wrong_password_is_refused_and_keyboard_interactive_is_tried_next(subject: &Subject) {
    let auth = VaultAuth::new().with_password("not the password").with_answers(&["not the password"]);
    let error = engine().connect(&subject.target_on(subject.port, AuthMethod::Password), &*TestPolicy::trusting(), &auth).err().expect("wrong credentials");
    assert!(matches!(&error, ConnectError::AuthFailed { tried, .. } if *tried == [AuthMethod::Password, AuthMethod::Interactive]), "{error:?}");
    assert_eq!((auth.password_asked_for().len(), auth.prompts_seen().len()), (1, 1));
}

fn keyboard_interactive_login_succeeds(subject: &Subject) {
    let auth = VaultAuth::new().with_answers(&[&subject.password]);
    let session = open_session_to(&engine(), &subject.target_on(subject.port, AuthMethod::Interactive), &auth);
    ok_output(session.as_ref());
    let prompts = auth.prompts_seen();
    assert_eq!(prompts.len(), 1, "one round of questions: {prompts:?}");
    assert!(prompts[0][0].text.contains("assword") && !prompts[0][0].echo, "{:?}", prompts[0][0]);
}

/// The host's key is not accepted by the server: the key method is refused without a signature, and the sequence falls back to the password.
fn a_refused_key_falls_back_to_the_password(subject: &Subject) {
    let Some(tools) = tools() else { return };
    let keys = tempfile::tempdir().unwrap();
    let stranger = generate_key(&tools, keys.path(), "stranger", KeyKind::Ed25519);
    let auth = VaultAuth::new().with_key("k1", &stranger.private_text).with_password(&subject.password);
    let session = open_session_to(&engine(), &subject.target_on(subject.port, AuthMethod::Key { key_id: "k1".into() }), &auth);
    ok_output(session.as_ref());
    assert_eq!(auth.password_asked_for().len(), 1, "the password was asked for after the key was refused");
}

/// Review focus: the user cancels the prompt. The login is abandoned with a clear error and the connection is dropped, not left waiting.
fn a_cancelled_prompt_abandons_the_login_and_drops_the_connection(subject: &Subject) {
    let proxy = Proxy::start(subject.port);
    let auth = VaultAuth::new();
    let started = Instant::now();
    let error = engine().connect(&subject.target_on(proxy.port, AuthMethod::Interactive), &*TestPolicy::trusting(), &auth).err().expect("nobody answered");
    assert!(matches!(&error, ConnectError::AuthAbandoned { hop, .. } if hop.alias == "login"), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10), "no waiting: {:?}", started.elapsed());
    eventually("the proxy to see the connection dropped", 5, || proxy.open_connections() == 0);
}

/// Review focus: the prompt takes longer than the engine will wait (here 1 s instead of the minute it is by default). A source that
/// behaves, like the broker, gives up at the deadline; one that answers late anyway is not believed either.
fn a_prompt_that_runs_out_of_time_abandons_the_login_and_drops_the_connection(subject: &Subject) {
    let engine = engine_with_prompt_wait(Duration::from_secs(1));
    for (label, auth) in [
        ("gives up at the deadline", VaultAuth::new().with_answers(&[&subject.password]).with_answer_delay(Duration::from_secs(5))),
        ("answers after the deadline", VaultAuth::new().with_answers(&[&subject.password]).with_answer_delay(Duration::from_millis(2500)).overrunning_the_deadline()),
    ] {
        let proxy = Proxy::start(subject.port);
        let started = Instant::now();
        let error = engine.connect(&subject.target_on(proxy.port, AuthMethod::Interactive), &*TestPolicy::trusting(), &auth).err().expect("the prompt ran out of time");
        let waited = started.elapsed();
        fact(&format!("prompt_timeout.{}.waited_ms", label.replace(' ', "_")), waited.as_millis());
        assert!(matches!(error, ConnectError::AuthAbandoned { .. }), "{label}: {error:?}");
        assert!(waited >= Duration::from_millis(900) && waited < Duration::from_secs(8), "{label}: waited {waited:?}");
        eventually("the proxy to see the connection dropped", 5, || proxy.open_connections() == 0);
    }
}

/// Review focus: a person is thinking about a prompt. russh's session is blocked inside the login while the engine waits, so the keepalive
/// timer does not turn into a busy loop. Measured in a child process, because the CPU time of a process is only meaningful when nothing else runs.
#[cfg(unix)]
fn waiting_for_a_prompt_costs_no_cpu(subject: &Subject, test: &str) {
    use crate::ssh::testing::{cpu_time_ms, fact_in, is_child, rerun_alone};

    if !is_child() {
        let output = rerun_alone(test);
        let used: u128 = fact_in(&output, "prompt_wait.cpu_ms").expect("the child measured").parse().expect("a number");
        assert!(used < 500, "2 s of waiting for a prompt used {used} ms of CPU");
        return;
    }
    let mut hop = subject.hop_on(subject.port, AuthMethod::Interactive);
    hop.keepalive_every = Duration::from_secs(1);
    let auth = VaultAuth::new().with_answers(&[&subject.password]).with_answer_delay(Duration::from_millis(3500));
    std::thread::scope(|scope| {
        let login = scope.spawn(|| engine().connect(&Target { hops: vec![hop] }, &*TestPolicy::trusting(), &auth).map(|session| session.is_alive()));
        std::thread::sleep(Duration::from_millis(1000));
        let before = cpu_time_ms();
        std::thread::sleep(Duration::from_millis(2000));
        fact("prompt_wait.cpu_ms", cpu_time_ms() - before);
        assert!(login.join().unwrap().expect("the login succeeded in the end"));
    });
}

// ---------------------------------------------------------------------------------------------------------------------------------

macro_rules! login_tests {
    ($server:ident) => {
        mod $server {
            use super::*;

            #[test]
            fn a_password_login_succeeds() {
                let Some(subject) = $server() else { return };
                password_login_succeeds(&subject);
            }

            #[test]
            fn a_wrong_password_is_refused_and_keyboard_interactive_is_tried_next() {
                let Some(subject) = $server() else { return };
                super::a_wrong_password_is_refused_and_keyboard_interactive_is_tried_next(&subject);
            }

            #[test]
            fn a_keyboard_interactive_login_succeeds() {
                let Some(subject) = $server() else { return };
                keyboard_interactive_login_succeeds(&subject);
            }

            #[test]
            fn a_refused_key_falls_back_to_the_password() {
                let Some(subject) = $server() else { return };
                super::a_refused_key_falls_back_to_the_password(&subject);
            }

            #[test]
            fn a_cancelled_prompt_abandons_the_login_and_drops_the_connection() {
                let Some(subject) = $server() else { return };
                super::a_cancelled_prompt_abandons_the_login_and_drops_the_connection(&subject);
            }

            #[test]
            fn a_prompt_that_runs_out_of_time_abandons_the_login_and_drops_the_connection() {
                let Some(subject) = $server() else { return };
                super::a_prompt_that_runs_out_of_time_abandons_the_login_and_drops_the_connection(&subject);
            }

            #[cfg(unix)]
            #[test]
            fn waiting_for_a_prompt_costs_no_cpu() {
                let Some(subject) = $server() else { return };
                super::waiting_for_a_prompt_costs_no_cpu(&subject, concat!("ssh::engine_tests::login_methods::", stringify!($server), "::waiting_for_a_prompt_costs_no_cpu"));
            }
        }
    };
}

login_tests!(toy);
login_tests!(pam);

#[test]
fn a_closed_session_after_a_login_says_so() {
    let Some(subject) = toy() else { return };
    let auth = VaultAuth::new().with_password(&subject.password);
    let session = open_session_to(&engine(), &subject.target_on(subject.port, AuthMethod::Password), &auth);
    session.close();
    assert_eq!(session.exec("echo no", Duration::from_secs(5), MIB), Err(SessionError::Closed));
}
```

`src-tauri/src/ssh/russh_engine.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/russh_engine.rs
+++ b/src-tauri/src/ssh/russh_engine.rs
@@ -852,13 +852,129 @@ async fn read_shell(mut read_half: ChannelReadHalf, write_half: Arc<ChannelWrite
     queue.close();
 }
 
+#[cfg(test)]
+pub(crate) mod toy_server {
+    use std::borrow::Cow;
+    use std::sync::Arc;
+
+    use russh::keys::PrivateKey;
+    use russh::server::{self, Auth, Config, Msg, Response, Server as _, Session};
+    use russh::{Channel, ChannelId, MethodKind, MethodSet};
+    use tokio::net::TcpListener;
+
+    use crate::sync::slot_rules::test_keys;
+
+    /// Who may log in, and what the server asks in keyboard-interactive.
+    #[derive(Clone)]
+    pub(crate) struct ToyLogin {
+        pub user: String,
+        pub password: String,
+        pub prompt: String,
+    }
+
+    /// The server's side of one client.
+    struct Toy {
+        login: Arc<ToyLogin>,
+    }
+
+    impl server::Handler for Toy {
+        type Error = russh::Error;
+
+        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
+            Ok(if user == self.login.user && password == self.login.password { Auth::Accept } else { Auth::reject() })
+        }
+
+        /// A single round: the prompt, then the answer is compared with the password.
+        async fn auth_keyboard_interactive<'a>(&'a mut self, user: &str, _submethods: &str, response: Option<Response<'a>>) -> Result<Auth, Self::Error> {
+            match response {
+                None => Ok(Auth::Partial {
+                    name: Cow::Borrowed(""),
+                    instructions: Cow::Borrowed(""),
+                    prompts: Cow::Owned(vec![(Cow::Owned(self.login.prompt.clone()), false)]),
+                }),
+                Some(mut response) => {
+                    let answer = response.next();
+                    let right = answer.is_some_and(|answer| answer[..] == *self.login.password.as_bytes());
+                    Ok(if user == self.login.user && right { Auth::Accept } else { Auth::reject() })
+                }
+            }
+        }
+
+        async fn auth_publickey_offered(&mut self, _user: &str, _key: &russh::keys::PublicKey) -> Result<Auth, Self::Error> {
+            Ok(Auth::reject())
+        }
+
+        async fn channel_open_session(&mut self, _channel: Channel<Msg>, reply: server::ChannelOpenHandle, _session: &mut Session) -> Result<(), Self::Error> {
+            reply.accept().await;
+            Ok(())
+        }
+
+        /// Whatever the command, it prints `ok` and exits 0.
+        async fn exec_request(&mut self, channel: ChannelId, _command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
+            session.channel_success(channel)?;
+            session.data(channel, b"ok\n".to_vec())?;
+            session.exit_status_request(channel, 0)?;
+            session.eof(channel)?;
+            session.close(channel)?;
+            Ok(())
+        }
+    }
+
+    struct Factory {
+        login: Arc<ToyLogin>,
+    }
+
+    impl server::Server for Factory {
+        type Handler = Toy;
+
+        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Toy {
+            Toy { login: Arc::clone(&self.login) }
+        }
+    }
+
+    /// The running server. Dropping it stops it.
+    pub(crate) struct ToyServer {
+        pub port: u16,
+        runtime: Option<tokio::runtime::Runtime>,
+    }
+
+    impl ToyServer {
+        pub(crate) fn start(login: ToyLogin) -> ToyServer {
+            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("the toy server's runtime");
+            let listener = runtime.block_on(TcpListener::bind(("127.0.0.1", 0))).expect("bind the toy server");
+            let port = listener.local_addr().expect("the toy server's address").port();
+            let host_key = PrivateKey::from_openssh(&test_keys::plain()).expect("the test key is an OpenSSH private key");
+            let config = Config {
+                methods: MethodSet::from(&[MethodKind::PublicKey, MethodKind::Password, MethodKind::KeyboardInteractive][..]),
+                auth_rejection_time: std::time::Duration::from_millis(10),
+                auth_rejection_time_initial: Some(std::time::Duration::ZERO),
+                keys: vec![host_key],
+                ..Config::default()
+            };
+            let mut factory = Factory { login: Arc::new(login) };
+            runtime.spawn(async move {
+                let _ = factory.run_on_socket(Arc::new(config), &listener).await;
+            });
+            ToyServer { port, runtime: Some(runtime) }
+        }
+    }
+
+    impl Drop for ToyServer {
+        fn drop(&mut self) {
+            if let Some(runtime) = self.runtime.take() {
+                runtime.shutdown_background();
+            }
+        }
+    }
+}
+
 #[cfg(test)]
 mod tests {
     use russh::keys::EcdsaCurve;
     use russh::Signer;
 
     use super::*;
-    use crate::ssh::{AuthError, Prompt, Secret, Signature};
+    use crate::ssh::{AuthError, Signature};
     use crate::sync::slot_rules::test_keys;
 
     #[test]
@@ -910,6 +1026,16 @@ mod tests {
         assert_eq!(choose_rsa_hash(None), RsaChoice::Use(HashAlg::Sha256), "a server that never announced its algorithms is tried with SHA-256");
     }
 
+    #[test]
+    fn a_keyboard_interactive_answer_gets_four_connect_timeouts_and_at_least_a_minute() {
+        let options = EngineOptions::default();
+        assert_eq!(options.prompt_wait_for(Duration::from_secs(15)), Duration::from_secs(60));
+        assert_eq!(options.prompt_wait_for(Duration::from_secs(30)), Duration::from_secs(120));
+        assert_eq!(options.prompt_wait_for(Duration::from_secs(5)), Duration::from_secs(60));
+        let short = EngineOptions { prompt_wait: Some(Duration::from_secs(2)), ..EngineOptions::default() };
+        assert_eq!(short.prompt_wait_for(Duration::from_secs(15)), Duration::from_secs(2));
+    }
+
     /// Counts the calls to `sign` and the hash each one got.
     #[derive(Default)]
     struct Counting {
```

- [ ] **Step 2: Run them to see them fail**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: FAIL, the crate does not compile. The first error is `error[E0425]: cannot find type `Secret` in this scope`, and the run ends with `error: could not compile `sshelter` (lib test) due to 9 previous errors` (the number of errors depends on the compiler; what matters is that the errors name items that do not exist yet). The errors are about `Secret` and `Prompt` (imports the implementation adds), `EngineOptions` having no field `prompt_wait` and no method `prompt_wait_for` (the new option and its helper).

- [ ] **Step 3: Write the implementation**

`src-tauri/src/ssh/russh_engine.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/russh_engine.rs
+++ b/src-tauri/src/ssh/russh_engine.rs
@@ -14,7 +14,7 @@ use std::sync::atomic::{AtomicBool, Ordering};
 use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
 use std::time::Duration;
 
-use russh::client::{self, AuthResult, Config, Handle, Handler, Msg};
+use russh::client::{self, AuthResult, Config, Handle, Handler, KeyboardInteractiveAuthResponse, Msg};
 use russh::client::DisconnectReason as RusshDisconnect;
 use russh::keys::agent::AgentIdentity;
 use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
@@ -28,7 +28,7 @@ use super::channel::{ByteQueue, ExitCell, QueuedShell, ShellInput};
 use super::error::{AuthError, ConnectError, SessionError};
 use super::traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
 use super::types::{
-    AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostKey, HostKeyVerdict, Phase, Pty, RsaHash, Target,
+    AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostKey, HostKeyVerdict, Phase, Prompt, Pty, RsaHash, Secret, Target,
 };
 
 fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
@@ -40,13 +40,22 @@ fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
 pub struct EngineOptions {
     /// Bytes of shell output kept between the channel reader and the thread that reads the shell (see `ByteQueue`).
     pub shell_queue_bytes: usize,
+    /// How long one keyboard-interactive answer may take. `None` = 4 × the hop's connect timeout, at least 60 s (spec §6.2 step 4).
+    pub prompt_wait: Option<Duration>,
     /// Worker threads of the engine's runtime.
     pub worker_threads: usize,
 }
 
 impl Default for EngineOptions {
     fn default() -> Self {
-        EngineOptions { shell_queue_bytes: 4 * 1024 * 1024, worker_threads: 2 }
+        EngineOptions { shell_queue_bytes: 4 * 1024 * 1024, prompt_wait: None, worker_threads: 2 }
+    }
+}
+
+impl EngineOptions {
+    /// The time a person gets to answer one keyboard-interactive round.
+    fn prompt_wait_for(&self, connect_timeout: Duration) -> Duration {
+        self.prompt_wait.unwrap_or_else(|| (connect_timeout * 4).max(Duration::from_secs(60)))
     }
 }
 
@@ -102,7 +111,7 @@ impl RusshEngine {
     /// Connects every hop of `target` and logs in to each; the connection-level half of `SshEngine::connect`. Blocks the calling thread
     /// (never call it from inside an async task).
     pub fn connect_chain(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
-        self.runtime.handle().block_on(connect_chain(target, host_keys, auth))
+        self.runtime.handle().block_on(connect_chain(target, host_keys, auth, &self.options))
     }
 }
 
@@ -307,11 +316,11 @@ impl Connection {
     }
 }
 
-async fn connect_chain(target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
+async fn connect_chain(target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource, options: &EngineOptions) -> Result<Connection, ConnectError> {
     check_chain(target)?;
     let mut connection = Connection::new();
     for hop in &target.hops {
-        match connect_one(hop, connection.hops.last(), host_keys, auth).await {
+        match connect_one(hop, connection.hops.last(), host_keys, auth, options).await {
             Ok(established) => connection.hops.push(established),
             Err(error) => {
                 connection.disconnect_all().await;
@@ -335,13 +344,25 @@ fn check_chain(target: &Target) -> Result<(), ConnectError> {
     Ok(())
 }
 
-async fn connect_one(hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Established, ConnectError> {
+async fn connect_one(
+    hop: &Hop,
+    via: Option<&Established>,
+    host_keys: &dyn HostKeyPolicy,
+    auth: &dyn AuthSource,
+    options: &EngineOptions,
+) -> Result<Established, ConnectError> {
     let reference = hop.reference();
+    // A hop that starts with the password method asks for it before anything is connected: a person typing must not keep an
+    // unauthenticated connection waiting (the server's login grace time runs, and russh spins while it idles).
+    let password = (hop.auth == AuthMethod::Password).then(|| auth.password(&reference));
     let (mut handle, shared) = connect_hop(hop, via, host_keys).await?;
-    authenticate(hop, &mut handle, auth).await?;
+    authenticate(hop, &mut handle, auth, password, options).await?;
     Ok(Established { hop: reference, handle, shared })
 }
 
+/// Connects one hop: over TCP for the first, through a direct-tcpip channel of the hop in front of it for every later one (the way
+/// OpenSSH's ProxyJump does), and runs the handshake with the host key check. TCP (or the tunnel) plus handshake share the hop's
+/// connect timeout.
 async fn connect_hop(hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy) -> Result<(Handle<EngineHandler>, Arc<HopShared>), ConnectError> {
     let reference = hop.reference();
     let shared = HopShared::new();
@@ -513,12 +534,13 @@ enum Step {
 /// it; a refusal moves to the next method on the same connection. A method that cannot be tried here is skipped, and then the server is
 /// asked once what it does offer (`none`), so later methods are not sent blindly. Anything that is our fault (the signer failed, a
 /// prompt was cancelled or ran late) or the server's silence abandons the login: the caller drops the connection (spec §6.2 step 4).
-async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, auth: &dyn AuthSource) -> Result<(), ConnectError> {
+async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, auth: &dyn AuthSource, mut prefetched_password: Option<Option<Secret>>, options: &EngineOptions) -> Result<(), ConnectError> {
     let reference = hop.reference();
     let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
     let timed_out = || ConnectError::Timeout { hop: reference.clone(), phase: Phase::Auth };
     let lost = |_: russh::Error| ConnectError::Unreachable { hop: reference.clone(), reason: "the connection was lost during login".to_string() };
     let call_limit = hop.connect_timeout.max(Duration::from_secs(1));
+    let prompt_wait = options.prompt_wait_for(hop.connect_timeout);
     let user = hop.user.as_str();
     let mut tried: Vec<AuthMethod> = Vec::new();
     let mut reasons: Vec<String> = Vec::new();
@@ -562,8 +584,53 @@ async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, auth: &dyn
                     Ok(Ok(AuthResult::Failure { remaining_methods, .. })) => Step::Refused(remaining_methods),
                 }
             }
-            // Password and keyboard-interactive logins come in Task 11; until then these methods are skipped like any method with nothing to offer.
-            AuthMethod::Password | AuthMethod::Interactive => Step::Skipped,
+            AuthMethod::Password => 'password: {
+                let password = match prefetched_password.take() {
+                    Some(answer) => answer,
+                    None => auth.password(&reference),
+                };
+                let Some(password) = password else { break 'password Step::Skipped };
+                tried.push(method.clone());
+                match tokio::time::timeout(call_limit, handle.authenticate_password(user, password.as_str())).await {
+                    Err(_) => return Err(timed_out()),
+                    Ok(Err(error)) => return Err(lost(error)),
+                    Ok(Ok(AuthResult::Success)) => return Ok(()),
+                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) => Step::Refused(remaining_methods),
+                }
+            }
+            AuthMethod::Interactive => {
+                tried.push(method.clone());
+                let mut response = tokio::time::timeout(call_limit, handle.authenticate_keyboard_interactive_start(user, None::<String>))
+                    .await
+                    .map_err(|_| timed_out())?
+                    .map_err(lost)?;
+                loop {
+                    match response {
+                        KeyboardInteractiveAuthResponse::Success => return Ok(()),
+                        KeyboardInteractiveAuthResponse::Failure { remaining_methods, .. } => break Step::Refused(remaining_methods),
+                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
+                            let answers = if prompts.is_empty() {
+                                Vec::new()
+                            } else {
+                                let prompts: Vec<Prompt> = prompts.into_iter().map(|prompt| Prompt { text: prompt.prompt, echo: prompt.echo }).collect();
+                                let deadline = std::time::Instant::now() + prompt_wait;
+                                let Some(answers) = auth.interactive(&reference, &prompts, deadline) else { return Err(abandoned("the prompt was cancelled")) };
+                                if std::time::Instant::now() > deadline {
+                                    return Err(abandoned("the prompt was answered after its deadline"));
+                                }
+                                if answers.len() != prompts.len() {
+                                    return Err(abandoned("the answers do not match the prompts"));
+                                }
+                                answers.iter().map(|answer| answer.to_string()).collect()
+                            };
+                            response = tokio::time::timeout(prompt_wait, handle.authenticate_keyboard_interactive_respond(answers))
+                                .await
+                                .map_err(|_| timed_out())?
+                                .map_err(lost)?;
+                        }
+                    }
+                }
+            }
         };
         match step {
             Step::Refused(remaining) => offered = Some(remaining),
@@ -852,6 +919,9 @@ async fn read_shell(mut read_half: ChannelReadHalf, write_half: Arc<ChannelWrite
     queue.close();
 }
 
+/// A small SSH server in process, on russh's own server side, for the logins that a scratch OpenSSH cannot do because it has no PAM:
+/// password and keyboard-interactive. It is a test fixture, not a model of any real server; the PAM job of the CI runs the same login
+/// tests against OpenSSH. It lives in this file because russh is named here and nowhere else (the test in `ssh/mod.rs`).
 #[cfg(test)]
 pub(crate) mod toy_server {
     use std::borrow::Cow;
```

- [ ] **Step 4: Run them to see them pass**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 127 passed; 0 failed`. The run takes about 20 s on this machine (18 cores).

- [ ] **Step 5: Run the whole lib suite**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1544 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. The suite takes about 108 s. The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/engine_tests/connect.rs src-tauri/src/ssh/engine_tests/login_methods.rs src-tauri/src/ssh/engine_tests/mod.rs src-tauri/src/ssh/russh_engine.rs
git commit -m "test(ssh): log in with passwords and keyboard-interactive against an in-process server"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

---

### Task 12: CI on macOS and Linux, with OpenSSH and PAM in a container

**Files:**
- Create: `.github/workflows/test-engine.yml`
- Create: `src-tauri/tests/pam-sshd/Dockerfile`
- Create: `src-tauri/tests/pam-sshd/sshd_config.test`

**Interfaces:**
- Consumes: Task 11's tests `ssh::engine_tests::login_methods::pam::*` and the variables they read (`SSHELTER_PAM_PORT`, `SSHELTER_PAM_USER`, `SSHELTER_PAM_PASSWORD`, `SSHELTER_REQUIRE_PAM`); Task 5's `SSHELTER_REQUIRE_OPENSSH`.
- Produces: the workflow `ssh engine` (file `test-engine.yml`) with the jobs `macos` and `linux`; the image `sshelter-pam-sshd` (user `sshelter`, password given as the build argument `TEST_PASSWORD`, sshd on port 22 of the container, published on `127.0.0.1:2222` by the workflow).

What shapes this task:
- **There is no workflow that runs the Rust tests on macOS or on Linux today** (`test-windows.yml` is the only one that runs `cargo test`; the release workflows build the app). Spec §12 asks for both. `test-engine.yml` runs the engine tests and `vault::` (the vault under `zeroize` 1.9.1 is the reason `vault::` is in the filter) on `macos-latest` and `ubuntu-latest`, and on Linux also the `pam` login tests against a real OpenSSH with PAM in a container. It triggers on pushes to `main` and `next/own-ssh` (the branch can be removed from the list when it is merged), on pull requests and by hand.
- **What `aws-lc-sys` needs on each runner: nothing installed.** russh's crypto is `aws-lc-rs`, the same crate and version (1.18.1, with `aws-lc-sys` 0.45.0) that rustls already pulls in for the updater, and the release workflow already builds it on macOS, Linux and Windows. Its build script uses the runner's C compiler (clang on macOS, gcc on `ubuntu-latest`). So the only apt packages are the ones `release.yml` installs to build the app on Linux, plus `openssh-server` for `/usr/sbin/sshd`.
- **The PAM container.** A scratch sshd cannot check a password (no PAM without root), so the password and keyboard-interactive tests also run against `tests/pam-sshd`: Ubuntu 24.04, `openssh-server`, a user `sshelter` whose password is the build argument, and `sshd_config.test` dropped into `/etc/ssh/sshd_config.d/00-sshelter-test.conf` with `UsePAM yes`, `PasswordAuthentication yes`, `KbdInteractiveAuthentication yes`. sshd keeps the **first** value it reads for a keyword and Ubuntu includes that directory before its own lines, so these lines win over Ubuntu's `KbdInteractiveAuthentication no`. Docker's default capabilities do not let `pam_loginuid` write `/proc/self/loginuid`, and as `required` it ends every session right after the login, so the image makes it `optional`. The password is random per run (`openssl rand -hex 16`), masked in the log with `::add-mask::`, and passed on through `GITHUB_ENV`; BuildKit's check about secrets in `ARG` is switched off in the Dockerfile for that reason (a throwaway test credential). The port is published on loopback only.
- **Gotcha already handled:** an unquoted `cargo test … -- ssh:: vault::` as a YAML `run:` value is read as a mapping and the workflow does not load, so the commands are quoted (actionlint says so).
- **What this task cannot check on this machine:** the Linux job (the scratch sshd as a non-root Linux user, `/usr/sbin/sshd` from the apt package), building the image (it needs the network and an Ubuntu base image) and starting it, and PAM's real behaviour. Steps 3 and 4 check the files for syntax; the first run on GitHub is the test. If the scratch-sshd tests fail only there, the harness says why in the failure message (`sshd -t rejected the config:` with sshd's own words, or `sshd did not come up on port … ; its log:`).

- [ ] **Step 1: Create the container files**

`src-tauri/tests/pam-sshd/Dockerfile`: create

```dockerfile
# check=skip=SecretsUsedInArgOrEnv
# A real OpenSSH server with PAM, for the password and keyboard-interactive tests of the SSH engine (own-ssh spec §12). A scratch sshd
# started by a test cannot check passwords (no PAM without root), so those logins are tested against this.
#
#   docker build --build-arg TEST_PASSWORD='choose-something' -t sshelter-pam-sshd src-tauri/tests/pam-sshd
#   docker run -d --name sshelter-pam-sshd -p 127.0.0.1:2222:22 sshelter-pam-sshd
#   SSHELTER_PAM_PORT=2222 SSHELTER_PAM_USER=sshelter SSHELTER_PAM_PASSWORD='choose-something' \
#     cargo test --locked --lib -- ssh::engine_tests::login_methods::pam        (from src-tauri/)
#   docker rm -f sshelter-pam-sshd
#
# Throwaway: the user's password is whatever you pass at build time (so the BuildKit check about secrets in ARG is switched off above),
# the port is published on localhost only, and the image is not meant for anything else.
FROM ubuntu:24.04
ARG TEST_USER=sshelter
ARG TEST_PASSWORD
RUN test -n "$TEST_PASSWORD" || { echo "pass --build-arg TEST_PASSWORD=<a password for the test user>" >&2; exit 1; }
# Docker's default capabilities do not let pam_loginuid write /proc/self/loginuid; as `required` it ends every session right after the
# login, so it is made optional.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd --create-home --shell /bin/bash "$TEST_USER" \
 && echo "$TEST_USER:$TEST_PASSWORD" | chpasswd \
 && sed -i 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@' /etc/pam.d/sshd
COPY sshd_config.test /etc/ssh/sshd_config.d/00-sshelter-test.conf
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
```

`src-tauri/tests/pam-sshd/sshd_config.test`: create

```
# Dropped into /etc/ssh/sshd_config.d/ of the test image. sshd keeps the FIRST value of a keyword and the distribution's sshd_config
# reads this directory before its own lines, so these win over its defaults (Ubuntu ships `KbdInteractiveAuthentication no`).
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
LogLevel VERBOSE
```

- [ ] **Step 2: Create the workflow**

`.github/workflows/test-engine.yml`: create

```yaml
# Runs the tests of the SSH engine (src-tauri/src/ssh/) where they can run for real: against a scratch OpenSSH server on macOS and on
# Linux, and on Linux also against a real OpenSSH with PAM in a container (the logins by password and by keyboard-interactive, which a
# scratch sshd cannot check). The Windows leg lives in test-windows.yml.
#
# aws-lc-sys (russh's crypto, the same crate rustls already pulls in for the updater) is built by its build script with the runner's C
# compiler: clang on macOS, gcc on ubuntu-latest. The release workflow already builds it on both through rustls, so nothing is installed
# for it here.
name: ssh engine

on:
  push:
    branches: [main, next/own-ssh]
    paths: ["src-tauri/**", ".github/workflows/test-engine.yml"]
  pull_request:
    paths: ["src-tauri/**", ".github/workflows/test-engine.yml"]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  macos:
    runs-on: macos-latest
    timeout-minutes: 45
    defaults:
      run:
        working-directory: src-tauri
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: "./src-tauri -> target"
      # tauri::generate_context! reads frontendDist (../dist) at compile time and fails when it is missing.
      # This job only runs Rust tests, so a placeholder page is enough.
      - name: Placeholder frontend
        run: |
          mkdir -p ../dist
          echo '<!doctype html>' > ../dist/index.html
      # Which OpenSSH the scratch servers will be. Never fails the job.
      - name: OpenSSH on the runner
        continue-on-error: true
        run: |
          ls -l /usr/sbin/sshd
          ssh -V
      # SSHELTER_REQUIRE_OPENSSH=1: a missing sshd is a failure here, not a skipped test.
      - name: Engine and vault tests
        env:
          SSHELTER_REQUIRE_OPENSSH: "1"
        # Quoted: an unquoted `ssh::` is read as a YAML mapping and the workflow would not load.
        run: "cargo test --locked --lib -- ssh:: vault::"

  linux:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    defaults:
      run:
        working-directory: src-tauri
    steps:
      - uses: actions/checkout@v4
      # The packages release.yml installs to build the app on Linux, and openssh-server for the scratch sshd (/usr/sbin/sshd).
      - name: Install system packages
        working-directory: .
        run: |
          sudo apt-get update
          sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf xdg-utils openssh-server
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
        with:
          workspaces: "./src-tauri -> target"
      - name: Placeholder frontend
        run: |
          mkdir -p ../dist
          echo '<!doctype html>' > ../dist/index.html
      - name: OpenSSH on the runner
        continue-on-error: true
        run: |
          ls -l /usr/sbin/sshd
          ssh -V
      # The pam tests are skipped here: the next steps run them against the container.
      - name: Engine and vault tests against a scratch sshd
        env:
          SSHELTER_REQUIRE_OPENSSH: "1"
        # Quoted: an unquoted `ssh::` is read as a YAML mapping and the workflow would not load.
        run: "cargo test --locked --lib -- ssh:: vault:: --skip ssh::engine_tests::login_methods::pam"
      # A random password for the test user, masked in the log, passed to the tests through the environment of the later steps.
      - name: Start OpenSSH with PAM in a container
        run: |
          password="$(openssl rand -hex 16)"
          echo "::add-mask::$password"
          docker build --build-arg TEST_PASSWORD="$password" -t sshelter-pam-sshd tests/pam-sshd
          docker run -d --name sshelter-pam-sshd -p 127.0.0.1:2222:22 sshelter-pam-sshd
          for _ in $(seq 1 30); do
            ssh-keyscan -T 2 -p 2222 127.0.0.1 > /dev/null 2>&1 && break
            sleep 1
          done
          ssh-keyscan -T 2 -p 2222 127.0.0.1 > /dev/null
          echo "SSHELTER_PAM_PASSWORD=$password" >> "$GITHUB_ENV"
      - name: Password and keyboard-interactive tests against the container
        env:
          SSHELTER_REQUIRE_OPENSSH: "1"
          SSHELTER_REQUIRE_PAM: "1"
          SSHELTER_PAM_PORT: "2222"
          SSHELTER_PAM_USER: sshelter
        # Quoted: an unquoted `ssh::` is read as a YAML mapping and the workflow would not load.
        run: "cargo test --locked --lib -- ssh::engine_tests::login_methods::pam"
      - name: What the container logged
        if: failure()
        run: docker logs sshelter-pam-sshd || true
```

- [ ] **Step 3: Check the container files**

```bash
cd src-tauri/tests/pam-sshd && docker build --check --build-arg TEST_PASSWORD=x .
```

Expected: BuildKit's lint pass ends with `Check complete, no warnings found.` (this parses and lints the Dockerfile and builds nothing). Without Docker on the machine, skip this step and say so when reporting the task.

- [ ] **Step 4: Check the workflow**

```bash
actionlint -color .github/workflows/test-engine.yml; echo "actionlint exit: $?"
```

Expected: no findings and `actionlint exit: 0` (actionlint 1.7.12 is installed on this machine; the image `rhysd/actionlint:1.7.12` is the same tool). If neither is available, pulling the image downloads: ask the user first.

- [ ] **Step 5: Run the macOS job's command here**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh:: vault::
```

Expected: `test result: ok. 182 passed; 0 failed`. That is the command the `macos` job runs (here with `--offline` as everywhere on this machine); it must pass here before it is asked of the runner.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add .github/workflows/test-engine.yml src-tauri/tests/pam-sshd/Dockerfile src-tauri/tests/pam-sshd/sshd_config.test
git commit -m "ci(ssh): run the engine tests on macOS and Linux, with OpenSSH+PAM in a container"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

- [ ] **Step 7: First run on GitHub (the user's step, after pushing)**

The implementer stops at the commit. After the branch is pushed, the user opens the run of `ssh engine` and checks, in this order: (1) `macos`: the step `OpenSSH on the runner` shows `/usr/sbin/sshd` and `ssh -V`, and the tests pass; (2) `linux`: the install step, then the scratch-sshd tests (the first thing that can differ from this Mac is a non-root sshd, see above), then `Start OpenSSH with PAM in a container` (the image builds, `ssh-keyscan` finds the port) and `Password and keyboard-interactive tests against the container`, which must report the 7 `pam::` tests passed; (3) if a `pam` test fails, the last step prints `docker logs sshelter-pam-sshd`. Record what the runs showed in the pull request.

---

### Task 13: Windows CI: build the app with russh and run the engine against the runner's OpenSSH

**Files:**
- Modify: `.github/workflows/test-windows.yml`
- Create (tests): `src-tauri/src/ssh/engine_tests/environment.rs` (the engine against the server the environment describes)
- Modify: `src-tauri/src/ssh/engine_tests/mod.rs`

**Interfaces:**
- Consumes: Task 7's `engine()` (in `engine_tests/mod.rs`); Task 6's `TestPolicy::trusting()` and `VaultAuth::with_key(self, key_id: &str, private_text: &str)`; Task 11's engine.
- Produces: the test `ssh::engine_tests::environment::connect_log_in_and_exec_against_the_server_in_the_environment`, which reads `SSHELTER_TEST_SSH_PORT`, `SSHELTER_TEST_SSH_USER` and `SSHELTER_TEST_SSH_KEY` (a passphrase-less OpenSSH private key) and prints `skipped` and passes when they are not all set; and the Windows job's new steps (build the whole app, install and start the OpenSSH server, authorize a throwaway key, run the test against it).

What shapes this task:
- **Why this test exists.** On Windows a scratch sshd cannot run (Win32-OpenSSH's `sshd` must run as a service), so the engine tests that start one print `skipped` there. The Windows job instead starts the **runner's own** OpenSSH server, authorizes a throwaway key and runs this one test against it: connect, log in with the vault key, `exec`. It is the same test body everywhere; the phase-0 spike's `spike-windows.yml` proved the setup (its PowerShell is ported here) and Task 14 deletes it.
- **What the test also proves.** `exec` returns raw bytes, and Windows OpenSSH ends the line of `echo` with CRLF (spec §6.3): the assertion is `contains("sshelter-engine-ok")`, never equality with a `\n`-terminated string. It also checks that a remote `exit 3` comes back as exit code 3.
- **The app is built with russh on Windows for the first time.** The spike only built its own crate (without the app library), and `aws-lc-sys` needs the Windows SDK headers, so the app's Windows build cannot be checked from this Mac. The job's `cargo build --locked` step is that check. It needs nothing installed for `aws-lc-sys`: the release job already builds the same crate on this runner image through rustls and installs nothing for it.
- **Not a TDD cycle.** The test has no production code to drive: the engine exists since Task 11. Step 2 runs it here against a sshd started by hand, which is what the Windows job does with the runner's server, so a typo in the test is found on this Mac and not on Windows. What the task adds is the Windows leg, which can only be checked on GitHub.
- The `on:` block of `test-windows.yml` is unchanged: it runs on pushes to `main`, on pull requests that touch `src-tauri/**` and by hand (`workflow_dispatch`), so the work branch gets a Windows run through a pull request or by hand.

- [ ] **Step 1: Write the test**

`src-tauri/src/ssh/engine_tests/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/engine_tests/mod.rs
+++ b/src-tauri/src/ssh/engine_tests/mod.rs
@@ -2,6 +2,7 @@
 //! returns early, printing "skipped", where the OpenSSH tools are missing (`SSHELTER_REQUIRE_OPENSSH=1` turns that into a failure).
 
 mod connect;
+mod environment;
 mod exec;
 mod jump;
 mod liveness;
```

`src-tauri/src/ssh/engine_tests/environment.rs`: create

```rust
//! The engine against the OpenSSH server that the environment describes: on Windows, the runner's own server, which test-windows.yml
//! starts and authorizes a throwaway key on (a scratch sshd cannot run there). The test is the same everywhere. Without
//! `SSHELTER_TEST_SSH_PORT`, `SSHELTER_TEST_SSH_USER` and `SSHELTER_TEST_SSH_KEY` (a passphrase-less OpenSSH private key) it prints
//! "skipped" and passes.

use std::time::Duration;

use super::engine;
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::fact;
use crate::ssh::{AuthMethod, Ended, Hop, SshEngine, Target};

#[test]
fn connect_log_in_and_exec_against_the_server_in_the_environment() {
    let (Ok(port), Ok(user), Ok(key_path)) = (
        std::env::var("SSHELTER_TEST_SSH_PORT"),
        std::env::var("SSHELTER_TEST_SSH_USER"),
        std::env::var("SSHELTER_TEST_SSH_KEY"),
    ) else {
        eprintln!("skipped: SSHELTER_TEST_SSH_PORT, SSHELTER_TEST_SSH_USER and SSHELTER_TEST_SSH_KEY are not all set");
        return;
    };
    let private_key = std::fs::read_to_string(&key_path).unwrap_or_else(|error| panic!("cannot read {key_path}: {error}"));
    let auth = VaultAuth::new().with_key("k1", &private_key);
    let policy = TestPolicy::trusting();
    let hop = Hop::new("host-env", "env", "127.0.0.1", port.parse().expect("SSHELTER_TEST_SSH_PORT is a port number"), &user, AuthMethod::Key { key_id: "k1".into() });

    let session = engine().connect(&Target { hops: vec![hop] }, &*policy, &auth).expect("the engine connects and logs in");
    if let Some((_, key)) = policy.seen().first() {
        fact("environment.host_key", format!("{} {}", key.algorithm, key.fingerprint));
    }

    // The output is raw bytes: Windows OpenSSH ends a line with CRLF, a Unix sshd with LF.
    let hello = session.exec("echo sshelter-engine-ok", Duration::from_secs(60), 1 << 20).expect("exec");
    fact("environment.echo_stdout", format!("{:?}", String::from_utf8_lossy(&hello.stdout)));
    assert!(String::from_utf8_lossy(&hello.stdout).contains("sshelter-engine-ok"), "stdout was {:?}", hello.stdout);
    assert_eq!((hello.ended, hello.exit_code), (Ended::Exited, Some(0)));

    let exit = session.exec("exit 3", Duration::from_secs(60), 1 << 20).expect("exec");
    assert_eq!((exit.ended, exit.exit_code), (Ended::Exited, Some(3)), "the remote exit code must come back through the server too");
    assert!(session.is_alive());
}
```

- [ ] **Step 2: Run it against a scratch sshd you start by hand**

The script starts a throwaway sshd on a free port with a fresh key (the same recipe as the harness, in shell), runs the test with the three variables set, and removes everything. Run it from anywhere inside the repository.

```bash
cat > "${TMPDIR:-/tmp}/engine-env.sh" <<'SCRIPT'
set -e
ROOT=$(git rev-parse --show-toplevel)
D=$(mktemp -d "${TMPDIR:-/tmp}/engine-env.XXXXXX")
trap 'kill $SSHD 2>/dev/null; rm -rf "$D"' EXIT
ssh-keygen -q -t ed25519 -N '' -f "$D/hostkey"
ssh-keygen -q -t ed25519 -N '' -C engine-env -f "$D/userkey"
cp "$D/userkey.pub" "$D/authorized_keys"
chmod 600 "$D/authorized_keys"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
cat > "$D/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $D/hostkey
PidFile none
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile $D/authorized_keys
StrictModes no
PermitUserRC no
LogLevel ERROR
EOF
/usr/sbin/sshd -D -e -f "$D/sshd_config" 2> "$D/sshd.log" &
SSHD=$!
sleep 1.5
cd "$ROOT/src-tauri"
SSHELTER_TEST_SSH_PORT=$PORT SSHELTER_TEST_SSH_USER=$(id -un) SSHELTER_TEST_SSH_KEY=$D/userkey \
  PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH \
  cargo test --offline --locked --lib -- ssh::engine_tests::environment --nocapture 2>&1 | grep -E "^running|FACT|test result|panicked|skipped" || true
SCRIPT
bash "${TMPDIR:-/tmp}/engine-env.sh"
rm -f "${TMPDIR:-/tmp}/engine-env.sh"
```

Expected:

```
running 1 test
FACT environment.host_key = ssh-ed25519 SHA256:<fingerprint of the throwaway host key>
FACT environment.echo_stdout = "sshelter-engine-ok\n"
test result: ok. 1 passed; 0 failed; …
```

Before Step 1 the same script prints `running 0 tests`: the test did not exist. The `FACT` lines show what came back through the engine; on Windows the second one ends in `\r\n`.

- [ ] **Step 3: See that it skips without the variables**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::engine_tests::environment --nocapture
```

Expected: `test result: ok. 1 passed; 0 failed`, with `skipped: SSHELTER_TEST_SSH_PORT, SSHELTER_TEST_SSH_USER and SSHELTER_TEST_SSH_KEY are not all set` on stderr.

- [ ] **Step 4: Extend the Windows workflow**

`.github/workflows/test-windows.yml`: apply this patch

```diff
--- a/.github/workflows/test-windows.yml
+++ b/.github/workflows/test-windows.yml
@@ -2,6 +2,11 @@
 # vault and SSH agent tests (the agent's named pipe and its owner-only DACL, Windows program identification, and the real
 # Win32-OpenSSH tools against the agent). The copy fallback (used when a hard link can't be made, for example across
 # drives) is not exercised on CI.
+# It also builds the whole app with russh (cargo build --locked) and runs the SSH engine (src/ssh/): the tests that need no sshd,
+# and the engine against the runner's own OpenSSH server, which this job starts. A scratch sshd cannot run on Windows (Win32-OpenSSH's
+# sshd must run as a service), so the engine tests that start one print "skipped" here.
+# aws-lc-sys (russh's crypto) needs nothing installed: it is the same crate rustls already builds for the updater in the release
+# job on this runner image, and that job installs nothing for it.
 # macOS can only type-check the Windows code; the permission behavior has to be seen on Windows.
 name: windows key slots
 
@@ -19,7 +24,7 @@ permissions:
 jobs:
   slots:
     runs-on: windows-latest
-    timeout-minutes: 30
+    timeout-minutes: 45
     defaults:
       run:
         working-directory: src-tauri
@@ -46,8 +51,75 @@ jobs:
       # slot_files_windows), the key vault (vault::), the local IPC transport (ipc:: covers the named pipe and program identification)
       # and the SSH agent (agent:: covers the real ssh-add / ssh-keygen against the agent). The rest of the suite runs on macOS; parts of
       # it use the system keychain.
-      - name: Key slot, vault and agent tests
+      - name: Key slot, vault, agent and engine tests
         env:
           SSHELTER_REQUIRE_OPENSSH: "1"
         # Quoted: an unquoted `vault:: ipc:: agent::` is read as a YAML mapping and the workflow would not load.
-        run: "cargo test --lib -- sync::slot_rules sync::slot_files vault:: ipc:: agent::"
+        # --locked: the committed Cargo.lock, with russh in it, is what is built.
+        run: "cargo test --locked --lib -- sync::slot_rules sync::slot_files vault:: ipc:: agent:: ssh::"
+      # The library and the binary, linked the way a release links them, with russh in the dependency graph.
+      - name: Build the whole app
+        run: cargo build --locked
+
+      # The runner image ships the OpenSSH client; the server is a Feature on Demand. If that capability cannot be added, the Chocolatey
+      # package (Win32-OpenSSH) is the fallback. The service creates its host keys the first time it starts.
+      - name: Install and start the OpenSSH server
+        shell: pwsh
+        run: |
+          $ErrorActionPreference = 'Stop'
+          $capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
+          $capability | Format-Table Name, State
+          if ($capability.State -ne 'Installed') {
+            try {
+              Add-WindowsCapability -Online -Name $capability.Name | Out-Null
+            } catch {
+              Write-Warning "Feature on Demand failed ($_); trying Chocolatey"
+              choco install openssh -y --no-progress --params '"/SSHServerFeature"'
+            }
+          }
+          Get-Service sshd | Format-Table Name, Status, StartType
+          Set-Service -Name sshd -StartupType Manual
+          Start-Service sshd
+          Get-Service sshd | Format-Table Name, Status, StartType
+
+      # The runner user is an Administrator, so Win32-OpenSSH reads C:\ProgramData\ssh\administrators_authorized_keys for it (the
+      # "Match Group administrators" block of the default sshd_config) and refuses the file unless only SYSTEM and Administrators can write it.
+      # The Windows client refuses a private key other users can read.
+      - name: Authorize a throwaway key for the runner user
+        shell: pwsh
+        run: |
+          $ErrorActionPreference = 'Stop'
+          $openssh = Join-Path $env:SystemRoot 'System32\OpenSSH'
+          $dir = Join-Path $env:RUNNER_TEMP 'engine-ssh'
+          New-Item -ItemType Directory -Force -Path $dir | Out-Null
+          $key = Join-Path $dir 'id_ed25519'
+          & "$openssh\ssh-keygen.exe" -q -t ed25519 -N '' -C engine -f $key
+          if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen failed' }
+          icacls.exe $key /inheritance:r /grant "$($env:USERNAME):F" | Out-Null
+          $authorized = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
+          Get-Content "$key.pub" | Set-Content -Path $authorized -Encoding ascii
+          icacls.exe $authorized /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
+          Restart-Service sshd
+          Add-Content -Path $env:GITHUB_ENV -Encoding utf8 -Value 'SSHELTER_TEST_SSH_PORT=22'
+          Add-Content -Path $env:GITHUB_ENV -Encoding utf8 -Value "SSHELTER_TEST_SSH_USER=$env:USERNAME"
+          Add-Content -Path $env:GITHUB_ENV -Encoding utf8 -Value "SSHELTER_TEST_SSH_KEY=$key"
+
+      # Separates a server that is set up wrong from an engine that cannot talk to it.
+      - name: The OpenSSH client logs in
+        shell: pwsh
+        run: |
+          $openssh = Join-Path $env:SystemRoot 'System32\OpenSSH'
+          & "$openssh\ssh.exe" -V
+          & "$openssh\ssh.exe" -F NUL -p $env:SSHELTER_TEST_SSH_PORT -i $env:SSHELTER_TEST_SSH_KEY -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL "$env:SSHELTER_TEST_SSH_USER@127.0.0.1" 'echo client-ok'
+          if ($LASTEXITCODE -ne 0) { throw "the OpenSSH client could not log in (exit $LASTEXITCODE): the server setup is wrong, not the engine" }
+
+      - name: The engine against the runner's OpenSSH server
+        env:
+          RUST_BACKTRACE: "1"
+        # Quoted for the same reason as above.
+        run: "cargo test --locked --lib -- ssh::engine_tests::environment --nocapture"
+
+      - name: What the OpenSSH server logged
+        if: failure()
+        shell: pwsh
+        run: Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 40 -ErrorAction SilentlyContinue | Format-List TimeCreated, Message
```

- [ ] **Step 5: Check both workflows**

```bash
actionlint -color .github/workflows/test-windows.yml .github/workflows/test-engine.yml; echo "actionlint exit: $?"
```

Expected: no findings and `actionlint exit: 0`.

- [ ] **Step 6: Run the engine tests and the whole suite**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::
```

Expected: `test result: ok. 128 passed; 0 failed`.

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1545 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`.

- [ ] **Step 7: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add .github/workflows/test-windows.yml src-tauri/src/ssh/engine_tests/environment.rs src-tauri/src/ssh/engine_tests/mod.rs
git commit -m "ci(ssh): build the app with russh and run the engine against the Windows runner's OpenSSH"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing.

- [ ] **Step 8: First run on Windows (the user's step, after pushing)**

The implementer stops at the commit. The user starts `windows key slots` (a pull request, or `workflow_dispatch`) and checks: (1) `Build the whole app` passes: the app compiles with russh under `--locked`, including `aws-lc-sys`; if it fails for a missing tool, that is the one thing the phase-0 spike could not tell; (2) `Key slot, vault, agent and engine tests` passes (`ssh::` runs there too: the scratch-sshd tests print `skipped`, and the tests that need no sshd run for real, among them the password and keyboard-interactive logins against the in-process server, so they show that russh works on Windows); (3) `Install and start the OpenSSH server` shows the service running (the Feature on Demand is tried first, Chocolatey is the fallback); (4) `The OpenSSH client logs in` prints `client-ok`: if this fails the server setup is wrong, not the engine; (5) `The engine against the runner's OpenSSH server` prints the two `environment.*` FACT lines and passes. Record the outcome, the FACT lines and the OpenSSH version in the pull request.

---

### Task 14: Delete the spike, check everything once more

**Files:**
- Delete: `spike/` (its 21 tracked files, `spike/russh/Cargo.lock` among them)
- Delete: `.github/workflows/spike-windows.yml`
- Modify: `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` (the line of §16 about the spike's lifetime)

**Interfaces:**
- Consumes: everything. Nothing in `spike/` is used by the app (`spike/` is its own cargo workspace).
- Produces: nothing new; the repository without the throwaway crate. The spike report stays: `docs/superpowers/specs/2026-10-10-own-ssh-spike-report.md`.

What shapes this task:
- Spec §16 said the spike's `Cargo.lock` records the app's whole dependency graph, so any change to `src-tauri/Cargo.toml` breaks its `--locked` Windows job; Task 1 changed that manifest, so `spike-windows.yml` would fail on the next run anyway. Everything it proved now lives in the app: the harness (Task 5), the proxy, fixture and doubles (Task 6), the engine tests (Tasks 7–11), the Windows setup (Task 13). The report stays because it is the record of what was measured.
- `git rm` removes tracked files only. `spike/russh/target/` is ignored by git and was 5.7 GB on this machine; it is left behind when the tracked files go. Do not delete it on your own: ask the user, and remove it (`rm -rf spike`) only when they say so.

- [ ] **Step 1: Delete the spike and its workflow**

```bash
git rm -r -q spike .github/workflows/spike-windows.yml
git status --short | sed -n '1,3p'
git status --short | wc -l
```

Expected: lines starting with `D ` and a count of 22 (the 21 files under `spike/` and the workflow). Then see what is left of the directory:

```bash
ls spike 2>/dev/null && du -sh spike 2>/dev/null
```

Expected: either nothing (the directory is gone) or `russh` and a size of several gigabytes: the ignored build directory. In that case stop and ask the user whether to remove it; do not run `rm -rf` yourself.

- [ ] **Step 2: Rewrite the line of the spec about the spike's lifetime**

`docs/superpowers/specs/2026-10-10-own-ssh-client-design.md`: apply this patch

```diff
--- a/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
+++ b/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
@@ -346,7 +346,7 @@ Connect 按鈕、指令面板、托盤的快速連線:沿用 `connect.rs` 的 `d
 
 - Windows:`AttachConsole` + VT 模式在 Windows Terminal 與傳統 console 的行為(第 3 期);PTY/ConPTY 與視窗大小沒量過。
 - 第 0 期沒量到、第 1 期要補(§12):密碼與 keyboard-interactive 的成功路徑(PAM);`sign` 出錯與被放棄的 keyboard-interactive 之後的 session;內層跳板自己先結束、外層還活著時的 `disconnected`;Linux 與其他版本的 sshd(所有計時只在 macOS OpenSSH 10.3p1 量過);長時間連線與 rekey;沒有 `server-sig-algs` 的老伺服器;app 加上 russh 後的 Windows build;`cargo audit` 對兩代 RustCrypto 的結果。
-- 試驗 crate `spike/` 的壽命:它的 lock 記了 app 的整個相依圖,`src-tauri/Cargo.toml` 一變,它的 `--locked` Windows 工作就壞;harness 搬進 app 之後刪掉 `spike/` 與 `spike-windows.yml`(報告留著)。
+- 試驗 crate `spike/` 的壽命:已結束。它的 lock 記了 app 的整個相依圖,`src-tauri/Cargo.toml` 一變,它的 `--locked` Windows 工作就壞,所以第 1a 期在 harness 搬進 app(`src-tauri/src/ssh/testing/`)之後刪掉了 `spike/` 與 `spike-windows.yml`。報告 `2026-10-10-own-ssh-spike-report.md` 留著;它引用的 `spike/russh/...` 檔案只剩 git 歷史(刪除那個 commit 之前)裡看得到。
 - 同一個 alias 在不同 space 重複時 CLI 的選法(本文件:回錯誤要求用 id;UI 可以禁止同名)。
 - keyboard-interactive 的提示在 MCP `ask` 模式下送 app 視窗,是否需要遮蔽輸入(`echo` 旗標已在協定裡,視窗照它做)。
 - 1.0 的 beta 何時開始發到唯一的 beta 通道(使用者決定)。
```

- [ ] **Step 3: Check that nothing refers to the spike any more**

```bash
grep -rnE 'spike/|spike-windows|russh-spike' .github src-tauri/Cargo.toml src-tauri/tauri.conf.json package.json 2>/dev/null; echo "grep exit: $?"
```

Expected: no match (`grep exit: 1`): no workflow, manifest or config names the spike.

```bash
grep -rn 'spike/' src-tauri/src
```

Expected: only comments that say where code was ported from (1 here, in the harness), no code:

```
src-tauri/src/ssh/testing/harness.rs:5://! Ported from the phase-0 spike (`spike/russh/src/harness.rs`, checked on macOS with OpenSSH 10.3p1): `Port 0` is rejected ("Badly
```

The plan documents and the spec still mention the spike by name; they are records, and so is the spike report.

- [ ] **Step 4: Check that nothing starts a process behind `crate::process`'s back**

```bash
grep -rnE '\.(spawn|output|status)\(\)' src-tauri/src/ssh; echo "grep exit: $?"
```

Expected: no output. (`clippy.toml` forbids `Command::spawn`, `output` and `status`; there is no clippy on this machine, so this grep stands in for it.)

- [ ] **Step 5: Build the library without tests**

```bash
cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo build --offline --locked --lib 2>&1 | tail -5
```

Expected: `Finished` and only the old warning (`function set_host_enabled is never used`). The engine sits unused inside the library, which is the point of this plan, and adds no warning.

- [ ] **Step 6: Run the whole lib suite once more**

```bash
cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain
```

Expected: `test result: ok. 1545 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`. That is the 1417 tests of the app before this plan plus the 128 tests of the engine and its test support.

- [ ] **Step 7: Check the workflows once more**

```bash
actionlint -color .github/workflows/*.yml; echo "actionlint exit: $?"
```

Expected: no findings and `actionlint exit: 0` for every workflow that is left.

- [ ] **Step 8: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
git commit -m "chore: delete the phase-0 spike crate and its Windows workflow"
```

Expected: `git status --short` lists exactly the files being added or changed here and nothing else; the `git diff --stat` prints nothing. The deletions are already staged by `git rm` (`D ` in the first column), so `git add` names only the edited spec; naming a deleted path would fail.

- [ ] **Step 9: Look at the whole branch**

```bash
git log --format=%s -n 14
git diff --stat HEAD~14 HEAD -- src-tauri/Cargo.toml src-tauri/Cargo.lock | tail -1
```

Expected: the subjects of the fourteen commits of this plan, newest first,

```
chore: delete the phase-0 spike crate and its Windows workflow
ci(ssh): build the app with russh and run the engine against the Windows runner's OpenSSH
ci(ssh): run the engine tests on macOS and Linux, with OpenSSH+PAM in a container
test(ssh): log in with passwords and keyboard-interactive against an in-process server
feat(ssh): connect through jump hosts and keep the real cause of a chain's end
test(ssh): measure keepalive, closing and dropping, the stuck session and the idle CPU
feat(ssh): run commands and PTY shells over an established connection
feat(ssh): connect, check host keys and log in with vault keys through russh
test(ssh): add the proxy, server fixture and policy/auth doubles for engine tests
test(ssh): port the scratch-sshd harness onto crate::process
test(ssh): add the scripted FakeEngine for broker, MCP and CLI tests
feat(ssh): add the bounded shell output queue and the queued shell
feat(ssh): add the engine interface: types, errors and traits
build(deps): add russh =0.64.1 and tokio for the SSH engine
```

and then `2 files changed, 1277 insertions(+), 164 deletions(-)` (the lock file of Task 1 and nothing after it). Nothing was pushed. What is left for the user is listed under "What is left for the user after the last commit" at the end of this plan: the first runs of the two workflows on GitHub (the Linux and Windows checks that this Mac could not make), and the decisions about `cargo audit` and `spike/russh/target/`.

---

## Coverage of the spec

Every test named here exists in the final tree (the list was taken from `cargo test -- --list`). Spec items that the tests do not reach are listed after the table.

| Spec item | Task | Tests |
|---|---|---|
| §6.1 the interface as written; error sentences of §11 | 2 | `connect_errors_read_like_the_messages_of_the_spec`, `an_auth_failure_reason_follows_the_sentence`, `no_common_algorithm_names_both_lists_and_explains_ssh_rsa` |
| §12 `FakeEngine`: host-key results, auth results, output, disconnect | 4 | `the_host_key_verdicts_become_the_connect_errors_the_real_engine_gives`, `a_password_login_asks_the_auth_source_and_checks_the_answer`, `a_keyboard_interactive_login_sends_the_prompts_and_compares_the_answers`, `a_scripted_exec_result_comes_back_for_exactly_that_command_and_is_cut_to_the_cap`, `a_scripted_disconnect_makes_every_call_fail_and_say_why` |
| §12 the harness: own sshd per test, bounded wait after a kill, never the real `~/.ssh`; keys the vault can read | 5 | `a_process_that_keeps_the_pipes_open_after_the_kill_does_not_hold_the_runner`, `the_system_ssh_client_logs_in_to_the_scratch_sshd_and_gets_the_exit_code`, `a_key_that_is_not_in_authorized_keys_is_refused`, `a_key_the_vaults_parser_cannot_read_is_told_apart_from_one_it_can`, `the_keys_the_harness_hands_out_can_all_be_read_by_the_vault` |
| §6.2 step 1: a chain with no hosts or a host twice | 7 | `an_empty_chain_and_a_chain_that_lists_a_host_twice_are_refused_before_anything_connects` |
| §6.2 step 2: unreachable and silent servers (timeouts) | 7 | `a_port_with_nothing_behind_it_is_unreachable_and_says_connection_refused`, `a_name_that_does_not_resolve_is_unreachable`, `a_handshake_that_never_gets_an_answer_times_out_after_the_connect_timeout`, `a_server_that_stops_answering_during_the_login_times_out_in_the_auth_phase` |
| §6.2 step 3: the three outcomes of a host key, the pinned family, no common algorithm | 7 | `an_unknown_host_key_fails_fast_with_the_key_the_server_presented_and_leaves_no_connection_behind`, `after_the_user_pins_the_key_the_same_policy_lets_the_next_connect_through`, `a_changed_host_key_is_a_mismatch_that_carries_the_observed_and_the_pinned_key`, `a_pinned_key_narrows_the_handshake_to_its_algorithm_family`, `a_server_that_only_has_an_ssh_rsa_host_key_has_nothing_in_common_and_the_message_says_why` |
| §6.2 step 4, §12: public-key login from the vault (Ed25519, ECDSA P-256, RSA 3072), a foreign signature, a key the server does not know | 7 | `an_ed25519_key_in_the_vault_logs_in`, `an_ecdsa_p256_key_in_the_vault_logs_in`, `an_rsa_3072_key_in_the_vault_logs_in_with_a_sha2_signature`, `a_signature_made_by_another_key_is_refused`, `a_key_the_server_does_not_know_is_refused_without_a_signature` |
| §6.3 b, §12: no RSA signature with SHA-1 | 7 | `an_rsa_key_is_never_signed_with_sha1`, `the_rsa_hash_is_what_the_server_lists_and_never_sha1`, `the_signer_never_asks_for_an_rsa_signature_with_sha1_and_appends_the_signature_to_what_russh_gave_it` |
| §12: `sign` fails, then what the session does; §6.2 step 4: nothing is switched on the same connection | 7 | `a_signer_that_fails_abandons_the_login_and_drops_the_connection` |
| §12: exec (exit code, stderr, signal, output cap, our own timeout), cut during exec, long output | 8 | `exec_returns_stdout_stderr_and_the_exit_code`, `a_command_killed_by_a_signal_has_no_exit_code_and_names_the_signal`, `a_connection_cut_during_a_command_ends_it_as_disconnected`, `thirty_two_mebibytes_of_output_arrive_complete`, `output_beyond_the_cap_is_cut_off_and_the_connection_survives`, `a_command_that_outlives_its_timeout_is_cut_and_the_connection_survives` |
| §6.3: raw bytes, CRLF untouched | 8 | `a_command_has_no_pty_and_its_output_is_not_reshaped` |
| §16: a connection that rekeys (the server asks every 512 KiB) | 8 | `a_connection_survives_the_key_exchanges_the_server_asks_for` |
| §12: PTY shell (prompt, command, exit status), window size, resize; §6.3 channel discipline | 8 | `a_pty_shell_prints_a_prompt_runs_a_command_and_reports_its_exit_status`, `the_size_given_with_the_pty_request_is_the_initial_size`, `a_window_change_while_the_shell_runs_is_applied`, `a_window_change_sent_right_after_the_shell_opens_is_applied`, `closing_a_shell_ends_its_reader_and_leaves_the_connection_and_other_shells_alone`, `a_reader_that_stops_reading_does_not_hold_up_the_connection_and_the_gap_is_announced` |
| §6.2 step 5, §12: keepalive detection and its reason; a healthy link is kept; liveness from state | 9 | `keepalive_closes_a_silent_link_and_the_reason_says_so`, `a_link_that_answers_keeps_the_session_alive_across_several_intervals`, `a_link_that_is_cut_while_idle_is_noticed_as_a_lost_connection` |
| §6.2 step 2: closing and dropping send a disconnect, the reason is ours | 9 | `closing_a_session_sends_a_disconnect_and_the_reason_is_ours`, `dropping_a_session_closes_the_connection_with_a_disconnect` |
| §12: the session after `sign` failed is stuck (measured); idle CPU, authenticated and unauthenticated | 9 | `a_session_whose_signer_failed_is_stuck_and_only_dropping_the_handle_ends_it`, `russh_spins_when_a_connection_idles_unauthenticated_past_the_keepalive_interval`, `an_authenticated_connection_that_idles_with_keepalive_does_not_burn_cpu` |
| §12: two-hop jump, a closed port, no forwarding, the real cause of an end (outer first, inner first), large output across a jump | 10 | `a_two_hop_jump_runs_a_command_on_the_second_host_and_checks_each_hops_own_host_key`, `an_unknown_key_on_the_second_hop_stops_the_chain_and_closes_the_first_hop`, `a_jump_to_a_closed_port_fails_cleanly_and_names_the_jump_host`, `a_jump_host_that_does_not_allow_forwarding_is_named_in_the_error`, `closing_the_session_disconnects_every_hop`, `when_the_outer_link_is_cut_the_reason_is_the_outer_hops`, `when_the_inner_hop_ends_first_the_chain_comes_down_and_the_reason_is_the_inner_hops`, `a_large_output_crosses_a_jump_without_stalling`, `a_shell_on_the_second_host_works_through_the_jump` |
| §12: password, keyboard-interactive, abandoned and overdue prompts, no CPU while a prompt waits (in process here; the PAM container in the Linux job) | 11 | `a_password_login_succeeds`, `a_wrong_password_is_refused_and_keyboard_interactive_is_tried_next`, `a_keyboard_interactive_login_succeeds`, `a_refused_key_falls_back_to_the_password`, `a_cancelled_prompt_abandons_the_login_and_drops_the_connection`, `a_prompt_that_runs_out_of_time_abandons_the_login_and_drops_the_connection`, `waiting_for_a_prompt_costs_no_cpu`, `a_password_is_asked_for_before_the_connection_is_opened`, `the_other_login_methods_are_refused_by_a_key_only_server_and_only_offered_methods_are_tried` |
| §12 Windows: the engine against the runner's OpenSSH server; CRLF from Windows OpenSSH | 13 | `connect_log_in_and_exec_against_the_server_in_the_environment` |

Not covered by a test, on purpose or for lack of a way:

- `TCP_NODELAY` on shell connections (§6.3): set in `connect_hop`; it cannot be seen from the server side, so no test pins it.
- `Timeout { phase: Tcp }`: written, not exercised (a proxy accepts the connection, so the tests reach `Handshake` and `Auth`).
- Connections that live for hours and the client's own rekey limits (1 GiB, one hour; §16): the server-forced key exchanges of Task 8 cover rekeying, not the passage of time.
- Servers older than OpenSSH 10.3p1 and sshd on other systems (§16): Linux runs in CI (Task 12), nothing older does.
- A server that sends no `server-sig-algs` (§16): the decision is unit-tested (`choose_rsa_hash(None)`), no integration test has such a server.
- `cargo audit` (§12, §16): Task 1 notes it; not run, no CI job.

---

## Decisions to confirm

These are the choices this plan makes where the spec, the plan's outline or the code left room. Each can be reversed by changing the named task.

1. **`AuthSource` gains `public_key` (Task 2).** Spec §6.1 gives the engine a `key_id` and a `sign` but no public key, and russh's `authenticate_publickey_with(user, PublicKey, hash_alg, signer)` announces the public key before it asks for a signature. §6.1's `AuthSource` therefore cannot be implemented as written against russh 0.64.1. The alternative is to put the public key into `AuthMethod::Key { key_id, public_key }` in the data model (plan 1c); this plan chose the trait method because it leaves `Hop` as the spec has it. `ShellChannel` is also `Send + Sync` instead of `Send`, because a shell is read on one thread while another writes.
2. **`check` and `sign` run on the thread that called `connect` (Task 7).** The outline suggested calling the vault through `spawn_blocking` and consulting the policy inside russh's callback. `&dyn HostKeyPolicy` and `&dyn AuthSource` are borrowed and cannot enter russh's `'static` tasks, so the handler asks the connect thread over a channel and `sign` is called inline from the signer. Nothing else stalls while it runs: `block_on` polls the future on the caller's thread and russh's own session task runs on the engine's workers. The contract for the implementers is the spec's: both must be quick.
3. **`password` returning `None` skips the method (Task 2, Task 11).** Spec §6.2 step 4 says the broker asks the user when there is no stored password. The engine asks `AuthSource::password` before it opens the connection for a hop that starts with the password method, so the broker can ask a person inside it; as a fallback after a refused key it is called during the login and must be quick.
4. **The output cap ends a command as `Ended::Truncated`, a fifth variant of `Ended` (Tasks 2, 4 and 8).** Spec §6.1 lists four and the spec says the connection stays usable after the cap. `Disconnected` would be wrong for a command that was stopped at the cap: the broker and the MCP tool would tell the user that the connection was lost. `Truncated` means the engine closed the channel at `output_cap`, the exit status is unknown and the connection is alive; `ExecResult::truncated` stays and is true exactly when `ended` is `Truncated` (the real engine and the fake both set the two together; the fake passes a scripted result through untouched when it fits the cap, so a script can set them inconsistently).
5. **A resize before the shell exists cannot be sent (Task 8).** `Session::shell` returns once the PTY and shell requests are on the wire and the server handles one channel's requests in order, so a `window_change` sent right after it is applied; the broker keeps the last size and sends it then (spec §7.2).
6. **The in-process SSH server for the password tests lives inside `russh_engine.rs`'s test module (Task 11)**, because russh may be named in no other file. The same test bodies also run against a real OpenSSH with PAM in the Linux CI job.
7. **A new workflow, `test-engine.yml`, for macOS and Linux (Task 12).** No workflow runs the Rust tests there today. It triggers on pushes to `main` and `next/own-ssh`, on pull requests and by hand; take `next/own-ssh` out of the list when the branch is merged. `test-windows.yml` keeps its triggers (pushes to `main`, pull requests and by hand).
8. **`cargo audit` is not added to CI (Task 1).** Spec §12 says it should be, and §16 lists its verdict on two generations of RustCrypto as unmeasured. It is not installed here and its first result is unknown, so a job that may fail from day one is for you to decide; Task 1 says what to look at.
9. **Comments in the new files are English (Global Constraints).** The vault, agent, sync and ipc comments (and the vault lines of `Cargo.toml`) are in Traditional Chinese; `mcp.rs`, `config/` and the workflows are in English; the `ssh/` module and the two lines added to `Cargo.toml` follow the second group.
10. **Tasks 7 and 8 are longer than the roughly 400 lines per task that the outline set ("How the tasks are cut").**
11. **The lock file moves nine versions, not one.** The spike report measured the spike's own lock: `zeroize` only. In `src-tauri/Cargo.lock` the eight `futures-*` crates move from 0.3.32 to 0.3.34 as well (Task 1 checks the exact numbers and stops if they differ).
12. **`spike/russh/target/` (5.7 GB, ignored by git) is not deleted by the plan (Task 14).** It stays until you say it can go.
13. **`an_rsa_key_is_never_signed_with_sha1` has an escape hatch, `SSHELTER_SKIP_SHA1=1` (Task 7),** for a machine whose OpenSSH cannot be told to accept `ssh-rsa` login signatures. Nothing in this plan sets it.
14. **A gap in the vault, found on the way and not touched here (Task 5).** `ssh-key` 0.6.7, the parser behind `Material::open`, cannot read an ECDSA private key whose secret number OpenSSH wrote in its shortest form (it starts with a zero byte): `length invalid`, which `open` reports as `Unreadable`. Measured with ssh-keygen from OpenSSH 10.3p1: about 1 in 256 P-256 and P-384 keys and about 1 in 4 P-521 keys. The app has a guard for unreadable keys (`agent_can_read`, used by `sync::slots::set_delivery` for "Only in SSHelter"), so the user is refused rather than crashed, but a valid key is refused because of a parser limitation. `vault/` is never modified by this plan; the test harness throws such keys away. Whether to fix it in `vault/` (pad the scalar before parsing), by upgrading `ssh-key`, or to leave it, is for you to decide.

## What is left for the user after the last commit

- Push the branch and read the first runs: `ssh engine` (Task 12) and `windows key slots` (Task 13), with the checklists at the end of those tasks. They are the only checks of the Linux scratch sshd, the PAM container, PAM's real behaviour and the Windows build of the app with russh.
- Decide about `cargo audit` (decision 8) and about `spike/russh/target/` (decision 12).
- The timings in the engine tests were measured on macOS with OpenSSH 10.3p1, as in the spike; their bounds are wide for that reason. A long-lived connection (hours, rekeys under real traffic) is not tested beyond the server-forced rekeys of Task 8.
