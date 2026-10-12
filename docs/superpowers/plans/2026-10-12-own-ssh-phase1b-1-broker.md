# Own SSH client — phase 1b-1: the session broker on the local socket — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sshelter_lib` gets the session broker of spec §4 and §7 (`src-tauri/src/session/`): it serves SSH shells to clients over a Unix socket with the shell subset of the §7.1 protocol, resolves the saved host through a `HostDirectory` (a temporary adapter over today's ssh_config, the vault keys and a pin file), connects through plan 1a's engine with its own host-key policy and auth source, asks the client's person what the login needs (passphrase, password, keyboard-interactive; host keys go to a confirmer, the window of plan 1b-2), relays the shell and says how it ended. The engine gets the signals the broker needs from it (R16, R19, R20) and the fake engine behaves like the real one where the broker relies on it (R18). The deliverable stands on its own: `session::broker::tests::a_real_shell_on_a_scratch_sshd_through_the_socket` opens a shell on a scratch sshd through the real engine and a socket in a temp directory. Nothing a user sees changes yet: the app does not start the broker until plan 1b-2, which adds `sshelter connect`, the host-key window and the Connect button.

**Architecture:** `session/` is a set of synchronous modules on plain threads, each tested on its own: `protocol.rs` (frames and messages), `directory.rs` (the `HostDirectory` trait) with `pins.rs` and the temporary `ssh_config_directory.rs`, `auth.rs` (`PinPolicy: HostKeyPolicy` and `BrokerAuth: AuthSource` over the vault, the keychain and the session's `Owner`), `connect.rs` (the connect loop: confirm a host key, pin, reconnect; ask for a password the server still wants and reconnect password-first; retry a pinned host without the key-type restriction), `relay.rs` (the shell between the engine and the client: last window size, output pump, the deferred close of R22, the ending sentences) and `broker.rs` (one client connection = one session, served on the IPC server's thread, the session on a second thread). Starting the app for a client moves from `mcp.rs` to `host_start.rs`, shared with the CLI of plan 1b-2. The test doubles live in `session/testing.rs`; `ssh/parity_tests.rs` runs the scenarios the broker relies on against both engines.

**Tech Stack:** Rust 2021 (rustc 1.98), only crates the app already has (serde/serde_json, zeroize, base64; no change to `Cargo.toml` in this plan), std threads, `Mutex`/`Condvar` and `mpsc`, phase 0's `crate::ipc::{server, peer}`, `crate::vault::material`, `crate::sync::env::Keychain` (its in-memory double `sync::testkit::MemKeychain` in tests), OpenSSH's `ssh -G` (read-only: the adapter, and one test with a config file in a temp directory), plan 1a's engine, `FakeEngine`, scratch-sshd harness and in-process toy server.

**Spec:** docs/superpowers/specs/2026-10-10-own-ssh-client-design.md (§4, §6.1–6.3, §7.1, §7.2, §10, §11, §12, §14, §16); the rulings R1–R22 of docs/superpowers/plans/2026-10-12-own-ssh-phase1b-design-brief.md; the facts of docs/superpowers/plans/2026-10-12-own-ssh-phase1b-scout.md. Plan 1b-2 (docs/superpowers/plans/2026-10-12-own-ssh-phase1b-2-connect.md) continues from the last commit of this plan.

## Global Constraints

- **Where.** Repository `/Users/ysya/project/sideproj/sshelter`, branch `next/own-ssh`, starting at a764792 (plan 1a's final HEAD). Every task ends with a commit on that branch; nothing is pushed, nothing is merged to main, no beta is published.
- **Starting state.** `git status --short` prints nothing. The whole lib suite passes with `test result: ok. 1585 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out` (the two are the keychain tests skipped below), `ssh::` alone with 168 passed; the frontend has 845 tests in 50 files and `tsc --noEmit` is clean (this plan does not touch it).
- **Toolchain.** As in plan 1a: every cargo command is prefixed `PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH` (rustc/cargo 1.98.0; Homebrew's cargo is broken on this machine). No clippy and no rustfmt: the code in this plan and the existing files (long lines, about 150 columns) are the style reference.
- **Where commands run.** Every command block is run from the repository root; cargo commands go into `src-tauri/` in a subshell, `(cd src-tauri && …)`, so the next block starts at the root again.
- **The app's Rust tests.** From `src-tauri/`, exactly one `--`, all filters after it: `PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- <filters>`; several filters run every test that matches one of them. A whole-suite run adds `--skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain` (they touch the real Keychain). A run that reaches a scratch sshd has `SSHELTER_REQUIRE_OPENSSH=1` in front, so that missing OpenSSH tools fail it instead of skipping tests. The filter `session::` alone also matches `agent::session::`; the commands below name the modules (`session::protocol::` and so on).
- **The leftover check.** After every run that starts a scratch sshd, and at the end of every task: `ps -axo command= | grep 'sshd -D -e -f .*sshelter-sshd' | grep -v grep | wc -l` (listeners) and `ps -axo command= | grep '^sshd-session' | grep -v grep | wc -l` (per-connection children) both print 0, and `ls -d "${TMPDIR:-/tmp}"/sshelter-sshd-* 2>/dev/null | wc -l` prints 0. The `grep -v grep` matters: without it the grep and the shell that runs it are counted. Another test run on the same machine (another worktree) shows up in the check, so run it when nothing else runs.
- **Lock file.** This plan changes neither `src-tauri/Cargo.toml` nor `src-tauri/Cargo.lock`: every cargo command runs `--offline --locked`, and `git diff --stat a764792 -- src-tauri/Cargo.toml src-tauri/Cargo.lock` prints nothing at the end of every task. The one task of plan 1b that changes a feature (R13) is plan 1b-2's Task 2.
- **russh in one file.** Unchanged from plan 1a: only `src-tauri/src/ssh/russh_engine.rs` names russh; `ssh::tests::russh_is_named_by_russh_engine_rs_and_by_no_other_file` scans all of `src/`, `session/` included.
- **Nothing else changes.** This plan edits `src-tauri/src/ssh/` (Tasks 1–3 and 9), creates `src-tauri/src/session/` (Tasks 4 and 6–11) and `src-tauri/src/host_start.rs` (Task 5), edits `src-tauri/src/mcp.rs`, `src-tauri/src/main.rs` and `src-tauri/src/lib.rs` (Task 5: the moved start-up code and the `--host` flag; Tasks 4 and 5: the `mod` lines), the two test workflows (Task 11) and the design spec (Tasks 2, 4 and 11). The frontend, `agent/`, `config/`, `ipc/`, `sync/` and `vault/` are not modified; the broker uses `config/`, `ipc/`, `sync/` and `vault/` as they are.
- **Isolation.** Tests never touch the real `~/.ssh`, the Keychain, any SSH agent or the app's data directory, and never contact a real host. The keychain is `sync::testkit::MemKeychain`, the vault keys are in memory (`session::testing::FakeKeys`), pins are written to temp directories, the one test that runs `ssh -G` gives it `-F` and a config file in a temp directory (with `-F`, OpenSSH reads neither `~/.ssh/config` nor `/etc/ssh/ssh_config`), sockets are made in temp directories under `/tmp` (the path of a Unix socket is limited to 104 bytes on macOS). Never launch the app, never run `pnpm`/`npm`/`npx`, never push.
- **A test that fails once.** The broker's end-to-end tests start real servers. Before this plan was written, the modules that do (`session::broker::`, `session::relay::`, `ssh::parity_tests::` and plan 1b-2's `cli::`, 60 tests) ran 10 times in a row at the last commit of plan 1b without a failure, and the whole lib suite ran at least once at every commit. If a test that passed before fails once, run it alone three times (`... -- --exact <full test path>`, one `--`) before suspecting the code: three failures in three are real; one in three is a timing problem to report, and longer waits are not the answer.
- **Spawning.** `src-tauri/clippy.toml` forbids `std::process::Command::spawn`, `output` and `status`; processes are started with `crate::process::spawn` (`host_start::start_host` does) or `crate::process::output` (`config::intel::effective_config` does).
- **Threads (spec §4; plan 1a's rules).** Every blocking engine call (`SshEngine::connect`, `Session::{shell, close}`, `ShellChannel::{write, read, window_change, close}`) runs on a plain thread, never in async code and never on the UI thread: the broker serves a client on the thread the IPC server gives it and runs the session on a second thread. `HostKeyPolicy::check` and every `AuthSource` call run on the thread that called `connect` and must be quick, so a person is asked only before `connect` (passphrases; the password of a hop that starts with the password method, which the engine fetches before it opens the connection) or inside keyboard-interactive (which has its deadline); a password wanted after a refused key is asked between two connects (R8, R16).
- **Commits.** Conventional commits in English, no attribution lines, files staged by path (never `git add -A`).
- **Comments.** The new files are commented in English, like `ssh/`, `mcp.rs` and `config/` (plan 1a's decision 9); the notes added to the spec are in Traditional Chinese, like the spec.
- **Reading the code blocks.** "Create" means a new file with exactly that content. "Create (only its tests for now …)" means a new file that holds its test module only, until the step named; "insert above the `#[cfg(test)]` line" (or the attribute named) then means the block goes at the very top of that file, followed by one empty line, in front of the tests that were written first. A `diff` block is a unified diff against the file as the earlier steps left it and is the complete change: run it from the repository root with `git apply` (paste it between `git apply <<'PATCH'` and `PATCH`) or make the same edits by hand. The blocks were generated from the verified commits and replayed in order on a764792: every task ends on exactly the tree of its commit.
- **Spec §7.1 frames, as built (Task 4).** `u32` length, big-endian, counting the type byte and the payload | `u8` type: `1` control (one JSON message, tagged by `type`), `2` data (raw bytes) | payload. At most 1 MiB per frame; a longer one, an unknown type, an empty frame or a stream that ends inside a frame ends the connection. `hello` carries `version` (1).
- **Error text (spec §11).** What the client is told is the engine's `Display` (plan 1a) or a sentence of the broker, each one written out in its task: `Could not connect through {jump alias}: {reason}`, `Waiting for you to confirm {alias}'s host key in SSHelter.`, `Connection to {alias} lost (no response for {n} seconds).`, `SSHelter quit, so the connection to {alias} was closed.` and the others. None of them carries a key, a passphrase or a password, and no `Debug` output does either.

## Review Focus

The input classes and failure modes the spec implies that no happy path exercises, most likely first. Each has a test in the task named after it.

1. **A terminal closed right after it opened, or a client that goes away in the middle of a login**: the user expects the login to stop where it is, the shell to be closed only once it has printed something or 3 s have passed (so no process holding a PTY is left on a macOS sshd, R22), and no thread, question or session to be left behind. Pinned in Task 10: `when_the_client_goes_away_the_shell_is_closed_after_its_first_output_and_nothing_more_is_sent` and `a_shell_that_never_prints_is_closed_once_the_settle_time_has_passed`; in Task 11: `when_the_client_goes_away_its_session_is_closed` and `the_window_stops_waiting_when_the_client_goes_away`.
2. **A host key that is new, changed, or now of another type**: the user expects to be asked in the window (never at the terminal), the pin to be written only for the exact key the window showed, a host whose server switched key type to give the changed-key warning and not an algorithm error (R17), and a pin file that cannot be read to stop the connection instead of making the host look new. Pinned in Task 9: `an_unknown_host_key_is_confirmed_in_the_window_then_pinned_and_the_broker_connects_again`, `an_answer_for_another_fingerprint_pins_nothing`, `a_changed_host_key_shows_the_pinned_one_and_replaces_it_only_when_accepted` and `a_pinned_host_that_now_has_another_key_type_gets_the_changed_key_warning_not_an_algorithm_error`; in Task 6: `an_unreadable_or_newer_file_is_an_error_and_is_never_overwritten`.
3. **A password asked at the wrong moment**: the user expects a password-first host to be asked once even though the first contact connects twice, a password the server still wants after a refused key to be asked between two connects (never while russh holds the connection, R8), a cancelled password not to come back as a keyboard-interactive prompt, and three refusals to end it. Pinned in Task 2: `a_refused_key_with_no_password_to_give_says_a_password_is_wanted`; in Task 8: `a_cancelled_password_is_not_asked_again_and_keyboard_interactive_does_not_ask_either` and `a_fallback_password_never_asks_a_person`; in Task 9: `the_first_contact_with_a_password_host_asks_for_the_password_once`, `a_password_wanted_after_a_refused_key_is_asked_for_and_the_broker_connects_again_with_the_password_first` and `a_refused_password_is_asked_for_again_up_to_three_times`.
4. **What arrives on the socket is malformed or comes from the wrong client**: a frame over 1 MiB, an unknown type, a stream cut inside a frame, another protocol version, `exec`, an MCP client: the other side expects a refusal it can show and the connection closed, never a hang, a crash, or a password in an error text or a log. Pinned in Task 4: `a_frame_over_the_limit_is_refused_from_its_header_and_never_written`, `a_stream_that_ends_inside_a_frame_is_truncated_and_odd_frames_are_errors` and `an_answer_keeps_its_value_out_of_debug_output_and_error_text`; in Task 11: `another_protocol_version_exec_and_the_mcp_client_are_refused_by_name`.
5. **A server that sends its output in tiny pieces, or a terminal that fell behind and a program that then goes quiet**: the user expects the memory the queue uses to follow the bytes it holds, not the number of pieces (R19), and the notice about dropped output to appear as soon as the terminal has caught up, not with the next output that may never come (R20). Pinned in Task 1: `small_chunks_are_merged_so_their_count_follows_the_bytes_and_not_the_pushes` and `a_reader_that_catches_up_after_a_gap_is_told_about_it_at_once`.

## File Structure

All paths under `src-tauri/src/` unless a path says otherwise.

- `ssh/channel.rs` — the output queue merges small chunks and announces a gap at once (Task 1).
- `ssh/error.rs`, `ssh/types.rs`, `ssh/traits.rs`, `ssh/russh_engine.rs` — `AuthFailed::password_wanted`, `Exit::Refused`, `AuthSource::banner` (Task 2).
- `ssh/engine_tests/broker_signals.rs` — the real engine's side of those three (Task 2).
- `ssh/fake.rs` — `FakeEngine` reworked to behave like the real engine where the broker relies on it (Task 3; the pinned key type in Task 9); `ssh/parity_tests.rs` — the same scenarios against both engines (Tasks 3 and 9).
- `session/mod.rs` — the module's front door (Tasks 4, 6–11).
- `session/protocol.rs` — frames and the messages of spec §7.1 (Task 4).
- `host_start.rs` — starting SSHelter in the background for a client, moved out of `mcp.rs`; `--host` (Task 5).
- `session/directory.rs` — the `HostDirectory` interface; `session/pins.rs` — the pin file; `session/testing.rs` — the test doubles of the broker (Task 6, extended in Tasks 8, 9, 11).
- `session/ssh_config_directory.rs` — TEMPORARY: the directory over today's ssh_config, vault keys and pin file; plan 1c deletes it (Task 7).
- `session/auth.rs` — the host-key policy and the auth source of one connect (Task 8).
- `session/connect.rs` — the connect loop (Task 9).
- `session/relay.rs` — a shell between the engine and its client (Task 10).
- `session/broker.rs` — the broker on the IPC socket (Task 11).
- `.github/workflows/test-engine.yml`, `.github/workflows/test-windows.yml` — the new test modules in CI (Task 11).
- `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` — §6.1 (Task 2), §7.1 (Task 4), §7.2 (Task 11).

## Tasks

1. The output queue merges small chunks and announces a gap at once
2. What the engine tells the broker: a password could still get in, the server's banner, why a shell was refused
3. A fake engine that behaves like the real one, and the scenarios that check it
4. The frames and messages of the local IPC protocol
5. Starting SSHelter for a client, shared and renamed `--host`
6. The host directory interface, its fake, and the pin file
7. The temporary directory over today's ssh_config, vault keys and pin file
8. The broker's host-key policy and auth source
9. The connect loop: host keys, typed passwords, a changed key type
10. The shell relay and how a session ends
11. The broker on the local socket

## How the tasks are cut

Eighteen commits were needed for the whole of plan 1b, more than the 10 to 14 tasks of one plan, so 1b is two plans that each end in something that can be tested on its own. This plan (1b-1) ends with a broker that serves real shells on a socket in tests; plan 1b-2 builds `sshelter connect`, the host-key window, the app wiring and the Connect button on it, and ends with `sshelter connect` running against a scratch sshd through the broker. The order inside this plan follows what each task needs: the engine changes the broker relies on first (Tasks 1–3, all of R16–R20 that touch `ssh/`), then the broker from the bottom up — the wire format (4), the start-up code it shares with the MCP adapter (5), where hosts and pins come from (6, 7), what the engine is given for one connect (8), the loop around `connect` (9), the shell (10) and the socket (11). Most tasks change 400 to 800 lines with their tests (Task 1 about 100, Task 5 mostly moved code); Task 3 is the largest, about 970 changed lines, because the parity scenarios only make sense with the fake they check.

## What this plan could not check on this machine, and where it deals with it

- Windows: the broker and the session code compile there behind `cfg(unix)`/`cfg(windows)` (R4), but nothing here builds for Windows; the first run of `test-windows.yml` (Task 11 adds `session::` to it) is the check. On Windows the broker serves nobody in 1b (plan 1b-2 Task 4 says why).
- Linux: the CI job runs the new modules against the Linux scratch sshd (Task 11); the measurements here are macOS 27 with OpenSSH 10.3p1.
- Real servers with PAM, a real keyboard-interactive second factor, and the timing of a person at a terminal: the login logic is tested against the fake engine and the in-process toy server; the Linux CI job's PAM container covers the engine side.
- The temporary directory's reading of a real user's ssh_config is tested on canned `ssh -G` answers and on one config file in a temp directory (Task 7); a real user's config with `Include`, `Match` and tokens reaches it only through `ssh -G` in the app (plan 1b-2).

---

### Task 1: The output queue merges small chunks and announces a gap at once

**Files:**
- Modify: `src-tauri/src/ssh/channel.rs` (with its tests)

**Interfaces:**
- Consumes (plan 1a Task 3): `ByteQueue::new(capacity: usize) -> Arc<ByteQueue>`, `ByteQueue::push(&self, chunk: Vec<u8>) -> bool`, `ByteQueue::close(&self)`, `ByteQueue::read_until(&self, buf: &mut [u8], deadline: Option<Instant>) -> QueueRead`, `ByteQueue::dropped_bytes(&self) -> u64`.
- Produces (`ssh/channel.rs`):
  - `pub const MERGE_LIMIT: usize = 16 * 1024`
  - (impl ByteQueue, test builds only) `fn chunk_count(&self) -> usize`
  - No signature changes. `push` now merges a chunk into the last queued one while that stays within `MERGE_LIMIT`; `read_until` announces a gap as soon as the queue is empty.

What shapes this task:
- R19 (plan 1a's final review, item 4): the queue kept one `Vec` per pushed chunk and counted the payload only, so a program — or a server doing it on purpose — that sends one byte per SSH packet cost about 40 times the queue's capacity in allocations. A chunk is now merged into the back chunk while the back chunk stays within 16 KiB; a chunk bigger than that stays whole (it is not split). Merging only grows the end of the back chunk, so the read position inside the front chunk stays valid even when the front chunk is the back chunk.
- R20, the gap notice (item 5): dropped output was announced in front of the next chunk that was kept, or at `close`. A program that goes quiet after the terminal fell behind left a hole in the output and no word about it. `read_until` now appends the notice as soon as the reader has emptied the queue, under the same lock, before it waits. The bound stays as plan 1a wrote it: `capacity` plus one notice while the queue is open.
- One existing test pinned the chunk boundaries: in `chunks_come_out_in_the_order_they_went_in_and_a_small_buffer_gets_part_of_a_chunk`, the two pushes are merged now, so the last read returns `d!` at once.

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/channel.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/channel.rs
+++ b/src-tauri/src/ssh/channel.rs
@@ -280,15 +280,63 @@ mod tests {
             assert_eq!(&buf, b"hello");
             assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(5));
             assert_eq!(&buf, b" worl");
-            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(1));
-            assert_eq!(&buf[..1], b"d");
-            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(1));
-            assert_eq!(&buf[..1], b"!");
+            // The two pushes were merged into one chunk (see `MERGE_LIMIT`), so the last read gets the end of both.
+            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(2));
+            assert_eq!(&buf[..2], b"d!");
             assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Timeout);
             assert_eq!(queue.read_until(&mut [], soon()), QueueRead::Bytes(0), "an empty buffer reads nothing and does not wait");
         });
     }
 
+    /// A writer that sends one byte at a time (a slow program, or a server doing it on purpose) must not cost a `Vec` per byte: small
+    /// chunks are merged into the last one while it stays within `MERGE_LIMIT`, so the number of chunks follows the bytes, not the pushes.
+    #[test]
+    fn small_chunks_are_merged_so_their_count_follows_the_bytes_and_not_the_pushes() {
+        let queue = ByteQueue::new(64 * 1024);
+        for index in 0..20_000u32 {
+            assert!(queue.push(vec![(index % 251) as u8]));
+        }
+        assert_eq!(queue.chunk_count(), 2, "16 KiB in the first chunk, the rest in a second");
+        let all = read_all(&queue);
+        assert_eq!(all.len(), 20_000);
+        assert!(all.iter().enumerate().all(|(index, byte)| *byte == (index as u32 % 251) as u8), "the bytes come out in the order they went in");
+    }
+
+    #[test]
+    fn a_chunk_is_not_merged_into_one_it_would_grow_past_the_merge_limit_and_a_big_chunk_stays_whole() {
+        let queue = ByteQueue::new(1024 * 1024);
+        assert!(queue.push(vec![1; MERGE_LIMIT]));
+        assert!(queue.push(vec![2; 1]));
+        assert_eq!(queue.chunk_count(), 2, "the full chunk takes nothing more");
+        assert!(queue.push(vec![3; MERGE_LIMIT + 4000]));
+        assert_eq!(queue.chunk_count(), 3, "a chunk bigger than the limit is queued as it is, not split");
+        let all = read_all(&queue);
+        assert_eq!(all.len(), 2 * MERGE_LIMIT + 4001);
+        assert_eq!((all[MERGE_LIMIT - 1], all[MERGE_LIMIT], all[MERGE_LIMIT + 1]), (1, 2, 3));
+    }
+
+    /// A gap is announced as soon as the reader has caught up, not only when more output arrives: a program that went quiet after the
+    /// terminal fell behind must not leave the user looking at output with a hole in it and no word about it.
+    #[test]
+    fn a_reader_that_catches_up_after_a_gap_is_told_about_it_at_once() {
+        bounded(|| {
+            let queue = ByteQueue::new(8);
+            assert!(queue.push(b"AAAAAA".to_vec()));
+            assert!(!queue.push(b"BBBBBB".to_vec()), "the terminal fell behind");
+            let mut buf = [0u8; 128];
+            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(6), "the reader catches up");
+            match queue.read_until(&mut buf, soon()) {
+                QueueRead::Bytes(count) => assert_eq!(
+                    std::str::from_utf8(&buf[..count]).unwrap(),
+                    "\r\n[SSHelter dropped 6 bytes of output because the terminal fell behind]\r\n"
+                ),
+                other => panic!("the gap must be announced without waiting for more output, got {other:?}"),
+            }
+            assert!(queue.push(b"C".to_vec()));
+            assert_eq!(read_all(&queue), b"C", "the gap is announced once");
+        });
+    }
+
     #[test]
     fn a_full_queue_drops_new_chunks_and_counts_them_instead_of_waiting() {
         bounded(|| {
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::channel::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find value `MERGE_LIMIT` in this scope
error: could not compile `sshelter` (lib test) due to 9 previous errors
```

- [ ] **Step 3: Write the code**

`src-tauri/src/ssh/channel.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/channel.rs
+++ b/src-tauri/src/ssh/channel.rs
@@ -37,14 +37,19 @@ struct QueueState {
     unannounced: u64,
 }
 
+/// Chunks are merged into the last queued chunk while it stays within this many bytes. A writer that sends one byte at a time (a slow
+/// program, or a server doing it on purpose) would otherwise cost a whole `Vec` per byte, about 40 times the bytes it sends.
+pub const MERGE_LIMIT: usize = 16 * 1024;
+
 /// A byte queue with a size limit. The producer (the engine's channel reader) must never wait: russh stalls the whole connection behind a
 /// channel nobody reads. So when the reader is slower than the server (a paused terminal) and the queue is full, new chunks are
-/// discarded and counted instead, and the connection keeps going. The stream says so: the next chunk that is kept is preceded by a
-/// one-line notice that tells how many bytes are missing.
+/// discarded and counted instead, and the connection keeps going. The stream says so with a one-line notice that tells how many bytes
+/// are missing: in front of the next chunk that is kept, or as soon as the reader has caught up, whichever comes first.
 ///
 /// While the queue is open it holds at most `capacity` bytes plus one notice (a notice is 72 bytes plus the digits of the count), and
 /// `close` can add a second one. The exception is an empty queue, which accepts a chunk of any size, so a chunk larger than `capacity` is
-/// taken whole and progress is always possible. The queue has one reading thread: `push` wakes a single waiting reader.
+/// taken whole and progress is always possible. Small chunks are merged (`MERGE_LIMIT`), so the memory the queue uses follows the bytes
+/// it holds, not the number of pushes. The queue has one reading thread: `push` wakes a single waiting reader.
 pub struct ByteQueue {
     state: Mutex<QueueState>,
     ready: Condvar,
@@ -64,9 +69,23 @@ impl ByteQueue {
         format!("\r\n[SSHelter dropped {bytes} bytes of output because the terminal fell behind]\r\n").into_bytes()
     }
 
+    /// Queues `chunk` after the others: merged into the last chunk while that stays within `MERGE_LIMIT`, else as a chunk of its own.
+    /// Merging only ever grows the end of a chunk, so the read position in the first chunk stays valid.
     fn append(state: &mut QueueState, chunk: Vec<u8>) {
         state.bytes += chunk.len();
-        state.chunks.push_back(chunk);
+        match state.chunks.back_mut() {
+            Some(back) if back.len() + chunk.len() <= MERGE_LIMIT => back.extend_from_slice(&chunk),
+            _ => state.chunks.push_back(chunk),
+        }
+    }
+
+    /// Announces a gap the stream has not mentioned yet; the reader has caught up, so there is room for the notice now.
+    fn announce_gap(state: &mut QueueState) {
+        if state.unannounced > 0 {
+            let notice = ByteQueue::notice(state.unannounced);
+            state.unannounced = 0;
+            ByteQueue::append(state, notice);
+        }
     }
 
     /// Appends `chunk` unless the queue is closed or the chunk would grow the queued bytes past `capacity`. The bound is `capacity` plus one
@@ -88,11 +107,7 @@ impl ByteQueue {
             state.unannounced += chunk.len() as u64;
             return false;
         }
-        if state.unannounced > 0 {
-            let notice = ByteQueue::notice(state.unannounced);
-            state.unannounced = 0;
-            ByteQueue::append(&mut state, notice);
-        }
+        ByteQueue::announce_gap(&mut state);
         ByteQueue::append(&mut state, chunk);
         self.ready.notify_one();
         true
@@ -104,11 +119,7 @@ impl ByteQueue {
         if state.closed {
             return;
         }
-        if state.unannounced > 0 {
-            let notice = ByteQueue::notice(state.unannounced);
-            state.unannounced = 0;
-            ByteQueue::append(&mut state, notice);
-        }
+        ByteQueue::announce_gap(&mut state);
         state.closed = true;
         self.ready.notify_all();
     }
@@ -121,6 +132,11 @@ impl ByteQueue {
         }
         let mut state = locked(&self.state);
         loop {
+            // Bytes were dropped and the reader has read everything else: the notice goes out now, not with the next output, which may
+            // never come.
+            if state.chunks.is_empty() {
+                ByteQueue::announce_gap(&mut state);
+            }
             if let Some(front) = state.chunks.front() {
                 let taken = (front.len() - state.front_read).min(buf.len());
                 buf[..taken].copy_from_slice(&front[state.front_read..state.front_read + taken]);
@@ -154,6 +170,12 @@ impl ByteQueue {
     pub fn dropped_bytes(&self) -> u64 {
         locked(&self.state).dropped
     }
+
+    /// How many chunks the queue holds (tests of the merging).
+    #[cfg(test)]
+    fn chunk_count(&self) -> usize {
+        locked(&self.state).chunks.len()
+    }
 }
 
 /// Holds how a shell ended, once. The first value set wins.
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::channel::)
```

Expected: PASS, `test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 1579 filtered out`.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1588 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out` (`ssh::` alone: 171). The only compiler warning is the old `function set_host_enabled is never used` of `src/config/edit.rs`. Then the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/channel.rs
git commit -m "fix(ssh): merge small output chunks and announce a gap as soon as the reader catches up"
```

Expected: `git status --short` lists `src-tauri/src/ssh/channel.rs` only; the `git diff --stat` prints nothing.

---

### Task 2: What the engine tells the broker: a password could still get in, the server's banner, why a shell was refused

**Files:**
- Create: `src-tauri/src/ssh/engine_tests/broker_signals.rs`
- Modify: `src-tauri/src/ssh/engine_tests/mod.rs`, `src-tauri/src/ssh/testing/doubles.rs` (test support)
- Modify: `src-tauri/src/ssh/error.rs`, `src-tauri/src/ssh/fake.rs` (with their tests), `src-tauri/src/ssh/russh_engine.rs`, `src-tauri/src/ssh/traits.rs`, `src-tauri/src/ssh/types.rs`
- Modify: `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` (§6.1)

**Interfaces:**
- Consumes (plan 1a): `ConnectError::AuthFailed { hop, tried, reason }`, `Exit::{Code, Signal, Disconnected}`, the trait `AuthSource` (`public_key`, `sign`, `password`, `interactive`), `FakeEngine`, the test doubles `VaultAuth` and `TestPolicy`, the toy server `ToyServer`/`ToyLogin` (with its `rounds` field) and the scratch-sshd `Server` fixture.
- Produces:
  - `ConnectError::AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String, password_wanted: bool }` — `Display` does not change
  - `Exit::Refused(String)` — the server refused the PTY or the shell request; the connection is still up
  - (trait AuthSource) `fn banner(&self, _hop: &HopRef, _text: &str) {}` — a default method
  - (impl FakeEngine, test code) `pub fn with_banner(self, text: &str) -> FakeEngine`
  - (impl VaultAuth, test code) `pub fn banners(&self) -> Vec<(HopRef, String)>`

What shapes this task:
- R16 (plan 1a's final review, item 1): R8's flow needs to know that a password typed now could get in, and `tried` cannot say it (it lists only what was attempted; a skipped method is not in it). `password_wanted` is true when the server's last list of methods still offers `password` and no password was tried on this connection — the auth source had none, or the login never got to the method. A server that offers no method at all (`no_login_method`) and a password that was tried and refused are both `false`; asking again after a refusal is the broker's call (Task 9), made from `tried`. The fake reports it the same way.
- Banners (R20, item 10): OpenSSH prints the server's `USERAUTH_BANNER`, and some sites require it to be shown. russh hands it to `Handler::auth_banner` on its own task, where the caller's `&dyn AuthSource` cannot go, so the handler keeps it in the hop's shared state and the thread that called `connect` hands it over (`deliver_banners`): before each method is tried, before each keyboard-interactive round's prompts, and after the login ends either way. The text is the server's, unfiltered; whoever shows it removes control characters first (the broker does, Task 8).
- A refused PTY or shell (R20, item 6): plan 1a ended such a shell as `Exit::Disconnected`, which says nothing. The engine sends the PTY request and the shell request with want-reply and the server answers in order, so the reader counts the `Success` replies: a `Failure` before any success refused the PTY, one after it the shell. The connection stays up and the session is still usable. sshd's `PermitTTY no` gives the test a refused PTY.
- R20's last item, a `DISCONNECT` during the handshake (item 11), is left as it is: OpenSSH rarely sends one there (it closes the connection), and the engine already reports what it can. It is listed under "Decisions to confirm".
- Spec §6.1 gets the three additions and a paragraph that says what `password_wanted` and `banner` mean (Step 5).

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/engine_tests/broker_signals.rs`: create

```rust
//! What the engine tells the broker besides a session or an error (plan 1b): whether a password typed now could still get in
//! (`ConnectError::AuthFailed::password_wanted`), the server's banner (`AuthSource::banner`), and why a shell was refused
//! (`Exit::Refused`).

use super::{engine, open_session, ShellProbe, SHELL_SERVER};
use crate::ssh::russh_engine::toy_server::{ToyLogin, ToyServer};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::eventually;
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::{AuthMethod, ConnectError, Exit, Hop, Pty, SshEngine, Target};
use crate::sync::slot_rules::test_keys;

/// The in-process server: it refuses every key and offers password and keyboard-interactive.
fn toy() -> (ToyServer, ToyLogin) {
    let login = ToyLogin { user: "tester".to_string(), password: "correct horse battery staple".to_string(), prompt: "Password: ".to_string(), rounds: None };
    (ToyServer::start(login.clone()), login)
}

fn toy_target(server: &ToyServer, login: &ToyLogin, auth: AuthMethod) -> Target {
    Target { hops: vec![Hop::new("host-toy", "toy", "127.0.0.1", server.port, &login.user, auth)] }
}

/// The key is refused and the auth source has no password, but the server offers the password method: a password the person types
/// now could get in, and the failure says so (the broker asks and connects again with the password first).
#[test]
fn a_refused_key_with_no_password_to_give_says_a_password_is_wanted() {
    let (server, login) = toy();
    // Keyboard-interactive gets a wrong answer, so the login ends refused (`AuthFailed`) rather than abandoned.
    let auth = VaultAuth::new().with_key("k1", &test_keys::plain()).with_answers(&["wrong"]);
    let target = toy_target(&server, &login, AuthMethod::Key { key_id: "k1".to_string() });
    match engine().connect(&target, &*TestPolicy::trusting(), &auth).err().expect("the login fails") {
        ConnectError::AuthFailed { tried, password_wanted, .. } => {
            assert_eq!(tried, vec![AuthMethod::Key { key_id: "k1".to_string() }, AuthMethod::Interactive]);
            assert!(password_wanted, "the server offers password and none was tried");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert_eq!(auth.password_asked_for().len(), 1, "the source was asked during the login and had nothing");
}

/// A password that was tried and refused is not reported as wanted: whether to ask the person for another one is the broker's call,
/// made from `tried`.
#[test]
fn a_password_that_was_tried_is_not_reported_as_wanted() {
    let (server, login) = toy();
    let auth = VaultAuth::new().with_password("wrong").with_answers(&["also wrong"]);
    let error = engine().connect(&toy_target(&server, &login, AuthMethod::Password), &*TestPolicy::trusting(), &auth).err().expect("refused");
    assert!(
        matches!(&error, ConnectError::AuthFailed { tried, password_wanted: false, .. } if *tried == [AuthMethod::Password, AuthMethod::Interactive]),
        "{error:?}"
    );
}

/// A server that does not offer the password method never wants one, and the auth source is not even asked.
#[test]
fn a_server_without_the_password_method_never_wants_a_password() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    // The vault holds a key the server does not know: sshd accepts only its own fresh user key.
    let auth = VaultAuth::new().with_key("other", &test_keys::plain());
    let error = engine().connect(&Target { hops: vec![server.hop("server", "other")] }, &*TestPolicy::trusting(), &auth).err().expect("refused");
    assert!(matches!(&error, ConnectError::AuthFailed { password_wanted: false, .. }), "{error:?}");
    assert!(auth.password_asked_for().is_empty(), "the server does not offer the method, so the source is not asked");
}

/// The text of the server's banner (sshd's `Banner`) reaches the auth source, as OpenSSH shows it to the user.
#[test]
fn the_servers_banner_reaches_the_auth_source() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().expect("temp dir for the banner");
    let banner = dir.path().join("banner");
    std::fs::write(&banner, "Authorized use only.\nActivity is logged.\n").expect("write the banner");
    let server = Server::start(&tools, &[&format!("Banner {}", banner.display())]);
    let auth = server.vault("k1");
    let _session = engine().connect(&server.target("k1"), &*TestPolicy::trusting(), &auth).expect("the engine connects");
    let banners = auth.banners();
    assert_eq!(banners.len(), 1, "{banners:?}");
    assert_eq!((banners[0].0.alias.as_str(), banners[0].1.as_str()), ("server", "Authorized use only.\nActivity is logged.\n"));
}

/// A server that allows no terminal (`PermitTTY no`) refuses the PTY request: the shell ends at once with that reason instead of a bare
/// "disconnected", and the connection stays up.
#[test]
fn a_refused_terminal_ends_the_shell_with_the_reason_and_the_connection_stays_up() {
    let Some(tools) = tools() else { return };
    let mut config = vec!["PermitTTY no"];
    config.extend_from_slice(SHELL_SERVER);
    let server = Server::start(&tools, &config);
    let session = open_session(&engine(), &server);
    let probe = ShellProbe::start(session.shell(Pty { term: "xterm-256color".to_string(), cols: 80, rows: 24 }).expect("the requests go out"));
    eventually("the shell to end", 10, || probe.shell.exited().is_some());
    assert_eq!(probe.shell.exited(), Some(Exit::Refused("the server refused to allocate a terminal (PTY)".to_string())));
    assert!(session.is_alive(), "only the shell was refused");
}
```

`src-tauri/src/ssh/engine_tests/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/engine_tests/mod.rs
+++ b/src-tauri/src/ssh/engine_tests/mod.rs
@@ -1,6 +1,7 @@
 //! Integration tests of the russh engine against a scratch OpenSSH server (own-ssh spec §12). Each test starts its own sshd; a test
 //! returns early, printing "skipped", where the OpenSSH tools are missing (`SSHELTER_REQUIRE_OPENSSH=1` turns that into a failure).
 
+mod broker_signals;
 mod connect;
 mod environment;
 mod exec;
```

`src-tauri/src/ssh/error.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/error.rs
+++ b/src-tauri/src/ssh/error.rs
@@ -147,7 +147,12 @@ mod tests {
             (ConnectError::HostKeyMismatch { hop: hop(), key: key(), pinned: key() }, "The host key of web changed. Connection refused."),
             (ConnectError::HostKeyUnknown { hop: hop(), key: key() }, "The host key of web has not been confirmed yet."),
             (
-                ConnectError::AuthFailed { hop: hop(), tried: vec![AuthMethod::Key { key_id: "k1".into() }, AuthMethod::Password], reason: String::new() },
+                ConnectError::AuthFailed {
+                    hop: hop(),
+                    tried: vec![AuthMethod::Key { key_id: "k1".into() }, AuthMethod::Password],
+                    reason: String::new(),
+                    password_wanted: false,
+                },
                 "Authentication failed for deploy@web (tried: publickey, password).",
             ),
             (ConnectError::AuthAbandoned { hop: hop(), reason: "the prompt timed out".into() }, "Authentication for web was abandoned (the prompt timed out)."),
@@ -165,19 +170,28 @@ mod tests {
             hop: hop(),
             tried: vec![AuthMethod::Key { key_id: "k1".into() }],
             reason: "The server only accepts RSA keys signed with SHA-1, which SSHelter does not do.".into(),
+            password_wanted: false,
         };
         assert_eq!(
             error.to_string(),
             "Authentication failed for deploy@web (tried: publickey). The server only accepts RSA keys signed with SHA-1, which SSHelter does not do."
         );
 
-        let nothing_tried = ConnectError::AuthFailed { hop: hop(), tried: vec![], reason: "The key k1 is not available on this computer.".into() };
+        let nothing_tried =
+            ConnectError::AuthFailed { hop: hop(), tried: vec![], reason: "The key k1 is not available on this computer.".into(), password_wanted: false };
         assert_eq!(
             nothing_tried.to_string(),
             "Authentication failed for deploy@web (no login method could be tried). The key k1 is not available on this computer."
         );
     }
 
+    /// Whether a password could still get in is for the broker, not for the user's sentence.
+    #[test]
+    fn a_wanted_password_does_not_change_the_sentence() {
+        let wanted = ConnectError::AuthFailed { hop: hop(), tried: vec![AuthMethod::Key { key_id: "k1".into() }], reason: String::new(), password_wanted: true };
+        assert_eq!(wanted.to_string(), "Authentication failed for deploy@web (tried: publickey).");
+    }
+
     #[test]
     fn no_common_algorithm_names_both_lists_and_explains_ssh_rsa() {
         let plain = ConnectError::NoCommonHostKeyAlgorithm { hop: hop(), ours: vec!["ssh-ed25519".into()], theirs: vec!["ssh-dss".into()] };
```

`src-tauri/src/ssh/fake.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/fake.rs
+++ b/src-tauri/src/ssh/fake.rs
@@ -431,6 +431,9 @@ mod tests {
             locked(&self.asked).push(format!("interactive {} {}", hop.alias, prompts.len()));
             self.answers.clone().map(|answers| answers.into_iter().map(Zeroizing::new).collect())
         }
+        fn banner(&self, hop: &HopRef, text: &str) {
+            locked(&self.asked).push(format!("banner {} {text}", hop.alias));
+        }
     }
 
     fn connect(engine: &FakeEngine, target: &Target, auth: &Auth) -> Result<Box<dyn Session>, ConnectError> {
@@ -525,7 +528,14 @@ mod tests {
         assert!(matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { tried, .. }) if tried == [AuthMethod::Password]));
 
         let none = Auth::default();
-        assert!(matches!(connect(&engine, &direct("web"), &none), Err(ConnectError::AuthFailed { tried, .. }) if tried.is_empty()), "no password: the method is skipped");
+        assert!(
+            matches!(connect(&engine, &direct("web"), &none), Err(ConnectError::AuthFailed { tried, password_wanted: true, .. }) if tried.is_empty()),
+            "no password: the method is skipped, and a typed one could get in"
+        );
+        assert!(
+            matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { password_wanted: false, .. })),
+            "a password was tried"
+        );
 
         let by_password = Target { hops: vec![Hop::new("id-pw", "pw", "pw.example.com", 22, "deploy", AuthMethod::Password)] };
         let unknown = Policy { accepted: None, pinned: None };
@@ -589,6 +599,14 @@ mod tests {
         assert_eq!(engine.events().last(), Some(&FakeEvent::Closed), "dropping a session closes it");
     }
 
+    #[test]
+    fn a_scripted_banner_is_handed_to_the_auth_source_of_each_hop() {
+        let engine = FakeEngine::new().with_banner("Authorized use only.");
+        let auth = Auth::default();
+        connect(&engine, &Target { hops: vec![hop("bastion"), hop("db")] }, &auth).expect("connects");
+        assert_eq!(*locked(&auth.asked), vec!["banner bastion Authorized use only.".to_string(), "banner db Authorized use only.".to_string()]);
+    }
+
     #[test]
     fn a_chain_with_a_repeated_host_or_no_host_is_a_bad_jump_chain() {
         let engine = FakeEngine::new();
```

`src-tauri/src/ssh/testing/doubles.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/testing/doubles.rs
+++ b/src-tauri/src/ssh/testing/doubles.rs
@@ -95,6 +95,7 @@ pub struct VaultAuth {
     signs: Mutex<Vec<SignCall>>,
     password_asks: Mutex<Vec<HopRef>>,
     prompts: Mutex<Vec<Vec<Prompt>>>,
+    banners: Mutex<Vec<(HopRef, String)>>,
 }
 
 impl VaultAuth {
@@ -111,6 +112,7 @@ impl VaultAuth {
             signs: Mutex::new(Vec::new()),
             password_asks: Mutex::new(Vec::new()),
             prompts: Mutex::new(Vec::new()),
+            banners: Mutex::new(Vec::new()),
         }
     }
 
@@ -176,6 +178,11 @@ impl VaultAuth {
     pub fn prompts_seen(&self) -> Vec<Vec<Prompt>> {
         locked(&self.prompts).clone()
     }
+
+    /// The banners the engine handed over, with the hop that sent each.
+    pub fn banners(&self) -> Vec<(HopRef, String)> {
+        locked(&self.banners).clone()
+    }
 }
 
 impl Default for VaultAuth {
@@ -238,6 +245,10 @@ impl AuthSource for VaultAuth {
         std::thread::sleep(self.answer_delay);
         self.answers.clone().map(|answers| answers.into_iter().map(Zeroizing::new).collect())
     }
+
+    fn banner(&self, hop: &HopRef, text: &str) {
+        locked(&self.banners).push((hop.clone(), text.to_string()));
+    }
 }
 
 #[cfg(test)]
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0407]: method `banner` is not a member of trait `AuthSource`
error: could not compile `sshelter` (lib test) due to 13 previous errors
```

- [ ] **Step 3: Write the code**

`src-tauri/src/ssh/error.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/error.rs
+++ b/src-tauri/src/ssh/error.rs
@@ -25,8 +25,10 @@ pub enum ConnectError {
     NoCommonHostKeyAlgorithm { hop: HopRef, ours: Vec<String>, theirs: Vec<String> },
     /// Every method was refused or could not be tried. `tried` lists the methods that were attempted, possibly none (a key that is not in
     /// the vault, no password to give); `reason` explains what the method list alone does not (for example that the server accepts RSA
-    /// keys only with SHA-1); empty for a plain refusal.
-    AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String },
+    /// keys only with SHA-1); empty for a plain refusal. `password_wanted`: the server still offers the password method and no password
+    /// was tried on this connection (the auth source had none, or the login did not reach the method): a password typed now could get in,
+    /// so the caller can ask for one and connect again with the password method first (spec §6.2 step 4).
+    AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String, password_wanted: bool },
     /// Login stopped on our side (signer failure, cancelled or overdue prompt) and the connection was dropped.
     AuthAbandoned { hop: HopRef, reason: String },
     /// Any other protocol or I/O failure, as text.
@@ -56,7 +58,7 @@ impl fmt::Display for ConnectError {
                 }
                 Ok(())
             }
-            ConnectError::AuthFailed { hop, tried, reason } => {
+            ConnectError::AuthFailed { hop, tried, reason, .. } => {
                 if tried.is_empty() {
                     write!(f, "Authentication failed for {}@{} (no login method could be tried).", hop.user, hop.alias)?;
                 } else {
```

`src-tauri/src/ssh/fake.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/fake.rs
+++ b/src-tauri/src/ssh/fake.rs
@@ -65,6 +65,7 @@ struct Script {
     shell_exit: Exit,
     shell_ends_at_once: bool,
     disconnect: Option<DisconnectReason>,
+    banner: Option<String>,
 }
 
 struct Shared {
@@ -105,6 +106,7 @@ impl FakeEngine {
             shell_exit: Exit::Code(0),
             shell_ends_at_once: false,
             disconnect: None,
+            banner: None,
         };
         FakeEngine { shared: Arc::new(Shared { script: Mutex::new(script), events: Mutex::new(Vec::new()) }) }
     }
@@ -169,6 +171,11 @@ impl FakeEngine {
         self.script(|script| script.disconnect = Some(reason))
     }
 
+    /// Every server sends this banner once its host key is accepted, before the login (`AuthSource::banner`).
+    pub fn with_banner(self, text: &str) -> FakeEngine {
+        self.script(|script| script.banner = Some(text.to_string()))
+    }
+
     /// Everything the code under test has done so far.
     pub fn events(&self) -> Vec<FakeEvent> {
         locked(&self.shared.events).clone()
@@ -191,9 +198,9 @@ fn check_chain(target: &Target) -> Result<(), ConnectError> {
 impl SshEngine for FakeEngine {
     fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
         check_chain(target)?;
-        let (login_default, logins, key_default, keys, scripted_error) = {
+        let (login_default, logins, key_default, keys, scripted_error, banner) = {
             let script = locked(&self.shared.script);
-            (script.login.clone(), script.logins.clone(), script.host_key.clone(), script.host_keys.clone(), script.connect_error.clone())
+            (script.login.clone(), script.logins.clone(), script.host_key.clone(), script.host_keys.clone(), script.connect_error.clone(), script.banner.clone())
         };
         if let Some(error) = scripted_error {
             return Err(error);
@@ -208,6 +215,9 @@ impl SshEngine for FakeEngine {
                 HostKeyVerdict::Unknown => return Err(ConnectError::HostKeyUnknown { hop: reference, key }),
                 HostKeyVerdict::Mismatch { pinned } => return Err(ConnectError::HostKeyMismatch { hop: reference, key, pinned }),
             }
+            if let Some(banner) = &banner {
+                auth.banner(&reference, banner);
+            }
             fake_login(hop, logins.get(&hop.alias).unwrap_or(&login_default), auth, prefetched)?;
         }
         self.shared.record(FakeEvent::Connect { aliases: target.hops.iter().map(|hop| hop.alias.clone()).collect() });
@@ -219,19 +229,20 @@ impl SshEngine for FakeEngine {
 
 fn fake_login(hop: &Hop, login: &FakeLogin, auth: &dyn AuthSource, prefetched: Option<Option<Secret>>) -> Result<(), ConnectError> {
     let reference = hop.reference();
-    let refused = |tried: Vec<AuthMethod>| ConnectError::AuthFailed { hop: reference.clone(), tried, reason: String::new() };
+    // `password_wanted` as the real engine reports it: the server offers the password method and none was tried.
+    let refused = |tried: Vec<AuthMethod>, password_wanted: bool| ConnectError::AuthFailed { hop: reference.clone(), tried, reason: String::new(), password_wanted };
     let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
     match login {
         FakeLogin::Accept => Ok(()),
-        FakeLogin::Refuse => Err(refused(hop.auth_sequence())),
+        FakeLogin::Refuse => Err(refused(hop.auth_sequence(), false)),
         FakeLogin::Signature => {
-            let AuthMethod::Key { key_id } = &hop.auth else { return Err(refused(vec![])) };
+            let AuthMethod::Key { key_id } = &hop.auth else { return Err(refused(vec![], false)) };
             auth.sign(key_id, b"fake-challenge", Some(RsaHash::Sha512)).map(|_| ()).map_err(|error| abandoned(&error.to_string()))
         }
         FakeLogin::Password(expected) => match prefetched.unwrap_or_else(|| auth.password(&reference)) {
-            None => Err(ConnectError::AuthFailed { hop: reference.clone(), tried: vec![], reason: "No password was given.".to_string() }),
+            None => Err(ConnectError::AuthFailed { hop: reference.clone(), tried: vec![], reason: "No password was given.".to_string(), password_wanted: true }),
             Some(given) if given.as_str() == expected => Ok(()),
-            Some(_) => Err(refused(vec![AuthMethod::Password])),
+            Some(_) => Err(refused(vec![AuthMethod::Password], false)),
         },
         FakeLogin::Interactive { prompts, answers } => {
             let deadline = std::time::Instant::now() + Duration::from_secs(60);
@@ -239,7 +250,7 @@ fn fake_login(hop: &Hop, login: &FakeLogin, auth: &dyn AuthSource, prefetched: O
                 None => Err(abandoned("the prompt was cancelled")),
                 Some(given) if given.len() != prompts.len() => Err(abandoned("the answers do not match the prompts")),
                 Some(given) if given.iter().map(|answer| answer.as_str()).eq(answers.iter().map(String::as_str)) => Ok(()),
-                Some(_) => Err(refused(vec![AuthMethod::Interactive])),
+                Some(_) => Err(refused(vec![AuthMethod::Interactive], false)),
             }
         }
     }
```

`src-tauri/src/ssh/russh_engine.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/russh_engine.rs
+++ b/src-tauri/src/ssh/russh_engine.rs
@@ -140,11 +140,27 @@ struct HopShared {
     /// Set by `Handler::disconnected`, just before `ended` is written, when the connection ended because the server had no login method
     /// to offer (russh's `NoAuthMethod`).
     no_login_method: std::sync::atomic::AtomicBool,
+    /// Banners the server sent during the login, not yet handed to the auth source (`deliver_banners`).
+    banners: Mutex<Vec<String>>,
 }
 
 impl HopShared {
     fn new() -> Arc<HopShared> {
-        Arc::new(HopShared { observed: Mutex::new(None), ended: Mutex::new(None), no_login_method: std::sync::atomic::AtomicBool::new(false) })
+        Arc::new(HopShared {
+            observed: Mutex::new(None),
+            ended: Mutex::new(None),
+            no_login_method: std::sync::atomic::AtomicBool::new(false),
+            banners: Mutex::new(Vec::new()),
+        })
+    }
+}
+
+/// Hands the banners the server has sent so far to the auth source, on the thread that called `connect` (the handler runs on russh's
+/// task, where the caller's `&dyn AuthSource` cannot go).
+fn deliver_banners(shared: &HopShared, auth: &dyn AuthSource, hop: &HopRef) {
+    let banners = std::mem::take(&mut *locked(&shared.banners));
+    for banner in banners {
+        auth.banner(hop, &banner);
     }
 }
 
@@ -187,6 +203,12 @@ impl Handler for EngineHandler {
         Ok(trusted)
     }
 
+    /// Keeps the banner for the connect thread, which hands it to the auth source (`deliver_banners`); nothing waits here.
+    async fn auth_banner(&mut self, banner: &str, _session: &mut client::Session) -> Result<(), Self::Error> {
+        locked(&self.shared.banners).push(banner.to_string());
+        Ok(())
+    }
+
     async fn disconnected(&mut self, reason: RusshDisconnect<Self::Error>) -> Result<(), Self::Error> {
         let record = match &reason {
             RusshDisconnect::ReceivedDisconnect(info) => (DisconnectKind::ClosedByPeer, format!("the server closed the connection: {}", info.message)),
@@ -400,7 +422,9 @@ async fn connect_one(
     // unauthenticated connection waiting (the server's login grace time runs, and russh spins while it idles).
     let password = (hop.auth == AuthMethod::Password).then(|| auth.password(&reference));
     let (mut handle, shared) = connect_hop(hop, via, host_keys).await?;
-    authenticate(hop, &mut handle, &shared, auth, password, options).await?;
+    let login = authenticate(hop, &mut handle, &shared, auth, password, options).await;
+    deliver_banners(&shared, auth, &reference);
+    login?;
     Ok(Established { hop: reference, handle, shared })
 }
 
@@ -645,7 +669,7 @@ async fn classify_empty_answer(shared: &HopShared, closed: impl Fn() -> bool, wa
 /// The failure for a server with no login method to offer, with what the methods that were skipped had to say.
 fn no_login_method(hop: &HopRef, tried: Vec<AuthMethod>, mut reasons: Vec<String>) -> ConnectError {
     reasons.push("The server offers no login method.".to_string());
-    ConnectError::AuthFailed { hop: hop.clone(), tried, reason: reasons.join(" ") }
+    ConnectError::AuthFailed { hop: hop.clone(), tried, reason: reasons.join(" "), password_wanted: false }
 }
 
 /// The failure for a connection that went away while the login was under way.
@@ -693,6 +717,8 @@ async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, shared: &Ho
         if offered.as_ref().is_some_and(|offered| !offered.contains(&method_kind(&method))) {
             continue;
         }
+        // A banner arrives with the server's answer to a login request; it is shown before the next prompt.
+        deliver_banners(shared, auth, &reference);
         let step = match &method {
             AuthMethod::Key { key_id } => 'key: {
                 let Some(line) = auth.public_key(key_id) else {
@@ -766,6 +792,7 @@ async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, shared: &Ho
                             } else {
                                 let prompts: Vec<Prompt> = prompts.into_iter().map(|prompt| Prompt { text: prompt.prompt, echo: prompt.echo }).collect();
                                 let deadline = std::time::Instant::now() + prompt_wait.min(LONGEST_TIMEOUT);
+                                deliver_banners(shared, auth, &reference);
                                 let Some(answers) = auth.interactive(&reference, &prompts, deadline) else { return Err(abandoned("the prompt was cancelled")) };
                                 if std::time::Instant::now() > deadline {
                                     return Err(abandoned("the prompt was answered after its deadline"));
@@ -798,7 +825,10 @@ async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, shared: &Ho
             Step::Skipped => {}
         }
     }
-    Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" ") })
+    // The server still offers the password method and no password was tried: one typed now could get in (the broker asks and connects
+    // again with the password first, rather than have a person type while this connection waits).
+    let password_wanted = offered.as_ref().is_some_and(|offered| offered.contains(&MethodKind::Password)) && !tried.contains(&AuthMethod::Password);
+    Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" "), password_wanted })
 }
 
 // ---------------------------------------------------------------------------------------------------------------------------------
@@ -1101,7 +1131,10 @@ impl Drop for RusshShellInput {
 /// output into the queue without ever waiting for the consumer, and when the channel ends it records how, then closes the queue, in
 /// that order, so a consumer that sees the end of the output finds the exit.
 async fn read_shell(mut read_half: ChannelReadHalf, write_half: Arc<ChannelWriteHalf<Msg>>, queue: Arc<ByteQueue>, exit: Arc<ExitCell>, mut closed_by_us: watch::Receiver<bool>) {
-    let (mut code, mut signal, mut refused) = (None, None, false);
+    let (mut code, mut signal, mut refused) = (None, None, None);
+    // The PTY request and the shell request both ask for a reply, and a server replies in the order of the requests: the first reply is
+    // the PTY's.
+    let mut replies = 0;
     loop {
         let message = tokio::select! {
             message = read_half.wait() => message,
@@ -1114,18 +1147,20 @@ async fn read_shell(mut read_half: ChannelReadHalf, write_half: Arc<ChannelWrite
             }
             ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
             ChannelMsg::ExitSignal { signal_name: name, .. } => signal = Some(signal_name(&name)),
+            ChannelMsg::Success => replies += 1,
             ChannelMsg::Failure => {
-                refused = true;
+                refused = Some(if replies == 0 { "the server refused to allocate a terminal (PTY)" } else { "the server refused to start a shell" });
                 let _ = sent(write_half.close()).await;
                 break;
             }
             _ => {}
         }
     }
-    exit.set(match (signal, code) {
-        (Some(signal), _) => Exit::Signal(signal),
-        (None, Some(code)) if !refused => Exit::Code(code),
-        _ => Exit::Disconnected,
+    exit.set(match (signal, code, refused) {
+        (Some(signal), _, _) => Exit::Signal(signal),
+        (None, _, Some(refused)) => Exit::Refused(refused.to_string()),
+        (None, Some(code), None) => Exit::Code(code),
+        (None, None, None) => Exit::Disconnected,
     });
     queue.close();
 }
```

`src-tauri/src/ssh/traits.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/traits.rs
+++ b/src-tauri/src/ssh/traits.rs
@@ -111,4 +111,9 @@ pub trait AuthSource: Send + Sync {
     /// The answers to one keyboard-interactive round, one per prompt, given before `deadline`; `None` abandons the login and the engine
     /// drops the connection. An answer that arrives after the deadline is not used either.
     fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>>;
+
+    /// The banner `hop`'s server sent during the login (SSH_MSG_USERAUTH_BANNER, sshd's `Banner`), as the server wrote it: the text comes
+    /// from the server, so whoever shows it removes control characters first. Handed over before the next prompt and at the end of the
+    /// login at the latest. Must be quick. The default drops it.
+    fn banner(&self, _hop: &HopRef, _text: &str) {}
 }
```

`src-tauri/src/ssh/types.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/types.rs
+++ b/src-tauri/src/ssh/types.rs
@@ -239,6 +239,9 @@ pub enum Exit {
     Code(u32),
     /// Killed by this signal (name without the `SIG` prefix).
     Signal(String),
+    /// The server refused the terminal (PTY) or the shell request, and the channel was closed; the text says which ("the server refused
+    /// to allocate a terminal (PTY)", "the server refused to start a shell"). The connection is still up.
+    Refused(String),
     /// The channel ended without a status: the connection was lost, or the server closed the channel.
     Disconnected,
 }
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::)
```

Expected: PASS, `test result: ok. 178 passed; 0 failed; 0 ignored; 0 measured; 1419 filtered out`. Then the leftover check prints 0, 0 and 0.

- [ ] **Step 5: Record the three additions in the spec**

`docs/superpowers/specs/2026-10-10-own-ssh-client-design.md`: apply this patch

````diff
--- a/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
+++ b/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
@@ -156,6 +156,7 @@ pub trait AuthSource: Send + Sync {
     fn public_key(&self, key_id: &str) -> Option<String>;                    // 該金鑰的 OpenSSH 公鑰行(公鑰登入要先送公鑰);None = 金鑰不存在
     fn password(&self, hop: &HopRef) -> Option<Secret>;                      // 已有的密碼(keychain 或剛問到的);None = 不試密碼
     fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>>; // 在 deadline 前回答;None = 放棄 → 引擎丟掉連線
+    fn banner(&self, hop: &HopRef, text: &str) {}                            // 伺服器登入時送的 banner(sshd 的 Banner);預設丟掉;顯示前去掉控制字元(第 1b 期)
 }
 
 pub struct Target { pub hops: Vec<Hop> }   // 依序經過,最後一個是目標;每一跳自帶設定
@@ -174,17 +175,19 @@ pub enum ConnectError {
     HostKeyUnknown { hop: HopRef, key: HostKey },
     HostKeyMismatch { hop: HopRef, key: HostKey, pinned: HostKey },
     NoCommonHostKeyAlgorithm { hop: HopRef, ours: Vec<String>, theirs: Vec<String> },
-    AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String }, // 含「RSA 只能 SHA-1」
+    AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String, password_wanted: bool }, // 含「RSA 只能 SHA-1」;password_wanted 見下方(第 1b 期)
     AuthAbandoned { hop: HopRef, reason: String },                      // sign 出錯、提示逾時或取消:連線已丟掉
     Protocol { hop: HopRef, text: String },                             // russh 的錯誤文字,不含秘密
 }
 pub struct ExecResult { pub ended: Ended, pub exit_code: Option<u32>, pub signal: Option<String>, pub stdout: Vec<u8>, pub stderr: Vec<u8>, pub truncated: bool }
 pub enum Ended { Exited, Signaled, TimedOut, Truncated, Disconnected } // Truncated:引擎在 output_cap 關掉 channel,結束碼不明、連線仍可用
-pub enum Exit { Code(u32), Signal(String), Disconnected }
+pub enum Exit { Code(u32), Signal(String), Refused(String), Disconnected } // Refused:伺服器拒絕 PTY 或 shell 的請求,連線仍在(第 1b 期)
 ```
 
 `Target` 是 host 記錄解析後的結果(含跳板鏈)。`HostKeyPolicy` 與 `AuthSource` 由 broker 實作:它決定提示送給誰(決策 7)。引擎不碰保管庫、不碰 UI。
 
+(第 1b 期)`AuthFailed` 的 `password_wanted`:伺服器最後仍提供 `password` 方法,而這條連線沒有試過密碼(`AuthSource::password` 沒有給,或登入的順序沒走到密碼)——現在輸入的密碼有機會登入。broker 據此問人,再以密碼優先重連;不在連線開著時等人輸入密碼(那會讓 russh 空轉,§6.2 第 4 步)。`banner`:伺服器在登入途中送的 banner,引擎在連線的執行緒上、下一個提示之前(最晚在登入結束時)交給 `AuthSource`。
+
 `sign` 的合約(第 0 期):russh 的 `Signer::auth_sign(&mut self, &AgentIdentity, Option<HashAlg>, Vec<u8>)` 把待簽緩衝區與**呼叫端選的** `hash_alg` 原樣交給簽章器,russh 自己不檢查;引擎把 `hash_alg` 轉成 `rsa_hash` 傳給 `sign`,RSA 金鑰而 `rsa_hash` 是 `None`(伺服器只接受 SHA-1)時引擎不呼叫 `sign`、直接回 `ConnectError::AuthFailed` 並說明原因。`sign`、`password`、`interactive` 都要**快**:russh 在等簽章與等 keyboard-interactive 的回答時把整條 session 停住、不讀 socket,等待期間伺服器的 `LoginGraceTime` 照跑,`disconnect()` 也變成 no-op(§6.2 第 4 步)。passphrase 的輸入、保管庫解鎖、核准等使用者互動都在呼叫引擎之前做完;keyboard-interactive 的提示本來就在認證途中回答,所以有逾時(§6.2 第 4 步)。
 
 ### 6.2 流程
````

- [ ] **Step 6: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1595 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 7: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add docs/superpowers/specs/2026-10-10-own-ssh-client-design.md \
  src-tauri/src/ssh/engine_tests/broker_signals.rs \
  src-tauri/src/ssh/engine_tests/mod.rs \
  src-tauri/src/ssh/error.rs \
  src-tauri/src/ssh/fake.rs \
  src-tauri/src/ssh/russh_engine.rs \
  src-tauri/src/ssh/testing/doubles.rs \
  src-tauri/src/ssh/traits.rs \
  src-tauri/src/ssh/types.rs
git commit -m "feat(ssh): tell the broker when a password could still get in, pass on the server's banner, and say why a shell was refused"
```

Expected: `git status --short` lists the nine files of this task; the `git diff --stat` prints nothing.

---

### Task 3: A fake engine that behaves like the real one, and the scenarios that check it

**Files:**
- Modify: `src-tauri/src/ssh/fake.rs` (the login model, the shells and a disconnect hook; with its tests)
- Modify: `src-tauri/src/ssh/mod.rs` (`#[cfg(test)] mod parity_tests;`)
- Create: `src-tauri/src/ssh/parity_tests.rs`

**Interfaces:**
- Consumes (Task 2): `ConnectError::AuthFailed { …, password_wanted }`, `FakeEngine::with_banner`; (plan 1a) the real engine (`RusshEngine`), the toy server, the scratch-sshd fixture and the proxy that cuts a link (`testing::proxy::{Proxy, Mode}`).
- Produces (`ssh/fake.rs`, test code; replaces `FakeLogin::{Refuse, Signature, Password, Interactive}`):
  - `pub enum FakeLogin { Accept, Server(FakeMethods) }`
  - `pub struct FakeMethods { pub key: bool, pub password: Option<String>, pub interactive: Option<FakeRound> }` with `FakeMethods::{key(), password(&str), interactive(prompt: &str, answer: &str), and_interactive(self, prompt: &str, answer: &str), none()}`
  - `pub struct FakeRound { pub prompts: Vec<Prompt>, pub answers: Vec<String> }`
  - (impl FakeEngine) `pub fn with_shell_error(self, error: SessionError) -> FakeEngine`, `pub fn with_write_errors(self, errors: Vec<SessionError>) -> FakeEngine`, `pub fn with_prompt_wait(self, wait: Duration) -> FakeEngine`, `pub fn shells(&self) -> Vec<FakeShell>`, `pub fn disconnect_now(&self, reason: DisconnectReason)`
  - `pub struct FakeShell` (the server's side of an open shell), `FakeShell::print(&self, bytes: &[u8])`, `FakeShell::end(&self, exit: Exit)`
  - Changed behaviour: `failing_with(error)` fails on the hop the error names, after that hop's password was fetched; a shell the code under test closes ends as `Exit::Disconnected`; `with_shell_exit` is how a shell ends by itself (`with_shell_ending_at_once`); writes fail with `SessionError::Closed` once the session is over.

What shapes this task:
- R18 (plan 1a's final review, item 3) lists where the fake and the real engine differ in what the broker leans on: (a) a shell we close (the fake: the scripted exit, default `Code(0)`; real: `Exit::Disconnected`), (b) writes after the session closed (fake `Ok`, real `Err(Closed)`), (c) no way to cut a live session, (d) `failing_with` returned before the password of a password-first hop was fetched, (e) the keyboard-interactive deadline (fake: a fixed minute, late answers taken; real: 4 × the connect timeout, at least 60 s, late answers abandon), (f) a missing password ended the fake's login where the real engine goes on to keyboard-interactive, (g) the fake never gave `SessionError::Timeout` or `Channel`. Each is fixed in the fake, as far as the broker relies on it, and pinned by a scenario that runs the same steps against both engines (`parity_tests.rs`).
- The fake's login is now the real engine's sequence (`russh_engine::authenticate`) against a scripted server (`FakeMethods`): the hop's methods in order, a method the server has said it does not offer is skipped without asking the auth source, a refusal moves on, a method the source has nothing for is skipped, and the end is `AuthFailed` with `tried`, the reasons and `password_wanted`. A failed signature, a cancelled or late prompt and a wrong number of answers abandon the login.
- The parity scenarios use the real engine where it can run here: the in-process toy server for passwords and keyboard-interactive, a scratch sshd for host keys, shells and a cut link (the proxy). The fake side scripts the same server.
- Step 7 breaks five of the fixed differences one at a time and watches the tests catch each (the same check was made while writing the plan).

- [ ] **Step 1: Write the tests**

`src-tauri/src/ssh/fake.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/fake.rs
+++ b/src-tauri/src/ssh/fake.rs
@@ -392,6 +392,10 @@ mod tests {
         Hop::new(&format!("id-{alias}"), alias, &format!("{alias}.example.com"), 22, "deploy", AuthMethod::Key { key_id: format!("key-{alias}") })
     }
 
+    fn password_first(alias: &str) -> Hop {
+        Hop::new(&format!("id-{alias}"), alias, &format!("{alias}.example.com"), 22, "deploy", AuthMethod::Password)
+    }
+
     /// Pins one fingerprint; everything else is unknown, or a mismatch when `pinned` is set.
     struct Policy {
         accepted: Option<String>,
@@ -455,10 +459,18 @@ mod tests {
         Target { hops: vec![hop(alias)] }
     }
 
+    fn asked(auth: &Auth) -> Vec<String> {
+        locked(&auth.asked).clone()
+    }
+
     fn exec(session: &dyn Session, command: &str) -> ExecResult {
         session.exec(command, SHORT, 1024).unwrap()
     }
 
+    fn server(methods: FakeMethods) -> FakeEngine {
+        FakeEngine::new().with_login(FakeLogin::Server(methods))
+    }
+
     #[test]
     fn by_default_everything_succeeds_and_the_calls_are_recorded() {
         let engine = FakeEngine::new();
@@ -528,45 +540,52 @@ mod tests {
         }
     }
 
+    /// The real engine's sequence against a server that offers only passwords: the key goes first and is refused, then the password.
     #[test]
-    fn a_password_login_asks_the_auth_source_and_checks_the_answer() {
-        let engine = FakeEngine::new().with_login(FakeLogin::Password("hunter2".into()));
+    fn a_password_server_refuses_the_key_then_checks_the_password_and_says_when_one_is_wanted() {
+        let engine = server(FakeMethods::password("hunter2"));
         let right = Auth { password: Some("hunter2".into()), ..Auth::default() };
         assert!(connect(&engine, &direct("web"), &right).is_ok());
-        assert_eq!(*locked(&right.asked), vec!["password web".to_string()]);
+        assert_eq!(asked(&right), ["public_key key-web", "password web"]);
 
+        let key = AuthMethod::Key { key_id: "key-web".into() };
         let wrong = Auth { password: Some("letmein".into()), ..Auth::default() };
-        assert!(matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { tried, .. }) if tried == [AuthMethod::Password]));
+        assert!(
+            matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { tried, password_wanted: false, .. }) if tried == [key.clone(), AuthMethod::Password])
+        );
 
         let none = Auth::default();
         assert!(
-            matches!(connect(&engine, &direct("web"), &none), Err(ConnectError::AuthFailed { tried, password_wanted: true, .. }) if tried.is_empty()),
+            matches!(connect(&engine, &direct("web"), &none), Err(ConnectError::AuthFailed { tried, password_wanted: true, .. }) if tried == [key]),
             "no password: the method is skipped, and a typed one could get in"
         );
-        assert!(
-            matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { password_wanted: false, .. })),
-            "a password was tried"
-        );
 
-        let by_password = Target { hops: vec![Hop::new("id-pw", "pw", "pw.example.com", 22, "deploy", AuthMethod::Password)] };
+        let by_password = Target { hops: vec![password_first("pw")] };
         let unknown = Policy { accepted: None, pinned: None };
-        let asked = Auth { password: Some("hunter2".into()), ..Auth::default() };
-        assert!(matches!(engine.connect(&by_password, &unknown, &asked), Err(ConnectError::HostKeyUnknown { .. })));
-        assert_eq!(*locked(&asked.asked), vec!["password pw".to_string()], "a hop that starts with the password method is asked before its host key is looked at");
+        let asked_first = Auth { password: Some("hunter2".into()), ..Auth::default() };
+        assert!(matches!(engine.connect(&by_password, &unknown, &asked_first), Err(ConnectError::HostKeyUnknown { .. })));
+        assert_eq!(asked(&asked_first), ["password pw"], "a hop that starts with the password method is asked before its host key is looked at");
+        let once = Auth { password: Some("hunter2".into()), ..Auth::default() };
+        assert!(connect(&engine, &by_password, &once).is_ok());
+        assert_eq!(asked(&once), ["password pw"], "asked once, before the host key, and not again during the login");
+    }
 
-        // With the host key trusted the same hop logs in on the password it was asked for first, and is not asked again during the login.
-        let asked_once = Auth { password: Some("hunter2".into()), ..Auth::default() };
-        assert!(connect(&engine, &by_password, &asked_once).is_ok());
-        assert_eq!(*locked(&asked_once.asked), vec!["password pw".to_string()], "asked once, before the host key, and not again during the login");
+    /// A password nobody has is skipped and keyboard-interactive comes next, when the server offers it, as in the real engine.
+    #[test]
+    fn a_missing_password_goes_on_to_keyboard_interactive() {
+        let engine = server(FakeMethods::password("hunter2").and_interactive("Password: ", "hunter2"));
+        let auth = Auth { answers: Some(vec!["hunter2".into()]), ..Auth::default() };
+        connect(&engine, &Target { hops: vec![password_first("pw")] }, &auth).expect("keyboard-interactive gets in");
+        assert_eq!(asked(&auth), ["password pw", "interactive pw 1"]);
     }
 
     #[test]
-    fn a_keyboard_interactive_login_sends_the_prompts_and_compares_the_answers() {
+    fn a_keyboard_interactive_server_sends_the_prompts_and_compares_the_answers() {
         let prompts = vec![Prompt { text: "Verification code: ".into(), echo: true }];
-        let engine = FakeEngine::new().with_login(FakeLogin::Interactive { prompts, answers: vec!["123456".into()] });
+        let engine = server(FakeMethods { interactive: Some(FakeRound { prompts, answers: vec!["123456".into()] }), ..FakeMethods::default() });
         let right = Auth { answers: Some(vec!["123456".into()]), ..Auth::default() };
         assert!(connect(&engine, &direct("web"), &right).is_ok());
-        assert_eq!(*locked(&right.asked), vec!["interactive web 1".to_string()]);
+        assert_eq!(asked(&right), ["public_key key-web", "interactive web 1"], "the password method is not offered, so it is not asked for");
         let wrong = Auth { answers: Some(vec!["000000".into()]), ..Auth::default() };
         assert!(matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { .. })));
         assert!(matches!(connect(&engine, &direct("web"), &Auth::default()), Err(ConnectError::AuthAbandoned { .. })), "a cancelled prompt abandons the login");
@@ -581,25 +600,72 @@ mod tests {
         }
     }
 
+    /// Records how long `interactive` was given, then answers after `delay`.
+    struct Clocked {
+        delay: Duration,
+        given: Mutex<Vec<Duration>>,
+    }
+
+    impl AuthSource for Clocked {
+        fn public_key(&self, _key_id: &str) -> Option<String> {
+            None
+        }
+        fn sign(&self, _key_id: &str, _data: &[u8], _rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
+            Err(AuthError::KeyUnavailable("none".into()))
+        }
+        fn password(&self, _hop: &HopRef) -> Option<Secret> {
+            None
+        }
+        fn interactive(&self, _hop: &HopRef, _prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
+            locked(&self.given).push(deadline.saturating_duration_since(Instant::now()));
+            std::thread::sleep(self.delay);
+            Some(vec![Zeroizing::new("123456".to_string())])
+        }
+    }
+
+    /// As in the real engine: a person gets 4 × the hop's connect timeout and at least a minute, and an answer after the deadline is not used.
     #[test]
-    fn a_signature_login_asks_for_the_key_of_the_hop_and_a_refusal_abandons_it() {
-        let engine = FakeEngine::new().with_login(FakeLogin::Signature);
+    fn a_prompt_gets_four_connect_timeouts_and_at_least_a_minute_and_a_late_answer_abandons_the_login() {
+        let engine = server(FakeMethods::interactive("Code: ", "123456"));
+        let auth = Clocked { delay: Duration::ZERO, given: Mutex::new(Vec::new()) };
+        for connect_timeout in [Duration::from_secs(1), Duration::from_secs(20), Duration::MAX] {
+            let mut hop = Hop::new("id-mfa", "mfa", "mfa.example.com", 22, "deploy", AuthMethod::Interactive);
+            hop.connect_timeout = connect_timeout;
+            engine.connect(&Target { hops: vec![hop] }, &trusting(), &auth).expect("the right code gets in");
+        }
+        let given = locked(&auth.given).clone();
+        assert!(given[0] > Duration::from_secs(59) && given[0] <= Duration::from_secs(60), "{given:?}");
+        assert!(given[1] > Duration::from_secs(79) && given[1] <= Duration::from_secs(80), "{given:?}");
+        assert!(given[2] > Duration::from_secs(60 * 60 * 24 * 364), "an absurd connect timeout saturates instead of panicking: {given:?}");
+
+        let late = server(FakeMethods::interactive("Code: ", "123456")).with_prompt_wait(Duration::from_millis(50));
+        let slow = Clocked { delay: Duration::from_millis(200), given: Mutex::new(Vec::new()) };
+        let target = Target { hops: vec![Hop::new("id-mfa", "mfa", "mfa.example.com", 22, "deploy", AuthMethod::Interactive)] };
+        match late.connect(&target, &trusting(), &slow) {
+            Err(ConnectError::AuthAbandoned { reason, .. }) => assert_eq!(reason, "the prompt was answered after its deadline"),
+            other => panic!("expected the late answer to abandon the login, got {:?}", other.err()),
+        }
+    }
+
+    #[test]
+    fn a_key_server_asks_for_a_signature_with_the_key_of_the_hop_and_a_failed_signature_abandons_the_login() {
+        let engine = server(FakeMethods::key());
         let auth = Auth::default();
         assert!(connect(&engine, &direct("web"), &auth).is_ok());
-        assert_eq!(*locked(&auth.asked), vec!["sign key-web".to_string()]);
+        assert_eq!(asked(&auth), ["public_key key-web", "sign key-web"]);
         let locked_vault = Auth { sign_fails: true, ..Auth::default() };
         assert!(matches!(connect(&engine, &direct("web"), &locked_vault), Err(ConnectError::AuthAbandoned { .. })));
     }
 
     #[test]
     fn a_jump_chain_is_checked_hop_by_hop_and_each_hop_can_be_scripted() {
-        let engine = FakeEngine::new().with_login_for("bastion", FakeLogin::Refuse);
+        let engine = FakeEngine::new().with_login_for("bastion", FakeLogin::Server(FakeMethods::none()));
         let target = Target { hops: vec![hop("bastion"), hop("db")] };
         match connect(&engine, &target, &Auth::default()) {
-            Err(ConnectError::AuthFailed { hop, tried, .. }) => {
+            Err(ConnectError::AuthFailed { hop, tried, reason, password_wanted }) => {
                 assert_eq!(hop.alias, "bastion");
-                assert_eq!(tried, target.hops[0].auth_sequence(), "a refusal has tried every method of the hop's sequence");
-                assert_eq!(tried.len(), 3, "key, password, keyboard-interactive");
+                assert_eq!(tried, [AuthMethod::Key { key_id: "key-bastion".into() }]);
+                assert_eq!((reason.as_str(), password_wanted), ("The server offers no login method.", false));
             }
             other => panic!("expected the bastion to refuse, got {:?}", other.err()),
         }
@@ -610,14 +676,6 @@ mod tests {
         assert_eq!(engine.events().last(), Some(&FakeEvent::Closed), "dropping a session closes it");
     }
 
-    #[test]
-    fn a_scripted_banner_is_handed_to_the_auth_source_of_each_hop() {
-        let engine = FakeEngine::new().with_banner("Authorized use only.");
-        let auth = Auth::default();
-        connect(&engine, &Target { hops: vec![hop("bastion"), hop("db")] }, &auth).expect("connects");
-        assert_eq!(*locked(&auth.asked), vec!["banner bastion Authorized use only.".to_string(), "banner db Authorized use only.".to_string()]);
-    }
-
     #[test]
     fn a_chain_with_a_repeated_host_or_no_host_is_a_bad_jump_chain() {
         let engine = FakeEngine::new();
@@ -626,11 +684,19 @@ mod tests {
         assert!(matches!(connect(&engine, &Target { hops: vec![] }, &Auth::default()), Err(ConnectError::BadJumpChain { .. })));
     }
 
+    /// The real engine asks a password-first hop for its password before it opens the connection, so a host that turns out to be
+    /// unreachable has been asked already; the fake fails on the hop the error names, after that question.
     #[test]
-    fn a_scripted_connect_failure_is_returned_as_it_is() {
+    fn a_scripted_connect_failure_comes_on_its_hop_after_that_hops_password_was_asked_for() {
         let error = ConnectError::Unreachable { hop: hop("web").reference(), reason: "connection refused".into() };
         let engine = FakeEngine::new().failing_with(error.clone());
         assert_eq!(connect(&engine, &direct("web"), &Auth::default()).err(), Some(error));
+
+        let unreachable = ConnectError::Unreachable { hop: password_first("pw").reference(), reason: "connection refused".into() };
+        let engine = FakeEngine::new().failing_with(unreachable.clone()).with_banner("hello");
+        let auth = Auth { password: Some("hunter2".into()), ..Auth::default() };
+        assert_eq!(connect(&engine, &Target { hops: vec![hop("bastion"), password_first("pw")] }, &auth).err(), Some(unreachable));
+        assert_eq!(asked(&auth), ["banner bastion hello", "password pw"], "the jump host got in, the destination's password was asked for, then it failed");
     }
 
     /// Runs a test body on its own thread and gives it 10 s: `ShellChannel::read` has no deadline, so a fake that stopped closing its
@@ -654,19 +720,23 @@ mod tests {
         buf[..count].to_vec()
     }
 
+    fn pty() -> Pty {
+        Pty { term: "xterm-256color".into(), cols: 80, rows: 24 }
+    }
+
     #[test]
-    fn a_shell_prints_its_script_records_the_input_and_ends_when_closed() {
+    fn a_shell_prints_its_script_records_the_input_and_ends_as_disconnected_when_we_close_it() {
         bounded(|| {
             let engine = FakeEngine::new().with_shell_output(b"welcome\r\n").with_shell_exit(Exit::Code(7));
             let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
-            let shell = session.shell(Pty { term: "xterm-256color".into(), cols: 80, rows: 24 }).unwrap();
+            let shell = session.shell(pty()).unwrap();
             assert_eq!(read_some(shell.as_ref()), b"welcome\r\n");
             shell.write(b"ls\n").unwrap();
             shell.window_change(100, 30).unwrap();
             assert_eq!(shell.exited(), None);
             shell.close();
             assert_eq!(read_some(shell.as_ref()), b"", "a closed shell reads 0");
-            assert_eq!(shell.exited(), Some(Exit::Code(7)));
+            assert_eq!(shell.exited(), Some(Exit::Disconnected), "a channel we close ends without a status, as with the real engine");
             assert_eq!(
                 engine.events(),
                 vec![
@@ -692,6 +762,25 @@ mod tests {
         });
     }
 
+    /// A test plays the server: it prints into a running shell and ends it with the status it chooses.
+    #[test]
+    fn a_test_can_print_into_a_running_shell_and_end_it() {
+        bounded(|| {
+            let engine = FakeEngine::new();
+            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
+            let shell = session.shell(pty()).unwrap();
+            let remote = engine.shells().pop().expect("the shell's remote side");
+            remote.print(b"$ ");
+            assert_eq!(read_some(shell.as_ref()), b"$ ");
+            remote.print(b"logout\r\n");
+            remote.end(Exit::Code(3));
+            assert_eq!(read_some(shell.as_ref()), b"logout\r\n", "what was printed before the end is still read");
+            assert_eq!(read_some(shell.as_ref()), b"");
+            assert_eq!(shell.exited(), Some(Exit::Code(3)));
+            assert!(session.is_alive(), "the shell ended, the connection did not");
+        });
+    }
+
     #[test]
     fn a_scripted_disconnect_makes_every_call_fail_and_say_why() {
         let reason = DisconnectReason { hop: hop("web").reference(), kind: DisconnectKind::KeepaliveTimeout, detail: "no answer".into() };
@@ -703,6 +792,55 @@ mod tests {
         assert!(matches!(session.shell(Pty { term: "dumb".into(), cols: 80, rows: 24 }), Err(SessionError::Closed)));
     }
 
+    /// The link goes away in the middle of a session: the shells end after what they printed, input fails, and the reason is the one given.
+    #[test]
+    fn a_disconnect_now_ends_the_live_sessions_and_their_shells_and_says_why() {
+        bounded(|| {
+            let engine = FakeEngine::new();
+            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
+            let shell = session.shell(pty()).unwrap();
+            engine.shells()[0].print(b"half a line");
+            let reason = DisconnectReason { hop: hop("web").reference(), kind: DisconnectKind::ConnectionLost, detail: "connection reset by peer".into() };
+            engine.disconnect_now(reason.clone());
+            assert_eq!(read_some(shell.as_ref()), b"half a line");
+            assert_eq!(read_some(shell.as_ref()), b"");
+            assert_eq!(shell.exited(), Some(Exit::Disconnected));
+            assert!(!session.is_alive());
+            assert_eq!(session.disconnect_reason(), Some(reason));
+            assert_eq!(shell.write(b"x"), Err(SessionError::Closed));
+            assert!(!engine.events().contains(&FakeEvent::Closed), "the connection was lost, not closed by us");
+        });
+    }
+
+    /// As with the real engine: input to a shell fails with `Closed` once the session is over, but a shell we closed ourselves still
+    /// takes it; scripted write errors (a link that does not take the input) come first and record nothing.
+    #[test]
+    fn input_fails_once_the_session_is_over_and_scripted_errors_come_first() {
+        bounded(|| {
+            let engine = FakeEngine::new().with_write_errors(vec![SessionError::Timeout]);
+            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
+            let first = session.shell(pty()).unwrap();
+            assert_eq!(first.write(b"lost"), Err(SessionError::Timeout));
+            assert_eq!(first.write(b"kept"), Ok(()));
+            first.close();
+            assert_eq!(first.write(b"after our close"), Ok(()), "the real engine takes it too");
+            let second = session.shell(pty()).unwrap();
+            session.close();
+            assert_eq!(second.write(b"x"), Err(SessionError::Closed));
+            assert_eq!(second.window_change(100, 30), Err(SessionError::Closed));
+            let inputs: Vec<Vec<u8>> = engine.events().into_iter().filter_map(|event| if let FakeEvent::ShellInput(bytes) = event { Some(bytes) } else { None }).collect();
+            assert_eq!(inputs, [b"kept".to_vec(), b"after our close".to_vec()]);
+        });
+    }
+
+    #[test]
+    fn a_scripted_shell_error_is_what_shell_returns() {
+        let engine = FakeEngine::new().with_shell_error(SessionError::Channel("channel open refused".into()));
+        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
+        assert_eq!(session.shell(pty()).err(), Some(SessionError::Channel("channel open refused".into())));
+        assert!(engine.shells().is_empty());
+    }
+
     #[test]
     fn closing_is_recorded_once() {
         bounded(|| {
@@ -723,8 +861,7 @@ mod tests {
                 vec![FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::ShellOpened { term: "dumb".into(), cols: 80, rows: 24 }, FakeEvent::Closed]
             );
             drop(session);
-            let closed = engine.events().iter().filter(|event| **event == FakeEvent::Closed).count();
-            assert_eq!(closed, 1, "dropping a session that was closed already records no second close");
+            assert_eq!(engine.events().iter().filter(|event| **event == FakeEvent::Closed).count(), 1, "dropping a closed session closes nothing more");
 
             // A shell opened while another thread closes the session is either refused or ended by that close; none is left open. Many scripted
             // chunks make a shell slow to build, which gives a close that is not synchronised with `shell` the time to slip in.
@@ -747,4 +884,12 @@ mod tests {
             }
         });
     }
+
+    #[test]
+    fn a_scripted_banner_is_handed_to_the_auth_source_of_each_hop() {
+        let engine = FakeEngine::new().with_banner("Authorized use only.");
+        let auth = Auth::default();
+        connect(&engine, &Target { hops: vec![hop("bastion"), hop("db")] }, &auth).expect("connects");
+        assert_eq!(asked(&auth), ["banner bastion Authorized use only.", "banner db Authorized use only."]);
+    }
 }
```

`src-tauri/src/ssh/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/mod.rs
+++ b/src-tauri/src/ssh/mod.rs
@@ -10,6 +10,8 @@ mod engine_tests;
 mod error;
 #[cfg(test)]
 pub mod fake;
+#[cfg(test)]
+mod parity_tests;
 pub mod russh_engine;
 #[cfg(test)]
 pub mod testing;
```

`src-tauri/src/ssh/parity_tests.rs`: create

```rust
//! The same scenarios against the fake engine and the real one (plan 1b): wherever the broker relies on how an engine behaves, the fake
//! must behave like the real engine, or the broker's tests would pass against behaviour the app never sees. Each scenario is written once,
//! as a function of an engine, a target and an auth source, and runs twice: against `FakeEngine`, and against `RusshEngine` with the
//! in-process server (logins) or a scratch OpenSSH behind a proxy (shells and a cut link).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::fake::{FakeEngine, FakeLogin, FakeMethods};
use super::russh_engine::toy_server::{ToyLogin, ToyServer};
use super::russh_engine::{EngineOptions, RusshEngine};
use super::testing::eventually;
use super::testing::fixture::Server;
use super::testing::harness::tools;
use super::testing::proxy::{Mode, Proxy};
use super::{
    AuthError, AuthMethod, AuthSource, ConnectError, DisconnectKind, DisconnectReason, Exit, Hop, HopRef, HostKey, HostKeyPolicy, HostKeyVerdict, Prompt, Pty,
    RsaHash, Secret, SessionError, ShellChannel, Signature, SshEngine, Target,
};
use crate::sync::slot_rules::test_keys;

const USER: &str = "tester";
const PASSWORD: &str = "correct horse battery staple";

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Both the host key policy and the auth source of a login scenario: it answers from fixed values and writes down, in order, every
/// question the engine asked.
#[derive(Default)]
struct Recorder {
    /// The policy pins every key when true, and knows none otherwise.
    trust: bool,
    password: Option<String>,
    answers: Option<Vec<String>>,
    answer_delay: Duration,
    log: Mutex<Vec<String>>,
    /// How long each `interactive` call was given.
    waits: Mutex<Vec<Duration>>,
}

impl Recorder {
    fn trusting() -> Recorder {
        Recorder { trust: true, ..Recorder::default() }
    }

    fn log(&self) -> Vec<String> {
        locked(&self.log).clone()
    }
}

impl HostKeyPolicy for Recorder {
    fn check(&self, hop: &HopRef, _key: &HostKey) -> HostKeyVerdict {
        locked(&self.log).push(format!("host key {}", hop.alias));
        if self.trust {
            HostKeyVerdict::Pinned
        } else {
            HostKeyVerdict::Unknown
        }
    }
}

impl AuthSource for Recorder {
    fn public_key(&self, key_id: &str) -> Option<String> {
        locked(&self.log).push(format!("public key {key_id}"));
        Some(test_keys::PLAIN_PUBLIC.to_string())
    }

    /// Never reached: both servers refuse the key before they ask for a signature.
    fn sign(&self, key_id: &str, _data: &[u8], _rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
        locked(&self.log).push(format!("sign {key_id}"));
        Err(AuthError::Refused("not in this test".to_string()))
    }

    fn password(&self, hop: &HopRef) -> Option<Secret> {
        locked(&self.log).push(format!("password {}", hop.alias));
        self.password.clone().map(Zeroizing::new)
    }

    fn interactive(&self, hop: &HopRef, _prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
        locked(&self.log).push(format!("interactive {}", hop.alias));
        locked(&self.waits).push(deadline.saturating_duration_since(Instant::now()));
        std::thread::sleep(self.answer_delay);
        self.answers.clone().map(|answers| answers.into_iter().map(Zeroizing::new).collect())
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Logins. The server refuses every key and offers the password method and one keyboard-interactive prompt, both taking `PASSWORD`:
// the in-process server, or a fake server with the same methods.

fn fake_logins() -> FakeEngine {
    FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password(PASSWORD).and_interactive("Password: ", PASSWORD)))
}

fn toy() -> ToyServer {
    ToyServer::start(ToyLogin { user: USER.to_string(), password: PASSWORD.to_string(), prompt: "Password: ".to_string(), rounds: None })
}

fn real_engine() -> RusshEngine {
    RusshEngine::with_options(EngineOptions { worker_threads: 2, ..EngineOptions::default() })
}

fn login_target(port: u16, auth: AuthMethod) -> Target {
    Target { hops: vec![Hop::new("host-login", "login", "127.0.0.1", port, USER, auth)] }
}

/// Runs `scenario` against the fake (any port: nothing is connected) and against the real engine and the in-process server.
fn both_logins(scenario: impl Fn(&dyn SshEngine, u16)) {
    scenario(&fake_logins(), 22);
    let server = toy();
    scenario(&real_engine(), server.port);
}

fn password_first_is_asked_before_the_host_key(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { password: Some(PASSWORD.to_string()), ..Recorder::default() };
    let error = engine.connect(&login_target(port, AuthMethod::Password), &recorder, &recorder).err().expect("the host key is not trusted");
    assert!(matches!(error, ConnectError::HostKeyUnknown { .. }), "{error:?}");
    assert_eq!(recorder.log(), ["password login", "host key login"]);
}

#[test]
fn the_password_of_a_password_first_hop_is_asked_for_before_its_host_key() {
    both_logins(password_first_is_asked_before_the_host_key);
}

fn missing_password_goes_on_to_keyboard_interactive(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { answers: Some(vec![PASSWORD.to_string()]), ..Recorder::trusting() };
    engine.connect(&login_target(port, AuthMethod::Password), &recorder, &recorder).expect("keyboard-interactive gets in");
    assert_eq!(recorder.log(), ["password login", "host key login", "interactive login"]);
}

#[test]
fn a_missing_password_goes_on_to_keyboard_interactive() {
    both_logins(missing_password_goes_on_to_keyboard_interactive);
}

fn refused_key_without_password_wants_one(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { answers: Some(vec!["wrong".to_string()]), ..Recorder::trusting() };
    let error = engine.connect(&login_target(port, AuthMethod::Key { key_id: "k1".to_string() }), &recorder, &recorder).err().expect("refused");
    match error {
        ConnectError::AuthFailed { tried, reason, password_wanted, .. } => {
            assert_eq!(tried, [AuthMethod::Key { key_id: "k1".to_string() }, AuthMethod::Interactive]);
            assert_eq!(reason, "No password was given.");
            assert!(password_wanted);
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert_eq!(recorder.log(), ["host key login", "public key k1", "password login", "interactive login"]);
}

#[test]
fn a_refused_key_with_no_password_to_give_says_a_password_is_wanted() {
    both_logins(refused_key_without_password_wants_one);
}

fn prompt_gets_at_least_a_minute(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { answers: Some(vec![PASSWORD.to_string()]), ..Recorder::trusting() };
    let mut target = login_target(port, AuthMethod::Interactive);
    target.hops[0].connect_timeout = Duration::from_secs(1);
    engine.connect(&target, &recorder, &recorder).expect("the right answer gets in");
    let waits = locked(&recorder.waits).clone();
    assert!(waits.len() == 1 && waits[0] > Duration::from_secs(59) && waits[0] <= Duration::from_secs(60), "{waits:?}");
}

#[test]
fn a_keyboard_interactive_prompt_gets_at_least_a_minute() {
    both_logins(prompt_gets_at_least_a_minute);
}

fn cancelled_prompt_abandons(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder::trusting();
    match engine.connect(&login_target(port, AuthMethod::Interactive), &recorder, &recorder).err().expect("abandoned") {
        ConnectError::AuthAbandoned { reason, .. } => assert_eq!(reason, "the prompt was cancelled"),
        other => panic!("expected AuthAbandoned, got {other:?}"),
    }
}

#[test]
fn a_cancelled_prompt_abandons_the_login() {
    both_logins(cancelled_prompt_abandons);
}

fn late_answer_abandons(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { answers: Some(vec![PASSWORD.to_string()]), answer_delay: Duration::from_millis(300), ..Recorder::trusting() };
    match engine.connect(&login_target(port, AuthMethod::Interactive), &recorder, &recorder).err().expect("abandoned") {
        ConnectError::AuthAbandoned { reason, .. } => assert_eq!(reason, "the prompt was answered after its deadline"),
        other => panic!("expected AuthAbandoned, got {other:?}"),
    }
}

#[test]
fn an_answer_after_the_deadline_abandons_the_login() {
    let wait = Duration::from_millis(100);
    late_answer_abandons(&fake_logins().with_prompt_wait(wait), 22);
    let server = toy();
    late_answer_abandons(&RusshEngine::with_options(EngineOptions { prompt_wait: Some(wait), worker_threads: 2, ..EngineOptions::default() }), server.port);
}

fn unreachable_after_the_password(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { password: Some(PASSWORD.to_string()), ..Recorder::trusting() };
    let error = engine.connect(&login_target(port, AuthMethod::Password), &recorder, &recorder).err().expect("nothing listens there");
    assert!(matches!(error, ConnectError::Unreachable { .. }), "{error:?}");
    assert_eq!(recorder.log(), ["password login"], "asked before the connection was tried, and nothing after");
}

#[test]
fn an_unreachable_password_first_hop_was_asked_for_its_password_first() {
    let closed_port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let refused = ConnectError::Unreachable { hop: login_target(closed_port, AuthMethod::Password).hops[0].reference(), reason: "connection refused".to_string() };
    unreachable_after_the_password(&fake_logins().failing_with(refused), closed_port);
    unreachable_after_the_password(&real_engine(), closed_port);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Shells. The server prints a prompt when a shell opens: a scratch OpenSSH with `/bin/sh` behind a proxy that can cut the link, or a
// fake that prints "$ ".

/// Reads `shell` on a thread of its own until it ends; `None` when it has not ended within `seconds`.
fn read_to_end(shell: &Arc<dyn ShellChannel>, seconds: u64) -> Option<Vec<u8>> {
    let (done, finished) = std::sync::mpsc::channel();
    let reader = Arc::clone(shell);
    std::thread::spawn(move || {
        let (mut all, mut buf) = (Vec::new(), [0u8; 4096]);
        while let Ok(count) = reader.read(&mut buf) {
            if count == 0 {
                break;
            }
            all.extend_from_slice(&buf[..count]);
        }
        let _ = done.send(all);
    });
    finished.recv_timeout(Duration::from_secs(seconds)).ok()
}

/// Waits until the shell has printed something (its prompt): a shell closed before that can leave a process behind on a macOS sshd.
fn first_output(shell: &Arc<dyn ShellChannel>) {
    let (done, printed) = std::sync::mpsc::channel();
    let reader = Arc::clone(shell);
    std::thread::spawn(move || {
        let mut buf = [0u8; 1];
        let _ = done.send(reader.read(&mut buf));
    });
    let count = printed.recv_timeout(Duration::from_secs(20)).expect("the shell prints a prompt").expect("the read works");
    assert_eq!(count, 1);
}

struct ShellWorld {
    engine: Box<dyn SshEngine>,
    target: Target,
    auth: Box<dyn AuthSource>,
    cut: Box<dyn Fn()>,
    _keep: Vec<Box<dyn std::any::Any>>,
}

fn fake_shells() -> ShellWorld {
    let engine = Arc::new(FakeEngine::new().with_shell_output(b"$ "));
    let target = Target { hops: vec![Hop::new("host-shell", "shell", "127.0.0.1", 22, USER, AuthMethod::Key { key_id: "k1".to_string() })] };
    let lost = DisconnectReason { hop: target.hops[0].reference(), kind: DisconnectKind::ConnectionLost, detail: "connection reset by peer".to_string() };
    let cutter = Arc::clone(&engine);
    ShellWorld { engine: Box::new(SharedFake(engine)), target, auth: Box::new(Recorder::default()), cut: Box::new(move || cutter.disconnect_now(lost.clone())), _keep: Vec::new() }
}

/// A `FakeEngine` shared with the closure that cuts its link.
struct SharedFake(Arc<FakeEngine>);

impl SshEngine for SharedFake {
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn super::Session>, ConnectError> {
        self.0.connect(target, host_keys, auth)
    }
}

fn real_shells() -> Option<ShellWorld> {
    let tools = tools()?;
    let server = Server::start(&tools, &["ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi"]);
    let proxy = Arc::new(Proxy::start(server.sshd.port));
    let target = Target { hops: vec![server.hop_with("shell", proxy.port, AuthMethod::Key { key_id: "k1".to_string() })] };
    let auth = Box::new(server.vault("k1"));
    let cutter = Arc::clone(&proxy);
    Some(ShellWorld { engine: Box::new(real_engine()), target, auth, cut: Box::new(move || cutter.set(Mode::Cut)), _keep: vec![Box::new(server), Box::new(proxy)] })
}

fn pty() -> Pty {
    Pty { term: "xterm-256color".to_string(), cols: 80, rows: 24 }
}

fn closing_a_shell_ends_it_as_disconnected(world: &ShellWorld) {
    let session = world.engine.connect(&world.target, &*super::testing::doubles::TestPolicy::trusting(), &*world.auth).expect("connects");
    let shell: Arc<dyn ShellChannel> = Arc::from(session.shell(pty()).expect("a shell"));
    first_output(&shell);
    shell.close();
    read_to_end(&shell, 10).expect("a shell we closed ends");
    assert_eq!(shell.exited(), Some(Exit::Disconnected));
    assert_eq!(shell.write(b"echo after\n"), Ok(()), "a shell we closed ourselves still takes input");
    assert!(session.is_alive(), "only the shell was closed");
}

#[test]
fn a_shell_we_close_ends_as_disconnected_and_still_takes_input() {
    closing_a_shell_ends_it_as_disconnected(&fake_shells());
    if let Some(world) = real_shells() {
        closing_a_shell_ends_it_as_disconnected(&world);
    }
}

fn input_after_the_session_closed_fails(world: &ShellWorld) {
    let session = world.engine.connect(&world.target, &*super::testing::doubles::TestPolicy::trusting(), &*world.auth).expect("connects");
    let shell: Arc<dyn ShellChannel> = Arc::from(session.shell(pty()).expect("a shell"));
    first_output(&shell);
    session.close();
    read_to_end(&shell, 10).expect("closing the session ends its shells");
    assert_eq!(shell.exited(), Some(Exit::Disconnected));
    assert_eq!(shell.write(b"x"), Err(SessionError::Closed));
    assert_eq!(shell.window_change(100, 30), Err(SessionError::Closed));
    assert!(!session.is_alive());
    assert_eq!(session.disconnect_reason().map(|reason| reason.kind), Some(DisconnectKind::ClosedByUs));
}

#[test]
fn input_fails_with_closed_once_the_session_is_closed() {
    input_after_the_session_closed_fails(&fake_shells());
    if let Some(world) = real_shells() {
        input_after_the_session_closed_fails(&world);
    }
}

fn a_cut_link_ends_the_shells(world: &ShellWorld) {
    let session = world.engine.connect(&world.target, &*super::testing::doubles::TestPolicy::trusting(), &*world.auth).expect("connects");
    let shell: Arc<dyn ShellChannel> = Arc::from(session.shell(pty()).expect("a shell"));
    first_output(&shell);
    (world.cut)();
    read_to_end(&shell, 15).expect("a shell on a cut link ends");
    assert_eq!(shell.exited(), Some(Exit::Disconnected));
    eventually("the session to notice", 10, || !session.is_alive());
    assert_eq!(session.disconnect_reason().map(|reason| reason.kind), Some(DisconnectKind::ConnectionLost));
}

#[test]
fn a_cut_link_ends_the_shells_and_the_session_says_the_connection_was_lost() {
    a_cut_link_ends_the_shells(&fake_shells());
    if let Some(world) = real_shells() {
        a_cut_link_ends_the_shells(&world);
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0432]: unresolved import `super::fake::FakeMethods`
error: could not compile `sshelter` (lib test) due to 22 previous errors
```

- [ ] **Step 3: Write the code**

`src-tauri/src/ssh/fake.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/fake.rs
+++ b/src-tauri/src/ssh/fake.rs
@@ -1,10 +1,13 @@
 //! A scripted engine for the tests of the broker, the MCP adapter and the CLI (own-ssh spec §12). It implements the same traits as the
 //! russh engine and touches no network: the "server" is a script, and what the code under test did is recorded for the assertions.
+//! Where the broker relies on how the real engine behaves (the order of the password question, the login sequence, the deadline of a
+//! prompt, how shells end), the fake behaves the same way, and `ssh/parity_tests.rs` runs the same scenarios against both.
 //! Test code only (`#[cfg(test)]` in `ssh/mod.rs`).
 
-use std::collections::{HashMap, HashSet};
-use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
-use std::time::Duration;
+use std::collections::{HashMap, HashSet, VecDeque};
+use std::sync::atomic::{AtomicBool, Ordering};
+use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
+use std::time::{Duration, Instant};
 
 use super::channel::{ByteQueue, ExitCell, QueuedShell, ShellInput};
 use super::error::{ConnectError, SessionError};
@@ -16,24 +19,77 @@ fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
     mutex.lock().unwrap_or_else(PoisonError::into_inner)
 }
 
-/// How the fake server answers a login.
+/// How the fake server of a host answers a login.
 #[derive(Clone, Debug, PartialEq, Eq)]
 pub enum FakeLogin {
-    /// Every login succeeds and the auth source is not consulted, with one exception that holds for every kind of login: a hop that
-    /// starts with the password method has its password asked for before its host key is checked, as the real engine does.
+    /// Every login succeeds and the auth source is not consulted, except for the password of a hop that starts with the password
+    /// method: the real engine asks for it before it connects (before the host key is checked), and so does the fake.
     Accept,
-    /// Every method is refused: `AuthFailed`, with the hop's whole `Hop::auth_sequence()` as `tried`.
-    Refuse,
-    /// The hop's key method: the fake asks the auth source for a signature over a fixed challenge and accepts any signature it gets
-    /// (it has no public key to verify with). A signing error abandons the login, as in the real engine.
-    Signature,
-    /// The fake asks `AuthSource::password` and accepts only `expected`. `None` skips the method, so nothing was tried and the login fails.
-    /// A hop that starts with the password method is asked before its host key is checked; any other hop is asked during the login.
-    Password(String),
-    /// The fake sends `prompts` to `AuthSource::interactive` and accepts only `answers`. `None` (a cancelled prompt) abandons the login,
-    /// and so does a number of answers that differs from the number of prompts, as in the real engine; the right number of wrong answers
-    /// is a refusal.
-    Interactive { prompts: Vec<Prompt>, answers: Vec<String> },
+    /// A server that offers these methods; the login runs the real engine's sequence against them (see `FakeMethods`).
+    Server(FakeMethods),
+}
+
+/// The login methods a fake server offers and what each one accepts. The login goes through the hop's methods in order
+/// (`Hop::auth_sequence`), as the real engine does: a method the server has said it does not offer is skipped without asking the auth
+/// source, a refusal moves on to the next method on the same connection, a method the source has nothing for (no such key, no password)
+/// is skipped, and the end is `AuthFailed` with the methods tried and `password_wanted`. A failed signature, a cancelled or late prompt
+/// and a wrong number of answers abandon the login.
+#[derive(Clone, Debug, Default, PartialEq, Eq)]
+pub struct FakeMethods {
+    /// Public-key login is offered, and any signature is accepted (the fake has no public key to check one with).
+    pub key: bool,
+    /// Password login is offered, and only this password is accepted.
+    pub password: Option<String>,
+    /// Keyboard-interactive is offered: one round with these prompts, and only these answers are accepted.
+    pub interactive: Option<FakeRound>,
+}
+
+/// One keyboard-interactive round of a fake server.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub struct FakeRound {
+    pub prompts: Vec<Prompt>,
+    pub answers: Vec<String>,
+}
+
+impl FakeMethods {
+    /// Public-key login only, accepting any signature.
+    pub fn key() -> FakeMethods {
+        FakeMethods { key: true, ..FakeMethods::default() }
+    }
+
+    /// Password login only, accepting `password`.
+    pub fn password(password: &str) -> FakeMethods {
+        FakeMethods { password: Some(password.to_string()), ..FakeMethods::default() }
+    }
+
+    /// Keyboard-interactive only: one prompt (no echo), accepting `answer`.
+    pub fn interactive(prompt: &str, answer: &str) -> FakeMethods {
+        FakeMethods::default().and_interactive(prompt, answer)
+    }
+
+    /// These methods, and keyboard-interactive too: one prompt (no echo), accepting `answer`.
+    pub fn and_interactive(mut self, prompt: &str, answer: &str) -> FakeMethods {
+        self.interactive = Some(FakeRound { prompts: vec![Prompt { text: prompt.to_string(), echo: false }], answers: vec![answer.to_string()] });
+        self
+    }
+
+    /// A server that offers no login method at all.
+    pub fn none() -> FakeMethods {
+        FakeMethods::default()
+    }
+
+    fn offers(&self, method: &AuthMethod) -> bool {
+        match method {
+            AuthMethod::Key { .. } => self.key,
+            AuthMethod::Password => self.password.is_some(),
+            AuthMethod::Interactive => self.interactive.is_some(),
+        }
+    }
+
+    /// The methods the server lists after a refusal.
+    fn offered(&self) -> Vec<AuthMethod> {
+        [AuthMethod::Key { key_id: String::new() }, AuthMethod::Password, AuthMethod::Interactive].into_iter().filter(|method| self.offers(method)).collect()
+    }
 }
 
 /// Everything the code under test did to the fake, in order.
@@ -64,13 +120,20 @@ struct Script {
     shell_output: Vec<Vec<u8>>,
     shell_exit: Exit,
     shell_ends_at_once: bool,
+    shell_error: Option<SessionError>,
+    write_errors: VecDeque<SessionError>,
     disconnect: Option<DisconnectReason>,
     banner: Option<String>,
+    prompt_wait: Option<Duration>,
 }
 
 struct Shared {
     script: Mutex<Script>,
     events: Mutex<Vec<FakeEvent>>,
+    /// Every session handed out, for `disconnect_now`.
+    sessions: Mutex<Vec<Weak<SessionState>>>,
+    /// The remote side of every shell opened, in order, for the tests that act as the server.
+    shells: Mutex<Vec<FakeShell>>,
 }
 
 impl Shared {
@@ -80,9 +143,7 @@ impl Shared {
 }
 
 /// The scripted engine. Build it with the `with_*` methods; the defaults are: the server presents `default_server_key()`, every login
-/// succeeds, every command exits 0 with no output, a shell prints nothing and exits with code 0 when it is closed, the connection never drops.
-/// Closing a session ends every shell opened on it with `Exit::Disconnected`, as a lost connection does; `with_shell_exit` is how a shell
-/// ends when it is closed itself (`ShellChannel::close`) or ends at once.
+/// succeeds, every command exits 0 with no output, a shell prints nothing and runs until it is closed, the connection never drops.
 pub struct FakeEngine {
     shared: Arc<Shared>,
 }
@@ -105,10 +166,14 @@ impl FakeEngine {
             shell_output: Vec::new(),
             shell_exit: Exit::Code(0),
             shell_ends_at_once: false,
+            shell_error: None,
+            write_errors: VecDeque::new(),
             disconnect: None,
             banner: None,
+            prompt_wait: None,
         };
-        FakeEngine { shared: Arc::new(Shared { script: Mutex::new(script), events: Mutex::new(Vec::new()) }) }
+        let shared = Shared { script: Mutex::new(script), events: Mutex::new(Vec::new()), sessions: Mutex::new(Vec::new()), shells: Mutex::new(Vec::new()) };
+        FakeEngine { shared: Arc::new(shared) }
     }
 
     fn script(self, change: impl FnOnce(&mut Script)) -> FakeEngine {
@@ -139,7 +204,9 @@ impl FakeEngine {
         })
     }
 
-    /// `connect` fails with this error before anything else happens.
+    /// `connect` fails with this error, as the real engine fails on the hop the error names: after that hop's password was asked for
+    /// (a hop that starts with the password method), and before its host key is checked. An error that names no hop
+    /// (`BadJumpChain`) comes before anything else.
     pub fn failing_with(self, error: ConnectError) -> FakeEngine {
         self.script(|script| script.connect_error = Some(error))
     }
@@ -156,16 +223,28 @@ impl FakeEngine {
         self.script(|script| script.shell_output.push(chunk.to_vec()))
     }
 
-    /// How shells end (when they are closed, or at once with `with_shell_ending_at_once`).
+    /// How a shell ends when it ends by itself at once (`with_shell_ending_at_once`). A shell the code under test closes ends as
+    /// `Exit::Disconnected`, as with the real engine; a test ends a running shell its own way with `FakeShell::end`.
     pub fn with_shell_exit(self, exit: Exit) -> FakeEngine {
         self.script(|script| script.shell_exit = exit)
     }
 
-    /// Shells end as soon as their scripted output has been produced, as a typed `exit` would.
+    /// Shells end as soon as their scripted output has been produced, as a typed `exit` would, with the `with_shell_exit` status.
     pub fn with_shell_ending_at_once(self) -> FakeEngine {
         self.script(|script| script.shell_ends_at_once = true)
     }
 
+    /// `Session::shell` fails with this error (a channel the server would not open: `SessionError::Channel`).
+    pub fn with_shell_error(self, error: SessionError) -> FakeEngine {
+        self.script(|script| script.shell_error = Some(error))
+    }
+
+    /// The next writes to a shell fail with these errors, one each, in order (a link that does not take the input:
+    /// `SessionError::Timeout`); after them, writes go through again. A failed write records no input.
+    pub fn with_write_errors(self, errors: Vec<SessionError>) -> FakeEngine {
+        self.script(|script| script.write_errors = errors.into())
+    }
+
     /// Every session connects fine and is over right away, for this reason.
     pub fn disconnecting_with(self, reason: DisconnectReason) -> FakeEngine {
         self.script(|script| script.disconnect = Some(reason))
@@ -176,10 +255,30 @@ impl FakeEngine {
         self.script(|script| script.banner = Some(text.to_string()))
     }
 
+    /// How long a person gets to answer a keyboard-interactive round; by default, as in the real engine, 4 × the hop's connect timeout
+    /// and at least 60 s (`EngineOptions::prompt_wait`).
+    pub fn with_prompt_wait(self, wait: Duration) -> FakeEngine {
+        self.script(|script| script.prompt_wait = Some(wait))
+    }
+
     /// Everything the code under test has done so far.
     pub fn events(&self) -> Vec<FakeEvent> {
         locked(&self.shared.events).clone()
     }
+
+    /// The remote side of every shell opened so far, in order.
+    pub fn shells(&self) -> Vec<FakeShell> {
+        locked(&self.shared.shells).clone()
+    }
+
+    /// Every live session ends now for `reason`, as a connection does when its link is cut or the server goes away: `is_alive` turns
+    /// false, `disconnect_reason` says why, and every shell opened on it ends as `Exit::Disconnected` after what it printed.
+    pub fn disconnect_now(&self, reason: DisconnectReason) {
+        let sessions: Vec<Arc<SessionState>> = locked(&self.shared.sessions).iter().filter_map(Weak::upgrade).collect();
+        for session in sessions {
+            session.end(reason.clone());
+        }
+    }
 }
 
 fn check_chain(target: &Target) -> Result<(), ConnectError> {
@@ -195,20 +294,46 @@ fn check_chain(target: &Target) -> Result<(), ConnectError> {
     Ok(())
 }
 
+/// The hop an error is about; `None` for an error about the whole chain.
+fn hop_of(error: &ConnectError) -> Option<&HopRef> {
+    match error {
+        ConnectError::BadJumpChain { .. } => None,
+        ConnectError::Unreachable { hop, .. }
+        | ConnectError::Timeout { hop, .. }
+        | ConnectError::HostKeyUnknown { hop, .. }
+        | ConnectError::HostKeyMismatch { hop, .. }
+        | ConnectError::NoCommonHostKeyAlgorithm { hop, .. }
+        | ConnectError::AuthFailed { hop, .. }
+        | ConnectError::AuthAbandoned { hop, .. }
+        | ConnectError::Protocol { hop, .. } => Some(hop),
+    }
+}
+
 impl SshEngine for FakeEngine {
     fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
         check_chain(target)?;
-        let (login_default, logins, key_default, keys, scripted_error, banner) = {
+        let (login_default, logins, key_default, keys, scripted_error, banner, prompt_wait) = {
             let script = locked(&self.shared.script);
-            (script.login.clone(), script.logins.clone(), script.host_key.clone(), script.host_keys.clone(), script.connect_error.clone(), script.banner.clone())
+            (
+                script.login.clone(),
+                script.logins.clone(),
+                script.host_key.clone(),
+                script.host_keys.clone(),
+                script.connect_error.clone(),
+                script.banner.clone(),
+                script.prompt_wait,
+            )
         };
-        if let Some(error) = scripted_error {
-            return Err(error);
+        if let Some(error) = scripted_error.as_ref().filter(|error| hop_of(error).is_none()) {
+            return Err(error.clone());
         }
         for hop in &target.hops {
             let reference = hop.reference();
             // A hop that starts with the password method has its password asked for before anything is connected (`AuthSource::password`).
             let prefetched = (hop.auth == AuthMethod::Password).then(|| auth.password(&reference));
+            if let Some(error) = scripted_error.as_ref().filter(|error| hop_of(error).is_some_and(|failing| failing.id == hop.id)) {
+                return Err(error.clone());
+            }
             let key = keys.get(&hop.alias).unwrap_or(&key_default).clone();
             match host_keys.check(&reference, &key) {
                 HostKeyVerdict::Pinned => {}
@@ -218,73 +343,193 @@ impl SshEngine for FakeEngine {
             if let Some(banner) = &banner {
                 auth.banner(&reference, banner);
             }
-            fake_login(hop, logins.get(&hop.alias).unwrap_or(&login_default), auth, prefetched)?;
+            match logins.get(&hop.alias).unwrap_or(&login_default) {
+                FakeLogin::Accept => {}
+                FakeLogin::Server(methods) => fake_login(hop, methods, auth, prefetched, prompt_wait)?,
+            }
+        }
+        if let Some(error) = scripted_error {
+            // It names a hop that is not in this chain: the script is about another target, and it still fails this one.
+            return Err(error);
         }
         self.shared.record(FakeEvent::Connect { aliases: target.hops.iter().map(|hop| hop.alias.clone()).collect() });
         let disconnect = locked(&self.shared.script).disconnect.clone();
         let destination = target.hops.last().map(Hop::reference).ok_or_else(|| ConnectError::BadJumpChain { why: "the target has no hosts".to_string() })?;
-        Ok(Box::new(FakeSession { shared: Arc::clone(&self.shared), destination, closed: Mutex::new(disconnect), shells: Mutex::new(Vec::new()) }))
+        let state = Arc::new(SessionState { destination, closed: Mutex::new(disconnect), shells: Mutex::new(Vec::new()) });
+        locked(&self.shared.sessions).push(Arc::downgrade(&state));
+        Ok(Box::new(FakeSession { shared: Arc::clone(&self.shared), state }))
     }
 }
 
-fn fake_login(hop: &Hop, login: &FakeLogin, auth: &dyn AuthSource, prefetched: Option<Option<Secret>>) -> Result<(), ConnectError> {
+/// The time a person gets for one keyboard-interactive round: the script's, or the real engine's default (4 × the connect timeout, at
+/// least 60 s).
+fn prompt_deadline(hop: &Hop, prompt_wait: Option<Duration>) -> Instant {
+    let wait = prompt_wait.unwrap_or_else(|| hop.connect_timeout.saturating_mul(4).max(Duration::from_secs(60)));
+    let now = Instant::now();
+    now.checked_add(wait).unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365))
+}
+
+/// The real engine's login sequence (`russh_engine::authenticate`) against the methods of a fake server.
+fn fake_login(hop: &Hop, server: &FakeMethods, auth: &dyn AuthSource, mut prefetched: Option<Option<Secret>>, prompt_wait: Option<Duration>) -> Result<(), ConnectError> {
     let reference = hop.reference();
-    // `password_wanted` as the real engine reports it: the server offers the password method and none was tried.
-    let refused = |tried: Vec<AuthMethod>, password_wanted: bool| ConnectError::AuthFailed { hop: reference.clone(), tried, reason: String::new(), password_wanted };
     let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
-    match login {
-        FakeLogin::Accept => Ok(()),
-        FakeLogin::Refuse => Err(refused(hop.auth_sequence(), false)),
-        FakeLogin::Signature => {
-            let AuthMethod::Key { key_id } = &hop.auth else { return Err(refused(vec![], false)) };
-            auth.sign(key_id, b"fake-challenge", Some(RsaHash::Sha512)).map(|_| ()).map_err(|error| abandoned(&error.to_string()))
-        }
-        FakeLogin::Password(expected) => match prefetched.unwrap_or_else(|| auth.password(&reference)) {
-            None => Err(ConnectError::AuthFailed { hop: reference.clone(), tried: vec![], reason: "No password was given.".to_string(), password_wanted: true }),
-            Some(given) if given.as_str() == expected => Ok(()),
-            Some(_) => Err(refused(vec![AuthMethod::Password], false)),
-        },
-        FakeLogin::Interactive { prompts, answers } => {
-            let deadline = std::time::Instant::now() + Duration::from_secs(60);
-            match auth.interactive(&reference, prompts, deadline) {
-                None => Err(abandoned("the prompt was cancelled")),
-                Some(given) if given.len() != prompts.len() => Err(abandoned("the answers do not match the prompts")),
-                Some(given) if given.iter().map(|answer| answer.as_str()).eq(answers.iter().map(String::as_str)) => Ok(()),
-                Some(_) => Err(refused(vec![AuthMethod::Interactive], false)),
+    let mut tried: Vec<AuthMethod> = Vec::new();
+    let mut reasons: Vec<String> = Vec::new();
+    // What the server has said it offers; nothing until it has answered a request.
+    let mut offered: Option<Vec<AuthMethod>> = None;
+    let lists = |offered: &Option<Vec<AuthMethod>>, method: &AuthMethod| {
+        offered.as_ref().is_some_and(|list| list.iter().any(|listed| std::mem::discriminant(listed) == std::mem::discriminant(method)))
+    };
+    let refusal = |reasons: &mut Vec<String>, tried: &[AuthMethod]| -> Result<Vec<AuthMethod>, ConnectError> {
+        let list = server.offered();
+        if list.is_empty() {
+            reasons.push("The server offers no login method.".to_string());
+            return Err(ConnectError::AuthFailed { hop: reference.clone(), tried: tried.to_vec(), reason: reasons.join(" "), password_wanted: false });
+        }
+        Ok(list)
+    };
+    for method in hop.auth_sequence() {
+        if offered.is_some() && !lists(&offered, &method) {
+            continue;
+        }
+        let accepted = match &method {
+            AuthMethod::Key { key_id } => {
+                if auth.public_key(key_id).is_none() {
+                    reasons.push(format!("The key {key_id} is not available on this computer."));
+                    None
+                } else {
+                    tried.push(method.clone());
+                    if server.key {
+                        auth.sign(key_id, b"fake-challenge", Some(RsaHash::Sha512)).map_err(|error| abandoned(&error.to_string()))?;
+                        Some(true)
+                    } else {
+                        Some(false)
+                    }
+                }
             }
+            AuthMethod::Password => match prefetched.take().unwrap_or_else(|| auth.password(&reference)) {
+                None => {
+                    reasons.push("No password was given.".to_string());
+                    None
+                }
+                Some(given) => {
+                    tried.push(method.clone());
+                    Some(server.password.as_deref() == Some(given.as_str()))
+                }
+            },
+            AuthMethod::Interactive => {
+                tried.push(method.clone());
+                match &server.interactive {
+                    None => Some(false),
+                    Some(round) => {
+                        let deadline = prompt_deadline(hop, prompt_wait);
+                        let Some(given) = auth.interactive(&reference, &round.prompts, deadline) else { return Err(abandoned("the prompt was cancelled")) };
+                        if Instant::now() > deadline {
+                            return Err(abandoned("the prompt was answered after its deadline"));
+                        }
+                        if given.len() != round.prompts.len() {
+                            return Err(abandoned("the answers do not match the prompts"));
+                        }
+                        Some(given.iter().map(|answer| answer.as_str()).eq(round.answers.iter().map(String::as_str)))
+                    }
+                }
+            }
+        };
+        match accepted {
+            Some(true) => return Ok(()),
+            Some(false) => offered = Some(refusal(&mut reasons, &tried)?),
+            // Skipped before the server said anything: the real engine asks it (`none`) what it offers.
+            None if offered.is_none() => offered = Some(refusal(&mut reasons, &tried)?),
+            None => {}
         }
     }
+    let password_wanted = lists(&offered, &AuthMethod::Password) && !tried.contains(&AuthMethod::Password);
+    Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" "), password_wanted })
 }
 
-struct FakeSession {
-    shared: Arc<Shared>,
+/// What a session and the shells opened on it share: whether (and why) it is over.
+struct SessionState {
     destination: HopRef,
     closed: Mutex<Option<DisconnectReason>>,
-    /// The queue and exit cell of every shell opened here: when the session ends, so do they, as they do on a lost connection.
-    /// A shell is added while `closed` is held (see `shell`) and `close` ends them while it holds `closed`, so none is missed.
-    shells: Mutex<Vec<(Arc<ByteQueue>, Arc<ExitCell>)>>,
+    /// The queue, exit cell and "session over" flag of every shell opened here: when the session ends, so do they, as they do on a lost
+    /// connection. A shell is added while `closed` is held (see `shell`) and `end` ends them while it holds `closed`, so none is missed.
+    shells: Mutex<Vec<(Arc<ByteQueue>, Arc<ExitCell>, Arc<AtomicBool>)>>,
+}
+
+impl SessionState {
+    /// Ends the session for `reason` unless it is over already; true when this call ended it.
+    fn end(&self, reason: DisconnectReason) -> bool {
+        let mut closed = locked(&self.closed);
+        if closed.is_some() {
+            return false;
+        }
+        *closed = Some(reason);
+        for (queue, exit, over) in locked(&self.shells).iter() {
+            over.store(true, Ordering::SeqCst);
+            exit.set(Exit::Disconnected);
+            queue.close();
+        }
+        true
+    }
+}
+
+struct FakeSession {
+    shared: Arc<Shared>,
+    state: Arc<SessionState>,
+}
+
+/// The remote side of a shell the fake opened: a test prints into it and ends it, as the server would.
+#[derive(Clone)]
+pub struct FakeShell {
+    queue: Arc<ByteQueue>,
+    exit: Arc<ExitCell>,
+}
+
+impl FakeShell {
+    /// The server prints `bytes`.
+    pub fn print(&self, bytes: &[u8]) {
+        self.queue.push(bytes.to_vec());
+    }
+
+    /// The shell ends as `exit` (the user typed `exit`, a signal killed it); what it printed before can still be read.
+    pub fn end(&self, exit: Exit) {
+        self.exit.set(exit);
+        self.queue.close();
+    }
 }
 
 struct FakeShellInput {
     shared: Arc<Shared>,
     queue: Arc<ByteQueue>,
     exit: Arc<ExitCell>,
+    /// The session is over: input fails with `Closed`, as on the real engine (a shell we closed ourselves still takes input there).
+    session_over: Arc<AtomicBool>,
 }
 
 impl ShellInput for FakeShellInput {
     fn write(&self, bytes: &[u8]) -> Result<(), SessionError> {
+        if self.session_over.load(Ordering::SeqCst) {
+            return Err(SessionError::Closed);
+        }
+        if let Some(error) = locked(&self.shared.script).write_errors.pop_front() {
+            return Err(error);
+        }
         self.shared.record(FakeEvent::ShellInput(bytes.to_vec()));
         Ok(())
     }
 
     fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
+        if self.session_over.load(Ordering::SeqCst) {
+            return Err(SessionError::Closed);
+        }
         self.shared.record(FakeEvent::WindowChange { cols, rows });
         Ok(())
     }
 
+    /// Our own close: the channel ends without a status, as with the real engine.
     fn close(&self) {
         self.shared.record(FakeEvent::ShellClosed);
-        self.exit.set(locked(&self.shared.script).shell_exit.clone());
+        self.exit.set(Exit::Disconnected);
         self.queue.close();
     }
 }
@@ -305,11 +550,11 @@ fn capped(mut result: ExecResult, cap: usize) -> ExecResult {
 
 impl Session for FakeSession {
     fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
-        let (output, exit, ends_at_once) = {
+        let (output, exit, ends_at_once, error) = {
             let script = locked(&self.shared.script);
-            (script.shell_output.clone(), script.shell_exit.clone(), script.shell_ends_at_once)
+            (script.shell_output.clone(), script.shell_exit.clone(), script.shell_ends_at_once, script.shell_error.clone())
         };
-        let (queue, cell) = (ByteQueue::new(1024 * 1024), ExitCell::new());
+        let (queue, cell, over) = (ByteQueue::new(1024 * 1024), ExitCell::new(), Arc::new(AtomicBool::new(false)));
         for chunk in output {
             queue.push(chunk);
         }
@@ -318,18 +563,22 @@ impl Session for FakeSession {
             queue.close();
         }
         {
-            // The check that the session is alive and the registration of the new shell are made under one lock, so a `close()` on another
+            // The check that the session is alive and the registration of the new shell are made under one lock, so a close on another
             // thread runs either before this (the call fails with `Closed` and records nothing) or after it (and ends this shell with the
             // others): no shell is left open on a closed session. The lock covers only these steps, because a thread that opens shells in
-            // a loop would otherwise keep `close()` waiting. (`self.is_alive()` would lock `closed` again here.)
-            let closed = locked(&self.closed);
+            // a loop would otherwise keep a close waiting. (`self.is_alive()` would lock `closed` again here.)
+            let closed = locked(&self.state.closed);
             if closed.is_some() {
                 return Err(SessionError::Closed);
             }
+            if let Some(error) = error {
+                return Err(error);
+            }
             self.shared.record(FakeEvent::ShellOpened { term: pty.term, cols: pty.cols, rows: pty.rows });
-            locked(&self.shells).push((Arc::clone(&queue), Arc::clone(&cell)));
+            locked(&self.state.shells).push((Arc::clone(&queue), Arc::clone(&cell), Arc::clone(&over)));
+            locked(&self.shared.shells).push(FakeShell { queue: Arc::clone(&queue), exit: Arc::clone(&cell) });
         }
-        let input = FakeShellInput { shared: Arc::clone(&self.shared), queue: Arc::clone(&queue), exit: Arc::clone(&cell) };
+        let input = FakeShellInput { shared: Arc::clone(&self.shared), queue: Arc::clone(&queue), exit: Arc::clone(&cell), session_over: over };
         Ok(Box::new(QueuedShell::new(Box::new(input), queue, cell)))
     }
 
@@ -351,22 +600,17 @@ impl Session for FakeSession {
     }
 
     fn is_alive(&self) -> bool {
-        locked(&self.closed).is_none()
+        locked(&self.state.closed).is_none()
     }
 
     fn disconnect_reason(&self) -> Option<DisconnectReason> {
-        locked(&self.closed).clone()
+        locked(&self.state.closed).clone()
     }
 
     fn close(&self) {
-        let mut closed = locked(&self.closed);
-        if closed.is_none() {
-            *closed = Some(DisconnectReason { hop: self.destination.clone(), kind: DisconnectKind::ClosedByUs, detail: "closed by the caller".to_string() });
+        let reason = DisconnectReason { hop: self.state.destination.clone(), kind: DisconnectKind::ClosedByUs, detail: "closed by the caller".to_string() };
+        if self.state.end(reason) {
             self.shared.record(FakeEvent::Closed);
-            for (queue, exit) in locked(&self.shells).iter() {
-                exit.set(Exit::Disconnected);
-                queue.close();
-            }
         }
     }
 }
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::)
```

Expected: PASS, `test result: ok. 194 passed; 0 failed; 0 ignored; 0 measured; 1419 filtered out`. Then the leftover check prints 0, 0 and 0.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1611 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/ssh/fake.rs \
  src-tauri/src/ssh/mod.rs \
  src-tauri/src/ssh/parity_tests.rs
git commit -m "test(ssh): make the fake engine behave like the real one where the broker relies on it, and check both with the same scenarios"
```

Expected: `git status --short` lists the three files of this task; the `git diff --stat` prints nothing.

- [ ] **Step 7: Prove the scenarios can fail (after the commit)**

Each edit below puts back one difference R18 named; the scenarios, or the fake's own tests where a scenario cannot tell the difference (edit 5: with a 15 s connect timeout, 4 × 15 s is the minute either way), must catch every one. Make one edit, run, then restore the file with `git checkout` (the tree is clean after the commit, so the checkout restores exactly the committed file) before the next. The run for each:

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::parity_tests:: ssh::fake::)
```

and after it:

```bash
git checkout -- src-tauri/src/ssh/fake.rs
```

Edit 1, a shell we close ends with the scripted exit again (difference a):

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path('src-tauri/src/ssh/fake.rs')
t = p.read_text()
old = '        self.exit.set(Exit::Disconnected);\n        self.queue.close();\n    }\n}'
new = '        self.exit.set(locked(&self.shared.script).shell_exit.clone());\n        self.queue.close();\n    }\n}'
assert t.count(old) == 1
p.write_text(t.replace(old, new))
PY
```

Expected: FAIL; the crate compiles and 2 tests fail (`ssh::fake::tests::a_shell_prints_its_script_records_the_input_and_ends_as_disconnected_when_we_close_it`, `ssh::parity_tests::a_shell_we_close_ends_as_disconnected_and_still_takes_input`): `test result: FAILED. 28 passed; 2 failed; 0 ignored; 0 measured; 1583 filtered out`.

Edit 2, input is taken after the session is over (b):

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path('src-tauri/src/ssh/fake.rs')
t = p.read_text()
old = '        if self.session_over.load(Ordering::SeqCst) {\n            return Err(SessionError::Closed);\n        }\n        if let Some(error)'
new = '        if let Some(error)'
assert t.count(old) == 1
p.write_text(t.replace(old, new))
PY
```

Expected: FAIL; the crate compiles and 3 tests fail (`ssh::fake::tests::a_disconnect_now_ends_the_live_sessions_and_their_shells_and_says_why`, `ssh::fake::tests::input_fails_once_the_session_is_over_and_scripted_errors_come_first`, `ssh::parity_tests::input_fails_with_closed_once_the_session_is_closed`): `test result: FAILED. 27 passed; 3 failed; 0 ignored; 0 measured; 1583 filtered out`.

Edit 3, the scripted error comes before the password of a password-first hop (d):

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path('src-tauri/src/ssh/fake.rs')
t = p.read_text()
old = '        if let Some(error) = scripted_error.as_ref().filter(|error| hop_of(error).is_none()) {'
new = '        if let Some(error) = scripted_error.as_ref() {'
assert t.count(old) == 1
p.write_text(t.replace(old, new))
PY
```

Expected: FAIL; the crate compiles and 2 tests fail (`ssh::fake::tests::a_scripted_connect_failure_comes_on_its_hop_after_that_hops_password_was_asked_for`, `ssh::parity_tests::an_unreachable_password_first_hop_was_asked_for_its_password_first`): `test result: FAILED. 28 passed; 2 failed; 0 ignored; 0 measured; 1583 filtered out`.

Edit 4, a missing password ends the login instead of going on to keyboard-interactive (f):

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path('src-tauri/src/ssh/fake.rs')
t = p.read_text()
old = '                None => {\n                    reasons.push("No password was given.".to_string());\n                    None\n                }'
new = '                None => {\n                    reasons.push("No password was given.".to_string());\n                    return Err(ConnectError::AuthFailed { hop: reference.clone(), tried, reason: reasons.join(" "), password_wanted: true });\n                }'
assert t.count(old) == 1
p.write_text(t.replace(old, new))
PY
```

Expected: FAIL; the crate compiles and 3 tests fail (`ssh::fake::tests::a_missing_password_goes_on_to_keyboard_interactive`, `ssh::parity_tests::a_missing_password_goes_on_to_keyboard_interactive`, `ssh::parity_tests::a_refused_key_with_no_password_to_give_says_a_password_is_wanted`): `test result: FAILED. 27 passed; 3 failed; 0 ignored; 0 measured; 1583 filtered out`.

Edit 5, a keyboard-interactive prompt gets a fixed minute (e):

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path('src-tauri/src/ssh/fake.rs')
t = p.read_text()
old = '    let wait = prompt_wait.unwrap_or_else(|| hop.connect_timeout.saturating_mul(4).max(Duration::from_secs(60)));'
new = '    let wait = prompt_wait.unwrap_or(Duration::from_secs(60));'
assert t.count(old) == 1
p.write_text(t.replace(old, new))
PY
```

Expected: FAIL; the crate compiles and 1 test fails (`ssh::fake::tests::a_prompt_gets_four_connect_timeouts_and_at_least_a_minute_and_a_late_answer_abandons_the_login`): `test result: FAILED. 29 passed; 1 failed; 0 ignored; 0 measured; 1583 filtered out`.

After the fifth edit, restore the file and check the tree:

```bash
git checkout -- src-tauri/src/ssh/fake.rs
git status --short
```

Expected: no output.

---

### Task 4: The frames and messages of the local IPC protocol

**Files:**
- Create: `src-tauri/src/session/mod.rs`, `src-tauri/src/session/protocol.rs` (with its tests)
- Modify: `src-tauri/src/lib.rs` (`pub mod session;`)
- Modify: `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` (§7.1)

**Interfaces:**
- Consumes: `serde`, `serde_json`, `zeroize::Zeroizing` (all already dependencies).
- Produces (`session/protocol.rs`):
  - `pub const PROTOCOL_VERSION: u32 = 1`, `pub const CONTROL: u8 = 1`, `pub const DATA: u8 = 2`, `pub const MAX_FRAME: usize = 1 << 20`, `pub const DATA_CHUNK: usize = 32 * 1024`
  - `pub enum Frame { Control(Zeroizing<Vec<u8>>), Data(Zeroizing<Vec<u8>>) }`
  - `pub enum FrameError { Io(io::Error), TooLarge(usize), UnknownType(u8), Empty, Truncated }` (`Display`, `Error`)
  - `pub fn read_frame(reader: &mut impl Read) -> Result<Option<Frame>, FrameError>` — `Ok(None)`: a clean end between two frames
  - `pub fn write_frame(writer: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()>`, `pub fn write_control<T: Serialize>(writer: &mut impl Write, message: &T) -> io::Result<()>`, `pub fn write_data(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()>`
  - `pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T, String>`
  - `pub enum ClientKind { Connect, Mcp }`, `pub enum HostQuery { Alias(String), Id(String) }` (`Display`), `pub struct PtyRequest { pub cols: u16, pub rows: u16, pub term: String }`
  - `pub enum ClientMessage { Hello { client, version, client_info }, OpenShell { host, pty }, Exec {}, WindowChange { cols, rows }, Answer { question_id, value: Option<String>, cancel: bool }, Close, Unknown }` (a hand-written `Debug` that hides an answer's value)
  - `pub enum QuestionKind { HostKeyNotice, Passphrase, Password, Interactive }`, `pub struct Question { pub question_id: String, pub kind: QuestionKind, pub text: String, pub echo: bool, pub deadline_ms: Option<u64> }`
  - `pub enum Event { Connected, Disconnected { reason }, Error { kind, text }, Banner { text } }` and `pub mod kinds` (`PROTOCOL`, `UNSUPPORTED`, `HOST`, `HOST_KEY`, `AUTH`, `CONNECT`, `SHELL`, `INPUT`)
  - `pub enum ServerMessage { Opened { session_id }, Question(Question), Event(Event), Exited { code: Option<u32>, signal: Option<String> } }`

What shapes this task:
- Spec §7.1 fixes the shape (`u32 length | u8 type | payload`, control JSON, data raw) and leaves the details open; this task fixes them and records them in the spec (Step 5): the length is big-endian and counts the type byte; type 1 is a control frame (one JSON object tagged by `type`), type 2 a data frame; a frame is at most 1 MiB; a longer one, an unknown type, a length of 0 or a stream that ends inside a frame ends the connection, because nothing after it can be trusted. A frame is written with one `write_all`, so two writers sharing a lock never interleave.
- `hello` carries `version`: after an update the `sshelter` on disk can be newer than the app that is still running, and the broker must be able to say so (Task 11) instead of misreading a message.
- `host` is `{"alias": …}` or `{"id": …}`, not a bare string: the spec allows either and a string cannot say which (`sshelter connect --id` names an id on purpose).
- `question.deadline_ms` is how long the answer is waited for, counted from when the question is sent (an `Instant` cannot cross processes); `null` for `host_key_notice`, which is shown and never answered (spec §7.2: host keys are confirmed in the app's window only). `answer` carries `value` or `cancel: true` (Ctrl-C, Ctrl-D). `event` has a fourth kind, `banner` (R20).
- Secrets stay out of everything that could be logged: frame payloads are `Zeroizing`, `ClientMessage`'s `Debug` hides an answer's value, and `decode` never quotes the payload (serde's error text can contain the value it choked on).
- `exec` and an MCP `hello` are read so that the broker can refuse them by name (phase 2); a message type this version does not know reads as `Unknown` (`#[serde(other)]`), so the broker answers a newer client with an error instead of losing the stream.
- `pub mod session;` is public for now, as plan 1a's `pub mod ssh;` was: nothing in the app uses the module until plan 1b-2, and a private module would warn about dead code in every task until then. Plan 1b-2's last task makes both private (R21).

- [ ] **Step 1: Write the tests**

`src-tauri/src/lib.rs`: apply this patch

```diff
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -13,6 +13,7 @@ mod known_hosts;
 pub mod mcp;
 mod process;
 mod secrets;
+pub mod session;
 mod settings_io;
 pub mod ssh;
 mod state;
```

`src-tauri/src/session/mod.rs`: create

```rust
//! The session broker (own-ssh spec §4, §7): it opens SSH sessions for its clients over the local IPC socket — `sshelter connect` in this
//! version, the MCP adapter in phase 2 — asks the client (or the app's window, for host keys) what a login needs, and relays the
//! terminal. Every SSH call it makes blocks, so it runs on plain threads, never in async code and never on the UI thread.

pub mod protocol;
```

`src-tauri/src/session/protocol.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn frames_of(bytes: &[u8]) -> Vec<Result<Option<Frame>, String>> {
        let mut reader = bytes;
        let mut all = Vec::new();
        loop {
            let next = read_frame(&mut reader).map_err(|error| error.to_string());
            let end = !matches!(next, Ok(Some(_)));
            all.push(next);
            if end {
                return all;
            }
        }
    }

    #[test]
    fn frames_come_back_in_order_and_a_clean_end_between_frames_is_none() {
        let mut stream = Vec::new();
        write_control(&mut stream, &ClientMessage::Close).unwrap();
        write_data(&mut stream, b"ls -l\r").unwrap();
        write_data(&mut stream, b"").unwrap();
        assert_eq!(
            frames_of(&stream),
            vec![
                Ok(Some(Frame::Control(Zeroizing::new(br#"{"type":"close"}"#.to_vec())))),
                Ok(Some(Frame::Data(Zeroizing::new(b"ls -l\r".to_vec())))),
                Ok(Some(Frame::Data(Zeroizing::new(Vec::new())))),
                Ok(None),
            ]
        );
    }

    /// `u32 length | u8 type | payload`, big-endian; the length counts the type byte and the payload.
    #[test]
    fn a_frame_is_a_big_endian_length_that_counts_the_type_byte_then_the_type_then_the_payload() {
        let mut stream = Vec::new();
        write_data(&mut stream, b"hi").unwrap();
        assert_eq!(stream, [0, 0, 0, 3, DATA, b'h', b'i']);
        let mut stream = Vec::new();
        write_frame(&mut stream, CONTROL, b"{}").unwrap();
        assert_eq!(stream, [0, 0, 0, 3, CONTROL, b'{', b'}']);
    }

    /// A length beyond the limit is refused from the header alone: nothing is allocated for it and nothing more is read.
    #[test]
    fn a_frame_over_the_limit_is_refused_from_its_header_and_never_written() {
        let mut header = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        header.push(DATA);
        let mut reader = header.as_slice();
        assert!(matches!(read_frame(&mut reader), Err(FrameError::TooLarge(length)) if length == MAX_FRAME + 1));
        assert_eq!(reader, [DATA], "the payload was not read");

        let error = write_data(&mut Vec::new(), &vec![0; MAX_FRAME]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(write_data(&mut Vec::new(), &vec![0; MAX_FRAME - 1]).is_ok(), "the type byte and MAX_FRAME - 1 bytes fit");
    }

    #[test]
    fn a_stream_that_ends_inside_a_frame_is_truncated_and_odd_frames_are_errors() {
        assert!(matches!(read_frame(&mut [0u8, 0].as_slice()), Err(FrameError::Truncated)), "inside the length");
        assert!(matches!(read_frame(&mut [0u8, 0, 0, 5, DATA, b'a'].as_slice()), Err(FrameError::Truncated)), "inside the payload");
        assert!(matches!(read_frame(&mut [0u8, 0, 0, 0].as_slice()), Err(FrameError::Empty)), "a frame without even a type");
        assert!(matches!(read_frame(&mut [0u8, 0, 0, 1, 9].as_slice()), Err(FrameError::UnknownType(9))));
    }

    #[test]
    fn client_messages_read_and_write_as_the_spec_names_them() {
        let cases: Vec<(&str, ClientMessage)> = vec![
            (
                r#"{"type":"hello","client":"connect","version":1,"client_info":null}"#,
                ClientMessage::Hello { client: ClientKind::Connect, version: 1, client_info: None },
            ),
            (
                r#"{"type":"open_shell","host":{"alias":"web"},"pty":{"cols":120,"rows":40,"term":"xterm-256color"}}"#,
                ClientMessage::OpenShell { host: HostQuery::Alias("web".into()), pty: PtyRequest { cols: 120, rows: 40, term: "xterm-256color".into() } },
            ),
            (
                r#"{"type":"open_shell","host":{"id":"0123456789abcdef"},"pty":{"cols":80,"rows":24,"term":"dumb"}}"#,
                ClientMessage::OpenShell { host: HostQuery::Id("0123456789abcdef".into()), pty: PtyRequest { cols: 80, rows: 24, term: "dumb".into() } },
            ),
            (r#"{"type":"window_change","cols":100,"rows":30}"#, ClientMessage::WindowChange { cols: 100, rows: 30 }),
            (
                r#"{"type":"answer","question_id":"q1","value":"hunter2","cancel":false}"#,
                ClientMessage::Answer { question_id: "q1".into(), value: Some("hunter2".into()), cancel: false },
            ),
            (r#"{"type":"answer","question_id":"q2","value":null,"cancel":true}"#, ClientMessage::Answer { question_id: "q2".into(), value: None, cancel: true }),
            (r#"{"type":"close"}"#, ClientMessage::Close),
        ];
        for (json, message) in cases {
            assert_eq!(decode::<ClientMessage>(json.as_bytes()), Ok(message.clone()), "{json}");
            assert_eq!(serde_json::to_string(&message).unwrap(), json);
        }
        // Phase 2's messages and the fields 1b does not know are read, so the broker can refuse them by name.
        assert_eq!(
            decode::<ClientMessage>(br#"{"type":"exec","host":{"alias":"web"},"command":"uptime","timeout_secs":60}"#),
            Ok(ClientMessage::Exec {})
        );
        assert_eq!(decode::<ClientMessage>(br#"{"type":"hello","client":"mcp","version":2,"client_info":{"name":"claude"}}"#).map(|m| matches!(m, ClientMessage::Hello { client: ClientKind::Mcp, version: 2, .. })), Ok(true));
        assert_eq!(decode::<ClientMessage>(br#"{"type":"teleport"}"#), Ok(ClientMessage::Unknown));
        assert_eq!(decode::<ClientMessage>(br#"{"type":"answer","question_id":"q3"}"#), Ok(ClientMessage::Answer { question_id: "q3".into(), value: None, cancel: false }), "value and cancel may be left out");
    }

    #[test]
    fn server_messages_read_and_write_as_the_spec_names_them() {
        let cases: Vec<(&str, ServerMessage)> = vec![
            (r#"{"type":"opened","session_id":"7"}"#, ServerMessage::Opened { session_id: "7".into() }),
            (
                r#"{"type":"question","question_id":"q1","kind":"password","text":"deploy@web's password: ","echo":false,"deadline_ms":60000}"#,
                ServerMessage::Question(Question { question_id: "q1".into(), kind: QuestionKind::Password, text: "deploy@web's password: ".into(), echo: false, deadline_ms: Some(60_000) }),
            ),
            (
                r#"{"type":"question","question_id":"q2","kind":"host_key_notice","text":"Waiting for you to confirm web's host key in SSHelter.","echo":false,"deadline_ms":null}"#,
                ServerMessage::Question(Question {
                    question_id: "q2".into(),
                    kind: QuestionKind::HostKeyNotice,
                    text: "Waiting for you to confirm web's host key in SSHelter.".into(),
                    echo: false,
                    deadline_ms: None,
                }),
            ),
            (r#"{"type":"event","event":"connected"}"#, ServerMessage::Event(Event::Connected)),
            (r#"{"type":"event","event":"disconnected","reason":"Connection to web lost."}"#, ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost.".into() })),
            (r#"{"type":"event","event":"error","kind":"auth","text":"Authentication failed."}"#, ServerMessage::Event(Event::Error { kind: "auth".into(), text: "Authentication failed.".into() })),
            (r#"{"type":"event","event":"banner","text":"Authorized use only.\n"}"#, ServerMessage::Event(Event::Banner { text: "Authorized use only.\n".into() })),
            (r#"{"type":"exited","code":3,"signal":null}"#, ServerMessage::Exited { code: Some(3), signal: None }),
            (r#"{"type":"exited","code":null,"signal":"KILL"}"#, ServerMessage::Exited { code: None, signal: Some("KILL".into()) }),
        ];
        for (json, message) in cases {
            assert_eq!(decode::<ServerMessage>(json.as_bytes()), Ok(message.clone()), "{json}");
            assert_eq!(serde_json::to_string(&message).unwrap(), json);
        }
    }

    /// An answer can carry a password: it never shows in debug output, and a message that does not parse is not quoted back.
    #[test]
    fn an_answer_keeps_its_value_out_of_debug_output_and_error_text() {
        let answer = ClientMessage::Answer { question_id: "q1".into(), value: Some("hunter2".into()), cancel: false };
        let shown = format!("{answer:?}");
        assert!(!shown.contains("hunter2") && shown.contains("q1"), "{shown}");
        let error = decode::<ClientMessage>(br#"{"type":"answer","question_id":7,"value":"hunter2"}"#).unwrap_err();
        assert!(!error.contains("hunter2"), "{error}");
        assert_eq!(error, "a control message SSHelter does not understand");
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::protocol::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find type `Frame` in this scope
error: could not compile `sshelter` (lib test) due to 87 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/session/protocol.rs`: insert above the `#[cfg(test)]` line

```rust
//! The local IPC protocol between the broker and its clients (own-ssh spec §7.1). A frame is `u32 length | u8 type | payload`, the
//! length big-endian and counting the type byte and the payload. A control frame (`CONTROL`) carries one JSON message; a data frame
//! (`DATA`) carries raw bytes: keystrokes from the client, terminal output (stdout and stderr merged by the PTY) from the broker.
//!
//! This version speaks the shell subset: client → broker `hello`, `open_shell`, `window_change`, `answer`, `close` and data; broker →
//! client `opened`, `question`, `event`, `exited` and data. `exec` and the MCP client are phase 2: they are read, so that the broker can
//! refuse them by name. Both sides are this same executable, but after an update the CLI on disk can be newer than the app that is
//! running, so `hello` carries `PROTOCOL_VERSION`.

use std::fmt;
use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The version of this protocol; `hello` carries it, and the broker refuses another.
pub const PROTOCOL_VERSION: u32 = 1;
/// A frame whose payload is one JSON message.
pub const CONTROL: u8 = 1;
/// A frame whose payload is raw bytes.
pub const DATA: u8 = 2;
/// The largest frame (type byte and payload) either side sends or reads: 1 MiB. A length beyond it ends the connection.
pub const MAX_FRAME: usize = 1 << 20;
/// Terminal output and keystrokes travel in data frames of at most this many bytes.
pub const DATA_CHUNK: usize = 32 * 1024;

/// One frame as read. The payload is zeroed when the frame is dropped: an `answer` carries a password, and keystrokes can be one too.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Control(Zeroizing<Vec<u8>>),
    Data(Zeroizing<Vec<u8>>),
}

/// Why a frame could not be read. Every one of them ends the connection: the stream is out of step and nothing after it can be trusted.
#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    /// The length says more than `MAX_FRAME`.
    TooLarge(usize),
    UnknownType(u8),
    /// A length of 0: not even a type byte.
    Empty,
    /// The stream ended inside a frame.
    Truncated,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Io(error) => write!(f, "the connection failed: {error}"),
            FrameError::TooLarge(length) => write!(f, "a frame of {length} bytes is larger than the limit of {MAX_FRAME}"),
            FrameError::UnknownType(kind) => write!(f, "a frame of an unknown type ({kind})"),
            FrameError::Empty => write!(f, "an empty frame"),
            FrameError::Truncated => write!(f, "the connection ended in the middle of a frame"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Fills `buf` from `reader`. `Ok(false)` when the stream ended before the first byte; the end of the stream after that is `Truncated`.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool, FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::Io(error)),
        }
    }
    Ok(true)
}

/// Reads one frame. `Ok(None)`: the other side closed the stream cleanly, between two frames.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Frame>, FrameError> {
    let mut header = [0u8; 4];
    if !read_full(reader, &mut header)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > MAX_FRAME {
        return Err(FrameError::TooLarge(length));
    }
    let mut kind = [0u8; 1];
    if !read_full(reader, &mut kind)? {
        return Err(FrameError::Truncated);
    }
    let mut payload = Zeroizing::new(vec![0u8; length - 1]);
    if !payload.is_empty() && !read_full(reader, &mut payload)? {
        return Err(FrameError::Truncated);
    }
    match kind[0] {
        CONTROL => Ok(Some(Frame::Control(payload))),
        DATA => Ok(Some(Frame::Data(payload))),
        other => Err(FrameError::UnknownType(other)),
    }
}

/// Writes one frame in one `write_all`, so that a frame is never interleaved with another writer's (the writers share a lock anyway).
pub fn write_frame(writer: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() + 1 > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("a frame of {} bytes is larger than the limit of {MAX_FRAME}", payload.len() + 1)));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(payload.len() + 5));
    frame.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(payload);
    writer.write_all(&frame)?;
    writer.flush()
}

/// Writes one control message.
pub fn write_control<T: Serialize>(writer: &mut impl Write, message: &T) -> io::Result<()> {
    let json = Zeroizing::new(serde_json::to_vec(message).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?);
    write_frame(writer, CONTROL, &json)
}

/// Writes raw bytes in one data frame (`bytes` must fit in `MAX_FRAME`; senders split at `DATA_CHUNK`).
pub fn write_data(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    write_frame(writer, DATA, bytes)
}

/// Reads a control message. The error text never quotes the payload: serde's messages can include the value it choked on, and an
/// `answer` carries a password.
pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T, String> {
    serde_json::from_slice(payload).map_err(|_| "a control message SSHelter does not understand".to_string())
}

/// Who is connecting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// `sshelter connect`.
    Connect,
    /// The MCP adapter (phase 2).
    Mcp,
}

/// Which saved host: by alias, or by host id (spec §7.1; an alias that several hosts share is refused, and the client is told to use the id).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostQuery {
    Alias(String),
    Id(String),
}

impl fmt::Display for HostQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostQuery::Alias(alias) => f.write_str(alias),
            HostQuery::Id(id) => write!(f, "the host with the id {id}"),
        }
    }
}

/// The terminal a shell is opened for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyRequest {
    pub cols: u16,
    pub rows: u16,
    /// `$TERM` of the client's terminal.
    pub term: String,
}

/// A message from a client.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// The first message on a connection. `client_info` is what an MCP client says about itself (phase 2).
    Hello {
        client: ClientKind,
        version: u32,
        #[serde(default)]
        client_info: Option<serde_json::Value>,
    },
    OpenShell { host: HostQuery, pty: PtyRequest },
    /// A command without a terminal (phase 2). Read so that it can be refused by name; its fields are not looked at.
    Exec {},
    /// The client's terminal was resized.
    WindowChange { cols: u16, rows: u16 },
    /// The answer to a `question`: `value`, or `cancel` (the person pressed Ctrl-C or Ctrl-D).
    Answer {
        question_id: String,
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        cancel: bool,
    },
    /// The client is leaving: end the session.
    Close,
    /// A message type this version does not know.
    #[serde(other)]
    Unknown,
}

/// An answer's value can be a password, so the debug form leaves it out.
impl fmt::Debug for ClientMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientMessage::Hello { client, version, client_info } => {
                f.debug_struct("Hello").field("client", client).field("version", version).field("client_info", client_info).finish()
            }
            ClientMessage::OpenShell { host, pty } => f.debug_struct("OpenShell").field("host", host).field("pty", pty).finish(),
            ClientMessage::Exec {} => f.write_str("Exec"),
            ClientMessage::WindowChange { cols, rows } => f.debug_struct("WindowChange").field("cols", cols).field("rows", rows).finish(),
            ClientMessage::Answer { question_id, value, cancel } => f
                .debug_struct("Answer")
                .field("question_id", question_id)
                .field("value", &value.as_ref().map(|_| "<hidden>"))
                .field("cancel", cancel)
                .finish(),
            ClientMessage::Close => f.write_str("Close"),
            ClientMessage::Unknown => f.write_str("Unknown"),
        }
    }
}

/// What a question asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionKind {
    /// Not a question: the host key is being confirmed in the app's window (spec §7.2); the client shows the text and sends no answer.
    HostKeyNotice,
    Passphrase,
    Password,
    Interactive,
}

/// A question for the person at the client's terminal (spec §7.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Question {
    pub question_id: String,
    pub kind: QuestionKind,
    pub text: String,
    /// Whether what the person types may be shown.
    pub echo: bool,
    /// Milliseconds the answer is waited for, from when the question was sent; `None` for a notice. A later answer is not used: the login
    /// has been abandoned by then.
    pub deadline_ms: Option<u64>,
}

/// Something that happened, for the client to show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Connected,
    /// The connection ended without the shell reporting how; `reason` is the sentence to show (spec §11).
    Disconnected { reason: String },
    /// Something failed; `text` is the sentence to show (spec §11), `kind` a short word for programs (`kinds`).
    Error { kind: String, text: String },
    /// The server's banner, with control characters already replaced.
    Banner { text: String },
}

/// The `kind` words of `Event::Error`.
pub mod kinds {
    /// A frame or message the broker cannot read, or a protocol version it does not speak.
    pub const PROTOCOL: &str = "protocol";
    /// Something this version does not do yet (exec, MCP clients).
    pub const UNSUPPORTED: &str = "unsupported";
    /// The saved host could not be found or used.
    pub const HOST: &str = "host";
    /// The host key was not confirmed, or changed and was refused.
    pub const HOST_KEY: &str = "host_key";
    /// Login failed or was abandoned.
    pub const AUTH: &str = "auth";
    /// The host could not be reached, or another connection failure.
    pub const CONNECT: &str = "connect";
    /// The shell could not be started.
    pub const SHELL: &str = "shell";
    /// Input did not reach the server in time.
    pub const INPUT: &str = "input";
}

/// A message from the broker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The shell is open: raw mode and data from here on.
    Opened { session_id: String },
    Question(Question),
    Event(Event),
    /// The shell ended: its exit code, or the signal that killed it; both `None` when it ended without either (a lost connection, which
    /// an `event{disconnected}` explains). Never a disconnect reported as 0.
    Exited { code: Option<u32>, signal: Option<String> },
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::protocol::)
```

Expected: PASS, `test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 1613 filtered out`.

- [ ] **Step 5: Record the frame format in the spec**

`docs/superpowers/specs/2026-10-10-own-ssh-client-design.md`: apply this patch

```diff
--- a/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
+++ b/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
@@ -218,6 +218,7 @@ pub enum Exit { Code(u32), Signal(String), Refused(String), Disconnected } // Re
 - 用戶端 → app:`hello{client: "connect" | "mcp", client_info?}`、`open_shell{host, pty{cols, rows, term}}`、`exec{host, command, timeout_secs}`、`data`(stdin)、`window_change{cols, rows}`、`answer{question_id, value | cancel}`、`close`。
 - app → 用戶端:`opened{session_id}`、`data`(stdout/stderr 合併,因為是 PTY)、`exec_result{ended: exited | signaled | timed_out | truncated | disconnected, exit_code (可空), signal (可空), stdout, stderr, truncated: bool}`(第 0 期:被訊號殺掉的指令沒有結束碼,連線中斷也沒有;輸出到上限時 `truncated`,連線仍可用;不能回 0)、`question{question_id, kind: host_key_notice | passphrase | password | interactive, text, echo: bool, deadline_ms}`(逾時視同取消:連線丟掉,§6.2 第 4 步)、`event{connected | disconnected{reason} | error{kind, text}}`、`exited{code (可空), signal (可空)}`;跳板的 `disconnected{reason}` 取自出事那一跳自己的紀錄(§6.2 第 2 步)。
 - `host` 可以是 alias 或 host id;alias 在多個 space 重複時回錯誤要求用 id。
+- (第 1b 期)訊框的長度是 big-endian、包含型別那一個位元組;型別 `1` = 控制(一則 JSON,以 `type` 欄位分辨)、`2` = 資料;一個訊框最多 1 MiB,超過、型別不明或在訊框中間斷掉都結束連線。`hello` 另帶 `version`(協定版本,目前 `1`):app 更新後磁碟上的 CLI 可能和執行中的 app 不同版,版本不合時 broker 回錯誤,請使用者重開 SSHelter。`host` 寫成 `{"alias": …}` 或 `{"id": …}`,`--id` 明確指 id、不和 alias 混淆。`question` 的 `deadline_ms` 是從送出起還等多少毫秒,`host_key_notice` 為 `null`(只顯示,不回答);`answer` 帶 `value` 或 `cancel: true`。`event` 另有 `banner{text}`:伺服器在登入時送的 banner,控制字元已換掉。
 
 ### 7.2 Broker 規則
 
```

- [ ] **Step 6: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1618 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 7: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add docs/superpowers/specs/2026-10-10-own-ssh-client-design.md \
  src-tauri/src/lib.rs \
  src-tauri/src/session/mod.rs \
  src-tauri/src/session/protocol.rs
git commit -m "feat(session): add the frames and messages of the local IPC protocol"
```

Expected: `git status --short` lists the four files of this task; the `git diff --stat` prints nothing.

---

### Task 5: Starting SSHelter for a client, shared and renamed `--host`

**Files:**
- Create: `src-tauri/src/host_start.rs` (moved from `mcp.rs`, with its tests)
- Modify: `src-tauri/src/mcp.rs` (the moved code and its tests leave), `src-tauri/src/lib.rs` (`pub mod host_start;`, the second-launch rule, its tests), `src-tauri/src/main.rs` (the host flag)

**Interfaces:**
- Consumes (`mcp.rs` at a764792): `ensure_started`, `SpawnLocks`, `take_spawn_locks`, `take_spawn_locks_at`, `lock_file_until`, `start_host`, `host_command`, `detach_from_client`, `HOST_FLAG = "--mcp-host"`, `START_WAIT`; `lib.rs`'s `second_launch_shows_window` and `START_HIDDEN_ENV`.
- Produces (`host_start.rs`):
  - `pub const HOST_FLAG: &str = "--host"`, `pub const LEGACY_HOST_FLAG: &str = "--mcp-host"`, `pub fn is_host_flag(arg: &str) -> bool`
  - `pub(crate) const START_WAIT: Duration` (12 s), `pub(crate) enum SpawnLocks<G> { Held(G), Busy }`, `pub(crate) type SpawnGuards`
  - `pub(crate) fn ensure_started<T, G>(answering: impl FnMut() -> Option<T>, lock: impl FnOnce() -> SpawnLocks<G>, start: impl FnOnce() -> Result<(), String>, wait: Duration, no_answer: &str) -> Result<T, String>`
  - `pub(crate) fn take_spawn_locks() -> SpawnLocks<SpawnGuards>`, `pub(crate) fn start_host() -> Result<(), String>`
  - `mcp.rs` keeps `NO_ANSWER` and calls `host_start::ensure_started(…, NO_ANSWER)`; `main.rs` starts the desktop app as a host for `is_host_flag(args[1])`.

What shapes this task:
- R6: `sshelter connect` (plan 1b-2) needs exactly what the MCP adapter does when the app is not running — start it in the background, under the same two locks so that two clients never start two apps, and wait. The code moves out of `mcp.rs` unchanged, but for two things: the sentence for "nothing answered" becomes the caller's (`no_answer`: the adapter keeps its own, the CLI prints spec §11's `SSHelter did not start within 12 seconds.`), and the flag is `--host`.
- `--mcp-host` stays accepted (`is_host_flag`): an update's "Install & restart" starts the app again with the arguments it was started with, so a 0.17 app started by an adapter comes back with the old flag. A second launch with either flag shows no window (`second_launch_shows_window`); `sshelter connect …` as a second launch is the user's and shows the window like any other.
- The lock file keeps its name, `mcp-spawn.lock`: a 0.17 adapter and a newer client on the same computer must take the same lock (listed under "Decisions to confirm").
- The nine tests of the moved code move with it into `host_start::tests` (`the_adapter_starts_the_mcp_host_with_its_window_hidden` becomes `a_client_starts_the_host_with_the_new_flag_and_its_window_hidden`), and one is new (`the_host_flag_is_the_new_one_and_the_old_one_is_still_accepted`); `mcp.rs` keeps the six tests of what stays. The red is the moved tests failing to compile until the code is there.

- [ ] **Step 1: Write the tests**

`src-tauri/src/host_start.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const NO_ANSWER: &str = "nothing answered";

    #[test]
    fn the_host_flag_is_the_new_one_and_the_old_one_is_still_accepted() {
        assert!(is_host_flag("--host"));
        assert!(is_host_flag("--mcp-host"));
        assert!(!is_host_flag("--mcp"));
        assert!(!is_host_flag("--host=1"));
        assert!(!is_host_flag("connect"));
    }

    #[test]
    fn a_call_that_finds_a_bridge_once_it_holds_the_locks_starts_nothing() {
        // Another call or adapter started SSHelter while this one waited for the locks.
        let mut answers = [None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || SpawnLocks::Held(()),
            || panic!("SSHelter already answers: starting it again could run two"),
            Duration::ZERO,
            NO_ANSWER,
        );
        assert_eq!(found, Ok("bridge"));
    }

    #[test]
    fn parallel_calls_start_sshelter_once() {
        let running = Arc::new(AtomicBool::new(false));
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let locks = Arc::new(Mutex::new(()));
        let calls: Vec<_> = (0..4)
            .map(|_| {
                let (running, starts, locks) = (running.clone(), starts.clone(), locks.clone());
                thread::spawn(move || {
                    ensure_started(
                        || running.load(Ordering::SeqCst).then_some(()),
                        || SpawnLocks::Held(locks.lock().unwrap()),
                        || {
                            starts.fetch_add(1, Ordering::SeqCst);
                            // Its bridge answers a little later, as a real start's does.
                            let running = running.clone();
                            thread::spawn(move || {
                                thread::sleep(Duration::from_millis(50));
                                running.store(true, Ordering::SeqCst);
                            });
                            Ok(())
                        },
                        Duration::from_secs(5),
                        NO_ANSWER,
                    )
                })
            })
            .collect();
        for call in calls {
            assert_eq!(call.join().unwrap(), Ok(()));
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn no_answer_after_the_start_says_what_to_do() {
        let mut starts = 0;
        let result: Result<(), String> = ensure_started(
            || None,
            || SpawnLocks::Held(()),
            || {
                starts += 1;
                Ok(())
            },
            Duration::ZERO,
            NO_ANSWER,
        );
        assert_eq!(result, Err(NO_ANSWER.to_string()));
        assert_eq!(starts, 1);
    }

    #[test]
    fn when_another_adapter_keeps_the_locks_one_more_look_decides() {
        let no_start = || -> Result<(), String> { panic!("the other adapter may be starting it") };
        let mut answers = [None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || SpawnLocks::<()>::Busy,
            no_start,
            Duration::ZERO,
            NO_ANSWER,
        );
        assert_eq!(found, Ok("bridge"));

        let found: Result<(), String> =
            ensure_started(|| None, || SpawnLocks::<()>::Busy, no_start, Duration::ZERO, NO_ANSWER);
        assert_eq!(found, Err(NO_ANSWER.to_string()));
    }

    fn held(lock: FileLock) -> File {
        match lock {
            FileLock::Held(file) => file,
            FileLock::Busy => panic!("busy"),
            FileLock::Unavailable(e) => panic!("{e}"),
        }
    }

    #[test]
    fn the_spawn_lock_file_lets_one_adapter_in_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-data").join("mcp-spawn.lock");
        let first = held(lock_file_until(&path, Instant::now()));
        let second = lock_file_until(&path, Instant::now());
        assert!(matches!(second, FileLock::Busy));
        drop(first);
        // Free again: taken, even if it takes a few tries.
        let soon = Instant::now() + Duration::from_secs(5);
        held(lock_file_until(&path, soon));
    }

    #[test]
    fn a_spawn_lock_held_past_the_deadline_ends_the_call_after_one_more_ping() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-spawn.lock");
        // Another adapter holds it, stopped in the middle of a start.
        let _other = held(lock_file_until(&path, Instant::now()));
        let mut pings = 0;
        let began = Instant::now();
        let result: Result<(), String> = ensure_started(
            || {
                pings += 1;
                None
            },
            || take_spawn_locks_at(Ok(path.clone()), began + Duration::from_millis(300)),
            || panic!("the other adapter may be starting it"),
            Duration::from_secs(5),
            NO_ANSWER,
        );
        assert_eq!(result, Err(NO_ANSWER.to_string()));
        assert_eq!(pings, 2, "the first look, and one more at the deadline");
        assert!(began.elapsed() >= Duration::from_millis(300));
        assert!(began.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn without_a_lock_file_the_call_still_starts_sshelter() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, b"").unwrap();
        let path = not_a_dir.join("mcp-spawn.lock");
        assert!(matches!(
            lock_file_until(&path, Instant::now()),
            FileLock::Unavailable(_)
        ));

        let mut starts = 0;
        let mut answers = [None, None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || take_spawn_locks_at(Ok(path.clone()), Instant::now()),
            || {
                starts += 1;
                Ok(())
            },
            Duration::from_secs(5),
            NO_ANSWER,
        );
        assert_eq!(found, Ok("bridge"));
        assert_eq!(starts, 1);
    }

    #[test]
    fn a_client_starts_the_host_with_the_new_flag_and_its_window_hidden() {
        use std::ffi::OsStr;
        let command = host_command(Path::new("/usr/bin/sshelter"));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, [OsStr::new(HOST_FLAG)]);
        let flag = command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(crate::START_HIDDEN_ENV))
            .and_then(|(_, value)| value);
        assert!(crate::starts_hidden(flag));
    }

    #[cfg(unix)]
    #[test]
    fn the_host_starts_in_its_own_process_group() {
        let mut command = Command::new("cat");
        command.stdin(Stdio::piped()).stdout(Stdio::null());
        detach_from_client(&mut command);
        let mut child = crate::process::spawn(&mut command).unwrap();
        let pid = child.id() as libc::pid_t;
        let group = unsafe { libc::getpgid(pid) };
        let ours = unsafe { libc::getpgid(0) };
        drop(child.stdin.take()); // `cat` exits at end of input.
        child.wait().unwrap();
        assert_eq!(group, pid);
        assert_ne!(group, ours);
    }
}
```

`src-tauri/src/lib.rs`: apply this patch

```diff
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -7,6 +7,7 @@ mod deploy;
 mod discover;
 mod error;
 mod fsutil;
+pub mod host_start;
 mod ipc;
 mod keys;
 mod known_hosts;
@@ -332,9 +333,10 @@ mod tests {
     }
 
     #[test]
-    fn a_second_mcp_host_launch_shows_no_window() {
+    fn a_second_host_launch_shows_no_window_with_the_new_flag_or_the_old_one() {
+        assert!(!shows(&[EXE, "--host"]));
         assert!(!shows(&[EXE, "--mcp-host"]));
-        assert!(!shows(&[r"C:\SSHelter\sshelter.exe", "--mcp-host"]));
+        assert!(!shows(&[r"C:\SSHelter\sshelter.exe", "--host"]));
     }
 
     #[test]
@@ -342,9 +344,10 @@ mod tests {
         assert!(shows(&[EXE]));
         assert!(shows(&[]));
         // Same rule as main.rs: only the first argument picks the mode.
-        assert!(shows(&[EXE, "--other", "--mcp-host"]));
+        assert!(shows(&[EXE, "--other", "--host"]));
         assert!(shows(&[EXE, "--mcp"]));
-        assert!(shows(&[EXE, "--mcp-host=1"]));
+        assert!(shows(&[EXE, "connect", "web"]));
+        assert!(shows(&[EXE, "--host=1"]));
     }
 
     #[test]
@@ -369,12 +372,12 @@ mod tests {
         let normal_launch = HashMap::new();
         assert!(!hidden(&normal_launch));
 
-        // mcp.rs `host_command` sets it; main.rs reads it and then removes it from the process.
+        // host_start.rs `host_command` sets it; main.rs reads it and then removes it from the process.
         let mut adapter_start = HashMap::from([(START_HIDDEN_ENV, "1")]);
         assert!(hidden(&adapter_start));
         adapter_start.remove(START_HIDDEN_ENV);
 
-        // tauri restarts with the same arguments (`--mcp-host`) and this process's environment.
+        // tauri restarts with the same arguments (`--host`) and this process's environment.
         let restart = adapter_start;
         assert!(!hidden(&restart));
     }
```

`src-tauri/src/mcp.rs`: apply this patch

```diff
--- a/src-tauri/src/mcp.rs
+++ b/src-tauri/src/mcp.rs
@@ -1542,182 +1542,4 @@ mod tests {
             "a missing file is fine"
         );
     }
-
-    #[test]
-    fn a_call_that_finds_a_bridge_once_it_holds_the_locks_starts_nothing() {
-        // Another call or adapter started SSHelter while this one waited for the locks.
-        let mut answers = [None, Some("bridge")].into_iter();
-        let found = ensure_started(
-            || answers.next().flatten(),
-            || SpawnLocks::Held(()),
-            || panic!("SSHelter already answers: starting it again could run two"),
-            Duration::ZERO,
-        );
-        assert_eq!(found, Ok("bridge"));
-    }
-
-    #[test]
-    fn parallel_calls_start_sshelter_once() {
-        let running = Arc::new(AtomicBool::new(false));
-        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
-        let locks = Arc::new(Mutex::new(()));
-        let calls: Vec<_> = (0..4)
-            .map(|_| {
-                let (running, starts, locks) = (running.clone(), starts.clone(), locks.clone());
-                thread::spawn(move || {
-                    ensure_started(
-                        || running.load(Ordering::SeqCst).then_some(()),
-                        || SpawnLocks::Held(locks.lock().unwrap()),
-                        || {
-                            starts.fetch_add(1, Ordering::SeqCst);
-                            // Its bridge answers a little later, as a real start's does.
-                            let running = running.clone();
-                            thread::spawn(move || {
-                                thread::sleep(Duration::from_millis(50));
-                                running.store(true, Ordering::SeqCst);
-                            });
-                            Ok(())
-                        },
-                        Duration::from_secs(5),
-                    )
-                })
-            })
-            .collect();
-        for call in calls {
-            assert_eq!(call.join().unwrap(), Ok(()));
-        }
-        assert_eq!(starts.load(Ordering::SeqCst), 1);
-    }
-
-    #[test]
-    fn no_answer_after_the_start_says_what_to_do() {
-        let mut starts = 0;
-        let result: Result<(), String> = ensure_started(
-            || None,
-            || SpawnLocks::Held(()),
-            || {
-                starts += 1;
-                Ok(())
-            },
-            Duration::ZERO,
-        );
-        assert_eq!(result, Err(NO_ANSWER.to_string()));
-        assert_eq!(starts, 1);
-    }
-
-    #[test]
-    fn when_another_adapter_keeps_the_locks_one_more_look_decides() {
-        let no_start = || -> Result<(), String> { panic!("the other adapter may be starting it") };
-        let mut answers = [None, Some("bridge")].into_iter();
-        let found = ensure_started(
-            || answers.next().flatten(),
-            || SpawnLocks::<()>::Busy,
-            no_start,
-            Duration::ZERO,
-        );
-        assert_eq!(found, Ok("bridge"));
-
-        let found: Result<(), String> =
-            ensure_started(|| None, || SpawnLocks::<()>::Busy, no_start, Duration::ZERO);
-        assert_eq!(found, Err(NO_ANSWER.to_string()));
-    }
-
-    fn held(lock: FileLock) -> File {
-        match lock {
-            FileLock::Held(file) => file,
-            FileLock::Busy => panic!("busy"),
-            FileLock::Unavailable(e) => panic!("{e}"),
-        }
-    }
-
-    #[test]
-    fn the_spawn_lock_file_lets_one_adapter_in_at_a_time() {
-        let dir = tempfile::tempdir().unwrap();
-        let path = dir.path().join("app-data").join("mcp-spawn.lock");
-        let first = held(lock_file_until(&path, Instant::now()));
-        let second = lock_file_until(&path, Instant::now());
-        assert!(matches!(second, FileLock::Busy));
-        drop(first);
-        // Free again: taken, even if it takes a few tries.
-        let soon = Instant::now() + Duration::from_secs(5);
-        held(lock_file_until(&path, soon));
-    }
-
-    #[test]
-    fn a_spawn_lock_held_past_the_deadline_ends_the_call_after_one_more_ping() {
-        let dir = tempfile::tempdir().unwrap();
-        let path = dir.path().join("mcp-spawn.lock");
-        // Another adapter holds it, stopped in the middle of a start.
-        let _other = held(lock_file_until(&path, Instant::now()));
-        let mut pings = 0;
-        let began = Instant::now();
-        let result: Result<(), String> = ensure_started(
-            || {
-                pings += 1;
-                None
-            },
-            || take_spawn_locks_at(Ok(path.clone()), began + Duration::from_millis(300)),
-            || panic!("the other adapter may be starting it"),
-            Duration::from_secs(5),
-        );
-        assert_eq!(result, Err(NO_ANSWER.to_string()));
-        assert_eq!(pings, 2, "the first look, and one more at the deadline");
-        assert!(began.elapsed() >= Duration::from_millis(300));
-        assert!(began.elapsed() < Duration::from_secs(5));
-    }
-
-    #[test]
-    fn without_a_lock_file_the_call_still_starts_sshelter() {
-        let dir = tempfile::tempdir().unwrap();
-        let not_a_dir = dir.path().join("file");
-        std::fs::write(&not_a_dir, b"").unwrap();
-        let path = not_a_dir.join("mcp-spawn.lock");
-        assert!(matches!(
-            lock_file_until(&path, Instant::now()),
-            FileLock::Unavailable(_)
-        ));
-
-        let mut starts = 0;
-        let mut answers = [None, None, Some("bridge")].into_iter();
-        let found = ensure_started(
-            || answers.next().flatten(),
-            || take_spawn_locks_at(Ok(path.clone()), Instant::now()),
-            || {
-                starts += 1;
-                Ok(())
-            },
-            Duration::from_secs(5),
-        );
-        assert_eq!(found, Ok("bridge"));
-        assert_eq!(starts, 1);
-    }
-
-    #[test]
-    fn the_adapter_starts_the_mcp_host_with_its_window_hidden() {
-        use std::ffi::OsStr;
-        let command = host_command(Path::new("/usr/bin/sshelter"));
-        let args: Vec<_> = command.get_args().collect();
-        assert_eq!(args, [OsStr::new(HOST_FLAG)]);
-        let flag = command
-            .get_envs()
-            .find(|(key, _)| *key == OsStr::new(crate::START_HIDDEN_ENV))
-            .and_then(|(_, value)| value);
-        assert!(crate::starts_hidden(flag));
-    }
-
-    #[cfg(unix)]
-    #[test]
-    fn the_host_starts_in_its_own_process_group() {
-        let mut command = Command::new("cat");
-        command.stdin(Stdio::piped()).stdout(Stdio::null());
-        detach_from_adapter(&mut command);
-        let mut child = crate::process::spawn(&mut command).unwrap();
-        let pid = child.id() as libc::pid_t;
-        let group = unsafe { libc::getpgid(pid) };
-        let ours = unsafe { libc::getpgid(0) };
-        drop(child.stdin.take()); // `cat` exits at end of input.
-        child.wait().unwrap();
-        assert_eq!(group, pid);
-        assert_ne!(group, ours);
-    }
 }
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- host_start:: mcp:: tests::a_second_host_launch tests::any_other_second_launch)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find function `ensure_started` in this scope
error: could not compile `sshelter` (lib test) due to 61 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/host_start.rs`: insert above the `#[cfg(test)]` line

```rust
//! Starting SSHelter in the background for a client that needs it and finds it not running (own-ssh spec §4): the MCP adapter, and
//! `sshelter connect` from plan 1b on. Both start the same thing, the app as a host (`--host`, its window hidden), under the same two
//! locks, so that they never start two. Moved here from `mcp.rs` unchanged, but for two things: the message for "nothing answered" is
//! the caller's (spec §11 gives the CLI its own), and the flag is `--host`, with the old `--mcp-host` still accepted (an update's
//! "Install & restart" starts the app again with the arguments it was started with).

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::AppError;
use crate::fsutil;

/// First argument that starts SSHelter as the host of its clients (main.rs): the desktop app, in the background.
pub const HOST_FLAG: &str = "--host";
/// The host flag before plan 1b. Still accepted, for the restart of an app that was started with it.
pub const LEGACY_HOST_FLAG: &str = "--mcp-host";

/// Whether `arg`, the first argument (main.rs reads the mode from it), starts SSHelter as a host.
pub fn is_host_flag(arg: &str) -> bool {
    arg == HOST_FLAG || arg == LEGACY_HOST_FLAG
}

/// How long a client waits for the SSHelter it started, and how often it looks.
pub(crate) const START_WAIT: Duration = Duration::from_secs(12);
const START_POLL: Duration = Duration::from_millis(120);

/// Serializes starting SSHelter between this process's calls, which can run in parallel (the MCP adapter's tool calls).
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// What a call got when it asked for the spawn locks.
pub(crate) enum SpawnLocks<G> {
    /// Start SSHelter while holding `G`.
    Held(G),
    /// Another client kept `mcp-spawn.lock` past the deadline: it may be stopped in the middle
    /// of a start (its AI CLI or its terminal suspended, for example).
    Busy,
}

/// Return what `answering` finds (a bridge, a socket) once it answers. If nothing does, take the
/// spawn locks and look again: a parallel call or another client may have started SSHelter
/// meanwhile. Only if still nothing answers, start SSHelter once and wait for it. Several
/// near-simultaneous starts could each claim the single instance before the others see it
/// (macOS), and leave two SSHelters running; so when another client keeps the locks too long,
/// look once more instead of starting a second one. `no_answer` is the error when nothing
/// answers in the end.
pub(crate) fn ensure_started<T, G>(
    mut answering: impl FnMut() -> Option<T>,
    lock: impl FnOnce() -> SpawnLocks<G>,
    start: impl FnOnce() -> Result<(), String>,
    wait: Duration,
    no_answer: &str,
) -> Result<T, String> {
    if let Some(found) = answering() {
        return Ok(found);
    }
    let _locks = match lock() {
        SpawnLocks::Held(locks) => locks,
        SpawnLocks::Busy => return answering().ok_or_else(|| no_answer.to_string()),
    };
    if let Some(found) = answering() {
        return Ok(found);
    }
    start()?;
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        thread::sleep(START_POLL);
        if let Some(found) = answering() {
            return Ok(found);
        }
    }
    Err(no_answer.to_string())
}

/// `SPAWN_LOCK`, and `mcp-spawn.lock` unless it can't be taken here.
pub(crate) type SpawnGuards = (MutexGuard<'static, ()>, Option<File>);

pub(crate) fn take_spawn_locks() -> SpawnLocks<SpawnGuards> {
    // The deadline counts from before this call waits for the adapter's other calls, so a call
    // never waits much longer than `START_WAIT` for the locks.
    let deadline = Instant::now() + START_WAIT;
    take_spawn_locks_at(spawn_lock_path().map_err(|e| e.to_string()), deadline)
}

/// Takes `SPAWN_LOCK` (this process's calls), then the exclusive file lock on `path`, by
/// default `mcp-spawn.lock` in the app data directory (other clients: other AI sessions, other
/// terminals), which the system releases when its holder exits. Dropping the guards releases both.
/// A file lock that can't be taken here at all (no app data directory, a file system without
/// locks) is skipped, as before there was one: only this process's calls wait for each other.
fn take_spawn_locks_at(
    path: Result<PathBuf, String>,
    deadline: Instant,
) -> SpawnLocks<SpawnGuards> {
    let calls = SPAWN_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let file = match path {
        Ok(path) => lock_file_until(&path, deadline),
        Err(e) => FileLock::Unavailable(e),
    };
    match file {
        FileLock::Held(file) => SpawnLocks::Held((calls, Some(file))),
        FileLock::Busy => SpawnLocks::Busy,
        FileLock::Unavailable(reason) => {
            eprintln!("[host] starting SSHelter without mcp-spawn.lock: {reason}");
            SpawnLocks::Held((calls, None))
        }
    }
}

/// The lock file keeps the name it had when only the MCP adapter started SSHelter: a 0.17 adapter
/// and a newer client on the same computer still take the same lock.
fn spawn_lock_path() -> Result<PathBuf, AppError> {
    Ok(crate::fsutil::app_data_root()?.join("mcp-spawn.lock"))
}

enum FileLock {
    Held(File),
    /// Someone else still held it at the deadline.
    Busy,
    /// It can't be opened or locked here.
    Unavailable(String),
}

/// Open `path`, creating it and its directory, and take an exclusive lock on it, trying until
/// `deadline`.
fn lock_file_until(path: &Path, deadline: Instant) -> FileLock {
    let opened = path
        .parent()
        .map_or(Ok(()), fsutil::ensure_dir_secure)
        .map_err(|e| e.to_string())
        .and_then(|()| {
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(path)
                .map_err(|e| e.to_string())
        });
    let file = match opened {
        Ok(file) => file,
        Err(e) => return FileLock::Unavailable(format!("cannot open {}: {e}", path.display())),
    };
    loop {
        match file.try_lock() {
            Ok(()) => return FileLock::Held(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(START_POLL),
            Err(TryLockError::WouldBlock) => return FileLock::Busy,
            Err(TryLockError::Error(e)) => {
                return FileLock::Unavailable(format!("cannot lock {}: {e}", path.display()))
            }
        }
    }
}

/// Start SSHelter in the background, or, when it already runs, hand over to it (single
/// instance): the running SSHelter rewrites the MCP runtime file and starts the broker's socket
/// again if it is not listening (lib.rs `on_second_launch`).
pub(crate) fn start_host() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate SSHelter: {e}"))?;
    let mut host = crate::process::spawn(&mut host_command(&exe))
        .map_err(|e| format!("cannot start SSHelter desktop: {e}"))?;
    // A launch that hands over exits at once: reap it instead of leaving a zombie behind.
    let _ = thread::Builder::new()
        .name("sshelter-host-wait".to_string())
        .spawn(move || {
            let _ = host.wait();
        });
    Ok(())
}

/// `--host` decides the hand-over and keeps SSHelter running when its window closes;
/// `SSHELTER_START_HIDDEN=1` keeps the window hidden at this start only (lib.rs `starts_hidden`).
fn host_command(exe: &Path) -> Command {
    let mut command = Command::new(exe);
    command
        .arg(HOST_FLAG)
        .env(crate::START_HIDDEN_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach_from_client(&mut command);
    command
}

/// Start the host outside the client's process group: an AI tool that ends its session by killing
/// its MCP server's process group, or a terminal tab that is closed with `sshelter connect` in it,
/// must not take SSHelter down with it.
fn detach_from_client(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
        // Its own process group: the client's console Ctrl+C / Ctrl+Break does not reach it.
        // No console: closing the console the AI tool runs in does not end it either.
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
}
```

`src-tauri/src/lib.rs`: apply this patch

```diff
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -76,21 +76,22 @@ pub fn run() {
 }
 
 /// The desktop app (main.rs).
-/// - `mcp_host`: started with `--mcp-host` by a stdio MCP adapter. Closing the window hides it
-///   instead of terminating active MCP access. (When SSHelter already runs, such a launch hands
-///   over without showing a window: `second_launch_shows_window`.)
-/// - `start_hidden`: see `starts_hidden`. The adapter's start runs in the background: no window
-///   until the user opens it or an MCP `run` request needs approval.
-pub fn run_desktop(mcp_host: bool, start_hidden: bool) {
-    run_app(mcp_host, start_hidden);
+/// - `host`: started with `--host` (or the older `--mcp-host`) by a client that needed it: the
+///   stdio MCP adapter or `sshelter connect` (`host_start`). Closing the window hides it instead
+///   of ending what the clients are using. (When SSHelter already runs, such a launch hands over
+///   without showing a window: `second_launch_shows_window`.)
+/// - `start_hidden`: see `starts_hidden`. A client's start runs in the background: no window
+///   until the user opens it or something needs the user (an MCP approval, a host key).
+pub fn run_desktop(host: bool, start_hidden: bool) {
+    run_app(host, start_hidden);
 }
 
-/// Set to `1` by the stdio MCP adapter on the SSHelter it starts (mcp.rs `host_command`).
+/// Set to `1` by a client on the SSHelter it starts (host_start.rs `host_command`).
 /// main.rs reads it, then removes it before anything else runs.
 pub const START_HIDDEN_ENV: &str = "SSHELTER_START_HIDDEN";
 
 /// Whether the main window starts hidden, from the value of `SSHELTER_START_HIDDEN`; nothing else
-/// decides it. A restart (an update's "Install & restart") reuses the arguments, `--mcp-host`
+/// decides it. A restart (an update's "Install & restart") reuses the arguments, the host flag
 /// included, but inherits an environment without the variable, so it comes back with its window.
 pub fn starts_hidden(value: Option<&std::ffi::OsStr>) -> bool {
     value == Some(std::ffi::OsStr::new("1"))
@@ -106,12 +107,12 @@ pub(crate) fn show_main_window(app: &tauri::AppHandle) {
 }
 
 /// What a second launch does in the running SSHelter. `args` are the second process's
-/// arguments, executable path first, so its mode is `args[1]` (as in main.rs). An MCP host
-/// launch means an adapter could not reach the bridge: it needs the bridge, not a window.
-/// Any other launch is the user opening SSHelter again.
+/// arguments, executable path first, so its mode is `args[1]` (as in main.rs). A host launch
+/// means a client could not reach this instance: it needs the bridge or the socket, not a
+/// window. Any other launch is the user opening SSHelter again.
 #[cfg(desktop)]
 fn second_launch_shows_window(args: &[String]) -> bool {
-    args.get(1).map(String::as_str) != Some(mcp::HOST_FLAG)
+    !args.get(1).is_some_and(|mode| host_start::is_host_flag(mode))
 }
 
 /// The single-instance plugin stopped a second launch before it started anything and handed
@@ -125,7 +126,7 @@ fn on_second_launch(app: &tauri::AppHandle, args: Vec<String>, _cwd: String) {
     }
 }
 
-fn run_app(mcp_host: bool, start_hidden: bool) {
+fn run_app(host: bool, start_hidden: bool) {
     let builder = tauri::Builder::default();
     // Only one SSHelter runs at a time: a second launch hands over to the running instance and
     // exits during plugin setup, before any window, the MCP bridge (and its runtime file), the
@@ -172,7 +173,7 @@ fn run_app(mcp_host: bool, start_hidden: bool) {
                     window.show()?;
                 }
             }
-            mcp::initialize(app.handle(), mcp_host)?;
+            mcp::initialize(app.handle(), host)?;
             sync::engine::initialize(app.handle())?;
             // SSHelter 的 SSH agent(金鑰保管庫 spec §5.1):開不起來只記在 `AgentRuntime::status`,不擋啟動。
             agent::start(app.handle());
```

`src-tauri/src/main.rs`: apply this patch

```diff
--- a/src-tauri/src/main.rs
+++ b/src-tauri/src/main.rs
@@ -17,7 +17,7 @@ fn main() {
 
     match std::env::args().nth(1).as_deref() {
         Some("--mcp") => sshelter_lib::mcp::run_stdio(),
-        Some(sshelter_lib::mcp::HOST_FLAG) => sshelter_lib::run_desktop(true, start_hidden),
+        Some(flag) if sshelter_lib::host_start::is_host_flag(flag) => sshelter_lib::run_desktop(true, start_hidden),
         _ => sshelter_lib::run_desktop(false, start_hidden),
     }
 }
```

`src-tauri/src/mcp.rs`: apply this patch

```diff
--- a/src-tauri/src/mcp.rs
+++ b/src-tauri/src/mcp.rs
@@ -8,13 +8,12 @@
 //! process running as the same OS account.
 
 use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
-use std::fs::{File, OpenOptions, TryLockError};
 use std::io::{BufRead, BufReader, Read, Write};
 use std::net::{Ipv4Addr, TcpListener, TcpStream};
 use std::path::{Path, PathBuf};
-use std::process::{Command, Stdio};
+use std::process::Stdio;
 use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
-use std::sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError};
+use std::sync::{mpsc, Arc, Mutex};
 use std::thread;
 use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
 
@@ -29,9 +28,6 @@ use crate::error::AppError;
 use crate::fsutil;
 use crate::state::AppState;
 
-/// First argument that starts SSHelter as the MCP host (main.rs): the desktop app, in the background.
-pub const HOST_FLAG: &str = "--mcp-host";
-
 const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
 const MAX_BRIDGE_LINE: u64 = 1_048_576;
 const MAX_COMMAND_BYTES: usize = 16_384;
@@ -1266,18 +1262,15 @@ const CALL_TIMEOUT: Duration = Duration::from_secs(430);
 /// file may belong to another program by now, and a ping must not hang on it while holding the
 /// spawn locks.
 const PING_TIMEOUT: Duration = Duration::from_secs(5);
-/// How long an adapter waits for the bridge of the SSHelter it started, and how often it looks.
-const START_WAIT: Duration = Duration::from_secs(12);
-const START_POLL: Duration = Duration::from_millis(120);
 /// Only one SSHelter runs: an open SSHelter whose bridge doesn't answer is not replaced.
 const NO_ANSWER: &str =
     "SSHelter didn't answer within 12 seconds. If it is open, quit it and open it again.";
 
-/// Serializes starting SSHelter between this adapter's tool calls, which run in parallel.
-static SPAWN_LOCK: Mutex<()> = Mutex::new(());
-
+/// The bridge of a running SSHelter, started in the background first if none answers
+/// (`host_start`, shared with `sshelter connect`).
 fn ensure_desktop_bridge() -> Result<RuntimeInfo, String> {
-    ensure_started(answering_bridge, take_spawn_locks, start_host, START_WAIT)
+    use crate::host_start::{ensure_started, start_host, take_spawn_locks, START_WAIT};
+    ensure_started(answering_bridge, take_spawn_locks, start_host, START_WAIT, NO_ANSWER)
 }
 
 /// The bridge named in `mcp-runtime.json`, if it answers a ping.
@@ -1287,171 +1280,6 @@ fn answering_bridge() -> Option<RuntimeInfo> {
         .filter(|info| send_to_runtime(info, "ping", json!({}), PING_TIMEOUT).is_ok())
 }
 
-/// What a call got when it asked for the spawn locks.
-enum SpawnLocks<G> {
-    /// Start SSHelter while holding `G`.
-    Held(G),
-    /// Another adapter kept `mcp-spawn.lock` past the deadline: it may be stopped in the middle
-    /// of a start (its AI CLI suspended, for example).
-    Busy,
-}
-
-/// Return a bridge that answers. If none does, take the spawn locks and look again: a parallel
-/// call or another adapter may have started SSHelter meanwhile. Only if still none answers, start
-/// SSHelter once and wait for its bridge. Several near-simultaneous starts could each claim the
-/// single instance before the others see it (macOS), and leave two SSHelters running; so when
-/// another adapter keeps the locks too long, look once more instead of starting a second one.
-fn ensure_started<T, G>(
-    mut answering: impl FnMut() -> Option<T>,
-    lock: impl FnOnce() -> SpawnLocks<G>,
-    start: impl FnOnce() -> Result<(), String>,
-    wait: Duration,
-) -> Result<T, String> {
-    if let Some(found) = answering() {
-        return Ok(found);
-    }
-    let _locks = match lock() {
-        SpawnLocks::Held(locks) => locks,
-        SpawnLocks::Busy => return answering().ok_or_else(|| NO_ANSWER.to_string()),
-    };
-    if let Some(found) = answering() {
-        return Ok(found);
-    }
-    start()?;
-    let deadline = Instant::now() + wait;
-    while Instant::now() < deadline {
-        thread::sleep(START_POLL);
-        if let Some(found) = answering() {
-            return Ok(found);
-        }
-    }
-    Err(NO_ANSWER.to_string())
-}
-
-/// `SPAWN_LOCK`, and `mcp-spawn.lock` unless it can't be taken here.
-type SpawnGuards = (MutexGuard<'static, ()>, Option<File>);
-
-fn take_spawn_locks() -> SpawnLocks<SpawnGuards> {
-    // The deadline counts from before this call waits for the adapter's other calls, so a call
-    // never waits much longer than `START_WAIT` for the locks.
-    let deadline = Instant::now() + START_WAIT;
-    take_spawn_locks_at(spawn_lock_path().map_err(|e| e.to_string()), deadline)
-}
-
-/// Takes `SPAWN_LOCK` (this adapter's tool calls), then the exclusive file lock on `path`, by
-/// default `mcp-spawn.lock` in the app data directory (other adapters, that is other AI
-/// sessions), which the system releases when its holder exits. Dropping the guards releases both.
-/// A file lock that can't be taken here at all (no app data directory, a file system without
-/// locks) is skipped, as before there was one: only this adapter's calls wait for each other.
-fn take_spawn_locks_at(
-    path: Result<PathBuf, String>,
-    deadline: Instant,
-) -> SpawnLocks<SpawnGuards> {
-    let calls = SPAWN_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
-    let file = match path {
-        Ok(path) => lock_file_until(&path, deadline),
-        Err(e) => FileLock::Unavailable(e),
-    };
-    match file {
-        FileLock::Held(file) => SpawnLocks::Held((calls, Some(file))),
-        FileLock::Busy => SpawnLocks::Busy,
-        FileLock::Unavailable(reason) => {
-            eprintln!("[mcp] starting SSHelter without mcp-spawn.lock: {reason}");
-            SpawnLocks::Held((calls, None))
-        }
-    }
-}
-
-fn spawn_lock_path() -> Result<PathBuf, AppError> {
-    Ok(crate::fsutil::app_data_root()?.join("mcp-spawn.lock"))
-}
-
-enum FileLock {
-    Held(File),
-    /// Someone else still held it at the deadline.
-    Busy,
-    /// It can't be opened or locked here.
-    Unavailable(String),
-}
-
-/// Open `path`, creating it and its directory, and take an exclusive lock on it, trying until
-/// `deadline`.
-fn lock_file_until(path: &Path, deadline: Instant) -> FileLock {
-    let opened = path
-        .parent()
-        .map_or(Ok(()), fsutil::ensure_dir_secure)
-        .map_err(|e| e.to_string())
-        .and_then(|()| {
-            OpenOptions::new()
-                .create(true)
-                .truncate(false)
-                .write(true)
-                .open(path)
-                .map_err(|e| e.to_string())
-        });
-    let file = match opened {
-        Ok(file) => file,
-        Err(e) => return FileLock::Unavailable(format!("cannot open {}: {e}", path.display())),
-    };
-    loop {
-        match file.try_lock() {
-            Ok(()) => return FileLock::Held(file),
-            Err(TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(START_POLL),
-            Err(TryLockError::WouldBlock) => return FileLock::Busy,
-            Err(TryLockError::Error(e)) => {
-                return FileLock::Unavailable(format!("cannot lock {}: {e}", path.display()))
-            }
-        }
-    }
-}
-
-/// Start SSHelter in the background, or, when it already runs, hand over to it (single
-/// instance): the running SSHelter rewrites the runtime file with its bridge.
-fn start_host() -> Result<(), String> {
-    let exe = std::env::current_exe().map_err(|e| format!("cannot locate SSHelter: {e}"))?;
-    let mut host = crate::process::spawn(&mut host_command(&exe))
-        .map_err(|e| format!("cannot start SSHelter desktop: {e}"))?;
-    // A launch that hands over exits at once: reap it instead of leaving a zombie behind.
-    let _ = thread::Builder::new()
-        .name("sshelter-mcp-host-wait".to_string())
-        .spawn(move || {
-            let _ = host.wait();
-        });
-    Ok(())
-}
-
-/// `--mcp-host` decides the hand-over and keeps SSHelter running when its window closes;
-/// `SSHELTER_START_HIDDEN=1` keeps the window hidden at this start only (lib.rs `starts_hidden`).
-fn host_command(exe: &Path) -> Command {
-    let mut command = Command::new(exe);
-    command
-        .arg(HOST_FLAG)
-        .env(crate::START_HIDDEN_ENV, "1")
-        .stdin(Stdio::null())
-        .stdout(Stdio::null())
-        .stderr(Stdio::null());
-    detach_from_adapter(&mut command);
-    command
-}
-
-/// Start the MCP host outside the adapter's process group: an AI tool that ends its session by
-/// killing its MCP server's process group must not take SSHelter down with it.
-fn detach_from_adapter(command: &mut Command) {
-    #[cfg(unix)]
-    {
-        use std::os::unix::process::CommandExt;
-        command.process_group(0);
-    }
-    #[cfg(windows)]
-    {
-        use std::os::windows::process::CommandExt;
-        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
-        // Its own process group: the adapter's console Ctrl+C / Ctrl+Break does not reach it.
-        // No console: closing the console the AI tool runs in does not end it either.
-        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
-    }
-}
-
 fn bridge_call(method: &str, params: Value) -> Result<Value, String> {
     let info = ensure_desktop_bridge()?;
     // Never automatically retry a tool call: an application-level denial or a
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- host_start:: mcp:: tests::a_second_host_launch tests::any_other_second_launch)
```

Expected: PASS, `test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 1600 filtered out` (`host_start::` alone: 10).

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1619 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out` (one test more than after Task 4: the new flag test); the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/host_start.rs \
  src-tauri/src/lib.rs \
  src-tauri/src/main.rs \
  src-tauri/src/mcp.rs
git commit -m "refactor: share starting SSHelter in the background between its clients, as --host"
```

Expected: `git status --short` lists the four files of this task; the `git diff --stat` prints nothing.

---

### Task 6: The host directory interface, its fake, and the pin file

**Files:**
- Create: `src-tauri/src/session/directory.rs` (the interface)
- Create: `src-tauri/src/session/pins.rs` (with its tests)
- Create: `src-tauri/src/session/testing.rs` (the broker's test doubles, with their own tests)
- Modify: `src-tauri/src/session/mod.rs`

**Interfaces:**
- Consumes: `crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target}` (plan 1a; `HostKey::from_openssh_line` in tests), `session::protocol::HostQuery` (Task 4), `crate::fsutil::atomic_write(path, bytes, mode)`.
- Produces:
  - `session/directory.rs`:
    - `pub struct PinnedKey { pub key: HostKey, pub pinned_at_ms: u64 }`
    - `pub enum DirectoryError { NotFound(String), Ambiguous(String), Unsupported(String), Failed(String) }` — `Display` is the sentence
    - `pub trait HostDirectory: Send + Sync` with `fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError>`, `fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError>`, `fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError>`, `fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError>`, `fn password_account(&self, host: &HostId) -> String`
  - `session/pins.rs`: `pub struct PinStore` with `new(path: PathBuf)`, `with_clock(path: PathBuf, clock: fn() -> u64)`, `path(&self) -> &Path`, `get(&self, host: &HostId) -> Result<Option<PinnedKey>, String>`, `pin(&self, host: &HostId, key: &HostKey) -> Result<(), String>`, `replace(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), String>`
  - `session/testing.rs` (test builds only): `pub fn locked<T>(&Mutex<T>) -> MutexGuard<'_, T>`; `pub struct FakeDirectory` with `new()`, `with_host(alias, auth)`, `with_host_via(alias, auth, jumps: &[&str])`, `with_second_host_called(alias)`, `with_pin(alias, key)`, `pins() -> HashMap<HostId, PinnedKey>` and `impl HostDirectory`; `pub const PINNED_AT_MS: u64`; `pub fn check_the_pin_contract(directory: &dyn HostDirectory, query: &HostQuery, first: &HostKey, second: &HostKey, third: &HostKey)`

What shapes this task:
- R2: the broker sees saved hosts only through `HostDirectory`: a host by alias or by id, resolved into the jump chain the engine connects through with each hop's pin in `Hop::pinned` (spec §6.2 step 1: a loop or a host that is not saved fails here, before anything connects); pinning; the keychain account of a host's password. Task 7 implements it over today's data, plan 1c over host records; the broker does not change between the two.
- Reading pins fails closed: a pin store that cannot be read is an error, never "nothing pinned". Otherwise a damaged file would make every pinned host look new and invite the person to trust whatever key is presented (spec §3).
- `pin` is idempotent for the same key and refuses another one (two connections confirming the same host at once must not overwrite each other's pin silently); `replace_pin` replaces only while the key the person was shown as "pinned" is still the pinned one.
- The pin file of 1b (R2: owned by the adapter, moved into `host.host_key` by plan 1c): `<app data>/host-pins.json`, `{"version": 1, "pins": {<host id>: {algorithm, public_key (SSH wire format, base64), fingerprint, pinned_at_ms}}}`. Every change is read, check and atomic write (`fsutil::atomic_write`, mode 0600) under one lock. A file in another format version is an error and is never overwritten, so a newer SSHelter's file survives a downgrade. `~/.ssh/known_hosts` is never read or written (spec §1).
- `FakeDirectory` names its hosts predictably — host id `id-<alias>`, hostname `<alias>.example.com`, user `deploy` — and `with_second_host_called` makes an alias ambiguous (spec §7.1: the client is told to use the id). `check_the_pin_contract` is what every directory must do with pins; it runs here on the fake and in Task 7 on the adapter.

- [ ] **Step 1: Write the interface and the tests**

`src-tauri/src/session/directory.rs`: create

```rust
//! Where the broker finds saved hosts (own-ssh spec §5.1, §6.2 step 1, §7.1): a host by alias or by host id, resolved into the jump chain
//! the engine connects through, with the pinned host keys in `Hop::pinned`; pinning a key the person trusted; and the keychain account
//! of a host's saved password. In this version the hosts are the app's ssh_config blocks, through a temporary adapter
//! (`ssh_config_directory.rs`; plan 1c replaces it with host records). The broker sees only this trait.

use std::fmt;

use super::protocol::HostQuery;
use crate::ssh::{HostId, HostKey, Target};

/// A pinned host key and when it was pinned (milliseconds since the Unix epoch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedKey {
    pub key: HostKey,
    pub pinned_at_ms: u64,
}

/// Why a host could not be found or a pin not written. The text is the sentence to show the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryError {
    /// No saved host matches.
    NotFound(String),
    /// Several saved hosts have this alias; the client has to name one by its id (spec §7.1).
    Ambiguous(String),
    /// The host is saved, but SSHelter's own client cannot connect to it (a ProxyCommand, a key that is not in SSHelter).
    Unsupported(String),
    /// Reading the saved hosts or the pins, or writing a pin, failed.
    Failed(String),
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectoryError::NotFound(text) | DirectoryError::Ambiguous(text) | DirectoryError::Unsupported(text) | DirectoryError::Failed(text) => {
                f.write_str(text)
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

/// The saved hosts, as the broker needs them. Implementations are called from the broker's connection threads, never from async code.
pub trait HostDirectory: Send + Sync {
    /// The saved host `query` names, with its jump hosts in front (each a saved host too), ready for the engine. The pin of each hop is in
    /// `Hop::pinned`. A chain that loops or names a host that is not saved is an error here, before anything connects.
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError>;

    /// The key pinned for `host`, if any. An error reading the pins is `Err`, never "nothing pinned": a host that was pinned must not
    /// look new because a file could not be read.
    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError>;

    /// Pins `key` for `host`: the person trusted it in the window. Pinning the key that is pinned already is fine; when another key was
    /// pinned in the meantime, nothing is written and the call fails.
    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError>;

    /// Replaces the pin of `host` with `key`: the person accepted a changed key. Only while `previous` is still the pinned key (or `key`
    /// already is); otherwise nothing is written and the call fails.
    fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError>;

    /// The keychain account of the saved password of `host` (spec §5.5: `host:<host id>`).
    fn password_account(&self, host: &HostId) -> String;
}
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -2,4 +2,8 @@
 //! version, the MCP adapter in phase 2 — asks the client (or the app's window, for host keys) what a login needs, and relays the
 //! terminal. Every SSH call it makes blocks, so it runs on plain threads, never in async code and never on the UI thread.
 
+pub mod directory;
+pub mod pins;
 pub mod protocol;
+#[cfg(test)]
+pub mod testing;
```

`src-tauri/src/session/pins.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).expect("a test key")
    }

    fn store(dir: &tempfile::TempDir) -> PinStore {
        PinStore::with_clock(dir.path().join("app-data").join("host-pins.json"), || 1_700_000_000_000)
    }

    #[test]
    fn a_pin_is_written_to_the_file_and_read_back_with_the_time_it_was_made() {
        let dir = tempfile::tempdir().unwrap();
        let pins = store(&dir);
        let web = HostId::from("web");
        assert_eq!(pins.get(&web), Ok(None), "no file yet: nothing is pinned");
        pins.pin(&web, &key(test_keys::PLAIN_PUBLIC)).unwrap();
        assert_eq!(pins.get(&web), Ok(Some(PinnedKey { key: key(test_keys::PLAIN_PUBLIC), pinned_at_ms: 1_700_000_000_000 })));

        let path = dir.path().join("app-data").join("host-pins.json");
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["version"], 1);
        assert_eq!(saved["pins"]["web"]["algorithm"], "ssh-ed25519");
        assert_eq!(saved["pins"]["web"]["fingerprint"], test_keys::PLAIN_FINGERPRINT);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let reopened = store(&dir);
        assert_eq!(reopened.get(&web).unwrap().map(|pin| pin.key), Some(key(test_keys::PLAIN_PUBLIC)), "a new store reads the same file");
    }

    #[test]
    fn pinning_the_pinned_key_again_is_fine_and_another_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let pins = store(&dir);
        let web = HostId::from("web");
        pins.pin(&web, &key(test_keys::PLAIN_PUBLIC)).unwrap();
        pins.pin(&web, &key(test_keys::PLAIN_PUBLIC)).unwrap();
        let error = pins.pin(&web, &key(test_keys::ECDSA_PUBLIC)).unwrap_err();
        assert!(error.contains("another key"), "{error}");
        assert_eq!(pins.get(&web).unwrap().map(|pin| pin.key), Some(key(test_keys::PLAIN_PUBLIC)), "the first pin stays");
    }

    #[test]
    fn a_changed_key_replaces_the_pin_only_while_the_old_one_is_still_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let pins = store(&dir);
        let web = HostId::from("web");
        let (old, new, other) = (key(test_keys::PLAIN_PUBLIC), key(test_keys::ECDSA_PUBLIC), key(test_keys::RSA_PUBLIC));
        pins.pin(&web, &old).unwrap();
        assert!(pins.replace(&web, &other, &new).is_err(), "the pin is not the key the person was shown as the old one");
        pins.replace(&web, &old, &new).unwrap();
        assert_eq!(pins.get(&web).unwrap().map(|pin| pin.key), Some(new.clone()));
        pins.replace(&web, &old, &new).unwrap();
        assert!(pins.replace(&HostId::from("db"), &old, &new).is_err(), "nothing pinned: there is nothing to replace");
    }

    #[test]
    fn pins_belong_to_one_host_id_each() {
        let dir = tempfile::tempdir().unwrap();
        let pins = store(&dir);
        pins.pin(&HostId::from("web"), &key(test_keys::PLAIN_PUBLIC)).unwrap();
        pins.pin(&HostId::from("db"), &key(test_keys::ECDSA_PUBLIC)).unwrap();
        assert_eq!(pins.get(&HostId::from("web")).unwrap().map(|pin| pin.key.algorithm), Some("ssh-ed25519".to_string()));
        assert_eq!(pins.get(&HostId::from("db")).unwrap().map(|pin| pin.key.algorithm), Some("ecdsa-sha2-nistp256".to_string()));
        assert_eq!(pins.get(&HostId::from("mail")), Ok(None));
    }

    /// A file that cannot be read is an error, not "nothing pinned": a pinned host must not look new (the person would be asked to trust
    /// whatever key is presented), and a pin written now must not wipe the others.
    #[test]
    fn an_unreadable_or_newer_file_is_an_error_and_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-data").join("host-pins.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let pins = store(&dir);
        for contents in [&b"{ not json"[..], br#"{"version":2,"pins":{}}"#] {
            std::fs::write(&path, contents).unwrap();
            let error = pins.get(&HostId::from("web")).unwrap_err();
            assert!(error.contains("host-pins.json"), "{error}");
            assert!(pins.pin(&HostId::from("web"), &key(test_keys::PLAIN_PUBLIC)).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), contents, "the file is left as it was");
        }
    }
}
```

`src-tauri/src/session/testing.rs`: create

```rust
//! Test doubles for the broker's tests (`#[cfg(test)]` in `session/mod.rs`): saved hosts in memory, and the checks every
//! `HostDirectory` must pass.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::directory::{DirectoryError, HostDirectory, PinnedKey};
use super::protocol::HostQuery;
use crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target};

pub fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One saved host of a `FakeDirectory`.
#[derive(Clone)]
struct FakeHost {
    hop: Hop,
    /// The aliases of its jump hosts, in the order they are connected.
    jumps: Vec<String>,
}

/// Saved hosts and pins in memory. A host added as `web` has the id `id-web`, the hostname `web.example.com`, port 22 and the user
/// `deploy`; pins are dated `PINNED_AT_MS`.
#[derive(Default)]
pub struct FakeDirectory {
    hosts: Vec<FakeHost>,
    pins: Mutex<HashMap<HostId, PinnedKey>>,
}

/// The time every pin of a `FakeDirectory` was made.
pub const PINNED_AT_MS: u64 = 1_700_000_000_000;

impl FakeDirectory {
    pub fn new() -> FakeDirectory {
        FakeDirectory::default()
    }

    /// A saved host reached directly, starting its login with `auth`.
    pub fn with_host(self, alias: &str, auth: AuthMethod) -> FakeDirectory {
        self.with_host_via(alias, auth, &[])
    }

    /// A saved host reached through the saved hosts `jumps`, in this order.
    pub fn with_host_via(mut self, alias: &str, auth: AuthMethod, jumps: &[&str]) -> FakeDirectory {
        let hop = Hop::new(&format!("id-{alias}"), alias, &format!("{alias}.example.com"), 22, "deploy", auth);
        self.hosts.push(FakeHost { hop, jumps: jumps.iter().map(|jump| jump.to_string()).collect() });
        self
    }

    /// A second saved host called `alias`, with the id `id-<alias>-2`: the alias alone no longer says which.
    pub fn with_second_host_called(mut self, alias: &str) -> FakeDirectory {
        let hop = Hop::new(&format!("id-{alias}-2"), alias, &format!("{alias}-2.example.com"), 22, "deploy", AuthMethod::Password);
        self.hosts.push(FakeHost { hop, jumps: Vec::new() });
        self
    }

    /// The key pinned for the host with this alias.
    pub fn with_pin(self, alias: &str, key: HostKey) -> FakeDirectory {
        locked(&self.pins).insert(HostId::from(format!("id-{alias}")), PinnedKey { key, pinned_at_ms: PINNED_AT_MS });
        self
    }

    /// What is pinned now, by host id.
    pub fn pins(&self) -> HashMap<HostId, PinnedKey> {
        locked(&self.pins).clone()
    }

    fn by_alias(&self, alias: &str) -> Result<&FakeHost, DirectoryError> {
        let mut found = self.hosts.iter().filter(|host| host.hop.alias == alias);
        match (found.next(), found.next()) {
            (None, _) => Err(DirectoryError::NotFound(format!("No saved host is called {alias}."))),
            (Some(host), None) => Ok(host),
            (Some(_), Some(_)) => Err(DirectoryError::Ambiguous(format!("More than one saved host is called {alias}. Connect with --id and the host's id."))),
        }
    }

    fn with_its_pin(&self, hop: &Hop) -> Hop {
        Hop { pinned: locked(&self.pins).get(&hop.id).map(|pin| pin.key.clone()), ..hop.clone() }
    }
}

impl HostDirectory for FakeDirectory {
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        let host = match query {
            HostQuery::Alias(alias) => self.by_alias(alias)?,
            HostQuery::Id(id) => self
                .hosts
                .iter()
                .find(|host| host.hop.id.as_str() == id)
                .ok_or_else(|| DirectoryError::NotFound(format!("No saved host has the id {id}.")))?,
        };
        let mut hops = Vec::new();
        for jump in &host.jumps {
            hops.push(self.with_its_pin(&self.by_alias(jump)?.hop));
        }
        hops.push(self.with_its_pin(&host.hop));
        Ok(Target { hops })
    }

    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        Ok(locked(&self.pins).get(host).cloned())
    }

    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
        let mut pins = locked(&self.pins);
        match pins.get(host) {
            Some(pinned) if pinned.key.fingerprint == key.fingerprint => Ok(()),
            Some(_) => Err(DirectoryError::Failed(format!("SSHelter did not pin the key of {host}: another key was pinned for it in the meantime."))),
            None => {
                pins.insert(host.clone(), PinnedKey { key: key.clone(), pinned_at_ms: PINNED_AT_MS });
                Ok(())
            }
        }
    }

    fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError> {
        let mut pins = locked(&self.pins);
        match pins.get(host) {
            Some(pinned) if pinned.key.fingerprint == key.fingerprint => Ok(()),
            Some(pinned) if pinned.key.fingerprint == previous.fingerprint => {
                pins.insert(host.clone(), PinnedKey { key: key.clone(), pinned_at_ms: PINNED_AT_MS });
                Ok(())
            }
            _ => Err(DirectoryError::Failed(format!("SSHelter did not replace the key of {host}: the pinned key is not the one you were shown."))),
        }
    }

    fn password_account(&self, host: &HostId) -> String {
        format!("host:{host}")
    }
}

/// What every `HostDirectory` must do with pins, for a host `host` that has none yet: pin once (again is fine, another key is refused),
/// and replace only from the key that is pinned. The resolved hop carries the pin.
pub fn check_the_pin_contract(directory: &dyn HostDirectory, query: &HostQuery, first: &HostKey, second: &HostKey, third: &HostKey) {
    let hop = directory.resolve(query).expect("the host resolves").hops.pop().expect("a hop");
    assert_eq!(hop.pinned, None, "nothing is pinned yet");
    assert_eq!(directory.pinned(&hop.id), Ok(None));
    directory.pin(&hop.id, first).expect("a first pin");
    directory.pin(&hop.id, first).expect("the same key again");
    assert!(directory.pin(&hop.id, second).is_err(), "another key is not pinned over the first");
    assert_eq!(directory.pinned(&hop.id).unwrap().map(|pin| pin.key), Some(first.clone()));
    assert_eq!(directory.resolve(query).unwrap().hops.pop().unwrap().pinned, Some(first.clone()), "the resolved hop carries the pin");
    assert!(directory.replace_pin(&hop.id, third, second).is_err(), "only the pinned key can be replaced");
    directory.replace_pin(&hop.id, first, second).expect("the changed key replaces the pinned one");
    assert_eq!(directory.pinned(&hop.id).unwrap().map(|pin| pin.key), Some(second.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).expect("a test key")
    }

    #[test]
    fn the_fake_directory_keeps_the_pin_contract() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Password);
        check_the_pin_contract(&directory, &HostQuery::Alias("web".into()), &key(test_keys::PLAIN_PUBLIC), &key(test_keys::ECDSA_PUBLIC), &key(test_keys::RSA_PUBLIC));
    }

    #[test]
    fn the_fake_directory_resolves_by_alias_or_id_with_the_jump_hosts_first_and_says_when_an_alias_is_not_enough() {
        let directory = FakeDirectory::new()
            .with_host("bastion", AuthMethod::Key { key_id: "k1".into() })
            .with_host_via("db", AuthMethod::Password, &["bastion"])
            .with_second_host_called("web")
            .with_host("web", AuthMethod::Password)
            .with_pin("bastion", key(test_keys::PLAIN_PUBLIC));
        let chain = directory.resolve(&HostQuery::Alias("db".into())).unwrap();
        let aliases: Vec<&str> = chain.hops.iter().map(|hop| hop.alias.as_str()).collect();
        assert_eq!(aliases, ["bastion", "db"]);
        assert_eq!(chain.hops[0].pinned, Some(key(test_keys::PLAIN_PUBLIC)));
        assert_eq!(directory.resolve(&HostQuery::Id("id-db".into())).unwrap(), chain);
        assert!(matches!(directory.resolve(&HostQuery::Alias("web".into())), Err(DirectoryError::Ambiguous(_))));
        assert_eq!(directory.resolve(&HostQuery::Id("id-web-2".into())).unwrap().hops[0].hostname, "web-2.example.com");
        assert!(matches!(directory.resolve(&HostQuery::Alias("mail".into())), Err(DirectoryError::NotFound(_))));
        assert_eq!(directory.password_account(&HostId::from("id-db")), "host:id-db");
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::pins:: session::testing::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find type `HostKey` in this scope
error: could not compile `sshelter` (lib test) due to 16 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the pin store**

`src-tauri/src/session/pins.rs`: insert above the `#[cfg(test)]` line

```rust
//! The pinned host keys of the temporary ssh_config directory (plan 1b): a small JSON file in the app's data directory,
//! `host-pins.json`, keyed by host id. Plan 1c moves the pins into the host records (`host_key`, spec §5.1) and deletes this file's code.
//! SSHelter's own client never reads or writes `~/.ssh/known_hosts` (spec §1, non-goals).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::directory::PinnedKey;
use crate::ssh::{HostId, HostKey};

/// The version of the file's format; a file with another one is not read (and never overwritten).
const FILE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct PinFile {
    version: u32,
    pins: BTreeMap<String, StoredPin>,
}

/// A pin as the file stores it (spec §5.1's `host_key`, without the device that pinned it).
#[derive(Serialize, Deserialize)]
struct StoredPin {
    algorithm: String,
    /// The public key in SSH wire format, base64.
    public_key: String,
    fingerprint: String,
    pinned_at_ms: u64,
}

impl StoredPin {
    fn of(key: &HostKey, pinned_at_ms: u64) -> StoredPin {
        StoredPin {
            algorithm: key.algorithm.clone(),
            public_key: base64::engine::general_purpose::STANDARD.encode(&key.public_key),
            fingerprint: key.fingerprint.clone(),
            pinned_at_ms,
        }
    }

    fn pinned_key(&self) -> Option<PinnedKey> {
        let public_key = base64::engine::general_purpose::STANDARD.decode(&self.public_key).ok()?;
        Some(PinnedKey { key: HostKey { algorithm: self.algorithm.clone(), public_key, fingerprint: self.fingerprint.clone() }, pinned_at_ms: self.pinned_at_ms })
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0)
}

/// The pin file. Every change is a read, a check and an atomic write under one lock, so two connections that pin at once cannot lose a pin.
pub struct PinStore {
    path: PathBuf,
    lock: Mutex<()>,
    clock: fn() -> u64,
}

impl PinStore {
    /// The store at `path` (`<app data>/host-pins.json` in the app). Nothing is read or created until it is used.
    pub fn new(path: PathBuf) -> PinStore {
        PinStore::with_clock(path, now_ms)
    }

    /// The same, with the clock that dates the pins.
    pub fn with_clock(path: PathBuf, clock: fn() -> u64) -> PinStore {
        PinStore { path, lock: Mutex::new(()), clock }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn unreadable(&self, why: impl std::fmt::Display) -> String {
        format!("SSHelter cannot read its pinned host keys in {} ({why}).", self.path.display())
    }

    /// The whole file; a missing file is an empty one.
    fn read(&self) -> Result<PinFile, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(PinFile { version: FILE_VERSION, pins: BTreeMap::new() }),
            Err(error) => return Err(self.unreadable(error)),
        };
        let file: PinFile = serde_json::from_slice(&bytes).map_err(|_| self.unreadable("the file is damaged"))?;
        if file.version != FILE_VERSION {
            return Err(self.unreadable(format!("it is in format {}, which this version of SSHelter does not know", file.version)));
        }
        Ok(file)
    }

    fn write(&self, file: &PinFile) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(file).map_err(|error| format!("SSHelter cannot save the pinned host key: {error}"))?;
        crate::fsutil::atomic_write(&self.path, &bytes, 0o600).map_err(|error| format!("SSHelter cannot save the pinned host key in {}: {error}", self.path.display()))
    }

    /// The key pinned for `host`. An unreadable file is an error, never "nothing pinned".
    pub fn get(&self, host: &HostId) -> Result<Option<PinnedKey>, String> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let file = self.read()?;
        match file.pins.get(host.as_str()) {
            None => Ok(None),
            Some(stored) => stored.pinned_key().map(Some).ok_or_else(|| self.unreadable(format!("the pin of {host} is damaged"))),
        }
    }

    /// Pins `key` for `host`, unless another key is pinned for it (then nothing is written). Pinning the pinned key again changes nothing.
    pub fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut file = self.read()?;
        match file.pins.get(host.as_str()) {
            Some(stored) if stored.fingerprint == key.fingerprint => Ok(()),
            Some(_) => Err(format!("SSHelter did not pin the key of {host}: another key was pinned for it in the meantime.")),
            None => {
                file.pins.insert(host.as_str().to_string(), StoredPin::of(key, (self.clock)()));
                self.write(&file)
            }
        }
    }

    /// Replaces the pin of `host` with `key`, only while `previous` is the pinned key (or `key` already is).
    pub fn replace(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut file = self.read()?;
        match file.pins.get(host.as_str()) {
            Some(stored) if stored.fingerprint == key.fingerprint => Ok(()),
            Some(stored) if stored.fingerprint == previous.fingerprint => {
                file.pins.insert(host.as_str().to_string(), StoredPin::of(key, (self.clock)()));
                self.write(&file)
            }
            _ => Err(format!("SSHelter did not replace the key of {host}: the pinned key is not the one you were shown.")),
        }
    }
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::pins:: session::testing::)
```

Expected: PASS, `test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 1621 filtered out`.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1626 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/session/directory.rs \
  src-tauri/src/session/mod.rs \
  src-tauri/src/session/pins.rs \
  src-tauri/src/session/testing.rs
git commit -m "feat(session): add the broker's host directory interface, a fake for its tests, and the pin store"
```

Expected: `git status --short` lists the four files of this task; the `git diff --stat` prints nothing.

---

### Task 7: The temporary directory over today's ssh_config, vault keys and pin file

**Files:**
- Create: `src-tauri/src/session/ssh_config_directory.rs` (with its tests)
- Modify: `src-tauri/src/session/mod.rs`

**Interfaces:**
- Consumes: `HostDirectory`, `DirectoryError`, `PinnedKey` and `PinStore` (Task 6); `crate::config::model::SshConfigDoc` and `crate::connect::validate_alias(doc, alias)` (an alias is a saved host when it is one of the doc's `Host` patterns); `crate::config::intel::effective_config(alias, config_path)` (`ssh -G`, in tests only); `crate::sync::slot_rules::{resolve_identity_value, IdentityTarget}` and `crate::sync::state_v2::{SlotSource, SyncStateV2}` (the SP3 slot rules); `crate::secrets::host_account(alias)` (`host:<alias>`); `crate::ssh::{Hop::new, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY}`.
- Produces (`session/ssh_config_directory.rs`):
  - `pub struct JumpSpec { pub user: Option<String>, pub host: String, pub port: Option<u16> }`, `pub fn parse_proxy_jump(value: &str) -> Result<Vec<JumpSpec>, String>`
  - `pub fn hop_from_effective(alias: &str, pairs: &[(String, String)], key_id: Option<String>, password_saved: bool) -> Result<Hop, DirectoryError>`
  - `pub fn vault_slot_of(identity_files: &[String], state: &SyncStateV2, home: &Path) -> Option<String>`
  - `pub struct Sources { pub doc, pub effective, pub vault_key, pub password_saved }` (boxed closures; the app wires them in plan 1b-2 Task 4, the tests give canned answers)
  - `pub struct SshConfigDirectory` with `new(sources: Sources, pins: PinStore)` and `impl HostDirectory`

What shapes this task:
- R2 makes this adapter TEMPORARY (its module documentation says so; plan 1c deletes it): it gives the broker today's hosts, read-only. A saved host is a `Host` pattern of the app's ssh_config; its settings are what `ssh -G` says (no connection is made); its key is the vault key — "Only in SSHelter" — that its first `IdentityFile` names under the SP3 slot rules (`vault_slot_of`, copied from `agent::oneshot`, which plan 1b-2 deletes); its password is the keychain's `host:<alias>`; a host id is its alias; pins come from `PinStore` (`host-pins.json`).
- What SSHelter's own client cannot do is refused with the reason, before anything connects: a `ProxyCommand` (`{alias} uses ProxyCommand, which SSHelter's own SSH client does not support.`), a jump host that is not a saved host (`{alias} jumps through {host}, which is not a saved host.`), a loop (`The jump hosts go round in a circle: loop1 → loop2 → loop1.`), more than five jump hosts, and a key that lives in a file instead of the vault (`{alias} logs in with the key file {file}, which SSHelter's own SSH client cannot use. Put the key in SSHelter (Keychain, Only in SSHelter) to connect with it.`). `ssh -G` lists OpenSSH's default key files for a host that names none (OpenSSH 10.3p1's seven, `DEFAULT_IDENTITY_FILES`); those mean "no key", not "a key file".
- A host without a key starts with the password method when the keychain has its password, else with keyboard-interactive: the broker then asks for a password only when the server still wants one (`password_wanted`, Task 9), so a server that asks through keyboard-interactive (PAM) is not asked twice. Listed under "Decisions to confirm".
- `ProxyJump` is read as OpenSSH writes it — `[user@]host[:port]`, `ssh://[user@]host[:port]`, `[v6]:port`, a comma-separated list in connect order, `none` — and the jump's own user and port override the jump host's (as `ssh -J admin@bastion:2200` does).
- Keepalive: the host's `ServerAliveInterval` when it sets one above 0, else SSHelter's default (spec §5.1: 30 s; OpenSSH's own default is off), and `ServerAliveCountMax` as the misses allowed; `ConnectTimeout` when set, else 15 s.
- One test runs the real `ssh -F <a config in a temp directory> -G` (it reads neither `~/.ssh/config` nor `/etc/ssh/ssh_config` with `-F`); the others give canned `ssh -G` answers.

- [ ] **Step 1: Write the tests**

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -5,5 +5,6 @@
 pub mod directory;
 pub mod pins;
 pub mod protocol;
+pub mod ssh_config_directory;
 #[cfg(test)]
 pub mod testing;
```

`src-tauri/src/session/ssh_config_directory.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::session::testing::check_the_pin_contract;
    use crate::sync::slot_rules::test_keys;
    use crate::sync::state_v2::LocalSlot;

    fn pairs(text: &str) -> Vec<(String, String)> {
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let (key, value) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
                (key.to_string(), value.to_string())
            })
            .collect()
    }

    /// `ssh -G`'s defaults for the key files of a host that names none.
    const NO_KEY: &str = "identityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ecdsa\nidentityfile ~/.ssh/id_ecdsa_sk\nidentityfile ~/.ssh/id_ed25519\nidentityfile ~/.ssh/id_ed25519_sk\n";

    #[test]
    fn a_proxy_jump_list_is_read_in_order_with_its_users_and_ports() {
        assert_eq!(parse_proxy_jump("none"), Ok(vec![]));
        assert_eq!(parse_proxy_jump(""), Ok(vec![]));
        assert_eq!(parse_proxy_jump("bastion"), Ok(vec![JumpSpec { user: None, host: "bastion".into(), port: None }]));
        assert_eq!(
            parse_proxy_jump("admin@web:2200,bastion"),
            Ok(vec![JumpSpec { user: Some("admin".into()), host: "web".into(), port: Some(2200) }, JumpSpec { user: None, host: "bastion".into(), port: None }])
        );
        assert_eq!(parse_proxy_jump("ssh://ops@gate:22"), Ok(vec![JumpSpec { user: Some("ops".into()), host: "gate".into(), port: Some(22) }]));
        assert_eq!(parse_proxy_jump("[fe80::1]:2222"), Ok(vec![JumpSpec { user: None, host: "fe80::1".into(), port: Some(2222) }]));
        assert!(parse_proxy_jump("gate:port").is_err());
        assert!(parse_proxy_jump("admin@").is_err());
    }

    #[test]
    fn a_hop_takes_its_address_user_and_timeouts_from_ssh_g_and_the_spec_defaults_otherwise() {
        let hop = hop_from_effective("web", &pairs(&format!("hostname web.example.com\nport 2222\nuser deploy\nconnecttimeout none\nserveraliveinterval 0\nserveralivecountmax 3\n{NO_KEY}")), None, true).unwrap();
        assert_eq!((hop.id.as_str(), hop.alias.as_str(), hop.hostname.as_str(), hop.port, hop.user.as_str()), ("web", "web", "web.example.com", 2222, "deploy"));
        assert_eq!((hop.connect_timeout, hop.keepalive_every, hop.keepalive_max_missed), (Duration::from_secs(15), Duration::from_secs(30), 3), "OpenSSH's 'off' keepalive becomes SSHelter's default");
        assert_eq!(hop.auth, AuthMethod::Password, "no key, a saved password: the password goes first");
        assert!(hop.nodelay && hop.pinned.is_none());

        let hop = hop_from_effective("db", &pairs("hostname 10.0.0.5\nport 22\nuser ops\nconnecttimeout 7\nserveraliveinterval 20\nserveralivecountmax 5\nidentityfile ~/.ssh/sshelter/keys/id_mac-aaaaaaaa\n"), Some("a".repeat(32)), false).unwrap();
        assert_eq!((hop.connect_timeout, hop.keepalive_every, hop.keepalive_max_missed), (Duration::from_secs(7), Duration::from_secs(20), 5));
        assert_eq!(hop.auth, AuthMethod::Key { key_id: "a".repeat(32) });
    }

    #[test]
    fn a_host_without_a_key_or_a_saved_password_starts_with_keyboard_interactive_and_a_key_file_is_refused() {
        let hop = hop_from_effective("mail", &pairs(&format!("hostname mail\nuser me\n{NO_KEY}")), None, false).unwrap();
        assert_eq!(hop.auth, AuthMethod::Interactive);
        let error = hop_from_effective("old", &pairs("hostname old\nuser me\nidentityfile ~/.ssh/work_key\n"), None, true).unwrap_err();
        assert_eq!(
            error,
            DirectoryError::Unsupported("old logs in with the key file ~/.ssh/work_key, which SSHelter's own SSH client cannot use. Put the key in SSHelter (Keychain, Only in SSHelter) to connect with it.".into())
        );
        assert!(matches!(hop_from_effective("x", &pairs("hostname x\nport 99999\n"), None, false), Err(DirectoryError::Unsupported(_))));
    }

    fn slot(file: &str, source: Option<SlotSource>) -> LocalSlot {
        LocalSlot {
            file_name: file.into(),
            source,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
            local_only: false,
        }
    }

    #[test]
    fn the_first_identity_file_on_a_vault_slot_names_the_key() {
        let home = Path::new("/h");
        let mut state = SyncStateV2::fresh("mac").unwrap();
        let vault = |fingerprint: &str| Some(SlotSource::Vault { fingerprint: fingerprint.into(), public_key: "ssh-ed25519 AAAA".into(), has_passphrase: false });
        state.key_slots.insert("a".repeat(32), slot("id_mac-aaaaaaaa", vault("SHA256:a")));
        state.key_slots.insert("b".repeat(32), slot("work-bbbbbbbb", Some(SlotSource::SyncedCopy { fingerprint: "SHA256:w".into() })));
        state.key_slots.insert("c".repeat(32), slot("work-cccccccc", vault("SHA256:c")));
        let files = |values: &[&str]| values.iter().map(|value| value.to_string()).collect::<Vec<_>>();
        assert_eq!(vault_slot_of(&files(&["~/.ssh/id_rsa", "~/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home), Some("a".repeat(32)));
        assert_eq!(vault_slot_of(&files(&["%d/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home), Some("a".repeat(32)));
        assert_eq!(vault_slot_of(&files(&["~/.ssh/sshelter/keys/work-bbbbbbbb"]), &state, home), None, "a file slot is not a vault key");
        assert_eq!(vault_slot_of(&files(&["~/.ssh/sshelter/keys/work-cccccccc", "~/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home), Some("c".repeat(32)), "the first one wins");
    }

    /// A directory over a canned ssh_config (`config_text`) and canned `ssh -G` answers (`effective`, by alias).
    fn directory(dir: &tempfile::TempDir, config_text: &str, effective: &[(&str, &str)]) -> SshConfigDirectory {
        let config = dir.path().join("config");
        std::fs::write(&config, config_text).unwrap();
        let answers: HashMap<String, Vec<(String, String)>> = effective.iter().map(|(alias, text)| (alias.to_string(), pairs(text))).collect();
        let sources = Sources {
            doc: Box::new(move || crate::config::include::load_doc(&config).map_err(|error| error.to_string())),
            effective: Box::new(move |alias| answers.get(alias).cloned().ok_or_else(|| format!("ssh -G does not know {alias}"))),
            vault_key: Box::new(|files| files.iter().any(|file| file.ends_with("id_mac-aaaaaaaa")).then(|| "a".repeat(32))),
            password_saved: Box::new(|host| host.as_str() == "web"),
        };
        SshConfigDirectory::new(sources, PinStore::with_clock(dir.path().join("host-pins.json"), || 1_700_000_000_000))
    }

    const CONFIG: &str = "Host web\n  HostName web.example.com\nHost bastion\n  HostName gate.example.com\nHost db\n  ProxyJump admin@bastion:2200\nHost pc\n  ProxyCommand nc %h %p\nHost loop1\n  ProxyJump loop2\nHost loop2\n  ProxyJump loop1\nHost outside\n  ProxyJump gate.example.org\n";

    fn effective() -> Vec<(&'static str, &'static str)> {
        vec![
            ("web", "hostname web.example.com\nport 22\nuser deploy\nidentityfile ~/.ssh/id_rsa\n"),
            ("bastion", "hostname gate.example.com\nport 22\nuser ops\nidentityfile ~/.ssh/sshelter/keys/id_mac-aaaaaaaa\n"),
            ("db", "hostname db\nport 22\nuser deploy\nproxyjump admin@bastion:2200\nidentityfile ~/.ssh/id_rsa\n"),
            ("pc", "hostname pc\nport 22\nuser deploy\nproxycommand nc %h %p\n"),
            ("loop1", "hostname loop1\nproxyjump loop2\n"),
            ("loop2", "hostname loop2\nproxyjump loop1\n"),
            ("outside", "hostname outside\nproxyjump gate.example.org\n"),
        ]
    }

    #[test]
    fn a_saved_host_resolves_with_its_jump_hosts_first_and_the_jump_users_and_ports_applied() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory(&dir, CONFIG, &effective());
        let target = directory.resolve(&HostQuery::Alias("db".into())).unwrap();
        let hops: Vec<(&str, &str, u16, &str)> = target.hops.iter().map(|hop| (hop.alias.as_str(), hop.hostname.as_str(), hop.port, hop.user.as_str())).collect();
        assert_eq!(hops, [("bastion", "gate.example.com", 2200, "admin"), ("db", "db", 22, "deploy")]);
        assert_eq!(target.hops[0].auth, AuthMethod::Key { key_id: "a".repeat(32) });
        assert_eq!(target.hops[1].auth, AuthMethod::Interactive);
        assert_eq!(directory.resolve(&HostQuery::Id("db".into())).unwrap(), target, "a host's id is its alias here");
        assert_eq!(directory.resolve(&HostQuery::Alias("web".into())).unwrap().hops[0].auth, AuthMethod::Password, "a saved password goes first");
        assert_eq!(directory.password_account(&HostId::from("web")), "host:web");
    }

    #[test]
    fn what_sshelter_cannot_connect_to_is_refused_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory(&dir, CONFIG, &effective());
        let refused = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).unwrap_err().to_string();
        assert_eq!(refused("mail"), "No saved host is called mail.");
        assert_eq!(refused("-oProxyCommand=evil"), "No saved host is called -oProxyCommand=evil.");
        assert_eq!(refused("pc"), "pc uses ProxyCommand, which SSHelter's own SSH client does not support.");
        assert_eq!(refused("outside"), "outside jumps through gate.example.org, which is not a saved host.");
        assert_eq!(refused("loop1"), "The jump hosts go round in a circle: loop1 → loop2 → loop1.");
    }

    #[test]
    fn a_pin_from_the_pin_file_is_in_the_resolved_hop_and_an_unreadable_file_stops_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory(&dir, CONFIG, &effective());
        let key = |line: &str| HostKey::from_openssh_line(line).unwrap();
        check_the_pin_contract(&directory, &HostQuery::Alias("web".into()), &key(test_keys::PLAIN_PUBLIC), &key(test_keys::ECDSA_PUBLIC), &key(test_keys::RSA_PUBLIC));
        std::fs::write(dir.path().join("host-pins.json"), "{ damaged").unwrap();
        assert!(matches!(directory.resolve(&HostQuery::Alias("web".into())), Err(DirectoryError::Failed(text)) if text.contains("host-pins.json")));
    }

    /// The adapter's reading of `ssh -G` against the real tool, on a config file of the test's own (`-F`; the user's `~/.ssh` is not read).
    #[test]
    fn the_real_ssh_g_output_resolves_into_the_same_hops() {
        let Some(_tools) = crate::ssh::testing::harness::tools() else { return };
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "Host bastion\n  HostName gate.example.com\n  User ops\n  ServerAliveInterval 20\nHost db\n  HostName 10.0.0.5\n  Port 2222\n  User deploy\n  ProxyJump admin@bastion:2200\n  ConnectTimeout 7\n").unwrap();
        let (doc_path, ssh_g_path) = (config.clone(), config.clone());
        let sources = Sources {
            doc: Box::new(move || crate::config::include::load_doc(&doc_path).map_err(|error| error.to_string())),
            effective: Box::new(move |alias| crate::config::intel::effective_config(alias, Some(&ssh_g_path)).map_err(|error| error.to_string())),
            vault_key: Box::new(|_| None),
            password_saved: Box::new(|_| false),
        };
        let directory = SshConfigDirectory::new(sources, PinStore::new(dir.path().join("host-pins.json")));
        let target = directory.resolve(&HostQuery::Alias("db".into())).unwrap();
        let hops: Vec<(&str, &str, u16, &str, Duration, Duration)> =
            target.hops.iter().map(|hop| (hop.alias.as_str(), hop.hostname.as_str(), hop.port, hop.user.as_str(), hop.connect_timeout, hop.keepalive_every)).collect();
        assert_eq!(
            hops,
            [
                ("bastion", "gate.example.com", 2200, "admin", Duration::from_secs(15), Duration::from_secs(20)),
                ("db", "10.0.0.5", 2222, "deploy", Duration::from_secs(7), Duration::from_secs(30)),
            ]
        );
        assert!(target.hops.iter().all(|hop| hop.auth == AuthMethod::Interactive));
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::ssh_config_directory::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0422]: cannot find struct, variant or union type `JumpSpec` in this scope
error: could not compile `sshelter` (lib test) due to 53 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/session/ssh_config_directory.rs`: insert above the `#[cfg(test)]` line

```rust
//! TEMPORARY: plan 1c deletes this file, when host records (spec §5.1) replace the ssh_config blocks. Until then it is the broker's
//! `HostDirectory` over the data the app has today, read-only: the hosts are the `Host` patterns of the app's ssh_config, their settings
//! come from `ssh -G` (no connection), a host's key is the vault key ("Only in SSHelter") that its first matching `IdentityFile` names
//! (the SP3 slot rules), a password is the keychain's `host:<alias>`, and pins live in `host-pins.json` (`pins.rs`). A host id is its
//! alias here. Never written: `~/.ssh` (spec §1). Never read: `~/.ssh/known_hosts`.
//!
//! What it cannot give the broker, and says so: a `ProxyCommand`, a jump host that is not a saved host, a key in a file instead of the
//! vault (SSHelter's own client signs with vault keys only).

use std::path::Path;

use super::directory::{DirectoryError, HostDirectory, PinnedKey};
use super::pins::PinStore;
use super::protocol::HostQuery;
use crate::config::model::SshConfigDoc;
use crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY};
use crate::sync::slot_rules::{resolve_identity_value, IdentityTarget};
use crate::sync::state_v2::{SlotSource, SyncStateV2};

/// How many jump hosts deep a chain may go (as `config::intel::jump_chain` shows chains).
const MAX_JUMPS: usize = 5;

/// The `IdentityFile` values `ssh -G` lists when a host names none (OpenSSH 10.3p1): no key was chosen for the host.
const DEFAULT_IDENTITY_FILES: &[&str] = &["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk", "~/.ssh/id_xmss", "~/.ssh/id_dsa"];

/// One element of a `ProxyJump` list: `[user@]host[:port]`, or `ssh://[user@]host[:port]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpSpec {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

/// The jump hosts of a `ProxyJump` value, in the order they are connected; `none` (or nothing) is none.
pub fn parse_proxy_jump(value: &str) -> Result<Vec<JumpSpec>, String> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|element| {
            let element = element.trim();
            let rest = element.strip_prefix("ssh://").unwrap_or(element);
            let (user, rest) = match rest.rsplit_once('@') {
                Some((user, rest)) => (Some(user.to_string()), rest),
                None => (None, rest),
            };
            let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
                let (host, after) = bracketed.split_once(']').ok_or_else(|| format!("ProxyJump {element} is not [user@]host[:port]"))?;
                (host, after.strip_prefix(':'))
            } else {
                match rest.rsplit_once(':') {
                    Some((host, port)) => (host, Some(port)),
                    None => (rest, None),
                }
            };
            let port = port.map(|port| port.parse::<u16>().map_err(|_| format!("ProxyJump {element} has no valid port"))).transpose()?;
            if host.is_empty() {
                return Err(format!("ProxyJump {element} names no host"));
            }
            Ok(JumpSpec { user, host: host.to_string(), port })
        })
        .collect()
}

/// The first value of `keyword` in `ssh -G`'s output.
fn value<'a>(pairs: &'a [(String, String)], keyword: &str) -> Option<&'a str> {
    pairs.iter().find(|(key, _)| key == keyword).map(|(_, value)| value.as_str())
}

/// A positive number of seconds; `none`, 0 or something else is `None`.
fn seconds(value: Option<&str>) -> Option<std::time::Duration> {
    value.and_then(|value| value.parse::<u64>().ok()).filter(|seconds| *seconds > 0).map(std::time::Duration::from_secs)
}

/// The hop of the saved host `alias` from its `ssh -G` settings. `key_id` is the vault key its `IdentityFile`s name, if any;
/// `password_saved` says whether the keychain holds its password. Keepalive: the host's `ServerAliveInterval` when it sets one, else
/// SSHelter's default (spec §5.1: 30 s; OpenSSH's own default is off); a dead link is given up after `ServerAliveCountMax` more.
pub fn hop_from_effective(alias: &str, pairs: &[(String, String)], key_id: Option<String>, password_saved: bool) -> Result<Hop, DirectoryError> {
    let hostname = value(pairs, "hostname").filter(|hostname| !hostname.is_empty()).unwrap_or(alias);
    let port = match value(pairs, "port") {
        None => 22,
        Some(port) => port.parse::<u16>().map_err(|_| DirectoryError::Unsupported(format!("{alias} has a port SSHelter cannot use ({port}).")))?,
    };
    let user = value(pairs, "user").unwrap_or_default();
    let auth = match key_id {
        Some(key_id) => AuthMethod::Key { key_id },
        None => {
            let identity_files: Vec<&str> = pairs.iter().filter(|(key, _)| key == "identityfile").map(|(_, value)| value.as_str()).collect();
            if let Some(file) = identity_files.iter().find(|file| !DEFAULT_IDENTITY_FILES.contains(file)) {
                return Err(DirectoryError::Unsupported(format!(
                    "{alias} logs in with the key file {file}, which SSHelter's own SSH client cannot use. Put the key in SSHelter (Keychain, Only in SSHelter) to connect with it."
                )));
            }
            // No key: a saved password is tried first; without one, keyboard-interactive comes first, and the broker asks for a password
            // only when the server wants one (`ConnectError::AuthFailed::password_wanted`), so a server that asks through
            // keyboard-interactive is not asked twice.
            if password_saved {
                AuthMethod::Password
            } else {
                AuthMethod::Interactive
            }
        }
    };
    let mut hop = Hop::new(alias, alias, hostname, port, user, auth);
    hop.connect_timeout = seconds(value(pairs, "connecttimeout")).unwrap_or(DEFAULT_CONNECT_TIMEOUT);
    hop.keepalive_every = seconds(value(pairs, "serveraliveinterval")).unwrap_or(DEFAULT_KEEPALIVE_EVERY);
    if let Some(count) = value(pairs, "serveralivecountmax").and_then(|count| count.parse::<u32>().ok()) {
        hop.keepalive_max_missed = count;
    }
    Ok(hop)
}

/// The vault key ("Only in SSHelter" slot) that the first of `identity_files` (`ssh -G`'s values, in order) names, if any. Copied from
/// `agent::oneshot`, which goes away with the one-shot channel.
pub fn vault_slot_of(identity_files: &[String], state: &SyncStateV2, home: &Path) -> Option<String> {
    identity_files.iter().find_map(|value| {
        let IdentityTarget::Slot(file) = resolve_identity_value(value, home) else { return None };
        state
            .key_slots
            .iter()
            .find(|(_, local)| local.file_name == file && matches!(local.source, Some(SlotSource::Vault { .. })))
            .map(|(id, _)| id.clone())
    })
}

/// The sources the adapter reads; in the app they are the loaded ssh_config, `ssh -G`, the sync state and the keychain (wired in by the
/// app), in tests whatever the test gives.
pub struct Sources {
    /// The ssh_config the app manages: the hosts one can connect to are its `Host` patterns.
    pub doc: Box<dyn Fn() -> Result<SshConfigDoc, String> + Send + Sync>,
    /// `ssh -G <alias>`: the effective settings of a host, keywords in lower case.
    pub effective: Box<dyn Fn(&str) -> Result<Vec<(String, String)>, String> + Send + Sync>,
    /// The vault key the `IdentityFile` values name, if any (`vault_slot_of`).
    pub vault_key: Box<dyn Fn(&[String]) -> Option<String> + Send + Sync>,
    /// Whether the keychain holds a password for the host.
    pub password_saved: Box<dyn Fn(&HostId) -> bool + Send + Sync>,
}

/// The temporary `HostDirectory` (see the module documentation).
pub struct SshConfigDirectory {
    sources: Sources,
    pins: PinStore,
}

impl SshConfigDirectory {
    pub fn new(sources: Sources, pins: PinStore) -> SshConfigDirectory {
        SshConfigDirectory { sources, pins }
    }

    /// Whether `alias` is a saved host: a safe name that is a `Host` pattern of the doc.
    fn check_saved(&self, doc: &SshConfigDoc, alias: &str) -> Result<(), DirectoryError> {
        crate::connect::validate_alias(doc, alias).map_err(|_| DirectoryError::NotFound(format!("No saved host is called {alias}.")))
    }

    /// The hops of `alias` and of its jump hosts, jump hosts first. `path` holds the hosts being expanded, to find a loop.
    fn hops(&self, doc: &SshConfigDoc, alias: &str, path: &mut Vec<String>) -> Result<Vec<Hop>, DirectoryError> {
        if path.iter().any(|seen| seen == alias) {
            path.push(alias.to_string());
            return Err(DirectoryError::Unsupported(format!("The jump hosts go round in a circle: {}.", path.join(" → "))));
        }
        if path.len() > MAX_JUMPS {
            return Err(DirectoryError::Unsupported(format!("{} needs more than {MAX_JUMPS} jump hosts.", path[0])));
        }
        path.push(alias.to_string());
        let pairs = (self.sources.effective)(alias).map_err(|error| DirectoryError::Failed(format!("SSHelter cannot read the settings of {alias}: {error}")))?;
        if value(&pairs, "proxycommand").is_some_and(|command| !command.trim().is_empty() && !command.trim().eq_ignore_ascii_case("none")) {
            return Err(DirectoryError::Unsupported(format!("{alias} uses ProxyCommand, which SSHelter's own SSH client does not support.")));
        }
        let jumps = parse_proxy_jump(value(&pairs, "proxyjump").unwrap_or_default()).map_err(|error| DirectoryError::Unsupported(format!("{alias}: {error}.")))?;
        let mut hops = Vec::new();
        for jump in jumps {
            if self.check_saved(doc, &jump.host).is_err() {
                return Err(DirectoryError::Unsupported(format!("{alias} jumps through {}, which is not a saved host.", jump.host)));
            }
            let mut jump_hops = self.hops(doc, &jump.host, path)?;
            if let Some(jump_hop) = jump_hops.last_mut() {
                if let Some(user) = jump.user {
                    jump_hop.user = user;
                }
                if let Some(port) = jump.port {
                    jump_hop.port = port;
                }
            }
            hops.extend(jump_hops);
        }
        let identity_files: Vec<String> = pairs.iter().filter(|(key, _)| key == "identityfile").map(|(_, value)| value.clone()).collect();
        let key_id = (self.sources.vault_key)(&identity_files);
        let id = HostId::from(alias);
        let mut hop = hop_from_effective(alias, &pairs, key_id, (self.sources.password_saved)(&id))?;
        hop.pinned = self.pinned(&hop.id)?.map(|pin| pin.key);
        hops.push(hop);
        path.pop();
        Ok(hops)
    }
}

impl HostDirectory for SshConfigDirectory {
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        // A host id is the alias in this adapter.
        let alias = match query {
            HostQuery::Alias(alias) | HostQuery::Id(alias) => alias.as_str(),
        };
        let doc = (self.sources.doc)().map_err(|error| DirectoryError::Failed(format!("SSHelter cannot read your SSH config: {error}")))?;
        self.check_saved(&doc, alias)?;
        Ok(Target { hops: self.hops(&doc, alias, &mut Vec::new())? })
    }

    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        self.pins.get(host).map_err(DirectoryError::Failed)
    }

    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
        self.pins.pin(host, key).map_err(DirectoryError::Failed)
    }

    fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError> {
        self.pins.replace(host, previous, key).map_err(DirectoryError::Failed)
    }

    /// Today's keychain entries are `host:<alias>`, and the id is the alias here.
    fn password_account(&self, host: &HostId) -> String {
        crate::secrets::host_account(host.as_str())
    }
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::ssh_config_directory::)
```

Expected: PASS, `test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 1628 filtered out`.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1634 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/session/mod.rs \
  src-tauri/src/session/ssh_config_directory.rs
git commit -m "feat(session): add the temporary directory over today's ssh_config hosts, vault keys and a pin file"
```

Expected: `git status --short` lists the two files of this task; the `git diff --stat` prints nothing.

---

### Task 8: The broker's host-key policy and auth source

**Files:**
- Create: `src-tauri/src/session/auth.rs` (with its tests)
- Modify: `src-tauri/src/session/testing.rs` (`FakeKeys`, `FakeOwner`), `src-tauri/src/session/mod.rs`

**Interfaces:**
- Consumes: `HostDirectory` (Task 6); `QuestionKind` (Task 4); `crate::ssh::{AuthError, AuthMethod, AuthSource, ConnectError, Hop, HopRef, HostId, HostKey, HostKeyPolicy, HostKeyVerdict, Prompt, RsaHash, Secret, Signature, Target}` and `AuthSource::banner` (Task 2); `crate::sync::env::Keychain` (`get`, `delete`); `crate::vault::material::{open, Material, OpenError, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512}`.
- Produces (`session/auth.rs`):
  - `pub const PASSPHRASE_ATTEMPTS: usize = 3`, `pub fn passphrase_account(key_id: &str) -> String` (`vault:passphrase:<key id>`), `pub fn prompt_wait(hop: &Hop) -> Duration` (4 × the connect timeout, at least 60 s)
  - `pub struct VaultKey { pub name: String, pub public_key: String, pub has_passphrase: bool }`, `pub trait KeyStore: Send + Sync { fn key(&self, key_id: &str) -> Option<VaultKey>; fn private_text(&self, key_id: &str) -> Result<Option<Zeroizing<String>>, String>; }`
  - `pub enum Reply { Answer(Secret), Cancelled, TimedOut, Gone }`, `pub trait Owner: Send + Sync { fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply; fn host_key_notice(&self, text: &str); fn banner(&self, text: &str); }`
  - `pub fn printable(text: &str) -> String`
  - `pub struct PinPolicy` with `from_target(&Target)`, `pin(&self, host: &HostId, key: HostKey)`, `pinned(&self, host: &HostId) -> Option<HostKey>` and `impl HostKeyPolicy`
  - `pub enum PasswordSource { Keychain, Typed }`
  - `pub struct BrokerAuth<'a>` with `new(keys: &dyn KeyStore, keychain: &dyn Keychain, owner: &dyn Owner, directory: &dyn HostDirectory)`, `prepare(&self, target: &Target)`, `unlock(&self, target: &Target) -> Result<(), String>`, `set_typed(&self, hop: &HostId, password: Secret)`, `forget_typed(&self, hop: &HostId)`, `cancelled(&self, hop: &HostId) -> bool`, `cancel(&self, hop: &HostId)`, `password_source(&self, hop: &HostId) -> Option<PasswordSource>`, and `impl AuthSource`
  - `session/testing.rs`: `pub const TEST_PASSPHRASE: &str`, `pub struct FakeKeys` (`new()`: `k-plain`, the Ed25519 test key named "plain", and `k-enc`, named "laptop", behind `TEST_PASSPHRASE`) with `impl KeyStore`; `pub struct Asked` and `pub struct FakeOwner` (`answering(Vec<Reply>)`, `typing(&[&str])`, `asked()`, `questions()`, and the notices and banners it saw) with `impl Owner`

What shapes this task:
- One `BrokerAuth` serves one `open_shell`, its reconnects included (R8): a first contact connects twice (the host key is unknown the first time), so what the person typed is kept in memory for exactly that long and dropped with it. A cancelled or overdue prompt is remembered for the same span, so the engine's next method (keyboard-interactive after a cancelled password, spec §6.2 step 4) does not ask again.
- Passphrases are asked before anything connects (`unlock`, spec §6.1: `sign` must be quick): the passphrase remembered in the keychain first (`vault:passphrase:<key id>`, as the agent remembers it; a stale one is deleted so it is not tried again), then the person, at most three times, with `Enter the passphrase for the key {name}: ` and `That passphrase didn't work. Enter the passphrase for the key {name}: `. A cancel, an overdue answer or three wrong ones end the connect with the spec §11 sentence, `Authentication for {alias} was abandoned (the passphrase was not given).` and its siblings. The opened key and its public line are kept, so `public_key` and `sign` never wait for the vault.
- Passwords (R8): what the person typed in this connect, else the keychain's. A person is asked only for a hop that starts with the password method (`prepare` records them), because the engine fetches that password before it opens the connection; a password wanted after a refused key never waits for a person here — the engine skips the method, reports `password_wanted` (Task 2), and the connect loop asks between two connects (Task 9). The question is `{user}@{alias}'s password: ` (OpenSSH's), without echo, with `prompt_wait` as its deadline (plan 1a's review, item 8: the password prompt needs a deadline too).
- Keyboard-interactive: one question per prompt, in order, with the prompt's own echo flag and the engine's deadline, each prefixed `({user}@{alias}) ` as OpenSSH does, so the person can tell which hop of a chain asks.
- `PinPolicy` answers from the pins the directory put in the target's hops and from the keys the person trusts while the connect runs; it compares fingerprints.
- A banner is shown without control characters (`printable`): CRLF becomes LF, and every other control character except the tab becomes `?`, so a server cannot rewrite the person's screen with escape sequences.

- [ ] **Step 1: Write the tests**

`src-tauri/src/session/auth.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::testing::{FakeDirectory, FakeKeys, FakeOwner, TEST_PASSPHRASE};
    use crate::sync::slot_rules::test_keys;
    use crate::sync::testkit::MemKeychain;

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).unwrap()
    }

    fn target(auth: AuthMethod) -> Target {
        Target { hops: vec![Hop::new("id-web", "web", "web.example.com", 22, "deploy", auth)] }
    }

    fn web() -> HopRef {
        target(AuthMethod::Password).hops[0].reference()
    }

    struct World {
        keys: FakeKeys,
        keychain: MemKeychain,
        directory: FakeDirectory,
    }

    fn world() -> World {
        World { keys: FakeKeys::new(), keychain: MemKeychain::default(), directory: FakeDirectory::new() }
    }

    impl World {
        fn auth<'a>(&'a self, owner: &'a FakeOwner) -> BrokerAuth<'a> {
            BrokerAuth::new(&self.keys, &self.keychain, owner, &self.directory)
        }
    }

    #[test]
    fn the_policy_trusts_the_pinned_key_only_and_learns_the_keys_the_person_trusts() {
        let mut pinned = target(AuthMethod::Password);
        pinned.hops[0].pinned = Some(key(test_keys::PLAIN_PUBLIC));
        let policy = PinPolicy::from_target(&pinned);
        assert_eq!(policy.check(&web(), &key(test_keys::PLAIN_PUBLIC)), HostKeyVerdict::Pinned);
        assert_eq!(policy.check(&web(), &key(test_keys::ECDSA_PUBLIC)), HostKeyVerdict::Mismatch { pinned: key(test_keys::PLAIN_PUBLIC) });
        let other = HopRef { id: HostId::from("id-db"), ..web() };
        assert_eq!(policy.check(&other, &key(test_keys::PLAIN_PUBLIC)), HostKeyVerdict::Unknown);
        policy.pin(&other.id, key(test_keys::ECDSA_PUBLIC));
        assert_eq!(policy.check(&other, &key(test_keys::ECDSA_PUBLIC)), HostKeyVerdict::Pinned);
    }

    #[test]
    fn a_key_without_a_passphrase_opens_without_a_question_and_signs() {
        let world = world();
        let owner = FakeOwner::default();
        let auth = world.auth(&owner);
        assert_eq!(auth.public_key("k-plain"), None, "nothing is offered before the key is opened");
        auth.unlock(&target(AuthMethod::Key { key_id: "k-plain".into() })).unwrap();
        assert_eq!(auth.public_key("k-plain").as_deref(), Some(test_keys::PLAIN_PUBLIC));
        let signature = auth.sign("k-plain", b"challenge", None).unwrap();
        assert_eq!(&signature.0[4..15], b"ssh-ed25519");
        assert!(owner.asked().is_empty());
        assert!(matches!(auth.sign("k-enc", b"challenge", None), Err(AuthError::KeyUnavailable(_))), "a key that was not opened does not sign");
    }

    #[test]
    fn a_passphrase_remembered_in_the_keychain_opens_the_key_without_a_question() {
        let world = world();
        world.keychain.set(&passphrase_account("k-enc"), TEST_PASSPHRASE).unwrap();
        let owner = FakeOwner::default();
        let auth = world.auth(&owner);
        auth.unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })).unwrap();
        assert_eq!(auth.public_key("k-enc").as_deref(), Some(test_keys::ENC_PUBLIC));
        assert!(owner.asked().is_empty());
    }

    /// Asked before anything connects, without echo, and again after a wrong one; a stale remembered passphrase is forgotten first.
    #[test]
    fn a_passphrase_is_asked_before_the_connection_and_again_after_a_wrong_one() {
        let world = world();
        world.keychain.set(&passphrase_account("k-enc"), "an old passphrase").unwrap();
        let owner = FakeOwner::typing(&["wrong", TEST_PASSPHRASE]);
        let auth = world.auth(&owner);
        auth.unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })).unwrap();
        assert_eq!(
            owner.questions(),
            ["Enter the passphrase for the key laptop: ", "That passphrase didn't work. Enter the passphrase for the key laptop: "]
        );
        assert!(owner.asked().iter().all(|asked| asked.kind == QuestionKind::Passphrase && !asked.echo && asked.deadline.is_some()));
        assert_eq!(world.keychain.entry(&passphrase_account("k-enc")), None, "the stale passphrase was forgotten");
        assert!(auth.sign("k-enc", b"challenge", None).is_ok());
    }

    #[test]
    fn a_cancelled_passphrase_or_three_wrong_ones_abandon_the_connect_with_the_spec_sentence() {
        let world = world();
        let cancelled = FakeOwner::answering(vec![Reply::Cancelled]);
        assert_eq!(
            world.auth(&cancelled).unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })),
            Err("Authentication for web was abandoned (the passphrase was not given).".to_string())
        );
        let wrong = FakeOwner::typing(&["one", "two", "three", TEST_PASSPHRASE]);
        assert_eq!(
            world.auth(&wrong).unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })),
            Err("Authentication for web was abandoned (the passphrase was wrong three times).".to_string())
        );
        assert_eq!(wrong.asked().len(), PASSPHRASE_ATTEMPTS);
    }

    #[test]
    fn a_saved_password_is_given_without_asking_anyone() {
        let world = world();
        world.keychain.set("host:id-web", "saved secret").unwrap();
        let owner = FakeOwner::default();
        let auth = world.auth(&owner);
        auth.prepare(&target(AuthMethod::Password));
        assert_eq!(auth.password(&web()).as_deref().map(String::as_str), Some("saved secret"));
        assert_eq!(auth.password_source(&web().id), Some(PasswordSource::Keychain));
        assert!(owner.asked().is_empty());
    }

    /// The engine asks a password-first hop before it connects, and asks again on the reconnect after the host key was confirmed: the
    /// person types it once.
    #[test]
    fn the_password_of_a_password_first_hop_is_asked_once_and_kept_for_the_reconnect() {
        let world = world();
        let owner = FakeOwner::typing(&["typed secret"]);
        let auth = world.auth(&owner);
        auth.prepare(&target(AuthMethod::Password));
        assert_eq!(auth.password(&web()).as_deref().map(String::as_str), Some("typed secret"));
        assert_eq!(auth.password(&web()).as_deref().map(String::as_str), Some("typed secret"));
        assert_eq!(owner.questions(), ["deploy@web's password: "]);
        let asked = &owner.asked()[0];
        assert!(asked.kind == QuestionKind::Password && !asked.echo);
        let given = asked.deadline.unwrap().saturating_duration_since(Instant::now());
        assert!(given > Duration::from_secs(55) && given <= Duration::from_secs(60), "four connect timeouts, at least a minute: {given:?}");
        assert_eq!(auth.password_source(&web().id), Some(PasswordSource::Typed));
    }

    /// After a refused key the engine asks during the login, while the connection waits: a person is never asked then.
    #[test]
    fn a_fallback_password_never_asks_a_person() {
        let world = world();
        let owner = FakeOwner::typing(&["typed secret"]);
        let auth = world.auth(&owner);
        auth.prepare(&target(AuthMethod::Key { key_id: "k-plain".into() }));
        assert_eq!(auth.password(&web()), None);
        assert!(owner.asked().is_empty());
        auth.set_typed(&web().id, Zeroizing::new("asked by the broker".into()));
        assert_eq!(auth.password(&web()).as_deref().map(String::as_str), Some("asked by the broker"), "what the broker asked for is given");
    }

    /// The person said no to the password: keyboard-interactive, which the server may offer next, does not ask again.
    #[test]
    fn a_cancelled_password_is_not_asked_again_and_keyboard_interactive_does_not_ask_either() {
        let world = world();
        let owner = FakeOwner::answering(vec![Reply::Cancelled]);
        let auth = world.auth(&owner);
        auth.prepare(&target(AuthMethod::Password));
        assert_eq!(auth.password(&web()), None);
        assert!(auth.cancelled(&web().id));
        assert_eq!(auth.password(&web()), None);
        assert_eq!(auth.interactive(&web(), &[Prompt { text: "Password: ".into(), echo: false }], Instant::now() + Duration::from_secs(60)), None);
        assert_eq!(owner.asked().len(), 1);
    }

    #[test]
    fn keyboard_interactive_prompts_are_asked_one_by_one_with_their_echo_and_the_engines_deadline() {
        let world = world();
        let owner = FakeOwner::typing(&["secret", "123456"]);
        let auth = world.auth(&owner);
        let deadline = Instant::now() + Duration::from_secs(90);
        let prompts = [Prompt { text: "Password: ".into(), echo: false }, Prompt { text: "Verification code: ".into(), echo: true }];
        let answers = auth.interactive(&web(), &prompts, deadline).expect("answered");
        assert_eq!(answers.iter().map(|answer| answer.as_str()).collect::<Vec<_>>(), ["secret", "123456"]);
        assert_eq!(owner.questions(), ["(deploy@web) Password: ", "(deploy@web) Verification code: "]);
        assert_eq!(owner.asked().iter().map(|asked| (asked.kind, asked.echo, asked.deadline)).collect::<Vec<_>>(), [(QuestionKind::Interactive, false, Some(deadline)), (QuestionKind::Interactive, true, Some(deadline))]);

        let cancelling = FakeOwner::answering(vec![Reply::Cancelled]);
        let auth = world.auth(&cancelling);
        assert_eq!(auth.interactive(&web(), &prompts, deadline), None);
        assert!(auth.cancelled(&web().id));
    }

    /// A server's banner can carry escape sequences that would rewrite the user's terminal: they are replaced before it is shown.
    #[test]
    fn a_banner_reaches_the_owner_without_control_characters() {
        let world = world();
        let owner = FakeOwner::default();
        world.auth(&owner).banner(&web(), "Welcome\r\n\x1b[2JAll\tclear\x07\n");
        assert_eq!(*crate::session::testing::locked(&owner.banners), ["Welcome\n?[2JAll\tclear?\n"]);
    }
}
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -2,6 +2,7 @@
 //! version, the MCP adapter in phase 2 — asks the client (or the app's window, for host keys) what a login needs, and relays the
 //! terminal. Every SSH call it makes blocks, so it runs on plain threads, never in async code and never on the UI thread.
 
+pub mod auth;
 pub mod directory;
 pub mod pins;
 pub mod protocol;
```

`src-tauri/src/session/testing.rs`: apply this patch

```diff
--- a/src-tauri/src/session/testing.rs
+++ b/src-tauri/src/session/testing.rs
@@ -1,12 +1,105 @@
 //! Test doubles for the broker's tests (`#[cfg(test)]` in `session/mod.rs`): saved hosts in memory, and the checks every
 //! `HostDirectory` must pass.
 
-use std::collections::HashMap;
+use std::collections::{HashMap, VecDeque};
 use std::sync::{Mutex, MutexGuard, PoisonError};
+use std::time::Instant;
 
+use zeroize::Zeroizing;
+
+use super::auth::{KeyStore, Owner, Reply, VaultKey};
 use super::directory::{DirectoryError, HostDirectory, PinnedKey};
-use super::protocol::HostQuery;
+use super::protocol::{HostQuery, QuestionKind};
 use crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target};
+use crate::sync::slot_rules::test_keys;
+
+/// The passphrase of `test_keys::encrypted()`.
+pub const TEST_PASSPHRASE: &str = "test-passphrase";
+
+/// A vault in memory: `k-plain` is the ed25519 test key without a passphrase (named "plain"), `k-enc` the one with the passphrase
+/// `TEST_PASSPHRASE` (named "laptop").
+pub struct FakeKeys {
+    keys: HashMap<String, (VaultKey, String)>,
+}
+
+impl FakeKeys {
+    pub fn new() -> FakeKeys {
+        let mut keys = HashMap::new();
+        keys.insert(
+            "k-plain".to_string(),
+            (VaultKey { name: "plain".into(), public_key: test_keys::PLAIN_PUBLIC.into(), has_passphrase: false }, test_keys::plain()),
+        );
+        keys.insert(
+            "k-enc".to_string(),
+            (VaultKey { name: "laptop".into(), public_key: test_keys::ENC_PUBLIC.into(), has_passphrase: true }, test_keys::encrypted()),
+        );
+        FakeKeys { keys }
+    }
+}
+
+impl KeyStore for FakeKeys {
+    fn key(&self, key_id: &str) -> Option<VaultKey> {
+        self.keys.get(key_id).map(|(key, _)| key.clone())
+    }
+
+    fn private_text(&self, key_id: &str) -> Result<Option<Zeroizing<String>>, String> {
+        Ok(self.keys.get(key_id).map(|(_, text)| Zeroizing::new(text.clone())))
+    }
+}
+
+/// One question the fake owner was asked.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub struct Asked {
+    pub kind: QuestionKind,
+    pub text: String,
+    pub echo: bool,
+    pub deadline: Option<Instant>,
+}
+
+/// The person at the client's terminal, scripted: each question takes the next reply (none left: `Reply::Gone`, the person left).
+/// Everything shown and asked is recorded.
+#[derive(Default)]
+pub struct FakeOwner {
+    replies: Mutex<VecDeque<Reply>>,
+    pub asked: Mutex<Vec<Asked>>,
+    pub notices: Mutex<Vec<String>>,
+    pub banners: Mutex<Vec<String>>,
+}
+
+impl FakeOwner {
+    pub fn answering(replies: Vec<Reply>) -> FakeOwner {
+        FakeOwner { replies: Mutex::new(replies.into()), ..FakeOwner::default() }
+    }
+
+    /// The person answers each question with these, in order.
+    pub fn typing(answers: &[&str]) -> FakeOwner {
+        FakeOwner::answering(answers.iter().map(|answer| Reply::Answer(Zeroizing::new(answer.to_string()))).collect())
+    }
+
+    pub fn asked(&self) -> Vec<Asked> {
+        locked(&self.asked).clone()
+    }
+
+    /// The texts of the questions asked, in order.
+    pub fn questions(&self) -> Vec<String> {
+        self.asked().into_iter().map(|asked| asked.text).collect()
+    }
+}
+
+impl Owner for FakeOwner {
+    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
+        locked(&self.asked).push(Asked { kind, text: text.to_string(), echo, deadline });
+        locked(&self.replies).pop_front().unwrap_or(Reply::Gone)
+    }
+
+    fn host_key_notice(&self, text: &str) {
+        locked(&self.notices).push(text.to_string());
+    }
+
+    fn banner(&self, text: &str) {
+        locked(&self.banners).push(text.to_string());
+    }
+}
 
 pub fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
     mutex.lock().unwrap_or_else(PoisonError::into_inner)
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::auth:: session::testing::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0432]: unresolved imports `super::auth::KeyStore`, `super::auth::Owner`, `super::auth::Reply`, `super::auth::VaultKey`
error: could not compile `sshelter` (lib test) due to 53 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/session/auth.rs`: insert above the `#[cfg(test)]` line

```rust
//! What the broker gives the engine for one connect (own-ssh spec §6.1, §7.2, decision 7): the host key policy, over the pins, and the
//! auth source, over the vault, the keychain and the session's owner (the person at the `sshelter connect` terminal, asked through
//! `question` frames). One `BrokerAuth` serves one `open_shell`, all its reconnects included: what the person typed lives in memory for
//! that long (a first contact connects twice: the host key is unknown the first time) and is dropped with it.
//!
//! The engine's rules (spec §6.1): passphrases and vault unlocking happen before `connect` (`BrokerAuth::unlock`); `sign` and a password
//! asked during the login must be quick, so a person is asked for a password only before the connection is opened, for a hop that
//! starts with the password method. A password wanted later, after a refused key, comes back as `AuthFailed { password_wanted }`, and the
//! broker asks and connects again with the password first.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::directory::HostDirectory;
use super::protocol::QuestionKind;
use crate::ssh::{AuthError, AuthMethod, AuthSource, ConnectError, Hop, HopRef, HostId, HostKey, HostKeyPolicy, HostKeyVerdict, Prompt, RsaHash, Secret, Signature, Target};
use crate::sync::env::Keychain;
use crate::vault::material::{self, Material, OpenError, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How many passphrases the person may try for one key (as the agent allows).
pub const PASSPHRASE_ATTEMPTS: usize = 3;

/// The keychain account of a passphrase remembered on this computer (the vault's: `vault:passphrase:<key id>`).
pub fn passphrase_account(key_id: &str) -> String {
    format!("vault:passphrase:{key_id}")
}

/// How long a person gets to answer a prompt for `hop`: 4 × its connect timeout, at least a minute (spec §6.2 step 4; the engine gives
/// keyboard-interactive the same).
pub fn prompt_wait(hop: &Hop) -> Duration {
    hop.connect_timeout.saturating_mul(4).max(Duration::from_secs(60))
}

/// `now + wait`, or a year from now when the clock cannot hold that.
fn deadline_after(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait).unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365))
}

/// A vault key as the broker sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKey {
    /// The name the user gave it, for questions and messages.
    pub name: String,
    /// Its OpenSSH public key line.
    pub public_key: String,
    pub has_passphrase: bool,
}

/// The vault, for the broker: the keys it holds and their private halves. The app's implementation reads the sync state and the vault
/// file; tests keep keys in memory.
pub trait KeyStore: Send + Sync {
    fn key(&self, key_id: &str) -> Option<VaultKey>;
    /// The private key as the vault stores it: OpenSSH text, passphrase-protected when the key has a passphrase.
    fn private_text(&self, key_id: &str) -> Result<Option<Zeroizing<String>>, String>;
}

/// How a question to the person ended.
#[derive(Debug)]
pub enum Reply {
    Answer(Secret),
    /// The person said no (Ctrl-C, Ctrl-D).
    Cancelled,
    /// The deadline passed.
    TimedOut,
    /// The client went away.
    Gone,
}

/// The owner of a session: the person at the client's terminal, who is asked for what a login needs (spec §7.2).
pub trait Owner: Send + Sync {
    /// Asks and waits for the answer until `deadline` (`None`: for as long as the owner is there).
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply;
    /// Shows that the host key waits for the person in SSHelter's window (spec §11); no answer.
    fn host_key_notice(&self, text: &str);
    /// Shows the server's banner (control characters already replaced).
    fn banner(&self, text: &str);
}

/// The text of a banner that is safe to print on a terminal: CRLF becomes LF, and every other control character (an escape sequence
/// from the server could rewrite the screen) becomes `?`. Tabs and line feeds stay.
pub fn printable(text: &str) -> String {
    text.replace("\r\n", "\n").chars().map(|c| if c.is_control() && c != '\n' && c != '\t' { '?' } else { c }).collect()
}

/// The host key policy of one connect: the pins of its hops, plus the keys the person trusts while it runs.
pub struct PinPolicy {
    pins: Mutex<HashMap<HostId, HostKey>>,
}

impl PinPolicy {
    /// The pins the directory put in the target's hops.
    pub fn from_target(target: &Target) -> PinPolicy {
        let pins = target.hops.iter().filter_map(|hop| hop.pinned.clone().map(|key| (hop.id.clone(), key))).collect();
        PinPolicy { pins: Mutex::new(pins) }
    }

    /// The person trusted `key` for `host` (and the directory has pinned it).
    pub fn pin(&self, host: &HostId, key: HostKey) {
        locked(&self.pins).insert(host.clone(), key);
    }

    pub fn pinned(&self, host: &HostId) -> Option<HostKey> {
        locked(&self.pins).get(host).cloned()
    }
}

impl HostKeyPolicy for PinPolicy {
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict {
        match locked(&self.pins).get(&hop.id) {
            Some(pinned) if pinned.fingerprint == key.fingerprint => HostKeyVerdict::Pinned,
            Some(pinned) => HostKeyVerdict::Mismatch { pinned: pinned.clone() },
            None => HostKeyVerdict::Unknown,
        }
    }
}

/// Where the last password given for a hop came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordSource {
    Keychain,
    Typed,
}

/// The auth source of one connect (see the module documentation).
pub struct BrokerAuth<'a> {
    keys: &'a dyn KeyStore,
    keychain: &'a dyn Keychain,
    owner: &'a dyn Owner,
    directory: &'a dyn HostDirectory,
    /// Keys opened for this connect (`unlock`), with their public key lines: the login asks for both and must not wait for the vault.
    opened: Mutex<HashMap<String, (Material, String)>>,
    /// Passwords the person typed, by hop: given again on the reconnects of this connect.
    typed: Mutex<HashMap<HostId, Secret>>,
    /// Hops whose prompt the person cancelled or let run out: they are not asked again in this connect.
    cancelled: Mutex<HashSet<HostId>>,
    /// Where the last password given for each hop came from.
    gave: Mutex<HashMap<HostId, PasswordSource>>,
    /// The hops of the target being connected that start with the password method, and their prompt deadlines.
    password_first: Mutex<HashMap<HostId, Duration>>,
}

impl<'a> BrokerAuth<'a> {
    pub fn new(keys: &'a dyn KeyStore, keychain: &'a dyn Keychain, owner: &'a dyn Owner, directory: &'a dyn HostDirectory) -> BrokerAuth<'a> {
        BrokerAuth {
            keys,
            keychain,
            owner,
            directory,
            opened: Mutex::new(HashMap::new()),
            typed: Mutex::new(HashMap::new()),
            cancelled: Mutex::new(HashSet::new()),
            gave: Mutex::new(HashMap::new()),
            password_first: Mutex::new(HashMap::new()),
        }
    }

    /// The target the next `connect` uses: the engine asks a hop that starts with the password method for its password before it
    /// connects, and only then may a person be asked.
    pub fn prepare(&self, target: &Target) {
        *locked(&self.password_first) = target.hops.iter().filter(|hop| hop.auth == AuthMethod::Password).map(|hop| (hop.id.clone(), prompt_wait(hop))).collect();
    }

    /// Opens the vault keys of `target` before anything connects (spec §6.1): a key with a passphrase takes the one remembered in the
    /// keychain, or asks the person, up to `PASSPHRASE_ATTEMPTS` times. A key the vault does not have is left to the engine, which skips
    /// it and says so. `Err` is the sentence for the user; nothing has connected.
    pub fn unlock(&self, target: &Target) -> Result<(), String> {
        for hop in &target.hops {
            let AuthMethod::Key { key_id } = &hop.auth else { continue };
            if locked(&self.opened).contains_key(key_id) {
                continue;
            }
            let Some(key) = self.keys.key(key_id) else { continue };
            let Some(text) = self.keys.private_text(key_id).map_err(|error| format!("SSHelter cannot read the key {} from its vault ({error}).", key.name))? else {
                continue;
            };
            let material = self.open(hop, key_id, &key, &text)?;
            locked(&self.opened).insert(key_id.clone(), (material, key.public_key));
        }
        Ok(())
    }

    fn open(&self, hop: &Hop, key_id: &str, key: &VaultKey, text: &str) -> Result<Material, String> {
        let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: hop.reference(), reason: reason.to_string() }.to_string();
        match material::open(text, None) {
            Ok(material) => return Ok(material),
            Err(OpenError::NeedsPassphrase) => {}
            Err(OpenError::UnsupportedCipher(cipher)) => return Err(format!("The key {} is encrypted with {cipher}, which SSHelter cannot open.", key.name)),
            Err(OpenError::Unreadable | OpenError::WrongPassphrase) => return Err(format!("The key {} in SSHelter's vault cannot be read.", key.name)),
        }
        let account = passphrase_account(key_id);
        if let Ok(Some(saved)) = self.keychain.get(&account) {
            let saved = Zeroizing::new(saved);
            match material::open(text, Some(&saved)) {
                Ok(material) => return Ok(material),
                Err(_) => {
                    // A remembered passphrase that no longer opens the key (the key was replaced) is forgotten, so it is not tried again.
                    if let Err(error) = self.keychain.delete(&account) {
                        eprintln!("[session] cannot forget the stale remembered passphrase of key {key_id}: {error}");
                    }
                }
            }
        }
        let mut text_of_question = format!("Enter the passphrase for the key {}: ", key.name);
        for _ in 0..PASSPHRASE_ATTEMPTS {
            let passphrase = match self.owner.ask(QuestionKind::Passphrase, &text_of_question, false, Some(deadline_after(prompt_wait(hop)))) {
                Reply::Answer(passphrase) => passphrase,
                Reply::Cancelled | Reply::Gone => return Err(abandoned("the passphrase was not given")),
                Reply::TimedOut => return Err(abandoned("the passphrase prompt timed out")),
            };
            match material::open(text, Some(&passphrase)) {
                Ok(material) => return Ok(material),
                Err(OpenError::WrongPassphrase) => text_of_question = format!("That passphrase didn't work. Enter the passphrase for the key {}: ", key.name),
                Err(_) => return Err(format!("The key {} in SSHelter's vault cannot be read.", key.name)),
            }
        }
        Err(abandoned("the passphrase was wrong three times"))
    }

    /// The person typed `password` for `hop` (asked by the broker after `AuthFailed { password_wanted }`): it is given on the reconnect.
    pub fn set_typed(&self, hop: &HostId, password: Secret) {
        locked(&self.typed).insert(hop.clone(), password);
    }

    /// Forgets what the person typed for `hop` (the server refused it).
    pub fn forget_typed(&self, hop: &HostId) {
        locked(&self.typed).remove(hop);
    }

    /// The person cancelled a prompt for `hop` (or let it run out) during this connect.
    pub fn cancelled(&self, hop: &HostId) -> bool {
        locked(&self.cancelled).contains(hop)
    }

    /// Marks `hop` as cancelled: no more questions for it in this connect.
    pub fn cancel(&self, hop: &HostId) {
        locked(&self.cancelled).insert(hop.clone());
    }

    /// Where the last password given for `hop` came from.
    pub fn password_source(&self, hop: &HostId) -> Option<PasswordSource> {
        locked(&self.gave).get(hop).copied()
    }
}

impl AuthSource for BrokerAuth<'_> {
    /// Only a key `unlock` opened: anything else is skipped by the engine, which says the key is not available.
    fn public_key(&self, key_id: &str) -> Option<String> {
        locked(&self.opened).get(key_id).map(|(_, public_key)| public_key.clone())
    }

    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
        let opened = locked(&self.opened);
        let (material, _) = opened.get(key_id).ok_or_else(|| AuthError::KeyUnavailable(format!("the key {key_id} was not opened")))?;
        let flags = match rsa_hash {
            Some(RsaHash::Sha512) => SSH_AGENT_RSA_SHA2_512,
            Some(RsaHash::Sha256) => SSH_AGENT_RSA_SHA2_256,
            None => 0,
        };
        material.sign(data, flags).map(Signature).map_err(|error| AuthError::Failed(error.to_string()))
    }

    /// What the person typed in this connect, else the keychain's; a person is asked only for a hop that starts with the password method,
    /// whose password the engine asks for before it connects. A fallback password (after a refused key) never waits for a person.
    fn password(&self, hop: &HopRef) -> Option<Secret> {
        if let Some(typed) = locked(&self.typed).get(&hop.id) {
            locked(&self.gave).insert(hop.id.clone(), PasswordSource::Typed);
            return Some(typed.clone());
        }
        match self.keychain.get(&self.directory.password_account(&hop.id)) {
            Ok(Some(saved)) if !saved.is_empty() => {
                locked(&self.gave).insert(hop.id.clone(), PasswordSource::Keychain);
                return Some(Zeroizing::new(saved));
            }
            Ok(_) => {}
            Err(error) => eprintln!("[session] cannot read the saved password of {}: {error}", hop.alias),
        }
        let wait = locked(&self.password_first).get(&hop.id).copied();
        let wait = wait.filter(|_| !self.cancelled(&hop.id))?;
        match self.owner.ask(QuestionKind::Password, &format!("{}@{}'s password: ", hop.user, hop.alias), false, Some(deadline_after(wait))) {
            Reply::Answer(password) => {
                locked(&self.typed).insert(hop.id.clone(), password.clone());
                locked(&self.gave).insert(hop.id.clone(), PasswordSource::Typed);
                Some(password)
            }
            Reply::Cancelled | Reply::TimedOut => {
                self.cancel(&hop.id);
                None
            }
            Reply::Gone => None,
        }
    }

    /// One question per prompt, in order, each showing which host asks (as OpenSSH does: `(user@host) Password:`), until `deadline`.
    fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
        if self.cancelled(&hop.id) {
            return None;
        }
        let mut answers = Vec::with_capacity(prompts.len());
        for prompt in prompts {
            match self.owner.ask(QuestionKind::Interactive, &format!("({}@{}) {}", hop.user, hop.alias, prompt.text), prompt.echo, Some(deadline)) {
                Reply::Answer(answer) => answers.push(answer),
                Reply::Cancelled => {
                    self.cancel(&hop.id);
                    return None;
                }
                Reply::TimedOut | Reply::Gone => return None,
            }
        }
        Some(answers)
    }

    fn banner(&self, _hop: &HopRef, text: &str) {
        self.owner.banner(&printable(text));
    }
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::auth:: session::testing::)
```

Expected: PASS, `test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 1634 filtered out`.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1645 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/session/auth.rs \
  src-tauri/src/session/mod.rs \
  src-tauri/src/session/testing.rs
git commit -m "feat(session): give the engine the broker's host key policy and an auth source over the vault, the keychain and the session's owner"
```

Expected: `git status --short` lists the three files of this task; the `git diff --stat` prints nothing.

---

### Task 9: The connect loop: host keys, typed passwords, a changed key type

**Files:**
- Create: `src-tauri/src/session/connect.rs` (with its tests)
- Modify: `src-tauri/src/session/testing.rs` (`Decision`, `FakeConfirmer`), `src-tauri/src/session/mod.rs`
- Modify: `src-tauri/src/ssh/fake.rs` (a pinned hop narrows the handshake to its key type; with its test), `src-tauri/src/ssh/parity_tests.rs` (the same scenario against the real engine)

**Interfaces:**
- Consumes: `HostDirectory`, `DirectoryError` (Task 6); `BrokerAuth`, `KeyStore`, `Owner`, `Reply`, `PinPolicy`, `prompt_wait` (Task 8); `HostQuery`, `QuestionKind`, `kinds` (Task 4); `ConnectError::AuthFailed { password_wanted, .. }` (Task 2); `SshEngine::connect`, `Session`, `Target`, `HostKey`, `HopRef`, `ConnectError::{HostKeyUnknown, HostKeyMismatch, NoCommonHostKeyAlgorithm, AuthAbandoned, …}` (plan 1a); `crate::sync::env::Keychain`.
- Produces (`session/connect.rs`):
  - `pub const PASSWORD_PROMPTS: usize = 3`, `pub const CANCELLED: &str = "cancelled"`
  - `pub struct CancelToken` (`Clone`, `Default`) with `cancel(&self)` and `is_cancelled(&self) -> bool`
  - `pub struct PinnedSummary { pub fingerprint: String, pub pinned_at_ms: u64 }`
  - `pub struct HostKeyQuestion { pub alias: String, pub hostname: String, pub port: u16, pub algorithm: String, pub fingerprint: String, pub changed: Option<PinnedSummary> }`
  - `pub trait HostKeyConfirmer: Send + Sync { fn confirm(&self, question: &HostKeyQuestion, cancel: &CancelToken) -> Option<String>; }` — the fingerprint the person trusted, `None` for no
  - `pub struct Connected { pub session: Box<dyn Session>, pub target: Target }`, `pub struct ConnectFailure { pub kind: String, pub text: String }`
  - `pub struct Connector<'a> { pub engine: &'a dyn SshEngine, pub directory: &'a dyn HostDirectory, pub keys: &'a dyn KeyStore, pub keychain: &'a dyn Keychain, pub confirmer: &'a dyn HostKeyConfirmer }` with `pub fn connect(&self, query: &HostQuery, owner: &dyn Owner, cancel: &CancelToken) -> Result<Connected, ConnectFailure>`
  - `session/testing.rs`: `pub enum Decision { Trust, TrustFingerprint(String), Refuse }`, `pub struct FakeConfirmer` with `deciding(Vec<Decision>)`, `asked() -> Vec<HostKeyQuestion>` and `impl HostKeyConfirmer`

What shapes this task:
- Host keys (spec §6.2 step 3, §10): the engine fails fast with the key the server presented; the broker tells the owner `Waiting for you to confirm {alias}'s host key in SSHelter.` (shown at the terminal, never answered there: decision 6 of the spec), asks the confirmer (the window of plan 1b-2) and, when the person trusted exactly the key the engine observed, pins it and connects again. The confirmer returns the fingerprint the person trusted; an answer for any other fingerprint (a window that still showed an older question) pins nothing. A refusal ends the connect with plan 1a's sentences: `The host key of {alias} has not been confirmed yet.` for a new key, `The host key of {alias} changed. Connection refused.` for a changed one.
- A changed key's question carries the pinned key's fingerprint and when it was pinned (spec §14's changed-key text names the date); accepting replaces the pin only from that key (`replace_pin`).
- R17: on `NoCommonHostKeyAlgorithm` for a pinned hop the broker connects once more with that hop's `pinned` cleared, so the handshake offers every key type, while the policy still holds the pin: the server's key of the new type then comes back as `HostKeyMismatch` and the person gets the changed-key warning of §14 instead of an algorithm error. The fake learns the narrowing (a pinned hop whose server has a key of another type has nothing in common with it) and a parity scenario runs the same against the real engine.
- Passwords (R8, R16): `AuthFailed` with `password_wanted`, or with a password that was given and refused (typed in this connect or from the keychain, `BrokerAuth::password_source`), asks the person `{user}@{alias}'s password: ` (after a refusal `That password didn't work. {user}@{alias}'s password: `), without echo, with the hop's prompt deadline; the hop's method becomes the password and the broker connects again, so the engine gets the typed password before it opens the connection (never while russh holds a connection open, where waiting for a person makes it spin). At most three per hop (`PASSWORD_PROMPTS`, OpenSSH's `NumberOfPasswordPrompts`). A cancelled or overdue question ends the connect with `Authentication for {alias} was abandoned (the password was not given).`; a hop whose prompt the person cancelled during the login is not asked again. A saved password that is refused stays saved: what the person types is used for this connect only.
- A failure on a jump host is said through it (spec §11): `Could not connect through {jump alias}: {reason}`. Each failure carries a `kind` word for the client (`protocol::kinds`).
- The loop is bounded (12 rounds: every question on every hop of a chain fits, and a server that keeps changing its answer cannot keep it going): `SSHelter gave up connecting to {alias}: the server kept asking for something new.`
- `CancelToken` is set when the client goes away (Task 11): the window stops waiting, nothing more is connected, and the failure's kind is `cancelled`, which nobody is told about.

- [ ] **Step 1: Write the tests**

`src-tauri/src/session/connect.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::auth::Reply;
    use crate::session::testing::{locked, Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner, PINNED_AT_MS, TEST_PASSPHRASE};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods};
    use crate::ssh::{AuthMethod, HostKey};
    use crate::sync::slot_rules::test_keys;
    use crate::sync::testkit::MemKeychain;

    const WAITING: &str = "Waiting for you to confirm web's host key in SSHelter.";

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).unwrap()
    }

    fn web() -> HostQuery {
        HostQuery::Alias("web".into())
    }

    struct World {
        engine: FakeEngine,
        directory: FakeDirectory,
        keys: FakeKeys,
        keychain: MemKeychain,
        confirmer: FakeConfirmer,
        owner: FakeOwner,
        cancel: CancelToken,
    }

    fn world(engine: FakeEngine, directory: FakeDirectory) -> World {
        World { engine, directory, keys: FakeKeys::new(), keychain: MemKeychain::default(), confirmer: FakeConfirmer::default(), owner: FakeOwner::default(), cancel: CancelToken::default() }
    }

    impl World {
        fn deciding(mut self, decisions: Vec<Decision>) -> World {
            self.confirmer = FakeConfirmer::deciding(decisions);
            self
        }

        fn typing(mut self, answers: &[&str]) -> World {
            self.owner = FakeOwner::typing(answers);
            self
        }

        fn connect(&self, query: &HostQuery) -> Result<Connected, ConnectFailure> {
            let connector = Connector { engine: &self.engine, directory: &self.directory, keys: &self.keys, keychain: &self.keychain, confirmer: &self.confirmer };
            connector.connect(query, &self.owner, &self.cancel)
        }

        fn connects(&self) -> usize {
            self.engine.events().iter().filter(|event| matches!(event, FakeEvent::Connect { .. })).count()
        }
    }

    fn failure(kind: &str, text: &str) -> ConnectFailure {
        ConnectFailure { kind: kind.to_string(), text: text.to_string() }
    }

    #[test]
    fn a_host_whose_key_is_pinned_connects_without_a_question() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()));
        world.keychain.set("host:id-web", "saved").unwrap();
        let connected = world.connect(&web()).expect("connects");
        assert!(connected.session.is_alive());
        assert_eq!(connected.target.hops[0].alias, "web");
        assert!(world.confirmer.asked().is_empty() && world.owner.asked().is_empty());
        assert!(locked(&world.owner.notices).is_empty());
    }

    /// Spec §10: the first connect fails on the unknown key; the window asks; the trusted key is pinned and the broker connects again, so
    /// the user sees "confirm, connected".
    #[test]
    fn an_unknown_host_key_is_confirmed_in_the_window_then_pinned_and_the_broker_connects_again() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Trust]);
        world.keychain.set("host:id-web", "saved").unwrap();
        world.connect(&web()).expect("connects after the key was trusted");
        assert_eq!(*locked(&world.owner.notices), [WAITING]);
        let asked = world.confirmer.asked();
        assert_eq!(asked.len(), 1);
        assert_eq!(
            asked[0],
            HostKeyQuestion {
                alias: "web".into(),
                hostname: "web.example.com".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                fingerprint: test_keys::PLAIN_FINGERPRINT.into(),
                changed: None,
            }
        );
        assert_eq!(world.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(default_server_key()));
        assert_eq!(world.connects(), 1, "one connect got through, after the one that stopped at the key");
    }

    #[test]
    fn an_unknown_host_key_the_person_does_not_trust_ends_the_connect_and_pins_nothing() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Refuse]);
        assert_eq!(world.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web has not been confirmed yet.")));
        assert!(world.directory.pins().is_empty());
    }

    /// The window answers for one fingerprint; only the key the broker itself observed is pinned, and only when the two match (as deploy's
    /// "trust this key" works): a stale answer pins nothing.
    #[test]
    fn an_answer_for_another_fingerprint_pins_nothing() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::TrustFingerprint("SHA256:stale".into())]);
        assert_eq!(world.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web has not been confirmed yet.")));
        assert!(world.directory.pins().is_empty());
    }

    #[test]
    fn a_changed_host_key_shows_the_pinned_one_and_replaces_it_only_when_accepted() {
        let old = key(test_keys::ENC_PUBLIC);
        let refusing = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", old.clone())).deciding(vec![Decision::Refuse]);
        assert_eq!(refusing.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web changed. Connection refused.")));
        assert_eq!(refusing.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(old.clone()), "the old pin stays");
        let asked = refusing.confirmer.asked();
        assert_eq!(asked[0].changed, Some(PinnedSummary { fingerprint: test_keys::ENC_FINGERPRINT.into(), pinned_at_ms: PINNED_AT_MS }));
        assert_eq!(asked[0].fingerprint, test_keys::PLAIN_FINGERPRINT);

        let accepting = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", old)).deciding(vec![Decision::Trust]);
        accepting.keychain.set("host:id-web", "saved").unwrap();
        accepting.connect(&web()).expect("connects with the accepted key");
        assert_eq!(accepting.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(default_server_key()));
        assert_eq!(*locked(&accepting.owner.notices), [WAITING]);
    }

    /// Plan 1b R17: a pinned host whose server no longer has a key of the pinned type would fail with "no common algorithm", because the
    /// handshake offers only the pinned type. The broker connects once more without that restriction, so the person gets the normal
    /// changed-key warning instead.
    #[test]
    fn a_pinned_host_that_now_has_another_key_type_gets_the_changed_key_warning_not_an_algorithm_error() {
        let ecdsa = key(test_keys::ECDSA_PUBLIC);
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", ecdsa.clone())).deciding(vec![Decision::Trust]);
        world.keychain.set("host:id-web", "saved").unwrap();
        let connected = world.connect(&web()).expect("connects once the new key was accepted");
        let asked = world.confirmer.asked();
        assert_eq!((asked.len(), asked[0].algorithm.as_str()), (1, "ssh-ed25519"));
        assert_eq!(asked[0].changed.as_ref().map(|pinned| pinned.fingerprint.as_str()), Some(test_keys::ECDSA_FINGERPRINT));
        assert_eq!(world.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(default_server_key()));
        assert_eq!(connected.target.hops[0].pinned, Some(default_server_key()), "the reconnect offered the new key's type");

        let refusing = world_refusing_algorithm_change(ecdsa);
        assert_eq!(refusing.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web changed. Connection refused.")));
    }

    fn world_refusing_algorithm_change(pinned: HostKey) -> World {
        world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", pinned)).deciding(vec![Decision::Refuse])
    }

    /// The fallback password after a refused key is not typed while the connection waits (russh spins then): the engine reports that a
    /// password is wanted, the broker asks, and connects again with the password first.
    #[test]
    fn a_password_wanted_after_a_refused_key_is_asked_for_and_the_broker_connects_again_with_the_password_first() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world(engine, directory).typing(&["right"]);
        let connected = world.connect(&web()).expect("the typed password gets in");
        assert_eq!(world.owner.questions(), ["deploy@web's password: "]);
        assert_eq!(connected.target.hops[0].auth, AuthMethod::Password);
    }

    #[test]
    fn a_refused_password_is_asked_for_again_up_to_three_times() {
        let engine = || FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let directory = || FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let third_time = world(engine(), directory()).typing(&["one", "two", "right"]);
        third_time.connect(&web()).expect("the third password is right");
        let again = "That password didn't work. deploy@web's password: ";
        assert_eq!(third_time.owner.questions(), ["deploy@web's password: ", again, again]);

        let never = world(engine(), directory()).typing(&["one", "two", "three", "right"]);
        assert_eq!(never.connect(&web()).err(), Some(failure(kinds::AUTH, "Authentication failed for deploy@web (tried: password).")));
        assert_eq!(never.owner.asked().len(), PASSWORD_PROMPTS);
    }

    /// A saved password that the server refuses: the person is asked, and what they type is used instead of the saved one.
    #[test]
    fn a_saved_password_that_is_refused_is_asked_for() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("new")));
        let world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key())).typing(&["new"]);
        world.keychain.set("host:id-web", "old").unwrap();
        world.connect(&web()).expect("the typed password gets in");
        assert_eq!(world.owner.questions(), ["That password didn't work. deploy@web's password: "]);
        assert_eq!(world.keychain.entry("host:id-web").as_deref(), Some("old"), "the saved password is not changed");
    }

    #[test]
    fn a_cancelled_password_question_abandons_the_connect() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let mut world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key()));
        world.owner = FakeOwner::answering(vec![Reply::Cancelled]);
        assert_eq!(world.connect(&web()).err(), Some(failure(kinds::AUTH, "Authentication for web was abandoned (the password was not given).")));
    }

    /// A first contact with a password-first host connects twice (the key is unknown the first time); the person types the password once.
    #[test]
    fn the_first_contact_with_a_password_host_asks_for_the_password_once() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Trust]).typing(&["right"]);
        world.connect(&web()).expect("connects");
        assert_eq!(world.owner.questions(), ["deploy@web's password: "]);
        assert_eq!(world.confirmer.asked().len(), 1);
    }

    #[test]
    fn a_passphrase_is_asked_for_before_anything_connects() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::key()));
        let world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-enc".into() }).with_pin("web", default_server_key())).typing(&[TEST_PASSPHRASE]);
        world.connect(&web()).expect("the key opens and logs in");
        assert_eq!(world.owner.questions(), ["Enter the passphrase for the key laptop: "]);

        let mut cancelled = self::world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-enc".into() }));
        cancelled.owner = FakeOwner::answering(vec![Reply::Cancelled]);
        assert_eq!(cancelled.connect(&web()).err(), Some(failure(kinds::AUTH, "Authentication for web was abandoned (the passphrase was not given).")));
        assert!(cancelled.engine.events().is_empty() && cancelled.confirmer.asked().is_empty(), "nothing was connected");
    }

    /// Spec §11: a failure on a jump host is said through it.
    #[test]
    fn a_failure_on_a_jump_host_names_the_jump_host() {
        let directory = FakeDirectory::new().with_host("bastion", AuthMethod::Password).with_host_via("db", AuthMethod::Password, &["bastion"]);
        let bastion = directory.resolve(&HostQuery::Alias("bastion".into())).unwrap().hops.remove(0).reference();
        let engine = FakeEngine::new().failing_with(ConnectError::Unreachable { hop: bastion, reason: "connection refused".into() });
        let world = world(engine, directory);
        assert_eq!(
            world.connect(&HostQuery::Alias("db".into())).err(),
            Some(failure(kinds::CONNECT, "Could not connect through bastion: Could not reach bastion.example.com:22 (connection refused)."))
        );
    }

    #[test]
    fn a_saved_host_that_cannot_be_found_or_named_by_its_alias_alone_is_a_host_error() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_second_host_called("web"));
        assert_eq!(world.connect(&HostQuery::Alias("mail".into())).err(), Some(failure(kinds::HOST, "No saved host is called mail.")));
        assert_eq!(
            world.connect(&web()).err(),
            Some(failure(kinds::HOST, "More than one saved host is called web. Connect with --id and the host's id."))
        );
    }

    /// The client went away (its terminal was closed while the window or a question waited): nothing more is connected.
    #[test]
    fn when_the_owner_goes_away_the_broker_stops_without_connecting_again() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Trust]);
        world.cancel.cancel();
        assert_eq!(world.connect(&web()).err().map(|failure| failure.kind), Some(CANCELLED.to_string()));
        assert!(world.engine.events().is_empty());
    }
}
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -3,6 +3,7 @@
 //! terminal. Every SSH call it makes blocks, so it runs on plain threads, never in async code and never on the UI thread.
 
 pub mod auth;
+pub mod connect;
 pub mod directory;
 pub mod pins;
 pub mod protocol;
```

`src-tauri/src/session/testing.rs`: apply this patch

```diff
--- a/src-tauri/src/session/testing.rs
+++ b/src-tauri/src/session/testing.rs
@@ -8,6 +8,7 @@ use std::time::Instant;
 use zeroize::Zeroizing;
 
 use super::auth::{KeyStore, Owner, Reply, VaultKey};
+use super::connect::{CancelToken, HostKeyConfirmer, HostKeyQuestion};
 use super::directory::{DirectoryError, HostDirectory, PinnedKey};
 use super::protocol::{HostQuery, QuestionKind};
 use crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target};
@@ -224,6 +225,48 @@ impl HostDirectory for FakeDirectory {
     }
 }
 
+/// What the person does in the fake host key window.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub enum Decision {
+    /// Trusts the key the window shows.
+    Trust,
+    /// Answers for this fingerprint (a window that showed another key: a stale answer).
+    TrustFingerprint(String),
+    /// Refuses (Cancel, Refuse) or closes the window.
+    Refuse,
+}
+
+/// SSHelter's host key window, scripted: each question takes the next decision (none left: `Refuse`). A cancelled wait is a refusal.
+#[derive(Default)]
+pub struct FakeConfirmer {
+    decisions: Mutex<VecDeque<Decision>>,
+    pub asked: Mutex<Vec<HostKeyQuestion>>,
+}
+
+impl FakeConfirmer {
+    pub fn deciding(decisions: Vec<Decision>) -> FakeConfirmer {
+        FakeConfirmer { decisions: Mutex::new(decisions.into()), asked: Mutex::new(Vec::new()) }
+    }
+
+    pub fn asked(&self) -> Vec<HostKeyQuestion> {
+        locked(&self.asked).clone()
+    }
+}
+
+impl HostKeyConfirmer for FakeConfirmer {
+    fn confirm(&self, question: &HostKeyQuestion, cancel: &CancelToken) -> Option<String> {
+        locked(&self.asked).push(question.clone());
+        if cancel.is_cancelled() {
+            return None;
+        }
+        match locked(&self.decisions).pop_front().unwrap_or(Decision::Refuse) {
+            Decision::Trust => Some(question.fingerprint.clone()),
+            Decision::TrustFingerprint(fingerprint) => Some(fingerprint),
+            Decision::Refuse => None,
+        }
+    }
+}
+
 /// What every `HostDirectory` must do with pins, for a host `host` that has none yet: pin once (again is fine, another key is refused),
 /// and replace only from the key that is pinned. The resolved hop carries the pin.
 pub fn check_the_pin_contract(directory: &dyn HostDirectory, query: &HostQuery, first: &HostKey, second: &HostKey, third: &HostKey) {
```

`src-tauri/src/ssh/fake.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/fake.rs
+++ b/src-tauri/src/ssh/fake.rs
@@ -784,6 +784,25 @@ mod tests {
         }
     }
 
+    /// A pinned hop offers only its pin's key type, as the real engine's handshake does: a server whose key is of another type has nothing
+    /// in common with it, and without the pin the same server presents its key as usual.
+    #[test]
+    fn a_pin_of_another_key_type_finds_no_common_algorithm() {
+        let engine = FakeEngine::new();
+        let ecdsa = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap();
+        let mut pinned = hop("web");
+        pinned.pinned = Some(ecdsa.clone());
+        match connect(&engine, &Target { hops: vec![pinned] }, &Auth::default()) {
+            Err(ConnectError::NoCommonHostKeyAlgorithm { hop, ours, theirs }) => {
+                assert_eq!((hop.alias.as_str(), ours, theirs), ("web", vec!["ecdsa-sha2-nistp256".to_string()], vec!["ssh-ed25519".to_string()]));
+            }
+            other => panic!("expected NoCommonHostKeyAlgorithm, got {:?}", other.err()),
+        }
+        let mut same_type = hop("web");
+        same_type.pinned = Some(default_server_key());
+        assert!(connect(&engine, &Target { hops: vec![same_type] }, &Auth::default()).is_ok());
+    }
+
     /// The real engine's sequence against a server that offers only passwords: the key goes first and is refused, then the password.
     #[test]
     fn a_password_server_refuses_the_key_then_checks_the_password_and_says_when_one_is_wanted() {
```

`src-tauri/src/ssh/parity_tests.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/parity_tests.rs
+++ b/src-tauri/src/ssh/parity_tests.rs
@@ -215,6 +215,31 @@ fn an_unreachable_password_first_hop_was_asked_for_its_password_first() {
     unreachable_after_the_password(&real_engine(), closed_port);
 }
 
+/// A hop pinned to a key of another type: the handshake offers only that type, and the server has none (the broker then reconnects
+/// without the restriction to show the changed-key warning, plan 1b R17).
+fn pinned_type_missing(engine: &dyn SshEngine, target: &Target, auth: &dyn AuthSource) {
+    match engine.connect(target, &*super::testing::doubles::TestPolicy::trusting(), auth).err().expect("nothing in common") {
+        ConnectError::NoCommonHostKeyAlgorithm { hop, ours, theirs } => {
+            assert_eq!(hop.alias, "shell");
+            assert_eq!(ours, ["ecdsa-sha2-nistp256"]);
+            assert_eq!(theirs, ["ssh-ed25519"]);
+        }
+        other => panic!("expected NoCommonHostKeyAlgorithm, got {other:?}"),
+    }
+}
+
+#[test]
+fn a_pin_of_another_key_type_finds_no_common_algorithm() {
+    let ecdsa = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap();
+    let mut fake = fake_shells();
+    fake.target.hops[0].pinned = Some(ecdsa.clone());
+    pinned_type_missing(&*fake.engine, &fake.target, &*fake.auth);
+    if let Some(mut real) = real_shells() {
+        real.target.hops[0].pinned = Some(ecdsa);
+        pinned_type_missing(&*real.engine, &real.target, &*real.auth);
+    }
+}
+
 // ---------------------------------------------------------------------------------------------------------------------------------
 // Shells. The server prints a prompt when a shell opens: a scratch OpenSSH with `/bin/sh` behind a proxy that can cut the link, or a
 // fake that prints "$ ".
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::connect:: ssh::fake:: ssh::parity_tests::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0432]: unresolved imports `super::connect::CancelToken`, `super::connect::HostKeyConfirmer`, `super::connect::HostKeyQuestion`
error: could not compile `sshelter` (lib test) due to 33 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/session/connect.rs`: insert above the `#[cfg(test)]` line

```rust
//! Opening a session (own-ssh spec §6.2, §7.2, §10): the broker's connect loop around the engine. The engine fails fast where a person
//! must decide (an unknown or changed host key, a password wanted after a refused key); the broker asks — the window for host keys, the
//! session's owner for everything else — and connects again with what it learned. Every call here blocks: it runs on the thread of the
//! client's connection, never in async code and never on the UI thread.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::auth::{prompt_wait, BrokerAuth, KeyStore, Owner, PinPolicy, Reply};
use super::directory::{DirectoryError, HostDirectory};
use super::protocol::{kinds, HostQuery, QuestionKind};
use crate::ssh::{AuthMethod, ConnectError, HopRef, HostId, HostKey, Session, SshEngine, Target};
use crate::sync::env::Keychain;

/// How many passwords the person may type for one host in one connect (OpenSSH's `NumberOfPasswordPrompts`).
pub const PASSWORD_PROMPTS: usize = 3;

/// How many times one connect may go round (host keys confirmed, a password typed, the key type of a changed pin): enough for every
/// question on every hop of a chain, and a bound in case a server keeps changing its answer.
const MAX_ROUNDS: usize = 12;

/// The `kind` of a failure nobody is told about: the client went away.
pub const CANCELLED: &str = "cancelled";

/// Set when the session's owner went away (its connection ended): whatever the broker waits for (the window, a question) gives up, and
/// nothing more is connected.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The key that was pinned, for a changed-key question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedSummary {
    pub fingerprint: String,
    pub pinned_at_ms: u64,
}

/// A host key for the person to confirm in SSHelter's window (spec §10, §14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKeyQuestion {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    /// `None` for a key SSHelter has not seen; for a changed key, the one that is pinned.
    pub changed: Option<PinnedSummary>,
}

/// SSHelter's host key window, for the broker. It blocks until the person decides, the question times out or `cancel` is set, and returns
/// the fingerprint the person trusted (`None`: refused, closed, timed out, cancelled). The broker pins only the key it observed itself,
/// and only when the fingerprints match.
pub trait HostKeyConfirmer: Send + Sync {
    fn confirm(&self, question: &HostKeyQuestion, cancel: &CancelToken) -> Option<String>;
}

/// A session that is open, and the target it reached (with what the connect learned: pins, the password-first hops).
pub struct Connected {
    pub session: Box<dyn Session>,
    pub target: Target,
}

/// Why no session was opened: the sentence for the user (spec §11) and the `kind` word of the error event (`protocol::kinds`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectFailure {
    pub kind: String,
    pub text: String,
}

impl ConnectFailure {
    fn new(kind: &str, text: impl Into<String>) -> ConnectFailure {
        ConnectFailure { kind: kind.to_string(), text: text.into() }
    }

    fn cancelled() -> ConnectFailure {
        ConnectFailure::new(CANCELLED, "The connection was cancelled.")
    }
}

/// What the broker connects with.
pub struct Connector<'a> {
    pub engine: &'a dyn SshEngine,
    pub directory: &'a dyn HostDirectory,
    pub keys: &'a dyn KeyStore,
    pub keychain: &'a dyn Keychain,
    pub confirmer: &'a dyn HostKeyConfirmer,
}

/// The hop an error is about; `None` for an error about the whole chain.
fn hop_of(error: &ConnectError) -> Option<&HopRef> {
    match error {
        ConnectError::BadJumpChain { .. } => None,
        ConnectError::Unreachable { hop, .. }
        | ConnectError::Timeout { hop, .. }
        | ConnectError::HostKeyUnknown { hop, .. }
        | ConnectError::HostKeyMismatch { hop, .. }
        | ConnectError::NoCommonHostKeyAlgorithm { hop, .. }
        | ConnectError::AuthFailed { hop, .. }
        | ConnectError::AuthAbandoned { hop, .. }
        | ConnectError::Protocol { hop, .. } => Some(hop),
    }
}

/// The failure the user sees for an engine error. A failure on a jump host is said through it (spec §11:
/// `Could not connect through {jump alias}: {reason}`).
fn failure_of(error: &ConnectError, target: &Target) -> ConnectFailure {
    let kind = match error {
        ConnectError::HostKeyUnknown { .. } | ConnectError::HostKeyMismatch { .. } => kinds::HOST_KEY,
        ConnectError::AuthFailed { .. } | ConnectError::AuthAbandoned { .. } => kinds::AUTH,
        _ => kinds::CONNECT,
    };
    let destination = target.hops.last().map(|hop| &hop.id);
    match hop_of(error) {
        Some(hop) if Some(&hop.id) != destination => ConnectFailure::new(kind, format!("Could not connect through {}: {error}", hop.alias)),
        _ => ConnectFailure::new(kind, error.to_string()),
    }
}

fn directory_failure(error: DirectoryError) -> ConnectFailure {
    ConnectFailure::new(kinds::HOST, error.to_string())
}

impl Connector<'_> {
    /// Opens a session to the saved host `query` names, asking `owner` (the person at the client's terminal) what the login needs and the
    /// window about host keys, until it is open, it fails, or `cancel` is set.
    pub fn connect(&self, query: &HostQuery, owner: &dyn Owner, cancel: &CancelToken) -> Result<Connected, ConnectFailure> {
        if cancel.is_cancelled() {
            return Err(ConnectFailure::cancelled());
        }
        let mut target = self.directory.resolve(query).map_err(directory_failure)?;
        let auth = BrokerAuth::new(self.keys, self.keychain, owner, self.directory);
        auth.unlock(&target).map_err(|text| ConnectFailure::new(kinds::AUTH, text))?;
        let policy = PinPolicy::from_target(&target);
        let mut unrestricted: HashSet<HostId> = HashSet::new();
        let mut passwords_typed: HashMap<HostId, usize> = HashMap::new();
        for _ in 0..MAX_ROUNDS {
            if cancel.is_cancelled() {
                return Err(ConnectFailure::cancelled());
            }
            auth.prepare(&target);
            let error = match self.engine.connect(&target, &policy, &auth) {
                Ok(session) => return Ok(Connected { session, target }),
                Err(error) => error,
            };
            match error {
                ConnectError::HostKeyUnknown { hop, key } => self.confirm(&mut target, &policy, owner, cancel, &hop, &key, None)?,
                ConnectError::HostKeyMismatch { hop, key, pinned } => self.confirm(&mut target, &policy, owner, cancel, &hop, &key, Some(pinned))?,
                // Plan 1b R17: the handshake offered only the pinned key's type and the server has none of it any more. Once more without the
                // restriction: the policy still knows the pin, so a key of another type comes back as a changed key, with its warning.
                ConnectError::NoCommonHostKeyAlgorithm { ref hop, .. } if policy.pinned(&hop.id).is_some() && unrestricted.insert(hop.id.clone()) => {
                    if let Some(restricted) = target.hops.iter_mut().find(|candidate| candidate.id == hop.id) {
                        restricted.pinned = None;
                    }
                }
                ConnectError::AuthFailed { ref hop, ref tried, password_wanted, .. } if !auth.cancelled(&hop.id) => {
                    // A password given and refused: a typed one is forgotten; a saved one stays saved, and what the person types is used instead.
                    let refused = tried.contains(&AuthMethod::Password) && auth.password_source(&hop.id).is_some();
                    let typed = passwords_typed.entry(hop.id.clone()).or_default();
                    if !(password_wanted || refused) || *typed >= PASSWORD_PROMPTS {
                        return Err(failure_of(&error, &target));
                    }
                    auth.forget_typed(&hop.id);
                    let question = if refused { format!("That password didn't work. {}@{}'s password: ", hop.user, hop.alias) } else { format!("{}@{}'s password: ", hop.user, hop.alias) };
                    let Some(index) = target.hops.iter().position(|candidate| candidate.id == hop.id) else { return Err(failure_of(&error, &target)) };
                    let deadline = std::time::Instant::now().checked_add(prompt_wait(&target.hops[index]));
                    *typed += 1;
                    match owner.ask(QuestionKind::Password, &question, false, deadline) {
                        Reply::Answer(password) => {
                            auth.set_typed(&hop.id, password);
                            target.hops[index].auth = AuthMethod::Password;
                        }
                        Reply::Cancelled | Reply::TimedOut => {
                            return Err(ConnectFailure::new(kinds::AUTH, ConnectError::AuthAbandoned { hop: hop.clone(), reason: "the password was not given".to_string() }.to_string()));
                        }
                        Reply::Gone => return Err(ConnectFailure::cancelled()),
                    }
                }
                other => return Err(failure_of(&other, &target)),
            }
        }
        let alias = target.hops.last().map(|hop| hop.alias.clone()).unwrap_or_default();
        Err(ConnectFailure::new(kinds::CONNECT, format!("SSHelter gave up connecting to {alias}: the server kept asking for something new.")))
    }

    /// Asks the window about `key`, which `hop` presented (`pinned`: the key on record, for a changed key). When the person trusts exactly
    /// this key, it is pinned (or replaces the old pin) and the next round connects with it; anything else ends the connect.
    #[allow(clippy::too_many_arguments)]
    fn confirm(
        &self,
        target: &mut Target,
        policy: &PinPolicy,
        owner: &dyn Owner,
        cancel: &CancelToken,
        hop: &HopRef,
        key: &HostKey,
        pinned: Option<HostKey>,
    ) -> Result<(), ConnectFailure> {
        owner.host_key_notice(&format!("Waiting for you to confirm {}'s host key in SSHelter.", hop.alias));
        let changed = match &pinned {
            None => None,
            Some(pinned) => {
                let pinned_at_ms = self.directory.pinned(&hop.id).map_err(directory_failure)?.map(|pin| pin.pinned_at_ms).unwrap_or(0);
                Some(PinnedSummary { fingerprint: pinned.fingerprint.clone(), pinned_at_ms })
            }
        };
        let question = HostKeyQuestion {
            alias: hop.alias.clone(),
            hostname: hop.hostname.clone(),
            port: hop.port,
            algorithm: key.algorithm.clone(),
            fingerprint: key.fingerprint.clone(),
            changed,
        };
        let trusted = self.confirmer.confirm(&question, cancel);
        if cancel.is_cancelled() {
            return Err(ConnectFailure::cancelled());
        }
        if trusted.as_deref() != Some(key.fingerprint.as_str()) {
            let refused = match pinned {
                None => ConnectError::HostKeyUnknown { hop: hop.clone(), key: key.clone() },
                Some(pinned) => ConnectError::HostKeyMismatch { hop: hop.clone(), key: key.clone(), pinned },
            };
            return Err(ConnectFailure::new(kinds::HOST_KEY, refused.to_string()));
        }
        match &pinned {
            None => self.directory.pin(&hop.id, key),
            Some(pinned) => self.directory.replace_pin(&hop.id, pinned, key),
        }
        .map_err(|error| ConnectFailure::new(kinds::HOST_KEY, error.to_string()))?;
        policy.pin(&hop.id, key.clone());
        if let Some(confirmed) = target.hops.iter_mut().find(|candidate| candidate.id == hop.id) {
            confirmed.pinned = Some(key.clone());
        }
        Ok(())
    }
}
```

`src-tauri/src/ssh/fake.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/fake.rs
+++ b/src-tauri/src/ssh/fake.rs
@@ -335,6 +335,11 @@ impl SshEngine for FakeEngine {
                 return Err(error.clone());
             }
             let key = keys.get(&hop.alias).unwrap_or(&key_default).clone();
+            // A pinned hop offers only its pin's key type in the handshake, as in the real engine: a server whose key is of another type has
+            // nothing in common with it.
+            if let Some(pinned) = hop.pinned.as_ref().filter(|pinned| pinned.algorithm != key.algorithm) {
+                return Err(ConnectError::NoCommonHostKeyAlgorithm { hop: reference, ours: vec![pinned.algorithm.clone()], theirs: vec![key.algorithm] });
+            }
             match host_keys.check(&reference, &key) {
                 HostKeyVerdict::Pinned => {}
                 HostKeyVerdict::Unknown => return Err(ConnectError::HostKeyUnknown { hop: reference, key }),
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::connect:: ssh::fake:: ssh::parity_tests::)
```

Expected: PASS, `test result: ok. 47 passed; 0 failed; 0 ignored; 0 measured; 1617 filtered out`. Then the leftover check prints 0, 0 and 0.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1662 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/session/connect.rs \
  src-tauri/src/session/mod.rs \
  src-tauri/src/session/testing.rs \
  src-tauri/src/ssh/fake.rs \
  src-tauri/src/ssh/parity_tests.rs
git commit -m "feat(session): connect through host key confirmations, typed passwords and a changed key type"
```

Expected: `git status --short` lists the five files of this task; the `git diff --stat` prints nothing.

---

### Task 10: The shell relay and how a session ends

**Files:**
- Create: `src-tauri/src/session/relay.rs` (with its tests)
- Modify: `src-tauri/src/session/mod.rs`

**Interfaces:**
- Consumes: `Connected` (Task 9); `ServerMessage`, `Event`, `kinds`, `DATA_CHUNK` (Task 4); `Exit::Refused` (Task 2); `FakeEngine::{shells, disconnect_now, with_shell_error, with_write_errors}` and `FakeShell::{print, end}` in the tests (Task 3); `Session::{shell, is_alive, disconnect_reason, close}`, `ShellChannel::{read, write, window_change, exited, close}`, `DisconnectReason { hop, kind, detail }`, `DisconnectKind`, `SessionError::{Closed, Timeout}`, `Pty`, `Target` (plan 1a).
- Produces (`session/relay.rs`):
  - `pub const SETTLE: Duration` (3 s)
  - `pub trait ClientLink: Send + Sync { fn send(&self, message: &ServerMessage) -> std::io::Result<()>; fn send_data(&self, bytes: &[u8]) -> std::io::Result<()>; }`
  - `pub struct ShellControl` (`Default`) with `new()`, `with_settle(settle: Duration)`, `resize(&self, cols: u16, rows: u16)`, `input(&self, bytes: &[u8], link: &dyn ClientLink)`, `owner_gone(&self)`, `end(&self, reason: &str)`, `is_gone(&self) -> bool`
  - `pub fn lost_sentence(reason: &DisconnectReason, target: &Target) -> String`
  - `pub fn run_shell(connected: Connected, pty: Pty, link: &dyn ClientLink, control: &ShellControl, session_id: &str)`

What shapes this task:
- R9, the size: the shell opens at the last size the client sent (it may have been resized while the login ran) and the same size is sent again once the shell is open, because a resize sent before the PTY exists is ignored by the server (spec §7.2; plan 1a's decision 5).
- Output is read on the session thread and sent in data frames of at most 32 KiB; the engine's bounded queue (Task 1) keeps a slow client from holding up the connection. Input: a write that times out (`SessionError::Timeout`) is not a dead connection (keepalive decides that; plan 1a's review, item 8): the client is told `What you typed did not reach {alias} in time: the connection is not responding.` as an `input` error and the shell goes on.
- How it ended, never a lost connection as exit status 0 (R9): the shell's code or signal is `exited{code}` or `exited{signal}`; a refused PTY or shell (Task 2) is `error{shell}` `SSHelter could not open a shell on {alias}: {reason}.`; a lost connection is `event{disconnected}` with spec §11's sentence for the hop that recorded the end (`lost_sentence`: `Connection to {alias} lost (no response for {n} seconds).` with n = (`keepalive_max_missed` + 1) × the keepalive interval of that hop, or `… closed by the server.`, `… lost ({detail}).`, `… closed.`, `… ended ({detail}).`); a shell that ends without a status while the connection lives is `The shell on {alias} ended without an exit status.`. Each of these is followed by `exited{code: null, signal: null}`. Then the session is closed.
- R22: when the client goes away (`owner_gone`) or the app ends the session (`end`), the shell is closed only once it has printed something or `SETTLE` has passed since it opened: a channel closed before its prompt can leave a process holding a PTY on a macOS sshd (plan 1a's Task 8 re-review). The wait is at most 3 s, on a plain thread; the shell is closed once, and not at all when it has already ended.
- `end(reason)` is how quitting the app reaches a session (Task 11's `end_all`): the client is told `event{disconnected}` with the reason and `exited` without a status.

- [ ] **Step 1: Write the tests**

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -7,6 +7,7 @@ pub mod connect;
 pub mod directory;
 pub mod pins;
 pub mod protocol;
+pub mod relay;
 pub mod ssh_config_directory;
 #[cfg(test)]
 pub mod testing;
```

`src-tauri/src/session/relay.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::session::testing::locked;
    use crate::ssh::fake::{FakeEngine, FakeEvent};
    use crate::ssh::{AuthMethod, DisconnectKind, DisconnectReason, Hop, SessionError, SshEngine};

    /// The client side, recorded.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<Sent>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Sent {
        Message(ServerMessage),
        Data(Vec<u8>),
    }

    impl ClientLink for Recorder {
        fn send(&self, message: &ServerMessage) -> std::io::Result<()> {
            locked(&self.sent).push(Sent::Message(message.clone()));
            Ok(())
        }
        fn send_data(&self, bytes: &[u8]) -> std::io::Result<()> {
            locked(&self.sent).push(Sent::Data(bytes.to_vec()));
            Ok(())
        }
    }

    impl Recorder {
        fn sent(&self) -> Vec<Sent> {
            locked(&self.sent).clone()
        }

        /// The output, joined, and the control messages, in order.
        fn split(&self) -> (Vec<u8>, Vec<ServerMessage>) {
            let mut output = Vec::new();
            let mut messages = Vec::new();
            for sent in self.sent() {
                match sent {
                    Sent::Data(bytes) => output.extend(bytes),
                    Sent::Message(message) => messages.push(message),
                }
            }
            (output, messages)
        }
    }

    fn target() -> Target {
        Target { hops: vec![Hop::new("id-web", "web", "web.example.com", 22, "deploy", AuthMethod::Password)] }
    }

    fn pty() -> Pty {
        Pty { term: "xterm-256color".into(), cols: 80, rows: 24 }
    }

    /// Runs the shell on a thread of its own, as the broker does, with a short settle time for the tests.
    struct Running {
        engine: Arc<FakeEngine>,
        link: Arc<Recorder>,
        control: Arc<ShellControl>,
        pump: Option<std::thread::JoinHandle<()>>,
    }

    fn start(engine: FakeEngine, control: ShellControl) -> Running {
        let engine = Arc::new(engine);
        let session = engine.connect(&target(), &*crate::ssh::testing::doubles::TestPolicy::trusting(), &crate::ssh::testing::doubles::VaultAuth::new()).unwrap();
        let (link, control) = (Arc::new(Recorder::default()), Arc::new(control));
        let pump = {
            let (link, control) = (Arc::clone(&link), Arc::clone(&control));
            std::thread::spawn(move || run_shell(Connected { session, target: target() }, pty(), link.as_ref(), &control, "7"))
        };
        Running { engine, link, control, pump: Some(pump) }
    }

    impl Running {
        fn wait_for_shell(&self) -> crate::ssh::fake::FakeShell {
            crate::ssh::testing::eventually("the shell to open", 5, || !self.engine.shells().is_empty());
            self.engine.shells().remove(0)
        }

        /// Waits for the pump to finish (the shell ended and the session is closed).
        fn finish(&mut self) {
            let pump = self.pump.take().expect("running");
            let deadline = Instant::now() + Duration::from_secs(10);
            while !pump.is_finished() {
                assert!(Instant::now() < deadline, "the shell's thread did not finish");
                std::thread::sleep(Duration::from_millis(10));
            }
            pump.join().unwrap();
        }
    }

    #[test]
    fn a_shell_opens_at_the_last_size_sends_it_again_and_relays_output_until_it_exits() {
        let control = ShellControl::new();
        control.resize(100, 30);
        let mut running = start(FakeEngine::new(), control);
        let remote = running.wait_for_shell();
        remote.print(b"$ ");
        remote.print(b"bye\r\n");
        remote.end(Exit::Code(3));
        running.finish();
        let (output, messages) = running.link.split();
        assert_eq!(output, b"$ bye\r\n");
        assert_eq!(messages, [ServerMessage::Opened { session_id: "7".into() }, ServerMessage::Exited { code: Some(3), signal: None }]);
        let events = running.engine.events();
        assert!(events.contains(&FakeEvent::ShellOpened { term: "xterm-256color".into(), cols: 100, rows: 30 }), "opened at the size the client sent last: {events:?}");
        assert!(events.contains(&FakeEvent::WindowChange { cols: 100, rows: 30 }), "and that size sent again once the shell is ready (spec §7.2)");
        assert_eq!(events.last(), Some(&FakeEvent::Closed), "the session is closed after its shell");
    }

    #[test]
    fn keystrokes_and_resizes_reach_the_shell_and_input_that_times_out_is_reported_without_ending_it() {
        let mut running = start(FakeEngine::new().with_write_errors(vec![SessionError::Timeout]), ShellControl::new());
        let remote = running.wait_for_shell();
        running.control.input(b"lost", running.link.as_ref());
        running.control.input(b"ls\r", running.link.as_ref());
        running.control.resize(120, 40);
        remote.end(Exit::Code(0));
        running.finish();
        let events = running.engine.events();
        assert!(events.contains(&FakeEvent::ShellInput(b"ls\r".to_vec())) && events.contains(&FakeEvent::WindowChange { cols: 120, rows: 40 }), "{events:?}");
        let (_, messages) = running.link.split();
        assert_eq!(
            messages[1],
            ServerMessage::Event(Event::Error { kind: kinds::INPUT.into(), text: "What you typed did not reach web in time: the connection is not responding.".into() })
        );
        assert_eq!(messages.last(), Some(&ServerMessage::Exited { code: Some(0), signal: None }), "the shell went on and ended normally");
    }

    #[test]
    fn a_shell_killed_by_a_signal_says_which() {
        let mut running = start(FakeEngine::new(), ShellControl::new());
        running.wait_for_shell().end(Exit::Signal("KILL".into()));
        running.finish();
        assert_eq!(running.link.split().1.last(), Some(&ServerMessage::Exited { code: None, signal: Some("KILL".into()) }));
    }

    /// A lost connection is a disconnect with its reason, never exit status 0 (spec §7.1, §11).
    #[test]
    fn a_lost_connection_is_reported_with_its_reason_and_no_exit_status() {
        let mut running = start(FakeEngine::new(), ShellControl::new());
        running.wait_for_shell().print(b"half a line");
        let hop = target().hops[0].reference();
        running.engine.disconnect_now(DisconnectReason { hop, kind: DisconnectKind::ConnectionLost, detail: "connection reset by peer".into() });
        running.finish();
        let (output, messages) = running.link.split();
        assert_eq!(output, b"half a line");
        assert_eq!(
            &messages[1..],
            [
                ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost (connection reset by peer).".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
    }

    /// Spec §11: `{n}` = (`keepalive_max_missed` + 1) × `keepalive_secs` of the hop that went silent.
    #[test]
    fn a_link_that_stopped_answering_keepalives_says_for_how_long() {
        let reason = |kind, detail: &str| DisconnectReason { hop: target().hops[0].reference(), kind, detail: detail.into() };
        let hops = target();
        assert_eq!(lost_sentence(&reason(DisconnectKind::KeepaliveTimeout, "silent"), &hops), "Connection to web lost (no response for 120 seconds).");
        assert_eq!(lost_sentence(&reason(DisconnectKind::ClosedByPeer, "the server closed the connection: bye"), &hops), "Connection to web closed by the server.");
        assert_eq!(lost_sentence(&reason(DisconnectKind::ConnectionLost, "broken pipe"), &hops), "Connection to web lost (broken pipe).");
        assert_eq!(lost_sentence(&reason(DisconnectKind::ClosedByUs, "closed"), &hops), "Connection to web closed.");
        assert_eq!(lost_sentence(&reason(DisconnectKind::Other, "protocol error"), &hops), "Connection to web ended (protocol error).");
        let mut quick = target();
        quick.hops[0].keepalive_every = Duration::from_secs(10);
        quick.hops[0].keepalive_max_missed = 2;
        assert_eq!(lost_sentence(&reason(DisconnectKind::KeepaliveTimeout, "silent"), &quick), "Connection to web lost (no response for 30 seconds).");
    }

    #[test]
    fn a_refused_terminal_or_a_shell_that_cannot_open_is_an_error_with_the_reason() {
        let refused = FakeEngine::new().with_shell_exit(Exit::Refused("the server refused to allocate a terminal (PTY)".into())).with_shell_ending_at_once();
        let mut running = start(refused, ShellControl::new());
        running.finish();
        assert_eq!(
            &running.link.split().1[1..],
            [
                ServerMessage::Event(Event::Error { kind: kinds::SHELL.into(), text: "SSHelter could not open a shell on web: the server refused to allocate a terminal (PTY).".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );

        let mut failing = start(FakeEngine::new().with_shell_error(SessionError::Channel("channel open refused".into())), ShellControl::new());
        failing.finish();
        assert_eq!(
            failing.link.split().1,
            [
                ServerMessage::Event(Event::Error { kind: kinds::SHELL.into(), text: "SSHelter could not open a shell on web: SSH error: channel open refused.".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
    }

    /// Plan 1b R22: the client left right after the shell opened; the shell is closed once it has printed something, not before.
    #[test]
    fn when_the_client_goes_away_the_shell_is_closed_after_its_first_output_and_nothing_more_is_sent() {
        let mut running = start(FakeEngine::new(), ShellControl::with_settle(Duration::from_secs(5)));
        let remote = running.wait_for_shell();
        let started = Instant::now();
        let leaving = {
            let control = Arc::clone(&running.control);
            std::thread::spawn(move || control.owner_gone())
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(!running.engine.events().contains(&FakeEvent::ShellClosed), "not closed before the shell printed anything");
        remote.print(b"$ ");
        leaving.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(3), "closed soon after the first output: {:?}", started.elapsed());
        running.finish();
        let events = running.engine.events();
        assert!(events.contains(&FakeEvent::ShellClosed) && events.last() == Some(&FakeEvent::Closed), "{events:?}");
        assert_eq!(running.link.split().1, [ServerMessage::Opened { session_id: "7".into() }], "the client is gone: nothing more is sent to it");
    }

    #[test]
    fn a_shell_that_never_prints_is_closed_once_the_settle_time_has_passed() {
        let mut running = start(FakeEngine::new(), ShellControl::with_settle(Duration::from_millis(300)));
        running.wait_for_shell();
        let started = Instant::now();
        running.control.owner_gone();
        assert!(started.elapsed() >= Duration::from_millis(250), "it waited for the settle time: {:?}", started.elapsed());
        running.finish();
        assert!(running.engine.events().contains(&FakeEvent::ShellClosed));
    }

    #[test]
    fn quitting_the_app_ends_the_shell_and_tells_the_client_why() {
        let mut running = start(FakeEngine::new(), ShellControl::with_settle(Duration::from_millis(100)));
        running.wait_for_shell().print(b"$ ");
        running.control.end("SSHelter quit, so the connection to web was closed.");
        running.finish();
        assert_eq!(
            &running.link.split().1[1..],
            [
                ServerMessage::Event(Event::Disconnected { reason: "SSHelter quit, so the connection to web was closed.".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
        assert_eq!(running.engine.events().last(), Some(&FakeEvent::Closed));
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::relay::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find type `Mutex` in this scope
error: could not compile `sshelter` (lib test) due to 72 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/session/relay.rs`: insert above the `#[cfg(test)]` line

```rust
//! A shell between the engine and a client (own-ssh spec §7.2): open it at the client's last known size and send that size again once
//! it is ready, pump its output to the client, take the client's keystrokes and resizes, and say how it ended (`exited`, after an
//! `event` that explains a lost connection or a refused shell; a lost connection is never exit status 0). When the client goes away the
//! shell and the session are closed from a plain thread, after the shell's first output or a few seconds (plan 1b R22: a shell closed
//! before its prompt can strand a process on a macOS sshd).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::connect::Connected;
use super::protocol::{kinds, Event, ServerMessage, DATA_CHUNK};
use crate::ssh::{DisconnectKind, DisconnectReason, Exit, Pty, Session, SessionError, ShellChannel, Target};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How long a shell the client left is given to print something before it is closed anyway (plan 1b R22).
pub const SETTLE: Duration = Duration::from_secs(3);

/// The client end of a shell: where its output and messages go. A write that fails means the client is gone.
pub trait ClientLink: Send + Sync {
    fn send(&self, message: &ServerMessage) -> std::io::Result<()>;
    fn send_data(&self, bytes: &[u8]) -> std::io::Result<()>;
}

/// What the client's side (the thread that reads its connection) and the shell's side (the thread that pumps output) share for one
/// shell: the shell once it is open, the last size the client sent, whether the client is gone, and why the app ends the session.
pub struct ShellControl {
    shell: Mutex<Option<Arc<dyn ShellChannel>>>,
    alias: Mutex<String>,
    size: Mutex<Option<(u16, u16)>>,
    gone: AtomicBool,
    /// The shell was asked to close (once is enough).
    closed: AtomicBool,
    /// Set when the app ends the session (it is quitting): the sentence the client is told.
    ended_by_app: Mutex<Option<String>>,
    /// When the shell opened, and whether it has printed anything yet (for `settle`).
    printed: Mutex<(Option<Instant>, bool)>,
    first_output: Condvar,
    settle: Duration,
}

impl Default for ShellControl {
    fn default() -> Self {
        ShellControl::new()
    }
}

impl ShellControl {
    pub fn new() -> ShellControl {
        ShellControl::with_settle(SETTLE)
    }

    /// The same, with another settle time (tests).
    pub fn with_settle(settle: Duration) -> ShellControl {
        ShellControl {
            shell: Mutex::new(None),
            alias: Mutex::new(String::new()),
            size: Mutex::new(None),
            gone: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            ended_by_app: Mutex::new(None),
            printed: Mutex::new((None, false)),
            first_output: Condvar::new(),
            settle,
        }
    }

    /// The client's terminal has this size: remembered, and sent to the shell when it is open (spec §7.2).
    pub fn resize(&self, cols: u16, rows: u16) {
        *locked(&self.size) = Some((cols, rows));
        let shell = locked(&self.shell).clone();
        if let Some(shell) = shell {
            if let Err(error) = shell.window_change(cols, rows) {
                eprintln!("[session] a window size did not reach the shell: {error}");
            }
        }
    }

    /// Keystrokes from the client. Before the shell is open there is nowhere for them to go (the CLI sends none then). A write the link
    /// did not take in time is not the end of the connection (keepalive decides that): the client is told, and the shell goes on.
    pub fn input(&self, bytes: &[u8], link: &dyn ClientLink) {
        let shell = locked(&self.shell).clone();
        let Some(shell) = shell else { return };
        match shell.write(bytes) {
            Ok(()) | Err(SessionError::Closed) => {}
            Err(SessionError::Timeout) => {
                let alias = locked(&self.alias).clone();
                let text = format!("What you typed did not reach {alias} in time: the connection is not responding.");
                let _ = link.send(&ServerMessage::Event(Event::Error { kind: kinds::INPUT.to_string(), text }));
            }
            Err(error) => eprintln!("[session] input did not reach the shell: {error}"),
        }
    }

    /// The client went away (its connection ended, or it sent `close`): the shell is closed once it has printed something or `settle`
    /// has passed since it opened, so that a shell closed right after it opened does not strand a process on the server. Blocks for at
    /// most that long; call it from a plain thread.
    pub fn owner_gone(&self) {
        self.gone.store(true, Ordering::SeqCst);
        self.close_settled();
    }

    /// The app ends the session (it is quitting): the client is told `reason`, then the shell is closed as for `owner_gone`.
    pub fn end(&self, reason: &str) {
        *locked(&self.ended_by_app) = Some(reason.to_string());
        self.close_settled();
    }

    pub fn is_gone(&self) -> bool {
        self.gone.load(Ordering::SeqCst)
    }

    fn close_settled(&self) {
        let shell = locked(&self.shell).clone();
        let Some(shell) = shell else { return };
        if shell.exited().is_some() || self.closed.load(Ordering::SeqCst) {
            return;
        }
        let mut printed = locked(&self.printed);
        while !printed.1 {
            let Some(opened) = printed.0 else { break };
            let left = (opened + self.settle).saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            printed = self.first_output.wait_timeout(printed, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        drop(printed);
        self.close_now();
    }

    /// Closes the shell, once.
    fn close_now(&self) {
        let shell = locked(&self.shell).clone();
        if let Some(shell) = shell {
            if !self.closed.swap(true, Ordering::SeqCst) {
                shell.close();
            }
        }
    }

    fn opened(&self, shell: Arc<dyn ShellChannel>) {
        *locked(&self.printed) = (Some(Instant::now()), false);
        *locked(&self.shell) = Some(shell);
    }

    fn printed(&self) {
        let mut printed = locked(&self.printed);
        if !printed.1 {
            printed.1 = true;
            self.first_output.notify_all();
        }
    }
}

/// The sentence for a connection that ended (spec §11), about the hop that recorded the end; a dead keepalive says how many seconds went
/// without an answer: (`keepalive_max_missed` + 1) × `keepalive_secs` of that hop.
pub fn lost_sentence(reason: &DisconnectReason, target: &Target) -> String {
    let alias = &reason.hop.alias;
    match reason.kind {
        DisconnectKind::KeepaliveTimeout => {
            let hop = target.hops.iter().find(|hop| hop.id == reason.hop.id);
            let seconds = hop.map(|hop| hop.keepalive_every.as_secs().saturating_mul(u64::from(hop.keepalive_max_missed) + 1)).unwrap_or(0);
            format!("Connection to {alias} lost (no response for {seconds} seconds).")
        }
        DisconnectKind::ClosedByPeer => format!("Connection to {alias} closed by the server."),
        DisconnectKind::ConnectionLost => format!("Connection to {alias} lost ({}).", reason.detail),
        DisconnectKind::ClosedByUs => format!("Connection to {alias} closed."),
        DisconnectKind::Other => format!("Connection to {alias} ended ({}).", reason.detail),
    }
}

/// What the client is told when its shell has ended: an event that explains an end without a status, then `exited`.
fn ending(exit: Option<Exit>, session: &dyn Session, target: &Target, alias: &str) -> (Option<Event>, ServerMessage) {
    let no_status = ServerMessage::Exited { code: None, signal: None };
    match exit {
        Some(Exit::Code(code)) => (None, ServerMessage::Exited { code: Some(code), signal: None }),
        Some(Exit::Signal(signal)) => (None, ServerMessage::Exited { code: None, signal: Some(signal) }),
        Some(Exit::Refused(why)) => {
            (Some(Event::Error { kind: kinds::SHELL.to_string(), text: format!("SSHelter could not open a shell on {alias}: {why}.") }), no_status)
        }
        Some(Exit::Disconnected) | None => {
            let reason = if session.is_alive() {
                format!("The shell on {alias} ended without an exit status.")
            } else {
                match session.disconnect_reason() {
                    Some(reason) => lost_sentence(&reason, target),
                    None => format!("Connection to {alias} lost."),
                }
            };
            (Some(Event::Disconnected { reason }), no_status)
        }
    }
}

/// Runs the client's shell on the session `connected` holds, then closes the session; returns when both are done. Call it from a plain
/// thread: the engine's calls block. `pty` is what the client asked for; the size is the last one it sent, if it sent one since.
pub fn run_shell(connected: Connected, pty: Pty, link: &dyn ClientLink, control: &ShellControl, session_id: &str) {
    let Connected { session, target } = connected;
    let alias = target.hops.last().map(|hop| hop.alias.clone()).unwrap_or_default();
    *locked(&control.alias) = alias.clone();
    let (cols, rows) = locked(&control.size).unwrap_or((pty.cols, pty.rows));
    let shell: Arc<dyn ShellChannel> = match session.shell(Pty { cols, rows, ..pty }) {
        Ok(shell) => Arc::from(shell),
        Err(error) => {
            let text = format!("SSHelter could not open a shell on {alias}: {}.", error.to_string().trim_end_matches('.'));
            let _ = link.send(&ServerMessage::Event(Event::Error { kind: kinds::SHELL.to_string(), text }));
            let _ = link.send(&ServerMessage::Exited { code: None, signal: None });
            session.close();
            return;
        }
    };
    control.opened(Arc::clone(&shell));
    if link.send(&ServerMessage::Opened { session_id: session_id.to_string() }).is_err() {
        control.gone.store(true, Ordering::SeqCst);
    }
    // The size the client sent while the shell was being opened, or the one it was opened with: sent once more now that the PTY exists
    // (spec §7.2: a resize before the shell is ready is ignored by the server).
    let (cols, rows) = locked(&control.size).unwrap_or((cols, rows));
    if let Err(error) = shell.window_change(cols, rows) {
        eprintln!("[session] the window size did not reach the new shell: {error}");
    }
    if control.is_gone() {
        control.close_settled();
    }
    let mut buf = vec![0u8; DATA_CHUNK];
    loop {
        let count = match shell.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        control.printed();
        if !control.is_gone() && link.send_data(&buf[..count]).is_err() {
            // The client is gone (its terminal has printed, so the shell is settled): close it, and drain it until it ends.
            control.gone.store(true, Ordering::SeqCst);
            control.close_now();
        }
    }
    if !control.is_gone() {
        let ended_by_app = locked(&control.ended_by_app).clone();
        let (event, exited) = match ended_by_app {
            Some(reason) => (Some(Event::Disconnected { reason }), ServerMessage::Exited { code: None, signal: None }),
            None => ending(shell.exited(), session.as_ref(), &target, &alias),
        };
        if let Some(event) = event {
            let _ = link.send(&ServerMessage::Event(event));
        }
        let _ = link.send(&exited);
    }
    session.close();
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::relay::)
```

Expected: PASS, `test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 1664 filtered out`.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1671 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/session/mod.rs \
  src-tauri/src/session/relay.rs
git commit -m "feat(session): relay a shell to its client and say how it ended"
```

Expected: `git status --short` lists the two files of this task; the `git diff --stat` prints nothing.

---

### Task 11: The broker on the local socket

**Files:**
- Create: `src-tauri/src/session/broker.rs` (with its tests, Unix only)
- Modify: `src-tauri/src/session/testing.rs` (`FakeKeys::with_key`, `FakeDirectory::with_hop`, `WaitingConfirmer`), `src-tauri/src/session/mod.rs`
- Modify: `.github/workflows/test-engine.yml`, `.github/workflows/test-windows.yml`
- Modify: `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` (§7.2)

**Interfaces:**
- Consumes: Tasks 4–10 (`read_frame`, `write_control`, `write_data`, `decode`, the messages; `KeyStore`, `Owner`, `Reply`; `Connector`, `CancelToken`, `HostKeyConfirmer`, `CANCELLED`; `HostDirectory`; `run_shell`, `ClientLink`, `ShellControl`); phase 0's `crate::ipc::server::{Handler, Stream}` (`Handler = Arc<dyn Fn(Stream, Option<u32>) + Send + Sync>`; `listen_unix(dir, handler)` in the tests) and `crate::ipc::peer::{process_chain, identify, ProcInfo}`; `crate::ssh::{HostId, Pty, SshEngine}`, `RusshEngine` in the end-to-end test.
- Produces (`session/broker.rs`):
  - `pub fn quit_reason(alias: &str) -> String`
  - `pub struct SessionInfo { pub id: u64, pub alias: String, pub host_id: HostId, pub requested_by: Option<Vec<String>>, pub started_at_ms: u64 }`
  - `pub struct Broker` with `pub fn new(engine: Arc<dyn SshEngine>, directory: Arc<dyn HostDirectory>, keys: Arc<dyn KeyStore>, keychain: Arc<dyn Keychain>, confirmer: Arc<dyn HostKeyConfirmer>) -> Arc<Broker>`, `pub fn handler(self: &Arc<Broker>) -> Handler`, `pub fn sessions(&self) -> Vec<SessionInfo>`, `pub fn has_sessions(&self) -> bool`, `pub fn end_all(&self, wait: Duration)`, `pub fn serve(self: &Arc<Broker>, stream: Stream, pid: Option<u32>)`
  - `pub fn without_own_executable(chain: Vec<ProcInfo>, own: Option<&Path>) -> Vec<ProcInfo>`, `pub fn requester_of(pid: Option<u32>) -> Option<Vec<String>>`
  - `session/testing.rs`: `FakeKeys::with_key(self, key_id: &str, name: &str, private_text: &str) -> FakeKeys` (a key of the test's own, such as a scratch sshd's user key), `FakeDirectory::with_hop(self, hop: Hop) -> FakeDirectory` (a host given as a whole hop, such as a scratch sshd's), and `pub struct WaitingConfirmer` (a window nobody answers: it waits until the connect is cancelled) with `impl HostKeyConfirmer`

What shapes this task:
- R5: one IPC connection is one session (spec §7.2), and the connection owns it. The connection's thread (the one the IPC server gives the handler) reads the client; a second plain thread, `sshelter-session`, connects and runs the shell. `hello` must come within 10 s; after it no read timeout applies, so the IPC server's 300 s idle timeout (phase 0's `IDLE_TIMEOUT`, set before the handler runs) does not end an idle shell. The server accepts only connections of the same user (peer uid) and at most 64 at a time (phase 0's `MAX_CONNECTIONS`), so at most 64 sessions are open at once.
- What this version does not serve is refused by name with an `error` event, and the connection is closed: another protocol version (`This sshelter speaks protocol {v} and the SSHelter that is running speaks 1. Quit SSHelter and open it again.`), an MCP client (`The MCP adapter cannot use SSHelter's sessions yet.`), `exec` (`Running a command through SSHelter's sessions is not supported yet.`), anything but `hello` first (`The first message must be hello.`). MCP and exec are phase 2 (R15).
- A session that could not be opened ends with `event{error{kind, text}}` and `exited{code: null, signal: null}`, then the connection closes; a client that is gone is told nothing.
- The session's owner is its connection: a question goes out as a `question` frame (`question_id` `q1`, `q2` …, `deadline_ms` from now) and the reader thread delivers the `answer`; an answer after the deadline or to an unknown id is dropped. The host key notice is a `question{kind: host_key_notice}` with `deadline_ms: null`.
- When the client goes away (end of stream, `close`, a frame error): cancel the connect (the window stops waiting), wake every waiting question with `Gone`, hand the shell to the settle of R22 (`owner_gone`), and wait for the session thread. When the session ends first, the broker shuts the connection down both ways, which ends the reader and tells the client.
- R5's requester: at accept, the peer pid's process chain (`ipc::peer::process_chain`) without SSHelter's own executable (`sshelter connect` is SSHelter; the person's program is what started it), named as `ipc::peer::identify` names programs, is recorded on the session (`SessionInfo::requested_by`); approvals and showing it are phase 2.
- R7: `sessions`, `has_sessions` and `end_all` are for the app (plan 1b-2 Task 4): it keeps running while sessions are open and, when it quits, ends every session and tells each client `SSHelter quit, so the connection to {alias} was closed.` (spec §4).
- Windows (R4): the module compiles there — `set_read_timeout` and `hang_up` have Windows versions that do nothing — and its tests are Unix only; the app does not start the broker on Windows in 1b.
- CI: `test-engine.yml` runs `ssh:: vault::` only, so `session::` and `host_start::` would not run on macOS and Linux; they join its filters. `test-windows.yml` gets `session::` (its platform-neutral tests).
- Spec §7.2 gets the rules as built (Step 5).
- `a_real_shell_on_a_scratch_sshd_through_the_socket` is this plan's end-to-end check: the real engine, a scratch sshd, the host key confirmed by a scripted window and pinned, a shell through a real socket in a temp directory, and its exit status.

- [ ] **Step 1: Write the tests**

`src-tauri/src/session/broker.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    use super::*;
    use crate::session::protocol::{read_frame, write_control, write_data, Frame, PtyRequest, QuestionKind};
    use crate::session::testing::{locked, Decision, FakeConfirmer, FakeDirectory, FakeKeys, WaitingConfirmer};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods, FakeShell};
    use crate::ipc::peer::ProcInfo;
    use crate::ssh::{AuthMethod, Exit};
    use crate::sync::testkit::MemKeychain;

    /// What the client received.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Got {
        Message(ServerMessage),
        Data(Vec<u8>),
    }

    /// A client of the broker, speaking the protocol over a socket.
    struct Client {
        stream: UnixStream,
    }

    impl Client {
        fn connect(sock: &Path) -> Client {
            let stream = UnixStream::connect(sock).expect("the broker listens");
            stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            Client { stream }
        }

        fn send(&mut self, message: &ClientMessage) {
            write_control(&mut self.stream, message).expect("the broker reads");
        }

        fn hello(&mut self) {
            self.send(&ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None });
        }

        fn open(&mut self, alias: &str) {
            self.hello();
            self.send(&ClientMessage::OpenShell { host: HostQuery::Alias(alias.into()), pty: PtyRequest { cols: 80, rows: 24, term: "xterm-256color".into() } });
        }

        fn type_text(&mut self, text: &str) {
            write_data(&mut self.stream, text.as_bytes()).unwrap();
        }

        /// The next thing the broker sent; `None` once it has closed the connection.
        fn next(&mut self) -> Option<Got> {
            match read_frame(&mut self.stream).expect("a frame or the end") {
                None => None,
                Some(Frame::Control(payload)) => Some(Got::Message(decode::<ServerMessage>(&payload).expect("a server message"))),
                Some(Frame::Data(bytes)) => Some(Got::Data(bytes.to_vec())),
            }
        }

        fn next_message(&mut self) -> ServerMessage {
            loop {
                match self.next() {
                    Some(Got::Message(message)) => return message,
                    Some(Got::Data(_)) => continue,
                    None => panic!("the broker closed the connection"),
                }
            }
        }

        /// Everything until the broker closes the connection: the output, and the messages.
        fn rest(&mut self) -> (Vec<u8>, Vec<ServerMessage>) {
            let (mut output, mut messages) = (Vec::new(), Vec::new());
            while let Some(got) = self.next() {
                match got {
                    Got::Data(bytes) => output.extend(bytes),
                    Got::Message(message) => messages.push(message),
                }
            }
            (output, messages)
        }

        fn answer(&mut self, question_id: &str, value: Option<&str>) {
            self.send(&ClientMessage::Answer { question_id: question_id.into(), value: value.map(str::to_string), cancel: value.is_none() });
        }
    }

    struct World {
        broker: Arc<Broker>,
        engine: Arc<FakeEngine>,
        directory: Arc<FakeDirectory>,
        sock: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    /// A broker over `engine`, `directory` and `confirmer`, listening on a socket in a short temp directory (macOS limits socket paths).
    fn world_with(engine: FakeEngine, directory: FakeDirectory, confirmer: Arc<dyn HostKeyConfirmer>, keychain: MemKeychain) -> World {
        let (engine, directory) = (Arc::new(engine), Arc::new(directory));
        let broker = Broker::new(
            Arc::clone(&engine) as Arc<dyn SshEngine>,
            Arc::clone(&directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new()),
            Arc::new(keychain),
            confirmer,
        );
        let dir = tempfile::Builder::new().prefix("sb").tempdir_in("/tmp").unwrap();
        let ipc = dir.path().join("ipc");
        assert_eq!(crate::ipc::server::listen_unix(&ipc, broker.handler()).unwrap(), crate::ipc::server::Started::Running);
        World { broker, engine, directory, sock: ipc.join("sock"), _dir: dir }
    }

    /// `web` is pinned and its password is saved: it connects without a question.
    fn world(engine: FakeEngine) -> World {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        world_with(engine, FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), Arc::new(FakeConfirmer::default()), keychain)
    }

    fn remote(world: &World) -> FakeShell {
        crate::ssh::testing::eventually("the shell to open", 10, || !world.engine.shells().is_empty());
        world.engine.shells().remove(0)
    }

    fn no_status() -> ServerMessage {
        ServerMessage::Exited { code: None, signal: None }
    }

    #[test]
    fn a_client_opens_a_shell_over_the_socket_types_into_it_and_gets_its_exit_status() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        client.type_text("ls\r");
        client.send(&ClientMessage::WindowChange { cols: 120, rows: 40 });
        let shell = remote(&world);
        shell.print(b"file.txt\r\n");
        crate::ssh::testing::eventually("the input to reach the shell", 5, || world.engine.events().contains(&FakeEvent::ShellInput(b"ls\r".to_vec())));
        crate::ssh::testing::eventually("the resize to reach the shell", 5, || world.engine.events().contains(&FakeEvent::WindowChange { cols: 120, rows: 40 }));
        shell.end(Exit::Code(5));
        let (output, messages) = client.rest();
        assert_eq!(output, b"file.txt\r\n");
        assert_eq!(messages, [ServerMessage::Exited { code: Some(5), signal: None }]);
        crate::ssh::testing::eventually("the session to be closed and forgotten", 5, || world.broker.sessions().is_empty());
        assert_eq!(world.engine.events().last(), Some(&FakeEvent::Closed));
    }

    #[test]
    fn the_client_is_told_to_look_at_the_window_while_the_host_key_is_confirmed_there() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let world = world_with(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password), Arc::new(FakeConfirmer::deciding(vec![Decision::Trust])), keychain);
        let mut client = Client::connect(&world.sock);
        client.open("web");
        match client.next_message() {
            ServerMessage::Question(question) => {
                assert_eq!((question.kind, question.text.as_str(), question.echo, question.deadline_ms), (QuestionKind::HostKeyNotice, "Waiting for you to confirm web's host key in SSHelter.", false, None));
            }
            other => panic!("expected the notice, got {other:?}"),
        }
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        assert!(world.directory.pins().contains_key(&HostId::from("id-web")));
    }

    #[test]
    fn a_password_the_login_wants_is_asked_of_the_client_and_its_answer_gets_in() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world_with(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, Arc::new(FakeConfirmer::default()), MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(question) = client.next_message() else { panic!("expected a question") };
        assert_eq!((question.kind, question.text.as_str(), question.echo), (QuestionKind::Password, "deploy@web's password: ", false));
        let deadline_ms = question.deadline_ms.expect("a deadline");
        assert!((55_000..=60_000).contains(&deadline_ms), "{deadline_ms}");
        client.answer(&question.question_id, Some("right"));
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
    }

    #[test]
    fn a_cancelled_question_ends_the_connect_with_an_error_and_no_exit_status() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world_with(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, Arc::new(FakeConfirmer::default()), MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(question) = client.next_message() else { panic!("expected a question") };
        client.answer(&question.question_id, None);
        assert_eq!(
            client.rest().1,
            [
                ServerMessage::Event(Event::Error { kind: kinds::AUTH.into(), text: "Authentication for web was abandoned (the password was not given).".into() }),
                no_status(),
            ]
        );
    }

    #[test]
    fn a_host_that_cannot_be_connected_is_an_error_then_an_exit_without_a_status() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("mail");
        assert_eq!(client.rest().1, [ServerMessage::Event(Event::Error { kind: kinds::HOST.into(), text: "No saved host is called mail.".into() }), no_status()]);
    }

    #[test]
    fn another_protocol_version_exec_and_the_mcp_client_are_refused_by_name() {
        let world = world(FakeEngine::new());
        let refused = |messages: &[ClientMessage]| {
            let mut client = Client::connect(&world.sock);
            for message in messages {
                client.send(message);
            }
            client.rest().1
        };
        let error = |kind: &str, text: &str| vec![ServerMessage::Event(Event::Error { kind: kind.into(), text: text.into() })];
        assert_eq!(
            refused(&[ClientMessage::Hello { client: ClientKind::Connect, version: 2, client_info: None }]),
            error(kinds::PROTOCOL, "This sshelter speaks protocol 2 and the SSHelter that is running speaks 1. Quit SSHelter and open it again.")
        );
        assert_eq!(refused(&[ClientMessage::Hello { client: ClientKind::Mcp, version: PROTOCOL_VERSION, client_info: None }]), error(kinds::UNSUPPORTED, "The MCP adapter cannot use SSHelter's sessions yet."));
        assert_eq!(
            refused(&[ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }, ClientMessage::Exec {}]),
            error(kinds::UNSUPPORTED, "Running a command through SSHelter's sessions is not supported yet.")
        );
        assert_eq!(refused(&[ClientMessage::Close]), error(kinds::PROTOCOL, "The first message must be hello."));
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    #[test]
    fn a_session_is_listed_while_it_runs() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        let sessions = world.broker.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!((sessions[0].id, sessions[0].alias.as_str(), sessions[0].host_id.as_str()), (1, "web", "id-web"));
        assert!(world.broker.has_sessions());
        remote(&world).end(Exit::Code(0));
        client.rest();
        crate::ssh::testing::eventually("the session to be forgotten", 5, || !world.broker.has_sessions());
    }

    /// The terminal was closed: the broker sees the end of the connection and closes the session (spec §7.2).
    #[test]
    fn when_the_client_goes_away_its_session_is_closed() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        remote(&world).print(b"$ ");
        drop(client);
        crate::ssh::testing::eventually("the session to be closed", 10, || world.engine.events().contains(&FakeEvent::Closed));
        assert_eq!(world.engine.events().iter().filter(|event| **event == FakeEvent::ShellClosed).count(), 1, "the shell is closed once");
        crate::ssh::testing::eventually("and forgotten", 5, || !world.broker.has_sessions());
    }

    /// The client left while the window asked about the host key: the question is withdrawn and nothing more is connected.
    #[test]
    fn the_window_stops_waiting_when_the_client_goes_away() {
        let confirmer = Arc::new(WaitingConfirmer::default());
        let world = world_with(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password), Arc::clone(&confirmer) as Arc<dyn HostKeyConfirmer>, MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(_) = client.next_message() else { panic!("expected the password question") };
        // The password is asked first (the hop starts with it); the host key comes next.
        drop(client);
        crate::ssh::testing::eventually("the connect to give up", 10, || !world.broker.has_sessions() && *locked(&confirmer.asked) <= 1);
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    /// The IPC server gives every connection a read timeout (an agent connection that idles is dropped); a session must not inherit it.
    #[test]
    fn an_idle_session_is_not_ended_by_a_read_timeout() {
        let world = world(FakeEngine::new());
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        theirs.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let broker = Arc::clone(&world.broker);
        std::thread::spawn(move || broker.serve(theirs, None));
        write_control(&mut ours, &ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }).unwrap();
        write_control(&mut ours, &ClientMessage::OpenShell { host: HostQuery::Alias("web".into()), pty: PtyRequest { cols: 80, rows: 24, term: "dumb".into() } }).unwrap();
        let mut client = Client { stream: ours };
        client.stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        std::thread::sleep(Duration::from_millis(800));
        client.stream.write_all(&[0, 0, 0, 3, crate::session::protocol::DATA, b'o', b'k']).unwrap();
        crate::ssh::testing::eventually("input after the idle time to reach the shell", 5, || world.engine.events().contains(&FakeEvent::ShellInput(b"ok".to_vec())));
        assert!(world.broker.has_sessions());
    }

    /// Spec §4: quitting the app ends every session; each client is told why.
    #[test]
    fn quitting_ends_every_session_and_tells_each_client_why() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        remote(&world).print(b"$ ");
        let started = Instant::now();
        world.broker.end_all(Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(!world.broker.has_sessions());
        assert_eq!(client.rest().1, [ServerMessage::Event(Event::Disconnected { reason: "SSHelter quit, so the connection to web was closed.".into() }), no_status()]);
    }

    /// The whole way with the real engine: a client asks the broker for a shell on a scratch OpenSSH, the host key is confirmed in the
    /// (scripted) window and pinned, the shell runs a command, and its exit status comes back.
    #[test]
    fn a_real_shell_on_a_scratch_sshd_through_the_socket() {
        let Some(tools) = crate::ssh::testing::harness::tools() else { return };
        let server = crate::ssh::testing::fixture::Server::start(&tools, &["ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi"]);
        let directory = Arc::new(FakeDirectory::new().with_hop(server.hop_with("lab", server.sshd.port, AuthMethod::Key { key_id: "k1".into() })));
        let broker = Broker::new(
            Arc::new(crate::ssh::russh_engine::RusshEngine::new()),
            Arc::clone(&directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new().with_key("k1", "lab key", &server.key.private_text)),
            Arc::new(MemKeychain::default()),
            Arc::new(FakeConfirmer::deciding(vec![Decision::Trust])),
        );
        let dir = tempfile::Builder::new().prefix("sb").tempdir_in("/tmp").unwrap();
        crate::ipc::server::listen_unix(&dir.path().join("ipc"), broker.handler()).unwrap();
        let mut client = Client::connect(&dir.path().join("ipc").join("sock"));
        client.open("lab");
        assert!(matches!(client.next_message(), ServerMessage::Question(Question { kind: QuestionKind::HostKeyNotice, .. })));
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        assert_eq!(directory.pins().get(&HostId::from("host-lab")).map(|pin| pin.key.clone()), Some(server.host_key()), "the key the server presented is pinned");

        let mut seen = Vec::new();
        let mut read_until = |client: &mut Client, needle: &str| {
            while !String::from_utf8_lossy(&seen).contains(needle) {
                match client.next() {
                    Some(Got::Data(bytes)) => seen.extend(bytes),
                    other => panic!("waiting for {needle:?}, got {other:?} after {:?}", String::from_utf8_lossy(&seen)),
                }
            }
        };
        read_until(&mut client, "$ ");
        client.type_text("echo SSHELTER_$((6*7))\r");
        read_until(&mut client, "SSHELTER_42");
        client.type_text("exit 7\r");
        assert_eq!(client.rest().1, [ServerMessage::Exited { code: Some(7), signal: None }]);
        crate::ssh::testing::eventually("the session to be forgotten", 10, || !broker.has_sessions());
    }

    #[test]
    fn the_requester_chain_leaves_out_sshelters_own_executable() {
        let process = |pid: u32, path: &str| ProcInfo { pid, ppid: pid + 1, path: Some(path.into()), argv: vec![path.into()] };
        let own = Path::new("/Applications/SSHelter.app/Contents/MacOS/sshelter");
        let chain = vec![process(10, "/Applications/SSHelter.app/Contents/MacOS/sshelter"), process(11, "/bin/zsh"), process(12, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")];
        let kept = without_own_executable(chain, Some(own));
        assert_eq!(kept.iter().map(|process| process.pid).collect::<Vec<_>>(), [11, 12]);
        assert_eq!(without_own_executable(vec![process(10, "/usr/bin/ssh")], None).len(), 1, "nothing to leave out when the own path is unknown");
    }
}
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -3,6 +3,7 @@
 //! terminal. Every SSH call it makes blocks, so it runs on plain threads, never in async code and never on the UI thread.
 
 pub mod auth;
+pub mod broker;
 pub mod connect;
 pub mod directory;
 pub mod pins;
```

`src-tauri/src/session/testing.rs`: apply this patch

```diff
--- a/src-tauri/src/session/testing.rs
+++ b/src-tauri/src/session/testing.rs
@@ -24,6 +24,14 @@ pub struct FakeKeys {
 }
 
 impl FakeKeys {
+    /// The vault also holds `private_text` (an OpenSSH private key without a passphrase) as `key_id`, named `name`.
+    pub fn with_key(mut self, key_id: &str, name: &str, private_text: &str) -> FakeKeys {
+        let material = crate::vault::material::open(private_text, None).expect("the vault opens the key");
+        let public_key = ssh_key::PublicKey::new(material.key_data(), "").to_openssh().expect("an OpenSSH public key");
+        self.keys.insert(key_id.to_string(), (VaultKey { name: name.into(), public_key, has_passphrase: false }, private_text.to_string()));
+        self
+    }
+
     pub fn new() -> FakeKeys {
         let mut keys = HashMap::new();
         keys.insert(
@@ -142,6 +150,12 @@ impl FakeDirectory {
         self
     }
 
+    /// A saved host exactly as `hop` says (a scratch server's address, port and user), reached directly.
+    pub fn with_hop(mut self, hop: Hop) -> FakeDirectory {
+        self.hosts.push(FakeHost { hop, jumps: Vec::new() });
+        self
+    }
+
     /// A second saved host called `alias`, with the id `id-<alias>-2`: the alias alone no longer says which.
     pub fn with_second_host_called(mut self, alias: &str) -> FakeDirectory {
         let hop = Hop::new(&format!("id-{alias}-2"), alias, &format!("{alias}-2.example.com"), 22, "deploy", AuthMethod::Password);
@@ -267,6 +281,29 @@ impl HostKeyConfirmer for FakeConfirmer {
     }
 }
 
+/// A host key window nobody answers: it waits until the question is withdrawn (the client went away) or 10 s pass, and records
+/// whether it saw the withdrawal.
+#[derive(Default)]
+pub struct WaitingConfirmer {
+    pub asked: Mutex<usize>,
+    pub withdrawn: Mutex<bool>,
+}
+
+impl HostKeyConfirmer for WaitingConfirmer {
+    fn confirm(&self, _question: &HostKeyQuestion, cancel: &CancelToken) -> Option<String> {
+        *locked(&self.asked) += 1;
+        let deadline = Instant::now() + std::time::Duration::from_secs(10);
+        while Instant::now() < deadline {
+            if cancel.is_cancelled() {
+                *locked(&self.withdrawn) = true;
+                return None;
+            }
+            std::thread::sleep(std::time::Duration::from_millis(10));
+        }
+        None
+    }
+}
+
 /// What every `HostDirectory` must do with pins, for a host `host` that has none yet: pin once (again is fine, another key is refused),
 /// and replace only from the key that is pinned. The resolved hop carries the pin.
 pub fn check_the_pin_contract(directory: &dyn HostDirectory, query: &HostQuery, first: &HostKey, second: &HostKey, third: &HostKey) {
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::broker::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find type `ServerMessage` in this scope
error: could not compile `sshelter` (lib test) due to 110 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/session/broker.rs`: insert above the `#[cfg(all(test, unix))]` line

```rust
//! The session broker (own-ssh spec §4, §7.2): it serves the clients that connect to the local IPC socket, one session per connection.
//! A connection says `hello`, asks for a shell (`open_shell`), and owns the session from then on: what the login needs is asked of it,
//! its keystrokes and resizes go to the shell, and when it goes away the session is closed. The connection's own thread reads it; a
//! second thread connects and pumps the shell. No read timeout applies once `hello` has arrived: an idle shell stays open for as long as
//! its terminal does.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::auth::{KeyStore, Owner, Reply};
use super::connect::{CancelToken, Connector, HostKeyConfirmer, CANCELLED};
use super::directory::HostDirectory;
use super::protocol::{decode, kinds, read_frame, write_control, write_data, ClientKind, ClientMessage, Event, Frame, HostQuery, Question, QuestionKind, ServerMessage, PROTOCOL_VERSION};
use super::relay::{run_shell, ClientLink, ShellControl};
use crate::ipc::peer::{self, ProcInfo};
use crate::ipc::server::{Handler, Stream};
use crate::ssh::{HostId, Pty, SshEngine};
use crate::sync::env::Keychain;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How long a new connection may take to say `hello`.
const HELLO_WAIT: Duration = Duration::from_secs(10);

/// The sentence a client is told when the app quits under its session (spec §4).
pub fn quit_reason(alias: &str) -> String {
    format!("SSHelter quit, so the connection to {alias} was closed.")
}

/// A session that is open: for the app (keep running while there are some, end them when quitting) and, in a later version, for the
/// list of sessions (spec §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: u64,
    pub alias: String,
    pub host_id: HostId,
    /// Who asked for it: the process chain of the client, outermost first, without SSHelter's own executable (spec §7.2); `None` when it
    /// could not be told. Recorded now, shown from phase 2 on.
    pub requested_by: Option<Vec<String>>,
    pub started_at_ms: u64,
}

struct Entry {
    info: SessionInfo,
    control: Arc<ShellControl>,
}

/// The broker. One per app; its handler serves the IPC socket.
pub struct Broker {
    engine: Arc<dyn SshEngine>,
    directory: Arc<dyn HostDirectory>,
    keys: Arc<dyn KeyStore>,
    keychain: Arc<dyn Keychain>,
    confirmer: Arc<dyn HostKeyConfirmer>,
    sessions: Mutex<BTreeMap<u64, Entry>>,
    /// Notified whenever a session leaves `sessions` (`end_all` waits on it).
    changed: Condvar,
    next_id: AtomicU64,
}

impl Broker {
    pub fn new(
        engine: Arc<dyn SshEngine>,
        directory: Arc<dyn HostDirectory>,
        keys: Arc<dyn KeyStore>,
        keychain: Arc<dyn Keychain>,
        confirmer: Arc<dyn HostKeyConfirmer>,
    ) -> Arc<Broker> {
        Arc::new(Broker { engine, directory, keys, keychain, confirmer, sessions: Mutex::new(BTreeMap::new()), changed: Condvar::new(), next_id: AtomicU64::new(0) })
    }

    /// The IPC server's handler: each connection is served on the thread the server gives it.
    pub fn handler(self: &Arc<Broker>) -> Handler {
        let broker = Arc::clone(self);
        Arc::new(move |stream, pid| broker.serve(stream, pid))
    }

    /// The sessions that are open now, oldest first.
    pub fn sessions(&self) -> Vec<SessionInfo> {
        locked(&self.sessions).values().map(|entry| entry.info.clone()).collect()
    }

    pub fn has_sessions(&self) -> bool {
        !locked(&self.sessions).is_empty()
    }

    /// The app is quitting (spec §4): every session ends, its client told why. Waits up to `wait` for them to close (each closes its own
    /// shell and connection on its own thread).
    pub fn end_all(&self, wait: Duration) {
        let entries: Vec<(String, Arc<ShellControl>)> = locked(&self.sessions).values().map(|entry| (entry.info.alias.clone(), Arc::clone(&entry.control))).collect();
        for (alias, control) in entries {
            std::thread::spawn(move || control.end(&quit_reason(&alias)));
        }
        let deadline = Instant::now() + wait;
        let mut sessions = locked(&self.sessions);
        while !sessions.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            sessions = self.changed.wait_timeout(sessions, left).unwrap_or_else(PoisonError::into_inner).0;
        }
    }

    /// Serves one client connection until it ends (the thread the IPC server gives it).
    pub fn serve(self: &Arc<Broker>, stream: Stream, pid: Option<u32>) {
        let Ok(writer) = stream.try_clone() else { return };
        let link = Arc::new(FrameLink { writer: Mutex::new(writer) });
        let mut reader = stream;
        let refuse = |kind: &str, text: &str| {
            let _ = link.send(&ServerMessage::Event(Event::Error { kind: kind.to_string(), text: text.to_string() }));
        };
        // `hello` first, within a short time; from then on no read timeout (an idle shell is not a dead client).
        let _ = set_read_timeout(&reader, Some(HELLO_WAIT));
        match next_message(&mut reader) {
            Some(ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, .. }) => {}
            Some(ClientMessage::Hello { client: ClientKind::Mcp, .. }) => return refuse(kinds::UNSUPPORTED, "The MCP adapter cannot use SSHelter's sessions yet."),
            Some(ClientMessage::Hello { version, .. }) => {
                return refuse(
                    kinds::PROTOCOL,
                    &format!("This sshelter speaks protocol {version} and the SSHelter that is running speaks {PROTOCOL_VERSION}. Quit SSHelter and open it again."),
                )
            }
            Some(_) => return refuse(kinds::PROTOCOL, "The first message must be hello."),
            None => return,
        }
        let _ = set_read_timeout(&reader, None);
        let requested_by = requester_of(pid);
        let (host, pty) = match next_message(&mut reader) {
            Some(ClientMessage::OpenShell { host, pty }) => (host, pty),
            Some(ClientMessage::Exec {}) => return refuse(kinds::UNSUPPORTED, "Running a command through SSHelter's sessions is not supported yet."),
            Some(_) => return refuse(kinds::PROTOCOL, "SSHelter expected open_shell."),
            None => return,
        };
        let owner = Arc::new(ConnectionOwner { link: Arc::clone(&link), questions: Mutex::new(HashMap::new()), next_question: AtomicU64::new(0) });
        let control = Arc::new(ShellControl::new());
        let cancel = CancelToken::default();
        control.resize(pty.cols, pty.rows);
        let Ok(closer) = reader.try_clone() else { return };
        let worker = {
            let (broker, owner, control, cancel, link) = (Arc::clone(self), Arc::clone(&owner), Arc::clone(&control), cancel.clone(), Arc::clone(&link));
            let pty = Pty { term: pty.term, cols: pty.cols, rows: pty.rows };
            let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
            std::thread::Builder::new().name("sshelter-session".to_string()).spawn(move || {
                broker.run_session(id, &host, pty, owner.as_ref(), link.as_ref(), &control, &cancel, requested_by);
                // The session is over: the connection is closed, which ends the reader below and tells the client.
                hang_up(&closer);
            })
        };
        let Ok(worker) = worker else { return refuse(kinds::CONNECT, "SSHelter could not start the session.") };
        // The client's messages, until it closes or goes away.
        loop {
            match read_frame(&mut reader) {
                Ok(Some(Frame::Data(bytes))) => control.input(&bytes, link.as_ref()),
                Ok(Some(Frame::Control(payload))) => match decode::<ClientMessage>(&payload) {
                    Ok(ClientMessage::WindowChange { cols, rows }) => control.resize(cols, rows),
                    Ok(ClientMessage::Answer { question_id, value, cancel }) => owner.answer(&question_id, value, cancel),
                    Ok(ClientMessage::Close) => break,
                    Ok(_) | Err(_) => refuse(kinds::PROTOCOL, "SSHelter did not expect that message."),
                },
                Ok(None) | Err(_) => break,
            }
        }
        // The owner is gone: whatever waits for it gives up, and the shell (once it has printed something) and the session are closed.
        cancel.cancel();
        owner.gone();
        control.owner_gone();
        let _ = worker.join();
    }

    /// The session thread: connects, then runs the shell. A failure is told to the client (unless it is gone) as an error and an exit
    /// without a status.
    #[allow(clippy::too_many_arguments)]
    fn run_session(
        &self,
        id: u64,
        host: &HostQuery,
        pty: Pty,
        owner: &dyn Owner,
        link: &dyn ClientLink,
        control: &Arc<ShellControl>,
        cancel: &CancelToken,
        requested_by: Option<Vec<String>>,
    ) {
        let connector = Connector {
            engine: self.engine.as_ref(),
            directory: self.directory.as_ref(),
            keys: self.keys.as_ref(),
            keychain: self.keychain.as_ref(),
            confirmer: self.confirmer.as_ref(),
        };
        let connected = match connector.connect(host, owner, cancel) {
            Ok(connected) => connected,
            Err(failure) => {
                if failure.kind != CANCELLED && !control.is_gone() {
                    let _ = link.send(&ServerMessage::Event(Event::Error { kind: failure.kind, text: failure.text }));
                    let _ = link.send(&ServerMessage::Exited { code: None, signal: None });
                }
                return;
            }
        };
        let Some(destination) = connected.target.hops.last() else { return };
        let started_at_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0);
        let info = SessionInfo { id, alias: destination.alias.clone(), host_id: destination.id.clone(), requested_by, started_at_ms };
        locked(&self.sessions).insert(id, Entry { info, control: Arc::clone(control) });
        run_shell(connected, pty, link, control, &id.to_string());
        locked(&self.sessions).remove(&id);
        self.changed.notify_all();
    }
}

/// `read_frame` and `decode` for the first messages; `None` for the end of the stream or anything that is not a control message.
fn next_message(reader: &mut Stream) -> Option<ClientMessage> {
    match read_frame(reader) {
        Ok(Some(Frame::Control(payload))) => decode(&payload).ok(),
        _ => None,
    }
}

#[cfg(unix)]
fn set_read_timeout(stream: &Stream, timeout: Option<Duration>) -> std::io::Result<()> {
    stream.set_read_timeout(timeout)
}

/// A Windows pipe has no read timeout.
#[cfg(windows)]
fn set_read_timeout(_stream: &Stream, _timeout: Option<Duration>) -> std::io::Result<()> {
    Ok(())
}

/// Closes the connection both ways: the client reads its end, and a read blocked on it returns.
#[cfg(unix)]
fn hang_up(stream: &Stream) {
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// The broker does not serve Windows clients in this version (plan 1b: `sshelter connect` is macOS and Linux); nothing to close.
#[cfg(windows)]
fn hang_up(_stream: &Stream) {}

/// The client's connection, as the relay writes to it: whole frames under one lock.
struct FrameLink {
    writer: Mutex<Stream>,
}

impl ClientLink for FrameLink {
    fn send(&self, message: &ServerMessage) -> std::io::Result<()> {
        write_control(&mut *locked(&self.writer), message)
    }

    fn send_data(&self, bytes: &[u8]) -> std::io::Result<()> {
        write_data(&mut *locked(&self.writer), bytes)
    }
}

/// The owner of a session: its client. A question goes out as a `question` frame; the connection's reader delivers the answer.
struct ConnectionOwner {
    link: Arc<FrameLink>,
    /// The questions waiting for an answer, by id. Emptied when the client is gone, which wakes every waiting `ask` with `Gone`.
    questions: Mutex<HashMap<String, SyncSender<Reply>>>,
    next_question: AtomicU64,
}

impl ConnectionOwner {
    fn question_id(&self) -> String {
        format!("q{}", self.next_question.fetch_add(1, Ordering::SeqCst) + 1)
    }

    /// The client's answer to `question_id` (a late or unknown one is dropped).
    fn answer(&self, question_id: &str, value: Option<String>, cancel: bool) {
        let Some(waiting) = locked(&self.questions).remove(question_id) else { return };
        let reply = match value {
            Some(value) if !cancel => Reply::Answer(Zeroizing::new(value)),
            _ => Reply::Cancelled,
        };
        let _ = waiting.try_send(reply);
    }

    fn gone(&self) {
        locked(&self.questions).clear();
    }
}

impl Owner for ConnectionOwner {
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        let question_id = self.question_id();
        let (answer, answered) = mpsc::sync_channel(1);
        locked(&self.questions).insert(question_id.clone(), answer);
        let deadline_ms = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()).as_millis() as u64);
        let question = Question { question_id: question_id.clone(), kind, text: text.to_string(), echo, deadline_ms };
        if self.link.send(&ServerMessage::Question(question)).is_err() {
            locked(&self.questions).remove(&question_id);
            return Reply::Gone;
        }
        let reply = match deadline {
            None => answered.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(deadline) => answered.recv_timeout(deadline.saturating_duration_since(Instant::now())),
        };
        match reply {
            Ok(reply) => reply,
            Err(RecvTimeoutError::Timeout) => {
                locked(&self.questions).remove(&question_id);
                Reply::TimedOut
            }
            Err(RecvTimeoutError::Disconnected) => Reply::Gone,
        }
    }

    fn host_key_notice(&self, text: &str) {
        let question = Question { question_id: self.question_id(), kind: QuestionKind::HostKeyNotice, text: text.to_string(), echo: false, deadline_ms: None };
        let _ = self.link.send(&ServerMessage::Question(question));
    }

    fn banner(&self, text: &str) {
        let _ = self.link.send(&ServerMessage::Event(Event::Banner { text: text.to_string() }));
    }
}

/// The process chain without SSHelter's own executable: `sshelter connect` is SSHelter, and the person's program is what started it.
pub fn without_own_executable(chain: Vec<ProcInfo>, own: Option<&Path>) -> Vec<ProcInfo> {
    let Some(own) = own else { return chain };
    chain.into_iter().filter(|process| process.path.as_deref().map(Path::new) != Some(own)).collect()
}

/// Who connected (spec §7.2): the peer's process chain, without SSHelter's own executable, named as `ipc::peer` names programs.
pub fn requester_of(pid: Option<u32>) -> Option<Vec<String>> {
    let own = std::env::current_exe().ok().map(|path| std::fs::canonicalize(&path).unwrap_or(path));
    let chain = without_own_executable(peer::process_chain(pid?), own.as_deref());
    peer::identify(&chain).map(|program| program.chain)
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::broker::)
```

Expected: PASS, `test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 1673 filtered out`. Then the leftover check prints 0, 0 and 0.

- [ ] **Step 5: Record the broker's rules in the spec, and run the new modules in CI**

`docs/superpowers/specs/2026-10-10-own-ssh-client-design.md`: apply this patch

```diff
--- a/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
+++ b/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
@@ -223,6 +223,7 @@ pub enum Exit { Code(u32), Signal(String), Refused(String), Disconnected } // Re
 ### 7.2 Broker 規則
 
 - 一個 session 一個擁有者(IPC 連線);連線斷掉就關 session;app 結束全部關。
+- (第 1b 期)一條 IPC 連線一個 session。`hello` 之後連線不受 IPC 伺服器的閒置逾時限制:閒置的 shell 照樣開著。開不成 session 時 broker 送 `event{error}` 再送 `exited{code: null, signal: null}`,然後關掉連線;`exec` 與 `hello{client: mcp}` 在第 1b 期回 `error{kind: unsupported}`。用戶端斷線時,broker 等 shell 第一次有輸出(或開啟滿 3 秒)才關 shell 與連線,免得 macOS 的 sshd 留下拿著 PTY 的程序。app 結束時每個 session 的用戶端都收到 `event{disconnected{reason}}`(`SSHelter quit, so the connection to {alias} was closed.`)與 `exited`。
 - 開 session 的核准:`client = connect`(終端機 CLI)不核准;`client = mcp` 依第 8 節。
 - 提示的去向(決策 7):擁有者是 `connect` → `question` 訊框送到 CLI,在終端機裡問;擁有者是 `mcp` 且模式 `ask` → app 視窗;`mcp` 且 `auto_log` → 回 `error{needs_interaction}`。主機金鑰的確認永遠在 app 視窗(決策 6),CLI 只收到 `host_key_notice`。
 - 每個 session 寫一筆 log(第 8.4 節的同一份 log,`client` 欄位區分 connect 與 mcp)。
```

`.github/workflows/test-engine.yml`: apply this patch

```diff
--- a/.github/workflows/test-engine.yml
+++ b/.github/workflows/test-engine.yml
@@ -1,6 +1,7 @@
-# Runs the tests of the SSH engine (src-tauri/src/ssh/) where they can run for real: against a scratch OpenSSH server on macOS and on
-# Linux, and on Linux also against a real OpenSSH with PAM in a container (the logins by password and by keyboard-interactive, which a
-# scratch sshd cannot check). The Windows leg lives in test-windows.yml.
+# Runs the tests of the SSH engine (src-tauri/src/ssh/) and of the session broker that uses it (src-tauri/src/session/, and starting
+# the app for its clients: host_start) where they can run for real: against a scratch OpenSSH server on macOS and on Linux, and on Linux
+# also against a real OpenSSH with PAM in a container (the logins by password and by keyboard-interactive, which a scratch sshd cannot
+# check). The Windows leg lives in test-windows.yml.
 #
 # aws-lc-sys (russh's crypto, the same crate rustls already pulls in for the updater) is built by its build script with the runner's C
 # compiler: clang on macOS, gcc on ubuntu-24.04. The release workflow already builds it on both through rustls, so nothing is installed
@@ -49,11 +50,11 @@ jobs:
           ls -l /usr/sbin/sshd
           ssh -V
       # SSHELTER_REQUIRE_OPENSSH=1: a missing sshd is a failure here, not a skipped test.
-      - name: Engine and vault tests
+      - name: Engine, broker and vault tests
         env:
           SSHELTER_REQUIRE_OPENSSH: "1"
         # Quoted: an unquoted `ssh::` is read as a YAML mapping and the workflow would not load.
-        run: "cargo test --locked --lib -- ssh:: vault::"
+        run: "cargo test --locked --lib -- ssh:: session:: host_start:: vault::"
 
   linux:
     # Not ubuntu-latest: the PAM image is ubuntu:24.04, and the package names below were checked against 24.04.
@@ -97,13 +98,13 @@ jobs:
           ssh-keyscan -T 2 -p 2222 127.0.0.1 > /dev/null
           echo "SSHELTER_PAM_PASSWORD=$password" >> "$GITHUB_ENV"
       # The pam tests are skipped here: the next step runs them against the container.
-      - name: Engine and vault tests against a scratch sshd
+      - name: Engine, broker and vault tests against a scratch sshd
         # Runs even when the container did not start, so that a first run shows both results.
         if: ${{ !cancelled() }}
         env:
           SSHELTER_REQUIRE_OPENSSH: "1"
         # Quoted: an unquoted `ssh::` is read as a YAML mapping and the workflow would not load.
-        run: "cargo test --locked --lib -- ssh:: vault:: --skip ssh::engine_tests::login_methods::pam"
+        run: "cargo test --locked --lib -- ssh:: session:: host_start:: vault:: --skip ssh::engine_tests::login_methods::pam"
       # Runs whatever the scratch sshd step came to, so that a first run shows both results.
       - name: Password and keyboard-interactive tests against the container
         if: ${{ !cancelled() }}
```

`.github/workflows/test-windows.yml`: apply this patch

```diff
--- a/.github/workflows/test-windows.yml
+++ b/.github/workflows/test-windows.yml
@@ -49,15 +49,15 @@ jobs:
           ssh -V
       # The platform-dependent tests: identity path parsing (slot_rules), the slot files, links and DACL (slot_files,
       # slot_files_windows), the key vault (vault::), the local IPC transport (ipc:: covers the named pipe and program identification),
-      # the SSH agent (agent:: covers the real ssh-add / ssh-keygen against the agent) and the SSH engine (`ssh::`: the tests that need
-      # no sshd of their own; the scratch-sshd ones print "skipped" on Windows). The rest of the suite runs on macOS; parts of it use the
-      # system keychain.
-      - name: Key slot, vault, agent and engine tests
+      # the SSH agent (agent:: covers the real ssh-add / ssh-keygen against the agent), the SSH engine (`ssh::`: the tests that need
+      # no sshd of their own; the scratch-sshd ones print "skipped" on Windows) and the session broker's platform-neutral parts
+      # (`session::`; its socket tests are Unix only). The rest of the suite runs on macOS; parts of it use the system keychain.
+      - name: Key slot, vault, agent, engine and broker tests
         env:
           SSHELTER_REQUIRE_OPENSSH: "1"
         # Quoted: an unquoted `vault:: ipc:: agent::` is read as a YAML mapping and the workflow would not load.
         # --locked: the committed Cargo.lock, with russh in it, is what is built.
-        run: "cargo test --locked --lib -- sync::slot_rules sync::slot_files vault:: ipc:: agent:: ssh::"
+        run: "cargo test --locked --lib -- sync::slot_rules sync::slot_files vault:: ipc:: agent:: ssh:: session::"
       # The library and the binary in a debug build, with russh in the dependency graph (the release workflow builds the same graph).
       - name: Build the whole app
         run: cargo build --locked
```

```bash
actionlint .github/workflows/test-engine.yml .github/workflows/test-windows.yml
```

Expected: no output, exit code 0 (actionlint 1.7.12 here). Then run what the macOS job runs:

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh:: session:: host_start:: vault::)
```

Expected: `test result: ok. 345 passed; 0 failed; 0 ignored; 0 measured; 1341 filtered out` (the leftover check prints 0, 0 and 0 after it).

- [ ] **Step 6: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1684 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 7: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add .github/workflows/test-engine.yml \
  .github/workflows/test-windows.yml \
  docs/superpowers/specs/2026-10-10-own-ssh-client-design.md \
  src-tauri/src/session/broker.rs \
  src-tauri/src/session/mod.rs \
  src-tauri/src/session/testing.rs
git commit -m "feat(session): serve sessions to clients over the local IPC socket"
```

Expected: `git status --short` lists the six files of this task; the `git diff --stat` prints nothing.

---

## Coverage of the spec

Every test named here exists in the final tree (the names were taken from `cargo test -- --list` at the last commit of plan 1b). Spec items that the tests do not reach are listed after the table; what plan 1b-2 covers is in its own table.

| Spec item | Task | Tests |
|---|---|---|
| §6.3 a bounded output queue whose memory follows the bytes (R19); the gap announced (R20) | 1 | `small_chunks_are_merged_so_their_count_follows_the_bytes_and_not_the_pushes`, `a_chunk_is_not_merged_into_one_it_would_grow_past_the_merge_limit_and_a_big_chunk_stays_whole`, `a_reader_that_catches_up_after_a_gap_is_told_about_it_at_once` |
| §6.1 as changed by 1b: `AuthFailed::password_wanted` (R16), `AuthSource::banner`, `Exit::Refused` (R20) | 2 | `a_refused_key_with_no_password_to_give_says_a_password_is_wanted`, `a_password_that_was_tried_is_not_reported_as_wanted`, `a_server_without_the_password_method_never_wants_a_password`, `the_servers_banner_reaches_the_auth_source`, `a_refused_terminal_ends_the_shell_with_the_reason_and_the_connection_stays_up`, `a_wanted_password_does_not_change_the_sentence`, `a_scripted_banner_is_handed_to_the_auth_source_of_each_hop` |
| §12 `FakeEngine` behaves like the real engine where the broker relies on it (R18) | 3, 9 | `ssh::parity_tests::` — `the_password_of_a_password_first_hop_is_asked_for_before_its_host_key`, `a_missing_password_goes_on_to_keyboard_interactive`, `a_refused_key_with_no_password_to_give_says_a_password_is_wanted`, `a_keyboard_interactive_prompt_gets_at_least_a_minute`, `a_cancelled_prompt_abandons_the_login`, `an_answer_after_the_deadline_abandons_the_login`, `an_unreachable_password_first_hop_was_asked_for_its_password_first`, `a_shell_we_close_ends_as_disconnected_and_still_takes_input`, `input_fails_with_closed_once_the_session_is_closed`, `a_cut_link_ends_the_shells_and_the_session_says_the_connection_was_lost`, `a_pin_of_another_key_type_finds_no_common_algorithm` |
| §7.1 frames and messages; secrets out of logs and errors | 4 | `a_frame_is_a_big_endian_length_that_counts_the_type_byte_then_the_type_then_the_payload`, `frames_come_back_in_order_and_a_clean_end_between_frames_is_none`, `a_frame_over_the_limit_is_refused_from_its_header_and_never_written`, `a_stream_that_ends_inside_a_frame_is_truncated_and_odd_frames_are_errors`, `client_messages_read_and_write_as_the_spec_names_them`, `server_messages_read_and_write_as_the_spec_names_them`, `an_answer_keeps_its_value_out_of_debug_output_and_error_text` |
| §4 a client starts the app with `--host` under the spawn locks (R6); the old flag still works | 5 | `the_host_flag_is_the_new_one_and_the_old_one_is_still_accepted`, `a_client_starts_the_host_with_the_new_flag_and_its_window_hidden`, `parallel_calls_start_sshelter_once`, `no_answer_after_the_start_says_what_to_do`, `tests::a_second_host_launch_shows_no_window_with_the_new_flag_or_the_old_one` |
| §6.2 step 1 and §7.1: a host by alias or id, jump hosts first, loops and missing hosts refused, an alias two hosts share | 6, 7, 9 | `the_fake_directory_resolves_by_alias_or_id_with_the_jump_hosts_first_and_says_when_an_alias_is_not_enough`, `a_saved_host_resolves_with_its_jump_hosts_first_and_the_jump_users_and_ports_applied`, `a_proxy_jump_list_is_read_in_order_with_its_users_and_ports`, `what_sshelter_cannot_connect_to_is_refused_with_the_reason`, `the_real_ssh_g_output_resolves_into_the_same_hops`, `a_saved_host_that_cannot_be_found_or_named_by_its_alias_alone_is_a_host_error` |
| §5.1 the pinned key (in 1b's pin file), never lost to an unreadable file; §1 never `known_hosts` | 6, 7 | `a_pin_is_written_to_the_file_and_read_back_with_the_time_it_was_made`, `pinning_the_pinned_key_again_is_fine_and_another_key_is_refused`, `a_changed_key_replaces_the_pin_only_while_the_old_one_is_still_pinned`, `an_unreadable_or_newer_file_is_an_error_and_is_never_overwritten`, `pins_belong_to_one_host_id_each`, `the_fake_directory_keeps_the_pin_contract`, `a_pin_from_the_pin_file_is_in_the_resolved_hop_and_an_unreadable_file_stops_the_connection` |
| §5.1 timeouts and keepalive defaults; a host without a key; key files the client cannot use | 7 | `a_hop_takes_its_address_user_and_timeouts_from_ssh_g_and_the_spec_defaults_otherwise`, `a_host_without_a_key_or_a_saved_password_starts_with_keyboard_interactive_and_a_key_file_is_refused`, `the_first_identity_file_on_a_vault_slot_names_the_key` |
| §6.1 the broker's policy and auth source: passphrases before connecting, the keychain, prompts with deadlines, banners without control characters | 8 | every test in `session::auth::` (11), e.g. `a_passphrase_is_asked_before_the_connection_and_again_after_a_wrong_one`, `a_cancelled_passphrase_or_three_wrong_ones_abandon_the_connect_with_the_spec_sentence`, `a_fallback_password_never_asks_a_person`, `keyboard_interactive_prompts_are_asked_one_by_one_with_their_echo_and_the_engines_deadline`, `a_banner_reaches_the_owner_without_control_characters` |
| §6.2 step 3, §10, §14: confirm, pin, reconnect; a changed key; another key type (R17) | 9 | `an_unknown_host_key_is_confirmed_in_the_window_then_pinned_and_the_broker_connects_again`, `an_unknown_host_key_the_person_does_not_trust_ends_the_connect_and_pins_nothing`, `an_answer_for_another_fingerprint_pins_nothing`, `a_changed_host_key_shows_the_pinned_one_and_replaces_it_only_when_accepted`, `a_host_whose_key_is_pinned_connects_without_a_question`, `a_pinned_host_that_now_has_another_key_type_gets_the_changed_key_warning_not_an_algorithm_error` |
| §6.2 step 4, R8, R16: the password asked once on first contact, again after a refusal (three times), never while connected; a cancel abandons | 9 | `the_first_contact_with_a_password_host_asks_for_the_password_once`, `a_password_wanted_after_a_refused_key_is_asked_for_and_the_broker_connects_again_with_the_password_first`, `a_refused_password_is_asked_for_again_up_to_three_times`, `a_saved_password_that_is_refused_is_asked_for`, `a_cancelled_password_question_abandons_the_connect`, `a_passphrase_is_asked_for_before_anything_connects`, `when_the_owner_goes_away_the_broker_stops_without_connecting_again` |
| §11 a jump host's failure is said through it | 9 | `a_failure_on_a_jump_host_names_the_jump_host` |
| §7.2 the last window size, sent again once the shell is ready | 10 | `a_shell_opens_at_the_last_size_sends_it_again_and_relays_output_until_it_exits` |
| §7.1 `exited` never 0 for a disconnect (R9); §11 the lost-connection sentences with `{n}` | 10 | `a_lost_connection_is_reported_with_its_reason_and_no_exit_status`, `a_link_that_stopped_answering_keepalives_says_for_how_long`, `a_shell_killed_by_a_signal_says_which`, `a_refused_terminal_or_a_shell_that_cannot_open_is_an_error_with_the_reason` |
| R9 a write that times out is not a dead connection | 10 | `keystrokes_and_resizes_reach_the_shell_and_input_that_times_out_is_reported_without_ending_it` |
| R22 the shell closed after its first output or 3 s | 10 | `when_the_client_goes_away_the_shell_is_closed_after_its_first_output_and_nothing_more_is_sent`, `a_shell_that_never_prints_is_closed_once_the_settle_time_has_passed` |
| §7.2 one owner per session; the client gone closes it; no idle timeout (R5) | 11 | `when_the_client_goes_away_its_session_is_closed`, `an_idle_session_is_not_ended_by_a_read_timeout`, `the_window_stops_waiting_when_the_client_goes_away` |
| §7.2 questions to the client, the host key notice | 11 | `a_password_the_login_wants_is_asked_of_the_client_and_its_answer_gets_in`, `a_cancelled_question_ends_the_connect_with_an_error_and_no_exit_status`, `the_client_is_told_to_look_at_the_window_while_the_host_key_is_confirmed_there` |
| R5, R15 `exec`, MCP clients and other versions refused | 11 | `another_protocol_version_exec_and_the_mcp_client_are_refused_by_name` |
| §7.2 the requester recorded; §4 the session table; §4 quitting ends every session with a reason | 10, 11 | `the_requester_chain_leaves_out_sshelters_own_executable`, `a_session_is_listed_while_it_runs`, `quitting_ends_every_session_and_tells_each_client_why`, `quitting_the_app_ends_the_shell_and_tells_the_client_why` |
| §12 the broker over a socket, on the fake and on the real engine against a scratch sshd | 11 | `a_client_opens_a_shell_over_the_socket_types_into_it_and_gets_its_exit_status`, `a_host_that_cannot_be_connected_is_an_error_then_an_exit_without_a_status`, `a_real_shell_on_a_scratch_sshd_through_the_socket` |

Not covered by a test in this plan, on purpose or for lack of a way:

- `sshelter connect`, the host-key window, the broker in the app, the Connect button: plan 1b-2.
- A client that connects and never says `hello`: `serve` waits 10 s for it (`HELLO_WAIT`); a test would have to wait that long, so the bound is written and not exercised.
- The connect loop's bound of 12 rounds (`SSHelter gave up connecting to {alias}: …`): written, not exercised (no scripted server keeps changing its answer).
- More than 64 sessions at once: phase 0's `MAX_CONNECTIONS` of the IPC server, tested there.
- A server's `DISCONNECT` during the handshake (R20, item 11): not changed; see decision 3.
- The temporary directory against a real user's ssh_config (`Include`, `Match`, tokens): only through `ssh -G` in the app (plan 1b-2), on the user's machine.
- Windows: the broker's code compiles there behind `cfg`, but nothing here builds for Windows; the first CI run is the check.

---

## Decisions to confirm

These are the choices this plan makes where the spec, the rulings or the code left room. None of them is a challenge to a ruling: every ruling could be built as written. Each can be reversed by changing the named task.

1. **Plan 1b is two plans (1b-1, 1b-2).** Eighteen commits did not fit the 10 to 14 tasks of one plan. This one ends with the broker serving real shells on a socket in tests; 1b-2 adds the CLI, the window, the app wiring and the Connect button, and ends with `sshelter connect` running against a scratch sshd.
2. **R16 is one field, `AuthFailed::password_wanted: bool` (Task 2),** not a `skipped`/`offered` list: the broker needs exactly one yes or no, `tried` keeps its meaning, and the sentence of §11 does not change. Recorded in spec §6.1.
3. **R20, decided as follows (Tasks 1 and 2).** The gap notice goes out as soon as the reader has caught up. A refused PTY or shell is a new variant, `Exit::Refused(String)`, rather than a reason inside `Exit::Disconnected` (the connection is up, and the broker says so differently). Banners reach the broker through a default method, `AuthSource::banner`, and the client through `event{banner}`, with control characters replaced. A server's `DISCONNECT` during the handshake (item 11) is left as plan 1a reports it: OpenSSH rarely sends one there, and the change would touch the handshake error path for little.
4. **Protocol details beyond spec §7.1 (Task 4, recorded in §7.1):** big-endian length counting the type byte, types 1 and 2, 1 MiB frames; `hello.version`; `host` as `{"alias": …}` or `{"id": …}`; `deadline_ms` relative to sending, `null` for the host key notice; `answer` with `value` or `cancel`; `event{banner}`. And beyond §7.2 (Task 11, recorded in §7.2): one session per connection; a failed open is `error` then `exited{null, null}`; `exec` and MCP clients refused as `unsupported`.
5. **The temporary directory (Task 7).** A host without a key starts with keyboard-interactive when no password is saved (the broker asks for a password only when the server wants one, so a PAM server is not asked twice); a key that lives in a file is refused with a sentence that says to put it in SSHelter (the engine signs only with vault keys); `ProxyCommand` is refused; the keepalive default is SSHelter's 30 s when the host sets no `ServerAliveInterval` (OpenSSH's own default is off).
6. **The pin file (Task 6):** `<app data>/host-pins.json`, read fail-closed (an unreadable or newer file stops the connection and is never overwritten), until plan 1c moves pins into the host records.
7. **A typed password lives for one connect (Tasks 8, 9):** given again on the reconnects of that connect, dropped with it; at most three per hop; a saved password that the server refuses stays saved and is not offered to be replaced; a password question waits 4 × the hop's connect timeout, at least 60 s, like keyboard-interactive (plan 1a's review asked for a deadline to be picked).
8. **A host key is pinned only when the window's answer names the fingerprint the engine observed (Task 9),** so a stale answer from a window that showed another key pins nothing.
9. **The settle time of R22 is 3 s (Task 10).**
10. **The requester's process chain is recorded on the session and not shown (Task 11);** the session list and approvals that would show it are phase 2.
11. **`mcp-spawn.lock` keeps its name (Task 5),** so a 0.17 MCP adapter and a newer client on the same computer still take the same lock; `--mcp-host` stays accepted next to `--host`.
12. **`pub mod session` for the length of this plan (Task 4),** like plan 1a's `pub mod ssh`; plan 1b-2's last task makes both private (R21).
13. **The fake engine's login API changed (Task 3):** `FakeLogin::{Refuse, Signature, Password, Interactive}` became `FakeLogin::Server(FakeMethods)`. Nothing outside `ssh/` used the old variants.
14. **Comments in `session/` are English (Global Constraints),** as in `ssh/`.

## What is left for the user after the last commit

- Nothing a user sees has changed yet: the app does not start the broker until plan 1b-2.
- Push the branch (with plan 1b-2) and read the first CI runs: `test-engine.yml` now runs `session::` and `host_start::` on macOS and Linux (the Linux scratch sshd is the first non-macOS run of the broker's end-to-end test), and `test-windows.yml` runs `session::` (the first Windows build of `session/`).
- The decisions above.
