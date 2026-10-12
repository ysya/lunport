> **Status (2026-10-13), added by the controller.** F1–F11 below were fixed on `next/own-ssh` in 5860056..ed37ab3, together with two
> items from the CLI loop's last re-review: F12 (a signal ends the wait for a slow terminal at an end the session came to, with 128 + the
> signal's number; 805c5ce) and F13 (the spec note and the run.rs doc say so; ed37ab3). The scoped re-review of that wave found every
> item addressed and nothing new of Critical or Important weight. Its three Minor residuals were settled by the controller: the F12
> test's ordering race is fixed (it waits for the terminal's first pieces too); the host editor's password note no longer says "until
> the next phase"; and the host key window's re-fetch after a rejected answer, which an event in flight can overwrite, goes to plan 1d
> (documented at `pendingFeed` in `src/lib/hostkey.ts`). The per-connection IPC thread is still named `sshelter-agent-connection` though
> it serves the broker too (cosmetic). The "Hand-off" and "Manual checks for the user" sections below are still open.

# Final review fix list — plan 1b (a764792..66b596e)

Verdict: **Ready with fixes.** Critical 0 · Important 1 · Minor 10 (F1–F11). The whole-branch review read the session, cli and
host_start modules and the hostkey window at HEAD in full, the engine/app/frontend hunks of the package, both ledgers, the spec, the
design brief and plan 1a's fix list; it ran `session:: cli:: host_start::` in a scratch worktree (328 passed, leftovers 0) and one scratch
test that proves F1 (red at 66b596e). The scoped re-review of 2546cce..66b596e (the CLI loop's last fix round) was not redone; nothing
below re-opens its items.

One fix wave, one implementer, in the order below (F1 first; then the test/doc items in any order). Base: `66b596e` on `next/own-ssh`
(small fixes that landed after it are to be merged with, not reverted). Every Global Constraint holds: `--offline --locked`, no change to
`src-tauri/Cargo.toml` / `Cargo.lock` (`git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock` empty at the end), russh named only
in `ssh/russh_engine.rs`, no new compiler warning (the old `set_host_enabled` one stays the only one), conventional commits staged by
path, nothing pushed, no beta. Commands from `src-tauri/` with `PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH`,
exactly one `--`, `SSHELTER_REQUIRE_OPENSSH=1`, and the leftover check (listeners / `sshd-session` / `sshelter-sshd-*` dirs all 0) after
every run that starts sshd. Frontend: `./node_modules/.bin/vitest run --exclude '.claude/**'` and `./node_modules/.bin/tsc --noEmit`,
never pnpm/npm/npx. Line numbers are those of `66b596e`; find each place by the quoted text when they have moved.

What the review found sound (no item): the end-of-session handshake tells exactly one reason exactly once on every path (relay `ending`,
`could_not_open`, `say_quit`, `Told`) and the remote shell/session is always closed; the broker holds no lock across I/O or a person
(table → short; link writer → the write itself; questions → never during `tell`; hostkey hub notify → pending); the named risk (a CLI
that stops reading) holds only that connection's `FrameLink` writer — `end_all`, other sessions and the host key flow proceed, the
engine's `ByteQueue` drops with its notice, and the stuck client is bounded by `QUIT_WAIT` at quit and by its own exit otherwise; every
server text reaches a terminal through `made_safe`/`printable` in the broker and through the CLI's own `printable`; secrets travel in
`Zeroizing` from the keys thread to the engine; the pins fail closed and are written atomically; the socket is owner-only with a peer
euid check; the Windows story is coherent (no broker, `ssh <alias>`, the CLI's sentence, the §7.4 loss list); CI selects the new tests.

---

## F1 — Important — a `ssh -G` answer that was read only in part is taken for the host's settings

- **Where:** `src-tauri/src/session/ssh_g.rs:192-201` (`PipeReader::collect`), used by `effective_within` at `:86-96`; the reader
  thread `:166-190`; module doc `:15-21`.
- **What is wrong:** `collect` returns `(bytes, error)` with `error = None` for every outcome but a read error — including
  `RecvTimeoutError::Timeout`, i.e. the pipe has **not** reached end-of-file within `PIPE_GRACE` (1 s after `ssh` exited). `ssh`'s
  stdout is held by nobody but `ssh` itself (OpenSSH's `execute_in_shell` gives a `Match exec` child `/dev/null` for stdin and stdout
  and only inherits stderr: `stdfd_devnull(1, 1, 0)` in readconf.c), so a stdout that has not ended a second after `ssh` exited can
  only mean the reader thread has not caught up — and then `bytes` may be a prefix of the answer. `effective_within` then returns a
  partial settings list as if complete. A missing tail is read as "not set": a `proxyjump` line (printed late in the list) is lost and
  the broker connects straight to the host; a missing `port` becomes 22; missing `identityfile` lines turn a key host into a
  keyboard-interactive one; and a wrong endpoint under the same host id reaches the person as a **changed host key** warning (the
  pin belongs to the id), which is the one warning that must never be spurious. Needs the reader thread starved for a second on a
  loaded machine — rare, silent, and the fix is one match. Proved by a scratch test (red at 66b596e): a `Read` that delivers
  `hostname x\n` then sleeps → `collect(now + 200 ms)` returns `(b"hostname x\n", None)`.
- **Change (a):** in `collect`, every outcome but a clean end is an error:
  ```rust
  /// What the pipe delivered, and `Some(error)` when that is not all of it: the reading failed, or the pipe had not reached its end by
  /// `until` (the output may be a part of the whole), or the thread reading it is gone.
  fn collect(&self, until: Instant) -> (Vec<u8>, Option<std::io::Error>) {
      let error = match self.ended.recv_timeout(until.saturating_duration_since(Instant::now())) {
          Ok(Ok(())) => None,
          Ok(Err(error)) => Some(error),
          Err(mpsc::RecvTimeoutError::Timeout) => Some(std::io::Error::new(std::io::ErrorKind::TimedOut, "its output had not reached its end a second after it exited")),
          Err(mpsc::RecvTimeoutError::Disconnected) => Some(std::io::Error::other("the thread reading its output ended without saying how")),
      };
      (self.bytes.lock().unwrap_or_else(PoisonError::into_inner).clone(), error)
  }
  ```
  `effective_within` already ignores stderr's error (`(stderr, _)`) and returns `Err("ssh -G could not be read: …")` for stdout's, so
  nothing else changes. The leftover-process case still passes: `a_process_left_behind_by_match_exec_does_not_hold_the_answer_up`
  holds only **stderr** open (the `sleep` inherits the shell's stdout, which is `/dev/null`), so stdout reaches EOF the moment `ssh`
  exits. Run that test first after the change; if it fails on this OpenSSH, stop and report (it would mean the child does hold stdout).
- **Change (b), same thread:** the reader appends to `bytes` without a bound (`:177`); a `Match exec` leftover that writes to stderr for
  ever grows the app's memory for as long as it lives. Add `const PIPE_CAP: usize = 1 << 20;` and, in the loop, stop storing once
  `sink.len() >= PIPE_CAP` (keep reading and discarding, so a live `ssh` is not killed by SIGPIPE on its stderr), recording
  `truncated = true` in a field next to `ended` (e.g. send `Err(io::Error::new(InvalidData, "more than a mebibyte of output"))` at the end
  instead of `Ok(())` when it was truncated). For stdout that is then an error as in (a); for stderr the first line is still reported.
- **Docs:** module doc `:18-19` says a leftover process "holds the pipes": say "holds its **stderr** (OpenSSH gives a `Match exec` command
  `/dev/null` for stdin and stdout and lets it inherit stderr only), so stdout always ends with `ssh`, and a stdout that has not ended a
  second later is an answer read only in part, not one to use".
- **Tests (red first):** in `ssh_g.rs` tests, `a_pipe_that_has_not_ended_by_the_grace_is_not_a_complete_answer`: the scratch test above
  (a `Read` returning 11 bytes once, then sleeping 5 s before `Ok(0)`), asserting `bytes == b"hostname x\n"` and `error.is_some()`; and
  `a_pipe_that_writes_without_end_is_read_only_up_to_the_cap`: a `Read` that fills every buffer with `b'x'` for ever → `collect(now + 300 ms)`
  returns at most `PIPE_CAP` bytes and an error (the thread keeps draining; the test ends by dropping the reader). Both fail at 66b596e
  (the first at the `error.is_some()` line, the second by growing past the cap).

---

## F2 — Minor — `the_quit_wait_outlasts_the_settle_time…` is flaky (1/1200): the entry leaves the table before the connection is closed

- **Where:** `src-tauri/src/session/broker.rs:329-338` (`forget`), `:413-419` (`SessionOver::drop`), `:304-308` (`could_not_start`);
  the test `:1692-1704`.
- **What is wrong:** for an open session the session thread's `SessionOver::drop` calls `forget` — which removes the entry and
  `notify_all`s, so `end_all` can return — and only then `hang_up`. The test reads `ready_now()` the moment `end_all` returns and expects
  the stream closed; once in ~1200 runs the shutdown has not happened yet. (Plan 1b-1 Task 11 round-2 re-review, parked EARLY.)
- **Change:** close before the entry leaves the table, in one place:
  ```rust
  /// … The entry of a client `end_all` is telling stays … When the entry is this thread's to take out, its connection is closed first:
  /// `end_all` returns as soon as the table is empty, and every client it ended must be able to read the end of its stream by then.
  fn forget(&self, id: u64) -> Told {
      let mut table = locked(&self.table);
      let told = table.entries.get(&id).map_or(Told::No, |entry| entry.told);
      if told != Told::ByEndAll {
          if let Some(entry) = table.entries.remove(&id) {
              hang_up(&entry.conn.closer);
          }
      }
      drop(table);
      self.changed.notify_all();
      told
  }
  ```
  `SessionOver::drop` becomes `self.broker.forget(self.conn.id);` (no hang-up of its own). `could_not_start` must tell before it
  forgets: `if self.claim(conn.id) { could_not_open(conn.link.as_ref(), kinds::CONNECT, "SSHelter could not start the session."); } self.forget(conn.id);`
  (`claim` is `false` when `end_all` told the client, exactly as the `!= ByEndAll` test did; `a_session_whose_thread_could_not_be_made_is_told_so_unless_the_app_is_quitting`
  keeps both halves). `hang_up` is one `shutdown` call under the table lock.
- **Test:** the flaky test needs no change; run `session::broker::` 30× in a loop (`for i in $(seq 30); do … --exact …; done`) and
  `the_outcome_of_a_connect_is_told_by_one_party…`, `a_panic_on_the_sessions_thread_still_forgets_the_session_and_hangs_up`.

---

## F3 — Minor — the CLI skips a control message it cannot read, silently

- **Where:** `src-tauri/src/cli/run.rs:559-578` (`read_broker`, `Err(_) => continue` at `:564`).
- **What is wrong:** a control frame whose JSON does not decode as `ServerMessage` is dropped and the loop goes on. Within one protocol
  version that is a bug in the app (the version check at `hello` rules out another version), and hiding it leaves the person waiting:
  a `question` the CLI could not read is answered by nobody until the broker's deadline (≥ 60 s) ends the login. The broker treats the
  same case the other way round (`protocol::kinds::PROTOCOL`, the connection ends). The spec (§7.1) makes an unreadable frame end the
  connection; an unreadable message should not be gentler.
- **Change:** treat it as the end: `Err(_) => (Input::Closed, 0)` is wrong (it would say "The connection to SSHelter ended."); add an
  input instead, e.g. `Input::Unreadable`, handled in `client.rs` like `Closed` but with the reason
  `"SSHelter sent a message this version of sshelter cannot read. Quit SSHelter and open it again."` and status 255, and make
  `read_broker` return after queuing it (the reader stops; the writer still sends `close` is not needed — the broker sees the stream end).
  Keep `Input`'s `Debug`.
- **Test:** `client.rs`: `a_message_the_cli_cannot_read_ends_the_session_with_a_sentence` (actions `[Mode(Cooked, false), Stderr("…\n"), Exit(255)]`,
  with the mid-line `"\n"` prefix when the shell is open); `run.rs`: a `by_hand` test writing `write_frame(&mut broker, CONTROL, br#"{"type":"teleport"}"#)`
  after `open()` and asserting `ends_within(5 s)` → `(255, true)` and the sentence on stderr. Both red at 66b596e (the frame is skipped
  and the run goes on).

---

## F4 — Minor — the host key window: a lost event, a stale card, a window that can flash, and test gaps (Task 3's parked items 2, 6, 8)

- **Where:** `src/components/HostKeyWindow.tsx:71-83` (the effect), `:88-95` (the rejected answer); `src/lib/hostkey.ts:92-103`;
  `src-tauri/src/session/hostkey_window.rs:93-121` (`ask`), the test at `:344`, tests `:244-363`.
- **What is wrong:** (a) the window calls `fetchPending()` and only then `onHostKeyRequests()`; the Rust listener is registered when the
  `listen` invoke completes, so an `emit_to` that falls between the fetch's answer and that registration is lost, and the window keeps
  showing a list that is no longer pending (`pendingFeed` only guards a fetch that answers after an event). The person then answers a
  question that is gone (`hostkey_resolve` → NotFound → the card stays, busy reset) while the real question waits for its 120 s.
  (b) `HostKeyHub::ask` pushes the question and publishes before it looks at `cancel`: a question withdrawn in the microseconds between
  `Connector::confirm`'s own check and `ask` opens the window for nothing. (c) `hostkey_window.rs:344` says "an answered question takes
  no second answer" for a question that has already **left** the list (`forget` ran when `ask` returned); the hub's tests dropped four of
  `agent/prompt.rs`'s (the `!answered` filter on `pending()`, an answer that arrives at the wait's end, `deny_all` with two questions,
  a surface that panics).
- **Change:** (a) register first, then fetch, and re-fetch after a rejected answer:
  ```tsx
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let live = true;
    const feed = pendingFeed((list) => { if (live) setPending(list); });
    void onHostKeyRequests(feed.fromEvent).then((u) => {
      if (!live) { u(); return; }
      unlisten = u;
      // The listener is in place: every change from now on arrives as an event, and the fetch fills in what was pending before it.
      void fetchPending().then(feed.fromFetch);
    });
    return () => { live = false; unlisten?.(); };
  }, []);
  ```
  and in the `.catch` of `resolveHostKey`: after resetting `answeredId`, `void fetchPending().then(setPending)` (the list as it is now).
  Update `pendingFeed`'s doc ("one fetch, started once the listener is registered"). (b) `ask`: `if cancel.is_cancelled() { return None; }`
  as its first line. (c) fix the message at `:344` ("a question that was answered and has left the list cannot be answered again") and
  port the four tests from `agent/prompt.rs` (same shapes, `HostKeyHub`/`HostKeyAnswer` names).
- **Tests:** vitest: the existing `hostkey.test.ts` and `HostKeyWindow.test.tsx` stay green; add, if `sync-events.test.ts`'s
  `stubEventBus` fits, `registers the listener before it fetches` (the first invoke is `plugin:event|listen`, the fetch comes after it);
  otherwise state the order in the effect's comment only. Rust: `a_question_withdrawn_before_it_is_asked_opens_no_window` (a cancelled
  token → `ask` returns `None` and the recorder surface saw nothing); the four ported tests.

---

## F5 — Minor — a second launch during the app's own start can leave `BrokerStatus::OtherInstance` while the broker serves

- **Where:** `src-tauri/src/session/app.rs:116-122` (`start`), `:125-154` (`listen`), `:162-167` (`ensure_listening`). (Task 4's
  parked item 1.)
- **What is wrong:** `on_second_launch` → `ensure_listening` → `start` can run before `setup`'s `start`; the second `listen_unix` then
  finds the lock held (by this very process, on another open file description) and records `OtherInstance`. Harmless for the clients
  (the first listener serves) but the status is wrong, and every later second launch calls `start` again for nothing.
- **Change:** make `start` idempotent under the status lock: take `state.session.status` at the top of `start`, return when it is
  `Running` or `NotOnThisPlatform`, else `listen` and write the result while still holding it (move `ensure_listening`'s check inside;
  `ensure_listening` becomes `start`). `listen` takes the `broker` lock only briefly and never the status lock, so the order is
  status → broker, taken nowhere else the other way.
- **Test:** none can run `listen` without an `AppHandle`; a unit test of the decision is enough: extract
  `fn needs_start(status: &BrokerStatus) -> bool` and pin `Running`/`NotOnThisPlatform` → false, the others → true.

---

## F6 — Minor — three sanitising/wording seams (Task 8 and Task 9 parked)

1. `src-tauri/src/session/auth.rs:248` and `:257`: the passphrase question uses `key.name` raw; every other question names things
   through `label()` (`:111`). Use `label(&key.name)` in both (the slot name is charset-checked today, the vault key name of plan 1c may
   not be). Test: in `a_passphrase_is_asked_before_the_connection_and_again_after_a_wrong_one`, a `FakeKeys::with_key("k-odd", "lap\u{1b}[2Jtop\n", …)`
   case whose question reads `Enter the passphrase for the key lap?[2Jtop?: `.
2. `src-tauri/src/session/connect.rs:281` (`pinned_summary`) and `:309` (`confirm`): a pin that cannot be **read** on a jump host is
   reported without the `Could not connect through {jump}: ` prefix that every other jump-host failure carries (`:135-141`,
   `a_host_key_problem_of_a_jump_host_is_said_through_it`). Replace both `.map_err(directory_failure)?` with
   `.map_err(|error| failure_at(Some(hop), target, kinds::HOST, error))?`. Test: add the unreadable-pins case to
   `a_host_key_problem_of_a_jump_host_is_said_through_it` (`chain().with_unreadable_pins()` → `through(kinds::HOST, "SSHelter cannot read its pinned host keys in host-pins.json (the file is damaged).")`;
   `resolve` fails first, so put the unreadable store behind a `PinMovedOn`-style wrapper whose `resolve` succeeds and whose `pinned`
   fails).
3. `src-tauri/src/session/auth.rs:75-76`: `Reply::Gone` doc "The client went away." → "The client went away, or the question could not
   be put to it (too large for a frame: `ConnectionOwner::ask`)."

---

## F7 — Minor — tests that cannot fail, and the cheap coverage the task reviews parked

Each is a few lines; all red-able unless marked (pins).

1. `src-tauri/src/session/protocol.rs:348-350`: the "never written" half inspects nothing. `let mut sink = Vec::new(); let error = write_data(&mut sink, &vec![0; MAX_FRAME]).unwrap_err(); assert!(sink.is_empty(), "nothing of a frame that does not fit is written");`
   (and the same `sink` for the `MAX_FRAME - 1` case, asserting `sink.len() == MAX_FRAME + 4`).
2. `protocol.rs:431-438`: `!error.contains("hunter2")` is vacuous (serde never quotes an integer). Use an input serde **would** quote:
   `br#"{"type":"answer","question_id":"q1","value":"hunter2","cancel":"hunter2"}"#` (serde's own text would be
   `invalid type: string "hunter2", expected a boolean`), keep both assertions.
3. `protocol.rs:29-33`: `Frame` derives `Debug`; the payload is hidden only because the locked zeroize 1.9.1 redacts `Zeroizing`. Pin it:
   `a_frame_hides_its_payload_in_debug_output` (`!format!("{:?}", Frame::Control(Zeroizing::new(b"hunter2".to_vec()))).contains("hunter2")`),
   or write `Debug` by hand (`Control(<n> bytes)`). (Task 4 parked 1.)
4. `protocol.rs` tests (Task 4 parked 2): a reader that returns one byte at a time and `Interrupted` twice; EOF between the header and the
   type byte (`Truncated`); a frame of exactly `MAX_FRAME` read back whole; an `io::Error` other than `Interrupted` → `FrameError::Io`;
   `decode` of `{}`, `[]`, `"x"`, `{"type":1}`.
5. `src-tauri/src/cli/client.rs:414-415`: pin the sizes, not the count: `assert_eq!(data_frames(&actions).iter().map(Vec::len).collect::<Vec<_>>(), [DATA_CHUNK, 10])`.
6. `src-tauri/src/session/connect.rs:871-896`, the `"a pinned key of another type"` case: add `assert_eq!(world.engine.attempts(), 1, "{label}: no reconnect without the pinned type for a connect the person gave up")`
   (the `NoCommonHostKeyAlgorithm` pattern of the abandonment arm is otherwise unpinned). (Task 9 parked.)
7. `src-tauri/src/session/broker.rs:1352`: next to the `claim(2)` assertion, `assert!(!world.broker.promote(2, &web), "nor is a session whose entry is gone made an open one")`
   (`promote`'s missing-entry branch, `:366`). (Task 11 parked.)
8. `src-tauri/src/session/testing.rs:508`: after the successful replace, `directory.replace_pin(&hop.id, third, second).expect("the key asked for is the pinned one already: nothing to write, and no refusal");`
   (the "or `key` already is" clause of `replace_pin`, unpinned for the real store). (Task 6 parked.)
9. `src-tauri/src/host_start.rs:215-221`: add `assert!(!is_host_flag("--mcp-host=1"));`. (Task 5 parked 5.)
10. `src-tauri/src/session/app.rs:205-213`: a slot with `payload: Some(..)` whose `name` is `"work laptop"` resolves to that name, and one
    with an empty payload name falls back to the file name (the naming mutant survives today). (Task 4 parked 6.)
11. `src-tauri/src/connect.rs:456-466`: `launch_for(id, "web", true)` for `iterm2` (the new-tab script) and a `connect_argv` of a path with
    a `'` in it through `build_launch_command("terminal", …)` (`'\''` quoting). (Task 5 parked 4, the two cheap ones.)

---

## F8 — Minor — `ByteQueue`: the parked test and doc items of plan 1b-1 Task 1

`src-tauri/src/ssh/channel.rs`:
1. The type's doc (`:47-49`, "the memory the queue uses follows the bytes it holds, not the number of pushes") → "… follows the bytes it
   holds (within about twice them, `Vec` growth), not the number of pushes".
2. `a_reader_that_catches_up_after_a_gap_is_told_about_it_at_once` (`:345`): the second read uses `soon()` (50 ms), so an announce that
   waits for a timed wait to expire still passes. Read it with a deadline that has passed already, `queue.read_until(&mut buf, Some(Instant::now()))`,
   and assert `Bytes(_)` (the notice); the mutant "announce only when a wait expires" then returns `Timeout`.
3. The `<=` of `append` (`:76`) is unpinned: `push(vec![1; MERGE_LIMIT - 1])`, `push(vec![2; 1])` → `chunk_count() == 1`; then `push(vec![3; 1])` → 2.
4. A merge into a partially read front chunk: push `b"abcd"`, read 2 bytes, push `b"ef"` → `chunk_count() == 1` and the next read is `b"cdef"`
   (`front_read` stays valid: the doc at `:72-73` claims it, nothing tests it).
5. Docs of `push` (`:91-96`), `close` (`:117`) and `read_until` (`:127-128`): say that a read may return only a notice (nothing of the
   server's), and that push, close **and** a read of an emptied queue announce a gap.
6. (Dropped: "T2/T3 not wrapped in `bounded()`" — `read_all` reads with `soon()` and cannot hang.)

---

## F9 — Minor — a Windows warning, and one in-app sentence that is no longer true

1. `src-tauri/src/connect.rs:362` (`connect_argv`): used only by `launch_for`'s `cfg(unix)` arm and the tests → a dead-code warning on
   the Windows CI leg. Add `#[cfg(any(unix, test))]` (as `build_launch` has its `cfg(any(windows, test))`). (Task 5 parked 2.)
2. `src/components/HostEditor.tsx:1284`: "Connect auto-fills it once the host key is trusted (not for ProxyJump or 2FA hosts)." — the
   autofill is deleted on every platform (spec §7.4). On macOS and Linux the saved password is now what `sshelter connect` logs in with
   first (`AuthSource::password`, keychain first); on Windows nothing uses it until phase 3. Replace the clause with
   "sshelter connect logs in with it (on Windows, until the next phase, ssh asks for it)." Plan 1d rewrites the editor; until then the
   text must not promise a feature that is gone. `README.md:18` describes the 0.17 Connect and is phase 3's (hand-off below).

---

## F10 — Minor — docs and comments that are not true of HEAD, and the spec notes the reviews parked

Text only; wrap at about 150 columns; spec text in Traditional Chinese.

1. **Spec §7.1** (`docs/superpowers/specs/2026-10-10-own-ssh-client-design.md:221`): the ending conditions miss a length of 0, the
   limit should say what it counts, and the `kind` words are unrecorded. After "超過、型別不明或在訊框中間斷掉都結束連線", write:
   "長度為 0(連型別位元組都沒有)也結束連線;1 MiB 指的是長度欄位的值(型別位元組加內容)。`event{error}` 的 `kind` 是給程式看的短字:
   `protocol`、`unsupported`、`host`、`host_key`、`auth`、`connect`、`shell`、`input`(`session::protocol::kinds`)。" (Task 4 parked 5.)
2. **Spec §7.1, the prefix rule** (`:222`): record the known limit (Task 8 round-2 re-review): "已知的限制:終端機自動換行時,一行夠長的提示
   可以把假冒的 `(deploy@db) ` 推到下一個畫面列的開頭;真正的修法需要知道終端機寬度,第 1b 期不做。"
3. **Spec §10** (`:296`, Task 7 Minor 4): the bullet names no phase for its other parts. Per §13: the MCP `ask` question window and the
   "這次作廢,請重連" hint belong to phase 2 (the CLI shows §11's sentence in the terminal, done in 1b); the session list is phase 3; AI
   Access's last-10 is phase 2. Rewrite the parenthetical: "(第 0 期後的介面後果;確認視窗在第 1b 期做,CLI 在終端機裡印 §11 的句子也是;
   MCP `ask` 模式的提問視窗與它的「這次作廢,請重連」提示在第 2 期;主機明細與「Forget pinned key」在 1d;進行中的 session 清單在第 3 期;
   AI Access 的最近 10 筆在第 2 期)".
4. **Spec §11** (`:300-311`): the two sentences plan 1b added are in no table. Add two rows after "主機金鑰不符":
   "| 連線途中主機金鑰一直變 | `The host key of {alias} kept changing while SSHelter was connecting. Connection refused.`(一次連線只問一次) |" and
   "| 問之前釘住的記錄已被別的連線改掉 | `SSHelter's record of {alias}'s host key changed while it was connecting. Connect again.` |".
5. `src-tauri/src/session/ssh_g.rs:15-21`: see F1 (stderr only).
6. `src-tauri/src/host_start.rs:3` "unchanged, but for two things" → "but for four things" and list them: the caller's no-answer
   message, the flag with the old one accepted, the `[host]` stderr prefix, the thread name. `:82` "the adapter's other calls" →
   "this process's other calls (the adapter's tool calls)". (Task 5 parked 2, 6.)
7. `src-tauri/src/main.rs:11`: "MCP adapter 啟動 SSHelter 時設 SSHELTER_START_HIDDEN=1" → "用戶端(MCP adapter、`sshelter connect`)在背景啟動
   SSHelter 時設 SSHELTER_START_HIDDEN=1". `src-tauri/src/lib.rs:371` and `:383`: test names `only_the_adapter_flag_…` →
   `only_the_hidden_start_variable_…`, `a_restart_of_an_adapter_started_sshelter_…` → `a_restart_of_a_client_started_sshelter_…`.
8. `src-tauri/src/session/connect.rs:22-26`: "all but the first need one answer of the person" is wrong — the pin taken from the
   directory and the plan 1b R17 reconnect need none. Write: "the host key question and the passwords each need one answer of the
   person; the pin taken meanwhile and the handshake without the pinned type need none".
9. `src-tauri/src/ssh/testing/harness.rs:9-10`: "A test that needs one sshd for a long loop adds `PerSourcePenalties no`" is a trap on
   OpenSSH 9.6 (Ubuntu 24.04 rejects the config). Add: "— only after checking with `sshd -t` that the runner's OpenSSH knows the
   keyword (9.8 and later); no test in the suite passes it today."
10. `src-tauri/src/session/ssh_config_directory.rs:198-199`: "Copied from `agent::oneshot`, which goes away with the one-shot channel"
    → "Copied from the one-shot key channel that plan 1b-2 deleted (`agent/oneshot.rs`)".
11. `src-tauri/src/ssh/engine_tests/broker_signals.rs:251`: "one call to the auth source carries the whole banner" → "… carries the
    banner, cut at the cap, in one piece".
12. `src-tauri/src/ipc/server.rs:86-87` and `:107`: `listen_unix`'s doc names `~/.ssh/sshelter/agent` and the thread `sshelter-agent`,
    but the broker's listener (`<app data>/ipc`) runs through it too. Doc: "在 `dir` 開 `sock`(agent 的 `~/.ssh/sshelter/agent`,或 broker 的
    `<app data>/ipc`)"; thread name: `sshelter-ipc-listener` (nothing matches on it: grep `sshelter-agent` in `src-tauri/src` first).
13. `src-tauri/src/session/hostkey_window.rs:344`: see F4 (c).

---

## F11 — Minor — the same test literal written five times

1. The scratch sshd's shell line `ForceCommand if [ -n "$SSH_ORIGINAL_COMMAND" ]; then eval "$SSH_ORIGINAL_COMMAND"; else exec /bin/sh; fi`
   is written in `src-tauri/src/cli/e2e_tests.rs:30`, `ssh/parity_tests.rs:326`, `ssh/engine_tests/mod.rs:24`, `session/broker.rs:1081`
   and `:1842`. Put one `pub const SH_SHELL: &str` next to `Server` in `ssh/testing/fixture.rs` (doc: a `/bin/sh` for the scratch sshd so
   the prompt depends on nobody's shell setup) and use it in all five (`SHELL_SERVER` becomes `&[SH_SHELL]`).
2. `src-tauri/src/ssh/engine_tests/broker_signals.rs:19, 178, 230, 246, 261`: the same `ToyLogin { user: "tester", password: "correct horse
   battery staple", prompt: "Password: ", rounds: None }` five times; `login_methods.rs:41` already has `toy_login()`. Make that helper
   `pub(super)` and use it in the five places. (Task 2 round-2 re-review, parked.)

---

## Verification for the wave

- Red first where the item says so (F1's two tests, F3's two, F4's withdrawn-question test, F7.1/2/5/6/7/8/10/11 where the assertion is new,
  F8.2–4); then green.
- `SSHELTER_REQUIRE_OPENSSH=1 … cargo test --offline --locked --lib -- session:: cli:: host_start::` (328 at 66b596e + the new tests);
  `ssh::` (F8, F11); the whole suite with the two keychain skips (1897 at 66b596e + the new tests, 2 filtered); `cargo check --offline --locked --bin sshelter`;
  `./node_modules/.bin/vitest run --exclude '.claude/**'` (51 files / 851 tests at 66b596e + any new) and `./node_modules/.bin/tsc --noEmit`.
- F2: `session::broker::` 30× in a loop, leftovers 0 after each sshd run.
- `git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock` empty; only the old warning; `grep -rn "oneshot" src-tauri/src --include='*.rs'`
  shows only tokio's and the one comment of F10.10.

---

## Hand-off (not for this wave)

Each with where it goes and why it is not fixed now.

1. **[user] Windows has no Connect through SSHelter's keys until phase 3.** The one-shot channel and the autofill are deleted on every
   platform (plan 1b-2 Task 5, ruled); Windows keeps `ssh <alias>` (spec §7.4 lists what it lost). Decide whether the Windows console
   work moves into phase 1 before any 1.0 beta reaches a Windows user. (Ledger 1b-1 top ruling.)
2. **[1d, UX] The host key window is destroyed when its list empties and rebuilt for the next question** (`hostkey_window.rs:196-232`): a
   `[Q1] → [] → [Q2]` within one main-loop turn finds the dying window and builds none, and Q2 waits its 120 s then is refused (Task 3
   parked 1). Needs two sessions asking within milliseconds; recoverable by connecting again; the same pattern as the agent's approval
   window. Fix in 1d with the pinning UI: hide the window when the list empties and show it on a new head, never destroy.
3. **[1d, UX] Escape in the window, a monospace fingerprint, a label on the changed-key line** (Task 3 parked 3–4); **`hostkey_resolve` is
   callable from any webview** (parked 5; the same holds for `agent_resolve` today; an app manifest would check the caller's label).
4. **[1d/3, design] Closing the main window while a session is open hides the app, and it stays hidden after the last session ends**
   (`lib.rs` `hides_on_close`): on Linux with the menu bar icon off there is then no window, tray or Dock — a relaunch (`on_second_launch`)
   or the macOS Dock brings the window back, so it is a wrinkle, not a trap (Task 4 parked EARLY 3). The same holds for the seconds a
   session that is already leaving (settle wait, an uninterruptible connect) is still counted. Decide with the session list (phase 3):
   minimize instead of hide, show the tray while sessions keep the app alive, or quit when the last session ends and nothing else keeps it.
5. **[1d, UX] The quit freezes the windows for up to `QUIT_WAIT` (5 s)** while `end_all` runs on the main thread in `RunEvent::Exit`
   (Task 4 parked 4); hide the main window before `end_all`, or move the wait. Also: a relaunch during the wait would start a second
   instance (the single-instance socket is gone by then) — contrived.
6. **[Linux manual / 1d] `std::env::current_exe()` in `launch_for` (`connect.rs:368`) and `start_host` (`host_start.rs:161`)** is the
   AppImage's temporary mount; once the AppImage that mounted it exits (the CLI that started the app from a shell), later launches name a
   path that may be gone. Tauri's `process::current_binary(&app.env())` / the `APPIMAGE` variable are the fix (Task 5 parked EARLY 5).
   Not graded higher: AppImage-only, and whether the mount outlives its runtime while a child uses it is unmeasured — a manual check below.
7. **[1c] The one-shot channel's dead "sign without asking" path in `agent/broker.rs`** (`Grant`, `Connection.grant`, always `None` in
   production, alive through tests; Task 5 parked EARLY 3): plan 1c deletes `agent/`; deleting it now is churn in code that goes.
8. **[1c] `session/app.rs` duplicates `agent/`'s `private_text` and naming rule** (Task 4 parked 7): gone with `agent/`.
9. **[phase 2] `SessionInfo.alias` of a connecting session is the raw query** (shown nowhere yet; make it printable before the session
   list shows it); **invisible format characters (U+200B, U+2060–4, U+FEFF, tags) pass `printable`** — reconsider before server text is
   relayed to an AI tool (Task 8 round-2 re-review); **MaxSessions-0 shell parity scenario** (Task 3 parked 1) with the exec parity work.
10. **[phase 3 docs] `README.md:18, 24`** describe the 0.17 Connect (`ssh <host>`, `SSH_ASKPASS` autofill); the 1.0 README is phase 3's.
11. **[phase 3] Windows: `set_read_timeout` is a no-op on a pipe, so the spec's 10 s `hello` bound does not hold there** — moot until the
    broker runs on Windows (`BrokerStatus::NotOnThisPlatform`).
12. **[accepted, documented] A session's end waits for a slow terminal to take the shell's last output** (up to the 256 KiB budget at the
    terminal's pace, raw meanwhile; SIGTERM/SIGHUP still end it; OpenSSH writes everything too); **a line the keys thread read but had not
    queued at a question's flush is not caught** (`run.rs` `forget_typed` doc); **two Ctrl-Ds at two questions, then a closed window**
    (verified); **`serde_json` leaves an escaped answer's scratch copy unwiped** on the broker's decode (a password with `"`/`\`/control
    characters; the same as the agent's broker today); **a panic on the IPC connection thread** (`serve`) leaves the session to end by its
    own write failures (bounded: the next write to the closed socket fails, the window question by its 120 s) — a bug anyway.
13. **[dropped] BrokerAuth does not say *why* a prompt ended** ("the password was not given" for cancel, timeout and gone alike; Task 9
    amendment concern 2) — the §11 sentence is the same; **"(the password was not given)" vs "(the prompt was cancelled)"** for the same
    action (Task 8 parked) — the engine's own wording, pinned by the parity tests; **the fake caps waits at 365 days and asks `interactive`
    for an empty round** (Task 3 parked 4) — nothing of the broker relies on it; **the plan texts still say MAX_ROUNDS = 12 / QUIT_WAIT = 3 s**
    — plan text is stale by ruling; **`FakeEngine::with_banner("")` delivers an empty banner and applies no cap** — test-only, unused that way;
    **the version labels of `DEFAULT_IDENTITY_SEQUENCES` are read from tags, not measured** — documented as such; **a v1 pin whose public key
    is undecodable can still be replaced by fingerprint** — unreachable through `resolve`; **"T2/T3 not in `bounded()`"** — see F8.6;
    **`an invalid-UTF-8 answer through from_utf8_lossy reallocates unwiped`** — a password with invalid UTF-8 bytes, no cheap fix;
    **`-o ForwardAgent=no` lost with the one-shot options** — the own client forwards no agent; **Ctrl-D on an empty line while
    connecting ends with 129 unlike OpenSSH** — a design choice (the end of input is the terminal going away).

---

## Parked findings, re-graded (every one, including the dropped)

| Ledger item | At HEAD | Now | Where |
|---|---|---|---|
| 1b-1 T1 (1) channel doc "memory follows the kept bytes" | present | Minor | F8.1 |
| T1 (2) catch-up test uses `soon()` | present | Minor | F8.2 |
| T1 (3) T2/T3 not in `bounded()` | n/a (`read_all` bounded) | dropped | F8.6 |
| T1 (4) `<=` MERGE_LIMIT boundary unpinned | present | Minor | F8.3 |
| T1 (5) announce/read docs | present | Minor | F8.5 |
| T1 (6) merge into a partly read front chunk untested | present | Minor | F8.4 |
| T2 re-review: harness `PerSourcePenalties` note | present | Minor | F10.9 |
| T2 re-review: `ToyLogin` literal ×5 | present | Minor | F11.2 |
| T2 re-review: test name `…needs_the_hops_own_method_order` | doc explains | dropped | — |
| T2 re-review: "the whole banner" message | present | Minor | F10.11 |
| T2: `with_banner("")` uncapped/empty | test-only | dropped | hand-off 13 |
| T3 (1) 20 s connect-timeout case (fake) | done (`[1, 20, MAX]`) | — | — |
| T3 (1) MaxSessions 0 shell scenario; why write Timeout is left out | absent | hand-off | 9 |
| T3 (2) cut scenario asserts the ending order | done | — | — |
| T3 (3) `failing_with` doc | done | — | — |
| T3 (4) fake's 365-day cap / empty KI round | present | dropped | 13 |
| T4 (1) `Frame` derives Debug | present | Minor | F7.3 |
| T4 (2) short reads / Interrupted / EOF / exact MAX / Io / malformed | absent | Minor | F7.4 |
| T4 (3) over-limit "never written" half cannot fail | present | Minor | F7.1 |
| T4 (4) `!error.contains("hunter2")` vacuous | present | Minor | F7.2 |
| T4 (5) spec §7.1 length 0, what 1 MiB counts, kind vocabulary | present | Minor | F10.1 |
| T4 (6) PROTOCOL_VERSION / `serde(other)` on ClientKind | done (`hello_version` reads the version first) | — | — |
| T4 (7) protocol.rs:124 "shorter than MAX_FRAME" | done | — | — |
| T5 (1) host_start.rs:157 claims on_second_launch restarts the socket | now true | — | — |
| T5 (2) "unchanged but for two things" | present | Minor | F10.6 |
| T5 (3) host-flag test compares with the constant | done (literal) | — | — |
| T5 (4) NO_ANSWER placeholder / mcp.rs assertion | `NO_ANSWER` has no test of its text | dropped (0.17 wording, unchanged) | — |
| T5 (5) `!is_host_flag("--mcp-host=1")` | absent | Minor | F7.9 |
| T5 (6) stale "adapter"/`--mcp-host` wording | partly | Minor | F10.6–7 |
| T5 (7) mcp.rs import style | — | dropped | — |
| T6: `check_the_pin_contract` does not gate "or key already is" | present | Minor | F7.8 |
| T6: undecodable v1 pin replaceable by fingerprint | unreachable | dropped | 13 |
| T6: pins.rs:59 vs a second store in a test | sequential, fine | dropped | — |
| T7 re-review FIRST: ssh_g `collect` takes a stalled stdout for complete | present (proved) | **Important** | F1 |
| T7 re-review: reader buffers unbounded | present | Minor | F1 (b) |
| T7 re-review: ssh_g.rs:18–19 doc (stderr only) | present | Minor | F1 docs |
| T7 re-review: default-list version labels guessed | documented | dropped | 13 |
| T8 → T9: passphrase question raw `key.name` | present | Minor | F6.1 |
| T8: "(the password was not given)" vs "(the prompt was cancelled)" | present | dropped | 13 |
| T8: plan/brief MAX_ROUNDS = 12 | stale plan | dropped | 13 |
| T8: the two new sentences not in the spec | present | Minor | F10.4 |
| T8 round-2: spec "that line" wording | reads fine | dropped | — |
| T8 round-2: `Reply::Gone` doc | present | Minor | F6.3 |
| T8 round-2: "\n\n" table entry | covered (`first\n\nthird\n`) | dropped | — |
| T8 round-2: soft-wrap known limit in spec §7.1 | absent | Minor | F10.2 |
| T8 round-2: invisible tag characters pass `printable` | present | hand-off | 9 |
| T9 re-review: `attempts() == 1` in the pinned-type abandonment case | absent | Minor | F7.6 |
| T9 re-review: pin-read failures lack the jump prefix | present | Minor | F6.2 |
| T9 re-review: connect.rs:25 ROUNDS doc; :1180 | present | Minor | F10.8 |
| T9 amendment concerns 1, 3, 4 | done / accepted | — | — |
| T9 amendment concern 2 (why a prompt ended) | present | dropped | 13 |
| T10 round-1 concerns 1–6 | done / accepted | — | — |
| T11 round-2 EARLY: flaky `the_quit_wait_outlasts…` | present | Minor | F2 |
| T11 round-2: `promote` missing entry unpinned | present | Minor | F7.7 |
| T11 round-1: a panic on `serve`'s thread | present, bounded | hand-off | 12 |
| T11 round-1: `SessionInfo.alias` raw query | present | hand-off | 9 |
| T11 round-1: Windows read timeout no-op | moot | hand-off | 11 |
| 1b-2 T1 re-review: wipe behaviours untested | done (`wiped()` tests) | — | — |
| T1 re-review: `SendData(<hidden>)` hides the length | done (`<N bytes>`) | — | — |
| T1 re-review: invalid-UTF-8 answer reallocates unwiped | present | dropped | 13 |
| T1 re-review: early return after Ended drops Stdin unwiped | done (`Zeroizing`) | — | — |
| T1 re-review: open-shell DATA_CHUNK size count only | present | Minor | F7.5 |
| T2 amendment "left": handler install warns only | done (fatal) | — | — |
| T2 amendment "left": Ctrl-Z at a hidden prompt | done | — | — |
| T2 amendment "left": a line read but not queued at the flush | documented | accepted | 12 |
| T2 review minors 1–5; round-1 N1–N3; round-2 F1–F9 | done | — | — |
| T2 round-2 concern 1: end waits for a slow terminal | by design | accepted | 12 |
| T2 round-2 concerns 2–7 | accepted / history | — | — |
| T3 (1) destroy race | present | Minor | hand-off 2 |
| T3 (2) fetch before listen | present | Minor | F4 (a) |
| T3 (3) Escape = refuse | present | hand-off | 3 |
| T3 (4) monospace fingerprint / label | present | hand-off | 3 |
| T3 (5) `hostkey_resolve` from any webview | present | hand-off | 3 |
| T3 (6) hub tests narrower; :344 message | present | Minor | F4 (c) |
| T3 (7) frontend busy/reset untested | present | dropped (1d rewrites) | — |
| T3 (8) a cancelled question can flash the window | present | Minor | F4 (b) |
| T4 EARLY (3) Linux tray-off hide | present | hand-off | 4 |
| T4 (2) Windows warnings | done (allow) | — | — |
| T4 (1) startup race → OtherInstance | present | Minor | F5 |
| T4 (4) quit freezes windows | present | hand-off | 5 |
| T4 (5) ExitRequested{None} unguarded | contrived | dropped | — |
| T4 (6) two surviving mutants (`vault_key_in` naming, `loaded_doc`) | present | Minor (naming) | F7.10 |
| T4 (7) duplicates `agent/` | present | hand-off | 8 |
| T4 (8) listen_unix wording / thread name; status doc | present | Minor | F10.12 |
| T5 EARLY (3) dead `Grant` path | present | hand-off | 7 |
| T5 EARLY (5) `current_exe()` on AppImage | present | hand-off + manual | 6 |
| T5 (1) HostEditor/README autofill text | present | Minor / phase 3 | F9.2 / 10 |
| T5 (2) Windows `connect_argv` warning | present | Minor | F9.1 |
| T5 (4) launch tests | partly | Minor (two) | F7.11 |
| T6 (1)–(4) e2e doc, restore asserts, early-end diagnostics, stdout/has_sessions | done | — | — |
| T6 (5) `(early eof)` exact text on Linux | watch | manual | below |
| T6 (6) SHELL line ×5; set-up copies | present | Minor (SHELL) | F11.1 |
| T6 declined: `texts` cfg | done | — | — |
| T7 (1b-2) Minor 4: spec §10 phases | present | Minor | F10.3 |
| T7 declined: ForwardAgent=no; Ctrl-D while connecting → 129 | — | dropped | 13 |

---

## Manual checks for the user (what only a real app, terminal, Linux desktop or Windows machine can show)

1. **macOS, real app:** Connect from the row button, the editor header, the command palette and the tray opens Terminal.app and iTerm2
   (window and tab) running `sshelter connect <alias>`; a first contact shows the host key window on top of a full-screen terminal,
   focused, with the trust button disabled for ~0.7 s; the red close button refuses; two first contacts from two terminals list both
   questions, oldest first; Trust pins (`host-pins.json`, mode 0600) and the shell opens without a second question.
2. **Hide-on-close and quit:** close the main window with a session open → hidden, the session lives; tray Quit, Cmd+Q and an update's
   "Install & restart" each print `SSHelter quit, so the connection to <alias> was closed.` in every terminal and exit 255, within 5 s;
   a shell that had not printed yet (connect, then quit at once) is told after up to ~3 s.
3. **The background start:** with SSHelter not running, `sshelter connect web` from a terminal starts it hidden and connects; with a
   debug build running next to the installed app, which one answers (`OtherInstance` in the other); with the app running but its broker
   failed (a socket path over 104 bytes), the CLI prints `SSHelter did not start within 12 seconds.` after 12 s (misleading but bounded).
4. **Terminal behaviour on a real pty:** Ctrl-Z at a password prompt then `fg` in bash, zsh and fish (echo stays off, the prompt is
   re-shown, nothing typed meanwhile becomes the password); a closed terminal window mid-shell (129, the broker closes the session after
   the prompt, no `sshd-session` left on a macOS server); `yes` on a slow terminal (a terminal over ssh) — Ctrl-C arrives at once and the
   stream shows `[SSHelter dropped N bytes …]`; a `Match exec` in `~/.ssh/config` that sleeps 30 s → `ssh -G did not finish within 10 seconds.`
   after 10 s and no leftover process; the keychain's first read of a vault key from the session thread (no prompt).
5. **Linux desktop:** gnome-terminal, konsole, kitty, wezterm, xfce4-terminal and xterm launch; a closed window reads as EIO/POLLHUP
   (129); IUCLC is clear in raw mode (typed capitals arrive as typed); "Show menu bar icon" off + close with a session (hand-off 4);
   an AppImage: `sshelter connect` from a shell that starts the app, then Connect from the app after the shell's AppImage exited
   (hand-off 6).
6. **First CI runs (watch, do not pre-fix):** the Linux leg's pty tests (`ctrl_d_at_two_questions…`, `the_terminal_says_when_it_hung_up…`,
   `what_was_typed_at_a_question_does_not_reach_the_shell…`, `ctrl_z_really_stops…`), `a_connection_lost_in_the_middle_of_a_shell…`'s exact
   `(early eof)` text (loosen to a prefix if Linux says `connection reset`), the PAM container, and the Windows leg with `session:: cli::`
   added (the allowed dead code, `connect_argv` until F9.1).
7. **Windows build:** `cargo test --locked --lib -- … session:: cli::` compiles and runs (the Unix-only modules are not built); Connect
   still opens `ssh <alias>`; `sshelter.exe connect web` prints `sshelter connect is not supported on Windows yet.` only where a console
   exists; what a Windows user lost (spec §7.4) is acceptable until phase 3 (hand-off 1).
