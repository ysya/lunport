# Own SSH client — phase 1b-2: `sshelter connect`, the host-key window and the Connect button — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On macOS and Linux, `sshelter connect <alias>` (or `--id <host id>`) opens a shell through the app's session broker of plan 1b-1: it starts SSHelter in the background when nothing answers, keeps the terminal as it is until the shell opens and then makes it raw, asks at the terminal what a login needs, follows the terminal's size and the signals that end it, and exits with the shell's status (128 + n for a signal, 255 for a lost connection, as ssh), putting the terminal back on every way out. Host keys are confirmed in a small window of their own with spec §14's texts. The app starts the broker on `<app data>/ipc/sock`, keeps running while sessions are open and ends them, with a reason, when it quits. The Connect button, the command palette and the tray's quick connect run `<SSHelter> connect <alias>` instead of `ssh <alias>` (Windows keeps `ssh <alias>` until phase 3), and the password autofill and the one-shot key channel are deleted. At the end the engine and the broker are private to the crate (R21) and the spec records `sshelter connect`. The deliverable stands on its own: `cli::e2e_tests` runs `sshelter connect` against a scratch sshd through the broker's socket, and the app does the same for a person (checklist at the end).

**Architecture:** `src-tauri/src/cli/` holds the CLI: `terminal.rs` (termios through `libc`: raw as OpenSSH sets it, a prompt mode, the mode of the start; restored on drop and on panic), `client.rs` (the client's side of one session as a state machine without I/O: inputs in, actions out), `run.rs` (the I/O: the broker's frames on one thread, the keys on another, the signals on a third with tokio's signal handling, all into one queue) and `mod.rs` (`run_connect`: arguments, `host_start::ensure_started` of plan 1b-1, the terminal, the threads; on Windows a sentence and exit code 1). `session/hostkey_window.rs` is the broker's `HostKeyConfirmer` in the app: a hub of waiting questions modelled on `agent/prompt.rs`'s, a Tauri window labelled `hostkey`, two commands; the window itself is React (`src/lib/hostkey.ts`, `src/components/HostKeyWindow.tsx`). `session/app.rs` builds the broker over the app's state in `setup` and answers the app's lifecycle. `connect.rs`'s `launch_for` is what the terminal runs.

**Tech Stack:** Rust (`libc` termios; tokio's `signal` feature — the only `Cargo.toml` change of plan 1b), Tauri 2 (a window, two commands, a capability file, `RunEvent::Exit`, the single-instance hand-over), React 19 and TypeScript with ts-rs bindings, vitest; plan 1b-1's broker, plan 1a's engine and scratch-sshd harness.

**Spec:** docs/superpowers/specs/2026-10-10-own-ssh-client-design.md (§4, §7.3, §7.4, §10, §11, §13, §14, §16); the rulings of docs/superpowers/plans/2026-10-12-own-ssh-phase1b-design-brief.md (R3, R4, R6, R7, R10–R14, R21 in particular); plan 1b-1 (docs/superpowers/plans/2026-10-12-own-ssh-phase1b-1-broker.md), whose last commit this plan starts from.

## Global Constraints

- **Where.** Repository `/Users/ysya/project/sideproj/sshelter`, branch `next/own-ssh`, starting at the last commit of plan 1b-1 (`feat(session): serve sessions to clients over the local IPC socket`). Every task ends with a commit on that branch; nothing is pushed, nothing is merged to main, no beta is published.
- **Starting state.** `git status --short` prints nothing. The whole lib suite passes with `test result: ok. 1684 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the frontend has 845 tests in 50 files (`Test Files  50 passed (50)`, `Tests  845 passed (845)`) and `tsc --noEmit` exits 0.
- **Toolchain, where commands run, the app's Rust tests, the leftover check, isolation, spawning, threads, commits.** As in plan 1b-1's Global Constraints, word for word: every block runs from the repository root, cargo in a subshell `(cd src-tauri && …)`; `PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- <filters>` from `src-tauri/`, exactly one `--`; the two keychain skips in a whole-suite run; `SSHELTER_REQUIRE_OPENSSH=1` where a scratch sshd runs; the three counts of the leftover check are 0 after every such run and at the end of every task; never the real `~/.ssh`, the Keychain, an SSH agent or the app's data directory; `crate::process::spawn`; blocking engine calls on plain threads; conventional commits, files staged by path. Never launch the app.
- **The frontend's checks.** From the repository root: `./node_modules/.bin/vitest run --exclude '.claude/**'` and `./node_modules/.bin/tsc --noEmit` — never `pnpm`, `npm` or `npx` (`--exclude` keeps vitest out of agent worktrees under `.claude/`).
- **Lock file (R13).** Task 2 is the one task of plan 1b that changes `src-tauri/Cargo.toml`: tokio gains the `signal` feature. Its `Cargo.lock` change is one line — tokio's dependency list gains `signal-hook-registry`, which the lock already holds — and no crate is added; Task 2 shows that diff and locks it. Every other cargo command runs `--offline --locked`, and in every other task `git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock` prints nothing before the commit.
- **Strings.** The window's texts are spec §14's, word for word (`Is this {alias}?`, the unknown-key body, `Cancel`, `Trust this key`; `{alias}'s host key changed`, the changed-key body, `Refuse`, `Accept new key`); the CLI's sentences are spec §11's or written out in their task.
- **Comments.** English in `cli/` and `session/`, like plan 1b-1; the frontend's like its neighbours (English); the spec's notes in Traditional Chinese.
- **Reading the code blocks.** As in plan 1b-1: "create", "create (only its tests for now …)", "insert above the `#[cfg(…)]` line", `diff` blocks for `git apply` against the file as the earlier steps left it, and "delete the file". The blocks were generated from the verified commits and replayed in order: every task ends on exactly the tree of its commit. Three binding files (`src/bindings/HostKey*.ts`) are written by a test run, as every ts-rs binding of the app is; Task 3 says what they must contain.

## Review Focus

The input classes and failure modes the spec implies that no happy path exercises, most likely first. Each has a test in the task named after it.

1. **Every way out of `sshelter connect` puts the terminal back** — the shell's exit, a lost connection, Ctrl-C while connecting, SIGTERM or SIGHUP, the broker going away, a panic: the person expects a terminal that echoes and edits lines again, with the reason on a line of its own. Pinned in Task 1: `the_terminal_is_put_back_when_the_tty_is_dropped_and_on_restore`, `a_panic_puts_the_terminal_back` and `the_broker_going_away_or_a_signal_ends_the_program_with_the_terminal_put_back`; in Task 2: `a_closed_terminal_ends_the_session`; in Task 6 every end-to-end test checks the terminal's mode at the end.
2. **A question in the middle of a session**: what was typed ahead must not become the password, a hidden prompt shows nothing, Ctrl-C or Ctrl-D cancels it, and a question asked while the shell is open goes back to raw mode afterwards. Pinned in Task 1: `a_password_question_is_asked_without_echo_and_the_answer_is_sent`, `ctrl_c_or_ctrl_d_at_a_question_cancels_it`, `a_code_question_shows_what_is_typed_and_a_question_in_the_open_shell_goes_back_to_raw` and `typeahead_reaches_the_shell_once_it_opens`; in Task 2: `a_question_is_asked_at_the_terminal_and_the_answer_gets_in`.
3. **An exit status that tells the truth**: never 0 for a lost connection (scripts and `&&` chains rely on it), 128 + n for a signal as a shell reports it, 255 when SSHelter went away. Pinned in Task 1: `exit_codes_follow_the_shell_and_a_signal_is_128_plus_its_number`, `a_lost_connection_is_said_on_a_line_of_its_own_and_exits_255` and `a_failed_connect_prints_the_reason_and_exits_255`; in Task 6: `a_connection_lost_in_the_middle_of_a_shell_is_said_and_the_status_is_255` and `sshelter_connect_confirms_the_host_key_runs_a_shell_and_exits_with_its_status` (and the first edit of Task 6's check that the tests can fail).
4. **The host-key window under pressure**: two questions at once, a question that times out or is withdrawn while the window shows it, the window closed with its close button, a keystroke or a second click that lands on the trust button the moment a new question appears. Pinned in Task 3: `a_changed_key_carries_the_pinned_one_and_answers_go_to_the_right_question`, `a_refusal_a_timeout_or_a_closed_window_is_no_trust`, `a_withdrawn_question_leaves_the_window` and `the_window_comes_to_the_front_only_for_a_new_question_at_the_head`, and the frontend's "keeps trust off until armed and both buttons off while an answer is on its way", "is not armed the moment a card mounts" and "arms the trust button after the delay, and a card that goes away first never arms".
5. **Closing the window, quitting, or a client starting the app while sessions are open**: closing the main window must not end the sessions, quitting must end each one with a reason its terminal prints, and a client that found nobody listening must get a listener even when the app was already running. Pinned in Task 4: `closing_the_window_hides_it_while_sessions_are_open`; the quit path is plan 1b-1's `quitting_ends_every_session_and_tells_each_client_why`; the Tauri glue around them needs the running app and is on the checklist of "What is left for the user".

## Amendments made during execution

The task texts below are what the drafter wrote before review; review and fix rounds changed the code after them. The branch, not the
task text, is the result, and the final review's list (`2026-10-13-own-ssh-phase1b-final-review-fixlist.md`) has the last word. The
larger changes, by task (commit ranges on `next/own-ssh`):

- Task 1: the CLI sanitises every text it prints outside the shell's data (the broker's `printable` rule, bidi controls included);
  typeahead goes in `DATA_CHUNK` frames; the terminal is put back before `close`; secrets are wiped and hidden from `Debug`
  (109dc87..81e4108).
- Task 2: SIGQUIT is caught; queued keys are dropped after a question's flush; a panic on any thread ends the program (255); the
  terminal is checked before SSHelter is reached or started (amendment 4e3cbe4..dc85988). Then the loop was redesigned: writer threads
  for the terminal and the broker, bounded output and keys, a watchdog, Ctrl-Z that puts the terminal back and stops for real (SIGCONT
  sets the mode again and asks again), a fatal failure to take over the signals, `args_os` (b53ac27..0645d5d); input typed at a question
  is flushed when the session ends under it, a write that would block waits, an end the session came to waits for a slow terminal, a
  hang-up is POLLHUP/EIO only (2db903a..66b596e); a signal ends that wait (805c5ce).
- Task 4: `session::broker::QUIT_WAIT` (not a local 3 s), the bounded `ssh -G`, `VaultKey` without `has_passphrase` (da5bf0a..25690ca);
  the listener is started once, decided under the status lock (5cc1bc7).
- Task 6: one line adapted to Task 2's `Zeroizing` keys (f445229); the doubles are named and the assertions can fail (e4c4529, a654556).
- Task 7: `ExecResult` kept for the tests; `#![cfg_attr(windows, allow(dead_code, unused_imports))]` on `session` and `ssh` (nothing calls
  them on Windows until phase 3); the spec notes corrected — a slow terminal makes the engine drop output with a notice, SSH's window is
  not involved (0240169..2546cce, 0864800, ed37ab3).
- The final fix wave (5860056..ed37ab3): a partly read `ssh -G` answer is an error; the broker closes a connection before its entry
  leaves the table; the CLI ends with a sentence on a message it cannot read; the host key window listens before it fetches; and the
  smaller items of the final review's list.

## File Structure

All paths under `src-tauri/src/` unless a path says otherwise.

- `cli/mod.rs` — `sshelter connect`: arguments, usage, starting the app, the Windows sentence (Tasks 1, 2, 6).
- `cli/terminal.rs` — the terminal's modes through termios, and putting them back (Task 1).
- `cli/client.rs` — the client's side of a session, without I/O (Task 1).
- `cli/run.rs` — the I/O of a session, the key and signal threads (Task 2).
- `cli/e2e_tests.rs` — `sshelter connect` the whole way against a scratch sshd (Task 6).
- `main.rs` — the `connect` mode (Task 2). `session/mod.rs` — `socket_path`, `ipc_dir` (Task 2), `SessionRuntime` (Tasks 3, 4).
- `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock` — tokio's `signal` feature (Task 2).
- `session/hostkey_window.rs`, `src-tauri/capabilities/hostkey.json`, `state.rs`, `lib.rs` (the commands, closing the window) — Task 3. `src/lib/hostkey.ts`, `src/components/HostKeyWindow.tsx` (with their tests), `src/main.tsx`, `src/bindings/HostKeyRequest.ts`, `PinnedHostKey.ts`, `HostKeyAnswer.ts` — Task 3.
- `session/app.rs`, `lib.rs` (setup, closing the main window, a second launch, quitting) — Task 4.
- `connect.rs`, `tray.rs`; deletions in `agent/` (`oneshot.rs`, `openssh_tests.rs`, `session.rs`, `mod.rs`), `deploy.rs`, `ipc/peer.rs`, `ipc/pipe_windows.rs`, `src/lib/agent.ts`, `src/lib/sync-events.ts` and their tests — Task 5.
- `lib.rs`, `ssh/` (the module's surface, dead test support), `session/pins.rs` — Task 7.
- `.github/workflows/test-engine.yml`, `.github/workflows/test-windows.yml` — `cli::` in CI (Task 2).
- `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` — §7.3, §7.4 and §10 (Task 7).

## Tasks

1. The terminal's modes and the client's side of a session
2. `sshelter connect`: start the app, relay the terminal, follow its size and signals
3. The host-key window
4. The broker in the app: start it, keep the app running for it, end its sessions on quit
5. Connect, the palette and the tray run `sshelter connect`; the password autofill and the one-shot key channel go
6. `sshelter connect` end to end against a scratch sshd
7. The engine and the broker private to the crate; `sshelter connect` in the spec

## How the tasks are cut

Plan 1b-1 ended with a broker that serves shells on a socket; this plan puts a terminal on one end and the app around it. The CLI is two tasks because its logic can be tested without a terminal (Task 1: the modes against a fake termios, the client as a state machine) and its I/O cannot (Task 2: the threads, the signals and the one Cargo change). The window (3) comes before the app wiring (4) because the wiring builds the broker with it. The Connect switch (5) is last of the visible changes: only when the app starts the broker and confirms host keys can the buttons run `sshelter connect`; it also deletes what the switch makes dead. Task 6 is tests only — the whole chain against a scratch sshd, with a check that the tests can fail — and Task 7 narrows the module surface once everything that uses it exists (R21) and records the CLI in the spec. Tasks 3 and 5 are the largest: Task 3 adds about 760 lines (Rust, React and their tests), Task 5 removes about 1,630 (most of them the one-shot channel).

## What this plan could not check on this machine, and where it deals with it

- A real terminal: raw mode in Terminal and iTerm2, a resize (SIGWINCH), Ctrl-C at a real prompt, a tab closed under a session (SIGHUP). The tests use a fake termios and send the signals' inputs directly; the checklist of "What is left for the user" covers the real thing.
- The real window and the running app: `TauriHostKeySurface` (creating, showing, destroying the `hostkey` window), the app's `setup`, hiding on close, quitting, the single-instance hand-over. No test launches the app (Global Constraints); what can be separated is tested — the hub, `note_head`, `hides_on_close`, `loaded_doc`, `vault_key_in`, and the React card in vitest.
- Starting a terminal from the Connect button (`connect::launch`, osascript on macOS): a side effect, not unit-tested, as before this plan; the argv it runs is tested.
- Windows: `sshelter connect`'s sentence, `launch_for`'s `ssh <alias>`, the broker's absence and the pipe changes compile only in CI (`test-windows.yml` gains `cli::` in Task 2).
- A development build next to the installed 0.17: both use the same app data directory; the checklist says what to look for.

---

### Task 1: The terminal's modes and the client's side of a session

**Files:**
- Create: `src-tauri/src/cli/mod.rs` (the module declarations)
- Create: `src-tauri/src/cli/terminal.rs`, `src-tauri/src/cli/client.rs` (each with its tests)
- Modify: `src-tauri/src/lib.rs` (`pub mod cli;`)

**Interfaces:**
- Consumes: `crate::session::protocol::{kinds, ClientKind, ClientMessage, Event, HostQuery, PtyRequest, Question, QuestionKind, ServerMessage, DATA_CHUNK, PROTOCOL_VERSION}` (plan 1b-1 Task 4); `libc` (`termios`, `tcgetattr`, `tcsetattr`, `ioctl(TIOCGWINSZ)`, the signal numbers); `zeroize::Zeroizing`.
- Produces (both files Unix only):
  - `cli/terminal.rs`:
    - `pub enum Mode { Cooked, Raw, Prompt { echo: bool } }`
    - `pub trait TermiosApi: Send + Sync { fn get(&self) -> io::Result<libc::termios>; fn set(&self, termios: &libc::termios, discard_input: bool) -> io::Result<()>; fn size(&self) -> Option<(u16, u16)>; }`
    - `pub fn attributes(original: &libc::termios, mode: Mode) -> libc::termios`
    - `pub struct Tty` with `new(api: Arc<dyn TermiosApi>) -> io::Result<Tty>`, `mode(&self) -> Mode`, `set_mode(&mut self, mode: Mode, discard_input: bool) -> io::Result<()>`, `size(&self) -> Option<(u16, u16)>`, `restore(&mut self)`, `restorer(&self) -> Restorer`, and `Drop` (restores)
    - `pub struct Restorer` with `restore(&self)`; `pub fn restore_on_panic(restorer: Restorer)`
    - `pub struct StdinTermios` (`impl TermiosApi` on standard input)
    - test builds: `fake::FakeTermios` with `new() -> Arc<FakeTermios>`, `now(&self) -> libc::termios`, `is_start(&self, &libc::termios) -> bool`, and the fields `start`, `sets`, `size`
  - `cli/client.rs`:
    - `pub enum Input { Message(ServerMessage), Output(Vec<u8>), Closed, Stdin(Vec<u8>), StdinEnd, Resize(u16, u16), Interrupt, Stop(i32) }`
    - `pub enum Action { Send(ClientMessage), SendData(Vec<u8>), Stdout(Vec<u8>), Stderr(String), Mode(Mode, bool), Exit(i32) }`
    - `pub fn exit_code(code: Option<u32>, signal: Option<&str>) -> i32`
    - `pub struct Client` with `start(host: HostQuery, term: String, size: (u16, u16)) -> (Client, Vec<Action>)` and `handle(&mut self, input: Input) -> Vec<Action>`

What shapes this task:
- R10: termios through `libc`, which the app already depends on for Unix (`[target.'cfg(unix)'.dependencies] libc = "0.2"`): no Cargo change at all. (R10 allowed `nix`'s `term` feature or `libc`; `nix` would be a new direct dependency.)
- Raw mode is OpenSSH's (`enter_raw_mode`, sshtty.c): input bytes untouched, no flow-control keys, no line editing, no echo, no keyboard signals, no output processing, `VMIN` 1. A question uses a prompt mode — line editing and signals as usual, echo off (`ECHO` and `ECHONL` cleared) when the question says so. The attributes of the start are what `Cooked` and every restore go back to.
- The terminal comes back on every way out (spec §7.3): `Tty::drop`, `Tty::restore`, and a panic hook installed once (`restore_on_panic`) that restores first, on whatever thread panics, and then lets the panic report as usual, on a terminal that echoes again.
- The client is a state machine without I/O (Task 2 does the I/O), so each rule is a unit test. It says `hello` and asks for a shell of the terminal's type and size. Until `opened` the terminal stays as it was — Ctrl-C still stops the program (SIGINT → `Interrupt` → `close`, exit 130) — and keys typed meanwhile are kept (up to 64 KiB) and sent when the shell opens, as OpenSSH's typeahead reaches the shell. At `opened` the terminal goes raw.
- A question: the prompt mode, with what was typed ahead thrown away first (`TCSAFLUSH`: it must not become the answer), the text on stderr, the answer collected up to Enter in a `Zeroizing` buffer and sent as `answer`; Ctrl-C (SIGINT in prompt mode) or Ctrl-D (the end of input) cancels it; afterwards the mode before the question comes back, raw for a question asked while the shell is open. The host-key notice and a banner are printed and need no answer.
- An `input` error while the shell is open is printed inline, `\r\n[text]\r\n`, and the session goes on; any other error or `disconnected` is kept and printed at the end.
- The end: the terminal is put back first, then the reason on a line of its own (a line break first when the shell was open), then the exit code (spec §7.3 as built): the shell's status (at most 255), 128 + the signal's number as a shell reports it, 255 when the shell ended without a status or SSHelter went away (`The connection to SSHelter ended.`), as ssh does; SIGTERM and SIGHUP send `close` and exit 128 + n; an end of input outside a question is the terminal going away, like SIGHUP.

- [ ] **Step 1: Write the tests**

`src-tauri/src/cli/client.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn started() -> Client {
        Client::start(HostQuery::Alias("web".into()), "xterm-256color".into(), (80, 24)).0
    }

    fn opened() -> Client {
        let mut client = started();
        client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() }));
        client
    }

    fn question(id: &str, kind: QuestionKind, text: &str, echo: bool) -> Input {
        Input::Message(ServerMessage::Question(Question { question_id: id.into(), kind, text: text.into(), echo, deadline_ms: Some(60_000) }))
    }

    #[test]
    fn it_says_hello_and_asks_for_a_shell_of_the_terminals_type_and_size() {
        let (_, actions) = Client::start(HostQuery::Id("0123456789abcdef".into()), "screen-256color".into(), (132, 43));
        assert_eq!(
            actions,
            [
                Action::Send(ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }),
                Action::Send(ClientMessage::OpenShell { host: HostQuery::Id("0123456789abcdef".into()), pty: PtyRequest { cols: 132, rows: 43, term: "screen-256color".into() } }),
            ]
        );
    }

    #[test]
    fn once_the_shell_is_open_the_terminal_is_raw_and_keys_output_and_resizes_pass_through() {
        let mut client = started();
        assert_eq!(client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() })), [Action::Mode(Mode::Raw, false)]);
        assert_eq!(client.handle(Input::Stdin(b"ls\r".to_vec())), [Action::SendData(b"ls\r".to_vec())]);
        assert_eq!(client.handle(Input::Output(b"file\r\n".to_vec())), [Action::Stdout(b"file\r\n".to_vec())]);
        assert_eq!(client.handle(Input::Resize(100, 30)), [Action::Send(ClientMessage::WindowChange { cols: 100, rows: 30 })]);
        let pasted = vec![b'x'; DATA_CHUNK + 10];
        assert_eq!(client.handle(Input::Stdin(pasted)).len(), 2, "a large paste goes out in data frames of at most DATA_CHUNK bytes");
    }

    /// What was typed while connecting reaches the shell once it is open (OpenSSH behaves the same).
    #[test]
    fn typeahead_reaches_the_shell_once_it_opens() {
        let mut client = started();
        assert!(client.handle(Input::Stdin(b"uptime\n".to_vec())).is_empty());
        assert_eq!(client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() })), [Action::Mode(Mode::Raw, false), Action::SendData(b"uptime\n".to_vec())]);
    }

    /// Spec §7.3: a question leaves raw mode (or the terminal as it was), asks without echo for a password, sends the answer and goes
    /// back; typeahead is thrown away, so it cannot become the password.
    #[test]
    fn a_password_question_is_asked_without_echo_and_the_answer_is_sent() {
        let mut client = started();
        client.handle(Input::Stdin(b"ls\n".to_vec()));
        assert_eq!(
            client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false)),
            [Action::Mode(Mode::Prompt { echo: false }, true), Action::Stderr("deploy@web's password: ".into())]
        );
        assert!(client.handle(Input::Stdin(b"hunt".to_vec())).is_empty(), "the answer is collected until Enter");
        assert_eq!(
            client.handle(Input::Stdin(b"er2\n".to_vec())),
            [
                Action::Stderr("\n".into()),
                Action::Send(ClientMessage::Answer { question_id: "q1".into(), value: Some("hunter2".into()), cancel: false }),
                Action::Mode(Mode::Cooked, false),
            ]
        );
        assert_eq!(client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() })), [Action::Mode(Mode::Raw, false)], "the typeahead from before the question is gone");
    }

    #[test]
    fn a_code_question_shows_what_is_typed_and_a_question_in_the_open_shell_goes_back_to_raw() {
        let mut client = opened();
        assert_eq!(client.handle(question("q2", QuestionKind::Interactive, "(deploy@web) Code: ", true))[0], Action::Mode(Mode::Prompt { echo: true }, true));
        assert_eq!(
            client.handle(Input::Stdin(b"123456\r\n".to_vec())),
            [Action::Send(ClientMessage::Answer { question_id: "q2".into(), value: Some("123456".into()), cancel: false }), Action::Mode(Mode::Raw, false)]
        );
    }

    #[test]
    fn ctrl_c_or_ctrl_d_at_a_question_cancels_it() {
        for input in [Input::Interrupt, Input::StdinEnd] {
            let mut client = started();
            client.handle(question("q1", QuestionKind::Passphrase, "Enter the passphrase for the key laptop: ", false));
            assert_eq!(
                client.handle(input),
                [Action::Stderr("\n".into()), Action::Send(ClientMessage::Answer { question_id: "q1".into(), value: None, cancel: true }), Action::Mode(Mode::Cooked, false)]
            );
        }
    }

    #[test]
    fn the_host_key_notice_and_a_banner_are_printed_and_need_no_answer() {
        let mut client = started();
        assert_eq!(
            client.handle(question("q1", QuestionKind::HostKeyNotice, "Waiting for you to confirm web's host key in SSHelter.", false)),
            [Action::Stderr("Waiting for you to confirm web's host key in SSHelter.\n".into())]
        );
        assert_eq!(client.handle(Input::Message(ServerMessage::Event(Event::Banner { text: "Authorized use only.".into() }))), [Action::Stderr("Authorized use only.\n".into())]);
    }

    /// Spec §7.3: the terminal is put back before anything else, then the program exits with the shell's status.
    #[test]
    fn the_shells_exit_status_becomes_the_programs_after_the_terminal_is_put_back() {
        let mut client = opened();
        assert_eq!(client.handle(Input::Message(ServerMessage::Exited { code: Some(3), signal: None })), [Action::Mode(Mode::Cooked, false), Action::Exit(3)]);
        assert!(client.handle(Input::Output(b"late".to_vec())).is_empty(), "nothing after the end");
    }

    #[test]
    fn a_lost_connection_is_said_on_a_line_of_its_own_and_exits_255() {
        let mut client = opened();
        assert!(client.handle(Input::Message(ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost (no response for 120 seconds).".into() }))).is_empty());
        assert_eq!(
            client.handle(Input::Message(ServerMessage::Exited { code: None, signal: None })),
            [Action::Mode(Mode::Cooked, false), Action::Stderr("\nConnection to web lost (no response for 120 seconds).\n".into()), Action::Exit(255)]
        );
    }

    #[test]
    fn a_failed_connect_prints_the_reason_and_exits_255() {
        let mut client = started();
        client.handle(Input::Message(ServerMessage::Event(Event::Error { kind: kinds::HOST.into(), text: "No saved host is called web.".into() })));
        assert_eq!(
            client.handle(Input::Message(ServerMessage::Exited { code: None, signal: None })),
            [Action::Mode(Mode::Cooked, false), Action::Stderr("No saved host is called web.\n".into()), Action::Exit(255)]
        );
    }

    #[test]
    fn input_that_did_not_reach_the_server_is_said_inline_and_the_shell_goes_on() {
        let mut client = opened();
        let error = Event::Error { kind: kinds::INPUT.into(), text: "What you typed did not reach web in time: the connection is not responding.".into() };
        assert_eq!(client.handle(Input::Message(ServerMessage::Event(error))), [Action::Stderr("\r\n[What you typed did not reach web in time: the connection is not responding.]\r\n".into())]);
        assert_eq!(client.handle(Input::Stdin(b"x".to_vec())), [Action::SendData(b"x".to_vec())]);
    }

    #[test]
    fn the_broker_going_away_or_a_signal_ends_the_program_with_the_terminal_put_back() {
        let mut client = opened();
        assert_eq!(client.handle(Input::Closed), [Action::Mode(Mode::Cooked, false), Action::Stderr("\nThe connection to SSHelter ended.\n".into()), Action::Exit(255)]);
        let mut client = opened();
        assert_eq!(client.handle(Input::Stop(libc::SIGTERM)), [Action::Send(ClientMessage::Close), Action::Mode(Mode::Cooked, false), Action::Exit(128 + libc::SIGTERM)]);
        let mut client = started();
        assert_eq!(client.handle(Input::Interrupt), [Action::Send(ClientMessage::Close), Action::Mode(Mode::Cooked, false), Action::Exit(130)], "Ctrl-C while connecting stops it");
    }

    /// Spec §7.3 / plan 1b R10: the shell's status, 128 + the signal's number for a signal (as a shell reports it), 255 for neither.
    #[test]
    fn exit_codes_follow_the_shell_and_a_signal_is_128_plus_its_number() {
        assert_eq!(exit_code(Some(0), None), 0);
        assert_eq!(exit_code(Some(42), None), 42);
        assert_eq!(exit_code(Some(70_000), None), 255, "more than a status can say is 255");
        assert_eq!(exit_code(None, Some("KILL")), 137);
        assert_eq!(exit_code(None, Some("TERM")), 143);
        assert_eq!(exit_code(None, Some("HUP")), 129);
        assert_eq!(exit_code(None, Some("WINCH")), 255, "a signal SSH does not name");
        assert_eq!(exit_code(None, None), 255, "a lost connection, as ssh");
    }
}
```

`src-tauri/src/cli/mod.rs`: create

```rust
//! `sshelter connect` (own-ssh spec §7.3): the terminal's end of a session in the app. macOS and Linux in this version; on Windows it
//! says so (plan 1b; the Windows console is phase 3).

#[cfg(unix)]
pub mod client;
#[cfg(unix)]
pub mod terminal;
```

`src-tauri/src/cli/terminal.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::fake::FakeTermios;
    use super::*;

    #[test]
    fn raw_mode_is_openssh_s_raw_mode_and_cooked_is_the_start() {
        let api = FakeTermios::new();
        let raw = attributes(&api.start, Mode::Raw);
        assert_eq!(raw.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN), 0, "no line editing, echo or keyboard signals");
        assert_eq!(raw.c_iflag & (libc::ICRNL | libc::IXON), 0, "Enter stays a carriage return and Ctrl-S goes to the shell");
        assert_eq!(raw.c_oflag & libc::OPOST, 0, "output is passed through");
        assert_eq!((raw.c_cc[libc::VMIN], raw.c_cc[libc::VTIME]), (1, 0), "a read returns every byte at once");
        assert!(api.is_start(&attributes(&api.start, Mode::Cooked)));
    }

    #[test]
    fn a_question_edits_lines_and_hides_a_password_but_shows_a_code() {
        let api = FakeTermios::new();
        let secret = attributes(&api.start, Mode::Prompt { echo: false });
        assert_eq!(secret.c_lflag & (libc::ICANON | libc::ISIG), libc::ICANON | libc::ISIG);
        assert_eq!(secret.c_lflag & (libc::ECHO | libc::ECHONL), 0);
        let shown = attributes(&api.start, Mode::Prompt { echo: true });
        assert_eq!(shown.c_lflag & libc::ECHO, libc::ECHO);
    }

    #[test]
    fn the_terminal_is_put_back_when_the_tty_is_dropped_and_on_restore() {
        let api = FakeTermios::new();
        {
            let mut tty = Tty::new(api.clone()).unwrap();
            tty.set_mode(Mode::Raw, false).unwrap();
            assert_eq!(tty.mode(), Mode::Raw);
            tty.set_mode(Mode::Prompt { echo: false }, true).unwrap();
            assert!(api.sets.lock().unwrap().last().unwrap().1, "a question throws away the typeahead");
        }
        assert!(api.is_start(&api.now()), "dropped: back to the start");

        let mut tty = Tty::new(api.clone()).unwrap();
        tty.set_mode(Mode::Raw, false).unwrap();
        tty.restore();
        assert!(api.is_start(&api.now()));
        let count = api.sets.lock().unwrap().len();
        drop(tty);
        assert_eq!(api.sets.lock().unwrap().len(), count, "nothing more to put back");
    }

    /// Spec §7.3: every way out, a panic too, puts the terminal back, before the panic message is printed.
    #[test]
    fn a_panic_puts_the_terminal_back() {
        let api = FakeTermios::new();
        let mut tty = Tty::new(api.clone()).unwrap();
        tty.set_mode(Mode::Raw, false).unwrap();
        restore_on_panic(tty.restorer());
        let crashed = std::thread::spawn(|| panic!("the CLI failed")).join();
        assert!(crashed.is_err());
        assert!(api.is_start(&api.now()), "the hook restored the terminal");
    }
}
```

`src-tauri/src/lib.rs`: apply this patch

```diff
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -1,5 +1,6 @@
 mod agent;
 pub mod askpass;
+pub mod cli;
 mod sync;
 mod config;
 mod connect;
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- cli::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0432]: unresolved import `super::fake`
error: could not compile `sshelter` (lib test) due to 153 previous errors; 2 warnings emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/cli/client.rs`: insert above the `#[cfg(test)]` line

```rust
//! The client's side of one session (own-ssh spec §7.3), with no I/O of its own: it is told what happened (`Input`) and answers with
//! what to do (`Action`); `run.rs` does the reading and writing. Until the shell is open the terminal stays as it was, so Ctrl-C still
//! stops the program; questions are asked with the terminal in its prompt mode; once the shell is open the terminal is raw and every
//! key goes to the shell; at the end the terminal is put back before anything is printed.

use zeroize::Zeroizing;

use super::terminal::Mode;
use crate::session::protocol::{kinds, ClientKind, ClientMessage, Event, HostQuery, PtyRequest, Question, QuestionKind, ServerMessage, DATA_CHUNK, PROTOCOL_VERSION};

/// What happened.
#[derive(Debug)]
pub enum Input {
    /// A control message from the broker.
    Message(ServerMessage),
    /// Terminal output from the broker.
    Output(Vec<u8>),
    /// The broker closed the connection.
    Closed,
    /// Bytes the person typed.
    Stdin(Vec<u8>),
    /// Standard input ended (Ctrl-D on an empty line, at a question).
    StdinEnd,
    /// The terminal was resized.
    Resize(u16, u16),
    /// Ctrl-C while the terminal was not raw (SIGINT).
    Interrupt,
    /// The program was told to stop, or its terminal went away (SIGTERM, SIGHUP): the signal's number.
    Stop(i32),
}

/// What to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Send(ClientMessage),
    SendData(Vec<u8>),
    Stdout(Vec<u8>),
    Stderr(String),
    /// Set the terminal's mode; `true` throws away what was typed ahead first.
    Mode(Mode, bool),
    Exit(i32),
}

/// What the person typed before the shell opened is kept for it (as OpenSSH's typeahead reaches the shell), up to this many bytes.
const TYPEAHEAD_LIMIT: usize = 64 * 1024;

enum Phase {
    Connecting,
    /// A question is on the terminal; the answer is collected until Enter.
    Asking { question_id: String, echo: bool, line: Zeroizing<Vec<u8>>, after: Mode },
    Open,
    Ended,
}

/// The exit status of `sshelter connect` for a shell that ended with `code` or was killed by `signal` (spec §7.3): the shell's own
/// status; for a signal 128 + its number, as a shell reports it; 255 when it ended without either (a lost connection), as ssh does.
pub fn exit_code(code: Option<u32>, signal: Option<&str>) -> i32 {
    match (code, signal) {
        (Some(code), _) => code.min(255) as i32,
        (None, Some(signal)) => signal_number(signal).map(|number| 128 + number).unwrap_or(255),
        (None, None) => 255,
    }
}

/// The local number of a signal named as SSH names it (RFC 4254 §6.10, without `SIG`).
fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "ABRT" => libc::SIGABRT,
        "ALRM" => libc::SIGALRM,
        "FPE" => libc::SIGFPE,
        "HUP" => libc::SIGHUP,
        "ILL" => libc::SIGILL,
        "INT" => libc::SIGINT,
        "KILL" => libc::SIGKILL,
        "PIPE" => libc::SIGPIPE,
        "QUIT" => libc::SIGQUIT,
        "SEGV" => libc::SIGSEGV,
        "TERM" => libc::SIGTERM,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        _ => return None,
    })
}

/// The client of one session.
pub struct Client {
    phase: Phase,
    /// Bytes typed before the shell opened.
    typeahead: Zeroizing<Vec<u8>>,
    /// What to say when it ends: why the connection ended or failed.
    reason: Option<String>,
}

impl Client {
    /// A client that opens a shell on `host` for a terminal of type `term` and size `size`; the actions say hello and ask for the shell.
    pub fn start(host: HostQuery, term: String, size: (u16, u16)) -> (Client, Vec<Action>) {
        let client = Client { phase: Phase::Connecting, typeahead: Zeroizing::new(Vec::new()), reason: None };
        let actions = vec![
            Action::Send(ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }),
            Action::Send(ClientMessage::OpenShell { host, pty: PtyRequest { cols: size.0, rows: size.1, term } }),
        ];
        (client, actions)
    }

    fn mode(&self) -> Mode {
        match self.phase {
            Phase::Open => Mode::Raw,
            Phase::Asking { echo, .. } => Mode::Prompt { echo },
            Phase::Connecting | Phase::Ended => Mode::Cooked,
        }
    }

    pub fn handle(&mut self, input: Input) -> Vec<Action> {
        if matches!(self.phase, Phase::Ended) {
            return Vec::new();
        }
        match input {
            Input::Message(message) => self.message(message),
            Input::Output(bytes) => vec![Action::Stdout(bytes)],
            Input::Closed => {
                let reason = self.reason.take().unwrap_or_else(|| "The connection to SSHelter ended.".to_string());
                self.finish(Some(reason), 255)
            }
            Input::Stdin(bytes) => self.typed(&bytes),
            Input::StdinEnd | Input::Interrupt if matches!(self.phase, Phase::Asking { .. }) => self.answer(None),
            Input::Interrupt => {
                let mut actions = vec![Action::Send(ClientMessage::Close)];
                actions.extend(self.finish(None, 130));
                actions
            }
            Input::StdinEnd => {
                let mut actions = vec![Action::Send(ClientMessage::Close)];
                actions.extend(self.finish(None, 128 + libc::SIGHUP));
                actions
            }
            Input::Resize(cols, rows) => vec![Action::Send(ClientMessage::WindowChange { cols, rows })],
            Input::Stop(signal) => {
                let mut actions = vec![Action::Send(ClientMessage::Close)];
                actions.extend(self.finish(None, 128 + signal));
                actions
            }
        }
    }

    fn message(&mut self, message: ServerMessage) -> Vec<Action> {
        match message {
            ServerMessage::Opened { .. } => {
                self.phase = Phase::Open;
                let mut actions = vec![Action::Mode(Mode::Raw, false)];
                if !self.typeahead.is_empty() {
                    actions.push(Action::SendData(std::mem::take(&mut *self.typeahead)));
                }
                actions
            }
            ServerMessage::Question(Question { kind: QuestionKind::HostKeyNotice, text, .. }) => vec![Action::Stderr(format!("{text}\n"))],
            ServerMessage::Question(Question { question_id, text, echo, .. }) => {
                let after = self.mode();
                self.typeahead.clear();
                self.phase = Phase::Asking { question_id, echo, line: Zeroizing::new(Vec::new()), after };
                vec![Action::Mode(Mode::Prompt { echo }, true), Action::Stderr(text)]
            }
            ServerMessage::Event(Event::Banner { text }) => {
                let text = if text.ends_with('\n') { text } else { format!("{text}\n") };
                vec![Action::Stderr(text)]
            }
            ServerMessage::Event(Event::Error { kind, text }) if kind == kinds::INPUT && matches!(self.phase, Phase::Open) => {
                vec![Action::Stderr(format!("\r\n[{text}]\r\n"))]
            }
            ServerMessage::Event(Event::Error { text, .. }) | ServerMessage::Event(Event::Disconnected { reason: text }) => {
                self.reason = Some(text);
                Vec::new()
            }
            ServerMessage::Event(Event::Connected) => Vec::new(),
            ServerMessage::Exited { code, signal } => {
                let reason = self.reason.take();
                self.finish(reason, exit_code(code, signal.as_deref()))
            }
        }
    }

    fn typed(&mut self, bytes: &[u8]) -> Vec<Action> {
        match &mut self.phase {
            Phase::Connecting => {
                let room = TYPEAHEAD_LIMIT.saturating_sub(self.typeahead.len());
                self.typeahead.extend_from_slice(&bytes[..bytes.len().min(room)]);
                Vec::new()
            }
            Phase::Asking { line, .. } => {
                line.extend_from_slice(bytes);
                match line.iter().position(|byte| *byte == b'\n' || *byte == b'\r') {
                    Some(end) => {
                        let answer = Zeroizing::new(String::from_utf8_lossy(&line[..end]).into_owned());
                        self.answer(Some(answer))
                    }
                    None => Vec::new(),
                }
            }
            Phase::Open => bytes.chunks(DATA_CHUNK).map(|chunk| Action::SendData(chunk.to_vec())).collect(),
            Phase::Ended => Vec::new(),
        }
    }

    /// Ends the question on the terminal: with the answer, or cancelled (`None`).
    fn answer(&mut self, answer: Option<Zeroizing<String>>) -> Vec<Action> {
        let Phase::Asking { question_id, echo, after, .. } = std::mem::replace(&mut self.phase, Phase::Connecting) else { return Vec::new() };
        self.phase = if after == Mode::Raw { Phase::Open } else { Phase::Connecting };
        let mut actions = Vec::new();
        if !echo || answer.is_none() {
            // The Enter of a hidden answer (or the Ctrl-C) did not move to the next line.
            actions.push(Action::Stderr("\n".to_string()));
        }
        let message = match answer {
            Some(answer) => ClientMessage::Answer { question_id, value: Some(answer.to_string()), cancel: false },
            None => ClientMessage::Answer { question_id, value: None, cancel: true },
        };
        actions.push(Action::Send(message));
        actions.push(Action::Mode(after, false));
        actions
    }

    /// The end: the terminal is put back first, then the reason is printed on a line of its own, then the program exits.
    fn finish(&mut self, reason: Option<String>, code: i32) -> Vec<Action> {
        let was_open = matches!(self.phase, Phase::Open) || matches!(self.phase, Phase::Asking { after: Mode::Raw, .. });
        self.phase = Phase::Ended;
        let mut actions = vec![Action::Mode(Mode::Cooked, false)];
        if let Some(reason) = reason {
            actions.push(Action::Stderr(if was_open { format!("\n{reason}\n") } else { format!("{reason}\n") }));
        }
        actions.push(Action::Exit(code));
        actions
    }
}
```

`src-tauri/src/cli/terminal.rs`: insert above the `#[cfg(test)]` line

```rust
//! The terminal `sshelter connect` runs in (own-ssh spec §7.3): its modes and its size, through termios (`libc`, already a dependency
//! on Unix). Raw while the shell runs, the way OpenSSH sets it; a prompt mode for questions (line editing on, echo off for a password);
//! cooked otherwise. The mode the terminal had at the start comes back on every way out: the end of the program, a dropped `Tty`, and a
//! panic (`restore_on_panic`).

use std::io;
use std::sync::{Arc, Mutex, Once, PoisonError};

/// What the terminal is set to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// As it was when the program started.
    Cooked,
    /// Every key goes to the shell as it is pressed; no echo, no signals from the keyboard, no output processing.
    Raw,
    /// A question: lines are edited and signals work as usual; what is typed is shown only when `echo`.
    Prompt { echo: bool },
}

/// Reading and setting the terminal's attributes (termios) and reading its size. The real one works on standard input; tests use a fake.
pub trait TermiosApi: Send + Sync {
    fn get(&self) -> io::Result<libc::termios>;
    /// Sets the attributes; with `discard_input`, what was typed and not read yet is thrown away first (`TCSAFLUSH`).
    fn set(&self, termios: &libc::termios, discard_input: bool) -> io::Result<()>;
    /// Columns and rows; `None` when it cannot be read.
    fn size(&self) -> Option<(u16, u16)>;
}

/// The attributes for `mode`, from the ones the terminal had at the start.
pub fn attributes(original: &libc::termios, mode: Mode) -> libc::termios {
    let mut termios = *original;
    match mode {
        Mode::Cooked => {}
        Mode::Raw => {
            // OpenSSH's enter_raw_mode (sshtty.c): input bytes untouched, no flow control keys, no line editing, echo or keyboard signals,
            // no output processing.
            termios.c_iflag |= libc::IGNPAR;
            termios.c_iflag &= !(libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::ICRNL | libc::IXON | libc::IXANY | libc::IXOFF);
            termios.c_lflag &= !(libc::ISIG | libc::ICANON | libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::IEXTEN);
            termios.c_oflag &= !libc::OPOST;
            termios.c_cc[libc::VMIN] = 1;
            termios.c_cc[libc::VTIME] = 0;
        }
        Mode::Prompt { echo } => {
            termios.c_lflag |= libc::ICANON | libc::ISIG;
            if echo {
                termios.c_lflag |= libc::ECHO;
            } else {
                termios.c_lflag &= !(libc::ECHO | libc::ECHONL);
            }
        }
    }
    termios
}

/// The terminal of this run. Dropping it puts the terminal back as it was.
pub struct Tty {
    api: Arc<dyn TermiosApi>,
    original: libc::termios,
    mode: Mode,
}

impl Tty {
    /// Remembers the terminal's attributes as they are now: they are what `Mode::Cooked` and every restore go back to.
    pub fn new(api: Arc<dyn TermiosApi>) -> io::Result<Tty> {
        let original = api.get()?;
        Ok(Tty { api, original, mode: Mode::Cooked })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Sets `mode`; `discard_input` throws away what was typed ahead first (a question must not take typeahead as its answer).
    pub fn set_mode(&mut self, mode: Mode, discard_input: bool) -> io::Result<()> {
        self.api.set(&attributes(&self.original, mode), discard_input)?;
        self.mode = mode;
        Ok(())
    }

    pub fn size(&self) -> Option<(u16, u16)> {
        self.api.size()
    }

    /// Back to the attributes of the start.
    pub fn restore(&mut self) {
        if self.mode != Mode::Cooked {
            let _ = self.api.set(&self.original, false);
            self.mode = Mode::Cooked;
        }
    }

    /// What a panic hook needs to put the terminal back.
    pub fn restorer(&self) -> Restorer {
        Restorer { api: Arc::clone(&self.api), original: self.original }
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Puts a terminal back to its attributes of the start, from wherever the program is.
#[derive(Clone)]
pub struct Restorer {
    api: Arc<dyn TermiosApi>,
    original: libc::termios,
}

impl Restorer {
    pub fn restore(&self) {
        let _ = self.api.set(&self.original, false);
    }
}

static PANIC_RESTORER: Mutex<Option<Restorer>> = Mutex::new(None);
static PANIC_HOOK: Once = Once::new();

/// From now on a panic, on any thread, first puts the terminal back, then reports as usual: the message lands on a terminal that
/// echoes again and starts at the left margin. The latest `restorer` counts.
pub fn restore_on_panic(restorer: Restorer) {
    *PANIC_RESTORER.lock().unwrap_or_else(PoisonError::into_inner) = Some(restorer);
    PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(restorer) = PANIC_RESTORER.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
                restorer.restore();
            }
            previous(info);
        }));
    });
}

/// The terminal on standard input.
#[cfg(unix)]
pub struct StdinTermios;

#[cfg(unix)]
impl TermiosApi for StdinTermios {
    fn get(&self) -> io::Result<libc::termios> {
        // SAFETY: `termios` is plain data that tcgetattr fills in completely on success.
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut termios) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(termios)
        }
    }

    fn set(&self, termios: &libc::termios, discard_input: bool) -> io::Result<()> {
        let when = if discard_input { libc::TCSAFLUSH } else { libc::TCSANOW };
        // SAFETY: a valid termios for a valid descriptor.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, when, termios) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn size(&self) -> Option<(u16, u16)> {
        // SAFETY: TIOCGWINSZ fills a winsize.
        unsafe {
            let mut size: libc::winsize = std::mem::zeroed();
            (libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut size) == 0 && size.ws_col > 0 && size.ws_row > 0).then_some((size.ws_col, size.ws_row))
        }
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    /// A terminal that records every change of attributes; its size can be changed by the test.
    pub struct FakeTermios {
        pub start: libc::termios,
        pub sets: Mutex<Vec<(libc::termios, bool)>>,
        pub size: Mutex<Option<(u16, u16)>>,
    }

    impl FakeTermios {
        pub fn new() -> Arc<FakeTermios> {
            // SAFETY: an all-zero termios is valid plain data; the flags below make it look like a terminal in its usual mode.
            let mut start: libc::termios = unsafe { std::mem::zeroed() };
            start.c_iflag = libc::ICRNL | libc::IXON;
            start.c_oflag = libc::OPOST;
            start.c_lflag = libc::ICANON | libc::ISIG | libc::ECHO | libc::IEXTEN;
            start.c_cc[libc::VMIN] = 4;
            Arc::new(FakeTermios { start, sets: Mutex::new(Vec::new()), size: Mutex::new(Some((80, 24))) })
        }

        /// The attributes set last, or the start's.
        pub fn now(&self) -> libc::termios {
            self.sets.lock().unwrap().last().map(|(termios, _)| *termios).unwrap_or(self.start)
        }

        pub fn is_start(&self, termios: &libc::termios) -> bool {
            (termios.c_iflag, termios.c_oflag, termios.c_lflag, termios.c_cc[libc::VMIN]) == (self.start.c_iflag, self.start.c_oflag, self.start.c_lflag, self.start.c_cc[libc::VMIN])
        }
    }

    impl TermiosApi for FakeTermios {
        fn get(&self) -> io::Result<libc::termios> {
            Ok(self.start)
        }
        fn set(&self, termios: &libc::termios, discard_input: bool) -> io::Result<()> {
            self.sets.lock().unwrap().push((*termios, discard_input));
            Ok(())
        }
        fn size(&self) -> Option<(u16, u16)> {
            *self.size.lock().unwrap()
        }
    }
}
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- cli::)
```

Expected: PASS, `test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 1686 filtered out`.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1701 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/cli/client.rs \
  src-tauri/src/cli/mod.rs \
  src-tauri/src/cli/terminal.rs \
  src-tauri/src/lib.rs
git commit -m "feat(cli): add the terminal modes and the client side of a session for sshelter connect"
```

Expected: `git status --short` lists the four files of this task; the `git diff --stat` prints nothing.

---

### Task 2: `sshelter connect`: start the app, relay the terminal, follow its size and signals

**Files:**
- Create: `src-tauri/src/cli/run.rs` (with its tests)
- Modify: `src-tauri/src/cli/mod.rs` (`run_connect` and its helpers, with their tests), `src-tauri/src/main.rs` (the `connect` mode), `src-tauri/src/session/mod.rs` (`socket_path`, `ipc_dir`)
- Modify: `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock` (tokio's `signal` feature)
- Modify: `.github/workflows/test-engine.yml`, `.github/workflows/test-windows.yml` (`cli::`)

**Interfaces:**
- Consumes: Task 1 (`Client`, `Input`, `Action`, `Tty`, `StdinTermios`, `restore_on_panic`, `FakeTermios`); plan 1b-1 Task 5 (`host_start::{ensure_started, take_spawn_locks, start_host, START_WAIT}`) and Task 4 (`read_frame`, `write_control`, `write_data`, `decode`, `Frame`, `HostQuery`, `ServerMessage`); `crate::fsutil::app_data_root()`; `tokio::signal::unix::{signal, SignalKind}` (with the `signal` feature); in the tests plan 1b-1's `Broker`, `FakeDirectory`, `FakeKeys`, `FakeConfirmer`, `FakeEngine` and `MemKeychain`.
- Produces:
  - `session/mod.rs`: `pub fn socket_path(app_data: &Path) -> PathBuf` (`<app data>/ipc/sock`), `pub fn ipc_dir(app_data: &Path) -> PathBuf` (`<app data>/ipc`)
  - `cli/mod.rs`: `pub const NOT_STARTED: &str = "SSHelter did not start within 12 seconds."`, `pub const USAGE: &str`, `pub fn parse_args(args: &[String]) -> Result<HostQuery, String>`, `pub fn term_from(value: Option<std::ffi::OsString>) -> String`, `pub fn run_connect(args: &[String]) -> i32` (on Windows: the sentence and 1)
  - `cli/run.rs` (Unix): `pub fn run(stream: UnixStream, host: HostQuery, term: String, tty: &mut Tty, inputs: (Sender<Input>, Receiver<Input>), stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32`, `pub fn stdin_thread(sender: Sender<Input>)`, `pub fn signal_thread(sender: Sender<Input>, size: impl Fn() -> Option<(u16, u16)> + Send + 'static) -> std::io::Result<()>`
  - `main.rs`: `sshelter connect …` exits with `cli::run_connect(&args[2..])`, before anything of Tauri runs

What shapes this task:
- Spec §4 and R6: when the socket does not answer, `run_connect` starts SSHelter through plan 1b-1's `host_start::ensure_started` — the same locks as the MCP adapter, the app started hidden with `--host` — and says spec §11's `SSHelter did not start within 12 seconds.` with exit code 1 when nothing answers. The socket's path is computed without the app (`session::socket_path(app_data_root)`); the app's broker listens on the same path (Task 4).
- R10's arguments: `sshelter connect <alias>` or `sshelter connect --id <host id>`; anything else — an alias that starts with a dash included, which would read as an option — prints the usage and exits 2. The terminal type is `$TERM`, `xterm-256color` without one. Without a terminal on standard input: `sshelter connect needs a terminal.`, exit 1.
- The I/O meets in one queue of `Input`s: the broker's frames on a reader thread; the keys on a thread that reads standard input (in raw mode a Ctrl-D is a byte for the shell, so the end of input means the terminal went away); the signals on a thread of their own that runs a current-thread tokio runtime with SIGWINCH (the new size is read then), SIGINT, SIGTERM and SIGHUP. With the handlers in place none of these ends the program by itself: the client decides, and the terminal is put back first.
- R13: tokio gains `signal`, the one Cargo change of plan 1b (Step 3). The lock gains one line, tokio's dependency list naming `signal-hook-registry`, which the lock already holds; no crate is added. From the end of Step 3 on, every command is `--locked` again.
- Windows (R4): `run_connect` prints `sshelter connect is not supported on Windows yet.` and returns 1. A release build there has no console, so the sentence is seen only where one exists; the console work is phase 3.
- The tests of `run.rs` run the CLI's loop against plan 1b-1's broker over a Unix socket pair, with the fake engine and the fake termios; `cli/mod.rs`'s tests check the arguments, `$TERM` and the "did not start" path without starting anything.
- CI: `cli::` joins both workflows' filters (Step 6).

- [ ] **Step 1: Write the tests**

`src-tauri/src/cli/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/cli/mod.rs
+++ b/src-tauri/src/cli/mod.rs
@@ -4,4 +4,49 @@
 #[cfg(unix)]
 pub mod client;
 #[cfg(unix)]
+pub mod run;
+#[cfg(unix)]
 pub mod terminal;
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    fn args(list: &[&str]) -> Vec<String> {
+        list.iter().map(|arg| arg.to_string()).collect()
+    }
+
+    #[test]
+    fn an_alias_or_an_id_names_the_host_and_anything_else_shows_the_usage() {
+        assert_eq!(parse_args(&args(&["web"])), Ok(HostQuery::Alias("web".into())));
+        assert_eq!(parse_args(&args(&["--id", "0123456789abcdef"])), Ok(HostQuery::Id("0123456789abcdef".into())));
+        for wrong in [&[][..], &["--id"], &["web", "db"], &["-oProxyCommand=x"], &["--id", "-x"], &[""], &["--new-tab", "web"]] {
+            assert_eq!(parse_args(&args(wrong)), Err(USAGE.to_string()), "{wrong:?}");
+        }
+    }
+
+    #[test]
+    fn the_terminal_type_is_term_or_xterm_256color() {
+        assert_eq!(term_from(Some("screen-256color".into())), "screen-256color");
+        assert_eq!(term_from(Some("".into())), "xterm-256color");
+        assert_eq!(term_from(None), "xterm-256color");
+    }
+
+    /// Spec §11: the sentence, exactly, when the app does not answer.
+    #[test]
+    fn when_nothing_answers_after_the_start_the_cli_says_sshelter_did_not_start() {
+        use crate::host_start::{ensure_started, SpawnLocks};
+        let mut starts = 0;
+        let result: Result<(), String> = ensure_started(
+            || None,
+            || SpawnLocks::Held(()),
+            || {
+                starts += 1;
+                Ok(())
+            },
+            std::time::Duration::ZERO,
+            NOT_STARTED,
+        );
+        assert_eq!((result, starts), (Err("SSHelter did not start within 12 seconds.".to_string()), 1));
+    }
+}
```

`src-tauri/src/cli/run.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::cli::terminal::fake::FakeTermios;
    use crate::session::broker::Broker;
    use crate::session::connect::HostKeyConfirmer;
    use crate::session::directory::HostDirectory;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods};
    use crate::ssh::testing::eventually;
    use crate::ssh::{AuthMethod, Exit, SshEngine};
    use crate::sync::env::Keychain;
    use crate::sync::testkit::MemKeychain;

    /// A `Write` the test can read while the run goes on.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    struct Setup {
        engine: Arc<FakeEngine>,
        termios: Arc<FakeTermios>,
        keys: Sender<Input>,
        stdout: Shared,
        stderr: Shared,
        run: std::thread::JoinHandle<i32>,
    }

    /// `sshelter connect web` against a broker over `engine` and `directory`, on the other end of a socket pair, with a fake terminal.
    fn connect(engine: FakeEngine, directory: FakeDirectory, keychain: MemKeychain) -> Setup {
        let engine = Arc::new(engine);
        let broker = Broker::new(
            Arc::clone(&engine) as Arc<dyn SshEngine>,
            Arc::new(directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new()),
            Arc::new(keychain) as Arc<dyn Keychain>,
            Arc::new(FakeConfirmer::default()) as Arc<dyn HostKeyConfirmer>,
        );
        let (ours, theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || broker.serve(theirs, None));
        let termios = FakeTermios::new();
        let (sender, receiver) = std::sync::mpsc::channel();
        let (stdout, stderr) = (Shared::default(), Shared::default());
        let run = {
            let (termios, sender, mut stdout, mut stderr) = (Arc::clone(&termios), sender.clone(), stdout.clone(), stderr.clone());
            std::thread::spawn(move || {
                let mut tty = Tty::new(termios).unwrap();
                run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (sender, receiver), &mut stdout, &mut stderr)
            })
        };
        Setup { engine, termios, keys: sender, stdout, stderr, run }
    }

    fn finish(setup: Setup) -> (i32, Setup) {
        eventually("the run to end", 10, || setup.run.is_finished());
        let Setup { engine, termios, keys, stdout, stderr, run } = setup;
        let code = run.join().unwrap();
        (code, Setup { engine, termios, keys, stdout, stderr, run: std::thread::spawn(|| 0) })
    }

    fn raw(termios: &FakeTermios) -> bool {
        termios.now().c_lflag & libc::ICANON == 0
    }

    #[test]
    fn the_cli_opens_a_shell_relays_keys_and_output_and_exits_with_the_shells_status() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let setup = connect(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), keychain);
        eventually("the terminal to be raw", 10, || raw(&setup.termios));
        setup.keys.send(Input::Stdin(b"ls\r".to_vec())).unwrap();
        eventually("the keys to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::ShellInput(b"ls\r".to_vec())));
        let remote = setup.engine.shells().remove(0);
        remote.print(b"file.txt\r\n");
        eventually("the output to reach the terminal", 10, || setup.stdout.text() == "file.txt\r\n");
        setup.keys.send(Input::Resize(100, 30)).unwrap();
        eventually("the resize to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::WindowChange { cols: 100, rows: 30 }));
        remote.end(Exit::Code(3));
        let (code, setup) = finish(setup);
        assert_eq!(code, 3);
        assert!(setup.termios.is_start(&setup.termios.now()), "the terminal is as it was");
        assert_eq!(setup.stderr.text(), "");
    }

    #[test]
    fn a_question_is_asked_at_the_terminal_and_the_answer_gets_in() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let setup = connect(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, MemKeychain::default());
        eventually("the question", 10, || setup.stderr.text() == "deploy@web's password: ");
        let prompt = setup.termios.sets.lock().unwrap().last().copied().unwrap();
        assert!(prompt.1, "typeahead thrown away");
        assert_eq!((prompt.0.c_lflag & libc::ECHO, prompt.0.c_lflag & libc::ICANON), (0, libc::ICANON), "no echo, line editing on");
        setup.keys.send(Input::Stdin(b"right\n".to_vec())).unwrap();
        eventually("the shell to open", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).end(Exit::Code(0));
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }

    #[test]
    fn a_host_that_cannot_be_reached_is_said_and_the_status_is_255() {
        let setup = connect(FakeEngine::new(), FakeDirectory::new(), MemKeychain::default());
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (255, "No saved host is called web.\n".to_string()));
        assert_eq!(setup.termios.sets.lock().unwrap().iter().filter(|(termios, _)| !setup.termios.is_start(termios)).count(), 0, "the terminal was never changed");
    }

    /// The terminal is closed (SIGHUP) while the shell runs: the CLI tells the broker, puts the terminal back and ends; the broker closes
    /// the session.
    #[test]
    fn a_closed_terminal_ends_the_session() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let setup = connect(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), keychain);
        eventually("the terminal to be raw", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).print(b"$ ");
        setup.keys.send(Input::Stop(libc::SIGHUP)).unwrap();
        let (code, setup) = finish(setup);
        assert_eq!(code, 128 + libc::SIGHUP);
        assert!(setup.termios.is_start(&setup.termios.now()));
        eventually("the session to be closed", 10, || setup.engine.events().contains(&FakeEvent::Closed));
    }
}
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- cli::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0405]: cannot find trait `Write` in this scope
error: could not compile `sshelter` (lib test) due to 21 previous errors; 2 warnings emitted
```

- [ ] **Step 3: Give tokio its `signal` feature, and lock it**

`src-tauri/Cargo.toml`: apply this patch

```diff
--- a/src-tauri/Cargo.toml
+++ b/src-tauri/Cargo.toml
@@ -53,7 +53,8 @@ signature = "2"
 # SSH engine (src/ssh/): russh is imported by src/ssh/russh_engine.rs only. Pinned to the exact version the phase-0 spike measured.
 russh = "=0.64.1"
 # russh runs on tokio. The engine owns a dedicated runtime (rt-multi-thread, net, time) and drives it with block_on; `macros` is for select!.
-tokio = { version = "1.52", features = ["rt-multi-thread", "macros", "net", "io-util", "time", "sync"] }
+# `signal`: `sshelter connect` follows the terminal's size (SIGWINCH) and stops cleanly on SIGINT, SIGTERM and SIGHUP (src/cli/run.rs).
+tokio = { version = "1.52", features = ["rt-multi-thread", "macros", "net", "io-util", "time", "sync", "signal"] }
 
 [dev-dependencies]
 ts-rs = "10"
```

Let cargo update the lock file without the network, then look at what it changed:

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo metadata --offline --format-version 1 > /dev/null)
git diff -- src-tauri/Cargo.lock
```

Expected: `cargo metadata` exits 0, and the diff is exactly this one line (no `[[package]]` is added):

```diff
diff --git a/src-tauri/Cargo.lock b/src-tauri/Cargo.lock
index 4f2f488..09cd8e9 100644
--- a/src-tauri/Cargo.lock
+++ b/src-tauri/Cargo.lock
@@ -6659,6 +6659,7 @@ dependencies = [
  "mio",
  "parking_lot",
  "pin-project-lite",
+ "signal-hook-registry",
  "socket2",
  "tokio-macros",
  "windows-sys 0.61.2",
```

Nothing else in `Cargo.lock` may change; if it does, stop and report.

- [ ] **Step 4: Write the code**

`src-tauri/src/cli/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/cli/mod.rs
+++ b/src-tauri/src/cli/mod.rs
@@ -8,6 +8,81 @@ pub mod run;
 #[cfg(unix)]
 pub mod terminal;
 
+use crate::session::protocol::HostQuery;
+
+/// What `sshelter connect` prints when the app does not answer after it was started (spec §7.3, §11).
+pub const NOT_STARTED: &str = "SSHelter did not start within 12 seconds.";
+
+/// How `sshelter connect` is used.
+pub const USAGE: &str = "usage: sshelter connect <alias>\n       sshelter connect --id <host id>";
+
+/// The host the arguments after `connect` name: an alias, or `--id` and a host id.
+pub fn parse_args(args: &[String]) -> Result<HostQuery, String> {
+    match args {
+        [flag, id] if flag == "--id" && !id.is_empty() && !id.starts_with('-') => Ok(HostQuery::Id(id.clone())),
+        [alias] if !alias.is_empty() && !alias.starts_with('-') => Ok(HostQuery::Alias(alias.clone())),
+        _ => Err(USAGE.to_string()),
+    }
+}
+
+/// The terminal type the shell is opened for: `$TERM`, or `xterm-256color` without one (spec §7.3).
+pub fn term_from(value: Option<std::ffi::OsString>) -> String {
+    value.and_then(|value| value.into_string().ok()).filter(|term| !term.is_empty()).unwrap_or_else(|| "xterm-256color".to_string())
+}
+
+/// `sshelter connect <arguments>`: returns the exit code (main.rs exits with it). Started before anything of Tauri.
+#[cfg(unix)]
+pub fn run_connect(args: &[String]) -> i32 {
+    use std::os::unix::net::UnixStream;
+    use std::sync::Arc;
+
+    use crate::host_start::{ensure_started, start_host, take_spawn_locks, START_WAIT};
+
+    let host = match parse_args(args) {
+        Ok(host) => host,
+        Err(usage) => {
+            eprintln!("{usage}");
+            return 2;
+        }
+    };
+    let socket = match crate::fsutil::app_data_root() {
+        Ok(root) => crate::session::socket_path(&root),
+        Err(error) => {
+            eprintln!("sshelter: {error}");
+            return 1;
+        }
+    };
+    let stream = match ensure_started(|| UnixStream::connect(&socket).ok(), take_spawn_locks, start_host, START_WAIT, NOT_STARTED) {
+        Ok(stream) => stream,
+        Err(text) => {
+            eprintln!("{text}");
+            return 1;
+        }
+    };
+    let mut tty = match terminal::Tty::new(Arc::new(terminal::StdinTermios)) {
+        Ok(tty) => tty,
+        Err(_) => {
+            eprintln!("sshelter connect needs a terminal.");
+            return 1;
+        }
+    };
+    terminal::restore_on_panic(tty.restorer());
+    let (sender, receiver) = std::sync::mpsc::channel();
+    run::stdin_thread(sender.clone());
+    if let Err(error) = run::signal_thread(sender.clone(), || terminal::TermiosApi::size(&terminal::StdinTermios)) {
+        eprintln!("sshelter: cannot follow the terminal's size: {error}");
+    }
+    let term = term_from(std::env::var_os("TERM"));
+    run::run(stream, host, term, &mut tty, (sender, receiver), &mut std::io::stdout(), &mut std::io::stderr())
+}
+
+/// Windows: the console work is phase 3 (spec §13, §16). A release build has no console, so the sentence shows only where one exists.
+#[cfg(windows)]
+pub fn run_connect(_args: &[String]) -> i32 {
+    eprintln!("sshelter connect is not supported on Windows yet.");
+    1
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
```

`src-tauri/src/cli/run.rs`: insert above the `#[cfg(test)]` line

```rust
//! The I/O of `sshelter connect` (own-ssh spec §7.3): the broker's frames are read on a thread of their own, the person's keys on
//! another, the signals (SIGWINCH, SIGINT, SIGTERM, SIGHUP) on a third with tokio's signal handling; everything meets in one queue, and
//! the client (`client.rs`) says what to do with each.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender};

use super::client::{Action, Client, Input};
use super::terminal::Tty;
use crate::session::protocol::{decode, read_frame, write_control, write_data, Frame, HostQuery, ServerMessage};

/// Runs one session over `stream`, connected to the broker, until it ends; returns the program's exit code. `inputs` brings the keys,
/// resizes and signals (`stdin_thread`, `signal_thread`); the broker's frames join it from a thread started here.
pub fn run(stream: UnixStream, host: HostQuery, term: String, tty: &mut Tty, inputs: (Sender<Input>, Receiver<Input>), stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (sender, receiver) = inputs;
    let size = tty.size().unwrap_or((80, 24));
    let Ok(mut reader) = stream.try_clone() else {
        let _ = writeln!(stderr, "The connection to SSHelter failed.");
        return 255;
    };
    let mut writer = stream;
    std::thread::spawn(move || loop {
        let input = match read_frame(&mut reader) {
            Ok(Some(Frame::Control(payload))) => match decode::<ServerMessage>(&payload) {
                Ok(message) => Input::Message(message),
                Err(_) => continue,
            },
            Ok(Some(Frame::Data(bytes))) => Input::Output(bytes.to_vec()),
            Ok(None) | Err(_) => Input::Closed,
        };
        let closed = matches!(input, Input::Closed);
        if sender.send(input).is_err() || closed {
            return;
        }
    });
    let (mut client, actions) = Client::start(host, term, size);
    if let Some(code) = perform(actions, &mut writer, tty, stdout, stderr) {
        return code;
    }
    while let Ok(input) = receiver.recv() {
        let actions = client.handle(input);
        if let Some(code) = perform(actions, &mut writer, tty, stdout, stderr) {
            return code;
        }
    }
    255
}

/// Does what the client said, in order; `Some(code)` when it is time to exit. A broker that no longer takes what is sent is a broker that
/// went away: its end of the connection arrives as `Input::Closed` from the reader.
fn perform(actions: Vec<Action>, writer: &mut UnixStream, tty: &mut Tty, stdout: &mut dyn Write, stderr: &mut dyn Write) -> Option<i32> {
    for action in actions {
        match action {
            Action::Send(message) => {
                let _ = write_control(writer, &message);
            }
            Action::SendData(bytes) => {
                let _ = write_data(writer, &bytes);
            }
            Action::Stdout(bytes) => {
                let _ = stdout.write_all(&bytes);
                let _ = stdout.flush();
            }
            Action::Stderr(text) => {
                let _ = stderr.write_all(text.as_bytes());
                let _ = stderr.flush();
            }
            Action::Mode(mode, discard_input) => {
                if let Err(error) = tty.set_mode(mode, discard_input) {
                    let _ = writeln!(stderr, "sshelter: cannot set the terminal: {error}");
                }
            }
            Action::Exit(code) => {
                tty.restore();
                return Some(code);
            }
        }
    }
    None
}

/// Reads the person's keys into the queue until standard input ends (or the program does).
pub fn stdin_thread(sender: Sender<Input>) {
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    // A question ends on Ctrl-D; the next question reads again.
                    if sender.send(Input::StdinEnd).is_err() {
                        return;
                    }
                }
                Ok(count) => {
                    if sender.send(Input::Stdin(buf[..count].to_vec())).is_err() {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    let _ = sender.send(Input::StdinEnd);
                    return;
                }
            }
        }
    });
}

/// Turns the signals into inputs: a resize (SIGWINCH, read with `size`), Ctrl-C while the terminal is not raw (SIGINT), and the end of the
/// terminal or a request to stop (SIGHUP, SIGTERM). With handlers in place none of them ends the program on its own: the client decides,
/// and the terminal is put back first.
pub fn signal_thread(sender: Sender<Input>, size: impl Fn() -> Option<(u16, u16)> + Send + 'static) -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let (mut resize, mut interrupt, mut terminate, mut hangup) = runtime.block_on(async {
        Ok::<_, std::io::Error>((signal(SignalKind::window_change())?, signal(SignalKind::interrupt())?, signal(SignalKind::terminate())?, signal(SignalKind::hangup())?))
    })?;
    std::thread::spawn(move || {
        runtime.block_on(async move {
            loop {
                let input = tokio::select! {
                    _ = resize.recv() => match size() {
                        Some((cols, rows)) => Input::Resize(cols, rows),
                        None => continue,
                    },
                    _ = interrupt.recv() => Input::Interrupt,
                    _ = terminate.recv() => Input::Stop(libc::SIGTERM),
                    _ = hangup.recv() => Input::Stop(libc::SIGHUP),
                };
                if sender.send(input).is_err() {
                    return;
                }
            }
        })
    });
    Ok(())
}
```

`src-tauri/src/main.rs`: apply this patch

```diff
--- a/src-tauri/src/main.rs
+++ b/src-tauri/src/main.rs
@@ -15,7 +15,10 @@ fn main() {
         sshelter_lib::starts_hidden(std::env::var_os(sshelter_lib::START_HIDDEN_ENV).as_deref());
     std::env::remove_var(sshelter_lib::START_HIDDEN_ENV);
 
-    match std::env::args().nth(1).as_deref() {
+    let args: Vec<String> = std::env::args().collect();
+    match args.get(1).map(String::as_str) {
+        // `sshelter connect <alias>`: the terminal's end of a session in the app (own-ssh spec §7.3), nothing of Tauri.
+        Some("connect") => std::process::exit(sshelter_lib::cli::run_connect(&args[2..])),
         Some("--mcp") => sshelter_lib::mcp::run_stdio(),
         Some(flag) if sshelter_lib::host_start::is_host_flag(flag) => sshelter_lib::run_desktop(true, start_hidden),
         _ => sshelter_lib::run_desktop(false, start_hidden),
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -2,6 +2,18 @@
 //! version, the MCP adapter in phase 2 — asks the client (or the app's window, for host keys) what a login needs, and relays the
 //! terminal. Every SSH call it makes blocks, so it runs on plain threads, never in async code and never on the UI thread.
 
+use std::path::{Path, PathBuf};
+
+/// The broker's socket in the app's data directory (spec §4): `<app data>/ipc/sock`. The CLI finds it the same way, without the app.
+pub fn socket_path(app_data: &Path) -> PathBuf {
+    ipc_dir(app_data).join("sock")
+}
+
+/// The broker's directory (its `lock` and `sock`; `ipc::server::listen_unix` makes it owner-only).
+pub fn ipc_dir(app_data: &Path) -> PathBuf {
+    app_data.join("ipc")
+}
+
 pub mod auth;
 pub mod broker;
 pub mod connect;
```

- [ ] **Step 5: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- cli::)
```

Expected: PASS, `test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 1686 filtered out`. The app's binary builds too, and `sshelter connect` without a host prints the usage:

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo build --offline --locked && ./target/debug/sshelter connect; echo "exit $?")
```

Expected: the two lines of `USAGE` on stderr (`usage: sshelter connect <alias>`, then `sshelter connect --id <host id>` aligned under it), then `exit 2`. Nothing is started: the arguments are checked first.

- [ ] **Step 6: Run `cli::` in CI**

`.github/workflows/test-engine.yml`: apply this patch

```diff
--- a/.github/workflows/test-engine.yml
+++ b/.github/workflows/test-engine.yml
@@ -1,7 +1,7 @@
-# Runs the tests of the SSH engine (src-tauri/src/ssh/) and of the session broker that uses it (src-tauri/src/session/, and starting
-# the app for its clients: host_start) where they can run for real: against a scratch OpenSSH server on macOS and on Linux, and on Linux
-# also against a real OpenSSH with PAM in a container (the logins by password and by keyboard-interactive, which a scratch sshd cannot
-# check). The Windows leg lives in test-windows.yml.
+# Runs the tests of the SSH engine (src-tauri/src/ssh/) and of what uses it (the session broker, src-tauri/src/session/; sshelter
+# connect, src-tauri/src/cli/; starting the app for its clients, host_start) where they can run for real: against a scratch OpenSSH
+# server on macOS and on Linux, and on Linux also against a real OpenSSH with PAM in a container (the logins by password and by
+# keyboard-interactive, which a scratch sshd cannot check). The Windows leg lives in test-windows.yml.
 #
 # aws-lc-sys (russh's crypto, the same crate rustls already pulls in for the updater) is built by its build script with the runner's C
 # compiler: clang on macOS, gcc on ubuntu-24.04. The release workflow already builds it on both through rustls, so nothing is installed
@@ -54,7 +54,7 @@ jobs:
         env:
           SSHELTER_REQUIRE_OPENSSH: "1"
         # Quoted: an unquoted `ssh::` is read as a YAML mapping and the workflow would not load.
-        run: "cargo test --locked --lib -- ssh:: session:: host_start:: vault::"
+        run: "cargo test --locked --lib -- ssh:: session:: cli:: host_start:: vault::"
 
   linux:
     # Not ubuntu-latest: the PAM image is ubuntu:24.04, and the package names below were checked against 24.04.
@@ -104,7 +104,7 @@ jobs:
         env:
           SSHELTER_REQUIRE_OPENSSH: "1"
         # Quoted: an unquoted `ssh::` is read as a YAML mapping and the workflow would not load.
-        run: "cargo test --locked --lib -- ssh:: session:: host_start:: vault:: --skip ssh::engine_tests::login_methods::pam"
+        run: "cargo test --locked --lib -- ssh:: session:: cli:: host_start:: vault:: --skip ssh::engine_tests::login_methods::pam"
       # Runs whatever the scratch sshd step came to, so that a first run shows both results.
       - name: Password and keyboard-interactive tests against the container
         if: ${{ !cancelled() }}
```

`.github/workflows/test-windows.yml`: apply this patch

```diff
--- a/.github/workflows/test-windows.yml
+++ b/.github/workflows/test-windows.yml
@@ -50,14 +50,15 @@ jobs:
       # The platform-dependent tests: identity path parsing (slot_rules), the slot files, links and DACL (slot_files,
       # slot_files_windows), the key vault (vault::), the local IPC transport (ipc:: covers the named pipe and program identification),
       # the SSH agent (agent:: covers the real ssh-add / ssh-keygen against the agent), the SSH engine (`ssh::`: the tests that need
-      # no sshd of their own; the scratch-sshd ones print "skipped" on Windows) and the session broker's platform-neutral parts
-      # (`session::`; its socket tests are Unix only). The rest of the suite runs on macOS; parts of it use the system keychain.
+      # no sshd of their own; the scratch-sshd ones print "skipped" on Windows) and the platform-neutral parts of the session broker
+      # (`session::`; its socket tests are Unix only) and of sshelter connect (`cli::`: its arguments; the rest is Unix only). The rest
+      # of the suite runs on macOS; parts of it use the system keychain.
       - name: Key slot, vault, agent, engine and broker tests
         env:
           SSHELTER_REQUIRE_OPENSSH: "1"
         # Quoted: an unquoted `vault:: ipc:: agent::` is read as a YAML mapping and the workflow would not load.
         # --locked: the committed Cargo.lock, with russh in it, is what is built.
-        run: "cargo test --locked --lib -- sync::slot_rules sync::slot_files vault:: ipc:: agent:: ssh:: session::"
+        run: "cargo test --locked --lib -- sync::slot_rules sync::slot_files vault:: ipc:: agent:: ssh:: session:: cli::"
       # The library and the binary in a debug build, with russh in the dependency graph (the release workflow builds the same graph).
       - name: Build the whole app
         run: cargo build --locked
```

```bash
actionlint .github/workflows/test-engine.yml .github/workflows/test-windows.yml
```

Expected: no output, exit code 0. Then run what the macOS job runs:

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh:: session:: cli:: host_start:: vault::)
```

Expected: `test result: ok. 369 passed; 0 failed; 0 ignored; 0 measured; 1341 filtered out` (the leftover check prints 0, 0 and 0 after it).

- [ ] **Step 7: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1708 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 8: Commit**

```bash
git status --short
git add .github/workflows/test-engine.yml \
  .github/workflows/test-windows.yml \
  src-tauri/Cargo.lock \
  src-tauri/Cargo.toml \
  src-tauri/src/cli/mod.rs \
  src-tauri/src/cli/run.rs \
  src-tauri/src/main.rs \
  src-tauri/src/session/mod.rs
git commit -m "feat(cli): add sshelter connect: start SSHelter if needed, relay the terminal, follow its size and signals"
```

Expected: `git status --short` lists the eight files of this task, `src-tauri/Cargo.toml` and `src-tauri/Cargo.lock` among them.

---

### Task 3: The host-key window

**Files:**
- Create: `src-tauri/src/session/hostkey_window.rs` (with its tests), `src-tauri/capabilities/hostkey.json`
- Modify: `src-tauri/src/session/mod.rs` (`SessionRuntime`), `src-tauri/src/state.rs` (`AppState::session`), `src-tauri/src/lib.rs` (the two commands; closing the window refuses)
- Create: `src/lib/hostkey.ts`, `src/components/HostKeyWindow.tsx` (with `src/lib/hostkey.test.ts` and `src/components/HostKeyWindow.test.tsx`)
- Modify: `src/main.tsx` (the window's component)
- Written by the test run: `src/bindings/HostKeyRequest.ts`, `src/bindings/PinnedHostKey.ts`, `src/bindings/HostKeyAnswer.ts`

**Interfaces:**
- Consumes: plan 1b-1 Task 9 (`HostKeyConfirmer`, `HostKeyQuestion`, `PinnedSummary`, `CancelToken`); `crate::error::AppError`; Tauri's `WebviewWindowBuilder`, `Emitter`, `Manager`; in the frontend `tauriInvoke` (`@/lib/ipc`), `errorMessage` (`@/lib/sync`), `revealHidden` (`@/lib/sync-approvals`), `listen` (`@tauri-apps/api/event`); the agent's approval window as the model (`agent/prompt.rs`, `src/components/AgentApprovalWindow.tsx`).
- Produces:
  - `session/hostkey_window.rs`:
    - `pub const HOSTKEY_WINDOW: &str = "hostkey"`, `pub const HOSTKEY_EVENT: &str = "hostkey://requests"`, `pub const HOSTKEY_TIMEOUT: Duration` (120 s)
    - `pub struct HostKeyRequest { pub id: String, pub alias: String, pub hostname: String, pub port: u16, pub algorithm: String, pub fingerprint: String, pub changed: Option<PinnedHostKey> }`, `pub struct PinnedHostKey { pub fingerprint: String, pub pinned_at_ms: u64 }`, `pub struct HostKeyAnswer { pub trust: bool, pub fingerprint: String }` (serde; ts-rs bindings in test builds)
    - `pub trait HostKeySurface: Send + Sync { fn changed(&self, pending: &[HostKeyRequest]); }`
    - `pub struct HostKeyHub` (`Default`) with `ask(&self, surface: &dyn HostKeySurface, request: HostKeyRequest, timeout: Duration, cancel: &CancelToken) -> Option<HostKeyAnswer>`, `resolve(&self, id: &str, answer: HostKeyAnswer) -> Result<(), AppError>`, `deny_all(&self)`, `pending(&self) -> Vec<HostKeyRequest>`
    - `pub struct WindowConfirmer { pub hub: Arc<HostKeyHub>, pub surface: Arc<dyn HostKeySurface>, pub timeout: Duration }` with `impl HostKeyConfirmer`
    - `pub struct TauriHostKeySurface { pub app: tauri::AppHandle }` with `impl HostKeySurface`
    - commands `hostkey_pending(state) -> Vec<HostKeyRequest>` and `hostkey_resolve(state, request_id: String, answer: HostKeyAnswer) -> Result<(), AppError>`
  - `session/mod.rs`: `pub struct SessionRuntime { pub host_keys: Arc<HostKeyHub> }` (`Default`), held by `AppState::session`
  - `src/lib/hostkey.ts`: `HOSTKEY_EVENT`, `fetchPending()`, `resolveHostKey(requestId, answer)`, `onHostKeyRequests(handler)`, `pinnedOn(ms)`, `hostKeyTitle(r)`, `hostKeyBody(r)`, `hostKeyButtons(r)`, `buildHostKeyAnswer(r, trust)`, `TRUST_ARM_DELAY_MS` (700), `armAfterDelay(arm)`, `answerRejectedMessage(id, error)`, `pendingFeed(set)`
  - `src/components/HostKeyWindow.tsx`: `HostKeyCardView` (the card, without effects), `HostKeyCard`, and the default export `HostKeyWindow`

What shapes this task:
- R3: a host key is confirmed in a window of SSHelter's, never at a terminal (spec §7.2, decision 6), built like the agent's approval window: a hub of waiting questions (`agent/prompt.rs`'s `PromptHub`), a small always-on-top window (480 × 320) that shows the oldest question, the answer through a command. Copied rather than shared, because plan 1c deletes `agent/`.
- The flow (spec §10): the broker's session thread asks and blocks — at most `HOSTKEY_TIMEOUT` (120 s; the connection is not waiting, the engine failed fast), and it gives up as soon as the client goes away (`cancel`, looked at every 100 ms). The surface is told whenever the list changes and creates, updates or destroys the window; only a new question at the head brings the window to the front, so another question timing out does not take the focus. Closing the window refuses every waiting question (`deny_all`, from lib.rs's window event); `destroy`, used when nothing is pending, does not go through `CloseRequested` and is not taken for the person closing it.
- The answer carries the fingerprint the window showed (`buildHostKeyAnswer`), and the broker pins only a key with that fingerprint (plan 1b-1 Task 9). An answer to a question that already left gets `NotFound`, and the window logs the request id and the error, never the answer (`answerRejectedMessage`).
- The texts are spec §14's, word for word. Names come from the user's hosts and from the server, so they are shown through `revealHidden`, as in the approval window. The changed-key card adds one line under §14's text: the new key's algorithm and fingerprint in a monospace font (the changed-key text names no fingerprint, and the person may want to compare it with what the server's administrator sent). `{pinned_at}` is `toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })`.
- The trust button is armed 700 ms after a card appears (`TRUST_ARM_DELAY_MS`): the next question replaces an answered one within milliseconds, and a second click or a stray Enter must not trust a key nobody looked at. Refusing never waits. While an answer is on its way, both buttons are off.
- The window gets the list two ways — one fetch when it opens, an event for every change after — and once an event has arrived a fetch still in flight is ignored (`pendingFeed`).
- The three bindings are written by the test run, like every ts-rs binding of the app (`export_bindings_*`); `pinned_at_ms` is a `number` in TypeScript (`#[ts(type = "number")]`: it fits until the year 287396).
- The window loads the app's page; `src/main.tsx` picks its component by the window's label (`approval`, `hostkey`, else the app). `capabilities/hostkey.json` gives the `hostkey` window `core:default` only; app commands are not ACL-checked without an app manifest, the same as for the approval window.

- [ ] **Step 1: Write the tests**

`src-tauri/src/session/hostkey_window.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::connect::PinnedSummary;

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<Vec<String>>>,
    }

    impl HostKeySurface for Recorder {
        fn changed(&self, pending: &[HostKeyRequest]) {
            self.seen.lock().unwrap().push(pending.iter().map(|request| request.id.clone()).collect());
        }
    }

    fn question(alias: &str) -> HostKeyQuestion {
        HostKeyQuestion { alias: alias.into(), hostname: format!("{alias}.example.com"), port: 22, algorithm: "ssh-ed25519".into(), fingerprint: "SHA256:new".into(), changed: None }
    }

    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// The broker asks; the window shows the question; the person trusts it: the fingerprint comes back.
    #[test]
    fn a_trusted_key_comes_back_as_its_fingerprint_and_the_window_is_told_both_times() {
        let hub = Arc::new(HostKeyHub::default());
        let surface = Arc::new(Recorder::default());
        let confirmer = WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface) as Arc<dyn HostKeySurface>, timeout: Duration::from_secs(5) };
        let asking = std::thread::spawn(move || confirmer.confirm(&question("web"), &CancelToken::default()));
        wait_until("the question to be shown", || !surface.seen.lock().unwrap().is_empty());
        let shown = hub.pending();
        assert_eq!((shown[0].alias.as_str(), shown[0].fingerprint.as_str(), shown[0].changed.clone()), ("web", "SHA256:new", None));
        hub.resolve(&shown[0].id, HostKeyAnswer { trust: true, fingerprint: "SHA256:new".into() }).unwrap();
        assert_eq!(asking.join().unwrap(), Some("SHA256:new".to_string()));
        assert_eq!(*surface.seen.lock().unwrap(), vec![vec![shown[0].id.clone()], vec![]]);
    }

    #[test]
    fn a_refusal_a_timeout_or_a_closed_window_is_no_trust() {
        let hub = Arc::new(HostKeyHub::default());
        let surface: Arc<dyn HostKeySurface> = Arc::new(Recorder::default());
        let confirmer = |timeout| WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface), timeout };
        assert_eq!(confirmer(Duration::from_millis(20)).confirm(&question("web"), &CancelToken::default()), None, "nobody answered");

        let refusing = confirmer(Duration::from_secs(5));
        let asking = std::thread::spawn(move || refusing.confirm(&question("web"), &CancelToken::default()));
        wait_until("the question", || !hub.pending().is_empty());
        hub.resolve(&hub.pending()[0].id, HostKeyAnswer { trust: false, fingerprint: "SHA256:new".into() }).unwrap();
        assert_eq!(asking.join().unwrap(), None);

        let closed = confirmer(Duration::from_secs(5));
        let asking = std::thread::spawn(move || closed.confirm(&question("web"), &CancelToken::default()));
        wait_until("the question", || !hub.pending().is_empty());
        hub.deny_all();
        assert_eq!(asking.join().unwrap(), None);
        assert!(hub.pending().is_empty());
    }

    /// The client went away while the window asked: the question leaves the window soon, and nothing is trusted.
    #[test]
    fn a_withdrawn_question_leaves_the_window() {
        let hub = Arc::new(HostKeyHub::default());
        let surface = Arc::new(Recorder::default());
        let cancel = CancelToken::default();
        let confirmer = WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface) as Arc<dyn HostKeySurface>, timeout: Duration::from_secs(30) };
        let withdrawn = cancel.clone();
        let asking = std::thread::spawn(move || confirmer.confirm(&question("web"), &withdrawn));
        wait_until("the question", || !hub.pending().is_empty());
        let started = Instant::now();
        cancel.cancel();
        assert_eq!(asking.join().unwrap(), None);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(hub.pending().is_empty());
        assert_eq!(surface.seen.lock().unwrap().last(), Some(&vec![]), "the window is told nothing is pending");
    }

    #[test]
    fn a_changed_key_carries_the_pinned_one_and_answers_go_to_the_right_question() {
        let hub = Arc::new(HostKeyHub::default());
        let surface: Arc<dyn HostKeySurface> = Arc::new(Recorder::default());
        let mut changed = question("db");
        changed.changed = Some(PinnedSummary { fingerprint: "SHA256:old".into(), pinned_at_ms: 1_700_000_000_000 });
        let first = WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface), timeout: Duration::from_secs(5) };
        let second = WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface), timeout: Duration::from_secs(5) };
        let web = std::thread::spawn(move || first.confirm(&question("web"), &CancelToken::default()));
        wait_until("web's question", || hub.pending().len() == 1);
        let db = std::thread::spawn(move || second.confirm(&changed, &CancelToken::default()));
        wait_until("db's question", || hub.pending().len() == 2);
        let pending = hub.pending();
        assert_eq!(pending.iter().map(|request| request.alias.as_str()).collect::<Vec<_>>(), ["web", "db"], "oldest first");
        assert_eq!(pending[1].changed, Some(PinnedHostKey { fingerprint: "SHA256:old".into(), pinned_at_ms: 1_700_000_000_000 }));
        assert_ne!(pending[0].id, pending[1].id);
        hub.resolve(&pending[1].id, HostKeyAnswer { trust: true, fingerprint: "SHA256:new".into() }).unwrap();
        assert_eq!(db.join().unwrap(), Some("SHA256:new".into()));
        assert!(hub.resolve(&pending[1].id, HostKeyAnswer::default()).is_err(), "an answered question takes no second answer");
        hub.resolve(&pending[0].id, HostKeyAnswer::default()).unwrap();
        assert_eq!(web.join().unwrap(), None);
    }

    #[test]
    fn the_window_comes_to_the_front_only_for_a_new_question_at_the_head() {
        let list = |ids: &[&str]| {
            ids.iter()
                .map(|id| HostKeyRequest { id: (*id).into(), alias: "web".into(), hostname: "web".into(), port: 22, algorithm: "ssh-ed25519".into(), fingerprint: "SHA256:x".into(), changed: None })
                .collect::<Vec<_>>()
        };
        let mut shown = None;
        assert!(note_head(&mut shown, &list(&["hostkey-1"])));
        assert!(!note_head(&mut shown, &list(&["hostkey-1", "hostkey-2"])));
        assert!(note_head(&mut shown, &list(&["hostkey-2"])));
        assert!(!note_head(&mut shown, &[]));
        assert_eq!(shown, None);
    }
}
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -18,6 +18,7 @@ pub mod auth;
 pub mod broker;
 pub mod connect;
 pub mod directory;
+pub mod hostkey_window;
 pub mod pins;
 pub mod protocol;
 pub mod relay;
```

`src/components/HostKeyWindow.test.tsx`: create

```tsx
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import { HostKeyCard, HostKeyCardView } from "@/components/HostKeyWindow";

function request(over: Partial<HostKeyRequest> = {}): HostKeyRequest {
  return { id: "hostkey-1", alias: "web", hostname: "web.example.com", port: 22, algorithm: "ssh-ed25519", fingerprint: "SHA256:new", changed: null, ...over };
}

const render = (r: HostKeyRequest, over: { busy?: boolean; armed?: boolean } = {}) =>
  renderToStaticMarkup(<HostKeyCardView request={r} busy={over.busy ?? false} armed={over.armed ?? true} onAnswer={() => {}} />);

/** Whether the button labelled `label` is disabled (React separates text nodes with comments). */
function buttonDisabled(html: string, label: string): boolean {
  const found = [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)].find((m) => m[2].replace(/<!--.*?-->/g, "").trim() === label);
  if (found === undefined) throw new Error(`no ${label} button in ${html}`);
  return found[1].includes('disabled=""');
}

describe("HostKeyCardView", () => {
  it("asks about a new key with Cancel and Trust this key", () => {
    const html = render(request());
    expect(html).toContain("Is this web?");
    expect(html).toContain("web.example.com:22 presented the key ssh-ed25519 SHA256:new.");
    expect(buttonDisabled(html, "Cancel")).toBe(false);
    expect(buttonDisabled(html, "Trust this key")).toBe(false);
  });

  it("warns about a changed key with Refuse and Accept new key, and shows the new key", () => {
    const html = render(request({ changed: { fingerprint: "SHA256:old", pinned_at_ms: 1_700_000_000_000 } }));
    expect(html).toContain("web&#x27;s host key changed");
    expect(html).toContain("ssh-ed25519 SHA256:new");
    expect(buttonDisabled(html, "Refuse")).toBe(false);
    expect(buttonDisabled(html, "Accept new key")).toBe(false);
  });

  it("keeps trust off until armed and both buttons off while an answer is on its way", () => {
    expect(buttonDisabled(render(request(), { armed: false }), "Trust this key")).toBe(true);
    expect(buttonDisabled(render(request(), { armed: false }), "Cancel")).toBe(false);
    const busy = render(request(), { busy: true });
    expect(buttonDisabled(busy, "Cancel")).toBe(true);
    expect(buttonDisabled(busy, "Trust this key")).toBe(true);
  });

  it("is not armed the moment a card mounts", () => {
    const first = renderToStaticMarkup(<HostKeyCard request={request()} busy={false} onAnswer={() => {}} />);
    expect(buttonDisabled(first, "Trust this key")).toBe(true);
  });
});
```

`src/lib/hostkey.test.ts`: create

```ts
import { afterEach, describe, expect, it, vi } from "vitest";

import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import {
  answerRejectedMessage,
  armAfterDelay,
  buildHostKeyAnswer,
  hostKeyBody,
  hostKeyButtons,
  hostKeyTitle,
  pendingFeed,
  pinnedOn,
  TRUST_ARM_DELAY_MS,
} from "@/lib/hostkey";

function request(over: Partial<HostKeyRequest> = {}): HostKeyRequest {
  return {
    id: "hostkey-1",
    alias: "web",
    hostname: "web.example.com",
    port: 22,
    algorithm: "ssh-ed25519",
    fingerprint: "SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew",
    changed: null,
    ...over,
  };
}

const changed = request({ changed: { fingerprint: "SHA256:old", pinned_at_ms: 1_700_000_000_000 } });

describe("host key texts (spec §14, word for word)", () => {
  it("asks about a key SSHelter has not seen", () => {
    expect(hostKeyTitle(request())).toBe("Is this web?");
    expect(hostKeyBody(request())).toBe(
      "web.example.com:22 presented the key ssh-ed25519 SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew. SSHelter has not seen it before. Connect only if the fingerprint matches what the server's administrator gave you.",
    );
    expect(hostKeyButtons(request())).toEqual({ refuse: "Cancel", trust: "Trust this key" });
  });

  it("warns about a key that changed", () => {
    expect(hostKeyTitle(changed)).toBe("web's host key changed");
    expect(hostKeyBody(changed)).toBe(
      `The key web.example.com:22 presented does not match the one SSHelter pinned on ${pinnedOn(1_700_000_000_000)}. Someone could be intercepting the connection. Refuse unless you know the server's key was reinstalled.`,
    );
    expect(hostKeyButtons(changed)).toEqual({ refuse: "Refuse", trust: "Accept new key" });
  });

  it("shows hidden characters in names instead of rendering them", () => {
    expect(hostKeyTitle(request({ alias: "we‮b" }))).toBe("Is this we⟨U+202E⟩b?");
    expect(hostKeyBody(request({ hostname: "evil\u0007.example.com" }))).toContain("evil⟨U+0007⟩.example.com:22");
  });
});

describe("host key answers", () => {
  it("carries the fingerprint the window showed", () => {
    expect(buildHostKeyAnswer(request(), true)).toEqual({ trust: true, fingerprint: request().fingerprint });
    expect(buildHostKeyAnswer(changed, false)).toEqual({ trust: false, fingerprint: changed.fingerprint });
  });

  it("says which answer was rejected without saying the answer", () => {
    expect(answerRejectedMessage("hostkey-3", new Error("gone"))).toBe("[hostkey] the answer to hostkey-3 was rejected: gone");
  });
});

describe("arming and the pending list", () => {
  afterEach(() => vi.useRealTimers());

  it("arms the trust button after the delay, and a card that goes away first never arms", () => {
    vi.useFakeTimers();
    const armed: string[] = [];
    armAfterDelay(() => armed.push("first"));
    const cancel = armAfterDelay(() => armed.push("second"));
    vi.advanceTimersByTime(TRUST_ARM_DELAY_MS - 1);
    expect(armed).toEqual([]);
    cancel();
    vi.advanceTimersByTime(1);
    expect(armed).toEqual(["first"]);
  });

  it("ignores a fetch that arrives after an event", () => {
    const lists: HostKeyRequest[][] = [];
    const feed = pendingFeed((list) => lists.push(list));
    feed.fromEvent([request()]);
    feed.fromFetch([]);
    expect(lists).toEqual([[request()]]);
  });
});
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::hostkey_window::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find type `Mutex` in this scope
error: could not compile `sshelter` (lib test) due to 71 previous errors; 1 warning emitted
```

```bash
./node_modules/.bin/vitest run --exclude '.claude/**' src/lib/hostkey.test.ts src/components/HostKeyWindow.test.tsx
```

Expected: FAIL before any test runs: both files import modules this step has not written yet (`<repository>` is the checkout's path):

```text
Test Files 2 failed (2)
Tests no tests
FAIL src/components/HostKeyWindow.test.tsx [ src/components/HostKeyWindow.test.tsx ]
Error: Cannot find package '@/components/HostKeyWindow' imported from <repository>/src/components/HostKeyWindow.test.tsx
FAIL src/lib/hostkey.test.ts [ src/lib/hostkey.test.ts ]
Error: Cannot find package '@/lib/hostkey' imported from <repository>/src/lib/hostkey.test.ts
```

- [ ] **Step 3: Write the code**

`src-tauri/capabilities/hostkey.json`: create

```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "hostkey",
  "description": "The host key window of SSHelter's own SSH client: it lists and answers the host key questions (app commands) and listens for their updates. This file limits plugin and core permissions only; app commands are not ACL-checked without an app manifest.",
  "windows": ["hostkey"],
  "permissions": ["core:default"]
}
```

`src-tauri/src/lib.rs`: apply this patch

```diff
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -35,6 +35,7 @@ use deploy::{
 use keys::{keys_agent_status, keys_deploy, keys_git_ssh_hint, keys_list, keys_read_public};
 use known_hosts::{known_hosts_list, known_hosts_remove};
 use mcp::{mcp_resolve_request, mcp_set_enabled, mcp_set_host_allowed, mcp_status};
+use session::hostkey_window::{hostkey_pending, hostkey_resolve};
 use settings_io::{settings_export, settings_import};
 use sync::engine::{
     sync_approve, sync_cancel_sync_code_change, sync_change_sync_code, sync_check_relay,
@@ -189,6 +190,13 @@ fn run_app(host: bool, start_hidden: bool) {
                 }
                 return;
             }
+            // The host key window (own-ssh spec §10): closing it refuses every key it was asking about.
+            if window.label() == session::hostkey_window::HOSTKEY_WINDOW {
+                if let tauri::WindowEvent::CloseRequested { .. } = event {
+                    window.app_handle().state::<state::AppState>().session.host_keys.deny_all();
+                }
+                return;
+            }
             // 視窗在前景時以一般間隔輪詢、回到前景立刻同步一輪(同步退避期間要等退避結束,spec §6.4);不在前景時省 relay 的配額(Sync v2)。
             if let tauri::WindowEvent::Focused(focused) = event {
                 sync::engine::window_focused(window.app_handle(), *focused);
@@ -309,6 +317,8 @@ fn run_app(host: bool, start_hidden: bool) {
             agent_resolve,
             agent_problem,
             agent_fix_include,
+            hostkey_pending,
+            hostkey_resolve,
         ])
         .build(tauri::generate_context!())
         .expect("error while building tauri application")
```

`src-tauri/src/session/hostkey_window.rs`: insert above the `#[cfg(test)]` line

```rust
//! SSHelter's host key window (own-ssh spec §10, §14, decision 6): the broker's `HostKeyConfirmer`. A host key is confirmed only here,
//! never in a terminal: the broker's session thread asks (`HostKeyHub::ask` blocks it), a small always-on-top window labelled `hostkey`
//! shows the oldest question, and the person's answer comes back through `hostkey_resolve`. Closing the window refuses every waiting
//! question (`deny_all`, from lib.rs). The window and its hub are modelled on the SSH agent's approval window (`agent/prompt.rs`), copied
//! rather than shared because plan 1c deletes `agent/`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::connect::{CancelToken, HostKeyConfirmer, HostKeyQuestion};
use crate::error::AppError;

pub const HOSTKEY_WINDOW: &str = "hostkey";
pub const HOSTKEY_EVENT: &str = "hostkey://requests";
/// How long a question waits for the person (the connection itself is not waiting: the engine failed fast, spec §6.2 step 3).
pub const HOSTKEY_TIMEOUT: Duration = Duration::from_secs(120);

/// A host key question as the window shows it. The strings come from the user's host settings and the server: the window shows them
/// through `revealHidden`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostKeyRequest {
    pub id: String,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    /// Set for a key that changed: the pinned one.
    pub changed: Option<PinnedHostKey>,
}

/// The pinned key a changed key replaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PinnedHostKey {
    pub fingerprint: String,
    /// When it was pinned (milliseconds since the Unix epoch). A number in the binding: it fits a JavaScript number until the year 287396.
    #[cfg_attr(test, ts(type = "number"))]
    pub pinned_at_ms: u64,
}

/// The window's answer: trust (Trust this key, Accept new key) or not (Cancel, Refuse), for the fingerprint the window showed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostKeyAnswer {
    pub trust: bool,
    pub fingerprint: String,
}

/// Told when the waiting questions change: opens, updates or closes the window. Called one at a time, each time with the latest list.
pub trait HostKeySurface: Send + Sync {
    fn changed(&self, pending: &[HostKeyRequest]);
}

struct Waiting {
    request: HostKeyRequest,
    answer: mpsc::SyncSender<HostKeyAnswer>,
    answered: bool,
}

/// The questions waiting for the person, in the order they came.
#[derive(Default)]
pub struct HostKeyHub {
    pending: Mutex<Vec<Waiting>>,
    /// Orders the notifications to the surface: taking the list and telling the surface happen under it, so the surface is told last
    /// what is pending last. Never held together with `pending` the other way round.
    notify: Mutex<()>,
    next_id: AtomicU64,
}

/// Takes the question off the list when `ask` leaves, however it leaves.
struct Leaving<'a> {
    hub: &'a HostKeyHub,
    id: &'a str,
}

impl Drop for Leaving<'_> {
    fn drop(&mut self) {
        self.hub.forget(self.id);
    }
}

impl HostKeyHub {
    /// Asks and waits for the answer, at most `timeout`, and gives up early when `cancel` is set (the client went away). `None` when
    /// nobody answered. Blocks, and the surface may create a window: call it from a worker thread (the broker's session thread).
    pub fn ask(&self, surface: &dyn HostKeySurface, mut request: HostKeyRequest, timeout: Duration, cancel: &CancelToken) -> Option<HostKeyAnswer> {
        let id = format!("hostkey-{}", self.next_id.fetch_add(1, Ordering::Relaxed) + 1);
        request.id = id.clone();
        let (answer, answered) = mpsc::sync_channel(1);
        self.pending.lock().unwrap_or_else(PoisonError::into_inner).push(Waiting { request, answer, answered: false });
        let _leave = Leaving { hub: self, id: &id };
        self.publish(surface);
        let deadline = Instant::now() + timeout;
        let mut reply = None;
        while reply.is_none() && !cancel.is_cancelled() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match answered.recv_timeout(left.min(Duration::from_millis(100))) {
                Ok(answer) => reply = Some(answer),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // No longer waiting: off the list first (a later `resolve` finds nothing), then one more look, so an answer that `resolve` reported
        // as taken still counts.
        self.forget(&id);
        if reply.is_none() {
            reply = answered.try_recv().ok();
        }
        self.publish(surface);
        reply
    }

    fn forget(&self, id: &str) {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner).retain(|waiting| waiting.request.id != id);
    }

    fn publish(&self, surface: &dyn HostKeySurface) {
        let _order = self.notify.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = self.pending();
        surface.changed(&snapshot);
    }

    /// Answers a waiting question. One that does not exist, was answered or gave up → NotFound.
    pub fn resolve(&self, id: &str, answer: HostKeyAnswer) -> Result<(), AppError> {
        let gone = || AppError::NotFound("that question was already answered or has expired".to_string());
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let waiting = pending.iter_mut().find(|waiting| waiting.request.id == id && !waiting.answered).ok_or_else(gone)?;
        waiting.answered = true;
        waiting.answer.try_send(answer).map_err(|_| gone())
    }

    /// The window was closed: every waiting question is refused.
    pub fn deny_all(&self) {
        for waiting in self.pending.lock().unwrap_or_else(PoisonError::into_inner).drain(..) {
            let _ = waiting.answer.try_send(HostKeyAnswer::default());
        }
    }

    /// The questions still waiting for an answer, oldest first.
    pub fn pending(&self) -> Vec<HostKeyRequest> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner).iter().filter(|waiting| !waiting.answered).map(|waiting| waiting.request.clone()).collect()
    }
}

/// The broker's `HostKeyConfirmer` over the hub and a surface.
pub struct WindowConfirmer {
    pub hub: Arc<HostKeyHub>,
    pub surface: Arc<dyn HostKeySurface>,
    pub timeout: Duration,
}

impl HostKeyConfirmer for WindowConfirmer {
    fn confirm(&self, question: &HostKeyQuestion, cancel: &CancelToken) -> Option<String> {
        let request = HostKeyRequest {
            id: String::new(),
            alias: question.alias.clone(),
            hostname: question.hostname.clone(),
            port: question.port,
            algorithm: question.algorithm.clone(),
            fingerprint: question.fingerprint.clone(),
            changed: question.changed.as_ref().map(|pinned| PinnedHostKey { fingerprint: pinned.fingerprint.clone(), pinned_at_ms: pinned.pinned_at_ms }),
        };
        let answer = self.hub.ask(self.surface.as_ref(), request, self.timeout, cancel)?;
        answer.trust.then_some(answer.fingerprint)
    }
}

/// The window last brought to the front for this head question (only one host key window exists).
static SHOWN_HEAD: Mutex<Option<String>> = Mutex::new(None);

/// Whether a new question is at the head (only then is the window brought to the front: another question timing out must not take the
/// focus from what the person is doing).
fn note_head(shown: &mut Option<String>, pending: &[HostKeyRequest]) -> bool {
    let head = pending.first().map(|request| request.id.as_str());
    let new_head = head.is_some() && shown.as_deref() != head;
    *shown = head.map(str::to_string);
    new_head
}

/// The app's surface: a small window that stays on top, shown even while SSHelter sits in the tray; destroyed when nothing is pending
/// (`destroy` does not go through `CloseRequested`, so it is not taken for the person closing it).
pub struct TauriHostKeySurface {
    pub app: tauri::AppHandle,
}

impl HostKeySurface for TauriHostKeySurface {
    fn changed(&self, pending: &[HostKeyRequest]) {
        use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
        let new_head = note_head(&mut SHOWN_HEAD.lock().unwrap_or_else(PoisonError::into_inner), pending);
        if pending.is_empty() {
            if let Some(window) = self.app.get_webview_window(HOSTKEY_WINDOW) {
                let _ = window.destroy();
            }
            return;
        }
        let (window, built) = match self.app.get_webview_window(HOSTKEY_WINDOW) {
            Some(window) => (Some(window), false),
            None => match WebviewWindowBuilder::new(&self.app, HOSTKEY_WINDOW, WebviewUrl::App("index.html".into()))
                .title("SSHelter")
                .inner_size(480.0, 320.0)
                .resizable(false)
                .always_on_top(true)
                .center()
                .build()
            {
                Ok(window) => (Some(window), true),
                Err(error) => {
                    eprintln!("[session] cannot open the host key window: {error}");
                    (None, false)
                }
            },
        };
        if let Some(window) = window {
            if built || new_head {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }
        let _ = self.app.emit_to(HOSTKEY_WINDOW, HOSTKEY_EVENT, pending);
    }
}

#[tauri::command]
pub fn hostkey_pending(state: tauri::State<crate::state::AppState>) -> Vec<HostKeyRequest> {
    state.session.host_keys.pending()
}

#[tauri::command]
pub fn hostkey_resolve(state: tauri::State<crate::state::AppState>, request_id: String, answer: HostKeyAnswer) -> Result<(), AppError> {
    state.session.host_keys.resolve(&request_id, answer)
}
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -14,6 +14,13 @@ pub fn ipc_dir(app_data: &Path) -> PathBuf {
     app_data.join("ipc")
 }
 
+/// The broker's state in the app (`AppState::session`).
+#[derive(Default)]
+pub struct SessionRuntime {
+    /// The host key questions waiting for the window.
+    pub host_keys: std::sync::Arc<hostkey_window::HostKeyHub>,
+}
+
 pub mod auth;
 pub mod broker;
 pub mod connect;
```

`src-tauri/src/state.rs`: apply this patch

```diff
--- a/src-tauri/src/state.rs
+++ b/src-tauri/src/state.rs
@@ -21,6 +21,8 @@ pub struct AppState {
     /// 同步執行期狀態:generation/狀態/帳戶金鑰同一把鎖(`SyncCore`)、lifecycle 互斥鎖、同步中旗標。
     pub sync: crate::sync::runtime::SyncRuntime,
     pub agent: crate::agent::AgentRuntime,
+    /// The session broker: its host key window, its sessions (own-ssh spec §4, §7).
+    pub session: crate::session::SessionRuntime,
 }
 
 impl Default for AppState {
@@ -34,6 +36,7 @@ impl Default for AppState {
             mcp: crate::mcp::McpRuntime::default(),
             sync: crate::sync::runtime::SyncRuntime::default(),
             agent: crate::agent::AgentRuntime::default(),
+            session: crate::session::SessionRuntime::default(),
         }
     }
 }
```

`src/components/HostKeyWindow.tsx`: create

```tsx
import { useEffect, useState } from "react";

import type { HostKeyAnswer } from "@/bindings/HostKeyAnswer";
import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import { Button } from "@/components/ui/button";
import {
  answerRejectedMessage,
  armAfterDelay,
  buildHostKeyAnswer,
  fetchPending,
  hostKeyBody,
  hostKeyButtons,
  hostKeyTitle,
  onHostKeyRequests,
  pendingFeed,
  resolveHostKey,
} from "@/lib/hostkey";
import { revealHidden } from "@/lib/sync-approvals";

/** One question: the texts of spec §14 and the two buttons. `armed` says whether the trust button may be pressed yet. Exported for tests. */
export function HostKeyCardView({
  request,
  busy,
  armed,
  onAnswer,
}: {
  request: HostKeyRequest;
  busy: boolean;
  armed: boolean;
  onAnswer: (answer: HostKeyAnswer) => void;
}) {
  const buttons = hostKeyButtons(request);
  return (
    <div className="space-y-3 p-4">
      <h1 className="text-sm font-semibold break-words">{hostKeyTitle(request)}</h1>
      <p className="text-sm break-words">{hostKeyBody(request)}</p>
      {request.changed !== null && (
        <p className="font-mono text-xs text-muted-foreground break-all">
          {revealHidden(request.algorithm)} {revealHidden(request.fingerprint)}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => onAnswer(buildHostKeyAnswer(request, false))}>
          {buttons.refuse}
        </Button>
        <Button
          type="button"
          size="sm"
          variant={request.changed === null ? "default" : "destructive"}
          disabled={busy || !armed}
          onClick={() => onAnswer(buildHostKeyAnswer(request, true))}
        >
          {buttons.trust}
        </Button>
      </div>
    </div>
  );
}

/** A question's card: keyed by the question id, so every question gets a card of its own, and its trust button stays off for a moment. */
export function HostKeyCard({ request, busy, onAnswer }: { request: HostKeyRequest; busy: boolean; onAnswer: (answer: HostKeyAnswer) => void }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => armAfterDelay(() => setArmed(true)), []);
  return <HostKeyCardView request={request} busy={busy} armed={armed} onAnswer={onAnswer} />;
}

/** The `hostkey` window: the oldest question; Rust opens and destroys the window. */
export default function HostKeyWindow() {
  const [pending, setPending] = useState<HostKeyRequest[]>([]);
  const [answeredId, setAnsweredId] = useState<string | null>(null);
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let live = true;
    const feed = pendingFeed((list) => {
      if (live) setPending(list);
    });
    void fetchPending().then(feed.fromFetch);
    void onHostKeyRequests(feed.fromEvent).then((u) => {
      if (live) unlisten = u;
      else u();
    });
    return () => {
      live = false;
      unlisten?.();
    };
  }, []);
  const request = pending[0];
  if (!request) return null;
  return (
    <HostKeyCard
      key={request.id}
      request={request}
      busy={answeredId === request.id}
      onAnswer={(answer) => {
        setAnsweredId(request.id);
        void resolveHostKey(request.id, answer).catch((error: unknown) => {
          console.warn(answerRejectedMessage(request.id, error));
          setAnsweredId((current) => (current === request.id ? null : current));
        });
      }}
    />
  );
}
```

`src/lib/hostkey.ts`: create

```ts
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type { HostKeyAnswer } from "@/bindings/HostKeyAnswer";
import type { HostKeyRequest } from "@/bindings/HostKeyRequest";
import { tauriInvoke } from "@/lib/ipc";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";

/**
 * The host key window of SSHelter's own SSH client (own-ssh spec §10, §14): a host key is confirmed here, never in a terminal. The
 * texts are spec §14's, word for word. Names come from the user's hosts and the server, so they are shown through `revealHidden`.
 */

export const HOSTKEY_EVENT = "hostkey://requests";

export function fetchPending(): Promise<HostKeyRequest[]> {
  return tauriInvoke<HostKeyRequest[]>("hostkey_pending");
}

export function resolveHostKey(requestId: string, answer: HostKeyAnswer): Promise<void> {
  return tauriInvoke<void>("hostkey_resolve", { requestId, answer });
}

export function onHostKeyRequests(handler: (pending: HostKeyRequest[]) => void): Promise<UnlistenFn> {
  return listen<HostKeyRequest[]>(HOSTKEY_EVENT, (event) => handler(event.payload));
}

/** When the old key was pinned, as the changed-key text says it. */
export function pinnedOn(pinnedAtMs: number): string {
  return new Date(pinnedAtMs).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function hostKeyTitle(r: HostKeyRequest): string {
  const alias = revealHidden(r.alias);
  return r.changed === null ? `Is this ${alias}?` : `${alias}'s host key changed`;
}

export function hostKeyBody(r: HostKeyRequest): string {
  const where = `${revealHidden(r.hostname)}:${r.port}`;
  if (r.changed === null) {
    return `${where} presented the key ${revealHidden(r.algorithm)} ${revealHidden(r.fingerprint)}. SSHelter has not seen it before. Connect only if the fingerprint matches what the server's administrator gave you.`;
  }
  return `The key ${where} presented does not match the one SSHelter pinned on ${pinnedOn(r.changed.pinned_at_ms)}. Someone could be intercepting the connection. Refuse unless you know the server's key was reinstalled.`;
}

/** The two buttons: the one that refuses, then the one that trusts. */
export function hostKeyButtons(r: HostKeyRequest): { refuse: string; trust: string } {
  return r.changed === null ? { refuse: "Cancel", trust: "Trust this key" } : { refuse: "Refuse", trust: "Accept new key" };
}

/** The answer for a button: trust carries the fingerprint the window showed, and the broker pins only a key with that fingerprint. */
export function buildHostKeyAnswer(r: HostKeyRequest, trust: boolean): HostKeyAnswer {
  return { trust, fingerprint: r.fingerprint };
}

/**
 * How long the trust button stays off after a card mounts: the next question replaces an answered one within milliseconds, and a quick
 * second click must not trust a key nobody looked at. Refusing never waits.
 */
export const TRUST_ARM_DELAY_MS = 700;

export function armAfterDelay(arm: () => void): () => void {
  const timer = setTimeout(arm, TRUST_ARM_DELAY_MS);
  return () => clearTimeout(timer);
}

/** The console line for an answer the backend rejected: the request id and the error only. */
export function answerRejectedMessage(requestId: string, error: unknown): string {
  return `[hostkey] the answer to ${requestId} was rejected: ${errorMessage(error)}`;
}

/**
 * The pending list reaches the window two ways: one fetch when it opens, and an event for every change after that. A fetch still in
 * flight may have read an older list, so once an event has arrived the fetch's result is ignored.
 */
export function pendingFeed(set: (list: HostKeyRequest[]) => void): { fromFetch: (list: HostKeyRequest[]) => void; fromEvent: (list: HostKeyRequest[]) => void } {
  let sawEvent = false;
  return {
    fromFetch: (list) => {
      if (!sawEvent) set(list);
    },
    fromEvent: (list) => {
      sawEvent = true;
      set(list);
    },
  };
}
```

`src/main.tsx`: apply this patch

```diff
--- a/src/main.tsx
+++ b/src/main.tsx
@@ -4,6 +4,7 @@ import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
 import { getCurrentWindow } from "@tauri-apps/api/window";
 import App from "./App";
 import AgentApprovalWindow from "./components/AgentApprovalWindow";
+import HostKeyWindow from "./components/HostKeyWindow";
 import "./index.css";
 
 const queryClient = new QueryClient();
@@ -11,18 +12,26 @@ const queryClient = new QueryClient();
 const rootEl = document.getElementById("root");
 if (!rootEl) throw new Error("Root element #root not found in index.html");
 
-// The agent's approval prompt (key vault spec §7.4) is a second window that loads the same page. Outside Tauri (a
-// plain-browser `vite dev`) there is no window to ask, so the page is the app.
-const isApprovalWindow = (() => {
+// The agent's approval prompt (key vault spec §7.4) and the host key window (own-ssh spec §10) are windows of their own that load
+// the same page. Outside Tauri (a plain-browser `vite dev`) there is no window to ask, so the page is the app.
+const windowLabel = (() => {
   try {
-    return getCurrentWindow().label === "approval";
+    return getCurrentWindow().label;
   } catch {
-    return false;
+    return "main";
   }
 })();
 
+function Root() {
+  if (windowLabel === "approval") return <AgentApprovalWindow />;
+  if (windowLabel === "hostkey") return <HostKeyWindow />;
+  return <App />;
+}
+
 ReactDOM.createRoot(rootEl).render(
   <React.StrictMode>
-    <QueryClientProvider client={queryClient}>{isApprovalWindow ? <AgentApprovalWindow /> : <App />}</QueryClientProvider>
+    <QueryClientProvider client={queryClient}>
+      <Root />
+    </QueryClientProvider>
   </React.StrictMode>,
 );
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::hostkey_window::)
```

Expected: PASS, `test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 1710 filtered out`. The run writes the three bindings (`git status --short src/bindings` lists them as new files):

`src/bindings/HostKeyAnswer.ts`, as the run writes it:

```ts
// This file was generated by [ts-rs](https://github.com/Aleph-Alpha/ts-rs). Do not edit this file manually.

/**
 * The window's answer: trust (Trust this key, Accept new key) or not (Cancel, Refuse), for the fingerprint the window showed.
 */
export type HostKeyAnswer = { trust: boolean, fingerprint: string, };
```

`src/bindings/HostKeyRequest.ts`, as the run writes it:

```ts
// This file was generated by [ts-rs](https://github.com/Aleph-Alpha/ts-rs). Do not edit this file manually.
import type { PinnedHostKey } from "./PinnedHostKey";

/**
 * A host key question as the window shows it. The strings come from the user's host settings and the server: the window shows them
 * through `revealHidden`.
 */
export type HostKeyRequest = { id: string, alias: string, hostname: string, port: number, algorithm: string, fingerprint: string, 
/**
 * Set for a key that changed: the pinned one.
 */
changed: PinnedHostKey | null, };
```

`src/bindings/PinnedHostKey.ts`, as the run writes it:

```ts
// This file was generated by [ts-rs](https://github.com/Aleph-Alpha/ts-rs). Do not edit this file manually.

/**
 * The pinned key a changed key replaces.
 */
export type PinnedHostKey = { fingerprint: string, 
/**
 * When it was pinned (milliseconds since the Unix epoch). A number in the binding: it fits a JavaScript number until the year 287396.
 */
pinned_at_ms: number, };
```

```bash
./node_modules/.bin/vitest run --exclude '.claude/**' src/lib/hostkey.test.ts src/components/HostKeyWindow.test.tsx
```

Expected: PASS, `Test Files 2 passed (2)`, `Tests 11 passed (11)`.

- [ ] **Step 5: Run the whole lib suite and the whole frontend**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1716 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

```bash
./node_modules/.bin/vitest run --exclude '.claude/**'
./node_modules/.bin/tsc --noEmit
```

Expected: `Test Files 52 passed (52)`, `Tests 856 passed (856)`, and `tsc` prints nothing and exits 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/capabilities/hostkey.json \
  src-tauri/src/lib.rs \
  src-tauri/src/session/hostkey_window.rs \
  src-tauri/src/session/mod.rs \
  src-tauri/src/state.rs \
  src/bindings/HostKeyAnswer.ts \
  src/bindings/HostKeyRequest.ts \
  src/bindings/PinnedHostKey.ts \
  src/components/HostKeyWindow.test.tsx \
  src/components/HostKeyWindow.tsx \
  src/lib/hostkey.test.ts \
  src/lib/hostkey.ts \
  src/main.tsx
git commit -m "feat(session): confirm host keys in a window of their own"
```

Expected: `git status --short` lists the thirteen files of this task (the three bindings among them); the `git diff --stat` prints nothing.

---

### Task 4: The broker in the app: start it, keep the app running for it, end its sessions on quit

**Files:**
- Create: `src-tauri/src/session/app.rs` (with its tests)
- Modify: `src-tauri/src/session/mod.rs` (`SessionRuntime::{broker, status}`), `src-tauri/src/lib.rs` (setup, closing the main window, a second launch, quitting)

**Interfaces:**
- Consumes: plan 1b-1's `Broker::{new, handler, has_sessions, end_all}`, `SshConfigDirectory`, `Sources`, `vault_slot_of`, `PinStore`, `KeyStore`, `VaultKey`; Task 2's `session::ipc_dir`; Task 3's `WindowConfirmer`, `TauriHostKeySurface`, `HOSTKEY_TIMEOUT`; `crate::ssh::russh_engine::RusshEngine::new()`; phase 0's `crate::ipc::server::{listen_unix, Started}`; `crate::sync::env::{Keychain, OsKeychain}`, `crate::sync::state_v2::{SlotSource, SyncStateV2}`, `crate::sync::engine::with_env`, `crate::vault::store::{vault_path, with_vault}`, `crate::config::{include::load_doc, intel::effective_config, model::SshConfigDoc}`, `crate::keys::ssh_dir`, `crate::secrets::host_account`, `crate::fsutil::app_data_root`; `AppState::{doc, sync, close_to_tray, mcp.keep_alive, session}`.
- Produces (`session/app.rs`):
  - `pub enum BrokerStatus { NotStarted, Running, OtherInstance, Failed(String), NotOnThisPlatform }` (`Default`: `NotStarted`)
  - `pub fn vault_key_in(state: &SyncStateV2, key_id: &str) -> Option<VaultKey>`
  - `pub fn loaded_doc(doc: &Mutex<Option<SshConfigDoc>>, wait: Duration, fallback: impl FnOnce() -> Result<SshConfigDoc, AppError>) -> Result<SshConfigDoc, String>`
  - `pub fn hides_on_close(close_to_tray: bool, host_keep_alive: bool, sessions: bool) -> bool`
  - `pub fn start(app: &tauri::AppHandle)`, `pub fn ensure_listening(app: &tauri::AppHandle)`, `pub fn has_sessions(app: &tauri::AppHandle) -> bool`, `pub fn quit(app: &tauri::AppHandle)`
  - `SessionRuntime` gains `pub broker: Mutex<Option<Arc<Broker>>>` and `pub status: Mutex<BrokerStatus>`

What shapes this task:
- The broker is built in `setup` from the app's state and listens on `<app data>/ipc/sock` with phase 0's `listen_unix`, under its own lock next to the agent's socket (R5). A failure is recorded in `AppState::session.status` and does not stop the app, as with the agent; another SSHelter that holds the lock (a debug build next to the installed app) is `OtherInstance`. On Windows the status is `NotOnThisPlatform`: the broker's Windows transport is not part of plan 1b, and nothing on Windows would talk to it (R4).
- The directory is plan 1b-1's temporary adapter over the app's data, read-only: the ssh_config the window loaded or, in an app a client started in the background (its window never loads one), the default `~/.ssh/config`, read after 5 s (`loaded_doc`, as the MCP bridge waits); `ssh -G` for a host's settings; the sync state's vault slots; the OS keychain for saved passwords; `host-pins.json` in the app's data for pins.
- The keys are the vault's: `vault_key_in` gives a slot "Only in SSHelter", named as the agent names it (the slot's name, else its file name); the private text comes from the vault file through the sync engine's environment (`with_env`, `with_vault`).
- R7: closing the main window hides it while sessions are open — as it already does for close-to-tray and for an app started for an MCP client — so the sessions live on; quitting ends every session and tells each client `SSHelter quit, so the connection to {alias} was closed.` (waiting up to 3 s for them, `end_all`); a second launch with the host flag, which means a client found nobody listening and started SSHelter and that launch handed over to this instance, makes the broker listen again unless it already does. A restart (an update's "Install & restart") ends every session; the terminals print the reason and exit. The module documentation says so.

- [ ] **Step 1: Write the tests**

`src-tauri/src/session/app.rs`: create (only its tests for now; the code goes above them in Step 3)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::state_v2::LocalSlot;

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
    fn a_vault_key_is_one_only_in_sshelter_named_by_its_slot() {
        let mut state = SyncStateV2::fresh("mac").unwrap();
        let vault = SlotSource::Vault { fingerprint: "SHA256:v".into(), public_key: "ssh-ed25519 AAAA".into(), has_passphrase: true };
        state.key_slots.insert("a".repeat(32), slot("id_mac-aaaaaaaa", Some(vault)));
        state.key_slots.insert("b".repeat(32), slot("work-bbbbbbbb", Some(SlotSource::SyncedCopy { fingerprint: "SHA256:w".into() })));
        assert_eq!(vault_key_in(&state, &"a".repeat(32)), Some(VaultKey { name: "id_mac-aaaaaaaa".into(), public_key: "ssh-ed25519 AAAA".into(), has_passphrase: true }));
        assert_eq!(vault_key_in(&state, &"b".repeat(32)), None, "a key in a file is not the vault's");
        assert_eq!(vault_key_in(&state, "missing"), None);
    }

    #[test]
    fn the_loaded_config_is_used_and_without_one_the_fallback_is_read_after_the_wait() {
        let doc = Mutex::new(Some(SshConfigDoc { files: Vec::new() }));
        assert!(loaded_doc(&doc, Duration::from_secs(5), || panic!("the window's config is there")).is_ok());

        let none = Mutex::new(None);
        let started = Instant::now();
        assert_eq!(loaded_doc(&none, Duration::from_millis(200), || Err(AppError::Other("no config".into()))).err(), Some("no config".to_string()));
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn closing_the_window_hides_it_while_sessions_are_open() {
        assert!(!hides_on_close(false, false, false), "nothing keeps the app: closing quits it");
        assert!(hides_on_close(false, false, true), "open sessions keep it");
        assert!(hides_on_close(true, false, false) && hides_on_close(false, true, false));
    }
}
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -21,6 +21,7 @@ pub struct SessionRuntime {
     pub host_keys: std::sync::Arc<hostkey_window::HostKeyHub>,
 }
 
+pub mod app;
 pub mod auth;
 pub mod broker;
 pub mod connect;
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::app::)
```

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find type `SlotSource` in this scope
error: could not compile `sshelter` (lib test) due to 22 previous errors; 1 warning emitted
```

- [ ] **Step 3: Write the code**

`src-tauri/src/lib.rs`: apply this patch

```diff
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -125,6 +125,7 @@ fn on_second_launch(app: &tauri::AppHandle, args: Vec<String>, _cwd: String) {
         show_main_window(app);
     } else {
         mcp::republish_bridge(app);
+        session::app::ensure_listening(app);
     }
 }
 
@@ -179,6 +180,8 @@ fn run_app(host: bool, start_hidden: bool) {
             sync::engine::initialize(app.handle())?;
             // SSHelter 的 SSH agent(金鑰保管庫 spec §5.1):開不起來只記在 `AgentRuntime::status`,不擋啟動。
             agent::start(app.handle());
+            // The session broker that `sshelter connect` talks to (own-ssh spec §4, §7): a failure is recorded, it does not stop the app.
+            session::app::start(app.handle());
             tray::rebuild_tray(app.handle(), &[])?;
             Ok(())
         })
@@ -203,14 +206,12 @@ fn run_app(host: bool, start_hidden: bool) {
             }
             if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                 let state = window.app_handle().state::<state::AppState>();
-                if state
-                    .close_to_tray
-                    .load(std::sync::atomic::Ordering::Relaxed)
-                    || state
-                        .mcp
-                        .keep_alive
-                        .load(std::sync::atomic::Ordering::Relaxed)
-                {
+                // Open sessions keep the app running too: quitting would end them (own-ssh spec §4).
+                if session::app::hides_on_close(
+                    state.close_to_tray.load(std::sync::atomic::Ordering::Relaxed),
+                    state.mcp.keep_alive.load(std::sync::atomic::Ordering::Relaxed),
+                    session::app::has_sessions(window.app_handle()),
+                ) {
                     // Hide to tray instead of quitting; the tray "Open SSHelter" item
                     // (show + set_focus) brings it back.
                     api.prevent_close();
@@ -327,7 +328,11 @@ fn run_app(host: bool, start_hidden: bool) {
             // no second process; it sends Reopen. Bring back the window, even a hidden one.
             #[cfg(target_os = "macos")]
             tauri::RunEvent::Reopen { .. } => show_main_window(app),
-            tauri::RunEvent::Exit => mcp::forget_bridge(app),
+            tauri::RunEvent::Exit => {
+                mcp::forget_bridge(app);
+                // Quitting ends every session; each terminal is told why (own-ssh spec §4).
+                session::app::quit(app);
+            }
             _ => {}
         });
 }
```

`src-tauri/src/session/app.rs`: insert above the `#[cfg(test)]` line

```rust
//! The broker in the app (own-ssh spec §4): built in `setup` from the app's state and listening on `<app data>/ipc/sock` (macOS and
//! Linux; the Windows transport is not part of plan 1b). Its sessions keep the app running when the window is closed, quitting the app
//! ends them, and a second launch with the host flag (a client that found nobody listening) starts the listener again if it is down.
//! A restart of the app (an update) ends every session; the clients say so and exit.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::Manager;
use zeroize::Zeroizing;

use super::auth::{KeyStore, VaultKey};
use super::broker::Broker;
use super::hostkey_window::{TauriHostKeySurface, WindowConfirmer, HOSTKEY_TIMEOUT};
use super::pins::PinStore;
use super::ssh_config_directory::{vault_slot_of, Sources, SshConfigDirectory};
use crate::config::model::SshConfigDoc;
use crate::error::AppError;
use crate::state::AppState;
use crate::sync::env::{Keychain, OsKeychain};
use crate::sync::state_v2::{SlotSource, SyncStateV2};

/// Whether the broker listens.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BrokerStatus {
    #[default]
    NotStarted,
    Running,
    /// Another SSHelter holds the broker's lock (a debug build next to the installed app).
    OtherInstance,
    Failed(String),
    /// The broker has no transport on this platform in this version (Windows).
    NotOnThisPlatform,
}

/// How long a connect waits for the window to load the SSH config before reading it itself (as the MCP bridge waits).
const DOC_WAIT: Duration = Duration::from_secs(5);
/// How long quitting waits for the sessions to close.
const QUIT_WAIT: Duration = Duration::from_secs(3);

/// The vault key `key_id` as the sync state lists it: a key "Only in SSHelter", named as the agent names it (the slot's name, else its
/// file name). `None` for a slot whose key is not in the vault.
pub fn vault_key_in(state: &SyncStateV2, key_id: &str) -> Option<VaultKey> {
    let local = state.key_slots.get(key_id)?;
    let Some(SlotSource::Vault { public_key, has_passphrase, .. }) = &local.source else { return None };
    let name = local.payload.as_ref().map(|payload| payload.name.clone()).filter(|name| !name.is_empty()).unwrap_or_else(|| local.file_name.clone());
    Some(VaultKey { name, public_key: public_key.clone(), has_passphrase: *has_passphrase })
}

/// The SSH config the window loaded; when it has not loaded one within `wait` (an app started in the background by a client), the one
/// `fallback` reads.
pub fn loaded_doc(doc: &Mutex<Option<SshConfigDoc>>, wait: Duration, fallback: impl FnOnce() -> Result<SshConfigDoc, AppError>) -> Result<SshConfigDoc, String> {
    let deadline = Instant::now() + wait;
    loop {
        if let Some(doc) = doc.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone() {
            return Ok(doc);
        }
        if Instant::now() >= deadline {
            return fallback().map_err(|error| error.to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether closing the main window hides it instead of quitting: the tray setting, a host started for a client, or open sessions (which
/// quitting would end, spec §4).
pub fn hides_on_close(close_to_tray: bool, host_keep_alive: bool, sessions: bool) -> bool {
    close_to_tray || host_keep_alive || sessions
}

/// The vault through the app's state: which keys are "Only in SSHelter" (the sync state) and their private halves (the vault file).
struct AppKeyStore {
    app: tauri::AppHandle,
}

impl KeyStore for AppKeyStore {
    fn key(&self, key_id: &str) -> Option<VaultKey> {
        let state = self.app.state::<AppState>();
        let core = state.sync.core.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        core.state.as_ref().and_then(|state| vault_key_in(state, key_id))
    }

    fn private_text(&self, key_id: &str) -> Result<Option<Zeroizing<String>>, String> {
        use crate::vault::store::{vault_path, with_vault};
        crate::sync::engine::with_env(&self.app, |env| {
            with_vault(env.runtime, &vault_path(&env.state_path), env.keychain, env.now(), |vault| vault.get(key_id))
                .map(|entry| entry.map(|entry| Zeroizing::new(entry.private_key.clone())))
                .map_err(|error| error.to_string())
        })
        .map_err(|error| error.to_string())
        .and_then(|inner| inner)
    }
}

/// The temporary directory over the app's ssh_config, sync state and keychain (`ssh_config_directory.rs`).
fn directory(app: &tauri::AppHandle) -> Result<SshConfigDirectory, AppError> {
    let pins = PinStore::new(crate::fsutil::app_data_root()?.join("host-pins.json"));
    let (for_doc, for_keys) = (app.clone(), app.clone());
    let sources = Sources {
        doc: Box::new(move || {
            let state = for_doc.state::<AppState>();
            loaded_doc(&state.doc, DOC_WAIT, || crate::config::include::load_doc(&crate::keys::ssh_dir()?.join("config")))
        }),
        effective: Box::new(|alias| crate::config::intel::effective_config(alias, None).map_err(|error| error.to_string())),
        vault_key: Box::new(move |identity_files| {
            let home = crate::keys::ssh_dir().ok()?.parent()?.to_path_buf();
            let state = for_keys.state::<AppState>();
            let core = state.sync.core.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            core.state.as_ref().and_then(|state| vault_slot_of(identity_files, state, &home))
        }),
        password_saved: Box::new(|host| OsKeychain.get(&crate::secrets::host_account(host.as_str())).ok().flatten().is_some_and(|password| !password.is_empty())),
    };
    Ok(SshConfigDirectory::new(sources, pins))
}

/// Builds the broker and starts its listener; what happened is recorded in `AppState::session`, nothing stops the app.
pub fn start(app: &tauri::AppHandle) {
    let status = listen(app);
    if let BrokerStatus::Failed(reason) = &status {
        eprintln!("[session] the broker is not listening: {reason}");
    }
    *app.state::<AppState>().session.status.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = status;
}

#[cfg(unix)]
fn listen(app: &tauri::AppHandle) -> BrokerStatus {
    let broker = {
        let state = app.state::<AppState>();
        let mut slot = state.session.broker.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            let directory = match directory(app) {
                Ok(directory) => directory,
                Err(error) => return BrokerStatus::Failed(error.to_string()),
            };
            let confirmer = WindowConfirmer { hub: Arc::clone(&state.session.host_keys), surface: Arc::new(TauriHostKeySurface { app: app.clone() }), timeout: HOSTKEY_TIMEOUT };
            *slot = Some(Broker::new(
                Arc::new(crate::ssh::russh_engine::RusshEngine::new()),
                Arc::new(directory),
                Arc::new(AppKeyStore { app: app.clone() }),
                Arc::new(OsKeychain),
                Arc::new(confirmer),
            ));
        }
        slot.clone().expect("the broker was just built")
    };
    let dir = match crate::fsutil::app_data_root() {
        Ok(root) => super::ipc_dir(&root),
        Err(error) => return BrokerStatus::Failed(error.to_string()),
    };
    match crate::ipc::server::listen_unix(&dir, broker.handler()) {
        Ok(crate::ipc::server::Started::Running) => BrokerStatus::Running,
        Ok(crate::ipc::server::Started::OtherInstance) => BrokerStatus::OtherInstance,
        Err(error) => BrokerStatus::Failed(error.to_string()),
    }
}

#[cfg(windows)]
fn listen(_app: &tauri::AppHandle) -> BrokerStatus {
    BrokerStatus::NotOnThisPlatform
}

/// A client found nobody listening and started SSHelter, which handed over to this instance: listen again unless it already does.
pub fn ensure_listening(app: &tauri::AppHandle) {
    let status = app.state::<AppState>().session.status.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    if !matches!(status, BrokerStatus::Running | BrokerStatus::NotOnThisPlatform) {
        start(app);
    }
}

/// Whether any session is open.
pub fn has_sessions(app: &tauri::AppHandle) -> bool {
    let broker = app.state::<AppState>().session.broker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    broker.is_some_and(|broker| broker.has_sessions())
}

/// The app is quitting: every session ends, each client told why (spec §4).
pub fn quit(app: &tauri::AppHandle) {
    let broker = app.state::<AppState>().session.broker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    if let Some(broker) = broker {
        broker.end_all(QUIT_WAIT);
    }
}
```

`src-tauri/src/session/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/session/mod.rs
+++ b/src-tauri/src/session/mod.rs
@@ -19,6 +19,9 @@ pub fn ipc_dir(app_data: &Path) -> PathBuf {
 pub struct SessionRuntime {
     /// The host key questions waiting for the window.
     pub host_keys: std::sync::Arc<hostkey_window::HostKeyHub>,
+    /// The broker, once `app::start` built it.
+    pub broker: std::sync::Mutex<Option<std::sync::Arc<broker::Broker>>>,
+    pub status: std::sync::Mutex<app::BrokerStatus>,
 }
 
 pub mod app;
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- session::app::)
```

Expected: PASS, `test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 1718 filtered out`.

- [ ] **Step 5: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1719 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 6: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/lib.rs \
  src-tauri/src/session/app.rs \
  src-tauri/src/session/mod.rs
git commit -m "feat(session): start the broker with the app, keep the app running while sessions are open, end them when it quits"
```

Expected: `git status --short` lists the three files of this task; the `git diff --stat` prints nothing.

---

### Task 5: Connect, the palette and the tray run `sshelter connect`; the password autofill and the one-shot key channel go

**Files:**
- Modify: `src-tauri/src/connect.rs` (with its tests), `src-tauri/src/tray.rs`
- Delete: `src-tauri/src/agent/oneshot.rs`
- Modify: `src-tauri/src/agent/mod.rs`, `src-tauri/src/agent/session.rs` (`testing::NoKeys`), `src-tauri/src/agent/openssh_tests.rs` (the one-shot test), `src-tauri/src/deploy.rs`, `src-tauri/src/ipc/peer.rs`, `src-tauri/src/ipc/pipe_windows.rs` (each with its tests)
- Modify: `src/lib/agent.ts`, `src/lib/sync-events.ts` (with `src/lib/agent.test.ts`, `src/lib/sync-events.test.ts`)

**Interfaces:**
- Consumes: `connect::{build_launch_command, launch, detect_terminals, validate_alias, LaunchSpec}` (as they are); Task 2's `sshelter connect`.
- Produces (`connect.rs`):
  - `pub fn connect_argv(exe: &std::path::Path, alias: &str) -> Vec<String>` — `[exe, "connect", alias]`
  - `pub fn launch_for(terminal_id: &str, alias: &str, new_tab: bool) -> Result<LaunchSpec, AppError>` — `sshelter connect` on macOS and Linux, `ssh <alias>` (`build_launch`) on Windows
  - `build_launch` only on Windows and in tests; `connect_launch` loses its `app` parameter (Tauri injects it; the frontend's call does not change)
- Removed: `connect::{autofill_ssh_argv, env_wrapped_argv, windows_autofill_cmd_string, build_autofill_launch, password_autofill_env, ssh_argv}` with their tests; the module `agent::oneshot`; `agent::session::testing::NoKeys`; `deploy::{is_default_config_root, openssh_supports_forced_askpass_in_terminal}` with its test; `ipc::peer::executable_base` with its two tests; `ipc::pipe_windows::one_shot` with its test; in the frontend `CONNECT_EXPIRED_EVENT`, `connectExpiredMessage` and the toast for `agent://connect-expired`.

What shapes this task:
- R11 and spec §7.4: the Connect button and the command palette (both call `connect_launch`) and the tray's quick connect run `<SSHelter's executable> connect <alias>` (`connect_argv`) through the same `build_launch_command` and `launch` as before, so every terminal SSHelter knows gets the command, quoted as before. The executable is the running app's (`current_exe()`); nothing installs `sshelter` on `PATH`.
- R4: Windows keeps `ssh <alias>` until phase 3 (`sshelter connect` needs a console there). R11 deletes the password autofill and the one-shot channel, which Windows used too, so on Windows `ssh <alias>` now runs plainly: a saved password is no longer typed for the person, and a host on an "Only in SSHelter" key gets the key from SSHelter's agent, behind the agent's approval window (spec §7.4's note, Task 7). This reading of R4 next to R11 is listed under "Decisions to confirm".
- What the switch leaves without a user goes with it — the scout's list, plus one thing the compiler then reported: `ipc::peer::executable_base`, which only the one-shot channel used. `deploy.rs` keeps everything its deploy flow still uses.
- The tests that go are those of the deleted code; the new tests check that every terminal gets `sshelter connect` and that the launch is `sshelter connect` on macOS and Linux and `ssh` on Windows.

- [ ] **Step 1: Write the tests (and drop the tests of what goes)**

`src-tauri/src/agent/openssh_tests.rs`: apply this patch

```diff
--- a/src-tauri/src/agent/openssh_tests.rs
+++ b/src-tauri/src/agent/openssh_tests.rs
@@ -10,9 +10,9 @@ use std::time::{Duration, Instant};
 use ssh_key::public::KeyData;
 use zeroize::Zeroizing;
 
-use crate::agent::broker::{AgentHost, Broker, Connection, Grant, VaultKey};
+use crate::agent::broker::{AgentHost, Broker, Connection, VaultKey};
 use crate::agent::prompt::{AgentApprovalAnswer, AgentApprovalRequest};
-use crate::agent::{oneshot, session};
+use crate::agent::session;
 use crate::error::AppError;
 use crate::ipc::peer;
 use crate::ipc::server::{Handler, Stream};
@@ -153,7 +153,6 @@ struct Running {
     /// `SSH_AUTH_SOCK` 的值。
     endpoint: String,
     host: Arc<TestHost>,
-    broker: Arc<Broker>,
 }
 
 /// 在暫存目錄開一個 agent(Windows 用這個測試自己的 pipe 名稱)。
@@ -162,7 +161,7 @@ fn start() -> Running {
     let host = Arc::new(TestHost::new());
     let broker = Arc::new(Broker::default());
     let handler: Handler = {
-        let (host, broker) = (Arc::clone(&host), Arc::clone(&broker));
+        let host = Arc::clone(&host);
         Arc::new(move |mut stream: Stream, pid: Option<u32>| {
             let program = pid.and_then(|pid| peer::identify(&peer::process_chain(pid)));
             let connection = Connection { broker: &broker, host: host.as_ref(), program, grant: None };
@@ -183,7 +182,7 @@ fn start() -> Running {
         crate::ipc::pipe_windows::listen(&agent_dir, &name, handler).unwrap();
         format!(r"\\.\pipe\{name}")
     };
-    Running { dir, endpoint, host, broker }
+    Running { dir, endpoint, host }
 }
 
 fn stderr(out: &std::process::Output) -> String {
@@ -242,44 +241,6 @@ fn ssh_keygen_signs_through_the_agent_and_the_signature_verifies() {
     assert!(asked.iter().all(|r| r.host.is_none() && !r.rememberable), "an SSHSIG request has no host and is never remembered");
 }
 
-#[test]
-fn a_one_shot_channel_lists_only_its_key_and_only_once() {
-    if !have("ssh-add") {
-        return;
-    }
-    let agent = start();
-    let serve: Box<dyn FnOnce(Stream, Option<u32>) + Send> = {
-        let (host, broker) = (Arc::clone(&agent.host), Arc::clone(&agent.broker));
-        Box::new(move |mut stream, _pid| {
-            let grant = Some(Grant { slot_id: IDS[1].into() });
-            let connection = Connection { broker: &broker, host: host.as_ref(), program: None, grant };
-            let _ = session::serve(&mut stream, &connection);
-        })
-    };
-    // `late` 不會被呼叫(10 秒內就連上了);`channel` 要留到兩次 ssh-add 都跑完:沒有 `keep` 就丟掉會取消通道。
-    let channel =
-        oneshot::open(&agent.dir.path().join("run"), serve, Box::new(|| {}), Duration::from_secs(10), Duration::from_secs(10)).unwrap();
-    #[cfg(unix)]
-    let endpoint = channel.path.display().to_string();
-    #[cfg(windows)]
-    let endpoint = format!(r"\\.\pipe\{}", channel.name);
-    let out = run(Command::new(tool("ssh-add")).arg("-L").env("SSH_AUTH_SOCK", &endpoint));
-    assert!(out.status.success(), "{}", stderr(&out));
-    let listed = String::from_utf8_lossy(&out.stdout);
-    assert!(listed.contains(test_keys::ECDSA_PUBLIC), "{listed}");
-    assert!(!listed.contains(test_keys::PLAIN_PUBLIC), "only the granted key: {listed}");
-    assert_eq!(listed.lines().count(), 1, "exactly one key is listed: {listed}");
-    // 第二次要的是「連不上」:ssh-add 連不到 agent 時結束碼是 2,連上了但 agent 沒有金鑰時是 1(只是「沒列出東西」不夠)。
-    let again = run(Command::new(tool("ssh-add")).arg("-L").env("SSH_AUTH_SOCK", &endpoint));
-    assert_eq!(
-        again.status.code(),
-        Some(2),
-        "the channel is gone after its first connection: ssh-add must fail to reach it (exit 2; exit 1 = it connected): stderr: {}, stdout: {}",
-        stderr(&again),
-        String::from_utf8_lossy(&again.stdout)
-    );
-}
-
 /// 立刻結束的命令:`run` 回傳它的輸出。命令用測試程式自己(兩個平台都有),它只列出這個測試的名稱就結束。
 #[test]
 fn run_returns_the_output_of_a_command_that_exits_at_once() {
```

`src-tauri/src/connect.rs`: apply this patch

```diff
--- a/src-tauri/src/connect.rs
+++ b/src-tauri/src/connect.rs
@@ -593,44 +593,41 @@ mod tests {
     use super::*;
     use crate::config::include::load_doc;
 
-    #[test]
-    fn ssh_argv_puts_the_options_before_the_alias() {
-        let options = vec!["-o".to_string(), "ForwardAgent=no".to_string()];
-        assert_eq!(ssh_argv(&options, "web"), vec!["ssh", "-o", "ForwardAgent=no", "web"]);
-        assert_eq!(ssh_argv(&[], "web"), vec!["ssh", "web"]);
-    }
-
-    /// 一次性通道的選項到每一種終端機都原樣、在主機名稱之前:交給 shell 的(AppleScript 的 `do script`、xfce4-terminal)把 `~` 單引號起來
-    /// (沒引號的 `~` 會被 shell 展開成可能含空白的家目錄路徑),直接執行的(Linux 的終端機、wt、cmd)不經 shell,整串原樣當引數。
-    #[test]
-    fn the_channel_options_reach_every_terminal_before_the_alias() {
-        let unix = ssh_argv(
-            &["-o".to_string(), "IdentityAgent=~/.ssh/sshelter/agent/run/0a1b2c3d".to_string(), "-o".to_string(), "ForwardAgent=no".to_string()],
-            "web",
-        );
-        let quoted = "ssh -o 'IdentityAgent=~/.ssh/sshelter/agent/run/0a1b2c3d' -o ForwardAgent=no web";
+    /// The connect command reaches every terminal as it is: terminals that hand it to a shell (AppleScript's `do script`,
+    /// xfce4-terminal) get the executable's path quoted when it has a space in it; the ones that run a program (the other Linux terminals,
+    /// wt, cmd) get the argv untouched.
+    #[test]
+    fn the_connect_command_reaches_every_terminal() {
+        let argv = connect_argv(std::path::Path::new("/Users/me/My Apps/SSHelter.app/Contents/MacOS/sshelter"), "web");
+        assert_eq!(argv, vec!["/Users/me/My Apps/SSHelter.app/Contents/MacOS/sshelter", "connect", "web"]);
+        let quoted = "'/Users/me/My Apps/SSHelter.app/Contents/MacOS/sshelter' connect web";
         for new_tab in [false, true] {
-            let terminal = build_launch_command("terminal", &unix, new_tab).unwrap();
+            let terminal = build_launch_command("terminal", &argv, new_tab).unwrap();
             assert_eq!(terminal.args.last().unwrap(), &format!("tell application \"Terminal\" to do script \"{quoted}\""));
-            let iterm = build_launch_command("iterm2", &unix, new_tab).unwrap();
+            let iterm = build_launch_command("iterm2", &argv, new_tab).unwrap();
             let carrying = iterm.args.iter().filter(|a| a.ends_with(&format!("command \"{quoted}\""))).count();
             assert_eq!(carrying, if new_tab { 2 } else { 1 }, "the new-tab script names the command twice: {:?}", iterm.args);
         }
-        assert_eq!(build_launch_command("xfce4-terminal", &unix, false).unwrap().args, vec!["-e".to_string(), quoted.to_string()]);
+        assert_eq!(build_launch_command("xfce4-terminal", &argv, false).unwrap().args, vec!["-e".to_string(), quoted.to_string()]);
         for (id, prefix) in [("gnome-terminal", vec!["--"]), ("konsole", vec!["-e"]), ("kitty", vec![]), ("wezterm", vec!["start", "--"])] {
-            let spec = build_launch_command(id, &unix, false).unwrap();
-            let expected: Vec<String> = prefix.into_iter().map(String::from).chain(unix.iter().cloned()).collect();
+            let spec = build_launch_command(id, &argv, false).unwrap();
+            let expected: Vec<String> = prefix.into_iter().map(String::from).chain(argv.iter().cloned()).collect();
             assert_eq!(spec.args, expected, "{id}");
         }
+        assert_eq!(build_launch_command("wt", &argv, false).unwrap().args, argv);
+    }
 
-        let windows = ssh_argv(
-            &["-o".to_string(), "IdentityAgent=//./pipe/sshelter-connect-00".to_string(), "-o".to_string(), "ForwardAgent=no".to_string()],
-            "web",
-        );
-        assert_eq!(build_launch_command("wt", &windows, false).unwrap().args, windows);
-        let cmd = build_launch_command("cmd", &windows, false).unwrap();
-        assert_eq!(cmd.args[..5], ["/c", "start", "", "cmd", "/k"].map(String::from));
-        assert_eq!(cmd.args[5..], windows[..]);
+    /// macOS and Linux connect through `sshelter connect`; Windows keeps `ssh <alias>` until phase 3.
+    #[test]
+    fn the_launch_runs_sshelter_connect_on_macos_and_linux_and_ssh_on_windows() {
+        let id = if cfg!(windows) { "cmd" } else { "kitty" };
+        let spec = launch_for(id, "web", false).unwrap();
+        if cfg!(windows) {
+            assert_eq!(spec.args, vec!["/c", "start", "", "cmd", "/k", "ssh", "web"]);
+        } else {
+            let exe = std::env::current_exe().unwrap().to_string_lossy().into_owned();
+            assert_eq!(spec.args, vec![exe, "connect".to_string(), "web".to_string()]);
+        }
     }
 
     #[test]
@@ -932,150 +929,4 @@ mod tests {
         let err = build_launch("nope-term", "web", false).unwrap_err();
         assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
     }
-
-    // ── password auto-fill launch ─────────────────────────────────────────────
-
-    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
-        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
-    }
-
-    #[test]
-    fn autofill_ssh_argv_limits_password_attempts_and_disables_kbdint() {
-        let argv = autofill_ssh_argv("web");
-        // One wrong saved password must not burn three attempts against
-        // fail2ban-style lockouts.
-        assert!(argv.windows(2).any(|w| w == ["-o", "NumberOfPasswordPrompts=1"]));
-        // Same anti-phishing model as deploy: with kbdint off, every prompt the
-        // helper sees is client-generated; server-controlled text never reaches it.
-        assert!(argv.windows(2).any(|w| w == ["-o", "KbdInteractiveAuthentication=no"]));
-        // A global `BatchMode yes` would silently disable password auth.
-        assert!(argv.windows(2).any(|w| w == ["-o", "BatchMode=no"]));
-        assert_eq!(argv.last().unwrap(), "web", "alias must come last");
-    }
-
-    #[test]
-    fn autofill_ssh_argv_keeps_the_session_interactive() {
-        // This launches a real terminal session: -T (no pty) would break the
-        // interactive shell, and pinning StrictHostKeyChecking/PreferredAuthentications
-        // is the precheck's job — an existing working key must still win.
-        let argv = autofill_ssh_argv("web");
-        assert!(!argv.iter().any(|a| a == "-T"));
-        assert!(!argv.iter().any(|a| a.starts_with("StrictHostKeyChecking")));
-        assert!(!argv.iter().any(|a| a.starts_with("PreferredAuthentications")));
-    }
-
-    #[test]
-    fn env_wrapped_argv_prefixes_env_program() {
-        // env(1) scopes the variables to the ssh process only — unlike shell
-        // `VAR=x` prefixes it also works when the user's shell is fish.
-        let env = pairs(&[("SSHELTER_ASKPASS", "1"), ("SSH_ASKPASS", "/a/b")]);
-        let argv: Vec<String> = vec!["ssh".into(), "web".into()];
-        assert_eq!(
-            env_wrapped_argv(&env, &argv),
-            vec!["env", "SSHELTER_ASKPASS=1", "SSH_ASKPASS=/a/b", "ssh", "web"]
-        );
-    }
-
-    #[test]
-    fn build_autofill_launch_macos_terminal_wraps_with_env() {
-        let env = pairs(&[
-            ("SSHELTER_ASKPASS", "1"),
-            ("SSH_ASKPASS", "/Applications/My SSHelter.app/sshelter"),
-        ]);
-        let spec = build_autofill_launch("terminal", "web", false, &env).unwrap();
-        assert_eq!(spec.program, "osascript");
-        // Shell-quoted first (space in the app path), AppleScript-escaped second.
-        assert_eq!(
-            spec.args.last().unwrap(),
-            "tell application \"Terminal\" to do script \"env SSHELTER_ASKPASS=1 \
-             'SSH_ASKPASS=/Applications/My SSHelter.app/sshelter' ssh -o BatchMode=no \
-             -o NumberOfPasswordPrompts=1 -o KbdInteractiveAuthentication=no web\""
-        );
-    }
-
-    #[test]
-    fn build_autofill_launch_linux_passes_env_argv_directly() {
-        let env = pairs(&[("SSH_ASKPASS", "/usr/bin/sshelter")]);
-        let spec = build_autofill_launch("gnome-terminal", "web", false, &env).unwrap();
-        assert_eq!(spec.program, "gnome-terminal");
-        assert_eq!(
-            spec.args,
-            vec![
-                "--",
-                "env",
-                "SSH_ASKPASS=/usr/bin/sshelter",
-                "ssh",
-                "-o",
-                "BatchMode=no",
-                "-o",
-                "NumberOfPasswordPrompts=1",
-                "-o",
-                "KbdInteractiveAuthentication=no",
-                "web"
-            ]
-        );
-    }
-
-    #[test]
-    fn build_autofill_launch_windows_wt_sets_runs_then_clears() {
-        let env = pairs(&[
-            ("SSHELTER_ASKPASS", "1"),
-            ("SSH_ASKPASS", r"C:\Program Files\SSHelter\sshelter.exe"),
-        ]);
-        let spec = build_autofill_launch("wt", "web", false, &env).unwrap();
-        assert_eq!(spec.program, "wt.exe");
-        assert_eq!(spec.args[..2], ["cmd".to_string(), "/k".to_string()]);
-        // `set "K=V"` quotes the value (the install path contains a space); the
-        // trailing `& set "K="` clears the variables from the surviving /k session
-        // so a later manual `ssh otherhost` in that window cannot reach our helper
-        // and be answered with THIS host's password.
-        assert_eq!(
-            spec.args[2],
-            "set \"SSHELTER_ASKPASS=1\" && \
-             set \"SSH_ASKPASS=C:\\Program Files\\SSHelter\\sshelter.exe\" && \
-             ssh -o BatchMode=no -o NumberOfPasswordPrompts=1 \
-             -o KbdInteractiveAuthentication=no web \
-             & set \"SSHELTER_ASKPASS=\" & set \"SSH_ASKPASS=\""
-        );
-
-        // new_tab keeps the existing `-w 0 nt` targeting.
-        let tab = build_autofill_launch("wt", "web", true, &env).unwrap();
-        assert_eq!(tab.args[..5], ["-w", "0", "nt", "cmd", "/k"].map(String::from));
-    }
-
-    #[test]
-    fn build_autofill_launch_windows_cmd_sets_runs_then_clears() {
-        let env = pairs(&[("SSHELTER_ASKPASS", "1")]);
-        let spec = build_autofill_launch("cmd", "web", false, &env).unwrap();
-        assert_eq!(spec.program, "cmd");
-        assert_eq!(
-            spec.args,
-            vec![
-                "/c".to_string(),
-                "start".to_string(),
-                String::new(),
-                "cmd".to_string(),
-                "/k".to_string(),
-                "set \"SSHELTER_ASKPASS=1\" && ssh -o BatchMode=no \
-                 -o NumberOfPasswordPrompts=1 -o KbdInteractiveAuthentication=no web \
-                 & set \"SSHELTER_ASKPASS=\""
-                    .to_string(),
-            ]
-        );
-    }
-
-    #[test]
-    fn build_autofill_launch_xfce4_uses_single_shell_string() {
-        let env = pairs(&[("SSH_ASKPASS", "/opt/s h/sshelter")]);
-        let spec = build_autofill_launch("xfce4-terminal", "web", false, &env).unwrap();
-        assert_eq!(
-            spec.args,
-            vec![
-                "-e".to_string(),
-                "env 'SSH_ASKPASS=/opt/s h/sshelter' ssh -o BatchMode=no \
-                 -o NumberOfPasswordPrompts=1 -o KbdInteractiveAuthentication=no web"
-                    .to_string(),
-            ]
-        );
-    }
 }
```

`src-tauri/src/deploy.rs`: apply this patch

```diff
--- a/src-tauri/src/deploy.rs
+++ b/src-tauri/src/deploy.rs
@@ -1428,29 +1428,6 @@ mod tests {
         ));
     }
 
-    #[test]
-    fn terminal_askpass_gate_needs_8_5_or_windows_8_6() {
-        // Connect 的自動填入是在「有 tty 的終端機裡」跑 ssh：
-        // - 非 Windows 沿用 8.5 門檻（force 蓋過 tty）。
-        // - Windows 8.1 只有在「開不到 console」時才走 askpass，終端機裡必然有
-        //   console，所以 Windows 門檻是 8.6（第一個支援 REQUIRE=force 的內建版）。
-        assert!(openssh_supports_forced_askpass_in_terminal("OpenSSH_9.6p1, LibreSSL 3.3.6"));
-        assert!(openssh_supports_forced_askpass_in_terminal("OpenSSH_8.5p1, OpenSSL 1.1.1"));
-        assert!(!openssh_supports_forced_askpass_in_terminal("OpenSSH_8.4p1, OpenSSL 1.1.1"));
-        assert!(openssh_supports_forced_askpass_in_terminal(
-            "OpenSSH_for_Windows_8.6p1, LibreSSL 3.4.3"
-        ));
-        assert!(openssh_supports_forced_askpass_in_terminal(
-            "OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2"
-        ));
-        assert!(!openssh_supports_forced_askpass_in_terminal(
-            "OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2"
-        ));
-        // 認不出版本 → 放行：多注入的環境變數在不支援的 ssh 上是無害的 no-op
-        //（終端機照樣出現一般密碼提示），少注入則是功能無聲失效。
-        assert!(openssh_supports_forced_askpass_in_terminal("something unparseable"));
-    }
-
     #[test]
     fn denied_password_with_answered_marker_is_wrong_password() {
         // helper 真的送出過密碼、伺服器仍拒絕 → 才是「密碼錯誤」。
```

`src-tauri/src/ipc/peer.rs`: apply this patch

```diff
--- a/src-tauri/src/ipc/peer.rs
+++ b/src-tauri/src/ipc/peer.rs
@@ -483,7 +483,7 @@ mod tests {
         );
     }
 
-    /// `executable_base` 讀出的名稱:小寫、沒有 `.exe`(Windows 的 `SSH.EXE` 與 `ssh.exe` 是同一個程式),讀不到路徑 → None。
+    /// `base_lower` 讀出的名稱:小寫、沒有 `.exe`(Windows 的 `SSH.EXE` 與 `ssh.exe` 是同一個程式),讀不到路徑 → None。
     #[test]
     fn the_base_name_is_lowercase_and_has_no_exe_extension() {
         assert_eq!(base_lower(&p(1, 0, r"C:\Windows\System32\OpenSSH\SSH.EXE", &[])).as_deref(), Some("ssh"));
@@ -546,30 +546,6 @@ mod tests {
         assert!(chain.iter().all(|p| p.argv.iter().all(|a| !a.contains("secret-token"))));
     }
 
-    #[cfg(unix)]
-    #[test]
-    fn the_executable_base_name_of_a_live_process_and_of_a_gone_one() {
-        let base = executable_base(std::process::id()).unwrap();
-        assert!(!base.is_empty() && !base.contains('/'));
-        assert_eq!(executable_base(u32::MAX - 7), None);
-    }
-
-    /// 別的程序(連上通道的 ssh 就是別的程序):名稱是它自己的執行檔,結束之後讀不到。期望值用 PATH 上找到的 `sleep` 解開 symlink 後的檔名
-    /// (系統回報的是真正的路徑,例如 busybox 的 applet 是 `busybox`)。
-    #[cfg(unix)]
-    #[test]
-    fn the_executable_base_of_another_live_process_is_its_own_file_name() {
-        let mut child = crate::process::spawn(std::process::Command::new("sleep").arg("30")).unwrap();
-        let pid = child.id();
-        let base = executable_base(pid);
-        child.kill().unwrap();
-        child.wait().unwrap();
-        let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap()).map(|dir| dir.join("sleep")).find(|p| p.is_file()).unwrap();
-        let expected = sleep.canonicalize().unwrap().file_name().unwrap().to_string_lossy().to_ascii_lowercase();
-        assert_eq!(base, Some(expected));
-        assert_eq!(executable_base(pid), None, "gone once it has been waited for");
-    }
-
     #[test]
     fn a_process_that_is_gone_gives_an_empty_chain() {
         #[cfg(unix)]
```

`src-tauri/src/ipc/pipe_windows.rs`: apply this patch

```diff
--- a/src-tauri/src/ipc/pipe_windows.rs
+++ b/src-tauri/src/ipc/pipe_windows.rs
@@ -237,15 +237,6 @@ mod tests {
         assert!(!other.contains("Another program"), "{other}");
     }
 
-    /// Connect 的一次性 pipe 只有一個 instance,名稱被佔用時開不起來(`FILE_FLAG_FIRST_PIPE_INSTANCE`),instance 關掉之後名稱又空出來。
-    #[test]
-    fn a_one_shot_pipe_cannot_be_opened_twice_under_one_name() {
-        let name = format!("sshelter-oneshot-test-{}", std::process::id());
-        let first = one_shot(&name).unwrap();
-        assert!(one_shot(&name).is_err(), "the name is taken");
-        drop(first);
-        assert!(one_shot(&name).is_ok(), "free again once the only instance is closed");
-    }
 
     #[test]
     fn a_pipe_name_someone_else_holds_is_an_error() {
```

`src/lib/agent.test.ts`: apply this patch

```diff
--- a/src/lib/agent.test.ts
+++ b/src/lib/agent.test.ts
@@ -10,8 +10,6 @@ import {
   approvalTitle,
   armAfterDelay,
   buildAnswer,
-  CONNECT_EXPIRED_EVENT,
-  connectExpiredMessage,
   destination,
   isAnswering,
   pendingFeed,
@@ -245,22 +243,3 @@ describe("the agent problem line", () => {
     expect(agentProblemText({ kind: "include_missing" })).toBe("Hosts that use keys in SSHelter can't reach its agent.");
   });
 });
-
-describe("the key channel that ssh asked too late", () => {
-  it("listens on the event the backend emits", () => {
-    expect(CONNECT_EXPIRED_EVENT).toBe("agent://connect-expired");
-  });
-
-  it("names the host and says what happened", () => {
-    expect(connectExpiredMessage("web")).toEqual({
-      title: "Connect to web again",
-      description:
-        "SSHelter offers the key for one minute after Connect, and ssh asked for it later (a new host's fingerprint question may have been open).",
-    });
-  });
-
-  it("shows hidden characters in the host's name instead of rendering them", () => {
-    expect(connectExpiredMessage("we\u202Eb").title).toBe("Connect to we⟨U+202E⟩b again");
-    expect(connectExpiredMessage("we\u0007b").title).toContain("⟨U+0007⟩");
-  });
-});
```

`src/lib/sync-events.test.ts`: apply this patch

```diff
--- a/src/lib/sync-events.test.ts
+++ b/src/lib/sync-events.test.ts
@@ -201,14 +201,13 @@ describe("subscribeSyncEvents", () => {
     const bus = stubEventBus();
     const queryClient = new QueryClient();
     const stop = subscribeSyncEvents(queryClient);
-    await vi.waitFor(() => expect(bus.handlers.size).toBe(6));
+    await vi.waitFor(() => expect(bus.handlers.size).toBe(5));
     return { ...bus, queryClient, stop };
   }
 
   it("listens to the engine's events and never asks for a sync round itself", async () => {
     const { handlers, commands, emit, stop } = await subscribed();
     expect([...handlers.keys()].sort()).toEqual([
-      "agent://connect-expired",
       "sync://applied",
       "sync://approval",
       "sync://conflict",
@@ -221,7 +220,6 @@ describe("subscribeSyncEvents", () => {
     emit("sync://approval", [{ space_id: "a", space_name: "Work", aliases: ["web"] }]);
     emit("sync://conflict", [{ space_id: "a", space_name: "Work", aliases: ["web"] }]);
     emit("sync://notice", { kind: "space_deleted", name: "Work", by_device: "MacBook-A" });
-    emit("agent://connect-expired", "web");
     stop();
     expect(commands.filter((c) => c.startsWith("sync_"))).toEqual([]);
   });
@@ -275,27 +273,6 @@ describe("subscribeSyncEvents", () => {
     expect(useUiStore.getState()).toEqual(expect.objectContaining({ settingsOpen: true, settingsCategory: "sync" }));
   });
 
-  it("toasts a Connect whose ssh asked for the key after the channel's one-minute window, naming the host", async () => {
-    const { emit } = await subscribed();
-    emit("agent://connect-expired", "web");
-    expect(toast.getToasts()).toEqual([
-      expect.objectContaining({
-        type: "warning",
-        title: "Connect to web again",
-        description:
-          "SSHelter offers the key for one minute after Connect, and ssh asked for it later (a new host's fingerprint question may have been open).",
-      }),
-    ]);
-  });
-
-  it("shows the hidden characters of the host's name in that toast", async () => {
-    const { emit } = await subscribed();
-    emit("agent://connect-expired", SPOOFED_NAME);
-    const [shown] = toast.getToasts();
-    expect(shown).toEqual(expect.objectContaining({ title: `Connect to ${SPOOFED_NAME_SHOWN} again` }));
-    expect(JSON.stringify(shown)).not.toMatch(/[\u202E\u200B]/);
-  });
-
   it("leaves the keys notice to its dialog", async () => {
     const { emit } = await subscribed();
     emit("sync://notice", { kind: "keys_needed", names: ["id_mac"] });
@@ -316,7 +293,6 @@ describe("subscribeSyncEvents", () => {
     bus.emit("sync://applied", 2);
     bus.emit("sync://conflict", [{ space_id: "a", space_name: "Work", aliases: ["web"] }]);
     bus.emit("sync://notice", { kind: "space_deleted", name: "Work", by_device: "MacBook-A" });
-    bus.emit("agent://connect-expired", "web");
     expect(queryClient.getQueryData(syncOverviewKey)).toBeUndefined();
     expect(queryClient.getQueryState(["config", "hosts"])?.isInvalidated).toBe(false);
     expect(queryClient.getQueryState(syncApprovalsKey)?.isInvalidated).toBe(false);
```

- [ ] **Step 2: Run them to see them fail**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- connect::tests:: --skip session::)
```

(`--skip session::` leaves out `session::connect::tests`, which the filter also matches.)

Expected: FAIL to compile (exit code 101), before any test runs. The first error and the last line:

```text
error[E0425]: cannot find function `connect_argv` in this scope
error: could not compile `sshelter` (lib test) due to 2 previous errors
```

- [ ] **Step 3: Switch the launch and delete what it leaves unused**

`src-tauri/src/agent/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/agent/mod.rs
+++ b/src-tauri/src/agent/mod.rs
@@ -1,7 +1,6 @@
 //! SSHelter 的 SSH agent(key roadmap 第 2 階段 spec §5)。
 pub mod approval;
 pub mod broker;
-pub mod oneshot;
 #[cfg(test)]
 mod openssh_tests;
 pub mod prompt;
```

`src-tauri/src/agent/oneshot.rs`: delete the file (`git rm src-tauri/src/agent/oneshot.rs`)

`src-tauri/src/agent/session.rs`: apply this patch

```diff
--- a/src-tauri/src/agent/session.rs
+++ b/src-tauri/src/agent/session.rs
@@ -86,25 +86,6 @@ pub fn serve(stream: &mut (impl Read + Write), authority: &dyn SignAuthority) ->
     Ok(())
 }
 
-/// 不提供任何金鑰的 authority:只想測連線與端點、不在乎簽章的測試用(`oneshot`)。
-#[cfg(test)]
-pub(crate) mod testing {
-    use ssh_key::public::KeyData;
-
-    use super::{SignAuthority, SignRequest};
-
-    pub struct NoKeys;
-
-    impl SignAuthority for NoKeys {
-        fn identities(&self) -> Vec<(KeyData, String)> {
-            Vec::new()
-        }
-        fn sign(&self, _request: &SignRequest) -> Option<Vec<u8>> {
-            None
-        }
-    }
-}
-
 #[cfg(test)]
 mod tests {
     use super::*;
```

`src-tauri/src/connect.rs`: apply this patch

```diff
--- a/src-tauri/src/connect.rs
+++ b/src-tauri/src/connect.rs
@@ -223,6 +223,8 @@ fn linux_args(id: &str, argv: &[String]) -> Option<Vec<String>> {
 /// or, when `new_tab` is true and the terminal supports it (only iTerm2), a new TAB of the
 /// current window (falling back to a new window when none exists).
 /// PURE function. The alias is assumed pre-validated; thin wrapper over `build_launch_command`.
+/// Windows still connects with the system `ssh` (`launch_for`, until phase 3); elsewhere only the tests use it.
+#[cfg(any(windows, test))]
 pub fn build_launch(terminal_id: &str, alias: &str, new_tab: bool) -> Result<LaunchSpec, AppError> {
     build_launch_command(terminal_id, &["ssh".to_string(), alias.to_string()], new_tab)
 }
@@ -353,169 +355,26 @@ pub fn build_launch_command(
     }
 }
 
-// ─── Password auto-fill (saved keychain password → askpass injection) ────────
-
-/// ssh argv (no program) for a password auto-fill connect. Mirrors the deploy
-/// argv's safety options but stays interactive: no `-T` (the session needs a
-/// pty), no pinned StrictHostKeyChecking (the caller pre-checks known_hosts),
-/// and no PreferredAuthentications so an existing working key still wins.
-pub fn autofill_ssh_argv(alias: &str) -> Vec<String> {
-    vec![
-        // A global `BatchMode yes` would silently disable password prompts.
-        "-o".to_string(), "BatchMode=no".to_string(),
-        // One wrong saved password must not burn three attempts against
-        // fail2ban-style lockouts.
-        "-o".to_string(), "NumberOfPasswordPrompts=1".to_string(),
-        // Same anti-phishing model as deploy (see `deploy::build_deploy_argv`):
-        // with kbdint off, every prompt the helper sees is client-generated;
-        // server-controlled text never reaches it. Cost: kbdint-only hosts
-        // (PAM 2FA) are not eligible for auto-fill — don't save a password there.
-        "-o".to_string(), "KbdInteractiveAuthentication=no".to_string(),
-        alias.to_string(),
-    ]
-}
-
-/// Wrap `argv` with env(1) assignments: `env K=V … <argv…>`. env scopes the
-/// variables to the ssh process only — nothing lingers in the shell session —
-/// and unlike `VAR=x cmd` prefixes it also works when the user's shell is fish.
-pub fn env_wrapped_argv(env_pairs: &[(String, String)], argv: &[String]) -> Vec<String> {
-    std::iter::once("env".to_string())
-        .chain(env_pairs.iter().map(|(k, v)| format!("{k}={v}")))
-        .chain(argv.iter().cloned())
-        .collect()
-}
+// ─── What the terminal runs ──────────────────────────────────────────────────
 
-/// One `cmd /k` command string: set the variables, run the command, then CLEAR
-/// the variables. The clearing tail is load-bearing: `/k` keeps the console
-/// session alive after ssh exits, and a leftover SSH_ASKPASS +
-/// SSHELTER_ASKPASS_ACCOUNT would make a later manual `ssh otherhost` in that
-/// window consult our helper — which would answer with THIS host's password
-/// (cross-host disclosure). `&` (not `&&`) so the clears run even when ssh
-/// fails. `set "K=V"` keeps spaces in values (the install path) intact.
-fn windows_autofill_cmd_string(env_pairs: &[(String, String)], command_argv: &[String]) -> String {
-    let sets: Vec<String> = env_pairs
-        .iter()
-        .map(|(k, v)| format!("set \"{k}={v}\""))
-        .collect();
-    let clears: Vec<String> = env_pairs
-        .iter()
-        .map(|(k, _)| format!("& set \"{k}=\""))
-        .collect();
-    format!(
-        "{} && {} {}",
-        sets.join(" && "),
-        command_argv.join(" "),
-        clears.join(" ")
-    )
+/// `<SSHelter's executable> connect <alias>`: the command the terminal runs to connect through SSHelter's own SSH client (own-ssh spec
+/// §7.4). The alias must be validated first.
+pub fn connect_argv(exe: &std::path::Path, alias: &str) -> Vec<String> {
+    vec![exe.to_string_lossy().into_owned(), "connect".to_string(), alias.to_string()]
 }
 
-/// Build the terminal launch for a password auto-fill connect.
-///
-/// POSIX terminals run `env K=V … ssh …` (per-process scope; every argv element
-/// still goes through the existing quoting paths). Windows terminals cannot
-/// take env assignments as argv, so both wt and cmd run one `cmd /k` string
-/// that sets the variables, runs ssh, and clears them again — deterministic
-/// even when Windows Terminal gloms the tab onto an existing window process
-/// that never inherited our environment.
-pub fn build_autofill_launch(
-    terminal_id: &str,
-    alias: &str,
-    new_tab: bool,
-    env_pairs: &[(String, String)],
-) -> Result<LaunchSpec, AppError> {
-    let ssh_argv: Vec<String> = std::iter::once("ssh".to_string())
-        .chain(autofill_ssh_argv(alias))
-        .collect();
-    match terminal_id {
-        "wt" => {
-            let mut args: Vec<String> = if new_tab {
-                vec!["-w".into(), "0".into(), "nt".into()]
-            } else {
-                Vec::new()
-            };
-            args.extend([
-                "cmd".to_string(),
-                "/k".to_string(),
-                windows_autofill_cmd_string(env_pairs, &ssh_argv),
-            ]);
-            Ok(LaunchSpec { program: "wt.exe".into(), args })
-        }
-        "cmd" => Ok(LaunchSpec {
-            program: "cmd".into(),
-            args: vec![
-                "/c".into(),
-                "start".into(),
-                String::new(),
-                "cmd".into(),
-                "/k".into(),
-                windows_autofill_cmd_string(env_pairs, &ssh_argv),
-            ],
-        }),
-        other => build_launch_command(other, &env_wrapped_argv(env_pairs, &ssh_argv), new_tab),
+/// The launch for connecting to `alias` in `terminal_id`: `sshelter connect <alias>` on macOS and Linux; on Windows still `ssh <alias>`,
+/// because `sshelter connect` needs a console there, which is phase 3 (spec §13, §16).
+pub fn launch_for(terminal_id: &str, alias: &str, new_tab: bool) -> Result<LaunchSpec, AppError> {
+    #[cfg(unix)]
+    {
+        let exe = std::env::current_exe().map_err(|e| AppError::Other(format!("cannot locate SSHelter: {e}")))?;
+        build_launch_command(terminal_id, &connect_argv(&exe, alias), new_tab)
     }
-}
-
-/// Decide whether THIS connect can auto-fill the saved password, and build the
-/// askpass environment if so. Every gate falls back to a plain launch (`None`)
-/// — auto-fill is a convenience and must never make Connect stop working. The
-/// password itself NEVER appears in the launch command; the helper reads it
-/// from the keychain via SSHELTER_ASKPASS_ACCOUNT.
-///
-/// Gates, in order (all mirror in-app deploy's reasoning):
-/// 1. a non-empty saved password exists in the OS keychain,
-/// 2. the loaded config root is the default `~/.ssh/config` — the terminal runs
-///    plain `ssh <alias>`, so reasoning based on any other file would be about
-///    a config ssh will not read,
-/// 3. the local ssh can force askpass while holding a tty
-///    (`deploy::openssh_supports_forced_askpass_in_terminal`),
-/// 4. the alias is not behind ProxyJump/ProxyCommand — the jump host's password
-///    prompt is a perfectly legal shape and would be answered with the TARGET
-///    host's password,
-/// 5. the host key is already in known_hosts: SSH_ASKPASS_REQUIRE=force routes
-///    the host-key confirmation to the helper too, which refuses it (multiline
-///    whitelist rule), so a first-time host would abort instead of asking — let
-///    a plain launch handle that first connection interactively.
-fn password_autofill_env(
-    state: &tauri::State<crate::state::AppState>,
-    alias: &str,
-) -> Option<Vec<(String, String)>> {
-    let account = crate::secrets::host_account(alias);
-    match crate::secrets::get(&account) {
-        Ok(Some(secret)) if !secret.is_empty() => {}
-        _ => return None,
+    #[cfg(windows)]
+    {
+        build_launch(terminal_id, alias, new_tab)
     }
-    if !crate::deploy::is_default_config_root(state) {
-        return None;
-    }
-    if !crate::deploy::openssh_supports_forced_askpass_in_terminal(
-        &crate::deploy::local_ssh_version(),
-    ) {
-        return None;
-    }
-    let pairs = crate::config::intel::effective_config(alias, None).ok()?;
-    if crate::deploy::has_proxy(&pairs) {
-        return None;
-    }
-    let ep = crate::deploy::endpoint_from_effective(&pairs)?;
-    let known = crate::process::output(
-        crate::process::background_command("ssh-keygen").args(crate::deploy::keygen_find_args(&ep)),
-    )
-    .ok()?;
-    if String::from_utf8_lossy(&known.stdout).trim().is_empty() {
-        return None;
-    }
-    let exe = std::env::current_exe().ok()?;
-    Some(vec![
-        ("SSHELTER_ASKPASS".to_string(), "1".to_string()),
-        ("SSHELTER_ASKPASS_ACCOUNT".to_string(), account),
-        ("SSH_ASKPASS".to_string(), exe.to_string_lossy().into_owned()),
-        ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
-    ])
-}
-
-/// `ssh <options…> <alias>`。
-pub fn ssh_argv(options: &[String], alias: &str) -> Vec<String> {
-    std::iter::once("ssh".to_string()).chain(options.iter().cloned()).chain(std::iter::once(alias.to_string())).collect()
 }
 
 /// Spawn the launch spec detached, inheriting the environment. Not unit-tested (side effect).
@@ -531,19 +390,14 @@ pub fn connect_list_terminals() -> Vec<TerminalInfo> {
     detect_terminals()
 }
 
-// (async): the auto-fill prechecks spawn `ssh -V`, `ssh -G`, and
-// `ssh-keygen -F`, and the vault-key check (`oneshot::prepare`) spawns `ssh -G`
-// — that must not run on the main thread.
+// (async): spawning the terminal (osascript on macOS) does not belong on the main thread.
 #[tauri::command(async)]
 pub fn connect_launch(
-    app: tauri::AppHandle,
     state: tauri::State<crate::state::AppState>,
     alias: String,
     terminal_override: Option<String>,
     new_tab: Option<bool>,
 ) -> Result<(), AppError> {
-    // Scoped: `password_autofill_env` takes the same lock again (via
-    // `is_default_config_root`); holding it across that call would deadlock.
     {
         let doc_lock = state.doc.lock().unwrap();
         let doc = doc_lock
@@ -563,27 +417,7 @@ pub fn connect_launch(
         }
     };
 
-    let new_tab = new_tab.unwrap_or(false);
-    // 用「只在 SSHelter」金鑰的主機經一次性通道連(金鑰保管庫 spec §5.6);其他主機照舊(含密碼自動填入)。
-    // The channel closes itself unless it is kept: any `?` before `keep` below drops it, which cancels it.
-    let channel = crate::agent::oneshot::prepare(&app, &alias)?;
-    let spec = match &channel {
-        Some(channel) => build_launch_command(
-            &terminal_id,
-            &ssh_argv(&crate::agent::oneshot::ssh_options(channel), &alias),
-            new_tab,
-        )?,
-        None => match password_autofill_env(&state, &alias) {
-            Some(env_pairs) => build_autofill_launch(&terminal_id, &alias, new_tab, &env_pairs)?,
-            None => build_launch(&terminal_id, &alias, new_tab)?,
-        },
-    };
-    launch(&spec)?;
-    // The terminal started: leave the channel to its ssh.
-    if let Some(channel) = channel {
-        channel.keep();
-    }
-    Ok(())
+    launch(&launch_for(&terminal_id, &alias, new_tab.unwrap_or(false))?)
 }
 
 // ─── Tests ──────────────────────────────────────────────────────────────────
```

`src-tauri/src/deploy.rs`: apply this patch

```diff
--- a/src-tauri/src/deploy.rs
+++ b/src-tauri/src/deploy.rs
@@ -465,24 +465,6 @@ fn require_default_config_root(state: &tauri::State<crate::state::AppState>) ->
     Ok(())
 }
 
-/// `require_default_config_root` 的布林版，給「不該報錯、只該安靜退回」的呼叫端
-/// （connect 的密碼自動填入）。理由同上：終端機跑的是 `ssh <alias>`（無 `-F`），
-/// 對非預設 config 的推理可能與 ssh 實際讀到的設定無關。
-pub(crate) fn is_default_config_root(state: &tauri::State<crate::state::AppState>) -> bool {
-    let Some(loaded) = ({
-        let doc_lock = state.doc.lock().unwrap();
-        doc_lock
-            .as_ref()
-            .and_then(|d| d.files.first().map(|f| f.path.clone()))
-    }) else {
-        return false;
-    };
-    let Ok(default) = crate::config::commands::default_config_path() else {
-        return false;
-    };
-    loaded.canonicalize().ok() == default.canonicalize().ok() || loaded == default
-}
-
 /// `ssh -V` 的輸出（版本寫在 stderr；順手併上 stdout 以防未來變動）。
 pub(crate) fn local_ssh_version() -> String {
     crate::process::output(crate::process::background_command("ssh").arg("-V"))
@@ -621,23 +603,6 @@ pub fn openssh_supports_askpass_require(version_line: &str) -> bool {
     }
 }
 
-/// Connect 自動填入用的閘門：在「有 tty 的終端機裡」強制 askpass。
-///
-/// 與 `openssh_supports_askpass_require`（部署用，子程序無 console）只差 Windows
-/// 門檻：8.1 走 askpass 的前提是「開不到 console」，終端機裡必然有 console，所以
-/// 8.1 在這個情境等於不支援；8.6（Win11 內建）起 `SSH_ASKPASS_REQUIRE=force` 直接
-/// 蓋過 tty（v8.6.0.0 readpass.c，並經 Win32-OpenSSH#2115 實測證實）。
-///
-/// 認不出版本 → 放行：多注入的環境變數在不支援的 ssh 上是無害的 no-op（終端機照樣
-/// 出現一般密碼提示），少注入則是功能無聲失效。
-pub fn openssh_supports_forced_askpass_in_terminal(version_line: &str) -> bool {
-    match parse_openssh_version(version_line) {
-        Some((major, minor, true)) => (major, minor) >= (8, 6),
-        Some((major, minor, false)) => (major, minor) >= (8, 5),
-        None => true,
-    }
-}
-
 /// 解析 `ssh -V` 的版本行，回 `(major, minor, 是否為 Microsoft Windows port)`。
 /// Windows port 自報 `OpenSSH_for_Windows_X.Y`，上游則是 `OpenSSH_X.Y`。
 fn parse_openssh_version(version_line: &str) -> Option<(u32, u32, bool)> {
```

`src-tauri/src/ipc/peer.rs`: apply this patch

```diff
--- a/src-tauri/src/ipc/peer.rs
+++ b/src-tauri/src/ipc/peer.rs
@@ -123,11 +123,6 @@ pub fn process_chain(pid: u32) -> Vec<ProcInfo> {
     walk(pid, proc_info)
 }
 
-/// `pid` 的執行檔名稱(小寫、去掉 `.exe`);讀不到(程序已經結束)→ None。
-pub fn executable_base(pid: u32) -> Option<String> {
-    base_lower(&proc_info(pid)?)
-}
-
 /// `process_chain` 的走法;讀一個程序的函式由呼叫端給(測試用假的)。
 fn walk(pid: u32, mut read: impl FnMut(u32) -> Option<ProcInfo>) -> Vec<ProcInfo> {
     let mut out: Vec<ProcInfo> = Vec::new();
```

`src-tauri/src/ipc/pipe_windows.rs`: apply this patch

```diff
--- a/src-tauri/src/ipc/pipe_windows.rs
+++ b/src-tauri/src/ipc/pipe_windows.rs
@@ -116,7 +116,7 @@ fn wide_pipe_path(name: &str) -> Vec<u16> {
     format!(r"\\.\pipe\{name}").encode_utf16().chain(std::iter::once(0)).collect()
 }
 
-/// 建一個 pipe instance。`max_instances`:agent 是 `PIPE_UNLIMITED_INSTANCES`,Connect 的一次性 pipe 是 1。
+/// 建一個 pipe instance。`max_instances`:agent 是 `PIPE_UNLIMITED_INSTANCES`(Connect 的一次性 pipe 隨第 1b 期刪掉了)。
 fn create_instance(path: &[u16], security: &OwnerOnly, first: bool, max_instances: u32) -> io::Result<OwnedHandle> {
     let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
     let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
@@ -156,11 +156,6 @@ pub(crate) fn accept(pipe: &OwnedHandle) -> io::Result<Option<u32>> {
     Ok(known.then_some(pid))
 }
 
-/// Connect 的一次性 pipe:只有一個 instance,名稱已經存在就失敗(`FILE_FLAG_FIRST_PIPE_INSTANCE`)。描述元在建立時複製,用完即丟。
-pub(crate) fn one_shot(name: &str) -> io::Result<OwnedHandle> {
-    let security = OwnerOnly::new()?;
-    create_instance(&wide_pipe_path(name), &security, true, 1)
-}
 
 /// 在 `dir` 拿鎖,開 `\\.\pipe\<name>`,每條連線交給 `handle`。另一個 SSHelter 拿著鎖 → `OtherInstance`;名稱被別的程式佔用(或其他開不起來的原因)→ 錯誤。
 pub fn listen(dir: &Path, name: &str, handle: Handler) -> Result<Started, AppError> {
```

`src-tauri/src/tray.rs`: apply this patch

```diff
--- a/src-tauri/src/tray.rs
+++ b/src-tauri/src/tray.rs
@@ -117,7 +117,7 @@ fn on_menu_event(app: &tauri::AppHandle, event: tauri::menu::MenuEvent) {
         "open" => crate::show_main_window(app),
         other => {
             if let Some(alias) = other.strip_prefix("connect:") {
-                // Off the menu thread: a host on a vault key runs `ssh -G` first (key vault spec §5.6).
+                // Off the menu thread: starting the terminal spawns a process (osascript on macOS).
                 let (app, alias) = (app.clone(), alias.to_string());
                 std::thread::spawn(move || {
                     if let Err(e) = quick_connect(&app, &alias) {
@@ -129,7 +129,7 @@ fn on_menu_event(app: &tauri::AppHandle, event: tauri::menu::MenuEvent) {
     }
 }
 
-/// Validate, then launch with the first detected terminal: a host on a vault key through a one-shot channel.
+/// Validate, then launch with the first detected terminal: `sshelter connect <alias>` (own-ssh spec §7.4; `ssh <alias>` on Windows).
 fn quick_connect(app: &tauri::AppHandle, alias: &str) -> Result<(), crate::error::AppError> {
     use crate::error::AppError;
 
@@ -147,22 +147,7 @@ fn quick_connect(app: &tauri::AppHandle, alias: &str) -> Result<(), crate::error
         .next()
         .ok_or_else(|| AppError::Other("no terminal found".to_string()))?;
 
-    // The channel closes itself unless it is kept: any `?` before `keep` below drops it, which cancels it.
-    let channel = crate::agent::oneshot::prepare(app, alias)?;
-    let spec = match &channel {
-        Some(channel) => crate::connect::build_launch_command(
-            &terminal.id,
-            &crate::connect::ssh_argv(&crate::agent::oneshot::ssh_options(channel), alias),
-            false,
-        )?,
-        None => crate::connect::build_launch(&terminal.id, alias, false)?,
-    };
-    crate::connect::launch(&spec)?;
-    // The terminal started: leave the channel to its ssh.
-    if let Some(channel) = channel {
-        channel.keep();
-    }
-    Ok(())
+    crate::connect::launch(&crate::connect::launch_for(&terminal.id, alias, false)?)
 }
 
 #[cfg(test)]
```

`src/lib/agent.ts`: apply this patch

```diff
--- a/src/lib/agent.ts
+++ b/src/lib/agent.ts
@@ -15,8 +15,6 @@ import { revealHidden } from "@/lib/sync-approvals";
  */
 
 export const APPROVALS_EVENT = "agent://approvals";
-/** Emitted with the host alias when ssh asked a Connect's one-shot key channel for the key after its one-minute window (`oneshot::CONNECT_EXPIRED_EVENT`). */
-export const CONNECT_EXPIRED_EVENT = "agent://connect-expired";
 
 export function fetchPending(): Promise<AgentApprovalRequest[]> {
   return tauriInvoke<AgentApprovalRequest[]>("agent_pending");
@@ -176,12 +174,3 @@ export function agentProblemText(problem: AgentProblem): string {
       return "Hosts that use keys in SSHelter can't reach its agent.";
   }
 }
-
-/** ssh asked the one-shot key channel for `alias` for the key after its one-minute window, so it was not offered (key vault spec §5.6, §11). */
-export function connectExpiredMessage(alias: string): { title: string; description: string } {
-  return {
-    title: `Connect to ${revealHidden(alias)} again`,
-    description:
-      "SSHelter offers the key for one minute after Connect, and ssh asked for it later (a new host's fingerprint question may have been open).",
-  };
-}
```

`src/lib/sync-events.ts`: apply this patch

```diff
--- a/src/lib/sync-events.ts
+++ b/src/lib/sync-events.ts
@@ -7,7 +7,6 @@ import type { ApprovalNotice } from "@/bindings/ApprovalNotice";
 import type { SyncConflict } from "@/bindings/SyncConflict";
 import type { SyncNotice } from "@/bindings/SyncNotice";
 import type { SyncOverview } from "@/bindings/SyncOverview";
-import { CONNECT_EXPIRED_EVENT, connectExpiredMessage } from "@/lib/agent";
 import { listNames } from "@/lib/format";
 import { syncApprovalsKey, syncOverviewKey } from "@/lib/sync";
 import { approvalMessage, revealHidden } from "@/lib/sync-approvals";
@@ -119,8 +118,7 @@ export function openSyncSettings(): void {
  * Sync engine → UI. Status pushes refresh every overview reader without polling;
  * applied remote changes refresh the config views (a newly synced host can shadow
  * a local one) and the approval list; conflicts, hosts held for approval and
- * notices surface as toasts, and so does a Connect whose ssh asked its one-shot key
- * channel for the key after the one-minute window (`agent://connect-expired`, key vault spec §11).
+ * notices surface as toasts.
  * The backend starts a round itself when the window regains focus, so nothing
  * here asks for one — a second round would double the relay usage.
  * Returns the unsubscribe function.
@@ -181,11 +179,6 @@ export function subscribeSyncEvents(queryClient: QueryClient): () => void {
     });
   });
 
-  on<string>(CONNECT_EXPIRED_EVENT, (alias) => {
-    const m = connectExpiredMessage(alias);
-    toast.warning(m.title, { description: m.description });
-  });
-
   return () => {
     disposed = true;
     unlisten.forEach((u) => void release(u));
```

- [ ] **Step 4: Run them to see them pass**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- connect::tests:: --skip session::)
```

Expected: PASS, `test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 1657 filtered out`. Then the modules that lost code:

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- deploy:: ipc:: agent::)
```

Expected: PASS, `test result: ok. 191 passed; 0 failed; 0 ignored; 0 measured; 1495 filtered out`; the leftover check prints 0, 0 and 0.

```bash
./node_modules/.bin/vitest run --exclude '.claude/**' src/lib/agent.test.ts src/lib/sync-events.test.ts
```

Expected: PASS, `Test Files 2 passed (2)`, `Tests 47 passed (47)`.

- [ ] **Step 5: Run the whole lib suite and the whole frontend**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1684 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out` (fewer than after Task 4: the deleted code's tests go); the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

```bash
./node_modules/.bin/vitest run --exclude '.claude/**'
./node_modules/.bin/tsc --noEmit
```

Expected: `Test Files 52 passed (52)`, `Tests 851 passed (851)` (five tests fewer than after Task 3), and `tsc` prints nothing and exits 0.

- [ ] **Step 6: Commit**

The deletion of `oneshot.rs` was staged by the `git rm` of Step 3, so it is not in the `git add` below.

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/agent/mod.rs \
  src-tauri/src/agent/openssh_tests.rs \
  src-tauri/src/agent/session.rs \
  src-tauri/src/connect.rs \
  src-tauri/src/deploy.rs \
  src-tauri/src/ipc/peer.rs \
  src-tauri/src/ipc/pipe_windows.rs \
  src-tauri/src/tray.rs \
  src/lib/agent.test.ts \
  src/lib/agent.ts \
  src/lib/sync-events.test.ts \
  src/lib/sync-events.ts
git commit -m "feat(connect): open sshelter connect from Connect, the palette and the tray, and drop the password autofill and the one-shot key channel"
```

Expected: `git status --short` lists the thirteen files of this task, `src-tauri/src/agent/oneshot.rs` as `D` (deleted); the `git diff --stat` prints nothing.

---

### Task 6: `sshelter connect` end to end against a scratch sshd

**Files:**
- Create: `src-tauri/src/cli/e2e_tests.rs`
- Modify: `src-tauri/src/cli/mod.rs` (`#[cfg(all(test, unix))] mod e2e_tests;`)

**Interfaces:**
- Consumes: Task 2's `run::run`, Task 1's `Tty`, `Input` and `fake::FakeTermios`; plan 1b-1's `Broker`, `HostDirectory`, `HostKeyConfirmer`, `HostQuery`, `FakeDirectory::with_hop`, `FakeKeys::with_key`, `FakeConfirmer::deciding`, `Decision`; Task 2's `session::{ipc_dir, socket_path}`; phase 0's `ipc::server::listen_unix`; plan 1a's `RusshEngine`, the `Server` fixture (`hop_with`, `host_key`, `key`), `Proxy` and `Mode::Cut`, `eventually`, `harness::tools`; `sync::testkit::MemKeychain`.
- Produces: tests only.

What shapes this task:
- R14 asks for a few end-to-end tests with the real engine against the scratch sshd through the real IPC socket in a temp directory. These run the whole chain of `sshelter connect`: the CLI's loop of Task 2 with a fake termios (the only double on the terminal side), the broker of plan 1b-1 behind a socket that `listen_unix` makes in a temp directory under `/tmp` (macOS limits a socket's path to 104 bytes), the real engine, and a scratch OpenSSH whose shell is `/bin/sh`. Only the window is scripted.
- Three cases: the first contact — the notice `Waiting for you to confirm lab's host key in SSHelter.` on stderr, the key pinned, a command typed into the raw terminal, `exit 7` and exit code 7, the terminal as it was; a key the person does not trust — exit 255, `The host key of lab has not been confirmed yet.`, nothing pinned; a link cut by the proxy while the shell runs — exit 255 and `Connection to lab lost (early eof).` on a line of its own, never 0.
- The code is all there, so the tests pass at once; Step 5 shows that they can fail, with two edits that each must break them.

- [ ] **Step 1: Write the tests**

`src-tauri/src/cli/e2e_tests.rs`: create

```rust
//! `sshelter connect` the whole way (plan 1b): the CLI's loop with a fake terminal, the broker on a real socket, the real engine, and a
//! scratch OpenSSH. The window that confirms host keys is scripted; nothing else is a double.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use super::client::Input;
use super::run::run;
use super::terminal::fake::FakeTermios;
use super::terminal::Tty;
use crate::session::broker::Broker;
use crate::session::connect::HostKeyConfirmer;
use crate::session::directory::HostDirectory;
use crate::session::protocol::HostQuery;
use crate::session::testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys};
use crate::ssh::russh_engine::RusshEngine;
use crate::ssh::testing::eventually;
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::{AuthMethod, HostId};
use crate::sync::testkit::MemKeychain;

/// A shell of `/bin/sh` for the scratch sshd (as the engine's own tests use), so the prompt does not depend on anyone's shell setup.
const SHELL: &str = "ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi";

/// A `Write` the test reads while the run goes on.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

struct Session {
    termios: Arc<FakeTermios>,
    keys: Sender<Input>,
    stdout: Shared,
    stderr: Shared,
    run: std::thread::JoinHandle<i32>,
    directory: Arc<FakeDirectory>,
    _dir: tempfile::TempDir,
}

impl Session {
    fn type_text(&self, text: &str) {
        self.keys.send(Input::Stdin(text.as_bytes().to_vec())).unwrap();
    }

    fn finish(self) -> (i32, String, Arc<FakeTermios>, Arc<FakeDirectory>) {
        eventually("sshelter connect to end", 30, || self.run.is_finished());
        let stderr = self.stderr.text();
        (self.run.join().unwrap(), stderr, self.termios, self.directory)
    }
}

/// `sshelter connect lab`, where `lab` is a scratch sshd reached on `port` (its own, or a proxy's) with its user key in the vault.
fn connect(server: &Server, port: u16, decisions: Vec<Decision>) -> Session {
    let directory = Arc::new(FakeDirectory::new().with_hop(server.hop_with("lab", port, AuthMethod::Key { key_id: "k1".into() })));
    let broker = Broker::new(
        Arc::new(RusshEngine::new()),
        Arc::clone(&directory) as Arc<dyn HostDirectory>,
        Arc::new(FakeKeys::new().with_key("k1", "lab key", &server.key.private_text)),
        Arc::new(MemKeychain::default()),
        Arc::new(FakeConfirmer::deciding(decisions)) as Arc<dyn HostKeyConfirmer>,
    );
    let dir = tempfile::Builder::new().prefix("sc").tempdir_in("/tmp").unwrap();
    let ipc = crate::session::ipc_dir(dir.path());
    crate::ipc::server::listen_unix(&ipc, broker.handler()).unwrap();
    let stream = UnixStream::connect(crate::session::socket_path(dir.path())).unwrap();
    let termios = FakeTermios::new();
    let (sender, receiver) = std::sync::mpsc::channel();
    let (stdout, stderr) = (Shared::default(), Shared::default());
    let run = {
        let (termios, sender, mut stdout, mut stderr) = (Arc::clone(&termios), sender.clone(), stdout.clone(), stderr.clone());
        std::thread::spawn(move || {
            let mut tty = Tty::new(termios).unwrap();
            run(stream, HostQuery::Alias("lab".into()), "xterm-256color".into(), &mut tty, (sender, receiver), &mut stdout, &mut stderr)
        })
    };
    Session { termios, keys: sender, stdout, stderr, run, directory, _dir: dir }
}

fn raw(termios: &FakeTermios) -> bool {
    termios.now().c_lflag & libc::ICANON == 0
}

/// The first contact: the host key is confirmed in the window and pinned, the shell runs a command, and its exit status is the CLI's.
#[test]
fn sshelter_connect_confirms_the_host_key_runs_a_shell_and_exits_with_its_status() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SHELL]);
    let session = connect(&server, server.sshd.port, vec![Decision::Trust]);
    eventually("the shell to open", 30, || raw(&session.termios));
    eventually("a prompt", 20, || session.stdout.text().contains("$ "));
    session.type_text("echo SSHELTER_$((6*7))\r");
    eventually("the command's output", 20, || session.stdout.text().contains("SSHELTER_42"));
    session.type_text("exit 7\r");
    let (code, stderr, termios, directory) = session.finish();
    assert_eq!(code, 7);
    assert_eq!(stderr, "Waiting for you to confirm lab's host key in SSHelter.\n");
    assert!(termios.is_start(&termios.now()), "the terminal is as it was");
    assert_eq!(directory.pins().get(&HostId::from("host-lab")).map(|pin| pin.key.clone()), Some(server.host_key()));
}

/// The person does not trust the key: nothing is pinned, the CLI says so and exits 255, as ssh does for a refused key.
#[test]
fn a_host_key_the_person_does_not_trust_ends_sshelter_connect() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SHELL]);
    let session = connect(&server, server.sshd.port, vec![Decision::Refuse]);
    let (code, stderr, termios, directory) = session.finish();
    assert_eq!(code, 255);
    assert_eq!(stderr, "Waiting for you to confirm lab's host key in SSHelter.\nThe host key of lab has not been confirmed yet.\n");
    assert!(termios.is_start(&termios.now()));
    assert!(directory.pins().is_empty());
}

/// The link is cut while the shell runs: the CLI puts the terminal back, says the connection was lost, and exits 255 — never 0.
#[test]
fn a_connection_lost_in_the_middle_of_a_shell_is_said_and_the_status_is_255() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SHELL]);
    let proxy = Proxy::start(server.sshd.port);
    let session = connect(&server, proxy.port, vec![Decision::Trust]);
    eventually("a prompt", 30, || session.stdout.text().contains("$ "));
    proxy.set(Mode::Cut);
    let (code, stderr, termios, _) = session.finish();
    assert_eq!(code, 255);
    assert_eq!(stderr, "Waiting for you to confirm lab's host key in SSHelter.\n\nConnection to lab lost (early eof).\n");
    assert!(termios.is_start(&termios.now()));
}
```

`src-tauri/src/cli/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/cli/mod.rs
+++ b/src-tauri/src/cli/mod.rs
@@ -3,6 +3,8 @@
 
 #[cfg(unix)]
 pub mod client;
+#[cfg(all(test, unix))]
+mod e2e_tests;
 #[cfg(unix)]
 pub mod run;
 #[cfg(unix)]
```

- [ ] **Step 2: Run them**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- cli::e2e_tests::)
```

Expected: PASS at once: `test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 1686 filtered out`.
The leftover check prints 0, 0 and 0.

- [ ] **Step 3: Run the whole lib suite**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1687 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 4: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add src-tauri/src/cli/e2e_tests.rs \
  src-tauri/src/cli/mod.rs
git commit -m "test(cli): run sshelter connect against a scratch sshd through the broker's socket"
```

Expected: `git status --short` lists the two files of this task; the `git diff --stat` prints nothing.

- [ ] **Step 5: Prove the tests can fail (after the commit)**

Make one edit, run the tests of Step 2, then put the file back with `git checkout -- <the file>` (the tree is clean after the commit) before the next edit.

Edit 1, a shell that ended without a status (a lost connection) exits 0:

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path('src-tauri/src/cli/client.rs')
t = p.read_text()
old = '        (None, None) => 255,'
new = '        (None, None) => 0,'
assert t.count(old) == 1
p.write_text(t.replace(old, new))
PY
```

Expected: FAIL; the crate compiles and 2 tests fail (`cli::e2e_tests::a_connection_lost_in_the_middle_of_a_shell_is_said_and_the_status_is_255`, `cli::e2e_tests::a_host_key_the_person_does_not_trust_ends_sshelter_connect`): `test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 1686 filtered out`.

Edit 2, a host key the person trusted is not pinned:

```bash
python3 -I - <<'PY'
import pathlib
p = pathlib.Path('src-tauri/src/session/connect.rs')
t = p.read_text()
old = '            None => self.directory.pin(&hop.id, key),'
new = '            None => Ok(()),'
assert t.count(old) == 1
p.write_text(t.replace(old, new))
PY
```

Expected: FAIL; the crate compiles and 1 test fails (`cli::e2e_tests::sshelter_connect_confirms_the_host_key_runs_a_shell_and_exits_with_its_status`): `test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 1686 filtered out`.

After the second edit, restore and check the tree:

```bash
git checkout -- src-tauri/src/session/connect.rs
git status --short
```

Expected: no output.

---

### Task 7: The engine and the broker private to the crate; `sshelter connect` in the spec

**Files:**
- Modify: `src-tauri/src/lib.rs` (`mod session;`, `mod ssh;`)
- Modify: `src-tauri/src/ssh/mod.rs` (the re-exports), `src-tauri/src/ssh/channel.rs`, `src-tauri/src/ssh/russh_engine.rs` (test-only helpers under `cfg(test)`), `src-tauri/src/ssh/testing/doubles.rs`, `src-tauri/src/ssh/testing/harness.rs` (test support nothing uses), `src-tauri/src/session/pins.rs` (`PinStore::path`)
- Modify: `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` (§7.3, §7.4, §10)

**Interfaces:**
- Consumes: everything of plans 1a, 1b-1 and Tasks 1–6.
- Produces: no new item. `crate::ssh` and `crate::session` become private modules; `ssh/mod.rs` re-exports `pub(crate)` only what the rest of the crate names, and under `cfg(test)` what only tests name (`Ended`, `Phase`). Removed: `PinStore::path`, `VaultAuth::with_password_delay` (and its field), `TestKey::kind`, the re-exports of the channel plumbing and of `DEFAULT_KEEPALIVE_MAX_MISSED`/`ExecResult`. Test builds only: `ByteQueue::dropped_bytes`, `QueuedShell::read_until`, `Connection::hop_count`.

What shapes this task:
- R21 (plan 1a's review, item 7): `ssh` (plan 1a) and `session` (plan 1b-1) were public only because nothing in the app used them, and a private module would have warned about dead code. Now the broker uses the engine and the app and the CLI use the broker, so both become private to the crate; `cli` and `host_start` stay public because `main.rs` (another crate) calls them.
- The compiler then reports what nothing uses (Step 2 lists the warnings, measured): re-exports nothing names outside the module, accessors only tests call, and test support no test uses any more. Each is removed, or put under `cfg(test)` when tests use it. The build is back to the one old warning.
- The spec gets what plan 1b built and the spec did not say: §7.3's details of the CLI (raw mode at `opened`, the prompt mode, `libc`, the signals, the exit codes, Windows), §7.4's note that Windows keeps `ssh <alias>` and what it lost with the one-shot channel and the autofill, and §10's note that the confirmation window is 1b's while the host details and "Forget pinned key" are 1d's.

- [ ] **Step 1: Make the two modules private**

`src-tauri/src/lib.rs`: apply this patch

```diff
--- a/src-tauri/src/lib.rs
+++ b/src-tauri/src/lib.rs
@@ -15,9 +15,9 @@ mod known_hosts;
 pub mod mcp;
 mod process;
 mod secrets;
-pub mod session;
+mod session;
 mod settings_io;
-pub mod ssh;
+mod ssh;
 mod state;
 mod tray;
 mod updater_channel;
```

- [ ] **Step 2: Build, and read what the compiler now reports**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo build --offline --locked --lib)
```

Expected: the build finishes, with these warnings (the first line of each, in the order cargo prints them):

```text
warning: unused imports: `ByteQueue`, `ExitCell`, `QueueRead`, `QueuedShell`, and `ShellInput`
warning: unused imports: `DEFAULT_KEEPALIVE_MAX_MISSED`, `Ended`, `ExecResult`, and `Phase`
warning: function `set_host_enabled` is never used
warning: method `path` is never used
warning: method `dropped_bytes` is never used
warning: method `read_until` is never used
warning: method `hop_count` is never used
warning: `sshelter` (lib) generated 7 warnings (run `cargo fix --lib -p sshelter` to apply 2 suggestions)
```

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib --no-run)
```

Expected: the test build finishes, with these warnings (the first line of each):

```text
warning: unused imports: `ByteQueue`, `ExitCell`, `QueueRead`, `QueuedShell`, and `ShellInput`
warning: unused imports: `DEFAULT_KEEPALIVE_MAX_MISSED` and `ExecResult`
warning: function `set_host_enabled` is never used
warning: method `path` is never used
warning: method `with_password_delay` is never used
warning: field `kind` is never read
warning: `sshelter` (lib test) generated 6 warnings (run `cargo fix --lib -p sshelter --tests` to apply 2 suggestions)
```

- [ ] **Step 3: Remove what nothing uses, and keep for the tests what only they use**

`src-tauri/src/session/pins.rs`: apply this patch

```diff
--- a/src-tauri/src/session/pins.rs
+++ b/src-tauri/src/session/pins.rs
@@ -3,7 +3,7 @@
 //! SSHelter's own client never reads or writes `~/.ssh/known_hosts` (spec §1, non-goals).
 
 use std::collections::BTreeMap;
-use std::path::{Path, PathBuf};
+use std::path::PathBuf;
 use std::sync::{Mutex, PoisonError};
 use std::time::{SystemTime, UNIX_EPOCH};
 
@@ -70,9 +70,6 @@ impl PinStore {
         PinStore { path, lock: Mutex::new(()), clock }
     }
 
-    pub fn path(&self) -> &Path {
-        &self.path
-    }
 
     fn unreadable(&self, why: impl std::fmt::Display) -> String {
         format!("SSHelter cannot read its pinned host keys in {} ({why}).", self.path.display())
```

`src-tauri/src/ssh/channel.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/channel.rs
+++ b/src-tauri/src/ssh/channel.rs
@@ -167,6 +167,7 @@ impl ByteQueue {
     }
 
     /// How many bytes were discarded because the reader fell behind.
+    #[cfg(test)]
     pub fn dropped_bytes(&self) -> u64 {
         locked(&self.state).dropped
     }
@@ -223,7 +224,8 @@ impl QueuedShell {
         QueuedShell { input, output, exit }
     }
 
-    /// `ShellChannel::read` with a deadline instead of an open end: for tests and for callers that must also watch something else.
+    /// `ShellChannel::read` with a deadline instead of an open end (tests).
+    #[cfg(test)]
     pub fn read_until(&self, buf: &mut [u8], deadline: Instant) -> QueueRead {
         self.output.read_until(buf, Some(deadline))
     }
```

`src-tauri/src/ssh/mod.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/mod.rs
+++ b/src-tauri/src/ssh/mod.rs
@@ -9,22 +9,25 @@ mod channel;
 mod engine_tests;
 mod error;
 #[cfg(test)]
-pub mod fake;
+pub(crate) mod fake;
 #[cfg(test)]
 mod parity_tests;
-pub mod russh_engine;
+pub(crate) mod russh_engine;
 #[cfg(test)]
-pub mod testing;
+pub(crate) mod testing;
 mod traits;
 mod types;
 
-pub use channel::{ByteQueue, ExitCell, QueueRead, QueuedShell, ShellInput};
-pub use error::{AuthError, ConnectError, SessionError};
-pub use traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
-pub use types::{
-    AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostId, HostKey, HostKeyVerdict, Phase, Prompt,
-    Pty, RsaHash, Secret, Signature, Target, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY, DEFAULT_KEEPALIVE_MAX_MISSED,
+// What the rest of the app uses (plan 1b R21: the module is private to the crate; the broker is its user).
+pub(crate) use error::{AuthError, ConnectError, SessionError};
+pub(crate) use traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
+pub(crate) use types::{
+    AuthMethod, DisconnectKind, DisconnectReason, Exit, Hop, HopRef, HostId, HostKey, HostKeyVerdict, Prompt, Pty, RsaHash, Secret, Signature, Target,
+    DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY,
 };
+// What only the tests name through `crate::ssh`.
+#[cfg(test)]
+pub(crate) use types::{Ended, Phase};
 
 #[cfg(test)]
 mod tests {
```

`src-tauri/src/ssh/russh_engine.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/russh_engine.rs
+++ b/src-tauri/src/ssh/russh_engine.rs
@@ -322,6 +322,7 @@ impl Connection {
         Connection { hops: Vec::new(), closing: AtomicBool::new(false), ended: Mutex::new(None) }
     }
 
+    #[cfg(test)]
     pub fn hop_count(&self) -> usize {
         self.hops.len()
     }
```

`src-tauri/src/ssh/testing/doubles.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/testing/doubles.rs
+++ b/src-tauri/src/ssh/testing/doubles.rs
@@ -87,7 +87,6 @@ pub struct VaultAuth {
     keys: HashMap<String, (Material, String)>,
     presented: HashMap<String, String>,
     password: Option<String>,
-    password_delay: Duration,
     answers: Option<Vec<String>>,
     answer_delay: Duration,
     overrun_deadline: bool,
@@ -104,7 +103,6 @@ impl VaultAuth {
             keys: HashMap::new(),
             presented: HashMap::new(),
             password: None,
-            password_delay: Duration::ZERO,
             answers: None,
             answer_delay: Duration::ZERO,
             overrun_deadline: false,
@@ -137,11 +135,6 @@ impl VaultAuth {
         self
     }
 
-    /// `password` takes this long to answer (the user is typing).
-    pub fn with_password_delay(mut self, delay: Duration) -> VaultAuth {
-        self.password_delay = delay;
-        self
-    }
 
     /// `interactive` returns these answers. Without them it returns `None`, as a cancelled prompt does.
     pub fn with_answers(mut self, answers: &[&str]) -> VaultAuth {
@@ -232,7 +225,6 @@ impl AuthSource for VaultAuth {
 
     fn password(&self, hop: &HopRef) -> Option<Secret> {
         locked(&self.password_asks).push(hop.clone());
-        std::thread::sleep(self.password_delay);
         self.password.clone().map(Zeroizing::new)
     }
 
```

`src-tauri/src/ssh/testing/harness.rs`: apply this patch

```diff
--- a/src-tauri/src/ssh/testing/harness.rs
+++ b/src-tauri/src/ssh/testing/harness.rs
@@ -178,7 +178,6 @@ impl KeyKind {
 
 /// A key pair made by ssh-keygen, in the OpenSSH private key format the vault reads.
 pub struct TestKey {
-    pub kind: KeyKind,
     pub private_path: PathBuf,
     pub private_text: String,
     /// `<type> <base64> sshelter-test`: the authorized_keys form.
@@ -208,7 +207,6 @@ pub fn generate_key(tools: &Tools, dir: &Path, name: &str, kind: KeyKind) -> Tes
         let private_text = std::fs::read_to_string(&private_path).expect("read the private key");
         if readable_by_the_vault(&private_text) {
             return TestKey {
-                kind,
                 private_text,
                 public_line: std::fs::read_to_string(&public_path).expect("read the public key").trim().to_string(),
                 private_path,
```

- [ ] **Step 4: Build again**

```bash
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo build --offline --locked --lib)
```

Expected: only the old warning:

```text
warning: function `set_host_enabled` is never used
warning: `sshelter` (lib) generated 1 warning
Finished `dev` profile [unoptimized + debuginfo] target(s)
```

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::)
```

Expected: PASS, `test result: ok. 196 passed; 0 failed; 0 ignored; 0 measured; 1493 filtered out`; the test build's only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

- [ ] **Step 5: Record `sshelter connect` in the spec**

`docs/superpowers/specs/2026-10-10-own-ssh-client-design.md`: apply this patch

```diff
--- a/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
+++ b/docs/superpowers/specs/2026-10-10-own-ssh-client-design.md
@@ -238,10 +238,11 @@ pub enum Exit { Code(u32), Signal(String), Refused(String), Disconnected } // Re
 - Unix:raw mode 用 termios(`nix`),`SIGWINCH` 用 tokio 的 `SignalKind::window_change`。
 - Windows:release 版沒有 console,先 `AttachConsole(ATTACH_PARENT_PROCESS)`;`SetConsoleMode` 開 VT input/output;視窗大小變更用 `ReadConsoleInput` 的事件;在 Windows Terminal 與傳統 console 都要測。
 - 任何結束路徑(含 panic)都還原終端機模式。
+- (第 1b 期)實作的細節:收到 `opened` 才進 raw mode(之前終端機維持原狀,Ctrl-C 照常中止;連線中打的字等 shell 開了再送,同 OpenSSH);raw mode 照 OpenSSH 的 `enter_raw_mode` 設;`question` 用終端機的行編輯問,`echo: false` 時不顯示,問之前丟掉先打的字(不讓它變成密碼),Ctrl-C 或 Ctrl-D 取消;termios 用 app 已有的 `libc`(Cargo.lock 不多套件),信號用 tokio 的 `signal`(`SIGWINCH`、`SIGINT`、`SIGTERM`、`SIGHUP`);結束碼:shell 的結束碼,被訊號殺掉為 128 + 訊號編號(同 shell),連線中斷或開不成為 255(同 ssh),參數錯誤為 2;Windows 在第 1b 期印 `sshelter connect is not supported on Windows yet.` 並以 1 結束(release 版沒有 console,看不到這句;console 的工作在第 3 期)。
 
 ### 7.4 從 app 啟動終端機
 
-Connect 按鈕、指令面板、托盤的快速連線:沿用 `connect.rs` 的 `detect_terminals`、`build_launch_command`、`launch`,只是 argv 從 `ssh <alias>` 變成 `<SSHelter 執行檔> connect <alias>`。密碼自動填入與一次性通道刪除。
+Connect 按鈕、指令面板、托盤的快速連線:沿用 `connect.rs` 的 `detect_terminals`、`build_launch_command`、`launch`,只是 argv 從 `ssh <alias>` 變成 `<SSHelter 執行檔> connect <alias>`。密碼自動填入與一次性通道刪除。(第 1b 期)Windows 在第 3 期之前照舊開 `ssh <alias>`(一次性通道與自動填入在各平台都已刪除,Windows 上「只在 SSHelter」的金鑰改經 agent 的核准視窗)。
 
 ## 8. MCP
 
@@ -288,7 +289,7 @@ Connect 按鈕、指令面板、托盤的快速連線:沿用 `connect.rs` 的 `d
 - **新視窗**:主機金鑰指紋確認(仿現有核准視窗);MCP `ask` 模式的提問視窗(passphrase、密碼、2FA)。主機明細顯示釘住的金鑰與「Forget pinned key」。
 - **進行中的 session**:設定或側欄一小區,可關閉。
 - **設定**:AI Access(允許清單用主機 id、核准模式單選加確認視窗、最近 10 筆含請求者);Advanced(再次匯入、清理);Sync 的檔案相關文字刪除。介面字串英文。
-- (第 0 期後的介面後果,細節在 1d 的計畫)主機金鑰確認:第一次連線會先失敗(引擎回 `HostKeyUnknown`,連線不留著等人),視窗問完、釘住後 broker 自動重連,使用者看到的是「確認 → 連上」,CLI 這段印 `Waiting for you to confirm {alias}'s host key in SSHelter.`;不符時同樣先失敗、警告視窗、接受才重連。認證提示(passphrase、密碼、2FA)有期限,逾時或取消後連線已丟掉,要再連一次(§11 的 `Authentication for {alias} was abandoned`),視窗要讓人看得出「這次作廢,請重連」。進行中的 session 清單與 AI Access 的最近 10 筆顯示結束方式(`ended`:正常結束碼、被訊號終止、逾時、連線中斷),不再把中斷顯示成 0。
+- (第 0 期後的介面後果;確認視窗在第 1b 期做,主機明細與「Forget pinned key」在 1d)主機金鑰確認:第一次連線會先失敗(引擎回 `HostKeyUnknown`,連線不留著等人),視窗問完、釘住後 broker 自動重連,使用者看到的是「確認 → 連上」,CLI 這段印 `Waiting for you to confirm {alias}'s host key in SSHelter.`;不符時同樣先失敗、警告視窗、接受才重連。認證提示(passphrase、密碼、2FA)有期限,逾時或取消後連線已丟掉,要再連一次(§11 的 `Authentication for {alias} was abandoned`),視窗要讓人看得出「這次作廢,請重連」。進行中的 session 清單與 AI Access 的最近 10 筆顯示結束方式(`ended`:正常結束碼、被訊號終止、逾時、連線中斷),不再把中斷顯示成 0。
 
 ## 11. 錯誤處理
 
```

- [ ] **Step 6: Run everything once more**

```bash
(cd src-tauri && SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain)
```

Expected: `test result: ok. 1687 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out`; the only warning is the old `set_host_enabled` one; the leftover check prints 0, 0 and 0.

```bash
./node_modules/.bin/vitest run --exclude '.claude/**'
./node_modules/.bin/tsc --noEmit
(cd src-tauri && PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo build --offline --locked && ./target/debug/sshelter connect; echo "exit $?")
```

Expected: `Test Files 52 passed (52)`, `Tests 851 passed (851)`; `tsc` prints nothing; the app's binary builds with the one old warning, and `sshelter connect` without a host prints the usage and `exit 2`.

```bash
git diff --stat a764792 -- src-tauri/Cargo.toml src-tauri/Cargo.lock
grep -rnE '\.(spawn|output|status)\(\)' src-tauri/src/session src-tauri/src/cli src-tauri/src/host_start.rs; echo "grep exit: $?"
```

Expected: the first prints the two files of Task 2 (`src-tauri/Cargo.lock | 1 +`, `src-tauri/Cargo.toml | 3 ++-`); the second prints only `grep exit: 1` (`clippy.toml` forbids `Command::spawn`, `output` and `status`, there is no clippy on this machine, and this grep stands in for it, as in plan 1a).

- [ ] **Step 7: Commit**

```bash
git status --short
git diff --stat -- src-tauri/Cargo.toml src-tauri/Cargo.lock
git add docs/superpowers/specs/2026-10-10-own-ssh-client-design.md \
  src-tauri/src/lib.rs \
  src-tauri/src/session/pins.rs \
  src-tauri/src/ssh/channel.rs \
  src-tauri/src/ssh/mod.rs \
  src-tauri/src/ssh/russh_engine.rs \
  src-tauri/src/ssh/testing/doubles.rs \
  src-tauri/src/ssh/testing/harness.rs
git commit -m "refactor: keep the SSH engine and the broker private to the crate, and record sshelter connect in the spec"
```

Expected: `git status --short` lists the eight files of this task; the `git diff --stat` prints nothing.

---

## Coverage of the spec

Every test named here exists in the final tree (the names were taken from `cargo test -- --list` and from the vitest files at the last commit). Spec items that the tests do not reach are listed after the table; plan 1b-1's table covers the broker and the engine.

| Spec item | Task | Tests |
|---|---|---|
| §7.3 `sshelter connect <alias>` or `--id <host id>`; `term` from `$TERM` | 2 | `an_alias_or_an_id_names_the_host_and_anything_else_shows_the_usage`, `the_terminal_type_is_term_or_xterm_256color` |
| §7.3, §11 `SSHelter did not start within 12 seconds.`, exit 1 | 2 | `when_nothing_answers_after_the_start_the_cli_says_sshelter_did_not_start` |
| §7.3 `hello`, `open_shell`, raw mode, keys, output, resizes | 1, 2 | `it_says_hello_and_asks_for_a_shell_of_the_terminals_type_and_size`, `once_the_shell_is_open_the_terminal_is_raw_and_keys_output_and_resizes_pass_through`, `typeahead_reaches_the_shell_once_it_opens`, `the_cli_opens_a_shell_relays_keys_and_output_and_exits_with_the_shells_status` |
| §7.3 a question leaves raw mode, asks at the terminal, answers, goes back; the host key notice and banners | 1, 2 | `a_password_question_is_asked_without_echo_and_the_answer_is_sent`, `a_code_question_shows_what_is_typed_and_a_question_in_the_open_shell_goes_back_to_raw`, `ctrl_c_or_ctrl_d_at_a_question_cancels_it`, `the_host_key_notice_and_a_banner_are_printed_and_need_no_answer`, `a_question_is_asked_at_the_terminal_and_the_answer_gets_in` |
| §7.3 `exited{code}` → the terminal back, the same code; R10 128 + n, 255 | 1, 2, 6 | `the_shells_exit_status_becomes_the_programs_after_the_terminal_is_put_back`, `exit_codes_follow_the_shell_and_a_signal_is_128_plus_its_number`, `a_lost_connection_is_said_on_a_line_of_its_own_and_exits_255`, `a_failed_connect_prints_the_reason_and_exits_255`, `a_host_that_cannot_be_reached_is_said_and_the_status_is_255`, `a_connection_lost_in_the_middle_of_a_shell_is_said_and_the_status_is_255` |
| §7.3 the terminal restored on every exit path, a panic included; §12 raw mode with a fake termios | 1, 2 | `raw_mode_is_openssh_s_raw_mode_and_cooked_is_the_start`, `a_question_edits_lines_and_hides_a_password_but_shows_a_code`, `the_terminal_is_put_back_when_the_tty_is_dropped_and_on_restore`, `a_panic_puts_the_terminal_back`, `the_broker_going_away_or_a_signal_ends_the_program_with_the_terminal_put_back`, `a_closed_terminal_ends_the_session` |
| R9 input that did not reach the server is said, the session goes on | 1 | `input_that_did_not_reach_the_server_is_said_inline_and_the_shell_goes_on` |
| §10, §14 the host key window: texts word for word, names shown safely, the answer to the right question, refusal, timeout, closing, focus | 3 | `a_trusted_key_comes_back_as_its_fingerprint_and_the_window_is_told_both_times`, `a_changed_key_carries_the_pinned_one_and_answers_go_to_the_right_question`, `a_refusal_a_timeout_or_a_closed_window_is_no_trust`, `a_withdrawn_question_leaves_the_window`, `the_window_comes_to_the_front_only_for_a_new_question_at_the_head`; vitest: "asks about a key SSHelter has not seen", "warns about a key that changed", "shows hidden characters in names instead of rendering them", "carries the fingerprint the window showed", "says which answer was rejected without saying the answer", "asks about a new key with Cancel and Trust this key", "warns about a changed key with Refuse and Accept new key, and shows the new key" |
| §10 a key nobody looked at is not trusted by a stray click | 3 | vitest: "arms the trust button after the delay, and a card that goes away first never arms", "keeps trust off until armed and both buttons off while an answer is on its way", "is not armed the moment a card mounts", "ignores a fetch that arrives after an event" |
| §4, R7 sessions keep the app running; the app's data for the broker | 4 | `closing_the_window_hides_it_while_sessions_are_open`, `the_loaded_config_is_used_and_without_one_the_fallback_is_read_after_the_wait`, `a_vault_key_is_one_only_in_sshelter_named_by_its_slot` |
| §7.4 Connect, the palette and the tray run `sshelter connect`; Windows keeps `ssh` | 5 | `the_connect_command_reaches_every_terminal`, `the_launch_runs_sshelter_connect_on_macos_and_linux_and_ssh_on_windows` |
| §12 the CLI against the real engine and a scratch sshd through the socket (R14) | 6 | `sshelter_connect_confirms_the_host_key_runs_a_shell_and_exits_with_its_status`, `a_host_key_the_person_does_not_trust_ends_sshelter_connect`, `a_connection_lost_in_the_middle_of_a_shell_is_said_and_the_status_is_255` |
| R21 the engine's and the broker's surface | 7 | the build's warnings (Task 7, Steps 2 and 4) |

Not covered by a test, on purpose or for lack of a way:

- A real terminal (Terminal, iTerm2, a Linux terminal): raw mode on a real tty, SIGWINCH from a real resize, Ctrl-C at a real prompt, a tab closed under a running session. The checklist below.
- The Tauri parts that need the running app: `TauriHostKeySurface`, `start`/`ensure_listening`/`quit` in `session/app.rs` and their calls in `lib.rs`, `connect::launch` starting a terminal. The checklist below.
- `sshelter connect --id` resolves through the temporary directory, where a host's id is its alias; ids that differ from aliases come with plan 1c's host records.
- Windows: `run_connect`'s sentence, `launch_for`'s `ssh <alias>`, the broker's absence and the pipe changes compile only in CI; the Windows console is phase 3 (spec §16).

---

## Decisions to confirm

These are the choices this plan makes where the spec, the rulings or the code left room. None of them is a challenge to a ruling. Each can be reversed by changing the named task.

1. **Windows Connect after R4 and R11 together (Task 5).** R4 keeps `ssh <alias>` on Windows until phase 3; R11 deletes the password autofill and the one-shot key channel, both of which Windows used. The plan does both, so a Windows Connect now runs plain `ssh <alias>`: the person types a saved password, and a host on an "Only in SSHelter" key gets the key from SSHelter's agent behind the agent's approval window (recorded in spec §7.4). The alternative — keeping `agent/oneshot.rs` and the autofill for Windows until phase 3 — keeps more than 1,000 lines that R11 asks to delete, in a part of `agent/` that plan 1c deletes anyway. Confirm, or ask for the alternative.
2. **Raw mode starts at `opened` (Task 1).** Until the shell is open the terminal stays as it was, so Ctrl-C ends a slow connect (exit 130), and keys typed meanwhile (up to 64 KiB) reach the shell when it opens, as with OpenSSH. Recorded in spec §7.3.
3. **termios through `libc` (Task 1),** which the app already depends on for Unix: no Cargo change. R10 allowed `nix`'s `term` feature too; `nix` would be a new direct dependency.
4. **The question at the terminal (Task 1):** line editing on, typed-ahead input thrown away first (so it cannot become a password), Ctrl-C or Ctrl-D cancels, and a question asked while the shell is open returns to raw mode after it.
5. **Exit codes (Tasks 1, 2; spec §7.3):** the shell's status (at most 255); 128 + n for a signal; 255 for a lost connection, a session that could not be opened, or SSHelter going away; 130 for Ctrl-C while connecting; 128 + n for SIGTERM and SIGHUP; 2 for wrong arguments; 1 when SSHelter does not start or there is no terminal.
6. **An `input` error is printed inside the session as `[text]` on a line of its own (Task 1),** and the session goes on.
7. **The host key window (Task 3):** questions wait 120 s; the trust button is armed after 700 ms; the changed-key card shows one line more than §14's text, the new key's algorithm and fingerprint in monospace; `{pinned_at}` reads like "Oct 12, 2026, 3:04 PM" in the system's locale; the window comes to the front only for a new question at the head; closing it refuses every waiting question.
8. **The app's lifecycle (Task 4):** closing the main window hides it while sessions are open; quitting waits up to 3 s for the sessions to tell their clients; a second launch with the host flag restarts a listener that is down; an update's restart ends every session (the terminals print the reason); the broker is not started on Windows in 1b.
9. **`ipc::peer::executable_base` is deleted too (Task 5),** beyond the scout's list: only the one-shot channel used it, and the compiler reported it as dead after the switch.
10. **The Windows sentence of `sshelter connect` cannot be seen in a release build (Task 2),** which has no console on Windows; R4 asks for it, and the console work is phase 3.
11. **The command the terminal runs is the running app's own executable path (`current_exe`, Task 5),** and nothing installs `sshelter` on `PATH`. On Linux an AppImage's executable lives inside its mount, which exists while the app runs; a `sshelter connect` line taken from the shell's history after the app quit will not find it.
12. **A host SSHelter's client cannot reach is refused in the terminal, not before it opens (Task 5).** The scout suggested resolving the host in `connect_launch` first, so that a `ProxyCommand` or a key that lives in a file would be a toast instead of a terminal that prints the reason; the rulings did not ask for it, and the plan keeps the launch as it was (validate the alias, open the terminal). `sshelter connect` prints the directory's sentence (plan 1b-1 Task 7) and exits 255; whether the window stays open after that is the terminal's setting, as it was when `ssh <alias>` failed.
13. **`ssh` and `session` are private to the crate (Task 7, R21),** and the test support nothing uses any more is removed (`VaultAuth::with_password_delay`, `TestKey::kind`, `PinStore::path`).
14. **The three bindings are written by the test run (Task 3),** as every ts-rs binding of the app is.

## What is left for the user after the last commit

- Push the branch and read the first runs: `test-engine.yml` (macOS and Linux: `ssh::`, `session::`, `cli::`, `host_start::`, `vault::`; the Linux run is the first of the broker and the CLI against the Linux scratch sshd) and `test-windows.yml` (`session::` and `cli::` added: the first Windows build of `session/` and `cli/`).
- The decisions above, the first one in particular.
- A check by hand on a development build (`pnpm tauri dev` or a debug build, run by you): a debug build has no single-instance plugin and shares the app's identifier and data directory with the installed 0.17; started second, its sync engine is read-only and its agent reports another instance (existing behaviour, scout §7), while its broker's `<app data>/ipc/` is unused by 0.17. Then:
  1. Connect to a host on a vault key from the Connect button in Terminal and in iTerm2 (a new window and a new tab): the terminal runs `…/sshelter connect <alias>`; on first contact the CLI prints `Waiting for you to confirm <alias>'s host key in SSHelter.` and the host key window shows spec §14's text; Trust this key → the shell opens. The second Connect opens without a window.
  2. While it connects, type something: it reaches the shell once the prompt is there. Resize the terminal: `stty size` in the shell follows.
  3. A passphrase-protected key: the question at the terminal, nothing echoed; a wrong passphrase is asked again; Ctrl-C at the question ends with `Authentication for <alias> was abandoned (the passphrase was not given).`
  4. A host with a password and no key: the password question once, even on first contact; three wrong passwords end it. A host with a second factor (PAM keyboard-interactive): the prompts show `(<user>@<alias>)`.
  5. `exit 3` in the shell; started by hand as `…/sshelter connect <alias>; echo $?`, the status is 3. `kill -9 $$` in the shell: 137.
  6. Turn the network off during a session: after (`ServerAliveCountMax` + 1) × the keepalive interval (120 s with the defaults) the terminal says `Connection to <alias> lost (no response for 120 seconds).` and the status is 255. Close a terminal tab during a session: the session ends (no shell left on the server).
  7. Close the main window with a session open: SSHelter stays in the tray and the session lives on. Quit from the tray: the terminal prints `SSHelter quit, so the connection to <alias> was closed.` and the status is 255.
  8. With SSHelter not running, run `…/sshelter connect <alias>` (the path the Connect button used): SSHelter starts in the background without a window and the session opens.
  9. A host whose key changed (reinstall a test server's host key): the changed-key window with the pinned date; Refuse → `The host key of <alias> changed. Connection refused.`; Accept new key → it connects and the pin is replaced. Close the window with its close button while it asks: `The host key of <alias> has not been confirmed yet.`
  10. On Linux, the same from an AppImage; on Windows, Connect still opens `ssh <alias>`.
