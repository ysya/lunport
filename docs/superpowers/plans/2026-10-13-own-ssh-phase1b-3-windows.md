# Own SSH client, plan 1b-3: `sshelter connect` on Windows

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a Windows user connects through SSHelter's own SSH client the way a macOS or Linux user does: Connect opens a terminal that runs
`sshelter connect <alias>`, the session lives in the app's broker, and the console behaves like a terminal (raw keys, questions, resizes,
every way out puts the console back).

**Architecture:** the broker listens on a named pipe as the agent already does (`ipc::pipe_windows`), with a pipe stream that can be hung up
for good without losing frames already written. `sshelter connect` gets a Windows console layer behind the same `cli::terminal` surface the
Unix loop uses (`Tty`, `Restorer`, `Mode`), and Windows inputs (console keys through `ReadConsoleW`, console control events, a polled window
size) feed the same queue and client state machine. Release `sshelter.exe` is a GUI program, so a tiny console program `sshelter-cli.exe`
(std only, its own crate) runs it with the same arguments and waits; `sshelter.exe connect` attaches to that console. Connect, the palette and
the tray launch `sshelter-cli.exe connect <alias>`; the release and beta Windows builds bundle it as a Tauri `externalBin`.

**Tech Stack:** Rust (std, `windows-sys` 0.61 already locked, plus its `Win32_System_Console` feature), Tauri v2 (`bundle.externalBin`
through `tauri build --config`), GitHub Actions `windows-latest`.

**Spec:** `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` — §4's Windows paragraph, §7.2, §7.3 (the Windows bullet and the
1b note), §7.4, §12, §13, §16. The user approved this design in chat on 2026-10-13 and asked for it before any beta.

## Global Constraints

- **Where.** Repository `/Users/ysya/project/sideproj/sshelter`, branch `next/own-ssh`, which tracks `origin/next/own-ssh`. Every task ends
  with its commits pushed to `origin next/own-ssh` (plain `git push`; never force, never another branch, never `main`) and with both
  workflows green on the pushed head: `windows key slots` (test-windows.yml, runs on every push) and `ssh engine` (test-engine.yml). Read
  results with `gh run list --branch next/own-ssh` and `gh run view <id> --log-failed`; never dispatch `publish beta`, `release`, `relay`,
  `build-platform` or `beta-manifest`.
- **This Mac cannot compile Windows code**: `aws-lc-sys` needs the Windows SDK. Windows code is checked by the Windows CI run. An isolated
  Windows module that needs only std and `windows-sys` may be type-checked first in a scratch crate under the session scratchpad with
  `cargo check --offline --target x86_64-pc-windows-msvc` (the target's rust-std is installed; `windows-sys` 0.61 is in the local registry).
- **Unix stays as it is.** No behaviour change on macOS or Linux: the whole lib suite stays green here (the count may only grow), and the
  Unix tests of `cli::`, `session::`, `ssh::`, `ipc::` and `agent::` are not weakened.
- **Lock file.** No new crate in `src-tauri/Cargo.lock`. Adding a feature to the already-locked `windows-sys` (0.61) in `src-tauri/Cargo.toml`
  is allowed (features are not in the lock); `cargo metadata --offline --locked` must pass. The helper crate (Task 4) has no dependencies.
- **Commands.** As in plans 1b-1/1b-2 (global-constraints of the 1b-2 workspace): cargo from `src-tauri/` with
  `PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH`, `--offline --locked`, exactly one `--`, `SSHELTER_REQUIRE_OPENSSH=1`
  where a scratch sshd runs, the two keychain skips in a whole-suite run, the leftover check after every run that starts sshd. Frontend:
  `./node_modules/.bin/vitest run --exclude '.claude/**'` and `./node_modules/.bin/tsc --noEmit`, never pnpm/npm/npx.
- **Safety.** Never launch the app; never touch the real `~/.ssh`, Keychain or SSH agent; the system-ssh rule (`-F <temp config> -o
  IdentityFile=none -o IdentityAgent=none -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null`, only closed local ports or a
  scratch sshd); never download anything; never start busy loops; kill exactly what you start; no subagents.
- **Code style.** Comments in English; spec notes in Traditional Chinese; conventional commits staged by path, no attribution lines. Unsafe
  Win32 calls carry a `// SAFETY:` line, as in `ipc/pipe_windows.rs`.

## Review Focus

1. A session that ends must reach the CLI whole: the broker's last frames (`event`, `exited`) are read before the end of the pipe, on every
   end path (shell exit, app quit, a hang-up), and a hung-up connection never blocks a broker thread for good.
2. Every way out of `sshelter connect` on Windows puts the console back (input and output modes, both code pages): normal end, Ctrl-C at a
   question, the window closed (CTRL_CLOSE_EVENT gives the process only seconds), log-off, a panic, the watchdog.
3. Nothing typed at a question reaches the remote or a later prompt by accident, and a password is never echoed (line input without
   `ENABLE_ECHO_INPUT`, the input buffer flushed before asking and when the session ends during a question, as on Unix).
4. Text is not corrupted: UTF-16 from `ReadConsoleW` (surrogate pairs across reads) becomes UTF-8 for the remote; UTF-8 from the remote is
   never cut inside a character between two console writes.
5. Windows launch paths: Windows Terminal (`wt.exe` with and without the new-tab arguments) and `cmd` both run the helper; a debug build
   without the helper runs `sshelter.exe` itself; paths with spaces survive.

---

### Task 1: The broker on a named pipe

**Files:**
- Modify: `src-tauri/src/ipc/pipe_windows.rs` (the pipe stream, its hang-up and deadline, naming per role, the listener's thread name, the
  client connect), `src-tauri/src/ipc/server.rs` (`Stream` on Windows), `src-tauri/src/agent/mod.rs` (the agent's pipe name call, if its
  signature changes), `src-tauri/src/session/mod.rs` (the broker's pipe name), `src-tauri/src/session/app.rs` (listen on Windows),
  `src-tauri/src/session/broker.rs` (`set_read_timeout` and `hang_up` on Windows), `src-tauri/Cargo.toml` (windows-sys features if needed).
- Test: Windows-only tests in the same files (`#[cfg(all(test, windows))]`).

**Interfaces:**
- Consumes: `ipc::server::{Handler, Started, dispatch, take_lock}`; `session::broker::Broker::{new, handler}`; `session::ipc_dir`.
- Produces: on Windows `ipc::server::Stream` = `ipc::pipe_windows::PipeStream` with `Read`, `Write`, `try_clone(&self) -> io::Result<Self>`,
  `hang_up(&self)` and a read deadline (`set_read_timeout(&self, Option<Duration>) -> io::Result<()>` or an equivalent the broker calls);
  `ipc::pipe_windows::pipe_name_for(role: &str) -> io::Result<String>` (`sshelter-<role>-<16 hex>`; the agent keeps `sshelter-agent-…`);
  `ipc::pipe_windows::connect(name: &str, busy_wait: Duration) -> io::Result<PipeStream>` (NotFound when no instance exists; waits with
  `WaitNamedPipeW` while every instance is busy); `session::pipe_name() -> io::Result<String>` (Windows: `pipe_name_for("session")`).

Requirements:
1. `PipeStream` wraps the pipe handle and a state shared by all its clones. `hang_up` marks the state hung up for good, then cancels the I/O
   pending on the pipe from any thread (`CancelIoEx(handle, null)`; the cancelled call returns `ERROR_OPERATION_ABORTED`). After a hang-up
   every read returns `Ok(0)` and every write fails with `BrokenPipe`, whether or not a call was pending. A hang-up never calls
   `DisconnectNamedPipe`: frames written before it stay readable by the client, which sees the end of the pipe when the last server handle
   closes (std reads `ERROR_BROKEN_PIPE` as the end).
2. The read deadline: `Some(d)` hangs the stream up if it has not been cleared within `d` (the broker's 10 s `hello`/`open_shell` bound,
   spec §7.2); `None` clears it. No busy waiting (a condvar or a sleep until the deadline).
3. The listener: `pipe_windows::listen` takes the thread's name (the agent keeps `sshelter-agent`; the broker's is `sshelter-session`) and
   hands every connection to the handler as a `PipeStream`. The agent's behaviour and tests do not change.
4. `session/app.rs`: the broker is built the same way on every platform (one code path for the engine, the directory, the key store, the
   keychain and the window confirmer); on Windows it listens through `pipe_windows::listen(&ipc_dir, &session::pipe_name()?, …)`.
   `BrokerStatus::NotOnThisPlatform` goes away with its uses.
5. `session/broker.rs`: the Windows `set_read_timeout` and `hang_up` use the `PipeStream` methods; nothing else in the broker changes.

- [ ] **Step 1:** Write the Windows tests first (they fail to compile or fail until the code exists): (a)
  `a_session_served_on_a_pipe_ends_with_exited_then_the_end_of_the_pipe` — the real broker on a test pipe name (unique per test, in a temp
  dir for the lock) with `FakeEngine`, a client through `pipe_windows::connect`: `hello`, `open_shell` → `opened` → data both ways → the
  fake shell exits → the client reads `exited{code}` and then `Ok(0)`; (b) `a_hang_up_wakes_a_blocked_reader_and_keeps_what_was_written` —
  a server thread blocked in `read` returns `Ok(0)` after `hang_up`, a later read returns `Ok(0)` at once, a write fails, and the client still
  reads the frame written just before the hang-up; (c) `a_client_that_says_nothing_is_hung_up_after_the_deadline` — a 300 ms deadline
  instead of 10 s; (d) `quitting_tells_a_connected_client_and_ends_its_pipe` — `end_all` with an open session: the client reads the quit
  reason and `exited`, then the end; (e) `connect_says_not_found_without_a_listener`.
- [ ] **Step 2:** Implement Requirements 1–5. Push; read the Windows run; fix until green. The agent's pipe tests stay green.
- [ ] **Step 3:** Run the macOS whole suite once (unchanged behaviour), push, and record the green run ids in the report.

### Task 2: The Windows console

**Files:**
- Create: `src-tauri/src/cli/terminal_windows.rs` (the console layer), compiled as `cli::terminal` on Windows
  (`#[cfg(windows)] #[path = "terminal_windows.rs"] pub mod terminal;` next to the Unix `terminal.rs`).
- Create or modify: a platform-neutral part for the mode arithmetic and the fake console (so its tests also run on macOS), e.g.
  `src-tauri/src/cli/console_modes.rs`.
- Modify: `src-tauri/Cargo.toml` (`Win32_System_Console` on `windows-sys`), `src-tauri/src/cli/mod.rs` (module wiring).

**Interfaces:**
- Produces, mirroring `cli/terminal.rs` so `run.rs` can use either: `Mode` (Cooked, Raw, Prompt { echo }), a `ConsoleApi: Send + Sync`
  trait (get/set the input mode and the output mode, get/set the input and output code pages, the window size, flush the input buffer),
  `Tty::new(api: Arc<dyn ConsoleApi>) -> io::Result<Tty>` (fails when the input handle is not a console), `Tty::{mode, set_mode(mode,
  discard_input), size, restore, restorer}`, `Restorer::{restore, hold_restored}`, `restore_on_panic(Restorer)`, and the real `StdConsole`
  (the console input and output handles; `CONIN$`/`CONOUT$` when the standard handles are not the console's).

Requirements:
1. At start the layer saves the original input mode, output mode, input code page and output code page. It sets the output mode once:
   original | `ENABLE_VIRTUAL_TERMINAL_PROCESSING` | `DISABLE_NEWLINE_AUTO_RETURN` (and `ENABLE_PROCESSED_OUTPUT`), and the output code page
   to UTF-8 (65001).
2. Input modes are computed from the ORIGINAL input mode, never chained: Raw = original without `ENABLE_LINE_INPUT`, `ENABLE_ECHO_INPUT`,
   `ENABLE_PROCESSED_INPUT`, with `ENABLE_VIRTUAL_TERMINAL_INPUT` (every other flag — quick edit, insert mode, `ENABLE_EXTENDED_FLAGS` —
   as the original had it); Prompt { echo } = original with `ENABLE_LINE_INPUT` and
   `ENABLE_PROCESSED_INPUT`, `ENABLE_ECHO_INPUT` exactly when `echo`, without `ENABLE_VIRTUAL_TERMINAL_INPUT`; Cooked = the original.
   `discard_input` flushes the input buffer (`FlushConsoleInputBuffer`) before the mode applies.
3. Every way out restores all four saved values: `Drop`, `restore`, the panic hook (lock-free, as on Unix), and `hold_restored` for the
   watchdog. A restore that fails on one value still tries the others.
4. `size()` = (`srWindow.Right - srWindow.Left + 1`, `srWindow.Bottom - srWindow.Top + 1`) from `GetConsoleScreenBufferInfo` on the output
   handle; `None` when it fails.

- [ ] **Step 1:** Write the portable tests first (they run on macOS too): the four mode computations from several originals (whole-value
  comparisons, never chained: Raw → Prompt → Raw gives Raw's value), `discard_input` flushes before the mode, every restore path restores all
  four values in a fake console that records calls, and a restore whose first call fails still makes the others.
- [ ] **Step 2:** Implement the portable part and the real Windows `StdConsole`; type-check the Windows module in a scratch crate if it helps,
  then push and make the Windows run green (its tests: the same fake-based tests, plus `a_real_console_handle_is_refused_when_input_is_a_pipe`
  — `Tty::new` with the standard handles of the CI job, which are pipes, fails with a clear error).

### Task 3: `sshelter connect` on Windows

**Files:**
- Modify: `src-tauri/src/cli/client.rs` (signal numbers without `libc`), `src-tauri/src/cli/run.rs` (the loop's platform parts),
  `src-tauri/src/cli/mod.rs` (`run_connect` and `session` on Windows; the Windows "not supported" sentence goes), `src-tauri/src/cli/e2e_tests.rs`
  only if a shared helper moves.
- Create (if it keeps `run.rs` readable): `src-tauri/src/cli/inputs_windows.rs` (keys, control events, size polling).

**Interfaces:**
- Consumes: Task 1's `ipc::pipe_windows::connect`, `session::pipe_name`, `PipeStream`; Task 2's `cli::terminal` on Windows;
  `host_start::{ensure_started, start_host, take_spawn_locks, START_WAIT}`.
- Produces: `cli::run_connect(&[OsString]) -> i32` on Windows with the same order and exit codes as on Unix.

Requirements:
1. `client.rs` compiles everywhere: the signal numbers it uses (`HUP` 1, `INT` 2, `QUIT` 3, `TERM` 15, and the table that maps a remote
   signal's name to a number for 128 + n) come from a `cli` constant table; on Unix the values equal `libc`'s (a Unix test pins each against
   `libc`), on Windows they are the POSIX/Linux numbers. No exit code changes on Unix.
2. `run.rs` builds on Windows: the broker connection is `ipc::server::Stream` (Unix socket or `PipeStream`); the Unix-only parts (`poll`,
   `EAGAIN`, file descriptors, TSTP/CONT, tokio's Unix signals) stay `cfg(unix)`; the shared parts (queue, budgets, writers, watchdog, the
   client's actions) are not duplicated.
3. Keys on Windows: one thread reads the console input with `ReadConsoleW` and queues UTF-8 (`Inputs::typed`, the keys budget as on Unix). A
   UTF-16 surrogate pair split across two reads is joined; an unpaired surrogate becomes U+FFFD. A read of 0 characters (Ctrl-C at a line
   read) is not the end; a failure that means the console is gone is the end (as SIGHUP: 129).
4. Control events through `SetConsoleCtrlHandler`: Ctrl-C (a signal only when the input is not raw) and Ctrl-Break → `Interrupt`;
   CTRL_CLOSE_EVENT → `Stop(HUP)` and the watchdog armed; CTRL_LOGOFF_EVENT and CTRL_SHUTDOWN_EVENT → `Stop(TERM)` and the watchdog armed.
   For close, log-off and shut-down the handler waits (up to the watchdog's grace) for the program to have put the console back before it
   returns, because Windows ends the process when the handler returns.
5. Window size: a thread checks `Tty::size` every 250 ms and queues a resize only when it changed (the same input SIGWINCH queues).
6. Terminal output on Windows never splits a UTF-8 character across two console writes (a character cut at the end of a piece waits for the
   next piece; at the end it is written as it is).
7. `run_connect` on Windows: the arguments (usage, 2); `AttachConsole(ATTACH_PARENT_PROCESS)` when the process has no console (an
   `ERROR_ACCESS_DENIED` means it already has one); the console check (`sshelter connect needs a terminal.`, 1); reach the broker through
   `pipe_windows::connect` and, when no pipe exists, `ensure_started` with `start_host` as on Unix (`SSHelter did not start within 12
   seconds.`, 1); install the control handler (failure → 1, before the console changes); then `run`.

- [ ] **Step 1:** Write the tests first. Portable: the signal table pinned against `libc` on Unix; the UTF-16 → UTF-8 decoder (ASCII, a BMP
  character, a surrogate pair in one read, the same pair split over two reads, a lone surrogate); the UTF-8 piece splitter (a character at
  the end of a piece is held back, the rest written, nothing lost at the end); the control-event mapping (event → input, which ones arm the
  watchdog). Windows-only: `run()` over a real pipe against the real broker with `FakeEngine` and a fake console (as `e2e_tests.rs` does with a
  socket): connect, a shell, typed keys, an exit code; a question answered; the console back at its start after the run, read before the
  `Tty` drops.
- [ ] **Step 2:** Implement Requirements 1–7. Push; make the Windows run green; keep the macOS suite green.

### Task 4: `sshelter-cli.exe`, the Windows launch, and the release builds

**Files:**
- Create: `src-tauri/cli-helper/Cargo.toml` (package `sshelter-cli`, `[workspace]` of its own, no dependencies), its `Cargo.lock`,
  `src-tauri/cli-helper/src/main.rs`.
- Modify: `src-tauri/src/connect.rs` (`launch_for` on Windows, `connect_argv`'s cfg), `.github/workflows/test-windows.yml` (build and test the
  helper), `.github/workflows/beta.yml`, `.github/workflows/release.yml`, `.github/workflows/build-platform.yml` (the Windows legs build the
  helper and bundle it), `.gitignore` (`src-tauri/binaries/`).
- Create: `.github/workflows/windows-bundle-check.yml` (workflow_dispatch only): builds the NSIS installer with the helper and without updater
  artifacts, and checks the installer holds `sshelter-cli.exe`.

**Interfaces:**
- Produces: `sshelter-cli.exe` next to `sshelter.exe` in the Windows installer; `connect::launch_for` on Windows returning
  `[<dir>\sshelter-cli.exe, "connect", alias]`, or `[sshelter.exe, "connect", alias]` when no helper is next to it.

Requirements:
1. The helper is a console program (no `windows_subsystem` attribute) that finds `sshelter.exe` in its own directory, runs it with exactly
   its own arguments (as `OsString`s) and inherited standard handles, waits, and exits with its exit code. It ignores Ctrl-C and Ctrl-Break
   with a handler that returns TRUE (not `SetConsoleCtrlHandler(NULL, TRUE)`, whose flag a child inherits). Without `sshelter.exe` next to it
   it prints `sshelter-cli: cannot find sshelter.exe in <dir>.` and exits with 1. It builds on every platform (on Unix it is a stub that says
   it is for Windows and exits 1), so `cargo test` of the helper runs on macOS too.
2. `launch_for` on Windows: Windows Terminal runs the argv directly (`wt.exe [-w 0 nt] <argv>`), cmd runs `cmd /c start "" cmd /k <argv>`
   (unchanged shapes); the helper when it exists next to the running executable, the running executable otherwise (debug builds are console
   programs).
3. The beta, release and build-platform workflows, Windows legs only: build the helper in release (`cargo build --release --locked
   --manifest-path src-tauri/cli-helper/Cargo.toml`), copy it to `src-tauri/binaries/sshelter-cli-x86_64-pc-windows-msvc.exe`, and pass
   `--config '{"bundle":{"externalBin":["binaries/sshelter-cli"]}}'` to `tauri build` (with the leg's other args). macOS and Linux legs do not
   change. `actionlint` passes on every workflow.
4. `windows-bundle-check.yml`: on `workflow_dispatch`, on `windows-latest`, the same steps as the beta's Windows leg up to `tauri build` with
   `--bundles nsis` and `createUpdaterArtifacts: false` (no signing key), then a check that the produced installer contains
   `sshelter-cli.exe` (list it with 7-Zip, which the runner image has) — the controller dispatches it once before the beta.

- [ ] **Step 1:** Tests first: the helper's unit tests (arguments passed through untouched, including spaces and quotes; the exit code
  relayed; the missing-target sentence) — the spawn is behind a function that takes the target path, so a test can point it at a small test
  program; `connect.rs` tests for both Windows launch shapes with the helper path and with the fallback.
- [ ] **Step 2:** Implement; push; the Windows run builds the helper, runs its tests, and runs `sshelter-cli.exe connect` next to the debug
  `sshelter.exe` (prints the usage, exits 2).

### Task 5: Truth in the docs, the Windows allowances, and the manual checklist

**Files:**
- Modify: `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` (only where the code differs from the 2026-10-13 text),
  `src-tauri/src/session/mod.rs` and `src-tauri/src/ssh/mod.rs` (drop `#![cfg_attr(windows, allow(dead_code, unused_imports))]` once the
  Windows build has no warning without it — read the Windows run's build log), `.github/workflows/test-windows.yml` (its header comment).
- Create: `docs/superpowers/plans/2026-10-13-own-ssh-windows-manual-checks.md` — what only a real Windows machine shows: Windows Terminal and
  the classic console, Connect from the row, the palette and the tray, a first host key, a password question (no echo), Ctrl-C at a question
  and in the shell, resizing, an IME, pasting a long text, closing the window during a session, quitting SSHelter during a session, the
  background start when SSHelter is not running, and the console left as it was each time.

- [ ] **Step 1:** Make every changed sentence true of the code; drop the allowances if the Windows build stays warning-free; write the
  checklist. Push; both workflows green.

---

## After the last task

The final whole-branch review of this plan (`next/own-ssh` from the commit before Task 1 to the end), one fix wave and its scoped re-review.
Then the controller dispatches `windows-bundle-check.yml` once, and, with it green, merges `next/own-ssh` into `main`, pushes `main`, and
dispatches `publish beta` with the next version (the user's word of 2026-10-13: push, merge, beta once Windows works).
