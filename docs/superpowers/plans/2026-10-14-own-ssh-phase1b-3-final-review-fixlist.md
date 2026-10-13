> **Status (2026-10-14), added by the controller.** F1 and F3–F8 below were fixed on `next/own-ssh` in aa23b36..80b1182, with F9–F12 the
> controller added (the pending read on the inherited standard input at exit — measured to end with the process; the release GUI pair's
> console path proven in CI from both installers; the last minors of Task 3; deterministic test waits). F2's prescribed fix was wrong on
> macOS (a bound, never-listening socket makes a connect time out, not fail): four tests use port 1 instead (8b0507b). Hand-off H2 was
> pulled in (fa2a128, ad93116: the helper puts the console back after its child ends). The scoped re-reviews found nothing open. The
> "Hand-off" items other than H2 and H5, and the "Manual checks for the user", are still open.

# Final whole-branch review of plan 1b-3 (`sshelter connect` on Windows) — fix list

Reviewed: `next/own-ssh` f7aab4a..aa23b36 (39 commits; package `final-review-f7aab4a..aa23b36.diff`), against the spec
(`docs/superpowers/specs/2026-10-10-own-ssh-client-design.md` §4, §7.2–7.4, §11, §12, §16 at HEAD), the plan, the two addenda, the
ledger, the five task reports, the CI runs (latest green heads: windows key slots 38423069911 = 728 passed, only the three baseline
warnings `tray.rs:64`, `config/edit.rs set_host_enabled`, `process.rs without_spawns`; ssh engine 38423069957 on attempt 2) and the
locked tauri CLI binary (its NSIS template is readable; its WiX template is not).

**Verdict: Ready with fixes.** Critical 0 · Important 4 (F1–F4) · Minor 4 (F5–F8). No security hole, secret leak or data loss found.
The Windows runtime (broker on the pipe → console layer → read gate → loop → launch chain → helper) holds together as one system; what
remains is the MSI gap of the bundle check, two flaky macOS engine tests that gate the merge, and documentation truth.

Scoped re-review in flight (d201408..aa23b36) judged as part of the whole: the discarding switch to cooked mode ends the question's read
while the console still hides input (console.rs `Reads::pause`, fake test + real-console case `an_end_under_a_question_leaves_nothing_behind`);
the shared-console measurement is sound (a grandchild without `CREATE_NEW_CONSOLE` leaves a raw read and a hidden line read holding
`hun`; the child's next reads get the next key and the next line, `hun` never shows); `QUESTION_READ_ENDS_ITS_LINE` leaves the Unix
client's actions byte-for-byte as before (`false` folds back into the old conditions) and the Windows pipe test expects no `\n` after the
hidden answer; the two test gaps are closed. Nothing new found there.

---

## Fix items (most severe first)

### F1 — Important — `windows-bundle-check.yml` must build and verify the MSI too (before the beta)

- Where: `.github/workflows/windows-bundle-check.yml:63-66` (build step: `--bundles nsis`), `:69-96` (NSIS listing), `:98-117` (the
  pair); spec `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md:332` (§12's sentence "照 beta 的 Windows 那條建出 NSIS 安裝檔").
- Failure scenario: the real Windows legs (`beta.yml`, `release.yml`, `build-platform.yml`) run `tauri build` with `bundle.targets: "all"`
  (`src-tauri/tauri.conf.json`), which on Windows is NSIS **and** MSI, and both installers are published. The check builds NSIS only. The
  WiX template of the locked CLI (`@tauri-apps/cli` 2.11.2) is not readable on this Mac (the NSIS template is in the binary's strings,
  the WiX one is not), so whether `bundle.externalBin` lands in the MSI's INSTALLDIR next to `sshelter.exe` is unproven. If it does not, a
  user who installs the `.msi` gets `sshelter-cli.exe is missing from C:\Program Files\SSHelter. Reinstall SSHelter.`
  (`src-tauri/src/connect.rs:376` `connect_program`) on every Connect: a beta that cannot connect for MSI users.
- Change:
  1. Build step: drop `--bundles nsis` (keep both `--config`s), rename it "Build the installers" and say in its comment that it builds
     every target of `tauri.conf.json` as the leg does (NSIS and MSI; tauri downloads WiX 3.14 on first use, as the leg does):
     ```yaml
           - name: Build the installers
             uses: tauri-apps/tauri-action@v0
             with:
               args: --config '{"bundle":{"externalBin":["binaries/sshelter-cli"]}}' --config '{"bundle":{"createUpdaterArtifacts":false}}'
     ```
  2. After the NSIS listing step add an MSI step. An administrative install (`msiexec /a`) lays the MSI's files out under `TARGETDIR` as
     its Directory table has them and registers nothing; the helper must be in the same directory as `sshelter.exe`:
     ```yaml
           # An administrative install (msiexec /a) lays the MSI's files out under TARGETDIR as its Directory table has them, registering
           # nothing: the helper has to land in the directory of sshelter.exe (where WiX puts external binaries is checked, not assumed).
           - name: The MSI holds sshelter-cli.exe next to sshelter.exe
             shell: pwsh
             run: |
               $msis = @(Get-ChildItem -Path src-tauri/target/release/bundle/msi -Filter '*.msi')
               if ($msis.Count -ne 1) { throw "expected one MSI, found $($msis.Count): $($msis.Name -join ', ')" }
               $msi = $msis[0].FullName
               $image = Join-Path $env:RUNNER_TEMP 'msi image'
               $log = Join-Path $env:RUNNER_TEMP 'msi.log'
               $run = Start-Process -FilePath msiexec.exe -ArgumentList @('/a', "`"$msi`"", '/qn', "TARGETDIR=`"$image`"", '/l*v', "`"$log`"") -Wait -PassThru
               if ($run.ExitCode -ne 0) { Get-Content $log | Select-Object -Last 60; throw "msiexec /a failed with $($run.ExitCode)" }
               $files = @(Get-ChildItem -Path $image -Recurse -File)
               Write-Output "$msi lays out:"
               $files | ForEach-Object { Write-Output "  $($_.FullName.Substring($image.Length + 1))" }
               $app = @($files | Where-Object Name -eq 'sshelter.exe' | ForEach-Object DirectoryName)
               $helper = @($files | Where-Object Name -eq 'sshelter-cli.exe' | ForEach-Object DirectoryName)
               if ($app.Count -eq 0) { throw 'the MSI has no sshelter.exe' }
               if ($helper.Count -eq 0) { throw 'the MSI has no sshelter-cli.exe' }
               if (@($helper | Where-Object { $app -contains $_ }).Count -eq 0) {
                 throw "sshelter-cli.exe ($($helper -join ', ')) is not in the directory of sshelter.exe ($($app -join ', '))"
               }
               Add-Content -Path $env:GITHUB_ENV -Encoding utf8 -Value "SSHELTER_MSI_DIR=$($app[0])"
               Write-Output 'sshelter-cli.exe is next to sshelter.exe in the MSI.'
               exit 0
     ```
  3. The pair step: run `sshelter-cli.exe connect` (usage, exit 2) from **both** images — the directory it extracts from the NSIS
     installer, and `$env:SSHELTER_MSI_DIR` (a `foreach` over the two; the dumpbin check once is enough, it is the same file).
  4. Header comment: "the Windows NSIS installer" → "the Windows installers (NSIS and MSI)"; spec §12 line 332: "建出 NSIS 安裝檔,檢查…"
     → "建出 NSIS 與 MSI 安裝檔(`bundle.targets: all`,同 beta),各自檢查 helper 與 `sshelter.exe` 在同一個資料夾(MSI 用 `msiexec /a` 展開)…".
  5. Keep the `push` trigger (lines 13-15): the wave's push of this file is what runs the check on `next/own-ssh` (its removal is a
     post-merge cleanup, Hand-off H3).
- Proof: the wave's push runs `windows bundle check` (its push trigger); its log lists both installers' files with `sshelter-cli.exe`
  beside `sshelter.exe` in each, and `sshelter-cli.exe connect` → usage + 2 from both images. After the merge the controller dispatches
  it once more from `main` before `publish beta` (as the plan says).

### F2 — Important — `a_port_with_nothing_behind_it_is_unreachable_and_says_connection_refused` races for a freed port (macOS flake)

- Where: `src-tauri/src/ssh/engine_tests/connect.rs:378-380` (`a_port_nobody_listens_on`), `:383-392` (the test).
- Failure scenario (ssh engine 38423069957, attempt 1, macOS): the helper binds `127.0.0.1:0`, drops the listener and returns the port;
  the suite runs tests in parallel and every scratch sshd and proxy picks its port the same way (`ssh/testing/harness.rs:557 free_port`,
  `ssh/testing/proxy.rs` `TcpListener::bind(("127.0.0.1", 0))`), so the freed port is handed to another test in the window, the engine's
  connect reaches that listener, and the error is `connection reset by peer` (port 49309 in the run) instead of `connection refused`: the
  macOS job fails and needs a rerun. A real race, not load.
- Change: hold the port for the test's whole life with a socket that is **bound but never listens**: nobody else can be given the port
  while it is bound, and a SYN to a bound socket that does not listen is answered with a reset (ECONNREFUSED on macOS and Linux). Unix
  through `libc` (already a dependency of the crate; the exact-text assertion at line 391 is Unix-only anyway); Windows keeps today's pick
  (std cannot bind without listening; the Windows job has not flaked, and `Win32_Networking_WinSock` is not an enabled windows-sys feature).
  ```rust
  /// A TCP port on 127.0.0.1 that nothing listens on, held for the life of the value: every other test of the run picks its ports by
  /// binding port 0 too (the scratch sshds, the proxies), and could be given a port this test had freed. The socket is bound and never
  /// listens, so the port stays taken, and a connection to it is refused (the kernel resets the SYN). Unix; on Windows a freed port, as
  /// before.
  struct ClosedPort {
      #[cfg(unix)]
      fd: libc::c_int,
      port: u16,
  }

  impl ClosedPort {
      #[cfg(unix)]
      fn reserve() -> ClosedPort {
          // SAFETY: plain socket calls on wholly initialised structures; the descriptor is closed once, in `Drop`.
          unsafe {
              let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
              assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
              let mut address: libc::sockaddr_in = std::mem::zeroed();
              address.sin_family = libc::AF_INET as libc::sa_family_t;
              address.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
              let length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
              let bound = libc::bind(fd, &address as *const libc::sockaddr_in as *const libc::sockaddr, length);
              assert_eq!(bound, 0, "bind: {}", std::io::Error::last_os_error());
              let mut name: libc::sockaddr_in = std::mem::zeroed();
              let mut name_length = length;
              let named = libc::getsockname(fd, &mut name as *mut libc::sockaddr_in as *mut libc::sockaddr, &mut name_length);
              assert_eq!(named, 0, "getsockname: {}", std::io::Error::last_os_error());
              ClosedPort { fd, port: u16::from_be(name.sin_port) }
          }
      }

      #[cfg(windows)]
      fn reserve() -> ClosedPort {
          ClosedPort { port: std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port() }
      }
  }

  #[cfg(unix)]
  impl Drop for ClosedPort {
      fn drop(&mut self) {
          // SAFETY: the descriptor `reserve` opened, closed once.
          unsafe { libc::close(self.fd) };
      }
  }
  ```
  In the test: `let closed = ClosedPort::reserve(); let hop = Hop::new("h1", "gone", "127.0.0.1", closed.port, "tester", AuthMethod::Password);`
  … and `drop(closed);` as the last line (it must outlive `connect_chain`). Delete `a_port_nobody_listens_on`.
- Proof: `SSHELTER_REQUIRE_OPENSSH=1 PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH cargo test --offline --locked --lib -- ssh::engine_tests::connect::a_port_with_nothing_behind_it_is_unreachable_and_says_connection_refused --exact`
  green on macOS (and the text `Could not reach 127.0.0.1:<port> (connection refused).` as before); a scratch check that
  `TcpStream::connect` to a held port fails with `ConnectionRefused` is a good red/green; ssh engine green on both legs of the wave's push.

### F3 — Important — `requests_to_a_peer_that_stopped_reading_come_back_in_time_and_the_cut_releases_the_rest` asserts on a race (macOS flake)

- Where: `src-tauri/src/ssh/engine_tests/shell.rs:439` (`assert!(timed_out > 0, "the link did not wedge …")`), `:346-349` (doc comment),
  `:399-410` (the stall detector), `:436` (the FACT line).
- Failure scenario (ssh engine 38416173709, macOS): 102 chunks taken before the stall; all 30 window changes came back `Ok`, slowest
  4542 ms; exec `TimedOut` at 5.30 s. The link **did** wedge: a window change that finds room returns in microseconds, and these waited
  4.5 s. The queue got room about 5 s after the stall — just before the resizers' own `SEND_LIMIT` (5 s, `russh_engine.rs:908`) ran out,
  because the stall detector starts them only after 500 ms of quiet. Which release gave the room is not in the facts (the command's
  `close` at its 4 s deadline is the candidate; shell writes are bounded by 30 s and do not free slots); either way the guard is a race
  between two 5 s bounds, and the good case ("20 of 30 time out", the doc comment) and this one are both wedged links.
- Change: make the precondition a direct observation of the wedge, independent of that race:
  ```rust
      // A window change that finds room in the queue returns in microseconds; one that waited a second or more found the queue full,
      // so the link wedged. Whether such a request then ends as Timeout or gets in when a slot frees (the command's close at its deadline,
      // another bounded send giving up) is a race between two bounds of SEND_LIMIT, measured both ways on the CI runner: not asserted.
      assert!(slowest >= 1_000, "no window change waited for room: the link did not wedge, so this test has shown nothing: {resizes_back:?}");
  ```
  (replacing line 439; `timed_out` stays in the FACT line); doc comment lines 348-349: "20 of the 30 window changes find no room" →
  "the window changes wait for room, and some of them time out". The exec and bound assertions stay as they are.
- Proof: red by temporarily `proxy.set(Mode::Forward)` instead of `Blackhole` (every resize returns at once → `slowest` ≈ 0 → the new
  message); green with `-- ssh::engine_tests::shell::requests_to_a_peer_that_stopped_reading_come_back_in_time_and_the_cut_releases_the_rest --exact`
  (a scratch sshd: `SSHELTER_REQUIRE_OPENSSH=1`, leftover check 0/0/0 after it); ssh engine green on the wave's push.

### F4 — Important (docs) — the manual checklist lacks install, update and uninstall items (Task 5's I1) and two wording fixes (M7, item 11)

- Where: `docs/superpowers/plans/2026-10-13-own-ssh-windows-manual-checks.md` — insert a section before `## Clean up` (line 146) and
  renumber the clean-up item; line 70-72 (item 11); line 119 (item 24).
- Failure scenario: the beta reaches Windows users through the in-app updater (NSIS, silent) and through two installers; nobody has
  checked that an update over 0.17.0-9 leaves the helper installed and new, that an update with a session open does not fail on a locked
  `sshelter-cli.exe` (the helper is running during every session; the installer kills `sshelter.exe` processes, the helper exits a moment
  later), that the MSI installs a working pair, and that uninstalling removes both programs.
- Change — add `## Install, update and uninstall` with:
  1. **The MSI.** Install the beta's `.msi` (per machine, `C:\Program Files\SSHelter`, elevation): `sshelter.exe` and `sshelter-cli.exe`
     are there; Connect `web` opens the session with Windows Terminal and with Command Prompt; `& "C:\Program Files\SSHelter\sshelter-cli.exe" connect`
     prints the usage and `$LASTEXITCODE` is 2. Uninstall from Settings → Apps: both programs are gone and the folder is removed.
     (Do not have the MSI and the NSIS install at once: the broker's lock makes the second app say `OtherInstance`.)
  2. **The in-app update from 0.17.0-9.** Install 0.17.0-9 with its NSIS installer, choose the Beta channel in Settings → General, check
     for updates: the beta installs and the app restarts; `Get-ChildItem "$env:LOCALAPPDATA\SSHelter" -Filter *.exe` shows both programs
     with the beta's dates and sizes; no dialog about a file in use appeared. Then the same with a `web` session open: the terminal prints
     `The connection to SSHelter ended.` (or `SSHelter quit, so the connection to web was closed.`), the program ends with 255 and check C
     passes, the update completes, and both programs are the beta's.
  3. **The installer over an installed beta with a session open** (run the `-setup.exe` again): the same expectations as 2.
  4. **Uninstall (NSIS, Settings → Apps):** both programs are gone.
  And: item 11, "(it only logs)" → "(it writes the failure only to its standard error, which a release build shows nowhere)"; item 24,
  "`who` no longer lists it" → "the login that `who` listed while the session was open is gone".
- Proof: the controller reads the file; `git diff --stat` touches only the checklist.

### F5 — Minor — `Console::take_over` clears `changed` after a failed best-effort put-back (Task 2 re-review, parked minor 1)

- Where: `src-tauri/src/cli/console.rs:362-367` (the UTF-8 failure branch of `take_over`).
- Failure scenario: `SetConsoleOutputCP(65001)` fails and the put-back of the output mode fails too (a console that stopped answering):
  the console keeps virtual terminal processing on while `changed` is `false`, so no later way out (the `Tty` drop after `session`
  prints `sshelter: <error>` and returns 1) tries again.
- Change: clear the flag only when the put-back succeeded:
  `if self.api.set(Setting::OutputMode, self.start.output_mode).is_ok() { self.changed.store(false, Ordering::SeqCst); }`.
  Test: extend `a_take_over_that_fails_half_way_puts_back_what_it_set` with a fake that fails both `Set(OutputCodePage, CP_UTF8)` and
  `Set(OutputMode, start.output_mode)`: after the failed `take_over`, `drop(tty)` makes the four put-back calls (one more
  `Set(OutputMode, start)` among them); in the existing case (put-back succeeds) the drop still adds nothing.
- Proof: `cargo test --offline --locked --lib -- cli::console::tests` on macOS (portable test); the Windows run runs it too.

### F6 — Minor — `connect_refuses_a_pipe_another_owner_made` must fail, not skip, on CI (Task 1 re-review, parked minor)

- Where: `src-tauri/src/ipc/pipe_windows.rs:864-868`.
- Failure scenario: should the runner ever stop being elevated, the security regression test for the owner check would print
  `skipped: …` and pass, and nobody would notice.
- Change: before the `eprintln!` + `return`, `if std::env::var_os("CI").is_some() { panic!("on CI the runner is elevated: the squatter's pipe must be makeable, and this test must run") }`
  (the pattern `a_real_console_handle_is_refused_when_input_is_a_pipe` in `terminal_windows.rs` uses).
- Proof: the Windows run lists the test as `ok` (it runs there: 38396057437 was its red).

### F7 — Minor (docs) — spec sentences that are not quite true of HEAD (Task 5's M2, M3, M4, M6; the §12 sentence of F1)

- Where and change, `docs/superpowers/specs/2026-10-10-own-ssh-client-design.md`:
  - line 321 (§11, "app 建不了 session pipe"): the two sentences (`Another program is using …`, `Can't create …`) are the first pipe
    instance's (`first_instance_error`); the lock (`take_lock`), the security descriptor (`OwnerOnly::new`) and the listener thread each
    put their own error text after `[session] the broker is not listening: ` instead. Say so ("其他錯誤是…" is only true of the first
    instance's other errors).
  - line 254 (§7.4) and line 325 (§11, the missing-helper row): "托盤的快速連線只記在 log" → "只寫到標準錯誤(`eprintln!`;release 版的
    GUI 行程沒有 console,看不到)" (M3; the same truth as item 11 in F4).
  - line 332 (§12): "也在 `next/own-ssh` 的每次 push 跑" → "在改到 `src-tauri/` 或這個 workflow 的 push 跑(paths filter)" (M4), plus the
    NSIS-and-MSI sentence of F1.
  - line 376 (§16, the phase-0 list): remove "app 加上 russh 後的 Windows build" (test-windows.yml's "Build the whole app" builds it with
    russh on every push: 38423069911), and line 4 (狀態): append "2026-10-13 依第 1 期 Windows 版修訂:§4、§7.2–7.4、§11、§12、§16;修訂處標
    「(第 1 期,Windows)」".
- Proof: read; no code.

### F8 — Minor (docs/bindings) — `TerminalInfo.supports_new_tab`'s doc says only iTerm2 qualifies (Task 5's M1, Task 4's minor)

- Where: `src-tauri/src/connect.rs:17-21`; `src/bindings/TerminalInfo.ts` (generated by ts-rs from that doc).
- Change: "Only iTerm2 qualifies: …" → "iTerm2 (macOS) and Windows Terminal (`wt -w 0 nt`) qualify; Terminal.app's only new-tab path is
  System Events GUI scripting (Accessibility permission: not done), cmd has no tabs, and every Linux emulator opens a window." Then
  regenerate the binding: `cargo test --offline --locked --lib -- connect::export_bindings_terminalinfo --exact` (from `src-tauri`, with
  the usual PATH) rewrites `src/bindings/TerminalInfo.ts`; commit it.
- Proof: the committed `.ts` carries the new text; `./node_modules/.bin/tsc --noEmit` exit 0.

---

## Before the beta

1. The wave (F1–F8) pushed to `next/own-ssh` with `windows key slots` and `ssh engine` green on its last head (both legs of the engine
   run; no rerun), and `windows bundle check` green on the wave's push of its file: both installers listed, the helper beside `sshelter.exe`
   in each, usage + 2 from both images (F1).
2. After the merge into `main`: dispatch `windows bundle check` once from `main` (the plan's step) and require green; then `publish beta`.
3. The beta's first manual checks are the gate on what CI cannot see (the checklist, items 4 and 8 first): the release GUI
   `sshelter.exe connect` reaching the console through the helper. CI proved the relay (usage + 2 with stderr captured through a pipe), not
   the console: `AttachConsole` plus the inherited console handles as standard input/output (`terminal_windows.rs` `StdConsole::new`,
   `Buffer::Standard`) run on a real Windows only — every real-console case in CI opens `CONIN$`/`CONOUT$` itself (`StdConsole::opened`).
   If item 4 shows the usage in the console and item 8 opens a session, the whole path is proven; if either fails, the beta cannot connect
   and must not be announced.

## Hand-off (not for this wave)

- H1. The requester chain of a connect session names the helper: `session/broker.rs:709-719` strips only SSHelter's own executable from
  the peer chain, and `ipc/peer.rs`'s `SKIP` list has no `sshelter-cli`, so on Windows `requested_by` reads "Windows Terminal → PowerShell
  → sshelter-cli" and the identity's program is the helper. Nothing shows it in phase 1 (the sessions list is phase 3; MCP clients do not
  go through the helper). Strip the helper too (same directory, `sshelter-cli.exe`) when the list is built.
- H2. The helper does not put the console back after a hard-killed child (`cli-helper/src/lib.rs:66` `run`): a `sshelter.exe` ended by
  TerminateProcess (Task Manager) leaves the console raw, with VT and UTF-8 on, for the shell. Saving the four settings before the relay
  and putting them back after it (std plus four kernel32 externs, ~40 lines, belt and braces) would cover it; spec §7.3 gives the restore
  to `sshelter.exe` today, and every way out it has restores. A manual check records the outcome meanwhile (below).
- H3. `windows-bundle-check.yml`'s `push` trigger (lines 13-15) is dead configuration after the merge (`workflow_dispatch` works from
  `main`); remove it in a post-merge cleanup.
- H4. README: the Connect bullet and the Windows paragraph say "up to 0.17.0-9" and "in development for 1.0"; when the beta ships they
  describe a released version — update them in the beta's notes (Task 5's concern 4).
- H5. Portable tests that sleep for a thread to be inside a read/write (not seen flaky, but the same shape as the slow-terminal flake):
  `cli/console.rs:1325` `INTO_THE_READ` (used at :1354, :1406, :1423, :1442, :1453: a loaded runner may not have the reading thread in the
  fake's read within 200 ms, then no `Wake` is recorded and the assertion fails) → count reads in progress in `FakeConsole::read` and wait
  with `eventually`; `cli/run.rs:1370` (`a_writer_that_cannot_write_is_stopped_within_its_bound` sleeps 100 ms for the writer to be inside
  `write`, then asserts `took >= STOP_WAIT`) → a flag in `Writes` set when a write starts waiting, waited for with `eventually`.
- H6. CI never runs the production console path with the standard handles (`Buffer::Standard`): a real-console case whose child has the
  new console's handles as its standard handles (not the parent's pipes) would need the child started without `STARTF_USESTDHANDLES`,
  which `std::process::Command` sets whenever the parent's handles are non-null; a small Win32 spawn in the test could do it. Until then
  the manual gate above stands.
- H7. Two paths the broker never takes today can show one blank line on Windows (a second question replacing the first; a shell opening
  over a question): the client's own `\n` comes before the console layer's Enter (Task 3's fix-round note). Declined; revisit if the broker
  ever takes them.
- H8. A release build that fails the tray's quick connect shows nothing (the failure goes to standard error only); a toast through the
  window is a product decision for phase 3.
- H9. Test listeners in `ipc/pipe_windows.rs`'s and `cli/mod.rs`'s Windows tests are never stopped (no stop API); harmless in a test
  process (Task 1's minor 2).
- H10. Phase 2 (MCP): the identity of a program that connects through the session pipe is the user's, not SSHelter's (spec §4 says so);
  the owner check accepts any same-user program, as the Unix socket does.

## Manual checks for the user (additions to the checklist file; F4 adds the install/update/uninstall section)

- Gate first: items 4 and 8 (see "Before the beta" 3): the usage printed in the console by the release pair, and a session opened from
  the row with Windows Terminal — the only proof of the release GUI build's console path.
- After a hard kill: with a `web` session open, end `sshelter.exe` (the one with `connect` on its command line) from Task Manager: the
  helper exits with the kill's code, and the console is expected to be left raw (no echo, no line editing; H2) — record what the window
  does and whether `chcp` still says 65001; close that window afterwards.
- Ctrl-C at the hidden password question in Windows Terminal and in the classic console: nothing typed shows at the next prompt (item
  22), and record how many line breaks follow the question (the cancel prints one of the CLI's own; whether the console moved already on
  a keyboard Ctrl-C was not measured).
- Elevated SSHelter with a normal `sshelter connect` (item 29): the expectation to record is that the session opens (a pipe made by a
  high-integrity process gets a medium label by default); `Another program is using …` or `cannot connect to SSHelter (Access is denied …)`
  would be a finding.
- Output redirected: `& <helper> connect web > "$env:TEMP\out.txt"` in a session that runs `echo hi; exit`: the keys still come from the
  console and the file holds the shell's output (the output buffer is `CONOUT$` for modes and size, the file for bytes).
- A non-ASCII hidden answer (type a password with an IME or `密` in it at `pw`'s question): the server receives it (the login succeeds with
  such a password set), since the keys are read as UTF-16 and sent as UTF-8 whatever the input code page is.

---

## Parked findings, re-graded

| Source | Finding | Now |
|---|---|---|
| Task 1 review | owner check (Important); each 10 s; guarded write | fixed (53c8d45, e0d44d5, 50963a5), re-reviewed; §4 and §7.2 say it |
| Task 1 review | test listeners never stopped | present, harmless → H9 |
| Task 1 re-review | squatter test skips silently when not elevated | present → F6 |
| Task 2 review | deferred take-over (Important); DNAR fallback; Unsupported; panic-hook race; CI assertion; pins | fixed (44e07fc), re-reviewed |
| Task 2 re-review (1) | take_over clears `changed` after a failed put-back | present → F5 |
| Task 2 re-review (2) | every way out before take_over (hook, watchdog, handler) | addressed: `cli/mod.rs:234-262` order, test `every_way_out_is_in_place_before_the_console_is_changed_and_a_legacy_console_is_said` |
| Task 2 re-review (3) | `restore_on_panic` untested | addressed: real-console case `a_panic_puts_the_real_console_back` (the hook installed, the panic reported) |
| Task 2 re-review (4) | take-over lines duplicated | two lines each now (`Tty::take_over`, `set_mode`); declined as polish |
| Task 3 review | Important 1 (wake on a discarding switch to cooked); Important 2 (reads left at exit) | fixed (8aff312); measured in a shared console (b3824a9), no change needed |
| Task 3 review | minors 1, 3, 4, 5, 6 | fixed (8aff312, bc9bb8b, b3824a9) |
| Task 3 review | minor 2 (a refused wake) | documented §16 (line 104); a code change is not worth it (UWP / lower-integrity consoles) — declined |
| Task 3 review | minor 7 (Ctrl-Z, usage after attach, foreign CTRL_C_EVENT, conhost-only) | documented §7.3, §16, checklist |
| Task 3 fix round | blank line in two unreachable paths | declined → H7 |
| Task 4 review | dispatchability (Important); connect:: on Windows; debug-only fallback; NTSTATUS code; --config comments | fixed (2eb97cd, a7a4b72, 1e587e6, c763c0e); the check ran (38412254650) |
| Task 4 review | cmd quoting limit | documented §16 (line 103) and checklist 13 |
| Task 4 re-review | MSI gap | present → F1 (before the beta) |
| Task 4 re-review | test-windows.yml comment; connect.rs:20; --config wording; dead push trigger | comment fixed (edc3862); connect.rs → F8; wording acceptable as written (declined); trigger → H3 |
| Task 5 review | I1 (install/update/uninstall items) | → F4 |
| Task 5 review | M1 | → F8 |
| Task 5 review | M2, M3, M4, M6 | → F7 |
| Task 5 review | M5 (§16 cites a measurement §7.3 did not hold) | resolved by aa23b36: §16 line 102 cites "§7.3 的讀取與模式切換", which §7.3 line 57 holds |
| Task 5 review | M7 (item 24 wording) | → F4 |
| Task 5 concerns | wedge flake; §7.3/§16 after Task 3's fix round; README framing; item 29 | → F3; re-checked true (below); → H4; stays manual |
| Ledger | slow-terminal flake (38381028775) | guarded since (38385515128); nothing to do |

## Checked and found sound (what no task review could see)

- CLI ↔ broker over the pipe, end to end: connect with the owner check (`pipe_windows.rs` `connect` → `pipe_owner`/`served_by_user`; a
  `PermissionDenied` without an OS code is the squatter sentence, with one the OS reason, neither starts SSHelter: `cli/mod.rs:193-212`);
  hello and open_shell each on a re-armed 10 s deadline (`broker.rs` `serve`, `hang_up_after`); questions, data, `exited` as the end
  (`client.rs` `Exited` → exit, never waiting for the pipe's end); every Windows end path puts the console back with the writer stopped
  first: shell exit (`Action::Exit` → `stop(STOP_WAIT)` → `restore`), app quit (`end_all` tells, hangs up; `exited` ends the CLI),
  window closed (`CTRL_CLOSE_EVENT` → `Stop(1)`, watchdog armed, the handler waits on `Over` ≤ 3.2 s; the watchdog's exit at 2.2 s; both
  under the 5 s close limit), Ctrl-C/Break (`Interrupt`: a question cancelled or 130; in raw mode Ctrl-C is a key, Break always a signal),
  the watchdog (`hold_restored` 200 ms, then exit), a panic (`restore_on_panic` → lock-free `put_back`, then `Input::Failed` → 255 with
  the console taken over and put back again), the console gone (a failed read → `Stop(1)` + watchdog). No key is lost to a read that spans
  a change (the gate's generation counter; delivery under the gate's lock), and the reads left at exit die with the process (measured).
- Lock order: `set_mode` holds `now` and takes `reads.state` (released while waiting); the keys thread takes only `reads.state`, and its
  delivery (`inputs.typed` → `Budget::charge`, an unbounded channel) never blocks under it; the handler, the watchdog and the panic hook
  take nothing blocking (`try_lock` everywhere; `Reads::halt` too). `Tty::drop`'s `reads.close()` takes `state` blocking, and nothing can
  hold it for long. Every wait is bounded: pause 500 ms, writer stop 200 + 200 ms, END_WAIT 1.5 s, MODE_WAIT 1 s, Over 3.2 s, busy pipe 2 s,
  start 12 s.
- Launch chain: Connect/palette/tray → `launch_for` → `connect_program` (helper when present; `sshelter.exe` only in a debug build; else
  the missing-helper sentence) → `wt.exe [-w 0 nt] <argv>` or `cmd /c start "" cmd /k <argv>` → `sshelter-cli.exe` (handler before the
  relay; exit code whole) → `sshelter.exe connect` (arguments, attach, `StdConsole`, `Tty::new`, broker, hook, watchdog, handler,
  take-over, keys, size, run). The background start (`host_start.rs:197-203`: `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`, null stdio)
  keeps a debug-build app off the terminal's console (no `CTRL_CLOSE_EVENT` reaches it); the release app is a GUI program anyway.
- Security: pipe DACL user-only, owner set to the user (also when elevated), remote clients refused, first-instance flag, client
  `SECURITY_IDENTIFICATION`, the client's owner check fails closed (null/unreadable owner refused), the helper runs only `sshelter.exe` from
  its own directory with no shell, the hidden answer is read without echo and is not in the console's history (measured), every buffer
  that held keys is `Zeroizing` or wiped, the stale read's text is wiped; the agent's pipe changed only in mode (overlapped) and owner, and
  the real ssh-add/ssh-keygen tests pass against it.
- Release pipeline: beta/release/build-platform Windows legs build the helper with `+crt-static` and pass `externalBin` through `--config`
  (the JSON holds nothing cmd would read); NSIS proven by the check (listing, imports, the pair); updater artifacts and signing untouched;
  `build-platform` guards older tags with `hashFiles`. MSI → F1.
- Unix unchanged: `signal::` numbers pinned against libc; `client.rs` actions identical with `QUESTION_READ_ENDS_ITS_LINE = false`;
  `run.rs`'s Unix paths `cfg(unix)`; the broker's second `set_read_timeout` sets the same `SO_RCVTIMEO`; `connect.rs` `launch_for` the same
  on Unix; test helpers gated `cfg(unix)` where only Unix tests use them.
- Docs: every Windows sentence of §4, §7.2, §7.3, §7.4, §11, §12, §16 checked against HEAD (constants: 4096 units, 500 ms, 250 ms,
  200 + 200 ms, 2 s busy wait, 3.2 s handler wait; the strings of §11 word for word), the README's framing, the HostEditor sentence, the
  CI comments, the checklist — true, except the items in F1, F4, F7, F8.
