# Own SSH client on Windows (plan 1b-3) — manual verification

Run on a Windows 11 computer and, if you have one, a Windows 10 one, with a beta build of this branch installed by its NSIS installer
(it installs for the current user, into `%LOCALAPPDATA%\SSHelter`). Items 5 and 10 also need a debug build (`pnpm tauri dev` from a
checkout on that computer). Use a test server you can log in to by key and by password, and throwaway keys and host entries. Record
each item as pass / fail with a note.

CI measured one console only: the classic console host (conhost) of the GitHub runner, through a test program that types into a console
of its own (own-ssh spec §7.3, §16). What a keyboard, Windows Terminal, an input method and a closed window do is what these items check.
Commands are for PowerShell unless an item says cmd. `<helper>` is `"$env:LOCALAPPDATA\SSHelter\sshelter-cli.exe"`; in PowerShell run it
as `& <helper> connect web` and read its exit code with `$LASTEXITCODE`.

## Setup

1. **Hosts.** In `%USERPROFILE%\.ssh\config` (press Reload from disk in SSHelter after a hand edit):
   - `web`: logs in with a key that is in SSHelter (Keychain, "In SSHelter"; SSHelter's own client does not use key files), its `.pub`
     in the test server's `authorized_keys`. Connect it once and press "Trust this key" before item 6.
   - `pw`: the same server with `IdentityFile none` and no saved password, so the server asks for a password.
   - `fresh`: the same server under a new alias, with `web`'s key. SSHelter has pinned no host key for it yet (item 7 uses it, and a
     second new alias, `fresh2`, for the Cancel half).
2. **Terminals.** SSHelter's Settings, Connection: "Default terminal" is Windows Terminal (when it is installed) or Command Prompt, and
   "Open connections in a new tab" applies to Windows Terminal only. On Windows 11 a new console window opens in Windows Terminal when
   Windows Terminal is the default terminal application (Windows Terminal → Settings → Startup → Default terminal application); for the
   items that say "classic console" set it to Windows Console Host, and set it back at the end.
3. **Check C (the console is as it was).** Before an item, note what `chcp` prints in the console you will use (for Connect through
   Command Prompt: in the window `cmd /k` keeps open afterwards, compared with a fresh Command Prompt window). After the item, in that
   console:
   - `chcp` prints the same code page;
   - type `echo hi` slowly: each letter shows as you type and Backspace erases; after Enter, Up brings the command back;
   - Ctrl-C at an empty prompt gives a new prompt;
   - PowerShell only: ``Write-Host "one`ntwo"`` prints `two` at the left edge;
   - mouse selection works as it did before (classic console with Quick Edit).

## Install and start

4. **The helper is installed next to SSHelter and needs no VC++ runtime.** `Get-ChildItem "$env:LOCALAPPDATA\SSHelter" -Filter *.exe`
   lists `sshelter.exe` and `sshelter-cli.exe`. On a Windows without "Microsoft Visual C++ 2015-2022 Redistributable" in Settings →
   Apps (a fresh VM), run `& <helper> connect`: it prints the usage (`usage: sshelter connect <alias>`, and below it, indented,
   `sshelter connect --id <host id>`), `$LASTEXITCODE` is 2, and no "VCRUNTIME140.dll was not found" dialog appears. The first Connect
   after installing (item 8) works on that computer too.
5. **The broker listens.** Run the debug build from a console (`pnpm tauri dev`, which shows what SSHelter writes to standard error):
   once the window is open there is no line starting with `[session]` (`[session] the broker is not listening: …`). With the installed
   build: quit SSHelter, run `Start-Process "$env:LOCALAPPDATA\SSHelter\sshelter.exe" -RedirectStandardError "$env:TEMP\sshelter-err.txt"`,
   and once its window is open `Select-String -Path "$env:TEMP\sshelter-err.txt" -Pattern '^\[session\]'` prints nothing.
6. **The background start.** Quit SSHelter (tray icon → Quit). In a Windows Terminal tab run `& <helper> connect web`. SSHelter starts
   without its window (its tray icon appears), answers within 12 seconds, and the remote prompt shows in this tab. `exit` the remote
   shell: the PowerShell prompt is back, `$LASTEXITCODE` is 0, check C passes, and SSHelter keeps running. Close the tab: SSHelter
   still runs.
   Then quit SSHelter again, run the same command, and press Ctrl-C at once, while SSHelter is still starting: the command ends at once
   with `$LASTEXITCODE` -1073741510 (STATUS_CONTROL_C_EXIT: the program ended the default way, before it changed anything), check C
   passes, and SSHelter still finishes starting. Pressed a little later, once SSHelter answered and while it connects, Ctrl-C ends the
   program with 130 instead, and check C passes too.

## Connect

7. **The first host key.** Connect `fresh` from its row. The terminal prints `Waiting for you to confirm fresh's host key in SSHelter.`
   and SSHelter's window "Is this fresh?" shows the server's key. "Trust this key": the remote prompt shows. `exit`, then Connect
   `fresh` again: no question. Connect `fresh2` and press "Cancel": the terminal prints `The host key of fresh2 has not been confirmed
   yet.` and the program ends (255); check C.
8. **Every way to Connect, in Windows Terminal.** With Windows Terminal as the default terminal, each of these opens Windows Terminal
   with `web`'s remote prompt: the row's Connect button, the editor's Connect button, the palette (Ctrl+K, type `web`, Enter), and the
   tray icon's quick connect (it always uses the first terminal SSHelter finds, Windows Terminal when it is installed). With "Open
   connections in a new tab" on, the row's Connect opens a tab in the most recent Windows Terminal window. `exit` ends each session.
9. **Command Prompt in the classic console.** Default terminal Command Prompt, Windows Console Host as the default terminal application
   (setup 2). Connect `web`: a new console window opens with the remote prompt. `exit`: the window stays open at a cmd prompt
   (`cmd /k`); check C in that window. Item 7 again in this console.
10. **A debug build has no helper.** With `pnpm tauri dev` running (there is no `sshelter-cli.exe` next to
    `src-tauri\target\debug\sshelter.exe`), Connect `web` with Windows Terminal and with Command Prompt: the session opens (the debug
    `sshelter.exe` is a console program and runs itself).
11. **A release build whose helper is missing.** Quit SSHelter, rename `sshelter-cli.exe` in the install folder to
    `sshelter-cli.exe.bak`, start SSHelter. Connect `web` from its row: no terminal opens, and the toast "Could not connect" says
    `sshelter-cli.exe is missing from <the install folder>. Reinstall SSHelter.` The tray's quick connect opens nothing either (it only
    logs). Rename the file back.
12. **Spaces in the install folder.** If your profile folder name has a space, or the installer lets you choose a folder such as
    `C:\SSHelter test`: Connect `web` works with Windows Terminal and with Command Prompt.
13. **The cmd limit (spec §16).** With a helper path that holds `&` or parentheses (a Windows account named like `R&D` or `Jo (test)`,
    whose profile folder is in the per-user install path, or a chosen folder such as `C:\R&D tools`): Connect `web` with Command Prompt
    and record what the window shows (the documented limit: cmd reads the path). With Windows Terminal the session opens.

## In the session

14. **Text and keys.** In a `web` session, in Windows Terminal and in the classic console: `echo 密碼 🔑` prints `密碼 🔑`; arrows,
    Home and End, Tab completion and the shell's history work; Ctrl-C at the remote prompt goes to the remote (`^C`, a new remote
    prompt, the session goes on); `sleep 30` and Ctrl-C stops the `sleep`.
15. **Pasting a long text.** ``Set-Clipboard ((1..2000 | ForEach-Object { "line $_ " + ('x' * 40) }) -join "`n")``. In the session run
    `cat > /tmp/paste.txt`, paste (accept Windows Terminal's multi-line paste warning), press Enter and then Ctrl-D:
    `wc -l /tmp/paste.txt` says 2000, `head -1` and `tail -1` show `line 1 x…` and `line 2000 x…`, nothing garbled. Remove the file.
16. **An input method.** With a Chinese (or Japanese) IME, compose at the remote prompt (`echo 你好`): the composition shows while you
    compose, the committed text reaches the remote once (the remote prints `你好`), nothing is doubled or lost. In both terminals.
17. **Resizing.** Run `stty size`, then resize the window (drag an edge, maximize; in Windows Terminal also Ctrl+= and a split pane):
    `stty size` shows the new rows and columns within half a second, and `top` (or `vim`) redraws to the new size.
18. **Line endings.** In the session: `stty -onlcr; printf 'one\ntwo\n'; stty onlcr` prints `two` below the end of `one` (a bare line
    feed does not return the carriage, as in xterm and in macOS Terminal), and `printf 'one\ntwo\n'` with `onlcr` on prints `two` at the
    left edge. SSHelter's own lines start at the left edge before, during and after a session: `Waiting for you to confirm …`, a
    question, and the reason printed at the end.
19. **Typing before the shell opens.** Quit SSHelter so that the start takes a few seconds, run `& <helper> connect web`, and at once
    type `uptimx`, Backspace, `e`, Enter. Nothing shows while it starts and connects (spec §7.3: Windows keeps typeahead in the console,
    unlike a Unix terminal, which shows it); once the shell opens it gets the keys as keys: the remote shell shows `uptime`, runs it, and
    shows no `x`.
20. **Ctrl-Break in the shell.** In a `web` session started with `& <helper> connect web` (Windows Terminal, then the classic console),
    press Ctrl-Break: the program ends at once with `$LASTEXITCODE` 130 (Ctrl-Break is always a signal on Windows, spec §7.3), the
    remote session ends, and check C passes. The PowerShell prompt comes back only then: the helper did not end first.

## Questions

21. **A password question.** Connect `pw`. The terminal shows the server's question: `(<user>@pw) Password: ` (keyboard-interactive) or
    `<user>@pw's password: `. What you type does not show; Enter answers it and the shell opens. No blank line follows the
    question: what comes next starts on the line after it (spec §7.3: the console ends the line on Enter).
22. **Ctrl-C, Ctrl-Break and Ctrl-Z at a question.** At `pw`'s question, type a few letters and press Ctrl-C: the question ends, the
    terminal prints `Authentication for pw was abandoned (…)`, the program ends (255), check C passes, and the letters typed at the
    question do not appear at the next prompt. The same with Ctrl-Break. Then Ctrl-Z as the first key of the answer and Enter: the
    question is cancelled as with Ctrl-C (Windows' end of input). Ctrl-D is part of the answer (on Unix it cancels the question): type
    Ctrl-D, the password and Enter, and the server does not accept it (it asks again, or the login fails).
23. **Typeahead does not become the answer.** Connect `pw` and type `secret` and Enter while it connects: the question still waits for
    an answer (the typed line was thrown away before it was asked).

## Endings

24. **Closing the window.** During a `web` session: close the Windows Terminal tab; close a Windows Terminal window that holds only that
    tab; close a classic console window. Then the same at `pw`'s question. Each time the remote login ends (on the server, `who` no
    longer lists it) and SSHelter keeps running. A new console window behaves normally (check C in it).
25. **Quitting SSHelter.** During a `web` session, quit SSHelter (tray → Quit): the terminal prints
    `SSHelter quit, so the connection to web was closed.`, the program ends (255), check C passes. The same at `pw`'s question, with a
    few letters typed into the answer first: the sentence names `pw`, and the letters do not appear at the next prompt.
26. **The shell's exit code.** `& <helper> connect web`, then `exit 3` in the remote shell: `$LASTEXITCODE` is 3, check C passes.
27. **The first key after the end is not lost.** In a Windows Terminal tab and in a classic console window: `& <helper> connect web`,
    end the session, and at once type `echo after` and Enter: PowerShell runs `echo after` whole (its first letter is not swallowed).
    End the session three ways: `exit` in the remote shell, Ctrl-Break, and quitting SSHelter.

## Consoles

28. **The legacy console.** In a classic console window open Properties (title bar menu), Options, check "Use legacy console", and open
    a new Command Prompt window (Windows Console Host as the default terminal application, setup 2). Run
    `"%LOCALAPPDATA%\SSHelter\sshelter-cli.exe" connect web`: it prints
    `sshelter: the console does not support virtual terminal sequences (…)` (the parentheses hold Windows' reason), `echo %ERRORLEVEL%`
    prints 1, and check C passes. Uncheck "Use legacy console".
29. **An elevated SSHelter next to a normal `sshelter connect` (the owner check).** Quit SSHelter and start it with "Run as
    administrator". In a normal Windows Terminal tab run `& <helper> connect web`. It must not print
    `Another program is using SSHelter's session pipe (…)`: SSHelter names you as the owner of its pipes even when it runs elevated.
    Record whether the session opens, or what it prints instead. Quit the elevated SSHelter and start it normally.
30. **(Optional, a known limit) A client at a lower integrity level.** Copy the install folder to `$env:TEMP\sshelter-low`, run
    `icacls "$env:TEMP\sshelter-low\sshelter-cli.exe" /setintegritylevel low` and the same for `sshelter.exe` there, then run
    `& "$env:TEMP\sshelter-low\sshelter-cli.exe" connect web` from a normal console. Record what it prints and whether check C passes
    (spec §16: a console that refuses `WriteConsoleInputW` cannot end a pending read at a change of mode). Delete the copy.

## Clean up

31. Set the default terminal application and SSHelter's terminal settings back, uncheck "Use legacy console" if it is still checked,
    remove `fresh`, `fresh2` and `pw` (and their pinned keys) and `$env:TEMP\sshelter-err.txt`.
