//! Connect module: terminal detection + per-emulator launch argv + alias validation.
//!
//! Security model: the WebView has NO shell permission. All process spawning happens here in
//! Rust. We NEVER use `sh -c`; commands are always built as argv vectors. The alias is validated
//! (charset + must exist as a host pattern in the loaded doc) before any spawn.

use serde::{Deserialize, Serialize};

use crate::config::model::{HostBlock, Item, SshConfigDoc};
use crate::error::AppError;

/// A terminal emulator we can launch into.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct TerminalInfo {
    pub id: String,
    pub label: String,
    /// Whether this terminal supports opening the connection in a NEW TAB of an existing window.
    /// iTerm2 (macOS) and Windows Terminal (`wt -w 0 nt`) qualify; Terminal.app's only new-tab path
    /// is System Events GUI scripting (Accessibility permission: not done), cmd has no tabs, and
    /// every Linux emulator opens a window.
    pub supports_new_tab: bool,
}

/// A resolved process invocation: program + argv (no shell).
#[derive(Debug, Clone, PartialEq)]
pub struct LaunchSpec {
    pub program: String,
    pub args: Vec<String>,
}

/// Allowed alias charset: non-empty and every char in [A-Za-z0-9._@%-].
fn alias_charset_ok(alias: &str) -> bool {
    !alias.is_empty()
        // Reject a leading '-': otherwise an alias like `-Fevil`/`-D8080` is read by `ssh` as an
        // OPTION, not a hostname (argument injection — `-F` loads an arbitrary config → ProxyCommand
        // RCE). OpenSSH has no `--` end-of-options marker, so rejecting the dash is the mitigation.
        && !alias.starts_with('-')
        && alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '%' | '-'))
}

/// True if the doc has a HostBlock whose patterns contain the exact `alias`.
fn doc_has_alias(doc: &SshConfigDoc, alias: &str) -> bool {
    doc.files.iter().any(|f| {
        f.items.iter().any(|item| {
            if let Item::Host(HostBlock { patterns, .. }) = item {
                patterns.iter().any(|p| p == alias)
            } else {
                false
            }
        })
    })
}

/// Validate an alias: charset must be safe AND the alias must exist as an exact host pattern in
/// the loaded doc. Bad charset → ForbiddenPath; absent from doc → NotFound.
pub fn validate_alias(doc: &SshConfigDoc, alias: &str) -> Result<(), AppError> {
    if !alias_charset_ok(alias) {
        return Err(AppError::ForbiddenPath(format!(
            "alias contains disallowed characters: {alias:?}"
        )));
    }
    if !doc_has_alias(doc, alias) {
        return Err(AppError::NotFound(format!("host '{alias}' not found")));
    }
    Ok(())
}

/// Escape a string for embedding inside an AppleScript double-quoted literal.
/// (The alias charset already forbids `"` and `\`, but we escape defensively.)
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Quote ONE argv element for a POSIX shell command line (the string a terminal
/// emulator hands to the user's shell, e.g. via AppleScript `do script`).
///
/// Args made of an unambiguous safe charset are left bare (so `ssh web` stays
/// `ssh web`); anything else is single-quoted with embedded `'` escaped as
/// `'\''`. NOTE `~` is NOT in the safe set — a bare `~` would be tilde-expanded.
pub fn shell_quote(arg: &str) -> String {
    let safe = |c: char| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '%' | '+' | '=' | ',')
    };
    if !arg.is_empty() && arg.chars().all(safe) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// Join an argv vector into one shell-safe command string (each element passed
/// through `shell_quote`).
pub fn shell_join(argv: &[String]) -> String {
    argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")
}

#[cfg(target_os = "macos")]
pub fn detect_terminals() -> Vec<TerminalInfo> {
    let mut out = vec![TerminalInfo {
        id: "terminal".to_string(),
        label: "Terminal".to_string(),
        // Terminal.app new-tab needs System Events GUI scripting + accessibility permission.
        supports_new_tab: false,
    }];
    if std::path::Path::new("/Applications/iTerm.app").exists() {
        out.push(TerminalInfo {
            id: "iterm2".to_string(),
            label: "iTerm2".to_string(),
            supports_new_tab: true,
        });
    }
    out
}

#[cfg(target_os = "windows")]
pub fn detect_terminals() -> Vec<TerminalInfo> {
    let mut out = Vec::new();
    // Windows Terminal when installed (per-user App Execution Alias on PATH)…
    if which_in_path("wt.exe") {
        out.push(TerminalInfo {
            id: "wt".to_string(),
            label: "Windows Terminal".to_string(),
            supports_new_tab: true,
        });
    }
    // …and cmd as the always-present fallback.
    out.push(TerminalInfo {
        id: "cmd".to_string(),
        label: "Command Prompt".to_string(),
        supports_new_tab: false,
    });
    out
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn detect_terminals() -> Vec<TerminalInfo> {
    let mut out = Vec::new();

    // $TERMINAL takes priority if set.
    if let Ok(term) = std::env::var("TERMINAL") {
        if !term.trim().is_empty() {
            let base = std::path::Path::new(term.trim())
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| term.trim().to_string());
            out.push(TerminalInfo {
                id: "env".to_string(),
                label: base,
                supports_new_tab: false,
            });
        }
    }

    // Probe PATH for known emulators, in priority order.
    const KNOWN: &[(&str, &str)] = &[
        ("ptyxis", "Ptyxis"),
        ("gnome-terminal", "GNOME Terminal"),
        ("konsole", "Konsole"),
        ("kitty", "Kitty"),
        ("alacritty", "Alacritty"),
        ("wezterm", "WezTerm"),
        ("foot", "Foot"),
        ("xfce4-terminal", "Xfce Terminal"),
        ("xterm", "XTerm"),
    ];
    for (bin, label) in KNOWN {
        if which_in_path(bin) {
            out.push(TerminalInfo {
                id: bin.to_string(),
                label: label.to_string(),
                supports_new_tab: false,
            });
        }
    }
    out
}

/// Best-effort `which`: is `bin` found on $PATH?
#[cfg(not(target_os = "macos"))]
fn which_in_path(bin: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(bin);
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

/// Map a known Linux terminal id to its argv tail for running `argv` in a new window.
/// `None` => unknown id. Where the emulator execs a program directly, the argv is passed
/// through untouched (no shell, no quoting); only `xfce4-terminal -e` takes a single
/// shell-parsed string, which is built with `shell_join`.
fn linux_args(id: &str, argv: &[String]) -> Option<Vec<String>> {
    let tail = |prefix: &[&str]| -> Vec<String> {
        prefix
            .iter()
            .map(|s| s.to_string())
            .chain(argv.iter().cloned())
            .collect()
    };
    Some(match id {
        "ptyxis" => tail(&["--"]),
        "gnome-terminal" => tail(&["--"]),
        "konsole" => tail(&["-e"]),
        "kitty" => tail(&[]),
        "alacritty" => tail(&["-e"]),
        "wezterm" => tail(&["start", "--"]),
        "foot" => tail(&[]),
        // single-string exec parsed by a shell → shell-safe quoting required.
        "xfce4-terminal" => vec!["-e".into(), shell_join(argv)],
        "xterm" => tail(&["-e"]),
        _ => return None,
    })
}

/// Build the platform/terminal-specific argv to open `ssh <alias>` in a NEW terminal window —
/// or, when `new_tab` is true and the terminal supports it (iTerm2, Windows Terminal), a new TAB of the
/// current window (falling back to a new window when none exists).
/// PURE function. The alias is assumed pre-validated; thin wrapper over `build_launch_command`.
/// Only the tests use it: every platform connects through `sshelter connect` (`launch_for`).
#[cfg(test)]
pub fn build_launch(terminal_id: &str, alias: &str, new_tab: bool) -> Result<LaunchSpec, AppError> {
    build_launch_command(terminal_id, &["ssh".to_string(), alias.to_string()], new_tab)
}

/// Generalized launcher: run an arbitrary `argv` (program + args) in a new terminal
/// window/tab. PURE function.
///
/// macOS paths embed the command into an AppleScript literal that the terminal hands to a
/// shell, so each argv element is shell-quoted (`shell_join`) FIRST and the resulting command
/// string AppleScript-escaped SECOND. Linux emulators receive the argv directly where they
/// exec the program (no shell), except `xfce4-terminal` (see `linux_args`).
pub fn build_launch_command(
    terminal_id: &str,
    argv: &[String],
    new_tab: bool,
) -> Result<LaunchSpec, AppError> {
    if argv.is_empty() {
        return Err(AppError::Other("empty command".to_string()));
    }
    match terminal_id {
        "terminal" => {
            let esc = applescript_escape(&shell_join(argv));
            Ok(LaunchSpec {
                program: "osascript".into(),
                args: vec![
                    "-e".into(),
                    "tell application \"Terminal\" to activate".into(),
                    "-e".into(),
                    format!("tell application \"Terminal\" to do script \"{esc}\""),
                ],
            })
        }
        "iterm2" => {
            let esc = applescript_escape(&shell_join(argv));
            if new_tab {
                // Multi-statement script as separate `-e` lines (osascript joins them into one
                // script): tab in the current window, or a new window when none exists.
                Ok(LaunchSpec {
                    program: "osascript".into(),
                    args: vec![
                        "-e".into(),
                        "tell application \"iTerm2\"".into(),
                        "-e".into(),
                        "activate".into(),
                        "-e".into(),
                        "if (count of windows) > 0 then".into(),
                        "-e".into(),
                        format!(
                            "tell current window to create tab with default profile command \"{esc}\""
                        ),
                        "-e".into(),
                        "else".into(),
                        "-e".into(),
                        format!("create window with default profile command \"{esc}\""),
                        "-e".into(),
                        "end if".into(),
                        "-e".into(),
                        "end tell".into(),
                    ],
                })
            } else {
                Ok(LaunchSpec {
                    program: "osascript".into(),
                    args: vec![
                        "-e".into(),
                        "tell application \"iTerm2\" to activate".into(),
                        "-e".into(),
                        format!(
                            "tell application \"iTerm2\" to create window with default profile command \"{esc}\""
                        ),
                    ],
                })
            }
        }
        "env" => {
            // Resolve $TERMINAL basename, then look it up in the Linux table.
            let term = std::env::var("TERMINAL").unwrap_or_default();
            let base = std::path::Path::new(term.trim())
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let args = linux_args(&base, argv)
                // unknown basename → best-effort `-e <argv…>`
                .unwrap_or_else(|| {
                    std::iter::once("-e".to_string())
                        .chain(argv.iter().cloned())
                        .collect()
                });
            Ok(LaunchSpec {
                program: if base.is_empty() { term } else { base },
                args,
            })
        }
        "wt" => {
            // Windows Terminal execs the argv directly (no shell). `-w 0 nt`
            // targets a tab in the most-recent window when asked; wt falls back
            // to a new window when none exists.
            let mut args: Vec<String> = if new_tab {
                vec!["-w".into(), "0".into(), "nt".into()]
            } else {
                Vec::new()
            };
            args.extend(argv.iter().cloned());
            Ok(LaunchSpec {
                program: "wt.exe".into(),
                args,
            })
        }
        "cmd" => {
            // `start` opens a fresh console; the inner `cmd /k` keeps it open
            // after the command exits, matching the mac/linux terminal behavior.
            // The empty "" is start's window-title slot.
            let mut args: Vec<String> =
                vec!["/c".into(), "start".into(), String::new(), "cmd".into(), "/k".into()];
            args.extend(argv.iter().cloned());
            Ok(LaunchSpec {
                program: "cmd".into(),
                args,
            })
        }
        other => match linux_args(other, argv) {
            Some(args) => Ok(LaunchSpec {
                program: other.to_string(),
                args,
            }),
            None => Err(AppError::NotFound(format!("unknown terminal: {other}"))),
        },
    }
}

// ─── What the terminal runs ──────────────────────────────────────────────────

/// `<program> connect [--pause-on-error] <alias>`: the command the terminal runs to connect through Lunport's own SSH client (own-ssh
/// spec §7.3, §7.4). `program` is Lunport's executable, or on Windows the console helper next to it (`connect_program`); `pause_on_error`
/// keeps the reason of a connection that fails before the shell opens on the terminal until Enter (`closes_after_a_failure`). The alias
/// must be validated first.
pub fn connect_argv(program: &std::path::Path, alias: &str, pause_on_error: bool) -> Vec<String> {
    let mut argv = vec![program.to_string_lossy().into_owned(), "connect".to_string()];
    if pause_on_error {
        argv.push(crate::cli::PAUSE_ON_ERROR.to_string());
    }
    argv.push(alias.to_string());
    argv
}

/// Stable identity survives alias changes and ambiguous aliases.
pub fn connect_id_argv(program:&std::path::Path,id:&str,pause_on_error:bool)->Vec<String>{
    let mut argv=vec![program.to_string_lossy().into_owned(),"connect".into()];
    if pause_on_error { argv.push(crate::cli::PAUSE_ON_ERROR.into()); }
    argv.extend(["--id".into(),id.into()]);argv
}
pub fn launch_for_id(terminal_id:&str,id:&str,new_tab:bool)->Result<LaunchSpec,AppError>{
    if !crate::sync::records_v3::is_host_id(id){return Err(AppError::Other("invalid host id".into()));}
    let exe=std::env::current_exe().map_err(AppError::Io)?;
    #[cfg(windows)]
    let exe=connect_program(&exe,cfg!(debug_assertions))?;
    build_launch_command(terminal_id,&connect_id_argv(&exe,id,closes_after_a_failure(terminal_id)),new_tab)
}

/// Whether the terminal `terminal_id` closes the window, and the reason of a failed connect with it, when the command ends with an error:
/// the terminals that run the command as the window's program and close it then (iTerm2, as 0.17.0-10 showed; the Linux emulators and an
/// unknown `$TERMINAL`, which are taken to). Not Terminal, whose `do script` runs the command in the shell of a new window; not cmd, whose
/// `cmd /k` stays after the command; and not Windows Terminal, whose `closeOnExit` default (`automatic`, which is `graceful` for a
/// program started in Terminal itself) keeps the pane of a program that ended with an error, with its own notice. There the reason stays
/// without a pause.
fn closes_after_a_failure(terminal_id: &str) -> bool {
    !matches!(terminal_id, "terminal" | "cmd" | "wt")
}

/// The console helper installed next to `sshelter.exe` on Windows (own-ssh spec §7.3; src-tauri/cli-helper). Release `sshelter.exe` is a
/// GUI program, which a shell does not wait for and a Windows Terminal tab gives no console; the helper is a console program that runs it
/// with the same arguments and waits for it.
#[cfg(any(windows, test))]
const CONSOLE_HELPER: &str = "sshelter-cli.exe";

/// What a Windows terminal runs to connect (own-ssh spec §7.4): the console helper next to Lunport's executable `exe` (an installed
/// Lunport). Without it a debug build (`debug_build`; a console program) runs `exe` itself, and a release build fails with a sentence
/// that names the missing helper: its `exe` is a GUI program, which a terminal neither waits for nor gives a console (§7.3).
#[cfg(any(windows, test))]
fn connect_program(exe: &std::path::Path, debug_build: bool) -> Result<std::path::PathBuf, AppError> {
    let helper = exe.with_file_name(CONSOLE_HELPER);
    if helper.is_file() {
        Ok(helper)
    } else if debug_build {
        Ok(exe.to_path_buf())
    } else {
        let dir = exe.parent().unwrap_or(exe);
        Err(AppError::Other(format!("{CONSOLE_HELPER} is missing from {}. Reinstall Lunport.", dir.display())))
    }
}

/// The launch for connecting to `alias` in `terminal_id`: `sshelter connect <alias>`, on Windows through the console helper
/// (`connect_program`), with `--pause-on-error` where a failure would close the window (`closes_after_a_failure`). Windows Terminal runs
/// that argv directly and cmd in a new console that stays open (`build_launch_command`).
pub fn launch_for(terminal_id: &str, alias: &str, new_tab: bool) -> Result<LaunchSpec, AppError> {
    let exe = std::env::current_exe().map_err(|e| AppError::Other(format!("cannot locate Lunport: {e}")))?;
    #[cfg(windows)]
    let exe = connect_program(&exe, cfg!(debug_assertions))?;
    build_launch_command(terminal_id, &connect_argv(&exe, alias, closes_after_a_failure(terminal_id)), new_tab)
}

/// Spawn the launch spec detached, inheriting the environment. Not unit-tested (side effect).
pub fn launch(spec: &LaunchSpec) -> Result<(), AppError> {
    crate::process::spawn(std::process::Command::new(&spec.program).args(&spec.args)).map_err(AppError::Io)?;
    Ok(())
}

// ─── Tauri commands ─────────────────────────────────────────────────────────

#[tauri::command]
pub fn connect_list_terminals() -> Vec<TerminalInfo> {
    detect_terminals()
}

// (async): spawning the terminal (osascript on macOS) does not belong on the main thread.
#[tauri::command(async)]
pub fn connect_launch(
    state: tauri::State<crate::state::AppState>,
    alias: String,
    terminal_override: Option<String>,
    new_tab: Option<bool>,
) -> Result<(), AppError> {
    {
        let doc_lock = state.doc.lock().unwrap();
        crate::sync::engine::require_legacy(&state.sync)?;
        let doc = doc_lock
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        validate_alias(doc, &alias)?;
    }

    let terminal_id = match terminal_override {
        Some(id) => id,
        None => {
            detect_terminals()
                .into_iter()
                .next()
                .ok_or_else(|| AppError::Other("no terminal found".to_string()))?
                .id
        }
    };

    launch(&launch_for(&terminal_id, &alias, new_tab.unwrap_or(false))?)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;

    /// The connect command reaches every terminal as it is: terminals that hand it to a shell (AppleScript's `do script`,
    /// xfce4-terminal) get the executable's path quoted when it has a space in it; the ones that run a program (the other Linux terminals,
    /// wt, cmd) get the argv untouched.
    #[test]
    fn a_record_launch_uses_id_even_when_an_alias_is_ambiguous_or_renamed(){
        let id="0123456789abcdef";
        for pause in [false,true]{let argv=connect_id_argv(std::path::Path::new("/app/Lunport"),id,pause);let args=&argv[2..];assert_eq!(crate::cli::parse_args(args).unwrap().host,crate::session::protocol::HostQuery::Id(id.into()));}
    }
    #[test]
    fn the_connect_command_reaches_every_terminal() {
        let argv = connect_argv(std::path::Path::new("/Users/me/My Apps/Lunport.app/Contents/MacOS/sshelter"), "web", false);
        assert_eq!(argv, vec!["/Users/me/My Apps/Lunport.app/Contents/MacOS/sshelter", "connect", "web"]);
        let quoted = "'/Users/me/My Apps/Lunport.app/Contents/MacOS/sshelter' connect web";
        for new_tab in [false, true] {
            let terminal = build_launch_command("terminal", &argv, new_tab).unwrap();
            assert_eq!(terminal.args.last().unwrap(), &format!("tell application \"Terminal\" to do script \"{quoted}\""));
            let iterm = build_launch_command("iterm2", &argv, new_tab).unwrap();
            let carrying = iterm.args.iter().filter(|a| a.ends_with(&format!("command \"{quoted}\""))).count();
            assert_eq!(carrying, if new_tab { 2 } else { 1 }, "the new-tab script names the command twice: {:?}", iterm.args);
        }
        assert_eq!(build_launch_command("xfce4-terminal", &argv, false).unwrap().args, vec!["-e".to_string(), quoted.to_string()]);
        for (id, prefix) in [("gnome-terminal", vec!["--"]), ("konsole", vec!["-e"]), ("kitty", vec![]), ("wezterm", vec!["start", "--"])] {
            let spec = build_launch_command(id, &argv, false).unwrap();
            let expected: Vec<String> = prefix.into_iter().map(String::from).chain(argv.iter().cloned()).collect();
            assert_eq!(spec.args, expected, "{id}");
        }
        assert_eq!(build_launch_command("wt", &argv, false).unwrap().args, argv);
    }

    /// A new tab of iTerm2 runs the connect command too, in both branches of its script (a tab in the window there is, or a new window).
    #[test]
    fn a_new_tab_in_iterm2_runs_the_connect_command() {
        // On Windows too: the test binary has no console helper beside it, so the command names the executable itself. iTerm2 ends the
        // window with the command: the command pauses on an error.
        let argv = connect_argv(&std::env::current_exe().unwrap(), "web", true);
        let command = applescript_escape(&shell_join(&argv));
        let spec = launch_for("iterm2", "web", true).unwrap();
        assert_eq!(spec.program, "osascript");
        let script: Vec<&str> = spec.args.iter().skip(1).step_by(2).map(String::as_str).collect();
        assert_eq!(
            script,
            [
                "tell application \"iTerm2\"",
                "activate",
                "if (count of windows) > 0 then",
                &format!("tell current window to create tab with default profile command \"{command}\""),
                "else",
                &format!("create window with default profile command \"{command}\""),
                "end if",
                "end tell",
            ]
        );
        assert!(spec.args.iter().step_by(2).all(|flag| flag == "-e"), "{:?}", spec.args);
    }

    /// The executable's path can hold a quote (a home folder named o'neil): the shell gets it quoted (`'\''`), and AppleScript gets that
    /// with its backslash escaped.
    #[test]
    fn a_path_with_a_quote_reaches_terminal_quoted_for_the_shell_and_escaped_for_applescript() {
        let argv = connect_argv(std::path::Path::new("/Users/o'neil/Apps/Lunport.app/Contents/MacOS/sshelter"), "web", false);
        let spec = build_launch_command("terminal", &argv, false).unwrap();
        assert_eq!(spec.args.last().unwrap(), r#"tell application "Terminal" to do script "'/Users/o'\\''neil/Apps/Lunport.app/Contents/MacOS/sshelter' connect web""#);
    }

    /// Every platform connects through `sshelter connect`, with `--pause-on-error` where a failure would close the window (not in cmd or
    /// Windows Terminal). On Windows the test binary has no console helper beside it, so a debug test build runs the executable itself,
    /// as a debug build of the app does; a release test build says the helper is missing.
    #[test]
    fn the_launch_runs_sshelter_connect_on_every_platform() {
        let exe = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        if cfg!(windows) && cfg!(debug_assertions) {
            assert_eq!(launch_for("cmd", "web", false).unwrap().args, ["/c", "start", "", "cmd", "/k", exe.as_str(), "connect", "web"]);
            assert_eq!(launch_for("wt", "web", true).unwrap().args, ["-w", "0", "nt", exe.as_str(), "connect", "web"]);
        } else if cfg!(windows) {
            assert!(launch_for("cmd", "web", false).unwrap_err().to_string().starts_with("sshelter-cli.exe is missing from "));
        } else {
            assert_eq!(launch_for("kitty", "web", false).unwrap().args, [exe.as_str(), "connect", "--pause-on-error", "web"]);
        }
    }

    /// Spec §7.4: Connect gives `--pause-on-error` to the terminals that close the window when the command ends with an error (the reason
    /// of a connect that fails before the shell opens would go with it), and not to Terminal (`do script` runs it in a shell that stays),
    /// cmd (`cmd /k`) or Windows Terminal (its default keeps a pane whose program failed). An unknown terminal (`$TERMINAL`) is taken to
    /// close.
    #[test]
    fn connect_pauses_on_an_error_where_a_failure_closes_the_window() {
        for id in ["iterm2", "ptyxis", "gnome-terminal", "konsole", "kitty", "alacritty", "wezterm", "foot", "xfce4-terminal", "xterm", "env"] {
            assert!(closes_after_a_failure(id), "{id}");
        }
        for id in ["terminal", "cmd", "wt"] {
            assert!(!closes_after_a_failure(id), "{id}");
        }
        let program = std::path::Path::new("/Applications/Lunport.app/Contents/MacOS/sshelter");
        assert_eq!(connect_argv(program, "web", true), [program.to_str().unwrap(), "connect", "--pause-on-error", "web"]);
        assert_eq!(connect_argv(program, "web", false), [program.to_str().unwrap(), "connect", "web"]);
        if !cfg!(windows) {
            let exe = std::env::current_exe().unwrap().to_string_lossy().into_owned();
            let terminal = launch_for("terminal", "web", false).unwrap();
            assert_eq!(terminal.args.last().unwrap(), &format!("tell application \"Terminal\" to do script \"{}\"", applescript_escape(&shell_join(&[exe.clone(), "connect".into(), "web".into()]))));
            let iterm = launch_for("iterm2", "web", false).unwrap();
            let paused = applescript_escape(&shell_join(&[exe, "connect".into(), "--pause-on-error".into(), "web".into()]));
            assert!(iterm.args.last().unwrap().ends_with(&format!("command \"{paused}\"")), "{:?}", iterm.args);
        }
    }

    /// On Windows the terminal runs the console helper when it is next to Lunport's executable (an installed Lunport), in a release and a
    /// debug build alike: Windows Terminal runs it directly, in a new window or in a new tab of the last one, and cmd starts it in a new
    /// console that stays open after it; the path with a space in it stays one argument.
    #[test]
    fn windows_terminals_run_the_console_helper_next_to_sshelter() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("Program Files").join("Lunport");
        std::fs::create_dir_all(&installed).unwrap();
        let exe = installed.join("sshelter.exe");
        std::fs::write(&exe, b"").unwrap();
        std::fs::write(installed.join("sshelter-cli.exe"), b"").unwrap();
        for debug_build in [false, true] {
            let argv = connect_argv(&connect_program(&exe, debug_build).unwrap(), "web", false);
            assert_eq!(argv, [installed.join("sshelter-cli.exe").to_string_lossy().as_ref(), "connect", "web"], "debug: {debug_build}");
            assert_the_windows_launches_run(&argv);
        }
    }

    /// Without the console helper next to it, a debug build (a console program itself) has the terminal run Lunport's executable.
    #[test]
    fn without_the_console_helper_a_debug_build_runs_sshelter_itself() {
        let dir = tempfile::tempdir().unwrap();
        let built = dir.path().join("my builds").join("debug");
        std::fs::create_dir_all(&built).unwrap();
        let exe = built.join("sshelter.exe");
        std::fs::write(&exe, b"").unwrap();
        // A directory by the helper's name is not the helper.
        std::fs::create_dir(built.join("sshelter-cli.exe")).unwrap();
        let argv = connect_argv(&connect_program(&exe, true).unwrap(), "web", false);
        assert_eq!(argv, [exe.to_string_lossy().as_ref(), "connect", "web"]);
        assert_the_windows_launches_run(&argv);
    }

    /// A release build without the console helper does not hand its sshelter.exe, a GUI program, to a terminal, which would neither wait for
    /// it nor give it a console (spec §7.3): Connect fails with a sentence that names the missing file and where it should be.
    #[test]
    fn without_the_console_helper_a_release_build_says_it_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("Program Files").join("Lunport");
        std::fs::create_dir_all(&installed).unwrap();
        let exe = installed.join("sshelter.exe");
        std::fs::write(&exe, b"").unwrap();
        let error = connect_program(&exe, false).unwrap_err();
        assert_eq!(error.to_string(), format!("sshelter-cli.exe is missing from {}. Reinstall Lunport.", installed.display()));
    }

    /// Both Windows terminals run `argv` as it is: `wt.exe <argv>`, `wt.exe -w 0 nt <argv>` for a new tab, and `cmd /c start "" cmd /k
    /// <argv>` (cmd has no tabs).
    fn assert_the_windows_launches_run(argv: &[String]) {
        let with = |prefix: &[&str]| -> Vec<String> { prefix.iter().map(|s| s.to_string()).chain(argv.iter().cloned()).collect() };
        assert_eq!(build_launch_command("wt", argv, false).unwrap(), LaunchSpec { program: "wt.exe".into(), args: argv.to_vec() });
        assert_eq!(build_launch_command("wt", argv, true).unwrap(), LaunchSpec { program: "wt.exe".into(), args: with(&["-w", "0", "nt"]) });
        let cmd = LaunchSpec { program: "cmd".into(), args: with(&["/c", "start", "", "cmd", "/k"]) };
        for new_tab in [false, true] {
            assert_eq!(build_launch_command("cmd", argv, new_tab).unwrap(), cmd, "new_tab: {new_tab}");
        }
    }

    #[test]
    fn windows_terminal_spec_execs_argv_directly() {
        let spec = build_launch("wt", "web", false).unwrap();
        assert_eq!(spec.program, "wt.exe");
        assert_eq!(spec.args, vec!["ssh", "web"]);
        let tab = build_launch("wt", "web", true).unwrap();
        assert_eq!(tab.args, vec!["-w", "0", "nt", "ssh", "web"]);
    }

    #[test]
    fn cmd_spec_keeps_the_console_open_after_ssh_exits() {
        let spec = build_launch("cmd", "web", false).unwrap();
        assert_eq!(spec.program, "cmd");
        assert_eq!(spec.args, vec!["/c", "start", "", "cmd", "/k", "ssh", "web"]);
    }

    fn doc_with(content: &str) -> SshConfigDoc {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, content).unwrap();
        let doc = load_doc(&path).unwrap();
        // Keep the tempdir alive for the duration by leaking it; tests are short-lived.
        std::mem::forget(dir);
        doc
    }

    #[test]
    fn validate_alias_accepts_known_alias() {
        let doc = doc_with("Host web\n    User x\n");
        assert!(validate_alias(&doc, "web").is_ok());
    }

    #[test]
    fn validate_alias_rejects_bad_charset() {
        let doc = doc_with("Host web\n    User x\n");
        let err = validate_alias(&doc, "we b").unwrap_err();
        assert!(matches!(err, AppError::ForbiddenPath(_)), "got {err:?}");
        let err2 = validate_alias(&doc, "we;b").unwrap_err();
        assert!(matches!(err2, AppError::ForbiddenPath(_)), "got {err2:?}");
        let err3 = validate_alias(&doc, "").unwrap_err();
        assert!(matches!(err3, AppError::ForbiddenPath(_)), "got {err3:?}");
    }

    #[test]
    fn validate_alias_rejects_absent_alias() {
        let doc = doc_with("Host web\n    User x\n");
        let err = validate_alias(&doc, "db").unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn validate_alias_rejects_leading_dash_argument_injection() {
        // A malicious/synced config can contain `Host -Fevil`; that pattern passes presence-in-doc,
        // so the charset gate MUST reject the leading dash to prevent `ssh -Fevil` (config-file →
        // ProxyCommand RCE). Also -D8080 / -E forms.
        let doc = doc_with("Host -Fevil\nHost -D8080\n");
        for bad in ["-Fevil", "-D8080", "-G", "-v"] {
            let err = validate_alias(&doc, bad).unwrap_err();
            assert!(
                matches!(err, AppError::ForbiddenPath(_)),
                "leading-dash alias {bad:?} must be rejected on charset, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_alias_accepts_dotted_and_at() {
        let doc = doc_with("Host foo.example.com\n    User x\n");
        assert!(validate_alias(&doc, "foo.example.com").is_ok());
    }

    #[test]
    fn build_launch_macos_terminal() {
        let spec = build_launch("terminal", "web", false).unwrap();
        assert_eq!(spec.program, "osascript");
        assert_eq!(
            spec.args,
            vec![
                "-e".to_string(),
                "tell application \"Terminal\" to activate".to_string(),
                "-e".to_string(),
                "tell application \"Terminal\" to do script \"ssh web\"".to_string(),
            ]
        );
    }

    #[test]
    fn build_launch_macos_terminal_escapes_quotes() {
        // Hypothetical quote/backslash in alias (charset-impossible post-validation, defense in
        // depth): the arg is single-quoted for the SHELL first, then the resulting command string
        // is escaped for the AppleScript literal. Inner shell: `ssh 'a"b\c'`.
        let spec = build_launch("terminal", "a\"b\\c", false).unwrap();
        let last = spec.args.last().unwrap();
        assert_eq!(
            last,
            "tell application \"Terminal\" to do script \"ssh 'a\\\"b\\\\c'\""
        );
    }

    // ── shell quoting helper ──────────────────────────────────────────────────

    #[test]
    fn shell_quote_leaves_safe_args_bare() {
        for s in ["web", "ssh", "/Users/frank/.ssh/id_ed25519.pub", "user@host", "a.b-c_d"] {
            assert_eq!(shell_quote(s), s, "{s:?} must stay bare");
        }
    }

    #[test]
    fn shell_quote_quotes_space_quote_and_dollar() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("a\"b"), "'a\"b'");
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
        assert_eq!(shell_quote(";rm -rf x"), "';rm -rf x'");
        assert_eq!(shell_quote(""), "''");
        // `~` is unsafe bare (tilde expansion).
        assert_eq!(shell_quote("~"), "'~'");
    }

    #[test]
    fn shell_join_quotes_each_arg() {
        let argv: Vec<String> = vec!["ssh-keygen".into(), "-C".into(), "work laptop".into()];
        assert_eq!(shell_join(&argv), "ssh-keygen -C 'work laptop'");
    }

    // ── generalized launcher ──────────────────────────────────────────────────

    #[test]
    fn build_launch_command_macos_terminal_arbitrary_argv() {
        let argv: Vec<String> = vec![
            "ssh-copy-id".into(),
            "-i".into(),
            "/Users/frank/.ssh/id_ed25519.pub".into(),
            "web".into(),
        ];
        let spec = build_launch_command("terminal", &argv, false).unwrap();
        assert_eq!(spec.program, "osascript");
        assert_eq!(
            spec.args.last().unwrap(),
            "tell application \"Terminal\" to do script \"ssh-copy-id -i /Users/frank/.ssh/id_ed25519.pub web\""
        );
    }

    #[test]
    fn build_launch_command_macos_quotes_args_with_spaces() {
        let argv: Vec<String> = vec![
            "ssh-keygen".into(),
            "-f".into(),
            "/Users/My Name/.ssh/key".into(),
            "-C".into(),
            "a \"quoted\" comment".into(),
        ];
        let spec = build_launch_command("iterm2", &argv, false).unwrap();
        // Shell-quoted first, AppleScript-escaped second.
        assert_eq!(
            spec.args.last().unwrap(),
            "tell application \"iTerm2\" to create window with default profile command \"ssh-keygen -f '/Users/My Name/.ssh/key' -C 'a \\\"quoted\\\" comment'\""
        );
    }

    #[test]
    fn build_launch_command_linux_passes_argv_directly() {
        let argv: Vec<String> = vec!["ssh-copy-id".into(), "-i".into(), "/h/.ssh/k.pub".into(), "web".into()];
        let spec = build_launch_command("gnome-terminal", &argv, false).unwrap();
        assert_eq!(spec.args, vec!["--", "ssh-copy-id", "-i", "/h/.ssh/k.pub", "web"]);
        // Args with spaces stay single argv elements — NO shell parses them.
        let argv2: Vec<String> = vec!["ssh-keygen".into(), "-C".into(), "two words".into()];
        let spec2 = build_launch_command("konsole", &argv2, false).unwrap();
        assert_eq!(spec2.args, vec!["-e", "ssh-keygen", "-C", "two words"]);
        // xfce4-terminal's single-string -e gets shell quoting.
        let spec3 = build_launch_command("xfce4-terminal", &argv2, false).unwrap();
        assert_eq!(spec3.args, vec!["-e".to_string(), "ssh-keygen -C 'two words'".to_string()]);
    }

    #[test]
    fn build_launch_command_rejects_empty_argv() {
        let err = build_launch_command("terminal", &[], false).unwrap_err();
        assert!(matches!(err, AppError::Other(_)), "got {err:?}");
    }

    #[test]
    fn build_launch_macos_iterm2() {
        let spec = build_launch("iterm2", "web", false).unwrap();
        assert_eq!(spec.program, "osascript");
        assert_eq!(
            spec.args,
            vec![
                "-e".to_string(),
                "tell application \"iTerm2\" to activate".to_string(),
                "-e".to_string(),
                "tell application \"iTerm2\" to create window with default profile command \"ssh web\""
                    .to_string(),
            ]
        );
    }

    #[test]
    fn build_launch_linux_gnome_terminal() {
        let spec = build_launch("gnome-terminal", "web", false).unwrap();
        assert_eq!(spec.program, "gnome-terminal");
        assert_eq!(spec.args, vec!["--", "ssh", "web"]);
    }

    #[test]
    fn build_launch_linux_konsole() {
        let spec = build_launch("konsole", "web", false).unwrap();
        assert_eq!(spec.program, "konsole");
        assert_eq!(spec.args, vec!["-e", "ssh", "web"]);
    }

    #[test]
    fn build_launch_linux_kitty() {
        let spec = build_launch("kitty", "web", false).unwrap();
        assert_eq!(spec.program, "kitty");
        assert_eq!(spec.args, vec!["ssh", "web"]);
    }

    #[test]
    fn build_launch_linux_wezterm() {
        let spec = build_launch("wezterm", "web", false).unwrap();
        assert_eq!(spec.program, "wezterm");
        assert_eq!(spec.args, vec!["start", "--", "ssh", "web"]);
    }

    #[test]
    fn build_launch_linux_xfce4() {
        let spec = build_launch("xfce4-terminal", "web", false).unwrap();
        assert_eq!(spec.program, "xfce4-terminal");
        assert_eq!(spec.args, vec!["-e".to_string(), "ssh web".to_string()]);
    }

    #[test]
    fn build_launch_linux_xterm() {
        let spec = build_launch("xterm", "web", false).unwrap();
        assert_eq!(spec.program, "xterm");
        assert_eq!(spec.args, vec!["-e", "ssh", "web"]);
    }

    #[test]
    fn build_launch_macos_iterm2_new_tab() {
        let spec = build_launch("iterm2", "web", true).unwrap();
        assert_eq!(spec.program, "osascript");
        assert_eq!(
            spec.args,
            vec![
                "-e".to_string(),
                "tell application \"iTerm2\"".to_string(),
                "-e".to_string(),
                "activate".to_string(),
                "-e".to_string(),
                "if (count of windows) > 0 then".to_string(),
                "-e".to_string(),
                "tell current window to create tab with default profile command \"ssh web\""
                    .to_string(),
                "-e".to_string(),
                "else".to_string(),
                "-e".to_string(),
                "create window with default profile command \"ssh web\"".to_string(),
                "-e".to_string(),
                "end if".to_string(),
                "-e".to_string(),
                "end tell".to_string(),
            ]
        );
    }

    #[test]
    fn build_launch_new_tab_is_noop_for_other_terminals() {
        // Only iTerm2 honors new_tab; everything else launches a new window either way.
        assert_eq!(
            build_launch("terminal", "web", true).unwrap(),
            build_launch("terminal", "web", false).unwrap()
        );
        assert_eq!(
            build_launch("gnome-terminal", "web", true).unwrap(),
            build_launch("gnome-terminal", "web", false).unwrap()
        );
    }

    /// The terminals that open a new tab: iTerm2 on macOS and Windows Terminal on Windows. Terminal.app (no GUI scripting), cmd, $TERMINAL
    /// and every Linux emulator open a new window. Holds whichever terminals the machine has (a Windows runner may have no wt.exe).
    #[test]
    fn detect_terminals_supports_new_tab_flags() {
        let terminals = detect_terminals();
        for t in &terminals {
            let tabs = (cfg!(target_os = "macos") && t.id == "iterm2") || (cfg!(windows) && t.id == "wt");
            assert_eq!(t.supports_new_tab, tabs, "{} says supports_new_tab = {}", t.id, t.supports_new_tab);
        }
        if cfg!(windows) {
            // cmd is always there, last.
            assert_eq!(terminals.last().map(|t| t.id.as_str()), Some("cmd"), "{terminals:?}");
        }
    }

    #[test]
    fn build_launch_unknown_id_errors() {
        let err = build_launch("nope-term", "web", false).unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
