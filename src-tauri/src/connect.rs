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
    /// Only iTerm2 qualifies: Terminal.app's only new-tab path is System Events GUI scripting,
    /// which requires the user to grant Accessibility permission — explicitly NOT doing that.
    /// All Linux emulators are launched as new windows, so they are `false` as well.
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
/// or, when `new_tab` is true and the terminal supports it (only iTerm2), a new TAB of the
/// current window (falling back to a new window when none exists).
/// PURE function. The alias is assumed pre-validated; thin wrapper over `build_launch_command`.
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
            // after ssh exits, matching the mac/linux terminal behavior. The
            // empty "" is start's window-title slot.
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

/// Spawn the launch spec detached, inheriting the environment. Not unit-tested (side effect).
pub fn launch(spec: &LaunchSpec) -> Result<(), AppError> {
    std::process::Command::new(&spec.program)
        .args(&spec.args)
        .spawn()
        .map_err(AppError::Io)?;
    Ok(())
}

// ─── Tauri commands ─────────────────────────────────────────────────────────

#[tauri::command]
pub fn connect_list_terminals() -> Vec<TerminalInfo> {
    detect_terminals()
}

#[tauri::command]
pub fn connect_launch(
    state: tauri::State<crate::state::AppState>,
    alias: String,
    terminal_override: Option<String>,
    new_tab: Option<bool>,
) -> Result<(), AppError> {
    let doc_lock = state.doc.lock().unwrap();
    let doc = doc_lock
        .as_ref()
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;

    validate_alias(doc, &alias)?;

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

    let spec = build_launch(&terminal_id, &alias, new_tab.unwrap_or(false))?;
    launch(&spec)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;

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

    #[test]
    fn detect_terminals_supports_new_tab_flags() {
        let terminals = detect_terminals();
        for t in &terminals {
            if t.id == "iterm2" {
                assert!(t.supports_new_tab, "iTerm2 must support new tabs");
            } else {
                // Terminal.app (no GUI-scripting), $TERMINAL, and all Linux emulators: false.
                assert!(!t.supports_new_tab, "{} must not claim new-tab support", t.id);
            }
        }
    }

    #[test]
    fn build_launch_unknown_id_errors() {
        let err = build_launch("nope-term", "web", false).unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
