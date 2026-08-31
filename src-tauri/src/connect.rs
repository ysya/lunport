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

// ─── Password auto-fill (saved keychain password → askpass injection) ────────

/// ssh argv (no program) for a password auto-fill connect. Mirrors the deploy
/// argv's safety options but stays interactive: no `-T` (the session needs a
/// pty), no pinned StrictHostKeyChecking (the caller pre-checks known_hosts),
/// and no PreferredAuthentications so an existing working key still wins.
pub fn autofill_ssh_argv(alias: &str) -> Vec<String> {
    vec![
        // A global `BatchMode yes` would silently disable password prompts.
        "-o".to_string(), "BatchMode=no".to_string(),
        // One wrong saved password must not burn three attempts against
        // fail2ban-style lockouts.
        "-o".to_string(), "NumberOfPasswordPrompts=1".to_string(),
        // Same anti-phishing model as deploy (see `deploy::build_deploy_argv`):
        // with kbdint off, every prompt the helper sees is client-generated;
        // server-controlled text never reaches it. Cost: kbdint-only hosts
        // (PAM 2FA) are not eligible for auto-fill — don't save a password there.
        "-o".to_string(), "KbdInteractiveAuthentication=no".to_string(),
        alias.to_string(),
    ]
}

/// Wrap `argv` with env(1) assignments: `env K=V … <argv…>`. env scopes the
/// variables to the ssh process only — nothing lingers in the shell session —
/// and unlike `VAR=x cmd` prefixes it also works when the user's shell is fish.
pub fn env_wrapped_argv(env_pairs: &[(String, String)], argv: &[String]) -> Vec<String> {
    std::iter::once("env".to_string())
        .chain(env_pairs.iter().map(|(k, v)| format!("{k}={v}")))
        .chain(argv.iter().cloned())
        .collect()
}

/// One `cmd /k` command string: set the variables, run the command, then CLEAR
/// the variables. The clearing tail is load-bearing: `/k` keeps the console
/// session alive after ssh exits, and a leftover SSH_ASKPASS +
/// SSHELTER_ASKPASS_ACCOUNT would make a later manual `ssh otherhost` in that
/// window consult our helper — which would answer with THIS host's password
/// (cross-host disclosure). `&` (not `&&`) so the clears run even when ssh
/// fails. `set "K=V"` keeps spaces in values (the install path) intact.
fn windows_autofill_cmd_string(env_pairs: &[(String, String)], command_argv: &[String]) -> String {
    let sets: Vec<String> = env_pairs
        .iter()
        .map(|(k, v)| format!("set \"{k}={v}\""))
        .collect();
    let clears: Vec<String> = env_pairs
        .iter()
        .map(|(k, _)| format!("& set \"{k}=\""))
        .collect();
    format!(
        "{} && {} {}",
        sets.join(" && "),
        command_argv.join(" "),
        clears.join(" ")
    )
}

/// Build the terminal launch for a password auto-fill connect.
///
/// POSIX terminals run `env K=V … ssh …` (per-process scope; every argv element
/// still goes through the existing quoting paths). Windows terminals cannot
/// take env assignments as argv, so both wt and cmd run one `cmd /k` string
/// that sets the variables, runs ssh, and clears them again — deterministic
/// even when Windows Terminal gloms the tab onto an existing window process
/// that never inherited our environment.
pub fn build_autofill_launch(
    terminal_id: &str,
    alias: &str,
    new_tab: bool,
    env_pairs: &[(String, String)],
) -> Result<LaunchSpec, AppError> {
    let ssh_argv: Vec<String> = std::iter::once("ssh".to_string())
        .chain(autofill_ssh_argv(alias))
        .collect();
    match terminal_id {
        "wt" => {
            let mut args: Vec<String> = if new_tab {
                vec!["-w".into(), "0".into(), "nt".into()]
            } else {
                Vec::new()
            };
            args.extend([
                "cmd".to_string(),
                "/k".to_string(),
                windows_autofill_cmd_string(env_pairs, &ssh_argv),
            ]);
            Ok(LaunchSpec { program: "wt.exe".into(), args })
        }
        "cmd" => Ok(LaunchSpec {
            program: "cmd".into(),
            args: vec![
                "/c".into(),
                "start".into(),
                String::new(),
                "cmd".into(),
                "/k".into(),
                windows_autofill_cmd_string(env_pairs, &ssh_argv),
            ],
        }),
        other => build_launch_command(other, &env_wrapped_argv(env_pairs, &ssh_argv), new_tab),
    }
}

/// Decide whether THIS connect can auto-fill the saved password, and build the
/// askpass environment if so. Every gate falls back to a plain launch (`None`)
/// — auto-fill is a convenience and must never make Connect stop working. The
/// password itself NEVER appears in the launch command; the helper reads it
/// from the keychain via SSHELTER_ASKPASS_ACCOUNT.
///
/// Gates, in order (all mirror in-app deploy's reasoning):
/// 1. a non-empty saved password exists in the OS keychain,
/// 2. the loaded config root is the default `~/.ssh/config` — the terminal runs
///    plain `ssh <alias>`, so reasoning based on any other file would be about
///    a config ssh will not read,
/// 3. the local ssh can force askpass while holding a tty
///    (`deploy::openssh_supports_forced_askpass_in_terminal`),
/// 4. the alias is not behind ProxyJump/ProxyCommand — the jump host's password
///    prompt is a perfectly legal shape and would be answered with the TARGET
///    host's password,
/// 5. the host key is already in known_hosts: SSH_ASKPASS_REQUIRE=force routes
///    the host-key confirmation to the helper too, which refuses it (multiline
///    whitelist rule), so a first-time host would abort instead of asking — let
///    a plain launch handle that first connection interactively.
fn password_autofill_env(
    state: &tauri::State<crate::state::AppState>,
    alias: &str,
) -> Option<Vec<(String, String)>> {
    let account = crate::secrets::host_account(alias);
    match crate::secrets::get(&account) {
        Ok(Some(secret)) if !secret.is_empty() => {}
        _ => return None,
    }
    if !crate::deploy::is_default_config_root(state) {
        return None;
    }
    if !crate::deploy::openssh_supports_forced_askpass_in_terminal(
        &crate::deploy::local_ssh_version(),
    ) {
        return None;
    }
    let pairs = crate::config::intel::effective_config(alias, None).ok()?;
    if crate::deploy::has_proxy(&pairs) {
        return None;
    }
    let ep = crate::deploy::endpoint_from_effective(&pairs)?;
    let known = crate::process::background_command("ssh-keygen")
        .args(crate::deploy::keygen_find_args(&ep))
        .output()
        .ok()?;
    if String::from_utf8_lossy(&known.stdout).trim().is_empty() {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    Some(vec![
        ("SSHELTER_ASKPASS".to_string(), "1".to_string()),
        ("SSHELTER_ASKPASS_ACCOUNT".to_string(), account),
        ("SSH_ASKPASS".to_string(), exe.to_string_lossy().into_owned()),
        ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
    ])
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

// (async): the auto-fill prechecks spawn `ssh -V`, `ssh -G`, and
// `ssh-keygen -F` — that must not run on the main thread.
#[tauri::command(async)]
pub fn connect_launch(
    state: tauri::State<crate::state::AppState>,
    alias: String,
    terminal_override: Option<String>,
    new_tab: Option<bool>,
) -> Result<(), AppError> {
    // Scoped: `password_autofill_env` takes the same lock again (via
    // `is_default_config_root`); holding it across that call would deadlock.
    {
        let doc_lock = state.doc.lock().unwrap();
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

    let new_tab = new_tab.unwrap_or(false);
    let spec = match password_autofill_env(&state, &alias) {
        Some(env_pairs) => build_autofill_launch(&terminal_id, &alias, new_tab, &env_pairs)?,
        None => build_launch(&terminal_id, &alias, new_tab)?,
    };
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

    // ── password auto-fill launch ─────────────────────────────────────────────

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn autofill_ssh_argv_limits_password_attempts_and_disables_kbdint() {
        let argv = autofill_ssh_argv("web");
        // One wrong saved password must not burn three attempts against
        // fail2ban-style lockouts.
        assert!(argv.windows(2).any(|w| w == ["-o", "NumberOfPasswordPrompts=1"]));
        // Same anti-phishing model as deploy: with kbdint off, every prompt the
        // helper sees is client-generated; server-controlled text never reaches it.
        assert!(argv.windows(2).any(|w| w == ["-o", "KbdInteractiveAuthentication=no"]));
        // A global `BatchMode yes` would silently disable password auth.
        assert!(argv.windows(2).any(|w| w == ["-o", "BatchMode=no"]));
        assert_eq!(argv.last().unwrap(), "web", "alias must come last");
    }

    #[test]
    fn autofill_ssh_argv_keeps_the_session_interactive() {
        // This launches a real terminal session: -T (no pty) would break the
        // interactive shell, and pinning StrictHostKeyChecking/PreferredAuthentications
        // is the precheck's job — an existing working key must still win.
        let argv = autofill_ssh_argv("web");
        assert!(!argv.iter().any(|a| a == "-T"));
        assert!(!argv.iter().any(|a| a.starts_with("StrictHostKeyChecking")));
        assert!(!argv.iter().any(|a| a.starts_with("PreferredAuthentications")));
    }

    #[test]
    fn env_wrapped_argv_prefixes_env_program() {
        // env(1) scopes the variables to the ssh process only — unlike shell
        // `VAR=x` prefixes it also works when the user's shell is fish.
        let env = pairs(&[("SSHELTER_ASKPASS", "1"), ("SSH_ASKPASS", "/a/b")]);
        let argv: Vec<String> = vec!["ssh".into(), "web".into()];
        assert_eq!(
            env_wrapped_argv(&env, &argv),
            vec!["env", "SSHELTER_ASKPASS=1", "SSH_ASKPASS=/a/b", "ssh", "web"]
        );
    }

    #[test]
    fn build_autofill_launch_macos_terminal_wraps_with_env() {
        let env = pairs(&[
            ("SSHELTER_ASKPASS", "1"),
            ("SSH_ASKPASS", "/Applications/My SSHelter.app/sshelter"),
        ]);
        let spec = build_autofill_launch("terminal", "web", false, &env).unwrap();
        assert_eq!(spec.program, "osascript");
        // Shell-quoted first (space in the app path), AppleScript-escaped second.
        assert_eq!(
            spec.args.last().unwrap(),
            "tell application \"Terminal\" to do script \"env SSHELTER_ASKPASS=1 \
             'SSH_ASKPASS=/Applications/My SSHelter.app/sshelter' ssh -o BatchMode=no \
             -o NumberOfPasswordPrompts=1 -o KbdInteractiveAuthentication=no web\""
        );
    }

    #[test]
    fn build_autofill_launch_linux_passes_env_argv_directly() {
        let env = pairs(&[("SSH_ASKPASS", "/usr/bin/sshelter")]);
        let spec = build_autofill_launch("gnome-terminal", "web", false, &env).unwrap();
        assert_eq!(spec.program, "gnome-terminal");
        assert_eq!(
            spec.args,
            vec![
                "--",
                "env",
                "SSH_ASKPASS=/usr/bin/sshelter",
                "ssh",
                "-o",
                "BatchMode=no",
                "-o",
                "NumberOfPasswordPrompts=1",
                "-o",
                "KbdInteractiveAuthentication=no",
                "web"
            ]
        );
    }

    #[test]
    fn build_autofill_launch_windows_wt_sets_runs_then_clears() {
        let env = pairs(&[
            ("SSHELTER_ASKPASS", "1"),
            ("SSH_ASKPASS", r"C:\Program Files\SSHelter\sshelter.exe"),
        ]);
        let spec = build_autofill_launch("wt", "web", false, &env).unwrap();
        assert_eq!(spec.program, "wt.exe");
        assert_eq!(spec.args[..2], ["cmd".to_string(), "/k".to_string()]);
        // `set "K=V"` quotes the value (the install path contains a space); the
        // trailing `& set "K="` clears the variables from the surviving /k session
        // so a later manual `ssh otherhost` in that window cannot reach our helper
        // and be answered with THIS host's password.
        assert_eq!(
            spec.args[2],
            "set \"SSHELTER_ASKPASS=1\" && \
             set \"SSH_ASKPASS=C:\\Program Files\\SSHelter\\sshelter.exe\" && \
             ssh -o BatchMode=no -o NumberOfPasswordPrompts=1 \
             -o KbdInteractiveAuthentication=no web \
             & set \"SSHELTER_ASKPASS=\" & set \"SSH_ASKPASS=\""
        );

        // new_tab keeps the existing `-w 0 nt` targeting.
        let tab = build_autofill_launch("wt", "web", true, &env).unwrap();
        assert_eq!(tab.args[..5], ["-w", "0", "nt", "cmd", "/k"].map(String::from));
    }

    #[test]
    fn build_autofill_launch_windows_cmd_sets_runs_then_clears() {
        let env = pairs(&[("SSHELTER_ASKPASS", "1")]);
        let spec = build_autofill_launch("cmd", "web", false, &env).unwrap();
        assert_eq!(spec.program, "cmd");
        assert_eq!(
            spec.args,
            vec![
                "/c".to_string(),
                "start".to_string(),
                String::new(),
                "cmd".to_string(),
                "/k".to_string(),
                "set \"SSHELTER_ASKPASS=1\" && ssh -o BatchMode=no \
                 -o NumberOfPasswordPrompts=1 -o KbdInteractiveAuthentication=no web \
                 & set \"SSHELTER_ASKPASS=\""
                    .to_string(),
            ]
        );
    }

    #[test]
    fn build_autofill_launch_xfce4_uses_single_shell_string() {
        let env = pairs(&[("SSH_ASKPASS", "/opt/s h/sshelter")]);
        let spec = build_autofill_launch("xfce4-terminal", "web", false, &env).unwrap();
        assert_eq!(
            spec.args,
            vec![
                "-e".to_string(),
                "env 'SSH_ASKPASS=/opt/s h/sshelter' ssh -o BatchMode=no \
                 -o NumberOfPasswordPrompts=1 -o KbdInteractiveAuthentication=no web"
                    .to_string(),
            ]
        );
    }
}
