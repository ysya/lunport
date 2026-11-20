//! Discovery and selection on the already authenticated terminal connection.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use super::connect::CancelToken;
use super::protocol::{ServerMessage, TmuxSession, TmuxTarget};
use super::relay::{tell, ClientLink};
use crate::connect::shell_quote;
use crate::ssh::{Ended, ExecResult, Session};

const LIST_FORMAT: &str =
    "#{session_id}\t#{session_created}\t#{pid}:#{start_time}\t#{destroy-unattached}\t#{session_name}";
const LIST_TIMEOUT: Duration = Duration::from_secs(10);
const LIST_LIMIT: usize = 64 * 1024;
const STALE: &str = "The selected tmux session changed or ended. Reopen the session picker.";

pub(super) fn select(
    session: &dyn Session,
    link: &dyn ClientLink,
    cancel: &CancelToken,
    selection: Receiver<TmuxTarget>,
) -> Result<Option<String>, String> {
    if cancel.is_cancelled() {
        return Ok(None);
    }
    let command = tmux_shell_command(&format!(
        "LC_ALL=C exec tmux -u list-sessions -F {}",
        shell_quote(LIST_FORMAT)
    ));
    let result = session
        .exec(&command, LIST_TIMEOUT, LIST_LIMIT)
        .map_err(|error| format!("Could not list remote tmux sessions. {error}"))?;
    let sessions = sessions_from_output(result)?;
    if cancel.is_cancelled()
        || tell(
            link,
            ServerMessage::TmuxSessions {
                sessions: sessions.clone(),
            },
        )
        .is_err()
    {
        return Ok(None);
    }
    loop {
        if cancel.is_cancelled() {
            return Ok(None);
        }
        if !session.is_alive() {
            return Err(
                "The SSH connection ended while waiting for a tmux session selection.".into(),
            );
        }
        match selection.recv_timeout(Duration::from_millis(100)) {
            Ok(target) if !cancel.is_cancelled() => {
                return control_command(target, &sessions).map(Some);
            }
            Ok(_) => return Ok(None),
            Err(RecvTimeoutError::Disconnected) => return Ok(None),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

fn tmux_shell_command(command: &str) -> String {
    // A macOS SSH exec request can have a shorter PATH than the user's interactive shell.
    const HOMEBREW_LOOKUP: &str = r#"if ! command -v tmux >/dev/null 2>&1; then
    export PATH="${PATH:+$PATH:}/opt/homebrew/bin:/usr/local/bin"
fi"#;
    format!("/bin/sh -c {}", shell_quote(&format!("{HOMEBREW_LOOKUP}\n{command}")))
}

fn sessions_from_output(result: ExecResult) -> Result<Vec<TmuxSession>, String> {
    let stderr = String::from_utf8_lossy(&result.stderr);
    match (result.ended, result.exit_code) {
        (Ended::Exited, Some(0)) => {}
        (Ended::Exited, Some(1))
            if result.stdout.is_empty()
                && stderr.lines().any(|line| {
                    line.starts_with("no server running on ")
                        || (line.starts_with("error connecting to ")
                            && line.ends_with(" (No such file or directory)"))
                }) =>
        {
            return Ok(Vec::new());
        }
        (Ended::Exited, Some(127)) => {
            return Err("Lunport could not find tmux on the remote SSH PATH. Install tmux or add it to the SSH login's PATH.".into());
        }
        (Ended::TimedOut, _) => return Err("Listing remote tmux sessions timed out.".into()),
        (Ended::Truncated, _) => {
            return Err("The remote tmux session list exceeded the output limit.".into())
        }
        _ if !stderr.trim().is_empty() => {
            return Err(format!(
                "Could not list remote tmux sessions. {}",
                stderr.trim()
            ));
        }
        _ => return Err("Could not list remote tmux sessions.".into()),
    }
    let malformed = || {
        "The remote tmux session list was invalid. Check whether the SSH startup scripts print to stdout.".to_string()
    };
    let output = std::str::from_utf8(&result.stdout).map_err(|_| malformed())?;
    output
        .lines()
        .map(|line| {
            let mut fields = line.splitn(5, '\t');
            let (Some(id), Some(created), Some(server), Some(destroy), Some(name)) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            ) else {
                return Err(malformed());
            };
            if !valid_identity(id, created, server) || name.is_empty() {
                return Err(malformed());
            }
            Ok(TmuxSession {
                id: id.into(),
                name: name.into(),
                created: created.into(),
                server: server.into(),
                destroy_unattached: !matches!(destroy, "" | "0" | "off" | "false"),
            })
        })
        .collect()
}

fn valid_identity(id: &str, created: &str, server: &str) -> bool {
    fn decimal(value: &str, max_len: usize) -> bool {
        !value.is_empty()
            && value.len() <= max_len
            && value.bytes().all(|byte| byte.is_ascii_digit())
    }
    id.strip_prefix('$')
        .is_some_and(|number| decimal(number, 10))
        && decimal(created, 20)
        && server
            .split_once(':')
            .is_some_and(|(pid, start)| decimal(pid, 10) && decimal(start, 20))
}

fn control_command(target: TmuxTarget, sessions: &[TmuxSession]) -> Result<String, String> {
    let arguments = match target {
        TmuxTarget::Attach {
            id,
            created,
            server,
        } => {
            if !valid_identity(&id, &created, &server)
                || !sessions.iter().any(|session| {
                    session.id == id && session.created == created && session.server == server
                })
            {
                return Err(STALE.into());
            }
            // The condition and attach are processed by the same tmux server. IDs are
            // unique within that server's lifetime, even if a session is renamed.
            let condition = format!(
                "#{{==:#{{session_id}}:#{{session_created}}:#{{pid}}:#{{start_time}},{id}:{created}:{server}}}"
            );
            let attach = format!("attach-session -t \"{id}\"");
            let stale = format!("display-message -p \"{STALE}\"");
            format!(
                "if-shell -F -t {} {} {} {}",
                shell_quote(&format!("{id}:")),
                shell_quote(&condition),
                shell_quote(&attach),
                shell_quote(&stale),
            )
        }
        TmuxTarget::Create { name } => {
            if name.is_empty()
                || name.len() > 128
                || name.trim() != name
                || name.chars().any(char::is_control)
                || name.contains('\\')
                || name.ends_with(';')
            {
                return Err("Use a tmux session name of 1–128 UTF-8 bytes without outer whitespace, control characters, backslashes or a trailing semicolon.".into());
            }
            // tmux expands formats in -s itself, after the login shell has unquoted it.
            format!("new-session -s {}", shell_quote(&name.replace('#', "##")))
        }
    };
    Ok(tmux_shell_command(&format!("exec tmux -u -C {arguments}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(code: u32, stdout: &[u8], stderr: &[u8]) -> ExecResult {
        ExecResult {
            ended: Ended::Exited,
            exit_code: Some(code),
            signal: None,
            stdout: stdout.into(),
            stderr: stderr.into(),
            truncated: false,
        }
    }

    #[test]
    fn no_tmux_server_is_empty_but_missing_tmux_and_denied_sockets_are_errors() {
        for stderr in [
            b"no server running on /tmp/tmux-1000/default\n".as_slice(),
            b"error connecting to /tmp/tmux-1000/default (No such file or directory)\n",
        ] {
            assert!(sessions_from_output(listed(1, b"", stderr))
                .unwrap()
                .is_empty());
        }
        assert!(sessions_from_output(listed(127, b"", b"tmux: not found\n"))
            .unwrap_err()
            .contains("Install tmux"));
        assert!(sessions_from_output(listed(
            1,
            b"",
            b"error connecting to /tmp/tmux-1000/default (Permission denied)\n"
        ))
        .is_err());
    }

    #[test]
    fn listing_preserves_names_and_selection_rejects_a_reused_id() {
        let sessions = sessions_from_output(listed(
            0,
            "$0\t123\t45:120\tkeep-last\twork '計畫'\n$1\t123\t45:120\t0\tweb-1\n".as_bytes(),
            b"",
        ))
        .unwrap();
        assert_eq!(sessions[0].name, "work '計畫'");
        assert!(sessions[0].destroy_unattached);
        assert!(!sessions[1].destroy_unattached);
        let reused = TmuxTarget::Attach {
            id: "$0".into(),
            created: "123".into(),
            server: "88:123".into(),
        };
        assert_eq!(control_command(reused, &sessions), Err(STALE.into()));
    }

    #[test]
    fn create_rejects_names_tmux_would_reinterpret_as_commands() {
        for name in ["", " leading", "line\nline", "trailing;", "back\\slash"] {
            assert!(control_command(TmuxTarget::Create { name: name.into() }, &[]).is_err());
        }
    }
}
