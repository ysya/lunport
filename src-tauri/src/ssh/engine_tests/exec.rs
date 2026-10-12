//! `Session::exec`: a command without a PTY, its output, how it ended, and what happens when it does not end by itself.

use std::path::Path;
use std::time::{Duration, Instant};

use super::{engine, open_session, open_session_to};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthMethod, Ended, Session, SessionError, Target};

const MIB: usize = 1024 * 1024;
const ENOUGH: Duration = Duration::from_secs(20);

#[test]
fn exec_returns_stdout_stderr_and_the_exit_code() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("printf out; printf err >&2; exit 7", ENOUGH, MIB).unwrap();
    assert_eq!((result.ended, result.exit_code, result.signal.as_deref()), (Ended::Exited, Some(7), None));
    assert_eq!((result.stdout.as_slice(), result.stderr.as_slice()), (b"out".as_slice(), b"err".as_slice()));
    assert!(!result.truncated);
}

/// The command has no terminal, and its output is bytes the engine does not touch: CRLF stays CRLF.
#[test]
fn a_command_has_no_pty_and_its_output_is_not_reshaped() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("tty; printf 'a\\r\\nb\\r\\n'", ENOUGH, MIB).unwrap();
    let text = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(text.starts_with("not a tty\n"), "no PTY was allocated: {text:?}");
    assert!(text.ends_with("a\r\nb\r\n"), "line endings are kept as the command wrote them: {text:?}");
}

/// The command's standard input is empty, as `ssh host command < /dev/null` gives it: a command that reads it sees the end at once
/// instead of waiting until the timeout.
#[test]
fn a_command_that_reads_its_input_sees_the_end_at_once() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let started = Instant::now();
    let result = session.exec("cat; read line; echo after:$?", Duration::from_secs(20), MIB).unwrap();
    assert_eq!((result.ended, result.exit_code, result.stdout.as_slice()), (Ended::Exited, Some(0), b"after:1\n".as_slice()));
    assert!(started.elapsed() < Duration::from_secs(5), "the command waited for input: {:?}", started.elapsed());
}

/// Review focus: a command that ends without an exit status must not look like a success.
#[test]
fn a_command_killed_by_a_signal_has_no_exit_code_and_names_the_signal() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("exec sh -c 'kill -9 $$'", ENOUGH, MIB).unwrap();
    fact("exec.killed_by_signal", format!("{:?} {:?}", result.ended, result.signal));
    assert_eq!((result.ended, result.exit_code, result.signal.as_deref()), (Ended::Signaled, None, Some("KILL")));
}

/// Review focus: the same, when the connection is cut instead: `Disconnected`, no exit code, no hang.
#[test]
fn a_connection_cut_during_a_command_ends_it_as_disconnected() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port);
    let target = Target { hops: vec![server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() })] };
    let session = open_session_to(&engine(), &target, &server.vault("k1"));

    let cutter = std::thread::scope(|scope| {
        let cutting = scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(500));
            proxy.set(Mode::Cut);
        });
        let started = Instant::now();
        let result = session.exec("sleep 30", ENOUGH, MIB).unwrap();
        cutting.join().unwrap();
        (result, started.elapsed())
    });
    let (result, waited) = cutter;
    fact("cut_during_exec.ended_after_ms", waited.as_millis());
    assert_eq!((result.ended, result.exit_code, result.signal), (Ended::Disconnected, None, None));
    assert!(waited < Duration::from_secs(10), "the cut was noticed: {waited:?}");
    eventually("the session to notice that it is dead", 5, || !session.is_alive());
    assert_eq!(session.exec("echo never", Duration::from_secs(5), MIB), Err(SessionError::Closed));
}

/// 32 MiB is sixteen times russh's initial window (2 MiB): this only completes if the window adjustments keep up.
#[test]
fn thirty_two_mebibytes_of_output_arrive_complete() {
    const SIZE: usize = 32 * MIB;
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let started = Instant::now();
    let result = session.exec(&format!("head -c {SIZE} /dev/zero"), Duration::from_secs(120), 64 * MIB).unwrap();
    fact("exec.long_output.mib_per_second", format!("{:.1}", SIZE as f64 / 1_048_576.0 / started.elapsed().as_secs_f64()));
    assert_eq!((result.stdout.len(), result.ended, result.exit_code, result.truncated), (SIZE, Ended::Exited, Some(0), false));
}

/// Review focus: a command that never stops printing. The caller's cap stops it, the channel is closed (that the command is really gone
/// from the server is pinned by `a_command_cut_off_at_the_cap_is_really_ended_on_the_server`), and the same connection still serves the
/// next command.
#[test]
fn output_beyond_the_cap_is_cut_off_and_the_connection_survives() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("yes sshelter", Duration::from_secs(30), MIB).unwrap();
    assert!(result.truncated);
    assert_eq!((result.ended, result.exit_code), (Ended::Truncated, None));
    assert_eq!(result.stdout.len() + result.stderr.len(), MIB, "exactly the cap was kept");
    assert!(result.stdout.starts_with(b"sshelter\nsshelter\n"));

    let started = Instant::now();
    let next = session.exec("echo alive", ENOUGH, MIB).unwrap();
    fact("exec.capped_reader.next_exec_ms", started.elapsed().as_millis());
    assert_eq!((next.stdout.as_slice(), next.ended), (b"alive\n".as_slice(), Ended::Exited));
    assert!(session.is_alive());
}

#[test]
fn output_that_exactly_fills_the_cap_is_not_truncated() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("printf 12345; printf 67890 >&2", ENOUGH, 10).unwrap();
    assert_eq!((result.truncated, result.ended, result.exit_code), (false, Ended::Exited, Some(0)));
    let over = session.exec("printf 12345; printf 678901 >&2", ENOUGH, 10).unwrap();
    assert_eq!((over.truncated, over.ended, over.stdout.len() + over.stderr.len()), (true, Ended::Truncated, 10));
}

/// russh has no command timeout; the engine's is a deadline on the read and a close of the channel (that the command is really gone from
/// the server is pinned by `a_command_that_timed_out_is_really_ended_on_the_server`). What the command printed before is kept.
#[test]
fn a_command_that_outlives_its_timeout_is_cut_and_the_connection_survives() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let started = Instant::now();
    let result = session.exec("echo started; sleep 30", Duration::from_secs(1), MIB).unwrap();
    let waited = started.elapsed();
    fact("exec.timeout.waited_ms", waited.as_millis());
    assert_eq!((result.ended, result.exit_code), (Ended::TimedOut, None));
    assert_eq!(result.stdout, b"started\n");
    assert!(waited >= Duration::from_millis(900) && waited < Duration::from_secs(5), "waited {waited:?}");

    let next = session.exec("echo alive", ENOUGH, MIB).unwrap();
    assert_eq!(next.stdout, b"alive\n");
}

/// Asks the server, through the same session, until the process whose id the command wrote to `pidfile` is gone. The result of `exec`
/// reads the same whether or not the engine closed the channel behind a command it gave up on; only the server can tell: the command's
/// next write meets a closed pipe and ends it, and without the close it would go on for ever.
fn gone_from_the_server(session: &dyn Session, pidfile: &Path, what: &str) {
    let mut pid = String::new();
    eventually("the command to write its process id", 5, || {
        pid = std::fs::read_to_string(pidfile).unwrap_or_default().trim().to_string();
        !pid.is_empty()
    });
    assert!(pid.bytes().all(|byte| byte.is_ascii_digit()), "a process id: {pid:?}");
    eventually(what, 5, || {
        let asked = session.exec(&format!("kill -0 {pid} 2>/dev/null && echo alive || echo gone"), ENOUGH, MIB).unwrap();
        asked.stdout == b"gone\n"
    });
}

/// The engine closes the channel behind a command that outlived its timeout, and the command ends on the server.
#[test]
fn a_command_that_timed_out_is_really_ended_on_the_server() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);
    let dir = tempfile::tempdir().expect("a temp dir");
    let pidfile = dir.path().join("pid");

    let command = format!("echo $$ > '{}'; while true; do echo x; sleep 0.05; done", pidfile.display());
    let result = session.exec(&command, Duration::from_millis(1500), MIB).unwrap();
    assert_eq!(result.ended, Ended::TimedOut);
    gone_from_the_server(&*session, &pidfile, "the timed-out command to end on the server");
}

/// The same for a command stopped by the output cap.
#[test]
fn a_command_cut_off_at_the_cap_is_really_ended_on_the_server() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);
    let dir = tempfile::tempdir().expect("a temp dir");
    let pidfile = dir.path().join("pid");

    let command = format!("echo $$ > '{}'; exec yes sshelter", pidfile.display());
    let result = session.exec(&command, Duration::from_secs(30), 64 * 1024).unwrap();
    assert_eq!(result.ended, Ended::Truncated);
    gone_from_the_server(&*session, &pidfile, "the capped command to end on the server");
}

/// A command that has exited but left a background job holding its output keeps the channel open. The engine cannot tell that from a
/// command that is still running, so it ends as `TimedOut`, with the status the command did report.
#[test]
fn a_command_that_exited_but_left_a_job_holding_its_output_times_out_with_its_exit_code() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    let result = session.exec("sleep 5 & echo done; exit 5", Duration::from_secs(2), MIB).unwrap();
    assert_eq!((result.ended, result.exit_code), (Ended::TimedOut, Some(5)));
    assert_eq!(result.stdout, b"done\n");
}

/// A timeout the clock cannot add to the present (`Duration::MAX`) means no timeout; it must not panic inside the engine.
#[test]
fn a_timeout_too_large_for_the_clock_means_no_timeout() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);

    for timeout in [Duration::MAX, Duration::from_secs(u64::MAX / 2), Duration::from_secs(10 * 365 * 24 * 3600)] {
        let result = session.exec("echo fine", timeout, MIB).unwrap();
        assert_eq!((result.stdout.as_slice(), result.ended, result.exit_code), (b"fine\n".as_slice(), Ended::Exited, Some(0)), "{timeout:?}");
    }
}

#[test]
fn a_closed_session_refuses_commands() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let session = open_session(&engine(), &server);
    assert!(session.is_alive());
    session.close();
    assert!(!session.is_alive());
    assert_eq!(session.exec("echo no", ENOUGH, MIB), Err(SessionError::Closed));
}

/// Spec §16: long connections and rekeying were not measured in the spike. sshd is told to start a new key exchange after every 512 KiB,
/// so 4 MiB of output makes it ask a dozen times. russh asks the host key question once, in the first exchange; if an upgrade of russh
/// ever asked again, the answer could only be "no" (the thread that answers is gone after `connect`) and this connection would die in
/// the middle of the output.
#[test]
fn a_connection_survives_the_key_exchanges_the_server_asks_for() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &["RekeyLimit 512K", "LogLevel DEBUG1"]);
    let session = open_session(&engine(), &server);

    let result = session.exec("head -c 4194304 /dev/zero", Duration::from_secs(60), 8 * MIB).unwrap();
    assert_eq!((result.ended, result.exit_code, result.stdout.len(), result.truncated), (Ended::Exited, Some(0), 4 * MIB, false));
    let exchanges = server.sshd.log().matches("SSH2_MSG_KEXINIT sent").count();
    fact("rekey.key_exchanges_started_by_sshd", exchanges);
    assert!(exchanges >= 4, "sshd started {exchanges} key exchanges: it did not rekey as often as it was told to");
    assert!(session.is_alive());
    assert_eq!(session.exec("echo still-here", ENOUGH, MIB).unwrap().stdout, b"still-here\n");
}
