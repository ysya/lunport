//! `Session::shell`: a PTY shell, its size, and a reader that falls behind.

use std::time::{Duration, Instant};

use super::{engine, open_session, ShellProbe, SHELL_SERVER};
use crate::ssh::russh_engine::{EngineOptions, RusshEngine};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{Exit, Pty, SessionError};

const MIB: usize = 1024 * 1024;

fn pty(cols: u16, rows: u16) -> Pty {
    Pty { term: "xterm-256color".to_string(), cols, rows }
}

#[test]
fn a_pty_shell_prints_a_prompt_runs_a_command_and_reports_its_exit_status() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let started = Instant::now();
    let shell = session.shell(pty(80, 24)).unwrap();
    assert_eq!(shell.exited(), None);
    let probe = ShellProbe::start(shell);
    // A POSIX sh prompt ends in "$ " (dash: "$ ", macOS bash as sh: "sh-3.2$ ").
    probe.wait_for_text(20, "$ ").expect("a prompt");
    fact("shell.first_prompt_ms", started.elapsed().as_millis());

    // "$((6*7))" is typed, "42" is printed: the echo of the typed line does not contain SSHELTER_42.
    probe.type_line("echo SSHELTER_$((6*7))");
    probe.wait_for_text(10, "SSHELTER_42").expect("the command's output");

    probe.type_line("exit 3");
    eventually("the shell to report its exit", 10, || probe.shell.exited().is_some());
    assert_eq!(probe.shell.exited(), Some(Exit::Code(3)));
    assert!(session.is_alive(), "the shell ended, the connection did not");
}

#[test]
fn the_size_given_with_the_pty_request_is_the_initial_size() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let probe = ShellProbe::start(session.shell(pty(97, 31)).unwrap());
    probe.wait_for_text(20, "$ ").expect("a prompt");
    assert_eq!(probe.stty_size().expect("stty answers"), "31 97");
}

#[test]
fn a_window_change_while_the_shell_runs_is_applied() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let probe = ShellProbe::start(session.shell(pty(80, 24)).unwrap());
    probe.wait_for_text(20, "$ ").expect("a prompt");
    probe.shell.window_change(100, 30).unwrap();
    assert_eq!(probe.stty_size().expect("stty answers"), "30 100");
}

/// Review focus. The user resizes the terminal the moment `sshelter connect` starts: the broker has the size ready when `shell` returns
/// and sends it at once, before the prompt is even drawn (spec §7.2). It must not be lost and must not hurt the shell.
#[test]
fn a_window_change_sent_right_after_the_shell_opens_is_applied() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let shell = session.shell(pty(80, 24)).unwrap();
    shell.window_change(120, 40).unwrap();
    let probe = ShellProbe::start(shell);
    probe.wait_for_text(20, "$ ").expect("a prompt");
    assert_eq!(probe.stty_size().expect("stty answers"), "40 120");
}

#[test]
fn closing_a_shell_ends_its_reader_and_leaves_the_connection_and_other_shells_alone() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    let first = ShellProbe::start(session.shell(pty(80, 24)).unwrap());
    let second = ShellProbe::start(session.shell(pty(80, 24)).unwrap());
    first.wait_for_text(20, "$ ").expect("a prompt in the first shell");
    second.wait_for_text(20, "$ ").expect("a prompt in the second shell");

    first.shell.close();
    eventually("the closed shell to report that it ended", 10, || first.shell.exited().is_some());
    assert!(session.is_alive());
    second.type_line("echo STILL_$((1+1))");
    second.wait_for_text(10, "STILL_2").expect("the second shell still works");
}

/// Review focus: the terminal is paused (or the CLI is busy) while the server keeps printing. The engine drains the channel anyway, into a
/// bounded queue; the connection is not held up (another command runs at once on it), the bytes that did not fit are dropped, and the
/// stream says so when the reader comes back.
#[test]
fn a_reader_that_stops_reading_does_not_hold_up_the_connection_and_the_gap_is_announced() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let small_queue = RusshEngine::with_options(EngineOptions { shell_queue_bytes: 64 * 1024, worker_threads: 2, ..EngineOptions::default() });
    let session = open_session(&small_queue, &server);

    let shell = session.shell(pty(80, 24)).unwrap();
    // Nobody reads yet. `yes` fills the queue in a moment and keeps going.
    shell.write(b"yes sshelter\n").unwrap();
    std::thread::sleep(Duration::from_secs(2));

    let started = Instant::now();
    let other = session.exec("echo alive", Duration::from_secs(10), MIB).unwrap();
    fact("shell.paused_reader.exec_ms", started.elapsed().as_millis());
    assert_eq!(other.stdout, b"alive\n");
    assert!(started.elapsed() < Duration::from_secs(5), "the connection was held up: {:?}", started.elapsed());

    let probe = ShellProbe::start(shell);
    probe.wait_for_text(20, "SSHelter dropped").expect("the stream announces the gap once the reader is back");
    let text = probe.text();
    assert!(text.contains("bytes of output because the terminal fell behind"), "{}", &text[text.len().saturating_sub(300)..]);
    probe.shell.close();
}

#[test]
fn a_closed_session_refuses_shells() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);
    session.close();
    assert!(matches!(session.shell(pty(80, 24)), Err(SessionError::Closed)));
}
