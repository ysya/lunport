//! Task 3b: an interactive shell with a PTY: a prompt, a command, the exit status, the window size.
//!
//! The scratch sshd forces `/bin/sh` (`ForceCommand`), so the interactive shell is the same POSIX sh on every machine and the prompt does
//! not depend on the developer's zsh configuration. That is the whole extent of the isolation: sshd starts a ForceCommand, like an exec
//! request, through the user's LOGIN shell with `-c` (sshd_config(5)), and zsh sources `~/.zshenv` even for `-c`. It is not a leak of
//! `~/.ssh`, but a `.zshenv` that prints to stdout would break the `out.text()` assertions in tests/exec.rs as well.
//! The markers are chosen so the PTY's echo of what was typed can never be mistaken for the answer.

use std::time::Instant;

use russh_spike::client::drain;
use russh_spike::fixture::Server;
use russh_spike::harness::tools;
use russh_spike::shell::{open_shell, read_until, stty_size, type_line};
use russh_spike::{fact, within};

const SHELL_SERVER: &[&str] = &["ForceCommand /bin/sh"];

#[tokio::test(flavor = "multi_thread")]
async fn a_pty_shell_prints_a_prompt_runs_a_command_and_reports_its_exit_status() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let connection = server.session().await;

    let started = Instant::now();
    let mut channel = within(20, "open the shell", open_shell(&connection.handle, "xterm-256color", 80, 24)).await.unwrap();
    // A POSIX sh prompt ends in "$ " (dash: "$ ", macOS bash as sh: "sh-3.2$ ").
    within(20, "the prompt", read_until(&mut channel, "$ ")).await.expect("a prompt");
    fact("shell.first_prompt_ms", started.elapsed().as_millis());

    // "$((6*7))" is typed, "42" is printed: the echo of the typed line does not contain SPIKE_42.
    type_line(&channel, "echo SPIKE_$((6*7))").await.unwrap();
    within(10, "the command's output", read_until(&mut channel, "SPIKE_42")).await.expect("the output");

    type_line(&channel, "exit 3").await.unwrap();
    let rest = within(10, "the shell's exit", drain(&mut channel)).await;
    assert_eq!(rest.exit_status, Some(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_size_given_with_the_pty_request_is_the_initial_size() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let connection = server.session().await;

    let mut channel = within(20, "open the shell", open_shell(&connection.handle, "xterm-256color", 97, 31)).await.unwrap();
    within(20, "the prompt", read_until(&mut channel, "$ ")).await.unwrap();
    assert_eq!(within(10, "stty size", stty_size(&mut channel)).await.unwrap(), "31 97");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_window_change_while_the_shell_runs_is_applied() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let connection = server.session().await;

    let mut channel = within(20, "open the shell", open_shell(&connection.handle, "xterm-256color", 80, 24)).await.unwrap();
    within(20, "the prompt", read_until(&mut channel, "$ ")).await.unwrap();
    channel.window_change(100, 30, 0, 0).await.unwrap();
    assert_eq!(within(10, "stty size", stty_size(&mut channel)).await.unwrap(), "30 100");
}

/// Review Focus 4. The user resizes the terminal the moment `sshelter connect` starts: the `window-change` goes out after `pty-req` but
/// before the shell is ready (nothing waits for the replies). It must not be lost, and must not break the shell.
#[tokio::test(flavor = "multi_thread")]
async fn a_window_change_sent_before_the_shell_is_ready_is_not_lost() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let connection = server.session().await;

    let mut channel = within(20, "open a session channel", connection.handle.channel_open_session()).await.unwrap();
    channel.request_pty(true, "xterm-256color", 80, 24, 0, 0, &[]).await.unwrap();
    channel.window_change(120, 40, 0, 0).await.unwrap();
    channel.request_shell(true).await.unwrap();
    within(20, "the prompt", read_until(&mut channel, "$ ")).await.unwrap();
    assert_eq!(within(10, "stty size", stty_size(&mut channel)).await.unwrap(), "40 120");
}

/// A fact, not a requirement: what sshd does with a `window-change` that arrives before there is a PTY at all. The broker has to keep the
/// latest size and replay it once the shell is up if sshd drops this one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an observation for the report: run with --ignored --nocapture"]
async fn observe_a_window_change_sent_before_the_pty_request() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let connection = server.session().await;

    let mut channel = within(20, "open a session channel", connection.handle.channel_open_session()).await.unwrap();
    channel.window_change(120, 40, 0, 0).await.unwrap();
    channel.request_pty(true, "xterm-256color", 80, 24, 0, 0, &[]).await.unwrap();
    channel.request_shell(true).await.unwrap();
    within(20, "the prompt", read_until(&mut channel, "$ ")).await.unwrap();
    let size = within(10, "stty size", stty_size(&mut channel)).await.unwrap();
    fact("shell.window_change_before_pty_request.final_size", &size);
    fact("shell.window_change_before_pty_request.was_kept", size == "40 120");
}
