//! Task 3a: exec channels against a scratch sshd: exit code, both streams, a command killed by a signal, a lot of output, a capped reader, a timeout.

use std::time::{Duration, Instant};

use russh::ChannelMsg;
use russh_spike::client::{drain, exec};
use russh_spike::fixture::Server;
use russh_spike::harness::tools;
use russh_spike::{fact, within};

#[tokio::test(flavor = "multi_thread")]
async fn exec_returns_stdout_stderr_and_the_exit_code() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let connection = server.session().await;

    let out = within(20, "exec", exec(&connection.handle, "printf out; printf err >&2; exit 7")).await.unwrap();
    assert_eq!(out.text(), "out");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "err");
    assert_eq!(out.exit_status, Some(7));
    assert_eq!(out.exit_signal, None);
    assert!(!out.refused);
}

/// Review Focus 3, first half. `exec` replaces the login shell, so the process sshd waits for is the one that kills itself: sshd
/// sends `exit-signal` (checked with `ssh -vv`: "rtype exit-signal"), never `exit-status`. The caller must not read that as exit code 0.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_killed_by_a_signal_reports_the_signal_and_no_exit_status() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let connection = server.session().await;

    let out = within(20, "exec", exec(&connection.handle, "exec sh -c 'kill -9 $$'")).await.unwrap();
    fact("exec.killed_by_signal.exit_status", format!("{:?}", out.exit_status));
    fact("exec.killed_by_signal.exit_signal", format!("{:?}", out.exit_signal));
    assert_eq!(out.exit_status, None);
    assert_eq!(out.exit_signal.as_deref(), Some("KILL"));
}

/// Review Focus 5, first half. 32 MiB is sixteen times russh's initial window (2 MiB), so this only completes if window adjustments keep up.
#[tokio::test(flavor = "multi_thread")]
async fn thirty_two_mebibytes_of_output_arrive_complete() {
    const SIZE: usize = 32 * 1024 * 1024;
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let connection = server.session().await;

    let started = Instant::now();
    let out = within(120, "32 MiB of output", exec(&connection.handle, &format!("head -c {SIZE} /dev/zero"))).await.unwrap();
    let seconds = started.elapsed().as_secs_f64();
    fact("exec.long_output.bytes", out.stdout.len());
    fact("exec.long_output.seconds", format!("{seconds:.2}"));
    fact("exec.long_output.mib_per_second", format!("{:.1}", SIZE as f64 / 1_048_576.0 / seconds));
    assert_eq!(out.stdout.len(), SIZE);
    assert_eq!(out.exit_status, Some(0));
}

/// Review Focus 5, second half. A command that never stops printing (`yes`) must not wedge the connection: the reader stops at a cap,
/// closes the channel, and the next exec on the same connection still works. This is how `ssh_exec` will limit output.
#[tokio::test(flavor = "multi_thread")]
async fn a_reader_that_stops_at_a_cap_and_closes_the_channel_leaves_the_connection_usable() {
    const CAP: usize = 1024 * 1024;
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let connection = server.session().await;

    let mut channel = within(20, "open a session channel", connection.handle.channel_open_session()).await.unwrap();
    channel.exec(true, "yes spike").await.unwrap();
    let mut read = 0usize;
    within(30, "reading up to the cap", async {
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::Data { data } = message {
                read += data.len();
                if read >= CAP {
                    break;
                }
            }
        }
    })
    .await;
    assert!(read >= CAP, "the channel ended after {read} bytes");
    channel.close().await.unwrap();

    let started = Instant::now();
    let out = within(20, "exec after the capped channel", exec(&connection.handle, "echo alive")).await.unwrap();
    fact("exec.capped_reader.next_exec_ms", started.elapsed().as_millis());
    assert_eq!(out.text(), "alive\n");
}

/// russh has no per-command timeout; the engine's `exec(command, timeout)` has to be built from `tokio::time::timeout` and `Channel::close`.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_timeout_is_ours_to_enforce_and_the_connection_survives_it() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let connection = server.session().await;

    let mut channel = within(20, "open a session channel", connection.handle.channel_open_session()).await.unwrap();
    channel.exec(true, "sleep 30").await.unwrap();
    let started = Instant::now();
    let waited = tokio::time::timeout(Duration::from_secs(1), drain(&mut channel)).await;
    assert!(waited.is_err(), "sleep 30 cannot have finished");
    fact("exec.timeout.waited_ms", started.elapsed().as_millis());
    channel.close().await.unwrap();

    let out = within(20, "exec after the timed-out channel", exec(&connection.handle, "echo alive")).await.unwrap();
    assert_eq!(out.text(), "alive\n");
}
