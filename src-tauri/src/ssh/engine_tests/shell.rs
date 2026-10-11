//! `Session::shell`: a PTY shell, its size, a reader that falls behind, and what happens to a shell when its connection does not answer
//! or is gone.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{engine, open_session, open_session_to, ShellProbe, SHELL_SERVER};
use crate::ssh::russh_engine::{EngineOptions, RusshEngine};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthMethod, Ended, Exit, Pty, SessionError, ShellChannel, Target};

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

/// Reads `shell` on a thread of its own until `read` returns 0, and reports what `exited()` said at that very moment (`None` also when a
/// read failed). The thread is blocked in `read` before anything else happens, which is what the tests that use this need.
fn exit_seen_when_the_read_ends(shell: &Arc<dyn ShellChannel>) -> Receiver<Option<Exit>> {
    let (seen, report) = std::sync::mpsc::channel();
    let shell = Arc::clone(shell);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match shell.read(&mut buf) {
                Ok(0) => {
                    let _ = seen.send(shell.exited());
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    let _ = seen.send(None);
                    return;
                }
            }
        }
    });
    report
}

/// Like `exit_seen_when_the_read_ends`, after `end` has made the shell end; `None` when the read did not end within ten seconds. Three
/// more threads ask for the exit all the time while that happens. They keep the lock of the exit busy, which holds the reader up between
/// recording the exit and closing the queue; if it ever closed the queue first, the reader that wakes up would be quick enough to see no
/// exit. Done right, the reader is not affected by them.
fn exit_seen_when_the_read_returns_zero(shell: &Arc<dyn ShellChannel>, end: impl FnOnce()) -> Option<Option<Exit>> {
    let report = exit_seen_when_the_read_ends(shell);
    let asking = Arc::new(AtomicBool::new(true));
    let askers: Vec<_> = (0..3)
        .map(|_| {
            let (shell, asking) = (Arc::clone(shell), Arc::clone(&asking));
            std::thread::spawn(move || {
                while asking.load(Ordering::Relaxed) {
                    let _ = shell.exited();
                }
            })
        })
        .collect();
    end();
    let seen = report.recv_timeout(Duration::from_secs(10)).ok();
    asking.store(false, Ordering::Relaxed);
    for asker in askers {
        let _ = asker.join();
    }
    seen
}

/// The reader records how the shell ended and only then closes the queue (`QueuedShell` promises that a `read` that returns 0 finds
/// `exited()` filled in), and it does close the queue when the shell ends, whoever is blocked in `read`. Twenty shells, one after the
/// other: the order is a matter of nanoseconds, so a single shell would hardly ever show a wrong one.
#[test]
fn when_a_blocked_read_returns_zero_the_exit_is_already_there() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    for round in 0..20 {
        let shell: Arc<dyn ShellChannel> = Arc::from(session.shell(pty(80, 24)).unwrap());
        let seen = exit_seen_when_the_read_returns_zero(&shell, || shell.write(b"exit 3\n").unwrap()).expect("a blocked read returns 0 when the shell ends");
        assert_eq!(seen, Some(Exit::Code(3)), "shell {round}: the exit is set when read returns 0");
    }
}

/// A local `close()` ends a blocked `read` the same way. A shell that was closed has no status to report: it ended as `Disconnected`.
#[test]
fn a_local_close_ends_a_blocked_read_with_the_exit_already_set() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);

    for round in 0..12 {
        let shell: Arc<dyn ShellChannel> = Arc::from(session.shell(pty(80, 24)).unwrap());
        let closing = || {
            std::thread::sleep(Duration::from_millis(50));
            shell.close();
        };
        let seen = exit_seen_when_the_read_returns_zero(&shell, closing).expect("a blocked read returns 0 after close()");
        assert_eq!(seen, Some(Exit::Disconnected), "shell {round}: the exit is set when read returns 0");
    }
    assert!(session.is_alive(), "the shells were closed, the connection was not");
}

/// The broker drops a session when a tab goes away while the CLI may still hold the shell, and the engine can be dropped before either.
/// The shell keeps what it needs: its reads end (it was disconnected), and its calls answer `Closed` instead of waiting or panicking.
#[test]
fn a_shell_that_outlives_its_session_and_its_engine_ends_and_answers_closed() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let engine = engine();
    let session = open_session(&engine, &server);
    let probe = ShellProbe::start(session.shell(pty(80, 24)).unwrap());
    probe.wait_for_text(20, "$ ").expect("a prompt");

    drop(session);
    drop(engine);
    eventually("the orphaned shell to report its end", 10, || probe.shell.exited().is_some());
    assert_eq!(probe.shell.exited(), Some(Exit::Disconnected));
    eventually("a write to say that the connection is closed", 5, || probe.shell.write(b"x") == Err(SessionError::Closed));
    eventually("a window change to say that the connection is closed", 5, || probe.shell.window_change(100, 30) == Err(SessionError::Closed));
    probe.shell.close();
}

/// Once the connection is gone every call on a shell says so in the same way: `write` and `window_change` both answer `Closed`. (The
/// shell reports its end a moment before the last send of the session fails, so the calls are repeated until the answer is final.)
#[test]
fn a_shell_whose_session_was_closed_answers_closed_to_every_call() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let session = open_session(&engine(), &server);
    let probe = ShellProbe::start(session.shell(pty(80, 24)).unwrap());
    probe.wait_for_text(20, "$ ").expect("a prompt");

    session.close();
    eventually("the shell to report its end after the session closed", 10, || probe.shell.exited().is_some());
    eventually("a write to say that the connection is closed", 5, || probe.shell.write(b"x") == Err(SessionError::Closed));
    eventually("a window change to say that the connection is closed", 5, || probe.shell.window_change(10, 10) == Err(SessionError::Closed));
}

/// Review focus. The peer stops reading (its socket buffers are full, as on a dead link that keepalive has not given up on yet). Every
/// request of every channel goes through one small queue of the connection, and the connection stops emptying it then, so a request that
/// waits for room in it would hold up its caller for as long as the link stays dead. Each request is bounded: window changes come back
/// (as `Timeout`), and the close behind a command that ran out of time does not keep `exec` from returning. The cut at the end releases
/// everything that is still waiting.
#[test]
fn requests_to_a_peer_that_stopped_reading_come_back_in_time_and_the_cut_releases_the_rest() {
    const BOUND: Duration = Duration::from_secs(20);
    const RESIZERS: u16 = 30;
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let proxy = Proxy::start(server.sshd.port);
    let target = Target { hops: vec![server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() })] };
    let session = open_session_to(&engine(), &target, &server.vault("k1"));
    // Eight shells and the command make nine of the ten sessions sshd allows on one connection.
    let probes: Vec<ShellProbe> = (0..8).map(|_| ShellProbe::start(session.shell(pty(80, 24)).unwrap())).collect();
    for probe in &probes {
        probe.wait_for_text(20, "$ ").expect("a prompt");
    }

    // The command says that it runs before the link goes silent, whatever the load on the machine.
    let dir = tempfile::tempdir().expect("a temp dir");
    let marker = dir.path().join("started");
    let command = format!("touch '{}'; sleep 6", marker.display());
    let (exec_done, exec_outcome) = std::sync::mpsc::channel();
    let (resized, resizes) = std::sync::mpsc::channel();
    let mut resizes_back = Vec::new();
    let mut exec_back = None;
    let chunks_taken = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        // A command that is running when the link goes silent and runs out of time (after 4 s) when the queue is full already.
        scope.spawn(|| {
            let started = Instant::now();
            let result = session.exec(&command, Duration::from_secs(4), MIB);
            let _ = exec_done.send((result.map(|result| result.ended), started.elapsed()));
        });
        eventually("the command to start on the server", 10, || marker.exists());
        proxy.set(Mode::Blackhole);
        // Every shell is fed 1.9 MiB, which is more than the sockets and the proxy hold together, so the connection stops writing. It is
        // a little less than the 2 MiB window of a channel on purpose: a writer that used its window up waits for an adjustment that never
        // comes, and only the 30 s write limit would release it after the cut.
        for probe in &probes {
            let (shell, taken) = (Arc::clone(&probe.shell), &chunks_taken);
            scope.spawn(move || {
                let chunk = vec![b'a'; 16 * 1024];
                for _ in 0..120 {
                    if shell.write(&chunk).is_err() {
                        return;
                    }
                    taken.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        // The link is full when no write has finished for half a second: that is waited for, not guessed (at most ten seconds).
        let (mut last, mut since) = (0, Instant::now());
        let patience = Instant::now() + Duration::from_secs(10);
        while Instant::now() < patience {
            std::thread::sleep(Duration::from_millis(50));
            let now = chunks_taken.load(Ordering::SeqCst);
            if now != last {
                (last, since) = (now, Instant::now());
            } else if last > 0 && since.elapsed() >= Duration::from_millis(500) {
                break;
            }
        }
        fact("shell.wedged_peer.chunks_taken_before_the_stall", last);
        // More window changes than the queue holds: the first ones may find room, the others have to wait for it.
        for call in 0..RESIZERS {
            let (shell, resized) = (Arc::clone(&probes[0].shell), resized.clone());
            scope.spawn(move || {
                let started = Instant::now();
                let result = shell.window_change(100 + call, 30);
                let _ = resized.send((result, started.elapsed()));
            });
        }
        drop(resized);

        // Collect without ever failing here: a panic would wait for threads that only the cut releases.
        let deadline = Instant::now() + BOUND;
        while resizes_back.len() < usize::from(RESIZERS) {
            match resizes.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(back) => resizes_back.push(back),
                Err(_) => break,
            }
        }
        exec_back = exec_outcome.recv_timeout(deadline.saturating_duration_since(Instant::now())).ok();
        proxy.set(Mode::Cut);
    });

    let slowest = resizes_back.iter().map(|(_, waited)| waited.as_millis()).max().unwrap_or(0);
    let timed_out = resizes_back.iter().filter(|(result, _)| *result == Err(SessionError::Timeout)).count();
    fact("shell.wedged_peer.window_changes_back", format!("{} of {RESIZERS}, {timed_out} as Timeout, slowest {slowest} ms", resizes_back.len()));
    fact("shell.wedged_peer.exec", format!("{exec_back:?}"));
    assert_eq!(resizes_back.len(), usize::from(RESIZERS), "every window change came back within {BOUND:?}: {resizes_back:?}");
    assert!(timed_out > 0, "the link did not wedge, so this test has shown nothing: {resizes_back:?}");
    assert!(resizes_back.iter().all(|(result, _)| matches!(result, Ok(()) | Err(SessionError::Timeout))), "{resizes_back:?}");
    let (ended, waited) = exec_back.expect("the command came back within the bound");
    assert_eq!(ended, Ok(Ended::TimedOut), "the close behind a command that ran out of time must not keep it from returning");
    assert!(waited >= Duration::from_secs(4) && waited < BOUND, "waited {waited:?}");
}
