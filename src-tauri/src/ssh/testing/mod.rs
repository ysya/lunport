//! Test support for the SSH engine (own-ssh spec §12): a scratch OpenSSH server, a link that misbehaves on demand, and stand-ins for
//! the broker's policy and auth source. Test code only (`#[cfg(test)]` in `ssh/mod.rs`).

pub mod doubles;
pub mod fixture;
pub mod harness;
pub mod proxy;

/// One measured fact, printed as `FACT <key> = <value>` so a run with `-- --nocapture` can be grepped for the numbers a report needs.
pub fn fact(key: &str, value: impl std::fmt::Display) {
    eprintln!("FACT {key} = {value}");
}

/// Polls `condition` until it holds; panics naming `what` when it does not within `seconds`. For things that happen on another thread or
/// in another process a moment after the call that caused them returned (a log line, a closed socket).
pub fn eventually(what: &str, seconds: u64, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // A condition that became true during the last sleep is not a timeout.
    if condition() {
        return;
    }
    panic!("timed out after {seconds} s waiting for: {what}");
}

/// A port on 127.0.0.1 that nothing listens on, so a connect to it is refused at once: 1 (TCP port service multiplexer, which nothing
/// runs). It is below every ephemeral range (macOS and Windows 49152–65535, Linux 32768–60999 by default), so no `bind(0)` of the suite
/// (a scratch sshd's port, a proxy's, a test's own listener) is ever given it. A port a test bound and let go is not closed for long:
/// another test running at the same time can be given it and listen there before the connect. Tests that count on the refusal take it
/// from `closed_port`.
pub const CLOSED_PORT: u16 = 1;

/// `CLOSED_PORT`, once a connect to it was refused: a test that counts on the refusal fails here, saying why, when something listens
/// there after all (or a firewall drops the connect), and not on what the engine made of it. On Windows the refusal comes after the
/// stack's retries, within the 5 s given.
pub fn closed_port() -> u16 {
    refused(CLOSED_PORT)
}

/// `port`, once a connect to it on 127.0.0.1 was refused; panics otherwise.
fn refused(port: u16) -> u16 {
    let address = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    match std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(5)) {
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => port,
        outcome => panic!("something listens on 127.0.0.1:{port}: a connect to it was not refused ({outcome:?})"),
    }
}

/// CPU time (user plus system) this whole process has used so far, in milliseconds. Unix only.
#[cfg(unix)]
pub fn cpu_time_ms() -> u128 {
    // SAFETY: `getrusage` only writes into the struct it is given, and `rusage` is plain data for which all-zero bytes are a valid value.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let millis = |time: libc::timeval| time.tv_sec as u128 * 1000 + time.tv_usec as u128 / 1000;
    millis(usage.ru_utime) + millis(usage.ru_stime)
}

/// The environment variable that tells a test it is the child that `rerun_alone` started.
const CHILD_VARIABLE: &str = "SSHELTER_TEST_CHILD";

/// True in the process `rerun_alone` started.
pub fn is_child() -> bool {
    std::env::var(CHILD_VARIABLE).is_ok_and(|value| value == "1")
}

/// Runs the test `name` (its full path, as `cargo test -- --list` prints it) alone in a fresh process of this test binary and returns what
/// that process wrote to stderr. The process-wide CPU time is only meaningful when no other test is running, and `cargo test` runs many at
/// once; a child with `--test-threads=1` is the only thing running. Panics when the child fails or takes more than two minutes. Unix
/// only, as its users are (the CPU-time measurements and the CLI's signal test); Windows tests call `rerun_alone_with`.
#[cfg(unix)]
pub fn rerun_alone(name: &str) -> String {
    rerun_alone_with(name, |_| {})
}

/// `rerun_alone`, with `configure` applied to the child's command before it starts (on Windows, say, a console of its own).
pub fn rerun_alone_with(name: &str, configure: impl FnOnce(&mut std::process::Command)) -> String {
    rerun(name, std::process::Stdio::null(), configure)
}

/// `rerun_alone_with`, the child reading `stdin` as its standard input instead of nothing: on Windows, a console's input buffer that this
/// process keeps a handle of too, as a shell and `sshelter-cli.exe` keep the one `sshelter connect` reads.
#[cfg(windows)]
pub fn rerun_alone_reading(name: &str, stdin: std::process::Stdio, configure: impl FnOnce(&mut std::process::Command)) -> String {
    rerun(name, stdin, configure)
}

fn rerun(name: &str, stdin: std::process::Stdio, configure: impl FnOnce(&mut std::process::Command)) -> String {
    let executable = std::env::current_exe().expect("the path of this test binary");
    let mut command = std::process::Command::new(executable);
    command.args(["--exact", name, "--nocapture", "--test-threads=1"]).env(CHILD_VARIABLE, "1");
    configure(&mut command);
    let output =
        harness::run_within_reading(&mut command, stdin, std::time::Duration::from_secs(120)).unwrap_or_else(|message| panic!("{message}"));
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "the child process failed:\n{stderr}");
    stderr
}

/// The value of the line `FACT <key> = <value>` in `output`. Unix only, as `rerun_alone` is.
#[cfg(unix)]
pub fn fact_in(output: &str, key: &str) -> Option<String> {
    let prefix = format!("FACT {key} = ");
    output.lines().find_map(|line| line.strip_prefix(&prefix)).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The precondition of `closed_port` is not taken for granted: a port something listens on is not handed to a test as closed.
    #[test]
    #[should_panic(expected = "something listens on 127.0.0.1:")]
    fn a_port_something_listens_on_is_not_taken_for_a_closed_one() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("a listener on a free port");
        refused(listener.local_addr().expect("its address").port());
    }

    #[test]
    fn nothing_listens_on_the_closed_port() {
        assert_eq!(closed_port(), CLOSED_PORT);
    }
}
