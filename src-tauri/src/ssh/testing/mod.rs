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
/// once; a child with `--test-threads=1` is the only thing running. Panics when the child fails or takes more than two minutes.
pub fn rerun_alone(name: &str) -> String {
    rerun_alone_with(name, |_| {})
}

/// `rerun_alone`, with `configure` applied to the child's command before it starts (on Windows, say, a console of its own).
pub fn rerun_alone_with(name: &str, configure: impl FnOnce(&mut std::process::Command)) -> String {
    let executable = std::env::current_exe().expect("the path of this test binary");
    let mut command = std::process::Command::new(executable);
    command.args(["--exact", name, "--nocapture", "--test-threads=1"]).env(CHILD_VARIABLE, "1");
    configure(&mut command);
    let output = harness::run_within(&mut command, std::time::Duration::from_secs(120)).unwrap_or_else(|message| panic!("{message}"));
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "the child process failed:\n{stderr}");
    stderr
}

/// The value of the line `FACT <key> = <value>` in `output`.
pub fn fact_in(output: &str, key: &str) -> Option<String> {
    let prefix = format!("FACT {key} = ");
    output.lines().find_map(|line| line.strip_prefix(&prefix)).map(str::to_string)
}
