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
    panic!("timed out after {seconds} s waiting for: {what}");
}
