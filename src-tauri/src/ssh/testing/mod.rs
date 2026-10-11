//! Test support for the SSH engine (own-ssh spec §12): a scratch OpenSSH server, a link that misbehaves on demand, and stand-ins for
//! the broker's policy and auth source. Test code only (`#[cfg(test)]` in `ssh/mod.rs`).

pub mod harness;

/// One measured fact, printed as `FACT <key> = <value>` so a run with `-- --nocapture` can be grepped for the numbers a report needs.
pub fn fact(key: &str, value: impl std::fmt::Display) {
    eprintln!("FACT {key} = {value}");
}
