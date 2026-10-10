//! Phase 0 spike for SSHelter's own SSH client (docs/superpowers/plans/2026-10-10-own-ssh-phase0-spike.md).
//!
//! THROWAWAY, NOT PRODUCT CODE. It answers questions about russh 0.64.1 and about the app's key vault. Phase 1 writes
//! `ssh/russh_engine.rs` behind the `SshEngine` trait from scratch; nothing here is copied into src-tauri. The crate has no
//! clippy.toml, so a direct `Command::spawn` is fine here (in src-tauri every spawn goes through `crate::process`).

/// One measured fact. Task 6 greps these lines out of `cargo test -- --nocapture`: `FACT <key> = <value>`.
pub fn fact(key: &str, value: impl std::fmt::Display) {
    eprintln!("FACT {key} = {value}");
}

/// Await `future` for at most `seconds`; panic naming `what` when it takes longer (a hung test must fail, not hang CI).
pub async fn within<T>(seconds: u64, what: &str, future: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(std::time::Duration::from_secs(seconds), future).await {
        Ok(value) => value,
        Err(_) => panic!("timed out after {seconds} s: {what}"),
    }
}

pub mod harness;
pub mod client;
pub mod fixture;
#[cfg(feature = "app-vault")]
pub mod signer;
