//! Integration tests of the russh engine against a scratch OpenSSH server (own-ssh spec §12). Each test starts its own sshd; a test
//! returns early, printing "skipped", where the OpenSSH tools are missing (`SSHELTER_REQUIRE_OPENSSH=1` turns that into a failure).

mod connect;

use super::russh_engine::{EngineOptions, RusshEngine};
use super::testing::fixture::Server;

/// An engine with a small runtime, one per test.
fn engine() -> RusshEngine {
    RusshEngine::with_options(EngineOptions { worker_threads: 2, ..EngineOptions::default() })
}

/// sshd logs accepted logins at INFO; the default of the harness is ERROR.
const LOG_LOGINS: &str = "LogLevel INFO";

/// How many public-key logins sshd has accepted (needs `LOG_LOGINS`).
fn accepted_logins(server: &Server) -> usize {
    server.sshd.log().lines().filter(|line| line.contains("Accepted publickey")).count()
}
