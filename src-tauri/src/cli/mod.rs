//! `sshelter connect` (own-ssh spec §7.3): the terminal's end of a session in the app. macOS and Linux in this version; on Windows it
//! says so (plan 1b; the Windows console is phase 3).

#[cfg(unix)]
pub mod client;
#[cfg(unix)]
pub mod terminal;
