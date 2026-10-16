//! Lunport's own SSH engine (own-ssh spec §4, §6): the interface the broker, the CLI and the MCP adapter use (`SshEngine`, `Session`,
//! `ShellChannel`, `HostKeyPolicy`, `AuthSource`), a fake for their tests, and the russh-backed engine behind the interface.
//!
//! russh is imported by exactly one file, `russh_engine.rs`; a test below keeps it that way. Swapping the engine later means replacing
//! that file.

mod channel;
#[cfg(test)]
mod engine_tests;
mod error;
#[cfg(test)]
pub(crate) mod fake;
#[cfg(test)]
mod parity_tests;
pub(crate) mod russh_engine;
#[cfg(test)]
pub(crate) mod testing;
mod traits;
mod types;

// What the rest of the app uses (plan 1b R21: the module is private to the crate; the broker is its user).
pub(crate) use error::{AuthError, ConnectError, SessionError};
pub(crate) use traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
pub(crate) use types::{
    AuthMethod, DisconnectKind, DisconnectReason, Exit, Hop, HopRef, HostId, HostKey, HostKeyVerdict, Prompt, Pty, RsaHash, Secret, Signature, Target,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY,
};
// Execution types shared by Records MCP and the human deployment integration.
pub(crate) use types::{Ended, ExecResult};
#[cfg(test)]
pub(crate) use types::Phase;

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// Every `.rs` file under `dir` (recursively), sorted so that a failure message is the same every time.
    fn rust_files(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap_or_else(|error| panic!("cannot list {}: {error}", dir.display())) {
            let path = entry.unwrap_or_else(|error| panic!("cannot list {}: {error}", dir.display())).path();
            if path.is_dir() {
                found.extend(rust_files(&path));
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
        found.sort();
        found
    }

    /// The engine can be replaced one day (spec §1, goal 5), so the library that speaks SSH is named in one file only. The text searched
    /// for is put together at run time, so that this file does not contain it.
    #[test]
    fn russh_is_named_by_russh_engine_rs_and_by_no_other_file() {
        let source = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let engine = source.join("ssh").join("russh_engine.rs");
        let files = rust_files(source);
        assert!(files.contains(&engine), "the scan did not find {}: it would pass without looking at anything", engine.display());

        let name = ["rus", "sh"].concat();
        let needles = [format!("{name}::"), format!("use {name}"), format!("extern crate {name}")];
        let mut offenders = Vec::new();
        for file in files.iter().filter(|file| **file != engine) {
            let text = std::fs::read_to_string(file).unwrap_or_else(|error| panic!("cannot read {}: {error}", file.display()));
            for (index, line) in text.lines().enumerate() {
                if needles.iter().any(|needle| line.contains(needle.as_str())) {
                    offenders.push(format!("{}:{}: {}", file.strip_prefix(source).unwrap_or(file).display(), index + 1, line.trim()));
                }
            }
        }
        assert!(offenders.is_empty(), "only ssh/russh_engine.rs may use {name}, but it is used in {} place(s):\n{}", offenders.len(), offenders.join("\n"));
    }
}
