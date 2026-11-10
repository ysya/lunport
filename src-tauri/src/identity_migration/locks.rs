//! The locks around a move: the migration's own lock beside the data roots, so that two processes of this version never move the same
//! folder, and the locks an earlier version holds in its data root while it runs, so that nothing moves under it. A build with another
//! identifier cannot see this one through the single-instance plugin, so its locks are the only sign that it runs.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::Move;

/// The lock files an earlier version holds in its data root, by their path inside it: the session broker's (`ipc/lock`) and the sync
/// engine's (`sync.lock`), each for as long as the app runs, and the one a client (`connect`, the MCP adapter) holds while it starts
/// the app (`mcp-spawn.lock`). These are the names of a version that is already installed, so they never change, whatever this version
/// calls its own.
const OLD_LOCKS: [&[&str]; 3] = [&["ipc", "lock"], &["sync.lock"], &["mcp-spawn.lock"]];

/// How often a held lock is tried again.
const POLL: Duration = Duration::from_millis(100);

/// Locks taken here, released when this is dropped.
pub(crate) struct Held {
    _files: Vec<File>,
}

/// What the old locks said.
pub(crate) enum Probe {
    /// Nobody held them: they are held here now.
    Free(Held),
    /// Another process still held this one (its path inside the old root) when the wait ran out.
    Busy(String),
}

/// Takes every old lock that exists in `old_root` the way the earlier version takes it (`File::try_lock`), trying again until `wait`
/// has passed: an earlier version that was just told to quit (the in-app update starts this one while the old one ends) lets go
/// within a few seconds. A lock file that does not exist is held by nobody, and none is created.
pub(crate) fn probe_old_locks(old_root: &Path, wait: Duration) -> io::Result<Probe> {
    let deadline = Instant::now() + wait;
    loop {
        match try_old_locks(old_root)? {
            Ok(held) => return Ok(Probe::Free(held)),
            Err(_) if Instant::now() < deadline => std::thread::sleep(POLL),
            Err(busy) => return Ok(Probe::Busy(busy)),
        }
    }
}

/// One attempt at every old lock: all of them held here, or the first one somebody else holds (and none held here).
fn try_old_locks(old_root: &Path) -> io::Result<Result<Held, String>> {
    let mut held = Vec::new();
    for parts in OLD_LOCKS {
        let path = parts.iter().fold(old_root.to_path_buf(), |path, part| path.join(part));
        // Opened to read, so that it is never created; a lock needs no more access on any platform.
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        match file.try_lock() {
            Ok(()) => held.push(file),
            Err(TryLockError::WouldBlock) => return Ok(Err(parts.join("/"))),
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
    Ok(Ok(Held { _files: held }))
}

/// The migration's own lock, held while this is alive.
pub(crate) struct MigrationLock {
    _file: File,
}

/// The migration's lock file: beside the two data roots, in their parent, named after the new root. It stays there after the
/// migration: removing it could let a process that is waiting for the old file and one that creates a new one both go ahead.
pub(crate) fn migration_lock_path(data: &Move) -> PathBuf {
    let mut name = data.new.file_name().unwrap_or_default().to_os_string();
    name.push(".migration.lock");
    data.new.with_file_name(name)
}

/// Takes the migration's lock, waiting at most `wait` for another process of this version that is moving the folders: `None` if it
/// still holds the lock then.
pub(crate) fn take_migration_lock(data: &Move, wait: Duration) -> io::Result<Option<MigrationLock>> {
    let path = migration_lock_path(data);
    crate::fsutil::check_write_io(&path)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path)?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Some(MigrationLock { _file: file })),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => std::thread::sleep(POLL),
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
}
