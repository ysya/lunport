//! The folders the migration moves, each renamed from the old identifier to the current one inside the same parent: the data root,
//! Production's roaming backups on Windows and the macOS WebView store. A folder is never merged into one that already holds something.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::journal::{self, Journal};
use super::locks::{self, Probe};
use super::Move;

/// What is at a folder's path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Folder {
    Missing,
    /// An empty directory: nothing is lost when another takes its place.
    Empty,
    /// Anything else: a directory with something in it, a file, a link.
    Occupied,
}

/// What is at `path`, not following a link.
pub(crate) fn folder(path: &Path) -> io::Result<Folder> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Folder::Missing),
        Err(error) => Err(error),
        Ok(metadata) if metadata.is_dir() && fs::read_dir(path)?.next().is_none() => Ok(Folder::Empty),
        Ok(_) => Ok(Folder::Occupied),
    }
}

/// Why the data root did not move.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// The new root holds data too.
    Conflict,
    /// An earlier version still holds this lock (its path inside the old root).
    Busy(String),
    /// Something failed, for this reason; nothing has moved.
    Failed(String),
}

/// What a move does with a new folder that already holds something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Occupied {
    /// Leave both: for the data root that is a conflict, for another folder both stay.
    Refuse,
    /// Set the new folder aside beside it first (`back_up`): the user chose the old data.
    BackUp,
}

/// Renames the data root from its old name to the new one, unless an earlier version holds one of the old root's locks after `wait`.
/// Returns the journal that the rename carried along: it is written into the old root first, so that whenever the process stops, a
/// root at the new name holds a journal and the next start resumes from it. The data root step in it is still pending: what has to
/// follow the rename has not been done yet.
pub(crate) fn move_data_root(data: &Move, wait: Duration, occupied: Occupied) -> Result<Journal, Refusal> {
    let new = folder(&data.new).map_err(|error| Refusal::Failed(format!("cannot inspect {}: {error}", data.new.display())))?;
    if new == Folder::Occupied && occupied == Occupied::Refuse {
        return Err(Refusal::Conflict);
    }
    let held = match locks::probe_old_locks(&data.old, wait) {
        Ok(Probe::Free(held)) => held,
        Ok(Probe::Busy(lock)) => return Err(Refusal::Busy(lock)),
        Err(error) => return Err(Refusal::Failed(format!("cannot check the locks in {}: {error}", data.old.display()))),
    };
    let failed = |error: &dyn std::fmt::Display| {
        Refusal::Failed(format!("cannot move {} to {}: {error}", data.old.display(), data.new.display()))
    };
    for path in [&data.old, &data.new] {
        crate::fsutil::check_write_io(path).map_err(|error| failed(&error))?;
    }
    // The user's choice of the old data travels with it, for the folders that move after the data root. A start that stopped before
    // the rename left that choice in the old root's journal, which this one replaces: it is kept, even from a journal this version
    // cannot read in full.
    let chosen = journal::records_old_data_choice(&data.old);
    let mut journal = Journal::default();
    journal.use_old_data = occupied == Occupied::BackUp || chosen;
    journal::write(&data.old, &journal).map_err(|error| failed(&error))?;
    match rename_root(data, new, held) {
        Ok(()) => {
            sync_parent(&data.new);
            Ok(journal)
        }
        Err(error) => {
            // Nothing has moved, and the journal that was to travel with the old root goes again, unless it carries the choice of the
            // old data: the new root may have been set aside already, and the next start has to know why.
            if !journal.use_old_data {
                let _ = fs::remove_file(journal::path(&data.old));
            }
            if occupied == Occupied::Refuse && matches!(folder(&data.new), Ok(Folder::Occupied)) {
                // Something put data at the new name in the meantime.
                Err(Refusal::Conflict)
            } else {
                Err(failed(&error))
            }
        }
    }
}

/// Clears the new name (an empty folder is removed, an occupied one backed up, which the caller chose) and renames the old root onto
/// it, `held` being the old root's locks.
fn rename_root(data: &Move, new: Folder, held: locks::Held) -> io::Result<()> {
    clear(data, new)?;
    // Unix keeps the old locks across the rename, so that an earlier version starting now finds them held and gives up. Windows cannot
    // rename a folder with files open in it, so the locks go first; an earlier version that starts in between makes the rename fail,
    // and nothing has moved.
    let held = if cfg!(windows) {
        drop(held);
        None
    } else {
        Some(held)
    };
    #[cfg(test)]
    let renamed = if FAIL_ROOT_RENAME.with(std::cell::Cell::get) {
        Err(io::Error::other("the rename failed (test)"))
    } else {
        crate::fsutil::rename_exclusive(&data.old, &data.new)
    };
    #[cfg(not(test))]
    let renamed = crate::fsutil::rename_exclusive(&data.old, &data.new);
    drop(held);
    renamed
}

/// Makes room at the new name for the old folder: removes an empty folder, backs up an occupied one.
fn clear(folders: &Move, new: Folder) -> io::Result<()> {
    match new {
        Folder::Missing => {}
        Folder::Empty => fs::remove_dir(&folders.new)?,
        Folder::Occupied => {
            back_up(&folders.new)?;
        }
    }
    Ok(())
}

/// Sets the folder at `path` aside beside it, as `<name>.backup-<milliseconds since 1970>`, and returns where it went.
fn back_up(path: &Path) -> io::Result<PathBuf> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_millis();
    let mut name = path.file_name().ok_or_else(|| io::Error::other("a folder to back up has a name"))?.to_os_string();
    name.push(format!(".backup-{millis}"));
    let backup = path.with_file_name(name);
    crate::fsutil::check_write_io(path)?;
    crate::fsutil::check_write_io(&backup)?;
    crate::fsutil::rename_exclusive(path, &backup)?;
    sync_parent(&backup);
    Ok(backup)
}

/// What became of a folder other than the data root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Moved {
    Moved,
    /// There was nothing under the old name.
    NothingToMove,
    /// Something is under the new name already: both stay as they are.
    KeptBoth,
}

/// Renames a folder other than the data root (the roaming backups, the WebKit store) from its old name to the new one; with
/// `Occupied::BackUp` a new folder that holds something is set aside first. The caller holds the old data root's locks when it exists.
pub(crate) fn move_folder(folders: &Move, occupied: Occupied) -> io::Result<Moved> {
    if folder(&folders.old)? == Folder::Missing {
        return Ok(Moved::NothingToMove);
    }
    crate::fsutil::check_write_io(&folders.old)?;
    crate::fsutil::check_write_io(&folders.new)?;
    let new = folder(&folders.new)?;
    if new == Folder::Occupied && occupied == Occupied::Refuse {
        return Ok(Moved::KeptBoth);
    }
    clear(folders, new)?;
    crate::fsutil::rename_exclusive(&folders.old, &folders.new)?;
    sync_parent(&folders.new);
    Ok(Moved::Moved)
}

/// Makes a rename into `path`'s parent survive a crash: the directory entry is on disk once this returns. Best effort.
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The folders, under the data root's `credential-helper`, of the programs only the credential migration uses: helper v1, which an
/// earlier version installed, and the bridge to it (macOS Production, `secrets::macos_helper`).
pub(crate) const MIGRATION_PROGRAMS: [&str; 2] = ["v1", "bridge"];

/// Removes helper v1 and the bridge from the data root once nothing is left to move: until then they may be what reads the saved
/// credentials. Best effort; a link in a folder's place is removed, not followed.
pub(crate) fn retire_migration_programs(root: &Path) {
    for folder in MIGRATION_PROGRAMS {
        let directory = root.join("credential-helper").join(folder);
        if fs::symlink_metadata(&directory).is_err() || crate::fsutil::check_write_io(&directory).is_err() {
            continue;
        }
        if let Err(error) = fs::remove_dir_all(&directory) {
            eprintln!("[migration] cannot remove {}: {error}", directory.display());
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Whether the data root's rename fails, for a test on this thread (`with_failing_root_rename`).
    static FAIL_ROOT_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` with the data root's rename failing, after whatever comes before it.
#[cfg(test)]
pub(crate) fn with_failing_root_rename<T>(f: impl FnOnce() -> T) -> T {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            FAIL_ROOT_RENAME.with(|failing| failing.set(false));
        }
    }
    let _restore = Restore;
    FAIL_ROOT_RENAME.with(|failing| failing.set(true));
    f()
}
