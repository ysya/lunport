//! Each test is a computer in a temporary folder: a local data folder that holds the old data root (`org.homelab.sshelter`, as an
//! earlier version left it) and receives the new one, plus whatever other folders the test gives its `Roots`.

use super::commands::{MigrationState, MigrationStatus};
use super::journal::{self, Journal, McpFailure, McpProgress, StepState};
use super::mcp_configs::McpNotice;
use super::*;
use crate::error::AppError;
use crate::mcp_setup::SetupClient;
use crate::write_policy::WritePolicy;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

const OLD_ID: &str = "org.homelab.sshelter";
const NEW_ID: &str = "dev.ysya.lunport";

/// Waits that keep a held lock held for the test's whole run.
const QUICK: Waits = Waits { old_locks: Duration::from_millis(150), migration_lock: Duration::from_millis(150) };

struct Computer {
    temp: tempfile::TempDir,
    roots: Roots,
}

impl Computer {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join("Local");
        fs::create_dir(&local).unwrap();
        let roots = Roots { data: Move::named(&local, OLD_ID, NEW_ID), backups: None, webkit: None, preferences: None };
        Self { temp, roots }
    }

    /// The old data root as an earlier version leaves it: its sync state, its vault and the broker's folder with its lock.
    fn with_old_data(self) -> Self {
        fs::create_dir_all(self.old().join("ipc")).unwrap();
        fs::write(self.old().join("sync-state.json"), br#"{"version":3}"#).unwrap();
        fs::write(self.old().join("vault.json"), br#"{"entries":[]}"#).unwrap();
        fs::write(self.old().join("ipc").join("lock"), b"").unwrap();
        self
    }

    /// A WebKit store under the old name (with a file in it) and the roots that move it.
    fn with_old_webkit(mut self) -> Self {
        let webkit = Move::named(&self.temp.path().join("WebKit"), OLD_ID, NEW_ID);
        fs::create_dir_all(webkit.old.join("WebsiteData")).unwrap();
        fs::write(webkit.old.join("WebsiteData").join("salt"), b"old store").unwrap();
        self.roots.webkit = Some(webkit);
        self
    }

    /// A data root that a crashed or failed earlier start has moved already, with this journal.
    fn moved_with(self, journal: &Journal) -> Self {
        fs::create_dir_all(self.new_root()).unwrap();
        fs::write(self.new_root().join("vault.json"), b"vault").unwrap();
        journal::write(self.new_root(), journal).unwrap();
        self
    }

    fn local(&self) -> PathBuf {
        self.temp.path().join("Local")
    }
    fn old(&self) -> &Path {
        &self.roots.data.old
    }
    fn new_root(&self) -> &Path {
        &self.roots.data.new
    }
    fn webkit(&self) -> &Move {
        self.roots.webkit.as_ref().unwrap()
    }
    fn run(&self, entry: Entry) -> Outcome {
        run(entry, &self.roots, &QUICK).outcome
    }
    fn journal(&self) -> Journal {
        journal::read(self.new_root()).unwrap().expect("the new root holds a journal")
    }
    fn conflict(&self) -> Outcome {
        Outcome::Conflict { old: self.old().to_path_buf(), new: self.new_root().to_path_buf() }
    }
    fn credentials_pending(&self) -> bool {
        credentials_pending_in(&self.roots.data)
    }
}

const DEFERRED: Outcome = Outcome::Deferred(DeferReason::OldInstanceRunning);

/// A journal whose steps in `done` are done.
fn journal_with(done: &[Step]) -> Journal {
    let mut journal = Journal::default();
    for &step in done {
        journal.set(step, StepState::Done);
    }
    journal
}

/// Whether `outcome` is a deferral because `step` failed.
fn failed(outcome: &Outcome, step: Step) -> bool {
    matches!(outcome, Outcome::Deferred(DeferReason::StepFailed { step: failed, .. }) if *failed == step)
}

/// A lock that a test holds the way a running earlier version holds it, let go of when this is dropped.
struct Holding(File);

impl Drop for Holding {
    fn drop(&mut self) {
        // Windows may free the lock of a closed handle only some time later: let go of it first, so that it is free once dropped.
        let _ = self.0.unlock();
    }
}

/// Holds the lock at `path` the way a running earlier version holds it.
fn hold(path: &Path) -> Holding {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let file = OpenOptions::new().create(true).truncate(false).write(true).open(path).unwrap();
    file.try_lock().unwrap();
    Holding(file)
}

/// Every path under `root` relative to it, with each file's contents: two equal trees hold the same things. Windows cannot read a
/// file whose lock another handle holds, so such a file counts as its marker on every platform alike: a tree taken while a test holds
/// a lock differs from one taken without it wherever the test runs, not only on Windows.
fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    /// The file's contents, read through a handle that takes its lock first (as the migration looks at an old lock), or the marker.
    fn contents(path: &Path) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        match file.try_lock() {
            Ok(()) => {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).unwrap();
                file.unlock().unwrap();
                contents
            }
            Err(TryLockError::WouldBlock) => b"<locked>".to_vec(),
            Err(TryLockError::Error(error)) => panic!("cannot take the lock of {}: {error}", path.display()),
        }
    }
    fn walk(root: &Path, at: &Path, into: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                into.insert(relative, None);
                walk(root, &path, into);
            } else {
                into.insert(relative, Some(contents(&path)));
            }
        }
    }
    let mut into = BTreeMap::new();
    walk(root, root, &mut into);
    into
}

/// `tree` without the migration's journal, which the move adds.
fn data_tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut tree = tree(root);
    tree.remove(Path::new("identity-migration.json"));
    tree
}

/// The old lock files, by their path in a data root.
fn old_locks(root: &Path) -> [PathBuf; 3] {
    [root.join("ipc").join("lock"), root.join("sync.lock"), root.join("mcp-spawn.lock")]
}

/// The folders in `parent` whose names start with `prefix`.
fn named_like(parent: &Path, prefix: &str) -> Vec<PathBuf> {
    fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with(prefix))
        .collect()
}

/// Runs `f` with `folder` taking no new entries (Unix permissions); `None` for a user the permissions do not hold back (root), whose
/// test then has nothing to show.
#[cfg(unix)]
fn with_read_only<T>(folder: &Path, f: impl FnOnce() -> T) -> Option<T> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(folder, fs::Permissions::from_mode(0o555)).unwrap();
    let probe = folder.join(".write-probe");
    let held_back = fs::write(&probe, b"").is_err();
    let _ = fs::remove_file(&probe);
    let result = held_back.then(f);
    fs::set_permissions(folder, fs::Permissions::from_mode(0o755)).unwrap();
    result
}

#[test]
fn a_fresh_install_needs_nothing_and_creates_nothing() {
    let computer = Computer::new();
    assert_eq!(computer.run(Entry::Desktop), Outcome::NotNeeded);
    assert!(fs::read_dir(computer.local()).unwrap().next().is_none(), "nothing was created, not even a lock");
}

#[test]
fn moves_the_old_root_and_marks_done() {
    let computer = Computer::new().with_old_data();
    let before = tree(computer.old());
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(!computer.old().exists());
    assert_eq!(data_tree(computer.new_root()), before);
    let journal = computer.journal();
    for step in Step::FOLDERS {
        assert_eq!(journal.state(step), &StepState::Done, "{step:?}");
    }
    for step in Step::LATER {
        assert_eq!(journal.state(step), &StepState::Pending, "{step:?}");
    }
    assert!(computer.credentials_pending());
}

#[test]
fn an_empty_new_root_is_taken_over() {
    let computer = Computer::new().with_old_data();
    fs::create_dir(computer.new_root()).unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(computer.new_root().join("sync-state.json").is_file());
    assert!(!computer.old().exists());
}

#[test]
fn does_not_move_while_an_old_lock_is_held() {
    for index in 0..3 {
        let computer = Computer::new().with_old_data();
        let lock = old_locks(computer.old())[index].clone();
        let _held = hold(&lock);
        let before = tree(computer.old());
        let report = run(Entry::Desktop, &computer.roots, &QUICK);
        assert_eq!(report.outcome, DEFERRED, "{}", lock.display());
        let name = lock.strip_prefix(computer.old()).unwrap().to_string_lossy().replace('\\', "/");
        assert!(report.detail.as_deref().is_some_and(|detail| detail.contains(&name)), "{:?} names {name}", report.detail);
        assert!(!computer.new_root().exists(), "the new root is not created");
        assert_eq!(tree(computer.old()), before, "nothing in the old root changed");
    }
}

#[cfg(unix)]
#[test]
fn a_rename_that_fails_leaves_the_old_root_as_it_was() {
    let computer = Computer::new().with_old_data();
    // The lock file exists already, so a parent that takes no new entries still lets the migration take it.
    fs::write(locks::migration_lock_path(&computer.roots.data), b"").unwrap();
    let before = tree(computer.old());
    let Some(report) = with_read_only(&computer.local(), || run(Entry::Desktop, &computer.roots, &QUICK)) else { return };
    assert!(failed(&report.outcome, Step::DataRoot), "{report:?}");
    let refusal = report.refusal().unwrap();
    assert!(refusal.contains("cannot move") && !refusal.contains("Quit other Lunport windows"), "an I/O error blames nobody: {refusal}");
    assert!(!computer.new_root().exists());
    assert_eq!(tree(computer.old()), before, "not even the journal that was to travel with it stays behind");
}

#[test]
fn waits_for_an_earlier_version_that_is_quitting() {
    // The in-app update starts this version while the old one is still letting go of its locks.
    let computer = Computer::new().with_old_data();
    let held = hold(&computer.old().join("sync.lock"));
    let quitting = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
    });
    let waits = Waits { old_locks: Duration::from_secs(10), migration_lock: Duration::from_secs(10) };
    let began = Instant::now();
    assert_eq!(run(Entry::Desktop, &computer.roots, &waits).outcome, Outcome::CredentialsPending);
    assert!(began.elapsed() < Duration::from_secs(5), "it moved once the lock was free, without waiting it out");
    quitting.join().unwrap();
    assert!(computer.new_root().join("sync-state.json").is_file());
}

#[test]
fn connect_and_mcp_entries_also_migrate_or_refuse() {
    for entry in [Entry::Connect, Entry::Mcp] {
        let computer = Computer::new().with_old_data();
        {
            let _held = hold(&computer.old().join("mcp-spawn.lock"));
            let report = run(entry, &computer.roots, &QUICK);
            assert_eq!(report.outcome, DEFERRED, "{entry:?}");
            assert!(!computer.new_root().exists(), "{entry:?}");
            let refusal = report.refusal().expect("a client is told why it does not start");
            assert!(refusal.starts_with("lunport: "), "{refusal}");
            assert!(refusal.contains("mcp-spawn.lock") && refusal.contains("Quit other Lunport windows"), "{refusal}");
        }
        assert_eq!(computer.run(entry), Outcome::CredentialsPending, "{entry:?}");
        assert!(computer.new_root().join("vault.json").is_file(), "{entry:?}");
        assert!(!computer.old().exists(), "{entry:?}");
        assert!(run(entry, &computer.roots, &QUICK).refusal().is_none());
    }
}

#[test]
fn does_not_merge_two_populated_roots() {
    let computer = Computer::new().with_old_data();
    fs::create_dir_all(computer.new_root()).unwrap();
    fs::write(computer.new_root().join("sync-state.json"), br#"{"version":3,"device":"new"}"#).unwrap();
    let (old, new) = (tree(computer.old()), tree(computer.new_root()));
    for entry in [Entry::Desktop, Entry::Connect, Entry::Mcp] {
        let report = run(entry, &computer.roots, &QUICK);
        assert_eq!(report.outcome, computer.conflict(), "{entry:?}");
        assert!(report.refusal().is_some_and(|refusal| refusal.contains("choose which to keep")));
    }
    assert_eq!(tree(computer.old()), old, "the old root is untouched");
    assert_eq!(tree(computer.new_root()), new, "the new root is untouched");
}

#[test]
fn keeping_the_new_data_settles_the_conflict_and_leaves_the_old_root() {
    let computer = Computer::new().with_old_data();
    fs::create_dir_all(computer.new_root()).unwrap();
    fs::write(computer.new_root().join("sync-state.json"), b"new").unwrap();
    let old = tree(computer.old());
    assert_eq!(resolve(ConflictChoice::KeepNew, &computer.roots, &QUICK).outcome, Outcome::Completed);
    assert_eq!(tree(computer.old()), old);
    assert_eq!(fs::read(computer.new_root().join("sync-state.json")).unwrap(), b"new");
    // The kept data has its own credentials: none are carried over from the old service.
    assert!(!computer.credentials_pending());
    assert_eq!(computer.journal().state(Step::LoginItem), &StepState::Pending);
    assert_eq!(computer.run(Entry::Desktop), Outcome::Completed, "the conflict does not come back");
    assert_eq!(tree(computer.old()), old);
}

#[test]
fn using_the_old_data_backs_up_the_new_root_first() {
    let computer = Computer::new().with_old_data();
    fs::create_dir_all(computer.new_root()).unwrap();
    fs::write(computer.new_root().join("sync-state.json"), b"new").unwrap();
    let old = tree(computer.old());
    assert_eq!(resolve(ConflictChoice::UseOldData, &computer.roots, &QUICK).outcome, Outcome::CredentialsPending);
    assert!(computer.journal().use_old_data, "the choice is recorded for the folders still to move");
    assert_eq!(data_tree(computer.new_root()), old, "the old data took the new root's place");
    assert!(!computer.old().exists());
    let backups = named_like(&computer.local(), &format!("{NEW_ID}.backup-"));
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(fs::read(backups[0].join("sync-state.json")).unwrap(), b"new", "the new root's data was kept aside");
}

#[test]
fn using_the_old_data_sets_the_new_webkit_store_and_backups_aside_too() {
    let mut computer = Computer::new().with_old_data().with_old_webkit();
    fs::create_dir_all(computer.new_root()).unwrap();
    fs::write(computer.new_root().join("sync-state.json"), b"new").unwrap();
    fs::create_dir_all(&computer.webkit().new).unwrap();
    fs::write(computer.webkit().new.join("salt"), b"new store").unwrap();
    let backups = Move::named(&computer.temp.path().join("Roaming"), OLD_ID, NEW_ID);
    for (folder, contents) in [(&backups.old, "old backup"), (&backups.new, "new backup")] {
        fs::create_dir_all(folder.join("backups")).unwrap();
        fs::write(folder.join("backups").join("config.1.bak"), contents).unwrap();
    }
    computer.roots.backups = Some(backups.clone());
    assert_eq!(resolve(ConflictChoice::UseOldData, &computer.roots, &QUICK).outcome, Outcome::CredentialsPending);
    let webkit = computer.webkit().clone();
    assert_eq!(fs::read(webkit.new.join("WebsiteData").join("salt")).unwrap(), b"old store", "the old display settings came along");
    let aside = named_like(webkit.new.parent().unwrap(), &format!("{NEW_ID}.backup-"));
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert_eq!(fs::read(aside[0].join("salt")).unwrap(), b"new store", "the new store was renamed aside, not deleted");
    assert_eq!(fs::read(backups.new.join("backups").join("config.1.bak")).unwrap(), b"old backup");
    let aside = named_like(backups.new.parent().unwrap(), &format!("{NEW_ID}.backup-"));
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert_eq!(fs::read(aside[0].join("backups").join("config.1.bak")).unwrap(), b"new backup");
    assert!(!webkit.old.exists() && !backups.old.exists());
}

#[test]
fn the_choice_of_the_old_data_survives_a_stop_before_the_other_folders() {
    // The user chose the old data and the data root moved; the start stopped before the WebKit store (a crash, or a failure and Retry).
    let computer = Computer::new().with_old_webkit();
    let mut journal = journal_with(&[Step::DataRoot, Step::BackupsRoot]);
    journal.use_old_data = true;
    let computer = computer.moved_with(&journal);
    fs::create_dir_all(&computer.webkit().new).unwrap();
    fs::write(computer.webkit().new.join("salt"), b"new store").unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    let webkit = computer.webkit();
    assert_eq!(fs::read(webkit.new.join("WebsiteData").join("salt")).unwrap(), b"old store", "still the old data's settings");
    let aside = named_like(webkit.new.parent().unwrap(), &format!("{NEW_ID}.backup-"));
    assert_eq!(aside.len(), 1, "{aside:?}");
}

#[test]
fn the_choice_of_the_old_data_survives_a_stop_between_the_backup_and_the_rename() {
    // Using the old data wrote its journal, choice included, into the old root and set the new root aside; the start stopped before
    // the rename, with the new WebKit store still in place.
    let computer = Computer::new().with_old_data().with_old_webkit();
    let mut chosen = Journal::default();
    chosen.use_old_data = true;
    journal::write(computer.old(), &chosen).unwrap();
    let aside = computer.local().join(format!("{NEW_ID}.backup-1700000000000"));
    fs::create_dir_all(&aside).unwrap();
    fs::write(aside.join("sync-state.json"), b"new").unwrap();
    fs::create_dir_all(&computer.webkit().new).unwrap();
    fs::write(computer.webkit().new.join("salt"), b"new store").unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(computer.journal().use_old_data);
    let webkit = computer.webkit();
    assert_eq!(fs::read(webkit.new.join("WebsiteData").join("salt")).unwrap(), b"old store", "the old data's settings");
    assert_eq!(named_like(webkit.new.parent().unwrap(), &format!("{NEW_ID}.backup-")).len(), 1, "the new store set aside");
}

#[test]
fn the_choice_of_the_old_data_survives_a_rename_that_fails_after_the_backup() {
    let computer = Computer::new().with_old_data().with_old_webkit();
    fs::create_dir_all(computer.new_root()).unwrap();
    fs::write(computer.new_root().join("sync-state.json"), b"new").unwrap();
    fs::create_dir_all(&computer.webkit().new).unwrap();
    fs::write(computer.webkit().new.join("salt"), b"new store").unwrap();
    let report = data_root::with_failing_root_rename(|| resolve(ConflictChoice::UseOldData, &computer.roots, &QUICK));
    assert!(failed(&report.outcome, Step::DataRoot), "{report:?}");
    assert!(!computer.new_root().exists(), "the new root was set aside before the rename failed");
    assert!(journal::read(computer.old()).unwrap().is_some_and(|journal| journal.use_old_data), "the choice waits in the old root");
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    let webkit = computer.webkit();
    assert_eq!(fs::read(webkit.new.join("WebsiteData").join("salt")).unwrap(), b"old store");
    assert_eq!(named_like(webkit.new.parent().unwrap(), &format!("{NEW_ID}.backup-")).len(), 1);
}

#[test]
fn a_conflict_is_settled_only_when_nothing_holds_the_old_root() {
    let computer = Computer::new().with_old_data();
    fs::create_dir_all(computer.new_root()).unwrap();
    fs::write(computer.new_root().join("sync-state.json"), b"new").unwrap();
    let (old, new) = (tree(computer.old()), tree(computer.new_root()));
    let held = hold(&computer.old().join("ipc").join("lock"));
    assert_eq!(resolve(ConflictChoice::UseOldData, &computer.roots, &QUICK).outcome, DEFERRED);
    // What `resolve` did while the lock was held, looked at once it is let go of, as it was when the trees above were taken: a held file
    // reads as its marker.
    drop(held);
    assert_eq!(tree(computer.old()), old);
    assert_eq!(tree(computer.new_root()), new, "the new root was not set aside either");
}

#[test]
fn a_crash_between_the_backup_and_the_rename_finishes_on_the_next_start() {
    // Using the old data writes the journal into the old root, sets the new root aside, then renames: here the process stopped before
    // the rename.
    let computer = Computer::new().with_old_data();
    journal::write(computer.old(), &Journal::default()).unwrap();
    let aside = computer.local().join(format!("{NEW_ID}.backup-1700000000000"));
    fs::create_dir_all(&aside).unwrap();
    fs::write(aside.join("sync-state.json"), b"new").unwrap();
    let old = data_tree(computer.old());
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert_eq!(data_tree(computer.new_root()), old);
    assert!(computer.journal().all_done(&Step::FOLDERS));
    assert_eq!(fs::read(aside.join("sync-state.json")).unwrap(), b"new", "the backup stays");
}

#[test]
fn resumes_after_a_crash_between_steps() {
    // The data root moved and the folders are done; the process stopped before the credentials.
    let computer = Computer::new().moved_with(&journal_with(&Step::FOLDERS));
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(computer.credentials_pending(), "the vault still waits for its credentials");
    assert!(!computer.old().exists(), "no second move");
    // An earlier version that starts again recreates its data root: that is not a second migration.
    fs::create_dir_all(computer.old()).unwrap();
    fs::write(computer.old().join("mcp-spawn.lock"), b"").unwrap();
    fs::write(computer.old().join("sync-state.json"), b"recreated").unwrap();
    let (old, new) = (tree(computer.old()), tree(computer.new_root()));
    for entry in [Entry::Desktop, Entry::Connect, Entry::Mcp] {
        assert_eq!(computer.run(entry), Outcome::CredentialsPending, "{entry:?}");
    }
    assert_eq!(tree(computer.old()), old);
    assert_eq!(tree(computer.new_root()), new);
}

#[test]
fn a_crash_right_after_the_rename_resumes_from_the_journal_it_carried() {
    // The journal is written into the old root before the rename. A process stopped just after the rename leaves a new root whose
    // journal has nothing done.
    let computer = Computer::new().with_old_data().with_old_webkit();
    journal::write(computer.old(), &Journal::default()).unwrap();
    fs::rename(computer.old(), computer.new_root()).unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(computer.journal().all_done(&Step::FOLDERS));
    let webkit = computer.webkit();
    assert!(webkit.new.join("WebsiteData").is_dir() && !webkit.old.exists(), "the steps after the rename ran");
}

#[test]
fn a_move_by_another_process_between_the_fast_paths_two_looks_is_waited_for() {
    // Another process renames the old root (with its journal) between this start's look at the old root and its look at the journal;
    // its WebKit step has not run yet. This start must not take that for a fresh install.
    let computer = Computer::new().with_old_data().with_old_webkit();
    let (old, new) = (computer.old().to_path_buf(), computer.new_root().to_path_buf());
    let outcome = with_fast_path_gap(
        move || {
            if old.exists() {
                journal::write(&old, &Journal::default()).unwrap();
                fs::rename(&old, &new).unwrap();
            }
        },
        || computer.run(Entry::Desktop),
    );
    assert_eq!(outcome, Outcome::CredentialsPending);
    let webkit = computer.webkit();
    assert!(webkit.new.join("WebsiteData").is_dir() && !webkit.old.exists(), "the pending WebKit step ran");
}

#[test]
fn an_unreadable_journal_blocks_without_changing_anything() {
    // A journal kept the user's choice of the new data: a journal that cannot be read now must not turn into a fresh one.
    let computer = Computer::new().moved_with(&Journal::kept_new());
    let journal = journal::path(computer.new_root());
    let saved = fs::read(&journal).unwrap();
    fs::rename(&journal, computer.new_root().join("kept.json")).unwrap();
    fs::create_dir(&journal).unwrap();
    let report = run(Entry::Desktop, &computer.roots, &QUICK);
    assert!(failed(&report.outcome, Step::DataRoot), "{report:?}");
    assert!(computer.credentials_pending(), "nothing says the credentials moved");
    assert!(journal.is_dir(), "what stands in the journal's place is left alone");
    fs::remove_dir(&journal).unwrap();
    fs::rename(computer.new_root().join("kept.json"), &journal).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = fs::read(&journal).is_err();
        let report = run(Entry::Desktop, &computer.roots, &QUICK);
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        if unreadable {
            assert!(failed(&report.outcome, Step::DataRoot), "{report:?}");
        }
    }
    assert_eq!(fs::read(&journal).unwrap(), saved, "the kept choice survives");
    assert_eq!(computer.run(Entry::Desktop), Outcome::Completed);
}

#[test]
fn a_damaged_journal_still_means_the_root_moved_and_keeps_what_it_can() {
    let computer = Computer::new().moved_with(&Journal::default());
    // What a later version might write: a state this one does not know, beside the credentials it marked done.
    fs::write(
        journal::path(computer.new_root()),
        br#"{"data_root":"done","webkit_store":"skipped","credentials":"done","use_old_data":true,
            "credential_progress":{"vault_keys_moved":true,"kept":{"host:web-2":"it can never be read"}}}"#,
    )
    .unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::Completed);
    let journal = computer.journal();
    assert!(journal.is_done(Step::Credentials), "the credential step stays done");
    assert!(journal.use_old_data, "and so does the choice of the old data");
    assert!(journal.credential_progress.vault_keys_moved && journal.credential_progress.kept.contains_key("host:web-2"), "{journal:?}");
    assert!(journal.all_done(&Step::FOLDERS));
    let aside = named_like(computer.new_root(), "identity-migration.unreadable-");
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert!(fs::read_to_string(&aside[0]).unwrap().contains("skipped"), "the damaged journal is kept as it was");
    assert!(journal.notes.iter().any(|note| note.contains("could not be read")), "{:?}", journal.notes);

    let computer = Computer::new().moved_with(&Journal::default());
    fs::write(journal::path(computer.new_root()), b"not a journal").unwrap();
    assert!(computer.credentials_pending());
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(computer.journal().all_done(&Step::FOLDERS));
}

#[test]
fn a_salvaged_journal_is_written_back_even_when_no_step_is_left_to_run() {
    // A journal this version cannot read in full (a later version's value, after a downgrade, say) with every folder step done.
    let computer = Computer::new().moved_with(&Journal::default());
    fs::write(
        journal::path(computer.new_root()),
        br#"{"data_root":"done","backups_root":"done","webkit_store":"done","credentials":"pending","login_item":"skipped"}"#,
    )
    .unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    let journal = computer.journal();
    assert!(journal.all_done(&Step::FOLDERS) && !journal.is_done(Step::Credentials), "{journal:?}");
    assert!(computer.credentials_pending(), "the credentials still have to move");
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending, "the next start is no fresh install");
    assert_eq!(named_like(computer.new_root(), "identity-migration.unreadable-").len(), 1, "the damaged journal is kept, once");
}

#[test]
fn a_kept_new_choice_survives_a_journal_this_version_cannot_read() {
    // The user kept the new data; the old root stays beside it.
    let computer = Computer::new().with_old_data().moved_with(&Journal::default());
    fs::write(
        journal::path(computer.new_root()),
        br#"{"data_root":"done","backups_root":"done","webkit_store":"done","credentials":"done","login_item":"skipped"}"#,
    )
    .unwrap();
    let old = tree(computer.old());
    assert_eq!(computer.run(Entry::Desktop), Outcome::Completed);
    assert_eq!(computer.run(Entry::Desktop), Outcome::Completed, "the conflict does not come back");
    assert!(!computer.credentials_pending(), "nothing is carried over into the kept data");
    assert_eq!(tree(computer.old()), old);
}

#[test]
fn moves_windows_roaming_backups() {
    let mut computer = Computer::new().with_old_data();
    let backups = Move::named(&computer.temp.path().join("Roaming"), OLD_ID, NEW_ID);
    let backup = Path::new("backups").join("Users").join("frank").join(".ssh").join("config.1700000000000.bak");
    fs::create_dir_all(backups.old.join(&backup).parent().unwrap()).unwrap();
    fs::write(backups.old.join(&backup), b"Host web-1\n").unwrap();
    computer.roots.backups = Some(backups.clone());
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert_eq!(fs::read(backups.new.join(&backup)).unwrap(), b"Host web-1\n");
    assert!(!backups.old.exists());
    assert_eq!(computer.journal().state(Step::BackupsRoot), &StepState::Done);
}

#[test]
fn moves_the_macos_webkit_store() {
    let computer = Computer::new().with_old_data().with_old_webkit();
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    let webkit = computer.webkit();
    assert_eq!(fs::read(webkit.new.join("WebsiteData").join("salt")).unwrap(), b"old store");
    assert!(!webkit.old.exists());
    assert_eq!(computer.journal().state(Step::WebKitStore), &StepState::Done);
}

#[test]
fn a_folder_that_exists_under_both_names_is_kept_twice() {
    let computer = Computer::new().with_old_data().with_old_webkit();
    fs::create_dir_all(&computer.webkit().new).unwrap();
    fs::write(computer.webkit().new.join("new"), b"new").unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    let webkit = computer.webkit();
    assert_eq!(fs::read(webkit.old.join("WebsiteData").join("salt")).unwrap(), b"old store");
    assert_eq!(fs::read(webkit.new.join("new")).unwrap(), b"new");
    assert!(!webkit.new.join("WebsiteData").exists(), "nothing merged");
    let journal = computer.journal();
    assert_eq!(journal.state(Step::WebKitStore), &StepState::Done);
    assert!(journal.notes.iter().any(|note| note.contains("was kept")), "{:?}", journal.notes);
}

#[cfg(unix)]
#[test]
fn a_webkit_store_that_fails_to_move_is_retried_and_says_why() {
    let computer = Computer::new().with_old_data().with_old_webkit();
    let parent = computer.webkit().old.parent().unwrap().to_path_buf();
    let Some(report) = with_read_only(&parent, || run(Entry::Desktop, &computer.roots, &QUICK)) else { return };
    assert!(failed(&report.outcome, Step::WebKitStore), "{report:?}");
    assert!(matches!(computer.journal().state(Step::WebKitStore), StepState::Failed(_)));
    assert!(computer.new_root().join("vault.json").is_file(), "the data root moved before it");
    let status = MigrationStatus::of(Some(&report));
    assert_eq!((status.state, status.failed_step), (MigrationState::Deferred, Some(Step::WebKitStore)));
    assert!(status.detail.as_deref().is_some_and(|detail| detail.contains("cannot move")), "{status:?}");
    let refusal = report.refusal().unwrap();
    assert!(!refusal.contains("Quit other Lunport windows"), "an I/O error blames nobody: {refusal}");
    // Retried on the next start, once the folder can take it.
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(computer.webkit().new.join("WebsiteData").is_dir());
    assert_eq!(computer.journal().state(Step::WebKitStore), &StepState::Done);
}

#[cfg(unix)]
#[test]
fn a_failed_webkit_store_holds_back_only_the_desktop() {
    for entry in [Entry::Connect, Entry::Mcp] {
        let computer = Computer::new().with_old_data().with_old_webkit();
        let parent = computer.webkit().old.parent().unwrap().to_path_buf();
        let Some(outcome) = with_read_only(&parent, || computer.run(entry)) else { return };
        assert_eq!(outcome, Outcome::CredentialsPending, "{entry:?} never uses the WebKit store");
        assert!(matches!(computer.journal().state(Step::WebKitStore), StepState::Failed(_)), "{entry:?}");
        assert!(computer.webkit().old.join("WebsiteData").is_dir(), "left for the desktop");
        assert_eq!(computer.run(entry), Outcome::CredentialsPending, "{entry:?} does not retry it");
        assert!(computer.webkit().old.exists(), "{entry:?}");
        assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
        assert!(computer.webkit().new.join("WebsiteData").is_dir(), "the desktop moved it");
    }
}

#[cfg(unix)]
#[test]
fn a_failing_folder_can_stay_where_it_is() {
    let computer = Computer::new().with_old_data().with_old_webkit();
    let parent = computer.webkit().old.parent().unwrap().to_path_buf();
    let Some(outcome) = with_read_only(&parent, || computer.run(Entry::Desktop)) else { return };
    assert!(failed(&outcome, Step::WebKitStore), "{outcome:?}");
    let store = tree(&computer.webkit().old);
    assert!(failed(&skip(Step::DataRoot, &computer.roots, &QUICK).outcome, Step::DataRoot), "the data root has no way around it");
    let outcome = with_read_only(&parent, || skip(Step::WebKitStore, &computer.roots, &QUICK).outcome).unwrap();
    assert_eq!(outcome, Outcome::CredentialsPending);
    assert_eq!(tree(&computer.webkit().old), store, "the old store stays exactly where it was");
    assert!(!computer.webkit().new.exists());
    let journal = computer.journal();
    assert!(journal.is_done(Step::WebKitStore));
    assert!(journal.notes.iter().any(|note| note.contains("was left where it is")), "{:?}", journal.notes);
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending, "and it is not tried again");
    assert_eq!(tree(&computer.webkit().old), store);
}

#[test]
fn a_resumed_folder_step_waits_for_an_earlier_version_that_runs_again() {
    // The data root moved, the WebKit store did not; the earlier version has started again, recreated its data root and holds its
    // locks, and may be using its WebKit store.
    let computer = Computer::new().moved_with(&journal_with(&[Step::DataRoot, Step::BackupsRoot])).with_old_webkit();
    let _held = hold(&computer.old().join("ipc").join("lock"));
    assert_eq!(computer.run(Entry::Desktop), DEFERRED);
    assert!(computer.webkit().old.join("WebsiteData").is_dir() && !computer.webkit().new.exists(), "nothing moved under it");
    assert_eq!(computer.run(Entry::Connect), Outcome::CredentialsPending, "a client is not held back by the desktop's folders");
    assert!(computer.webkit().old.exists());
}

#[test]
fn folder_steps_with_nothing_to_move_do_not_wait_for_an_earlier_version() {
    // No roaming backups on this platform and no old WebKit store on this computer: an earlier version running again, with its data
    // root recreated, holds nothing these steps need.
    let mut computer = Computer::new().moved_with(&journal_with(&[Step::DataRoot]));
    computer.roots.webkit = Some(Move::named(&computer.temp.path().join("WebKit"), OLD_ID, NEW_ID));
    let _held = hold(&computer.old().join("ipc").join("lock"));
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(computer.journal().all_done(&Step::FOLDERS));
}

#[cfg(unix)]
#[test]
fn a_lock_probe_that_fails_names_a_folder_that_moves() {
    use std::os::unix::fs::PermissionsExt;
    // The earlier version's data root came back with a lock file this user cannot open. Only the WebKit store has a folder to move:
    // the roaming backups do not exist on this platform, so no way around them may be offered.
    let computer = Computer::new().moved_with(&journal_with(&[Step::DataRoot])).with_old_webkit();
    fs::create_dir_all(computer.old()).unwrap();
    let lock = computer.old().join("sync.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o000)).unwrap();
    let opens = File::open(&lock).is_ok();
    let report = run(Entry::Desktop, &computer.roots, &QUICK);
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    if opens {
        return; // A user the permissions do not hold back (root): nothing to show here.
    }
    assert!(failed(&report.outcome, Step::WebKitStore), "{report:?}");
    assert!(computer.webkit().old.join("WebsiteData").is_dir(), "nothing moved");
}

#[cfg(target_os = "macos")]
#[test]
fn copies_the_macos_preferences_and_never_replaces_new_ones() {
    // `defaults` takes a path for a domain: these stand for `~/Library/Preferences/<app id>.plist`.
    let write = |file: &Path, key: &str| {
        let mut settings = plist::Dictionary::new();
        settings.insert(key.into(), plist::Value::String("value".into()));
        plist::Value::Dictionary(settings).to_file_xml(file).unwrap();
    };
    let exported = |domain: &Path| {
        let output = std::process::Command::new("/usr/bin/defaults").arg("export").arg(domain).arg("-").output().unwrap();
        plist::Value::from_reader(std::io::Cursor::new(output.stdout)).unwrap().into_dictionary().unwrap()
    };
    let preferences = |computer: &Computer| {
        let folder = computer.temp.path().join("Preferences");
        fs::create_dir_all(&folder).unwrap();
        Preferences {
            old_domain: folder.join(OLD_ID).display().to_string(),
            new_domain: folder.join(NEW_ID).display().to_string(),
            old_file: folder.join(format!("{OLD_ID}.plist")),
        }
    };

    let mut computer = Computer::new().with_old_data();
    let copied = preferences(&computer);
    write(&copied.old_file, "NSNavLastRootDirectory");
    computer.roots.preferences = Some(copied.clone());
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(exported(Path::new(&copied.new_domain)).contains_key("NSNavLastRootDirectory"));

    let mut computer = Computer::new().with_old_data();
    let kept = preferences(&computer);
    write(&kept.old_file, "OldSetting");
    write(Path::new(&format!("{}.plist", kept.new_domain)), "NewSetting");
    computer.roots.preferences = Some(kept.clone());
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    let settings = exported(Path::new(&kept.new_domain));
    assert!(settings.contains_key("NewSetting") && !settings.contains_key("OldSetting"), "{settings:?}");
}

#[test]
fn rewrites_import_provenance_into_the_new_root() {
    use crate::sync::record_import::pending_journal_for_tests as pending;
    let computer = Computer::new().with_old_data();
    let ssh = computer.old().join("sandbox-home").join(".ssh");
    let (source, private) = (ssh.join("config"), ssh.join("id_ed25519"));
    let outside = computer.temp.path().join("home").join(".ssh").join("config");
    let (id, other) = ("0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210");
    let workspace = format!("server-workspace-{}", "ab".repeat(16));
    let journals = [
        (Path::new("imports").join(id), pending(id, &source, &private)),
        (Path::new(&workspace).join("imports").join(id), pending(id, &source, &private)),
        // Nothing of this one is in the old root.
        (Path::new("imports").join(other), pending(other, &outside, &outside)),
        // Not an import journal's place.
        (Path::new("elsewhere").join(id), pending(id, &source, &private)),
    ];
    for (folder, journal) in &journals {
        fs::create_dir_all(computer.old().join(folder)).unwrap();
        fs::write(computer.old().join(folder).join("journal.json"), journal).unwrap();
    }
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);

    let ssh = computer.new_root().join("sandbox-home").join(".ssh");
    for (folder, _) in &journals[..2] {
        let journal: serde_json::Value =
            serde_json::from_slice(&fs::read(computer.new_root().join(folder).join("journal.json")).unwrap()).unwrap();
        let path = |pointer: &str| PathBuf::from(journal.pointer(pointer).and_then(serde_json::Value::as_str).unwrap());
        assert_eq!(path("/source"), ssh.join("config"));
        assert_eq!(path("/options/home"), ssh);
        assert_eq!(path("/provenance/0/path"), ssh.join("config"));
        assert_eq!(path("/provenance/0/canonical_path"), ssh.join("config"));
        assert_eq!(path(&format!("/copies/{id}/source")), ssh.join("id_ed25519"));
        assert_eq!(path(&format!("/copies/{id}/canonical_source")), ssh.join("id_ed25519"));
    }
    for (folder, journal) in &journals[2..] {
        assert_eq!(&fs::read(computer.new_root().join(folder).join("journal.json")).unwrap(), journal, "{}", folder.display());
    }
}

#[test]
fn dev_profile_move_is_allowed_by_the_write_policy() {
    let computer = Computer::new().with_old_data();
    let before = tree(computer.old());
    let policy = WritePolicy::Confined { root: computer.new_root().to_path_buf() };
    crate::fsutil::with_test_write_policy(policy, || {
        assert!(crate::fsutil::check_write(computer.old()).is_err(), "outside a migration the old root is out of bounds");
        assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
        assert!(crate::fsutil::check_write(computer.old()).is_err(), "and so it is again afterwards");
        assert!(crate::fsutil::check_write(&computer.local().join("elsewhere")).is_err());
    });
    assert_eq!(data_tree(computer.new_root()), before);
    assert!(!computer.old().exists());
}

#[test]
fn the_dev_exception_covers_only_the_move() {
    let computer = Computer::new().with_old_data();
    let root = computer.new_root().to_path_buf();
    let policy = WritePolicy::Confined { root: root.clone() };
    let legacy = computer.old();
    let allowed = |path: &Path| policy.check_root_move(path, legacy).is_ok();
    assert!(allowed(legacy) && allowed(&legacy.join("identity-migration.json")));
    assert!(allowed(&root) && allowed(&root.join("vault.json")));
    assert!(allowed(&computer.local().join(format!("{NEW_ID}.migration.lock"))));
    assert!(allowed(&computer.local().join(format!("{NEW_ID}.backup-1700000000000"))));
    for refused in [
        computer.local().join("another-app"),
        computer.local().join(format!("{NEW_ID}.backup-")),
        computer.local().join(format!("{NEW_ID}.backup-x")),
        computer.local().join(format!("{OLD_ID}.migration.lock")),
        computer.temp.path().join("elsewhere"),
    ] {
        assert!(!allowed(&refused), "{}", refused.display());
    }
    // A legacy root that is not beside the root is no exception at all.
    let stray = computer.temp.path().join(OLD_ID);
    assert!(policy.check_root_move(&stray, &stray).is_err());
    #[cfg(unix)]
    {
        // A link in the legacy root's place would become the root itself.
        let elsewhere = computer.temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let linked = computer.local().join("linked");
        std::os::unix::fs::symlink(&elsewhere, &linked).unwrap();
        assert!(policy.check_root_move(&linked, &linked).is_err());
        assert!(policy.check_root_move(&linked.join("file"), &linked).is_err());
    }
}

#[test]
fn retires_the_credential_helper_v1_and_the_bridge_only_once_credentials_moved() {
    let computer = Computer::new().with_old_data();
    for folder in ["v1", "v2", "bridge"] {
        fs::create_dir_all(computer.old().join("credential-helper").join(folder)).unwrap();
        fs::write(computer.old().join("credential-helper").join(folder).join("program"), b"program").unwrap();
    }
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    let helpers = computer.new_root().join("credential-helper");
    for folder in ["v1", "bridge"] {
        assert!(helpers.join(folder).join("program").is_file(), "the credentials may still need {folder}");
    }

    let mut journal = computer.journal();
    journal.set(Step::Credentials, StepState::Done);
    journal::write(computer.new_root(), &journal).unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::Completed);
    assert!(!helpers.join("v1").exists() && !helpers.join("bridge").exists());
    assert!(helpers.join("v2").join("program").is_file());
    assert!(!computer.credentials_pending());
}

#[test]
fn credentials_are_pending_wherever_they_may_still_be_under_the_old_name() {
    // Not moved yet.
    let computer = Computer::new().with_old_data();
    assert!(computer.credentials_pending());
    // Deferred: an earlier version runs.
    {
        let _held = hold(&computer.old().join("sync.lock"));
        assert_eq!(computer.run(Entry::Desktop), DEFERRED);
        assert!(computer.credentials_pending());
    }
    // In conflict.
    let conflict = Computer::new().with_old_data();
    fs::create_dir_all(conflict.new_root()).unwrap();
    fs::write(conflict.new_root().join("sync-state.json"), b"new").unwrap();
    assert_eq!(conflict.run(Entry::Desktop), conflict.conflict());
    assert!(conflict.credentials_pending());
    // Neither root: a fresh install has no credentials anywhere else.
    assert!(!Computer::new().credentials_pending());
    // A blocked start says so whatever is on disk, before it looks at any folder.
    let blocked = Report::busy(&computer.roots.data, "sync.lock");
    assert!(with_test_last(Some((Entry::Desktop, blocked)), || credentials_now().0));
}

#[test]
fn clients_reach_the_data_root_only_once_it_is_in_place() {
    let computer = Computer::new().with_old_data();
    let busy = Report::busy(&computer.roots.data, "ipc/lock");
    // No migration ran in this process (a test, say): nothing to refuse.
    assert_eq!(with_test_last(None, || ensure_ready_with(|_| panic!("nothing to run again"))), Ok(()));
    // `connect` reports what its start found, without running it again.
    let refused = with_test_last(Some((Entry::Connect, busy.clone())), || ensure_ready_with(|_| panic!("connect runs once")));
    assert_eq!(refused, Err(busy.refusal().unwrap()));
    // The one way to the data root (`cli::reach_broker`) asks first, and never reaches the socket path or the spawn lock on a refusal.
    // The way itself is a stand-in, and so is the run again: no test may touch the real data root or start a process.
    let ready = || ensure_ready_with(|_| panic!("connect runs once"));
    let reached = with_test_last(Some((Entry::Connect, busy.clone())), || {
        crate::cli::gated(ready, || -> Result<(), String> { panic!("the data root was reached") })
    });
    assert_eq!(reached, Err(busy.refusal().unwrap()));
    assert_eq!(with_test_last(None, || crate::cli::gated(ready, || Ok("reached"))), Ok("reached"));
    // The MCP adapter runs it again: still held, then free.
    let held = hold(&computer.old().join("ipc").join("lock"));
    let still = with_test_last(Some((Entry::Mcp, busy.clone())), || {
        ensure_ready_with(|entry| Some(run(entry, &computer.roots, &QUICK)))
    });
    assert!(still.is_err_and(|refusal| refusal.contains("ipc/lock")));
    drop(held);
    let (ready, recorded) = with_test_last(Some((Entry::Mcp, busy)), || {
        (ensure_ready_with(|entry| Some(run(entry, &computer.roots, &QUICK))), last())
    });
    assert_eq!(ready, Ok(()));
    assert_eq!(recorded.map(|(_, report)| report.outcome), Some(Outcome::CredentialsPending), "the new run is the one recorded");
    assert!(computer.new_root().join("vault.json").is_file());
}

/// A start that an earlier Lunport blocked keeps its window, which says why. The user quits the earlier Lunport and starts this one
/// again: that start moves the folders before it hands over, and the blocked start restarts into the app instead of showing what no
/// longer holds. A hand-over that finds the folders still not in place (the earlier version still runs, or both roots hold data)
/// changes nothing.
#[test]
fn a_blocked_start_restarts_once_another_start_moved_the_folders() {
    let computer = Computer::new().with_old_data();
    let held = hold(&computer.old().join("sync.lock"));
    let blocked = run(Entry::Desktop, &computer.roots, &QUICK);
    assert_eq!(blocked.outcome, DEFERRED);
    let refreshed = |computer: &Computer, blocked: &Report| with_test_last(Some((Entry::Desktop, blocked.clone())), || refresh_in(&computer.roots));
    // Started again while the earlier version still runs: nothing moved.
    assert_eq!(computer.run(Entry::Desktop), DEFERRED);
    assert!(!refreshed(&computer, &blocked));
    drop(held);
    // Started again once it quit: the folders are in place.
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(refreshed(&computer, &blocked));
    // A start that found both roots holding data is still blocked after another such start.
    let conflict = Computer::new().with_old_data();
    fs::create_dir_all(conflict.new_root()).unwrap();
    fs::write(conflict.new_root().join("sync-state.json"), b"new").unwrap();
    let blocked = run(Entry::Desktop, &conflict.roots, &QUICK);
    assert_eq!(conflict.run(Entry::Desktop), conflict.conflict());
    assert!(!refreshed(&conflict, &blocked));
    // The data root moved, but a folder after it has not: the desktop stays blocked.
    let webkit = Computer::new().with_old_webkit().moved_with(&journal_with(&[Step::DataRoot, Step::BackupsRoot]));
    assert!(!refreshed(&webkit, &Report::failed(Step::WebKitStore, "cannot move it")));
}

#[test]
fn both_ways_to_the_broker_ask_the_migration_first() {
    // `cli::reach_broker` (Unix and Windows) goes through `through_gate`, the gate with this process's own migration in it. Only the
    // way on is a stand-in; `connect` does not run the migration again, and a test that did would stop at `Roots::current`.
    let busy = Report::busy(&Move::named(Path::new("/data"), OLD_ID, NEW_ID), "ipc/lock");
    let reached =
        with_test_last(Some((Entry::Connect, busy.clone())), || crate::cli::through_gate(|| -> Result<(), String> { panic!("reached") }));
    assert_eq!(reached, Err(busy.refusal().unwrap()));
    assert_eq!(with_test_last(None, || crate::cli::through_gate(|| Ok("reached"))), Ok("reached"));
}

#[test]
#[should_panic(expected = "real data folders")]
fn no_test_reaches_this_computers_data_folders() {
    // They hold the owner's own data: a run against them in a test would move it.
    let _ = Roots::current();
}

#[test]
fn a_folder_that_appears_after_the_lock_check_stays_where_it_is() {
    // The data root moved; an earlier version runs again, with its data root recreated and its locks held. No old WebKit store was
    // there when this start looked, so it took no lock, and the earlier version makes one just then: it stays where it is.
    let mut computer = Computer::new().moved_with(&journal_with(&[Step::DataRoot, Step::BackupsRoot]));
    let webkit = Move::named(&computer.temp.path().join("WebKit"), OLD_ID, NEW_ID);
    computer.roots.webkit = Some(webkit.clone());
    let _held = hold(&computer.old().join("ipc").join("lock"));
    let store = webkit.old.join("WebsiteData");
    let made = store.clone();
    let outcome = with_folder_check_gap(move || fs::create_dir_all(&made).unwrap(), || computer.run(Entry::Desktop));
    assert_eq!(outcome, Outcome::CredentialsPending);
    assert!(store.is_dir() && !webkit.new.exists(), "nothing moved that no lock covered");
    assert!(computer.journal().is_done(Step::WebKitStore), "there was nothing to move when it looked");
}

#[test]
fn the_choice_of_the_old_data_survives_a_journal_this_version_cannot_read_in_full() {
    // A later version recorded the user's choice of the old data in the old root's journal, with a state this one does not know, and
    // set the new root aside; it stopped before the rename, and this version starts.
    let computer = Computer::new().with_old_data().with_old_webkit();
    fs::write(journal::path(computer.old()), br#"{"data_root":"pending","webkit_store":"skipped","use_old_data":true}"#).unwrap();
    fs::create_dir_all(&computer.webkit().new).unwrap();
    fs::write(computer.webkit().new.join("salt"), b"new store").unwrap();
    assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
    assert!(computer.journal().use_old_data, "the choice travelled with the data");
    let webkit = computer.webkit();
    assert_eq!(fs::read(webkit.new.join("WebsiteData").join("salt")).unwrap(), b"old store", "the old data's settings");
    assert_eq!(named_like(webkit.new.parent().unwrap(), &format!("{NEW_ID}.backup-")).len(), 1, "the new store set aside");
}

#[test]
fn main_runs_the_migration_for_the_entry_it_dispatches_to() {
    use std::ffi::OsStr;
    assert_eq!(entry_for(Some(OsStr::new("connect"))), Entry::Connect);
    assert_eq!(entry_for(Some(OsStr::new("--mcp"))), Entry::Mcp);
    for desktop in [None, Some("--host"), Some("--mcp-host"), Some("--window-diagnostics"), Some("Connect"), Some("")] {
        assert_eq!(entry_for(desktop.map(OsStr::new)), Entry::Desktop, "{desktop:?}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(entry_for(Some(OsStr::from_bytes(b"connect\xff"))), Entry::Desktop, "an argument that is not UTF-8");
    }
}

#[test]
fn the_outcome_waits_for_the_folders_an_entry_needs_and_the_credentials() {
    let mut journal = Journal::default();
    assert_eq!(journal.outcome(&Step::FOLDERS), Outcome::CredentialsPending);
    journal = journal_with(&[Step::DataRoot, Step::BackupsRoot, Step::WebKitStore, Step::Credentials]);
    assert_eq!(journal.outcome(&Step::FOLDERS), Outcome::Completed, "the login item and the MCP settings never hold it back");
    journal.set(Step::WebKitStore, StepState::Failed("busy".into()));
    assert_eq!(journal.outcome(&Step::FOLDERS), Outcome::CredentialsPending);
    assert_eq!(journal.outcome(folders_for(Entry::Connect)), Outcome::Completed, "a client never needs the WebKit store");
}

#[test]
fn the_journal_keeps_every_state_and_reads_a_missing_step_as_pending() {
    let temp = tempfile::tempdir().unwrap();
    let mut written = Journal::default();
    written.set(Step::DataRoot, StepState::Done);
    written.set(Step::WebKitStore, StepState::Failed("the store is busy".into()));
    written.notes.push("a note".into());
    journal::write(temp.path(), &written).unwrap();
    assert_eq!(journal::read(temp.path()).unwrap(), Some(written));
    fs::write(journal::path(temp.path()), br#"{"data_root":"done"}"#).unwrap();
    let read = journal::read(temp.path()).unwrap().unwrap();
    assert!(read.is_done(Step::DataRoot) && *read.state(Step::Credentials) == StepState::Pending);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        journal::write(temp.path(), &read).unwrap();
        assert_eq!(fs::metadata(journal::path(temp.path())).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn the_journal_keeps_what_the_mcp_settings_move_did() {
    let temp = tempfile::tempdir().unwrap();
    let mut written = journal_with(&[Step::DataRoot]);
    let failed = McpFailure { client: Some(SetupClient::ClaudeDesktop), reason: "the file is busy".into() };
    let dismissed = Some(vec![None, Some(SetupClient::ClaudeDesktop)]);
    written.mcp_progress = McpProgress { updated: vec![SetupClient::Codex], failed: vec![failed], dismissed };
    journal::write(temp.path(), &written).unwrap();
    assert_eq!(journal::read(temp.path()).unwrap(), Some(written.clone()));
    journal::write(temp.path(), &journal_with(&[Step::DataRoot])).unwrap();
    assert!(!fs::read_to_string(journal::path(temp.path())).unwrap().contains("mcp_progress"), "nothing to keep, nothing written");
    let mut only_dismissed = journal_with(&[Step::DataRoot]);
    only_dismissed.mcp_progress.dismissed = Some(Vec::new());
    journal::write(temp.path(), &only_dismissed).unwrap();
    assert_eq!(journal::read(temp.path()).unwrap(), Some(only_dismissed), "a dismissal alone is kept");
    // A journal this version cannot read in full keeps it too.
    let mut later = serde_json::to_value(&written).unwrap();
    later["webkit_store"] = serde_json::json!("skipped");
    fs::write(journal::path(temp.path()), serde_json::to_vec(&later).unwrap()).unwrap();
    assert_eq!(journal::salvage(temp.path()).unwrap().mcp_progress, written.mcp_progress);
}

/// The launch-at-login entry moves on a desktop start once the folders are in place, whether the old entry is on read again on every
/// attempt: one that fails is tried again by the next desktop start, which reads it again (the user may have turned it off meanwhile).
/// `connect` and the MCP adapter leave it to the desktop, and nothing else waits for it.
#[test]
fn the_login_item_moves_on_desktop_starts_reading_again_whether_it_was_on() {
    let computer = Computer::new().with_old_data();
    let asked = Rc::new(RefCell::new(Vec::<String>::new()));
    let on = RefCell::new(VecDeque::from([true, false]));
    let busy = Rc::new(Cell::new(true));
    let (read_asked, move_asked, move_busy) = (Rc::clone(&asked), Rc::clone(&asked), Rc::clone(&busy));
    login_item::with_test_entries(
        move || {
            read_asked.borrow_mut().push("is the old entry on".into());
            Ok(on.borrow_mut().pop_front().expect("one read per attempt"))
        },
        move |enabled_before| {
            move_asked.borrow_mut().push(format!("move ({enabled_before})"));
            if move_busy.get() {
                Err(AppError::Other("the launch agents folder is busy".into()))
            } else {
                Ok(())
            }
        },
        || {
            for entry in [Entry::Connect, Entry::Mcp] {
                assert_eq!(computer.run(entry), Outcome::CredentialsPending, "{entry:?}");
            }
            assert!(asked.borrow().is_empty(), "connect and the MCP adapter leave it to the desktop");
            let report = run(Entry::Desktop, &computer.roots, &QUICK);
            assert_eq!(report.outcome, Outcome::CredentialsPending, "a failure holds nothing back");
            assert!(matches!(computer.journal().state(Step::LoginItem), StepState::Failed(reason) if reason.contains("busy")));
            busy.set(false);
            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            assert_eq!(computer.journal().state(Step::LoginItem), &StepState::Done);
            assert_eq!(*asked.borrow(), ["is the old entry on", "move (true)", "is the old entry on", "move (false)"]);
            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            assert_eq!(asked.borrow().len(), 4, "done: later starts leave it alone");
        },
    );
}

/// What the window says of the MCP settings on `computer` (`identity_migration_mcp_settings`).
fn mcp_notice(computer: &Computer) -> Option<McpNotice> {
    mcp_configs::notice_in(&computer.roots)
}

/// Dismisses the notice on `computer` as the window does, having seen what it said fail.
fn dismiss_mcp_notice(computer: &Computer) {
    let seen: Vec<_> = mcp_notice(computer).expect("a notice to dismiss").failed.iter().map(|failed| failed.client).collect();
    mcp_configs::dismiss_in(&computer.roots, &seen, QUICK.migration_lock).unwrap();
}

/// The AI clients' MCP settings move on a desktop start once the data root is in place, where their backups go. A client that fails
/// keeps the step for the next desktop start, and the clients that moved stay named: the window hears of every client moved so far and
/// of the ones that failed. `connect` and the MCP adapter leave it to the desktop, and nothing else waits for it.
#[test]
fn the_mcp_settings_move_on_desktop_starts_until_no_client_fails() {
    let computer = Computer::new().with_old_data();
    let attempts = Rc::new(RefCell::new(VecDeque::from([
        mcp_configs::Moved { updated: vec![SetupClient::Codex], failed: vec![(SetupClient::ClaudeCode, "the file is busy".into())] },
        mcp_configs::Moved { updated: vec![SetupClient::ClaudeCode], failed: vec![] },
    ])));
    let left = Rc::clone(&attempts);
    mcp_configs::with_test_settings(
        move || Ok(left.borrow_mut().pop_front().expect("one move per attempt")),
        || {
            for entry in [Entry::Connect, Entry::Mcp] {
                assert_eq!(computer.run(entry), Outcome::CredentialsPending, "{entry:?}");
            }
            assert_eq!(attempts.borrow().len(), 2, "connect and the MCP adapter leave it to the desktop");

            let report = run(Entry::Desktop, &computer.roots, &QUICK);
            assert_eq!(report.outcome, Outcome::CredentialsPending, "a client that failed holds nothing back");
            let failed = McpFailure { client: Some(SetupClient::ClaudeCode), reason: "the file is busy".into() };
            let first = McpNotice { updated: vec![SetupClient::Codex], failed: vec![failed] };
            assert_eq!(mcp_notice(&computer), Some(first));
            let journal = computer.journal();
            assert!(matches!(journal.state(Step::McpConfigs), StepState::Failed(reason) if reason.contains("Claude Code")), "{journal:?}");

            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            let both = McpNotice { updated: vec![SetupClient::Codex, SetupClient::ClaudeCode], failed: vec![] };
            assert_eq!(mcp_notice(&computer), Some(both.clone()));
            assert_eq!(computer.journal().state(Step::McpConfigs), &StepState::Done);

            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            assert!(attempts.borrow().is_empty(), "done: later starts leave it alone");
            assert_eq!(mcp_notice(&computer), Some(both), "and still say it, until it is dismissed");
        },
    );
}

/// After an upgrade the window reminds the user to add Lunport to Cursor and VS Code again even when no client's settings changed, on
/// every start until the user dismisses it; a fresh install never hears of it.
#[test]
fn the_reminder_follows_every_upgrade_until_it_is_dismissed() {
    let fresh = Computer::new();
    assert_eq!(fresh.run(Entry::Desktop), Outcome::NotNeeded);
    assert_eq!(mcp_notice(&fresh), None, "a fresh install");
    let computer = Computer::new().with_old_data();
    mcp_configs::with_test_settings(
        || Ok(mcp_configs::Moved::default()),
        || {
            let reminder = McpNotice { updated: vec![], failed: vec![] };
            for _ in 0..2 {
                assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
                assert_eq!(mcp_notice(&computer), Some(reminder.clone()));
            }
            dismiss_mcp_notice(&computer);
            assert_eq!(mcp_notice(&computer), None);
            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            assert_eq!(mcp_notice(&computer), None, "and stays dismissed");
        },
    );
}

/// A client that keeps failing does not bring a dismissed notice back, whatever its reason says now, while the step keeps trying it on
/// every desktop start; a client that newly fails does bring it back, and one that stops failing does not.
#[test]
fn a_dismissed_notice_comes_back_only_for_a_client_that_newly_fails() {
    let computer = Computer::new().with_old_data();
    let failing = Rc::new(RefCell::new(vec![(SetupClient::ClaudeCode, "its settings file is a symbolic link".to_string())]));
    let attempts = Rc::new(Cell::new(0));
    let (now_failing, counted) = (Rc::clone(&failing), Rc::clone(&attempts));
    mcp_configs::with_test_settings(
        move || {
            counted.set(counted.get() + 1);
            Ok(mcp_configs::Moved { updated: vec![], failed: now_failing.borrow().clone() })
        },
        || {
            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            dismiss_mcp_notice(&computer);
            *failing.borrow_mut() = vec![(SetupClient::ClaudeCode, "the file is busy".into())];
            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            assert_eq!(attempts.get(), 2, "the step keeps trying");
            assert_eq!(mcp_notice(&computer), None, "the same client, another reason: not said again");

            failing.borrow_mut().push((SetupClient::Codex, "the file is busy".into()));
            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            let clients: Vec<_> = mcp_notice(&computer).expect("a new failure is said").failed.iter().map(|failed| failed.client).collect();
            assert_eq!(clients, [Some(SetupClient::ClaudeCode), Some(SetupClient::Codex)]);
            dismiss_mcp_notice(&computer);

            failing.borrow_mut().pop();
            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            assert_eq!(mcp_notice(&computer), None, "a client that stopped failing says nothing new");
        },
    );
}

/// The window's Retry moves what an earlier version held back, the MCP settings included, and restarts the app: the restarted
/// process, which takes the fast path, still says what the move did.
#[test]
fn the_notice_survives_the_restart_after_a_retry() {
    let computer = Computer::new().with_old_data();
    mcp_configs::with_test_settings(
        || Ok(mcp_configs::Moved { updated: vec![SetupClient::Codex], failed: vec![] }),
        || {
            let held = hold(&computer.old().join("ipc").join("lock"));
            assert_eq!(computer.run(Entry::Desktop), DEFERRED);
            assert_eq!(mcp_notice(&computer), None, "nothing has moved yet");
            drop(held);
            // `identity_migration_retry`, then `app.restart()`.
            assert_eq!(run(Entry::Desktop, &computer.roots, &STARTUP).outcome, Outcome::CredentialsPending);
            assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending);
            assert_eq!(mcp_notice(&computer), Some(McpNotice { updated: vec![SetupClient::Codex], failed: vec![] }));
        },
    );
}

/// The dismissal waits for the migration's lock, as every write of the journal does: while another process holds it, nothing is
/// recorded and the window hears why.
#[test]
fn a_dismissal_waits_for_the_migrations_lock() {
    let computer = Computer::new().moved_with(&journal_with(&Step::FOLDERS));
    let held = locks::take_migration_lock(&computer.roots.data, Duration::ZERO).unwrap().expect("the lock is free");
    assert!(mcp_configs::dismiss_in(&computer.roots, &[], QUICK.migration_lock).is_err());
    assert_eq!(computer.journal().mcp_progress.dismissed, None);
    drop(held);
    mcp_configs::dismiss_in(&computer.roots, &[], QUICK.migration_lock).unwrap();
    assert_eq!(computer.journal().mcp_progress.dismissed, Some(vec![]));
    // Nothing moved on a fresh install: nothing to dismiss, and nothing is created, not even the lock.
    let fresh = Computer::new();
    mcp_configs::dismiss_in(&fresh.roots, &[], QUICK.migration_lock).unwrap();
    assert!(fs::read_dir(fresh.local()).unwrap().next().is_none());
}

/// A lock that cannot be taken at all is said as such, not as another process holding it.
#[test]
fn a_dismissal_says_why_the_lock_could_not_be_taken() {
    let computer = Computer::new().moved_with(&journal_with(&Step::FOLDERS));
    fs::create_dir_all(locks::migration_lock_path(&computer.roots.data)).unwrap();
    let error = mcp_configs::dismiss_in(&computer.roots, &[], QUICK.migration_lock).unwrap_err().to_string();
    assert!(!error.contains("Another Lunport") && error.contains("lock"), "{error}");
    assert_eq!(computer.journal().mcp_progress.dismissed, None);
}

/// A dismissal keeps only what can fail, each once, whatever the window sends: the journal stays small.
#[test]
fn a_dismissal_keeps_each_failing_entry_once() {
    let computer = Computer::new().moved_with(&journal_with(&Step::FOLDERS));
    let mut sent = vec![Some(SetupClient::Cursor), Some(SetupClient::ClaudeCode), None, Some(SetupClient::Codex)];
    sent.extend(std::iter::repeat_n(Some(SetupClient::ClaudeCode), 10_000));
    sent.extend(std::iter::repeat_n(None, 10_000));
    mcp_configs::dismiss_in(&computer.roots, &sent, QUICK.migration_lock).unwrap();
    assert_eq!(computer.journal().mcp_progress.dismissed, Some(vec![None, Some(SetupClient::Codex), Some(SetupClient::ClaudeCode)]));
}

/// The MCP settings never move before the data root, where their backups go: not while an earlier version holds the old root, nor
/// while both roots hold data.
#[test]
fn the_mcp_settings_wait_for_the_data_root() {
    mcp_configs::with_test_settings(
        || panic!("the MCP settings moved before the data root"),
        || {
            let computer = Computer::new().with_old_data();
            let held = hold(&computer.old().join("sync.lock"));
            assert_eq!(computer.run(Entry::Desktop), DEFERRED);
            drop(held);
            let conflict = Computer::new().with_old_data();
            fs::create_dir_all(conflict.new_root()).unwrap();
            fs::write(conflict.new_root().join("sync-state.json"), b"new").unwrap();
            assert_eq!(conflict.run(Entry::Desktop), conflict.conflict());
        },
    );
}

/// However often they fail, the launch-at-login entry and the MCP settings never hold back the outcome or the start, nor send
/// `connect` and the MCP adapter past their fast path.
#[test]
fn the_login_item_and_the_mcp_settings_never_hold_back_the_outcome() {
    let computer =
        Computer::new().moved_with(&journal_with(&[Step::DataRoot, Step::BackupsRoot, Step::WebKitStore, Step::Credentials]));
    login_item::with_test_entries(
        || Ok(true),
        |_| Err(AppError::Other("the launch agents folder is busy".into())),
        || {
            mcp_configs::with_test_settings(
                || Err(AppError::Other("cannot determine home directory".into())),
                || {
                    for _ in 0..2 {
                        let report = run(Entry::Desktop, &computer.roots, &QUICK);
                        assert_eq!(report.outcome, Outcome::Completed);
                        assert!(!report.outcome.blocks_startup() && report.refusal().is_none());
                    }
                    let journal = computer.journal();
                    for step in [Step::LoginItem, Step::McpConfigs] {
                        assert!(matches!(journal.state(step), StepState::Failed(_)), "{step:?}: {journal:?}");
                    }
                    for entry in [Entry::Connect, Entry::Mcp] {
                        assert_eq!(computer.run(entry), Outcome::Completed, "{entry:?}");
                    }
                },
            );
        },
    );
}

/// While another process holds the migration's lock, a start whose folders are in place does not wait for steps that never hold a start
/// back: it goes on as the journal is and leaves them to a later start. `connect` and the MCP adapter take the fast path as well.
#[test]
fn steps_that_never_hold_a_start_back_do_not_wait_for_the_migrations_lock() {
    let computer = Computer::new().moved_with(&journal_with(&Step::FOLDERS));
    let waits = Waits { old_locks: Duration::from_secs(10), migration_lock: Duration::from_secs(10) };
    login_item::with_test_entries(
        || panic!("the login item moved under another process's lock"),
        |_| panic!("the login item moved under another process's lock"),
        || {
            mcp_configs::with_test_settings(
                || panic!("the MCP settings moved under another process's lock"),
                || {
                    let _held = locks::take_migration_lock(&computer.roots.data, Duration::ZERO).unwrap().expect("the lock is free");
                    for entry in [Entry::Desktop, Entry::Connect, Entry::Mcp] {
                        let began = Instant::now();
                        let report = run(entry, &computer.roots, &waits);
                        assert_eq!(report.outcome, Outcome::CredentialsPending, "{entry:?}");
                        assert!(began.elapsed() < Duration::from_secs(2), "{entry:?} waited for the lock");
                    }
                    let journal = computer.journal();
                    for step in [Step::LoginItem, Step::McpConfigs] {
                        assert_eq!(journal.state(step), &StepState::Pending, "{step:?} is left for a later start");
                    }
                },
            );
        },
    );
}

/// A step that never holds a start back and whose record cannot be saved blocks nothing either: it runs again on a later start.
#[cfg(unix)]
#[test]
fn a_record_that_cannot_be_saved_after_a_step_that_never_holds_a_start_back_blocks_nothing() {
    let computer =
        Computer::new().moved_with(&journal_with(&[Step::DataRoot, Step::BackupsRoot, Step::WebKitStore, Step::Credentials]));
    let moved = || Ok(mcp_configs::Moved { updated: vec![SetupClient::Codex], failed: vec![] });
    let Some(report) =
        with_read_only(computer.new_root(), || mcp_configs::with_test_settings(moved, || run(Entry::Desktop, &computer.roots, &QUICK)))
    else {
        return;
    };
    assert_eq!(report.outcome, Outcome::Completed, "{report:?}");
    assert!(report.refusal().is_none());
    assert_eq!(computer.journal().state(Step::McpConfigs), &StepState::Pending, "left for a later start");
}

/// The window reads the notice from the journal of this computer's data root, whatever start moved the settings, and nothing while
/// this start is blocked (its window shows why instead, and reads no folder).
#[test]
fn the_window_reads_the_notice_from_the_journal() {
    let computer = Computer::new().with_old_data();
    mcp_configs::with_test_settings(
        || Ok(mcp_configs::Moved { updated: vec![SetupClient::Codex], failed: vec![] }),
        || assert_eq!(computer.run(Entry::Desktop), Outcome::CredentialsPending),
    );
    let notice = Some(McpNotice { updated: vec![SetupClient::Codex], failed: vec![] });
    let read = |last: Option<(Entry, Report)>| with_test_last(last, || super::commands::mcp_settings_with(|| Some(computer.roots.clone())));
    assert_eq!(read(None), notice);
    assert_eq!(read(Some((Entry::Desktop, Report::of(Outcome::CredentialsPending)))), notice);
    let blocked = Report::busy(&computer.roots.data, "ipc/lock");
    let unread = with_test_last(Some((Entry::Desktop, blocked)), || {
        super::commands::mcp_settings_with(|| panic!("a blocked start reads no folder"))
    });
    assert_eq!(unread, None);
}

#[test]
fn the_window_sees_the_notice_as_the_bindings_describe_it() {
    let link = "Its settings file is a symbolic link, which Lunport does not change. Set it up by hand in Settings → AI access.";
    let unchecked = "Lunport could not check the AI tools' settings: cannot determine home directory";
    let notice = McpNotice {
        updated: vec![SetupClient::Codex],
        failed: vec![
            McpFailure { client: Some(SetupClient::ClaudeCode), reason: link.into() },
            McpFailure { client: None, reason: unchecked.into() },
        ],
    };
    assert_eq!(
        serde_json::to_value(&notice).unwrap(),
        serde_json::json!({
            "updated": ["codex"],
            "failed": [{"client": "claude_code", "reason": link}, {"client": null, "reason": unchecked}]
        })
    );
}

#[test]
fn a_step_has_one_name_in_the_journal_and_toward_the_window() {
    for step in Step::ALL {
        assert_eq!(serde_json::to_value(step).unwrap(), serde_json::json!(step.key()), "{step:?}");
        let written = serde_json::to_value(journal_with(&[step])).unwrap();
        assert_eq!(written[step.key()], serde_json::json!("done"), "{step:?}");
    }
}

#[test]
fn the_window_sees_why_a_start_is_blocked() {
    let conflict = Report::of(Outcome::Conflict { old: PathBuf::from("/data/old"), new: PathBuf::from("/data/new") });
    let status = MigrationStatus::of(Some(&conflict));
    assert_eq!(status.state, MigrationState::Conflict);
    assert_eq!((status.old_path.as_deref(), status.new_path.as_deref()), (Some("/data/old"), Some("/data/new")));
    let data = Move::named(Path::new("/data"), OLD_ID, NEW_ID);
    let busy = MigrationStatus::of(Some(&Report::busy(&data, "sync.lock")));
    assert_eq!((busy.state, busy.failed_step), (MigrationState::Deferred, None));
    assert!(busy.detail.as_deref().is_some_and(|detail| detail.contains("sync.lock")));
    let failed = MigrationStatus::of(Some(&Report::failed(Step::BackupsRoot, "cannot move it")));
    assert_eq!((failed.state, failed.failed_step, failed.detail.as_deref()), (MigrationState::Deferred, Some(Step::BackupsRoot), Some("cannot move it")));
    assert_eq!(MigrationStatus::of(None).state, MigrationState::NotNeeded);
    assert_eq!(
        serde_json::to_value(&failed).unwrap(),
        serde_json::json!({
            "state": "deferred",
            "old_path": null,
            "new_path": null,
            "detail": "cannot move it",
            "failed_step": "backups_root",
            "credentials_left": 0,
            "credentials_need_permission": 0,
            "credentials_retry_helps": false,
            "credentials_permission_put_off": 0
        })
    );
    assert_eq!(serde_json::from_str::<ConflictChoice>(r#""use_old_data""#).unwrap(), ConflictChoice::UseOldData);
    assert_eq!(serde_json::from_str::<ConflictChoice>(r#""keep_new""#).unwrap(), ConflictChoice::KeepNew);
}

#[test]
fn a_retry_of_the_saved_credentials_never_runs_twice_at_once() {
    // A second Retry while the first holds the migration's lock would wait for it and then report the start as blocked.
    let first = super::commands::Retrying::take().expect("nothing runs yet");
    assert!(super::commands::Retrying::take().is_none(), "the second one is refused");
    drop(first);
    assert!(super::commands::Retrying::take().is_some(), "free again once the first is done");
}

#[test]
fn a_blocked_window_keeps_nothing_in_a_data_root() {
    let directory = blocked_webview_directory();
    if let Some(local) = dirs::data_local_dir() {
        assert!(!directory.starts_with(local.join(identity::current().app_id)));
    }
    #[cfg(not(target_os = "linux"))]
    assert!(directory.starts_with(std::env::temp_dir()), "the user's own temporary folder");
    // Linux shares its temporary folder between users: the runtime folder, then the cache folder, then a folder of the user's own.
    let (runtime, cache, temp) = (PathBuf::from("/run/user/1000"), PathBuf::from("/home/frank/.cache"), PathBuf::from("/tmp"));
    assert_eq!(per_user_folder(Some(runtime.clone()), Some(cache.clone()), temp.clone(), 1000), runtime);
    assert_eq!(per_user_folder(None, Some(cache.clone()), temp.clone(), 1000), cache);
    assert_eq!(per_user_folder(None, None, temp.clone(), 1000), temp.join("user-1000"));
}

#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
#[test]
fn a_volume_without_an_exclusive_rename_still_never_replaces_anything() {
    let temp = tempfile::tempdir().unwrap();
    let (from, to) = (temp.path().join("from"), temp.path().join("to"));
    fs::create_dir(&from).unwrap();
    let unsupported = |code| Err(std::io::Error::from_raw_os_error(code));
    #[cfg(target_os = "macos")]
    let code = libc::ENOTSUP;
    #[cfg(not(target_os = "macos"))]
    let code = libc::EINVAL;
    fs::create_dir(&to).unwrap();
    let refused = crate::fsutil::or_rename_if_absent(unsupported(code), &[code], &from, &to).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists, "an empty folder at the name is not replaced either");
    fs::remove_dir(&to).unwrap();
    crate::fsutil::or_rename_if_absent(unsupported(code), &[code], &from, &to).unwrap();
    assert!(to.is_dir() && !from.exists());
    let other = crate::fsutil::or_rename_if_absent(unsupported(libc::EIO), &[code], &to, &from).unwrap_err();
    assert_eq!(other.raw_os_error(), Some(libc::EIO), "any other failure is the answer");
    assert!(to.is_dir() && !from.exists());
}
