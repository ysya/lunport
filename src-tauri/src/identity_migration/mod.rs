//! The first start after the rename moves what a version with the old identifier left on this computer to where this version keeps it:
//! the data root, Production's roaming backups on Windows, the macOS WebView store with the preferences, and then (moved by code that
//! plugs in here, `mover`) the saved credentials, the launch-at-login entry and the AI clients' MCP settings. Every way of starting runs
//! it first (main.rs), the desktop app, `connect` and the MCP adapter, before anything could create the new data root.
//!
//! Nothing moves while an earlier version runs (`locks`), two data roots that both hold data are never merged (the user chooses,
//! `ConflictChoice`), and a migration that stops part way resumes from its journal (`journal`). The window's side is in `commands`.

pub(crate) mod commands;
mod credentials;
#[cfg(target_os = "macos")]
mod credentials_adopt;
#[cfg(target_os = "macos")]
mod credentials_helper;
#[cfg(target_os = "macos")]
mod credentials_keyring;
#[cfg(target_os = "macos")]
mod credentials_macos;
#[cfg(any(target_os = "linux", test))]
mod credentials_linux;
#[cfg(any(windows, test))]
mod credentials_windows;
mod data_root;
mod journal;
mod locks;
pub mod login_item;
pub mod mcp_configs;
mod preferences;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde::Deserialize;

use crate::app_profile::{self, AppProfile};
use crate::{identity, legacy_identity};
use data_root::{Moved, Occupied, Refusal};
pub(crate) use credentials::MissingVaultKey;
pub use journal::Step;
use journal::{Journal, StepState, Unreadable};
use locks::Probe;
use preferences::Preferences;

/// How this process was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// The desktop app, also when a client starts it (`--host`).
    Desktop,
    /// `lunport connect`.
    Connect,
    /// The MCP adapter (`--mcp`).
    Mcp,
}

/// The entry of a process whose first argument is `first`; main.rs runs the migration for it and then dispatches on it.
pub fn entry_for(first: Option<&OsStr>) -> Entry {
    match first.and_then(OsStr::to_str) {
        Some("connect") => Entry::Connect,
        Some("--mcp") => Entry::Mcp,
        _ => Entry::Desktop,
    }
}

/// What a start found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing of an earlier version is on this computer.
    NotNeeded,
    /// Everything that has to move has moved.
    Completed,
    /// The folders have moved; the saved credentials have not been carried over yet.
    CredentialsPending,
    /// The folders are not all in place yet, and nothing that is still under its old name was changed, with one exception: a rename
    /// that fails after the user chose the old data leaves the migration journal, which carries that choice, in the old data root
    /// (`data_root::move_data_root`). Trying again can finish it.
    Deferred(DeferReason),
    /// The old and the new data root both hold data: nothing was merged or changed, and the user chooses (`ConflictChoice`).
    Conflict { old: PathBuf, new: PathBuf },
}

/// Why the folders did not move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeferReason {
    /// An earlier version still holds one of the old data root's locks, so it runs (or another process of this version is moving the
    /// folders right now).
    OldInstanceRunning,
    /// `step` could not be carried out, for the reason `error`; nothing was deleted or merged.
    StepFailed { step: Step, error: String },
}

impl Outcome {
    /// This version's data is not where it keeps it yet: nothing may start that reads or writes it.
    pub fn blocks_startup(&self) -> bool {
        matches!(self, Self::Deferred(_) | Self::Conflict { .. })
    }
}

/// A folder's path under the old identifier and under the current one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Move {
    pub old: PathBuf,
    pub new: PathBuf,
}

impl Move {
    /// The folders in `parent` named after the old and the current app id.
    pub(crate) fn named(parent: &Path, old: &str, new: &str) -> Self {
        Self { old: parent.join(old), new: parent.join(new) }
    }
}

/// What moves on this computer for this build's profile.
#[derive(Clone, Debug)]
pub(crate) struct Roots {
    /// The data root, `<local data>/<app id>` (`fsutil::app_data_root`).
    pub data: Move,
    /// Production's backups where the data root does not hold them: Windows keeps them in the roaming profile, `<roaming data>/<app
    /// id>` (`fsutil::backups_root`).
    pub backups: Option<Move>,
    /// The macOS WebView's store, `~/Library/WebKit/<app id>`.
    pub webkit: Option<Move>,
    /// The macOS preferences, copied once the WebKit store is in place.
    pub preferences: Option<Preferences>,
}

impl Roots {
    /// This computer's folders for this build's profile; `None` when the system names no data folder. A test that gets here stops:
    /// they hold the owner's own data, which a run in a test would move. Tests give `run` roots of their own.
    fn current() -> Option<Self> {
        assert!(!cfg!(test), "a test reached this computer's real data folders (identity_migration::Roots::current)");
        let (old, new) = (legacy_identity::current().app_id, identity::current().app_id);
        let local = dirs::data_local_dir()?;
        let data = Move::named(&local, old, new);
        // The Development profile writes only inside its data root (`write_policy`), which holds its backups too; the WebKit store and
        // the preferences of its old name stay where they are.
        if app_profile::CURRENT != AppProfile::Production {
            return Some(Self { data, backups: None, webkit: None, preferences: None });
        }
        let backups = dirs::data_dir().filter(|roaming| *roaming != local).map(|roaming| Move::named(&roaming, old, new));
        #[cfg(target_os = "macos")]
        let (webkit, preferences) = match dirs::home_dir() {
            Some(home) => (
                Some(Move::named(&home.join("Library").join("WebKit"), old, new)),
                Some(Preferences {
                    old_domain: old.to_string(),
                    new_domain: new.to_string(),
                    old_file: home.join("Library").join("Preferences").join(format!("{old}.plist")),
                }),
            ),
            None => (None, None),
        };
        #[cfg(not(target_os = "macos"))]
        let (webkit, preferences) = (None, None);
        Some(Self { data, backups, webkit, preferences })
    }
}

/// How long a migration waits for other processes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Waits {
    /// For an earlier version to let go of its locks: the in-app update starts this version while the old one is still ending.
    pub old_locks: Duration,
    /// For another process of this version that is moving the folders.
    pub migration_lock: Duration,
}

/// The waits of a real start.
const STARTUP: Waits = Waits { old_locks: Duration::from_secs(5), migration_lock: Duration::from_secs(30) };

/// A run's outcome, which lock held a deferred run back, and what the window hears of saved credentials still to move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Report {
    pub outcome: Outcome,
    pub detail: Option<String>,
    pub credentials: Option<credentials::LeftBehind>,
    /// The run moved a saved credential the running app started without and that a restart lets it use: a vault key or the sync code
    /// (`credentials::restart_helps`).
    pub restart_helps: bool,
    /// How many attempts had moved such a credential when the run looked at the journal (`CredentialProgress::start_credential_moves`):
    /// a later look that counts more finds that another start moved one (`refresh_after_another_start`).
    pub credential_moves: u32,
}

impl Report {
    fn of(outcome: Outcome) -> Self {
        Self { outcome, detail: None, credentials: None, restart_helps: false, credential_moves: 0 }
    }

    /// Another process holds what the move needs: `detail` says which.
    fn waiting(detail: String) -> Self {
        Self { detail: Some(detail), ..Self::of(Outcome::Deferred(DeferReason::OldInstanceRunning)) }
    }

    /// An earlier version holds `lock`, a lock file inside the old data root.
    fn busy(data: &Move, lock: &str) -> Self {
        Self::waiting(format!("an earlier Lunport still holds {lock} in {}", data.old.display()))
    }

    fn failed(step: Step, error: impl Into<String>) -> Self {
        Self::of(Outcome::Deferred(DeferReason::StepFailed { step, error: error.into() }))
    }

    fn conflict(data: &Move) -> Self {
        Self::of(Outcome::Conflict { old: data.old.clone(), new: data.new.clone() })
    }

    /// What `connect` and the MCP adapter say instead of starting when this version's data is not in place: why, and what to do.
    pub(crate) fn refusal(&self) -> Option<String> {
        match &self.outcome {
            Outcome::Deferred(DeferReason::OldInstanceRunning) => Some(format!(
                "lunport: Lunport is moving its data to a new folder, but {}. Quit other Lunport windows and AI clients connected to \
                 Lunport, then try again.",
                self.detail.as_deref().unwrap_or("the old folder is in use")
            )),
            Outcome::Deferred(DeferReason::StepFailed { error, .. }) => Some(format!(
                "lunport: Lunport could not move its data to the new folder: {error}. Nothing was deleted or merged; open Lunport to try \
                 again."
            )),
            Outcome::Conflict { old, new } => Some(format!(
                "lunport: Lunport found data both in {} and in {}. Open Lunport to choose which to keep.",
                old.display(),
                new.display()
            )),
            _ => None,
        }
    }
}

/// Moves what an earlier version left to where this version keeps it, before anything of this process reads or writes there. Runs
/// once, first, for every way of starting (main.rs). When nothing has to move it costs a stat or two and creates nothing. `hidden`: a
/// desktop start hidden for a client (`--host` with the start-hidden variable), which moves no saved credentials that would ask the
/// user anything (`credentials::runs`).
pub fn run_before_startup(entry: Entry, hidden: bool) -> Outcome {
    credentials::set_hidden(hidden);
    let report = match Roots::current() {
        Some(roots) => run(entry, &roots, &STARTUP),
        None => Report::of(Outcome::NotNeeded),
    };
    record(entry, report).outcome
}

/// The migration for `roots`, which `run_before_startup` runs with this computer's folders.
pub(crate) fn run(entry: Entry, roots: &Roots, waits: &Waits) -> Report {
    // What a start pays when nothing is left to do: no lock, no write. The old root is looked at before the journal: another process's
    // move takes the old root and its journal to the new name in one rename, so an old root seen gone here has its journal in the new
    // root, and one seen present sends this start to the lock, where it waits for that move to finish.
    let old_exists = exists(&roots.data.old);
    #[cfg(test)]
    fast_path_gap();
    match journal::read(&roots.data.new) {
        Ok(Some(journal)) if journal.all_done(folders_for(entry)) && !later_steps_to_run(&journal, entry, true) => {
            // Only steps that never hold a start back may be left. They run when the migration's lock is free at once; otherwise, as
            // when one of them cannot be recorded (`run_later_steps`), the start goes on as the journal is and leaves them for a later
            // start.
            if later_steps_to_run(&journal, entry, false) {
                if let Ok(Some(report)) = with_migration_lock(roots, Duration::ZERO, || migrate(entry, roots, waits, Occupied::Refuse)) {
                    return report;
                }
            }
            if journal.is_done(Step::Credentials) {
                data_root::retire_migration_programs(&roots.data.new);
            }
            return finished(&journal, entry, false);
        }
        Ok(None) if !old_exists => return Report::of(Outcome::NotNeeded),
        _ => {}
    }
    locked(roots, waits, |roots, waits| migrate(entry, roots, waits, Occupied::Refuse))
}

/// Settles a conflict between the two data roots the way the user chose, then runs the rest of the migration.
pub(crate) fn resolve(choice: ConflictChoice, roots: &Roots, waits: &Waits) -> Report {
    locked(roots, waits, |roots, waits| {
        // Only the conflict the user saw: no journal in the new root, and data under both names.
        let conflict = matches!(journal::read(&roots.data.new), Ok(None))
            && exists(&roots.data.old)
            && matches!(data_root::folder(&roots.data.new), Ok(data_root::Folder::Occupied));
        if !conflict {
            return migrate(Entry::Desktop, roots, waits, Occupied::Refuse);
        }
        match choice {
            // The other new folders are set aside too: old data under new display settings would be neither.
            ConflictChoice::UseOldData => migrate(Entry::Desktop, roots, waits, Occupied::BackUp),
            // None of the old data's saved credentials moves. A known limitation, left as it is: a kept vault whose own key exists only
            // under the earlier version's credential service (a data root copied from the old one, say) has no key under the current
            // service. While the earlier service holds that key, `Vault::open` keeps the vault closed (`missing_vault_key`), and nothing
            // ever moves the key.
            ConflictChoice::KeepNew => match save(roots, Step::DataRoot, &Journal::kept_new()) {
                Ok(()) => migrate(Entry::Desktop, roots, waits, Occupied::Refuse),
                Err(report) => report,
            },
        }
    })
}

/// Goes on without moving the folder of `step`, the roaming backups or the WebKit store, which failed to move: the step is done, its old
/// folder stays exactly where it is, and a note says so. The data root has no way around it.
pub(crate) fn skip(step: Step, roots: &Roots, waits: &Waits) -> Report {
    if !matches!(step, Step::BackupsRoot | Step::WebKitStore) {
        return Report::failed(step, "only the roaming backups or the WebKit store can stay where they are");
    }
    locked(roots, waits, |roots, waits| {
        if let Ok(Some(mut journal)) = journal::read(&roots.data.new) {
            if !journal.is_done(step) {
                let folders = if step == Step::BackupsRoot { &roots.backups } else { &roots.webkit };
                if let Some(folders) = folders {
                    journal.notes.push(format!("{} was left where it is: the user went on without moving it", folders.old.display()));
                }
                journal.set(step, StepState::Done);
                if let Err(report) = save(roots, step, &journal) {
                    return report;
                }
            }
        }
        migrate(Entry::Desktop, roots, waits, Occupied::Refuse)
    })
}

/// Runs `work` under the migration's lock, waiting at most `wait` for it, with the development write policy's exception for the move
/// (`fsutil::with_root_move`); `None` when another process holds the lock all that time, an error when it cannot be taken.
fn with_migration_lock<T>(roots: &Roots, wait: Duration, work: impl FnOnce() -> T) -> std::io::Result<Option<T>> {
    crate::fsutil::with_root_move(&roots.data.old, || {
        let Some(_lock) = locks::take_migration_lock(&roots.data, wait)? else { return Ok(None) };
        Ok(Some(work()))
    })
}

/// Runs `work` under the migration's lock, with the development write policy's exception for the move (`fsutil::with_root_move`).
fn locked(roots: &Roots, waits: &Waits, work: impl FnOnce(&Roots, &Waits) -> Report) -> Report {
    crate::fsutil::with_root_move(&roots.data.old, || {
        let _lock = match locks::take_migration_lock(&roots.data, waits.migration_lock) {
            Ok(Some(lock)) => lock,
            Ok(None) => return Report::waiting("another Lunport is moving the data folders right now".into()),
            Err(error) => return Report::failed(Step::DataRoot, format!("cannot take the migration lock: {error}")),
        };
        work(roots, waits)
    })
}

/// Everything after the decision that something has to be done, under the migration's lock: the data root (`occupied` says what
/// happens to a new folder that holds something), the other folders, then the steps after them.
fn migrate(entry: Entry, roots: &Roots, waits: &Waits, occupied: Occupied) -> Report {
    let mut journal = match journal::read(&roots.data.new) {
        Ok(Some(journal)) => journal,
        // Only a root that has moved holds a journal, so a damaged one still says the data root is in place; what it still says is kept.
        Err(Unreadable::Damaged) => match journal::salvage(&roots.data.new) {
            Ok(journal) => journal,
            Err(error) => {
                let error = format!("cannot set the damaged migration journal aside, or write back what could be read of it: {error}");
                return Report::failed(Step::DataRoot, error);
            }
        },
        // Read nothing into a journal that cannot be read, and change nothing: the cause has to go first.
        Err(error @ Unreadable::Io(_)) => return Report::failed(Step::DataRoot, format!("{error} (in {})", roots.data.new.display())),
        Ok(None) => {
            if !exists(&roots.data.old) {
                return Report::of(Outcome::NotNeeded);
            }
            match data_root::move_data_root(&roots.data, waits.old_locks, occupied) {
                Ok(journal) => journal,
                Err(Refusal::Conflict) => return Report::conflict(&roots.data),
                Err(Refusal::Busy(lock)) => return Report::busy(&roots.data, &lock),
                Err(Refusal::Failed(error)) => return Report::failed(Step::DataRoot, error),
            }
        }
    };
    if !journal.is_done(Step::DataRoot) {
        // A pending import keeps the absolute paths of its sources, and those inside the old root are in the new one now.
        if let Err(error) = crate::sync::record_import::relocate_journals(&roots.data.new, &roots.data.old) {
            journal.notes.push(format!("pending imports keep their old source paths: {error}"));
        }
        journal.set(Step::DataRoot, StepState::Done);
        if let Err(report) = save(roots, Step::DataRoot, &journal) {
            return report;
        }
    }
    let occupied = if journal.use_old_data { Occupied::BackUp } else { occupied };
    if let Err(report) = move_folders(&mut journal, roots, waits, occupied) {
        // `connect` and the MCP adapter never use the roaming backups or the WebKit store: a step that cannot finish now stays for the
        // desktop's next start.
        if entry == Entry::Desktop {
            return report;
        }
    }
    let ran = match run_later_steps(&mut journal, entry, roots) {
        Ok(ran) => ran,
        Err(report) => return report,
    };
    if journal.is_done(Step::Credentials) {
        data_root::retire_migration_programs(&roots.data.new);
    }
    finished(&journal, entry, ran.contains(&Step::Credentials))
}

/// Moves the folders other than the data root that have not moved yet. An earlier version that runs again recreates its data root and
/// holds its locks there, and it may be using these folders: nothing moves while it holds them.
fn move_folders(journal: &mut Journal, roots: &Roots, waits: &Waits, occupied: Occupied) -> Result<(), Report> {
    let steps = [(Step::BackupsRoot, &roots.backups), (Step::WebKitStore, &roots.webkit)];
    if steps.iter().all(|&(step, _)| journal.is_done(step)) {
        return Ok(());
    }
    // Only a pending step with a folder under its old name on this computer can be in the earlier version's way; a step whose folder
    // does not exist here (no roaming backups on macOS, say) is done without asking. What is looked at here is all that moves: a
    // folder that appears afterwards was made by an earlier version that runs, which the locks below were not taken for, and stays.
    let present = steps.map(|(step, folders)| !journal.is_done(step) && folders.as_ref().is_some_and(|folders| exists(&folders.old)));
    let moving = steps.iter().zip(present).find(|&(_, present)| present).map(|(&(step, _), _)| step);
    let _held = match moving {
        Some(step) if exists(&roots.data.old) => match locks::probe_old_locks(&roots.data.old, waits.old_locks) {
            Ok(Probe::Free(held)) => Some(held),
            Ok(Probe::Busy(lock)) => return Err(Report::busy(&roots.data, &lock)),
            Err(error) => return Err(Report::failed(step, format!("cannot check the locks in {}: {error}", roots.data.old.display()))),
        },
        _ => None,
    };
    #[cfg(test)]
    folder_check_gap();
    for ((step, folders), present) in steps.into_iter().zip(present) {
        if journal.is_done(step) {
            continue;
        }
        if let Some(folders) = folders.as_ref().filter(|_| present) {
            match data_root::move_folder(folders, occupied) {
                Ok(Moved::Moved | Moved::NothingToMove) => {}
                Ok(Moved::KeptBoth) => {
                    journal.notes.push(format!("{} was kept: {} existed already", folders.old.display(), folders.new.display()))
                }
                Err(error) => {
                    let error = format!("cannot move {} to {}: {error}", folders.old.display(), folders.new.display());
                    journal.set(step, StepState::Failed(error.clone()));
                    let _ = save(roots, step, journal);
                    return Err(Report::failed(step, error));
                }
            }
        }
        if step == Step::WebKitStore {
            if let Some(preferences) = &roots.preferences {
                if let Err(error) = preferences::copy(preferences) {
                    journal.notes.push(format!("the preferences were not copied: {error}"));
                }
            }
        }
        journal.set(step, StepState::Done);
        save(roots, step, journal)?;
    }
    Ok(())
}

/// The report of a start through `entry` that got past the folders it needs: its outcome and what the window hears of saved
/// credentials still under the earlier name (`credentials::left_behind`; `attempted`: this start ran their step).
fn finished(journal: &Journal, entry: Entry, attempted: bool) -> Report {
    let outcome = journal.outcome(folders_for(entry));
    Report {
        outcome,
        detail: None,
        credentials: credentials::left_behind(journal, attempted, credentials::hidden()),
        restart_helps: credentials::restart_helps(&journal.moved_credentials),
        credential_moves: journal.credential_progress.start_credential_moves,
    }
}

/// The folders a start through `entry` needs in place: the desktop all of them, `connect` and the MCP adapter only the data root.
fn folders_for(entry: Entry) -> &'static [Step] {
    match entry {
        Entry::Desktop => &Step::FOLDERS,
        Entry::Connect | Entry::Mcp => &[Step::DataRoot],
    }
}

/// Records `journal` in the new data root, after `step`.
fn save(roots: &Roots, step: Step, journal: &Journal) -> Result<(), Report> {
    journal::write(&roots.data.new, journal)
        .map_err(|error| Report::failed(step, format!("cannot record the migration in {}: {error}", roots.data.new.display())))
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// What carries out one of the steps after the folders, given the folders and the journal (which it may read, and record what it
/// did in beyond the step's state): the step's new state.
type Mover = fn(&Roots, &mut Journal) -> StepState;

/// The mover of a step after the folders for a start through `entry`: the saved credentials, the launch-at-login entry and the AI
/// clients' MCP settings move with code outside this module, which plugs in here, and may suit only some entries. `None` while this
/// version has nothing that moves the step: it stays pending.
fn mover(step: Step, entry: Entry) -> Option<Mover> {
    match step {
        Step::Credentials => credentials::mover(entry),
        Step::LoginItem => login_item::mover(entry),
        Step::McpConfigs => mcp_configs::mover(entry),
        // `migrate` moves the folders itself.
        Step::DataRoot | Step::BackupsRoot | Step::WebKitStore => None,
    }
}

/// Whether a start waits for `step` when it has to run it: not for the launch-at-login entry and the MCP settings, which belong to the
/// installation, never change the outcome, and are left for a later start whenever they cannot run or be recorded now.
fn holds_back(step: Step) -> bool {
    !matches!(step, Step::LoginItem | Step::McpConfigs)
}

/// Whether a step after the folders is not done and has a mover for `entry`, among the steps a start waits for (`holding`) or among
/// the ones it never waits for (`holds_back`).
fn later_steps_to_run(journal: &Journal, entry: Entry, holding: bool) -> bool {
    Step::LATER.iter().any(|&step| holds_back(step) == holding && !journal.is_done(step) && mover(step, entry).is_some())
}

/// Runs the movers of the steps after the folders that are not done, recording each; returns the steps that ran and were recorded. A
/// step that never holds a start back and cannot be recorded runs again on a later start.
fn run_later_steps(journal: &mut Journal, entry: Entry, roots: &Roots) -> Result<Vec<Step>, Report> {
    let mut ran = Vec::new();
    for step in Step::LATER {
        if let Some(mover) = mover(step, entry).filter(|_| !journal.is_done(step)) {
            let state = mover(roots, journal);
            journal.set(step, state);
            match save(roots, step, journal) {
                Ok(()) => ran.push(step),
                Err(report) if holds_back(step) => return Err(report),
                Err(_) => {}
            }
        }
    }
    Ok(ran)
}

/// What the journal in `data`'s new root says of the saved credentials, for the vault's guard: whether the vault keys still wait
/// (`Journal::credentials_wait`; with no journal in the new root beside an old root, or one that cannot be read, they may), and the
/// items it keeps under the earlier name for good, which never move.
fn credentials_in(data: &Move) -> (bool, BTreeMap<String, String>) {
    match journal::read(&data.new) {
        Ok(Some(journal)) => (journal.credentials_wait(), journal.credential_progress.kept),
        Ok(None) => (exists(&data.old), BTreeMap::new()),
        Err(_) => (true, BTreeMap::new()),
    }
}

/// Whether the vault keys still wait, by the journal in `data`'s new root (`credentials_in`).
#[cfg(test)]
fn credentials_pending_in(data: &Move) -> bool {
    credentials_in(data).0
}

/// `credentials_in` for this computer's data root; a blocked start says the vault keys may still wait whatever is on disk, before it
/// looks at any folder.
fn credentials_now() -> (bool, BTreeMap<String, String>) {
    if blocks_startup() {
        return (true, BTreeMap::new());
    }
    Roots::current().map_or_else(|| (false, BTreeMap::new()), |roots| credentials_in(&roots.data))
}

/// What may have become of the vault key saved for `key_account`, which the current credential service does not hold: it may still be
/// on its way from the earlier version's service while this start is blocked, while the vault keys still wait (`credentials_in`), or
/// while that service still holds this very key (another vault's key there says nothing about this one); unless the journal keeps it
/// under the earlier name for good (`credentials::missing_vault_key`). `Vault::open` asks before it would set a vault aside or start
/// one again for a missing key, and keeps the vault as it is while the key may still move.
pub(crate) fn missing_vault_key(key_account: &str) -> MissingVaultKey {
    #[cfg(test)]
    return TEST_VAULT_GUARD.with(|guard| guard.borrow().as_ref().map_or(MissingVaultKey::Lost, |guard| guard(key_account)));
    #[cfg(not(test))]
    {
        let (pending, kept) = credentials_now();
        credentials::missing_vault_key(pending, &kept, key_account, credentials::legacy_accounts)
    }
}

/// `missing_vault_key` for the data root `data`, with `legacy` listing the earlier version's credential service.
#[cfg(test)]
fn missing_vault_key_in(
    data: &Move,
    key_account: &str,
    legacy: impl FnOnce() -> Result<Vec<String>, crate::error::AppError>,
) -> MissingVaultKey {
    let (pending, kept) = credentials_in(data);
    credentials::missing_vault_key(pending, &kept, key_account, legacy)
}

#[cfg(test)]
thread_local! {
    /// What `missing_vault_key` says for a test on this thread (`with_test_vault_guard`); without one, the key is lost.
    static TEST_VAULT_GUARD: std::cell::RefCell<Option<Box<dyn Fn(&str) -> MissingVaultKey>>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` with `guard` answering `missing_vault_key` on this thread.
#[cfg(test)]
pub(crate) fn with_test_vault_guard<T>(guard: impl Fn(&str) -> MissingVaultKey + 'static, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Box<dyn Fn(&str) -> MissingVaultKey>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_VAULT_GUARD.with(|guard| *guard.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(TEST_VAULT_GUARD.with(|slot| slot.replace(Some(Box::new(guard)))));
    f()
}

/// Runs the saved credentials' step again for the desktop, as the user asked in its window (`identity_migration_retry_credentials`):
/// from now on this process counts as one the user sees, whatever its start was.
pub(crate) fn retry_credentials(roots: &Roots, waits: &Waits) -> Report {
    credentials::set_hidden(false);
    run(Entry::Desktop, roots, waits)
}

/// After another start of this version handed over to this process (the single-instance plugin): that start ran the migration first
/// (main.rs) and may have moved what this process's own start left, so the journal is read again for the window. Nothing moves here.
/// `by_user`: the user started it, so this process no longer counts as started hidden for a client. Returns whether this process
/// restarts: a blocked start once the folders it waited for are in place, any other start as `restarts_after_hand_over` says.
pub(crate) fn refresh_after_another_start(by_user: bool) -> bool {
    if by_user {
        credentials::set_hidden(false);
    }
    Roots::current().is_some_and(|roots| refresh_in(&roots))
}

/// `refresh_after_another_start` with `roots`. A blocked start, whose window says why it waits, restarts once the journal has the
/// folders it needs in place: the other start moved them (the user quit the earlier Lunport and started this one again, say), and the
/// app starts with them instead of saying what no longer holds. A start that was not blocked takes what the journal says now. What
/// stays under the earlier name for good is said in this process's window when it still had something to say of the saved
/// credentials: the mention its own start was to make, or one for the step that the other start finished while this process waited
/// for it.
fn refresh_in(roots: &Roots) -> bool {
    let Some((entry, report)) = last() else { return false };
    if report.outcome.blocks_startup() {
        return matches!(journal::read(&roots.data.new), Ok(Some(journal)) if journal.all_done(folders_for(entry)));
    }
    match journal::read(&roots.data.new) {
        Ok(Some(journal)) if journal.all_done(folders_for(entry)) => {
            let now = record(entry, finished(&journal, entry, report.credentials.is_some()));
            restarts_after_hand_over(&report, &now)
        }
        _ => false,
    }
}

/// Whether this process restarts once another start handed over to it (`refresh_in`), its report having been `before` and now `after`:
/// when another start moved a saved credential the running app reads only when it starts (a vault key or the sync code) since this
/// process last looked, and nothing waits for the saved credentials any more. The app then starts with what it holds now; its open
/// sessions end, as with a retry from the window (`commands::restarts_after`).
fn restarts_after_hand_over(before: &Report, after: &Report) -> bool {
    after.outcome == Outcome::Completed && after.credential_moves > before.credential_moves
}

/// This process's last run, and the entry it ran for.
static LAST: Mutex<Option<(Entry, Report)>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    /// A test's own last run, used instead of the process's while it is set (`with_test_last`).
    static TEST_LAST: std::cell::RefCell<Option<Option<(Entry, Report)>>> = const { std::cell::RefCell::new(None) };
}

fn record(entry: Entry, report: Report) -> Report {
    #[cfg(test)]
    if TEST_LAST.with(|last| last.borrow().is_some()) {
        TEST_LAST.with(|last| *last.borrow_mut() = Some(Some((entry, report.clone()))));
        return report;
    }
    *LAST.lock().unwrap_or_else(PoisonError::into_inner) = Some((entry, report.clone()));
    report
}

fn last() -> Option<(Entry, Report)> {
    #[cfg(test)]
    if let Some(last) = TEST_LAST.with(|last| last.borrow().clone()) {
        return last;
    }
    LAST.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// Runs `f` as if this process's last run had been `last`, on this thread only.
#[cfg(test)]
pub(crate) fn with_test_last<T>(last: Option<(Entry, Report)>, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Option<(Entry, Report)>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_LAST.with(|last| *last.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(TEST_LAST.with(|slot| slot.replace(Some(last))));
    f()
}

/// Whether this process started without its data in place (`Outcome::blocks_startup`): the desktop app then opens only the window that
/// says why, and nothing that reads or writes the data root.
pub(crate) fn blocks_startup() -> bool {
    last().is_some_and(|(_, report)| report.outcome.blocks_startup())
}

/// For `connect` and the MCP adapter, before they reach the data root (`cli::reach_broker`): `Ok` when this process found its data in
/// place, the refusal otherwise. The MCP adapter lives as long as its client's session, so it runs the migration again first: the user
/// may have quit the earlier Lunport since.
pub(crate) fn ensure_ready() -> Result<(), String> {
    ensure_ready_with(|entry| Roots::current().map(|roots| run(entry, &roots, &STARTUP)))
}

/// `ensure_ready`, with `rerun` running the migration again for an entry.
fn ensure_ready_with(rerun: impl FnOnce(Entry) -> Option<Report>) -> Result<(), String> {
    let Some((entry, mut report)) = last() else {
        return Ok(());
    };
    if report.outcome.blocks_startup() && entry == Entry::Mcp {
        if let Some(again) = rerun(entry) {
            report = record(entry, again);
        }
    }
    report.refusal().map_or(Ok(()), Err)
}

/// Where a blocked start's window keeps what its WebView must keep on disk (WebView2's browser files): a folder of its own outside the
/// data root, which must not be created before the data has moved. The window is private as well, so it saves nothing a later start
/// would read.
pub(crate) fn blocked_webview_directory() -> PathBuf {
    #[cfg(target_os = "linux")]
    let base = per_user_folder(dirs::runtime_dir(), dirs::cache_dir(), std::env::temp_dir(), unsafe { libc::geteuid() });
    #[cfg(not(target_os = "linux"))]
    let base = std::env::temp_dir();
    base.join(format!("{}-migration", identity::current().app_id))
}

/// A folder of the current user's own, where the temporary folder is shared (Linux): their runtime folder (`$XDG_RUNTIME_DIR`), else
/// their cache folder, else a folder named after their user id in the temporary folder.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn per_user_folder(runtime: Option<PathBuf>, cache: Option<PathBuf>, temp: PathBuf, uid: u32) -> PathBuf {
    runtime.or(cache).unwrap_or_else(|| temp.join(format!("user-{uid}")))
}

/// What the user chose for two data roots that both hold data.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum ConflictChoice {
    /// The old data takes the new root's place; the new root, and a new WebKit store and roaming backups folder, are backed up beside
    /// them first.
    UseOldData,
    /// The new root stays as it is, and so does the old one; nothing of the old data moves.
    KeepNew,
}

#[cfg(test)]
thread_local! {
    /// What a test does between the fast path's two looks (`with_fast_path_gap`): another process moving the folders, say.
    static FAST_PATH_GAP: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn fast_path_gap() {
    FAST_PATH_GAP.with(|gap| {
        if let Some(gap) = gap.borrow_mut().as_mut() {
            gap();
        }
    });
}

/// Runs `f` with `gap` called between the fast path's look at the old root and its look at the journal.
#[cfg(test)]
pub(crate) fn with_fast_path_gap<T>(gap: impl FnMut() + 'static, f: impl FnOnce() -> T) -> T {
    with_gap(&FAST_PATH_GAP, gap, f)
}

#[cfg(test)]
thread_local! {
    /// What a test does between `move_folders`' look at the old folders (and the locks it then takes) and the moves
    /// (`with_folder_check_gap`): an earlier version that makes a folder, say.
    static FOLDER_CHECK_GAP: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn folder_check_gap() {
    FOLDER_CHECK_GAP.with(|gap| {
        if let Some(gap) = gap.borrow_mut().as_mut() {
            gap();
        }
    });
}

/// Runs `f` with `gap` called between `move_folders`' look at the old folders and its moves.
#[cfg(test)]
pub(crate) fn with_folder_check_gap<T>(gap: impl FnMut() + 'static, f: impl FnOnce() -> T) -> T {
    with_gap(&FOLDER_CHECK_GAP, gap, f)
}

/// Runs `f` with `gap` in `slot` on this thread.
#[cfg(test)]
fn with_gap<T>(
    slot: &'static std::thread::LocalKey<std::cell::RefCell<Option<Box<dyn FnMut()>>>>,
    gap: impl FnMut() + 'static,
    f: impl FnOnce() -> T,
) -> T {
    struct Restore(&'static std::thread::LocalKey<std::cell::RefCell<Option<Box<dyn FnMut()>>>>, Option<Box<dyn FnMut()>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.1.take();
            self.0.with(|gap| *gap.borrow_mut() = previous);
        }
    }
    let _restore = Restore(slot, slot.with(|slot| slot.replace(Some(Box::new(gap)))));
    f()
}
