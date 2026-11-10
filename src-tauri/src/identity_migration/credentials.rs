//! The saved credentials' step: every item an earlier version saved under its credential service
//! (`legacy_identity::current().credential_service`) moves to this version's (`identity::current().credential_service`), the vault's
//! keys first. An item is written under the new service and read back there before its old copy is deleted. The vault's key decrypts
//! its private keys, so a vault key that does not move stops the attempt, and the vault and the outcome wait until no vault key is left
//! for a later attempt (`missing_vault_key`, `Vault::open`, `Journal::credentials_wait`); nothing else holds anything back. A vault
//! key's earlier value is the one to keep: nothing writes a vault key's account under the current service, so another value there is a
//! copy the store did not keep, and it gives way (`move_one`).
//!
//! Each item ends an attempt in one of four states:
//! - moved: under the new service only;
//! - settled: the new service holds another value. Normally that value stays (the app saved it after the move began) and the old item
//!   is left as it is; when the user chose the old data, and for a vault key, the old value wins: the current one is set aside first,
//!   and its set-aside name is in the journal before anything replaces it (`Conflicts`, `replace`);
//! - retry later: a failure that may pass (a locked or busy store, a refused or denied request, an old copy that would not delete, a
//!   vault key the store does not keep as it was written); a later desktop start tries it again without asking anybody;
//! - kept for good: it can never be read here (its data is damaged or gone, or several old items of its name differ), or the new
//!   service keeps something other than what was written; recorded in the journal and never tried again, like a settled conflict. Where
//!   nothing ever asks the user (Windows), so is an item other than a vault key that failed the same way several attempts in a row
//!   (`run_step_keeping_repeated_failures`).
//!
//! The step is done once nothing is left for a later attempt, however many items stay for good (helper v1 and the bridge then go,
//! `data_root::retire_migration_programs`).
//!
//! Each platform's store has a module of its own: the Windows Credential Manager with its DPAPI files (`credentials_windows`), the
//! Secret Service (`credentials_linux`), the macOS keychain, which the Development profile reaches through the keyring crate
//! (`credentials_keyring`), and macOS Production's frozen credential helpers (`credentials_helper`), which may leave items that wait
//! for the user's permission (`credentials_adopt`).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use super::journal::{CredentialProgress, Journal, SameFailure};
use super::{Entry, Mover, Step, StepState};
use crate::app_profile::{self, AppProfile};
use crate::error::AppError;
use crate::vault::store::is_vault_key_account;

use super::Roots;

/// The credential service an earlier version saved under, as far as the move needs it.
pub(crate) trait LegacyCredentials {
    /// Every account saved under the service.
    fn accounts(&self) -> Result<Vec<String>, AppError>;
    /// The value saved for `account`; `None` when there is none.
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError>;
    /// Deletes what is saved for `account`; none is fine.
    fn delete(&self, account: &str) -> Result<(), AppError>;
    /// Whether `error`, from `read`, means the item can never be read here: its data is damaged or gone. A failure that may pass (a
    /// locked or busy store, a refused request) is not.
    fn unreadable_for_good(&self, error: &AppError) -> bool {
        let _ = error;
        false
    }
}

/// This version's credential service, as far as the move needs it.
pub(crate) trait CurrentCredentials {
    /// Saves `value` for `account`, replacing what is saved there. The move asks so only for an account that has nothing saved, or,
    /// when the old value wins a conflict, once the current value is set aside.
    fn write(&self, account: &str, value: &str) -> Result<(), AppError>;
    /// The value saved for `account`; `None` when there is none.
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError>;
    /// Deletes what is saved for `account`; none is fine. The move asks so only for a vault key's copy that the store does not keep as
    /// it was written, once the value that copy replaced is set aside.
    fn delete(&self, account: &str) -> Result<(), AppError>;
}

/// What one move did with the items it saw.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CredentialReport {
    /// The accounts now saved under the new service only, in the order they moved.
    pub moved: Vec<String>,
    /// The accounts left under the old service for a later attempt, each with why: their failure may pass. An empty account stands for
    /// all of them (they could not be listed).
    pub failed: Vec<(String, String)>,
    /// The accounts left under the old service for good, each with why: settled conflicts and items that can never be read or that the
    /// new service would not keep. No attempt tries them again.
    pub kept: Vec<(String, String)>,
    /// Where a current value went when the old value won a conflict (`Conflicts::PreferOld`): the account and its set-aside name.
    pub set_aside: Vec<(String, String)>,
    /// The accounts this attempt saved under the new service and read back there, in order: moved, or copied with only the old copy
    /// left. The running app may not have had them; an identical copy that was there already is not among them.
    pub written: Vec<String>,
    /// No vault key is left for a later attempt: each is under the new service now, or kept for good; or there was none. A vault key
    /// that is left stops the attempt, and keeps the vault waiting.
    pub vault_key_ok: bool,
}

/// Which value a conflict keeps: the same account under both services, with different values. A vault key's conflict always goes the
/// way of `PreferOld`: nothing writes a vault key's account under the current service (a new key gets an account of its own), so a
/// value there that differs is a copy the store did not keep, never a newer key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Conflicts {
    /// The current service's value stays: the app saved it after the move began. The old item is left as it is.
    KeepCurrent,
    /// The old value wins, because the user chose the old data (`ConflictChoice::UseOldData`), whose fixed accounts (the sync code, the
    /// first vault's key) need their own values. Nothing is lost: the current value is set aside under `set-aside:<account>` and read
    /// back, then the old value takes its place and is read back, and only then is the old item deleted.
    PreferOld,
}

/// Moves every item under `old` to `new`, a conflict keeping the current value (`Conflicts::KeepCurrent`). The step itself goes
/// through `run_step`, which picks the way conflicts go.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn migrate_credentials(old: &dyn LegacyCredentials, new: &dyn CurrentCredentials) -> CredentialReport {
    migrate_credentials_with(old, new, Conflicts::KeepCurrent, &mut |_, _| Ok(()))
}

/// Moves every item under `old` to `new`: the vault keys first, then, once none of them is left for a later attempt, the rest. Each
/// item is written to `new` and read back before it is deleted from `old`; an item `new` holds already with the same value is moved by
/// deleting the old copy, one with another value is settled as `conflicts` says. A failure leaves the item where it is and the move
/// goes on with the next, except after a vault key that is left for a later attempt: the rest waits for it. `noted` records an account
/// and the set-aside name of the value it keeps, before that value is replaced; an error from it stops that item.
pub(crate) fn migrate_credentials_with(
    old: &dyn LegacyCredentials,
    new: &dyn CurrentCredentials,
    conflicts: Conflicts,
    noted: &mut dyn FnMut(&str, &str) -> Result<(), AppError>,
) -> CredentialReport {
    let mut report = CredentialReport { vault_key_ok: true, ..CredentialReport::default() };
    let mut accounts = match old.accounts() {
        Ok(accounts) => accounts,
        Err(error) => {
            // Nothing says where the vault keys are.
            report.vault_key_ok = false;
            report.failed.push((String::new(), format!("they could not be listed: {error}")));
            return report;
        }
    };
    accounts.sort();
    accounts.dedup();
    let (vault_keys, others): (Vec<String>, Vec<String>) = accounts.into_iter().partition(|account| is_vault_key_account(account));
    for account in vault_keys {
        let (fate, written) = move_one(old, new, &account, conflicts, noted);
        // A vault key whose copy read back opens the vault, even when its old copy is still to delete.
        if matches!(fate, Fate::Later { copied: false, .. }) {
            report.vault_key_ok = false;
        }
        report.record(account, fate, written);
    }
    if report.vault_key_ok {
        for account in others {
            let (fate, written) = move_one(old, new, &account, conflicts, noted);
            report.record(account, fate, written);
        }
    }
    report
}

/// What became of one item in an attempt (the states are described in the module's documentation).
enum Fate {
    Moved,
    /// Moved, the old value having won a conflict: the current value it replaced is kept under this set-aside name.
    MovedSettingAside(String),
    /// It was gone by the time it was read: nothing was left to move.
    Gone,
    /// Left for a later attempt, for this reason; `copied`: its value is under the new service already, only its old copy is left.
    Later { why: String, copied: bool },
    /// Left for good, for this reason: never tried again.
    Kept(String),
}

fn later(why: String) -> Fate {
    Fate::Later { why, copied: false }
}

/// The most set-aside names tried for one account: `set-aside:<account>`, then `set-aside:<account>:2` and on.
const SET_ASIDE_NAMES: usize = 20;

/// What a copy that is not what was written says.
const READS_BACK_DIFFERENTLY: &str = "its copy under the new name reads back differently";

/// Moves `account` from `old` to `new` (see `migrate_credentials_with`); also says whether this attempt wrote its value under the new
/// service and read it back there.
fn move_one(
    old: &dyn LegacyCredentials,
    new: &dyn CurrentCredentials,
    account: &str,
    conflicts: Conflicts,
    noted: &mut dyn FnMut(&str, &str) -> Result<(), AppError>,
) -> (Fate, bool) {
    let value = match old.read(account) {
        Ok(Some(value)) => value,
        Ok(None) => return (Fate::Gone, false),
        Err(error) if old.unreadable_for_good(&error) => return (Fate::Kept(format!("it can never be read: {error}")), false),
        Err(error) => return (later(format!("it could not be read: {error}")), false),
    };
    // A vault key's earlier value is the one to keep (`Conflicts`).
    let vault_key = is_vault_key_account(account);
    let (set_aside, written) = match new.read(account) {
        // A move that stopped before the delete: the copy is there.
        Ok(Some(existing)) if *existing == *value => (None, false),
        Ok(Some(_)) if conflicts == Conflicts::KeepCurrent && !vault_key => {
            return (Fate::Kept("another value is saved under the new name, and stays".into()), false);
        }
        Ok(Some(existing)) => match replace(new, account, &existing, &value, noted) {
            Ok(name) => (Some(name), true),
            Err(fate) => return (fate, false),
        },
        Ok(None) => match write_and_check(new, account, &value) {
            Ok(()) => (None, true),
            // The store keeps something else: a vault key is written again, once that copy is set aside.
            Err(Unwritten::Differs(copy)) if vault_key => match replace(new, account, &copy, &value, noted) {
                Ok(name) => (Some(name), true),
                Err(fate) => return (fate, false),
            },
            Err(Unwritten::Differs(_)) => return (Fate::Kept(READS_BACK_DIFFERENTLY.into()), false),
            Err(Unwritten::Failed(fate)) => return (fate, false),
        },
        Err(error) => return (later(format!("the new name could not be checked: {error}")), false),
    };
    if let Err(error) = old.delete(account) {
        return (Fate::Later { why: format!("it moved, but its old copy could not be deleted: {error}"), copied: true }, written);
    }
    (set_aside.map_or(Fate::Moved, Fate::MovedSettingAside), written)
}

/// How a write that did not read back as it was written ended.
enum Unwritten {
    /// The store keeps another value than was written: this one.
    Differs(Zeroizing<String>),
    /// It failed otherwise, with this fate.
    Failed(Fate),
}

/// Writes `value` for `account` in `new` and reads it back.
fn write_and_check(new: &dyn CurrentCredentials, account: &str, value: &str) -> Result<(), Unwritten> {
    let failed = |why: String| Unwritten::Failed(later(why));
    new.write(account, value).map_err(|error| failed(format!("it could not be saved under the new name: {error}")))?;
    match new.read(account) {
        Ok(Some(copy)) if *copy == *value => Ok(()),
        Ok(Some(copy)) => Err(Unwritten::Differs(copy)),
        Ok(None) => Err(failed("its copy under the new name could not be found back".into())),
        Err(error) => Err(failed(format!("its copy under the new name could not be read back: {error}"))),
    }
}

/// Puts `value` under `account` in `new` in place of `current`, the value saved there now, and returns the set-aside name that keeps
/// `current`: it is set aside and read back first (`set_aside`), and its name is recorded through `noted` before anything is
/// replaced, so that an attempt that stops part way never loses track of it. A vault key that still does not read back as it was
/// written is not left where the vault would read it: that copy is deleted (the value it replaced is kept under the set-aside name),
/// and the item is left for a later attempt, the vault waiting for it. Any other item that does so is kept for good.
fn replace(
    new: &dyn CurrentCredentials,
    account: &str,
    current: &str,
    value: &str,
    noted: &mut dyn FnMut(&str, &str) -> Result<(), AppError>,
) -> Result<String, Fate> {
    let name = set_aside(new, account, current).map_err(later)?;
    noted(account, &name)
        .map_err(|error| later(format!("{name}, which keeps the value saved under the new name, could not be recorded: {error}")))?;
    match write_and_check(new, account, value) {
        Ok(()) => Ok(name),
        Err(Unwritten::Failed(fate)) => Err(fate),
        Err(Unwritten::Differs(_)) if is_vault_key_account(account) => {
            let removed = match new.delete(account) {
                Ok(()) => String::new(),
                Err(error) => format!(", and that copy could not be removed: {error}"),
            };
            Err(later(format!("{READS_BACK_DIFFERENTLY} after it was written again{removed}")))
        }
        Err(Unwritten::Differs(_)) => Err(Fate::Kept(READS_BACK_DIFFERENTLY.into())),
    }
}

/// Keeps `current`, the value saved for `account` in `new`, under a set-aside name there, read back: `set-aside:<account>`, or the
/// next free one when that name holds another value. A name that holds this value already (an earlier attempt's) is used as it is.
/// Returns that name, or why the value could not be set aside.
pub(super) fn set_aside(new: &dyn CurrentCredentials, account: &str, current: &str) -> Result<String, String> {
    let failed = |why: String| format!("the value saved under the new name could not be set aside: {why}");
    for number in 1..=SET_ASIDE_NAMES {
        let name = if number == 1 { format!("set-aside:{account}") } else { format!("set-aside:{account}:{number}") };
        match new.read(&name) {
            Ok(Some(held)) if *held == *current => return Ok(name),
            Ok(Some(_)) => continue,
            Ok(None) => {
                new.write(&name, current).map_err(|error| failed(error.to_string()))?;
                return match new.read(&name) {
                    Ok(Some(copy)) if *copy == *current => Ok(name),
                    Ok(_) => Err(failed(format!("{name} does not read back"))),
                    Err(error) => Err(failed(error.to_string())),
                };
            }
            Err(error) => return Err(failed(error.to_string())),
        }
    }
    Err(failed("every set-aside name holds another value".into()))
}

impl CredentialReport {
    fn record(&mut self, account: String, fate: Fate, written: bool) {
        if written {
            self.written.push(account.clone());
        }
        match fate {
            Fate::Moved => self.moved.push(account),
            Fate::MovedSettingAside(name) => {
                self.set_aside.push((account.clone(), name));
                self.moved.push(account);
            }
            Fate::Gone => {}
            Fate::Later { why, .. } => self.failed.push((account, why)),
            Fate::Kept(why) => self.kept.push((account, why)),
        }
    }
}

/// The most of the reason a move that did not finish leaves in the journal and shows the window, in characters.
pub(super) const MAX_REASON: usize = 500;
/// The most items the journal names among those kept for good (`CredentialProgress::kept`), vault keys aside, so that it stays small:
/// more are only counted (`CredentialProgress::kept_unnamed`).
const MAX_KEPT: usize = 100;
/// The most of one kept item's reason the journal holds, in characters.
const MAX_KEPT_REASON: usize = 160;
/// The most items the journal counts at a time among those that failed the same way attempts in a row
/// (`CredentialProgress::same_failures`), so that it stays small.
const MAX_SAME_FAILURES: usize = 32;

/// The step's state after `report`: done once nothing is left for a later attempt (items kept for good do not count, however many);
/// otherwise it runs again on the next desktop start, and the reason says what is left and why.
pub(super) fn step_state(report: &CredentialReport) -> StepState {
    if report.vault_key_ok && report.failed.is_empty() {
        return StepState::Done;
    }
    let mut reason = String::new();
    if !report.vault_key_ok {
        reason.push_str("the vault's key has not moved, so the vault stays closed until it has; ");
    }
    match report.failed.as_slice() {
        [(account, why)] if account.is_empty() => reason.push_str(&format!("the saved credentials did not move: {why}")),
        failed => {
            let count = failed.len();
            reason.push_str(&format!("{count} saved credential{} did not move yet: ", if count == 1 { "" } else { "s" }));
            reason.push_str(&listed(failed.iter().map(|(account, why)| (account, why))));
        }
    }
    StepState::Failed(shortened(reason, MAX_REASON))
}

/// `items`, each an account and why, as `<account> (<why>); ...`.
fn listed<'a>(items: impl IntoIterator<Item = (&'a String, &'a String)>) -> String {
    items.into_iter().map(|(account, why)| format!("{account} ({why})")).collect::<Vec<_>>().join("; ")
}

/// `text`, cut to `limit` characters.
fn shortened(text: String, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text;
    }
    text.chars().take(limit - 1).collect::<String>() + "…"
}

/// The credential step with `old` and `new` for a journal that got as far as `journal` says: what it kept for good stays where it is,
/// a conflict goes the way the user's choice of data says, and what this attempt did is recorded in `journal`; `record` writes the
/// journal down at once, which the step asks for before it replaces a value it set aside. Returns the step's state. Windows goes through
/// `run_step_keeping_repeated_failures` instead.
#[cfg_attr(windows, allow(dead_code))]
pub(super) fn run_step(
    old: &dyn LegacyCredentials,
    new: &dyn CurrentCredentials,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
) -> StepState {
    run_step_reporting(old, new, journal, record).0
}

/// `run_step`, also returning what the attempt did with each item it saw.
pub(super) fn run_step_reporting(
    old: &dyn LegacyCredentials,
    new: &dyn CurrentCredentials,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
) -> (StepState, CredentialReport) {
    run_step_with(old, new, journal, record, None)
}

/// `run_step` for a store that never asks the user anything (Windows), where a failure that repeats does not pass: an item that `limit`
/// attempts in a row left for a later one for the same reason is kept for good instead (`keep_repeated_failures`), so that the step
/// can be done. A vault key never is: its vault would be set aside.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(super) fn run_step_keeping_repeated_failures(
    old: &dyn LegacyCredentials,
    new: &dyn CurrentCredentials,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
    limit: u32,
) -> StepState {
    run_step_with(old, new, journal, record, Some(limit)).0
}

/// `run_step_reporting`, keeping for good what failed the same way `keep_after` attempts in a row (`None`: whatever repeats is tried
/// again).
fn run_step_with(
    old: &dyn LegacyCredentials,
    new: &dyn CurrentCredentials,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
    keep_after: Option<u32>,
) -> (StepState, CredentialReport) {
    let conflicts = if journal.use_old_data { Conflicts::PreferOld } else { Conflicts::KeepCurrent };
    let skipping = Skipping { old, kept: journal.credential_progress.kept.keys().cloned().collect(), listed: RefCell::new(None) };
    let mut noted = |account: &str, name: &str| {
        note_set_aside(journal, account, name);
        record(journal)
    };
    let mut report = migrate_credentials_with(&skipping, new, conflicts, &mut noted);
    let listed = skipping.listed.into_inner();
    let progress = &mut journal.credential_progress;
    if let Some(limit) = keep_after {
        keep_repeated_failures(&mut report, progress, limit);
    }
    progress.waiting_for_the_user = false;
    progress.vault_keys_moved |= report.vault_key_ok;
    if let Some(listed) = listed {
        // An item kept for good that is gone from the old service is not left behind any more.
        progress.kept.retain(|account, _| listed.contains(account));
    }
    let mut unnamed = 0;
    for (account, why) in &report.kept {
        // A vault key is always named: the vault's guard looks for it there (`missing_vault_key`).
        if progress.kept.len() < MAX_KEPT || progress.kept.contains_key(account) || is_vault_key_account(account) {
            progress.kept.insert(account.clone(), kept_reason(why));
        } else {
            unnamed += 1;
        }
    }
    if report.vault_key_ok {
        // An attempt that stopped at the vault keys did not look at the rest.
        progress.kept_unnamed = unnamed;
    }
    progress.retrying = report.failed.iter().filter(|(account, _)| !account.is_empty()).count();
    if restart_helps(&report.written) {
        progress.start_credential_moves = progress.start_credential_moves.saturating_add(1);
    }
    journal.moved_credentials = report.written.clone();
    (step_state(&report), report)
}

/// Counts, by account, the attempts in a row that left an item for a later one for the same reason (`CredentialProgress::same_failures`),
/// and keeps for good what `report` leaves for the `limit`th time that way: it moves from `report.failed` to `report.kept`, saying so.
/// A vault key is never counted, nor are all of them when they could not be listed. An item this attempt did not leave for a later one
/// (it moved, stays for good, or was not reached) starts again, as does one that failed another way; at most `MAX_SAME_FAILURES` are
/// counted at a time, the rest once those are settled.
fn keep_repeated_failures(report: &mut CredentialReport, progress: &mut CredentialProgress, limit: u32) {
    let before = std::mem::take(&mut progress.same_failures);
    let mut later = Vec::new();
    for (account, why) in std::mem::take(&mut report.failed) {
        if account.is_empty() || is_vault_key_account(&account) {
            later.push((account, why));
            continue;
        }
        let reason = kept_reason(&why);
        let times = match before.get(&account) {
            Some(failure) if failure.why == reason => failure.times.saturating_add(1),
            _ => 1,
        };
        if times >= limit {
            report.kept.push((account, format!("it failed the same way {times} attempts in a row: {why}")));
            continue;
        }
        if progress.same_failures.len() < MAX_SAME_FAILURES {
            progress.same_failures.insert(account.clone(), SameFailure { why: reason, times });
        }
        later.push((account, why));
    }
    report.failed = later;
}

/// Notes in `journal` that the value saved under the new name for `account` is kept as `name`, so that the earlier value can take its
/// place; once.
pub(super) fn note_set_aside(journal: &mut Journal, account: &str, name: &str) {
    let note = format!("the value saved under the new name for {account} is kept as {name}, so that the earlier value can take its place");
    if !journal.notes.contains(&note) {
        journal.notes.push(note);
    }
}

/// `why` an item stays under the earlier name for good, as the journal keeps it (`CredentialProgress::kept`).
pub(super) fn kept_reason(why: &str) -> String {
    shortened(why.to_string(), MAX_KEPT_REASON)
}

/// The old service without the items the journal kept for good, remembering every account it listed.
struct Skipping<'a> {
    old: &'a dyn LegacyCredentials,
    kept: BTreeSet<String>,
    listed: RefCell<Option<Vec<String>>>,
}

impl LegacyCredentials for Skipping<'_> {
    fn accounts(&self) -> Result<Vec<String>, AppError> {
        let all = self.old.accounts()?;
        let left = all.iter().filter(|account| !self.kept.contains(*account)).cloned().collect();
        *self.listed.borrow_mut() = Some(all);
        Ok(left)
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.old.read(account)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.old.delete(account)
    }
    fn unreadable_for_good(&self, error: &AppError) -> bool {
        self.old.unreadable_for_good(error)
    }
}

/// What records the journal in the moved data root of `roots` while the step runs (`run_step`'s `record`).
pub(super) fn record_in(roots: &Roots) -> impl Fn(&Journal) -> Result<(), AppError> + '_ {
    move |journal| super::journal::write(&roots.data.new, journal)
}

/// Whether the earlier version's service may still hold the vault key saved for `account`, from the list of its accounts: under that
/// account, or staged by an import as `migration:<import>:<account>` (which the import reads first). What cannot be listed may.
pub(super) fn holds_vault_key(account: &str, accounts: Result<Vec<String>, AppError>) -> bool {
    let staged_for = |held: &str| held.strip_prefix("migration:")?.split_once(':').map(|(_, staged)| staged == account);
    accounts.map_or(true, |accounts| accounts.iter().any(|held| held == account || staged_for(held) == Some(true)))
}

/// What may have become of a vault key that the current credential service lacks (`missing_vault_key`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MissingVaultKey {
    /// It may still be on its way from the earlier version's credential service: the vault waits for it.
    MayStillMove,
    /// It stays under the earlier version's service for good, for this reason (`CredentialProgress::kept`): it never moves.
    LeftBehind(String),
    /// Nothing says where it is.
    Lost,
}

/// What may have become of the vault key saved for `account`, which the current service lacks, by what the journal says (`pending`:
/// the vault keys still wait, `Journal::credentials_wait`; `kept`: the items kept under the earlier name for good) and by the accounts
/// under the earlier version's service (`legacy`, listed only when that matters). A key the journal keeps for good never moves: it
/// stays behind, unless an import's staged copy of it may still move. Any other key may still be on its way while the vault keys are
/// pending or while that service holds it (`holds_vault_key`, the items it keeps for good aside), and is lost otherwise.
pub(super) fn missing_vault_key(
    pending: bool,
    kept: &BTreeMap<String, String>,
    account: &str,
    legacy: impl FnOnce() -> Result<Vec<String>, AppError>,
) -> MissingVaultKey {
    let on_its_way = |accounts: Result<Vec<String>, AppError>| {
        holds_vault_key(account, accounts.map(|accounts| accounts.into_iter().filter(|held| !kept.contains_key(held)).collect()))
    };
    if let Some(why) = kept.get(account) {
        return if on_its_way(legacy()) { MissingVaultKey::MayStillMove } else { MissingVaultKey::LeftBehind(why.clone()) };
    }
    if pending || on_its_way(legacy()) {
        MissingVaultKey::MayStillMove
    } else {
        MissingVaultKey::Lost
    }
}

/// Whether a restart lets the running app use what an attempt moved (`moved`): a vault key, whose vault the app started without, or
/// the sync code, which the sync engine reads only when it starts (`sync::engine::initialize`). The app reads any other saved
/// credential when it uses it.
pub(super) fn restart_helps(moved: &[String]) -> bool {
    moved.iter().any(|account| is_vault_key_account(account) || account == crate::sync::state::MNEMONIC_ACCOUNT)
}

/// Saved credentials a start left under the earlier version's name, as the window hears of them (`MigrationStatus`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeftBehind {
    /// The window asks for the user's attention: the vault waits for its keys, or the move waits for the user (a locked keyring, a
    /// start in the background, where nothing asks).
    pub retry: bool,
    /// A retry from the window can move some now: unless only the user's permission holds the vault back
    /// (`CredentialProgress::vault_waits_for_permission`), which a retry cannot give.
    pub retry_helps: bool,
    /// How many items are under the earlier name, as far as the last attempt saw them, besides those that wait for the user's
    /// permission.
    pub count: usize,
    /// How many items wait for the user's permission before they can move (`CredentialProgress::needs_permission`): the window asks
    /// for it once for all of them (`identity_migration_adopt_credentials`).
    pub permission: usize,
    /// For how many of those the user chose Later at an earlier start (`CredentialProgress::permission_put_off`): the window does not
    /// ask for as many at start. 0 while a vault key waits for permission, which keeps the vault closed until the user allows it.
    pub put_off: usize,
    /// Why, for the window.
    pub why: String,
}

/// What the window hears of the saved credentials after a start with `journal`, which ran their step when `attempted` and started
/// hidden for a client when `hidden`. Items kept for good are said once, by the start that finished the step; `None` once nothing is
/// left to say, or where nothing in this build moves them.
pub(super) fn left_behind(journal: &Journal, attempted: bool, hidden: bool) -> Option<LeftBehind> {
    let store = this_build()?;
    let progress = &journal.credential_progress;
    let kept = progress.kept.len() + progress.kept_unnamed;
    match journal.state(Step::Credentials) {
        StepState::Done => (attempted && kept > 0).then(|| LeftBehind {
            retry: false,
            retry_helps: false,
            count: kept,
            permission: 0,
            put_off: 0,
            why: shortened(format!("they stay under the earlier name{}", kept_listed(progress)), MAX_REASON),
        }),
        state => {
            let background = hidden && store.may_ask();
            let why = match state {
                StepState::Failed(reason) => reason.clone(),
                _ if background => "Lunport started in the background, where it does not ask for access to your credential store".into(),
                _ => "they have not been moved yet".into(),
            };
            let retry = journal.credentials_wait() || progress.waiting_for_the_user || background;
            let retry_helps =
                progress.waiting_for_the_user || background || (journal.credentials_wait() && !progress.vault_waits_for_permission);
            // Those that wait for permission are counted apart (`CredentialProgress::retrying` leaves them out); the window asks for
            // them on its own.
            let permission = progress.needs_permission.len() + progress.needs_permission_unnamed;
            // What the user put off is not asked for at start, unless the vault waits for it (vault keys are always named).
            let vault_key_waits = progress.needs_permission.iter().any(|account| is_vault_key_account(account));
            let put_off = if vault_key_waits { 0 } else { progress.permission_put_off };
            Some(LeftBehind { retry, retry_helps, count: progress.retrying + kept, permission, put_off, why })
        }
    }
}

/// Records that the user chose Later in the window that asks their permission for the saved credentials that wait for it
/// (`commands::identity_migration_put_off_credentials`): as many as the journal in the data root of `roots` says wait now. Later starts
/// then keep that window away for as many (`left_behind`). The journal is written under the migration's lock like every write of it,
/// waiting at most `wait` for that lock; nothing is made where nothing moved.
pub(super) fn put_off_in(roots: &Roots, wait: std::time::Duration) -> Result<(), AppError> {
    let unreadable = |error: super::journal::Unreadable| AppError::Other(error.to_string());
    if super::journal::read(&roots.data.new).map_err(unreadable)?.is_none() {
        return Ok(());
    }
    let recorded = super::with_migration_lock(roots, wait, || {
        let Some(mut journal) = super::journal::read(&roots.data.new).map_err(unreadable)? else { return Ok(()) };
        let progress = &mut journal.credential_progress;
        progress.permission_put_off = progress.needs_permission.len() + progress.needs_permission_unnamed;
        super::journal::write(&roots.data.new, &journal)
    });
    match recorded {
        Ok(Some(recorded)) => recorded,
        Ok(None) => Err(AppError::Other("Another Lunport is moving its data right now. Try again in a moment.".into())),
        Err(error) => Err(AppError::Other(format!("The lock beside Lunport's data folder could not be taken: {error}"))),
    }
}

/// What `progress` keeps for good, as `: <account> (<why>); ...`, saying first how many more it does not name.
fn kept_listed(progress: &CredentialProgress) -> String {
    let more = match progress.kept_unnamed {
        0 => String::new(),
        more => format!(" ({} named here and {more} more)", progress.kept.len()),
    };
    format!("{more}: {}", listed(&progress.kept))
}

/// Where this build keeps saved credentials, which decides how they move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Store {
    /// Windows: the Credential Manager, with DPAPI files beside it for large values. It never asks the user anything.
    Windows,
    /// Linux: the Secret Service. It may ask to unlock a collection.
    SecretService,
    /// The macOS keychain through the keyring crate, where the Development profile keeps them. It may ask to allow access.
    Keychain,
    /// macOS Production's frozen credential helpers: helper v1, through the bridge, for the earlier service and helper v2 for the current
    /// one (`credentials_helper`). No request of the move lets macOS ask anything; what helper v1 may not hand over without asking waits
    /// for the user's permission (`credentials_adopt`).
    CredentialHelpers,
}

impl Store {
    /// Whether moving may ask the user something.
    fn may_ask(self) -> bool {
        !matches!(self, Store::Windows | Store::CredentialHelpers)
    }

    /// The step with this store on this computer; `None` for another platform's store, which is never this build's (`this_build`). In a
    /// test, the test's own mover (`with_test_mover`): no test reaches this computer's store, which holds the owner's own items.
    fn mover(self) -> Option<Mover> {
        #[cfg(test)]
        return test_mover();
        #[cfg(not(test))]
        match self {
            #[cfg(windows)]
            Store::Windows => Some(super::credentials_windows::move_credentials as Mover),
            #[cfg(target_os = "linux")]
            Store::SecretService => Some(super::credentials_linux::move_credentials as Mover),
            #[cfg(target_os = "macos")]
            Store::Keychain => Some(super::credentials_keyring::move_credentials as Mover),
            #[cfg(target_os = "macos")]
            Store::CredentialHelpers => Some(super::credentials_helper::move_credentials as Mover),
            _ => None,
        }
    }

    /// The accounts under the earlier version's service in this store on this computer; none for another platform's store.
    #[cfg_attr(test, allow(dead_code))]
    fn legacy_accounts(self) -> Result<Vec<String>, AppError> {
        match self {
            #[cfg(windows)]
            Store::Windows => super::credentials_windows::legacy_accounts(),
            #[cfg(target_os = "linux")]
            Store::SecretService => super::credentials_linux::legacy_accounts(),
            #[cfg(target_os = "macos")]
            Store::Keychain => super::credentials_keyring::legacy_accounts(),
            #[cfg(target_os = "macos")]
            Store::CredentialHelpers => super::credentials_helper::legacy_accounts(),
            _ => Ok(Vec::new()),
        }
    }
}

/// This build's store; `None` on a platform where this version has nothing that moves the saved credentials.
pub(super) const fn this_build() -> Option<Store> {
    if cfg!(windows) {
        Some(Store::Windows)
    } else if cfg!(target_os = "linux") {
        Some(Store::SecretService)
    } else if cfg!(target_os = "macos") {
        Some(if matches!(app_profile::CURRENT, AppProfile::Development) { Store::Keychain } else { Store::CredentialHelpers })
    } else {
        None
    }
}

/// Whether a start through `entry` moves the saved credentials of `store`: only the desktop app does (`connect` and the MCP adapter
/// never read one), and a start `hidden` for a client leaves a store that may ask the user something for a start the user sees.
pub(super) fn runs(store: Option<Store>, entry: Entry, hidden: bool) -> bool {
    store.is_some_and(|store| entry == Entry::Desktop && !(hidden && store.may_ask()))
}

/// Whether this process started hidden for a client (`--host` with the start-hidden variable: `AppState::background_credentials_only`)
/// and nothing has been asked of it in its window since.
static HIDDEN: AtomicBool = AtomicBool::new(false);

/// Records whether this process started hidden for a client (main.rs, before the migration runs), or that the user has since asked for
/// something in its window (`false`).
pub(super) fn set_hidden(hidden: bool) {
    HIDDEN.store(hidden, Ordering::SeqCst);
}

/// Whether this process counts as started hidden for a client (`set_hidden`).
pub(super) fn hidden() -> bool {
    HIDDEN.load(Ordering::SeqCst)
}

/// The mover of the credential step for a start through `entry` (`super::mover`): this computer's store, when the start moves it.
pub(super) fn mover(entry: Entry) -> Option<Mover> {
    this_build().filter(|&store| runs(Some(store), entry, hidden()))?.mover()
}

/// The accounts under the earlier version's credential service on this computer, for the vault's guard (`missing_vault_key`): none
/// where nothing in this build moves them.
#[cfg_attr(test, allow(dead_code))]
pub(super) fn legacy_accounts() -> Result<Vec<String>, AppError> {
    this_build().map_or(Ok(Vec::new()), Store::legacy_accounts)
}

#[cfg(test)]
thread_local! {
    /// The credential mover of a test on this thread (`with_test_mover`). No test reaches this computer's credential store: it holds the
    /// owner's own items.
    static TEST_MOVER: std::cell::RefCell<Option<std::rc::Rc<dyn Fn(&Roots, &mut Journal) -> StepState>>> =
        const { std::cell::RefCell::new(None) };
}

/// The test's mover, when it set one: without one the step stays as it is, as where nothing moves it.
#[cfg(test)]
fn test_mover() -> Option<Mover> {
    fn run(roots: &Roots, journal: &mut Journal) -> StepState {
        let mover = TEST_MOVER.with(|mover| mover.borrow().clone()).expect("the test's credential mover");
        mover(roots, journal)
    }
    TEST_MOVER.with(|mover| mover.borrow().is_some()).then_some(run as Mover)
}

/// Runs `f` with `mover` as the credential step's mover on this thread.
#[cfg(test)]
pub(crate) fn with_test_mover<T>(mover: impl Fn(&Roots, &mut Journal) -> StepState + 'static, f: impl FnOnce() -> T) -> T {
    type Shared = std::rc::Rc<dyn Fn(&Roots, &mut Journal) -> StepState>;
    struct Restore(Option<Shared>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_MOVER.with(|mover| *mover.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(TEST_MOVER.with(|slot| slot.replace(Some(std::rc::Rc::new(mover)))));
    f()
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "credentials_runs_tests.rs"]
mod runs_tests;
