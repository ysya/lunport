//! The saved credentials' step in the migration's runs: the journal, the vault's guard, the window and a retry from it, with the
//! credential services in memory (`credentials_tests.rs`). No test reaches a real credential store.

use std::cell::Cell;
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use super::super::commands::{restarts_after, MigrationState, MigrationStatus};
use super::super::journal::{self, Journal};
use super::super::{
    credentials_pending_in, last, missing_vault_key_in, refresh_in, resolve, retry_credentials, run, with_test_last,
    with_test_vault_guard, ConflictChoice, Entry, Move, Outcome, Report, Roots, Step, Waits,
};
use super::tests::{logged, Current, Log, Service, OLD, VAULT_KEY};
use super::*;
use crate::sync::env::Keychain;
use crate::sync::testkit::MemKeychain;
use crate::vault::store::{EntryOrigin, Vault, VaultEntry, VaultError};

const OLD_ID: &str = "org.homelab.sshelter";
const NEW_ID: &str = "dev.ysya.lunport";
const QUICK: Waits = Waits { old_locks: Duration::from_millis(150), migration_lock: Duration::from_millis(150) };

/// A journal whose steps in `done` are done.
fn journal_with(done: &[Step]) -> Journal {
    let mut journal = Journal::default();
    for &step in done {
        journal.set(step, StepState::Done);
    }
    journal
}

/// A computer whose data root has moved to the new name, the migration having got as far as `journal` says.
fn moved(journal: &Journal) -> (tempfile::TempDir, Roots) {
    let temp = tempfile::tempdir().unwrap();
    let roots = Roots { data: Move::named(temp.path(), OLD_ID, NEW_ID), backups: None, webkit: None, preferences: None };
    fs::create_dir_all(&roots.data.new).unwrap();
    journal::write(&roots.data.new, journal).unwrap();
    (temp, roots)
}

fn read_journal(roots: &Roots) -> Journal {
    journal::read(&roots.data.new).unwrap().unwrap()
}

fn vault_entry() -> VaultEntry {
    VaultEntry {
        private_key: "synthetic private key of frank@laptop".into(),
        public_key: "ssh-ed25519 AAAAsynthetic frank@laptop".into(),
        fingerprint: "SHA256:synthetic".into(),
        origin: EntryOrigin::Generated,
        added_at_ms: 1,
    }
}

/// A vault with one entry at `path`, its key under the account it names in the returned keychain.
fn vault_at(path: &Path) -> (MemKeychain, String) {
    let keychain = MemKeychain::default();
    Vault::open(path, &keychain, 1).unwrap().put(&keychain, &"a".repeat(32), &vault_entry()).unwrap();
    let file: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    (keychain, file["key_account"].as_str().unwrap().to_string())
}

/// The names in `folder` that start with `prefix`, sorted.
fn names(folder: &Path, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(prefix))
        .collect();
    names.sort();
    names
}

/// The vault's guard as production composes it, over `roots`' journal and the stand-in old service.
fn guard_over(roots: &Roots, old: &Rc<Service>) -> impl Fn(&str) -> MissingVaultKey + Clone + 'static {
    let (data, old) = (roots.data.clone(), Rc::clone(old));
    move |account: &str| missing_vault_key_in(&data, account, || old.accounts())
}

/// The credential step with `old` and the vault's keychain `current`, recording the journal as production does.
fn mover(old: &Rc<Service>, current: &Arc<MemKeychain>) -> impl Fn(&Roots, &mut Journal) -> StepState + Clone + 'static {
    let (old, current) = (Rc::clone(old), Arc::clone(current));
    move |roots: &Roots, journal: &mut Journal| run_step(&*old, &Current(&current), journal, &record_in(roots))
}

/// The vault's keychain as a store that keeps something other than a vault key it is given, while `garbling`.
struct Garbling<'a> {
    keychain: &'a MemKeychain,
    garbling: Cell<bool>,
}

impl CurrentCredentials for Garbling<'_> {
    fn write(&self, account: &str, value: &str) -> Result<(), AppError> {
        let broken = self.garbling.get() && is_vault_key_account(account);
        self.keychain.set(account, &if broken { format!("{value} garbled") } else { value.to_string() })
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        Ok(self.keychain.get(account)?.map(Zeroizing::new))
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.keychain.delete(account)
    }
}

#[test]
fn vault_open_does_not_rename_while_credentials_are_pending() {
    // The data root moved and the process stopped before the saved credentials did: the vault file is in the new root, its key still
    // under the earlier version's service.
    let (_temp, roots) = moved(&journal_with(&Step::FOLDERS));
    let path = roots.data.new.join("vault.json");
    let (sealing, account) = vault_at(&path);
    let key = sealing.get(&account).unwrap().unwrap();
    let log = Log::default();
    let old = Rc::new(Service::new(OLD, &log, &[(account.as_str(), key.as_str()), ("host:web-1", "hunter2")]));
    let current = Arc::new(MemKeychain::default());
    let saved = fs::read(&path).unwrap();
    let guard = guard_over(&roots, &old);
    let open = |at| with_test_vault_guard(guard.clone(), || Vault::open(&path, &*current, at));
    let mover = mover(&old, &current);

    // The next start resumes from the journal, and this time the store refuses the vault key: the vault stays closed, exactly as it
    // was, and nothing starts an empty one.
    old.fail("read", &account);
    assert_eq!(with_test_mover(mover.clone(), || run(Entry::Desktop, &roots, &QUICK).outcome), Outcome::CredentialsPending);
    assert!(matches!(read_journal(&roots).state(Step::Credentials), StepState::Failed(_)));
    assert!(matches!(open(2), Err(VaultError::CredentialsPending)));
    assert!(matches!(open(3), Err(VaultError::CredentialsPending)), "and again: nothing was set aside in between");
    assert_eq!(fs::read(&path).unwrap(), saved, "the vault file is as it was");
    assert_eq!(names(&roots.data.new, "vault."), ["vault.json"], "nothing set aside, nothing new");
    assert_eq!(current.entry(&account), None, "no key was drawn for it");
    assert_eq!(current.entry("host:web-1"), None, "the rest waits for the vault key");

    // The start after that moves them, and the same file opens with everything in it.
    old.heal();
    assert_eq!(with_test_mover(mover, || run(Entry::Desktop, &roots, &QUICK).outcome), Outcome::Completed);
    assert_eq!(current.entry(&account).as_deref(), Some(key.as_str()));
    let vault = open(4).unwrap();
    assert_eq!(vault.get(&"a".repeat(32)).unwrap().unwrap().fingerprint, "SHA256:synthetic");
    assert!(old.items.borrow().is_empty());
}

#[test]
fn the_vault_never_opens_with_a_broken_copy_of_its_key() {
    // The store does not keep the vault key it is given: the vault waits for it, closed and as it is, rather than reading the broken copy.
    let (_temp, roots) = moved(&journal_with(&Step::FOLDERS));
    let path = roots.data.new.join("vault.json");
    let (sealing, account) = vault_at(&path);
    let key = sealing.get(&account).unwrap().unwrap();
    let log = Log::default();
    let old = Rc::new(Service::new(OLD, &log, &[(account.as_str(), key.as_str())]));
    let current = Arc::new(MemKeychain::default());
    let garbling = Rc::new(Cell::new(true));
    let mover = {
        let (old, current, garbling) = (Rc::clone(&old), Arc::clone(&current), Rc::clone(&garbling));
        move |roots: &Roots, journal: &mut Journal| {
            let store = Garbling { keychain: &current, garbling: Cell::new(garbling.get()) };
            run_step(&*old, &store, journal, &record_in(roots))
        }
    };
    let report = with_test_mover(mover.clone(), || run(Entry::Desktop, &roots, &QUICK));
    assert_eq!(report.outcome, Outcome::CredentialsPending);
    let StepState::Failed(reason) = read_journal(&roots).state(Step::Credentials).clone() else { panic!("the step did not finish") };
    assert!(reason.contains("reads back differently"), "{reason}");
    assert_eq!(MigrationStatus::of(Some(&report)).failed_step, Some(Step::Credentials), "Retry, with why");
    assert_eq!(current.entry(&account), None, "no broken key to read");
    let saved = fs::read(&path).unwrap();
    let opened = with_test_vault_guard(guard_over(&roots, &old), || Vault::open(&path, &*current, 2));
    assert!(matches!(opened, Err(VaultError::CredentialsPending)), "{opened:?}");
    assert_eq!((fs::read(&path).unwrap(), names(&roots.data.new, "vault.")), (saved, vec!["vault.json".to_string()]));

    // Once the store keeps it, the next start moves it and the vault opens.
    garbling.set(false);
    assert_eq!(with_test_mover(mover, || run(Entry::Desktop, &roots, &QUICK).outcome), Outcome::Completed);
    let vault = with_test_vault_guard(guard_over(&roots, &old), || Vault::open(&path, &*current, 3)).unwrap();
    assert_eq!(vault.get(&"a".repeat(32)).unwrap().unwrap().fingerprint, "SHA256:synthetic");
}

#[test]
fn the_vault_waits_only_for_its_keys() {
    // The vault key moves, another item cannot move for now, and a third can never be read.
    let (_temp, roots) = moved(&journal_with(&Step::FOLDERS));
    fs::create_dir_all(roots.data.new.join("credential-helper").join("v1")).unwrap();
    let path = roots.data.new.join("vault.json");
    let (sealing, account) = vault_at(&path);
    let key = sealing.get(&account).unwrap().unwrap();
    let log = Log::default();
    let old = Rc::new(Service::new(OLD, &log, &[(account.as_str(), key.as_str()), ("host:web-1", "hunter2"), ("host:web-2", "damaged")]));
    old.damaged.borrow_mut().insert("host:web-2".into());
    let current = Arc::new(MemKeychain::default());
    current.fail_writes_to("host:web-1", true);
    let mover = mover(&old, &current);
    let report = with_test_mover(mover.clone(), || run(Entry::Desktop, &roots, &QUICK));
    assert_eq!(report.outcome, Outcome::Completed, "nothing waits for the other items");
    assert!(!credentials_pending_in(&roots.data));
    let journal = read_journal(&roots);
    assert!(matches!(journal.state(Step::Credentials), StepState::Failed(_)), "host:web-1 is tried again later");
    assert!(roots.data.new.join("credential-helper").join("v1").exists(), "the helper stays while something is left to try");
    let opened = with_test_vault_guard(guard_over(&roots, &old), || Vault::open(&path, &*current, 2));
    assert!(opened.is_ok(), "{opened:?}");
    let left = report.credentials.expect("the window hears of what is left");
    assert!(!left.retry, "no Retry that cannot help");
    assert_eq!(left.count, 2);

    // A later desktop start moves it without asking anybody, and leaves the damaged item alone.
    current.fail_writes_to("host:web-1", false);
    log.borrow_mut().clear();
    let report = with_test_mover(mover, || run(Entry::Desktop, &roots, &QUICK));
    assert_eq!(report.outcome, Outcome::Completed);
    assert_eq!(current.entry("host:web-1").as_deref(), Some("hunter2"));
    assert!(logged(&log, "host:web-2").is_empty(), "{:#?}", log.borrow());
    assert!(read_journal(&roots).is_done(Step::Credentials));
    assert!(!roots.data.new.join("credential-helper").join("v1").exists(), "retired once nothing is left to try");
    let left = report.credentials.expect("the start that finished says what stays behind");
    assert_eq!((left.retry, left.count), (false, 1));
    assert!(left.why.contains("host:web-2"), "{}", left.why);
    // The start after that says nothing more.
    let report = with_test_mover(|_, _| panic!("the step is done"), || run(Entry::Desktop, &roots, &QUICK));
    assert_eq!((report.outcome, report.credentials), (Outcome::Completed, None));
}

#[test]
fn a_vault_key_that_can_never_be_read_does_not_hold_the_rest_back() {
    let (_temp, roots) = moved(&journal_with(&Step::FOLDERS));
    let path = roots.data.new.join("vault.json");
    let (_, account) = vault_at(&path);
    let log = Log::default();
    let old = Rc::new(Service::new(OLD, &log, &[(account.as_str(), "damaged"), ("host:web-1", "hunter2")]));
    old.damaged.borrow_mut().insert(account.clone());
    let current = Arc::new(MemKeychain::default());
    assert_eq!(with_test_mover(mover(&old, &current), || run(Entry::Desktop, &roots, &QUICK).outcome), Outcome::Completed);
    assert_eq!(current.entry("host:web-1").as_deref(), Some("hunter2"), "the rest moved");
    // Its key never moves, so its vault does not wait for it: the vault is set aside, its file kept beside it, saying why.
    let saved = fs::read(&path).unwrap();
    let opened = with_test_vault_guard(guard_over(&roots, &old), || Vault::open(&path, &*current, 2));
    let Err(VaultError::Unreadable { kept_as: Some(kept_as), reason }) = opened else { panic!("{opened:?}") };
    assert!(reason.contains("earlier version") && reason.contains("damaged"), "{reason}");
    assert_eq!(fs::read(roots.data.new.join(&kept_as)).unwrap(), saved, "kept as it was");
    assert_eq!(old.get(&account).as_deref(), Some("damaged"), "the old item is left as it is");
}

#[test]
fn a_kept_new_vault_whose_key_is_missing_is_set_aside() {
    // Both roots held data and the user kept the new one; the old data's vault key stays under the old service, untouched.
    let temp = tempfile::tempdir().unwrap();
    let roots = Roots { data: Move::named(temp.path(), OLD_ID, NEW_ID), backups: None, webkit: None, preferences: None };
    fs::create_dir_all(&roots.data.old).unwrap();
    fs::write(roots.data.old.join("sync-state.json"), b"old").unwrap();
    fs::create_dir_all(&roots.data.new).unwrap();
    let path = roots.data.new.join("vault.json");
    let (_, account) = vault_at(&path);
    let keep = || resolve(ConflictChoice::KeepNew, &roots, &QUICK);
    assert_eq!(with_test_mover(|_, _| panic!("the kept data's credentials were touched"), keep).outcome, Outcome::Completed);
    let log = Log::default();
    let old = Rc::new(Service::new(OLD, &log, &[("vault:key:fedcba9876543210", "the old data's vault key")]));
    assert_ne!(account, "vault:key:fedcba9876543210");
    // The kept vault's own key is missing: another vault's key under the old service does not keep it closed.
    let opened = with_test_vault_guard(guard_over(&roots, &old), || Vault::open(&path, &MemKeychain::default(), 2));
    assert!(matches!(opened, Err(VaultError::Unreadable { kept_as: Some(_), .. })), "{opened:?}");
}

#[test]
fn the_journal_and_the_window_say_why_credentials_did_not_move() {
    let (_temp, roots) = moved(&journal_with(&Step::FOLDERS));
    fs::create_dir_all(roots.data.new.join("credential-helper").join("v1")).unwrap();
    let locked = "the keyring is locked: unlock it, then retry";
    let report = with_test_mover(move |_, _| StepState::Failed(locked.into()), || run(Entry::Desktop, &roots, &QUICK));
    assert_eq!(report.outcome, Outcome::CredentialsPending);
    assert_eq!(read_journal(&roots).state(Step::Credentials), &StepState::Failed(locked.into()));
    let status = MigrationStatus::of(Some(&report));
    assert_eq!(
        (status.state, status.failed_step, status.detail.as_deref()),
        (MigrationState::CredentialsPending, Some(Step::Credentials), Some(locked))
    );
    assert!(report.refusal().is_none(), "pending credentials hold no client back");
    assert!(roots.data.new.join("credential-helper").join("v1").exists(), "the helper may still be what reads them");

    // Tried again from the window: they move.
    let report = with_test_mover(|_, journal| {
        journal.credential_progress.vault_keys_moved = true;
        StepState::Done
    }, || retry_credentials(&roots, &QUICK));
    assert_eq!((report.outcome, report.credentials), (Outcome::Completed, None));
    assert!(read_journal(&roots).is_done(Step::Credentials));
    assert!(!roots.data.new.join("credential-helper").join("v1").exists(), "retired once they moved");
    // Once done, nothing runs them again.
    let report = with_test_mover(|_, _| panic!("the step is done"), || run(Entry::Desktop, &roots, &QUICK));
    assert_eq!(report.outcome, Outcome::Completed);
}

#[test]
fn the_window_offers_retry_only_where_it_can_help() {
    let failed = |reason: &str| {
        let mut journal = journal_with(&Step::FOLDERS);
        journal.set(Step::Credentials, StepState::Failed(reason.into()));
        journal
    };
    let status = |journal: &Journal, attempted: bool, hidden: bool| {
        let report = Report {
            outcome: journal.outcome(&Step::FOLDERS),
            detail: None,
            credentials: left_behind(journal, attempted, hidden),
            restart_helps: false,
            credential_moves: 0,
        };
        MigrationStatus::of(Some(&report))
    };
    // The vault keys have not moved: Retry, with why.
    let blocking = failed("the vault's key has not moved");
    let shown = status(&blocking, true, false);
    assert_eq!((shown.state, shown.failed_step), (MigrationState::CredentialsPending, Some(Step::Credentials)));
    assert!(shown.detail.as_deref().is_some_and(|detail| detail.contains("vault")), "{shown:?}");
    // The vault keys moved; two items wait for a later start: they are mentioned, without a Retry.
    let mut later = failed("2 saved credentials did not move");
    later.credential_progress.vault_keys_moved = true;
    later.credential_progress.retrying = 2;
    let shown = status(&later, true, false);
    assert_eq!((shown.state, shown.failed_step, shown.credentials_left), (MigrationState::Completed, None, 2));
    // The last attempt waited for the user (a locked keyring): Retry helps once they have unlocked it.
    let mut waiting = later.clone();
    waiting.credential_progress.waiting_for_the_user = true;
    assert_eq!(status(&waiting, true, false).failed_step, Some(Step::Credentials));
    // A start in the background left them to a start the user sees, where this build's store may ask; Windows never asks, and moved
    // them even then.
    let asks = this_build().is_some_and(Store::may_ask);
    assert_eq!(status(&later, false, true).failed_step, asks.then_some(Step::Credentials));
    let never_tried = journal_with(&Step::FOLDERS);
    assert_eq!(status(&never_tried, false, true).failed_step, Some(Step::Credentials), "the vault keys are still pending anyway");
    // Done, with an item kept for good: said once, by the start that finished, and never again.
    let mut done = journal_with(&[Step::DataRoot, Step::BackupsRoot, Step::WebKitStore, Step::Credentials]);
    done.credential_progress.vault_keys_moved = true;
    done.credential_progress.kept.insert("host:web-2".into(), "it can never be read".into());
    let shown = status(&done, true, false);
    assert_eq!((shown.state, shown.failed_step, shown.credentials_left), (MigrationState::Completed, None, 1));
    assert_eq!(status(&done, false, false).credentials_left, 0);
    assert_eq!(left_behind(&done, false, false), None);
}

/// What a start reported, as a retry or an adopt run from the window sees it before it runs: its outcome, and whether its window asked
/// for Retry.
fn reported(outcome: Outcome, retry: bool) -> Report {
    let credentials = Some(LeftBehind { retry, retry_helps: retry, count: 1, permission: 0, put_off: 0, why: "a reason".into() });
    Report { outcome, detail: None, credentials, restart_helps: false, credential_moves: 0 }
}

#[test]
fn a_retry_restarts_only_when_it_changed_what_the_app_has() {
    let after = |journal: &Journal, items: &[(&str, &str)]| {
        let (_temp, roots) = moved(journal);
        let log = Log::default();
        let old = Rc::new(Service::new(OLD, &log, items));
        let current = Arc::new(MemKeychain::default());
        current.fail_writes_to("host:web-3", true);
        with_test_mover(mover(&old, &current), || retry_credentials(&roots, &QUICK))
    };
    // The vault waited for its key: it moved, and the running app started without it.
    let pending = reported(Outcome::CredentialsPending, true);
    let report = after(&journal_with(&Step::FOLDERS), &[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")]);
    assert_eq!(report.outcome, Outcome::Completed);
    assert!(restarts_after(&pending, &report));
    // The vault keys had moved before, and a later item waits for a later start.
    let mut moved_before = journal_with(&Step::FOLDERS);
    moved_before.set(Step::Credentials, StepState::Failed("1 saved credential did not move yet".into()));
    moved_before.credential_progress.vault_keys_moved = true;
    moved_before.credential_progress.retrying = 1;
    // The sync code is read when the app starts: moving it restarts.
    let report = after(&moved_before, &[("sync:mnemonic", "twelve synthetic words")]);
    assert!(report.restart_helps);
    assert!(restarts_after(&reported(Outcome::Completed, false), &report));
    // A password the app reads when it uses it: its open sessions stay, where the store could be used when this process started.
    let report = after(&moved_before, &[("host:web-1", "hunter2")]);
    assert_eq!((report.outcome.clone(), report.restart_helps), (Outcome::Completed, false));
    assert!(!restarts_after(&reported(Outcome::Completed, false), &report));
    // Retry was offered because this process started hidden for a client, or its keyring was locked: it could not read the store when it
    // started (the sync code among what it holds), so a retry that ran restarts it, whatever it moved.
    let background = reported(Outcome::Completed, true);
    assert!(restarts_after(&background, &report));
    let report = after(&moved_before, &[("host:web-3", "hunter2")]);
    assert!(restarts_after(&background, &report), "the store can be read now");
    // Not while the window still asks for Retry (the keyring is still locked), nor while the vault waits.
    let still_locked = reported(Outcome::Completed, true);
    assert!(!restarts_after(&background, &still_locked));
    let report = Report { outcome: Outcome::CredentialsPending, detail: None, credentials: None, restart_helps: true, credential_moves: 0 };
    assert!(!restarts_after(&pending, &report));
}

/// Another start, which handed over to this process, moved a credential the app reads only when it starts while this process waited
/// for it: this process restarts once nothing waits any more. One that moved only what the app reads when it uses it does not.
#[test]
fn another_start_that_moved_what_the_app_reads_at_start_restarts_this_one() {
    let (_temp, roots) = moved(&journal_with(&Step::FOLDERS));
    let refreshed = |before: Report, change: &dyn Fn(&mut Journal)| {
        let mut journal = read_journal(&roots);
        change(&mut journal);
        journal::write(&roots.data.new, &journal).unwrap();
        with_test_last(Some((Entry::Desktop, before)), || refresh_in(&roots))
    };
    // This process waited for the vault keys; the other start moved them (and counted the move).
    let waiting = Report { credential_moves: 0, ..reported(Outcome::CredentialsPending, true) };
    assert!(refreshed(waiting.clone(), &|journal| {
        journal.set(Step::Credentials, StepState::Done);
        journal.credential_progress.vault_keys_moved = true;
        journal.credential_progress.start_credential_moves = 1;
    }));
    // The vault keys had moved; the other start moved the sync code, which this process left for later.
    let completed = Report { credential_moves: 1, ..reported(Outcome::Completed, false) };
    assert!(refreshed(completed.clone(), &|journal| journal.credential_progress.start_credential_moves = 2));
    // It moved only a password: no count changed.
    let now = Report { credential_moves: 2, ..reported(Outcome::Completed, false) };
    assert!(!refreshed(now.clone(), &|journal| journal.credential_progress.retrying = 0));
    // While the vault still waits, the app gains nothing from a restart.
    assert!(!refreshed(waiting, &|journal| {
        journal.set(Step::Credentials, StepState::Failed("the vault's key has not moved".into()));
        journal.credential_progress.vault_keys_moved = false;
        journal.credential_progress.start_credential_moves = 3;
    }));
    // A blocked start restarts into the folders the other start moved, whatever it moved besides
    // (`a_blocked_start_restarts_once_another_start_moved_the_folders`).
    let blocked = Report::of(Outcome::Deferred(super::super::DeferReason::OldInstanceRunning));
    assert!(refreshed(blocked, &|journal| journal.credential_progress.start_credential_moves = 4));
}

/// An attempt that moves a credential the app reads only when it starts counts it in the journal, for the other processes.
#[test]
fn an_attempt_that_moves_what_the_app_reads_at_start_counts_it() {
    let log = Log::default();
    let mut journal = Journal::default();
    let old = Service::new(OLD, &log, &[("host:web-1", "hunter2")]);
    run_step(&old, &Current(&MemKeychain::default()), &mut journal, &record_none);
    assert_eq!(journal.credential_progress.start_credential_moves, 0, "a password is read when it is used");
    let old = Service::new(OLD, &log, &[(VAULT_KEY, "vault key"), ("sync:mnemonic", "twelve synthetic words")]);
    run_step(&old, &Current(&MemKeychain::default()), &mut journal, &record_none);
    assert_eq!(journal.credential_progress.start_credential_moves, 1, "one attempt, one count");
}

fn record_none(_: &Journal) -> Result<(), AppError> {
    Ok(())
}

#[test]
fn another_start_that_moved_them_is_seen_by_this_one() {
    // This process started hidden and left them; then the user started Lunport again, and that start moved them before it handed over
    // to this one.
    let (_temp, roots) = moved(&journal_with(&Step::FOLDERS));
    let credentials = left_behind(&read_journal(&roots), false, true);
    let hidden = Report { outcome: Outcome::CredentialsPending, detail: None, credentials, restart_helps: false, credential_moves: 0 };
    let mut journal = read_journal(&roots);
    journal.set(Step::Credentials, StepState::Done);
    journal.credential_progress.vault_keys_moved = true;
    journal::write(&roots.data.new, &journal).unwrap();
    let seen = with_test_last(Some((Entry::Desktop, hidden)), || {
        refresh_in(&roots);
        last()
    });
    let (entry, report) = seen.unwrap();
    assert_eq!((entry, report.outcome, report.credentials), (Entry::Desktop, Outcome::Completed, None));
}

#[test]
fn a_hand_over_keeps_the_mention_of_what_stays() {
    let mut done = journal_with(&[Step::DataRoot, Step::BackupsRoot, Step::WebKitStore, Step::Credentials]);
    done.credential_progress.vault_keys_moved = true;
    done.credential_progress.kept.insert("host:web-2".into(), "it can never be read".into());
    let (_temp, roots) = moved(&done);
    let refreshed = |last_report: Report| {
        with_test_last(Some((Entry::Desktop, last_report)), || {
            refresh_in(&roots);
            last()
        })
        .unwrap()
        .1
        .credentials
    };
    let Some(mention) = left_behind(&done, true, false) else { return };
    // This process finished the step; another start hands over before its window has said what stays: it still says it.
    let finished_here =
        Report { outcome: Outcome::Completed, detail: None, credentials: Some(mention.clone()), restart_helps: false, credential_moves: 0 };
    assert_eq!(refreshed(finished_here), Some(mention.clone()));
    // The start that handed over finished the step, which this process was still waiting for: this window says what stays.
    let waiting = left_behind(&journal_with(&Step::FOLDERS), false, false);
    assert!(waiting.is_some());
    let waiting_here =
        Report { outcome: Outcome::CredentialsPending, detail: None, credentials: waiting, restart_helps: false, credential_moves: 0 };
    assert_eq!(refreshed(waiting_here), Some(mention));
    // Nothing was left to say here: nothing is said.
    let nothing = Report { outcome: Outcome::Completed, detail: None, credentials: None, restart_helps: false, credential_moves: 0 };
    assert_eq!(refreshed(nothing), None);
}

#[test]
fn only_the_desktop_start_runs_the_credential_step() {
    let (_temp, roots) = moved(&journal_with(&Step::FOLDERS));
    for entry in [Entry::Connect, Entry::Mcp] {
        let outcome = with_test_mover(|_, _| panic!("a client moved credentials"), || run(entry, &roots, &QUICK).outcome);
        assert_eq!(outcome, Outcome::CredentialsPending, "{entry:?}");
        assert_eq!(read_journal(&roots).state(Step::Credentials), &StepState::Pending, "{entry:?}");
    }
    let calls = Rc::new(Cell::new(0));
    let counted = Rc::clone(&calls);
    let outcome = with_test_mover(
        move |_, _| {
            counted.set(counted.get() + 1);
            StepState::Done
        },
        || run(Entry::Desktop, &roots, &QUICK).outcome,
    );
    assert_eq!((outcome, calls.get()), (Outcome::Completed, 1));
}

#[test]
fn keeping_the_new_data_moves_no_credentials() {
    // Both roots hold data; the user keeps the new one, whose credentials are under the new service already.
    let temp = tempfile::tempdir().unwrap();
    let roots = Roots { data: Move::named(temp.path(), OLD_ID, NEW_ID), backups: None, webkit: None, preferences: None };
    fs::create_dir_all(&roots.data.old).unwrap();
    fs::write(roots.data.old.join("vault.json"), b"old vault").unwrap();
    fs::create_dir_all(&roots.data.new).unwrap();
    fs::write(roots.data.new.join("vault.json"), b"new vault").unwrap();
    let keep = || resolve(ConflictChoice::KeepNew, &roots, &QUICK);
    let report = with_test_mover(|_, _| panic!("the kept data's credentials were touched"), keep);
    assert_eq!(report.outcome, Outcome::Completed);
    assert!(read_journal(&roots).is_done(Step::Credentials));
    assert!(!credentials_pending_in(&roots.data));
}

/// The user chose Later in the window that asks their permission for saved credentials: the journal remembers how many waited, and
/// later starts keep the window away for as many, offering the reminder with Allow… instead, until more wait. Not while a vault key
/// waits for permission: the vault stays closed until the user allows it, so the window asks at every start, as before.
#[test]
fn later_is_remembered_for_later_starts_unless_a_vault_key_waits_for_permission() {
    let mut waiting = journal_with(&Step::FOLDERS);
    waiting.set(Step::Credentials, StepState::Failed("2 saved credentials did not move yet".into()));
    waiting.credential_progress.vault_keys_moved = true;
    waiting.credential_progress.needs_permission = ["host:web-1".to_string(), "host:web-2".to_string()].into();
    waiting.credential_progress.needs_permission_unnamed = 1;
    let (_temp, roots) = moved(&waiting);
    let status = |roots: &Roots| {
        let journal = read_journal(roots);
        let credentials = left_behind(&journal, false, false);
        let report = Report { outcome: journal.outcome(&Step::FOLDERS), detail: None, credentials, restart_helps: false, credential_moves: 0 };
        MigrationStatus::of(Some(&report))
    };
    assert_eq!(status(&roots).credentials_permission_put_off, 0, "not answered yet: the window asks");
    put_off_in(&roots, Duration::ZERO).unwrap();
    let shown = status(&roots);
    assert_eq!((shown.credentials_need_permission, shown.credentials_permission_put_off), (3, 3));
    assert_eq!(read_journal(&roots).credential_progress.permission_put_off, 3);

    // A vault key waits for permission: the window asks whatever the user put off.
    let mut journal = read_journal(&roots);
    journal.credential_progress.needs_permission.insert(VAULT_KEY.into());
    journal::write(&roots.data.new, &journal).unwrap();
    assert_eq!(status(&roots).credentials_permission_put_off, 0);

    // Nothing is recorded, nor made, where nothing moved.
    let temp = tempfile::tempdir().unwrap();
    let fresh = Roots { data: Move::named(temp.path(), OLD_ID, NEW_ID), backups: None, webkit: None, preferences: None };
    put_off_in(&fresh, Duration::ZERO).unwrap();
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

/// Where items wait for the user's permission, the window still offers Retry where it can help: the keychain is locked, or a vault key
/// waits for a failure that may pass. Only when the user's permission alone holds the vault back does Retry not help.
#[test]
fn retry_is_offered_beside_allow_where_it_can_help() {
    let status = |journal: &Journal| {
        let report = Report {
            outcome: journal.outcome(&Step::FOLDERS),
            detail: None,
            credentials: left_behind(journal, true, false),
            restart_helps: false,
            credential_moves: 0,
        };
        MigrationStatus::of(Some(&report))
    };
    let mut waiting = journal_with(&Step::FOLDERS);
    waiting.set(Step::Credentials, StepState::Failed("the vault's key has not moved".into()));
    waiting.credential_progress.needs_permission = [VAULT_KEY.to_string()].into();
    waiting.credential_progress.vault_waits_for_permission = true;
    let shown = status(&waiting);
    assert_eq!((shown.failed_step, shown.credentials_need_permission, shown.credentials_retry_helps), (Some(Step::Credentials), 1, false));
    // The keychain is locked (the last attempt waited for the user): unlocking it and retrying helps, besides the permission.
    let mut locked = waiting.clone();
    locked.credential_progress.waiting_for_the_user = true;
    assert!(status(&locked).credentials_retry_helps);
    // A vault key waits for a failure that may pass, while another item waits for permission: Retry helps.
    let mut later = waiting.clone();
    later.credential_progress.vault_waits_for_permission = false;
    later.credential_progress.needs_permission = ["host:web-2".to_string()].into();
    assert!(status(&later).credentials_retry_helps);
    // Nothing waits for permission: Retry wherever the window asks for it, as before.
    let mut plain = journal_with(&Step::FOLDERS);
    plain.set(Step::Credentials, StepState::Failed("the vault's key has not moved".into()));
    assert!(status(&plain).credentials_retry_helps);
    // Nothing to retry: no Retry either.
    let mut done = journal_with(&Step::FOLDERS);
    done.set(Step::Credentials, StepState::Failed("1 saved credential did not move yet".into()));
    done.credential_progress.vault_keys_moved = true;
    done.credential_progress.needs_permission = ["host:web-2".to_string()].into();
    assert_eq!((status(&done).failed_step, status(&done).credentials_retry_helps), (None, false));
}
