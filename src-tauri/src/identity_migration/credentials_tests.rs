//! The saved credentials' move against credential services in memory. The step in the migration's runs has tests of its own
//! (`credentials_runs_tests.rs`), and so have the platform stores, beside their modules. No test reaches a real credential store: this
//! computer's hold the owner's own items under the old services.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use zeroize::Zeroizing;

use super::super::journal::Journal;
use super::*;
use crate::sync::env::Keychain;
use crate::sync::testkit::MemKeychain;

pub(super) const OLD: &str = "SSHelter";
pub(super) const NEW: &str = "Lunport";
pub(super) const VAULT_KEY: &str = "vault:key:0123456789abcdef";
/// What a stand-in service says of an item whose data is damaged for good.
pub(super) const DAMAGED: &str = "the item's data is damaged";

/// What the stores of one test did, in order: `<service> <operation> <account>`.
pub(super) type Log = Rc<RefCell<Vec<String>>>;

/// One credential service in memory. Every read, write and delete goes into the test's log, and any of them can be made to fail for an
/// account, for now or (a read) for good.
pub(super) struct Service {
    name: &'static str,
    pub items: RefCell<BTreeMap<String, String>>,
    log: Log,
    pub unlistable: Cell<bool>,
    failing: RefCell<BTreeSet<(&'static str, String)>>,
    pub damaged: RefCell<BTreeSet<String>>,
    /// How many more writes of an account keep something other than the value they are given: a store that does not keep what it is
    /// given (`usize::MAX`: every write).
    garbled: RefCell<BTreeMap<String, usize>>,
}

impl Service {
    pub fn new(name: &'static str, log: &Log, items: &[(&str, &str)]) -> Self {
        Self {
            name,
            items: RefCell::new(items.iter().map(|&(account, value)| (account.to_string(), value.to_string())).collect()),
            log: Rc::clone(log),
            unlistable: Cell::new(false),
            failing: RefCell::default(),
            damaged: RefCell::default(),
            garbled: RefCell::default(),
        }
    }

    pub fn fail(&self, operation: &'static str, account: &str) {
        self.failing.borrow_mut().insert((operation, account.to_string()));
    }

    pub fn heal(&self) {
        self.failing.borrow_mut().clear();
    }

    /// The next `writes` writes of `account` keep `<value> garbled` instead of the value.
    pub fn garble(&self, account: &str, writes: usize) {
        self.garbled.borrow_mut().insert(account.to_string(), writes);
    }

    /// The value saved for `account`, looked at without the log.
    pub fn get(&self, account: &str) -> Option<String> {
        self.items.borrow().get(account).cloned()
    }

    fn act(&self, operation: &'static str, account: &str) -> Result<(), AppError> {
        self.log.borrow_mut().push(format!("{} {operation} {account}", self.name));
        if self.failing.borrow().contains(&(operation, account.to_string())) {
            return Err(AppError::Other(format!("the store refused to {operation} it")));
        }
        Ok(())
    }

    fn value(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.act("read", account)?;
        if self.damaged.borrow().contains(account) {
            return Err(AppError::Other(DAMAGED.into()));
        }
        Ok(self.get(account).map(Zeroizing::new))
    }

    fn remove(&self, account: &str) -> Result<(), AppError> {
        self.act("delete", account)?;
        self.items.borrow_mut().remove(account);
        Ok(())
    }
}

impl LegacyCredentials for Service {
    fn accounts(&self) -> Result<Vec<String>, AppError> {
        if self.unlistable.get() {
            return Err(AppError::Other("the store is locked".into()));
        }
        Ok(self.items.borrow().keys().cloned().collect())
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.value(account)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.remove(account)
    }
    fn unreadable_for_good(&self, error: &AppError) -> bool {
        error.to_string() == DAMAGED
    }
}

impl CurrentCredentials for Service {
    fn write(&self, account: &str, value: &str) -> Result<(), AppError> {
        self.act("write", account)?;
        let mut garbled = self.garbled.borrow_mut();
        let saved = match garbled.get_mut(account) {
            Some(writes) if *writes > 0 => {
                *writes = writes.saturating_sub(usize::from(*writes != usize::MAX));
                format!("{value} garbled")
            }
            _ => value.to_string(),
        };
        self.items.borrow_mut().insert(account.to_string(), saved);
        Ok(())
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.value(account)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.remove(account)
    }
}

/// The new service as the vault sees it (`Keychain`) and as the move writes to it.
pub(super) struct Current<'a>(pub &'a MemKeychain);

impl CurrentCredentials for Current<'_> {
    fn write(&self, account: &str, value: &str) -> Result<(), AppError> {
        self.0.set(account, value)
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        Ok(self.0.get(account)?.map(Zeroizing::new))
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.0.delete(account)
    }
}

/// How `run_step` records the journal where a test does not look at it.
pub(super) fn unrecorded(_: &Journal) -> Result<(), AppError> {
    Ok(())
}

pub(super) fn accounts(items: &[(String, String)]) -> Vec<&str> {
    items.iter().map(|(account, _)| account.as_str()).collect()
}

/// The entries of `log` for `account`, in order.
pub(super) fn logged(log: &Log, account: &str) -> Vec<String> {
    log.borrow().iter().filter(|entry| entry.ends_with(&format!(" {account}"))).cloned().collect()
}

/// The entries of `log` that name `account`, its set-aside names included, in order.
fn touching(log: &Log, account: &str) -> Vec<String> {
    log.borrow().iter().filter(|entry| entry.contains(account)).cloned().collect()
}

#[test]
fn moves_vault_keys_first() {
    let log = Log::default();
    let saved = [
        ("central:v2:token:acme-prod-123456", "central token"),
        ("host:web-1", "hunter2"),
        ("sync:mnemonic", "twelve synthetic words"),
        ("vault:key", "plan-1 vault key"),
        (VAULT_KEY, "vault key"),
        ("vault:passphrase:0123456789abcdef", "a key's passphrase"),
    ];
    let old = Service::new(OLD, &log, &saved);
    let new = Service::new(NEW, &log, &[]);
    let report = migrate_credentials(&old, &new);
    assert!(report.vault_key_ok && report.failed.is_empty() && report.kept.is_empty(), "{report:?}");
    assert_eq!(&report.moved[..2], ["vault:key", VAULT_KEY], "the vault keys move first");
    assert_eq!(report.moved.len(), saved.len(), "{report:?}");
    for (account, value) in saved {
        assert_eq!(new.get(account).as_deref(), Some(value), "{account}");
    }
    assert!(old.items.borrow().is_empty(), "every old copy goes once its new copy read back");
    assert_eq!(step_state(&report), StepState::Done);

    let log = log.borrow();
    let vault_key = |entry: &String| entry.ends_with(" vault:key") || entry.ends_with(&format!(" {VAULT_KEY}"));
    let last_vault_key = log.iter().rposition(vault_key).unwrap();
    let first_other = log.iter().position(|entry| !vault_key(entry)).unwrap();
    assert!(last_vault_key < first_other, "nothing else is touched before the vault keys have moved: {log:#?}");
    // An old copy is deleted only after the new one read back.
    for (account, _) in saved {
        let at = |entry: String| log.iter().position(|logged| *logged == entry).unwrap_or_else(|| panic!("{entry}: {log:#?}"));
        let written = at(format!("{NEW} write {account}"));
        let read_back = log.iter().rposition(|logged| *logged == format!("{NEW} read {account}")).unwrap();
        let deleted = at(format!("{OLD} delete {account}"));
        assert!(written < read_back && read_back < deleted, "{account}: {log:#?}");
    }
}

#[test]
fn a_vault_key_that_does_not_move_stops_the_attempt() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("host:web-1", "hunter2"), (VAULT_KEY, "first key"), ("vault:key:fedcba9876543210", "second key")]);
    let new = Service::new(NEW, &log, &[]);
    new.fail("write", VAULT_KEY);
    let report = migrate_credentials(&old, &new);
    assert!(!report.vault_key_ok);
    assert_eq!(report.moved, ["vault:key:fedcba9876543210"], "the other vault key still moves");
    assert_eq!(accounts(&report.failed), [VAULT_KEY]);
    assert_eq!(old.get(VAULT_KEY).as_deref(), Some("first key"), "kept where it is");
    assert_eq!(new.get(VAULT_KEY), None);
    assert!(logged(&log, "host:web-1").is_empty(), "the rest waits for the next attempt: {:#?}", log.borrow());
    let StepState::Failed(reason) = step_state(&report) else { panic!("{:?}", step_state(&report)) };
    assert!(reason.contains("vault") && reason.contains(VAULT_KEY), "{reason}");
}

#[test]
fn keeps_the_old_item_when_the_read_back_differs() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("host:web-1", "hunter2"), ("sync:mnemonic", "twelve synthetic words")]);
    let new = Service::new(NEW, &log, &[]);
    new.garble("host:web-1", usize::MAX);
    let report = migrate_credentials(&old, &new);
    assert_eq!(accounts(&report.kept), ["host:web-1"], "a store that keeps something else is not asked again: {report:?}");
    assert!(report.kept[0].1.contains("back"), "{report:?}");
    assert_eq!(old.get("host:web-1").as_deref(), Some("hunter2"), "the old item stays: its copy is not the same");
    assert!(!log.borrow().contains(&format!("{OLD} delete host:web-1")));
    assert_eq!(report.moved, ["sync:mnemonic"]);
    assert!(report.vault_key_ok && report.failed.is_empty());
}

#[test]
fn a_vault_key_that_differs_under_the_new_name_gives_way_to_the_earlier_one() {
    // Nothing writes a vault key's account under the current service (a new key gets an account of its own), so another value there is
    // a copy the store did not keep: the earlier value is the vault's key, whatever the user chose. The value there is set aside first.
    // Another item keeps the current value, as before.
    let log = Log::default();
    let old = Service::new(OLD, &log, &[(VAULT_KEY, "vault key"), ("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[(VAULT_KEY, "a broken copy"), ("sync:mnemonic", "new words")]);
    let report = migrate_credentials(&old, &new);
    assert!(report.vault_key_ok && report.failed.is_empty(), "{report:?}");
    assert_eq!(report.moved, [VAULT_KEY]);
    assert_eq!(report.set_aside, [(VAULT_KEY.to_string(), format!("set-aside:{VAULT_KEY}"))]);
    assert_eq!(new.get(VAULT_KEY).as_deref(), Some("vault key"));
    assert_eq!(new.get(&format!("set-aside:{VAULT_KEY}")).as_deref(), Some("a broken copy"), "nothing is lost");
    assert_eq!(old.get(VAULT_KEY), None);
    assert_eq!(accounts(&report.kept), ["sync:mnemonic"], "another item keeps the current value");
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("new words"));
}

#[test]
fn a_vault_key_whose_copy_reads_back_differently_is_written_again() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")]);
    let new = Service::new(NEW, &log, &[]);
    new.garble(VAULT_KEY, 1);
    let report = migrate_credentials(&old, &new);
    assert!(report.vault_key_ok && report.failed.is_empty() && report.kept.is_empty(), "{report:?}");
    assert_eq!(report.moved, [VAULT_KEY, "host:web-1"]);
    assert_eq!(new.get(VAULT_KEY).as_deref(), Some("vault key"));
    assert_eq!(new.get(&format!("set-aside:{VAULT_KEY}")).as_deref(), Some("vault key garbled"), "set aside like any value there");
    // Written and read back broken; the broken copy set aside and read back; written again and read back; only then the old item goes.
    assert_eq!(
        touching(&log, VAULT_KEY),
        [
            format!("{OLD} read {VAULT_KEY}"),
            format!("{NEW} read {VAULT_KEY}"),
            format!("{NEW} write {VAULT_KEY}"),
            format!("{NEW} read {VAULT_KEY}"),
            format!("{NEW} read set-aside:{VAULT_KEY}"),
            format!("{NEW} write set-aside:{VAULT_KEY}"),
            format!("{NEW} read set-aside:{VAULT_KEY}"),
            format!("{NEW} write {VAULT_KEY}"),
            format!("{NEW} read {VAULT_KEY}"),
            format!("{OLD} delete {VAULT_KEY}"),
        ]
    );
}

#[test]
fn a_vault_key_the_store_never_keeps_holds_the_vault_back() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")]);
    let new = Service::new(NEW, &log, &[]);
    new.garble(VAULT_KEY, usize::MAX);
    let mut journal = Journal::default();
    let StepState::Failed(reason) = run_step(&old, &new, &mut journal, &unrecorded) else { panic!("the vault key did not move") };
    assert!(reason.contains("vault") && reason.contains(VAULT_KEY) && reason.contains("reads back differently"), "{reason}");
    let progress = &journal.credential_progress;
    assert!(!progress.vault_keys_moved, "the vault keeps waiting for its key");
    assert!(journal.credentials_wait());
    assert_eq!((progress.retrying, progress.kept.len()), (1, 0), "tried again later, never kept: {progress:?}");
    // Nothing reads the broken copy in place of the key: it went, its value kept under the set-aside name.
    assert_eq!(new.get(VAULT_KEY), None);
    assert_eq!(new.get(&format!("set-aside:{VAULT_KEY}")).as_deref(), Some("vault key garbled"));
    assert_eq!(old.get(VAULT_KEY).as_deref(), Some("vault key"), "the earlier copy stays");
    assert!(logged(&log, "host:web-1").is_empty(), "the rest waits for the vault key");

    // Once the store keeps what it is given, the next attempt moves it, and the rest after it.
    new.garble(VAULT_KEY, 0);
    assert_eq!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Done);
    assert_eq!(new.get(VAULT_KEY).as_deref(), Some("vault key"));
    assert_eq!(new.get("host:web-1").as_deref(), Some("hunter2"));
    assert!(journal.credential_progress.vault_keys_moved);
}

#[test]
fn reports_partial_failure_and_keeps_going() {
    let log = Log::default();
    let old = Service::new(
        OLD,
        &log,
        &[
            ("central:v2:token:acme-prod-123456", "central token"),
            ("host:web-1", "hunter2"),
            ("sync:mnemonic", "twelve synthetic words"),
            (VAULT_KEY, "vault key"),
        ],
    );
    let new = Service::new(NEW, &log, &[]);
    old.fail("read", "central:v2:token:acme-prod-123456");
    new.fail("write", "host:web-1");
    old.fail("delete", "sync:mnemonic");
    let report = migrate_credentials(&old, &new);
    assert!(report.vault_key_ok, "{report:?}");
    assert_eq!(report.moved, [VAULT_KEY]);
    assert_eq!(accounts(&report.failed), ["central:v2:token:acme-prod-123456", "host:web-1", "sync:mnemonic"]);
    assert_eq!(old.get("central:v2:token:acme-prod-123456").as_deref(), Some("central token"));
    assert_eq!((old.get("host:web-1").as_deref(), new.get("host:web-1")), (Some("hunter2"), None));
    // Its copy read back, so it is under the new name too; only the old copy stayed.
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("twelve synthetic words"));
    assert_eq!(old.get("sync:mnemonic").as_deref(), Some("twelve synthetic words"));
    let StepState::Failed(reason) = step_state(&report) else { panic!("{:?}", step_state(&report)) };
    assert!(reason.contains('3') && reason.contains("host:web-1"), "{reason}");

    // The next attempt finishes it, and writes nothing twice.
    old.heal();
    new.heal();
    log.borrow_mut().clear();
    let again = migrate_credentials(&old, &new);
    assert!(again.vault_key_ok && again.failed.is_empty(), "{again:?}");
    assert_eq!(again.moved, ["central:v2:token:acme-prod-123456", "host:web-1", "sync:mnemonic"]);
    assert!(!log.borrow().contains(&format!("{NEW} write sync:mnemonic")), "{:#?}", log.borrow());
    assert!(old.items.borrow().is_empty());
    assert_eq!(step_state(&again), StepState::Done);
}

#[test]
fn an_item_already_under_the_new_name_is_never_overwritten() {
    // Without the user's choice of the old data, the current value stays: the app saved it after the move began. The old item is left
    // as it is, and the conflict is settled there.
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("host:web-1", "hunter2"), ("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[("host:web-1", "hunter2"), ("sync:mnemonic", "new words")]);
    let report = migrate_credentials(&old, &new);
    assert_eq!(report.moved, ["host:web-1"], "the same value: only the old copy goes");
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(accounts(&report.kept), ["sync:mnemonic"]);
    assert!(report.kept[0].1.contains("new name"), "{report:?}");
    assert_eq!(old.get("host:web-1"), None);
    assert_eq!(new.get("host:web-1").as_deref(), Some("hunter2"));
    assert_eq!(old.get("sync:mnemonic").as_deref(), Some("old words"), "the old item is left as it is");
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("new words"));
    assert!(!log.borrow().iter().any(|entry| entry.starts_with(&format!("{NEW} write"))), "{:#?}", log.borrow());
    assert_eq!(step_state(&report), StepState::Done, "a settled conflict leaves nothing to try again");
}

#[test]
fn with_the_old_data_chosen_a_conflict_sets_the_current_value_aside_first() {
    // The user chose the old data: its own values win, fixed accounts such as the sync code and the first vault's key included. The
    // value under the new name is kept as `set-aside:<account>` first.
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("sync:mnemonic", "old words"), ("vault:key", "old vault key")]);
    let new = Service::new(NEW, &log, &[("sync:mnemonic", "new words"), ("vault:key", "new vault key")]);
    let report = migrate_credentials_with(&old, &new, Conflicts::PreferOld, &mut |_, _| Ok(()));
    assert!(report.vault_key_ok && report.failed.is_empty() && report.kept.is_empty(), "{report:?}");
    assert_eq!(report.moved, ["vault:key", "sync:mnemonic"]);
    assert_eq!(
        report.set_aside,
        [("vault:key".to_string(), "set-aside:vault:key".to_string()), ("sync:mnemonic".to_string(), "set-aside:sync:mnemonic".to_string())]
    );
    for (account, old_value, new_value) in [("sync:mnemonic", "old words", "new words"), ("vault:key", "old vault key", "new vault key")] {
        assert_eq!(new.get(account).as_deref(), Some(old_value), "{account}");
        assert_eq!(new.get(&format!("set-aside:{account}")).as_deref(), Some(new_value), "{account}");
        assert_eq!(old.get(account), None, "{account}");
    }
    // Set aside and read back, then replaced and read back, then the old item deleted.
    let order = [
        format!("{NEW} write set-aside:sync:mnemonic"),
        format!("{NEW} read set-aside:sync:mnemonic"),
        format!("{NEW} write sync:mnemonic"),
        format!("{NEW} read sync:mnemonic"),
        format!("{OLD} delete sync:mnemonic"),
    ];
    let log = log.borrow();
    let at: Vec<usize> = order.iter().map(|entry| log.iter().rposition(|logged| logged == entry).expect(entry)).collect();
    assert!(at.windows(2).all(|pair| pair[0] < pair[1]), "{log:#?}");
}

#[test]
fn a_set_aside_name_that_is_taken_is_not_reused() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[("sync:mnemonic", "new words"), ("set-aside:sync:mnemonic", "an earlier value")]);
    let report = migrate_credentials_with(&old, &new, Conflicts::PreferOld, &mut |_, _| Ok(()));
    assert_eq!(report.set_aside, [("sync:mnemonic".to_string(), "set-aside:sync:mnemonic:2".to_string())]);
    assert_eq!(new.get("set-aside:sync:mnemonic").as_deref(), Some("an earlier value"), "never replaced");
    assert_eq!(new.get("set-aside:sync:mnemonic:2").as_deref(), Some("new words"));
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("old words"));
}

#[test]
fn a_failure_while_the_old_value_wins_keeps_every_copy() {
    // Setting the current value aside fails: nothing else is done.
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[("sync:mnemonic", "new words")]);
    new.fail("write", "set-aside:sync:mnemonic");
    let report = migrate_credentials_with(&old, &new, Conflicts::PreferOld, &mut |_, _| Ok(()));
    assert_eq!(accounts(&report.failed), ["sync:mnemonic"], "{report:?}");
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("new words"));
    assert_eq!(old.get("sync:mnemonic").as_deref(), Some("old words"));

    // Replacing the current value fails after it was set aside: the copy under the set-aside name stays, and so does the old item.
    new.heal();
    new.fail("write", "sync:mnemonic");
    let report = migrate_credentials_with(&old, &new, Conflicts::PreferOld, &mut |_, _| Ok(()));
    assert_eq!(accounts(&report.failed), ["sync:mnemonic"], "{report:?}");
    assert_eq!(new.get("set-aside:sync:mnemonic").as_deref(), Some("new words"));
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("new words"));
    assert_eq!(old.get("sync:mnemonic").as_deref(), Some("old words"));

    // The next attempt finishes it, with the copy it set aside before.
    new.heal();
    let report = migrate_credentials_with(&old, &new, Conflicts::PreferOld, &mut |_, _| Ok(()));
    assert_eq!(report.moved, ["sync:mnemonic"], "{report:?}");
    assert_eq!(report.set_aside, [("sync:mnemonic".to_string(), "set-aside:sync:mnemonic".to_string())]);
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("old words"));
    assert_eq!(old.get("sync:mnemonic"), None);
}

#[test]
fn a_set_aside_copy_is_recorded_before_the_value_it_keeps_is_replaced() {
    // The user chose the old data, and the old copy will not delete once its value has taken the current one's place.
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[("sync:mnemonic", "new words")]);
    old.fail("delete", "sync:mnemonic");
    let mut journal = Journal::default();
    journal.use_old_data = true;
    let record = |journal: &Journal| -> Result<(), AppError> {
        log.borrow_mut().push(format!("journal recorded: {}", journal.notes.join(" | ")));
        Ok(())
    };
    assert!(matches!(run_step(&old, &new, &mut journal, &record), StepState::Failed(_)), "its old copy is still to delete");
    let notes = |journal: &Journal| journal.notes.iter().filter(|note| note.contains("set-aside:sync:mnemonic")).count();
    assert_eq!(notes(&journal), 1, "{:?}", journal.notes);
    {
        // In the journal file after the set-aside copy read back, and before the value it keeps was replaced.
        let log = log.borrow();
        let kept = log.iter().rposition(|entry| *entry == format!("{NEW} read set-aside:sync:mnemonic")).unwrap();
        let recorded = log.iter().position(|entry| entry.starts_with("journal recorded:") && entry.contains("set-aside:sync:mnemonic"));
        let replaced = log.iter().position(|entry| *entry == format!("{NEW} write sync:mnemonic")).unwrap();
        assert!(recorded.is_some_and(|recorded| kept < recorded && recorded < replaced), "{log:#?}");
    }

    // The next attempt finds the old value in place and deletes the old copy; the record of the set-aside copy stays, once.
    old.heal();
    assert_eq!(run_step(&old, &new, &mut journal, &record), StepState::Done);
    assert_eq!(notes(&journal), 1, "{:?}", journal.notes);
    assert_eq!(new.get("set-aside:sync:mnemonic").as_deref(), Some("new words"));
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("old words"));
}

#[test]
fn a_set_aside_copy_stays_recorded_however_the_replace_ends() {
    // The value that took the current one's place reads back differently: kept for good, with the set-aside copy recorded.
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[("sync:mnemonic", "new words")]);
    new.garble("sync:mnemonic", usize::MAX);
    let mut journal = Journal::default();
    journal.use_old_data = true;
    assert_eq!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Done);
    assert!(journal.credential_progress.kept.contains_key("sync:mnemonic"), "{journal:?}");
    assert!(journal.notes.iter().any(|note| note.contains("set-aside:sync:mnemonic")), "{:?}", journal.notes);
    assert_eq!(new.get("set-aside:sync:mnemonic").as_deref(), Some("new words"));

    // A journal that cannot be written stops it before anything is replaced: the set-aside copy waits for a later attempt.
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[("sync:mnemonic", "new words")]);
    let mut journal = Journal::default();
    journal.use_old_data = true;
    let full = |_: &Journal| -> Result<(), AppError> { Err(AppError::Other("the disk is full".into())) };
    let StepState::Failed(reason) = run_step(&old, &new, &mut journal, &full) else { panic!("nothing may be replaced") };
    assert!(reason.contains("set-aside:sync:mnemonic") && reason.contains("the disk is full"), "{reason}");
    assert!(!log.borrow().contains(&format!("{NEW} write sync:mnemonic")), "{:#?}", log.borrow());
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("new words"));
    assert_eq!(new.get("set-aside:sync:mnemonic").as_deref(), Some("new words"));
    assert_eq!(old.get("sync:mnemonic").as_deref(), Some("old words"));
    assert_eq!(journal.credential_progress.retrying, 1);
}

#[test]
fn a_service_that_cannot_be_listed_moves_nothing() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[(VAULT_KEY, "vault key")]);
    old.unlistable.set(true);
    let new = Service::new(NEW, &log, &[]);
    let report = migrate_credentials(&old, &new);
    assert!(!report.vault_key_ok, "nothing says where the vault keys are");
    assert!(report.moved.is_empty() && report.failed.len() == 1, "{report:?}");
    assert!(log.borrow().is_empty(), "{:#?}", log.borrow());
    let StepState::Failed(reason) = step_state(&report) else { panic!("{:?}", step_state(&report)) };
    assert!(reason.contains("locked"), "{reason}");
}

#[test]
fn the_reason_of_a_move_that_did_not_finish_stays_short() {
    let failed = (0..200).map(|index| (format!("host:web-{index}"), "the store refused to write it ".repeat(20))).collect();
    let report = CredentialReport { failed, vault_key_ok: true, ..CredentialReport::default() };
    let StepState::Failed(reason) = step_state(&report) else { panic!("{:?}", step_state(&report)) };
    assert!(reason.chars().count() <= MAX_REASON, "{} characters", reason.chars().count());
    assert!(reason.contains("200") && reason.contains("host:web-0"), "{reason}");
}

#[test]
fn an_item_that_can_never_be_read_is_kept_and_not_tried_again() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("host:web-1", "hunter2"), ("host:web-2", "damaged"), (VAULT_KEY, "vault key")]);
    old.damaged.borrow_mut().insert("host:web-2".into());
    let new = Service::new(NEW, &log, &[]);
    let mut journal = Journal::default();
    assert_eq!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Done, "nothing is left for a later attempt");
    let progress = &journal.credential_progress;
    assert!(progress.vault_keys_moved);
    assert_eq!(progress.kept.keys().collect::<Vec<_>>(), ["host:web-2"]);
    assert!(progress.kept["host:web-2"].contains("damaged"), "{progress:?}");
    assert_eq!(progress.retrying, 0);
    assert_eq!(old.get("host:web-2").as_deref(), Some("damaged"), "left as it is");

    // An attempt after that (a journal that came back pending, say) leaves it alone.
    journal.set(Step::Credentials, StepState::Pending);
    log.borrow_mut().clear();
    assert_eq!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Done);
    assert!(logged(&log, "host:web-2").is_empty(), "{:#?}", log.borrow());
    // Once its old item is gone, the record of it goes too.
    old.items.borrow_mut().remove("host:web-2");
    run_step(&old, &new, &mut journal, &unrecorded);
    assert!(journal.credential_progress.kept.is_empty());
}

#[test]
fn the_step_finishes_however_many_items_stay_for_good() {
    // More items can never be read than the journal names: the step is done all the same once nothing is left for a later attempt.
    let log = Log::default();
    let damaged: Vec<String> = (0..MAX_KEPT + 50).map(|index| format!("host:web-{index:03}")).collect();
    let mut items: Vec<(&str, &str)> = damaged.iter().map(|account| (account.as_str(), "damaged")).collect();
    items.push((VAULT_KEY, "vault key"));
    let old = Service::new(OLD, &log, &items);
    old.damaged.borrow_mut().extend(damaged.iter().cloned());
    let new = Service::new(NEW, &log, &[]);
    let mut journal = Journal::default();
    let state = run_step(&old, &new, &mut journal, &unrecorded);
    assert_eq!(state, StepState::Done, "every item has its final fate");
    let progress = &journal.credential_progress;
    assert_eq!((progress.kept.len(), progress.kept_unnamed, progress.retrying), (MAX_KEPT, 50, 0));
    assert!(serde_json::to_vec(&journal).unwrap().len() < 32 * 1024, "the journal stays small");
    // The start that finished says what stays, all of it counted.
    journal.set(Step::Credentials, state);
    if this_build().is_some() {
        let left = left_behind(&journal, true, false).expect("said by the start that finished");
        assert_eq!((left.retry, left.count), (false, MAX_KEPT + 50));
        assert!(left.why.contains("and 50 more"), "{}", left.why);
    }
}

#[test]
fn a_vault_key_kept_for_good_is_named_even_when_the_record_is_full() {
    // The vault's guard reads what is kept by name: a vault key is named whatever else the record holds.
    let log = Log::default();
    let others: Vec<String> = (0..MAX_KEPT).map(|index| format!("host:web-{index:03}")).collect();
    let mut items: Vec<(&str, &str)> = others.iter().map(|account| (account.as_str(), "damaged")).collect();
    items.push((VAULT_KEY, "damaged"));
    let old = Service::new(OLD, &log, &items);
    old.damaged.borrow_mut().insert(VAULT_KEY.into());
    let new = Service::new(NEW, &log, &[]);
    let mut journal = Journal::default();
    journal.credential_progress.kept = others.iter().map(|account| (account.clone(), "it can never be read".to_string())).collect();
    assert_eq!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Done);
    let progress = &journal.credential_progress;
    assert!(progress.kept.contains_key(VAULT_KEY), "{:?}", progress.kept.keys().last());
    assert_eq!((progress.kept.len(), progress.kept_unnamed), (MAX_KEPT + 1, 0));
}

#[test]
fn a_failure_that_may_pass_is_tried_again_silently() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("host:web-1", "hunter2"), (VAULT_KEY, "vault key")]);
    let new = Service::new(NEW, &log, &[]);
    new.fail("write", "host:web-1");
    let mut journal = Journal::default();
    assert!(matches!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Failed(_)));
    assert!(journal.credential_progress.vault_keys_moved, "the vault key moved");
    assert_eq!(journal.credential_progress.retrying, 1);
    assert!(journal.credential_progress.kept.is_empty());
    new.heal();
    assert_eq!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Done);
    assert_eq!(new.get("host:web-1").as_deref(), Some("hunter2"));
    assert_eq!(journal.credential_progress.retrying, 0);
}

/// Where nothing asks the user anything (Windows), an item that failed the same way on `limit` attempts in a row is kept for good:
/// its failure does not pass, and the step would never be done. Another failure, or an attempt that does not leave it for a later one,
/// starts the count again. A vault key is never kept this way (its vault would be set aside): it keeps the vault waiting, as before.
#[test]
fn an_item_that_keeps_failing_the_same_way_is_kept_for_good_where_nothing_asks() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    let new = Service::new(NEW, &log, &[]);
    old.fail("read", "host:web-1");
    old.fail("delete", "host:web-2");
    let mut journal = Journal::default();
    let attempt = |journal: &mut Journal| run_step_keeping_repeated_failures(&old, &new, journal, &unrecorded, 3);
    for times in 1..=2 {
        assert!(matches!(attempt(&mut journal), StepState::Failed(_)), "attempt {times}");
        let progress = &journal.credential_progress;
        assert_eq!((progress.retrying, progress.kept.len()), (2, 0), "attempt {times}: tried again");
        assert_eq!(progress.same_failures["host:web-1"].times, times);
    }
    // host:web-2 fails another way now: its count starts again.
    old.heal();
    old.fail("read", "host:web-1");
    old.fail("read", "host:web-2");
    assert!(matches!(attempt(&mut journal), StepState::Failed(_)));
    let progress = &journal.credential_progress;
    assert_eq!(progress.kept.keys().collect::<Vec<_>>(), ["host:web-1"], "the third attempt in a row that could not read it");
    let why = &progress.kept["host:web-1"];
    assert!(why.contains("3 attempts in a row") && why.contains("the store refused to read it"), "{why}");
    assert_eq!((progress.retrying, progress.same_failures["host:web-2"].times), (1, 1));
    assert!(!progress.same_failures.contains_key("host:web-1"), "kept, not counted");
    assert_eq!(old.get("host:web-1").as_deref(), Some("hunter2"), "left as it is");
    // It moves on a later attempt, which leaves nothing behind: the count goes with it.
    old.heal();
    assert_eq!(attempt(&mut journal), StepState::Done);
    assert_eq!(new.get("host:web-2").as_deref(), Some("an old password"));
    assert!(journal.credential_progress.same_failures.is_empty());

    // A vault key that fails the same way every time is tried again every time, and the vault waits for it.
    let old = Service::new(OLD, &log, &[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")]);
    let new = Service::new(NEW, &log, &[]);
    old.fail("read", VAULT_KEY);
    let mut journal = Journal::default();
    for _ in 0..5 {
        let StepState::Failed(_) = run_step_keeping_repeated_failures(&old, &new, &mut journal, &unrecorded, 3) else { panic!("done") };
    }
    let progress = &journal.credential_progress;
    assert!(progress.kept.is_empty() && progress.same_failures.is_empty() && !progress.vault_keys_moved, "{progress:?}");
    assert!(journal.credentials_wait());

    // Elsewhere an item that fails the same way is tried again however often it did.
    let old = Service::new(OLD, &log, &[("host:web-1", "hunter2")]);
    old.fail("read", "host:web-1");
    let mut journal = Journal::default();
    for _ in 0..5 {
        assert!(matches!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Failed(_)));
    }
    assert!(journal.credential_progress.kept.is_empty() && journal.credential_progress.same_failures.is_empty());
}

#[test]
fn a_conflict_settled_on_the_current_value_is_recorded_and_not_read_again() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[("sync:mnemonic", "new words")]);
    let mut journal = Journal::default();
    assert_eq!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Done);
    assert!(journal.credential_progress.kept.contains_key("sync:mnemonic"), "{journal:?}");
    journal.set(Step::Credentials, StepState::Pending);
    log.borrow_mut().clear();
    run_step(&old, &new, &mut journal, &unrecorded);
    assert!(logged(&log, "sync:mnemonic").is_empty(), "no prompt for it at every start: {:#?}", log.borrow());

    // With the old data chosen, the step sets the current value aside and moves the old one.
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("sync:mnemonic", "old words")]);
    let new = Service::new(NEW, &log, &[("sync:mnemonic", "new words")]);
    let mut journal = Journal::default();
    journal.use_old_data = true;
    assert_eq!(run_step(&old, &new, &mut journal, &unrecorded), StepState::Done);
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("old words"));
    assert_eq!(new.get("set-aside:sync:mnemonic").as_deref(), Some("new words"));
    assert!(journal.notes.iter().any(|note| note.contains("set-aside:sync:mnemonic")), "{:?}", journal.notes);
}

#[test]
fn an_attempt_remembers_what_it_moved_without_writing_it_down() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[("host:web-1", "hunter2"), ("sync:mnemonic", "twelve synthetic words"), (VAULT_KEY, "vault key")]);
    let new = Service::new(NEW, &log, &[]);
    new.fail("write", "sync:mnemonic");
    let mut journal = Journal::default();
    run_step(&old, &new, &mut journal, &unrecorded);
    assert_eq!(journal.moved_credentials, [VAULT_KEY, "host:web-1"]);
    assert!(!serde_json::to_string(&journal).unwrap().contains("host:web-1"), "not in the journal file");
    // A restart helps the running app only for what it read when it started: a vault key, or the sync code.
    assert!(restart_helps(&journal.moved_credentials));
    assert!(!restart_helps(&["host:web-1".to_string(), "central:v2:token:acme-prod-123456".to_string()]));
    assert!(restart_helps(&["sync:mnemonic".to_string()]));
    assert!(!restart_helps(&[]));
}

/// What an attempt remembers for the running app is what it made usable under the new service: a value it wrote and read back there,
/// also when its old copy would not delete. An identical copy that was there already (an earlier attempt's) only loses its old copy:
/// the running app had it.
#[test]
fn an_attempt_remembers_only_what_it_made_usable() {
    let log = Log::default();
    let old = Service::new(OLD, &log, &[(VAULT_KEY, "vault key"), ("sync:mnemonic", "twelve synthetic words"), ("host:web-1", "hunter2")]);
    let new = Service::new(NEW, &log, &[(VAULT_KEY, "vault key")]);
    old.fail("delete", "sync:mnemonic");
    let mut journal = Journal::default();
    run_step(&old, &new, &mut journal, &unrecorded);
    assert_eq!(new.get("sync:mnemonic").as_deref(), Some("twelve synthetic words"), "written, its old copy kept");
    assert!(old.get(VAULT_KEY).is_none(), "the identical copy moved by deleting the old one");
    assert_eq!(journal.moved_credentials, ["host:web-1", "sync:mnemonic"]);
    assert_eq!(journal.credential_progress.start_credential_moves, 1, "the sync code became usable");
    // The next attempt deletes the sync code's old copy: nothing new for the running app.
    old.heal();
    run_step(&old, &new, &mut journal, &unrecorded);
    assert!(old.get("sync:mnemonic").is_none());
    assert!(journal.moved_credentials.is_empty());
    assert_eq!(journal.credential_progress.start_credential_moves, 1);
}

#[test]
fn the_vault_guard_asks_about_this_vaults_own_key() {
    let other = "vault:key:fedcba9876543210".to_string();
    assert!(!holds_vault_key(VAULT_KEY, Ok(vec!["host:web-1".into(), other.clone()])), "another vault's key does not hold this one");
    assert!(holds_vault_key(VAULT_KEY, Ok(vec![other.clone(), VAULT_KEY.into()])));
    assert!(holds_vault_key("vault:key", Ok(vec!["vault:key".into()])), "the first vault's own account");
    assert!(holds_vault_key(VAULT_KEY, Ok(vec![format!("migration:0123:{VAULT_KEY}")])), "an import staged under its own name");
    assert!(!holds_vault_key(VAULT_KEY, Ok(vec![format!("migration:0123:{other}")])));
    assert!(!holds_vault_key(VAULT_KEY, Ok(Vec::new())));
    assert!(holds_vault_key(VAULT_KEY, Err(AppError::Other("locked".into()))), "what cannot be listed may hold it");
    let none = BTreeMap::new();
    let pending = missing_vault_key(true, &none, VAULT_KEY, || panic!("nothing is listed while the vault keys are pending"));
    assert_eq!(pending, MissingVaultKey::MayStillMove);
    assert_eq!(missing_vault_key(false, &none, VAULT_KEY, || Ok(vec![VAULT_KEY.into()])), MissingVaultKey::MayStillMove);
    assert_eq!(missing_vault_key(false, &none, VAULT_KEY, || Ok(vec![other.clone()])), MissingVaultKey::Lost);
}

#[test]
fn a_vault_key_kept_for_good_is_not_on_its_way() {
    let why = "it can never be read: the item's data is damaged";
    let kept = BTreeMap::from([(VAULT_KEY.to_string(), why.to_string())]);
    let left = MissingVaultKey::LeftBehind(why.into());
    // The old service still holds it, and other vault keys may still be on their way: neither brings it back.
    assert_eq!(missing_vault_key(false, &kept, VAULT_KEY, || Ok(vec![VAULT_KEY.into()])), left);
    assert_eq!(missing_vault_key(true, &kept, VAULT_KEY, || Ok(vec![VAULT_KEY.into()])), left);
    // An import's staged copy of it that may still move is on its way, and so is what cannot be listed.
    let staged = || Ok(vec![VAULT_KEY.into(), format!("migration:0123:{VAULT_KEY}")]);
    assert_eq!(missing_vault_key(false, &kept, VAULT_KEY, staged), MissingVaultKey::MayStillMove);
    let locked = || Err(AppError::Other("locked".into()));
    assert_eq!(missing_vault_key(false, &kept, VAULT_KEY, locked), MissingVaultKey::MayStillMove);
    // Another vault's key kept for good says nothing of this one.
    let other = BTreeMap::from([("vault:key:fedcba9876543210".to_string(), why.to_string())]);
    assert_eq!(missing_vault_key(false, &other, VAULT_KEY, || Ok(vec![VAULT_KEY.into()])), MissingVaultKey::MayStillMove);
}

#[test]
fn only_the_desktop_moves_credentials_and_never_hidden_where_a_store_may_ask() {
    for store in [Store::Windows, Store::SecretService, Store::Keychain, Store::CredentialHelpers] {
        assert!(runs(Some(store), Entry::Desktop, false), "{store:?}");
        for entry in [Entry::Connect, Entry::Mcp] {
            assert!(!runs(Some(store), entry, false), "{store:?} {entry:?}");
        }
    }
    assert!(runs(Some(Store::Windows), Entry::Desktop, true), "the Windows store never asks");
    assert!(runs(Some(Store::CredentialHelpers), Entry::Desktop, true), "no request of macOS Production's move lets macOS ask");
    assert!(!runs(Some(Store::SecretService), Entry::Desktop, true), "a hidden start leaves the Secret Service for a start the user sees");
    assert!(!runs(Some(Store::Keychain), Entry::Desktop, true));
    assert!(!runs(None, Entry::Desktop, false), "on a platform where this version moves nothing, the step waits");
    #[cfg(windows)]
    assert_eq!(this_build(), Some(Store::Windows));
    #[cfg(target_os = "linux")]
    assert_eq!(this_build(), Some(Store::SecretService));
    #[cfg(target_os = "macos")]
    assert_eq!(
        this_build(),
        Some(if app_profile::CURRENT == AppProfile::Development { Store::Keychain } else { Store::CredentialHelpers })
    );
}
