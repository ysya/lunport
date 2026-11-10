//! The Windows Credential Manager and its DPAPI files as `credential_blob`'s test backend models them. No test reaches the real
//! Credential Manager.

use super::super::credentials::{migrate_credentials, LegacyCredentials};
use super::super::journal::Journal;
use super::super::StepState;
use super::*;
use crate::secrets::credential_blob::tests::{Fixture, Slot};

const OLD: &str = "SSHelter";
const NEW: &str = "Lunport";

/// One service's entries in a store of their own.
impl Stores for Fixture {
    type Store<'a> = Slot<'a>;
    fn store<'a>(&'a self, account: &'a str) -> Result<Slot<'a>, AppError> {
        Ok(self.slot(account))
    }
}

/// One service's entries in the store all services share, named `<account>.<service>` as the keyring crate names a Windows
/// credential, over the one folder of DPAPI files the data root holds: what production has.
struct Shared<'f> {
    store: &'f Fixture,
    service: &'static str,
}

impl Stores for Shared<'_> {
    type Store<'a>
        = Slot<'a>
    where
        Self: 'a;
    fn store<'a>(&'a self, account: &'a str) -> Result<Slot<'a>, AppError> {
        Ok(self.store.slot_named(format!("{account}.{}", self.service)))
    }
}

/// The entry names of `store`, as the Credential Manager lists them.
fn targets_of(store: &Fixture) -> impl Fn() -> Result<Vec<String>, AppError> + '_ {
    move || Ok(store.entry_names())
}

#[test]
fn windows_large_value_is_reencrypted_with_the_new_service() {
    let (old_store, new_store) = (Fixture::default(), Fixture::default());
    let archive = "central:v2:source-archive-1:acme-prod-123456";
    let large = "synthetic archive credential \u{1f512}".repeat(200);
    blob::set(&old_store.slot(archive), OLD, archive, &large).unwrap();
    blob::set(&old_store.slot("host:web-1"), OLD, "host:web-1", "hunter2").unwrap();
    assert_eq!(old_store.files(), 1, "the large value lives in a DPAPI file");
    let targets = || -> Result<Vec<String>, AppError> { Ok(vec![format!("{archive}.{OLD}"), format!("host:web-1.{OLD}")]) };
    let none = || -> Result<Vec<String>, AppError> { Ok(Vec::new()) };
    let report = migrate_credentials(
        &Blobs { service: OLD, stores: &old_store, targets: &targets },
        &Blobs { service: NEW, stores: &new_store, targets: &none },
    );
    assert!(report.vault_key_ok && report.failed.is_empty(), "{report:?}");
    assert_eq!(report.moved, [archive, "host:web-1"]);
    // The copy is encrypted again, in a file of its own, bound to the new service: it opens with the new service's binding only.
    assert_eq!(blob::get(&new_store.slot(archive), NEW, archive).unwrap().as_deref(), Some(large.as_str()));
    assert!(blob::get(&new_store.slot(archive), OLD, archive).is_err(), "the old service's binding does not open it");
    assert_eq!(new_store.files(), 1);
    assert_eq!(blob::get(&new_store.slot("host:web-1"), NEW, "host:web-1").unwrap().as_deref(), Some("hunter2"));
    // The old entries are gone, and with the old entry its file.
    assert_eq!(blob::get(&old_store.slot(archive), OLD, archive).unwrap(), None);
    assert_eq!(blob::get(&old_store.slot("host:web-1"), OLD, "host:web-1").unwrap(), None);
    assert_eq!(old_store.files(), 0);
}

#[test]
fn both_services_share_one_folder_of_dpapi_files() {
    // Production keeps the old service's files and the new one's in the same `protected-credentials` folder.
    let store = Fixture::default();
    let archive = "central:v2:source-archive-1:acme-prod-123456";
    let large = "synthetic archive credential \u{1f512}".repeat(200);
    let (old, new) = (Shared { store: &store, service: OLD }, Shared { store: &store, service: NEW });
    blob::set(&old.store(archive).unwrap(), OLD, archive, &large).unwrap();
    blob::set(&old.store("host:web-1").unwrap(), OLD, "host:web-1", "hunter2").unwrap();
    let targets = targets_of(&store);
    let report = migrate_credentials(
        &Blobs { service: OLD, stores: &old, targets: &targets },
        &Blobs { service: NEW, stores: &new, targets: &targets },
    );
    assert!(report.vault_key_ok && report.failed.is_empty() && report.kept.is_empty(), "{report:?}");
    assert_eq!(store.entry_names(), [format!("{archive}.{NEW}"), format!("host:web-1.{NEW}")], "the old entries are gone");
    assert_eq!(store.files(), 1, "the new file is there and the old one went with the old entry");
    assert_eq!(blob::get(&new.store(archive).unwrap(), NEW, archive).unwrap().as_deref(), Some(large.as_str()));
    assert!(blob::get(&new.store(archive).unwrap(), OLD, archive).is_err(), "bound to the new service");
}

#[test]
fn windows_targets_are_renamed() {
    assert_eq!(account_of("host:x.SSHelter", OLD), Some("host:x"));
    assert_eq!(account_of("host:web-1.example.com.SSHelter", OLD), Some("host:web-1.example.com"), "an account may hold dots");
    assert_eq!(account_of("host:x.SSHelter Development", OLD), None, "the other profile's");
    assert_eq!(account_of("host:x.SSHelter Development", "SSHelter Development"), Some("host:x"));
    assert_eq!(account_of("host:x.Lunport", OLD), None);
    assert_eq!(account_of("host:xSSHelter", OLD), None);
    assert_eq!(account_of(".SSHelter", OLD), None, "no account");
    assert_eq!(account_of("SSHelter", OLD), None);

    // Other services' entries and other programs' share the Credential Manager, and stay as they are.
    let store = Fixture::default();
    let (old, new) = (Shared { store: &store, service: OLD }, Shared { store: &store, service: NEW });
    blob::set(&old.store("host:x").unwrap(), OLD, "host:x", "hunter2").unwrap();
    let development = Shared { store: &store, service: "SSHelter Development" };
    blob::set(&development.store("host:y").unwrap(), "SSHelter Development", "host:y", "development password").unwrap();
    store.slot("git:https://github.com").set_entry(b"x\0").unwrap();
    let targets = targets_of(&store);
    let report = migrate_credentials(
        &Blobs { service: OLD, stores: &old, targets: &targets },
        &Blobs { service: NEW, stores: &new, targets: &targets },
    );
    assert_eq!(report.moved, ["host:x"], "{report:?}");
    assert_eq!(store.entry_names(), ["git:https://github.com", "host:x.Lunport", "host:y.SSHelter Development"]);
    assert_eq!(blob::get(&new.store("host:x").unwrap(), NEW, "host:x").unwrap().as_deref(), Some("hunter2"));
}

#[test]
fn an_entry_whose_file_is_gone_is_kept_and_not_tried_again() {
    let store = Fixture::default();
    let (old, new) = (Shared { store: &store, service: OLD }, Shared { store: &store, service: NEW });
    let archive = "central:v2:source-archive-1:acme-prod-123456";
    blob::set(&old.store(archive).unwrap(), OLD, archive, &"synthetic \u{1f512}".repeat(400)).unwrap();
    blob::set(&old.store("host:web-1").unwrap(), OLD, "host:web-1", "hunter2").unwrap();
    // The entry points to a DPAPI file that is not there any more.
    store.remove_files();
    let targets = targets_of(&store);
    let blobs = Blobs { service: OLD, stores: &old, targets: &targets };
    let error = LegacyCredentials::read(&blobs, archive).unwrap_err();
    assert!(blobs.unreadable_for_good(&error), "{error}");
    let report = migrate_credentials(&blobs, &Blobs { service: NEW, stores: &new, targets: &targets });
    assert_eq!(report.moved, ["host:web-1"]);
    assert_eq!(report.kept.iter().map(|(account, _)| account.as_str()).collect::<Vec<_>>(), [archive], "{report:?}");
    assert!(report.failed.is_empty(), "{report:?}");
    assert!(store.entry_names().contains(&format!("{archive}.{OLD}")), "left as it is");
}

fn refuse_files(store: &Fixture) {
    // What the pinned reader says of a file it will not read (too large, linked, with other streams, changed while it was read).
    store.fail_file_reads(Some(std::io::ErrorKind::PermissionDenied));
}

fn refuse_decryption(store: &Fixture) {
    // A DPAPI error other than the two that mean damaged data.
    store.fail_decryption(Some(5));
}

/// Windows never asks the user anything, so an entry that fails the same way on every start would never move, and every start would
/// say so: a DPAPI file the pinned reader refuses, or a DPAPI error other than the two that mean damaged data. After three attempts in a
/// row that left it for the same reason it is kept for good, as it is, and the step is done.
#[test]
fn an_entry_that_fails_the_same_way_three_attempts_in_a_row_is_kept_for_good() {
    let archive = "central:v2:source-archive-1:acme-prod-123456";
    let large = "synthetic \u{1f512}".repeat(400);
    let cases: [(fn(&Fixture), &str); 2] = [(refuse_files, "cannot be read right now"), (refuse_decryption, "(Windows error 5)")];
    for (fail, says) in cases {
        let store = Fixture::default();
        let (old, new) = (Shared { store: &store, service: OLD }, Shared { store: &store, service: NEW });
        blob::set(&old.store(archive).unwrap(), OLD, archive, &large).unwrap();
        blob::set(&old.store("host:web-1").unwrap(), OLD, "host:web-1", "hunter2").unwrap();
        fail(&store);
        let targets = targets_of(&store);
        let (from, to) = (Blobs { service: OLD, stores: &old, targets: &targets }, Blobs { service: NEW, stores: &new, targets: &targets });
        let mut journal = Journal::default();
        for attempt in 1..SAME_FAILURES_BEFORE_KEEPING {
            assert!(matches!(move_entries(&from, &to, &mut journal, &|_| Ok(())), StepState::Failed(_)), "{says}: attempt {attempt}");
            assert_eq!(journal.credential_progress.retrying, 1, "{says}");
        }
        assert_eq!(move_entries(&from, &to, &mut journal, &|_| Ok(())), StepState::Done, "{says}");
        let why = &journal.credential_progress.kept[archive];
        assert!(why.contains(says), "{why}");
        assert!(store.entry_names().contains(&format!("{archive}.{OLD}")), "{says}: left as it is");
        assert_eq!(blob::get(&new.store("host:web-1").unwrap(), NEW, "host:web-1").unwrap().as_deref(), Some("hunter2"));
    }
}

/// The user chose the earlier data: a value saved under the new name in a DPAPI file went with the folders set aside, so the new name
/// can no longer be checked, the same way on every start. After three attempts in a row the earlier entry is kept for good, as it is.
#[test]
fn an_entry_whose_new_name_cannot_be_checked_is_kept_after_three_attempts() {
    let store = Fixture::default();
    let (old, new) = (Shared { store: &store, service: OLD }, Shared { store: &store, service: NEW });
    let archive = "central:v2:source-archive-1:acme-prod-123456";
    blob::set(&new.store(archive).unwrap(), NEW, archive, &"synthetic \u{1f512}".repeat(400)).unwrap();
    store.remove_files();
    blob::set(&old.store(archive).unwrap(), OLD, archive, "an earlier synthetic value").unwrap();
    let targets = targets_of(&store);
    let (from, to) = (Blobs { service: OLD, stores: &old, targets: &targets }, Blobs { service: NEW, stores: &new, targets: &targets });
    let mut journal = Journal::default();
    journal.use_old_data = true;
    for _ in 1..SAME_FAILURES_BEFORE_KEEPING {
        assert!(matches!(move_entries(&from, &to, &mut journal, &|_| Ok(())), StepState::Failed(_)));
    }
    assert_eq!(move_entries(&from, &to, &mut journal, &|_| Ok(())), StepState::Done);
    let why = &journal.credential_progress.kept[archive];
    assert!(why.contains("the new name could not be checked"), "{why}");
    assert_eq!(blob::get(&old.store(archive).unwrap(), OLD, archive).unwrap().as_deref(), Some("an earlier synthetic value"));
}

#[test]
fn a_dpapi_file_that_cannot_be_read_for_now_is_tried_again() {
    let store = Fixture::default();
    let (old, new) = (Shared { store: &store, service: OLD }, Shared { store: &store, service: NEW });
    let archive = "central:v2:source-archive-1:acme-prod-123456";
    let large = "synthetic \u{1f512}".repeat(400);
    blob::set(&old.store(archive).unwrap(), OLD, archive, &large).unwrap();
    // Another process holds its file open (a sharing violation): left for a later start, never kept for good.
    store.fail_file_reads(Some(std::io::ErrorKind::Other));
    let targets = targets_of(&store);
    let (from, to) = (Blobs { service: OLD, stores: &old, targets: &targets }, Blobs { service: NEW, stores: &new, targets: &targets });
    let report = migrate_credentials(&from, &to);
    assert_eq!(report.failed.iter().map(|(account, _)| account.as_str()).collect::<Vec<_>>(), [archive], "{report:?}");
    assert!(report.kept.is_empty(), "{report:?}");
    // The next start reads it.
    store.fail_file_reads(None);
    let report = migrate_credentials(&from, &to);
    assert_eq!(report.moved, [archive], "{report:?}");
    assert_eq!(blob::get(&new.store(archive).unwrap(), NEW, archive).unwrap().as_deref(), Some(large.as_str()));
}
