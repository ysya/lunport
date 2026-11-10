//! The Secret Service as a list of items. No test reaches a real Secret Service.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use super::super::credentials::{CurrentCredentials, LegacyCredentials};
use super::super::journal::Journal;
use super::super::Step;
use super::*;

/// How the step records the journal where a test does not look at it.
fn unrecorded(_: &Journal) -> Result<(), AppError> {
    Ok(())
}

const OLD: &str = "SSHelter";
const NEW: &str = "Lunport";
const VAULT_KEY: &str = "vault:key:0123456789abcdef";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Item {
    attributes: BTreeMap<String, String>,
    label: String,
    secret: Vec<u8>,
    locked: bool,
}

fn item(service: &str, account: &str, secret: &[u8]) -> Item {
    Item {
        attributes: BTreeMap::from([("service".into(), service.into()), ("username".into(), account.into())]),
        label: format!("keyring:{account}@{service}"),
        secret: secret.to_vec(),
        locked: false,
    }
}

/// A Secret Service: its items, and whether its default collection is locked.
#[derive(Default)]
struct FakeSecretService {
    items: RefCell<Vec<Item>>,
    default_locked: Cell<bool>,
}

impl FakeSecretService {
    fn with(items: Vec<Item>) -> Self {
        Self { items: RefCell::new(items), default_locked: Cell::new(false) }
    }

    fn named(item: &Item, service: &str, account: &str) -> bool {
        item.attributes["service"] == service && item.attributes["username"] == account
    }

    fn matching(&self, service: &str, account: &str) -> Vec<Item> {
        self.items.borrow().iter().filter(|item| Self::named(item, service, account)).cloned().collect()
    }

    fn secret_of(&self, service: &str, account: &str) -> Option<Vec<u8>> {
        self.matching(service, account).first().map(|item| item.secret.clone())
    }
}

impl SecretItems for FakeSecretService {
    fn listing(&self, service: &str) -> Result<Listing, AppError> {
        let items = self.items.borrow();
        let of_service = || items.iter().filter(|item| item.attributes["service"] == service);
        Ok(Listing {
            accounts: of_service().filter(|item| !item.locked).map(|item| item.attributes["username"].clone()).collect(),
            locked: of_service().filter(|item| item.locked).count(),
        })
    }
    fn secrets(&self, service: &str, account: &str) -> Result<Vec<Zeroizing<Vec<u8>>>, AppError> {
        let found = self.matching(service, account);
        if found.iter().any(|item| item.locked) {
            return Err(AppError::Other("the item is locked".into()));
        }
        Ok(found.into_iter().map(|item| Zeroizing::new(item.secret)).collect())
    }
    fn save(&self, service: &str, account: &str, label: &str, secret: &[u8]) -> Result<(), AppError> {
        if self.default_locked.get() {
            return Err(AppError::Other("the collection is locked".into()));
        }
        let mut items = self.items.borrow_mut();
        let named: Vec<usize> = (0..items.len()).filter(|&index| Self::named(&items[index], service, account)).collect();
        match named.as_slice() {
            [] => {
                let mut created = item(service, account, secret);
                created.label = label.to_string();
                items.push(created);
            }
            &[index] if !items[index].locked => items[index].secret = secret.to_vec(),
            _ => return Err(AppError::Other("the item cannot be replaced".into())),
        }
        Ok(())
    }
    fn delete(&self, service: &str, account: &str) -> Result<(), AppError> {
        if self.matching(service, account).iter().any(|item| item.locked) {
            return Err(AppError::Other("the item is locked".into()));
        }
        self.items.borrow_mut().retain(|item| !Self::named(item, service, account));
        Ok(())
    }
    fn default_collection_locked(&self) -> Result<bool, AppError> {
        Ok(self.default_locked.get())
    }
}

#[test]
fn linux_items_move_by_service_attribute() {
    let development = item("SSHelter Development", "host:web-1", b"development password");
    let foreign = item("org.example.Other", "host:web-1", b"another program's");
    let ss = FakeSecretService::with(vec![
        item(OLD, "host:web-1", b"hunter2"),
        item(OLD, VAULT_KEY, b"vault key"),
        development.clone(),
        foreign.clone(),
    ]);
    let mut journal = Journal::default();
    assert_eq!(move_with(&ss, OLD, NEW, &mut journal, &unrecorded), StepState::Done);
    assert!(journal.credential_progress.vault_keys_moved);
    let items = ss.items.borrow();
    assert!(!items.iter().any(|item| item.attributes["service"] == OLD), "{items:#?}");
    for (account, secret) in [("host:web-1", "hunter2"), (VAULT_KEY, "vault key")] {
        let moved = items.iter().find(|item| item.attributes["service"] == NEW && item.attributes["username"] == account).unwrap();
        assert_eq!(moved.attributes.len(), 2, "{moved:?}");
        assert_eq!(moved.label, format!("keyring:{account}@Lunport"));
        assert_eq!(moved.label, label(account, NEW));
        assert_eq!(moved.secret, secret.as_bytes());
    }
    assert!(items.contains(&development) && items.contains(&foreign), "other services' items stay: {items:#?}");
    assert_eq!(items.len(), 4);
}

#[test]
fn linux_waits_while_the_keyring_is_locked() {
    // New items go to the default collection: while it is locked, nothing is asked and nothing moves.
    let ss = FakeSecretService::with(vec![item(OLD, "host:web-1", b"hunter2")]);
    ss.default_locked.set(true);
    let before = ss.items.borrow().clone();
    let mut journal = Journal::default();
    let StepState::Failed(reason) = move_with(&ss, OLD, NEW, &mut journal, &unrecorded) else { panic!("the step waits") };
    assert!(reason.contains("locked"), "{reason}");
    assert!(journal.credential_progress.waiting_for_the_user, "Retry helps once it is unlocked");
    assert!(!journal.credential_progress.vault_keys_moved);
    assert_eq!(*ss.items.borrow(), before);

    // An old item that is locked may be the vault key.
    let mut locked = item(OLD, VAULT_KEY, b"vault key");
    locked.locked = true;
    let ss = FakeSecretService::with(vec![item(OLD, "host:web-1", b"hunter2"), locked]);
    let before = ss.items.borrow().clone();
    let mut journal = Journal::default();
    assert!(matches!(move_with(&ss, OLD, NEW, &mut journal, &unrecorded), StepState::Failed(reason) if reason.contains("locked")));
    assert!(journal.credential_progress.waiting_for_the_user);
    assert_eq!(*ss.items.borrow(), before, "nothing moved");

    // Unlocked, the next attempt moves them and stops waiting.
    ss.items.borrow_mut().iter_mut().for_each(|item| item.locked = false);
    assert_eq!(move_with(&ss, OLD, NEW, &mut journal, &unrecorded), StepState::Done);
    assert!(!journal.credential_progress.waiting_for_the_user);
}

#[test]
fn linux_replaces_a_current_value_only_once_it_is_set_aside() {
    // The user chose the old data: the item under the new service is kept as `set-aside:<account>` and then takes the old value.
    let ss = FakeSecretService::with(vec![item(OLD, "sync:mnemonic", b"old words"), item(NEW, "sync:mnemonic", b"new words")]);
    let mut journal = Journal::default();
    journal.use_old_data = true;
    assert_eq!(move_with(&ss, OLD, NEW, &mut journal, &unrecorded), StepState::Done);
    assert_eq!(ss.secret_of(NEW, "sync:mnemonic").as_deref(), Some(&b"old words"[..]));
    assert_eq!(ss.secret_of(NEW, "set-aside:sync:mnemonic").as_deref(), Some(&b"new words"[..]));
    assert_eq!(ss.matching(NEW, "sync:mnemonic").len(), 1, "replaced, not doubled");
    assert!(ss.matching(OLD, "sync:mnemonic").is_empty());
}

#[test]
fn a_value_that_is_not_text_is_kept_and_not_tried_again() {
    let ss = FakeSecretService::with(vec![item(OLD, "host:web-1", b"hunter2"), item(OLD, "host:web-2", &[0xff, 0xfe])]);
    let old = Items { ss: &ss, service: OLD };
    let error = LegacyCredentials::read(&old, "host:web-2").unwrap_err();
    assert!(old.unreadable_for_good(&error), "{error}");
    let mut journal = Journal::default();
    assert_eq!(move_with(&ss, OLD, NEW, &mut journal, &unrecorded), StepState::Done);
    assert!(journal.credential_progress.kept.contains_key("host:web-2"), "{journal:?}");
    assert_eq!(ss.secret_of(NEW, "host:web-1").as_deref(), Some(&b"hunter2"[..]));
    assert_eq!(ss.secret_of(OLD, "host:web-2").as_deref(), Some(&[0xff, 0xfe][..]), "left as it is");
    assert!(CurrentCredentials::read(&Items { ss: &ss, service: NEW }, "host:web-2").unwrap().is_none());
}

#[test]
fn linux_copies_of_one_old_item_move_as_one() {
    // Two old items with the same name and the same secret are one item: it moves once, and both old copies go.
    let ss = FakeSecretService::with(vec![item(OLD, "host:web-1", b"hunter2"), item(OLD, "host:web-1", b"hunter2")]);
    let mut journal = Journal::default();
    assert_eq!(move_with(&ss, OLD, NEW, &mut journal, &unrecorded), StepState::Done);
    assert!(ss.matching(OLD, "host:web-1").is_empty(), "{:#?}", ss.items.borrow());
    assert_eq!(ss.matching(NEW, "host:web-1").len(), 1);
    assert_eq!(ss.secret_of(NEW, "host:web-1").as_deref(), Some(&b"hunter2"[..]));
    assert!(journal.credential_progress.kept.is_empty(), "{journal:?}");
}

#[test]
fn linux_old_items_that_differ_are_kept_for_good() {
    // Two old items with the same name and different secrets: nothing tells which one is meant, and nothing the user can do in Lunport
    // changes that. Kept for good, said why, and never tried again (a locked keyring, which the user can unlock, stays retry-later:
    // `linux_waits_while_the_keyring_is_locked`).
    let ss = FakeSecretService::with(vec![
        item(OLD, "host:web-1", b"hunter2"),
        item(OLD, "host:web-1", b"hunter3"),
        item(OLD, "host:web-2", b"another password"),
    ]);
    let old = Items { ss: &ss, service: OLD };
    let error = LegacyCredentials::read(&old, "host:web-1").unwrap_err();
    assert!(old.unreadable_for_good(&error), "{error}");
    assert!(error.to_string().contains("ambiguous"), "{error}");
    let mut journal = Journal::default();
    assert_eq!(move_with(&ss, OLD, NEW, &mut journal, &unrecorded), StepState::Done, "nothing is left for a later attempt");
    assert!(journal.credential_progress.kept.get("host:web-1").is_some_and(|why| why.contains("ambiguous")), "{journal:?}");
    assert_eq!(ss.matching(OLD, "host:web-1").len(), 2, "both are left as they are");
    assert!(ss.matching(NEW, "host:web-1").is_empty());
    assert_eq!(ss.secret_of(NEW, "host:web-2").as_deref(), Some(&b"another password"[..]), "the rest moved");
    // A later attempt (a journal that came back pending, say) leaves them alone.
    journal.set(Step::Credentials, StepState::Pending);
    let before = ss.items.borrow().clone();
    assert_eq!(move_with(&ss, OLD, NEW, &mut journal, &unrecorded), StepState::Done);
    assert_eq!(*ss.items.borrow(), before);
}
