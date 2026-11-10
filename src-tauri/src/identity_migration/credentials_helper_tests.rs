//! macOS Production's move (helper v1 through the bridge, helper v2) with the keychain in memory. The adopt fallback's tests
//! (`credentials_adopt_tests.rs`) use the same stand-ins. No test reaches a real keychain or helper: this computer's hold the owner's
//! own items.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use zeroize::Zeroizing;

use super::super::credentials::{CurrentCredentials, LegacyCredentials};
use super::super::credentials_adopt::Adopter;
use super::super::credentials_macos::LOCKED;
use super::super::journal::Journal;
use super::*;
use crate::error::AppError;
use crate::secrets::macos_helper::Adoption;

pub(in crate::identity_migration) const VAULT_KEY: &str = "vault:key:0123456789abcdef";
/// What the stand-in bridge says of an item helper v1 may not reach without asking.
const NOT_ALLOWED: &str = "helper v1 may not reach it without asking";
/// What the stand-in bridge says when it did not get an answer from helper v1, in a way that may pass.
const UNREACHABLE: &str = "the bridge did not answer in time";

/// One test's keychain in memory: the items under the earlier service and under this version's, what helper v1 may not reach without
/// asking, what the user answers when macOS asks, and every request in order (`<program> <operation> <account>`).
#[derive(Default)]
pub(in crate::identity_migration) struct Keychain {
    pub earlier: RefCell<BTreeMap<String, String>>,
    pub current: RefCell<BTreeMap<String, String>>,
    /// Items helper v1 may neither read nor delete without asking.
    pub not_allowed: RefCell<BTreeSet<String>>,
    /// Items helper v1 may read but not delete without asking.
    pub undeletable: RefCell<BTreeSet<String>>,
    /// Items about which the bridge fails, in a way that may pass.
    pub unreachable: RefCell<BTreeSet<String>>,
    /// The pinned SHA-256 of the bridge this keychain is reached through (`EarlierHelper::bridge`); "bridge-1" when not set.
    pub bridge: RefCell<String>,
    /// Items the user does not allow when macOS asks.
    pub denied: RefCell<BTreeSet<String>>,
    /// What adopt answers for an account, once, instead of moving it.
    pub scripted: RefCell<BTreeMap<String, Adoption>>,
    /// The adopt request for an account (counted from 1) at which helper v2 cannot be reached.
    pub unreachable_adopt: RefCell<BTreeMap<String, usize>>,
    /// What happens while macOS asks, at every adopt request.
    #[allow(clippy::type_complexity)]
    pub on_adopt: RefCell<Option<Box<dyn Fn()>>>,
    adopts: RefCell<BTreeMap<String, usize>>,
    pub log: Rc<RefCell<Vec<String>>>,
}

impl Keychain {
    /// A keychain whose earlier service holds `items`.
    pub fn with(items: &[(&str, &str)]) -> Self {
        let keychain = Self::default();
        keychain.earlier.borrow_mut().extend(items.iter().map(|&(account, value)| (account.to_string(), value.to_string())));
        keychain
    }

    pub fn earlier(&self, account: &str) -> Option<String> {
        self.earlier.borrow().get(account).cloned()
    }

    pub fn current(&self, account: &str) -> Option<String> {
        self.current.borrow().get(account).cloned()
    }

    pub fn entries(&self) -> Vec<String> {
        self.log.borrow().clone()
    }

    fn logged(&self, entry: String) {
        self.log.borrow_mut().push(entry);
    }
}

pub(in crate::identity_migration) fn set(accounts: &[&str]) -> BTreeSet<String> {
    accounts.iter().map(|account| account.to_string()).collect()
}

/// Helper v1 through the bridge.
pub(in crate::identity_migration) struct Bridge<'a>(pub &'a Keychain);

impl EarlierHelper for Bridge<'_> {
    fn accounts(&self) -> Result<Vec<String>, AppError> {
        Ok(self.0.earlier.borrow().keys().cloned().collect())
    }
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.0.logged(format!("bridge get {account}"));
        if self.0.unreachable.borrow().contains(account) {
            return Err(AppError::Other(UNREACHABLE.into()));
        }
        if self.0.not_allowed.borrow().contains(account) {
            return Err(AppError::Other(NOT_ALLOWED.into()));
        }
        Ok(self.0.earlier(account).map(Zeroizing::new))
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.0.logged(format!("bridge delete {account}"));
        if self.0.not_allowed.borrow().contains(account) || self.0.undeletable.borrow().contains(account) {
            return Err(AppError::Other(NOT_ALLOWED.into()));
        }
        self.0.earlier.borrow_mut().remove(account);
        Ok(())
    }
    fn needs_permission(&self, error: &AppError) -> bool {
        error.to_string() == NOT_ALLOWED
    }
    fn chain_failed(&self, error: &AppError) -> bool {
        error.to_string() == UNREACHABLE
    }
    fn unreadable_for_good(&self, _: &AppError) -> bool {
        false
    }
    fn bridge(&self) -> String {
        let bridge = self.0.bridge.borrow();
        if bridge.is_empty() { "bridge-1".into() } else { bridge.clone() }
    }
}

/// Helper v2: this version's items, and adopt, which asks the user (`denied`) and moves an item itself.
pub(in crate::identity_migration) struct HelperV2<'a>(pub &'a Keychain);

impl CurrentCredentials for HelperV2<'_> {
    fn write(&self, account: &str, value: &str) -> Result<(), AppError> {
        self.0.logged(format!("helper-v2 write {account}"));
        self.0.current.borrow_mut().insert(account.to_string(), value.to_string());
        Ok(())
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.0.logged(format!("helper-v2 read {account}"));
        Ok(self.0.current(account).map(Zeroizing::new))
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.0.logged(format!("helper-v2 delete {account}"));
        self.0.current.borrow_mut().remove(account);
        Ok(())
    }
}

impl Adopter for HelperV2<'_> {
    fn adopt(&self, account: &str) -> Result<Adoption, AppError> {
        self.0.logged(format!("helper-v2 adopt {account}"));
        let call = {
            let mut adopts = self.0.adopts.borrow_mut();
            let call = adopts.entry(account.to_string()).or_default();
            *call += 1;
            *call
        };
        if let Some(during) = self.0.on_adopt.borrow().as_ref() {
            during();
        }
        if self.0.unreachable_adopt.borrow().get(account) == Some(&call) {
            return Err(AppError::Other("credential helper: request was cancelled, timed out or the helper stopped".into()));
        }
        if let Some(scripted) = self.0.scripted.borrow_mut().remove(account) {
            // A copy that did not read back may stay under the current service.
            if scripted == Adoption::NotVerified {
                if let Some(old) = self.0.earlier(account) {
                    self.0.current.borrow_mut().insert(account.to_string(), old);
                }
            }
            return Ok(scripted);
        }
        if self.0.denied.borrow().contains(account) {
            return Ok(Adoption::Refused(-128));
        }
        let Some(old) = self.0.earlier(account) else { return Ok(Adoption::NoOldItem) };
        match self.0.current(account) {
            Some(value) if value != old => return Ok(Adoption::Conflict),
            Some(_) => {}
            None => {
                self.0.current.borrow_mut().insert(account.to_string(), old);
            }
        }
        self.0.earlier.borrow_mut().remove(account);
        Ok(Adoption::Moved)
    }
}

/// The move on `keychain`, its keychain unlocked, the journal not written down.
fn moved(keychain: &Keychain, journal: &mut Journal) -> StepState {
    move_with(&Bridge(keychain), &HelperV2(keychain), Ok(false), journal, &|_| Ok(()))
}

#[test]
fn migration_prefers_the_bridge_and_falls_back_per_account() {
    let keychain = Keychain::with(&[
        (VAULT_KEY, "vault key"),
        ("host:web-1", "hunter2"),
        ("host:web-2", "an old password"),
        ("sync:mnemonic", "twelve synthetic words"),
    ]);
    keychain.not_allowed.borrow_mut().extend(set(&["host:web-2", "sync:mnemonic"]));
    let mut journal = Journal::default();
    let state = moved(&keychain, &mut journal);

    // What helper v1 hands over moves through the bridge to helper v2, vault keys first, and its old copy goes through the bridge.
    assert_eq!(keychain.entries().first().map(String::as_str), Some(format!("bridge get {VAULT_KEY}").as_str()));
    for (account, value) in [(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")] {
        assert_eq!((keychain.current(account).as_deref(), keychain.earlier(account)), (Some(value), None), "{account}");
    }
    // The others stay where they are, untouched, and wait for the user's permission: helper v2's adopt moves them.
    let progress = &journal.credential_progress;
    assert_eq!(progress.needs_permission, set(&["host:web-2", "sync:mnemonic"]));
    for account in ["host:web-2", "sync:mnemonic"] {
        assert!(keychain.earlier(account).is_some() && keychain.current(account).is_none(), "{account}");
    }
    assert!(progress.vault_keys_moved, "nothing waits for the vault");
    assert!(matches!(state, StepState::Failed(_)), "they are left for a later attempt: {state:?}");
    // Nothing asked the user anything.
    assert!(!keychain.entries().iter().any(|entry| entry.contains("adopt")), "{:#?}", keychain.entries());
}

/// A vault key helper v1 may not hand over stops the attempt (the rest waits for the vault keys), and the vault waits for it. So
/// that the window asks once for everything, the attempt also asks helper v1 for the items it did not get to: what it may not reach
/// waits for permission with the vault key, what it may is left for the next attempt, and nothing else is written.
#[test]
fn a_vault_key_that_needs_permission_stops_the_move_and_everything_needing_it_is_counted_at_once() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    keychain.not_allowed.borrow_mut().extend(set(&[VAULT_KEY, "host:web-2"]));
    let mut journal = Journal::default();
    let state = moved(&keychain, &mut journal);
    assert!(matches!(&state, StepState::Failed(reason) if reason.contains("vault")), "{state:?}");
    let progress = &journal.credential_progress;
    assert!(!progress.vault_keys_moved);
    assert!(journal.credentials_wait(), "the vault waits for its key");
    assert_eq!(progress.needs_permission, set(&[VAULT_KEY, "host:web-2"]));
    assert!(keychain.current.borrow().is_empty(), "nothing moves before the vault keys");
    assert!(!keychain.entries().iter().any(|entry| entry.starts_with("helper-v2") || entry.starts_with("bridge delete")));
    assert_eq!(keychain.earlier("host:web-1").as_deref(), Some("hunter2"), "left for the next attempt");
}

/// Helper v1 may read an item but not delete it: the copy is under the new service, and the old item waits for permission (adopt
/// finishes over the identical copy).
#[test]
fn an_old_copy_helper_v1_may_not_delete_waits_for_permission() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")]);
    keychain.undeletable.borrow_mut().extend(set(&[VAULT_KEY, "host:web-1"]));
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    assert_eq!(keychain.current(VAULT_KEY).as_deref(), Some("vault key"));
    assert!(journal.credential_progress.vault_keys_moved, "the vault key is readable under the new service");
    assert_eq!(journal.credential_progress.needs_permission, set(&[VAULT_KEY, "host:web-1"]));
}

/// A failure that may pass is left for the next attempt, silently: it is no reason to ask the user.
#[test]
fn a_bridge_that_fails_for_now_asks_nobody_for_permission() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")]);
    keychain.unreachable.borrow_mut().insert("host:web-1".into());
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    assert!(journal.credential_progress.needs_permission.is_empty());
    assert_eq!(journal.credential_progress.retrying, 1);
}

#[test]
fn a_locked_keychain_waits_for_the_user_and_nothing_is_asked_of_any_helper() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key")]);
    let mut journal = Journal::default();
    let state = move_with(&Bridge(&keychain), &HelperV2(&keychain), Ok(true), &mut journal, &|_| Ok(()));
    assert_eq!(state, StepState::Failed(LOCKED.into()));
    assert!(journal.credential_progress.waiting_for_the_user);
    assert!(keychain.entries().is_empty());
}

/// What waits for permission is what the last attempt saw: an item it read says what it is now, one gone from the earlier service or
/// kept there for good waits no more, one it did not get to keeps waiting. Vault keys are always named, the rest only up to a size.
#[test]
fn what_waits_for_permission_is_what_the_last_attempt_saw() {
    let mut progress = CredentialProgress { needs_permission: set(&["host:a", "host:b", "host:c", "host:d"]), ..Default::default() };
    progress.kept.insert("host:d".into(), "another value is saved under the new name, and stays".into());
    let listed: Vec<String> = ["host:a", "host:b", "host:d", "host:e"].map(String::from).to_vec();
    // host:a was read and needs no permission any more, host:b was not read, host:c is gone, host:e is new.
    waiting_for_permission(&mut progress, &listed, &set(&["host:a", "host:e"]), set(&["host:e"]));
    assert_eq!((progress.needs_permission.clone(), progress.needs_permission_unnamed), (set(&["host:b", "host:e"]), 0));

    let long: Vec<String> = (0..2_000).map(|index| format!("host:{index:0>20}")).collect();
    let mut progress = CredentialProgress::default();
    let mut refused: BTreeSet<String> = long.iter().cloned().collect();
    refused.insert(VAULT_KEY.into());
    let mut listed = long.clone();
    listed.push(VAULT_KEY.into());
    waiting_for_permission(&mut progress, &listed, &refused.clone(), refused);
    assert!(progress.needs_permission.contains(VAULT_KEY));
    let named: usize = progress.needs_permission.iter().map(String::len).sum();
    assert!(named <= MAX_PERMISSION_NAMES, "{named}");
    assert_eq!(progress.needs_permission.len() + progress.needs_permission_unnamed, 2_001);
    assert!(progress.needs_permission_unnamed > 0);
}

/// What the user put off (Later) is remembered while something waits for permission, and forgotten once nothing does: an item that
/// waits for it later on is asked for at start again.
#[test]
fn what_the_user_put_off_is_forgotten_once_nothing_waits() {
    let mut progress = CredentialProgress { needs_permission: set(&["host:a", "host:b"]), permission_put_off: 2, ..Default::default() };
    let listed: Vec<String> = ["host:a", "host:b"].map(String::from).to_vec();
    waiting_for_permission(&mut progress, &listed, &set(&["host:a"]), BTreeSet::new());
    assert_eq!((progress.needs_permission.clone(), progress.permission_put_off), (set(&["host:b"]), 2));
    waiting_for_permission(&mut progress, &listed, &set(&["host:b"]), BTreeSet::new());
    assert_eq!((progress.needs_permission.len(), progress.permission_put_off), (0, 0));
}

/// The earlier service as the core sees it through the bridge: what needs permission is remembered, whatever else it does.
#[test]
fn the_core_sees_helper_v1_as_the_earlier_service() {
    let keychain = Keychain::with(&[("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    keychain.not_allowed.borrow_mut().insert("host:web-2".into());
    let bridge = Bridge(&keychain);
    let watched = Watched::new(&bridge);
    assert_eq!(watched.accounts().unwrap(), ["host:web-1", "host:web-2"]);
    assert_eq!(watched.read("host:web-1").unwrap().as_deref().map(String::as_str), Some("hunter2"));
    assert!(watched.read("host:web-2").is_err());
    assert!(watched.delete("host:web-2").is_err());
    assert_eq!(*watched.refused.borrow(), set(&["host:web-2"]));
    assert_eq!(*watched.read.borrow(), set(&["host:web-1", "host:web-2"]));
}

/// The folders the migration retires once nothing is left to move are those of helper v1 and the bridge, never helper v2's.
#[test]
fn the_retired_folders_are_those_of_helper_v1_and_the_bridge() {
    use crate::secrets::macos_helper::{bridge, helper_v1, helper_v2};
    let folder = |path: &str| path.strip_prefix("credential-helper/").and_then(|rest| rest.split_once('/')).map(|(folder, _)| folder.to_string());
    let retired: Vec<String> = super::super::data_root::MIGRATION_PROGRAMS.iter().map(|folder| folder.to_string()).collect();
    assert_eq!(retired, [folder(helper_v1().path()).unwrap(), folder(bridge().path()).unwrap()]);
    assert!(!retired.contains(&folder(helper_v2().path()).unwrap()));
}

/// The window counts what stays from sets that do not overlap: what waits for permission (asked for on its own), and what a later
/// attempt tries again, the items an attempt a vault key stopped did not get to among them.
#[test]
fn what_stays_and_what_waits_for_permission_are_counted_apart() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    keychain.not_allowed.borrow_mut().extend(set(&[VAULT_KEY, "host:web-2"]));
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    let progress = &journal.credential_progress;
    assert_eq!((progress.needs_permission.len(), progress.retrying), (2, 1), "host:web-1 was not reached: a later attempt moves it");

    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-2", "an old password"), ("host:web-3", "hunter3")]);
    keychain.not_allowed.borrow_mut().insert("host:web-2".into());
    keychain.unreachable.borrow_mut().insert("host:web-3".into());
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    let progress = &journal.credential_progress;
    assert_eq!((progress.needs_permission.len(), progress.retrying), (1, 1));
}

/// An item already known to need permission is not asked of helper v1 again by an attempt a vault key stopped: each would cost a
/// bridge and a helper v1 before the window opens, on every start and every Retry.
#[test]
fn an_attempt_a_vault_key_stopped_asks_only_about_what_is_not_known_to_need_permission() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    keychain.not_allowed.borrow_mut().extend(set(&[VAULT_KEY, "host:web-2"]));
    let mut journal = Journal::default();
    journal.credential_progress.needs_permission = set(&[VAULT_KEY, "host:web-2"]);
    moved(&keychain, &mut journal);
    let entries = keychain.entries();
    assert!(!entries.contains(&"bridge get host:web-2".to_string()), "{entries:#?}");
    assert!(entries.contains(&"bridge get host:web-1".to_string()), "{entries:#?}");
    assert_eq!(journal.credential_progress.needs_permission, set(&[VAULT_KEY, "host:web-2"]), "it still waits");
}

/// An item helper v1 handed over when an attempt that a vault key stopped asked about it is not asked about again while that vault key
/// waits for the user: each request would cost a bridge and a helper v1, its secret pulled in and dropped, before the window opens on
/// every start. It is left for the attempt that reaches it, which moves it once the vault key has moved.
#[test]
fn an_item_helper_v1_handed_over_is_not_asked_about_again_while_the_vault_key_waits() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    keychain.not_allowed.borrow_mut().extend(set(&[VAULT_KEY, "host:web-2"]));
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    assert!(keychain.entries().contains(&"bridge get host:web-1".to_string()), "{:#?}", keychain.entries());
    let progress = &journal.credential_progress;
    assert_eq!((progress.probed_readable.clone(), progress.needs_permission.clone()), (set(&["host:web-1"]), set(&[VAULT_KEY, "host:web-2"])));
    assert_eq!(progress.retrying, 1, "left for the attempt that reaches it");

    // The next start: the vault key still waits, and is all that is asked about.
    keychain.log.borrow_mut().clear();
    moved(&keychain, &mut journal);
    assert_eq!(keychain.entries(), [format!("bridge get {VAULT_KEY}")]);
    let progress = &journal.credential_progress;
    assert_eq!((progress.probed_readable.clone(), progress.needs_permission.clone()), (set(&["host:web-1"]), set(&[VAULT_KEY, "host:web-2"])));
    assert_eq!(progress.retrying, 1);

    // Once the vault key can move, the attempt reaches the item, moves it, and forgets it.
    keychain.not_allowed.borrow_mut().remove(VAULT_KEY);
    moved(&keychain, &mut journal);
    assert_eq!(keychain.current("host:web-1").as_deref(), Some("hunter2"));
    assert!(journal.credential_progress.probed_readable.is_empty());
    assert_eq!(journal.credential_progress.needs_permission, set(&["host:web-2"]));
}

/// What is remembered as handed over shares the room of the names that wait for permission, and goes once it waits for permission, is
/// gone, or was read.
#[test]
fn what_helper_v1_handed_over_is_remembered_within_the_room_of_the_names() {
    let mut progress = CredentialProgress { needs_permission: set(&["host:a"]), ..Default::default() };
    progress.probed_readable = set(&["host:b", "host:c", "host:d"]);
    // host:b is still not reached, host:c was read, host:d waits for permission now, host:e was handed over by this attempt.
    let unreached = set(&["host:b", "host:d", "host:e", "host:f"]);
    remember_readable(&mut progress, &unreached, set(&["host:e"]), &set(&["host:a", "host:d"]));
    assert_eq!(progress.probed_readable, set(&["host:b", "host:e"]));

    let long: BTreeSet<String> = (0..2_000).map(|index| format!("host:{index:0>20}")).collect();
    let mut progress = CredentialProgress { needs_permission: long.iter().take(500).cloned().collect(), ..Default::default() };
    let handed: BTreeSet<String> = long.iter().skip(500).cloned().collect();
    let waiting = progress.needs_permission.clone();
    remember_readable(&mut progress, &long, handed, &waiting);
    let named: usize = progress.needs_permission.iter().chain(&progress.probed_readable).map(String::len).sum();
    assert!(named <= MAX_PERMISSION_NAMES && !progress.probed_readable.is_empty(), "{named}");
}

/// A bridge that never gets an answer from helper v1, in a way that may pass, would keep a vault key waiting forever behind a Retry
/// that cannot help. From the third attempt in a row that got no answer at all, what is left waits for the user's permission instead
/// (helper v2's adopt goes around the bridge); one answer before that starts the count again.
#[test]
fn a_bridge_that_keeps_failing_sends_what_is_left_to_the_permission_sheet() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")]);
    keychain.unreachable.borrow_mut().extend(set(&[VAULT_KEY, "host:web-1"]));
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    moved(&keychain, &mut journal);
    assert_eq!(journal.credential_progress.chain_failures, 2);
    keychain.unreachable.borrow_mut().remove(VAULT_KEY);
    moved(&keychain, &mut journal);
    assert_eq!(journal.credential_progress.chain_failures, 0, "an answer starts the count again");
    assert!(journal.credential_progress.needs_permission.is_empty());

    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    keychain.unreachable.borrow_mut().extend(set(&[VAULT_KEY, "host:web-1", "host:web-2"]));
    keychain.current.borrow_mut().insert("host:web-3".into(), "kept".into());
    let mut journal = Journal::default();
    journal.credential_progress.kept.insert("host:web-2".into(), "another value is saved under the new name, and stays".into());
    for attempt in 1..CHAIN_FAILURES_BEFORE_ADOPT {
        moved(&keychain, &mut journal);
        let progress = &journal.credential_progress;
        assert_eq!(progress.chain_failures, attempt);
        assert!(progress.needs_permission.is_empty(), "attempt {attempt}: it may still pass");
    }
    moved(&keychain, &mut journal);
    assert_eq!(journal.credential_progress.chain_failures, CHAIN_FAILURES_BEFORE_ADOPT);
    assert_eq!(journal.credential_progress.needs_permission, set(&[VAULT_KEY, "host:web-1"]), "what is left, the kept item aside");
    assert_eq!(journal.credential_progress.retrying, 0);
}

/// The journal says whether only the user's permission holds the vault back, which decides whether the window offers Retry: not for a
/// vault key helper v1 may not hand over, but for one that failed in a way that may pass, whatever else waits for permission. A locked
/// keychain leaves what the last attempt found as it was (the window offers Retry for the lock).
#[test]
fn the_journal_says_whether_only_the_users_permission_holds_the_vault_back() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-2", "an old password")]);
    keychain.not_allowed.borrow_mut().extend(set(&[VAULT_KEY, "host:web-2"]));
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    assert!(journal.credential_progress.vault_waits_for_permission);
    let state = move_with(&Bridge(&keychain), &HelperV2(&keychain), Ok(true), &mut journal, &|_| Ok(()));
    assert_eq!(state, StepState::Failed(LOCKED.into()));
    assert!(journal.credential_progress.vault_waits_for_permission && journal.credential_progress.waiting_for_the_user);

    // The vault key failed in a way that may pass, while an item an earlier attempt found waits for permission.
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-2", "an old password")]);
    keychain.unreachable.borrow_mut().insert(VAULT_KEY.into());
    keychain.not_allowed.borrow_mut().insert("host:web-2".into());
    let mut journal = Journal::default();
    journal.credential_progress.needs_permission = set(&["host:web-2"]);
    moved(&keychain, &mut journal);
    assert!(!journal.credential_progress.vault_waits_for_permission, "a retry may move the vault key");
    assert_eq!(journal.credential_progress.needs_permission, set(&["host:web-2"]));
}

/// Once the bridge has got no answer three attempts in a row, a start does not ask it at all (a hanging bridge would delay every start
/// before the window): what is left waits for the user's permission straight away, read from the keychain's attributes alone.
#[test]
fn after_the_bridge_kept_failing_a_start_does_not_ask_it_again() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    let mut journal = Journal::default();
    journal.credential_progress.chain_failures = CHAIN_FAILURES_BEFORE_ADOPT;
    journal.credential_progress.chain_failures_bridge = "bridge-1".into();
    journal.credential_progress.kept.insert("host:web-2".into(), "another value is saved under the new name, and stays".into());
    let state = moved(&keychain, &mut journal);
    assert!(keychain.entries().is_empty(), "nothing was asked of the bridge or of helper v2: {:#?}", keychain.entries());
    let progress = &journal.credential_progress;
    assert_eq!(progress.needs_permission, set(&[VAULT_KEY, "host:web-1"]));
    assert!(progress.vault_waits_for_permission && !progress.vault_keys_moved);
    assert_eq!((progress.retrying, progress.chain_failures), (0, CHAIN_FAILURES_BEFORE_ADOPT));
    assert!(matches!(&state, StepState::Failed(reason) if reason.contains("vault") && reason.contains("permission")), "{state:?}");
    assert!(journal.credentials_wait(), "the vault waits for its key");
    // Nothing is left: the step is done.
    keychain.earlier.borrow_mut().clear();
    assert_eq!(moved(&keychain, &mut journal), StepState::Done);
    assert!(journal.credential_progress.needs_permission.is_empty());
}

/// The requests that reached the stand-in bridge about an item it does not answer for.
fn unanswered_requests(keychain: &Keychain) -> Vec<String> {
    let unreachable = keychain.unreachable.borrow();
    keychain.entries().into_iter().filter(|entry| entry.starts_with("bridge ") && unreachable.iter().any(|account| entry.ends_with(&format!(" {account}")))).collect()
}

/// A bridge that does not answer costs one wait per attempt at most: after the first request that got no answer, the attempt asks the
/// bridge nothing more, not even to probe what it did not reach. What it did not ask stays as if not reached: left for a later attempt,
/// and still waiting for permission if an earlier attempt found it so. The attempt counts once.
#[test]
fn a_hanging_bridge_costs_at_most_one_wait_per_attempt() {
    // The vault key moves; then the bridge stops answering.
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:a", "a"), ("host:b", "b"), ("host:c", "c")]);
    keychain.unreachable.borrow_mut().extend(set(&["host:a", "host:b", "host:c"]));
    let mut journal = Journal::default();
    journal.credential_progress.needs_permission = set(&["host:c"]);
    moved(&keychain, &mut journal);
    assert_eq!(unanswered_requests(&keychain), ["bridge get host:a"]);
    assert_eq!(keychain.current(VAULT_KEY).as_deref(), Some("vault key"));
    let progress = &journal.credential_progress;
    assert_eq!(progress.needs_permission, set(&["host:c"]), "what was not asked keeps what an earlier attempt found");
    assert_eq!(progress.retrying, 2, "host:a and host:b are left for a later attempt");
    assert_eq!(progress.chain_failures, 0, "the vault key's answer starts the count again");

    // Nothing answers: one request, and the attempt counts once.
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("vault:key", "the first vault key"), ("host:a", "a")]);
    keychain.unreachable.borrow_mut().extend(set(&[VAULT_KEY, "vault:key", "host:a"]));
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    assert_eq!(unanswered_requests(&keychain).len(), 1, "{:#?}", keychain.entries());
    assert_eq!(journal.credential_progress.chain_failures, 1);

    // A vault key that needs permission stopped the attempt, and the probe of what it did not reach stops at the first request that
    // gets no answer.
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:a", "a"), ("host:b", "b")]);
    keychain.not_allowed.borrow_mut().insert(VAULT_KEY.into());
    keychain.unreachable.borrow_mut().extend(set(&["host:a", "host:b"]));
    let mut journal = Journal::default();
    moved(&keychain, &mut journal);
    assert_eq!(unanswered_requests(&keychain), ["bridge get host:a"]);
    assert_eq!(journal.credential_progress.needs_permission, set(&[VAULT_KEY]));
}

/// The count of attempts without an answer belongs to the bridge they were made with: a later version that embeds another bridge
/// starts the count again, and so asks the bridge again at start.
#[test]
fn another_embedded_bridge_starts_the_count_again() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key")]);
    keychain.unreachable.borrow_mut().insert(VAULT_KEY.into());
    let mut journal = Journal::default();
    for _ in 0..CHAIN_FAILURES_BEFORE_ADOPT {
        moved(&keychain, &mut journal);
    }
    assert_eq!(journal.credential_progress.chain_failures, CHAIN_FAILURES_BEFORE_ADOPT);
    assert_eq!(journal.credential_progress.chain_failures_bridge, "bridge-1");
    keychain.log.borrow_mut().clear();
    moved(&keychain, &mut journal);
    assert!(keychain.entries().is_empty(), "the same bridge is not asked again");

    // An update ships another bridge, which answers.
    *keychain.bridge.borrow_mut() = "bridge-2".into();
    keychain.unreachable.borrow_mut().clear();
    moved(&keychain, &mut journal);
    assert_eq!(keychain.current(VAULT_KEY).as_deref(), Some("vault key"), "the new bridge was asked");
    assert_eq!(journal.credential_progress.chain_failures, 0);
}
