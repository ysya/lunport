//! The adopt fallback with the keychain in memory (`credentials_helper_tests.rs` has the stand-ins), on its own and in the migration's
//! runs. No test reaches a real keychain or helper.

use std::cell::RefCell;
use std::fs;
use std::rc::Rc;
use std::time::Duration;

use super::super::commands::{not_run, restarts_after, MigrationStatus};
use super::super::credentials::{record_in, with_test_mover};
use super::super::credentials_helper::move_with;
use super::super::credentials_helper::tests::{set, Bridge, HelperV2, Keychain, VAULT_KEY};
use super::super::journal::{self, Journal, StepState};
use super::super::{run, Entry, Move, Outcome, Report, Roots, Step, Waits};
use super::*;

const QUICK: Waits = Waits { old_locks: Duration::from_millis(150), migration_lock: Duration::from_millis(150) };

/// The adopt requests `keychain` saw, in order.
fn adopts(keychain: &Keychain) -> Vec<String> {
    keychain.entries().into_iter().filter(|entry| entry.contains(" adopt ")).collect()
}

/// The adopt run on `keychain` for a journal in which `waiting` wait for the user's permission.
fn adopt_waiting(keychain: &Keychain, waiting: &[&str], use_old_data: bool) -> (Adopted, Journal) {
    let mut journal = Journal::default();
    journal.use_old_data = use_old_data;
    journal.credential_progress.needs_permission = set(waiting);
    let adopted = adopt_with(&HelperV2(keychain), &HelperV2(keychain), &mut journal, &|_| Ok(()));
    (adopted, journal)
}

#[test]
fn adopt_moves_what_the_user_allows_and_keeps_asking_for_what_they_deny() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]);
    keychain.denied.borrow_mut().insert("host:web-2".into());
    let (adopted, journal) = adopt_waiting(&keychain, &["host:web-1", "host:web-2", VAULT_KEY], false);
    // Vault keys first; macOS asks once for each.
    assert_eq!(
        adopts(&keychain),
        [format!("helper-v2 adopt {VAULT_KEY}"), "helper-v2 adopt host:web-1".into(), "helper-v2 adopt host:web-2".into()]
    );
    assert_eq!(adopted.moved, [VAULT_KEY, "host:web-1"]);
    assert_eq!(adopted.denied, ["host:web-2"]);
    assert_eq!((keychain.current("host:web-1").as_deref(), keychain.earlier("host:web-1")), (Some("hunter2"), None));
    // A denial keeps the old item as it was, and the item waits for the next time Lunport asks.
    assert_eq!((keychain.earlier("host:web-2").as_deref(), keychain.current("host:web-2")), (Some("an old password"), None));
    assert_eq!(journal.credential_progress.needs_permission, set(&["host:web-2"]));
    assert_eq!(adopted.stopped, None);
    // The vault key moved: a process that started without it restarts once it hears of it.
    assert_eq!(journal.credential_progress.start_credential_moves, 1);
}

/// errSecVerifyFailed: the copy did not read back, or vanished. The item keeps waiting, the old one untouched; the next adopt
/// finishes the move over an identical copy.
#[test]
fn an_unverified_copy_keeps_the_item_waiting_and_the_next_adopt_finishes_over_it() {
    let keychain = Keychain::with(&[("host:web-1", "hunter2")]);
    keychain.scripted.borrow_mut().insert("host:web-1".into(), Adoption::NotVerified);
    let (adopted, mut journal) = adopt_waiting(&keychain, &["host:web-1"], false);
    assert_eq!(adopted.failed.len(), 1);
    assert!(adopted.failed[0].1.contains("did not read back"), "{:?}", adopted.failed);
    assert_eq!(journal.credential_progress.needs_permission, set(&["host:web-1"]));
    assert_eq!(keychain.earlier("host:web-1").as_deref(), Some("hunter2"));
    let adopted = adopt_with(&HelperV2(&keychain), &HelperV2(&keychain), &mut journal, &|_| Ok(()));
    assert_eq!(adopted.moved, ["host:web-1"]);
    assert_eq!((keychain.current("host:web-1").as_deref(), keychain.earlier("host:web-1")), (Some("hunter2"), None));
    assert!(journal.credential_progress.needs_permission.is_empty());
}

/// errSecParam: this build names one service for both sides. Nothing is touched, nothing more is asked, and the run says why.
#[test]
fn a_misconfigured_build_stops_the_run_and_touches_nothing() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2")]);
    keychain.scripted.borrow_mut().insert(VAULT_KEY.into(), Adoption::Misconfigured);
    let (adopted, journal) = adopt_waiting(&keychain, &[VAULT_KEY, "host:web-1"], false);
    assert!(adopted.stopped.as_deref().is_some_and(|why| why.contains("one credential service for both sides")), "{adopted:?}");
    assert_eq!(adopts(&keychain), [format!("helper-v2 adopt {VAULT_KEY}")], "nothing more was asked");
    assert!(adopted.moved.is_empty() && keychain.current.borrow().is_empty());
    assert_eq!(journal.credential_progress.needs_permission, set(&[VAULT_KEY, "host:web-1"]));
}

/// An item too large for a helper stays for good; one already gone from the earlier service waits no more.
#[test]
fn an_item_too_large_stays_for_good_and_one_already_gone_waits_no_more() {
    let keychain = Keychain::with(&[("host:web-1", "hunter2")]);
    keychain.scripted.borrow_mut().insert("host:web-1".into(), Adoption::TooLarge);
    let (adopted, journal) = adopt_waiting(&keychain, &["host:web-1", "host:gone"], false);
    assert_eq!(adopted.kept, [("host:web-1".to_string(), "it holds more than 1 MiB".to_string())]);
    let progress = &journal.credential_progress;
    assert!(progress.needs_permission.is_empty());
    assert!(progress.kept.contains_key("host:web-1"), "no later attempt asks helper v1 for it again");
}

/// A conflict keeps the value saved under the new name, as the core does, unless the old value wins: for a vault key, and for every
/// item once the user chose the old data. Then the current value is set aside, read back and recorded before it makes way.
#[test]
fn a_conflict_keeps_the_current_value_unless_the_old_value_wins() {
    let keychain = Keychain::with(&[("host:web-1", "an old password")]);
    keychain.current.borrow_mut().insert("host:web-1".into(), "a newer password".into());
    let (adopted, journal) = adopt_waiting(&keychain, &["host:web-1"], false);
    assert_eq!(adopted.kept, [("host:web-1".to_string(), SETTLED.to_string())]);
    assert_eq!(keychain.current("host:web-1").as_deref(), Some("a newer password"));
    assert_eq!(keychain.earlier("host:web-1").as_deref(), Some("an old password"), "the old item is left as it is");
    assert!(journal.credential_progress.kept.contains_key("host:web-1"));

    for (account, use_old_data) in [(VAULT_KEY, false), ("host:web-1", true)] {
        let keychain = Keychain::with(&[(account, "the earlier value")]);
        keychain.current.borrow_mut().insert(account.into(), "another value".into());
        let mut journal = Journal::default();
        journal.use_old_data = use_old_data;
        journal.credential_progress.needs_permission = set(&[account]);
        // The journal is written down with the set-aside name before the value it keeps makes way.
        let recorded = Rc::new(RefCell::new(Vec::new()));
        let record = {
            let (recorded, keychain_log) = (Rc::clone(&recorded), Rc::clone(&keychain.log));
            move |journal: &Journal| -> Result<(), AppError> {
                recorded.borrow_mut().push((journal.notes.clone(), keychain_log.borrow().len()));
                Ok(())
            }
        };
        let adopted = adopt_with(&HelperV2(&keychain), &HelperV2(&keychain), &mut journal, &record);
        assert_eq!(adopted.moved, [account], "{account}");
        let aside = format!("set-aside:{account}");
        assert_eq!(keychain.current(&aside).as_deref(), Some("another value"), "{account}");
        assert_eq!((keychain.current(account).as_deref(), keychain.earlier(account)), (Some("the earlier value"), None));
        assert!(journal.notes.iter().any(|note| note.contains(&aside)), "{:?}", journal.notes);
        let entries = keychain.entries();
        let deleted = entries.iter().position(|entry| *entry == format!("helper-v2 delete {account}")).expect("it made way");
        let recorded = recorded.borrow();
        assert!(recorded.iter().any(|(notes, at)| notes.iter().any(|note| note.contains(&aside)) && *at <= deleted), "{entries:#?}");
    }
}

/// A journal whose steps in `done` are done.
fn journal_with(done: &[Step]) -> Journal {
    let mut journal = Journal::default();
    for &step in done {
        journal.set(step, StepState::Done);
    }
    journal
}

/// A computer whose data root has moved to the new name, the migration having got as far as `journal` says.
fn computer(journal: &Journal) -> (tempfile::TempDir, Roots) {
    let temp = tempfile::tempdir().unwrap();
    let roots = Roots { data: Move::named(temp.path(), "acme-earlier", "acme-current"), backups: None, webkit: None, preferences: None };
    fs::create_dir_all(&roots.data.new).unwrap();
    journal::write(&roots.data.new, journal).unwrap();
    (temp, roots)
}

/// The credential step on `keychain`, as macOS Production runs it, recording the journal.
fn mover(keychain: &Rc<Keychain>) -> impl Fn(&Roots, &mut Journal) -> StepState + Clone + 'static {
    let keychain = Rc::clone(keychain);
    move |roots: &Roots, journal: &mut Journal| move_with(&Bridge(&keychain), &HelperV2(&keychain), Ok(false), journal, &record_in(roots))
}

fn read_journal(roots: &Roots) -> Journal {
    journal::read(&roots.data.new).unwrap().unwrap()
}

/// A vault key helper v1 may not hand over keeps the vault waiting, start after start, until the user lets helper v2 adopt it; the
/// window counts what waits for permission apart from the rest, and the adopt run moves everything, the rest through the bridge.
#[test]
fn a_refused_vault_key_blocks_until_adopted() {
    let (_temp, roots) = computer(&journal_with(&Step::FOLDERS));
    let keychain = Rc::new(Keychain::with(&[(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")]));
    keychain.not_allowed.borrow_mut().extend(set(&[VAULT_KEY, "host:web-2"]));
    for _ in 0..2 {
        let report = with_test_mover(mover(&keychain), || run(Entry::Desktop, &roots, &QUICK));
        assert_eq!(report.outcome, Outcome::CredentialsPending);
        let status = MigrationStatus::of(Some(&report));
        assert_eq!((status.failed_step, status.credentials_need_permission), (Some(Step::Credentials), 2));
        assert!(keychain.current.borrow().is_empty());
    }
    assert!(!keychain.entries().iter().any(|entry| entry.contains("adopt")), "nothing asked the user before the window did");

    let before = with_test_mover(mover(&keychain), || run(Entry::Desktop, &roots, &QUICK));
    let (report, stopped) = with_test_mover(mover(&keychain), || adopt_credentials_with(&roots, &QUICK, &HelperV2(&keychain), &HelperV2(&keychain)));
    assert_eq!((report.outcome.clone(), stopped), (Outcome::Completed, None));
    for (account, value) in [(VAULT_KEY, "vault key"), ("host:web-1", "hunter2"), ("host:web-2", "an old password")] {
        assert_eq!((keychain.current(account).as_deref(), keychain.earlier(account)), (Some(value), None), "{account}");
    }
    let entries = keychain.entries();
    assert!(entries.contains(&format!("helper-v2 adopt {VAULT_KEY}")) && entries.contains(&"helper-v2 adopt host:web-2".to_string()));
    assert!(!entries.contains(&"helper-v2 adopt host:web-1".to_string()), "helper v1 handed it over: {entries:#?}");
    assert!(read_journal(&roots).is_done(Step::Credentials));
    assert_eq!(MigrationStatus::of(Some(&report)).credentials_need_permission, 0);
    // The vault no longer waits: the app restarts, with the vault's key.
    assert!(restarts_after(&before, &report));
}

/// An adopt run that moves the sync code (or a vault key), which the app reads only when it starts, restarts the app; one that moves
/// only a password, which the app reads when it uses it, leaves its sessions alone.
#[test]
fn an_adopt_run_restarts_only_when_it_moved_what_the_app_reads_at_start() {
    let after_adopting = |items: &[(&str, &str)], waiting: &[&str]| {
        let mut journal = journal_with(&Step::FOLDERS);
        journal.credential_progress.vault_keys_moved = true;
        let (_temp, roots) = computer(&journal);
        let keychain = Rc::new(Keychain::with(items));
        keychain.not_allowed.borrow_mut().extend(set(waiting));
        let before = with_test_mover(mover(&keychain), || run(Entry::Desktop, &roots, &QUICK));
        assert_eq!((before.outcome.clone(), MigrationStatus::of(Some(&before)).credentials_need_permission), (Outcome::Completed, 1));
        let (after, _) =
            with_test_mover(mover(&keychain), || adopt_credentials_with(&roots, &QUICK, &HelperV2(&keychain), &HelperV2(&keychain)));
        (before, after)
    };
    let (before, after) = after_adopting(&[("sync:mnemonic", "twelve synthetic words")], &["sync:mnemonic"]);
    assert!(after.restart_helps && restarts_after(&before, &after));
    let (before, after) = after_adopting(&[("host:web-1", "hunter2")], &["host:web-1"]);
    assert_eq!(after.outcome, Outcome::Completed);
    assert!(!after.restart_helps && !restarts_after(&before, &after));
}

/// The window counts what waits for permission apart from what is left for other reasons: only the latter is mentioned as staying.
#[test]
fn the_window_counts_what_waits_for_permission_apart() {
    let mut journal = journal_with(&Step::FOLDERS);
    journal.set(Step::Credentials, StepState::Failed("3 saved credentials did not move yet".into()));
    journal.credential_progress.vault_keys_moved = true;
    // One item is left for a later attempt for another reason; two wait for permission (`retrying` leaves those out).
    journal.credential_progress.retrying = 1;
    journal.credential_progress.needs_permission = set(&["host:web-1", "host:web-2"]);
    let report = Report {
        outcome: journal.outcome(&Step::FOLDERS),
        detail: None,
        credentials: super::super::credentials::left_behind(&journal, true, false),
        restart_helps: false,
        credential_moves: 0,
    };
    let status = MigrationStatus::of(Some(&report));
    assert_eq!((status.failed_step, status.credentials_left, status.credentials_need_permission), (None, 1, 2));
}

/// A helper v2 that cannot be reached stops the run, whether its first adopt of an item fails or the second one, after a conflict made
/// way: nothing more is asked, and what was not moved keeps waiting.
#[test]
fn a_helper_that_cannot_be_reached_stops_the_run_however_far_it_got() {
    for (call, conflict) in [(1, false), (2, true)] {
        let keychain = Keychain::with(&[(VAULT_KEY, "the earlier value"), ("host:web-1", "hunter2")]);
        if conflict {
            keychain.current.borrow_mut().insert(VAULT_KEY.into(), "another value".into());
        }
        keychain.unreachable_adopt.borrow_mut().insert(VAULT_KEY.into(), call);
        let (adopted, journal) = adopt_waiting(&keychain, &[VAULT_KEY, "host:web-1"], false);
        assert!(adopted.stopped.as_deref().is_some_and(|why| why.contains("helper stopped")), "call {call}: {adopted:?}");
        assert!(adopted.failed.is_empty() && adopted.moved.is_empty(), "call {call}: {adopted:?}");
        assert!(!keychain.entries().contains(&"helper-v2 adopt host:web-1".to_string()), "call {call}: nothing more was asked");
        assert_eq!(journal.credential_progress.needs_permission, set(&[VAULT_KEY, "host:web-1"]), "call {call}");
    }
}

/// An item whose copy was usable under the new name already (helper v1 could read it but not delete its old copy) only loses its old
/// copy to adopt: the running app had it, so nothing restarts for it.
#[test]
fn an_item_already_usable_under_the_new_name_restarts_nothing() {
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key"), ("sync:mnemonic", "twelve synthetic words")]);
    keychain.current.borrow_mut().insert(VAULT_KEY.into(), "vault key".into());
    keychain.current.borrow_mut().insert("sync:mnemonic".into(), "twelve synthetic words".into());
    let (adopted, journal) = adopt_waiting(&keychain, &[VAULT_KEY, "sync:mnemonic"], false);
    assert_eq!(adopted.moved, [VAULT_KEY, "sync:mnemonic"]);
    assert!(adopted.made_usable.is_empty(), "{adopted:?}");
    assert_eq!(journal.credential_progress.start_credential_moves, 0);

    let mut journal = journal_with(&Step::FOLDERS);
    journal.credential_progress.vault_keys_moved = true;
    let (_temp, roots) = computer(&journal);
    let keychain = Rc::new(Keychain::with(&[("sync:mnemonic", "twelve synthetic words")]));
    keychain.current.borrow_mut().insert("sync:mnemonic".into(), "twelve synthetic words".into());
    keychain.undeletable.borrow_mut().insert("sync:mnemonic".into());
    let before = with_test_mover(mover(&keychain), || run(Entry::Desktop, &roots, &QUICK));
    assert_eq!(MigrationStatus::of(Some(&before)).credentials_need_permission, 1);
    let (after, _) = with_test_mover(mover(&keychain), || adopt_credentials_with(&roots, &QUICK, &HelperV2(&keychain), &HelperV2(&keychain)));
    assert_eq!(keychain.earlier("sync:mnemonic"), None, "the old copy went");
    assert_eq!(after.outcome, Outcome::Completed);
    assert!(!after.restart_helps && !restarts_after(&before, &after));
}

/// A journal this version cannot read in full (a later version's, say) is salvaged first, and the adopt still runs on what it says;
/// one that cannot be read at all stops the run before anything is asked, saying why.
#[test]
fn a_journal_that_cannot_be_read_in_full_is_salvaged_and_one_that_cannot_be_read_stops_the_run() {
    let (_temp, roots) = computer(&journal_with(&Step::FOLDERS));
    let mut written: serde_json::Value = serde_json::to_value(read_journal(&roots)).unwrap();
    written["credential_progress"] = serde_json::json!({ "needs_permission": [VAULT_KEY] });
    written["login_item"] = serde_json::json!("a state from a later version");
    fs::write(journal::path(&roots.data.new), serde_json::to_vec(&written).unwrap()).unwrap();
    assert!(journal::read(&roots.data.new).is_err(), "this version cannot read it in full");
    let keychain = Rc::new(Keychain::with(&[(VAULT_KEY, "vault key")]));
    keychain.not_allowed.borrow_mut().insert(VAULT_KEY.into());
    let (report, stopped) =
        with_test_mover(mover(&keychain), || adopt_credentials_with(&roots, &QUICK, &HelperV2(&keychain), &HelperV2(&keychain)));
    assert_eq!((report.outcome, stopped), (Outcome::Completed, None));
    assert_eq!(keychain.current(VAULT_KEY).as_deref(), Some("vault key"), "adopted");
    assert!(read_journal(&roots).notes.iter().any(|note| note.contains("could not be read")), "the salvage left its note");

    let (_temp, roots) = computer(&journal_with(&Step::FOLDERS));
    fs::remove_file(journal::path(&roots.data.new)).unwrap();
    fs::create_dir(journal::path(&roots.data.new)).unwrap();
    let keychain = Keychain::with(&[(VAULT_KEY, "vault key")]);
    let (report, _) = with_test_mover(|_, _| panic!("nothing runs"), || adopt_credentials_with(&roots, &QUICK, &HelperV2(&keychain), &HelperV2(&keychain)));
    assert!(matches!(&report.outcome, Outcome::Deferred(super::super::DeferReason::StepFailed { error, .. }) if error.contains("cannot be read")), "{report:?}");
    assert!(keychain.entries().is_empty(), "nothing was asked");
}

/// A run from the window that found the migration blocked says why, in its own words for each reason: another process holds what the
/// move needs, or a step failed (the record of the move cannot be read, say).
#[test]
fn a_run_from_the_window_that_could_not_go_ahead_says_why() {
    let waiting = Report { detail: Some("another Lunport is moving the data folders right now".into()), ..Report::of(Outcome::Deferred(super::super::DeferReason::OldInstanceRunning)) };
    let message = not_run(&waiting).to_string();
    assert!(message.contains("another Lunport is moving the data folders right now") && message.contains("Try again in a moment"), "{message}");
    let failed = Report::of(Outcome::Deferred(super::super::DeferReason::StepFailed {
        step: Step::DataRoot,
        error: "the migration journal cannot be read: Permission denied".into(),
    }));
    let message = not_run(&failed).to_string();
    assert!(message.contains("the migration journal cannot be read: Permission denied"), "{message}");
    assert!(message.contains("No saved item was lost"), "{message}");
    assert!(!message.contains("Another Lunport") && !message.contains("Nothing was deleted"), "{message}");
}

/// An adopt run that moved items before the run failed (the record of the move could not be written) says so truthfully: items that
/// moved had their earlier copies deleted, each only after its new copy read back, so nothing was lost; it does not claim that nothing
/// was deleted.
#[test]
fn a_failure_after_the_adopt_moved_items_does_not_claim_nothing_was_deleted() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, roots) = computer(&journal_with(&Step::FOLDERS));
    let mut journal = read_journal(&roots);
    journal.credential_progress.needs_permission = set(&["host:web-1"]);
    journal::write(&roots.data.new, &journal).unwrap();
    let keychain = Keychain::with(&[("host:web-1", "hunter2")]);
    // The data root becomes read-only while macOS asks: the journal cannot be written afterwards.
    let root = roots.data.new.clone();
    *keychain.on_adopt.borrow_mut() = Some(Box::new(move || fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap()));
    let (report, _) = with_test_mover(|_, _| panic!("the move does not run again"), || {
        adopt_credentials_with(&roots, &QUICK, &HelperV2(&keychain), &HelperV2(&keychain))
    });
    fs::set_permissions(&roots.data.new, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(report.outcome.blocks_startup(), "{report:?}");
    assert_eq!((keychain.current("host:web-1").as_deref(), keychain.earlier("host:web-1")), (Some("hunter2"), None), "it moved");
    let message = not_run(&report).to_string();
    assert!(message.contains("No saved item was lost") && !message.contains("Nothing was deleted"), "{message}");
}

/// A Continue that completes an item an earlier adopt in this process half did (its copy is there, its old item stayed) still counts
/// it as made usable: the running app started without it.
#[test]
fn a_copy_an_earlier_adopt_in_this_process_left_still_counts_as_made_usable() {
    let keychain = Keychain::with(&[("sync:mnemonic", "twelve synthetic words")]);
    keychain.scripted.borrow_mut().insert("sync:mnemonic".into(), Adoption::NotVerified);
    let (adopted, mut journal) = adopt_waiting(&keychain, &["sync:mnemonic"], false);
    assert!(adopted.moved.is_empty());
    assert!(keychain.current("sync:mnemonic").is_some(), "the copy stayed");
    let adopted = adopt_with(&HelperV2(&keychain), &HelperV2(&keychain), &mut journal, &|_| Ok(()));
    assert_eq!((adopted.moved.clone(), adopted.made_usable), (vec!["sync:mnemonic".to_string()], vec!["sync:mnemonic".to_string()]));
    assert_eq!(journal.credential_progress.start_credential_moves, 1);
}
