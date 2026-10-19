use super::*;
use crate::sync::{
    central::{migration::legacy_checkpoint, migration_freeze::ProofStep, source_cursor::Cursor},
    testkit::TestDevice,
};
use std::{collections::BTreeMap, fs};
fn fixture(joined: bool) -> (TestDevice, VaultKeys) {
    let (device, keys, _) = source_capture::tests::fixture(joined);
    source_capture::start_or_resume(&device.env(), &keys, &BTreeMap::new()).unwrap();
    (device, keys)
}
fn progress(loaded: &Loaded, freeze: bool) -> Progress {
    let chains = loaded.intent().body.source_order();
    Progress {
        proof: vec![ProofStep {
            digest: loaded.intent().digest().unwrap(),
            intent: loaded.intent().clone(),
        }],
        sources: if freeze {
            chains
                .iter()
                .map(|chain| legacy_checkpoint(chain, 0, &[]).unwrap())
                .collect()
        } else {
            vec![]
        },
        phase: if freeze || chains.is_empty() {
            Phase::Frozen
        } else {
            Phase::Freezing
        },
        next: if freeze {
            vec![]
        } else {
            chains.iter().take(8).map(|s| s.to_string()).collect()
        },
    }
}
fn cursor(device: &TestDevice) -> Cursor {
    let env = device.env();
    let state = record_runtime::snapshot(&env).unwrap().0;
    let life = env.runtime.lifecycle.lock().unwrap();
    Cursor::load(&env, &life, state.local.central.as_ref().unwrap())
        .unwrap()
        .unwrap()
        .cursor
}
fn tree(device: &TestDevice) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    let root = device
        .env()
        .state_path
        .parent()
        .unwrap()
        .join("central-source-archives");
    fs::read_dir(root)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name(), fs::read(e.path()).unwrap())
        })
        .collect()
}
fn empty_frozen(env: &SyncEnv, loaded: &Loaded, action: &Action) -> Result<Received, AppError> {
    assert!(env.runtime.lifecycle.try_lock().is_ok());
    assert!(env.runtime.vault.try_lock().is_ok());
    assert!(env.runtime.format_publication.try_lock().is_ok());
    assert!(env.runtime.core.try_lock().is_ok());
    match action {
        Action::Freeze { next, .. } => {
            assert_eq!(next.len(), loaded.intent().body.chains.len());
            Ok(Received::Freeze(progress(loaded, true)))
        }
        Action::Fetch(_) => Ok(Received::Fetch(PullResponse {
            records: vec![],
            latest_seq: 0,
        })),
        _ => panic!("local continuation cannot perform HTTP"),
    }
}
#[test]
fn a_local_only_account_finishes_capture_without_legacy_bearers_or_library_publication() {
    let (d, keys) = fixture(false);
    let env = d.env();
    let before = record_runtime::snapshot(&env).unwrap();
    assert_eq!(
        with_transport(&env, &keys, |_, loaded, action| empty_frozen(
            &env, loaded, action
        ))
        .unwrap(),
        Step::More
    );
    assert_eq!(
        with_transport(&env, &keys, |_, _, _| panic!("ready capture has no HTTP")).unwrap(),
        Step::Ready
    );
    assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
    assert_eq!(cursor(&d).revision(), 3);
}
#[test]
fn a_parent_is_frozen_then_fetched_and_its_discovery_is_saved_before_book_activation() {
    let (d, keys) = fixture(true);
    let env = d.env();
    assert_eq!(
        with_transport(&env, &keys, |_, loaded, action| {
            assert!(matches!(action, Action::Freeze { .. }));
            empty_frozen(&env, loaded, action)
        })
        .unwrap(),
        Step::More
    );
    assert_eq!(
        with_transport(&env, &keys, |_, loaded, action| {
            assert!(matches!(action, Action::Fetch(_)));
            empty_frozen(&env, loaded, action)
        })
        .unwrap(),
        Step::More
    );
    assert_eq!(
        with_transport(&env, &keys, |_, _, _| panic!(
            "discovery must be saved before HTTP"
        ))
        .unwrap(),
        Step::More
    );
    assert_eq!(cursor(&d).revision(), 5);
    assert_eq!(
        with_transport(&env, &keys, |_, loaded, action| {
            assert!(loaded.pending_discovery());
            assert!(matches!(action, Action::Freeze { .. }));
            Ok(Received::Freeze(
                loaded.fetching().unwrap().progress().clone(),
            ))
        })
        .unwrap(),
        Step::More
    );
    assert_eq!(
        with_transport(&env, &keys, |_, _, _| panic!("ready has no HTTP")).unwrap(),
        Step::Ready
    );
    assert_eq!(cursor(&d).revision(), 6);
    assert!(
        !record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap()
            .control
            .cutover
    );
}
#[test]
fn an_unfrozen_parent_is_never_read_and_a_lost_reply_reuses_the_same_intent() {
    let (d, keys) = fixture(true);
    let env = d.env();
    let before = cursor(&d);
    let exact = tree(&d);
    let mut sent = None;
    assert!(with_transport(&env, &keys, |_, loaded, action| {
        assert!(matches!(action, Action::Freeze { .. }));
        sent = Some(loaded.intent().clone());
        Err(invalid())
    })
    .is_err());
    assert!(cursor(&d) == before);
    assert_eq!(tree(&d), exact);
    assert_eq!(
        with_transport(&env, &keys, |_, loaded, action| {
            assert!(matches!(action, Action::Freeze { .. }));
            assert_eq!(sent.as_ref(), Some(loaded.intent()));
            Ok(Received::Freeze(progress(loaded, false)))
        })
        .unwrap(),
        Step::More
    );
    assert_eq!(
        with_transport(&env, &keys, |_, loaded, action| {
            assert!(matches!(action, Action::Freeze { .. }));
            Ok(Received::Freeze(progress(loaded, true)))
        })
        .unwrap(),
        Step::More
    );
}
#[test]
fn stale_sessions_generations_or_source_files_after_http_never_advance_the_protected_cursor() {
    for change in ["session", "generation", "files"] {
        let (d, keys) = fixture(false);
        let env = d.env();
        let before = cursor(&d);
        let exact = tree(&d);
        assert!(
            with_transport(&env, &keys, |_, loaded, action| {
                let reply = empty_frozen(&env, loaded, action)?;
                match change {
                    "session" => env.runtime.core.lock().unwrap().central_session = None,
                    "generation" => env.runtime.core.lock().unwrap().generation += 1,
                    _ => fs::write(&env.state_path, b"changed source").unwrap(),
                };
                Ok(reply)
            })
            .is_err(),
            "{change}"
        );
        assert!(cursor(&d) == before);
        assert_eq!(tree(&d), exact);
    }
}
#[test]
fn wrong_proof_or_wrong_reply_type_never_persists_a_successful_prefix() {
    for wrong in ["proof", "type"] {
        let (d, keys) = fixture(false);
        let env = d.env();
        let before = cursor(&d);
        let exact = tree(&d);
        assert!(with_transport(&env, &keys, |_, loaded, _| {
            if wrong == "type" {
                return Ok(Received::Fetch(PullResponse {
                    records: vec![],
                    latest_seq: 0,
                }));
            }
            let mut progress = progress(loaded, true);
            progress.proof[0].digest = "0".repeat(64);
            Ok(Received::Freeze(progress))
        })
        .is_err());
        assert!(cursor(&d) == before);
        assert_eq!(tree(&d), exact);
    }
}

#[test]
fn an_exhausted_shared_round_never_resumes_transport_or_changes_the_source_cursor() {
    let (d, keys) = fixture(false);
    let env = d.env();
    let before = cursor(&d);
    let exact = tree(&d);
    let budget = Budget::limited(0, std::time::Duration::from_secs(30));
    let error = advance(&env, &keys, &budget).err().unwrap();
    assert!(Budget::exhausted(&error));
    assert_eq!(budget.used(), 0);
    assert!(cursor(&d) == before);
    assert_eq!(tree(&d), exact);
}

#[test]
fn a_nonadvancing_service_cannot_fill_the_archive_with_redundant_progress_snapshots() {
    let (d, keys) = fixture(true);
    let env = d.env();
    with_transport(&env, &keys, |_, loaded, _| {
        Ok(Received::Freeze(progress(loaded, false)))
    })
    .unwrap();
    let before = cursor(&d);
    let exact = tree(&d);
    assert!(with_transport(&env, &keys, |_, loaded, action| {
        assert!(matches!(action, Action::Freeze { .. }));
        Ok(Received::Freeze(
            loaded.fetching().unwrap().progress().clone(),
        ))
    })
    .is_err());
    assert!(cursor(&d) == before);
    assert_eq!(tree(&d), exact);
}
