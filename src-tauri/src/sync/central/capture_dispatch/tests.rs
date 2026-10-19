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
pub(super) fn ready_fixture(joined: bool) -> (TestDevice, VaultKeys) {
    let (device, keys) = fixture(joined);
    let env = device.env();
    for _ in 0..10 {
        let step = with_transport(&env, &keys, |_, loaded, action| match action {
            Action::Freeze { .. } => Ok(Received::Freeze(if loaded.pending_discovery() {
                loaded.fetching().unwrap().progress().clone()
            } else {
                progress(loaded, true)
            })),
            Action::Fetch(_) => Ok(Received::Fetch(PullResponse {
                records: vec![],
                latest_seq: 0,
            })),
            _ => panic!("local step cannot cross HTTP"),
        })
        .unwrap();
        if step == Step::Ready {
            return (device, keys);
        }
    }
    panic!("fixture did not finish capture")
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

struct CursorFault<'a> {
    inner: &'a crate::sync::testkit::MemKeychain,
    role: String,
    after: bool,
    armed: std::sync::atomic::AtomicBool,
}
impl crate::sync::env::Keychain for CursorFault<'_> {
    fn get(&self, k: &str) -> Result<Option<String>, AppError> {
        self.inner.get(k)
    }
    fn get_noninteractive(&self, k: &str) -> Result<Option<String>, AppError> {
        self.inner.get_noninteractive(k)
    }
    fn set(&self, k: &str, v: &str) -> Result<(), AppError> {
        self.inner.set(k, v)
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        panic!("continuation cannot delete credentials")
    }
    fn set_noninteractive(&self, k: &str, v: &str) -> Result<(), AppError> {
        let fail = k == self.role && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst);
        if fail && !self.after {
            return Err(invalid());
        }
        self.inner.set_noninteractive(k, v)?;
        if fail && self.after {
            return Err(invalid());
        }
        Ok(())
    }
}
#[test]
fn cold_dispatch_recovers_a_freeze_snapshot_after_cursor_failure_without_refetching_or_reencrypting(
) {
    use crate::sync::env::Keychain;
    for after in [false, true] {
        let (d, keys) = fixture(false);
        let env = d.env();
        let owner = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        let fault = CursorFault {
            inner: &d.keychain,
            role: owner
                .control
                .profile
                .profile()
                .unwrap()
                .slot("source-migration-cursor"),
            after,
            armed: std::sync::atomic::AtomicBool::new(true),
        };
        let mut interrupted = d.env();
        interrupted.keychain = &fault;
        assert!(
            with_transport(&interrupted, &keys, |_, loaded, action| empty_frozen(
                &interrupted,
                loaded,
                action
            ))
            .is_err()
        );
        let exact = tree(&d);
        assert_eq!(exact.len(), 4);
        d.runtime.core.lock().unwrap().generation = 0;
        let result = with_transport(&env, &keys, |_, _, _| {
            panic!("already written result must not be requested again")
        })
        .unwrap();
        assert_eq!(result, if after { Step::Ready } else { Step::More });
        assert_eq!(tree(&d), exact);
        assert_eq!(cursor(&d).revision(), 3);
        assert_eq!(
            with_transport(&env, &keys, |_, _, _| panic!("ready has no HTTP")).unwrap(),
            Step::Ready
        );
        // Confirm the test adapter can read but no recovery path silently recreated a role.
        assert!(d
            .keychain
            .get_noninteractive(&fault.role)
            .unwrap()
            .is_some());
    }
}
#[test]
fn cold_dispatch_recovers_fetch_and_discovery_snapshots_as_the_exact_expected_next_step() {
    for step in ["fetch", "discovery"] {
        let (d, keys) = fixture(true);
        let env = d.env();
        with_transport(&env, &keys, |_, loaded, action| {
            empty_frozen(&env, loaded, action)
        })
        .unwrap();
        if step == "discovery" {
            with_transport(&env, &keys, |_, loaded, action| {
                empty_frozen(&env, loaded, action)
            })
            .unwrap();
        }
        let before = cursor(&d);
        let owner = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        let fault = CursorFault {
            inner: &d.keychain,
            role: owner
                .control
                .profile
                .profile()
                .unwrap()
                .slot("source-migration-cursor"),
            after: false,
            armed: std::sync::atomic::AtomicBool::new(true),
        };
        let mut interrupted = d.env();
        interrupted.keychain = &fault;
        assert!(
            with_transport(&interrupted, &keys, |_, loaded, action| empty_frozen(
                &interrupted,
                loaded,
                action
            ))
            .is_err()
        );
        assert!(cursor(&d) == before);
        let exact = tree(&d);
        assert_eq!(
            with_transport(&env, &keys, |_, _, _| panic!("orphan recovery has no HTTP")).unwrap(),
            Step::More
        );
        assert_eq!(tree(&d), exact);
        assert_eq!(cursor(&d).revision(), before.revision() + 1);
    }
}
#[test]
fn authenticated_but_wrong_step_or_duplicate_orphans_are_preserved_and_never_admitted() {
    for wrong in ["unknown", "old_frame", "duplicate"] {
        let (d, keys) = fixture(false);
        let env = d.env();
        let owner = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        let before = cursor(&d);
        {
            let life = env.runtime.lifecycle.lock().unwrap();
            let saved = Cursor::load(&env, &life, &owner).unwrap().unwrap();
            let bytes = if wrong == "unknown" {
                zeroize::Zeroizing::new(b"UNKNOWN_PRIVATE_INPUT".to_vec())
            } else {
                saved.bytes
            };
            super::super::source_archive::next(
                &env,
                &life,
                &owner,
                before.receipt().next_ordinal().unwrap(),
                before.receipt(),
                &bytes,
            )
            .unwrap();
            if wrong == "duplicate" {
                super::super::source_archive::next(
                    &env,
                    &life,
                    &owner,
                    before.receipt().next_ordinal().unwrap(),
                    before.receipt(),
                    &bytes,
                )
                .unwrap();
            }
        }
        let exact = tree(&d);
        assert!(
            with_transport(&env, &keys, |_, _, _| panic!(
                "unadmitted data cannot cross HTTP"
            ))
            .is_err(),
            "{wrong}"
        );
        assert!(cursor(&d) == before);
        assert_eq!(tree(&d), exact);
    }
}
#[test]
fn an_exact_orphan_cannot_hide_a_source_change_before_cold_recovery() {
    let (d, keys) = fixture(false);
    let env = d.env();
    let owner = record_runtime::snapshot(&env)
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let fault = CursorFault {
        inner: &d.keychain,
        role: owner
            .control
            .profile
            .profile()
            .unwrap()
            .slot("source-migration-cursor"),
        after: false,
        armed: std::sync::atomic::AtomicBool::new(true),
    };
    let mut interrupted = d.env();
    interrupted.keychain = &fault;
    let before = cursor(&d);
    assert!(
        with_transport(&interrupted, &keys, |_, loaded, action| empty_frozen(
            &interrupted,
            loaded,
            action
        ))
        .is_err()
    );
    let exact = tree(&d);
    fs::write(&env.state_path, b"new local source B").unwrap();
    assert!(with_transport(&env, &keys, |_, _, _| panic!(
        "changed source cannot cross HTTP"
    ))
    .is_err());
    assert!(cursor(&d) == before);
    assert_eq!(tree(&d), exact);
    assert_eq!(fs::read(&env.state_path).unwrap(), b"new local source B");
}

#[test]
fn a_remote_only_child_is_discovered_and_durably_bound_before_its_first_frozen_read() {
    use crate::sync::{
        crypto::{derive_account, ChainKeys},
        record::{Record, RecordKind, SpaceKeyPayload},
        state::MNEMONIC_ACCOUNT,
        state_v2::SealedRecord,
    };
    let (d, keys) = fixture(true);
    let env = d.env();
    let phrase = zeroize::Zeroizing::new(d.keychain.entry(MNEMONIC_ACCOUNT).unwrap());
    let mut parent = derive_account(&phrase).unwrap();
    let mut child = ChainKeys::generate().unwrap();
    let envelope = SealedRecord::seal(
        &parent,
        &Record {
            kind: RecordKind::SpaceKey,
            id: child.chain_id.clone(),
            version: 1,
            updated_at_ms: 1,
            device_id: "d".repeat(32),
            deleted: false,
            payload: serde_json::to_value(SpaceKeyPayload::from_keys(&child)).unwrap(),
        },
        1,
    )
    .unwrap()
    .envelope;
    let checkpoint = legacy_checkpoint(&parent.chain_id, 1, &[envelope.clone()]).unwrap();
    with_transport(&env, &keys, |_, loaded, _| {
        let mut p = progress(loaded, true);
        p.sources = vec![checkpoint.clone()];
        Ok(Received::Freeze(p))
    })
    .unwrap();
    with_transport(&env, &keys, |_, _, action| {
        assert!(matches!(action,Action::Fetch(chain) if chain==&parent.chain_id));
        Ok(Received::Fetch(PullResponse {
            records: vec![envelope],
            latest_seq: 1,
        }))
    })
    .unwrap();
    let owner = record_runtime::snapshot(&env)
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let fault = CursorFault {
        inner: &d.keychain,
        role: owner
            .control
            .profile
            .profile()
            .unwrap()
            .slot("source-migration-cursor"),
        after: false,
        armed: std::sync::atomic::AtomicBool::new(true),
    };
    let mut interrupted = d.env();
    interrupted.keychain = &fault;
    assert!(with_transport(&interrupted, &keys, |_, _, _| panic!(
        "discover before transport"
    ))
    .is_err());
    let exact = tree(&d);
    assert_eq!(
        with_transport(&env, &keys, |_, _, _| panic!(
            "restore discovered book before transport"
        ))
        .unwrap(),
        Step::More
    );
    assert_eq!(tree(&d), exact);
    with_transport(&env, &keys, |_, loaded, action| {
        let Action::Freeze { sources, next } = action else {
            panic!("new child must first freeze")
        };
        assert_eq!(next, &vec![child.chain_id.clone()]);
        assert!(sources.chains().contains(&child.chain_id));
        let mut p = loaded.fetching().unwrap().progress().clone();
        p.proof.push(ProofStep {
            digest: loaded.intent().digest().unwrap(),
            intent: loaded.intent().clone(),
        });
        p.sources
            .push(legacy_checkpoint(&child.chain_id, 0, &[]).unwrap());
        p.sources.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));
        p.phase = Phase::Frozen;
        p.next = vec![];
        Ok(Received::Freeze(p))
    })
    .unwrap();
    with_transport(&env, &keys, |_, _, action| {
        assert!(matches!(action,Action::Fetch(chain) if chain==&child.chain_id));
        Ok(Received::Fetch(PullResponse {
            records: vec![],
            latest_seq: 0,
        }))
    })
    .unwrap();
    assert_eq!(
        with_transport(&env, &keys, |_, _, _| panic!("all snapshots are captured")).unwrap(),
        Step::Ready
    );
    parent.clear_sensitive();
    child.clear_sensitive();
}

pub(super) fn material_ready_fixture() -> (TestDevice, VaultKeys) {
    material_ready_fixture_at(false)
}
pub(super) fn material_ready_fixture_at(canonical: bool) -> (TestDevice, VaultKeys) {
    let (device, keys, session) = source_capture::tests::fixture(false);
    if canonical {
        // Older unit fixtures used an arbitrary Vault id. Actual account reads pin the
        // deterministic personal id, so integration fixtures use the production derivation.
        let env = device.env();
        let mut state = record_runtime::snapshot(&env).unwrap().0;
        let owner = state.local.central.as_mut().unwrap();
        let vault =
            super::super::membership::personal_vault_id(owner.control.anchor.as_ref().unwrap())
                .unwrap();
        owner.control.personal_vault = Some(vault.clone());
        owner.replica.as_mut().unwrap().vault = vault.clone();
        owner.control.auth_epoch = 2;
        owner.replica.as_mut().unwrap().creation_authorization_epoch = 2;
        let signer = &session.identity.as_ref().unwrap().keys;
        let mut header = owner.own_wraps[0].header.clone();
        header.vault_id = vault;
        owner.own_wraps = vec![super::super::crypto::wrap_keys(&keys, signer, header).unwrap()];
        let account = owner.control.account_id.clone();
        owner.validate().unwrap();
        fs::write(&env.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let mut core = device.runtime.core.lock().unwrap();
        core.records = Some(state);
        core.central_session = Some(Arc::new(Session {
            profile: session.profile.clone(),
            identity: session.identity.clone(),
            tokens: Arc::clone(&session.tokens),
            device: Some(super::super::api::DeviceSession::synthetic_for_test(
                account,
                super::super::api::DeviceState::Active,
                2,
                std::time::Duration::from_secs(300),
            )),
            device_access_denied: false,
            tokens_started: std::time::Instant::now(),
        }));
    }
    {
        let env = device.env();
        let view = crate::vault::store::read_vault(
            &crate::vault::store::vault_path(&env.state_path),
            env.keychain,
        )
        .unwrap();
        let entry = view.get(&"3".repeat(32)).unwrap().unwrap();
        let public = super::super::projection::tests::slot(&entry.private_key).public;
        record_runtime::mutate_records(&env, |state| {
            let mut next = state.clone();
            next.local.keys.insert(
                "1".repeat(32),
                crate::sync::records_v3::LocalKeyMetadata {
                    vault_id: "3".repeat(32),
                    public: public.clone(),
                },
            );
            Ok(next)
        })
        .unwrap();
        source_capture::start_or_resume(&env, &keys, &BTreeMap::new()).unwrap();
    }
    let env = device.env();
    for _ in 0..10 {
        let step = with_transport(&env, &keys, |_, loaded, action| match action {
            Action::Freeze { .. } => Ok(Received::Freeze(progress(loaded, true))),
            Action::Fetch(_) => Ok(Received::Fetch(PullResponse {
                records: vec![],
                latest_seq: 0,
            })),
            _ => panic!("local step cannot cross HTTP"),
        })
        .unwrap();
        if step == Step::Ready {
            return (device, keys);
        }
    }
    panic!("material fixture did not finish capture")
}
