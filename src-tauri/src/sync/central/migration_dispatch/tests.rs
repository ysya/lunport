use super::super::{api::MigrationAction, migration_progress::Phase};
use super::*;
use crate::sync::testkit::TestDevice;
use serde_json::{json, Value};
fn fixture(approved: bool, joined: bool) -> (TestDevice, VaultKeys) {
    let (d, keys) = super::super::capture_dispatch::ready_for_test(joined);
    source_complete::ensure(&d.env(), &keys).unwrap().unwrap();
    let shown = review::preview(&d.env(), &keys, &BTreeMap::new()).unwrap();
    if approved {
        let value = serde_json::to_value(shown).unwrap();
        review::confirm(
            &d.env(),
            &keys,
            &BTreeMap::new(),
            value["ticket"].as_str().unwrap(),
        )
        .unwrap();
    }
    (d, keys)
}
fn progress(loaded: &Loaded, phase: &str, staged: usize) -> Value {
    json!({"manifest":loaded.plan.manifest,"manifest_digest":loaded.plan.manifest.digest().unwrap(),"phase":phase,"staged":staged.to_string(),"history_hash":if staged==0{"0".repeat(64)}else{loaded.plan.rows[staged-1].history_hash.clone()},"retired":if phase=="retired"{loaded.plan.manifest.body.sources.len().to_string()}else{"0".into()}})
}
#[test]
fn without_explicit_consent_no_migration_status_or_mutation_crosses_transport() {
    let (d, keys) = fixture(false, false);
    assert!(
        with_transport(&d.env(), &keys, &BTreeMap::new(), |_, _, _| panic!(
            "no transport before consent"
        ))
        .is_err()
    );
}
#[test]
fn exact_stage_commit_retire_and_real_readback_remain_inert_and_cold_resumable() {
    for joined in [false, true] {
        let (d, keys) = fixture(true, joined);
        let env = d.env();
        let original = record_runtime::snapshot(&env).unwrap().0;
        let mut remote: Option<Value> = None;
        let mut sent = Vec::new();
        let mut readback = 0;
        let mut finished = false;
        for _ in 0..15 {
            let step=with_transport(&env,&keys,&BTreeMap::new(),|_,loaded,action|{
            assert!(env.runtime.lifecycle.try_lock().is_ok());assert!(env.runtime.vault.try_lock().is_ok());assert!(env.runtime.format_publication.try_lock().is_ok());assert!(env.runtime.core.try_lock().is_ok());
            match action{
                Action::Status=>Ok(Reply::for_test(if remote.is_some(){200}else{404},&remote)),
                Action::Send(request)=>{
                    sent.push(match request.action { MigrationAction::Begin=>"begin", MigrationAction::Stage=>"stage", MigrationAction::Commit=>"commit", MigrationAction::Retire=>"retire" }.to_string());
                    remote=Some(match request.action{
                        MigrationAction::Begin=>progress(loaded,"staging",0),
                        MigrationAction::Stage=>{let body:Value=serde_json::from_slice(&request.body).unwrap();assert_eq!(body["rows"],serde_json::to_value(loaded.plan.rows.iter().map(|r|&r.envelope).collect::<Vec<_>>()).unwrap());progress(loaded,"staging",loaded.plan.rows.len())},
                        MigrationAction::Commit=>progress(loaded,if joined{"committed"}else{"retired"},loaded.plan.rows.len()),
                        MigrationAction::Retire=>progress(loaded,"retired",loaded.plan.rows.len()),
                    });Ok(Reply::for_test(200,remote.as_ref().unwrap()))
                },
                Action::Readback(since)=>{assert_eq!(since,0);readback+=1;Ok(Reply::for_test(200,&json!({"records":loaded.plan.rows,"sequence":loaded.plan.rows.len().to_string(),"history_hash":loaded.plan.manifest.body.target_history_hash,"membership_head":loaded.plan.manifest.body.membership_head,"epoch":1,"phase":"ready"})))},
            }
        }).unwrap();
            d.runtime.core.lock().unwrap().generation = 0;
            match step {
                Step::More => {}
                Step::Verified(verified) => {
                    finished = true;
                    assert_eq!(
                        sent,
                        if joined {
                            vec!["begin", "stage", "commit", "retire"]
                        } else {
                            vec!["begin", "stage", "commit"]
                        }
                    );
                    assert_eq!(readback, 1);
                    assert!(!verified.committed.workspace().control.cutover);
                    assert!(verified.loaded.progress().unwrap().phase() == Phase::Retired);
                    verified
                        .approval
                        .require_current(&env, &verified.loaded)
                        .unwrap();
                    assert_eq!(record_runtime::snapshot(&env).unwrap().0, original);
                    break;
                }
            }
        }
        assert!(finished, "migration did not finish");
        assert_eq!(readback, 1);
    }
}
#[test]
fn changed_source_during_http_does_not_advance_the_saved_cursor() {
    let (d, keys) = fixture(true, false);
    let env = d.env();
    let before = migration_journal::ensure(&env, &keys, &BTreeMap::new())
        .unwrap()
        .cursor;
    assert!(
        with_transport(&env, &keys, &BTreeMap::new(), |_, loaded, action| {
            assert!(matches!(action, Action::Status));
            std::fs::write(&env.state_path, b"source B").unwrap();
            Ok(Reply::for_test(200, &progress(loaded, "staging", 0)))
        })
        .is_err()
    );
    let owner = record_runtime::snapshot(&env)
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let life = env.runtime.lifecycle.lock().unwrap();
    assert!(
        super::super::source_cursor::Cursor::load(&env, &life, &owner)
            .unwrap()
            .unwrap()
            .cursor
            == before
    );
}
#[test]
fn stalled_forged_or_missing_remote_state_keeps_saved_progress_and_never_publishes() {
    for case in ["stalled", "forged", "missing"] {
        let (d, keys) = fixture(true, false);
        let env = d.env();
        with_transport(&env, &keys, &BTreeMap::new(), |_, loaded, action| {
            Ok(match action {
                Action::Status => Reply::for_test(404, &json!({})),
                Action::Send(_) => Reply::for_test(200, &progress(loaded, "staging", 0)),
                _ => panic!(),
            })
        })
        .unwrap();
        let before = migration_journal::ensure(&env, &keys, &BTreeMap::new())
            .unwrap()
            .cursor;
        let result = with_transport(&env, &keys, &BTreeMap::new(), |_, loaded, _action| {
            let mut body = progress(loaded, "staging", 0);
            if case == "forged" {
                body["history_hash"] = "9".repeat(64).into();
            }
            Ok(Reply::for_test(
                if case == "missing" { 404 } else { 200 },
                &body,
            ))
        });
        assert!(result.is_err(), "{case}");
        let restored = migration_journal::ensure(&env, &keys, &BTreeMap::new()).unwrap();
        assert!(restored.cursor == before);
        assert!(!restored.plan.before().control.cutover);
    }
}

#[test]
fn the_actual_http_adapter_shares_the_request_budget_across_status_and_mutation() {
    let (d, keys) = fixture(true, false);
    let env = d.env();
    let loaded = migration_journal::ensure(&env, &keys, &BTreeMap::new()).unwrap();
    let vault = loaded
        .plan
        .before()
        .control
        .personal_vault
        .as_ref()
        .unwrap();
    let before = loaded.cursor;
    let mut server = mockito::Server::new();
    let status = server
        .mock("GET", format!("/v2/vaults/{vault}/migration").as_str())
        .with_status(404)
        .expect(1)
        .create();
    let mutation = server
        .mock(
            "POST",
            format!("/v2/vaults/{vault}/migration/begin").as_str(),
        )
        .with_status(500)
        .expect(0)
        .create();
    let budget = Budget::limited(1, std::time::Duration::from_secs(30));
    let result = with_transport(&env, &keys, &BTreeMap::new(), |session, loaded, action| {
        let api = Api::bounded(&server.url(), &budget)?;
        let grant = session.device.as_ref().unwrap();
        let vault = loaded
            .plan
            .before()
            .control
            .personal_vault
            .as_deref()
            .unwrap();
        match action {
            Action::Status => api.migration_status(grant, vault, false),
            Action::Send(request) => {
                api.migration(grant, vault, request.action, request.body.clone())
            }
            Action::Readback(_) => panic!("no readback before stage"),
        }
    });
    assert!(Budget::exhausted(&result.err().unwrap()));
    assert_eq!(budget.used(), 1);
    status.assert();
    mutation.assert();
    assert!(
        migration_journal::ensure(&env, &keys, &BTreeMap::new())
            .unwrap()
            .cursor
            == before
    );
}
#[test]
fn rate_limit_retains_the_cooldown_and_starts_no_mutation() {
    let (d, keys) = fixture(true, false);
    let env = d.env();
    let mut calls = 0;
    assert!(
        with_transport(&env, &keys, &BTreeMap::new(), |_, _, action| {
            calls += 1;
            assert!(matches!(action, Action::Status));
            Ok(Reply::for_test(429, &json!({})))
        })
        .is_err()
    );
    assert_eq!(calls, 1);
    assert!(round::cooldown(&env) > std::time::Duration::from_secs(85));
    // A cooldown must also precede account/session renewal, even if no cached session exists.
    d.runtime.core.lock().unwrap().central_session = None;
    let expected = round::check_cooldown(&env).unwrap_err().to_string();
    let budget = Budget::new();
    assert_eq!(
        advance(&env, &keys, &BTreeMap::new(), &budget)
            .err()
            .unwrap()
            .to_string(),
        expected
    );
    assert_eq!(
        super::super::capture_dispatch::advance(&env, &keys, &budget)
            .err()
            .unwrap()
            .to_string(),
        expected
    );
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_lost_stage_reply_recovers_the_exact_remote_floor_without_regenerating_or_reuploading_rows() {
    let (d, keys) = fixture(true, false);
    let env = d.env();
    with_transport(&env, &keys, &BTreeMap::new(), |_, loaded, action| {
        Ok(match action {
            Action::Status => Reply::for_test(404, &json!({})),
            Action::Send(_) => Reply::for_test(200, &progress(loaded, "staging", 0)),
            _ => panic!(),
        })
    })
    .unwrap();
    let before = migration_journal::ensure(&env, &keys, &BTreeMap::new()).unwrap();
    let exact = before.plan.rows.clone();
    let receipt = before.cursor.receipt().clone();
    let mut remote = None;
    assert!(with_transport(
        &env,
        &keys,
        &BTreeMap::new(),
        |_, loaded, action| match action {
            Action::Status => Ok(Reply::for_test(200, &progress(loaded, "staging", 0))),
            Action::Send(request) => {
                assert!(matches!(request.action, MigrationAction::Stage));
                remote = Some(progress(loaded, "staging", loaded.plan.rows.len()));
                Err(AppError::Other("synthetic lost reply".into()))
            }
            _ => panic!(),
        }
    )
    .is_err());
    assert_eq!(
        migration_journal::ensure(&env, &keys, &BTreeMap::new())
            .unwrap()
            .cursor
            .receipt(),
        &receipt
    );
    d.runtime.core.lock().unwrap().generation = 0;
    with_transport(&env, &keys, &BTreeMap::new(), |_, _, action| {
        assert!(matches!(action, Action::Status));
        Ok(Reply::for_test(200, remote.as_ref().unwrap()))
    })
    .unwrap();
    let restored = migration_journal::ensure(&env, &keys, &BTreeMap::new()).unwrap();
    assert!(restored.plan.rows == exact);
    assert_eq!(restored.progress().unwrap().staged(), exact.len() as u64);
}
#[test]
fn advertised_retirement_without_matching_readback_cannot_produce_verified_publication_input() {
    let (d, keys) = fixture(true, false);
    let env = d.env();
    with_transport(&env, &keys, &BTreeMap::new(), |_, loaded, action| {
        assert!(matches!(action, Action::Status));
        Ok(Reply::for_test(
            200,
            &progress(loaded, "retired", loaded.plan.rows.len()),
        ))
    })
    .unwrap();
    let before = migration_journal::ensure(&env, &keys, &BTreeMap::new())
        .unwrap()
        .cursor;
    assert!(with_transport(&env,&keys,&BTreeMap::new(),|_,loaded,action|match action{Action::Status=>Ok(Reply::for_test(200,&progress(loaded,"retired",loaded.plan.rows.len()))),Action::Readback(_)=>{let mut rows=serde_json::to_value(&loaded.plan.rows).unwrap();rows[0]["history_hash"]="9".repeat(64).into();Ok(Reply::for_test(200,&json!({"records":rows,"sequence":loaded.plan.rows.len().to_string(),"history_hash":loaded.plan.manifest.body.target_history_hash,"membership_head":loaded.plan.manifest.body.membership_head,"epoch":1,"phase":"ready"})))},_=>panic!("no mutation after retired status")}).is_err());
    assert!(
        migration_journal::ensure(&env, &keys, &BTreeMap::new())
            .unwrap()
            .cursor
            == before
    );
}

pub(super) fn verified(env: &SyncEnv, keys: &VaultKeys) -> Verified {
    for _ in 0..4 {
        let step=with_transport(env,keys,&BTreeMap::new(),|_,loaded,action|match action{
            Action::Status=>Ok(Reply::for_test(200,&progress(loaded,"retired",loaded.plan.rows.len()))),
            Action::Readback(_)=>Ok(Reply::for_test(200,&json!({"records":loaded.plan.rows,"sequence":loaded.plan.rows.len().to_string(),"history_hash":loaded.plan.manifest.body.target_history_hash,"membership_head":loaded.plan.manifest.body.membership_head,"epoch":1,"phase":"ready"}))),
            Action::Send(_)=>panic!("exact retired fixture needs no write"),
        }).unwrap();
        if let Step::Verified(verified) = step {
            return verified;
        }
    }
    panic!("fixture did not verify readback")
}
pub(super) fn verified_fixture() -> (TestDevice, VaultKeys, Verified) {
    let (d, keys) = fixture(true, false);
    let verified = verified(&d.env(), &keys);
    (d, keys, verified)
}

pub(super) fn material_verified_fixture() -> (TestDevice, VaultKeys, Verified) {
    let (d, keys) = super::super::capture_dispatch::material_ready_for_test();
    source_complete::ensure(&d.env(), &keys).unwrap().unwrap();
    let shown =
        serde_json::to_value(review::preview(&d.env(), &keys, &BTreeMap::new()).unwrap()).unwrap();
    review::confirm(
        &d.env(),
        &keys,
        &BTreeMap::new(),
        shown["ticket"].as_str().unwrap(),
    )
    .unwrap();
    let result = verified(&d.env(), &keys);
    (d, keys, result)
}
