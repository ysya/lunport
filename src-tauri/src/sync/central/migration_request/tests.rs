use super::*;
use crate::sync::central::{
    migration::Source,
    migration_history::{
        self,
        tests::{context, initial, library},
    },
    migration_progress::Progress,
    payload::{Catalog, Data, Identity},
};
fn plan() -> Plan {
    let (before, keys, signer) = initial();
    let mut expected = context();
    expected.sources = vec![Source {
        chain_id: "1".repeat(64),
        sequence: "0".into(),
        count: "0".into(),
        ciphertext_digest: "9".repeat(64),
    }];
    migration_history::prepare(&before, &keys, &signer, expected, &library()).unwrap()
}
fn known(plan: &Plan, phase: &str, staged: u64, retired: u64) -> Known {
    let status = serde_json::json!({"manifest":plan.manifest,"manifest_digest":plan.manifest.digest().unwrap(),"phase":phase,"staged":staged.to_string(),"history_hash":if staged==0{"0".repeat(64)}else{plan.rows[staged as usize-1].history_hash.clone()},"retired":retired.to_string()});
    serde_json::from_value::<Progress>(status)
        .unwrap()
        .verify(plan, None)
        .unwrap()
}
#[test]
fn begin_is_exact_ciphertext_manifest_and_wraps_while_missing_saved_progress_never_restarts() {
    let plan = plan();
    let Next::Send(request) = next(&plan, None, None).unwrap() else {
        panic!("begin")
    };
    assert!(matches!(request.action, MigrationAction::Begin));
    let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 2);
    assert_eq!(
        value["manifest"],
        serde_json::to_value(&plan.manifest).unwrap()
    );
    assert_eq!(value["wraps"], serde_json::to_value(&plan.wraps).unwrap());
    assert!(!String::from_utf8_lossy(&request.body).contains("PRIVATE KEY"));
    let minimum = known(&plan, "staging", 0, 0);
    assert!(next(&plan, Some(&minimum), None).is_err());
}
#[test]
fn changed_status_must_be_persisted_before_stage_commit_or_retire() {
    let plan = plan();
    let end = plan.rows.len() as u64;
    for observed in [
        known(&plan, "staging", 0, 0),
        known(&plan, "staging", end, 0),
        known(&plan, "committed", end, 0),
        known(&plan, "retired", end, 1),
    ] {
        assert!(matches!(
            next(&plan, None, Some(observed)).unwrap(),
            Next::Persist(_)
        ));
    }
    let minimum = known(&plan, "staging", 0, 0);
    assert!(matches!(
        next(&plan, Some(&minimum), Some(known(&plan, "staging", 1, 0))).unwrap(),
        Next::Persist(_)
    ));
}
#[test]
fn stage_uses_original_envelopes_and_exact_worker_field_names() {
    let plan = plan();
    let minimum = known(&plan, "staging", 2, 0);
    let Next::Send(request) =
        next(&plan, Some(&minimum), Some(known(&plan, "staging", 2, 0))).unwrap()
    else {
        panic!("stage")
    };
    assert!(matches!(request.action, MigrationAction::Stage));
    let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert_eq!(value["migration"], plan.manifest.body.migration_id);
    assert_eq!(value["after"], "2");
    assert_eq!(
        value["rows"],
        serde_json::to_value(
            plan.rows[2..]
                .iter()
                .map(|v| &v.envelope)
                .collect::<Vec<_>>()
        )
        .unwrap()
    );
}
#[test]
fn commit_and_retire_are_fixed_idempotent_operations_and_retired_only_requests_real_library_verification(
) {
    let plan = plan();
    let end = plan.rows.len() as u64;
    for (phase, commit) in [("staging", true), ("committed", false)] {
        let floor = known(&plan, phase, end, 0);
        let Next::Send(request) =
            next(&plan, Some(&floor), Some(known(&plan, phase, end, 0))).unwrap()
        else {
            panic!("operation")
        };
        assert!(if commit {
            matches!(request.action, MigrationAction::Commit)
        } else {
            matches!(request.action, MigrationAction::Retire)
        });
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
            serde_json::json!({"migration":plan.manifest.body.migration_id})
        );
    }
    let floor = known(&plan, "retired", end, 1);
    assert!(matches!(
        next(&plan, Some(&floor), Some(known(&plan, "retired", end, 1))).unwrap(),
        Next::VerifyCommitted
    ));
}
#[test]
fn saved_floor_cannot_roll_back_or_switch_to_a_new_ciphertext_plan() {
    let plan = plan();
    let floor = known(&plan, "staging", 2, 0);
    assert!(next(&plan, Some(&floor), Some(known(&plan, "staging", 1, 0))).is_err());
    let other = super::tests::plan();
    assert!(next(&other, Some(&floor), Some(known(&other, "staging", 2, 0))).is_err());
}
#[test]
fn large_staged_history_still_emits_no_more_than_thirty_two_existing_envelopes() {
    let (before, keys, signer) = initial();
    let mut history = library();
    history.extend((0..70).map(|_| {
        (
            Identity {
                kind: "meta".into(),
                id: "catalog".into(),
                scope: None,
            },
            Data::Catalog(Catalog {
                tunnels: vec![],
                collections: vec![],
                group_orders: vec![],
            }),
        )
    }));
    let plan = migration_history::prepare(&before, &keys, &signer, context(), &history).unwrap();
    let floor = known(&plan, "staging", 17, 0);
    let Next::Send(request) =
        next(&plan, Some(&floor), Some(known(&plan, "staging", 17, 0))).unwrap()
    else {
        panic!("stage")
    };
    let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    let rows = value["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 32);
    assert_eq!(
        rows[0],
        serde_json::to_value(&plan.rows[17].envelope).unwrap()
    );
    assert_eq!(
        rows[31],
        serde_json::to_value(&plan.rows[48].envelope).unwrap()
    );
}
