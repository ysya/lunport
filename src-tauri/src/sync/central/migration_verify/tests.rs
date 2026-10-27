use super::*;
use crate::sync::central::{
    crypto::DeviceKeys,
    migration::Source,
    migration_history::{
        self,
        tests::{context, initial, library},
    },
    migration_progress::Progress,
    payload::{Catalog, Data, Identity},
};
fn fixture(large: bool) -> (Plan, VaultKeys, DeviceKeys, Known) {
    let (before, keys, signer) = initial();
    let mut expected = context();
    expected.sources = vec![Source {
        chain_id: "1".repeat(64),
        sequence: "0".into(),
        count: "0".into(),
        ciphertext_digest: "9".repeat(64),
    }];
    let mut history = library();
    if large {
        history.extend((0..70).map(|_| {
            (
                Identity {
                    kind: "meta".into(),
                    id: "catalog".into(),
                    scope: None,
                },
                Data::Catalog(Catalog {
                    tunnels: vec![],
                    transports: vec![],
                    collections: vec![],
                    group_orders: vec![],
                }),
            )
        }));
    }
    let plan = migration_history::prepare(&before, &keys, &signer, expected, &history).unwrap();
    let body = serde_json::json!({"manifest":plan.manifest,"manifest_digest":plan.manifest.digest().unwrap(),"phase":"retired","staged":plan.rows.len().to_string(),"history_hash":plan.manifest.body.target_history_hash,"retired":"1"});
    let retired = serde_json::from_value::<Progress>(body)
        .unwrap()
        .verify(&plan, None)
        .unwrap();
    (plan, keys, signer, retired)
}
fn page(plan: &Plan, rows: Vec<Version>) -> Page {
    Page {
        records: rows,
        sequence: plan.rows.len().to_string(),
        history_hash: plan.manifest.body.target_history_hash.clone(),
        membership_head: plan
            .before()
            .control
            .highwater
            .as_ref()
            .unwrap()
            .head
            .clone(),
        epoch: 1,
        phase: "ready".into(),
    }
}
#[test]
fn full_actual_ciphertext_readback_returns_a_complete_native_candidate_without_setting_cutover() {
    let (plan, keys, _, retired) = fixture(true);
    let before = plan.before().clone();
    let mut verifier = Verifier::new(&plan, &retired).unwrap();
    for rows in plan.rows.chunks(32) {
        verifier
            .admit(&plan, &keys, page(&plan, rows.to_vec()))
            .unwrap();
    }
    let verified = verifier.finish(&plan, &keys).unwrap();
    assert_eq!(verified.manifest(), plan.manifest.digest().unwrap());
    assert_eq!(
        verified
            .workspace()
            .replica
            .as_ref()
            .unwrap()
            .checkpoint
            .sequence,
        plan.rows.len() as u64
    );
    assert!(!verified.workspace().control.cutover);
    assert!(plan.before() == &before);
}
#[test]
fn protected_prefix_metadata_reconstructs_only_the_exact_previously_verified_plan_prefix() {
    let (plan, keys, _, retired) = fixture(false);
    let mut verifier = Verifier::new(&plan, &retired).unwrap();
    verifier
        .admit(&plan, &keys, page(&plan, plan.rows[..2].to_vec()))
        .unwrap();
    let prefix = verifier.snapshot(&plan).unwrap();
    drop(verifier);
    let saved = serde_json::from_slice::<Prefix>(&serde_json::to_vec(&prefix).unwrap()).unwrap();
    let mut resumed = Verifier::resume(&plan, &retired, &keys, &saved).unwrap();
    assert_eq!(resumed.sequence(), 2);
    resumed
        .admit(&plan, &keys, page(&plan, plan.rows[2..].to_vec()))
        .unwrap();
    resumed.finish(&plan, &keys).unwrap();
    for case in ["version", "manifest", "sequence", "hash"] {
        let mut value = prefix.clone();
        match case {
            "version" => value.version = 2,
            "manifest" => value.manifest = "0".repeat(64),
            "sequence" => value.sequence = 999,
            _ => value.history_hash = "0".repeat(64),
        }
        assert!(
            Verifier::resume(&plan, &retired, &keys, &value).is_err(),
            "{case}"
        );
    }
}
#[test]
fn modified_missing_duplicated_reordered_or_wrong_target_pages_do_not_advance_any_local_checkpoint()
{
    let (plan, keys, _, retired) = fixture(false);
    for case in [
        "sequence",
        "hash",
        "head",
        "epoch",
        "phase",
        "ciphertext",
        "missing",
        "duplicate",
        "reordered",
        "empty",
        "oversize",
    ] {
        let mut value = page(&plan, plan.rows.clone());
        match case {
            "sequence" => value.sequence = (plan.rows.len() - 1).to_string(),
            "hash" => value.history_hash = "0".repeat(64),
            "head" => value.membership_head = "0".repeat(64),
            "epoch" => value.epoch = 2,
            "phase" => value.phase = "rekey_pending".into(),
            "ciphertext" => value.records[2].envelope.ciphertext = "AAAA".into(),
            "missing" => {
                value.records.remove(2);
            }
            "duplicate" => value.records[2] = value.records[1].clone(),
            "reordered" => value.records.swap(1, 2),
            "empty" => value.records.clear(),
            _ => value.records = vec![plan.rows[0].clone(); 33],
        }
        let mut verifier = Verifier::new(&plan, &retired).unwrap();
        assert!(verifier.admit(&plan, &keys, value).is_err(), "{case}");
        assert_eq!(verifier.sequence(), 0, "{case}");
    }
}
#[test]
fn an_incomplete_tail_wrong_keys_or_nonretired_status_never_produces_a_committed_candidate() {
    let (plan, keys, _, retired) = fixture(false);
    let mut verifier = Verifier::new(&plan, &retired).unwrap();
    verifier
        .admit(
            &plan,
            &keys,
            page(&plan, plan.rows[..plan.rows.len() - 1].to_vec()),
        )
        .unwrap();
    assert!(verifier.finish(&plan, &keys).is_err());
    let mut verifier = Verifier::new(&plan, &retired).unwrap();
    assert!(verifier
        .admit(
            &plan,
            &VaultKeys::generate().unwrap(),
            page(&plan, plan.rows.clone())
        )
        .is_err());
    assert_eq!(verifier.sequence(), 0);
    let body = serde_json::json!({"manifest":plan.manifest,"manifest_digest":plan.manifest.digest().unwrap(),"phase":"committed","staged":plan.rows.len().to_string(),"history_hash":plan.manifest.body.target_history_hash,"retired":"0"});
    let committed = serde_json::from_value::<Progress>(body)
        .unwrap()
        .verify(&plan, None)
        .unwrap();
    assert!(Verifier::new(&plan, &committed).is_err());
}
