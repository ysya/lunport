use super::*;
use crate::sync::central::{
    migration::Source,
    migration_history::{
        self,
        tests::{context, initial, library},
    },
    payload::{Catalog, Data, Identity},
};
fn plan(sources: bool) -> Plan {
    let (before, keys, signer) = initial();
    let mut context = context();
    if sources {
        context.sources = (1..=2)
            .map(|id| Source {
                chain_id: format!("{id:064x}"),
                sequence: "0".into(),
                count: "0".into(),
                ciphertext_digest: "9".repeat(64),
            })
            .collect();
    }
    migration_history::prepare(&before, &keys, &signer, context, &library()).unwrap()
}
fn status(plan: &Plan, phase: Phase, staged: u64, retired: u64) -> Progress {
    Progress {
        manifest: plan.manifest.clone(),
        manifest_digest: plan.manifest.digest().unwrap(),
        phase,
        staged: staged.to_string(),
        history_hash: if staged == 0 {
            "0".repeat(64)
        } else {
            plan.rows
                .get(staged as usize - 1)
                .map(|r| r.history_hash.clone())
                .unwrap_or_else(|| "0".repeat(64))
        },
        retired: retired.to_string(),
    }
}
#[test]
fn exact_staged_prefix_commit_and_each_retirement_prefix_advance_monotonically() {
    let p = plan(true);
    let end = p.rows.len() as u64;
    let mut known = None;
    for (phase, staged, retired) in [
        (Phase::Staging, 0, 0),
        (Phase::Staging, 2, 0),
        (Phase::Staging, end, 0),
        (Phase::Committed, end, 0),
        (Phase::Committed, end, 1),
        (Phase::Retired, end, 2),
    ] {
        let next = status(&p, phase, staged, retired)
            .verify(&p, known.as_ref())
            .unwrap();
        assert!(next.phase() == phase);
        assert_eq!(next.staged(), staged);
        assert_eq!(next.retired(), retired);
        known = Some(serde_json::from_slice::<Known>(&serde_json::to_vec(&next).unwrap()).unwrap());
    }
    assert!(known.unwrap().next_batch(&p).unwrap().is_none());
}
#[test]
fn a_high_chain_claim_cannot_hide_a_wrong_prefix_hash_or_impossible_phase_counts() {
    let p = plan(true);
    let end = p.rows.len() as u64;
    for (phase, staged, retired) in [
        (Phase::Staging, 1, 1),
        (Phase::Staging, end + 1, 0),
        (Phase::Committed, end - 1, 0),
        (Phase::Committed, end, 2),
        (Phase::Retired, end, 1),
        (Phase::Retired, end, 3),
    ] {
        assert!(status(&p, phase, staged, retired).verify(&p, None).is_err());
    }
    let mut wrong = status(&p, Phase::Staging, 2, 0);
    wrong.history_hash = p.manifest.body.target_history_hash.clone();
    assert!(wrong.verify(&p, None).is_err());
    wrong = status(&p, Phase::Staging, 0, 0);
    wrong.history_hash = p.rows[0].history_hash.clone();
    assert!(wrong.verify(&p, None).is_err());
}
#[test]
fn saved_phase_staged_and_retirement_floors_cannot_rollback_or_move_to_another_plan() {
    let p = plan(true);
    let end = p.rows.len() as u64;
    let minimum = status(&p, Phase::Committed, end, 1)
        .verify(&p, None)
        .unwrap();
    for (phase, staged, retired) in [(Phase::Staging, end, 0), (Phase::Committed, end, 0)] {
        assert!(status(&p, phase, staged, retired)
            .verify(&p, Some(&minimum))
            .is_err());
    }
    let stage_min = status(&p, Phase::Staging, 3, 0).verify(&p, None).unwrap();
    assert!(status(&p, Phase::Staging, 2, 0)
        .verify(&p, Some(&stage_min))
        .is_err());
    let other = plan(true);
    assert!(status(&other, Phase::Staging, 0, 0)
        .verify(&other, Some(&minimum))
        .is_err());
    let mut replaced = status(&p, Phase::Committed, end, 1);
    replaced.manifest = other.manifest;
    assert!(replaced.verify(&p, Some(&minimum)).is_err());
}
#[test]
fn malformed_counters_unknown_wire_fields_and_corrupt_saved_minima_never_mean_an_empty_migration() {
    let p = plan(true);
    let initial = status(&p, Phase::Staging, 0, 0);
    let original = serde_json::json!({"manifest":initial.manifest,"manifest_digest":initial.manifest_digest,"phase":"staging","staged":"0","history_hash":"0".repeat(64),"retired":"0"});
    for bad in ["00", "-1", "1.0", "9007199254740992", " 0"] {
        let mut value = original.clone();
        value["staged"] = bad.into();
        let parsed: Progress = serde_json::from_value(value).unwrap();
        assert!(parsed.verify(&p, None).is_err(), "{bad}");
    }
    let mut extra = original.clone();
    extra["other"] = true.into();
    assert!(serde_json::from_value::<Progress>(extra).is_err());
    assert!(serde_json::from_str::<Progress>("{}").is_err());
    assert!(serde_json::from_str::<Progress>("null").is_err());
    let good: Progress = serde_json::from_value(original).unwrap();
    let floor = good.verify(&p, None).unwrap();
    for case in ["version", "digest", "staged", "retired"] {
        let mut value = serde_json::to_value(&floor).unwrap();
        match case {
            "version" => value["version"] = 2.into(),
            "digest" => value["digest"] = "0".repeat(64).into(),
            "staged" => value["staged"] = 999.into(),
            _ => value["retired"] = 1.into(),
        }
        let minimum: Known = serde_json::from_value(value).unwrap();
        assert!(good.verify(&p, Some(&minimum)).is_err(), "{case}");
    }
}
#[test]
fn resumed_ciphertext_batches_can_start_mid_page_without_changing_any_envelope() {
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
                collections: vec![],
                group_orders: vec![],
            }),
        )
    }));
    let p = migration_history::prepare(&before, &keys, &signer, context(), &history).unwrap();
    let known = status(&p, Phase::Staging, 17, 0).verify(&p, None).unwrap();
    let batch = known.next_batch(&p).unwrap().unwrap();
    assert_eq!(batch.len(), 32);
    assert!(batch == &p.rows[17..49]);
    assert!(
        batch
            .iter()
            .map(|v| serde_json::to_vec(&v.envelope).unwrap().len())
            .sum::<usize>()
            <= 1024 * 1024
    );
    assert!(p.next_batch(p.rows.len() as u64).unwrap().is_none());
    assert!(p.next_batch(p.rows.len() as u64 + 1).is_err());
}
#[test]
fn a_zero_source_migration_can_retire_at_commit_but_still_requires_its_complete_history() {
    let p = plan(false);
    let end = p.rows.len() as u64;
    assert!(status(&p, Phase::Retired, end, 0).verify(&p, None).is_ok());
    assert!(status(&p, Phase::Committed, end, 0)
        .verify(&p, None)
        .is_err());
    assert!(status(&p, Phase::Retired, end - 1, 0)
        .verify(&p, None)
        .is_err());
}
