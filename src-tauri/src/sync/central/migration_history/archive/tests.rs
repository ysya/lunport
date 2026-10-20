use super::*;
use crate::sync::central::migration_history::tests::{context, initial, library};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
#[test]
fn local_round_trip_keeps_exact_operation_ids_ciphertext_wraps_and_page_ranges() {
    let (before, keys, signer) = initial();
    let plan = prepare(&before, &keys, &signer, context(), &library()).unwrap();
    let encoded = plan.encode_local().unwrap();
    assert!(!String::from_utf8_lossy(&encoded).contains("PRIVATE KEY"));
    let restored = Plan::decode_local(&encoded, &before, &keys, &signer, &context()).unwrap();
    assert!(restored.manifest == plan.manifest);
    assert!(restored.rows == plan.rows);
    assert!(restored.wraps == plan.wraps);
    assert_eq!(restored.pages, plan.pages);
    assert!(restored.encode_local().unwrap().as_slice() == encoded.as_slice());
    assert_eq!(before.replica.as_ref().unwrap().checkpoint.sequence, 0);
    assert!(!before.control.cutover);
}
#[test]
fn missing_reordered_or_modified_ciphertext_and_wraps_never_restore_a_partial_plan() {
    let (before, keys, signer) = initial();
    let plan = prepare(&before, &keys, &signer, context(), &library()).unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&plan.encode_local().unwrap()).unwrap();
    for case in [
        "drop",
        "duplicate",
        "reorder",
        "ciphertext",
        "operation",
        "digest",
        "history",
        "revision",
        "wrap-missing",
        "wrap-signature",
        "wrap-recipient",
        "manifest",
        "before",
        "unknown",
        "version",
    ] {
        let mut value = original.clone();
        match case {
            "drop" => {
                value["rows"].as_array_mut().unwrap().remove(2);
            }
            "duplicate" => value["rows"][2] = value["rows"][1].clone(),
            "reorder" => value["rows"].as_array_mut().unwrap().swap(1, 2),
            "ciphertext" => value["rows"][2]["envelope"]["ciphertext"] = "AAAA".into(),
            "operation" => {
                value["rows"][2]["envelope"]["header"]["operation_id"] = "e".repeat(32).into()
            }
            "digest" => value["rows"][2]["digest"] = "0".repeat(64).into(),
            "history" => value["rows"][2]["history_hash"] = "0".repeat(64).into(),
            "revision" => value["rows"][2]["revision"] = "2".into(),
            "wrap-missing" => {
                value["wraps"].as_array_mut().unwrap().pop();
            }
            "wrap-signature" => value["wraps"][0]["signature"] = "AAAA".into(),
            "wrap-recipient" => value["wraps"][0]["header"]["recipient"] = "recovery".into(),
            "manifest" => value["manifest"]["signature"] = "AAAA".into(),
            "before" => value["before"]["identity_slot"] = "7".repeat(32).into(),
            "unknown" => value["other"] = true.into(),
            _ => value["version"] = 2.into(),
        }
        assert!(
            Plan::decode_local(
                &serde_json::to_vec(&value).unwrap(),
                &before,
                &keys,
                &signer,
                &context()
            )
            .is_err(),
            "{case}"
        );
    }
    assert!(Plan::decode_local(
        &vec![b' '; MAX_PLAN_BYTES + 1],
        &before,
        &keys,
        &signer,
        &context()
    )
    .is_err());
}
#[test]
fn exact_caller_context_and_content_signing_keys_are_required() {
    let (before, keys, signer) = initial();
    let plan = prepare(&before, &keys, &signer, context(), &library()).unwrap();
    let bytes = plan.encode_local().unwrap();
    for case in ["operation", "inventory", "sources"] {
        let mut expected = context();
        match case {
            "operation" => expected.operation = "6".repeat(32),
            "inventory" => expected.inventory_digest = "9".repeat(64),
            _ => {
                expected.sources = vec![Source {
                    chain_id: "1".repeat(64),
                    sequence: "0".into(),
                    count: "0".into(),
                    ciphertext_digest: "9".repeat(64),
                }]
            }
        }
        assert!(
            Plan::decode_local(&bytes, &before, &keys, &signer, &expected).is_err(),
            "{case}"
        );
    }
    assert!(Plan::decode_local(
        &bytes,
        &before,
        &VaultKeys::generate().unwrap(),
        &signer,
        &context()
    )
    .is_err());
    let wrong = DeviceKeys::decode_secret(&B64.encode([9u8; 64])).unwrap();
    assert!(Plan::decode_local(&bytes, &before, &keys, &wrong, &context()).is_err());
}
fn rewrite(
    plan: &mut Plan,
    index: usize,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    edit: impl FnOnce(&mut serde_json::Value),
) {
    let row = &mut plan.rows[index];
    let plaintext = row
        .envelope
        .verify(&signer.public().signing)
        .unwrap()
        .open(keys)
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    edit(&mut value);
    row.envelope = crypto::seal_record(
        keys,
        signer,
        row.envelope.header.clone(),
        &serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    let mut history = ZERO.to_string();
    for row in &mut plan.rows {
        row.digest = rekey::envelope_digest(&row.envelope).unwrap();
        history = crypto::hash(
            &canonical(&["lunport-history-v2", &history, &row.sequence, &row.digest]).unwrap(),
        );
        row.history_hash = history.clone();
    }
    let mut body = plan.manifest.body.clone();
    body.target_history_hash = history;
    plan.manifest = SignedMigration::sign(body, signer).unwrap();
}
#[test]
fn even_valid_resigned_history_must_admit_superseded_payloads_and_a_complete_material_projection() {
    for hidden in [true, false] {
        let (before, keys, signer) = initial();
        let mut plan = prepare(&before, &keys, &signer, context(), &library()).unwrap();
        if hidden {
            rewrite(&mut plan, 4, &keys, &signer, |value| {
                value["schema"] = 999.into()
            });
        } else {
            rewrite(&mut plan, 1, &keys, &signer, |value| {
                value["payload"]["storage"]["sha256"] = "0".repeat(64).into()
            });
        }
        plan.manifest
            .verify(
                &before.control.verified_chain().unwrap().current(),
                before.control.auth_epoch,
                1,
                &before.replica.as_ref().unwrap().vault,
                &before.control.device.id,
            )
            .unwrap();
        assert!(Plan::decode_local(
            &plan.encode_local().unwrap(),
            &before,
            &keys,
            &signer,
            &context()
        )
        .is_err());
    }
}
#[test]
fn encrypted_source_cursor_restores_the_same_prepared_plan_after_the_original_plan_is_dropped() {
    use crate::sync::{
        central::{source_archive, source_cursor::Cursor},
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    let (before, keys, signer) = initial();
    let plan = prepare(&before, &keys, &signer, context(), &library()).unwrap();
    let manifest = plan.manifest.clone();
    let rows = plan.rows.clone();
    let plain = plan.encode_local().unwrap();
    let device = TestDevice::new(
        "migration-plan-archive",
        &FakeRelay::new(),
        &TestClock::new(),
    );
    let env = device.env();
    std::fs::create_dir_all(env.state_path.parent().unwrap()).unwrap();
    let life = env.runtime.lifecycle.lock().unwrap();
    let archived = source_archive::create(&env, &life, &before, 0, &plain).unwrap();
    Cursor::initialize(&env, &life, &before, &archived).unwrap();
    drop((plan, plain, archived));
    let saved = Cursor::load(&env, &life, &before).unwrap().unwrap();
    let restored = Plan::decode_local(&saved.bytes, &before, &keys, &signer, &context()).unwrap();
    assert!(restored.manifest == manifest);
    assert!(restored.rows == rows);
    assert!(env.runtime.core.lock().unwrap().records.is_none());
}
