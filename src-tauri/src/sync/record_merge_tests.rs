use super::*;
use crate::sync::crypto;
use crate::sync::record::{record_key, Envelope, LocalRecord, RecordKind, ACCOUNT_META_ID};
use crate::sync::state_v2::{sealed_key, SealedRecord};
use serde_json::{json, Value};

const HOST: &str = "0000000000000001";
const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn record(kind: RecordKind, id: &str, payload: Value, at: u64) -> Record {
    Record {
        kind,
        id: id.into(),
        version: 1,
        updated_at_ms: at,
        device_id: "d".repeat(32),
        deleted: false,
        payload,
    }
}
fn host(alias: &str, at: u64) -> Record {
    record(
        RecordKind::Host,
        HOST,
        json!({"schema":2,"alias":alias,"hostname":"web.example","auth":"password"}),
        at,
    )
}
fn meta(schema: u32, at: u64) -> Record {
    record(
        RecordKind::Meta,
        ACCOUNT_META_ID,
        json!({"schema_version":schema,"created_by_app_version":"test"}),
        at,
    )
}
fn marker(phase: &str, at: u64) -> Record {
    let mut value = meta(3, at);
    value.payload["migration"] =
        json!({"id":"e".repeat(32),"source_digest":"f".repeat(64),"phase":phase});
    value
}
fn envelope(keys: &ChainKeys, value: &Record, seq: u64) -> Envelope {
    let sealed = crypto::seal(
        keys,
        value.kind.as_str(),
        &value.id,
        &serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
    Envelope {
        id_hash: sealed.id_hash,
        kind: value.kind.as_str().into(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        deleted: value.deleted,
        seq,
    }
}
fn pull(records: Vec<Envelope>, latest_seq: u64) -> PullResponse {
    PullResponse {
        records,
        latest_seq,
    }
}
fn account(keys: &ChainKeys) -> AccountState {
    let mut section = AccountState::new(&keys.chain_id);
    section.baseline_established = true;
    section.cursor_seq = 1;
    section.remote_schema_version = Some(3);
    let value = meta(3, 1);
    section.records.insert(
        record_key(value.kind, &value.id),
        LocalRecord {
            record: value,
            seq: 1,
            dirty: false,
        },
    );
    section
}
fn space() -> SpaceStateV3 {
    SpaceStateV3 {
        selected: true,
        ..SpaceStateV3::default()
    }
}
fn keyslot(at: u64) -> Record {
    record(
        RecordKind::KeySlot,
        KEY,
        json!({"schema":2,"name":"key","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5M9xdffT0p33BD1LiLFTiEvrjv4IZMFADC81ex4ndf","fingerprint":"SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew","key_type":"ssh-ed25519","has_passphrase":false,"created_at_ms":1,"origin_device_id":"d".repeat(32)}),
        at,
    )
}

#[test]
fn typed_hosts_merge_without_files_and_establish_a_valid_baseline() {
    let keys = ChainKeys::generate().unwrap();
    let value = host("web", 2);
    let out = merge_space(
        &space(),
        &keys,
        &pull(vec![envelope(&keys, &value, 1)], 1),
        0,
        &AccountGate::Compatible,
    );
    assert_eq!(
        out.section.records[&record_key(value.kind, HOST)].record,
        value
    );
    assert!(out.section.baseline_established);
    assert_eq!(out.section.cursor_seq, 1);
}
#[test]
fn typed_keyslot_public_metadata_is_accepted_and_legacy_own_stays_opaque() {
    let keys = ChainKeys::generate().unwrap();
    let old = record(
        RecordKind::KeySlot,
        &"b".repeat(32),
        json!({"schema":1,"mode":"own","name":"old"}),
        2,
    );
    let good = keyslot(3);
    let old_env = envelope(&keys, &old, 2);
    let out = merge_account(
        &account(&keys),
        &keys,
        &pull(vec![old_env.clone(), envelope(&keys, &good, 3)], 3),
        1,
    );
    assert_eq!(
        out.section.records[&record_key(RecordKind::KeySlot, KEY)].record,
        good
    );
    assert!(!out
        .section
        .records
        .contains_key(&record_key(old.kind, &old.id)));
    assert_eq!(
        out.section.sealed[&sealed_key(&old_env.kind, &old_env.id_hash)].envelope,
        old_env
    );
    assert_eq!(out.skipped, 1);
}
#[test]
fn a_future_account_schema_preflights_every_record_and_preserves_the_exact_section() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = account(&keys);
    before.records.get_mut("meta:account").unwrap().dirty = true;
    let secret = envelope(
        &keys,
        &record(
            RecordKind::Key,
            KEY,
            json!({"schema":1,"private_key":"test-secret"}),
            2,
        ),
        0,
    );
    before.sealed.insert(
        sealed_key(&secret.kind, &secret.id_hash),
        SealedRecord {
            envelope: secret,
            dirty: true,
        },
    );
    let out = merge_account(
        &before,
        &keys,
        &pull(
            vec![
                envelope(&keys, &keyslot(3), 2),
                envelope(&keys, &meta(4, 0), 3),
            ],
            3,
        ),
        1,
    );
    assert_eq!(out.gate, AccountGate::NeedsUpdate { schema: 4 });
    assert_eq!(out.section, before);
}
#[test]
fn pending_migration_is_read_only_and_active_or_fresh_metadata_is_compatible() {
    let keys = ChainKeys::generate().unwrap();
    let before = account(&keys);
    for phase in ["account-gated", "publishing"] {
        let out = merge_account(
            &before,
            &keys,
            &pull(vec![envelope(&keys, &marker(phase, 3), 2)], 2),
            1,
        );
        assert!(matches!(out.gate, AccountGate::MigrationPending(_)));
        assert_eq!(out.section, before);
    }
    for value in [marker("active", 3), meta(3, 3)] {
        let out = merge_account(
            &before,
            &keys,
            &pull(vec![envelope(&keys, &value, 2)], 2),
            1,
        );
        assert_eq!(out.gate, AccountGate::Compatible);
        assert_eq!(out.section.cursor_seq, 2);
    }
}
#[test]
fn malformed_migration_fields_and_phases_fail_closed() {
    let keys = ChainKeys::generate().unwrap();
    let before = account(&keys);
    for field in ["id", "source_digest", "phase"] {
        let mut bad = marker("active", 3);
        bad.payload["migration"][field] = json!("invalid");
        let out = merge_account(&before, &keys, &pull(vec![envelope(&keys, &bad, 2)], 2), 1);
        assert_eq!(out.gate, AccountGate::InvalidMigration);
        assert_eq!(out.section, before);
    }
}
#[test]
fn winning_active_meta_ignores_an_older_publishing_marker_but_future_schema_is_conservative() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = account(&keys);
    before.records.get_mut("meta:account").unwrap().record = marker("active", 20);
    let out = merge_account(
        &before,
        &keys,
        &pull(vec![envelope(&keys, &marker("publishing", 10), 2)], 2),
        1,
    );
    assert_eq!(out.gate, AccountGate::Compatible);
    let out = merge_account(
        &before,
        &keys,
        &pull(vec![envelope(&keys, &meta(4, 0), 2)], 2),
        1,
    );
    assert_eq!(out.gate, AccountGate::NeedsUpdate { schema: 4 });
    assert_eq!(out.section, before);
}
#[test]
fn old_schema_accounts_require_explicit_migration_and_never_publish_a_new_gate() {
    let keys = ChainKeys::generate().unwrap();
    let before = AccountState::new(&keys.chain_id);
    let out = merge_account(
        &before,
        &keys,
        &pull(vec![envelope(&keys, &meta(2, 1), 1)], 1),
        0,
    );
    assert_eq!(out.gate, AccountGate::NeedsMigration { schema: 2 });
    assert_eq!(out.section, before);
}
#[test]
fn self_dangling_and_alias_conflicting_hosts_are_preserved_for_review() {
    let keys = ChainKeys::generate().unwrap();
    for jumps in [vec![HOST], vec!["ffffffffffffffff"]] {
        let mut value = host("web", 2);
        value.payload["jump"] = json!(jumps);
        let out = merge_space(
            &space(),
            &keys,
            &pull(vec![envelope(&keys, &value, 1)], 1),
            0,
            &AccountGate::Compatible,
        );
        assert_eq!(out.section.records.len(), 1);
        assert!(out.review_required);
    }
    let one = host("web", 2);
    let mut two = host("web", 3);
    two.id = "0000000000000002".into();
    let out = merge_space(
        &space(),
        &keys,
        &pull(vec![envelope(&keys, &one, 1), envelope(&keys, &two, 2)], 2),
        0,
        &AccountGate::Compatible,
    );
    assert_eq!(out.section.records.len(), 2);
    assert!(out.review_required);
}
#[test]
fn lww_uses_device_order_tombstones_and_keeps_dirty_local_winners() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = space();
    before.baseline_established = true;
    let mine = host("mine", 10);
    before.records.insert(
        "host:0000000000000001".into(),
        LocalRecord {
            record: mine.clone(),
            seq: 0,
            dirty: true,
        },
    );
    let mut remote = host("remote", 10);
    remote.device_id = "a".repeat(32);
    let out = merge_space(
        &before,
        &keys,
        &pull(vec![envelope(&keys, &remote, 1)], 1),
        0,
        &AccountGate::Compatible,
    );
    assert_eq!(out.section.records["host:0000000000000001"].record, remote);
    assert_eq!(out.conflicts.len(), 1);
    let mut dead = mine.clone();
    dead.deleted = true;
    dead.payload = Value::Null;
    dead.device_id = "z".repeat(32);
    let out = merge_space(
        &before,
        &keys,
        &pull(vec![envelope(&keys, &dead, 1)], 1),
        0,
        &AccountGate::Compatible,
    );
    assert!(out.section.records["host:0000000000000001"].record.deleted);
    let out = merge_space(
        &before,
        &keys,
        &pull(vec![envelope(&keys, &host("older", 9), 1)], 1),
        0,
        &AccountGate::Compatible,
    );
    assert_eq!(out.section.records["host:0000000000000001"].record, mine);
    assert!(out.section.records["host:0000000000000001"].dirty);
}
#[test]
fn opaque_alias_unknown_schema_unknown_kind_and_bad_ciphertext_survive() {
    let keys = ChainKeys::generate().unwrap();
    let old = record(
        RecordKind::Host,
        "old-alias",
        json!({"schema":1,"text":"Host old-alias"}),
        2,
    );
    let mut newer = host("future", 3);
    newer.id = "0000000000000002".into();
    newer.payload["schema"] = json!(9);
    let mut unknown_record = host("unknown", 4);
    unknown_record.id = "0000000000000003".into();
    let mut unknown = envelope(&keys, &unknown_record, 3);
    unknown.kind = "future-kind".into();
    let mut bad_record = host("bad", 5);
    bad_record.id = "0000000000000004".into();
    let mut bad = envelope(&keys, &bad_record, 4);
    bad.ciphertext = "invalid".into();
    let rows = vec![
        envelope(&keys, &old, 1),
        envelope(&keys, &newer, 2),
        unknown,
        bad,
    ];
    let out = merge_space(
        &space(),
        &keys,
        &pull(rows.clone(), 4),
        0,
        &AccountGate::Compatible,
    );
    assert!(out.section.records.is_empty());
    assert_eq!(out.skipped, 4);
    for env in rows {
        assert_eq!(
            out.section.sealed[&sealed_key(&env.kind, &env.id_hash)].envelope,
            env
        );
    }
}
#[test]
fn unauthenticated_deleted_flags_cannot_delete_typed_material() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = space();
    before.baseline_established = true;
    let good = host("web", 2);
    before.records.insert(
        "host:0000000000000001".into(),
        LocalRecord {
            record: good.clone(),
            seq: 0,
            dirty: false,
        },
    );
    let mut bad = envelope(&keys, &host("remote", 3), 1);
    bad.deleted = true;
    let out = merge_space(
        &before,
        &keys,
        &pull(vec![bad], 1),
        0,
        &AccountGate::Compatible,
    );
    assert_eq!(out.section.records["host:0000000000000001"].record, good);
    assert_eq!(out.skipped, 1);
}
#[test]
fn invalid_since_watermarks_and_duplicate_rows_do_not_advance_any_state() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = space();
    before.baseline_established = true;
    before.cursor_seq = 5;
    for response in [
        pull(vec![], 4),
        pull(vec![], 9_007_199_254_740_992),
        pull(vec![envelope(&keys, &host("web", 1), 7)], 6),
        pull(
            vec![
                envelope(&keys, &host("web", 1), 6),
                envelope(&keys, &host("web", 2), 6),
            ],
            6,
        ),
    ] {
        let out = merge_space(&before, &keys, &response, 5, &AccountGate::Compatible);
        assert_eq!(out.gate, AccountGate::InvalidPull);
        assert_eq!(out.section, before);
    }
    let out = merge_space(
        &space(),
        &keys,
        &pull(vec![], 10),
        5,
        &AccountGate::Compatible,
    );
    assert_eq!(out.gate, AccountGate::InvalidPull);
}
#[test]
fn secret_payloads_stay_sealed_and_lww_is_transient() {
    let keys = ChainKeys::generate().unwrap();
    let before = account(&keys);
    let value = record(
        RecordKind::Key,
        KEY,
        json!({"schema":1,"private_key":"unique-test-private-secret"}),
        2,
    );
    let env = envelope(&keys, &value, 2);
    let out = merge_account(&before, &keys, &pull(vec![env.clone()], 2), 1);
    assert_eq!(
        out.section.sealed[&sealed_key(&env.kind, &env.id_hash)].envelope,
        env
    );
    assert!(!serde_json::to_string(&out.section)
        .unwrap()
        .contains("unique-test-private-secret"));
    assert!(!format!("{out:?}").contains("unique-test-private-secret"));
    assert!(!out
        .section
        .records
        .contains_key(&record_key(value.kind, &value.id)));
}
#[test]
fn outgoing_requires_supported_account_gate_and_established_baselines() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = account(&keys);
    before.baseline_established = false;
    assert!(account_outgoing(&before, &keys).is_err());
    assert!(space_outgoing(&space(), &keys, &AccountGate::Compatible).is_err());
    let mut ready = space();
    ready.baseline_established = true;
    assert!(space_outgoing(&ready, &keys, &AccountGate::NeedsUpdate { schema: 4 }).is_err());
}
#[test]
fn partial_public_receipts_require_exact_revision_device_and_body_and_keep_cursor() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = space();
    before.baseline_established = true;
    before.records.insert(
        "host:0000000000000001".into(),
        LocalRecord {
            record: host("web", 1),
            seq: 0,
            dirty: true,
        },
    );
    let outgoing = space_outgoing(&before, &keys, &AccountGate::Compatible).unwrap();
    assert_eq!(outgoing.len(), 1);
    let pushed = Pushed {
        accepted: vec![("host:0000000000000001".into(), 5)],
        frozen: true,
        error: Some(crate::sync::relay::RelayError::RateLimited),
        ..Pushed::default()
    };
    let accepted = apply_space_receipts(&before, &outgoing, &pushed);
    assert!(!accepted.records["host:0000000000000001"].dirty);
    assert_eq!(accepted.cursor_seq, before.cursor_seq);
    for change in ["device", "body", "deleted", "version"] {
        let mut changed = before.clone();
        let row = changed.records.get_mut("host:0000000000000001").unwrap();
        match change {
            "device" => row.record.device_id = "a".repeat(32),
            "body" => row.record.payload["notes"] = json!("changed"),
            "deleted" => row.record.deleted = true,
            _ => row.record.version += 1,
        }
        assert_eq!(
            apply_space_receipts(&changed, &outgoing, &pushed),
            changed,
            "{change}"
        );
    }
}
#[test]
fn secret_ciphertext_receipts_do_not_clear_changed_material() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = account(&keys);
    let value = record(
        RecordKind::Key,
        KEY,
        json!({"schema":1,"private_key":"test-secret"}),
        2,
    );
    let env = envelope(&keys, &value, 0);
    let id = sealed_key(&env.kind, &env.id_hash);
    before.sealed.insert(
        id.clone(),
        SealedRecord {
            envelope: env.clone(),
            dirty: true,
        },
    );
    let outgoing = account_outgoing(&before, &keys).unwrap();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].outgoing.item.ciphertext, env.ciphertext);
    let pushed = Pushed {
        accepted: vec![(id.clone(), 6)],
        ..Pushed::default()
    };
    let accepted = apply_account_receipts(&before, &outgoing, &pushed);
    assert!(!accepted.sealed[&id].dirty);
    for field in ["nonce", "ciphertext", "deleted"] {
        let mut changed = before.clone();
        let env = &mut changed.sealed.get_mut(&id).unwrap().envelope;
        match field {
            "nonce" => env.nonce.push('x'),
            "ciphertext" => env.ciphertext.push('x'),
            _ => env.deleted = true,
        }
        assert_eq!(
            apply_account_receipts(&changed, &outgoing, &pushed),
            changed
        );
    }
}
#[test]
fn local_encode_uses_same_authenticated_wire_contract() {
    let keys = ChainKeys::generate().unwrap();
    let value = host("web", 3);
    let wire = encode_record(&keys, &value, 9).unwrap();
    assert_eq!(wire.base_seq, 9);
    assert_eq!(wire.id_hash, crypto::id_hash(&keys, "host", HOST));
    let opened = crypto::open(
        &keys,
        "host",
        &wire.id_hash,
        &crypto::Sealed {
            id_hash: wire.id_hash.clone(),
            nonce: wire.nonce,
            ciphertext: wire.ciphertext,
        },
    )
    .unwrap();
    assert_eq!(serde_json::from_slice::<Record>(&opened).unwrap(), value);
}

#[test]
fn older_typed_rows_cannot_discard_a_newer_opaque_revision() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = space();
    before.baseline_established = true;
    before.cursor_seq = 2;
    let good = host("known", 1);
    before.records.insert(
        record_key(good.kind, HOST),
        LocalRecord {
            record: good.clone(),
            seq: 1,
            dirty: false,
        },
    );
    let mut future = host("future", 10);
    future.payload["schema"] = json!(9);
    let opaque = envelope(&keys, &future, 2);
    before.sealed.insert(
        sealed_key(&opaque.kind, &opaque.id_hash),
        SealedRecord {
            envelope: opaque,
            dirty: false,
        },
    );
    let mut stale = host("older", 5);
    stale.deleted = true;
    stale.payload = Value::Null;
    let out = merge_space(
        &before,
        &keys,
        &pull(vec![envelope(&keys, &stale, 3)], 3),
        2,
        &AccountGate::Compatible,
    );
    assert_eq!(
        out.section, before,
        "unrecognized newer material must remain recoverable"
    );
    assert_eq!(out.gate, AccountGate::InvalidPull);
}
#[test]
fn secret_lww_keeps_newer_dirty_material_and_clears_only_a_remote_winner() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = account(&keys);
    let mine = record(
        RecordKind::Key,
        KEY,
        json!({"schema":1,"private_key":"new-test-secret"}),
        10,
    );
    let env = envelope(&keys, &mine, 1);
    let id = sealed_key(&env.kind, &env.id_hash);
    before.sealed.insert(
        id.clone(),
        SealedRecord {
            envelope: env.clone(),
            dirty: true,
        },
    );
    let old = record(
        RecordKind::Key,
        KEY,
        json!({"schema":1,"private_key":"old-test-secret"}),
        9,
    );
    let kept = merge_account(&before, &keys, &pull(vec![envelope(&keys, &old, 2)], 2), 1);
    assert_eq!(kept.section.sealed[&id].envelope.ciphertext, env.ciphertext);
    assert!(kept.section.sealed[&id].dirty);
    assert_eq!(kept.section.sealed[&id].envelope.seq, 2);
    let mut remote = mine.clone();
    remote.device_id = "a".repeat(32);
    let remote = envelope(&keys, &remote, 2);
    let won = merge_account(&before, &keys, &pull(vec![remote.clone()], 2), 1);
    assert_eq!(won.section.sealed[&id].envelope, remote);
    assert!(!won.section.sealed[&id].dirty);
    assert_eq!(won.conflicts, vec![id]);
    for section in [&kept.section, &won.section] {
        let disk = serde_json::to_string(section).unwrap();
        assert!(!disk.contains("new-test-secret") && !disk.contains("old-test-secret"));
    }
}
#[test]
fn malformed_secret_collision_preserves_dirty_ciphertext_and_cursor() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = account(&keys);
    let mine = record(
        RecordKind::Key,
        KEY,
        json!({"schema":1,"private_key":"retained-test-secret"}),
        10,
    );
    let env = envelope(&keys, &mine, 1);
    before.sealed.insert(
        sealed_key(&env.kind, &env.id_hash),
        SealedRecord {
            envelope: env,
            dirty: true,
        },
    );
    let mut malformed = mine;
    malformed.payload["private_key"] = json!(0);
    let out = merge_account(
        &before,
        &keys,
        &pull(vec![envelope(&keys, &malformed, 2)], 2),
        1,
    );
    assert_eq!(out.section, before);
    assert_eq!(out.gate, AccountGate::InvalidPull);
    assert!(!format!("{out:?}").contains("retained-test-secret"));
}
#[test]
fn known_device_and_space_metadata_remain_public_but_secret_space_keys_stay_sealed() {
    let keys = ChainKeys::generate().unwrap();
    let before = account(&keys);
    let child = ChainKeys::generate().unwrap();
    let device = record(
        RecordKind::Device,
        &"a".repeat(32),
        json!({"schema":1,"name":"test","platform":"test","joined_at_ms":1,"last_seen_ms":2,"spaces":[child.chain_id.clone()]}),
        2,
    );
    let space = record(
        RecordKind::Space,
        &child.chain_id,
        json!({"schema":1,"name":"test","slug":"test","created_at_ms":1}),
        2,
    );
    let secret = record(
        RecordKind::SpaceKey,
        &child.chain_id,
        json!({"schema":1,"auth_token":child.auth_token,"enc_key":child.enc_key_b64()}),
        2,
    );
    let out = merge_account(
        &before,
        &keys,
        &pull(
            vec![
                envelope(&keys, &device, 2),
                envelope(&keys, &space, 3),
                envelope(&keys, &secret, 4),
            ],
            4,
        ),
        1,
    );
    assert!(out
        .section
        .records
        .contains_key(&record_key(device.kind, &device.id)));
    assert!(out
        .section
        .records
        .contains_key(&record_key(space.kind, &space.id)));
    assert!(!out
        .section
        .records
        .contains_key(&record_key(secret.kind, &secret.id)));
    let disk = serde_json::to_string(&out.section).unwrap();
    assert!(!disk.contains(secret.payload["auth_token"].as_str().unwrap()));
}
#[test]
fn schema_one_keyslot_tombstones_and_malformed_typed_rows_remain_opaque() {
    let keys = ChainKeys::generate().unwrap();
    let mut before = account(&keys);
    let good = keyslot(1);
    before.records.insert(
        record_key(good.kind, &good.id),
        LocalRecord {
            record: good.clone(),
            seq: 1,
            dirty: false,
        },
    );
    let mut old = record(
        RecordKind::KeySlot,
        KEY,
        json!({"schema":1,"mode":"own"}),
        20,
    );
    old.deleted = true;
    let env = envelope(&keys, &old, 2);
    let out = merge_account(&before, &keys, &pull(vec![env.clone()], 2), 1);
    assert_eq!(
        out.section.records[&record_key(good.kind, &good.id)].record,
        good
    );
    assert_eq!(out.skipped, 1);
    assert_eq!(
        out.section.sealed[&sealed_key(&env.kind, &env.id_hash)].envelope,
        env
    );
    assert!(account_outgoing(&out.section, &keys).unwrap().is_empty());
}

#[test]
fn owned_secret_sealing_and_reading_never_put_private_text_in_public_state() {
    let keys = ChainKeys::generate().unwrap();
    let mut state = account(&keys);
    let metadata = keyslot(1);
    state.records.insert(
        record_key(metadata.kind, &metadata.id),
        LocalRecord {
            record: metadata,
            seq: 1,
            dirty: false,
        },
    );
    let secret = record(
        RecordKind::Key,
        KEY,
        json!({"schema":1,"private_key":"owned-test-private"}),
        2,
    );
    let sealed = seal_secret_record(&keys, secret, 1).unwrap();
    let id = sealed_key(&sealed.envelope.kind, &sealed.envelope.id_hash);
    state.sealed.insert(id, sealed);
    assert_eq!(
        key_secret(&state, &keys, KEY).unwrap().unwrap().as_str(),
        "owned-test-private"
    );
    assert!(!serde_json::to_string(&state)
        .unwrap()
        .contains("owned-test-private"));
    state
        .records
        .get_mut(&record_key(RecordKind::KeySlot, KEY))
        .unwrap()
        .record
        .deleted = true;
    assert!(key_secret(&state, &keys, KEY).unwrap().is_none());
}
#[test]
fn space_credentials_read_from_sealed_transport_require_live_public_metadata() {
    let keys = ChainKeys::generate().unwrap();
    let child = ChainKeys::generate().unwrap();
    let mut state = account(&keys);
    let metadata = record(
        RecordKind::Space,
        &child.chain_id,
        json!({"schema":1,"name":"child","slug":"child","created_at_ms":1}),
        2,
    );
    state.records.insert(
        record_key(metadata.kind, &metadata.id),
        LocalRecord {
            record: metadata,
            seq: 1,
            dirty: false,
        },
    );
    let sealed = seal_secret_record(
        &keys,
        record(
            RecordKind::SpaceKey,
            &child.chain_id,
            json!({"schema":1,"auth_token":child.auth_token,"enc_key":child.enc_key_b64()}),
            2,
        ),
        1,
    )
    .unwrap();
    state.sealed.insert(
        sealed_key(&sealed.envelope.kind, &sealed.envelope.id_hash),
        sealed,
    );
    let found = space_keys(&state, &keys, &child.chain_id).unwrap().unwrap();
    assert_eq!(found.chain_id, child.chain_id);
    assert!(found.auth_token == child.auth_token);
    assert!(found.enc_key_b64() == child.enc_key_b64());
    state
        .records
        .get_mut(&record_key(RecordKind::Space, &child.chain_id))
        .unwrap()
        .record
        .deleted = true;
    assert!(space_keys(&state, &keys, &child.chain_id)
        .unwrap()
        .is_none());
    assert!(space_keys(&state, &ChainKeys::generate().unwrap(), &child.chain_id).is_err());
}

#[test]
fn unknown_outer_record_fields_are_retained_opaque_without_accepting_partial_semantics() {
    let keys = ChainKeys::generate().unwrap();
    let value = host("web", 2);
    let mut body = serde_json::to_value(&value).unwrap();
    body["future_permission"] = json!("unknown");
    let encoded = crypto::seal(&keys, "host", HOST, &serde_json::to_vec(&body).unwrap()).unwrap();
    let env = Envelope {
        id_hash: encoded.id_hash,
        kind: "host".into(),
        seq: 1,
        nonce: encoded.nonce,
        ciphertext: encoded.ciphertext,
        deleted: false,
    };
    let out = merge_space(
        &space(),
        &keys,
        &pull(vec![env.clone()], 1),
        0,
        &AccountGate::Compatible,
    );
    assert!(out.section.records.is_empty());
    assert_eq!(out.skipped, 1);
    assert_eq!(
        out.section.sealed[&sealed_key(&env.kind, &env.id_hash)].envelope,
        env
    );
}

#[test]
fn opaque_supported_headers_follow_lww_instead_of_relay_arrival_order() {
    let keys = ChainKeys::generate().unwrap();
    let mut newer = host("future", 20);
    newer.payload["schema"] = json!(99);
    let mut older = newer.clone();
    older.updated_at_ms = 10;
    let newer_env = envelope(&keys, &newer, 1);
    let mut state = space();
    state.baseline_established = true;
    state.cursor_seq = 1;
    let key = sealed_key(&newer_env.kind, &newer_env.id_hash);
    state.sealed.insert(
        key.clone(),
        SealedRecord {
            envelope: newer_env.clone(),
            dirty: false,
        },
    );
    let out = merge_space(
        &state,
        &keys,
        &pull(vec![envelope(&keys, &older, 2)], 2),
        1,
        &AccountGate::Compatible,
    );
    assert!(out.section.records.is_empty());
    assert_eq!(
        out.section.sealed[&key].envelope.ciphertext,
        newer_env.ciphertext
    );
    assert_eq!(out.section.sealed[&key].envelope.seq, 2);
    assert_eq!(out.section.cursor_seq, 2);
}

#[test]
fn receipt_sequence_outside_relay_safe_integer_does_not_poison_local_state() {
    let keys = ChainKeys::generate().unwrap();
    let mut state = account(&keys);
    state
        .records
        .get_mut(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
        .unwrap()
        .dirty = true;
    let sent = account_outgoing(&state, &keys).unwrap();
    let pushed = Pushed {
        accepted: vec![(sent[0].outgoing.key.clone(), 9_007_199_254_740_992)],
        ..Pushed::default()
    };
    assert_eq!(apply_account_receipts(&state, &sent, &pushed), state);
}

#[test]
fn secret_revision_returns_live_and_tombstone_headers_without_plaintext_payloads() {
    let keys = ChainKeys::generate().unwrap();
    let mut state = account(&keys);
    let mut secret = record(
        RecordKind::Key,
        KEY,
        json!({"schema":1,"private_key":"HEADER_SECRET_SENTINEL"}),
        4_000_000_000_000,
    );
    secret.version = 7;
    let env = envelope(&keys, &secret, 2);
    let key = sealed_key(&env.kind, &env.id_hash);
    state.sealed.insert(
        key.clone(),
        SealedRecord {
            envelope: env,
            dirty: false,
        },
    );
    let revision = secret_revision(&state, &keys, RecordKind::Key, KEY)
        .unwrap()
        .unwrap();
    assert_eq!(revision.version, 7);
    assert_eq!(revision.updated_at_ms, 4_000_000_000_000);
    assert!(!revision.deleted);
    assert!(!format!("{revision:?}").contains("HEADER_SECRET_SENTINEL"));
    secret.deleted = true;
    secret.payload = Value::Null;
    secret.version = 8;
    state.sealed.get_mut(&key).unwrap().envelope = envelope(&keys, &secret, 3);
    assert!(
        secret_revision(&state, &keys, RecordKind::Key, KEY)
            .unwrap()
            .unwrap()
            .deleted
    );
    assert!(secret_revision(
        &state,
        &ChainKeys::generate().unwrap(),
        RecordKind::Key,
        KEY
    )
    .is_err());
}
#[test]
fn authenticated_future_meta_with_new_outer_fields_still_reports_needs_update() {
    let keys = crate::sync::crypto::ChainKeys::generate().unwrap();
    let old = crate::sync::state_v2::AccountState::new(&keys.chain_id);
    let raw = serde_json::json!({"kind":"meta","id":"account","version":1,"updated_at_ms":1,"device_id":"a".repeat(32),"deleted":false,"payload":{"schema_version":4,"created_by_app_version":"future"},"future_header":"new"});
    let seal =
        crate::sync::crypto::seal(&keys, "meta", "account", &serde_json::to_vec(&raw).unwrap())
            .unwrap();
    let pulled = crate::sync::relay::PullResponse {
        latest_seq: 1,
        records: vec![crate::sync::record::Envelope {
            kind: "meta".into(),
            id_hash: seal.id_hash,
            nonce: seal.nonce,
            ciphertext: seal.ciphertext,
            seq: 1,
            deleted: false,
        }],
    };
    let result = merge_account(&old, &keys, &pulled, 0);
    assert_eq!(result.gate, AccountGate::NeedsUpdate { schema: 4 });
    assert_eq!(result.section, old);
    assert_eq!(result.observed_schema, Some(4));
}
#[test]
fn authenticated_future_meta_precedes_an_inconsistent_cursor_without_advancing_it() {
    let keys = crate::sync::crypto::ChainKeys::generate().unwrap();
    let mut old = crate::sync::state_v2::AccountState::new(&keys.chain_id);
    old.cursor_seq = 10;
    old.baseline_established = true;
    let raw = serde_json::json!({"kind":"meta","id":"account","version":1,"updated_at_ms":1,"device_id":"a".repeat(32),"deleted":false,"payload":{"schema_version":4,"created_by_app_version":"future"}});
    let seal =
        crate::sync::crypto::seal(&keys, "meta", "account", &serde_json::to_vec(&raw).unwrap())
            .unwrap();
    let pulled = crate::sync::relay::PullResponse {
        latest_seq: 1,
        records: vec![crate::sync::record::Envelope {
            kind: "meta".into(),
            id_hash: seal.id_hash,
            nonce: seal.nonce,
            ciphertext: seal.ciphertext,
            seq: 1,
            deleted: false,
        }],
    };
    let result = merge_account(&old, &keys, &pulled, 0);
    assert_eq!(result.gate, AccountGate::NeedsUpdate { schema: 4 });
    assert_eq!(result.section, old);
}
