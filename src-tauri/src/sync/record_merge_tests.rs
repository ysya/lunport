use super::*;
use crate::sync::crypto;
use crate::sync::record::{record_key, Envelope, LocalRecord, RecordKind, ACCOUNT_META_ID};
use crate::sync::state_v2::{sealed_key, SealedRecord};
use serde_json::{json, Value};

const HOST: &str = "0000000000000001";
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
fn account(keys: &ChainKeys) -> AccountState {
    let mut section = AccountState::new(&keys.chain_id);
    section.baseline_established = true;
    section.cursor_seq = 1;
    section.remote_schema_version = Some(3);
    let value = record(
        RecordKind::Meta,
        ACCOUNT_META_ID,
        json!({"schema_version":3,"created_by_app_version":"test"}),
        1,
    );
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
    let space_key = record(
        RecordKind::SpaceKey,
        &child.chain_id,
        json!({"schema":1,"auth_token":child.auth_token,"enc_key":child.enc_key_b64()}),
        2,
    );
    let sealed = SealedRecord {
        envelope: envelope(&keys, &space_key, 1),
        dirty: false,
        public_identity: None,
    };
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
fn only_the_old_alias_text_host_shape_counts_as_a_legacy_alias_host() {
    let keys = ChainKeys::generate().unwrap();
    let old = record(
        RecordKind::Host,
        "web",
        json!({"schema":1,"text":"Host web\n  HostName web.example\n"}),
        1,
    );
    assert!(is_legacy_alias_host(&keys, &envelope(&keys, &old, 1)));
    let typed = record(
        RecordKind::Host,
        HOST,
        json!({"schema":2,"alias":"web","hostname":"web.example","auth":"password"}),
        1,
    );
    assert!(!is_legacy_alias_host(&keys, &envelope(&keys, &typed, 1)));
    let mut deleted = old.clone();
    deleted.deleted = true;
    assert!(!is_legacy_alias_host(&keys, &envelope(&keys, &deleted, 1)));
    assert!(!is_legacy_alias_host(
        &ChainKeys::generate().unwrap(),
        &envelope(&keys, &old, 1)
    ));
}
