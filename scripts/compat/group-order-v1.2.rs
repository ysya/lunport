//! Copied into the unmodified v1.2.0 crate by validate-group-order-compat.sh.
use super::*;
use serde_json::json;

#[test]
fn group_order_compat_old_client_preserves_optional_metadata_and_keeps_normal_writes() {
    let keys = ChainKeys::generate().unwrap();
    let actor = "d".repeat(32);
    let record = |id: &str, payload| Record {
        kind: RecordKind::Meta,
        id: id.into(),
        version: 1,
        updated_at_ms: 10,
        device_id: actor.clone(),
        deleted: false,
        payload,
    };
    let rows = [
        record(
            ACCOUNT_META_ID,
            json!({"schema_version":4,"created_by_app_version":"fixture"}),
        ),
        record(
            "library-group-order",
            json!({"schema":1,"ids":["0000000000000002","0000000000000001"]}),
        ),
        record(
            "tunnel:0000000000000001",
            json!({"schema":1,"rule":{"id":"0000000000000001","host_id":"0000000000000002","name":"Database","forward":{"kind":"local","bind_address":"127.0.0.1","port":15432,"target_host":"db.internal","target_port":5432}}}),
        ),
        Record {
            deleted: true,
            ..record("tunnel:0000000000000003", serde_json::Value::Null)
        },
    ];
    let envelopes = rows
        .iter()
        .enumerate()
        .map(|(index, r)| {
            let item = encode_record(&keys, r, 0).unwrap();
            Envelope {
                id_hash: item.id_hash,
                kind: item.kind,
                seq: index as u64 + 1,
                nonce: item.nonce,
                ciphertext: item.ciphertext,
                deleted: item.deleted,
            }
        })
        .collect();
    let merged = merge_account(
        &AccountState::new(&keys.chain_id),
        &keys,
        &PullResponse {
            records: envelopes,
            latest_seq: 4,
        },
        0,
    );
    assert_eq!(merged.gate, AccountGate::Compatible);
    assert_eq!(merged.skipped, 3);
    assert_eq!(merged.section.cursor_seq, 4);
    assert_eq!(merged.section.sealed.len(), 3);
    for r in &rows[1..] {
        let id_hash = crypto::id_hash(&keys, "meta", &r.id);
        let opaque = merged
            .section
            .sealed
            .values()
            .find(|row| row.envelope.id_hash == id_hash)
            .unwrap();
        assert!(!opaque.dirty);
        assert_eq!(opaque.envelope.deleted, r.deleted);
    }
    assert!(!merged
        .section
        .records
        .contains_key("meta:library-group-order"));
    let opaque = merged
        .section
        .sealed
        .values()
        .find(|r| r.envelope.id_hash == crypto::id_hash(&keys, "meta", "library-group-order"))
        .unwrap();
    assert!(!opaque.dirty);
    let ciphertext = opaque.envelope.clone();
    let mut account = merged.section;
    let device = Record {
        kind: RecordKind::Device,
        id: actor.clone(),
        version: 1,
        updated_at_ms: 11,
        device_id: actor.clone(),
        deleted: false,
        payload: json!({"schema":1,"name":"old client","platform":"fixture","joined_at_ms":1,"last_seen_ms":11}),
    };
    account.records.insert(
        record_key(RecordKind::Device, &actor),
        LocalRecord {
            record: device,
            seq: 0,
            dirty: true,
        },
    );
    let outgoing = account_outgoing(&account, &keys).unwrap();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].outgoing.item.kind, "device");
    assert!(account.sealed.values().any(|r| r.envelope == ciphertext));
    // The old state parser accepts its preserved opaque metadata and Group schema 1 stays readable.
    let mut state:crate::sync::records_v3::SyncStateV3=serde_json::from_value(json!({
        "version":4,"device_id":actor,"device_name":"old client","relay_url":"http://127.0.0.1",
        "last_sync_ms":null,"last_error":null,"account":account,
        "local":{"groups":{"group:0000000000000001":{"record":{"kind":"group","id":"0000000000000001","version":1,
        "updated_at_ms":1,"device_id":"dddddddddddddddddddddddddddddddd","deleted":false,"payload":{"schema":1,"name":"Alpha","defaults":{}}},"seq":0,"dirty":false}}}
    })).unwrap();
    crate::sync::records_v3::validate_state(&state).unwrap();
    let group = crate::sync::record_groups::list_groups(&state)
        .unwrap()
        .remove(0);
    let mut payload = group.group.payload.clone();
    payload.name = "Renamed on old client".into();
    state = crate::sync::record_groups::update_group(
        &state,
        &group.group.id,
        &group.revision,
        payload,
        12,
    )
    .unwrap();
    assert_eq!(
        crate::sync::record_groups::list_groups(&state).unwrap()[0]
            .group
            .payload
            .name,
        "Renamed on old client"
    );
}
