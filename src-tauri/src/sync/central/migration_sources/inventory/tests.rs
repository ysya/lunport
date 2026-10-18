use super::*;
use crate::sync::{
    record::{record_key, LocalRecord, Record},
    record_conflicts::RecordConflict,
};
use serde_json::json;
fn public(kind: RecordKind, id: &str, version: u64, deleted: bool) -> LocalRecord {
    let payload = if deleted {
        serde_json::Value::Null
    } else {
        match kind {
            RecordKind::Host => {
                json!({"schema":2,"alias":"synthetic","hostname":"fixture.invalid","auth":"password"})
            }
            RecordKind::Group => json!({"schema":1,"name":"synthetic"}),
            RecordKind::Meta => json!({"schema_version":4,"created_by_app_version":"test"}),
            _ => panic!("public fixture kind"),
        }
    };
    LocalRecord {
        record: Record {
            kind,
            id: id.into(),
            version,
            updated_at_ms: version,
            device_id: "d".repeat(32),
            deleted,
            payload,
        },
        seq: version,
        dirty: false,
    }
}
#[test]
fn local_account_unselected_missing_scopes_and_every_public_or_private_conflict_side_are_included()
{
    let (mut state, parent, child) = super::super::records::tests::fixture();
    let host = public(RecordKind::Host, &"6".repeat(16), 1, false);
    state
        .local
        .hosts
        .insert(record_key(host.record.kind, &host.record.id), host);
    let group = public(RecordKind::Group, &"7".repeat(16), 1, false);
    state
        .local
        .groups
        .insert(record_key(group.record.kind, &group.record.id), group);
    let account = state.account.as_mut().unwrap();
    let meta = public(RecordKind::Meta, "account", 1, false);
    let key = record_key(RecordKind::Meta, "account");
    account.records.insert(key.clone(), meta.clone());
    account
        .recovery
        .bases
        .insert(key.clone(), RecordVersion::Public(meta.clone()));
    account.recovery.conflicts.insert(
        key,
        vec![RecordConflict {
            base: Some(RecordVersion::Public(meta)),
            local: RecordVersion::Public(public(RecordKind::Meta, "account", 2, false)),
            remote: RecordVersion::Public(public(RecordKind::Meta, "account", 3, false)),
        }],
    );
    let row = public(RecordKind::Host, &"8".repeat(16), 1, false);
    state
        .spaces
        .get_mut(&child.chain_id)
        .unwrap()
        .records
        .insert(record_key(row.record.kind, &row.record.id), row);
    let sources = Sources::discover(&state, Some(&parent)).unwrap();
    let before = serde_json::to_vec(&state).unwrap();
    let inventory = Inventory::from_state(&sources, &state).unwrap();
    assert_eq!(inventory.rows().len(), 20);
    assert_eq!(inventory.positions.len(), 20);
    assert_eq!(
        inventory
            .rows()
            .iter()
            .filter(|r| r.location.scope == Scope::Local)
            .count(),
        2
    );
    assert_eq!(
        inventory
            .rows()
            .iter()
            .filter(|r| matches!(&r.location.scope,Scope::Space(id) if id==&child.chain_id))
            .count(),
        6
    );
    for position in [
        Position::ChainDelete,
        Position::RecoveryBase,
        Position::ConflictBase,
        Position::ConflictLocal,
        Position::ConflictRemote,
    ] {
        assert!(inventory
            .rows()
            .iter()
            .any(|r| r.location.position == position));
    }
    assert!(inventory.rows().iter().any(|r| r
        .view()
        .unwrap()
        .payload
        .get()
        .contains("PRIVATE_RETAINED_SENTINEL")));
    assert!(
        inventory
            .rows()
            .iter()
            .any(|r| r.view().unwrap().version == 3
                && r.location.position == Position::ConflictRemote)
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}
#[test]
fn an_unreadable_last_conflict_side_never_returns_a_partial_success() {
    let (mut state, parent, child) = super::super::records::tests::fixture();
    let sources = Sources::discover(&state, Some(&parent)).unwrap();
    let recovery = &mut state.spaces.get_mut(&child.chain_id).unwrap().recovery;
    let RecordVersion::Sealed(last) =
        &mut recovery.conflicts.values_mut().next().unwrap()[0].remote
    else {
        panic!()
    };
    last.envelope.ciphertext.replace_range(..4, "AAAA");
    assert!(Inventory::from_state(&sources, &state).is_err());
}
#[test]
fn empty_local_sources_still_inventory_local_tombstones_and_dirty_false_rows() {
    let mut state:SyncStateV3=serde_json::from_value(json!({"version":7,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap();
    for (id, deleted) in [("1".repeat(16), false), ("2".repeat(16), true)] {
        let row = public(RecordKind::Host, &id, 1, deleted);
        state
            .local
            .hosts
            .insert(record_key(row.record.kind, &id), row);
    }
    let sources = Sources::discover(&state, None).unwrap();
    let inventory = Inventory::from_state(&sources, &state).unwrap();
    assert_eq!(inventory.rows().len(), 2);
    assert!(inventory.rows().iter().all(|r| !r.dirty));
    assert!(inventory.rows().iter().any(|r| r.view().unwrap().deleted));
}
#[test]
fn public_and_encrypted_inputs_share_one_aggregate_record_and_byte_limit() {
    let (state, parent, _) = super::super::records::tests::fixture();
    let sources = Sources::discover(&state, Some(&parent)).unwrap();
    let mut inventory = Inventory::from_state(&sources, &state).unwrap();
    let row = public(RecordKind::Meta, "account", 1, false);
    inventory.bytes = 32 * 1024 * 1024 - 256 * 1024;
    assert!(inventory
        .public(
            Scope::Account(parent.chain_id.clone()),
            Position::Current,
            "meta:account",
            0,
            &row
        )
        .is_err());
    let mut inventory = Inventory::from_state(&sources, &state).unwrap();
    for index in 0..(16384 - 12) {
        inventory
            .public(
                Scope::Account(parent.chain_id.clone()),
                Position::Current,
                "meta:account",
                index,
                &row,
            )
            .unwrap();
    }
    assert_eq!(inventory.rows().len(), 16384);
    assert!(inventory
        .public(
            Scope::Account(parent.chain_id),
            Position::Current,
            "meta:account",
            20000,
            &row
        )
        .is_err());
}
