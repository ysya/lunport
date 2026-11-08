use super::*;
use crate::sync::record::{Envelope, ACCOUNT_META_ID};
use crate::sync::{
    crypto::ChainKeys,
    records_v3,
    state_v2::{sealed_key, SealedRecord, VerifiedPublicIdentity},
};
use serde_json::json;

const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn fixture() -> (SyncStateV3, ChainKeys, ChainKeys) {
    let account_keys = ChainKeys::generate().unwrap();
    let space_keys = ChainKeys::generate().unwrap();
    let mut s = state();
    let mut account = AccountState::new(&account_keys.chain_id);
    account.cursor_seq = 9;
    account.baseline_established = true;
    account.records.insert(
        record_key(RecordKind::Meta, ACCOUNT_META_ID),
        LocalRecord {
            record: Record {
                kind: RecordKind::Meta,
                id: ACCOUNT_META_ID.into(),
                version: 1,
                updated_at_ms: 1,
                device_id: s.device_id.clone(),
                deleted: false,
                payload: json!({"schema_version":3,"created_by_app_version":"fixture"}),
            },
            seq: 1,
            dirty: false,
        },
    );
    s.account = Some(account);
    let mut space = SpaceStateV3 {
        selected: true,
        cursor_seq: 7,
        baseline_established: true,
        ..Default::default()
    };
    space.records.insert(
        record_key(RecordKind::Host, ID),
        cached(ID, payload("web"), 7),
    );
    s.spaces.insert(space_keys.chain_id.clone(), space);
    (s, account_keys, space_keys)
}
fn envelope(keys: &ChainKeys, r: &Record, seq: u64) -> Envelope {
    let sealed = crate::sync::crypto::seal(keys, r.kind.as_str(), &r.id, &serde_json::to_vec(r).unwrap()).unwrap();
    Envelope {
        kind: r.kind.as_str().into(),
        id_hash: sealed.id_hash,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        seq,
        deleted: r.deleted,
    }
}
/// What the retired chain merger kept of a row this build cannot read as a typed record, as states saved by earlier builds still
/// carry it: the ciphertext and, for the kinds the repository reads, the authenticated public header.
fn retained(keys: &ChainKeys, row: Envelope, readable: &[&str]) -> SealedRecord {
    let public_identity = readable.contains(&row.kind.as_str()).then(|| {
        let sealed = crate::sync::crypto::Sealed {
            id_hash: row.id_hash.clone(),
            nonce: row.nonce.clone(),
            ciphertext: row.ciphertext.clone(),
        };
        let header: serde_json::Value =
            serde_json::from_slice(&crate::sync::crypto::open(keys, &row.kind, &row.id_hash, &sealed).unwrap()).unwrap();
        VerifiedPublicIdentity {
            id: header["id"].as_str().unwrap().into(),
            version: header["version"].as_u64().unwrap(),
            updated_at_ms: header["updated_at_ms"].as_u64().unwrap(),
            device_id: header["device_id"].as_str().unwrap().into(),
            deleted: header["deleted"].as_bool().unwrap(),
        }
    });
    SealedRecord {
        envelope: row,
        dirty: false,
        public_identity,
    }
}
fn apply_host(s: &mut SyncStateV3, keys: &ChainKeys, row: Envelope) {
    let space = s.spaces.get_mut(&keys.chain_id).unwrap();
    space.cursor_seq = space.cursor_seq.max(row.seq);
    let row = retained(keys, row, &["host", "group"]);
    space.sealed.insert(sealed_key(&row.envelope.kind, &row.envelope.id_hash), row);
}
fn apply_slot(s: &mut SyncStateV3, keys: &ChainKeys, row: Envelope) {
    let account = s.account.as_mut().unwrap();
    account.cursor_seq = account.cursor_seq.max(row.seq);
    let row = retained(keys, row, &["keyslot", "meta"]);
    account.sealed.insert(sealed_key(&row.envelope.kind, &row.envelope.id_hash), row);
}
fn future_host() -> Record {
    Record {
        kind: RecordKind::Host,
        id: ID.into(),
        version: 5,
        updated_at_ms: 200,
        device_id: "e".repeat(32),
        deleted: false,
        payload: json!({"schema":3,"hostname":"future.test"}),
    }
}
fn local_key(s: &mut SyncStateV3) {
    s.local.keys.insert(
        KEY.into(),
        LocalKeyMetadata {
            vault_id: "a".repeat(32),
            public: slot(PUBLIC),
        },
    );
}
fn future_slot() -> Record {
    Record {
        kind: RecordKind::KeySlot,
        id: KEY.into(),
        version: 2,
        updated_at_ms: 200,
        device_id: "e".repeat(32),
        deleted: false,
        payload: json!({"schema":3,"future":"unrecognized public identity"}),
    }
}
fn restart(s: &SyncStateV3) -> SyncStateV3 {
    let records_v3::DecodedState::V3(state) =
        records_v3::decode_state(&serde_json::to_string(s).unwrap()).unwrap()
    else {
        panic!("v3")
    };
    *state
}
#[test]
fn newer_authenticated_unsupported_host_keeps_cache_but_blocks_every_readiness_path_after_restart()
{
    let (mut s, _, keys) = fixture();
    let before = s.spaces[&keys.chain_id].records.clone();
    apply_host(&mut s, &keys, envelope(&keys, &future_host(), 10));
    assert_eq!(s.spaces[&keys.chain_id].records, before);
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
    assert_eq!(
        resolve_host_chain(&s, ID).unwrap()[0].readiness,
        HostReadiness::NeedsReview
    );
    assert_eq!(
        get_host(&restart(&s), ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
}
#[test]
fn unsupported_account_key_authority_cannot_fall_back_to_available_local_material() {
    for cached_public in [true, false] {
        let (mut s, keys, _) = fixture();
        local_key(&mut s);
        if cached_public {
            account_key(&mut s, KEY, slot(PUBLIC), false);
        }
        let space_id = s.spaces.keys().next().unwrap().clone();
        let host = s
            .spaces
            .get_mut(&space_id)
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::Host, ID))
            .unwrap();
        host.record.payload["auth"] = json!("key");
        host.record.payload["key_id"] = json!(KEY);
        let local = s.local.clone();
        apply_slot(&mut s, &keys, envelope(&keys, &future_slot(), 10));
        assert_eq!(s.local, local);
        let key = resolve_key(&s, KEY).unwrap();
        assert_eq!(key.status, KeyStatus::Conflict);
        assert!(key.vault_id.is_none());
        assert_eq!(
            get_host(&s, ID).unwrap().readiness,
            HostReadiness::KeyConflict(KEY.into())
        );
        assert_eq!(
            resolve_key(&restart(&s), KEY).unwrap().status,
            KeyStatus::Conflict
        );
    }
}
#[test]
fn persisted_identity_hints_reject_secret_kinds_wrong_shapes_and_deleted_mismatch() {
    let (mut s, keys, space) = fixture();
    apply_host(&mut s, &space, envelope(&space, &future_host(), 10));
    let value = serde_json::to_value(&s).unwrap();
    let wire = sealed_key("host", &crate::sync::crypto::id_hash(&space, "host", ID));
    for (field, replacement) in [
        ("id", json!("not-a-public-host-id")),
        ("device_id", json!("invalid actor")),
        ("deleted", json!(true)),
        ("version", json!(0)),
    ] {
        let mut bad = value.clone();
        bad["spaces"][&space.chain_id]["sealed"][&wire]["public_identity"] = json!({"id":ID,"version":1,"updated_at_ms":200,"device_id":"e".repeat(32),"deleted":false});
        bad["spaces"][&space.chain_id]["sealed"][&wire]["public_identity"][field] = replacement;
        assert!(records_v3::decode_state(&bad.to_string()).is_err());
    }
    let secret = Record {
        kind: RecordKind::Key,
        id: KEY.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema":9,"private_key":"synthetic secret sentinel"}),
    };
    apply_slot(&mut s, &keys, envelope(&keys, &secret, 10));
    let mut bad = serde_json::to_value(&s).unwrap();
    let wire = sealed_key("key", &crate::sync::crypto::id_hash(&keys, "key", KEY));
    bad["account"]["sealed"][&wire]["public_identity"] =
        json!({"id":KEY,"version":1,"updated_at_ms":1,"device_id":"d".repeat(32),"deleted":false});
    assert!(records_v3::decode_state(&bad.to_string()).is_err());
    assert!(!serde_json::to_string(&s)
        .unwrap()
        .contains("synthetic secret sentinel"));
}

#[test]
fn unknown_kinds_and_secret_identity_strings_never_become_persisted_hints() {
    let (mut s, keys, _) = fixture();
    let private_id = "synthetic secret identity sentinel";
    let raw = json!({"kind":"future-widget","id":private_id,"version":1,"updated_at_ms":200,"device_id":"d".repeat(32),"deleted":false,"payload":{"private":"synthetic private sentinel"}});
    let sealed = crate::sync::crypto::seal(
        &keys,
        "future-widget",
        private_id,
        &serde_json::to_vec(&raw).unwrap(),
    )
    .unwrap();
    apply_slot(
        &mut s,
        &keys,
        Envelope {
            kind: "future-widget".into(),
            id_hash: sealed.id_hash.clone(),
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            seq: 10,
            deleted: false,
        },
    );
    let serialized = serde_json::to_string(&s).unwrap();
    assert!(!serialized.contains(private_id));
    assert!(!serialized.contains("synthetic private sentinel"));
    let mut value = serde_json::to_value(&s).unwrap();
    let wire = sealed_key("future-widget", &sealed.id_hash);
    assert!(value["account"]["sealed"][&wire]
        .get("public_identity")
        .is_none());
    value["account"]["sealed"][&wire]["public_identity"] =
        json!({"id":KEY,"version":1,"updated_at_ms":1,"device_id":"d".repeat(32),"deleted":false});
    assert!(records_v3::decode_state(&value.to_string()).is_err());
}

// All mutation tests cross the persisted v3 restart boundary.
fn opaque_mutation_fixture(pinned: bool) -> SyncStateV3 {
    let (mut s, _, keys) = fixture();
    local_key(&mut s);
    if pinned {
        s.spaces
            .get_mut(&keys.chain_id)
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::Host, ID))
            .unwrap()
            .record
            .payload["host_key"] = json!(pin());
    }
    apply_host(&mut s, &keys, envelope(&keys, &future_host(), 10));
    s
}
fn for_live_and_restarted(s: &SyncStateV3, check: impl Fn(&SyncStateV3)) {
    for current in [s.clone(), restart(s)] {
        let before = current.clone();
        assert_eq!(
            get_host(&current, ID).unwrap().readiness,
            HostReadiness::NeedsReview
        );
        check(&current);
        assert_eq!(
            current, before,
            "rejection preserves typed cache, sealed evidence and local material"
        );
        assert_eq!(
            get_host(&restart(&current), ID).unwrap().readiness,
            HostReadiness::NeedsReview
        );
    }
}
fn endpoint() -> HostEndpoint {
    HostEndpoint {
        hostname: "server.example.com".into(),
        port: 22,
    }
}
fn alternate_pin() -> StoredHostKey {
    let public = slot(ECDSA);
    StoredHostKey {
        algorithm: public.key_type,
        public_key: ECDSA.split_whitespace().nth(1).unwrap().into(),
        fingerprint: public.fingerprint,
        pinned_at_ms: 1,
        pinned_by_device_id: "d".repeat(32),
    }
}
#[test]
fn winning_opaque_host_refuses_update_before_stale_endpoint_and_pin_become_ready() {
    for_live_and_restarted(&opaque_mutation_fixture(true), |s| {
        let host = get_host(s, ID).unwrap();
        assert!(
            matches!(update_host(s, ID, &host.revision, payload("renamed"), 300), Err(RepositoryError::OpaqueHostAuthority(id)) if id == ID),
            "a stale typed revision cannot supersede winning unsupported authority"
        );
    });
}
#[test]
fn winning_opaque_host_refuses_move_before_stale_payload_and_pin_become_local() {
    for_live_and_restarted(&opaque_mutation_fixture(true), |s| {
        let host = get_host(s, ID).unwrap();
        assert!(
            matches!(move_host(s, ID, &host.revision, HostScope::Local, 300), Err(RepositoryError::OpaqueHostAuthority(id)) if id == ID),
            "opaque authority cannot be escaped by changing scope"
        );
        assert!(
            matches!(move_host(s, ID, &host.revision, host.host.scope, 300), Err(RepositoryError::OpaqueHostAuthority(id)) if id == ID),
            "same-scope no-op also checks canonical authority"
        );
    });
}
#[test]
fn winning_opaque_host_refuses_delete_before_inventing_a_newer_tombstone() {
    for_live_and_restarted(&opaque_mutation_fixture(true), |s| {
        let host = get_host(s, ID).unwrap();
        assert!(
            matches!(delete_host(s, ID, &host.revision, 300), Err(RepositoryError::OpaqueHostAuthority(id)) if id == ID),
            "a stale typed revision cannot delete unsupported authority"
        );
    });
}
#[test]
fn winning_opaque_host_refuses_first_pin() {
    for_live_and_restarted(&opaque_mutation_fixture(false), |s| {
        assert!(
            matches!(pin_host_key(s, ID, &endpoint(), None, pin(), 300), Err(RepositoryError::OpaqueHostAuthority(id)) if id == ID),
            "an old endpoint cannot establish trust under unsupported authority"
        );
    });
}
#[test]
fn winning_opaque_host_refuses_replacement_pin() {
    for_live_and_restarted(&opaque_mutation_fixture(true), |s| {
        assert!(
            matches!(pin_host_key(s, ID, &endpoint(), Some(&pin()), alternate_pin(), 300), Err(RepositoryError::OpaqueHostAuthority(id)) if id == ID),
            "old endpoint/pin CAS cannot supersede unsupported authority"
        );
    });
}
#[test]
fn winning_opaque_host_refuses_idempotent_pin_acceptance() {
    for_live_and_restarted(&opaque_mutation_fixture(true), |s| {
        assert!(
            matches!(pin_host_key(s, ID, &endpoint(), Some(&pin()), pin(), 300), Err(RepositoryError::OpaqueHostAuthority(id)) if id == ID),
            "a repeated stale pin is not an accepted confirmation"
        );
    });
}
#[test]
fn opaque_cached_id_cannot_be_recreated_but_unrelated_creation_remains_available() {
    for_live_and_restarted(&opaque_mutation_fixture(true), |s| {
        assert!(matches!(
            create_host(s, ID, HostScope::Local, payload("replacement"), 300),
            Err(RepositoryError::Validation(
                RecordValidationError::DuplicateId(_)
            ))
        ));
        let next = create_host(s, OTHER, HostScope::Local, payload("unrelated"), 300).unwrap();
        assert_eq!(
            get_host(&next, ID).unwrap().readiness,
            HostReadiness::NeedsReview
        );
        assert_eq!(
            get_host(&next, OTHER).unwrap().readiness,
            HostReadiness::Ready
        );
        assert_eq!(next.spaces, s.spaces);
        assert_eq!(next.local.keys, s.local.keys);
    });
}
#[test]
fn imported_needs_review_remains_editable_without_opaque_authority() {
    let (mut s, _, keys) = fixture();
    let host = s
        .spaces
        .get_mut(&keys.chain_id)
        .unwrap()
        .records
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap();
    host.record.payload["imported"] = json!({"source":"temporary fixture", "at_ms":1,"unsupported":[{"keyword":"ProxyCommand","value":"unsupported fixture","requires_review":true}]});
    let s = restart(&s);
    let view = get_host(&s, ID).unwrap();
    assert_eq!(view.readiness, HostReadiness::NeedsReview);
    let repaired = update_host(&s, ID, &view.revision, payload("reviewed"), 300).unwrap();
    assert_eq!(
        get_host(&repaired, ID).unwrap().readiness,
        HostReadiness::Ready
    );
    assert!(move_host(&s, ID, &view.revision, HostScope::Local, 300).is_ok());
    assert!(delete_host(&s, ID, &view.revision, 300).is_ok());
    assert!(pin_host_key(&s, ID, &endpoint(), None, pin(), 300).is_ok());
}
