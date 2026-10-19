use super::*;
use crate::sync::{
    central::{
        migration::legacy_checkpoint,
        migration_freeze::{Phase as FreezePhase, ProofStep},
    },
    record::{SpaceKeyPayload, SpacePayload},
    state_v2::AccountState,
};
use serde_json::json;
fn fixture() -> (
    SyncStateV3,
    Sources,
    Workspace,
    DeviceKeys,
    Progress,
    PullResponse,
    ChainKeys,
) {
    let (owner, _, signer) = super::super::super::migration_history::tests::initial();
    let parent = ChainKeys::generate().unwrap();
    let child = ChainKeys::generate().unwrap();
    let mut state: SyncStateV3 = serde_json::from_value(json!({
        "version":8,"device_id":"d".repeat(32),"device_name":"Synthetic",
        "relay_url":owner.control.profile.origin,"last_sync_ms":null,"last_error":null
    }))
    .unwrap();
    state.account = Some(AccountState::new(&parent.chain_id));
    state.local.central = Some(owner.clone());
    let sources = Sources::discover(&state, Some(&parent)).unwrap();
    let mut rows = vec![];
    for (kind, payload) in [
        (
            RecordKind::Space,
            serde_json::to_value(SpacePayload {
                schema: 1,
                name: "Previously unseen".into(),
                slug: "unseen".into(),
                created_at_ms: 1,
                previous_id: None,
            })
            .unwrap(),
        ),
        (
            RecordKind::SpaceKey,
            serde_json::to_value(SpaceKeyPayload::from_keys(&child)).unwrap(),
        ),
    ] {
        rows.push(
            SealedRecord::seal(
                &parent,
                &Record {
                    kind,
                    id: child.chain_id.clone(),
                    version: 1,
                    updated_at_ms: 1,
                    device_id: state.device_id.clone(),
                    deleted: false,
                    payload,
                },
                rows.len() as u64 + 1,
            )
            .unwrap()
            .envelope,
        );
    }
    let response = PullResponse {
        records: rows,
        latest_seq: 2,
    };
    let intent = sources
        .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
        .unwrap();
    let progress = Progress {
        proof: vec![ProofStep {
            digest: intent.digest().unwrap(),
            intent,
        }],
        sources: vec![
            legacy_checkpoint(&parent.chain_id, response.latest_seq, &response.records).unwrap(),
        ],
        phase: FreezePhase::Frozen,
        next: vec![],
    };
    (state, sources, owner, signer, progress, response, child)
}
fn expanded() -> (SyncStateV3, Sources, Workspace, Progress, ChainKeys) {
    let (state, sources, owner, _, progress, response, child) = fixture();
    let snapshot = sources
        .admit_frozen(
            &owner,
            &"7".repeat(32),
            &progress,
            None,
            &sources.parent,
            response,
        )
        .unwrap();
    let sources = sources.with_parent_discovery(&owner, &snapshot).unwrap();
    (state, sources, owner, progress, child)
}
#[test]
fn previously_unseen_child_round_trips_only_from_the_original_state_and_verified_parent() {
    let (state, sources, owner, progress, child) = expanded();
    assert_eq!(sources.chains().len(), 2);
    assert!(state.spaces.is_empty());
    let book = sources.encode_local().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&book).unwrap()["version"],
        2
    );
    drop(sources);
    let restored = Sources::decode_local(&book, &state).unwrap();
    assert_eq!(restored.encode_local().unwrap().as_slice(), book.as_slice());
    assert_eq!(
        restored.keys[&child.chain_id].token.as_str(),
        child.auth_token
    );
    // Discovery grants a key, never permission to request an unextended signed source list.
    assert!(restored
        .freeze_body(&progress.proof[0].intent, &[child.chain_id.clone()])
        .is_err());
    let (_, _, signer) = super::super::super::migration_history::tests::initial();
    let next = restored
        .intent(
            &owner,
            &signer,
            &"7".repeat(32),
            &"8".repeat(64),
            Some(&progress),
        )
        .unwrap();
    assert_eq!(next.body.revision, "2");
    assert!(next.body.chains.contains(&child.chain_id));
    assert_eq!(
        next.body.preview_digest,
        progress.proof[0].intent.body.preview_digest
    );
    restored
        .freeze_body(&next, &[child.chain_id.clone()])
        .unwrap();
    let before = serde_json::to_vec(&state).unwrap();
    Inventory::from_state(&restored, &state).unwrap();
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}
#[test]
fn fabricated_serialized_children_missing_evidence_or_modified_ciphertext_never_restore() {
    let (state, sources, _, _, child) = expanded();
    let book = sources.encode_local().unwrap();
    let original: serde_json::Value = serde_json::from_slice(&book).unwrap();
    for case in [
        "missing-proof",
        "ciphertext",
        "checkpoint",
        "signature",
        "child-token",
        "extra-key",
        "missing-key",
        "base-key",
        "recursive",
        "version",
        "unknown",
        "missing-record",
        "target",
    ] {
        let mut value = original.clone();
        match case {
            "missing-proof" => value["discovery"]["progress"]["proof"] = json!([]),
            "ciphertext" => value["discovery"]["records"][0]["ciphertext"] = "AAAA".into(),
            "checkpoint" => value["discovery"]["latest_seq"] = 3.into(),
            "signature" => {
                value["discovery"]["progress"]["proof"][0]["intent"]["signature"] = "AAAA".into()
            }
            "child-token" => {
                value["keys"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|v| v["chain_id"] == child.chain_id)
                    .unwrap()["auth_token"] = "e".repeat(64).into()
            }
            "extra-key" => {
                let mut row = value["keys"][0].clone();
                row["chain_id"] = "f".repeat(64).into();
                value["keys"].as_array_mut().unwrap().push(row);
            }
            "missing-key" => {
                value["keys"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|v| v["chain_id"] != child.chain_id);
            }
            "base-key" => {
                let mut base: serde_json::Value =
                    serde_json::from_str(value["discovery"]["base"].as_str().unwrap()).unwrap();
                base["keys"][0]["auth_token"] = "e".repeat(64).into();
                value["discovery"]["base"] = serde_json::to_string(&base).unwrap().into();
            }
            "recursive" => {
                value["discovery"]["base"] = serde_json::to_string(&original).unwrap().into()
            }
            "version" => value["version"] = 1.into(),
            "unknown" => value["discovery"]["other"] = true.into(),
            "missing-record" => {
                value["discovery"]["records"].as_array_mut().unwrap().pop();
            }
            _ => {
                value["discovery"]["progress"]["proof"][0]["intent"]["body"]["author"] =
                    "e".repeat(32).into()
            }
        }
        assert!(
            Sources::decode_local(&serde_json::to_vec(&value).unwrap(), &state).is_err(),
            "{case}"
        );
    }
    assert!(Sources::decode_local(&vec![b' '; MAX_BOOK_BYTES + 1], &state).is_err());
}
#[test]
fn changed_enrollment_slot_relay_and_missing_central_owner_cannot_restore_remote_credentials() {
    let (state, sources, _, _, _) = expanded();
    let book = sources.encode_local().unwrap();
    for case in ["slot", "relay", "owner"] {
        let mut changed = state.clone();
        match case {
            "slot" => changed.local.central.as_mut().unwrap().identity_slot = Some("9".repeat(32)),
            "relay" => changed.relay_url = "https://other.example".into(),
            _ => changed.local.central = None,
        }
        // The slot is local context, so it must be persisted in evidence rather than inferred anew.
        assert!(Sources::decode_local(&book, &changed).is_err(), "{case}");
    }
}
#[test]
fn discovery_cannot_be_reapplied_or_replace_a_known_child_credential() {
    let (mut state, sources, owner, signer, progress, response, child) = fixture();
    let snapshot = sources
        .admit_frozen(
            &owner,
            &"7".repeat(32),
            &progress,
            None,
            &sources.parent,
            response.clone(),
        )
        .unwrap();
    let expanded = sources.with_parent_discovery(&owner, &snapshot).unwrap();
    assert!(expanded.with_parent_discovery(&owner, &snapshot).is_err());
    let (other_state, parent_key, known_child, _) = super::tests::fixture();
    state.account = other_state.account;
    state.relay_url = owner.control.profile.origin.clone();
    let known = Sources::discover(&state, Some(&parent_key)).unwrap();
    let different = ChainKeys::generate().unwrap();
    let record = Record {
        kind: RecordKind::SpaceKey,
        id: known_child.chain_id.clone(),
        version: 2,
        updated_at_ms: 2,
        device_id: state.device_id.clone(),
        deleted: false,
        payload: serde_json::to_value(SpaceKeyPayload::from_keys(&different)).unwrap(),
    };
    let response = PullResponse {
        records: vec![
            SealedRecord::seal(&parent_key, &record, 1)
                .unwrap()
                .envelope,
        ],
        latest_seq: 1,
    };
    let intent = known
        .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
        .unwrap();
    let progress = Progress {
        proof: vec![ProofStep {
            digest: intent.digest().unwrap(),
            intent,
        }],
        sources: vec![legacy_checkpoint(&parent_key.chain_id, 1, &response.records).unwrap()],
        phase: FreezePhase::Freezing,
        next: vec![known_child.chain_id.clone()],
    };
    let snapshot = known
        .admit_frozen(
            &owner,
            &"7".repeat(32),
            &progress,
            None,
            &parent_key.chain_id,
            response,
        )
        .unwrap();
    assert!(known.with_parent_discovery(&owner, &snapshot).is_err());
    drop(child);
}

#[test]
fn expanded_keybook_survives_the_actual_encrypted_package_archive_without_live_child_keys() {
    use crate::sync::central::source_package::Package;
    let (device, mut package, keys, owner, raw) =
        crate::sync::central::source_package::tests::fixture();
    let key = package.sources.keys.get(&package.sources.parent).unwrap();
    let parent = Temporary(
        ChainKeys::from_parts(&package.sources.parent, &key.token, &key.encryption).unwrap(),
    );
    let child = ChainKeys::generate().unwrap();
    let child_id = child.chain_id.clone();
    let row = SealedRecord::seal(
        &parent.0,
        &Record {
            kind: RecordKind::SpaceKey,
            id: child_id.clone(),
            version: 1,
            updated_at_ms: 1,
            device_id: package.state.device_id.clone(),
            deleted: false,
            payload: serde_json::to_value(SpaceKeyPayload::from_keys(&child)).unwrap(),
        },
        1,
    )
    .unwrap();
    let mut parent_records = vec![row.envelope];
    let parsed = crate::vault::material::parse(&raw).unwrap();
    let key_id = "6".repeat(32);
    let public = crate::sync::records_v3::KeySlotPayload {
        schema: 2,
        name: "remote-key".into(),
        public_key: parsed.public_key().to_openssh().unwrap(),
        fingerprint: parsed
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        key_type: parsed.public_key().algorithm().as_str().into(),
        has_passphrase: true,
        created_at_ms: 1,
        origin_device_id: package.state.device_id.clone(),
    };
    for (kind, id, payload) in [
        (
            RecordKind::Space,
            child_id.clone(),
            serde_json::to_value(SpacePayload {
                schema: 1,
                name: "Previously unseen".into(),
                slug: "unseen".into(),
                created_at_ms: 1,
                previous_id: None,
            })
            .unwrap(),
        ),
        (
            RecordKind::KeySlot,
            key_id.clone(),
            serde_json::to_value(public).unwrap(),
        ),
        (
            RecordKind::Key,
            key_id.clone(),
            json!({"schema":1,"private_key":raw}),
        ),
    ] {
        let record = Record {
            kind,
            id,
            payload,
            version: 1,
            updated_at_ms: 1,
            device_id: package.state.device_id.clone(),
            deleted: false,
        };
        parent_records.push(
            SealedRecord::seal(&parent.0, &record, parent_records.len() as u64 + 1)
                .unwrap()
                .envelope,
        );
    }
    let response = PullResponse {
        records: parent_records,
        latest_seq: 4,
    };
    let host = Record {
        kind: RecordKind::Host,
        id: "1111111111111111".into(),
        version: 1,
        updated_at_ms: 1,
        device_id: package.state.device_id.clone(),
        deleted: false,
        payload: json!({"schema":2,"alias":"unseen-host","hostname":"fixture.invalid","auth":"key","key_id":key_id}),
    };
    let child_records = vec![SealedRecord::seal(&child, &host, 1).unwrap().envelope];
    let (_, _, signer) = crate::sync::central::migration_history::tests::initial();
    let intent = package
        .sources
        .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
        .unwrap();
    let progress = Progress {
        proof: vec![ProofStep {
            digest: intent.digest().unwrap(),
            intent,
        }],
        sources: vec![legacy_checkpoint(&parent.0.chain_id, 4, &response.records).unwrap()],
        phase: FreezePhase::Frozen,
        next: vec![],
    };
    let snapshot = package
        .sources
        .admit_frozen(
            &owner,
            &"7".repeat(32),
            &progress,
            None,
            &parent.0.chain_id,
            response,
        )
        .unwrap();
    package.sources = package
        .sources
        .with_parent_discovery(&owner, &snapshot)
        .unwrap();
    let next = package
        .sources
        .intent(
            &owner,
            &signer,
            &"7".repeat(32),
            &"8".repeat(64),
            Some(&progress),
        )
        .unwrap();
    let mut complete = progress.clone();
    complete.proof.push(ProofStep {
        digest: next.digest().unwrap(),
        intent: next,
    });
    complete
        .sources
        .push(legacy_checkpoint(&child_id, 1, &child_records).unwrap());
    complete.sources.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));
    let parent_snapshot = package
        .sources
        .admit_frozen(
            &owner,
            &"7".repeat(32),
            &complete,
            None,
            &parent.0.chain_id,
            PullResponse {
                records: snapshot.records().to_vec(),
                latest_seq: 4,
            },
        )
        .unwrap();
    let child_snapshot = package
        .sources
        .admit_frozen(
            &owner,
            &"7".repeat(32),
            &complete,
            None,
            &child_id,
            PullResponse {
                records: child_records,
                latest_seq: 1,
            },
        )
        .unwrap();
    package = package
        .with_frozen(
            &"7".repeat(32),
            &complete,
            None,
            vec![parent_snapshot, child_snapshot],
        )
        .unwrap();
    let plain = package.encode_local().unwrap();
    assert_eq!(&plain[..8], b"LPSRCPK2");
    assert!(Package::decode_local(&plain[..plain.len() - 1]).is_err());
    let mut wrong_version = plain.to_vec();
    wrong_version[..8].copy_from_slice(b"LPSRCPK1");
    assert!(Package::decode_local(&wrong_version).is_err());

    let decoded = Package::decode_local(&plain).unwrap();
    assert!(decoded.sources.keys.contains_key(&child_id));
    drop((child, parent, decoded));
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let archived = package.archive(&env, &life, &owner, 0).unwrap();
    package.revalidate_archive(&env, &archived).unwrap();
    let receipt = archived.receipt().clone();
    drop((package, plain, archived, life));
    let restored =
        Package::restore(&env, &owner.control.profile.profile().unwrap(), &receipt).unwrap();
    assert!(restored.sources.keys.contains_key(&child_id));
    let inventory = restored.record_inputs().unwrap();
    assert_eq!(
        inventory
            .rows()
            .iter()
            .filter(|row| row.location.position == Position::Frozen)
            .count(),
        5
    );
    inventory.admit_known().unwrap();
    // The complete set now passes conservative current reconciliation; no source is activated.
    let before = restored.encode_local().unwrap();
    let history = restored
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    assert!(history.iter().any(|(_,data)|matches!(data,crate::sync::central::payload::Data::Host(host)if host.alias=="unseen-host")));
    assert!(history.iter().any(|(_,data)|matches!(data,crate::sync::central::payload::Data::Catalog(catalog)if catalog.collections.iter().any(|c|c.id==child_id))));
    assert!(history.iter().any(|(id,data)|id.id==key_id && matches!(data,crate::sync::central::payload::Data::Key(private)if private.private()==raw)));
    assert!(restored.encode_local().unwrap().as_slice() == before.as_slice());
}

#[test]
fn verified_parent_metadata_without_readable_child_credentials_blocks_the_whole_discovery() {
    for case in ["metadata-only", "future-secret"] {
        let (_, sources, owner, _, mut progress, mut response, _) = fixture();
        if case == "metadata-only" {
            response.records.retain(|row| row.kind != "spacekey");
        } else {
            let key = &sources.keys[&sources.parent];
            let parent = Temporary(
                ChainKeys::from_parts(&sources.parent, &key.token, &key.encryption).unwrap(),
            );
            let envelope = response
                .records
                .iter_mut()
                .find(|row| row.kind == "spacekey")
                .unwrap();
            let row = SealedRecord {
                envelope: envelope.clone(),
                dirty: false,
                public_identity: None,
            };
            let mut decoded = row.open(&parent.0).unwrap();
            decoded.payload["schema"] = 2.into();
            *envelope = SealedRecord::seal(&parent.0, &decoded, envelope.seq)
                .unwrap()
                .envelope;
        }
        progress.sources =
            vec![
                legacy_checkpoint(&sources.parent, response.latest_seq, &response.records).unwrap(),
            ];
        let snapshot = sources
            .admit_frozen(
                &owner,
                &"7".repeat(32),
                &progress,
                None,
                &sources.parent,
                response,
            )
            .unwrap();
        assert!(
            sources.with_parent_discovery(&owner, &snapshot).is_err(),
            "{case}"
        );
    }
}

#[test]
fn partial_fetch_can_extend_only_from_its_exact_authenticated_parent_book() {
    use super::super::fetching::Fetching;
    let (state, sources, owner, signer, progress, response, child) = fixture();
    let parent = sources.parent.clone();
    let mut fetching = Fetching::new(&sources, &state, &"7".repeat(32), &progress).unwrap();
    let snapshot = sources.admit_frozen(&owner, fetching.operation(), &progress, None, &parent, response.clone()).unwrap();
    fetching.insert(&sources, &state, snapshot).unwrap();
    let snapshot = sources.admit_frozen(&owner, fetching.operation(), &progress, None, &parent, response).unwrap();
    let expanded = sources.with_parent_discovery(&owner, &snapshot).unwrap();
    let intent = expanded.intent(&owner, &signer, fetching.operation(), &"8".repeat(64), Some(&progress)).unwrap();
    let mut next = progress.clone();
    next.proof.push(ProofStep { digest: intent.digest().unwrap(), intent });
    next.phase = FreezePhase::Freezing;
    next.next = vec![child.chain_id.clone()];
    fetching.advance(&expanded, &state, &next).unwrap();
    assert_eq!(fetching.next_source(&expanded, &state).unwrap(), None);
    let encoded = fetching.encode_local().unwrap();
    let book = expanded.encode_local().unwrap();
    let expanded = Sources::decode_local(&book, &state).unwrap();
    let mut restored = Fetching::decode_local(&encoded, &expanded, &state).unwrap();
    let empty = PullResponse { records: vec![], latest_seq: 0 };
    next.sources.push(legacy_checkpoint(&child.chain_id, 0, &[]).unwrap());
    next.sources.sort_by(|a,b| a.chain_id.cmp(&b.chain_id));
    next.phase = FreezePhase::Frozen;
    next.next.clear();
    restored.advance(&expanded, &state, &next).unwrap();
    let snapshot = expanded.admit_frozen(&owner, restored.operation(), &next, None, &child.chain_id, empty).unwrap();
    restored.insert(&expanded, &state, snapshot).unwrap();
    restored.complete(&expanded, &state).unwrap();
    assert!(state.spaces.is_empty());
}
