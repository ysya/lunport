use super::*;

fn pinned() -> SyncStateV3 {
    let state = with_host();
    let host = get_host(&state, ID).unwrap();
    let public = ssh_key::PublicKey::from_openssh(PUBLIC).unwrap();
    pin_host_key(
        &state,
        ID,
        &HostEndpoint {
            hostname: host.effective_payload.hostname,
            port: host.effective_payload.port,
        },
        None,
        StoredHostKey {
            algorithm: public.algorithm().as_str().into(),
            public_key: PUBLIC.split_whitespace().nth(1).unwrap().into(),
            fingerprint: public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            pinned_at_ms: 0,
            pinned_by_device_id: state.device_id.clone(),
        },
        200,
    )
    .unwrap()
}
#[test]
fn forgetting_a_displayed_pin_preserves_the_host_and_requires_fresh_trust() {
    let state = pinned();
    let host = get_host(&state, ID).unwrap();
    let next = forget_host_key(
        &state,
        ID,
        &host.revision,
        &HostEndpoint {
            hostname: host.effective_payload.hostname,
            port: host.effective_payload.port,
        },
        host.host.payload.host_key.as_ref().unwrap(),
        201,
    )
    .unwrap();
    let changed = get_host(&next, ID).unwrap();
    let mut expected = host.host.payload;
    expected.host_key = None;
    assert_eq!(changed.host.payload, expected);
    assert_eq!(changed.host.id, host.host.id);
    assert!(changed.revision.version > host.revision.version);
    assert_eq!(next.local.keys, state.local.keys);
}
#[test]
fn a_stale_revision_endpoint_or_key_cannot_clear_a_different_trust_decision() {
    let state = pinned();
    let host = get_host(&state, ID).unwrap();
    let endpoint = HostEndpoint {
        hostname: host.effective_payload.hostname,
        port: host.effective_payload.port,
    };
    let pin = host.host.payload.host_key.as_ref().unwrap();
    let mut wrong = pin.clone();
    wrong.fingerprint = "SHA256:other".into();
    assert!(matches!(
        forget_host_key(&state, ID, &host.revision, &endpoint, &wrong, 201),
        Err(RepositoryError::PinConflict(_))
    ));
    let mut old = host.revision.clone();
    old.version -= 1;
    assert!(matches!(
        forget_host_key(&state, ID, &old, &endpoint, pin, 201),
        Err(RepositoryError::RevisionConflict { .. })
    ));
    assert!(matches!(
        forget_host_key(
            &state,
            ID,
            &host.revision,
            &HostEndpoint {
                hostname: "different.test".into(),
                port: 22
            },
            pin,
            201
        ),
        Err(RepositoryError::EndpointChanged(_))
    ));
}

#[test]
fn shared_pin_removal_respects_account_gates_and_queues_a_host_metadata_update() {
    let mut state = pinned();
    let space_id = "a".repeat(64);
    state.account = Some(AccountState::new(&"b".repeat(64)));
    state.spaces.insert(
        space_id.clone(),
        SpaceStateV3 {
            selected: true,
            ..Default::default()
        },
    );
    let host = get_host(&state, ID).unwrap();
    let mut state = move_host(
        &state,
        ID,
        &host.revision,
        HostScope::Space {
            space_id: space_id.clone(),
        },
        201,
    )
    .unwrap();
    let host = get_host(&state, ID).unwrap();
    let endpoint = HostEndpoint {
        hostname: host.effective_payload.hostname,
        port: host.effective_payload.port,
    };
    let pin = host.host.payload.host_key.as_ref().unwrap();
    state.shared_writes_blocked = true;
    assert!(matches!(
        forget_host_key(&state, ID, &host.revision, &endpoint, pin, 202),
        Err(RepositoryError::ReadOnlyAccount)
    ));
    state.shared_writes_blocked = false;
    let next = forget_host_key(&state, ID, &host.revision, &endpoint, pin, 202).unwrap();
    let row = &next.spaces[&space_id].records[&record_key(RecordKind::Host, ID)];
    assert!(row.dirty);
    assert!(row.record.payload["host_key"].is_null());
    assert_eq!(next.account, state.account);
}
