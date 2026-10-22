use super::*;
use crate::sync::{
    central::{append_library_for_test, projection_capture},
    records_v3::{HostPayload, HostScope},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
const HOST: &str = "000000000000a099";
fn fixture() -> (SyncStateV3, VaultKeys, DeviceKeys) {
    let (s, k, _) = super::super::library_fixture_for_test();
    let payload:HostPayload=serde_json::from_value(serde_json::json!({"schema":2,"alias":"password-test","hostname":"fixture-password.invalid","user":"fixture","auth":"password"})).unwrap();
    let s = repo::create_host(&s, HOST, HostScope::Local, payload, 111).unwrap();
    let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
    (s, k, signer)
}
fn material(state: &SyncStateV3, value: &str) -> Data {
    Data::Password(Material {
        binding: binding(&repo::get_host(state, HOST).unwrap()).unwrap(),
        nonce: crypto::random_id(16).unwrap(),
        value: Zeroizing::new(value.into()),
    })
}
#[test]
fn password_sync_encrypts_exact_bytes_and_public_capture_cannot_erase_a_secret_or_its_conflict() {
    let (state, keys, signer) = fixture();
    let host = repo::get_host(&state, HOST).unwrap();
    let id = identity(&host);
    let opaque = id.opaque(&keys).unwrap();
    let mut candidate = enqueue(
        &state,
        &keys,
        &signer,
        id.clone(),
        material(&state, " SYNTHETIC PASSWORD ∎ "),
    )
    .unwrap();
    let record = &candidate
        .local
        .central
        .as_ref()
        .unwrap()
        .replica
        .as_ref()
        .unwrap()
        .pending[&opaque]
        .latest;
    let admitted = open(&candidate, &keys, &record.envelope, &record.content_hash).unwrap();
    assert!(matches!(admitted.data,Data::Password(ref p) if &*p.value==" SYNTHETIC PASSWORD ∎ "));
    assert!(!serde_json::to_string(&candidate)
        .unwrap()
        .contains("SYNTHETIC PASSWORD"));
    candidate = projection_capture::public_candidate(&candidate, &keys, &signer).unwrap();
    assert!(
        !candidate
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[&opaque]
            .latest
            .envelope
            .header
            .deleted
    );
    let other = material(&state, "OTHER SYNTHETIC PASSWORD");
    append_library_for_test(&mut candidate, &keys, id.clone(), other);
    let before = candidate.clone();
    let captured = projection_capture::public_candidate(&candidate, &keys, &signer).unwrap();
    let replica = captured
        .local
        .central
        .as_ref()
        .unwrap()
        .replica
        .as_ref()
        .unwrap();
    assert!(!replica.conflicts[&opaque].is_empty());
    assert_eq!(
        replica.pending[&opaque],
        before
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[&opaque]
    );
    // Host removal creates a real encrypted delete rather than merely omitting the private row.
    let host = repo::get_host(&captured, HOST).unwrap();
    let removed = repo::delete_host(&captured, HOST, &host.revision, 999).unwrap();
    let removed = capture_removed(&removed, &keys, &signer).unwrap();
    assert!(
        removed
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[&opaque]
            .latest
            .envelope
            .header
            .deleted
    );
}
#[test]
fn password_sync_rejects_oversize_malformed_substituted_or_modified_material_without_echoing_it() {
    let (state, keys, signer) = fixture();
    let id = identity(&repo::get_host(&state, HOST).unwrap());
    for value in ["".to_string(), "X".repeat(16 * 1024 + 1)] {
        assert!(payload::encode(&id, &material(&state, &value)).is_err());
    }
    let data = material(&state, "SYNTHETIC PASSWORD");
    let bytes = payload::encode(&id, &data).unwrap();
    let mut other = id.clone();
    other.id = "000000000000a098".into();
    let candidate = enqueue(&state, &keys, &signer, id.clone(), data).unwrap();
    let opaque = id.opaque(&keys).unwrap();
    let draft = &candidate
        .local
        .central
        .as_ref()
        .unwrap()
        .replica
        .as_ref()
        .unwrap()
        .pending[&opaque]
        .latest;
    let mut substituted = draft.envelope.clone();
    substituted.header.record_id = other.opaque(&keys).unwrap();
    assert!(open(&candidate, &keys, &substituted, &draft.content_hash).is_err());
    assert!(open(&candidate, &keys, &draft.envelope, &"0".repeat(64)).is_err());
    // Parsing errors from the native admission boundary are fixed diagnostics.
    let invalid = Zeroizing::new(String::from_utf8(bytes.to_vec()).unwrap().replace(
        "\"payload\":{",
        "\"payload\":{\"unknown_secret\":\"SYNTHETIC PASSWORD\",",
    ));
    let error = payload::admit_snapshot("password", false, invalid.as_bytes())
        .err()
        .unwrap()
        .to_string();
    assert!(!error.contains("SYNTHETIC PASSWORD"));
    assert!(
        other.opaque(&keys).unwrap()
            != identity(&repo::get_host(&state, HOST).unwrap())
                .opaque(&keys)
                .unwrap()
    );
}
#[test]
fn password_sync_retains_exact_sent_operations_and_newer_local_edits() {
    let (state, keys, signer) = fixture();
    let id = identity(&repo::get_host(&state, HOST).unwrap());
    let opaque = id.opaque(&keys).unwrap();
    let mut state = enqueue(
        &state,
        &keys,
        &signer,
        id.clone(),
        material(&state, "sent password A"),
    )
    .unwrap();
    let pending = state
        .local
        .central
        .as_mut()
        .unwrap()
        .replica
        .as_mut()
        .unwrap()
        .pending
        .get_mut(&opaque)
        .unwrap();
    let sent = pending.latest.clone();
    pending.sent = Some(sent.clone());
    let next = enqueue(
        &state,
        &keys,
        &signer,
        id,
        material(&state, "newer password B"),
    )
    .unwrap();
    let pending = &next
        .local
        .central
        .as_ref()
        .unwrap()
        .replica
        .as_ref()
        .unwrap()
        .pending[&opaque];
    assert_eq!(pending.sent.as_ref(), Some(&sent));
    assert!(pending.latest.local_revision > sent.local_revision);
    let value = open(
        &next,
        &keys,
        &pending.latest.envelope,
        &pending.latest.content_hash,
    )
    .unwrap();
    assert!(matches!(value.data,Data::Password(ref value) if &*value.value=="newer password B"));
}
#[test]
fn password_sync_rejects_stale_editor_and_wrong_account_before_changing_saved_material() {
    let d = crate::sync::record_import::central_local::tests::fixture();
    let payload:HostPayload=serde_json::from_value(serde_json::json!({"schema":2,"alias":"fenced-password","hostname":"fenced.invalid","user":"fixture","auth":"password"})).unwrap();
    crate::sync::record_commands::edit_records(&d.env(), |s, now| {
        repo::create_host(s, HOST, HostScope::Local, payload.clone(), now).map_err(|_| invalid())
    })
    .unwrap();
    let (state, generation) = record_runtime::snapshot(&d.env()).unwrap();
    let host = repo::get_host(&state, HOST).unwrap();
    let expected = central_local::invocation(&state)
        .unwrap()
        .with_generation(generation);
    assert!(change(
        &d.env(),
        HOST,
        &host.revision,
        generation + 1,
        Some(&expected),
        Some("never submitted")
    )
    .is_err());
    assert!(change(
        &d.env(),
        HOST,
        &host.revision,
        generation,
        None,
        Some("never submitted")
    )
    .is_err());
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap().0, state);
    change(
        &d.env(),
        HOST,
        &host.revision,
        generation,
        Some(&expected),
        Some("correct synthetic password"),
    )
    .unwrap();
    assert_eq!(
        read(&d.env(), HOST).unwrap().as_deref().map(String::as_str),
        Some("correct synthetic password")
    );
    assert!(change(
        &d.env(),
        HOST,
        &host.revision,
        generation,
        Some(&expected),
        None
    )
    .is_err());
    assert_eq!(
        read(&d.env(), HOST).unwrap().as_deref().map(String::as_str),
        Some("correct synthetic password")
    );
}
