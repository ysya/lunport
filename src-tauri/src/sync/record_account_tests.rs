use super::*;
use crate::sync::crypto::{self, ChainKeys};
use crate::sync::env::Keychain;
use crate::sync::fake_relay::FakeRelay;
use crate::sync::record::{record_key, LocalRecord, Record, RecordKind, ACCOUNT_META_ID};
use crate::sync::record_merge::encode_record;
use crate::sync::record_runtime::{self, StartupProbe};
use crate::sync::relay::RelayApi;
use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::testkit::{MemKeychain, TestClock, TestDevice};
use serde_json::json;
use std::sync::{Arc, Mutex};
const HOST: &str = "0000000000000001";
fn fresh() -> Arc<TestDevice> {
    let d = Arc::new(TestDevice::new("a", &FakeRelay::new(), &TestClock::new()));
    let env = d.env();
    let StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&env.state_path, "fixture")
    else {
        panic!("fresh")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    state.local.hosts.insert(record_key(RecordKind::Host,HOST),LocalRecord{record:Record{kind:RecordKind::Host,id:HOST.into(),version:1,updated_at_ms:1,device_id:state.device_id.clone(),deleted:false,payload:json!({"schema":2,"alias":"local","hostname":"local.test","auth":"password"})},seq:0,dirty:false});
    record_runtime::activate_probe(
        &mut d.runtime.core.lock().unwrap(),
        StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    let (s, g) = record_runtime::snapshot(&env).unwrap();
    record_runtime::commit_candidate(&env, g, s).unwrap();
    d
}
fn state(d: &TestDevice) -> crate::sync::records_v3::SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
fn remote(d: &TestDevice, schema: u32) -> (String, ChainKeys) {
    let phrase = crypto::generate_mnemonic().unwrap();
    let keys = crypto::derive_account(&phrase).unwrap();
    d.relay
        .create_chain(&keys.chain_id, &keys.auth_token)
        .unwrap();
    let meta = Record {
        kind: RecordKind::Meta,
        id: ACCOUNT_META_ID.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema_version":schema,"created_by_app_version":"test"}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &meta, 0).unwrap()],
        )
        .unwrap();
    (phrase, keys)
}
fn joined() -> (Arc<TestDevice>, ChainKeys) {
    let d = fresh();
    let (phrase, keys) = remote(&d, 3);
    join_account(&d.env(), &phrase, "station").unwrap();
    (d, keys)
}
#[test]
fn new_account_is_schema_three_and_preserves_local_workspace_without_ssh_writers() {
    let d = fresh();
    let local = state(&d).local;
    let config = d.ssh_dir().join("config");
    let bytes = std::fs::read(&config).unwrap();
    let created = create_account(&d.env(), "station").unwrap();
    assert!(created.complete);
    let keys = crypto::derive_account(&created.code).unwrap();
    let after = state(&d);
    assert_eq!(after.account.as_ref().unwrap().chain_id, keys.chain_id);
    assert!(after.pending_account.is_none());
    assert_eq!(after.local, local);
    assert_eq!(
        after.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, ACCOUNT_META_ID)]
            .record
            .payload["schema_version"],
        json!(3)
    );
    assert_eq!(std::fs::read(config).unwrap(), bytes);
    assert!(!d.ssh_dir().join("sshelter").exists());
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_some());
    assert!(d
        .keychain
        .entry(&format!("{PENDING_CODE_PREFIX}{}", created.operation_id))
        .is_none());
    assert!(!format!("{created:?}").contains(&*created.code));
}
#[test]
fn failed_account_create_keeps_fixed_identity_and_resumes_the_same_operation() {
    let d = fresh();
    d.relay.fail_creates_with_429(1);
    let created = create_account(&d.env(), "station").unwrap();
    assert!(!created.complete);
    let pending = state(&d).pending_account.unwrap();
    let chain = pending.prepared_account.chain_id.clone();
    assert_eq!(pending.id, created.operation_id);
    assert!(!d.relay.exists(&chain));
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_none());
    resume_pending(&d.env(), None).unwrap();
    assert_eq!(state(&d).account.unwrap().chain_id, chain);
    assert!(state(&d).pending_account.is_none());
    assert!(d.relay.exists(&chain));
}
struct DenyPending<'a> {
    inner: &'a MemKeychain,
    deny: std::sync::atomic::AtomicBool,
    calls: Mutex<Vec<String>>,
}
impl Keychain for DenyPending<'_> {
    fn get(&self, a: &str) -> Result<Option<String>, AppError> {
        self.inner.get(a)
    }
    fn set(&self, a: &str, s: &str) -> Result<(), AppError> {
        self.calls.lock().unwrap().push(a.into());
        if self.deny.load(std::sync::atomic::Ordering::SeqCst) && a.starts_with(PENDING_CODE_PREFIX)
        {
            return Err(AppError::Other("denied".into()));
        }
        self.inner.set(a, s)
    }
    fn delete(&self, a: &str) -> Result<(), AppError> {
        self.inner.delete(a)
    }
}
#[test]
fn staged_code_denial_has_durable_id_no_remote_effect_and_explicit_code_retry() {
    let d = fresh();
    let keychain = DenyPending {
        inner: &d.keychain,
        deny: std::sync::atomic::AtomicBool::new(true),
        calls: Mutex::new(vec![]),
    };
    let mut env = d.env();
    env.keychain = &keychain;
    d.relay.clear_calls();
    let result = create_account(&env, "station").unwrap();
    assert!(!result.complete);
    assert!(d.relay.calls().is_empty());
    let pending = state(&d).pending_account.unwrap();
    assert_eq!(pending.id, result.operation_id);
    let disk: crate::sync::records_v3::SyncStateV3 =
        serde_json::from_slice(&std::fs::read(env.state_path.clone()).unwrap()).unwrap();
    assert_eq!(disk.pending_account.unwrap().id, result.operation_id);
    keychain
        .deny
        .store(false, std::sync::atomic::Ordering::SeqCst);
    resume_pending(&env, Some(&result.code)).unwrap();
    assert!(state(&d).pending_account.is_none());
    assert_eq!(
        state(&d).account.unwrap().chain_id,
        pending.prepared_account.chain_id
    );
}
#[test]
fn joining_old_schema_does_not_write_keychain_journal_or_any_local_state() {
    let d = fresh();
    let (code, _) = remote(&d, 2);
    let before = state(&d);
    let bytes = std::fs::read(d.env().state_path).unwrap();
    d.relay.clear_calls();
    let e = join_account(&d.env(), &code, "station").unwrap_err();
    assert!(e.to_string().contains("migration"));
    assert_eq!(state(&d), before);
    assert_eq!(std::fs::read(d.env().state_path).unwrap(), bytes);
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_none());
    assert_eq!(d.relay.calls().len(), 1);
    assert!(d.relay.calls()[0].starts_with("pull:"));
}
#[test]
fn compatible_join_preserves_local_hosts_and_incoming_private_transport_stays_sealed() {
    let d = fresh();
    let local = state(&d).local;
    let (code, keys) = remote(&d, 3);
    let key = Record {
        kind: RecordKind::Key,
        id: "a".repeat(32),
        version: 1,
        updated_at_ms: 2,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema":1,"private_key":"fixture-secret-only"}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &key, 0).unwrap()],
        )
        .unwrap();
    join_account(&d.env(), &code, "station").unwrap();
    let after = state(&d);
    assert_eq!(after.local, local);
    assert!(after
        .account
        .as_ref()
        .unwrap()
        .records
        .values()
        .all(|r| !r.record.kind.is_secret()));
    assert_eq!(after.account.as_ref().unwrap().sealed.len(), 1);
    assert!(!serde_json::to_string(&after)
        .unwrap()
        .contains("fixture-secret-only"));
    assert!(after.pending_account.is_none());
}
#[test]
fn current_code_promotion_failure_preserves_pending_stage_and_join_retry_identity() {
    let d = fresh();
    let (code, keys) = remote(&d, 3);
    d.keychain.fail_writes_to(MNEMONIC_ACCOUNT, true);
    assert!(join_account(&d.env(), &code, "station").is_err());
    let pending = state(&d).pending_account.unwrap();
    assert_eq!(pending.phase, PendingAccountPhase::ActivationReady);
    assert!(state(&d).account.is_none());
    assert!(d
        .keychain
        .entry(pending.staged_code_account.as_deref().unwrap())
        .is_some());
    d.keychain.fail_writes_to(MNEMONIC_ACCOUNT, false);
    join_account(&d.env(), &code, "station").unwrap();
    assert_eq!(state(&d).account.unwrap().chain_id, keys.chain_id);
    assert!(state(&d).pending_account.is_none());
}
#[test]
fn cleanup_denial_keeps_activated_journal_until_idempotent_retry() {
    let d = fresh();
    let (code, keys) = remote(&d, 3);
    d.keychain
        .fail_deletes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(join_account(&d.env(), &code, "station").is_err());
    let pending = state(&d).pending_account.unwrap();
    assert_eq!(pending.phase, PendingAccountPhase::Activated);
    assert_eq!(state(&d).account.as_ref().unwrap().chain_id, keys.chain_id);
    assert!(crate::sync::records_v3::account_writes_blocked(&state(&d)));
    d.keychain
        .fail_deletes
        .store(false, std::sync::atomic::Ordering::SeqCst);
    resume_pending(&d.env(), None).unwrap();
    assert!(state(&d).pending_account.is_none());
}
#[test]
fn space_create_partial_success_uses_same_sealed_credentials_and_space_id() {
    let (d, _) = joined();
    d.relay.fail_creates_with_429(1);
    assert!(create_space(&d.env(), "Personal").is_err());
    let op = state(&d).pending_account.unwrap();
    let id = op.space_id.clone().unwrap();
    let serialized = serde_json::to_string(&op).unwrap();
    assert!(!serialized.contains("auth_token"));
    assert!(!serialized.contains("enc_key"));
    let envelope = op
        .prepared_account
        .sealed
        .values()
        .find(|r| r.envelope.kind == "spacekey")
        .unwrap()
        .envelope
        .clone();
    resume_pending(&d.env(), None).unwrap();
    let after = state(&d);
    assert!(after.pending_account.is_none());
    assert!(after.spaces[&id].selected);
    assert!(after.spaces[&id].baseline_established);
    assert!(d.relay.exists(&id));
    let accepted = after
        .account
        .unwrap()
        .sealed
        .into_values()
        .find(|r| r.envelope.id_hash == envelope.id_hash)
        .unwrap();
    assert_eq!(accepted.envelope.ciphertext, envelope.ciphertext);
}
#[test]
fn space_select_and_rename_require_fresh_format_before_staging_any_change() {
    let (d, keys) = joined();
    let id = create_space(&d.env(), "Before").unwrap();
    let prior = d
        .relay
        .rows(&keys.chain_id)
        .into_iter()
        .find(|r| r.kind == "meta")
        .unwrap()
        .seq;
    let future = Record {
        kind: RecordKind::Meta,
        id: ACCOUNT_META_ID.into(),
        version: 2,
        updated_at_ms: u64::MAX,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema_version":4,"created_by_app_version":"future"}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &future, prior).unwrap()],
        )
        .unwrap();
    let before = state(&d);
    d.relay.clear_calls();
    assert!(select_space(&d.env(), &id, false).is_err());
    assert!(rename_space(&d.env(), &id, "Changed").is_err());
    let after = state(&d);
    assert_eq!(after.spaces, before.spaces);
    assert_eq!(
        after.account.as_ref().unwrap().records,
        before.account.as_ref().unwrap().records
    );
    assert!(!d
        .relay
        .calls()
        .iter()
        .any(|c| c.starts_with("push:") || c.starts_with("create:")));
}

#[test]
fn staged_device_name_is_trimmed_persisted_and_published_as_own_device_metadata() {
    let d = fresh();
    let result = create_account(&d.env(), "  Station A  ").unwrap();
    assert!(result.complete);
    let current = state(&d);
    assert_eq!(current.device_name, "Station A");
    let row = &current.account.as_ref().unwrap().records
        [&record_key(RecordKind::Device, &current.device_id)];
    assert_eq!(row.record.payload["name"], json!("Station A"));
    assert!(!row.dirty);
}

fn public(text: &str, state: &crate::sync::records_v3::SyncStateV3) -> KeySlotPayload {
    let key = crate::vault::material::parse(text).unwrap();
    KeySlotPayload {
        schema: 2,
        name: "sync key".into(),
        public_key: key.public_key().to_openssh().unwrap(),
        fingerprint: key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        key_type: key.algorithm().as_str().into(),
        has_passphrase: key.is_encrypted(),
        created_at_ms: 1,
        origin_device_id: state.device_id.clone(),
    }
}
#[test]
fn explicit_key_publish_stays_sealed_and_stamps_after_the_latest_private_revision() {
    let (d, keys) = joined();
    let private = crate::sync::slot_rules::test_keys::plain();
    let metadata = public(&private, &state(&d));
    let id = "a".repeat(32);
    let slot = Record {
        kind: RecordKind::KeySlot,
        id: id.clone(),
        version: 1,
        updated_at_ms: 2,
        device_id: "d".repeat(32),
        deleted: false,
        payload: serde_json::to_value(&metadata).unwrap(),
    };
    let secret = Record {
        kind: RecordKind::Key,
        id: id.clone(),
        version: 7,
        updated_at_ms: 4_000_000_000_000,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema":1,"private_key":private}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[
                encode_record(&keys, &slot, 0).unwrap(),
                encode_record(&keys, &secret, 0).unwrap(),
            ],
        )
        .unwrap();
    publish_key(&d.env(), &id, metadata, Zeroizing::new(private.clone())).unwrap();
    let after = state(&d);
    let revision =
        record_merge::secret_revision(after.account.as_ref().unwrap(), &keys, RecordKind::Key, &id)
            .unwrap()
            .unwrap();
    assert_eq!(revision.version, 8);
    assert_eq!(revision.updated_at_ms, 4_000_000_000_001);
    assert_eq!(revision.device_id, after.device_id);
    assert!(!serde_json::to_string(&after)
        .unwrap()
        .contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(after
        .account
        .as_ref()
        .unwrap()
        .records
        .values()
        .all(|r| !r.record.kind.is_secret()));
    assert!(after
        .account
        .as_ref()
        .unwrap()
        .sealed
        .values()
        .all(|r| !r.dirty));
    assert!(!crate::vault::store::vault_path(&d.env().state_path).exists());
}
#[test]
fn private_identity_mismatch_fails_before_any_account_or_relay_mutation() {
    let (d, _) = joined();
    let text = crate::sync::slot_rules::test_keys::plain();
    let metadata = public(
        &crate::sync::slot_rules::test_keys::ecdsa_full_p256(),
        &state(&d),
    );
    let before = state(&d);
    d.relay.clear_calls();
    assert!(publish_key(&d.env(), &"a".repeat(32), metadata, Zeroizing::new(text)).is_err());
    assert_eq!(state(&d), before);
    assert!(d.relay.calls().is_empty());
}

#[test]
fn activated_cleanup_rechecks_account_format_before_deleting_staged_credentials() {
    let d = fresh();
    let (code, keys) = remote(&d, 3);
    d.keychain
        .fail_deletes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(join_account(&d.env(), &code, "station").is_err());
    let pending = state(&d).pending_account.unwrap();
    let name = pending.staged_code_account.unwrap();
    let previous = d
        .relay
        .rows(&keys.chain_id)
        .iter()
        .find(|r| r.kind == "meta")
        .unwrap()
        .seq;
    let future = Record {
        kind: RecordKind::Meta,
        id: ACCOUNT_META_ID.into(),
        version: 2,
        updated_at_ms: u64::MAX,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema_version":4,"created_by_app_version":"future"}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &future, previous).unwrap()],
        )
        .unwrap();
    d.keychain
        .fail_deletes
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(resume_pending(&d.env(), None).is_err());
    assert!(d.keychain.entry(&name).is_some());
    assert!(state(&d).pending_account.is_some());
    assert!(state(&d).shared_writes_blocked);
}

#[test]
fn unknown_keyslot_authority_cannot_be_replaced_by_explicit_publish() {
    let (d, keys) = joined();
    let private = crate::sync::slot_rules::test_keys::plain();
    let metadata = public(&private, &state(&d));
    let id = "a".repeat(32);
    let opaque = Record {
        kind: RecordKind::KeySlot,
        id: id.clone(),
        version: 1,
        updated_at_ms: 2,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema":99,"name":"future"}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &opaque, 0).unwrap()],
        )
        .unwrap();
    crate::sync::record_round::fresh_account_gate(&d.env()).unwrap();
    let before = state(&d);
    d.relay.clear_calls();
    assert!(publish_key(&d.env(), &id, metadata, Zeroizing::new(private)).is_err());
    let after = state(&d);
    assert_eq!(
        after.account.as_ref().unwrap().records,
        before.account.as_ref().unwrap().records
    );
    assert_eq!(
        after.account.as_ref().unwrap().sealed,
        before.account.as_ref().unwrap().sealed
    );
    assert!(!d.relay.calls().iter().any(|c| c.starts_with("push:")));
}
fn put_incoming_key(d: &TestDevice, keys: &ChainKeys, id: &str, private: &str) -> KeySlotPayload {
    let metadata = public(private, &state(d));
    let slot = Record {
        kind: RecordKind::KeySlot,
        id: id.into(),
        version: 1,
        updated_at_ms: 2,
        device_id: "d".repeat(32),
        deleted: false,
        payload: serde_json::to_value(&metadata).unwrap(),
    };
    let secret = Record {
        kind: RecordKind::Key,
        id: id.into(),
        version: 1,
        updated_at_ms: 2,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema":1,"private_key":private}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[
                encode_record(keys, &slot, 0).unwrap(),
                encode_record(keys, &secret, 0).unwrap(),
            ],
        )
        .unwrap();
    metadata
}
#[test]
fn explicit_synced_download_activates_validated_vault_material_without_plaintext_state_or_files() {
    let (d, keys) = joined();
    let private = crate::sync::slot_rules::test_keys::plain();
    let id = "a".repeat(32);
    let metadata = put_incoming_key(&d, &keys, &id, &private);
    let path = d.ssh_dir().join("config");
    let original = std::fs::read(&path).unwrap();
    download_key(&d.env(), &id).unwrap();
    let after = state(&d);
    let local = &after.local.keys[&id];
    assert_eq!(local.public, metadata);
    let vault = crate::vault::store::read_vault(
        &crate::vault::store::vault_path(&d.env().state_path),
        &d.keychain,
    )
    .unwrap();
    assert_eq!(
        vault.get(&local.vault_id).unwrap().unwrap().private_key,
        private
    );
    assert_eq!(std::fs::read(path).unwrap(), original);
    assert!(after
        .account
        .as_ref()
        .unwrap()
        .records
        .values()
        .all(|r| !r.record.kind.is_secret()));
    assert!(!serde_json::to_string(&after)
        .unwrap()
        .contains("BEGIN OPENSSH PRIVATE KEY"));
}
#[test]
fn synced_download_refuses_a_local_public_identity_conflict_without_creating_a_vault() {
    let (d, keys) = joined();
    let private = crate::sync::slot_rules::test_keys::plain();
    let id = "a".repeat(32);
    put_incoming_key(&d, &keys, &id, &private);
    let other = public(
        &crate::sync::slot_rules::test_keys::ecdsa_full_p256(),
        &state(&d),
    );
    record_runtime::mutate_records(&d.env(), |s| {
        let mut next = s.clone();
        next.local.keys.insert(
            id.clone(),
            records_v3::LocalKeyMetadata {
                vault_id: "b".repeat(32),
                public: other,
            },
        );
        Ok(next)
    })
    .unwrap();
    let before = state(&d).local;
    assert!(download_key(&d.env(), &id).is_err());
    assert_eq!(state(&d).local, before);
    assert!(!crate::vault::store::vault_path(&d.env().state_path).exists());
}
#[test]
fn synced_download_fresh_future_gate_stops_before_vault_material() {
    let (d, keys) = joined();
    let private = crate::sync::slot_rules::test_keys::plain();
    let id = "a".repeat(32);
    put_incoming_key(&d, &keys, &id, &private);
    let previous = d
        .relay
        .rows(&keys.chain_id)
        .iter()
        .find(|r| r.kind == "meta")
        .unwrap()
        .seq;
    let future = Record {
        kind: RecordKind::Meta,
        id: ACCOUNT_META_ID.into(),
        version: 2,
        updated_at_ms: u64::MAX,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema_version":4,"created_by_app_version":"future"}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &future, previous).unwrap()],
        )
        .unwrap();
    assert!(download_key(&d.env(), &id).is_err());
    assert!(state(&d).shared_writes_blocked);
    assert!(!crate::vault::store::vault_path(&d.env().state_path).exists());
}

#[test]
fn known_future_pending_account_retry_only_polls_and_never_rewrites_staged_credentials() {
    let d = fresh();
    d.relay.fail_creates_with_429(1);
    let created = create_account(&d.env(), "station").unwrap();
    assert!(!created.complete);
    let keys = crypto::derive_account(&created.code).unwrap();
    d.relay
        .create_chain(&keys.chain_id, &keys.auth_token)
        .unwrap();
    let future = Record {
        kind: RecordKind::Meta,
        id: ACCOUNT_META_ID.into(),
        version: 1,
        updated_at_ms: u64::MAX,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema_version":4,"created_by_app_version":"future"}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &future, 0).unwrap()],
        )
        .unwrap();
    assert!(resume_pending(&d.env(), None).is_err());
    let keychain = DenyPending {
        inner: &d.keychain,
        deny: std::sync::atomic::AtomicBool::new(false),
        calls: Mutex::new(vec![]),
    };
    let mut env = d.env();
    env.keychain = &keychain;
    d.relay.clear_calls();
    assert!(resume_pending(&env, Some(&created.code)).is_err());
    assert!(keychain.calls.lock().unwrap().is_empty());
    assert_eq!(
        d.relay.calls(),
        vec![format!("pull:{}", &keys.chain_id[..8])]
    );
}

#[test]
fn unpublish_only_tombstones_transport_and_keeps_public_metadata_and_local_vault() {
    let (d, keys) = joined();
    let text = crate::sync::slot_rules::test_keys::plain();
    let id = "a".repeat(32);
    put_incoming_key(&d, &keys, &id, &text);
    download_key(&d.env(), &id).unwrap();
    let before = state(&d);
    let local = before.local.keys[&id].clone();
    let public = before.account.as_ref().unwrap().records[&record_key(RecordKind::KeySlot, &id)]
        .record
        .clone();
    d.relay.clear_calls();
    unpublish_key(&d.env(), &id).unwrap();
    let after = state(&d);
    assert_eq!(after.local, before.local);
    assert_eq!(
        after.account.as_ref().unwrap().records[&record_key(RecordKind::KeySlot, &id)].record,
        public
    );
    assert!(
        record_merge::secret_revision(after.account.as_ref().unwrap(), &keys, RecordKind::Key, &id)
            .unwrap()
            .unwrap()
            .deleted
    );
    assert!(
        record_merge::key_secret(after.account.as_ref().unwrap(), &keys, &id)
            .unwrap()
            .is_none()
    );
    let vault = crate::vault::store::read_vault(
        &crate::vault::store::vault_path(&d.env().state_path),
        &d.keychain,
    )
    .unwrap();
    assert_eq!(
        vault.get(&local.vault_id).unwrap().unwrap().private_key,
        text
    );
    assert!(!d.relay.calls().iter().any(|c| c.starts_with("delete:")));
}

#[test]
fn explicitly_publishing_migrated_own_slot_upgrades_the_same_wire_identity_with_cas() {
    let (d, keys) = joined();
    let id = "a".repeat(32);
    let s = state(&d);
    let old = Record {
        kind: RecordKind::KeySlot,
        id: id.clone(),
        version: 7,
        updated_at_ms: 8000,
        device_id: s.device_id.clone(),
        deleted: false,
        payload: json!({"schema":1,"name":"old-own","mode":"own","origin_device_id":s.device_id,"created_at_ms":1,"public_key":null,"fingerprint":null,"key_type":null,"has_passphrase":null}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &old, 0).unwrap()],
        )
        .unwrap();
    crate::sync::record_round::sync_once(&d.env()).unwrap();
    let text = crate::sync::slot_rules::test_keys::plain();
    publish_key(
        &d.env(),
        &id,
        public(&text, &state(&d)),
        Zeroizing::new(text.clone()),
    )
    .unwrap();
    let after = state(&d);
    let a = after.account.as_ref().unwrap();
    assert!(!a.sealed.contains_key(&sealed_key(
        "keyslot",
        &crypto::id_hash(&keys, "keyslot", &id)
    )));
    let row = &a.records[&record_key(RecordKind::KeySlot, &id)];
    assert_eq!(row.record.payload["schema"], json!(2));
    assert!(row.record.version > old.version);
    assert!(row.record.updated_at_ms > old.updated_at_ms);
    assert!(!row.dirty);
    assert!(row.seq > 0);
    assert_eq!(
        record_merge::key_secret(a, &keys, &id)
            .unwrap()
            .unwrap()
            .as_str(),
        text
    );
    let remote = d.relay.pull(&keys.chain_id, &keys.auth_token, 0).unwrap();
    let slot = remote.records.iter().find(|r| r.kind == "keyslot").unwrap();
    assert_eq!(slot.seq, row.seq);
    assert!(!serde_json::to_string(&after).unwrap().contains(&text));
}
