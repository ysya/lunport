use super::*;
use crate::sync::env::Keychain;
use crate::sync::fake_relay::FakeRelay;
use crate::sync::record::{record_key, LocalRecord, Record, RecordKind, ACCOUNT_META_ID};
use crate::sync::records_v3::SyncStateV3;
use crate::sync::relay::RelayApi;
use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::testkit::{TestClock, TestDevice};
use crate::sync::{record_account, record_merge, record_round, record_runtime};
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
const A: &str = "0000000000000001";
const B: &str = "0000000000000002";
const LOCAL: &str = "0000000000000099";
fn state(d: &TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
fn fixture() -> (Arc<TestDevice>, String, crate::sync::crypto::ChainKeys) {
    let d = Arc::new(TestDevice::new(
        "leave",
        &FakeRelay::new(),
        &TestClock::new(),
    ));
    let crate::sync::record_runtime::StartupProbe::Records {
        state: mut active, ..
    } = record_runtime::probe_startup(&d.env().state_path, "fixture")
    else {
        panic!()
    };
    active.relay_url = crate::sync::testkit::RELAY_URL.into();
    active.local.hosts.insert(record_key(RecordKind::Host,LOCAL),LocalRecord{record:Record{kind:RecordKind::Host,id:LOCAL.into(),version:1,updated_at_ms:1,device_id:active.device_id.clone(),deleted:false,payload:json!({"schema":2,"alias":"jump","hostname":"local.test","auth":"password"})},seq:0,dirty:false});
    record_runtime::activate_probe(
        &mut d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state: active,
            fresh: false,
        },
    )
    .unwrap();
    let created = record_account::create_account(&d.env(), "fixture").unwrap();
    assert!(created.complete);
    let sid = record_account::create_space(&d.env(), "Space").unwrap();
    let s = state(&d);
    let keys = d.runtime.core.lock().unwrap().account_keys.clone().unwrap();
    let child = record_merge::space_keys(s.account.as_ref().unwrap(), &keys, &sid)
        .unwrap()
        .unwrap();
    for (id, alias, jump) in [(A, "jump", vec![]), (B, "server", vec![A])] {
        let r = Record {
            kind: RecordKind::Host,
            id: id.into(),
            version: 2,
            updated_at_ms: 2,
            device_id: s.device_id.clone(),
            deleted: false,
            payload: json!({"schema":2,"alias":alias,"hostname":format!("{alias}.test"),"auth":"password","jump":jump,"tags":["preserved"],"notes":"keep notes"}),
        };
        d.relay
            .push(
                &sid,
                &child.auth_token,
                &[record_merge::encode_record(&child, &r, 0).unwrap()],
            )
            .unwrap();
    }
    record_round::sync_once(&d.env()).unwrap();
    d.keychain
        .set(&format!("host:{A}"), "fixture password A")
        .unwrap();
    d.keychain
        .set(&format!("host:{B}"), "fixture password B")
        .unwrap();
    d.relay.clear_calls();
    (d, sid, keys)
}

#[test]
fn rotation_copies_host_two_keyslot_two_and_sealed_private_material_without_local_writers() {
    let (d, sid, old) = fixture();
    let before = state(&d);
    let private = crate::sync::slot_rules::test_keys::plain();
    let inspected = crate::vault::material::parse(&private).unwrap();
    let public = crate::sync::records_v3::KeySlotPayload {
        schema: 2,
        name: "own".into(),
        public_key: inspected.public_key().to_openssh().unwrap(),
        fingerprint: inspected
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        key_type: inspected.algorithm().as_str().into(),
        has_passphrase: false,
        created_at_ms: 1,
        origin_device_id: before.device_id.clone(),
    };
    let kid = "a".repeat(32);
    record_account::publish_key(
        &d.env(),
        &kid,
        public.clone(),
        zeroize::Zeroizing::new(private.clone()),
    )
    .unwrap();
    let local = state(&d).local;
    let config = std::fs::read(d.ssh_dir().join("config")).unwrap();
    d.relay.clear_calls();
    let r = start_rotation(&d.env(), " Rotated ").unwrap();
    assert!(r.complete, "{:?}", r);
    let new = crate::sync::crypto::derive_account(&r.code).unwrap();
    let after = state(&d);
    assert_eq!(after.account.as_ref().unwrap().chain_id, new.chain_id);
    assert_ne!(new.chain_id, old.chain_id);
    assert!(after.pending_account.is_none());
    assert_eq!(after.local, local);
    assert_eq!(after.device_name, "Rotated");
    let (newid, space) = after.spaces.iter().find(|(_, s)| s.selected).unwrap();
    assert_ne!(newid, &sid);
    assert!(space.records.contains_key(&record_key(RecordKind::Host, A)));
    assert_eq!(
        space.records[&record_key(RecordKind::Host, B)]
            .record
            .payload["jump"],
        json!([A])
    );
    let acct = after.account.as_ref().unwrap();
    assert_eq!(
        acct.records[&record_key(RecordKind::Space, newid)]
            .record
            .payload["previous_id"],
        json!(sid)
    );
    assert_eq!(
        acct.records[&record_key(RecordKind::KeySlot, &kid)]
            .record
            .payload["schema"],
        json!(2)
    );
    assert_eq!(
        &*record_merge::key_secret(acct, &new, &kid).unwrap().unwrap(),
        &private
    );
    assert!(d.relay.exists(&old.chain_id));
    assert!(d.relay.exists(&sid));
    assert!(d.relay.calls().iter().all(|c| !c.starts_with("delete:")));
    assert_eq!(std::fs::read(d.ssh_dir().join("config")).unwrap(), config);
    assert!(!serde_json::to_string(&after).unwrap().contains(&private));
}
#[test]
fn unselected_live_space_is_copied_and_remains_unselected() {
    let (d, sid, _) = fixture();
    record_account::select_space(&d.env(), &sid, false).unwrap();
    let r = start_rotation(&d.env(), "rotate").unwrap();
    assert!(r.complete);
    let s = state(&d);
    assert_eq!(s.spaces.len(), 1);
    assert!(!s.spaces.values().next().unwrap().selected);
    assert!(s
        .spaces
        .values()
        .next()
        .unwrap()
        .records
        .contains_key(&record_key(RecordKind::Host, A)));
}
#[test]
fn missing_live_space_refuses_before_source_freeze_or_scoped_code_staging() {
    let (d, sid, old) = fixture();
    let s = state(&d);
    let child = record_merge::space_keys(s.account.as_ref().unwrap(), &old, &sid)
        .unwrap()
        .unwrap();
    d.relay.delete_chain(&sid, &child.auth_token).unwrap();
    d.relay.clear_calls();
    assert!(start_rotation(&d.env(), "rotate").is_err());
    assert!(state(&d).pending_account.is_none());
    assert_eq!(state(&d).local, s.local);
    assert!(!d
        .relay
        .calls()
        .iter()
        .any(|c| c.starts_with("freeze:") || c.starts_with("create:")));
}
#[test]
fn partial_target_publication_keeps_source_code_and_retries_fixed_identity() {
    let (d, _, old) = fixture();
    let phrase = d.keychain.entry(MNEMONIC_ACCOUNT).unwrap();
    d.relay.set_push_quota(Some(1));
    let r = start_rotation(&d.env(), "rotate").unwrap();
    assert!(!r.complete);
    let op = state(&d).pending_account.unwrap();
    let target = op.prepared_account.chain_id.clone();
    assert_ne!(target, old.chain_id);
    assert_eq!(d.keychain.entry(MNEMONIC_ACCOUNT).unwrap(), phrase);
    assert_eq!(state(&d).account.unwrap().chain_id, old.chain_id);
    assert!(!format!("{r:?}").contains(&*r.code));
    d.relay.set_push_quota(None);
    record_account::resume_pending(&d.env(), None).unwrap();
    assert_eq!(state(&d).account.unwrap().chain_id, target);
    assert!(state(&d).pending_account.is_none());
}
#[test]
fn future_source_format_refuses_before_staging_new_code_or_freeze() {
    let (d, _, old) = fixture();
    let s = state(&d);
    let row = &s.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, ACCOUNT_META_ID)];
    let mut meta = row.record.clone();
    meta.payload["schema_version"] = json!(5);
    meta.version += 1;
    meta.updated_at_ms += 1;
    d.relay
        .push(
            &old.chain_id,
            &old.auth_token,
            &[record_merge::encode_record(&old, &meta, row.seq).unwrap()],
        )
        .unwrap();
    d.relay.clear_calls();
    assert!(start_rotation(&d.env(), "rotate").is_err());
    assert!(state(&d).pending_account.is_none());
    assert_eq!(state(&d).local, s.local);
    assert!(!d
        .relay
        .calls()
        .iter()
        .any(|c| c.starts_with("freeze:") || c.starts_with("create:")));
}
#[test]
fn future_target_format_during_retry_refuses_push_and_current_code_promotion() {
    let (d, _, old) = fixture();
    d.relay.set_push_quota(Some(0));
    let r = start_rotation(&d.env(), "rotate").unwrap();
    assert!(!r.complete);
    let next = crate::sync::crypto::derive_account(&r.code).unwrap();
    d.relay.set_push_quota(None);
    let meta = Record {
        kind: RecordKind::Meta,
        id: ACCOUNT_META_ID.into(),
        version: 10,
        updated_at_ms: u64::MAX,
        device_id: state(&d).device_id.clone(),
        deleted: false,
        payload: json!({"schema_version":5,"created_by_app_version":"future"}),
    };
    d.relay
        .push(
            &next.chain_id,
            &next.auth_token,
            &[record_merge::encode_record(&next, &meta, 0).unwrap()],
        )
        .unwrap();
    d.relay.clear_calls();
    assert!(record_account::resume_pending(&d.env(), None).is_err());
    assert_eq!(state(&d).account.unwrap().chain_id, old.chain_id);
    assert_eq!(
        crate::sync::crypto::derive_account(&d.keychain.entry(MNEMONIC_ACCOUNT).unwrap())
            .unwrap()
            .chain_id,
        old.chain_id
    );
    assert!(d.relay.calls().iter().all(|c| c.starts_with("pull:")));
}
#[test]
fn current_code_promotion_denial_keeps_source_and_resumes_complete_target() {
    let (d, _, old) = fixture();
    let phrase = d.keychain.entry(MNEMONIC_ACCOUNT).unwrap();
    d.keychain.fail_writes_to(MNEMONIC_ACCOUNT, true);
    let r = start_rotation(&d.env(), "rotate").unwrap();
    assert!(!r.complete);
    assert_eq!(d.keychain.entry(MNEMONIC_ACCOUNT).unwrap(), phrase);
    assert_eq!(state(&d).account.unwrap().chain_id, old.chain_id);
    d.keychain.fail_writes_to(MNEMONIC_ACCOUNT, false);
    record_account::resume_pending(&d.env(), None).unwrap();
    assert!(state(&d).pending_account.is_none());
    assert_ne!(state(&d).account.unwrap().chain_id, old.chain_id);
}
#[test]
fn pending_leave_and_migration_are_mutually_exclusive_with_rotation() {
    let (d, _, _) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.migration_gate = Some(crate::sync::records_v3::MigrationGate {
            id: "f".repeat(32),
            source_digest: "a".repeat(64),
            phase: crate::sync::records_v3::MigrationPhase::Publishing,
        });
        Ok(n)
    })
    .unwrap();
    let before = state(&d);
    assert!(start_rotation(&d.env(), "rotate").is_err());
    assert_eq!(state(&d), before);
}
#[test]
fn retained_future_source_observation_cannot_be_cleared_by_an_older_supported_pull() {
    let (d, _, old) = fixture();
    d.relay.set_push_quota(Some(0));
    let r = start_rotation(&d.env(), "rotate").unwrap();
    assert!(!r.complete);
    let before = state(&d);
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.account.as_mut().unwrap().remote_schema_version = Some(5);
        n.shared_writes_blocked = true;
        Ok(n)
    })
    .unwrap();
    d.relay.set_push_quota(None);
    d.relay.clear_calls();
    assert!(record_account::resume_pending(&d.env(), None).is_err());
    assert_eq!(state(&d).account.as_ref().unwrap().chain_id, old.chain_id);
    assert_eq!(state(&d).local, before.local);
    assert!(d
        .relay
        .calls()
        .iter()
        .all(|c| c.starts_with("pull:") && c.contains(&old.chain_id[..8])));
}
struct CountingKeychain<'a> {
    inner: &'a crate::sync::testkit::MemKeychain,
    calls: Mutex<Vec<String>>,
}
impl Keychain for CountingKeychain<'_> {
    fn get(&self, n: &str) -> Result<Option<String>, AppError> {
        self.calls.lock().unwrap().push(format!("get:{n}"));
        self.inner.get(n)
    }
    fn set(&self, n: &str, s: &str) -> Result<(), AppError> {
        self.calls.lock().unwrap().push(format!("set:{n}"));
        self.inner.set(n, s)
    }
    fn delete(&self, n: &str) -> Result<(), AppError> {
        self.calls.lock().unwrap().push(format!("delete:{n}"));
        self.inner.delete(n)
    }
}
#[cfg(unix)]
#[test]
fn escaping_state_symlink_refuses_before_all_keychain_and_relay_callbacks() {
    let (d, _, _) = fixture();
    let path = d.env().state_path;
    let backup = path.with_extension("saved");
    std::fs::rename(&path, &backup).unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), &path).unwrap();
    let kc = CountingKeychain {
        inner: &d.keychain,
        calls: Mutex::new(vec![]),
    };
    let mut env = d.env();
    env.keychain = &kc;
    d.relay.clear_calls();
    assert!(start_rotation(&env, "rotate").is_err());
    assert!(kc.calls.lock().unwrap().is_empty());
    assert!(d.relay.calls().is_empty());
    assert!(std::fs::read(outside.path()).unwrap().is_empty());
}
#[test]
fn authenticated_unknown_and_old_host_rows_remain_sealed_after_reencryption() {
    let (d, sid, old) = fixture();
    let s = state(&d);
    let child = record_merge::space_keys(s.account.as_ref().unwrap(), &old, &sid)
        .unwrap()
        .unwrap();
    let id = "old-alias";
    let body = json!({"kind":"host","id":id,"version":7,"updated_at_ms":77,"device_id":s.device_id,"deleted":false,"payload":{"schema":1,"text":"Host old-alias\n HostName old.test\n"}});
    let seal =
        crate::sync::crypto::seal(&child, "host", id, &serde_json::to_vec(&body).unwrap()).unwrap();
    d.relay
        .push(
            &sid,
            &child.auth_token,
            &[crate::sync::relay::PushItem {
                kind: "host".into(),
                id_hash: seal.id_hash,
                nonce: seal.nonce,
                ciphertext: seal.ciphertext,
                deleted: false,
                base_seq: 0,
            }],
        )
        .unwrap();
    let opaque = json!({"kind":"futurekind","id":"opaque","version":2,"updated_at_ms":88,"device_id":s.device_id,"deleted":false,"payload":{"secret":"opaque fixture secret"}});
    let seal = crate::sync::crypto::seal(
        &old,
        "futurekind",
        "opaque",
        &serde_json::to_vec(&opaque).unwrap(),
    )
    .unwrap();
    d.relay
        .push(
            &old.chain_id,
            &old.auth_token,
            &[crate::sync::relay::PushItem {
                kind: "futurekind".into(),
                id_hash: seal.id_hash,
                nonce: seal.nonce,
                ciphertext: seal.ciphertext,
                deleted: false,
                base_seq: 0,
            }],
        )
        .unwrap();
    let r = start_rotation(&d.env(), "rotate").unwrap();
    assert!(r.complete);
    let new = crate::sync::crypto::derive_account(&r.code).unwrap();
    let after = state(&d);
    let acct = after.account.as_ref().unwrap();
    let e = &acct
        .sealed
        .values()
        .find(|e| e.envelope.kind == "futurekind")
        .unwrap()
        .envelope;
    let bytes = crate::sync::crypto::open(
        &new,
        &e.kind,
        &e.id_hash,
        &crate::sync::crypto::Sealed {
            id_hash: e.id_hash.clone(),
            nonce: e.nonce.clone(),
            ciphertext: e.ciphertext.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        opaque
    );
    let (newid, target) = after.spaces.iter().next().unwrap();
    let keys = record_merge::space_keys(acct, &new, newid)
        .unwrap()
        .unwrap();
    assert_eq!(target.records.len(), 2);
    let oldrow = target
        .sealed
        .values()
        .find(|r| r.envelope.kind == "host")
        .unwrap();
    assert!(!oldrow.dirty);
    let e = &oldrow.envelope;
    let bytes = crate::sync::crypto::open(
        &keys,
        &e.kind,
        &e.id_hash,
        &crate::sync::crypto::Sealed {
            id_hash: e.id_hash.clone(),
            nonce: e.nonce.clone(),
            ciphertext: e.ciphertext.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        body
    );
    assert!(!serde_json::to_string(&after)
        .unwrap()
        .contains("opaque fixture secret"));
}
#[test]
fn accepted_destination_receipts_survive_disk_failure_without_replaying_the_same_rows() {
    let (d, _, _) = fixture();
    let path = d.env().state_path;
    let backup = path.with_extension("preserved");
    let p = path.clone();
    let b = backup.clone();
    let connector = crate::sync::testkit::HookedConnector::new(
        &d.relay,
        crate::sync::testkit::Hooks {
            after_push: Some(Box::new(move || {
                std::fs::rename(&p, &b).unwrap();
                std::fs::create_dir(&p).unwrap();
            })),
            ..Default::default()
        },
    );
    let mut env = d.env();
    env.relays = &connector;
    let r = start_rotation(&env, "rotate").unwrap();
    assert!(!r.complete);
    assert!(d.runtime.core.lock().unwrap().unsaved);
    let op = state(&d).pending_account.unwrap();
    assert!(op.prepared_account.records.values().all(|r| !r.dirty));
    let target = op.prepared_account.chain_id.clone();
    let first = d.relay.rows(&target);
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(backup, path).unwrap();
    record_account::resume_pending(&d.env(), None).unwrap();
    for row in first.iter().filter(|r| r.kind != "meta") {
        assert_eq!(
            d.relay
                .rows(&target)
                .iter()
                .find(|r| r.id_hash == row.id_hash && r.kind == row.kind)
                .unwrap()
                .seq,
            row.seq
        );
    }
    assert!(!d.runtime.core.lock().unwrap().unsaved);
}
struct BreakPromotion<'a> {
    inner: &'a crate::sync::testkit::MemKeychain,
    path: std::path::PathBuf,
    backup: std::path::PathBuf,
    armed: AtomicBool,
}
impl Keychain for BreakPromotion<'_> {
    fn get(&self, n: &str) -> Result<Option<String>, AppError> {
        self.inner.get(n)
    }
    fn set(&self, n: &str, s: &str) -> Result<(), AppError> {
        self.inner.set(n, s)?;
        if n == MNEMONIC_ACCOUNT && self.armed.swap(false, Ordering::SeqCst) {
            std::fs::rename(&self.path, &self.backup).unwrap();
            std::fs::create_dir(&self.path).unwrap();
        }
        Ok(())
    }
    fn delete(&self, n: &str) -> Result<(), AppError> {
        self.inner.delete(n)
    }
}
#[test]
fn successful_code_promotion_before_disk_failure_does_not_strand_the_source_identity() {
    let (d, _, old) = fixture();
    let path = d.env().state_path;
    let backup = path.with_extension("preserved");
    let kc = BreakPromotion {
        inner: &d.keychain,
        path: path.clone(),
        backup: backup.clone(),
        armed: AtomicBool::new(true),
    };
    let mut env = d.env();
    env.keychain = &kc;
    let r = start_rotation(&env, "rotate").unwrap();
    assert!(!r.complete);
    assert_eq!(state(&d).account.unwrap().chain_id, old.chain_id);
    let op = state(&d).pending_account.unwrap();
    assert!(d
        .keychain
        .entry(&op.rotation.unwrap().source_code_account)
        .is_some());
    assert_eq!(
        crate::sync::crypto::derive_account(&d.keychain.entry(MNEMONIC_ACCOUNT).unwrap())
            .unwrap()
            .chain_id,
        op.prepared_account.chain_id
    );
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(backup, path).unwrap();
    record_account::resume_pending(&d.env(), None).unwrap();
    assert!(state(&d).pending_account.is_none());
    assert_eq!(
        state(&d).account.unwrap().chain_id,
        op.prepared_account.chain_id
    );
}
#[test]
fn incomplete_target_space_plan_is_invalid_before_any_resume_effect() {
    let (d, _, _) = fixture();
    d.relay.set_push_quota(Some(0));
    let r = start_rotation(&d.env(), "rotate").unwrap();
    assert!(!r.complete);
    let mut op = state(&d).pending_account.unwrap();
    op.rotation.as_mut().unwrap().target_spaces.clear();
    assert!(record_account::validate_pending(&op).is_err());
}
struct BreakGateStorage {
    relay: Arc<FakeRelay>,
    target: String,
    path: std::path::PathBuf,
    backup: std::path::PathBuf,
    armed: AtomicBool,
}
struct GateStorageConnector(Arc<BreakGateStorage>);
struct GateStorageRelay(Arc<BreakGateStorage>);
impl crate::sync::env::RelayConnector for GateStorageConnector {
    fn connect(&self, _: &str) -> Result<Box<dyn RelayApi>, AppError> {
        Ok(Box::new(GateStorageRelay(self.0.clone())))
    }
}
impl RelayApi for GateStorageRelay {
    fn info(&self) -> Result<crate::sync::relay::RelayInfo, crate::sync::relay::RelayError> {
        self.0.relay.info()
    }
    fn create_chain(&self, c: &str, t: &str) -> Result<(), crate::sync::relay::RelayError> {
        self.0.relay.create_chain(c, t)
    }
    fn delete_chain(&self, c: &str, t: &str) -> Result<(), crate::sync::relay::RelayError> {
        self.0.relay.delete_chain(c, t)
    }
    fn freeze_chain(&self, c: &str, t: &str) -> Result<(), crate::sync::relay::RelayError> {
        self.0.relay.freeze_chain(c, t)
    }
    fn pull(
        &self,
        c: &str,
        t: &str,
        s: u64,
    ) -> Result<crate::sync::relay::PullResponse, crate::sync::relay::RelayError> {
        let p = self.0.relay.pull(c, t, s)?;
        if c == self.0.target && self.0.armed.swap(false, Ordering::SeqCst) {
            std::fs::rename(&self.0.path, &self.0.backup).unwrap();
            std::fs::create_dir(&self.0.path).unwrap();
        }
        Ok(p)
    }
    fn pull_batch(
        &self,
        i: &[crate::sync::relay::BatchPullItem],
    ) -> Result<Vec<crate::sync::relay::BatchPullEntry>, crate::sync::relay::RelayError> {
        self.0.relay.pull_batch(i)
    }
    fn push(
        &self,
        c: &str,
        t: &str,
        i: &[crate::sync::relay::PushItem],
    ) -> Result<crate::sync::relay::PushOutcome, crate::sync::relay::RelayError> {
        self.0.relay.push(c, t, i)
    }
}
#[test]
fn failed_future_gate_persistence_keeps_the_observation_and_blocks_current_memory() {
    let (d, _, old) = fixture();
    d.relay.set_push_quota(Some(0));
    let r = start_rotation(&d.env(), "rotate").unwrap();
    assert!(!r.complete);
    let new = crate::sync::crypto::derive_account(&r.code).unwrap();
    d.relay.set_push_quota(None);
    let s = state(&d);
    let meta = Record {
        kind: RecordKind::Meta,
        id: ACCOUNT_META_ID.into(),
        version: 99,
        updated_at_ms: 99,
        device_id: s.device_id.clone(),
        deleted: false,
        payload: json!({"schema_version":5,"created_by_app_version":"future"}),
    };
    d.relay
        .push(
            &new.chain_id,
            &new.auth_token,
            &[record_merge::encode_record(&new, &meta, 0).unwrap()],
        )
        .unwrap();
    let path = d.env().state_path;
    let connector = GateStorageConnector(Arc::new(BreakGateStorage {
        relay: d.relay.clone(),
        target: new.chain_id.clone(),
        backup: path.with_extension("original"),
        path,
        armed: AtomicBool::new(true),
    }));
    let mut env = d.env();
    env.relays = &connector;
    assert!(record_account::resume_pending(&env, None).is_err());
    let core = d.runtime.core.lock().unwrap();
    assert!(core.save_blocked.is_some());
    let after = core.records.as_ref().unwrap();
    assert_eq!(
        after
            .pending_account
            .as_ref()
            .unwrap()
            .prepared_account
            .remote_schema_version,
        Some(5)
    );
    assert_eq!(after.local, s.local);
    assert_eq!(after.account.as_ref().unwrap().chain_id, old.chain_id);
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_some());
}

#[test]
fn exhausted_source_meta_stamp_refuses_before_journal_credentials_or_freeze() {
    let (d, _, keys) = fixture();
    let s = state(&d);
    let row = &s.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, ACCOUNT_META_ID)];
    let mut meta = row.record.clone();
    meta.version = u64::MAX;
    meta.updated_at_ms = u64::MAX;
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[record_merge::encode_record(&keys, &meta, row.seq).unwrap()],
        )
        .unwrap();
    d.relay.clear_calls();
    assert!(start_rotation(&d.env(), "rotate").is_err());
    assert!(state(&d).pending_account.is_none());
    assert!(!d
        .relay
        .calls()
        .iter()
        .any(|c| c.starts_with("freeze:") || c.starts_with("create:")));
}
struct OmitTarget {
    relay: Arc<FakeRelay>,
    target: String,
    regress: bool,
}
struct OmitConnector(Arc<OmitTarget>);
struct OmitRelay(Arc<OmitTarget>);
impl crate::sync::env::RelayConnector for OmitConnector {
    fn connect(&self, _: &str) -> Result<Box<dyn RelayApi>, AppError> {
        Ok(Box::new(OmitRelay(self.0.clone())))
    }
}
impl RelayApi for OmitRelay {
    fn info(&self) -> Result<crate::sync::relay::RelayInfo, crate::sync::relay::RelayError> {
        self.0.relay.info()
    }
    fn create_chain(&self, c: &str, t: &str) -> Result<(), crate::sync::relay::RelayError> {
        self.0.relay.create_chain(c, t)
    }
    fn delete_chain(&self, c: &str, t: &str) -> Result<(), crate::sync::relay::RelayError> {
        self.0.relay.delete_chain(c, t)
    }
    fn freeze_chain(&self, c: &str, t: &str) -> Result<(), crate::sync::relay::RelayError> {
        self.0.relay.freeze_chain(c, t)
    }
    fn pull(
        &self,
        c: &str,
        t: &str,
        s: u64,
    ) -> Result<crate::sync::relay::PullResponse, crate::sync::relay::RelayError> {
        let mut p = self.0.relay.pull(c, t, s)?;
        if c == self.0.target {
            let max = p.records.iter().map(|r| r.seq).max().unwrap();
            p.records.retain(|r| r.seq != max);
            if self.0.regress {
                p.latest_seq = max - 1;
            }
        }
        Ok(p)
    }
    fn pull_batch(
        &self,
        i: &[crate::sync::relay::BatchPullItem],
    ) -> Result<Vec<crate::sync::relay::BatchPullEntry>, crate::sync::relay::RelayError> {
        self.0.relay.pull_batch(i)
    }
    fn push(
        &self,
        c: &str,
        t: &str,
        i: &[crate::sync::relay::PushItem],
    ) -> Result<crate::sync::relay::PushOutcome, crate::sync::relay::RelayError> {
        self.0.relay.push(c, t, i)
    }
}
#[test]
fn accepted_target_receipts_cannot_be_erased_by_regressed_or_incomplete_full_baselines() {
    for regress in [true, false] {
        let (d, _, _) = fixture();
        d.relay.set_push_quota(Some(1));
        let r = start_rotation(&d.env(), "rotate").unwrap();
        assert!(!r.complete);
        let new = crypto::derive_account(&r.code).unwrap();
        let mut op = state(&d).pending_account.unwrap();
        assert!(op
            .prepared_account
            .records
            .values()
            .any(|r| !r.dirty && r.seq > 0));
        let before = op.prepared_account.clone();
        let connector = OmitConnector(Arc::new(OmitTarget {
            relay: d.relay.clone(),
            target: new.chain_id.clone(),
            regress,
        }));
        let mut env = d.env();
        env.relays = &connector;
        assert!(target_proof(&env, &mut op, &new).is_err());
        assert_eq!(op.prepared_account, before);
        assert_eq!(state(&d).pending_account.unwrap().prepared_account, before);
    }
}

#[test]
fn storage_preflight_rejects_when_the_initial_journal_fits_but_complete_copy_cannot() {
    let (d, _, old) = fixture();
    d.relay.set_push_quota(Some(0));
    let receipt = start_rotation(&d.env(), "rotate").unwrap();
    let new = crypto::derive_account(&receipt.code).unwrap();
    let mut state = state(&d);
    let mut op = state.pending_account.take().unwrap();
    op.prepared_account = AccountState::new(&new.chain_id);
    let plan = op.rotation.as_mut().unwrap();
    plan.step = RotationStep::Prepared;
    plan.target_spaces.clear();
    plan.frozen.clear();
    plan.created.clear();
    let mut initial = state.clone();
    initial.pending_account = Some(op.clone());
    let limit = serde_json::to_vec_pretty(&initial).unwrap().len() as u64 + 512;
    assert!(check_storage_budget(&state, &op, &old, &new, limit).is_err());
    assert!(check_storage_budget(&state, &op, &old, &new, record_runtime::MAX_STATE_BYTES).is_ok());
}

#[test]
fn group_rotation_preserves_live_and_tombstone_rows_and_effective_values() {
    let (d, sid, _) = fixture();
    let scope = records_v3::HostScope::Space {
        space_id: sid.clone(),
    };
    record_runtime::mutate_records(&d.env(), |s| {
        let p = serde_json::from_value(
            json!({"schema":1,"name":"Ops","defaults":{"user":"ops","port":2222}}),
        )
        .unwrap();
        let s = crate::sync::record_groups::create_group(
            s,
            "0000000000000031",
            scope.clone(),
            p,
            true,
            100,
        )
        .unwrap();
        let p = serde_json::from_value(json!({"schema":1,"name":"Deleted","defaults":{}})).unwrap();
        let s = crate::sync::record_groups::create_group(
            &s,
            "0000000000000032",
            scope.clone(),
            p,
            false,
            101,
        )
        .unwrap();
        let g = crate::sync::record_groups::list_groups(&s)
            .unwrap()
            .into_iter()
            .find(|g| g.group.id == "0000000000000032")
            .unwrap();
        let s =
            crate::sync::record_groups::delete_group(&s, &g.group.id, &g.revision, 102).unwrap();
        let h = crate::sync::record_repository::get_host(&s, B).unwrap();
        let mut p = h.host.payload;
        p.schema = 3;
        p.group_id = Some("0000000000000031".into());
        p.inherit = vec![
            records_v3::InheritedField::User,
            records_v3::InheritedField::Port,
        ];
        Ok(crate::sync::record_repository::update_host(&s, B, &h.revision, p, 103).unwrap())
    })
    .unwrap();
    record_round::sync_once(&d.env()).unwrap();
    let before = state(&d);
    let rows = before.spaces[&sid].records.clone();
    let r = start_rotation(&d.env(), "rotated").unwrap();
    assert!(
        r.complete,
        "{:?}; retry: {:?}",
        r.pending_error,
        resume_locked(&d.env(), None)
    );
    let after = state(&d);
    let groups: Vec<_> = after
        .spaces
        .values()
        .flat_map(|s| s.records.values())
        .filter(|r| r.record.kind == RecordKind::Group)
        .collect();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups.iter().filter(|r| r.record.deleted).count(), 1);
    for g in groups {
        assert_eq!(
            g.record,
            rows[&record_key(RecordKind::Group, &g.record.id)].record
        );
    }
    let h = crate::sync::record_repository::get_host(&after, B).unwrap();
    assert_eq!(h.effective_payload.user, "ops");
    assert_eq!(h.effective_payload.port, 2222);
    assert_eq!(
        after.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, ACCOUNT_META_ID)]
            .record
            .payload["schema_version"],
        4
    );
}
