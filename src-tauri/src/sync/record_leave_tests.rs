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
fn selected_hosts_remap_jumps_passwords_aliases_without_replacing_local_or_remote() {
    let (d, sid, _) = fixture();
    let before = state(&d);
    let config = std::fs::read(d.ssh_dir().join("config")).unwrap();
    let r = leave_account(&d.env()).unwrap();
    assert!(r.complete);
    assert_eq!(r.copied_hosts, 2);
    assert_eq!(r.mappings.len(), 2);
    let after = state(&d);
    assert!(after.account.is_none());
    assert!(after.spaces.is_empty());
    assert!(after.pending_account.is_none());
    assert_eq!(after.local.keys, before.local.keys);
    assert_eq!(
        after.local.hosts[&record_key(RecordKind::Host, LOCAL)],
        before.local.hosts[&record_key(RecordKind::Host, LOCAL)]
    );
    let a = r.mappings.iter().find(|m| m.source_host_id == A).unwrap();
    let b = r.mappings.iter().find(|m| m.source_host_id == B).unwrap();
    assert_ne!(a.alias, "jump");
    assert_ne!(a.local_host_id, A);
    assert_eq!(
        after.local.hosts[&record_key(RecordKind::Host, &b.local_host_id)]
            .record
            .payload["jump"],
        json!([a.local_host_id])
    );
    assert_eq!(
        d.keychain
            .entry(&format!("host:{}", a.local_host_id))
            .as_deref(),
        Some("fixture password A")
    );
    assert_eq!(
        d.keychain.entry(&format!("host:{A}")).as_deref(),
        Some("fixture password A")
    );
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_none());
    assert!(d.relay.exists(&sid));
    assert!(d.relay.calls().iter().all(|c| c.starts_with("pull:")));
    assert_eq!(std::fs::read(d.ssh_dir().join("config")).unwrap(), config);
    assert!(!serde_json::to_string(&after)
        .unwrap()
        .contains("fixture password"));
}
#[test]
fn missing_selected_space_refuses_without_password_copy_or_detach() {
    let (d, sid, keys) = fixture();
    let source = state(&d);
    let child = record_merge::space_keys(source.account.as_ref().unwrap(), &keys, &sid)
        .unwrap()
        .unwrap();
    d.relay.delete_chain(&sid, &child.auth_token).unwrap();
    assert!(leave_account(&d.env()).is_err());
    let s = state(&d);
    assert_eq!(s.local, source.local);
    assert!(s.account.is_some());
    assert!(s.pending_account.is_none());
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_some());
}
#[test]
fn future_account_format_refuses_before_copy_even_when_frozen() {
    let (d, _, keys) = fixture();
    let s = state(&d);
    let mut meta = s.account.as_ref().unwrap().records
        [&record_key(RecordKind::Meta, ACCOUNT_META_ID)]
        .record
        .clone();
    meta.version += 1;
    meta.updated_at_ms += 100;
    meta.payload["schema_version"] = json!(5);
    let base =
        s.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, ACCOUNT_META_ID)].seq;
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[record_merge::encode_record(&keys, &meta, base).unwrap()],
        )
        .unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.account.as_mut().unwrap().frozen = Some(crate::sync::state_v2::FreezeInfo {
            detected_at_ms: 1,
            markers: vec![],
        });
        Ok(n)
    })
    .unwrap();
    assert!(leave_account(&d.env()).is_err());
    assert_eq!(state(&d).local, s.local);
    assert!(state(&d).pending_account.is_none());
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_some());
}
struct FailCopies<'a> {
    inner: &'a crate::sync::testkit::MemKeychain,
    fail: AtomicBool,
    calls: Mutex<Vec<String>>,
}
impl Keychain for FailCopies<'_> {
    fn get(&self, a: &str) -> Result<Option<String>, AppError> {
        self.inner.get(a)
    }
    fn set(&self, a: &str, v: &str) -> Result<(), AppError> {
        self.calls.lock().unwrap().push(a.into());
        if a.starts_with("host:") && self.fail.load(Ordering::SeqCst) {
            Err(AppError::Other("denied".into()))
        } else {
            self.inner.set(a, v)
        }
    }
    fn delete(&self, a: &str) -> Result<(), AppError> {
        self.inner.delete(a)
    }
}
#[test]
fn password_denial_is_partial_and_resume_keeps_planned_ids_and_latest_local_edit() {
    let (d, _, _) = fixture();
    let kc = FailCopies {
        inner: &d.keychain,
        fail: AtomicBool::new(true),
        calls: Mutex::new(vec![]),
    };
    let mut env = d.env();
    env.keychain = &kc;
    let r = leave_account(&env).unwrap();
    assert!(!r.complete);
    assert_eq!(
        state(&d).pending_account.as_ref().unwrap().id,
        r.operation_id
    );
    assert!(state(&d).account.is_some());
    record_runtime::mutate_records(&env, |s| {
        let mut n = s.clone();
        n.local
            .hosts
            .get_mut(&record_key(RecordKind::Host, LOCAL))
            .unwrap()
            .record
            .payload["notes"] = json!("latest local edit");
        Ok(n)
    })
    .unwrap();
    kc.fail.store(false, Ordering::SeqCst);
    record_account::resume_pending(&env, None).unwrap();
    let s = state(&d);
    assert!(s.pending_account.is_none());
    for m in r.mappings {
        assert!(s
            .local
            .hosts
            .contains_key(&record_key(RecordKind::Host, &m.local_host_id)));
    }
    assert_eq!(
        s.local.hosts[&record_key(RecordKind::Host, LOCAL)]
            .record
            .payload["notes"],
        json!("latest local edit")
    );
}
#[test]
fn mnemonic_cleanup_denial_retains_copied_local_rows_and_resumes_without_new_ids() {
    let (d, _, _) = fixture();
    d.keychain.fail_deletes.store(true, Ordering::SeqCst);
    let r = leave_account(&d.env()).unwrap();
    assert!(!r.complete);
    assert!(state(&d).account.is_none());
    assert!(state(&d).pending_account.is_some());
    let local = state(&d).local;
    d.keychain.fail_deletes.store(false, Ordering::SeqCst);
    record_account::resume_pending(&d.env(), None).unwrap();
    assert_eq!(state(&d).local, local);
    assert!(state(&d).pending_account.is_none());
}
#[test]
fn dirty_cached_host_is_copied_instead_of_discarded_by_newer_remote_revision() {
    let (d, sid, _) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        let r = n
            .spaces
            .get_mut(&sid)
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::Host, B))
            .unwrap();
        r.record.payload["notes"] = json!("unuploaded");
        r.dirty = true;
        Ok(n)
    })
    .unwrap();
    let r = leave_account(&d.env()).unwrap();
    assert!(r.complete);
    let b = r.mappings.iter().find(|m| m.source_host_id == B).unwrap();
    assert_eq!(
        state(&d).local.hosts[&record_key(RecordKind::Host, &b.local_host_id)]
            .record
            .payload["notes"],
        json!("unuploaded")
    );
}
#[test]
fn supported_frozen_account_can_detach_locally_without_remote_mutation() {
    let (d, _, _) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.account.as_mut().unwrap().frozen = Some(crate::sync::state_v2::FreezeInfo {
            detected_at_ms: 1,
            markers: vec![],
        });
        Ok(n)
    })
    .unwrap();
    let r = leave_account(&d.env()).unwrap();
    assert!(r.complete);
    assert!(state(&d).account.is_none());
    assert!(d.relay.calls().iter().all(|c| c.starts_with("pull:")));
}
#[test]
fn different_target_password_refuses_retry_without_overwrite_or_detach() {
    let (d, _, _) = fixture();
    let kc = FailCopies {
        inner: &d.keychain,
        fail: AtomicBool::new(true),
        calls: Mutex::new(vec![]),
    };
    let mut env = d.env();
    env.keychain = &kc;
    let r = leave_account(&env).unwrap();
    assert!(!r.complete);
    let target = format!("host:{}", r.mappings[0].local_host_id);
    d.keychain
        .set(&target, "different target password")
        .unwrap();
    kc.fail.store(false, Ordering::SeqCst);
    assert!(record_account::resume_pending(&env, None).is_err());
    assert_eq!(
        d.keychain.entry(&target).as_deref(),
        Some("different target password")
    );
    assert!(state(&d).account.is_some());
    assert_eq!(state(&d).local.hosts.len(), 1);
}
#[test]
fn future_format_after_partial_copy_blocks_retry_before_next_namespace_write() {
    let (d, _, keys) = fixture();
    let kc = FailCopies {
        inner: &d.keychain,
        fail: AtomicBool::new(true),
        calls: Mutex::new(vec![]),
    };
    let mut env = d.env();
    env.keychain = &kc;
    let r = leave_account(&env).unwrap();
    assert!(!r.complete);
    let before = state(&d);
    let row =
        &before.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, ACCOUNT_META_ID)];
    let mut meta = row.record.clone();
    meta.payload["schema_version"] = json!(5);
    meta.version += 1;
    meta.updated_at_ms += 10;
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[record_merge::encode_record(&keys, &meta, row.seq).unwrap()],
        )
        .unwrap();
    kc.fail.store(false, Ordering::SeqCst);
    kc.calls.lock().unwrap().clear();
    assert!(record_account::resume_pending(&env, None).is_err());
    assert!(kc.calls.lock().unwrap().is_empty());
    assert_eq!(state(&d).local, before.local);
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_some());
}
#[test]
fn source_change_after_partial_copy_refuses_false_preservation_success() {
    let (d, sid, keys) = fixture();
    let kc = FailCopies {
        inner: &d.keychain,
        fail: AtomicBool::new(true),
        calls: Mutex::new(vec![]),
    };
    let mut env = d.env();
    env.keychain = &kc;
    let r = leave_account(&env).unwrap();
    assert!(!r.complete);
    let s = state(&d);
    let child = record_merge::space_keys(s.account.as_ref().unwrap(), &keys, &sid)
        .unwrap()
        .unwrap();
    let row = &s.spaces[&sid].records[&record_key(RecordKind::Host, B)];
    let mut edited = row.record.clone();
    edited.version += 1;
    edited.updated_at_ms += 100;
    edited.payload["notes"] = json!("remote changed during pause");
    d.relay
        .push(
            &sid,
            &child.auth_token,
            &[record_merge::encode_record(&child, &edited, row.seq).unwrap()],
        )
        .unwrap();
    kc.fail.store(false, Ordering::SeqCst);
    assert!(record_account::resume_pending(&env, None).is_err());
    assert!(state(&d).account.is_some());
    assert_eq!(state(&d).local.hosts.len(), 1);
}
fn public_key(text: &str, s: &SyncStateV3) -> crate::sync::records_v3::KeySlotPayload {
    let k = crate::vault::material::parse(text).unwrap();
    crate::sync::records_v3::KeySlotPayload {
        schema: 2,
        name: "fixture key".into(),
        public_key: k.public_key().to_openssh().unwrap(),
        fingerprint: k
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        key_type: k.algorithm().as_str().into(),
        has_passphrase: k.is_encrypted(),
        created_at_ms: 1,
        origin_device_id: s.device_id.clone(),
    }
}
#[test]
fn conflicting_authoritative_key_cannot_silently_become_a_local_key_after_detach() {
    let (d, sid, keys) = fixture();
    let kid = "a".repeat(32);
    let s = state(&d);
    let text = crate::sync::slot_rules::test_keys::plain();
    record_account::publish_key(
        &d.env(),
        &kid,
        public_key(&text, &s),
        zeroize::Zeroizing::new(text),
    )
    .unwrap();
    let wrong = public_key(&crate::sync::slot_rules::test_keys::ecdsa_full_p256(), &s);
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.local.keys.insert(
            kid.clone(),
            crate::sync::records_v3::LocalKeyMetadata {
                vault_id: "b".repeat(32),
                public: wrong,
            },
        );
        Ok(n)
    })
    .unwrap();
    let s = state(&d);
    let child = record_merge::space_keys(s.account.as_ref().unwrap(), &keys, &sid)
        .unwrap()
        .unwrap();
    let row = &s.spaces[&sid].records[&record_key(RecordKind::Host, B)];
    let mut host = row.record.clone();
    host.version += 1;
    host.updated_at_ms += 100;
    host.payload["auth"] = json!("key");
    host.payload["key_id"] = json!(kid);
    d.relay
        .push(
            &sid,
            &child.auth_token,
            &[record_merge::encode_record(&child, &host, row.seq).unwrap()],
        )
        .unwrap();
    let local = state(&d).local;
    assert!(leave_account(&d.env()).is_err());
    assert!(state(&d).account.is_some());
    assert!(state(&d).pending_account.is_none());
    assert_eq!(state(&d).local, local);
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_some());
}
#[test]
fn migrated_legacy_alias_ciphertext_does_not_prevent_copying_supported_hosts() {
    let (d, sid, keys) = fixture();
    let s = state(&d);
    let child = record_merge::space_keys(s.account.as_ref().unwrap(), &keys, &sid)
        .unwrap()
        .unwrap();
    let legacy = Record {
        kind: RecordKind::Host,
        id: "legacy-alias".into(),
        version: 1,
        updated_at_ms: 1,
        device_id: s.device_id,
        deleted: false,
        payload: json!({"schema":1,"text":"Host legacy-alias\n HostName legacy.test\n"}),
    };
    d.relay
        .push(
            &sid,
            &child.auth_token,
            &[record_merge::encode_record(&child, &legacy, 0).unwrap()],
        )
        .unwrap();
    let r = leave_account(&d.env()).unwrap();
    assert!(r.complete);
    assert_eq!(r.copied_hosts, 2);
    assert_eq!(state(&d).local.hosts.len(), 3);
}

#[test]
fn migrated_own_slot_keeps_available_local_material_after_detach() {
    let (d, sid, keys) = fixture();
    let kid = "a".repeat(32);
    let s = state(&d);
    let public = public_key(&crate::sync::slot_rules::test_keys::plain(), &s);
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.local.keys.insert(
            kid.clone(),
            records_v3::LocalKeyMetadata {
                vault_id: "b".repeat(32),
                public: public.clone(),
            },
        );
        Ok(n)
    })
    .unwrap();
    let old = Record {
        kind: RecordKind::KeySlot,
        id: kid.clone(),
        version: 1,
        updated_at_ms: 1,
        device_id: s.device_id.clone(),
        deleted: false,
        payload: json!({"schema":1,"name":"old-own","mode":"own","origin_device_id":s.device_id,"created_at_ms":1,"public_key":null,"fingerprint":null,"key_type":null,"has_passphrase":null}),
    };
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[record_merge::encode_record(&keys, &old, 0).unwrap()],
        )
        .unwrap();
    let child = record_merge::space_keys(s.account.as_ref().unwrap(), &keys, &sid)
        .unwrap()
        .unwrap();
    let row = &s.spaces[&sid].records[&record_key(RecordKind::Host, B)];
    let mut h = row.record.clone();
    h.version += 1;
    h.updated_at_ms += 100;
    h.payload["auth"] = json!("key");
    h.payload["key_id"] = json!(kid);
    d.relay
        .push(
            &sid,
            &child.auth_token,
            &[record_merge::encode_record(&child, &h, row.seq).unwrap()],
        )
        .unwrap();
    let before = state(&d).local.keys;
    let receipt = leave_account(&d.env()).unwrap();
    assert!(receipt.complete);
    assert_eq!(state(&d).local.keys, before);
    let copied = receipt
        .mappings
        .iter()
        .find(|m| m.source_host_id == B)
        .unwrap();
    assert_eq!(
        state(&d).local.hosts[&record_key(RecordKind::Host, &copied.local_host_id)]
            .record
            .payload["key_id"],
        json!(kid)
    );
}
#[test]
fn unknown_live_host_shape_still_prevents_detach_before_password_or_journal_writes() {
    let (d, sid, keys) = fixture();
    let s = state(&d);
    let child = record_merge::space_keys(s.account.as_ref().unwrap(), &keys, &sid)
        .unwrap()
        .unwrap();
    let unknown = Record {
        kind: RecordKind::Host,
        id: "unsupported-alias".into(),
        version: 1,
        updated_at_ms: 1,
        device_id: s.device_id,
        deleted: false,
        payload: json!({"schema":3,"text":"future"}),
    };
    d.relay
        .push(
            &sid,
            &child.auth_token,
            &[record_merge::encode_record(&child, &unknown, 0).unwrap()],
        )
        .unwrap();
    let before = state(&d).local;
    assert!(leave_account(&d.env()).is_err());
    assert_eq!(state(&d).local, before);
    assert!(state(&d).pending_account.is_none());
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_some());
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
fn denied_cleanup_gate_save_retains_newer_format_and_blocks_memory_before_code_deletion() {
    let (d, _, keys) = fixture();
    d.keychain.fail_deletes.store(true, Ordering::SeqCst);
    let r = leave_account(&d.env()).unwrap();
    assert!(!r.complete);
    let s = state(&d);
    assert!(s.account.is_none());
    let op = s.pending_account.as_ref().unwrap();
    let old = &op.prepared_account.records[&record_key(RecordKind::Meta, ACCOUNT_META_ID)];
    let mut future = old.record.clone();
    future.updated_at_ms += 1;
    future.version += 1;
    future.payload["schema_version"] = json!(5);
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[record_merge::encode_record(&keys, &future, old.seq).unwrap()],
        )
        .unwrap();
    d.keychain.fail_deletes.store(false, Ordering::SeqCst);
    let path = d.env().state_path;
    let connector = GateStorageConnector(Arc::new(BreakGateStorage {
        relay: d.relay.clone(),
        target: keys.chain_id.clone(),
        backup: path.with_extension("original"),
        path,
        armed: AtomicBool::new(true),
    }));
    let mut env = d.env();
    env.relays = &connector;
    assert!(record_account::resume_pending(&env, None).is_err());
    let core = d.runtime.core.lock().unwrap();
    assert!(core.save_blocked.is_some());
    let n = core.records.as_ref().unwrap();
    assert_eq!(
        n.pending_account
            .as_ref()
            .unwrap()
            .prepared_account
            .remote_schema_version,
        Some(5)
    );
    assert_eq!(n.local, s.local);
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_some());
}

#[test]
fn a_leave_journal_cannot_substitute_another_endpoint_or_drop_source_annotations() {
    let (d, _, _) = fixture();
    let kc = FailCopies {
        inner: &d.keychain,
        fail: AtomicBool::new(true),
        calls: Mutex::new(vec![]),
    };
    let mut env = d.env();
    env.keychain = &kc;
    let receipt = leave_account(&env).unwrap();
    assert!(!receipt.complete);
    let op = state(&d).pending_account.unwrap();
    let original = op.leave.unwrap();
    assert!(validate_plan(&original).is_ok());
    for (field, value) in [
        ("hostname", json!("different.test")),
        ("notes", json!("lost notes")),
    ] {
        let mut altered = original.clone();
        altered.hosts[0].local.record.payload[field] = value;
        assert!(validate_plan(&altered).is_err());
    }
}

#[test]
fn group_leave_preserves_nested_defaults_parent_membership_and_jump_remaps() {
    let (d, sid, _) = fixture();
    let scope = HostScope::Space {
        space_id: sid.clone(),
    };
    record_runtime::mutate_records(&d.env(),|s|{
        let parent=serde_json::from_value(json!({"schema":1,"name":"Ops","defaults":{"user":"ops","jump":[A]}})).unwrap();
        let s=crate::sync::record_groups::create_group(s,"0000000000000031",scope.clone(),parent,true,100).unwrap();
        let child=serde_json::from_value(json!({"schema":1,"name":"Child","parent_id":"0000000000000031","defaults":{"port":2222}})).unwrap();
        let s=crate::sync::record_groups::create_group(&s,"0000000000000032",scope.clone(),child,false,101).unwrap();
        let h=crate::sync::record_repository::get_host(&s,B).unwrap();let mut p=h.host.payload;p.schema=3;p.group_id=Some("0000000000000032".into());p.inherit=vec![records_v3::InheritedField::User,records_v3::InheritedField::Port,records_v3::InheritedField::Jump];
        Ok(crate::sync::record_repository::update_host(&s,B,&h.revision,p,102).unwrap())
    }).unwrap();
    record_round::sync_once(&d.env()).unwrap();
    let result = leave_account(&d.env()).unwrap();
    assert!(result.complete, "{:?}", result.pending_error);
    let s = state(&d);
    let new_id = &result
        .mappings
        .iter()
        .find(|m| m.source_host_id == B)
        .unwrap()
        .local_host_id;
    let jump_id = &result
        .mappings
        .iter()
        .find(|m| m.source_host_id == A)
        .unwrap()
        .local_host_id;
    let h = crate::sync::record_repository::get_host(&s, new_id).unwrap();
    assert_eq!(h.effective_payload.user, "ops");
    assert_eq!(h.effective_payload.port, 2222);
    assert_eq!(&h.effective_payload.jump, &vec![jump_id.clone()]);
    let groups = crate::sync::record_groups::list_groups(&s).unwrap();
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().all(|g| g.group.scope == HostScope::Local
        && g.group.id != "0000000000000031"
        && g.group.id != "0000000000000032"));
    assert!(groups
        .iter()
        .any(|g| Some(&g.group.id) == h.host.payload.group_id.as_ref()
            && g.group.payload.parent_id.is_some()));
    assert_eq!(
        d.keychain
            .get(&format!("host:{new_id}"))
            .unwrap()
            .as_deref(),
        Some("fixture password B")
    );
}

#[test]
fn group_unreadable_selected_source_refuses_detach_without_credential_copies() {
    let (d, sid, keys) = fixture();
    let before = state(&d);
    let child = record_merge::space_keys(before.account.as_ref().unwrap(), &keys, &sid)
        .unwrap()
        .unwrap();
    let row = Record {
        kind: RecordKind::Group,
        id: "0000000000000031".into(),
        version: 1,
        updated_at_ms: 10,
        device_id: before.device_id.clone(),
        deleted: false,
        payload: json!({"schema":99,"name":"Future"}),
    };
    d.relay
        .push(
            &sid,
            &child.auth_token,
            &[record_merge::encode_record(&child, &row, 0).unwrap()],
        )
        .unwrap();
    assert!(leave_account(&d.env()).is_err());
    assert!(state(&d).account.is_some());
    assert_eq!(state(&d).local, before.local);
}
