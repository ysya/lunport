use super::*;
use crate::sync::crypto::ChainKeys;
use crate::sync::env::Keychain;
use crate::sync::fake_relay::FakeRelay;
use crate::sync::record::{record_key, LocalRecord, Record, RecordKind, ACCOUNT_META_ID};
use crate::sync::records_v3::migration_host_id;
use crate::sync::relay::RelayApi;
use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::state_v2::{AccountState, SpaceState};
use crate::sync::testkit::{TestClock, TestDevice};
use crate::sync::{crypto, record_merge, record_runtime};
use serde_json::json;
use std::{fs, sync::Arc};
struct Fixture {
    d: TestDevice,
    code: String,
    account: ChainKeys,
    space: ChainKeys,
}
fn row(kind: RecordKind, id: &str, payload: serde_json::Value) -> Record {
    Record {
        kind,
        id: id.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: "d".repeat(32),
        deleted: false,
        payload,
    }
}
fn push(d: &TestDevice, keys: &ChainKeys, record: &Record) {
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[record_merge::encode_record(keys, record, 0).unwrap()],
        )
        .unwrap();
}
fn fixture(schema: u32) -> Fixture {
    let relay = FakeRelay::new();
    let d = TestDevice::new("d", &relay, &TestClock::new());
    let code = crypto::generate_mnemonic().unwrap();
    let account = crypto::derive_account(&code).unwrap();
    let space = ChainKeys::generate().unwrap();
    for keys in [&account, &space] {
        relay
            .create_chain(&keys.chain_id, &keys.auth_token)
            .unwrap();
    }
    push(
        &d,
        &account,
        &row(
            RecordKind::Meta,
            ACCOUNT_META_ID,
            json!({"schema_version":schema,"created_by_app_version":"fixture"}),
        ),
    );
    push(
        &d,
        &account,
        &row(
            RecordKind::Space,
            &space.chain_id,
            json!({"schema":1,"name":"Work","slug":"work","created_at_ms":1}),
        ),
    );
    push(
        &d,
        &account,
        &row(
            RecordKind::SpaceKey,
            &space.chain_id,
            json!({"schema":1,"auth_token":space.auth_token,"enc_key":space.enc_key_b64()}),
        ),
    );
    push(
        &d,
        &space,
        &row(
            RecordKind::Host,
            "web",
            json!({"schema":1,"text":"Host web\n  HostName web.test\n  PreferredAuthentications password\n"}),
        ),
    );
    d.keychain.set(MNEMONIC_ACCOUNT, &code).unwrap();
    {
        let mut core = d.runtime.core.lock().unwrap();
        let s = core.state.as_mut().unwrap();
        s.device_id = "a".repeat(32);
        s.account = Some(AccountState::new(&account.chain_id));
        s.spaces
            .insert(space.chain_id.clone(), SpaceState::new("work.config"));
        core.legacy_paused = true;
    }
    let s = d.runtime.core.lock().unwrap().state.clone().unwrap();
    fs::create_dir_all(d.env().state_path.parent().unwrap()).unwrap();
    fs::write(d.env().state_path, serde_json::to_vec_pretty(&s).unwrap()).unwrap();
    relay.clear_calls();
    Fixture {
        d,
        code,
        account,
        space,
    }
}
fn consent() -> MigrationConsent {
    MigrationConsent {
        old_clients_stopped_or_compatible: true,
    }
}
#[test]
fn preview_and_cancel_preserve_all_originals_and_issue_no_network_or_credential_writes() {
    let f = fixture(2);
    let bytes = fs::read(f.d.env().state_path).unwrap();
    let ssh = f.d.main_config();
    let p = prepare(&f.d.env(), None).unwrap();
    assert_eq!(p.preview().account_schema, 2);
    assert_eq!(p.preview().host_count, 1);
    assert!(p.preview().can_confirm);
    assert!(!format!("{p:?}").contains(&f.code));
    drop(p);
    assert_eq!(fs::read(f.d.env().state_path).unwrap(), bytes);
    assert_eq!(f.d.main_config(), ssh);
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
    assert!(f.d.relay.calls().iter().all(|c| c.starts_with("pull:")));
    assert_eq!(
        f.d.keychain.entry(MNEMONIC_ACCOUNT).as_deref(),
        Some(f.code.as_str())
    );
}
#[test]
fn explicit_old_clients_consent_is_required_before_any_migration_effect() {
    let f = fixture(2);
    let p = prepare(&f.d.env(), None).unwrap();
    f.d.relay.clear_calls();
    assert!(confirm(
        &f.d.env(),
        p,
        MigrationConsent {
            old_clients_stopped_or_compatible: false
        }
    )
    .is_err());
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
    assert!(f.d.relay.calls().is_empty());
}
#[test]
fn confirmed_schema_two_migration_retains_old_rows_and_ssh_sources_then_activates_records() {
    let f = fixture(2);
    let original = fs::read(f.d.env().state_path).unwrap();
    let ssh = f.d.main_config();
    let receipt = confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&f.d.env()).unwrap().0;
    let id = migration_host_id(&f.space.chain_id, "web").unwrap();
    assert_eq!(
        state.spaces[&f.space.chain_id].records[&record_key(RecordKind::Host, &id)]
            .record
            .payload["hostname"],
        "web.test"
    );
    assert_eq!(f.d.relay.rows(&f.space.chain_id).len(), 2);
    assert_eq!(f.d.main_config(), ssh);
    assert!(f.d.doc.lock().unwrap().is_none());
    assert_eq!(
        fs::read(
            f.d.env()
                .state_path
                .parent()
                .unwrap()
                .join("migrations")
                .join(&receipt.migration_id)
                .join("original-state.json")
        )
        .unwrap(),
        original
    );
    assert_eq!(resume(&f.d.env(), &receipt.migration_id).unwrap(), receipt);
}
#[test]
fn stale_legacy_relay_snapshot_refuses_before_schema_gate_or_journal() {
    let f = fixture(2);
    let p = prepare(&f.d.env(), None).unwrap();
    let rows = f.d.relay.rows(&f.space.chain_id);
    let mut edited = row(
        RecordKind::Host,
        "web",
        json!({"schema":1,"text":"Host web\n HostName changed.test\n"}),
    );
    edited.updated_at_ms = 2;
    f.d.relay
        .push(
            &f.space.chain_id,
            &f.space.auth_token,
            &[record_merge::encode_record(&f.space, &edited, rows[0].seq).unwrap()],
        )
        .unwrap();
    f.d.relay.clear_calls();
    assert!(confirm(&f.d.env(), p, consent()).is_err());
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
    assert!(f.d.relay.calls().iter().all(|c| c.starts_with("pull:")));
}
#[test]
fn a_newer_account_cannot_create_migration_files_or_write_gate() {
    let f = fixture(4);
    assert!(prepare(&f.d.env(), None).is_err());
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
    assert!(f.d.relay.calls().iter().all(|c| c.starts_with("pull:")));
}
#[test]
fn second_device_schema_three_baseline_preserves_existing_edits_tombstones_and_pin() {
    let f = fixture(3);
    let id = migration_host_id(&f.space.chain_id, "web").unwrap();
    let mut edited = row(
        RecordKind::Host,
        &id,
        json!({"schema":2,"alias":"renamed","hostname":"edited.test","auth":"password","host_key":null}),
    );
    edited.updated_at_ms = 5;
    push(&f.d, &f.space, &edited);
    let receipt = confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&f.d.env()).unwrap().0;
    assert_eq!(
        state.spaces[&f.space.chain_id].records[&record_key(RecordKind::Host, &id)].record,
        edited
    );
    assert_eq!(f.d.relay.rows(&f.space.chain_id).len(), 2);
}
#[test]
fn every_durable_migration_step_resumes_same_ids_without_deleting_old_rows_or_config() {
    for stop in [
        Step::Prepared,
        Step::CodeStaged,
        Step::AccountGated,
        Step::BatchSaved,
        Step::VaultPublished,
        Step::BeforeStateSave,
        Step::StateSaved,
    ] {
        let f = fixture(2);
        let ssh = f.d.main_config();
        let generation = f.d.runtime.core.lock().unwrap().generation;
        assert!(with_test_step(
            move |s| if s == stop {
                Err(failure("test interruption"))
            } else {
                Ok(())
            },
            || confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent())
        )
        .is_err());
        let pending = pending_migrations(&f.d.env()).unwrap();
        assert_eq!(pending.len(), 1);
        if stop != Step::StateSaved {
            assert_eq!(f.d.runtime.core.lock().unwrap().generation, generation);
            assert!(f.d.runtime.core.lock().unwrap().records.is_none());
        }
        let receipt = resume(&f.d.env(), &pending[0].migration_id).unwrap();
        assert!(receipt.complete);
        let state = record_runtime::snapshot(&f.d.env()).unwrap().0;
        assert_eq!(state.spaces[&f.space.chain_id].records.len(), 1);
        assert_eq!(f.d.relay.rows(&f.space.chain_id).len(), 2);
        assert_eq!(f.d.main_config(), ssh);
    }
}
#[test]
fn lost_separate_state_receipt_uses_atomic_state_proof_and_preserves_later_user_edit() {
    let f = fixture(2);
    assert!(with_test_step(
        |s| if s == Step::StateSaved {
            Err(failure("test interruption"))
        } else {
            Ok(())
        },
        || confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent())
    )
    .is_err());
    let pending = pending_migrations(&f.d.env()).unwrap();
    let id = pending[0].migration_id.clone();
    let path =
        f.d.env()
            .state_path
            .parent()
            .unwrap()
            .join("migrations")
            .join(&id)
            .join("journal.json");
    let mut j: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    j["phase"] = json!("prepared");
    j["state_published"] = json!(false);
    fs::write(&path, serde_json::to_vec(&j).unwrap()).unwrap();
    crate::sync::record_runtime::mutate_records(&f.d.env(), |s| {
        let mut s = s.clone();
        s.spaces.get_mut(&f.space.chain_id).unwrap().records.clear();
        Ok(s)
    })
    .unwrap();
    let generation = f.d.runtime.core.lock().unwrap().generation;
    f.d.relay.clear_calls();
    assert!(resume(&f.d.env(), &id).unwrap().complete);
    assert_eq!(f.d.runtime.core.lock().unwrap().generation, generation);
    assert!(
        record_runtime::snapshot(&f.d.env()).unwrap().0.spaces[&f.space.chain_id]
            .records
            .is_empty()
    );
    assert!(f.d.relay.calls().is_empty());
}
#[test]
fn late_old_alias_changes_pause_publication_and_retain_review_ciphertext_without_activation() {
    let f = fixture(2);
    assert!(with_test_step(
        |s| if s == Step::AccountGated {
            Err(failure("test interruption"))
        } else {
            Ok(())
        },
        || confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent())
    )
    .is_err());
    let pending = pending_migrations(&f.d.env()).unwrap();
    let old = f.d.relay.rows(&f.space.chain_id)[0].clone();
    let mut changed = row(
        RecordKind::Host,
        "web",
        json!({"schema":1,"text":"Host web\n HostName late.test\n"}),
    );
    changed.updated_at_ms = 4;
    f.d.relay
        .push(
            &f.space.chain_id,
            &f.space.auth_token,
            &[record_merge::encode_record(&f.space, &changed, old.seq).unwrap()],
        )
        .unwrap();
    f.d.relay.clear_calls();
    assert!(resume(&f.d.env(), &pending[0].migration_id).is_err());
    assert!(f.d.runtime.core.lock().unwrap().records.is_none());
    assert!(f.d.relay.calls().iter().all(|c| c.starts_with("pull:")));
    let review =
        f.d.env()
            .state_path
            .parent()
            .unwrap()
            .join("migrations")
            .join(&pending[0].migration_id)
            .join("review-sources.json");
    assert!(review.exists());
    assert!(!fs::read_to_string(review).unwrap().contains("late.test"));
}
#[test]
fn state_save_failure_preserves_core_doc_generation_and_journal_can_resume() {
    let f = fixture(2);
    let prepared = prepare(&f.d.env(), None).unwrap();
    let generation = f.d.runtime.core.lock().unwrap().generation;
    let path = f.d.env().state_path;
    let saved = fs::read(&path).unwrap();
    let injected = path.clone();
    assert!(with_test_step(
        move |s| {
            if s == Step::BeforeStateSave {
                fs::remove_file(&injected).unwrap();
                fs::create_dir(&injected).unwrap();
            }
            Ok(())
        },
        || confirm(&f.d.env(), prepared, consent())
    )
    .is_err());
    assert_eq!(f.d.runtime.core.lock().unwrap().generation, generation);
    assert!(f.d.runtime.core.lock().unwrap().records.is_none());
    let pending = pending_migrations(&f.d.env()).unwrap();
    fs::remove_dir(&path).unwrap();
    fs::write(&path, saved).unwrap();
    assert!(
        resume(&f.d.env(), &pending[0].migration_id)
            .unwrap()
            .complete
    );
}
#[test]
fn new_records_device_can_confirm_entered_schema_two_code_and_preserve_local_edits() {
    let f = fixture(2);
    let env = f.d.env();
    fs::remove_file(&env.state_path).unwrap();
    let record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&env.state_path, "new")
    else {
        panic!("records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut f.d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    let prepared = prepare(&env, Some(Zeroizing::new(f.code.clone()))).unwrap();
    assert_eq!(prepared.preview().source_kind, "new_join");
    let local_id = "0000000000000001";
    let device = Arc::new(f.d);
    let update = Arc::clone(&device);
    let receipt=with_test_step(move|s|{if s==Step::BeforeStateSave{record_runtime::mutate_records(&update.env(),|state|{let mut state=state.clone();state.local.hosts.insert(record_key(RecordKind::Host,local_id),LocalRecord{record:row(RecordKind::Host,local_id,json!({"schema":2,"alias":"concurrent","hostname":"local.test","auth":"password"})),seq:0,dirty:false});Ok(state)})?;}Ok(())},||confirm(&device.env(),prepared,consent())).unwrap();
    assert!(receipt.complete);
    assert!(record_runtime::snapshot(&device.env())
        .unwrap()
        .0
        .local
        .hosts
        .contains_key(&record_key(RecordKind::Host, local_id)));
}
#[test]
fn legacy_dirty_source_is_preserved_as_local_review_copy_without_overwriting_remote_host() {
    let f = fixture(2);
    {
        let mut core = f.d.runtime.core.lock().unwrap();
        core.state
            .as_mut()
            .unwrap()
            .spaces
            .get_mut(&f.space.chain_id)
            .unwrap()
            .records
            .insert(
                record_key(RecordKind::Host, "web"),
                LocalRecord {
                    record: row(
                        RecordKind::Host,
                        "web",
                        json!({"schema":1,"text":"Host web\n HostName unsent.test\n"}),
                    ),
                    seq: 0,
                    dirty: true,
                },
            );
    }
    let old = f.d.runtime.core.lock().unwrap().state.clone().unwrap();
    fs::write(f.d.env().state_path, serde_json::to_vec(&old).unwrap()).unwrap();
    let p = prepare(&f.d.env(), None).unwrap();
    assert!(p
        .preview()
        .diagnostics
        .iter()
        .any(|d| d.code == "dirty_legacy_copy_retained"));
    let receipt = confirm(&f.d.env(), p, consent()).unwrap();
    assert!(receipt.complete);
    let s = record_runtime::snapshot(&f.d.env()).unwrap().0;
    assert!(s
        .local
        .hosts
        .values()
        .any(|r| r.record.payload["hostname"] == "unsent.test"));
    assert_eq!(
        s.spaces[&f.space.chain_id]
            .records
            .values()
            .next()
            .unwrap()
            .record
            .payload["hostname"],
        "web.test"
    );
}
#[test]
fn deterministic_conversions_count_old_and_new_rows_before_any_schema_gate() {
    let f = fixture(2);
    for i in 0..2050 {
        push(
            &f.d,
            &f.space,
            &row(
                RecordKind::Host,
                &format!("host{i}"),
                json!({"schema":1,"text":format!("Host host{i}\n HostName node{i}.test\n PreferredAuthentications password\n")}),
            ),
        );
    }
    f.d.relay.clear_calls();
    assert!(prepare(&f.d.env(), None).is_err());
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
    assert!(f.d.relay.calls().iter().all(|c| c.starts_with("pull:")));
    assert_eq!(f.d.relay.rows(&f.space.chain_id).len(), 2051);
}
#[test]
fn migration_includes_only_proven_endpoint_pins_and_retains_original_pin_file() {
    let f = fixture(2);
    fs::write(
        f.d.main_path(),
        "Host web\n HostName web.test\n PreferredAuthentications password\n",
    )
    .unwrap();
    let private = crate::sync::slot_rules::test_keys::plain();
    let key = crate::vault::material::parse(&private).unwrap();
    let public = key.public_key().to_openssh().unwrap();
    let parts: Vec<_> = public.split_whitespace().collect();
    let pins = json!({"version":1,"pins":{"web":{"algorithm":parts[0],"public_key":parts[1],"fingerprint":key.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string(),"pinned_at_ms":10}}});
    let path = f.d.env().state_path.with_file_name("host-pins.json");
    let original = serde_json::to_vec(&pins).unwrap();
    fs::write(&path, &original).unwrap();
    let receipt = confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&f.d.env()).unwrap().0;
    let id = migration_host_id(&f.space.chain_id, "web").unwrap();
    assert_eq!(
        state.spaces[&f.space.chain_id].records[&record_key(RecordKind::Host, &id)]
            .record
            .payload["host_key"]["fingerprint"],
        pins["pins"]["web"]["fingerprint"]
    );
    assert_eq!(fs::read(path).unwrap(), original);
}
#[test]
fn confirmed_password_copy_preserves_alias_and_refuses_differing_destination_without_secret_metadata(
) {
    for conflict in [false, true] {
        let f = fixture(2);
        fs::write(
            f.d.main_path(),
            "Host web\n HostName web.test\n PreferredAuthentications password\n",
        )
        .unwrap();
        let id = migration_host_id(&f.space.chain_id, "web").unwrap();
        f.d.keychain
            .set("host:web", "PASSWORD_PRIVATE_SENTINEL")
            .unwrap();
        if conflict {
            f.d.keychain.set(&format!("host:{id}"), "existing").unwrap();
        }
        let prepared = prepare(&f.d.env(), None).unwrap();
        assert_eq!(
            f.d.keychain.entry(&format!("host:{id}")).as_deref(),
            if conflict { Some("existing") } else { None }
        );
        let receipt = confirm(&f.d.env(), prepared, consent()).unwrap();
        assert!(receipt.complete);
        assert_eq!(
            f.d.keychain.entry("host:web").as_deref(),
            Some("PASSWORD_PRIVATE_SENTINEL")
        );
        assert_eq!(
            f.d.keychain.entry(&format!("host:{id}")).as_deref(),
            if conflict {
                Some("existing")
            } else {
                Some("PASSWORD_PRIVATE_SENTINEL")
            }
        );
        let journal = fs::read_to_string(
            f.d.env()
                .state_path
                .parent()
                .unwrap()
                .join("migrations")
                .join(receipt.migration_id)
                .join("journal.json"),
        )
        .unwrap();
        assert!(!journal.contains("PASSWORD_PRIVATE_SENTINEL"));
        assert!(
            !serde_json::to_string(&record_runtime::snapshot(&f.d.env()).unwrap().0)
                .unwrap()
                .contains("PASSWORD_PRIVATE_SENTINEL")
        );
    }
}
#[test]
fn corrupt_original_vault_refuses_preview_without_archival_or_schema_mutation() {
    let f = fixture(2);
    let vault = f.d.env().state_path.with_file_name("vault.json");
    fs::write(&vault, b"{damaged PRIVATE_SENTINEL").unwrap();
    assert!(prepare(&f.d.env(), None).is_err());
    assert_eq!(fs::read(&vault).unwrap(), b"{damaged PRIVATE_SENTINEL");
    assert_eq!(fs::read_dir(vault.parent().unwrap()).unwrap().count(), 2);
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
    assert!(f.d.relay.calls().iter().all(|c| c.starts_with("pull:")));
}
#[test]
fn readonly_legacy_v1_decoder_migrates_directly_without_v1_upgrader_or_original_chain_deletion() {
    let f = fixture(2);
    let v1keys = crypto::derive_keys(&f.code).unwrap();
    f.d.relay
        .create_chain(&v1keys.chain_id, &v1keys.auth_token)
        .unwrap();
    push(
        &f.d,
        &v1keys,
        &row(
            RecordKind::Host,
            "old",
            json!({"schema":1,"text":"Host old\n HostName legacy.test\n PreferredAuthentications password\n"}),
        ),
    );
    let mut old = crate::sync::state::SyncState::fresh("legacy").unwrap();
    old.device_id = "b".repeat(32);
    old.relay_url = crate::sync::testkit::RELAY_URL.into();
    old.chain_id = Some(v1keys.chain_id.clone());
    let original = serde_json::to_vec(&old).unwrap();
    fs::write(f.d.env().state_path, &original).unwrap();
    {
        let mut c = f.d.runtime.core.lock().unwrap();
        c.state = None;
        c.legacy = Some(old);
        c.legacy_paused = true;
    }
    let receipt = confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&f.d.env()).unwrap().0;
    let space0 = crypto::derive_space0(&f.code).unwrap();
    assert!(state.spaces.contains_key(&space0.chain_id));
    assert_eq!(
        state.spaces[&space0.chain_id]
            .records
            .values()
            .next()
            .unwrap()
            .record
            .payload["hostname"],
        "legacy.test"
    );
    assert_eq!(f.d.relay.rows(&v1keys.chain_id).len(), 1);
    assert!(f.d.relay.calls().iter().all(|s| !s.starts_with("delete:")));
    assert_eq!(f.d.main_config(), "# main\n");
}
#[test]
fn an_unsaved_document_source_remains_protected_after_migration_clears_the_legacy_doc() {
    let f = fixture(2);
    let (items, trailing_newline) = crate::config::parser::parse_file(
        "Host unsaved\n HostName memory.test\n PreferredAuthentications password\n",
    );
    *f.d.doc.lock().unwrap() = Some(crate::config::model::SshConfigDoc {
        files: vec![crate::config::model::ConfigFile {
            path: f.d.main_path(),
            items,
            trailing_newline,
            fingerprint: crate::fsutil::fingerprint_of(&fs::read(f.d.main_path()).unwrap()),
        }],
    });
    let receipt = confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent()).unwrap();
    let dir =
        f.d.env()
            .state_path
            .parent()
            .unwrap()
            .join("migrations")
            .join(receipt.migration_id)
            .join("documents");
    let saved: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(saved.iter().any(|text| text.contains("Host unsaved")));
    assert!(record_runtime::snapshot(&f.d.env())
        .unwrap()
        .0
        .local
        .hosts
        .values()
        .any(|r| r.record.payload["hostname"] == "memory.test"));
    assert_eq!(f.d.main_config(), "# main\n");
}
#[test]
fn an_unjoined_legacy_profile_converts_local_sources_without_any_sync_code_or_relay() {
    let relay = FakeRelay::new();
    let d = TestDevice::with_main_config(
        "d",
        &relay,
        &TestClock::new(),
        "Host local\n HostName local.test\n PreferredAuthentications password\n",
    );
    {
        let mut core = d.runtime.core.lock().unwrap();
        core.state.as_mut().unwrap().device_id = "a".repeat(32);
        core.legacy_paused = true;
    }
    fs::create_dir_all(d.env().state_path.parent().unwrap()).unwrap();
    fs::write(
        d.env().state_path,
        serde_json::to_vec(&d.runtime.core.lock().unwrap().state).unwrap(),
    )
    .unwrap();
    let prepared = prepare(&d.env(), None).unwrap();
    assert_eq!(prepared.preview().account_schema, 0);
    assert!(prepared.preview().selected_space_ids.is_empty());
    let receipt = confirm(&d.env(), prepared, consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&d.env()).unwrap().0;
    assert!(state.account.is_none());
    assert_eq!(state.local.hosts.len(), 1);
    assert!(d.relay.calls().is_empty());
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_none());
}
#[test]
fn changed_local_sources_after_gate_do_not_allow_publication_or_discard_actual_user_file() {
    let f = fixture(2);
    assert!(with_test_step(
        |s| if s == Step::AccountGated {
            Err(failure("test interruption"))
        } else {
            Ok(())
        },
        || confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent())
    )
    .is_err());
    let id = pending_migrations(&f.d.env()).unwrap()[0]
        .migration_id
        .clone();
    fs::write(f.d.main_path(), "Host late\n HostName late-local.test\n").unwrap();
    f.d.relay.clear_calls();
    assert!(resume(&f.d.env(), &id).is_err());
    assert!(f.d.relay.calls().iter().all(|s| s.starts_with("pull:")));
    assert!(f.d.runtime.core.lock().unwrap().records.is_none());
    assert!(f.d.main_config().contains("late-local.test"));
}
#[test]
fn unsupported_known_secret_schema_cannot_establish_an_incomplete_active_baseline() {
    let f = fixture(2);
    let id = "a".repeat(32);
    push(
        &f.d,
        &f.account,
        &row(
            RecordKind::Key,
            &id,
            json!({"schema":4,"private_key":"PRIVATE_SENTINEL"}),
        ),
    );
    f.d.relay.clear_calls();
    let error = prepare(&f.d.env(), None)
        .err()
        .expect("unknown secret schema refuses active");
    assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
    assert!(f.d.relay.calls().iter().all(|s| s.starts_with("pull:")));
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
}
#[test]
fn existing_pending_join_staged_code_is_read_only_until_explicit_migration_confirmation() {
    let f = fixture(2);
    let env = f.d.env();
    fs::remove_file(&env.state_path).unwrap();
    let record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&env.state_path, "new")
    else {
        panic!("records")
    };
    let op_id = "e".repeat(32);
    let name = format!("sync:records-pending:{op_id}");
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    state.pending_account = Some(crate::sync::record_account::PendingAccountOperation {
        id: op_id,
        device_name: "new".into(),
        kind: crate::sync::record_account::PendingAccountKind::JoinAccount,
        phase: crate::sync::record_account::PendingAccountPhase::Prepared,
        migration_gate: None,
        relay_url: state.relay_url.clone(),
        staged_code_account: Some(name.clone()),
        prepared_account: AccountState::new(&f.account.chain_id),
        space_id: None,
        prepared_space: None,
    });
    f.d.keychain.set(&name, &f.code).unwrap();
    record_runtime::activate_probe(
        &mut f.d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    let prepared = prepare(&env, None).unwrap();
    assert_eq!(prepared.preview().source_kind, "pending_join");
    assert!(pending_migrations(&env).unwrap().is_empty());
    assert!(confirm(&env, prepared, consent()).unwrap().complete);
    assert!(record_runtime::snapshot(&env)
        .unwrap()
        .0
        .pending_account
        .is_none());
    assert_eq!(f.d.keychain.entry(&name).as_deref(), Some(f.code.as_str()));
}
#[test]
fn a_real_profile_lock_denies_second_process_migration_before_journal_or_credentials() {
    let f = fixture(2);
    let prepared = prepare(&f.d.env(), None).unwrap();
    let lock = publication::lock_profile(&f.d.env()).unwrap();
    f.d.relay.clear_calls();
    assert!(confirm(&f.d.env(), prepared, consent()).is_err());
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
    assert!(f.d.relay.calls().iter().all(|s| s.starts_with("pull:")));
    drop(lock);
}
#[test]
fn future_account_on_resume_leaves_pending_progress_and_primary_originals_unchanged() {
    let f = fixture(2);
    assert!(with_test_step(
        |s| if s == Step::AccountGated {
            Err(failure("test interruption"))
        } else {
            Ok(())
        },
        || confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent())
    )
    .is_err());
    let id = pending_migrations(&f.d.env()).unwrap()[0]
        .migration_id
        .clone();
    let envelope =
        f.d.relay
            .rows(&f.account.chain_id)
            .into_iter()
            .find(|e| e.kind == "meta")
            .unwrap();
    let mut meta = row(
        RecordKind::Meta,
        ACCOUNT_META_ID,
        json!({"schema_version":4,"created_by_app_version":"future"}),
    );
    meta.updated_at_ms = u64::MAX - 10;
    f.d.relay
        .push(
            &f.account.chain_id,
            &f.account.auth_token,
            &[record_merge::encode_record(&f.account, &meta, envelope.seq).unwrap()],
        )
        .unwrap();
    let original = fs::read(f.d.env().state_path).unwrap();
    f.d.relay.clear_calls();
    assert!(resume(&f.d.env(), &id).is_err());
    assert!(f.d.relay.calls().iter().all(|s| s.starts_with("pull:")));
    assert_eq!(fs::read(f.d.env().state_path).unwrap(), original);
}
#[test]
fn published_typed_row_disappearing_from_relay_refuses_incomplete_activation() {
    let f = fixture(2);
    assert!(with_test_step(
        |s| if s == Step::BatchSaved {
            Err(failure("test interruption"))
        } else {
            Ok(())
        },
        || confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent())
    )
    .is_err());
    let id = pending_migrations(&f.d.env()).unwrap()[0]
        .migration_id
        .clone();
    f.d.relay.roll_back(&f.space.chain_id, 1);
    assert!(resume(&f.d.env(), &id).is_err());
    assert!(f.d.runtime.core.lock().unwrap().records.is_none());
    assert_eq!(f.d.relay.rows(&f.space.chain_id).len(), 1);
}
#[test]
fn gate_replacement_bytes_are_reserved_before_journal_or_credential_staging() {
    let f = fixture(2);
    let mut n = 0u32;
    let mut last = None;
    loop {
        let used =
            f.d.relay
                .rows(&f.account.chain_id)
                .iter()
                .map(|e| e.ciphertext.len() + e.nonce.len())
                .sum::<usize>();
        let remaining = MAX_CHAIN_BYTES - 16 - used;
        let id = format!("{n:032x}");
        let make = |length: usize| {
            record_merge::encode_record(&f.account,&row(RecordKind::Device,&id,json!({"schema":1,"name":"x".repeat(length),"platform":"test","joined_at_ms":0,"last_seen_ms":0,"keys":[],"spaces":[]})),0).unwrap()
        };
        let mut low = 0;
        let mut high = 45000;
        while low < high {
            let mid = (low + high + 1) / 2;
            let item = make(mid);
            if item.ciphertext.len() + item.nonce.len() <= remaining {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        let item = make(low);
        if item.ciphertext.len() + item.nonce.len() > remaining {
            break;
        }
        f.d.relay
            .push(&f.account.chain_id, &f.account.auth_token, &[item])
            .unwrap();
        last = Some((id, low));
        n += 1;
    }
    // Enlarge one existing row to within 16-20 bytes of the chain cap; base64 size changes in steps of four.
    let (id, size) = last.unwrap();
    let old =
        f.d.relay
            .rows(&f.account.chain_id)
            .into_iter()
            .find(|e| e.id_hash == crypto::id_hash(&f.account, "device", &id))
            .unwrap();
    let used =
        f.d.relay
            .rows(&f.account.chain_id)
            .iter()
            .map(|e| e.ciphertext.len() + e.nonce.len())
            .sum::<usize>();
    let without = used - old.ciphertext.len() - old.nonce.len();
    let mut low = size;
    let mut high = 45000;
    while low < high {
        let mid = (low + high + 1) / 2;
        let item=record_merge::encode_record(&f.account,&row(RecordKind::Device,&id,json!({"schema":1,"name":"x".repeat(mid),"platform":"test","joined_at_ms":0,"last_seen_ms":0,"keys":[],"spaces":[]})),old.seq).unwrap();
        if without + item.ciphertext.len() + item.nonce.len() <= MAX_CHAIN_BYTES - 16 {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    let item=record_merge::encode_record(&f.account,&row(RecordKind::Device,&id,json!({"schema":1,"name":"x".repeat(low),"platform":"test","joined_at_ms":0,"last_seen_ms":0,"keys":[],"spaces":[]})),old.seq).unwrap();
    f.d.relay
        .push(&f.account.chain_id, &f.account.auth_token, &[item])
        .unwrap();
    f.d.relay.clear_calls();
    assert!(prepare(&f.d.env(), None).is_err());
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
    assert!(f.d.relay.calls().iter().all(|s| s.starts_with("pull:")));
}
#[test]
fn parallel_devices_preserve_an_existing_typed_tombstone_and_the_same_host_mapping() {
    let f = fixture(2);
    let second = Arc::new(TestDevice::new("b", &f.d.relay, &f.d.clock));
    second.keychain.set(MNEMONIC_ACCOUNT, &f.code).unwrap();
    {
        let mut c = second.runtime.core.lock().unwrap();
        let s = c.state.as_mut().unwrap();
        s.device_id = "c".repeat(32);
        s.account = Some(AccountState::new(&f.account.chain_id));
        s.spaces
            .insert(f.space.chain_id.clone(), SpaceState::new("work.config"));
        c.legacy_paused = true;
    }
    fs::create_dir_all(second.env().state_path.parent().unwrap()).unwrap();
    fs::write(
        second.env().state_path,
        serde_json::to_vec(&second.runtime.core.lock().unwrap().state).unwrap(),
    )
    .unwrap();
    let other = Arc::clone(&second);
    let space = f.space.clone();
    let typed = migration_host_id(&space.chain_id, "web").unwrap();
    let id = typed.clone();
    let receipt = with_test_step(
        move |s| {
            if s == Step::AccountGated {
                let other = Arc::clone(&other);
                let space = space.clone();
                let id = id.clone();
                std::thread::spawn(move || {
                    assert!(
                        confirm(
                            &other.env(),
                            prepare(&other.env(), None).unwrap(),
                            consent()
                        )
                        .unwrap()
                        .complete
                    );
                    let old = other
                        .relay
                        .rows(&space.chain_id)
                        .into_iter()
                        .find(|e| e.id_hash == crypto::id_hash(&space, "host", &id))
                        .unwrap();
                    let mut tombstone = row(RecordKind::Host, &id, serde_json::Value::Null);
                    tombstone.deleted = true;
                    tombstone.updated_at_ms = u64::MAX - 10;
                    other
                        .relay
                        .push(
                            &space.chain_id,
                            &space.auth_token,
                            &[record_merge::encode_record(&space, &tombstone, old.seq).unwrap()],
                        )
                        .unwrap();
                })
                .join()
                .unwrap();
            }
            Ok(())
        },
        || confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent()),
    )
    .unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&f.d.env()).unwrap().0;
    assert!(
        state.spaces[&f.space.chain_id].records[&record_key(RecordKind::Host, &typed)]
            .record
            .deleted
    );
    assert_eq!(f.d.relay.rows(&f.space.chain_id).len(), 2);
}
#[test]
fn rate_limit_backoff_retains_pending_progress_and_blocks_immediate_network_retry() {
    let f = fixture(2);
    let prepared = prepare(&f.d.env(), None).unwrap();
    f.d.relay.fail_pushes_with_429(1);
    assert!(confirm(&f.d.env(), prepared, consent()).is_err());
    let id = pending_migrations(&f.d.env()).unwrap()[0]
        .migration_id
        .clone();
    f.d.relay.clear_calls();
    assert!(resume(&f.d.env(), &id).is_err());
    assert!(f.d.relay.calls().is_empty());
    f.d.clock.advance(1_000_000);
    assert!(resume(&f.d.env(), &id).unwrap().complete);
}
#[test]
fn new_join_can_resume_with_reentered_code_after_scoped_credential_staging_denial() {
    let f = fixture(2);
    f.d.keychain.delete(MNEMONIC_ACCOUNT).unwrap();
    fs::remove_file(f.d.env().state_path).unwrap();
    let record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&f.d.env().state_path, "new")
    else {
        panic!("records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut f.d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    let prepared = prepare(&f.d.env(), Some(Zeroizing::new(f.code.clone()))).unwrap();
    let id = prepared.plan.migration_id.clone();
    let account = format!("{CODE_PREFIX}{id}");
    f.d.keychain.fail_writes_to(&account, true);
    f.d.relay.clear_calls();
    assert!(confirm(&f.d.env(), prepared, consent()).is_err());
    assert!(f.d.relay.calls().iter().all(|s| s.starts_with("pull:")));
    assert!(f.d.keychain.entry(MNEMONIC_ACCOUNT).is_none());
    f.d.keychain.fail_writes_to(&account, false);
    assert!(
        resume_with_code(&f.d.env(), &id, Zeroizing::new(f.code.clone()))
            .unwrap()
            .complete
    );
}
#[cfg(unix)]
#[test]
fn a_redirected_migration_directory_denies_before_lock_journal_or_credential_mutation() {
    let f = fixture(2);
    let prepared = prepare(&f.d.env(), None).unwrap();
    let id = prepared.plan.migration_id.clone();
    let data = f.d.env().state_path.parent().unwrap().to_path_buf();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("sentinel"), b"unchanged").unwrap();
    std::os::unix::fs::symlink(outside.path(), data.join("migrations")).unwrap();
    let state = fs::read(f.d.env().state_path).unwrap();
    assert!(crate::fsutil::with_test_write_policy(
        crate::write_policy::WritePolicy::Confined { root: data.clone() },
        || confirm(&f.d.env(), prepared, consent())
    )
    .is_err());
    assert!(!data.join("migration.lock").exists());
    assert!(!outside.path().join(id).exists());
    assert_eq!(
        fs::read(outside.path().join("sentinel")).unwrap(),
        b"unchanged"
    );
    assert_eq!(fs::read(f.d.env().state_path).unwrap(), state);
}
#[test]
fn future_primary_state_written_after_startup_is_preserved_before_any_preview_credentials_or_relay()
{
    let f = fixture(2);
    let future = b"{\"version\":4,\"private_marker\":\"PRIVATE_SENTINEL\"}";
    fs::write(f.d.env().state_path, future).unwrap();
    f.d.relay.clear_calls();
    assert!(prepare(&f.d.env(), None).is_err());
    assert_eq!(fs::read(f.d.env().state_path).unwrap(), future);
    assert!(f.d.relay.calls().is_empty());
    assert!(pending_migrations(&f.d.env()).unwrap().is_empty());
}
#[test]
fn changed_space_encryption_identity_after_gate_refuses_before_new_host_or_active_marker() {
    let f = fixture(2);
    assert!(with_test_step(
        |s| if s == Step::AccountGated {
            Err(failure("test interruption"))
        } else {
            Ok(())
        },
        || confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent())
    )
    .is_err());
    let id = pending_migrations(&f.d.env()).unwrap()[0]
        .migration_id
        .clone();
    let original =
        f.d.relay
            .rows(&f.account.chain_id)
            .into_iter()
            .find(|e| e.kind == "spacekey")
            .unwrap();
    let different = ChainKeys::generate().unwrap();
    let mut key = row(
        RecordKind::SpaceKey,
        &f.space.chain_id,
        json!({"schema":1,"auth_token":different.auth_token,"enc_key":different.enc_key_b64()}),
    );
    key.updated_at_ms = 10;
    f.d.relay
        .push(
            &f.account.chain_id,
            &f.account.auth_token,
            &[record_merge::encode_record(&f.account, &key, original.seq).unwrap()],
        )
        .unwrap();
    f.d.relay.clear_calls();
    assert!(resume(&f.d.env(), &id).is_err());
    assert!(f.d.relay.calls().iter().all(|s| s.starts_with("pull:")));
    assert!(f.d.runtime.core.lock().unwrap().records.is_none());
}
#[test]
fn legacy_file_boundary_actual_managed_edits_are_retained_as_local_review_copies() {
    let f = fixture(2);
    let path = f.d.ssh_dir().join("sshelter/work.config");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = "Host web\n HostName managed-unsent.test\n PreferredAuthentications password\n";
    fs::write(&path, text).unwrap();
    fs::write(f.d.main_path(), "Include ~/.ssh/sshelter/work.config\n").unwrap();
    let receipt = confirm(&f.d.env(), prepare(&f.d.env(), None).unwrap(), consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&f.d.env()).unwrap().0;
    assert!(state
        .local
        .hosts
        .values()
        .any(|r| r.record.payload["hostname"] == "managed-unsent.test"));
    assert_eq!(fs::read_to_string(path).unwrap(), text);
    assert_eq!(
        state.spaces[&f.space.chain_id]
            .records
            .values()
            .next()
            .unwrap()
            .record
            .payload["hostname"],
        "web.test"
    );
}
#[test]
fn legacy_file_boundary_new_record_join_does_not_implicitly_import_external_config() {
    let f = fixture(2);
    fs::remove_file(f.d.env().state_path).unwrap();
    let record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&f.d.env().state_path, "new")
    else {
        panic!("records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut f.d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    fs::write(
        f.d.main_path(),
        "Host external\n HostName external.test\n PreferredAuthentications password\n",
    )
    .unwrap();
    assert!(
        confirm(
            &f.d.env(),
            prepare(&f.d.env(), Some(Zeroizing::new(f.code))).unwrap(),
            consent()
        )
        .unwrap()
        .complete
    );
    assert!(record_runtime::snapshot(&f.d.env())
        .unwrap()
        .0
        .local
        .hosts
        .is_empty());
}
#[test]
fn legacy_file_boundary_resume_preserves_new_local_vault_entries_added_after_pause() {
    let f = fixture(2);
    fs::remove_file(f.d.env().state_path).unwrap();
    let record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&f.d.env().state_path, "new")
    else {
        panic!("records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut f.d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    let first = crate::sync::record_keys::import_local(
        &f.d.env(),
        "first",
        Zeroizing::new(crate::sync::slot_rules::test_keys::plain()),
        crate::vault::store::EntryOrigin::Imported,
    )
    .unwrap();
    assert!(with_test_step(
        |s| if s == Step::BeforeStateSave {
            Err(failure("test interruption"))
        } else {
            Ok(())
        },
        || confirm(
            &f.d.env(),
            prepare(&f.d.env(), Some(Zeroizing::new(f.code.clone()))).unwrap(),
            consent()
        )
    )
    .is_err());
    let id = pending_migrations(&f.d.env()).unwrap()[0]
        .migration_id
        .clone();
    let second = crate::sync::record_keys::import_local(
        &f.d.env(),
        "second",
        Zeroizing::new(crate::sync::slot_rules::test_keys::plain()),
        crate::vault::store::EntryOrigin::Imported,
    )
    .unwrap();
    let before = fs::read(f.d.env().state_path.with_file_name("vault.json")).unwrap();
    assert!(resume(&f.d.env(), &id).unwrap().complete);
    let state = record_runtime::snapshot(&f.d.env()).unwrap().0;
    assert!(state.local.keys.contains_key(&first.key_id));
    assert!(state.local.keys.contains_key(&second.key_id));
    assert_eq!(
        fs::read(f.d.env().state_path.with_file_name("vault.json")).unwrap(),
        before
    );
}

#[test]
fn records_join_rebase_preserves_a_local_host_deletion_during_publication() {
    let f = fixture(2);
    fs::remove_file(f.d.env().state_path).unwrap();
    let record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&f.d.env().state_path, "new")
    else {
        panic!("records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    let id = "0000000000000001";
    state.local.hosts.insert(
        record_key(RecordKind::Host, id),
        LocalRecord {
            record: row(
                RecordKind::Host,
                id,
                json!({"schema":2,"alias":"removed","hostname":"local.test","auth":"password"}),
            ),
            seq: 0,
            dirty: false,
        },
    );
    record_runtime::activate_probe(
        &mut f.d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    let prepared = prepare(&f.d.env(), Some(Zeroizing::new(f.code))).unwrap();
    let device = Arc::new(f.d);
    let update = Arc::clone(&device);
    assert!(
        with_test_step(
            move |s| {
                if s == Step::BeforeStateSave {
                    record_runtime::mutate_records(&update.env(), |state| {
                        let mut state = state.clone();
                        state.local.hosts.remove(&record_key(RecordKind::Host, id));
                        Ok(state)
                    })?;
                }
                Ok(())
            },
            || confirm(&device.env(), prepared, consent())
        )
        .unwrap()
        .complete
    );
    assert!(!record_runtime::snapshot(&device.env())
        .unwrap()
        .0
        .local
        .hosts
        .contains_key(&record_key(RecordKind::Host, id)));
}
