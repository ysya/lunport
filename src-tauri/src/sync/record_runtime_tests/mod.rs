use super::*;
use crate::sync::records_v3::{LocalState, STATE_VERSION};
use crate::sync::state_v2::SyncStateV2;
use std::fs;
fn state() -> SyncStateV3 {
    SyncStateV3 {
        version: 3,
        device_id: "d".repeat(32),
        device_name: "fixture".into(),
        relay_url: "http://127.0.0.1:8787".into(),
        account: None,
        spaces: Default::default(),
        local: LocalState::default(),
        rotation: None,
        migration_gate: None,
        shared_writes_blocked: false,
        pending_account: None,
        relay_features: None,
        legacy_v1_backup: None,
        phrase_cleanup_pending: false,
        notices: vec![],
        last_sync_ms: None,
        last_error: None,
    }
}
fn names(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}
#[test]
fn missing_state_starts_records_without_creating_state_or_parent() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("new/sync-state.json");
    let StartupProbe::Records { state, fresh } = probe_startup(&path, "New device") else {
        panic!("fresh records")
    };
    assert!(fresh);
    assert_eq!(state.version, STATE_VERSION);
    assert_eq!(state.device_name, "New device");
    assert!(crate::sync::slot_rules::is_slot_id(&state.device_id));
    assert!(state.account.is_none());
    assert!(state.local.hosts.is_empty());
    assert!(!path.parent().unwrap().exists());
}
#[test]
fn a_fresh_records_workspace_can_save_when_its_data_directory_does_not_exist() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("new-profile/data/sync-state.json");
    let StartupProbe::Records { state, fresh: true } = probe_startup(&path, "New device") else {
        panic!("missing directories must open a fresh records workspace")
    };
    save_active(&path, &state).unwrap();
    assert!(matches!(probe_startup(&path, "unused"), StartupProbe::Records { state: loaded, fresh: false } if *loaded == *state));
    assert!(!temp.path().join(".ssh").exists(), "records mode does not create a legacy SSH config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
#[test]
fn navigation_upgrade_retains_the_exact_previous_v4_state_once() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let mut previous = state();
    previous.version = 4;
    save_active(&path, &previous).unwrap();
    let bytes = fs::read(&path).unwrap();
    let mut next = previous;
    next.version = crate::sync::records_v3::NAVIGATION_STATE_VERSION;
    next.local.group_order = vec!["0000000000000001".into()];
    save_active(&path, &next).unwrap();
    let backup = path.with_file_name(format!(
        "sync-state-v4-{:x}.backup.json",
        Sha256::digest(&bytes)
    ));
    assert_eq!(fs::read(&backup).unwrap(), bytes);
    next.local.group_order.clear();
    save_active(&path, &next).unwrap();
    assert_eq!(fs::read(&backup).unwrap(), bytes);
    assert_eq!(names(temp.path()).len(), 2);
}
#[test]
fn received_navigation_metadata_promotes_the_local_decoder_before_publication() {
    use crate::sync::{
        crypto::ChainKeys,
        record::{record_key, LocalRecord, Record, RecordKind},
        state_v2::AccountState,
    };
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let mut previous = state();
    previous.version = 4;
    previous.account = Some(AccountState::new(&ChainKeys::generate().unwrap().chain_id));
    save_active(&path, &previous).unwrap();
    let bytes = fs::read(&path).unwrap();
    let mut core = crate::sync::runtime::SyncCore::default();
    activate_probe(
        &mut core,
        StartupProbe::Records {
            state: Box::new(previous.clone()),
            fresh: false,
        },
    )
    .unwrap();
    let mut candidate = previous;
    let record = Record {
        kind: RecordKind::Meta,
        id: crate::sync::group_order::RECORD_ID.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: candidate.device_id.clone(),
        deleted: false,
        payload: serde_json::json!({"schema":1,"ids":[]}),
    };
    candidate.account.as_mut().unwrap().records.insert(
        record_key(record.kind, &record.id),
        LocalRecord {
            record,
            seq: 0,
            dirty: false,
        },
    );
    persist_candidate(&mut core, &path, candidate).unwrap();
    assert_eq!(
        core.records.as_ref().unwrap().version,
        crate::sync::records_v3::NAVIGATION_STATE_VERSION
    );
    let backups: Vec<_> = fs::read_dir(temp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|p| {
            p.file_name()
                .to_string_lossy()
                .starts_with("sync-state-v4-")
        })
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].path()).unwrap(), bytes);
    let StartupProbe::Records {
        state: reopened, ..
    } = probe_startup(&path, "unused")
    else {
        panic!("new decoder")
    };
    assert_eq!(
        reopened.version,
        crate::sync::records_v3::NAVIGATION_STATE_VERSION
    );
}

#[test]
fn legacy_v1_and_v2_probe_retains_original_bytes_without_upgrade_or_rename() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let v1=br#"{"version":1,"chain_id":null,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"legacy","relay_url":"http://127.0.0.1:8787","cursor_seq":9,"password_sync":false,"records":{},"last_sync_ms":null,"last_error":null}"#.to_vec();
    let v2 = serde_json::to_vec(&SyncStateV2::fresh("old").unwrap()).unwrap();
    for (bytes, version) in [(v1, 1), (v2, 2)] {
        fs::write(&path, &bytes).unwrap();
        let StartupProbe::Legacy { state } = probe_startup(&path, "unused") else {
            panic!("legacy")
        };
        assert!(match state {
            DecodedState::V1(s) => s.version == version,
            DecodedState::V2(s) => s.version == version,
            _ => false,
        });
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(names(temp.path()), vec!["sync-state.json"]);
    }
}
#[test]
fn valid_v3_probe_returns_unchanged_records_without_saving_or_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let original = state();
    let bytes = serde_json::to_vec(&original).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert!(
        matches!(probe_startup(&path,"unused"),StartupProbe::Records{state:loaded,fresh:false} if *loaded==original)
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(names(temp.path()), vec!["sync-state.json"]);
}
#[test]
fn malformed_future_unknown_invalid_utf8_and_invalid_legacy_remain_original_and_blocked() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    for bytes in [
        b"broken".to_vec(),
        br#"{"version":99}"#.to_vec(),
        br#"{"version":0}"#.to_vec(),
        vec![255, 254],
        br#"{"version":1}"#.to_vec(),
        br#"{"version":2}"#.to_vec(),
    ] {
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            probe_startup(&path, "unused"),
            StartupProbe::Blocked { .. }
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(names(temp.path()), vec!["sync-state.json"]);
    }
}
#[test]
fn oversized_and_nonregular_paths_block_without_reading_or_modifying_them() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_STATE_BYTES + 1).unwrap();
    assert!(matches!(
        probe_startup(&path, "unused"),
        StartupProbe::Blocked { .. }
    ));
    assert_eq!(fs::metadata(&path).unwrap().len(), MAX_STATE_BYTES + 1);
    let directory = temp.path().join("directory");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("keep"), b"sentinel").unwrap();
    assert!(matches!(
        probe_startup(&directory, "unused"),
        StartupProbe::Blocked { .. }
    ));
    assert_eq!(fs::read(directory.join("keep")).unwrap(), b"sentinel");
}
#[cfg(unix)]
#[test]
fn a_redirected_state_file_is_blocked_without_touching_its_target() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let path = temp.path().join("sync-state.json");
    let bytes = serde_json::to_vec(&state()).unwrap();
    fs::write(&source, &bytes).unwrap();
    std::os::unix::fs::symlink(&source, &path).unwrap();
    assert!(matches!(
        probe_startup(&path, "unused"),
        StartupProbe::Blocked { .. }
    ));
    assert_eq!(fs::read(source).unwrap(), bytes);
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
}
#[test]
fn invalid_state_save_preserves_existing_bytes_and_creates_no_other_files() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    fs::write(&path, b"source").unwrap();
    let mut invalid = state();
    invalid.version = crate::sync::records_v3::TRANSPORT_SYNC_STATE_VERSION + 1;
    assert!(save_active(&path, &invalid).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"source");
    assert_eq!(names(temp.path()), vec!["sync-state.json"]);
    let path = temp.path().join("absent/sync-state.json");
    assert!(save_active(&path, &invalid).is_err());
    assert!(!path.parent().unwrap().exists());
}
#[test]
fn active_state_save_is_atomic_readable_and_secure() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("data/sync-state.json");
    let original = state();
    save_active(&path, &original).unwrap();
    assert!(
        matches!(probe_startup(&path,"unused"),StartupProbe::Records{state:loaded,fresh:false} if *loaded==original)
    );
    assert_eq!(names(path.parent().unwrap()), vec!["sync-state.json"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn save_io_failure_returns_error_without_modifying_an_existing_directory() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    fs::create_dir(&path).unwrap();
    fs::write(path.join("keep"), b"sentinel").unwrap();
    assert!(save_active(&path, &state()).is_err());
    assert!(path.is_dir());
    assert_eq!(fs::read(path.join("keep")).unwrap(), b"sentinel");
}

mod active;

#[test]
fn startup_error_classification_never_reports_unvalidated_payload_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    for (bytes, wanted) in [
        (
            br#"{"version":99,"unvalidated":"sensitive-marker"}"#.to_vec(),
            StartupErrorKind::UnsupportedVersion,
        ),
        (
            br#"{"version":3,"unvalidated":"sensitive-marker"}"#.to_vec(),
            StartupErrorKind::InvalidData,
        ),
    ] {
        fs::write(&path, &bytes).unwrap();
        let StartupProbe::Blocked { kind, reason } = probe_startup(&path, "unused") else {
            panic!("blocked")
        };
        assert_eq!(kind, wanted);
        assert!(!reason.contains("sensitive-marker"));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}
#[cfg(unix)]
#[test]
fn an_existing_fifo_is_refused_before_opening_and_cannot_block_startup() {
    use std::os::unix::ffi::OsStrExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the NUL-terminated fixture path is owned for this call and names a new FIFO in temp.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    assert!(matches!(
        probe_startup(&path, "unused"),
        StartupProbe::Blocked {
            kind: StartupErrorKind::UnsafePath,
            ..
        }
    ));
    assert!(fs::symlink_metadata(&path).is_ok());
}
#[test]
fn valid_remote_relationship_conflicts_are_saved_for_repair_without_blocking_startup() {
    use crate::sync::record::{record_key, LocalRecord, Record, RecordKind};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let mut records = state();
    for (id, jump) in [
        ("0000000000000001", "0000000000000002"),
        ("0000000000000002", "0000000000000001"),
    ] {
        records.local.hosts.insert(record_key(RecordKind::Host, id), LocalRecord {
            record: Record { kind: RecordKind::Host, id: id.into(), version: 1, updated_at_ms: 1, device_id: "d".repeat(32), deleted: false,
                payload: serde_json::json!({"schema":2,"alias":id,"hostname":"fixture.invalid","auth":"password","jump":[jump]}) },
            seq: 0, dirty: false,
        });
    }
    save_active(&path, &records).unwrap();
    assert!(
        matches!(probe_startup(&path, "unused"), StartupProbe::Records { state: loaded, fresh: false } if *loaded == records)
    );
}

#[test]
fn central_publication_is_persistent_and_cannot_remove_the_root_or_downgrade_after_restart() {
    let temp=tempfile::tempdir().unwrap();let path=temp.path().join("sync-state.json");
    let mut candidate=state();candidate.version=crate::sync::records_v3::CENTRAL_STATE_VERSION;
    let mut central=crate::sync::central::workspace::tests::enrolled();central.control.cutover=true;
    candidate.local.central=Some(central.clone());save_active(&path,&candidate).unwrap();
    let original=std::fs::read(&path).unwrap();
    let mut removed=candidate.clone();removed.local.central=None;
    assert!(save_active(&path,&removed).is_err());assert_eq!(std::fs::read(&path).unwrap(),original);
    let mut older=candidate.clone();older.version=crate::sync::records_v3::LOCAL_CONFLICT_STATE_VERSION;older.local.central=None;
    assert!(save_active(&path,&older).is_err());assert_eq!(std::fs::read(&path).unwrap(),original);
    let restored=match probe_startup(&path,"test") {StartupProbe::Records {state,..}=>*state,other=>panic!("unexpected {other:?}")};
    assert_eq!(restored.local.central.as_ref(),Some(&central));
    assert!(crate::sync::records_v3::decode_state(&serde_json::to_string(&restored).unwrap()).is_ok());
}

#[test]
fn a_central_history_page_cannot_overwrite_a_local_edit_saved_while_it_was_inflight() {
    use crate::sync::{central::{crypto::{DeviceKeys,VaultKeys},rekey::{Checkpoint,Version},wire::{canonical,RecordHeader}},
        fake_relay::FakeRelay,testkit::{TestClock,TestDevice},record::{LocalRecord,Record,RecordKind,record_key}};
    use base64::{engine::general_purpose::STANDARD as B64,Engine as _};
    let relay=FakeRelay::new();let device=TestDevice::new("a",&relay,&TestClock::new());let env=device.env();
    let mut records=state();records.version=crate::sync::records_v3::CENTRAL_STATE_VERSION;
    let mut workspace=crate::sync::central::workspace::tests::enrolled();workspace.control.cutover=true;
    let chain=workspace.control.verified_chain().unwrap();
    let fixture:serde_json::Value=serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json")).unwrap();
    let mut header:RecordHeader=serde_json::from_value(fixture["record"]["header"].clone()).unwrap();header.membership_head=chain.current().head().into();
    let keys=VaultKeys::from_bytes(&[3;64]).unwrap();let signer=DeviceKeys::decode_secret(&B64.encode([1;64])).unwrap();
    let replica=workspace.replica.as_mut().unwrap();replica.enqueue(&chain,&keys,&signer,1,header,b"A").unwrap();
    let sent=replica.prepare_send(&chain,1,1,&[]).unwrap().pop().unwrap();
    let digest=crate::sync::central::rekey::envelope_digest(&sent).unwrap();
    let hash=crate::sync::central::crypto::hash(&canonical(&["lunport-history-v2",&"0".repeat(64),"1",&digest]).unwrap());
    let row=Version {revision:"1".into(),sequence:"1".into(),envelope:sent,digest,history_hash:hash.clone()};
    let prepared=replica.prepare_page(&chain,&keys,&[row],&Checkpoint{epoch:1,sequence:1,history_hash:hash}).unwrap();
    let host_key=record_key(RecordKind::Host,"0000000000000001");
    records.local.hosts.insert(host_key.clone(),LocalRecord {record:Record {kind:RecordKind::Host,id:"0000000000000001".into(),
        version:1,updated_at_ms:1,device_id:records.device_id.clone(),deleted:false,
        payload:serde_json::json!({"schema":2,"alias":"test","hostname":"fixture.invalid","auth":"password","notes":"A"})},seq:0,dirty:true});
    records.local.central=Some(workspace);
    save_active(&env.state_path,&records).unwrap();
    activate_probe(&mut device.runtime.core.lock().unwrap(),StartupProbe::Records {state:Box::new(records),fresh:false}).unwrap();
    let (mut network_candidate,generation)=snapshot(&env).unwrap();
    network_candidate.local.central.as_mut().unwrap().replica=Some(prepared.next);
    mutate_records(&env,|current| {
        let mut next=current.clone();let row=next.local.hosts.get_mut(&host_key).unwrap();
        row.record.version+=1;row.record.payload["notes"]="B".into();Ok(next)
    }).unwrap();
    assert!(commit_candidate(&env,generation,network_candidate).is_err());
    let (latest,_)=snapshot(&env).unwrap();
    assert_eq!(latest.local.hosts[&host_key].record.payload["notes"],"B");
    let replica=latest.local.central.unwrap().replica.unwrap();
    assert_eq!(replica.checkpoint.sequence,0);assert!(replica.pending.values().next().unwrap().sent.is_some());
}

/// Design 2026-10-25: a transport (device-local, `local.transports`) needs state version `TRANSPORT_STATE_VERSION`, which an older
/// Lunport refuses to open. Every save goes through the runtime, so the runtime raises the version, as it does for tunnel rules.
#[test]
fn a_transport_promotes_the_state_version_when_persisted() {
    use crate::sync::transports::{self, HostTransport, TransportKind};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let previous = state();
    save_active(&path, &previous).unwrap();
    let mut core = crate::sync::runtime::SyncCore::default();
    activate_probe(&mut core, StartupProbe::Records { state: Box::new(previous.clone()), fresh: false }).unwrap();
    let transport = HostTransport {
        host_id: "0000000000000001".into(),
        kind: TransportKind::GcpIap {
            project: "eng-dev-396409".into(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic0".into(),
            account: None,
            os_login: true,
            pam: None,
        },
    };
    let mut candidate = transports::set(&previous, "0000000000000001", None, Some(transport), 1).unwrap();
    // A candidate that reached the runtime by another road than `transports::set` carries the version it had.
    candidate.version = previous.version;
    persist_candidate(&mut core, &path, candidate).unwrap();
    assert_eq!(core.records.as_ref().unwrap().version, crate::sync::records_v3::TRANSPORT_STATE_VERSION);
    let StartupProbe::Records { state: reopened, .. } = probe_startup(&path, "unused") else { panic!("records") };
    assert_eq!(reopened.version, crate::sync::records_v3::TRANSPORT_STATE_VERSION);
    assert!(transports::has_data(&reopened));
}

/// Design 2026-10-26: the device-local grant memory needs state version 10, the same way (and so will a library's synced route rows). A
/// candidate that reached the runtime by another road than `remember_grant_request` carries the version it had.
#[test]
fn grant_memory_promotes_the_state_version_when_persisted() {
    use crate::sync::transports::{self, GrantMemory};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("sync-state.json");
    let previous = state();
    save_active(&path, &previous).unwrap();
    let mut core = crate::sync::runtime::SyncCore::default();
    activate_probe(&mut core, StartupProbe::Records { state: Box::new(previous.clone()), fresh: false }).unwrap();
    let mut candidate = previous.clone();
    candidate.local.transport_grants.insert("0000000000000001".into(), GrantMemory { justification: "restart app-api".into(), duration_secs: 1800 });
    persist_candidate(&mut core, &path, candidate).unwrap();
    assert_eq!(core.records.as_ref().unwrap().version, crate::sync::records_v3::TRANSPORT_SYNC_STATE_VERSION);
    let StartupProbe::Records { state: reopened, .. } = probe_startup(&path, "unused") else { panic!("records") };
    assert_eq!(reopened.version, crate::sync::records_v3::TRANSPORT_SYNC_STATE_VERSION);
    assert_eq!(transports::grant_memory(&reopened, "0000000000000001").map(|memory| memory.duration_secs), Some(1800));
}
