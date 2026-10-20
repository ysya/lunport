use super::*;
use crate::sync::{
    record::{Envelope, RecordKind},
    record_merge,
    record_round::{
        self,
        tests::{add_space, fixture},
    },
    record_runtime,
    relay::{PullResponse, RelayApi},
};
use serde_json::json;
const HOST: &str = "0000000000000001";
fn host(note: &str, time: u64) -> Record {
    Record {
        kind: RecordKind::Host,
        id: HOST.into(),
        version: 1,
        updated_at_ms: time,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema":2,"alias":"web","hostname":"example.test","auth":"password","notes":note}),
    }
}
fn state(d: &crate::sync::testkit::TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
fn conflict_fixture() -> (std::sync::Arc<crate::sync::testkit::TestDevice>, ChainKeys) {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    d.relay
        .push(
            &child.chain_id,
            &child.auth_token,
            &[record_merge::encode_record(&child, &host("base", 2), 0).unwrap()],
        )
        .unwrap();
    record_round::sync_once(&d.env()).unwrap();
    record_runtime::mutate_records(&d.env(), |state| {
        let mut next = state.clone();
        let row = next
            .spaces
            .get_mut(&child.chain_id)
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::Host, HOST))
            .unwrap();
        row.record.payload["notes"] = json!("local offline");
        row.record.updated_at_ms = 1000000;
        row.record.version += 1;
        row.dirty = true;
        Ok(next)
    })
    .unwrap();
    d.relay
        .push(
            &child.chain_id,
            &child.auth_token,
            &[record_merge::encode_record(&child, &host("remote", 3), 1).unwrap()],
        )
        .unwrap();
    record_round::sync_once(&d.env()).unwrap();
    (d, child)
}
#[test]
fn restart_retains_three_versions_and_resolution_keeps_local_remote_or_a_host_copy() {
    for choice in [
        Resolution::Local,
        Resolution::Remote,
        Resolution::CopyRemote,
    ] {
        let (d, child) = conflict_fixture();
        let before = state(&d);
        let conflict =
            &before.spaces[&child.chain_id].recovery.conflicts["host:0000000000000001"][0];
        assert!(
            matches!(&conflict.base, Some(RecordVersion::Public(row)) if row.record.payload["notes"] == "base")
        );
        assert!(
            matches!(&conflict.local, RecordVersion::Public(row) if row.record.payload["notes"] == "local offline")
        );
        assert!(
            matches!(&conflict.remote, RecordVersion::Public(row) if row.record.payload["notes"] == "remote")
        );
        let record_runtime::StartupProbe::Records {
            state: restarted, ..
        } = record_runtime::probe_startup(&d.env().state_path, "restart")
        else {
            panic!("restart lost versions")
        };
        assert_eq!(before, *restarted);
        assert_eq!(
            before.version,
            crate::sync::records_v3::LOCAL_CONFLICT_STATE_VERSION
        );
        let view = views(&before).unwrap().remove(0);
        resolve_saved(
            &d.env(),
            view.space_id.as_deref(),
            &view.key,
            &view.token,
            choice,
            Some("web-copy"),
        )
        .unwrap();
        let after = state(&d);
        assert!(after.spaces[&child.chain_id].recovery.conflicts.is_empty());
        let row = &after.spaces[&child.chain_id].records["host:0000000000000001"];
        assert_eq!(row.seq, 2);
        assert_eq!(
            row.record.payload["notes"],
            if matches!(choice, Resolution::Remote) {
                "remote"
            } else {
                "local offline"
            }
        );
        assert_eq!(row.dirty, !matches!(choice, Resolution::Remote));
        if matches!(choice, Resolution::CopyRemote) {
            assert_eq!(after.spaces[&child.chain_id].records.len(), 2);
            assert!(after.spaces[&child.chain_id]
                .records
                .values()
                .any(|r| r.record.payload["alias"] == "web-copy"
                    && r.record.payload["notes"] == "remote"));
        }
        record_round::sync_once(&d.env()).unwrap();
        assert!(state(&d).spaces[&child.chain_id]
            .records
            .values()
            .all(|r| !r.dirty));
    }
}
#[test]
fn stale_resolution_never_clears_a_subsequent_local_edit_or_another_account() {
    let (d, child) = conflict_fixture();
    let before = state(&d);
    let view = views(&before).unwrap().remove(0);
    record_runtime::mutate_records(&d.env(), |state| {
        let mut next = state.clone();
        next.spaces
            .get_mut(&child.chain_id)
            .unwrap()
            .records
            .get_mut(&view.key)
            .unwrap()
            .record
            .payload["notes"] = json!("saved after opening review");
        Ok(next)
    })
    .unwrap();
    assert!(resolve_saved(
        &d.env(),
        view.space_id.as_deref(),
        &view.key,
        &view.token,
        Resolution::Remote,
        None
    )
    .is_err());
    assert_eq!(
        state(&d).spaces[&child.chain_id].recovery,
        before.spaces[&child.chain_id].recovery
    );
    let mut other = before.clone();
    other.relay_url = "https://other.test".into();
    assert!(resolve(
        &other,
        view.space_id.as_deref(),
        &view.key,
        &view.token,
        Resolution::Remote,
        None,
        None,
        9
    )
    .is_err());
    assert!(require_resolved(&before).is_err());
}
#[test]
fn secret_versions_and_resolution_never_put_private_material_in_state_or_ui() {
    let (d, _) = fixture();
    let mut before = state(&d);
    let keys = record_runtime::read_account_keys(&before, &d.keychain)
        .unwrap()
        .unwrap();
    let secret = |text: &str, time| Record {
        kind: RecordKind::Key,
        id: "a".repeat(32),
        version: 1,
        updated_at_ms: time,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema":1,"private_key":text}),
    };
    let local =
        record_merge::seal_secret_record(&keys, secret("local-test-secret", 50), 0).unwrap();
    let mut remote =
        record_merge::seal_secret_record(&keys, secret("remote-test-secret", 10), 0).unwrap();
    remote.envelope.seq = 2;
    remote.dirty = false;
    let key = local.envelope.kind.clone() + ":" + &local.envelope.id_hash;
    let account = before.account.as_mut().unwrap();
    account.sealed.insert(key.clone(), local.clone());
    account.recovery.retain(
        &key,
        RecordVersion::Sealed(local),
        RecordVersion::Sealed(remote),
    );
    upgrade_state(&mut before);
    let view = views(&before).unwrap().remove(0);
    for choice in [Resolution::Local, Resolution::Remote] {
        let after = resolve(
            &before,
            None,
            &key,
            &view.token,
            choice,
            None,
            Some(&keys),
            60,
        )
        .unwrap();
        let material = after.account.as_ref().unwrap().sealed[&key]
            .open(&keys)
            .unwrap();
        assert_eq!(
            material.payload["private_key"],
            if matches!(choice, Resolution::Local) {
                "local-test-secret"
            } else {
                "remote-test-secret"
            }
        );
        let disk = serde_json::to_string(&after).unwrap();
        let ui = serde_json::to_string(&views(&before).unwrap()).unwrap();
        for value in [disk, ui] {
            assert!(
                !value.contains("local-test-secret")
                    && !value.contains("remote-test-secret")
                    && !value.contains("private_key")
            );
        }
    }
}
#[test]
fn recovery_capacity_stops_before_cursor_or_local_content_changes() {
    let (d, child) = conflict_fixture();
    let mut before = state(&d).spaces[&child.chain_id].clone();
    let key = "host:0000000000000001";
    let template = before.recovery.conflicts[key][0].clone();
    before.recovery.conflicts.insert(
        key.into(),
        (0..8192)
            .map(|i| {
                let mut copy = template.clone();
                if let RecordVersion::Public(row) = &mut copy.remote {
                    row.seq = 2 + i;
                }
                copy
            })
            .collect(),
    );
    assert!(before.recovery.bounded());
    let item = record_merge::encode_record(&child, &host("one more remote", 5), 0).unwrap();
    let pulled = PullResponse {
        records: vec![Envelope {
            id_hash: item.id_hash,
            kind: item.kind,
            nonce: item.nonce,
            ciphertext: item.ciphertext,
            deleted: false,
            seq: 9000,
        }],
        latest_seq: 9000,
    };
    let outcome = record_merge::merge_space(
        &before,
        &child,
        &pulled,
        before.cursor_seq,
        &record_merge::AccountGate::Compatible,
    );
    assert_eq!(outcome.gate, record_merge::AccountGate::RecoveryFull);
    assert_eq!(outcome.section, before);
}
#[cfg(unix)]
#[test]
fn failed_resolution_persistence_keeps_all_unresolved_versions_in_memory_and_disk() {
    let (d, _) = conflict_fixture();
    let before = state(&d);
    let view = views(&before).unwrap().remove(0);
    let path = d.env().state_path;
    let backup = d.home.path().join("unchanged-state");
    std::fs::rename(&path, &backup).unwrap();
    std::os::unix::fs::symlink(&backup, &path).unwrap();
    assert!(resolve_saved(
        &d.env(),
        view.space_id.as_deref(),
        &view.key,
        &view.token,
        Resolution::Remote,
        None
    )
    .is_err());
    assert_eq!(state(&d), before);
    let persisted: SyncStateV3 = serde_json::from_slice(&std::fs::read(backup).unwrap()).unwrap();
    assert_eq!(persisted, before);
}

#[test]
fn push_conflict_response_is_saved_before_another_pull_and_does_not_advance_the_cursor() {
    let (d, child) = conflict_fixture();
    let view = views(&state(&d)).unwrap().remove(0);
    resolve_saved(
        &d.env(),
        view.space_id.as_deref(),
        &view.key,
        &view.token,
        Resolution::Local,
        None,
    )
    .unwrap();
    let relay = std::sync::Arc::clone(&d.relay);
    let remote_keys = child.clone();
    let connector = crate::sync::testkit::HookedConnector::new(
        &d.relay,
        crate::sync::testkit::Hooks {
            before_push: Some(Box::new(move || {
                relay
                    .push(
                        &remote_keys.chain_id,
                        &remote_keys.auth_token,
                        &[record_merge::encode_record(
                            &remote_keys,
                            &host("changed during upload", 7),
                            2,
                        )
                        .unwrap()],
                    )
                    .unwrap();
            })),
            ..Default::default()
        },
    );
    let mut env = d.env();
    env.relays = &connector;
    record_round::sync_once(&env).unwrap();
    let after = state(&d);
    let section = &after.spaces[&child.chain_id];
    assert_eq!(section.cursor_seq, 2); // response at 3 is saved without claiming a complete pull
    assert_eq!(section.recovery.conflicts.len(), 1);
    assert!(
        matches!(&section.recovery.conflicts[&view.key][0].remote, RecordVersion::Public(row) if row.record.payload["notes"] == "changed during upload" && row.seq == 3)
    );
    let record_runtime::StartupProbe::Records { state: disk, .. } =
        record_runtime::probe_startup(&env.state_path, "restart")
    else {
        panic!("conflict receipt missing")
    };
    assert_eq!(*disk, after);
    assert!(
        record_merge::space_outgoing(section, &child, &record_merge::AccountGate::Compatible)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_conflict_response_cannot_replace_a_different_record() {
    let (d, child) = conflict_fixture();
    let view = views(&state(&d)).unwrap().remove(0);
    let resolved = resolve(
        &state(&d),
        view.space_id.as_deref(),
        &view.key,
        &view.token,
        Resolution::Local,
        None,
        None,
        30,
    )
    .unwrap();
    let section = &resolved.spaces[&child.chain_id];
    let sent =
        record_merge::space_outgoing(section, &child, &record_merge::AccountGate::Compatible)
            .unwrap();
    let mut different = host("wrong record", 50);
    different.id = "0000000000000002".into();
    let item = record_merge::encode_record(&child, &different, 0).unwrap();
    let pushed = crate::sync::merge::Pushed {
        conflicts: 1,
        conflict_rows: vec![Envelope {
            id_hash: item.id_hash,
            kind: item.kind,
            nonce: item.nonce,
            ciphertext: item.ciphertext,
            seq: 3,
            deleted: false,
        }],
        ..Default::default()
    };
    let mut copy = section.clone();
    assert!(record_merge::retain_push_conflicts(
        &mut copy.records,
        &mut copy.sealed,
        &mut copy.recovery,
        &child,
        false,
        &sent,
        &pushed
    )
    .is_err());
    assert_eq!(&copy, section);
}
