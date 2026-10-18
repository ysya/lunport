use super::*;
use crate::sync::{
    central::{
        active_dispatch::tests::fixture,
        crypto,
        payload::{self, Data, Identity},
        rekey,
        wire::{canonical, RecordHeader},
    },
    record_import::central_local::tests::selected_session,
};
use std::fs;
fn state(d: &crate::sync::testkit::TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
fn page_for(d: &crate::sync::testkit::TestDevice, envelopes: Vec<RecordEnvelope>) -> Page {
    let state = state(d);
    let owner = state.local.central.as_ref().unwrap();
    let replica = owner.replica.as_ref().unwrap();
    let mut sequence = replica.checkpoint.sequence;
    let mut hash = replica.checkpoint.history_hash.clone();
    let mut records = vec![];
    for envelope in envelopes {
        sequence += 1;
        let digest = rekey::envelope_digest(&envelope).unwrap();
        hash = crypto::hash(
            &canonical(&["lunport-history-v2", &hash, &sequence.to_string(), &digest]).unwrap(),
        );
        records.push(Version {
            revision: (number(&envelope.header.expected_revision, true).unwrap() + 1).to_string(),
            sequence: sequence.to_string(),
            envelope,
            digest,
            history_hash: hash.clone(),
        });
    }
    Page {
        records,
        sequence: sequence.to_string(),
        history_hash: hash,
        membership_head: owner.control.highwater.as_ref().unwrap().head.clone(),
        epoch: replica.checkpoint.epoch,
        phase: "ready".into(),
    }
}
fn remote_page(d: &crate::sync::testkit::TestDevice, count: usize) -> (Page, String) {
    let state = state(d);
    let context = Context::load(&d.env(), &state).unwrap();
    let owner = state.local.central.as_ref().unwrap();
    let replica = owner.replica.as_ref().unwrap();
    let anchor = owner.control.anchor.as_ref().unwrap();
    let template = state.local.hosts.values().next().unwrap();
    let id = template.record.id.clone();
    let mut envelopes = vec![];
    for index in 0..count {
        let logical = if index == 0 {
            id.clone()
        } else {
            format!("{:016x}", index + 0x1000)
        };
        let identity = Identity {
            kind: "host".into(),
            id: logical,
            scope: Some(crate::sync::records_v3::HostScope::Local),
        };
        let mut host: crate::sync::records_v3::HostPayload =
            serde_json::from_value(template.record.payload.clone()).unwrap();
        host.alias = format!("remote_c_{index}");
        let opaque = identity.opaque(context.keys()).unwrap();
        let header = RecordHeader {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: replica.vault.clone(),
            record_id: opaque.clone(),
            key_epoch: replica.checkpoint.epoch.to_string(),
            membership_head: owner.control.highwater.as_ref().unwrap().head.clone(),
            author: owner.control.device.id.clone(),
            operation_id: crypto::random_id(16).unwrap(),
            expected_revision: replica
                .current
                .get(&opaque)
                .map_or("0", |b| b.version.revision.as_str())
                .into(),
            kind: "host".into(),
            deleted: false,
        };
        envelopes.push(
            crypto::seal_record(
                context.keys(),
                context.signer(),
                header,
                &payload::encode(&identity, &Data::Host(host)).unwrap(),
            )
            .unwrap(),
        );
    }
    (page_for(d, envelopes), id)
}
#[test]
fn valid_page_advances_only_ciphertext_and_never_activates_public_or_private_cache() {
    let (d, _) = fixture();
    let before = state(&d);
    let vault = fs::read(crate::vault::store::vault_path(&d.env().state_path)).unwrap();
    let (page, _) = remote_page(&d, 2);
    let report = with_transport(&d.env(), |_, _, since| {
        assert_eq!(
            since,
            before
                .local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .checkpoint
                .sequence
        );
        Ok(page)
    })
    .unwrap();
    let after = state(&d);
    assert_eq!(report.staged, 2);
    assert!(!report.more);
    assert!(!report.revalidate);
    let mut expected = before.clone();
    expected.local.central = after.local.central.clone();
    assert_eq!(expected, after);
    assert_eq!(
        after.local.central_projection,
        before.local.central_projection
    );
    assert_eq!(after.local.keys, before.local.keys);
    assert_eq!(
        fs::read(crate::vault::store::vault_path(&d.env().state_path)).unwrap(),
        vault
    );
}
#[test]
fn local_b_created_during_http_survives_and_conflicts_with_authenticated_remote_c() {
    let (d, _) = fixture();
    let (page, id) = remote_page(&d, 1);
    let report = with_transport(&d.env(), |_, _, _| {
        let (mut local, generation) = record_runtime::snapshot(&d.env())?;
        local
            .local
            .hosts
            .get_mut(&crate::sync::record::record_key(
                crate::sync::record::RecordKind::Host,
                &id,
            ))
            .unwrap()
            .record
            .payload["alias"] = "local_b".into();
        record_runtime::commit_candidate(&d.env(), generation, local)?;
        Ok(page)
    })
    .unwrap();
    assert_eq!(report.staged, 1);
    let after = state(&d);
    assert_eq!(
        after.local.hosts
            [&crate::sync::record::record_key(crate::sync::record::RecordKind::Host, &id)]
            .record
            .payload["alias"],
        "local_b"
    );
    let owner = after.local.central.as_ref().unwrap();
    let context = Context::load(&d.env(), &after).unwrap();
    let opaque = Identity {
        kind: "host".into(),
        id,
        scope: Some(crate::sync::records_v3::HostScope::Local),
    }
    .opaque(context.keys())
    .unwrap();
    assert!(owner
        .replica
        .as_ref()
        .unwrap()
        .pending
        .contains_key(&opaque));
    assert!(owner
        .replica
        .as_ref()
        .unwrap()
        .conflicts
        .contains_key(&opaque));
}
#[test]
fn a_bad_later_row_rejects_the_entire_page_and_keeps_the_old_disk_and_core() {
    let (d, _) = fixture();
    let before = state(&d);
    let disk = fs::read(&d.env().state_path).unwrap();
    let (mut page, _) = remote_page(&d, 2);
    page.records[1].envelope.signature = "AAAA".into();
    page.records[1].digest = rekey::envelope_digest(&page.records[1].envelope).unwrap();
    page.records[1].history_hash = crypto::hash(
        &canonical(&[
            "lunport-history-v2",
            &page.records[0].history_hash,
            &page.records[1].sequence,
            &page.records[1].digest,
        ])
        .unwrap(),
    );
    page.history_hash = page.records[1].history_hash.clone();

    assert!(with_transport(&d.env(), |_, _, _| Ok(page)).is_err());
    assert_eq!(state(&d), before);
    assert_eq!(fs::read(&d.env().state_path).unwrap(), disk);
}
#[test]
fn changed_session_discards_a_late_page_without_changing_ciphertext() {
    let (d, _) = fixture();
    let before = state(&d);
    let (page, _) = remote_page(&d, 1);
    assert!(with_transport(&d.env(), |_, _, _| {
        d.runtime.core.lock().unwrap().central_session =
            Some(selected_session(&d, Duration::from_secs(300)));
        Ok(page)
    })
    .is_err());
    assert_eq!(state(&d), before);
}
#[test]
fn new_epoch_head_or_rekey_notice_only_quiesces_dispatch_and_does_not_accept_rows() {
    for kind in 0..3 {
        let (d, _) = fixture();
        let before = state(&d);
        let (mut page, _) = remote_page(&d, 1);
        if kind == 0 {
            page.epoch += 1;
        } else if kind == 1 {
            page.membership_head = "e".repeat(64);
            assert_ne!(
                page.membership_head,
                before
                    .local
                    .central
                    .as_ref()
                    .unwrap()
                    .control
                    .highwater
                    .as_ref()
                    .unwrap()
                    .head
            );
        } else {
            page.phase = "rekey_pending".into();
        }
        let report = with_transport(&d.env(), |_, _, _| Ok(page)).unwrap();
        assert!(report.revalidate);
        assert_eq!(report.staged, 0);
        let mut expected = before;
        expected.local.central.as_mut().unwrap().control.phase =
            crate::sync::central::client_state::Phase::Rekey;
        assert_eq!(state(&d), expected);
        assert!(super::super::prepare(&d.env(), None).is_err());
    }
}
#[test]
fn signed_history_clears_own_public_sent_and_releases_the_dependent_private_batch() {
    let (d, _) = fixture();
    let operation = super::super::prepare(&d.env(), None)
        .unwrap()
        .operation
        .unwrap();
    let page = page_for(&d, operation.records.clone());
    with_transport(&d.env(), |_, _, _| Ok(page)).unwrap();
    let next = super::super::prepare(&d.env(), None)
        .unwrap()
        .operation
        .unwrap();
    assert_eq!(next.records.len(), 1);
    assert_eq!(next.records[0].header.kind, "key");
}
#[test]
fn strict_pull_publication_faults_preserve_prior_core_and_restart_recovers_a_completed_disk_write()
{
    use record_runtime::{with_replacement_write_hook, ReplacementWriteStage as Stage};
    for stop in [Stage::FileSync, Stage::DirectorySync] {
        let (d, _) = fixture();
        let before = state(&d);
        let (page, _) = remote_page(&d, 1);
        let path = d.env().state_path.clone();
        let result = with_replacement_write_hook(
            Box::new(move |stage, target| {
                if target == path && stage == stop {
                    Err(invalid())
                } else {
                    Ok(())
                }
            }),
            || with_transport(&d.env(), |_, _, _| Ok(page)),
        );
        assert!(result.is_err());
        assert_eq!(state(&d), before);
        if stop == Stage::DirectorySync {
            assert!(d.runtime.core.lock().unwrap().save_blocked.is_some());
            let probe = record_runtime::probe_startup(&d.env().state_path, "restart");
            record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
            assert_eq!(
                state(&d)
                    .local
                    .central
                    .as_ref()
                    .unwrap()
                    .replica
                    .as_ref()
                    .unwrap()
                    .checkpoint
                    .sequence,
                before
                    .local
                    .central
                    .as_ref()
                    .unwrap()
                    .replica
                    .as_ref()
                    .unwrap()
                    .checkpoint
                    .sequence
                    + 1
            );
        }
    }
}

#[test]
fn a_checkpoint_advanced_by_another_verified_operation_rejects_the_late_old_request() {
    let (d, _) = fixture();
    let (page, _) = remote_page(&d, 1);
    let other = page.records[0].envelope.clone();
    let result = with_transport(&d.env(), |_, _, _| {
        let (mut current, generation) = record_runtime::snapshot(&d.env())?;
        let context = Context::load(&d.env(), &current)?;
        crate::sync::central::outbox::tests::accept(&mut current, context.keys(), other);
        record_runtime::commit_candidate(&d.env(), generation, current)?;
        Ok(page)
    });
    assert!(result.is_err());
    let saved: SyncStateV3 =
        serde_json::from_slice(&fs::read(&d.env().state_path).unwrap()).unwrap();
    assert_eq!(state(&d), saved);
}
#[test]
fn over_limit_or_rollback_metadata_never_updates_control_or_checkpoint() {
    for oversize in [false, true] {
        let (d, _) = fixture();
        let before = state(&d);
        let (mut page, _) = remote_page(&d, if oversize { 33 } else { 1 });
        if !oversize {
            page.epoch = 0;
        }
        assert!(with_transport(&d.env(), |_, _, _| Ok(page)).is_err());
        assert_eq!(state(&d), before);
    }
}

#[test]
fn notifications_after_pull_and_revalidation_never_hold_runtime_locks() {
    for revalidate in [false, true] {
        let (d, _) = fixture();
        let probe = crate::sync::central::active_dispatch::tests::AssertUnlocked {
            runtime: &d.runtime,
        };
        let mut env = d.env();
        env.events = &probe;
        let (mut page, _) = remote_page(&d, 1);
        if revalidate {
            page.phase = "rekey_pending".into();
        }
        with_transport(&env, |_, _, _| Ok(page)).unwrap();
    }
}

#[test]
fn a_new_local_key_completes_public_private_history_and_reuses_its_protected_source_on_first_projection(
) {
    let (d, id) = fixture();
    let original = state(&d).local.keys[&id].vault_id.clone();
    let vault_before = fs::read(crate::vault::store::vault_path(&d.env().state_path)).unwrap();
    for kind in ["keyslot", "key"] {
        let operation = super::super::prepare(&d.env(), None)
            .unwrap()
            .operation
            .unwrap();
        assert_eq!(operation.records.len(), 1);
        assert_eq!(operation.records[0].header.kind, kind);
        let page = page_for(&d, operation.records.clone());
        with_transport(&d.env(), |_, _, _| Ok(page)).unwrap();
    }
    let current = state(&d);
    let context = Context::load(&d.env(), &current).unwrap();
    let delta =
        crate::sync::central::LibraryDelta::prepare(&current, context.keys(), d.env().now())
            .unwrap();
    assert!(delta.has_changes());
    let staged = crate::sync::record_import::central_stage::prepare(&d.env(), &delta).unwrap();
    crate::sync::record_import::central_stage::publish(
        &d.env(),
        staged.operation(),
        context.keys(),
    )
    .unwrap();
    let after = state(&d);
    assert_eq!(after.local.keys[&id].vault_id, original);
    assert_eq!(
        fs::read(crate::vault::store::vault_path(&d.env().state_path)).unwrap(),
        vault_before
    );
    assert_eq!(
        crate::sync::record_repository::resolve_key(&after, &id)
            .unwrap()
            .status,
        crate::sync::record_repository::KeyStatus::Available
    );
}
