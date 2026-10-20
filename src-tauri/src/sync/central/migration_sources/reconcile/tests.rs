use super::*;
use crate::sync::{
    central::{
        migration::legacy_checkpoint,
        migration_freeze::{Phase as FreezePhase, ProofStep},
        migration_library,
        migration_materials::Materials,
        payload::Data,
    },
    record::{SpaceKeyPayload, SpacePayload},
    record_conflicts::{RecordConflict, RecordVersion},
    relay::PullResponse,
    state_v2::AccountState,
    testkit::MemKeychain,
};
use crate::vault::store;
use serde_json::json;
const HOST: &str = "1111111111111111";
fn host(alias: &str, version: u64, seq: u64, dirty: bool) -> LocalRecord {
    LocalRecord {
        record: Record {
            kind: RecordKind::Host,
            id: HOST.into(),
            version,
            updated_at_ms: version,
            device_id: "d".repeat(32),
            deleted: false,
            payload: json!({"schema":2,"alias":alias,"hostname":"fixture.invalid","auth":"password"}),
        },
        seq,
        dirty,
    }
}
struct Fixture {
    state: SyncStateV3,
    parent: ChainKeys,
    child: ChainKeys,
    remote: Vec<LocalRecord>,
    parent_override: Vec<LocalRecord>,
}
impl Fixture {
    fn new() -> Self {
        let (owner, _, _) = crate::sync::central::migration_history::tests::initial();
        let parent = ChainKeys::generate().unwrap();
        let child = ChainKeys::generate().unwrap();
        let mut state:SyncStateV3=serde_json::from_value(json!({"version":8,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":owner.control.profile.origin,"last_sync_ms":null,"last_error":null})).unwrap();
        state.local.central = Some(owner);
        let mut account = AccountState::new(&parent.chain_id);
        let mut secret = SealedRecord::seal(
            &parent,
            &Record {
                kind: RecordKind::SpaceKey,
                id: child.chain_id.clone(),
                version: 1,
                updated_at_ms: 1,
                device_id: state.device_id.clone(),
                deleted: false,
                payload: serde_json::to_value(SpaceKeyPayload::from_keys(&child)).unwrap(),
            },
            1,
        )
        .unwrap();
        secret.dirty = false;
        account.sealed.insert(secret.key(), secret);
        let collection = LocalRecord {
            record: Record {
                kind: RecordKind::Space,
                id: child.chain_id.clone(),
                version: 1,
                updated_at_ms: 1,
                device_id: state.device_id.clone(),
                deleted: false,
                payload: serde_json::to_value(SpacePayload {
                    schema: 1,
                    name: "Unselected".into(),
                    slug: "unselected".into(),
                    created_at_ms: 1,
                    previous_id: None,
                })
                .unwrap(),
            },
            seq: 2,
            dirty: false,
        };
        account
            .records
            .insert(record_key(RecordKind::Space, &child.chain_id), collection);
        state.account = Some(account);
        let mut space = SpaceStateV3 {
            selected: false,
            missing: true,
            ..Default::default()
        };
        let a = host("A", 1, 1, false);
        let key = record_key(RecordKind::Host, HOST);
        space.records.insert(key.clone(), a.clone());
        space.recovery.bases.insert(key, RecordVersion::Public(a));
        state.spaces.insert(child.chain_id.clone(), space);
        let mut local = host("native-local", 1, 0, false);
        local.record.id = "2222222222222222".into();
        state
            .local
            .hosts
            .insert(record_key(RecordKind::Host, &local.record.id), local);
        Self {
            state,
            parent,
            child,
            remote: vec![host("C", 3, 3, false)],
            parent_override: vec![],
        }
    }
    fn current(&mut self) -> &mut LocalRecord {
        self.state
            .spaces
            .get_mut(&self.child.chain_id)
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::Host, HOST))
            .unwrap()
    }
    fn frozen(&self) -> (Sources, FrozenSet) {
        let sources = Sources::discover(&self.state, Some(&self.parent)).unwrap();
        let owner = self.state.local.central.as_ref().unwrap();
        let (_, _, signer) = crate::sync::central::migration_history::tests::initial();
        let intent = sources
            .intent(owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
            .unwrap();
        let account = self.state.account.as_ref().unwrap();
        let mut records: Vec<_> = account
            .sealed
            .values()
            .map(|v| v.envelope.clone())
            .collect();
        for row in account.records.values() {
            records.push(
                SealedRecord::seal(&self.parent, &row.record, row.seq)
                    .unwrap()
                    .envelope,
            );
        }
        for row in &self.parent_override {
            let envelope = SealedRecord::seal(&self.parent, &row.record, row.seq)
                .unwrap()
                .envelope;
            records.retain(|v| v.id_hash != envelope.id_hash);
            records.push(envelope);
        }
        let parent_seq = records.iter().map(|v| v.seq).max().unwrap_or(0);
        let parent = PullResponse {
            records,
            latest_seq: parent_seq,
        };
        let child = PullResponse {
            records: self
                .remote
                .iter()
                .map(|row| {
                    SealedRecord::seal(&self.child, &row.record, row.seq)
                        .unwrap()
                        .envelope
                })
                .collect(),
            latest_seq: 10,
        };
        let mut checkpoints = vec![
            legacy_checkpoint(&self.parent.chain_id, parent.latest_seq, &parent.records).unwrap(),
            legacy_checkpoint(&self.child.chain_id, child.latest_seq, &child.records).unwrap(),
        ];
        checkpoints.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));
        let progress = Progress {
            proof: vec![ProofStep {
                digest: intent.digest().unwrap(),
                intent,
            }],
            sources: checkpoints,
            phase: FreezePhase::Frozen,
            next: vec![],
        };
        let snapshots = vec![
            sources
                .admit_frozen(
                    owner,
                    &"7".repeat(32),
                    &progress,
                    None,
                    &self.parent.chain_id,
                    parent,
                )
                .unwrap(),
            sources
                .admit_frozen(
                    owner,
                    &"7".repeat(32),
                    &progress,
                    None,
                    &self.child.chain_id,
                    child,
                )
                .unwrap(),
        ];
        let frozen = FrozenSet::capture(
            &self.state,
            &sources,
            &"7".repeat(32),
            &progress,
            None,
            snapshots,
        )
        .unwrap();
        (sources, frozen)
    }
    fn plan(&self) -> Reconciliation {
        let (sources, frozen) = self.frozen();
        frozen.reconcile(&sources, &self.state).unwrap()
    }
}
fn alias(state: &SyncStateV3, child: &str) -> String {
    state.spaces[child].records[&record_key(RecordKind::Host, HOST)]
        .record
        .payload["alias"]
        .as_str()
        .unwrap()
        .into()
}
#[test]
fn clean_local_a_and_newer_remote_c_preserve_a_and_put_c_last_in_actual_structured_history() {
    let f = Fixture::new();
    let before = serde_json::to_vec(&f.state).unwrap();
    let prepared = f.plan().prepare().unwrap();
    assert_eq!(alias(&prepared.state, &f.child.chain_id), "C");
    assert!(!prepared.state.spaces[&f.child.chain_id].missing);
    let (owner, keys, _) = crate::sync::central::migration_history::tests::initial();
    drop(owner);
    let memory = MemKeychain::default();
    let vault = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
    let materials =
        Materials::from_vault(&prepared.state, &keys, &vault, &BTreeMap::new()).unwrap();
    let history = migration_library::prepare(&prepared.state, &prepared.known, materials)
        .unwrap()
        .into_rows();
    let aliases: Vec<_> = history
        .iter()
        .filter_map(|(id, data)| match data {
            Data::Host(host) if id.id == HOST => Some(host.alias.as_str()),
            _ => None,
        })
        .collect();
    assert!(aliases.contains(&"A"));
    assert_eq!(aliases.last(), Some(&"C"));
    assert!(history
        .iter()
        .any(|(_, data)| matches!(data,Data::Host(h)if h.alias=="native-local")));
    assert_eq!(serde_json::to_vec(&f.state).unwrap(), before);
}
#[test]
fn dirty_b_is_kept_only_when_remote_still_equals_the_exact_clean_base_a() {
    let mut f = Fixture::new();
    *f.current() = host("B", 2, 1, true);
    f.remote = vec![host("A", 1, 1, false)];
    let prepared = f.plan().prepare().unwrap();
    assert_eq!(alias(&prepared.state, &f.child.chain_id), "B");
    assert!(
        prepared.state.spaces[&f.child.chain_id].records[&record_key(RecordKind::Host, HOST)].dirty
    );
    assert!(prepared
        .known
        .rows()
        .iter()
        .any(|row| row.location.position == Position::Retained
            && matches!(&row.data,super::super::KnownData::Host(h)if h.alias=="A")));
}
#[test]
fn already_accepted_dirty_b_uses_the_remote_copy_without_discarding_the_local_original() {
    let mut f = Fixture::new();
    *f.current() = host("B", 2, 1, true);
    f.remote = vec![host("B", 2, 3, false)];
    let prepared = f.plan().prepare().unwrap();
    let current =
        &prepared.state.spaces[&f.child.chain_id].records[&record_key(RecordKind::Host, HOST)];
    assert_eq!(current.seq, 3);
    assert!(!current.dirty);
    assert_eq!(alias(&prepared.state, &f.child.chain_id), "B");
    assert!(prepared
        .known
        .rows()
        .iter()
        .any(|r| r.dirty && r.location.position == Position::Retained));
}
#[test]
fn parallel_b_and_c_or_an_unknown_common_base_remain_explicit_conflicts() {
    for with_base in [true, false] {
        let mut f = Fixture::new();
        *f.current() = host("B", 2, 1, true);
        if !with_base {
            f.state
                .spaces
                .get_mut(&f.child.chain_id)
                .unwrap()
                .recovery
                .bases
                .clear();
        }
        let plan = f.plan();
        assert!(plan
            .conflicts()
            .iter()
            .any(|c| c.reason == Reason::ParallelChanges
                && c.inputs.len() >= 2
                && c.identity.2 == HOST));
        assert!(plan.prepare().is_err());
    }
}
#[test]
fn missing_clean_rows_and_per_record_sequence_or_version_rollback_cannot_be_hidden_by_a_high_chain_cursor(
) {
    for case in ["missing", "sequence", "version"] {
        let mut f = Fixture::new();
        match case {
            "missing" => f.remote.clear(),
            "sequence" => {
                f.current().seq = 4;
            }
            _ => {
                f.remote[0].record.version = 1;
            }
        }
        let plan = f.plan();
        assert!(plan
            .conflicts()
            .iter()
            .any(|c| matches!(c.reason, Reason::MissingRemote | Reason::Rollback)));
        assert!(plan.prepare().is_err());
    }
}
#[test]
fn existing_saved_conflicts_and_contradictory_local_current_copies_never_pick_an_implicit_winner() {
    for saved in [true, false] {
        let mut f = Fixture::new();
        let space = f.state.spaces.get_mut(&f.child.chain_id).unwrap();
        if saved {
            space.recovery.conflicts.insert(
                record_key(RecordKind::Host, HOST),
                vec![RecordConflict {
                    base: None,
                    local: RecordVersion::Public(host("B", 2, 1, true)),
                    remote: RecordVersion::Public(host("C", 3, 3, false)),
                }],
            );
        } else {
            let mut row = SealedRecord::seal(&f.child, &host("B", 2, 2, false).record, 2).unwrap();
            row.dirty = false;
            space.sealed.insert(row.key(), row);
        }
        let plan = f.plan();
        assert!(plan.conflicts().iter().any(|c| c.reason
            == if saved {
                Reason::SavedConflict
            } else {
                Reason::LocalCopies
            }));
        assert!(plan.prepare().is_err());
    }
}
#[test]
fn newer_remote_tombstones_are_current_while_the_original_live_host_remains_history() {
    let mut f = Fixture::new();
    f.remote[0].record.deleted = true;
    f.remote[0].record.payload = serde_json::Value::Null;
    let prepared = f.plan().prepare().unwrap();
    assert!(
        prepared.state.spaces[&f.child.chain_id].records[&record_key(RecordKind::Host, HOST)]
            .record
            .deleted
    );
    assert!(prepared.known.rows().iter().any(|r| !r.deleted
        && r.location.position == Position::Retained
        && r.kind == "host"
        && r.id == HOST));
}
#[test]
fn a_newer_private_container_for_an_existing_key_requires_explicit_conflict_resolution() {
    let mut f = Fixture::new();
    let id = "6".repeat(32);
    let row = |raw: String, version, seq| LocalRecord {
        record: Record {
            kind: RecordKind::Key,
            id: id.clone(),
            version,
            updated_at_ms: version,
            device_id: "d".repeat(32),
            deleted: false,
            payload: json!({"schema":1,"private_key":raw}),
        },
        seq,
        dirty: false,
    };
    let a = row(crate::sync::slot_rules::test_keys::plain(), 1, 3);
    let mut sealed = SealedRecord::seal(&f.parent, &a.record, a.seq).unwrap();
    sealed.dirty = false;
    f.state
        .account
        .as_mut()
        .unwrap()
        .sealed
        .insert(sealed.key(), sealed);
    f.parent_override
        .push(row(crate::sync::slot_rules::test_keys::encrypted(), 2, 4));
    let plan = f.plan();
    assert!(plan
        .conflicts()
        .iter()
        .any(|c| c.reason == Reason::PrivateMaterialChanged && c.identity.2 == id));
    assert!(plan.prepare().is_err());
}

#[test]
fn public_default_fields_do_not_make_the_same_authenticated_record_look_like_a_conflict() {
    let mut f = Fixture::new();
    f.remote = vec![host("A", 1, 1, false)];
    let normalized: records_v3::HostPayload =
        serde_json::from_value(f.current().record.payload.clone()).unwrap();
    f.current().record.payload = serde_json::to_value(normalized).unwrap();
    let plan = f.plan();
    assert!(plan.conflicts().is_empty());
    plan.prepare().unwrap();
}
#[test]
fn matching_tombstone_intent_preserves_a_retained_body_without_reviving_the_host() {
    let mut f = Fixture::new();
    f.current().record.deleted = true;
    f.current().record.payload = serde_json::Value::Null;
    let mut remote = host("Retained", 1, 1, false);
    remote.record.deleted = true;
    f.remote = vec![remote];
    let prepared = f.plan().prepare().unwrap();
    assert!(
        prepared.state.spaces[&f.child.chain_id].records[&record_key(RecordKind::Host, HOST)]
            .record
            .deleted
    );
    assert!(prepared
        .known
        .rows()
        .iter()
        .any(|r| r.deleted
            && matches!(&r.data,super::super::KnownData::Host(h)if h.alias=="Retained")));
}
