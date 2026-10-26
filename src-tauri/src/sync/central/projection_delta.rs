//! Native delta/material candidate. No save, credential mutation, HTTP, UI or activation occurs.
//! Final publication additionally needs the exact journal/session/durability authority.
#[cfg(test)]
use super::payload::Identity;
use super::{
    crypto::{self, VaultKeys},
    payload::{self, Catalog, KeyStorage},
    projection::{Plan, PublicData, Receipt},
    wire::{invalid, MAX_SAFE_INTEGER},
};
use crate::{
    error::AppError,
    sync::{
        record::{record_key, LocalRecord, RecordKind},
        records_v3::{self, HostScope, LocalKeyMetadata, SpaceStateV3, SyncStateV3},
        transports,
    },
    vault::store::ReadOnlyVault,
};
use std::collections::{BTreeMap, BTreeSet};

pub struct Delta {
    before: SyncStateV3,
    candidate: SyncStateV3,
    plan: Plan,
    required: BTreeSet<String>,
    catalogue_deferred: bool,
}
/// Native-only result; this value alone is not permission for an ordinary state writer.
pub struct Verified {
    before: SyncStateV3,
    candidate: SyncStateV3,
    pub catalogue_deferred: bool,
}
impl Verified {
    pub fn before(&self) -> &SyncStateV3 {
        &self.before
    }
    pub fn candidate(&self) -> &SyncStateV3 {
        &self.candidate
    }
}
fn fresh(
    previous: Option<&LocalRecord>,
    kind: RecordKind,
    id: &str,
    body: serde_json::Value,
    receipt: &Receipt,
    observed: u64,
) -> Result<LocalRecord, AppError> {
    let mut next = super::projection_cache::row(kind, id, body, receipt, observed);
    if let Some(previous) = previous {
        next.record.version = receipt.revision.max(
            previous
                .record
                .version
                .checked_add(1)
                .filter(|n| *n <= MAX_SAFE_INTEGER)
                .ok_or_else(invalid)?,
        );
        next.record.updated_at_ms = observed.max(
            previous
                .record
                .updated_at_ms
                .checked_add(1)
                .filter(|n| *n <= MAX_SAFE_INTEGER)
                .ok_or_else(invalid)?,
        );
    }
    Ok(next)
}
fn catalog(
    state: &mut SyncStateV3,
    value: &Catalog,
    receipt: &Receipt,
    observed: u64,
) -> Result<(), AppError> {
    let account = state.account.as_mut().ok_or_else(invalid)?;
    let ids: BTreeSet<_> = value.collections.iter().map(|c| c.id.clone()).collect();
    let removed: Vec<_> = state
        .spaces
        .keys()
        .filter(|id| !ids.contains(*id))
        .cloned()
        .collect();
    for id in removed {
        let space = &state.spaces[&id];
        // Do not drop live/missing/opaque/local rows because a catalogue omitted their collection.
        if space.missing
            || !space.sealed.is_empty()
            || space.records.values().any(|r| !r.record.deleted || r.dirty)
        {
            return Err(invalid());
        }
        let key = record_key(RecordKind::Space, &id);
        let tombstone = fresh(
            account.records.get(&key),
            RecordKind::Space,
            &id,
            serde_json::Value::Null,
            &Receipt {
                deleted: true,
                ..receipt.clone()
            },
            observed,
        )?;
        account.records.insert(key, tombstone);
        state.spaces.remove(&id);
    }
    for collection in &value.collections {
        let key = record_key(RecordKind::Space, &collection.id);
        let previous = account.records.get(&key);
        let body = if let Some(previous) = previous.filter(|r| !r.record.deleted) {
            let mut metadata: crate::sync::record::SpacePayload =
                serde_json::from_value(previous.record.payload.clone())
                    .map_err(|_| invalid())?;
            metadata.name = collection.name.clone();
            serde_json::to_value(metadata).map_err(|_| invalid())?
        } else {
            serde_json::json!({"schema":1,"name":collection.name,"slug":format!("central-{}",&collection.id[..16]),"created_at_ms":observed,"previous_id":null})
        };
        let row = fresh(
            previous,
            RecordKind::Space,
            &collection.id,
            body,
            receipt,
            observed,
        )?;
        account.records.insert(key, row);
        state
            .spaces
            .entry(collection.id.clone())
            .or_insert_with(|| SpaceStateV3 {
                selected: true,
                baseline_established: true,
                ..Default::default()
            });
    }
    let previous_tunnels: BTreeMap<_, _> = account
        .records
        .iter()
        .filter(|(_, r)| {
            r.record.kind == RecordKind::Meta && crate::sync::tunnel_rules::is_id(&r.record.id)
        })
        .map(|(k, r)| (k.clone(), r.clone()))
        .collect();
    account.records.retain(|_, r| {
        !(r.record.kind == RecordKind::Meta && crate::sync::tunnel_rules::is_id(&r.record.id))
    });
    for rule in &value.tunnels {
        let id = crate::sync::tunnel_rules::wire_id(&rule.id);
        let key = record_key(RecordKind::Meta, &id);
        account.records.insert(
            key.clone(),
            fresh(
                previous_tunnels.get(&key),
                RecordKind::Meta,
                &id,
                serde_json::json!({"schema":1,"rule":rule}),
                receipt,
                observed,
            )?,
        );
    }
    state.local.tunnel_rules.clear();
    // Routes take the tunnels' path, orphans included. The library's route for a host also replaces the one this device kept alone,
    // whether a capture published that one or it differs; what grant requests taught this device stays (`transport_grants`).
    let previous_routes: BTreeMap<_, _> = account
        .records
        .iter()
        .filter(|(_, r)| r.record.kind == RecordKind::Meta && transports::is_id(&r.record.id))
        .map(|(k, r)| (k.clone(), r.clone()))
        .collect();
    account
        .records
        .retain(|_, r| !(r.record.kind == RecordKind::Meta && transports::is_id(&r.record.id)));
    for route in &value.transports {
        let id = transports::wire_id(&route.host_id);
        let key = record_key(RecordKind::Meta, &id);
        account.records.insert(
            key.clone(),
            fresh(
                previous_routes.get(&key),
                RecordKind::Meta,
                &id,
                serde_json::json!({"schema":1,"transport":route}),
                receipt,
                observed,
            )?,
        );
        state.local.transports.remove(&key);
    }
    // R19: the library's route rows need their version, which nothing else on a central publication's path raises (its save admits
    // this raise, `record_runtime::save_active_with_authority`).
    if !value.transports.is_empty() {
        state.version = state.version.max(transports::SYNC_STATE_VERSION);
    }
    state.local.group_order = value
        .group_orders
        .iter()
        .find(|o| o.scope == HostScope::Local)
        .map_or_else(Vec::new, |o| o.ids.clone());
    let key = record_key(RecordKind::Meta, crate::sync::group_order::RECORD_ID);
    if let Some(previous) = account.records.get(&key) {
        let row = fresh(
            Some(previous),
            RecordKind::Meta,
            crate::sync::group_order::RECORD_ID,
            serde_json::json!({"schema":1,"ids":state.local.group_order}),
            receipt,
            observed,
        )?;
        account.records.insert(key, row);
    }
    Ok(())
}
impl Delta {
    /// Requires durable capture of current public B. It cannot silently acknowledge/overwrite it.
    pub fn prepare(state: &SyncStateV3, keys: &VaultKeys, observed: u64) -> Result<Self, AppError> {
        if observed > MAX_SAFE_INTEGER {
            return Err(invalid());
        }
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let ledger = state
            .local
            .central_projection
            .as_ref()
            .ok_or_else(invalid)?;
        let replica = owner.replica.as_ref().ok_or_else(invalid)?;
        if ledger.checkpoint.epoch != replica.checkpoint.epoch {
            return Err(invalid());
        }
        if !ledger.public_changes_captured(state, keys)? {
            return Err(AppError::Other("Capture the latest local library changes before publishing a central delta. Local data is retained.".into()));
        }
        let plan = Plan::current(owner.clone(), keys)?;
        let mut candidate = state.clone();
        let mut accepted = BTreeSet::new();
        let mut catalogue_deferred = false;
        let catalog_row = plan
            .rows()
            .values()
            .find(|r| matches!(r.data, PublicData::Catalog(_)));
        if let Some(row) = catalog_row {
            // A pending catalogue stays on its accepted basis; scopes cannot disappear behind it.
            if !replica.conflicts.contains_key(&row.receipt.opaque)
                && ledger.bases.get(&row.receipt.opaque).map(|b| &b.remote) != Some(&row.receipt)
            {
                let mut staged = candidate.clone();
                let PublicData::Catalog(value) = &row.data else {
                    unreachable!()
                };
                let removed: BTreeSet<_> = state
                    .spaces
                    .keys()
                    .filter(|id| {
                        !value
                            .collections
                            .iter()
                            .any(|collection| &collection.id == *id)
                    })
                    .cloned()
                    .collect();
                let loses_local_or_live=removed.iter().any(|id|state.spaces.get(id).is_some_and(|space|space.missing || !space.sealed.is_empty() || space.records.values().any(|r|!r.record.deleted || r.dirty)))
                    || ledger.bases.iter().any(|(opaque,basis)|matches!(&basis.remote.scope,Some(HostScope::Space{space_id}) if removed.contains(space_id)) && (replica.pending.contains_key(opaque) || replica.conflicts.contains_key(opaque)));
                if loses_local_or_live {
                    catalogue_deferred = true;
                } else {
                    catalog(&mut staged, value, &row.receipt, observed)?;
                    candidate = staged;
                    accepted.insert(row.receipt.opaque.clone());
                }
            }
        }
        let mut required = BTreeSet::new();
        let blocked_keys: BTreeSet<_> = plan
            .issues()
            .iter()
            .filter(|issue| {
                !matches!(
                    issue.kind,
                    super::projection::IssueKind::MissingCatalog
                        | super::projection::IssueKind::UncataloguedScope
                )
            })
            .map(|issue| issue.id.as_str())
            .collect();
        for (opaque, row) in plan.rows() {
            if row.receipt.kind == "keyslot" && blocked_keys.contains(row.receipt.id.as_str()) {
                continue;
            }
            if matches!(row.data, PublicData::Catalog(_)) || replica.conflicts.contains_key(opaque)
            {
                continue;
            }
            if ledger.bases.get(opaque).map(|b| &b.remote) == Some(&row.receipt) {
                if let PublicData::Keyslot(slot) = &row.data {
                    if matches!(slot.storage, KeyStorage::Managed { .. })
                        && plan.materials().contains_key(&row.receipt.id)
                        && !ledger.has_material(&row.receipt.id, &plan)
                    {
                        required.insert(row.receipt.id.clone());
                    }
                }
                continue;
            }
            if let Some(HostScope::Space { space_id }) = &row.receipt.scope {
                if !candidate.spaces.contains_key(space_id) {
                    if row.receipt.deleted
                        && matches!(row.data, PublicData::Deleted)
                        && matches!(row.receipt.kind.as_str(), "host" | "group")
                    {
                        accepted.insert(opaque.clone());
                    }
                    continue;
                }
            }
            let (kind, body) = match &row.data {
                PublicData::Host(value) => (
                    RecordKind::Host,
                    serde_json::to_value(value).map_err(|_| invalid())?,
                ),
                PublicData::Group(value) => (
                    RecordKind::Group,
                    serde_json::to_value(value).map_err(|_| invalid())?,
                ),
                PublicData::Keyslot(slot) => {
                    if matches!(slot.storage, KeyStorage::Managed { .. }) {
                        // A mismatched/missing/pending pair never publishes half an identity.
                        let Some(material) = plan.materials().get(&row.receipt.id) else {
                            continue;
                        };
                        accepted.insert(material.private_receipt.opaque.clone());
                        required.insert(row.receipt.id.clone());
                    }
                    (
                        RecordKind::KeySlot,
                        serde_json::to_value(&slot.public).map_err(|_| invalid())?,
                    )
                }
                PublicData::Deleted => match row.receipt.kind.as_str() {
                    "host" => (RecordKind::Host, serde_json::Value::Null),
                    "group" => (RecordKind::Group, serde_json::Value::Null),
                    "keyslot" => (RecordKind::KeySlot, serde_json::Value::Null),
                    _ => return Err(invalid()),
                },
                PublicData::Catalog(_) => continue,
            };
            let cache_key = record_key(kind, &row.receipt.id);
            let destination = match &row.receipt.scope {
                Some(HostScope::Local) if kind == RecordKind::Host => &mut candidate.local.hosts,
                Some(HostScope::Local) if kind == RecordKind::Group => &mut candidate.local.groups,
                Some(HostScope::Space { space_id }) => {
                    &mut candidate
                        .spaces
                        .get_mut(space_id)
                        .ok_or_else(invalid)?
                        .records
                }
                None if kind == RecordKind::KeySlot => {
                    &mut candidate.account.as_mut().ok_or_else(invalid)?.records
                }
                _ => return Err(invalid()),
            };
            let local = fresh(
                destination.get(&cache_key),
                kind,
                &row.receipt.id,
                body,
                &row.receipt,
                observed,
            )?;
            destination.insert(cache_key, local);
            accepted.insert(opaque.clone());
        }
        // A private-only replacement is still a material transaction, even if the public line and
        // label did not change. Required pairs enter the new ledger together after exact readback.
        for (id, material) in plan.materials() {
            if !ledger.has_material(id, &plan) {
                let public = &material.public_receipt;
                if !replica.conflicts.contains_key(&public.opaque)
                    && !replica.pending.contains_key(&public.opaque)
                {
                    accepted.insert(public.opaque.clone());
                    accepted.insert(material.private_receipt.opaque.clone());
                    required.insert(id.clone());
                }
            }
        }
        for (opaque, receipt) in plan.receipts() {
            if receipt.kind == "password"
                && !replica.pending.contains_key(opaque)
                && !replica.conflicts.contains_key(opaque)
            {
                accepted.insert(opaque.clone());
            }
        }
        let next = ledger.merge_bases(&plan, &accepted, keys)?;
        candidate.local.central_projection = Some(next);
        Ok(Self {
            before: state.clone(),
            candidate,
            plan,
            required,
            catalogue_deferred,
        })
    }
    pub fn before(&self) -> &SyncStateV3 {
        &self.before
    }
    pub fn has_changes(&self) -> bool {
        self.candidate != self.before || !self.required.is_empty()
    }
    pub fn required_material(&self) -> &BTreeSet<String> {
        &self.required
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    /// The caller owns lifecycle/vault. This read-only protected snapshot must come from the
    /// exact digest-bound staged/active file in the eventual journal, never a frontend input.
    pub fn finish(
        mut self,
        vault: &ReadOnlyVault,
        mapping: &BTreeMap<String, String>,
        operation: &str,
    ) -> Result<Verified, AppError> {
        if !super::wire::hex(operation, 32)
            || mapping.keys().collect::<BTreeSet<_>>()
                != self.required.iter().collect::<BTreeSet<_>>()
            || mapping.values().collect::<BTreeSet<_>>().len() != mapping.len()
        {
            return Err(invalid());
        }
        let mut ledger = self
            .candidate
            .local
            .central_projection
            .take()
            .ok_or_else(invalid)?;
        for (id, vault_id) in mapping {
            if let Some(old) = self.before.local.keys.get(id) {
                // Rebinding unchanged bytes after a metadata-only rename can reuse this slot.
                // Changed bytes cannot: source and new receipt must both validate the readback.
                let original = vault
                    .get(&old.vault_id)
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?;
                self.before
                    .local
                    .central_projection
                    .as_ref()
                    .ok_or_else(invalid)?
                    .verify_source_material(self.before.local.central.as_ref().ok_or_else(invalid)?, id, old, &original)?;
            }
            let material = self.plan.materials().get(id).ok_or_else(invalid)?;
            let entry = vault
                .get(vault_id)
                .map_err(|_| invalid())?
                .ok_or_else(invalid)?;
            ledger = ledger.with_material_readback(&self.plan, id, vault_id, operation, &entry)?;
            self.candidate.local.keys.insert(
                id.clone(),
                LocalKeyMetadata {
                    vault_id: vault_id.clone(),
                    public: material.metadata.public.clone(),
                },
            );
        }
        self.candidate.local.central_projection = Some(ledger);
        self.candidate =
            crate::sync::record_groups::invalidate_changed_pins(&self.before, self.candidate)
                .map_err(|_| invalid())?;
        crate::sync::record_conflicts::upgrade_state(&mut self.candidate);
        records_v3::validate_state(&self.candidate).map_err(|_| invalid())?;
        Ok(Verified {
            before: self.before,
            candidate: self.candidate,
            catalogue_deferred: self.catalogue_deferred,
        })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{
        crypto::DeviceKeys,
        projection_capture,
        projection_state::tests::{initial, material_fixture},
        rekey::{self, Checkpoint, Version},
        wire::{canonical, RecordHeader},
    };
    use super::*;
    use crate::{
        sync::{
            fake_relay::FakeRelay,
            testkit::{TestClock, TestDevice},
        },
        vault::store::{self, Vault},
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    pub(in crate::sync) fn append(
        state: &mut SyncStateV3,
        keys: &VaultKeys,
        identity: Identity,
        data: payload::Data,
    ) {
        let owner = state.local.central.as_mut().unwrap();
        let replica = owner.replica.as_ref().unwrap();
        let id = identity.opaque(keys).unwrap();
        let revision = replica
            .current
            .get(&id)
            .map_or(0, |b| rekey_number(&b.version.revision));
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        let anchor = owner.control.anchor.as_ref().unwrap();
        let envelope = crypto::seal_record(
            keys,
            &signer,
            RecordHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: replica.vault.clone(),
                record_id: id,
                key_epoch: "1".into(),
                membership_head: owner.control.highwater.as_ref().unwrap().head.clone(),
                author: owner.control.device.id.clone(),
                operation_id: crypto::random_id(16).unwrap(),
                expected_revision: revision.to_string(),
                kind: identity.kind.clone(),
                deleted: matches!(data, payload::Data::Deleted),
            },
            &payload::encode(&identity, &data).unwrap(),
        )
        .unwrap();
        let digest = rekey::envelope_digest(&envelope).unwrap();
        let sequence = (replica.checkpoint.sequence + 1).to_string();
        let history_hash = crypto::hash(
            &canonical(&[
                "lunport-history-v2",
                &replica.checkpoint.history_hash,
                &sequence,
                &digest,
            ])
            .unwrap(),
        );
        let row = Version {
            envelope,
            digest,
            sequence: sequence.clone(),
            history_hash: history_hash.clone(),
            revision: (revision + 1).to_string(),
        };
        let target = Checkpoint {
            epoch: 1,
            sequence: rekey_number(&sequence),
            history_hash,
        };
        owner.replica = Some(
            replica
                .prepare_page(
                    &owner.control.verified_chain().unwrap(),
                    keys,
                    &[row],
                    &target,
                )
                .unwrap()
                .next,
        );
    }
    fn rekey_number(value: &str) -> u64 {
        super::super::wire::number(value, false).unwrap()
    }
    fn empty_finish(delta: Delta) -> Verified {
        let device = TestDevice::new("delta-readback", &FakeRelay::new(), &TestClock::new());
        let vault = store::read_vault(
            &store::vault_path(&device.env().state_path),
            &device.keychain,
        )
        .unwrap();
        delta
            .finish(&vault, &BTreeMap::new(), &"c".repeat(32))
            .unwrap()
    }
    #[test]
    fn removed_collection_tombstones_advance_without_recreating_scope_or_republishing() {
        let (mut state, keys, _) = initial();
        let removed = "f".repeat(64);
        append(
            &mut state,
            &keys,
            Identity {
                kind: "host".into(),
                id: "0000000000000001".into(),
                scope: Some(HostScope::Space {
                    space_id: removed.clone(),
                }),
            },
            payload::Data::Deleted,
        );
        let mut state = empty_finish(Delta::prepare(&state, &keys, 200).unwrap())
            .candidate()
            .clone();
        let unseen = Identity {
            kind: "group".into(),
            id: "0000000000000002".into(),
            scope: Some(HostScope::Space {
                space_id: removed.clone(),
            }),
        };
        append(&mut state, &keys, unseen.clone(), payload::Data::Deleted);
        let mut catalog = state
            .local
            .central_projection
            .as_ref()
            .unwrap()
            .catalog
            .clone();
        catalog
            .collections
            .retain(|collection| collection.id != removed);
        catalog
            .group_orders
            .retain(|order| !matches!(&order.scope,HostScope::Space{space_id} if space_id==&removed));
        append(
            &mut state,
            &keys,
            Identity {
                kind: "meta".into(),
                id: "catalog".into(),
                scope: None,
            },
            payload::Data::Catalog(catalog),
        );
        let verified = empty_finish(Delta::prepare(&state, &keys, 201).unwrap());
        assert!(!verified.catalogue_deferred);
        let next = verified.candidate();
        assert!(!next.spaces.contains_key(&removed));
        assert!(
            !next.local.hosts[&record_key(RecordKind::Host, "0000000000000001")]
                .record
                .deleted
        );
        assert!(
            next.local.central_projection.as_ref().unwrap().bases[&unseen.opaque(&keys).unwrap()]
                .remote
                .deleted
        );
        assert!(next
            .local
            .central_projection
            .as_ref()
            .unwrap()
            .public_changes(next, &keys)
            .unwrap()
            .is_empty());
        records_v3::validate_state(next).unwrap();
    }
    #[test]
    fn unchanged_delta_is_a_noop_and_uncaptured_local_b_is_never_overwritten() {
        let (mut state, keys, _) = initial();
        let unchanged = empty_finish(Delta::prepare(&state, &keys, 200).unwrap());
        assert_eq!(unchanged.before(), unchanged.candidate());
        let key = record_key(RecordKind::Host, "0000000000000001");
        state.local.hosts.get_mut(&key).unwrap().record.payload["alias"] = "B".into();
        assert!(Delta::prepare(&state, &keys, 200).is_err());
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        state = projection_capture::public_candidate(&state, &keys, &signer).unwrap();
        let row = projection_capture::tests::remote(&state, &keys, "C", None);
        projection_capture::tests::apply(&mut state, &keys, row);
        let mut value: records_v3::HostPayload = serde_json::from_value(
            state.spaces[&"f".repeat(64)].records[&key]
                .record
                .payload
                .clone(),
        )
        .unwrap();
        value.alias = "unrelated-D".into();
        append(
            &mut state,
            &keys,
            Identity {
                kind: "host".into(),
                id: "0000000000000001".into(),
                scope: Some(HostScope::Space {
                    space_id: "f".repeat(64),
                }),
            },
            payload::Data::Host(value),
        );
        let source = state.clone();
        let verified = empty_finish(Delta::prepare(&state, &keys, 201).unwrap());
        let after = verified.candidate();
        assert_eq!(after.local.hosts[&key].record.payload["alias"], "B");
        assert_eq!(
            after.spaces[&"f".repeat(64)].records[&key].record.payload["alias"],
            "unrelated-D"
        );
        let id = Identity {
            kind: "host".into(),
            id: "0000000000000001".into(),
            scope: Some(HostScope::Local),
        }
        .opaque(&keys)
        .unwrap();
        assert_eq!(
            after.local.central_projection.as_ref().unwrap().bases[&id],
            source.local.central_projection.as_ref().unwrap().bases[&id]
        );
        assert_eq!(
            after.local.central.as_ref().unwrap().replica,
            source.local.central.as_ref().unwrap().replica
        );
        assert!(!after
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .conflicts[&id]
            .is_empty());
        assert_eq!(state, source);
    }
    #[test]
    fn catalog_rename_preserves_selection_and_live_collection_omission_does_not_drop_records() {
        let (mut state, keys, ledger) = initial();
        state.spaces.get_mut(&"f".repeat(64)).unwrap().selected = false;
        let mut catalog = ledger.catalog;
        catalog.collections[0].name = "renamed".into();
        append(
            &mut state,
            &keys,
            Identity {
                kind: "meta".into(),
                id: "catalog".into(),
                scope: None,
            },
            payload::Data::Catalog(catalog.clone()),
        );
        let verified = empty_finish(Delta::prepare(&state, &keys, 200).unwrap());
        let mut next = verified.candidate().clone();
        assert!(!next.spaces[&"f".repeat(64)].selected);
        assert_eq!(
            next.account.as_ref().unwrap().records[&record_key(RecordKind::Space, &"f".repeat(64))]
                .record
                .payload["name"],
            "renamed"
        );
        catalog.collections.retain(|c| c.id != "f".repeat(64));
        catalog.group_orders.retain(
            |o| !matches!(&o.scope,HostScope::Space{space_id} if space_id==&"f".repeat(64)),
        );
        append(
            &mut next,
            &keys,
            Identity {
                kind: "meta".into(),
                id: "catalog".into(),
                scope: None,
            },
            payload::Data::Catalog(catalog),
        );
        let held = empty_finish(Delta::prepare(&next, &keys, 201).unwrap());
        assert!(held.catalogue_deferred);
        assert!(held.candidate().spaces.contains_key(&"f".repeat(64)));
        assert_eq!(
            held.candidate().spaces[&"f".repeat(64)].records,
            next.spaces[&"f".repeat(64)].records
        );
        assert_eq!(
            held.candidate()
                .local
                .central_projection
                .as_ref()
                .unwrap()
                .catalog,
            next.local.central_projection.as_ref().unwrap().catalog
        );
    }
    #[test]
    fn managed_delta_requires_complete_exact_protected_readback_before_producing_a_state_candidate()
    {
        let (mut state, keys, _, id, entry) = material_fixture();
        // A new approved empty-device cache has no unclassified old local material to replace.
        state.local.keys.clear();
        let delta = Delta::prepare(&state, &keys, 200).unwrap();
        assert_eq!(delta.required_material(), &BTreeSet::from([id.clone()]));
        let device = TestDevice::new("delta-protected", &FakeRelay::new(), &TestClock::new());
        let path = store::vault_path(&device.env().state_path);
        let protected_id = "e".repeat(32);
        let empty = store::read_vault(&path, &device.keychain).unwrap();
        assert!(Delta::prepare(&state, &keys, 200)
            .unwrap()
            .finish(
                &empty,
                &BTreeMap::from([(id.clone(), protected_id.clone())]),
                &"c".repeat(32)
            )
            .is_err());
        let mut vault = Vault::open(&path, &device.keychain, 1).unwrap();
        vault
            .put_new_batch(
                &device.keychain,
                &BTreeMap::from([(protected_id.clone(), entry.clone())]),
            )
            .unwrap();
        let readback = store::read_vault(&path, &device.keychain).unwrap();
        let verified = delta
            .finish(
                &readback,
                &BTreeMap::from([(id.clone(), protected_id.clone())]),
                &"c".repeat(32),
            )
            .unwrap();
        assert!(!state.local.keys.contains_key(&id));
        assert_eq!(verified.candidate().local.keys[&id].vault_id, protected_id);
        let key = crate::sync::record_repository::resolve_key(verified.candidate(), &id).unwrap();
        assert!(crate::session::record_material::matches(&key, &entry));
        assert!(!serde_json::to_string(verified.candidate())
            .unwrap()
            .contains("private_key"));
    }

    // ---- Routes from the Catalog (design 2026-10-26, Inside Lunport, routes take tunnel rules' central path) ----

    use crate::sync::transports::{
        self,
        tests::{iap, with_zone},
        wire_id, HostTransport,
    };

    /// The host `initial`'s library holds, in this device's own scope and in a collection: no capture can tell which of the two a
    /// route saved on this device names, so such a route stays on the device (R14).
    const HOST: &str = "0000000000000001";
    /// A host the library does not hold.
    const OTHER: &str = "0000000000000002";

    /// A projected central library and the keys its history is sealed with; it reads as its state.
    struct Projected {
        state: SyncStateV3,
        keys: VaultKeys,
    }
    impl std::ops::Deref for Projected {
        type Target = SyncStateV3;
        fn deref(&self) -> &SyncStateV3 {
            &self.state
        }
    }
    /// `initial`'s projected library, which holds `host`.
    fn cache_with_host(host: &str) -> Projected {
        let (state, keys, _) = initial();
        assert!(crate::sync::record_repository::list_hosts(&state)
            .unwrap()
            .iter()
            .any(|view| view.host.id == host));
        Projected { state, keys }
    }
    /// `library` with `route` saved on this device alone, as Lunport saved it before its library used central sync.
    fn with_local_route(mut library: Projected, route: HostTransport) -> Projected {
        library.state = transports::tests::saved_on_this_device(&library.state, &route);
        library
    }
    /// `library`'s state once another device has published its Catalog holding the routes of `routes`, its collections, group orders
    /// and tunnels unchanged: one more Catalog version in its history.
    fn published(library: &Projected, routes: &Catalog) -> SyncStateV3 {
        let mut catalog = library
            .local
            .central_projection
            .as_ref()
            .unwrap()
            .catalog
            .clone();
        catalog.transports = routes.transports.clone();
        let mut state = library.state.clone();
        append(
            &mut state,
            &library.keys,
            Identity {
                kind: "meta".into(),
                id: "catalog".into(),
                scope: None,
            },
            payload::Data::Catalog(catalog),
        );
        state
    }
    /// The delta projection of that Catalog.
    fn project_delta(library: &Projected, routes: &Catalog) -> Projected {
        let verified =
            empty_finish(Delta::prepare(&published(library, routes), &library.keys, 300).unwrap());
        assert!(!verified.catalogue_deferred);
        Projected {
            state: verified.candidate().clone(),
            keys: library.keys.duplicate(),
        }
    }
    /// The initial projection of that Catalog: the library rebuilt from its history, as `initial_projection` installs a cache, at the
    /// state version it gives the result, with the ledger it builds.
    fn project_initial(library: &Projected, routes: &Catalog) -> Projected {
        let mut state = published(library, routes);
        let plan = Plan::current(state.local.central.clone().unwrap(), &library.keys).unwrap();
        let cache =
            super::super::projection_cache::Cache::initial(&plan, 300, &BTreeMap::new()).unwrap();
        state.account = Some(cache.account);
        state.spaces = cache.spaces;
        state.local.hosts = cache.hosts;
        state.local.groups = cache.groups;
        state.local.group_order = cache.group_order;
        state.version = super::super::initial_projection::candidate_version(&state);
        state.local.central_projection = Some(
            super::super::projection_state::Ledger::initial(&plan, &state, &library.keys).unwrap(),
        );
        records_v3::validate_state(&state).unwrap();
        Projected {
            state,
            keys: library.keys.duplicate(),
        }
    }

    #[test]
    fn routes_round_trip_through_both_projections() {
        let catalog = Catalog {
            transports: vec![iap(HOST)],
            ..Catalog::default()
        };
        for next in [
            project_initial(&cache_with_host(HOST), &catalog),
            project_delta(&cache_with_host(HOST), &catalog),
        ] {
            assert_eq!(transports::get(&next, HOST), Some(iap(HOST)));
            assert!(
                !next.account.as_ref().unwrap().records
                    [&record_key(RecordKind::Meta, &wire_id(HOST))]
                    .dirty
            );
            assert_eq!(
                next.version,
                transports::SYNC_STATE_VERSION,
                "the library's route rows need version 10 (R19)"
            );
        }
    }

    #[test]
    fn a_catalog_without_routes_leaves_the_state_version_alone() {
        let library = cache_with_host(HOST);
        for next in [
            project_initial(&library, &Catalog::default()),
            project_delta(&library, &Catalog::default()),
        ] {
            assert!(transports::view(&next).is_empty());
            assert_eq!(next.version, records_v3::CENTRAL_STATE_VERSION);
        }
    }

    #[test]
    fn a_route_removed_from_the_catalog_leaves_the_rows() {
        let with = project_delta(
            &cache_with_host(HOST),
            &Catalog {
                transports: vec![iap(HOST)],
                ..Catalog::default()
            },
        );
        assert_eq!(transports::get(&with, HOST), Some(iap(HOST)));
        let without = project_delta(&with, &Catalog::default());
        assert_eq!(transports::get(&without, HOST), None);
        assert!(
            !without
                .account
                .as_ref()
                .unwrap()
                .records
                .contains_key(&record_key(RecordKind::Meta, &wire_id(HOST))),
            "the row is gone, not a tombstone"
        );
    }

    #[test]
    fn the_librarys_route_replaces_a_different_local_route_for_the_same_host() {
        let local = with_local_route(cache_with_host(HOST), with_zone(iap(HOST), "asia-east1-a"));
        let next = project_delta(
            &local,
            &Catalog {
                transports: vec![iap(HOST)],
                ..Catalog::default()
            },
        );
        assert_eq!(transports::get(&next, HOST), Some(iap(HOST)));
        assert!(next.local.transports.is_empty());
    }

    /// Only the routes the library now holds retire this device's own: a route for a host the Catalog holds no route for stays here,
    /// for a capture to publish once the library has its host.
    #[test]
    fn a_local_route_for_a_host_the_catalog_holds_no_route_for_stays() {
        let local = with_local_route(
            with_local_route(cache_with_host(HOST), with_zone(iap(HOST), "asia-east1-a")),
            iap(OTHER),
        );
        let next = project_delta(
            &local,
            &Catalog {
                transports: vec![iap(HOST)],
                ..Catalog::default()
            },
        );
        assert_eq!(transports::get(&next, HOST), Some(iap(HOST)));
        assert_eq!(transports::get(&next, OTHER), Some(iap(OTHER)));
        assert!(!transports::synced(&next, OTHER));
        assert_eq!(
            next.local.transports.keys().collect::<Vec<_>>(),
            [&record_key(RecordKind::Meta, &wire_id(OTHER))]
        );
    }

    #[test]
    fn retiring_a_local_route_keeps_what_grant_requests_taught_this_device() {
        let mut local =
            with_local_route(cache_with_host(HOST), with_zone(iap(HOST), "asia-east1-a"));
        let memory = transports::GrantMemory {
            justification: "restart app-api".into(),
            duration_secs: 1800,
        };
        local
            .state
            .local
            .transport_grants
            .insert(HOST.into(), memory.clone());
        local.state.version = transports::SYNC_STATE_VERSION;
        let next = project_delta(
            &local,
            &Catalog {
                transports: vec![iap(HOST)],
                ..Catalog::default()
            },
        );
        assert!(next.local.transports.is_empty());
        assert_eq!(transports::grant_memory(&next, HOST), Some(memory));
    }

    #[test]
    fn an_orphan_route_in_the_catalog_does_not_fail_the_projection() {
        let catalog = Catalog {
            transports: vec![iap(OTHER)],
            ..Catalog::default()
        };
        for next in [
            project_initial(&cache_with_host(HOST), &catalog),
            project_delta(&cache_with_host(HOST), &catalog),
        ] {
            assert_eq!(transports::get(&next, OTHER), Some(iap(OTHER)));
        }
    }
}

#[cfg(test)]
mod material_tests {
    use super::super::{
        crypto::DeviceKeys, projection_capture, projection_state::tests::material_fixture,
    };
    use super::tests::append;
    use super::*;
    use crate::{
        sync::{
            fake_relay::FakeRelay,
            testkit::{TestClock, TestDevice},
        },
        vault::store::{self, EntryOrigin, Vault, VaultEntry},
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    #[test]
    fn a_new_remote_key_preserves_old_material_and_rejects_an_uncaptured_private_b_even_with_the_same_fingerprint(
    ) {
        let (mut state, keys, plan, id, entry_a) = material_fixture();
        state.local.central_projection = Some(
            state
                .local
                .central_projection
                .as_ref()
                .unwrap()
                .with_material_readback(&plan, &id, &"b".repeat(32), &"c".repeat(32), &entry_a)
                .unwrap(),
        );
        let private = crate::sync::slot_rules::test_keys::ecdsa();
        let slot = super::super::projection::tests::slot(&private);
        let entry_c = VaultEntry {
            private_key: private.clone(),
            public_key: slot.public.public_key.clone(),
            fingerprint: slot.public.fingerprint.clone(),
            origin: EntryOrigin::Synced,
            added_at_ms: 100,
        };
        append(
            &mut state,
            &keys,
            Identity {
                kind: "keyslot".into(),
                id: id.clone(),
                scope: None,
            },
            payload::Data::Keyslot(slot),
        );
        append(
            &mut state,
            &keys,
            Identity {
                kind: "key".into(),
                id: id.clone(),
                scope: None,
            },
            payload::Data::Key(
                payload::PrivateMaterial::new(zeroize::Zeroizing::new(private)).unwrap(),
            ),
        );
        let device = TestDevice::new("delta-key-C", &FakeRelay::new(), &TestClock::new());
        let path = store::vault_path(&device.env().state_path);
        let destination = "e".repeat(32);
        let mut vault = Vault::open(&path, &device.keychain, 1).unwrap();
        vault
            .put_new_batch(
                &device.keychain,
                &BTreeMap::from([
                    ("b".repeat(32), entry_a.clone()),
                    (destination.clone(), entry_c.clone()),
                ]),
            )
            .unwrap();
        let readback = store::read_vault(&path, &device.keychain).unwrap();
        let verified = Delta::prepare(&state, &keys, 200)
            .unwrap()
            .finish(
                &readback,
                &BTreeMap::from([(id.clone(), destination.clone())]),
                &"d".repeat(32),
            )
            .unwrap();
        let key = crate::sync::record_repository::resolve_key(verified.candidate(), &id).unwrap();
        assert!(crate::session::record_material::matches(&key, &entry_c));
        assert_eq!(
            readback.get(&"b".repeat(32)).unwrap(),
            Some(entry_a.clone())
        );
        assert_eq!(state.local.keys[&id].vault_id, "b".repeat(32));
        // User B changed the encoded private key without changing its public identity.
        let mut same = crate::vault::material::parse(&entry_a.private_key).unwrap();
        same.set_comment("local private B");
        let mut entry_b = entry_a;
        entry_b.private_key = same
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        vault
            .put(&device.keychain, &"b".repeat(32), &entry_b)
            .unwrap();
        let b = store::read_vault(&path, &device.keychain).unwrap();
        assert!(Delta::prepare(&state, &keys, 200)
            .unwrap()
            .finish(
                &b,
                &BTreeMap::from([(id.clone(), destination)]),
                &"d".repeat(32)
            )
            .is_err());
        assert_eq!(b.get(&"b".repeat(32)).unwrap(), Some(entry_b));
    }
    #[test]
    fn a_metadata_only_rename_rebinds_exact_material_without_creating_another_private_copy() {
        let (mut state, keys, plan, id, entry) = material_fixture();
        state.local.central_projection = Some(
            state
                .local
                .central_projection
                .as_ref()
                .unwrap()
                .with_material_readback(&plan, &id, &"b".repeat(32), &"c".repeat(32), &entry)
                .unwrap(),
        );
        let mut slot = super::super::projection::tests::slot(&entry.private_key);
        slot.public.name = "renamed".into();
        append(
            &mut state,
            &keys,
            Identity {
                kind: "keyslot".into(),
                id: id.clone(),
                scope: None,
            },
            payload::Data::Keyslot(slot),
        );
        let device = TestDevice::new("delta-rename", &FakeRelay::new(), &TestClock::new());
        let path = store::vault_path(&device.env().state_path);
        let mut vault = Vault::open(&path, &device.keychain, 1).unwrap();
        vault
            .put_new_batch(
                &device.keychain,
                &BTreeMap::from([("b".repeat(32), entry.clone())]),
            )
            .unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let readback = store::read_vault(&path, &device.keychain).unwrap();
        let next = Delta::prepare(&state, &keys, 200)
            .unwrap()
            .finish(
                &readback,
                &BTreeMap::from([(id.clone(), "b".repeat(32))]),
                &"d".repeat(32),
            )
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(readback.ids().len(), 1);
        let key = crate::sync::record_repository::resolve_key(next.candidate(), &id).unwrap();
        assert_eq!(key.public.as_ref().unwrap().name, "renamed");
        assert!(crate::session::record_material::matches(&key, &entry));
    }
    #[test]
    fn rebuilding_on_latest_public_b_during_material_staging_retains_b_and_reuses_exact_readback() {
        let (mut state, keys, _, id, entry) = material_fixture();
        state.local.keys.clear();
        let old = Delta::prepare(&state, &keys, 200).unwrap();
        let device = TestDevice::new("delta-late-B", &FakeRelay::new(), &TestClock::new());
        let path = store::vault_path(&device.env().state_path);
        let destination = "e".repeat(32);
        let mut vault = Vault::open(&path, &device.keychain, 1).unwrap();
        vault
            .put_new_batch(
                &device.keychain,
                &BTreeMap::from([(destination.clone(), entry)]),
            )
            .unwrap();
        let host:records_v3::HostPayload=serde_json::from_value(serde_json::json!({"schema":2,"alias":"created-during-staging","hostname":"fixture.invalid","auth":"password"})).unwrap();
        state = crate::sync::record_repository::create_host(
            &state,
            "0000000000000008",
            HostScope::Local,
            host,
            201,
        )
        .unwrap();
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        state = projection_capture::public_candidate(&state, &keys, &signer).unwrap();
        let readback = store::read_vault(&path, &device.keychain).unwrap();
        let mapping = BTreeMap::from([(id, destination)]);
        let stale = old.finish(&readback, &mapping, &"c".repeat(32)).unwrap();
        assert_ne!(stale.before(), &state);
        let latest = Delta::prepare(&state, &keys, 202)
            .unwrap()
            .finish(&readback, &mapping, &"c".repeat(32))
            .unwrap();
        assert_eq!(latest.candidate().local.hosts, state.local.hosts);
        assert_eq!(
            latest.candidate().local.central.as_ref().unwrap().replica,
            state.local.central.as_ref().unwrap().replica
        );
    }
    #[test]
    fn a_reference_slot_with_retained_private_ciphertext_is_deferred_while_unrelated_candidates_remain_possible(
    ) {
        let (mut state, keys, _, id, _) = material_fixture();
        let mut slot =
            super::super::projection::tests::slot(&crate::sync::slot_rules::test_keys::plain());
        slot.storage = KeyStorage::Hardware;
        append(
            &mut state,
            &keys,
            Identity {
                kind: "keyslot".into(),
                id: id.clone(),
                scope: None,
            },
            payload::Data::Keyslot(slot),
        );
        let before = state.clone();
        let delta = Delta::prepare(&state, &keys, 200).unwrap();
        assert!(delta.required_material().is_empty());
        assert!(delta
            .plan()
            .issues()
            .iter()
            .any(|issue| issue.kind == super::super::projection::IssueKind::ReferenceHasMaterial));
        let device = TestDevice::new("delta-reference", &FakeRelay::new(), &TestClock::new());
        let empty = store::read_vault(
            &store::vault_path(&device.env().state_path),
            &device.keychain,
        )
        .unwrap();
        let next = delta
            .finish(&empty, &BTreeMap::new(), &"c".repeat(32))
            .unwrap();
        assert_eq!(next.candidate().account, before.account);
        assert_eq!(next.candidate().local.keys, before.local.keys);
        assert!(
            crate::sync::record_repository::resolve_key(next.candidate(), &id)
                .unwrap()
                .vault_id
                .is_none()
        );
    }
}
