//! Durable public projection bases inside the existing Records/SyncCore owner.
//! These are acknowledgement evidence, never a second runtime or permission to publish material.
use super::{
    crypto::{self, VaultKeys},
    membership::TrustAnchor,
    payload::{self, Catalog, Data, Identity, KeyStorage},
    projection::{Plan, Receipt},
    rekey::Checkpoint,
    wire::{hex, invalid, MAX_SAFE_INTEGER},
    workspace::Workspace,
};
use crate::{error::AppError, sync::records_v3::SyncStateV3};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Basis {
    pub remote: Receipt,
    /// Signed ciphertext basis survives a later remote C while local cache still contains A/B.
    pub wire: super::replica::Base,
    /// Exact semantic cache value last published. Wire revision and observation time are separate.
    pub local_hash: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub version: u32,
    pub anchor: TrustAnchor,
    pub vault: String,
    pub checkpoint: Checkpoint,
    pub catalog: Catalog,
    pub storage: BTreeMap<String, KeyStorage>,
    pub bases: BTreeMap<String, Basis>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    materials: BTreeMap<String, MaterialReceipt>,
}
/// Public evidence for one exact protected material publication. No raw key or passphrase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialReceipt {
    operation: String,
    vault_id: String,
    public: Receipt,
    private: Receipt,
    slot: payload::SharedKeyslot,
}
/// Native-only pending public edits. Encrypt before persisting; no frontend/mutation cache.
pub struct Change {
    pub identity: Identity,
    pub data: Data,
    pub base: Option<Receipt>,
}
impl Ledger {
    pub(in crate::sync::central) fn initial(
        plan: &Plan,
        state: &SyncStateV3,
        keys: &VaultKeys,
    ) -> Result<Self, AppError> {
        if !plan.complete() || state.local.central.as_ref() != Some(plan.before()) {
            return Err(invalid());
        }
        let catalog = plan
            .rows()
            .values()
            .find_map(|r| match &r.data {
                super::projection::PublicData::Catalog(c) => Some(c.clone()),
                _ => None,
            })
            .ok_or_else(invalid)?;
        let storage = plan
            .rows()
            .values()
            .filter_map(|r| match &r.data {
                super::projection::PublicData::Keyslot(s) => {
                    Some((r.receipt.id.clone(), s.storage.clone()))
                }
                _ => None,
            })
            .collect();
        let mut local = BTreeMap::new();
        for (identity, data) in super::projection_local::public_rows(state, &catalog, &storage)? {
            let opaque = identity.opaque(keys)?;
            let hash = crypto::hash(&payload::encode(&identity, &data)?);
            let accepted = plan.receipts().get(&opaque).ok_or_else(invalid)?;
            if hash != accepted.semantic_hash || local.insert(opaque, hash).is_some() {
                return Err(invalid());
            }
        }
        if plan.rows().keys().any(|opaque| !local.contains_key(opaque)) {
            return Err(invalid());
        }
        let ledger = Self {
            version: 1,
            anchor: plan.before().control.anchor.clone().ok_or_else(invalid)?,
            vault: plan
                .before()
                .replica
                .as_ref()
                .ok_or_else(invalid)?
                .vault
                .clone(),
            checkpoint: plan.checkpoint().clone(),
            catalog,
            storage,
            materials: BTreeMap::new(),
            bases: plan
                .receipts()
                .iter()
                .map(|(opaque, remote)| {
                    (
                        opaque.clone(),
                        Basis {
                            remote: remote.clone(),
                            wire: plan
                                .before()
                                .replica
                                .as_ref()
                                .expect("admitted replica")
                                .current[opaque]
                                .clone(),
                            local_hash: local.get(opaque).cloned(),
                        },
                    )
                })
                .collect(),
        };
        ledger.validate(plan.before())?;
        Ok(ledger)
    }
    pub fn validate(&self, owner: &Workspace) -> Result<(), AppError> {
        let replica = owner.replica.as_ref().ok_or_else(invalid)?;
        if self.version != 1
            || !owner.control.cutover
            || owner.control.anchor.as_ref() != Some(&self.anchor)
            || self.vault != replica.vault
            || self.bases.len() > 4096
            || self.storage.len() > 4096
            || self.materials.len() > 4096
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > 32 * 1024 * 1024
        {
            return Err(invalid());
        }
        self.catalog.validate()?;
        let cp = &self.checkpoint;
        if cp.epoch == 0
            || cp.epoch > replica.checkpoint.epoch
            || cp.sequence > 16384
            || !hex(&cp.history_hash, 64)
            || cp.sequence == 0 && cp.history_hash != "0".repeat(64)
            || cp.epoch == replica.checkpoint.epoch
                && (cp.sequence > replica.checkpoint.sequence
                    || cp.sequence == replica.checkpoint.sequence
                        && cp.history_hash != replica.checkpoint.history_hash)
        {
            return Err(invalid());
        }
        let chain = owner.control.verified_chain()?;
        let mut identities = BTreeSet::new();
        for (opaque, basis) in &self.bases {
            let r = &basis.remote;
            let h = &basis.wire.version.envelope.header;
            if basis.wire.version.digest != r.envelope_digest
                || basis.wire.content_hash != r.content_hash
                || super::wire::number(&basis.wire.version.revision, false)? != r.revision
                || super::wire::number(&basis.wire.version.sequence, false)? != r.sequence
                || h.author != r.author
                || h.membership_head != r.membership_head
                || super::wire::number(&h.key_epoch, false)? != r.key_epoch
                || h.record_id != r.opaque
                || h.kind != r.kind
                || h.deleted != r.deleted
            {
                return Err(invalid());
            }
            let identity = Identity {
                kind: r.kind.clone(),
                id: r.id.clone(),
                scope: r.scope.clone(),
            };
            identity.validate()?;
            if opaque != &r.opaque
                || !hex(opaque, 64)
                || !hex(&r.envelope_digest, 64)
                || !hex(&r.content_hash, 64)
                || !hex(&r.semantic_hash, 64)
                || r.revision == 0
                || r.revision > MAX_SAFE_INTEGER
                || r.sequence == 0
                || r.sequence > cp.sequence
                || r.key_epoch == 0
                || r.key_epoch > cp.epoch
                || chain.author_at(&r.membership_head, &r.author).is_none()
                || basis
                    .local_hash
                    .as_ref()
                    .is_some_and(|h| !hex(h, 64) || h != &r.semantic_hash)
                || (r.kind == "key") != basis.local_hash.is_none()
                || !identities.insert((r.kind.clone(), r.id.clone(), r.scope.clone()))
            {
                return Err(invalid());
            }
        }
        let mut retained = replica.clone();
        retained.checkpoint = self.checkpoint.clone();
        retained.minimum = None;
        retained.needs_epoch_rebuild = false;
        retained.current = self
            .bases
            .iter()
            .map(|(id, basis)| (id.clone(), basis.wire.clone()))
            .collect();
        retained.pending.clear();
        retained.conflicts.clear();
        retained.validate(&chain)?;
        for (id, kind) in &self.storage {
            if !hex(id, 32)
                || matches!(kind,KeyStorage::Managed{sha256} if !hex(sha256,64))
                || !self
                    .bases
                    .values()
                    .any(|b| b.remote.kind == "keyslot" && &b.remote.id == id && !b.remote.deleted)
            {
                return Err(invalid());
            }
        }
        for (id, receipt) in &self.materials {
            receipt.slot.validate(id)?;
            if !hex(&receipt.operation, 32)
                || !hex(&receipt.vault_id, 32)
                || receipt.public.kind != "keyslot"
                || receipt.private.kind != "key"
                || receipt.public.id != *id
                || receipt.private.id != *id
                || receipt.public.deleted
                || receipt.private.deleted
                || self.bases.get(&receipt.public.opaque).map(|b| &b.remote)
                    != Some(&receipt.public)
                || self.bases.get(&receipt.private.opaque).map(|b| &b.remote)
                    != Some(&receipt.private)
                || self.storage.get(id) != Some(&receipt.slot.storage)
                || !matches!(&receipt.slot.storage, KeyStorage::Managed { .. })
            {
                return Err(invalid());
            }
            let identity = Identity {
                kind: "keyslot".into(),
                id: id.clone(),
                scope: None,
            };
            if crypto::hash(&payload::encode(
                &identity,
                &Data::Keyslot(receipt.slot.clone()),
            )?) != receipt.public.semantic_hash
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    /// Pure receipt candidate only. The eventual journal writer must prove source/state/session,
    /// protected vault readback and strict durability before atomically publishing this candidate.
    pub(in crate::sync::central) fn with_material_readback(
        &self,
        plan: &Plan,
        id: &str,
        vault_id: &str,
        operation: &str,
        entry: &crate::vault::store::VaultEntry,
    ) -> Result<Self, AppError> {
        self.validate(plan.before())?;
        let material = plan.materials().get(id).ok_or_else(invalid)?;
        if !hex(vault_id, 32)
            || !hex(operation, 32)
            || self.checkpoint != *plan.checkpoint()
            || self
                .bases
                .get(&material.public_receipt.opaque)
                .map(|b| &b.remote)
                != Some(&material.public_receipt)
            || self
                .bases
                .get(&material.private_receipt.opaque)
                .map(|b| &b.remote)
                != Some(&material.private_receipt)
        {
            return Err(invalid());
        }
        let opened =
            payload::PrivateMaterial::new(zeroize::Zeroizing::new(entry.private_key.clone()))?;
        opened.validate_against(id, &material.metadata)?;
        crate::sync::records_v3::key_material_matches(
            &material.metadata.public,
            &entry.public_key,
            &entry.fingerprint,
        )
        .map_err(|_| invalid())?;
        let mut next = self.clone();
        next.materials.insert(
            id.into(),
            MaterialReceipt {
                operation: operation.into(),
                vault_id: vault_id.into(),
                public: material.public_receipt.clone(),
                private: material.private_receipt.clone(),
                slot: material.metadata.clone(),
            },
        );
        next.validate(plan.before())?;
        Ok(next)
    }
    /// Metadata-side readiness only. A consumer must also verify raw material SHA256 on read.
    pub(crate) fn material_reference(
        &self,
        owner: &Workspace,
        id: &str,
        local: &crate::sync::records_v3::LocalKeyMetadata,
        public: &crate::sync::records_v3::KeySlotPayload,
    ) -> Option<String> {
        let receipt = self.materials.get(id)?;
        let replica = owner.replica.as_ref()?;
        let slot = &receipt.slot.public;
        if local.vault_id != receipt.vault_id
            || public.has_passphrase != slot.has_passphrase
            || public.key_type != slot.key_type
            || public.fingerprint != slot.fingerprint
            || crate::vault::material::public_key_data(&public.public_key)
                != crate::vault::material::public_key_data(&slot.public_key)
            || local.public.has_passphrase != public.has_passphrase
        {
            return None;
        }
        for r in [&receipt.public, &receipt.private] {
            let basis = self.bases.get(&r.opaque)?;
            if basis.remote != *r
                || replica.current.get(&r.opaque) != Some(&basis.wire)
                || replica.pending.contains_key(&r.opaque)
                || replica.conflicts.contains_key(&r.opaque)
            {
                return None;
            }
        }
        match &receipt.slot.storage {
            KeyStorage::Managed { sha256 } => Some(sha256.clone()),
            _ => None,
        }
    }
    /// Credentials/keys never validate a cached logical ID merely by being supplied by a caller.
    /// Re-open the retained signed basis and bind its typed identity and semantic digest first.
    fn verify_native(&self, owner: &Workspace, keys: &VaultKeys) -> Result<(), AppError> {
        let chain = owner.control.verified_chain()?;
        let mut catalog = None;
        let mut storage = BTreeMap::new();
        for (opaque, basis) in &self.bases {
            let r = &basis.remote;
            let header = &basis.wire.version.envelope.header;
            let author = chain
                .author_at(&header.membership_head, &header.author)
                .ok_or_else(invalid)?;
            let plaintext = basis
                .wire
                .version
                .envelope
                .verify(&author.signing)?
                .open(keys)?;
            let admitted = payload::admit(keys, header, &plaintext)?;
            if crypto::hash(&plaintext) != r.content_hash
                || admitted.identity.kind != r.kind
                || admitted.identity.id != r.id
                || admitted.identity.scope != r.scope
                || admitted.identity.opaque(keys)? != *opaque
                || crypto::hash(&payload::encode(&admitted.identity, &admitted.data)?)
                    != r.semantic_hash
            {
                return Err(invalid());
            }
            match admitted.data {
                Data::Catalog(value) => {
                    if catalog.replace(value).is_some() {
                        return Err(invalid());
                    }
                }
                Data::Keyslot(value) => {
                    storage.insert(r.id.clone(), value.storage);
                }
                _ => {}
            }
        }
        if catalog.as_ref() != Some(&self.catalog) || storage != self.storage {
            return Err(invalid());
        }
        Ok(())
    }
    pub(in crate::sync::central) fn public_changes(
        &self,
        state: &SyncStateV3,
        keys: &VaultKeys,
    ) -> Result<Vec<Change>, AppError> {
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        self.validate(owner)?;
        self.verify_native(owner, keys)?;
        if state.account.as_ref().map(|a| a.chain_id.as_str()) != Some(self.vault.as_str()) {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut changes = vec![];
        for (identity, data) in
            super::projection_local::public_rows(state, &self.catalog, &self.storage)?
        {
            let opaque = identity.opaque(keys)?;
            if !seen.insert(opaque.clone()) {
                return Err(invalid());
            }
            let hash = crypto::hash(&payload::encode(&identity, &data)?);
            let base = self.bases.get(&opaque);
            let pending_differs = owner
                .replica
                .as_ref()
                .ok_or_else(invalid)?
                .pending
                .get(&opaque)
                .is_some_and(|pending| pending.latest.content_hash != hash);
            if base.and_then(|b| b.local_hash.as_ref()) != Some(&hash) || pending_differs {
                changes.push(Change {
                    identity,
                    data,
                    base: base.map(|b| b.remote.clone()),
                });
            }
        }
        // Physical removal is a local deletion, never permission to resurrect a prior remote row.
        for (opaque, basis) in &self.bases {
            let r = &basis.remote;
            if r.kind != "key" && !seen.contains(opaque) && !r.deleted {
                changes.push(Change {
                    identity: Identity {
                        kind: r.kind.clone(),
                        id: r.id.clone(),
                        scope: r.scope.clone(),
                    },
                    data: Data::Deleted,
                    base: Some(r.clone()),
                });
            }
        }
        Ok(changes)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{projection::tests::fixture, projection_cache::Cache};
    use super::*;
    use crate::sync::{
        record::{record_key, RecordKind},
        records_v3::{self, HostScope},
    };
    pub(in crate::sync::central) fn initial() -> (SyncStateV3, VaultKeys, Ledger) {
        let mut collections = vec![];
        for id in ["f", "e"] {
            collections.push(payload::Collection {
                id: id.repeat(64),
                name: format!("collection-{id}"),
            });
        }
        let scope = HostScope::Space {
            space_id: "f".repeat(64),
        };
        let mut data = vec![(
            Identity {
                kind: "meta".into(),
                id: "catalog".into(),
                scope: None,
            },
            Data::Catalog(Catalog {
                collections,
                group_orders: vec![
                    payload::GroupOrder {
                        scope: scope.clone(),
                        ids: vec![],
                    },
                    payload::GroupOrder {
                        scope: HostScope::Local,
                        ids: vec![],
                    },
                ],
            }),
        )];
        for scope in [HostScope::Local, scope] {
            data.push((Identity{kind:"host".into(),id:"0000000000000001".into(),scope:Some(scope)},Data::Host(serde_json::from_value(serde_json::json!({"schema":2,"alias":"fixture","hostname":"fixture.invalid","auth":"password"})).unwrap())));
        }
        let (ws, keys) = fixture(data);
        let plan = Plan::current(ws.clone(), &keys).unwrap();
        let cache = Cache::initial(&plan, 100, &BTreeMap::new()).unwrap();
        let device = crate::sync::testkit::TestDevice::new(
            "projection-ledger",
            &crate::sync::fake_relay::FakeRelay::new(),
            &crate::sync::testkit::TestClock::new(),
        );
        let crate::sync::record_runtime::StartupProbe::Records { mut state, .. } =
            crate::sync::record_runtime::probe_startup(&device.env().state_path, "ledger")
        else {
            panic!()
        };
        state.version = records_v3::CENTRAL_STATE_VERSION;
        state.local.central = Some(ws);
        state.account = Some(cache.account);
        state.spaces = cache.spaces;
        state.local.hosts = cache.hosts;
        state.local.groups = cache.groups;
        state.local.group_order = cache.group_order;
        let ledger = Ledger::initial(&plan, &state, &keys).unwrap();
        state.local.central_projection = Some(ledger.clone());
        records_v3::validate_state(&state).unwrap();
        (*state, keys, ledger)
    }
    #[test]
    fn durable_bases_detect_local_edits_without_dirty_flags_and_keep_scope_identity() {
        let (mut state, keys, ledger) = initial();
        assert!(ledger.public_changes(&state, &keys).unwrap().is_empty());
        let key = record_key(RecordKind::Host, "0000000000000001");
        let local = state.local.hosts.get_mut(&key).unwrap();
        assert!(!local.dirty);
        local.record.payload["alias"] = "local-B".into();
        let bytes = serde_json::to_string(&state).unwrap();
        let records_v3::DecodedState::V3(restarted) = records_v3::decode_state(&bytes).unwrap()
        else {
            panic!()
        };
        let changes = restarted
            .local
            .central_projection
            .as_ref()
            .unwrap()
            .public_changes(&restarted, &keys)
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].identity.scope, Some(HostScope::Local));
        assert!(changes[0].base.is_some());
        assert!(matches!(&changes[0].data,Data::Host(h) if h.alias=="local-B"));
        assert!(!bytes.contains("private_key"));
        assert!(!bytes.contains("auth_token"));
    }
    #[test]
    fn selection_observation_time_and_compatibility_slugs_are_not_cloud_edits() {
        let (mut state, keys, ledger) = initial();
        for space in state.spaces.values_mut() {
            space.selected = false;
            space.cursor_seq += 10;
        }
        for row in state.local.hosts.values_mut() {
            row.record.updated_at_ms += 500;
            row.record.version += 8;
        }
        for row in state
            .account
            .as_mut()
            .unwrap()
            .records
            .values_mut()
            .filter(|row| row.record.kind == RecordKind::Space)
        {
            row.record.payload["slug"] = "different-local-slug".into();
            row.record.payload["created_at_ms"] = 500.into();
        }
        assert!(ledger.public_changes(&state, &keys).unwrap().is_empty());
        // Preserve the authenticated collection and group-order vector order exactly.
        assert_eq!(ledger.catalog.collections[0].id, "f".repeat(64));
        let rows =
            super::super::projection_local::public_rows(&state, &ledger.catalog, &ledger.storage)
                .unwrap();
        assert!(rows
            .iter()
            .any(|(_, data)| matches!(data,Data::Catalog(c) if c==&ledger.catalog)));
    }
    #[test]
    fn physical_deletion_and_new_records_are_changes_and_unselected_rows_are_included() {
        let (mut state, keys, ledger) = initial();
        let key = record_key(RecordKind::Host, "0000000000000001");
        let mut added = state.local.hosts.remove(&key).unwrap();
        added.record.id = "0000000000000002".into();
        state
            .local
            .hosts
            .insert(record_key(RecordKind::Host, &added.record.id), added);
        let space = state.spaces.get_mut(&"f".repeat(64)).unwrap();
        space.selected = false;
        space.records.get_mut(&key).unwrap().record.payload["alias"] =
            "remote-scope-local-B".into();
        let changes = ledger.public_changes(&state, &keys).unwrap();
        assert_eq!(changes.len(), 3);
        assert!(changes.iter().any(|c| c.identity.id == "0000000000000001"
            && c.identity.scope == Some(HostScope::Local)
            && matches!(c.data, Data::Deleted)));
        assert!(changes
            .iter()
            .any(|c| c.base.is_none() && c.identity.id == "0000000000000002"));
        assert!(changes.iter().any(
            |c| matches!(&c.identity.scope, Some(HostScope::Space { .. }))
                && matches!(&c.data,Data::Host(h) if h.alias=="remote-scope-local-B")
        ));
    }
    fn material_fixture() -> (
        SyncStateV3,
        VaultKeys,
        Plan,
        String,
        crate::vault::store::VaultEntry,
    ) {
        let (mut state, _, _) = initial();
        let id = "a".repeat(32);
        let private = crate::sync::slot_rules::test_keys::plain();
        let slot = super::super::projection::tests::slot(&private);
        let entry = crate::vault::store::VaultEntry {
            private_key: private.clone(),
            public_key: slot.public.public_key.clone(),
            fingerprint: slot.public.fingerprint.clone(),
            origin: crate::vault::store::EntryOrigin::Synced,
            added_at_ms: 100,
        };
        let (ws, keys) = fixture(vec![
            (
                Identity {
                    kind: "meta".into(),
                    id: "catalog".into(),
                    scope: None,
                },
                Data::Catalog(Catalog {
                    collections: vec![],
                    group_orders: vec![],
                }),
            ),
            (
                Identity {
                    kind: "keyslot".into(),
                    id: id.clone(),
                    scope: None,
                },
                Data::Keyslot(slot.clone()),
            ),
            (
                Identity {
                    kind: "key".into(),
                    id: id.clone(),
                    scope: None,
                },
                Data::Key(payload::PrivateMaterial::new(zeroize::Zeroizing::new(private)).unwrap()),
            ),
        ]);
        let plan = Plan::current(ws.clone(), &keys).unwrap();
        let cache = Cache::initial(&plan, 100, &BTreeMap::new()).unwrap();
        state.local.central = Some(ws);
        state.account = Some(cache.account);
        state.spaces = cache.spaces;
        state.local.hosts = cache.hosts;
        state.local.groups = cache.groups;
        state.local.group_order = cache.group_order;
        state.local.central_projection = None;
        let ledger = Ledger::initial(&plan, &state, &keys).unwrap();
        state.local.central_projection = Some(ledger);
        state.local.keys.insert(
            id.clone(),
            records_v3::LocalKeyMetadata {
                vault_id: "b".repeat(32),
                public: slot.public,
            },
        );
        (state, keys, plan, id, entry)
    }
    #[test]
    fn an_old_vault_reference_with_the_same_public_key_is_not_activated_without_a_bound_material_receipt(
    ) {
        let (mut state, _, plan, id, entry) = material_fixture();
        let before = crate::sync::record_repository::resolve_key(&state, &id).unwrap();
        assert_eq!(
            before.status,
            crate::sync::record_repository::KeyStatus::NeedsMaterial
        );
        assert!(before.vault_id.is_none());
        let ledger = state.local.central_projection.as_ref().unwrap();
        state.local.central_projection = Some(
            ledger
                .with_material_readback(&plan, &id, &"b".repeat(32), &"c".repeat(32), &entry)
                .unwrap(),
        );
        records_v3::validate_state(&state).unwrap();
        let key = crate::sync::record_repository::resolve_key(&state, &id).unwrap();
        assert_eq!(
            key.status,
            crate::sync::record_repository::KeyStatus::Available
        );
        assert_eq!(
            key.expected_material_hash,
            Some(crypto::hash(entry.private_key.as_bytes()))
        );
        assert!(crate::session::record_material::matches(&key, &entry));
        let mut different = entry.clone();
        let mut same_key = crate::vault::material::parse(&different.private_key).unwrap();
        same_key.set_comment("different encoding, same SSH public identity");
        different.private_key = same_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        assert!(crate::vault::material::parse(&different.private_key).is_some());
        let mut legacy_check = key.clone();
        legacy_check.expected_material_hash = None;
        assert!(crate::session::record_material::matches(
            &legacy_check,
            &different
        ));
        assert!(!crate::session::record_material::matches(&key, &different));
        assert!(state
            .local
            .central_projection
            .as_ref()
            .unwrap()
            .with_material_readback(&plan, &id, &"b".repeat(32), &"d".repeat(32), &different)
            .is_err());
        let bytes = serde_json::to_string(&state).unwrap();
        assert!(!bytes.contains("private_key"));
        let records_v3::DecodedState::V3(restarted) = records_v3::decode_state(&bytes).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            crate::sync::record_repository::resolve_key(&restarted, &id).unwrap(),
            key
        );
    }
    #[test]
    fn material_binding_cannot_fall_back_after_slot_deletion_new_local_vault_or_pending_private_change(
    ) {
        let (mut state, _, plan, id, entry) = material_fixture();
        state.local.central_projection = Some(
            state
                .local
                .central_projection
                .as_ref()
                .unwrap()
                .with_material_readback(&plan, &id, &"b".repeat(32), &"c".repeat(32), &entry)
                .unwrap(),
        );
        let mut moved = state.clone();
        moved.local.keys.get_mut(&id).unwrap().vault_id = "e".repeat(32);
        assert!(crate::sync::record_repository::resolve_key(&moved, &id)
            .unwrap()
            .vault_id
            .is_none());
        let mut deleted = state.clone();
        let row = deleted
            .account
            .as_mut()
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::KeySlot, &id))
            .unwrap();
        row.record.deleted = true;
        row.record.payload = serde_json::Value::Null;
        assert_eq!(
            crate::sync::record_repository::resolve_key(&deleted, &id)
                .unwrap()
                .status,
            crate::sync::record_repository::KeyStatus::Deleted
        );
        let mut pending = state.clone();
        let ledger = pending.local.central_projection.as_ref().unwrap();
        let r = ledger.materials[&id].private.clone();
        let base = pending
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .current[&r.opaque]
            .clone();
        pending
            .local
            .central
            .as_mut()
            .unwrap()
            .replica
            .as_mut()
            .unwrap()
            .pending
            .insert(
                r.opaque,
                super::super::replica::Pending {
                    latest: super::super::replica::Draft {
                        local_revision: 1,
                        content_hash: base.content_hash,
                        envelope: base.version.envelope,
                    },
                    sent: None,
                    claimed: None,
                },
            );
        assert!(crate::sync::record_repository::resolve_key(&pending, &id)
            .unwrap()
            .vault_id
            .is_none());
        let mut removed = state.clone();
        removed
            .account
            .as_mut()
            .unwrap()
            .records
            .remove(&record_key(RecordKind::KeySlot, &id));
        assert!(crate::sync::record_repository::resolve_key(&removed, &id)
            .unwrap()
            .vault_id
            .is_none());
        let mut missing = state;
        missing.local.central_projection = None;
        assert!(crate::sync::record_repository::resolve_key(&missing, &id)
            .unwrap()
            .vault_id
            .is_none());
    }
    #[test]
    fn ordinary_state_and_core_writers_cannot_erase_or_reissue_projection_receipts() {
        let (state, _, _) = initial();
        let device = crate::sync::testkit::TestDevice::new(
            "projection-fence",
            &crate::sync::fake_relay::FakeRelay::new(),
            &crate::sync::testkit::TestClock::new(),
        );
        let env = device.env();
        crate::sync::record_runtime::save_active(&env.state_path, &state).unwrap();
        let before = std::fs::read(&env.state_path).unwrap();
        let probe = crate::sync::record_runtime::probe_startup(&env.state_path, "projection-fence");
        crate::sync::record_runtime::activate_probe(
            &mut device.runtime.core.lock().unwrap(),
            probe,
        )
        .unwrap();
        let (mut missing, generation) = crate::sync::record_runtime::snapshot(&env).unwrap();
        missing.local.central_projection = None;
        assert!(
            crate::sync::record_runtime::commit_candidate(&env, generation, missing.clone())
                .is_err()
        );
        assert!(crate::sync::record_runtime::save_active(&env.state_path, &missing).is_err());
        assert_eq!(std::fs::read(&env.state_path).unwrap(), before);
        assert_eq!(
            crate::sync::record_runtime::snapshot(&env).unwrap().0,
            state
        );
    }
    #[test]
    fn wrong_owner_vault_floor_and_corrupt_receipts_fail_without_resetting_bases() {
        let (mut state, keys, ledger) = initial();
        let mut damaged = ledger.clone();
        damaged.checkpoint.sequence += 1;
        assert!(damaged
            .validate(state.local.central.as_ref().unwrap())
            .is_err());
        let mut damaged = ledger.clone();
        damaged.bases.values_mut().next().unwrap().remote.opaque = "0".repeat(64);
        assert!(damaged
            .validate(state.local.central.as_ref().unwrap())
            .is_err());
        state.account.as_mut().unwrap().chain_id = "0".repeat(64);
        assert!(ledger.public_changes(&state, &keys).is_err());
        assert!(records_v3::validate_state(&state).is_err());
        state.account.as_mut().unwrap().chain_id = ledger.vault.clone();
        state.local.central = None;
        assert!(records_v3::validate_state(&state).is_err());
    }
}
