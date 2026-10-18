//! Native semantic projection planning. No repository, credential or filesystem publication here.
//! A plan alone cannot enable central mode, replace the current owner, or activate a private key.
use super::{
    crypto::VaultKeys,
    library_page::{self, Change},
    payload::{Catalog, Data, Identity, KeyStorage, PrivateMaterial, SharedKeyslot},
    rekey::Checkpoint,
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::records_v3::{GroupPayload, HostPayload, HostScope},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Public journal evidence. Raw private material never implements Serialize or Debug.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub opaque: String,
    pub kind: String,
    pub id: String,
    pub scope: Option<HostScope>,
    pub revision: u64,
    pub sequence: u64,
    pub envelope_digest: String,
    pub content_hash: String,
    pub semantic_hash: String,
    pub author: String,
    pub membership_head: String,
    pub key_epoch: u64,
    pub deleted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicData {
    Deleted,
    Host(HostPayload),
    Group(GroupPayload),
    Keyslot(SharedKeyslot),
    Catalog(Catalog),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRow {
    pub receipt: Receipt,
    pub data: PublicData,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    MissingCatalog,
    MissingMaterial,
    MissingPublicMetadata,
    MaterialMismatch,
    ReferenceHasMaterial,
    LocalChangePending,
    UncataloguedScope,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub kind: IssueKind,
    pub id: String,
}
/// This nonserializable native value holds exact OpenSSH bytes, including their encryption.
pub struct Material {
    pub metadata: SharedKeyslot,
    pub public_receipt: Receipt,
    pub private_receipt: Receipt,
    private: PrivateMaterial,
}
impl Material {
    pub fn private(&self) -> &PrivateMaterial {
        &self.private
    }
}
/// A completed admitted snapshot, still requiring consent, outbox reconciliation and a durable
/// material transaction before any local library publication. No Debug/Serialize by construction.
pub struct Plan {
    before: Workspace,
    rows: BTreeMap<String, PublicRow>,
    receipts: BTreeMap<String, Receipt>,
    materials: BTreeMap<String, Material>,
    issues: Vec<Issue>,
}
impl Plan {
    pub fn current(before: Workspace, keys: &VaultKeys) -> Result<Self, AppError> {
        let changes = library_page::materialize_current(&before, keys)?;
        Self::admitted(before, keys, changes)
    }
    /// Semantic verification for a proposed initial history. Keeps control pre-cutover;
    /// this native planning value grants no publication or material authority.
    pub(super) fn inventory(before: Workspace, keys: &VaultKeys) -> Result<Self, AppError> {
        before.validate()?;
        before.require_key_recipients()?;
        if before.control.cutover
            || before.control.phase != super::client_state::Phase::Enrolled
            || before.replacement.is_some()
            || !before.replacement_archives.is_empty()
            || before.rotation.is_some()
            || before.recovery.is_some()
            || before.bootstrap.is_some()
        {
            return Err(super::wire::invalid());
        }
        let chain = before.control.verified_chain()?;
        let replica = before.replica.as_ref().ok_or_else(super::wire::invalid)?;
        if !replica.baseline_ready() || !replica.pending.is_empty() || !replica.conflicts.is_empty() {
            return Err(super::wire::invalid());
        }
        replica.verify_write_authority(
            &chain,
            before.control.auth_epoch,
            replica.checkpoint.epoch,
            &before.epochs,
        )?;
        let changes = library_page::current(replica, &chain, keys)?;
        Self::admitted(before, keys, changes)
    }
    fn admitted(
        before: Workspace,
        keys: &VaultKeys,
        changes: Vec<Change>,
    ) -> Result<Self, AppError> {
        before.validate()?;
        let replica = before.replica.as_ref().ok_or_else(invalid)?;
        let mut rows = BTreeMap::new();
        let mut receipts = BTreeMap::new();
        let mut slots = BTreeMap::new();
        let mut private = BTreeMap::new();
        let mut catalog = None;
        for change in changes {
            let h = &change.version.envelope.header;
            let identity = &change.payload.identity;
            let base = replica.current.get(&h.record_id).ok_or_else(invalid)?;
            if base.version != change.version || identity.opaque(keys)? != h.record_id {
                return Err(invalid());
            }
            let semantic = super::payload::encode(identity, &change.payload.data)?;
            let receipt = Receipt {
                opaque: h.record_id.clone(),
                kind: identity.kind.clone(),
                id: identity.id.clone(),
                scope: identity.scope.clone(),
                revision: number(&change.version.revision, false)?,
                sequence: number(&change.version.sequence, false)?,
                envelope_digest: change.version.digest.clone(),
                content_hash: base.content_hash.clone(),
                semantic_hash: super::crypto::hash(&semantic),
                author: h.author.clone(),
                membership_head: h.membership_head.clone(),
                key_epoch: number(&h.key_epoch, false)?,
                deleted: h.deleted,
            };
            if receipts
                .insert(h.record_id.clone(), receipt.clone())
                .is_some()
            {
                return Err(invalid());
            }
            let data = match change.payload.data {
                Data::Key(material) => {
                    private.insert(identity.id.clone(), (receipt, material));
                    continue;
                }
                Data::Deleted if identity.kind == "key" => continue,
                Data::Deleted => PublicData::Deleted,
                Data::Host(host) => PublicData::Host(host),
                Data::Group(group) => PublicData::Group(group),
                Data::Keyslot(slot) => {
                    slots.insert(identity.id.clone(), (receipt.clone(), slot.clone()));
                    PublicData::Keyslot(slot)
                }
                Data::Catalog(value) => {
                    if catalog.is_some() {
                        return Err(invalid());
                    }
                    catalog = Some(value.clone());
                    PublicData::Catalog(value)
                }
            };
            rows.insert(h.record_id.clone(), PublicRow { receipt, data });
        }
        let mut issues = vec![];
        if catalog.is_none() {
            issues.push(Issue {
                kind: IssueKind::MissingCatalog,
                id: "catalog".into(),
            });
        }
        for row in rows.values() {
            if row.receipt.deleted {
                continue;
            }
            if let Some(HostScope::Space { space_id }) = &row.receipt.scope {
                if catalog.as_ref().is_none_or(|c| {
                    !c.collections
                        .iter()
                        .any(|collection| &collection.id == space_id)
                }) {
                    issues.push(Issue {
                        kind: IssueKind::UncataloguedScope,
                        id: space_id.clone(),
                    });
                }
            }
        }
        let mut materials = BTreeMap::new();
        for (id, (public_receipt, metadata)) in slots {
            let private_id = Identity {
                kind: "key".into(),
                id: id.clone(),
                scope: None,
            }
            .opaque(keys)?;
            let local_change = [public_receipt.opaque.as_str(), private_id.as_str()]
                .iter()
                .any(|opaque| {
                    replica.pending.contains_key(*opaque) || replica.conflicts.contains_key(*opaque)
                });
            if local_change {
                issues.push(Issue {
                    kind: IssueKind::LocalChangePending,
                    id,
                });
                continue;
            }
            match (&metadata.storage, private.remove(&id)) {
                (KeyStorage::Managed { .. }, Some((private_receipt, material))) => {
                    if material.validate_against(&id, &metadata).is_err() {
                        issues.push(Issue {
                            kind: IssueKind::MaterialMismatch,
                            id,
                        });
                    } else {
                        materials.insert(
                            id,
                            Material {
                                metadata,
                                public_receipt,
                                private_receipt,
                                private: material,
                            },
                        );
                    }
                }
                (KeyStorage::Managed { .. }, None) => issues.push(Issue {
                    kind: IssueKind::MissingMaterial,
                    id,
                }),
                (KeyStorage::Hardware | KeyStorage::ExternalAgent, Some(_)) => issues.push(Issue {
                    kind: IssueKind::ReferenceHasMaterial,
                    id,
                }),
                (KeyStorage::Hardware | KeyStorage::ExternalAgent, None) => {}
            }
        }
        // A tombstoned slot cannot be resurrected by retained private ciphertext. A private
        // row that never had public metadata remains an explicit incomplete-data issue.
        for (id, _) in private {
            let tombstoned = rows.values().any(|row| {
                row.receipt.kind == "keyslot" && row.receipt.id == id && row.receipt.deleted
            });
            if !tombstoned {
                let public_id = Identity {
                    kind: "keyslot".into(),
                    id: id.clone(),
                    scope: None,
                }
                .opaque(keys)?;
                let pending = replica.pending.contains_key(&public_id)
                    || replica.conflicts.contains_key(&public_id);
                issues.push(Issue {
                    kind: if pending {
                        IssueKind::LocalChangePending
                    } else {
                        IssueKind::MissingPublicMetadata
                    },
                    id,
                });
            }
        }
        issues.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.kind.cmp(&b.kind)));
        issues.dedup();
        Ok(Self {
            before,
            rows,
            receipts,
            materials,
            issues,
        })
    }
    pub fn before(&self) -> &Workspace {
        &self.before
    }
    pub fn checkpoint(&self) -> &Checkpoint {
        &self
            .before
            .replica
            .as_ref()
            .expect("admitted replica")
            .checkpoint
    }
    pub fn rows(&self) -> &BTreeMap<String, PublicRow> {
        &self.rows
    }
    pub fn receipts(&self) -> &BTreeMap<String, Receipt> {
        &self.receipts
    }
    pub fn materials(&self) -> &BTreeMap<String, Material> {
        &self.materials
    }
    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }
    pub fn complete(&self) -> bool {
        self.issues.is_empty()
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{
        crypto::{self, DeviceKeys},
        payload,
        rekey::Version,
        wire::{canonical, RecordHeader},
    };
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use zeroize::Zeroizing;
    fn identity(kind: &str, id: &str) -> Identity {
        Identity {
            kind: kind.into(),
            id: id.into(),
            scope: None,
        }
    }
    pub(in crate::sync::central) fn slot(private: &str) -> SharedKeyslot {
        let key = crate::vault::material::parse(private).unwrap();
        SharedKeyslot {
            public: crate::sync::records_v3::KeySlotPayload {
                schema: crate::sync::records_v3::KEYSLOT_SCHEMA,
                name: "fixture".into(),
                public_key: key.public_key().to_openssh().unwrap(),
                fingerprint: key
                    .public_key()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string(),
                key_type: key.algorithm().as_str().into(),
                has_passphrase: key.is_encrypted(),
                created_at_ms: 1,
                origin_device_id: "d".repeat(32),
            },
            storage: KeyStorage::Managed {
                sha256: crypto::hash(private.as_bytes()),
            },
        }
    }
    pub(in crate::sync::central) fn fixture(data: Vec<(Identity, Data)>) -> (Workspace, VaultKeys) {
        let mut ws = super::super::workspace::tests::enrolled();
        ws.control.cutover = true;
        ws.control = ws
            .control
            .approve_library("a".repeat(64), &ws.control.highwater.as_ref().unwrap().head)
            .unwrap();
        let keys = VaultKeys::generate().unwrap();
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        let mut rows = vec![];
        let mut previous = "0".repeat(64);
        for (index, (id, data)) in data.into_iter().enumerate() {
            let sequence = (index + 1).to_string();
            let plain = payload::encode(&id, &data).unwrap();
            let anchor = ws.control.anchor.as_ref().unwrap();
            let envelope = crypto::seal_record(
                &keys,
                &signer,
                RecordHeader {
                    origin: anchor.origin.clone(),
                    account_id: anchor.account_id.clone(),
                    genesis_hash: anchor.genesis_hash.clone(),
                    vault_id: ws.replica.as_ref().unwrap().vault.clone(),
                    record_id: id.opaque(&keys).unwrap(),
                    key_epoch: "1".into(),
                    membership_head: ws.control.highwater.as_ref().unwrap().head.clone(),
                    author: ws.control.device.id.clone(),
                    operation_id: format!("{:032x}", index + 1),
                    expected_revision: "0".into(),
                    kind: id.kind,
                    deleted: matches!(data, Data::Deleted),
                },
                &plain,
            )
            .unwrap();
            let digest = super::super::rekey::envelope_digest(&envelope).unwrap();
            let history_hash = crypto::hash(
                &canonical(&["lunport-history-v2", &previous, &sequence, &digest]).unwrap(),
            );
            previous = history_hash.clone();
            rows.push(Version {
                envelope,
                digest,
                history_hash,
                revision: "1".into(),
                sequence,
            });
        }
        let target = Checkpoint {
            epoch: 1,
            sequence: rows.len() as u64,
            history_hash: previous,
        };
        ws.replica = Some(
            ws.replica
                .as_ref()
                .unwrap()
                .prepare_page(&ws.control.verified_chain().unwrap(), &keys, &rows, &target)
                .unwrap()
                .next,
        );
        ws.validate().unwrap();
        (ws, keys)
    }
    fn catalog() -> (Identity, Data) {
        (
            identity("meta", "catalog"),
            Data::Catalog(Catalog {
                collections: vec![],
                group_orders: vec![],
            }),
        )
    }
    #[test]
    fn managed_material_is_matched_without_removing_openssh_encryption_or_leaking_into_public_receipts(
    ) {
        let private = crate::sync::slot_rules::test_keys::encrypted();
        let id = "a".repeat(32);
        let (ws, keys) = fixture(vec![
            catalog(),
            (identity("keyslot", &id), Data::Keyslot(slot(&private))),
            (
                identity("key", &id),
                Data::Key(PrivateMaterial::new(Zeroizing::new(private.clone())).unwrap()),
            ),
        ]);
        let plan = Plan::current(ws.clone(), &keys).unwrap();
        assert!(plan.complete());
        assert_eq!(plan.before(), &ws);
        assert_eq!(plan.materials().len(), 1);
        let material = &plan.materials()[&id];
        assert_eq!(material.private().private(), private);
        assert!(material.metadata.public.has_passphrase);
        let public = serde_json::to_string(plan.receipts()).unwrap();
        assert!(!public.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!public.contains(&private));
        assert_eq!(plan.rows().len(), 2);
        assert_eq!(plan.receipts().len(), 3);
    }
    #[test]
    fn missing_mismatched_reference_and_tombstoned_metadata_never_activate_a_private_key() {
        let private = crate::sync::slot_rules::test_keys::plain();
        let other = crate::sync::slot_rules::test_keys::ecdsa();
        let id = "a".repeat(32);
        for mode in 0..6 {
            let mut metadata = slot(&private);
            if mode == 2 {
                metadata.storage = KeyStorage::Hardware;
            }
            if mode == 3 {
                metadata.storage = KeyStorage::ExternalAgent;
            }
            let public = if mode == 4 {
                Data::Deleted
            } else {
                Data::Keyslot(metadata)
            };
            let mut rows = vec![catalog()];
            if mode != 5 {
                rows.push((identity("keyslot", &id), public));
            }
            if mode != 0 {
                rows.push((
                    identity("key", &id),
                    Data::Key(
                        PrivateMaterial::new(Zeroizing::new(if mode == 1 {
                            other.clone()
                        } else {
                            private.clone()
                        }))
                        .unwrap(),
                    ),
                ));
            }
            let (ws, keys) = fixture(rows);
            let plan = Plan::current(ws, &keys).unwrap();
            assert!(plan.materials().is_empty());
            if mode != 4 {
                assert!(!plan.complete());
                assert_eq!(
                    plan.issues()[0].kind,
                    match mode {
                        0 => IssueKind::MissingMaterial,
                        1 => IssueKind::MaterialMismatch,
                        5 => IssueKind::MissingPublicMetadata,
                        _ => IssueKind::ReferenceHasMaterial,
                    }
                );
            }
        }
    }
    #[test]
    fn local_pending_public_or_private_changes_are_not_replaced_by_remote_material() {
        for public in [false, true] {
            let private = crate::sync::slot_rules::test_keys::plain();
            let id = "a".repeat(32);
            let (mut ws, keys) = fixture(vec![
                catalog(),
                (identity("keyslot", &id), Data::Keyslot(slot(&private))),
                (
                    identity("key", &id),
                    Data::Key(PrivateMaterial::new(Zeroizing::new(private)).unwrap()),
                ),
            ]);
            let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
            let changed = if public {
                let mut value = slot(&crate::sync::slot_rules::test_keys::plain());
                value.public.name = "newer local B".into();
                Data::Keyslot(value)
            } else {
                Data::Key(
                    PrivateMaterial::new(Zeroizing::new(
                        crate::sync::slot_rules::test_keys::ecdsa(),
                    ))
                    .unwrap(),
                )
            };
            let logical = identity(if public { "keyslot" } else { "key" }, &id);
            let opaque = logical.opaque(&keys).unwrap();
            let header = ws.replica.as_ref().unwrap().current[&opaque]
                .version
                .envelope
                .header
                .clone();
            let plain = payload::encode(&logical, &changed).unwrap();
            let chain = ws.control.verified_chain().unwrap();
            ws.replica
                .as_mut()
                .unwrap()
                .enqueue(&chain, &keys, &signer, 2, header, &plain)
                .unwrap();
            let plan = Plan::current(ws.clone(), &keys).unwrap();
            assert_eq!(plan.before(), &ws);
            assert!(plan.materials().is_empty());
            assert!(!plan.complete());
            assert!(plan
                .issues()
                .iter()
                .any(|issue| issue.id == id && issue.kind == IssueKind::LocalChangePending));
            assert_eq!(
                plan.before().replica.as_ref().unwrap().pending[&opaque]
                    .latest
                    .local_revision,
                2
            );
        }
    }
    #[test]
    fn scoped_host_ids_are_preserved_and_an_absent_collection_is_reported() {
        for named in [false, true] {
            let collection = "f".repeat(64);
            let local = Identity {
                kind: "host".into(),
                id: "0000000000000001".into(),
                scope: Some(HostScope::Local),
            };
            let remote = Identity {
                scope: Some(HostScope::Space {
                    space_id: collection.clone(),
                }),
                ..local.clone()
            };
            let host = || {
                Data::Host(serde_json::from_value(serde_json::json!({"schema":2,"alias":"fixture","hostname":"fixture.invalid","auth":"password"})).unwrap())
            };
            let catalogue = Data::Catalog(Catalog {
                collections: if named {
                    vec![super::super::payload::Collection {
                        id: collection.clone(),
                        name: "Personal collection".into(),
                    }]
                } else {
                    vec![]
                },
                group_orders: vec![],
            });
            let (ws, keys) = fixture(vec![
                (identity("meta", "catalog"), catalogue),
                (local, host()),
                (remote, host()),
            ]);
            let plan = Plan::current(ws, &keys).unwrap();
            assert_eq!(
                plan.rows()
                    .values()
                    .filter(|row| row.receipt.kind == "host")
                    .count(),
                2
            );
            assert_eq!(plan.complete(), named);
            if !named {
                assert_eq!(
                    plan.issues(),
                    &[Issue {
                        kind: IssueKind::UncataloguedScope,
                        id: collection
                    }]
                );
            }
        }
    }
    #[test]
    fn no_consent_or_corrupt_stored_plaintext_hash_blocks_even_a_pure_projection() {
        let (mut ws, keys) = fixture(vec![catalog()]);
        ws.control.library = None;
        ws.control.phase = super::super::client_state::Phase::Enrolled;
        assert!(Plan::current(ws, &keys).is_err());
        let (mut ws, keys) = fixture(vec![catalog()]);
        ws.replica
            .as_mut()
            .unwrap()
            .current
            .values_mut()
            .next()
            .unwrap()
            .content_hash = "f".repeat(64);
        assert!(Plan::current(ws, &keys).is_err());
    }
}
