//! Pure local managed-key provenance and encrypted pending work. Not vault readback/readiness.
use super::{
    crypto::{self, DeviceKeys, VaultKeys},
    membership::{Device, TrustAnchor},
    payload::{self, Data, Identity, KeyStorage, PrivateMaterial, SharedKeyslot},
    replica::Draft,
    wire::{canonical, hex, invalid, number, RecordHeader},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{
        record::{record_key, RecordKind},
        records_v3::{self, KeySlotPayload, LocalKeyMetadata, SyncStateV3},
    },
    vault::store::{EntryOrigin, VaultEntry},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
/// Native generated transaction identifiers. Physical destination freshness still requires I/O proof.
pub(super) struct Context {
    pub operation: String,
    pub key_id: String,
    pub vault_id: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    version: u32,
    profile: String,
    anchor: TrustAnchor,
    vault: String,
    device: Device,
    identity_slot: Option<String>,
    operation: String,
    key_id: String,
    vault_id: String,
    membership_head: String,
    key_epoch: String,
    slot: SharedKeyslot,
    private_content_hash: String,
}
fn identity(kind: &str, id: &str) -> Identity {
    Identity {
        kind: kind.into(),
        id: id.into(),
        scope: None,
    }
}
impl Body {
    fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if self.version != 1
            || !hex(&self.profile, 64)
            || !hex(&self.vault, 64)
            || !hex(&self.operation, 32)
            || !hex(&self.key_id, 32)
            || !hex(&self.vault_id, 32)
            || !hex(&self.membership_head, 64)
            || !hex(&self.private_content_hash, 64)
            || !hex(&self.device.id, 32)
            || !hex(&self.anchor.account_id, 64)
            || !hex(&self.anchor.genesis_hash, 64)
            || !super::wire::origin(&self.anchor.origin)
            || !self.anchor.origin.starts_with("https://")
            || self.identity_slot.as_ref().is_some_and(|v| !hex(v, 32))
            || number(&self.key_epoch, false)? > 65
            || self.slot.public.origin_device_id != self.device.id
            || !matches!(self.slot.storage, KeyStorage::Managed { .. })
        {
            return Err(invalid());
        }
        self.device.keys.validate()?;
        let slot = payload::encode(
            &identity("keyslot", &self.key_id),
            &Data::Keyslot(self.slot.clone()),
        )?;
        canonical(&[
            "lunport-local-managed-source-v1",
            &self.version.to_string(),
            &self.profile,
            &self.anchor.origin,
            &self.anchor.account_id,
            &self.anchor.genesis_hash,
            &self.vault,
            &self.device.id,
            &self.device.keys.signing,
            &self.device.keys.encryption,
            self.identity_slot.as_deref().unwrap_or(""),
            &self.operation,
            &self.key_id,
            &self.vault_id,
            &self.membership_head,
            &self.key_epoch,
            &crypto::hash(&slot),
            &self.private_content_hash,
        ])
    }
}
/// Native signed provenance only. A consumer still needs real protected-vault readback and a
/// check that no newer remote public/material identity supersedes this original source.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    body: Body,
    signature: String,
}
impl Receipt {
    pub fn key_id(&self) -> &str {
        &self.body.key_id
    }
    pub fn vault_id(&self) -> &str {
        &self.body.vault_id
    }
    pub fn verify(&self, owner: &Workspace) -> Result<(), AppError> {
        owner.validate()?;
        let body = &self.body;
        let chain = owner.control.verified_chain()?;
        if owner.control.anchor.as_ref() != Some(&body.anchor)
            || owner.control.profile.locator != body.profile
            || owner.control.personal_vault.as_ref() != Some(&body.vault)
            || owner.control.device != body.device
            || owner.identity_slot != body.identity_slot
            || number(&body.key_epoch, false)?
                > owner.replica.as_ref().ok_or_else(invalid)?.checkpoint.epoch
        {
            return Err(invalid());
        }
        let author = chain
            .author_at(&body.membership_head, &body.device.id)
            .ok_or_else(invalid)?;
        if author != &body.device.keys {
            return Err(invalid());
        }
        crypto::verify(&author.signing, &body.canonical()?, &self.signature)
    }
    pub fn verify_material(
        &self,
        owner: &Workspace,
        id: &str,
        local: &LocalKeyMetadata,
        entry: &VaultEntry,
    ) -> Result<(), AppError> {
        self.verify(owner)?;
        if id != self.body.key_id
            || local.vault_id != self.body.vault_id
            || local.public.key_type != self.body.slot.public.key_type
            || local.public.has_passphrase != self.body.slot.public.has_passphrase
            || entry.added_at_ms != self.body.slot.public.created_at_ms
        {
            return Err(invalid());
        }
        records_v3::validate_keyslot(id, &local.public).map_err(|_| invalid())?;
        records_v3::key_material_matches(
            &self.body.slot.public,
            &local.public.public_key,
            &local.public.fingerprint,
        )
        .map_err(|_| invalid())?;
        let material = material(entry, &self.body.slot, id)?;
        if crypto::hash(&payload::encode(
            &identity("key", id),
            &Data::Key(material),
        )?) != self.body.private_content_hash
        {
            return Err(invalid());
        }
        Ok(())
    }
}
/// An immutable ciphertext candidate, never a Core/vault/journal publication or readiness permit.
pub(super) struct Plan {
    owner: Workspace,
    receipt: Receipt,
    order: [String; 2],
}
impl Plan {
    pub fn owner(&self) -> &Workspace {
        &self.owner
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    /// New private rows must be dispatched after their corresponding public metadata.
    pub fn ordered(&self) -> Result<[&Draft; 2], AppError> {
        let replica = self.owner.replica.as_ref().ok_or_else(invalid)?;
        Ok([
            &replica
                .pending
                .get(&self.order[0])
                .ok_or_else(invalid)?
                .latest,
            &replica
                .pending
                .get(&self.order[1])
                .ok_or_else(invalid)?
                .latest,
        ])
    }
}
fn material(
    entry: &VaultEntry,
    slot: &SharedKeyslot,
    id: &str,
) -> Result<PrivateMaterial, AppError> {
    records_v3::key_material_matches(&slot.public, &entry.public_key, &entry.fingerprint)
        .map_err(|_| invalid())?;
    let material = PrivateMaterial::new(Zeroizing::new(entry.private_key.clone()))?;
    material.validate_against(id, slot)?;
    Ok(material)
}
pub(super) fn prepare_new(
    state: &SyncStateV3,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    context: Context,
    public: KeySlotPayload,
    entry: &VaultEntry,
) -> Result<Plan, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    let before = state.local.central.as_ref().ok_or_else(invalid)?;
    let ledger = state
        .local
        .central_projection
        .as_ref()
        .ok_or_else(invalid)?;
    let account = state.account.as_ref().ok_or_else(invalid)?;
    if !before.control.cutover
        || !before.can_upload()
        || signer.public() != before.control.device.keys
        || !hex(&context.operation, 32)
        || !hex(&context.key_id, 32)
        || !hex(&context.vault_id, 32)
        || state.pending_account.is_some()
        || state.rotation.is_some()
        || records_v3::account_migration_pending(state)
        || !account.sealed.is_empty()
        || !account.chain_deletes.is_empty()
        || matches!(entry.origin, EntryOrigin::Synced)
        || public.origin_device_id != before.control.device.id
        || entry.added_at_ms != public.created_at_ms
        || state.local.import_receipts.contains_key(&context.operation)
        || state.local.keys.contains_key(&context.key_id)
        || state
            .local
            .keys
            .values()
            .any(|key| key.vault_id == context.vault_id)
        || account
            .records
            .contains_key(&record_key(RecordKind::KeySlot, &context.key_id))
        || ledger.storage.contains_key(&context.key_id)
    {
        return Err(invalid());
    }
    before.require_key_recipients()?;
    ledger.validate(before)?;
    ledger.verify_native(before, keys)?;
    let chain = before.control.verified_chain()?;
    let replica = before.replica.as_ref().ok_or_else(invalid)?;
    replica.verify_write_authority(
        &chain,
        before.control.auth_epoch,
        replica.checkpoint.epoch,
        &before.epochs,
    )?;
    let epoch = replica.checkpoint.epoch.to_string();
    let wrap = before
        .own_wraps
        .iter()
        .find(|wrap| wrap.header.key_epoch == epoch)
        .ok_or_else(invalid)?;
    let author = chain
        .author_at(&wrap.header.membership_head, &wrap.header.author)
        .ok_or_else(invalid)?;
    wrap.open(signer, &wrap.header, &author.signing)?
        .verify_same(keys)?;
    let slot = SharedKeyslot {
        public,
        storage: KeyStorage::Managed {
            sha256: crypto::hash(entry.private_key.as_bytes()),
        },
    };
    let private = material(entry, &slot, &context.key_id)?;
    let public_bytes = payload::encode(
        &identity("keyslot", &context.key_id),
        &Data::Keyslot(slot.clone()),
    )?;
    let private_bytes = payload::encode(&identity("key", &context.key_id), &Data::Key(private))?;
    let order = [
        identity("keyslot", &context.key_id).opaque(keys)?,
        identity("key", &context.key_id).opaque(keys)?,
    ];
    if order[0] == order[1]
        || order.iter().any(|id| {
            replica.current.contains_key(id)
                || replica.pending.contains_key(id)
                || replica.conflicts.contains_key(id)
                || ledger.bases.contains_key(id)
        })
    {
        return Err(invalid());
    }
    let anchor = before.control.anchor.clone().ok_or_else(invalid)?;
    let body = Body {
        version: 1,
        profile: before.control.profile.locator.clone(),
        anchor: anchor.clone(),
        vault: replica.vault.clone(),
        device: before.control.device.clone(),
        identity_slot: before.identity_slot.clone(),
        operation: context.operation,
        key_id: context.key_id,
        vault_id: context.vault_id,
        membership_head: chain.current().head().into(),
        key_epoch: epoch.clone(),
        slot,
        private_content_hash: crypto::hash(&private_bytes),
    };
    let receipt = Receipt {
        signature: signer.sign(&body.canonical()?),
        body,
    };
    receipt.verify(before)?;
    let mut owner = before.clone();
    let pending = owner.replica.as_mut().ok_or_else(invalid)?;
    for ((opaque, kind), plain) in order
        .iter()
        .zip(["keyslot", "key"])
        .zip([public_bytes.as_slice(), private_bytes.as_slice()])
    {
        pending.enqueue(
            &chain,
            keys,
            signer,
            1,
            RecordHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: replica.vault.clone(),
                record_id: opaque.clone(),
                key_epoch: epoch.clone(),
                membership_head: chain.current().head().into(),
                author: before.control.device.id.clone(),
                operation_id: "0".repeat(32),
                expected_revision: "0".into(),
                kind: kind.into(),
                deleted: false,
            },
            plain,
        )?;
    }
    owner.validate()?;
    Ok(Plan {
        owner,
        receipt,
        order,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::central::{
        payload, projection::tests::slot, projection_state::tests::initial, wire::WrapHeader,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    fn fixture(
        encrypted: bool,
    ) -> (
        SyncStateV3,
        VaultKeys,
        DeviceKeys,
        Context,
        KeySlotPayload,
        VaultEntry,
    ) {
        let (mut state, keys, _) = initial();
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        let owner = state.local.central.as_mut().unwrap();
        let anchor = owner.control.anchor.as_ref().unwrap();
        owner.own_wraps = vec![crypto::wrap_keys(
            &keys,
            &signer,
            WrapHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: owner.control.personal_vault.clone().unwrap(),
                key_epoch: "1".into(),
                membership_head: owner.control.highwater.as_ref().unwrap().head.clone(),
                author: owner.control.device.id.clone(),
                recipient: owner.control.device.id.clone(),
                recipient_key: signer.public().encryption,
            },
        )
        .unwrap()];
        let raw = if encrypted {
            crate::sync::slot_rules::test_keys::encrypted()
        } else {
            crate::sync::slot_rules::test_keys::plain()
        };
        let mut public = slot(&raw).public;
        public.origin_device_id = owner.control.device.id.clone();
        let entry = VaultEntry {
            private_key: raw,
            public_key: public.public_key.clone(),
            fingerprint: public.fingerprint.clone(),
            origin: EntryOrigin::Imported,
            added_at_ms: public.created_at_ms,
        };
        let context = Context {
            operation: "a".repeat(32),
            key_id: "b".repeat(32),
            vault_id: "c".repeat(32),
        };
        (state, keys, signer, context, public, entry)
    }
    #[test]
    fn original_plain_and_encrypted_containers_prepare_public_then_private_without_session_or_state_mutation(
    ) {
        for encrypted in [false, true] {
            let (state, keys, signer, context, public, entry) = fixture(encrypted);
            let original = state.clone();
            let plan =
                prepare_new(&state, &keys, &signer, context, public.clone(), &entry).unwrap();
            let ordered = plan.ordered().unwrap();
            assert_eq!(ordered[0].envelope.header.kind, "keyslot");
            assert_eq!(ordered[1].envelope.header.kind, "key");
            let first = ordered[0]
                .envelope
                .verify(&signer.public().signing)
                .unwrap()
                .open(&keys)
                .unwrap();
            let admitted = payload::admit(&keys, &ordered[0].envelope.header, &first).unwrap();
            assert!(matches!(admitted.data,Data::Keyslot(ref value)if value.public==public));
            let second = ordered[1]
                .envelope
                .verify(&signer.public().signing)
                .unwrap()
                .open(&keys)
                .unwrap();
            let admitted = payload::admit(&keys, &ordered[1].envelope.header, &second).unwrap();
            assert!(
                matches!(admitted.data,Data::Key(ref value)if value.private()==entry.private_key)
            );
            let local = LocalKeyMetadata {
                vault_id: plan.receipt().vault_id().into(),
                public: public.clone(),
            };
            plan.receipt()
                .verify_material(plan.owner(), plan.receipt().key_id(), &local, &entry)
                .unwrap();
            let encoded = serde_json::to_vec(plan.receipt()).unwrap();
            let restored: Receipt = serde_json::from_slice(&encoded).unwrap();
            restored.verify(plan.owner()).unwrap();
            for serialized in [
                serde_json::to_string(plan.owner()).unwrap(),
                String::from_utf8(encoded).unwrap(),
            ] {
                assert!(!serialized.contains("BEGIN OPENSSH PRIVATE KEY"));
                assert!(!serialized.contains(&entry.private_key));
            }
            assert_eq!(state, original);
            assert_eq!(plan.owner().replica.as_ref().unwrap().pending.len(), 2);
            assert_eq!(
                plan.owner().control.cutover,
                original.local.central.as_ref().unwrap().control.cutover
            );
        }
    }
    #[test]
    fn altered_signed_scope_signature_hash_and_schema_do_not_authenticate_as_local_provenance() {
        let (state, keys, signer, context, public, entry) = fixture(true);
        let plan = prepare_new(&state, &keys, &signer, context, public, &entry).unwrap();
        let original: serde_json::Value = serde_json::to_value(plan.receipt()).unwrap();
        for field in [
            "profile",
            "vault",
            "operation",
            "key_id",
            "vault_id",
            "membership_head",
            "key_epoch",
            "private_content_hash",
            "signature",
            "version",
            "unknown",
        ] {
            let mut value = original.clone();
            match field {
                "signature" => value["signature"] = "AAAA".into(),
                "version" => value["body"]["version"] = 2.into(),
                "unknown" => value["body"]["unexpected"] = "PRIVATE_SENTINEL".into(),
                "key_epoch" => value["body"][field] = "2".into(),
                _ => {
                    value["body"][field] = "f"
                        .repeat(if matches!(field, "operation" | "key_id" | "vault_id") {
                            32
                        } else {
                            64
                        })
                        .into()
                }
            }
            assert!(
                serde_json::from_value::<Receipt>(value)
                    .map_or(true, |receipt| receipt.verify(plan.owner()).is_err()),
                "{field}"
            );
        }
        let mut moved = plan.owner().clone();
        moved.identity_slot = Some("e".repeat(32));
        assert!(plan.receipt().verify(&moved).is_err());
    }
    #[test]
    fn readiness_provenance_keeps_harmless_names_but_rejects_wrong_key_physical_binding_and_raw_container(
    ) {
        let (state, keys, signer, context, public, entry) = fixture(true);
        let plan = prepare_new(&state, &keys, &signer, context, public.clone(), &entry).unwrap();
        let mut local = LocalKeyMetadata {
            vault_id: plan.receipt().vault_id().into(),
            public,
        };
        local.public.name = "renamed".into();
        plan.receipt()
            .verify_material(plan.owner(), plan.receipt().key_id(), &local, &entry)
            .unwrap();
        let mut relocated = local.clone();
        relocated.vault_id = "e".repeat(32);
        assert!(plan
            .receipt()
            .verify_material(plan.owner(), plan.receipt().key_id(), &relocated, &entry)
            .is_err());
        let mut wrong = entry.clone();
        wrong.private_key.push('\n');
        assert!(plan
            .receipt()
            .verify_material(plan.owner(), plan.receipt().key_id(), &local, &wrong)
            .is_err());
        local.public.has_passphrase = false;
        assert!(plan
            .receipt()
            .verify_material(plan.owner(), plan.receipt().key_id(), &local, &entry)
            .is_err());
    }
    #[test]
    fn wrong_keys_signer_public_identity_time_and_synced_source_do_not_create_partial_pending_work()
    {
        let (state, keys, signer, _, public, entry) = fixture(false);
        let context = || Context {
            operation: "a".repeat(32),
            key_id: "b".repeat(32),
            vault_id: "c".repeat(32),
        };
        let wrong = VaultKeys::generate().unwrap();
        assert!(prepare_new(&state, &wrong, &signer, context(), public.clone(), &entry).is_err());
        let other = DeviceKeys::generate().unwrap();
        assert!(prepare_new(&state, &keys, &other, context(), public.clone(), &entry).is_err());
        for field in [
            "public",
            "fingerprint",
            "passphrase",
            "origin",
            "time",
            "source",
        ] {
            let mut public = public.clone();
            let mut entry = entry.clone();
            match field {
                "public" => {
                    entry.public_key =
                        crate::sync::slot_rules::test_keys::ECDSA_SHORT_P384_PUBLIC.into()
                }
                "fingerprint" => entry.fingerprint = "SHA256:wrong".into(),
                "passphrase" => public.has_passphrase = true,
                "origin" => public.origin_device_id = "d".repeat(32),
                "time" => public.created_at_ms = super::super::wire::MAX_SAFE_INTEGER + 1,
                _ => entry.origin = EntryOrigin::Synced,
            }
            assert!(
                prepare_new(&state, &keys, &signer, context(), public, &entry).is_err(),
                "{field}"
            );
        }
        assert!(state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending
            .is_empty());
    }
    #[test]
    fn valid_cached_tombstones_and_invalid_transaction_ids_cannot_be_reused_for_a_new_source() {
        use crate::sync::record::{LocalRecord, Record};
        let (state, keys, signer, _, public, entry) = fixture(false);
        let context = || Context {
            operation: "a".repeat(32),
            key_id: "b".repeat(32),
            vault_id: "c".repeat(32),
        };
        let mut deleted = state.clone();
        let id = context().key_id;
        deleted.account.as_mut().unwrap().records.insert(
            record_key(RecordKind::KeySlot, &id),
            LocalRecord {
                record: Record {
                    kind: RecordKind::KeySlot,
                    id,
                    version: 1,
                    updated_at_ms: 1,
                    device_id: state.device_id.clone(),
                    deleted: true,
                    payload: serde_json::Value::Null,
                },
                seq: 0,
                dirty: false,
            },
        );
        records_v3::validate_state(&deleted).unwrap();
        assert!(prepare_new(&deleted, &keys, &signer, context(), public.clone(), &entry).is_err());
        for field in ["operation", "key", "vault"] {
            let mut context = context();
            match field {
                "operation" => context.operation = "../not-an-operation".into(),
                "key" => context.key_id = "short".into(),
                _ => context.vault_id = "A".repeat(32),
            }
            assert!(prepare_new(&state, &keys, &signer, context, public.clone(), &entry).is_err());
        }
        assert!(state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending
            .is_empty());
    }
    #[test]
    fn oversized_original_material_stops_before_returning_any_pending_candidate() {
        let (state, keys, signer, context, _, _) = fixture(false);
        let mut parsed =
            crate::vault::material::parse(&crate::sync::slot_rules::test_keys::plain()).unwrap();
        parsed.set_comment("x".repeat(super::super::wire::MAX_PLAINTEXT_BYTES));
        let raw = parsed
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let mut public = slot(&raw).public;
        public.origin_device_id = state
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .device
            .id
            .clone();
        let entry = VaultEntry {
            private_key: raw.clone(),
            public_key: public.public_key.clone(),
            fingerprint: public.fingerprint.clone(),
            origin: EntryOrigin::Imported,
            added_at_ms: public.created_at_ms,
        };
        assert!(prepare_new(&state, &keys, &signer, context, public, &entry).is_err());
        assert_eq!(entry.private_key, raw);
        assert!(state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending
            .is_empty());
    }
    #[test]
    fn every_occupied_or_retained_identifier_and_unapproved_owner_blocks_new_source_preparation() {
        let (state, keys, signer, _, public, entry) = fixture(false);
        for case in [
            "local",
            "pending",
            "current",
            "basis",
            "physical",
            "operation",
            "not-cutover",
            "signed-out",
        ] {
            let mut state = state.clone();
            let id = "b".repeat(32);
            let context = Context {
                operation: "a".repeat(32),
                key_id: id.clone(),
                vault_id: "c".repeat(32),
            };
            match case {
                "local" => {
                    state.local.keys.insert(
                        id.clone(),
                        LocalKeyMetadata {
                            vault_id: "d".repeat(32),
                            public: public.clone(),
                        },
                    );
                }
                "physical" => {
                    state.local.keys.insert(
                        "e".repeat(32),
                        LocalKeyMetadata {
                            vault_id: context.vault_id.clone(),
                            public: public.clone(),
                        },
                    );
                }
                "operation" => {
                    state.local.import_receipts.insert(
                        context.operation.clone(),
                        records_v3::LocalImportReceipt {
                            source_digest: "e".repeat(64),
                            host_ids: vec![],
                            key_ids: vec![],
                        },
                    );
                }
                "not-cutover" => {
                    state.local.central_projection = None;
                    state.local.central.as_mut().unwrap().control.cutover = false;
                }
                "signed-out" => {
                    state.local.central.as_mut().unwrap().control.phase =
                        super::super::client_state::Phase::SignedOut
                }
                "basis" => {
                    let ledger = state.local.central_projection.as_mut().unwrap();
                    let value = ledger.bases.values().next().unwrap().clone();
                    ledger
                        .bases
                        .insert(identity("keyslot", &id).opaque(&keys).unwrap(), value);
                }
                "current" => {
                    let replica = state
                        .local
                        .central
                        .as_mut()
                        .unwrap()
                        .replica
                        .as_mut()
                        .unwrap();
                    let value = replica.current.values().next().unwrap().clone();
                    replica
                        .current
                        .insert(identity("keyslot", &id).opaque(&keys).unwrap(), value);
                }
                _ => {
                    let prior = prepare_new(
                        &state,
                        &keys,
                        &signer,
                        Context {
                            operation: context.operation.clone(),
                            key_id: id.clone(),
                            vault_id: context.vault_id.clone(),
                        },
                        public.clone(),
                        &entry,
                    )
                    .unwrap();
                    state.local.central = Some(prior.owner().clone());
                }
            }
            assert!(
                prepare_new(&state, &keys, &signer, context, public.clone(), &entry).is_err(),
                "{case}"
            );
        }
    }
}
