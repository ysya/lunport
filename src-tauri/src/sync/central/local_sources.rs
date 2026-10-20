//! Passive signed local provenance. Never enough to publish or activate material by itself.
use super::{
    crypto,
    local_material::Receipt,
    payload::{self, Data, Identity, KeyStorage},
    projection_state::Basis,
    trust::VerifiedChain,
    wire::invalid,
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::records_v3::{KeySlotPayload, LocalKeyMetadata},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct Sources(BTreeMap<String, Receipt>);
impl std::fmt::Debug for Sources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalMaterialSources")
            .field("count", &self.0.len())
            .finish()
    }
}
impl Sources {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn contains(&self, id: &str) -> bool {
        self.0.contains_key(id)
    }
    pub fn get(&self, id: &str) -> Option<&Receipt> {
        self.0.get(id)
    }
    pub fn validate(&self, owner: &Workspace, chain: &VerifiedChain) -> Result<(), AppError> {
        if self.0.len() > 4096 {
            return Err(invalid());
        }
        let mut operations = BTreeSet::new();
        let mut physical = BTreeSet::new();
        let mut opaque = BTreeSet::new();
        for (id, source) in &self.0 {
            source.verify_with_chain(owner, chain)?;
            let (public, private) = source.wire_handles();
            if id != source.key_id()
                || !operations.insert(source.operation())
                || !physical.insert(source.vault_id())
                || !opaque.insert(public)
                || !opaque.insert(private)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn insert(&mut self, receipt: Receipt) -> Result<(), AppError> {
        if self.0.contains_key(receipt.key_id()) {
            return Err(invalid());
        }
        self.0.insert(receipt.key_id().into(), receipt);
        Ok(())
    }
    pub fn storage(&self, id: &str) -> Option<&KeyStorage> {
        self.get(id).map(|s| &s.slot().storage)
    }
    pub fn classifications(&self) -> BTreeMap<String, KeyStorage> {
        self.0
            .iter()
            .map(|(id, source)| (id.clone(), source.slot().storage.clone()))
            .collect()
    }
    pub fn material_reference(
        &self,
        owner: &Workspace,
        bases: &BTreeMap<String, Basis>,
        storage: &BTreeMap<String, KeyStorage>,
        id: &str,
        local: &LocalKeyMetadata,
        public: &KeySlotPayload,
    ) -> Option<String> {
        let source = self.get(id)?;
        let slot = source.slot();
        let original = &slot.public;
        let replica = owner.replica.as_ref()?;
        if source.vault_id() != local.vault_id
            || public.has_passphrase != original.has_passphrase
            || public.key_type != original.key_type
            || public.fingerprint != original.fingerprint
            || crate::vault::material::public_key_data(&public.public_key)
                != crate::vault::material::public_key_data(&original.public_key)
            || local.public.has_passphrase != public.has_passphrase
        {
            return None;
        }
        let public_hash = crypto::hash(
            &payload::encode(
                &Identity {
                    kind: "keyslot".into(),
                    id: id.into(),
                    scope: None,
                },
                &Data::Keyslot(payload::SharedKeyslot {
                    public: public.clone(),
                    storage: slot.storage.clone(),
                }),
            )
            .ok()?,
        );
        let (public_handle, private_handle) = source.wire_handles();
        for (handle, kind, hash) in [
            (public_handle, "keyslot", public_hash.as_str()),
            (private_handle, "key", source.private_content_hash()),
        ] {
            if replica.conflicts.contains_key(handle) {
                return None;
            }
            match (replica.current.get(handle), bases.get(handle)) {
                (Some(current), Some(basis)) => {
                    if current != &basis.wire
                        || basis.remote.deleted
                        || basis.remote.id != id
                        || basis.remote.kind != kind
                        || kind == "key" && basis.remote.content_hash != hash
                        || kind == "keyslot" && storage.get(id) != Some(&slot.storage)
                    {
                        return None;
                    }
                    if !replica.pending.contains_key(handle) && basis.remote.semantic_hash != hash {
                        return None;
                    }
                }
                (None, None) => {
                    if !replica.pending.contains_key(handle) {
                        return None;
                    }
                }
                _ => return None,
            }
            if let Some(pending) = replica.pending.get(handle) {
                let h = &pending.latest.envelope.header;
                if h.kind != kind
                    || h.record_id != handle
                    || h.deleted
                    || h.author != owner.control.device.id
                    || pending.latest.content_hash != hash
                {
                    return None;
                }
            }
        }
        match &slot.storage {
            KeyStorage::Managed { sha256 } => Some(sha256.clone()),
            _ => None,
        }
    }
}
