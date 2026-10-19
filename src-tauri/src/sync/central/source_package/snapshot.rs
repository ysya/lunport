//! Device-attested logical history inside the encrypted native source package only.
//! Original captured files remain bound and retained. No saved identity or Vault epoch key.
use super::super::{
    credentials::DeviceIdentity, crypto, migration_library::History, payload, rekey::Checkpoint,
};
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
const MAGIC: &[u8; 8] = b"LPHISTS1";
const DOMAIN: &[u8] = b"lunport-native-signed-history-v1\0";
const MAX_HISTORY: usize = 32 * 1024 * 1024 - 256 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    source: Option<Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    planned: bool,
    admitted: BTreeSet<String>,
    floors: Vec<Checkpoint>,
    controls: Vec<super::super::adoption::captured::ControlMinimum>,
}
#[derive(Clone, PartialEq, Eq)]
pub(in crate::sync::central) struct Group {
    meta: Metadata,
    rows: Zeroizing<Vec<u8>>,
}
/// Deliberately lacks Serialize/Debug. This is plaintext only inside native encryption buffers.
pub(super) struct Snapshot {
    bytes: Zeroizing<Vec<u8>>,
}
fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AppError> {
    if out
        .len()
        .checked_add(8)
        .and_then(|n| n.checked_add(bytes.len()))
        .is_none_or(|n| n > MAX_BYTES)
    {
        return Err(invalid());
    }
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn rows(history: History) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let mut out = Zeroizing::new(Vec::new());
    for (id, data) in history.into_rows() {
        put(&mut out, id.kind.as_bytes())?;
        out.push(u8::from(matches!(data, payload::Data::Deleted)));
        put(&mut out, &payload::encode(&id, &data)?)?;
        if out.len() > MAX_HISTORY {
            return Err(invalid());
        }
    }
    Ok(out)
}
fn group_key(source: &Receipt, admitted: &BTreeSet<String>) -> Result<String, AppError> {
    Ok(crypto::hash(
        &serde_json::to_vec(&(source, admitted)).map_err(|_| invalid())?,
    ))
}
pub(super) fn captured_group_key(
    source: &Receipt,
    frames: &[(Receipt, Zeroizing<Vec<u8>>)],
) -> Result<String, AppError> {
    let mut admitted = BTreeSet::from([source.ciphertext_hash.clone()]);
    for (receipt, bytes) in frames {
        if super::super::adoption::captured::source(bytes)?.as_ref() == Some(source) {
            admitted.insert(receipt.ciphertext_hash.clone());
        }
    }
    group_key(source, &admitted)
}
impl Group {
    pub(super) fn captured(
        source: &Receipt,
        value: super::super::adoption::captured::Captured,
    ) -> Result<Self, AppError> {
        let result = Self {
            meta: Metadata {
                source: Some(source.clone()),
                state: None,
                planned: false,
                admitted: value.admitted,
                floors: value.floors,
                controls: value.controls,
            },
            rows: rows(value.history)?,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<(), AppError> {
        if let Some(source) = &self.meta.source {
            source.validate()?;
            if self.meta.state.is_some()
                || self.meta.admitted.len() < 2
                || !self.meta.admitted.contains(&source.ciphertext_hash)
                || !self.meta.planned && self.meta.floors.is_empty()
            {
                return Err(invalid());
            }
        } else {
            let state = self.meta.state.as_ref().ok_or_else(invalid)?;
            if self.meta.planned
                || !super::super::wire::hex(state, 64)
                || self.meta.admitted != BTreeSet::from([state.clone()])
            {
                return Err(invalid());
            }
        }
        if self.meta.admitted.is_empty()
            || self.meta.admitted.len() > if self.meta.planned { 256 } else { 9 }
            || self
                .meta
                .admitted
                .iter()
                .any(|s| !super::super::wire::hex(s, 64))
            || self.meta.floors.len() > if self.meta.state.is_some() { 256 } else { 16 }
            || self.rows.len() > MAX_HISTORY
        {
            return Err(invalid());
        }
        if self.meta.controls.is_empty()
            || self.meta.controls.len() > 16
            || self.meta.controls.iter().any(|c| {
                c.highwater.revision > 1024
                    || !super::super::wire::hex(&c.highwater.head, 64)
                    || c.auth_epoch == 0
                    || c.auth_epoch > super::super::wire::MAX_SAFE_INTEGER
            })
        {
            return Err(invalid());
        }
        for floor in &self.meta.floors {
            if floor.epoch == 0
                || floor.epoch > 65
                || floor.sequence > 16384
                || !super::super::wire::hex(&floor.history_hash, 64)
                || floor.sequence == 0 && floor.history_hash != "0".repeat(64)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(super) fn planned(
        source: &Receipt,
        admitted: BTreeSet<String>,
        history: History,
        owner: &Workspace,
    ) -> Result<Self, AppError> {
        let group = Self {
            meta: Metadata {
                source: Some(source.clone()),
                state: None,
                planned: true,
                admitted,
                floors: vec![],
                controls: vec![super::super::adoption::captured::ControlMinimum {
                    highwater: owner.control.verified_chain()?.highwater(),
                    auth_epoch: owner.control.auth_epoch,
                }],
            },
            rows: rows(history)?,
        };
        group.validate()?;
        Ok(group)
    }
    pub(super) fn require_plan(
        &self,
        source: &Receipt,
        admitted: &BTreeSet<String>,
    ) -> Result<(), AppError> {
        self.validate()?;
        if !self.meta.planned
            || self.meta.source.as_ref() != Some(source)
            || &self.meta.admitted != admitted
            || !self.meta.floors.is_empty()
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn plan_key(
        source: &Receipt,
        admitted: &BTreeSet<String>,
    ) -> Result<String, AppError> {
        group_key(source, admitted)
    }
    pub(super) fn controls(&self) -> &[super::super::adoption::captured::ControlMinimum] {
        &self.meta.controls
    }
    pub(super) fn key(&self) -> Result<String, AppError> {
        match &self.meta.source {
            Some(source) => group_key(source, &self.meta.admitted),
            None => Ok(format!(
                "state:{}",
                self.meta.state.as_ref().ok_or_else(invalid)?
            )),
        }
    }
    pub(super) fn source(&self) -> Option<&Receipt> {
        self.meta.source.as_ref()
    }
    pub(in crate::sync::central) fn state_key(state: &SyncStateV3) -> Result<String, AppError> {
        Ok(format!(
            "state:{}",
            crypto::hash(&Zeroizing::new(
                serde_json::to_vec(state).map_err(|_| invalid())?
            ))
        ))
    }
    pub(super) fn state_captured(
        state: &SyncStateV3,
        captured: super::super::historical_state::Captured,
    ) -> Result<Self, AppError> {
        let hash = Self::state_key(state)?
            .strip_prefix("state:")
            .ok_or_else(invalid)?
            .to_owned();
        let group = Self {
            meta: Metadata {
                source: None,
                state: Some(hash.clone()),
                planned: false,
                admitted: BTreeSet::from([hash]),
                floors: captured.floors,
                controls: captured.controls,
            },
            rows: rows(captured.history)?,
        };
        group.validate()?;
        Ok(group)
    }
    pub(in crate::sync::central) fn require_state(
        &self,
        state: &SyncStateV3,
    ) -> Result<(), AppError> {
        self.validate()?;
        if self.meta.source.is_some() || self.key()? != Self::state_key(state)? {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn admitted(&self) -> &BTreeSet<String> {
        &self.meta.admitted
    }
    pub(super) fn floors(&self) -> &[Checkpoint] {
        &self.meta.floors
    }
    /// Call only after the enclosing snapshot has passed signature and complete input binding.
    pub(super) fn history(&self) -> Result<History, AppError> {
        self.validate()?;
        let mut input = self.rows.as_slice();
        let mut history = History::empty_retained();
        let mut count = 0;
        while !input.is_empty() {
            count += 1;
            if count > 16384 {
                return Err(invalid());
            }
            let kind = std::str::from_utf8(section(&mut input, 16)?).map_err(|_| invalid())?;
            let deleted = match input.first() {
                Some(0) => false,
                Some(1) => true,
                _ => return Err(invalid()),
            };
            input = &input[1..];
            let plain = section(&mut input, super::super::wire::MAX_PLAINTEXT_BYTES)?;
            let admitted = payload::admit_snapshot(kind, deleted, plain)?;
            // Canonical bytes make schema evolution and duplicate-field ambiguity fail closed.
            if payload::encode(&admitted.identity, &admitted.data)?.as_slice() != plain {
                return Err(invalid());
            }
            history.push_retained(admitted.identity, admitted.data)?;
        }
        Ok(history)
    }
    pub(super) fn require_frames(
        &self,
        frames: &[(Receipt, Zeroizing<Vec<u8>>)],
    ) -> Result<(), AppError> {
        self.validate()?;
        if self.meta.planned {
            return Err(invalid());
        }
        let source = self.meta.source.as_ref().ok_or_else(invalid)?;
        let (_, plain) = frames
            .iter()
            .find(|(r, _)| r == source)
            .ok_or_else(invalid)?;
        let package = Package::decode_local(plain)?;
        source.matches_selected(package.state.local.central.as_ref().ok_or_else(invalid)?)?;
        let mut actual = BTreeSet::from([source.ciphertext_hash.clone()]);
        for (receipt, bytes) in frames {
            if let Some(source) = super::super::adoption::captured::source(bytes)? {
                if &source == self.meta.source.as_ref().ok_or_else(invalid)? {
                    if !receipt.follows(&source)? || !actual.insert(receipt.ciphertext_hash.clone())
                    {
                        return Err(invalid());
                    }
                } else if receipt.operation()
                    == self.meta.source.as_ref().ok_or_else(invalid)?.operation()
                {
                    return Err(invalid());
                }
            }
        }
        if actual != self.meta.admitted {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Package {
    fn snapshot_binding(&self) -> Result<String, AppError> {
        let mut bytes = Zeroizing::new(Vec::new());
        put(&mut bytes, self.state_name.as_bytes())?;
        put(&mut bytes, &self.files.encode_local()?)?;
        put(&mut bytes, &self.decryptors.encode_local()?)?;
        Ok(crypto::hash(&bytes))
    }
    pub(super) fn snapshot_groups(&self) -> Result<Vec<Group>, AppError> {
        let mut groups = match &self.snapshot {
            Some(snapshot) => snapshot.verify(self)?,
            None => vec![],
        };
        groups.extend(self.inherited.iter().cloned());
        Ok(groups)
    }
    pub(in crate::sync::central) fn require_captured_inputs(
        &self,
        original: &Self,
    ) -> Result<(), AppError> {
        if self.state != original.state
            || self.snapshot_binding()? != original.snapshot_binding()?
            || self.sources.encode_local()?.as_slice()
                != original.sources.encode_local()?.as_slice()
            || self
                .frozen
                .as_ref()
                .map(|v| v.encode_local())
                .transpose()?
                .as_deref()
                != original
                    .frozen
                    .as_ref()
                    .map(|v| v.encode_local())
                    .transpose()?
                    .as_deref()
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Snapshot {
    pub(super) fn create(
        package: &Package,
        identity: &DeviceIdentity,
        groups: Vec<Group>,
    ) -> Result<Self, AppError> {
        let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
        if identity.device() != owner.control.device || groups.is_empty() || groups.len() > 256 {
            return Err(invalid());
        }
        let mut out = Zeroizing::new(MAGIC.to_vec());
        put(&mut out, package.snapshot_binding()?.as_bytes())?;
        put(&mut out, &package.sources.encode_local()?)?;
        let mut logical_bytes = 0usize;
        for group in groups {
            group.validate()?;
            logical_bytes = logical_bytes
                .checked_add(group.rows.len())
                .ok_or_else(invalid)?;
            if logical_bytes > MAX_HISTORY {
                return Err(invalid());
            }
            put(
                &mut out,
                &serde_json::to_vec(&group.meta).map_err(|_| invalid())?,
            )?;
            put(&mut out, &group.rows)?;
        }
        let mut signed = Zeroizing::new(DOMAIN.to_vec());
        signed.extend_from_slice(&out);
        let signature = identity.keys.sign(&signed);
        put(&mut out, signature.as_bytes())?;
        let result = Self { bytes: out };
        drop(result.verify(package)?);
        Ok(result)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > MAX_BYTES || !bytes.starts_with(MAGIC) {
            return Err(invalid());
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn verify(&self, package: &Package) -> Result<Vec<Group>, AppError> {
        let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
        let chain = owner.control.verified_chain()?;
        let public = chain
            .current()
            .devices()
            .get(&owner.control.device.id)
            .ok_or_else(invalid)?;
        if public != &owner.control.device.keys {
            return Err(invalid());
        }
        let mut input = &self.bytes[8..];
        let binding = section(&mut input, 64)?;
        if binding != package.snapshot_binding()?.as_bytes() {
            return Err(invalid());
        }
        let book = Sources::decode_local(
            section(&mut input, super::super::migration_sources::MAX_BOOK_BYTES)?,
            &package.state,
        )?;
        package.sources.require_retained_subset(&book)?;
        // The final fixed-size Ed25519 signature section cannot be confused with a group.
        let mut groups = vec![];
        let mut seen = BTreeSet::new();
        let mut logical_bytes = 0usize;
        while input.len() > 96 {
            if groups.len() >= 256 {
                return Err(invalid());
            }
            let meta: Metadata =
                serde_json::from_slice(section(&mut input, 128 * 1024)?).map_err(|_| invalid())?;
            let rows = Zeroizing::new(section(&mut input, MAX_HISTORY)?.to_vec());
            logical_bytes = logical_bytes.checked_add(rows.len()).ok_or_else(invalid)?;
            if logical_bytes > MAX_HISTORY {
                return Err(invalid());
            }
            let group = Group { meta, rows };
            group.validate()?;
            if !seen.insert(group.key()?) {
                return Err(invalid());
            }
            groups.push(group);
        }
        let signed_length = self.bytes.len() - input.len();
        let signature = std::str::from_utf8(section(&mut input, 88)?).map_err(|_| invalid())?;
        if !input.is_empty() || groups.is_empty() {
            return Err(invalid());
        }
        let mut signed = Zeroizing::new(DOMAIN.to_vec());
        signed.extend_from_slice(&self.bytes[..signed_length]);
        crypto::verify(&public.signing, &signed, signature)?;
        for group in &groups {
            drop(group.history()?);
        }
        Ok(groups)
    }
}

/// A state-bound logical witness for replacement archival. Enclose only in native encryption.
pub(in crate::sync::central) struct StateSnapshot {
    bytes: Zeroizing<Vec<u8>>,
}
impl StateSnapshot {
    pub(in crate::sync::central) fn create(
        state: &SyncStateV3,
        identity: &DeviceIdentity,
    ) -> Result<Self, AppError> {
        let group = Group::state_captured(
            state,
            super::super::historical_state::read(state, identity)?,
        )?;
        let mut bytes = Zeroizing::new(b"LPSTATE1".to_vec());
        put(
            &mut bytes,
            &serde_json::to_vec(&group.meta).map_err(|_| invalid())?,
        )?;
        put(&mut bytes, &group.rows)?;
        let mut signed = Zeroizing::new(b"lunport-native-state-history-v1\0".to_vec());
        signed.extend_from_slice(&bytes);
        put(&mut bytes, identity.keys.sign(&signed).as_bytes())?;
        let result = Self { bytes };
        drop(result.verify(state)?);
        Ok(result)
    }
    pub(in crate::sync::central) fn decode(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > MAX_HISTORY + 128 * 1024 || !bytes.starts_with(b"LPSTATE1") {
            return Err(invalid());
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }
    pub(in crate::sync::central) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(in crate::sync::central) fn verify(&self, state: &SyncStateV3) -> Result<Group, AppError> {
        records_v3::validate_state(state).map_err(|_| invalid())?;
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let chain = match &owner.recovery {
            Some(super::super::recovery_state::RecoveryState::Pending { package }) => {
                package.admission.verify(&package.proof())?
            }
            _ => owner.control.verified_chain()?,
        };
        if !(0..=chain.highwater().revision).any(|r| {
            chain.head_at(r as usize).is_some_and(|head| {
                chain.author_at(head, &owner.control.device.id) == Some(&owner.control.device.keys)
            })
        }) {
            return Err(invalid());
        }
        let mut input = &self.bytes[8..];
        let meta =
            serde_json::from_slice(section(&mut input, 128 * 1024)?).map_err(|_| invalid())?;
        let rows = Zeroizing::new(section(&mut input, MAX_HISTORY)?.to_vec());
        let signed_len = self.bytes.len() - input.len();
        let signature = std::str::from_utf8(section(&mut input, 88)?).map_err(|_| invalid())?;
        if !input.is_empty() {
            return Err(invalid());
        }
        let mut signed = Zeroizing::new(b"lunport-native-state-history-v1\0".to_vec());
        signed.extend_from_slice(&self.bytes[..signed_len]);
        crypto::verify(&owner.control.device.keys.signing, &signed, signature)?;
        let group = Group { meta, rows };
        group.require_state(state)?;
        drop(group.history()?);
        Ok(group)
    }
}
