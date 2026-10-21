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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    ordered: bool,
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
                ordered: false,
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
            if self.meta.ordered
                || self.meta.state.is_some()
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
            || self.meta.controls.len() > if self.meta.state.is_some() { 256 } else { 16 }
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
                ordered: false,
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
    pub(in crate::sync::central) fn controls(
        &self,
    ) -> &[super::super::adoption::captured::ControlMinimum] {
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
    pub(in crate::sync::central) fn state_captured(
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
                ordered: super::super::replacement_reconciliation::projected(state),
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
    pub(in crate::sync::central) fn floors(&self) -> &[Checkpoint] {
        &self.meta.floors
    }
    /// Call only after the enclosing snapshot has passed signature and complete input binding.
    pub(in crate::sync::central) fn history(&self) -> Result<History, AppError> {
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
            if self.meta.ordered {
                history.push_selected(admitted.identity, admitted.data)?;
            } else {
                history.push_retained(admitted.identity, admitted.data)?;
            }
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
        let book = Package::restore_sources(
            &package.state,
            &package.files,
            &package.decryptors,
            section(&mut input, super::super::migration_sources::MAX_BOOK_BYTES)?,
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
        Self::create_captured(
            state,
            identity,
            super::super::historical_state::read(state, identity)?,
        )
    }
    pub(in crate::sync::central) fn create_captured(
        state: &SyncStateV3,
        identity: &DeviceIdentity,
        captured: super::super::historical_state::Captured,
    ) -> Result<Self, AppError> {
        if identity.device()
            != state
                .local
                .central
                .as_ref()
                .ok_or_else(invalid)?
                .control
                .device
        {
            return Err(invalid());
        }
        let group = Group::state_captured(state, captured)?;
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
        if bytes.len() > MAX_HISTORY + 128 * 1024
            || !(bytes.starts_with(b"LPSTATE1")
                || bytes.starts_with(b"LPSTATE2")
                || bytes.starts_with(b"LPSTATE3"))
        {
            return Err(invalid());
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }
    pub(in crate::sync::central) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(in crate::sync::central) fn create_groups(
        state: &SyncStateV3,
        identity: &DeviceIdentity,
        groups: Vec<Group>,
    ) -> Result<Self, AppError> {
        Self::create_signed_groups(state, identity, groups, false)
    }
    pub(in crate::sync::central) fn create_reconnected(
        state: &SyncStateV3,
        identity: &DeviceIdentity,
        read: &super::super::active_read::VerifiedLibrary,
        groups: Vec<Group>,
    ) -> Result<Self, AppError> {
        // This native capability includes the exact staged owner and original membership/history floors.
        super::super::replacement_proof::active_read(
            state.local.central.as_ref().ok_or_else(invalid)?,
            read,
            &[],
        )?;
        Self::create_signed_groups(state, identity, groups, true)
    }
    fn create_signed_groups(
        state: &SyncStateV3,
        identity: &DeviceIdentity,
        groups: Vec<Group>,
        reconnected: bool,
    ) -> Result<Self, AppError> {
        let expected = if reconnected {
            Self::reconnected_signing_key(state)?
        } else {
            Self::signing_key(state)?
        };
        if identity.device().keys.signing != expected
            || !reconnected
                && identity.device()
                    != state
                        .local
                        .central
                        .as_ref()
                        .ok_or_else(invalid)?
                        .control
                        .device
            || groups.is_empty()
            || groups.len() > 256
        {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(if reconnected {
            b"LPSTATE3".to_vec()
        } else {
            b"LPSTATE2".to_vec()
        });
        put(&mut bytes, Group::state_key(state)?.as_bytes())?;
        bytes.extend_from_slice(&(groups.len() as u32).to_be_bytes());
        let mut logical = 0usize;
        let mut seen = BTreeSet::new();
        for group in groups {
            group.validate()?;
            if !seen.insert(group.key()?) {
                return Err(invalid());
            }
            logical = logical.checked_add(group.rows.len()).ok_or_else(invalid)?;
            if logical > MAX_HISTORY {
                return Err(invalid());
            }
            put(
                &mut bytes,
                &serde_json::to_vec(&group.meta).map_err(|_| invalid())?,
            )?;
            put(&mut bytes, &group.rows)?;
            if bytes.len() > MAX_HISTORY + 128 * 1024 - 96 {
                return Err(invalid());
            }
        }
        let mut signed = Zeroizing::new(if reconnected {
            b"lunport-native-state-history-v3\0".to_vec()
        } else {
            b"lunport-native-state-history-v2\0".to_vec()
        });
        signed.extend_from_slice(&bytes);
        put(&mut bytes, identity.keys.sign(&signed).as_bytes())?;
        let result = Self { bytes };
        drop(result.verify_all(state)?);
        Ok(result)
    }
    pub(in crate::sync::central) fn verify_all(
        &self,
        state: &SyncStateV3,
    ) -> Result<Vec<Group>, AppError> {
        if self.bytes.starts_with(b"LPSTATE1") {
            return Ok(vec![self.verify_one(state)?]);
        }
        let reconnected = self.bytes.starts_with(b"LPSTATE3");
        if !(self.bytes.starts_with(b"LPSTATE2") || reconnected)
            || self.bytes.len() > MAX_HISTORY + 128 * 1024
        {
            return Err(invalid());
        }
        let signing = if reconnected {
            Self::reconnected_signing_key(state)?
        } else {
            Self::signing_key(state)?
        };
        let mut input = &self.bytes[8..];
        if section(&mut input, 70)? != Group::state_key(state)?.as_bytes() || input.len() < 4 {
            return Err(invalid());
        }
        let count = u32::from_be_bytes(input[..4].try_into().map_err(|_| invalid())?) as usize;
        input = &input[4..];
        if count == 0 || count > 256 {
            return Err(invalid());
        }
        let mut groups = vec![];
        let mut logical = 0usize;
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let meta =
                serde_json::from_slice(section(&mut input, 128 * 1024)?).map_err(|_| invalid())?;
            let rows = Zeroizing::new(section(&mut input, MAX_HISTORY)?.to_vec());
            logical = logical.checked_add(rows.len()).ok_or_else(invalid)?;
            if logical > MAX_HISTORY {
                return Err(invalid());
            }
            let group = Group { meta, rows };
            group.validate()?;
            if !seen.insert(group.key()?) {
                return Err(invalid());
            }
            groups.push(group);
        }
        let signed_len = self.bytes.len() - input.len();
        let signature = std::str::from_utf8(section(&mut input, 88)?).map_err(|_| invalid())?;
        if !input.is_empty() {
            return Err(invalid());
        }
        let mut signed = Zeroizing::new(if reconnected {
            b"lunport-native-state-history-v3\0".to_vec()
        } else {
            b"lunport-native-state-history-v2\0".to_vec()
        });
        signed.extend_from_slice(&self.bytes[..signed_len]);
        crypto::verify(signing, &signed, signature)?;
        if !groups.iter().any(|g| g.require_state(state).is_ok()) {
            return Err(invalid());
        }
        for group in &groups {
            drop(group.history()?);
        }
        Ok(groups)
    }
    fn reconnected_signing_key(state: &SyncStateV3) -> Result<&str, AppError> {
        records_v3::validate_state(state).map_err(|_| invalid())?;
        let source = state.local.central.as_ref().ok_or_else(invalid)?;
        let intent = source.replacement.as_ref().ok_or_else(invalid)?;
        let candidate = intent.candidate.as_deref().ok_or_else(invalid)?;
        let chain = candidate.control.verified_chain()?;
        let confirmation = candidate
            .control
            .pairing_confirmation
            .as_ref()
            .ok_or_else(invalid)?;
        let revision = chain
            .revision_of(&confirmation.approved_head)
            .ok_or_else(invalid)?;
        let node = candidate
            .control
            .proof
            .as_ref()
            .ok_or_else(invalid)?
            .nodes
            .get(revision.checked_sub(1).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if intent.route != super::super::replacement::Route::SyncPassword
            || source.control.anchor.as_ref() != candidate.control.anchor.as_ref()
            || candidate.control.auth_epoch < source.control.auth_epoch
            || node.body.action != super::super::membership::Action::Unlock
            || node
                .body
                .enrollment
                .as_ref()
                .is_none_or(|r| r.device != candidate.control.device)
        {
            return Err(invalid());
        }
        candidate
            .control
            .proof
            .as_ref()
            .ok_or_else(invalid)?
            .verify(chain.current().anchor(), source.control.highwater.as_ref())?;
        Ok(&candidate.control.device.keys.signing)
    }
    fn signing_key(state: &SyncStateV3) -> Result<&str, AppError> {
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
        Ok(&owner.control.device.keys.signing)
    }
    pub(in crate::sync::central) fn verify(&self, state: &SyncStateV3) -> Result<Group, AppError> {
        self.verify_all(state)?
            .into_iter()
            .find(|g| g.require_state(state).is_ok())
            .ok_or_else(invalid)
    }
    fn verify_one(&self, state: &SyncStateV3) -> Result<Group, AppError> {
        let signing = Self::signing_key(state)?;
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
        crypto::verify(signing, &signed, signature)?;
        let group = Group { meta, rows };
        group.require_state(state)?;
        drop(group.history()?);
        Ok(group)
    }
}

#[cfg(test)]
mod order_tests {
    use super::*;
    #[cfg(any(unix, windows))]
    #[test]
    fn complete_replacement_snapshot_binds_all_groups_and_keeps_single_state_compatibility() {
        let (device, _keys, session) = super::super::super::source_capture::tests::fixture(false);
        let state = crate::sync::record_runtime::snapshot(&device.env())
            .unwrap()
            .0;
        let signer = session.identity.as_ref().unwrap();
        let legacy = StateSnapshot::create(&state, signer).unwrap();
        assert_eq!(legacy.verify_all(&state).unwrap().len(), 1);
        let current = legacy.verify(&state).unwrap();
        let mut older = state.clone();
        older.device_name = "older captured image".into();
        let old = StateSnapshot::create(&older, signer)
            .unwrap()
            .verify(&older)
            .unwrap();
        let complete =
            StateSnapshot::create_groups(&state, signer, vec![current.clone(), old.clone()])
                .unwrap();
        assert_eq!(complete.verify_all(&state).unwrap().len(), 2);
        let mut substituted = complete.bytes().to_vec();
        substituted[..8].copy_from_slice(b"LPSTATE3");
        assert!(StateSnapshot::decode(&substituted)
            .unwrap()
            .verify_all(&state)
            .is_err());
        assert!(complete.verify_all(&older).is_err());
        assert!(StateSnapshot::create_groups(&state, signer, vec![old]).is_err());
        assert!(
            StateSnapshot::create_groups(&state, signer, vec![current.clone(), current]).is_err()
        );
        let mut changed = complete.bytes().to_vec();
        let n = changed.len() - 1;
        changed[n] ^= 1;
        assert!(StateSnapshot::decode(&changed)
            .unwrap()
            .verify_all(&state)
            .is_err());
        let mut oversized = complete.bytes().to_vec();
        let count_at = 8 + 8 + Group::state_key(&state).unwrap().len();
        oversized[count_at..count_at + 4].copy_from_slice(&257u32.to_be_bytes());
        assert!(StateSnapshot::decode(&oversized)
            .unwrap()
            .verify_all(&state)
            .is_err());
    }
    #[test]
    fn selected_history_replays_a_returned_value_without_changing_legacy_snapshot_semantics() {
        let mut history = History::empty_retained();
        for alias in ["first", "second", "first"] {
            history.push_selected(payload::Identity{kind:"host".into(),id:"1".repeat(16),scope:Some(crate::sync::records_v3::HostScope::Local)},payload::Data::Host(serde_json::from_value(serde_json::json!({"schema":2,"alias":alias,"hostname":"test.invalid","auth":"password"})).unwrap())).unwrap();
        }
        let hash = "1".repeat(64);
        let mut group = Group {
            meta: Metadata {
                source: None,
                state: Some(hash.clone()),
                planned: false,
                ordered: true,
                admitted: BTreeSet::from([hash]),
                floors: vec![],
                controls: vec![super::super::super::adoption::captured::ControlMinimum {
                    highwater: super::super::super::trust::Highwater {
                        revision: 0,
                        head: "2".repeat(64),
                    },
                    auth_epoch: 1,
                }],
            },
            rows: rows(history).unwrap(),
        };
        assert_eq!(group.history().unwrap().into_rows().len(), 3);
        group.meta.ordered = false;
        assert_eq!(group.history().unwrap().into_rows().len(), 2);
        let old = serde_json::to_value(&group.meta).unwrap();
        assert!(old.get("ordered").is_none());
        assert!(!serde_json::from_value::<Metadata>(old).unwrap().ordered);
    }
}
