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
    source: Receipt,
    admitted: BTreeSet<String>,
    floors: Vec<Checkpoint>,
    controls: Vec<super::super::adoption::captured::ControlMinimum>,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Group {
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
                source: source.clone(),
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
        self.meta.source.validate()?;
        if self.meta.admitted.len() < 2
            || self.meta.admitted.len() > 9
            || !self
                .meta
                .admitted
                .contains(&self.meta.source.ciphertext_hash)
            || self
                .meta
                .admitted
                .iter()
                .any(|s| !super::super::wire::hex(s, 64))
            || self.meta.floors.is_empty()
            || self.meta.floors.len() > 16
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
    pub(super) fn controls(&self) -> &[super::super::adoption::captured::ControlMinimum] {
        &self.meta.controls
    }
    pub(super) fn key(&self) -> Result<String, AppError> {
        group_key(&self.meta.source, &self.meta.admitted)
    }
    pub(super) fn source(&self) -> &Receipt {
        &self.meta.source
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
        let (_, plain) = frames
            .iter()
            .find(|(r, _)| r == &self.meta.source)
            .ok_or_else(invalid)?;
        let package = Package::decode_local(plain)?;
        self.meta
            .source
            .matches_selected(package.state.local.central.as_ref().ok_or_else(invalid)?)?;
        let mut actual = BTreeSet::from([self.meta.source.ciphertext_hash.clone()]);
        for (receipt, bytes) in frames {
            if let Some(source) = super::super::adoption::captured::source(bytes)? {
                if source == self.meta.source {
                    if !receipt.follows(&source)? || !actual.insert(receipt.ciphertext_hash.clone())
                    {
                        return Err(invalid());
                    }
                } else if receipt.operation() == self.meta.source.operation() {
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
