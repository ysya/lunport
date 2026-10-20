//! Rebase only the unsent catalog suffix against a completed authenticated history.
//! Accepted operations and independent imported record identities retain their exact ciphertext.
use super::super::{
    active_read::VerifiedLibrary,
    crypto::{DeviceKeys, RecordEnvelope},
    payload::{self, Catalog, Data},
    projection::PublicData,
    rekey::{self, Version},
    wire::canonical,
};
use super::*;
use crate::sync::records_v3::HostScope;
fn catalog(read: &VerifiedLibrary) -> Result<Catalog, AppError> {
    let owner = merge::current_owner(read.previous_owner(), read)?;
    let inventory = super::merge::inventory(owner, read.keys())?;
    if !inventory.complete() {
        return Err(invalid());
    }
    inventory
        .rows()
        .values()
        .find_map(|r| {
            if let PublicData::Catalog(c) = &r.data {
                Some(c.clone())
            } else {
                None
            }
        })
        .ok_or_else(invalid)
}
fn revision(read: &VerifiedLibrary, row: &RecordEnvelope) -> Result<u64, AppError> {
    read.replica()
        .current
        .get(&row.header.record_id)
        .map_or(Ok(0), |r| number(&r.version.revision, false))
}
fn partition(
    mut c: Catalog,
    owned: &std::collections::BTreeSet<String>,
    owned_tunnels: &std::collections::BTreeSet<String>,
) -> Catalog {
    c.tunnels.retain(|r| owned_tunnels.contains(&r.id));
    c.collections.retain(|v| owned.contains(&v.id));
    c.group_orders
        .retain(|v| matches!(&v.scope,HostScope::Space{space_id} if owned.contains(space_id)));
    c
}
impl merge::Plan {
    pub(super) fn needs_rebase(
        &self,
        read: &VerifiedLibrary,
        completed: usize,
    ) -> Result<bool, AppError> {
        if completed > self.rows.len() {
            return Err(invalid());
        }
        if let Some(row) = self
            .rows
            .iter()
            .skip(completed)
            .find(|r| r.header.kind == "meta")
        {
            let current = revision(read, row)?;
            let expected = number(&row.header.expected_revision, true)?;
            if current < expected {
                return Err(invalid());
            }
            return Ok(current > expected);
        }
        Ok(false)
    }
    fn rebase_inputs(
        &self,
        package: &Package,
        read: &VerifiedLibrary,
        transcript: &Transcript,
        completed: usize,
    ) -> Result<Vec<(super::super::payload::Identity, Data)>, AppError> {
        if completed != observed(self, transcript)?
            || !self.needs_rebase(read, completed)?
            || read.checkpoint().epoch
                != number(
                    &self.rows.first().ok_or_else(invalid)?.header.key_epoch,
                    false,
                )?
        {
            return Err(invalid());
        }
        let source = package
            .structured_history(read.keys(), &BTreeMap::new())?
            .into_rows();
        let owned = merge::owned_collections(&source, &self.operation)?;
        let owned_tunnels = merge::owned_tunnels(&source, &self.operation)?;
        let current = partition(catalog(read)?, &owned, &owned_tunnels);
        let previous = match self
            .rows
            .iter()
            .take(completed)
            .rev()
            .find(|r| r.header.kind == "meta")
        {
            Some(row) => {
                let author = read
                    .chain()
                    .author_at(&row.header.membership_head, &row.header.author)
                    .ok_or_else(invalid)?;
                let plain = row.verify(&author.signing)?.open(read.keys())?;
                match payload::admit(read.keys(), &row.header, &plain)?.data {
                    Data::Catalog(c) => partition(c, &owned, &owned_tunnels),
                    _ => return Err(invalid()),
                }
            }
            None => Catalog {
                tunnels: vec![],
                collections: vec![],
                group_orders: vec![],
            },
        };
        if current != previous {
            return Err(AppError::Other("Imported collection names or ordering changed on another device. The merge is paused with all source data retained.".into()));
        }
        let history = merge::history(package, read, &self.operation)?;
        if history.len() != self.rows.len() {
            return Err(invalid());
        }
        Ok(history)
    }
    pub(super) fn rebase(
        &self,
        package: &Package,
        read: &VerifiedLibrary,
        transcript: &Transcript,
        completed: usize,
        signer: &DeviceKeys,
    ) -> Result<Self, AppError> {
        let history = self.rebase_inputs(package, read, transcript, completed)?;
        let mut result = self.clone();
        let mut next = None;
        for (index, (id, data)) in history.iter().enumerate().skip(completed) {
            if id.kind != "meta" {
                continue;
            }
            let old = &self.rows[index];
            let base = next.get_or_insert(revision(read, old)?);
            let mut header = old.header.clone();
            header.expected_revision = base.to_string();
            header.operation_id = super::super::crypto::random_id(16)?;
            result.rows[index] = super::super::crypto::seal_record(
                read.keys(),
                signer,
                header,
                &payload::encode(id, data)?,
            )?;
            *base = base.checked_add(1).ok_or_else(invalid)?;
        }
        self.verify_rebase(&result, package, read, transcript, completed)?;
        Ok(result)
    }
    pub(super) fn verify_rebase(
        &self,
        next: &Self,
        package: &Package,
        read: &VerifiedLibrary,
        transcript: &Transcript,
        completed: usize,
    ) -> Result<(), AppError> {
        let history = self.rebase_inputs(package, read, transcript, completed)?;
        if next.version != self.version
            || next.operation != self.operation
            || next.rows.len() != self.rows.len()
        {
            return Err(invalid());
        }
        let owner = read.previous_owner();
        let mut catalog_revision = None;
        let mut seen = std::collections::BTreeSet::new();
        let old_operations: std::collections::BTreeSet<_> = self
            .rows
            .iter()
            .map(|r| r.header.operation_id.as_str())
            .collect();
        let mut bytes = 0usize;
        for (index, ((id, data), row)) in history.iter().zip(&next.rows).enumerate() {
            bytes = bytes
                .checked_add(serde_json::to_vec(row).map_err(|_| invalid())?.len())
                .ok_or_else(invalid)?;
            if bytes > 32 * 1024 * 1024 - 256 * 1024 || !seen.insert(&row.header.operation_id) {
                return Err(invalid());
            }
            if index < completed || id.kind != "meta" {
                if row != &self.rows[index] {
                    return Err(invalid());
                }
                continue;
            }
            let base = catalog_revision.get_or_insert(revision(read, row)?);
            let mut expected = self.rows[index].header.clone();
            expected.expected_revision = base.to_string();
            expected.operation_id = row.header.operation_id.clone();
            if row.header != expected
                || old_operations.contains(row.header.operation_id.as_str())
                || row.header.author != owner.control.device.id
            {
                return Err(invalid());
            }
            read.chain().current().verify_write(
                row,
                &read.replica().vault,
                read.checkpoint().epoch,
                &row.header.author,
            )?;
            if row
                .verify(&owner.control.device.keys.signing)?
                .open(read.keys())?
                .as_slice()
                != payload::encode(id, data)?.as_slice()
            {
                return Err(invalid());
            }
            *base = base.checked_add(1).ok_or_else(invalid)?;
        }
        let mut shadow = merge::current_owner(owner, read)?;
        let mut checkpoint = read.checkpoint().clone();
        let mut versions = vec![];
        let mut revisions = BTreeMap::new();
        for row in next.rows.iter().skip(completed) {
            let base = revisions
                .entry(&row.header.record_id)
                .or_insert(revision(read, row)?);
            if number(&row.header.expected_revision, true)? != *base {
                return Err(AppError::Other("An imported record changed on another device. The merge is paused with all source data retained.".into()));
            }
            *base += 1;
            checkpoint.sequence += 1;
            if checkpoint.sequence > 16384 {
                return Err(invalid());
            }
            let digest = rekey::envelope_digest(row)?;
            checkpoint.history_hash = super::super::crypto::hash(&canonical(&[
                "lunport-history-v2",
                &checkpoint.history_hash,
                &checkpoint.sequence.to_string(),
                &digest,
            ])?);
            versions.push(Version {
                revision: base.to_string(),
                sequence: checkpoint.sequence.to_string(),
                envelope: row.clone(),
                digest,
                history_hash: checkpoint.history_hash.clone(),
            });
        }
        for page in versions.chunks(32) {
            shadow.replica = Some(
                shadow
                    .replica
                    .as_ref()
                    .ok_or_else(invalid)?
                    .prepare_page(read.chain(), read.keys(), page, &checkpoint)?
                    .next,
            );
        }
        shadow.validate()?;
        if !super::merge::inventory(shadow, read.keys())?.complete() {
            return Err(invalid());
        }
        Ok(())
    }
}
