//! Complete recoverable remote inputs, never winner selection or consent/cutover authority.
use super::*;
use crate::sync::{record::Envelope, relay::PullResponse};
pub(in crate::sync::central) const MAX_FROZEN_BYTES: usize = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    chain: String,
    sequence: u64,
    records: Vec<Envelope>,
}
/// Native protected archive data only. No Debug, public fields or IPC DTO implementation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct FrozenSet {
    version: u32,
    local_context: String,
    keybook: String,
    operation: String,
    progress: Progress,
    snapshots: Vec<Snapshot>,
}
impl FrozenSet {
    pub fn capture(
        state: &SyncStateV3,
        sources: &Sources,
        operation: &str,
        progress: &Progress,
        minimum: Option<&super::super::migration_freeze::Known>,
        snapshots: Vec<FrozenSnapshot>,
    ) -> Result<Self, AppError> {
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let context = sources.progress_context(owner, operation, progress, minimum)?;
        if context.target != super::frozen::Target::current(owner)?
            || progress.phase != super::super::migration_freeze::Phase::Frozen
            || snapshots.len() != progress.sources.len()
        {
            return Err(invalid());
        }
        let mut stored = BTreeMap::new();
        for snapshot in snapshots {
            let checkpoint = snapshot.checkpoint().clone();
            if snapshot.context() != &context || !progress.sources.contains(&checkpoint) {
                return Err(invalid());
            }
            let mut records = snapshot.into_records();
            records.sort_by(|a, b| a.id_hash.cmp(&b.id_hash));
            let value = Snapshot {
                chain: checkpoint.chain_id.clone(),
                sequence: super::super::wire::number(&checkpoint.sequence, true)?,
                records,
            };
            if stored.insert(checkpoint.chain_id, value).is_some() {
                return Err(invalid());
            }
        }
        let result = Self {
            version: 1,
            local_context: context.target.binding()?,
            keybook: context.keybook,
            operation: operation.into(),
            progress: progress.clone(),
            snapshots: stored.into_values().collect(),
        };
        drop(result.encode_local()?);
        drop(result.inventory(sources, state)?);
        Ok(result)
    }
    pub fn inventory(&self, sources: &Sources, state: &SyncStateV3) -> Result<Inventory, AppError> {
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let context = sources.progress_context(owner, &self.operation, &self.progress, None)?;
        if self.version != 1
            || self.keybook != context.keybook
            || self.local_context != context.target.binding()?
            || context.target != super::frozen::Target::current(owner)?
            || self.progress.phase != super::super::migration_freeze::Phase::Frozen
            || self.snapshots.len() != self.progress.sources.len()
            || self.snapshots.len() > MAX_SOURCES
        {
            return Err(invalid());
        }
        let mut result = Inventory::from_state(sources, state)?;
        let mut previous = "";
        for snapshot in &self.snapshots {
            if snapshot.chain.as_str() <= previous {
                return Err(invalid());
            }
            previous = &snapshot.chain;
            let admitted = sources.admit_frozen(
                owner,
                &self.operation,
                &self.progress,
                None,
                &snapshot.chain,
                PullResponse {
                    records: snapshot.records.clone(),
                    latest_seq: snapshot.sequence,
                },
            )?;
            result = result.with_frozen(sources, &admitted)?;
        }
        Ok(result)
    }
    pub fn reconcile_with_retained(
        &self,
        sources: &Sources,
        state: &SyncStateV3,
        retained: &[SyncStateV3],
    ) -> Result<super::reconcile::Reconciliation, AppError> {
        let mut inventory = self.inventory(sources, state)?;
        for image in retained {
            inventory = inventory.with_retained_state(sources, image)?;
        }
        super::reconcile::Reconciliation::from_complete(inventory, state)
    }
    pub fn reconcile(
        &self,
        sources: &Sources,
        state: &SyncStateV3,
    ) -> Result<super::reconcile::Reconciliation, AppError> {
        super::reconcile::Reconciliation::from_complete(self.inventory(sources, state)?, state)
    }
    pub fn context(
        &self,
        operation: &str,
        inventory_digest: &str,
    ) -> Result<super::super::migration_history::Context, AppError> {
        if operation != self.operation {
            return Err(invalid());
        }
        Ok(super::super::migration_history::Context {
            operation: operation.into(),
            inventory_digest: inventory_digest.into(),
            sources: self.progress.sources.clone(),
        })
    }
    pub fn encode_local(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let mut bytes = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *bytes, self).map_err(|_| invalid())?;
        if bytes.len() > MAX_FROZEN_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub fn decode_local(
        bytes: &[u8],
        sources: &Sources,
        state: &SyncStateV3,
    ) -> Result<Self, AppError> {
        if bytes.len() > MAX_FROZEN_BYTES {
            return Err(invalid());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        drop(value.inventory(sources, state)?);
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
