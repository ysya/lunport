//! Passive partial frozen inputs. Only a complete set can become FrozenSet.
use super::*;
use crate::sync::{record::Envelope, relay::PullResponse};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    chain: String,
    sequence: u64,
    records: Vec<Envelope>,
}
/// Only explicit local encoding for an encrypted source archive. Never an IPC DTO or runtime.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct Fetching {
    version: u32,
    local_context: String,
    keybook: String,
    operation: String,
    progress: Progress,
    responses: BTreeMap<String, Response>,
}
impl Fetching {
    pub fn new(
        sources: &Sources,
        state: &SyncStateV3,
        operation: &str,
        progress: &Progress,
    ) -> Result<Self, AppError> {
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let context = sources.progress_context(owner, operation, progress, None)?;
        let result = Self {
            version: 1,
            local_context: context.target.binding()?,
            keybook: context.keybook,
            operation: operation.into(),
            progress: progress.clone(),
            responses: BTreeMap::new(),
        };
        drop(result.validate(sources, state)?);
        Ok(result)
    }
    fn validate(
        &self,
        sources: &Sources,
        state: &SyncStateV3,
    ) -> Result<Vec<FrozenSnapshot>, AppError> {
        records_v3::validate_state(state).map_err(|_| invalid())?;
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let context = sources.progress_context(owner, &self.operation, &self.progress, None)?;
        if self.version != 1
            || self.keybook != context.keybook
            || self.local_context != context.target.binding()?
            || context.target != frozen::Target::current(owner)?
            || self.responses.len() > MAX_SOURCES
        {
            return Err(invalid());
        }
        drop(self.encode_local()?);
        let mut snapshots = vec![];
        for (chain, response) in &self.responses {
            if chain != &response.chain {
                return Err(invalid());
            }
            snapshots.push(sources.admit_frozen(
                owner,
                &self.operation,
                &self.progress,
                None,
                chain,
                PullResponse {
                    records: response.records.clone(),
                    latest_seq: response.sequence,
                },
            )?);
        }
        // Local cursor minima and all already captured record semantics must hold even before
        // completion. This is enumeration only; unknown legacy payloads remain later blockers.
        let mut inventory = Inventory::from_state(sources, state)?;
        for snapshot in &snapshots {
            inventory = inventory.with_frozen(sources, snapshot)?;
        }
        Ok(snapshots)
    }
    pub fn progress(&self) -> &Progress {
        &self.progress
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn next_source(
        &self,
        sources: &Sources,
        state: &SyncStateV3,
    ) -> Result<Option<String>, AppError> {
        drop(self.validate(sources, state)?);
        Ok(self
            .progress
            .proof
            .last()
            .ok_or_else(invalid)?
            .intent
            .body
            .source_order()
            .into_iter()
            .find(|chain| !self.responses.contains_key(*chain))
            .filter(|chain| self.progress.sources.iter().any(|s| s.chain_id == **chain))
            .map(str::to_owned))
    }
    /// Same authenticated response retries do not replace ciphertext or consume extra capacity.
    pub fn insert(
        &mut self,
        sources: &Sources,
        state: &SyncStateV3,
        snapshot: FrozenSnapshot,
    ) -> Result<bool, AppError> {
        drop(self.validate(sources, state)?);
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let context = sources.progress_context(owner, &self.operation, &self.progress, None)?;
        if snapshot.context() != &context {
            return Err(invalid());
        }
        let chain = snapshot.checkpoint().chain_id.clone();
        let sequence = super::super::wire::number(&snapshot.checkpoint().sequence, true)?;
        let mut records = snapshot.into_records();
        // The frozen checkpoint commits to id_hash order. Equivalent transport ordering must
        // produce the same local continuation bytes after an interrupted cursor write.
        records.sort_by(|a, b| a.id_hash.cmp(&b.id_hash));
        let response = Response {
            chain: chain.clone(),
            sequence,
            records,
        };
        if let Some(previous) = self.responses.get(&chain) {
            if previous.sequence != response.sequence || previous.records != response.records {
                return Err(invalid());
            }
            return Ok(false);
        }
        if self.responses.len() >= MAX_SOURCES {
            return Err(invalid());
        }
        self.responses.insert(chain.clone(), response);
        if let Err(error) = self.validate(sources, state) {
            self.responses.remove(&chain);
            return Err(error);
        }
        Ok(true)
    }
    /// Freeze progress and an authenticated parent discovery can only add obligations.
    pub fn advance(
        &mut self,
        sources: &Sources,
        state: &SyncStateV3,
        progress: &Progress,
    ) -> Result<(), AppError> {
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let vault = owner
            .control
            .personal_vault
            .as_deref()
            .ok_or_else(invalid)?;
        let minimum = self.progress.verify(
            &owner.control.verified_chain()?,
            &self.operation,
            vault,
            None,
        )?;
        progress.verify(
            &owner.control.verified_chain()?,
            &self.operation,
            vault,
            Some(&minimum),
        )?;
        if !sources.follows_book(&self.keybook)? {
            return Err(invalid());
        }
        let context = sources.progress_context(owner, &self.operation, progress, Some(&minimum))?;
        if context.target != frozen::Target::current(owner)?
            || self.local_context != context.target.binding()?
        {
            return Err(invalid());
        }
        let old_progress = std::mem::replace(&mut self.progress, progress.clone());
        let old_book = std::mem::replace(&mut self.keybook, context.keybook);
        if let Err(error) = self.validate(sources, state) {
            self.progress = old_progress;
            self.keybook = old_book;
            return Err(error);
        }
        Ok(())
    }
    /// A protected journal may preserve or extend progress; it may never drop a completed input.
    pub fn require_after(
        &self,
        sources: &Sources,
        state: &SyncStateV3,
        previous: &Self,
    ) -> Result<(), AppError> {
        drop(self.validate(sources, state)?);
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let vault = owner
            .control
            .personal_vault
            .as_deref()
            .ok_or_else(invalid)?;
        let minimum = previous.progress.verify(
            &owner.control.verified_chain()?,
            &previous.operation,
            vault,
            None,
        )?;
        self.progress.verify(
            &owner.control.verified_chain()?,
            &self.operation,
            vault,
            Some(&minimum),
        )?;
        if self.operation != previous.operation
            || self.local_context != previous.local_context
            || !sources.follows_book(&previous.keybook)?
            || previous.responses.iter().any(|(chain, old)| {
                self.responses.get(chain).is_none_or(|next| {
                    old.chain != next.chain
                        || old.sequence != next.sequence
                        || old.records != next.records
                })
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn snapshot_for(
        &self,
        sources: &Sources,
        state: &SyncStateV3,
        chain: &str,
    ) -> Result<FrozenSnapshot, AppError> {
        self.validate(sources, state)?
            .into_iter()
            .find(|snapshot| snapshot.checkpoint().chain_id == chain)
            .ok_or_else(invalid)
    }
    pub fn discovered_sources(
        &self,
        sources: &Sources,
        state: &SyncStateV3,
    ) -> Result<Option<Sources>, AppError> {
        let snapshots = self.validate(sources, state)?;
        if sources.parent.is_empty() || sources.discovery.is_some() {
            return Ok(None);
        }
        let Some(parent) = snapshots
            .iter()
            .find(|snapshot| snapshot.checkpoint().chain_id == sources.parent)
        else {
            return Ok(None);
        };
        let copy = Sources::decode_local(&sources.encode_local()?, state)?;
        Ok(Some(copy.with_parent_discovery(
            state.local.central.as_ref().ok_or_else(invalid)?,
            parent,
        )?))
    }
    pub fn complete(self, sources: &Sources, state: &SyncStateV3) -> Result<FrozenSet, AppError> {
        let snapshots = self.validate(sources, state)?;
        FrozenSet::capture(
            state,
            sources,
            &self.operation,
            &self.progress,
            None,
            snapshots,
        )
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
        drop(value.validate(sources, state)?);
        Ok(value)
    }
}
#[cfg(test)]
mod tests;

mod delta;
