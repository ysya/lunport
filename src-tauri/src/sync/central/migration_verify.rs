//! Readback of an exact committed initial plan. No Core, activation or cutover authority.
use super::{
    crypto::VaultKeys,
    migration_history::Plan,
    migration_progress::{Known, Phase},
    payload, projection,
    rekey::{Checkpoint, Version},
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    records: Vec<Version>,
    sequence: String,
    history_hash: String,
    membership_head: String,
    epoch: u64,
    phase: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prefix {
    version: u32,
    manifest: String,
    sequence: u64,
    history_hash: String,
}
pub(super) struct Verifier {
    manifest: String,
    working: Workspace,
}
pub(super) struct Committed {
    manifest: String,
    workspace: Workspace,
}
fn checkpoint(plan: &Plan) -> Result<Checkpoint, AppError> {
    let count = number(&plan.manifest.body.target_sequence, false)?;
    if count != plan.rows.len() as u64 {
        return Err(invalid());
    }
    Ok(Checkpoint {
        epoch: 1,
        sequence: count,
        history_hash: plan.manifest.body.target_history_hash.clone(),
    })
}
impl Prefix {
    pub(super) fn require_after(&self, plan: &Plan, previous: &Self) -> Result<(), AppError> {
        self.validate(plan)?;
        previous.validate(plan)?;
        if self.sequence < previous.sequence {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn validate(&self, plan: &Plan) -> Result<(), AppError> {
        let target = checkpoint(plan)?;
        if self.version != 1
            || self.manifest != plan.manifest.digest()?
            || self.sequence > target.sequence
        {
            return Err(invalid());
        }
        let expected = if self.sequence == 0 {
            "0000000000000000000000000000000000000000000000000000000000000000"
        } else {
            &plan.rows[self.sequence as usize - 1].history_hash
        };
        if self.history_hash != expected {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Verifier {
    pub fn new(plan: &Plan, retired: &Known) -> Result<Self, AppError> {
        retired.validate(plan)?;
        if retired.phase() != Phase::Retired {
            return Err(invalid());
        }
        let before = plan.before();
        before.validate()?;
        before.require_key_recipients()?;
        let chain = before.control.verified_chain()?;
        plan.manifest.verify(
            chain.current(),
            before.control.auth_epoch,
            1,
            &before.replica.as_ref().ok_or_else(invalid)?.vault,
            &before.control.device.id,
        )?;
        if before.control.cutover
            || before
                .replica
                .as_ref()
                .ok_or_else(invalid)?
                .checkpoint
                .sequence
                != 0
        {
            return Err(invalid());
        }
        Ok(Self {
            manifest: plan.manifest.digest()?,
            working: before.clone(),
        })
    }
    /// Only a prefix restored from protected journal metadata may be supplied by the driver.
    pub fn resume(
        plan: &Plan,
        retired: &Known,
        keys: &VaultKeys,
        prefix: &Prefix,
    ) -> Result<Self, AppError> {
        prefix.validate(plan)?;
        let mut result = Self::new(plan, retired)?;
        for rows in plan.rows[..prefix.sequence as usize].chunks(32) {
            result.rows(plan, keys, rows)?;
        }
        if result.snapshot(plan)? != *prefix {
            return Err(invalid());
        }
        Ok(result)
    }
    pub fn sequence(&self) -> u64 {
        self.working
            .replica
            .as_ref()
            .map_or(0, |r| r.checkpoint.sequence)
    }
    pub fn snapshot(&self, plan: &Plan) -> Result<Prefix, AppError> {
        if self.manifest != plan.manifest.digest()? {
            return Err(invalid());
        }
        let current = &self
            .working
            .replica
            .as_ref()
            .ok_or_else(invalid)?
            .checkpoint;
        let result = Prefix {
            version: 1,
            manifest: self.manifest.clone(),
            sequence: current.sequence,
            history_hash: current.history_hash.clone(),
        };
        result.validate(plan)?;
        Ok(result)
    }
    pub fn admit_reply(
        &mut self,
        plan: &Plan,
        keys: &VaultKeys,
        reply: &super::api::Reply,
    ) -> Result<(), AppError> {
        if reply.status != 200 {
            reply.success()?;
            return Err(invalid());
        }
        self.admit(plan, keys, reply.decode::<Page>()?)
    }
    pub fn admit(&mut self, plan: &Plan, keys: &VaultKeys, page: Page) -> Result<(), AppError> {
        let target = checkpoint(plan)?;
        if page.epoch != 1
            || number(&page.sequence, false)? != target.sequence
            || page.history_hash != target.history_hash
            || page.phase != "ready"
            || page.membership_head
                != plan
                    .before()
                    .control
                    .highwater
                    .as_ref()
                    .ok_or_else(invalid)?
                    .head
        {
            return Err(invalid());
        }
        self.rows(plan, keys, &page.records)
    }
    fn rows(&mut self, plan: &Plan, keys: &VaultKeys, rows: &[Version]) -> Result<(), AppError> {
        let start = usize::try_from(self.sequence()).map_err(|_| invalid())?;
        let end = start.checked_add(rows.len()).ok_or_else(invalid)?;
        if self.manifest != plan.manifest.digest()?
            || rows.is_empty()
            || rows.len() > 32
            || plan.rows.get(start..end) != Some(rows)
        {
            return Err(invalid());
        }
        let chain = self.working.control.verified_chain()?;
        let target = checkpoint(plan)?;
        let page = self
            .working
            .replica
            .as_ref()
            .ok_or_else(invalid)?
            .prepare_page(&chain, keys, rows, &target)?;
        for opened in page.opened {
            payload::admit(keys, &opened.version.envelope.header, &opened.plaintext)?;
        }
        self.working.replica = Some(page.next);
        Ok(())
    }
    pub fn finish(self, plan: &Plan, keys: &VaultKeys) -> Result<Committed, AppError> {
        if self.manifest != plan.manifest.digest()?
            || self
                .working
                .replica
                .as_ref()
                .ok_or_else(invalid)?
                .checkpoint
                != checkpoint(plan)?
            || !projection::Plan::inventory(self.working.clone(), keys)?.complete()
        {
            return Err(invalid());
        }
        Ok(Committed {
            manifest: self.manifest,
            workspace: self.working,
        })
    }
}
impl Committed {
    pub fn workspace(&self) -> &Workspace {
        &self.workspace
    }
    pub fn manifest(&self) -> &str {
        &self.manifest
    }
}

#[cfg(test)]
mod tests;
