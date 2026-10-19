//! Native status consistency against one immutable plan; not consent or cutover authority.
use super::{
    migration::SignedMigration,
    migration_history::Plan,
    wire::{invalid, number},
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Staging,
    Committed,
    Retired,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Progress {
    manifest: SignedMigration,
    manifest_digest: String,
    phase: Phase,
    staged: String,
    history_hash: String,
    retired: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Known {
    version: u32,
    digest: String,
    phase: Phase,
    staged: u64,
    retired: u64,
}
impl Known {
    fn validate(&self, plan: &Plan) -> Result<(), AppError> {
        let count = plan.rows.len() as u64;
        let sources = plan.manifest.body.sources.len() as u64;
        if self.version != 1
            || self.digest != plan.manifest.digest()?
            || self.staged > count
            || self.retired > sources
            || number(&plan.manifest.body.target_sequence, false)? != count
            || plan
                .rows
                .last()
                .is_none_or(|row| row.history_hash != plan.manifest.body.target_history_hash)
            || match self.phase {
                Phase::Staging => self.retired != 0,
                Phase::Committed => self.staged != count || self.retired >= sources,
                Phase::Retired => self.staged != count || self.retired != sources,
            }
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn staged(&self) -> u64 {
        self.staged
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn retired(&self) -> u64 {
        self.retired
    }
    pub fn next_batch<'a>(
        &self,
        plan: &'a Plan,
    ) -> Result<Option<&'a [super::rekey::Version]>, AppError> {
        self.validate(plan)?;
        if self.phase != Phase::Staging {
            return Ok(None);
        }
        plan.next_batch(self.staged)
    }
}
impl Progress {
    pub fn from_reply(
        reply: &super::api::Reply,
        plan: &Plan,
        minimum: Option<&Known>,
    ) -> Result<Known, AppError> {
        if reply.status != 200 {
            reply.success()?;
            return Err(invalid());
        }
        reply.decode::<Self>()?.verify(plan, minimum)
    }
    pub fn verify(&self, plan: &Plan, minimum: Option<&Known>) -> Result<Known, AppError> {
        let before = plan.before();
        before.validate()?;
        let chain = before.control.verified_chain()?;
        plan.manifest.verify(
            chain.current(),
            before.control.auth_epoch,
            1,
            &before.replica.as_ref().ok_or_else(invalid)?.vault,
            &before.control.device.id,
        )?;
        if self.manifest != plan.manifest || self.manifest_digest != plan.manifest.digest()? {
            return Err(invalid());
        }
        let result = Known {
            version: 1,
            digest: self.manifest_digest.clone(),
            phase: self.phase,
            staged: number(&self.staged, true)?,
            retired: number(&self.retired, true)?,
        };
        result.validate(plan)?;
        let hash = if result.staged == 0 {
            "0000000000000000000000000000000000000000000000000000000000000000"
        } else {
            &plan.rows[result.staged as usize - 1].history_hash
        };
        if self.history_hash != hash {
            return Err(invalid());
        }
        if let Some(minimum) = minimum {
            minimum.validate(plan)?;
            if result.phase < minimum.phase
                || result.staged < minimum.staged
                || result.retired < minimum.retired
            {
                return Err(invalid());
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
