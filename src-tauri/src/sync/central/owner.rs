//! A location inside the one authoritative Records Core. This is never a second runtime owner.
use super::{
    wire::{hex, invalid},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime, records_v3::SyncStateV3},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum OwnerPath {
    Current,
    Replacement(String),
}
impl OwnerPath {
    pub(super) fn get<'a>(&self, records: &'a SyncStateV3) -> Result<&'a Workspace, AppError> {
        let current = records.local.central.as_ref().ok_or_else(invalid)?;
        match self {
            Self::Current => Ok(current),
            Self::Replacement(operation) => {
                if !hex(operation, 32) {
                    return Err(invalid());
                }
                let intent = current.replacement.as_ref().ok_or_else(invalid)?;
                if &intent.operation != operation {
                    return Err(crate::sync::runtime::superseded());
                }
                intent.candidate.as_deref().ok_or_else(invalid)
            }
        }
    }
    pub(super) fn snapshot(&self, env: &SyncEnv) -> Result<Workspace, AppError> {
        Ok(self.get(&record_runtime::snapshot(env)?.0)?.clone())
    }
    /// Every mutation still passes the existing top-level and nested publication invariants.
    pub(super) fn publish(
        &self,
        env: &SyncEnv,
        before: &Workspace,
        after: &Workspace,
    ) -> Result<(), AppError> {
        record_runtime::mutate_records(env, |records| {
            if self.get(records)? != before {
                return Err(crate::sync::runtime::superseded());
            }
            let mut next = records.clone();
            match self {
                Self::Current => next.local.central = Some(after.clone()),
                Self::Replacement(operation) => {
                    let intent = next
                        .local
                        .central
                        .as_mut()
                        .ok_or_else(invalid)?
                        .replacement
                        .as_mut()
                        .ok_or_else(invalid)?;
                    if &intent.operation != operation {
                        return Err(crate::sync::runtime::superseded());
                    }
                    if intent.recovery_confirmation.is_none() {
                        if let (
                            Some(super::recovery_state::RecoveryState::Pending { package }),
                            Some(super::recovery_state::RecoveryState::Accepted {
                                admission, ..
                            }),
                        ) = (before.recovery.as_ref(), after.recovery.as_ref())
                        {
                            if !package.backup_confirmed
                                || !package.submitted
                                || &package.admission != admission
                            {
                                return Err(invalid());
                            }
                            intent.recovery_confirmation = Some(admission.clone());
                        }
                    }
                    intent.candidate = Some(Box::new(after.clone()));
                }
            }
            Ok(next)
        })?;
        Ok(())
    }
}
