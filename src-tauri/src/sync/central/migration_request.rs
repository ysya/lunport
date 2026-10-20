//! Pure private-ingress request preparation. No consent, HTTP, live authority or publication.
use super::{
    api::MigrationAction,
    migration_history::Plan,
    migration_progress::{Known, Phase},
    wire::invalid,
};
use crate::error::AppError;
use serde::Serialize;
use zeroize::Zeroizing;
pub(super) struct Request {
    pub action: MigrationAction,
    pub body: Zeroizing<Vec<u8>>,
}
pub(super) enum Next {
    Persist(Known),
    Send(Request),
    VerifyCommitted,
}
fn body(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, value).map_err(|_| invalid())?;
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok(bytes)
}
pub(super) fn next(
    plan: &Plan,
    saved: Option<&Known>,
    observed: Option<Known>,
) -> Result<Next, AppError> {
    let Some(observed) = observed else {
        if saved.is_some() {
            return Err(AppError::Other("The saved migration is missing from the account service. Original sources and progress are retained.".into()));
        }
        #[derive(Serialize)]
        struct Begin<'a> {
            manifest: &'a super::migration::SignedMigration,
            wraps: &'a [super::crypto::WrappedKeys],
        }
        return Ok(Next::Send(Request {
            action: MigrationAction::Begin,
            body: body(&Begin {
                manifest: &plan.manifest,
                wraps: &plan.wraps,
            })?,
        }));
    };
    observed.validate(plan)?;
    if let Some(minimum) = saved {
        observed.require_after(plan, minimum)?;
    }
    if saved != Some(&observed) {
        return Ok(Next::Persist(observed));
    }
    #[derive(Serialize)]
    struct Operation<'a> {
        migration: &'a str,
    }
    let operation = Operation {
        migration: &plan.manifest.body.migration_id,
    };
    let (action, bytes) = match observed.phase() {
        Phase::Staging => {
            if let Some(rows) = observed.next_batch(plan)? {
                #[derive(Serialize)]
                struct Stage<'a> {
                    migration: &'a str,
                    after: String,
                    rows: Vec<&'a super::crypto::RecordEnvelope>,
                }
                let request = Stage {
                    migration: operation.migration,
                    after: observed.staged().to_string(),
                    rows: rows.iter().map(|row| &row.envelope).collect(),
                };
                (MigrationAction::Stage, body(&request)?)
            } else {
                (MigrationAction::Commit, body(&operation)?)
            }
        }
        Phase::Committed => (MigrationAction::Retire, body(&operation)?),
        Phase::Retired => return Ok(Next::VerifyCommitted),
    };
    Ok(Next::Send(Request {
        action,
        body: bytes,
    }))
}

#[cfg(test)]
mod tests;
