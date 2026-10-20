//! Bounded normal rounds for an already consented and durably cut-over library.
use super::{
    active_dispatch,
    api::{Api, VaultResource},
    controller,
    outbox::claims::PushReply,
    request_budget::Budget,
    round::{self, Report},
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
fn rekey_required() -> AppError {
    AppError::Other("Verified library reconciliation is required before this device can resume synchronization. Local edits and protected keys are retained.".into())
}
pub(super) fn run(env: &SyncEnv, report: &mut Report) -> Result<(), AppError> {
    let budget = Budget::new();
    let result = with_budget(env, report, &budget);
    report.requests += budget.used();
    match result {
        Err(error) if Budget::exhausted(&error) => {
            report.more = true;
            Ok(())
        }
        outcome => outcome,
    }
}
pub(super) fn with_budget(
    env: &SyncEnv,
    report: &mut Report,
    budget: &Budget,
) -> Result<(), AppError> {
    if !controller::resume_bounded(env, false, budget)? {
        return Ok(());
    }
    let mut renewed = false;
    loop {
        budget.remaining()?;
        let state = record_runtime::snapshot(env)?.0;
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        if !owner.control.cutover || !owner.can_upload() {
            return Err(rekey_required());
        }
        let mut refused = false;
        let pulled = active_dispatch::pull::with_reply(env, |session, vault, since| {
            let reply = Api::bounded(&session.profile.origin, budget)?.vault(
                session.device.as_ref().ok_or_else(invalid)?,
                vault,
                VaultResource::Records { since },
            )?;
            refused = matches!(reply.status, 401 | 403);
            Ok(reply)
        });
        if refused && !renewed {
            budget.remaining()?;
            renewed = true;
            if !controller::resume_bounded(env, true, budget)? {
                return Err(rekey_required());
            }
            continue;
        }
        let pulled = pulled?;
        report.staged += pulled.staged;
        report.more = pulled.more;
        if pulled.revalidate {
            return Err(rekey_required());
        }
        if pulled.more {
            continue;
        }
        budget.remaining()?;
        let cursor = env
            .runtime
            .core
            .lock()
            .unwrap()
            .central_poll
            .dispatch_cursor
            .clone();
        let batch = active_dispatch::prepare(env, cursor.as_deref())?;
        let Some(operation) = batch.operation else {
            // Complete authenticated history first; private dependencies can span several pages.
            let _ = active_dispatch::apply::once(env)?;
            report.more = false;
            return Ok(());
        };
        let reply = operation.push(env, budget)?;
        if matches!(reply.status, 401 | 403) && !renewed {
            budget.remaining()?;
            renewed = true;
            if !controller::resume_bounded(env, true, budget)? {
                return Err(rekey_required());
            }
            continue;
        }
        round::require_success(env, &reply)?;
        let claims: PushReply = reply.decode()?;
        operation.claims(env, &claims)?;
        env.runtime
            .core
            .lock()
            .unwrap()
            .central_poll
            .dispatch_cursor = batch.cursor;
        // A successful HTTP response is only a claim. Pull again before releasing dependencies,
        // clearing pending operations, projecting public records, or exposing received material.
        report.more = true;
    }
}
