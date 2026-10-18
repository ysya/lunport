//! One bounded same-epoch pull. Data activation remains a separate typed readback publication.
use super::*;
use crate::sync::central::{
    api::VaultResource,
    library_page,
    rekey::{Checkpoint, Version},
    wire::number,
};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    records: Vec<Version>,
    sequence: String,
    history_hash: String,
    membership_head: String,
    epoch: u64,
    phase: String,
}
pub(in crate::sync::central) struct Report {
    pub staged: usize,
    pub more: bool,
    pub revalidate: bool,
}
fn check(
    env: &SyncEnv,
    context: &Context,
    session: &Arc<Session>,
) -> Result<(SyncStateV3, u64), AppError> {
    let (state, generation) = record_runtime::snapshot(env)?;
    context.verify(env, &state)?;
    fresh(session, &state)?;
    if context
        .session()
        .is_none_or(|selected| !Arc::ptr_eq(selected, session))
    {
        return Err(crate::sync::runtime::superseded());
    }
    Ok((state, generation))
}
fn with_transport(
    env: &SyncEnv,
    request: impl FnOnce(&Session, &str, u64) -> Result<Page, AppError>,
) -> Result<Report, AppError> {
    super::super::controller::require_enabled()?;
    let (context, session, vault, requested) = {
        let _life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        let (before, _) = record_runtime::snapshot(env)?;
        let session = super::super::controller::context(env)?;
        fresh(&session, &before)?;
        let context = Context::load(env, &before)?;
        let replica = before
            .local
            .central
            .as_ref()
            .ok_or_else(invalid)?
            .replica
            .as_ref()
            .ok_or_else(invalid)?;
        (
            context,
            session,
            replica.vault.clone(),
            replica.checkpoint.clone(),
        )
    };
    let (before_request, _) = check(env, &context, &session)?;
    if before_request
        .local
        .central
        .as_ref()
        .and_then(|o| o.replica.as_ref())
        .is_none_or(|r| r.vault != vault || r.checkpoint != requested)
    {
        return Err(crate::sync::runtime::superseded());
    }
    let page = request(&session, &vault, requested.sequence)?;
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (before, generation) = check(env, &context, &session)?;
    let owner = before.local.central.as_ref().ok_or_else(invalid)?;
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    if replica.vault != vault || replica.checkpoint != requested {
        return Err(crate::sync::runtime::superseded());
    }
    if page.records.len() > 32
        || page.epoch < requested.epoch
        || page.epoch > 65
        || !["ready", "rekey_pending"].contains(&page.phase.as_str())
        || !super::super::wire::hex(&page.membership_head, 64)
        || !super::super::wire::hex(&page.history_hash, 64)
        || number(&page.sequence, true)? > 16384
    {
        return Err(invalid());
    }
    let revalidate = page.epoch != requested.epoch
        || page.phase != "ready"
        || owner.control.highwater.as_ref().map(|h| h.head.as_str())
            != Some(page.membership_head.as_str());
    if revalidate {
        let mut candidate = before.clone();
        candidate
            .local
            .central
            .as_mut()
            .ok_or_else(invalid)?
            .control
            .phase = super::super::client_state::Phase::Rekey;
        let authority = Publication {
            before,
            candidate,
            generation,
            session,
            kind: Kind::Revalidate,
        };
        context.verify(env, &authority.before)?;
        record_runtime::publish_dispatch(env, &authority)?;
        drop(_publication);
        drop(_vault);
        drop(_life);
        env.events.status();
        return Ok(Report {
            staged: 0,
            more: false,
            revalidate: true,
        });
    }
    let advertised = Checkpoint {
        epoch: page.epoch,
        sequence: number(&page.sequence, true)?,
        history_hash: page.history_hash,
    };
    let captured = super::super::capture_public(&before, context.keys(), context.signer())?;
    let checked = library_page::prepare(
        captured.local.central.as_ref().ok_or_else(invalid)?,
        context.keys(),
        &page.records,
        &advertised,
    )?;
    let staged = checked
        .next
        .checkpoint
        .sequence
        .checked_sub(requested.sequence)
        .ok_or_else(invalid)? as usize;
    let more = checked.next.checkpoint.sequence < advertised.sequence;
    let mut candidate = captured;
    candidate
        .local
        .central
        .as_mut()
        .ok_or_else(invalid)?
        .replica = Some(checked.next);
    if candidate != before {
        let authority = Publication {
            before,
            candidate,
            generation,
            session,
            kind: Kind::Cipher,
        };
        context.verify(env, &authority.before)?;
        record_runtime::publish_dispatch(env, &authority)?;
    }
    drop(_publication);
    drop(_vault);
    drop(_life);
    env.events.status();
    Ok(Report {
        staged,
        more,
        revalidate: false,
    })
}
pub(in crate::sync::central) fn once(env: &SyncEnv) -> Result<Report, AppError> {
    with_reply(env, |session, vault, since| {
        Api::new(&session.profile.origin)?.vault(
            session.device.as_ref().ok_or_else(invalid)?,
            vault,
            VaultResource::Records { since },
        )
    })
}
pub(in crate::sync::central) fn with_reply(
    env: &SyncEnv,
    request: impl FnOnce(&Session, &str, u64) -> Result<Reply, AppError>,
) -> Result<Report, AppError> {
    with_transport(env, |session, vault, since| {
        let reply = request(session, vault, since)?;
        super::super::round::require_success(env, &reply)?;
        reply.decode()
    })
}
#[cfg(all(test, unix))]
mod tests;
