//! Normal same-epoch automatic publication through the existing protected staged-vault writer.
use super::*;
use crate::sync::{
    central::{credentials::Background, LibraryDelta},
    record_import::{self, central_stage},
};
pub(in crate::sync::central) struct Report {
    pub published: bool,
    pub keys: usize,
}
fn plan(env: &SyncEnv) -> Result<(Context, LibraryDelta), AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (before, generation) = record_runtime::snapshot(env)?;
    let session = super::super::controller::context(env)?;
    fresh(&session, &before)?;
    let context = Context::load(env, &before)?;
    if context
        .session()
        .is_none_or(|current| !Arc::ptr_eq(current, &session))
    {
        return Err(crate::sync::runtime::superseded());
    }
    let captured = super::super::capture_public(&before, context.keys(), context.signer())?;
    if captured != before {
        let authority = Publication {
            before,
            candidate: captured.clone(),
            generation,
            session,
            kind: Kind::Cipher,
        };
        context.verify(env, &authority.before)?;
        record_runtime::publish_dispatch(env, &authority)?;
    }
    let delta = LibraryDelta::prepare(&captured, context.keys(), env.now())?;
    Ok((context, delta))
}
pub(in crate::sync::central) fn once(env: &SyncEnv) -> Result<Report, AppError> {
    super::super::controller::require_enabled()?;
    let background = Background(env.keychain);
    let safe = SyncEnv {
        doc: env.doc,
        backed_up: env.backed_up,
        retention: env.retention,
        runtime: env.runtime,
        ssh_dir: env.ssh_dir.clone(),
        state_path: env.state_path.clone(),
        home: env.home.clone(),
        keychain: &background,
        relays: env.relays,
        events: env.events,
        clock: env.clock,
        platform: env.platform,
    };
    let pending = record_import::pending_imports(&safe)?;
    if pending.len() > 1
        || pending.iter().any(|p| {
            !matches!(
                p.phase.as_str(),
                "central_prepared" | "central_staged" | "central_vault_published"
            )
        })
    {
        return Err(AppError::Other("Finish the pending local import or recovery before automatic Vault publication; all data is retained.".into()));
    }
    let (context, delta) = plan(&safe)?;
    if !delta.has_changes() && pending.is_empty() {
        return Ok(Report {
            published: false,
            keys: 0,
        });
    }
    let staged = if let Some(pending) = pending.first() {
        central_stage::resume(&safe, &pending.import_id, &delta)?
    } else {
        central_stage::prepare(&safe, &delta)?
    };
    context.verify(&safe, &record_runtime::snapshot(&safe)?.0)?;
    let result = central_stage::publish(&safe, staged.operation(), context.keys())?;
    env.events.status();
    Ok(Report {
        published: true,
        keys: result.key_count,
    })
}
#[cfg(all(test, any(unix, windows)))]
mod tests;
