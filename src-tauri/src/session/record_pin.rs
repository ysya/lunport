//! Two-phase human-confirmed Records host-key persistence.
use super::{connect::CancelToken, directory::DirectoryError};
use crate::{
    error::AppError,
    ssh::{HopRef, HostKey},
    sync::{
        env::{Keychain, SyncEnv},
        record_repository as repo, record_round, record_runtime,
        records_v3::{HostScope, SyncStateV3},
    },
};

fn failed(error: impl std::fmt::Display) -> AppError {
    AppError::Other(error.to_string())
}
fn live(cancel: &CancelToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        Err(failed("The connection was cancelled."))
    } else {
        Ok(())
    }
}
/// Pure current-snapshot identity: scope, effective route, revisions and authoritative key metadata.
fn identity(
    state: &SyncStateV3,
    id: &str,
) -> Result<(Vec<repo::HostView>, Vec<repo::KeyView>), AppError> {
    let route = repo::resolve_host_chain(state, id).map_err(failed)?;
    let keys = route
        .iter()
        .filter_map(|host| host.effective_payload.key_id.as_deref())
        .map(|id| repo::resolve_key(state, id).map_err(failed))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((route, keys))
}

pub(crate) fn confirm(
    env: &SyncEnv,
    hop: &HopRef,
    previous: Option<&HostKey>,
    key: &HostKey,
    credentials: &dyn Keychain,
    cancel: &CancelToken,
    guard: &(dyn Fn() -> Result<(), DirectoryError> + Sync),
) -> Result<(), AppError> {
    live(cancel)?;
    let (captured, generation) = {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        record_round::preflight(env)?;
        record_runtime::snapshot(env)?
    };
    let host = repo::get_host(&captured, hop.id.as_str()).map_err(failed)?;
    if host.group_error.is_some()
        || host.effective_payload.hostname != hop.hostname
        || host.effective_payload.port != hop.port
    {
        return Err(failed("The confirmed endpoint changed; connect again."));
    }
    let expected = host.host.payload.host_key.as_ref();
    let current = expected
        .map(super::record_directory::pinned_key)
        .transpose()
        .map_err(failed)?;
    match current.as_ref().map(|p| &p.key) {
        Some(current) if current != key && previous != Some(current) => {
            return Err(failed("The confirmed host key changed; connect again."))
        }
        None if previous.is_some() => {
            return Err(failed("The confirmed host key changed; connect again."))
        }
        _ => {}
    }
    let approved = identity(&captured, hop.id.as_str())?;
    // Guards may resolve through FormatDirectory. All callbacks and external IO stay outside lifecycle.
    guard().map_err(failed)?;
    live(cancel)?;
    let prepared = if matches!(host.host.scope, HostScope::Space { .. }) {
        Some(record_round::prepare_account_gate(
            env,
            credentials,
            captured.clone(),
            generation,
        )?)
    } else {
        None
    };
    guard().map_err(failed)?;
    live(cancel)?;
    {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        record_round::require_no_pending_migration(env)?;
        let (current, current_generation) = record_runtime::snapshot(env)?;
        // Conservative: even an unrelated intervening generation requires new review/preparation.
        if current_generation != generation
            || current != captured
            || prepared
                .as_ref()
                .is_some_and(|p| p.generation != generation)
        {
            return Err(crate::sync::runtime::superseded());
        }
        live(cancel)?;
        if let Some(prepared) = prepared {
            record_round::publish_prepared_account_gate(env, prepared, Some(generation))?
                .ensure_compatible()?;
        }
        // Publication can change account availability/key authority. Re-read purely; no caller callbacks here.
        let _publication = env.runtime.format_publication.lock().unwrap();
        let (current, current_generation) = record_runtime::snapshot(env)?;
        if current.device_id != captured.device_id
            || current.relay_url != captured.relay_url
            || current.account.as_ref().map(|a| &a.chain_id)
                != captured.account.as_ref().map(|a| &a.chain_id)
            || identity(&current, hop.id.as_str())? != approved
        {
            return Err(failed("The confirmed route or key changed; connect again."));
        }
        let candidate = repo::pin_host_key(
            &current,
            hop.id.as_str(),
            &repo::HostEndpoint {
                hostname: hop.hostname.clone(),
                port: hop.port,
            },
            expected,
            super::record_directory::stored(key),
            env.now(),
        )
        .map_err(failed)?;
        live(cancel)?;
        record_runtime::commit_candidate(env, current_generation, candidate)?;
    }
    env.events.wake();
    Ok(())
}
