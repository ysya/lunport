//! Local trust cannot be reconstructed from a synchronized server pin.
use super::directory::DirectoryError;
use crate::{
    ssh::{HopRef, HostKey},
    sync::{
        record_repository as repo,
        records_v3::{CredentialApproval, HostScope, SyncStateV3, LOCAL_CREDENTIAL_STATE_VERSION},
    },
};

fn identity(
    state: &SyncStateV3,
    hop: &HopRef,
    key: &HostKey,
) -> Result<CredentialApproval, DirectoryError> {
    let host = repo::get_host(state, hop.id.as_str())
        .map_err(|e| DirectoryError::Failed(e.to_string()))?;
    let payload = &host.effective_payload;
    if host.group_error.is_some()
        || payload.hostname != hop.hostname
        || payload.port != hop.port
        || (!payload.user.is_empty() && payload.user != hop.user)
        || payload
            .host_key
            .as_ref()
            .map(|pin| pin.fingerprint.as_str())
            != Some(key.fingerprint.as_str())
    {
        return Err(DirectoryError::Failed(
            "The approved connection identity changed; connect again.".into(),
        ));
    }
    let shared = matches!(host.host.scope, HostScope::Space { .. });
    Ok(CredentialApproval {
        device_id: state.device_id.clone(),
        scope: host.host.scope,
        account_id: if shared {
            state.account.as_ref().map(|a| a.chain_id.clone())
        } else {
            None
        },
        relay_url: shared.then(|| state.relay_url.clone()),
        hostname: hop.hostname.clone(),
        port: hop.port,
        user: hop.user.clone(),
        fingerprint: key.fingerprint.clone(),
    })
}

pub(crate) fn matches(state: &SyncStateV3, hop: &HopRef, key: &HostKey) -> bool {
    identity(state, hop, key).ok().is_some_and(|expected| {
        state.local.credential_approvals.get(hop.id.as_str()) == Some(&expected)
    })
}

/// Called only by a locally confirmed pin transaction, never by merge/import.
pub(crate) fn approve(
    mut state: SyncStateV3,
    hop: &HopRef,
    key: &HostKey,
) -> Result<SyncStateV3, DirectoryError> {
    let approved = identity(&state, hop, key)?;
    state
        .local
        .credential_approvals
        .insert(hop.id.as_str().into(), approved);
    state.version = state.version.max(LOCAL_CREDENTIAL_STATE_VERSION);
    Ok(state)
}
