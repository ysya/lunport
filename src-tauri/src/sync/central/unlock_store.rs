//! Native encrypted account-unlock storage and authenticated readback.
use super::{
    api::{Api, Control},
    controller::Session,
    recovery::RecoveryKit,
    trust::VerifiedChain,
    unlock_credentials,
    unlock_envelope::{Binding, Envelope, Header},
    unlock_registry::{self, SignedRegistry, VerifiedRegistry},
    wire::invalid,
};
use crate::{error::AppError, sync::env::SyncEnv};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    registry: Option<SignedRegistry>,
}
pub(super) fn read(
    env: &SyncEnv,
    session: &Session,
    chain: &VerifiedChain,
) -> Result<Option<VerifiedRegistry>, AppError> {
    let profile = session.profile.profile()?;
    let anchor = chain.current().anchor();
    let minimum = unlock_credentials::minimum(env.keychain, &profile, anchor)?;
    let reply =
        Api::new(&profile.origin)?.unlock_registry(session.device.as_ref().ok_or_else(invalid)?)?;
    super::round::require_success(env, &reply)?;
    let reply: Reply = reply.decode()?;
    let verified = reply
        .registry
        .map(|r| r.verify(chain, minimum.as_ref()))
        .transpose()?;
    if verified.is_none() && minimum.is_some() {
        return Err(invalid());
    }
    if let Some(value) = &verified {
        unlock_credentials::remember(env.keychain, &profile, value)?;
    }
    Ok(verified)
}
pub(super) fn password(
    env: &SyncEnv,
    session: &Session,
    chain: &VerifiedChain,
    kit: &RecoveryKit,
    password: &str,
) -> Result<(), AppError> {
    if password.chars().count() < 12 || password.len() > 1024 {
        return Err(AppError::Other(
            "Use at least 12 characters for your sync unlock password.".into(),
        ));
    }
    kit.current_keys(chain)?;
    let previous = read(env, session, chain)?;
    let revision = previous
        .as_ref()
        .map_or(0, |p| p.highwater().revision)
        .checked_add(1)
        .ok_or_else(invalid)?;
    let binding = Binding::Password;
    let header = Header::new(chain.current().anchor().clone(), revision, binding.clone())?;
    let envelope = Envelope::seal_password(header, password, kit)?;
    let mut slots = previous
        .as_ref()
        .filter(|p| p.uses_current_authority(chain))
        .map(|p| {
            p.signed()
                .body
                .slots
                .iter()
                .filter(|e| e.header.binding != binding)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    slots.push(envelope.clone());
    slots.sort_by_key(|e| unlock_registry::slot_id(e).unwrap_or_default());
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let signed = SignedRegistry::create(
        chain,
        &identity.keys,
        &identity.id,
        session.device.as_ref().ok_or_else(invalid)?.auth_epoch,
        previous.as_ref(),
        slots,
    )?;
    let reply = Api::new(&session.profile.origin)?.control(
        session.device.as_ref().ok_or_else(invalid)?,
        Control::UpdateUnlock,
        &serde_json::json!({"registry":signed}),
    )?;
    super::round::require_success(env, &reply)?;
    // Read independently; an ACK/echo alone cannot justify deleting the temporary authority.
    let observed = read(env, session, chain)?.ok_or_else(invalid)?;
    if observed.signed() != &signed {
        return Err(invalid());
    }
    envelope
        .open_password(password, chain.current().anchor(), 1)?
        .current_keys(chain)?;
    Ok(())
}
