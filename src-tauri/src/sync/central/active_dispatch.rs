//! Durable native ciphertext dispatch, restricted to a trusted cut-over library.
use super::{
    api::{Api, DeviceState, Reply},
    controller::Session,
    crypto::{DeviceKeys, RecordEnvelope, VaultKeys},
    outbox::{self, claims::PushReply},
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{
        env::SyncEnv, record_import::central_local::Context, record_runtime,
        records_v3::SyncStateV3, runtime::SyncCore,
    },
};
use std::{path::Path, sync::Arc, time::Duration};
fn fresh(session: &Session, state: &SyncStateV3) -> Result<(), AppError> {
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let device = session.device.as_ref().ok_or_else(invalid)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let profile = owner.control.profile.profile()?;
    if !owner.control.cutover
        || !owner.can_upload()
        || session.profile != owner.control.profile
        || session.tokens.issuer != session.profile.issuer
        || session.tokens.subject != session.profile.subject
        || session.device_access_denied
        || device.expired()
        || device.device_state != DeviceState::Active
        || device.account_id != owner.control.account_id
        || device.auth_epoch != owner.control.auth_epoch
        || session
            .tokens_started
            .elapsed()
            .saturating_add(Duration::from_secs(5))
            >= session.tokens.expires_in
        || identity.device() != owner.control.device
        || identity.slot(&profile, "device")?
            != profile.device_slot("device", owner.identity_slot.as_deref())?
    {
        return Err(invalid());
    }
    Ok(())
}
/// Constructed only from actual protected selection and a pure validated candidate below.
/// It cannot change ledger, material pointers or public Records cache.
enum Kind {
    Cipher,
    Revalidate,
}
pub(crate) struct Publication {
    before: SyncStateV3,
    candidate: SyncStateV3,
    generation: u64,
    session: Arc<Session>,
    kind: Kind,
}
impl Publication {
    pub(crate) fn candidate(&self) -> &SyncStateV3 {
        &self.candidate
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn verify_core(&self, core: &SyncCore) -> Result<(), AppError> {
        if core.generation != self.generation
            || core
                .central_session
                .as_ref()
                .is_none_or(|s| !Arc::ptr_eq(s, &self.session))
        {
            return Err(crate::sync::runtime::superseded());
        }
        self.verify_records(
            record_runtime::active_state(core)?,
            &self.candidate,
            self.generation,
        )
    }
    pub(crate) fn verify_records(
        &self,
        before: &SyncStateV3,
        candidate: &SyncStateV3,
        generation: u64,
    ) -> Result<(), AppError> {
        if before != &self.before || candidate != &self.candidate || generation != self.generation {
            return Err(crate::sync::runtime::superseded());
        }
        let mut expected = before.clone();
        expected.local.central = candidate.local.central.clone();
        if &expected != candidate {
            return Err(invalid());
        }
        match self.kind {
            Kind::Cipher => {
                if before.local.central.as_ref().map(|o| &o.control)
                    != candidate.local.central.as_ref().map(|o| &o.control)
                {
                    return Err(invalid());
                }
            }
            Kind::Revalidate => {
                let mut notice = before.clone();
                notice
                    .local
                    .central
                    .as_mut()
                    .ok_or_else(invalid)?
                    .control
                    .phase = super::client_state::Phase::Rekey;
                if &notice != candidate {
                    return Err(invalid());
                }
            }
        }
        fresh(&self.session, before)?;
        super::workspace::verify_publication(
            before.local.central.as_ref(),
            candidate.local.central.as_ref(),
        )?;
        crate::sync::records_v3::validate_state(candidate).map_err(|_| invalid())
    }
    /// No vault/material publication is possible through this ciphertext-only authority.
    pub(crate) fn verify_vault(&self, _: &Path) -> Result<(), AppError> {
        Ok(())
    }
}
pub(super) struct Batch {
    pub operation: Option<Operation>,
    pub waiting_private: usize,
    pub ready_remaining: usize,
    pub cursor: Option<String>,
}
/// No Clone/Serialize/Debug. Exact ciphertext/operation is already durable when this is returned.
pub(super) struct Operation {
    context: Context,
    session: Arc<Session>,
    records: Vec<RecordEnvelope>,
    vault: String,
}
impl Operation {
    fn check(&self, env: &SyncEnv) -> Result<SyncStateV3, AppError> {
        let (state, generation) = record_runtime::snapshot(env)?;
        self.context.verify(env, &state)?;
        fresh(&self.session, &state)?;
        let replica = state
            .local
            .central
            .as_ref()
            .ok_or_else(invalid)?
            .replica
            .as_ref()
            .ok_or_else(invalid)?;
        if replica.vault != self.vault
            || self.records.is_empty()
            || self.records.iter().any(|row| {
                replica
                    .pending
                    .get(&row.header.record_id)
                    .and_then(|p| p.sent.as_ref())
                    .is_none_or(|sent| &sent.envelope != row)
            })
        {
            return Err(crate::sync::runtime::superseded());
        }
        let saved = record_runtime::read_saved_records(&env.state_path)?;
        fresh(&self.session, &saved)?;
        let saved_replica = saved
            .local
            .central
            .as_ref()
            .ok_or_else(invalid)?
            .replica
            .as_ref()
            .ok_or_else(invalid)?;
        if saved_replica.vault != self.vault
            || saved.local.central.as_ref().map(|o| &o.control)
                != state.local.central.as_ref().map(|o| &o.control)
            || self.records.iter().any(|row| {
                saved_replica
                    .pending
                    .get(&row.header.record_id)
                    .and_then(|p| p.sent.as_ref())
                    .is_none_or(|sent| &sent.envelope != row)
            })
        {
            return Err(crate::sync::runtime::superseded());
        }
        // Re-evaluate later edits without publishing their ephemeral capture. Only this operation's
        // already durable sent bytes may reach transport; a later deletion/material change blocks it.
        let captured = super::capture_public(&state, self.context.keys(), self.context.signer())?;
        let allowed = outbox::prepare_exact(
            &captured,
            self.context.keys(),
            self.context.signer(),
            &self.records,
        )?;
        if self
            .records
            .iter()
            .any(|row| !allowed.records.iter().any(|ready| ready == row))
        {
            return Err(crate::sync::runtime::superseded());
        }
        {
            let core = env.runtime.core.lock().unwrap();
            if core.generation != generation
                || core.save_blocked.is_some()
                || core
                    .central_session
                    .as_ref()
                    .is_none_or(|session| !Arc::ptr_eq(session, &self.session))
            {
                return Err(crate::sync::runtime::superseded());
            }
            fresh(&self.session, record_runtime::active_state(&core)?)?;
        }
        Ok(state)
    }
    fn with_transport<T>(
        &self,
        env: &SyncEnv,
        send: impl FnOnce(&super::api::DeviceSession, &str, &[RecordEnvelope]) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        self.check(env)?;
        let response = send(
            self.session.device.as_ref().ok_or_else(invalid)?,
            &self.vault,
            &self.records,
        )?;
        self.check(env)?;
        Ok(response)
    }
    pub(super) fn push(
        &self,
        env: &SyncEnv,
        budget: &super::request_budget::Budget,
    ) -> Result<Reply, AppError> {
        self.with_transport(env, |device, vault, records| {
            let api=Api::bounded(&self.session.profile.origin, budget)?;
            if records.iter().any(|r|r.header.kind=="password")
                && !api.info()?.features.iter().any(|f|f=="ssh-password-sync-v1") {
                return Err(AppError::Other("Update your sync server to enable encrypted SSH password sync. Local changes are retained.".into()));
            }
            api.push(device, vault, records)
        })
    }
    pub fn claims(&self, env: &SyncEnv, reply: &PushReply) -> Result<(), AppError> {
        let _life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        self.check(env)?;
        let (before, generation) = record_runtime::snapshot(env)?;
        let mut candidate = before.clone();
        candidate.local.central = Some(outbox::claims::candidate(
            before.local.central.as_ref().ok_or_else(invalid)?,
            &self.records,
            reply,
        )?);
        let authority = Publication {
            before,
            candidate,
            generation,
            session: Arc::clone(&self.session),
            kind: Kind::Cipher,
        };
        self.context.verify(env, &authority.before)?;
        record_runtime::publish_dispatch(env, &authority)?;
        drop(_publication);
        drop(_vault);
        drop(_life);
        env.events.status();
        Ok(())
    }
}
/// The publish step (design 2026-10-26, Existing routes move in; R64a): the routes saved on this device alone that the library takes
/// become its rows by an ordinary save of their own (they change the library's rows, which this dispatch's own publication never does),
/// so that the capture after it publishes them. It waits while a Catalog captured now would conflict with the library's: until the
/// latest Catalog the pull staged is read into this device's rows, which the round that staged it does at its end, and while the
/// Catalog is in conflict (`projection_capture::move_local_routes`). A library that takes no edit, its writes blocked or frozen for an
/// encrypted migration, takes none either. Whether it saved.
fn publish_local_routes(env: &SyncEnv, state: &SyncStateV3, keys: &VaultKeys) -> Result<bool, AppError> {
    let now = env.now();
    if super::projection_capture::move_local_routes(state, keys, now)?.is_none() {
        return Ok(false);
    }
    super::migration_flow::refresh_edit_gate(env)?;
    if env.runtime.core.lock().unwrap().central_migration_frozen {
        return Ok(false);
    }
    record_runtime::mutate_records(env, |latest| {
        Ok(super::projection_capture::move_local_routes(latest, keys, now)?.unwrap_or_else(|| latest.clone()))
    })?;
    Ok(true)
}
/// The automatic merge (design 2026-10-27, Catalog conflicts keep both devices' changes): a Catalog conflict whose two versions change
/// different items is merged into this device's rows and draft by an ordinary save of its own, as the publish step saves, so that the
/// capture after it publishes the merged Catalog (`catalog_conflict::merge_automatically`). Under the publish step's gates: a library
/// frozen for an encrypted migration, or whose writes are blocked, takes none, and the conflict waits. Whether it saved.
fn merge_catalog(env: &SyncEnv, state: &SyncStateV3, keys: &VaultKeys, signer: &DeviceKeys) -> Result<bool, AppError> {
    let now = env.now();
    if super::catalog_conflict::merge_automatically(state, keys, signer, now)?.is_none() {
        return Ok(false);
    }
    super::migration_flow::refresh_edit_gate(env)?;
    if env.runtime.core.lock().unwrap().central_migration_frozen {
        return Ok(false);
    }
    record_runtime::mutate_records(env, |latest| {
        Ok(super::catalog_conflict::merge_automatically(latest, keys, signer, now)?.map_or_else(|| latest.clone(), |next| *next))
    })?;
    Ok(true)
}
pub(super) fn prepare(env: &SyncEnv, after: Option<&str>) -> Result<Batch, AppError> {
    super::controller::require_enabled()?;
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (before, generation) = record_runtime::snapshot(env)?;
    let session = super::controller::context(env)?;
    fresh(&session, &before)?;
    let context = Context::load(env, &before)?;
    if context.session().is_none_or(|s| !Arc::ptr_eq(s, &session)) {
        return Err(crate::sync::runtime::superseded());
    }
    let (before, generation) = if merge_catalog(env, &before, context.keys(), context.signer())? {
        let (before, generation) = record_runtime::snapshot(env)?;
        fresh(&session, &before)?;
        (before, generation)
    } else {
        (before, generation)
    };
    let (before, generation) = if publish_local_routes(env, &before, context.keys())? {
        let (before, generation) = record_runtime::snapshot(env)?;
        fresh(&session, &before)?;
        (before, generation)
    } else {
        (before, generation)
    };
    let adopted = super::passwords::adopt_saved(env, &before, context.keys(), context.signer())?;
    let captured = super::capture_public(&adopted, context.keys(), context.signer())?;
    let prepared = outbox::prepare(&captured, context.keys(), context.signer(), after)?;
    let mut candidate = captured;
    let vault = prepared
        .owner
        .replica
        .as_ref()
        .ok_or_else(invalid)?
        .vault
        .clone();
    candidate.local.central = Some(prepared.owner);
    if candidate != before {
        let authority = Publication {
            before,
            candidate,
            generation,
            session: Arc::clone(&session),
            kind: Kind::Cipher,
        };
        context.verify(env, &authority.before)?;
        record_runtime::publish_dispatch(env, &authority)?;
    }
    let operation = (!prepared.records.is_empty()).then_some(Operation {
        context,
        session,
        records: prepared.records,
        vault,
    });
    Ok(Batch {
        operation,
        waiting_private: prepared.waiting_private,
        ready_remaining: prepared.ready_remaining,
        cursor: prepared.cursor,
    })
}
pub(super) mod apply;
pub(super) mod pull;
#[cfg(all(test, any(unix, windows)))]
mod tests;
