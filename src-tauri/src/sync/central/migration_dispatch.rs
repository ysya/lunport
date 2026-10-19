//! Consent-gated bounded migration transport. Verified results remain inert until initial publication.
use super::{
    api::{Api, Reply, VaultResource},
    controller::{self, Session},
    crypto::VaultKeys,
    migration_journal::{
        self,
        review::{self, Approval},
        Journal, Loaded,
    },
    migration_progress::Progress,
    migration_request::{self, Next, Request},
    migration_verify::Committed,
    payload::KeyStorage,
    request_budget::Budget,
    round, source_complete,
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use std::{collections::BTreeMap, sync::Arc};
pub(super) struct Verified {
    pub loaded: Loaded,
    pub committed: Committed,
    pub approval: Approval,
    pub generation: u64,
    pub session: Arc<Session>,
}
pub(super) enum Step {
    More,
    Verified(Verified),
}
enum Action<'a> {
    Status,
    Send(&'a Request),
    Readback(u64),
}
struct Prepared {
    loaded: Loaded,
    approval: Approval,
    generation: u64,
    session: Arc<Session>,
}
impl Prepared {
    fn current(&self, env: &SyncEnv, keys: &VaultKeys) -> Result<(), AppError> {
        source_complete::check(
            env,
            &self.loaded.package.state,
            self.generation,
            &self.session,
            keys,
        )?;
        self.approval.require_current(env, &self.loaded)?;
        self.loaded.require_unchanged(env)
    }
    fn before_http(&self, env: &SyncEnv, keys: &VaultKeys) -> Result<(), AppError> {
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        self.current(env, keys)?;
        let owner = self.loaded.plan.before();
        if super::source_cursor::Cursor::load(env, &life, owner)?
            .ok_or_else(invalid)?
            .cursor
            != self.loaded.cursor
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(())
    }
    fn save(self, env: &SyncEnv, keys: &VaultKeys, journal: Journal) -> Result<Step, AppError> {
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        self.current(env, keys)?;
        let owner = self.loaded.plan.before();
        let signer = &self.session.identity.as_ref().ok_or_else(invalid)?.keys;
        let next = journal.store(
            env,
            &life,
            owner,
            keys,
            signer,
            &self.loaded.cursor,
            self.loaded.cursor.receipt().next_ordinal()?,
        )?;
        source_complete::check(
            env,
            &self.loaded.package.state,
            self.generation,
            &self.session,
            keys,
        )?;
        self.approval.require_current(env, &next)?;
        next.require_unchanged(env)?;
        Ok(Step::More)
    }
}
fn prepare(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
) -> Result<Prepared, AppError> {
    let loaded = migration_journal::ensure(env, keys, references)?;
    let approval = review::accepted(env, &loaded)?;
    let (_, generation) = record_runtime::snapshot(env)?;
    let session = controller::context(env)?;
    let prepared = Prepared {
        loaded,
        approval,
        generation,
        session,
    };
    prepared.before_http(env, keys)?;
    Ok(prepared)
}
fn with_transport(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
    mut request: impl FnMut(&Session, &Loaded, Action<'_>) -> Result<Reply, AppError>,
) -> Result<Step, AppError> {
    let prepared = prepare(env, keys, references)?;
    // The complete runtime/vault/publication guard set was dropped before this callback.
    let status = request(&prepared.session, &prepared.loaded, Action::Status)?;
    prepared.before_http(env, keys)?;
    let observed = if status.status == 404 {
        None
    } else {
        round::require_success(env, &status)?;
        Some(Progress::from_reply(
            &status,
            &prepared.loaded.plan,
            prepared.loaded.progress(),
        )?)
    };
    match migration_request::next(
        &prepared.loaded.plan,
        prepared.loaded.progress(),
        observed.clone(),
    )? {
        Next::Persist(next) => {
            let journal = prepared
                .loaded
                .with_progress(next, prepared.loaded.plan.before())?
                .ok_or_else(invalid)?;
            prepared.save(env, keys, journal)
        }
        Next::Send(send) => {
            prepared.before_http(env, keys)?;
            let reply = request(&prepared.session, &prepared.loaded, Action::Send(&send))?;
            prepared.before_http(env, keys)?;
            round::require_success(env, &reply)?;
            let known = Progress::from_reply(&reply, &prepared.loaded.plan, observed.as_ref())?;
            if observed.as_ref() == Some(&known) {
                return Err(AppError::Other("The account service did not advance migration. The exact plan, source snapshots and saved progress are retained.".into()));
            }
            let journal = prepared
                .loaded
                .with_progress(known, prepared.loaded.plan.before())?
                .ok_or_else(invalid)?;
            prepared.save(env, keys, journal)
        }
        Next::VerifyCommitted => {
            let mut verifier = prepared.loaded.verifier(keys)?;
            if verifier.sequence() == prepared.loaded.plan.rows.len() as u64 {
                prepared.before_http(env, keys)?;
                let committed = verifier.finish(&prepared.loaded.plan, keys)?;
                return Ok(Step::Verified(Verified {
                    loaded: prepared.loaded,
                    committed,
                    approval: prepared.approval,
                    generation: prepared.generation,
                    session: prepared.session,
                }));
            }
            prepared.before_http(env, keys)?;
            let reply = request(
                &prepared.session,
                &prepared.loaded,
                Action::Readback(verifier.sequence()),
            )?;
            prepared.before_http(env, keys)?;
            round::require_success(env, &reply)?;
            verifier.admit_reply(&prepared.loaded.plan, keys, &reply)?;
            let journal = prepared
                .loaded
                .with_readback(&verifier, prepared.loaded.plan.before())?
                .ok_or_else(invalid)?;
            prepared.save(env, keys, journal)
        }
    }
}
pub(super) fn advance(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
    budget: &Budget,
) -> Result<Step, AppError> {
    round::check_cooldown(env)?;
    if !controller::resume_bounded(env, false, budget)? {
        return Err(invalid());
    }
    let mut renewed = false;
    loop {
        round::check_cooldown(env)?;
        if let Err(error) = budget.remaining() {
            return if Budget::exhausted(&error) {
                Ok(Step::More)
            } else {
                Err(error)
            };
        }
        let mut refused = false;
        let result = with_transport(env, keys, references, |session, loaded, action| {
            let api = Api::bounded(&session.profile.origin, budget)?;
            let grant = session.device.as_ref().ok_or_else(invalid)?;
            let vault = loaded
                .plan
                .before()
                .control
                .personal_vault
                .as_deref()
                .ok_or_else(invalid)?;
            let reply = match action {
                Action::Status => api.migration_status(grant, vault, false)?,
                Action::Send(send) => {
                    api.migration(grant, vault, send.action, send.body.clone())?
                }
                Action::Readback(since) => {
                    api.vault(grant, vault, VaultResource::Records { since })?
                }
            };
            refused = matches!(reply.status, 401 | 403);
            Ok(reply)
        });
        if refused && !renewed {
            renewed = true;
            if !controller::resume_bounded(env, true, budget)? {
                return Err(invalid());
            }
            continue;
        }
        match result {
            Ok(Step::More) => {}
            Ok(verified) => return Ok(verified),
            Err(error) if Budget::exhausted(&error) => return Ok(Step::More),
            Err(error) => return Err(error),
        }
    }
}
#[cfg(all(test, unix))]
pub(super) fn verified_for_test(env: &SyncEnv, keys: &VaultKeys) -> Verified {
    tests::verified(env, keys)
}
#[cfg(all(test, unix))]
pub(super) fn verified_fixture_for_test() -> (crate::sync::testkit::TestDevice, VaultKeys, Verified)
{
    tests::verified_fixture()
}
#[cfg(all(test,unix))]
pub(super) fn verified_material_fixture_for_test()->(crate::sync::testkit::TestDevice,VaultKeys,Verified){tests::material_verified_fixture()}
#[cfg(all(test, unix))]
mod tests;
