//! Bounded continuation of an explicitly started source capture; never library publication.
use super::{
    api::Api,
    capture_journal::{Journal, Loaded},
    controller::{self, Session},
    crypto::VaultKeys,
    migration_freeze::{Phase, Progress},
    migration_sources::Sources,
    request_budget::Budget,
    round, source_capture,
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime, relay::PullResponse},
};
use std::sync::Arc;
enum Action {
    Freeze { sources: Sources, next: Vec<String> },
    Fetch(String),
    Discover(Sources),
    Ready,
}
enum Received {
    Freeze(Progress),
    Fetch(PullResponse),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    More,
    Ready,
}
fn action(loaded: &Loaded) -> Result<Action, AppError> {
    if let Some(fetching) = loaded.fetching() {
        if !loaded.pending_discovery() {
            if let Some(discovered) =
                fetching.discovered_sources(&loaded.package.sources, &loaded.package.state)?
            {
                return Ok(Action::Discover(discovered));
            }
            if let Some(chain) =
                fetching.next_source(&loaded.package.sources, &loaded.package.state)?
            {
                return Ok(Action::Fetch(chain));
            }
            if fetching.progress().phase == Phase::Frozen {
                return Ok(Action::Ready);
            }
        }
    }
    let next = loaded
        .intent()
        .body
        .source_order()
        .into_iter()
        .filter(|chain| {
            loaded.fetching().is_none_or(|fetching| {
                !fetching
                    .progress()
                    .sources
                    .iter()
                    .any(|source| source.chain_id == **chain)
            })
        })
        .take(8)
        .map(str::to_owned)
        .collect();
    Ok(Action::Freeze {
        sources: loaded.effective_sources()?,
        next,
    })
}
pub(super) fn ready(loaded: &Loaded) -> Result<bool, AppError> {
    Ok(matches!(action(loaded)?, Action::Ready))
}
struct Prepared {
    loaded: Loaded,
    generation: u64,
    session: Arc<Session>,
}
impl Prepared {
    fn identity_current(&self, env: &SyncEnv, keys: &VaultKeys) -> Result<(), AppError> {
        let (state, generation) = record_runtime::snapshot(env)?;
        if generation != self.generation
            || state != self.loaded.package.state
            || !Arc::ptr_eq(&controller::context(env)?, &self.session)
        {
            return Err(crate::sync::runtime::superseded());
        }
        source_capture::require_target(
            env,
            state.local.central.as_ref().ok_or_else(invalid)?,
            &self.session,
            keys,
        )?;
        Ok(())
    }
    fn current(&self, env: &SyncEnv, keys: &VaultKeys) -> Result<(), AppError> {
        self.identity_current(env, keys)?;
        self.loaded.require_unchanged(env)
    }
    fn recover_pending(
        &self,
        env: &SyncEnv,
        life: &std::sync::MutexGuard<'_, ()>,
        keys: &VaultKeys,
    ) -> Result<Option<Loaded>, AppError> {
        self.identity_current(env, keys)?;
        let owner = self
            .loaded
            .package
            .state
            .local
            .central
            .as_ref()
            .ok_or_else(invalid)?;
        let Some(bytes) = super::source_archive::candidate_next(
            env,
            owner,
            self.loaded.cursor.receipt(),
            self.loaded.cursor.receipt().next_ordinal()?,
            &self.loaded.outputs,
        )?
        else {
            return Ok(None);
        };
        let signer = &self.session.identity.as_ref().ok_or_else(invalid)?.keys;
        // Derive the exact one-step successor again; AEAD by itself is not admission.
        let expected = match action(&self.loaded)? {
            Action::Ready => return Err(invalid()),
            Action::Discover(sources) => self.loaded.with_discovery(owner, signer, sources)?,
            Action::Fetch(chain) => self.loaded.with_snapshot(
                owner,
                Journal::pending_snapshot(
                    &bytes,
                    &self.loaded.package.sources,
                    &self.loaded.package.state,
                    &chain,
                )?,
            )?,
            Action::Freeze { .. } => {
                let progress = Journal::pending_progress(&bytes)?;
                if !self.loaded.pending_discovery()
                    && self
                        .loaded
                        .fetching()
                        .is_some_and(|f| f.progress() == &progress)
                {
                    return Err(invalid());
                }
                self.loaded.with_progress(owner, &progress)?
            }
        };
        if !expected.matches_bytes(&bytes)? {
            return Err(invalid());
        }
        self.identity_current(env, keys)?;
        Ok(Some(expected.store(
            env,
            life,
            owner,
            signer,
            &self.loaded.cursor,
            self.loaded.cursor.receipt().next_ordinal()?,
        )?))
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
        let owner = self
            .loaded
            .package
            .state
            .local
            .central
            .as_ref()
            .ok_or_else(invalid)?;
        let signer = &self.session.identity.as_ref().ok_or_else(invalid)?.keys;
        let saved = journal.store(
            env,
            &life,
            owner,
            signer,
            &self.loaded.cursor,
            self.loaded.cursor.receipt().next_ordinal()?,
        )?;
        saved.require_unchanged(env)?;
        // The write cannot grant transport/publication authority after a concurrent Core change.
        let (state, generation) = record_runtime::snapshot(env)?;
        if state != self.loaded.package.state
            || generation != self.generation
            || !Arc::ptr_eq(&controller::context(env)?, &self.session)
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(Step::More)
    }
}
fn with_transport(
    env: &SyncEnv,
    keys: &VaultKeys,
    request: impl FnOnce(&Session, &Loaded, &Action) -> Result<Received, AppError>,
) -> Result<Step, AppError> {
    controller::require_enabled()?;
    let prepared = {
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        let (state, generation) = record_runtime::snapshot(env)?;
        let session = controller::context(env)?;
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        source_capture::require_target(env, owner, &session, keys)?;
        let signer = &session.identity.as_ref().ok_or_else(invalid)?.keys;
        let loaded = Journal::load(env, &life, owner, signer)?.ok_or_else(invalid)?;
        let prepared = Prepared {
            loaded,
            generation,
            session,
        };
        if let Some(loaded) = prepared.recover_pending(env, &life, keys)? {
            let recovered = Prepared {
                loaded,
                generation: prepared.generation,
                session: Arc::clone(&prepared.session),
            };
            recovered.current(env, keys)?;
            return Ok(Step::More);
        }
        prepared.current(env, keys)?;
        prepared
    };
    let selected = action(&prepared.loaded)?;
    let owner = prepared
        .loaded
        .package
        .state
        .local
        .central
        .as_ref()
        .ok_or_else(invalid)?;
    let signer = &prepared.session.identity.as_ref().ok_or_else(invalid)?.keys;
    match selected {
        Action::Ready => {
            prepared.current(env, keys)?;
            Ok(Step::Ready)
        }
        Action::Discover(sources) => {
            let journal = prepared.loaded.with_discovery(owner, signer, sources)?;
            prepared.save(env, keys, journal)
        }
        selected => {
            // No runtime, publication or vault lock crosses HTTP.
            prepared.current(env, keys)?;
            let received = request(&prepared.session, &prepared.loaded, &selected)?;
            let journal = match (&selected, received) {
                (Action::Freeze { .. }, Received::Freeze(progress)) => {
                    if !prepared.loaded.pending_discovery()
                        && prepared
                            .loaded
                            .fetching()
                            .is_some_and(|fetching| fetching.progress() == &progress)
                    {
                        return Err(AppError::Other("The account service did not advance source freezing. Saved progress and original files are retained.".into()));
                    }
                    prepared.loaded.with_progress(owner, &progress)?
                }
                (Action::Fetch(chain), Received::Fetch(response)) => {
                    let fetching = prepared.loaded.fetching().ok_or_else(invalid)?;
                    let snapshot = prepared.loaded.package.sources.admit_frozen(
                        owner,
                        &prepared.loaded.intent().body.migration_id,
                        fetching.progress(),
                        None,
                        chain,
                        response,
                    )?;
                    prepared.loaded.with_snapshot(owner, snapshot)?
                }
                _ => return Err(invalid()),
            };
            prepared.save(env, keys, journal)
        }
    }
}
/// Resumes only an existing protected capture journal. New sources require explicit foreground start.
pub(super) fn advance(env: &SyncEnv, keys: &VaultKeys, budget: &Budget) -> Result<Step, AppError> {
    round::check_cooldown(env)?;
    if !controller::resume_bounded(env, false, budget)? {
        return Err(invalid());
    }
    let mut renewed = false;
    loop {
        round::check_cooldown(env)?;
        budget.remaining()?;
        let mut refused = false;
        let result = with_transport(env, keys, |session, loaded, action| {
            let api = Api::bounded(&session.profile.origin, budget)?;
            let grant = session.device.as_ref().ok_or_else(invalid)?;
            let owner = loaded
                .package
                .state
                .local
                .central
                .as_ref()
                .ok_or_else(invalid)?;
            let reply = match action {
                Action::Freeze { sources, next } => api.freeze_sources(
                    grant,
                    owner
                        .control
                        .personal_vault
                        .as_deref()
                        .ok_or_else(invalid)?,
                    sources,
                    loaded.intent(),
                    next,
                )?,
                Action::Fetch(chain) => api.frozen_source(
                    grant,
                    owner,
                    &loaded.package.sources,
                    &loaded.intent().body.migration_id,
                    loaded.fetching().ok_or_else(invalid)?.progress(),
                    None,
                    chain,
                )?,
                _ => return Err(invalid()),
            };
            refused = matches!(reply.status, 401 | 403);
            round::require_success(env, &reply)?;
            match action {
                Action::Freeze { .. } => Ok(Received::Freeze(reply.decode()?)),
                Action::Fetch(_) => Ok(Received::Fetch(reply.decode()?)),
                _ => Err(invalid()),
            }
        });
        if refused && !renewed {
            renewed = true;
            if !controller::resume_bounded(env, true, budget)? {
                return Err(invalid());
            }
            continue;
        }
        match result? {
            Step::More => continue,
            Step::Ready => return Ok(Step::Ready),
        }
    }
}
#[cfg(all(test, unix))]
pub(super) fn ready_for_test(joined: bool) -> (crate::sync::testkit::TestDevice, VaultKeys) {
    tests::ready_fixture(joined)
}
#[cfg(all(test,unix))]
pub(super) fn material_ready_for_test()->(crate::sync::testkit::TestDevice,VaultKeys){tests::material_ready_fixture()}
#[cfg(all(test, unix))]
mod tests;

#[cfg(all(test,unix))]
pub(super) fn material_ready_for_adoption_test()->(crate::sync::testkit::TestDevice,VaultKeys){tests::material_ready_fixture_at(true)}
