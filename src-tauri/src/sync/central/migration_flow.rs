//! One native driver for explicit review, bounded migration and protected first publication.
use super::{
    capture_dispatch, controller,
    crypto::VaultKeys,
    initial_publication, migration_dispatch,
    migration_journal::{self, review},
    payload::KeyStorage,
    request_budget::Budget,
    round, source_capture, source_complete,
    source_cursor::Cursor,
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime, records_v3::SyncStateV3},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::atomic::Ordering};
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    service: String,
    account_id: String,
    device_id: String,
    root_fingerprint: String,
    membership_head: String,
    authorization_epoch: String,
}
impl Scope {
    pub(super) fn from_state(state: &SyncStateV3) -> Result<Self, AppError> {
        let w = state.local.central.as_ref().ok_or_else(invalid)?;
        Ok(Self {
            service: w.control.profile.origin.clone(),
            account_id: w.control.account_id.clone(),
            device_id: w.control.device.id.clone(),
            root_fingerprint: w
                .control
                .anchor
                .as_ref()
                .ok_or_else(invalid)?
                .genesis_hash
                .clone(),
            membership_head: w
                .control
                .highwater
                .as_ref()
                .ok_or_else(invalid)?
                .head
                .clone(),
            authorization_epoch: w.control.auth_epoch.to_string(),
        })
    }
    pub(super) fn check(&self, env: &SyncEnv) -> Result<SyncStateV3, AppError> {
        controller::require_enabled()?;
        let state = record_runtime::snapshot(env)?.0;
        if Self::from_state(&state)? != *self {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(state)
    }
}
#[derive(Clone, Serialize)]
pub struct Progress {
    pub(super) phase: &'static str,
    pub(super) mode: &'static str,
    pub(super) legacy_sources: bool,
    pub(super) total: usize,
    pub(super) staged: usize,
    pub(super) verified: usize,
    pub(super) approved: bool,
}
impl Default for Progress {
    fn default() -> Self {
        Self {
            phase: "idle",
            mode: "publish",
            legacy_sources: false,
            total: 0,
            staged: 0,
            verified: 0,
            approved: false,
        }
    }
}
#[derive(Clone)]
pub struct Cached {
    scope: Scope,
    progress: Progress,
}
#[derive(Serialize)]
pub struct Preparation {
    pub(super) progress: Progress,
    pub(super) review: Option<review::Preview>,
}
struct Running<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
fn enter<'a>(env: &'a SyncEnv<'_>) -> Result<Running<'a>, AppError> {
    if env.runtime.syncing.swap(true, Ordering::SeqCst) {
        return Err(AppError::Other(
            "Synchronization is already running. Retry after the current operation finishes."
                .into(),
        ));
    }
    Ok(Running(&env.runtime.syncing))
}
pub(super) fn cached(
    env: &SyncEnv,
    scope: &Scope,
    progress: Progress,
) -> Result<Progress, AppError> {
    scope.check(env)?;
    env.runtime.core.lock().unwrap().central_migration = Some(Cached {
        scope: scope.clone(),
        progress: progress.clone(),
    });
    Ok(progress)
}
fn joining(state: &SyncStateV3) -> Result<bool, AppError> {
    let w = state.local.central.as_ref().ok_or_else(invalid)?;
    Ok(super::replacement_reconciliation::required(w)
        || w.control.proof.as_ref().ok_or_else(invalid)?.genesis.first != w.control.device)
}
pub fn status(env: &SyncEnv, scope: &Scope) -> Result<Progress, AppError> {
    let state = scope.check(env)?;
    if state
        .local
        .central
        .as_ref()
        .is_some_and(|w| w.control.cutover && !super::replacement_reconciliation::required(w))
    {
        return Ok(Progress {
            phase: "complete",
            approved: true,
            ..Progress::default()
        });
    }
    Ok(env
        .runtime
        .core
        .lock()
        .unwrap()
        .central_migration
        .as_ref()
        .filter(|c| c.scope == *scope)
        .map(|c| c.progress.clone())
        .unwrap_or_else(|| {
            if joining(&state).unwrap_or(true) {
                Progress {
                    phase: "waiting",
                    mode: "join",
                    ..Progress::default()
                }
            } else {
                Progress::default()
            }
        }))
}
fn keys(env: &SyncEnv, scope: &Scope) -> Result<VaultKeys, AppError> {
    let state = scope.check(env)?;
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let session = controller::context(env)?;
    let epoch = owner.replica.as_ref().ok_or_else(invalid)?.checkpoint.epoch;
    let wrap = owner
        .own_wraps
        .iter()
        .find(|w| w.header.key_epoch == epoch.to_string())
        .ok_or_else(invalid)?;
    let chain = owner.control.verified_chain()?;
    let author = chain
        .author_at(&wrap.header.membership_head, &wrap.header.author)
        .ok_or_else(invalid)?;
    let keys = wrap.open(
        &session.identity.as_ref().ok_or_else(invalid)?.keys,
        &wrap.header,
        &author.signing,
    )?;
    source_capture::require_target(env, owner, &session, &keys)?;
    Ok(keys)
}
fn reserved(env: &SyncEnv, state: &SyncStateV3) -> Result<bool, AppError> {
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let role = owner.control.profile.profile()?.device_slot(
        "source-migration-publication",
        owner.identity_slot.as_deref(),
    )?;
    Ok(env.keychain.get_noninteractive(&role)?.is_some())
}
/// Probe protected metadata only. No archive decryption, mutation or network is performed.
pub(in crate::sync) fn pending(env: &SyncEnv) -> Result<bool, AppError> {
    let state = record_runtime::snapshot(env)?.0;
    let Some(w) = state.local.central.as_ref() else {
        return Ok(false);
    };
    if w.control.cutover && !super::replacement_reconciliation::required(w) {
        return Ok(false);
    }
    super::source_archive::initial_pending(env, w)
}
fn loaded_progress(
    env: &SyncEnv,
    loaded: &migration_journal::Loaded,
    keys: &VaultKeys,
) -> Result<Progress, AppError> {
    let approved = review::is_approved(env, loaded)?;
    let staged = loaded.progress().map_or(0, |p| p.staged() as usize);
    let verified = loaded.verifier(keys)?.sequence() as usize;
    Ok(Progress {
        phase: if !approved {
            "review"
        } else if verified > 0 || staged == loaded.plan.rows.len() {
            "reading"
        } else {
            "staging"
        },
        mode: "publish",
        legacy_sources: !loaded.plan.manifest.body.sources.is_empty(),
        total: loaded.plan.rows.len(),
        staged,
        verified,
        approved,
    })
}
fn publish(
    env: &SyncEnv,
    scope: &Scope,
    prepared: super::InitialPreparation,
    keys: &VaultKeys,
) -> Result<Preparation, AppError> {
    cached(
        env,
        scope,
        Progress {
            phase: "publishing",
            approved: true,
            ..Progress::default()
        },
    )?;
    scope.check(env)?;
    crate::sync::record_import::central_stage::prepare_initial_reserved(env, &prepared, keys)?;
    scope.check(env)?;
    crate::sync::record_import::central_stage::publish_initial(env, &prepared, keys)?;
    Ok(Preparation {
        progress: cached(
            env,
            scope,
            Progress {
                phase: "complete",
                approved: true,
                ..Progress::default()
            },
        )?,
        review: None,
    })
}
#[derive(Clone, Copy)]
pub(super) enum Action {
    Prepare,
    Continue,
    Background,
}
fn run(
    env: &SyncEnv,
    scope: &Scope,
    action: Action,
    budget: &Budget,
) -> Result<Preparation, AppError> {
    let state = scope.check(env)?;
    if state
        .local
        .central
        .as_ref()
        .is_some_and(|w| w.control.cutover && !super::replacement_reconciliation::required(w))
    {
        super::initial_transaction::complete_saved(env)?;
        return Ok(Preparation {
            progress: status(env, scope)?,
            review: None,
        });
    }
    if joining(&state)? {
        return super::adoption::run(env, scope, action, budget);
    }
    run_first(env, scope, action, budget)
}
fn run_first(
    env: &SyncEnv,
    scope: &Scope,
    action: Action,
    budget: &Budget,
) -> Result<Preparation, AppError> {
    round::check_cooldown(env)?;
    if !controller::resume_bounded(env, false, budget)? {
        return Err(invalid());
    }
    let state = scope.check(env)?;
    let keys = keys(env, scope)?;
    if reserved(env, &state)? {
        return resume_reserved(env, scope, &keys);
    }
    run_unreserved(env, scope, action, budget, &state, &keys)
}
// Resumption reads nested journals. Do not retain the unrelated capture/staging temporaries
// from the unreserved path on that reader's stack.
#[inline(never)]
fn resume_reserved(
    env: &SyncEnv,
    scope: &Scope,
    keys: &VaultKeys,
) -> Result<Preparation, AppError> {
    let prepared = initial_publication::resume(env, keys, &BTreeMap::new())?;
    publish(env, scope, prepared, keys)
}
#[inline(never)]
fn run_unreserved(
    env: &SyncEnv,
    scope: &Scope,
    action: Action,
    budget: &Budget,
    state: &SyncStateV3,
    keys: &VaultKeys,
) -> Result<Preparation, AppError> {
    let references = BTreeMap::<String, KeyStorage>::new();
    let capturing = {
        let life = env.runtime.lifecycle.lock().unwrap();
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        match Cursor::load(env, &life, owner)? {
            None => true,
            Some(saved) => {
                saved.cursor.revision() == 1 || super::capture_journal::is_frame(&saved.bytes)
            }
        }
    };
    if capturing {
        if !matches!(action, Action::Prepare) && !pending(env)? {
            return Err(AppError::Other(
                "Prepare and review this library before enabling synchronization.".into(),
            ));
        }
        cached(
            env,
            scope,
            Progress {
                phase: "capturing",
                ..Progress::default()
            },
        )?;
        source_capture::start_or_resume(env, &keys, &references)?;
        scope.check(env)?;
        let step = capture_dispatch::advance(env, &keys, budget);
        match step {
            Ok(capture_dispatch::Step::More) => {
                return Ok(Preparation {
                    progress: status(env, scope)?,
                    review: None,
                })
            }
            Err(e) if Budget::exhausted(&e) => {
                return Ok(Preparation {
                    progress: status(env, scope)?,
                    review: None,
                })
            }
            Err(e) => return Err(e),
            Ok(capture_dispatch::Step::Ready) => {}
        }
        source_complete::ensure(env, &keys)?.ok_or_else(invalid)?;
    }
    scope.check(env)?;
    let loaded = migration_journal::ensure(env, &keys, &references)?;
    let progress = loaded_progress(env, &loaded, &keys)?;
    cached(env, scope, progress.clone())?;
    drop(loaded);
    if !progress.approved || matches!(action, Action::Prepare) {
        let preview = if matches!(action, Action::Prepare) {
            Some(review::preview(env, &keys, &references)?)
        } else {
            None
        };
        return Ok(Preparation {
            progress,
            review: preview,
        });
    }
    scope.check(env)?;
    match migration_dispatch::advance(env, &keys, &references, budget)? {
        migration_dispatch::Step::More => {
            let loaded = migration_journal::ensure(env, &keys, &references)?;
            Ok(Preparation {
                progress: cached(env, scope, loaded_progress(env, &loaded, &keys)?)?,
                review: None,
            })
        }
        migration_dispatch::Step::Verified(verified) => {
            scope.check(env)?;
            let prepared = initial_publication::prepare(env, verified, &keys)?;
            publish(env, scope, prepared, &keys)
        }
    }
}
fn foreground(env: &SyncEnv, scope: &Scope, action: Action) -> Result<Preparation, AppError> {
    scope.check(env)?;
    let running = enter(env)?;
    let budget = Budget::new();
    let result = run(env, scope, action, &budget);
    env.runtime.core.lock().unwrap().central_poll.requests = budget.used();
    drop(running);
    env.events.status();
    result
}
pub fn prepare(env: &SyncEnv, scope: &Scope) -> Result<Preparation, AppError> {
    foreground(env, scope, Action::Prepare)
}
pub fn advance(env: &SyncEnv, scope: &Scope) -> Result<Progress, AppError> {
    foreground(env, scope, Action::Continue).map(|r| r.progress)
}
pub fn confirm(env: &SyncEnv, scope: &Scope, ticket: &str) -> Result<Progress, AppError> {
    scope.check(env)?;
    let running = enter(env)?;
    let result = (|| {
        if joining(&scope.check(env)?)? {
            return super::adoption::confirm(env, scope, ticket);
        }
        let keys = keys(env, scope)?;
        scope.check(env)?;
        review::confirm(env, &keys, &BTreeMap::new(), ticket)?;
        let loaded = migration_journal::ensure(env, &keys, &BTreeMap::new())?;
        cached(env, scope, loaded_progress(env, &loaded, &keys)?)
    })();
    drop(running);
    env.events.status();
    if result.is_ok() {
        env.events.wake();
    }
    result
}
/// Called inside the ordinary worker's existing syncing reservation; never starts a new capture.
pub(super) fn background(env: &SyncEnv, report: &mut round::Report) -> Result<bool, AppError> {
    if !pending(env)? {
        return Ok(false);
    }
    let scope = Scope::from_state(&record_runtime::snapshot(env)?.0)?;
    let budget = Budget::new();
    let result = run(env, &scope, Action::Background, &budget);
    report.requests += budget.used();
    match result {
        Ok(result) => {
            report.more = matches!(
                result.progress.phase,
                "capturing" | "staging" | "reading" | "publishing"
            );
            Ok(true)
        }
        Err(e) if Budget::exhausted(&e) => {
            report.more = true;
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

/// Read protected startup state outside Core, then cache only the ordinary edit barrier.
pub(in crate::sync) fn refresh_edit_gate(env: &SyncEnv) -> Result<(), AppError> {
    let state = record_runtime::snapshot(env)?.0;
    let frozen = state.local.central_cache_source.is_some()
        || if let Some(w) = &state.local.central {
            (!w.control.cutover || super::replacement_reconciliation::required(w))
                && super::source_archive::initial_pending(env, w)?
        } else {
            false
        };
    let mut core = env.runtime.core.lock().unwrap();
    if record_runtime::active_state(&core)?.local.central != state.local.central {
        return Err(crate::sync::runtime::superseded());
    }
    // An in-flight begin may already have raised the barrier before its protected write.
    if frozen
        || state
            .local
            .central
            .as_ref()
            .is_none_or(|w| w.control.cutover)
    {
        core.central_migration_frozen = frozen;
    }
    Ok(())
}
pub(in crate::sync) fn require_editable(env: &SyncEnv) -> Result<(), AppError> {
    refresh_edit_gate(env)?;
    if env.runtime.core.lock().unwrap().central_migration_frozen {
        return Err(edit_error());
    }
    Ok(())
}
pub(in crate::sync) fn edit_error() -> AppError {
    AppError::Other("Library changes are paused while this device completes its encrypted migration. Continue library setup; original data and saved progress are retained.".into())
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use crate::sync::{central::migration_files::Files, record_keys};
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn stale_account_scope_blocks_status_prepare_confirm_and_continue_before_any_effect() {
        let (d, _, _) = super::super::source_capture::tests::fixture(false);
        let env = d.env();
        let mut expected = Scope::from_state(&record_runtime::snapshot(&env).unwrap().0).unwrap();
        expected.authorization_epoch = "stale-epoch".into();
        let files = Files::capture(&env, None).unwrap();
        let before = record_runtime::snapshot(&env).unwrap();
        assert!(status(&env, &expected).is_err());
        assert!(prepare(&env, &expected).is_err());
        assert!(confirm(&env, &expected, &"a".repeat(64)).is_err());
        assert!(advance(&env, &expected).is_err());
        files.require_unchanged(&env, None).unwrap();
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        assert!(!env.runtime.syncing.load(Ordering::SeqCst));
    }
    #[test]
    fn worker_never_starts_source_capture_without_an_explicit_foreground_start() {
        let (d, _, _) = super::super::source_capture::tests::fixture(false);
        let env = d.env();
        let files = Files::capture(&env, None).unwrap();
        let mut report = round::Report::default();
        assert!(!background(&env, &mut report).unwrap());
        assert_eq!(report.requests, 0);
        files.require_unchanged(&env, None).unwrap();
    }
    #[test]
    fn a_cold_protected_capture_blocks_public_edits_and_key_generation_before_any_file_effect() {
        let (d, _) = super::super::capture_dispatch::material_ready_for_test();
        let env = d.env();
        env.runtime.core.lock().unwrap().central_migration_frozen = false;
        let files = Files::capture(&env, None).unwrap();
        let before = record_runtime::snapshot(&env).unwrap();
        assert!(record_runtime::mutate_records(&env, |old| {
            let mut next = old.clone();
            next.device_name = "changed during capture".into();
            Ok(next)
        })
        .is_err());
        assert!(record_keys::generate_local(
            &env,
            "blocked",
            crate::vault::generate::KeyAlgorithm::Ed25519,
            "",
            None
        )
        .is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        files.require_unchanged(&env, None).unwrap();
        assert!(env.runtime.core.lock().unwrap().central_migration_frozen);
    }
    #[test]
    fn safety_controls_remain_available_while_library_edits_are_frozen_without_credential_reads() {
        struct NoCredentials;
        impl crate::sync::env::Keychain for NoCredentials {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> {
                panic!("no credential read for account safety control")
            }
            fn get_noninteractive(&self, _: &str) -> Result<Option<String>, AppError> {
                panic!("no credential read for account safety control")
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                panic!("no credential write")
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("no credential deletion")
            }
        }
        let (d, _, _) = super::super::source_capture::tests::fixture(false);
        let readonly = NoCredentials;
        let mut env = d.env();
        env.keychain = &readonly;
        env.runtime.core.lock().unwrap().central_migration_frozen = true;
        let before = record_runtime::snapshot(&env).unwrap().0;
        record_runtime::mutate_records(&env, |old| {
            let mut next = old.clone();
            next.local.central.as_mut().unwrap().control.phase =
                super::super::client_state::Phase::SignedOut;
            Ok(next)
        })
        .unwrap();
        let mut after = record_runtime::snapshot(&env).unwrap().0;
        after.version = before.version;
        after.local.central = before.local.central.clone();
        assert_eq!(after, before);
    }
    #[test]
    fn a_saved_initial_reservation_runs_through_the_driver_and_retry_preserves_the_active_library()
    {
        let (d, keys, verified) =
            super::super::migration_dispatch::verified_material_fixture_for_test();
        let env = d.env();
        std::fs::set_permissions(
            env.state_path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let expected = Scope::from_state(&record_runtime::snapshot(&env).unwrap().0).unwrap();
        initial_publication::prepare(&env, verified, &keys).unwrap();
        assert_eq!(advance(&env, &expected).unwrap().phase, "complete");
        let active = record_runtime::snapshot(&env).unwrap();
        assert!(active.0.local.central.as_ref().unwrap().control.cutover);
        assert!(active.0.local.central_projection.is_some());
        assert_eq!(advance(&env, &expected).unwrap().phase, "complete");
        assert_eq!(record_runtime::snapshot(&env).unwrap(), active);
        assert!(!env.runtime.syncing.load(Ordering::SeqCst));
    }
}
