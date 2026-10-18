//! Bounded personal-Vault ciphertext staging. No pre-consent material release or legacy transport.
use super::{
    api::{Api, Reply, VaultResource},
    client_state::Phase,
    controller, joining, library_page,
    rekey::{Checkpoint, Version},
    wire::{invalid, number},
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::Deserialize;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Polling {
    pub retry_at: Option<Instant>,
    pub failures: u32,
    pub requests: usize,
}
#[derive(Default)]
pub struct Report {
    pub requests: usize,
    pub more: bool,
    pub staged: usize,
}
pub fn configured(env: &SyncEnv) -> bool {
    if !controller::enabled() {
        return false;
    }
    let core = env.runtime.core.lock().unwrap();
    core.format == record_runtime::RuntimeFormat::Records
        && core.save_blocked.is_none()
        && core
            .records
            .as_ref()
            .is_some_and(|r| r.local.central.is_some())
}
struct Running<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
pub fn cooldown(env: &SyncEnv) -> Duration {
    env.runtime
        .core
        .lock()
        .unwrap()
        .central_poll
        .retry_at
        .map_or(Duration::ZERO, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        })
}
pub fn check_cooldown(env: &SyncEnv) -> Result<(), AppError> {
    if cooldown(env).is_zero() {
        Ok(())
    } else {
        Err(AppError::Other("The account service requested a cooldown. Local changes are retained; retry after the waiting period.".into()))
    }
}
pub fn next_delay(env: &SyncEnv) -> Duration {
    let core = env.runtime.core.lock().unwrap();
    let base = crate::sync::relay::next_poll_delay(
        1,
        env.runtime
            .focused
            .load(std::sync::atomic::Ordering::SeqCst),
        env.runtime
            .last_activity_ms
            .load(std::sync::atomic::Ordering::SeqCst),
        env.now(),
        core.central_poll.failures,
    )
    .max(Duration::from_secs(90));
    base.max(Duration::from_secs(
        40 * core.central_poll.requests.min(64) as u64,
    ))
    .max(core.central_poll.retry_at.map_or(Duration::ZERO, |t| {
        t.saturating_duration_since(Instant::now())
    }))
}
pub(crate) fn require_success(env: &SyncEnv, reply: &Reply) -> Result<(), AppError> {
    if reply.status == 429 {
        let duration = reply
            .retry_after
            .unwrap_or(Duration::from_secs(90))
            .max(Duration::from_secs(90));
        let mut core = env.runtime.core.lock().unwrap();
        let deadline = Instant::now() + duration;
        core.central_poll.retry_at = Some(
            core.central_poll
                .retry_at
                .map_or(deadline, |known| known.max(deadline)),
        );
    }
    reply.success()
}
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
pub fn sync_once(env: &SyncEnv) -> Result<Report, AppError> {
    if !configured(env) || !cooldown(env).is_zero() {
        return Ok(Report::default());
    }
    if env
        .runtime
        .syncing
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return Ok(Report::default());
    }
    let running = Running(&env.runtime.syncing);
    let mut report = Report::default();
    let outcome = stage(env, &mut report);
    drop(running);
    match &outcome {
        Ok(()) => {
            let mut core = env.runtime.core.lock().unwrap();
            core.central_poll.failures = 0;
            core.central_poll.requests = report.requests;
            if core
                .central_poll
                .retry_at
                .is_some_and(|t| t <= Instant::now())
            {
                core.central_poll.retry_at = None;
            }
            if report.requests > 0 {
                core.central_user_action = None;
            }
        }
        Err(error) if error.to_string() == crate::sync::runtime::SUPERSEDED => {
            env.runtime.core.lock().unwrap().central_poll.requests = report.requests;
        }
        Err(error) => {
            let mut core = env.runtime.core.lock().unwrap();
            core.central_poll.requests = report.requests.saturating_add(1).min(32);
            core.central_poll.failures = core.central_poll.failures.saturating_add(1);
            let deadline =
                Instant::now() + crate::sync::relay::backoff_delay(core.central_poll.failures);
            core.central_poll.retry_at = Some(
                core.central_poll
                    .retry_at
                    .map_or(deadline, |known| known.max(deadline)),
            );
            core.central_user_action = Some(error.to_string());
        }
    }
    env.events.status();
    if outcome.is_ok() && report.more {
        env.events.wake();
    }
    outcome.map(|()| report)
}
fn stage(env: &SyncEnv, report: &mut Report) -> Result<(), AppError> {
    if record_runtime::snapshot(env)?
        .0
        .local
        .central
        .as_ref()
        .is_some_and(|w| w.control.cutover)
    {
        return Err(AppError::Other(
            "This build cannot activate the central library yet. Local data is retained.".into(),
        ));
    }
    if !controller::resume(env, false)? {
        return Ok(());
    }
    let start = Instant::now();
    let mut renewed = false;
    loop {
        let (mut records, generation) = record_runtime::snapshot(env)?;
        let before = records.local.central.as_ref().ok_or_else(invalid)?;
        if matches!(
            before.control.phase,
            Phase::Revoked | Phase::SignedOut | Phase::BackupRequired | Phase::Setup
        ) {
            return Ok(());
        }
        if before.control.phase == Phase::Rekey {
            report.more = super::rotation_runtime::advance(env, report)?;
            return Ok(());
        }
        let session = controller::context(env)?;
        let device = session.device.as_ref().ok_or_else(invalid)?;
        let api = Api::new(&before.control.profile.origin)?;
        if before.control.phase == Phase::AwaitingApproval {
            let reply = api.account(device)?;
            report.requests += 1;
            if matches!(reply.status, 401 | 403) && !renewed {
                controller::resume(env, true)?;
                renewed = true;
                continue;
            }
            require_success(env, &reply)?;
            return Ok(());
        }
        if before.replica.is_none() {
            joining::initialize(env)?;
            if record_runtime::snapshot(env)?
                .0
                .local
                .central
                .as_ref()
                .is_none_or(|w| w.replica.is_none())
            {
                return Err(AppError::Other("The saved Vault requires recovery or initialization before synchronization. Local data is retained.".into()));
            }
            continue;
        }
        if before.control.cutover {
            return Err(AppError::Other(
                "This build cannot activate the central library yet. Local data is retained."
                    .into(),
            ));
        }
        let replica = before.replica.as_ref().ok_or_else(invalid)?;
        let reply = api.vault(
            device,
            &replica.vault,
            VaultResource::Records {
                since: replica.checkpoint.sequence,
            },
        )?;
        report.requests += 1;
        if matches!(reply.status, 401 | 403) && !renewed {
            controller::resume(env, true)?;
            renewed = true;
            continue;
        }
        require_success(env, &reply)?;
        let page: Page = reply.decode()?;
        if page.epoch < replica.checkpoint.epoch
            || page.epoch > 65
            || !["ready", "rekey_pending"].contains(&page.phase.as_str())
        {
            return Err(invalid());
        }
        if page.epoch != replica.checkpoint.epoch || page.phase != "ready" {
            records
                .local
                .central
                .as_mut()
                .ok_or_else(invalid)?
                .control
                .phase = Phase::Rekey;
            record_runtime::commit_candidate(env, generation, records)?;
            return Ok(());
        }
        if before.control.highwater.as_ref().map(|h| h.head.as_str())
            != Some(page.membership_head.as_str())
        {
            return Err(invalid());
        }
        let identity = session.identity.as_ref().ok_or_else(invalid)?;
        let chain = before.control.verified_chain()?;
        let wrap = before
            .own_wraps
            .iter()
            .find(|w| number(&w.header.key_epoch, false).ok() == Some(replica.checkpoint.epoch))
            .ok_or_else(invalid)?;
        let author = chain
            .author_at(&wrap.header.membership_head, &wrap.header.author)
            .ok_or_else(invalid)?;
        let keys = wrap.open(&identity.keys, &wrap.header, &author.signing)?;
        let advertised = Checkpoint {
            epoch: page.epoch,
            sequence: number(&page.sequence, true)?,
            history_hash: page.history_hash,
        };
        let verified = library_page::prepare(before, &keys, &page.records, &advertised)?;
        if !verified.publication.is_empty() {
            return Err(invalid());
        }
        let old = replica.checkpoint.sequence;
        let new = verified.next.checkpoint.sequence;
        if new > old {
            report.staged += (new - old) as usize;
            records.local.central.as_mut().ok_or_else(invalid)?.replica = Some(verified.next);
            record_runtime::commit_candidate(env, generation, records)?;
        }
        report.more = new < advertised.sequence;
        if !report.more || report.requests >= 32 || start.elapsed() >= Duration::from_secs(30) {
            return Ok(());
        }
    }
}
