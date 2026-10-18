//! Bounded native acquisition of an authenticated active-device baseline.
//! No repository, Keychain material or current-owner publication occurs here.
use super::{
    active_read::{Plan, ReadSession, Snapshot, VerifiedLibrary},
    api::{Api, Reply, VaultResource},
    controller::Session,
    crypto::WrappedKeys,
    owner::OwnerPath,
    recovery_read::{EpochBundle, HistoryPage, RecoveryVault},
    recovery_revalidation::{Bridge, Work},
    rekey::{Checkpoint, SignedRekey, SourceDigest},
    replacement_proof, round,
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::{error::AppError, sync::env::SyncEnv};
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    vault: String,
    epoch: u64,
    membership_head: String,
    authorization_epoch: String,
    phase: String,
    sequence: String,
    history_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    manifest: SignedRekey,
    staged: String,
    history_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    phase: String,
    epoch: u64,
    sequence: String,
    history_hash: String,
    journal: Option<Journal>,
    commits: Vec<SignedRekey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePage {
    manifest: SignedRekey,
    digests: Vec<SourceDigest>,
}
struct Budget {
    started: Instant,
    requests: usize,
}
impl Budget {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            requests: 0,
        }
    }
    fn available(&self) -> bool {
        self.requests < 32 && self.started.elapsed() < Duration::from_secs(30)
    }
    fn call(
        &mut self,
        env: &SyncEnv,
        check: &impl Fn() -> Result<(), AppError>,
        action: impl FnOnce() -> Result<Reply, AppError>,
    ) -> Result<Reply, AppError> {
        check()?;
        round::check_cooldown(env)?;
        if !self.available() {
            return Err(AppError::Other(
                "Continue Vault verification to finish the remaining requests.".into(),
            ));
        }
        self.requests += 1;
        {
            let mut core = env.runtime.core.lock().unwrap();
            core.central_poll.requests = core.central_poll.requests.saturating_add(1);
        }
        let reply = action()?;
        check()?;
        round::require_success(env, &reply)?;
        Ok(reply)
    }
}
/// Keys and partially admitted history remain memory-only until finish mints VerifiedLibrary.
pub(super) struct Reading {
    path: OwnerPath,
    before: Workspace,
    source: Option<Workspace>,
    session: Arc<Session>,
    snapshot: Snapshot,
    proof: super::trust::ControlProof,
    own_floors: Vec<Checkpoint>,
    complete: bool,
    plan: Option<Plan>,
    work: Work,
    read: Option<ReadSession>,
}
fn bridges_for(bridges: &[Bridge], floors: &[Checkpoint]) -> Result<Vec<Bridge>, AppError> {
    let epoch = floors.first().ok_or_else(invalid)?.epoch;
    if floors.iter().any(|floor| floor.epoch != epoch) {
        return Err(invalid());
    }
    Ok(bridges
        .iter()
        .filter(|bridge| bridge.epoch > epoch)
        .cloned()
        .collect())
}
impl Reading {
    /// The caller owns the existing lifecycle gate and a cancellation generation.
    pub(super) fn begin(
        env: &SyncEnv,
        path: OwnerPath,
        session: Arc<Session>,
        source: Option<Workspace>,
        check: &impl Fn() -> Result<(), AppError>,
    ) -> Result<Self, AppError> {
        Self::begin_at(env, path, session, source, check, Instant::now())
    }
    pub(super) fn begin_at(
        env: &SyncEnv,
        path: OwnerPath,
        session: Arc<Session>,
        source: Option<Workspace>,
        check: &impl Fn() -> Result<(), AppError>,
        started: Instant,
    ) -> Result<Self, AppError> {
        let before = path.snapshot(env)?;
        let identity = session.identity.as_ref().ok_or_else(invalid)?;
        let device = session.device.as_ref().ok_or_else(invalid)?;
        if session.profile != before.control.profile
            || identity.device() != before.control.device
            || device.account_id != before.control.account_id
            || device.expired()
            || device.device_state != super::api::DeviceState::Active
            || session.device_access_denied
        {
            return Err(invalid());
        }
        let api = Api::new(&before.control.profile.origin)?;
        let mut budget = Budget {
            started,
            requests: 0,
        };
        let remote: super::api::AccountOverview =
            budget.call(env, check, || api.account(device))?.decode()?;
        remote.validate(device)?;
        let proof = remote.proof.ok_or_else(invalid)?;
        if remote.phase != "ready"
            || remote.barrier.is_some()
            || remote.vaults.len() != 1
            || remote.denied.contains(&identity.id)
        {
            return Err(invalid());
        }
        let vault = before.control.personal_vault.as_ref().ok_or_else(invalid)?;
        let advertised = remote.vaults.get(vault).ok_or_else(invalid)?;
        let status: Status = budget
            .call(env, check, || {
                api.vault(device, vault, VaultResource::Rekey)
            })?
            .decode()?;
        if status.epoch != advertised.epoch
            || status.epoch == 0
            || status.epoch > 65
            || status.commits.len() + 1 != status.epoch as usize
            || !["ready", "rekey_pending"].contains(&status.phase.as_str())
        {
            return Err(invalid());
        }
        // An in-progress journal is not a committed epoch. Its bounded public shape is still checked.
        if let Some(journal) = &status.journal {
            if number(&journal.staged, true)? > 16384
                || !super::wire::hex(&journal.history_hash, 64)
                || number(&journal.manifest.body.from_epoch, false)? != status.epoch
            {
                return Err(invalid());
            }
        }
        let wrap: WrappedKeys = budget
            .call(env, check, || api.vault(device, vault, VaultResource::Wrap))?
            .decode()?;
        let committed = if status.epoch == 1 {
            None
        } else {
            Some(
                budget
                    .call(env, check, || {
                        api.vault(
                            device,
                            vault,
                            VaultResource::EpochWraps {
                                epoch: status.epoch,
                            },
                        )
                    })?
                    .decode::<EpochBundle>()?,
            )
        };
        let snapshot = Snapshot {
            membership_head: proof
                .verify(
                    before.control.anchor.as_ref().ok_or_else(invalid)?,
                    before.control.highwater.as_ref(),
                )?
                .current()
                .head()
                .into(),
            auth_epoch: remote.auth_epoch,
            vault: RecoveryVault {
                vault: vault.clone(),
                epoch: status.epoch,
                phase: status.phase,
                wrap,
                committed,
                commits: status.commits,
                sequence: status.sequence,
                history_hash: status.history_hash,
            },
        };
        let metadata: Metadata = budget
            .call(env, check, || {
                api.vault(device, vault, VaultResource::Metadata)
            })?
            .decode()?;
        Self::check_metadata(&snapshot, &metadata)?;
        let plan = Plan::new(&before, identity, proof.clone(), snapshot.clone())?;
        let mut floors = plan.floors().to_vec();
        if let Some(source) = &source {
            source.validate()?;
            if source.control.profile != before.control.profile
                || source.control.account_id != before.control.account_id
                || source
                    .control
                    .anchor
                    .as_ref()
                    .is_some_and(|anchor| Some(anchor) != before.control.anchor.as_ref())
                || !plan.epochs().starts_with(&source.epochs)
                || !plan.epochs().starts_with(&source.observed_epochs)
            {
                return Err(invalid());
            }
            if let Some((known, _, _)) = replacement_proof::minimums(source)? {
                floors.extend(known);
            }
        }
        floors.sort_by_key(|floor| (floor.epoch, floor.sequence));
        floors.dedup();
        let base = floors.first().ok_or_else(invalid)?.clone();
        let work = Work::new(
            base,
            floors.into_iter().skip(1).collect(),
            plan.checkpoint().epoch,
        )?;
        check()?;
        let own_floors = plan.floors().to_vec();
        Ok(Self {
            path,
            before,
            source,
            session,
            snapshot,
            proof,
            own_floors,
            complete: false,
            plan: Some(plan),
            work,
            read: None,
        })
    }
    fn check_metadata(snapshot: &Snapshot, metadata: &Metadata) -> Result<(), AppError> {
        if metadata.vault != snapshot.vault.vault
            || metadata.epoch != snapshot.vault.epoch
            || metadata.membership_head != snapshot.membership_head
            || number(&metadata.authorization_epoch, false)? != snapshot.auth_epoch
            || metadata.phase != snapshot.vault.phase
            || metadata.sequence != snapshot.vault.sequence
            || metadata.history_hash != snapshot.vault.history_hash
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(())
    }
    fn own_bridges(&self) -> Result<Vec<Bridge>, AppError> {
        bridges_for(&self.work.bridges, &self.own_floors)
    }
    fn source_bridges(&self) -> Result<Vec<Bridge>, AppError> {
        match self
            .source
            .as_ref()
            .map(replacement_proof::minimums)
            .transpose()?
            .flatten()
        {
            Some((floors, _, _)) => bridges_for(&self.work.bridges, &floors),
            None => Ok(vec![]),
        }
    }
    pub(super) fn position(&self) -> u64 {
        self.read.as_ref().map_or(0, ReadSession::position)
    }
    pub(super) fn total(&self) -> u64 {
        number(&self.snapshot.vault.sequence, true).unwrap_or(0)
    }
    pub(super) fn advance(
        &mut self,
        env: &SyncEnv,
        check: &impl Fn() -> Result<(), AppError>,
    ) -> Result<bool, AppError> {
        self.complete = false;
        if self.path.snapshot(env)? != self.before {
            return Err(crate::sync::runtime::superseded());
        }
        let api = Api::new(&self.before.control.profile.origin)?;
        let device = self.session.device.as_ref().ok_or_else(invalid)?;
        if device.expired() {
            return Err(invalid());
        }
        let mut budget = Budget::new();
        if let Some(plan) = &self.plan {
            loop {
                let Some((epoch, after)) =
                    self.work.next(plan.chain(), plan.vault(), plan.epochs())?
                else {
                    break;
                };
                if !budget.available() {
                    return Ok(false);
                }
                let page: SourcePage = budget
                    .call(env, check, || {
                        api.vault(
                            device,
                            plan.vault(),
                            VaultResource::SourceProof { epoch, after },
                        )
                    })?
                    .decode()?;
                self.work.append(
                    plan.chain(),
                    plan.vault(),
                    plan.epochs(),
                    &page.manifest,
                    &page.digests,
                )?;
            }
        }
        if self.read.is_none() {
            let bridges = self.own_bridges()?;
            let mut read = self.plan.take().ok_or_else(invalid)?.start(&bridges)?;
            if let Some(source) = &self.source {
                replacement_proof::pin_active_read(source, &mut read, &self.source_bridges()?)?;
            }
            self.read = Some(read);
        }
        let read = self.read.as_mut().ok_or_else(invalid)?;
        while read.position() < read.total() {
            if !budget.available() {
                return Ok(false);
            }
            let page: HistoryPage = budget
                .call(env, check, || {
                    api.vault(
                        device,
                        read.vault(),
                        VaultResource::Records {
                            since: read.position(),
                        },
                    )
                })?
                .decode()?;
            read.append(page)?;
        }
        // Leave enough room for both final fences; a continuation performs them together.
        if budget.requests > 30 || !budget.available() {
            return Ok(false);
        }
        let remote: super::api::AccountOverview =
            budget.call(env, check, || api.account(device))?.decode()?;
        remote.validate(device)?;
        if remote.proof.as_ref() != Some(&self.proof)
            || remote.auth_epoch != self.snapshot.auth_epoch
            || remote.phase != "ready"
            || remote.barrier.is_some()
            || remote.denied.contains(&self.before.control.device.id)
            || remote.vaults.len() != 1
            || remote
                .vaults
                .get(read.vault())
                .is_none_or(|vault| vault.epoch != self.snapshot.vault.epoch)
        {
            return Err(crate::sync::runtime::superseded());
        }
        let metadata: Metadata = budget
            .call(env, check, || {
                api.vault(device, read.vault(), VaultResource::Metadata)
            })?
            .decode()?;
        Self::check_metadata(&self.snapshot, &metadata)?;
        check()?;
        self.complete = true;
        Ok(true)
    }
    /// Caller must have received true from advance under the same lifecycle/cancellation gate.
    pub(super) fn finish(
        mut self,
    ) -> Result<(VerifiedLibrary, Vec<Bridge>, Vec<Bridge>), AppError> {
        if !self.complete {
            return Err(invalid());
        }
        let own = self.own_bridges()?;
        let source = self.source_bridges()?;
        Ok((self.read.take().ok_or_else(invalid)?.finish()?, own, source))
    }
}
