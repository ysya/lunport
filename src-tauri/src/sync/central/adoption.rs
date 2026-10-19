//! Approved-device adoption. Local source, consent and authenticated remote read remain distinct.
use super::{
    active_flow::{Reading, Transcript},
    api::{Api, VaultResource},
    controller::{self, Session},
    crypto::VaultKeys,
    initial_projection::Candidate,
    initial_transaction::{self, InitialTransaction},
    migration_flow::{self, Action, Preparation, Progress, Scope},
    migration_journal::review,
    owner::OwnerPath,
    rekey::Checkpoint,
    request_budget::Budget,
    source_archive::{self, Outputs, Receipt},
    source_cursor::Cursor,
    source_package::Package,
    wire::{hex, invalid, number, MAX_SAFE_INTEGER},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime, records_v3::SyncStateV3},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, MutexGuard},
};
use zeroize::Zeroizing;
mod merge;
mod rebase;
const CAP: usize = 32768;
const MAGIC: &[u8; 8] = b"LPADOPT1";
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    policy: String,
    source: Cursor,
    floor: Checkpoint,
    archives: Vec<Receipt>,
    remote: Option<Receipt>,
    plan: Option<Receipt>,
    final_read: Option<Receipt>,
    ticket: String,
    accepted: bool,
    completed: usize,
    operation: String,
    observed: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    version: u32,
    source: Receipt,
    body: Body,
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Body {
    Remote(Transcript),
    Plan(merge::Plan),
    Rebase {
        parent: Receipt,
        transcript: Transcript,
        completed: usize,
        plan: merge::Plan,
    },
    Final(Transcript),
}
struct Loaded {
    state: State,
    package: Package,
    outputs: Outputs,
    generation: u64,
    session: Arc<Session>,
}
/// Passive bounded read state, stored inside the one Records Core; never an IPC DTO.
pub(in crate::sync) struct ReadingCache {
    reading: Reading,
}
pub(super) struct Prepared {
    loaded: Loaded,
    initial: Candidate,
    proof: Transcript,
}
pub(super) fn target(
    env: &SyncEnv,
    owner: &Workspace,
    session: &Session,
    keys: &VaultKeys,
) -> Result<(), AppError> {
    super::source_capture::require_adoption_target(env, owner, session, keys)
}
fn role(owner: &Workspace) -> Result<String, AppError> {
    owner
        .control
        .profile
        .profile()?
        .device_slot("source-adoption", owner.identity_slot.as_deref())
}
impl State {
    fn validate(&self, owner: &Workspace) -> Result<(), AppError> {
        self.source.validate(owner)?;
        if self.version != 1
            || self.policy != "device-adoption-v1"
            || self.source.revision() != 1
            || self.archives.len() > 8
            || !hex(&self.ticket, 64)
            || !hex(&self.operation, 32)
            || self.observed > MAX_SAFE_INTEGER
            || self.completed > 16384
            || self.floor.epoch == 0
            || self.floor.epoch > 65
            || self.floor.sequence > 16384
            || !hex(&self.floor.history_hash, 64)
            || self.floor.sequence == 0 && self.floor.history_hash != "0".repeat(64)
            || self.accepted && self.plan.is_none()
            || self.plan.is_some() && self.remote.is_none()
            || self.final_read.is_some() && !self.accepted
        {
            return Err(invalid());
        }
        let mut previous = self.source.receipt();
        let mut seen = std::collections::BTreeSet::new();
        for receipt in &self.archives {
            receipt.matches_selected(owner)?;
            if !receipt.follows(previous)?
                || receipt.next_ordinal()?
                    != previous
                        .next_ordinal()?
                        .checked_add(1)
                        .ok_or_else(invalid)?
                || !seen.insert(&receipt.ciphertext_hash)
            {
                return Err(invalid());
            }
            previous = receipt;
        }
        for r in [&self.remote, &self.plan, &self.final_read]
            .into_iter()
            .flatten()
        {
            if !self.archives.contains(r) {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn read(env: &SyncEnv, owner: &Workspace) -> Result<Option<State>, AppError> {
    let Some(value) = env
        .keychain
        .get_noninteractive(&role(owner)?)?
        .map(Zeroizing::new)
    else {
        return Ok(None);
    };
    if value.len() > CAP {
        return Err(invalid());
    }
    let state: State = serde_json::from_str(&value).map_err(|_| invalid())?;
    state.validate(owner)?;
    Ok(Some(state))
}
fn save(
    env: &SyncEnv,
    owner: &Workspace,
    before: Option<&State>,
    next: &State,
) -> Result<(), AppError> {
    next.validate(owner)?;
    let current = read(env, owner)?;
    if current.as_ref() == Some(next) {
        return Ok(());
    }
    if current.as_ref() != before {
        return Err(crate::sync::runtime::superseded());
    }
    let value = Zeroizing::new(serde_json::to_string(next).map_err(|_| invalid())?);
    if value.len() > CAP {
        return Err(invalid());
    }
    env.keychain.set_noninteractive(&role(owner)?, &value)?;
    if read(env, owner)?.as_ref() != Some(next) {
        return Err(invalid());
    }
    Ok(())
}
fn frame(bytes: &[u8]) -> Result<Frame, AppError> {
    if bytes.len() > 80 * 1024 * 1024 || !bytes.starts_with(MAGIC) {
        return Err(invalid());
    }
    let v: Frame = serde_json::from_slice(&bytes[8..]).map_err(|_| invalid())?;
    if v.version != 1 {
        return Err(invalid());
    }
    Ok(v)
}
fn encode(source: &Receipt, body: Body) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let mut out = Zeroizing::new(MAGIC.to_vec());
    serde_json::to_writer(
        &mut *out,
        &Frame {
            version: 1,
            source: source.clone(),
            body,
        },
    )
    .map_err(|_| invalid())?;
    if out.len() > 80 * 1024 * 1024 {
        return Err(invalid());
    }
    Ok(out)
}
impl Loaded {
    fn owner(&self) -> Result<&Workspace, AppError> {
        self.package
            .state
            .local
            .central
            .as_ref()
            .ok_or_else(invalid)
    }
    fn current(&self, env: &SyncEnv, life: &MutexGuard<'_, ()>) -> Result<(), AppError> {
        let (state, generation) = record_runtime::snapshot(env)?;
        let session = controller::context(env)?;
        if state != self.package.state
            || generation != self.generation
            || !Arc::ptr_eq(&session, &self.session)
            || Cursor::load(env, life, self.owner()?)?
                .ok_or_else(invalid)?
                .cursor
                != self.state.source
            || read(env, self.owner()?)?.as_ref() != Some(&self.state)
        {
            return Err(crate::sync::runtime::superseded());
        }
        super::source_capture::require_selected(env, self.owner()?, &session)?;
        Ok(())
    }
    fn files(&self, env: &SyncEnv) -> Result<(), AppError> {
        self.package.files.require_unchanged_after_archive(
            env,
            self.package.state.legacy_v1_backup.as_deref(),
            &self.outputs,
        )
    }
    fn check(&self, env: &SyncEnv) -> Result<(), AppError> {
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        self.current(env, &life)?;
        self.files(env)
    }
    fn update(&mut self, env: &SyncEnv, next: State) -> Result<(), AppError> {
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        self.current(env, &life)?;
        self.files(env)?;
        save(env, self.owner()?, Some(&self.state), &next)?;
        self.state = next;
        Ok(())
    }
    fn body(&self, env: &SyncEnv, r: &Receipt) -> Result<Body, AppError> {
        if !self.state.archives.contains(r) {
            return Err(invalid());
        }
        let bytes = source_archive::restore(env, &self.owner()?.control.profile.profile()?, r)?;
        let value = frame(&bytes)?;
        if value.source != *self.state.source.receipt() {
            return Err(invalid());
        }
        Ok(value.body)
    }
    fn remote(&self, env: &SyncEnv) -> Result<Transcript, AppError> {
        match self.body(env, self.state.remote.as_ref().ok_or_else(invalid)?)? {
            Body::Remote(r) => Ok(r),
            _ => Err(invalid()),
        }
    }
    fn plan(
        &self,
        env: &SyncEnv,
        remote: &super::active_read::VerifiedLibrary,
    ) -> Result<merge::Plan, AppError> {
        self.plan_at(
            env,
            self.state.plan.as_ref().ok_or_else(invalid)?,
            remote,
            0,
        )
        .map(|(plan, _)| plan)
    }
    fn plan_at(
        &self,
        env: &SyncEnv,
        receipt: &Receipt,
        remote: &super::active_read::VerifiedLibrary,
        depth: usize,
    ) -> Result<(merge::Plan, Checkpoint), AppError> {
        if depth >= 8 {
            return Err(invalid());
        }
        match self.body(env, receipt)? {
            Body::Plan(p) => {
                p.verify(&self.package, remote)?;
                Ok((p, remote.checkpoint().clone()))
            }
            Body::Rebase {
                parent,
                transcript,
                completed,
                plan,
            } => {
                if parent.next_ordinal()? >= receipt.next_ordinal()? {
                    return Err(invalid());
                }
                let (prior, floor) = self.plan_at(env, &parent, remote, depth + 1)?;
                let read = transcript.verify(
                    self.owner()?,
                    self.session.identity.as_ref().ok_or_else(invalid)?,
                    Some(&floor),
                )?;
                prior.verify_rebase(&plan, &self.package, &read, &transcript, completed)?;
                Ok((plan, read.checkpoint().clone()))
            }
            _ => Err(invalid()),
        }
    }
    fn final_read(&self, env: &SyncEnv) -> Result<Transcript, AppError> {
        match self.body(env, self.state.final_read.as_ref().ok_or_else(invalid)?)? {
            Body::Final(r) => Ok(r),
            _ => Err(invalid()),
        }
    }
    fn pending(&self, env: &SyncEnv) -> Result<Option<Frame>, AppError> {
        let previous = self
            .state
            .archives
            .last()
            .unwrap_or(self.state.source.receipt());
        source_archive::candidate_next(
            env,
            self.owner()?,
            previous,
            previous.next_ordinal()?,
            &self.outputs,
        )?
        .map(|b| frame(&b))
        .transpose()
    }
    fn append(&mut self, env: &SyncEnv, body: Body) -> Result<(), AppError> {
        let encoded = encode(self.state.source.receipt(), body)?;
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        self.current(env, &life)?;
        self.outputs.require_room_for_snapshot(encoded.len())?;
        let previous = self
            .state
            .archives
            .last()
            .unwrap_or(self.state.source.receipt());
        let (archived, outputs) = if let Some(saved) = source_archive::resume_next(
            env,
            self.owner()?,
            previous,
            previous.next_ordinal()?,
            &encoded,
            &self.outputs,
        )? {
            saved
        } else {
            self.files(env)?;
            let saved = source_archive::next(
                env,
                &life,
                self.owner()?,
                previous.next_ordinal()?,
                previous,
                &encoded,
            )?;
            let outputs =
                saved.outputs(env, &self.owner()?.control.profile.profile()?, &encoded)?;
            (saved, outputs)
        };
        let mut next = self.state.clone();
        let receipt = archived.receipt().clone();
        match frame(&encoded)?.body {
            Body::Remote(_) => {
                if next.remote.is_some() {
                    return Err(invalid());
                }
                next.remote = Some(receipt.clone());
            }
            Body::Plan(_) => {
                if next.plan.is_some() {
                    return Err(invalid());
                }
                next.plan = Some(receipt.clone());
            }
            Body::Rebase { parent, .. } => {
                if !next.accepted
                    || next.plan.as_ref() != Some(&parent)
                    || next.final_read.is_some()
                {
                    return Err(invalid());
                }
                next.plan = Some(receipt.clone());
            }
            Body::Final(_) => {
                if next.final_read.is_some() {
                    return Err(invalid());
                }
                next.final_read = Some(receipt.clone());
            }
        }
        let combined = self.outputs.extended(outputs)?;
        self.package.files.require_unchanged_after_archive(
            env,
            self.package.state.legacy_v1_backup.as_deref(),
            &combined,
        )?;
        next.archives.push(receipt);
        save(env, self.owner()?, Some(&self.state), &next)?;
        self.outputs = combined;
        self.state = next;
        self.current(env, &life)?;
        self.files(env)
    }
}
fn load(env: &SyncEnv) -> Result<Option<Loaded>, AppError> {
    let life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (records, generation) = record_runtime::snapshot(env)?;
    let owner = records.local.central.as_ref().ok_or_else(invalid)?;
    let Some(state) = read(env, owner)? else {
        return Ok(None);
    };
    let source = Cursor::load(env, &life, owner)?.ok_or_else(invalid)?;
    if source.cursor != state.source {
        return Err(invalid());
    }
    let package = Package::decode_local(&source.bytes)?;
    if package.state != records {
        return Err(crate::sync::runtime::superseded());
    }
    let mut outputs = source.outputs;
    for receipt in &state.archives {
        let (bytes, proof) =
            source_archive::restore_with_outputs(env, &owner.control.profile.profile()?, receipt)?;
        let value = frame(&bytes)?;
        if value.source != *state.source.receipt() {
            return Err(invalid());
        }
        outputs = outputs.merge(proof)?;
    }
    Ok(Some(Loaded {
        state,
        package,
        outputs,
        generation,
        session: controller::context(env)?,
    }))
}
fn initialize(env: &SyncEnv, scope: &Scope, reading: &Reading) -> Result<Loaded, AppError> {
    scope.check(env)?;
    let captured = super::source_capture::capture_adoption(env, reading.keys()?, &BTreeMap::new())?;
    let life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    scope.check(env)?;
    captured.require_current(env)?;
    let owner = captured
        .package
        .state
        .local
        .central
        .as_ref()
        .ok_or_else(invalid)?;
    if reading.before() != owner {
        return Err(crate::sync::runtime::superseded());
    }
    if let Some(state) = read(env, owner)? {
        drop(_publication);
        drop(_vault);
        drop(life);
        let _ = state;
        return load(env)?.ok_or_else(invalid);
    }
    env.runtime.core.lock().unwrap().central_migration_frozen = true;
    let source = captured.package.initialize_source(env, &life, owner, 0)?;
    let state = State {
        version: 1,
        policy: "device-adoption-v1".into(),
        source: source.cursor,
        floor: reading.checkpoint()?,
        archives: vec![],
        remote: None,
        plan: None,
        final_read: None,
        ticket: super::crypto::random_id(32)?,
        accepted: false,
        completed: 0,
        operation: super::crypto::random_id(16)?,
        observed: env.now(),
    };
    save(env, owner, None, &state)?;
    Ok(Loaded {
        state,
        package: captured.package,
        outputs: source.outputs,
        generation: captured.generation,
        session: captured.session,
    })
}
fn read_remote(
    env: &SyncEnv,
    scope: &Scope,
    loaded: Option<&Loaded>,
    budget: &Budget,
) -> Result<Option<(super::active_read::VerifiedLibrary, Transcript)>, AppError> {
    scope.check(env)?;
    super::round::check_cooldown(env)?;
    let selected = controller::context(env)?;
    let owner = record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)?;
    let check = || {
        scope.check(env)?;
        if let Some(l) = loaded {
            l.check(env)?;
        }
        Ok(())
    };
    let saved = env.runtime.core.lock().unwrap().adoption_read.take();
    let mut reading = match saved {
        Some(cache)
            if cache.reading.before() == &owner
                && Arc::ptr_eq(cache.reading.session(), &selected) =>
        {
            cache.reading
        }
        _ => {
            let mut r = Reading::begin_bounded(env, OwnerPath::Current, selected, &check, budget)?;
            r.capture(
                loaded
                    .map(|l| vec![l.state.floor.clone()])
                    .unwrap_or_default(),
            )?;
            r
        }
    };
    if reading.total() == 0 {
        return Ok(None);
    }
    let result = reading.advance_bounded(env, &check, budget);
    match result {
        Ok(true) => Ok(Some(reading.finish_captured()?)),
        Ok(false) => {
            scope.check(env)?;
            env.runtime.core.lock().unwrap().adoption_read =
                Some(Box::new(ReadingCache { reading }));
            Ok(None)
        }
        Err(e) if Budget::exhausted(&e) => {
            scope.check(env)?;
            env.runtime.core.lock().unwrap().adoption_read =
                Some(Box::new(ReadingCache { reading }));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
fn observed(plan: &merge::Plan, transcript: &Transcript) -> Result<usize, AppError> {
    let expected: BTreeMap<_, _> = plan
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.header.operation_id.as_str(), (i, r)))
        .collect();
    let mut prefix = 0;
    for row in transcript.pages.iter().flat_map(|p| &p.records) {
        if let Some((index, known)) = expected.get(row.envelope.header.operation_id.as_str()) {
            if *index != prefix || *known != &row.envelope {
                return Err(invalid());
            }
            prefix += 1;
        }
    }
    Ok(prefix)
}
fn review_history(
    loaded: &Loaded,
    remote: &super::active_read::VerifiedLibrary,
    transcript: &Transcript,
) -> Result<Vec<(super::payload::Identity, super::payload::Data)>, AppError> {
    let mut history = vec![];
    for row in transcript.pages.iter().flat_map(|p| &p.records) {
        let author = remote
            .chain()
            .author_at(
                &row.envelope.header.membership_head,
                &row.envelope.header.author,
            )
            .ok_or_else(invalid)?;
        let plain = row.envelope.verify(&author.signing)?.open(remote.keys())?;
        let admitted = super::payload::admit(remote.keys(), &row.envelope.header, &plain)?;
        history.push((admitted.identity, admitted.data));
    }
    history.extend(merge::history(
        &loaded.package,
        remote,
        &loaded.state.operation,
    )?);
    Ok(history)
}
fn progress(loaded: &Loaded, total: usize, phase: &'static str) -> Progress {
    Progress {
        phase,
        mode: "join",
        legacy_sources: false,
        total: total.max(if loaded.state.remote.is_some() {
            loaded.state.floor.sequence as usize
        } else {
            0
        }),
        staged: loaded.state.completed,
        verified: if loaded.state.remote.is_some() {
            loaded.state.floor.sequence as usize
        } else {
            0
        },
        approved: loaded.state.accepted,
    }
}
fn result(
    env: &SyncEnv,
    scope: &Scope,
    progress: Progress,
    review: Option<review::Preview>,
) -> Result<Preparation, AppError> {
    Ok(Preparation {
        progress: migration_flow::cached(env, scope, progress)?,
        review,
    })
}
pub(super) fn run(
    env: &SyncEnv,
    scope: &Scope,
    action: Action,
    budget: &Budget,
) -> Result<Preparation, AppError> {
    let outcome = run_once(env, scope, action, budget);
    if outcome.is_err() && budget.take_refusal() {
        super::round::check_cooldown(env)?;
        if controller::resume_bounded(env, true, budget)? {
            scope.check(env)?;
            return run_once(env, scope, action, budget);
        }
    }
    outcome
}
fn run_once(
    env: &SyncEnv,
    scope: &Scope,
    action: Action,
    budget: &Budget,
) -> Result<Preparation, AppError> {
    scope.check(env)?;
    if !controller::resume_bounded(env, false, budget)? {
        return Err(invalid());
    }
    scope.check(env)?;
    let mut loaded = load(env)?;
    if loaded.is_none() {
        if !matches!(action, Action::Prepare) && !super::migration_flow::pending(env)? {
            return Err(AppError::Other(
                "Review this device before joining the encrypted library.".into(),
            ));
        }
        // Capture a ready authenticated metadata view before freezing any local library.
        let selected = controller::context(env)?;
        let check = || scope.check(env).map(|_| ());
        let mut reading =
            Reading::begin_bounded(env, OwnerPath::Current, selected, &check, budget)?;
        if reading.total() == 0 {
            return result(
                env,
                scope,
                Progress {
                    phase: "waiting",
                    mode: "join",
                    ..Progress::default()
                },
                None,
            );
        }
        reading.capture(vec![])?;
        let next = initialize(env, scope, &reading)?;
        env.runtime.core.lock().unwrap().adoption_read = Some(Box::new(ReadingCache { reading }));
        loaded = Some(next);
    }
    continue_loaded(env, scope, action, budget, loaded.ok_or_else(invalid)?)
}
fn continue_loaded(
    env: &SyncEnv,
    scope: &Scope,
    action: Action,
    budget: &Budget,
    mut loaded: Loaded,
) -> Result<Preparation, AppError> {
    if loaded.state.final_read.is_none() && loaded.pending(env)?.is_none() {
        loaded.check(env)?;
    }
    if loaded.state.remote.is_none() {
        if let Some(candidate) = loaded.pending(env)? {
            if candidate.source != *loaded.state.source.receipt() {
                return Err(invalid());
            }
            match candidate.body {
                Body::Remote(r) => {
                    r.verify(
                        loaded.owner()?,
                        loaded.session.identity.as_ref().ok_or_else(invalid)?,
                        Some(&loaded.state.floor),
                    )?;
                    loaded.append(env, Body::Remote(r))?;
                }
                _ => return Err(invalid()),
            }
        } else {
            let Some((remote, transcript)) = read_remote(env, scope, Some(&loaded), budget)? else {
                return result(
                    env,
                    scope,
                    progress(&loaded, loaded.state.floor.sequence as usize, "reading"),
                    None,
                );
            };
            if remote.auth_epoch() != loaded.owner()?.control.auth_epoch {
                return Err(crate::sync::runtime::superseded());
            }
            let mut next = loaded.state.clone();
            next.floor = remote.checkpoint().clone();
            loaded.update(env, next)?;
            loaded.append(env, Body::Remote(transcript))?;
        }
    }
    let original = loaded.remote(env)?;
    let remote = original.verify(
        loaded.owner()?,
        loaded.session.identity.as_ref().ok_or_else(invalid)?,
        None,
    )?;
    if loaded.state.plan.is_none() {
        let plan = if let Some(candidate) = loaded.pending(env)? {
            if candidate.source != *loaded.state.source.receipt() {
                return Err(invalid());
            }
            match candidate.body {
                Body::Plan(p) => {
                    p.verify(&loaded.package, &remote)?;
                    p
                }
                _ => return Err(invalid()),
            }
        } else {
            merge::Plan::create(
                &loaded.package,
                &remote,
                &loaded.session.identity.as_ref().ok_or_else(invalid)?.keys,
                &loaded.state.operation,
            )?
        };
        loaded.append(env, Body::Plan(plan))?;
    }
    // Recover an exact orphan adjustment before any further local or remote effect.
    if let Some(candidate) = loaded.pending(env)? {
        if candidate.source != *loaded.state.source.receipt() {
            return Err(invalid());
        }
        if let Body::Rebase {
            parent,
            transcript,
            completed,
            plan,
        } = candidate.body
        {
            if loaded.state.plan.as_ref() != Some(&parent) {
                return Err(invalid());
            }
            let prior = loaded.plan(env, &remote)?;
            let read = transcript.verify(
                loaded.owner()?,
                loaded.session.identity.as_ref().ok_or_else(invalid)?,
                Some(&loaded.state.floor),
            )?;
            prior.verify_rebase(&plan, &loaded.package, &read, &transcript, completed)?;
            loaded.append(
                env,
                Body::Rebase {
                    parent,
                    transcript,
                    completed,
                    plan,
                },
            )?;
        }
    }
    let plan = loaded.plan(env, &remote)?;
    let total = remote.checkpoint().sequence as usize + plan.rows.len();
    if !loaded.state.accepted || matches!(action, Action::Prepare) {
        let preview = if matches!(action, Action::Prepare) {
            Some(review::from_history(
                loaded.state.ticket.clone(),
                loaded.state.accepted,
                &review_history(&loaded, &remote, &original)?,
            )?)
        } else {
            None
        };
        return result(
            env,
            scope,
            progress(
                &loaded,
                total,
                if loaded.state.accepted {
                    "staging"
                } else {
                    "review"
                },
            ),
            preview,
        );
    }
    if loaded.state.final_read.is_none() {
        if let Some(candidate) = loaded.pending(env)? {
            if candidate.source != *loaded.state.source.receipt() {
                return Err(invalid());
            }
            match candidate.body {
                Body::Final(t) => {
                    let verified = t.verify(
                        loaded.owner()?,
                        loaded.session.identity.as_ref().ok_or_else(invalid)?,
                        Some(&loaded.state.floor),
                    )?;
                    if observed(&plan, &t)? != plan.rows.len() {
                        return Err(invalid());
                    }
                    let _ = verified;
                    loaded.append(env, Body::Final(t))?;
                }
                _ => return Err(invalid()),
            }
        } else {
            let Some((read, transcript)) = read_remote(env, scope, Some(&loaded), budget)? else {
                return result(env, scope, progress(&loaded, total, "reading"), None);
            };
            let completed = observed(&plan, &transcript)?;
            if completed < loaded.state.completed {
                return Err(invalid());
            }
            let mut next = loaded.state.clone();
            next.completed = completed;
            next.floor = read.checkpoint().clone();
            loaded.update(env, next)?;
            if completed == plan.rows.len() {
                loaded.append(env, Body::Final(transcript))?;
            } else {
                if plan.needs_rebase(&read, completed)? {
                    let adjusted = plan.rebase(
                        &loaded.package,
                        &read,
                        &transcript,
                        completed,
                        &loaded.session.identity.as_ref().ok_or_else(invalid)?.keys,
                    )?;
                    let parent = loaded.state.plan.clone().ok_or_else(invalid)?;
                    // Leave capacity for the final authenticated read before sending more data.
                    if loaded.state.archives.len() >= 7 {
                        return Err(AppError::Other("The library kept changing during this merge. Original data and verified progress are retained; finish other-device edits before continuing.".into()));
                    }
                    loaded.append(
                        env,
                        Body::Rebase {
                            parent,
                            transcript,
                            completed,
                            plan: adjusted,
                        },
                    )?;
                    return result(env, scope, progress(&loaded, total, "staging"), None);
                }
                let mut batch = vec![];
                let mut seen = std::collections::BTreeSet::new();
                let mut bytes = 0;
                for row in plan.rows.iter().skip(completed).take(32) {
                    let size = serde_json::to_vec(row).map_err(|_| invalid())?.len();
                    if !seen.insert(&row.header.record_id)
                        || !batch.is_empty() && bytes + size > 1024 * 1024
                    {
                        break;
                    }
                    bytes += size;
                    batch.push(row.clone());
                }
                loaded.check(env)?;
                scope.check(env)?;
                let reply = Api::bounded(&loaded.owner()?.control.profile.origin, budget)?.push(
                    loaded.session.device.as_ref().ok_or_else(invalid)?,
                    &read.replica().vault,
                    &batch,
                )?;
                loaded.check(env)?;
                super::round::require_success(env, &reply)?;
                return result(env, scope, progress(&loaded, total, "staging"), None);
            }
        }
    }
    publish(env, scope, budget, loaded, plan, total)
}
fn publish(
    env: &SyncEnv,
    scope: &Scope,
    budget: &Budget,
    loaded: Loaded,
    plan: merge::Plan,
    total: usize,
) -> Result<Preparation, AppError> {
    let transcript = loaded.final_read(env)?;
    let final_read = transcript.verify(
        loaded.owner()?,
        loaded.session.identity.as_ref().ok_or_else(invalid)?,
        Some(&loaded.state.floor),
    )?;
    if observed(&plan, &transcript)? != plan.rows.len() {
        return Err(invalid());
    }
    let commitment = loaded
        .state
        .plan
        .as_ref()
        .ok_or_else(invalid)?
        .ciphertext_hash
        .clone();
    let initial = Candidate::adopt(
        &loaded.package.state,
        &final_read,
        &commitment,
        loaded.state.observed,
        &merge::selections(&loaded.package.state, &loaded.state.operation)?,
    )?;
    let prepared = Prepared {
        loaded,
        initial,
        proof: transcript,
    };
    let keys = final_read.keys();
    migration_flow::cached(env, scope, progress(&prepared.loaded, total, "publishing"))?;
    fence(env, scope, &prepared, budget)?;
    crate::sync::record_import::central_stage::prepare_initial_reserved(env, &prepared, keys)?;
    fence(env, scope, &prepared, budget)?;
    crate::sync::record_import::central_stage::publish_initial(env, &prepared, keys)?;
    result(
        env,
        scope,
        Progress {
            phase: "complete",
            mode: "join",
            approved: true,
            total,
            staged: plan.rows.len(),
            verified: total,
            ..Progress::default()
        },
        None,
    )
}
pub(super) fn confirm(env: &SyncEnv, scope: &Scope, ticket: &str) -> Result<Progress, AppError> {
    scope.check(env)?;
    if !hex(ticket, 64) {
        return Err(invalid());
    }
    let mut loaded = load(env)?.ok_or_else(invalid)?;
    loaded.check(env)?;
    if loaded.state.ticket != ticket || loaded.state.plan.is_none() {
        return Err(invalid());
    }
    let original = loaded.remote(env)?;
    let remote = original.verify(
        loaded.owner()?,
        loaded.session.identity.as_ref().ok_or_else(invalid)?,
        None,
    )?;
    let plan = loaded.plan(env, &remote)?;
    let mut next = loaded.state.clone();
    next.accepted = true;
    loaded.update(env, next)?;
    migration_flow::cached(
        env,
        scope,
        progress(
            &loaded,
            remote.checkpoint().sequence as usize + plan.rows.len(),
            "staging",
        ),
    )
}
impl initial_transaction::sealed::Sealed for Prepared {}
impl InitialTransaction for Prepared {
    fn projection(&self) -> &Candidate {
        &self.initial
    }
    fn operation(&self) -> &str {
        &self.loaded.state.operation
    }
    fn generation(&self) -> u64 {
        self.loaded.generation
    }
    fn session(&self) -> &Arc<Session> {
        &self.loaded.session
    }
    fn check_identity_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &MutexGuard<'_, ()>,
    ) -> Result<(), AppError> {
        self.loaded.current(env, life)?;
        if !self.loaded.state.accepted
            || self.loaded.state.final_read.is_none()
            || self.initial.source() != &self.loaded.package.state
            || self.initial.observed() != self.loaded.state.observed
            || self.initial.manifest()
                != self
                    .loaded
                    .state
                    .plan
                    .as_ref()
                    .ok_or_else(invalid)?
                    .ciphertext_hash
        {
            return Err(invalid());
        }
        let read = self.proof.verify(
            self.loaded.owner()?,
            self.loaded.session.identity.as_ref().ok_or_else(invalid)?,
            Some(&self.loaded.state.floor),
        )?;
        read.keys().verify_same(keys)?;
        Ok(())
    }
    fn check_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &MutexGuard<'_, ()>,
    ) -> Result<(), AppError> {
        self.check_identity_locked(env, keys, life)?;
        self.loaded.files(env)
    }
    fn original_import_root(&self) -> bool {
        self.loaded
            .package
            .files
            .directories
            .contains(Path::new("data/imports"))
    }
    fn original_state<'a>(&'a self, env: &SyncEnv) -> Result<&'a [u8], AppError> {
        self.loaded
            .package
            .files
            .bytes
            .get(&Path::new("data").join(env.state_path.file_name().ok_or_else(invalid)?))
            .map(|b| b.as_slice())
            .ok_or_else(invalid)
    }
    fn original_vault<'a>(&'a self, env: &SyncEnv) -> Result<Option<&'a [u8]>, AppError> {
        Ok(self
            .loaded
            .package
            .files
            .bytes
            .get(
                &Path::new("data").join(
                    crate::vault::store::vault_path(&env.state_path)
                        .file_name()
                        .ok_or_else(invalid)?,
                ),
            )
            .map(|b| b.as_slice()))
    }
    fn verify_files_at(
        &self,
        state: &Path,
        ssh: &Path,
        effects: &crate::sync::record_import::central_stage::InitialEffects,
    ) -> Result<(), AppError> {
        effects.matches(&self.initial, self.operation())?;
        self.loaded
            .package
            .files
            .require_unchanged_after_initial_at(
                state,
                ssh,
                self.loaded.package.state.legacy_v1_backup.as_deref(),
                &self.loaded.outputs,
                effects,
            )
    }
}
pub(super) fn verify_saved(
    env: &SyncEnv,
    life: &MutexGuard<'_, ()>,
    current: &Workspace,
    original: &SyncStateV3,
    operation: &str,
    manifest: &str,
    observed: u64,
) -> Result<(), AppError> {
    let before = original.local.central.as_ref().ok_or_else(invalid)?;
    let state = read(env, before)?.ok_or_else(invalid)?;
    if !current.control.cutover
        || current.control.profile != before.control.profile
        || current.control.anchor != before.control.anchor
        || current.control.device != before.control.device
        || current.identity_slot != before.identity_slot
        || state.operation != operation
        || state.observed != observed
        || !state.accepted
        || state.final_read.is_none()
        || state
            .plan
            .as_ref()
            .is_none_or(|r| r.ciphertext_hash != manifest)
        || Cursor::load(env, life, before)?.ok_or_else(invalid)?.cursor != state.source
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn complete_saved(env: &SyncEnv) -> Result<(), AppError> {
    let records = record_runtime::snapshot(env)?.0;
    let owner = records.local.central.as_ref().ok_or_else(invalid)?;
    let Some(encoded) = env
        .keychain
        .get_noninteractive(&role(owner)?)?
        .map(Zeroizing::new)
    else {
        return Ok(());
    };
    if encoded.len() > CAP {
        return Err(invalid());
    }
    let state: State = serde_json::from_str(&encoded).map_err(|_| invalid())?;
    if state.version != 1 || state.policy != "device-adoption-v1" || !hex(&state.operation, 32) {
        return Err(invalid());
    }
    crate::sync::record_import::central_stage::complete_initial_saved(env, &state.operation)?;
    Ok(())
}
#[cfg(all(test, unix))]
mod tests;

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
fn fence(
    env: &SyncEnv,
    scope: &Scope,
    prepared: &Prepared,
    budget: &Budget,
) -> Result<(), AppError> {
    let check = || -> Result<(), AppError> {
        scope.check(env)?;
        let path = env
            .state_path
            .parent()
            .ok_or_else(invalid)?
            .join("imports")
            .join(prepared.operation());
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                drop(crate::sync::record_import::central_stage::initial_effects(
                    env,
                    prepared,
                    prepared
                        .proof
                        .verify(
                            prepared.loaded.owner()?,
                            prepared
                                .loaded
                                .session
                                .identity
                                .as_ref()
                                .ok_or_else(invalid)?,
                            Some(&prepared.loaded.state.floor),
                        )?
                        .keys(),
                )?);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => prepared.loaded.check(env)?,
            Err(e) => return Err(e.into()),
        }
        Ok(())
    };
    check()?;
    super::round::check_cooldown(env)?;
    let session = &prepared.loaded.session;
    let grant = session.device.as_ref().ok_or_else(invalid)?;
    let api = Api::bounded(&session.profile.origin, budget)?;
    let reply = api.account(grant)?;
    super::round::require_success(env, &reply)?;
    let account: super::api::AccountOverview = reply.decode()?;
    account.validate(grant)?;
    let snapshot = &prepared.proof.snapshot;
    if account.proof.as_ref() != Some(&prepared.proof.proof)
        || account.auth_epoch != snapshot.auth_epoch
        || account.phase != "ready"
        || account.barrier.is_some()
        || account
            .denied
            .contains(&prepared.loaded.owner()?.control.device.id)
        || account.vaults.len() != 1
        || account
            .vaults
            .get(&snapshot.vault.vault)
            .is_none_or(|v| v.epoch != snapshot.vault.epoch)
    {
        return Err(crate::sync::runtime::superseded());
    }
    check()?;
    let reply = api.vault(grant, &snapshot.vault.vault, VaultResource::Metadata)?;
    super::round::require_success(env, &reply)?;
    let metadata: Metadata = reply.decode()?;
    let sequence = number(&metadata.sequence, true)?;
    let minimum = number(&snapshot.vault.sequence, true)?;
    if metadata.vault != snapshot.vault.vault
        || metadata.epoch != snapshot.vault.epoch
        || metadata.membership_head != snapshot.membership_head
        || number(&metadata.authorization_epoch, false)? != snapshot.auth_epoch
        || metadata.phase != "ready"
        || sequence < minimum
        || sequence == minimum && metadata.history_hash != snapshot.vault.history_hash
        || !hex(&metadata.history_hash, 64)
    {
        return Err(crate::sync::runtime::superseded());
    }
    check()
}
