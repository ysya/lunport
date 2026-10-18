//! Typed records transport only: no SSH files, slot maintenance, agent wiring or vault access.
use crate::error::AppError;
use crate::sync::crypto::ChainKeys;
use crate::sync::env::SyncEnv;
use crate::sync::record_merge::AccountGate;

#[derive(Clone, Debug)]
pub struct FreshAccountProof {
    pub keys: ChainKeys,
    pub relay_url: String,
    pub gate: AccountGate,
    /// Authenticated format result, before local freeze/rotation policy. Only local detach uses it.
    pub format_gate: AccountGate,
    pub observed_schema: Option<u32>,
}
impl FreshAccountProof {
    pub fn ensure_compatible(&self) -> Result<(), AppError> {
        if self.gate == AccountGate::Compatible {
            Ok(())
        } else {
            Err(AppError::Other("record account is not writable".into()))
        }
    }
}
#[derive(Clone, Debug)]
pub struct RecordRoundReport {
    pub gate: Option<AccountGate>,
    pub spaces_pulled: usize,
    pub pushed: usize,
    pub conflicts: usize,
    pub review_required: bool,
}
const TEMPORARY_SPACE_ERROR: &str = "This space is temporarily unavailable. Cached records are kept; sync will retry automatically.";
const OLD_MISSING_SPACE_ERROR: &str = "the selected record space is missing from the relay";

fn error(message: &str) -> AppError {
    AppError::Other(message.into())
}
fn gate_message(gate: &AccountGate) -> &'static str {
    match gate {
        AccountGate::Compatible => "",
        AccountGate::NeedsMigration { .. } => "this account needs an explicit record migration",
        AccountGate::NeedsUpdate { .. } => "this account uses a newer format; update Lunport",
        AccountGate::MigrationPending(_) => "account migration is still being published",
        AccountGate::InvalidMigration => "the account migration marker is invalid or unavailable",
        AccountGate::InvalidPull => "the relay returned inconsistent record transport metadata",
        AccountGate::RecoveryFull => "Sync recovery storage is full. Resolve saved conflicts or free space; existing versions have been kept.",
    }
}
/// Check the only write boundary in this transport before credential/network callbacks.
/// No SSH config, agent or vault path is touched by active record transport.
pub(crate) fn preflight(env: &SyncEnv) -> Result<(), AppError> {
    crate::fsutil::check_write(&env.state_path)?;
    require_no_pending_migration(env)?;
    match std::fs::symlink_metadata(&env.state_path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(error("record state must be a regular file"))
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut core = env.runtime.core.lock().unwrap();
    if let Some(reason) = &core.save_blocked {
        return Err(error(reason));
    }
    crate::sync::record_runtime::active_state(&core)?;
    if core.generation == u64::MAX {
        return Err(error("record state generation exhausted"));
    }
    if core.unsaved {
        crate::sync::runtime::save_core(&mut core, &env.state_path)?;
    }
    Ok(())
}
/// Call while holding lifecycle. Bounded journal inspection precedes credentials and shared IO.
pub(crate) fn require_no_pending_migration(env: &SyncEnv) -> Result<(), AppError> {
    if !crate::sync::record_migration::pending_migrations(env)?.is_empty() {
        return Err(error(
            "finish the pending account migration before changing shared data",
        ));
    }
    Ok(())
}
fn same_account(state: &crate::sync::records_v3::SyncStateV3, chain: &str, url: &str) -> bool {
    state.relay_url == url && state.account.as_ref().is_some_and(|a| a.chain_id == chain)
}
fn read_keys_from(
    keychain: &dyn crate::sync::env::Keychain,
    state: &crate::sync::records_v3::SyncStateV3,
) -> Result<ChainKeys, AppError> {
    let account = state
        .account
        .as_ref()
        .ok_or_else(|| error("join or create a record account first"))?;
    let phrase = zeroize::Zeroizing::new(
        keychain
            .get(crate::sync::state::MNEMONIC_ACCOUNT)
            .map_err(|_| error("the sync code could not be read"))?
            .ok_or_else(|| error("the sync code is unavailable on this device"))?,
    );
    let keys = crate::sync::crypto::derive_account(&phrase)
        .map_err(|_| error("the sync code is invalid"))?;
    if keys.chain_id != account.chain_id {
        return Err(error("the sync code belongs to a different account"));
    }
    Ok(keys)
}
fn publish_gate(
    state: &mut crate::sync::records_v3::SyncStateV3,
    gate: &AccountGate,
    schema: Option<u32>,
) {
    state.shared_writes_blocked = *gate != AccountGate::Compatible;
    state.migration_gate = match gate {
        AccountGate::MigrationPending(marker) => Some(marker.clone()),
        _ => None,
    };
    if let (Some(account), Some(schema)) = (
        &mut state.account,
        schema.filter(|v| *v > crate::sync::records_v3::ACCOUNT_SCHEMA),
    ) {
        account.remote_schema_version =
            Some(account.remote_schema_version.unwrap_or(0).max(schema));
    }
    state.last_error = (*gate != AccountGate::Compatible).then(|| gate_message(gate).into());
}
fn fail_closed(env: &SyncEnv, chain: &str, url: &str, gate: &AccountGate, schema: Option<u32>) {
    let mut core = env.runtime.core.lock().unwrap();
    if let Some(state) = core
        .records
        .as_mut()
        .filter(|state| same_account(state, chain, url))
    {
        publish_gate(state, gate, schema);
        core.save_blocked = Some(
            "an authenticated account gate could not be saved; restart after fixing record storage"
                .into(),
        );
    }
}
/// Always authenticates account metadata from a full account pull. It intentionally does not own
/// lifecycle; shared command callers own lifecycle across this proof and their subsequent mutation.
/// Publication owns publication -> core only, and never waits for vault/doc while holding it.
pub fn fresh_account_gate(env: &SyncEnv) -> Result<FreshAccountProof, AppError> {
    preflight(env)?;
    let (snapshot, _) = crate::sync::record_runtime::snapshot(env)?;
    let prepared = prepare_account_gate(env, env.keychain, snapshot)?;
    publish_prepared_account_gate(env, prepared)
}
/// Credential and network work only. This phase must not publish account state or own lifecycle.
pub(crate) struct PreparedAccountGate {
    snapshot: crate::sync::records_v3::SyncStateV3,
    keys: ChainKeys,
    pulled: crate::sync::relay::PullResponse,
}
pub(crate) fn prepare_account_gate(
    env: &SyncEnv,
    credentials: &dyn crate::sync::env::Keychain,
    snapshot: crate::sync::records_v3::SyncStateV3,
) -> Result<PreparedAccountGate, AppError> {
    let keys = read_keys_from(credentials, &snapshot)?;
    let relay = env.relay(&snapshot.relay_url)?;
    let pulled = relay.pull(&keys.chain_id, &keys.auth_token, 0)?;
    Ok(PreparedAccountGate {
        snapshot,
        keys,
        pulled,
    })
}
/// Local publication only: merge into current state of the same account. Callers bind any
/// operation-specific approval to its own route/key identity before their subsequent write.
pub(crate) fn publish_prepared_account_gate(
    env: &SyncEnv,
    prepared: PreparedAccountGate,
) -> Result<FreshAccountProof, AppError> {
    let PreparedAccountGate {
        snapshot,
        keys,
        pulled,
        ..
    } = prepared;
    let mut observed = None;
    let mut gate = AccountGate::InvalidPull;
    let mut format_gate = AccountGate::InvalidPull;
    let _publication = env.runtime.format_publication.lock().unwrap();
    let transform = |latest: &crate::sync::records_v3::SyncStateV3| {
        if !same_account(latest, &keys.chain_id, &snapshot.relay_url) {
            return Err(crate::sync::runtime::superseded());
        }
        let section = latest.account.as_ref().unwrap();
        let merged = crate::sync::record_merge::merge_account(section, &keys, &pulled, 0);
        format_gate = merged.gate.clone();
        gate = merged.gate;
        observed = merged.observed_schema;
        if format_gate == AccountGate::Compatible
            && (latest.rotation.is_some() || section.frozen.is_some())
        {
            gate = AccountGate::InvalidMigration;
        }
        let mut next = latest.clone();
        if format_gate == AccountGate::Compatible {
            next.account = Some(merged.section);
            // Discovery is passive. New spaces are unselected; deleted spaces retain every cache.
            for row in next
                .account
                .as_ref()
                .unwrap()
                .records
                .values()
                .filter(|r| r.record.kind == crate::sync::record::RecordKind::Space)
            {
                if row.record.deleted {
                    if let Some(space) = next.spaces.get_mut(&row.record.id) {
                        space.missing = true;
                        space.last_error = None;
                    }
                } else {
                    let space = next.spaces.entry(row.record.id.clone()).or_default();
                    // Older clients treated an ambiguous transport 404 as permanent deletion.
                    // Authenticated live metadata permits a retry, never a new chain creation.
                    if space.missing && space.last_error.as_deref() == Some(OLD_MISSING_SPACE_ERROR) {
                        space.missing = false;
                    }
                }
            }
        }
        crate::sync::record_library::select_library_spaces(&mut next);
        publish_gate(&mut next, &gate, observed);
        Ok(next)
    };
    let result = crate::sync::record_runtime::mutate_records(env, transform);
    if let Err(e) = result {
        if gate != AccountGate::Compatible && !crate::sync::runtime::is_superseded(&e) {
            fail_closed(env, &keys.chain_id, &snapshot.relay_url, &gate, observed);
        }
        return Err(e);
    }
    let mut core = env.runtime.core.lock().unwrap();
    if core
        .records
        .as_ref()
        .is_some_and(|state| same_account(state, &keys.chain_id, &snapshot.relay_url))
    {
        core.account_keys = Some(keys.clone());
    }
    Ok(FreshAccountProof {
        keys,
        relay_url: snapshot.relay_url,
        gate,
        format_gate,
        observed_schema: observed,
    })
}
fn section_commit(
    env: &SyncEnv,
    proof: &FreshAccountProof,
    transform: impl FnOnce(
        &crate::sync::records_v3::SyncStateV3,
    ) -> Result<crate::sync::records_v3::SyncStateV3, AppError>,
) -> Result<(), AppError> {
    let _publication = env.runtime.format_publication.lock().unwrap();
    crate::sync::record_runtime::mutate_records(env, |latest| {
        if !same_account(latest, &proof.keys.chain_id, &proof.relay_url) {
            return Err(crate::sync::runtime::superseded());
        }
        if crate::sync::records_v3::account_writes_blocked(latest) {
            return Err(error("record account shared writes are blocked"));
        }
        transform(latest)
    })
    .map(|_| ())
}
/// Remote acceptance already happened. Retain exact receipts in current memory on disk failure;
/// core.unsaved makes the next round retry persistence before any credential/network callback.
pub(crate) fn receipt_commit(
    env: &SyncEnv,
    proof: &FreshAccountProof,
    space_id: Option<&str>,
    keys: &ChainKeys,
    sent: &[crate::sync::record_merge::TypedOutgoing],
    pushed: &crate::sync::merge::Pushed,
) -> Result<(), AppError> {
    let mut core = env.runtime.core.lock().unwrap();
    if let Some(reason) = &core.save_blocked {
        return Err(error(reason));
    }
    let latest = crate::sync::record_runtime::active_state(&core)?;
    if !same_account(latest, &proof.keys.chain_id, &proof.relay_url) {
        return Err(crate::sync::runtime::superseded());
    }
    let mut next = latest.clone();
    let conflict_result;
    if let Some(id) = space_id {
        let section = next
            .spaces
            .get_mut(id)
            .ok_or_else(crate::sync::runtime::superseded)?;
        *section = crate::sync::record_merge::apply_space_receipts(section, sent, pushed);
        conflict_result = crate::sync::record_merge::retain_push_conflicts(&mut section.records, &mut section.sealed, &mut section.recovery, keys, false, sent, pushed);
    } else {
        let account = next.account.as_mut().unwrap();
        *account = crate::sync::record_merge::apply_account_receipts(account, sent, pushed);
        conflict_result = crate::sync::record_merge::retain_push_conflicts(&mut account.records, &mut account.sealed, &mut account.recovery, keys, true, sent, pushed);
    }
    crate::sync::record_conflicts::upgrade_state(&mut next);
    crate::sync::records_v3::validate_state(&next)
        .map_err(|_| error("cannot retain invalid typed receipts"))?;
    let generation = core
        .generation
        .checked_add(1)
        .ok_or_else(|| error("record state generation exhausted"))?;
    core.records = Some(next);
    core.generation = generation;
    crate::sync::runtime::save_core(&mut core, &env.state_path)?;
    conflict_result
}
fn push_section(
    env: &SyncEnv,
    proof: &FreshAccountProof,
    space_id: Option<&str>,
    keys: &ChainKeys,
    sent: &[crate::sync::record_merge::TypedOutgoing],
    report: &mut RecordRoundReport,
) -> Result<bool, AppError> {
    if sent.is_empty() {
        return Ok(true);
    }
    let fresh = fresh_account_gate(env)?;
    report.gate = Some(fresh.gate.clone());
    if fresh.ensure_compatible().is_err() {
        return Ok(false);
    }
    preflight(env)?;
    let (latest, _) = crate::sync::record_runtime::snapshot(env)?;
    if !same_account(&latest, &proof.keys.chain_id, &proof.relay_url) {
        return Err(crate::sync::runtime::superseded());
    }
    if crate::sync::records_v3::account_writes_blocked(&latest) {
        return Err(error("record account shared writes are blocked"));
    }
    if space_id.is_some()
        && sent
            .iter()
            .any(|row| row.outgoing.item.kind == "group" || row.outgoing.item.kind == "host")
    {
        let account = latest
            .account
            .as_ref()
            .ok_or_else(|| error("account missing"))?;
        let meta = account.records.get(&crate::sync::record::record_key(
            crate::sync::record::RecordKind::Meta,
            crate::sync::record::ACCOUNT_META_ID,
        ));
        let needs_gate = latest.spaces.values().any(|s| {
            s.records.values().any(|r| {
                r.record.kind == crate::sync::record::RecordKind::Group
                    || r.record
                        .payload
                        .get("schema")
                        .and_then(serde_json::Value::as_u64)
                        == Some(3)
            })
        });
        if needs_gate
            && !meta.is_some_and(|m| {
                !m.dirty
                    && m.record
                        .payload
                        .get("schema_version")
                        .and_then(serde_json::Value::as_u64)
                        == Some(4)
            })
        {
            return Err(error("group account schema gate has not been acknowledged"));
        }
    }
    let relay = env.relay(&proof.relay_url)?;
    let outgoing: Vec<_> = sent.iter().map(|row| row.outgoing.clone()).collect();
    let mut pushed =
        crate::sync::merge::push_outgoing(&*relay, &keys.chain_id, &keys.auth_token, &outgoing);
    if pushed
        .accepted
        .iter()
        .any(|(_, seq)| *seq == 0 || *seq > 9_007_199_254_740_991)
    {
        pushed
            .accepted
            .retain(|(_, seq)| *seq > 0 && *seq <= 9_007_199_254_740_991);
        pushed.error = Some(crate::sync::relay::RelayError::BadResponse(
            "invalid accepted record sequence".into(),
        ));
    }
    receipt_commit(env, proof, space_id, keys, sent, &pushed)?;
    report.pushed += pushed.accepted.len();
    report.conflicts += pushed.conflicts;
    if pushed.frozen {
        mark_frozen(env, proof)?;
        return Ok(false);
    }
    if let Some(e) = pushed.error {
        return Err(e.into());
    }
    Ok(true)
}
pub(crate) fn mark_frozen(env: &SyncEnv, proof: &FreshAccountProof) -> Result<(), AppError> {
    let now = env.now();
    let _publication = env.runtime.format_publication.lock().unwrap();
    let info = crate::sync::state_v2::FreezeInfo {
        detected_at_ms: now,
        markers: Vec::new(),
    };
    let result = crate::sync::record_runtime::mutate_records(env, |latest| {
        if !same_account(latest, &proof.keys.chain_id, &proof.relay_url) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut next = latest.clone();
        next.shared_writes_blocked = true;
        next.account.as_mut().unwrap().frozen = Some(info.clone());
        next.last_error = Some("the record chain is frozen; shared publication stopped".into());
        Ok(next)
    });
    if let Err(e) = result {
        if !crate::sync::runtime::is_superseded(&e) {
            fail_closed(
                env,
                &proof.keys.chain_id,
                &proof.relay_url,
                &AccountGate::InvalidMigration,
                None,
            );
        }
        return Err(e);
    }
    Ok(())
}

pub(crate) fn flush_for_rotation(env: &SyncEnv) -> Result<RecordRoundReport, AppError> {
    run(env)
}
fn run(env: &SyncEnv) -> Result<RecordRoundReport, AppError> {
    preflight(env)?;
    let (snapshot, _) = crate::sync::record_runtime::snapshot(env)?;
    let mut report = RecordRoundReport {
        gate: None,
        spaces_pulled: 0,
        pushed: 0,
        conflicts: 0,
        review_required: false,
    };
    if snapshot.account.is_none() || snapshot.pending_account.is_some() {
        return Ok(report);
    }
    let proof = fresh_account_gate(env)?;
    report.gate = Some(proof.gate.clone());
    if proof.ensure_compatible().is_err() {
        return Ok(report);
    }
    let (current, _) = crate::sync::record_runtime::snapshot(env)?;
    let outgoing = crate::sync::record_merge::account_outgoing(
        current.account.as_ref().unwrap(),
        &proof.keys,
    )?;
    if !push_section(env, &proof, None, &proof.keys, &outgoing, &mut report)? {
        return Ok(report);
    }
    let (current, _) = crate::sync::record_runtime::snapshot(env)?;
    let selected: Vec<_> = current
        .spaces
        .iter()
        .filter(|(_, s)| s.selected && !s.missing)
        .map(|(id, _)| id.clone())
        .collect();
    let relay = env.relay(&proof.relay_url)?;
    let features = match current.relay_features.as_ref().filter(|f| f.url == proof.relay_url && env.now().saturating_sub(f.checked_at_ms) < 24 * 60 * 60 * 1000) {
        Some(features) => features.clone(),
        None => {
            let info = relay.info()?;
            let features = crate::sync::state_v2::RelayFeatures::from_info(&proof.relay_url, &info, env.now());
            section_commit(env, &proof, |latest| {
                let mut next = latest.clone();
                next.relay_features = Some(features.clone());
                Ok(next)
            })?;
            features
        }
    };
    let mut planned = Vec::new();
    for id in selected {
        if let Some(keys) = crate::sync::record_merge::space_keys(current.account.as_ref().unwrap(), &proof.keys, &id)? {
            let section = &current.spaces[&id];
            let since = if section.baseline_established { section.cursor_seq } else { 0 };
            planned.push((id, keys, since));
        }
    }
    let targets: Vec<_> = planned.iter().map(|(_, keys, since)| crate::sync::relay::BatchPullItem {
        chain: keys.chain_id.clone(), token: keys.auth_token.clone(), since: *since,
    }).collect();
    let failures = env.runtime.core.lock().unwrap().batch_failures;
    let mut pulled_all = crate::sync::round::pull_all(&*relay, &targets,
        features.supports(crate::sync::relay::FEATURE_PULL_BATCH), failures)?;
    {
        let mut core = env.runtime.core.lock().unwrap();
        core.records_pull_cost = (pulled_all.requests, pulled_all.pull_units);
        if pulled_all.batch_failed { core.batch_failures = core.batch_failures.saturating_add(1); }
        else if pulled_all.batch_ok { core.batch_failures = 0; }
    }
    if !targets.is_empty() && !pulled_all.limited && pulled_all.fetched.values().all(|result| matches!(result, crate::sync::round::Fetched::Missed)) {
        pulled_all.failed = true;
    }
    if pulled_all.batch_unsupported {
        section_commit(env, &proof, |latest| {
            let mut next = latest.clone();
            if let Some(features) = &mut next.relay_features {
                features.features.retain(|f| f != crate::sync::relay::FEATURE_PULL_BATCH);
            }
            Ok(next)
        })?;
    }
    let stopped = pulled_all.limited || pulled_all.failed;
    for (id, keys, since) in planned {
        let pulled = match pulled_all.fetched.remove(&keys.chain_id) {
            Some(crate::sync::round::Fetched::Ok(pulled)) => pulled,
            Some(crate::sync::round::Fetched::NotFound) => {
                section_commit(env, &proof, |latest| {
                    let mut next = latest.clone();
                    let section = next.spaces.get_mut(&id).ok_or_else(crate::sync::runtime::superseded)?;
                    // v1 deliberately conflates a missing chain and a wrong token. Neither is
                    // authoritative deletion. Keep the cache and cursor, and retry normally.
                    section.last_error = Some(TEMPORARY_SPACE_ERROR.into());
                    Ok(next)
                })?;
                continue;
            }
            _ => continue,
        };
        let mut review = false;
        let mut gate = AccountGate::Compatible;
        section_commit(env, &proof, |latest| {
            let Some(section) = latest.spaces.get(&id).filter(|s| s.selected && !s.missing) else {
                return Err(crate::sync::runtime::superseded());
            };
            let merged = crate::sync::record_merge::merge_space(
                section,
                &keys,
                &pulled,
                since,
                &AccountGate::Compatible,
            );
            gate = merged.gate;
            let mut next = latest.clone();
            next.spaces.insert(id.clone(), merged.section);
            if gate == AccountGate::Compatible {
                next.spaces.get_mut(&id).unwrap().last_error = None;
            }
            if gate == AccountGate::Compatible {
                // Resolve inheritance and cross-scope routes against one complete candidate.
                review = crate::sync::record_repository::scope_requires_relationship_review(
                    &next,
                    &crate::sync::records_v3::HostScope::Space {
                        space_id: id.clone(),
                    },
                )
                .map_err(|_| error("record repository cannot be validated for synchronization"))?;
            } else {
                publish_gate(&mut next, &gate, None);
            }
            Ok(next)
        })?;
        report.spaces_pulled += 1;
        report.review_required |= review;
        if gate != AccountGate::Compatible {
            report.gate = Some(gate);
            return Ok(report);
        }
        if review || stopped {
            continue;
        }
        let (current, _) = crate::sync::record_runtime::snapshot(env)?;
        let outgoing = crate::sync::record_merge::space_outgoing(
            &current.spaces[&id],
            &keys,
            &AccountGate::Compatible,
        )?;
        if !push_section(env, &proof, Some(&id), &keys, &outgoing, &mut report)? {
            return Ok(report);
        }
    }
    let (latest, _) = crate::sync::record_runtime::snapshot(env)?;
    report.conflicts = report.conflicts.max(latest.account.as_ref().map_or(0, |a| a.recovery.conflicts.len())
        + latest.spaces.values().map(|s| s.recovery.conflicts.len()).sum::<usize>());
    if pulled_all.limited { return Err(crate::sync::relay::RelayError::RateLimited.into()); }
    if pulled_all.failed { return Err(crate::sync::relay::RelayError::Http(503).into()); }
    let now = env.now();
    section_commit(env, &proof, |latest| {
        let mut next = latest.clone();
        next.last_sync_ms = Some(now);
        if !report.review_required {
            next.last_error = next.spaces.values().find(|s| s.selected && !s.missing && s.last_error.as_deref() == Some(TEMPORARY_SPACE_ERROR)).and_then(|s| s.last_error.clone());
        }
        Ok(next)
    })?;
    Ok(report)
}
fn note_failure(env: &SyncEnv) {
    let mut core = env.runtime.core.lock().unwrap();
    core.failed_rounds = core.failed_rounds.saturating_add(1);
    if core.save_blocked.is_some() {
        return;
    }
    let Ok(latest) = crate::sync::record_runtime::active_state(&core) else {
        return;
    };
    if crate::sync::records_v3::account_writes_blocked(latest) {
        return;
    }
    let mut next = latest.clone();
    next.last_error=Some("Sync could not complete. Check record storage, relay access, and the sync code, then retry.".into());
    core.records = Some(next);
    // Safe fixed diagnostic only. Existing accepted receipts remain in this exact latest core;
    // save failure marks unsaved so the next attempt stops before any network callback.
    let _ = crate::sync::runtime::save_core(&mut core, &env.state_path);
}

pub fn sync_once(env: &SyncEnv) -> Result<RecordRoundReport, AppError> {
    use std::sync::atomic::Ordering;
    if env
        .runtime
        .syncing
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(RecordRoundReport {
            gate: None,
            spaces_pulled: 0,
            pushed: 0,
            conflicts: 0,
            review_required: false,
        });
    }
    // Publish transient activity before acquiring lifecycle; event callbacks may read state.
    env.events.status();
    struct Running<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for Running<'_> {
        fn drop(&mut self) {
            self.0.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let running = Running(&env.runtime.syncing);
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let result = finish_round(env);
    // Clear activity while still owning lifecycle. An explicit setup round may be
    // waiting for it and must never have its activity cleared by this round.
    drop(running);
    drop(lifecycle);
    env.events.status();
    result
}

/// Library setup requires an authoritative report, even when a background round
/// already claimed `syncing` and is waiting for lifecycle. Never interpret a skipped
/// round as an incompatible account. The caller must not already own lifecycle.
pub(crate) fn sync_once_required(env: &SyncEnv) -> Result<RecordRoundReport, AppError> {
    use std::sync::atomic::Ordering;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let owns_activity = !env.runtime.syncing.swap(true, Ordering::SeqCst);
    let result = finish_round(env);
    if owns_activity {
        env.runtime.syncing.store(false, Ordering::SeqCst);
    }
    // If a queued background round owns activity, it will clear it after running.
    drop(lifecycle);
    env.events.status();
    result
}

fn finish_round(env: &SyncEnv) -> Result<RecordRoundReport, AppError> {
    crate::diagnostics::event("records_sync_started", None);
    let result = run(env);
    if let Err(e) = &result {
        if !crate::sync::runtime::is_superseded(e) {
            crate::diagnostics::app_error("records_sync_failed", e);
            note_failure(env);
        }
    } else {
        env.runtime.core.lock().unwrap().failed_rounds = 0;
        crate::diagnostics::event("records_sync_finished", None);
    }
    result
}
#[cfg(test)]
#[path = "record_round_tests.rs"]
pub(crate) mod tests;
