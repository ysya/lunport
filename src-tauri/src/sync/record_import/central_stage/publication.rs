//! Final authority stays native and can only be made from this exact journal's protected readback.
use super::*;
use crate::sync::{
    central::{
        api::DeviceState,
        controller::{self, Session},
        credentials::DeviceIdentity,
    },
    records_v3::LocalImportReceipt,
    runtime::SyncCore,
};
use std::{cell::Cell, sync::Arc};

/// No Clone/Debug/Serialize. The Core writer cannot manufacture, widen or replay this authority.
pub(crate) struct Publication {
    before: SyncStateV3,
    candidate: SyncStateV3,
    generation: u64,
    session: Arc<Session>,
    vault_digest: Option<String>,
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
                .is_none_or(|current| !Arc::ptr_eq(current, &self.session))
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
        if before != &self.before
            || candidate != &self.candidate
            || generation != self.generation
            || before.local.central != candidate.local.central
            || before.local.central_projection.is_none()
            || !before
                .local
                .central
                .as_ref()
                .is_some_and(|owner| owner.control.cutover)
        {
            return Err(failure(
                "central publication source changed; all material is retained",
            ));
        }
        check_session(&self.session, before)?;
        crate::sync::records_v3::validate_state(candidate)
            .map_err(|_| failure("central publication candidate is invalid"))?;
        Ok(())
    }
    pub(crate) fn verify_vault(&self, state_path: &Path) -> Result<(), AppError> {
        if optional_bytes(
            &store::vault_path(state_path),
            store::MAX_READ_ONLY_VAULT_BYTES,
        )?
        .as_ref()
        .map(|b| digest(b))
            != self.vault_digest
        {
            return Err(failure(
                "active vault changed before central publication; stage retained",
            ));
        }
        Ok(())
    }
}
fn check_session(session: &Session, state: &SyncStateV3) -> Result<(), AppError> {
    let owner = state
        .local
        .central
        .as_ref()
        .ok_or_else(|| failure("central owner is missing"))?;
    let grant = session
        .device
        .as_ref()
        .ok_or_else(|| failure("an active device grant is required"))?;
    let identity = session
        .identity
        .as_ref()
        .ok_or_else(|| failure("selected protected device identity is missing"))?;
    if session.profile != owner.control.profile
        || session.tokens.issuer != session.profile.issuer
        || session.tokens.subject != session.profile.subject
        || session.device_access_denied
        || grant.expired()
        || grant.device_state != DeviceState::Active
        || grant.auth_epoch != owner.control.auth_epoch
        || grant.account_id != owner.control.account_id
        || identity.device() != owner.control.device
        || !owner.can_upload()
    {
        return Err(failure(
            "refresh this selected device session before publishing; stage retained",
        ));
    }
    let profile = owner.control.profile.profile()?;
    if identity.slot(&profile, "device")?
        != profile.device_slot("device", owner.identity_slot.as_deref())?
    {
        return Err(failure(
            "protected device selection changed; stage retained",
        ));
    }
    Ok(())
}
fn checked_session(env: &SyncEnv, state: &SyncStateV3) -> Result<Arc<Session>, AppError> {
    let session = controller::context(env)?;
    check_session(&session, state)?;
    let owner = state.local.central.as_ref().unwrap();
    let profile = owner.control.profile.profile()?;
    // A missing/changed OS item cannot be silently recreated from the cached session.
    let protected = DeviceIdentity::load_selected(
        env.keychain,
        &profile,
        owner.identity_slot.as_deref(),
        false,
    )
    .map_err(|_| {
        failure("selected protected device credentials are unavailable; stage retained")
    })?;
    let cached = session.identity.as_ref().unwrap();
    if protected.device() != owner.control.device || protected.credential() != cached.credential() {
        return Err(failure(
            "selected protected device credentials changed; stage retained",
        ));
    }
    Ok(session)
}
fn receipt(j: &Journal) -> Result<LocalImportReceipt, AppError> {
    #[derive(Serialize)]
    struct Binding<'a> {
        domain: &'static str,
        operation: &'a str,
        profile: &'a central::client_state::ProfileData,
        anchor: &'a TrustAnchor,
        device: &'a Device,
        identity_slot: &'a Option<String>,
        vault: &'a str,
        checkpoint: &'a Checkpoint,
        source: &'a Option<String>,
        staged: &'a Option<String>,
        master: &'a Option<String>,
        bindings: &'a BTreeMap<String, super::Binding>,
    }
    let bytes = serde_json::to_vec(&Binding {
        domain: "lunport-central-library-publication-v1",
        operation: &j.operation,
        profile: &j.profile,
        anchor: &j.anchor,
        device: &j.device,
        identity_slot: &j.identity_slot,
        vault: &j.vault,
        checkpoint: &j.checkpoint,
        source: &j.source_state_digest,
        staged: &j.staged_vault_digest,
        master: &j.staged_key_account,
        bindings: &j.bindings,
    })
    .map_err(|_| failure("cannot bind central publication receipt"))?;
    Ok(LocalImportReceipt {
        source_digest: digest(&bytes),
        host_ids: vec![],
        key_ids: j.bindings.keys().cloned().collect(),
    })
}
pub(super) fn completed(state: &SyncStateV3, j: &Journal) -> Result<bool, AppError> {
    matches_receipt(state.local.import_receipts.get(&j.operation), j)
}
pub(super) fn matches_receipt(
    saved: Option<&LocalImportReceipt>,
    j: &Journal,
) -> Result<bool, AppError> {
    match saved {
        None => Ok(false),
        Some(saved) if saved == &receipt(j)? => Ok(true),
        Some(_) => Err(failure(
            "central operation conflicts with a different durable receipt",
        )),
    }
}
fn active_vault(env: &SyncEnv, paths: &Paths, j: &Journal) -> Result<(), AppError> {
    let Some(expected) = j.staged_vault_digest.as_ref() else {
        if !j.bindings.is_empty()
            || optional_bytes(
                &store::vault_path(&env.state_path),
                store::MAX_READ_ONLY_VAULT_BYTES,
            )?
            .is_some()
        {
            return Err(failure("empty central vault source changed"));
        }
        return Ok(());
    };
    let bytes = bounded_read(&paths.vault, store::MAX_READ_ONLY_VAULT_BYTES)?;
    if &digest(&bytes) != expected {
        return Err(failure("central stage changed before vault publication"));
    }
    let destination = store::vault_path(&env.state_path);
    let current = optional_bytes(&destination, store::MAX_READ_ONLY_VAULT_BYTES)?
        .as_ref()
        .map(|b| digest(b));
    if current.as_ref() == Some(expected) {
        // A previous rename may have succeeded before its phase/response or directory fsync.
        // Confirm this exact image is durable before allowing its new metadata to reach disk.
        let result = (|| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut options = fs::OpenOptions::new();
                options
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                options.open(&destination)?.sync_all()?;
                fs::File::open(destination.parent().unwrap())?.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let mut core = env.runtime.core.lock().unwrap();
            core.save_blocked=Some("Cannot confirm central vault durability. Restart to reload; sources and stages are retained.".into());
            core.central_session = None;
        }
        return result;
    }
    if current != j.source_vault_digest {
        return Err(failure("source vault changed before publication; retained"));
    }
    let published = Cell::new(false);
    let result = (|| {
        use std::io::Write;
        fsutil_check(&destination)?;
        let parent = destination
            .parent()
            .ok_or_else(|| failure("active vault has no directory"))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        temp.write_all(&bytes)?;
        #[cfg(test)]
        record_runtime::replacement_write_stage(
            record_runtime::ReplacementWriteStage::FileSync,
            &destination,
        )?;
        temp.as_file().sync_all()?;
        #[cfg(test)]
        record_runtime::replacement_write_stage(
            record_runtime::ReplacementWriteStage::SourceRecheck,
            &destination,
        )?;
        if optional_bytes(&destination, store::MAX_READ_ONLY_VAULT_BYTES)?
            .as_ref()
            .map(|b| digest(b))
            != j.source_vault_digest
        {
            return Err(failure("source vault changed before rename; retained"));
        }
        #[cfg(test)]
        record_runtime::replacement_write_stage(
            record_runtime::ReplacementWriteStage::Rename,
            &destination,
        )?;
        temp.persist(&destination)
            .map_err(|e| AppError::Io(e.error))?;
        published.set(true);
        #[cfg(test)]
        record_runtime::replacement_write_stage(
            record_runtime::ReplacementWriteStage::DirectorySync,
            &destination,
        )?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        if digest(&bounded_read(
            &destination,
            store::MAX_READ_ONLY_VAULT_BYTES,
        )?) != *expected
        {
            return Err(failure("active vault readback differs"));
        }
        Ok(())
    })();
    if result.is_err() && published.get() {
        let mut core = env.runtime.core.lock().unwrap();
        core.save_blocked=Some("Central vault reached disk but durability is uncertain. Restart to reload; all sources and stages are retained.".into());
        core.central_session = None;
    }
    result
}
/// Caller supplies native verified epoch keys; no frontend command can supply them. No HTTP.
pub(crate) fn publish(
    env: &SyncEnv,
    operation: &str,
    keys: &central::crypto::VaultKeys,
) -> Result<PendingImport, AppError> {
    if !cfg!(unix) {
        return Err(failure(
            "central publication is not verified on this platform",
        ));
    }
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let paths = Paths::new(env, operation)?;
    let mut journal: Journal =
        serde_json::from_slice(&bounded_read(&paths.journal, MAX_JOURNAL_BYTES)?)
            .map_err(|_| failure("central stage journal is unreadable"))?;
    validate_header(&journal, operation)?;
    let (before, _) = record_runtime::snapshot(env)?;
    if completed(&before, &journal)? {
        if journal.phase != Phase::Active {
            journal.phase = Phase::Active;
            save(&paths, &journal)?;
        }
        return Ok(summary(&journal));
    }
    if journal.phase == Phase::Active {
        return Err(failure(
            "active central journal has no durable state receipt; retained",
        ));
    }
    checked_session(env, &before)?;
    let delta = LibraryDelta::prepare(&before, keys, env.now())?;
    saved_source(env, &delta)?;
    execute(env, &paths, &mut journal, &delta)?;
    let scoped = ScopedKeychain {
        inner: env.keychain,
        import_id: operation,
        receipts: &paths.masters,
    };
    if let Some(account) = journal.staged_key_account.as_ref() {
        scoped.promote(account)?;
    }
    super::super::step(super::super::PublishStep::MasterPromoted)?;
    checked_session(env, &record_runtime::snapshot(env)?.0)?;
    active_vault(env, &paths, &journal)?;
    super::super::step(super::super::PublishStep::VaultSaved)?;
    if journal.phase != Phase::VaultPublished {
        journal.phase = Phase::VaultPublished;
        save(&paths, &journal)?;
    }
    // Rebuild from latest Core; a late uncaptured B safely leaves VaultPublished pending for the
    // next capture/sync pass. The additive active vault still contains every old reference.
    let (before, generation) = record_runtime::snapshot(env)?;
    let session = checked_session(env, &before)?;
    let delta = LibraryDelta::prepare(&before, keys, env.now())?;
    verify_delta(&journal, &delta)?;
    let vault = validate_vault(&store::vault_path(&env.state_path), env.keychain)?;
    let verified = delta.finish(
        &vault,
        &journal
            .bindings
            .iter()
            .map(|(id, b)| (id.clone(), b.protected_id.clone()))
            .collect(),
        operation,
    )?;
    let mut candidate = verified.candidate().clone();
    candidate
        .local
        .import_receipts
        .insert(operation.into(), receipt(&journal)?);
    let authority = Publication {
        before,
        candidate,
        generation,
        session,
        vault_digest: journal.staged_vault_digest.clone(),
    };
    authority.verify_vault(&env.state_path)?;
    super::super::step(super::super::PublishStep::BeforeStateSave)?;
    record_runtime::publish_projection(env, &authority)?;
    super::super::step(super::super::PublishStep::StateSaved)?;
    journal.phase = Phase::Active;
    save(&paths, &journal)?;
    Ok(summary(&journal))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{delta, fixture};
    use super::*;
    use crate::sync::{
        central::{api::DeviceSession, oidc::LoginTokens},
        env::Keychain,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::time::{Duration, Instant};
    pub(super) fn session(
        device: &crate::sync::testkit::TestDevice,
        lifetime: Duration,
    ) -> Arc<Session> {
        let state = record_runtime::snapshot(&device.env()).unwrap().0;
        let owner = state.local.central.as_ref().unwrap();
        let profile = owner.control.profile.profile().unwrap();
        let keys = central::crypto::DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        assert_eq!(keys.public(), owner.control.device.keys);
        let encoded=zeroize::Zeroizing::new(serde_json::json!({"version":1,"locator":profile.locator,"id":owner.control.device.id,"keys":&*keys.encode_secret(),"credential":"d".repeat(64)}).to_string());
        let slot = profile
            .device_slot("device", owner.identity_slot.as_deref())
            .unwrap();
        device.keychain.set(&slot, &encoded).unwrap();
        let identity = Arc::new(
            DeviceIdentity::load_selected(
                &device.keychain,
                &profile,
                owner.identity_slot.as_deref(),
                false,
            )
            .unwrap(),
        );
        let session = Arc::new(Session {
            profile: owner.control.profile.clone(),
            identity: Some(identity),
            tokens: Arc::new(LoginTokens {
                issuer: profile.issuer,
                subject: profile.subject,
                nonce: zeroize::Zeroizing::new("synthetic nonce".into()),
                access: zeroize::Zeroizing::new("synthetic access".into()),
                refresh: None,
                expires_in: Duration::from_secs(300),
            }),
            device: Some(DeviceSession::synthetic_for_test(
                owner.control.account_id.clone(),
                DeviceState::Active,
                owner.control.auth_epoch,
                lifetime,
            )),
            device_access_denied: false,
            tokens_started: Instant::now(),
        });
        device.runtime.core.lock().unwrap().central_session = Some(Arc::clone(&session));
        session
    }
    #[test]
    fn native_selected_session_publishes_exact_material_and_receipt_and_completed_retry_does_not_resurrect_later_removal(
    ) {
        let (device, keys, id, entry) = fixture();
        let env = device.env();
        session(&device, Duration::from_secs(300));
        let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
        let operation = staged.operation().to_owned();
        let before = record_runtime::snapshot(&env).unwrap().0;
        assert!(record_runtime::commit_candidate(
            &env,
            record_runtime::snapshot(&env).unwrap().1,
            delta(&device, &keys)
                .finish(
                    &validate_vault(
                        &staged.paths.vault,
                        &ScopedKeychain {
                            inner: env.keychain,
                            import_id: &operation,
                            receipts: &staged.paths.masters
                        }
                    )
                    .unwrap(),
                    &staged.mapping(),
                    &operation
                )
                .unwrap()
                .candidate()
                .clone()
        )
        .is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap().0, before);
        let result = publish(&env, &operation, &keys).unwrap();
        assert_eq!(result.phase, "central_active");
        let (active, generation) = record_runtime::snapshot(&env).unwrap();
        assert!(active.local.import_receipts.contains_key(&operation));
        let key = crate::sync::record_repository::resolve_key(&active, &id).unwrap();
        let vault = validate_vault(&store::vault_path(&env.state_path), env.keychain).unwrap();
        assert!(crate::session::record_material::matches(
            &key,
            &vault
                .get(&active.local.keys[&id].vault_id)
                .unwrap()
                .unwrap()
        ));
        assert!(super::super::super::pending_imports(&env)
            .unwrap()
            .is_empty());
        let mut removed = active;
        removed.local.keys.remove(&id);
        record_runtime::commit_candidate(&env, generation, removed.clone()).unwrap();
        // Completed retries do not require a session, stage image or original private material.
        device.runtime.core.lock().unwrap().central_session = None;
        fs::remove_file(&staged.paths.vault).unwrap();
        assert_eq!(
            publish(&env, &operation, &keys).unwrap().phase,
            "central_active"
        );
        assert_eq!(record_runtime::snapshot(&env).unwrap().0, removed);
        assert!(!serde_json::to_string(&removed)
            .unwrap()
            .contains(&entry.private_key));
    }
    #[test]
    fn missing_expired_or_missing_protected_identity_refuses_before_active_vault_or_state_publication(
    ) {
        for failure_kind in 0..4 {
            let (device, keys, _, _) = fixture();
            let env = device.env();
            let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
            let before = fs::read(&env.state_path).unwrap();
            if failure_kind > 0 {
                let s = session(
                    &device,
                    if failure_kind == 1 {
                        Duration::ZERO
                    } else {
                        Duration::from_secs(300)
                    },
                );
                if failure_kind == 2 {
                    let profile = s.profile.profile().unwrap();
                    device
                        .keychain
                        .delete(&profile.device_slot("device", None).unwrap())
                        .unwrap();
                } else if failure_kind == 3 {
                    let profile = s.profile.profile().unwrap();
                    let slot = profile.device_slot("device", None).unwrap();
                    let mut stored: serde_json::Value =
                        serde_json::from_str(&device.keychain.get(&slot).unwrap().unwrap())
                            .unwrap();
                    stored["credential"] = "e".repeat(64).into();
                    device.keychain.set(&slot, &stored.to_string()).unwrap();
                }
            }
            assert!(publish(&env, staged.operation(), &keys).is_err());
            assert_eq!(fs::read(&env.state_path).unwrap(), before);
            assert!(!store::vault_path(&env.state_path).exists());
        }
    }
}

#[cfg(test)]
mod fault_tests {
    use super::super::tests::{delta, fixture};
    use super::tests::session;
    use super::*;
    use crate::sync::record_runtime::{
        with_replacement_write_hook, ReplacementWriteStage as WriteStage,
    };
    use std::time::Duration;
    #[test]
    fn strict_record_write_faults_retain_sources_and_post_rename_faults_block_until_restart() {
        for stop in [
            WriteStage::FileSync,
            WriteStage::Rename,
            WriteStage::DirectorySync,
        ] {
            let (device, keys, id, _) = fixture();
            let env = device.env();
            session(&device, Duration::from_secs(300));
            let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
            let before = record_runtime::snapshot(&env).unwrap();
            let path = env.state_path.clone();
            let fault = path.clone();
            let result = with_replacement_write_hook(
                Box::new(move |stage, path| {
                    if path == fault && stage == stop {
                        Err(failure("injected state write failure"))
                    } else {
                        Ok(())
                    }
                }),
                || publish(&env, staged.operation(), &keys),
            );
            assert!(result.is_err());
            assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
            if stop == WriteStage::DirectorySync {
                {
                    let core = env.runtime.core.lock().unwrap();
                    assert!(core.save_blocked.is_some());
                    assert!(core.central_session.is_none());
                }
                assert!(
                    record_runtime::commit_candidate(&env, before.1, before.0.clone()).is_err()
                );
                let probe = record_runtime::probe_startup(&path, "restarted");
                record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe)
                    .unwrap();
            } else {
                assert!(env.runtime.core.lock().unwrap().save_blocked.is_none());
            }
            let resumed = publish(&env, staged.operation(), &keys).unwrap();
            assert_eq!(resumed.phase, "central_active");
            assert!(record_runtime::snapshot(&env)
                .unwrap()
                .0
                .local
                .keys
                .contains_key(&id));
        }
    }
    #[test]
    fn vault_directory_sync_failure_blocks_without_replacing_records_and_resumes_after_restart() {
        let (device, keys, _, _) = fixture();
        let env = device.env();
        session(&device, Duration::from_secs(300));
        let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
        let before = record_runtime::snapshot(&env).unwrap();
        let vault_path = store::vault_path(&env.state_path);
        let outcome = with_replacement_write_hook(
            Box::new(move |stage, path| {
                if path == vault_path && stage == WriteStage::DirectorySync {
                    Err(failure("injected vault directory sync failure"))
                } else {
                    Ok(())
                }
            }),
            || publish(&env, staged.operation(), &keys),
        );
        assert!(outcome.is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        assert!(env.runtime.core.lock().unwrap().save_blocked.is_some());
        let probe = record_runtime::probe_startup(&env.state_path, "restarted");
        record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
        session(&device, Duration::from_secs(300));
        assert_eq!(
            publish(&env, staged.operation(), &keys).unwrap().phase,
            "central_active"
        );
    }
    #[test]
    fn lost_vault_or_state_phase_resumes_without_new_ids_and_durable_completion_preserves_later_edits(
    ) {
        for stop in [
            super::super::super::PublishStep::MasterPromoted,
            super::super::super::PublishStep::VaultSaved,
            super::super::super::PublishStep::StateSaved,
        ] {
            let (device, keys, id, _) = fixture();
            let env = device.env();
            session(&device, Duration::from_secs(300));
            let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
            let mapping = staged.mapping();
            let outcome = super::super::super::with_test_step(
                move |stage| {
                    if stage == stop {
                        Err(failure("lost phase response"))
                    } else {
                        Ok(())
                    }
                },
                || publish(&env, staged.operation(), &keys),
            );
            assert!(outcome.is_err());
            if stop == super::super::super::PublishStep::StateSaved {
                let (mut state, generation) = record_runtime::snapshot(&env).unwrap();
                state.local.keys.remove(&id);
                record_runtime::commit_candidate(&env, generation, state).unwrap();
                device.runtime.core.lock().unwrap().central_session = None;
                fs::remove_file(&staged.paths.vault).unwrap();
                assert!(super::super::super::pending_imports(&env)
                    .unwrap()
                    .is_empty());
            }
            assert_eq!(
                publish(&env, staged.operation(), &keys).unwrap().phase,
                "central_active"
            );
            let state = record_runtime::snapshot(&env).unwrap().0;
            if stop == super::super::super::PublishStep::StateSaved {
                assert!(!state.local.keys.contains_key(&id));
            } else {
                assert_eq!(state.local.keys[&id].vault_id, mapping[&id]);
            }
        }
    }
    #[test]
    fn a_public_only_delta_uses_no_vault_or_master_and_still_requires_the_typed_journal_session() {
        use crate::sync::{
            central::payload::{Data, Identity},
            records_v3::HostScope,
        };
        let (mut state, keys, _) = central::library_fixture_for_test();
        let key = crate::sync::record::record_key(
            crate::sync::record::RecordKind::Host,
            "0000000000000001",
        );
        let mut host: crate::sync::records_v3::HostPayload =
            serde_json::from_value(state.local.hosts[&key].record.payload.clone()).unwrap();
        host.alias = "remote-C".into();
        central::append_library_for_test(
            &mut state,
            &keys,
            Identity {
                kind: "host".into(),
                id: "0000000000000001".into(),
                scope: Some(HostScope::Local),
            },
            Data::Host(host),
        );
        let device = crate::sync::testkit::TestDevice::new(
            "public-only",
            &crate::sync::fake_relay::FakeRelay::new(),
            &crate::sync::testkit::TestClock::new(),
        );
        let env = device.env();
        record_runtime::save_active(&env.state_path, &state).unwrap();
        let probe = record_runtime::probe_startup(&env.state_path, "public-only");
        record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
        let delta = delta(&device, &keys);
        assert!(delta.required_material().is_empty());
        let staged = super::super::prepare(&env, &delta).unwrap();
        assert!(!staged.paths.vault.exists());
        assert!(!staged.paths.masters.exists());
        session(&device, Duration::from_secs(300));
        assert_eq!(
            publish(&env, staged.operation(), &keys).unwrap().phase,
            "central_active"
        );
        let state = record_runtime::snapshot(&env).unwrap().0;
        assert_eq!(state.local.hosts[&key].record.payload["alias"], "remote-C");
        assert!(!store::vault_path(&env.state_path).exists());
        assert!(!staged.paths.masters.exists());
    }
    #[test]
    fn public_b_created_while_the_additive_vault_is_published_survives_capture_and_same_operation_retry(
    ) {
        let (device, keys, id, _) = fixture();
        let device = Arc::new(device);
        let env = device.env();
        session(&device, Duration::from_secs(300));
        let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
        let hook_device = Arc::clone(&device);
        let vault = store::vault_path(&env.state_path);
        let mut once = true;
        let result = with_replacement_write_hook(
            Box::new(move |stage, path| {
                if once && path == vault && stage == WriteStage::Rename {
                    once = false;
                    let env = hook_device.env();
                    record_runtime::mutate_records(&env, |state| {
                        crate::sync::record_repository::create_host(state,"0000000000000008",crate::sync::records_v3::HostScope::Local,serde_json::from_value(serde_json::json!({"schema":2,"alias":"late-local-B","hostname":"fixture.invalid","auth":"password"})).unwrap(),201).map_err(|_|failure("cannot create test B"))
                    })?;
                }
                Ok(())
            }),
            || publish(&env, staged.operation(), &keys),
        );
        assert!(result.is_err());
        let (state, generation) = record_runtime::snapshot(&env).unwrap();
        assert!(!state.local.hosts.is_empty());
        assert!(!state.local.keys.contains_key(&id));
        let signer = central::crypto::DeviceKeys::decode_secret(&base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [1u8; 64],
        ))
        .unwrap();
        let captured = central::capture_for_test(&state, &keys, &signer).unwrap();
        record_runtime::commit_candidate(&env, generation, captured.clone()).unwrap();
        assert_eq!(
            publish(&env, staged.operation(), &keys).unwrap().phase,
            "central_active"
        );
        let active = record_runtime::snapshot(&env).unwrap().0;
        assert_eq!(active.local.hosts, captured.local.hosts);
        assert_eq!(
            active.local.central.as_ref().unwrap().replica,
            captured.local.central.as_ref().unwrap().replica
        );
        assert!(active.local.keys.contains_key(&id));
    }
    #[test]
    fn losing_the_exact_session_before_final_core_write_cannot_publish_stale_metadata() {
        let (device, keys, _, _) = fixture();
        let device = Arc::new(device);
        let env = device.env();
        session(&device, Duration::from_secs(300));
        let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
        let before = record_runtime::snapshot(&env).unwrap();
        let hook_device = Arc::clone(&device);
        let result = super::super::super::with_test_step(
            move |step| {
                if step == super::super::super::PublishStep::BeforeStateSave {
                    hook_device.runtime.core.lock().unwrap().central_session = None;
                }
                Ok(())
            },
            || publish(&env, staged.operation(), &keys),
        );
        assert!(crate::sync::runtime::is_superseded(&result.unwrap_err()));
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        session(&device, Duration::from_secs(300));
        assert_eq!(
            publish(&env, staged.operation(), &keys).unwrap().phase,
            "central_active"
        );
    }
    #[test]
    fn an_external_saved_source_b_is_rechecked_before_rename_and_preserved_through_restart() {
        let (device, keys, _, _) = fixture();
        let env = device.env();
        session(&device, Duration::from_secs(300));
        let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
        let before = record_runtime::snapshot(&env).unwrap();
        let source = env.state_path.clone();
        let result = with_replacement_write_hook(
            Box::new(move |step, path| {
                if path == source && step == WriteStage::SourceRecheck {
                    let mut state: SyncStateV3 = serde_json::from_slice(&fs::read(path)?).unwrap();
                    state.last_error = Some("external-source-B".into());
                    fs::write(path, serde_json::to_vec_pretty(&state).unwrap())?;
                }
                Ok(())
            }),
            || publish(&env, staged.operation(), &keys),
        );
        assert!(result.is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        let saved: SyncStateV3 =
            serde_json::from_slice(&fs::read(&env.state_path).unwrap()).unwrap();
        assert_eq!(saved.last_error.as_deref(), Some("external-source-B"));
        let probe = record_runtime::probe_startup(&env.state_path, "external-B-reload");
        record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
        session(&device, Duration::from_secs(300));
        assert_eq!(
            publish(&env, staged.operation(), &keys).unwrap().phase,
            "central_active"
        );
        assert_eq!(
            record_runtime::snapshot(&env)
                .unwrap()
                .0
                .last_error
                .as_deref(),
            Some("external-source-B")
        );
    }
    #[test]
    fn a_false_success_of_master_promotion_cannot_write_active_material_or_records() {
        use crate::sync::env::Keychain;
        struct DropPromotion<'a>(&'a dyn Keychain);
        impl Keychain for DropPromotion<'_> {
            fn get(&self, key: &str) -> Result<Option<String>, AppError> {
                self.0.get(key)
            }
            fn get_noninteractive(&self, key: &str) -> Result<Option<String>, AppError> {
                self.0.get_noninteractive(key)
            }
            fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
                if key.starts_with(store::VAULT_KEY_ACCOUNT_PREFIX) {
                    Ok(())
                } else {
                    self.0.set(key, value)
                }
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                Err(failure("unexpected protected delete"))
            }
        }
        let (device, keys, _, _) = fixture();
        let env = device.env();
        session(&device, Duration::from_secs(300));
        let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
        let before = record_runtime::snapshot(&env).unwrap();
        let drop = DropPromotion(&device.keychain);
        let mut bad = device.env();
        bad.keychain = &drop;
        assert!(publish(&bad, staged.operation(), &keys).is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        assert!(!store::vault_path(&env.state_path).exists());
        assert_eq!(
            publish(&env, staged.operation(), &keys).unwrap().phase,
            "central_active"
        );
    }
    #[test]
    fn an_active_journal_without_its_durable_state_receipt_cannot_claim_completion_or_allow_a_duplicate_stage(
    ) {
        let (device, keys, _, _) = fixture();
        let env = device.env();
        session(&device, Duration::from_secs(300));
        let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
        publish(&env, staged.operation(), &keys).unwrap();
        let (mut state, generation) = record_runtime::snapshot(&env).unwrap();
        state.local.import_receipts.remove(staged.operation());
        record_runtime::commit_candidate(&env, generation, state).unwrap();
        let pending = super::super::super::pending_imports(&env).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].phase, "central_missing_receipt");
        assert!(publish(&env, staged.operation(), &keys).is_err());
        assert!(super::super::prepare(&env, &delta(&device, &keys)).is_err());
    }
    #[test]
    fn central_projection_cannot_upgrade_or_back_up_an_unexpected_saved_source_format() {
        let (device, keys, _, _) = fixture();
        let device = Arc::new(device);
        let env = device.env();
        session(&device, Duration::from_secs(300));
        let staged = super::super::prepare(&env, &delta(&device, &keys)).unwrap();
        let before = record_runtime::snapshot(&env).unwrap();
        let hook_device = Arc::clone(&device);
        let result = super::super::super::with_test_step(
            move |step| {
                if step == super::super::super::PublishStep::BeforeStateSave {
                    let path = hook_device.env().state_path;
                    let mut state: serde_json::Value =
                        serde_json::from_slice(&fs::read(&path)?).unwrap();
                    state["version"] = 7.into();
                    fs::write(path, serde_json::to_vec(&state).unwrap())?;
                }
                Ok(())
            },
            || publish(&env, staged.operation(), &keys),
        );
        assert!(result.is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        assert!(!fs::read_dir(env.state_path.parent().unwrap())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("sync-state-v7-")));
    }
}
