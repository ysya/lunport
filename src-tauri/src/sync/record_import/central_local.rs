//! Local creation uses the existing additive import journal and one native Core publication.
use super::*;
use crate::sync::{
    central::{self, controller::Session, credentials::DeviceIdentity, crypto::VaultKeys},
    runtime::SyncCore,
};
use std::sync::Arc;

/// Public expected destination, never a credential or private material reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    profile: String,
    account: String,
    genesis: String,
    vault: String,
    device: String,
    identity_slot: Option<String>,
    generation: String,
}
impl Invocation {
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation.to_string();
        self
    }
    pub(super) fn device_id(&self) -> &str {
        &self.device
    }
}
pub fn invocation(state: &SyncStateV3) -> Option<Invocation> {
    let owner = state.local.central.as_ref().filter(|o| o.control.cutover)?;
    Some(Invocation {
        profile: owner.control.profile.locator.clone(),
        account: owner.control.account_id.clone(),
        genesis: owner.control.anchor.as_ref()?.genesis_hash.clone(),
        vault: owner.control.personal_vault.clone()?,
        device: owner.control.device.id.clone(),
        identity_slot: owner.identity_slot.clone(),
        generation: "0".into(),
    })
}
/// Public request fence includes the current Core generation to reject an account A -> B -> A replay.
pub fn check_request(
    state: &SyncStateV3,
    generation: u64,
    expected: Option<&Invocation>,
) -> Result<(), AppError> {
    if invocation(state)
        .map(|scope| scope.with_generation(generation))
        .as_ref()
        != expected
    {
        return Err(failure(
            "key destination changed; reopen the key dialog and retry",
        ));
    }
    Ok(())
}
pub fn check_invocation(
    state: &SyncStateV3,
    expected: Option<&Invocation>,
) -> Result<(), AppError> {
    if invocation(state).as_ref() != expected {
        return Err(failure(
            "key destination changed; reopen the key dialog and retry",
        ));
    }
    Ok(())
}
fn same_selection(a: Option<&Arc<Session>>, b: Option<&Arc<Session>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}
/// Native transient keys only; never a DTO, journal or Core field.
pub(in crate::sync) struct Context {
    scope: Invocation,
    head: String,
    epoch: u64,
    auth_epoch: u64,
    identity: DeviceIdentity,
    keys: VaultKeys,
    session: Option<Arc<Session>>,
}
impl Context {
    pub(in crate::sync) fn keys(&self) -> &VaultKeys {
        &self.keys
    }
    pub(in crate::sync) fn signer(&self) -> &central::crypto::DeviceKeys {
        &self.identity.keys
    }
    pub(in crate::sync) fn session(&self) -> Option<&Arc<Session>> {
        self.session.as_ref()
    }
    pub fn load(env: &SyncEnv, state: &SyncStateV3) -> Result<Self, AppError> {
        central::controller::require_enabled()?;
        if !cfg!(unix) {
            return Err(failure(
                "central material publication is not verified on this platform",
            ));
        }
        fsutil::check_write(&env.state_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let parent = env
                .state_path
                .parent()
                .ok_or_else(|| failure("central local data has no directory"))?;
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(failure(
                    "central local material requires a private owned data directory",
                ));
            }
        }

        let saved = record_runtime::read_saved_records(&env.state_path)?;
        if &saved != state {
            return Err(failure(
                "saved key destination changed; reload the workspace",
            ));
        }

        let owner = state
            .local
            .central
            .as_ref()
            .ok_or_else(|| failure("central owner is missing"))?;
        owner.validate()?;
        if !owner.control.cutover || !owner.can_upload() {
            return Err(failure(
                "unlock this device and finish its account operation before adding a key",
            ));
        }
        let scope = invocation(state).ok_or_else(|| failure("key destination is unavailable"))?;
        let profile = owner.control.profile.profile()?;
        let identity = DeviceIdentity::load_selected(
            env.keychain,
            &profile,
            owner.identity_slot.as_deref(),
            false,
        )?;
        if identity.device() != owner.control.device {
            return Err(failure("selected protected device identity changed"));
        }
        let session = env.runtime.core.lock().unwrap().central_session.clone();
        if let Some(session) = session.as_ref() {
            if session.profile != owner.control.profile
                || session.identity.as_ref().is_none_or(|cached| {
                    cached.device() != identity.device()
                        || cached.credential() != identity.credential()
                        || cached.slot(&profile, "device").ok()
                            != profile
                                .device_slot("device", owner.identity_slot.as_deref())
                                .ok()
                })
            {
                return Err(failure(
                    "selected account session changed; reopen the key dialog",
                ));
            }
        }
        let chain = owner.control.verified_chain()?;
        let replica = owner
            .replica
            .as_ref()
            .ok_or_else(|| failure("central library is unavailable"))?;
        let epoch = replica.checkpoint.epoch;
        replica.verify_write_authority(&chain, owner.control.auth_epoch, epoch, &owner.epochs)?;
        let wrap = owner
            .own_wraps
            .iter()
            .find(|w| w.header.key_epoch == epoch.to_string())
            .ok_or_else(|| failure("current encrypted vault keys are unavailable"))?;
        let author = chain
            .author_at(&wrap.header.membership_head, &wrap.header.author)
            .ok_or_else(|| failure("vault key author is unavailable"))?;
        let keys = wrap.open(&identity.keys, &wrap.header, &author.signing)?;
        let result = Self {
            scope,
            head: chain.current().head().into(),
            epoch,
            auth_epoch: owner.control.auth_epoch,
            identity,
            keys,
            session,
        };
        result.verify(env, state)?;
        Ok(result)
    }
    pub fn prepare(
        &self,
        state: &SyncStateV3,
        operation: &str,
        id: &str,
        public: &KeySlotPayload,
        entry: &VaultEntry,
    ) -> Result<central::LocalMaterialIntent, AppError> {
        central::prepare_local_material(
            state,
            &self.keys,
            &self.identity.keys,
            central::LocalMaterialContext {
                operation: operation.into(),
                key_id: id.into(),
                vault_id: id.into(),
            },
            public.clone(),
            entry,
        )?
        .intent()
    }
    pub(in crate::sync) fn verify(
        &self,
        env: &SyncEnv,
        state: &SyncStateV3,
    ) -> Result<(), AppError> {
        check_invocation(state, Some(&self.scope))?;
        let owner = state.local.central.as_ref().unwrap();
        let chain = owner.control.verified_chain()?;
        if !owner.can_upload()
            || owner.control.auth_epoch != self.auth_epoch
            || chain.current().head() != self.head
            || owner
                .replica
                .as_ref()
                .is_none_or(|r| r.checkpoint.epoch != self.epoch)
        {
            return Err(failure(
                "central key context changed; import stage retained",
            ));
        }
        let protected = DeviceIdentity::load_selected(
            env.keychain,
            &owner.control.profile.profile()?,
            owner.identity_slot.as_deref(),
            false,
        )?;
        if protected.device() != self.identity.device()
            || protected.credential() != self.identity.credential()
        {
            return Err(failure(
                "protected device credential changed; import stage retained",
            ));
        }
        let core = env.runtime.core.lock().unwrap();
        if core.save_blocked.is_some()
            || !same_selection(core.central_session.as_ref(), self.session.as_ref())
        {
            return Err(crate::sync::runtime::superseded());
        }
        let latest = record_runtime::active_state(&core)?;
        if invocation(latest).as_ref() != Some(&self.scope)
            || latest.local.central.as_ref().is_none_or(|owner| {
                !owner.can_upload()
                    || owner.control.auth_epoch != self.auth_epoch
                    || owner
                        .control
                        .highwater
                        .as_ref()
                        .is_none_or(|h| h.head != self.head)
                    || owner
                        .replica
                        .as_ref()
                        .is_none_or(|r| r.checkpoint.epoch != self.epoch)
            })
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(())
    }
    pub fn recover(
        &self,
        env: &SyncEnv,
        state: &SyncStateV3,
        j: &Journal,
    ) -> Result<BTreeMap<String, VaultEntry>, AppError> {
        self.verify(env, state)?;
        validate_journal(j)?;
        let intent = j
            .central_intent
            .as_ref()
            .ok_or_else(|| failure("local ciphertext intent is missing"))?;
        let entry = intent.recover_entry(state, &self.keys, &self.identity.keys)?;
        self.verify(env, state)?;
        Ok(BTreeMap::from([(intent.key_id().into(), entry)]))
    }
    fn candidate(
        &self,
        state: &SyncStateV3,
        j: &Journal,
        vault: &store::ReadOnlyVault,
    ) -> Result<SyncStateV3, AppError> {
        validate_journal(j)?;
        let intent = j
            .central_intent
            .as_ref()
            .ok_or_else(|| failure("central material intent is missing"))?;
        let entry = vault
            .get(intent.vault_id())
            .map_err(|_| failure("protected local material is unreadable"))?
            .ok_or_else(|| failure("protected local material is missing; import stage retained"))?;
        intent.candidate(state, &self.keys, &self.identity.keys, &entry)
    }
}
pub(super) fn validate_journal(j: &Journal) -> Result<(), AppError> {
    let Some(intent) = j.central_intent.as_ref() else {
        return Ok(());
    };
    if j.source_kind != SourceKind::Material
        || j.import_id != intent.operation()
        || j.keys.len() != 1
        || !j.hosts.is_empty()
        || !j.copies.is_empty()
        || j.authoritative.is_some()
        || j.source_digest != intent.digest()?
        || j.material_digests.get(intent.key_id()).map(String::as_str) != Some(intent.raw_hash()?)
        || j.keys.get(intent.key_id()).is_none_or(|local| {
            local.vault_id != intent.vault_id() || &local.public != intent.public()
        })
    {
        return Err(failure(
            "central key journal mapping changed; retained for recovery",
        ));
    }
    Ok(())
}
pub(super) fn context(
    env: &SyncEnv,
    state: &SyncStateV3,
    j: &Journal,
) -> Result<Option<Context>, AppError> {
    validate_journal(j)?;
    if let Some(intent) = j.central_intent.as_ref() {
        let context = Context::load(env, state)?;
        intent.verify_scope(state.local.central.as_ref().unwrap())?;
        return Ok(Some(context));
    }
    if invocation(state).is_some() && !j.keys.is_empty() {
        return Err(failure(
            "legacy private import needs explicit reconciliation with this central account",
        ));
    }
    Ok(None)
}
pub(super) fn before_vault(
    env: &SyncEnv,
    state: &SyncStateV3,
    j: &Journal,
    paths: &Paths,
    context: &Context,
) -> Result<(), AppError> {
    context.verify(env, state)?;
    confirm_staged_durability(paths, j)?;
    let scoped = ScopedKeychain {
        inner: env.keychain,
        import_id: &j.import_id,
        receipts: &paths.masters,
    };
    let staged = validate_vault(&paths.vault, &scoped)?;
    context.candidate(state, j, &staged)?;
    context.verify(env, state)?;
    let active = optional_bytes(
        &store::vault_path(&env.state_path),
        store::MAX_READ_ONLY_VAULT_BYTES,
    )?
    .as_ref()
    .map(|b| digest(b));
    if active != j.original_vault_digest && active != j.staged_vault_digest {
        return Err(failure(
            "original protected vault changed; import stage retained",
        ));
    }
    Ok(())
}
fn confirm_staged_durability(paths: &Paths, j: &Journal) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        for path in [
            &paths.journal,
            &paths.vault,
            &paths.state,
            &paths.original_state,
            &paths.original_vault,
            &paths.masters,
        ] {
            fsutil::check_write(path)?;
            let mut options = fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            match options.open(path) {
                Ok(file) if file.metadata()?.is_file() => file.sync_all()?,
                Err(e)
                    if e.kind() == ErrorKind::NotFound
                        && (path == &paths.masters
                            || path == &paths.original_vault
                                && j.original_vault_digest.is_none()) => {}
                _ => {
                    return Err(failure(
                        "local material stage is not a durable regular file",
                    ))
                }
            }
        }
        for directory in [
            Some(paths.dir.as_path()),
            paths.dir.parent(),
            paths.dir.parent().and_then(Path::parent),
        ] {
            fs::File::open(
                directory.ok_or_else(|| failure("local material stage has no parent"))?,
            )?
            .sync_all()?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (paths, j);
        Err(failure(
            "central material durability is unverified on this platform",
        ))
    }
}
/// Can only be made below after actual protected active-vault readback. No external constructor.
pub(crate) struct Publication {
    before: SyncStateV3,
    candidate: SyncStateV3,
    generation: u64,
    session: Option<Arc<Session>>,
    vault_digest: String,
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
            || !same_selection(core.central_session.as_ref(), self.session.as_ref())
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
            || invocation(before).is_none()
            || invocation(before) != invocation(candidate)
        {
            return Err(failure(
                "central local publication source changed; stage retained",
            ));
        }
        central::workspace::verify_publication(
            before.local.central.as_ref(),
            candidate.local.central.as_ref(),
        )?;
        crate::sync::records_v3::validate_state(candidate)
            .map_err(|_| failure("central local candidate is invalid"))
    }
    pub(crate) fn verify_vault(&self, state_path: &Path) -> Result<(), AppError> {
        if optional_bytes(
            &store::vault_path(state_path),
            store::MAX_READ_ONLY_VAULT_BYTES,
        )?
        .as_ref()
        .map(|b| digest(b))
        .as_ref()
            != Some(&self.vault_digest)
        {
            return Err(failure(
                "protected local vault changed before metadata publication; stage retained",
            ));
        }
        Ok(())
    }
}
pub(super) fn publish(env: &SyncEnv, j: &Journal, context: &Context) -> Result<(), AppError> {
    let paths = Paths::new(env, &j.import_id)?;
    confirm_staged_durability(&paths, j)?;
    central_stage::publish_vault_image(
        env,
        &paths,
        &j.original_vault_digest,
        j.staged_vault_digest
            .as_deref()
            .ok_or_else(|| failure("local protected vault receipt is missing"))?,
    )?;
    let (before, generation) = record_runtime::snapshot(env)?;
    context.verify(env, &before)?;
    let vault = validate_vault(&store::vault_path(&env.state_path), env.keychain)?;
    let candidate = context.candidate(&before, j, &vault)?;
    let vault_digest = j
        .staged_vault_digest
        .clone()
        .ok_or_else(|| failure("protected local vault receipt is missing"))?;
    let authority = Publication {
        before,
        candidate,
        generation,
        session: context.session.clone(),
        vault_digest,
    };
    authority.verify_vault(&env.state_path)?;
    step(PublishStep::BeforeStateSave)?;
    context.verify(env, &authority.before)?;
    record_runtime::publish_local_material(env, &authority)?;
    step(PublishStep::StateSaved)
}

/// Capture the public edit before publishing its cache, so a new source's initial public draft
/// cannot make its still-identical protected material temporarily unavailable.
pub(crate) fn rename(
    env: &SyncEnv,
    invocation: &Invocation,
    id: &str,
    expected: &KeySlotPayload,
    name: &str,
) -> Result<crate::sync::record_commands::RecordOverview, AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (before, generation) = record_runtime::snapshot(env)?;
    check_request(&before, generation, Some(invocation))?;
    let proposed =
        crate::sync::record_repository::rename_key(&before, id, expected, name, env.now())
            .map_err(|_| failure("key metadata changed; refresh and retry the rename"))?;
    if proposed != before {
        let context = Context::load(env, &before)?;
        let candidate = central::capture_public(&proposed, &context.keys, &context.identity.keys)?;
        step(PublishStep::BeforeStateSave)?;
        context.verify(env, &before)?;
        record_runtime::commit_candidate(env, generation, candidate)?;
    }
    let result = crate::sync::record_commands::overview(env)?;
    env.events.status();
    env.events.wake();
    Ok(result)
}
#[cfg(all(test, unix))]
#[path = "central_local_tests.rs"]
pub(in crate::sync) mod tests;
