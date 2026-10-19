//! Native source capture and durable start. No consent, network or library publication authority.
use super::{
    api::DeviceState,
    client_state::Phase,
    controller::{self, Session},
    credentials::DeviceIdentity,
    crypto::VaultKeys,
    inventory_keys::Capture,
    migration_files::Files,
    migration_materials::Materials,
    migration_sources::{Inventory, Sources},
    payload::KeyStorage,
    source_package::Package,
    wire::invalid,
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{
        crypto::ChainKeys,
        env::{NonInteractiveKeychain, SyncEnv},
        record_runtime,
        records_v3::SyncStateV3,
    },
};
use std::{collections::BTreeMap, sync::Arc};
struct Legacy(Option<ChainKeys>);
impl Drop for Legacy {
    fn drop(&mut self) {
        if let Some(keys) = &mut self.0 {
            keys.clear_sensitive();
        }
    }
}
/// A passive input snapshot. Later effects must compare the session/generation and inputs again.
pub(super) struct Captured {
    pub package: Package,
    pub generation: u64,
    pub session: Arc<Session>,
}
fn session(owner: &Workspace, session: &Session) -> Result<(), AppError> {
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let grant = session.device.as_ref().ok_or_else(invalid)?;
    let profile = owner.control.profile.profile()?;
    if session.profile != owner.control.profile
        || session.tokens.issuer != profile.issuer
        || session.tokens.subject != profile.subject
        || session.device_access_denied
        || grant.expired()
        || session
            .tokens_started
            .elapsed()
            .saturating_add(std::time::Duration::from_secs(5))
            >= session.tokens.expires_in
        || grant.device_state != DeviceState::Active
        || grant.account_id != owner.control.account_id
        || grant.auth_epoch != owner.control.auth_epoch
        || identity.device() != owner.control.device
        || identity.slot(&profile, "device")?
            != profile.device_slot("device", owner.identity_slot.as_deref())?
    {
        return Err(invalid());
    }
    Ok(())
}
fn protected(env: &SyncEnv, owner: &Workspace, current: &Session) -> Result<(), AppError> {
    session(owner, current)?;
    let cached = current.identity.as_ref().ok_or_else(invalid)?;
    let stored = DeviceIdentity::load_selected(
        env.keychain,
        &owner.control.profile.profile()?,
        owner.identity_slot.as_deref(),
        false,
    )?;
    if stored.device() != owner.control.device || stored.credential() != cached.credential() {
        return Err(invalid());
    }
    Ok(())
}
fn target(owner: &Workspace, current: &Session, keys: &VaultKeys) -> Result<(), AppError> {
    owner.validate()?;
    owner.require_key_recipients()?;
    session(owner, current)?;
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    if owner.control.phase != Phase::Enrolled
        || owner.control.proof.as_ref().is_none_or(|proof| proof.genesis.first != owner.control.device)
        || owner.control.cutover
        || owner.bootstrap.is_some()
        || owner.replacement.is_some()
        || !owner.replacement_archives.is_empty()
        || owner.recovery.is_some()
        || owner.rotation.is_some()
        || !owner.epochs.is_empty()
        || !owner.observed_epochs.is_empty()
        || replica.checkpoint.epoch != 1
        || replica.checkpoint.sequence != 0
        || replica.checkpoint.history_hash != "0".repeat(64)
        || !replica.baseline_ready()
        || !replica.current.is_empty()
        || !replica.pending.is_empty()
        || !replica.conflicts.is_empty()
    {
        return Err(invalid());
    }
    let chain = owner.control.verified_chain()?;
    replica.verify_write_authority(&chain, owner.control.auth_epoch, 1, &owner.epochs)?;
    let wrap = owner
        .own_wraps
        .iter()
        .find(|wrap| wrap.header.key_epoch == "1")
        .ok_or_else(invalid)?;
    let author = chain
        .author_at(&wrap.header.membership_head, &wrap.header.author)
        .ok_or_else(invalid)?;
    let opened = wrap.open(
        &current.identity.as_ref().ok_or_else(invalid)?.keys,
        &wrap.header,
        &author.signing,
    )?;
    opened.verify_same(keys)
}
pub(super) fn require_target(
    env: &SyncEnv,
    owner: &Workspace,
    selected: &Session,
    keys: &VaultKeys,
) -> Result<(), AppError> {
    target(owner, selected, keys)?;
    protected(env, owner, selected)
}
fn current(env: &SyncEnv) -> Result<(SyncStateV3, u64, Arc<Session>), AppError> {
    let core = env.runtime.core.lock().unwrap();
    if core.save_blocked.is_some() {
        return Err(invalid());
    }
    Ok((
        record_runtime::active_state(&core)?.clone(),
        core.generation,
        core.central_session.clone().ok_or_else(invalid)?,
    ))
}
pub(super) fn capture(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
) -> Result<Captured, AppError> {
    controller::require_enabled()?;
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (before, generation, selected) = current(env)?;
    let owner = before.local.central.as_ref().ok_or_else(invalid)?;
    target(owner, &selected, keys)?;
    protected(env, owner, &selected)?;
    let readonly = NonInteractiveKeychain(env.keychain);
    let account = Legacy(record_runtime::read_account_keys(&before, &readonly)?);
    let sources = Sources::discover(&before, account.0.as_ref())?;
    let record_inputs = Inventory::from_state(&sources, &before)?;
    let private_inputs = record_inputs.admit_known()?.into_keys();
    drop(record_inputs);
    let mut initial = super::source_archive::initial_inputs(env, &_life, owner)?;
    let original = initial.as_mut().and_then(|input| input.original.take());
    let mut package = if let Some(original) = original {
        let package = Package::decode_local(&original)?;
        if package.state != before {
            return Err(crate::sync::runtime::superseded());
        }
        package
    } else {
        let files = match &initial {
            Some(input) => Files::capture_after_archive(
                env,
                before.legacy_v1_backup.as_deref(),
                &input.outputs,
            )?,
            None => Files::capture(env, before.legacy_v1_backup.as_deref())?,
        };
        let observer = Capture::new(&readonly);
        drop(Materials::from_files_with_key_inputs(
            &before,
            keys,
            &files,
            &observer,
            references,
            private_inputs,
        )?);
        let decryptors = observer.finish()?;
        Package::assemble(
            &before,
            env.state_path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(invalid)?,
            files,
            sources,
            decryptors,
        )?
    };
    if let Some(input) = &initial {
        if !input.matches(&package.encode_local()?) {
            package.files.without_empty_source_root()?;
            if !input.matches(&package.encode_local()?) {
                return Err(crate::sync::runtime::superseded());
            }
        }
    }
    drop(package.materials(keys, references)?);
    let latest_account = Legacy(record_runtime::read_account_keys(&before, &readonly)?);
    let latest_sources = Sources::discover(&before, latest_account.0.as_ref())?;
    if latest_sources.encode_local()?.as_slice() != package.sources.encode_local()?.as_slice() {
        return Err(crate::sync::runtime::superseded());
    }
    match &initial {
        Some(input) => package.files.require_unchanged_after_archive(
            env,
            before.legacy_v1_backup.as_deref(),
            &input.outputs,
        )?,
        None => package
            .files
            .require_unchanged(env, before.legacy_v1_backup.as_deref())?,
    }
    protected(env, owner, &selected)?;
    let (latest, latest_generation, latest_session) = current(env)?;
    if generation != latest_generation
        || before != latest
        || !Arc::ptr_eq(&selected, &latest_session)
    {
        return Err(crate::sync::runtime::superseded());
    }
    session(owner, &selected)?;
    Ok(Captured {
        package,
        generation,
        session: selected,
    })
}

/// Foreground start/re-entry. Restore protected progress before considering a new capture.
pub(super) fn start_or_resume(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
) -> Result<super::capture_journal::Loaded, AppError> {
    controller::require_enabled()?;
    {
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        let (state, generation, selected) = current(env)?;
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        target(owner, &selected, keys)?;
        protected(env, owner, &selected)?;
        if let Some(saved) = super::source_cursor::Cursor::load(env, &life, owner)? {
            let signer = &selected.identity.as_ref().ok_or_else(invalid)?.keys;
            let loaded = if saved.cursor.revision() == 1 {
                let package = Package::decode_local(&saved.bytes)?;
                if package.state != state {
                    return Err(crate::sync::runtime::superseded());
                }
                drop(package.materials(keys, references)?);
                let cursor = if super::source_archive::initial_attached(env, owner, &saved.cursor)?
                {
                    saved.cursor
                } else {
                    package.initialize_source(env, &life, owner, 0)?.cursor
                };
                super::capture_journal::Journal::begin(&cursor, &package, signer)?.store(
                    env,
                    &life,
                    owner,
                    signer,
                    &cursor,
                    cursor.receipt().next_ordinal()?,
                )?
            } else {
                super::capture_journal::Journal::load(env, &life, owner, signer)?
                    .ok_or_else(invalid)?
            };
            if loaded.package.state != state {
                return Err(crate::sync::runtime::superseded());
            }
            let readonly = NonInteractiveKeychain(env.keychain);
            let legacy = Legacy(record_runtime::read_account_keys(&state, &readonly)?);
            let live = Sources::discover(&state, legacy.0.as_ref())?;
            if !loaded
                .package
                .sources
                .follows_book(&super::crypto::hash(&live.encode_local()?))?
            {
                return Err(crate::sync::runtime::superseded());
            }
            loaded.require_unchanged(env)?;
            protected(env, owner, &selected)?;
            let (latest, next_generation, next_session) = current(env)?;
            if latest != state
                || generation != next_generation
                || !Arc::ptr_eq(&selected, &next_session)
            {
                return Err(crate::sync::runtime::superseded());
            }
            return Ok(loaded);
        }
    }
    capture(env, keys, references)?.begin(env)
}

impl Captured {
    fn require_current(&self, env: &SyncEnv) -> Result<(), AppError> {
        let owner = self
            .package
            .state
            .local
            .central
            .as_ref()
            .ok_or_else(invalid)?;
        protected(env, owner, &self.session)?;
        let (state, generation, session) = current(env)?;
        if state != self.package.state
            || generation != self.generation
            || !Arc::ptr_eq(&session, &self.session)
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(())
    }
    /// The signed freeze intent is durable before transport can use it. No HTTP or events here.
    pub fn begin(&self, env: &SyncEnv) -> Result<super::capture_journal::Loaded, AppError> {
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        self.require_current(env)?;
        let owner = self
            .package
            .state
            .local
            .central
            .as_ref()
            .ok_or_else(invalid)?;
        env.runtime.core.lock().unwrap().central_migration_frozen = true;
        let initial = self.package.initialize_source(env, &life, owner, 0)?;
        self.require_current(env)?;
        let signer = &self.session.identity.as_ref().ok_or_else(invalid)?.keys;
        let journal =
            super::capture_journal::Journal::begin(&initial.cursor, &self.package, signer)?;
        let loaded = journal.store(
            env,
            &life,
            owner,
            signer,
            &initial.cursor,
            initial.cursor.receipt().next_ordinal()?,
        )?;
        self.require_current(env)?;
        loaded.require_unchanged(env)?;
        Ok(loaded)
    }
}
#[cfg(all(test, unix))]
pub(in crate::sync::central) mod tests {
    use super::*;
    use crate::sync::{
        central::{api::DeviceSession, crypto::DeviceKeys, oidc::LoginTokens},
        env::Keychain,
        state::MNEMONIC_ACCOUNT,
        testkit::{MemKeychain, TestDevice},
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::{
        fs,
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;
    pub(in crate::sync::central) fn fixture(joined: bool) -> (TestDevice, VaultKeys, Arc<Session>) {
        let (device, package, keys, owner, _) = super::super::source_package::tests::fixture();
        let mut state = package.state;
        if joined {
            let phrase = Zeroizing::new(crate::sync::crypto::generate_mnemonic().unwrap());
            let account = Legacy(Some(crate::sync::crypto::derive_account(&phrase).unwrap()));
            state.account = Some(crate::sync::state_v2::AccountState::new(
                &account.0.as_ref().unwrap().chain_id,
            ));
            device.keychain.set(MNEMONIC_ACCOUNT, &phrase).unwrap();
        } else {
            state.account = None;
        }
        let mut retained = state.clone();
        retained.version = crate::sync::records_v3::LOCAL_CONFLICT_STATE_VERSION;
        retained.local.central = None;
        fs::write(
            device.env().state_path.parent().unwrap().join("sync-state.retained"),
            serde_json::to_vec(&retained).unwrap(),
        ).unwrap();
        let profile = owner.control.profile.profile().unwrap();
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        let encoded=Zeroizing::new(serde_json::json!({"version":1,"locator":profile.locator,"id":owner.control.device.id,"keys":&*signer.encode_secret(),"credential":"d".repeat(64)}).to_string());
        device
            .keychain
            .set(
                &profile
                    .device_slot("device", owner.identity_slot.as_deref())
                    .unwrap(),
                &encoded,
            )
            .unwrap();
        let identity = Arc::new(
            DeviceIdentity::load_selected(
                &device.keychain,
                &profile,
                owner.identity_slot.as_deref(),
                false,
            )
            .unwrap(),
        );
        let selected = Arc::new(Session {
            profile: owner.control.profile.clone(),
            identity: Some(identity),
            tokens: Arc::new(LoginTokens {
                issuer: profile.issuer,
                subject: profile.subject,
                nonce: Zeroizing::new("synthetic nonce".into()),
                access: Zeroizing::new("synthetic access".into()),
                refresh: None,
                expires_in: Duration::from_secs(300),
            }),
            device: Some(DeviceSession::synthetic_for_test(
                owner.control.account_id.clone(),
                DeviceState::Active,
                owner.control.auth_epoch,
                Duration::from_secs(300),
            )),
            device_access_denied: false,
            tokens_started: Instant::now(),
        });
        fs::write(
            &device.env().state_path,
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        {
            let mut core = device.runtime.core.lock().unwrap();
            core.state = None;
            core.legacy = None;
            core.format = record_runtime::RuntimeFormat::Records;
            core.records = Some(state);
            core.save_blocked = None;
            core.generation = 9;
            core.central_session = Some(Arc::clone(&selected));
        }
        (device, keys, selected)
    }
    struct ReadOnly<'a> {
        inner: &'a MemKeychain,
    }
    impl Keychain for ReadOnly<'_> {
        fn get(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("preflight must not prompt")
        }
        fn get_noninteractive(&self, role: &str) -> Result<Option<String>, AppError> {
            assert!(!role.contains("password") && !role.contains("passphrase"));
            self.inner.get(role)
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("preflight cannot write")
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("preflight cannot erase")
        }
    }
    #[test]
    fn an_unreadable_retained_state_blocks_capture_without_creating_an_archive_or_credentials() {
        let (device, keys, _) = fixture(false);
        let readonly = ReadOnly {
            inner: &device.keychain,
        };
        let mut env = device.env();
        env.keychain = &readonly;
        fs::write(
            env.state_path.parent().unwrap().join("sync-state.extra"),
            b"UNREVIEWED-SECRET-SENTINEL",
        )
        .unwrap();
        let before = fs::read(&env.state_path).unwrap();
        let error = capture(&env, &keys, &BTreeMap::new())
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("UNREVIEWED-SECRET-SENTINEL"));
        assert_eq!(fs::read(&env.state_path).unwrap(), before);
        assert_eq!(device.runtime.core.lock().unwrap().generation, 9);
        assert!(!env
            .state_path
            .parent()
            .unwrap()
            .join("central-source-archives")
            .exists());
    }
    #[test]
    fn unknown_recovery_inputs_stop_actual_capture_before_archiving_or_publishing() {
        for (path, directory) in [
            ("imports/empty-unknown", true),
            ("migrations/old/journal.json", false),
            ("central-recovery-archives/old.lparch", false),
        ] {
            let (device, keys, _) = fixture(false);
            let readonly = ReadOnly { inner: &device.keychain };
            let mut env = device.env();
            env.keychain = &readonly;
            let root = env.state_path.parent().unwrap();
            let source = root.join(path);
            if directory {
                fs::create_dir_all(&source).unwrap();
            } else {
                fs::create_dir_all(source.parent().unwrap()).unwrap();
                fs::write(&source, b"UNREVIEWED-SECRET-SENTINEL").unwrap();
            }
            let before = fs::read(&env.state_path).unwrap();
            let error = capture(&env, &keys, &BTreeMap::new()).err().unwrap().to_string();
            assert!(!error.contains("UNREVIEWED-SECRET-SENTINEL"));
            assert_eq!(fs::read(&env.state_path).unwrap(), before);
            assert_eq!(device.runtime.core.lock().unwrap().generation, 9);
            assert!(!root.join("central-source-archives").exists());
            assert!(source.exists());
        }
    }
    #[test]
    fn local_and_joined_source_capture_are_read_only_noninteractive_and_leave_the_single_core_unchanged(
    ) {
        for joined in [false, true] {
            let (device, keys, selected) = fixture(joined);
            let readonly = ReadOnly {
                inner: &device.keychain,
            };
            let mut env = device.env();
            env.keychain = &readonly;
            let before = fs::read(&env.state_path).unwrap();
            let captured = capture(&env, &keys, &BTreeMap::new()).unwrap();
            assert_eq!(captured.generation, 9);
            assert!(Arc::ptr_eq(&captured.session, &selected));
            assert_eq!(captured.package.sources.chains().len(), usize::from(joined));
            assert_eq!(
                captured
                    .package
                    .materials(&keys, &BTreeMap::new())
                    .unwrap()
                    .retained,
                1
            );
            assert_eq!(fs::read(&env.state_path).unwrap(), before);
            assert_eq!(device.runtime.core.lock().unwrap().generation, 9);
            assert!(!env
                .state_path
                .parent()
                .unwrap()
                .join("central-source-archives")
                .exists());
        }
    }
    #[test]
    fn a_corrupt_pending_secret_that_is_not_part_of_source_key_discovery_blocks_capture() {
        use crate::sync::{
            record::{Record, RecordKind},
            state_v2::SealedRecord,
        };
        let (device, keys, _) = fixture(true);
        let env = device.env();
        let (mut state, _) = record_runtime::snapshot(&env).unwrap();
        let parent = Legacy(record_runtime::read_account_keys(&state, env.keychain).unwrap());
        let mut sealed = SealedRecord::seal(
            parent.0.as_ref().unwrap(),
            &Record {
                kind: RecordKind::Key,
                id: "1".repeat(32),
                version: 1,
                updated_at_ms: 1,
                device_id: state.device_id.clone(),
                deleted: false,
                payload: serde_json::json!({"schema":1,"private_key":"PRIVATE_PENDING_SENTINEL"}),
            },
            0,
        )
        .unwrap();
        sealed.envelope.ciphertext = B64.encode([0u8; 32]);
        state
            .account
            .as_mut()
            .unwrap()
            .sealed
            .insert(sealed.key(), sealed);
        assert!(Sources::discover(&state, parent.0.as_ref()).is_ok());
        fs::write(&env.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        device.runtime.core.lock().unwrap().records = Some(state);
        let error = capture(&env, &keys, &BTreeMap::new())
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE_PENDING_SENTINEL"));
        assert_eq!(device.runtime.core.lock().unwrap().generation, 9);
        assert!(!env
            .state_path
            .parent()
            .unwrap()
            .join("central-source-archives")
            .exists());
    }
    #[test]
    fn missing_expired_or_changed_protected_session_and_wrong_target_keys_block_before_archiving() {
        for case in [
            "missing-session",
            "expired",
            "missing-identity",
            "changed-credential",
            "wrong-keys",
            "blocked",
        ] {
            let (device, keys, selected) = fixture(false);
            let env = device.env();
            match case {
                "missing-session" => device.runtime.core.lock().unwrap().central_session = None,
                "expired" => {
                    let bad = Session {
                        profile: selected.profile.clone(),
                        identity: selected.identity.clone(),
                        tokens: Arc::clone(&selected.tokens),
                        device: Some(DeviceSession::synthetic_for_test(
                            selected.device.as_ref().unwrap().account_id.clone(),
                            DeviceState::Active,
                            selected.device.as_ref().unwrap().auth_epoch,
                            Duration::ZERO,
                        )),
                        device_access_denied: false,
                        tokens_started: selected.tokens_started,
                    };
                    device.runtime.core.lock().unwrap().central_session = Some(Arc::new(bad));
                }
                "missing-identity" | "changed-credential" => {
                    let profile = selected.profile.profile().unwrap();
                    let slot = profile.device_slot("device", None).unwrap();
                    if case == "missing-identity" {
                        device.keychain.delete(&slot).unwrap();
                    } else {
                        let mut value: serde_json::Value =
                            serde_json::from_str(&device.keychain.get(&slot).unwrap().unwrap())
                                .unwrap();
                        value["credential"] = "f".repeat(64).into();
                        device.keychain.set(&slot, &value.to_string()).unwrap();
                    }
                }
                "blocked" => {
                    device.runtime.core.lock().unwrap().save_blocked =
                        Some("synthetic block".into())
                }
                _ => {}
            }
            let wrong = VaultKeys::generate().unwrap();
            assert!(
                capture(
                    &env,
                    if case == "wrong-keys" { &wrong } else { &keys },
                    &BTreeMap::new()
                )
                .is_err(),
                "{case}"
            );
            assert!(!env
                .state_path
                .parent()
                .unwrap()
                .join("central-source-archives")
                .exists());
        }
    }
    struct Hook<'a> {
        device: &'a TestDevice,
        fired: AtomicBool,
        change: &'a str,
    }
    impl Keychain for Hook<'_> {
        fn get(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("capture cannot prompt")
        }
        fn get_noninteractive(&self, role: &str) -> Result<Option<String>, AppError> {
            let value = self.device.keychain.get(role)?;
            if crate::vault::store::is_vault_key_account(role)
                && !self.fired.swap(true, Ordering::SeqCst)
            {
                match self.change {
                    "session" => self.device.runtime.core.lock().unwrap().central_session = None,
                    "same-session" => {
                        let mut core = self.device.runtime.core.lock().unwrap();
                        let old = core.central_session.as_ref().unwrap();
                        let grant = old.device.as_ref().unwrap();
                        core.central_session = Some(Arc::new(Session {
                            profile: old.profile.clone(),
                            identity: old.identity.clone(),
                            tokens: Arc::clone(&old.tokens),
                            device: Some(DeviceSession::synthetic_for_test(
                                grant.account_id.clone(),
                                grant.device_state,
                                grant.auth_epoch,
                                Duration::from_secs(300),
                            )),
                            device_access_denied: old.device_access_denied,
                            tokens_started: old.tokens_started,
                        }));
                    }
                    "state" => {
                        let mut core = self.device.runtime.core.lock().unwrap();
                        core.records.as_mut().unwrap().device_name = "source B".into();
                        core.generation += 1;
                    }
                    "vault" => self.device.keychain.set(role, &B64.encode([7u8; 32]))?,
                    "legacy" => self.device.keychain.delete(MNEMONIC_ACCOUNT)?,
                    _ => {}
                }
            }
            Ok(value)
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("read observer cannot mutate")
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("read observer cannot erase")
        }
    }
    #[test]
    fn state_session_vault_and_legacy_key_changes_during_material_reads_never_return_a_stale_capture(
    ) {
        for change in ["session", "same-session", "state", "vault", "legacy"] {
            let (device, keys, _) = fixture(true);
            let hook = Hook {
                device: &device,
                fired: AtomicBool::new(false),
                change,
            };
            let mut env = device.env();
            env.keychain = &hook;
            assert!(capture(&env, &keys, &BTreeMap::new()).is_err(), "{change}");
            assert!(hook.fired.load(Ordering::SeqCst));
            assert!(!env
                .state_path
                .parent()
                .unwrap()
                .join("central-source-archives")
                .exists());
        }
    }
    #[test]
    fn known_private_frames_are_admitted_before_capture_and_restore_without_live_legacy_credentials() {
        use crate::sync::{record::{Record,RecordKind},state_v2::SealedRecord,slot_rules::test_keys};
        let plain=test_keys::plain();let encrypted=test_keys::encrypted();
        let cases=[
            (serde_json::json!({"schema":1,"private_key":plain}),Some(plain.as_str())),
            (serde_json::json!({"schema":1,"private_key":encrypted}),Some(encrypted.as_str())),
            (serde_json::json!({"schema":2,"private_key":plain}),None),
            (serde_json::json!({"schema":1,"private_key":"PRIVATE_PENDING_SENTINEL"}),None),
            (serde_json::json!({"schema":1,"private_key":encrypted,"password":"PRIVATE_PENDING_SENTINEL"}),None),
        ];
        for (payload,expected) in cases {
            let (device,keys,_)=fixture(true);let env=device.env();
            let (mut state,_)=record_runtime::snapshot(&env).unwrap();
            let parent=Legacy(record_runtime::read_account_keys(&state,env.keychain).unwrap());
            let row=SealedRecord::seal(parent.0.as_ref().unwrap(),&Record{kind:RecordKind::Key,id:"1".repeat(32),version:1,updated_at_ms:1,device_id:state.device_id.clone(),deleted:false,payload},0).unwrap();
            state.account.as_mut().unwrap().sealed.insert(row.key(),row);
            let original=serde_json::to_vec(&state).unwrap();fs::write(&env.state_path,&original).unwrap();
            device.runtime.core.lock().unwrap().records=Some(state);
            let readonly=ReadOnly{inner:&device.keychain};let mut safe=device.env();safe.keychain=&readonly;
            let result=capture(&safe,&keys,&BTreeMap::new());
            if let Some(expected)=expected {
                let captured=result.unwrap();
                let package=Package::decode_local(&captured.package.encode_local().unwrap()).unwrap();
                let inputs=package.record_inputs().unwrap().keys().unwrap();assert_eq!(inputs.len(),1);
                assert!(inputs[0].material.as_ref().unwrap().private()==expected);
            } else {
                assert!(!result.err().unwrap().to_string().contains("SENTINEL"));
            }
            assert_eq!(fs::read(&env.state_path).unwrap(),original);assert_eq!(device.runtime.core.lock().unwrap().generation,9);
            assert!(!env.state_path.parent().unwrap().join("central-source-archives").exists());
        }
    }

    #[test]
    fn an_authenticated_current_legacy_key_can_supply_a_missing_remote_copy_for_the_passive_plan() {
        use crate::sync::{
            record::{record_key, LocalRecord, Record, RecordKind},
            slot_rules::test_keys,
            state_v2::SealedRecord,
        };
        let (device, keys, _) = fixture(true);
        let env = device.env();
        let (mut state, _) = record_runtime::snapshot(&env).unwrap();
        let parent = Legacy(record_runtime::read_account_keys(&state, env.keychain).unwrap());
        let raw = test_keys::plain();
        let parsed = crate::vault::material::parse(&raw).unwrap();
        let id = "1".repeat(32);
        let public = crate::sync::records_v3::KeySlotPayload {
            schema: 2,
            name: "remote key".into(),
            public_key: parsed.public_key().to_openssh().unwrap(),
            fingerprint: parsed
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
            key_type: parsed.public_key().algorithm().as_str().into(),
            has_passphrase: false,
            created_at_ms: 1,
            origin_device_id: state.device_id.clone(),
        };
        let account = state.account.as_mut().unwrap();
        account.records.insert(
            record_key(RecordKind::KeySlot, &id),
            LocalRecord {
                record: Record {
                    kind: RecordKind::KeySlot,
                    id: id.clone(),
                    version: 1,
                    updated_at_ms: 1,
                    device_id: state.device_id.clone(),
                    deleted: false,
                    payload: serde_json::to_value(&public).unwrap(),
                },
                seq: 1,
                dirty: false,
            },
        );
        let row = SealedRecord::seal(
            parent.0.as_ref().unwrap(),
            &Record {
                kind: RecordKind::Key,
                id: id.clone(),
                version: 1,
                updated_at_ms: 1,
                device_id: state.device_id.clone(),
                deleted: false,
                payload: serde_json::json!({"schema":1,"private_key":raw}),
            },
            0,
        )
        .unwrap();
        account.sealed.insert(row.key(), row);
        let original = serde_json::to_vec(&state).unwrap();
        fs::write(&env.state_path, &original).unwrap();
        device.runtime.core.lock().unwrap().records = Some(state);
        let vault = fs::read(crate::vault::store::vault_path(&env.state_path)).unwrap();
        let captured = capture(&env, &keys, &BTreeMap::new()).expect(
            "current authenticated remote material must be admitted without a local pointer",
        );
        let restored = Package::decode_local(&captured.package.encode_local().unwrap()).unwrap();
        let materials = restored.materials(&keys, &BTreeMap::new()).unwrap();
        assert_eq!(materials.active.len(), 1);
        assert_eq!(materials.active[&id].public, public);
        assert_eq!(materials.retained, 1);
        assert!(materials.into_history().iter().any(|(logical,data)|logical.id==id && matches!(data,super::super::payload::Data::Key(private) if private.private()==raw)));
        assert_eq!(fs::read(&env.state_path).unwrap(), original);
        assert_eq!(
            fs::read(crate::vault::store::vault_path(&env.state_path)).unwrap(),
            vault
        );
        assert!(record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .keys
            .is_empty());
    }


    #[test]
    fn authenticated_unknown_or_unsupported_nonkey_payloads_block_capture_before_any_archive() {
        use crate::sync::{crypto, record::Envelope, state_v2::SealedRecord};
        for (kind, payload) in [
            (
                "future",
                serde_json::json!({"schema":1,"future_secret":"PRIVATE_SENTINEL"}),
            ),
            (
                "password",
                serde_json::json!({"schema":1,"password":"PRIVATE_SENTINEL"}),
            ),
            (
                "device",
                serde_json::json!({"schema":1,"name":"old","platform":"synthetic","joined_at_ms":1,"last_seen_ms":2,"future_secret":"PRIVATE_SENTINEL"}),
            ),
        ] {
            let (device, keys, _) = fixture(true);
            let env = device.env();
            let (mut state, _) = record_runtime::snapshot(&env).unwrap();
            let parent = Legacy(record_runtime::read_account_keys(&state, env.keychain).unwrap());
            let id = "1".repeat(32);
            let body=Zeroizing::new(serde_json::json!({"kind":kind,"id":id,"version":1,"updated_at_ms":1,"device_id":state.device_id,"deleted":false,"payload":payload}).to_string().into_bytes());
            let sealed = crypto::seal(parent.0.as_ref().unwrap(), kind, &id, &body).unwrap();
            let row = SealedRecord {
                envelope: Envelope {
                    id_hash: sealed.id_hash,
                    kind: kind.into(),
                    seq: 1,
                    nonce: sealed.nonce,
                    ciphertext: sealed.ciphertext,
                    deleted: false,
                },
                dirty: false,
                public_identity: None,
            };
            state
                .account
                .as_mut()
                .unwrap()
                .sealed
                .insert(row.key(), row);
            let original = serde_json::to_vec(&state).unwrap();
            fs::write(&env.state_path, &original).unwrap();
            device.runtime.core.lock().unwrap().records = Some(state);
            let readonly = ReadOnly {
                inner: &device.keychain,
            };
            let mut safe = device.env();
            safe.keychain = &readonly;
            assert!(!capture(&safe, &keys, &BTreeMap::new())
                .err()
                .unwrap()
                .to_string()
                .contains("SENTINEL"));
            assert_eq!(fs::read(&env.state_path).unwrap(), original);
            assert_eq!(device.runtime.core.lock().unwrap().generation, 9);
            assert!(!env
                .state_path
                .parent()
                .unwrap()
                .join("central-source-archives")
                .exists());
        }
    }

    struct InitialFault<'a>{inner:&'a MemKeychain,role:String,at:usize,after:bool,writes:std::sync::atomic::AtomicUsize}
    impl Keychain for InitialFault<'_>{
        fn get(&self,k:&str)->Result<Option<String>,AppError>{self.inner.get(k)}
        fn get_noninteractive(&self,k:&str)->Result<Option<String>,AppError>{self.inner.get_noninteractive(k)}
        fn set(&self,k:&str,v:&str)->Result<(),AppError>{self.inner.set(k,v)}
        fn delete(&self,_:&str)->Result<(),AppError>{panic!("capture/start must preserve credentials")}
        fn set_noninteractive(&self,k:&str,v:&str)->Result<(),AppError>{
            let n=if k==self.role {self.writes.fetch_add(1,Ordering::SeqCst)+1}else{usize::MAX};
            if n==self.at && !self.after {return Err(invalid());}
            self.inner.set_noninteractive(k,v)?;
            if n==self.at && self.after {return Err(invalid());}
            Ok(())
        }
    }
    #[test]
    fn native_capture_reloads_a_reserved_or_completed_first_package_then_begins_the_same_operation(){
        for (at,after) in [(1,true),(2,false),(2,true),(3,false)] {
            let (device,keys,_)=fixture(false);let env=device.env();
            let first=capture(&env,&keys,&BTreeMap::new()).unwrap();
            let original=first.package.encode_local().unwrap();
            let owner=first.package.state.local.central.clone().unwrap();
            let role=owner.control.profile.profile().unwrap().slot("source-migration-initial");
            let fault=InitialFault{inner:&device.keychain,role,at,after,writes:std::sync::atomic::AtomicUsize::new(0)};
            let mut interrupted=device.env();interrupted.keychain=&fault;
            {
                let life=env.runtime.lifecycle.lock().unwrap();
                assert!(first.package.initialize_source(&interrupted,&life,&owner,0).is_err());
            }
            drop(first);
            // No Captured or original Package object is supplied to the second capture.
            let resumed=capture(&env,&keys,&BTreeMap::new()).unwrap();
            assert_eq!(resumed.package.encode_local().unwrap().as_slice(),original.as_slice());
            let loaded=resumed.begin(&env).unwrap();
            assert_eq!(loaded.cursor.revision(),2);
            assert_eq!(loaded.intent().body.migration_id,loaded.cursor.receipt().operation());
            loaded.require_unchanged(&env).unwrap();
            assert!(!loaded.package.state.local.central.as_ref().unwrap().control.cutover);
            assert!(capture(&env,&keys,&BTreeMap::new()).is_err());
        }
    }
    #[test]
    fn actual_begin_rejects_a_replaced_runtime_session_before_creating_archive_outputs(){
        let (device,keys,_)=fixture(false);let env=device.env();let captured=capture(&env,&keys,&BTreeMap::new()).unwrap();
        device.runtime.core.lock().unwrap().central_session=None;
        assert!(captured.begin(&env).is_err());
        let root=env.state_path.parent().unwrap().join("central-source-archives");assert!(!root.exists());
    }

    #[test]
    fn start_reentry_recovers_a_lost_first_journal_cursor_without_reencrypting_its_orphan(){
        for after in [false,true] {
            let (device,keys,_)=fixture(false);let env=device.env();let owner=current(&env).unwrap().0.local.central.unwrap();
            let fault=InitialFault{inner:&device.keychain,role:owner.control.profile.profile().unwrap().slot("source-migration-cursor"),at:2,after,writes:std::sync::atomic::AtomicUsize::new(0)};
            let mut interrupted=device.env();interrupted.keychain=&fault;
            assert!(start_or_resume(&interrupted,&keys,&BTreeMap::new()).is_err());
            let root=env.state_path.parent().unwrap().join("central-source-archives");
            let exact: BTreeMap<_,_>=fs::read_dir(&root).unwrap().map(|e|{let e=e.unwrap();(e.file_name(),fs::read(e.path()).unwrap())}).collect();
            assert_eq!(exact.len(),3); // marker, original package, first capture journal.
            device.runtime.core.lock().unwrap().generation=0;
            let resumed=start_or_resume(&env,&keys,&BTreeMap::new()).unwrap();
            assert_eq!(resumed.cursor.revision(),2);assert_eq!(resumed.cursor.receipt().next_ordinal().unwrap(),2);
            let checked:BTreeMap<_,_>=fs::read_dir(&root).unwrap().map(|e|{let e=e.unwrap();(e.file_name(),fs::read(e.path()).unwrap())}).collect();
            assert_eq!(checked,exact);resumed.require_unchanged(&env).unwrap();
            let again=start_or_resume(&env,&keys,&BTreeMap::new()).unwrap();assert_eq!(again.cursor.receipt(),resumed.cursor.receipt());
        }
    }

}
