//! Native preflight input capture. No consent, transport, migration or publication authority.
use super::{
    api::DeviceState,
    client_state::Phase,
    controller::{self, Session},
    credentials::DeviceIdentity,
    crypto::VaultKeys,
    inventory_keys::Capture,
    migration_files::Files,
    migration_materials::Materials,
    migration_sources::Sources,
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
    let files = Files::capture(env, before.legacy_v1_backup.as_deref())?;
    let observer = Capture::new(&readonly);
    drop(Materials::from_files(
        &before, keys, &files, &observer, references,
    )?);
    let decryptors = observer.finish()?;
    let package = Package::assemble(
        &before,
        env.state_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(invalid)?,
        files,
        sources,
        decryptors,
    )?;
    let latest_account = Legacy(record_runtime::read_account_keys(&before, &readonly)?);
    let latest_sources = Sources::discover(&before, latest_account.0.as_ref())?;
    if latest_sources.encode_local()?.as_slice() != package.sources.encode_local()?.as_slice() {
        return Err(crate::sync::runtime::superseded());
    }
    package
        .files
        .require_unchanged(env, before.legacy_v1_backup.as_deref())?;
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

#[cfg(all(test, unix))]
mod tests {
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
    fn fixture(joined: bool) -> (TestDevice, VaultKeys, Arc<Session>) {
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
}
