use super::*;
use crate::sync::crypto::{derive_account, generate_mnemonic, ChainKeys};
use crate::sync::env::{Clock, Keychain, SyncEnv, SyncEvents};
use crate::sync::runtime::{SyncCore, SyncRuntime};
use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::state_v2::AccountState;
use std::sync::atomic::{AtomicUsize, Ordering};

struct ForbiddenIo;
impl Keychain for ForbiddenIo {
    fn get(&self, _: &str) -> Result<Option<String>, AppError> {
        panic!("unexpected credential read")
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        panic!("unexpected credential write")
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        panic!("unexpected credential delete")
    }
}
impl Clock for ForbiddenIo {
    fn now_ms(&self) -> u64 {
        panic!("unexpected clock callback")
    }
}
impl SyncEvents for ForbiddenIo {
    fn status(&self) {
        panic!("unexpected event")
    }
    fn wake(&self) {
        panic!("unexpected event")
    }
}
struct Fixture {
    temp: tempfile::TempDir,
    runtime: SyncRuntime,
}
impl Fixture {
    fn new() -> Self {
        Self {
            temp: tempfile::tempdir().unwrap(),
            runtime: SyncRuntime::default(),
        }
    }
    fn env(&self) -> SyncEnv<'_> {
        SyncEnv {
            runtime: &self.runtime,
            ssh_dir: self.temp.path().join("ssh"),
            state_path: self.temp.path().join("sync-state.json"),
            home: None,
            keychain: &ForbiddenIo,
            events: &ForbiddenIo,
            clock: &ForbiddenIo,
            platform: "test",
        }
    }
    fn active() -> Self {
        let fixture = Self::new();
        activate_probe(
            &mut fixture.runtime.core.lock().unwrap(),
            StartupProbe::Records {
                state: Box::new(super::state()),
                fresh: false,
            },
        )
        .unwrap();
        fixture
    }
}
fn legacy_state() -> SyncStateV2 {
    SyncStateV2::fresh("legacy").unwrap()
}
fn v1() -> crate::sync::state::SyncState {
    serde_json::from_str(r#"{"version":1,"chain_id":null,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"legacy","relay_url":"http://127.0.0.1:8787","cursor_seq":9,"password_sync":false,"records":{},"last_sync_ms":null,"last_error":null}"#).unwrap()
}

#[test]
fn migration_activation_persists_before_switching_to_records() {
    let f = Fixture::new();
    activate_probe(
        &mut f.runtime.core.lock().unwrap(),
        StartupProbe::Legacy {
            state: DecodedState::V2(Box::new(legacy_state())),
        },
    )
    .unwrap();
    let generation = f.runtime.core.lock().unwrap().generation;
    let candidate = super::state();
    let env = f.env();
    let _life = f.runtime.lifecycle.lock().unwrap();
    let _vault = f.runtime.vault.lock().unwrap();
    let _publication = f.runtime.format_publication.lock().unwrap();
    let next = commit_migration_candidate(&env, generation, candidate.clone(), None).unwrap();
    assert_eq!(next, generation + 1);
    let core = f.runtime.core.lock().unwrap();
    assert_eq!(core.format, RuntimeFormat::Records);
    assert_eq!(core.records.as_ref(), Some(&candidate));
    assert!(core.state.is_none() && core.legacy.is_none());
    assert_eq!(
        serde_json::from_slice::<SyncStateV3>(&fs::read(&env.state_path).unwrap()).unwrap(),
        candidate
    );
}

/// Design 2026-10-26: a migration's candidate that carries the device-local grant memory is saved at state version 10 too.
#[test]
fn migration_activation_raises_the_version_for_grant_memory() {
    let f = Fixture::new();
    activate_probe(
        &mut f.runtime.core.lock().unwrap(),
        StartupProbe::Legacy {
            state: DecodedState::V2(Box::new(legacy_state())),
        },
    )
    .unwrap();
    let generation = f.runtime.core.lock().unwrap().generation;
    let mut candidate = super::state();
    candidate.local.transport_grants.insert(
        "0000000000000001".into(),
        crate::sync::transports::GrantMemory { justification: "restart app-api".into(), duration_secs: 1800 },
    );
    let env = f.env();
    let _life = f.runtime.lifecycle.lock().unwrap();
    let _vault = f.runtime.vault.lock().unwrap();
    let _publication = f.runtime.format_publication.lock().unwrap();
    commit_migration_candidate(&env, generation, candidate, None).unwrap();
    let core = f.runtime.core.lock().unwrap();
    assert_eq!(core.records.as_ref().unwrap().version, crate::sync::records_v3::TRANSPORT_SYNC_STATE_VERSION);
    let saved = serde_json::from_slice::<SyncStateV3>(&fs::read(&env.state_path).unwrap()).unwrap();
    assert_eq!(saved.version, crate::sync::records_v3::TRANSPORT_SYNC_STATE_VERSION);
    assert_eq!(saved.local.transport_grants.len(), 1);
}

#[test]
fn migration_failed_save_and_stale_generation_preserve_legacy_runtime_and_source() {
    let f = Fixture::new();
    let legacy = legacy_state();
    activate_probe(
        &mut f.runtime.core.lock().unwrap(),
        StartupProbe::Legacy {
            state: DecodedState::V2(Box::new(legacy.clone())),
        },
    )
    .unwrap();
    let env = f.env();
    let source = serde_json::to_vec(&legacy).unwrap();
    fs::write(&env.state_path, &source).unwrap();
    let generation = f.runtime.core.lock().unwrap().generation;
    assert!(commit_migration_candidate(&env, generation + 1, super::state(), None).is_err());
    assert_eq!(fs::read(&env.state_path).unwrap(), source);
    fs::remove_file(&env.state_path).unwrap();
    fs::create_dir(&env.state_path).unwrap();
    assert!(commit_migration_candidate(&env, generation, super::state(), None).is_err());
    let core = f.runtime.core.lock().unwrap();
    assert_eq!(core.format, RuntimeFormat::Legacy);
    assert_eq!(core.generation, generation);
    assert_eq!(core.state.as_ref(), Some(&legacy));
}

#[test]
fn activating_records_clears_legacy_keys_and_upgrade_state_in_the_single_core() {
    let mut core = SyncCore::default();
    core.state = Some(legacy_state());
    core.legacy = Some(v1());
    core.account_keys = Some(ChainKeys::generate().unwrap());
    core.generation = 7;
    core.unsaved = true;
    core.swap_pending = true;
    let records = super::state();
    activate_probe(
        &mut core,
        StartupProbe::Records {
            state: Box::new(records.clone()),
            fresh: false,
        },
    )
    .unwrap();
    assert_eq!(core.format, RuntimeFormat::Records);
    assert_eq!(core.records, Some(records));
    assert!(core.state.is_none());
    assert!(core.legacy.is_none());
    assert!(core.account_keys.is_none());
    assert_eq!(core.generation, 8);
    assert!(!core.unsaved);
    assert!(!core.swap_pending);
}
#[test]
fn legacy_activation_preserves_v1_source_and_refuses_writes() {
    let fixture = Fixture::active();
    let env = fixture.env();
    let original = v1();
    activate_probe(
        &mut fixture.runtime.core.lock().unwrap(),
        StartupProbe::Legacy {
            state: DecodedState::V1(Box::new(original.clone())),
        },
    )
    .unwrap();
    let mut core = fixture.runtime.core.lock().unwrap();
    assert_eq!(core.format, RuntimeFormat::Legacy);
    assert!(core.records.is_none());
    assert!(core.state.is_none());
    assert_eq!(core.legacy, Some(original));
    assert!(crate::sync::runtime::save_core(&mut core, &env.state_path).is_err());
    drop(core);
    assert!(snapshot(&env).is_err());
    assert!(!env.state_path.exists());
}
#[test]
fn blocked_activation_clears_both_models_and_refuses_snapshots_or_candidates() {
    let fixture = Fixture::active();
    let env = fixture.env();
    std::fs::write(&env.state_path, b"future bytes").unwrap();
    activate_probe(
        &mut fixture.runtime.core.lock().unwrap(),
        StartupProbe::Blocked {
            kind: StartupErrorKind::UnsupportedVersion,
            reason: "future state retained".into(),
        },
    )
    .unwrap();
    let core = fixture.runtime.core.lock().unwrap();
    assert_eq!(core.format, RuntimeFormat::Blocked);
    assert!(core.records.is_none());
    assert!(core.state.is_none());
    assert!(core.legacy.is_none());
    assert!(core.account_keys.is_none());
    let generation = core.generation;
    drop(core);
    assert!(snapshot(&env).is_err());
    assert!(commit_candidate(&env, generation, super::state()).is_err());
    assert_eq!(std::fs::read(&env.state_path).unwrap(), b"future bytes");
}
#[test]
fn successful_candidate_is_saved_before_memory_and_generation_are_published() {
    let fixture = Fixture::active();
    let env = fixture.env();
    let (mut candidate, generation) = snapshot(&env).unwrap();
    candidate.device_name = "Edited".into();
    let next = commit_candidate(&env, generation, candidate.clone()).unwrap();
    assert_eq!(next, generation + 1);
    assert_eq!(snapshot(&env).unwrap(), (candidate.clone(), next));
    assert!(
        matches!(probe_startup(&env.state_path,"unused"),StartupProbe::Records{state,..} if *state==candidate)
    );
    assert!(!fixture.runtime.core.lock().unwrap().unsaved);
}
#[test]
fn failed_user_save_leaves_original_memory_generation_and_pending_save_status_unchanged() {
    let fixture = Fixture::active();
    let env = fixture.env();
    std::fs::create_dir(&env.state_path).unwrap();
    std::fs::write(env.state_path.join("keep"), b"sentinel").unwrap();
    let (mut candidate, generation) = snapshot(&env).unwrap();
    let original = candidate.clone();
    candidate.device_name = "Not saved".into();
    assert!(commit_candidate(&env, generation, candidate).is_err());
    assert_eq!(snapshot(&env).unwrap(), (original, generation));
    assert!(!fixture.runtime.core.lock().unwrap().unsaved);
    assert_eq!(
        std::fs::read(env.state_path.join("keep")).unwrap(),
        b"sentinel"
    );
}
#[test]
fn stale_generation_cannot_replace_newer_host_or_account_state() {
    let fixture = Fixture::active();
    let env = fixture.env();
    let (mut stale, generation) = snapshot(&env).unwrap();
    stale.device_name = "Stale".into();
    mutate_records(&env, |current| {
        let mut next = current.clone();
        next.device_name = "Latest".into();
        Ok(next)
    })
    .unwrap();
    let latest = snapshot(&env).unwrap();
    let bytes = std::fs::read(&env.state_path).unwrap();
    assert!(commit_candidate(&env, generation, stale)
        .as_ref()
        .is_err_and(crate::sync::runtime::is_superseded));
    assert_eq!(snapshot(&env).unwrap(), latest);
    assert_eq!(std::fs::read(&env.state_path).unwrap(), bytes);
}
#[test]
fn validation_failure_generation_overflow_and_pure_transform_error_never_publish_or_save() {
    let fixture = Fixture::active();
    let env = fixture.env();
    let (mut invalid, generation) = snapshot(&env).unwrap();
    invalid.version = crate::sync::records_v3::PAM_STATE_VERSION + 1;
    assert!(commit_candidate(&env, generation, invalid).is_err());
    assert!(!env.state_path.exists());
    let original = snapshot(&env).unwrap();
    assert!(mutate_records(&env, |_| Err(AppError::Other("rejected edit".into()))).is_err());
    assert_eq!(snapshot(&env).unwrap(), original);
    fixture.runtime.core.lock().unwrap().generation = u64::MAX;
    let (mut candidate, generation) = snapshot(&env).unwrap();
    candidate.device_name = "Would overflow".into();
    assert!(commit_candidate(&env, generation, candidate).is_err());
    assert_eq!(fixture.runtime.core.lock().unwrap().generation, u64::MAX);
    assert!(!env.state_path.exists());
}
#[test]
fn save_blocked_prevents_transform_calls_and_preserves_old_records() {
    let fixture = Fixture::active();
    let env = fixture.env();
    fixture.runtime.core.lock().unwrap().save_blocked = Some("other process owns state".into());
    let before = snapshot(&env).unwrap();
    assert!(mutate_records(&env, |_| panic!("blocked transform must not run")).is_err());
    assert!(commit_candidate(&env, before.1, before.0.clone()).is_err());
    assert_eq!(snapshot(&env).unwrap(), before);
    assert!(!env.state_path.exists());
}
#[test]
fn save_core_dispatches_records_without_a_v2_fallback_and_keeps_retry_semantics() {
    let fixture = Fixture::active();
    let env = fixture.env();
    let mut core = fixture.runtime.core.lock().unwrap();
    crate::sync::runtime::save_core(&mut core, &env.state_path).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&env.state_path).unwrap())
            .unwrap()["version"],
        3
    );
    assert!(!core.unsaved);
    let bad = fixture.temp.path().join("bad");
    std::fs::create_dir(&bad).unwrap();
    assert!(crate::sync::runtime::save_core(&mut core, &bad).is_err());
    assert!(core.unsaved);
    crate::sync::runtime::save_core(&mut core, &env.state_path).unwrap();
    assert!(!core.unsaved);
}
struct ReadOnlyCodes {
    current: Option<String>,
    reads: AtomicUsize,
    writes: AtomicUsize,
}
impl Keychain for ReadOnlyCodes {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        assert_eq!(
            account, MNEMONIC_ACCOUNT,
            "never read or promote staged codes"
        );
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.current.clone())
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(AppError::Other("unexpected write".into()))
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(AppError::Other("unexpected delete".into()))
    }
}
#[test]
fn account_key_read_is_current_only_and_chain_verified_without_promotion_or_cleanup() {
    let phrase = generate_mnemonic().unwrap();
    let keys = derive_account(&phrase).unwrap();
    let mut records = super::state();
    records.account = Some(AccountState::new(&keys.chain_id));
    let keychain = ReadOnlyCodes {
        current: Some(phrase),
        reads: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    };
    assert_eq!(
        read_account_keys(&records, &keychain)
            .unwrap()
            .unwrap()
            .chain_id,
        keys.chain_id
    );
    assert_eq!(keychain.reads.load(Ordering::SeqCst), 1);
    assert_eq!(keychain.writes.load(Ordering::SeqCst), 0);
    records.account.as_mut().unwrap().chain_id = "b".repeat(64);
    assert!(read_account_keys(&records, &keychain).is_err());
    assert_eq!(keychain.writes.load(Ordering::SeqCst), 0);
}
#[test]
fn unjoined_or_invalid_records_never_access_credentials() {
    assert!(read_account_keys(&super::state(), &ForbiddenIo)
        .unwrap()
        .is_none());
    let mut invalid = super::state();
    invalid.version = crate::sync::records_v3::PAM_STATE_VERSION + 1;
    assert!(read_account_keys(&invalid, &ForbiddenIo).is_err());
}
#[test]
fn changing_account_clears_old_runtime_keys_after_durable_candidate_save() {
    let fixture = Fixture::active();
    let env = fixture.env();
    let keys = ChainKeys::generate().unwrap();
    let (mut old, generation) = snapshot(&env).unwrap();
    old.account = Some(AccountState::new(&keys.chain_id));
    commit_candidate(&env, generation, old).unwrap();
    fixture.runtime.core.lock().unwrap().account_keys = Some(keys);
    let (mut next, generation) = snapshot(&env).unwrap();
    next.account = None;
    commit_candidate(&env, generation, next).unwrap();
    assert!(fixture.runtime.core.lock().unwrap().account_keys.is_none());
}

#[test]
fn failed_user_save_preserves_an_existing_background_unsaved_retry_marker() {
    let fixture = Fixture::active();
    let env = fixture.env();
    std::fs::create_dir(&env.state_path).unwrap();
    fixture.runtime.core.lock().unwrap().unsaved = true;
    let before = snapshot(&env).unwrap();
    assert!(mutate_records(&env, |current| {
        let mut next = current.clone();
        next.device_name = "Unstored edit".into();
        Ok(next)
    })
    .is_err());
    assert_eq!(snapshot(&env).unwrap(), before);
    assert!(fixture.runtime.core.lock().unwrap().unsaved);
}
#[test]
fn invalid_activation_or_generation_overflow_never_erases_the_active_model() {
    let fixture = Fixture::active();
    let env = fixture.env();
    let before = snapshot(&env).unwrap();
    let mut invalid = state();
    invalid.version = 99;
    assert!(activate_probe(
        &mut fixture.runtime.core.lock().unwrap(),
        StartupProbe::Records {
            state: Box::new(invalid),
            fresh: false
        }
    )
    .is_err());
    assert_eq!(snapshot(&env).unwrap(), before);
    fixture.runtime.core.lock().unwrap().generation = u64::MAX;
    assert!(activate_probe(
        &mut fixture.runtime.core.lock().unwrap(),
        StartupProbe::Blocked {
            kind: StartupErrorKind::Io,
            reason: "blocked".into()
        }
    )
    .is_err());
    assert_eq!(snapshot(&env).unwrap(), (before.0, u64::MAX));
}
