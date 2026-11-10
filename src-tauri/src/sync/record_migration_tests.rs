use super::*;
use crate::sync::crypto;
use crate::sync::env::Keychain;
use crate::sync::record_runtime;
use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::state_v2::AccountState;
use crate::sync::testkit::{TestClock, TestDevice};
use std::fs;

fn consent() -> MigrationConsent {
    MigrationConsent {
        old_clients_stopped_or_compatible: true,
    }
}

/// Saves the workspace in the core as the state file, as a Legacy build left it.
fn save_source(d: &TestDevice) {
    let core = d.runtime.core.lock().unwrap();
    let bytes = match (&core.state, &core.legacy) {
        (Some(v2), None) => serde_json::to_vec(v2).unwrap(),
        (None, Some(v1)) => serde_json::to_vec(v1).unwrap(),
        _ => panic!("one saved Legacy state"),
    };
    fs::create_dir_all(d.env().state_path.parent().unwrap()).unwrap();
    fs::write(d.env().state_path, bytes).unwrap();
}

#[test]
fn an_unjoined_legacy_profile_converts_local_sources_without_any_sync_code_or_relay() {
    let d = TestDevice::with_main_config(
        "d",
        &TestClock::new(),
        "Host local\n HostName local.test\n PreferredAuthentications password\n",
    );
    d.runtime.core.lock().unwrap().state.as_mut().unwrap().device_id = "a".repeat(32);
    save_source(&d);
    let prepared = prepare(&d.env(), None).unwrap();
    assert_eq!(prepared.preview().account_schema, 0);
    assert!(prepared.preview().selected_space_ids.is_empty());
    let receipt = confirm(&d.env(), prepared, consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&d.env()).unwrap().0;
    assert!(state.account.is_none());
    assert_eq!(state.local.hosts.len(), 1);
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_none());
}

#[test]
fn an_unsynced_legacy_v1_profile_converts_local_sources_too() {
    let d = TestDevice::with_main_config(
        "d",
        &TestClock::new(),
        "Host old\n HostName old.test\n PreferredAuthentications password\n",
    );
    let v1: crate::sync::state::SyncState = serde_json::from_str(r#"{"version":1,"chain_id":null,"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","device_name":"legacy","relay_url":"http://127.0.0.1:8787","cursor_seq":0,"password_sync":false,"records":{},"last_sync_ms":null,"last_error":null}"#).unwrap();
    {
        let mut core = d.runtime.core.lock().unwrap();
        core.state = None;
        core.legacy = Some(v1);
    }
    save_source(&d);
    let receipt = confirm(&d.env(), prepare(&d.env(), None).unwrap(), consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&d.env()).unwrap().0;
    assert!(state.account.is_none());
    assert_eq!(state.local.hosts.len(), 1);
}

/// A workspace that joined an account of the retired chain sync imports from its local files, managed space files included; the
/// account, which lived on the retired relay, stays behind.
#[test]
fn a_workspace_that_joined_the_retired_chain_sync_imports_its_local_files() {
    let d = TestDevice::with_main_config(
        "d",
        &TestClock::new(),
        "Include ~/.ssh/sshelter/work.config\nHost local\n HostName local.test\n PreferredAuthentications password\n", // frozen-identity: the managed folder as it is on users' disks.
    );
    fs::create_dir_all(d.ssh_dir().join("sshelter")).unwrap(); // frozen-identity: the managed folder as it is on users' disks.
    fs::write(
        d.ssh_dir().join("sshelter/work.config"), // frozen-identity: the managed folder as it is on users' disks.
        "Host web\n HostName web.test\n PreferredAuthentications password\n",
    )
    .unwrap();
    let code = crypto::generate_mnemonic().unwrap();
    let account = crypto::derive_account(&code).unwrap();
    d.keychain.set(MNEMONIC_ACCOUNT, &code).unwrap();
    {
        let mut core = d.runtime.core.lock().unwrap();
        let s = core.state.as_mut().unwrap();
        s.device_id = "a".repeat(32);
        s.account = Some(AccountState::new(&account.chain_id));
        s.spaces.insert(
            crypto::ChainKeys::generate().unwrap().chain_id,
            crate::sync::state_v2::SpaceState::new("work.config"),
        );
    }
    save_source(&d);
    let prepared = prepare(&d.env(), None).unwrap();
    assert_eq!(prepared.preview().account_schema, 0);
    let receipt = confirm(&d.env(), prepared, consent()).unwrap();
    assert!(receipt.complete);
    let state = record_runtime::snapshot(&d.env()).unwrap().0;
    assert!(state.account.is_none() && state.spaces.is_empty());
    let mut aliases: Vec<_> = crate::sync::record_repository::list_hosts(&state)
        .unwrap()
        .into_iter()
        .map(|host| host.host.payload.alias)
        .collect();
    aliases.sort();
    assert_eq!(aliases, ["local", "web"]);
    assert_eq!(d.keychain.entry(MNEMONIC_ACCOUNT).as_deref(), Some(code.as_str()));
}

/// A sync code entered for an old account would publish through the retired chain relay: the review says so before it writes a
/// journal or touches a credential.
#[test]
fn an_entered_sync_code_is_refused_before_any_journal_or_credential_write() {
    let d = TestDevice::new("d", &TestClock::new());
    let code = crypto::generate_mnemonic().unwrap();
    let account = crypto::derive_account(&code).unwrap();
    {
        let mut core = d.runtime.core.lock().unwrap();
        let s = core.state.as_mut().unwrap();
        s.device_id = "a".repeat(32);
        s.account = Some(AccountState::new(&account.chain_id));
    }
    save_source(&d);
    let saved = fs::read(d.env().state_path).unwrap();
    let error = prepare(&d.env(), Some(zeroize::Zeroizing::new(code.clone())))
        .unwrap_err()
        .to_string();
    assert_eq!(error, CHAIN_RETIRED);
    assert!(pending_migrations(&d.env()).unwrap().is_empty());
    assert_eq!(fs::read(d.env().state_path).unwrap(), saved);
    assert!(d.keychain.entry(MNEMONIC_ACCOUNT).is_none());
}

/// An interruption before the records state is saved leaves the journal; resuming it finishes the import once.
#[test]
fn an_interrupted_local_import_resumes_from_its_journal() {
    let d = TestDevice::with_main_config(
        "d",
        &TestClock::new(),
        "Host local\n HostName local.test\n PreferredAuthentications password\n",
    );
    d.runtime.core.lock().unwrap().state.as_mut().unwrap().device_id = "a".repeat(32);
    save_source(&d);
    let prepared = prepare(&d.env(), None).unwrap();
    let interrupted = with_test_step(
        |step| if step == Step::BeforeStateSave { Err(failure("interrupted before the state save")) } else { Ok(()) },
        || confirm(&d.env(), prepared, consent()),
    );
    assert!(interrupted.is_err());
    let pending = pending_migrations(&d.env()).unwrap();
    assert_eq!(pending.len(), 1);
    let receipt = resume(&d.env(), &pending[0].migration_id).unwrap();
    assert!(receipt.complete);
    assert!(pending_migrations(&d.env()).unwrap().is_empty());
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap().0.local.hosts.len(), 1);
}
