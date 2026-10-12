//! The broker in the app (own-ssh spec §4): built in `setup` from the app's state and listening on `<app data>/ipc/sock` (macOS and
//! Linux; the Windows transport is not part of plan 1b). Its sessions keep the app running when the window is closed, quitting the app
//! ends them, and a second launch with the host flag (a client that found nobody listening) starts the listener again if it is down.
//! A restart of the app (an update) ends every session; the clients say so and exit.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::Manager;
use zeroize::Zeroizing;

use super::auth::{KeyStore, VaultKey};
use super::broker::{Broker, QUIT_WAIT};
use super::hostkey_window::{TauriHostKeySurface, WindowConfirmer, HOSTKEY_TIMEOUT};
use super::pins::PinStore;
use super::ssh_config_directory::{vault_slot_of, Sources, SshConfigDirectory};
use crate::config::model::SshConfigDoc;
use crate::error::AppError;
use crate::state::AppState;
use crate::sync::env::{Keychain, OsKeychain};
use crate::sync::state_v2::{SlotSource, SyncStateV2};

/// Whether the broker listens.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BrokerStatus {
    #[default]
    NotStarted,
    Running,
    /// Another SSHelter holds the broker's lock (a debug build next to the installed app).
    OtherInstance,
    Failed(String),
    /// The broker has no transport on this platform in this version (Windows).
    NotOnThisPlatform,
}

/// How long a connect waits for the window to load the SSH config before reading it itself (as the MCP bridge waits).
const DOC_WAIT: Duration = Duration::from_secs(5);

/// The vault key `key_id` as the sync state lists it: a key "Only in SSHelter", named as the agent names it (the slot's name, else its
/// file name). `None` for a slot whose key is not in the vault.
pub fn vault_key_in(state: &SyncStateV2, key_id: &str) -> Option<VaultKey> {
    let local = state.key_slots.get(key_id)?;
    let Some(SlotSource::Vault { public_key, .. }) = &local.source else { return None };
    let name = local.payload.as_ref().map(|payload| payload.name.clone()).filter(|name| !name.is_empty()).unwrap_or_else(|| local.file_name.clone());
    Some(VaultKey { name, public_key: public_key.clone() })
}

/// The SSH config the window loaded; when it has not loaded one within `wait` (an app started in the background by a client), the one
/// `fallback` reads.
pub fn loaded_doc(doc: &Mutex<Option<SshConfigDoc>>, wait: Duration, fallback: impl FnOnce() -> Result<SshConfigDoc, AppError>) -> Result<SshConfigDoc, String> {
    let deadline = Instant::now() + wait;
    loop {
        if let Some(doc) = doc.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone() {
            return Ok(doc);
        }
        if Instant::now() >= deadline {
            return fallback().map_err(|error| error.to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether closing the main window hides it instead of quitting: the tray setting, a host started for a client, or open sessions (which
/// quitting would end, spec §4).
pub fn hides_on_close(close_to_tray: bool, host_keep_alive: bool, sessions: bool) -> bool {
    close_to_tray || host_keep_alive || sessions
}

/// The vault through the app's state: which keys are "Only in SSHelter" (the sync state) and their private halves (the vault file).
struct AppKeyStore {
    app: tauri::AppHandle,
}

impl KeyStore for AppKeyStore {
    fn key(&self, key_id: &str) -> Option<VaultKey> {
        let state = self.app.state::<AppState>();
        let core = state.sync.core.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        core.state.as_ref().and_then(|state| vault_key_in(state, key_id))
    }

    fn private_text(&self, key_id: &str) -> Result<Option<Zeroizing<String>>, String> {
        use crate::vault::store::{vault_path, with_vault};
        crate::sync::engine::with_env(&self.app, |env| {
            with_vault(env.runtime, &vault_path(&env.state_path), env.keychain, env.now(), |vault| vault.get(key_id))
                .map(|entry| entry.map(|entry| Zeroizing::new(entry.private_key.clone())))
                .map_err(|error| error.to_string())
        })
        .map_err(|error| error.to_string())
        .and_then(|inner| inner)
    }
}

/// The temporary directory over the app's ssh_config, sync state and keychain (`ssh_config_directory.rs`).
fn directory(app: &tauri::AppHandle) -> Result<SshConfigDirectory, AppError> {
    let pins = PinStore::new(crate::fsutil::app_data_root()?.join("host-pins.json"));
    let (for_doc, for_keys) = (app.clone(), app.clone());
    let sources = Sources {
        doc: Box::new(move || {
            let state = for_doc.state::<AppState>();
            loaded_doc(&state.doc, DOC_WAIT, || crate::config::include::load_doc(&crate::keys::ssh_dir()?.join("config")))
        }),
        // With a deadline: a `Match exec` in the user's config can keep `ssh -G` from ever answering, and the connect would hang with it.
        effective: Box::new(|alias| crate::session::ssh_g::effective_within(alias, None, crate::session::ssh_g::EFFECTIVE_DEADLINE)),
        vault_key: Box::new(move |identity_files| {
            let home = crate::keys::ssh_dir().ok()?.parent()?.to_path_buf();
            let state = for_keys.state::<AppState>();
            let core = state.sync.core.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            core.state.as_ref().and_then(|state| vault_slot_of(identity_files, state, &home))
        }),
        password_saved: Box::new(|host| OsKeychain.get(&crate::secrets::host_account(host.as_str())).ok().flatten().is_some_and(|password| !password.is_empty())),
    };
    Ok(SshConfigDirectory::new(sources, pins))
}

/// Builds the broker and starts its listener, unless it listens already: at the app's start (`setup`), and when a client found nobody
/// listening and started SSHelter, which handed over to this instance (`on_second_launch`, which can come before `setup`'s start). What
/// happened is recorded in `AppState::session`; nothing stops the app. The status stays locked from the look to the record, so two
/// starts at once listen once, and the second does not record `OtherInstance` (a second listener would find the lock held by this very
/// process). Locks: the status, then the broker (`listen`), never the other way.
pub fn start(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    let mut status = state.session.status.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !needs_start(&status) {
        return;
    }
    let now = listen(app);
    if let BrokerStatus::Failed(reason) = &now {
        eprintln!("[session] the broker is not listening: {reason}");
    }
    *status = now;
}

/// Whether `start` has a listener to start: not when the broker listens already, nor where it has no transport; after a failure, or
/// while another SSHelter held the lock, it tries again.
fn needs_start(status: &BrokerStatus) -> bool {
    !matches!(status, BrokerStatus::Running | BrokerStatus::NotOnThisPlatform)
}

#[cfg(unix)]
fn listen(app: &tauri::AppHandle) -> BrokerStatus {
    let broker = {
        let state = app.state::<AppState>();
        let mut slot = state.session.broker.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            let directory = match directory(app) {
                Ok(directory) => directory,
                Err(error) => return BrokerStatus::Failed(error.to_string()),
            };
            let confirmer = WindowConfirmer { hub: Arc::clone(&state.session.host_keys), surface: Arc::new(TauriHostKeySurface { app: app.clone() }), timeout: HOSTKEY_TIMEOUT };
            *slot = Some(Broker::new(
                Arc::new(crate::ssh::russh_engine::RusshEngine::new()),
                Arc::new(directory),
                Arc::new(AppKeyStore { app: app.clone() }),
                Arc::new(OsKeychain),
                Arc::new(confirmer),
            ));
        }
        slot.clone().expect("the broker was just built")
    };
    let dir = match crate::fsutil::app_data_root() {
        Ok(root) => super::ipc_dir(&root),
        Err(error) => return BrokerStatus::Failed(error.to_string()),
    };
    match crate::ipc::server::listen_unix(&dir, broker.handler()) {
        Ok(crate::ipc::server::Started::Running) => BrokerStatus::Running,
        Ok(crate::ipc::server::Started::OtherInstance) => BrokerStatus::OtherInstance,
        Err(error) => BrokerStatus::Failed(error.to_string()),
    }
}

#[cfg(windows)]
fn listen(_app: &tauri::AppHandle) -> BrokerStatus {
    BrokerStatus::NotOnThisPlatform
}

/// Whether any session is open.
pub fn has_sessions(app: &tauri::AppHandle) -> bool {
    let broker = app.state::<AppState>().session.broker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    broker.is_some_and(|broker| broker.has_sessions())
}

/// The app is quitting: every session ends, each client told why (spec §4). It waits the broker's `QUIT_WAIT`, not less: a shell that has
/// not printed yet is closed, and its client told, only after `SETTLE`, and the app exits when this returns.
pub fn quit(app: &tauri::AppHandle) {
    let broker = app.state::<AppState>().session.broker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    if let Some(broker) = broker {
        broker.end_all(QUIT_WAIT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::state_v2::LocalSlot;

    fn slot(file: &str, source: Option<SlotSource>) -> LocalSlot {
        LocalSlot {
            file_name: file.into(),
            source,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
            local_only: false,
        }
    }

    #[test]
    fn a_vault_key_is_one_only_in_sshelter_named_by_its_slot() {
        let mut state = SyncStateV2::fresh("mac").unwrap();
        let vault = SlotSource::Vault { fingerprint: "SHA256:v".into(), public_key: "ssh-ed25519 AAAA".into(), has_passphrase: true };
        state.key_slots.insert("a".repeat(32), slot("id_mac-aaaaaaaa", Some(vault)));
        state.key_slots.insert("b".repeat(32), slot("work-bbbbbbbb", Some(SlotSource::SyncedCopy { fingerprint: "SHA256:w".into() })));
        assert_eq!(vault_key_in(&state, &"a".repeat(32)), Some(VaultKey { name: "id_mac-aaaaaaaa".into(), public_key: "ssh-ed25519 AAAA".into() }));
        assert_eq!(vault_key_in(&state, &"b".repeat(32)), None, "a key in a file is not the vault's");
        assert_eq!(vault_key_in(&state, "missing"), None);
    }

    #[test]
    fn the_loaded_config_is_used_and_without_one_the_fallback_is_read_after_the_wait() {
        let doc = Mutex::new(Some(SshConfigDoc { files: Vec::new() }));
        assert!(loaded_doc(&doc, Duration::from_secs(5), || panic!("the window's config is there")).is_ok());

        let none = Mutex::new(None);
        let started = Instant::now();
        assert_eq!(loaded_doc(&none, Duration::from_millis(200), || Err(AppError::Other("no config".into()))).err(), Some("no config".to_string()));
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    /// A start is a no-op for a broker that listens already, or that has no transport here; every other status is worth another try.
    #[test]
    fn only_a_broker_that_does_not_listen_is_started() {
        assert!(!needs_start(&BrokerStatus::Running));
        assert!(!needs_start(&BrokerStatus::NotOnThisPlatform));
        for status in [BrokerStatus::NotStarted, BrokerStatus::OtherInstance, BrokerStatus::Failed("the socket path is too long".into())] {
            assert!(needs_start(&status), "{status:?}");
        }
    }

    #[test]
    fn closing_the_window_hides_it_while_sessions_are_open() {
        assert!(!hides_on_close(false, false, false), "nothing keeps the app: closing quits it");
        assert!(hides_on_close(false, false, true), "open sessions keep it");
        assert!(hides_on_close(true, false, false) && hides_on_close(false, true, false));
    }
}
