//! The broker in the app (own-ssh spec §4): built in `setup` from the app's state, the same way on every platform, and listening on
//! `<app data>/ipc/sock` on macOS and Linux and on the user's named pipe on Windows (`session::pipe_name`), its lock in `<app data>/ipc`
//! either way. Its sessions keep the app running when the window is closed, quitting the app ends them, and a second launch with the host
//! flag (a client that found nobody listening) starts the listener again if it is down. A restart of the app (an update) ends every
//! session; the clients say so and exit.

use std::sync::Arc;

use tauri::Manager;
use zeroize::Zeroizing;

use super::auth::{KeyStore, VaultKey};
use super::broker::{Broker, QUIT_WAIT};
use super::hostkey_window::{TauriHostKeySurface, WindowConfirmer, HOSTKEY_TIMEOUT};
use crate::error::AppError;
use crate::state::AppState;
use crate::sync::env::{Keychain, OsKeychain};

/// Whether the broker listens.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BrokerStatus {
    #[default]
    NotStarted,
    Running,
    /// Another Lunport holds the broker's lock (a debug build next to the installed app).
    OtherInstance,
    Failed(String),
}

/// The vault key `key_id` as the sync state lists it: a key "Only in Lunport", named as the agent names it (the slot's name, else its

/// The SSH config the window loaded; when it has not loaded one within `wait` (an app started in the background by a client), the one

/// Whether closing the main window hides it instead of quitting: the tray setting, a host started for a client, or open sessions (which
/// quitting would end, spec §4).
pub fn hides_on_close(close_to_tray: bool, host_keep_alive: bool, sessions: bool) -> bool {
    close_to_tray || host_keep_alive || sessions
}

/// The vault through the app's state: which keys are "Only in Lunport" (the sync state) and their private halves (the vault file).
struct AppKeyStore {
    app: tauri::AppHandle,
}

impl KeyStore for AppKeyStore {
    fn key(&self,key_id:&str)->Option<VaultKey>{
        let state=self.app.state::<AppState>();let core=state.sync.core.lock().unwrap();
        match core.format {
            crate::sync::record_runtime::RuntimeFormat::Records=>{
                let key=crate::sync::record_repository::resolve_key(core.records.as_ref()?,key_id).ok()?;
                if key.status!=crate::sync::record_repository::KeyStatus::Available{return None;}
                let public=key.public?;Some(VaultKey{name:public.name,public_key:public.public_key})
            }
            _=>None,
        }
    }
    fn private_text(&self,key_id:&str)->Result<Option<Zeroizing<String>>,String>{self.read_private(key_id,true)}
    fn private_text_noninteractive(&self,key_id:&str)->Result<Option<Zeroizing<String>>,String>{self.read_private(key_id,false)}

}

impl AppKeyStore {
    fn read_private(&self,key_id:&str,interactive:bool)->Result<Option<Zeroizing<String>>,String>{
        if !interactive && !cfg!(windows) {return Err("needs interaction: this credential source has no verified noninteractive read".into());}
        crate::sync::engine::with_env(&self.app,|env|{
            let _lifecycle=env.runtime.lifecycle.lock().unwrap();
            let noninteractive=crate::sync::env::NonInteractiveKeychain(env.keychain);
            let read_keychain:&dyn Keychain=if interactive {&OsKeychain}else{&noninteractive};
            let format=env.runtime.core.lock().unwrap().format;
            match format {
                crate::sync::record_runtime::RuntimeFormat::Records=>{
                    drop(_lifecycle);
                    let _vault=env.runtime.vault.lock().unwrap();
                    let(s,_)=crate::sync::record_runtime::snapshot(env).map_err(|e|e.to_string())?;
                    let key=crate::sync::record_repository::resolve_key(&s,key_id).map_err(|e|e.to_string())?;
                    let Some(vault_id)=&key.vault_id else{return Ok(None);};
                    let vault=crate::vault::store::read_vault(&crate::vault::store::vault_path(&env.state_path),read_keychain).map_err(|_|"The vault is unavailable; its original file was retained.".to_string())?;
                    let Some(entry)=vault.get(vault_id).map_err(|_|"The saved key cannot be read.".to_string())? else{return Ok(None);};
                    super::record_material::verify(&key,&entry).map_err(str::to_owned)?;
                    Ok(Some(Zeroizing::new(entry.private_key.clone())))
                }
                _=>Err("The workspace is blocked.".into()),
            }
        }).map_err(|e|e.to_string()).and_then(|r|r)
        }
}

fn record_directory(app:&tauri::AppHandle)->super::record_directory::RecordDirectory{
    let(for_state,for_material,for_pin)=(app.clone(),app.clone(),app.clone());
    let sources=super::record_directory::RecordSources{
        snapshot:Box::new(move||crate::sync::engine::with_env(&for_state,|env|crate::sync::record_runtime::snapshot(env).map(|(s,_)|s)).map_err(|e|super::directory::DirectoryError::Failed(e.to_string()))?.map_err(|e|super::directory::DirectoryError::Failed(e.to_string()))),
        material:Box::new(move|key|crate::sync::engine::with_env(&for_material,|env|{
            let Some(id)=&key.vault_id else{return Ok(false);};let _vault=env.runtime.vault.lock().unwrap();
            let vault=crate::vault::store::read_vault(&crate::vault::store::vault_path(&env.state_path),&OsKeychain).map_err(|_|super::directory::DirectoryError::Failed("The vault is unavailable; its original file was retained.".into()))?;
            let entry=vault.get(id).map_err(|_|super::directory::DirectoryError::Failed("The saved key cannot be read.".into()))?;
            super::record_material::available(key,entry.as_ref()).map_err(|message|super::directory::DirectoryError::Unsupported(message.into()))
        }).map_err(|e|super::directory::DirectoryError::Failed(e.to_string()))?),
        username:Box::new(||super::os_identity::current_username().map_err(|_|super::directory::DirectoryError::Failed("Cannot read this device's operating system username.".into()))),
        pin:Box::new(move|id,endpoint,previous,candidate|crate::sync::engine::with_env(&for_pin,|env|{
            let now=env.now();
            let(s,_)=crate::sync::record_runtime::snapshot(env)?;
            crate::sync::record_repository::get_host(&s,id.as_str()).map_err(|e|AppError::Other(e.to_string()))?;
                        crate::sync::record_runtime::mutate_records(env,|s|crate::sync::record_repository::pin_host_key(s,id.as_str(),endpoint,previous,candidate.clone(),now).map_err(|e|AppError::Other(e.to_string())))?;
            env.events.wake();Ok::<_,AppError>(())
        }).map_err(|e|super::directory::DirectoryError::Failed(e.to_string()))?.map_err(|e|super::directory::DirectoryError::Failed(e.to_string()))),
    };
    let for_password = app.clone();
    let for_grant = app.clone();
    let app = app.clone();
    // Google Cloud IAP transports: OS Login and PAM through the app's one client (design 2026-10-25).
    let gcp: Arc<dyn crate::gcp::rest::GcpClient> = app.state::<AppState>().gcp.clone();
    super::record_directory::RecordDirectory::new(sources).with_password_reader(Box::new(move |hop,keychain| {
        crate::sync::engine::with_env(&for_password, |env| {
            let safe=crate::sync::env::SyncEnv{runtime:env.runtime,ssh_dir:env.ssh_dir.clone(),state_path:env.state_path.clone(),home:env.home.clone(),keychain,events:env.events,clock:env.clock,platform:env.platform};
            crate::sync::central::passwords::read(&safe,hop.id.as_str())
        }).map_err(|_|super::directory::DirectoryError::Failed("The saved password is unavailable.".into()))?
          .map_err(|_|super::directory::DirectoryError::Failed("Unlock your library to use its saved password.".into()))
    })).with_confirmed_pin(Box::new(
        move |hop, previous, key, cancel, guard| {
            // Native host-key trust authorizes this one credential read, without lifting the
            // background gate. Which questions an AI client's call may ask is the MCP
            // confirmer's (`mcp::records::ClientConfirmer`).
            crate::sync::engine::with_env(&app, |env| {
                super::record_pin::confirm(env, hop, previous, key, cancel, guard)
            })
            .map_err(|e| super::directory::DirectoryError::Failed(e.to_string()))?
            .map_err(|e| super::directory::DirectoryError::Failed(e.to_string()))
        },
    ))
    .with_gcp(gcp)
    // A grant the person requested from a connection: its justification and duration are remembered for its entitlement (the library's
    // grant memory, design 2026-10-27) and offered next time; what an earlier release remembered for the host goes.
    .with_grant_memory(Box::new(move |host, name, justification, duration_secs| crate::sync::engine::with_env(&for_grant, |env| {
        let now = env.now();
        crate::sync::record_runtime::mutate_records(env, |s| Ok(crate::sync::pam_records::remember(s, name, justification, duration_secs, Some(host.as_str()), now).unwrap_or_else(|| s.clone())))?;
        env.events.wake();
        Ok::<_, AppError>(())
    }).map_err(|e| super::directory::DirectoryError::Failed(e.to_string()))?.map_err(|e| super::directory::DirectoryError::Failed(e.to_string()))))
}

/// Builds the broker and starts its listener, unless it listens already: at the app's start (`setup`), and when a client found nobody
/// listening and started Lunport, which handed over to this instance (`on_second_launch`, which can come before `setup`'s start). What
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

/// Whether `start` has a listener to start: not when the broker listens already; after a failure, or while another Lunport held the
/// lock, it tries again.
fn needs_start(status: &BrokerStatus) -> bool {
    !matches!(status, BrokerStatus::Running)
}

fn listen(app: &tauri::AppHandle) -> BrokerStatus {
    let broker = {
        let state = app.state::<AppState>();
        let mut slot = state.session.broker.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            let confirmer = WindowConfirmer { hub: Arc::clone(&state.session.host_keys), surface: Arc::new(TauriHostKeySurface { app: app.clone() }), timeout: HOSTKEY_TIMEOUT };
            *slot = Some(Broker::new(
                Arc::new(crate::ssh::russh_engine::RusshEngine::new()),
                Arc::new(super::format_directory::FormatDirectory {
                    lifecycle: Arc::clone(&state.sync.lifecycle),
                    mode: { let app = app.clone(); Box::new(move || app.state::<AppState>().sync.core.lock().unwrap().format) },
                    records: Arc::new(record_directory(app)),
                }),
                Arc::new(AppKeyStore { app: app.clone() }),
                Arc::new(OsKeychain),
                Arc::new(confirmer),
            ));
        }
        slot.clone().expect("the broker was just built")
    };
    broker.set_audit({let app=app.clone();Arc::new(move |entry|app.state::<AppState>().mcp.record(entry))});
    broker.set_authentication_owner({
        let app = app.clone();
        let hub = Arc::clone(&app.state::<AppState>().session.auth_questions);
        Arc::new(move |id, cancel| Arc::new(super::auth_window::NativeOwner {
            ai: None,
            hub: Arc::clone(&hub),
            surface: Arc::new(super::auth_window::TauriAuthSurface { app: app.clone() }),
            request_id: format!("terminal-{id}"),
            cancel,
        }))
    });
    broker.set_mcp_handler({let app=app.clone();Arc::new(move |connector,method,params,context,cancel|crate::mcp::records::dispatch(&app,connector,method,params,context,cancel))});
    let dir = match crate::fsutil::app_data_root() {
        Ok(root) => super::ipc_dir(&root),
        Err(error) => return BrokerStatus::Failed(error.to_string()),
    };
    match listen_on(&dir, broker.handler()) {
        Ok(crate::ipc::server::Started::Running) => BrokerStatus::Running,
        Ok(crate::ipc::server::Started::OtherInstance) => BrokerStatus::OtherInstance,
        Err(error) => BrokerStatus::Failed(error.to_string()),
    }
}

/// The broker's endpoint (spec §4): the socket `<dir>/sock` on macOS and Linux.
#[cfg(unix)]
fn listen_on(dir: &std::path::Path, handler: crate::ipc::server::Handler) -> Result<crate::ipc::server::Started, AppError> {
    crate::ipc::server::listen_unix(dir, handler)
}

/// The broker's endpoint (spec §4): the user's named pipe on Windows, with the lock in `dir` as on the other platforms.
#[cfg(windows)]
fn listen_on(dir: &std::path::Path, handler: crate::ipc::server::Handler) -> Result<crate::ipc::server::Started, AppError> {
    crate::ipc::pipe_windows::listen(dir, &super::pipe_name()?, &crate::identity::thread_name("session"), handler)
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

    /// A start is a no-op for a broker that listens already; every other status is worth another try.
    #[test]
    fn only_a_broker_that_does_not_listen_is_started() {
        assert!(!needs_start(&BrokerStatus::Running));
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
