//! User-facing account commands. Browser authorization and all token exchange remain native.
use super::{
    api::Api,
    bootstrap::{self, RecoveryReveal},
    browser::BrowserLogin,
    controller::{self, Status},
    crypto,
    oidc::BoundedHttp,
};
use crate::{error::AppError, state::AppState, sync::engine};
use tauri::{AppHandle, Manager};
use tauri_plugin_opener::OpenerExt;

#[tauri::command]
pub async fn central_status(app: AppHandle) -> Result<Status, AppError> {
    tauri::async_runtime::spawn_blocking(move || engine::with_env(&app, controller::status)?)
        .await
        .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_sign_in(app: AppHandle, service: String) -> Result<Status, AppError> {
    controller::require_enabled()?;
    let operation = crypto::random_id(16)?;
    {
        let state = app.state::<AppState>();
        let mut pending = state.sync.central_login.lock().unwrap();
        if pending.is_some() {
            return Err(AppError::Other(
                "A sign-in is already in progress. Finish or cancel it first.".into(),
            ));
        }
        // Reserve before discovery so cancellation also works while opening the provider.
        *pending = Some((operation.clone(), None));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let result = (|| {
            let info = Api::new(&service)?.info()?;
            engine::with_env(&app, |env| {
                controller::checked_config(env, &service, &info.oidc)
            })??;
            let http = BoundedHttp::new()?;
            let (login, url) = BrowserLogin::begin(info.oidc.clone(), &http)?;
            {
                let state = app.state::<AppState>();
                let mut pending = state.sync.central_login.lock().unwrap();
                if pending.as_ref().map(|(id, _)| id) != Some(&operation) {
                    return Err(AppError::Other("Sign-in was cancelled.".into()));
                }
                *pending = Some((operation.clone(), Some(login.cancellation())));
            }
            app.opener().open_url(url, None::<&str>).map_err(|_| {
                AppError::Other("Could not open the system browser for sign-in.".into())
            })?;
            let tokens = login.finish(&http)?;
            engine::with_env(&app, |env| {
                controller::establish(env, &service, info.oidc, tokens, Some(&operation))
            })?
        })();
        let current = {
            let state = app.state::<AppState>();
            let mut pending = state.sync.central_login.lock().unwrap();
            let current = pending.as_ref().map(|(id, _)| id) == Some(&operation);
            if current {
                if let Some((_, Some(cancel))) = pending.take() {
                    cancel.cancel();
                }
            }
            current
        };
        if current {
            if let Err(ref error) = result {
                app.state::<AppState>()
                    .sync
                    .core
                    .lock()
                    .unwrap()
                    .central_user_action = Some(error.to_string());
            }
            let _ = engine::with_env(&app, |env| env.events.status());
        }
        let result = result.and_then(|_| {
            engine::with_env(&app, |env| {
                super::joining::initialize(env)?;
                controller::status(env)
            })?
        });
        result
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub fn central_cancel_sign_in(app: AppHandle) -> Result<(), AppError> {
    controller::require_enabled()?;
    let state = app.state::<AppState>();
    if let Some((_, Some(cancel))) = state.sync.central_login.lock().unwrap().take() {
        cancel.cancel();
    }
    Ok(())
}
#[tauri::command]
pub async fn central_refresh(app: AppHandle) -> Result<Status, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            controller::refresh(env)?;
            super::joining::initialize(env)?;
            super::round::sync_once(env)?;
            controller::status(env)
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_sign_out(app: AppHandle) -> Result<Status, AppError> {
    tauri::async_runtime::spawn_blocking(move || engine::with_env(&app, controller::sign_out)?)
        .await
        .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_prepare_vault(app: AppHandle) -> Result<Status, AppError> {
    tauri::async_runtime::spawn_blocking(move || engine::with_env(&app, bootstrap::prepare)?)
        .await
        .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_reveal_recovery(app: AppHandle) -> Result<RecoveryReveal, AppError> {
    tauri::async_runtime::spawn_blocking(move || engine::with_env(&app, bootstrap::reveal)?)
        .await
        .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_confirm_recovery(app: AppHandle, root: String) -> Result<Status, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| bootstrap::confirm(env, &root))?
    })
    .await
    .map_err(engine::join_error)?
}

#[tauri::command]
pub async fn central_pairing_code(
    app: AppHandle,
) -> Result<super::devices::PairingReveal, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, super::devices::pairing_code)?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_devices(app: AppHandle) -> Result<super::devices::Registry, AppError> {
    tauri::async_runtime::spawn_blocking(move || engine::with_env(&app, super::devices::registry)?)
        .await
        .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_approve_device(app: AppHandle, code: String) -> Result<Status, AppError> {
    let code = zeroize::Zeroizing::new(code);
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| super::devices::approve(env, &code))?
    })
    .await
    .map_err(engine::join_error)?
}
