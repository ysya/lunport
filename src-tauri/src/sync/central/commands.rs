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
pub async fn central_sign_in(app: AppHandle, service: String, method: Option<super::authentication::Method>) -> Result<Status, AppError> {
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
            let config=engine::with_env(&app,|env|{
                let (state,_)=crate::sync::record_runtime::snapshot(env)?;
                let config=info.login_for_method(&service,state.local.central.as_ref().map(|w|&w.control.profile),method)?;
                controller::checked_config(env,&service,&config)?;
                Ok::<_,AppError>(config)
            })??;
            let http = BoundedHttp::new()?;
            let (login, url) = BrowserLogin::begin(config.clone(), &http)?;
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
                controller::establish(env, &service, config, tokens, Some(&operation))
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

#[tauri::command]
pub async fn central_revoke_device(
    app: AppHandle,
    device: String,
    membership_head: String,
    authorization_epoch: String,
    fingerprint: String,
) -> Result<super::devices::RevokeResult, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::devices::revoke(
                env,
                &device,
                &membership_head,
                &authorization_epoch,
                &fingerprint,
            )
        })?
    })
    .await
    .map_err(engine::join_error)?
}

#[tauri::command]
pub async fn central_account_access(
    app: AppHandle,
) -> Result<super::account_access::Registry, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, super::account_access::registry)?
    })
    .await
    .map_err(engine::join_error)?
}

#[tauri::command]
pub async fn central_revoke_account_device(
    app: AppHandle,
    selection: super::account_access::Selection,
) -> Result<super::devices::RevokeResult, AppError> {
    controller::require_enabled()?;
    let prepared = {
        let app = app.clone();
        let _ = engine::with_env(&app, |env| env.events.status());
        tauri::async_runtime::spawn_blocking(move || {
            engine::with_env(&app, |env| {
                super::account_access::prepare_revoke(env, selection)
            })?
        })
        .await
        .map_err(engine::join_error)??
    };
    let operation = crypto::random_id(16)?;
    {
        let state = app.state::<AppState>();
        let mut pending = state.sync.central_login.lock().unwrap();
        if pending.is_some() {
            return Err(AppError::Other(
                "A sign-in is already in progress. Finish or cancel it first.".into(),
            ));
        }
        *pending = Some((operation.clone(), None));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let result = (|| {
            let http = BoundedHttp::new()?;
            let (login, url) = BrowserLogin::begin_fresh_for(prepared.profile.login.clone(), &prepared.profile.locator, &http)?;
            {
                let state = app.state::<AppState>();
                let mut pending = state.sync.central_login.lock().unwrap();
                if pending.as_ref().map(|(id, _)| id.as_str()) != Some(operation.as_str()) {
                    return Err(AppError::Other(
                        "Account authentication was cancelled.".into(),
                    ));
                }
                *pending = Some((operation.clone(), Some(login.cancellation())));
            }
            app.opener().open_url(url, None::<&str>).map_err(|_| {
                AppError::Other(
                    "Could not open the system browser for account authentication.".into(),
                )
            })?;
            let fresh = login.finish_fresh(&http)?;
            engine::with_env(&app, |env| {
                super::account_access::complete_revoke(env, prepared, fresh, &operation)
            })?
        })();
        {
            let state = app.state::<AppState>();
            let mut pending = state.sync.central_login.lock().unwrap();
            if pending.as_ref().map(|(id, _)| id.as_str()) == Some(operation.as_str()) {
                if let Some((_, Some(cancel))) = pending.take() {
                    cancel.cancel();
                }
            }
        }
        let _ = engine::with_env(&app, |env| env.events.status());
        result
    })
    .await
    .map_err(engine::join_error)?
}

#[tauri::command]
pub async fn central_recovery_status(
    app: AppHandle,
) -> Result<super::recovery_flow::Progress, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, super::recovery_flow::status)?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_begin_account_recovery(
    app: AppHandle,
    kit: Option<String>,
) -> Result<super::recovery_flow::Progress, AppError> {
    let kit = kit.map(zeroize::Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::recovery_flow::begin(env, kit.as_deref().map(String::as_str))
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_revalidate_account_recovery(
    app: AppHandle,
    kit: Option<String>,
) -> Result<super::recovery_flow::Progress, AppError> {
    let kit = kit.map(zeroize::Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::recovery_flow::revalidate(env, kit.as_deref().map(String::as_str))
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_advance_account_recovery(
    app: AppHandle,
) -> Result<super::recovery_flow::Progress, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, super::recovery_flow::advance)?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub fn central_cancel_account_recovery(app: AppHandle) -> Result<(), AppError> {
    controller::require_enabled()?;
    engine::with_env(&app, |env| super::recovery_flow::cancel(env))?;
    Ok(())
}
#[tauri::command]
pub async fn central_reveal_new_recovery(app: AppHandle) -> Result<RecoveryReveal, AppError> {
    controller::require_enabled()?;
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, super::recovery_credentials::reveal)?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_confirm_account_recovery(
    app: AppHandle,
    operation: String,
) -> Result<super::recovery_flow::Progress, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| super::recovery_flow::confirm(env, &operation))?
    })
    .await
    .map_err(engine::join_error)?
}

// UI commands accept exact native invocation fences; convenience flow methods are not IPC APIs.
#[tauri::command]
pub async fn central_replacement_status(
    app: AppHandle,
) -> Result<super::replacement_flow::Progress, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, super::replacement_flow::status)?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_replacement_reserve(
    app: AppHandle,
    route: super::replacement::Route,
) -> Result<super::replacement_flow::Invocation, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::replacement_flow::reserve_invocation(env, route)
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_replacement_start(
    app: AppHandle,
    invocation: super::replacement_flow::Invocation,
    kit: Option<String>,
) -> Result<super::replacement_flow::Progress, AppError> {
    let kit = kit.map(zeroize::Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::replacement_flow::start_invocation(
                env,
                &invocation,
                kit.as_deref().map(String::as_str),
            )
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_replacement_continue(
    app: AppHandle,
    invocation: super::replacement_flow::Invocation,
    operation: String,
) -> Result<super::replacement_flow::Progress, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::replacement_flow::continue_invocation(env, &invocation, &operation)
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_replacement_revalidate(
    app: AppHandle,
    invocation: super::replacement_flow::Invocation,
    operation: String,
    kit: Option<String>,
) -> Result<super::replacement_flow::Progress, AppError> {
    let kit = kit.map(zeroize::Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::replacement_flow::revalidate_invocation(
                env,
                &invocation,
                &operation,
                kit.as_deref().map(String::as_str),
            )
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_replacement_cancel(
    app: AppHandle,
    invocation: super::replacement_flow::Invocation,
) -> Result<super::replacement_flow::Progress, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::replacement_flow::cancel_invocation(env, &invocation)
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_replacement_reveal_pairing(
    app: AppHandle,
    invocation: super::replacement_flow::Invocation,
    operation: String,
) -> Result<super::devices::PairingReveal, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::replacement_flow::reveal_pairing_invocation(env, &invocation, &operation)
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_replacement_reveal_kit(
    app: AppHandle,
    invocation: super::replacement_flow::Invocation,
    operation: String,
) -> Result<RecoveryReveal, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::replacement_flow::reveal_kit_invocation(env, &invocation, &operation)
        })?
    })
    .await
    .map_err(engine::join_error)?
}
#[tauri::command]
pub async fn central_replacement_confirm(
    app: AppHandle,
    invocation: super::replacement_flow::Invocation,
    operation: String,
) -> Result<super::replacement_flow::Progress, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        engine::with_env(&app, |env| {
            super::replacement_flow::confirm_invocation(env, &invocation, &operation)
        })?
    })
    .await
    .map_err(engine::join_error)?
}
