//! What the window asks of the migration: where it stands, and the ways on from a blocked start (try again, settle a conflict, go on
//! without a folder that will not move). Each way on restarts the app once nothing blocks the start any more.

use serde::Serialize;

use super::{
    last, record, resolve, retry_credentials, run, skip, ConflictChoice, DeferReason, Entry, Outcome, Report, Roots, Step, STARTUP,
};
use crate::error::AppError;

/// Where the migration stands, for the window.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum MigrationState {
    NotNeeded,
    Completed,
    CredentialsPending,
    Deferred,
    Conflict,
}

/// This process's migration, for the window (`identity_migration_status`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct MigrationStatus {
    pub state: MigrationState,
    /// A conflict's old data root.
    pub old_path: Option<String>,
    /// A conflict's new data root.
    pub new_path: Option<String>,
    /// What held a deferred migration back: the lock an earlier version holds, or the error of the step that failed. With saved
    /// credentials under the earlier name: why.
    pub detail: Option<String>,
    /// The step that failed, when a deferred migration did not wait for another process. With saved credentials under the earlier
    /// name: the credential step, when Retry can move them now (`identity_migration_retry_credentials`): the vault waits for its keys,
    /// or the move waits for the user.
    pub failed_step: Option<Step>,
    /// How many saved credentials are under the earlier name, as far as the last attempt saw: what is left for a later start, and what
    /// stays for good (said once, by the start that finished the step). Those that wait for the user's permission are counted apart.
    pub credentials_left: u32,
    /// How many saved credentials wait for the user's permission before Lunport can move them: macOS asks once for each when the user
    /// agrees (`identity_migration_adopt_credentials`).
    pub credentials_need_permission: u32,
    /// With the credential step as `failed_step`: whether Retry can move some now (the keychain is locked, say), beside what waits for
    /// the user's permission. Not when only that permission holds the vault back.
    pub credentials_retry_helps: bool,
    /// For how many of the items that wait for the user's permission they chose Later at an earlier start
    /// (`identity_migration_put_off_credentials`): the window keeps the sheet that asks for it away for as many, and offers a reminder
    /// with Allow… instead. 0 while a vault key waits for permission: the vault stays closed until the user allows it, so the sheet asks.
    pub credentials_permission_put_off: u32,
}

impl MigrationStatus {
    pub(super) fn of(report: Option<&Report>) -> Self {
        let mut status = Self {
            state: MigrationState::NotNeeded,
            old_path: None,
            new_path: None,
            detail: None,
            failed_step: None,
            credentials_left: 0,
            credentials_need_permission: 0,
            credentials_retry_helps: false,
            credentials_permission_put_off: 0,
        };
        let Some(report) = report else { return status };
        status.detail = report.detail.clone();
        if let Some(left) = &report.credentials {
            status.detail = Some(left.why.clone());
            status.failed_step = left.retry.then_some(Step::Credentials);
            status.credentials_left = u32::try_from(left.count).unwrap_or(u32::MAX);
            status.credentials_need_permission = u32::try_from(left.permission).unwrap_or(u32::MAX);
            status.credentials_retry_helps = left.retry && left.retry_helps;
            status.credentials_permission_put_off = u32::try_from(left.put_off).unwrap_or(u32::MAX);
        }
        status.state = match &report.outcome {
            Outcome::NotNeeded => MigrationState::NotNeeded,
            Outcome::Completed => MigrationState::Completed,
            Outcome::CredentialsPending => MigrationState::CredentialsPending,
            Outcome::Deferred(DeferReason::OldInstanceRunning) => MigrationState::Deferred,
            Outcome::Deferred(DeferReason::StepFailed { step, error }) => {
                status.failed_step = Some(*step);
                status.detail = Some(error.clone());
                MigrationState::Deferred
            }
            Outcome::Conflict { old, new } => {
                status.old_path = Some(old.display().to_string());
                status.new_path = Some(new.display().to_string());
                MigrationState::Conflict
            }
        };
        status
    }
}

#[tauri::command]
pub fn identity_migration_status() -> MigrationStatus {
    MigrationStatus::of(last().as_ref().map(|(_, report)| report))
}

/// Runs a blocked migration again (once the user has quit the earlier Lunport, say). A start that was not blocked has nothing to retry.
#[tauri::command]
pub async fn identity_migration_retry(app: tauri::AppHandle) -> Result<MigrationStatus, AppError> {
    if !super::blocks_startup() {
        return Ok(identity_migration_status());
    }
    way_on(app, |roots| Ok(run(Entry::Desktop, roots, &STARTUP))).await
}

/// Settles the conflict this start found the way the user chose.
#[tauri::command]
pub async fn identity_migration_resolve_conflict(
    app: tauri::AppHandle,
    choice: ConflictChoice,
) -> Result<MigrationStatus, AppError> {
    way_on(app, move |roots| match last() {
        Some((_, Report { outcome: Outcome::Conflict { .. }, .. })) => Ok(resolve(choice, roots, &STARTUP)),
        _ => Err(AppError::Other("There is no conflict between data folders to settle.".into())),
    })
    .await
}

/// Moves the saved credentials again, from the window: once the user has unlocked their keyring, say. Only when the status asks for
/// it (a blocked start has `identity_migration_retry`), and never at the same time as another run of the saved credentials. Lunport
/// restarts only when the retry changed what the running app has (`restarts_after`); otherwise the status says what is left, and why.
/// A run that finds the migration's lock held by another process is not recorded: this start stays as it was.
#[tauri::command]
pub async fn identity_migration_retry_credentials(app: tauri::AppHandle) -> Result<MigrationStatus, AppError> {
    let Some(before) = last()
        .filter(|(_, report)| {
            !report.outcome.blocks_startup() && MigrationStatus::of(Some(report)).failed_step == Some(Step::Credentials)
        })
        .map(|(_, report)| report)
    else {
        return Ok(identity_migration_status());
    };
    let Some(running) = Retrying::take() else {
        return Err(AppError::Other("Lunport is already moving the saved credentials.".into()));
    };
    let report = tauri::async_runtime::spawn_blocking(move || {
        let _running = running;
        let roots = Roots::current().ok_or_else(|| AppError::Other("The data folder cannot be found.".into()))?;
        Ok::<_, AppError>(retry_credentials(&roots, &STARTUP))
    })
    .await
    .map_err(|_| AppError::Other("The saved credentials could not be moved again.".into()))??;
    if report.outcome.blocks_startup() {
        return Err(not_run(&report));
    }
    let report = record(Entry::Desktop, report);
    if restarts_after(&before, &report) {
        app.restart();
    }
    Ok(identity_migration_status())
}

/// Why a run of the saved credentials' step from the window (a retry, or the adopt run) could not go ahead, `report` being that run,
/// which found the migration blocked: another process holds what the move needs, or a step failed (the record of the move cannot be
/// read or written, say). An adopt run may have moved some items before that.
pub(super) fn not_run(report: &Report) -> AppError {
    AppError::Other(match &report.outcome {
        Outcome::Deferred(DeferReason::OldInstanceRunning) => format!(
            "Lunport could not move the saved items now: {}. Try again in a moment.",
            report.detail.as_deref().unwrap_or("another Lunport is moving its data")
        ),
        // The run may have moved some before it failed (an adopt run, say): an earlier copy goes only once its new copy reads back.
        Outcome::Deferred(DeferReason::StepFailed { error, .. }) => format!(
            "Lunport could not finish moving the saved items: {error}. No saved item was lost: each earlier copy is deleted only after \
             its new copy reads back."
        ),
        Outcome::Conflict { .. } => {
            "Lunport found data both in its earlier folder and in its new one: restart Lunport to choose which to keep.".into()
        }
        Outcome::NotNeeded | Outcome::Completed | Outcome::CredentialsPending => {
            "Lunport could not move the saved items now. Try again in a moment.".into()
        }
    })
}

/// Whether a run of the saved credentials' step that the user asked for in the window (a retry, or the adopt run of the items that
/// wait for permission) restarts the app, which ends its open sessions: only once nothing waits for the saved credentials (`after`
/// completed), and only when the run changed what the running app has. Either the vault keys no longer wait (`before`, this process's
/// report until then, waited for them); or the run moved a credential the app reads only when it starts (`Report::restart_helps`: a
/// vault key or the sync code); or the run was offered because this process's start could not use the credential store (a start
/// hidden for a client, a locked keyring: the outcome had completed, yet the window asked for Retry), and nothing asks for one any
/// more: this process started without reading what the store holds.
pub(super) fn restarts_after(before: &Report, after: &Report) -> bool {
    let asks_for_retry = |report: &Report| report.credentials.as_ref().is_some_and(|left| left.retry);
    let store_was_unavailable = before.outcome == Outcome::Completed && asks_for_retry(before);
    after.outcome == Outcome::Completed
        && (before.outcome == Outcome::CredentialsPending || after.restart_helps || (store_was_unavailable && !asks_for_retry(after)))
}

// The saved credentials that wait for the user's permission (macOS Production): the window asks once for all of them.

/// Moves the saved credentials that wait for the user's permission (`MigrationStatus::credentials_need_permission`), as the user chose
/// Continue in the window that says so: helper v2 moves each, macOS asking once for each, then the credential step runs again. Only
/// when the status counts some, and never at the same time as another run of the saved credentials. Lunport restarts when the run
/// changed what the running app has (`restarts_after`). A run that stopped before it got to every item says why, as an error.
#[tauri::command]
pub async fn identity_migration_adopt_credentials(app: tauri::AppHandle) -> Result<MigrationStatus, AppError> {
    let Some(before) = last()
        .filter(|(_, report)| {
            !report.outcome.blocks_startup() && MigrationStatus::of(Some(report)).credentials_need_permission > 0
        })
        .map(|(_, report)| report)
    else {
        return Ok(identity_migration_status());
    };
    let Some(running) = Retrying::take() else {
        return Err(AppError::Other("Lunport is already moving the saved credentials.".into()));
    };
    let (report, stopped) = tauri::async_runtime::spawn_blocking(move || {
        let _running = running;
        let roots = Roots::current().ok_or_else(|| AppError::Other("The data folder cannot be found.".into()))?;
        Ok::<_, AppError>(adopted(&roots))
    })
    .await
    .map_err(|_| AppError::Other("The saved credentials could not be moved.".into()))??;
    if report.outcome.blocks_startup() {
        return Err(not_run(&report));
    }
    let report = record(Entry::Desktop, report);
    if restarts_after(&before, &report) {
        app.restart();
    }
    match stopped {
        Some(why) => Err(AppError::Other(format!("Lunport could not ask macOS about every saved item: {why}"))),
        None => Ok(identity_migration_status()),
    }
}

/// Remembers that the user chose Later in the sheet that asks their permission for saved credentials: later starts offer the reminder
/// with Allow… instead of the sheet, until more wait or a vault key does (`credentials::put_off_in`). Nothing while this start is
/// blocked, whose window has no such sheet.
#[tauri::command]
pub async fn identity_migration_put_off_credentials() -> Result<(), AppError> {
    if super::blocks_startup() {
        return Ok(());
    }
    tauri::async_runtime::spawn_blocking(|| {
        let roots = Roots::current().ok_or_else(|| AppError::Other("The data folder cannot be found.".into()))?;
        super::credentials::put_off_in(&roots, std::time::Duration::from_secs(5))
    })
    .await
    .map_err(|_| AppError::Other("Later could not be remembered.".into()))?
}

/// The adopt run with this computer's helpers, and why it stopped early, if it did. Only macOS Production has items that wait for the
/// user's permission; anywhere else the status never counts any, and this runs the migration again.
fn adopted(roots: &Roots) -> (Report, Option<String>) {
    #[cfg(target_os = "macos")]
    return super::credentials_adopt::adopt_credentials(roots, &STARTUP);
    #[cfg(not(target_os = "macos"))]
    return (run(Entry::Desktop, roots, &STARTUP), None);
}

/// A run of the saved credentials' step from the window (`identity_migration_retry_credentials`, `identity_migration_adopt_credentials`);
/// there is at most one at a time.
pub(super) struct Retrying(());

static RETRYING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Retrying {
    /// The run's turn; `None` while another one runs.
    pub(super) fn take() -> Option<Self> {
        RETRYING.compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst).ok()?;
        Some(Self(()))
    }
}

impl Drop for Retrying {
    fn drop(&mut self) {
        RETRYING.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Goes on without the roaming backups or the WebKit store when it keeps failing to move: its old folder stays where it is, untouched.
#[tauri::command]
pub async fn identity_migration_continue_without_moving(app: tauri::AppHandle) -> Result<MigrationStatus, AppError> {
    way_on(app, |roots| match last() {
        Some((_, Report { outcome: Outcome::Deferred(DeferReason::StepFailed { step, .. }), .. }))
            if matches!(step, Step::BackupsRoot | Step::WebKitStore) =>
        {
            Ok(skip(step, roots, &STARTUP))
        }
        _ => Err(AppError::Other("Only a folder that failed to move can stay where it is.".into())),
    })
    .await
}

/// Runs `work` off the main thread (the lock probe can wait seconds), records its run, and restarts the app when the run no longer
/// blocks the start, so that it starts with its data in place.
async fn way_on(
    app: tauri::AppHandle,
    work: impl FnOnce(&Roots) -> Result<Report, AppError> + Send + 'static,
) -> Result<MigrationStatus, AppError> {
    let report = tauri::async_runtime::spawn_blocking(move || {
        let roots = Roots::current().ok_or_else(|| AppError::Other("The data folder cannot be found.".into()))?;
        Ok::<_, AppError>(record(Entry::Desktop, work(&roots)?))
    })
    .await
    .map_err(|_| AppError::Other("The data folders could not be checked again.".into()))??;
    if !report.outcome.blocks_startup() {
        app.restart();
    }
    Ok(identity_migration_status())
}

/// What the window says of the AI tools' MCP settings (`McpMigrationNotice`), by the journal of this computer's data root: after an
/// upgrade, what the move did with the reminder, until the user dismisses it (`mcp_configs::notice`); `null` otherwise.
#[tauri::command]
pub async fn identity_migration_mcp_settings() -> Option<super::mcp_configs::McpNotice> {
    tauri::async_runtime::spawn_blocking(|| mcp_settings_with(Roots::current)).await.ok().flatten()
}

/// `identity_migration_mcp_settings` with `roots` naming this computer's folders: nothing while this start is blocked, whose window
/// says why instead, and reads no folder.
pub(super) fn mcp_settings_with(roots: impl FnOnce() -> Option<Roots>) -> Option<super::mcp_configs::McpNotice> {
    if super::blocks_startup() {
        return None;
    }
    super::mcp_configs::notice_in(&roots()?)
}

/// Remembers that the user dismissed the notice having seen `failed` fail, by client (`null`: the whole attempt): it comes back only
/// when something else fails (`mcp_configs::dismiss_in`).
#[tauri::command]
pub async fn identity_migration_dismiss_mcp_settings(
    failed: Vec<Option<crate::mcp_setup::SetupClient>>,
) -> Result<(), AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let roots = Roots::current().ok_or_else(|| AppError::Other("The data folder cannot be found.".into()))?;
        super::mcp_configs::dismiss_in(&roots, &failed, std::time::Duration::from_secs(5))
    })
    .await
    .map_err(|_| AppError::Other("The notice could not be dismissed.".into()))?
}
