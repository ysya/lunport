//! The AI clients' MCP settings that the setup wrote before the rename: an entry of this app that starts this installation's earlier
//! executable (gone since the update, or left behind by it), or goes by the earlier server name, moves to this version's executable and
//! the current name. Nothing else in the file changes, and the file is backed up and replaced the way the setup replaces it
//! (`mcp_setup::commit`). An entry that starts an earlier Lunport elsewhere, an older copy of the app, is no entry of this installation
//! to move: it stays as it is, and the client is named until it no longer starts one (`mcp_setup::earlier_program_elsewhere`).
//!
//! Only the files the setup edits move: Codex's, Claude Code's and Claude Desktop's. Cursor and VS Code installed their entries from a
//! link and keep them, as do configurations the user exported: the completion notice asks to add Lunport there again. An AppImage keeps
//! its path across updates, and `connect` commands are put together anew for every terminal, so neither has anything to move.
//!
//! The migration moves them in a step of its own once the data root is in place (`step`), on desktop starts until nothing fails. After
//! an upgrade the window says what the step did, with the reminder, until the user dismisses it; afterwards only something that newly
//! fails brings it back (`notice`, `dismiss_in`).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use super::journal::{self, Journal, McpFailure, StepState};
use super::{Entry, Mover, Roots, Step};
use crate::app_profile::{self, AppProfile};
use crate::error::AppError;
use crate::mcp_setup::{self, SetupClient};

/// The clients whose settings files the setup writes.
const CLIENTS: [SetupClient; 3] = [SetupClient::Codex, SetupClient::ClaudeCode, SetupClient::ClaudeDesktop];

/// The most of a reason the journal keeps and the window shows, in characters.
pub(super) const MAX_REASON: usize = 500;

/// The most of a settings file the setup does not edit that is read to tell whether it still holds an earlier entry (`peek`): several
/// times what the setup edits, since Claude Code's file grows with its history. A larger one is left alone, as before.
const PEEK_LIMIT: u64 = 64 * 1024 * 1024;

/// What a move did, client by client.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Moved {
    /// The clients whose settings now start this version under the current name.
    pub updated: Vec<SetupClient>,
    /// The clients whose settings could not be read or written, that the setup does not edit while they still hold an earlier entry,
    /// or that still start an earlier Lunport elsewhere, with why: they may still start the earlier executable, and a later run tries
    /// them again (the clients that moved have nothing left to move then).
    pub failed: Vec<(SetupClient, String)>,
}

/// Points this app's entries in the settings files of `home`'s AI clients at `new_exe`, under the current server name. The files are
/// the ones the setup edits, found by its rules (`mcp_setup::client_path_in`), and the backups go where the setup keeps its own, in the
/// data root. A Development build's setup works in the sandbox home inside its data root, which is all its write policy allows: so does
/// this, whatever `home` is.
pub fn migrate(home: &Path, new_exe: &Path) -> Result<Moved, AppError> {
    let home = match app_profile::CURRENT {
        AppProfile::Production => home.to_path_buf(),
        AppProfile::Development => crate::fsutil::home_dir()?,
    };
    // A client whose settings the setup cannot name here has none to move: Claude Desktop on Linux, or a configuration folder of its
    // own that the setup does not follow.
    let files: Vec<_> = CLIENTS
        .into_iter()
        .filter_map(|client| Some((client, mcp_setup::client_path_in(client, &home).ok()??)))
        .collect();
    migrate_files(&files, new_exe, &crate::fsutil::app_data_root()?)
}

/// `migrate` for the clients' settings `files`, with the backups in `data_root`. Every client is tried.
pub(crate) fn migrate_files(
    files: &[(SetupClient, PathBuf)],
    new_exe: &Path,
    data_root: &Path,
) -> Result<Moved, AppError> {
    if new_exe.to_str().is_none() {
        return Err(AppError::Other("This installation path cannot be represented in client settings.".into()));
    }
    let mut moved = Moved::default();
    for &(client, ref path) in files {
        let before = match mcp_setup::read_config(path) {
            Ok(Some(before)) => before,
            // A missing file holds nothing to move.
            Ok(None) => continue,
            // A file the setup does not edit (a symbolic link, not a regular file, too large) is left to manual setup, where the setup
            // page sends it; `read_config` refuses those with `AppError::Other`. One that still holds an earlier entry is reported, so
            // that the notice names it; one without has nothing to move.
            Err(AppError::Other(_)) => {
                if let Some(reason) = peek(path).and_then(|bytes| earlier_entry(client, &bytes, new_exe, path)) {
                    moved.failed.push((client, reason));
                }
                continue;
            }
            // An I/O error may pass (Claude Code rewrites its file while it runs, Windows refuses a file another program holds open).
            Err(error) => {
                moved.failed.push((client, failure_reason(error, false)));
                continue;
            }
        };
        // Settings that do not parse hold nothing this app can call its own, and stay as they are.
        let after = mcp_setup::retarget(client, &before, new_exe);
        if let Some(after) = &after {
            match mcp_setup::commit(path, Some(&before), after, &mcp_setup::backup_folder(data_root, client)) {
                Ok(_) => moved.updated.push(client),
                Err(error) => {
                    moved.failed.push((client, failure_reason(error, true)));
                    continue;
                }
            }
        }
        // What the move leaves: an entry that starts an earlier Lunport elsewhere still does, and is named.
        if let Some(program) = mcp_setup::earlier_program_elsewhere(client, after.as_deref().unwrap_or(&before), new_exe) {
            moved.failed.push((client, starts_an_earlier_lunport(&program)));
        }
    }
    Ok(moved)
}

/// What the notice says of an entry that still starts an earlier Lunport at `program`, which the move leaves as it is.
fn starts_an_earlier_lunport(program: &str) -> String {
    format!("It still starts an earlier Lunport at {program}. Change that entry to start this Lunport, or remove it.")
}

/// What the notice says of `error`, which kept a client's settings file from moving while it was read (`writing`: changed). The
/// setup's own wording, made for its settings page, and an I/O error's prefix give way to the notice's.
fn failure_reason(error: AppError, writing: bool) -> String {
    match error {
        AppError::Io(error) => format!("Its settings file could not be {}: {error}.", if writing { "changed" } else { "read" }),
        AppError::Other(message) if message == mcp_setup::SETTINGS_CHANGED => {
            "Its settings file changed while Lunport was updating it.".into()
        }
        AppError::Other(message) if message == mcp_setup::READ_ONLY => {
            "Its settings file is read-only. Make it writable, or set it up by hand in Settings → AI access.".into()
        }
        error => error.to_string(),
    }
}

/// What a settings file the setup does not edit holds, read only to tell whether it still holds an earlier entry: through a symbolic
/// link, and only from a regular file of at most `PEEK_LIMIT`. `None` when there is no such file to read. Nothing waits on a file that
/// is not regular: a named pipe would wait for a writer.
fn peek(path: &Path) -> Option<Vec<u8>> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > PEEK_LIMIT {
        return None;
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    // Nor on one that took the file's place since it was looked at.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(PEEK_LIMIT + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= PEEK_LIMIT).then_some(bytes)
}

/// Why `client`'s settings `bytes`, read from `path`, a file the setup does not edit, still hold an earlier entry: one the move would
/// change (`mcp_setup::retarget`), which is left to manual setup, or one that starts an earlier Lunport elsewhere
/// (`mcp_setup::earlier_program_elsewhere`). `None` when they hold neither. Of JSON settings only the servers are read, which is all
/// either looks at: a large file holds much else, which is skipped.
fn earlier_entry(client: SetupClient, bytes: &[u8], new_exe: &Path, path: &Path) -> Option<String> {
    let servers;
    let bytes = if client == SetupClient::Codex {
        bytes
    } else {
        #[derive(serde::Deserialize)]
        struct Settings {
            #[serde(rename = "mcpServers")]
            servers: Option<serde_json::Value>,
        }
        let Ok(Settings { servers: Some(found) }) = serde_json::from_slice(bytes) else {
            return None;
        };
        servers = serde_json::to_vec(&serde_json::json!({ "mcpServers": found })).expect("JSON values serialize");
        &servers[..]
    };
    if mcp_setup::retarget(client, bytes, new_exe).is_some() {
        return Some(left_to_manual_setup(path));
    }
    mcp_setup::earlier_program_elsewhere(client, bytes, new_exe).map(|program| starts_an_earlier_lunport(&program))
}

/// Why the settings file at `path`, which the setup does not edit and which still holds an earlier entry, did not move, and what to do.
fn left_to_manual_setup(path: &Path) -> String {
    let why = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => "Its settings file is a symbolic link, which Lunport does not change.",
        // `peek` reads only a regular file: the setup refused this one for its size.
        _ => "Its settings file is too large for Lunport to change.",
    };
    format!("{why} Set it up by hand in Settings → AI access.")
}

/// The step's mover for a start through `entry` (`identity_migration::mover`): the desktop's. `connect` and the MCP adapter leave it to
/// the desktop app, which a client's start brings up too; it asks the user nothing, so a start hidden for a client moves them as well.
/// In a test only a stand-in for this computer's settings files moves anything (`with_test_settings`): no test reaches the owner's own.
pub(super) fn mover(entry: Entry) -> Option<Mover> {
    #[cfg(test)]
    if TEST_SETTINGS.with(|settings| settings.borrow().is_none()) {
        return None;
    }
    (entry == Entry::Desktop).then_some(run_step as Mover)
}

/// The step with this computer's settings files, pointed at this version's executable (`mcp_setup::executable`).
fn run_step(_: &Roots, journal: &mut Journal) -> StepState {
    #[cfg(test)]
    return step(journal, test_settings);
    #[cfg(not(test))]
    step(journal, || migrate(&crate::fsutil::home_dir()?, &mcp_setup::executable()?))
}

/// The step for a migration that got as far as `journal` says, with `migrate` moving the settings. It waits for the data root, where
/// the backups go, then records what the attempt did (`Journal::mcp_progress`): the clients it updated join those of earlier attempts,
/// and what it could not update replaces what the attempt before could not; an attempt that could not look at any client is one
/// failure that names the cause. Done once nothing failed; otherwise the next desktop start tries again.
pub(super) fn step(journal: &mut Journal, migrate: impl FnOnce() -> Result<Moved, AppError>) -> StepState {
    if !journal.is_done(Step::DataRoot) {
        return journal.state(Step::McpConfigs).clone();
    }
    let progress = &mut journal.mcp_progress;
    match migrate() {
        Ok(moved) => {
            for client in moved.updated {
                if !progress.updated.contains(&client) {
                    progress.updated.push(client);
                }
            }
            progress.failed =
                moved.failed.into_iter().map(|(client, reason)| McpFailure { client: Some(client), reason: shortened(reason) }).collect();
        }
        Err(error) => {
            let cause = match error {
                AppError::Io(error) => error.to_string(),
                AppError::Other(message) => message,
                error => error.to_string(),
            };
            let reason = shortened(format!("Lunport could not check the AI tools' settings: {cause}"));
            progress.failed = vec![McpFailure { client: None, reason }];
        }
    }
    match progress.failed.as_slice() {
        [] => StepState::Done,
        [McpFailure { client: None, reason }] => StepState::Failed(reason.clone()),
        failed => {
            let listed: Vec<String> =
                failed.iter().map(|failed| format!("{} ({})", failed.client.map_or("?", SetupClient::name), failed.reason)).collect();
            StepState::Failed(shortened(format!("the MCP settings of {} did not move yet", listed.join("; "))))
        }
    }
}

/// What the window says of the AI tools' MCP settings after an upgrade (`identity_migration_mcp_settings`): every client the move
/// updated and what it could not update, with why. With neither, it is the reminder to add Lunport to Cursor and VS Code again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/", rename = "McpMigration"))]
pub(crate) struct McpNotice {
    pub updated: Vec<SetupClient>,
    pub failed: Vec<McpFailure>,
}

/// What the window says of the MCP settings by `journal`: after an upgrade (a data root that moved here, or was kept over the
/// earlier version's), what the step did so far with the reminder, until the user dismisses it; afterwards only something that newly
/// fails brings it back, while what keeps failing is tried again silently. `None` on a fresh install, which has no journal.
pub(super) fn notice(journal: &Journal) -> Option<McpNotice> {
    if !journal.is_done(Step::DataRoot) {
        return None;
    }
    let progress = &journal.mcp_progress;
    if let Some(seen) = &progress.dismissed {
        if progress.failed.iter().all(|failed| seen.contains(&failed.client)) {
            return None;
        }
    }
    Some(McpNotice { updated: progress.updated.clone(), failed: progress.failed.clone() })
}

/// The notice by the journal in the data root of `roots`, whichever start wrote it: `None` without one, or when it cannot be read.
pub(super) fn notice_in(roots: &Roots) -> Option<McpNotice> {
    notice(&journal::read(&roots.data.new).ok()??)
}

/// Records that the user dismissed the notice having seen `seen` fail (`None`: the whole attempt), in the journal and under the
/// migration's lock like every write of it, waiting at most `wait` for that lock. Only what can fail is kept, each once, whatever the
/// window sends: the journal stays small. Nothing is made where nothing moved.
pub(super) fn dismiss_in(roots: &Roots, seen: &[Option<SetupClient>], wait: Duration) -> Result<(), AppError> {
    let unreadable = |error: journal::Unreadable| AppError::Other(error.to_string());
    if journal::read(&roots.data.new).map_err(unreadable)?.is_none() {
        return Ok(());
    }
    let seen: Vec<Option<SetupClient>> = [None].into_iter().chain(CLIENTS.map(Some)).filter(|failing| seen.contains(failing)).collect();
    let recorded = super::with_migration_lock(roots, wait, || {
        let Some(mut journal) = journal::read(&roots.data.new).map_err(unreadable)? else { return Ok(()) };
        journal.mcp_progress.dismissed = Some(seen);
        journal::write(&roots.data.new, &journal)
    });
    match recorded {
        Ok(Some(recorded)) => recorded,
        Ok(None) => Err(AppError::Other("Another Lunport is moving its data right now. Try again in a moment.".into())),
        Err(error) => Err(AppError::Other(format!("The lock beside Lunport's data folder could not be taken: {error}"))),
    }
}

/// `text`, cut to `MAX_REASON` characters.
fn shortened(text: String) -> String {
    if text.chars().count() <= MAX_REASON {
        return text;
    }
    text.chars().take(MAX_REASON - 1).collect::<String>() + "…"
}

#[cfg(test)]
thread_local! {
    /// A test's stand-in for the move of this computer's settings files on this thread (`with_test_settings`): what each attempt
    /// returns.
    static TEST_SETTINGS: std::cell::RefCell<Option<std::rc::Rc<dyn Fn() -> Result<Moved, AppError>>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_settings() -> Result<Moved, AppError> {
    let settings = TEST_SETTINGS.with(|settings| settings.borrow().clone()).expect("the test's settings files");
    settings()
}

/// Runs `f` with `migrate` standing in for the move of this computer's settings files on this thread.
#[cfg(test)]
pub(crate) fn with_test_settings<T>(migrate: impl Fn() -> Result<Moved, AppError> + 'static, f: impl FnOnce() -> T) -> T {
    type Shared = std::rc::Rc<dyn Fn() -> Result<Moved, AppError>>;
    struct Restore(Option<Shared>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_SETTINGS.with(|settings| *settings.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(TEST_SETTINGS.with(|slot| slot.replace(Some(std::rc::Rc::new(migrate)))));
    f()
}

#[cfg(test)]
#[path = "mcp_configs_tests.rs"]
mod tests;
