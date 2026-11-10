//! The migration's record of what it has done: one state per step, in `identity-migration.json` inside the data root it moves, written
//! atomically after every step. A migration that stops part way resumes from it on the next start.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::Outcome;
use crate::error::AppError;
use crate::mcp_setup::SetupClient;

/// The journal's file in the data root.
const FILE: &str = "identity-migration.json";
/// The most of a journal that is read back; a real one is a few hundred bytes.
const MAX_BYTES: u64 = 64 * 1024;

/// One part of the migration, in the order it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/", rename = "MigrationStep"))]
pub enum Step {
    /// The main data root, renamed whole.
    DataRoot,
    /// Production's backups in the Windows roaming profile.
    BackupsRoot,
    /// The macOS WebView's store, with the preferences copied beside it.
    #[serde(rename = "webkit_store")]
    WebKitStore,
    /// Saved credentials, from the old credential service to the current one.
    Credentials,
    /// The launch-at-login entry.
    LoginItem,
    /// The AI clients' MCP settings that start the old executable.
    McpConfigs,
}

impl Step {
    pub(crate) const ALL: [Step; 6] =
        [Step::DataRoot, Step::BackupsRoot, Step::WebKitStore, Step::Credentials, Step::LoginItem, Step::McpConfigs];
    /// The folders, which are in place before this version reads or writes any of them.
    pub(crate) const FOLDERS: [Step; 3] = [Step::DataRoot, Step::BackupsRoot, Step::WebKitStore];
    /// The steps after the folders.
    pub(crate) const LATER: [Step; 3] = [Step::Credentials, Step::LoginItem, Step::McpConfigs];

    /// The step's name in the journal file, which is also its name toward the window.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Step::DataRoot => "data_root",
            Step::BackupsRoot => "backups_root",
            Step::WebKitStore => "webkit_store",
            Step::Credentials => "credentials",
            Step::LoginItem => "login_item",
            Step::McpConfigs => "mcp_configs",
        }
    }
}

/// Where one step stands.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StepState {
    #[default]
    Pending,
    Done,
    /// The last attempt failed, for this reason; the step runs again on the next start.
    Failed(String),
}

/// The state of every step. A step missing from the file is pending.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Journal {
    #[serde(default)]
    data_root: StepState,
    #[serde(default)]
    backups_root: StepState,
    #[serde(default)]
    webkit_store: StepState,
    #[serde(default)]
    credentials: StepState,
    #[serde(default)]
    login_item: StepState,
    #[serde(default)]
    mcp_configs: StepState,
    /// The user chose the old data over a new data root that held data (`ConflictChoice::UseOldData`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub use_old_data: bool,
    /// What a finished step could not do and did not need to: a preferences copy that failed, pending imports that keep their old
    /// paths, a folder kept under both names or left where it was.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// How far the saved credentials' move got, beyond its step state (`credentials`).
    #[serde(default, skip_serializing_if = "CredentialProgress::is_empty")]
    pub credential_progress: CredentialProgress,
    /// What the move of the AI clients' MCP settings did, beyond its step state (`mcp_configs`).
    #[serde(default, skip_serializing_if = "McpProgress::is_empty")]
    pub mcp_progress: McpProgress,
    /// The saved credentials this process's attempt at their step made usable under the new service (`CredentialReport::written`). Not
    /// written to the file: a retry from the window decides on it whether the running app restarts (`Report::restart_helps`).
    #[serde(skip)]
    pub moved_credentials: Vec<String>,
}

/// How far the saved credentials' move got. The step itself is done once nothing is left for a later attempt; the vault and the
/// outcome wait only for the vault keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CredentialProgress {
    /// No vault key waits for a later attempt any more: each is under the current service, or settled there, or can never be read; or
    /// there was none. From then on nothing waits for the saved credentials (`Journal::outcome`, `credentials_pending`): the vault
    /// guard only asks whether the old service still holds the vault's own key.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub vault_keys_moved: bool,
    /// Items left under the earlier version's name for good, by account, with why: a conflict settled on the current service's value,
    /// an item that can never be read or that the current service would not keep (the states are in `credentials`). No attempt tries
    /// them again, and the vault's guard knows that a vault key here never moves (`credentials::missing_vault_key`). It names at most
    /// `credentials::MAX_KEPT` of them, every vault key among them included, so that the journal stays small.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub kept: BTreeMap<String, String>,
    /// How many more items the last attempt left for good than `kept` names. They hold nothing back either: a later attempt reads them
    /// again only while something else is left for it, and the step is done without them.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub kept_unnamed: usize,
    /// How many items the last attempt left for a later desktop start, which tries them again: their failure may pass. Those that wait
    /// for the user's permission are not among them (`needs_permission`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub retrying: usize,
    /// The last attempt waited for the user (a locked keyring): Retry from the window moves them once the user has done what it said.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub waiting_for_the_user: bool,
    /// Items that wait for the user's permission before they can move (macOS Production: helper v1 may not hand them over without
    /// asking, and helper v2's adopt moves each once the user allows it, `credentials_adopt`). They are left for a later attempt like
    /// any item whose failure may pass. It names them up to `credentials_helper::MAX_PERMISSION_NAMES` bytes, vault keys always.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub needs_permission: BTreeSet<String>,
    /// How many more items wait for the user's permission than `needs_permission` names.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub needs_permission_unnamed: usize,
    /// How many items waited for the user's permission when they chose Later in the window that asks for it
    /// (`commands::identity_migration_put_off_credentials`): later starts keep that window away for as many, offering a reminder with
    /// Allow… instead, unless a vault key waits for permission (`credentials::left_behind`). Forgotten once nothing waits.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub permission_put_off: usize,
    /// Items helper v1 handed over without asking when an attempt that a vault key waiting for permission stopped asked about them,
    /// only to count what waits for permission (`credentials_helper::move_with`). Later such attempts do not ask again: each request
    /// costs a bridge and a helper v1 before the window opens. They are left for the attempt that reaches them, like any item not
    /// reached, and named in what `credentials_helper::MAX_PERMISSION_NAMES` leaves beside `needs_permission`.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub probed_readable: BTreeSet<String>,
    /// The vault keys left under the earlier name wait only for the user's permission (macOS Production: helper v1 may not hand them
    /// over without asking): a retry cannot move them, helper v2's adopt can. Recorded by every attempt that got to the vault keys.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub vault_waits_for_permission: bool,
    /// How many attempts in a row got no answer at all from helper v1 through the bridge, in a way that may pass (macOS Production),
    /// each counted once. Below `credentials_helper::CHAIN_FAILURES_BEFORE_ADOPT`, an attempt that gets any answer starts the count
    /// again. From it on, what is left waits for the user's permission instead (helper v2's adopt goes around the bridge) and no start
    /// asks that bridge any more, so nothing answers to reset the count: only another bridge does (`chain_failures_bridge`).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chain_failures: u32,
    /// The bridge `chain_failures` was counted with: its pinned SHA-256. A version that embeds another bridge starts the count again.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chain_failures_bridge: String,
    /// How many attempts moved a saved credential the running app reads only when it starts (a vault key or the sync code,
    /// `credentials::restart_helps`). A process that last saw a lower count started without something that has moved since, and
    /// restarts once nothing waits any more (`identity_migration::refresh_after_another_start`).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub start_credential_moves: u32,
    /// Windows: the items the last attempts in a row left for a later one for the same reason, by account. Windows never asks the user
    /// anything, so an item that fails the same way that often does not pass: it is kept for good instead
    /// (`credentials::run_step_keeping_repeated_failures`). Vault keys are never counted, and only the items the last attempt left are:
    /// any other starts again. It names at most `credentials::MAX_SAME_FAILURES` of them, so that the journal stays small.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub same_failures: BTreeMap<String, SameFailure>,
}

/// How the attempts in a row that left an item for a later one failed (`CredentialProgress::same_failures`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SameFailure {
    /// Why, shortened as the journal keeps a kept item's reason (`credentials::kept_reason`).
    pub why: String,
    /// How many attempts in a row failed this way.
    pub times: u32,
}

impl CredentialProgress {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

fn is_zero_u32(count: &u32) -> bool {
    *count == 0
}

/// What the move of the AI clients' MCP settings did (`mcp_configs`), and what the user dismissed of what the window said of it
/// (`mcp_configs::notice`). The step itself is done once no client failed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct McpProgress {
    /// Every client whose settings an attempt moved to this version, each once, in the order they moved.
    #[serde(default)]
    pub updated: Vec<SetupClient>,
    /// What the last attempt could not move, with why: it may still start the earlier program, and the next desktop start tries it
    /// again.
    #[serde(default)]
    pub failed: Vec<McpFailure>,
    /// What was failing when the user last dismissed the notice, by client (`None`: the whole attempt); `None` until they dismiss it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dismissed: Option<Vec<Option<SetupClient>>>,
}

impl McpProgress {
    pub(crate) fn is_empty(&self) -> bool {
        self.updated.is_empty() && self.failed.is_empty() && self.dismissed.is_none()
    }
}

/// What of the MCP settings did not move, and why: one client's settings, or none when the attempt could not look at any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/", rename = "McpMigrationFailure"))]
pub(crate) struct McpFailure {
    pub client: Option<SetupClient>,
    pub reason: String,
}

impl Journal {
    /// The journal of a new data root the user kept over the old one: none of the old data moves, its other folders and its credentials
    /// included (the kept data has credentials of its own, under the current service). The launch-at-login entry and the MCP settings
    /// belong to the installation, not to the data, and still move. The limitation this leaves is described where the choice is
    /// settled (`identity_migration::resolve`).
    pub(crate) fn kept_new() -> Self {
        Self {
            data_root: StepState::Done,
            backups_root: StepState::Done,
            webkit_store: StepState::Done,
            credentials: StepState::Done,
            credential_progress: CredentialProgress { vault_keys_moved: true, ..CredentialProgress::default() },
            ..Self::default()
        }
    }

    pub(crate) fn state(&self, step: Step) -> &StepState {
        match step {
            Step::DataRoot => &self.data_root,
            Step::BackupsRoot => &self.backups_root,
            Step::WebKitStore => &self.webkit_store,
            Step::Credentials => &self.credentials,
            Step::LoginItem => &self.login_item,
            Step::McpConfigs => &self.mcp_configs,
        }
    }

    pub(crate) fn set(&mut self, step: Step, state: StepState) {
        let slot = match step {
            Step::DataRoot => &mut self.data_root,
            Step::BackupsRoot => &mut self.backups_root,
            Step::WebKitStore => &mut self.webkit_store,
            Step::Credentials => &mut self.credentials,
            Step::LoginItem => &mut self.login_item,
            Step::McpConfigs => &mut self.mcp_configs,
        };
        *slot = state;
    }

    pub(crate) fn is_done(&self, step: Step) -> bool {
        *self.state(step) == StepState::Done
    }

    pub(crate) fn all_done(&self, steps: &[Step]) -> bool {
        steps.iter().all(|&step| self.is_done(step))
    }

    /// What a start that needs `folders` reports once they are in place: `Completed` once nothing waits for the saved credentials
    /// any more (`credentials_wait`), `CredentialsPending` until then. The launch-at-login entry and the MCP settings never hold it back.
    pub(crate) fn outcome(&self, folders: &[Step]) -> Outcome {
        if self.all_done(folders) && !self.credentials_wait() {
            Outcome::Completed
        } else {
            Outcome::CredentialsPending
        }
    }

    /// Whether something still waits for the saved credentials: until their step is done or no vault key waits for a later attempt
    /// (`CredentialProgress::vault_keys_moved`). Other items that did not move hold nothing back.
    pub(crate) fn credentials_wait(&self) -> bool {
        !self.is_done(Step::Credentials) && !self.credential_progress.vault_keys_moved
    }
}

/// Why a journal that is there could not be read.
#[derive(Debug)]
pub(crate) enum Unreadable {
    /// A regular file that is not a journal: damaged, or written by a version this one does not understand (`salvage`).
    Damaged,
    /// It could not be looked at or read: a folder in its place, no permission, a failing disk.
    Io(io::Error),
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unreadable::Damaged => write!(f, "the migration journal is damaged"),
            Unreadable::Io(error) => write!(f, "the migration journal cannot be read: {error}"),
        }
    }
}

/// The journal's path in the data root `root`.
pub(crate) fn path(root: &Path) -> PathBuf {
    root.join(FILE)
}

/// The journal in `root`: `None` when there is none.
pub(crate) fn read(root: &Path) -> Result<Option<Journal>, Unreadable> {
    let Some(bytes) = read_bytes(root)? else { return Ok(None) };
    serde_json::from_slice(&bytes).map(Some).map_err(|_| Unreadable::Damaged)
}

/// The journal file's contents, `None` when there is none; more than a journal's size is damaged.
fn read_bytes(root: &Path) -> Result<Option<Vec<u8>>, Unreadable> {
    let path = path(root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Unreadable::Io(error)),
    };
    if !metadata.is_file() {
        return Err(Unreadable::Io(io::Error::other(format!("{} is not a regular file", path.display()))));
    }
    let mut bytes = Vec::new();
    fs::File::open(&path).and_then(|file| file.take(MAX_BYTES + 1).read_to_end(&mut bytes)).map_err(Unreadable::Io)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(Unreadable::Damaged);
    }
    Ok(Some(bytes))
}

/// What can still be read of a damaged journal: each step whose state parses keeps it (so a later version's journal keeps, say, the
/// credentials it marked done), every other step is pending. The result replaces the damaged journal at once, so that the next start
/// reads it whatever this one still does; the damaged file is kept beside it, `identity-migration.unreadable-<milliseconds since
/// 1970>.json`, never deleted, and a note says so.
pub(crate) fn salvage(root: &Path) -> Result<Journal, AppError> {
    let bytes = match read_bytes(root) {
        Ok(bytes) => bytes.unwrap_or_default(),
        Err(Unreadable::Damaged) => Vec::new(),
        Err(Unreadable::Io(error)) => return Err(error.into()),
    };
    let mut journal = Journal::default();
    if let Ok(serde_json::Value::Object(fields)) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        for step in Step::ALL {
            if let Some(state) = fields.get(step.key()).and_then(|value| serde_json::from_value(value.clone()).ok()) {
                journal.set(step, state);
            }
        }
        journal.use_old_data = chose_old_data(&fields);
        if let Some(notes) = fields.get("notes").and_then(|value| serde_json::from_value::<Vec<String>>(value.clone()).ok()) {
            journal.notes = notes;
        }
        if let Some(progress) = fields.get("credential_progress").and_then(|value| serde_json::from_value(value.clone()).ok()) {
            journal.credential_progress = progress;
        }
        if let Some(progress) = fields.get("mcp_progress").and_then(|value| serde_json::from_value(value.clone()).ok()) {
            journal.mcp_progress = progress;
        }
    }
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| AppError::Other(error.to_string()))?.as_millis();
    let aside = root.join(format!("identity-migration.unreadable-{millis}.json"));
    crate::fsutil::check_write(&aside)?;
    // Copied, not renamed: the damaged journal stays in its place until the salvaged one replaces it, so the root always holds a
    // journal (without one, a moved root would pass for a fresh install).
    fs::copy(path(root), &aside)?;
    journal.notes.push(format!("the journal could not be read and was kept as {}", aside.display()));
    write(root, &journal)?;
    Ok(journal)
}

/// Whether the journal in `root` records the user's choice of the old data, read as leniently as `salvage` reads it: a journal this
/// version cannot read in full (a later version's) keeps the choice too. No journal, or none that is JSON, records none.
pub(crate) fn records_old_data_choice(root: &Path) -> bool {
    match read_bytes(root).ok().flatten().map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes)) {
        Some(Ok(serde_json::Value::Object(fields))) => chose_old_data(&fields),
        _ => false,
    }
}

fn chose_old_data(fields: &serde_json::Map<String, serde_json::Value>) -> bool {
    fields.get("use_old_data").and_then(serde_json::Value::as_bool).unwrap_or(false)
}

/// Writes `journal` into `root`, atomically (owner-only on Unix).
pub(crate) fn write(root: &Path, journal: &Journal) -> Result<(), AppError> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(|error| AppError::Other(error.to_string()))?;
    crate::fsutil::atomic_write(&path(root), &bytes, 0o600)
}
