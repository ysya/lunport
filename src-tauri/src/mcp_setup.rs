//! Client-specific setup for the existing stdio adapter. No host or AI permission is granted.
use crate::{app_profile::AppProfile, error::AppError, legacy_identity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const SERVER_ID: &str = "lunport";
const LEGACY_SERVER_ID: &str = legacy_identity::MCP_ALIAS;
const MAX_CONFIG: u64 = 8 * 1024 * 1024;
/// What `commit` says when the settings changed after they were read.
pub(crate) const SETTINGS_CHANGED: &str = "Settings changed while preparing setup. Refresh and try again.";
/// What `commit` says of a settings file that is read-only.
pub(crate) const READ_ONLY: &str = "This settings file is read-only. Use manual setup or make it writable first.";
const ALIASES: [&str; 2] = [SERVER_ID, LEGACY_SERVER_ID];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum SetupClient {
    Codex,
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
    Vscode,
}

impl SetupClient {
    fn key(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::ClaudeDesktop => "claude-desktop",
            Self::Cursor => "cursor",
            Self::Vscode => "vscode",
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::ClaudeDesktop => "Claude Desktop",
            Self::Cursor => "Cursor",
            Self::Vscode => "VS Code",
        }
    }
    fn external(self) -> bool {
        matches!(self, Self::Cursor | Self::Vscode)
    }
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ClientSetup {
    pub client: SetupClient,
    pub state: String,
    pub message: Option<String>,
    pub config_path: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SetupOverview {
    pub sandbox: bool,
    pub executable: String,
    pub clients: Vec<ClientSetup>,
}
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SetupResult {
    pub external: bool,
    pub changed: bool,
    pub backup_path: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupFormat {
    Json,
    Toml,
    Vscode,
}

fn config_path(
    client: SetupClient,
    home: &Path,
    os: &str,
    codex_home: Option<PathBuf>,
) -> Option<PathBuf> {
    match client {
        SetupClient::Codex => Some(
            codex_home
                .unwrap_or_else(|| home.join(".codex"))
                .join("config.toml"),
        ),
        SetupClient::ClaudeCode => Some(home.join(".claude.json")),
        SetupClient::ClaudeDesktop => match os {
            "macos" => {
                Some(home.join("Library/Application Support/Claude/claude_desktop_config.json"))
            }
            "windows" => Some(home.join("AppData/Roaming/Claude/claude_desktop_config.json")),
            _ => None,
        },
        SetupClient::Cursor | SetupClient::Vscode => None,
    }
}

fn client_path(client: SetupClient) -> Result<Option<PathBuf>, AppError> {
    client_path_in(client, &crate::fsutil::home_dir()?)
}

/// The settings file of `client` that the setup edits: in `home`, unless a Production build's environment says otherwise (`CODEX_HOME`
/// names Codex's folder, Windows' roaming folder holds Claude Desktop's file, and with `CLAUDE_CONFIG_DIR` set the setup refuses Claude
/// Code). `None` where the setup has no file for `client`.
pub(crate) fn client_path_in(client: SetupClient, home: &Path) -> Result<Option<PathBuf>, AppError> {
    let production = crate::app_profile::CURRENT == AppProfile::Production;
    #[cfg(windows)]
    if production && client == SetupClient::ClaudeDesktop {
        return Ok(dirs::config_dir().map(|root| root.join("Claude/claude_desktop_config.json")));
    }
    if production
        && client == SetupClient::ClaudeCode
        && std::env::var_os("CLAUDE_CONFIG_DIR").is_some()
    {
        return Err(AppError::Other("Claude Code uses a custom configuration directory. Use manual setup for this installation.".into()));
    }
    let codex_home = if production {
        std::env::var_os("CODEX_HOME").map(PathBuf::from)
    } else {
        None
    };
    if codex_home.as_ref().is_some_and(|p| !p.is_absolute()) {
        return Err(AppError::Other(
            "Codex's custom configuration directory must be an absolute path.".into(),
        ));
    }
    Ok(config_path(client, home, std::env::consts::OS, codex_home))
}

/// Where the setup keeps the backups of `client`'s settings, in the data root `data_root`.
pub(crate) fn backup_folder(data_root: &Path, client: SetupClient) -> PathBuf {
    data_root.join("backups/mcp-setup").join(client.key())
}

pub(crate) fn read_config(path: &Path) -> Result<Option<Vec<u8>>, AppError> {
    let metadata = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    if metadata.file_type().is_symlink() {
        return Err(AppError::Other(
            "This settings file is a symbolic link. Use manual setup to preserve it.".into(),
        ));
    }
    if !metadata.is_file() || metadata.len() > MAX_CONFIG {
        return Err(AppError::Other(
            "This settings file cannot be edited automatically. Use manual setup.".into(),
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err(AppError::Other(
            "This settings file is too large for automatic setup.".into(),
        ));
    }
    Ok(Some(bytes))
}

/// What a command in a client's settings starts, seen from `executable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Program {
    /// `executable` itself, or a path that leads to it.
    Current,
    /// One of this installation's executables from before the rename (`earlier_executables`), whether or not it is still there: the
    /// update may leave it behind (Windows keeps a file that was in use), and so may an earlier bundle beside this one, but this
    /// installation starts from `executable` now.
    Earlier,
    /// Anything else. An existing different executable never counts as this app's by its name; one by the earlier executable's name
    /// elsewhere is named by the migration instead (`earlier_program_elsewhere`).
    Other,
}

fn program(command: &str, executable: &Path) -> Program {
    let path = Path::new(command);
    if path == executable {
        return Program::Current;
    }
    if let (Ok(a), Ok(b)) = (fs::canonicalize(path), fs::canonicalize(executable)) {
        if a == b {
            return Program::Current;
        }
    }
    if earlier_executables(executable).iter().any(|old| path == old) {
        Program::Earlier
    } else {
        Program::Other
    }
}

/// Whether `command` starts this app, now or from before the rename.
fn owned_command(command: &str, executable: &Path) -> bool {
    program(command, executable) != Program::Other
}

/// Where this installation's executable was before the rename: under the old name next to `executable` (inside the macOS bundle, in the
/// Windows install folder, in `/usr/bin`), and inside an app bundle with an old name beside this one.
fn earlier_executables(executable: &Path) -> Vec<PathBuf> {
    let binary = format!(
        "{}{}",
        legacy_identity::current().main_binary,
        std::env::consts::EXE_SUFFIX
    );
    let mut paths = vec![executable.with_file_name(&binary)];
    if let Some(bundle) = executable.parent().and_then(Path::parent).and_then(Path::parent) {
        paths.extend(
            legacy_identity::BUNDLE_NAMES
                .iter()
                .map(|old| bundle.with_file_name(old).join("Contents/MacOS").join(&binary)),
        );
    }
    paths
}

/// Whether `command` names a program by the file name this app's executable had before the rename, with or without the suffix this
/// platform gives executables (in any case on Windows, whose file names ignore it).
fn names_earlier_binary(command: &str) -> bool {
    let Some(name) = Path::new(command).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let binary = legacy_identity::current().main_binary;
    let with_suffix = format!("{binary}{}", std::env::consts::EXE_SUFFIX);
    [binary, with_suffix.as_str()]
        .iter()
        .any(|candidate| if cfg!(windows) { name.eq_ignore_ascii_case(candidate) } else { name == *candidate })
}

/// The program of a JSON server entry that starts an MCP adapter: `--mcp` alone, over stdio.
fn json_adapter_command(entry: &Value) -> Option<&str> {
    if entry.get("args") != Some(&json!(["--mcp"])) || !entry.get("type").is_none_or(|v| v == "stdio") {
        return None;
    }
    entry.get("command").and_then(Value::as_str)
}

/// The program of a TOML server entry that starts an MCP adapter: `--mcp` alone.
fn toml_adapter_command(entry: &toml_edit::Item) -> Option<&str> {
    use toml_edit::Item;
    let args = entry.get("args").and_then(Item::as_array)?;
    if args.len() != 1 || args.get(0).and_then(toml_edit::Value::as_str) != Some("--mcp") {
        return None;
    }
    entry.get("command").and_then(Item::as_str)
}

fn owned_json(entry: &Value, executable: &Path) -> bool {
    json_adapter_command(entry).is_some_and(|s| owned_command(s, executable))
}

fn owned_toml(entry: &toml_edit::Item, executable: &Path) -> bool {
    toml_adapter_command(entry).is_some_and(|s| owned_command(s, executable))
}

/// The program of an entry among `client`'s settings `bytes` that starts an earlier Lunport this installation does not own: an MCP
/// adapter entry under one of this app's server names whose program has the earlier executable's file name (`names_earlier_binary`)
/// but is none of this installation's (`program`), such as an older copy of the app elsewhere. Nothing tells it apart from a copy the
/// user keeps on purpose, so the move to this version (`retarget`) leaves it as it is, and the migration names it. `None` when there is
/// none, or the settings do not parse.
pub(crate) fn earlier_program_elsewhere(client: SetupClient, bytes: &[u8], executable: &Path) -> Option<String> {
    if client == SetupClient::Codex {
        let doc = std::str::from_utf8(bytes).ok()?.parse::<toml_edit::DocumentMut>().ok()?;
        toml_earlier_elsewhere(doc.get("mcp_servers")?.as_table_like()?, executable)
    } else {
        let doc: Value = serde_json::from_slice(bytes).ok()?;
        json_earlier_elsewhere(doc.get("mcpServers")?.as_object()?, executable)
    }
}

/// `earlier_program_elsewhere` among the programs of the MCP adapter entries under this app's server names.
fn earlier_elsewhere<'a>(commands: impl IntoIterator<Item = &'a str>, executable: &Path) -> Option<String> {
    commands
        .into_iter()
        .find(|command| names_earlier_binary(command) && program(command, executable) == Program::Other)
        .map(str::to_owned)
}

/// `earlier_program_elsewhere` among a client's JSON servers.
fn json_earlier_elsewhere(servers: &serde_json::Map<String, Value>, executable: &Path) -> Option<String> {
    earlier_elsewhere(ALIASES.iter().filter_map(|id| servers.get(*id).and_then(json_adapter_command)), executable)
}

/// `earlier_program_elsewhere` among a client's TOML servers.
fn toml_earlier_elsewhere(servers: &dyn toml_edit::TableLike, executable: &Path) -> Option<String> {
    earlier_elsewhere(ALIASES.iter().filter_map(|id| servers.get(id).and_then(toml_adapter_command)), executable)
}

/// The server names of this app that a client's servers hold, each with whether its entry is this app's own.
fn json_candidates(
    servers: &serde_json::Map<String, Value>,
    executable: &Path,
) -> Vec<(&'static str, bool)> {
    ALIASES
        .iter()
        .filter_map(|id| servers.get(*id).map(|v| (*id, owned_json(v, executable))))
        .collect()
}

fn toml_candidates(
    servers: &dyn toml_edit::TableLike,
    executable: &Path,
) -> Vec<(&'static str, bool)> {
    ALIASES
        .iter()
        .filter_map(|id| servers.get(id).map(|v| (*id, owned_toml(v, executable))))
        .collect()
}

/// Where this app's entry goes among a client's servers (`select_id`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Placement {
    /// The server name the entry is written under.
    id: &'static str,
    /// This app's entry under the old name leaves it for `id`: moved there with its settings, or merged into this app's entry there,
    /// which keeps its own.
    retire_legacy: bool,
}

/// Where this app's entry goes, given which of its server names a client's servers hold and whether the entry there is this app's own
/// (`json_candidates`, `toml_candidates`): the current name, to which an entry of this app under the old name moves as well. When
/// another server holds the current name, this app's entry stays under the old one. Where only other servers hold the names, nothing is
/// placed: another server is never overwritten.
fn select_id(entries: &[(&str, bool)]) -> Result<Placement, AppError> {
    let owned = |id: &str| entries.iter().find(|(name, _)| *name == id).map(|(_, owned)| *owned);
    match (owned(SERVER_ID), owned(LEGACY_SERVER_ID)) {
        (None | Some(true), legacy @ (None | Some(true))) => Ok(Placement { id: SERVER_ID, retire_legacy: legacy.is_some() }),
        (Some(true), Some(false)) => Ok(Placement { id: SERVER_ID, retire_legacy: false }),
        (Some(false), Some(true)) => Ok(Placement { id: LEGACY_SERVER_ID, retire_legacy: false }),
        _ => Err(AppError::Other("An unrelated server already uses this name. It was not changed; use manual setup with another server name.".into())),
    }
}

/// `select_id`'s refusal (`unrelated`) for a client's servers, unless they hold an entry under this app's server names that starts an
/// earlier Lunport elsewhere (`earlier`, as `earlier_program_elsewhere` finds it): that is no unrelated server, and as the migration's
/// notice says, it is changed to start this Lunport or removed, not set up again under another server name.
fn refusal_for(earlier: Option<String>, unrelated: AppError) -> AppError {
    match earlier {
        Some(program) => AppError::Other(format!("An entry under this name starts an earlier Lunport at {program}. It was not changed; change that entry to start this Lunport, or remove it.")),
        None => unrelated,
    }
}

/// Carries out `placement` among a client's JSON servers and returns the entry at its name, an empty one when there was none.
fn place_json(
    servers: &mut serde_json::Map<String, Value>,
    placement: Placement,
) -> &mut Value {
    if placement.retire_legacy {
        if let Some(old) = servers.remove(LEGACY_SERVER_ID) {
            servers.entry(SERVER_ID).or_insert(old);
        }
    }
    servers.entry(placement.id).or_insert_with(|| json!({}))
}

/// Carries out `placement` among a client's TOML servers and returns the entry at its name, an empty table when there was none. A
/// moved entry keeps its comments and its place in the file.
fn place_toml(
    servers: &mut dyn toml_edit::TableLike,
    placement: Placement,
) -> &mut toml_edit::Item {
    if placement.retire_legacy {
        let decor = servers.key(LEGACY_SERVER_ID).map(|key| (key.leaf_decor().clone(), key.dotted_decor().clone()));
        if let Some(old) = servers.remove(LEGACY_SERVER_ID) {
            if servers.get(SERVER_ID).is_none() {
                servers.insert(SERVER_ID, old);
                if let (Some((leaf, dotted)), Some(mut key)) = (decor, servers.key_mut(SERVER_ID)) {
                    *key.leaf_decor_mut() = leaf;
                    *key.dotted_decor_mut() = dotted;
                }
            }
        }
    }
    if servers.get(placement.id).is_none() {
        servers.insert(placement.id, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    servers.get_mut(placement.id).expect("inserted above")
}

/// Sets `key` of a TOML server entry to `value`. An existing value is replaced where it is, with the comment beside it: inserting would
/// format the key anew (toml_edit's `Key::fmt`) and drop the comment lines above it and its indentation.
fn set_toml_value(entry: &mut dyn toml_edit::TableLike, key: &str, value: impl Into<toml_edit::Value>) {
    match entry.get_mut(key).and_then(toml_edit::Item::as_value_mut) {
        Some(existing) => {
            let decor = existing.decor().clone();
            *existing = value.into();
            *existing.decor_mut() = decor;
        }
        None => {
            entry.insert(key, toml_edit::Item::Value(value.into()));
        }
    }
}

/// Sets the command of a TOML server entry, keeping its comments.
fn set_toml_command(entry: &mut dyn toml_edit::TableLike, command: &str) {
    set_toml_value(entry, "command", command);
}

/// Returns the edited document and whether the existing entry already used this exact path.
fn configure_json(bytes: &[u8], executable: &Path) -> Result<(Vec<u8>, bool), AppError> {
    let mut doc: Value = serde_json::from_slice(bytes)
        .map_err(|_| AppError::Other("The existing JSON settings could not be parsed. Nothing was changed; use manual setup.".into()))?;
    let root = doc.as_object_mut().ok_or_else(|| {
        AppError::Other("Settings must be a JSON object. Nothing was changed.".into())
    })?;
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            AppError::Other(
                "The existing MCP server settings are invalid. Nothing was changed.".into(),
            )
        })?;
    let placement = select_id(&json_candidates(servers, executable))
        .map_err(|unrelated| refusal_for(json_earlier_elsewhere(servers, executable), unrelated))?;
    let entry = place_json(servers, placement);
    let ready = !placement.retire_legacy
        && entry.get("command").and_then(Value::as_str) == executable.to_str()
        && owned_json(entry, executable);
    let entry = entry
        .as_object_mut()
        .ok_or_else(|| AppError::Other("The existing server entry is invalid.".into()))?;
    entry.insert("command".into(), json!(executable));
    entry.insert("args".into(), json!(["--mcp"]));
    let mut result = serde_json::to_vec_pretty(&doc).expect("JSON values serialize");
    result.push(b'\n');
    Ok((result, ready))
}

fn configure_toml(bytes: &[u8], executable: &Path) -> Result<(Vec<u8>, bool), AppError> {
    use toml_edit::{Array, DocumentMut, Item, Table};
    let text = std::str::from_utf8(bytes).map_err(|_| {
        AppError::Other("The existing TOML settings are not UTF-8. Nothing was changed.".into())
    })?;
    let mut doc = text.parse::<DocumentMut>().map_err(|_| AppError::Other("The existing TOML settings could not be parsed. Nothing was changed; use manual setup.".into()))?;
    let servers = doc
        .entry("mcp_servers")
        .or_insert(Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(|| {
            AppError::Other(
                "The existing MCP server settings are invalid. Nothing was changed.".into(),
            )
        })?;
    let placement = select_id(&toml_candidates(servers, executable))
        .map_err(|unrelated| refusal_for(toml_earlier_elsewhere(servers, executable), unrelated))?;
    let entry = place_toml(servers, placement);
    let ready = !placement.retire_legacy
        && entry.get("command").and_then(Item::as_str) == executable.to_str()
        && owned_toml(entry, executable)
        && entry.get("enabled").and_then(Item::as_bool) != Some(false);
    let table = entry
        .as_table_like_mut()
        .ok_or_else(|| AppError::Other("The existing server entry is invalid.".into()))?;
    set_toml_command(table, executable.to_string_lossy().as_ref());
    let mut args = Array::new();
    args.push("--mcp");
    set_toml_value(table, "args", args);
    if table.get("enabled").and_then(Item::as_bool) == Some(false) {
        set_toml_value(table, "enabled", true);
    }
    Ok((doc.to_string().into_bytes(), ready))
}

fn configure(client: SetupClient, bytes: &[u8], exe: &Path) -> Result<(Vec<u8>, bool), AppError> {
    if client == SetupClient::Codex {
        configure_toml(bytes, exe)
    } else {
        configure_json(bytes, exe)
    }
}

/// `client`'s settings with this app's entry moved, for the move to the new executable: an entry under the old server name takes the
/// current one, and a command that names an earlier executable becomes `executable`. `None` when there is nothing to move. Unlike the
/// setup's Add, it adds no entry, changes no other setting, keeps a command that starts this version by a path of the user's own, and
/// never touches another server's entry.
pub(crate) fn retarget(client: SetupClient, bytes: &[u8], executable: &Path) -> Option<Vec<u8>> {
    let command = executable.to_str()?;
    if client == SetupClient::Codex {
        retarget_toml(bytes, executable, command)
    } else {
        retarget_json(bytes, executable, command)
    }
}

fn retarget_toml(bytes: &[u8], executable: &Path, command: &str) -> Option<Vec<u8>> {
    let mut doc = std::str::from_utf8(bytes).ok()?.parse::<toml_edit::DocumentMut>().ok()?;
    let servers = doc.get_mut("mcp_servers")?.as_table_like_mut()?;
    let placement = own_placement(&toml_candidates(servers, executable))?;
    let entry = place_toml(servers, placement);
    let earlier = entry
        .get("command")
        .and_then(toml_edit::Item::as_str)
        .is_some_and(|current| program(current, executable) == Program::Earlier);
    if !placement.retire_legacy && !earlier {
        return None;
    }
    if earlier {
        set_toml_command(entry.as_table_like_mut()?, command);
    }
    Some(doc.to_string().into_bytes())
}

fn retarget_json(bytes: &[u8], executable: &Path, command: &str) -> Option<Vec<u8>> {
    let mut doc: Value = serde_json::from_slice(bytes).ok()?;
    let servers = doc.get_mut("mcpServers")?.as_object_mut()?;
    let placement = own_placement(&json_candidates(servers, executable))?;
    let entry = place_json(servers, placement);
    let earlier = entry
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|current| program(current, executable) == Program::Earlier);
    if !placement.retire_legacy && !earlier {
        return None;
    }
    if earlier {
        entry.as_object_mut()?.insert("command".into(), json!(command));
    }
    let mut result = serde_json::to_vec_pretty(&doc).ok()?;
    result.push(b'\n');
    Some(result)
}

/// Where this app's entry goes, when the client has one: a client without an entry of this app's gets none.
fn own_placement(candidates: &[(&'static str, bool)]) -> Option<Placement> {
    if !candidates.iter().any(|(_, owned)| *owned) {
        return None;
    }
    select_id(candidates).ok()
}

pub(crate) fn commit(
    path: &Path,
    before: Option<&[u8]>,
    after: &[u8],
    backups: &Path,
) -> Result<Option<PathBuf>, AppError> {
    crate::fsutil::check_write(path)?;
    crate::fsutil::check_write(backups)?;
    if read_config(path)?.as_deref() != before {
        return Err(AppError::Other(SETTINGS_CHANGED.into()));
    }
    #[cfg(unix)]
    if path.exists() {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o200 == 0 {
            return Err(AppError::Other(READ_ONLY.into()));
        }
    }
    let backup = if let Some(bytes) = before {
        crate::fsutil::ensure_dir_secure(backups)?;
        #[cfg(windows)]
        crate::sync::slot_files_windows::restrict_to_owner(backups, true)?;
        let mut file = tempfile::Builder::new()
            .prefix("before-setup-")
            .suffix(".bak")
            .tempfile_in(backups)?;
        #[cfg(windows)]
        crate::sync::slot_files_windows::restrict_to_owner(file.path(), false)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        Some(file.keep().map_err(|e| AppError::Io(e.error))?.1)
    } else {
        None
    };
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Other("Settings have no parent directory.".into()))?;
    crate::fsutil::ensure_dir_secure(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(windows)]
    crate::sync::slot_files_windows::restrict_to_owner(file.path(), false)?;
    file.write_all(after)?;
    file.as_file().sync_all()?;
    if read_config(path)?.as_deref() != before {
        return Err(AppError::Other(SETTINGS_CHANGED.into()));
    }
    if before.is_none() {
        file.persist_noclobber(path)
            .map_err(|e| AppError::Io(e.error))?;
    } else {
        file.persist(path).map_err(|e| AppError::Io(e.error))?;
    }
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(backup)
}

/// The program client settings start: this executable by its real path, or on Linux the AppImage that runs. It must be UTF-8.
pub(crate) fn executable() -> Result<PathBuf, AppError> {
    // The inner binary of an AppImage lives under a temporary mount. Register the
    // persistent AppImage itself so later client launches survive an app restart.
    let exe = setup_executable(
        std::env::consts::OS,
        &std::env::current_exe()?,
        std::env::var_os("APPIMAGE").map(PathBuf::from).as_deref(),
    )?;
    if exe.to_str().is_none() {
        return Err(AppError::Other(
            "This installation path cannot be represented in client settings.".into(),
        ));
    }
    Ok(exe)
}
fn setup_executable(
    os: &str,
    running: &Path,
    appimage: Option<&Path>,
) -> Result<PathBuf, AppError> {
    let path = if os == "linux" {
        appimage.filter(|p| p.is_absolute()).unwrap_or(running)
    } else {
        running
    };
    Ok(path.canonicalize()?)
}
fn empty_config(client: SetupClient) -> &'static [u8] {
    if client == SetupClient::Codex {
        b""
    } else {
        b"{}"
    }
}
fn overview() -> Result<SetupOverview, AppError> {
    let exe = executable()?;
    let clients = [SetupClient::Codex, SetupClient::ClaudeCode, SetupClient::ClaudeDesktop, SetupClient::Cursor, SetupClient::Vscode].into_iter().map(|client| {
        let mut result = ClientSetup { client, state: "not_added".into(), message: None, config_path: None };
        if client.external() { result.state = "external".into(); return result; }
        let check = (|| {
            let path = client_path(client)?.ok_or_else(|| AppError::Other(format!("{} setup is available on macOS and Windows. Use manual setup on this platform.", client.name())))?;
            result.config_path = Some(path.to_string_lossy().into_owned());
            let bytes = read_config(&path)?;
            let (_, ready) = configure(client, bytes.as_deref().unwrap_or(empty_config(client)), &exe)?;
            // An unrelated config file without our entry is still Not added, never Needs repair.
            result.state = if ready { "configured" } else if bytes.as_ref().is_some_and(|b| has_entry(client, b)) {
                if client == SetupClient::Codex && bytes.as_ref().is_some_and(|b| codex_disabled(b)) { "disabled" } else { "needs_repair" }
            } else { "not_added" }.into();
            Ok::<_, AppError>(())
        })();
        if let Err(error) = check { result.state = "unavailable".into(); result.message = Some(error.to_string()); }
        result
    }).collect();
    Ok(SetupOverview {
        sandbox: !crate::app_profile::CURRENT.allows_os_integrations(),
        executable: exe.to_string_lossy().into_owned(),
        clients,
    })
}

fn codex_disabled(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .is_some_and(|d| {
            ALIASES.iter().any(|id| {
                d.get("mcp_servers")
                    .and_then(|v| v.get(id))
                    .and_then(|v| v.get("enabled"))
                    .and_then(toml_edit::Item::as_bool)
                    == Some(false)
            })
        })
}

fn has_entry(client: SetupClient, bytes: &[u8]) -> bool {
    if client == SetupClient::Codex {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .is_some_and(|d| {
                ALIASES
                    .iter()
                    .any(|id| d.get("mcp_servers").and_then(|v| v.get(id)).is_some())
            })
    } else {
        serde_json::from_slice::<Value>(bytes)
            .ok()
            .is_some_and(|d| {
                ALIASES
                    .iter()
                    .any(|id| d.get("mcpServers").and_then(|v| v.get(id)).is_some())
            })
    }
}

fn install_link(client: SetupClient, exe: &Path) -> Result<String, AppError> {
    use base64::Engine;
    let server = json!({"command":exe, "args":["--mcp"]});
    if client == SetupClient::Cursor {
        let config = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&server).expect("JSON values serialize"));
        let mut url = tauri::Url::parse("cursor://anysphere.cursor-deeplink/mcp/install").unwrap();
        url.query_pairs_mut()
            .append_pair("name", SERVER_ID)
            .append_pair("config", &config);
        Ok(url.into())
    } else if client == SetupClient::Vscode {
        // VS Code expects a percent-encoded JSON query, rather than key/value pairs.
        let json = serde_json::to_vec(
            &json!({"name":SERVER_ID,"type":"stdio","command":exe,"args":["--mcp"]}),
        )
        .expect("JSON values serialize");
        let encoded: String = json.iter().map(|b| format!("%{b:02X}")).collect();
        Ok(format!("vscode:mcp/install?{encoded}"))
    } else {
        Err(AppError::Other(
            "This client does not use an installation link.".into(),
        ))
    }
}

#[tauri::command]
pub async fn mcp_setup_overview() -> Result<SetupOverview, AppError> {
    tauri::async_runtime::spawn_blocking(overview)
        .await
        .map_err(|_| AppError::Other("Client setup could not be inspected.".into()))?
}

#[tauri::command]
pub async fn mcp_setup_add(
    app: tauri::AppHandle,
    client: SetupClient,
) -> Result<SetupResult, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let exe = executable()?;
        if client.external() {
            if !crate::app_profile::CURRENT.allows_os_integrations() { return Err(AppError::Other("Development does not install servers in external apps. Use the sandbox configuration preview.".into())); }
            use tauri_plugin_opener::OpenerExt;
            app.opener().open_url(install_link(client, &exe)?, None::<String>)
                .map_err(|_| AppError::Other(format!("Could not open {}. Install it first, or use manual setup.", client.name())))?;
            return Ok(SetupResult { external: true, changed: false, backup_path: None });
        }
        let path = client_path(client)?.ok_or_else(|| AppError::Other("Use manual setup for this client on this platform.".into()))?;
        let before = read_config(&path)?;
        let (after, ready) = configure(client, before.as_deref().unwrap_or(empty_config(client)), &exe)?;
        if ready { return Ok(SetupResult { external: false, changed: false, backup_path: None }); }
        let backups = backup_folder(&crate::fsutil::app_data_root()?, client);
        let backup = commit(&path, before.as_deref(), &after, &backups)?;
        Ok(SetupResult { external: false, changed: true, backup_path: backup.map(|p| p.to_string_lossy().into_owned()) })
    }).await.map_err(|_| AppError::Other("Client setup could not be completed.".into()))?
}

#[tauri::command]
pub async fn mcp_setup_export(
    app: tauri::AppHandle,
    format: SetupFormat,
) -> Result<Option<String>, AppError> {
    use tauri_plugin_dialog::DialogExt;
    let exe = executable()?;
    let (name, extension, bytes) = match format {
        SetupFormat::Toml => ("lunport-mcp.toml", "toml", configure_toml(b"", &exe)?.0),
        SetupFormat::Json => ("lunport-mcp.json", "json", configure_json(b"{}", &exe)?.0),
        SetupFormat::Vscode => (
            "lunport-vscode-mcp.json",
            "json",
            serde_json::to_vec_pretty(
                &json!({"servers":{SERVER_ID:{"type":"stdio","command":exe,"args":["--mcp"]}}}),
            )
            .expect("JSON values serialize"),
        ),
    };
    let Some(picked) = app
        .dialog()
        .file()
        .set_file_name(name)
        .add_filter("MCP configuration", &[extension])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = picked
        .into_path()
        .map_err(|_| AppError::Other("The selected file location is unavailable.".into()))?;
    crate::fsutil::atomic_write(&path, &bytes, 0o600)?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

#[cfg(test)]
#[path = "mcp_setup_tests.rs"]
mod tests;
