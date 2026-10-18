//! Client-specific setup for the existing stdio adapter. No host or AI permission is granted.
use crate::{app_profile::AppProfile, error::AppError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const SERVER_ID: &str = "sshelter";
const MAX_CONFIG: u64 = 8 * 1024 * 1024;
const ALIASES: [&str; 2] = [SERVER_ID, "lunport"];

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
    fn name(self) -> &'static str {
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
    let home = crate::fsutil::home_dir()?;
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
    Ok(config_path(client, &home, std::env::consts::OS, codex_home))
}

fn read_config(path: &Path) -> Result<Option<Vec<u8>>, AppError> {
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

fn owned_command(command: &str, executable: &Path) -> bool {
    let path = Path::new(command);
    if path == executable {
        return true;
    }
    match (fs::canonicalize(path), fs::canonicalize(executable)) {
        (Ok(a), Ok(b)) => a == b,
        // Recover only the original app name alongside this canonical macOS installation.
        // An existing different executable never qualifies by basename alone.
        (Err(e), _) if e.kind() == std::io::ErrorKind::NotFound => {
            let legacy = executable
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent);
            legacy.is_some_and(|bundle| {
                ["SSHelter.app", "sshelter.app", "SSHelter Dev.app"]
                    .iter()
                    .any(|old| path == bundle.with_file_name(old).join("Contents/MacOS/sshelter"))
            })
        }
        _ => false,
    }
}
fn owned_json(entry: &Value, executable: &Path) -> bool {
    entry.get("args") == Some(&json!(["--mcp"]))
        && entry.get("type").is_none_or(|v| v == "stdio")
        && entry
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|s| owned_command(s, executable))
}
fn select_id(entries: &[(&str, bool)]) -> Result<&'static str, AppError> {
    if let Some((id, _)) = entries.iter().find(|(_, owned)| *owned) {
        return Ok(if *id == "lunport" {
            "lunport"
        } else {
            SERVER_ID
        });
    }
    if !entries.is_empty() {
        return Err(AppError::Other("An unrelated server already uses this name. It was not changed; use manual setup with another server name.".into()));
    }
    Ok(SERVER_ID)
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
    let candidates: Vec<_> = ALIASES
        .iter()
        .filter_map(|id| servers.get(*id).map(|v| (*id, owned_json(v, executable))))
        .collect();
    let id = select_id(&candidates)?;
    let entry = servers.entry(id).or_insert_with(|| json!({}));
    let ready = entry.get("command").and_then(Value::as_str) == executable.to_str()
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
    let owned = |entry: &Item| {
        entry.get("args").and_then(Item::as_array).is_some_and(|a| {
            a.len() == 1 && a.get(0).and_then(toml_edit::Value::as_str) == Some("--mcp")
        }) && entry
            .get("command")
            .and_then(Item::as_str)
            .is_some_and(|s| owned_command(s, executable))
    };
    let candidates: Vec<_> = ALIASES
        .iter()
        .filter_map(|id| servers.get(id).map(|v| (*id, owned(v))))
        .collect();
    let id = select_id(&candidates)?;
    if servers.get(id).is_none() {
        servers.insert(id, Item::Table(Table::new()));
    }
    let entry = servers.get_mut(id).unwrap();
    let ready = entry.get("command").and_then(Item::as_str) == executable.to_str()
        && owned(entry)
        && entry.get("enabled").and_then(Item::as_bool) != Some(false);
    let table = entry
        .as_table_like_mut()
        .ok_or_else(|| AppError::Other("The existing server entry is invalid.".into()))?;
    table.insert(
        "command",
        toml_edit::value(executable.to_string_lossy().as_ref()),
    );
    let mut args = Array::new();
    args.push("--mcp");
    table.insert("args", toml_edit::value(args));
    if table.get("enabled").and_then(Item::as_bool) == Some(false) {
        table.insert("enabled", toml_edit::value(true));
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

fn commit(
    path: &Path,
    before: Option<&[u8]>,
    after: &[u8],
    backups: &Path,
) -> Result<Option<PathBuf>, AppError> {
    crate::fsutil::check_write(path)?;
    crate::fsutil::check_write(backups)?;
    if read_config(path)?.as_deref() != before {
        return Err(AppError::Other(
            "Settings changed while preparing setup. Refresh and try again.".into(),
        ));
    }
    #[cfg(unix)]
    if path.exists() {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o200 == 0 {
            return Err(AppError::Other(
                "This settings file is read-only. Use manual setup or make it writable first."
                    .into(),
            ));
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
        return Err(AppError::Other(
            "Settings changed while preparing setup. Refresh and try again.".into(),
        ));
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

fn executable() -> Result<PathBuf, AppError> {
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
        let backups = crate::fsutil::app_data_root()?.join("backups/mcp-setup").join(client.key());
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
