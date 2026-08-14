use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use crate::config::model::SshConfigDoc;

/// Tauri-managed app state: the loaded multi-file config document and which files have already
/// been backed up this session (so we back up each live file only once before the first write).
pub struct AppState {
    pub doc: Mutex<Option<SshConfigDoc>>,
    pub backed_up: Mutex<HashSet<PathBuf>>,
    /// How many `.bak` snapshots to keep per managed file. `None` = unlimited (no pruning).
    pub backup_retention: Mutex<Option<usize>>,
    /// Desired menubar tray visibility; `rebuild_tray` re-applies it so a hidden tray stays hidden.
    pub tray_visible: AtomicBool,
    /// When true, closing the main window hides it to the tray instead of quitting.
    pub close_to_tray: AtomicBool,
    /// Local MCP bridge policy, pending approvals, and recent audit events.
    pub mcp: crate::mcp::McpRuntime,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            doc: Mutex::new(None),
            backed_up: Mutex::new(HashSet::new()),
            backup_retention: Mutex::new(None),
            tray_visible: AtomicBool::new(true),
            close_to_tray: AtomicBool::new(false),
            mcp: crate::mcp::McpRuntime::default(),
        }
    }
}
