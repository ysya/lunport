use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::config::model::SshConfigDoc;

/// Tauri-managed app state: the loaded multi-file config document and which files have already
/// been backed up this session (so we back up each live file only once before the first write).
#[derive(Default)]
pub struct AppState {
    pub doc: Mutex<Option<SshConfigDoc>>,
    pub backed_up: Mutex<HashSet<PathBuf>>,
}
