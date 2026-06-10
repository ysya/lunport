//! Tray (menubar) quick-connect. The tray itself can't be unit-tested; pure list logic lives in
//! `tray_aliases` (tested), and `rebuild_tray` stays thin.

use tauri::menu::{MenuBuilder, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

use crate::config::model::{HostBlock, Item, SshConfigDoc};

/// Tray menu capacity for connect entries.
const MAX_TRAY_ALIASES: usize = 25;

/// First pattern of each HostBlock across all files, skipping pure-wildcard patterns ("*"),
/// capped at MAX_TRAY_ALIASES. Pure function for testing.
pub fn tray_aliases(doc: &SshConfigDoc) -> Vec<String> {
    let mut out = Vec::new();
    for file in &doc.files {
        for item in &file.items {
            if let Item::Host(HostBlock { patterns, .. }) = item {
                if let Some(first) = patterns.first() {
                    if first == "*" {
                        continue;
                    }
                    out.push(first.clone());
                    if out.len() >= MAX_TRAY_ALIASES {
                        return out;
                    }
                }
            }
        }
    }
    out
}

/// Build (or update) the single menubar tray with the given aliases.
pub fn rebuild_tray(app: &tauri::AppHandle, aliases: &[String]) -> tauri::Result<()> {
    let mut builder = MenuBuilder::new(app);

    let mut connect_items: Vec<MenuItem<tauri::Wry>> = Vec::new();
    for alias in aliases.iter().take(MAX_TRAY_ALIASES) {
        let item = MenuItem::with_id(
            app,
            format!("connect:{alias}"),
            alias,
            true,
            None::<&str>,
        )?;
        connect_items.push(item);
    }
    for item in &connect_items {
        builder = builder.item(item);
    }

    builder = builder
        .separator()
        .text("open", "Open SSHelter")
        .text("quit", "Quit");

    let menu = builder.build()?;

    if let Some(tray) = app.tray_by_id("main-tray") {
        tray.set_menu(Some(menu))?;
    } else {
        let mut tray_builder = TrayIconBuilder::with_id("main-tray")
            .icon(
                app.default_window_icon()
                    .cloned()
                    .expect("default window icon must be configured"),
            )
            .menu(&menu)
            .show_menu_on_left_click(true)
            .on_menu_event(on_menu_event);

        #[cfg(target_os = "macos")]
        {
            tray_builder = tray_builder.icon_as_template(true);
        }

        tray_builder.build(app)?;
    }

    Ok(())
}

/// Handle tray menu clicks. Errors are logged and swallowed — never panic from a menu callback.
fn on_menu_event(app: &tauri::AppHandle, event: tauri::menu::MenuEvent) {
    let id = event.id().as_ref();
    match id {
        "quit" => app.exit(0),
        "open" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        other => {
            if let Some(alias) = other.strip_prefix("connect:") {
                if let Err(e) = quick_connect(app, alias) {
                    eprintln!("[tray] quick-connect '{alias}' failed: {e}");
                }
            }
        }
    }
}

/// Validate + build_launch with the first detected terminal, then launch.
fn quick_connect(app: &tauri::AppHandle, alias: &str) -> Result<(), crate::error::AppError> {
    use crate::error::AppError;

    let state = app.state::<crate::state::AppState>();
    let doc_lock = state.doc.lock().unwrap();
    let doc = doc_lock
        .as_ref()
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;

    crate::connect::validate_alias(doc, alias)?;

    let terminal = crate::connect::detect_terminals()
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Other("no terminal found".to_string()))?;

    let spec = crate::connect::build_launch(&terminal.id, alias)?;
    crate::connect::launch(&spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;

    fn doc_with(content: &str) -> SshConfigDoc {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, content).unwrap();
        let doc = load_doc(&path).unwrap();
        std::mem::forget(dir);
        doc
    }

    #[test]
    fn tray_aliases_lists_first_patterns_skipping_wildcard() {
        let doc = doc_with(
            "Host web prod\n    User x\nHost *\n    ForwardAgent yes\nHost db\n    User y\n",
        );
        let aliases = tray_aliases(&doc);
        assert_eq!(aliases, vec!["web".to_string(), "db".to_string()]);
    }

    #[test]
    fn tray_aliases_caps_at_25() {
        let mut content = String::new();
        for i in 0..40 {
            content.push_str(&format!("Host h{i}\n    User x\n"));
        }
        let doc = doc_with(&content);
        let aliases = tray_aliases(&doc);
        assert_eq!(aliases.len(), 25);
        assert_eq!(aliases[0], "h0");
        assert_eq!(aliases[24], "h24");
    }

    #[test]
    fn tray_aliases_empty_for_no_hosts() {
        let doc = doc_with("# just a comment\n");
        assert!(tray_aliases(&doc).is_empty());
    }
}
