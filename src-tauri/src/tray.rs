//! Tray quick-connect. Pure public-data helpers choose IDs, labels and readiness; Tauri menu
//! building stays thin. Click workers validate the latest runtime before launching a terminal.

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

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordTrayItem {
    id: String,
    label: String,
    enabled: bool,
}

fn menu_label(value: &str) -> String {
    crate::session::auth::printable(value).replace(['\n', '\t'], "?")
}

fn unique_host<'a>(
    hosts: &'a [crate::sync::record_repository::HostView],
    id: &str,
) -> Option<&'a crate::sync::record_repository::HostView> {
    let mut matching = hosts.iter().filter(|view| view.host.id == id);
    let first = matching.next()?;
    matching.next().is_none().then_some(first)
}

/// Snapshot validation already checks routes. Check every hop's public readiness, inheriting only
/// the first jump's own route, as the repository and session directory do.
fn route_ready(hosts: &[crate::sync::record_repository::HostView], id: &str) -> bool {
    use crate::sync::record_repository::HostReadiness;
    let mut current = id;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        if !seen.insert(current) || seen.len() > crate::sync::records_v3::MAX_JUMPS + 1 {
            return false;
        }
        let Some(view) = unique_host(hosts, current) else {
            return false;
        };
        if view.readiness != HostReadiness::Ready {
            return false;
        }
        for jump in view.host.payload.jump.iter().skip(1) {
            if !unique_host(hosts, jump).is_some_and(|view| view.readiness == HostReadiness::Ready)
            {
                return false;
            }
        }
        match view.host.payload.jump.first() {
            Some(first) => current = first,
            None => return true,
        }
    }
}

fn tray_record_items(
    state: &crate::sync::records_v3::SyncStateV3,
) -> Result<Vec<RecordTrayItem>, crate::sync::record_repository::RepositoryError> {
    use crate::sync::record::{record_key, RecordKind};
    use crate::sync::record_repository::{snapshot, HostReadiness};
    use crate::sync::records_v3::HostScope;
    use std::collections::{BTreeMap, BTreeSet};
    let snapshot = snapshot(state)?;
    let mut aliases = BTreeMap::new();
    let mut ids = BTreeMap::new();
    for view in &snapshot.hosts {
        *aliases
            .entry(view.host.payload.alias.as_str())
            .or_insert(0usize) += 1;
        *ids.entry(view.host.id.as_str()).or_insert(0usize) += 1;
    }
    let mut emitted = BTreeSet::new();
    let mut items = Vec::new();
    for view in &snapshot.hosts {
        let host = &view.host;
        if !emitted.insert(host.id.as_str()) {
            continue;
        }
        if ids[host.id.as_str()] > 1 {
            items.push(RecordTrayItem {
                id: format!("record-connect:{}", host.id),
                label: format!("Conflicting host ID ({})", host.id),
                enabled: false,
            });
            continue;
        }
        let mut label = menu_label(&host.payload.alias);
        if aliases[host.payload.alias.as_str()] > 1 {
            let context = match &host.scope {
                HostScope::Local => "Local".to_owned(),
                HostScope::Space { space_id } => {
                    let name = state
                        .account
                        .as_ref()
                        .and_then(|account| {
                            account
                                .records
                                .get(&record_key(RecordKind::Space, space_id))
                        })
                        .filter(|local| !local.record.deleted)
                        .and_then(|local| local.record.payload.get("name"))
                        .and_then(serde_json::Value::as_str)
                        .map(menu_label)
                        .unwrap_or_else(|| "Space".into());
                    format!("{name} [{}]", &space_id[..8])
                }
            };
            label.push_str(&format!(" — {context}"));
        }
        let enabled = route_ready(&snapshot.hosts, &host.id);
        if !enabled {
            let reason = match &view.readiness {
                HostReadiness::Ready => "Review jump hosts",
                HostReadiness::NeedsKey(_) => "Needs key",
                HostReadiness::KeyConflict(_) => "Key conflict",
                HostReadiness::NeedsReview => "Needs review",
            };
            label.push_str(&format!(" · {reason}"));
        }
        items.push(RecordTrayItem {
            id: format!("record-connect:{}", host.id),
            label,
            enabled,
        });
    }
    let mut labels = BTreeMap::new();
    for item in &items {
        *labels.entry(item.label.clone()).or_insert(0usize) += 1;
    }
    for item in &mut items {
        if labels[&item.label] > 1 {
            item.label.push_str(&format!(
                " [{}]",
                item.id
                    .strip_prefix("record-connect:")
                    .expect("constructed record menu ID")
            ));
        }
    }
    items.truncate(MAX_TRAY_ALIASES);
    Ok(items)
}

fn legacy_tray_allowed(core: &crate::sync::runtime::SyncCore) -> bool {
    core.format == crate::sync::record_runtime::RuntimeFormat::Legacy
        && !core.legacy_paused
        && core.records.is_none()
        && core.save_blocked.is_none()
}
fn active_record_snapshot(
    core: &crate::sync::runtime::SyncCore,
) -> Result<crate::sync::records_v3::SyncStateV3, crate::error::AppError> {
    if core.format != crate::sync::record_runtime::RuntimeFormat::Records
        || core.state.is_some()
        || core.legacy.is_some()
        || core.save_blocked.is_some()
    {
        return Err(crate::error::AppError::Other(
            "record workspace is unavailable".into(),
        ));
    }
    core.records
        .clone()
        .ok_or_else(|| crate::error::AppError::Other("record workspace is not initialized".into()))
}
fn record_connect_id(
    state: &crate::sync::records_v3::SyncStateV3,
    id: &str,
) -> Result<String, crate::error::AppError> {
    use crate::error::AppError;
    use crate::sync::record_repository::{resolve_host_chain, HostReadiness};
    if !crate::sync::records_v3::is_host_id(id) {
        return Err(AppError::Other("invalid host id".into()));
    }
    let hops = resolve_host_chain(state, id).map_err(|error| AppError::Other(error.to_string()))?;
    if hops.iter().any(|hop| hop.readiness != HostReadiness::Ready) {
        return Err(AppError::Other(
            "resolve the host's key or settings before connecting".into(),
        ));
    }
    Ok(id.into())
}

/// Build the records menu from one public snapshot. Callers must release all runtime locks before
/// this function: Tauri menu operations synchronously wait for the main thread.
pub fn rebuild_record_tray(
    app: &tauri::AppHandle,
    state: &crate::sync::records_v3::SyncStateV3,
) -> tauri::Result<()> {
    let items =
        tray_record_items(state).map_err(|error| std::io::Error::other(error.to_string()))?;
    rebuild_menu(app, &items)
}

/// Build (or update) the single menubar tray with the given aliases.
pub fn rebuild_tray(app: &tauri::AppHandle, aliases: &[String]) -> tauri::Result<()> {
    let items: Vec<_> = aliases
        .iter()
        .take(MAX_TRAY_ALIASES)
        .map(|alias| RecordTrayItem {
            id: format!("connect:{alias}"),
            label: alias.clone(),
            enabled: true,
        })
        .collect();
    rebuild_menu(app, &items)
}

fn rebuild_menu(app: &tauri::AppHandle, items: &[RecordTrayItem]) -> tauri::Result<()> {
    let mut builder = MenuBuilder::new(app);
    let mut connect_items: Vec<MenuItem<tauri::Wry>> = Vec::new();
    for entry in items.iter().take(MAX_TRAY_ALIASES) {
        connect_items.push(MenuItem::with_id(
            app,
            &entry.id,
            &entry.label,
            entry.enabled,
            None::<&str>,
        )?);
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

    // Re-apply the desired visibility so a rebuild never resurrects a hidden tray.
    let visible = app
        .state::<crate::state::AppState>()
        .tray_visible
        .load(std::sync::atomic::Ordering::Relaxed);
    if let Some(tray) = app.tray_by_id("main-tray") {
        tray.set_visible(visible)?;
    }

    Ok(())
}

/// Show or hide the menubar tray icon. The desired state is stored in AppState so
/// `rebuild_tray` (e.g. on config reload) keeps honoring it.
#[tauri::command]
pub fn tray_set_visible(
    app: tauri::AppHandle,
    state: tauri::State<crate::state::AppState>,
    visible: bool,
) -> Result<(), crate::error::AppError> {
    state
        .tray_visible
        .store(visible, std::sync::atomic::Ordering::Relaxed);
    if let Some(tray) = app.tray_by_id("main-tray") {
        tray.set_visible(visible)
            .map_err(|e| crate::error::AppError::Other(e.to_string()))?;
    }
    Ok(())
}

/// Handle tray menu clicks. Errors are logged and swallowed — never panic from a menu callback.
fn on_menu_event(app: &tauri::AppHandle, event: tauri::menu::MenuEvent) {
    let id = event.id().as_ref();
    match id {
        "quit" => app.exit(0),
        "open" => crate::show_main_window_by_user(app),
        other => {
            if let Some(host_id) = other.strip_prefix("record-connect:") {
                let (app, host_id) = (app.clone(), host_id.to_owned());
                std::thread::spawn(move || {
                    if let Err(error) = quick_connect_record(&app, &host_id) {
                        eprintln!("[tray] record quick-connect failed: {error}");
                    }
                });
            } else if let Some(alias) = other.strip_prefix("connect:") {
                // Off the menu thread: starting the terminal spawns a process (osascript on macOS).
                let (app, alias) = (app.clone(), alias.to_string());
                std::thread::spawn(move || {
                    if let Err(e) = quick_connect(&app, &alias) {
                        eprintln!("[tray] quick-connect '{alias}' failed: {e}");
                    }
                });
            }
        }
    }
}

/// Validate, then launch with the first detected terminal: `sshelter connect <alias>` (own-ssh spec §7.4; on Windows through the console
/// helper `sshelter-cli.exe`, see `connect::launch_for`).
fn quick_connect(app: &tauri::AppHandle, alias: &str) -> Result<(), crate::error::AppError> {
    use crate::error::AppError;

    let state = app.state::<crate::state::AppState>();
    // Off the menu thread. Keep mode publication serialized through the terminal process spawn,
    // without holding core/doc during detection or launch and without reading any credential.
    let _publication = state.sync.format_publication.lock().unwrap();
    if !legacy_tray_allowed(&state.sync.core.lock().unwrap()) {
        return Err(AppError::Other("legacy workspace is unavailable".into()));
    }
    {
        let doc_lock = state.doc.lock().unwrap();
        let doc = doc_lock
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        crate::connect::validate_alias(doc, alias)?;
    }

    let terminal = crate::connect::detect_terminals()
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Other("no terminal found".to_string()))?;

    crate::connect::launch(&crate::connect::launch_for(&terminal.id, alias, false)?)
}

/// Records menu events never consult doc, ssh -G, Keychain or a private-material owner.
fn quick_connect_record(
    app: &tauri::AppHandle,
    host_id: &str,
) -> Result<(), crate::error::AppError> {
    use crate::error::AppError;
    let state = app.state::<crate::state::AppState>();
    let _publication = state.sync.format_publication.lock().unwrap();
    let snapshot = active_record_snapshot(&state.sync.core.lock().unwrap())?;
    let host_id = record_connect_id(&snapshot, host_id)?;
    let terminal = crate::connect::detect_terminals()
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Other("no terminal found".into()))?;
    crate::connect::launch(&crate::connect::launch_for_id(
        &terminal.id,
        &host_id,
        false,
    )?)
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
    use crate::sync::record::{record_key, LocalRecord, Record, RecordKind};
    use crate::sync::record_runtime::RuntimeFormat;
    use crate::sync::records_v3::{AuthKind, HostPayload, SpaceStateV3, SyncStateV3};
    use crate::sync::runtime::SyncCore;
    use crate::sync::state_v2::AccountState;
    const RECORD_ID: &str = "0000000000000001";
    const SECOND_ID: &str = "0000000000000002";
    fn record_state() -> SyncStateV3 {
        serde_json::from_value(serde_json::json!({"version":3,"device_id":"d".repeat(32),"device_name":"fixture","relay_url":"http://127.0.0.1:8787","last_sync_ms":null,"last_error":null})).unwrap()
    }
    fn host_payload(alias: &str) -> HostPayload {
        serde_json::from_value(serde_json::json!({"schema":2,"alias":alias,"hostname":"fixture.invalid","auth":"password"})).unwrap()
    }
    fn cached_host(id: &str, payload: HostPayload) -> LocalRecord {
        LocalRecord {
            record: Record {
                kind: RecordKind::Host,
                id: id.into(),
                version: 1,
                updated_at_ms: 1,
                device_id: "d".repeat(32),
                deleted: false,
                payload: serde_json::to_value(payload).unwrap(),
            },
            seq: 0,
            dirty: false,
        }
    }
    fn add_local(state: &mut SyncStateV3, id: &str, payload: HostPayload) {
        state
            .local
            .hosts
            .insert(record_key(RecordKind::Host, id), cached_host(id, payload));
    }
    fn add_space(
        state: &mut SyncStateV3,
        id: &str,
        name: &str,
        host_id: &str,
        payload: HostPayload,
    ) {
        let account = state
            .account
            .get_or_insert_with(|| AccountState::new(&"c".repeat(64)));
        account.records.insert(record_key(RecordKind::Space,id),LocalRecord { record: Record { kind:RecordKind::Space,id:id.into(),version:1,updated_at_ms:1,device_id:"d".repeat(32),deleted:false,payload:serde_json::json!({"schema":1,"name":name,"slug":"fixture","created_at_ms":1}) },seq:0,dirty:false });
        let mut space = SpaceStateV3 {
            selected: true,
            ..Default::default()
        };
        space.records.insert(
            record_key(RecordKind::Host, host_id),
            cached_host(host_id, payload),
        );
        state.spaces.insert(id.into(), space);
    }
    #[test]
    fn records_tray_uses_ids_and_labels_duplicate_aliases_by_scope() {
        let mut state = record_state();
        add_local(&mut state, RECORD_ID, host_payload("web"));
        add_space(
            &mut state,
            &"a".repeat(64),
            "Team",
            SECOND_ID,
            host_payload("web"),
        );
        let items = tray_record_items(&state).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, format!("record-connect:{RECORD_ID}"));
        assert_eq!(items[1].id, format!("record-connect:{SECOND_ID}"));
        assert!(items[0].label.contains("Local"));
        assert!(items[1].label.contains("Team"));
        assert!(items[1].label.contains("aaaaaaaa"));
        assert!(items.iter().all(|i| i.enabled));
    }
    #[test]
    fn records_tray_disables_missing_keys_review_and_blocked_jump_routes() {
        let mut state = record_state();
        let mut key = host_payload("bastion");
        key.auth = AuthKind::Key;
        key.key_id = Some("e".repeat(32));
        add_local(&mut state, SECOND_ID, key);
        let mut host = host_payload("web");
        host.jump = vec![SECOND_ID.into()];
        add_local(&mut state, RECORD_ID, host);
        let items = tray_record_items(&state).unwrap();
        assert!(items.iter().all(|i| !i.enabled));
        assert!(items.iter().any(|i| i.label.contains("Needs key")));
        assert!(record_connect_id(&state, RECORD_ID).is_err());
    }
    #[test]
    fn records_tray_disables_imported_review_without_reading_original_file() {
        let mut state = record_state();
        let mut host = host_payload("web");
        host.imported = Some(crate::sync::records_v3::ImportedSettings {
            source: "/never/read/config".into(),
            at_ms: 1,
            unsupported: vec![crate::sync::records_v3::UnsupportedSetting {
                keyword: "ProxyCommand".into(),
                value: "unsupported".into(),
                requires_review: true,
            }],
        });
        add_local(&mut state, RECORD_ID, host);
        let items = tray_record_items(&state).unwrap();
        assert_eq!(items.len(), 1);
        assert!(!items[0].enabled);
        assert!(items[0].label.contains("Needs review"));
        assert!(record_connect_id(&state, RECORD_ID).is_err());
    }
    #[test]
    fn records_tray_preserves_capacity_and_ignores_unselected_or_missing_spaces() {
        let mut state = record_state();
        for id in 1..=40 {
            add_local(
                &mut state,
                &format!("{id:016x}"),
                host_payload(&format!("host{id}")),
            );
        }
        let items = tray_record_items(&state).unwrap();
        assert_eq!(items.len(), 25);
        assert_eq!(items[24].id, "record-connect:0000000000000019");
        let mut state = record_state();
        add_space(
            &mut state,
            &"a".repeat(64),
            "Hidden",
            RECORD_ID,
            host_payload("hidden"),
        );
        state.spaces.get_mut(&"a".repeat(64)).unwrap().selected = false;
        assert!(tray_record_items(&state).unwrap().is_empty());
        state.spaces.get_mut(&"a".repeat(64)).unwrap().selected = true;
        state.spaces.get_mut(&"a".repeat(64)).unwrap().missing = true;
        assert!(tray_record_items(&state).unwrap().is_empty());
    }
    #[test]
    fn records_tray_collapses_conflicting_global_id_into_one_disabled_menu_item() {
        let mut state = record_state();
        add_local(&mut state, RECORD_ID, host_payload("local"));
        add_space(
            &mut state,
            &"a".repeat(64),
            "Team",
            RECORD_ID,
            host_payload("shared"),
        );
        let items = tray_record_items(&state).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, format!("record-connect:{RECORD_ID}"));
        assert!(!items[0].enabled);
        assert!(items[0].label.contains("Conflicting host ID"));
        assert!(record_connect_id(&state, RECORD_ID).is_err());
    }
    #[test]
    fn records_tray_contexts_remain_distinct_and_cannot_spoof_menu_lines() {
        let mut state = record_state();
        add_space(
            &mut state,
            &"a".repeat(64),
            "Team\u{202e}\n",
            RECORD_ID,
            host_payload("web"),
        );
        add_space(
            &mut state,
            &"b".repeat(64),
            "Team\u{202e}\n",
            SECOND_ID,
            host_payload("web"),
        );
        let items = tray_record_items(&state).unwrap();
        assert_ne!(items[0].label, items[1].label);
        assert!(items.iter().all(|i| !i.label.contains(['\n', '\u{202e}'])));
    }
    #[test]
    fn legacy_tray_guard_refuses_records_blocked_paused_and_dual_owner() {
        let mut core = SyncCore::default();
        assert!(legacy_tray_allowed(&core));
        core.legacy_paused = true;
        assert!(!legacy_tray_allowed(&core));
        core.legacy_paused = false;
        for format in [RuntimeFormat::Records, RuntimeFormat::Blocked] {
            core.format = format;
            assert!(!legacy_tray_allowed(&core));
        }
        core.format = RuntimeFormat::Legacy;
        core.records = Some(record_state());
        assert!(!legacy_tray_allowed(&core));
        core.records = None;
        core.save_blocked = Some("blocked".into());
        assert!(!legacy_tray_allowed(&core));
    }
    #[test]
    fn record_click_checks_latest_records_mode_and_target_id_without_alias_fallback() {
        let mut state = record_state();
        add_local(&mut state, RECORD_ID, host_payload("web"));
        let mut core = SyncCore {
            format: RuntimeFormat::Records,
            records: Some(state),
            ..Default::default()
        };
        let snapshot = active_record_snapshot(&core).unwrap();
        assert_eq!(record_connect_id(&snapshot, RECORD_ID).unwrap(), RECORD_ID);
        assert!(record_connect_id(&snapshot, "web").is_err());
        assert!(record_connect_id(&snapshot, SECOND_ID).is_err());
        core.records.as_mut().unwrap().local.hosts.clear();
        assert!(record_connect_id(&active_record_snapshot(&core).unwrap(), RECORD_ID).is_err());
        assert_eq!(snapshot.local.hosts.len(), 1);
        core.format = RuntimeFormat::Legacy;
        assert!(active_record_snapshot(&core).is_err());
        core.format = RuntimeFormat::Blocked;
        assert!(active_record_snapshot(&core).is_err());
    }
    #[test]
    fn records_tray_checks_nonfirst_jump_readiness_too() {
        let mut state = record_state();
        add_local(&mut state, SECOND_ID, host_payload("first"));
        let third = "0000000000000003";
        let mut key = host_payload("second");
        key.auth = AuthKind::Key;
        key.key_id = Some("e".repeat(32));
        add_local(&mut state, third, key);
        let mut host = host_payload("web");
        host.jump = vec![SECOND_ID.into(), third.into()];
        add_local(&mut state, RECORD_ID, host);
        let items = tray_record_items(&state).unwrap();
        assert!(
            !items
                .iter()
                .find(|i| i.id == format!("record-connect:{RECORD_ID}"))
                .unwrap()
                .enabled
        );
        assert!(
            items
                .iter()
                .find(|i| i.id == format!("record-connect:{SECOND_ID}"))
                .unwrap()
                .enabled
        );
        assert!(record_connect_id(&state, RECORD_ID).is_err());
    }
    #[test]
    fn records_tray_disambiguates_equal_names_and_short_space_prefixes() {
        let mut state = record_state();
        add_space(
            &mut state,
            &"a".repeat(64),
            "Team",
            RECORD_ID,
            host_payload("web"),
        );
        add_space(
            &mut state,
            &format!("aaaaaaaa{}", "b".repeat(56)),
            "Team",
            SECOND_ID,
            host_payload("web"),
        );
        let items = tray_record_items(&state).unwrap();
        assert_ne!(items[0].label, items[1].label);
        assert!(items[0].label.contains(RECORD_ID));
        assert!(items[1].label.contains(SECOND_ID));
    }
}
