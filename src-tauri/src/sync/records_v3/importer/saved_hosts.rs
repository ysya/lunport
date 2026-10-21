//! Recover public host and Group settings through the normal reviewed, resumable file import.
//! No relay, credential adapter, Vault, private-key source or old account is imported.
use super::*;
use crate::sync::{
    record::{record_key, Record, RecordKind},
    record_repository as repo,
    records_v3::*,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs::File, io::Read};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSettings {
    format: String,
    version: u32,
    hosts: Vec<HostRecord>,
    #[serde(default)]
    groups: Vec<GroupRecord>,
}

fn invalid(path: &Path, reason: &str) -> ImportError {
    ImportError::InvalidSource {
        location: SourceLocation {
            path: path.into(),
            line: 1,
        },
        reason: reason.into(),
    }
}

pub(super) fn preview(path: &Path, options: &ImportOptions) -> Result<ImportPreview, ImportError> {
    if !path.is_absolute() || !options.home.is_absolute() {
        return Err(invalid(path, "source and home must be absolute paths"));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| invalid(path, "cannot open saved hosts"))?;
    let file = File::open(&canonical).map_err(|_| invalid(path, "cannot open saved hosts"))?;
    if !file
        .metadata()
        .map_err(|_| invalid(path, "cannot inspect saved hosts"))?
        .is_file()
    {
        return Err(invalid(path, "saved hosts must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid(path, "cannot read saved hosts"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ImportError::Limit {
            location: SourceLocation {
                path: path.into(),
                line: 1,
            },
            limit: "file bytes",
        });
    }
    if bytes
        .windows(b"PRIVATE KEY-----".len())
        .any(|b| b == b"PRIVATE KEY-----")
    {
        return Err(ImportError::PrivateKeyContent {
            location: SourceLocation {
                path: path.into(),
                line: 1,
            },
        });
    }
    let provenance = vec![SourceFile {
        path: path.into(),
        canonical_path: canonical,
        digest: source::hex(&Sha256::digest(&bytes)),
        bytes: bytes.len(),
    }];
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| invalid(path, "expected a Lunport host export or saved workspace"))?;
    if value.get("format").is_some() {
        let settings: HostSettings = serde_json::from_value(value)
            .map_err(|_| invalid(path, "invalid Lunport host export"))?;
        if settings.format != "lunport-host-settings" || ![1, 2].contains(&settings.version) {
            return Err(invalid(path, "unsupported Lunport host export"));
        }
        if settings
            .hosts
            .iter()
            .any(|host| host.scope != HostScope::Local)
            || settings
                .groups
                .iter()
                .any(|group| group.scope != HostScope::Local)
            || settings.version == 1
                && (!settings.groups.is_empty()
                    || settings.hosts.iter().any(|host| {
                        host.payload.group_id.is_some() || !host.payload.inherit.is_empty()
                    }))
        {
            return Err(invalid(
                path,
                "exported settings must use local relationships",
            ));
        }
        validate_settings(&settings.hosts, &settings.groups, path)?;
        return from_records(settings.hosts, settings.groups, provenance, options, path);
    }
    let state: SyncStateV3 = serde_json::from_value(value)
        .map_err(|_| invalid(path, "expected a supported Lunport saved workspace"))?;
    validate_state(&state)
        .map_err(|_| invalid(path, "saved workspace is invalid or needs a newer version"))?;
    from_state(state, provenance, options, path)
}

/// Serialize only reviewed public host and Group settings, never a workspace or its authority.
pub(crate) fn export_state(state: &SyncStateV3) -> Result<(String, usize, usize), ImportError> {
    let home = std::env::temp_dir();
    let path = home.join("lunport-hosts.json");
    export_preview(
        from_state(state.clone(), vec![], &ImportOptions::new(home), &path)?,
        &path,
    )
}

pub(crate) fn export_workspace(
    path: &Path,
    home: PathBuf,
) -> Result<(String, usize, usize), ImportError> {
    export_preview(preview(path, &ImportOptions::new(home))?, path)
}

fn export_preview(
    mut preview: ImportPreview,
    path: &Path,
) -> Result<(String, usize, usize), ImportError> {
    if preview.candidates.is_empty() && preview.groups.is_empty() {
        return Err(invalid(
            path,
            "This workspace has no saved hosts or Groups to export.",
        ));
    }
    for host in &mut preview.candidates {
        // Old import paths and unsupported commands are not portable connection settings.
        host.payload.imported = None;
    }
    let count = preview.candidates.len();
    let groups = preview.groups.len();
    let json = serde_json::to_string_pretty(&HostSettings {
        format: "lunport-host-settings".into(),
        version: 2,
        hosts: preview.candidates,
        groups: preview.groups,
    })
    .map_err(|_| invalid(path, "cannot serialize host settings"))?;
    if json.len() > MAX_FILE_BYTES {
        return Err(invalid(
            path,
            "host export exceeds the supported import size",
        ));
    }
    Ok((json, count, groups))
}

fn from_state(
    mut state: SyncStateV3,
    provenance: Vec<SourceFile>,
    options: &ImportOptions,
    path: &Path,
) -> Result<ImportPreview, ImportError> {
    // An unavailable/retired relay does not delete its locally cached host rows.
    // This changes only the owned read snapshot, never the source or its authority.
    for space in state.spaces.values_mut() {
        space.selected = true;
        space.missing = false;
    }
    let groups = crate::sync::record_groups::list_groups(&state)
        .map_err(|_| invalid(path, "saved Groups need review"))?;
    if groups.iter().any(|view| view.group_error.is_some()) {
        return Err(invalid(path, "saved Group hierarchy needs review"));
    }
    let views = repo::list_hosts(&state)
        .map_err(|_| invalid(path, "saved host relationships need review"))?;
    let mut hosts = Vec::new();
    for view in views {
        if view.group_error.is_some() {
            return Err(invalid(path, "saved Group inheritance needs review"));
        }
        hosts.push(HostRecord {
            id: view.host.id,
            scope: view.host.scope,
            payload: view.effective_payload,
        });
    }
    from_records(
        hosts,
        groups.into_iter().map(|view| view.group).collect(),
        provenance,
        options,
        path,
    )
}

fn from_records(
    hosts: Vec<HostRecord>,
    groups: Vec<GroupRecord>,
    provenance: Vec<SourceFile>,
    options: &ImportOptions,
    path: &Path,
) -> Result<ImportPreview, ImportError> {
    let mut result = ImportPreview {
        source_digest: source::snapshot_digest(&provenance, options),
        provenance,
        ..Default::default()
    };
    let mut used = options.reserved_host_ids.clone();
    for host in &hosts {
        if result.host_ids.contains_key(&host.id) {
            return Err(invalid(
                path,
                "saved Group inheritance or host identities need review",
            ));
        }
        let id = if let Some(id) = options.host_ids.get(&host.id) {
            id.clone()
        } else {
            let mut value = [0u8; 8];
            getrandom::fill(&mut value)
                .map_err(|_| invalid(path, "cannot create recovered host identity"))?;
            source::hex(&value)
        };
        if !is_host_id(&id) || !used.insert(id.clone()) {
            return Err(invalid(path, "recovered host identity is occupied"));
        }
        result.host_ids.insert(host.id.clone(), id);
    }
    let mut group_ids = std::collections::BTreeMap::new();
    let mut used_groups = BTreeSet::new();
    for group in &groups {
        let source = serde_json::to_string(&(&group.scope, &group.id))
            .map_err(|_| invalid(path, "cannot identify saved Group"))?;
        if group_ids.contains_key(&source) {
            return Err(invalid(path, "duplicate saved Group identity"));
        }
        let id = if let Some(id) = options.group_ids.get(&source) {
            id.clone()
        } else {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes)
                .map_err(|_| invalid(path, "cannot create recovered Group identity"))?;
            source::hex(&bytes)
        };
        if !is_host_id(&id) || !used_groups.insert(id.clone()) {
            return Err(invalid(path, "recovered Group identity is occupied"));
        }
        group_ids.insert(source, id);
    }
    result.group_ids = group_ids;
    let map_group = |scope: &HostScope, id: &str| -> Result<String, ImportError> {
        let source = serde_json::to_string(&(scope, id))
            .map_err(|_| invalid(path, "cannot identify saved Group"))?;
        result
            .group_ids
            .get(&source)
            .cloned()
            .ok_or_else(|| invalid(path, "a saved Group is missing"))
    };
    let map_jumps = |jumps: &mut Vec<String>| -> Result<(), ImportError> {
        for jump in jumps {
            *jump = result
                .host_ids
                .get(jump)
                .ok_or_else(|| invalid(path, "a saved jump host is missing"))?
                .clone();
        }
        Ok(())
    };
    let mut names = BTreeSet::new();
    for group in groups {
        let id = map_group(&group.scope, &group.id)?;
        let mut payload = group.payload;
        payload.parent_id = payload
            .parent_id
            .as_deref()
            .map(|parent| map_group(&group.scope, parent))
            .transpose()?;
        if !names.insert((payload.parent_id.clone(), payload.name.clone())) {
            // Independent source scopes can have same-named root Groups.
            payload.name = format!(
                "{}-{}",
                payload.name.chars().take(111).collect::<String>(),
                id
            );
            if !names.insert((payload.parent_id.clone(), payload.name.clone())) {
                return Err(invalid(path, "recovered Group names need review"));
            }
        }
        if let Some(jumps) = &mut payload.defaults.jump {
            map_jumps(jumps)?;
        }
        if let Some(auth) = &mut payload.defaults.authentication {
            auth.key_id =
                (auth.auth == AuthKind::Key).then(|| missing_key(&result.source_digest, &id));
        }
        result.groups.push(GroupRecord {
            id,
            scope: HostScope::Local,
            payload,
        });
    }
    let mut aliases = BTreeSet::new();
    for host in hosts {
        let mut payload = host.payload;
        payload.group_id = payload
            .group_id
            .as_deref()
            .map(|id| map_group(&host.scope, id))
            .transpose()?;
        payload.schema = if payload.group_id.is_some() || !payload.inherit.is_empty() {
            GROUPED_HOST_SCHEMA
        } else {
            HOST_SCHEMA
        };
        payload.host_key = None;
        let id = result.host_ids[&host.id].clone();
        if !aliases.insert(payload.alias.clone()) {
            payload.alias = format!("{}-{}", payload.alias, id);
            if !aliases.insert(payload.alias.clone()) {
                return Err(invalid(path, "recovered aliases need review"));
            }
        }
        map_jumps(&mut payload.jump)?;
        payload.key_id =
            (payload.auth == AuthKind::Key).then(|| missing_key(&result.source_digest, &id));
        result.candidates.push(HostRecord {
            id,
            scope: HostScope::Local,
            payload,
        });
    }
    validate_settings(&result.candidates, &result.groups, path)?;
    if !result.candidates.is_empty() {
        result.warnings.push(ImportWarning { location: SourceLocation { path: path.into(), line: 1 },
            keyword: "Saved hosts".into(), reason: "Host and Group settings only. Group hierarchy, defaults and host membership are retained. Assign new SSH keys and confirm server fingerprints before connecting.".into(), blocks_connection: false, alias: None });
    }
    Ok(result)
}

fn missing_key(source: &str, id: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"lunport-recovered-host-needs-new-key-v1");
    hash.update(source.as_bytes());
    hash.update(id.as_bytes());
    source::hex(&hash.finalize())[..32].into()
}

/// Validate a self-contained public transfer with the same Group and route rules as the library.
pub(crate) fn validate_settings(
    hosts: &[HostRecord],
    groups: &[GroupRecord],
    path: &Path,
) -> Result<(), ImportError> {
    let mut state = SyncStateV3 {
        version: GROUP_STATE_VERSION,
        device_id: "0".repeat(32),
        device_name: String::new(),
        relay_url: String::new(),
        account: None,
        spaces: Default::default(),
        local: Default::default(),
        rotation: None,
        relay_features: None,
        legacy_v1_backup: None,
        phrase_cleanup_pending: false,
        migration_gate: None,
        shared_writes_blocked: false,
        pending_account: None,
        notices: vec![],
        last_sync_ms: None,
        last_error: None,
    };
    for group in groups {
        validate_group(group).map_err(ImportError::InvalidRecords)?;
        if group.scope != HostScope::Local
            || state
                .local
                .groups
                .insert(
                    record_key(RecordKind::Group, &group.id),
                    repo::cached(
                        Record {
                            kind: RecordKind::Group,
                            id: group.id.clone(),
                            version: 1,
                            updated_at_ms: 0,
                            device_id: state.device_id.clone(),
                            deleted: false,
                            payload: serde_json::to_value(&group.payload)
                                .map_err(|_| invalid(path, "invalid Group settings"))?,
                        },
                        0,
                        &HostScope::Local,
                    ),
                )
                .is_some()
        {
            return Err(invalid(path, "duplicate or non-local Group identity"));
        }
    }
    validate_hosts(hosts).map_err(ImportError::InvalidRecords)?;
    for host in hosts {
        if host.scope != HostScope::Local {
            return Err(invalid(path, "non-local host settings"));
        }
        state.local.hosts.insert(
            record_key(RecordKind::Host, &host.id),
            repo::cached(
                Record {
                    kind: RecordKind::Host,
                    id: host.id.clone(),
                    version: 1,
                    updated_at_ms: 0,
                    device_id: state.device_id.clone(),
                    deleted: false,
                    payload: serde_json::to_value(&host.payload)
                        .map_err(|_| invalid(path, "invalid host settings"))?,
                },
                0,
                &HostScope::Local,
            ),
        );
    }
    crate::sync::record_groups::validate_groups(&state, &HostScope::Local)
        .map_err(|_| invalid(path, "Group hierarchy or names need review"))?;
    // This also checks inherited jump routes, including defaults on currently empty Groups.
    for group in groups {
        if group.payload.defaults.jump.as_ref().is_some_and(|jumps| {
            jumps
                .iter()
                .any(|id| !hosts.iter().any(|host| &host.id == id))
        }) {
            return Err(invalid(path, "a Group jump host is missing"));
        }
    }
    let views =
        repo::list_hosts(&state).map_err(|_| invalid(path, "invalid host relationships"))?;
    if views.iter().any(|view| view.group_error.is_some()) {
        return Err(invalid(path, "invalid Group inheritance"));
    }
    let effective: Vec<_> = views
        .into_iter()
        .map(|view| HostRecord {
            payload: view.effective_payload,
            ..view.host
        })
        .collect();
    validate_hosts(&effective).map_err(ImportError::InvalidRecords)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn state() -> SyncStateV3 {
        serde_json::from_value(json!({"version":3,"device_id":"d".repeat(32),"device_name":"old","relay_url":"https://retired.example","local":{},"last_sync_ms":null,"last_error":null})).unwrap()
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, ImportOptions) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let mut old = state();
        let group: GroupPayload = serde_json::from_value(
            json!({"schema":1,"name":"Old group","defaults":{"port":2222,"user":"ops"}}),
        )
        .unwrap();
        old = crate::sync::record_groups::create_group(
            &old,
            "aaaaaaaaaaaaaaaa",
            HostScope::Local,
            group,
            true,
            1,
        )
        .unwrap();
        for (id, alias, jump) in [
            ("1111111111111111", "jump", vec![]),
            ("2222222222222222", "web", vec!["1111111111111111"]),
        ] {
            let payload:HostPayload=serde_json::from_value(json!({"schema":3,"alias":alias,"hostname":format!("{alias}.example"),"auth":"key","key_id":"e".repeat(32),"group_id":"aaaaaaaaaaaaaaaa","inherit":["port","user"],"jump":jump,"tags":["saved"],"notes":"keep my host notes"})).unwrap();
            old = repo::create_host(&old, id, HostScope::Local, payload, 2).unwrap();
        }
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let options = ImportOptions::new(dir.path().to_path_buf());
        (dir, path, options)
    }
    #[test]
    fn saved_hosts_preserve_groups_relink_jumps_and_preserve_settings_without_credentials() {
        let (dir, path, options) = fixture();
        let original = std::fs::read(&path).unwrap();
        // A private container beside the source must never be opened.
        std::fs::write(dir.path().join("vault.json"), b"unreadable private source").unwrap();
        let preview = preview_file(&path, &options).unwrap();
        assert_eq!(preview.candidates.len(), 2);
        assert!(preview.key_references.is_empty());
        assert_eq!(preview.groups.len(), 1);
        assert_eq!(preview.groups[0].payload.name, "Old group");
        let jump = &preview.candidates[0];
        let web = &preview.candidates[1];
        assert_eq!(web.payload.jump, vec![jump.id.clone()]);
        for host in &preview.candidates {
            assert_eq!(host.scope, HostScope::Local);
            assert_eq!(host.payload.port, 2222);
            assert_eq!(host.payload.user, "ops");
            assert_eq!(host.payload.notes, "keep my host notes");
            assert_eq!(host.payload.tags, vec!["saved"]);
            assert_eq!(
                host.payload.group_id.as_deref(),
                Some(preview.groups[0].id.as_str())
            );
            assert_eq!(
                host.payload.inherit,
                vec![InheritedField::Port, InheritedField::User]
            );
            assert!(host.payload.host_key.is_none());
            assert_ne!(
                host.payload.key_id.as_deref(),
                Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            );
        }
        let mut repeat = options;
        repeat.host_ids = preview.host_ids.clone();
        repeat.group_ids = preview.group_ids.clone();
        assert_eq!(preview_file(&path, &repeat).unwrap(), preview);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            std::fs::read(dir.path().join("vault.json")).unwrap(),
            b"unreadable private source"
        );
    }
    #[test]
    fn host_export_roundtrip_preserves_routes_and_settings_but_drops_old_identity() {
        let (dir, path, options) = fixture();
        let mut old: SyncStateV3 = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for (id, name) in [
            ("bbbbbbbbbbbbbbbb", "Nested"),
            ("cccccccccccccccc", "Empty"),
        ] {
            let payload: GroupPayload = serde_json::from_value(
                json!({"schema":1,"name":name,"parent_id":"aaaaaaaaaaaaaaaa"}),
            )
            .unwrap();
            old = crate::sync::record_groups::create_group(
                &old,
                id,
                HostScope::Local,
                payload,
                true,
                3,
            )
            .unwrap();
        }
        old.local
            .groups
            .get_mut("group:bbbbbbbbbbbbbbbb")
            .unwrap()
            .record
            .payload["defaults"] = json!({"jump":["1111111111111111"],"authentication":{"auth":"key","key_id":"e".repeat(32)}});
        old.local
            .hosts
            .get_mut("host:2222222222222222")
            .unwrap()
            .record
            .payload["group_id"] = json!("bbbbbbbbbbbbbbbb");
        old.local
            .hosts
            .get_mut("host:2222222222222222")
            .unwrap()
            .record
            .payload["inherit"] = json!(["port", "user", "jump", "authentication"]);
        old.legacy_v1_backup = Some("PRIVATE_BACKUP_SENTINEL".into());
        for row in old.local.hosts.values_mut() {
            row.record.payload["imported"] = json!({"source":"PRIVATE_PATH_SENTINEL","at_ms":1,"unsupported":[{"keyword":"ProxyCommand","value":"PRIVATE_COMMAND_SENTINEL","requires_review":true}]});
        }
        let before = old.clone();
        let (json, count, group_count) = export_state(&old).unwrap();
        assert_eq!(count, 2);
        assert_eq!(group_count, 3);
        assert_eq!(old, before);
        for excluded in [
            "PRIVATE_",
            "retired.example",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "device_id",
            "account",
            "vault",
            "host_key\": {",
        ] {
            assert!(
                !json.contains(excluded),
                "unexpected export content: {excluded}"
            );
        }
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["version"], 2);
        assert_eq!(value["groups"][0]["payload"]["name"], "Old group");
        assert_eq!(value["format"], "lunport-host-settings");
        let export = dir.path().join("lunport-hosts.json");
        std::fs::write(&export, &json).unwrap();
        let recovered = preview_file(&export, &options).unwrap();
        assert_eq!(recovered.candidates.len(), 2);
        assert!(recovered.key_references.is_empty());
        assert_eq!(recovered.groups.len(), 3);
        let root = recovered
            .groups
            .iter()
            .find(|g| g.payload.name == "Old group")
            .unwrap();
        let nested = recovered
            .groups
            .iter()
            .find(|g| g.payload.name == "Nested")
            .unwrap();
        let empty = recovered
            .groups
            .iter()
            .find(|g| g.payload.name == "Empty")
            .unwrap();
        assert_eq!(root.payload.defaults.port, Some(2222));
        assert_eq!(nested.payload.parent_id.as_deref(), Some(root.id.as_str()));
        assert_eq!(empty.payload.parent_id.as_deref(), Some(root.id.as_str()));
        assert_ne!(
            nested
                .payload
                .defaults
                .authentication
                .as_ref()
                .unwrap()
                .key_id
                .as_deref(),
            Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
        );
        let jump = recovered
            .candidates
            .iter()
            .find(|h| h.payload.alias == "jump")
            .unwrap();
        let web = recovered
            .candidates
            .iter()
            .find(|h| h.payload.alias == "web")
            .unwrap();
        assert_eq!(web.payload.jump, vec![jump.id.clone()]);
        assert_eq!(
            nested.payload.defaults.jump.as_ref().unwrap(),
            &vec![jump.id.clone()]
        );
        assert_eq!(web.payload.group_id.as_deref(), Some(nested.id.as_str()));
        assert_eq!(jump.payload.group_id.as_deref(), Some(root.id.as_str()));
        for host in recovered.candidates {
            assert_eq!(host.payload.port, 2222);
            assert_eq!(host.payload.user, "ops");
            assert_eq!(host.payload.notes, "keep my host notes");
            assert_eq!(host.payload.tags, vec!["saved"]);
            assert!(host.payload.group_id.is_some());
            assert!(!host.payload.inherit.is_empty());
            assert!(host.payload.imported.is_none());
            assert!(host.payload.host_key.is_none());
        }
    }

    #[test]
    fn export_refuses_empty_snapshots_and_unknown_transfer_versions() {
        assert!(export_state(&state()).is_err());
        let (_dir, path, options) = fixture();
        let old: SyncStateV3 = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let (json, _, _) = export_state(&old).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["version"] = json!(99);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(preview_file(&path, &options).is_err());
    }
    #[test]
    fn source_changes_invalidate_the_confirmation_preview_and_future_or_private_files_fail() {
        let (_dir, path, mut options) = fixture();
        let first = preview_file(&path, &options).unwrap();
        options.host_ids = first.host_ids.clone();
        options.group_ids = first.group_ids.clone();
        let mut old: SyncStateV3 = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        old.local.hosts.values_mut().next().unwrap().record.payload["notes"] = json!("changed");
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        assert_ne!(preview_file(&path, &options).unwrap(), first);
        old.version = 999;
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(preview_file(&path, &options).is_err());
        std::fs::write(&path, b"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap();
        assert!(matches!(
            preview_file(&path, &options),
            Err(ImportError::PrivateKeyContent { .. })
        ));
    }
    #[test]
    fn old_host_only_exports_still_import_and_empty_groups_can_transfer() {
        let (_dir, path, options) = fixture();
        let mut old: SyncStateV3 = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let (json, _, _) = export_state(&old).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["version"] = json!(1);
        value.as_object_mut().unwrap().remove("groups");
        for host in value["hosts"].as_array_mut().unwrap() {
            host["payload"]["schema"] = json!(HOST_SCHEMA);
            host["payload"]["group_id"] = serde_json::Value::Null;
            host["payload"]["inherit"] = json!([]);
        }
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let legacy = preview_file(&path, &options).unwrap();
        assert_eq!(legacy.candidates.len(), 2);
        assert!(legacy.groups.is_empty());
        assert_eq!(legacy.candidates[0].payload.port, 2222);
        old.local.hosts.clear();
        let (json, hosts, groups) = export_state(&old).unwrap();
        assert_eq!((hosts, groups), (0, 1));
        std::fs::write(&path, json).unwrap();
        let empty = preview_file(&path, &options).unwrap();
        assert!(empty.candidates.is_empty());
        assert_eq!(empty.groups[0].payload.name, "Old group");
    }

    #[test]
    fn malformed_group_relationships_are_rejected_before_confirmation() {
        let (_dir, path, options) = fixture();
        let old: SyncStateV3 = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let (json, _, _) = export_state(&old).unwrap();
        let original: serde_json::Value = serde_json::from_str(&json).unwrap();
        for kind in ["cycle", "missing_group", "missing_jump"] {
            let mut value = original.clone();
            match kind {
                "cycle" => {
                    value["groups"][0]["payload"]["parent_id"] = value["groups"][0]["id"].clone()
                }
                "missing_group" => value["hosts"][0]["payload"]["group_id"] = json!("f".repeat(16)),
                _ => value["groups"][0]["payload"]["defaults"]["jump"] = json!(["f".repeat(16)]),
            }
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(preview_file(&path, &options).is_err(), "accepted {kind}");
        }
    }
}
