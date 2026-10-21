//! Recover public host settings through the normal reviewed, resumable file import.
//! No relay, credential adapter, Vault, private-key source or old account is imported.
use super::*;
use crate::sync::{record_repository as repo, records_v3::*};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs::File, io::Read};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSettings {
    format: String,
    version: u32,
    hosts: Vec<HostRecord>,
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
        if settings.format != "lunport-host-settings" || settings.version != 1 {
            return Err(invalid(path, "unsupported Lunport host export"));
        }
        validate_hosts(&settings.hosts)
            .map_err(|_| invalid(path, "exported host relationships need review"))?;
        if settings.hosts.iter().any(|host| {
            host.scope != HostScope::Local
                || host.payload.group_id.is_some()
                || !host.payload.inherit.is_empty()
        }) {
            return Err(invalid(
                path,
                "exported hosts must contain resolved local settings",
            ));
        }
        return from_hosts(settings.hosts, provenance, options, path);
    }
    let state: SyncStateV3 = serde_json::from_value(value)
        .map_err(|_| invalid(path, "expected a supported Lunport saved workspace"))?;
    validate_state(&state)
        .map_err(|_| invalid(path, "saved workspace is invalid or needs a newer version"))?;
    from_state(state, provenance, options, path)
}

/// Serialize only reviewed public host settings, never a workspace or its authority.
pub(crate) fn export_state(state: &SyncStateV3) -> Result<(String, usize), ImportError> {
    let home = std::env::temp_dir();
    let path = home.join("lunport-hosts.json");
    export_preview(
        from_state(state.clone(), vec![], &ImportOptions::new(home), &path)?,
        &path,
    )
}

pub(crate) fn export_workspace(path: &Path, home: PathBuf) -> Result<(String, usize), ImportError> {
    export_preview(preview(path, &ImportOptions::new(home))?, path)
}

fn export_preview(mut preview: ImportPreview, path: &Path) -> Result<(String, usize), ImportError> {
    if preview.candidates.is_empty() {
        return Err(invalid(
            path,
            "This workspace has no saved hosts to export.",
        ));
    }
    for host in &mut preview.candidates {
        // Old import paths and unsupported commands are not portable connection settings.
        host.payload.imported = None;
    }
    let count = preview.candidates.len();
    let json = serde_json::to_string_pretty(&HostSettings {
        format: "lunport-host-settings".into(),
        version: 1,
        hosts: preview.candidates,
    })
    .map_err(|_| invalid(path, "cannot serialize host settings"))?;
    if json.len() > MAX_FILE_BYTES {
        return Err(invalid(
            path,
            "host export exceeds the supported import size",
        ));
    }
    Ok((json, count))
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
    let views = repo::list_hosts(&state)
        .map_err(|_| invalid(path, "saved host relationships need review"))?;
    let mut hosts = Vec::new();
    for view in views {
        if view.group_error.is_some() {
            return Err(invalid(path, "saved Group inheritance needs review"));
        }
        hosts.push(HostRecord {
            id: view.host.id,
            scope: HostScope::Local,
            payload: view.effective_payload,
        });
    }
    from_hosts(hosts, provenance, options, path)
}

fn from_hosts(
    hosts: Vec<HostRecord>,
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
    let mut aliases = BTreeSet::new();
    for host in hosts {
        let mut payload = host.payload;
        payload.schema = HOST_SCHEMA;
        payload.group_id = None;
        payload.inherit.clear();
        payload.host_key = None;
        let id = result.host_ids[&host.id].clone();
        if !aliases.insert(payload.alias.clone()) {
            payload.alias = format!("{}-{}", payload.alias, id);
            if !aliases.insert(payload.alias.clone()) {
                return Err(invalid(path, "recovered aliases need review"));
            }
        }
        for jump in &mut payload.jump {
            *jump = result
                .host_ids
                .get(jump)
                .ok_or_else(|| invalid(path, "a saved jump host is missing"))?
                .clone();
        }
        // Retain key authentication as NeedsKey, without binding to an old or current key.
        // A stable absent reference also makes the second preview identical at confirmation.
        payload.key_id = if payload.auth == AuthKind::Key {
            let mut hash = Sha256::new();
            hash.update(b"lunport-recovered-host-needs-new-key-v1");
            hash.update(result.source_digest.as_bytes());
            hash.update(id.as_bytes());
            Some(source::hex(&hash.finalize())[..32].into())
        } else {
            None
        };
        result.candidates.push(HostRecord {
            id,
            scope: HostScope::Local,
            payload,
        });
    }
    validate_hosts(&result.candidates)
        .map_err(|_| invalid(path, "saved aliases or jump routes need review"))?;
    if !result.candidates.is_empty() {
        result.warnings.push(ImportWarning { location: SourceLocation { path: path.into(), line: 1 },
            keyword: "Saved hosts".into(), reason: "Host settings only. Group defaults are applied to each host. Assign new SSH keys and confirm server fingerprints before connecting.".into(), blocks_connection: false, alias: None });
    }
    Ok(result)
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
    fn saved_hosts_flatten_groups_relink_jumps_and_preserve_settings_without_credentials() {
        let (dir, path, options) = fixture();
        let original = std::fs::read(&path).unwrap();
        // A private container beside the source must never be opened.
        std::fs::write(dir.path().join("vault.json"), b"unreadable private source").unwrap();
        let preview = preview_file(&path, &options).unwrap();
        assert_eq!(preview.candidates.len(), 2);
        assert!(preview.key_references.is_empty());
        let jump = &preview.candidates[0];
        let web = &preview.candidates[1];
        assert_eq!(web.payload.jump, vec![jump.id.clone()]);
        for host in &preview.candidates {
            assert_eq!(host.scope, HostScope::Local);
            assert_eq!(host.payload.port, 2222);
            assert_eq!(host.payload.user, "ops");
            assert_eq!(host.payload.notes, "keep my host notes");
            assert_eq!(host.payload.tags, vec!["saved"]);
            assert!(host.payload.group_id.is_none());
            assert!(host.payload.inherit.is_empty());
            assert!(host.payload.host_key.is_none());
            assert_ne!(
                host.payload.key_id.as_deref(),
                Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            );
        }
        let mut repeat = options;
        repeat.host_ids = preview.host_ids.clone();
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
        old.legacy_v1_backup = Some("PRIVATE_BACKUP_SENTINEL".into());
        for row in old.local.hosts.values_mut() {
            row.record.payload["imported"] = json!({"source":"PRIVATE_PATH_SENTINEL","at_ms":1,"unsupported":[{"keyword":"ProxyCommand","value":"PRIVATE_COMMAND_SENTINEL","requires_review":true}]});
        }
        let before = old.clone();
        let (json, count) = export_state(&old).unwrap();
        assert_eq!(count, 2);
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
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["format"], "lunport-host-settings");
        let export = dir.path().join("lunport-hosts.json");
        std::fs::write(&export, &json).unwrap();
        let recovered = preview_file(&export, &options).unwrap();
        assert_eq!(recovered.candidates.len(), 2);
        assert!(recovered.key_references.is_empty());
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
        for host in recovered.candidates {
            assert_eq!(host.payload.port, 2222);
            assert_eq!(host.payload.user, "ops");
            assert_eq!(host.payload.notes, "keep my host notes");
            assert_eq!(host.payload.tags, vec!["saved"]);
            assert!(host.payload.imported.is_none());
            assert!(host.payload.host_key.is_none());
        }
    }

    #[test]
    fn export_refuses_empty_snapshots_and_unknown_transfer_versions() {
        assert!(export_state(&state()).is_err());
        let (_dir, path, options) = fixture();
        let old: SyncStateV3 = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let (json, _) = export_state(&old).unwrap();
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
}
