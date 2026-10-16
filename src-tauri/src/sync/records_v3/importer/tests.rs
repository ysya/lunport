use super::*;
use std::path::PathBuf;

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    source: PathBuf,
}
impl Fixture {
    fn new(text: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let source = home.join(".ssh/config");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, text).unwrap();
        Self {
            _dir: dir,
            home,
            source,
        }
    }
    fn options(&self) -> ImportOptions {
        ImportOptions::new(self.home.clone())
    }
    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.home.join(".ssh").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }
}

#[test]
fn explicit_home_relative_globs_and_quoted_includes_are_loaded_in_lexical_order_without_writes() {
    let original = r#"Include conf/*.cfg "with spaces.cfg"
Host local
"#;
    let f = Fixture::new(&original);
    f.file("conf/b.cfg", "Host b\n");
    f.file("conf/a.cfg", "Host a\n");
    f.file("with spaces.cfg", "Host spaced\n");
    let snapshot = source::load(&f.source, &f.options()).unwrap();
    assert_eq!(snapshot.files.len(), 4);
    assert_eq!(snapshot.files[1].path.file_name().unwrap(), "a.cfg");
    assert_eq!(snapshot.files[2].path.file_name().unwrap(), "b.cfg");
    assert_eq!(std::fs::read_to_string(&f.source).unwrap(), original);
    assert!(!f.home.join("sync-state.json").exists());
    assert!(!f.home.join("vault.json").exists());
}

#[test]
fn include_cycles_and_depth_seventeen_are_errors_with_locations() {
    let f = Fixture::new("Include child\n");
    f.file("child", "Include config\n");
    assert!(
        matches!(source::load(&f.source,&f.options()),Err(ImportError::Cycle{location}) if location.line==1)
    );
    let f = Fixture::new("Include d1\n");
    for i in 1..=17 {
        f.file(&format!("d{i}"), &format!("Include d{}\n", i + 1));
    }
    f.file("d18", "Host final\n");
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Limit { limit: "depth", .. })
    ));
}

#[test]
fn source_file_count_and_capped_byte_limits_are_enforced() {
    let f = Fixture::new("Include many/*\n");
    for i in 0..128 {
        f.file(&format!("many/{i:03}"), "# fixture\n");
    }
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Limit { limit: "files", .. })
    ));
    let f = Fixture::new(&"#".repeat(MAX_FILE_BYTES + 1));
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Limit {
            limit: "file bytes",
            ..
        })
    ));
    let f = Fixture::new("Include big*\n");
    for i in 0..4 {
        f.file(&format!("big{i}"), &"#".repeat(MAX_FILE_BYTES));
    }
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Limit {
            limit: "total bytes",
            ..
        })
    ));
}

#[test]
fn environment_values_are_injected_and_managed_sources_are_excluded() {
    let f = Fixture::new("Include ${CONFIG_CHILD}\nInclude managed\nHost local\n");
    let child = f.file("child", "Host child\n");
    let managed = f.file("managed", "Host synced\n");
    let mut options = f.options();
    options
        .env
        .insert("CONFIG_CHILD".into(), child.to_string_lossy().into_owned());
    options.excluded_sources.insert(managed);
    let snapshot = source::load(&f.source, &options).unwrap();
    assert_eq!(snapshot.files.len(), 2);
    assert_eq!(snapshot.files[1].path, child);
    let f = Fixture::new("Include ${UNSET_EXPLICIT_VAR}\nHost local\n");
    let snapshot = source::load(&f.source, &f.options()).unwrap();
    assert!(snapshot.events[0]
        .issue
        .as_ref()
        .is_some_and(|(_, blocks)| *blocks));
}

#[cfg(unix)]
#[test]
fn symlinks_are_deduplicated_and_symlink_cycles_cannot_bypass_the_stack() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new("Include child alias\n");
    let child = f.file("child", "Host child\n");
    symlink(&child, f.home.join(".ssh/alias")).unwrap();
    let snapshot = source::load(&f.source, &f.options()).unwrap();
    assert_eq!(snapshot.files.len(), 2);
    let f = Fixture::new("Include alias\n");
    symlink(&f.source, f.home.join(".ssh/alias")).unwrap();
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Cycle { .. })
    ));
}

#[test]
fn private_key_sources_are_rejected_without_exposing_contents() {
    let marker = concat!(
        "-----BEGIN ",
        "OPENSSH",
        " PRIVATE KEY-----\n",
        "sensitive-fixture-body"
    );
    let f = Fixture::new(marker);
    let error = source::load(&f.source, &f.options())
        .err()
        .expect("private material rejected");
    assert!(matches!(error, ImportError::PrivateKeyContent { .. }));
    assert!(!format!("{error:?}").contains("sensitive-fixture-body"));
}

fn candidate<'a>(preview: &'a ImportPreview, alias: &str) -> &'a super::super::HostRecord {
    preview
        .candidates
        .iter()
        .find(|h| h.payload.alias == alias)
        .expect("candidate alias")
}

#[test]
fn explicit_aliases_get_first_valid_values_and_wildcard_negation_defaults() {
    let f=Fixture::new("Host web db\n  HostName shared.example.com\n  Port invalid\n  Port 2222\nHost *.internal !db\n  User ignored\nHost * !db\n  User alice\n  Port 22\nHost db\n  User bob\n");
    let mut options = f.options();
    options
        .host_ids
        .insert("web".into(), "0000000000000001".into());
    options
        .host_ids
        .insert("db".into(), "0000000000000002".into());
    let preview = preview_file(&f.source, &options).unwrap();
    assert_eq!(
        preview
            .candidates
            .iter()
            .map(|h| h.payload.alias.as_str())
            .collect::<Vec<_>>(),
        vec!["web", "db"]
    );
    assert_eq!(
        (
            candidate(&preview, "web").payload.port,
            candidate(&preview, "web").payload.user.as_str()
        ),
        (2222, "alice")
    );
    assert_eq!(
        (
            candidate(&preview, "db").payload.port,
            candidate(&preview, "db").payload.user.as_str()
        ),
        (2222, "bob")
    );
    assert_eq!(candidate(&preview, "web").id, "0000000000000001");
    assert!(candidate(&preview, "web")
        .payload
        .imported
        .as_ref()
        .unwrap()
        .unsupported
        .iter()
        .any(|s| s.keyword.eq_ignore_ascii_case("port")
            && s.value == "invalid"
            && s.requires_review));
}

#[test]
fn conditional_include_restores_parent_scope_and_cannot_define_an_inactive_alias() {
    let f = Fixture::new("Host web\n  Include child\n  User outer\nHost db\n  User dbuser\n");
    f.file("child", "Port 2200\nHost other\n  User inner\n");
    let preview = preview_file(&f.source, &f.options()).unwrap();
    assert_eq!(preview.candidates.len(), 2);
    assert_eq!(candidate(&preview, "web").payload.user, "outer");
    assert_eq!(candidate(&preview, "web").payload.port, 2200);
    assert_eq!(candidate(&preview, "db").payload.user, "dbuser");
    assert_eq!(candidate(&preview, "db").payload.port, 22);
    assert!(!preview
        .candidates
        .iter()
        .any(|h| h.payload.alias == "other"));
}

#[test]
fn execution_directives_and_match_are_preserved_but_never_run() {
    let f = Fixture::new("");
    let marker = f.home.join("must-not-exist");
    std::fs::write(&f.source,format!("Host web\n  ProxyCommand touch {}\n  LocalCommand touch {}\n  KnownHostsCommand touch {}\n  HostName %h\nMatch exec touch {}\n  User changed\n",marker.display(),marker.display(),marker.display(),marker.display())).unwrap();
    let before = std::fs::read(&f.source).unwrap();
    let preview = preview_file(&f.source, &f.options()).unwrap();
    let h = candidate(&preview, "web");
    let unsupported = &h.payload.imported.as_ref().unwrap().unsupported;
    for keyword in [
        "ProxyCommand",
        "LocalCommand",
        "KnownHostsCommand",
        "HostName",
        "Match",
    ] {
        assert!(unsupported
            .iter()
            .any(|s| s.keyword.eq_ignore_ascii_case(keyword) && s.requires_review));
    }
    assert!(!marker.exists());
    assert_eq!(std::fs::read(&f.source).unwrap(), before);
    assert_ne!(h.payload.user, "changed");
    assert_eq!(
        super::super::connection_readiness(h, &Default::default()),
        Ok(super::super::ConnectionReadiness::NeedsReview)
    );
}

#[test]
fn key_references_are_only_suggestions_and_additional_keys_require_review() {
    let f=Fixture::new("Host web\n  IdentityFile ~/.ssh/key-that-does-not-exist\n  IdentityFile \"~/.ssh/second key\"\n");
    let preview = preview_file(&f.source, &f.options()).unwrap();
    let h = candidate(&preview, "web");
    assert_eq!(h.payload.auth, super::super::AuthKind::Key);
    assert_eq!(preview.key_references.len(), 2);
    assert_eq!(
        preview.key_references[0].resolved_path.as_deref(),
        Some(f.home.join(".ssh/key-that-does-not-exist").as_path())
    );
    assert!(preview
        .key_references
        .iter()
        .all(|k| k.fingerprint.is_none() && !k.will_copy));
    assert_eq!(
        super::super::connection_readiness(h, &Default::default()),
        Ok(super::super::ConnectionReadiness::NeedsReview)
    );
    assert!(!f.home.join(".ssh/key-that-does-not-exist").exists());
}

#[test]
fn jump_references_reuse_saved_ids_and_complete_missing_endpoints_can_be_previewed() {
    let f=Fixture::new("Host web\n  ProxyJump alice@jump.example.com:2222\nHost jump.example.com\n  HostName jump.example.com\n  User alice\n  Port 2222\n");
    let preview = preview_file(&f.source, &f.options()).unwrap();
    assert_eq!(
        candidate(&preview, "web").payload.jump,
        vec![candidate(&preview, "jump.example.com").id.clone()]
    );
    let f = Fixture::new("Host web\n  ProxyJump alice@missing.example.com:2222\n");
    let preview = preview_file(&f.source, &f.options()).unwrap();
    let jump = candidate(&preview, "missing.example.com");
    assert_eq!(
        (
            jump.payload.hostname.as_str(),
            jump.payload.port,
            jump.payload.user.as_str()
        ),
        ("missing.example.com", 2222, "alice")
    );
    assert_eq!(
        candidate(&preview, "web").payload.jump,
        vec![jump.id.clone()]
    );
    let f = Fixture::new("Host web\n  ProxyJump missing-alias\n");
    let preview = preview_file(&f.source, &f.options()).unwrap();
    assert!(candidate(&preview, "web").payload.jump.is_empty());
    assert!(preview
        .warnings
        .iter()
        .any(|w| w.blocks_connection && w.keyword.eq_ignore_ascii_case("ProxyJump")));
}

#[test]
fn endpoint_overrides_do_not_share_a_pin_identity_and_jump_cycles_are_errors() {
    let f = Fixture::new(
        "Host web\n  ProxyJump jump:2222\nHost jump\n  HostName jump.example.com\n  Port 22\n",
    );
    let preview = preview_file(&f.source, &f.options()).unwrap();
    assert!(candidate(&preview, "web").payload.jump.is_empty());
    assert!(preview
        .warnings
        .iter()
        .any(|w| w.blocks_connection && w.keyword.eq_ignore_ascii_case("ProxyJump")));
    let f = Fixture::new("Host web\n  ProxyJump jump\nHost jump\n  ProxyJump web\n");
    assert!(matches!(
        preview_file(&f.source, &f.options()),
        Err(ImportError::InvalidRecords(
            super::super::RecordValidationError::JumpCycle(_)
        ))
    ));
}

#[test]
fn source_digest_changes_when_sources_change_but_supplied_host_mapping_stays_stable() {
    let f = Fixture::new("Host web\n  User first\n");
    let mut options = f.options();
    options
        .host_ids
        .insert("web".into(), "0000000000000001".into());
    let first = preview_file(&f.source, &options).unwrap();
    std::fs::write(&f.source, "Host web\n  User second\n").unwrap();
    let second = preview_file(&f.source, &options).unwrap();
    assert_ne!(first.source_digest, second.source_digest);
    assert_eq!(candidate(&first, "web").id, candidate(&second, "web").id);
}

#[test]
fn relay_source_keeps_original_space_and_stable_id_without_reading_its_includes() {
    use crate::sync::record::{Record, RecordKind};
    let f = Fixture::new("Host wrong\n");
    let space = "a".repeat(64);
    let r = Record {
        kind: RecordKind::Host,
        id: "web".into(),
        version: 1,
        updated_at_ms: 1,
        device_id: "d".repeat(32),
        deleted: false,
        payload: serde_json::json!({"schema":1,"text":"Host web\n  HostName web.example.com\n  Include /this-path-is-not-opened\n"}),
    };
    let preview = preview_legacy_record(&r, &space, &f.options()).unwrap();
    let h = candidate(&preview, "web");
    assert_eq!(h.id, "97ae2d71de67d6f1");
    assert_eq!(h.scope, super::super::HostScope::Space { space_id: space });
    assert!(h
        .payload
        .imported
        .as_ref()
        .unwrap()
        .unsupported
        .iter()
        .any(|s| s.keyword.eq_ignore_ascii_case("Include") && s.requires_review));
}

fn legacy(alias: &str, text: &str) -> crate::sync::record::Record {
    crate::sync::record::Record {
        kind: crate::sync::record::RecordKind::Host,
        id: alias.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: "d".repeat(32),
        deleted: false,
        payload: serde_json::json!({"schema":1,"text":text}),
    }
}
#[test]
fn complete_legacy_space_snapshot_maps_jump_aliases_to_shared_deterministic_ids() {
    let f = Fixture::new("");
    let space = "a".repeat(64);
    let web = legacy("web", "Host web\n  ProxyJump jump\n");
    let jump = legacy("jump", "Host jump\n  HostName jump.example.com\n");
    let first = preview_legacy_records(&[web.clone(), jump.clone()], &space, &f.options()).unwrap();
    let second = preview_legacy_records(&[jump, web], &space, &f.options()).unwrap();
    assert_eq!(first.candidates.len(), 2);
    assert_eq!(first.host_ids, second.host_ids);
    assert_eq!(
        candidate(&first, "web").payload.jump,
        vec![candidate(&first, "jump").id.clone()]
    );
    assert!(first.candidates.iter().all(|h| h.scope
        == super::super::HostScope::Space {
            space_id: space.clone()
        }));
}
#[test]
fn standalone_legacy_jump_never_leaves_a_dangling_id_or_invents_a_random_shared_record() {
    let f = Fixture::new("");
    let r = legacy(
        "web",
        "Host web\n  ProxyJump alice@missing.example.com:2222\n",
    );
    let preview = preview_legacy_record(&r, &"a".repeat(64), &f.options()).unwrap();
    assert_eq!(preview.candidates.len(), 1);
    assert!(candidate(&preview, "web").payload.jump.is_empty());
    assert!(candidate(&preview, "web")
        .payload
        .imported
        .as_ref()
        .unwrap()
        .unsupported
        .iter()
        .any(|s| s.keyword.eq_ignore_ascii_case("ProxyJump") && s.requires_review));
    assert!(super::super::validate_hosts(&preview.candidates).is_ok());
}

#[test]
fn legacy_preflight_refuses_collisions_with_old_aliases_and_unrelated_reserved_ids() {
    let f = Fixture::new("");
    let space = "a".repeat(64);
    let web = legacy("web", "Host web\n");
    let alias = legacy("97ae2d71de67d6f1", "Host 97ae2d71de67d6f1\n");
    assert!(matches!(
        preview_legacy_records(&[web.clone(), alias], &space, &f.options()),
        Err(ImportError::InvalidRecords(
            super::super::RecordValidationError::MigrationCollision { .. }
        ))
    ));
    let mut options = f.options();
    options.reserved_host_ids.insert("97ae2d71de67d6f1".into());
    assert!(matches!(
        preview_legacy_records(&[web], &space, &options),
        Err(ImportError::InvalidRecords(
            super::super::RecordValidationError::MigrationCollision { .. }
        ))
    ));
}
#[test]
fn authentication_timeouts_and_source_metadata_changes_are_preserved() {
    let f=Fixture::new("Host web\n  PreferredAuthentications keyboard-interactive\n  ConnectTimeout 7\n  ServerAliveInterval 20\n  ServerAliveCountMax 5\n  LogLevel DEBUG\n");
    let preview = preview_file(&f.source, &f.options()).unwrap();
    let h = candidate(&preview, "web");
    assert_eq!(h.payload.auth, super::super::AuthKind::Interactive);
    assert_eq!(
        (
            h.payload.connect_timeout_secs,
            h.payload.keepalive_secs,
            h.payload.keepalive_max_missed
        ),
        (7, 20, 5)
    );
    assert_eq!(
        super::super::connection_readiness(h, &Default::default()),
        Ok(super::super::ConnectionReadiness::Ready)
    );
    let mut r = legacy("web", "Host web\n");
    let first = preview_legacy_record(&r, &"a".repeat(64), &f.options()).unwrap();
    r.version = 2;
    let second = preview_legacy_record(&r, &"a".repeat(64), &f.options()).unwrap();
    assert_ne!(first.source_digest, second.source_digest);
}
