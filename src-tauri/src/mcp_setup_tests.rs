use super::*;
fn exe() -> &'static Path {
    Path::new("/Applications/Lunport.app/Contents/MacOS/sshelter")
}

#[test]
fn codex_preserves_comments_tables_and_other_servers() {
    let before = br#"# personal settings
model = "keep-model" # comment
[projects."/workspace"]
trust_level = "trusted"
[mcp_servers.other]
command = "other-server"
args = ["secret-argument"]
"#;
    let (bytes, ready) = configure_toml(before, exe()).unwrap();
    assert!(!ready);
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.starts_with(std::str::from_utf8(before).unwrap()));
    let doc = text.parse::<toml_edit::DocumentMut>().unwrap();
    assert_eq!(
        doc["mcp_servers"]["lunport"]["command"].as_str(),
        exe().to_str()
    );
    assert_eq!(
        doc["mcp_servers"]["other"]["args"][0].as_str(),
        Some("secret-argument")
    );
    assert!(configure_toml(&bytes, exe()).unwrap().1);
}

#[test]
fn existing_server_alias_is_repaired_without_duplicate_or_permissions_loss() {
    let old = "/Applications/SSHelter.app/Contents/MacOS/sshelter";
    for id in ALIASES {
        let before = json!({"mcpServers":{id:{"command":old,"args":["--mcp"],"env":{"KEEP":"fixture"}}},"other":{"keep":true}});
        let (bytes, ready) = configure_json(&serde_json::to_vec(&before).unwrap(), exe()).unwrap();
        assert!(!ready);
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["mcpServers"].as_object().unwrap().len(), 1);
        assert_eq!(doc["mcpServers"][id]["command"], exe().to_str().unwrap());
        assert_eq!(doc["mcpServers"][id]["env"]["KEEP"], "fixture");
        assert_eq!(doc["other"]["keep"], true);
        assert!(configure_json(&bytes, exe()).unwrap().1);
    }
}

#[test]
fn unrelated_same_name_servers_are_never_overwritten_or_executed() {
    for client in [SetupClient::ClaudeCode, SetupClient::ClaudeDesktop] {
        let before = br#"{"mcpServers":{"sshelter":{"command":"unrelated","args":["--mcp"]}}}"#;
        assert!(configure(client, before, exe()).is_err());
    }
    assert!(configure_toml(
        b"[mcp_servers.sshelter]\ncommand='unrelated'\nargs=['--mcp']",
        exe()
    )
    .is_err());
    assert!(configure_json(br#"{"mcpServers":{"sshelter":{"command":"/Applications/Lunport.app/Contents/MacOS/sshelter","args":["connect","host"]}}}"#, exe()).is_err());
}

#[test]
fn json_preserves_unknown_roots_servers_and_user_permissions() {
    let before = br#"{"theme":"dark","mcpServers":{"other":{"command":"other","env":{"API_KEY":"fixture"}}},"permissions":{"keep":false}}"#;
    let (bytes, _) = configure_json(before, exe()).unwrap();
    let doc: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["mcpServers"]["other"]["env"]["API_KEY"], "fixture");
    assert_eq!(doc["permissions"]["keep"], false);
    assert_eq!(doc["theme"], "dark");
    assert!(configure_json(&bytes, exe()).unwrap().1);
}

#[test]
fn malformed_settings_errors_do_not_include_their_secret_contents() {
    for (client, bytes) in [
        (SetupClient::Codex, b"secret-token='fixture\n".as_slice()),
        (
            SetupClient::ClaudeCode,
            b"{\"secret-token\":\"fixture\n".as_slice(),
        ),
    ] {
        let error = configure(client, bytes, exe()).unwrap_err().to_string();
        assert!(!error.contains("secret-token"));
        assert!(!error.contains("fixture"));
    }
    assert!(configure_json(b"", exe()).is_err());
    assert!(configure_json(b"[]", exe()).is_err());
    assert!(configure_json(br#"{"mcpServers":false}"#, exe()).is_err());
}

#[test]
fn explicit_codex_add_can_enable_only_its_owned_disabled_server() {
    for id in ALIASES {
        let before = format!("[mcp_servers.{id}]\ncommand={}\nargs=['--mcp']\nenabled=false\ndisabled_tools=['keep']\n", serde_json::to_string(exe().to_str().unwrap()).unwrap());
        let (bytes, ready) = configure_toml(before.as_bytes(), exe()).unwrap();
        assert!(!ready);
        let doc = String::from_utf8(bytes).unwrap().parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(doc["mcp_servers"].as_table().unwrap().len(), 1);
        assert_eq!(doc["mcp_servers"][id]["enabled"].as_bool(), Some(true));
        assert_eq!(doc["mcp_servers"][id]["disabled_tools"][0].as_str(), Some("keep"));
    }
}

#[test]
fn atomic_setup_backs_up_exact_bytes_and_rejects_a_concurrent_edit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("client/settings.json");
    let backups = root.path().join("backups");
    fs::create_dir(path.parent().unwrap()).unwrap();
    let before = b"{\"keep\":1}\n";
    fs::write(&path, before).unwrap();
    let backup = commit(&path, Some(before), b"{\"keep\":2}\n", &backups)
        .unwrap()
        .unwrap();
    assert_eq!(fs::read(backup).unwrap(), before);
    assert_eq!(fs::read(&path).unwrap(), b"{\"keep\":2}\n");
    fs::write(&path, b"changed externally").unwrap();
    assert!(commit(&path, Some(before), b"replacement", &backups).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"changed externally");
}

#[test]
fn a_new_config_is_created_without_a_fake_backup() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("client/settings.json");
    let backups = root.path().join("backups");
    assert!(commit(&path, None, b"{}\n", &backups).unwrap().is_none());
    assert_eq!(fs::read(&path).unwrap(), b"{}\n");
    assert!(!backups.exists());
    assert!(commit(&path, None, b"changed", &backups).is_err());
}

#[cfg(unix)]
#[test]
fn config_and_backup_are_owner_only_and_symlinks_are_preserved() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("client.json");
    let original = root.path().join("managed.json");
    fs::write(&original, b"{}\n").unwrap();
    symlink(&original, &path).unwrap();
    assert!(read_config(&path).is_err());
    assert!(commit(&path, Some(b"{}\n"), b"new", &root.path().join("backups")).is_err());
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&original).unwrap(), b"{}\n");
    fs::remove_file(&path).unwrap();
    commit(&path, None, b"first", &root.path().join("backups")).unwrap();
    let backup = commit(
        &path,
        Some(b"first"),
        b"second",
        &root.path().join("backups"),
    )
    .unwrap()
    .unwrap();
    for path in [&path, &backup] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn development_write_policy_rejects_external_client_settings() {
    let root = tempfile::tempdir().unwrap();
    let sandbox = root.path().join("sandbox");
    let external = root.path().join("personal/config.json");
    crate::fsutil::with_test_write_policy(
        crate::write_policy::WritePolicy::Confined {
            root: sandbox.clone(),
        },
        || {
            assert!(commit(&external, None, b"{}", &sandbox.join("backups")).is_err());
            assert!(!external.exists());
            commit(
                &sandbox.join("config.json"),
                None,
                b"{}",
                &sandbox.join("backups"),
            )
            .unwrap();
        },
    );
}

#[test]
fn platform_config_locations_and_custom_codex_root_are_explicit() {
    let home = Path::new("/fixture/home");
    assert_eq!(
        config_path(SetupClient::Codex, home, "macos", None).unwrap(),
        home.join(".codex/config.toml")
    );
    assert_eq!(
        config_path(
            SetupClient::Codex,
            home,
            "macos",
            Some(PathBuf::from("/custom/codex"))
        )
        .unwrap(),
        Path::new("/custom/codex/config.toml")
    );
    assert_eq!(
        config_path(SetupClient::ClaudeCode, home, "macos", None).unwrap(),
        home.join(".claude.json")
    );
    assert!(config_path(SetupClient::ClaudeDesktop, home, "linux", None).is_none());
    assert_eq!(
        config_path(SetupClient::ClaudeDesktop, home, "windows", None).unwrap(),
        home.join("AppData/Roaming/Claude/claude_desktop_config.json")
    );
}

#[test]
fn install_links_keep_unicode_and_shell_syntax_in_a_command_value() {
    use base64::Engine;
    let path = Path::new("/Applications/測試 A & $x/Lunport.app/Contents/MacOS/sshelter");
    let url = tauri::Url::parse(&install_link(SetupClient::Cursor, path).unwrap()).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(query["name"], "lunport");
    let doc: Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(query["config"].as_bytes())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(doc["command"], path.to_str().unwrap());
    assert_eq!(doc["args"], json!(["--mcp"]));
    let vscode = install_link(SetupClient::Vscode, path).unwrap();
    assert!(vscode.starts_with("vscode:mcp/install?%7B"));
    assert!(!vscode.contains("$x"));
}

#[test]
fn linux_uses_the_persistent_appimage_instead_of_its_temporary_mount() {
    let root = tempfile::tempdir().unwrap();
    let appimage = root.path().join("Lunport.AppImage");
    let binary = root.path().join("mounted-sshelter");
    fs::write(&appimage, b"fixture image").unwrap();
    fs::write(&binary, b"fixture executable").unwrap();
    assert_eq!(
        setup_executable("linux", &binary, Some(&appimage)).unwrap(),
        appimage.canonicalize().unwrap()
    );
    assert_eq!(
        setup_executable("macos", &binary, Some(&appimage)).unwrap(),
        binary.canonicalize().unwrap()
    );
    assert_eq!(
        setup_executable("linux", &binary, Some(Path::new("relative.AppImage"))).unwrap(),
        binary.canonicalize().unwrap()
    );
}

#[cfg(windows)]
#[test]
fn windows_settings_and_backups_do_not_inherit_a_broad_parent_acl() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("client.json");
    let backups = root.path().join("backups");
    commit(&path, None, b"first", &backups).unwrap();
    let backup = commit(&path, Some(b"first"), b"second", &backups)
        .unwrap()
        .unwrap();
    for path in [&path, &backups, &backup] {
        assert_eq!(crate::sync::slot_files_windows::ace_count(path).unwrap(), 1);
    }
}
