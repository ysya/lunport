use super::*;
use crate::legacy_identity;

fn exe() -> &'static Path {
    Path::new("/Applications/Lunport.app/Contents/MacOS/lunport")
}

/// The executable's file name before the rename, with the suffix this platform gives executables.
fn old_binary() -> String {
    format!(
        "{}{}",
        legacy_identity::current().main_binary,
        std::env::consts::EXE_SUFFIX
    )
}

/// A folder of applications in a temporary folder: whether a path names this app's earlier executable depends on what exists there, so
/// a real `/Applications` would decide the answer on a computer that still has an old bundle.
struct Applications(tempfile::TempDir);

impl Applications {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }
    /// The executable of this version, in `Lunport.app`.
    fn exe(&self) -> PathBuf {
        self.0.path().join("Lunport.app/Contents/MacOS/lunport")
    }
    /// The old executable of an app bundle named `bundle`, as an MCP client's settings still name it.
    fn old_exe(&self, bundle: &str) -> String {
        self.0
            .path()
            .join(bundle)
            .join("Contents/MacOS")
            .join(old_binary())
            .to_string_lossy()
            .into_owned()
    }
}

#[test]
fn this_apps_entry_takes_the_current_name_unless_another_server_holds_it() {
    let (new, old) = (SERVER_ID, LEGACY_SERVER_ID);
    let at = |id, retire_legacy| Placement { id, retire_legacy };
    assert_eq!(select_id(&[]).unwrap(), at(new, false));
    assert_eq!(select_id(&[(new, true)]).unwrap(), at(new, false));
    assert_eq!(select_id(&[(new, true), (old, false)]).unwrap(), at(new, false));
    // This app's entry under the old name moves to the current one, and merges into this app's entry there.
    assert_eq!(select_id(&[(old, true)]).unwrap(), at(new, true));
    assert_eq!(select_id(&[(new, true), (old, true)]).unwrap(), at(new, true));
    // Another server holds the current name: this app's entry stays where it is.
    assert_eq!(select_id(&[(new, false), (old, true)]).unwrap(), at(old, false));
    for taken in [&[(new, false)][..], &[(old, false)], &[(new, false), (old, false)]] {
        assert!(select_id(taken).is_err(), "{taken:?}");
    }
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

/// An entry of this app under either name is repaired into one entry under the current name, with its other settings.
#[test]
fn existing_server_alias_is_repaired_without_duplicate_or_permissions_loss() {
    let apps = Applications::new();
    let exe = apps.exe();
    let old = apps.old_exe(legacy_identity::BUNDLE_NAMES[0]);
    for id in ALIASES {
        let before = json!({"mcpServers":{id:{"command":old,"args":["--mcp"],"env":{"KEEP":"fixture"}}},"other":{"keep":true}});
        let (bytes, ready) = configure_json(&serde_json::to_vec(&before).unwrap(), &exe).unwrap();
        assert!(!ready);
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["mcpServers"].as_object().unwrap().len(), 1);
        assert_eq!(doc["mcpServers"][SERVER_ID]["command"], exe.to_str().unwrap());
        assert_eq!(doc["mcpServers"][SERVER_ID]["env"]["KEEP"], "fixture");
        assert_eq!(doc["other"]["keep"], true);
        assert!(configure_json(&bytes, &exe).unwrap().1);
    }
}

/// Every bundle name the app had before the rename counts, Development's lower-case one among them: a client's settings that name
/// the old executable of a bundle that is gone are the app's own entry.
#[test]
fn an_entry_in_any_bundle_name_from_before_the_rename_is_this_apps_own() {
    let apps = Applications::new();
    for bundle in legacy_identity::BUNDLE_NAMES {
        let old = apps.old_exe(bundle);
        assert!(owned_command(&old, &apps.exe()), "{old}");
    }
    // The old executable of an unrelated app is not.
    assert!(!owned_command(&apps.old_exe("Unrelated.app"), &apps.exe()));
}

/// 1.14.4 was already `Lunport.app`; only its executable had the old name. The update replaced the bundle, and a client's settings still
/// name the old executable inside it. The same holds wherever the old executable sat next to this one: the Windows install folder,
/// `/usr/bin`.
#[test]
fn an_entry_naming_the_old_executable_next_to_this_one_is_this_apps_own() {
    let apps = Applications::new();
    let exe = apps.exe();
    let old = apps.old_exe("Lunport.app");
    assert!(owned_command(&old, &exe), "{old}");
    let before = json!({"mcpServers":{SERVER_ID:{"command":old,"args":["--mcp"]}}});
    let (bytes, ready) = configure_json(&serde_json::to_vec(&before).unwrap(), &exe).unwrap();
    assert!(!ready);
    let doc: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["mcpServers"][SERVER_ID]["command"], exe.to_str().unwrap());

    let folder = apps.0.path().join("Programs").join("Lunport");
    let installed = folder.join(format!("lunport{}", std::env::consts::EXE_SUFFIX));
    assert!(owned_command(folder.join(old_binary()).to_str().unwrap(), &installed));
    // Only next to this executable: the old name in another folder is someone else's.
    assert!(!owned_command(
        apps.0.path().join("Elsewhere").join(old_binary()).to_str().unwrap(),
        &installed
    ));
}

/// This installation's earlier executable is this app's own while it is still there, too: the update may leave it behind (Windows keeps
/// a file that was in use), and so may an earlier bundle beside this one. The setup repairs such an entry, and the migration moves it.
#[test]
fn an_earlier_executable_of_this_installation_that_still_exists_is_this_apps_own() {
    let apps = Applications::new();
    let exe = apps.exe();
    fs::create_dir_all(exe.parent().unwrap()).unwrap();
    fs::write(&exe, b"fixture executable").unwrap();
    let old = apps.old_exe("Lunport.app");
    fs::write(&old, b"the earlier executable").unwrap();
    assert!(owned_command(&old, &exe), "{old}");
    let before = json!({"mcpServers":{SERVER_ID:{"command":old,"args":["--mcp"]}}});
    let (bytes, ready) = configure_json(&serde_json::to_vec(&before).unwrap(), &exe).unwrap();
    assert!(!ready, "Add repairs it");
    let doc: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["mcpServers"][SERVER_ID]["command"], exe.to_str().unwrap());
    for bundle in legacy_identity::BUNDLE_NAMES {
        let sibling = apps.old_exe(bundle);
        fs::create_dir_all(Path::new(&sibling).parent().unwrap()).unwrap();
        fs::write(&sibling, b"an earlier bundle's executable").unwrap();
        assert!(owned_command(&sibling, &exe), "{sibling}");
    }
}

/// A program by the earlier executable's name anywhere else is not this installation's, whether or not it is there: the migration names
/// an entry that starts one (`earlier_program_elsewhere`), and leaves it as it is.
#[test]
fn an_earlier_executable_elsewhere_is_not_this_installations() {
    let apps = Applications::new();
    let exe = apps.exe();
    fs::create_dir_all(exe.parent().unwrap()).unwrap();
    fs::write(&exe, b"fixture executable").unwrap();
    let elsewhere = apps.0.path().join("Downloads/Lunport.app/Contents/MacOS").join(old_binary());
    fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
    fs::write(&elsewhere, b"an older copy").unwrap();
    assert!(!owned_command(elsewhere.to_str().unwrap(), &exe));
    let gone = apps.0.path().join("Elsewhere").join(old_binary());
    assert!(!owned_command(gone.to_str().unwrap(), &exe));
}

/// What `earlier_program_elsewhere` finds: an MCP adapter entry under this app's server names whose program has the earlier
/// executable's file name, and is none of this installation's. Not this installation's own earlier executable (the move changes that),
/// another server's name, another program, or the earlier program started for something else.
#[test]
fn an_entry_that_starts_an_earlier_lunport_elsewhere_is_found() {
    let apps = Applications::new();
    let exe = apps.exe();
    let elsewhere = apps.0.path().join("Elsewhere").join(old_binary()).to_string_lossy().into_owned();
    let own_earlier = apps.old_exe("Lunport.app");
    let json_with = |servers: Value| serde_json::to_vec(&json!({ "mcpServers": servers })).unwrap();
    for id in ALIASES {
        let settings = json_with(json!({ id: {"command": elsewhere, "args": ["--mcp"]} }));
        assert_eq!(earlier_program_elsewhere(SetupClient::ClaudeCode, &settings, &exe).as_deref(), Some(elsewhere.as_str()), "{id}");
        let codex = format!("[mcp_servers.{id}]\ncommand = {}\nargs = [\"--mcp\"]\n", toml_edit::Value::from(elsewhere.as_str()));
        assert_eq!(earlier_program_elsewhere(SetupClient::Codex, codex.as_bytes(), &exe).as_deref(), Some(elsewhere.as_str()), "{id}");
    }
    let untouched = [
        json!({ SERVER_ID: {"command": own_earlier, "args": ["--mcp"]} }),
        json!({ SERVER_ID: {"command": exe, "args": ["--mcp"]} }),
        json!({ "other": {"command": elsewhere, "args": ["--mcp"]} }),
        json!({ SERVER_ID: {"command": apps.0.path().join("Elsewhere/other-server"), "args": ["--mcp"]} }),
        json!({ SERVER_ID: {"command": elsewhere, "args": ["connect", "web-1"]} }),
        json!({ SERVER_ID: {"type": "http", "command": elsewhere, "args": ["--mcp"]} }),
    ];
    for servers in untouched {
        assert_eq!(earlier_program_elsewhere(SetupClient::ClaudeDesktop, &json_with(servers.clone()), &exe), None, "{servers}");
    }
    assert_eq!(earlier_program_elsewhere(SetupClient::ClaudeCode, b"{not json", &exe), None);
    assert_eq!(earlier_program_elsewhere(SetupClient::Codex, b"[mcp_servers", &exe), None);
}

#[test]
fn unrelated_same_name_servers_are_never_overwritten_or_executed() {
    let old_alias = legacy_identity::MCP_ALIAS;
    for client in [SetupClient::ClaudeCode, SetupClient::ClaudeDesktop] {
        let before = json!({"mcpServers":{old_alias:{"command":"unrelated","args":["--mcp"]}}});
        assert!(configure(client, &serde_json::to_vec(&before).unwrap(), exe()).is_err());
    }
    assert!(configure_toml(
        format!("[mcp_servers.{old_alias}]\ncommand='unrelated'\nargs=['--mcp']").as_bytes(),
        exe()
    )
    .is_err());
    let own_program_with_other_arguments = json!({"mcpServers":{old_alias:{"command":exe(),"args":["connect","host"]}}});
    assert!(configure_json(&serde_json::to_vec(&own_program_with_other_arguments).unwrap(), exe()).is_err());
}

/// An entry under this app's server names that starts an earlier Lunport elsewhere (`earlier_program_elsewhere`) holds the setup back as
/// another server does, but the refusal says what it is and that it is changed or removed, as the migration's notice does, rather than
/// calling it unrelated and asking for another server name. Apart from the program it names, it names no earlier product.
#[test]
fn an_earlier_lunport_elsewhere_that_holds_the_setup_back_is_named() {
    let apps = Applications::new();
    let exe = apps.exe();
    let elsewhere = apps.0.path().join("Elsewhere").join(old_binary()).to_string_lossy().into_owned();
    let says = format!(
        "An entry under this name starts an earlier Lunport at {elsewhere}. It was not changed; change that entry to start this Lunport, or remove it."
    );
    let earlier = json!({"command": elsewhere, "args": ["--mcp"]});
    let unrelated = json!({"command": "unrelated", "args": ["--mcp"]});
    // Alone under either name, or under the old name while another server holds the current one.
    for servers in [json!({ SERVER_ID: earlier }), json!({ LEGACY_SERVER_ID: earlier }), json!({ SERVER_ID: unrelated, LEGACY_SERVER_ID: earlier })] {
        let settings = serde_json::to_vec(&json!({ "mcpServers": servers })).unwrap();
        for client in [SetupClient::ClaudeCode, SetupClient::ClaudeDesktop] {
            assert_eq!(configure(client, &settings, &exe).unwrap_err().to_string(), says, "{client:?}: {servers}");
        }
    }
    for id in ALIASES {
        let codex = format!("[mcp_servers.{id}]\ncommand = {}\nargs = [\"--mcp\"]\n", toml_edit::Value::from(elsewhere.as_str()));
        assert_eq!(configure(SetupClient::Codex, codex.as_bytes(), &exe).unwrap_err().to_string(), says, "{id}");
    }
    let words = says.replace(&elsewhere, "").to_lowercase();
    for old in [LEGACY_SERVER_ID, legacy_identity::current().installer_identity, legacy_identity::current().main_binary] {
        assert!(!words.contains(&old.to_lowercase()), "{says}");
    }
}

/// Another program's server under this app's server names keeps the refusal it always had, the earlier program started for something
/// else than the MCP adapter included: it is unrelated, and manual setup under another server name is the way on.
#[test]
fn an_unrelated_server_that_holds_the_setup_back_is_refused_as_before() {
    let apps = Applications::new();
    let exe = apps.exe();
    let elsewhere = apps.0.path().join("Elsewhere").join(old_binary()).to_string_lossy().into_owned();
    let says = "An unrelated server already uses this name. It was not changed; use manual setup with another server name.";
    for entry in [
        json!({"command": "unrelated", "args": ["--mcp"]}),
        json!({"command": apps.0.path().join("Elsewhere/other-server"), "args": ["--mcp"]}),
        json!({"command": elsewhere, "args": ["connect", "web-1"]}),
    ] {
        for id in ALIASES {
            let settings = serde_json::to_vec(&json!({ "mcpServers": { id: entry } })).unwrap();
            assert_eq!(configure(SetupClient::ClaudeCode, &settings, &exe).unwrap_err().to_string(), says, "{id}: {entry}");
        }
    }
    for id in ALIASES {
        let codex = format!("[mcp_servers.{id}]\ncommand = 'unrelated'\nargs = ['--mcp']\n");
        assert_eq!(configure(SetupClient::Codex, codex.as_bytes(), &exe).unwrap_err().to_string(), says, "{id}");
    }
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
        let before = format!("# Lunport\n[mcp_servers.{id}]\n# keep: the program\n  command={} # the program\n# keep: the arguments\nargs=['--mcp']\n# keep: on or off\nenabled=false\ndisabled_tools=['keep']\n", serde_json::to_string(exe().to_str().unwrap()).unwrap());
        let (bytes, ready) = configure_toml(before.as_bytes(), exe()).unwrap();
        assert!(!ready);
        let text = String::from_utf8(bytes).unwrap();
        let doc = text.parse::<toml_edit::DocumentMut>().unwrap();
        // An entry under the old name moves to the current one, with its comments.
        assert_eq!(doc["mcp_servers"].as_table().unwrap().len(), 1);
        assert_eq!(doc["mcp_servers"][SERVER_ID]["enabled"].as_bool(), Some(true));
        assert_eq!(doc["mcp_servers"][SERVER_ID]["disabled_tools"][0].as_str(), Some("keep"));
        assert!(text.starts_with(&format!("# Lunport\n[mcp_servers.{SERVER_ID}]\n")), "{text}");
        // The values the setup sets keep the comments above them, their indentation and the comment beside them.
        assert!(text.contains("\n# keep: the program\n  command="), "{text}");
        assert!(text.contains(" # the program\n"), "{text}");
        assert!(text.contains("\n# keep: the arguments\nargs="), "{text}");
        assert!(text.contains("\n# keep: on or off\nenabled=true\n"), "{text}");
        assert!(configure_toml(text.as_bytes(), exe()).unwrap().1);
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
    let path = Path::new("/Applications/測試 A & $x/Lunport.app/Contents/MacOS/lunport");
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
    let binary = root.path().join("mounted-lunport");
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
