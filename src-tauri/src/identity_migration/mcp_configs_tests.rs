//! Each test is a folder in a temporary folder holding the AI clients' settings as the setup of 1.14.4 left them: entries named
//! `sshelter` or `lunport` that start the executable `sshelter`, which the update removed from beside this version's `lunport`. The
//! tests name every settings file themselves, so nothing depends on the build profile or the environment.

use super::super::journal::{Journal, McpFailure, McpProgress, StepState};
use super::super::Step;
use super::*;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

struct Home {
    temp: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        Self { temp: tempfile::tempdir().unwrap() }
    }
    fn data(&self) -> PathBuf {
        self.temp.path().join("data")
    }
    fn new_exe(&self) -> PathBuf {
        self.temp
            .path()
            .join("Applications/Lunport.app/Contents/MacOS")
            .join(format!("lunport{}", std::env::consts::EXE_SUFFIX))
    }
    fn old_exe(&self) -> String {
        let old = self.new_exe().with_file_name(format!("sshelter{}", std::env::consts::EXE_SUFFIX));
        old.to_string_lossy().into_owned()
    }
    /// A path in the temporary folder that names nothing of this app's.
    fn elsewhere(&self, name: &str) -> String {
        self.temp.path().join("elsewhere").join(name).to_string_lossy().into_owned()
    }
    /// The settings file of every client whose file the setup writes.
    fn files(&self) -> Vec<(SetupClient, PathBuf)> {
        let home = self.temp.path().join("home");
        vec![
            (SetupClient::Codex, home.join(".codex/config.toml")),
            (SetupClient::ClaudeCode, home.join(".claude.json")),
            (SetupClient::ClaudeDesktop, home.join("Claude/claude_desktop_config.json")),
        ]
    }
    fn settings(&self, client: SetupClient) -> PathBuf {
        self.files().into_iter().find(|(file_client, _)| *file_client == client).unwrap().1
    }
    fn write(&self, client: SetupClient, bytes: &[u8]) {
        let path = self.settings(client);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn read(&self, client: SetupClient) -> Vec<u8> {
        fs::read(self.settings(client)).unwrap()
    }
    fn migrate(&self) -> Moved {
        migrate_files(&self.files(), &self.new_exe(), &self.data()).unwrap()
    }
    /// The clients a move updated, when none failed.
    fn updated(&self) -> Vec<SetupClient> {
        let moved = self.migrate();
        assert_eq!(moved.failed, [], "nothing fails here");
        moved.updated
    }
    /// The backups the move made of `client`'s settings.
    fn backups(&self, client: SetupClient) -> Vec<Vec<u8>> {
        match fs::read_dir(mcp_setup::backup_folder(&self.data(), client)) {
            Ok(entries) => entries.map(|entry| fs::read(entry.unwrap().path()).unwrap()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// `value` as a TOML string, the way toml_edit writes it.
fn toml_string(value: &str) -> String {
    toml_edit::Value::from(value).to_string()
}

fn codex_1_14_4(alias: &str, command: &str) -> String {
    format!(
        r#"# personal settings
model = "keep-model" # comment

[projects."/workspace"]
trust_level = "trusted"

# Lunport, added by its setup
[mcp_servers.{alias}]
# keep: the program path
  command = {command} # the program
args = ["--mcp"]
enabled = false
startup_timeout_sec = 20

[mcp_servers.other]
command = "other-server"
args = ["keep-argument"]
"#,
        command = toml_string(command)
    )
}

fn claude_1_14_4(alias: &str, command: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"mcpServers": {alias: {"command": command, "args": ["--mcp"]}}})).unwrap()
}

#[test]
fn codex_toml_old_alias_and_path_rewritten_keeping_comments() {
    let home = Home::new();
    let before = codex_1_14_4("sshelter", &home.old_exe());
    home.write(SetupClient::Codex, before.as_bytes());
    assert_eq!(home.updated(), [SetupClient::Codex]);
    // Byte for byte what was there, but for the name and the program: comments, indentation, order, `enabled = false` and the rest
    // stay.
    assert_eq!(
        String::from_utf8(home.read(SetupClient::Codex)).unwrap(),
        codex_1_14_4("lunport", home.new_exe().to_str().unwrap())
    );
    assert_eq!(home.backups(SetupClient::Codex), [before.into_bytes()]);
    // Moved once: a later start changes nothing.
    assert_eq!(home.updated(), []);
    assert_eq!(home.backups(SetupClient::Codex).len(), 1);
}

#[test]
fn claude_json_old_path_rewritten_with_backup() {
    let home = Home::new();
    let before = json!({
        "numStartups": 12,
        "mcpServers": {
            "lunport": {"type": "stdio", "command": home.old_exe(), "args": ["--mcp"], "env": {"KEEP": "fixture"}},
            "other": {"command": "other-server", "args": ["keep-argument"]}
        },
        "projects": {"/workspace": {"allowedTools": ["keep"]}}
    });
    let bytes = serde_json::to_vec_pretty(&before).unwrap();
    home.write(SetupClient::ClaudeCode, &bytes);
    assert_eq!(home.updated(), [SetupClient::ClaudeCode]);
    let mut expected = before.clone();
    expected["mcpServers"]["lunport"]["command"] = json!(home.new_exe());
    let after: Value = serde_json::from_slice(&home.read(SetupClient::ClaudeCode)).unwrap();
    assert_eq!(after, expected);
    assert_eq!(home.backups(SetupClient::ClaudeCode), [bytes]);
}

#[test]
fn an_entry_under_the_old_name_moves_to_the_current_one() {
    let home = Home::new();
    let before = json!({"mcpServers": {"sshelter": {"command": home.old_exe(), "args": ["--mcp"], "env": {"KEEP": "fixture"}}}});
    home.write(SetupClient::ClaudeCode, &serde_json::to_vec(&before).unwrap());
    assert_eq!(home.updated(), [SetupClient::ClaudeCode]);
    let after: Value = serde_json::from_slice(&home.read(SetupClient::ClaudeCode)).unwrap();
    assert_eq!(
        after,
        json!({"mcpServers": {"lunport": {"command": home.new_exe(), "args": ["--mcp"], "env": {"KEEP": "fixture"}}}})
    );
}

/// An entry that starts this version already, by a path of the user's own (here one through `..`, as a link on the PATH would), is
/// left as the user wrote it; under the old name only the name moves.
#[test]
fn a_working_entry_keeps_the_path_the_user_wrote() {
    let home = Home::new();
    fs::create_dir_all(home.new_exe().parent().unwrap()).unwrap();
    fs::write(home.new_exe(), b"fixture executable").unwrap();
    let own_path = home.new_exe().parent().unwrap().join("..").join("MacOS").join(home.new_exe().file_name().unwrap());
    let own_path = own_path.to_str().unwrap();
    let codex = codex_1_14_4("lunport", own_path);
    home.write(SetupClient::Codex, codex.as_bytes());
    home.write(SetupClient::ClaudeCode, &claude_1_14_4("sshelter", own_path));
    assert_eq!(home.updated(), [SetupClient::ClaudeCode]);
    assert_eq!(home.read(SetupClient::Codex), codex.as_bytes());
    let after: Value = serde_json::from_slice(&home.read(SetupClient::ClaudeCode)).unwrap();
    assert_eq!(after, json!({"mcpServers": {"lunport": {"command": own_path, "args": ["--mcp"]}}}));
}

/// The setup used to keep an entry under the old name and add one under the current name: the two are one server, which keeps the
/// current name's settings.
#[test]
fn entries_under_both_names_become_one() {
    let home = Home::new();
    let before = json!({"mcpServers": {
        "lunport": {"command": home.old_exe(), "args": ["--mcp"], "env": {"FROM": "current"}},
        "sshelter": {"command": home.old_exe(), "args": ["--mcp"], "env": {"FROM": "old"}}
    }});
    home.write(SetupClient::ClaudeCode, &serde_json::to_vec(&before).unwrap());
    assert_eq!(home.updated(), [SetupClient::ClaudeCode]);
    let after: Value = serde_json::from_slice(&home.read(SetupClient::ClaudeCode)).unwrap();
    assert_eq!(
        after,
        json!({"mcpServers": {"lunport": {"command": home.new_exe(), "args": ["--mcp"], "env": {"FROM": "current"}}}})
    );
}

/// Another server holds the current name: this app's entry keeps the old name and starts this version.
#[test]
fn the_current_name_taken_by_another_server_keeps_ours_under_the_old_name() {
    let home = Home::new();
    let other = json!({"command": home.elsewhere("lunport"), "args": ["--mcp"]});
    let before = json!({"mcpServers": {"lunport": other, "sshelter": {"command": home.old_exe(), "args": ["--mcp"]}}});
    home.write(SetupClient::ClaudeCode, &serde_json::to_vec(&before).unwrap());
    assert_eq!(home.updated(), [SetupClient::ClaudeCode]);
    let after: Value = serde_json::from_slice(&home.read(SetupClient::ClaudeCode)).unwrap();
    assert_eq!(
        after,
        json!({"mcpServers": {"lunport": other, "sshelter": {"command": home.new_exe(), "args": ["--mcp"]}}})
    );
}

#[test]
fn foreign_entries_untouched() {
    let home = Home::new();
    // Under this app's names, but not this app's entries: its program with other arguments is not the MCP adapter, and another program
    // is someone else's.
    let codex = format!(
        "[mcp_servers.lunport]\ncommand = {}\nargs = [\"connect\", \"web-1\"]\n\n[mcp_servers.sshelter]\ncommand = {}\nargs = [\"--mcp\"]\n",
        toml_string(&home.old_exe()),
        toml_string(&home.elsewhere("other-server"))
    );
    // No entry of this app's at all: none is added. A program by the earlier executable's name under another server's name is that
    // server's.
    let claude = serde_json::to_vec_pretty(&json!({"theme": "dark", "mcpServers": {
        "other": {"command": "other-server"},
        "mine": {"command": home.elsewhere("sshelter"), "args": ["--mcp"]}
    }}))
    .unwrap();
    home.write(SetupClient::Codex, codex.as_bytes());
    home.write(SetupClient::ClaudeCode, &claude);
    assert_eq!(home.updated(), []);
    assert_eq!(home.read(SetupClient::Codex), codex.as_bytes());
    assert_eq!(home.read(SetupClient::ClaudeCode), claude);
    assert!(!home.data().exists());
}

/// The update could not remove the earlier executable beside this one (Windows keeps a file that was in use, and the installer only
/// notes it): it is still this installation's, and the entries that start it move to this version all the same. The file stays.
#[test]
fn an_earlier_executable_the_update_left_behind_still_moves() {
    let home = Home::new();
    fs::create_dir_all(home.new_exe().parent().unwrap()).unwrap();
    fs::write(home.new_exe(), b"this version").unwrap();
    fs::write(home.old_exe(), b"the earlier executable, left behind").unwrap();
    home.write(SetupClient::Codex, codex_1_14_4("sshelter", &home.old_exe()).as_bytes());
    home.write(SetupClient::ClaudeDesktop, &claude_1_14_4("lunport", &home.old_exe()));
    assert_eq!(home.updated(), [SetupClient::Codex, SetupClient::ClaudeDesktop]);
    assert_eq!(
        String::from_utf8(home.read(SetupClient::Codex)).unwrap(),
        codex_1_14_4("lunport", home.new_exe().to_str().unwrap())
    );
    let after: Value = serde_json::from_slice(&home.read(SetupClient::ClaudeDesktop)).unwrap();
    assert_eq!(after, json!({"mcpServers": {"lunport": {"command": home.new_exe(), "args": ["--mcp"]}}}));
    assert_eq!(fs::read(home.old_exe()).unwrap(), b"the earlier executable, left behind");
    assert_eq!(home.updated(), [], "nothing is left to move");

    // So does an entry that starts the earlier executable of an older bundle beside this one.
    let home = Home::new();
    let bundle = home.new_exe().parent().unwrap().parent().unwrap().parent().unwrap().with_file_name("SSHelter.app");
    let sibling = bundle.join("Contents/MacOS").join(format!("sshelter{}", std::env::consts::EXE_SUFFIX));
    fs::create_dir_all(sibling.parent().unwrap()).unwrap();
    fs::write(&sibling, b"an earlier bundle").unwrap();
    home.write(SetupClient::ClaudeCode, &claude_1_14_4("sshelter", sibling.to_str().unwrap()));
    assert_eq!(home.updated(), [SetupClient::ClaudeCode]);
    let after: Value = serde_json::from_slice(&home.read(SetupClient::ClaudeCode)).unwrap();
    assert_eq!(after, json!({"mcpServers": {"lunport": {"command": home.new_exe(), "args": ["--mcp"]}}}));
}

/// An entry under this app's names that starts an earlier Lunport somewhere else (an older copy of the app, kept or gone) is not this
/// installation's to move: it stays as it is, and the client is named with that program, so that the step stays for a later start and
/// the notice says what to change. What else in the file moves still moves.
#[test]
fn an_earlier_lunport_elsewhere_is_named_and_left_as_it_is() {
    let home = Home::new();
    let kept = home.elsewhere("sshelter");
    fs::create_dir_all(Path::new(&kept).parent().unwrap()).unwrap();
    fs::write(&kept, b"an older copy of the app").unwrap();
    let gone = home.temp.path().join("Downloads/Lunport.app/Contents/MacOS/sshelter").to_string_lossy().into_owned();
    let codex = codex_1_14_4("lunport", &kept);
    home.write(SetupClient::Codex, codex.as_bytes());
    home.write(SetupClient::ClaudeCode, &claude_1_14_4("sshelter", &gone));
    // Claude Desktop has this installation's earlier entry, which moves, beside one that starts the older copy.
    let desktop = json!({"mcpServers": {
        "lunport": {"command": home.old_exe(), "args": ["--mcp"]},
        "sshelter": {"command": kept, "args": ["--mcp"]}
    }});
    home.write(SetupClient::ClaudeDesktop, &serde_json::to_vec(&desktop).unwrap());
    let moved = home.migrate();
    assert_eq!(moved.updated, [SetupClient::ClaudeDesktop]);
    let reasons: Vec<(SetupClient, &str)> = moved.failed.iter().map(|(client, reason)| (*client, reason.as_str())).collect();
    let says = |program: &str| format!("It still starts an earlier Lunport at {program}. Change that entry to start this Lunport, or remove it.");
    assert_eq!(
        reasons,
        [
            (SetupClient::Codex, says(&kept).as_str()),
            (SetupClient::ClaudeCode, says(&gone).as_str()),
            (SetupClient::ClaudeDesktop, says(&kept).as_str())
        ]
    );
    assert_eq!(home.read(SetupClient::Codex), codex.as_bytes());
    assert_eq!(home.read(SetupClient::ClaudeCode), claude_1_14_4("sshelter", &gone));
    let after: Value = serde_json::from_slice(&home.read(SetupClient::ClaudeDesktop)).unwrap();
    assert_eq!(
        after,
        json!({"mcpServers": {"lunport": {"command": home.new_exe(), "args": ["--mcp"]}, "sshelter": {"command": kept, "args": ["--mcp"]}}})
    );
    assert_eq!((home.backups(SetupClient::Codex).len(), home.backups(SetupClient::ClaudeCode).len()), (0, 0), "nothing else changed");

    // The step stays for a later start, and the notice names each client with why.
    let mut journal = moved_journal();
    let state = step(&mut journal, || Ok(moved.clone()));
    assert!(matches!(&state, StepState::Failed(reason) if reason.contains("It still starts an earlier Lunport at")), "{state:?}");
    let failed = moved.failed.iter().map(|(client, reason)| McpFailure { client: Some(*client), reason: reason.clone() });
    assert_eq!(notice(&journal).map(|notice| notice.failed), Some(failed.collect()));

    // Once the user points them at this version, nothing is left to say.
    home.write(SetupClient::Codex, codex_1_14_4("lunport", home.new_exe().to_str().unwrap()).as_bytes());
    home.write(SetupClient::ClaudeCode, &claude_1_14_4("lunport", home.new_exe().to_str().unwrap()));
    home.write(SetupClient::ClaudeDesktop, &claude_1_14_4("lunport", home.new_exe().to_str().unwrap()));
    assert_eq!(home.migrate(), Moved::default());
}

/// A settings file the setup does not edit that starts an earlier Lunport elsewhere is named the same way.
#[cfg(unix)]
#[test]
fn a_link_to_settings_that_start_an_earlier_lunport_elsewhere_is_named() {
    let home = Home::new();
    let elsewhere = home.elsewhere("sshelter");
    let target = home.temp.path().join("dotfiles/claude.json");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, claude_1_14_4("lunport", &elsewhere)).unwrap();
    let link = home.settings(SetupClient::ClaudeCode);
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let moved = home.migrate();
    assert_eq!(failed_clients(&moved), [SetupClient::ClaudeCode]);
    assert!(moved.failed[0].1.starts_with(&format!("It still starts an earlier Lunport at {elsewhere}.")), "{}", moved.failed[0].1);
    assert_eq!(fs::read(&target).unwrap(), claude_1_14_4("lunport", &elsewhere));
}

/// An entry written inline under `[mcp_servers]` keeps the comment above it and the one beside it.
#[test]
fn an_inline_codex_entry_moves_with_its_comments() {
    let home = Home::new();
    let codex = |alias: &str, command: &str| {
        format!(
            "model = \"keep-model\"\n\n[mcp_servers]\n# Lunport, added by its setup\n{alias} = {{ command = {}, args = [\"--mcp\"] }} # inline\n",
            toml_string(command)
        )
    };
    home.write(SetupClient::Codex, codex("sshelter", &home.old_exe()).as_bytes());
    assert_eq!(home.updated(), [SetupClient::Codex]);
    assert_eq!(
        String::from_utf8(home.read(SetupClient::Codex)).unwrap(),
        codex("lunport", home.new_exe().to_str().unwrap())
    );
}

#[test]
fn settings_that_are_current_missing_or_cannot_be_parsed_are_left_alone() {
    let home = Home::new();
    let current = serde_json::to_vec(&json!({"mcpServers": {"lunport": {"command": home.new_exe(), "args": ["--mcp"]}}})).unwrap();
    let broken = format!("[mcp_servers.sshelter]\ncommand = {}\nargs = [\"--mcp\"\n", toml_string(&home.old_exe()));
    home.write(SetupClient::ClaudeCode, &current);
    home.write(SetupClient::Codex, broken.as_bytes());
    // Claude Desktop's file is missing.
    assert_eq!(home.updated(), []);
    assert_eq!(home.read(SetupClient::ClaudeCode), current);
    assert_eq!(home.read(SetupClient::Codex), broken.as_bytes());
    assert!(!home.data().exists());
}

#[test]
fn every_client_with_a_settings_file_moves() {
    let home = Home::new();
    home.write(SetupClient::Codex, codex_1_14_4("lunport", &home.old_exe()).as_bytes());
    for client in [SetupClient::ClaudeCode, SetupClient::ClaudeDesktop] {
        home.write(client, &claude_1_14_4("lunport", &home.old_exe()));
    }
    assert_eq!(home.updated(), CLIENTS);
    for client in CLIENTS {
        let text = String::from_utf8(home.read(client)).unwrap();
        assert!(!text.contains("sshelter"), "{client:?}: {text}");
        assert_eq!(home.backups(client).len(), 1, "{client:?}");
    }
}

/// The clients a move reported as failed.
fn failed_clients(moved: &Moved) -> Vec<SetupClient> {
    moved.failed.iter().map(|(client, _)| *client).collect()
}

/// A settings file the setup does not edit (here a symbolic link, as dotfile managers make) is left to manual setup, where the setup
/// page sends it. While it still holds an earlier entry it is reported, so that the notice names it; nothing in it changes.
#[cfg(unix)]
#[test]
fn settings_the_setup_does_not_edit_are_left_to_manual_setup() {
    let home = Home::new();
    let target = home.temp.path().join("dotfiles/claude.json");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, claude_1_14_4("lunport", &home.old_exe())).unwrap();
    let link = home.settings(SetupClient::ClaudeCode);
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let moved = home.migrate();
    assert_eq!((moved.updated.as_slice(), failed_clients(&moved)), (&[][..], vec![SetupClient::ClaudeCode]));
    let reason = &moved.failed[0].1;
    assert!(reason.contains("symbolic link") && reason.contains("Set it up by hand in Settings → AI access"), "{reason}");
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&target).unwrap(), claude_1_14_4("lunport", &home.old_exe()));
    assert!(!home.data().exists(), "nothing was backed up");
    // Set up by hand, it starts this version under the current name: nothing is left to say.
    fs::write(&target, serde_json::to_vec(&json!({"mcpServers": {"lunport": {"command": home.new_exe(), "args": ["--mcp"]}}})).unwrap())
        .unwrap();
    assert_eq!(home.migrate(), Moved::default());
}

/// Settings the setup does not edit that hold no earlier entry stay skipped: a link to settings with another server only, or with this
/// version's entry, and a link that leads nowhere.
#[cfg(unix)]
#[test]
fn links_to_settings_without_an_earlier_entry_stay_skipped() {
    let home = Home::new();
    let link = |client: SetupClient, target: &Path, bytes: Option<&[u8]>| {
        if let Some(bytes) = bytes {
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, bytes).unwrap();
        }
        let path = home.settings(client);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, &path).unwrap();
    };
    let dotfiles = home.temp.path().join("dotfiles");
    link(SetupClient::Codex, &dotfiles.join("config.toml"), Some(b"[mcp_servers.other]\ncommand = \"other-server\"\nargs = []\n"));
    let current = serde_json::to_vec(&json!({"mcpServers": {"lunport": {"command": home.new_exe(), "args": ["--mcp"]}}})).unwrap();
    link(SetupClient::ClaudeCode, &dotfiles.join("claude.json"), Some(&current));
    link(SetupClient::ClaudeDesktop, &dotfiles.join("gone.json"), None);
    assert_eq!(home.migrate(), Moved::default());
}

/// Something in a settings file's place that is not a regular file holds no entry to read: a folder, or a named pipe, which is never
/// opened (it would wait for a writer).
#[cfg(unix)]
#[test]
fn settings_that_are_not_regular_files_are_skipped_without_waiting() {
    use std::os::unix::ffi::OsStrExt;
    let home = Home::new();
    fs::create_dir_all(home.settings(SetupClient::Codex)).unwrap();
    let pipe = home.settings(SetupClient::ClaudeCode);
    fs::create_dir_all(pipe.parent().unwrap()).unwrap();
    let name = std::ffi::CString::new(pipe.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (files, new_exe, data) = (home.files(), home.new_exe(), home.data());
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || sender.send(migrate_files(&files, &new_exe, &data).unwrap()).unwrap());
    let moved = receiver.recv_timeout(std::time::Duration::from_secs(10)).expect("the move waited for the named pipe");
    assert_eq!(moved, Moved::default());
}

/// Settings too large for the setup (Claude Code's file grows with its history) are reported while they hold an earlier entry, and
/// skipped once they hold none; nothing in them changes.
#[test]
fn settings_too_large_for_the_setup_are_reported_while_they_hold_an_earlier_entry() {
    let home = Home::new();
    let large = |servers: Value| serde_json::to_vec(&json!({"mcpServers": servers, "history": "x".repeat(9 * 1024 * 1024)})).unwrap();
    let before = large(json!({"sshelter": {"command": home.old_exe(), "args": ["--mcp"]}}));
    home.write(SetupClient::ClaudeCode, &before);
    let moved = home.migrate();
    assert_eq!((moved.updated.as_slice(), failed_clients(&moved)), (&[][..], vec![SetupClient::ClaudeCode]));
    let reason = &moved.failed[0].1;
    assert!(reason.contains("too large") && reason.contains("Set it up by hand in Settings → AI access"), "{reason}");
    assert_eq!(home.read(SetupClient::ClaudeCode), before);
    assert!(!home.data().exists(), "nothing was backed up");
    home.write(SetupClient::ClaudeCode, &large(json!({"other": {"command": "other-server", "args": ["--mcp"]}})));
    assert_eq!(home.migrate(), Moved::default());
}

/// What cannot be read now may be readable on a later start (Claude Code rewrites its file while it runs): it is reported, and the
/// other clients move meanwhile.
#[cfg(unix)]
#[test]
fn settings_that_cannot_be_read_are_reported_after_the_others_moved() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let home = Home::new();
    home.write(SetupClient::Codex, codex_1_14_4("lunport", &home.old_exe()).as_bytes());
    home.write(SetupClient::ClaudeCode, &claude_1_14_4("lunport", &home.old_exe()));
    let claude = home.settings(SetupClient::ClaudeCode);
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o000)).unwrap();
    let moved = home.migrate();
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(moved.updated, [SetupClient::Codex]);
    assert_eq!(moved.failed.iter().map(|(client, _)| *client).collect::<Vec<_>>(), [SetupClient::ClaudeCode]);
    let reason = &moved.failed[0].1;
    assert!(reason.starts_with("Its settings file could not be read: ") && !reason.contains("io error"), "{reason}");
    assert_eq!(home.read(SetupClient::ClaudeCode), claude_1_14_4("lunport", &home.old_exe()));
}

/// What cannot be written is reported and tried again on a later start; the clients that moved are reported too.
#[cfg(unix)]
#[test]
fn settings_that_cannot_be_written_fail_after_the_others_moved() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    home.write(SetupClient::Codex, codex_1_14_4("lunport", &home.old_exe()).as_bytes());
    home.write(SetupClient::ClaudeCode, &claude_1_14_4("lunport", &home.old_exe()));
    fs::set_permissions(home.settings(SetupClient::ClaudeCode), fs::Permissions::from_mode(0o400)).unwrap();
    let moved = home.migrate();
    assert_eq!(moved.updated, [SetupClient::Codex]);
    assert_eq!(moved.failed.len(), 1);
    assert_eq!(moved.failed[0].0, SetupClient::ClaudeCode);
    assert_eq!(moved.failed[0].1, "Its settings file is read-only. Make it writable, or set it up by hand in Settings → AI access.");
    assert_eq!(
        String::from_utf8(home.read(SetupClient::Codex)).unwrap(),
        codex_1_14_4("lunport", home.new_exe().to_str().unwrap())
    );
    assert_eq!(home.read(SetupClient::ClaudeCode), claude_1_14_4("lunport", &home.old_exe()));
}

/// A journal whose data root is in place.
fn moved_journal() -> Journal {
    let mut journal = Journal::default();
    journal.set(Step::DataRoot, StepState::Done);
    journal
}

/// The step waits for the data root, where the backups go: nothing is looked at before it is in place.
#[test]
fn the_step_waits_for_the_data_root() {
    let mut journal = Journal::default();
    assert_eq!(step(&mut journal, || panic!("nothing moves before the data root")), StepState::Pending);
    assert_eq!(journal.mcp_progress, McpProgress::default());
}

/// Every attempt adds the clients it updated to those before it, each named once in the order it moved, and the step stays for the
/// next start while a client fails; the clients that failed are those of the last attempt.
#[test]
fn the_step_names_every_client_moved_and_is_done_once_none_failed() {
    let mut journal = moved_journal();
    let state = step(&mut journal, || {
        Ok(Moved { updated: vec![SetupClient::Codex], failed: vec![(SetupClient::ClaudeCode, "the file is busy".into())] })
    });
    assert!(matches!(&state, StepState::Failed(reason) if reason.contains("Claude Code (the file is busy)")), "{state:?}");
    let failed = McpFailure { client: Some(SetupClient::ClaudeCode), reason: "the file is busy".into() };
    assert_eq!(journal.mcp_progress, McpProgress { updated: vec![SetupClient::Codex], failed: vec![failed], dismissed: None });

    let state = step(&mut journal, || Ok(Moved { updated: vec![SetupClient::ClaudeCode, SetupClient::Codex], failed: vec![] }));
    assert_eq!(state, StepState::Done);
    let both = McpProgress { updated: vec![SetupClient::Codex, SetupClient::ClaudeCode], failed: vec![], dismissed: None };
    assert_eq!(journal.mcp_progress, both);
}

/// An attempt that could not look at any client (no home folder, an installation path client settings cannot hold) is recorded as one
/// failure naming the cause, so that the notice says it; what earlier attempts moved stays named.
#[test]
fn an_attempt_that_could_not_look_at_any_client_is_recorded() {
    let mut journal = moved_journal();
    journal.mcp_progress.updated.push(SetupClient::Codex);
    let state = step(&mut journal, || Err(AppError::Other("This installation path cannot be represented in client settings.".into())));
    let reason = "Lunport could not check the AI tools' settings: This installation path cannot be represented in client settings.";
    assert_eq!(state, StepState::Failed(reason.into()));
    assert_eq!(journal.mcp_progress.failed, [McpFailure { client: None, reason: reason.into() }]);
    assert_eq!(journal.mcp_progress.updated, [SetupClient::Codex]);
    let io = AppError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"));
    step(&mut journal, || Err(io));
    assert_eq!(journal.mcp_progress.failed[0].reason, "Lunport could not check the AI tools' settings: no such file");
}

/// The setup's own wording, made for its settings page, and an I/O error's prefix give way to the notice's.
#[test]
fn reasons_are_said_in_the_notices_words() {
    let io = || AppError::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied (os error 13)"));
    assert_eq!(failure_reason(io(), false), "Its settings file could not be read: Permission denied (os error 13).");
    assert_eq!(failure_reason(io(), true), "Its settings file could not be changed: Permission denied (os error 13).");
    assert_eq!(
        failure_reason(AppError::Other(mcp_setup::SETTINGS_CHANGED.into()), true),
        "Its settings file changed while Lunport was updating it."
    );
    assert_eq!(
        failure_reason(AppError::Other(mcp_setup::READ_ONLY.into()), true),
        "Its settings file is read-only. Make it writable, or set it up by hand in Settings → AI access."
    );
    assert_eq!(failure_reason(AppError::Other("something else".into()), true), "something else");
}

/// A reason as long as an error can make it is cut to what the journal keeps.
#[test]
fn a_long_reason_is_cut_to_what_the_journal_keeps() {
    let mut journal = moved_journal();
    let long = "x".repeat(10_000);
    let state = step(&mut journal, || Ok(Moved { updated: vec![], failed: vec![(SetupClient::Codex, long.clone())] }));
    let StepState::Failed(summary) = state else { panic!("{state:?}") };
    assert!(summary.chars().count() <= MAX_REASON, "{}", summary.len());
    let kept = &journal.mcp_progress.failed[0].reason;
    assert!(kept.chars().count() <= MAX_REASON && kept.ends_with('…'), "{}", kept.len());
}

/// What the window says of the MCP settings, by the journal: after an upgrade, the reminder with what the step did so far, until the
/// user dismisses it; afterwards only a client that newly fails (`None`: the whole attempt) brings it back.
#[test]
fn the_notice_follows_the_journal_and_the_users_dismissal() {
    let failure = |client: Option<SetupClient>| McpFailure { client, reason: "busy".into() };
    assert_eq!(notice(&Journal::default()), None, "no data root moved here");
    let mut journal = moved_journal();
    assert_eq!(notice(&journal), Some(McpNotice { updated: vec![], failed: vec![] }), "the reminder alone");
    journal.mcp_progress.updated.push(SetupClient::ClaudeDesktop);
    journal.mcp_progress.failed.push(failure(Some(SetupClient::Codex)));
    let said = Some(McpNotice { updated: vec![SetupClient::ClaudeDesktop], failed: vec![failure(Some(SetupClient::Codex))] });
    assert_eq!(notice(&journal), said);
    journal.mcp_progress.dismissed = Some(vec![Some(SetupClient::Codex)]);
    assert_eq!(notice(&journal), None, "dismissed with this failure in view");
    journal.mcp_progress.failed = vec![];
    assert_eq!(notice(&journal), None, "nothing fails any more");
    journal.mcp_progress.failed = vec![failure(None)];
    assert_eq!(notice(&journal).map(|notice| notice.failed), Some(vec![failure(None)]), "the whole attempt newly failed");
    journal.mcp_progress.dismissed = Some(vec![None]);
    assert_eq!(notice(&journal), None);
}
