//! `ssh` 怎麼找到 SSHelter 的 agent(金鑰保管庫 spec §6):`~/.ssh/sshelter/agent/config` 只列用到「只在 SSHelter」插槽的主機,
//! 每個 Host 區塊設 `IdentityAgent` 與 `IdentitiesOnly yes`;`~/.ssh/config` 的第一行 Include 它(ssh_config 取第一個符合的值)。
//! 這個檔案在子目錄裡:同步把 `~/.ssh/sshelter/<名稱>.config` 當成 space 檔,子目錄裡的不碰(`hosts_file::is_our_include_token`)。
//! SSHelter 讀取 config 時略過它(`config::include::load_recursive`),主機清單才不會重複。

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use crate::agent::agent_dir;
use crate::config::commands::persist_file;
use crate::config::model::{Directive, Item, SshConfigDoc};
use crate::config::parser::parse_file;
use crate::error::AppError;
use crate::sync::env::SyncEnv;
use crate::sync::slot_files;
use crate::sync::slot_rules::{resolve_identity_value, IdentityTarget};

pub const INCLUDE_TOKEN: &str = "~/.ssh/sshelter/agent/config";
pub const HEADER: &str = "# Managed by SSHelter. Changes here are overwritten.";

pub fn agent_config_path(home: &Path) -> PathBuf {
    agent_dir(home).join("config")
}

pub fn is_agent_include_token(token: &str) -> bool {
    token == INCLUDE_TOKEN
}

/// 一行生效中的 `Include`(不論在 top-level 還是區塊裡),列有 agent 的 token。
fn lists_agent_token(d: &Directive) -> bool {
    d.key == "include" && !d.serializes_as_comment() && d.value.split_whitespace().any(is_agent_include_token)
}

/// 生效中的 top-level `Include`,而且含有 agent 的 token。
pub fn is_agent_include(item: &Item) -> bool {
    matches!(item, Item::Directive(d) if lists_agent_token(d))
}

/// 用到「只在 SSHelter」插槽(`vault_files` 是插槽檔名)的 Host 區塊的 pattern,依出現順序,重複的只留一次。註解掉的 Host 與 `IdentityFile`
/// 不算;`Match` 區塊不支援(spec §6)。
pub fn vault_host_patterns(doc: &SshConfigDoc, vault_files: &BTreeSet<String>, home: &Path) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    for file in &doc.files {
        for item in &file.items {
            let Item::Host(host) = item else { continue };
            if host.header.serializes_as_comment() {
                continue;
            }
            let uses_vault = host.body.iter().any(|line| {
                matches!(line, Item::Directive(d) if d.key == "identityfile"
                    && !d.serializes_as_comment()
                    && matches!(resolve_identity_value(&d.value, home), IdentityTarget::Slot(f) if vault_files.contains(&f)))
            });
            if uses_vault && !out.contains(&host.patterns) {
                out.push(host.patterns.clone());
            }
        }
    }
    out
}

/// `agent/config` 的內容。`endpoint` = `IdentityAgent` 的值(`crate::agent::identity_agent_value`)。
pub fn render(patterns: &[Vec<String>], endpoint: &str) -> String {
    let mut out = format!("{HEADER}\n");
    for host in patterns {
        out.push_str(&format!("Host {}\n  IdentityAgent {endpoint}\n  IdentitiesOnly yes\n", host.join(" ")));
    }
    out
}

/// `items`(含 Host / Match 區塊裡的行)裡生效中的 `Include` 一共列了幾個 agent 的 token。
fn agent_tokens_in(items: &[Item]) -> usize {
    items
        .iter()
        .map(|item| match item {
            Item::Directive(d) if lists_agent_token(d) => d.value.split_whitespace().filter(|t| is_agent_include_token(t)).count(),
            Item::Host(h) => agent_tokens_in(&h.body),
            Item::Match(m) => agent_tokens_in(&m.body),
            _ => 0,
        })
        .sum()
}

/// 抽走 `items`(含區塊裡的行)每一行生效中的 `Include` 的 agent token:整行只有它就移除整行,一起列著的別的路徑留在原地(同
/// `hosts_file::ensure_include`:使用者的 Include 不能因為我們搬動自己的 token 而不見)。
fn take_agent_tokens(items: &mut Vec<Item>) {
    for i in (0..items.len()).rev() {
        let rest: Vec<String> = match &mut items[i] {
            Item::Host(h) => {
                take_agent_tokens(&mut h.body);
                continue;
            }
            Item::Match(m) => {
                take_agent_tokens(&mut m.body);
                continue;
            }
            Item::Directive(d) if lists_agent_token(d) => {
                d.value.split_whitespace().filter(|t| !is_agent_include_token(t)).map(str::to_string).collect()
            }
            _ => continue,
        };
        if rest.is_empty() {
            items.remove(i);
        } else if let Item::Directive(d) = &mut items[i] {
            d.value = rest.join(" ");
            d.dirty = true;
            d.enabled = true; // 它是生效中的一行;標成 dirty 之後仍要寫成生效的一行,不能變成註解
        }
    }
}

/// 把 agent 的 Include 放在 `items` 的第 0 項:第 0 項已經是它(ssh 先讀它)、別處(含區塊裡)也沒有它的 token 就不動(回傳 false);其他位置的
/// 一併抽走再插到最前面。CRLF 的檔案插入 CRLF 的一行;空檔案加上結尾換行。
pub fn ensure_include_first(items: &mut Vec<Item>, trailing_newline: &mut bool) -> bool {
    let first = matches!(items.first(), Some(Item::Directive(d)) if lists_agent_token(d) && d.value.split_whitespace().next().is_some_and(is_agent_include_token));
    if first && agent_tokens_in(items) == 1 {
        return false;
    }
    let crlf = items.iter().any(|item| match item {
        Item::Blank(s) | Item::Comment(s) => s.ends_with('\r'),
        Item::Directive(d) => d.raw.ends_with('\r'),
        Item::Host(h) => h.header.raw.ends_with('\r'),
        Item::Match(m) => m.header.raw.ends_with('\r'),
    });
    let was_empty = items.is_empty();
    take_agent_tokens(items);
    let (mut line, _) = parse_file(&format!("Include {INCLUDE_TOKEN}{}\n", if crlf { "\r" } else { "" }));
    items.insert(0, line.remove(0));
    if was_empty {
        *trailing_newline = true;
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WiringStatus {
    /// 這台沒有任何主機用到只在 SSHelter 的金鑰,也從沒寫過 `agent/config`。
    NotNeeded,
    Ready,
    /// `agent/config` 在,`~/.ssh/config` 卻沒有它的 Include(使用者拿掉了,或載入的不是預設的 config):不自動加回(spec §6、§11)。
    IncludeMissing,
}

/// 重寫 `agent/config`(內容有變才寫),第一次寫時在主 config 的第一行加上 Include。呼叫端持有 doc 與 backed_up 的鎖。
pub fn refresh(
    doc: &mut SshConfigDoc,
    backed_up: &mut HashSet<PathBuf>,
    retention: Option<usize>,
    home: &Path,
    vault_files: &BTreeSet<String>,
    endpoint: &str,
) -> Result<WiringStatus, AppError> {
    let patterns = vault_host_patterns(doc, vault_files, home);
    let config_path = agent_config_path(home);
    let first_time = !config_path.exists();
    if patterns.is_empty() && first_time {
        return Ok(WiringStatus::NotNeeded);
    }
    let content = render(&patterns, endpoint);
    if std::fs::read_to_string(&config_path).ok().as_deref() != Some(content.as_str()) {
        slot_files::ensure_keys_dir(&agent_dir(home))?;
        crate::fsutil::atomic_write(&config_path, content.as_bytes(), 0o600)?;
    }
    let default_root = home.join(".ssh").join("config");
    let Some(main) = doc.files.first() else { return Ok(WiringStatus::IncludeMissing) };
    if main.path != default_root {
        return Ok(WiringStatus::IncludeMissing);
    }
    let present = main.items.iter().any(is_agent_include);
    if !present && !first_time {
        return Ok(WiringStatus::IncludeMissing);
    }
    put_include_first(doc, backed_up, retention)?;
    Ok(WiringStatus::Ready)
}

/// 把 agent 的 Include 放在主 config(`doc.files[0]`)的第 0 項並存檔;已經在那裡就什麼都不做。存檔失敗時記憶體裡的 doc 復原。
fn put_include_first(doc: &mut SshConfigDoc, backed_up: &mut HashSet<PathBuf>, retention: Option<usize>) -> Result<(), AppError> {
    let mut items = doc.files[0].items.clone();
    let mut trailing = doc.files[0].trailing_newline;
    if !ensure_include_first(&mut items, &mut trailing) {
        return Ok(());
    }
    let saved = (std::mem::replace(&mut doc.files[0].items, items), doc.files[0].trailing_newline);
    doc.files[0].trailing_newline = trailing;
    if let Err(e) = persist_file(doc, 0, backed_up, retention) {
        doc.files[0].items = saved.0;
        doc.files[0].trailing_newline = saved.1;
        return Err(e);
    }
    Ok(())
}

/// 同步執行緒與命令用:取保管庫的插槽檔名(只短暫拿 core 鎖),再拿 doc 與 backed_up 的鎖呼叫 `refresh`。config 還沒載入就什麼都不做。
pub fn refresh_env(env: &SyncEnv) -> Result<WiringStatus, AppError> {
    let Some(home) = env.ssh_dir.parent().map(Path::to_path_buf) else { return Ok(WiringStatus::NotNeeded) };
    let vault_files = env
        .runtime
        .core
        .lock()
        .unwrap()
        .state
        .as_ref()
        .map(crate::sync::slots::vault_slot_files)
        .unwrap_or_default();
    let endpoint = crate::agent::identity_agent_value()?;
    let mut doc_lock = env.doc.lock().unwrap();
    let Some(doc) = doc_lock.as_mut() else { return Ok(WiringStatus::NotNeeded) };
    let mut backed_up = env.backed_up.lock().unwrap();
    refresh(doc, &mut backed_up, env.retention(), &home, &vault_files, &endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::parse_file;
    use crate::config::serialize::serialize_items;

    const SOCK: &str = "~/.ssh/sshelter/agent/sock";

    fn with_include(text: &str) -> String {
        let (mut items, mut trailing) = parse_file(text);
        assert!(ensure_include_first(&mut items, &mut trailing));
        serialize_items(&items, trailing)
    }

    #[test]
    fn the_include_goes_first_and_nothing_else_changes() {
        assert_eq!(with_include(""), "Include ~/.ssh/sshelter/agent/config\n");
        assert_eq!(with_include("# mine\nHost a\n  HostName x\n"), "Include ~/.ssh/sshelter/agent/config\n# mine\nHost a\n  HostName x\n");
        assert_eq!(with_include("Host a\n  HostName x"), "Include ~/.ssh/sshelter/agent/config\nHost a\n  HostName x");
        assert_eq!(with_include("# c\r\nHost a\r\n"), "Include ~/.ssh/sshelter/agent/config\r\n# c\r\nHost a\r\n");
    }

    #[test]
    fn an_include_already_first_is_left_alone_and_others_move_to_the_top() {
        let (mut items, mut trailing) = parse_file("Include ~/.ssh/sshelter/agent/config\nHost a\n");
        assert!(!ensure_include_first(&mut items, &mut trailing));
        let (mut items, mut trailing) = parse_file("Host a\n  HostName x\nInclude ~/.ssh/sshelter/agent/config\n");
        assert!(ensure_include_first(&mut items, &mut trailing));
        assert_eq!(serialize_items(&items, trailing), "Include ~/.ssh/sshelter/agent/config\nHost a\n  HostName x\n");
    }

    #[test]
    fn agent_config_lists_only_hosts_on_vault_slots_with_their_patterns() {
        let home = Path::new("/h");
        let (items, trailing) = parse_file(
            "Host web\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111\n\
             Host *.lab !bastion.lab\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111\n\
             Host plain\n  IdentityFile ~/.ssh/id_rsa\n\
             Host other\n  IdentityFile ~/.ssh/sshelter/keys/other-22222222\n\
             Host off\n  #IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111\n\
             Host web\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111\n",
        );
        let doc = SshConfigDoc {
            files: vec![crate::config::model::ConfigFile {
                path: home.join(".ssh/config"),
                items,
                trailing_newline: trailing,
                // `Fingerprint` 沒有 `Default`:這個測試不讀也不寫檔,內容是什麼都無所謂。
                fingerprint: crate::fsutil::fingerprint_of(b""),
            }],
        };
        let vault = BTreeSet::from(["id_mac-11111111".to_string()]);
        let patterns = vault_host_patterns(&doc, &vault, home);
        assert_eq!(patterns, vec![vec!["web".to_string()], vec!["*.lab".to_string(), "!bastion.lab".to_string()]]);
        assert_eq!(
            render(&patterns, SOCK),
            "# Managed by SSHelter. Changes here are overwritten.\n\
             Host web\n  IdentityAgent ~/.ssh/sshelter/agent/sock\n  IdentitiesOnly yes\n\
             Host *.lab !bastion.lab\n  IdentityAgent ~/.ssh/sshelter/agent/sock\n  IdentitiesOnly yes\n"
        );
    }

    #[test]
    fn the_agent_include_token_is_recognised_exactly() {
        assert!(is_agent_include_token("~/.ssh/sshelter/agent/config"));
        assert!(!is_agent_include_token("~/.ssh/sshelter/agent/config.bak"));
        assert!(!is_agent_include_token("~/.ssh/sshelter/work-11111111.config"));
    }

    /// 搬動 agent 的 Include 時,使用者在同一行列的別的路徑不能不見(同 `hosts_file::ensure_include`);已經排在那一行最前面的不動。
    #[test]
    fn moving_the_include_keeps_the_other_paths_listed_with_it() {
        let ours = "~/.ssh/sshelter/agent/config";
        // 我們的 token 在別的路徑後面(ssh 會先讀別人的):抽出來放到最前面,別的路徑留在原地。
        assert_eq!(
            with_include(&format!("Include ~/.ssh/a.config {ours}\nHost a\n")),
            format!("Include {ours}\nInclude ~/.ssh/a.config\nHost a\n")
        );
        assert_eq!(
            with_include(&format!("AddKeysToAgent yes\nInclude {ours} ~/.ssh/a.config # mine\nHost a\n")),
            format!("Include {ours}\nAddKeysToAgent yes\nInclude ~/.ssh/a.config # mine\nHost a\n")
        );
        // 區塊裡的(Include 接在 Host / Match 之後會被 scope 進那個區塊,對其他主機沒有作用):抽走,別的行與別的路徑原封不動。
        assert_eq!(
            with_include(&format!("Host a\n  HostName x\n  Include ~/.ssh/b.config {ours}\nMatch all\n  Include {ours}\n  User u\n")),
            format!("Include {ours}\nHost a\n  HostName x\n  Include ~/.ssh/b.config\nMatch all\n  User u\n")
        );
        // 已經在第一行、而且排在那一行最前面:不動。
        let (mut items, mut trailing) = parse_file(&format!("Include {ours} ~/.ssh/a.config\nHost a\n"));
        assert!(!ensure_include_first(&mut items, &mut trailing));
        assert_eq!(serialize_items(&items, trailing), format!("Include {ours} ~/.ssh/a.config\nHost a\n"));
        // 重複列的 token 收成一個。
        assert_eq!(with_include(&format!("Include {ours} {ours}\nHost a\n")), format!("Include {ours}\nHost a\n"));
    }

    /// 註解掉的 Include(解析成註解,或被停用而序列化成註解的那一行)不算,也不被動到。
    #[test]
    fn a_commented_include_is_not_the_include() {
        let ours = "~/.ssh/sshelter/agent/config";
        assert_eq!(with_include(&format!("# Include {ours}\nHost a\n")), format!("Include {ours}\n# Include {ours}\nHost a\n"));
        let (mut items, mut trailing) = parse_file("Host a\n");
        let mut disabled = Directive::new("Include", ours, "");
        disabled.enabled = false;
        items.insert(0, Item::Directive(disabled));
        assert!(!is_agent_include(&items[0]));
        assert!(ensure_include_first(&mut items, &mut trailing));
        assert_eq!(serialize_items(&items, trailing), format!("Include {ours}\n# Include {ours}\nHost a\n"));
    }

    const SLOT: &str = "id_mac-11111111";
    const WEB: &str = "Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111\n";

    fn vault() -> BTreeSet<String> {
        BTreeSet::from([SLOT.to_string()])
    }

    /// 載入 `home/.ssh/config`(內容 `text`,production 載入的主 config 就是這個路徑);`~` 指到 `home`。
    fn load_home_config(home: &Path, text: &str) -> SshConfigDoc {
        let main = home.join(".ssh").join("config");
        std::fs::create_dir_all(main.parent().unwrap()).unwrap();
        std::fs::write(&main, text).unwrap();
        crate::config::include::with_test_home(home, || crate::config::include::load_doc(&main)).unwrap()
    }

    fn refresh_at(home: &Path, doc: &mut SshConfigDoc, vault_files: &BTreeSet<String>) -> Result<WiringStatus, AppError> {
        refresh(doc, &mut HashSet::new(), None, home, vault_files, SOCK)
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    fn main_of(home: &Path) -> PathBuf {
        home.join(".ssh").join("config")
    }

    /// 把檔案的修改時間設回很久以前:之後沒有被重寫,修改時間就還是那個值。
    fn age(path: &Path) {
        std::fs::File::options().write(true).open(path).unwrap().set_modified(std::time::UNIX_EPOCH).unwrap();
    }

    fn is_aged(path: &Path) -> bool {
        std::fs::metadata(path).unwrap().modified().unwrap() == std::time::UNIX_EPOCH
    }

    #[test]
    fn nothing_is_written_until_a_host_uses_a_vault_key() {
        let home = tempfile::tempdir().unwrap();
        let mut doc = load_home_config(home.path(), WEB);
        assert_eq!(refresh_at(home.path(), &mut doc, &BTreeSet::new()).unwrap(), WiringStatus::NotNeeded);
        assert!(!agent_dir(home.path()).exists(), "not even the directory");
        assert_eq!(read(&main_of(home.path())), WEB);
    }

    #[test]
    fn the_first_refresh_writes_the_agent_config_and_the_include_and_a_later_one_changes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let (config, main) = (agent_config_path(home.path()), main_of(home.path()));
        let mut doc = load_home_config(home.path(), &format!("# mine\n{WEB}"));
        assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::Ready);
        assert_eq!(read(&config), render(&[vec!["web".to_string()]], SOCK));
        assert_eq!(read(&main), format!("Include {INCLUDE_TOKEN}\n# mine\n{WEB}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!((mode(&config), mode(&agent_dir(home.path()))), (0o600, 0o700), "only this user reads the agent config");
        }

        age(&config);
        age(&main);
        assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::Ready);
        assert!(is_aged(&config) && is_aged(&main), "nothing changed, so nothing was written");
    }

    #[test]
    fn the_agent_config_follows_the_hosts_and_the_include_stays() {
        let home = tempfile::tempdir().unwrap();
        let mut doc = load_home_config(home.path(), WEB);
        assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::Ready);
        let with_include = read(&main_of(home.path()));

        // 主機不再用保管庫的金鑰:agent/config 只剩標頭,Include 留著。
        assert_eq!(refresh_at(home.path(), &mut doc, &BTreeSet::new()).unwrap(), WiringStatus::Ready);
        assert_eq!(read(&agent_config_path(home.path())), format!("{HEADER}\n"));
        assert_eq!(read(&main_of(home.path())), with_include);

        // 又用到了:寫回主機,Include 不必再動。
        age(&main_of(home.path()));
        assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::Ready);
        assert!(read(&agent_config_path(home.path())).contains("Host web\n  IdentityAgent "));
        assert!(is_aged(&main_of(home.path())), "the main config was not written again");
    }

    #[test]
    fn a_main_config_that_is_not_the_default_one_gets_no_include() {
        let home = tempfile::tempdir().unwrap();
        let other = home.path().join("elsewhere");
        std::fs::write(&other, WEB).unwrap();
        let mut doc = crate::config::include::with_test_home(home.path(), || crate::config::include::load_doc(&other)).unwrap();
        assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::IncludeMissing);
        assert_eq!(read(&other), WEB, "a config ssh does not read by default is left alone");
        assert!(agent_config_path(home.path()).is_file(), "the agent config is still written");
    }

    #[test]
    fn a_main_config_changed_since_it_was_loaded_is_never_overwritten() {
        let home = tempfile::tempdir().unwrap();
        let mut doc = load_home_config(home.path(), WEB);
        let loaded = serialize_items(&doc.files[0].items, doc.files[0].trailing_newline);
        let edited = format!("# edited elsewhere\n{WEB}");
        std::fs::write(main_of(home.path()), &edited).unwrap();

        let error = refresh_at(home.path(), &mut doc, &vault()).unwrap_err();
        assert!(matches!(error, AppError::Conflict(_)), "{error}");
        assert_eq!(read(&main_of(home.path())), edited, "the edit made elsewhere is still there");
        assert_eq!(serialize_items(&doc.files[0].items, doc.files[0].trailing_newline), loaded, "and the loaded copy is as it was");
    }

    #[test]
    fn a_crlf_config_gets_a_crlf_include_and_a_missing_final_newline_stays_missing() {
        let key = "IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111";
        for (text, expected) in [
            (format!("# c\r\nHost web\r\n  {key}\r\n"), format!("Include {INCLUDE_TOKEN}\r\n# c\r\nHost web\r\n  {key}\r\n")),
            (format!("Host web\n  {key}"), format!("Include {INCLUDE_TOKEN}\nHost web\n  {key}")),
            (format!("Host web\r\n  {key}"), format!("Include {INCLUDE_TOKEN}\r\nHost web\r\n  {key}")),
        ] {
            let home = tempfile::tempdir().unwrap();
            let mut doc = load_home_config(home.path(), &text);
            assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::Ready, "{text:?}");
            assert_eq!(std::fs::read(main_of(home.path())).unwrap(), expected.as_bytes(), "{text:?}");
        }
    }

    /// config 還沒載入(`doc` 是 None)就什麼都不做;載入了、也沒有用到保管庫的金鑰就一樣。
    #[test]
    fn refreshing_with_no_config_loaded_or_no_vault_key_does_nothing() {
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let d = TestDevice::new("a", &FakeRelay::new(), &TestClock::new());
        assert_eq!(refresh_env(&d.env()).unwrap(), WiringStatus::NotNeeded);
        *d.doc.lock().unwrap() = None;
        assert_eq!(refresh_env(&d.env()).unwrap(), WiringStatus::NotNeeded);
        let home = d.home.path();
        assert!(!agent_dir(home).exists());
        assert_eq!(std::fs::read_to_string(d.main_path()).unwrap(), "# main\n");
    }

    #[test]
    fn only_host_blocks_that_name_a_vault_slot_are_listed() {
        let home = Path::new("/h");
        let (items, trailing) = parse_file(
            "Host quoted\n  IdentityFile \"~/.ssh/sshelter/keys/id_mac-11111111\"\n\
             Host percent\n  IdentityFile %d/.ssh/sshelter/keys/id_mac-11111111\n\
             Host two\n  IdentityFile ~/.ssh/id_rsa\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111\n\
             Host pubkey\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111.pub\n\
             Match host lab\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111\n\
             Host none\n  HostName x\n",
        );
        let doc = SshConfigDoc {
            files: vec![crate::config::model::ConfigFile {
                path: home.join(".ssh/config"),
                items,
                trailing_newline: trailing,
                fingerprint: crate::fsutil::fingerprint_of(b""),
            }],
        };
        let listed: Vec<String> = vault_host_patterns(&doc, &vault(), home).into_iter().map(|patterns| patterns.join(" ")).collect();
        assert_eq!(listed, ["quoted", "percent", "two"], "a Match block is not supported, and a .pub path is not a slot");
    }
}
