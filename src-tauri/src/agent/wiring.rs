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

/// 以空白為界的 agent token 在 `text` 裡的位置(同 `split_whitespace` 斷詞:前後都是空白或字串的頭尾)。
fn standalone_agent_token(text: &str) -> Option<usize> {
    text.match_indices(INCLUDE_TOKEN).map(|(at, _)| at).find(|&at| {
        text[..at].chars().next_back().is_none_or(char::is_whitespace) && text[at + INCLUDE_TOKEN.len()..].chars().next().is_none_or(char::is_whitespace)
    })
}

/// 把 `value`(一行 Include 的值)裡每個 agent 的 token 剪掉,連同它前面的那一段空白(排在最前面的,連同後面的那一段):別的路徑、它們之間的空白(tab、
/// 連續的空格)、帶引號而且路徑裡有空格的,一個位元組都不動 —— 不是把剩下的 token 用單一空格重新接起來。整行只有它就剪成空字串。
fn without_agent_tokens(value: &str) -> String {
    let mut text = value.to_string();
    while let Some(at) = standalone_agent_token(&text) {
        let end = at + INCLUDE_TOKEN.len();
        let (from, to) = if at > 0 { (text[..at].trim_end().len(), end) } else { (0, text.len() - text[end..].trim_start().len()) };
        text.replace_range(from..to, "");
    }
    text
}

/// 抽走 `items`(含區塊裡的行)每一行生效中的 `Include` 的 agent token:整行只有它就移除整行,一起列著的別的路徑留在原地、位元組不動(`without_agent_tokens`;
/// 同 `hosts_file::ensure_include`:使用者的 Include 不能因為我們搬動自己的 token 而不見或被改寫)。
fn take_agent_tokens(items: &mut Vec<Item>) {
    for i in (0..items.len()).rev() {
        let emptied = match &mut items[i] {
            Item::Host(h) => {
                take_agent_tokens(&mut h.body);
                false
            }
            Item::Match(m) => {
                take_agent_tokens(&mut m.body);
                false
            }
            Item::Directive(d) if lists_agent_token(d) => {
                let rest = without_agent_tokens(&d.value);
                if rest.is_empty() {
                    true
                } else {
                    // 縮排、分隔符、行尾註解與行尾的 CR 都在欄位裡,`dirty` 重新組出來的就是原來的那一行少了我們的 token。
                    d.value = rest;
                    d.dirty = true;
                    d.enabled = true; // 它是生效中的一行;標成 dirty 之後仍要寫成生效的一行,不能變成註解
                    false
                }
            }
            _ => false,
        };
        if emptied {
            items.remove(i);
        }
    }
}

/// 把 agent 的 Include 放在 `items` 的第 0 項:第 0 項已經只列我們的 token、別處(含區塊裡)也沒有它的 token 就不動(回傳 false);第 0 項只列我們的 token、別處還有,
/// 就只清掉別處的(第 0 項連同使用者加在那一行的空白與註解原樣留著)。其他情形 —— 第 0 項是別的東西,或除了我們的 token 還列著使用者的路徑 —— 把每一行裡我們的 token
/// 抽走(別的路徑留在原地、位元組不動),再把只有我們 token 的一行插到最前面:使用者的那一行接在它後面,同步的 Include 才排得進它們之間(同步檔先讀,spec §10)。
/// CRLF 的檔案插入 CRLF 的一行;空檔案加上結尾換行。
pub fn ensure_include_first(items: &mut Vec<Item>, trailing_newline: &mut bool) -> bool {
    let first_is_only_ours = matches!(items.first(), Some(Item::Directive(d)) if lists_agent_token(d) && d.value.split_whitespace().eq([INCLUDE_TOKEN]));
    if first_is_only_ours {
        if agent_tokens_in(&items[1..]) == 0 {
            return false;
        }
        let mut rest = items.split_off(1);
        take_agent_tokens(&mut rest);
        items.append(&mut rest);
        return true;
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

/// 重寫 `agent/config`(內容有變才寫),第一次需要時在主 config 的第一行加上 Include。呼叫端持有 doc 與 backed_up 的鎖。
///
/// `agent/config` 只在 Include 已經放好之後(或載入的不是預設的 config)才寫,所以它存在就表示 Include 放過,之後不見了是使用者拿掉的,不自動加回。第一次放不進去
/// (主 config 在載入之後被外部改過的 `Conflict`、備份或 I/O 錯誤)就回 Err,`agent/config` 還不存在,下一次 refresh 當成第一次重試 —— 不會被誤認成使用者拿掉了。
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
    // agent/config 只在 Include 已經放好之後(或載入的不是預設的 config)才寫:它存在就表示 Include 放過,之後不見了是使用者拿掉的(spec §6、§11)。
    let wired = config_path.exists();
    if patterns.is_empty() && !wired {
        return Ok(WiringStatus::NotNeeded);
    }
    let default_root = home.join(".ssh").join("config");
    let on_default_root = doc.files.first().is_some_and(|f| f.path == default_root);
    let present = on_default_root && doc.files[0].items.iter().any(is_agent_include);
    let status = if !on_default_root {
        // 仍然寫 agent/config:提示(Task 11 的 `status`)要靠它知道需要接上。
        WiringStatus::IncludeMissing
    } else if present || !wired {
        // 寫不進去 → Err,agent/config 還不存在,下一次 refresh 當成第一次重試。
        put_include_first(doc, backed_up, retention)?;
        WiringStatus::Ready
    } else {
        // 使用者拿掉了:不自動加回。
        WiringStatus::IncludeMissing
    };
    let content = render(&patterns, endpoint);
    if std::fs::read_to_string(&config_path).ok().as_deref() != Some(content.as_str()) {
        slot_files::ensure_keys_dir(&agent_dir(home))?;
        crate::fsutil::atomic_write(&config_path, content.as_bytes(), 0o600)?;
    }
    Ok(status)
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

/// 同步執行緒與命令用:先拿 doc 與 backed_up 的鎖,再在鎖裡短暫拿 core 鎖讀保管庫的插槽檔名(doc 然後 core,`config::commands` 與存檔 hook 同一個順序),呼叫 `refresh`。
/// 插槽檔名不在 doc 鎖外先讀:兩邊同時更新時,後拿到 doc 鎖的那一個讀到的不會比先寫的那一個舊,`agent/config` 不會被過時的集合蓋回去。config 還沒載入就什麼都不做。
///
/// 主 config 在載入之後被外部改過、Include 存不進去(`Conflict`)時,把過期的 doc 整份重載(同 `files::prepare_files` 對同步自己的 Include),放掉所有鎖之後通知前端
/// (`applied(0)`),原本的錯誤照樣回給呼叫端記錄;下一次 refresh(下一次同步嘗試,或下一次改插槽的提供方式)就在新的 doc 上放得進去。
pub fn refresh_env(env: &SyncEnv) -> Result<WiringStatus, AppError> {
    let Some(home) = env.ssh_dir.parent().map(Path::to_path_buf) else { return Ok(WiringStatus::NotNeeded) };
    let endpoint = crate::agent::identity_agent_value()?;
    let mut doc_lock = env.doc.lock().unwrap();
    let Some(doc) = doc_lock.as_mut() else { return Ok(WiringStatus::NotNeeded) };
    let mut backed_up = env.backed_up.lock().unwrap();
    let retention = env.retention();
    let vault_files = env.runtime.core.lock().unwrap().state.as_ref().map(crate::sync::slots::vault_slot_files).unwrap_or_default();
    let error = match refresh(doc, &mut backed_up, retention, &home, &vault_files, &endpoint) {
        Err(error @ AppError::Conflict(_)) => error,
        other => return other,
    };
    // 磁碟上的主 config 沒動,in-memory 的也已退回原樣(`put_include_first`);整份重載讓 doc 回到磁碟上的內容。重載不了就清掉 doc(前端重新載入之前什麼都不寫)。
    let Some(main) = doc_lock.as_ref().and_then(|doc| doc.files.first()).map(|file| file.path.clone()) else { return Err(error) };
    let error = match env.load_doc(&main) {
        Ok(fresh) => {
            *doc_lock = Some(fresh);
            error
        }
        Err(reload) => {
            *doc_lock = None;
            AppError::Other(format!("{error}; reloading the config afterwards also failed: {reload}"))
        }
    };
    drop(backed_up);
    drop(doc_lock);
    env.events.applied(0);
    Err(error)
}

/// 這台的 `ssh` 接不接得到 agent(畫面提示用;spec §6、§11):沒有主機用到只在 SSHelter 的金鑰、也從沒寫過 `agent/config` → NotNeeded;主 config
/// 是預設的 `~/.ssh/config` 而且有 agent 的 Include → Ready;其他(使用者拿掉了,或第一次一直加不進去 —— `agent/config` 要等 Include 放好才寫)→ IncludeMissing。
pub fn status(doc: &SshConfigDoc, home: &Path, vault_files: &BTreeSet<String>) -> WiringStatus {
    let needed = agent_config_path(home).exists() || !vault_host_patterns(doc, vault_files, home).is_empty();
    if !needed {
        return WiringStatus::NotNeeded;
    }
    let default_root = home.join(".ssh").join("config");
    match doc.files.first() {
        Some(main) if main.path == default_root && main.items.iter().any(is_agent_include) => WiringStatus::Ready,
        _ => WiringStatus::IncludeMissing,
    }
}

/// 使用者按 Fix:把 Include 放回 `~/.ssh/config` 的第一行(spec §6:不會自己加回去)。載入的主 config 不是預設的那一個 → 錯誤。
pub fn restore_include(
    doc: &mut SshConfigDoc,
    backed_up: &mut HashSet<PathBuf>,
    retention: Option<usize>,
    home: &Path,
) -> Result<(), AppError> {
    let default_root = home.join(".ssh").join("config");
    if doc.files.first().map(|f| f.path.as_path()) != Some(default_root.as_path()) {
        return Err(AppError::Other("SSHelter isn't using ~/.ssh/config, so it can't add the line there.".to_string()));
    }
    put_include_first(doc, backed_up, retention)
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

    /// 搬動 agent 的 Include 時,使用者在同一行列的別的路徑不能不見(同 `hosts_file::ensure_include`)。
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
        // 重複列的 token 收成一個。
        assert_eq!(with_include(&format!("Include {ours} {ours}\nHost a\n")), format!("Include {ours}\nHost a\n"));
    }

    /// 一行 Include 裡我們的 token 和使用者的路徑並列:只剪掉我們的 token 與它前面的空白(排在最前面的,連同後面的空白),別的位元組 —— tab、連續的空格、
    /// 帶引號而且路徑裡有空格的、行尾註解、CRLF —— 一個都不動,不是把剩下的 token 用單一空格重新接起來。
    #[test]
    fn moving_the_include_leaves_the_users_other_bytes_on_a_shared_line_alone() {
        let ours = INCLUDE_TOKEN;
        let user = "~/.ssh/a.config\t\"~/my  dir/b.config\"";
        // 排在最後:tab 與引號裡的兩個空格都在。
        assert_eq!(
            with_include(&format!("AddKeysToAgent yes\nInclude {user} {ours} # note\nHost a\n")),
            format!("Include {ours}\nAddKeysToAgent yes\nInclude {user} # note\nHost a\n")
        );
        // 排在中間:前面的空白(tab 加空格)連它一起剪,後面的空白留著隔開兩邊。
        assert_eq!(
            with_include(&format!("Include ~/.ssh/a.config\t {ours} \t~/.ssh/c.config\nHost a\n")),
            format!("Include {ours}\nInclude ~/.ssh/a.config \t~/.ssh/c.config\nHost a\n")
        );
        // 區塊裡、CRLF:縮排、分隔符、行尾的 CR 都照舊。
        assert_eq!(
            with_include(&format!("Host a\r\n  Include={user}  {ours}\r\n  HostName x\r\n")),
            format!("Include {ours}\r\nHost a\r\n  Include={user}\r\n  HostName x\r\n")
        );
    }

    /// 剪 token 的規則:連同它前面的那一段空白剪掉(排在最前面的,連同後面的那一段),別的空白原樣;以空白為界的才算(`...config.bak`、前面黏著字的、帶引號的都不是)。
    #[test]
    fn only_our_token_and_the_whitespace_before_it_are_cut() {
        let ours = INCLUDE_TOKEN;
        for (value, expected) in [
            (ours.to_string(), ""),
            (format!("a {ours}"), "a"),
            (format!("{ours} a"), "a"),
            (format!("{ours} \t a"), "a"),
            (format!("a  {ours}  b"), "a  b"),
            (format!("a\t{ours} b"), "a b"),
            (format!("{ours} {ours} b"), "b"),
            (format!("a {ours} {ours}"), "a"),
            (format!("a {ours}.bak"), &format!("a {ours}.bak")),
            (format!("a x{ours}"), &format!("a x{ours}")),
            (format!("a \"{ours}\""), &format!("a \"{ours}\"")),
        ] {
            assert_eq!(without_agent_tokens(&value), expected, "{value:?}");
        }
    }

    /// 第 0 項除了我們的 token 還列著使用者的路徑:拆開 —— 我們的單獨一行放在最前面,使用者的那一行(原樣,只少了我們的 token)接在後面 —— 同步的 Include 才
    /// 排得進我們和使用者的檔案之間(同步檔先讀,spec §10)。第 0 項只有我們的 token 就留著不動,連同使用者加在那一行的空白與註解,別處多出來的才清掉。
    #[test]
    fn a_shared_first_line_is_split_and_a_lone_one_is_kept_as_the_user_wrote_it() {
        let ours = INCLUDE_TOKEN;
        let (mut items, mut trailing) = parse_file(&format!("Include {ours}  ~/.ssh/a.config # mine\nHost a\n"));
        assert!(ensure_include_first(&mut items, &mut trailing));
        assert_eq!(serialize_items(&items, trailing), format!("Include {ours}\nInclude ~/.ssh/a.config # mine\nHost a\n"));
        assert!(!ensure_include_first(&mut items, &mut trailing), "and then it is settled");
        // 同步的 Include 排在我們和使用者的那一行之間。
        let work = "~/.ssh/sshelter/work-3fa2c1d9.config".to_string();
        assert!(crate::sync::hosts_file::ensure_include(&mut items, &[work.clone()]));
        assert_eq!(serialize_items(&items, trailing), format!("Include {ours}\nInclude {work}\nInclude ~/.ssh/a.config # mine\nHost a\n"));

        // 第 0 項只有我們的 token:加了註解與空白的那一行原樣留著,別處多出來的(區塊裡的)才清掉。
        let (mut items, mut trailing) = parse_file(&format!("Include   {ours}   # keep\nHost a\n  Include {ours}\n"));
        assert!(ensure_include_first(&mut items, &mut trailing));
        assert_eq!(serialize_items(&items, trailing), format!("Include   {ours}   # keep\nHost a\n"));
        let (mut items, mut trailing) = parse_file(&format!("Include {ours} # keep\nHost a\n"));
        assert!(!ensure_include_first(&mut items, &mut trailing));
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

    /// 載入 `home/.ssh/config`(production 載入的主 config 就是這個路徑);`~` 指到 `home`。
    fn load_home(home: &Path) -> SshConfigDoc {
        let main = home.join(".ssh").join("config");
        crate::config::include::with_test_home(home, || crate::config::include::load_doc(&main)).unwrap()
    }

    /// 把 `text` 寫成 `home/.ssh/config` 再載入。
    fn load_home_config(home: &Path, text: &str) -> SshConfigDoc {
        let main = home.join(".ssh").join("config");
        std::fs::create_dir_all(main.parent().unwrap()).unwrap();
        std::fs::write(&main, text).unwrap();
        load_home(home)
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

        // agent/config 要等 Include 放好才寫:它存在就表示 Include 放過。第一次放不進去,它還不存在 —— 重載之後的下一次 refresh 當成第一次重試,
        // 不是以為「使用者拿掉了」而永遠停在 IncludeMissing。
        assert!(!agent_config_path(home.path()).exists(), "no agent config without its Include");
        let mut doc = load_home(home.path());
        assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::Ready);
        assert_eq!(read(&main_of(home.path())), format!("Include {INCLUDE_TOKEN}\n{edited}"));
        assert!(read(&agent_config_path(home.path())).contains("Host web\n  IdentityAgent "));
    }

    /// 使用者拿掉 Include 之後不會被加回去:agent/config 在了、Include 卻不在,就是他拿掉的(重載之後也一樣);agent/config 仍跟著主機重寫。
    #[test]
    fn a_removal_after_the_first_add_sticks() {
        let home = tempfile::tempdir().unwrap();
        let mut doc = load_home_config(home.path(), WEB);
        assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::Ready);
        std::fs::write(main_of(home.path()), WEB).unwrap();

        let mut doc = load_home(home.path());
        assert_eq!(refresh_at(home.path(), &mut doc, &vault()).unwrap(), WiringStatus::IncludeMissing);
        assert_eq!(refresh_at(home.path(), &mut doc, &BTreeSet::new()).unwrap(), WiringStatus::IncludeMissing);
        assert_eq!(read(&main_of(home.path())), WEB, "not added back");
        assert_eq!(read(&agent_config_path(home.path())), format!("{HEADER}\n"), "the agent config still follows the hosts");
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

    /// 只在 SSHelter 的插槽記錄(檔名 `file`)。
    fn vault_slot(file: &str) -> crate::sync::state_v2::LocalSlot {
        use crate::sync::state_v2::{LocalSlot, SlotSource};
        LocalSlot {
            file_name: file.to_string(),
            source: Some(SlotSource::Vault { fingerprint: "SHA256:x".into(), public_key: "ssh-ed25519 AAAA".into(), has_passphrase: false }),
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
        }
    }

    /// 這台把 `file` 這個插槽放進保管庫(只改狀態,不經過 `set_delivery`)。
    fn put_in_vault(d: &crate::sync::testkit::TestDevice, file: &str) {
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().key_slots.insert("slot".to_string(), vault_slot(file));
    }

    /// 第一次放 Include 時主 config 在載入之後被外部改過(存檔撞上 `Conflict`):記憶體裡的 doc 整份重載(同 `files::prepare_files` 對同步自己的 Include),
    /// 放掉所有鎖之後才通知(`applied(0)`,前端重讀),原本的錯誤照樣回給呼叫端記錄;下一次 refresh 就在新的 doc 上把 Include 放進去。
    #[test]
    fn a_stale_config_is_reloaded_when_the_include_cannot_be_saved() {
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{AppliedProbe, TestClock, TestDevice};
        let d = TestDevice::with_main_config("a", &FakeRelay::new(), &TestClock::new(), WEB);
        put_in_vault(&d, SLOT);
        let edited = format!("# edited elsewhere\n{WEB}");
        d.write_externally(&d.main_path(), &edited);

        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        let error = refresh_env(&env).unwrap_err();
        assert!(matches!(error, AppError::Conflict(_)), "the original error is returned: {error}");
        assert_eq!(*probe.all_free.lock().unwrap(), [true], "announced once, after every lock was released");
        assert_eq!(read(&d.main_path()), edited, "the edit made elsewhere is never overwritten");
        assert!(!agent_config_path(d.home.path()).exists(), "no agent config without its Include");
        {
            let doc = d.doc.lock().unwrap();
            let loaded = &doc.as_ref().expect("the config is loaded again").files[0];
            assert_eq!(serialize_items(&loaded.items, loaded.trailing_newline), edited, "the loaded copy is what is on disk now");
        }

        // 下一次(不必再手動重載)就放得進去。
        assert_eq!(refresh_env(&d.env()).unwrap(), WiringStatus::Ready);
        assert_eq!(read(&d.main_path()), format!("Include {INCLUDE_TOKEN}\n{edited}"));
        assert!(read(&agent_config_path(d.home.path())).contains("Host web\n  IdentityAgent "));
    }

    /// 重載也失敗(這裡是主 config 整個不見了,存檔的衝突保護把「檔案不見了」也當成 `Conflict`):doc 清掉 —— 前端重新載入之前什麼都不寫 —— 錯誤說明帶著兩個原因。
    #[test]
    fn a_config_that_cannot_be_loaded_again_is_cleared() {
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{AppliedProbe, TestClock, TestDevice};
        let d = TestDevice::with_main_config("a", &FakeRelay::new(), &TestClock::new(), WEB);
        put_in_vault(&d, SLOT);
        std::fs::remove_file(d.main_path()).unwrap();

        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        let error = refresh_env(&env).unwrap_err();
        assert!(error.to_string().contains("reloading the config afterwards also failed"), "{error}");
        assert_eq!(*probe.all_free.lock().unwrap(), [true]);
        assert!(d.doc.lock().unwrap().is_none(), "nothing is written until the config is loaded again");
        assert_eq!(refresh_env(&d.env()).unwrap(), WiringStatus::NotNeeded);
        assert!(!agent_config_path(d.home.path()).exists());
    }

    /// `refresh_env` 先拿 doc 鎖,再在鎖裡短暫拿 core 鎖讀保管庫的插槽檔名(doc 然後 core,`config::commands` 與存檔 hook 同一個順序):讀到的不會是比 doc 舊的集合,
    /// 拿它寫出去的 `agent/config` 也就不會過時。
    #[test]
    fn the_vault_slots_are_read_while_the_config_is_held() {
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let d = TestDevice::with_main_config("a", &FakeRelay::new(), &TestClock::new(), WEB);
        // 這台還沒有只在 SSHelter 的插槽。測試拿著 core 鎖,讓 refresh_env 停在要讀插槽檔名的那一刻。
        let mut core = d.runtime.core.lock().unwrap();
        let status = std::thread::scope(|scope| {
            let refresh = scope.spawn(|| refresh_env(&d.env()));
            let started = std::time::Instant::now();
            while d.doc.try_lock().is_ok() {
                assert!(started.elapsed() < std::time::Duration::from_secs(5), "refresh_env waited for core before it took the config lock");
                std::thread::yield_now();
            }
            // 它拿著 doc 鎖、被 core 鎖擋住:現在才把插槽放進保管庫(還握著 core 鎖)、再放掉 —— 它讀到的是新的。
            core.state.as_mut().unwrap().key_slots.insert("slot".to_string(), vault_slot(SLOT));
            drop(core);
            refresh.join().unwrap()
        });
        assert_eq!(status.unwrap(), WiringStatus::Ready, "it saw the slot that was put in the vault while it waited");
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

    fn loaded(home: &Path, text: &str) -> SshConfigDoc {
        let main = home.join(".ssh").join("config");
        std::fs::create_dir_all(main.parent().unwrap()).unwrap();
        std::fs::write(&main, text).unwrap();
        crate::config::include::with_test_home(home, || crate::config::commands::load_doc_migrated(&main)).unwrap()
    }

    #[test]
    fn status_tells_whether_ssh_reaches_the_agent() {
        let home = tempfile::tempdir().unwrap();
        let none = BTreeSet::new();
        let doc = loaded(home.path(), "Host a\n  HostName x\n");
        assert_eq!(status(&doc, home.path(), &none), WiringStatus::NotNeeded);
        // A host on a vault key, but the first Include add never succeeded (agent/config is only written after it).
        let vault = BTreeSet::from(["id_mac-11111111".to_string()]);
        let on_vault = loaded(home.path(), "Host a\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-11111111\n");
        assert_eq!(status(&on_vault, home.path(), &vault), WiringStatus::IncludeMissing, "needed but not wired yet");
        std::fs::create_dir_all(crate::agent::agent_dir(home.path())).unwrap();
        std::fs::write(agent_config_path(home.path()), format!("{HEADER}\n")).unwrap();
        assert_eq!(status(&doc, home.path(), &none), WiringStatus::IncludeMissing);
        let doc = loaded(home.path(), "Include ~/.ssh/sshelter/agent/config\nHost a\n");
        assert_eq!(status(&doc, home.path(), &none), WiringStatus::Ready);
    }

    #[test]
    fn fix_puts_the_include_back_first_once_and_saves() {
        let home = tempfile::tempdir().unwrap();
        let mut doc = loaded(home.path(), "# mine\nHost a\n  HostName x\n");
        let mut backed_up = HashSet::new();
        restore_include(&mut doc, &mut backed_up, None, home.path()).unwrap();
        let main = home.path().join(".ssh").join("config");
        assert_eq!(std::fs::read_to_string(&main).unwrap(), "Include ~/.ssh/sshelter/agent/config\n# mine\nHost a\n  HostName x\n");
        restore_include(&mut doc, &mut backed_up, None, home.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&main).unwrap().matches("sshelter/agent/config").count(), 1);
    }
}
