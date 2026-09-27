//! 受管同步檔 `~/.ssh/sshelter/hosts.config`:同步範圍就是這個檔案裡的 Host 區塊。
//! 區塊以原始文字為單位進出(lossless),其他項目(註解、空行、wildcard)原封不動。

use std::path::{Path, PathBuf};

use crate::config::model::{Directive, Item};
use crate::config::parser::parse_file;
use crate::config::serialize::serialize_items;
use crate::error::AppError;
use crate::fsutil;

/// 寫進主 config 的 Include 值;`~` 在 macOS/Linux/Windows OpenSSH 皆可解析。
pub const INCLUDE_VALUE: &str = "~/.ssh/sshelter/hosts.config";

pub fn managed_path(ssh_dir: &Path) -> PathBuf {
    ssh_dir.join("sshelter").join("hosts.config")
}

/// 建立 `~/.ssh/sshelter/`(0700)與空的 `hosts.config`(0600);已存在則不動內容。
/// 存在與否用 `try_exists`:查不到 metadata(權限、I/O 錯誤)是錯誤,不是「不存在」—— 否則一次暫時的
/// stat 失敗就會用空檔蓋掉既有的同步檔(這條路徑不做備份)。
pub fn ensure_managed_file(ssh_dir: &Path) -> Result<PathBuf, AppError> {
    let path = managed_path(ssh_dir);
    let dir = path.parent().expect("managed path always has a parent");
    fsutil::ensure_dir_secure(dir)?;
    if !path.try_exists()? {
        fsutil::atomic_write(&path, b"", 0o600)?;
    }
    Ok(path)
}

fn is_our_include(item: &Item) -> bool {
    matches!(item, Item::Directive(d) if d.key == "include" && d.enabled && d.value.split_whitespace().any(|t| t == INCLUDE_VALUE))
}

/// 同步 Include 的位置:前導註解/空行之後、其他任何項目(既有 Include、全域指令、Host/Match)之前。
/// 刻意不用 `newfile::include_insert_index`(它插在最後一個 Include **之後**):ssh 是
/// first-obtained-wins,同步檔必須是第一個被讀到的定義,spec §10 的遮蔽承諾才成立。
fn sync_include_index(items: &[Item]) -> usize {
    items
        .iter()
        .position(|i| !matches!(i, Item::Blank(_) | Item::Comment(_)))
        .unwrap_or(items.len())
}

/// 主 config 的同步 Include 必須在最頂端(見 `sync_include_index`):沒有就插入;已存在但不在
/// 最頂端(舊版插法、使用者搬動)就搬上去 —— 多路徑的 `Include a b` 只抽走我們的 token。
/// 回傳是否改了 items。
pub fn ensure_include(items: &mut Vec<Item>) -> bool {
    let top = sync_include_index(items);
    // 「已經正確」= 在最頂端、而且那一行只有我們這一個路徑。多路徑的 `Include a ours` 就算在首行,
    // ssh 也會先讀 a —— 一律正規化成獨立的一行。
    let exact = |item: &Item| matches!(item, Item::Directive(d) if d.key == "include" && d.enabled && d.value.trim() == INCLUDE_VALUE);
    match items.iter().position(is_our_include) {
        Some(pos) if pos == top && exact(&items[pos]) => false,
        Some(pos) => {
            let leftover: Vec<String> = match &items[pos] {
                Item::Directive(d) => d
                    .value
                    .split_whitespace()
                    .filter(|t| *t != INCLUDE_VALUE)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            };
            if leftover.is_empty() {
                items.remove(pos);
            } else if let Item::Directive(d) = &mut items[pos] {
                d.value = leftover.join(" ");
                d.dirty = true;
            }
            // `pos >= top`(Include 是 Directive,不可能在前導註解區裡):移除或就地改寫都不影響 top。
            items.insert(top, Item::Directive(Directive::new("Include", INCLUDE_VALUE, "")));
            true
        }
        None => {
            items.insert(top, Item::Directive(Directive::new("Include", INCLUDE_VALUE, "")));
            true
        }
    }
}

/// 具名 pattern 才同步;含 wildcard/否定字元的 pattern(`*`、`*.internal`、`!x`)是裝置本地的 config 結構。
pub fn is_syncable_alias(alias: &str) -> bool {
    !alias.is_empty() && !alias.contains(['*', '?', '!'])
}

/// 整個區塊的同步資格:非空且**所有** pattern 都具名。`Host web *.internal` 的第一個 pattern 具名,
/// 但它是 wildcard 規則的一部分 —— 整個區塊不擷取、不上傳、不遷入、不套用、不刪除。
pub fn is_syncable_block(patterns: &[String]) -> bool {
    !patterns.is_empty() && patterns.iter().all(|p| is_syncable_alias(p))
}

fn first_alias(item: &Item) -> Option<&str> {
    match item {
        Item::Host(h) => h.patterns.first().map(String::as_str),
        _ => None,
    }
}

/// 第一個 pattern 等於 `alias` 的具名 Host 區塊位置。alias 本身是 wildcard、或本地那個同名區塊含
/// wildcard pattern(不能替換它、也不能在旁邊再附加一個 `Host alias`)→ Err;找不到 → Ok(None)。
fn syncable_host_position(items: &[Item], alias: &str) -> Result<Option<usize>, AppError> {
    if !is_syncable_alias(alias) {
        return Err(AppError::Other(format!("'{alias}' is a wildcard pattern; wildcard blocks are never synced")));
    }
    match items.iter().position(|i| first_alias(i) == Some(alias)) {
        Some(p) => match &items[p] {
            Item::Host(h) if is_syncable_block(&h.patterns) => Ok(Some(p)),
            _ => Err(AppError::Other(format!("local block '{alias}' has wildcard patterns and stays local"))),
        },
        None => Ok(None),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HostBlockText {
    pub alias: String,
    /// 區塊原始文字,含 header 與 body 所有行(含 `#tags:` 與尾隨空行)。
    pub text: String,
}

fn block_text(item: &Item) -> String {
    serialize_items(std::slice::from_ref(item), true)
}

/// 只取可同步的 Host 區塊(`is_syncable_block`);alias = 第一個 pattern。註解、空行、Match 與
/// 含 wildcard 的區塊一律略過。
pub fn blocks_of(items: &[Item]) -> Vec<HostBlockText> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Host(h) if is_syncable_block(&h.patterns) => h
                .patterns
                .first()
                .map(|alias| HostBlockText { alias: alias.clone(), text: block_text(item) }),
            _ => None,
        })
        .collect()
}

/// 文字必須「只」含一個 Host 區塊:夾帶 Match、全域指令或區塊外註解都拒絕 —— 否則套用後檔案裡只剩
/// Host,快取卻是完整文字,下一輪會把截斷結果當成本機修改重新上傳。
fn parse_single_host(alias: &str, text: &str) -> Result<Item, AppError> {
    let (parsed, _) = parse_file(text);
    let mut hosts = Vec::new();
    for item in parsed {
        match item {
            Item::Host(_) => hosts.push(item),
            _ => return Err(AppError::Other(format!("synced record for '{alias}' must contain nothing but one Host block"))),
        }
    }
    if hosts.len() != 1 {
        return Err(AppError::Other(format!("synced record for '{alias}' must contain exactly one Host block")));
    }
    let host = hosts.remove(0);
    match &host {
        Item::Host(h) if h.patterns.first().map(String::as_str) != Some(alias) => {
            Err(AppError::Other(format!("synced record for '{alias}' names a different host")))
        }
        Item::Host(h) if !is_syncable_block(&h.patterns) => {
            Err(AppError::Other(format!("synced record for '{alias}' contains wildcard patterns")))
        }
        _ => Ok(host),
    }
}

/// `apply_host_text` 對文字的全部要求,拆成純檢查:恰好一個 Host 區塊、第一個 pattern 等於 alias、
/// 所有 pattern 皆具名。A3 在合併前用它把壞掉的遠端記錄擋在快取外(否則套用失敗的記錄會在下一輪
/// 被當成本機刪除而產生 tombstone)。
pub fn validate_host_text(alias: &str, text: &str) -> Result<(), AppError> {
    if !is_syncable_alias(alias) {
        return Err(AppError::Other(format!("'{alias}' is a wildcard pattern; wildcard blocks are never synced")));
    }
    parse_single_host(alias, text).map(|_| ())
}

/// 以原始文字替換(或附加)一個具名 Host 區塊。回傳是否真的改了內容;wildcard alias、本地同名區塊
/// 含 wildcard、文字不合法都回 Err。
pub fn apply_host_text(items: &mut Vec<Item>, alias: &str, text: &str) -> Result<bool, AppError> {
    let pos = syncable_host_position(items, alias)?;
    let incoming = parse_single_host(alias, text)?;
    match pos {
        Some(p) => {
            if block_text(&items[p]) == block_text(&incoming) {
                return Ok(false);
            }
            items[p] = incoming;
            Ok(true)
        }
        None => {
            items.push(incoming);
            Ok(true)
        }
    }
}

/// 移除一個具名 Host 區塊;wildcard alias 或本地區塊含 wildcard 一律 false(tombstone 刪不到本地結構)。
pub fn remove_host_block(items: &mut Vec<Item>, alias: &str) -> bool {
    match syncable_host_position(items, alias) {
        Ok(Some(p)) => {
            items.remove(p);
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# synced by sshelter\n\nHost web-1\n  HostName 10.0.0.9\n  #tags: prod, web\n\nHost db-1\n  HostName 10.0.0.10\n";
    const WITH_WILDCARD: &str = "Host *\n  ServerAliveInterval 30\n\nHost web-1\n  HostName 10.0.0.9\n\nHost *.internal !bad.internal\n  User ops\n";

    #[test]
    fn managed_path_lives_under_ssh_dir() {
        let p = managed_path(Path::new("/home/f/.ssh"));
        assert_eq!(p, Path::new("/home/f/.ssh").join("sshelter").join("hosts.config"));
    }

    #[test]
    fn ensure_managed_file_creates_dir_and_empty_file_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = ensure_managed_file(dir.path()).unwrap();
        assert!(p.is_file());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "");
        std::fs::write(&p, "Host keep\n").unwrap();
        ensure_managed_file(dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "Host keep\n");
    }

    #[test]
    fn ensure_include_goes_to_the_very_top_and_is_idempotent() {
        // 前導註解/空行之後、既有 Include 與全域指令之前:同步檔必須是 ssh 第一個讀到的定義
        // (first-obtained-wins),spec §10 的「同步主機遮蔽本地同名主機」才成立。
        let (mut items, _) = parse_file("# main\n\nInclude ~/.ssh/other.config\nAddKeysToAgent yes\nHost a\n  HostName 1\n");
        assert!(ensure_include(&mut items));
        assert!(!ensure_include(&mut items));
        let text = serialize_items(&items, true);
        assert_eq!(
            text,
            format!("# main\n\nInclude {INCLUDE_VALUE}\nInclude ~/.ssh/other.config\nAddKeysToAgent yes\nHost a\n  HostName 1\n")
        );
        // 空檔:就是第一行。
        let (mut empty, _) = parse_file("");
        assert!(ensure_include(&mut empty));
        assert_eq!(serialize_items(&empty, true), format!("Include {INCLUDE_VALUE}\n"));
    }

    #[test]
    fn ensure_include_moves_an_existing_include_to_the_top() {
        // 舊版插法(最後一個 Include 之後)或使用者搬動過:搬到最頂端,其他行原封不動。
        let (mut items, _) = parse_file("Include ~/.ssh/other.config\nInclude ~/.ssh/sshelter/hosts.config\nHost a\n");
        assert!(ensure_include(&mut items));
        assert_eq!(serialize_items(&items, true), format!("Include {INCLUDE_VALUE}\nInclude ~/.ssh/other.config\nHost a\n"));
        assert!(!ensure_include(&mut items));
        // 多路徑 Include:只抽走我們的 token,其他路徑留在原地。
        let (mut items, _) = parse_file("# c\nAddKeysToAgent yes\nInclude ~/.ssh/a.config ~/.ssh/sshelter/hosts.config\nHost a\n");
        assert!(ensure_include(&mut items));
        assert_eq!(
            serialize_items(&items, true),
            format!("# c\nInclude {INCLUDE_VALUE}\nAddKeysToAgent yes\nInclude ~/.ssh/a.config\nHost a\n")
        );
        assert!(!ensure_include(&mut items));
        // 已在首行、但排在別的路徑後面(`Include a ours`):ssh 會先讀 a,所以仍要正規化成獨立一行。
        let (mut items, _) = parse_file("Include ~/.ssh/a.config ~/.ssh/sshelter/hosts.config\nHost a\n");
        assert!(ensure_include(&mut items));
        assert_eq!(serialize_items(&items, true), format!("Include {INCLUDE_VALUE}\nInclude ~/.ssh/a.config\nHost a\n"));
        assert!(!ensure_include(&mut items));
    }

    #[test]
    fn wildcard_blocks_are_neither_extracted_nor_touched() {
        let (mut items, _) = parse_file(WITH_WILDCARD);
        // 先綁定 blocks_of 的結果再借用,否則暫時 Vec 在敘述結束就釋放(E0716)。
        let blocks = blocks_of(&items);
        let aliases: Vec<&str> = blocks.iter().map(|b| b.alias.as_str()).collect();
        assert_eq!(aliases, vec!["web-1"]);
        // 遠端送來 wildcard alias 的記錄:拒絕、不套用。
        assert!(apply_host_text(&mut items, "*", "Host *\n  User root\n").is_err());
        assert!(apply_host_text(&mut items, "*.internal", "Host *.internal\n").is_err());
        // tombstone 也刪不到 wildcard 區塊。
        assert!(!remove_host_block(&mut items, "*"));
        assert!(!remove_host_block(&mut items, "*.internal"));
        assert_eq!(serialize_items(&items, true), WITH_WILDCARD);
        assert!(!is_syncable_alias("*"));
        assert!(!is_syncable_alias("web?"));
        assert!(!is_syncable_alias("!web"));
        assert!(!is_syncable_alias(""));
        assert!(is_syncable_alias("web-1"));
        // 混合 pattern(`Host web *.internal`、`Host web !prod`):第一個 pattern 具名也不算,整個區塊本地。
        assert!(!is_syncable_block(&["web".to_string(), "*.internal".to_string()]));
        assert!(!is_syncable_block(&["web".to_string(), "!prod".to_string()]));
        assert!(!is_syncable_block(&[]));
        assert!(is_syncable_block(&["web".to_string(), "web.example.com".to_string()]));
        const MIXED: &str = "Host web *.internal\n  User ops\n\nHost db\n  HostName 1\n";
        let (mut items, _) = parse_file(MIXED);
        let blocks = blocks_of(&items);
        assert_eq!(blocks.iter().map(|b| b.alias.as_str()).collect::<Vec<_>>(), vec!["db"]);
        // 遠端的 `web` 記錄不能替換、也不能在旁邊附加第二個 `Host web`;tombstone 也刪不到它。
        assert!(apply_host_text(&mut items, "web", "Host web\n  User root\n").is_err());
        assert!(!remove_host_block(&mut items, "web"));
        assert_eq!(serialize_items(&items, true), MIXED);
        // 遠端記錄的文字本身含 wildcard pattern:拒絕。
        assert!(validate_host_text("web", "Host web *.internal\n").is_err());
        assert!(validate_host_text("web", "Host web\n  User root\n").is_ok());
    }

    #[test]
    fn blocks_of_extracts_every_host_block_verbatim_and_skips_the_rest() {
        let (items, _) = parse_file(FILE);
        let blocks = blocks_of(&items);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].alias, "web-1");
        assert!(blocks[0].text.contains("#tags: prod, web"));
        assert_eq!(blocks[1].alias, "db-1");
        assert_eq!(blocks[1].text, "Host db-1\n  HostName 10.0.0.10\n");
    }

    #[test]
    fn apply_replaces_one_block_and_leaves_neighbors_byte_identical() {
        let (mut items, _) = parse_file(FILE);
        let changed = apply_host_text(&mut items, "web-1", "Host web-1\n  HostName 10.0.0.99\n\n").unwrap();
        assert!(changed);
        let text = serialize_items(&items, true);
        assert!(text.starts_with("# synced by sshelter\n\nHost web-1\n  HostName 10.0.0.99\n"));
        assert!(text.ends_with("Host db-1\n  HostName 10.0.0.10\n"));
        // 相同內容再套一次 → 無變更。
        assert!(!apply_host_text(&mut items, "web-1", "Host web-1\n  HostName 10.0.0.99\n\n").unwrap());
    }

    #[test]
    fn apply_appends_when_missing_and_rejects_non_host_text() {
        let (mut items, _) = parse_file(FILE);
        assert!(apply_host_text(&mut items, "new", "Host new\n  User root\n").unwrap());
        assert!(serialize_items(&items, true).ends_with("Host new\n  User root\n"));
        assert!(apply_host_text(&mut items, "bad", "# just a comment\n").is_err());
        assert!(apply_host_text(&mut items, "mismatch", "Host other\n").is_err());
        // 同一套規則的純檢查(A3 在合併前用它):
        assert!(validate_host_text("bad", "# just a comment\n").is_err());
        assert!(validate_host_text("mismatch", "Host other\n").is_err());
        assert!(validate_host_text("two", "Host two\nHost three\n").is_err());
        // 夾帶 Match / 全域指令 / 區塊外註解:套用後只剩 Host,與快取不一致 → 拒絕。
        assert!(validate_host_text("web", "Host web\n  User a\nMatch all\n  User b\n").is_err());
        assert!(validate_host_text("web", "# leading comment\nHost web\n").is_err());
        assert!(validate_host_text("web", "AddKeysToAgent yes\nHost web\n").is_err());
        assert!(validate_host_text("new", "Host new\n  User root\n").is_ok());
        // 區塊內的註解與尾隨空行屬於區塊本身,可以。
        assert!(validate_host_text("new", "Host new\n  # inside\n  User root\n\n").is_ok());
    }

    #[test]
    fn remove_deletes_only_that_block() {
        let (mut items, _) = parse_file(FILE);
        assert!(remove_host_block(&mut items, "web-1"));
        assert!(!remove_host_block(&mut items, "web-1"));
        let text = serialize_items(&items, true);
        assert!(!text.contains("web-1"));
        assert!(text.contains("Host db-1"));
        assert!(text.starts_with("# synced by sshelter\n"));
    }
}
