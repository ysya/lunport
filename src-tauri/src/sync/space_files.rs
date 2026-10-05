//! Space 檔(spec §4.3):每個勾選的 space 一個 `~/.ssh/sshelter/<slug>-<space id 前 8 字元>.config`,主 config
//! 最頂端一行明確列出它們的 Include(`hosts_file::ensure_include`),以及讓 OpenSSH 永遠不會讀到半成品、也不會讀到
//! 不該讀的檔案的建立 / 移除 / 改名順序。主 config 的寫入由呼叫端注入(`write_include`:在 doc 鎖內改清單並
//! `persist_file`),這裡只負責順序與 space 檔本身。

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::error::AppError;
use crate::fsutil;
use crate::sync::crypto::is_chain_id;

/// slug 最長幾個字元(spec §4.3)。
pub const MAX_SLUG_LEN: usize = 40;
/// name 產生不出任何 `[a-z0-9]` 時的 slug。
pub const FALLBACK_SLUG: &str = "space";
/// Include 清單裡的路徑前綴;`~` 在 macOS/Linux/Windows 的 OpenSSH 都能解析(v1 的 `hosts.config` 也是這個寫法)。
pub const INCLUDE_DIR: &str = "~/.ssh/sshelter/";

/// name → slug(spec §4.3):小寫 → 非 `[a-z0-9]` 的連續字元換成一個 `-` → 去掉頭尾 `-` → 最長 40 字元(截斷後
/// 再去一次結尾的 `-`)→ 空字串時為 `space`。對合法的 slug 是恆等函數,所以也拿來正規化別台寫來的 slug。
pub fn slugify(name: &str) -> String {
    let mut slug = String::new();
    let mut gap = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            if gap && !slug.is_empty() {
                slug.push('-');
            }
            gap = false;
            slug.push(ch);
        } else {
            gap = true;
        }
    }
    // 只剩 ASCII:位元組長度 = 字元數。
    slug.truncate(MAX_SLUG_LEN);
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() {
        FALLBACK_SLUG.to_string()
    } else {
        slug.to_string()
    }
}

/// `<slug>-<space id 前 8 字元>.config`。檔名帶 space id,不同 space 的檔名永遠不同,也不會是 Windows 保留名。
/// space id 必須是 64 字元小寫 hex;slug 一律再經 `slugify`(別台寫來的 slug 不可信,不能讓它組出路徑)。
pub fn space_file_name(slug: &str, space_id: &str) -> Result<String, AppError> {
    if !is_chain_id(space_id) {
        return Err(AppError::Other("space id must be 64 lowercase hex characters".to_string()));
    }
    Ok(format!("{}-{}.config", slugify(slug), &space_id[..8]))
}

/// 是不是 `space_file_name` 產生得出來的檔名:`<slug>-<8 個小寫 hex>.config`,slug 為 1–40 個 `[a-z0-9-]`、頭尾不是 `-`、
/// 也沒有連續的 `-`(`slugify` 把連續的非英數字元收成一個 `-`)。狀態檔裡讀回來的檔名先過這關,才拿去組路徑。v1 的
/// `hosts.config` 不是 space 檔名。
pub fn is_space_file_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".config") else { return false };
    let Some((slug, id8)) = stem.rsplit_once('-') else { return false };
    id8.len() == 8
        && id8.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && !slug.is_empty()
        && slug.len() <= MAX_SLUG_LEN
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--")
        && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `<ssh_dir>/sshelter`(0700;v1 的 `hosts.config` 也在這裡)。
pub fn spaces_dir(ssh_dir: &Path) -> PathBuf {
    ssh_dir.join("sshelter")
}

pub fn space_file_path(ssh_dir: &Path, file_name: &str) -> Result<PathBuf, AppError> {
    if !is_space_file_name(file_name) {
        return Err(AppError::Other(format!("'{file_name}' is not a space file name")));
    }
    Ok(spaces_dir(ssh_dir).join(file_name))
}

/// 主 config Include 清單裡代表這個檔案的路徑:`~/.ssh/sshelter/<file_name>`。
pub fn include_token(file_name: &str) -> Result<String, AppError> {
    if !is_space_file_name(file_name) {
        return Err(AppError::Other(format!("'{file_name}' is not a space file name")));
    }
    Ok(format!("{INCLUDE_DIR}{file_name}"))
}

/// 一個這台勾選的 space:id、顯示名稱(排序用)、檔名。
#[derive(Clone, Debug, PartialEq)]
pub struct SpaceFileRef {
    pub space_id: String,
    pub name: String,
    pub file_name: String,
}

/// Include 清單的順序(spec §4.3):space 名稱不分大小寫、再比原字串,名稱相同再依 id —— 每台電腦算出同樣的順序;同一個 alias 出現在兩個 space 時,ssh 先讀排在前面的
/// 那個檔案(每個設定取先讀到的值)。參數是(名稱, space id)。**全部**要這個順序的地方都用這一個比較:主 config 的 Include 清單(`include_tokens`)、帳戶裡 space 的列出(`merge::space_entries`)、
/// 搬移時這台勾選的 space 檔的順序(`merge::selected_space_refs`)—— 兩份各寫各的,哪天只改了一邊,搬移精靈說的「前面那個」就和 ssh 實際讀的不同。
pub fn include_order(a: (&str, &str), b: (&str, &str)) -> std::cmp::Ordering {
    a.0.to_lowercase().cmp(&b.0.to_lowercase()).then_with(|| a.0.cmp(b.0)).then_with(|| a.1.cmp(b.1))
}

/// Include 清單(spec §4.3):依 `include_order` 排序。
pub fn include_tokens(spaces: &[SpaceFileRef]) -> Result<Vec<String>, AppError> {
    let mut sorted: Vec<&SpaceFileRef> = spaces.iter().collect();
    sorted.sort_by(|a, b| include_order((&a.name, &a.space_id), (&b.name, &b.space_id)));
    sorted.iter().map(|s| include_token(&s.file_name)).collect()
}

/// 勾選(spec §4.3):先把檔案建立並寫好 → 再更新 Include 清單。`initial` = None:檔案已存在就保留原內容(例如
/// 離開帳戶後留下的檔案;之後的基線輪以 chain 為準),不存在就建立空檔;Some:整份寫入(v1 升級)。檔案 0600(沿用的
/// 既有檔案也收回 0600)、目錄 0700。`write_include` 失敗時檔案留著 —— 它不在清單上,OpenSSH 不讀。
pub fn add_space_file(
    ssh_dir: &Path,
    file_name: &str,
    initial: Option<&[u8]>,
    write_include: impl FnOnce() -> Result<(), AppError>,
) -> Result<PathBuf, AppError> {
    let path = space_file_path(ssh_dir, file_name)?;
    match initial {
        Some(bytes) => fsutil::atomic_write(&path, bytes, 0o600)?,
        // 空檔以 `create_new` 建立:檢查與建立之間剛出現的檔案、或一個斷掉的 symlink 都不會被空檔取代(同重新長出 space 檔)。
        None => {
            if !create_empty_space_file(&path)? {
                // 沿用既有檔案時一樣收回 0600:OpenSSH 拒絕讀 group 或 world 可寫的 Include 檔(Bad owner or permissions,
                // 之後每一次 ssh 都失敗)。斷掉的 symlink(指向的檔案不在)留著、照樣列進清單:讀檔時那個 space 停在「讀不到」。
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(AppError::Io(e)),
                    }
                }
            }
        }
    }
    write_include()?;
    Ok(path)
}

/// 建一個空的 space 檔(0600,目錄 0700),**不取代**任何已經在那裡的東西:`create_new` 讓檢查與建立之間剛出現的檔案
/// (別的程式放的、使用者從備份還原的)或一個斷掉的 symlink 不會被空檔蓋掉。回傳是不是這次建的;已經有東西了(`AlreadyExists`)
/// = 有人先放了,留著它 —— 之後的重載與讀檔會看到它(讀不到就是那個 space 的讀檔錯誤)。先 `try_exists` 再 `atomic_write` 的寫法有這個空窗,
/// 還會把斷掉的 symlink 換成一般的空檔。
pub fn create_empty_space_file(path: &Path) -> Result<bool, AppError> {
    if let Some(dir) = path.parent() {
        fsutil::ensure_dir_secure(dir)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(AppError::Io(e)),
    }
}

/// 取消勾選、刪除 space(spec §4.3):先從 Include 清單移除 → 再備份並刪除檔案。`write_include` 失敗 → 檔案不動。
/// 回傳備份路徑(檔案本來就不在 → None)。存在與否用 `try_exists`:查不到 metadata 是錯誤,不是「不存在」。檔案在,就一定
/// 要先拿到備份才刪 —— 備份失敗,或 `fsutil::backup` 沒做出備份(它用 `exists()` 判斷,一次暫時的 stat 錯誤就回 None),
/// 都回錯誤、不刪:檔案已經不在清單上,OpenSSH 不會讀它。
pub fn remove_space_file(
    ssh_dir: &Path,
    file_name: &str,
    write_include: impl FnOnce() -> Result<(), AppError>,
) -> Result<Option<PathBuf>, AppError> {
    let path = space_file_path(ssh_dir, file_name)?;
    write_include()?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let Some(backup) = fsutil::backup(&path)? else {
        return Err(AppError::Other("the space file could not be backed up, so it was not deleted".to_string()));
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(Some(backup)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Some(backup)),
        Err(e) => Err(AppError::Io(e)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenameOutcome {
    /// 檔案已改名,清單已指向新名稱。
    Renamed,
    /// 新舊檔名相同(slug 沒變):什麼都沒做。
    Unchanged,
    /// 新檔名已有檔案:什麼都沒改 —— 不覆蓋、保留舊檔名,呼叫端在狀態列提示(spec §4.3)。
    TargetExists,
}

/// 改名(spec §4.3):先讓檔案以新名稱存在 → 再更新 Include 清單 → 最後移除舊名稱。新名稱以 hard link 建立:目標
/// 已存在就原子地失敗,不覆蓋任何檔案;兩個名稱指向同一個檔案,所以清單換過去之前或之後 OpenSSH 讀到的都是完整
/// 內容,清單也從不指向不存在的檔案。`write_include` 失敗 → 移除新名稱、回到原狀。舊名稱移除失敗只留下一個不在
/// 清單上的檔案(OpenSSH 不讀,`stray_space_files` 會列出),仍算改名成功。新名稱已經是舊檔案的另一個 hard link
/// (上一次改名在 hard link 之後就中斷了)→ 接著做完,否則之後每一次重試都卡在 `TargetExists`。檔案系統不支援 hard link
/// 時退回 `rename_without_links`。
pub fn rename_space_file(
    ssh_dir: &Path,
    from: &str,
    to: &str,
    write_include: impl FnOnce() -> Result<(), AppError>,
) -> Result<RenameOutcome, AppError> {
    let old = space_file_path(ssh_dir, from)?;
    let new = space_file_path(ssh_dir, to)?;
    if from == to {
        return Ok(RenameOutcome::Unchanged);
    }
    match std::fs::hard_link(&old, &new) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            if !same_file(&old, &new) {
                return Ok(RenameOutcome::TargetExists);
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(AppError::Io(e)),
        Err(_) => return rename_without_links(&old, &new, write_include),
    }
    if let Err(e) = write_include() {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }
    if let Err(e) = std::fs::remove_file(&old) {
        eprintln!("[sync] a space file was renamed but its old name could not be removed: {e}");
    }
    Ok(RenameOutcome::Renamed)
}

/// 兩個路徑是不是同一個檔案:同一個裝置上的同一個 inode(unix)。不跟隨 symlink —— 指向舊檔案的 symlink 不算,舊名稱刪掉
/// 之後它就斷了。查不到 metadata、或不是 unix(判斷不了)→ false:呼叫端回 `TargetExists`,什麼都不改。
fn same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::symlink_metadata(a), std::fs::symlink_metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}

/// 不支援 hard link 的檔案系統(FAT、部分網路磁碟):先確認目標不存在 → 改名 → 更新清單(失敗就改回)。確認與
/// 改名之間沒有原子保證,但目標檔名帶 space id,只有這台的 app 會建立它。清單更新失敗、改回也失敗 → 回一個不同的錯誤:
/// 內容現在只在新名稱、清單仍列著不存在的舊名稱(OpenSSH 略過它,這個 space 的主機暫時讀不到)—— 呼叫端不能把它當成
/// 「什麼都沒改」,更不能在舊名稱建一個空檔(空檔 = 刪掉每一台主機)。
fn rename_without_links(
    old: &Path,
    new: &Path,
    write_include: impl FnOnce() -> Result<(), AppError>,
) -> Result<RenameOutcome, AppError> {
    if new.try_exists()? {
        return Ok(RenameOutcome::TargetExists);
    }
    std::fs::rename(old, new)?;
    if let Err(e) = write_include() {
        if let Err(rollback) = std::fs::rename(new, old) {
            return Err(AppError::Other(format!(
                "the space file was renamed but the include list could not be updated ({e}), and renaming it back failed ({rollback}); its hosts are only in the renamed file now"
            )));
        }
        return Err(e);
    }
    Ok(RenameOutcome::Renamed)
}

/// `~/.ssh/sshelter/` 裡不在清單上的 `.config` 檔(含 v1 留下的 `hosts.config`):OpenSSH 不讀;app 不讀、不改、
/// 不刪,只在狀態列提示(spec §4.3)。`listed` = 目前勾選的 space 檔名。目錄不存在 → 空。依檔名排序。
pub fn stray_space_files(ssh_dir: &Path, listed: &[String]) -> Result<Vec<String>, AppError> {
    let entries = match std::fs::read_dir(spaces_dir(ssh_dir)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(AppError::Io(e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".config") && !listed.contains(&name) && entry.file_type()?.is_file() {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

/// 離開帳戶之後,這台的檔案改當一般的本機檔案時放的目錄(spec §7.3):`~/.ssh/sshelter-local/`。它不在 `INCLUDE_DIR`
/// 底下,所以主 config 裡指向它的 Include 不是「我們的」token(`hosts_file::is_our_include_token`)——
/// `ensure_include` 永遠不碰,之後建立或加入別的帳戶,ssh 照樣讀得到這些檔案。
pub const LOCAL_INCLUDE_DIR: &str = "~/.ssh/sshelter-local/";

/// `<ssh_dir>/sshelter-local`(0700)。
pub fn local_dir(ssh_dir: &Path) -> PathBuf {
    ssh_dir.join("sshelter-local")
}

/// 一個改成本機檔案的檔案:主 config 裡原本的 Include token、新的完整路徑、新的 Include token。
#[derive(Clone, Debug, PartialEq)]
pub struct KeptFile {
    pub old_token: String,
    pub path: PathBuf,
    pub token: String,
}

/// 離開帳戶(spec §7.3「本機 space 檔案與 Include 保留,ssh 照常可用;它們之後就是一般的本機檔案」):把 `files`
/// (`~/.ssh/sshelter/` 裡的檔案:space 檔,或放棄升級時 v1 的 `hosts.config`)搬到 `~/.ssh/sshelter-local/`,檔名不變;
/// 那裡已有同名檔就用 `<名稱>-2.config`、`-3`……,絕不覆蓋。順序同改名(`rename_space_file`),主 config 從不指向不存在的
/// 檔案:先讓每個檔案以新路徑存在(hard link;不支援就複製成 0600 的新檔)→ `write_include`(呼叫端把主 config 裡的舊
/// token 原地換成新 token)→ 移除舊路徑。建立新路徑或 `write_include` 失敗 → 移除已建立的新路徑、回錯誤,什麼都沒變。
/// 舊路徑移除失敗只留下一份相同、不在 Include 上的檔案(OpenSSH 不讀),仍算成功。不存在的檔案略過;`write_include`
/// 一律呼叫(清單可能是空的 —— 呼叫端藉此拿掉指向已不存在檔案的 token)。
pub fn keep_files_local(
    ssh_dir: &Path,
    files: &[PathBuf],
    write_include: impl FnOnce(&[KeptFile]) -> Result<(), AppError>,
) -> Result<Vec<KeptFile>, AppError> {
    let mut sources = Vec::new();
    for path in files {
        if path.try_exists()? {
            sources.push(path);
        }
    }
    let mut kept = Vec::new();
    if let Err(e) = create_kept_files(ssh_dir, &sources, &mut kept).and_then(|()| write_include(&kept)) {
        for k in &kept {
            let _ = std::fs::remove_file(&k.path);
        }
        return Err(e);
    }
    for source in sources {
        if let Err(e) = std::fs::remove_file(source) {
            eprintln!("[sync] a file was kept as a local file but its old path could not be removed: {e}");
        }
    }
    Ok(kept)
}

/// `keep_files_local` 的第一步:每個檔案在 `~/.ssh/sshelter-local/`(0700)以新路徑存在。建立了的都記在 `kept`,失敗時
/// 呼叫端據此回復。
fn create_kept_files(ssh_dir: &Path, sources: &[&PathBuf], kept: &mut Vec<KeptFile>) -> Result<(), AppError> {
    if sources.is_empty() {
        return Ok(());
    }
    let dir = local_dir(ssh_dir);
    fsutil::ensure_dir_secure(&dir)?;
    for source in sources {
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| AppError::Other(format!("'{}' has no usable file name", source.display())))?;
        let (new_name, path) = create_kept_file(source, &dir, name)?;
        kept.push(KeptFile { old_token: format!("{INCLUDE_DIR}{name}"), path, token: format!("{LOCAL_INCLUDE_DIR}{new_name}") });
    }
    Ok(())
}

/// 在 `dir` 裡以 `file_name` 建立 `source` 的新路徑(已有同名檔就 `<名稱>-2.config`、`-3`……),絕不覆蓋任何檔案:先試
/// hard link(兩個路徑指向同一個檔案,權限照舊);檔案系統不支援時改成複製成 0600 的新檔。
fn create_kept_file(source: &Path, dir: &Path, file_name: &str) -> Result<(String, PathBuf), AppError> {
    let stem = file_name.strip_suffix(".config").unwrap_or(file_name);
    let mut links = true;
    let mut n = 1u32;
    loop {
        let name = if n == 1 { file_name.to_string() } else { format!("{stem}-{n}.config") };
        let target = dir.join(&name);
        let made = if links { std::fs::hard_link(source, &target) } else { copy_new(source, &target) };
        match made {
            Ok(()) => return Ok((name, target)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => n += 1,
            // 不支援 hard link 的檔案系統(FAT、部分網路磁碟):同一個名稱改用複製再試。
            Err(_) if links => links = false,
            Err(e) => return Err(AppError::Io(e)),
        }
    }
}

/// 複製成一個新檔:0600、`create_new`(目標已存在 → `AlreadyExists`,絕不覆蓋);寫到一半失敗就把它刪掉。
fn copy_new(source: &Path, target: &Path) -> std::io::Result<()> {
    let bytes = std::fs::read(source)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(target)?;
    let written = std::io::Write::write_all(&mut file, &bytes).and_then(|()| file.sync_all());
    if written.is_err() {
        let _ = std::fs::remove_file(target);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const ID_A: &str = "3fa2c1d9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "8b01e4aabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn space(id: &str, name: &str) -> SpaceFileRef {
        SpaceFileRef { space_id: id.to_string(), name: name.to_string(), file_name: space_file_name(name, id).unwrap() }
    }

    #[test]
    fn slugs_follow_the_spec_rules() {
        assert_eq!(slugify("Work"), "work");
        assert_eq!(slugify("My Servers (prod)"), "my-servers-prod");
        assert_eq!(slugify("  --Home   Lab--  "), "home-lab");
        assert_eq!(slugify("Café Été"), "caf-t");
        assert_eq!(slugify("日本語"), "space");
        assert_eq!(slugify(""), "space");
        assert_eq!(slugify("a".repeat(50).as_str()), "a".repeat(40));
        // 截斷落在 `-` 上:再去一次結尾的 `-`,不會出現 `aaa--3fa2c1d9.config`。
        assert_eq!(slugify(&format!("{} b", "a".repeat(39))), "a".repeat(39));
        // 對合法 slug 是恆等函數。
        for slug in ["work", "my-servers-prod", "space", "a1-b2"] {
            assert_eq!(slugify(slug), slug);
        }
    }

    #[test]
    fn file_names_carry_the_space_id_and_never_leave_the_directory() {
        assert_eq!(space_file_name("work", ID_A).unwrap(), "work-3fa2c1d9.config");
        assert_eq!(space_file_name("con", ID_B).unwrap(), "con-8b01e4aa.config");
        // 別台寫來的 slug 不可信:一律正規化,組不出路徑。
        assert_eq!(space_file_name("../../etc/passwd", ID_A).unwrap(), "etc-passwd-3fa2c1d9.config");
        assert!(space_file_name("work", "../x").is_err());
        assert!(space_file_name("work", &ID_A.to_uppercase()).is_err());
        assert!(is_space_file_name("work-3fa2c1d9.config"));
        for bad in ["hosts.config", "work-3FA2C1D9.config", "-3fa2c1d9.config", "../a-3fa2c1d9.config", "a-3fa2c1d.config", "work-3fa2c1d9.conf", "a/b-3fa2c1d9.config", "a--b-3fa2c1d9.config", "a--3fa2c1d9.config"] {
            assert!(!is_space_file_name(bad), "{bad}");
        }
        // `slugify` 把連續的非英數字元收成一個 `-`,產生的檔名一定通過檢查。
        assert_eq!(space_file_name("a -- b", ID_A).unwrap(), "a-b-3fa2c1d9.config");
        assert!(is_space_file_name(&space_file_name("a -- b", ID_A).unwrap()));
        let ssh = Path::new("/home/f/.ssh");
        assert_eq!(space_file_path(ssh, "work-3fa2c1d9.config").unwrap(), ssh.join("sshelter").join("work-3fa2c1d9.config"));
        assert!(space_file_path(ssh, "../config").is_err());
        assert_eq!(include_token("work-3fa2c1d9.config").unwrap(), "~/.ssh/sshelter/work-3fa2c1d9.config");
        assert!(include_token("hosts.config").is_err());
    }

    #[test]
    fn include_tokens_are_sorted_by_name_then_id() {
        let spaces = [space(ID_B, "work"), space(ID_A, "Personal"), space(ID_B, "personal"), space(ID_A, "work")];
        assert_eq!(
            include_tokens(&spaces).unwrap(),
            vec![
                "~/.ssh/sshelter/personal-3fa2c1d9.config", // "Personal"(大寫在前)
                "~/.ssh/sshelter/personal-8b01e4aa.config",
                "~/.ssh/sshelter/work-3fa2c1d9.config", // 同名 → 依 id
                "~/.ssh/sshelter/work-8b01e4aa.config",
            ]
        );
        assert!(include_tokens(&[]).unwrap().is_empty());
    }

    #[test]
    fn adding_a_space_writes_the_file_before_the_include() {
        let dir = tempfile::tempdir().unwrap();
        let name = "work-3fa2c1d9.config";
        let path = space_file_path(dir.path(), name).unwrap();
        let seen = Cell::new(None);
        add_space_file(dir.path(), name, Some(b"Host a\n"), || {
            seen.set(Some(std::fs::read_to_string(&path).unwrap()));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen.take().as_deref(), Some("Host a\n"), "the file is complete before it is listed");
        // initial = None:已存在的檔案保留內容,權限收回 0600(OpenSSH 拒絕讀 group 可寫的 Include 檔;下面的 unix 區塊檢查)。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        }
        add_space_file(dir.path(), name, None, || Ok(())).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "Host a\n");
        // 不存在 → 空檔。
        let other = add_space_file(dir.path(), "home-8b01e4aa.config", None, || Ok(())).unwrap();
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(spaces_dir(dir.path())).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn adding_a_space_never_replaces_a_dangling_symlink_with_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let name = "work-3fa2c1d9.config";
        let path = space_file_path(dir.path(), name).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let target = dir.path().join("elsewhere.config");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let listed = Cell::new(false);
        add_space_file(dir.path(), name, None, || {
            listed.set(true);
            Ok(())
        })
        .unwrap();
        assert!(listed.get(), "listed as usual (a missing Include target is skipped by OpenSSH)");
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink(), "the link is left as it was");
        assert!(!target.exists(), "and nothing was created where it points");
    }

    #[test]
    fn a_failed_include_update_leaves_the_new_file_unlisted_and_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let err = add_space_file(dir.path(), "work-3fa2c1d9.config", Some(b"Host a\n"), || {
            Err(AppError::Other("main config changed on disk".to_string()))
        });
        assert!(err.is_err());
        assert!(space_file_path(dir.path(), "work-3fa2c1d9.config").unwrap().is_file());
    }

    #[test]
    fn removing_a_space_unlists_it_before_backing_up_and_deleting_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let name = "work-3fa2c1d9.config";
        let path = add_space_file(dir.path(), name, Some(b"Host a\n"), || Ok(())).unwrap();
        // Include 更新失敗:檔案不動。
        assert!(remove_space_file(dir.path(), name, || Err(AppError::Other("boom".into()))).is_err());
        assert!(path.is_file());
        let still_there = Cell::new(false);
        let backup = remove_space_file(dir.path(), name, || {
            still_there.set(path.is_file());
            Ok(())
        })
        .unwrap()
        .expect("a backup was taken");
        assert!(still_there.get(), "the file is deleted only after it left the include list");
        assert!(!path.exists());
        assert_eq!(std::fs::read_to_string(backup).unwrap(), "Host a\n");
        // 檔案本來就不在:照樣更新清單,沒有備份。
        assert_eq!(remove_space_file(dir.path(), name, || Ok(())).unwrap(), None);
        // 查不到 metadata 不是「不存在」:回錯誤、什麼都不刪(這裡用指向自己的 symlink 讓 stat 失敗;只看 `exists()` 的話
        // 會把它當成不存在、不備份就刪)。
        #[cfg(unix)]
        {
            let looped = space_file_path(dir.path(), "loop-3fa2c1d9.config").unwrap();
            std::os::unix::fs::symlink(&looped, &looped).unwrap();
            assert!(remove_space_file(dir.path(), "loop-3fa2c1d9.config", || Ok(())).is_err());
            assert!(std::fs::symlink_metadata(&looped).is_ok(), "nothing was deleted");
        }
    }

    #[test]
    fn renaming_never_overwrites_and_never_lists_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let (from, to) = ("work-3fa2c1d9.config", "office-3fa2c1d9.config");
        let old = add_space_file(dir.path(), from, Some(b"Host a\n"), || Ok(())).unwrap();
        let new = space_file_path(dir.path(), to).unwrap();
        let both = Cell::new(false);
        let outcome = rename_space_file(dir.path(), from, to, || {
            both.set(old.is_file() && new.is_file());
            Ok(())
        })
        .unwrap();
        assert_eq!(outcome, RenameOutcome::Renamed);
        assert!(both.get(), "old and new names both exist while the include list switches");
        assert!(!old.exists());
        assert_eq!(std::fs::read_to_string(&new).unwrap(), "Host a\n");
        // 目標已存在:什麼都不改、清單也不動。
        let blocker = add_space_file(dir.path(), "home-3fa2c1d9.config", Some(b"Host other\n"), || Ok(())).unwrap();
        let called = Cell::new(false);
        let outcome = rename_space_file(dir.path(), to, "home-3fa2c1d9.config", || {
            called.set(true);
            Ok(())
        })
        .unwrap();
        assert_eq!(outcome, RenameOutcome::TargetExists);
        assert!(!called.get());
        assert_eq!(std::fs::read_to_string(&blocker).unwrap(), "Host other\n");
        assert_eq!(std::fs::read_to_string(&new).unwrap(), "Host a\n");
        // 清單更新失敗:回到原狀。
        assert!(rename_space_file(dir.path(), to, "lab-3fa2c1d9.config", || Err(AppError::Other("boom".into()))).is_err());
        assert!(new.is_file());
        assert!(!space_file_path(dir.path(), "lab-3fa2c1d9.config").unwrap().exists());
        // slug 沒變。
        assert_eq!(rename_space_file(dir.path(), to, to, || Ok(())).unwrap(), RenameOutcome::Unchanged);
        // 舊檔不見了:錯誤,清單不動。
        assert!(rename_space_file(dir.path(), "gone-3fa2c1d9.config", "lab-3fa2c1d9.config", || Ok(())).is_err());
        #[cfg(unix)]
        {
            // 上一次改名在 hard link 之後就中斷了(新名稱是舊檔案的另一個 hard link):這次接著做完,不會永遠卡在 TargetExists。
            let studio = space_file_path(dir.path(), "studio-3fa2c1d9.config").unwrap();
            std::fs::hard_link(&new, &studio).unwrap();
            let called = Cell::new(false);
            let outcome = rename_space_file(dir.path(), to, "studio-3fa2c1d9.config", || {
                called.set(true);
                Ok(())
            })
            .unwrap();
            assert_eq!(outcome, RenameOutcome::Renamed);
            assert!(called.get(), "the include list was updated");
            assert!(!new.exists());
            assert_eq!(std::fs::read_to_string(&studio).unwrap(), "Host a\n");
            // 指向舊檔案的 symlink 不是同一個檔案(舊名稱刪掉之後它就斷了):照樣 TargetExists。
            let den = space_file_path(dir.path(), "den-3fa2c1d9.config").unwrap();
            std::os::unix::fs::symlink(&studio, &den).unwrap();
            let outcome = rename_space_file(dir.path(), "studio-3fa2c1d9.config", "den-3fa2c1d9.config", || Ok(())).unwrap();
            assert_eq!(outcome, RenameOutcome::TargetExists);
            assert_eq!(std::fs::read_to_string(&studio).unwrap(), "Host a\n");
        }
    }

    #[test]
    fn the_rename_fallback_without_hard_links_keeps_the_same_rules() {
        let dir = tempfile::tempdir().unwrap();
        let old = add_space_file(dir.path(), "work-3fa2c1d9.config", Some(b"Host a\n"), || Ok(())).unwrap();
        let new = space_file_path(dir.path(), "office-3fa2c1d9.config").unwrap();
        let renamed_first = Cell::new(false);
        let failed = rename_without_links(&old, &new, || {
            renamed_first.set(new.is_file() && !old.exists());
            Err(AppError::Other("boom".into()))
        });
        assert_eq!(failed.unwrap_err().to_string(), "boom");
        assert!(renamed_first.get(), "the file has its new name before the include list switches");
        assert!(old.is_file() && !new.exists(), "renamed back after a failed include update");
        // 改回也失敗(這裡在舊名稱放一個目錄):回另一個錯誤 —— 內容留在新名稱,清單還列著舊名稱。
        let error = rename_without_links(&old, &new, || {
            std::fs::create_dir(&old).unwrap();
            Err(AppError::Other("boom".into()))
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("renaming it back failed") && error.contains("boom"), "{error}");
        assert_eq!(std::fs::read_to_string(&new).unwrap(), "Host a\n");
        std::fs::remove_dir(&old).unwrap();
        std::fs::rename(&new, &old).unwrap();
        assert_eq!(rename_without_links(&old, &new, || Ok(())).unwrap(), RenameOutcome::Renamed);
        assert!(!old.exists());
        std::fs::write(&old, "Host b\n").unwrap();
        assert_eq!(rename_without_links(&old, &new, || Ok(())).unwrap(), RenameOutcome::TargetExists);
        assert_eq!(std::fs::read_to_string(&new).unwrap(), "Host a\n");
    }

    #[test]
    fn stray_files_are_the_unlisted_config_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(stray_space_files(dir.path(), &[]).unwrap().is_empty(), "no directory yet");
        let listed = "work-3fa2c1d9.config".to_string();
        add_space_file(dir.path(), &listed, None, || Ok(())).unwrap();
        add_space_file(dir.path(), "old-8b01e4aa.config", None, || Ok(())).unwrap();
        let sync_dir = spaces_dir(dir.path());
        std::fs::write(sync_dir.join("hosts.config"), "").unwrap();
        std::fs::write(sync_dir.join("notes.txt"), "").unwrap();
        std::fs::create_dir(sync_dir.join("nested.config")).unwrap();
        assert_eq!(stray_space_files(dir.path(), &[listed]).unwrap(), vec!["hosts.config", "old-8b01e4aa.config"]);
    }

    #[test]
    fn leaving_keeps_files_as_plain_local_files_without_overwriting_any() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path();
        let work = add_space_file(ssh, "work-3fa2c1d9.config", Some(b"Host a\n"), || Ok(())).unwrap();
        let home = add_space_file(ssh, "home-8b01e4aa.config", Some(b"Host b\n"), || Ok(())).unwrap();
        let gone = spaces_dir(ssh).join("gone-11111111.config");
        // 本機目錄裡已經有同名檔:不覆蓋,改用 `-2`。
        std::fs::create_dir_all(local_dir(ssh)).unwrap();
        std::fs::write(local_dir(ssh).join("work-3fa2c1d9.config"), "Host mine\n").unwrap();
        let mut seen = Vec::new();
        let kept = keep_files_local(ssh, &[work.clone(), home.clone(), gone], |kept| {
            // Include 換過去的那一刻,新路徑都已存在、舊路徑也還在:主 config 從不指向不存在的檔案。
            assert!(kept.iter().all(|k| k.path.is_file()));
            assert!(work.is_file() && home.is_file());
            seen = kept.to_vec();
            Ok(())
        })
        .unwrap();
        assert_eq!(kept, seen);
        assert_eq!(
            kept.iter().map(|k| (k.old_token.as_str(), k.token.as_str())).collect::<Vec<_>>(),
            vec![
                ("~/.ssh/sshelter/work-3fa2c1d9.config", "~/.ssh/sshelter-local/work-3fa2c1d9-2.config"),
                ("~/.ssh/sshelter/home-8b01e4aa.config", "~/.ssh/sshelter-local/home-8b01e4aa.config"),
            ],
            "files that are not there are skipped"
        );
        assert_eq!(std::fs::read_to_string(local_dir(ssh).join("work-3fa2c1d9.config")).unwrap(), "Host mine\n");
        assert_eq!(std::fs::read_to_string(&kept[0].path).unwrap(), "Host a\n");
        assert_eq!(std::fs::read_to_string(&kept[1].path).unwrap(), "Host b\n");
        assert!(!work.exists() && !home.exists(), "the old paths are gone");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&kept[1].path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_failed_include_update_removes_the_new_paths_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path();
        let work = add_space_file(ssh, "work-3fa2c1d9.config", Some(b"Host a\n"), || Ok(())).unwrap();
        let home = add_space_file(ssh, "home-8b01e4aa.config", Some(b"Host b\n"), || Ok(())).unwrap();
        let err = keep_files_local(ssh, &[work.clone(), home.clone()], |_| Err(AppError::Other("boom".into()))).unwrap_err();
        assert_eq!(err.to_string(), "boom");
        assert_eq!(std::fs::read_dir(local_dir(ssh)).unwrap().count(), 0, "every new path was removed");
        assert_eq!(std::fs::read_to_string(&work).unwrap(), "Host a\n");
        assert_eq!(std::fs::read_to_string(&home).unwrap(), "Host b\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(local_dir(ssh)).unwrap().permissions().mode() & 0o777, 0o700);
        }
        // 複製的退路一樣不覆蓋。
        let target = local_dir(ssh).join("copy.config");
        copy_new(&work, &target).unwrap();
        assert_eq!(copy_new(&home, &target).unwrap_err().kind(), ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "Host a\n");
    }
}
