//! SP3 插槽的檔案系統動作(spec §4.2、§8):插槽目錄、私鑰與 `.pub` 的寫入、連結(symlink / hard link / 複製)、
//! 內容雜湊、移除與改名保留。所有函式都收明確的路徑,不碰同步狀態。

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::sync::slot_rules::{new_slot_id, public_path};

/// 插槽連到本機金鑰的方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// Unix:指向原檔路徑的 symlink(原檔被換掉也跟著走)。
    Symlink,
    /// Windows:hard link(和原檔共用內容與 ACL;原檔被換成新檔時不會跟著變,由指紋檢查重新連結)。
    HardLink,
    /// 建不了連結時的複製(只有目前使用者能讀)。
    Copy,
}

fn parent_of(path: &Path) -> Result<&Path, AppError> {
    path.parent().ok_or_else(|| AppError::Other(format!("no parent dir for {}", path.display())))
}

/// 確保插槽目錄存在且只有目前使用者能存取。Unix:0700(已存在也改 —— 這是 SSHelter 自己的目錄);Windows:owner-only、
/// 不繼承上層、會被子項繼承的 DACL。
pub fn ensure_keys_dir(dir: &Path) -> Result<(), AppError> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    crate::sync::slot_files_windows::restrict_to_owner(dir, true)?;
    Ok(())
}

/// 原子寫入私鑰檔:暫存檔建在同一個目錄(Unix 先設 0600 再寫;Windows 從 `ensure_keys_dir` 設好的目錄繼承 owner-only
/// 權限),寫入、fsync、rename 蓋過去;Windows 另外把結果設成明確的 owner-only DACL。
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let mut tmp = tempfile::NamedTempFile::new_in(parent_of(path)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file().set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| AppError::Io(e.error))?;
    #[cfg(windows)]
    crate::sync::slot_files_windows::restrict_to_owner(path, false)?;
    Ok(())
}

/// 寫插槽旁的 `<slot>.pub`(公鑰一行加換行;Unix 0644)。
pub fn write_public(slot: &Path, public_key: &str) -> Result<(), AppError> {
    crate::fsutil::atomic_write(&public_path(slot), format!("{public_key}\n").as_bytes(), 0o644)
}

/// 讓插槽 `slot` 指到 `source`(建立插槽那台的原檔,或使用者在這台挑的金鑰),原子替換插槽上原本的東西。
/// Unix 建 symlink(就用 `source` 這個絕對路徑);Windows 建 hard link,不行(不同磁碟、FAT/exFAT)時複製。
pub fn link(source: &Path, slot: &Path) -> Result<LinkKind, AppError> {
    if !source.is_absolute() {
        return Err(AppError::Other(format!("the key path must be absolute: {}", source.display())));
    }
    let dir = parent_of(slot)?;
    let name = slot.file_name().and_then(|n| n.to_str()).unwrap_or("slot");
    let tmp = dir.join(format!(".{name}.{}.tmp", new_slot_id()?));
    let kind = link_at(source, &tmp, slot)?;
    if kind != LinkKind::Copy {
        if let Err(e) = fs::rename(&tmp, slot) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        // `tmp` 與 `slot` 已是同一個檔案的兩個名字時(Windows 對同一個原檔重做 hard link),POSIX 式的 rename 成功卻不會移走 `tmp`;已移走時這行不做事。
        let _ = fs::remove_file(&tmp);
    }
    Ok(kind)
}

#[cfg(unix)]
fn link_at(source: &Path, tmp: &Path, _slot: &Path) -> Result<LinkKind, AppError> {
    std::os::unix::fs::symlink(source, tmp)?;
    Ok(LinkKind::Symlink)
}

#[cfg(not(unix))]
fn link_at(source: &Path, tmp: &Path, slot: &Path) -> Result<LinkKind, AppError> {
    match fs::hard_link(source, tmp) {
        Ok(()) => Ok(LinkKind::HardLink),
        Err(_) => {
            // 複製直接寫到插槽(`write_private` 自己做原子替換),不經 `tmp`。
            write_private(slot, &fs::read(source)?)?;
            Ok(LinkKind::Copy)
        }
    }
}

/// 檔案目前內容的 SHA-256(小寫 hex;跟著 symlink 讀)。讀不到 → None。
pub fn content_sha256(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| crate::fsutil::fingerprint_of(&bytes).sha256)
}

/// 路徑上有沒有東西(包括指向不存在檔案的 symlink)。
pub fn occupied(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn remove_if_present(path: &Path) -> Result<(), AppError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// 移除插槽(連結本身或檔案)與它的 `.pub`;不存在不算錯。移除 symlink 不會動到它指向的金鑰。
pub fn remove_slot(slot: &Path) -> Result<(), AppError> {
    remove_if_present(slot)?;
    remove_if_present(&public_path(slot))
}

/// 把插槽上的舊副本改名保留成 `<file>.previous-<tag>`(計畫裁定 3:私鑰不自動刪除),已存在時加 `-2`、`-3`…,
/// 不覆蓋任何檔案;`.pub` 一起改名。回傳保留的路徑。
pub fn retire(slot: &Path, tag: &str) -> Result<PathBuf, AppError> {
    let dir = parent_of(slot)?;
    let name = slot.file_name().and_then(|n| n.to_str()).unwrap_or("slot");
    let base = format!("{name}.previous-{tag}");
    let mut kept = dir.join(&base);
    let mut n = 2;
    while occupied(&kept) {
        kept = dir.join(format!("{base}-{n}"));
        n += 1;
    }
    fs::rename(slot, &kept)?;
    if occupied(&public_path(slot)) {
        fs::rename(public_path(slot), public_path(&kept))?;
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::{public_path, test_keys};

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    #[cfg(unix)]
    fn keys_dir_and_private_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh/sshelter/keys");
        ensure_keys_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        // SSHelter 自己的目錄:權限被放寬過也改回 0700。
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_keys_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);

        let slot = dir.join("id_mac-3fa2c1d9");
        write_private(&slot, test_keys::plain().as_bytes()).unwrap();
        assert_eq!(mode(&slot), 0o600);
        assert_eq!(fs::read_to_string(&slot).unwrap(), test_keys::plain());
        write_public(&slot, test_keys::PLAIN_PUBLIC).unwrap();
        assert_eq!(fs::read_to_string(public_path(&slot)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        assert_eq!(mode(&public_path(&slot)), 0o644);
        // 沒有留下暫存檔。
        let mut names: Vec<String> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["id_mac-3fa2c1d9", "id_mac-3fa2c1d9.pub"]);
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_slot_follows_its_source_and_replaces_what_was_there() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join(".ssh/id_mac");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, test_keys::plain()).unwrap();
        let dir = home.path().join(".ssh/sshelter/keys");
        ensure_keys_dir(&dir).unwrap();
        let slot = dir.join("id_mac-3fa2c1d9");
        write_private(&slot, b"old").unwrap();

        assert_eq!(link(&source, &slot).unwrap(), LinkKind::Symlink);
        assert_eq!(fs::read_link(&slot).unwrap(), source);
        assert_eq!(content_sha256(&slot), content_sha256(&source));
        fs::write(&source, test_keys::ecdsa()).unwrap();
        assert_eq!(content_sha256(&slot), content_sha256(&source), "a symlink follows the file at the source path");

        assert!(link(Path::new("id_mac"), &slot).is_err(), "the source must be an absolute path");
        remove_slot(&slot).unwrap();
        assert!(!occupied(&slot));
        assert!(source.exists(), "removing a slot never touches the key it points to");
        remove_slot(&slot).unwrap();
    }

    #[test]
    fn a_broken_link_still_occupies_the_slot() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("keys");
        ensure_keys_dir(&dir).unwrap();
        let source = home.path().join("gone");
        fs::write(&source, test_keys::plain()).unwrap();
        let slot = dir.join("gone-3fa2c1d9");
        link(&source, &slot).unwrap();
        fs::remove_file(&source).unwrap();
        assert!(occupied(&slot));
        #[cfg(unix)]
        assert_eq!(content_sha256(&slot), None);
    }

    #[test]
    fn retired_copies_keep_their_bytes_under_a_new_name() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("keys");
        ensure_keys_dir(&dir).unwrap();
        let slot = dir.join("id_mac-3fa2c1d9");
        write_private(&slot, test_keys::plain().as_bytes()).unwrap();
        write_public(&slot, test_keys::PLAIN_PUBLIC).unwrap();

        let kept = retire(&slot, "0a1b2c3d").unwrap();
        assert_eq!(kept, dir.join("id_mac-3fa2c1d9.previous-0a1b2c3d"));
        assert_eq!(fs::read_to_string(&kept).unwrap(), test_keys::plain());
        assert!(public_path(&kept).exists());
        assert!(!occupied(&slot));

        write_private(&slot, b"second").unwrap();
        let again = retire(&slot, "0a1b2c3d").unwrap();
        assert_eq!(again, dir.join("id_mac-3fa2c1d9.previous-0a1b2c3d-2"));
        assert_eq!(fs::read_to_string(&kept).unwrap(), test_keys::plain(), "never overwrites an earlier copy");
    }

    #[test]
    #[cfg(windows)]
    fn windows_slots_are_owner_only_and_hard_linked() {
        use crate::sync::slot_files_windows::ace_count;
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("keys");
        ensure_keys_dir(&dir).unwrap();
        assert_eq!(ace_count(&dir).unwrap(), 1);
        let slot = dir.join("id_win-3fa2c1d9");
        write_private(&slot, test_keys::plain().as_bytes()).unwrap();
        assert_eq!(ace_count(&slot).unwrap(), 1);

        let source = home.path().join("id_win");
        fs::write(&source, test_keys::ecdsa()).unwrap();
        let linked = dir.join("linked-3fa2c1d9");
        assert_eq!(link(&source, &linked).unwrap(), LinkKind::HardLink);
        assert_eq!(content_sha256(&linked), content_sha256(&source));

        // 對同一個原檔再連一次:`linked` 已經和原檔是同一個檔案,這之後插槽目錄裡不能留下 `.tmp` 的暫存名稱。
        assert_eq!(link(&source, &linked).unwrap(), LinkKind::HardLink);
        let leftovers: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "a re-made link leaves no temp name behind: {leftovers:?}");
        assert_eq!(content_sha256(&linked), content_sha256(&source));
    }
}
