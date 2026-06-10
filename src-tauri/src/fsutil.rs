use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// 確保目錄存在，且（unix）權限為 0700。不存在才建立。
/// 僅在「建立時」設定權限；既有目錄的權限刻意不改動（避免動到使用者既有的 ~/.ssh）。
pub fn ensure_dir_secure(dir: &Path) -> Result<(), AppError> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// 原子寫入：在目標同目錄建 temp 檔，設好權限後寫入、fsync，再 rename 蓋回。
/// `mode` 為 unix 權限（如 config 用 0o600、known_hosts 用 0o644）。
/// 注意：rename 會取代 `path` 這個路徑項本身；若 `path` 是 symlink，連結會被實體檔取代（而非寫入其指向的目標）。
pub fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), AppError> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Other(format!("no parent dir for {}", path.display())))?;
    ensure_dir_secure(parent)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| AppError::Io(e.error))?;

    // Best-effort durability: fsync the parent directory so the rename entry
    // survives a crash. `sync_all` above only persisted the file's contents,
    // not the directory entry created by the rename.
    #[cfg(unix)]
    {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// 若 `path` 存在，複製成 `<path>.<unix_millis>.bak` 並回傳備份路徑；不存在則回 None。
/// 在每個 session 第一次寫入 live 檔案前呼叫。
pub fn backup(path: &Path) -> Result<Option<PathBuf>, AppError> {
    if !path.exists() {
        return Ok(None);
    }
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| AppError::Other(e.to_string()))?
        .as_millis();

    let mut name = path
        .file_name()
        .ok_or_else(|| AppError::Other(format!("no file name for {}", path.display())))?
        .to_os_string();
    name.push(format!(".{millis}.bak"));
    let backup_path = path.with_file_name(name);

    fs::copy(path, &backup_path)?;
    Ok(Some(backup_path))
}

/// SECURITY-CRITICAL strict parse: if `name` is exactly `<target_filename>.<digits>.bak` (digits
/// non-empty, all ASCII, parseable as u64), return the millis. Anything else → None. Mirrors the
/// parsing discipline of `commands::parse_backup_name` / `resolve_restore_target`.
fn backup_millis_for(name: &str, target_filename: &str) -> Option<u64> {
    let rest = name.strip_prefix(target_filename)?;
    let rest = rest.strip_prefix('.')?;
    let digits = rest.strip_suffix(".bak")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()
}

/// SECURITY-CRITICAL deletion: prune old backups of `target`, keeping the newest `keep`.
/// Returns the number of files deleted.
///
/// Conservative constraints (non-negotiable):
/// - only considers files in the SAME directory as `target` (never recurses);
/// - only names that strictly parse as `<target filename>.<digits>.bak` (see `backup_millis_for`);
/// - only regular files per `symlink_metadata` — symlinks are skipped, never deleted through;
/// - ordering comes from the millis in the NAME (not mtime), newest kept;
/// - a single failed deletion is skipped, never failing the overall operation.
pub fn prune_backups(target: &Path, keep: usize) -> Result<usize, AppError> {
    let parent = target
        .parent()
        .ok_or_else(|| AppError::Other(format!("no parent dir for {}", target.display())))?;
    let filename = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AppError::Other(format!("no file name for {}", target.display())))?;

    let mut backups: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(parent)?.filter_map(|e| e.ok()) {
        let entry_name = entry.file_name();
        let Some(entry_name) = entry_name.to_str() else {
            continue;
        };
        let Some(millis) = backup_millis_for(entry_name, filename) else {
            continue;
        };
        // Never delete through a symlink (or anything that isn't a plain file).
        match fs::symlink_metadata(entry.path()) {
            Ok(md) if md.file_type().is_file() => {}
            _ => continue,
        }
        backups.push((millis, entry.path()));
    }

    // Newest first by the millis embedded in the filename; delete everything past `keep`.
    backups.sort_by_key(|b| std::cmp::Reverse(b.0));
    let mut deleted = 0;
    for (_, path) in backups.into_iter().skip(keep) {
        match fs::remove_file(&path) {
            Ok(()) => deleted += 1,
            Err(e) => eprintln!("[fsutil] prune_backups: failed to delete {}: {e}", path.display()),
        }
    }
    Ok(deleted)
}

/// 檔案指紋：用於偵測 SSH config 被外部工具（ssh CLI、其他編輯器）改動。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct Fingerprint {
    /// 修改時間（unix 毫秒；取不到時為 0）
    #[cfg_attr(test, ts(type = "number"))]
    pub mtime_ms: u64,
    /// 檔案內容的小寫 hex SHA-256
    pub sha256: String,
}

pub fn file_fingerprint(path: &Path) -> Result<Fingerprint, AppError> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = hex_lower(&hasher.finalize());

    let mtime_ms = fs::metadata(path)?
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    Ok(Fingerprint { mtime_ms, sha256 })
}

/// 檔案目前內容雜湊是否與快照不同（內容導向，比 mtime 可靠）。
pub fn has_changed(path: &Path, snapshot: &Fingerprint) -> Result<bool, AppError> {
    let current = file_fingerprint(path)?;
    Ok(current.sha256 != snapshot.sha256)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn ensure_dir_secure_creates_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join(".ssh");
        ensure_dir_secure(&sub).unwrap();
        let mode = fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn atomic_write_creates_file_with_contents() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config");
        atomic_write(&p, b"Host x\n", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"Host x\n");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_sets_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config");
        atomic_write(&p, b"data", 0o600).unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn backup_copies_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config");
        fs::write(&p, b"original").unwrap();
        let b = backup(&p).unwrap().expect("backup should be created");
        assert_eq!(fs::read(&b).unwrap(), b"original");
        assert!(b.to_string_lossy().ends_with(".bak"));
    }

    #[test]
    fn backup_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope");
        assert!(backup(&p).unwrap().is_none());
    }

    #[test]
    fn prune_backups_deletes_oldest_beyond_keep() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        fs::write(&target, b"live").unwrap();
        for ts in [100u64, 300, 200, 400] {
            fs::write(dir.path().join(format!("config.{ts}.bak")), b"x").unwrap();
        }

        let deleted = prune_backups(&target, 2).unwrap();
        assert_eq!(deleted, 2);
        // Newest two (400, 300) survive; 200 and 100 are gone; live file untouched.
        assert!(dir.path().join("config.400.bak").exists());
        assert!(dir.path().join("config.300.bak").exists());
        assert!(!dir.path().join("config.200.bak").exists());
        assert!(!dir.path().join("config.100.bak").exists());
        assert!(target.exists());
    }

    #[test]
    fn prune_backups_keeps_all_when_under_limit() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        fs::write(&target, b"live").unwrap();
        fs::write(dir.path().join("config.100.bak"), b"x").unwrap();
        fs::write(dir.path().join("config.200.bak"), b"x").unwrap();

        let deleted = prune_backups(&target, 5).unwrap();
        assert_eq!(deleted, 0);
        assert!(dir.path().join("config.100.bak").exists());
        assert!(dir.path().join("config.200.bak").exists());
    }

    #[test]
    fn prune_backups_ignores_non_matching_names() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        fs::write(&target, b"live").unwrap();
        // Decoys that must NEVER be touched.
        fs::write(dir.path().join("other.123.bak"), b"x").unwrap(); // different target
        fs::write(dir.path().join("config.abc.bak"), b"x").unwrap(); // non-digit millis
        fs::write(dir.path().join("config.123.bak.txt"), b"x").unwrap(); // wrong suffix
        fs::write(dir.path().join("config.bak"), b"x").unwrap(); // no millis segment
        // Real backups: keep=0 → all real ones deleted, decoys intact.
        fs::write(dir.path().join("config.100.bak"), b"x").unwrap();
        fs::write(dir.path().join("config.200.bak"), b"x").unwrap();

        let deleted = prune_backups(&target, 0).unwrap();
        assert_eq!(deleted, 2);
        assert!(dir.path().join("other.123.bak").exists());
        assert!(dir.path().join("config.abc.bak").exists());
        assert!(dir.path().join("config.123.bak.txt").exists());
        assert!(dir.path().join("config.bak").exists());
        assert!(!dir.path().join("config.100.bak").exists());
        assert!(!dir.path().join("config.200.bak").exists());
    }

    #[cfg(unix)]
    #[test]
    fn prune_backups_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        fs::write(&target, b"live").unwrap();

        // A precious file outside the prune set, symlinked under a matching backup name.
        let precious = dir.path().join("precious");
        fs::write(&precious, b"do not delete").unwrap();
        let link = dir.path().join("config.100.bak");
        std::os::unix::fs::symlink(&precious, &link).unwrap();

        // One real (newer) backup; keep=0 would otherwise delete everything.
        fs::write(dir.path().join("config.200.bak"), b"x").unwrap();

        let deleted = prune_backups(&target, 0).unwrap();
        assert_eq!(deleted, 1, "only the regular file is deleted");
        assert!(link.exists(), "symlink must be skipped");
        assert!(precious.exists(), "symlink target must survive");
        assert_eq!(fs::read(&precious).unwrap(), b"do not delete");
        assert!(!dir.path().join("config.200.bak").exists());
    }

    #[test]
    fn fingerprint_is_stable_for_same_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config");
        fs::write(&p, b"v1").unwrap();
        let a = file_fingerprint(&p).unwrap();
        let b = file_fingerprint(&p).unwrap();
        assert_eq!(a.sha256, b.sha256);
    }

    #[test]
    fn has_changed_detects_modification() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config");
        fs::write(&p, b"v1").unwrap();
        let snap = file_fingerprint(&p).unwrap();
        assert!(!has_changed(&p, &snap).unwrap());
        fs::write(&p, b"v2").unwrap();
        assert!(has_changed(&p, &snap).unwrap());
    }
}
