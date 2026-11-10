use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use crate::error::AppError;

/// Validate a write against the immutable build profile (injected only by unit fixtures).
pub(crate) fn check_write(path: &Path) -> Result<(), AppError> {
    check_write_io(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            AppError::ForbiddenPath(path.display().to_string())
        } else {
            AppError::Io(error)
        }
    })
}

pub(crate) fn check_write_io(path: &Path) -> std::io::Result<()> {
    let policy = current_write_policy()?;
    match ROOT_MOVE.with(|legacy| legacy.borrow().clone()) {
        Some(legacy) => policy.check_root_move(path, &legacy),
        None => policy.check(path),
    }
}

thread_local! {
    /// The data root of the identity before the rename, while this thread's identity migration moves it (`with_root_move`).
    static ROOT_MOVE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` with the development write policy's one exception, for the identity migration: besides the data root, writes may then go
/// to `legacy`, the data root this profile had before its identity changed, and to the migration's lock and backup beside the root
/// (`WritePolicy::check_root_move`). Only this thread, only during `f`. Production writes are not restricted either way.
pub(crate) fn with_root_move<T>(legacy: &Path, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<PathBuf>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ROOT_MOVE.with(|legacy| *legacy.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(ROOT_MOVE.with(|scope| scope.replace(Some(legacy.to_path_buf()))));
    f()
}

pub(crate) fn writes_are_confined() -> bool {
    matches!(
        current_write_policy(),
        Ok(crate::write_policy::WritePolicy::Confined { .. })
    )
}

fn current_write_policy() -> std::io::Result<crate::write_policy::WritePolicy> {
    #[cfg(test)]
    {
        Ok(TEST_WRITE_POLICY.with(|policy| policy.borrow().clone()))
    }
    #[cfg(not(test))]
    {
        match crate::app_profile::CURRENT {
            crate::app_profile::AppProfile::Production => {
                Ok(crate::write_policy::WritePolicy::Unrestricted)
            }
            crate::app_profile::AppProfile::Development => {
                Ok(crate::write_policy::WritePolicy::Confined {
                    root: app_data_root()
                        .map_err(|error| std::io::Error::other(error.to_string()))?,
                })
            }
        }
    }
}

pub(crate) fn home_dir() -> Result<PathBuf, AppError> {
    match crate::app_profile::CURRENT {
        crate::app_profile::AppProfile::Production => dirs::home_dir()
            .ok_or_else(|| AppError::Other("cannot determine home directory".into())),
        crate::app_profile::AppProfile::Development => Ok(app_data_root()?.join("sandbox-home")),
    }
}

#[cfg(test)]
thread_local! {
    static TEST_WRITE_POLICY: std::cell::RefCell<crate::write_policy::WritePolicy> = const {
        std::cell::RefCell::new(crate::write_policy::WritePolicy::Unrestricted)
    };
}

#[cfg(test)]
pub(crate) fn with_test_write_policy<T>(
    policy: crate::write_policy::WritePolicy,
    f: impl FnOnce() -> T,
) -> T {
    struct Restore(crate::write_policy::WritePolicy);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_WRITE_POLICY.with(|policy| *policy.borrow_mut() = self.0.clone());
        }
    }
    let _restore = Restore(TEST_WRITE_POLICY.with(|value| value.replace(policy)));
    f()
}

/// 應用程式本機資料根目錄(MCP policy、sync state 等皆放這裡)。
pub fn app_data_root() -> Result<PathBuf, AppError> {
    dirs::data_local_dir()
        .ok_or_else(|| AppError::Other("cannot determine local data directory".to_string()))
        .map(|p| p.join(crate::app_profile::CURRENT.identifier()))
}

/// Renames `from` to `to`, and fails with `AlreadyExists` when something is at `to` already: a plain rename replaces a file there,
/// and on Unix an empty directory too. A file system without an exclusive rename (Linux before 3.15, an SMB or other network volume)
/// gets a check of `to` just before the rename, which the caller's lock has to make enough.
pub(crate) fn rename_exclusive(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let (from_c, to_c) = (CString::new(from.as_os_str().as_bytes())?, CString::new(to.as_os_str().as_bytes())?);
        let renamed = if unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        };
        // RENAME_EXCL is a capability of the volume (VOL_CAP_INT_RENAME_EXCL): without it renamex_np answers ENOTSUP.
        or_rename_if_absent(renamed, &[libc::ENOTSUP], from, to)
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let (from_c, to_c) = (CString::new(from.as_os_str().as_bytes())?, CString::new(to.as_os_str().as_bytes())?);
        let renamed = if unsafe {
            libc::renameat2(libc::AT_FDCWD, from_c.as_ptr(), libc::AT_FDCWD, to_c.as_ptr(), libc::RENAME_NOREPLACE)
        } == 0
        {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        };
        // Before 3.15 the kernel has no renameat2 (ENOSYS); some file systems refuse the flag (EINVAL).
        or_rename_if_absent(renamed, &[libc::EINVAL, libc::ENOSYS], from, to)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide = |path: &Path| path.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let (from, to) = (wide(from), wide(to));
        // Without MOVEFILE_REPLACE_EXISTING the move fails when `to` exists.
        if unsafe { windows_sys::Win32::Storage::FileSystem::MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } != 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error())
    }
    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"), windows)))]
    {
        rename_if_absent(from, to)
    }
}

/// An exclusive rename's result, or, when it failed only because the system cannot rename exclusively (`unsupported` errors), the
/// rename done the checking way (`rename_if_absent`).
#[cfg(any(target_os = "macos", all(target_os = "linux", target_env = "gnu")))]
pub(crate) fn or_rename_if_absent(renamed: std::io::Result<()>, unsupported: &[i32], from: &Path, to: &Path) -> std::io::Result<()> {
    match renamed {
        Err(error) if error.raw_os_error().is_some_and(|code| unsupported.contains(&code)) => rename_if_absent(from, to),
        renamed => renamed,
    }
}

/// `rename_exclusive` where the system has no exclusive rename.
#[cfg(not(windows))]
fn rename_if_absent(from: &Path, to: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(to) {
        Ok(_) => Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} exists", to.display()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::rename(from, to),
        Err(error) => Err(error),
    }
}

/// 確保目錄存在，且（unix）權限為 0700。不存在才建立。
/// 僅在「建立時」設定權限；既有目錄的權限刻意不改動（避免動到使用者既有的 ~/.ssh）。
pub fn ensure_dir_secure(dir: &Path) -> Result<(), AppError> {
    check_write(dir)?;
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
    check_write(path)?;
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

/// 所有 config 備份的根目錄，位於任何 ssh 可見目錄之外：
/// `dirs::data_dir()/<app id>/backups`，`<app id>` 是 `identity::current().app_id`
/// （macOS: `~/Library/Application Support/<app id>/backups`；
/// Linux: `~/.local/share/<app id>/backups`）。
///
/// 備份絕不能放在目標檔旁邊：使用者的 `Include config.d/*` 之類 glob 會把 `.bak`
/// 檔當成 live config，讓本 app 的 loader 和真正的 `ssh` 都讀進過期副本。
pub fn backups_root() -> Result<PathBuf, AppError> {
    #[cfg(test)]
    let root = test_backups_root().to_path_buf();
    #[cfg(not(test))]
    let root = if crate::app_profile::CURRENT == crate::app_profile::AppProfile::Development {
        app_data_root()?.join("backups")
    } else {
        let data_dir = dirs::data_dir().ok_or_else(|| {
            AppError::Other("cannot determine user data directory for backups".to_string())
        })?;
        backups_root_in(&data_dir, crate::identity::current())
    };
    Ok(root)
}

/// Production's backup root: `identity`'s folder inside `data_dir`, the per-user data directory.
fn backups_root_in(data_dir: &Path, identity: &crate::identity::Identity) -> PathBuf {
    data_dir.join(identity.app_id).join("backups")
}

/// Tests must never touch the real user data dir: one shared per-process temp root. Every test
/// target lives in its own tempdir, so mirror dirs never collide between tests.
#[cfg(test)]
pub(crate) fn test_backups_root() -> &'static Path {
    use std::sync::OnceLock;
    static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    ROOT.get_or_init(|| tempfile::tempdir().expect("create test backups root"))
        .path()
}

/// `target` 的備份所在「鏡像目錄」：backups_root + target 的絕對父目錄路徑（去掉開頭的
/// root / prefix），例如 `/Users/frank/.ssh/config.d/leg.config` 的備份放在
/// `<root>/Users/frank/.ssh/config.d/`。
///
/// Restore matches each managed target's canonical backup directory and file name;
/// dropping a Windows drive prefix makes this mapping unsuitable for path inversion.
/// Dot components are normalized lexically, and parent components only pop existing
/// relative components, so the result cannot escape backups_root.
pub fn backup_dir_for(target: &Path) -> Result<PathBuf, AppError> {
    let parent = target
        .parent()
        .ok_or_else(|| AppError::Other(format!("no parent dir for {}", target.display())))?;
    let abs_parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent)
    };

    let mut rel = PathBuf::new();
    for comp in abs_parent.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            // `pop` on an empty path is a no-op: `..` can never climb above the backups root.
            Component::ParentDir => {
                rel.pop();
            }
            Component::Normal(c) => rel.push(c),
        }
    }
    Ok(backups_root()?.join(rel))
}

/// Preflight every existing candidate before a caller changes its document or vault.
/// A future timestamped destination has the same checked parent; existing links must not
/// redirect it before `backup` gets to choose its timestamp.
pub(crate) fn check_backup_write(target: &Path) -> Result<(), AppError> {
    if !writes_are_confined() { return Ok(()); }
    let dir = backup_dir_for(target)?;
    check_write(&dir)?;
    let filename = target.file_name().and_then(|name| name.to_str())
        .ok_or_else(|| AppError::Other("backup target has no file name".into()))?;
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_str().is_some_and(|name| backup_millis_for(name, filename).is_some()) {
            check_write(&entry.path())?;
        }
    }
    Ok(())
}

/// 若 `path` 存在，複製成 `<mirror dir>/<filename>.<unix_millis>.bak` 並回傳備份路徑；
/// 不存在則回 None。在每個 session 第一次寫入 live 檔案前呼叫。
/// 備份一律寫進 `backups_root()` 下的鏡像目錄（見 `backup_dir_for`），絕不寫在目標旁邊
/// —— 否則 glob `Include` 會把備份當成 live config 讀進去。
pub fn backup(path: &Path) -> Result<Option<PathBuf>, AppError> {
    if !path.exists() {
        return Ok(None);
    }
    check_backup_write(path)?;
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| AppError::Other(e.to_string()))?
        .as_millis();

    let mut name = path
        .file_name()
        .ok_or_else(|| AppError::Other(format!("no file name for {}", path.display())))?
        .to_os_string();
    name.push(format!(".{millis}.bak"));

    let dir = backup_dir_for(path)?;
    let backup_path = dir.join(name);
    check_write(&dir)?;
    check_write(&backup_path)?;
    fs::create_dir_all(&dir)?;

    fs::copy(path, &backup_path)?;
    Ok(Some(backup_path))
}

/// SECURITY-CRITICAL strict parse: if `name` is exactly `<target_filename>.<digits>.bak` (digits
/// non-empty, all ASCII, parseable as u64), return the millis. Anything else → None. Mirrors the
/// parsing discipline of `commands::parse_backup_name` / `resolve_restore_target`.
pub(crate) fn backup_millis_for(name: &str, target_filename: &str) -> Option<u64> {
    let rest = name.strip_prefix(target_filename)?;
    let rest = rest.strip_prefix('.')?;
    let digits = rest.strip_suffix(".bak")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()
}

/// SECURITY-CRITICAL deletion: prune old backups of `target` in its mirror dir under
/// `backups_root()`, keeping the newest `keep`. Returns the number of files deleted.
///
/// Conservative constraints (non-negotiable):
/// - only considers files in `target`'s MIRROR backup dir (never recurses, never the live dir);
/// - only names that strictly parse as `<target filename>.<digits>.bak` (see `backup_millis_for`);
/// - only regular files per `symlink_metadata` — symlinks are skipped, never deleted through;
/// - ordering comes from the millis in the NAME (not mtime), newest kept;
/// - a single failed deletion is skipped, never failing the overall operation;
/// - a missing mirror dir simply means zero backups (`Ok(0)`).
pub fn prune_backups(target: &Path, keep: usize) -> Result<usize, AppError> {
    let filename = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| AppError::Other(format!("no file name for {}", target.display())))?;
    let dir = backup_dir_for(target)?;
    check_write(&dir)?;

    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(AppError::Io(e)),
    };

    let mut backups: Vec<(u64, PathBuf)> = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
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
        check_write(&path)?;
        match fs::remove_file(&path) {
            Ok(()) => deleted += 1,
            Err(e) => eprintln!(
                "[fsutil] prune_backups: failed to delete {}: {e}",
                path.display()
            ),
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mirror dir for `target`, created so tests can seed backups into it.
    fn mirror_dir(target: &Path) -> PathBuf {
        let dir = backup_dir_for(target).unwrap();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bak_count_in(dir: &Path) -> usize {
        match fs::read_dir(dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".bak"))
                .count(),
            Err(_) => 0,
        }
    }

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
    fn backup_dir_for_mirrors_absolute_target_path() {
        let root = backups_root().unwrap();
        let dir = backup_dir_for(Path::new("/Users/frank/.ssh/config.d/leg.config")).unwrap();
        assert_eq!(dir, root.join("Users/frank/.ssh/config.d"));
    }

    /// `backups_root()` itself answers with a scratch directory under test, so the Production
    /// layout is checked through the function it uses in a real build.
    #[test]
    fn production_backups_live_under_the_app_id_in_the_user_data_dir() {
        let data_dir = tempfile::tempdir().unwrap();
        let root = backups_root_in(data_dir.path(), &crate::identity::PRODUCTION);
        assert_eq!(
            root,
            data_dir.path().join(crate::identity::PRODUCTION.app_id).join("backups")
        );
        assert!(root.ends_with("dev.ysya.lunport/backups"), "{}", root.display());
        // The Development identity names a sibling folder, never the Production one.
        let development = backups_root_in(data_dir.path(), &crate::identity::DEVELOPMENT);
        assert!(development.ends_with("dev.ysya.lunport.dev/backups"), "{}", development.display());
        assert!(!development.starts_with(&root));
    }

    #[test]
    fn backup_dir_for_normalizes_dots_and_never_escapes_root() {
        let root = backups_root().unwrap();
        let dir = backup_dir_for(Path::new("/a/b/../c/config")).unwrap();
        assert_eq!(dir, root.join("a/c"));
        // `..` at the top can never climb above the backups root.
        let dir2 = backup_dir_for(Path::new("/../../etc/config")).unwrap();
        assert_eq!(dir2, root.join("etc"));
    }

    #[test]
    fn backup_copies_into_mirror_dir_not_next_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config");
        fs::write(&p, b"original").unwrap();

        let b = backup(&p).unwrap().expect("backup should be created");
        assert_eq!(fs::read(&b).unwrap(), b"original");
        assert!(b.to_string_lossy().ends_with(".bak"));

        // The backup lives in the mirror dir under backups_root…
        let mirror = backup_dir_for(&p).unwrap();
        assert_eq!(b.parent().unwrap(), mirror);
        assert!(mirror.starts_with(backups_root().unwrap()));
        // …and NEVER next to the live file (glob Includes would read it as config).
        assert_eq!(
            bak_count_in(dir.path()),
            0,
            "no .bak may sit next to the live file"
        );
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
        let mirror = mirror_dir(&target);
        for ts in [100u64, 300, 200, 400] {
            fs::write(mirror.join(format!("config.{ts}.bak")), b"x").unwrap();
        }

        let deleted = prune_backups(&target, 2).unwrap();
        assert_eq!(deleted, 2);
        // Newest two (400, 300) survive; 200 and 100 are gone; live file untouched.
        assert!(mirror.join("config.400.bak").exists());
        assert!(mirror.join("config.300.bak").exists());
        assert!(!mirror.join("config.200.bak").exists());
        assert!(!mirror.join("config.100.bak").exists());
        assert!(target.exists());
    }

    #[test]
    fn prune_backups_keeps_all_when_under_limit() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        fs::write(&target, b"live").unwrap();
        let mirror = mirror_dir(&target);
        fs::write(mirror.join("config.100.bak"), b"x").unwrap();
        fs::write(mirror.join("config.200.bak"), b"x").unwrap();

        let deleted = prune_backups(&target, 5).unwrap();
        assert_eq!(deleted, 0);
        assert!(mirror.join("config.100.bak").exists());
        assert!(mirror.join("config.200.bak").exists());
    }

    #[test]
    fn prune_backups_with_no_mirror_dir_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        fs::write(&target, b"live").unwrap();
        // No mirror dir was ever created for this target.
        assert_eq!(prune_backups(&target, 0).unwrap(), 0);
    }

    #[test]
    fn prune_backups_ignores_non_matching_names() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        fs::write(&target, b"live").unwrap();
        let mirror = mirror_dir(&target);
        // Decoys that must NEVER be touched.
        fs::write(mirror.join("other.123.bak"), b"x").unwrap(); // different target
        fs::write(mirror.join("config.abc.bak"), b"x").unwrap(); // non-digit millis
        fs::write(mirror.join("config.123.bak.txt"), b"x").unwrap(); // wrong suffix
        fs::write(mirror.join("config.bak"), b"x").unwrap(); // no millis segment
                                                             // Real backups: keep=0 → all real ones deleted, decoys intact.
        fs::write(mirror.join("config.100.bak"), b"x").unwrap();
        fs::write(mirror.join("config.200.bak"), b"x").unwrap();

        let deleted = prune_backups(&target, 0).unwrap();
        assert_eq!(deleted, 2);
        assert!(mirror.join("other.123.bak").exists());
        assert!(mirror.join("config.abc.bak").exists());
        assert!(mirror.join("config.123.bak.txt").exists());
        assert!(mirror.join("config.bak").exists());
        assert!(!mirror.join("config.100.bak").exists());
        assert!(!mirror.join("config.200.bak").exists());
    }

    #[cfg(unix)]
    #[test]
    fn prune_backups_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config");
        fs::write(&target, b"live").unwrap();
        let mirror = mirror_dir(&target);

        // A precious file outside the prune set, symlinked under a matching backup name.
        let precious = dir.path().join("precious");
        fs::write(&precious, b"do not delete").unwrap();
        let link = mirror.join("config.100.bak");
        std::os::unix::fs::symlink(&precious, &link).unwrap();

        // One real (newer) backup; keep=0 would otherwise delete everything.
        fs::write(mirror.join("config.200.bak"), b"x").unwrap();

        let deleted = prune_backups(&target, 0).unwrap();
        assert_eq!(deleted, 1, "only the regular file is deleted");
        assert!(link.exists(), "symlink must be skipped");
        assert!(precious.exists(), "symlink target must survive");
        assert_eq!(fs::read(&precious).unwrap(), b"do not delete");
        assert!(!mirror.join("config.200.bak").exists());
    }

}

#[cfg(test)]
mod profile_boundary_tests {
    use super::*;
    use crate::write_policy::WritePolicy;

    #[test]
    fn confined_atomic_write_preserves_an_outside_file_and_creates_no_parent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        let outside = temp.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        with_test_write_policy(WritePolicy::Confined { root }, || {
            assert!(atomic_write(&outside, b"changed", 0o600).is_err());
            assert!(ensure_dir_secure(&temp.path().join("outside-parent/nested")).is_err());
        });
        assert_eq!(fs::read(outside).unwrap(), b"keep");
        assert!(!temp.path().join("outside-parent").exists());
    }

    #[test]
    fn confined_backup_and_prune_preserve_an_outside_mirror() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("config");
        fs::write(&target, b"keep").unwrap();
        let dir = backup_dir_for(&target).unwrap();
        fs::create_dir_all(&dir).unwrap();
        let sentinel = dir.join("config.1.bak");
        fs::write(&sentinel, b"backup").unwrap();
        with_test_write_policy(
            WritePolicy::Confined {
                root: temp.path().join("dev"),
            },
            || {
                assert!(backup(&target).is_err());
                assert!(prune_backups(&target, 0).is_err());
            },
        );
        assert_eq!(fs::read(sentinel).unwrap(), b"backup");
        assert_eq!(fs::read(target).unwrap(), b"keep");
    }

    #[test]
    fn a_scoped_policy_is_restored_even_when_the_fixture_unwinds() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        with_test_write_policy(WritePolicy::Confined { root: root.clone() }, || assert!(writes_are_confined()));
        let caught = std::panic::catch_unwind(|| {
            with_test_write_policy(WritePolicy::Confined { root }, || {
                assert!(writes_are_confined());
                panic!("fixture unwind");
            })
        });
        assert!(caught.is_err());
        assert!(!writes_are_confined());
    }
}

#[cfg(all(test, unix))]
mod backup_boundary_tests {
    use super::*;
    #[test]
    fn backup_preflight_refuses_an_existing_redirected_candidate_without_changing_it() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("config");
        let dir = backup_dir_for(&target).unwrap();
        fs::create_dir_all(&dir).unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("config.1.bak")).unwrap();
        with_test_write_policy(crate::write_policy::WritePolicy::Confined { root: test_backups_root().to_path_buf() }, || {
            assert!(check_backup_write(&target).is_err());
        });
        assert_eq!(fs::read(outside).unwrap(), b"keep");
    }
}

/// The user's `~/.ssh` directory. Errors if the home directory is unknown.
pub fn ssh_dir() -> Result<PathBuf, AppError> {
    Ok(home_dir()?.join(".ssh"))
}

/// Create `dir` (and its parents) so that only its owner can enter it: Unix 0700, Windows an owner-only DACL.
pub fn ensure_private_dir(dir: &Path) -> Result<(), AppError> {
    check_write(dir)?;
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    crate::sync::slot_files_windows::restrict_to_owner(dir, true)?;
    Ok(())
}

/// Atomically write a private file: a temporary file in the same directory (Unix 0600 before writing), fsync, rename over
/// the target; on Windows the result gets an explicit owner-only DACL.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    use std::io::Write;
    check_write(path)?;
    let dir = path.parent().ok_or_else(|| AppError::Other(format!("{} has no parent directory", path.display())))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| AppError::Io(e.error))?;
    #[cfg(windows)]
    crate::sync::slot_files_windows::restrict_to_owner(path, false)?;
    Ok(())
}
