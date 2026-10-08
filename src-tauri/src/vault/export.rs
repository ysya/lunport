//! 匯出私鑰(金鑰保管庫 spec §7.3.2):需要檔案時唯一的出口。內容是保管庫裡的私鑰原文,可選擇加上 passphrase;存到 SSHelter 管理的 `~/.ssh/sshelter/`
//! 底下會被拒絕。檔案直接寫在使用者選的路徑上(`save_export`),在寫入任何金鑰內容之前就只有擁有者能讀寫。存檔對話框在 `sync::engine::sync_key_export_private`。
//!
//! 代價:不是原子的 —— 寫到一半當掉(斷電、被終止)可能留下不完整的檔案,使用者重新匯出即可(寫入失敗時檔案會被移除,不留半把金鑰)。換來的是使用者的資料夾裡
//! 沒有暫存檔,也沒有「先寫整把金鑰、之後才限縮權限」的空窗。

use std::io::Write as _;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::AppError;

/// 要存到 SSHelter 管理的資料夾裡:拒絕(那裡的檔案由 SSHelter 維護,會被改寫或移除)。
pub const EXPORT_INSIDE_MESSAGE: &str = "Choose a folder outside ~/.ssh/sshelter: SSHelter manages that folder.";
/// 已經有 passphrase 的金鑰不能再加一個(匯出時照原樣,仍是加密的)。
pub const ALREADY_PROTECTED_MESSAGE: &str = "This key already has a passphrase.";
/// 目的地已經是一個資料夾:不是能存金鑰的檔案(存檔對話框問過要不要取代檔案,資料夾不能取代)。
pub const EXPORT_FOLDER_MESSAGE: &str = "There is a folder at that path. Choose a file name for the key.";

/// 要寫進檔案的內容:沒給 passphrase(或是空的)就是保管庫裡的原文,有 passphrase 的仍是加密狀態;給了就把沒有 passphrase 的金鑰加密
/// (OpenSSH 格式,aes256-ctr + bcrypt,同 `ssh-keygen -p` 的預設)。錯誤訊息不帶金鑰。
pub fn export_text(private_key: &str, passphrase: Option<&str>) -> Result<Zeroizing<String>, AppError> {
    let Some(passphrase) = passphrase.filter(|p| !p.is_empty()) else {
        return Ok(Zeroizing::new(private_key.to_string()));
    };
    let key = ssh_key::PrivateKey::from_openssh(private_key).map_err(|_| AppError::Other("SSHelter can't read this key.".to_string()))?;
    if key.is_encrypted() {
        return Err(AppError::Other(ALREADY_PROTECTED_MESSAGE.to_string()));
    }
    let encrypted = key
        .encrypt(&mut rand_core::OsRng, passphrase)
        .map_err(|e| AppError::Other(format!("cannot add the passphrase: {e}")))?;
    encrypted.to_openssh(ssh_key::LineEnding::LF).map_err(|e| AppError::Other(format!("cannot write the key: {e}")))
}

/// 匯出的目的地不能在 `<home>/.ssh/sshelter/` 底下。比對前把資料夾換成真正的路徑(macOS 的 `/var` 是 `/private/var` 的 symlink、使用者自己的 symlink);
/// 還不存在的就照原樣比。
pub fn check_destination(path: &Path, home: &Path) -> Result<(), AppError> {
    let parent = path.parent().ok_or_else(|| AppError::Other("Choose a file to save the key in.".to_string()))?;
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if real(parent).starts_with(real(&home.join(".ssh").join("sshelter"))) {
        return Err(AppError::Other(EXPORT_INSIDE_MESSAGE.to_string()));
    }
    Ok(())
}

/// 把匯出的內容寫到使用者選的 `path`:目的地先過 `check_destination`,再由 `write_export` 直接寫成只有擁有者能讀寫的檔案。
///
/// 不用 `slot_files::write_private`(暫存檔 + rename):那是給 SSHelter 自己的資料夾用的,暫存檔會繼承所在資料夾的權限;使用者選的資料夾(`C:\` 底下、共用資料夾……)
/// 不一定只有他自己能讀,而 Windows 上整把金鑰寫進去、rename 之後才限縮權限,中間(以及限縮失敗的時候)別的使用者可能讀得到。暫存檔也不該出現在使用者的資料夾裡
/// (`settings_export` 同樣直接寫使用者選的路徑)。代價是不原子:寫到一半當掉(斷電、被終止)可能留下不完整的檔案,使用者重新匯出即可。
pub fn save_export(path: &Path, home: &Path, text: &str) -> Result<(), AppError> {
    check_destination(path, home)?;
    write_export(path, text.as_bytes())
}

/// 把 `bytes` 寫成 `path` 上一個全新的、只有擁有者能讀寫的檔案(Unix 0600;Windows 只給目前使用者)。
/// 路徑上已經有東西(存檔對話框問過要不要取代):資料夾拒絕(`EXPORT_FOLDER_MESSAGE`),其他的 —— 檔案、symlink —— 先移除。換掉的是這個名字本身,不會跟著 symlink 寫到別處;
/// 資料夾不能寫的時候,移除舊檔會先失敗,舊檔原封不動。再由 `create_owner_only` 建立新檔案、寫入、`sync_all`;建立之後任何一步失敗,檔案都被移除、回傳原本的錯誤。
fn write_export(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => return Err(AppError::Other(EXPORT_FOLDER_MESSAGE.to_string())),
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    create_owner_only(path, |file| {
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })
}

/// 在 `path` 建立一個全新的、只有擁有者能讀寫的檔案(路徑上不能已經有東西),交給 `fill` 寫內容;`fill` 失敗就關掉檔案、移除它,回傳 `fill` 的錯誤。
/// - 用 `create_new`(Unix 的 `O_EXCL`):路徑上就算在檢查之後被換上 symlink,也不會跟著走、寫到別處。
/// - Unix:建立時就是 0600(`mode`)。Windows:以獨佔(`share_mode(0)`)開啟,我們放手之前別的程式沒辦法開啟它來讀寫,再把 DACL 限縮到擁有者(`restrict_then_fill`)。
/// - 權限在第一個位元組寫進去之前就到位,`fill` 拿到的是空檔案。
/// 只有這裡自己建出來的檔案才會被移除:開檔失敗(例如路徑上已經有東西)什麼都不動。
fn create_owner_only(path: &Path, fill: impl FnOnce(&mut std::fs::File) -> Result<(), AppError>) -> Result<(), AppError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.share_mode(0);
    }
    let mut file = options.open(path)?;
    let filled = restrict_then_fill(path, &mut file, fill);
    if filled.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    filled
}

/// 建立之後、寫入之前:Windows 把檔案的 DACL 換成只有目前使用者(`restrict_to_owner` 用 `SetFileSecurityW`,只要 WRITE_DAC 存取、不碰檔案資料,
/// 不會和我們獨佔開啟的 handle 衝突);Unix 建立時已經是 0600,不用做。然後交給 `fill`。
fn restrict_then_fill(path: &Path, file: &mut std::fs::File, fill: impl FnOnce(&mut std::fs::File) -> Result<(), AppError>) -> Result<(), AppError> {
    #[cfg(windows)]
    crate::sync::slot_files_windows::restrict_to_owner(path, false)?;
    #[cfg(not(windows))]
    let _ = path;
    fill(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    #[test]
    fn a_key_exports_as_it_is_stored_without_a_new_passphrase() {
        assert_eq!(export_text(&test_keys::plain(), None).unwrap().as_str(), test_keys::plain());
        assert_eq!(export_text(&test_keys::encrypted(), None).unwrap().as_str(), test_keys::encrypted(), "an encrypted key stays encrypted");
        assert_eq!(export_text(&test_keys::plain(), Some("")).unwrap().as_str(), test_keys::plain(), "an empty passphrase adds none");
    }

    /// 沒有 passphrase 的金鑰可以加一個:匯出的檔案是加密過的同一把金鑰。
    #[test]
    fn a_passphrase_can_be_added_to_a_key_that_has_none() {
        let out = export_text(&test_keys::plain(), Some("correct horse")).unwrap();
        let facts = crate::sync::slot_rules::inspect_private_key(out.as_str()).unwrap();
        assert!(facts.has_passphrase);
        assert_eq!(facts.fingerprint, test_keys::PLAIN_FINGERPRINT, "the same key");
        let key = ssh_key::PrivateKey::from_openssh(out.as_str()).unwrap();
        assert!(key.decrypt("correct horse").is_ok());
        assert!(key.decrypt("wrong horse").is_err());
    }

    #[test]
    fn a_key_that_already_has_a_passphrase_is_not_given_another() {
        assert_eq!(export_text(&test_keys::encrypted(), Some("x")).unwrap_err().to_string(), ALREADY_PROTECTED_MESSAGE);
    }

    /// 不能存到 SSHelter 管理的 `~/.ssh/sshelter/` 底下(包括 `keys/`、`agent/`);其他地方都可以,`~/.ssh` 本身也可以。
    #[test]
    fn a_file_inside_sshelters_folder_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let managed = home.path().join(".ssh/sshelter/keys");
        std::fs::create_dir_all(&managed).unwrap();
        std::fs::create_dir_all(home.path().join("Desktop")).unwrap();
        for inside in [home.path().join(".ssh/sshelter/id_mac"), managed.join("id_mac")] {
            assert_eq!(check_destination(&inside, home.path()).unwrap_err().to_string(), EXPORT_INSIDE_MESSAGE, "{}", inside.display());
        }
        for outside in [home.path().join("Desktop/id_mac"), home.path().join(".ssh/id_mac")] {
            assert!(check_destination(&outside, home.path()).is_ok(), "{}", outside.display());
        }
    }

    /// 存到外面:內容就是匯出的文字,只有擁有者能讀寫(unix 0600);存到 SSHelter 的資料夾:什麼都不寫。
    #[test]
    fn an_export_is_written_owner_only_and_never_inside_sshelters_folder() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".ssh/sshelter/keys")).unwrap();
        let inside = home.path().join(".ssh/sshelter/keys/id_mac");
        assert_eq!(save_export(&inside, home.path(), "KEY").unwrap_err().to_string(), EXPORT_INSIDE_MESSAGE);
        assert!(!inside.exists());
        let outside = home.path().join("id_mac");
        save_export(&outside, home.path(), "KEY").unwrap();
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "KEY");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    /// 資料夾是 symlink 也一樣:使用者自己的 symlink 指進 SSHelter 的資料夾,或 `~/.ssh` 本身是 symlink(dotfiles 放在別處),實際位置在 `~/.ssh/sshelter/`
    /// 底下的都拒絕、什麼都不寫;同一個 `~/.ssh` 裡 SSHelter 的資料夾以外的地方照常可以存。
    #[cfg(unix)]
    #[test]
    fn a_symlink_into_sshelters_folder_does_not_get_around_the_refusal() {
        let home = tempfile::tempdir().unwrap();
        let managed = home.path().join("dotfiles/ssh/sshelter/keys");
        std::fs::create_dir_all(&managed).unwrap();
        std::os::unix::fs::symlink(home.path().join("dotfiles/ssh"), home.path().join(".ssh")).unwrap();
        std::os::unix::fs::symlink(&managed, home.path().join("shortcut")).unwrap();
        for (how, inside) in [
            ("through ~/.ssh", home.path().join(".ssh/sshelter/keys/id_mac")),
            ("by its real place", managed.join("id_mac")),
            ("through the user's own link", home.path().join("shortcut/id_mac")),
        ] {
            assert_eq!(save_export(&inside, home.path(), "KEY").unwrap_err().to_string(), EXPORT_INSIDE_MESSAGE, "{how}");
            assert!(!managed.join("id_mac").exists(), "{how}: nothing was written");
        }
        save_export(&home.path().join(".ssh/id_mac"), home.path(), "KEY").unwrap();
        assert_eq!(std::fs::read_to_string(home.path().join("dotfiles/ssh/id_mac")).unwrap(), "KEY", "~/.ssh itself is fine");
    }

    /// 資料夾裡現在有哪些東西(檔名,排序過)。
    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        names
    }

    /// 目的地已經有檔案(對話框已經問過要不要取代):換成新的檔案,內容整份是這次匯出的(舊的比較長也不會剩尾巴),權限是 0600 而不是舊檔的 0644;
    /// 資料夾裡沒有留下別的東西(沒有暫存檔)。
    #[cfg(unix)]
    #[test]
    fn an_existing_file_is_replaced_by_an_owner_only_one() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("id_mac");
        std::fs::write(&path, "an older file that is longer than the new key").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_export(&path, home.path(), "KEY").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "KEY");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(names_in(home.path()), ["id_mac"], "nothing else is left beside it");
    }

    /// 目的地是 symlink:換掉的是這個名字本身(變成一般檔案),不會跟著它寫到別處;它指的檔案原封不動,懸空的 symlink 也不會在它指的地方建出檔案。
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_destination_is_replaced_not_followed() {
        let home = tempfile::tempdir().unwrap();
        let target = home.path().join("target");
        std::fs::write(&target, "the target").unwrap();
        let link = home.path().join("id_mac");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        save_export(&link, home.path(), "KEY").unwrap();
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "the name is a regular file now");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "KEY");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "the target", "what the link pointed to is untouched");

        let missing = home.path().join("missing");
        let dangling = home.path().join("id_other");
        std::os::unix::fs::symlink(&missing, &dangling).unwrap();
        save_export(&dangling, home.path(), "KEY").unwrap();
        assert!(!std::fs::symlink_metadata(&dangling).unwrap().file_type().is_symlink(), "a dangling link is replaced too");
        assert!(!missing.exists(), "nothing was created where the link pointed");
    }

    /// 目的地是資料夾:拒絕(說明是資料夾),資料夾和裡面的東西原封不動。
    #[test]
    fn a_folder_at_the_destination_is_refused_and_left_alone() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("id_mac");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("keep"), "mine").unwrap();
        assert_eq!(save_export(&folder, home.path(), "KEY").unwrap_err().to_string(), EXPORT_FOLDER_MESSAGE);
        assert!(folder.is_dir());
        assert_eq!(std::fs::read_to_string(folder.join("keep")).unwrap(), "mine");
    }

    /// 檔案交給寫入的那一刻就只有擁有者能讀寫,而且還是空的:金鑰的第一個位元組寫進去之前,權限已經限縮好了(不是寫完再限縮)。
    /// Unix 看權限位元(建立時就是 0600);Windows 看 DACL 已經只剩一條 ACE。
    #[test]
    fn the_file_is_owner_only_before_any_byte_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_mac");
        let mut seen = false;
        create_owner_only(&path, |file| {
            let meta = file.metadata()?;
            assert_eq!(meta.len(), 0, "nothing is written yet");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(meta.permissions().mode() & 0o777, 0o600, "owner-only from the start");
            }
            #[cfg(windows)]
            assert_eq!(crate::sync::slot_files_windows::ace_count(&path).unwrap(), 1, "the DACL is the owner's alone from the start");
            seen = true;
            Ok(())
        })
        .unwrap();
        assert!(seen, "the writer was called");
        assert!(path.exists(), "and a writer that succeeds leaves the file");
    }

    /// 建立之後任何一步失敗(這裡是寫了一半的時候):把檔案移除、回傳原本的錯誤 —— 失敗的匯出不留下檔案,也不留下半把金鑰。
    #[test]
    fn a_failed_write_leaves_nothing_at_the_path() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_mac");
        let err = create_owner_only(&path, |file| {
            file.write_all(b"the first half of a key")?;
            Err(AppError::Other("the disk is full".to_string()))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "the disk is full", "the original error comes back");
        assert!(std::fs::symlink_metadata(&path).is_err(), "nothing is left at the path");
        assert!(names_in(dir.path()).is_empty(), "and nothing is left in the folder");
    }

    /// 寫不進去的匯出(資料夾不能寫):回傳錯誤、路徑上什麼都沒有;原本就在那裡的檔案也不會被動到(移除它也需要資料夾能寫)。
    #[cfg(unix)]
    #[test]
    fn an_export_that_cannot_be_created_leaves_nothing_and_keeps_what_was_there() {
        use std::os::unix::fs::PermissionsExt;
        // 不管測試怎麼結束,資料夾都要改回能寫,暫存目錄才清得掉。
        struct Reopen(std::path::PathBuf);
        impl Drop for Reopen {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("locked");
        std::fs::create_dir(&folder).unwrap();
        let old = folder.join("old");
        std::fs::write(&old, "mine").unwrap();
        let _reopen = Reopen(folder.clone());
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500)).unwrap();
        // 以管理者(root)身分跑時資料夾的權限擋不住任何事,這個測試沒有東西可驗證。
        if std::fs::File::create(folder.join("probe")).is_ok() {
            return;
        }

        let fresh = folder.join("id_mac");
        assert!(save_export(&fresh, home.path(), "KEY").is_err());
        assert!(std::fs::symlink_metadata(&fresh).is_err(), "nothing was created");
        assert!(save_export(&old, home.path(), "KEY").is_err());
        assert_eq!(std::fs::read_to_string(&old).unwrap(), "mine", "the file that was there is still there");
    }

    /// Windows:匯出的檔案只有一條 ACE(目前使用者),不是資料夾繼承來的那幾條;取代已經存在的檔案也一樣。
    #[cfg(windows)]
    #[test]
    fn an_export_has_only_the_owners_ace_on_windows() {
        use crate::sync::slot_files_windows::ace_count;
        let home = tempfile::tempdir().unwrap();
        // 前提:同一個資料夾裡隨手建立的檔案會繼承好幾條 ACE,否則下面的比較什麼都證明不了。
        let plain = home.path().join("plain");
        std::fs::write(&plain, "x").unwrap();
        let inherited = ace_count(&plain).unwrap();
        assert!(inherited > 1, "a file made in this folder must inherit more than one ACE, or the check below proves nothing (it has {inherited})");

        let path = home.path().join("id_mac");
        save_export(&path, home.path(), "KEY").unwrap();
        assert_eq!(ace_count(&path).unwrap(), 1, "only the current user, not the folder's entries");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "KEY");
        save_export(&path, home.path(), "KEY2").unwrap();
        assert_eq!(ace_count(&path).unwrap(), 1, "a replaced file is the same");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "KEY2");
        assert_eq!(names_in(home.path()), ["id_mac", "plain"], "no temp file is left beside it");
    }
}
