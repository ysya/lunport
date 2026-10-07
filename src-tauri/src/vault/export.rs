//! 匯出私鑰(金鑰保管庫 spec §7.3.2):需要檔案時唯一的出口。內容是保管庫裡的私鑰原文,可選擇加上 passphrase;存到 SSHelter 管理的 `~/.ssh/sshelter/`
//! 底下會被拒絕,寫出的檔案只有擁有者能讀寫(`save_export`)。存檔對話框在 `sync::engine::sync_key_export_private`。

use std::path::Path;

use zeroize::Zeroizing;

use crate::error::AppError;

/// 要存到 SSHelter 管理的資料夾裡:拒絕(那裡的檔案由 SSHelter 維護,會被改寫或移除)。
pub const EXPORT_INSIDE_MESSAGE: &str = "Choose a folder outside ~/.ssh/sshelter: SSHelter manages that folder.";
/// 已經有 passphrase 的金鑰不能再加一個(匯出時照原樣,仍是加密的)。
pub const ALREADY_PROTECTED_MESSAGE: &str = "This key already has a passphrase.";

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

/// 把匯出的內容寫到使用者選的 `path`:目的地先過 `check_destination`,再寫成只有擁有者能讀寫的檔案(`slot_files::write_private`:暫存檔 + rename;
/// Windows 在 rename 之後把權限限縮到擁有者)。
pub fn save_export(path: &Path, home: &Path, text: &str) -> Result<(), AppError> {
    check_destination(path, home)?;
    crate::sync::slot_files::write_private(path, text.as_bytes())
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
}
