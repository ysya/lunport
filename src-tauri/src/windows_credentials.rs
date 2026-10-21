//! Windows adapter. DPAPI CurrentUser protects large local values; Credential
//! Manager retains the authoritative, bounded pointer. No prompting or plaintext fallback.
use super::credential_blob::{self as blob, Backend};
use crate::error::AppError;
use std::{
    path::PathBuf,
    ptr,
    sync::{Mutex, MutexGuard},
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    },
};
use zeroize::{Zeroize, Zeroizing};

fn guard() -> MutexGuard<'static, ()> {
    static ACCESS: Mutex<()> = Mutex::new(());
    ACCESS.lock().unwrap_or_else(|p| p.into_inner())
}
struct Store {
    entry: keyring::Entry,
    root: PathBuf,
}
impl Store {
    fn new(service: &str, account: &str, root: PathBuf) -> Result<Self, AppError> {
        Ok(Self {
            entry: keyring::Entry::new(service, account).map_err(super::map_err)?,
            root,
        })
    }
    fn path(&self, name: &str) -> Result<PathBuf, AppError> {
        if name.len() != 69
            || !name.ends_with(".cred")
            || !name.as_bytes()[..64]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(blob::invalid());
        }
        Ok(self.root.join(name))
    }
}
struct LocalBuffer(CRYPT_INTEGER_BLOB);
impl Drop for LocalBuffer {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: DPAPI owns an allocation of cbData bytes until LocalFree.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}
fn dpapi(value: &[u8], entropy: &[u8], decrypt: bool) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: value.len().try_into().map_err(|_| blob::invalid())?,
        pbData: value.as_ptr().cast_mut(),
    };
    let extra = CRYPT_INTEGER_BLOB {
        cbData: entropy.len().try_into().map_err(|_| blob::invalid())?,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut out = LocalBuffer(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    });
    // SAFETY: borrowed buffers outlive this synchronous call. DPAPI does not mutate
    // the input blobs. NULL prompts plus UI_FORBIDDEN preserve background operation.
    // Deliberately omit LOCAL_MACHINE: protection must belong to the current user.
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &extra,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        } else {
            CryptProtectData(
                &input,
                ptr::null(),
                &extra,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        }
    };
    let limit = if decrypt {
        blob::MAX_VALUE_BYTES
    } else {
        blob::MAX_BLOB_BYTES
    };
    if ok == 0 || out.0.pbData.is_null() || out.0.cbData as usize > limit {
        return Err(blob::invalid());
    }
    // SAFETY: successful DPAPI output is initialized and owned by out until drop.
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(out.0.pbData, out.0.cbData as usize) }.to_vec(),
    ))
}
impl Backend for Store {
    fn get_entry(&self) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
        match self.entry.get_secret() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(super::map_err(e)),
        }
    }
    fn set_entry(&self, value: &[u8]) -> Result<(), AppError> {
        if value.len() > blob::NATIVE_BYTES {
            return Err(blob::invalid());
        }
        self.entry.set_secret(value).map_err(super::map_err)
    }
    fn delete_entry(&self) -> Result<(), AppError> {
        match self.entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(super::map_err(e)),
        }
    }
    fn protect(&self, value: &[u8], entropy: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(std::mem::take(&mut *dpapi(value, entropy, false)?))
    }
    fn unprotect(&self, value: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
        dpapi(value, entropy, true)
    }
    fn read_blob(&self, name: &str, limit: usize) -> Result<Vec<u8>, AppError> {
        self.path(name)?;
        crate::sync::central_files_windows::Directory::private(&self.root, false)?
            .read_private(name, limit as u64)
    }
    fn write_blob(&self, name: &str, value: &[u8]) -> Result<(), AppError> {
        crate::sync::central_files_windows::write(&self.path(name)?, value, false)
    }
    fn remove_blob(&self, name: &str) -> Result<(), AppError> {
        let path = self.path(name)?;
        let pinned = crate::sync::central_files_windows::Directory::private(&self.root, false)?;
        pinned.check_private()?;
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
fn store(account: &str) -> Result<Store, AppError> {
    Store::new(
        super::SERVICE,
        account,
        crate::fsutil::app_data_root()?.join("protected-credentials"),
    )
}
pub(super) fn get(account: &str) -> Result<Option<String>, AppError> {
    let _guard = guard();
    blob::get(&store(account)?, super::SERVICE, account)
}
pub(super) fn set(account: &str, secret: &str) -> Result<(), AppError> {
    let _guard = guard();
    blob::set(&store(account)?, super::SERVICE, account, secret)
}
pub(super) fn delete(account: &str) -> Result<(), AppError> {
    let _guard = guard();
    blob::delete(&store(account)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "uses uniquely scoped native Windows credentials; CI invokes explicitly"]
    fn native_large_credentials() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        let root = tempfile::tempdir().unwrap();
        let service = "Lunport CI DPAPI credential capacity";
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let account: String = id.iter().map(|v| format!("{v:02x}")).collect();
        let store = Store::new(service, &account, root.path().join("private")).unwrap();
        struct Cleanup<'a>(&'a Store);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = self.0.delete_entry();
            }
        }
        let _cleanup = Cleanup(&store);
        assert_eq!(
            blob::NATIVE_BYTES,
            windows_sys::Win32::Security::Credentials::CRED_MAX_CREDENTIAL_BLOB_SIZE as usize
        );
        store
            .entry
            .set_password("legacy synthetic credential")
            .unwrap();
        assert_eq!(
            blob::get(&store, service, &account).unwrap().as_deref(),
            Some("legacy synthetic credential")
        );
        let large = "synthetic Windows secret \u{1f512}".repeat(300);
        assert!(store.entry.set_password(&large).is_err());
        blob::set(&store, service, &account, &large).unwrap();
        assert_eq!(store.get_entry().unwrap().unwrap().len(), 81);
        assert_eq!(
            blob::get(&store, service, &account).unwrap().as_deref(),
            Some(large.as_str())
        );
        assert!(blob::get(&store, "another service", &account).is_err());
        assert!(blob::get(&store, service, "another account").is_err());
        let fresh = Store::new(service, &account, root.path().join("private")).unwrap();
        assert_eq!(
            blob::get(&fresh, service, &account).unwrap().as_deref(),
            Some(large.as_str())
        );
        // Current-user DPAPI binding requires the same secret optional entropy.
        let protected = store.protect(b"synthetic", b"scope-a").unwrap();
        assert!(store.unprotect(&protected, b"scope-b").is_err());
        assert_eq!(
            store.unprotect(&protected, b"scope-a").unwrap().as_slice(),
            b"synthetic"
        );
        let names: Vec<_> = std::fs::read_dir(&store.root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(names.len(), 1);
        let current = std::fs::read(&names[0]).unwrap();
        std::fs::write(&names[0], b"corrupt ciphertext").unwrap();
        assert!(blob::get(&fresh, service, &account).is_err());
        std::fs::write(&names[0], current).unwrap();
        blob::set(&store, service, &account, "short replacement").unwrap();
        assert_eq!(store.entry.get_password().unwrap(), "short replacement");
        assert_eq!(std::fs::read_dir(&store.root).unwrap().count(), 0);
        blob::set(&store, service, &account, &large).unwrap();
        blob::delete(&store).unwrap();
        assert!(blob::get(&store, service, &account).unwrap().is_none());
        assert_eq!(std::fs::read_dir(&store.root).unwrap().count(), 0);
        blob::delete(&store).unwrap();
    }
}
