//! Windows: the Credential Manager names an entry `<account>.<service>`, and a value too large for an entry lives in a DPAPI file in the
//! data root's `protected-credentials` folder that the entry points to, its encryption bound to the entry's service and account
//! (`secrets::credential_blob`). An entry moves to the new service when it is read with the old service's binding and saved again with
//! the new one's: a large value is encrypted again for the new service, in a file of its own, and the old entry's file goes when the
//! old entry is deleted.

use zeroize::Zeroizing;

use super::credentials::{run_step_keeping_repeated_failures, CurrentCredentials, LegacyCredentials};
use super::journal::Journal;
use super::StepState;
use crate::error::AppError;
use crate::secrets::credential_blob::{self as blob, Backend};

/// How many attempts in a row may leave an entry for a later one for the same reason before it is kept for good. Windows never asks the
/// user anything, so a failure that repeats that often does not pass: a DPAPI file the pinned reader refuses (too large, linked, with
/// other streams or unsafe permissions, changed while it was read), a DPAPI error other than the two that mean damaged data
/// (`credential_blob::dpapi_failure`), or a value under the new name whose DPAPI file went with the folders set aside when the user
/// chose the earlier data. Otherwise the step would never be done, and every start would say the entry stays behind.
pub(super) const SAME_FAILURES_BEFORE_KEEPING: u32 = 3;

/// The credential step between the entries of the earlier service (`old`) and this version's (`new`), keeping for good what fails the
/// same way `SAME_FAILURES_BEFORE_KEEPING` attempts in a row. Vault keys are never kept this way, and none is a DPAPI file reference:
/// they are small.
pub(super) fn move_entries(
    old: &dyn LegacyCredentials,
    new: &dyn CurrentCredentials,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
) -> StepState {
    run_step_keeping_repeated_failures(old, new, journal, record, SAME_FAILURES_BEFORE_KEEPING)
}

/// The account of the Credential Manager entry named `target`, when the entry belongs to `service`.
pub(super) fn account_of<'t>(target: &'t str, service: &str) -> Option<&'t str> {
    target.strip_suffix(service)?.strip_suffix('.').filter(|account| !account.is_empty())
}

/// Makes the store of one account under one service: its Credential Manager entry and the folder of its DPAPI files.
pub(super) trait Stores {
    type Store<'a>: Backend
    where
        Self: 'a;
    fn store<'a>(&'a self, account: &'a str) -> Result<Self::Store<'a>, AppError>;
}

/// The entries of one service.
pub(super) struct Blobs<'a, S> {
    pub service: &'a str,
    pub stores: &'a S,
    /// The names of every entry in the Credential Manager, read without their values.
    pub targets: &'a dyn Fn() -> Result<Vec<String>, AppError>,
}

impl<S: Stores> Blobs<'_, S> {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        Ok(blob::get(&self.stores.store(account)?, self.service, account)?.map(Zeroizing::new))
    }
}

impl<S: Stores> LegacyCredentials for Blobs<'_, S> {
    fn accounts(&self) -> Result<Vec<String>, AppError> {
        Ok((self.targets)()?.iter().filter_map(|target| account_of(target, self.service)).map(str::to_owned).collect())
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.get(account)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        blob::delete(&self.stores.store(account)?)
    }
    fn unreadable_for_good(&self, error: &AppError) -> bool {
        // An entry, or the DPAPI file it points to, that is damaged or gone.
        blob::is_invalid(error)
    }
}

impl<S: Stores> CurrentCredentials for Blobs<'_, S> {
    fn write(&self, account: &str, value: &str) -> Result<(), AppError> {
        blob::set(&self.stores.store(account)?, self.service, account, value)
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.get(account)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        blob::delete(&self.stores.store(account)?)
    }
}

#[cfg(windows)]
#[cfg_attr(test, allow(unused_imports))]
pub(super) use native::{legacy_accounts, move_credentials};

/// This computer's Credential Manager. Only built for Windows, and never reached by a test.
#[cfg(windows)]
mod native {
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
    use windows_sys::Win32::Security::Credentials::{CredEnumerateW, CredFree, CREDENTIALW, CRED_TYPE_GENERIC};

    use super::super::credentials::record_in;
    use super::super::journal::Journal;
    use super::super::{Roots, StepState};
    use super::{account_of, move_entries, Blobs, Stores};
    use crate::error::AppError;
    use crate::secrets::windows_credentials;
    use crate::{identity, legacy_identity};

    /// The entries of one service, with their DPAPI files in `root`.
    struct Native {
        service: &'static str,
        root: PathBuf,
    }

    impl Stores for Native {
        type Store<'a> = windows_credentials::Store;
        fn store<'a>(&'a self, account: &'a str) -> Result<windows_credentials::Store, AppError> {
            windows_credentials::Store::new(self.service, account, self.root.clone())
        }
    }

    /// The name of every generic credential of this user, listed without reading a value.
    fn targets() -> Result<Vec<String>, AppError> {
        let mut count = 0u32;
        let mut credentials: *mut *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: a null filter lists every credential of the user; on success Windows hands over `count` credential pointers in one
        // allocation, released by CredFree below.
        if unsafe { CredEnumerateW(std::ptr::null(), 0, &mut count, &mut credentials) } == 0 {
            // SAFETY: reads this thread's last error, set by the call that just failed.
            let error = unsafe { GetLastError() };
            return if error == ERROR_NOT_FOUND {
                Ok(Vec::new())
            } else {
                Err(AppError::Other(format!("the Windows credentials could not be listed (error {error})")))
            };
        }
        struct Free(*mut *mut CREDENTIALW);
        impl Drop for Free {
            fn drop(&mut self) {
                // SAFETY: the allocation CredEnumerateW returned, released once.
                unsafe { CredFree(self.0 as *const core::ffi::c_void) }
            }
        }
        let _free = Free(credentials);
        let mut targets = Vec::new();
        for index in 0..count as usize {
            // SAFETY: the allocation holds `count` valid credential pointers until it is released.
            let credential = unsafe { &mut **credentials.add(index) };
            if !credential.CredentialBlob.is_null() {
                // The values come along with the list; none is needed here, so none stays in memory.
                // SAFETY: the value's bytes belong to the allocation, which is released after this.
                unsafe { std::ptr::write_bytes(credential.CredentialBlob, 0, credential.CredentialBlobSize as usize) };
            }
            if credential.Type != CRED_TYPE_GENERIC || credential.TargetName.is_null() {
                continue;
            }
            // SAFETY: the name is a NUL-terminated wide string inside the allocation.
            let name = unsafe {
                let length = (0..).take_while(|&offset| *credential.TargetName.add(offset) != 0).count();
                std::slice::from_raw_parts(credential.TargetName, length)
            };
            if let Ok(name) = String::from_utf16(name) {
                targets.push(name);
            }
        }
        Ok(targets)
    }

    /// The credential step on this computer: the earlier version's entries move to this version's service, their DPAPI files staying
    /// in the moved data root. Windows never asks the user anything here, so even a start hidden for a client runs it, and what fails
    /// the same way attempt after attempt is kept for good (`move_entries`).
    #[cfg_attr(test, allow(dead_code))]
    pub(in crate::identity_migration) fn move_credentials(roots: &Roots, journal: &mut Journal) -> StepState {
        assert!(!cfg!(test), "a test reached this computer's Credential Manager");
        let root = roots.data.new.join("protected-credentials");
        let (old, new) = (legacy_identity::current().credential_service, identity::current().credential_service);
        let (old_stores, new_stores) = (Native { service: old, root: root.clone() }, Native { service: new, root });
        // Nothing else in this process reads or writes a credential meanwhile.
        let _exclusive = windows_credentials::guard();
        move_entries(
            &Blobs { service: old, stores: &old_stores, targets: &targets },
            &Blobs { service: new, stores: &new_stores, targets: &targets },
            journal,
            &record_in(roots),
        )
    }

    /// The accounts under the earlier version's service.
    pub(in crate::identity_migration) fn legacy_accounts() -> Result<Vec<String>, AppError> {
        assert!(!cfg!(test), "a test reached this computer's Credential Manager");
        let old = legacy_identity::current().credential_service;
        Ok(targets()?.iter().filter_map(|target| account_of(target, old)).map(str::to_owned).collect())
    }
}

#[cfg(test)]
#[path = "credentials_windows_tests.rs"]
mod tests;
