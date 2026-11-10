//! The macOS keychain as the keyring crate uses it, where the Development profile saves credentials: a generic password whose service
//! is the credential service and whose account is the account, in the default keychain. Its accounts are listed from the items'
//! attributes alone (`credentials_macos`), which reads no secret and asks nothing; a locked keychain leaves the step waiting for the
//! user (`credentials_macos::unless_locked`). Reading an item an earlier build saved may ask the user to allow access, so a start hidden
//! for a client leaves the step for one the user sees (`credentials::runs`).

#[cfg_attr(test, allow(unused_imports))]
pub(super) use native::{legacy_accounts, move_credentials};

/// This computer's keychain, never reached by a test.
mod native {
    use zeroize::Zeroizing;

    use super::super::credentials::{record_in, run_step, CurrentCredentials, LegacyCredentials};
    use super::super::credentials_macos::{accounts_metadata_only, default_keychain_locked, unless_locked};
    use super::super::journal::Journal;
    use super::super::{Roots, StepState};
    use crate::error::AppError;
    use crate::{identity, legacy_identity};

    /// The items of one service, through the keyring crate as the app reads and writes them.
    struct Keyring {
        service: &'static str,
    }

    /// What a saved value that is not text says: no retry makes it one.
    const NOT_TEXT: &str = "keychain error: the saved value is not text";

    fn failure(error: keyring::Error) -> AppError {
        match error {
            keyring::Error::BadEncoding(_) => AppError::Other(NOT_TEXT.into()),
            error => AppError::Other(format!("keychain error: {error}")),
        }
    }

    impl Keyring {
        fn entry(&self, account: &str) -> Result<keyring::Entry, AppError> {
            keyring::Entry::new(self.service, account).map_err(failure)
        }
        fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            match self.entry(account)?.get_password() {
                Ok(value) => Ok(Some(Zeroizing::new(value))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(error) => Err(failure(error)),
            }
        }
        fn remove(&self, account: &str) -> Result<(), AppError> {
            match self.entry(account)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(failure(error)),
            }
        }
    }

    impl LegacyCredentials for Keyring {
        fn accounts(&self) -> Result<Vec<String>, AppError> {
            accounts_metadata_only(self.service)
        }
        fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            self.get(account)
        }
        fn delete(&self, account: &str) -> Result<(), AppError> {
            self.remove(account)
        }
        fn unreadable_for_good(&self, error: &AppError) -> bool {
            matches!(error, AppError::Other(message) if message == NOT_TEXT)
        }
    }

    impl CurrentCredentials for Keyring {
        fn write(&self, account: &str, value: &str) -> Result<(), AppError> {
            self.entry(account)?.set_password(value).map_err(failure)
        }
        fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            self.get(account)
        }
        fn delete(&self, account: &str) -> Result<(), AppError> {
            self.remove(account)
        }
    }

    /// The credential step on this computer (the Development profile, in a start the user sees: `credentials::runs`).
    #[cfg_attr(test, allow(dead_code))]
    pub(in crate::identity_migration) fn move_credentials(roots: &Roots, journal: &mut Journal) -> StepState {
        assert!(!cfg!(test), "a test reached this computer's keychain, which holds the owner's own items");
        // A request that asks the user waits for the one before it to be answered, as every keychain request of this process does.
        let _access = crate::secrets::access_guard();
        unless_locked(default_keychain_locked(), journal, |journal| {
            run_step(
                &Keyring { service: legacy_identity::current().credential_service },
                &Keyring { service: identity::current().credential_service },
                journal,
                &record_in(roots),
            )
        })
    }

    /// The accounts under the earlier version's service.
    #[cfg_attr(test, allow(dead_code))]
    pub(in crate::identity_migration) fn legacy_accounts() -> Result<Vec<String>, AppError> {
        assert!(!cfg!(test), "a test reached this computer's keychain, which holds the owner's own items");
        accounts_metadata_only(legacy_identity::current().credential_service)
    }
}
