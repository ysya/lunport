//! Linux: the Secret Service finds an item by its attributes; the keyring crate, which this app saves credentials with, gives each the
//! attributes `service` and `username` (the account) and the label `keyring:<account>@<service>`, in the default collection. An item
//! moves when it is created again with the new service's attributes and label and its old item is deleted. Nothing here unlocks or
//! asks anything: a locked collection keeps the step waiting for the user, who unlocks it and retries. Several old items of one
//! account are one item when they hold the same secret; when they differ, nothing tells which one is meant and nothing the user can do
//! in Lunport changes that, so the account stays behind for good. The move holds the same lock as the app's own reads and writes of a
//! credential (`secrets::access_guard`), so that none of them comes between a check and a write.

use zeroize::Zeroizing;

use super::credentials::{run_step, CurrentCredentials, LegacyCredentials};
use super::journal::Journal;
use super::StepState;
use crate::error::AppError;

/// What the move needs of the Secret Service, item by item.
pub(super) trait SecretItems {
    /// The accounts of the unlocked items whose `service` attribute is `service`, and how many of its items are locked.
    fn listing(&self, service: &str) -> Result<Listing, AppError>;
    /// The secrets of the unlocked items with these `service` and `username` attributes, none when there is none; an error when one is
    /// locked.
    fn secrets(&self, service: &str, account: &str) -> Result<Vec<Zeroizing<Vec<u8>>>, AppError>;
    /// Saves `secret` in the one unlocked item with these attributes, or, where there is none, in a new item in the default collection
    /// with `label`; several such items, or a locked one, are an error.
    fn save(&self, service: &str, account: &str, label: &str, secret: &[u8]) -> Result<(), AppError>;
    /// Deletes the unlocked items with these attributes; none is fine, a locked one is an error.
    fn delete(&self, service: &str, account: &str) -> Result<(), AppError>;
    /// Whether the default collection, where new items go, is locked.
    fn default_collection_locked(&self) -> Result<bool, AppError>;
}

/// The items of one service.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Listing {
    /// The accounts of its unlocked items.
    pub accounts: Vec<String>,
    /// How many of its items are locked: their attributes are not read.
    pub locked: usize,
}

/// The label the keyring crate gives the item of `account` under `service`.
pub(super) fn label(account: &str, service: &str) -> String {
    format!("keyring:{account}@{service}")
}

fn locked() -> AppError {
    AppError::Other("the keyring is locked: unlock it, then retry".into())
}

/// What a saved value that is not text says: no retry makes it one.
const NOT_TEXT: &str = "the saved value is not text";

/// What several old items of one account with different secrets say: no retry tells which one is meant.
const AMBIGUOUS: &str = "ambiguous: several old items differ";

/// The items of one service.
pub(super) struct Items<'a, S: ?Sized> {
    pub ss: &'a S,
    pub service: &'a str,
}

impl<S: SecretItems + ?Sized> Items<'_, S> {
    /// The value saved for `account`: copies of one item (the same secret under the same attributes) are that item, and items whose
    /// secrets differ are the error `differ`.
    fn get(&self, account: &str, differ: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        let secrets = self.ss.secrets(self.service, account)?;
        let Some((secret, copies)) = secrets.split_first() else { return Ok(None) };
        if copies.iter().any(|copy| copy.as_slice() != secret.as_slice()) {
            return Err(AppError::Other(differ.into()));
        }
        let text = std::str::from_utf8(secret).map_err(|_| AppError::Other(NOT_TEXT.into()))?;
        Ok(Some(Zeroizing::new(text.to_owned())))
    }
}

impl<S: SecretItems + ?Sized> LegacyCredentials for Items<'_, S> {
    fn accounts(&self) -> Result<Vec<String>, AppError> {
        let listing = self.ss.listing(self.service)?;
        if listing.locked > 0 {
            return Err(locked());
        }
        Ok(listing.accounts)
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.get(account, AMBIGUOUS)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.ss.delete(self.service, account)
    }
    fn unreadable_for_good(&self, error: &AppError) -> bool {
        matches!(error, AppError::Other(message) if message == NOT_TEXT || message == AMBIGUOUS)
    }
}

impl<S: SecretItems + ?Sized> CurrentCredentials for Items<'_, S> {
    fn write(&self, account: &str, value: &str) -> Result<(), AppError> {
        self.ss.save(self.service, account, &label(account, self.service), value.as_bytes())
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        self.get(account, "several items have this name, with different values")
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.ss.delete(self.service, account)
    }
}

/// The credential step with the items of service `old` in `ss` and service `new` (`credentials::run_step`), unless it would ask the
/// user to unlock something: a locked default collection or a locked old item (which may be the vault's key) leaves the step waiting
/// for the user, with why; Retry from the window moves them once the user has unlocked it.
pub(super) fn move_with(
    ss: &impl SecretItems,
    old: &str,
    new: &str,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
) -> StepState {
    let waiting = match (ss.default_collection_locked(), ss.listing(old)) {
        (Ok(false), Ok(listing)) if listing.locked == 0 => None,
        (Ok(_), Ok(_)) => Some(locked().to_string()),
        (Err(error), _) | (_, Err(error)) => Some(format!("the Secret Service could not be asked: {error}")),
    };
    if let Some(reason) = waiting {
        journal.credential_progress.waiting_for_the_user = true;
        return StepState::Failed(reason);
    }
    run_step(&Items { ss, service: old }, &Items { ss, service: new }, journal, record)
}

#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(unused_imports))]
pub(super) use native::{legacy_accounts, move_credentials};

/// This computer's Secret Service. Only built for Linux, and never reached by a test.
#[cfg(target_os = "linux")]
mod native {
    use std::collections::HashMap;

    use secret_service::blocking::SecretService;
    use secret_service::EncryptionType;
    use zeroize::Zeroizing;

    use super::super::credentials::record_in;
    use super::super::journal::Journal;
    use super::super::{Roots, StepState};
    use super::{locked, move_with, Listing, SecretItems};
    use crate::error::AppError;
    use crate::{identity, legacy_identity};

    /// The Secret Service through one connection.
    struct Native<'s>(&'s SecretService<'s>);

    fn failure(error: secret_service::Error) -> AppError {
        AppError::Other(format!("Secret Service: {error}"))
    }

    impl SecretItems for Native<'_> {
        fn listing(&self, service: &str) -> Result<Listing, AppError> {
            let (accounts, locked) = crate::secrets::linux_background::accounts(self.0, service)?;
            Ok(Listing { accounts, locked })
        }
        fn secrets(&self, service: &str, account: &str) -> Result<Vec<Zeroizing<Vec<u8>>>, AppError> {
            let found = self.0.search_items(HashMap::from([("service", service), ("username", account)])).map_err(failure)?;
            if !found.locked.is_empty() {
                return Err(locked());
            }
            found.unlocked.iter().map(|item| item.get_secret().map(Zeroizing::new).map_err(failure)).collect()
        }
        fn save(&self, service: &str, account: &str, label: &str, secret: &[u8]) -> Result<(), AppError> {
            let found = self.0.search_items(HashMap::from([("service", service), ("username", account)])).map_err(failure)?;
            if !found.locked.is_empty() {
                return Err(locked());
            }
            match found.unlocked.as_slice() {
                [] => {}
                [item] => return item.set_secret(secret, "text/plain").map_err(failure),
                _ => return Err(AppError::Other("several items have this name".into())),
            }
            let collection = self.0.get_default_collection().map_err(failure)?;
            if collection.is_locked().map_err(failure)? {
                return Err(locked());
            }
            let attributes = HashMap::from([("service", service), ("username", account)]);
            collection.create_item(label, attributes, secret, false, "text/plain").map_err(failure)?;
            Ok(())
        }
        fn delete(&self, service: &str, account: &str) -> Result<(), AppError> {
            let found = self.0.search_items(HashMap::from([("service", service), ("username", account)])).map_err(failure)?;
            if !found.locked.is_empty() {
                return Err(locked());
            }
            for item in &found.unlocked {
                item.delete().map_err(failure)?;
            }
            Ok(())
        }
        fn default_collection_locked(&self) -> Result<bool, AppError> {
            self.0.get_default_collection().and_then(|collection| collection.is_locked()).map_err(failure)
        }
    }

    /// The credential step on this computer (a start the user sees: `credentials::runs`).
    #[cfg_attr(test, allow(dead_code))]
    pub(in crate::identity_migration) fn move_credentials(roots: &Roots, journal: &mut Journal) -> StepState {
        assert!(!cfg!(test), "a test reached this computer's Secret Service");
        // Nothing else in this process reads or writes a credential meanwhile.
        let _access = crate::secrets::access_guard();
        let ss = match SecretService::connect(EncryptionType::Dh) {
            Ok(ss) => ss,
            Err(error) => return StepState::Failed(format!("the Secret Service could not be reached: {error}")),
        };
        let (old, new) = (legacy_identity::current().credential_service, identity::current().credential_service);
        move_with(&Native(&ss), old, new, journal, &record_in(roots))
    }

    /// The accounts under the earlier version's service; an error while any of its items is locked (it may be the vault's key).
    pub(in crate::identity_migration) fn legacy_accounts() -> Result<Vec<String>, AppError> {
        assert!(!cfg!(test), "a test reached this computer's Secret Service");
        let ss = SecretService::connect(EncryptionType::Dh).map_err(failure)?;
        let (accounts, locked_items) = crate::secrets::linux_background::accounts(&ss, legacy_identity::current().credential_service)?;
        if locked_items > 0 {
            return Err(locked());
        }
        Ok(accounts)
    }
}

#[cfg(test)]
#[path = "credentials_linux_tests.rs"]
mod tests;
