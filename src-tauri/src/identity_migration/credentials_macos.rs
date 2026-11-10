//! The macOS keychain items an earlier version saved, as the credential migration lists them, for both profiles: the accounts under
//! one service in the user's default keychain, the only keychain the credential helpers and the keyring crate read, from the items'
//! attributes alone. The search never returns an item's data and never lets macOS ask anything: a locked keychain is reported, not
//! unlocked, and the credential step then waits for the user, who unlocks it and retries (`unless_locked`).

use std::ffi::c_void;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll, kSecMatchSearchList,
    kSecReturnAttributes, kSecUseAuthenticationUI,
};

use super::journal::Journal;
use super::StepState;
use crate::error::AppError;

#[link(name = "Security", kind = "framework")]
extern "C" {
    /// The value of `kSecUseAuthenticationUI` that makes a search fail with errSecInteractionNotAllowed where it would need to ask the
    /// user (security-framework-sys does not bind it).
    static kSecUseAuthenticationUIFail: CFStringRef;
    fn SecKeychainGetStatus(keychain: security_framework_sys::base::SecKeychainRef, status: *mut u32) -> i32;
}

/// `kSecUnlockStateStatus`: the keychain is unlocked.
const UNLOCKED: u32 = 1;
/// `errSecItemNotFound`: the search matched nothing.
const ITEM_NOT_FOUND: i32 = -25300;
/// `errSecInteractionNotAllowed`: the search would have had to ask the user (to unlock the keychain).
const INTERACTION_NOT_ALLOWED: i32 = -25308;

/// Why the credential step waits for a locked keychain.
pub(super) const LOCKED: &str = "the keychain is locked: unlock it, then retry";

/// The accounts saved under `service` in the user's default keychain, from the attributes of its generic passwords. Nothing is read
/// but attributes, and nothing is asked: a locked keychain is an error (`LOCKED`).
pub(super) fn accounts_metadata_only(service: &str) -> Result<Vec<String>, AppError> {
    assert!(!cfg!(test), "a test reached this computer's keychain, which holds the owner's own items");
    let keychain = default_keychain()?;
    // A search of a locked keychain would ask to unlock it.
    if is_locked(&keychain)? {
        return Err(AppError::Other(LOCKED.into()));
    }
    let query = metadata_query(service, &keychain.as_CFType());
    let mut result: CFTypeRef = std::ptr::null();
    let status = unsafe { security_framework_sys::keychain_item::SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    match status {
        0 if result.is_null() => Ok(Vec::new()),
        0 => Ok(accounts_in(&unsafe { CFType::wrap_under_create_rule(result) }, service)),
        ITEM_NOT_FOUND => Ok(Vec::new()),
        INTERACTION_NOT_ALLOWED => Err(AppError::Other(LOCKED.into())),
        other => Err(AppError::Other(format!("keychain error: the saved credentials could not be listed (OSStatus {other})"))),
    }
}

/// Whether the user's default keychain is locked. Asks nothing.
pub(super) fn default_keychain_locked() -> Result<bool, AppError> {
    assert!(!cfg!(test), "a test reached this computer's keychain, which holds the owner's own items");
    is_locked(&default_keychain()?)
}

fn default_keychain() -> Result<security_framework::os::macos::keychain::SecKeychain, AppError> {
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
    SecKeychain::default_for_domain(SecPreferencesDomain::User)
        .map_err(|error| AppError::Other(format!("keychain error: the default keychain could not be found: {error}")))
}

fn is_locked(keychain: &security_framework::os::macos::keychain::SecKeychain) -> Result<bool, AppError> {
    let mut status = 0u32;
    match unsafe { SecKeychainGetStatus(keychain.as_concrete_TypeRef(), &mut status) } {
        0 => Ok(status & UNLOCKED == 0),
        other => Err(AppError::Other(format!("keychain error: the default keychain's state could not be read (OSStatus {other})"))),
    }
}

/// The search for every generic password saved under `service` in `keychain` (the user's default keychain) that returns the
/// attributes of each and never its data, and fails rather than ask the user anything: the class, the service, kSecReturnAttributes,
/// kSecMatchLimitAll, kSecMatchSearchList with `keychain` alone, and kSecUseAuthenticationUI set to fail. Nothing else.
fn metadata_query(service: &str, keychain: &CFType) -> CFDictionary<CFString, CFType> {
    let constant = |name: CFStringRef| unsafe { CFString::wrap_under_get_rule(name) };
    unsafe {
        CFDictionary::from_CFType_pairs(&[
            (constant(kSecClass), constant(kSecClassGenericPassword).into_CFType()),
            (constant(kSecAttrService), CFString::new(service).into_CFType()),
            (constant(kSecReturnAttributes), CFBoolean::true_value().into_CFType()),
            (constant(kSecMatchLimit), constant(kSecMatchLimitAll).into_CFType()),
            (constant(kSecMatchSearchList), CFArray::from_CFTypes(&[keychain.clone()]).into_CFType()),
            (constant(kSecUseAuthenticationUI), constant(kSecUseAuthenticationUIFail).into_CFType()),
        ])
    }
}

/// The accounts of the items the search returned: an array with one attribute dictionary per item, or one dictionary. An item of
/// another service, or one without an account, is left out.
fn accounts_in(result: &CFType, service: &str) -> Vec<String> {
    let items: Vec<CFDictionary> = match result.downcast::<CFArray>() {
        Some(array) => array.iter().filter_map(|item| unsafe { CFType::wrap_under_get_rule(*item) }.downcast::<CFDictionary>()).collect(),
        None => result.downcast::<CFDictionary>().into_iter().collect(),
    };
    items
        .iter()
        .filter(|item| text(item, unsafe { kSecAttrService }).as_deref() == Some(service))
        .filter_map(|item| text(item, unsafe { kSecAttrAccount }))
        .collect()
}

/// The string `item` holds under `key`; `None` when it holds none, or something else.
fn text(item: &CFDictionary, key: CFStringRef) -> Option<String> {
    let value = item.find(key as *const c_void)?;
    unsafe { CFType::wrap_under_get_rule(*value) }.downcast::<CFString>().map(|value| value.to_string())
}

/// The credential step of a macOS store (`step`), unless the default keychain is locked, as `locked` says: then the step waits for the
/// user, nothing is read, and Retry from the window moves them once the user has unlocked it. A keychain whose state cannot be read is
/// tried again by a later start.
pub(super) fn unless_locked(
    locked: Result<bool, AppError>,
    journal: &mut Journal,
    step: impl FnOnce(&mut Journal) -> StepState,
) -> StepState {
    match locked {
        Ok(false) => step(journal),
        Ok(true) => {
            journal.credential_progress.waiting_for_the_user = true;
            StepState::Failed(LOCKED.into())
        }
        Err(error) => StepState::Failed(format!("the keychain could not be asked whether it is locked: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_foundation::data::CFData;
    use security_framework_sys::item::{kSecReturnData, kSecReturnPersistentRef, kSecReturnRef, kSecValueData};

    const SERVICE: &str = "Acme Earlier Service";

    fn key(name: CFStringRef) -> CFString {
        unsafe { CFString::wrap_under_get_rule(name) }
    }

    /// The query asks for one service's generic passwords in the default keychain alone, every one of them, returns their attributes
    /// and fails rather than ask the user: six keys, and none that would return data or a reference to read it through.
    #[test]
    fn the_query_returns_attributes_of_every_generic_password_of_one_service_and_never_data() {
        // Stands in for the user's default keychain: no test reaches the real one.
        let keychain = CFString::new("the default keychain").into_CFType();
        let query = metadata_query(SERVICE, &keychain);
        assert_eq!(query.len(), 6);
        let value = |name: CFStringRef| query.find(&key(name)).map(|value| value.clone());
        assert_eq!(value(unsafe { kSecClass }).unwrap().downcast::<CFString>().unwrap(), key(unsafe { kSecClassGenericPassword }));
        assert_eq!(value(unsafe { kSecAttrService }).unwrap().downcast::<CFString>().unwrap().to_string(), SERVICE);
        assert_eq!(value(unsafe { kSecReturnAttributes }).unwrap().downcast::<CFBoolean>().unwrap(), CFBoolean::true_value());
        assert_eq!(value(unsafe { kSecMatchLimit }).unwrap().downcast::<CFString>().unwrap(), key(unsafe { kSecMatchLimitAll }));
        for absent in unsafe { [kSecReturnData, kSecReturnRef, kSecReturnPersistentRef, kSecValueData] } {
            assert!(value(absent).is_none(), "{}", key(absent));
        }
    }

    /// The search covers the default keychain alone (the helpers read no other), and never asks the user anything, not even to unlock.
    #[test]
    fn the_query_searches_the_default_keychain_alone_and_never_asks() {
        let keychain = CFString::new("the default keychain").into_CFType();
        let query = metadata_query(SERVICE, &keychain);
        let list = query.find(&key(unsafe { kSecMatchSearchList })).unwrap().downcast::<CFArray>().unwrap();
        let searched: Vec<CFType> = list.iter().map(|item| unsafe { CFType::wrap_under_get_rule(*item) }).collect();
        assert_eq!(searched, [keychain]);
        let ui = query.find(&key(unsafe { kSecUseAuthenticationUI })).unwrap().downcast::<CFString>().unwrap();
        assert_eq!(ui, key(unsafe { kSecUseAuthenticationUIFail }));
    }

    // One item's attributes as the search returns them: the keychain's own keys (`svce` the service, `acct` the account).
    fn attributes(pairs: &[(CFStringRef, CFType)]) -> CFType {
        let pairs: Vec<(CFString, CFType)> = pairs.iter().map(|(name, value)| (key(*name), value.clone())).collect();
        CFDictionary::from_CFType_pairs(&pairs).into_CFType()
    }

    fn string(value: &str) -> CFType {
        CFString::new(value).into_CFType()
    }

    #[test]
    fn the_accounts_come_from_each_items_attributes() {
        let (service, account) = unsafe { (kSecAttrService, kSecAttrAccount) };
        let items = [
            attributes(&[(service, string(SERVICE)), (account, string("host:web-1"))]),
            attributes(&[(service, string(SERVICE)), (account, string("vault:key"))]),
            // Another service, though the query asks for one: left out.
            attributes(&[(service, string("Acme Other Service")), (account, string("host:other"))]),
            // No account, or an account that is not a string: nothing to list.
            attributes(&[(service, string(SERVICE))]),
            attributes(&[(service, string(SERVICE)), (account, CFData::from_buffer(b"not text").into_CFType())]),
        ];
        let result = CFArray::from_CFTypes(&items).into_CFType();
        assert_eq!(accounts_in(&result, SERVICE), ["host:web-1", "vault:key"]);
        // A search that found one item may return its dictionary alone.
        assert_eq!(accounts_in(&items[1], SERVICE), ["vault:key"]);
        assert!(accounts_in(&string("unexpected"), SERVICE).is_empty());
        assert!(accounts_in(&CFArray::<CFType>::from_CFTypes(&[]).into_CFType(), SERVICE).is_empty());
    }

    /// Accounts are listed exactly, including the long and unusual ones the app saves (`central:v2:…`, non-ASCII aliases).
    #[test]
    fn accounts_are_listed_exactly_as_saved() {
        let (service, account) = unsafe { (kSecAttrService, kSecAttrAccount) };
        let saved = ["central:v2:replacement-archive-1:acme-prod-123456/web-1", "host:サーバー", "migration:2:vault:key:0123456789abcdef"];
        let items: Vec<CFType> = saved.iter().map(|name| attributes(&[(service, string(SERVICE)), (account, string(name))])).collect();
        assert_eq!(accounts_in(&CFArray::from_CFTypes(&items).into_CFType(), SERVICE), saved);
    }

    /// A locked keychain leaves the step waiting for the user, with why, and reads nothing; one whose state cannot be read leaves it
    /// for a later start; an unlocked one runs the step.
    #[test]
    fn a_locked_keychain_waits_for_the_user_and_reads_nothing() {
        let mut journal = Journal::default();
        let state = unless_locked(Ok(true), &mut journal, |_| panic!("a locked keychain was read"));
        assert_eq!(state, StepState::Failed(LOCKED.into()));
        assert!(journal.credential_progress.waiting_for_the_user);

        let mut journal = Journal::default();
        let state = unless_locked(Err(AppError::Other("no default keychain".into())), &mut journal, |_| panic!("read"));
        assert!(matches!(&state, StepState::Failed(reason) if reason.contains("no default keychain")), "{state:?}");
        assert!(!journal.credential_progress.waiting_for_the_user, "nothing the user can do");

        let mut journal = Journal::default();
        assert_eq!(unless_locked(Ok(false), &mut journal, |_| StepState::Done), StepState::Done);
        assert!(!journal.credential_progress.waiting_for_the_user);
    }
}
