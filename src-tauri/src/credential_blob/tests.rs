//! Synthetic physical store: every OS entry enforces the SDK byte limit.
//! Only this test backend uses an AEAD model; production Windows uses DPAPI.
use super::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
pub(crate) struct Fixture {
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    entries: BTreeMap<String, Vec<u8>>,
    blobs: BTreeMap<String, Vec<u8>>,
    fail_file: bool,
    corrupt_file: bool,
    fail_entry: bool,
    commit_error: bool,
    readback_error: bool,
    fail_next_read: bool,
    fail_delete: bool,
    fail_cleanup: bool,
    entry_on_blob_read: Option<(String, Vec<u8>)>,
}
pub(crate) struct Slot<'a> {
    fixture: &'a Fixture,
    account: &'a str,
}
impl Fixture {
    pub(crate) fn slot<'a>(&'a self, account: &'a str) -> Slot<'a> {
        Slot {
            fixture: self,
            account,
        }
    }
}
impl Backend for Slot<'_> {
    fn get_entry(&self) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
        let mut s = self.fixture.state.lock().unwrap();
        if std::mem::take(&mut s.fail_next_read) {
            return Err(invalid());
        }
        Ok(s.entries.get(self.account).cloned().map(Zeroizing::new))
    }
    fn set_entry(&self, value: &[u8]) -> Result<(), AppError> {
        if value.len() > NATIVE_BYTES {
            return Err(invalid());
        }
        let mut s = self.fixture.state.lock().unwrap();
        if s.fail_entry {
            return Err(invalid());
        }
        s.entries.insert(self.account.into(), value.into());
        if s.readback_error {
            s.fail_next_read = true;
        }
        if s.commit_error {
            return Err(invalid());
        }
        Ok(())
    }
    fn delete_entry(&self) -> Result<(), AppError> {
        let mut s = self.fixture.state.lock().unwrap();
        if s.fail_delete {
            return Err(invalid());
        }
        s.entries.remove(self.account);
        Ok(())
    }
    fn protect(&self, value: &[u8], entropy: &[u8]) -> Result<Vec<u8>, AppError> {
        let key = Zeroizing::new(digest(entropy));
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| invalid())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(
            &XChaCha20Poly1305::new((&*key).into())
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: value,
                        aad: entropy,
                    },
                )
                .map_err(|_| invalid())?,
        );
        Ok(out)
    }
    fn unprotect(&self, value: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
        if value.len() < 40 {
            return Err(invalid());
        }
        let key = Zeroizing::new(digest(entropy));
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&value[..24]),
                Payload {
                    msg: &value[24..],
                    aad: entropy,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| invalid())
    }
    fn read_blob(&self, name: &str, limit: usize) -> Result<Vec<u8>, AppError> {
        let mut s = self.fixture.state.lock().unwrap();
        if let Some((account, entry)) = s.entry_on_blob_read.take() {
            s.entries.insert(account, entry);
            s.blobs.remove(name);
        }
        let v = s.blobs.get(name).ok_or_else(invalid)?;
        if v.len() > limit {
            return Err(invalid());
        }
        Ok(v.clone())
    }
    fn write_blob(&self, name: &str, value: &[u8]) -> Result<(), AppError> {
        let mut s = self.fixture.state.lock().unwrap();
        if s.fail_file || s.blobs.contains_key(name) {
            return Err(invalid());
        }
        let mut value = value.to_vec();
        if s.corrupt_file {
            value[0] ^= 1;
        }
        s.blobs.insert(name.into(), value);
        Ok(())
    }
    fn remove_blob(&self, name: &str) -> Result<(), AppError> {
        let mut s = self.fixture.state.lock().unwrap();
        if s.fail_cleanup {
            return Err(invalid());
        }
        s.blobs.remove(name);
        Ok(())
    }
}
const SERVICE: &str = "synthetic development service";
const ACCOUNT: &str = "synthetic account";
fn large() -> String {
    "synthetic sensitive text \u{1f512}".repeat(300)
}
#[test]
fn utf16_byte_boundary_legacy_and_large_values_survive_cold_reads() {
    let f = Fixture::default();
    let slot = f.slot(ACCOUNT);
    assert_eq!(get(&slot, SERVICE, ACCOUNT).unwrap(), None);
    for value in [
        String::new(),
        "x".repeat(1280),
        "\u{1f512}".repeat(640),
        "x".repeat(1281),
        "\u{1f512}".repeat(641),
        "中".repeat(1281),
    ] {
        set(&slot, SERVICE, ACCOUNT, &value).unwrap();
        let raw = slot.get_entry().unwrap().unwrap();
        assert!(raw.len() <= 2560);
        if value.encode_utf16().count() <= 1280 {
            assert_eq!(legacy(&raw).unwrap(), value);
        } else {
            assert_eq!(raw.len(), REFERENCE_BYTES);
            assert!(!raw.windows(16).any(|v| v == &value.as_bytes()[..16]));
        }
        assert_eq!(
            get(&f.slot(ACCOUNT), SERVICE, ACCOUNT).unwrap().as_deref(),
            Some(value.as_str())
        );
    }
    set(&slot, SERVICE, ACCOUNT, "legacy again").unwrap();
    assert_eq!(f.state.lock().unwrap().blobs.len(), 0);
}
#[test]
fn ciphertext_is_bound_to_current_os_pointer_service_and_account() {
    let f = Fixture::default();
    let slot = f.slot(ACCOUNT);
    let value = large();
    set(&slot, SERVICE, ACCOUNT, &value).unwrap();
    let old = slot.get_entry().unwrap().unwrap();
    let old_ref = reference(&old).unwrap().unwrap();
    let old_blob = slot.read_blob(&old_ref.name(), MAX_BLOB_BYTES).unwrap();
    assert!(!old_blob.windows(24).any(|v| v == &value.as_bytes()[..24]));
    assert!(get(&slot, "another service", ACCOUNT).is_err());
    assert!(get(&slot, SERVICE, "another account").is_err());
    set(&slot, SERVICE, ACCOUNT, &format!("{value} newer")).unwrap();
    let current = slot.get_entry().unwrap().unwrap();
    let current_ref = reference(&current).unwrap().unwrap();
    assert_ne!(*old, *current);
    // Replacing a current file with old ciphertext cannot restore old authority.
    let current_blob = slot.read_blob(&current_ref.name(), MAX_BLOB_BYTES).unwrap();
    f.state
        .lock()
        .unwrap()
        .blobs
        .insert(current_ref.name(), old_blob);
    assert!(get(&slot, SERVICE, ACCOUNT).is_err());
    assert_eq!(*slot.get_entry().unwrap().unwrap(), *current);
    f.state
        .lock()
        .unwrap()
        .blobs
        .insert(current_ref.name(), current_blob);
    assert!(get(&slot, SERVICE, ACCOUNT)
        .unwrap()
        .unwrap()
        .ends_with(" newer"));
    f.state.lock().unwrap().blobs.remove(&current_ref.name());
    assert!(get(&slot, SERVICE, ACCOUNT).is_err());
    assert_eq!(*slot.get_entry().unwrap().unwrap(), *current);
}
#[test]
fn failed_file_or_pointer_writes_keep_previous_credential_readable() {
    for failure in 0..3 {
        let f = Fixture::default();
        let slot = f.slot(ACCOUNT);
        set(&slot, SERVICE, ACCOUNT, &large()).unwrap();
        let old = slot.get_entry().unwrap().unwrap();
        {
            let mut s = f.state.lock().unwrap();
            match failure {
                0 => s.fail_file = true,
                1 => s.corrupt_file = true,
                _ => s.fail_entry = true,
            }
        }
        assert!(set(&slot, SERVICE, ACCOUNT, &format!("{} next", large())).is_err());
        assert_eq!(*slot.get_entry().unwrap().unwrap(), *old);
        assert_eq!(
            get(&slot, SERVICE, ACCOUNT).unwrap().as_deref(),
            Some(large().as_str())
        );
    }
}
#[test]
fn ambiguous_os_commit_keeps_new_payload_for_restart() {
    for readback in [false, true] {
        let f = Fixture::default();
        let slot = f.slot(ACCOUNT);
        set(&slot, SERVICE, ACCOUNT, "old").unwrap();
        {
            let mut s = f.state.lock().unwrap();
            s.commit_error = !readback;
            s.readback_error = readback;
        }
        let value = large();
        assert!(set(&slot, SERVICE, ACCOUNT, &value).is_err());
        {
            let mut s = f.state.lock().unwrap();
            s.commit_error = false;
            s.readback_error = false;
        }
        assert_eq!(
            get(&f.slot(ACCOUNT), SERVICE, ACCOUNT).unwrap().as_deref(),
            Some(value.as_str())
        );
    }
}
#[test]
fn forgetting_removes_os_authority_before_best_effort_ciphertext_cleanup() {
    let f = Fixture::default();
    let slot = f.slot(ACCOUNT);
    set(&slot, SERVICE, ACCOUNT, &large()).unwrap();
    let old = slot.get_entry().unwrap().unwrap();
    f.state.lock().unwrap().fail_delete = true;
    assert!(delete(&slot).is_err());
    assert_eq!(*slot.get_entry().unwrap().unwrap(), *old);
    f.state.lock().unwrap().fail_delete = false;
    f.state.lock().unwrap().fail_cleanup = true;
    delete(&slot).unwrap();
    assert!(get(&slot, SERVICE, ACCOUNT).unwrap().is_none());
    assert!(!f.state.lock().unwrap().blobs.is_empty());
    delete(&slot).unwrap();
}
#[test]
fn corrupt_descriptors_and_over_capacity_values_fail_without_reset_or_write() {
    let f = Fixture::default();
    let slot = f.slot(ACCOUNT);
    for bad in [vec![1], vec![0; NATIVE_BYTES + 1], vec![0xd8, 0xd8]] {
        f.state
            .lock()
            .unwrap()
            .entries
            .insert(ACCOUNT.into(), bad.clone());
        assert!(get(&slot, SERVICE, ACCOUNT).is_err());
        assert_eq!(*slot.get_entry().unwrap().unwrap(), bad);
    }
    set(&slot, SERVICE, ACCOUNT, "retained").unwrap();
    assert!(set(&slot, SERVICE, ACCOUNT, &"x".repeat(MAX_VALUE_BYTES + 1)).is_err());
    assert_eq!(
        get(&slot, SERVICE, ACCOUNT).unwrap().as_deref(),
        Some("retained")
    );
    for index in [0, 72, 76, 80] {
        set(&slot, SERVICE, ACCOUNT, &large()).unwrap();
        let mut raw = slot.get_entry().unwrap().unwrap().to_vec();
        raw[index] ^= 0xff;
        slot.set_entry(&raw).unwrap();
        assert!(get(&slot, SERVICE, ACCOUNT).is_err());
    }
}
#[test]
fn maximum_supported_value_uses_one_small_os_entry() {
    let f = Fixture::default();
    let slot = f.slot(ACCOUNT);
    let value = "x".repeat(MAX_VALUE_BYTES);
    set(&slot, SERVICE, ACCOUNT, &value).unwrap();
    assert_eq!(slot.get_entry().unwrap().unwrap().len(), 81);
    assert_eq!(
        get(&slot, SERVICE, ACCOUNT).unwrap().as_deref(),
        Some(value.as_str())
    );
}

#[test]
fn an_observed_concurrent_commit_retries_the_new_pointer_after_old_file_cleanup() {
    let f = Fixture::default();
    let slot = f.slot(ACCOUNT);
    set(&slot, SERVICE, ACCOUNT, &large()).unwrap();
    let old = slot.get_entry().unwrap().unwrap();
    let value = format!("{} newer", large());
    set(&slot, SERVICE, ACCOUNT, &value).unwrap();
    let current = slot.get_entry().unwrap().unwrap();
    slot.set_entry(&old).unwrap();
    f.state.lock().unwrap().entry_on_blob_read = Some((ACCOUNT.into(), current.to_vec()));
    assert_eq!(
        get(&slot, SERVICE, ACCOUNT).unwrap().as_deref(),
        Some(value.as_str())
    );
}
