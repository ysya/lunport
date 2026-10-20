use super::*;
use crate::sync::{
    env::Keychain,
    record_runtime,
    testkit::{MemKeychain, TestDevice},
};
use std::sync::atomic::{AtomicBool, Ordering};
fn fixture() -> (TestDevice, VaultKeys) {
    let (d, keys) = crate::sync::central::capture_dispatch::ready_for_test(false);
    source_complete::ensure(&d.env(), &keys).unwrap().unwrap();
    (d, keys)
}
#[test]
fn preview_is_pending_and_only_the_exact_ticket_can_create_durable_consent() {
    let (d, keys) = fixture();
    let env = d.env();
    let before = record_runtime::snapshot(&env).unwrap();
    let first = preview(&env, &keys, &BTreeMap::new()).unwrap();
    assert!(!first.approved);
    let loaded = ensure(&env, &keys, &BTreeMap::new()).unwrap();
    assert!(accepted(&env, &loaded).is_err());
    assert!(confirm(&env, &keys, &BTreeMap::new(), &"f".repeat(64)).is_err());
    let again = preview(&env, &keys, &BTreeMap::new()).unwrap();
    assert_eq!(first.ticket, again.ticket);
    assert!(!again.approved);
    confirm(&env, &keys, &BTreeMap::new(), &first.ticket).unwrap();
    accepted(&env, &loaded)
        .unwrap()
        .require_current(&env, &loaded)
        .unwrap();
    let checked = preview(&env, &keys, &BTreeMap::new()).unwrap();
    assert!(checked.approved);
    assert_eq!(checked.ticket, first.ticket);
    assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
    confirm(&env, &keys, &BTreeMap::new(), &first.ticket).unwrap();
}
struct Fault<'a> {
    inner: &'a MemKeychain,
    role: String,
    after: bool,
    armed: AtomicBool,
}
impl Keychain for Fault<'_> {
    fn get(&self, k: &str) -> Result<Option<String>, AppError> {
        self.inner.get(k)
    }
    fn get_noninteractive(&self, k: &str) -> Result<Option<String>, AppError> {
        self.inner.get_noninteractive(k)
    }
    fn set(&self, k: &str, v: &str) -> Result<(), AppError> {
        self.inner.set(k, v)
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        panic!("no credential deletion")
    }
    fn set_noninteractive(&self, k: &str, v: &str) -> Result<(), AppError> {
        let fail = k == self.role && self.armed.swap(false, Ordering::SeqCst);
        if fail && !self.after {
            return Err(invalid());
        }
        self.inner.set_noninteractive(k, v)?;
        if fail && self.after {
            return Err(invalid());
        }
        Ok(())
    }
}
#[test]
fn uncertain_confirmation_before_or_after_write_requires_exact_retry_and_never_recaptures_sources()
{
    for after in [false, true] {
        let (d, keys) = fixture();
        let env = d.env();
        let shown = preview(&env, &keys, &BTreeMap::new()).unwrap();
        let loaded = ensure(&env, &keys, &BTreeMap::new()).unwrap();
        let fault = Fault {
            inner: &d.keychain,
            role: role(&loaded).unwrap(),
            after,
            armed: AtomicBool::new(true),
        };
        let mut interrupted = d.env();
        interrupted.keychain = &fault;
        assert!(confirm(&interrupted, &keys, &BTreeMap::new(), &shown.ticket).is_err());
        assert_eq!(read(&env, &loaded).unwrap().unwrap().accepted, after);
        confirm(&env, &keys, &BTreeMap::new(), &shown.ticket).unwrap();
        let restored = ensure(&env, &keys, &BTreeMap::new()).unwrap();
        assert_eq!(restored.cursor.receipt(), loaded.cursor.receipt());
        assert!(accepted(&env, &restored).is_ok());
    }
}
#[test]
fn changed_binding_unknown_policy_missing_and_corrupt_protected_reviews_do_not_grant_consent() {
    for case in [
        "source",
        "plan",
        "manifest",
        "selection",
        "policy",
        "ticket",
        "version",
        "missing",
        "corrupt",
    ] {
        let (d, keys) = fixture();
        let env = d.env();
        let shown = preview(&env, &keys, &BTreeMap::new()).unwrap();
        let loaded = ensure(&env, &keys, &BTreeMap::new()).unwrap();
        let role = role(&loaded).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&d.keychain.entry(&role).unwrap()).unwrap();
        value["accepted"] = true.into();
        match case {
            "source" | "plan" => value["binding"][case]["ciphertext_hash"] = "9".repeat(64).into(),
            "manifest" => value["binding"][case] = "9".repeat(64).into(),
            "selection" => value["binding"][case] = "8".repeat(32).into(),
            "policy" => value["binding"][case] = "unknown-policy".into(),
            "ticket" => value[case] = "invalid".into(),
            "version" => value[case] = 2.into(),
            _ => {}
        }
        if case == "missing" {
            d.keychain.delete(&role).unwrap();
        } else {
            let encoded = if case == "corrupt" {
                "broken".into()
            } else {
                serde_json::to_string(&value).unwrap()
            };
            d.keychain.set(&role, &encoded).unwrap();
        }
        assert!(accepted(&env, &loaded).is_err(), "{case}");
        assert!(
            confirm(&env, &keys, &BTreeMap::new(), &shown.ticket).is_err(),
            "{case}"
        );
    }
}
#[test]
fn source_changes_prevent_confirmation_even_for_an_existing_exact_ticket() {
    let (d, keys) = fixture();
    let env = d.env();
    let shown = preview(&env, &keys, &BTreeMap::new()).unwrap();
    std::fs::write(&env.state_path, b"source B").unwrap();
    assert!(confirm(&env, &keys, &BTreeMap::new(), &shown.ticket).is_err());
}
#[test]
fn preview_exposes_public_key_versions_and_retained_history_without_material_or_internal_hashes() {
    let history = crate::sync::central::migration_history::tests::library();
    let view = summary(&history).unwrap();
    assert_eq!(view.history_records, 6);
    assert_eq!(view.private_key_versions, 2);
    assert_eq!(view.key_versions.len(), 2);
    assert!(view.key_versions[1].retained);
    let value = serde_json::to_string(&view).unwrap();
    for forbidden in [
        "PRIVATE KEY",
        "private_key\"",
        "sha256",
        "content_hash",
        "inventory_digest",
        "ciphertext",
        "source_cursor",
    ] {
        assert!(!value.contains(forbidden), "{forbidden}");
    }
    assert!(value.contains("fingerprint"));
    assert!(value.contains("managed"));
}
