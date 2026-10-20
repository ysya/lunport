//! Read-only verification against the account-authoritative public identity.
use crate::sync::record_repository::{KeyStatus, KeyView};
use crate::vault::store::VaultEntry;

/// Presence and identity are different failures. Never suggest fetching a missing key when
/// bytes exist but fail the authoritative identity check, and never modify those bytes here.
pub const IDENTITY_MISMATCH: &str = "The saved SSH private key does not match this key reference.";
pub fn available(key: &KeyView, entry: Option<&VaultEntry>) -> Result<bool, &'static str> {
    entry.map_or(Ok(false), |entry| verify(key, entry).map(|()| true))
}

#[cfg(test)]
pub fn matches(key: &KeyView, entry: &VaultEntry) -> bool {
    verify(key, entry).is_ok()
}

/// Fixed diagnostics only: parser errors may contain private input and must never cross IPC.
pub fn verify(key: &KeyView, entry: &VaultEntry) -> Result<(), &'static str> {
    if key.status != KeyStatus::Available {
        return Err("This key reference is unavailable or needs review.");
    }
    if key.expected_material_hash.as_ref().is_some_and(|expected| {
        crate::sync::central::crypto::hash(entry.private_key.as_bytes()) != *expected
    }) {
        return Err("The saved private key differs from the encrypted account copy.");
    }
    let public = key
        .public
        .as_ref()
        .ok_or("This key has no public identity.")?;
    crate::sync::records_v3::key_material_matches(public, &entry.public_key, &entry.fingerprint)
        .map_err(|_| IDENTITY_MISMATCH)?;
    let private = crate::vault::material::parse(&entry.private_key)
        .ok_or("The saved SSH private key could not be parsed.")?;
    let identity =
        crate::vault::material::public_key_data(&public.public_key).ok_or(IDENTITY_MISMATCH)?;
    if private.public_key().key_data() != &identity {
        return Err(IDENTITY_MISMATCH);
    }
    if private.is_encrypted() != public.has_passphrase {
        return Err("The saved private key's passphrase state does not match this key reference.");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::record_repository::KeyAuthority;
    use crate::sync::records_v3::KeySlotPayload;
    use crate::sync::slot_rules::test_keys;
    use crate::vault::store::EntryOrigin;
    fn fixture() -> (KeyView, VaultEntry) {
        let public = ssh_key::PublicKey::from_openssh(test_keys::PLAIN_PUBLIC).unwrap();
        let fp = public.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        let key = KeyView {
            id: "a".repeat(32),
            authority: KeyAuthority::Account,
            public: Some(KeySlotPayload {
                schema: 2,
                name: "work".into(),
                public_key: test_keys::PLAIN_PUBLIC.into(),
                fingerprint: fp.clone(),
                key_type: "ssh-ed25519".into(),
                has_passphrase: false,
                created_at_ms: 1,
                origin_device_id: "d".repeat(32),
            }),
            vault_id: Some("b".repeat(32)),
            status: KeyStatus::Available,
            expected_material_hash: None,
        };
        let entry = VaultEntry {
            private_key: test_keys::plain(),
            public_key: test_keys::PLAIN_PUBLIC.into(),
            fingerprint: fp,
            origin: EntryOrigin::Imported,
            added_at_ms: 1,
        };
        (key, entry)
    }
    #[test]
    fn all_supported_vault_key_formats_keep_their_public_identity() {
        for text in [
            test_keys::plain(),
            test_keys::encrypted(),
            test_keys::rsa(),
            test_keys::ecdsa(),
            test_keys::ecdsa_short_p256(),
            test_keys::ecdsa_short_p256_encrypted(),
            test_keys::ecdsa_short_p384(),
            test_keys::ecdsa_short_p521(),
            test_keys::ecdsa_full_p256(),
        ] {
            let private = crate::vault::material::parse(&text).unwrap();
            let (mut key, mut entry) = fixture();
            entry.private_key = text;
            entry.public_key = private.public_key().to_openssh().unwrap();
            entry.fingerprint = private
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string();
            let public = key.public.as_mut().unwrap();
            public.public_key = entry.public_key.clone();
            public.fingerprint = entry.fingerprint.clone();
            public.key_type = private.public_key().algorithm().as_str().into();
            public.has_passphrase = private.is_encrypted();
            let kind = public.key_type.clone();
            let encrypted = public.has_passphrase;
            assert!(
                matches(&key, &entry),
                "usable {kind} key was rejected (encrypted: {encrypted})"
            );
        }
    }
    #[test]
    fn missing_material_and_an_existing_mismatched_key_have_distinct_results() {
        let (mut key, mut entry) = fixture();
        assert_eq!(available(&key, None), Ok(false));
        assert_eq!(available(&key, Some(&entry)), Ok(true));
        entry.private_key = test_keys::ecdsa();
        assert_eq!(available(&key, Some(&entry)), Err(IDENTITY_MISMATCH));
        entry.private_key = test_keys::plain();
        key.expected_material_hash = Some("0".repeat(64));
        assert_eq!(
            available(&key, Some(&entry)),
            Err("The saved private key differs from the encrypted account copy.")
        );
    }
    #[test]
    fn verification_reports_safe_reasons_without_parser_details() {
        let (mut key, mut entry) = fixture();
        entry.private_key = "PRIVATE fixture invalid OpenSSH data".into();
        assert_eq!(
            verify(&key, &entry),
            Err("The saved SSH private key could not be parsed.")
        );
        entry.private_key = test_keys::plain();
        key.public.as_mut().unwrap().has_passphrase = true;
        assert_eq!(
            verify(&key, &entry),
            Err("The saved private key's passphrase state does not match this key reference.")
        );
    }
    #[test]
    fn coherent_unencrypted_or_encrypted_material_is_usable_without_a_passphrase_prompt() {
        let (mut k, mut e) = fixture();
        assert!(matches(&k, &e));
        e.private_key = test_keys::encrypted();
        let private = crate::vault::material::parse(&e.private_key).unwrap();
        e.public_key = private.public_key().to_openssh().unwrap();
        e.fingerprint = private
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        let p = k.public.as_mut().unwrap();
        p.public_key = e.public_key.clone();
        p.fingerprint = e.fingerprint.clone();
        p.has_passphrase = true;
        assert!(matches(&k, &e));
    }
    #[test]
    fn a_matching_vault_label_cannot_hide_a_different_private_identity() {
        let (k, mut e) = fixture();
        e.private_key = test_keys::ecdsa();
        assert!(!matches(&k, &e));
    }
    #[test]
    fn inconsistent_public_metadata_or_unreadable_private_bytes_are_refused() {
        let (k, mut e) = fixture();
        e.fingerprint = "wrong".into();
        assert!(!matches(&k, &e));
        let (k, mut e) = fixture();
        e.public_key = test_keys::ECDSA_PUBLIC.into();
        assert!(!matches(&k, &e));
        let (k, mut e) = fixture();
        e.private_key = "not an OpenSSH private key".into();
        assert!(!matches(&k, &e));
    }
    #[test]
    fn deleted_or_conflicting_account_keys_cannot_fall_back_to_local_material() {
        let (mut k, e) = fixture();
        for status in [
            KeyStatus::Deleted,
            KeyStatus::Conflict,
            KeyStatus::NeedsMaterial,
        ] {
            k.status = status;
            assert!(!matches(&k, &e));
        }
    }
}
