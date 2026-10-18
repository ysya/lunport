//! Read-only verification against the account-authoritative public identity.
use crate::sync::record_repository::{KeyStatus, KeyView};
use crate::vault::store::VaultEntry;

pub fn matches(key: &KeyView, entry: &VaultEntry) -> bool {
    if key.status != KeyStatus::Available {
        return false;
    }
    if key.expected_material_hash.as_ref().is_some_and(|expected| {
        crate::sync::central::crypto::hash(entry.private_key.as_bytes()) != *expected
    }) {
        return false;
    }
    let Some(public) = &key.public else {
        return false;
    };
    if crate::sync::records_v3::key_material_matches(public, &entry.public_key, &entry.fingerprint)
        .is_err()
    {
        return false;
    }
    let Some(private) = crate::vault::material::parse(&entry.private_key) else {
        return false;
    };
    let Some(identity) = crate::vault::material::public_key_data(&public.public_key) else {
        return false;
    };
    private.public_key().key_data() == &identity && private.is_encrypted() == public.has_passphrase
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
