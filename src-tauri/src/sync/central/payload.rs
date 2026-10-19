//! Typed admission between authenticated ciphertext history and the existing library repository.
//! Private material has no Debug/Serialize/frontend representation. A borrowed raw JSON body avoids
//! copying it through an untyped Value or returning parser error text containing decrypted data.
use super::{
    crypto::{self, VaultKeys},
    wire::{canonical, hex, invalid, RecordHeader, MAX_PLAINTEXT_BYTES},
};
use crate::{
    error::AppError,
    sync::records_v3::{
        self, GroupPayload, GroupRecord, HostPayload, HostRecord, HostScope, KeySlotPayload,
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use zeroize::Zeroizing;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub kind: String,
    pub id: String,
    pub scope: Option<HostScope>,
}
impl Identity {
    pub fn validate(&self) -> Result<(), AppError> {
        if let Some(HostScope::Space { space_id }) = &self.scope {
            if !hex(space_id, 64) {
                return Err(invalid());
            }
        }
        match self.kind.as_str() {
            "host" | "group" if hex(&self.id, 16) && self.scope.is_some() => Ok(()),
            "keyslot" | "key" if hex(&self.id, 32) && self.scope.is_none() => Ok(()),
            "meta" if self.id == "catalog" && self.scope.is_none() => Ok(()),
            _ => Err(invalid()),
        }
    }
    pub fn opaque(&self, keys: &VaultKeys) -> Result<String, AppError> {
        self.validate()?;
        let (kind, scope) = match &self.scope {
            None => ("account", ""),
            Some(HostScope::Local) => ("local", ""),
            Some(HostScope::Space { space_id }) => ("space", space_id.as_str()),
        };
        let binding = canonical(&[
            "lunport-library-identity-v1",
            &self.kind,
            kind,
            scope,
            &self.id,
        ])?;
        keys.record_id(
            &self.kind,
            std::str::from_utf8(&binding).map_err(|_| invalid())?,
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyStorage {
    Managed { sha256: String },
    Hardware,
    ExternalAgent,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedKeyslot {
    pub public: KeySlotPayload,
    pub storage: KeyStorage,
}
impl SharedKeyslot {
    pub fn validate(&self, id: &str) -> Result<(), AppError> {
        records_v3::validate_keyslot(id, &self.public).map_err(|_| invalid())?;
        if let KeyStorage::Managed { sha256 } = &self.storage {
            if !hex(sha256, 64)
                || crate::vault::material::public_key_data(&self.public.public_key)
                    .is_none_or(|key| !crate::vault::material::agent_can_sign(&key))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateMaterial {
    pub fingerprint: String,
    #[serde(deserialize_with = "secret")]
    private_key: Zeroizing<String>,
}
impl PrivateMaterial {
    pub fn new(private_key: Zeroizing<String>) -> Result<Self, AppError> {
        let parsed = crate::vault::material::parse(&private_key).ok_or_else(invalid)?;
        let value = Self {
            fingerprint: parsed
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
            private_key,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn private(&self) -> &str {
        &self.private_key
    }
    pub fn digest(&self) -> String {
        crypto::hash(self.private_key.as_bytes())
    }
    pub fn validate(&self) -> Result<(), AppError> {
        if self.private_key.len() > MAX_PLAINTEXT_BYTES {
            return Err(invalid());
        }
        let parsed = crate::vault::material::parse(&self.private_key).ok_or_else(invalid)?;
        if parsed
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
            != self.fingerprint
            || !crate::vault::material::agent_can_sign(parsed.public_key().key_data())
            || crate::vault::material::unsupported_cipher(&self.private_key).is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Only a matching exportable managed key may enter App Keychain. Reference-only sources never do.
    pub fn validate_against(&self, id: &str, slot: &SharedKeyslot) -> Result<(), AppError> {
        self.validate()?;
        slot.validate(id)?;
        let KeyStorage::Managed { sha256 } = &slot.storage else {
            return Err(invalid());
        };
        let parsed = crate::vault::material::parse(&self.private_key).ok_or_else(invalid)?;
        if &self.digest() != sha256
            || self.fingerprint != slot.public.fingerprint
            || parsed.is_encrypted() != slot.public.has_passphrase
            || Some(parsed.public_key().key_data().clone())
                != crate::vault::material::public_key_data(&slot.public.public_key)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupOrder {
    pub scope: HostScope,
    pub ids: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub collections: Vec<Collection>,
    pub group_orders: Vec<GroupOrder>,
}
impl Catalog {
    pub fn validate(&self) -> Result<(), AppError> {
        let mut ids = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        if self.collections.len() > 256 || self.group_orders.len() > 257 {
            return Err(invalid());
        }
        for c in &self.collections {
            if !hex(&c.id, 64)
                || !ids.insert(&c.id)
                || c.name.trim() != c.name
                || c.name.is_empty()
                || c.name.chars().count() > 128
                || c.name.chars().any(char::is_control)
            {
                return Err(invalid());
            }
        }
        let mut groups = 0;
        for order in &self.group_orders {
            if !scopes.insert(&order.scope) || !crate::sync::group_order::valid_ids(&order.ids) {
                return Err(invalid());
            }
            if let HostScope::Space { space_id } = &order.scope {
                if !ids.contains(space_id) {
                    return Err(invalid());
                }
            }
            groups += order.ids.len();
            if groups > 4096 {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
/// Not Serialize/Debug: callers must consciously encrypt or selectively publish public variants.
pub enum Data {
    Deleted,
    Host(HostPayload),
    Group(GroupPayload),
    Keyslot(SharedKeyslot),
    Key(PrivateMaterial),
    Catalog(Catalog),
}
pub struct Admitted {
    pub identity: Identity,
    pub data: Data,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Incoming<'a> {
    schema: u32,
    id: String,
    scope: Option<HostScope>,
    #[serde(borrow)]
    payload: &'a RawValue,
}
fn check(identity: &Identity, data: &Data) -> Result<(), AppError> {
    identity.validate()?;
    match (identity.kind.as_str(), data) {
        (_, Data::Deleted) => Ok(()),
        ("host", Data::Host(payload)) => records_v3::validate_host_shape(&HostRecord {
            id: identity.id.clone(),
            scope: identity.scope.clone().ok_or_else(invalid)?,
            payload: payload.clone(),
        })
        .map_err(|_| invalid()),
        ("group", Data::Group(payload)) => records_v3::validate_group(&GroupRecord {
            id: identity.id.clone(),
            scope: identity.scope.clone().ok_or_else(invalid)?,
            payload: payload.clone(),
        })
        .map_err(|_| invalid()),
        ("keyslot", Data::Keyslot(slot)) => slot.validate(&identity.id),
        ("key", Data::Key(material)) => material.validate(),
        ("meta", Data::Catalog(catalog)) => catalog.validate(),
        _ => Err(invalid()),
    }
}
/// Call only on plaintext returned by signature/epoch/AEAD-verified history, before any publication.
pub fn admit(
    keys: &VaultKeys,
    header: &RecordHeader,
    plaintext: &[u8],
) -> Result<Admitted, AppError> {
    header.validate()?;
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(invalid());
    }
    let incoming: Incoming<'_> = serde_json::from_slice(plaintext).map_err(|_| invalid())?;
    let identity = Identity {
        kind: header.kind.clone(),
        id: incoming.id.clone(),
        scope: incoming.scope.clone(),
    };
    if incoming.schema != 1 || identity.opaque(keys)? != header.record_id {
        return Err(invalid());
    }
    logical(header.kind.as_str(), header.deleted, incoming)
}
/// Native signed-history admission only. This does not authenticate an original record envelope.
pub(in crate::sync::central) fn admit_snapshot(
    kind: &str,
    deleted: bool,
    plaintext: &[u8],
) -> Result<Admitted, AppError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(invalid());
    }
    let incoming: Incoming<'_> = serde_json::from_slice(plaintext).map_err(|_| invalid())?;
    if incoming.schema != 1 {
        return Err(invalid());
    }
    logical(kind, deleted, incoming)
}
fn logical(kind: &str, deleted: bool, incoming: Incoming<'_>) -> Result<Admitted, AppError> {
    let identity = Identity {
        kind: kind.into(),
        id: incoming.id,
        scope: incoming.scope,
    };
    let raw = incoming.payload.get();
    let data = if deleted {
        if raw != "null" {
            return Err(invalid());
        }
        Data::Deleted
    } else {
        match kind {
            "host" => Data::Host(serde_json::from_str(raw).map_err(|_| invalid())?),
            "group" => Data::Group(serde_json::from_str(raw).map_err(|_| invalid())?),
            "keyslot" => Data::Keyslot(serde_json::from_str(raw).map_err(|_| invalid())?),
            "key" => Data::Key(serde_json::from_str(raw).map_err(|_| invalid())?),
            "meta" => Data::Catalog(serde_json::from_str(raw).map_err(|_| invalid())?),
            _ => return Err(invalid()),
        }
    };
    check(&identity, &data)?;
    Ok(Admitted { identity, data })
}
fn bytes<T: Serialize>(identity: &Identity, payload: &T) -> Result<Zeroizing<Vec<u8>>, AppError> {
    #[derive(Serialize)]
    struct Outgoing<'a, T> {
        schema: u32,
        id: &'a str,
        scope: &'a Option<HostScope>,
        payload: &'a T,
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(&Outgoing {
            schema: 1,
            id: &identity.id,
            scope: &identity.scope,
            payload,
        })
        .map_err(|_| invalid())?,
    );
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}
pub fn encode(identity: &Identity, data: &Data) -> Result<Zeroizing<Vec<u8>>, AppError> {
    check(identity, data)?;
    match data {
        Data::Deleted => bytes(identity, &Option::<()>::None),
        Data::Host(host) => bytes(identity, host),
        Data::Group(group) => bytes(identity, group),
        Data::Keyslot(slot) => bytes(identity, slot),
        Data::Catalog(catalog) => bytes(identity, catalog),
        Data::Key(material) => {
            #[derive(Serialize)]
            struct Private<'a> {
                fingerprint: &'a str,
                private_key: &'a str,
            }
            bytes(
                identity,
                &Private {
                    fingerprint: &material.fingerprint,
                    private_key: &material.private_key,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::crypto::{self, DeviceKeys};
    use super::*;
    use crate::sync::slot_rules::test_keys;
    use serde_json::json;
    fn identity(kind: &str) -> Identity {
        Identity {
            kind: kind.into(),
            id: match kind {
                "host" | "group" => "a".repeat(16),
                "meta" => "catalog".into(),
                _ => "b".repeat(32),
            },
            scope: matches!(kind, "host" | "group").then_some(HostScope::Local),
        }
    }
    fn header(id: &Identity, keys: &VaultKeys) -> RecordHeader {
        RecordHeader {
            origin: "https://relay.test".into(),
            account_id: "a".repeat(64),
            genesis_hash: "b".repeat(64),
            vault_id: "c".repeat(64),
            record_id: id.opaque(keys).unwrap(),
            key_epoch: "1".into(),
            membership_head: "b".repeat(64),
            author: "d".repeat(32),
            operation_id: "e".repeat(32),
            expected_revision: "0".into(),
            kind: id.kind.clone(),
            deleted: false,
        }
    }
    fn host() -> HostPayload {
        serde_json::from_value(
            json!({"schema":2,"alias":"fixture","hostname":"fixture.invalid","auth":"password"}),
        )
        .unwrap()
    }
    fn slot(private: &str) -> SharedKeyslot {
        let key = crate::vault::material::parse(private).unwrap();
        SharedKeyslot {
            public: KeySlotPayload {
                schema: 2,
                name: "Synthetic key".into(),
                public_key: key.public_key().to_openssh().unwrap(),
                fingerprint: key
                    .public_key()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string(),
                key_type: key.algorithm().as_str().into(),
                has_passphrase: key.is_encrypted(),
                created_at_ms: 1,
                origin_device_id: "d".repeat(32),
            },
            storage: KeyStorage::Managed {
                sha256: crypto::hash(private.as_bytes()),
            },
        }
    }
    #[test]
    fn host_identity_is_scoped_and_a_scope_or_kind_splice_cannot_enter_the_library() {
        let keys = VaultKeys::generate().unwrap();
        let local = identity("host");
        let mut space = local.clone();
        space.scope = Some(HostScope::Space {
            space_id: "f".repeat(64),
        });
        assert_ne!(local.opaque(&keys).unwrap(), space.opaque(&keys).unwrap());
        let bytes = encode(&local, &Data::Host(host())).unwrap();
        assert!(admit(&keys, &header(&local, &keys), &bytes).is_ok());
        assert!(admit(&keys, &header(&space, &keys), &bytes).is_err());
        let mut wrong = header(&local, &keys);
        wrong.kind = "group".into();
        assert!(admit(&keys, &wrong, &bytes).is_err());
        let mut deleted = header(&local, &keys);
        deleted.deleted = true;
        assert!(admit(&keys, &deleted, &bytes).is_err());
        let tombstone = encode(&local, &Data::Deleted).unwrap();
        assert!(matches!(
            admit(&keys, &deleted, &tombstone).unwrap().data,
            Data::Deleted
        ));
    }
    #[test]
    fn an_encrypted_openssh_key_round_trips_without_decrypting_or_reencoding_and_references_cannot_activate_it(
    ) {
        let original = Zeroizing::new(test_keys::encrypted());
        let keys = VaultKeys::generate().unwrap();
        let device = DeviceKeys::generate().unwrap();
        let id = identity("key");
        let data = Data::Key(PrivateMaterial::new(Zeroizing::new(original.to_string())).unwrap());
        let bytes = encode(&id, &data).unwrap();
        let header = header(&id, &keys);
        let sealed = crypto::seal_record(&keys, &device, header, &bytes).unwrap();
        let opened = sealed
            .verify(&device.public().signing)
            .unwrap()
            .open(&keys)
            .unwrap();
        let decoded = admit(&keys, &sealed.header, &opened).unwrap();
        let Data::Key(material) = decoded.data else {
            panic!("expected private material");
        };
        assert_eq!(material.private(), original.as_str());
        assert!(crate::vault::material::parse(material.private())
            .unwrap()
            .is_encrypted());
        let mut metadata = slot(&original);
        metadata.validate(&id.id).unwrap();
        material.validate_against(&id.id, &metadata).unwrap();
        metadata.storage = KeyStorage::Hardware;
        assert!(material.validate_against(&id.id, &metadata).is_err());
        metadata.storage = KeyStorage::ExternalAgent;
        assert!(material.validate_against(&id.id, &metadata).is_err());
        metadata.storage = KeyStorage::Managed {
            sha256: material.digest(),
        };
        metadata.public.has_passphrase = false;
        assert!(material.validate_against(&id.id, &metadata).is_err());
        metadata.public.has_passphrase = true;
        metadata.public.public_key = crate::vault::material::parse(&test_keys::ecdsa())
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        assert!(material.validate_against(&id.id, &metadata).is_err());
        assert!(!serde_json::to_string(&sealed)
            .unwrap()
            .contains("OPENSSH PRIVATE KEY"));
    }
    #[test]
    fn duplicate_fields_unknown_secrets_and_password_records_fail_with_redacted_errors() {
        let keys = VaultKeys::generate().unwrap();
        let id = identity("host");
        let h = header(&id, &keys);
        let bad = [
            format!(
                r#"{{"schema":1,"id":"{}","id":"{}","scope":{{"kind":"local"}},"payload":{{}}}}"#,
                id.id, id.id
            ),
            format!(
                r#"{{"schema":1,"id":"{}","scope":{{"kind":"local"}},"payload":{{"schema":2,"alias":"fixture","hostname":"fixture.invalid","auth":"password","password":"PRIVATE-PASSWORD-SENTINEL"}}}}"#,
                id.id
            ),
            format!(
                r#"{{"schema":1,"id":"{}","scope":{{"kind":"local"}},"payload":{{"schema":2,"alias":"fixture","hostname":"fixture.invalid","auth":"password","auth":"key"}}}}"#,
                id.id
            ),
        ];
        for bytes in bad {
            let error = admit(&keys, &h, bytes.as_bytes()).err().unwrap();
            assert!(!error.to_string().contains("SENTINEL"));
        }
        let mut password = h;
        password.kind = "password".into();
        assert!(admit(&keys, &password, b"PRIVATE-PASSWORD-SENTINEL").is_err());
        let key_id = identity("key");
        let h = header(&key_id, &keys);
        let bytes=Zeroizing::new(json!({"schema":1,"id":key_id.id,"scope":null,"payload":{"fingerprint":"fp","private_key":test_keys::plain(),"passphrase":"PRIVATE-PASSPHRASE-SENTINEL"}}).to_string());
        assert!(!admit(&keys, &h, bytes.as_bytes())
            .err()
            .unwrap()
            .to_string()
            .contains("SENTINEL"));
    }
    #[test]
    fn oversized_records_block_admission_and_catalogue_duplicates_cannot_drop_a_collection() {
        let keys = VaultKeys::generate().unwrap();
        let id = identity("host");
        let mut payload = host();
        payload.notes = "PRIVATE-NOTE-SENTINEL".repeat(MAX_PLAINTEXT_BYTES / 8);
        assert!(encode(&id, &Data::Host(payload)).is_err());
        assert!(admit(
            &keys,
            &header(&id, &keys),
            &vec![b'x'; MAX_PLAINTEXT_BYTES + 1]
        )
        .is_err());
        let c = Collection {
            id: "f".repeat(64),
            name: "Work".into(),
        };
        let catalog = Catalog {
            collections: vec![c.clone(), c],
            group_orders: vec![],
        };
        assert!(catalog.validate().is_err());
        let catalog = Catalog {
            collections: vec![],
            group_orders: vec![GroupOrder {
                scope: HostScope::Space {
                    space_id: "f".repeat(64),
                },
                ids: vec![],
            }],
        };
        assert!(catalog.validate().is_err());
    }
}
