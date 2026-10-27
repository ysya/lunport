//! Typed admission between authenticated ciphertext history and the existing library repository.
//! Private material has no Debug/Serialize/frontend representation. A borrowed raw JSON body avoids
//! copying it through an untyped Value or returning parser error text containing decrypted data.
use super::{
    crypto::{self, VaultKeys},
    wire::{canonical, hex, invalid, RecordHeader, MAX_PLAINTEXT_BYTES},
};
use crate::{
    error::AppError,
    sync::{
        records_v3::{
            self, GroupPayload, GroupRecord, HostPayload, HostRecord, HostScope, KeySlotPayload,
        },
        transports::{self, HostTransport, TransportKind},
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
            "host" | "group" | "password" if hex(&self.id, 16) && self.scope.is_some() => Ok(()),
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub collections: Vec<Collection>,
    pub group_orders: Vec<GroupOrder>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<crate::sync::tunnel_rules::TunnelRule>,
    /// Host routes, at most one per host (design 2026-10-26, Connect via). The field is not written
    /// without routes, so a library without any stays readable by every release.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<HostTransport>,
    /// The search scopes the person added for Privileged Access Manager, and the grant memory, one per entitlement (design 2026-10-27).
    /// Neither field is written while empty, so a library without them stays readable by every release.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pam_scopes: Vec<crate::sync::pam_records::PamScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pam_requests: Vec<crate::sync::pam_records::GrantRequestMemory>,
}
/// The most collections, tunnel rules and group orders a Catalog holds, and the most groups its orders name together.
pub const MAX_COLLECTIONS: usize = 256;
pub const MAX_TUNNELS: usize = 256;
pub const MAX_GROUP_ORDERS: usize = 257;
pub const MAX_ORDERED_GROUPS: usize = 4096;
/// A route as the Catalog may hold it: one `HostTransport::validate` accepts, without the
/// justification a grant request left in it. That is remembered on the device that asked
/// (`GrantMemory`) and never syncs, so a Catalog that carries one is refused when built and read.
fn is_catalog_route(route: &HostTransport) -> bool {
    let TransportKind::GcpIap { pam, .. } = &route.kind;
    route.validate().is_ok() && pam.as_ref().is_none_or(|pam| pam.justification.is_none())
}
impl Catalog {
    pub fn validate(&self) -> Result<(), AppError> {
        let mut ids = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        if self.collections.len() > MAX_COLLECTIONS || self.group_orders.len() > MAX_GROUP_ORDERS {
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
        let mut tunnel_ids = BTreeSet::new();
        if self.tunnels.len() > MAX_TUNNELS
            || self
                .tunnels
                .iter()
                .any(|r| r.validate().is_err() || !tunnel_ids.insert(&r.id))
        {
            return Err(invalid());
        }
        let mut route_hosts = BTreeSet::new();
        if self.transports.len() > transports::MAX_ROUTES
            || self
                .transports
                .iter()
                .any(|r| !is_catalog_route(r) || !route_hosts.insert(&r.host_id))
        {
            return Err(invalid());
        }
        if !crate::sync::pam_records::valid_catalog(self) {
            return Err(invalid());
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
            if groups > MAX_ORDERED_GROUPS {
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
    Password(super::passwords::Material),
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
        ("password", Data::Password(material)) => material.validate(),
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
            "password" => Data::Password(serde_json::from_str(raw).map_err(|_| invalid())?),
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
        Data::Password(material) => bytes(identity, &material.outgoing()),
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
/// Whether the Catalog, encoded as capture encodes it, stays within one record's plaintext
/// (`MAX_PLAINTEXT_BYTES`). A Catalog that does not fit fails the whole capture, and with it
/// everything the library syncs, so a write that changes the Catalog checks its candidate here.
/// It is `encode`'s verdict, so it is also false for a Catalog that `validate` refuses.
pub fn catalog_fits(catalog: &Catalog) -> bool {
    let identity = Identity {
        kind: "meta".into(),
        id: "catalog".into(),
        scope: None,
    };
    encode(&identity, &Data::Catalog(catalog.clone())).is_ok()
}

#[cfg(test)]
mod tests {
    use super::super::crypto::{self, DeviceKeys};
    use super::*;
    use crate::sync::slot_rules::test_keys;
    use crate::sync::transports::PamCheck;
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
        let catalog = Catalog { pam_scopes: vec![], pam_requests: vec![],
            tunnels: vec![],
            transports: vec![],
            collections: vec![c.clone(), c],
            group_orders: vec![],
        };
        assert!(catalog.validate().is_err());
        let catalog = Catalog { pam_scopes: vec![], pam_requests: vec![],
            tunnels: vec![],
            transports: vec![],
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
    #[test]
    fn tunnel_catalog_is_backward_compatible_and_rejects_duplicates_invalid_rules_and_overflow() {
        let legacy = r#"{"collections":[],"group_orders":[]}"#;
        let mut catalog: Catalog = serde_json::from_str(legacy).unwrap();
        assert_eq!(serde_json::to_string(&catalog).unwrap(), legacy);
        let rule: crate::sync::tunnel_rules::TunnelRule = serde_json::from_value(json!({"id":"a".repeat(16),"name":"Database","host_id":"b".repeat(16),"forward":{"kind":"local","bind_address":"127.0.0.1","port":15432,"target_host":"db.internal","target_port":5432}})).unwrap();
        catalog.tunnels.push(rule.clone());
        let keys = VaultKeys::generate().unwrap();
        let id = identity("meta");
        let bytes = encode(&id, &Data::Catalog(catalog.clone())).unwrap();
        let Data::Catalog(restored) = admit(&keys, &header(&id, &keys), &bytes).unwrap().data
        else {
            panic!()
        };
        assert_eq!(restored, catalog);
        catalog.tunnels.push(rule.clone());
        assert!(catalog.validate().is_err());
        catalog.tunnels = (0..257)
            .map(|i| {
                let mut r = rule.clone();
                r.id = format!("{i:016x}");
                r
            })
            .collect();
        assert!(catalog.validate().is_err());
        catalog.tunnels = vec![rule];
        catalog.tunnels[0].forward.bind_address = "public.invalid".into();
        assert!(catalog.validate().is_err());
    }
    const HOST: &str = "0000000000000001";
    fn empty_catalog() -> Catalog {
        Catalog::default()
    }
    fn route(host_id: &str) -> HostTransport {
        HostTransport {
            host_id: host_id.into(),
            kind: TransportKind::GcpIap {
                project: "synthetic-project".into(),
                zone: "asia-east1-b".into(),
                instance: "jumpbox".into(),
                interface: "nic0".into(),
                account: Some("person@example.com".into()),
                os_login: true,
                pam: None,
            },
        }
    }
    fn route_with_pam(host_id: &str) -> HostTransport {
        let mut route = route(host_id);
        let TransportKind::GcpIap { pam, .. } = &mut route.kind;
        *pam = Some(PamCheck {
            entitlements: vec!["prod-operate".into()],
            location: "global".into(),
            duration_secs: 30 * 60,
            justification: None,
        });
        route
    }
    /// The largest route: every name at its maximum length, and the most entitlements.
    fn long_route(n: usize) -> HostTransport {
        HostTransport {
            host_id: format!("{n:016x}"),
            kind: TransportKind::GcpIap {
                project: format!("p{}", "x".repeat(29)),
                zone: format!("z{}", "x".repeat(62)),
                instance: format!("i{}", "x".repeat(62)),
                interface: "nic7".into(),
                account: Some(format!("{}@{}.example.com", "a".repeat(64), "b".repeat(63))),
                os_login: true,
                pam: Some(PamCheck {
                    entitlements: (0..8).map(|e| format!("{}{e}", "e".repeat(62))).collect(),
                    location: format!("l{}", "x".repeat(62)),
                    duration_secs: 480 * 60,
                    justification: None,
                }),
            },
        }
    }
    /// A tunnel rule with its name at the maximum length.
    fn long_tunnel(n: usize) -> crate::sync::tunnel_rules::TunnelRule {
        serde_json::from_value(json!({
            "id": format!("{n:016x}"),
            "name": "t".repeat(128),
            "host_id": HOST,
            "forward": {
                "kind": "local",
                "bind_address": "127.0.0.1",
                "port": 15432,
                "target_host": "db.internal",
                "target_port": 5432
            }
        }))
        .unwrap()
    }
    #[test]
    fn a_catalog_without_routes_serializes_as_before() {
        let catalog = Catalog { pam_scopes: vec![], pam_requests: vec![],
            collections: vec![],
            group_orders: vec![],
            tunnels: vec![],
            transports: vec![],
        };
        assert_eq!(
            serde_json::to_string(&catalog).unwrap(),
            r#"{"collections":[],"group_orders":[]}"#
        );
    }
    #[test]
    fn catalog_routes_are_capped_unique_validated_and_carry_no_justification() {
        let mut catalog = empty_catalog();
        catalog.transports = (0..256).map(|n| route(&format!("{n:016x}"))).collect();
        assert!(catalog.validate().is_ok(), "256 routes");
        catalog.transports = (0..257).map(|n| route(&format!("{n:016x}"))).collect();
        assert!(catalog.validate().is_err(), "257 routes");
        catalog.transports = vec![route(HOST)];
        assert!(catalog.validate().is_ok(), "one route for a host");
        catalog.transports = vec![route(HOST), route(HOST)];
        assert!(catalog.validate().is_err(), "two routes for one host");
        let mut unusable = route(HOST);
        let TransportKind::GcpIap { zone, .. } = &mut unusable.kind;
        *zone = "Not A Zone".into();
        catalog.transports = vec![unusable];
        assert!(
            catalog.validate().is_err(),
            "a route HostTransport::validate refuses"
        );
        catalog.transports = vec![route_with_pam(HOST)];
        assert!(catalog.validate().is_ok(), "a grant requirement alone");
        let mut remembered = route_with_pam(HOST);
        if let TransportKind::GcpIap { pam: Some(pam), .. } = &mut remembered.kind {
            pam.justification = Some("x".into())
        }
        catalog.transports = vec![remembered];
        assert!(
            catalog.validate().is_err(),
            "a justification inside the Catalog"
        );
    }
    #[test]
    fn catalog_routes_cross_the_wire_and_a_justification_is_refused_on_reading() {
        let keys = VaultKeys::generate().unwrap();
        let id = identity("meta");
        let mut catalog = empty_catalog();
        catalog.transports = vec![route(HOST), route_with_pam("0000000000000002")];
        let bytes = encode(&id, &Data::Catalog(catalog.clone())).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            text.contains(
                r#""transports":[{"host_id":"0000000000000001","kind":{"type":"gcp_iap","#
            ),
            "{text}"
        );
        let Data::Catalog(restored) = admit(&keys, &header(&id, &keys), &bytes).unwrap().data
        else {
            panic!("expected a catalog")
        };
        assert_eq!(restored, catalog);
        let tampered = text.replace(r#""justification":null"#, r#""justification":"x""#);
        assert_ne!(tampered, text);
        assert!(admit(&keys, &header(&id, &keys), tampered.as_bytes()).is_err());
    }
    #[test]
    fn catalog_fits_follows_the_plaintext_limit() {
        let mut catalog = empty_catalog();
        assert!(catalog_fits(&catalog));
        catalog.tunnels = (0..256).map(long_tunnel).collect(); // names at their maximum length
        catalog.transports = (0..256).map(long_route).collect(); // 8 entitlements of 63 characters
        assert!(
            catalog.validate().is_ok(),
            "every entry is valid; only the size is wrong"
        );
        assert!(!catalog_fits(&catalog));
        // The edge is the plaintext limit itself, not a count: the most routes that fit leave no
        // room for one more.
        let with_routes = |n| Catalog {
            transports: (0..n).map(long_route).collect(),
            ..Catalog::default()
        };
        let size = |n| {
            encode(&identity("meta"), &Data::Catalog(with_routes(n)))
                .unwrap()
                .len()
        };
        let step = size(2) - size(1);
        let most = 1 + (MAX_PLAINTEXT_BYTES - size(1)) / step;
        assert!(most < transports::MAX_ROUTES, "{most} routes");
        assert!(catalog_fits(&with_routes(most)));
        assert!(!catalog_fits(&with_routes(most + 1)));
    }
}
