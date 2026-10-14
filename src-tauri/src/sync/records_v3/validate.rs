use super::*;
use crate::sync::crypto::is_chain_id;
use crate::sync::record::{Record, RecordKind};
use crate::sync::slot_rules::is_slot_id;
use std::collections::{BTreeMap, BTreeSet};

pub fn is_host_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn invalid(field: &'static str, id: &str, reason: &str) -> RecordValidationError {
    RecordValidationError::Invalid {
        field,
        id: id.into(),
        reason: reason.into(),
    }
}
fn schema(kind: &'static str, found: u32, expected: u32) -> Result<(), RecordValidationError> {
    if found == expected {
        Ok(())
    } else {
        Err(RecordValidationError::UnsupportedSchema { kind, found })
    }
}
pub fn validate_host(host: &HostRecord) -> Result<(), RecordValidationError> {
    schema("host", host.payload.schema, HOST_SCHEMA)?;
    if !is_host_id(&host.id) {
        return Err(invalid(
            "id",
            &host.id,
            "expected 16 lowercase hex characters",
        ));
    }
    if let HostScope::Space { space_id } = &host.scope {
        if !is_chain_id(space_id) {
            return Err(invalid("space_id", &host.id, "expected a valid chain id"));
        }
    }
    let p = &host.payload;
    if p.alias.is_empty()
        || p.alias.starts_with('-')
        || !p
            .alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@%-".contains(&b))
    {
        return Err(invalid("alias", &host.id, "not a valid CLI alias"));
    }
    if p.hostname.is_empty()
        || p.hostname
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid("hostname", &host.id, "missing or invalid endpoint"));
    }
    if p.port == 0 {
        return Err(invalid("port", &host.id, "must be between 1 and 65535"));
    }
    if p.user.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid(
            "user",
            &host.id,
            "contains whitespace or control characters",
        ));
    }
    // u32 is the persisted upper bound; zero is only meaningful for disabling keepalive.
    if p.connect_timeout_secs == 0 {
        return Err(invalid("connect_timeout_secs", &host.id, "must be nonzero"));
    }
    if p.auth == AuthKind::Key && p.key_id.is_none() {
        return Err(invalid(
            "key_id",
            &host.id,
            "key authentication requires a key reference",
        ));
    }
    if let Some(key_id) = &p.key_id {
        if !is_slot_id(key_id) {
            return Err(invalid(
                "key_id",
                &host.id,
                "expected an existing-format vault id",
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for id in &p.jump {
        if !is_host_id(id) {
            return Err(invalid("jump", &host.id, "expected host ids"));
        }
        if id == &host.id {
            return Err(RecordValidationError::JumpCycle(host.id.clone()));
        }
        if !seen.insert(id) {
            return Err(RecordValidationError::RepeatedJump {
                host_id: host.id.clone(),
                jump_id: id.clone(),
            });
        }
    }
    if p.jump.len() > MAX_JUMPS {
        return Err(RecordValidationError::JumpDepth(host.id.clone()));
    }
    if let Some(pin) = &p.host_key {
        if !is_slot_id(&pin.pinned_by_device_id) {
            return Err(invalid(
                "pinned_by_device_id",
                &host.id,
                "expected a device id",
            ));
        }
        let key = parse_public(&format!("{} {}", pin.algorithm, pin.public_key), &host.id)?;
        if key.algorithm().as_str() != pin.algorithm
            || key.fingerprint(ssh_key::HashAlg::Sha256).to_string() != pin.fingerprint
        {
            return Err(RecordValidationError::PublicKeyMismatch(host.id.clone()));
        }
    }
    Ok(())
}
fn parse_public(line: &str, id: &str) -> Result<ssh_key::PublicKey, RecordValidationError> {
    ssh_key::PublicKey::from_openssh(line.trim())
        .map_err(|_| invalid("public_key", id, "not a complete OpenSSH public key"))
}
pub fn validate_keyslot(id: &str, slot: &KeySlotPayload) -> Result<(), RecordValidationError> {
    schema("keyslot", slot.schema, KEYSLOT_SCHEMA)?;
    if !is_slot_id(id) {
        return Err(invalid("id", id, "expected 32 lowercase hex characters"));
    }
    if slot.name.trim().is_empty() || slot.name.chars().any(char::is_control) {
        return Err(invalid("name", id, "missing or invalid label"));
    }
    if !is_slot_id(&slot.origin_device_id) {
        return Err(invalid("origin_device_id", id, "expected a device id"));
    }
    let key = parse_public(&slot.public_key, id)?;
    if key.algorithm().as_str() != slot.key_type
        || key.fingerprint(ssh_key::HashAlg::Sha256).to_string() != slot.fingerprint
    {
        return Err(RecordValidationError::PublicKeyMismatch(id.into()));
    }
    Ok(())
}
/// Missing material can be persisted. This check must precede building a key-authenticated Hop.
pub fn connection_readiness(
    host: &HostRecord,
    available_keys: &BTreeSet<String>,
) -> Result<ConnectionReadiness, RecordValidationError> {
    validate_host(host)?;
    if host
        .payload
        .imported
        .as_ref()
        .is_some_and(|i| i.unsupported.iter().any(|s| s.requires_review))
    {
        return Ok(ConnectionReadiness::NeedsReview);
    }
    if host.payload.auth == AuthKind::Key {
        let id = host
            .payload
            .key_id
            .as_ref()
            .expect("validated key reference");
        if !available_keys.contains(id) {
            return Ok(ConnectionReadiness::NeedsKey(id.clone()));
        }
    }
    Ok(ConnectionReadiness::Ready)
}
pub fn validate_hosts(hosts: &[HostRecord]) -> Result<(), RecordValidationError> {
    let mut ids = BTreeMap::new();
    let mut aliases = BTreeSet::new();
    for host in hosts {
        validate_host(host)?;
        if ids.insert(host.id.as_str(), host).is_some() {
            return Err(RecordValidationError::DuplicateId(host.id.clone()));
        }
        if !aliases.insert((&host.scope, host.payload.alias.as_str())) {
            return Err(RecordValidationError::AliasConflict {
                alias: host.payload.alias.clone(),
                scope: host.scope.clone(),
            });
        }
    }
    for host in hosts {
        chain_ids(&ids, host)?;
    }
    Ok(())
}
/// Match HostDirectory's ProxyJump route: only the first jump's own route is inherited.
fn chain_ids<'a>(
    hosts: &BTreeMap<&'a str, &'a HostRecord>,
    target: &'a HostRecord,
) -> Result<Vec<&'a str>, RecordValidationError> {
    fn append<'a>(
        hosts: &BTreeMap<&'a str, &'a HostRecord>,
        current: &'a HostRecord,
        root: &str,
        stack: &mut BTreeSet<&'a str>,
        out: &mut Vec<&'a str>,
    ) -> Result<(), RecordValidationError> {
        if !stack.insert(&current.id) {
            return Err(RecordValidationError::JumpCycle(root.into()));
        }
        if stack.len() > MAX_JUMPS + 1 {
            return Err(RecordValidationError::JumpDepth(root.into()));
        }
        for (position, id) in current.payload.jump.iter().enumerate() {
            let jump =
                hosts
                    .get(id.as_str())
                    .ok_or_else(|| RecordValidationError::MissingJump {
                        host_id: current.id.clone(),
                        jump_id: id.clone(),
                    })?;
            if stack.contains(id.as_str()) {
                return Err(RecordValidationError::JumpCycle(root.into()));
            }
            if position == 0 {
                append(hosts, jump, root, stack, out)?;
            } else {
                add(jump, root, out)?;
            }
        }
        stack.remove(current.id.as_str());
        add(current, root, out)
    }
    fn add<'a>(
        host: &'a HostRecord,
        root: &str,
        out: &mut Vec<&'a str>,
    ) -> Result<(), RecordValidationError> {
        if out.contains(&host.id.as_str()) {
            return Err(RecordValidationError::RepeatedJump {
                host_id: root.into(),
                jump_id: host.id.clone(),
            });
        }
        out.push(&host.id);
        if out.len() > MAX_JUMPS + 1 {
            return Err(RecordValidationError::JumpDepth(root.into()));
        }
        Ok(())
    }
    let mut out = Vec::new();
    append(hosts, target, &target.id, &mut BTreeSet::new(), &mut out)?;
    Ok(out)
}
pub fn resolve_alias<'a>(
    hosts: &'a [HostRecord],
    alias: &str,
) -> Result<&'a HostRecord, RecordValidationError> {
    validate_hosts(hosts)?;
    let mut matching = hosts.iter().filter(|h| h.payload.alias == alias);
    let first = matching
        .next()
        .ok_or_else(|| RecordValidationError::HostNotFound(alias.into()))?;
    if matching.next().is_some() {
        return Err(RecordValidationError::AmbiguousAlias(alias.into()));
    }
    Ok(first)
}
fn payload_schema(
    record: &Record,
    kind: &'static str,
    expected: u32,
) -> Result<(), RecordValidationError> {
    let found = record
        .payload
        .get("schema")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| invalid("schema", &record.id, "missing or invalid schema"))?;
    schema(kind, found, expected)
}
pub fn decode_host(
    record: &Record,
    scope: HostScope,
) -> Result<TypedRecord<HostRecord>, RecordValidationError> {
    if record.kind != RecordKind::Host {
        return Err(RecordValidationError::WrongKind {
            expected: "host",
            found: record.kind.as_str().into(),
        });
    }
    if !is_host_id(&record.id) {
        return Err(invalid("id", &record.id, "expected a host id"));
    }
    if record.deleted {
        return Ok(TypedRecord::Tombstone {
            id: record.id.clone(),
        });
    }
    payload_schema(record, "host", HOST_SCHEMA)?;
    let payload = serde_json::from_value(record.payload.clone()).map_err(|e| {
        RecordValidationError::Decode {
            kind: "host",
            reason: e.to_string(),
        }
    })?;
    let host = HostRecord {
        id: record.id.clone(),
        scope,
        payload,
    };
    validate_host(&host)?;
    Ok(TypedRecord::Live(host))
}
pub fn decode_keyslot(
    record: &Record,
) -> Result<TypedRecord<KeySlotPayload>, RecordValidationError> {
    if record.kind != RecordKind::KeySlot {
        return Err(RecordValidationError::WrongKind {
            expected: "keyslot",
            found: record.kind.as_str().into(),
        });
    }
    if !is_slot_id(&record.id) {
        return Err(invalid("id", &record.id, "expected a keyslot id"));
    }
    if record.deleted {
        return Ok(TypedRecord::Tombstone {
            id: record.id.clone(),
        });
    }
    payload_schema(record, "keyslot", KEYSLOT_SCHEMA)?;
    let slot = serde_json::from_value(record.payload.clone()).map_err(|e| {
        RecordValidationError::Decode {
            kind: "keyslot",
            reason: e.to_string(),
        }
    })?;
    validate_keyslot(&record.id, &slot)?;
    Ok(TypedRecord::Live(slot))
}
/// Account identity never falls back to the metadata of a same-ID local key.
pub fn key_material_matches(
    slot: &KeySlotPayload,
    local_public_key: &str,
    local_fingerprint: &str,
) -> Result<(), RecordValidationError> {
    schema("keyslot", slot.schema, KEYSLOT_SCHEMA)?;
    let authoritative = parse_public(&slot.public_key, "account keyslot")?;
    let local = parse_public(local_public_key, "local key")?;
    let expected = authoritative
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    if authoritative.key_data() != local.key_data()
        || expected != slot.fingerprint
        || expected != local_fingerprint
        || authoritative.algorithm().as_str() != slot.key_type
    {
        return Err(RecordValidationError::PublicKeyMismatch(
            "account keyslot".into(),
        ));
    }
    Ok(())
}
/// One pure edit keeps identity and invalidates the old endpoint's pin before validation.
pub fn replace_host_payload(
    host: &HostRecord,
    mut payload: HostPayload,
) -> Result<HostRecord, RecordValidationError> {
    if host.payload.hostname != payload.hostname || host.payload.port != payload.port {
        payload.host_key = None;
    }
    let updated = HostRecord {
        payload,
        ..host.clone()
    };
    validate_host(&updated)?;
    Ok(updated)
}
