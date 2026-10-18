//! Pure v3 account/space transport. No network, filesystem, credential or vault access.
//! Unsupported records remain encrypted; gate outcomes are observed evidence for the runtime to
//! persist before permitting shared writes. A gate never rewrites the returned old section.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AppError;
use crate::sync::crypto::{self, ChainKeys, Sealed};
use crate::sync::merge::{Outgoing, Pushed};
use crate::sync::record::{
    merge, record_key, DevicePayload, Envelope, LocalRecord, MergeOutcome, Record, RecordKind,
    SpacePayload, ACCOUNT_META_ID,
};
use crate::sync::records_v3::{
    decode_host, decode_keyslot, validate_migration_gate, HostScope, MigrationPhase, SpaceStateV3,
    ACCOUNT_SCHEMA, MIN_ACCOUNT_SCHEMA,
};
use crate::sync::relay::{PullResponse, PushItem};
use crate::sync::slot_rules::is_slot_id;
use crate::sync::state_v2::{sealed_key, AccountState, SealedRecord};

pub use crate::sync::records_v3::MigrationGate;

// The relay stores JavaScript safe integers; invalid transport metadata must never poison cursors.
const MAX_RELAY_SEQ: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaPayloadV3 {
    pub schema_version: u32,
    pub created_by_app_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration: Option<MigrationGate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountGate {
    Compatible,
    NeedsMigration { schema: u32 },
    NeedsUpdate { schema: u32 },
    MigrationPending(MigrationGate),
    InvalidMigration,
    InvalidPull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    Unreadable,
    Unsupported,
    InvalidShape,
    OpaqueConflict,
}

/// Diagnostics use only wire identities and fixed codes, never decrypted payload/error text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeDiagnostic {
    pub kind: String,
    pub id_hash: String,
    pub code: DiagnosticCode,
}

#[derive(Clone, Debug)]
pub struct TypedMergeOutcome<S> {
    pub section: S,
    pub gate: AccountGate,
    pub observed_schema: Option<u32>,
    pub skipped: u32,
    pub conflicts: Vec<String>,
    pub diagnostics: Vec<MergeDiagnostic>,
    pub baseline_established: bool,
}

#[derive(Clone, Debug)]
pub struct TypedOutgoing {
    pub outgoing: Outgoing,
    expected: ExpectedRevision,
}
#[derive(Clone, Debug)]
enum ExpectedRevision {
    Public(Record),
    Sealed(Envelope),
}

/// Successful decrypted JSON is zeroized on every exit, including unsupported schema/identity.
/// Public records are cloned only after typed admission; secret records never enter a section.
struct SensitiveJson(Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        clear_json(&mut self.0);
    }
}
struct OpenedRecord(Record);
impl Drop for OpenedRecord {
    fn drop(&mut self) {
        clear_json(&mut self.0.payload);
        self.0.id.zeroize();
        self.0.device_id.zeroize();
    }
}
fn clear_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(clear_json),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                clear_json(&mut value);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}
fn failure() -> AppError {
    AppError::Other("typed sync record is invalid or unavailable".into())
}
fn open_record(keys: &ChainKeys, envelope: &Envelope) -> Result<OpenedRecord, DiagnosticCode> {
    let kind = RecordKind::parse(&envelope.kind).ok_or(DiagnosticCode::Unsupported)?;
    let sealed = Sealed {
        id_hash: envelope.id_hash.clone(),
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let bytes = Zeroizing::new(
        crypto::open(keys, &envelope.kind, &envelope.id_hash, &sealed)
            .map_err(|_| DiagnosticCode::Unreadable)?,
    );
    // Construct the protection before checking required/unknown fields. A complete JSON payload
    // is cleared even when later header validation fails, without a second secret payload clone.
    let mut value = SensitiveJson(
        serde_json::from_slice::<Value>(&bytes).map_err(|_| DiagnosticCode::Unreadable)?,
    );
    let fields = value.0.as_object().ok_or(DiagnosticCode::InvalidShape)?;
    if fields.keys().any(|key| {
        ![
            "kind",
            "id",
            "version",
            "updated_at_ms",
            "device_id",
            "deleted",
            "payload",
        ]
        .contains(&key.as_str())
    }) {
        return Err(DiagnosticCode::Unsupported);
    }
    let wire_kind = fields
        .get("kind")
        .and_then(Value::as_str)
        .and_then(RecordKind::parse)
        .ok_or(DiagnosticCode::InvalidShape)?;
    let id = fields
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DiagnosticCode::InvalidShape)?
        .to_string();
    let version = fields
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(DiagnosticCode::InvalidShape)?;
    let updated_at_ms = fields
        .get("updated_at_ms")
        .and_then(Value::as_u64)
        .ok_or(DiagnosticCode::InvalidShape)?;
    let device_id = fields
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or(DiagnosticCode::InvalidShape)?
        .to_string();
    let deleted = fields
        .get("deleted")
        .and_then(Value::as_bool)
        .ok_or(DiagnosticCode::InvalidShape)?;
    let payload = std::mem::take(
        value
            .0
            .get_mut("payload")
            .ok_or(DiagnosticCode::InvalidShape)?,
    );
    let record = OpenedRecord(Record {
        kind: wire_kind,
        id,
        version,
        updated_at_ms,
        device_id,
        deleted,
        payload,
    });
    if record.0.kind != kind
        || record.0.deleted != envelope.deleted
        || crypto::id_hash(keys, kind.as_str(), &record.0.id) != envelope.id_hash
    {
        return Err(DiagnosticCode::InvalidShape);
    }
    Ok(record)
}
/// Wire-compatible encoding, with the serialization buffer cleared on success and failure.
pub fn encode_record(
    keys: &ChainKeys,
    record: &Record,
    base_seq: u64,
) -> Result<PushItem, AppError> {
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, record).map_err(|_| failure())?;
    let sealed = crypto::seal(keys, record.kind.as_str(), &record.id, &bytes)?;
    Ok(PushItem {
        id_hash: sealed.id_hash,
        kind: record.kind.as_str().into(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        deleted: record.deleted,
        base_seq,
    })
}
/// Ownership clears the caller's secret JSON value after encryption; no plaintext state is returned.
pub fn seal_secret_record(
    keys: &ChainKeys,
    record: Record,
    base_seq: u64,
) -> Result<SealedRecord, AppError> {
    let record = OpenedRecord(record);
    if !record.0.kind.is_secret() || !valid_secret(&record.0) {
        return Err(failure());
    }
    let item = encode_record(keys, &record.0, base_seq)?;
    Ok(SealedRecord {
        envelope: Envelope {
            id_hash: item.id_hash,
            kind: item.kind,
            seq: base_seq,
            nonce: item.nonce,
            ciphertext: item.ciphertext,
            deleted: item.deleted,
        },
        dirty: true,
        public_identity: None,
    })
}

fn opened_secret(
    section: &AccountState,
    keys: &ChainKeys,
    kind: RecordKind,
    id: &str,
) -> Result<Option<OpenedRecord>, AppError> {
    if section.chain_id != keys.chain_id {
        return Err(failure());
    }
    let key = sealed_key(kind.as_str(), &crypto::id_hash(keys, kind.as_str(), id));
    let Some(sealed) = section.sealed.get(&key) else {
        return Ok(None);
    };
    let opened = open_record(keys, &sealed.envelope).map_err(|_| failure())?;
    if opened.0.kind != kind || opened.0.id != id || !valid_secret(&opened.0) {
        return Err(failure());
    }
    if opened.0.deleted {
        return Ok(None);
    }
    Ok(Some(opened))
}
fn live_metadata(
    section: &AccountState,
    keys: &ChainKeys,
    kind: RecordKind,
    id: &str,
) -> Result<bool, AppError> {
    if section.chain_id != keys.chain_id {
        return Err(failure());
    }
    let Some(row) = section.records.get(&record_key(kind, id)) else {
        return Ok(false);
    };
    if row.record.deleted {
        return Ok(false);
    }
    if !valid_public(&row.record, true, keys)
        || section.sealed.contains_key(&sealed_key(
            kind.as_str(),
            &crypto::id_hash(keys, kind.as_str(), id),
        ))
    {
        return Err(failure());
    }
    Ok(true)
}
/// Transport credentials require a live, recognized public space. The caller still checks the
/// fresh account gate before any space request; only the intended live ChainKeys leaves this scope.
pub fn space_keys(
    section: &AccountState,
    keys: &ChainKeys,
    id: &str,
) -> Result<Option<ChainKeys>, AppError> {
    if !live_metadata(section, keys, RecordKind::Space, id)? {
        return Ok(None);
    }
    let Some(opened) = opened_secret(section, keys, RecordKind::SpaceKey, id)? else {
        return Ok(None);
    };
    let token = opened
        .0
        .payload
        .get("auth_token")
        .and_then(Value::as_str)
        .ok_or_else(failure)?;
    let encoded = opened
        .0
        .payload
        .get("enc_key")
        .and_then(Value::as_str)
        .ok_or_else(failure)?;
    ChainKeys::from_parts(id, token, encoded).map(Some)
}
/// The returned private copy is zeroizing. Activation must additionally match the authoritative
/// public key/fingerprint, using the existing key material validator before touching a vault.
pub fn key_secret(
    section: &AccountState,
    keys: &ChainKeys,
    id: &str,
) -> Result<Option<Zeroizing<String>>, AppError> {
    if !live_metadata(section, keys, RecordKind::KeySlot, id)? {
        return Ok(None);
    }
    let Some(opened) = opened_secret(section, keys, RecordKind::Key, id)? else {
        return Ok(None);
    };
    let text = opened
        .0
        .payload
        .get("private_key")
        .and_then(Value::as_str)
        .ok_or_else(failure)?;
    Ok(Some(Zeroizing::new(text.to_string())))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRevision {
    pub version: u64,
    pub updated_at_ms: u64,
    pub device_id: String,
    pub deleted: bool,
}
/// Revision headers are public; decrypted secret payloads never leave this helper.
pub fn secret_revision(
    section: &AccountState,
    keys: &ChainKeys,
    kind: RecordKind,
    id: &str,
) -> Result<Option<SecretRevision>, AppError> {
    if section.chain_id != keys.chain_id || !matches!(kind, RecordKind::Key | RecordKind::SpaceKey)
    {
        return Err(failure());
    }
    let key = sealed_key(kind.as_str(), &crypto::id_hash(keys, kind.as_str(), id));
    let Some(sealed) = section.sealed.get(&key) else {
        return Ok(None);
    };
    let opened = open_record(keys, &sealed.envelope).map_err(|_| failure())?;
    if opened.0.kind != kind || opened.0.id != id || !valid_secret(&opened.0) {
        return Err(failure());
    }
    Ok(Some(SecretRevision {
        version: opened.0.version,
        updated_at_ms: opened.0.updated_at_ms,
        device_id: opened.0.device_id.clone(),
        deleted: opened.0.deleted,
    }))
}

/// A migrated Own1 slot has no account-wide public identity. Only explicit publishing may
/// replace this recognized opaque revision; arbitrary future/invalid slots still fail closed.
pub(crate) fn legacy_own_slot_revision(
    section: &AccountState,
    keys: &ChainKeys,
    id: &str,
) -> Result<Option<SecretRevision>, AppError> {
    if section.chain_id != keys.chain_id || !is_slot_id(id) {
        return Err(failure());
    }
    let key = sealed_key("keyslot", &crypto::id_hash(keys, "keyslot", id));
    let Some(sealed) = section.sealed.get(&key) else {
        return Ok(None);
    };
    let opened = open_record(keys, &sealed.envelope).map_err(|_| failure())?;
    if opened.0.kind != RecordKind::KeySlot
        || opened.0.id != id
        || opened.0.deleted
        || !legacy_own_payload(&opened.0.payload)
    {
        return Err(failure());
    }
    Ok(Some(SecretRevision {
        version: opened.0.version,
        updated_at_ms: opened.0.updated_at_ms,
        device_id: opened.0.device_id.clone(),
        deleted: false,
    }))
}
fn legacy_own_payload(payload: &Value) -> bool {
    let Some(fields) = payload.as_object() else {
        return false;
    };
    !fields.keys().any(|key| {
        ![
            "schema",
            "name",
            "mode",
            "origin_device_id",
            "created_at_ms",
            "public_key",
            "fingerprint",
            "key_type",
            "has_passphrase",
        ]
        .contains(&key.as_str())
    }) && fields.get("schema").and_then(Value::as_u64) == Some(1)
        && fields.get("mode").and_then(Value::as_str) == Some("own")
        && fields
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(crate::sync::slot_rules::valid_slot_name)
        && fields
            .get("origin_device_id")
            .and_then(Value::as_str)
            .is_some_and(is_slot_id)
        && fields
            .get("created_at_ms")
            .and_then(Value::as_u64)
            .is_some()
        && ["public_key", "fingerprint", "key_type", "has_passphrase"]
            .iter()
            .all(|key| fields.get(*key).is_none_or(Value::is_null))
}
/// Authenticate fixed public identity/ordering even when an unsupported outer header cannot be
/// admitted as a Record. The protected JSON is cleared; only bounded public headers leave it.
fn verified_public_identity(
    keys: &ChainKeys,
    envelope: &Envelope,
    account: bool,
) -> Option<crate::sync::state_v2::VerifiedPublicIdentity> {
    if !matches!(
        (account, envelope.kind.as_str()),
        (true, "keyslot" | "meta") | (false, "host" | "group")
    ) {
        return None;
    }
    let sealed = Sealed {
        id_hash: envelope.id_hash.clone(),
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let bytes =
        Zeroizing::new(crypto::open(keys, &envelope.kind, &envelope.id_hash, &sealed).ok()?);
    let value = SensitiveJson(serde_json::from_slice::<Value>(&bytes).ok()?);
    let fields = value.0.as_object()?;
    let id = fields.get("id")?.as_str()?;
    if fields.get("kind")?.as_str()? != envelope.kind
        || crypto::id_hash(keys, &envelope.kind, id) != envelope.id_hash
    {
        return None;
    }
    // Validate borrowed identities before copying even a header string out of protected JSON.
    let actor = fields.get("device_id")?.as_str()?;
    let version = fields.get("version")?.as_u64()?;
    let deleted = fields.get("deleted")?.as_bool()?;
    let known_id = if account && envelope.kind == "meta" {
        id == crate::sync::group_order::RECORD_ID || crate::sync::tunnel_rules::is_id(id)
    } else if account {
        is_slot_id(id)
    } else {
        crate::sync::records_v3::is_host_id(id)
    };
    if !known_id || !is_slot_id(actor) || version == 0 || deleted != envelope.deleted {
        return None;
    }
    let hint = crate::sync::state_v2::VerifiedPublicIdentity {
        id: id.into(),
        version,
        updated_at_ms: fields.get("updated_at_ms")?.as_u64()?,
        device_id: actor.into(),
        deleted,
    };
    if fields.len() == 7 && !hint.deleted {
        if let Some(payload) = fields.get("payload") {
            let legacy_alias = envelope.kind == "host"
                && payload.as_object().is_some_and(|p| {
                    p.len() == 2
                        && p.get("schema").and_then(Value::as_u64) == Some(1)
                        && p.get("text").and_then(Value::as_str).is_some()
                });
            if legacy_alias || envelope.kind == "keyslot" && legacy_own_payload(payload) {
                return None;
            }
        }
    }
    Some(hint)
}

/// Old alias/text hosts intentionally retained by migration are source evidence, not active hosts.
/// This recognizes only the old shape; callers must still reject an opaque shadow of a typed id.
pub(crate) fn is_legacy_alias_host(keys: &ChainKeys, envelope: &Envelope) -> bool {
    let Ok(opened) = open_record(keys, envelope) else {
        return false;
    };
    let Some(fields) = opened.0.payload.as_object() else {
        return false;
    };
    opened.0.kind == RecordKind::Host
        && !opened.0.deleted
        && fields.len() == 2
        && fields.get("schema").and_then(Value::as_u64) == Some(1)
        && fields.get("text").and_then(Value::as_str).is_some()
}
/// A future account may extend its outer header. Authenticate its fixed identity and format
/// hint without admitting its payload or weakening the supported-record shape validation.
fn authenticated_future_schema(keys: &ChainKeys, envelope: &Envelope) -> Option<u32> {
    let sealed = Sealed {
        id_hash: envelope.id_hash.clone(),
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let bytes = Zeroizing::new(crypto::open(keys, "meta", &envelope.id_hash, &sealed).ok()?);
    let value = SensitiveJson(serde_json::from_slice::<Value>(&bytes).ok()?);
    let fields = value.0.as_object()?;
    if fields.get("kind")?.as_str()? != "meta"
        || fields.get("id")?.as_str()? != ACCOUNT_META_ID
        || fields.get("deleted")?.as_bool()? != envelope.deleted
        || crypto::id_hash(keys, "meta", ACCOUNT_META_ID) != envelope.id_hash
    {
        return None;
    }
    let schema = fields.get("payload")?.get("schema_version")?.as_u64()?;
    (schema > u64::from(ACCOUNT_SCHEMA)).then(|| u32::try_from(schema).unwrap_or(u32::MAX))
}

fn result<S: Clone>(
    section: &S,
    gate: AccountGate,
    schema: Option<u32>,
    baseline: bool,
) -> TypedMergeOutcome<S> {
    TypedMergeOutcome {
        section: section.clone(),
        gate,
        observed_schema: schema,
        skipped: 0,
        conflicts: Vec::new(),
        diagnostics: Vec::new(),
        baseline_established: baseline,
    }
}
fn meta_schema(record: &Record) -> Option<u32> {
    record
        .payload
        .get("schema_version")?
        .as_u64()
        .map(|version| u32::try_from(version).unwrap_or(u32::MAX))
}
fn valid_meta(record: &Record) -> Result<MetaPayloadV3, AccountGate> {
    if record.deleted {
        return Err(AccountGate::InvalidMigration);
    }
    let meta: MetaPayloadV3 = serde_json::from_value(record.payload.clone())
        .map_err(|_| AccountGate::InvalidMigration)?;
    if !(MIN_ACCOUNT_SCHEMA..=ACCOUNT_SCHEMA).contains(&meta.schema_version) {
        return Err(AccountGate::NeedsMigration {
            schema: meta.schema_version,
        });
    }
    if let Some(marker) = &meta.migration {
        validate_migration_gate(marker).map_err(|_| AccountGate::InvalidMigration)?;
    }
    Ok(meta)
}
/// Max authenticated future format is conservative; supported metadata uses the same LWW as rows.
pub fn account_gate(
    section: &AccountState,
    keys: &ChainKeys,
    pulled: &PullResponse,
) -> (AccountGate, Option<u32>) {
    if section.chain_id != keys.chain_id {
        return (AccountGate::InvalidPull, None);
    }
    let mut schema = section.remote_schema_version;
    let mut winner = section
        .records
        .get(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
        .cloned();
    if let Some(local) = &winner {
        schema = schema.into_iter().chain(meta_schema(&local.record)).max();
    }
    let meta_hash = crypto::id_hash(keys, "meta", ACCOUNT_META_ID);
    let mut unreadable_meta = false;
    for envelope in pulled
        .records
        .iter()
        .filter(|row| row.kind == "meta" && row.id_hash == meta_hash)
    {
        match open_record(keys, envelope) {
            Ok(remote) => {
                schema = schema.into_iter().chain(meta_schema(&remote.0)).max();
                if merge(winner.as_ref(), &remote.0) != MergeOutcome::KeepLocal {
                    winner = Some(LocalRecord {
                        record: remote.0.clone(),
                        seq: envelope.seq,
                        dirty: false,
                    });
                }
            }
            Err(_) => {
                schema = schema
                    .into_iter()
                    .chain(authenticated_future_schema(keys, envelope))
                    .max();
                unreadable_meta = true;
            }
        }
    }
    if let Some(schema) = schema.filter(|schema| *schema > ACCOUNT_SCHEMA) {
        return (AccountGate::NeedsUpdate { schema }, Some(schema));
    }
    if unreadable_meta {
        return (AccountGate::InvalidMigration, schema);
    }
    let Some(winner) = winner else {
        return (
            AccountGate::NeedsMigration {
                schema: schema.unwrap_or(0),
            },
            schema,
        );
    };
    let Some(winning_schema) = meta_schema(&winner.record) else {
        return (AccountGate::InvalidMigration, schema);
    };
    if winning_schema < MIN_ACCOUNT_SCHEMA {
        return (
            AccountGate::NeedsMigration {
                schema: winning_schema,
            },
            schema,
        );
    }
    match valid_meta(&winner.record) {
        Ok(meta) => match meta.migration {
            Some(marker) if marker.phase != MigrationPhase::Active => {
                (AccountGate::MigrationPending(marker), schema)
            }
            _ => (AccountGate::Compatible, schema),
        },
        Err(gate) => (gate, schema),
    }
}
pub(crate) fn valid_pull(
    cursor: u64,
    baseline: bool,
    known_seq: u64,
    pulled: &PullResponse,
    since: u64,
) -> bool {
    if pulled.latest_seq > MAX_RELAY_SEQ
        || (!baseline && since != 0)
        || (baseline && since != 0 && since != cursor)
        || pulled.latest_seq < cursor
        || pulled.latest_seq < known_seq
        || pulled.latest_seq < since
    {
        return false;
    }
    let mut sequences = BTreeSet::new();
    let mut identities = BTreeSet::new();
    pulled.records.iter().all(|row| {
        row.seq > since
            && row.seq <= pulled.latest_seq
            && sequences.insert(row.seq)
            && identities.insert((&row.kind, &row.id_hash))
    })
}
fn max_seq(
    records: &BTreeMap<String, LocalRecord>,
    sealed: &BTreeMap<String, SealedRecord>,
) -> u64 {
    records
        .values()
        .map(|row| row.seq)
        .chain(sealed.values().map(|row| row.envelope.seq))
        .max()
        .unwrap_or(0)
}
fn valid_secret(record: &Record) -> bool {
    let id_valid = match record.kind {
        RecordKind::Key => is_slot_id(&record.id),
        RecordKind::SpaceKey => crypto::is_chain_id(&record.id),
        _ => false,
    };
    if !id_valid {
        return false;
    }
    if record.deleted {
        return record.payload.is_null()
            || record.payload.get("schema").and_then(Value::as_u64) == Some(1);
    }
    if record.payload.get("schema").and_then(Value::as_u64) != Some(1) {
        return false;
    }
    match record.kind {
        RecordKind::Key => record
            .payload
            .get("private_key")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty() && text.len() <= 16 * 1024),
        RecordKind::SpaceKey => {
            let token = record.payload.get("auth_token").and_then(Value::as_str);
            let encoded = record.payload.get("enc_key").and_then(Value::as_str);
            token.is_some_and(crypto::is_chain_id)
                && encoded
                    .and_then(|text| B64.decode(text).ok())
                    .map(Zeroizing::new)
                    .is_some_and(|bytes| bytes.len() == 32)
        }
        _ => false,
    }
}
fn valid_public(record: &Record, account: bool, keys: &ChainKeys) -> bool {
    if account {
        match record.kind {
            RecordKind::Meta if record.id == ACCOUNT_META_ID => valid_meta(record).is_ok(),
            RecordKind::Meta if record.id == crate::sync::group_order::RECORD_ID => {
                crate::sync::group_order::decode(record).is_some()
            }
            RecordKind::Meta if crate::sync::tunnel_rules::is_id(&record.id) => crate::sync::tunnel_rules::valid(record),
            RecordKind::KeySlot => {
                decode_keyslot(record).is_ok()
                    && (!record.deleted
                        || record.payload.is_null()
                        || record.payload.get("schema").and_then(Value::as_u64) == Some(2))
            }
            RecordKind::Space => {
                crypto::is_chain_id(&record.id)
                    && (record.deleted && record.payload.is_null()
                        || serde_json::from_value::<SpacePayload>(record.payload.clone())
                            .is_ok_and(|payload| {
                                payload.schema == 1
                                    && !payload.name.trim().is_empty()
                                    && payload
                                        .previous_id
                                        .as_deref()
                                        .is_none_or(crypto::is_chain_id)
                            }))
            }
            RecordKind::Device => {
                is_slot_id(&record.id)
                    && (record.deleted && record.payload.is_null()
                        || serde_json::from_value::<DevicePayload>(record.payload.clone())
                            .is_ok_and(|payload| {
                                payload.schema == 1
                                    && payload.spaces.iter().all(|id| crypto::is_chain_id(id))
                            }))
            }
            _ => false,
        }
    } else if record.kind == RecordKind::Group {
        crate::sync::records_v3::decode_group(
            record,
            HostScope::Space {
                space_id: keys.chain_id.clone(),
            },
        )
        .is_ok()
            && (!record.deleted || record.payload.is_null())
    } else {
        decode_host(
            record,
            HostScope::Space {
                space_id: keys.chain_id.clone(),
            },
        )
        .is_ok()
            && (!record.deleted
                || record.payload.is_null()
                || record.payload.get("schema").and_then(Value::as_u64) == Some(2))
    }
}
fn header_view(record: &Record, seq: u64, dirty: bool) -> LocalRecord {
    LocalRecord {
        record: Record {
            kind: record.kind,
            id: record.id.clone(),
            version: record.version,
            updated_at_ms: record.updated_at_ms,
            device_id: record.device_id.clone(),
            deleted: record.deleted,
            payload: Value::Null,
        },
        seq,
        dirty,
    }
}
fn retain_opaque(
    sealed: &mut BTreeMap<String, SealedRecord>,
    keys: &ChainKeys,
    envelope: &Envelope,
    account: bool,
) -> bool {
    let key = sealed_key(&envelope.kind, &envelope.id_hash);
    if let Some(local) = sealed.get_mut(&key) {
        if local.dirty && !same_ciphertext(&local.envelope, envelope) {
            return false;
        }
        if let (Ok(old), Ok(remote)) = (
            open_record(keys, &local.envelope),
            open_record(keys, envelope),
        ) {
            if merge(
                Some(&header_view(&old.0, local.envelope.seq, local.dirty)),
                &remote.0,
            ) == MergeOutcome::KeepLocal
            {
                local.envelope.seq = local.envelope.seq.max(envelope.seq);
                local.public_identity = verified_public_identity(keys, &local.envelope, account);
                return true;
            }
        }
        if local.envelope.seq > envelope.seq {
            local.public_identity = verified_public_identity(keys, &local.envelope, account);
            return true;
        }
    }
    sealed.insert(
        key,
        SealedRecord {
            envelope: envelope.clone(),
            dirty: false,
            public_identity: verified_public_identity(keys, envelope, account),
        },
    );
    true
}
fn merge_rows(
    records: &mut BTreeMap<String, LocalRecord>,
    sealed: &mut BTreeMap<String, SealedRecord>,
    keys: &ChainKeys,
    pulled: &PullResponse,
    account: bool,
    conflicts: &mut Vec<String>,
    diagnostics: &mut Vec<MergeDiagnostic>,
) -> bool {
    for envelope in &pulled.records {
        let opened = open_record(keys, envelope);
        let valid = opened.as_ref().is_ok_and(|row| {
            if row.0.kind.is_secret() {
                account && valid_secret(&row.0)
            } else {
                valid_public(&row.0, account, keys)
            }
        });
        if !valid {
            let code = opened
                .as_ref()
                .err()
                .copied()
                .unwrap_or(DiagnosticCode::Unsupported);
            diagnostics.push(MergeDiagnostic {
                kind: envelope.kind.clone(),
                id_hash: envelope.id_hash.clone(),
                code,
            });
            if !retain_opaque(sealed, keys, envelope, account) {
                return false;
            }
            continue;
        }
        let remote = opened.as_ref().expect("valid opened record");
        let wire_key = sealed_key(&envelope.kind, &envelope.id_hash);
        if remote.0.kind.is_secret() {
            let local = sealed.get(&wire_key).and_then(|row| {
                open_record(keys, &row.envelope)
                    .ok()
                    .map(|record| (record, row.dirty, row.envelope.seq))
            });
            // LWW needs headers only: never clone a decrypted secret JSON payload.
            let local_view = local
                .as_ref()
                .map(|(record, dirty, seq)| header_view(&record.0, *seq, *dirty));
            let outcome = merge(local_view.as_ref(), &remote.0);
            if outcome == MergeOutcome::KeepLocal {
                if let Some(local) = sealed.get_mut(&wire_key) {
                    local.envelope.seq = local.envelope.seq.max(envelope.seq);
                }
            } else {
                if outcome == MergeOutcome::RemoteWinsOverDirtyLocal {
                    conflicts.push(wire_key.clone());
                }
                sealed.insert(
                    wire_key,
                    SealedRecord {
                        envelope: envelope.clone(),
                        dirty: false,
                        public_identity: None,
                    },
                );
            }
        } else {
            if let Some(opaque) = sealed.get(&wire_key) {
                if let Ok(old) = open_record(keys, &opaque.envelope) {
                    if merge(
                        Some(&header_view(&old.0, opaque.envelope.seq, opaque.dirty)),
                        &remote.0,
                    ) == MergeOutcome::KeepLocal
                    {
                        // One canonical sealed slot cannot store both revisions. Retain all old
                        // state and leave the cursor for a future decoder instead of discarding it.
                        return false;
                    }
                } else if opaque.envelope.seq > envelope.seq {
                    return false;
                }
            }
            let key = record_key(remote.0.kind, &remote.0.id);
            let outcome = merge(records.get(&key), &remote.0);
            if outcome == MergeOutcome::KeepLocal {
                if let Some(local) = records.get_mut(&key) {
                    local.seq = local.seq.max(envelope.seq);
                }
            } else {
                if outcome == MergeOutcome::RemoteWinsOverDirtyLocal {
                    conflicts.push(key.clone());
                }
                records.insert(
                    key,
                    LocalRecord {
                        record: remote.0.clone(),
                        seq: envelope.seq,
                        dirty: false,
                    },
                );
            }
            if !sealed.get(&wire_key).is_some_and(|row| row.dirty) {
                sealed.remove(&wire_key);
            }
        }
    }
    true
}
/// Older clients retain this optional metadata as ciphertext and advance their cursor. Admit it
/// after upgrading even when the relay has no new rows; preserve unsupported and dirty envelopes.
fn admit_retained_group_order(
    section: &mut AccountState,
    keys: &ChainKeys,
    conflicts: &mut Vec<String>,
    diagnostics: &mut Vec<MergeDiagnostic>,
) -> bool {
    let hash = crypto::id_hash(keys, "meta", crate::sync::group_order::RECORD_ID);
    let wire_key = sealed_key("meta", &hash);
    let Some(retained) = section.sealed.get(&wire_key) else {
        return true;
    };
    if retained.dirty {
        return true;
    }
    let envelope = retained.envelope.clone();
    if !open_record(keys, &envelope)
        .is_ok_and(|record| crate::sync::group_order::decode(&record.0).is_some())
    {
        section.sealed.get_mut(&wire_key).unwrap().public_identity =
            verified_public_identity(keys, &envelope, true);
        return true;
    }
    // Remove only this authenticated, supported envelope before comparing with any typed row.
    // Leaving its identical opaque copy in place would make merge_rows retain it for a decoder.
    section.sealed.remove(&wire_key);
    merge_rows(
        &mut section.records,
        &mut section.sealed,
        keys,
        &PullResponse {
            records: vec![envelope],
            latest_seq: section.cursor_seq,
        },
        true,
        conflicts,
        diagnostics,
    )
}
fn admit_retained_tunnels(section: &mut AccountState, keys: &ChainKeys, conflicts: &mut Vec<String>, diagnostics: &mut Vec<MergeDiagnostic>) -> bool {
    let retained: Vec<_> = section.sealed.iter().filter(|(_, row)| row.envelope.kind == "meta" && !row.dirty).map(|(wire, row)| (wire.clone(), row.envelope.clone())).collect();
    for (wire, envelope) in retained {
        let supported = open_record(keys, &envelope).is_ok_and(|record| crate::sync::tunnel_rules::valid(&record.0));
        if !supported {
            if let Some(hint) = verified_public_identity(keys, &envelope, true).filter(|hint| crate::sync::tunnel_rules::is_id(&hint.id)) {
                section.sealed.get_mut(&wire).unwrap().public_identity = Some(hint);
            }
            continue;
        }
        section.sealed.remove(&wire);
        if !merge_rows(&mut section.records, &mut section.sealed, keys, &PullResponse { records: vec![envelope], latest_seq: section.cursor_seq }, true, conflicts, diagnostics) { return false; }
    }
    true
}
pub fn merge_account(
    section: &AccountState,
    keys: &ChainKeys,
    pulled: &PullResponse,
    since: u64,
) -> TypedMergeOutcome<AccountState> {
    let (gate, schema) = account_gate(section, keys, pulled);
    let mut out = result(section, gate, schema, section.baseline_established);
    if out.gate != AccountGate::Compatible {
        return out;
    }
    if !valid_pull(
        section.cursor_seq,
        section.baseline_established,
        max_seq(&section.records, &section.sealed),
        pulled,
        since,
    ) {
        out.gate = AccountGate::InvalidPull;
        return out;
    }
    if !admit_retained_group_order(
        &mut out.section,
        keys,
        &mut out.conflicts,
        &mut out.diagnostics,
    ) || !admit_retained_tunnels(&mut out.section, keys, &mut out.conflicts, &mut out.diagnostics) || !merge_rows(
        &mut out.section.records,
        &mut out.section.sealed,
        keys,
        pulled,
        true,
        &mut out.conflicts,
        &mut out.diagnostics,
    ) {
        out.section = section.clone();
        out.gate = AccountGate::InvalidPull;
        out.conflicts.clear();
        out.skipped = out.diagnostics.len().try_into().unwrap_or(u32::MAX);
        out.diagnostics.push(MergeDiagnostic {
            kind: String::new(),
            id_hash: String::new(),
            code: DiagnosticCode::OpaqueConflict,
        });
        return out;
    }
    out.skipped = out.diagnostics.len().try_into().unwrap_or(u32::MAX);
    out.section.cursor_seq = pulled.latest_seq;
    out.section.baseline_established = true;
    out.section.remote_schema_version = schema;
    out.baseline_established = true;
    out
}
pub fn merge_space(
    section: &SpaceStateV3,
    keys: &ChainKeys,
    pulled: &PullResponse,
    since: u64,
    gate: &AccountGate,
) -> TypedMergeOutcome<SpaceStateV3> {
    let mut out = result(section, gate.clone(), None, section.baseline_established);
    if *gate != AccountGate::Compatible {
        return out;
    }
    if !valid_pull(
        section.cursor_seq,
        section.baseline_established,
        max_seq(&section.records, &section.sealed),
        pulled,
        since,
    ) {
        out.gate = AccountGate::InvalidPull;
        return out;
    }
    if !merge_rows(
        &mut out.section.records,
        &mut out.section.sealed,
        keys,
        pulled,
        false,
        &mut out.conflicts,
        &mut out.diagnostics,
    ) {
        out.section = section.clone();
        out.gate = AccountGate::InvalidPull;
        out.conflicts.clear();
        out.skipped = out.diagnostics.len().try_into().unwrap_or(u32::MAX);
        out.diagnostics.push(MergeDiagnostic {
            kind: String::new(),
            id_hash: String::new(),
            code: DiagnosticCode::OpaqueConflict,
        });
        return out;
    }
    out.skipped = out.diagnostics.len().try_into().unwrap_or(u32::MAX);
    // Relationship review needs effective Group settings and hosts from every selected scope.
    // The round performs it after inserting this section into the complete candidate state.
    out.section.cursor_seq = pulled.latest_seq;
    out.section.baseline_established = true;
    out.baseline_established = true;
    out
}
fn outgoing(
    records: &BTreeMap<String, LocalRecord>,
    sealed: &BTreeMap<String, SealedRecord>,
    keys: &ChainKeys,
    account: bool,
) -> Result<Vec<TypedOutgoing>, AppError> {
    let mut out = Vec::new();
    for (key, row) in records.iter().filter(|(_, row)| row.dirty) {
        if row.record.kind.is_secret()
            || *key != record_key(row.record.kind, &row.record.id)
            || !valid_public(&row.record, account, keys)
            || sealed.contains_key(&sealed_key(
                row.record.kind.as_str(),
                &crypto::id_hash(keys, row.record.kind.as_str(), &row.record.id),
            ))
        {
            return Err(failure());
        }
        out.push(TypedOutgoing {
            outgoing: Outgoing {
                key: key.clone(),
                item: encode_record(keys, &row.record, row.seq)?,
                version: row.record.version,
                updated_at_ms: row.record.updated_at_ms,
            },
            expected: ExpectedRevision::Public(row.record.clone()),
        });
    }
    for (key, row) in sealed.iter().filter(|(_, row)| row.dirty) {
        let opened = open_record(keys, &row.envelope).map_err(|_| failure())?;
        if !account
            || !opened.0.kind.is_secret()
            || !valid_secret(&opened.0)
            || *key != sealed_key(&row.envelope.kind, &row.envelope.id_hash)
        {
            return Err(failure());
        }
        let envelope = &row.envelope;
        let item = PushItem {
            id_hash: envelope.id_hash.clone(),
            kind: envelope.kind.clone(),
            nonce: envelope.nonce.clone(),
            ciphertext: envelope.ciphertext.clone(),
            deleted: envelope.deleted,
            base_seq: envelope.seq,
        };
        out.push(TypedOutgoing {
            outgoing: Outgoing {
                key: key.clone(),
                item,
                version: opened.0.version,
                updated_at_ms: opened.0.updated_at_ms,
            },
            expected: ExpectedRevision::Sealed(envelope.clone()),
        });
    }
    Ok(out)
}
pub fn account_outgoing(
    section: &AccountState,
    keys: &ChainKeys,
) -> Result<Vec<TypedOutgoing>, AppError> {
    let (gate, _) = account_gate(
        section,
        keys,
        &PullResponse {
            records: Vec::new(),
            latest_seq: section.cursor_seq,
        },
    );
    if gate != AccountGate::Compatible || !section.baseline_established || section.frozen.is_some()
    {
        return Err(failure());
    }
    outgoing(&section.records, &section.sealed, keys, true)
}
pub fn space_outgoing(
    section: &SpaceStateV3,
    keys: &ChainKeys,
    gate: &AccountGate,
) -> Result<Vec<TypedOutgoing>, AppError> {
    if *gate != AccountGate::Compatible
        || !section.baseline_established
        || !section.selected
        || section.missing
    {
        return Err(failure());
    }
    outgoing(&section.records, &section.sealed, keys, false)
}
fn same_ciphertext(a: &Envelope, b: &Envelope) -> bool {
    a.kind == b.kind
        && a.id_hash == b.id_hash
        && a.nonce == b.nonce
        && a.ciphertext == b.ciphertext
        && a.deleted == b.deleted
}
fn apply_receipts(
    records: &mut BTreeMap<String, LocalRecord>,
    sealed: &mut BTreeMap<String, SealedRecord>,
    outgoing: &[TypedOutgoing],
    pushed: &Pushed,
) {
    for (key, seq) in &pushed.accepted {
        let Some(sent) = outgoing.iter().find(|sent| &sent.outgoing.key == key) else {
            continue;
        };
        if *seq == 0 || *seq > MAX_RELAY_SEQ || *seq < sent.outgoing.item.base_seq {
            continue;
        }
        match &sent.expected {
            ExpectedRevision::Public(expected) => {
                if let Some(row) = records
                    .get_mut(key)
                    .filter(|row| row.dirty && row.record == *expected && row.seq <= *seq)
                {
                    row.seq = *seq;
                    row.dirty = false;
                }
            }
            ExpectedRevision::Sealed(expected) => {
                if let Some(row) = sealed.get_mut(key).filter(|row| {
                    row.dirty
                        && same_ciphertext(&row.envelope, expected)
                        && row.envelope.seq <= *seq
                }) {
                    row.envelope.seq = *seq;
                    row.dirty = false;
                }
            }
        }
    }
}
/// Apply every accepted row first, irrespective of a later error/freeze. Cursor belongs to pull only.
pub fn apply_account_receipts(
    section: &AccountState,
    outgoing: &[TypedOutgoing],
    pushed: &Pushed,
) -> AccountState {
    let mut next = section.clone();
    apply_receipts(&mut next.records, &mut next.sealed, outgoing, pushed);
    next
}
pub fn apply_space_receipts(
    section: &SpaceStateV3,
    outgoing: &[TypedOutgoing],
    pushed: &Pushed,
) -> SpaceStateV3 {
    let mut next = section.clone();
    apply_receipts(&mut next.records, &mut next.sealed, outgoing, pushed);
    next
}

#[cfg(test)]
#[path = "record_merge_tests.rs"]
mod tests;
