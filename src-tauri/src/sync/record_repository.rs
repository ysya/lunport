//! Pure, immutable record operations. SyncCore alone owns locks, persistence and generation.
//! A returned state is a candidate: persist it before replacing the runtime state.

use crate::sync::crypto::is_chain_id;
use crate::sync::record::{record_key, LocalRecord, Record, RecordKind};
use crate::sync::records_v3::*;
use crate::sync::slot_rules::is_slot_id;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRevision {
    pub version: u64,
    pub updated_at_ms: u64,
    pub device_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostReadiness {
    Ready,
    NeedsKey(String),
    KeyConflict(String),
    NeedsReview,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostView {
    pub host: HostRecord,
    pub effective_payload: HostPayload,
    pub inherited_from: BTreeMap<String, String>,
    pub group_error: Option<String>,
    pub revision: RecordRevision,
    pub readiness: HostReadiness,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyAuthority {
    Local,
    Account,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    Available,
    NeedsMaterial,
    Conflict,
    Deleted,
}
/// Available means coherent metadata and a vault reference, not that material exists or is unlocked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyView {
    pub id: String,
    pub authority: KeyAuthority,
    pub public: Option<KeySlotPayload>,
    pub vault_id: Option<String>,
    pub status: KeyStatus,
    /// Native-only central material digest; legacy metadata never supplies this binding.
    pub expected_material_hash: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositorySnapshot {
    pub hosts: Vec<HostView>,
    pub keys: Vec<KeyView>,
    pub groups: Vec<crate::sync::record_groups::GroupView>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEndpoint {
    pub hostname: String,
    pub port: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepositoryError {
    Validation(RecordValidationError),
    RevisionConflict { id: String, current: RecordRevision },
    SpaceUnavailable(String),
    ReadOnlyAccount,
    Group(String),
    UpgradeConfirmationRequired,
    OpaqueHostAuthority(String),
    EndpointChanged(String),
    PinConflict(String),
    KeyNotFound(String),
    KeyInUse(String),
    OrderingOverflow(String),
    /// A save that would leave the library's Catalog too large for one sync record (design 2026-10-26, Room in the Catalog). It reads
    /// as `transports::NO_ROOM` wherever it is shown.
    NoRoom,
    /// A route save whose displayed route is no longer the saved one. It reads as `transports::ROUTE_CHANGED` wherever it is shown.
    RouteChanged,
}
impl From<RecordValidationError> for RepositoryError {
    fn from(error: RecordValidationError) -> Self {
        Self::Validation(error)
    }
}
impl std::fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRoom => f.write_str(super::transports::NO_ROOM),
            Self::RouteChanged => f.write_str(super::transports::ROUTE_CHANGED),
            _ => write!(f, "{self:?}"),
        }
    }
}
impl std::error::Error for RepositoryError {}

pub(crate) fn invalid(field: &'static str, id: &str, reason: &str) -> RepositoryError {
    RecordValidationError::Invalid {
        field,
        id: id.into(),
        reason: reason.into(),
    }
    .into()
}
fn validate_header(state: &SyncStateV3) -> Result<(), RepositoryError> {
    if !matches!(
        state.version,
        STATE_VERSION | GROUP_STATE_VERSION | NAVIGATION_STATE_VERSION | LOCAL_CREDENTIAL_STATE_VERSION | LOCAL_CONFLICT_STATE_VERSION | CENTRAL_STATE_VERSION
            | TRANSPORT_STATE_VERSION | TRANSPORT_SYNC_STATE_VERSION
    ) {
        return Err(RecordValidationError::UnsupportedSchema {
            kind: "state",
            found: state.version,
        }
        .into());
    }
    if !is_slot_id(&state.device_id) {
        return Err(invalid(
            "device_id",
            &state.device_id,
            "expected a device id",
        ));
    }
    if state.account.is_none() && !state.spaces.is_empty() {
        return Err(invalid("spaces", "state", "spaces require an account"));
    }
    if let Some(account) = &state.account {
        if !is_chain_id(&account.chain_id) {
            return Err(invalid(
                "chain_id",
                &account.chain_id,
                "expected an account chain id",
            ));
        }
    }
    for id in state.spaces.keys() {
        if !is_chain_id(id) {
            return Err(invalid("space_id", id, "expected a chain id"));
        }
    }
    Ok(())
}
pub(crate) fn validate_cache(key: &str, local: &LocalRecord) -> Result<(), RepositoryError> {
    if local.record.kind.is_secret() {
        return Err(invalid(
            "records",
            &local.record.id,
            "secret records must remain sealed",
        ));
    }
    if key != record_key(local.record.kind, &local.record.id) {
        return Err(invalid(
            "record_key",
            &local.record.id,
            "cache key does not match kind and id",
        ));
    }
    if local.record.version == 0 || !is_slot_id(&local.record.device_id) {
        return Err(invalid(
            "revision",
            &local.record.id,
            "invalid record ordering identity",
        ));
    }
    Ok(())
}
pub(crate) fn revision(record: &Record) -> RecordRevision {
    RecordRevision {
        version: record.version,
        updated_at_ms: record.updated_at_ms,
        device_id: record.device_id.clone(),
    }
}
pub(crate) fn opaque_shadows(
    sealed: &crate::sync::state_v2::SealedRecord,
    local: Option<&LocalRecord>,
    kind: RecordKind,
    id: &str,
) -> bool {
    let Some(identity) = sealed.public_identity.as_ref().filter(|hint| {
        hint.is_valid_for(&sealed.envelope)
            && hint.id == id
            && sealed.envelope.kind == kind.as_str()
    }) else {
        return false;
    };
    crate::sync::record::merge(local, &identity.header(kind))
        != crate::sync::record::MergeOutcome::KeepLocal
}

fn read_hosts(
    records: &BTreeMap<String, LocalRecord>,
    scope: HostScope,
    sealed: Option<&BTreeMap<String, crate::sync::state_v2::SealedRecord>>,
    out: &mut Vec<HostView>,
) -> Result<(), RepositoryError> {
    for (key, local) in records {
        validate_cache(key, local)?;
        if local.record.kind == RecordKind::Group {
            continue;
        }
        if let TypedRecord::Live(host) = decode_host(&local.record, scope.clone())? {
            out.push(HostView {
                effective_payload: host.payload.clone(),
                inherited_from: BTreeMap::new(),
                group_error: None,
                host,
                revision: revision(&local.record),
                readiness: if sealed.is_some_and(|rows| {
                    rows.values().any(|row| {
                        opaque_shadows(row, Some(local), RecordKind::Host, &local.record.id)
                    })
                }) {
                    HostReadiness::NeedsReview
                } else {
                    HostReadiness::Ready
                },
            });
        }
    }
    Ok(())
}
fn needs_import_review(host: &HostRecord) -> bool {
    host.payload.imported.as_ref().is_some_and(|imported| {
        imported
            .unsupported
            .iter()
            .any(|setting| setting.requires_review)
    })
}
fn duplicate_id(hosts: &[HostView], id: &str) -> bool {
    hosts.iter().filter(|view| view.host.id == id).count() > 1
}
fn alias_conflict(hosts: &[HostView], host: &HostRecord) -> bool {
    hosts
        .iter()
        .filter(|view| {
            view.host.scope == host.scope && view.host.payload.alias == host.payload.alias
        })
        .count()
        > 1
}
fn host_index<'a>(hosts: &'a [HostView], id: &str) -> Result<usize, RecordValidationError> {
    let mut matching = hosts
        .iter()
        .enumerate()
        .filter(|(_, view)| view.host.id == id);
    let first = matching
        .next()
        .ok_or_else(|| RecordValidationError::HostNotFound(id.into()))?
        .0;
    if matching.next().is_some() {
        return Err(RecordValidationError::DuplicateId(id.into()));
    }
    Ok(first)
}
/// Resolve from one owned snapshot. Only the first jump inherits its own route, as OpenSSH does.
fn route_indices(hosts: &[HostView], id: &str) -> Result<Vec<usize>, RecordValidationError> {
    fn append(
        hosts: &[HostView],
        index: usize,
        root: &str,
        stack: &mut BTreeSet<usize>,
        out: &mut Vec<usize>,
    ) -> Result<(), RecordValidationError> {
        let host = &hosts[index].host;
        let payload = &hosts[index].effective_payload;
        if !stack.insert(index) {
            return Err(RecordValidationError::JumpCycle(root.into()));
        }
        if stack.len() > MAX_JUMPS + 1 {
            return Err(RecordValidationError::JumpDepth(root.into()));
        }
        for (position, id) in payload.jump.iter().enumerate() {
            let jump = match host_index(hosts, id) {
                Err(RecordValidationError::HostNotFound(_)) => {
                    return Err(RecordValidationError::MissingJump {
                        host_id: host.id.clone(),
                        jump_id: id.clone(),
                    });
                }
                other => other?,
            };
            if stack.contains(&jump) {
                return Err(RecordValidationError::JumpCycle(root.into()));
            }
            if position == 0 {
                append(hosts, jump, root, stack, out)?;
            } else {
                add(hosts, jump, root, out)?;
            }
        }
        stack.remove(&index);
        add(hosts, index, root, out)
    }
    fn add(
        hosts: &[HostView],
        index: usize,
        root: &str,
        out: &mut Vec<usize>,
    ) -> Result<(), RecordValidationError> {
        if out.contains(&index) {
            return Err(RecordValidationError::RepeatedJump {
                host_id: root.into(),
                jump_id: hosts[index].host.id.clone(),
            });
        }
        out.push(index);
        if out.len() > MAX_JUMPS + 1 {
            return Err(RecordValidationError::JumpDepth(root.into()));
        }
        Ok(())
    }
    let index = host_index(hosts, id)?;
    let mut out = Vec::new();
    append(hosts, index, id, &mut BTreeSet::new(), &mut out)?;
    Ok(out)
}

/// Relationship conflicts can arise from valid remote records; retain them for explicit repair.
pub fn snapshot(state: &SyncStateV3) -> Result<RepositorySnapshot, RepositoryError> {
    validate_header(state)?;
    let keys = list_keys(state)?;
    let mut hosts = Vec::new();
    read_hosts(&state.local.hosts, HostScope::Local, None, &mut hosts)?;
    for (space_id, space) in &state.spaces {
        if space.selected && !space.missing {
            read_hosts(
                &space.records,
                HostScope::Space {
                    space_id: space_id.clone(),
                },
                Some(&space.sealed),
                &mut hosts,
            )?;
        }
    }
    for view in &mut hosts {
        match crate::sync::record_groups::resolve_effective(state, &view.host) {
            Ok(effective) => {
                view.effective_payload = effective.payload;
                view.inherited_from = effective.inherited_from;
            }
            Err(e) => {
                view.group_error = Some(e.to_string());
                view.readiness = HostReadiness::NeedsReview;
            }
        }
    }
    let readiness: Vec<_> = hosts
        .iter()
        .map(|view| {
            let host = &view.host;
            if view.readiness == HostReadiness::NeedsReview
                || needs_import_review(host)
                || alias_conflict(&hosts, host)
                || route_indices(&hosts, &host.id).is_err()
            {
                return HostReadiness::NeedsReview;
            }
            if view.effective_payload.auth == AuthKind::Key {
                let id = view
                    .effective_payload
                    .key_id
                    .as_ref()
                    .expect("decoded key reference");
                return match keys.iter().find(|key| &key.id == id).map(|key| &key.status) {
                    Some(KeyStatus::Available) => HostReadiness::Ready,
                    Some(KeyStatus::Conflict) => HostReadiness::KeyConflict(id.clone()),
                    _ => HostReadiness::NeedsKey(id.clone()),
                };
            }
            HostReadiness::Ready
        })
        .collect();
    for (host, status) in hosts.iter_mut().zip(readiness) {
        host.readiness = status;
    }
    Ok(RepositorySnapshot {
        hosts,
        keys,
        groups: crate::sync::record_groups::list_groups(state)?,
    })
}
/// Upload review excludes connection-only import warnings and unavailable key material.
/// Resolve against the complete snapshot so jumps can target hosts in another scope.
pub(crate) fn scope_requires_relationship_review(
    state: &SyncStateV3,
    scope: &HostScope,
) -> Result<bool, RepositoryError> {
    let repository = snapshot(state)?;
    Ok(repository.hosts.iter().any(|view| {
        &view.host.scope == scope
            && (view.group_error.is_some()
                || ensure_host_authority(state, &view.host).is_err()
                || alias_conflict(&repository.hosts, &view.host)
                || route_indices(&repository.hosts, &view.host.id).is_err())
    }))
}

pub fn list_hosts(state: &SyncStateV3) -> Result<Vec<HostView>, RepositoryError> {
    Ok(snapshot(state)?.hosts)
}
pub fn get_host(state: &SyncStateV3, id: &str) -> Result<HostView, RepositoryError> {
    let hosts = list_hosts(state)?;
    Ok(hosts[host_index(&hosts, id)?].clone())
}
pub fn find_by_alias(state: &SyncStateV3, alias: &str) -> Result<HostView, RepositoryError> {
    let hosts = list_hosts(state)?;
    let mut matching = hosts.iter().filter(|host| host.host.payload.alias == alias);
    let first = matching
        .next()
        .ok_or_else(|| RecordValidationError::HostNotFound(alias.into()))?;
    if matching.next().is_some() {
        return Err(RecordValidationError::AmbiguousAlias(alias.into()).into());
    }
    host_index(&hosts, &first.host.id)?;
    Ok(first.clone())
}
/// Returned hops also carry readiness; the adapter must reject any blocked hop before engine construction.
pub fn resolve_host_chain(state: &SyncStateV3, id: &str) -> Result<Vec<HostView>, RepositoryError> {
    let snapshot = snapshot(state)?;
    Ok(route_indices(&snapshot.hosts, id)?
        .into_iter()
        .map(|index| snapshot.hosts[index].clone())
        .collect())
}

pub fn list_keys(state: &SyncStateV3) -> Result<Vec<KeyView>, RepositoryError> {
    validate_header(state)?;
    let mut keys = BTreeMap::new();
    for (id, local) in &state.local.keys {
        validate_keyslot(id, &local.public)?;
        if !is_slot_id(&local.vault_id) {
            return Err(invalid("vault_id", id, "expected a vault id"));
        }
        keys.insert(
            id.clone(),
            KeyView {
                id: id.clone(),
                authority: KeyAuthority::Local,
                public: Some(local.public.clone()),
                vault_id: Some(local.vault_id.clone()),
                status: KeyStatus::Available,
                expected_material_hash: None,
            },
        );
    }
    if let Some(account) = &state.account {
        for (cache_key, local) in &account.records {
            validate_cache(cache_key, local)?;
            if local.record.kind == RecordKind::Host {
                return Err(RecordValidationError::WrongKind {
                    expected: "account metadata",
                    found: "host".into(),
                }
                .into());
            }
            if local.record.kind != RecordKind::KeySlot {
                continue;
            }
            let id = &local.record.id;
            let view = match decode_keyslot(&local.record)? {
                TypedRecord::Tombstone { .. } => KeyView {
                    id: id.clone(),
                    authority: KeyAuthority::Account,
                    public: None,
                    vault_id: None,
                    status: KeyStatus::Deleted,
                    expected_material_hash: None,
                },
                TypedRecord::Live(public) => {
                    let material = state.local.keys.get(id);
                    let status = match material {
                        None => KeyStatus::NeedsMaterial,
                        Some(material)
                            if key_material_matches(
                                &public,
                                &material.public.public_key,
                                &material.public.fingerprint,
                            )
                            .is_ok() =>
                        {
                            KeyStatus::Available
                        }
                        Some(_) => KeyStatus::Conflict,
                    };
                    let vault_id = if status == KeyStatus::Available {
                        material.map(|key| key.vault_id.clone())
                    } else {
                        None
                    };
                    KeyView {
                        id: id.clone(),
                        authority: KeyAuthority::Account,
                        public: Some(public),
                        vault_id,
                        status,
                        expected_material_hash: None,
                    }
                }
            };
            keys.insert(id.clone(), view);
        }
        for sealed in account.sealed.values() {
            let Some(identity) = sealed.public_identity.as_ref() else {
                continue;
            };
            let Some(view) = keys.get_mut(&identity.id) else {
                continue;
            };
            let local = account
                .records
                .get(&record_key(RecordKind::KeySlot, &identity.id));
            if opaque_shadows(sealed, local, RecordKind::KeySlot, &identity.id) {
                // Keep old public metadata for inspection, but never expose a vault fallback.
                view.authority = KeyAuthority::Account;
                view.status = KeyStatus::Conflict;
                view.vault_id = None;
            }
        }
    }
    if let Some(owner) = state.local.central.as_ref().filter(|owner| owner.control.cutover) {
        let ledger = state.local.central_projection.as_ref();
        if ledger.is_some_and(|ledger| {
            ledger.validate(owner).is_err()
                || state.account.as_ref().map(|account| account.chain_id.as_str())
                    != Some(ledger.vault.as_str())
        }) {
            return Err(invalid("central_projection", "local", "central material authority does not match this vault"));
        }
        for view in keys.values_mut() {
            if view.status == KeyStatus::Deleted || view.status == KeyStatus::Conflict {
                continue;
            }
            let binding = (view.authority == KeyAuthority::Account).then_some(ledger).flatten()
                .and_then(|ledger| ledger.material_reference(
                    owner, &view.id, state.local.keys.get(&view.id)?, view.public.as_ref()?,
                ));
            if let Some(hash) = binding {
                view.expected_material_hash = Some(hash);
            } else {
                view.status = KeyStatus::NeedsMaterial;
                view.vault_id = None;
            }
        }
    }
    Ok(keys.into_values().collect())
}
pub fn resolve_key(state: &SyncStateV3, id: &str) -> Result<KeyView, RepositoryError> {
    list_keys(state)?
        .into_iter()
        .find(|key| key.id == id)
        .ok_or_else(|| RepositoryError::KeyNotFound(id.into()))
}

/// Rename public metadata only. Stable IDs, vault material and host references are untouched.
pub fn rename_key(
    state: &SyncStateV3,
    id: &str,
    expected: &KeySlotPayload,
    name: &str,
    now_ms: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let name = name.trim();
    if !crate::sync::slot_rules::valid_slot_name(name) {
        return Err(invalid("name", id, "expected 1–64 letters, numbers, dots, dashes or underscores"));
    }
    let key = resolve_key(state, id)?;
    if matches!(key.status, KeyStatus::Conflict | KeyStatus::Deleted) {
        return Err(invalid("key", id, "resolve the key conflict or deletion before renaming"));
    }
    if key.public.as_ref() != Some(expected) {
        return Err(invalid("key", id, "key metadata changed; refresh before renaming"));
    }
    if key.authority == KeyAuthority::Account && (account_writes_blocked(state) || state.rotation.is_some()) {
        return Err(RepositoryError::ReadOnlyAccount);
    }
    if expected.name == name {
        return Ok(state.clone());
    }
    let mut public = expected.clone();
    public.name = name.into();
    validate_keyslot(id, &public)?;
    let mut next = state.clone();
    if key.authority == KeyAuthority::Account {
        let cache_key = record_key(RecordKind::KeySlot, id);
        let previous = &state.account.as_ref().unwrap().records[&cache_key];
        let mut record = ordered_record(state, id, serde_json::to_value(&public).unwrap(), false, now_ms, &[&previous.record])?;
        record.kind = RecordKind::KeySlot;
        next.account.as_mut().unwrap().records.insert(cache_key, LocalRecord {
            record, seq: previous.seq, dirty: true,
        });
    }
    // Keep a coherent local copy's label in step with account metadata, including after leaving sync.
    if let Some(local) = next.local.keys.get_mut(id) {
        local.public.name = name.into();
    }
    Ok(next)
}

/// Delete the library identity; retained encrypted material/history grants no active reference.
/// Force permits referenced keys, while leaving every host and Group configuration intact.
pub fn delete_key(
    state: &SyncStateV3,
    id: &str,
    expected: &KeySlotPayload,
    reviewed_snapshot: &str,
    force: bool,
    now_ms: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let key = resolve_key(state, id)?;
    if matches!(key.status, KeyStatus::Conflict | KeyStatus::Deleted)
        || key.public.as_ref() != Some(expected)
        || crate::sync::record_groups::deletion_snapshot_token(&snapshot(state)?)?
            != reviewed_snapshot
    {
        return Err(invalid(
            "key",
            id,
            "key deletion review changed; refresh and retry",
        ));
    }
    if key.authority == KeyAuthority::Account
        && (account_writes_blocked(state) || state.rotation.is_some())
    {
        return Err(RepositoryError::ReadOnlyAccount);
    }
    fn references(value: &serde_json::Value, id: &str) -> bool {
        match value {
            serde_json::Value::Object(fields) => fields.iter().any(|(name, value)| {
                name == "key_id" && value.as_str() == Some(id) || references(value, id)
            }),
            serde_json::Value::Array(values) => values.iter().any(|value| references(value, id)),
            _ => false,
        }
    }
    let used = state
        .local
        .hosts
        .values()
        .chain(state.local.groups.values())
        .chain(
            state
                .spaces
                .values()
                .flat_map(|space| space.records.values()),
        )
        .any(|row| !row.record.deleted && references(&row.record.payload, id));
    if used && !force {
        return Err(RepositoryError::KeyInUse(id.into()));
    }
    let mut next = state.clone();
    if key.authority == KeyAuthority::Account {
        let cache_key = record_key(RecordKind::KeySlot, id);
        let previous = &state.account.as_ref().unwrap().records[&cache_key];
        let mut record = ordered_record(
            state,
            id,
            serde_json::Value::Null,
            true,
            now_ms,
            &[&previous.record],
        )?;
        record.kind = RecordKind::KeySlot;
        next.account.as_mut().unwrap().records.insert(
            cache_key,
            LocalRecord {
                record,
                seq: previous.seq,
                dirty: true,
            },
        );
    }
    next.local.keys.remove(id);
    validate_state(&next)?;
    Ok(next)
}

pub(crate) fn ensure_scope(state: &SyncStateV3, scope: &HostScope) -> Result<(), RepositoryError> {
    if let HostScope::Space { space_id } = scope {
        state
            .account
            .as_ref()
            .ok_or_else(|| RepositoryError::SpaceUnavailable(space_id.clone()))?;
        if account_writes_blocked(state) {
            return Err(RepositoryError::ReadOnlyAccount);
        }
        let space = state
            .spaces
            .get(space_id)
            .ok_or_else(|| RepositoryError::SpaceUnavailable(space_id.clone()))?;
        if !space.selected || space.missing {
            return Err(RepositoryError::SpaceUnavailable(space_id.clone()));
        }
    }
    Ok(())
}
fn records<'a>(state: &'a SyncStateV3, scope: &HostScope) -> &'a BTreeMap<String, LocalRecord> {
    match scope {
        HostScope::Local => &state.local.hosts,
        HostScope::Space { space_id } => &state.spaces[space_id].records,
    }
}
fn records_mut<'a>(
    state: &'a mut SyncStateV3,
    scope: &HostScope,
) -> &'a mut BTreeMap<String, LocalRecord> {
    match scope {
        HostScope::Local => &mut state.local.hosts,
        HostScope::Space { space_id } => {
            &mut state
                .spaces
                .get_mut(space_id)
                .expect("validated destination")
                .records
        }
    }
}
/// Cached supported payloads remain inspectable, but cannot overwrite winning opaque authority.
/// Imported review and route defects remain repairable; readiness alone is not an authority check.
fn ensure_host_authority(state: &SyncStateV3, host: &HostRecord) -> Result<(), RepositoryError> {
    let HostScope::Space { space_id } = &host.scope else {
        return Ok(());
    };
    let space = &state.spaces[space_id];
    let local = space.records.get(&record_key(RecordKind::Host, &host.id));
    if space.sealed.values().any(|sealed| opaque_shadows(sealed, local, RecordKind::Host, &host.id)) {
        return Err(RepositoryError::OpaqueHostAuthority(host.id.clone()));
    }
    Ok(())
}
fn checked_host(
    state: &SyncStateV3,
    id: &str,
    expected: &RecordRevision,
) -> Result<HostView, RepositoryError> {
    let host = get_host(state, id)?;
    if &host.revision != expected {
        return Err(RepositoryError::RevisionConflict {
            id: id.into(),
            current: host.revision,
        });
    }
    ensure_scope(state, &host.host.scope)?;
    ensure_host_authority(state, &host.host)?;
    Ok(host)
}
pub(crate) fn ordered_record(
    state: &SyncStateV3,
    id: &str,
    payload: serde_json::Value,
    deleted: bool,
    now_ms: u64,
    previous: &[&Record],
) -> Result<Record, RepositoryError> {
    let max_version = previous
        .iter()
        .map(|record| record.version)
        .max()
        .unwrap_or(0);
    let version = max_version
        .checked_add(1)
        .ok_or_else(|| RepositoryError::OrderingOverflow(id.into()))?;
    let updated_at_ms = match previous.iter().map(|record| record.updated_at_ms).max() {
        Some(previous) if previous >= now_ms => previous
            .checked_add(1)
            .ok_or_else(|| RepositoryError::OrderingOverflow(id.into()))?,
        _ => now_ms,
    };
    Ok(Record {
        kind: RecordKind::Host,
        id: id.into(),
        version,
        updated_at_ms,
        device_id: state.device_id.clone(),
        deleted,
        payload,
    })
}
pub(crate) fn cached(record: Record, seq: u64, scope: &HostScope) -> LocalRecord {
    LocalRecord {
        record,
        seq,
        dirty: matches!(scope, HostScope::Space { .. }),
    }
}
/// Reject newly introduced relationship defects; existing unrelated remote conflicts remain repairable.
pub(crate) fn validate_transition(
    before: &SyncStateV3,
    after: &SyncStateV3,
) -> Result<(), RepositoryError> {
    let old = snapshot(before)?.hosts;
    let new = snapshot(after)?.hosts;
    for view in &new {
        let host = &view.host;
        if let Some(error) = &view.group_error {
            if !old
                .iter()
                .any(|v| v.host.id == host.id && v.group_error.as_ref() == Some(error))
            {
                return Err(RepositoryError::Group(error.clone()));
            }
        }
        if duplicate_id(&new, &host.id) && !duplicate_id(&old, &host.id) {
            return Err(RecordValidationError::DuplicateId(host.id.clone()).into());
        }
        if alias_conflict(&new, host)
            && !old.iter().any(|view| {
                view.host.scope == host.scope
                    && view.host.payload.alias == host.payload.alias
                    && alias_conflict(&old, &view.host)
            })
        {
            return Err(RecordValidationError::AliasConflict {
                alias: host.payload.alias.clone(),
                scope: host.scope.clone(),
            }
            .into());
        }
        if let Err(error) = route_indices(&new, &host.id) {
            if matches!(error, RecordValidationError::MissingJump { .. })
                && needs_import_review(host)
            {
                continue;
            }
            if route_indices(&old, &host.id).err().as_ref() != Some(&error) {
                return Err(error.into());
            }
        }
    }
    Ok(())
}
/// The caller chooses Local by default and supplies a fresh ID. A UI payload cannot establish a pin.
pub fn create_host(
    state: &SyncStateV3,
    id: &str,
    scope: HostScope,
    mut payload: HostPayload,
    now_ms: u64,
) -> Result<SyncStateV3, RepositoryError> {
    ensure_scope(state, &scope)?;
    crate::sync::record_groups::require_host_format(state, &payload, &scope)?;
    let key = record_key(RecordKind::Host, id);
    if state.local.hosts.contains_key(&key)
        || state
            .spaces
            .values()
            .any(|space| space.records.contains_key(&key))
    {
        return Err(RecordValidationError::DuplicateId(id.into()).into());
    }
    payload.host_key = None;
    validate_host(&HostRecord {
        id: id.into(),
        scope: scope.clone(),
        payload: payload.clone(),
    })?;
    let record = ordered_record(
        state,
        id,
        serde_json::to_value(payload).expect("HostPayload serializes"),
        false,
        now_ms,
        &[],
    )?;
    let mut next = state.clone();
    records_mut(&mut next, &scope).insert(key, cached(record, 0, &scope));
    validate_transition(state, &next)?;
    Ok(next)
}
/// Preserve the server's current pin for an unchanged endpoint; discard client-supplied pin fields.
pub fn update_host(
    state: &SyncStateV3,
    id: &str,
    expected: &RecordRevision,
    mut payload: HostPayload,
    now_ms: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let host = checked_host(state, id, expected)?;
    crate::sync::record_groups::require_host_format(state, &payload, &host.host.scope)?;
    let effective = crate::sync::record_groups::resolve_effective(
        state,
        &HostRecord {
            payload: payload.clone(),
            ..host.host.clone()
        },
    )?;
    payload.host_key = if host.effective_payload.hostname == effective.payload.hostname
        && host.effective_payload.port == effective.payload.port
    {
        host.host.payload.host_key.clone()
    } else {
        None
    };
    validate_host(&HostRecord {
        payload: payload.clone(),
        ..host.host.clone()
    })?;
    let key = record_key(RecordKind::Host, id);
    let previous = &records(state, &host.host.scope)[&key];
    let record = ordered_record(
        state,
        id,
        serde_json::to_value(payload).expect("HostPayload serializes"),
        false,
        now_ms,
        &[&previous.record],
    )?;
    let mut next = state.clone();
    records_mut(&mut next, &host.host.scope)
        .insert(key, cached(record, previous.seq, &host.host.scope));
    validate_transition(state, &next)?;
    Ok(next)
}
pub fn delete_host(
    state: &SyncStateV3,
    id: &str,
    expected: &RecordRevision,
    now_ms: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let host = checked_host(state, id, expected)?;
    let key = record_key(RecordKind::Host, id);
    let previous = &records(state, &host.host.scope)[&key];
    let record = ordered_record(
        state,
        id,
        serde_json::Value::Null,
        true,
        now_ms,
        &[&previous.record],
    )?;
    let mut next = state.clone();
    records_mut(&mut next, &host.host.scope)
        .insert(key, cached(record, previous.seq, &host.host.scope));
    validate_transition(state, &next)?;
    Ok(next)
}
/// One candidate contains the source tombstone and destination live record with the same global ID.
pub fn move_host(
    state: &SyncStateV3,
    id: &str,
    expected: &RecordRevision,
    destination: HostScope,
    now_ms: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let host = checked_host(state, id, expected)?;
    ensure_scope(state, &destination)?;
    if host.host.scope == destination {
        return Ok(state.clone());
    }
    let key = record_key(RecordKind::Host, id);
    let source = &records(state, &host.host.scope)[&key];
    let existing = records(state, &destination).get(&key);
    if existing.is_some_and(|local| !local.record.deleted) {
        return Err(RecordValidationError::DuplicateId(id.into()).into());
    }
    let mut previous = vec![&source.record];
    if let Some(existing) = existing {
        validate_cache(&key, existing)?;
        previous.push(&existing.record);
    }
    let record = ordered_record(
        state,
        id,
        serde_json::to_value(crate::sync::record_groups::materialize(
            &crate::sync::record_groups::resolve_effective(state, &host.host)?.payload,
        ))
        .expect("host payload"),
        false,
        now_ms,
        &previous,
    )?;
    let mut tombstone = record.clone();
    tombstone.deleted = true;
    tombstone.payload = serde_json::Value::Null;
    let mut next = state.clone();
    records_mut(&mut next, &host.host.scope)
        .insert(key.clone(), cached(tombstone, source.seq, &host.host.scope));
    records_mut(&mut next, &destination).insert(
        key,
        cached(record, existing.map_or(0, |local| local.seq), &destination),
    );
    validate_transition(state, &next)?;
    Ok(next)
}
fn same_pin(left: &StoredHostKey, right: &StoredHostKey) -> bool {
    left.algorithm == right.algorithm
        && left.public_key == right.public_key
        && left.fingerprint == right.fingerprint
}
/// Forget only the identity displayed by the user, leaving connection settings and keys intact.
pub fn forget_host_key(
    state: &SyncStateV3,
    id: &str,
    expected: &RecordRevision,
    endpoint: &HostEndpoint,
    pin: &StoredHostKey,
    now_ms: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let host = checked_host(state, id, expected)?;
    if host.effective_payload.hostname != endpoint.hostname
        || host.effective_payload.port != endpoint.port
    {
        return Err(RepositoryError::EndpointChanged(id.into()));
    }
    if host.host.payload.host_key.as_ref() != Some(pin) {
        return Err(RepositoryError::PinConflict(id.into()));
    }
    let mut payload = host.host.payload.clone();
    payload.host_key = None;
    let key = record_key(RecordKind::Host, id);
    let previous = &records(state, &host.host.scope)[&key];
    let record = ordered_record(
        state,
        id,
        serde_json::to_value(payload).unwrap(),
        false,
        now_ms,
        &[&previous.record],
    )?;
    let mut next = state.clone();
    next.local.credential_approvals.remove(id);
    records_mut(&mut next, &host.host.scope)
        .insert(key, cached(record, previous.seq, &host.host.scope));
    validate_transition(state, &next)?;
    Ok(next)
}
/// Compare endpoint and prior public key identity under SyncCore's lock; never write on conflict.
pub fn pin_host_key(
    state: &SyncStateV3,
    id: &str,
    endpoint: &HostEndpoint,
    previous_pin: Option<&StoredHostKey>,
    mut candidate: StoredHostKey,
    now_ms: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let host = get_host(state, id)?;
    ensure_scope(state, &host.host.scope)?;
    ensure_host_authority(state, &host.host)?;
    if host.group_error.is_some()
        || host.effective_payload.hostname != endpoint.hostname
        || host.effective_payload.port != endpoint.port
    {
        return Err(RepositoryError::EndpointChanged(id.into()));
    }
    let current = host.host.payload.host_key.as_ref();
    if current.is_some_and(|current| same_pin(current, &candidate)) {
        return Ok(state.clone());
    }
    let matches = match (current, previous_pin) {
        (None, None) => true,
        (Some(current), Some(previous)) => same_pin(current, previous),
        _ => false,
    };
    if !matches {
        return Err(RepositoryError::PinConflict(id.into()));
    }
    candidate.pinned_at_ms = now_ms;
    candidate.pinned_by_device_id = state.device_id.clone();
    let mut payload = host.host.payload.clone();
    payload.host_key = Some(candidate);
    validate_host(&HostRecord {
        payload: payload.clone(),
        ..host.host.clone()
    })?;
    let key = record_key(RecordKind::Host, id);
    let previous = &records(state, &host.host.scope)[&key];
    let record = ordered_record(
        state,
        id,
        serde_json::to_value(payload).expect("HostPayload serializes"),
        false,
        now_ms,
        &[&previous.record],
    )?;
    let mut next = state.clone();
    records_mut(&mut next, &host.host.scope)
        .insert(key, cached(record, previous.seq, &host.host.scope));
    validate_transition(state, &next)?;
    Ok(next)
}

#[cfg(test)]
#[path = "record_repository_tests/mod.rs"]
mod tests;
