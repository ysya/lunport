//! Pure structured library history candidate. No frozen-source/file-completeness/consent authority.
use super::{
    crypto,
    migration_materials::Materials,
    migration_sources::{Known, KnownData, KnownInput, Position, Scope},
    payload::{
        self, Catalog, Collection, Data, GroupOrder, Identity, KeyStorage, PrivateMaterial,
        SharedKeyslot,
    },
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{
        record::{record_key, LocalRecord, Record, RecordKind},
        records_v3::{self, HostScope, SyncStateV3},
        state_v2::AccountState,
    },
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
pub(super) struct History {
    rows: Vec<(Identity, Data)>,
    bytes: usize,
    seen: BTreeSet<(String, String)>,
    latest: BTreeMap<String, String>,
}
impl History {
    pub(in crate::sync::central) fn empty_retained() -> Self {
        Self {
            rows: vec![],
            bytes: 0,
            seen: BTreeSet::new(),
            latest: BTreeMap::new(),
        }
    }
    pub(in crate::sync::central) fn push_retained(
        &mut self,
        identity: Identity,
        data: Data,
    ) -> Result<(), AppError> {
        self.append(identity, data, false)
    }
    /// Preserve an explicitly verified selected value after historical occurrences of that value.
    pub(in crate::sync::central) fn push_selected(
        &mut self,
        identity: Identity,
        data: Data,
    ) -> Result<(), AppError> {
        self.append(identity, data, true)
    }
    /// Ancestor-only items remain inactive; selected library versions always come last.
    pub(in crate::sync::central) fn with_retained(
        self,
        histories: Vec<Self>,
    ) -> Result<Self, AppError> {
        if histories.is_empty() {
            return Ok(self);
        }
        let desired: BTreeSet<_> = self.rows.iter().map(|(id, _)| identity_key(id)).collect();
        let mut result = Self {
            rows: vec![],
            bytes: 0,
            seen: BTreeSet::new(),
            latest: BTreeMap::new(),
        };
        let mut closing = BTreeMap::new();
        for history in histories {
            for (id, data) in history.rows {
                let key = identity_key(&id);
                if !desired.contains(&key) {
                    closing.insert(key, id.clone());
                }
                result.append(id, data, false)?;
            }
        }
        for id in closing.into_values() {
            result.append(id, Data::Deleted, true)?;
        }
        for (id, data) in self.rows {
            result.append(id, data, true)?;
        }
        Ok(result)
    }
    pub(in crate::sync::central) fn rows(&self) -> &[(Identity, Data)] {
        &self.rows
    }
    pub fn into_rows(self) -> Vec<(Identity, Data)> {
        self.rows
    }
    fn append(&mut self, id: Identity, data: Data, force: bool) -> Result<(), AppError> {
        let bytes = payload::encode(&id, &data)?;
        let key = (identity_key(&id), crypto::hash(&bytes));
        if self.latest.get(&key.0) == Some(&key.1) || !force && self.seen.contains(&key) {
            return Ok(());
        }
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(invalid)?;
        if self.rows.len() >= 16384 || self.bytes > 32 * 1024 * 1024 - 256 * 1024 {
            return Err(invalid());
        }
        self.latest.insert(key.0.clone(), key.1.clone());
        self.seen.insert(key);
        self.rows.push((id, data));
        Ok(())
    }
}
fn identity_key(id: &Identity) -> String {
    let scope = match &id.scope {
        None => "account".into(),
        Some(HostScope::Local) => "local".into(),
        Some(HostScope::Space { space_id }) => format!("space:{space_id}"),
    };
    format!("{}:{scope}:{}", id.kind, id.id)
}
fn failure() -> AppError {
    AppError::Other("Complete legacy conversion, missing collection recovery and source conflict resolution before preparing this structured library. Every original source is retained.".into())
}
fn scope(value: &Scope) -> Result<HostScope, AppError> {
    match value {
        Scope::Local => Ok(HostScope::Local),
        Scope::Space(id) => Ok(HostScope::Space {
            space_id: id.clone(),
        }),
        _ => Err(invalid()),
    }
}
fn logical(row: &KnownInput) -> Result<Identity, AppError> {
    Ok(Identity {
        kind: row.kind.clone(),
        id: row.id.clone(),
        scope: if matches!(row.kind.as_str(), "host" | "group") {
            Some(scope(&row.location.scope)?)
        } else {
            None
        },
    })
}
fn current(row: &KnownInput) -> bool {
    matches!(row.location.position, Position::Current | Position::Sealed)
}
fn public(row: &KnownInput) -> Result<Option<serde_json::Value>, AppError> {
    if row.deleted {
        return Ok(Some(serde_json::Value::Null));
    }
    let value = match &row.data {
        KnownData::Host(value) => serde_json::to_value(value).map_err(|_| invalid())?,
        KnownData::Group(value) => serde_json::to_value(value).map_err(|_| invalid())?,
        KnownData::Keyslot(value) => serde_json::to_value(value).map_err(|_| invalid())?,
        KnownData::Collection(value) => {
            serde_json::json!({"schema":value.schema,"name":value.name,"slug":value.slug,"created_at_ms":value.created_at_ms,"previous_id":value.previous_id})
        }
        KnownData::Navigation(value) => serde_json::to_value(value).map_err(|_| invalid())?,
        KnownData::LegacyHost(_) | KnownData::LegacySlot(_) => return Err(failure()),
        _ => return Ok(None),
    };
    Ok(Some(value))
}
fn canonical(record: &Record) -> Result<serde_json::Value, AppError> {
    if record.deleted {
        return Ok(serde_json::Value::Null);
    }
    fn value<T: serde::de::DeserializeOwned + serde::Serialize>(
        raw: &serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        serde_json::to_value(serde_json::from_value::<T>(raw.clone()).map_err(|_| invalid())?)
            .map_err(|_| invalid())
    }
    match record.kind {
        RecordKind::Host => value::<records_v3::HostPayload>(&record.payload),
        RecordKind::Group => value::<records_v3::GroupPayload>(&record.payload),
        RecordKind::KeySlot => value::<records_v3::KeySlotPayload>(&record.payload),
        RecordKind::Space => value::<crate::sync::record::SpacePayload>(&record.payload),
        RecordKind::Meta if record.id == crate::sync::group_order::RECORD_ID => {
            value::<crate::sync::group_order::GroupOrder>(&record.payload)
        }
        _ => Err(invalid()),
    }
}
fn supported_public(row: &KnownInput) -> bool {
    matches!(row.kind.as_str(), "host" | "group" | "keyslot" | "space")
        || row.kind == "meta" && row.id == crate::sync::group_order::RECORD_ID
}
fn normalized(
    state: &SyncStateV3,
    known: &Known,
    active: &BTreeMap<String, SharedKeyslot>,
) -> Result<SyncStateV3, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    if known
        .rows()
        .iter()
        .any(|row| row.location.position == Position::Frozen)
        || state.local.central_projection.is_some()
        || state
            .local
            .central
            .as_ref()
            .is_some_and(|owner| owner.control.cutover)
        || state
            .account
            .as_ref()
            .is_some_and(|a| !a.recovery.conflicts.is_empty())
        || state
            .spaces
            .values()
            .any(|s| s.missing || !s.recovery.conflicts.is_empty())
    {
        return Err(failure());
    }
    let mut next = state.clone();
    if next.account.is_none() {
        let vault = next
            .local
            .central
            .as_ref()
            .and_then(|o| o.control.personal_vault.as_deref())
            .ok_or_else(invalid)?;
        next.account = Some(AccountState::new(vault));
    }
    for row in known.rows() {
        if matches!(
            &row.data,
            KnownData::LegacyHost(_) | KnownData::LegacySlot(_)
        ) {
            return Err(failure());
        }
        if !current(row) || !supported_public(row) {
            continue;
        }
        let value = public(row)?.ok_or_else(invalid)?;
        let kind = RecordKind::parse(&row.kind).ok_or_else(invalid)?;
        let records = match &row.location.scope {
            Scope::Local => match kind {
                RecordKind::Host => &mut next.local.hosts,
                RecordKind::Group => &mut next.local.groups,
                _ => return Err(invalid()),
            },
            Scope::Account(_) => &mut next.account.as_mut().ok_or_else(invalid)?.records,
            Scope::Space(id) => &mut next.spaces.get_mut(id).ok_or_else(invalid)?.records,
        };
        let key = record_key(kind, &row.id);
        if let Some(existing) = records.get_mut(&key) {
            if existing.record.deleted != row.deleted || canonical(&existing.record)? != value {
                return Err(failure());
            }
            existing.record.payload = value;
        } else {
            records.insert(
                key,
                LocalRecord {
                    record: Record {
                        kind,
                        id: row.id.clone(),
                        version: row.version,
                        updated_at_ms: row.updated_at_ms,
                        device_id: row.device_id.clone(),
                        deleted: row.deleted,
                        payload: value,
                    },
                    seq: row.sequence,
                    dirty: row.dirty,
                },
            );
        }
    }
    let account = next.account.as_mut().ok_or_else(invalid)?;
    // These known legacy system records remain exact archived source facts, never central control.
    account.records.retain(|_, row| {
        !matches!(
            row.record.kind,
            RecordKind::Device | RecordKind::SpaceKey | RecordKind::Key | RecordKind::Password
        ) && !(row.record.kind == RecordKind::Meta
            && row
                .record
                .id
                .starts_with(crate::sync::record::ROTATION_META_PREFIX))
    });
    account.sealed.clear();
    account.chain_deletes.clear();
    for space in next.spaces.values_mut() {
        space.sealed.clear();
    }
    for (id, slot) in active {
        let key = record_key(RecordKind::KeySlot, id);
        if !account.records.contains_key(&key) {
            account.records.insert(
                key,
                LocalRecord {
                    record: Record {
                        kind: RecordKind::KeySlot,
                        id: id.clone(),
                        version: 1,
                        updated_at_ms: slot.public.created_at_ms,
                        device_id: slot.public.origin_device_id.clone(),
                        deleted: false,
                        payload: serde_json::to_value(&slot.public).map_err(|_| invalid())?,
                    },
                    seq: 0,
                    dirty: false,
                },
            );
        }
    }
    Ok(next)
}
fn catalog_id() -> Identity {
    Identity {
        kind: "meta".into(),
        id: "catalog".into(),
        scope: None,
    }
}
fn key_id(kind: &str, id: &str) -> Identity {
    Identity {
        kind: kind.into(),
        id: id.into(),
        scope: None,
    }
}
fn historical_key(
    history: &mut History,
    row: &KnownInput,
    slot: &records_v3::KeySlotPayload,
    pool: &[(Identity, Data)],
    active: &BTreeMap<String, SharedKeyslot>,
) -> Result<(), AppError> {
    let mut matched = BTreeSet::new();
    for (_, data) in pool {
        let Data::Key(private) = data else {
            continue;
        };
        if private.fingerprint != slot.fingerprint {
            continue;
        }
        let storage = KeyStorage::Managed {
            sha256: private.digest(),
        };
        let public = SharedKeyslot {
            public: slot.clone(),
            storage,
        };
        if private.validate_against(&row.id, &public).is_err() || !matched.insert(private.digest())
        {
            continue;
        }
        history.append(key_id("keyslot", &row.id), Data::Keyslot(public), false)?;
        history.append(
            key_id("key", &row.id),
            Data::Key(PrivateMaterial::new(Zeroizing::new(
                private.private().into(),
            ))?),
            false,
        )?;
    }
    if matched.is_empty() {
        let reference = active
            .get(&row.id)
            .filter(|known| {
                !matches!(known.storage, KeyStorage::Managed { .. })
                    && known.public.fingerprint == slot.fingerprint
                    && known.public.key_type == slot.key_type
                    && known.public.has_passphrase == slot.has_passphrase
            })
            .ok_or_else(failure)?;
        history.append(
            key_id("keyslot", &row.id),
            Data::Keyslot(SharedKeyslot {
                public: slot.clone(),
                storage: reference.storage.clone(),
            }),
            false,
        )?;
    }
    if row.deleted {
        history.append(key_id("keyslot", &row.id), Data::Deleted, false)?;
    }
    Ok(())
}
fn navigation(catalog: &Catalog, row: &KnownInput, ids: Vec<String>) -> Result<Catalog, AppError> {
    let order_scope = if matches!(row.location.scope, Scope::Account(_)) {
        HostScope::Local
    } else {
        scope(&row.location.scope)?
    };
    let mut version = catalog.clone();
    if let HostScope::Space { space_id } = &order_scope {
        if !version.collections.iter().any(|c| &c.id == space_id) {
            return Err(failure());
        }
    }
    version.group_orders.retain(|o| o.scope != order_scope);
    version.group_orders.push(GroupOrder {
        scope: order_scope,
        ids,
    });
    Ok(version)
}
pub(super) fn prepare(
    state: &SyncStateV3,
    known: &Known,
    materials: Materials,
) -> Result<History, AppError> {
    let active = materials.active.clone();
    let storage = materials.storage.clone();
    let next = normalized(state, known, &active)?;
    let empty = Catalog {
        collections: vec![],
        group_orders: vec![GroupOrder {
            scope: HostScope::Local,
            ids: vec![],
        }],
    };
    let public = super::projection_local::public_rows(&next, &empty, &storage)?;
    let catalog = public
        .iter()
        .find_map(|(_, value)| match value {
            Data::Catalog(value) => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(invalid)?;
    let material_rows = materials.into_history();
    let mut current_private = BTreeMap::new();
    for (id, slot) in &active {
        if storage.get(id) != Some(&slot.storage)
            || !public.iter().any(|(identity, value)| {
                identity.kind == "keyslot"
                    && identity.id == *id
                    && matches!(value, Data::Keyslot(current) if current == slot)
            })
        {
            return Err(failure());
        }
        if matches!(slot.storage, KeyStorage::Managed { .. }) {
            let private = material_rows
                .iter()
                .rev()
                .find_map(|(identity, value)| match value {
                    Data::Key(private)
                        if identity.id == *id && private.validate_against(id, slot).is_ok() => Some(private),
                    _ => None,
                })
                .ok_or_else(invalid)?;
            private.validate_against(id, slot)?;
            current_private.insert(
                id.clone(),
                PrivateMaterial::new(Zeroizing::new(private.private().into()))?,
            );
        }
    }
    let mut history = History {
        rows: vec![],
        bytes: 0,
        seen: BTreeSet::new(),
        latest: BTreeMap::new(),
    };
    history.append(catalog_id(), Data::Catalog(catalog.clone()), true)?;
    for row in known
        .rows()
        .iter()
        .filter(|row| !current(row) || row.deleted)
    {
        match &row.data {
            KnownData::Host(value) => {
                history.append(logical(row)?, Data::Host(value.clone()), false)?;
                if row.deleted {
                    history.append(logical(row)?, Data::Deleted, false)?;
                }
            }
            KnownData::Group(value) => {
                history.append(logical(row)?, Data::Group(value.clone()), false)?;
                if row.deleted {
                    history.append(logical(row)?, Data::Deleted, false)?;
                }
            }
            KnownData::Keyslot(value) => {
                historical_key(&mut history, row, value, &material_rows, &active)?
            }
            KnownData::Deleted if matches!(row.kind.as_str(), "host" | "group" | "keyslot") => {
                history.append(logical(row)?, Data::Deleted, false)?
            }
            KnownData::Collection(value) => {
                let mut version = catalog.clone();
                version.collections.retain(|c| c.id != row.id);
                version
                    .group_orders
                    .retain(|o| !matches!(&o.scope,HostScope::Space{space_id}if space_id==&row.id));
                if !row.deleted {
                    version.collections.push(Collection {
                        id: row.id.clone(),
                        name: value.name.clone(),
                    });
                }
                history.append(catalog_id(), Data::Catalog(version), false)?;
            }
            KnownData::Navigation(value) => {
                let version = navigation(
                    &catalog,
                    row,
                    if row.deleted {
                        vec![]
                    } else {
                        value.ids.clone()
                    },
                )?;
                history.append(catalog_id(), Data::Catalog(version), false)?;
            }
            KnownData::Deleted if row.kind == "space" => {
                let mut version = catalog.clone();
                version.collections.retain(|c| c.id != row.id);
                version
                    .group_orders
                    .retain(|o| !matches!(&o.scope,HostScope::Space{space_id}if space_id==&row.id));
                history.append(catalog_id(), Data::Catalog(version), false)?;
            }
            KnownData::Deleted
                if row.kind == "meta" && row.id == crate::sync::group_order::RECORD_ID =>
            {
                history.append(
                    catalog_id(),
                    Data::Catalog(navigation(&catalog, row, vec![])?),
                    false,
                )?;
            }
            _ => {} // All remaining known system/credential facts stay in the independent source archive.
        }
    }
    // Retained material is already inactive where required. Current library always comes last.
    for (id, value) in material_rows {
        history.append(id, value, false)?;
    }
    // Retaining an old version must not manufacture a live item absent from the current library.
    let desired: BTreeSet<_> = public
        .iter()
        .map(|(id, _)| identity_key(id))
        .chain(
            current_private
                .keys()
                .map(|id| identity_key(&key_id("key", id))),
        )
        .collect();
    let closing: BTreeMap<_, _> = history
        .rows
        .iter()
        .filter_map(|(id, _)| {
            let key = identity_key(id);
            (!desired.contains(&key)).then(|| (key, id.clone()))
        })
        .collect();
    for id in closing.into_values() {
        history.append(id, Data::Deleted, true)?;
    }
    for (id, value) in public {
        history.append(id, value, true)?;
    }
    for (id, private) in current_private {
        history.append(key_id("key", &id), Data::Key(private), true)?;
    }
    Ok(history)
}
#[cfg(test)]
mod tests;
