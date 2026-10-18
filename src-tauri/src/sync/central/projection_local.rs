//! Read exact public cache semantics, including unselected collections and dirty=false Local edits.
//! No timestamps, selection preferences, cursors or synthetic legacy slug enter a cloud payload.
use super::{
    payload::{self, Catalog, Collection, Data, GroupOrder, Identity, KeyStorage, SharedKeyslot},
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{
        record::{record_key, LocalRecord, RecordKind},
        records_v3::{self, HostScope, SyncStateV3},
    },
};
use std::collections::BTreeMap;

pub fn public_rows(
    state: &SyncStateV3,
    original: &Catalog,
    storage: &BTreeMap<String, KeyStorage>,
) -> Result<Vec<(Identity, Data)>, AppError> {
    let mut rows = vec![];
    let mut append = |row: &LocalRecord, scope: HostScope| -> Result<(), AppError> {
        let identity = Identity {
            kind: row.record.kind.as_str().into(),
            id: row.record.id.clone(),
            scope: Some(scope),
        };
        let data = if row.record.deleted {
            Data::Deleted
        } else {
            match row.record.kind {
                RecordKind::Host => Data::Host(
                    serde_json::from_value(row.record.payload.clone()).map_err(|_| invalid())?,
                ),
                RecordKind::Group => Data::Group(
                    serde_json::from_value(row.record.payload.clone()).map_err(|_| invalid())?,
                ),
                _ => return Err(invalid()),
            }
        };
        payload::encode(&identity, &data)?;
        rows.push((identity, data));
        Ok(())
    };
    for row in state
        .local
        .hosts
        .values()
        .chain(state.local.groups.values())
    {
        append(row, HostScope::Local)?;
    }
    let mut orders: BTreeMap<HostScope, Vec<String>> = original.group_orders.iter().filter(|order| matches!(&order.scope, HostScope::Space { space_id } if state.spaces.contains_key(space_id))).map(|order|(order.scope.clone(),order.ids.clone())).collect();
    orders.insert(HostScope::Local, state.local.group_order.clone());
    for (id, space) in &state.spaces {
        if !space.sealed.is_empty() || space.missing {
            return Err(invalid());
        }
        let scope = HostScope::Space {
            space_id: id.clone(),
        };
        for row in space.records.values() {
            if row.record.kind == RecordKind::Meta
                && row.record.id == crate::sync::group_order::RECORD_ID
            {
                let order = crate::sync::group_order::decode(&row.record).ok_or_else(invalid)?;
                orders.insert(scope.clone(), order.ids);
            } else {
                append(row, scope.clone())?;
            }
        }
    }
    let account = state.account.as_ref().ok_or_else(invalid)?;
    if !account.sealed.is_empty() || !account.chain_deletes.is_empty() {
        return Err(invalid());
    }
    let mut collections = BTreeMap::new();
    for row in account.records.values() {
        match row.record.kind {
            RecordKind::Space if !row.record.deleted => {
                let value: crate::sync::record::SpacePayload =
                    serde_json::from_value(row.record.payload.clone()).map_err(|_| invalid())?;
                if value.schema != 1 || !state.spaces.contains_key(&row.record.id) {
                    return Err(invalid());
                }
                collections.insert(
                    row.record.id.clone(),
                    Collection {
                        id: row.record.id.clone(),
                        name: value.name,
                    },
                );
            }
            RecordKind::Space => {}
            RecordKind::KeySlot => {
                let id = row.record.id.clone();
                let identity = Identity {
                    kind: "keyslot".into(),
                    id: id.clone(),
                    scope: None,
                };
                let data = if row.record.deleted {
                    Data::Deleted
                } else {
                    let public =
                        match records_v3::decode_keyslot(&row.record).map_err(|_| invalid())? {
                            records_v3::TypedRecord::Live(public) => public,
                            _ => return Err(invalid()),
                        };
                    // New unclassified keys require complete material inventory, never omission or guessing.
                    Data::Keyslot(SharedKeyslot {
                        public,
                        storage: storage.get(&id).ok_or_else(invalid)?.clone(),
                    })
                };
                payload::encode(&identity, &data)?;
                rows.push((identity, data));
            }
            RecordKind::Meta if row.record.id == crate::sync::record::ACCOUNT_META_ID => {}
            RecordKind::Meta if row.record.id == crate::sync::group_order::RECORD_ID => {
                orders.insert(
                    HostScope::Local,
                    crate::sync::group_order::decode(&row.record)
                        .ok_or_else(invalid)?
                        .ids,
                );
            }
            _ => return Err(invalid()),
        }
    }
    if state.spaces.keys().any(|id| !collections.contains_key(id)) {
        return Err(invalid());
    }
    // Preserve authenticated wire order for unchanged entries; append newly-created collections in
    // deterministic ID order. Compatibility slug/time/selection are deliberately irrelevant.
    let mut next_collections = vec![];
    for old in &original.collections {
        if let Some(value) = collections.remove(&old.id) {
            next_collections.push(value);
        }
    }
    next_collections.extend(collections.into_values());
    let mut next_orders = vec![];
    for old in &original.group_orders {
        if matches!(&old.scope,HostScope::Space{space_id} if !state.spaces.contains_key(space_id)) {
            continue;
        }
        next_orders.push(GroupOrder {
            scope: old.scope.clone(),
            ids: orders.remove(&old.scope).unwrap_or_default(),
        });
    }
    next_orders.extend(
        orders
            .into_iter()
            .filter(|(_, ids)| !ids.is_empty())
            .map(|(scope, ids)| GroupOrder { scope, ids }),
    );
    let catalog = Catalog {
        collections: next_collections,
        group_orders: next_orders,
    };
    catalog.validate()?;
    rows.push((
        Identity {
            kind: "meta".into(),
            id: "catalog".into(),
            scope: None,
        },
        Data::Catalog(catalog),
    ));
    // A new local-only slot is part of inventory even when no public account row exists yet.
    if state.local.keys.keys().any(|id| {
        !account
            .records
            .contains_key(&record_key(RecordKind::KeySlot, id))
    }) {
        return Err(invalid());
    }
    Ok(rows)
}
