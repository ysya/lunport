//! Initial public repository cache only. This is not a runtime owner or a delta merge.
//! A typed inventory/consent/archive/cutover transaction must consume it before publication.
use super::{
    payload::KeyStorage,
    projection::{Plan, PublicData, Receipt},
    wire::{invalid, MAX_SAFE_INTEGER},
};
use crate::{
    error::AppError,
    sync::{
        record::{record_key, LocalRecord, Record, RecordKind, ACCOUNT_META_ID},
        records_v3::{self, HostScope, SpaceStateV3},
        state_v2::AccountState,
    },
};
use std::collections::BTreeMap;

/// Public compatibility cache for the existing repository. No legacy keys, token, sealed secret,
/// chain delete or private material is created. The real authority remains central Workspace.
pub struct Cache {
    pub account: AccountState,
    pub spaces: BTreeMap<String, SpaceStateV3>,
    pub hosts: BTreeMap<String, LocalRecord>,
    pub groups: BTreeMap<String, LocalRecord>,
    pub group_order: Vec<String>,
    pub key_storage: BTreeMap<String, KeyStorage>,
}
pub(super) fn row(
    kind: RecordKind,
    id: &str,
    payload: serde_json::Value,
    receipt: &Receipt,
    observed: u64,
) -> LocalRecord {
    LocalRecord {
        record: Record {
            kind,
            id: id.into(),
            version: receipt.revision,
            updated_at_ms: observed,
            device_id: receipt.author.clone(),
            deleted: receipt.deleted,
            payload,
        },
        seq: receipt.sequence,
        dirty: false,
    }
}
impl Cache {
    /// Complete baseline only; never call this to overwrite a live cache that may contain local B.
    /// Selection preferences remain local, while every collection's records are retained.
    pub fn initial(
        plan: &Plan,
        observed: u64,
        selections: &BTreeMap<String, bool>,
    ) -> Result<Self, AppError> {
        let replica = plan.before().replica.as_ref().ok_or_else(invalid)?;
        if !plan.complete()
            || !replica.pending.is_empty()
            || !replica.conflicts.is_empty()
            || observed > MAX_SAFE_INTEGER
        {
            return Err(invalid());
        }
        let catalogue = plan
            .rows()
            .values()
            .find_map(|row| match &row.data {
                PublicData::Catalog(catalogue) => Some((&row.receipt, catalogue)),
                _ => None,
            })
            .ok_or_else(invalid)?;
        let (catalogue_receipt, catalogue) = catalogue;
        let mut account = AccountState::new(&replica.vault);
        account.cursor_seq = replica.checkpoint.sequence;
        account.baseline_established = true;
        account.remote_schema_version = Some(records_v3::ACCOUNT_SCHEMA);
        let meta = row(
            RecordKind::Meta,
            ACCOUNT_META_ID,
            serde_json::json!({"schema_version":records_v3::ACCOUNT_SCHEMA,"created_by_app_version":env!("CARGO_PKG_VERSION")}),
            catalogue_receipt,
            observed,
        );
        account
            .records
            .insert(record_key(RecordKind::Meta, ACCOUNT_META_ID), meta);
        let mut spaces = BTreeMap::new();
        for collection in &catalogue.collections {
            let metadata = row(
                RecordKind::Space,
                &collection.id,
                serde_json::json!({"schema":1,"name":collection.name,"slug":format!("central-{}",&collection.id[..16]),"created_at_ms":observed,"previous_id":null}),
                catalogue_receipt,
                observed,
            );
            account
                .records
                .insert(record_key(RecordKind::Space, &collection.id), metadata);
            spaces.insert(
                collection.id.clone(),
                SpaceStateV3 {
                    selected: selections.get(&collection.id).copied().unwrap_or(true),
                    cursor_seq: replica.checkpoint.sequence,
                    baseline_established: true,
                    ..Default::default()
                },
            );
        }
        let mut cache = Self {
            account,
            spaces,
            hosts: BTreeMap::new(),
            groups: BTreeMap::new(),
            group_order: vec![],
            key_storage: BTreeMap::new(),
        };
        for order in &catalogue.group_orders {
            match &order.scope {
                HostScope::Local => cache.group_order = order.ids.clone(),
                HostScope::Space { space_id } => {
                    if !cache.spaces.contains_key(space_id) {
                        return Err(invalid());
                    }
                    // Existing Records collection maps accept host/group rows only. The exact
                    // scoped order remains in the durable central ledger's authenticated catalog.
                }
            }
        }
        for projected in plan.rows().values() {
            let receipt = &projected.receipt;
            // A deleted collection has no cache namespace; keep its authenticated
            // tombstones in the ledger without recreating a collection or Local row.
            if receipt.deleted
                && matches!(projected.data, PublicData::Deleted)
                && matches!(receipt.kind.as_str(), "host" | "group")
                && matches!(&receipt.scope, Some(HostScope::Space { space_id }) if !cache.spaces.contains_key(space_id))
            {
                continue;
            }
            let (kind, payload) = match &projected.data {
                PublicData::Host(host) => (
                    RecordKind::Host,
                    serde_json::to_value(host).map_err(|_| invalid())?,
                ),
                PublicData::Group(group) => (
                    RecordKind::Group,
                    serde_json::to_value(group).map_err(|_| invalid())?,
                ),
                PublicData::Keyslot(slot) => {
                    cache
                        .key_storage
                        .insert(receipt.id.clone(), slot.storage.clone());
                    let metadata = row(
                        RecordKind::KeySlot,
                        &receipt.id,
                        serde_json::to_value(&slot.public).map_err(|_| invalid())?,
                        receipt,
                        observed,
                    );
                    cache
                        .account
                        .records
                        .insert(record_key(RecordKind::KeySlot, &receipt.id), metadata);
                    continue;
                }
                PublicData::Catalog(_) => continue,
                PublicData::Deleted => match receipt.kind.as_str() {
                    "host" => (RecordKind::Host, serde_json::Value::Null),
                    "group" => (RecordKind::Group, serde_json::Value::Null),
                    "keyslot" => {
                        cache.account.records.insert(
                            record_key(RecordKind::KeySlot, &receipt.id),
                            row(
                                RecordKind::KeySlot,
                                &receipt.id,
                                serde_json::Value::Null,
                                receipt,
                                observed,
                            ),
                        );
                        continue;
                    }
                    _ => return Err(invalid()),
                },
            };
            let metadata = row(kind, &receipt.id, payload, receipt, observed);
            let key = record_key(kind, &receipt.id);
            match receipt.scope.as_ref().ok_or_else(invalid)? {
                HostScope::Local => {
                    let destination = if kind == RecordKind::Host {
                        &mut cache.hosts
                    } else {
                        &mut cache.groups
                    };
                    if destination.insert(key, metadata).is_some() {
                        return Err(invalid());
                    }
                }
                HostScope::Space { space_id } => {
                    if cache
                        .spaces
                        .get_mut(space_id)
                        .ok_or_else(invalid)?
                        .records
                        .insert(key, metadata)
                        .is_some()
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(cache)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        payload::{Catalog, Collection, Data, GroupOrder, Identity},
        projection,
    };
    use super::*;
    #[test]
    fn complete_public_baseline_reuses_repository_shapes_and_retains_unselected_collections_without_legacy_auth(
    ) {
        let collection = "f".repeat(64);
        let group_id = "0000000000000002";
        let local = Identity {
            kind: "host".into(),
            id: "0000000000000001".into(),
            scope: Some(HostScope::Local),
        };
        let remote = Identity {
            scope: Some(HostScope::Space {
                space_id: collection.clone(),
            }),
            ..local.clone()
        };
        let host = |name: &str| {
            Data::Host(serde_json::from_value(serde_json::json!({"schema":2,"alias":name,"hostname":"fixture.invalid","auth":"password"})).unwrap())
        };
        let catalogue = Catalog {
            collections: vec![Collection {
                id: collection.clone(),
                name: "Private collection".into(),
            }],
            group_orders: vec![GroupOrder {
                scope: HostScope::Local,
                ids: vec![group_id.into()],
            }],
        };
        let group = Data::Group(
            serde_json::from_value(
                serde_json::json!({"schema":1,"name":"Personal group","defaults":{}}),
            )
            .unwrap(),
        );
        let (ws, keys) = projection::tests::fixture(vec![
            (
                Identity {
                    kind: "meta".into(),
                    id: "catalog".into(),
                    scope: None,
                },
                Data::Catalog(catalogue),
            ),
            (local, host("local")),
            (remote, host("space")),
            (
                Identity {
                    kind: "group".into(),
                    id: group_id.into(),
                    scope: Some(HostScope::Local),
                },
                group,
            ),
        ]);
        let plan = Plan::current(ws, &keys).unwrap();
        let selection = BTreeMap::from([(collection.clone(), false)]);
        let cache = Cache::initial(&plan, 1000, &selection).unwrap();
        assert_eq!(
            cache.account.chain_id,
            plan.before().replica.as_ref().unwrap().vault
        );
        assert!(cache.account.sealed.is_empty());
        assert!(cache.account.chain_deletes.is_empty());
        assert_eq!(cache.hosts.len(), 1);
        assert_eq!(cache.groups.len(), 1);
        assert_eq!(cache.spaces[&collection].records.len(), 1);
        assert!(!cache.spaces[&collection].selected);
        assert_eq!(cache.group_order, vec![group_id]);
        assert!(cache.key_storage.is_empty());
        let device = crate::sync::testkit::TestDevice::new(
            "public-cache",
            &crate::sync::fake_relay::FakeRelay::new(),
            &crate::sync::testkit::TestClock::new(),
        );
        let crate::sync::record_runtime::StartupProbe::Records { mut state, .. } =
            crate::sync::record_runtime::probe_startup(&device.env().state_path, "cache")
        else {
            panic!()
        };
        state.version = records_v3::CENTRAL_STATE_VERSION;
        state.local.central = Some(plan.before().clone());
        state.account = Some(cache.account);
        state.spaces = cache.spaces;
        state.local.hosts = cache.hosts;
        state.local.groups = cache.groups;
        state.local.group_order = cache.group_order;
        records_v3::validate_state(&state).unwrap();
        let repository = crate::sync::record_repository::snapshot(&state).unwrap();
        assert!(!repository.hosts.is_empty());
        let serialized = serde_json::to_string(&state).unwrap();
        assert!(!serialized.contains("auth_token"));
        assert!(!serialized.contains("private_key"));
        // Construction did not create active state/vault files or protected credentials.
        assert!(!device.env().state_path.exists());
        assert!(!crate::vault::store::vault_path(&device.env().state_path).exists());
    }
    #[test]
    fn incomplete_catalogue_cannot_become_a_claimed_complete_initial_cache() {
        let (ws, keys) = projection::tests::fixture(vec![]);
        let plan = Plan::current(ws, &keys).unwrap();
        assert!(Cache::initial(&plan, 1, &BTreeMap::new()).is_err());
    }
}
