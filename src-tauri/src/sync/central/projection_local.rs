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
        transports,
    },
};
use std::collections::BTreeMap;

/// The routes in the Catalog are the library's (`catalog_of`): the routes saved on this device alone never join it here. They move into
/// the library by one publish step, which makes them the library's rows first (design 2026-10-26, Existing routes move in; R64a:
/// `transports::publish_local`, run by the central dispatch before its capture).
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
                    serde_json::from_value(row.record.payload.clone())
                        .map_err(|_| invalid())?,
                ),
                RecordKind::Group => Data::Group(
                    serde_json::from_value(row.record.payload.clone())
                        .map_err(|_| invalid())?,
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
    for (id, space) in &state.spaces {
        if !space.sealed.is_empty() || space.missing {
            return Err(invalid());
        }
        let scope = HostScope::Space {
            space_id: id.clone(),
        };
        // A collection's group order is the Catalog's.
        for row in space.records.values().filter(|row| !is_group_order(row)) {
            append(row, scope.clone())?;
        }
    }
    let account = state.account.as_ref().ok_or_else(invalid)?;
    if !account.sealed.is_empty() || !account.chain_deletes.is_empty() {
        return Err(invalid());
    }
    for row in account.records.values() {
        match row.record.kind {
            // Collections, the group order, tunnels and routes are read into the Catalog by `catalog_of`.
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
            RecordKind::Meta if crate::sync::tunnel_rules::is_id(&row.record.id) => {}
            RecordKind::Meta if transports::is_id(&row.record.id) => {}
            RecordKind::Meta if row.record.id == crate::sync::record::ACCOUNT_META_ID => {}
            RecordKind::Meta if row.record.id == crate::sync::group_order::RECORD_ID => {}
            _ => return Err(invalid()),
        }
    }
    rows.push((
        Identity {
            kind: "meta".into(),
            id: "catalog".into(),
            scope: None,
        },
        Data::Catalog(catalog_of(state, original)?),
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
fn is_group_order(row: &LocalRecord) -> bool {
    row.record.kind == RecordKind::Meta && row.record.id == crate::sync::group_order::RECORD_ID
}
/// The Catalog `public_rows` publishes: the collections, group orders, tunnels and routes of this state, each in `original`'s order
/// and then new ones by id. Its routes are the account's `transport:` rows, the library's, never the routes saved on this device alone
/// (R64a), and none keeps a justification. Account rows the Catalog does not carry are skipped, those it does not know included:
/// `public_rows` is what refuses an unknown row, so a caller of `catalog_of` alone (the room check of route and tunnel saves,
/// `transports::ensure_room`, and the publish step's walk, `transports::local_routes`) learns the Catalog, not whether the state can be
/// captured.
pub(crate) fn catalog_of(state: &SyncStateV3, original: &Catalog) -> Result<Catalog, AppError> {
    let account = state.account.as_ref().ok_or_else(invalid)?;
    if !account.sealed.is_empty() || !account.chain_deletes.is_empty() {
        return Err(invalid());
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
        for row in space.records.values().filter(|row| is_group_order(row)) {
            let order = crate::sync::group_order::decode(&row.record).ok_or_else(invalid)?;
            orders.insert(scope.clone(), order.ids);
        }
    }
    let mut collections = BTreeMap::new();
    for row in account.records.values() {
        match row.record.kind {
            RecordKind::Space if !row.record.deleted => {
                let value: crate::sync::record::SpacePayload =
                    serde_json::from_value(row.record.payload.clone())
                        .map_err(|_| invalid())?;
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
            RecordKind::Meta if row.record.id == crate::sync::group_order::RECORD_ID => {
                orders.insert(
                    HostScope::Local,
                    crate::sync::group_order::decode(&row.record)
                        .ok_or_else(invalid)?
                        .ids,
                );
            }
            _ => {}
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
        if matches!(&old.scope,HostScope::Space{space_id} if !state.spaces.contains_key(space_id))
        {
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
    let mut tunnels = BTreeMap::new();
    for row in state
        .local
        .tunnel_rules
        .values()
        .chain(account.records.values().filter(|r| {
            r.record.kind == RecordKind::Meta && crate::sync::tunnel_rules::is_id(&r.record.id)
        }))
    {
        if !crate::sync::tunnel_rules::valid(&row.record) {
            return Err(invalid());
        }
        let id = row
            .record
            .id
            .strip_prefix(crate::sync::tunnel_rules::PREFIX)
            .ok_or_else(invalid)?;
        tunnels.remove(id);
        if let Some(rule) = crate::sync::tunnel_rules::decode(&row.record) {
            tunnels.insert(rule.id.clone(), rule);
        }
    }
    let mut next_tunnels = vec![];
    for old in &original.tunnels {
        if let Some(rule) = tunnels.remove(&old.id) {
            next_tunnels.push(rule);
        }
    }
    next_tunnels.extend(tunnels.into_values());
    let mut routes = BTreeMap::new();
    for row in account
        .records
        .values()
        .filter(|r| r.record.kind == RecordKind::Meta && transports::is_id(&r.record.id))
    {
        if !transports::valid(&row.record) {
            return Err(invalid());
        }
        if let Some(route) = transports::decode(&row.record) {
            routes.insert(route.host_id.clone(), transports::without_justification(route));
        }
    }
    let mut catalog = Catalog {
        tunnels: next_tunnels,
        transports: vec![],
        collections: next_collections,
        group_orders: next_orders,
    };
    for old in &original.transports {
        if let Some(route) = routes.remove(&old.host_id) {
            catalog.transports.push(route);
        }
    }
    catalog.transports.extend(routes.into_values());
    catalog.validate()?;
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        record::Record,
        state_v2::AccountState,
        transports::{HostTransport, PamCheck, TransportKind},
    };
    use serde_json::json;

    const HOST: &str = "0000000000000001";
    const OTHER: &str = "0000000000000002";
    const THIRD: &str = "0000000000000003";

    fn empty() -> Catalog {
        Catalog::default()
    }
    /// A device enrolled in central sync, with its account; `cutover` says whether its library has moved there.
    fn base_central_state(cutover: bool) -> SyncStateV3 {
        let mut state: SyncStateV3 = serde_json::from_value(json!({"version":records_v3::CENTRAL_STATE_VERSION,"device_id":"d".repeat(32),"device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap();
        let mut central = crate::sync::central::workspace::tests::enrolled();
        central.control.cutover = cutover;
        state.local.central = Some(central);
        state.account = Some(AccountState::new(&"a".repeat(64)));
        state
    }
    /// A stored record; a `null` payload makes a tombstone.
    fn row(kind: RecordKind, id: &str, payload: serde_json::Value) -> LocalRecord {
        LocalRecord {
            record: Record {
                kind,
                id: id.into(),
                version: 1,
                updated_at_ms: 1,
                device_id: "d".repeat(32),
                deleted: payload.is_null(),
                payload,
            },
            seq: 0,
            dirty: false,
        }
    }
    fn insert(records: &mut BTreeMap<String, LocalRecord>, row: LocalRecord) {
        records.insert(record_key(row.record.kind, &row.record.id), row);
    }
    /// A route as an earlier release saved it: names at their longest, the most entitlements, and the justification of its last
    /// grant request inside.
    fn route(host_id: &str) -> HostTransport {
        HostTransport {
            host_id: host_id.into(),
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
                    justification: Some("Investigate the outage".into()),
                }),
            },
        }
    }
    /// The smallest route.
    fn plain_route(host_id: &str) -> HostTransport {
        serde_json::from_value(json!({"host_id":host_id,"kind":{"type":"gcp_iap","project":"eng-dev-396409","zone":"asia-east1-b","instance":"jumpbox"}})).unwrap()
    }
    fn hosts(routes: &[HostTransport]) -> Vec<&str> {
        routes.iter().map(|route| route.host_id.as_str()).collect()
    }
    /// The library's row for a host's route, as central sync keeps it in the account: the route, or `None` once removed.
    fn library_route(state: &mut SyncStateV3, host_id: &str, route: Option<&HostTransport>) {
        let payload = route.map_or(serde_json::Value::Null, |route| json!({"schema":1,"transport":route}));
        insert(&mut state.account.as_mut().unwrap().records, row(RecordKind::Meta, &transports::wire_id(host_id), payload));
    }
    /// `state` with a host and a route for it saved on this device alone.
    fn with_host_and_local_route(mut state: SyncStateV3, host_id: &str) -> SyncStateV3 {
        let host = json!({"schema":2,"alias":format!("host-{host_id}"),"hostname":"fixture.invalid","auth":"password"});
        insert(&mut state.local.hosts, row(RecordKind::Host, host_id, host));
        transports::tests::saved_on_this_device(&state, &route(host_id))
    }

    /// R64a: a capture never takes the routes saved on this device alone, before or after the library moved to central sync: they
    /// become the library's rows by the publish step first (`transports::publish_local`), and only those rows reach the Catalog.
    #[test]
    fn a_capture_never_takes_the_routes_saved_on_this_device() {
        for cutover in [false, true] {
            let mut state = with_host_and_local_route(base_central_state(cutover), HOST);
            library_route(&mut state, OTHER, Some(&plain_route(OTHER)));
            assert_eq!(hosts(&catalog_of(&state, &empty()).unwrap().transports), [OTHER]);
            let routes = public_rows(&state, &empty(), &BTreeMap::new())
                .unwrap()
                .into_iter()
                .find_map(|(_, data)| match data {
                    Data::Catalog(catalog) => Some(catalog.transports),
                    _ => None,
                })
                .unwrap();
            assert_eq!(hosts(&routes), [OTHER], "the rows a capture publishes hold the library's route alone");
        }
    }

    #[test]
    fn the_librarys_routes_always_enter_the_catalog_in_their_published_order() {
        for cutover in [false, true] {
            let mut state = base_central_state(cutover); // no hosts at all: the library's routes are its own
            library_route(&mut state, OTHER, Some(&route(OTHER)));
            library_route(&mut state, HOST, Some(&route(HOST)));
            library_route(&mut state, THIRD, None);
            let original = Catalog { transports: vec![transports::without_justification(route(OTHER))], ..empty() };
            let routes = catalog_of(&state, &original).unwrap().transports;
            assert_eq!(
                routes,
                [transports::without_justification(route(OTHER)), transports::without_justification(route(HOST))],
                "published order, then new routes by host id, none with a justification"
            );
        }
    }

    #[test]
    fn a_library_route_row_that_does_not_decode_refuses_the_catalog() {
        let mut state = base_central_state(true);
        library_route(&mut state, HOST, Some(&plain_route(OTHER))); // the row's id names another host
        assert!(catalog_of(&state, &empty()).is_err());
        assert!(public_rows(&state, &empty(), &BTreeMap::new()).is_err());
    }
}
