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
        transports::{self, HostTransport, TransportKind},
    },
};
use std::collections::BTreeMap;

/// `local_routes`: whether the routes saved on this device that the library does not hold yet join the Catalog (`catalog_of`). A
/// capture asks for them. First publication and the ledger of an initial projection do not: they describe the library as published,
/// and those routes move in afterwards, by one step (design 2026-10-26, Existing routes move in).
pub fn public_rows(
    state: &SyncStateV3,
    original: &Catalog,
    storage: &BTreeMap<String, KeyStorage>,
    local_routes: bool,
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
        Data::Catalog(catalog_of(state, original, local_routes)?),
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
/// and then new ones by id. Its routes are the account's `transport:` rows, always; then, if `local_routes` is set and this device has
/// cut over to central sync, the routes saved on this device that the library does not hold yet, in host-id order, while they fit: one
/// whose host the library lacks stays on the device, and so does every later one once one does not fit or the Catalog holds
/// `transports::MAX_ROUTES` (design 2026-10-26, Room in the Catalog). No route keeps a justification.
pub(crate) fn catalog_of(
    state: &SyncStateV3,
    original: &Catalog,
    local_routes: bool,
) -> Result<Catalog, AppError> {
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
            routes.insert(route.host_id.clone(), without_justification(route));
        }
    }
    let mut catalog = Catalog {
        tunnels: next_tunnels,
        transports: vec![],
        collections: next_collections,
        group_orders: next_orders,
    };
    if local_routes && records_v3::central_cutover(state) {
        // Each route is tried in the whole Catalog; the order of its routes does not change its size.
        let mut candidate = Catalog {
            transports: routes.values().cloned().collect(),
            ..catalog.clone()
        };
        // Keyed `meta:transport:<host id>`, so in host-id order.
        for row in state.local.transports.values() {
            if candidate.transports.len() >= transports::MAX_ROUTES {
                break;
            }
            let Some(route) = transports::decode(&row.record) else {
                continue;
            };
            if account
                .records
                .contains_key(&record_key(RecordKind::Meta, &row.record.id))
                || crate::sync::record_repository::get_host(state, &route.host_id).is_err()
            {
                continue;
            }
            let route = without_justification(route);
            candidate.transports.push(route.clone());
            if !payload::catalog_fits(&candidate) {
                break;
            }
            routes.insert(route.host_id.clone(), route);
        }
    }
    for old in &original.transports {
        if let Some(route) = routes.remove(&old.host_id) {
            catalog.transports.push(route);
        }
    }
    catalog.transports.extend(routes.into_values());
    catalog.validate()?;
    Ok(catalog)
}
/// A route as the Catalog holds it: without the justification earlier releases kept in it. The device that asked remembers that
/// (`GrantMemory`); it never syncs.
fn without_justification(mut route: HostTransport) -> HostTransport {
    let TransportKind::GcpIap { pam, .. } = &mut route.kind;
    if let Some(pam) = pam {
        pam.justification = None;
    }
    route
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{record::Record, state_v2::AccountState, transports::PamCheck};
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
    fn with_local_route_only(state: SyncStateV3, host_id: &str) -> SyncStateV3 {
        transports::set(&state, host_id, None, Some(route(host_id)), 1).unwrap()
    }
    fn with_host_and_local_route(mut state: SyncStateV3, host_id: &str) -> SyncStateV3 {
        let host = json!({"schema":2,"alias":format!("host-{host_id}"),"hostname":"fixture.invalid","auth":"password"});
        insert(&mut state.local.hosts, row(RecordKind::Host, host_id, host));
        with_local_route_only(state, host_id)
    }
    /// The state with as many library tunnels, names at their longest, as the Catalog holds: the room left is less than one more
    /// tunnel, a few hundred bytes, and `route` takes about 1.2 KB.
    fn filled_to_the_limit_with_tunnels(mut state: SyncStateV3) -> SyncStateV3 {
        let mut catalog = catalog_of(&state, &empty(), false).unwrap();
        loop {
            let rule: crate::sync::tunnel_rules::TunnelRule = serde_json::from_value(json!({"id":format!("{:016x}", 0x1000 + catalog.tunnels.len()),"name":"t".repeat(128),"host_id":HOST,
                "forward":{"kind":"local","bind_address":"127.0.0.1","port":15432,"target_host":"db.internal","target_port":5432}})).unwrap();
            catalog.tunnels.push(rule.clone());
            if !payload::catalog_fits(&catalog) {
                return state;
            }
            let id = crate::sync::tunnel_rules::wire_id(&rule.id);
            insert(&mut state.account.as_mut().unwrap().records, row(RecordKind::Meta, &id, json!({"schema":1,"rule":rule})));
        }
    }

    #[test]
    fn local_routes_enter_the_catalog_only_once_the_device_is_on_central() {
        let state = with_host_and_local_route(base_central_state(false), HOST); // cutover off
        assert!(catalog_of(&state, &empty(), true).unwrap().transports.is_empty());
        let state = with_host_and_local_route(base_central_state(true), HOST);
        let routes = catalog_of(&state, &empty(), true).unwrap().transports;
        assert_eq!(routes.iter().map(|t| t.host_id.as_str()).collect::<Vec<_>>(), [HOST]);
        assert!(routes.iter().all(|t| matches!(&t.kind, TransportKind::GcpIap { pam, .. } if pam.as_ref().is_none_or(|p| p.justification.is_none()))));
    }

    #[test]
    fn a_local_route_without_its_host_or_without_room_stays_out() {
        let state = with_local_route_only(base_central_state(true), HOST); // no such host
        assert!(catalog_of(&state, &empty(), true).unwrap().transports.is_empty());
        let state = filled_to_the_limit_with_tunnels(with_host_and_local_route(base_central_state(true), HOST));
        assert!(catalog_of(&state, &empty(), true).unwrap().transports.is_empty());
    }

    #[test]
    fn the_librarys_routes_always_enter_the_catalog_in_their_published_order() {
        for cutover in [false, true] {
            let mut state = base_central_state(cutover); // no hosts at all: the library's routes are its own
            library_route(&mut state, OTHER, Some(&route(OTHER)));
            library_route(&mut state, HOST, Some(&route(HOST)));
            library_route(&mut state, THIRD, None);
            let original = Catalog { transports: vec![without_justification(route(OTHER))], ..empty() };
            for local_routes in [false, true] {
                let routes = catalog_of(&state, &original, local_routes).unwrap().transports;
                assert_eq!(routes, [without_justification(route(OTHER)), without_justification(route(HOST))], "published order, then new routes by host id");
            }
        }
    }

    #[test]
    fn a_library_route_row_that_does_not_decode_refuses_the_catalog() {
        let mut state = base_central_state(true);
        library_route(&mut state, HOST, Some(&plain_route(OTHER))); // the row's id names another host
        assert!(catalog_of(&state, &empty(), true).is_err());
        assert!(public_rows(&state, &empty(), &BTreeMap::new(), true).is_err());
    }

    #[test]
    fn a_route_the_library_holds_or_removed_is_not_taken_from_this_device() {
        let mut state = with_host_and_local_route(with_host_and_local_route(base_central_state(true), HOST), OTHER);
        library_route(&mut state, HOST, Some(&plain_route(HOST)));
        library_route(&mut state, OTHER, None);
        assert_eq!(catalog_of(&state, &empty(), true).unwrap().transports, [plain_route(HOST)]);
    }

    #[test]
    fn local_routes_stop_at_the_most_routes_a_library_holds() {
        let mut state = with_host_and_local_route(with_host_and_local_route(base_central_state(true), HOST), OTHER);
        for n in 1..transports::MAX_ROUTES {
            let host_id = format!("{:016x}", 0x1000 + n);
            library_route(&mut state, &host_id, Some(&plain_route(&host_id)));
        }
        let routes = catalog_of(&state, &empty(), true).unwrap().transports;
        assert_eq!(routes.len(), transports::MAX_ROUTES);
        assert!(hosts(&routes).contains(&HOST) && !hosts(&routes).contains(&OTHER), "the first by host id");
        let mut more = Catalog { transports: routes, ..empty() };
        more.transports.push(without_justification(route(OTHER)));
        assert!(serde_json::to_vec(&more).unwrap().len() < super::super::wire::MAX_PLAINTEXT_BYTES, "room is not what keeps it out");
    }

    #[test]
    fn public_rows_carry_the_librarys_routes_and_this_devices_only_when_asked() {
        let mut state = with_host_and_local_route(base_central_state(true), HOST);
        library_route(&mut state, OTHER, Some(&plain_route(OTHER)));
        let routes = |local_routes| {
            let rows = public_rows(&state, &empty(), &BTreeMap::new(), local_routes).unwrap();
            rows.into_iter()
                .find_map(|(_, data)| match data {
                    Data::Catalog(catalog) => Some(catalog.transports),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(hosts(&routes(true)), [HOST, OTHER]);
        assert_eq!(hosts(&routes(false)), [OTHER], "first publication and the initial ledger leave this device's routes to a capture");
    }
}
