//! The three-way rule of a Catalog conflict (design 2026-10-27, Catalog conflicts keep both devices' changes). Pure: no state, keys
//! or I/O; the caller reads the three versions and applies what `merge` returns.
use super::payload::{Catalog, Collection, GroupOrder};
use crate::sync::{records_v3::HostScope, transports::HostTransport, tunnel_rules::TunnelRule};
use serde::Serialize;
use std::collections::BTreeSet;

/// Whose version a reviewed choice keeps for the items both devices changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}

/// An item both devices changed from the common version, to different values: this device's (`local`) and the synced one
/// (`remote`), `None` where that side removed it or never had it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Collision {
    Tunnel { id: String, local: Option<TunnelRule>, remote: Option<TunnelRule> },
    Route { host_id: String, local: Option<HostTransport>, remote: Option<HostTransport> },
    /// A collection's name.
    Collection { id: String, local: Option<String>, remote: Option<String> },
    GroupOrder { scope: HostScope, local: Option<Vec<String>>, remote: Option<Vec<String>> },
}

#[derive(Debug)]
pub struct Merged {
    pub catalog: Catalog,
    /// Empty when `merge` was given a side, which settles each collision.
    pub collisions: Vec<Collision>,
    /// The host ids of the routes this device added: absent from the common and the synced Catalog. `fit` keeps them while they fit.
    pub new_routes: Vec<String>,
}

/// One item's value after the rule, or that both sides changed it differently.
enum Pick<'a, T> {
    Value(Option<&'a T>),
    Collides,
}

/// The rule for one item: `common` is `None` when the common version is unknown (only `t == s` merges then), else the item's value
/// in it.
fn pick<'a, T: PartialEq>(common: Option<Option<&'a T>>, t: Option<&'a T>, s: Option<&'a T>) -> Pick<'a, T> {
    if t == s {
        return Pick::Value(t);
    }
    match common {
        Some(c) if t == c => Pick::Value(s),
        Some(c) if s == c => Pick::Value(t),
        _ => Pick::Collides,
    }
}

/// The items of one list of the Catalog, merged by `key`: the synced side's in its order, then those only this device has, in its.
/// `kept` overrides the synced side's removal of an item this device still holds. A collision takes `side`'s value; without a side
/// it is recorded and keeps the synced value.
#[allow(clippy::too_many_arguments)]
fn merge_list<T: Clone + PartialEq, K: Ord + Clone>(
    common: Option<&[T]>,
    local: &[T],
    remote: &[T],
    key: impl Fn(&T) -> K,
    kept: impl Fn(&K) -> bool,
    side: Option<Side>,
    collision: impl Fn(K, Option<T>, Option<T>) -> Collision,
    collisions: &mut Vec<Collision>,
) -> Vec<T> {
    let find = |items: &'_ [T], k: &K| items.iter().find(|item| &key(item) == k).cloned();
    let mut keys: Vec<K> = remote.iter().map(&key).collect();
    for item in local {
        let k = key(item);
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    let mut merged = vec![];
    for k in keys {
        let (t, s) = (find(local, &k), find(remote, &k));
        let c = common.map(|items| find(items, &k));
        let value = if kept(&k) && s.is_none() && t.is_some() {
            t
        } else {
            match pick(c.as_ref().map(Option::as_ref), t.as_ref(), s.as_ref()) {
                Pick::Value(value) => value.cloned(),
                Pick::Collides => match side {
                    Some(Side::Local) => t,
                    Some(Side::Remote) => s,
                    None => {
                        collisions.push(collision(k, t, s.clone()));
                        s
                    }
                },
            }
        };
        merged.extend(value);
    }
    merged
}

/// Merges this device's Catalog (`local`) and the synced one (`remote`) item by item against `common`, the Catalog this device's
/// change was made on (`None` when it cannot be read: then every item the two versions hold differently collides). `keep` holds the
/// collections the synced side removed that this device still holds hosts in: they stay, with their order. Space group orders whose
/// collection is not in the result are dropped.
pub fn merge(common: Option<&Catalog>, local: &Catalog, remote: &Catalog, keep: &BTreeSet<String>, side: Option<Side>) -> Merged {
    let mut collisions = vec![];
    let collections = merge_list(
        common.map(|c| c.collections.as_slice()),
        &local.collections,
        &remote.collections,
        |c: &Collection| c.id.clone(),
        |id: &String| keep.contains(id),
        side,
        |id, local, remote| Collision::Collection { id, local: local.map(|c| c.name), remote: remote.map(|c| c.name) },
        &mut collisions,
    );
    let mut group_orders = merge_list(
        common.map(|c| c.group_orders.as_slice()),
        &local.group_orders,
        &remote.group_orders,
        |o: &GroupOrder| o.scope.clone(),
        |scope: &HostScope| matches!(scope, HostScope::Space { space_id } if keep.contains(space_id)),
        side,
        |scope, local, remote| Collision::GroupOrder { scope, local: local.map(|o| o.ids), remote: remote.map(|o| o.ids) },
        &mut collisions,
    );
    group_orders.retain(|o| match &o.scope {
        HostScope::Space { space_id } => collections.iter().any(|c| &c.id == space_id),
        HostScope::Local => true,
    });
    let tunnels = merge_list(
        common.map(|c| c.tunnels.as_slice()),
        &local.tunnels,
        &remote.tunnels,
        |t: &TunnelRule| t.id.clone(),
        |_: &String| false,
        side,
        |id, local, remote| Collision::Tunnel { id, local, remote },
        &mut collisions,
    );
    let transports = merge_list(
        common.map(|c| c.transports.as_slice()),
        &local.transports,
        &remote.transports,
        |r: &HostTransport| r.host_id.clone(),
        |_: &String| false,
        side,
        |host_id, local, remote| Collision::Route { host_id, local, remote },
        &mut collisions,
    );
    let new_routes = match common {
        Some(common) => local
            .transports
            .iter()
            .map(|r| &r.host_id)
            .filter(|host| {
                !common.transports.iter().any(|r| &r.host_id == *host) && !remote.transports.iter().any(|r| &r.host_id == *host)
            })
            .cloned()
            .collect(),
        None => vec![],
    };
    Merged { catalog: Catalog { collections, group_orders, tunnels, transports }, collisions, new_routes }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "000000000000000a";
    const B: &str = "000000000000000b";
    const C: &str = "000000000000000c";
    const D: &str = "000000000000000d";
    const E: &str = "000000000000000e";
    const H1: &str = "0000000000000101";
    const H2: &str = "0000000000000102";
    const H3: &str = "0000000000000103";
    const H4: &str = "0000000000000104";
    const H5: &str = "0000000000000105";
    const G1: &str = "00000000000000a1";
    const G2: &str = "00000000000000a2";
    const G3: &str = "00000000000000a3";

    /// A local forward named after its id, through host `0000000000000001`.
    fn tunnel(id: &str, port: u16) -> TunnelRule {
        serde_json::from_value(serde_json::json!({"id":id,"name":format!("tunnel-{id}"),"host_id":"0000000000000001","forward":{"kind":"local","bind_address":"127.0.0.1","port":port,"target_host":"db.invalid","target_port":5432}})).unwrap()
    }
    fn route(host: &str, zone: &str) -> HostTransport {
        serde_json::from_value(serde_json::json!({"host_id":host,"kind":{"type":"gcp_iap","project":"acme-dev-654321","zone":zone,"instance":"jumpbox"}})).unwrap()
    }
    fn collection(id: &str, name: &str) -> Collection {
        Collection { id: id.into(), name: name.into() }
    }
    fn order(scope: HostScope, ids: &[&str]) -> GroupOrder {
        GroupOrder { scope, ids: ids.iter().map(|id| id.to_string()).collect() }
    }
    fn space(id: &str) -> HostScope {
        HostScope::Space { space_id: id.into() }
    }
    fn ids(tunnels: &[TunnelRule]) -> Vec<&str> {
        tunnels.iter().map(|t| t.id.as_str()).collect()
    }
    fn hosts(routes: &[HostTransport]) -> Vec<&str> {
        routes.iter().map(|r| r.host_id.as_str()).collect()
    }
    fn sorted<'a>(mut values: Vec<&'a str>) -> Vec<&'a str> {
        values.sort();
        values
    }
    fn none() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn different_items_from_both_devices_all_survive() {
        let common = Catalog { tunnels: vec![tunnel(A, 15432)], transports: vec![route(H1, "asia-east1-b")], ..Catalog::default() };
        let mut local = common.clone();
        local.tunnels.push(tunnel(B, 15433));
        local.transports.push(route(H2, "asia-east1-b"));
        let mut remote = common.clone();
        remote.tunnels.push(tunnel(C, 15434));
        remote.transports.push(route(H3, "asia-east1-b"));
        let merged = merge(Some(&common), &local, &remote, &none(), None);
        assert_eq!(sorted(ids(&merged.catalog.tunnels)), [A, B, C]);
        assert_eq!(sorted(hosts(&merged.catalog.transports)), [H1, H2, H3]);
        assert!(merged.collisions.is_empty());
        assert_eq!(merged.new_routes, [H2]);
    }

    #[test]
    fn a_change_on_one_side_takes_that_change() {
        let common = Catalog { tunnels: vec![tunnel(A, 15432)], transports: vec![route(H1, "asia-east1-b")], ..Catalog::default() };
        let mut local = common.clone();
        local.transports = vec![route(H1, "asia-east1-a")];
        let mut remote = common.clone();
        remote.tunnels = vec![tunnel(A, 16000)];
        let merged = merge(Some(&common), &local, &remote, &none(), None);
        assert_eq!(merged.catalog.tunnels, [tunnel(A, 16000)], "the synced side's change");
        assert_eq!(merged.catalog.transports, [route(H1, "asia-east1-a")], "this device's change");
        assert!(merged.collisions.is_empty() && merged.new_routes.is_empty());
    }

    #[test]
    fn the_same_change_on_both_sides_does_not_collide() {
        let common = Catalog { tunnels: vec![tunnel(A, 15432)], transports: vec![route(H1, "asia-east1-b")], ..Catalog::default() };
        let mut local = common.clone();
        local.tunnels.clear();
        local.transports.push(route(H4, "asia-east1-b"));
        let remote = local.clone();
        let merged = merge(Some(&common), &local, &remote, &none(), None);
        assert!(merged.catalog.tunnels.is_empty(), "removed on both");
        assert_eq!(hosts(&merged.catalog.transports), [H1, H4], "added on both, once");
        assert!(merged.collisions.is_empty());
        assert!(merged.new_routes.is_empty(), "the synced Catalog holds it too");
    }

    /// Common, this device's and the synced Catalog, with six items both sides changed differently, and one route only this device
    /// added.
    fn colliding() -> (Catalog, Catalog, Catalog) {
        let x = "c".repeat(64);
        let common = Catalog {
            collections: vec![collection(&x, "Team")],
            group_orders: vec![order(HostScope::Local, &[G1, G2, G3])],
            tunnels: vec![tunnel(A, 15432), tunnel(E, 15500)],
            transports: vec![route(H1, "asia-east1-b")],
        };
        let mut renamed = tunnel(E, 15500);
        renamed.name = "renamed-here".into();
        let local = Catalog {
            collections: vec![collection(&x, "Work")],
            group_orders: vec![order(HostScope::Local, &[G3, G1, G2])],
            tunnels: vec![tunnel(A, 15433), renamed],
            transports: vec![route(H4, "asia-east1-a"), route(H5, "asia-east1-b")],
        };
        let remote = Catalog {
            collections: vec![collection(&x, "Clients")],
            group_orders: vec![order(HostScope::Local, &[G2, G3, G1])],
            tunnels: vec![tunnel(A, 15434), tunnel(E, 15501)],
            transports: vec![route(H1, "asia-east1-c"), route(H4, "asia-east1-c")],
        };
        (common, local, remote)
    }

    #[test]
    fn different_changes_to_one_item_collide() {
        let (common, local, remote) = colliding();
        let x = "c".repeat(64);
        let merged = merge(Some(&common), &local, &remote, &none(), None);
        let mut renamed = tunnel(E, 15500);
        renamed.name = "renamed-here".into();
        for expected in [
            Collision::Tunnel { id: A.into(), local: Some(tunnel(A, 15433)), remote: Some(tunnel(A, 15434)) },
            Collision::Tunnel { id: E.into(), local: Some(renamed), remote: Some(tunnel(E, 15501)) },
            Collision::Route { host_id: H1.into(), local: None, remote: Some(route(H1, "asia-east1-c")) },
            Collision::Route { host_id: H4.into(), local: Some(route(H4, "asia-east1-a")), remote: Some(route(H4, "asia-east1-c")) },
            Collision::Collection { id: x.clone(), local: Some("Work".into()), remote: Some("Clients".into()) },
            Collision::GroupOrder {
                scope: HostScope::Local,
                local: Some(vec![G3.into(), G1.into(), G2.into()]),
                remote: Some(vec![G2.into(), G3.into(), G1.into()]),
            },
        ] {
            assert!(merged.collisions.contains(&expected), "{expected:?} in {:?}", merged.collisions);
        }
        assert_eq!(merged.collisions.len(), 6, "an item is the smallest unit; nothing else collides");
        assert_eq!(merged.new_routes, [H5], "the route only this device added merges");
        assert!(hosts(&merged.catalog.transports).contains(&H5));
    }

    #[test]
    fn a_side_settles_every_collision() {
        let (common, local, remote) = colliding();
        let mine = merge(Some(&common), &local, &remote, &none(), Some(Side::Local));
        assert!(mine.collisions.is_empty());
        assert_eq!(mine.catalog.collections[0].name, "Work");
        assert_eq!(mine.catalog.group_orders, local.group_orders);
        assert_eq!(mine.catalog.tunnels.iter().find(|t| t.id == A), Some(&tunnel(A, 15433)));
        assert_eq!(sorted(hosts(&mine.catalog.transports)), [H4, H5], "this device removed H1");
        assert_eq!(mine.catalog.transports.iter().find(|r| r.host_id == H4), Some(&route(H4, "asia-east1-a")));
        let synced = merge(Some(&common), &local, &remote, &none(), Some(Side::Remote));
        assert!(synced.collisions.is_empty());
        assert_eq!(synced.catalog.collections[0].name, "Clients");
        assert_eq!(synced.catalog.group_orders, remote.group_orders);
        assert_eq!(synced.catalog.tunnels.iter().find(|t| t.id == A), Some(&tunnel(A, 15434)));
        assert_eq!(sorted(hosts(&synced.catalog.transports)), [H1, H4, H5], "only this device's own new route joins the synced ones");
        assert_eq!(synced.catalog.transports.iter().find(|r| r.host_id == H4), Some(&route(H4, "asia-east1-c")));
    }

    #[test]
    fn without_a_common_version_every_difference_collides() {
        let local = Catalog { tunnels: vec![tunnel(A, 15432), tunnel(B, 15433)], transports: vec![route(H1, "asia-east1-b")], ..Catalog::default() };
        let remote = Catalog { tunnels: vec![tunnel(A, 15432)], transports: vec![route(H1, "asia-east1-b")], ..Catalog::default() };
        let merged = merge(None, &local, &remote, &none(), None);
        assert_eq!(merged.collisions, [Collision::Tunnel { id: B.into(), local: Some(tunnel(B, 15433)), remote: None }]);
        assert_eq!(ids(&merged.catalog.tunnels), [A], "identical items merge; an unresolved one keeps the synced value");
        assert_eq!(hosts(&merged.catalog.transports), [H1]);
        assert!(merged.new_routes.is_empty());
    }

    #[test]
    fn a_kept_collection_stays_with_its_order() {
        let x = "c".repeat(64);
        let common = Catalog { collections: vec![collection(&x, "Team")], group_orders: vec![order(space(&x), &[G1, G2])], ..Catalog::default() };
        let local = common.clone();
        let remote = Catalog::default();
        let kept = merge(Some(&common), &local, &remote, &BTreeSet::from([x.clone()]), None);
        assert_eq!(kept.catalog.collections, [collection(&x, "Team")]);
        assert_eq!(kept.catalog.group_orders, [order(space(&x), &[G1, G2])]);
        assert!(kept.collisions.is_empty());
        let removed = merge(Some(&common), &local, &remote, &none(), None);
        assert!(removed.catalog.collections.is_empty());
        assert!(removed.catalog.group_orders.is_empty(), "a removed collection takes its order along");
    }

    #[test]
    fn the_merged_order_is_the_synced_order_then_this_devices_new_items() {
        let common = Catalog { tunnels: vec![tunnel(A, 15432)], transports: vec![route(H1, "asia-east1-b")], ..Catalog::default() };
        let local = Catalog {
            tunnels: vec![tunnel(A, 15432), tunnel(D, 15436), tunnel(B, 15433)],
            transports: vec![route(H1, "asia-east1-b"), route(H5, "asia-east1-b"), route(H2, "asia-east1-b")],
            ..Catalog::default()
        };
        let remote = Catalog {
            tunnels: vec![tunnel(C, 15434), tunnel(A, 15432)],
            transports: vec![route(H3, "asia-east1-b"), route(H1, "asia-east1-b")],
            ..Catalog::default()
        };
        let merged = merge(Some(&common), &local, &remote, &none(), None);
        assert_eq!(ids(&merged.catalog.tunnels), [C, A, D, B]);
        assert_eq!(hosts(&merged.catalog.transports), [H3, H1, H5, H2]);
        assert_eq!(merged.new_routes, [H5, H2]);
    }
}
