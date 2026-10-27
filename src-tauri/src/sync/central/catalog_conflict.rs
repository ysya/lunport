//! A Catalog conflict merged into this device's state (design 2026-10-27, Catalog conflicts keep both devices' changes). Pure
//! transitions; the central dispatch saves an automatic merge, and the review commits a chosen one.
use super::{
    catalog_merge::{fit, merge, Collision, Over, Side},
    crypto::{self, DeviceKeys, VaultKeys},
    payload::{self, Catalog, Data, Identity},
    projection::Receipt,
    replica::Base,
    wire::{invalid, number},
};
use crate::{error::AppError, sync::records_v3::SyncStateV3};
use std::collections::BTreeSet;

pub(super) fn catalog_identity() -> Identity {
    Identity { kind: "meta".into(), id: "catalog".into(), scope: None }
}

/// The three versions of a Catalog in conflict, opened.
pub(super) struct Versions {
    /// The Catalog's record id.
    pub opaque: String,
    /// The Catalog this device's change was made on (`projection_capture::basis_of`); `None` when it cannot be read.
    pub common: Option<Catalog>,
    /// What this device's rows hold now, as the capture would publish it: a change not yet captured is part of it.
    pub local: Catalog,
    /// The library's current Catalog.
    pub remote: Catalog,
    pub remote_base: Base,
    /// The collections the synced Catalog dropped that this device still holds something of (`projection_delta::holds_local`).
    pub keep: BTreeSet<String>,
}

fn opened(state: &SyncStateV3, keys: &VaultKeys, base: &Base) -> Result<Catalog, AppError> {
    match super::conflicts::open(state, keys, &base.version.envelope, &base.content_hash)?.data {
        Data::Catalog(catalog) => Ok(catalog),
        _ => Err(invalid()),
    }
}

/// The versions of the Catalog in conflict, or `None` when it is not.
pub(super) fn versions(state: &SyncStateV3, keys: &VaultKeys) -> Result<Option<Versions>, AppError> {
    let ledger = state.local.central_projection.as_ref().ok_or_else(invalid)?;
    let replica = state.local.central.as_ref().and_then(|owner| owner.replica.as_ref()).ok_or_else(invalid)?;
    let opaque = catalog_identity().opaque(keys)?;
    if !replica.conflicts.contains_key(&opaque) {
        return Ok(None);
    }
    let remote_base = replica.current.get(&opaque).ok_or_else(invalid)?.clone();
    let remote = opened(state, keys, &remote_base)?;
    let common = super::projection_capture::basis_of(replica, ledger, &opaque).and_then(|basis| opened(state, keys, basis).ok());
    let local = super::catalog_of(state, &ledger.catalog)?;
    let keep = local
        .collections
        .iter()
        .filter(|c| !remote.collections.iter().any(|r| r.id == c.id))
        .filter(|c| super::projection_delta::holds_local(state, ledger, replica, &c.id))
        .map(|c| c.id.clone())
        .collect();
    Ok(Some(Versions { opaque, common, local, remote, remote_base, keep }))
}

pub(super) enum Outcome {
    /// The state with the merged Catalog in this device's rows and pending draft, its conflict retired.
    Merged(Box<SyncStateV3>),
    /// Items both devices changed differently: a choice must settle them.
    Collides(Vec<Collision>),
    /// The merged Catalog does not fit in one record, even without this device's new routes.
    Over(Over),
}

/// The receipt the delta projection's reader writes rows with: the synced Catalog's version.
fn receipt_of(opaque: &str, base: &Base, remote: &Catalog) -> Result<Receipt, AppError> {
    let header = &base.version.envelope.header;
    Ok(Receipt {
        opaque: opaque.into(),
        kind: "meta".into(),
        id: "catalog".into(),
        scope: None,
        revision: number(&base.version.revision, false)?,
        sequence: number(&base.version.sequence, false)?,
        envelope_digest: base.version.digest.clone(),
        content_hash: base.content_hash.clone(),
        semantic_hash: crypto::hash(&payload::encode(&catalog_identity(), &Data::Catalog(remote.clone()))?),
        author: header.author.clone(),
        membership_head: header.membership_head.clone(),
        key_epoch: number(&header.key_epoch, false)?,
        deleted: false,
    })
}

/// Merges the Catalog in conflict (`catalog_merge::merge`, then `fit`) with `side` settling items both devices changed; without a
/// side such items are `Collides`. The merged Catalog is read into this device's rows, this device's new routes it has no room for
/// stay on this device, and the Catalog's pending draft becomes the merged Catalog as the capture builds it, written against the
/// synced version and confirmed on it, so the capture after it raises no new conflict (`conflicts::retire_conflict`).
pub(super) fn apply(
    state: &SyncStateV3,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    side: Option<Side>,
    now: u64,
) -> Result<Outcome, AppError> {
    let versions = versions(state, keys)?.ok_or_else(invalid)?;
    let merged = merge(versions.common.as_ref(), &versions.local, &versions.remote, &versions.keep, side);
    if !merged.collisions.is_empty() {
        return Ok(Outcome::Collides(merged.collisions));
    }
    let fitted = match fit(merged) {
        Ok(fitted) => fitted,
        Err(over) => return Ok(Outcome::Over(over)),
    };
    let mut next = Box::new(state.clone());
    let receipt = receipt_of(&versions.opaque, &versions.remote_base, &versions.remote)?;
    super::projection_delta::catalog(&mut next, &fitted.catalog, &receipt, now)?;
    for route in fitted.stay_local {
        *next = crate::sync::transports::keep_on_this_device(&next, route, now).map_err(|e| AppError::Other(e.to_string()))?;
    }
    let ledger = next.local.central_projection.as_ref().ok_or_else(invalid)?;
    let draft = Data::Catalog(super::catalog_of(&next, &ledger.catalog)?);
    let next = super::conflicts::retire_conflict(*next, keys, signer, &versions.opaque, Some((&catalog_identity(), &draft)), &versions.remote_base)?;
    Ok(Outcome::Merged(Box::new(next)))
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{
        catalog_merge::{
            tests::{long_route, route, tunnel},
            Collision, Over, Side,
        },
        crypto::{DeviceKeys, VaultKeys},
        payload::{catalog_fits, Catalog, Data},
        projection_delta::tests::append,
        projection_state::tests::initial,
    };
    use super::*;
    use crate::sync::{
        record::{record_key, RecordKind},
        record_repository as repo,
        records_v3::{HostScope, SyncStateV3},
        transports::{self, HostTransport},
        tunnel_rules::{self, TunnelRule},
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::collections::BTreeSet;

    const A: &str = "000000000000000a";
    const B: &str = "000000000000000b";
    const C: &str = "000000000000000c";
    const D: &str = "000000000000000d";
    /// The fixture's host.
    const H1: &str = "0000000000000001";
    const H2: &str = "0000000000000002";

    pub(in crate::sync::central) fn signer() -> DeviceKeys {
        DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap()
    }
    pub(in crate::sync::central) fn with_tunnel(state: SyncStateV3, rule: TunnelRule) -> SyncStateV3 {
        let id = rule.id.clone();
        tunnel_rules::set(&state, None, &id, None, Some(rule), 200).unwrap()
    }
    pub(in crate::sync::central) fn with_route(state: SyncStateV3, route: HostTransport) -> SyncStateV3 {
        let host = route.host_id.clone();
        transports::set(&state, &host, None, Some(route), 200).unwrap()
    }
    fn with_host(state: SyncStateV3, id: &str) -> SyncStateV3 {
        let host = serde_json::from_value(serde_json::json!({"schema":2,"alias":format!("jump-{id}"),"hostname":"jump.invalid","auth":"password"})).unwrap();
        repo::create_host(&state, id, HostScope::Local, host, 150).unwrap()
    }
    /// This device's change (`here`, through the writers a save uses), captured; then another device's Catalog, the one this device
    /// last read changed by `there`, read by a pull: the Catalog is in conflict.
    pub(in crate::sync::central) fn conflicted(
        here: impl FnOnce(SyncStateV3) -> SyncStateV3,
        there: impl FnOnce(&mut Catalog),
    ) -> (SyncStateV3, VaultKeys, DeviceKeys) {
        let (state, keys, ledger) = initial();
        let signer = signer();
        let mut state = super::super::capture_public(&here(state), &keys, &signer).unwrap();
        let mut catalog = ledger.catalog.clone();
        there(&mut catalog);
        append(&mut state, &keys, catalog_identity(), Data::Catalog(catalog));
        let state = super::super::capture_public(&state, &keys, &signer).unwrap();
        assert!(versions(&state, &keys).unwrap().is_some(), "the Catalog is in conflict");
        (state, keys, signer)
    }
    fn merged(outcome: Outcome) -> SyncStateV3 {
        match outcome {
            Outcome::Merged(next) => *next,
            Outcome::Collides(collisions) => panic!("collides: {collisions:?}"),
            Outcome::Over(over) => panic!("over: {over:?}"),
        }
    }
    /// The Catalog this device's pending draft publishes.
    fn draft(state: &SyncStateV3, keys: &VaultKeys) -> Catalog {
        let opaque = catalog_identity().opaque(keys).unwrap();
        let pending = &state.local.central.as_ref().unwrap().replica.as_ref().unwrap().pending[&opaque];
        let admitted = super::super::conflicts::open(state, keys, &pending.latest.envelope, &pending.latest.content_hash).unwrap();
        let Data::Catalog(catalog) = admitted.data else { panic!("not a Catalog") };
        catalog
    }
    fn tunnel_ids(state: &SyncStateV3) -> BTreeSet<String> {
        tunnel_rules::view(state).into_iter().map(|row| row.rule.id).collect()
    }

    #[test]
    fn a_merge_reads_both_devices_items_into_this_devices_rows() {
        let (state, keys, signer) = conflicted(
            |state| with_route(with_tunnel(state, tunnel(B, 15433)), route(H1, "asia-east1-b")),
            |catalog| {
                catalog.tunnels.push(tunnel(C, 15434));
                catalog.transports.push(route(H2, "asia-east1-c"));
            },
        );
        let next = merged(apply(&state, &keys, &signer, None, 300).unwrap());
        assert!(tunnel_ids(&next).is_superset(&BTreeSet::from([B.to_string(), C.to_string()])));
        assert_eq!(transports::get(&next, H1), Some(route(H1, "asia-east1-b")));
        assert_eq!(transports::get(&next, H2), Some(route(H2, "asia-east1-c")));
        assert!(transports::synced(&next, H1) && transports::synced(&next, H2));
        let opaque = catalog_identity().opaque(&keys).unwrap();
        let replica = next.local.central.as_ref().unwrap().replica.as_ref().unwrap();
        assert!(!replica.conflicts.contains_key(&opaque));
        let ledger = next.local.central_projection.as_ref().unwrap();
        assert_eq!(draft(&next, &keys), super::super::catalog_of(&next, &ledger.catalog).unwrap());
        let pending = &replica.pending[&opaque];
        assert_eq!(pending.latest.envelope.header.expected_revision, replica.current[&opaque].version.revision);
        assert_eq!(pending.confirmed.as_ref(), Some(&replica.current[&opaque]));
        assert_eq!(super::super::capture_public(&next, &keys, &signer).unwrap(), next, "the capture raises no new conflict");
    }

    /// Both devices added a tunnel with one id and different ports: one item, changed differently on each side.
    fn colliding() -> (SyncStateV3, VaultKeys, DeviceKeys) {
        conflicted(|state| with_tunnel(state, tunnel(A, 15433)), |catalog| catalog.tunnels.push(tunnel(A, 15434)))
    }

    #[test]
    fn a_collision_changes_nothing_and_is_reported() {
        let (state, keys, signer) = colliding();
        match apply(&state, &keys, &signer, None, 300).unwrap() {
            Outcome::Collides(collisions) => assert_eq!(
                collisions,
                [Collision::Tunnel { id: A.into(), local: Some(tunnel(A, 15433)), remote: Some(tunnel(A, 15434)) }]
            ),
            _ => panic!("a collision merged"),
        }
    }

    #[test]
    fn an_edit_not_yet_captured_is_merged_not_overwritten() {
        let (state, keys, signer) = conflicted(|state| with_tunnel(state, tunnel(B, 15433)), |catalog| catalog.tunnels.push(tunnel(C, 15434)));
        let state = with_tunnel(state, tunnel(D, 15436));
        let next = merged(apply(&state, &keys, &signer, None, 300).unwrap());
        assert!(tunnel_ids(&next).is_superset(&BTreeSet::from([B.to_string(), C.to_string(), D.to_string()])));
        assert!(draft(&next, &keys).tunnels.iter().any(|rule| rule.id == D));
    }

    #[test]
    fn a_collection_the_other_device_removed_stays_while_this_device_has_hosts_in_it() {
        let (f, e) = ("f".repeat(64), "e".repeat(64));
        let (state, keys, signer) = conflicted(
            |state| with_tunnel(state, tunnel(B, 15433)),
            |catalog| {
                catalog.collections.clear();
                catalog.group_orders.retain(|order| order.scope == HostScope::Local);
            },
        );
        let next = merged(apply(&state, &keys, &signer, None, 300).unwrap());
        assert!(next.spaces.contains_key(&f), "the fixture's host lives in collection f");
        assert!(!next.spaces.contains_key(&e), "an empty collection goes");
        let collections: Vec<_> = draft(&next, &keys).collections.into_iter().map(|c| c.id).collect();
        assert_eq!(collections, [f]);
    }

    #[test]
    fn this_devices_routes_that_do_not_fit_stay_on_this_device() {
        let (l1, l2) = ("fffffffffffffff1", "fffffffffffffff2");
        let (_, _, ledger) = initial();
        let with = |n: usize| {
            let mut catalog = ledger.catalog.clone();
            catalog.transports = (0..n).map(|n| long_route(&format!("{n:016x}"))).collect();
            catalog
        };
        let most = (1..transports::MAX_ROUTES).take_while(|n| catalog_fits(&with(*n))).last().unwrap();
        let (state, keys, signer) = conflicted(
            |state| with_route(with_route(with_host(with_host(state, l1), l2), long_route(l1)), long_route(l2)),
            |catalog| *catalog = with(most - 1),
        );
        let next = merged(apply(&state, &keys, &signer, None, 300).unwrap());
        assert!(transports::synced(&next, l1), "the first in host-id order fits");
        assert!(!transports::synced(&next, l2));
        assert_eq!(transports::get(&next, l2), Some(long_route(l2)), "it stays usable on this device");
        assert!(next.local.transports.contains_key(&record_key(RecordKind::Meta, &transports::wire_id(l2))));
        assert!(transports::local_routes(&next).unwrap().no_room.contains(l2));
        assert!(catalog_fits(&draft(&next, &keys)));
    }

    #[test]
    fn a_catalog_over_its_room_is_not_merged() {
        let (state, keys, signer) = conflicted(
            |state| (0..10).fold(state, |state, n| with_tunnel(state, tunnel(&format!("{:016x}", 0x1000 + n), 15432))),
            |catalog| catalog.tunnels.extend((0..250).map(|n| tunnel(&format!("{n:016x}"), 15432))),
        );
        assert!(matches!(apply(&state, &keys, &signer, None, 300).unwrap(), Outcome::Over(Over::Tunnels(260))));
    }

    #[test]
    fn a_chosen_side_settles_the_collision() {
        let (state, keys, signer) = colliding();
        let port = |state: &SyncStateV3| tunnel_rules::view(state).into_iter().find(|row| row.rule.id == A).unwrap().rule.forward.port;
        assert_eq!(port(&merged(apply(&state, &keys, &signer, Some(Side::Local), 300).unwrap())), 15433);
        assert_eq!(port(&merged(apply(&state, &keys, &signer, Some(Side::Remote), 300).unwrap())), 15434);
    }
}
