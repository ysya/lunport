//! Immutable additive import. New source identities never overwrite existing remote identities.
use super::super::{
    payload::{self, Collection, Data, GroupOrder, Identity},
    projection::{self, PublicData},
    rekey::{self, Version},
    wire::{canonical, RecordHeader},
};
use super::*;
use crate::sync::{
    record::{record_key, RecordKind},
    records_v3::HostScope,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub(super) version: u32,
    pub operation: String,
    pub rows: Vec<super::super::crypto::RecordEnvelope>,
}
fn named(
    operation: &str,
    kind: &str,
    scope: Option<&HostScope>,
    id: &str,
    len: usize,
) -> Result<String, AppError> {
    let scope = serde_json::to_string(&scope).map_err(|_| invalid())?;
    Ok(super::super::crypto::hash(&canonical(&[
        "lunport-device-library-merge-id-v1",
        operation,
        kind,
        &scope,
        id,
    ])?)[..len]
        .to_owned())
}
fn scope(operation: &str, old: &HostScope) -> Result<HostScope, AppError> {
    Ok(HostScope::Space {
        space_id: named(
            operation,
            "collection",
            None,
            match old {
                HostScope::Local => "local",
                HostScope::Space { space_id } => space_id,
            },
            64,
        )?,
    })
}
/// The id this merge gives a host it imports from `old_scope`, wherever the host's id is used: its own rows, the jumps and tunnels that
/// name it, and what this device keeps by host id (`route_host_ids`).
pub(crate) fn adopted_host_id(
    operation: &str,
    old_scope: &HostScope,
    id: &str,
) -> Result<String, AppError> {
    named(operation, "host", Some(old_scope), id, 16)
}
fn group(operation: &str, old_scope: &HostScope, id: &str) -> Result<String, AppError> {
    named(operation, "group", Some(old_scope), id, 16)
}
fn key(operation: &str, id: &str) -> Result<String, AppError> {
    named(operation, "key", None, id, 32)
}
fn map_optional(
    value: &mut Option<String>,
    f: impl FnOnce(&str) -> Result<String, AppError>,
) -> Result<(), AppError> {
    if let Some(old) = value.take() {
        *value = Some(f(&old)?);
    }
    Ok(())
}
pub(super) fn inventory(
    owner: Workspace,
    keys: &VaultKeys,
) -> Result<projection::Plan, AppError> {
    if super::super::replacement_reconciliation::required(&owner) {
        projection::Plan::reconciliation_inventory(owner, keys)
    } else {
        projection::Plan::inventory(owner, keys)
    }
}
pub(super) fn current_owner(
    before: &Workspace,
    read: &super::super::active_read::VerifiedLibrary,
) -> Result<Workspace, AppError> {
    if before != read.previous_owner() || read.phase() != "ready" || read.checkpoint().sequence == 0
    {
        return Err(invalid());
    }
    let mut owner = before.clone();
    owner.control.proof = Some(read.proof().clone());
    owner.control.highwater = Some(read.chain().highwater());
    owner.control.auth_epoch = read.auth_epoch();
    owner.replica = Some(read.replica().clone());
    owner.last_epoch_acceptance = read.epoch_acceptance().cloned();
    owner.epochs = read.epochs().to_vec();
    owner.observed_epochs.clear();
    owner
        .own_wraps
        .retain(|w| w.header.key_epoch != read.checkpoint().epoch.to_string());
    owner.own_wraps.push(read.wrap().clone());
    owner.validate()?;
    Ok(owner)
}
pub(super) fn history(
    package: &super::super::source_package::Package,
    read: &super::super::active_read::VerifiedLibrary,
    operation: &str,
) -> Result<Vec<(Identity, Data)>, AppError> {
    let owner = current_owner(
        package.state.local.central.as_ref().ok_or_else(invalid)?,
        read,
    )?;
    let projected = inventory(owner, read.keys())?;
    if !projected.complete() {
        return Err(invalid());
    }
    let mut remote = projected
        .rows()
        .values()
        .find_map(|r| {
            if let PublicData::Catalog(c) = &r.data {
                Some(c.clone())
            } else {
                None
            }
        })
        .ok_or_else(invalid)?;
    let original = package
        .structured_history(read.keys(), &BTreeMap::new())?
        .into_rows();
    let owned = owned_collections(&original, operation)?;
    let owned_rules = owned_tunnels(&original, operation)?;
    let mut host_scopes: BTreeMap<String, std::collections::BTreeSet<HostScope>> =
        BTreeMap::new();
    for (id, _) in &original {
        if id.kind == "host" {
            host_scopes
                .entry(id.id.clone())
                .or_default()
                .insert(id.scope.clone().ok_or_else(invalid)?);
        }
    }
    remote.tunnels.retain(|r| !owned_rules.contains(&r.id));
    remote.collections.retain(|c| !owned.contains(&c.id));
    remote
        .group_orders
        .retain(|o| !matches!(&o.scope,HostScope::Space{space_id} if owned.contains(space_id)));
    if original.iter().all(|(id, _)| id.kind == "meta") && owned_rules.is_empty() {
        return Ok(vec![]);
    }
    let has_local = original
        .iter()
        .any(|(id, _)| id.scope == Some(HostScope::Local));
    let label = format!("Imported from {}", package.state.device_name)
        .chars()
        .take(128)
        .collect::<String>();
    let mut result = vec![];
    for (mut id, mut data) in original {
        let old_scope = id.scope.clone();
        match &mut data {
            Data::Host(value) => {
                let s = old_scope.as_ref().ok_or_else(invalid)?;
                map_optional(&mut value.group_id, |v| group(operation, s, v))?;
                map_optional(&mut value.key_id, |v| key(operation, v))?;
                value.jump = value
                    .jump
                    .iter()
                    .map(|v| adopted_host_id(operation, s, v))
                    .collect::<Result<_, _>>()?;
                // Source trust approvals are scoped to their old host identity/device.
                value.host_key = None;
            }
            Data::Group(value) => {
                let s = old_scope.as_ref().ok_or_else(invalid)?;
                map_optional(&mut value.parent_id, |v| group(operation, s, v))?;
                if let Some(auth) = &mut value.defaults.authentication {
                    map_optional(&mut auth.key_id, |v| key(operation, v))?;
                }
                if let Some(jump) = &mut value.defaults.jump {
                    *jump = jump
                        .iter()
                        .map(|v| adopted_host_id(operation, s, v))
                        .collect::<Result<_, _>>()?;
                }
            }
            Data::Catalog(value) => {
                // The library's routes stay as they are: this device brings none (R11). Its own stay on it, under the ids its
                // hosts get here (`route_host_ids`), until a capture publishes them.
                let mut merged = remote.clone();
                if has_local {
                    merged.collections.push(Collection {
                        id: match scope(operation, &HostScope::Local)? {
                            HostScope::Space { space_id } => space_id,
                            _ => unreachable!(),
                        },
                        name: label.trim().into(),
                    });
                }
                for collection in &value.collections {
                    merged.collections.push(Collection {
                        id: named(operation, "collection", None, &collection.id, 64)?,
                        name: collection.name.clone(),
                    });
                }
                for order in &value.group_orders {
                    if order.scope == HostScope::Local && !has_local {
                        continue;
                    }
                    merged.group_orders.push(GroupOrder {
                        scope: scope(operation, &order.scope)?,
                        ids: order
                            .ids
                            .iter()
                            .map(|v| group(operation, &order.scope, v))
                            .collect::<Result<_, _>>()?,
                    });
                }
                for old in &value.tunnels {
                    let mut rule = old.clone();
                    rule.id = named(operation, "tunnel", None, &old.id, 16)?;
                    rule.host_id = match host_scopes.get(&old.host_id) {
                    Some(scopes) if scopes.len() == 1 => adopted_host_id(operation, scopes.first().ok_or_else(invalid)?, &old.host_id)?,
                    Some(_) => return Err(AppError::Other("A retained tunnel has an ambiguous host identity. Original data is retained; resolve its host before merging.".into())),
                    None => named(operation, "orphan-tunnel-host", None, &old.host_id, 16)?,
                };
                    merged.tunnels.push(rule);
                }
                // The merged Catalog is published as one record (design 2026-10-26, Room in the Catalog).
                if !payload::catalog_fits(&merged) {
                    return Err(AppError::Other(crate::sync::transports::NO_ROOM.into()));
                }
                merged.validate()?;
                *value = merged;
            }
            _ => {}
        }
        match id.kind.as_str() {
            "host" | "password" => id.id = adopted_host_id(operation, old_scope.as_ref().ok_or_else(invalid)?, &id.id)?,
            "group" => {
                id.id = group(operation, old_scope.as_ref().ok_or_else(invalid)?, &id.id)?
            }
            "keyslot" | "key" => id.id = key(operation, &id.id)?,
            "meta" => {}
            _ => return Err(invalid()),
        }
        if let Some(s) = old_scope {
            id.scope = Some(scope(operation, &s)?);
        }
        payload::encode(&id, &data)?;
        result.push((id, data));
    }
    Ok(result)
}
impl Plan {
    pub fn create(
        package: &super::super::source_package::Package,
        read: &super::super::active_read::VerifiedLibrary,
        signer: &super::super::crypto::DeviceKeys,
        operation: &str,
    ) -> Result<Self, AppError> {
        let history = history(package, read, operation)?;
        let before = package.state.local.central.as_ref().ok_or_else(invalid)?;
        let owner = current_owner(before, read)?;
        let chain = owner.control.verified_chain()?;
        if signer.public() != owner.control.device.keys
            || !super::super::wire::hex(operation, 32)
            || history.len() as u64 + read.checkpoint().sequence > 16384
        {
            return Err(invalid());
        }
        let anchor = owner.control.anchor.as_ref().ok_or_else(invalid)?;
        let mut revisions = BTreeMap::new();
        let mut rows = vec![];
        let mut bytes = 0usize;
        for (id, data) in history {
            let record = id.opaque(read.keys())?;
            if id.kind != "meta" && read.replica().current.contains_key(&record) {
                return Err(invalid());
            }
            let base = revisions.entry(record.clone()).or_insert_with(|| {
                read.replica().current.get(&record).map_or(0, |b| {
                    super::super::wire::number(&b.version.revision, false).unwrap_or(u64::MAX)
                })
            });
            let plain = payload::encode(&id, &data)?;
            let envelope = super::super::crypto::seal_record(
                read.keys(),
                signer,
                RecordHeader {
                    origin: anchor.origin.clone(),
                    account_id: anchor.account_id.clone(),
                    genesis_hash: anchor.genesis_hash.clone(),
                    vault_id: read.replica().vault.clone(),
                    record_id: record,
                    key_epoch: read.checkpoint().epoch.to_string(),
                    membership_head: chain.current().head().into(),
                    author: owner.control.device.id.clone(),
                    operation_id: super::super::crypto::random_id(16)?,
                    expected_revision: base.to_string(),
                    kind: id.kind,
                    deleted: matches!(data, Data::Deleted),
                },
                &plain,
            )?;
            *base = base.checked_add(1).ok_or_else(invalid)?;
            let size = serde_json::to_vec(&envelope).map_err(|_| invalid())?.len();
            bytes = bytes.checked_add(size).ok_or_else(invalid)?;
            if size > 1024 * 1024 || bytes > 32 * 1024 * 1024 - 256 * 1024 {
                return Err(invalid());
            }
            rows.push(envelope);
        }
        let result = Self {
            version: 1,
            operation: operation.into(),
            rows,
        };
        result.verify(package, read)?;
        Ok(result)
    }
    pub fn verify(
        &self,
        package: &super::super::source_package::Package,
        read: &super::super::active_read::VerifiedLibrary,
    ) -> Result<(), AppError> {
        if self.version != 1
            || !super::super::wire::hex(&self.operation, 32)
            || self.rows.len() > 16384
        {
            return Err(invalid());
        }
        let expected = history(package, read, &self.operation)?;
        if expected.len() != self.rows.len() {
            return Err(invalid());
        }
        let mut owner = current_owner(
            package.state.local.central.as_ref().ok_or_else(invalid)?,
            read,
        )?;
        let chain = owner.control.verified_chain()?;
        let mut versions = vec![];
        let mut checkpoint = read.checkpoint().clone();
        let mut revisions = BTreeMap::new();
        let mut operations = std::collections::BTreeSet::new();
        for ((id, data), envelope) in expected.iter().zip(&self.rows) {
            let h = &envelope.header;
            let opaque = id.opaque(read.keys())?;
            if id.kind != "meta" && read.replica().current.contains_key(&opaque) {
                return Err(invalid());
            }
            let rev = revisions.entry(opaque.clone()).or_insert_with(|| {
                read.replica().current.get(&opaque).map_or(0, |r| {
                    super::super::wire::number(&r.version.revision, false).unwrap_or(u64::MAX)
                })
            });
            if h.record_id != opaque
                || h.expected_revision != rev.to_string()
                || h.author != owner.control.device.id
                || h.key_epoch != checkpoint.epoch.to_string()
                || !operations.insert(&h.operation_id)
            {
                return Err(invalid());
            }
            chain.current().verify_write(
                envelope,
                &read.replica().vault,
                checkpoint.epoch,
                &h.author,
            )?;
            let plain = envelope
                .verify(&owner.control.device.keys.signing)?
                .open(read.keys())?;
            if plain.as_slice() != payload::encode(id, data)?.as_slice() {
                return Err(invalid());
            }
            *rev = rev.checked_add(1).ok_or_else(invalid)?;
            checkpoint.sequence += 1;
            let digest = rekey::envelope_digest(envelope)?;
            checkpoint.history_hash = super::super::crypto::hash(&canonical(&[
                "lunport-history-v2",
                &checkpoint.history_hash,
                &checkpoint.sequence.to_string(),
                &digest,
            ])?);
            versions.push(Version {
                revision: rev.to_string(),
                sequence: checkpoint.sequence.to_string(),
                envelope: envelope.clone(),
                digest,
                history_hash: checkpoint.history_hash.clone(),
            });
        }
        for page in versions.chunks(32) {
            owner.replica = Some(
                owner
                    .replica
                    .as_ref()
                    .ok_or_else(invalid)?
                    .prepare_page(&chain, read.keys(), page, &checkpoint)?
                    .next,
            );
        }
        owner.validate()?;
        let projected = inventory(owner, read.keys())?;
        if !projected.complete() {
            return Err(AppError::Other("The combined library is incomplete. Original local data and the existing Vault are retained.".into()));
        }
        Ok(())
    }
}

pub(super) fn owned_tunnels(
    history: &[(Identity, Data)],
    operation: &str,
) -> Result<std::collections::BTreeSet<String>, AppError> {
    let mut owned = std::collections::BTreeSet::new();
    for (_, data) in history {
        if let Data::Catalog(catalog) = data {
            for rule in &catalog.tunnels {
                owned.insert(named(operation, "tunnel", None, &rule.id, 16)?);
            }
        }
    }
    Ok(owned)
}

pub(super) fn owned_collections(
    history: &[(Identity, Data)],
    operation: &str,
) -> Result<std::collections::BTreeSet<String>, AppError> {
    let mut owned = std::collections::BTreeSet::new();
    for (id, data) in history {
        if let Some(old) = &id.scope {
            if let HostScope::Space { space_id } = scope(operation, old)? {
                owned.insert(space_id);
            }
        }
        if let Data::Catalog(c) = data {
            for collection in &c.collections {
                owned.insert(named(operation, "collection", None, &collection.id, 64)?);
            }
        }
    }
    Ok(owned)
}
/// The ids this merge gives the hosts this device's own routes name (old → new), so that those routes, and what grant requests taught
/// this device about their hosts, follow the hosts (design 2026-10-26, Existing routes move in): they stay this device's until a
/// capture publishes them. A host id `source` holds in no scope, or in more than one, names no one host, so it keeps its id.
pub(super) fn route_host_ids(
    source: &SyncStateV3,
    operation: &str,
) -> Result<BTreeMap<String, String>, AppError> {
    let mut host_ids = BTreeMap::new();
    for row in source.local.transports.values() {
        let Some(id) = row.record.id.strip_prefix(crate::sync::transports::PREFIX) else {
            continue;
        };
        let key = record_key(RecordKind::Host, id);
        let local = source
            .local
            .hosts
            .contains_key(&key)
            .then_some(HostScope::Local);
        let spaces = source
            .spaces
            .iter()
            .filter(|(_, space)| space.records.contains_key(&key))
            .map(|(space_id, _)| HostScope::Space {
                space_id: space_id.clone(),
            });
        let mut scopes = local.into_iter().chain(spaces);
        if let (Some(scope), None) = (scopes.next(), scopes.next()) {
            host_ids.insert(id.to_owned(), adopted_host_id(operation, &scope, id)?);
        }
    }
    Ok(host_ids)
}
pub(super) fn selections(
    source: &SyncStateV3,
    operation: &str,
) -> Result<BTreeMap<String, bool>, AppError> {
    source
        .spaces
        .iter()
        .map(|(id, s)| Ok((named(operation, "collection", None, id, 64)?, s.selected)))
        .collect()
}
