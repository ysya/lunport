//! Navigation metadata is independent of Group payloads and connection inheritance.
//! Older sync clients retain the unsupported account Meta envelope and keep name sorting.
use crate::sync::{
    record::{record_key, LocalRecord, Record, RecordKind},
    record_repository::{self as repo, RecordRevision, RepositoryError},
    records_v3::{account_writes_blocked, is_host_id, SyncStateV3, NAVIGATION_STATE_VERSION},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const RECORD_ID: &str = "library-group-order";
const MAX_GROUPS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupOrder {
    pub schema: u32,
    pub ids: Vec<String>,
}

pub fn valid_ids(ids: &[String]) -> bool {
    ids.len() <= MAX_GROUPS
        && ids.iter().all(|id| is_host_id(id))
        && ids.iter().collect::<BTreeSet<_>>().len() == ids.len()
}

pub fn decode(record: &Record) -> Option<GroupOrder> {
    if record.kind != RecordKind::Meta
        || record.id != RECORD_ID
        || record.version == 0
        || !crate::sync::slot_rules::is_slot_id(&record.device_id)
    {
        return None;
    }
    if record.deleted {
        return record.payload.is_null().then(|| GroupOrder {
            schema: 1,
            ids: vec![],
        });
    }
    let payload: GroupOrder = serde_json::from_value(record.payload.clone()).ok()?;
    (payload.schema == 1 && valid_ids(&payload.ids)).then_some(payload)
}

pub struct OrderView {
    pub ids: Vec<String>,
    pub revision: Option<RecordRevision>,
    pub blocked: bool,
}

/// Typed navigation caches and authenticated hints also need the newer local decoder.
pub fn has_navigation_data(state: &SyncStateV3) -> bool {
    !state.local.group_order.is_empty()
        || state.account.as_ref().is_some_and(|account| {
            account
                .records
                .contains_key(&record_key(RecordKind::Meta, RECORD_ID))
                || account.sealed.values().any(|row| {
                    row.envelope.kind == "meta"
                        && row
                            .public_identity
                            .as_ref()
                            .is_some_and(|hint| hint.id == RECORD_ID)
                })
        })
}

/// A ciphertext without an authenticated header must not be overwritten by a cached edit.
/// Use already-loaded account keys only; an unrelated legacy Meta envelope is harmless.
pub fn blocked_by_opaque(
    state: &SyncStateV3,
    keys: Option<&crate::sync::crypto::ChainKeys>,
) -> bool {
    let Some(account) = &state.account else {
        return false;
    };
    let opaque: Vec<_> = account
        .sealed
        .values()
        .filter(|r| r.envelope.kind == "meta" && r.public_identity.is_none())
        .collect();
    if opaque.is_empty() {
        return false;
    }
    let Some(keys) = keys.filter(|keys| keys.chain_id == account.chain_id) else {
        return true;
    };
    let hash = crate::sync::crypto::id_hash(keys, "meta", RECORD_ID);
    opaque.iter().any(|r| r.envelope.id_hash == hash)
}

pub fn view(state: &SyncStateV3) -> OrderView {
    let Some(account) = &state.account else {
        return OrderView {
            ids: state.local.group_order.clone(),
            revision: None,
            blocked: false,
        };
    };
    let row = account
        .records
        .get(&record_key(RecordKind::Meta, RECORD_ID));
    let shadowed = account
        .sealed
        .values()
        .any(|opaque| repo::opaque_shadows(opaque, row, RecordKind::Meta, RECORD_ID));
    OrderView {
        ids: if shadowed {
            vec![]
        } else {
            row.and_then(|r| decode(&r.record))
                .map(|p| p.ids)
                .unwrap_or_else(|| state.local.group_order.clone())
        },
        revision: row.map(|r| repo::revision(&r.record)),
        blocked: shadowed || account_writes_blocked(state),
    }
}

/// Hidden/unselected groups retain their positions. Only existing or already-known IDs can enter.
pub fn set(
    state: &SyncStateV3,
    expected_ids: &[String],
    expected_revision: Option<&RecordRevision>,
    ids: Vec<String>,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let current = view(state);
    if current.blocked {
        return Err(RepositoryError::ReadOnlyAccount);
    }
    if current.ids != expected_ids || current.revision.as_ref() != expected_revision {
        return Err(repo::invalid(
            "group_order",
            RECORD_ID,
            "Group order changed; refresh and try again.",
        ));
    }
    if !valid_ids(&ids) {
        return Err(repo::invalid(
            "group_order",
            RECORD_ID,
            "Invalid or duplicate group identities.",
        ));
    }
    let groups = crate::sync::record_groups::list_groups(state)?;
    for id in &ids {
        if !current.ids.contains(id) && !groups.iter().any(|g| &g.group.id == id) {
            return Err(repo::invalid(
                "group_order",
                id,
                "Group is no longer available.",
            ));
        }
    }
    if ids == current.ids {
        return Ok(state.clone());
    }
    let mut next = state.clone();
    next.version = next.version.max(NAVIGATION_STATE_VERSION);
    if let Some(account) = &state.account {
        let key = record_key(RecordKind::Meta, RECORD_ID);
        let previous = account.records.get(&key);
        let mut record = repo::ordered_record(
            state,
            RECORD_ID,
            serde_json::to_value(GroupOrder { schema: 1, ids }).unwrap(),
            false,
            now,
            &previous.into_iter().map(|r| &r.record).collect::<Vec<_>>(),
        )?;
        record.kind = RecordKind::Meta;
        next.account.as_mut().unwrap().records.insert(
            key,
            LocalRecord {
                record,
                seq: previous.map_or(0, |r| r.seq),
                dirty: true,
            },
        );
    } else {
        next.local.group_order = ids;
    }
    Ok(next)
}

/// Library inclusion preserves group IDs; publish any pre-account navigation order once.
pub fn publish_local(
    state: &mut SyncStateV3,
    keys: Option<&crate::sync::crypto::ChainKeys>,
    now: u64,
) -> Result<(), RepositoryError> {
    if state.local.group_order.is_empty()
        || state.account.is_none()
        || state
            .account
            .as_ref()
            .unwrap()
            .records
            .contains_key(&record_key(RecordKind::Meta, RECORD_ID))
    {
        return Ok(());
    }
    if blocked_by_opaque(state, keys) {
        return Err(RepositoryError::ReadOnlyAccount);
    }
    if state
        .account
        .as_ref()
        .unwrap()
        .sealed
        .values()
        .any(|opaque| repo::opaque_shadows(opaque, None, RecordKind::Meta, RECORD_ID))
    {
        return Err(RepositoryError::ReadOnlyAccount);
    }
    let mut record = repo::ordered_record(
        state,
        RECORD_ID,
        serde_json::to_value(GroupOrder {
            schema: 1,
            ids: state.local.group_order.clone(),
        })
        .unwrap(),
        false,
        now,
        &[],
    )?;
    record.kind = RecordKind::Meta;
    state.account.as_mut().unwrap().records.insert(
        record_key(RecordKind::Meta, RECORD_ID),
        LocalRecord {
            record,
            seq: 0,
            dirty: true,
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests;
