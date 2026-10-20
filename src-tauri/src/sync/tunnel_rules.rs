//! Optional account metadata: one encrypted record per rule. Old clients retain
//! unknown Meta envelopes; no host payload or account protocol is reinterpreted.
use super::{
    crypto::ChainKeys,
    record::{record_key, LocalRecord, Record, RecordKind},
    record_repository::{self as repo, RepositoryError},
    records_v3::{self, SyncStateV3},
};
use crate::ssh::forward::ForwardSpec;
use serde::{Deserialize, Serialize};

pub const PREFIX: &str = "tunnel:";
pub const STATE_VERSION: u32 = 6;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct TunnelRule {
    pub id: String,
    pub name: String,
    pub host_id: String,
    pub forward: ForwardSpec,
}
impl TunnelRule {
    pub fn validate(&self) -> Result<(), String> {
        if !records_v3::is_host_id(&self.id) || !records_v3::is_host_id(&self.host_id) {
            return Err("Invalid tunnel or host identity.".into());
        }
        if self.name.trim().is_empty()
            || self.name.chars().count() > 128
            || self.name.chars().any(char::is_control)
        {
            return Err("Enter a tunnel name (up to 128 characters).".into());
        }
        self.forward.validate()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Payload {
    pub schema: u32,
    pub rule: TunnelRule,
}
pub fn is_id(id: &str) -> bool {
    id.strip_prefix(PREFIX).is_some_and(records_v3::is_host_id)
}
pub fn wire_id(id: &str) -> String {
    format!("{PREFIX}{id}")
}
pub fn decode(record: &Record) -> Option<TunnelRule> {
    if record.deleted || record.kind != RecordKind::Meta || !is_id(&record.id) {
        return None;
    }
    let payload: Payload = serde_json::from_value(record.payload.clone()).ok()?;
    (payload.schema == 1
        && wire_id(&payload.rule.id) == record.id
        && payload.rule.validate().is_ok())
    .then_some(payload.rule)
}
pub fn valid(record: &Record) -> bool {
    record.kind == RecordKind::Meta
        && is_id(&record.id)
        && record.version > 0
        && super::slot_rules::is_slot_id(&record.device_id)
        && if record.deleted {
            record.payload.is_null()
        } else {
            decode(record).is_some()
        }
}

#[cfg(test)]
#[path = "tunnel_rules_tests.rs"]
mod tests;
pub struct Stored {
    pub rule: TunnelRule,
    pub synced: bool,
    pub blocked: bool,
}
pub fn view(state: &SyncStateV3) -> Vec<Stored> {
    let mut rows = state.local.tunnel_rules.clone();
    if let Some(account) = &state.account {
        for (key, row) in &account.records {
            if row.record.kind == RecordKind::Meta && is_id(&row.record.id) {
                rows.insert(key.clone(), row.clone());
            }
        }
    }
    rows.values()
        .filter_map(|row| {
            let rule = decode(&row.record)?;
            let synced = state.account.as_ref().is_some_and(|account| {
                account
                    .records
                    .contains_key(&record_key(RecordKind::Meta, &row.record.id))
            });
            let blocked = state.account.as_ref().is_some_and(|account| {
                account.sealed.values().any(|opaque| {
                    repo::opaque_shadows(opaque, Some(row), RecordKind::Meta, &row.record.id)
                })
            }) || state.account.is_some()
                && records_v3::account_writes_blocked(state);
            Some(Stored {
                rule,
                synced,
                blocked,
            })
        })
        .collect()
}
pub fn blocked_by_opaque(state: &SyncStateV3, keys: Option<&ChainKeys>, id: &str) -> bool {
    let Some(account) = &state.account else {
        return false;
    };
    let row = account.records.get(&record_key(RecordKind::Meta, id));
    account.sealed.values().any(|opaque| {
        if opaque.envelope.kind != "meta" {
            return false;
        }
        if opaque.public_identity.is_some() {
            return repo::opaque_shadows(opaque, row, RecordKind::Meta, id);
        }
        keys.filter(|k| k.chain_id == account.chain_id)
            .is_none_or(|k| opaque.envelope.id_hash == super::crypto::id_hash(k, "meta", id))
    })
}
pub fn set(
    state: &SyncStateV3,
    keys: Option<&ChainKeys>,
    id: &str,
    expected: Option<&TunnelRule>,
    rule: Option<TunnelRule>,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let wire = wire_id(id);
    if !is_id(&wire) {
        return Err(repo::invalid("tunnel", id, "Invalid tunnel identity."));
    }
    if state.account.is_some() && records_v3::account_writes_blocked(state)
        || blocked_by_opaque(state, keys, &wire)
    {
        return Err(RepositoryError::ReadOnlyAccount);
    }
    let current = view(state);
    if current
        .iter()
        .find(|row| row.rule.id == id)
        .map(|row| &row.rule)
        != expected
    {
        return Err(repo::invalid(
            "tunnel",
            id,
            "This tunnel changed on another device. Refresh and try again.",
        ));
    }
    if let Some(rule) = &rule {
        rule.validate()
            .map_err(|e| repo::invalid("tunnel", id, &e))?;
        if rule.id != id {
            return Err(repo::invalid("tunnel", id, "The tunnel identity changed."));
        }
        if expected.is_none() && current.len() >= 256 {
            return Err(repo::invalid(
                "tunnel",
                id,
                "The maximum of 256 saved tunnels has been reached.",
            ));
        }
    }
    let mut next = state.clone();
    let map = state
        .account
        .as_ref()
        .map(|a| &a.records)
        .unwrap_or(&state.local.tunnel_rules);
    let key = record_key(RecordKind::Meta, &wire);
    let previous = map.get(&key);
    let payload = rule
        .as_ref()
        .map(|rule| {
            serde_json::to_value(Payload {
                schema: 1,
                rule: rule.clone(),
            })
            .unwrap()
        })
        .unwrap_or(serde_json::Value::Null);
    let mut record = repo::ordered_record(
        state,
        &wire,
        payload,
        rule.is_none(),
        now,
        &previous.into_iter().map(|r| &r.record).collect::<Vec<_>>(),
    )?;
    record.kind = RecordKind::Meta;
    let destination = next
        .account
        .as_mut()
        .map(|a| &mut a.records)
        .unwrap_or(&mut next.local.tunnel_rules);
    destination.insert(
        key,
        LocalRecord {
            record,
            seq: previous.map_or(0, |r| r.seq),
            dirty: state.account.is_some(),
        },
    );
    next.version = next.version.max(STATE_VERSION);
    Ok(next)
}
pub fn has_data(state: &SyncStateV3) -> bool {
    !state.local.tunnel_rules.is_empty()
        || state.account.as_ref().is_some_and(|a| {
            a.records
                .values()
                .any(|r| r.record.kind == RecordKind::Meta && is_id(&r.record.id))
                || a.sealed
                    .values()
                    .any(|r| r.public_identity.as_ref().is_some_and(|id| is_id(&id.id)))
        })
}
/// Joining sync retains local definitions and publishes each identity once. Unknown
/// or unreadable remote revisions remain authoritative until this client can read them.
pub fn publish_local(
    state: &mut SyncStateV3,
    keys: Option<&ChainKeys>,
    now: u64,
) -> Result<(), RepositoryError> {
    if records_v3::account_writes_blocked(state)
        || !state
            .account
            .as_ref()
            .is_some_and(|a| a.baseline_established)
        || !keys.is_some_and(|keys| {
            state
                .account
                .as_ref()
                .is_some_and(|account| keys.chain_id == account.chain_id)
        })
    {
        return Ok(());
    }
    for (key, row) in state.local.tunnel_rules.clone() {
        if row.record.deleted
            || state.account.as_ref().unwrap().records.contains_key(&key)
            || blocked_by_opaque(state, keys, &row.record.id)
        {
            continue;
        }
        let mut record = repo::ordered_record(
            state,
            &row.record.id,
            row.record.payload.clone(),
            false,
            now,
            &[&row.record],
        )?;
        record.kind = RecordKind::Meta;
        state.account.as_mut().unwrap().records.insert(
            key,
            LocalRecord {
                record,
                seq: 0,
                dirty: true,
            },
        );
    }
    Ok(())
}

/// Leaving sync preserves definitions only for hosts kept on this computer.
/// Account tombstones must also suppress an older, pre-sync local definition.
pub fn preserve_on_leave(
    before: &SyncStateV3,
    next: &mut SyncStateV3,
    host_ids: &std::collections::BTreeMap<String, String>,
    now: u64,
) -> Result<(), RepositoryError> {
    if let Some(account) = &before.account {
        for (key, row) in &account.records {
            if row.record.kind == RecordKind::Meta && is_id(&row.record.id) {
                next.local.tunnel_rules.remove(key);
            }
        }
    }
    for row in view(before) {
        // Detach intentionally blocks ordinary account writes while its journal
        // is active. Only a newer opaque rule prevents preserving this payload.
        let wire = wire_id(&row.rule.id);
        if before.account.as_ref().is_some_and(|account| {
            account.sealed.values().any(|opaque| {
                repo::opaque_shadows(
                    opaque,
                    account.records.get(&record_key(RecordKind::Meta, &wire)),
                    RecordKind::Meta,
                    &wire,
                )
            })
        }) {
            continue;
        }
        let mut rule = row.rule;
        if let Some(local_id) = host_ids.get(&rule.host_id) {
            rule.host_id = local_id.clone();
        }
        let host_key = record_key(RecordKind::Host, &rule.host_id);
        if !next
            .local
            .hosts
            .get(&host_key)
            .is_some_and(|host| !host.record.deleted)
        {
            continue;
        }
        let expected = view(next)
            .into_iter()
            .find(|r| r.rule.id == rule.id)
            .map(|r| r.rule);
        *next = set(
            next,
            None,
            &rule.id.clone(),
            expected.as_ref(),
            Some(rule),
            now,
        )?;
    }
    Ok(())
}
