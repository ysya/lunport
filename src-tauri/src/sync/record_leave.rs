//! The leave plan a chain-era `pending_account` can still carry (decoded from an old state file) and its validation.
use crate::error::AppError;
use crate::sync::{
    record::{record_key, LocalRecord, RecordKind},
    records_v3::{self, HostScope, SpaceStateV3, TypedRecord},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRemap {
    pub source_space_id: String,
    pub source_host_id: String,
    pub local_host_id: String,
    pub alias: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedHost {
    pub mapping: HostRemap,
    pub local: LocalRecord,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeavePlan {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<PlannedGroup>,
    pub source_spaces: BTreeMap<String, SpaceStateV3>,
    pub hosts: Vec<PlannedHost>,
    pub passwords_copied: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedGroup {
    pub source_space_id: String,
    pub source_group_id: String,
    pub local_group_id: String,
    pub local: LocalRecord,
}
fn error(s: &str) -> AppError {
    AppError::Other(s.into())
}
fn remapped_group_name(name: &str, id: &str) -> String {
    format!("{}-{id}", name.chars().take(111).collect::<String>())
}
pub fn validate_plan(plan: &LeavePlan) -> Result<(), AppError> {
    let mut ids = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for (id, space) in &plan.source_spaces {
        if !crate::sync::crypto::is_chain_id(id) || !space.selected || space.missing {
            return Err(error("invalid leave source space"));
        }
        for (key, row) in &space.records {
            if *key != record_key(row.record.kind, &row.record.id)
                || !matches!(row.record.kind, RecordKind::Host | RecordKind::Group)
            {
                return Err(error("invalid leave source row"));
            }
            if row.record.kind == RecordKind::Group {
                records_v3::decode_group(
                    &row.record,
                    HostScope::Space {
                        space_id: id.clone(),
                    },
                )
                .map_err(|_| error("invalid leave source group"))?;
                continue;
            }
            records_v3::decode_host(
                &row.record,
                HostScope::Space {
                    space_id: id.clone(),
                },
            )
            .map_err(|_| error("invalid leave source host"))?;
        }
    }
    let remap: BTreeMap<_, _> = plan
        .hosts
        .iter()
        .map(|h| {
            (
                h.mapping.source_host_id.as_str(),
                h.mapping.local_host_id.as_str(),
            )
        })
        .collect();
    let group_remap: BTreeMap<_, _> = plan
        .groups
        .iter()
        .map(|g| (g.source_group_id.as_str(), g.local_group_id.as_str()))
        .collect();
    for host in &plan.hosts {
        let m = &host.mapping;
        if !records_v3::is_host_id(&m.local_host_id)
            || !ids.insert(&m.local_host_id)
            || !sources.insert((&m.source_space_id, &m.source_host_id))
        {
            return Err(error("invalid leave mapping identity"));
        }
        let source = plan
            .source_spaces
            .get(&m.source_space_id)
            .and_then(|s| {
                s.records
                    .get(&record_key(RecordKind::Host, &m.source_host_id))
            })
            .filter(|r| !r.record.deleted)
            .ok_or_else(|| error("leave mapping has no source"))?;
        let TypedRecord::Live(local) =
            records_v3::decode_host(&host.local.record, HostScope::Local)
                .map_err(|_| error("invalid planned local host"))?
        else {
            return Err(error("leave plan cannot copy a tombstone"));
        };
        let TypedRecord::Live(mut expected) =
            records_v3::decode_host(&source.record, HostScope::Local)
                .map_err(|_| error("invalid leave source host"))?
        else {
            return Err(error("leave source is deleted"));
        };
        if m.alias != expected.payload.alias
            && m.alias != format!("{}-{}", expected.payload.alias, m.local_host_id)
        {
            return Err(error("leave alias is not a stable source remap"));
        }
        expected.payload.alias = m.alias.clone();
        if let Some(id) = &mut expected.payload.group_id {
            *id = group_remap
                .get(id.as_str())
                .ok_or_else(|| error("missing preserved group"))?
                .to_string();
        }
        for jump in &mut expected.payload.jump {
            if let Some(target) = remap.get(jump.as_str()) {
                *jump = (*target).to_string();
            }
        }
        if local.payload != expected.payload {
            return Err(error("leave plan does not preserve its source host"));
        }
        if local.id != m.local_host_id
            || local.payload.alias != m.alias
            || host.local.seq != 0
            || host.local.dirty
            || source.record.id != m.source_host_id
        {
            return Err(error("inconsistent leave mapping"));
        }
    }
    for g in &plan.groups {
        if !ids.insert(&g.local_group_id)
            || !sources.insert((&g.source_space_id, &g.source_group_id))
        {
            return Err(error("duplicate preserved group identity"));
        }
        let source = plan
            .source_spaces
            .get(&g.source_space_id)
            .and_then(|s| {
                s.records
                    .get(&record_key(RecordKind::Group, &g.source_group_id))
            })
            .ok_or_else(|| error("group source missing"))?;
        let TypedRecord::Live(mut expected) =
            records_v3::decode_group(&source.record, HostScope::Local)
                .map_err(|_| error("invalid group source"))?
        else {
            return Err(error("deleted group source"));
        };
        let TypedRecord::Live(local) = records_v3::decode_group(&g.local.record, HostScope::Local)
            .map_err(|_| error("invalid preserved group"))?
        else {
            return Err(error("deleted preserved group"));
        };
        if let Some(parent) = &mut expected.payload.parent_id {
            *parent = group_remap
                .get(parent.as_str())
                .ok_or_else(|| error("missing preserved parent"))?
                .to_string();
        }
        if let Some(jumps) = &mut expected.payload.defaults.jump {
            for jump in jumps {
                if let Some(target) = remap.get(jump.as_str()) {
                    *jump = target.to_string();
                }
            }
        }
        if local.payload.name != expected.payload.name
            && local.payload.name != remapped_group_name(&expected.payload.name, &g.local_group_id)
        {
            return Err(error("group name is not a stable remap"));
        }
        expected.payload.name = local.payload.name.clone();
        if local.id != g.local_group_id
            || local.payload != expected.payload
            || g.local.seq != 0
            || g.local.dirty
        {
            return Err(error("group preservation mismatch"));
        }
    }
    if plan
        .passwords_copied
        .iter()
        .any(|id| !plan.hosts.iter().any(|h| &h.mapping.local_host_id == id))
    {
        return Err(error("invalid leave credential receipt"));
    }
    if plan
        .source_spaces
        .values()
        .map(|s| s.records.values().filter(|r| !r.record.deleted).count())
        .sum::<usize>()
        != plan.hosts.len() + plan.groups.len()
    {
        return Err(error("incomplete leave plan"));
    }
    Ok(())
}
