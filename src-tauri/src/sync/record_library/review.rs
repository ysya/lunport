//! Explicit, snapshot-bound name resolution. Never merges or overwrites a remote identity.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize)]
pub struct LibraryFailure {
    pub code: &'static str,
    pub message: String,
}
impl LibraryFailure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
impl From<AppError> for LibraryFailure {
    fn from(_: AppError) -> Self {
        Self::new("unavailable", "Library sync could not access this workspace. Existing records have been kept. Retry when the workspace is available.")
    }
}
impl From<RepositoryError> for LibraryFailure {
    fn from(error: RepositoryError) -> Self {
        use crate::sync::records_v3::RecordValidationError;
        match error {
            RepositoryError::UpgradeConfirmationRequired => Self::new("upgrade_required", "Confirm that older clients have been updated or stopped before including Groups and inherited settings."),
            RepositoryError::Validation(RecordValidationError::AliasConflict { alias, .. }) => Self::new("name_conflict", format!("Host alias {alias:?} is already used. Review the proposed names and choose a unique alias.")),
            RepositoryError::Validation(RecordValidationError::DuplicateId(_)) => Self::new("identity_conflict", "A local record and synced record share an identity. They have been kept separately; review the conflicting records before including the library."),
            RepositoryError::SpaceUnavailable(reason) => Self::new("sync_data_unavailable", match reason.as_str() {
                "Finish downloading the library before including existing records" => "Library setup is waiting for a complete download of every selected sync space. Finish syncing, then retry. Existing records have been kept.",
                "Some synced record identities cannot be read" => "A synced host or Group has an unreadable or unsupported identity. Update Lunport on the devices in this chain and retry. Existing records and encrypted source data have been kept.",
                _ => "Some library data has not been downloaded or cannot be read. Finish syncing or update Lunport, then retry. Existing records have been kept.",
            }),
            RepositoryError::Group(_) => Self::new("group_conflict", "Group names or relationships conflict. Choose unique names under each parent and review unavailable parent Groups, then retry. Existing records have been kept."),
            _ => Self::new("record_validation", "A host or Group needs review before it can be included. Check its fields, Group and jump-host references. Existing records have been kept."),
        }
    }
}
impl From<LibraryFailure> for AppError {
    fn from(error: LibraryFailure) -> Self {
        Self::Other(error.message)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameKind {
    Host,
    Group,
}
impl NameKind {
    fn record_kind(self) -> RecordKind {
        match self {
            Self::Host => RecordKind::Host,
            Self::Group => RecordKind::Group,
        }
    }
    fn field(self) -> &'static str {
        match self {
            Self::Host => "alias",
            Self::Group => "name",
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct NameConflict {
    pub kind: NameKind,
    pub id: String,
    pub current_name: String,
    pub suggested_name: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    pub kind: NameKind,
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryReview {
    pub token: String,
    pub renames: Vec<Rename>,
}
#[derive(Clone, Debug, Serialize)]
pub struct LibraryPreview {
    pub token: String,
    pub conflicts: Vec<NameConflict>,
    pub local_hosts: usize,
    pub local_groups: usize,
}

/// Ignore transport acknowledgements and timestamps, but bind every inclusion authority.
fn token(state: &SyncStateV3, destination: &str) -> String {
    let spaces: BTreeMap<_, _> = state
        .spaces
        .iter()
        .map(|(id, space)| {
            let records: Vec<_> = space
                .records
                .values()
                .filter(|r| matches!(r.record.kind, RecordKind::Host | RecordKind::Group))
                .map(|r| &r.record)
                .collect();
            let sealed: Vec<_> = space
                .sealed
                .values()
                .filter(|r| matches!(r.envelope.kind.as_str(), "host" | "group"))
                .collect();
            (
                id,
                json!([
                    space.selected,
                    space.missing,
                    space.baseline_established,
                    records,
                    sealed
                ]),
            )
        })
        .collect();
    let local: Vec<_> = state
        .local
        .groups
        .values()
        .chain(state.local.hosts.values())
        .map(|r| &r.record)
        .collect();
    let account = state.account.as_ref().map(|a| {
        (
            &a.chain_id,
            a.records
                .get(&record_key(
                    RecordKind::Meta,
                    crate::sync::record::ACCOUNT_META_ID,
                ))
                .map(|r| &r.record),
        )
    });
    let value = json!([
        destination,
        state.device_id,
        state.version,
        account,
        local,
        spaces
    ]);
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&value).expect("public library snapshot"))
    )
}

fn conflicts(state: &SyncStateV3, destination: &str) -> Vec<NameConflict> {
    let target = &state.spaces[destination];
    let mut aliases = BTreeSet::new();
    let mut names = BTreeSet::new();
    for row in target.records.values().filter(|r| !r.record.deleted) {
        if row.record.kind == RecordKind::Host {
            if let Some(name) = row.record.payload["alias"].as_str() {
                aliases.insert(name.to_owned());
            }
        } else if row.record.kind == RecordKind::Group {
            if let Some(name) = row.record.payload["name"].as_str() {
                names.insert((
                    row.record.payload["parent_id"].as_str().map(str::to_owned),
                    name.to_owned(),
                ));
            }
        }
    }
    // Reserve all unchanged local names first, so suggestions never steal a later record's name.
    let mut out = Vec::new();
    for (kind, rows) in [
        (NameKind::Group, &state.local.groups),
        (NameKind::Host, &state.local.hosts),
    ] {
        for row in rows.values().filter(|r| !r.record.deleted) {
            let Some(name) = row.record.payload[kind.field()].as_str() else {
                continue;
            };
            let parent = row.record.payload["parent_id"].as_str().map(str::to_owned);
            let duplicate = match kind {
                NameKind::Host => !aliases.insert(name.to_owned()),
                NameKind::Group => !names.insert((parent, name.to_owned())),
            };
            if duplicate {
                out.push(NameConflict {
                    kind,
                    id: row.record.id.clone(),
                    current_name: name.into(),
                    suggested_name: String::new(),
                });
            }
        }
    }
    for conflict in &mut out {
        let rows = match conflict.kind {
            NameKind::Host => &state.local.hosts,
            NameKind::Group => &state.local.groups,
        };
        let row = &rows[&record_key(conflict.kind.record_kind(), &conflict.id)];
        let parent = row.record.payload["parent_id"].as_str().map(str::to_owned);
        for suffix in 2u64.. {
            let name = match conflict.kind {
                NameKind::Host => format!("{}-{suffix}", conflict.current_name),
                NameKind::Group => {
                    let tail = format!(" ({suffix})");
                    let prefix: String = conflict
                        .current_name
                        .chars()
                        .take(128 - tail.chars().count())
                        .collect();
                    format!("{}{tail}", prefix.trim_end())
                }
            };
            let free = match conflict.kind {
                NameKind::Host => aliases.insert(name.clone()),
                NameKind::Group => names.insert((parent.clone(), name.clone())),
            };
            if free {
                conflict.suggested_name = name;
                break;
            }
        }
    }
    out
}

fn rename(state: &SyncStateV3, renames: &[Rename]) -> Result<SyncStateV3, LibraryFailure> {
    let mut next = state.clone();
    let mut seen = BTreeSet::new();
    for edit in renames {
        if !seen.insert((edit.kind, &edit.id))
            || edit.name.trim() != edit.name
            || edit.name.is_empty()
        {
            return Err(LibraryFailure::new(
                "invalid_rename",
                "Choose one nonempty name for each conflicting record, without surrounding spaces.",
            ));
        }
        let rows = match edit.kind {
            NameKind::Host => &mut next.local.hosts,
            NameKind::Group => &mut next.local.groups,
        };
        let row = rows
            .get_mut(&record_key(edit.kind.record_kind(), &edit.id))
            .filter(|r| !r.record.deleted)
            .ok_or_else(|| {
                LibraryFailure::new(
                    "stale_review",
                    "The library changed. Review the latest records before including them.",
                )
            })?;
        row.record.payload[edit.kind.field()] = edit.name.clone().into();
    }
    Ok(next)
}

pub fn preview(
    state: &SyncStateV3,
    keys: Option<&ChainKeys>,
) -> Result<LibraryPreview, LibraryFailure> {
    let id = space_id(state).ok_or_else(|| {
        LibraryFailure::new(
            "sync_data_unavailable",
            "The sync library is unavailable. Retry after syncing.",
        )
    })?;
    repo::ensure_scope(
        state,
        &HostScope::Space {
            space_id: id.clone(),
        },
    )?;
    let conflicts = conflicts(state, &id);
    let renames: Vec<_> = conflicts
        .iter()
        .map(|c| Rename {
            kind: c.kind,
            id: c.id.clone(),
            name: c.suggested_name.clone(),
        })
        .collect();
    // Validate the complete proposal without publishing a format upgrade or changing records.
    let proposed = rename(state, &renames)?;
    include_existing(&proposed, &id, true, 0, keys)?;
    Ok(LibraryPreview {
        token: token(state, &id),
        conflicts,
        local_hosts: state
            .local
            .hosts
            .values()
            .filter(|r| !r.record.deleted)
            .count(),
        local_groups: state
            .local
            .groups
            .values()
            .filter(|r| !r.record.deleted)
            .count(),
    })
}

pub fn include_reviewed(
    state: &SyncStateV3,
    id: &str,
    confirmed: bool,
    now: u64,
    review: Option<&LibraryReview>,
    keys: Option<&ChainKeys>,
) -> Result<SyncStateV3, LibraryFailure> {
    let Some(review) = review else {
        return include_existing(state, id, confirmed, now, keys).map_err(Into::into);
    };
    if review.token != token(state, id) {
        return Err(LibraryFailure::new("stale_review", "The library changed while you were reviewing it. Review the latest records and retry; no names have been changed."));
    }
    let expected: BTreeSet<_> = conflicts(state, id)
        .into_iter()
        .map(|c| (c.kind, c.id))
        .collect();
    let supplied: BTreeSet<_> = review
        .renames
        .iter()
        .map(|r| (r.kind, r.id.clone()))
        .collect();
    if expected != supplied || review.renames.len() != supplied.len() {
        return Err(LibraryFailure::new("invalid_rename", "Review every conflicting name before including the library. Only those local records may be renamed."));
    }
    let proposed = rename(state, &review.renames)?;
    let next = include_existing(&proposed, id, confirmed, now, keys)?;
    repo::validate_transition(state, &next)?;
    Ok(next)
}
