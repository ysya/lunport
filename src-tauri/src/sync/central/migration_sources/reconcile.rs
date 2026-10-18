//! Conservative three-way source selection. Every input survives; no publication authority.
use super::*;
use crate::sync::{
    record::{record_key, LocalRecord},
    records_v3::SpaceStateV3,
};
use inventory::{Item, Known, Position, Scope};
type Logical = (Scope, String, String);
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::sync::central) enum Reason {
    SavedConflict,
    LocalCopies,
    MissingRemote,
    ParallelChanges,
    Rollback,
    PrivateMaterialChanged,
}
pub(in crate::sync::central) struct Conflict {
    pub identity: Logical,
    pub reason: Reason,
    pub inputs: Vec<usize>,
}
pub(in crate::sync::central) struct Reconciliation {
    inventory: Inventory,
    source: SyncStateV3,
    selected: BTreeSet<usize>,
    conflicts: Vec<Conflict>,
}
pub(in crate::sync::central) struct Prepared {
    pub state: SyncStateV3,
    pub known: Known,
}
#[derive(Default)]
struct Versions {
    local: Vec<usize>,
    remote: Vec<usize>,
    bases: Vec<usize>,
    saved: bool,
    all: Vec<usize>,
}
fn equivalent(a: &Item, b: &Item) -> Result<bool, AppError> {
    let a = a.view()?;
    let b = b.view()?;
    if a.kind != b.kind
        || a.id != b.id
        || a.version != b.version
        || a.updated_at_ms != b.updated_at_ms
        || a.device_id != b.device_id
        || a.deleted != b.deleted
    {
        return Ok(false);
    }
    // Bodies remain retained independently even when two current tombstones express the same deletion.
    if a.deleted || a.payload.get() == b.payload.get() {
        return Ok(true);
    }
    fn public<T: serde::de::DeserializeOwned + PartialEq>(a: &str, b: &str) -> bool {
        match (serde_json::from_str::<T>(a), serde_json::from_str::<T>(b)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false, // Admitted legacy schemas retain exact comparison until explicit conversion.
        }
    }
    let (left, right) = (a.payload.get(), b.payload.get());
    Ok(match a.kind {
        "host" => public::<records_v3::HostPayload>(left, right),
        "group" => public::<records_v3::GroupPayload>(left, right),
        "keyslot" => public::<records_v3::KeySlotPayload>(left, right),
        "space" => public::<crate::sync::record::SpacePayload>(left, right),
        "meta" if a.id == crate::sync::group_order::RECORD_ID => {
            public::<crate::sync::group_order::GroupOrder>(left, right)
        }
        _ => false, // Secret payloads never pass through a public JSON value or semantic coercion.
    })
}

impl Reconciliation {
    pub(super) fn from_complete(
        inventory: Inventory,
        state: &SyncStateV3,
    ) -> Result<Self, AppError> {
        drop(inventory.admit_known()?);
        let mut groups: BTreeMap<Logical, Versions> = BTreeMap::new();
        for (index, item) in inventory.rows().iter().enumerate() {
            let view = item.view()?;
            let group = groups
                .entry((
                    item.location.scope.clone(),
                    view.kind.into(),
                    view.id.into(),
                ))
                .or_default();
            group.all.push(index);
            match item.location.position {
                Position::Current | Position::Sealed | Position::ChainDelete => {
                    group.local.push(index)
                }
                Position::Frozen => group.remote.push(index),
                Position::RecoveryBase => group.bases.push(index),
                Position::ConflictBase | Position::ConflictLocal | Position::ConflictRemote => {
                    group.saved = true
                }
                Position::Retained => return Err(invalid()),
            }
        }
        let mut result = Self {
            inventory,
            source: state.clone(),
            selected: BTreeSet::new(),
            conflicts: vec![],
        };
        for (identity, versions) in groups {
            match result.choose(&identity, &versions)? {
                Ok(Some(index)) => {
                    result.selected.insert(index);
                }
                Ok(None) => {}
                Err(reason) => result.conflicts.push(Conflict {
                    identity,
                    reason,
                    inputs: versions.all,
                }),
            }
        }
        Ok(result)
    }
    fn choose(
        &self,
        identity: &Logical,
        v: &Versions,
    ) -> Result<Result<Option<usize>, Reason>, AppError> {
        let rows = self.inventory.rows();
        if v.saved {
            return Ok(Err(Reason::SavedConflict));
        }
        if v.remote.len() > 1 {
            return Err(invalid());
        }
        for pair in v.local.windows(2) {
            if !equivalent(&rows[pair[0]], &rows[pair[1]])? {
                return Ok(Err(Reason::LocalCopies));
            }
        }
        for pair in v.bases.windows(2) {
            if !equivalent(&rows[pair[0]], &rows[pair[1]])? {
                return Ok(Err(Reason::LocalCopies));
            }
        }
        let local = v
            .local
            .iter()
            .copied()
            .max_by_key(|i| (rows[*i].dirty, rows[*i].sequence));
        if matches!(identity.0, Scope::Local) {
            return if v.remote.is_empty() {
                Ok(Ok(local))
            } else {
                Err(invalid())
            };
        }
        let remote = v.remote.first().copied();
        let minimum = v
            .local
            .iter()
            .chain(&v.bases)
            .map(|i| rows[*i].sequence)
            .max()
            .unwrap_or(0);
        if remote.is_some_and(|i| rows[i].sequence < minimum) {
            return Ok(Err(Reason::Rollback));
        }
        match (local, remote) {
            (None, None) => Ok(Ok(None)),
            (None, Some(remote)) => {
                let version = rows[remote].view()?.version;
                for base in &v.bases {
                    if !equivalent(&rows[*base], &rows[remote])?
                        && (rows[*base].view()?.version >= version
                            || rows[*base].sequence >= rows[remote].sequence)
                    {
                        return Ok(Err(Reason::Rollback));
                    }
                }
                Ok(Ok(Some(remote)))
            }
            (Some(local), None) => {
                if rows[local].dirty && minimum == 0 && v.bases.is_empty() {
                    Ok(Ok(Some(local)))
                } else {
                    Ok(Err(Reason::MissingRemote))
                }
            }
            (Some(local), Some(remote)) => {
                if equivalent(&rows[local], &rows[remote])? {
                    return Ok(Ok(Some(remote)));
                }
                if rows[local].dirty {
                    for base in &v.bases {
                        if equivalent(&rows[*base], &rows[remote])? {
                            return Ok(Ok(Some(local)));
                        }
                    }
                    return Ok(Err(Reason::ParallelChanges));
                }
                if rows[remote].sequence <= minimum
                    || rows[remote].view()?.version <= rows[local].view()?.version
                {
                    return Ok(Err(Reason::Rollback));
                }
                if identity.1 == "key" {
                    return Ok(Err(Reason::PrivateMaterialChanged));
                }
                Ok(Ok(Some(remote)))
            }
        }
    }
    pub fn conflicts(&self) -> &[Conflict] {
        &self.conflicts
    }
    pub fn prepare(self) -> Result<Prepared, AppError> {
        if !self.conflicts.is_empty() {
            return Err(AppError::Other(format!("Resolve {} source conflicts before preparing migration. Every original version is retained.",self.conflicts.len())));
        }
        let mut state = self.source;
        let mut known = self.inventory.admit_known()?;
        for (index, row) in known.rows_mut().iter_mut().enumerate() {
            if !self.selected.contains(&index) {
                row.location.position = Position::Retained;
                continue;
            }
            let kind = RecordKind::parse(&row.kind).ok_or_else(invalid)?;
            row.location.position = if kind.is_secret() {
                Position::Sealed
            } else {
                Position::Current
            };
            if kind.is_secret() {
                continue;
            }
            let view = self.inventory.rows()[index].view()?;
            let record = Record {
                kind,
                id: view.id.into(),
                version: view.version,
                updated_at_ms: view.updated_at_ms,
                device_id: view.device_id.into(),
                deleted: view.deleted,
                payload: serde_json::from_str(view.payload.get()).map_err(|_| invalid())?,
            };
            let local = LocalRecord {
                record,
                seq: row.sequence,
                dirty: row.dirty,
            };
            let key = record_key(kind, &row.id);
            match &row.location.scope {
                Scope::Local => match kind {
                    RecordKind::Host => {
                        state.local.hosts.insert(key, local);
                    }
                    RecordKind::Group => {
                        state.local.groups.insert(key, local);
                    }
                    _ => return Err(invalid()),
                },
                Scope::Account(_) => {
                    state
                        .account
                        .as_mut()
                        .ok_or_else(invalid)?
                        .records
                        .insert(key, local);
                }
                Scope::Space(id) => {
                    state
                        .spaces
                        .entry(id.clone())
                        .or_insert_with(SpaceStateV3::default)
                        .records
                        .insert(key, local);
                }
            }
        }
        // Every known child has an authenticated full frozen response, including empty snapshots.
        for space in state.spaces.values_mut() {
            space.missing = false;
        }
        if let Some(account) = &state.account {
            for row in account
                .records
                .values()
                .filter(|r| r.record.kind == RecordKind::Space && !r.record.deleted)
            {
                state
                    .spaces
                    .entry(row.record.id.clone())
                    .or_insert_with(SpaceStateV3::default);
            }
        }
        records_v3::validate_state(&state).map_err(|_| invalid())?;
        Ok(Prepared { state, known })
    }
}

#[cfg(test)]
mod tests;
