//! Complete native inputs from one captured state; semantic mapping and consent are separate.
use super::{
    records::{Authenticated, View},
    *,
};
use crate::sync::record::LocalRecord;
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::sync::central) enum Scope {
    Local,
    Account(String),
    Space(String),
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::sync::central) enum Position {
    Current,
    Sealed,
    ChainDelete,
    RecoveryBase,
    ConflictBase,
    ConflictLocal,
    ConflictRemote,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::sync::central) struct Location {
    pub scope: Scope,
    pub position: Position,
    pub key: String,
    pub index: usize,
}
pub(in crate::sync::central) struct Item {
    pub location: Location,
    pub sequence: u64,
    pub dirty: bool,
    opened: Authenticated,
}
impl Item {
    pub fn view(&self) -> Result<View<'_>, AppError> {
        self.opened.view()
    }
}
/// No Debug/Serialize/IPC. Secret payload backing bytes are erased on all error/return paths.
pub(in crate::sync::central) struct Inventory {
    rows: Vec<Item>,
    bytes: usize,
    positions: BTreeSet<Location>,
}
impl Inventory {
    pub fn rows(&self) -> &[Item] {
        &self.rows
    }
    pub fn from_state(sources: &Sources, state: &SyncStateV3) -> Result<Self, AppError> {
        records_v3::validate_state(state).map_err(|_| invalid())?;
        drop(Sources::decode_local(&sources.encode_local()?, state)?);
        let mut result = Self {
            rows: vec![],
            bytes: 0,
            positions: BTreeSet::new(),
        };
        for row in state
            .local
            .hosts
            .values()
            .chain(state.local.groups.values())
        {
            result.public(
                Scope::Local,
                Position::Current,
                &crate::sync::record::record_key(row.record.kind, &row.record.id),
                0,
                row,
            )?;
        }
        if let Some(account) = &state.account {
            let scope = Scope::Account(account.chain_id.clone());
            for (key, row) in &account.records {
                result.public(scope.clone(), Position::Current, key, 0, row)?;
            }
            for (key, row) in &account.sealed {
                result.sealed(sources, scope.clone(), Position::Sealed, key, 0, row)?;
            }
            for (index, row) in account.chain_deletes.iter().enumerate() {
                result.sealed(
                    sources,
                    scope.clone(),
                    Position::ChainDelete,
                    &row.key(),
                    index,
                    row,
                )?;
            }
            result.recovery(sources, &scope, &account.recovery)?;
        }
        for (id, space) in &state.spaces {
            let scope = Scope::Space(id.clone());
            for (key, row) in &space.records {
                result.public(scope.clone(), Position::Current, key, 0, row)?;
            }
            for (key, row) in &space.sealed {
                result.sealed(sources, scope.clone(), Position::Sealed, key, 0, row)?;
            }
            result.recovery(sources, &scope, &space.recovery)?;
        }
        Ok(result)
    }
    fn append(
        &mut self,
        location: Location,
        sequence: u64,
        dirty: bool,
        opened: Authenticated,
    ) -> Result<(), AppError> {
        self.bytes = self
            .bytes
            .checked_add(opened.byte_len())
            .ok_or_else(invalid)?;
        if self.rows.len() >= 16384
            || self.bytes > 32 * 1024 * 1024 - 256 * 1024
            || sequence > MAX_SAFE_INTEGER
            || !self.positions.insert(location.clone())
        {
            return Err(invalid());
        }
        self.rows.push(Item {
            location,
            sequence,
            dirty,
            opened,
        });
        Ok(())
    }
    fn public(
        &mut self,
        scope: Scope,
        position: Position,
        key: &str,
        index: usize,
        row: &LocalRecord,
    ) -> Result<(), AppError> {
        if crate::sync::record::record_key(row.record.kind, &row.record.id) != key {
            return Err(invalid());
        }
        self.append(
            Location {
                scope,
                position,
                key: key.into(),
                index,
            },
            row.seq,
            row.dirty,
            Authenticated::public(&row.record)?,
        )
    }
    fn sealed(
        &mut self,
        sources: &Sources,
        scope: Scope,
        position: Position,
        key: &str,
        index: usize,
        row: &SealedRecord,
    ) -> Result<(), AppError> {
        if row.key() != key {
            return Err(invalid());
        }
        let chain = match &scope {
            Scope::Account(chain) | Scope::Space(chain) => chain,
            Scope::Local => return Err(invalid()),
        };
        let opened = sources.open(chain, row)?;
        self.append(
            Location {
                scope,
                position,
                key: key.into(),
                index,
            },
            row.envelope.seq,
            row.dirty,
            opened,
        )
    }
    fn version(
        &mut self,
        sources: &Sources,
        scope: &Scope,
        position: Position,
        key: &str,
        index: usize,
        row: &RecordVersion,
    ) -> Result<(), AppError> {
        match row {
            RecordVersion::Public(row) => self.public(scope.clone(), position, key, index, row),
            RecordVersion::Sealed(row) => {
                self.sealed(sources, scope.clone(), position, key, index, row)
            }
        }
    }
    fn recovery(
        &mut self,
        sources: &Sources,
        scope: &Scope,
        recovery: &RecordRecovery,
    ) -> Result<(), AppError> {
        for (key, row) in &recovery.bases {
            self.version(sources, scope, Position::RecoveryBase, key, 0, row)?;
        }
        for (key, conflicts) in &recovery.conflicts {
            for (index, conflict) in conflicts.iter().enumerate() {
                if let Some(base) = &conflict.base {
                    self.version(sources, scope, Position::ConflictBase, key, index, base)?;
                }
                self.version(
                    sources,
                    scope,
                    Position::ConflictLocal,
                    key,
                    index,
                    &conflict.local,
                )?;
                self.version(
                    sources,
                    scope,
                    Position::ConflictRemote,
                    key,
                    index,
                    &conflict.remote,
                )?;
            }
        }
        Ok(())
    }
}
mod keys;
mod typed;
pub(in crate::sync::central) use keys::KeyInput;
pub(in crate::sync::central) use typed::{Known, KnownData, KnownInput};
#[cfg(test)]
mod tests;
