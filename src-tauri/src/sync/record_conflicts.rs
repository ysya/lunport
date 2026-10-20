//! Durable recovery for concurrent edits. Secret versions remain encrypted envelopes.
use crate::sync::{
    record::{record_key, LocalRecord},
    state_v2::{sealed_key, SealedRecord},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Write};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "storage",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RecordVersion {
    Public(LocalRecord),
    Sealed(SealedRecord),
}
impl RecordVersion {
    pub fn seq(&self) -> u64 {
        match self {
            Self::Public(r) => r.seq,
            Self::Sealed(r) => r.envelope.seq,
        }
    }
    pub fn key(&self) -> String {
        match self {
            Self::Public(r) => record_key(r.record.kind, &r.record.id),
            Self::Sealed(r) => sealed_key(&r.envelope.kind, &r.envelope.id_hash),
        }
    }
    pub fn clean(&self) -> bool {
        match self {
            Self::Public(r) => !r.dirty && !r.record.kind.is_secret(),
            Self::Sealed(r) => !r.dirty,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordConflict {
    /// Older installations may not have retained an exact common base.
    pub base: Option<RecordVersion>,
    pub local: RecordVersion,
    pub remote: RecordVersion,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRecovery {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bases: BTreeMap<String, RecordVersion>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub conflicts: BTreeMap<String, Vec<RecordConflict>>,
}
impl RecordRecovery {
    pub fn is_empty(&self) -> bool {
        self.bases.is_empty() && self.conflicts.is_empty()
    }
    pub fn retain(&mut self, key: &str, local: RecordVersion, remote: RecordVersion) {
        let versions = self.conflicts.entry(key.into()).or_default();
        if !versions.iter().any(|c| c.remote == remote) {
            versions.push(RecordConflict {
                base: self.bases.get(key).cloned(),
                local,
                remote,
            });
        }
    }
    pub fn bounded(&self) -> bool {
        if self.bases.len() > 4096 || self.conflicts.values().map(Vec::len).sum::<usize>() > 8192 {
            return false;
        }
        struct Counter(usize);
        impl Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.saturating_add(bytes.len());
                if self.0 > 16 * 1024 * 1024 {
                    return Err(std::io::Error::other("recovery storage is full"));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Counter(0), self).is_ok()
    }
    pub fn valid(&self) -> bool {
        self.bounded() && self.bases.iter().all(|(key, row)| row.clean() && row.key() == *key)
            && self.conflicts.iter().all(|(key, versions)| !versions.is_empty() && versions.iter().all(|c| {
                c.local.key() == *key && c.remote.key() == *key && c.remote.clean()
                    && c.base.as_ref().is_none_or(|base| base.key() == *key && base.clean())
                    && !matches!(&c.local, RecordVersion::Public(row) if row.record.kind.is_secret())
                    && matches!((&c.local, &c.remote), (RecordVersion::Public(_), RecordVersion::Public(_)) | (RecordVersion::Sealed(_), RecordVersion::Sealed(_)))
            }))
    }
}
pub fn require_resolved(
    state: &crate::sync::records_v3::SyncStateV3,
) -> Result<(), crate::error::AppError> {
    if state
        .account
        .as_ref()
        .is_some_and(|a| !a.recovery.conflicts.is_empty())
        || state
            .spaces
            .values()
            .any(|s| !s.recovery.conflicts.is_empty())
    {
        return Err(crate::error::AppError::Other(
            "Resolve saved sync conflicts before leaving or changing the sync account.".into(),
        ));
    }
    Ok(())
}

pub fn upgrade_state(state: &mut crate::sync::records_v3::SyncStateV3) {
    let has_recovery = state
        .account
        .as_ref()
        .is_some_and(|a| !a.recovery.is_empty())
        || state.spaces.values().any(|s| !s.recovery.is_empty())
        || state.pending_account.as_ref().is_some_and(|p| {
            !p.prepared_account.recovery.is_empty()
                || p.prepared_space
                    .as_ref()
                    .is_some_and(|s| !s.recovery.is_empty())
        });
    if has_recovery {
        state.version = state
            .version
            .max(crate::sync::records_v3::LOCAL_CONFLICT_STATE_VERSION);
    }
}

mod commands;
pub use commands::{resolve_saved, views, ConflictView, Resolution};
