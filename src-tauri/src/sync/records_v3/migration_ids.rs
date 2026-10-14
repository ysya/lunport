use super::RecordValidationError;
use crate::sync::crypto::is_chain_id;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"sshelter-host-migration-v1";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationSource {
    pub space_id: String,
    pub old_record_id: String,
}

/// Stable across devices: domain bytes followed by each UTF-8 field's u64 big-endian byte length and bytes.
pub fn migration_host_id(
    space_id: &str,
    old_record_id: &str,
) -> Result<String, RecordValidationError> {
    if !is_chain_id(space_id) {
        return Err(RecordValidationError::Invalid {
            field: "space_id",
            id: old_record_id.into(),
            reason: "expected a chain id".into(),
        });
    }
    if old_record_id.is_empty() {
        return Err(RecordValidationError::Invalid {
            field: "old_record_id",
            id: String::new(),
            reason: "missing source record id".into(),
        });
    }
    Ok(hash_fields(space_id, old_record_id))
}

fn hash_fields(space_id: &str, old_record_id: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    for value in [space_id, old_record_id] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Repeated occurrences of one source are deduplicated; every legacy alias ID is reserved automatically.
/// Errors do not return a partial mapping and never replace a collision with randomness.
pub fn preflight_host_ids(
    sources: &[MigrationSource],
    reserved_ids: &BTreeSet<String>,
) -> Result<BTreeMap<MigrationSource, String>, RecordValidationError> {
    let sources: BTreeSet<_> = sources.iter().cloned().collect();
    let mut occupied: BTreeMap<_, _> = reserved_ids
        .iter()
        .map(|id| (id.clone(), "reserved existing id".to_string()))
        .collect();
    for source in &sources {
        occupied
            .entry(source.old_record_id.clone())
            .or_insert_with(|| format!("legacy {}:{}", source.space_id, source.old_record_id));
    }
    let mut mapping = BTreeMap::new();
    for source in sources {
        let id = migration_host_id(&source.space_id, &source.old_record_id)?;
        let origin = format!("{}:{}", source.space_id, source.old_record_id);
        if let Some(first) = occupied.insert(id.clone(), origin.clone()) {
            return Err(RecordValidationError::MigrationCollision {
                id,
                first,
                second: origin,
            });
        }
        mapping.insert(source, id);
    }
    Ok(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn field_boundaries_cannot_be_confused_by_concatenation() {
        assert_ne!(hash_fields("a", "bc"), hash_fields("ab", "c"));
    }
}
