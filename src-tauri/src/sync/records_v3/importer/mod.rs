//! Explicit read-only configuration previews. No config repair, credential access or command execution.
mod resolve;
mod saved_hosts;
mod source;
mod types;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
pub use types::*;

pub fn preview_file(source: &Path, options: &ImportOptions) -> Result<ImportPreview, ImportError> {
    if source.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("json")) {
        return saved_hosts::preview(source, options);
    }
    resolve::resolve(source::load(source, options)?, options)
}

/// A single legacy record can only link jumps when the complete space snapshot is supplied separately.
pub fn preview_legacy_record(
    record: &crate::sync::record::Record,
    space_id: &str,
    options: &ImportOptions,
) -> Result<ImportPreview, ImportError> {
    preview_legacy_records(std::slice::from_ref(record), space_id, options)
}

/// Decode every legacy alias independently, then link jumps across this immutable space snapshot.
/// Stored Include paths are preserved for review and never opened on this device.
pub fn preview_legacy_records(
    records: &[crate::sync::record::Record],
    space_id: &str,
    options: &ImportOptions,
) -> Result<ImportPreview, ImportError> {
    use super::{preflight_host_ids, MigrationSource, RecordValidationError};
    if !crate::sync::crypto::is_chain_id(space_id) {
        return Err(ImportError::InvalidRecords(
            RecordValidationError::Invalid {
                field: "space_id",
                id: space_id.into(),
                reason: "expected a chain id".into(),
            },
        ));
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Legacy {
        schema: u32,
        text: String,
    }
    let mut unique = BTreeMap::new();
    for record in records {
        if record.kind != crate::sync::record::RecordKind::Host {
            return Err(ImportError::InvalidRecords(
                RecordValidationError::WrongKind {
                    expected: "legacy host",
                    found: record.kind.as_str().into(),
                },
            ));
        }
        if record.deleted {
            continue;
        }
        if let Some(old) = unique.insert(record.id.clone(), record) {
            if old.payload != record.payload {
                return Err(ImportError::InvalidSource {
                    location: SourceLocation {
                        path: PathBuf::from(format!("relay:{space_id}:{}", record.id)),
                        line: 1,
                    },
                    reason: "same legacy alias has conflicting source payloads".into(),
                });
            }
        }
    }
    let migrations: Vec<_> = unique
        .keys()
        .map(|alias| MigrationSource {
            space_id: space_id.into(),
            old_record_id: alias.clone(),
        })
        .collect();
    let mut reserved = options.reserved_host_ids.clone();
    reserved.extend(records.iter().map(|record| record.id.clone()));
    let mapping =
        preflight_host_ids(&migrations, &reserved).map_err(ImportError::InvalidRecords)?;
    let mut options = options.clone();
    let mut sources = Vec::new();
    for (alias, record) in unique {
        let found = record
            .payload
            .get("schema")
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);
        if found != 1 {
            return Err(ImportError::UnsupportedLegacySchema(found));
        }
        let legacy: Legacy = serde_json::from_value(record.payload.clone()).map_err(|_| {
            ImportError::InvalidSource {
                location: SourceLocation {
                    path: PathBuf::from("relay"),
                    line: 0,
                },
                reason: "legacy host payload is malformed".into(),
            }
        })?;
        if legacy.schema != 1 {
            return Err(ImportError::UnsupportedLegacySchema(legacy.schema));
        }
        options.host_ids.insert(
            alias.clone(),
            mapping[&MigrationSource {
                space_id: space_id.into(),
                old_record_id: alias.clone(),
            }]
                .clone(),
        );
        let label = PathBuf::from(format!("relay:{space_id}:{alias}"));
        let mut snapshot = source::memory_snapshot(&label, &legacy.text, &options)?;
        // Source metadata participates in confirmation invalidation even when its text is unchanged.
        let bytes = serde_json::to_vec(record).map_err(|_| ImportError::InvalidSource {
            location: SourceLocation {
                path: label,
                line: 0,
            },
            reason: "cannot fingerprint legacy source".into(),
        })?;
        use sha2::Digest;
        snapshot.files[0].digest = source::hex(&sha2::Sha256::digest(bytes));
        sources.push((alias, snapshot));
    }
    resolve::resolve_legacy_sources(sources, &options, space_id)
}
#[cfg(test)]
mod tests;
