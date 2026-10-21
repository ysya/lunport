use super::super::{GroupRecord, HostRecord, RecordValidationError};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub const MAX_DEPTH: usize = 16;
pub const MAX_FILES: usize = 128;
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// Every external value is explicit. This is never populated from the process environment.
#[derive(Clone)]
pub struct ImportOptions {
    pub home: PathBuf,
    pub env: BTreeMap<String, String>,
    pub at_ms: u64,
    /// An existing confirmation journal may supply stable IDs for retries.
    pub host_ids: BTreeMap<String, String>,
    pub group_ids: BTreeMap<String, String>,
    pub key_ids: BTreeMap<String, String>,
    /// Managed copies of already-synced hosts must not be imported again.
    pub excluded_sources: BTreeSet<PathBuf>,
    /// Existing unrelated identities reserved by migration preflight.
    pub reserved_host_ids: BTreeSet<String>,
}
impl ImportOptions {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            env: BTreeMap::new(),
            at_ms: 0,
            host_ids: BTreeMap::new(),
            group_ids: BTreeMap::new(),
            key_ids: BTreeMap::new(),
            excluded_sources: BTreeSet::new(),
            reserved_host_ids: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceLocation {
    pub path: PathBuf,
    pub line: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceFile {
    pub path: PathBuf,
    pub canonical_path: PathBuf,
    pub digest: String,
    pub bytes: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportWarning {
    pub location: SourceLocation,
    pub keyword: String,
    pub reason: String,
    pub blocks_connection: bool,
    pub alias: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyReferenceSuggestion {
    pub host_id: String,
    pub key_id: String,
    pub value: String,
    pub resolved_path: Option<PathBuf>,
    pub fingerprint: Option<String>,
    pub will_copy: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ImportPreview {
    pub candidates: Vec<HostRecord>,
    pub groups: Vec<GroupRecord>,
    pub group_ids: BTreeMap<String, String>,
    pub warnings: Vec<ImportWarning>,
    pub provenance: Vec<SourceFile>,
    pub key_references: Vec<KeyReferenceSuggestion>,
    pub host_ids: BTreeMap<String, String>,
    pub source_digest: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportError {
    Io {
        location: SourceLocation,
        message: String,
    },
    InvalidSource {
        location: SourceLocation,
        reason: String,
    },
    Cycle {
        location: SourceLocation,
    },
    Limit {
        location: SourceLocation,
        limit: &'static str,
    },
    PrivateKeyContent {
        location: SourceLocation,
    },
    InvalidRecords(RecordValidationError),
    UnsupportedLegacySchema(u32),
}
impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ImportError {}
