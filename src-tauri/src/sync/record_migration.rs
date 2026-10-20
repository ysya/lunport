//! Confirmed account migration. Previews remain in memory and all originals are retained.
mod publication;
pub(in crate::sync) mod inventory;
mod source;
pub(in crate::sync) use source::key_options as legacy_key_options;
use crate::error::AppError;
use crate::sync::crypto::ChainKeys;
use crate::sync::env::SyncEnv;
use crate::sync::record::{record_key, Envelope, RecordKind};
use crate::sync::record_runtime::{self, RuntimeFormat, MAX_STATE_BYTES};
use crate::sync::records_v3::{
    self, KeySlotPayload, MigrationGate, MigrationPhase, SpaceStateV3, SyncStateV3,
};
use crate::sync::relay::PushItem;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
const MAX_RECORD_BYTES: usize = 65_536;
const MAX_CHAIN_BYTES: usize = 1_048_576;
const MAX_CHAIN_RECORDS: usize = 4096;
const MAX_LOCAL_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const CODE_PREFIX: &str = "sync:records-migration:";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationDiagnostic {
    pub code: String,
    pub host_id: Option<String>,
    pub space_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MigrationPreview {
    pub source_digest: String,
    pub source_kind: String,
    pub account_schema: u32,
    pub selected_space_ids: Vec<String>,
    pub host_count: usize,
    pub key_count: usize,
    pub diagnostics: Vec<MigrationDiagnostic>,
    pub can_confirm: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationConsent {
    pub old_clients_stopped_or_compatible: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MigrationReceipt {
    pub migration_id: String,
    pub phase: String,
    pub complete: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PendingMigration {
    pub migration_id: String,
    pub phase: String,
    pub host_count: usize,
    pub key_count: usize,
}
pub struct PreparedMigration {
    preview: MigrationPreview,
    input: source::Input,
    plan: MigrationPlan,
}
impl std::fmt::Debug for PreparedMigration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedMigration")
            .field("preview", &self.preview)
            .finish_non_exhaustive()
    }
}
impl PreparedMigration {
    pub fn preview(&self) -> &MigrationPreview {
        &self.preview
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainPlan {
    chain_id: String,
    original: Vec<Envelope>,
    items: Vec<PushItem>,
    create: bool,
}
impl ChainPlan {
    fn new(keys: &ChainKeys, original: Vec<Envelope>, create: bool) -> Self {
        Self {
            chain_id: keys.chain_id.clone(),
            original,
            items: vec![],
            create,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentSource {
    source: String,
    disk_digest: String,
    memory_digest: String,
    #[serde(skip)]
    text: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationPlan {
    migration_id: String,
    source_digest: String,
    candidate: SyncStateV3,
    chains: BTreeMap<String, ChainPlan>,
    legacy_digests: BTreeMap<String, String>,
    local_source_digest: String,
    pins_digest: String,
    space_identities: BTreeMap<String, String>,
    #[serde(skip)]
    original_state_bytes: Option<Zeroizing<Vec<u8>>>,
    documents: Vec<DocumentSource>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    phase: String,
    source_kind: String,
    source_state_digest: String,
    source_generation: u64,
    host_count: usize,
    key_count: usize,
    diagnostics: Vec<MigrationDiagnostic>,
    plan: MigrationPlan,
    created_chains: BTreeSet<String>,
    gate_written: bool,
    code_staged: bool,
    vault_staged: bool,
    state_published: bool,
    password_receipts: BTreeMap<String, String>,
    next_retry_ms: u64,
    failures: u32,
}
impl Journal {
    fn receipt(&self) -> MigrationReceipt {
        MigrationReceipt {
            migration_id: self.plan.migration_id.clone(),
            phase: self.phase.clone(),
            complete: self.phase == "active",
        }
    }
}
fn failure(text: &str) -> AppError {
    AppError::Other(text.into())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn read_optional(path: &Path, limit: u64) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(failure("migration source cannot be read")),
    };
    if !metadata.is_file() || metadata.len() > limit {
        return Err(failure("migration source is not a bounded regular file"));
    }
    let file = File::open(path).map_err(|_| failure("migration source cannot be opened"))?;
    if file
        .metadata()
        .map_err(|_| failure("migration source cannot be inspected"))?
        .len()
        > limit
    {
        return Err(failure("migration source exceeds its size limit"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("migration source cannot be read"))?;
    if bytes.len() as u64 > limit {
        return Err(failure("migration source exceeds its size limit"));
    }
    Ok(Some(bytes))
}
fn capacity(chain: &ChainPlan) -> Result<(), AppError> {
    let mut rows: BTreeMap<_, _> = chain
        .original
        .iter()
        .map(|e| {
            (
                (e.kind.clone(), e.id_hash.clone()),
                e.ciphertext.len() + e.nonce.len(),
            )
        })
        .collect();
    for i in &chain.items {
        if i.ciphertext.len() > MAX_RECORD_BYTES {
            return Err(failure("migration row exceeds relay capacity"));
        }
        rows.insert(
            (i.kind.clone(), i.id_hash.clone()),
            i.ciphertext.len() + i.nonce.len(),
        );
    }
    if rows.len() > MAX_CHAIN_RECORDS
        || rows
            .values()
            .try_fold(0usize, |a, b| a.checked_add(*b))
            .is_none_or(|n| n > MAX_CHAIN_BYTES)
    {
        return Err(failure(
            "migration requires more relay capacity; old records were retained",
        ));
    }
    Ok(())
}
/// No journal, lock file, credential write or network mutation is created by preparation.
pub fn prepare(
    env: &SyncEnv,
    entered_code: Option<Zeroizing<String>>,
) -> Result<PreparedMigration, AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env.runtime.vault.lock().unwrap();
    let _publication = env.runtime.format_publication.lock().unwrap();
    crate::fsutil::check_write(&env.state_path)?;
    let input = source::snapshot(env, entered_code)?;
    source::build(env, input, &crate::sync::slot_rules::new_slot_id()?)
}
/// The consumed memory preview is rehashed against real seq0 sources before any mutation.
pub fn confirm(
    env: &SyncEnv,
    prepared: PreparedMigration,
    consent: MigrationConsent,
) -> Result<MigrationReceipt, AppError> {
    if !consent.old_clients_stopped_or_compatible {
        return Err(failure(
            "confirm that old clients are stopped or compatible before account migration",
        ));
    }
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env.runtime.vault.lock().unwrap();
    let _publication = env.runtime.format_publication.lock().unwrap();
    let refreshed = source::build(
        env,
        source::snapshot(
            env,
            if prepared.input.code.is_empty() {
                None
            } else {
                Some(Zeroizing::new(prepared.input.code.to_string()))
            },
        )?,
        &prepared.plan.migration_id,
    )?;
    if refreshed.preview.source_digest != prepared.preview.source_digest
        || refreshed.input.generation != prepared.input.generation
    {
        return Err(failure("migration source changed; preview it again"));
    }
    let paths = publication::Paths::new(env, &prepared.plan.migration_id)?;
    paths.preflight(env)?;
    let _file_lock = publication::lock_profile(env)?;
    let mut journal = Journal {
        version: 1,
        phase: "prepared".into(),
        source_kind: prepared.input.kind.clone(),
        source_state_digest: prepared.input.state_digest.clone(),
        source_generation: prepared.input.generation,
        host_count: prepared.preview.host_count,
        key_count: prepared.preview.key_count,
        diagnostics: prepared.preview.diagnostics.clone(),
        plan: prepared.plan,
        created_chains: BTreeSet::new(),
        gate_written: false,
        code_staged: false,
        vault_staged: false,
        state_published: false,
        password_receipts: BTreeMap::new(),
        next_retry_ms: 0,
        failures: 0,
    };
    publication::prepare_journal(env, &paths, &mut journal, &prepared.input.code)?;
    publication::execute(env, &paths, &mut journal, &prepared.input.code)
}
pub fn resume(env: &SyncEnv, id: &str) -> Result<MigrationReceipt, AppError> {
    resume_inner(env, id, None)
}
fn resume_inner(
    env: &SyncEnv,
    id: &str,
    supplied: Option<Zeroizing<String>>,
) -> Result<MigrationReceipt, AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env.runtime.vault.lock().unwrap();
    let _publication = env.runtime.format_publication.lock().unwrap();
    let paths = publication::Paths::new(env, id)?;
    paths.preflight(env)?;
    let _file_lock = publication::lock_profile(env)?;
    let mut journal = publication::read_journal(&paths)?;
    if journal.phase == "active" {
        return Ok(journal.receipt());
    }
    if let Some(receipt) = publication::completed_receipt(&paths, &mut journal, env)? {
        return Ok(receipt);
    }
    let code = if let Some(code) = supplied {
        Zeroizing::new(
            crate::sync::crypto::normalize_mnemonic(&code)
                .map_err(|_| failure("migration sync code is invalid"))?,
        )
    } else if journal.plan.candidate.account.is_none() {
        Zeroizing::new(String::new())
    } else {
        Zeroizing::new(
            env.keychain
                .get(&format!("{CODE_PREFIX}{id}"))
                .map_err(|_| failure("migration scoped sync code cannot be read"))?
                .or(env
                    .keychain
                    .get(crate::sync::state::MNEMONIC_ACCOUNT)
                    .map_err(|_| failure("migration sync code cannot be read"))?)
                .ok_or_else(|| failure("migration sync code is unavailable; enter it again"))?,
        )
    };
    publication::prepare_journal(env, &paths, &mut journal, &code)?;
    publication::execute(env, &paths, &mut journal, &code)
}
/// Only bounded public metadata is read; no core, vault or credential access.
pub fn pending_migrations(env: &SyncEnv) -> Result<Vec<PendingMigration>, AppError> {
    let root = env
        .state_path
        .parent()
        .ok_or_else(|| failure("migration profile data path is unavailable"))?
        .join("migrations");
    if !root.exists() {
        return Ok(vec![]);
    }
    let entries =
        fs::read_dir(root).map_err(|_| failure("migration recovery metadata cannot be read"))?;
    let mut out = Vec::new();
    let mut bytes = 0u64;
    for (n, entry) in entries.enumerate() {
        if n >= 1024 {
            return Err(failure(
                "migration recovery metadata exceeds the scan limit",
            ));
        }
        let entry = entry.map_err(|_| failure("migration recovery metadata cannot be read"))?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if !crate::sync::slot_rules::is_slot_id(&id) {
            continue;
        }
        let path = entry.path().join("journal.json");
        let size = fs::metadata(&path).map_or(0, |m| m.len());
        bytes = bytes.saturating_add(size);
        if bytes > MAX_JOURNAL_BYTES {
            return Err(failure(
                "migration recovery metadata exceeds the size limit",
            ));
        }
        let Ok(Some(data)) = read_optional(&path, MAX_JOURNAL_BYTES) else {
            out.push(PendingMigration {
                migration_id: id,
                phase: "invalid".into(),
                host_count: 0,
                key_count: 0,
            });
            continue;
        };
        let value: serde_json::Value = serde_json::from_slice(&data)
            .map_err(|_| failure("migration recovery metadata is malformed"))?;
        let phase = value
            .get("phase")
            .and_then(|v| v.as_str())
            .filter(|p| matches!(*p, "prepared" | "account-gated" | "publishing" | "active"))
            .unwrap_or("invalid");
        if phase == "active" {
            continue;
        }
        out.push(PendingMigration {
            migration_id: id,
            phase: phase.into(),
            host_count: value
                .get("host_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
            key_count: value.get("key_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
        });
    }
    out.sort_by(|a, b| a.migration_id.cmp(&b.migration_id));
    Ok(out)
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    Prepared,
    CodeStaged,
    AccountGated,
    BatchSaved,
    VaultPublished,
    BeforeStateSave,
    StateSaved,
    ActiveSaved,
}
#[cfg(test)]
thread_local! {static TEST_STEP:std::cell::RefCell<Option<Box<dyn FnMut(Step)->Result<(),AppError>>>>=std::cell::RefCell::new(None);}
#[cfg(test)]
pub(crate) fn with_test_step<T>(
    hook: impl FnMut(Step) -> Result<(), AppError> + 'static,
    f: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_STEP.with(|h| *h.borrow_mut() = None);
        }
    }
    TEST_STEP.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    let _reset = Reset;
    f()
}
#[cfg(test)]
fn step(s: Step) -> Result<(), AppError> {
    TEST_STEP.with(|h| h.borrow_mut().as_mut().map_or(Ok(()), |f| f(s)))
}
#[cfg(test)]
#[path = "record_migration_tests.rs"]
mod tests;
/// Re-enter a code after a scoped credential staging failure; identities remain fixed by the journal.
pub fn resume_with_code(
    env: &SyncEnv,
    id: &str,
    code: Zeroizing<String>,
) -> Result<MigrationReceipt, AppError> {
    resume_inner(env, id, Some(code))
}

fn space_identity(keys: &ChainKeys) -> String {
    let mut hash = Sha256::new();
    hash.update(b"sshelter-migration-space-identity-v1");
    hash.update(keys.chain_id.as_bytes());
    hash.update(keys.auth_token.as_bytes());
    let encoded = Zeroizing::new(keys.enc_key_b64());
    hash.update(encoded.as_bytes());
    hex(&hash.finalize())
}
