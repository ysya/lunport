//! Explicitly confirmed Local file imports. Sources are never moved or removed.
//! Vault and state publication are separate atomic writes, recovered through a public journal.

use crate::error::AppError;
use crate::fsutil;
use crate::sync::env::{Keychain, SyncEnv};
use crate::sync::record::{record_key, LocalRecord, Record, RecordKind};
use crate::sync::record_runtime;
use crate::sync::records_v3::importer::{self, ImportOptions, ImportPreview};
use crate::sync::records_v3::{
    HostRecord, HostScope, KeySlotPayload, LocalKeyMetadata, SyncStateV3,
};
use crate::vault::store::{self, EntryOrigin, Vault, VaultEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
pub(crate) mod central_stage;
pub(crate) mod central_local;
pub(crate) mod inventory;

pub const MAX_PRIVATE_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
const JOURNAL_VERSION: u32 = 1;
const MAX_COMMIT_ATTEMPTS: usize = 16;

pub struct PreparedImport {
    source: PathBuf,
    options: ImportOptions,
    preview: ImportPreview,
    copies: BTreeMap<String, KeyCopyConsent>,
}
impl std::fmt::Debug for PreparedImport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedImport")
            .field("source", &self.source)
            .field("host_count", &self.preview.candidates.len())
            .field("copies", &self.copies)
            .finish_non_exhaustive()
    }
}
impl PreparedImport {
    pub fn preview(&self) -> &ImportPreview {
        &self.preview
    }
    pub fn selected_copies(&self) -> &BTreeMap<String, KeyCopyConsent> {
        &self.copies
    }
    pub fn deselect_key_copy(&mut self, key_id: &str) {
        self.copies.remove(key_id);
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCopyConsent {
    pub key_id: String,
    pub source: PathBuf,
    pub canonical_source: PathBuf,
    pub digest: String,
    pub public_key: String,
    pub fingerprint: String,
    pub key_type: String,
    pub has_passphrase: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportReceipt {
    pub import_id: String,
    pub host_ids: Vec<String>,
    pub copied_key_ids: Vec<String>,
}
/// Public recovery status. Counts and phase are metadata; this function never opens a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PendingImport {
    pub import_id: String,
    pub phase: String,
    pub host_count: usize,
    pub key_count: usize,
}
/// Bounded read-only recovery discovery, called without core. Corrupt journals remain visible.
pub fn pending_imports(env: &SyncEnv) -> Result<Vec<PendingImport>, AppError> {
    const MAX_SCAN_ENTRIES: usize = 1024;
    const MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024;
    let parent = env
        .state_path
        .parent()
        .ok_or_else(|| failure("sync state has no data directory"))?;
    let dir = parent.join("imports");
    fsutil::check_write(&dir)?;
    match fs::symlink_metadata(&dir) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(vec![]),
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        _ => return Err(failure("cannot inspect import recovery directory")),
    }
    let mut result = Vec::new();
    let mut total = 0u64;
    for (index, entry) in fs::read_dir(&dir)
        .map_err(|_| failure("cannot list import recovery directory"))?
        .enumerate()
    {
        if index >= MAX_SCAN_ENTRIES {
            return Err(failure("import recovery directory exceeds its scan limit"));
        }
        let entry = entry.map_err(|_| failure("cannot inspect import recovery entry"))?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if !crate::sync::slot_rules::is_slot_id(&id)
            || !entry
                .file_type()
                .map_err(|_| failure("cannot inspect import recovery entry"))?
                .is_dir()
        {
            continue;
        }
        let paths = Paths::new(env, &id)?;
        let metadata = fs::symlink_metadata(&paths.journal)
            .map_err(|_| failure("cannot inspect import recovery journal"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_JOURNAL_BYTES
        {
            result.push(PendingImport {
                import_id: id,
                phase: "invalid".into(),
                host_count: 0,
                key_count: 0,
            });
            continue;
        }
        if total.saturating_add(metadata.len()) > MAX_SCAN_BYTES {
            return Err(failure("import recovery journals exceed their scan limit"));
        }
        let bytes = bounded_read(
            &paths.journal,
            (MAX_SCAN_BYTES - total).min(MAX_JOURNAL_BYTES),
        )?;
        total += bytes.len() as u64;
        if let Some(pending) = central_stage::pending(env, &id, &bytes)? {
            if pending.phase != "central_active" {
                result.push(pending);
            }
            continue;
        }
        match serde_json::from_slice::<Journal>(&bytes) {
            Ok(journal) if journal.version == JOURNAL_VERSION && journal.import_id == id => {
                if journal.phase != Phase::Active {
                    let phase = serde_json::to_value(journal.phase)
                        .map_err(|_| failure("cannot describe import recovery phase"))?
                        .as_str()
                        .unwrap_or("invalid")
                        .to_string();
                    result.push(PendingImport {
                        import_id: id,
                        phase,
                        host_count: journal.hosts.len(),
                        key_count: journal.keys.len(),
                    });
                }
            }
            _ => result.push(PendingImport {
                import_id: id,
                phase: "invalid".into(),
                host_count: 0,
                key_count: 0,
            }),
        }
    }
    result.sort_by(|a, b| a.import_id.cmp(&b.import_id));
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    path: PathBuf,
    canonical_path: PathBuf,
    digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicOptions {
    home: PathBuf,
    // Explicit environment values remain in memory; resolved provenance is the retry input.
    env_digest: String,
    host_ids: BTreeMap<String, String>,
    key_ids: BTreeMap<String, String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Staged,
    VaultPublished,
    Active,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    #[default]
    Files,
    Material,
    Synced,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncedPrecondition {
    chain_id: String,
    key_row: LocalRecord,
    old_material: Option<LocalKeyMetadata>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    import_id: String,
    source: PathBuf,
    source_digest: String,
    #[serde(default)]
    source_kind: SourceKind,
    #[serde(default)]
    material_digests: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    central_intent: Option<crate::sync::central::LocalMaterialIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authoritative: Option<SyncedPrecondition>,
    options: PublicOptions,
    provenance: Vec<Provenance>,
    copies: BTreeMap<String, KeyCopyConsent>,
    hosts: Vec<HostRecord>,
    keys: BTreeMap<String, LocalKeyMetadata>,
    device_id: String,
    at_ms: u64,
    phase: Phase,
    originals_captured: bool,
    original_vault_digest: Option<String>,
    staged_vault_digest: Option<String>,
    staged_key_account: Option<String>,
    completed_hosts: BTreeSet<String>,
    completed_keys: BTreeSet<String>,
}
impl Journal {
    fn receipt(&self) -> ImportReceipt {
        ImportReceipt {
            import_id: self.import_id.clone(),
            host_ids: self.hosts.iter().map(|h| h.id.clone()).collect(),
            copied_key_ids: self.keys.keys().cloned().collect(),
        }
    }
}
#[derive(Debug)]
struct Paths {
    dir: PathBuf,
    journal: PathBuf,
    state: PathBuf,
    vault: PathBuf,
    original_state: PathBuf,
    original_vault: PathBuf,
    masters: PathBuf,
}
impl Paths {
    fn new(env: &SyncEnv, id: &str) -> Result<Self, AppError> {
        if !crate::sync::slot_rules::is_slot_id(id) {
            return Err(failure("invalid import id"));
        }
        let parent = env
            .state_path
            .parent()
            .ok_or_else(|| failure("sync state has no data directory"))?;
        let dir = parent.join("imports").join(id);
        let paths = Self {
            journal: dir.join("journal.json"),
            state: dir.join("state.json"),
            vault: dir.join("vault.json"),
            original_state: dir.join("original-state.json"),
            original_vault: dir.join("original-vault.json"),
            masters: dir.join("master-receipts.json"),
            dir,
        };
        // All possible destinations are checked before the first directory, credential or file change.
        for path in [
            &env.state_path,
            &store::vault_path(&env.state_path),
            &paths.dir,
            &paths.journal,
            &paths.state,
            &paths.vault,
            &paths.original_state,
            &paths.original_vault,
            &paths.masters,
        ] {
            fsutil::check_write(path)?;
        }
        Ok(paths)
    }
}
fn failure(message: &'static str) -> AppError {
    AppError::Other(message.into())
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn is_vault_account(account: &str) -> bool {
    account == store::VAULT_KEY_ACCOUNT
        || account
            .strip_prefix(store::VAULT_KEY_ACCOUNT_PREFIX)
            .is_some_and(|id| {
                id.len() == 16
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
}
pub(super) fn bounded_read(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if !path.is_absolute() {
        return Err(failure("import source must be an explicit absolute path"));
    }
    let metadata = fs::metadata(path).map_err(|_| failure("cannot inspect import source"))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(failure(
            "import source is not a supported bounded regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    // Open the confirmed physical path, not a redirected symlink while the read is underway.
    let canonical = path
        .canonicalize()
        .map_err(|_| failure("cannot resolve import source"))?;
    let file = options
        .open(canonical)
        .map_err(|_| failure("cannot read import source"))?;
    let metadata = file
        .metadata()
        .map_err(|_| failure("cannot inspect opened import source"))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(failure(
            "import source is not a supported bounded regular file",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("cannot read import source"))?;
    if bytes.len() as u64 > limit {
        return Err(failure("import source exceeds its supported size limit"));
    }
    Ok(bytes)
}
fn optional_bytes(path: &Path, limit: u64) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(failure("cannot inspect import destination")),
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            Err(failure("import destination must be a regular file"))
        }
        Ok(_) => bounded_read(path, limit).map(Some),
    }
}
fn inspect_copy(key_id: &str, source: &Path) -> Result<(KeyCopyConsent, VaultEntry), AppError> {
    if !crate::sync::slot_rules::is_slot_id(key_id) {
        return Err(failure("invalid imported key id"));
    }
    let canonical_source = source
        .canonicalize()
        .map_err(|_| failure("cannot resolve selected private source"))?;
    let bytes = bounded_read(source, MAX_PRIVATE_SOURCE_BYTES)?;
    if source.canonicalize().ok().as_ref() != Some(&canonical_source) {
        return Err(failure("selected private source changed"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| failure("selected private source is not readable OpenSSH material"))?;
    let key = crate::vault::material::parse(text)
        .ok_or_else(|| failure("selected private source is not readable OpenSSH material"))?;
    let public = key.public_key();
    if !crate::vault::material::agent_can_sign(public.key_data())
        || crate::vault::material::unsupported_cipher(text).is_some()
    {
        return Err(failure(
            "selected private source uses an unsupported key format",
        ));
    }
    let public_key = public
        .to_openssh()
        .map_err(|_| failure("cannot read selected public key identity"))?;
    let fingerprint = public.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    let consent = KeyCopyConsent {
        key_id: key_id.into(),
        source: source.into(),
        canonical_source,
        digest: digest(&bytes),
        public_key: public_key.clone(),
        fingerprint: fingerprint.clone(),
        key_type: public.algorithm().as_str().into(),
        has_passphrase: key.is_encrypted(),
    };
    let entry = VaultEntry {
        private_key: text.into(),
        public_key,
        fingerprint,
        origin: EntryOrigin::Imported,
        added_at_ms: 0,
    };
    Ok((consent, entry))
}
/// Preview only; no directories, credentials, state, vault or private source reads.
pub fn prepare(source: &Path, options: &ImportOptions) -> Result<PreparedImport, AppError> {
    if !source.is_absolute() {
        return Err(failure("local import requires an absolute file source"));
    }
    let preview = importer::preview_file(source, options)
        .map_err(|_| failure("cannot preview this configuration source"))?;
    if preview
        .provenance
        .iter()
        .any(|p| !p.path.is_absolute() || !p.canonical_path.is_absolute())
    {
        return Err(failure("virtual sources cannot be imported as local files"));
    }
    let mut options = options.clone();
    options.host_ids = preview.host_ids.clone();
    for reference in &preview.key_references {
        let identity = reference
            .resolved_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| reference.value.clone());
        options.key_ids.insert(identity, reference.key_id.clone());
    }
    Ok(PreparedImport {
        source: source.into(),
        options,
        preview,
        copies: BTreeMap::new(),
    })
}
/// Only this explicitly selected reference is read; the resulting consent contains public facts.
pub fn select_key_copy(prepared: &mut PreparedImport, key_id: &str) -> Result<(), AppError> {
    let reference = prepared
        .preview
        .key_references
        .iter()
        .find(|r| r.key_id == key_id)
        .ok_or_else(|| failure("key reference is not part of this preview"))?;
    let source = reference
        .resolved_path
        .as_ref()
        .ok_or_else(|| failure("key reference has no static private source"))?;
    if reference.value.to_ascii_lowercase().ends_with(".pub") {
        return Err(failure(
            "a public key file cannot be copied as private material",
        ));
    }
    let (consent, _) = inspect_copy(key_id, source)?;
    prepared.copies.insert(key_id.into(), consent);
    Ok(())
}
fn save_journal(paths: &Paths, journal: &Journal) -> Result<(), AppError> {
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|_| failure("cannot serialize import journal"))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(failure("import journal exceeds its supported size limit"));
    }
    if journal.central_intent.is_some() { return central_stage::durable(paths, &paths.journal, &bytes); }
    fsutil::ensure_dir_secure(&paths.dir)?;
    fsutil::atomic_write(&paths.journal, &bytes, 0o600)
}
fn source_unchanged(journal: &Journal) -> Result<(), AppError> {
    if journal.source_kind != SourceKind::Files {
        return Ok(());
    }
    for file in &journal.provenance {
        if !file.path.is_absolute()
            || !file.canonical_path.is_absolute()
            || file.path.canonicalize().ok().as_ref() != Some(&file.canonical_path)
            || digest(&bounded_read(&file.path, importer::MAX_FILE_BYTES as u64)?) != file.digest
        {
            return Err(failure(
                "confirmed configuration source changed; preview it again",
            ));
        }
    }
    Ok(())
}
fn check_runtime(state: &SyncStateV3) -> Result<(), AppError> {
    if state.rotation.is_some()
        || crate::sync::records_v3::account_migration_pending(state)
        || state.account.as_ref().is_some_and(|account| {
            account.frozen.is_some()
                || account
                    .remote_schema_version
                    .is_some_and(|schema| schema > crate::sync::records_v3::ACCOUNT_SCHEMA)
        })
    {
        return Err(failure(
            "finish the current account operation before importing",
        ));
    }
    Ok(())
}
fn snapshot_for_write(env: &SyncEnv) -> Result<(SyncStateV3, u64), AppError> {
    crate::sync::central::migration_flow::require_editable(env)?;
    let core = env.runtime.core.lock().unwrap();
    if core.save_blocked.is_some() {
        return Err(failure(
            "record state writes are blocked; import has not been published",
        ));
    }
    if core.generation == u64::MAX {
        return Err(failure("record state generation is exhausted"));
    }
    let state = record_runtime::active_state(&core)?.clone();
    check_runtime(&state)?;
    Ok((state, core.generation))
}
/// Consuming this value is the explicit confirmation boundary.
pub fn confirm(env: &SyncEnv, prepared: PreparedImport) -> Result<ImportReceipt, AppError> {
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (state, _) = snapshot_for_write(env)?;
    if central_local::invocation(&state).is_some() && !prepared.copies.is_empty() {
        return Err(failure("add private keys through Keys before importing this configuration"));
    }
    check_runtime(&state)?;
    let actual = importer::preview_file(&prepared.source, &prepared.options)
        .map_err(|_| failure("confirmed configuration source changed; preview it again"))?;
    if actual != prepared.preview {
        return Err(failure(
            "confirmed configuration source changed; preview it again",
        ));
    }
    for (id, consent) in &prepared.copies {
        if &inspect_copy(id, &consent.source)?.0 != consent {
            return Err(failure("selected private source changed; select it again"));
        }
    }
    let id = crate::sync::slot_rules::new_slot_id()?;
    let paths = Paths::new(env, &id)?;
    if paths.dir.exists() {
        return Err(failure("import journal id is already occupied"));
    }
    let at_ms = env.now();
    let keys = prepared
        .copies
        .iter()
        .map(|(id, copy)| {
            (
                id.clone(),
                LocalKeyMetadata {
                    vault_id: id.clone(),
                    public: KeySlotPayload {
                        schema: crate::sync::records_v3::KEYSLOT_SCHEMA,
                        name: crate::sync::slot_rules::default_slot_name(
                            copy.source
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .as_ref(),
                        ),
                        public_key: copy.public_key.clone(),
                        fingerprint: copy.fingerprint.clone(),
                        key_type: copy.key_type.clone(),
                        has_passphrase: copy.has_passphrase,
                        created_at_ms: at_ms,
                        origin_device_id: state.device_id.clone(),
                    },
                },
            )
        })
        .collect();
    let mut journal = Journal {
        version: JOURNAL_VERSION,
        import_id: id,
        source: prepared.source,
        source_digest: actual.source_digest,
        source_kind: SourceKind::Files,
        material_digests: BTreeMap::new(),
        central_intent: None,
        authoritative: None,
        options: PublicOptions {
            home: prepared.options.home,
            env_digest: digest(
                &serde_json::to_vec(&prepared.options.env)
                    .map_err(|_| failure("cannot fingerprint explicit import options"))?,
            ),
            host_ids: prepared.options.host_ids,
            key_ids: prepared.options.key_ids,
        },
        provenance: actual
            .provenance
            .into_iter()
            .map(|p| Provenance {
                path: p.path,
                canonical_path: p.canonical_path,
                digest: p.digest,
            })
            .collect(),
        copies: prepared.copies,
        hosts: actual.candidates,
        keys,
        device_id: state.device_id.clone(),
        at_ms,
        phase: Phase::Prepared,
        originals_captured: false,
        original_vault_digest: None,
        staged_vault_digest: None,
        staged_key_account: None,
        completed_hosts: BTreeSet::new(),
        completed_keys: BTreeSet::new(),
    };
    overlay(&state, &journal)?;
    // First durable side effect. All later writes have this consent/mapping receipt to recover from.
    save_journal(&paths, &journal)?;
    step(PublishStep::JournalPrepared)?;
    execute(env, &paths, &mut journal, None, None).map_err(|error| {
        AppError::Other(format!(
            "confirmed import {} remains pending: {error}",
            journal.import_id
        ))
    })
}
/// Shared explicit Local material publication. Never open virtual provenance as a file.
pub(crate) fn publish_material(
    env: &SyncEnv,
    name: &str,
    mut entry: VaultEntry,
    invocation: Option<&central_local::Invocation>,
) -> Result<(ImportReceipt, KeySlotPayload), AppError> {
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (state, generation) = snapshot_for_write(env)?;
    central_local::check_request(&state, generation, invocation)?;
    let central_context = if invocation.is_some() {
        Some(central_local::Context::load(env, &state)?)
    } else {
        None
    };
    let import_id = crate::sync::slot_rules::new_slot_id()?;
    let key_id = crate::sync::slot_rules::new_slot_id()?;
    let paths = Paths::new(env, &import_id)?;
    if paths.dir.exists() {
        return Err(failure("import journal id is already occupied"));
    }
    let at_ms = env.now();
    let private = crate::vault::material::parse(&entry.private_key)
        .ok_or_else(|| failure("local private material is not readable"))?;
    let public = KeySlotPayload {
        schema: crate::sync::records_v3::KEYSLOT_SCHEMA,
        name: name.into(),
        public_key: private
            .public_key()
            .to_openssh()
            .map_err(|_| failure("local public identity is not readable"))?,
        fingerprint: private
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        key_type: private.public_key().algorithm().as_str().into(),
        has_passphrase: private.is_encrypted(),
        created_at_ms: at_ms,
        origin_device_id: invocation
            .map_or_else(|| state.device_id.clone(), |scope| scope.device_id().into()),
    };
    crate::sync::records_v3::validate_keyslot(&key_id, &public)
        .map_err(|_| failure("local key metadata is not valid"))?;
    let material_digest = digest(entry.private_key.as_bytes());
    entry.added_at_ms = at_ms;
    let central_intent = central_context
        .as_ref()
        .map(|context| context.prepare(&state, &import_id, &key_id, &public, &entry))
        .transpose()?;
    let source_digest = central_intent
        .as_ref()
        .map(|intent| intent.digest())
        .transpose()?
        .unwrap_or_else(|| material_digest.clone());
    let mut journal = Journal {
        version: JOURNAL_VERSION,
        import_id: import_id.clone(),
        source: paths.dir.join("memory-source"),
        source_digest,
        source_kind: SourceKind::Material,
        material_digests: BTreeMap::from([(key_id.clone(), material_digest)]),
        central_intent,
        authoritative: None,
        options: PublicOptions {
            home: env.state_path.parent().unwrap().into(),
            env_digest: digest(b""),
            host_ids: BTreeMap::new(),
            key_ids: BTreeMap::from([(name.into(), key_id.clone())]),
        },
        provenance: vec![],
        copies: BTreeMap::new(),
        hosts: vec![],
        keys: BTreeMap::from([(
            key_id.clone(),
            LocalKeyMetadata {
                vault_id: key_id.clone(),
                public: public.clone(),
            },
        )]),
        device_id: state.device_id.clone(),
        at_ms,
        phase: Phase::Prepared,
        originals_captured: false,
        original_vault_digest: None,
        staged_vault_digest: None,
        staged_key_account: None,
        completed_hosts: BTreeSet::new(),
        completed_keys: BTreeSet::new(),
    };
    verify_entry(&journal, &key_id, &entry)?;
    overlay(&state, &journal)?;
    save_journal(&paths, &journal)?;
    step(PublishStep::JournalPrepared)?;
    let provided = BTreeMap::from([(key_id, entry)]);
    let receipt =
        execute(env, &paths, &mut journal, Some(provided), central_context).map_err(|error| {
            AppError::Other(format!(
                "confirmed local key {} remains pending: {error}",
                journal.import_id
            ))
        })?;
    Ok((receipt, public))
}
/// Caller owns lifecycle; this activation owns vault -> publication only.
pub(crate) fn publish_synced_material(
    env: &SyncEnv,
    key_id: &str,
    public: KeySlotPayload,
    mut entry: VaultEntry,
) -> Result<ImportReceipt, AppError> {
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (state, _) = snapshot_for_write(env)?;
    if crate::sync::records_v3::account_writes_blocked(&state) {
        return Err(failure(
            "shared account writes are blocked; download requires a compatible fresh pull",
        ));
    }
    let account = state
        .account
        .as_ref()
        .ok_or_else(|| failure("download requires a joined account"))?;
    let row = account
        .records
        .get(&record_key(RecordKind::KeySlot, key_id))
        .ok_or_else(|| failure("account key metadata is not available"))?;
    let authoritative = match crate::sync::records_v3::decode_keyslot(&row.record)
        .map_err(|_| failure("account key metadata is not valid"))?
    {
        crate::sync::records_v3::TypedRecord::Live(public) => public,
        _ => return Err(failure("account key metadata was deleted")),
    };
    if authoritative != public {
        return Err(failure(
            "authoritative account key metadata changed; download it again",
        ));
    }
    let import_id = crate::sync::slot_rules::new_slot_id()?;
    let vault_id = crate::sync::slot_rules::new_slot_id()?;
    let paths = Paths::new(env, &import_id)?;
    if paths.dir.exists() {
        return Err(failure("import journal id is already occupied"));
    }
    let at_ms = env.now();
    entry.added_at_ms = at_ms;
    let material_digest = digest(entry.private_key.as_bytes());
    let mut source = Sha256::new();
    source.update(b"sshelter-explicit-key-download-v1");
    source.update(account.chain_id.as_bytes());
    source.update(
        serde_json::to_vec(&row.record)
            .map_err(|_| failure("cannot fingerprint public account metadata"))?,
    );
    source.update(material_digest.as_bytes());
    let source_digest = source
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut journal = Journal {
        version: JOURNAL_VERSION,
        import_id: import_id.clone(),
        source: paths.dir.join("download-source"),
        source_digest,
        source_kind: SourceKind::Synced,
        material_digests: BTreeMap::from([(key_id.into(), material_digest)]),
        central_intent: None,
        authoritative: Some(SyncedPrecondition {
            chain_id: account.chain_id.clone(),
            key_row: row.clone(),
            old_material: state.local.keys.get(key_id).cloned(),
        }),
        options: PublicOptions {
            home: env.state_path.parent().unwrap().into(),
            env_digest: digest(b""),
            host_ids: BTreeMap::new(),
            key_ids: BTreeMap::from([(public.name.clone(), key_id.into())]),
        },
        provenance: vec![],
        copies: BTreeMap::new(),
        hosts: vec![],
        keys: BTreeMap::from([(key_id.into(), LocalKeyMetadata { vault_id, public })]),
        device_id: state.device_id.clone(),
        at_ms,
        phase: Phase::Prepared,
        originals_captured: false,
        original_vault_digest: None,
        staged_vault_digest: None,
        staged_key_account: None,
        completed_hosts: BTreeSet::new(),
        completed_keys: BTreeSet::new(),
    };
    verify_entry(&journal, key_id, &entry)?;
    overlay(&state, &journal)?;
    save_journal(&paths, &journal)?;
    execute(
        env,
        &paths,
        &mut journal,
        Some(BTreeMap::from([(key_id.into(), entry)])),
        None,
    )
    .map_err(|error| {
        AppError::Other(format!(
            "confirmed key download {} remains pending: {error}",
            journal.import_id
        ))
    })
}

/// Resume the exact confirmed mapping; it never discovers or imports new sources on retry.
pub fn resume(env: &SyncEnv, id: &str) -> Result<ImportReceipt, AppError> {
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let paths = Paths::new(env, id)?;
    let mut journal: Journal =
        serde_json::from_slice(&bounded_read(&paths.journal, MAX_JOURNAL_BYTES)?)
            .map_err(|_| failure("import journal is not readable"))?;
    validate_journal(&journal, id)?;
    let (state, _) = snapshot_for_write(env)?;
    if journal.phase == Phase::Active && !already_applied(&state, &journal)? {
        return Err(failure(
            "active import has no matching durable state receipt",
        ));
    }
    execute(env, &paths, &mut journal, None, None)
}
fn validate_journal(journal: &Journal, id: &str) -> Result<(), AppError> {
    if journal.version != JOURNAL_VERSION
        || journal.import_id != id
        || !journal.source.is_absolute()
        || !is_digest(&journal.source_digest)
        || !is_digest(&journal.options.env_digest)
    {
        return Err(failure(
            "import journal has an unsupported or invalid header",
        ));
    }
    if journal.hosts.iter().any(|h| h.scope != HostScope::Local) {
        return Err(failure("file import journal contains a non-local host"));
    }
    if journal.source_kind == SourceKind::Files && journal.keys.len() != journal.copies.len() {
        return Err(failure("import journal has inconsistent copy consent"));
    }
    if journal.source_kind != SourceKind::Files
        && (!journal.hosts.is_empty()
            || !journal.copies.is_empty()
            || !journal.provenance.is_empty()
            || journal.keys.len() != journal.material_digests.len())
    {
        return Err(failure("material journal has inconsistent public mapping"));
    }
    for (id, key) in &journal.keys {
        crate::sync::records_v3::validate_keyslot(id, &key.public)
            .map_err(|_| failure("import journal contains invalid key metadata"))?;
        if !crate::sync::slot_rules::is_slot_id(&key.vault_id)
            || (journal.source_kind != SourceKind::Synced && key.vault_id != *id)
        {
            return Err(failure("import journal has inconsistent key mapping"));
        }
        match journal.source_kind {
            SourceKind::Files => {
                let consent = journal
                    .copies
                    .get(id)
                    .ok_or_else(|| failure("import journal has inconsistent copy consent"))?;
                if consent.key_id != *id
                    || !consent.source.is_absolute()
                    || !consent.canonical_source.is_absolute()
                    || !is_digest(&consent.digest)
                    || consent.public_key != key.public.public_key
                    || consent.fingerprint != key.public.fingerprint
                    || consent.key_type != key.public.key_type
                    || consent.has_passphrase != key.public.has_passphrase
                {
                    return Err(failure("import journal material identity is inconsistent"));
                }
            }
            SourceKind::Material | SourceKind::Synced => {
                if !journal
                    .material_digests
                    .get(id)
                    .is_some_and(|digest| is_digest(digest))
                {
                    return Err(failure("material journal is missing its confirmed digest"));
                }
            }
        }
    }
    match (&journal.authoritative, journal.source_kind) {
        (Some(authority), SourceKind::Synced) => {
            if !crate::sync::crypto::is_chain_id(&authority.chain_id)
                || journal.keys.len() != 1
                || authority.key_row.record.kind != RecordKind::KeySlot
                || authority.key_row.record.deleted
                || !journal.keys.contains_key(&authority.key_row.record.id)
            {
                return Err(failure(
                    "synced journal has invalid public authority mapping",
                ));
            }
            let public = match crate::sync::records_v3::decode_keyslot(&authority.key_row.record)
                .map_err(|_| failure("synced journal public authority is not valid"))?
            {
                crate::sync::records_v3::TypedRecord::Live(public) => public,
                _ => return Err(failure("synced journal public authority was deleted")),
            };
            if journal.keys[&authority.key_row.record.id].public != public {
                return Err(failure("synced journal public authority is inconsistent"));
            }
        }
        (None, SourceKind::Files | SourceKind::Material) => {}
        _ => {
            return Err(failure(
                "journal source kind has inconsistent authority metadata",
            ))
        }
    }
    if journal
        .staged_key_account
        .as_deref()
        .is_some_and(|a| !is_vault_account(a))
    {
        return Err(failure(
            "import journal contains an untrusted credential account",
        ));
    }
    central_local::validate_journal(&journal)?;
    Ok(())
}

fn expected_receipt(journal: &Journal) -> crate::sync::records_v3::LocalImportReceipt {
    crate::sync::records_v3::LocalImportReceipt {
        source_digest: journal.source_digest.clone(),
        host_ids: journal.hosts.iter().map(|h| h.id.clone()).collect(),
        key_ids: journal.keys.keys().cloned().collect(),
    }
}
fn already_applied(state: &SyncStateV3, journal: &Journal) -> Result<bool, AppError> {
    match state.local.import_receipts.get(&journal.import_id) {
        Some(receipt) if receipt == &expected_receipt(journal) => Ok(true),
        Some(_) => Err(failure(
            "import id conflicts with a different durable receipt",
        )),
        None => Ok(false),
    }
}
fn verify_authority(state: &SyncStateV3, journal: &Journal) -> Result<(), AppError> {
    if journal.source_kind != SourceKind::Synced {
        return Ok(());
    }
    if crate::sync::records_v3::account_writes_blocked(state) {
        return Err(failure(
            "shared account writes are blocked; download requires a compatible fresh pull",
        ));
    }
    let authority = journal
        .authoritative
        .as_ref()
        .ok_or_else(|| failure("synced journal is missing its public authority"))?;
    let account = state
        .account
        .as_ref()
        .ok_or_else(|| failure("the download account is no longer joined"))?;
    let id = &authority.key_row.record.id;
    let latest = account
        .records
        .get(&record_key(RecordKind::KeySlot, id))
        .ok_or_else(|| failure("authoritative account key metadata changed; download it again"))?;
    if account.chain_id != authority.chain_id
        || latest.record != authority.key_row.record
        || state.local.keys.get(id) != authority.old_material.as_ref()
    {
        return Err(failure(
            "authoritative account or local key metadata changed; review before retry",
        ));
    }
    let view = crate::sync::record_repository::resolve_key(state, id)
        .map_err(|_| failure("account key metadata is not available"))?;
    if matches!(
        view.status,
        crate::sync::record_repository::KeyStatus::Conflict
            | crate::sync::record_repository::KeyStatus::Deleted
    ) {
        return Err(failure(
            "local key conflicts with account identity; review is required",
        ));
    }
    Ok(())
}
fn overlay(state: &SyncStateV3, journal: &Journal) -> Result<SyncStateV3, AppError> {
    check_runtime(state)?;
    // This receipt was saved atomically with the whole import overlay. All subsequent edits,
    // moves and removals belong to the user; neither an absent row nor a tombstone is recreated.
    if already_applied(state, journal)? {
        return Ok(state.clone());
    }
    verify_authority(state, journal)?;
    let mut candidate = state.clone();
    for host in &journal.hosts {
        crate::sync::records_v3::validate_host(host)
            .map_err(|_| failure("confirmed import contains an invalid host"))?;
        let key = record_key(RecordKind::Host, &host.id);
        if state.local.hosts.contains_key(&key)
            || state
                .spaces
                .values()
                .any(|space| space.records.contains_key(&key))
        {
            return Err(failure("import host id conflicts with an existing host"));
        }
        candidate.local.hosts.insert(
            key,
            LocalRecord {
                record: Record {
                    kind: RecordKind::Host,
                    id: host.id.clone(),
                    version: 1,
                    updated_at_ms: journal.at_ms,
                    device_id: journal.device_id.clone(),
                    deleted: false,
                    payload: serde_json::to_value(&host.payload)
                        .map_err(|_| failure("cannot serialize imported host"))?,
                },
                seq: 0,
                dirty: false,
            },
        );
    }
    for (id, key) in &journal.keys {
        if journal.source_kind != SourceKind::Synced && state.local.keys.contains_key(id) {
            return Err(failure(
                "import key id conflicts with existing local material",
            ));
        }
        if journal.source_kind != SourceKind::Synced
            && state.account.as_ref().is_some_and(|account| {
                account
                    .records
                    .contains_key(&record_key(RecordKind::KeySlot, id))
            })
        {
            return Err(failure("import key id conflicts with account metadata"));
        }
        candidate.local.keys.insert(id.clone(), key.clone());
    }
    candidate
        .local
        .import_receipts
        .insert(journal.import_id.clone(), expected_receipt(journal));
    crate::sync::records_v3::validate_state(&candidate)
        .map_err(|_| failure("import overlay is not valid record state"))?;
    let existing = crate::sync::record_repository::list_hosts(state)
        .map_err(|_| failure("cannot inspect existing host identities"))?;
    for host in &journal.hosts {
        if existing
            .iter()
            .any(|h| h.host.scope == HostScope::Local && h.host.payload.alias == host.payload.alias)
        {
            return Err(failure(
                "import alias conflicts with an existing local host",
            ));
        }
    }
    crate::sync::records_v3::validate_hosts(&journal.hosts)
        .map_err(|_| failure("import host relationships are not valid"))?;
    Ok(candidate)
}
/// Only recognized vault accounts can cross this adapter. New writes stay in the import namespace.
struct ScopedKeychain<'a> {
    inner: &'a dyn Keychain,
    import_id: &'a str,
    receipts: &'a Path,
}
impl ScopedKeychain<'_> {
    fn scoped(&self, account: &str) -> Result<String, AppError> {
        if !is_vault_account(account) {
            return Err(failure("untrusted staged vault credential account"));
        }
        Ok(format!("migration:{}:{account}", self.import_id))
    }
    fn promote(&self, account: &str) -> Result<(), AppError> {
        let scoped = self.scoped(account)?;
        let staged = self
            .inner
            .get(&scoped)
            .map_err(|_| failure("cannot read staged vault master credential"))?
            .map(Zeroizing::new);
        let Some(staged) = staged else {
            return Ok(());
        };
        match self
            .inner
            .get(account)
            .map_err(|_| failure("cannot inspect vault master promotion destination"))?
            .map(Zeroizing::new)
        {
            Some(existing) if *existing != *staged => {
                return Err(failure(
                    "vault master promotion destination contains a different credential",
                ))
            }
            Some(_) => return Ok(()),
            None => {}
        }
        self.inner
            .set(account, &staged)
            .map_err(|_| failure("cannot promote staged vault master credential"))?;
        if self
            .inner
            .get(account)
            .map_err(|_| failure("cannot verify vault master promotion"))?
            .map(Zeroizing::new)
            .as_ref()
            .map(|s| s.as_str())
            != Some(staged.as_str())
        {
            return Err(failure("vault master promotion was not retained"));
        }
        Ok(())
    }
}
impl Keychain for ScopedKeychain<'_> {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        let scoped = self.scoped(account)?;
        if let Some(secret) = self
            .inner
            .get(&scoped)
            .map_err(|_| failure("cannot read staged vault credential"))?
        {
            return Ok(Some(secret));
        }
        self.inner
            .get(account)
            .map_err(|_| failure("cannot read original vault credential"))
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        let scoped = self.scoped(account)?;
        if self
            .inner
            .get(account)
            .map_err(|_| failure("cannot inspect original vault credential"))?
            .map(Zeroizing::new)
            .is_some_and(|existing| existing.as_str() != secret)
        {
            return Err(failure(
                "new staged vault account conflicts with an original credential",
            ));
        }
        if self
            .inner
            .get(&scoped)
            .map_err(|_| failure("cannot inspect staged vault credential"))?
            .map(Zeroizing::new)
            .is_some_and(|existing| existing.as_str() != secret)
        {
            return Err(failure(
                "staged vault account contains a different credential",
            ));
        }
        let mut accounts: BTreeSet<String> = match optional_bytes(self.receipts, MAX_JOURNAL_BYTES)?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| failure("staged master receipt is not readable"))?,
            None => BTreeSet::new(),
        };
        accounts.insert(account.into());
        fsutil::atomic_write(
            self.receipts,
            &serde_json::to_vec(&accounts)
                .map_err(|_| failure("cannot serialize staged master receipt"))?,
            0o600,
        )?;
        self.inner
            .set(&scoped, secret)
            .map_err(|_| failure("cannot save staged vault master credential"))?;
        if self.inner.get(&scoped)
            .map_err(|_| failure("cannot verify staged vault master credential"))?
            .map(Zeroizing::new).as_ref().map(|saved|saved.as_str()) != Some(secret) {
            return Err(failure("staged vault master credential was not retained"));
        }
        Ok(())
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        Err(failure("import cannot delete a credential"))
    }
}
fn validate_vault(path: &Path, keychain: &dyn Keychain) -> Result<store::ReadOnlyVault, AppError> {
    let vault = store::read_vault(path, keychain)
        .map_err(|_| failure("vault is not readable; original retained"))?;
    for id in vault.ids() {
        vault
            .get(&id)
            .map_err(|_| failure("vault entry is not readable; original retained"))?;
    }
    Ok(vault)
}
fn stage(
    env: &SyncEnv,
    paths: &Paths,
    journal: &mut Journal,
    provided: Option<BTreeMap<String, VaultEntry>>,
) -> Result<(), AppError> {
    source_unchanged(journal)?;
    let (state, _) = snapshot_for_write(env)?;
    let candidate = overlay(&state, journal)?;
    let mut entries = Vec::new();
    match journal.source_kind {
        SourceKind::Files => {
            for (id, consent) in &journal.copies {
                let (actual, mut entry) = inspect_copy(id, &consent.source)?;
                if &actual != consent {
                    return Err(failure("selected private source changed; select it again"));
                }
                entry.added_at_ms = journal.at_ms;
                entries.push((id.clone(), entry));
            }
        }
        SourceKind::Material | SourceKind::Synced => {
            let staged = if provided.is_none() {
                let scoped = ScopedKeychain {
                    inner: env.keychain,
                    import_id: &journal.import_id,
                    receipts: &paths.masters,
                };
                if !paths.vault.exists() {
                    return Err(failure(
                        "local key material was not durably staged; provide it again",
                    ));
                }
                Some(validate_vault(&paths.vault, &scoped)?)
            } else {
                None
            };
            let mut provided = provided.unwrap_or_default();
            for id in journal.keys.keys() {
                let mut entry = match provided.remove(id) {
                    Some(entry) => entry,
                    None => staged
                        .as_ref()
                        .ok_or_else(|| {
                            failure("local key material was not durably staged; provide it again")
                        })?
                        .get(&journal.keys[id].vault_id)
                        .map_err(|_| failure("staged local key material is not readable"))?
                        .ok_or_else(|| {
                            failure("local key material was not durably staged; provide it again")
                        })?,
                };
                entry.added_at_ms = journal.at_ms;
                verify_entry(journal, id, &entry)?;
                entries.push((id.clone(), entry));
            }
        }
    }
    // All original entries decrypt before the stage writer can perform its archival behavior.
    let original = if entries.is_empty() {
        None
    } else {
        validate_vault(&store::vault_path(&env.state_path), env.keychain)?;
        optional_bytes(
            &store::vault_path(&env.state_path),
            store::MAX_READ_ONLY_VAULT_BYTES,
        )?
    };
    let original_digest = original.as_ref().map(|bytes| digest(bytes));
    if journal.originals_captured {
        if !entries.is_empty() && original_digest != journal.original_vault_digest {
            return Err(failure(
                "original vault changed after staging began; import retained for recovery",
            ));
        }
    } else {
        // Persist the baseline before any stage writer or backup. A crash cannot adopt a newer
        // original vault while retaining an older partial stage, then publish the incomplete copy.
        journal.original_vault_digest = original_digest;
        journal.originals_captured = true;
        save_journal(paths, journal)?;
    }
    let original_state = optional_bytes(&env.state_path, record_runtime::MAX_STATE_BYTES)?;
    if let Some(bytes) = original_state {
        if !paths.original_state.exists() {
            fsutil::atomic_write(&paths.original_state, &bytes, 0o600)?;
        }
    }
    if let Some(bytes) = &original {
        if !paths.original_vault.exists() {
            fsutil::atomic_write(&paths.original_vault, bytes, 0o600)?;
        }
    }
    record_runtime::save_active(&paths.state, &candidate)?;
    if !entries.is_empty() {
        // A partially staged writer file is validated read-only too; never repair/rename a stage.
        let scoped = ScopedKeychain {
            inner: env.keychain,
            import_id: &journal.import_id,
            receipts: &paths.masters,
        };
        if paths.vault.exists() {
            validate_vault(&paths.vault, &scoped)?;
        } else if let Some(bytes) = &original {
            fsutil::atomic_write(&paths.vault, bytes, 0o600)?;
            validate_vault(&paths.vault, &scoped)?;
        }
        let mut vault = Vault::open(&paths.vault, &scoped, journal.at_ms)
            .map_err(|_| failure("cannot open validated staged vault"))?;
        let mut batch = BTreeMap::new();
        for (id, entry) in entries {
            if batch.insert(journal.keys[&id].vault_id.clone(),entry).is_some() {
                return Err(failure("import maps multiple keys onto the same protected vault ID"));
            }
        }
        vault.put_new_batch(&scoped,&batch)
            .map_err(|_| failure("cannot save material batch in staged vault; original retained"))?;
        let staged = validate_vault(&paths.vault, &scoped)?;
        journal.staged_key_account = Some(staged.key_account().into());
        journal.staged_vault_digest = Some(digest(&bounded_read(
            &paths.vault,
            store::MAX_READ_ONLY_VAULT_BYTES,
        )?));
    }
    step(PublishStep::VaultStaged)?;
    journal.phase = Phase::Staged;
    save_journal(paths, journal)?;
    step(PublishStep::Staged)
}
fn verify_entry(journal: &Journal, id: &str, entry: &VaultEntry) -> Result<(), AppError> {
    let metadata = journal
        .keys
        .get(id)
        .ok_or_else(|| failure("import journal has inconsistent key mapping"))?;
    let expected_digest = match journal.source_kind {
        SourceKind::Files => journal
            .copies
            .get(id)
            .map(|consent| consent.digest.as_str()),
        SourceKind::Material | SourceKind::Synced => journal
            .material_digests
            .get(id)
            .map(|digest| digest.as_str()),
    }
    .ok_or_else(|| failure("import journal has inconsistent material consent"))?;
    let private = crate::vault::material::parse(&entry.private_key)
        .ok_or_else(|| failure("import private material is not readable"))?;
    if private.is_encrypted() != metadata.public.has_passphrase
        || Some(private.public_key().key_data().clone())
            != crate::vault::material::public_key_data(&metadata.public.public_key)
        || crate::sync::records_v3::key_material_matches(
            &metadata.public,
            &entry.public_key,
            &entry.fingerprint,
        )
        .is_err()
        || digest(entry.private_key.as_bytes()) != expected_digest
    {
        return Err(failure(
            "import material identity changed; import retained for recovery",
        ));
    }
    Ok(())
}
fn verify_material(vault: &store::ReadOnlyVault, journal: &Journal) -> Result<(), AppError> {
    for (id, metadata) in &journal.keys {
        let entry = vault
            .get(&metadata.vault_id)
            .map_err(|_| failure("published import material is not readable"))?
            .ok_or_else(|| {
                failure("published import material was removed; import retained for recovery")
            })?;
        verify_entry(journal, id, &entry)?;
    }
    Ok(())
}
fn verify_published_material(env: &SyncEnv, journal: &Journal) -> Result<(), AppError> {
    if journal.keys.is_empty() {
        return Ok(());
    }
    let vault = validate_vault(&store::vault_path(&env.state_path), env.keychain)?;
    verify_material(&vault, journal)
}
fn execute(
    env: &SyncEnv,
    paths: &Paths,
    journal: &mut Journal,
    mut provided: Option<BTreeMap<String, VaultEntry>>,
    prepared_context: Option<central_local::Context>,
) -> Result<ImportReceipt, AppError> {
    // The state receipt is the publication proof even if the separate journal phase was lost.
    // Do not read/rewrite old sources or vault material after the user has edited completed data.
    if already_applied(&snapshot_for_write(env)?.0, journal)? {
        if journal.phase != Phase::Active {
            journal
                .completed_hosts
                .extend(journal.hosts.iter().map(|host| host.id.clone()));
            journal.completed_keys.extend(journal.keys.keys().cloned());
            journal.phase = Phase::Active;
            save_journal(paths, journal)?;
        }
        return Ok(journal.receipt());
    }
    if journal.phase == Phase::Active {
        return Err(failure("active import has no matching durable state receipt"));
    }
    let central_context = match prepared_context {
        Some(context) => Some(context),
        None => central_local::context(env, &snapshot_for_write(env)?.0, journal)?,
    };
    if journal.phase == Phase::Prepared {
        if provided.is_none() {
            if let Some(context) = central_context.as_ref() {
                provided = Some(context.recover(env, &snapshot_for_write(env)?.0, journal)?);
            }
        }
        stage(env, paths, journal, provided)?;
    }
    if journal.phase == Phase::Staged {
        overlay(&snapshot_for_write(env)?.0, journal)?;
        if !journal.keys.is_empty() {
            let bytes = bounded_read(&paths.vault, store::MAX_READ_ONLY_VAULT_BYTES)?;
            if journal.staged_vault_digest.as_deref() != Some(digest(&bytes).as_str()) {
                return Err(failure(
                    "staged vault changed; import retained for recovery",
                ));
            }
            let scoped = ScopedKeychain {
                inner: env.keychain,
                import_id: &journal.import_id,
                receipts: &paths.masters,
            };
            let staged = validate_vault(&paths.vault, &scoped)?;
            verify_material(&staged, journal)?;
            if journal.staged_key_account.as_deref() != Some(staged.key_account()) {
                return Err(failure("staged vault account changed"));
            }
            let main = store::vault_path(&env.state_path);
            let current = optional_bytes(&main, store::MAX_READ_ONLY_VAULT_BYTES)?
                .as_ref()
                .map(|b| digest(b));
            if current != journal.original_vault_digest && current != journal.staged_vault_digest {
                return Err(failure(
                    "original vault changed; import retained for recovery",
                ));
            }
            if let Some(context) = central_context.as_ref() {
                central_local::before_vault(env, &snapshot_for_write(env)?.0, journal, paths, context)?;
            }
            scoped.promote(staged.key_account())?;
            if let Some(context) = central_context.as_ref() {
                central_local::before_vault(env, &snapshot_for_write(env)?.0, journal, paths, context)?;
            }
            step(PublishStep::MasterPromoted)?;
            if let Some(context) = central_context.as_ref() {
                central_local::before_vault(env, &snapshot_for_write(env)?.0, journal, paths, context)?;
            }
            if central_context.is_some() {
                central_stage::publish_vault_image(env, paths, &journal.original_vault_digest,
                    journal.staged_vault_digest.as_deref().ok_or_else(|| failure("central local vault receipt is missing"))?)?;
            } else if current != journal.staged_vault_digest {
                fsutil::atomic_write(&main, &bytes, 0o600)?;
            }
            step(PublishStep::VaultSaved)?;
        }
        journal.phase = Phase::VaultPublished;
        save_journal(paths, journal)?;
    }
    if already_applied(&snapshot_for_write(env)?.0, journal)? {
        journal
            .completed_hosts
            .extend(journal.hosts.iter().map(|h| h.id.clone()));
        journal.completed_keys.extend(journal.keys.keys().cloned());
        journal.phase = Phase::Active;
        save_journal(paths, journal)?;
        return Ok(journal.receipt());
    }
    verify_published_material(env, journal)?;
    if let Some(context) = central_context.as_ref() {
        central_local::publish(env, journal, context)?;
        journal.completed_keys.extend(journal.keys.keys().cloned());
        journal.phase = Phase::Active;
        save_journal(paths, journal)?;
        return Ok(journal.receipt());
    }
    for _ in 0..MAX_COMMIT_ATTEMPTS {
        let (state, generation) = snapshot_for_write(env)?;
        let candidate = overlay(&state, journal)?;
        // Retain the exact candidate before a separate main-state publication attempt.
        record_runtime::save_active(&paths.state, &candidate)?;
        step(PublishStep::BeforeStateSave)?;
        match record_runtime::commit_candidate(env, generation, candidate) {
            Err(error) if crate::sync::runtime::is_superseded(&error) => continue,
            Err(error) => return Err(error),
            Ok(_) => {
                step(PublishStep::StateSaved)?;
                journal
                    .completed_hosts
                    .extend(journal.hosts.iter().map(|h| h.id.clone()));
                journal.completed_keys.extend(journal.keys.keys().cloned());
                journal.phase = Phase::Active;
                save_journal(paths, journal)?;
                return Ok(journal.receipt());
            }
        }
    }
    Err(failure(
        "record state kept changing; confirmed import is retained for retry",
    ))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublishStep {
    JournalPrepared,
    VaultStaged,
    Staged,
    MasterPromoted,
    VaultSaved,
    BeforeStateSave,
    StateSaved,
}
fn step(value: PublishStep) -> Result<(), AppError> {
    #[cfg(test)]
    {
        return TEST_STEP.with(|hook| {
            let mut hook = hook.borrow_mut();
            match hook.as_mut() {
                Some(callback) => callback(value),
                None => Ok(()),
            }
        });
    }
    #[cfg(not(test))]
    {
        let _ = value;
        Ok(())
    }
}
#[cfg(test)]
thread_local! { static TEST_STEP:std::cell::RefCell<Option<Box<dyn FnMut(PublishStep)->Result<(),AppError>>>>=const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
pub(crate) fn with_test_step<T>(
    hook: impl FnMut(PublishStep) -> Result<(), AppError> + 'static,
    f: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Box<dyn FnMut(PublishStep) -> Result<(), AppError>>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_STEP.with(|hook| *hook.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(TEST_STEP.with(|slot| slot.replace(Some(Box::new(hook)))));
    f()
}
#[cfg(test)]
#[path = "record_import_tests.rs"]
mod tests;
