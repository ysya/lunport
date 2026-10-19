//! Central-only inert protected staging, using the existing import paths/credential namespace.
//! Does not publish the active vault, ledger, keys, owner or session. Final typed publication follows.
use super::{
    bounded_read, digest, failure, optional_bytes, validate_vault, Paths, PendingImport,
    ScopedKeychain, MAX_JOURNAL_BYTES,
};
use crate::{
    error::AppError,
    sync::{
        central::{
            self,
            membership::{Device, TrustAnchor},
            rekey::Checkpoint,
            wire::hex,
            LibraryDelta,
        },
        env::SyncEnv,
        record_runtime,
        records_v3::SyncStateV3,
    },
    vault::store::{self, EntryOrigin, Vault, VaultEntry},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
const FORMAT: &str = "lunport-central-library-stage-v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Staged,
    VaultPublished,
    Active,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    id: String,
    protected_id: String,
    public_digest: String,
    private_digest: String,
    sha256: String,
    rebind: bool,
    old_material: Option<crate::sync::records_v3::LocalKeyMetadata>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: String,
    operation: String,
    anchor: TrustAnchor,
    profile: central::client_state::ProfileData,
    device: Device,
    identity_slot: Option<String>,
    vault: String,
    checkpoint: Checkpoint,
    at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initial: Option<input::InitialBinding>,
    source_state_digest: Option<String>,
    source_vault_digest: Option<String>,
    staged_vault_digest: Option<String>,
    staged_key_account: Option<String>,
    bindings: BTreeMap<String, Binding>,
    phase: Phase,
}
#[cfg(test)]
mod initial_tests;
/// Native capability to an immutable staged image; no Serialize/Debug/Clone or active publication.
pub(in crate::sync::record_import) mod inventory;
mod input;
mod initial_effects;
mod initial_publish;
pub(in crate::sync) use initial_publish::{
    complete_saved as complete_initial_saved, publish as publish_initial,
    Publication as InitialPublication,
};
pub(in crate::sync) use initial_effects::{InitialEffects, read as initial_effects, read_locked as initial_effects_locked};
use input::Input;
pub(crate) use input::{prepare as prepare_initial, prepare_reserved as prepare_initial_reserved, resume as resume_initial};
mod publication;
pub(super) use publication::publish_vault_image;
pub(crate) use publication::{publish, Publication};

pub(crate) struct Staged {
    journal: Journal,
    paths: Paths,
}
impl Staged {
    pub fn operation(&self) -> &str {
        &self.journal.operation
    }
    pub fn mapping(&self) -> BTreeMap<String, String> {
        self.journal
            .bindings
            .iter()
            .map(|(id, b)| (id.clone(), b.protected_id.clone()))
            .collect()
    }
    pub fn summary(&self) -> PendingImport {
        summary(&self.journal)
    }
}
fn summary(journal: &Journal) -> PendingImport {
    PendingImport {
        import_id: journal.operation.clone(),
        phase: match journal.phase {
            Phase::Prepared => "central_prepared",
            Phase::Staged => "central_staged",
            Phase::VaultPublished => "central_vault_published",
            Phase::Active => "central_active",
        }
        .into(),
        host_count: 0,
        key_count: journal.bindings.len(),
    }
}
pub(super) fn pending(
    env: &SyncEnv,
    id: &str,
    bytes: &[u8],
) -> Result<Option<PendingImport>, AppError> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if value.get("format").and_then(|v| v.as_str()) != Some(FORMAT) {
        return Ok(None);
    }
    let journal: Journal = serde_json::from_slice(bytes)
        .map_err(|_| failure("central stage journal is unreadable; retained for recovery"))?;
    validate_header(&journal, id)?;
    let mut status = summary(&journal);
    if journal.phase != Phase::Prepared {
        // Clone only this public receipt, not an entire ciphertext library per journal entry.
        let receipt = {
            let core = env.runtime.core.lock().unwrap();
            record_runtime::active_state(&core)
                .ok()
                .and_then(|state| state.local.import_receipts.get(id).cloned())
        };
        let proven = if journal.initial.is_some(){initial_publish::matches_receipt(receipt.as_ref(),&journal)?}else{publication::matches_receipt(receipt.as_ref(),&journal)?};
        if proven {
            status.phase = "central_active".into();
        } else if journal.phase == Phase::Active {
            status.phase = "central_missing_receipt".into();
        }
    }
    Ok(Some(status))
}
fn validate_header(j: &Journal, id: &str) -> Result<(), AppError> {
    j.profile.profile()?;
    if let Some(initial) = &j.initial {
        initial.validate()?;
    }
    j.device.keys.validate()?;
    if j.anchor.origin != j.profile.origin
        || !hex(&j.anchor.account_id, 64)
        || !hex(&j.anchor.genesis_hash, 64)
        || !hex(&j.device.id, 32)
        || j.format != FORMAT
        || j.operation != id
        || !hex(id, 32)
        || !hex(&j.vault, 64)
        || j.source_state_digest.as_ref().is_some_and(|d| !hex(d, 64))
        || j.source_vault_digest.as_ref().is_some_and(|d| !hex(d, 64))
        || j.staged_vault_digest.as_ref().is_some_and(|d| !hex(d, 64))
        || j.identity_slot.as_ref().is_some_and(|id| !hex(id, 32))
        || j.bindings.len() > 4096
        || j.at_ms > central::wire::MAX_SAFE_INTEGER
        || j.checkpoint.epoch == 0
        || j.checkpoint.epoch > 65
        || j.checkpoint.sequence > 16384
        || !hex(&j.checkpoint.history_hash, 64)
    {
        return Err(failure("central stage journal has invalid public metadata"));
    }
    let mut slots = BTreeSet::new();
    for (id, b) in &j.bindings {
        if id != &b.id
            || !hex(id, 32)
            || !hex(&b.protected_id, 32)
            || !hex(&b.public_digest, 64)
            || !hex(&b.private_digest, 64)
            || !hex(&b.sha256, 64)
            || !slots.insert(&b.protected_id)
            || b.rebind
                && b.old_material
                    .as_ref()
                    .is_none_or(|old| old.vault_id != b.protected_id)
            || b.old_material.as_ref().is_some_and(|old| {
                !hex(&old.vault_id, 32)
                    || crate::sync::records_v3::validate_keyslot(id, &old.public).is_err()
            })
        {
            return Err(failure("central stage has invalid material mapping"));
        }
    }
    match j.phase {
        Phase::Prepared if j.staged_vault_digest.is_none() && j.staged_key_account.is_none() => {}
        Phase::Staged | Phase::VaultPublished | Phase::Active
            if j.source_state_digest.is_some()
                && ((j.staged_vault_digest.is_some()
                    && j.staged_key_account
                        .as_deref()
                        .is_some_and(super::is_vault_account))
                    || (j.bindings.is_empty()
                        && j.staged_vault_digest.is_none()
                        && j.staged_key_account.is_none())) => {}
        _ => return Err(failure("central stage has inconsistent durable phase")),
    }
    Ok(())
}
fn source(state: &SyncStateV3) -> Result<(), AppError> {
    crate::sync::records_v3::validate_state(state)
        .map_err(|_| failure("central stage source is not valid Records state"))?;
    let owner = state
        .local
        .central
        .as_ref()
        .ok_or_else(|| failure("central stage has no account owner"))?;
    let account = state
        .account
        .as_ref()
        .ok_or_else(|| failure("central stage has no public library cache"))?;
    if !owner.control.cutover
        || !owner.can_upload()
        || state.local.central_projection.is_none()
        || state.legacy_v1_backup.is_some()
        || state.pending_account.is_some()
        || state.rotation.is_some()
        || state.migration_gate.is_some()
        || !account.sealed.is_empty()
        || !account.chain_deletes.is_empty()
        || !account.recovery.is_empty()
        || state
            .spaces
            .values()
            .any(|space| !space.sealed.is_empty() || !space.recovery.is_empty())
    {
        return Err(failure(
            "finish central inventory and legacy migration before staging material",
        ));
    }
    Ok(())
}
fn saved_source(env: &SyncEnv, input: Input<'_>) -> Result<zeroize::Zeroizing<Vec<u8>>, AppError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let directory = env
            .state_path
            .parent()
            .ok_or_else(|| failure("central state has no data directory"))?;
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(failure(
                "central material staging requires a private owned data directory",
            ));
        }
    }
    let (live, _) = record_runtime::snapshot(env)?;
    if &live != input.source() {
        return Err(failure(
            "central source changed; rebuild from the latest library before staging",
        ));
    }
    input.validate_source(&live)?;
    let bytes = bounded_read(&env.state_path, record_runtime::MAX_STATE_BYTES)?;
    let disk: SyncStateV3 = serde_json::from_slice(&bytes)
        .map_err(|_| failure("cannot validate saved central source"))?;
    if disk != live {
        return Err(failure(
            "saved central source differs; retain pending stage and reload the library",
        ));
    }
    Ok(bytes)
}
/// Only stage/journal files use this helper. The active-state writer must separately handle
/// uncertain post-rename errors by blocking Core/session; this function grants no such authority.
pub(super) fn durable(paths: &Paths, path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    #[cfg(not(unix))]
    {
        let _ = (paths, path, bytes);
        return Err(failure("central material staging needs the verified secure file implementation on this platform"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fsutil_check(path)?;
        crate::fsutil::ensure_dir_secure(&paths.dir)?;
        crate::fsutil::atomic_write(path, bytes, 0o600)?;
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(failure("central stage output must be a regular file"));
        }
        file.sync_all()?;
        for directory in [
            Some(paths.dir.as_path()),
            paths.dir.parent(),
            paths.dir.parent().and_then(Path::parent),
        ]
        .into_iter()
        .flatten()
        {
            fs::File::open(directory)?.sync_all()?;
        }
        if bounded_read(path, bytes.len() as u64)?.as_slice() != bytes {
            return Err(failure("central stage readback differs; original retained"));
        }
        Ok(())
    }
}
fn fsutil_check(path: &Path) -> Result<(), AppError> {
    crate::fsutil::check_write(path)?;
    match fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() || m.file_type().is_symlink() => {
            Err(failure("central stage destination is not a regular file"))
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}
fn save(paths: &Paths, journal: &Journal) -> Result<(), AppError> {
    validate_header(journal, &journal.operation)?;
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|_| failure("cannot encode central stage journal"))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(failure("central stage journal exceeds its limit"));
    }
    durable(paths, &paths.journal, &bytes)
}
fn verify_delta(j: &Journal, input: Input<'_>) -> Result<(), AppError> {
    input.verify_binding(j.initial.as_ref())?;
    let delta = input.delta();
    let state = delta.before();
    source(state)?;
    let owner = state.local.central.as_ref().unwrap();
    let replica = owner.replica.as_ref().unwrap();
    if owner.control.profile != j.profile
        || owner.control.anchor.as_ref() != Some(&j.anchor)
        || owner.control.device != j.device
        || owner.identity_slot != j.identity_slot
        || replica.vault != j.vault
        || replica.checkpoint.epoch != j.checkpoint.epoch
        || replica.checkpoint.sequence < j.checkpoint.sequence
        || replica.checkpoint.sequence == j.checkpoint.sequence
            && replica.checkpoint.history_hash != j.checkpoint.history_hash
        || delta.required_material().iter().collect::<BTreeSet<_>>()
            != j.bindings.keys().collect::<BTreeSet<_>>()
    {
        return Err(failure(
            "central stage scope or baseline changed; staged material is retained",
        ));
    }
    for (id, b) in &j.bindings {
        let material = delta
            .plan()
            .materials()
            .get(id)
            .ok_or_else(|| failure("central stage material is no longer admitted"))?;
        if state.local.keys.get(id) != b.old_material.as_ref()
            || material.public_receipt.envelope_digest != b.public_digest
            || material.private_receipt.envelope_digest != b.private_digest
            || material.private().digest() != b.sha256
        {
            return Err(failure(
                "central stage material version changed; original retained",
            ));
        }
    }
    Ok(())
}
/// Inert staging only. No active vault promotion, public repository write, session switch or HTTP.
pub(crate) fn prepare(env: &SyncEnv, delta: &LibraryDelta) -> Result<Staged, AppError> {
    prepare_input(env, Input::Library(delta))
}
fn prepare_input(env: &SyncEnv, input: Input<'_>) -> Result<Staged, AppError> {
    prepare_with_reservation(env,input,None)
}
fn prepare_with_reservation(env:&SyncEnv,input:Input<'_>,reservation:Option<(&dyn central::InitialTransaction,&central::crypto::VaultKeys)>)->Result<Staged,AppError>{
    let delta = input.delta();
    if !cfg!(unix) {
        return Err(failure(
            "central material staging is not verified on this platform",
        ));
    }
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    if let Some((prepared,keys))=reservation {
        if !matches!(input,Input::Initial(_)) || input.binding()?!=Input::Initial(prepared.projection()).binding()? {return Err(failure("initial stage reservation does not match its projection"));}
        prepared.check_locked(env,keys,&_lifecycle)?;
    }
    drop(saved_source(env, input)?);
    if !super::pending_imports(env)?.is_empty() {
        return Err(failure(
            "resume the existing pending import or central stage before creating another",
        ));
    }
    if !delta.has_changes() && !matches!(input, Input::Initial(_)) {
        return Err(failure("no central library delta needs publication"));
    }
    let original_path = store::vault_path(&env.state_path);
    let original = optional_bytes(&original_path, store::MAX_READ_ONLY_VAULT_BYTES)?;
    let view = validate_vault(&original_path, env.keychain)?;
    if optional_bytes(&original_path, store::MAX_READ_ONLY_VAULT_BYTES)?
        .as_ref()
        .map(|b| digest(b))
        != original.as_ref().map(|b| digest(b))
    {
        return Err(failure("source vault changed during preflight"));
    }
    let operation = match reservation {Some((prepared,_))=>prepared.operation().to_string(),None=>central::crypto::random_id(16)?};
    let paths = Paths::new(env, &operation)?;
    if paths.dir.exists() {
        return Err(failure("central stage ID is already occupied"));
    }
    let mut occupied: BTreeSet<_> = view.ids().into_iter().collect();
    let state = delta.before();
    let ledger = state.local.central_projection.as_ref().unwrap();
    let owner = state.local.central.as_ref().unwrap();
    let mut bindings = BTreeMap::new();
    for id in delta.required_material() {
        let material = delta
            .plan()
            .materials()
            .get(id)
            .ok_or_else(|| failure("material pair is incomplete"))?;
        let rebind = if let Some(old) = state.local.keys.get(id) {
            let entry = view
                .get(&old.vault_id)
                .map_err(|_| failure("old source material is unreadable"))?
                .ok_or_else(|| failure("old source material is missing"))?;
            ledger.verify_source_material(owner, id, old, &entry)?;
            central::crypto::hash(entry.private_key.as_bytes()) == material.private().digest()
        } else {
            false
        };
        let protected_id = if rebind {
            state.local.keys[id].vault_id.clone()
        } else {
            let id = central::crypto::random_id(16)?;
            if !occupied.insert(id.clone()) {
                return Err(failure("new protected material ID collided"));
            }
            id
        };
        bindings.insert(
            id.clone(),
            Binding {
                id: id.clone(),
                protected_id,
                public_digest: material.public_receipt.envelope_digest.clone(),
                private_digest: material.private_receipt.envelope_digest.clone(),
                sha256: material.private().digest(),
                rebind,
                old_material: state.local.keys.get(id).cloned(),
            },
        );
    }
    let mut journal = Journal {
        format: FORMAT.into(),
        operation,
        anchor: owner.control.anchor.clone().unwrap(),
        profile: owner.control.profile.clone(),
        device: owner.control.device.clone(),
        identity_slot: owner.identity_slot.clone(),
        vault: owner.replica.as_ref().unwrap().vault.clone(),
        checkpoint: owner.replica.as_ref().unwrap().checkpoint.clone(),
        at_ms: env.now(),
        initial: input.binding()?,
        source_state_digest: None,
        source_vault_digest: original.as_ref().map(|b| digest(b)),
        staged_vault_digest: None,
        staged_key_account: None,
        bindings,
        phase: Phase::Prepared,
    };
    if let Some((prepared,keys))=reservation {prepared.check_locked(env,keys,&_lifecycle)?;}
    save(&paths, &journal)?;
    super::step(super::PublishStep::JournalPrepared)?;
    execute(env, &paths, &mut journal, input)?;
    Ok(Staged { journal, paths })
}
fn execute(
    env: &SyncEnv,
    paths: &Paths,
    journal: &mut Journal,
    input: Input<'_>,
) -> Result<(), AppError> {
    verify_delta(journal, input)?;
    let delta = input.delta();
    if journal.source_state_digest.is_none() {
        let original_state = if paths.original_state.exists() {
            bounded_read(&paths.original_state, record_runtime::MAX_STATE_BYTES)?
        } else {
            // No material/credential effects occur before this durable source snapshot. A new
            // unrelated B can be supplied by a rebuilt Delta on retry under the same operation.
            let bytes = saved_source(env, input)?;
            durable(paths, &paths.original_state, &bytes)?;
            bytes
        };
        let archived: SyncStateV3 = serde_json::from_slice(&original_state)
            .map_err(|_| failure("central stage source snapshot is unreadable"))?;
        input.validate_source(&archived)?;
        let owner = if journal.initial.is_some() {
            delta.before().local.central.as_ref().unwrap()
        } else {
            archived.local.central.as_ref().unwrap()
        };
        if owner.control.profile != journal.profile
            || owner.control.anchor.as_ref() != Some(&journal.anchor)
            || owner.control.device != journal.device
            || owner.identity_slot != journal.identity_slot
            || journal.initial.is_none()
                && journal
                    .bindings
                    .iter()
                    .any(|(id, b)| archived.local.keys.get(id) != b.old_material.as_ref())
        {
            return Err(failure(
                "central stage source snapshot has a different owner or material",
            ));
        }
        if journal.source_vault_digest.is_some() && !paths.original_vault.exists() {
            let bytes = bounded_read(
                &store::vault_path(&env.state_path),
                store::MAX_READ_ONLY_VAULT_BYTES,
            )?;
            if journal.source_vault_digest.as_ref() != Some(&digest(&bytes)) {
                return Err(failure("source vault changed before archive capture"));
            }
            durable(paths, &paths.original_vault, &bytes)?;
        }
        let replica = owner.replica.as_ref().unwrap();
        if replica.vault != journal.vault
            || replica.checkpoint.epoch != journal.checkpoint.epoch
            || replica.checkpoint.sequence < journal.checkpoint.sequence
            || replica.checkpoint.sequence == journal.checkpoint.sequence
                && replica.checkpoint.history_hash != journal.checkpoint.history_hash
            || journal.bindings.iter().any(|(id, b)| {
                let material = &delta.plan().materials()[id];
                replica
                    .current
                    .get(&material.public_receipt.opaque)
                    .is_none_or(|base| base.version.digest != b.public_digest)
                    || replica
                        .current
                        .get(&material.private_receipt.opaque)
                        .is_none_or(|base| base.version.digest != b.private_digest)
            })
        {
            return Err(failure(
                "central source snapshot does not contain the fixed material baseline",
            ));
        }
        journal.source_state_digest = Some(digest(&original_state));
        save(paths, journal)?;
    }
    if Some(digest(&bounded_read(
        &paths.original_state,
        record_runtime::MAX_STATE_BYTES,
    )?)) != journal.source_state_digest
    {
        return Err(failure("central stage source snapshot changed"));
    }
    let active = optional_bytes(
        &store::vault_path(&env.state_path),
        store::MAX_READ_ONLY_VAULT_BYTES,
    )?
    .as_ref()
    .map(|bytes| digest(bytes));
    if active != journal.source_vault_digest
        && (journal.staged_vault_digest.is_none() || active != journal.staged_vault_digest)
    {
        return Err(failure(
            "active vault changed; pending central stage retained",
        ));
    }
    if optional_bytes(&paths.original_vault, store::MAX_READ_ONLY_VAULT_BYTES)?
        .as_ref()
        .map(|b| digest(b))
        != journal.source_vault_digest
    {
        return Err(failure("central stage original vault snapshot changed"));
    }
    let scoped = ScopedKeychain {
        inner: env.keychain,
        import_id: &journal.operation,
        receipts: &paths.masters,
    };
    if journal.phase == Phase::Prepared {
        if paths.vault.exists() {
            validate_vault(&paths.vault, &scoped)?;
        } else if let Some(bytes) =
            optional_bytes(&paths.original_vault, store::MAX_READ_ONLY_VAULT_BYTES)?
        {
            durable(paths, &paths.vault, &bytes)?;
        }
        let mut batch = BTreeMap::new();
        for (id, b) in &journal.bindings {
            if b.rebind {
                continue;
            }
            let material = &delta.plan().materials()[id];
            batch.insert(
                b.protected_id.clone(),
                VaultEntry {
                    private_key: material.private().private().to_owned(),
                    public_key: material.metadata.public.public_key.clone(),
                    fingerprint: material.metadata.public.fingerprint.clone(),
                    origin: EntryOrigin::Synced,
                    added_at_ms: journal.at_ms,
                },
            );
        }
        let mut vault = Vault::open(&paths.vault, &scoped, journal.at_ms)
            .map_err(|_| failure("cannot open validated central stage"))?;
        vault
            .put_new_batch(&scoped, &batch)
            .map_err(|_| failure("cannot save central material stage; original retained"))?;
        if paths.vault.exists() {
            let bytes = bounded_read(&paths.vault, store::MAX_READ_ONLY_VAULT_BYTES)?;
            durable(paths, &paths.vault, &bytes)?;
            journal.staged_vault_digest = Some(digest(&bytes));
            journal.staged_key_account =
                Some(validate_vault(&paths.vault, &scoped)?.key_account().into());
        } else if !journal.bindings.is_empty() {
            return Err(failure("central material stage is missing"));
        }
        super::step(super::PublishStep::VaultStaged)?;
        journal.phase = Phase::Staged;
        save(paths, journal)?;
    }
    if journal.staged_vault_digest.is_none() {
        if !journal.bindings.is_empty() || paths.vault.exists() {
            return Err(failure("central empty-vault stage is inconsistent"));
        }
        return Ok(());
    }
    let bytes = bounded_read(&paths.vault, store::MAX_READ_ONLY_VAULT_BYTES)?;
    if journal.staged_vault_digest.as_ref() != Some(&digest(&bytes)) {
        return Err(failure("central staged vault changed; original retained"));
    }
    let view = validate_vault(&paths.vault, &scoped)?;
    if journal.staged_key_account.as_deref() != Some(view.key_account()) {
        return Err(failure("central staged master selection changed"));
    }
    for (id, b) in &journal.bindings {
        let entry = view
            .get(&b.protected_id)
            .map_err(|_| failure("staged central material is unreadable"))?
            .ok_or_else(|| failure("staged central material is missing"))?;
        let material = &delta.plan().materials()[id];
        let opened = central::payload::PrivateMaterial::new(zeroize::Zeroizing::new(
            entry.private_key.clone(),
        ))?;
        opened.validate_against(id, &material.metadata)?;
        crate::sync::records_v3::key_material_matches(
            &material.metadata.public,
            &entry.public_key,
            &entry.fingerprint,
        )
        .map_err(|_| failure("central material readback metadata differs"))?;
    }
    Ok(())
}
/// Resume the same immutable mapping. Never discover new keys or allocate a replacement operation.
pub(crate) fn resume(
    env: &SyncEnv,
    operation: &str,
    delta: &LibraryDelta,
) -> Result<Staged, AppError> {
    resume_input(env, operation, Input::Library(delta))
}
fn resume_input(env: &SyncEnv, operation: &str, input: Input<'_>) -> Result<Staged, AppError> {
    if !cfg!(unix) {
        return Err(failure(
            "central material staging is not verified on this platform",
        ));
    }
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    saved_source(env, input)?;
    let paths = Paths::new(env, operation)?;
    let mut journal: Journal =
        serde_json::from_slice(&bounded_read(&paths.journal, MAX_JOURNAL_BYTES)?)
            .map_err(|_| failure("central stage journal is unreadable"))?;
    validate_header(&journal, operation)?;
    execute(env, &paths, &mut journal, input)?;
    Ok(Staged { journal, paths })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        central::{crypto::VaultKeys, material_fixture_for_test},
        fake_relay::FakeRelay,
        record_runtime,
        testkit::{TestClock, TestDevice},
    };
    pub(super) fn fixture() -> (TestDevice, VaultKeys, String, VaultEntry) {
        let (mut state, keys, _, id, entry) = material_fixture_for_test();
        state.local.keys.clear();
        let device = TestDevice::new("central-stage", &FakeRelay::new(), &TestClock::new());
        record_runtime::save_active(&device.env().state_path, &state).unwrap();
        let probe = record_runtime::probe_startup(&device.env().state_path, "central-stage");
        record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
        (device, keys, id, entry)
    }
    pub(super) fn delta(device: &TestDevice, keys: &VaultKeys) -> LibraryDelta {
        LibraryDelta::prepare(
            &record_runtime::snapshot(&device.env()).unwrap().0,
            keys,
            100,
        )
        .unwrap()
    }
    #[test]
    fn staging_and_same_operation_resume_are_inert_and_never_promote_a_new_master_or_private_material(
    ) {
        let (device, keys, id, entry) = fixture();
        let env = device.env();
        let before = fs::read(&env.state_path).unwrap();
        let staged = prepare(&env, &delta(&device, &keys)).unwrap();
        let operation = staged.operation().to_owned();
        let mapping = staged.mapping();
        assert_eq!(staged.summary().phase, "central_staged");
        assert!(mapping.contains_key(&id));
        assert_eq!(fs::read(&env.state_path).unwrap(), before);
        assert!(!store::vault_path(&env.state_path).exists());
        let account = staged.journal.staged_key_account.as_ref().unwrap();
        assert!(device.keychain.entry(account).is_none());
        assert!(device
            .keychain
            .entry(&format!("migration:{operation}:{account}"))
            .is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&staged.paths.dir)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            for path in [
                &staged.paths.journal,
                &staged.paths.vault,
                &staged.paths.original_state,
                &staged.paths.masters,
            ] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        let bytes = fs::read(&staged.paths.vault).unwrap();
        let journal = fs::read_to_string(&staged.paths.journal).unwrap();
        assert!(!journal.contains("private_key"));
        assert!(!journal.contains("OPENSSH PRIVATE KEY"));
        let scoped = ScopedKeychain {
            inner: env.keychain,
            import_id: &operation,
            receipts: &staged.paths.masters,
        };
        let view = validate_vault(&staged.paths.vault, &scoped).unwrap();
        assert_eq!(
            view.get(&mapping[&id]).unwrap().unwrap().private_key,
            entry.private_key
        );
        let resumed = resume(&env, &operation, &delta(&device, &keys)).unwrap();
        assert_eq!(resumed.mapping(), mapping);
        assert_eq!(fs::read(&resumed.paths.vault).unwrap(), bytes);
        let pending = super::super::pending_imports(&env).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].phase, "central_staged");
        assert!(prepare(&env, &delta(&device, &keys)).is_err());
        assert!(super::super::resume(&env, &operation).is_err());
    }
    #[test]
    fn retired_and_orphan_source_entries_survive_and_a_corrupt_stage_never_changes_the_active_vault(
    ) {
        let (device, keys, _, entry) = fixture();
        let env = device.env();
        let path = store::vault_path(&env.state_path);
        let mut original = Vault::open(&path, env.keychain, 1).unwrap();
        original.put(env.keychain, "retired:old:1", &entry).unwrap();
        original.put(env.keychain, "orphan-old", &entry).unwrap();
        let bytes = fs::read(&path).unwrap();
        let staged = prepare(&env, &delta(&device, &keys)).unwrap();
        let scoped = ScopedKeychain {
            inner: env.keychain,
            import_id: staged.operation(),
            receipts: &staged.paths.masters,
        };
        let readback = validate_vault(&staged.paths.vault, &scoped).unwrap();
        assert_eq!(readback.get("retired:old:1").unwrap(), Some(entry.clone()));
        assert_eq!(readback.get("orphan-old").unwrap(), Some(entry));
        fs::write(&staged.paths.vault, b"corrupt").unwrap();
        assert!(resume(&env, staged.operation(), &delta(&device, &keys)).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    #[test]
    fn a_journal_prepared_interruption_can_capture_latest_unrelated_b_under_the_same_fixed_mapping()
    {
        let (device, keys, _, _) = fixture();
        let env = device.env();
        let before = delta(&device, &keys);
        let result = super::super::with_test_step(
            |step| {
                if step == super::super::PublishStep::JournalPrepared {
                    Err(failure("stop before source capture"))
                } else {
                    Ok(())
                }
            },
            || prepare(&env, &before),
        );
        assert!(result.is_err());
        let pending = super::super::pending_imports(&env).unwrap();
        assert_eq!(pending.len(), 1);
        let operation = pending[0].import_id.clone();
        let paths = Paths::new(&env, &operation).unwrap();
        let saved: Journal = serde_json::from_slice(&fs::read(&paths.journal).unwrap()).unwrap();
        assert!(saved.source_state_digest.is_none());
        assert!(!paths.original_state.exists());
        let (mut state, generation) = record_runtime::snapshot(&env).unwrap();
        let host:crate::sync::records_v3::HostPayload=serde_json::from_value(serde_json::json!({"schema":2,"alias":"local-B","hostname":"fixture.invalid","auth":"password"})).unwrap();
        state = crate::sync::record_repository::create_host(
            &state,
            "0000000000000008",
            crate::sync::records_v3::HostScope::Local,
            host,
            101,
        )
        .unwrap();
        // Preserve B as ciphertext before preparing the resumed delta.
        let signer = central::crypto::DeviceKeys::decode_secret(&base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [1u8; 64],
        ))
        .unwrap();
        state = central::capture_for_test(&state, &keys, &signer).unwrap();
        record_runtime::commit_candidate(&env, generation, state).unwrap();
        let resumed = resume(&env, &operation, &delta(&device, &keys)).unwrap();
        assert_eq!(resumed.journal.bindings, saved.bindings);
        assert!(resumed.journal.source_state_digest.is_some());
        let archived: SyncStateV3 =
            serde_json::from_slice(&fs::read(&paths.original_state).unwrap()).unwrap();
        assert!(!archived.local.hosts.is_empty());
        assert!(!archived
            .local
            .central
            .unwrap()
            .replica
            .unwrap()
            .pending
            .is_empty());
        assert!(!store::vault_path(&env.state_path).exists());
    }
    #[test]
    fn changed_active_vault_or_profile_journal_cannot_resume_over_the_source() {
        let (device, keys, _, entry) = fixture();
        let env = device.env();
        let staged = prepare(&env, &delta(&device, &keys)).unwrap();
        let journal = fs::read(&staged.paths.journal).unwrap();
        let mut wrong: Journal = serde_json::from_slice(&journal).unwrap();
        wrong.profile.subject = "different-login".into();
        let profile = central::credentials::Profile::new(
            &wrong.profile.origin,
            &wrong.profile.issuer,
            &wrong.profile.subject,
        )
        .unwrap();
        wrong.profile.locator = profile.locator;
        fs::write(&staged.paths.journal, serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert!(resume(&env, staged.operation(), &delta(&device, &keys)).is_err());
        fs::write(&staged.paths.journal, &journal).unwrap();
        let active = store::vault_path(&env.state_path);
        let mut source = Vault::open(&active, env.keychain, 1).unwrap();
        source
            .put(env.keychain, "new-local-private-B", &entry)
            .unwrap();
        let bytes = fs::read(&active).unwrap();
        assert!(resume(&env, staged.operation(), &delta(&device, &keys)).is_err());
        assert_eq!(fs::read(&active).unwrap(), bytes);
    }
    #[test]
    fn a_stage_vault_write_interruption_resumes_the_same_image_ids_and_protected_namespace() {
        let (device, keys, _, _) = fixture();
        let env = device.env();
        let outcome = super::super::with_test_step(
            |step| {
                if step == super::super::PublishStep::VaultStaged {
                    Err(failure("stop after vault write"))
                } else {
                    Ok(())
                }
            },
            || prepare(&env, &delta(&device, &keys)),
        );
        assert!(outcome.is_err());
        let pending = super::super::pending_imports(&env).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].phase, "central_prepared");
        let operation = &pending[0].import_id;
        let paths = Paths::new(&env, operation).unwrap();
        let bytes = fs::read(&paths.vault).unwrap();
        let masters = fs::read(&paths.masters).unwrap();
        let journal: Journal = serde_json::from_slice(&fs::read(&paths.journal).unwrap()).unwrap();
        let resumed = resume(&env, operation, &delta(&device, &keys)).unwrap();
        assert_eq!(resumed.journal.bindings, journal.bindings);
        assert_eq!(fs::read(&paths.vault).unwrap(), bytes);
        assert_eq!(fs::read(&paths.masters).unwrap(), masters);
        assert!(!store::vault_path(&env.state_path).exists());
    }
    #[test]
    fn false_success_of_scoped_master_set_leaves_originals_intact_and_resumes_fixed_ids() {
        use crate::sync::env::Keychain;
        struct Forget<'a>(&'a dyn Keychain);
        impl Keychain for Forget<'_> {
            fn get(&self, key: &str) -> Result<Option<String>, AppError> {
                self.0.get(key)
            }
            fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
                if key.starts_with("migration:") {
                    Ok(())
                } else {
                    self.0.set(key, value)
                }
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                Err(failure("unexpected credential delete"))
            }
        }
        let (device, keys, _, _) = fixture();
        let original = fs::read(&device.env().state_path).unwrap();
        let forget = Forget(&device.keychain);
        let mut bad = device.env();
        bad.keychain = &forget;
        assert!(prepare(&bad, &delta(&device, &keys)).is_err());
        assert_eq!(fs::read(&bad.state_path).unwrap(), original);
        assert!(!store::vault_path(&bad.state_path).exists());
        let pending = super::super::pending_imports(&bad).unwrap();
        let operation = &pending[0].import_id;
        let paths = Paths::new(&bad, operation).unwrap();
        let journal: Journal = serde_json::from_slice(&fs::read(&paths.journal).unwrap()).unwrap();
        assert!(!paths.vault.exists());
        let resumed = resume(&device.env(), operation, &delta(&device, &keys)).unwrap();
        assert_eq!(resumed.journal.bindings, journal.bindings);
        assert_eq!(fs::read(&device.env().state_path).unwrap(), original);
    }
    #[cfg(unix)]
    #[test]
    fn a_shared_data_directory_is_rejected_before_any_staging_side_effect() {
        use std::os::unix::fs::PermissionsExt;
        let (device, keys, _, _) = fixture();
        let env = device.env();
        let bytes = fs::read(&env.state_path).unwrap();
        fs::set_permissions(
            env.state_path.parent().unwrap(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(prepare(&env, &delta(&device, &keys)).is_err());
        assert_eq!(fs::read(&env.state_path).unwrap(), bytes);
        assert!(!env.state_path.parent().unwrap().join("imports").exists());
        assert!(!store::vault_path(&env.state_path).exists());
    }
}
