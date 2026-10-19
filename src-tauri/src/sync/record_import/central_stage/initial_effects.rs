//! Exact readback of one reserved initial stage; never a caller-supplied exclusion list.
use super::*;
use crate::sync::central::{crypto::VaultKeys, InitialProjection, InitialTransaction};
use std::path::PathBuf;
use zeroize::Zeroizing;
struct Replacement {
    path: PathBuf,
    before: Option<Zeroizing<Vec<u8>>>,
    after: Zeroizing<Vec<u8>>,
}
pub(in crate::sync) struct InitialEffects {
    operation: String,
    binding: input::InitialBinding,
    files: BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    directories: BTreeSet<PathBuf>,
    replacement: Option<Replacement>,
}
impl InitialEffects {
    pub(in crate::sync) fn matches(
        &self,
        initial: &InitialProjection,
        operation: &str,
    ) -> Result<(), AppError> {
        if operation != self.operation {
            return Err(failure("owned initial stage belongs to another operation"));
        }
        Input::Initial(initial).verify_binding(Some(&self.binding))
    }
    pub(super) fn empty(&self) -> bool {
        self.files.is_empty() && self.replacement.is_none()
    }
    pub(in crate::sync) fn files(&self) -> impl Iterator<Item = (&Path, &[u8])> {
        self.files.iter().map(|(p, b)| (p.as_path(), b.as_slice()))
    }
    pub(in crate::sync) fn directories(&self) -> &BTreeSet<PathBuf> {
        &self.directories
    }
    pub(in crate::sync) fn replacement(&self) -> Option<(&Path, Option<&[u8]>, &[u8])> {
        self.replacement.as_ref().map(|r| {
            (
                r.path.as_path(),
                r.before.as_deref().map(|b| b.as_slice()),
                r.after.as_slice(),
            )
        })
    }
}
fn names(paths: &Paths) -> Result<BTreeSet<String>, AppError> {
    fs::read_dir(&paths.dir)?
        .map(|entry| {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| failure("initial stage has an unknown filename"))?;
            if ![
                "journal.json",
                "original-state.json",
                "original-vault.json",
                "vault.json",
                "master-receipts.json",
            ]
            .contains(&name.as_str())
                || !entry.file_type()?.is_file()
            {
                return Err(failure("initial stage has an unknown retained entry"));
            }
            Ok(name)
        })
        .collect()
}
fn from_stage(
    env: &SyncEnv,
    initial: &InitialProjection,
    operation: &str,
    original_state: &[u8],
    original_vault: Option<&[u8]>,
) -> Result<InitialEffects, AppError> {
    let paths = Paths::new(env, operation)?;
    let before_names = names(&paths)?;
    if before_names.is_empty() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            for directory in [
                paths.dir.as_path(),
                paths
                    .dir
                    .parent()
                    .ok_or_else(|| failure("reserved stage binding is invalid"))?,
            ] {
                let meta = fs::symlink_metadata(directory)?;
                if !meta.is_dir()
                    || meta.file_type().is_symlink()
                    || meta.uid() != unsafe { libc::geteuid() }
                    || meta.mode() & 0o077 != 0
                {
                    return Err(failure("empty reserved stage must be private and owned"));
                }
            }
        }
        #[cfg(not(unix))]
        return Err(failure(
            "empty reserved stages require the verified secure file implementation",
        ));
        let directory = Path::new("data/imports").join(operation);
        return Ok(InitialEffects {
            operation: operation.into(),
            binding: Input::Initial(initial)
                .binding()?
                .ok_or_else(|| failure("reserved stage binding is invalid"))?,
            files: BTreeMap::new(),
            directories: BTreeSet::from([PathBuf::from("data/imports"), directory]),
            replacement: None,
        });
    }
    let journal_bytes = bounded_read(&paths.journal, MAX_JOURNAL_BYTES)?;
    let journal: Journal = serde_json::from_slice(&journal_bytes)
        .map_err(|_| failure("initial stage journal is unreadable"))?;
    validate_header(&journal, operation)?;
    verify_delta(&journal, Input::Initial(initial))?;
    let binding = journal
        .initial
        .clone()
        .ok_or_else(|| failure("owned stage is not an initial migration"))?;
    if journal.source_vault_digest != original_vault.map(digest)
        || journal
            .bindings
            .values()
            .any(|b| b.rebind || b.old_material.is_some())
    {
        return Err(failure("initial stage source or observation changed"));
    }
    let source = optional_bytes(&paths.original_state, record_runtime::MAX_STATE_BYTES)?;
    if source
        .as_ref()
        .map(|b| b.as_slice())
        .is_some_and(|b| b != original_state)
        || journal
            .source_state_digest
            .as_ref()
            .is_some_and(|d| source.as_ref().is_none_or(|b| digest(b) != *d))
        || source.is_none() && journal.phase != Phase::Prepared
    {
        return Err(failure(
            "initial stage original state differs from the captured source",
        ));
    }
    let vault_source = optional_bytes(&paths.original_vault, store::MAX_READ_ONLY_VAULT_BYTES)?;
    if vault_source
        .as_deref()
        .is_some_and(|b| Some(b.as_slice()) != original_vault)
        || journal.source_state_digest.is_some()
            && vault_source.as_ref().map(|b| b.as_slice()) != original_vault
    {
        return Err(failure(
            "initial stage original vault differs from the captured source",
        ));
    }
    let scoped = ScopedKeychain {
        inner: env.keychain,
        import_id: operation,
        receipts: &paths.masters,
    };
    let master_bytes = optional_bytes(&paths.masters, MAX_JOURNAL_BYTES)?;
    let accounts: BTreeSet<String> = match &master_bytes {
        Some(b) => serde_json::from_slice(b)
            .map_err(|_| failure("initial scoped master receipt is unreadable"))?,
        None => BTreeSet::new(),
    };
    if accounts.len() > 4096 || master_bytes.is_some() && accounts.is_empty() {
        return Err(failure("initial scoped master receipt is invalid"));
    }
    for account in &accounts {
        if !super::super::is_vault_account(account) {
            return Err(failure("initial scoped master account is invalid"));
        }
        let key = env
            .keychain
            .get(&scoped.scoped(account)?)?
            .map(Zeroizing::new)
            .ok_or_else(|| failure("initial scoped master is missing"))?;
        drop(Zeroizing::new(central::crypto::decode(&key, 32, 32)?));
    }
    let staged_bytes = optional_bytes(&paths.vault, store::MAX_READ_ONLY_VAULT_BYTES)?;
    if journal.source_state_digest.is_none() && (staged_bytes.is_some() || master_bytes.is_some())
        || journal
            .staged_vault_digest
            .as_ref()
            .is_some_and(|d| staged_bytes.as_ref().is_none_or(|b| digest(b) != *d))
    {
        return Err(failure(
            "initial stage outputs do not match its durable phase",
        ));
    }
    if let Some(_) = &staged_bytes {
        let view = validate_vault(&paths.vault, &scoped)?;
        if journal
            .staged_key_account
            .as_ref()
            .is_some_and(|a| a != view.key_account())
        {
            return Err(failure("initial staged master selection changed"));
        }
        // Never treat an already-published active image as the immutable old baseline.
        let original = validate_vault(&paths.original_vault, env.keychain)?;
        let old_ids: BTreeSet<_> = original.ids().into_iter().collect();
        if original_vault.is_some() && view.key_account() != original.key_account()
            || original_vault.is_none() && !accounts.contains(view.key_account())
        {
            return Err(failure("initial stage has no bound master provenance"));
        }
        for id in &old_ids {
            if original.get(id)? != view.get(id)? {
                return Err(failure("initial stage changed a retained original entry"));
            }
        }
        let mapped: BTreeSet<_> = journal
            .bindings
            .values()
            .map(|b| b.protected_id.clone())
            .collect();
        if !old_ids.is_disjoint(&mapped)
            || view
                .ids()
                .iter()
                .any(|id| !old_ids.contains(id) && !mapped.contains(id))
        {
            return Err(failure(
                "initial stage contains an unbound material identity",
            ));
        }
        for (id, b) in &journal.bindings {
            let Some(entry) = view.get(&b.protected_id)? else {
                if journal.phase == Phase::Prepared {
                    continue;
                }
                return Err(failure("initial staged material is missing"));
            };
            if entry.origin != EntryOrigin::Synced || entry.added_at_ms != journal.at_ms {
                return Err(failure("initial staged material provenance changed"));
            }
            let material = &initial.delta().plan().materials()[id];
            let private =
                central::payload::PrivateMaterial::new(Zeroizing::new(entry.private_key.clone()))?;
            private.validate_against(id, &material.metadata)?;
            crate::sync::records_v3::key_material_matches(
                &material.metadata.public,
                &entry.public_key,
                &entry.fingerprint,
            )
            .map_err(|_| failure("initial staged public metadata differs"))?;
        }
    } else if journal.phase != Phase::Prepared
        && (!journal.bindings.is_empty() || journal.staged_vault_digest.is_some())
    {
        return Err(failure("initial staged vault is missing"));
    }
    let active = optional_bytes(
        &store::vault_path(&env.state_path),
        store::MAX_READ_ONLY_VAULT_BYTES,
    )?;
    let replacement = if active.as_ref().map(|b| b.as_slice()) != original_vault {
        if journal.phase == Phase::Prepared
            || journal.staged_vault_digest.is_none()
            || active.as_ref().map(|b| b.as_slice()) != staged_bytes.as_ref().map(|b| b.as_slice())
        {
            return Err(failure("initial active vault has an unbound replacement"));
        }
        let active_view = validate_vault(&store::vault_path(&env.state_path), env.keychain)?;
        if journal.staged_key_account.as_deref() != Some(active_view.key_account()) {
            return Err(failure("initial active master has not been verified"));
        }
        let path = store::vault_path(&env.state_path);
        let name = path
            .file_name()
            .ok_or_else(|| failure("initial vault has no filename"))?;
        Some(Replacement {
            path: Path::new("data").join(name),
            before: original_vault.map(|b| Zeroizing::new(b.to_vec())),
            after: active.ok_or_else(|| failure("initial active image is missing"))?,
        })
    } else {
        None
    };
    if journal.phase == Phase::VaultPublished
        && replacement.is_none()
        && staged_bytes.as_ref().map(|b| b.as_slice()) != original_vault
    {
        return Err(failure("published initial vault is missing"));
    }
    let directory = Path::new("data/imports").join(operation);
    let mut files = BTreeMap::new();
    for (name, bytes) in [
        ("journal.json", Some(journal_bytes)),
        ("original-state.json", source),
        ("original-vault.json", vault_source),
        ("vault.json", staged_bytes),
        ("master-receipts.json", master_bytes),
    ] {
        if let Some(bytes) = bytes {
            files.insert(directory.join(name), bytes);
        }
    }
    if names(&paths)? != before_names {
        return Err(failure("initial stage entries changed during readback"));
    }
    Ok(InitialEffects {
        operation: operation.into(),
        binding,
        files,
        directories: BTreeSet::from([PathBuf::from("data/imports"), directory]),
        replacement,
    })
}
pub(in crate::sync) fn read(
    env: &SyncEnv,
    prepared: &dyn InitialTransaction,
    keys: &VaultKeys,
) -> Result<InitialEffects, AppError> {
    let life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    read_locked(env, prepared, keys, &life)
}
/// Caller owns lifecycle -> vault -> publication. This function performs no mutation or HTTP.
pub(in crate::sync) fn read_locked(
    env: &SyncEnv,
    prepared: &dyn InitialTransaction,
    keys: &VaultKeys,
    life: &std::sync::MutexGuard<'_, ()>,
) -> Result<InitialEffects, AppError> {
    let background = central::credentials::Background(env.keychain);
    let safe = SyncEnv {
        doc: env.doc,
        backed_up: env.backed_up,
        retention: env.retention,
        runtime: env.runtime,
        ssh_dir: env.ssh_dir.clone(),
        state_path: env.state_path.clone(),
        home: env.home.clone(),
        keychain: &background,
        relays: env.relays,
        events: env.events,
        clock: env.clock,
        platform: env.platform,
    };
    prepared.check_identity_locked(&safe, keys, life)?;
    drop(saved_source(&safe, Input::Initial(prepared.projection()))?);
    let effects = from_stage(
        &safe,
        prepared.projection(),
        prepared.operation(),
        prepared.original_state(&safe)?,
        prepared.original_vault(&safe)?,
    )?;
    prepared.check_effects_locked(&safe, keys, life, &effects)?;
    Ok(effects)
}

#[cfg(all(test, unix))]
mod tests;
