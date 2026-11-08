use super::*;
#[derive(Clone)]
pub(super) struct Paths {
    root: PathBuf,
    journal: PathBuf,
    state: PathBuf,
    vault: PathBuf,
    original_state: PathBuf,
    original_vault: PathBuf,
    review: PathBuf,
    documents: PathBuf,
}
impl Paths {
    pub fn new(env: &SyncEnv, id: &str) -> Result<Self, AppError> {
        if !crate::sync::slot_rules::is_slot_id(id) {
            return Err(failure("migration recovery identity is invalid"));
        }
        let root = env
            .state_path
            .parent()
            .ok_or_else(|| failure("migration profile data path is unavailable"))?
            .join("migrations")
            .join(id);
        Ok(Self {
            journal: root.join("journal.json"),
            state: root.join("state.json"),
            vault: root.join("vault.json"),
            original_state: root.join("original-state.json"),
            original_vault: root.join("original-vault.json"),
            review: root.join("review-sources.json"),
            documents: root.join("documents"),
            root,
        })
    }
    pub fn preflight(&self, env: &SyncEnv) -> Result<(), AppError> {
        for p in [
            &self.root,
            &self.journal,
            &self.state,
            &self.vault,
            &self.original_state,
            &self.original_vault,
            &self.review,
            &self.documents,
            &env.state_path,
            &crate::vault::store::vault_path(&env.state_path),
        ] {
            crate::fsutil::check_write(p)?;
        }
        Ok(())
    }
}
pub(super) fn lock_profile(env: &SyncEnv) -> Result<File, AppError> {
    let path = env.state_path.with_file_name("migration.lock");
    crate::fsutil::check_write(&path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|_| failure("migration profile lock cannot be opened"))?;
    file.try_lock()
        .map_err(|_| failure("another process owns this profile migration"))?;
    Ok(file)
}
fn save(paths: &Paths, j: &Journal) -> Result<(), AppError> {
    let bytes = serde_json::to_vec_pretty(j)
        .map_err(|_| failure("migration progress cannot be encoded"))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(failure(
            "migration progress exceeds the supported size limit",
        ));
    }
    crate::fsutil::atomic_write(&paths.journal, &bytes, 0o600)
}
pub(super) fn read_journal(paths: &Paths) -> Result<Journal, AppError> {
    let bytes = read_optional(&paths.journal, MAX_JOURNAL_BYTES)?
        .ok_or_else(|| failure("migration recovery journal is missing"))?;
    parse_captured_journal(&bytes, &paths.root.file_name().unwrap().to_string_lossy())
}
pub(super) fn parse_captured_journal(bytes: &[u8], id: &str) -> Result<Journal, AppError> {
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(failure("captured migration journal exceeds its size limit"));
    }
    let j: Journal = serde_json::from_slice(bytes)
        .map_err(|_| failure("migration recovery journal is invalid"))?;
    if j.version != 1
        || j.plan.migration_id != id
        || !crate::sync::crypto::is_chain_id(&j.plan.source_digest)
        || !crate::sync::crypto::is_chain_id(&j.source_state_digest)
        || !matches!(
            j.phase.as_str(),
            "prepared" | "account-gated" | "publishing" | "active"
        )
    {
        return Err(failure("migration recovery identity is invalid"));
    }
    records_v3::validate_state(&j.plan.candidate)
        .map_err(|_| failure("migration recovery candidate is invalid"))?;
    for (id, chain) in &j.plan.chains {
        if id != &chain.chain_id || !crate::sync::crypto::is_chain_id(id) {
            return Err(failure("migration recovery chain identity is invalid"));
        }
        capacity(chain)?;
    }
    Ok(j)
}
fn write_once(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    if let Some(existing) = read_optional(
        path,
        MAX_STATE_BYTES.max(crate::vault::store::MAX_READ_ONLY_VAULT_BYTES),
    )? {
        if existing.as_slice() != bytes {
            return Err(failure(
                "migration protected backup differs; it was retained",
            ));
        }
        return Ok(());
    }
    crate::fsutil::atomic_write(path, bytes, 0o600)
}
fn code_keys(j: &Journal, code: &str) -> Result<ChainKeys, AppError> {
    let keys = crate::sync::crypto::derive_account(code)
        .map_err(|_| failure("migration sync code is invalid"))?;
    if j.plan
        .candidate
        .account
        .as_ref()
        .map(|a| a.chain_id.as_str())
        != Some(&keys.chain_id)
    {
        return Err(failure("migration sync code belongs to another account"));
    }
    Ok(keys)
}
fn set_absent_or_same(env: &SyncEnv, account: &str, value: &str) -> Result<(), AppError> {
    let previous = Zeroizing::new(
        env.keychain
            .get(account)
            .map_err(|_| failure("migration credential cannot be inspected"))?,
    );
    if previous.as_deref().is_some_and(|s| s != value) {
        return Err(failure(
            "migration destination credential differs; the original was retained",
        ));
    }
    if previous.is_none() {
        env.keychain
            .set(account, value)
            .map_err(|_| failure("migration credential cannot be copied"))?;
    }
    if env
        .keychain
        .get(account)
        .map_err(|_| failure("migration credential copy cannot be verified"))?
        .as_deref()
        != Some(value)
    {
        return Err(failure("migration credential copy was not verified"));
    }
    Ok(())
}
pub(super) fn prepare_journal(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    code: &str,
) -> Result<(), AppError> {
    paths.preflight(env)?;
    for source in &j.plan.documents {
        crate::fsutil::check_write(
            &paths
                .documents
                .join(format!("{}.config", digest(source.source.as_bytes()))),
        )?;
    }
    if j.plan.candidate.account.is_some() {
        code_keys(j, code)?;
    }
    if !j.state_published {
        let current = read_optional(&env.state_path, MAX_STATE_BYTES)?;
        if digest(current.as_ref().map_or(&[][..], |b| b.as_slice())) != j.source_state_digest
            && j.source_kind.starts_with("legacy_")
        {
            return Err(failure("original migration state changed; it was retained"));
        }
    }
    if j.plan.candidate.account.is_some() {
        for account in [
            format!("{CODE_PREFIX}{}", j.plan.migration_id),
            crate::sync::state::MNEMONIC_ACCOUNT.into(),
        ] {
            let old = Zeroizing::new(
                env.keychain
                    .get(&account)
                    .map_err(|_| failure("migration code destination cannot be inspected"))?,
            );
            if old.as_deref().is_some_and(|v| v != code) {
                return Err(failure(
                    "migration code destination differs; it was retained",
                ));
            }
        }
    }
    crate::fsutil::ensure_dir_secure(&paths.root)?;
    save(paths, j)?;
    if !paths.original_state.exists() && j.source_state_digest != digest(&[]) {
        let original = match &j.plan.original_state_bytes {
            Some(bytes) => bytes.clone(),
            None => read_optional(&env.state_path, MAX_STATE_BYTES)?
                .ok_or_else(|| failure("protected original state source is unavailable"))?,
        };
        if digest(&original) != j.source_state_digest {
            return Err(failure("protected original state source changed before its backup; retained journal requires review"));
        }
        write_once(&paths.original_state, &original)?;
    }
    for source in &j.plan.documents {
        let target = paths
            .documents
            .join(format!("{}.config", digest(source.source.as_bytes())));
        crate::fsutil::check_write(&target)?;
        if !target.exists() {
            let text = if source.text.is_empty() {
                source::document_text(env, &source.source, &source.memory_digest)?
            } else {
                source.text.clone()
            };
            if digest(text.as_bytes()) != source.memory_digest {
                return Err(failure("migration document backup identity is invalid"));
            }
            crate::fsutil::ensure_dir_secure(&paths.documents)?;
            write_once(&target, text.as_bytes())?;
        }
    }
    record_runtime::save_active(&paths.state, &j.plan.candidate)?;
    let saved = read_optional(&paths.state, MAX_STATE_BYTES)?
        .ok_or_else(|| failure("migration staged state is missing"))?;
    match records_v3::decode_state(
        std::str::from_utf8(&saved).map_err(|_| failure("migration staged state is invalid"))?,
    )
    .map_err(|_| failure("migration staged state is invalid"))?
    {
        records_v3::DecodedState::V3(state) if *state == j.plan.candidate => {}
        _ => return Err(failure("migration staged state did not verify")),
    }
    if !j.vault_staged {
        let original = crate::vault::store::vault_path(&env.state_path);
        let vault = crate::vault::store::read_vault(&original, env.keychain)
            .map_err(|_| failure("original vault is not safely readable; it was retained"))?;
        for id in vault.ids() {
            vault
                .get(&id)
                .map_err(|_| failure("original vault entry cannot be verified"))?;
        }
        if let Some(bytes) =
            read_optional(&original, crate::vault::store::MAX_READ_ONLY_VAULT_BYTES)?
        {
            write_once(&paths.original_vault, &bytes)?;
            write_once(&paths.vault, &bytes)?;
        }
        j.vault_staged = true;
        save(paths, j)?;
    }
    #[cfg(test)]
    step(Step::Prepared)?;
    if !j.code_staged && j.plan.candidate.account.is_some() {
        set_absent_or_same(env, &format!("{CODE_PREFIX}{}", j.plan.migration_id), code)?;
        j.code_staged = true;
        save(paths, j)?;
    }
    #[cfg(test)]
    step(Step::CodeStaged)?;
    Ok(())
}
pub(super) fn completed_receipt(
    paths: &Paths,
    j: &mut Journal,
    env: &SyncEnv,
) -> Result<Option<MigrationReceipt>, AppError> {
    let complete = {
        let core = env.runtime.core.lock().unwrap();
        core.records
            .as_ref()
            .and_then(|s| s.local.import_receipts.get(&j.plan.migration_id))
            .map(|r| r.source_digest.clone())
    };
    if let Some(source) = complete {
        if source != j.plan.source_digest {
            return Err(failure(
                "migration atomic receipt identity conflicts with its journal",
            ));
        }
        j.phase = "active".into();
        j.state_published = true;
        save(paths, j)?;
        return Ok(Some(j.receipt()));
    }
    Ok(None)
}
fn copy_passwords(env: &SyncEnv, paths: &Paths, j: &mut Journal) -> Result<(), AppError> {
    if !j.source_kind.starts_with("legacy_") {
        return Ok(());
    }
    let mut aliases: BTreeMap<String, Vec<(String, String, u16)>> = BTreeMap::new();
    for row in j
        .plan
        .candidate
        .spaces
        .values()
        .flat_map(|s| s.records.values())
        .chain(j.plan.candidate.local.hosts.values())
    {
        let Ok(records_v3::TypedRecord::Live(h)) =
            records_v3::decode_host(&row.record, records_v3::HostScope::Local)
        else {
            continue;
        };
        if h.payload.auth == records_v3::AuthKind::Password {
            aliases.entry(h.payload.alias.clone()).or_default().push((
                h.id,
                h.payload.hostname,
                h.payload.port,
            ));
        }
    }
    let options = crate::sync::records_v3::importer::ImportOptions::new(
        env.home.clone().unwrap_or(crate::fsutil::home_dir()?),
    );
    let preview =
        crate::sync::records_v3::importer::preview_file(&env.ssh_dir.join("config"), &options)
            .map_err(|_| failure("migration password source correspondence cannot be proven"))?;
    for (alias, hosts) in aliases {
        if hosts.len() != 1 {
            continue;
        }
        let (id, hostname, port) = &hosts[0];
        let proven: Vec<_> = preview
            .candidates
            .iter()
            .filter(|h| h.payload.alias == alias)
            .collect();
        if proven.len() != 1
            || proven[0].payload.hostname != *hostname
            || proven[0].payload.port != *port
        {
            continue;
        }
        if j.password_receipts.get(id).is_some_and(|s| s == "copied") {
            continue;
        }
        let source = Zeroizing::new(
            env.keychain
                .get(&format!("host:{alias}"))
                .map_err(|_| failure("migration source password cannot be read"))?,
        );
        let Some(password) = source.as_deref() else {
            continue;
        };
        let scoped = format!("migration:{}:host:{id}", j.plan.migration_id);
        j.password_receipts.insert(id.clone(), "staging".into());
        save(paths, j)?;
        set_absent_or_same(env, &scoped, password)?;
        if set_absent_or_same(env, &format!("host:{id}"), password).is_err() {
            j.password_receipts.insert(id.clone(), "review".into());
            save(paths, j)?;
            continue;
        }
        j.password_receipts.insert(id.clone(), "copied".into());
        save(paths, j)?;
    }
    Ok(())
}
pub(super) fn execute(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    _code: &str,
) -> Result<MigrationReceipt, AppError> {
    if j.next_retry_ms > env.now() {
        return Err(failure("migration network backoff is still active"));
    }
    if j.plan.candidate.account.is_some() {
        return Err(failure(super::CHAIN_RETIRED));
    }
    execute_local(env, paths, j)
}
fn execute_local(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
) -> Result<MigrationReceipt, AppError> {
    if let Some(receipt) = completed_receipt(paths, j, env)? {
        return Ok(receipt);
    }
    source::verify_local(env, j, "")?;
    copy_passwords(env, paths, j)?;
    j.plan.candidate.local.import_receipts.insert(
        j.plan.migration_id.clone(),
        records_v3::LocalImportReceipt {
            source_digest: j.plan.source_digest.clone(),
            host_ids: j
                .plan
                .candidate
                .local
                .hosts
                .values()
                .map(|r| r.record.id.clone())
                .collect(),
            key_ids: j.plan.candidate.local.keys.keys().cloned().collect(),
        },
    );
    record_runtime::save_active(&paths.state, &j.plan.candidate)?;
    save(paths, j)?;
    #[cfg(test)]
    step(Step::BeforeStateSave)?;
    record_runtime::commit_migration_candidate(
        env,
        j.source_generation,
        j.plan.candidate.clone(),
        None,
    )?;
    j.state_published = true;
    save(paths, j)?;
    #[cfg(test)]
    step(Step::StateSaved)?;
    j.phase = "active".into();
    save(paths, j)?;
    Ok(j.receipt())
}
