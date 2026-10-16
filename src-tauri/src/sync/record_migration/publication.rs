use super::*;
use crate::sync::record::{LocalRecord, Record, ACCOUNT_META_ID};
use crate::sync::record_merge::{self, AccountGate};
use crate::sync::relay::{PullResponse, PushOutcome, PushResult, RelayApi, RelayError};
use crate::sync::state_v2::AccountState;
use serde_json::{json, Value};
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
    let j: Journal = serde_json::from_slice(&bytes)
        .map_err(|_| failure("migration recovery journal is invalid"))?;
    if j.version != 1
        || j.plan.migration_id != paths.root.file_name().unwrap().to_string_lossy()
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
fn retry_failure(env: &SyncEnv, paths: &Paths, j: &mut Journal, error: RelayError) -> AppError {
    j.failures = j.failures.saturating_add(1);
    if matches!(
        error,
        RelayError::RateLimited | RelayError::Http(500..=599) | RelayError::Unreachable(_)
    ) {
        j.next_retry_ms = env
            .now()
            .saturating_add(crate::sync::relay::backoff_delay(j.failures).as_millis() as u64);
    }
    let _ = save(paths, j);
    failure("migration network publication is paused; retry after backoff")
}
fn pull(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    relay: &dyn RelayApi,
    keys: &ChainKeys,
    missing_ok: bool,
) -> Result<Option<PullResponse>, AppError> {
    match relay.pull(&keys.chain_id, &keys.auth_token, 0) {
        Ok(p) => {
            if p.latest_seq > 9_007_199_254_740_991 || p.records.len() > MAX_CHAIN_RECORDS {
                return Err(failure("migration full baseline is invalid"));
            }
            let mut seq = BTreeSet::new();
            let mut ids = BTreeSet::new();
            let mut bytes = 0usize;
            for e in &p.records {
                if e.seq == 0
                    || e.seq > p.latest_seq
                    || !seq.insert(e.seq)
                    || !ids.insert((&e.kind, &e.id_hash))
                {
                    return Err(failure("migration full baseline receipts are invalid"));
                }
                source::open_public(keys, e)?;
                bytes = bytes.saturating_add(e.ciphertext.len() + e.nonce.len());
            }
            if bytes > MAX_CHAIN_BYTES {
                return Err(failure("migration source exceeds relay capacity"));
            }
            Ok(Some(p))
        }
        Err(RelayError::NotFound) if missing_ok => Ok(None),
        Err(e) => Err(retry_failure(env, paths, j, e)),
    }
}
fn current_meta(keys: &ChainKeys, p: &PullResponse) -> Result<Option<(Record, u64)>, AppError> {
    for e in &p.records {
        if e.kind == "meta"
            && e.id_hash == crate::sync::crypto::id_hash(keys, "meta", ACCOUNT_META_ID)
        {
            let r = source::open_public(keys, e)?
                .ok_or_else(|| failure("migration account metadata cannot be decoded"))?;
            return Ok(Some((r, e.seq)));
        }
    }
    Ok(None)
}
fn observed_gate(keys: &ChainKeys, p: &PullResponse) -> Result<Option<MigrationGate>, AppError> {
    let empty = AccountState::new(&keys.chain_id);
    let (gate, schema) = record_merge::account_gate(&empty, keys, p);
    if schema.is_some_and(|s| s > 3) {
        return Err(failure("account uses a newer format; migration is paused"));
    }
    match gate {
        AccountGate::Compatible => Ok(current_meta(keys, p)?
            .and_then(|(r, _)| r.payload.get("migration").filter(|v| !v.is_null()).cloned())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| failure("migration account marker is invalid"))?),
        AccountGate::NeedsMigration { schema: 2 } => Ok(None),
        AccountGate::MigrationPending(g) => Ok(Some(g)),
        AccountGate::NeedsMigration { schema: 0 } if p.records.is_empty() => Ok(None),
        _ => Err(failure("migration account baseline cannot be admitted")),
    }
}
fn chain_keys(
    j: &Journal,
    account: &ChainKeys,
    id: &str,
    code: &str,
) -> Result<ChainKeys, AppError> {
    if id == account.chain_id {
        return Ok(account.clone());
    }
    if j.source_kind == "legacy_v1" && crate::sync::crypto::derive_space0(code)?.chain_id == id {
        return crate::sync::crypto::derive_space0(code);
    }
    record_merge::space_keys(j.plan.candidate.account.as_ref().unwrap(), account, id)?
        .ok_or_else(|| failure("migration selected space identity is unavailable"))
}
fn ensure_chains(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    relay: &dyn RelayApi,
    account: &ChainKeys,
    code: &str,
) -> Result<(), AppError> {
    let ids: Vec<_> = j
        .plan
        .chains
        .iter()
        .filter(|(_, c)| c.create)
        .map(|(id, _)| id.clone())
        .collect();
    for id in ids {
        if j.created_chains.contains(&id) {
            continue;
        }
        let keys = chain_keys(j, account, &id, code)?;
        if pull(env, paths, j, relay, &keys, true)?.is_none() {
            relay
                .create_chain(&id, &keys.auth_token)
                .map_err(|e| retry_failure(env, paths, j, e))?;
        }
        j.created_chains.insert(id);
        save(paths, j)?;
    }
    Ok(())
}
fn make_meta(
    j: &Journal,
    remote: Option<(Record, u64)>,
    phase: MigrationPhase,
    env: &SyncEnv,
) -> Result<(Record, PushItem), AppError> {
    let (mut record, seq) = remote.unwrap_or_else(|| {
        (
            Record {
                kind: RecordKind::Meta,
                id: ACCOUNT_META_ID.into(),
                version: 0,
                updated_at_ms: 0,
                device_id: j.plan.candidate.device_id.clone(),
                deleted: false,
                payload: Value::Null,
            },
            0,
        )
    });
    record.version = record
        .version
        .checked_add(1)
        .ok_or_else(|| failure("migration metadata revision exhausted"))?;
    record.updated_at_ms = record
        .updated_at_ms
        .max(env.now())
        .checked_add(1)
        .ok_or_else(|| failure("migration metadata timestamp exhausted"))?;
    record.device_id = j.plan.candidate.device_id.clone();
    let mut gate = j.plan.candidate.migration_gate.clone().unwrap();
    gate.phase = phase;
    record.payload = json!({"schema_version":3,"created_by_app_version":env!("CARGO_PKG_VERSION"),"migration":gate});
    let code = Zeroizing::new(
        env.keychain
            .get(&format!("{CODE_PREFIX}{}", j.plan.migration_id))
            .map_err(|_| failure("migration scoped code cannot be read"))?
            .ok_or_else(|| failure("migration scoped code is unavailable"))?,
    );
    let keys = code_keys(j, &code)?;
    let item = record_merge::encode_record(&keys, &record, seq)?;
    Ok((record, item))
}
fn gate_account(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    relay: &dyn RelayApi,
    keys: &ChainKeys,
) -> Result<(), AppError> {
    let p = pull(env, paths, j, relay, keys, false)?.unwrap();
    let observed = observed_gate(keys, &p)?;
    if let Some(gate) = observed {
        j.plan.candidate.migration_gate = Some(gate.clone());
        j.gate_written = true;
        j.phase = if gate.phase == MigrationPhase::Active {
            "publishing"
        } else {
            "account-gated"
        }
        .into();
        save(paths, j)?;
        return Ok(());
    }
    let (record, item) = make_meta(
        j,
        current_meta(keys, &p)?,
        MigrationPhase::AccountGated,
        env,
    )?;
    let mut capacity_plan = j.plan.chains.get(&keys.chain_id).unwrap().clone();
    capacity_plan.original = p.records;
    capacity_plan.items.push(item.clone());
    capacity(&capacity_plan)?;
    let outcome = relay
        .push(&keys.chain_id, &keys.auth_token, &[item])
        .map_err(|e| retry_failure(env, paths, j, e))?;
    match outcome {
        PushOutcome::Applied(results) if results.len() == 1 => match &results[0] {
            PushResult::Accepted { seq } => {
                j.plan.candidate.account.as_mut().unwrap().records.insert(
                    record_key(RecordKind::Meta, ACCOUNT_META_ID),
                    LocalRecord {
                        record,
                        seq: *seq,
                        dirty: false,
                    },
                );
            }
            PushResult::Conflict { .. } => {
                return Err(failure(
                    "account migration gate changed; resume from a fresh baseline",
                ))
            }
        },
        _ => return Err(failure("account migration gate is not writable")),
    };
    j.gate_written = true;
    j.phase = "account-gated".into();
    save(paths, j)?;
    #[cfg(test)]
    step(Step::AccountGated)?;
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
fn verify_legacy_sources(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    relay: &dyn RelayApi,
    account: &ChainKeys,
    code: &str,
) -> Result<(), AppError> {
    let mut pulls = BTreeMap::new();
    let account_pull = pull(env, paths, j, relay, account, j.source_kind == "legacy_v1")?;
    if let Some(p) = account_pull {
        observed_gate(account, &p)?;
        pulls.insert(account.chain_id.clone(), p);
    }
    if let Some(p) = pulls.get(&account.chain_id) {
        let mut records = BTreeMap::new();
        for e in &p.records {
            if e.kind == "space" {
                if let Some(record) = source::open_public(account, e)? {
                    records.insert(
                        record_key(record.kind, &record.id),
                        LocalRecord {
                            record,
                            seq: e.seq,
                            dirty: false,
                        },
                    );
                }
            }
        }
        let section = AccountState {
            records,
            sealed: p
                .records
                .iter()
                .filter(|e| e.kind == "spacekey")
                .map(|e| {
                    (
                        crate::sync::state_v2::sealed_key(&e.kind, &e.id_hash),
                        crate::sync::state_v2::SealedRecord {
                            envelope: e.clone(),
                            dirty: false,
                            public_identity: None,
                        },
                    )
                })
                .collect(),
            ..AccountState::new(&account.chain_id)
        };
        for (id, expected) in &j.plan.space_identities {
            let actual = record_merge::space_keys(&section, account, id)?
                .or_else(|| {
                    if j.source_kind == "legacy_v1" {
                        crate::sync::crypto::derive_space0(code)
                            .ok()
                            .filter(|k| &k.chain_id == id)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| failure("migration selected space identity is missing"))?;
            if space_identity(&actual) != *expected {
                return Err(failure("migration selected space encryption identity changed; originals retained for review"));
            }
        }
    }
    let ids: BTreeSet<_> = j
        .plan
        .legacy_digests
        .keys()
        .filter_map(|s| s.split_once(':').map(|(id, _)| id.to_string()))
        .collect();
    for id in ids {
        if pulls.contains_key(&id) {
            continue;
        }
        let keys = if j.source_kind == "legacy_v1"
            && crate::sync::crypto::derive_keys(code)?.chain_id == id
        {
            crate::sync::crypto::derive_keys(code)?
        } else {
            chain_keys(j, account, &id, code)?
        };
        if let Some(p) = pull(env, paths, j, relay, &keys, false)? {
            pulls.insert(id, p);
        }
    }
    if let Err(error) = check_legacy_sources(j, &pulls) {
        let review=serde_json::to_vec_pretty(&json!({"version":1,"migration_id":j.plan.migration_id,"code":"legacy_source_changed","ciphertext_sources":pulls.into_iter().map(|(id,p)|(id,p.records)).collect::<BTreeMap<_,_>>()})).map_err(|_|failure("migration review sources cannot be encoded"))?;
        if review.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(failure("migration review sources exceed the size limit"));
        }
        crate::fsutil::atomic_write(&paths.review, &review, 0o600)?;
        return Err(error);
    }
    Ok(())
}
fn check_legacy_sources(
    j: &Journal,
    pulls: &BTreeMap<String, PullResponse>,
) -> Result<(), AppError> {
    for (identity, expected) in &j.plan.legacy_digests {
        let (chain, id) = identity
            .split_once(':')
            .ok_or_else(|| failure("migration source receipt is invalid"))?;
        let source = pulls
            .get(chain)
            .and_then(|p| p.records.iter().find(|e| e.id_hash == id))
            .ok_or_else(|| {
                failure("legacy migration source disappeared; originals were retained")
            })?;
        if digest(&serde_json::to_vec(source).unwrap()) != *expected {
            return Err(failure("legacy migration source changed after confirmation; originals were retained for review"));
        }
    }
    Ok(())
}
fn update_public_candidate(
    j: &mut Journal,
    chain: &str,
    keys: &ChainKeys,
    current: &Envelope,
) -> Result<(), AppError> {
    let record = source::open_public(keys, current)?
        .ok_or_else(|| failure("migration conflict is not a public record"))?;
    if record.kind == RecordKind::Host {
        records_v3::decode_host(
            &record,
            records_v3::HostScope::Space {
                space_id: chain.into(),
            },
        )
        .map_err(|_| failure("migration destination host requires review"))?;
        j.plan
            .candidate
            .spaces
            .get_mut(chain)
            .ok_or_else(|| failure("migration destination space is missing"))?
            .records
            .insert(
                record_key(record.kind, &record.id),
                LocalRecord {
                    record,
                    seq: current.seq,
                    dirty: false,
                },
            );
    } else if record.kind == RecordKind::KeySlot {
        records_v3::decode_keyslot(&record)
            .map_err(|_| failure("migration destination key metadata requires review"))?;
        j.plan.candidate.account.as_mut().unwrap().records.insert(
            record_key(record.kind, &record.id),
            LocalRecord {
                record,
                seq: current.seq,
                dirty: false,
            },
        );
    } else if record.kind == RecordKind::Space || record.kind == RecordKind::Device {
        j.plan.candidate.account.as_mut().unwrap().records.insert(
            record_key(record.kind, &record.id),
            LocalRecord {
                record,
                seq: current.seq,
                dirty: false,
            },
        );
    } else {
        return Err(failure(
            "migration destination identity conflicts with a source",
        ));
    }
    Ok(())
}
fn select_batch(items: &[PushItem]) -> Result<Vec<PushItem>, AppError> {
    let mut out = Vec::new();
    for i in items.iter().take(200) {
        out.push(i.clone());
        if serde_json::to_vec(&out)
            .map_err(|_| failure("migration batch cannot be encoded"))?
            .len()
            > MAX_CHAIN_BYTES
        {
            out.pop();
            break;
        }
    }
    if out.is_empty() && !items.is_empty() {
        return Err(failure("migration batch exceeds the relay body limit"));
    }
    Ok(out)
}
fn publish_chain(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    relay: &dyn RelayApi,
    keys: &ChainKeys,
) -> Result<(), AppError> {
    loop {
        let p = pull(env, paths, j, relay, keys, false)?.unwrap();
        let account_keys = code_keys(
            j,
            &Zeroizing::new(
                env.keychain
                    .get(&format!("{CODE_PREFIX}{}", j.plan.migration_id))
                    .map_err(|_| failure("migration scoped code cannot be read"))?
                    .ok_or_else(|| failure("migration scoped code is unavailable"))?,
            ),
        )?;
        let account_pull = if keys.chain_id == account_keys.chain_id {
            p.clone()
        } else {
            pull(env, paths, j, relay, &account_keys, false)?.unwrap()
        };
        observed_gate(&account_keys, &account_pull)?;
        let mut seen = Vec::new();
        let planned = j.plan.chains[&keys.chain_id].items.clone();
        for i in &planned {
            if let Some(existing) = p
                .records
                .iter()
                .find(|e| e.kind == i.kind && e.id_hash == i.id_hash)
            {
                if existing.seq > i.base_seq {
                    if i.kind == "spacekey" {
                        if existing.ciphertext != i.ciphertext {
                            let current = record_merge::space_keys(
                                j.plan.candidate.account.as_ref().unwrap(),
                                &account_keys,
                                &keys.chain_id,
                            )?;
                            let _ = current;
                        }
                    } else {
                        update_public_candidate(j, &keys.chain_id, keys, existing)?;
                    }
                    seen.push((i.kind.clone(), i.id_hash.clone()));
                }
            }
        }
        if !seen.is_empty() {
            j.plan
                .chains
                .get_mut(&keys.chain_id)
                .unwrap()
                .items
                .retain(|i| !seen.contains(&(i.kind.clone(), i.id_hash.clone())));
            save(paths, j)?;
        }
        let mut chain = j.plan.chains[&keys.chain_id].clone();
        chain.original = p.records;
        capacity(&chain)?;
        let batch = select_batch(&chain.items)?;
        if batch.is_empty() {
            return Ok(());
        }
        j.phase = "publishing".into();
        save(paths, j)?;
        let outcome = relay
            .push(&keys.chain_id, &keys.auth_token, &batch)
            .map_err(|e| retry_failure(env, paths, j, e))?;
        let PushOutcome::Applied(results) = outcome else {
            return Err(failure("migration destination is frozen"));
        };
        if results.len() != batch.len() {
            return Err(failure("migration publication receipts are incomplete"));
        }
        for (item, result) in batch.iter().zip(results) {
            match result {
                PushResult::Accepted { seq } => {
                    if seq == 0 || seq > 9_007_199_254_740_991 {
                        return Err(failure("migration receipt sequence is invalid"));
                    }
                    if item.kind == "host" {
                        if let Some(row) =
                            j.plan
                                .candidate
                                .spaces
                                .get_mut(&keys.chain_id)
                                .and_then(|s| {
                                    s.records.values_mut().find(|r| {
                                        crate::sync::crypto::id_hash(keys, "host", &r.record.id)
                                            == item.id_hash
                                    })
                                })
                        {
                            row.seq = seq;
                        }
                    } else if item.kind == "keyslot" || item.kind == "space" {
                        if let Some(row) = j.plan.candidate.account.as_mut().and_then(|a| {
                            a.records.values_mut().find(|r| {
                                crate::sync::crypto::id_hash(
                                    keys,
                                    r.record.kind.as_str(),
                                    &r.record.id,
                                ) == item.id_hash
                            })
                        }) {
                            row.seq = seq;
                        }
                    }
                }
                PushResult::Conflict { current } => {
                    if item.kind == "spacekey" {
                        return Err(failure(
                            "migration space encryption identity changed; review is required",
                        ));
                    }
                    update_public_candidate(j, &keys.chain_id, keys, &current)?;
                }
            }
            j.plan
                .chains
                .get_mut(&keys.chain_id)
                .unwrap()
                .items
                .retain(|i| i.kind != item.kind || i.id_hash != item.id_hash);
        }
        save(paths, j)?;
        #[cfg(test)]
        step(Step::BatchSaved)?;
    }
}
fn fresh_candidate(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    relay: &dyn RelayApi,
    keys: &ChainKeys,
    code: &str,
) -> Result<SyncStateV3, AppError> {
    let account_pull = pull(env, paths, j, relay, keys, false)?.unwrap();
    let gate = observed_gate(keys, &account_pull)?;
    let meta = current_meta(keys, &account_pull)?
        .ok_or_else(|| failure("migration account metadata is missing"))?;
    let mut section = AccountState::new(&keys.chain_id);
    let mut synthetic = meta.0.clone();
    synthetic.version = synthetic
        .version
        .checked_add(1)
        .ok_or_else(|| failure("migration revision exhausted"))?;
    synthetic.updated_at_ms = synthetic
        .updated_at_ms
        .checked_add(1)
        .ok_or_else(|| failure("migration timestamp exhausted"))?;
    synthetic.payload =
        json!({"schema_version":3,"created_by_app_version":env!("CARGO_PKG_VERSION")});
    section.records.insert(
        record_key(RecordKind::Meta, ACCOUNT_META_ID),
        LocalRecord {
            record: synthetic,
            seq: meta.1,
            dirty: false,
        },
    );
    let merged = record_merge::merge_account(&section, keys, &account_pull, 0);
    if merged.gate != AccountGate::Compatible
        || merged
            .diagnostics
            .iter()
            .any(|d| d.code != record_merge::DiagnosticCode::Unsupported)
    {
        return Err(failure("migration final account baseline is incomplete"));
    }
    let mut candidate = j.plan.candidate.clone();
    candidate.account = Some(merged.section);
    candidate.account.as_mut().unwrap().records.insert(
        record_key(RecordKind::Meta, ACCOUNT_META_ID),
        LocalRecord {
            record: meta.0,
            seq: meta.1,
            dirty: false,
        },
    );
    candidate.migration_gate = gate;
    let mut pulls = BTreeMap::new();
    pulls.insert(keys.chain_id.clone(), account_pull);
    for id in j
        .plan
        .chains
        .keys()
        .filter(|id| *id != &keys.chain_id)
        .cloned()
        .collect::<Vec<_>>()
    {
        let child = chain_keys(j, keys, &id, code)?;
        let p = pull(env, paths, j, relay, &child, false)?.unwrap();
        let merged = record_merge::merge_space(
            &SpaceStateV3 {
                selected: true,
                ..Default::default()
            },
            &child,
            &p,
            0,
            &AccountGate::Compatible,
        );
        if merged.gate != AccountGate::Compatible
            || merged
                .diagnostics
                .iter()
                .any(|d| d.code != record_merge::DiagnosticCode::Unsupported)
        {
            return Err(failure("migration final space baseline is incomplete"));
        }
        if let Some(expected) = j.plan.candidate.spaces.get(&id) {
            for (key, row) in &expected.records {
                if row.seq > 0 && !merged.section.records.contains_key(key) {
                    return Err(failure("migration published typed row is missing from the full baseline; activation paused"));
                }
            }
        }
        candidate.spaces.insert(id.clone(), merged.section);
        pulls.insert(id, p);
    }
    if j.source_kind == "legacy_v1" {
        let old = crate::sync::crypto::derive_keys(code)?;
        if let Some(p) = pull(env, paths, j, relay, &old, true)? {
            pulls.insert(old.chain_id, p);
        }
    }
    check_legacy_sources(j, &pulls)?;
    Ok(candidate)
}
fn finish_gate(
    env: &SyncEnv,
    paths: &Paths,
    j: &mut Journal,
    relay: &dyn RelayApi,
    keys: &ChainKeys,
) -> Result<(), AppError> {
    let p = pull(env, paths, j, relay, keys, false)?.unwrap();
    if observed_gate(keys, &p)?.is_some_and(|g| g.phase == MigrationPhase::Active) {
        return Ok(());
    }
    let (record, item) = make_meta(j, current_meta(keys, &p)?, MigrationPhase::Active, env)?;
    let outcome = relay
        .push(&keys.chain_id, &keys.auth_token, &[item])
        .map_err(|e| retry_failure(env, paths, j, e))?;
    match outcome {
        PushOutcome::Applied(results) if results.len() == 1 => match &results[0] {
            PushResult::Accepted { seq } => {
                j.plan.candidate.account.as_mut().unwrap().records.insert(
                    record_key(RecordKind::Meta, ACCOUNT_META_ID),
                    LocalRecord {
                        record,
                        seq: *seq,
                        dirty: false,
                    },
                );
                j.plan.candidate.migration_gate.as_mut().unwrap().phase = MigrationPhase::Active;
                save(paths, j)?;
                Ok(())
            }
            _ => Err(failure(
                "migration activation marker changed; resume from fresh metadata",
            )),
        },
        _ => Err(failure("migration activation marker is not writable")),
    }
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
    code: &str,
) -> Result<MigrationReceipt, AppError> {
    if j.next_retry_ms > env.now() {
        return Err(failure("migration network backoff is still active"));
    }
    if j.plan.candidate.account.is_none() {
        return execute_local(env, paths, j);
    }
    let keys = code_keys(j, code)?;
    let relay = env.relay(&j.plan.candidate.relay_url)?;
    if let Some(receipt) = completed_receipt(paths, j, env)? {
        return Ok(receipt);
    }
    source::verify_local(env, j, code)?;
    verify_legacy_sources(env, paths, j, &*relay, &keys, code)?;
    ensure_chains(env, paths, j, &*relay, &keys, code)?;
    gate_account(env, paths, j, &*relay, &keys)?;
    let ids: Vec<_> = j.plan.chains.keys().cloned().collect();
    for id in ids {
        let child = chain_keys(j, &keys, &id, code)?;
        publish_chain(env, paths, j, &*relay, &child)?;
    }
    j.plan.candidate = fresh_candidate(env, paths, j, &*relay, &keys, code)?;
    record_runtime::save_active(&paths.state, &j.plan.candidate)?;
    save(paths, j)?;
    copy_passwords(env, paths, j)?;
    set_absent_or_same(env, crate::sync::state::MNEMONIC_ACCOUNT, code)?;
    // Migration never publishes the staged vault over later Local material. Validate the latest
    // encrypted vault read-only; final state rebase preserves concurrent Local metadata.
    let vault = crate::vault::store::read_vault(
        &crate::vault::store::vault_path(&env.state_path),
        env.keychain,
    )
    .map_err(|_| {
        failure("current vault is not safely readable; encrypted snapshots were retained")
    })?;
    for id in vault.ids() {
        vault.get(&id).map_err(|_| {
            failure("current vault material cannot be validated; encrypted snapshots were retained")
        })?;
    }
    #[cfg(test)]
    step(Step::VaultPublished)?;
    finish_gate(env, paths, j, &*relay, &keys)?;
    j.plan.candidate = fresh_candidate(env, paths, j, &*relay, &keys, code)?;
    j.plan.candidate.shared_writes_blocked = false;
    j.plan.candidate.pending_account = None;
    j.plan.candidate.local.import_receipts.insert(
        j.plan.migration_id.clone(),
        records_v3::LocalImportReceipt {
            source_digest: j.plan.source_digest.clone(),
            host_ids: j
                .plan
                .candidate
                .spaces
                .values()
                .flat_map(|s| s.records.values())
                .chain(j.plan.candidate.local.hosts.values())
                .map(|r| r.record.id.clone())
                .collect(),
            key_ids: j.plan.candidate.local.keys.keys().cloned().collect(),
        },
    );
    record_runtime::save_active(&paths.state, &j.plan.candidate)?;
    save(paths, j)?;
    #[cfg(test)]
    step(Step::BeforeStateSave)?;
    let original_keys = read_optional(&paths.original_state, MAX_STATE_BYTES)?
        .as_ref()
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|s| records_v3::decode_state(s).ok())
        .and_then(|s| {
            if let records_v3::DecodedState::V3(old) = s {
                Some(old.local.keys.keys().cloned().collect::<BTreeSet<_>>())
            } else {
                None
            }
        })
        .unwrap_or_default();
    for _ in 0..16 {
        let (mut candidate, generation) = {
            let core = env.runtime.core.lock().unwrap();
            if core.save_blocked.is_some() || core.generation == u64::MAX {
                return Err(failure("migration runtime activation is blocked"));
            }
            let mut candidate = j.plan.candidate.clone();
            if core.format == RuntimeFormat::Records {
                let latest = record_runtime::active_state(&core)?;
                if latest
                    .account
                    .as_ref()
                    .is_some_and(|a| a.chain_id != keys.chain_id)
                {
                    return Err(failure("migration runtime account changed"));
                }
                let mut local = latest.local.clone();
                if j.source_kind.starts_with("legacy_") {
                    for (id, r) in &candidate.local.hosts {
                        local.hosts.entry(id.clone()).or_insert_with(|| r.clone());
                    }
                }
                for (id, k) in &candidate.local.keys {
                    if !j.source_kind.starts_with("legacy_")
                        && !latest.local.keys.contains_key(id)
                        && original_keys.contains(id)
                    {
                        continue;
                    }
                    local.keys.entry(id.clone()).or_insert_with(|| k.clone());
                }
                local
                    .import_receipts
                    .extend(candidate.local.import_receipts.clone());
                candidate.local = local;
                candidate.device_name = latest.device_name.clone();
                candidate.notices = latest.notices.clone();
                candidate.phrase_cleanup_pending = latest.phrase_cleanup_pending;
            } else if core.generation != j.source_generation {
                return Err(failure(
                    "legacy migration runtime changed; originals were retained",
                ));
            }
            (candidate, core.generation)
        };
        candidate.last_error = None;
        match record_runtime::commit_migration_candidate(
            env,
            generation,
            candidate,
            Some(keys.clone()),
        ) {
            Ok(_) => {
                j.state_published = true;
                save(paths, j)?;
                #[cfg(test)]
                step(Step::StateSaved)?;
                j.phase = "active".into();
                save(paths, j)?;
                #[cfg(test)]
                step(Step::ActiveSaved)?;
                return Ok(j.receipt());
            }
            Err(e) if e.to_string() == crate::sync::runtime::superseded().to_string() => continue,
            Err(e) => return Err(e),
        }
    }
    Err(failure(
        "migration runtime changed repeatedly; resume its journal",
    ))
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
