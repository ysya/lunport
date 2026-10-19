//! Completed legacy import evidence only. Never replay an overlay or access original source paths.
use super::*;
pub(in crate::sync) struct Images {
    pub states: Vec<SyncStateV3>,
    pub admitted: BTreeSet<PathBuf>,
}
struct Masters<'a> {
    keychain: &'a dyn Keychain,
    operation: &'a str,
}
impl Keychain for Masters<'_> {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        if !is_vault_account(account) {
            return Err(failure("untrusted import master role"));
        }
        if let Some(value) = self
            .keychain
            .get(&format!("migration:{}:{account}", self.operation))?
        {
            return Ok(Some(value));
        }
        self.keychain.get(account)
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        Err(failure("import inventory is read-only"))
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        Err(failure("import inventory is read-only"))
    }
}
fn state(bytes: &[u8]) -> Result<SyncStateV3, AppError> {
    if bytes.len() as u64 > record_runtime::MAX_STATE_BYTES {
        return Err(failure("import state image is too large"));
    }
    let state: SyncStateV3 = serde_json::from_slice(bytes)
        .map_err(|_| failure("import state needs supported normalization"))?;
    crate::sync::records_v3::validate_state(&state)
        .map_err(|_| failure("import state is invalid"))?;
    Ok(state)
}
const NAMES: [&str; 6] = [
    "journal.json",
    "state.json",
    "original-state.json",
    "vault.json",
    "original-vault.json",
    "master-receipts.json",
];
/// The keychain must be the captured decryptor Snapshot, never the live OS adapter.
pub(in crate::sync) fn read_all(
    selected: &SyncStateV3,
    files: &BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    keychain: &crate::sync::central::inventory_keys::Snapshot,
) -> Result<Images, AppError> {
    let mut operations = BTreeSet::new();
    for path in files.keys().filter(|p| p.starts_with("data/imports")) {
        let parts: Vec<_> = path
            .iter()
            .map(|v| {
                v.to_str()
                    .ok_or_else(|| failure("invalid captured import path"))
            })
            .collect::<Result<_, _>>()?;
        if parts.len() != 4
            || !crate::sync::slot_rules::is_slot_id(parts[2])
            || !NAMES.contains(&parts[3])
        {
            return Err(failure(
                "unknown import evidence must be resolved before migration",
            ));
        }
        operations.insert(parts[2].to_owned());
        if operations.len() > 1024 {
            return Err(failure("too many import evidence directories"));
        }
    }
    let mut result = Images {
        states: vec![],
        admitted: BTreeSet::new(),
    };
    for operation in operations {
        let base = Path::new("data/imports").join(&operation);
        let bytes = files
            .get(&base.join("journal.json"))
            .ok_or_else(|| failure("import journal is missing"))?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(failure("import journal is too large"));
        }
        let journal: Journal = serde_json::from_slice(bytes)
            .map_err(|_| failure("import journal needs supported normalization"))?;
        validate_journal(&journal, &operation)?;
        if journal.phase != Phase::Active
            || !journal.originals_captured
            || journal.central_intent.is_some()
            || !already_applied(selected, &journal)?
        {
            return Err(failure(
                "finish the pending import or account recovery before migration",
            ));
        }
        if journal.completed_hosts != journal.hosts.iter().map(|host| host.id.clone()).collect()
            || journal.completed_keys != journal.keys.keys().cloned().collect()
        {
            return Err(failure("completed import evidence is incomplete"));
        }
        let original = state(
            files
                .get(&base.join("original-state.json"))
                .ok_or_else(|| failure("original import state is missing"))?,
        )?;
        let staged = state(
            files
                .get(&base.join("state.json"))
                .ok_or_else(|| failure("staged import state is missing"))?,
        )?;
        if !already_applied(&staged, &journal)? {
            return Err(failure("staged import receipt differs"));
        }
        for host in &journal.hosts {
            crate::sync::records_v3::validate_host(host)
                .map_err(|_| failure("invalid import host evidence"))?;
            let key = record_key(RecordKind::Host, &host.id);
            let row = staged
                .local
                .hosts
                .get(&key)
                .ok_or_else(|| failure("staged import host is missing"))?;
            if row.record.deleted
                || row.record.id != host.id
                || row.record.kind != RecordKind::Host
                || row.record.payload
                    != serde_json::to_value(&host.payload)
                        .map_err(|_| failure("invalid import host evidence"))?
            {
                return Err(failure("staged import host metadata differs"));
            }
        }
        if journal
            .keys
            .iter()
            .any(|(id, key)| staged.local.keys.get(id) != Some(key))
        {
            return Err(failure("staged import key mapping differs"));
        }
        let original_vault = files.get(&base.join("original-vault.json"));
        let staged_vault = files.get(&base.join("vault.json"));
        if original_vault.map(|b| digest(b)) != journal.original_vault_digest
            || staged_vault.map(|b| digest(b)) != journal.staged_vault_digest
        {
            return Err(failure("captured import vault digest differs"));
        }
        if let Some(bytes) = staged_vault {
            let view = store::read_vault_image(
                bytes,
                &Masters {
                    keychain,
                    operation: &operation,
                },
            )
            .map_err(|_| failure("captured import vault cannot be opened"))?;
            if Some(view.key_account()) != journal.staged_key_account.as_deref() {
                return Err(failure("captured import master selection differs"));
            }
            verify_material(&view, &journal)?;
        } else if !journal.keys.is_empty() || journal.staged_key_account.is_some() {
            return Err(failure("import material evidence is missing"));
        }
        if let Some(bytes) = files.get(&base.join("master-receipts.json")) {
            if bytes.len() as u64 > MAX_JOURNAL_BYTES {
                return Err(failure("captured master receipts are too large"));
            }
            let roles: BTreeSet<String> = serde_json::from_slice(bytes)
                .map_err(|_| failure("captured master receipts are unreadable"))?;
            if roles.iter().any(|role| !is_vault_account(role)) {
                return Err(failure("captured master receipt contains an unknown role"));
            }
        }
        for name in NAMES {
            let path = base.join(name);
            if files.contains_key(&path) {
                result.admitted.insert(path);
            }
        }
        result.states.extend([original, staged]);
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
