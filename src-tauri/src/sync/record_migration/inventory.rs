//! Completed migration evidence from descriptor-captured bytes. Never follow source paths or resume effects.
use super::*;
pub(in crate::sync) struct Images {
    pub states: Vec<SyncStateV3>,
    pub legacy: Vec<Zeroizing<Vec<u8>>>,
    pub chains: Vec<(String, Vec<Envelope>)>,
    pub admitted: BTreeSet<PathBuf>,
}
fn invalid() -> AppError {
    failure("Finish or review the retained legacy migration before central synchronization. Every original source is retained.")
}
fn image(bytes: &[u8]) -> Result<records_v3::DecodedState, AppError> {
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(invalid());
    }
    records_v3::decode_state(std::str::from_utf8(bytes).map_err(|_| invalid())?)
        .map_err(|_| invalid())
}
pub(in crate::sync) fn read_all(
    selected: &SyncStateV3,
    files: &BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
) -> Result<Images, AppError> {
    let mut operations = BTreeSet::new();
    for path in files
        .keys()
        .filter(|path| path.starts_with("data/migrations"))
    {
        let parts: Vec<_> = path
            .iter()
            .map(|part| part.to_str().ok_or_else(invalid))
            .collect::<Result<_, _>>()?;
        if parts.len() < 4 || !crate::sync::slot_rules::is_slot_id(parts[2]) {
            return Err(invalid());
        }
        operations.insert(parts[2].to_owned());
        if operations.len() > 1024 {
            return Err(invalid());
        }
    }
    let mut result = Images {
        states: vec![],
        legacy: vec![],
        chains: vec![],
        admitted: BTreeSet::new(),
    };
    for operation in operations {
        let base = Path::new("data/migrations").join(&operation);
        let read = |name: &str| files.get(&base.join(name)).ok_or_else(invalid);
        let journal = publication::parse_captured_journal(read("journal.json")?, &operation)?;
        if journal.phase != "active"
            || !journal.state_published
            || selected
                .local
                .import_receipts
                .get(&operation)
                .is_none_or(|receipt| receipt.source_digest != journal.plan.source_digest)
            || journal
                .plan
                .candidate
                .local
                .import_receipts
                .get(&operation)
                .is_none_or(|receipt| receipt.source_digest != journal.plan.source_digest)
        {
            return Err(invalid());
        }
        let records_v3::DecodedState::V3(staged) = image(read("state.json")?)? else {
            return Err(invalid());
        };
        if *staged != journal.plan.candidate {
            return Err(invalid());
        }
        result.states.push(*staged);
        let mut admitted: BTreeSet<_> = ["journal.json", "state.json"]
            .into_iter()
            .map(|name| base.join(name))
            .collect();
        if journal.source_state_digest != digest(&[]) {
            let original = read("original-state.json")?;
            if digest(original) != journal.source_state_digest {
                return Err(invalid());
            }
            match image(original)? {
                records_v3::DecodedState::V3(state) => result.states.push(*state),
                records_v3::DecodedState::V2(state) => {
                    if state.legacy_v1_backup.as_ref().is_some_and(|name| {
                        name.contains(['/', '\\', '\0'])
                            || !name.starts_with("sync-state")
                            || !files.contains_key(&Path::new("data").join(name))
                    }) {
                        return Err(invalid());
                    }
                    result.legacy.push(original.clone());
                }
                records_v3::DecodedState::V1(_) => result.legacy.push(original.clone()),
            }
            admitted.insert(base.join("original-state.json"));
        }
        for name in ["vault.json", "original-vault.json"] {
            if files.contains_key(&base.join(name)) {
                admitted.insert(base.join(name));
            }
        }
        for (id, chain) in journal.plan.chains {
            let mut rows = chain.original;
            rows.extend(chain.items.into_iter().map(|item| Envelope {
                seq: item.base_seq,
                id_hash: item.id_hash,
                kind: item.kind,
                nonce: item.nonce,
                ciphertext: item.ciphertext,
                deleted: item.deleted,
            }));
            result.chains.push((id, rows));
        }
        let mut document_bytes = 0usize;
        for source in journal.plan.documents {
            let name =
                Path::new("documents").join(format!("{}.config", digest(source.source.as_bytes())));
            let bytes = files.get(&base.join(&name)).ok_or_else(invalid)?;
            document_bytes = document_bytes
                .checked_add(bytes.len())
                .ok_or_else(invalid)?;
            let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
            if source.source.len() > 4096
                || !crate::sync::crypto::is_chain_id(&source.disk_digest)
                || digest(bytes) != source.memory_digest
                || document_bytes as u64 > MAX_LOCAL_SOURCE_BYTES
                || text.contains("PRIVATE KEY-----")
            {
                return Err(invalid());
            }
            admitted.insert(base.join(name));
        }
        if let Some(bytes) = files.get(&base.join("review-sources.json")) {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Review {
                version: u32,
                migration_id: String,
                code: String,
                ciphertext_sources: BTreeMap<String, Vec<Envelope>>,
            }
            let review: Review = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            if bytes.len() as u64 > MAX_JOURNAL_BYTES
                || review.version != 1
                || review.migration_id != operation
                || review.code != "legacy_source_changed"
                || review.ciphertext_sources.len() > 65
            {
                return Err(invalid());
            }
            for (id, rows) in review.ciphertext_sources {
                if !crate::sync::crypto::is_chain_id(&id) || rows.len() > MAX_CHAIN_RECORDS {
                    return Err(invalid());
                }
                result.chains.push((id, rows));
            }
            admitted.insert(base.join("review-sources.json"));
        }
        if files
            .keys()
            .any(|path| path.starts_with(&base) && !admitted.contains(path))
        {
            return Err(invalid());
        }
        result.admitted.extend(admitted);
    }
    Ok(result)
}
