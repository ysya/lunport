//! Passive completed-stage evidence. Never executes publication, overlays, consent or recovery.
use super::*;
use crate::sync::{
    central::inventory_keys::Snapshot,
    record_import::inventory::{Images, Masters},
};
use std::path::PathBuf;
use zeroize::Zeroizing;
const NAMES: [&str; 5] = [
    "journal.json",
    "original-state.json",
    "original-vault.json",
    "vault.json",
    "master-receipts.json",
];
fn check_entry(entry: &VaultEntry) -> Result<(), AppError> {
    let private =
        central::payload::PrivateMaterial::new(Zeroizing::new(entry.private_key.clone()))?;
    let parsed = crate::vault::material::parse(private.private())
        .ok_or_else(|| failure("invalid retained central material"))?;
    if private.fingerprint != entry.fingerprint
        || crate::vault::material::public_key_data(&entry.public_key).as_ref()
            != Some(parsed.public_key().key_data())
        || entry.added_at_ms > central::wire::MAX_SAFE_INTEGER
    {
        return Err(failure("retained central material metadata differs"));
    }
    Ok(())
}
fn same(a: &VaultEntry, b: &VaultEntry) -> bool {
    a.private_key == b.private_key
        && a.public_key == b.public_key
        && a.fingerprint == b.fingerprint
        && a.origin == b.origin
        && a.added_at_ms == b.added_at_ms
}
fn check_binding(
    binding: &Binding,
    entry: &VaultEntry,
    original: Option<&VaultEntry>,
    staged_at_ms: u64,
) -> Result<(), AppError> {
    if digest(entry.private_key.as_bytes()) != binding.sha256
        || (!binding.rebind && entry.added_at_ms != staged_at_ms)
    {
        return Err(failure("central stage private container differs"));
    }
    if binding.rebind {
        if !original.is_some_and(|prior| same(prior, entry)) {
            return Err(failure("central stage reused private container differs"));
        }
    } else if original.is_some() {
        return Err(failure("central stage replaces existing protected material"));
    }
    Ok(())
}
pub(in crate::sync::record_import) fn read_operation(
    selected: &SyncStateV3,
    operation: &str,
    files: &BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    keys: &Snapshot,
) -> Result<Option<Images>, AppError> {
    let base = Path::new("data/imports").join(operation);
    let raw = files
        .get(&base.join("journal.json"))
        .ok_or_else(|| failure("captured stage journal missing"))?;
    #[derive(Deserialize)]
    struct Kind {
        format: Option<String>,
    }
    let kind: Kind =
        serde_json::from_slice(raw).map_err(|_| failure("captured import header unreadable"))?;
    let Some(format) = kind.format else {
        return Ok(None);
    };
    if format != FORMAT || raw.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(failure("unsupported captured central stage"));
    }
    let j: Journal =
        serde_json::from_slice(raw).map_err(|_| failure("captured central stage is invalid"))?;
    validate_header(&j, operation)?;
    let matches = if j.initial.is_some() {
        initial_publish::matches_receipt(selected.local.import_receipts.get(operation), &j)?
    } else {
        publication::matches_receipt(selected.local.import_receipts.get(operation), &j)?
    };
    if j.phase != Phase::Active || !matches {
        return Err(failure(
            "finish pending central publication before historical migration",
        ));
    }
    let mut admitted = BTreeSet::new();
    for path in files.keys().filter(|p| p.starts_with(&base)) {
        if path.parent() != Some(base.as_path())
            || !path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| NAMES.contains(&s))
        {
            return Err(failure("unknown captured central stage input"));
        }
        admitted.insert(path.clone());
    }
    let original_bytes = files
        .get(&base.join("original-state.json"))
        .ok_or_else(|| failure("central stage original state missing"))?;
    if j.source_state_digest.as_ref() != Some(&digest(original_bytes)) {
        return Err(failure("central stage original state digest differs"));
    }
    let original = crate::sync::record_import::inventory::state(original_bytes)?;
    let owner = original
        .local
        .central
        .as_ref()
        .ok_or_else(|| failure("central stage historical owner missing"))?;
    let current = selected
        .local
        .central
        .as_ref()
        .ok_or_else(|| failure("selected historical account missing"))?;
    if owner.control.profile != j.profile
        || owner.control.anchor.as_ref() != Some(&j.anchor)
        || owner.control.device != j.device
        || owner.identity_slot != j.identity_slot
        || current.control.profile != j.profile
        || current.control.anchor.as_ref() != Some(&j.anchor)
    {
        return Err(failure("central stage account or source selection differs"));
    }
    if let Some(initial) = &j.initial {
        if !initial.matches_source(&original)? {
            return Err(failure("initial stage source differs"));
        }
    } else {
        let replica = owner
            .replica
            .as_ref()
            .ok_or_else(|| failure("central stage replica missing"))?;
        if !owner.control.cutover
            || replica.vault != j.vault
            || replica.checkpoint.epoch != j.checkpoint.epoch
            || replica.checkpoint.sequence < j.checkpoint.sequence
            || replica.checkpoint.sequence == j.checkpoint.sequence
                && replica.checkpoint.history_hash != j.checkpoint.history_hash
        {
            return Err(failure("central stage baseline differs"));
        }
        for (id, b) in &j.bindings {
            if original.local.keys.get(id) != b.old_material.as_ref()
                || !replica.current.values().any(|row| {
                    row.version.digest == b.public_digest
                        && row.version.envelope.header.kind == "keyslot"
                })
                || !replica.current.values().any(|row| {
                    row.version.digest == b.private_digest
                        && row.version.envelope.header.kind == "key"
                })
            {
                return Err(failure("central stage signed material basis differs"));
            }
        }
    }
    let original_vault = files.get(&base.join("original-vault.json"));
    let staged_vault = files.get(&base.join("vault.json"));
    if original_vault.map(|b| digest(b)) != j.source_vault_digest
        || staged_vault.map(|b| digest(b)) != j.staged_vault_digest
    {
        return Err(failure("central stage vault image differs"));
    }
    let master = Masters {
        keychain: keys,
        operation,
    };
    let old = original_vault
        .map(|b| store::read_vault_image(b, keys))
        .transpose()?;
    let staged = staged_vault
        .map(|b| store::read_vault_image(b, &master))
        .transpose()?;
    if staged.as_ref().map(|v| v.key_account()) != j.staged_key_account.as_deref() {
        return Err(failure("central stage scoped master differs"));
    }
    if let Some(view) = &old {
        for id in view.ids() {
            check_entry(
                &view
                    .get_inventory(&id)?
                    .ok_or_else(|| failure("missing original central material"))?,
            )?;
        }
    }
    if let Some(view) = &staged {
        for id in view.ids() {
            let entry = view
                .get_inventory(&id)?
                .ok_or_else(|| failure("missing staged central material"))?;
            check_entry(&entry)?;
            if let Some(b) = j.bindings.values().find(|b| b.protected_id == id) {
                let original = old
                    .as_ref()
                    .map(|v| v.get_inventory(&id))
                    .transpose()?
                    .flatten();
                check_binding(b, &entry, original.as_ref(), j.at_ms)?;
            } else {
                let prior = old
                    .as_ref()
                    .map(|v| v.get_inventory(&id))
                    .transpose()?
                    .flatten()
                    .ok_or_else(|| failure("unmapped staged central material"))?;
                if !same(&prior, &entry) {
                    return Err(failure("unrelated central material was changed"));
                }
            }
        }
    }
    for b in j.bindings.values() {
        if staged
            .as_ref()
            .map(|v| v.get_inventory(&b.protected_id))
            .transpose()?
            .flatten()
            .is_none()
        {
            return Err(failure("bound staged central material missing"));
        }
    }
    if let Some(view) = &old {
        for id in view.ids() {
            if staged
                .as_ref()
                .map(|v| v.get_inventory(&id))
                .transpose()?
                .flatten()
                .is_none()
            {
                return Err(failure("original central material was omitted"));
            }
        }
    }
    if let Some(raw) = files.get(&base.join("master-receipts.json")) {
        if raw.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(failure("central master receipts too large"));
        }
        let roles: BTreeSet<String> =
            serde_json::from_slice(raw).map_err(|_| failure("central master receipts invalid"))?;
        if roles.iter().any(|r| !super::super::is_vault_account(r)) {
            return Err(failure("untrusted central master role"));
        }
    }
    // Native staged receipts are inert; signed ciphertext semantics are admitted separately by
    // the historical-state reader before any source snapshot or merge can be accepted.
    Ok(Some(Images {
        states: vec![original],
        admitted,
        central_floors: vec![j.checkpoint],
    }))
}
#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use crate::sync::record_import::inventory;
    use std::time::Duration;
    #[test]
    fn reused_private_container_keeps_its_original_timestamp_and_exact_contents() {
        let original = VaultEntry {
            private_key: "retained material".into(),
            public_key: "public".into(),
            fingerprint: "fingerprint".into(),
            origin: EntryOrigin::Synced,
            added_at_ms: 100,
        };
        let binding = Binding {
            id: "a".repeat(32),
            protected_id: "b".repeat(32),
            public_digest: "c".repeat(64),
            private_digest: "d".repeat(64),
            sha256: digest(original.private_key.as_bytes()),
            rebind: true,
            old_material: None,
        };
        assert!(check_binding(&binding, &original, Some(&original), 200).is_ok());
        assert!(check_binding(&binding, &original, None, 200).is_err());
        let mut changed = original.clone();
        changed.added_at_ms = 200;
        assert!(check_binding(&binding, &changed, Some(&original), 200).is_err());
        changed = original.clone();
        changed.private_key.push('!');
        assert!(check_binding(&binding, &changed, Some(&original), 200).is_err());
        changed = original.clone();
        changed.public_key.push('!');
        assert!(check_binding(&binding, &changed, Some(&original), 200).is_err());

        let new_binding = Binding { rebind: false, ..binding };
        assert!(check_binding(&new_binding, &original, None, 200).is_err());
        let mut created = original.clone();
        created.added_at_ms = 200;
        assert!(check_binding(&new_binding, &created, None, 200).is_ok());
        assert!(check_binding(&new_binding, &created, Some(&original), 200).is_err());
    }
    fn fixture() -> (
        crate::sync::testkit::TestDevice,
        SyncStateV3,
        BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
        Snapshot,
        String,
    ) {
        let (device, keys, _, _) = super::super::tests::fixture();
        let env = device.env();
        super::super::publication::tests::session(&device, Duration::from_secs(300));
        let staged = prepare(&env, &super::super::tests::delta(&device, &keys)).unwrap();
        publish(&env, staged.operation(), &keys).unwrap();
        let selected = record_runtime::snapshot(&env).unwrap().0;
        let mut files = BTreeMap::new();
        let base = Path::new("data/imports").join(staged.operation());
        for e in fs::read_dir(&staged.paths.dir).unwrap() {
            let e = e.unwrap();
            files.insert(
                base.join(e.file_name()),
                Zeroizing::new(fs::read(e.path()).unwrap()),
            );
        }
        let journal: Journal = serde_json::from_slice(&files[&base.join("journal.json")]).unwrap();
        let mut roles = BTreeSet::new();
        if let Some(role) = &journal.staged_key_account {
            roles.insert(role.clone());
            roles.insert(format!("migration:{}:{role}", staged.operation()));
        }
        if let Some(bytes) = files.get(&base.join("original-vault.json")) {
            roles.insert(
                store::read_vault_image(bytes, &device.keychain)
                    .unwrap()
                    .key_account()
                    .to_owned(),
            );
        }
        let entries: Vec<_> = roles
            .into_iter()
            .filter_map(|role| {
                device
                    .keychain
                    .entry(&role)
                    .map(|value| serde_json::json!({"role":role,"value":value}))
            })
            .collect();
        let snapshot = Snapshot::decode_local(&Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({"version":1,"keys":entries})).unwrap(),
        ))
        .unwrap();
        let operation = staged.operation().to_owned();
        (device, selected, files, snapshot, operation)
    }
    #[test]
    fn completed_central_stage_reads_captured_images_and_retains_observed_checkpoint_without_effects(
    ) {
        let (device, mut selected, files, keys, _) = fixture();
        let before = fs::read(&device.env().state_path).unwrap();
        selected.local.keys.clear();
        device
            .keychain
            .fail_reads
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let read = inventory::read_all(&selected, &files, &keys).unwrap();
        assert_eq!(read.states.len(), 1);
        assert_eq!(read.admitted, files.keys().cloned().collect());
        assert_eq!(read.central_floors.len(), 1);
        assert!(read.central_floors[0].sequence > 0);
        assert_eq!(fs::read(&device.env().state_path).unwrap(), before);
    }
    #[test]
    fn altered_pending_missing_or_cross_account_central_stages_never_admit_partial_history() {
        let (_device, selected, files, keys, operation) = fixture();
        let base = Path::new("data/imports").join(&operation);
        for case in [
            "phase", "receipt", "source", "scope", "baseline", "binding", "vault", "master",
            "extra", "missing",
        ] {
            let mut files = files.clone();
            let mut selected = selected.clone();
            let mut j: Journal =
                serde_json::from_slice(&files[&base.join("journal.json")]).unwrap();
            match case {
                "phase" => j.phase = Phase::VaultPublished,
                "receipt" => selected.local.import_receipts.clear(),
                "source" => j.source_state_digest = Some("f".repeat(64)),
                "scope" => j.anchor.account_id = "e".repeat(64),
                "baseline" => j.checkpoint.history_hash = "d".repeat(64),
                "binding" => {
                    j.bindings.values_mut().next().unwrap().private_digest = "c".repeat(64)
                }
                "vault" => j.staged_vault_digest = Some("b".repeat(64)),
                "master" => {
                    files.insert(
                        base.join("master-receipts.json"),
                        Zeroizing::new(br#"["central:v2:device:bad"]"#.to_vec()),
                    );
                }
                "extra" => {
                    files.insert(base.join("unrecognized"), Zeroizing::new(vec![1]));
                }
                _ => {
                    files.remove(&base.join("vault.json"));
                }
            }
            files.insert(
                base.join("journal.json"),
                Zeroizing::new(serde_json::to_vec(&j).unwrap()),
            );
            assert!(
                inventory::read_all(&selected, &files, &keys).is_err(),
                "{case}"
            );
        }
    }
}
