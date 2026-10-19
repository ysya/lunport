//! Enclosed packages contribute inactive history, never activation or consent.
use super::*;
const MAX_DEPTH: usize = 8;
const MAX_PACKAGES: usize = 256;
impl Package {
    fn retained_packages(&self) -> Result<Vec<Package>, AppError> {
        fn visit(
            parent: &Package,
            selected: &Package,
            depth: usize,
            bytes: &mut usize,
            result: &mut Vec<Package>,
        ) -> Result<(), AppError> {
            parent.require_own_supported_files()?;
            let captured =
                source_archive::captured::read_all(&parent.files.bytes, &parent.decryptors)?;
            if depth >= MAX_DEPTH && !captured.frames.is_empty() {
                return Err(invalid());
            }
            for (_, plain) in &captured.frames {
                *bytes = bytes.checked_add(plain.len()).ok_or_else(invalid)?;
                if *bytes > MAX_BYTES {
                    return Err(invalid());
                }
            }
            let mut referenced = std::collections::BTreeSet::new();
            for (_, plain) in &captured.frames {
                if super::super::capture_journal::Journal::frame(plain) {
                    for receipt in
                        super::super::capture_journal::Journal::captured_references(plain)?
                    {
                        referenced.insert(receipt.ciphertext_hash);
                    }
                }
            }
            let mut covered = std::collections::BTreeSet::new();
            let read = |expected: &Receipt| -> Result<Zeroizing<Vec<u8>>, AppError> {
                let (_, plain) = captured
                    .frames
                    .iter()
                    .find(|(receipt, _)| receipt == expected)
                    .ok_or_else(invalid)?;
                Ok(Zeroizing::new(plain.to_vec()))
            };
            for (receipt, plain) in &captured.frames {
                if super::super::capture_journal::Journal::frame(plain)
                    && referenced.contains(&receipt.ciphertext_hash)
                {
                    continue;
                }
                if result.len() >= MAX_PACKAGES {
                    return Err(invalid());
                }
                let nested = if super::super::capture_journal::Journal::frame(plain) {
                    let (package, ancestors) =
                        super::super::capture_journal::Journal::captured_complete(
                            plain, receipt, &read,
                        )?;
                    covered.extend(ancestors.into_iter().map(|r| r.ciphertext_hash));
                    package
                } else {
                    Package::decode_local(plain)?
                };
                covered.insert(receipt.ciphertext_hash.clone());
                let owner = nested.state.local.central.as_ref().ok_or_else(invalid)?;
                receipt.matches_selected(owner)?;
                let current = selected.state.local.central.as_ref().ok_or_else(invalid)?;
                if current.control.anchor != owner.control.anchor
                    || current.control.profile != owner.control.profile
                    || current.control.device != owner.control.device
                    || current.control.personal_vault != owner.control.personal_vault
                {
                    return Err(invalid());
                }
                selected.sources.require_retained_subset(&nested.sources)?;
                visit(&nested, selected, depth + 1, bytes, result)?;
                if result.len() >= MAX_PACKAGES {
                    return Err(invalid());
                }
                result.push(nested);
            }
            if captured
                .frames
                .iter()
                .any(|(r, _)| !covered.contains(&r.ciphertext_hash))
            {
                return Err(invalid());
            }
            Ok(())
        }
        let mut result = vec![];
        visit(self, self, 0, &mut 0, &mut result)?;
        Ok(result)
    }
    pub(super) fn require_supported_files(&self) -> Result<(), AppError> {
        drop(self.retained_packages()?);
        Ok(())
    }
    pub fn record_inputs(&self) -> Result<Inventory, AppError> {
        let mut inventory = self.own_record_inputs()?;
        for package in self.retained_packages()? {
            inventory = inventory.with_retained_requirements(
                &self.sources,
                &package.sources,
                package.own_record_inputs()?,
            )?;
        }
        Ok(inventory)
    }
    pub fn materials(
        &self,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<Materials, AppError> {
        let mut materials = self.own_materials(keys, references)?;
        for package in self.retained_packages()? {
            materials =
                materials.with_retained_materials(package.own_materials(keys, references)?)?;
        }
        drop(self.record_inputs()?);
        Ok(materials)
    }
    pub fn structured_history(
        &self,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<super::super::migration_library::History, AppError> {
        drop(self.record_inputs()?);
        let mut retained = vec![];
        for package in self.retained_packages()? {
            retained.push(package.own_structured_history(keys, references)?);
        }
        self.own_structured_history(keys, references)?
            .with_retained(retained)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        sync::{
            central::inventory_keys::Capture,
            env::Keychain,
            record::{record_key, LocalRecord, Record, RecordKind},
        },
        vault::store::Vault,
    };
    use std::fs;
    fn rec(id: &str) -> LocalRecord {
        LocalRecord {
            record: Record {
                kind: RecordKind::Host,
                id: id.into(),
                version: 1,
                updated_at_ms: 1,
                device_id: "d".repeat(32),
                deleted: false,
                payload: serde_json::json!({"schema":2,"alias":"ancestor-only","hostname":"ancestor.invalid","auth":"password"}),
            },
            seq: 0,
            dirty: true,
        }
    }
    fn capture(
        device: &crate::sync::testkit::TestDevice,
        previous: &Package,
        keys: &VaultKeys,
    ) -> Package {
        let env = device.env();
        let state: SyncStateV3 =
            serde_json::from_slice(&fs::read(&env.state_path).unwrap()).unwrap();
        let files = Files::capture(&env, None).unwrap();
        let observer = Capture::new(&device.keychain);
        Materials::from_files(&state, keys, &files, &observer, &BTreeMap::new()).unwrap();
        drop(source_archive::captured::read_all(&files.bytes, &observer).unwrap());
        Package::assemble(
            &state,
            &previous.state_name,
            files,
            Sources::decode_local(&previous.sources.encode_local().unwrap(), &state).unwrap(),
            observer.finish().unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn nested_capsules_restore_unique_public_and_private_history_after_original_keys_and_files_are_removed(
    ) {
        let (device, mut first, keys, owner, raw) = super::super::tests::fixture();
        let env = device.env();
        let id = "a".repeat(16);
        first
            .state
            .local
            .hosts
            .insert(record_key(RecordKind::Host, &id), rec(&id));
        let image = Zeroizing::new(serde_json::to_vec(&first.state).unwrap());
        fs::write(&env.state_path, &*image).unwrap();
        first.files = Files::capture(&env, None).unwrap();
        {
            let life = env.runtime.lifecycle.lock().unwrap();
            first.archive(&env, &life, &owner, 1).unwrap();
        }
        let mut current = first.state.clone();
        current.local.hosts.clear();
        fs::write(&env.state_path, serde_json::to_vec(&current).unwrap()).unwrap();
        let mut vault = Vault::open(
            &env.state_path.parent().unwrap().join("vault.json"),
            &device.keychain,
            0,
        )
        .unwrap();
        assert!(vault.remove(&"3".repeat(32)).unwrap());
        drop(vault);
        let second = capture(&device, &first, &keys);
        {
            let life = env.runtime.lifecycle.lock().unwrap();
            second.archive(&env, &life, &owner, 2).unwrap();
        }
        let selected = capture(&device, &second, &keys);
        let encoded = selected.encode_local().unwrap();
        let book: serde_json::Value =
            serde_json::from_slice(&selected.decryptors.encode_local().unwrap()).unwrap();
        for key in book["keys"].as_array().unwrap() {
            device
                .keychain
                .delete(key["role"].as_str().unwrap())
                .unwrap();
        }
        fs::remove_dir_all(
            env.state_path
                .parent()
                .unwrap()
                .join("central-source-archives"),
        )
        .unwrap();
        let restored = Package::decode_local(&encoded).unwrap();
        assert!(restored.state.local.hosts.is_empty());
        assert!(restored.materials(&keys,&BTreeMap::new()).unwrap().into_history().iter().any(|(_,data)|matches!(data,super::super::super::payload::Data::Key(private) if private.private()==raw)));
        let rows = restored
            .structured_history(&keys, &BTreeMap::new())
            .unwrap()
            .into_rows();
        assert!(rows.iter().any(|(logical,data)|logical.id==id&&matches!(data,super::super::super::payload::Data::Host(h) if h.alias=="ancestor-only")));
        assert!(matches!(
            rows.iter()
                .rev()
                .find(|(logical, _)| logical.id == id)
                .unwrap()
                .1,
            super::super::super::payload::Data::Deleted
        ));
        assert_eq!(
            restored.encode_local().unwrap().as_slice(),
            encoded.as_slice()
        );
    }
    #[test]
    fn modified_missing_or_unscoped_capsule_evidence_never_admits_a_partial_library() {
        let (device, first, keys, owner, _) = super::super::tests::fixture();
        let env = device.env();
        {
            let life = env.runtime.lifecycle.lock().unwrap();
            first.archive(&env, &life, &owner, 1).unwrap();
        }
        let package = capture(&device, &first, &keys);
        let bytes = package.encode_local().unwrap();
        for kind in ["marker", "ciphertext", "name", "key", "extra", "nested"] {
            let mut test = Package::decode_local(&bytes).unwrap();
            let file = test
                .files
                .bytes
                .keys()
                .find(|p| p.extension().is_some_and(|e| e == "lpsource"))
                .unwrap()
                .clone();
            let marker = test
                .files
                .bytes
                .keys()
                .find(|p| {
                    p.starts_with("data/central-source-archives")
                        && p.extension().is_some_and(|e| e == "sha256")
                })
                .unwrap()
                .clone();
            match kind {
                "marker" => {
                    test.files.bytes.get_mut(&marker).unwrap()[0] ^= 1;
                }
                "ciphertext" => {
                    let cipher = test.files.bytes.get_mut(&file).unwrap();
                    let last = cipher.len() - 1;
                    cipher[last] ^= 1;
                }
                "key" => {
                    test.decryptors = Snapshot::decode_local(br#"{"version":1,"keys":[]}"#).unwrap()
                }
                "name" => {
                    let value = test.files.bytes.remove(&file).unwrap();
                    test.files.bytes.insert(
                        file.with_file_name(format!(
                            "{}-{}.lpsource",
                            "b".repeat(32),
                            "c".repeat(32)
                        )),
                        value,
                    );
                }
                _ => {
                    test.files.bytes.insert(
                        Path::new("data/central-source-archives").join(if kind == "extra" {
                            "extra"
                        } else {
                            "nested/archive"
                        }),
                        Zeroizing::new(vec![1]),
                    );
                }
            }
            assert!(test.materials(&keys, &BTreeMap::new()).is_err(), "{kind}");
            assert!(
                test.structured_history(&keys, &BTreeMap::new()).is_err(),
                "{kind}"
            );
        }
    }
    #[test]
    fn nested_capsule_depth_exhaustion_keeps_every_original_and_returns_no_partial_history() {
        let (device, mut package, keys, owner, _) = super::super::tests::fixture();
        let env = device.env();
        for ordinal in 0..=MAX_DEPTH {
            let archived = {
                let life = env.runtime.lifecycle.lock().unwrap();
                package
                    .archive(&env, &life, &owner, ordinal as u64)
                    .unwrap()
            };
            let files = Files::capture(&env, None).unwrap();
            let file = files
                .bytes
                .iter()
                .find(|(path, bytes)| {
                    path.extension().is_some_and(|v| v == "lpsource")
                        && super::super::super::crypto::hash(bytes)
                            == archived.receipt().ciphertext_hash
                })
                .unwrap()
                .0
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let marker = format!("{}-key.sha256", archived.receipt().operation());
            let root = env
                .state_path
                .parent()
                .unwrap()
                .join("central-source-archives");
            for entry in fs::read_dir(&root).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name() != file.as_str() && entry.file_name() != marker.as_str() {
                    fs::remove_file(entry.path()).unwrap();
                }
            }
            package = capture(&device, &package, &keys);
        }
        let original = package.encode_local().unwrap();
        assert!(package.materials(&keys, &BTreeMap::new()).is_err());
        assert!(package.structured_history(&keys, &BTreeMap::new()).is_err());
        assert_eq!(
            package.encode_local().unwrap().as_slice(),
            original.as_slice()
        );
        package.files.require_unchanged(&env, None).unwrap();
    }
}
