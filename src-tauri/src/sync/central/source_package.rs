//! Recoverable captured inputs, not full semantic inventory or a migration/publication permit.
use super::{
    credentials::Profile,
    crypto::VaultKeys,
    inventory_keys::Snapshot,
    migration_files::Files,
    migration_materials::Materials,
    migration_sources::{Inventory, Sources},
    payload::KeyStorage,
    source_archive::{self, Archived, Receipt},
    wire::invalid,
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{
        env::SyncEnv,
        records_v3::{self, SyncStateV3},
    },
};
use std::{collections::BTreeMap, path::Path};
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"LPSRCPK1";
const MAX_BYTES: usize = 192 * 1024 * 1024;
/// Only explicit native encode/decode. Never a frontend DTO or an SSH private-key export.
pub(super) struct Package {
    state_name: String,
    pub state: SyncStateV3,
    pub files: Files,
    pub sources: Sources,
    decryptors: Snapshot,
}
fn state(files: &Files, name: &str) -> Result<SyncStateV3, AppError> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || name.contains(['/', '\\', '\0'])
    {
        return Err(invalid());
    }
    let bytes = files
        .bytes
        .get(&Path::new("data").join(name))
        .ok_or_else(invalid)?;
    if bytes.len() as u64 > crate::sync::record_runtime::MAX_STATE_BYTES {
        return Err(invalid());
    }
    let state: SyncStateV3 = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    records_v3::validate_state(&state).map_err(|_| invalid())?;
    if let Some(backup) = &state.legacy_v1_backup {
        if backup.is_empty()
            || backup.len() > 255
            || matches!(backup.as_str(), "." | "..")
            || backup.contains(['/', '\\', '\0'])
            || !files.bytes.contains_key(&Path::new("data").join(backup))
        {
            return Err(invalid());
        }
    }
    Ok(state)
}
impl Package {
    /// The caller captures observed decryptors using Materials::from_files; no live key fallback here.
    pub fn assemble(
        expected: &SyncStateV3,
        state_name: &str,
        files: Files,
        sources: Sources,
        decryptors: Snapshot,
    ) -> Result<Self, AppError> {
        let archived = state(&files, state_name)?;
        if &archived != expected {
            return Err(crate::sync::runtime::superseded());
        }
        let book = sources.encode_local()?;
        let sources = Sources::decode_local(&book, &archived)?;
        // Validate the full path set now, before any archive key or file can be created.
        files.validate_archive()?;
        Ok(Self {
            state_name: state_name.into(),
            state: archived,
            files,
            sources,
            decryptors,
        })
    }
    /// Full current/recovery input enumeration using this package's archived legacy keybook.
    /// Payload semantics and other captured source images still require separate admission.
    pub fn record_inputs(&self) -> Result<Inventory, AppError> {
        if state(&self.files, &self.state_name)? != self.state { return Err(invalid()); }
        Inventory::from_state(&self.sources, &self.state)
    }
    /// Admission always uses the enclosed decryptors. No OS access, writes, activation or consent.
    pub fn materials(
        &self,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<Materials, AppError> {
        let private_inputs = self.record_inputs()?.admit_known()?.into_keys();
        Materials::from_files_with_key_inputs(
            &self.state, keys, &self.files, &self.decryptors, references, private_inputs,
        )
    }
    /// Structured-record history candidate only; other files/frozen sources and consent remain gates.
    pub fn structured_history(&self, keys: &VaultKeys, references: &BTreeMap<String, KeyStorage>) -> Result<super::migration_library::History, AppError> {
        let known = self.record_inputs()?.admit_known()?;
        let materials = self.materials(keys, references)?;
        super::migration_library::prepare(&self.state, &known, materials)
    }
    pub fn encode_local(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        if state(&self.files, &self.state_name)? != self.state {
            return Err(invalid());
        }
        let files = self.files.encode_local()?;
        let sources = self.sources.encode_local()?;
        drop(Sources::decode_local(&sources, &self.state)?);
        let decryptors = self.decryptors.encode_local()?;
        let sections = [
            self.state_name.as_bytes(),
            files.as_slice(),
            sources.as_slice(),
            decryptors.as_slice(),
        ];
        let length = sections
            .iter()
            .try_fold(8usize, |sum, value| {
                sum.checked_add(8)?.checked_add(value.len())
            })
            .ok_or_else(invalid)?;
        if length > MAX_BYTES {
            return Err(invalid());
        }
        let mut out = Zeroizing::new(Vec::with_capacity(length));
        out.extend_from_slice(MAGIC);
        for section in sections {
            out.extend_from_slice(&(section.len() as u64).to_be_bytes());
            out.extend_from_slice(section);
        }
        Ok(out)
    }
    pub fn decode_local(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > MAX_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(invalid());
        }
        let mut input = &bytes[8..];
        let name = std::str::from_utf8(section(&mut input, 255)?)
            .map_err(|_| invalid())?
            .to_owned();
        let files = Files::decode_local(section(
            &mut input,
            super::migration_files::MAX_ARCHIVE_BYTES,
        )?)?;
        let state = state(&files, &name)?;
        let sources = Sources::decode_local(section(&mut input, super::migration_sources::MAX_BOOK_BYTES)?, &state)?;
        let decryptors = Snapshot::decode_local(section(&mut input, 2 * 1024 * 1024)?)?;
        if !input.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            state_name: name,
            state,
            files,
            sources,
            decryptors,
        })
    }
    /// No complete-inventory authority: this only durably preserves the captured original inputs.
    pub fn archive(
        &self,
        env: &SyncEnv,
        life: &std::sync::MutexGuard<'_, ()>,
        owner: &Workspace,
        generation: u64,
    ) -> Result<Archived, AppError> {
        if self.state.local.central.as_ref() != Some(owner) {
            return Err(invalid());
        }
        let plain = self.encode_local()?;
        self.files
            .require_unchanged(env, self.state.legacy_v1_backup.as_deref())?;
        source_archive::create(env, life, owner, generation, &plain)
    }
    /// Momentary source comparison, not a permit that survives later edits or HTTP.
    pub fn revalidate_archive(&self, env: &SyncEnv, archived: &Archived) -> Result<(), AppError> {
        let owner = self.state.local.central.as_ref().ok_or_else(invalid)?;
        archived.receipt().context.matches_owner(owner)?;
        let outputs = archived.outputs(
            env,
            &owner.control.profile.profile()?,
            &self.encode_local()?,
        )?;
        self.files.require_unchanged_after_archive(
            env,
            self.state.legacy_v1_backup.as_deref(),
            &outputs,
        )
    }
    pub fn restore(env: &SyncEnv, profile: &Profile, receipt: &Receipt) -> Result<Self, AppError> {
        let plain = source_archive::restore(env, profile, receipt)?;
        let package = Self::decode_local(&plain)?;
        receipt
            .context
            .matches_owner(package.state.local.central.as_ref().ok_or_else(invalid)?)?;
        Ok(package)
    }
}
fn section<'a>(input: &mut &'a [u8], max: usize) -> Result<&'a [u8], AppError> {
    if input.len() < 8 {
        return Err(invalid());
    }
    let length = u64::from_be_bytes(input[..8].try_into().map_err(|_| invalid())?);
    *input = &input[8..];
    if length > max as u64 || length > input.len() as u64 {
        return Err(invalid());
    }
    let (value, rest) = input.split_at(length as usize);
    *input = rest;
    Ok(value)
}

#[cfg(all(test, unix))]
pub(in crate::sync::central) mod tests {
    use super::*;
    use crate::{
        sync::{
            central::inventory_keys::Capture,
            crypto::ChainKeys,
            env::Keychain,
            fake_relay::FakeRelay,
            state_v2::AccountState,
            testkit::{TestClock, TestDevice},
        },
        vault::{
            material,
            store::{self, Vault},
        },
    };
    use serde_json::json;
    use std::fs;
    pub(in crate::sync::central) fn fixture() -> (TestDevice, Package, VaultKeys, Workspace, String)
    {
        let device = TestDevice::new("source-package", &FakeRelay::new(), &TestClock::new());
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        fs::create_dir_all(root).unwrap();
        let (owner, keys, _) = super::super::migration_history::tests::initial();
        let parent = ChainKeys::generate().unwrap();
        let mut state: SyncStateV3 = serde_json::from_value(json!({"version":8,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":owner.control.profile.origin,"last_sync_ms":null,"last_error":null})).unwrap();
        state.account = Some(AccountState::new(&parent.chain_id));
        state.local.central = Some(owner.clone());
        fs::write(&env.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let raw = crate::sync::slot_rules::test_keys::encrypted();
        let parsed = material::parse(&raw).unwrap();
        let mut vault = Vault::open(&root.join("vault.json"), &device.keychain, 0).unwrap();
        vault
            .put(
                &device.keychain,
                "orphan",
                &store::VaultEntry {
                    private_key: raw.clone(),
                    public_key: parsed.public_key().to_openssh().unwrap(),
                    fingerprint: parsed
                        .public_key()
                        .fingerprint(ssh_key::HashAlg::Sha256)
                        .to_string(),
                    origin: store::EntryOrigin::Imported,
                    added_at_ms: 1,
                },
            )
            .unwrap();
        fs::create_dir_all(root.join("imports/unknown-empty")).unwrap();
        fs::write(
            root.join("sync-state.retained"),
            b"unique retained bytes\0\xff",
        )
        .unwrap();
        let files = Files::capture(&env, None).unwrap();
        let observer = Capture::new(&device.keychain);
        Materials::from_files(&state, &keys, &files, &observer, &BTreeMap::new()).unwrap();
        let decryptors = observer.finish().unwrap();
        let package = Package::assemble(
            &state,
            env.state_path.file_name().unwrap().to_str().unwrap(),
            files,
            Sources::discover(&state, Some(&parent)).unwrap(),
            decryptors,
        )
        .unwrap();
        drop(vault);
        drop(parent);
        (device, package, keys, owner, raw)
    }
    #[test]
    fn encrypted_package_restores_original_source_credentials_and_private_material_without_live_vault_masters(
    ) {
        let (device, package, keys, owner, raw) = fixture();
        let env = device.env();
        let plain = package.encode_local().unwrap();
        let original = Package::decode_local(&plain).unwrap();
        assert_eq!(
            original.encode_local().unwrap().as_slice(),
            plain.as_slice()
        );
        package.files.require_unchanged(&env, None).unwrap();
        let life = env.runtime.lifecycle.lock().unwrap();
        let archived = package.archive(&env, &life, &owner, 7).unwrap();
        package.revalidate_archive(&env, &archived).unwrap();
        device.keychain.delete("vault:key").unwrap();
        // The vault creates a path-specific role; erase every observed synthetic vault role as well.
        let book: serde_json::Value =
            serde_json::from_slice(&package.decryptors.encode_local().unwrap()).unwrap();
        for entry in book["keys"].as_array().unwrap() {
            device
                .keychain
                .delete(entry["role"].as_str().unwrap())
                .unwrap();
        }
        drop(package);
        drop(original);
        drop(plain);
        let restored = Package::restore(
            &env,
            &owner.control.profile.profile().unwrap(),
            archived.receipt(),
        )
        .unwrap();
        assert_eq!(restored.sources.chains().len(), 1);
        assert_eq!(
            restored.files.bytes[Path::new("data/sync-state.retained")].as_slice(),
            b"unique retained bytes\0\xff"
        );
        assert!(restored
            .files
            .directories
            .contains(Path::new("data/imports/unknown-empty")));
        let materials = restored.materials(&keys, &BTreeMap::new()).unwrap();
        assert_eq!(materials.retained, 1);
        assert!(materials.active.is_empty());
        assert!(materials.into_history().iter().any(|(_, value)| matches!(value, super::super::payload::Data::Key(private) if private.private()==raw)));
        let encoded = serde_json::to_string(archived.receipt()).unwrap();
        assert!(!encoded.contains(&raw));
        assert!(restored.files.require_unchanged(&env, None).is_err()); // Own output still needs the future typed driver exception.
    }
    #[test]
    fn incomplete_credential_components_and_malformed_package_framing_cannot_be_accepted_as_complete_material(
    ) {
        let (_, package, keys, _, _) = fixture();
        let bytes = package.encode_local().unwrap();
        for length in [0, 7, 8, 15, bytes.len() - 1] {
            assert!(Package::decode_local(&bytes[..length]).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(Package::decode_local(&extra).is_err());
        let mut oversized = bytes.to_vec();
        oversized[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Package::decode_local(&oversized).is_err());
        let mut version = bytes.to_vec();
        version[7] = b'2';
        assert!(Package::decode_local(&version).is_err());
        let mut restored = Package::decode_local(&bytes).unwrap();
        restored.decryptors = Snapshot::decode_local(br#"{"version":1,"keys":[]}"#).unwrap();
        assert!(restored.materials(&keys, &BTreeMap::new()).is_err());
        // Use its actual captured state filename, independent of the test environment's basename.
        restored
            .files
            .bytes
            .remove(&Path::new("data").join(&restored.state_name));
        assert!(restored.encode_local().is_err());
    }
    #[test]
    fn own_output_does_not_hide_any_source_write_removal_or_added_empty_directory() {
        for change in ["write", "remove", "new-file", "empty-dir"] {
            let (device, package, _, owner, _) = fixture();
            let env = device.env();
            let life = env.runtime.lifecycle.lock().unwrap();
            let archived = package.archive(&env, &life, &owner, 1).unwrap();
            package.revalidate_archive(&env, &archived).unwrap();
            let root = env.state_path.parent().unwrap();
            match change {
                "write" => fs::write(root.join("sync-state.retained"), b"unique source B").unwrap(),
                "remove" => fs::remove_file(root.join("sync-state.retained")).unwrap(),
                "new-file" => {
                    fs::write(root.join("central-source-archives/extra"), b"new source B").unwrap()
                }
                _ => fs::create_dir(root.join("central-source-archives/empty-B")).unwrap(),
            }
            assert!(
                package.revalidate_archive(&env, &archived).is_err(),
                "{change}"
            );
        }
    }
    #[test]
    fn altered_own_ciphertext_marker_and_missing_key_block_revalidation_without_repair() {
        for change in ["ciphertext", "marker", "key"] {
            let (device, package, _, owner, _) = fixture();
            let env = device.env();
            let life = env.runtime.lifecycle.lock().unwrap();
            let archived = package.archive(&env, &life, &owner, 1).unwrap();
            let root = env
                .state_path
                .parent()
                .unwrap()
                .join("central-source-archives");
            if change == "key" {
                let profile = owner.control.profile.profile().unwrap();
                device
                    .keychain
                    .delete(&profile.slot(&format!(
                        "source-archive-{}",
                        archived.receipt().operation()
                    )))
                    .unwrap();
            } else {
                let extension = if change == "ciphertext" {
                    "lpsource"
                } else {
                    "sha256"
                };
                let path = fs::read_dir(&root)
                    .unwrap()
                    .map(|v| v.unwrap().path())
                    .find(|v| v.extension().is_some_and(|v| v == extension))
                    .unwrap();
                fs::write(&path, b"ALTERED_SOURCE_SENTINEL").unwrap();
                assert!(package.revalidate_archive(&env, &archived).is_err());
                assert_eq!(fs::read(path).unwrap(), b"ALTERED_SOURCE_SENTINEL");
                continue;
            }
            assert!(package.revalidate_archive(&env, &archived).is_err());
        }
    }
    #[test]
    fn prior_archive_in_later_snapshot_stays_protected_and_cannot_be_excluded_as_own_output() {
        let (device, package, _, owner, _) = fixture();
        let env = device.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        let first = package.archive(&env, &life, &owner, 1).unwrap();
        let sources =
            Sources::decode_local(&package.sources.encode_local().unwrap(), &package.state)
                .unwrap();
        let decryptors =
            Snapshot::decode_local(&package.decryptors.encode_local().unwrap()).unwrap();
        let later = Package::assemble(
            &package.state,
            &package.state_name,
            Files::capture(&env, None).unwrap(),
            sources,
            decryptors,
        )
        .unwrap();
        let second = later.archive(&env, &life, &owner, 2).unwrap();
        later.revalidate_archive(&env, &second).unwrap();
        assert!(later.revalidate_archive(&env, &first).is_err());
        let prior = env
            .state_path
            .parent()
            .unwrap()
            .join("central-source-archives")
            .join(format!("{}-key.sha256", first.receipt().operation()));
        fs::remove_file(prior).unwrap();
        assert!(later.revalidate_archive(&env, &second).is_err());
    }
    #[test]
    fn changed_sources_block_archive_creation_before_creating_an_archive_directory() {
        let (device, package, _, owner, _) = fixture();
        let env = device.env();
        fs::write(
            env.state_path.parent().unwrap().join("sync-state.retained"),
            b"source B",
        )
        .unwrap();
        let life = env.runtime.lifecycle.lock().unwrap();
        assert!(package.archive(&env, &life, &owner, 0).is_err());
        assert!(!env
            .state_path
            .parent()
            .unwrap()
            .join("central-source-archives")
            .exists());
        assert_eq!(
            fs::read(env.state_path.parent().unwrap().join("sync-state.retained")).unwrap(),
            b"source B"
        );
    }
    #[test]
    fn assembly_rejects_current_state_drift_missing_named_backups_and_cross_owner_archive_creation()
    {
        let (device, package, _, owner, _) = fixture();
        let encoded = package.encode_local().unwrap();
        let mut altered = Package::decode_local(&encoded).unwrap();
        altered.state.device_name = "Changed after capture".into();
        assert!(altered.encode_local().is_err());
        assert!(Package::assemble(
            &altered.state,
            &package.state_name,
            Package::decode_local(&encoded).unwrap().files,
            package.sources,
            package.decryptors
        )
        .is_err());
        let env = device.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        let mut other = owner;
        other.control.profile.locator = "f".repeat(64);
        assert!(altered.archive(&env, &life, &other, 1).is_err());
        let mut backup = Package::decode_local(&encoded).unwrap();
        backup.state.legacy_v1_backup = Some("missing-backup".into());
        backup.files.bytes.insert(
            Path::new("data").join(&backup.state_name),
            Zeroizing::new(serde_json::to_vec(&backup.state).unwrap()),
        );
        assert!(backup.encode_local().is_err());
    }
}
