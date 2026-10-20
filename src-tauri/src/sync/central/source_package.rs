//! Recoverable captured inputs, not full semantic inventory or a migration/publication permit.
use super::{
    credentials::Profile,
    crypto::VaultKeys,
    inventory_keys::Snapshot,
    migration_files::Files,
    migration_materials::Materials,
    migration_sources::{FrozenSet, FrozenSnapshot, Inventory, Sources},
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
const SNAPSHOT_MAGIC: &[u8; 8] = b"LPSRCPK3";
const FROZEN_MAGIC: &[u8; 8] = b"LPSRCPK2";
const MAX_BYTES: usize = 192 * 1024 * 1024;
mod coverage;
mod legacy_book;
mod retained;
mod replacement_history;
pub(in crate::sync::central) mod snapshot;
/// Only explicit native encode/decode. Never a frontend DTO or an SSH private-key export.
pub(super) struct Package {
    state_name: String,
    pub state: SyncStateV3,
    pub files: Files,
    pub sources: Sources,
    decryptors: Snapshot,
    frozen: Option<FrozenSet>,
    snapshot: Option<snapshot::Snapshot>,
    // Ephemeral proofs inherited only from a fully checked enclosing graph. Never serialized.
    inherited: Vec<snapshot::Group>,
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
    pub(super) fn decryptors(&self) -> &Snapshot {
        &self.decryptors
    }
    pub(super) fn replacement_sources(
        state: &SyncStateV3,
        files: &Files,
        keys: &dyn crate::sync::env::Keychain,
    ) -> Result<Sources, AppError> {
        legacy_book::discover(state, files, keys)
    }
    fn restore_sources(
        state: &SyncStateV3,
        files: &Files,
        keys: &dyn crate::sync::env::Keychain,
        bytes: &[u8],
    ) -> Result<Sources, AppError> {
        if super::replacement_reconciliation::projected(state) {
            let sources = legacy_book::discover(state, files, keys)?;
            if sources.encode_local()?.as_slice() != bytes {
                return Err(invalid());
            }
            Ok(sources)
        } else {
            Sources::decode_local(bytes, state)
        }
    }

    /// Modern retained states; v1/v2 histories use their separate strict admission below.
    fn retained_states(&self) -> Result<Vec<SyncStateV3>, AppError> {
        let mut result = crate::sync::record_import::inventory::read_all(
            &self.state,
            &self.files.bytes,
            &self.decryptors,
        )?
        .states;
        result.extend(
            crate::sync::record_migration::inventory::read_all(&self.state, &self.files.bytes)?
                .states,
        );
        result.extend(
            super::replacement_archive::captured::read_all(&self.files.bytes, &self.decryptors)?
                .states,
        );
        for (path, bytes) in &self.files.bytes {
            if path.parent() != Some(Path::new("data")) {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(invalid)?;
            if name == self.state_name
                || !(name.starts_with("sync-state")
                    || self.state.legacy_v1_backup.as_deref() == Some(name))
            {
                continue;
            }
            if bytes.len() as u64 > crate::sync::record_runtime::MAX_STATE_BYTES {
                return Err(invalid());
            }
            #[derive(serde::Deserialize)]
            struct Version {
                version: u32,
            }
            let version: Version = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            if matches!(version.version, 1 | 2) {
                continue;
            }
            let image: SyncStateV3 = serde_json::from_slice(bytes).map_err(|_| AppError::Other("A retained sync-state image needs supported normalization before migration. Every original file is retained.".into()))?;
            records_v3::validate_state(&image).map_err(|_| invalid())?;
            result.push(image);
        }
        for image in &result {
            if let Some(old) = &image.local.central {
                old.validate()?;
                let selected = self.state.local.central.as_ref().ok_or_else(invalid)?;
                let old_anchor = match &old.recovery {
                    Some(super::recovery_state::RecoveryState::Pending { package }) => {
                        Some(&package.admission.anchor)
                    }
                    _ => old.control.anchor.as_ref(),
                };
                if old_anchor.is_some() && old_anchor != selected.control.anchor.as_ref()
                    || old.control.profile != selected.control.profile
                    || old.control.account_id != selected.control.account_id
                {
                    return Err(invalid());
                }
            }
        }
        if super::replacement_reconciliation::projected(&self.state) {
            result.push(self.state.clone());
        }
        // A historical image may name an older backup that the selected state no longer names.
        // It is complete only when that exact backup is captured and read as a state image too.
        for image in &result {
            if let Some(backup) = &image.legacy_v1_backup {
                if backup.is_empty()
                    || backup.len() > 255
                    || matches!(backup.as_str(), "." | "..")
                    || backup.contains(['/', '\\', '\0'])
                    || !(backup == &self.state_name
                        || backup.starts_with("sync-state")
                        || self.state.legacy_v1_backup.as_deref() == Some(backup.as_str()))
                    || !self
                        .files
                        .bytes
                        .contains_key(&Path::new("data").join(backup))
                {
                    return Err(invalid());
                }
            }
        }
        Ok(result)
    }
    fn needs_state_history(&self, state: &SyncStateV3) -> bool {
        super::historical_state::needed(state)
            || state.local.central.as_ref().is_some_and(|owner| {
                owner.control.anchor.is_some() && Some(owner) != self.state.local.central.as_ref()
            })
    }
    fn legacy_retained_states(&self) -> Result<Vec<SyncStateV3>, AppError> {
        Ok(self
            .retained_states()?
            .into_iter()
            .filter(|s| !super::historical_state::projected(s))
            .collect())
    }
    fn state_groups(&self) -> Result<Vec<snapshot::Group>, AppError> {
        let groups = self.snapshot_groups()?;
        let mut result = vec![];
        for state in self
            .retained_states()?
            .into_iter()
            .filter(|state| self.needs_state_history(state))
        {
            let key = snapshot::Group::state_key(&state)?;
            let group = groups
                .iter()
                .find(|g| g.key().ok().as_ref() == Some(&key))
                .ok_or_else(invalid)?;
            group.require_state(&state)?;
            result.push(group.clone());
        }
        Ok(result)
    }
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
        let sources = Self::restore_sources(&archived, &files, &decryptors, &book)?;
        // Validate the full path set now, before any archive key or file can be created.
        files.validate_archive()?;
        Ok(Self {
            state_name: state_name.into(),
            state: archived,
            files,
            sources,
            decryptors,
            frozen: None,
            snapshot: None,
            inherited: vec![],
        })
    }
    /// Full current/recovery input enumeration using this package's archived legacy keybook.
    /// Payload semantics and other captured source images still require separate admission.
    fn own_record_inputs(&self) -> Result<Inventory, AppError> {
        if state(&self.files, &self.state_name)? != self.state {
            return Err(invalid());
        }
        let mut inventory = match &self.frozen {
            Some(frozen) => frozen.inventory(&self.sources, &self.state)?,
            None if super::replacement_reconciliation::projected(&self.state) => {
                Inventory::for_replacement(&self.sources, &self.state)?
            }
            None => Inventory::from_state(&self.sources, &self.state)?,
        };
        for image in self
            .retained_states()?
            .into_iter()
            .filter(|s| !super::historical_state::projected(s))
        {
            inventory = inventory.with_retained_state(&self.sources, &image)?;
        }
        let migrations =
            crate::sync::record_migration::inventory::read_all(&self.state, &self.files.bytes)?;
        for bytes in migrations.legacy {
            inventory = inventory.with_retained_legacy(&self.sources, &bytes)?;
        }
        for (chain, rows) in migrations.chains {
            inventory = inventory.with_retained_envelopes(&self.sources, &chain, rows)?;
        }
        for (path, bytes) in &self.files.bytes {
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(invalid)?;
            if path.parent() != Some(Path::new("data"))
                || name == self.state_name
                || !(name.starts_with("sync-state")
                    || self.state.legacy_v1_backup.as_deref() == Some(name))
            {
                continue;
            }
            #[derive(serde::Deserialize)]
            struct Version {
                version: u32,
                #[serde(default)]
                legacy_v1_backup: Option<String>,
            }
            let version: Version = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            if matches!(version.version, 1 | 2) {
                if version.legacy_v1_backup.as_ref().is_some_and(|backup| {
                    backup.contains(['/', '\\', '\0'])
                        || !(backup.starts_with("sync-state")
                            || self.state.legacy_v1_backup.as_ref() == Some(backup))
                        || !self
                            .files
                            .bytes
                            .contains_key(&Path::new("data").join(backup))
                }) {
                    return Err(invalid());
                }
                inventory = inventory.with_retained_legacy(&self.sources, bytes)?;
            }
        }
        Ok(inventory)
    }
    /// Preserve complete remote inputs alongside this exact captured source, without choosing winners.
    pub fn with_frozen(
        mut self,
        operation: &str,
        progress: &super::migration_freeze::Progress,
        minimum: Option<&super::migration_freeze::Known>,
        snapshots: Vec<FrozenSnapshot>,
    ) -> Result<Self, AppError> {
        if self.frozen.is_some() {
            return Err(invalid());
        }
        drop(self.record_inputs()?);
        self.frozen = Some(FrozenSet::capture(
            &self.state,
            &self.sources,
            operation,
            progress,
            minimum,
            snapshots,
        )?);
        drop(self.record_inputs()?);
        Ok(self)
    }
    /// A passive complete continuation only; typed reconciliation and consent remain gates.
    pub fn finish_fetching(mut self, fetching: super::migration_sources::Fetching) -> Result<Self, AppError> {
        if self.frozen.is_some() { return Err(invalid()); }
        self.frozen = Some(fetching.complete(&self.sources, &self.state)?);
        drop(self.record_inputs()?);
        Ok(self)
    }
    /// Historical graph readers own the shared depth/byte budget. Do not recurse into capsule
    /// graphs here; the caller must visit every enclosed source before semantic admission.
    pub(in crate::sync::central) fn finish_captured_fetching(
        mut self,
        fetching: super::migration_sources::Fetching,
    ) -> Result<Self, AppError> {
        if self.frozen.is_some() {
            return Err(invalid());
        }
        self.frozen = Some(fetching.complete(&self.sources, &self.state)?);
        drop(self.own_record_inputs()?);
        Ok(self)
    }
    /// Admission always uses the enclosed decryptors. No OS access, writes, activation or consent.
    fn own_materials(
        &self,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<Materials, AppError> {
        self.require_own_supported_files()?;
        let mut normalized = super::replacement_reconciliation::physical_view(&self.state)?;
        let private_inputs = self
            .own_record_inputs()?
            .admit_known()?
            .normalize_legacy(&mut normalized, Some(&self.files))?
            .into_keys();
        Materials::from_files_with_key_inputs(
            &normalized,
            keys,
            &self.files,
            &self.decryptors,
            references,
            private_inputs,
        )
        .and_then(|materials| {
            let mut materials = materials.with_retained_states(
                &self.legacy_retained_states()?,
                &self.files,
                &self.decryptors,
            )?;
            for group in self.state_groups()? {
                materials = materials.with_retained_history(group.history()?)?;
            }
            Ok(materials)
        })
    }
    /// Structured history candidate; other captured files and explicit consent remain gates.
    fn own_structured_history(
        &self,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<super::migration_library::History, AppError> {
        self.require_own_supported_files()?;
        if super::replacement_reconciliation::projected(&self.state) {
            return self.replacement_structured_history(keys, references);
        }
        if self.frozen.is_some() {
            drop(self.own_record_inputs()?); // Compare the captured state image before deriving a passive candidate.
            let prepared = self
                .own_record_inputs()?
                .reconcile_captured(&self.state)?
                .prepare_with_files(Some(&self.files))?;
            let materials = Materials::from_files_with_key_inputs(
                &prepared.state,
                keys,
                &self.files,
                &self.decryptors,
                references,
                prepared.known.key_inputs()?,
            )?
            .with_retained_states(
                &self.legacy_retained_states()?,
                &self.files,
                &self.decryptors,
            )?;
            return super::migration_library::prepare(&prepared.state, &prepared.known, materials)?
                .with_retained(
                    self.state_groups()?
                        .into_iter()
                        .map(|g| g.history())
                        .collect::<Result<_, _>>()?,
                );
        }
        let mut normalized = super::replacement_reconciliation::physical_view(&self.state)?;
        let known = self
            .own_record_inputs()?
            .admit_known()?
            .normalize_legacy(&mut normalized, Some(&self.files))?;
        let materials = Materials::from_files_with_key_inputs(
            &normalized,
            keys,
            &self.files,
            &self.decryptors,
            references,
            known.key_inputs()?,
        )?
        .with_retained_states(
            &self.legacy_retained_states()?,
            &self.files,
            &self.decryptors,
        )?;
        super::migration_library::prepare(&normalized, &known, materials)?.with_retained(
            self.state_groups()?
                .into_iter()
                .map(|g| g.history())
                .collect::<Result<_, _>>()?,
        )
    }
    // Keep replacement-only scratch state out of every ordinary source reader's stack frame.
    #[inline(never)]
    fn replacement_structured_history(
        &self,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<super::migration_library::History, AppError> {
        let inventory = self.own_record_inputs()?;
        let groups = self.state_groups()?;
        let current = groups
            .iter()
            .find(|g| g.require_state(&self.state).is_ok())
            .ok_or_else(invalid)?;
        let mut view = super::replacement_reconciliation::physical_view(&self.state)?;
        let known = inventory
            .admit_known()?
            .normalize_legacy(&mut view, Some(&self.files))?;
        let materials = Materials::from_files_with_key_inputs(
            &view,
            keys,
            &self.files,
            &self.decryptors,
            references,
            known.key_inputs()?,
        )?;
        // This passive empty account gives retained legacy catalog versions a scope. It
        // carries no credentials or control authority and is never selected or published.
        let vault = self
            .state
            .local
            .central
            .as_ref()
            .and_then(|owner| owner.control.personal_vault.as_deref())
            .ok_or_else(invalid)?;
        view.account = Some(crate::sync::state_v2::AccountState::new(vault));
        let physical = super::migration_library::prepare(&view, &known, materials)?;
        let mut retained = vec![physical];
        for group in &groups {
            if group.require_state(&self.state).is_err() {
                retained.push(group.history()?);
            }
        }
        current.history()?.with_retained(retained)
    }
    pub(in crate::sync::central) fn captured_initial_digest(&self) -> Result<&str, AppError> {
        self.frozen.as_ref().ok_or_else(invalid)?.initial_digest()
    }
    pub(in crate::sync::central) fn require_captured_base(
        &self,
        original: &Self,
        receipt: &Receipt,
    ) -> Result<(), AppError> {
        receipt.matches_selected(original.state.local.central.as_ref().ok_or_else(invalid)?)?;
        if original.frozen.is_some()
            || self.state_name != original.state_name
            || self.state != original.state
            || self.files.encode_local()?.as_slice() != original.files.encode_local()?.as_slice()
            || self.decryptors.encode_local()?.as_slice()
                != original.decryptors.encode_local()?.as_slice()
            || self.snapshot.as_ref().map(|snapshot| snapshot.bytes())
                != original.snapshot.as_ref().map(|snapshot| snapshot.bytes())
            || !self
                .sources
                .follows_book(&super::crypto::hash(&original.sources.encode_local()?))?
            || self.captured_initial_digest()? != receipt.ciphertext_hash
        {
            return Err(invalid());
        }
        drop(
            self.frozen
                .as_ref()
                .ok_or_else(invalid)?
                .context(receipt.operation(), &receipt.ciphertext_hash)?,
        );
        Ok(())
    }
    /// The caller must have decoded this package from this exact authenticated receipt.
    /// This binds frozen inputs only; other files, consent and actual source freshness are separate.
    pub fn migration_context(&self, receipt: &Receipt) -> Result<super::migration_history::Context, AppError> {
        let owner = self.state.local.central.as_ref().ok_or_else(invalid)?;
        receipt.matches_selected(owner)?;
        drop(self.record_inputs()?);
        self.frozen.as_ref().ok_or_else(invalid)?.context(receipt.operation(), &receipt.ciphertext_hash)
    }
    pub fn encode_local(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        if state(&self.files, &self.state_name)? != self.state {
            return Err(invalid());
        }
        let files = self.files.encode_local()?;
        let sources = self.sources.encode_local()?;
        drop(Self::restore_sources(
            &self.state,
            &self.files,
            &self.decryptors,
            &sources,
        )?);
        let decryptors = self.decryptors.encode_local()?;
        let frozen = self
            .frozen
            .as_ref()
            .map(|value| value.encode_local())
            .transpose()?;
        if self.frozen.is_some() {
            drop(self.record_inputs()?);
        }
        let mut sections = vec![
            self.state_name.as_bytes(),
            files.as_slice(),
            sources.as_slice(),
            decryptors.as_slice(),
        ];
        if let Some(snapshot) = &self.snapshot {
            drop(snapshot.verify(self)?);
            sections.push(frozen.as_deref().map(|v| v.as_slice()).unwrap_or(&[]));
            sections.push(snapshot.bytes());
        } else if let Some(bytes) = &frozen {
            sections.push(bytes.as_slice());
        }
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
        out.extend_from_slice(if self.snapshot.is_some() {
            SNAPSHOT_MAGIC
        } else if frozen.is_some() {
            FROZEN_MAGIC
        } else {
            MAGIC
        });
        for section in sections {
            out.extend_from_slice(&(section.len() as u64).to_be_bytes());
            out.extend_from_slice(section);
        }
        Ok(out)
    }
    pub fn frame(bytes: &[u8]) -> bool {
        [MAGIC, FROZEN_MAGIC, SNAPSHOT_MAGIC]
            .iter()
            .any(|magic| bytes.starts_with(*magic))
    }
    pub fn complete_frame(bytes: &[u8]) -> bool {
        if bytes.starts_with(FROZEN_MAGIC) {
            return true;
        }
        bytes.starts_with(SNAPSHOT_MAGIC)
            && Self::decode_local(bytes).is_ok_and(|p| p.frozen.is_some())
    }
    pub fn decode_local(bytes: &[u8]) -> Result<Self, AppError> {
        let magic = bytes.get(..8);
        if bytes.len() > MAX_BYTES
            || ![
                Some(MAGIC.as_slice()),
                Some(FROZEN_MAGIC.as_slice()),
                Some(SNAPSHOT_MAGIC.as_slice()),
            ]
            .contains(&magic)
        {
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
        let book = section(&mut input, super::migration_sources::MAX_BOOK_BYTES)?;
        let decryptors = Snapshot::decode_local(section(&mut input, 2 * 1024 * 1024)?)?;
        let sources = Self::restore_sources(&state, &files, &decryptors, book)?;
        let frozen_bytes = if magic == Some(SNAPSHOT_MAGIC.as_slice()) {
            Some(section(
                &mut input,
                super::migration_sources::MAX_FROZEN_BYTES,
            )?)
        } else {
            None
        };
        let frozen = if frozen_bytes.is_some_and(|bytes| !bytes.is_empty()) {
            Some(FrozenSet::decode_local(
                frozen_bytes.ok_or_else(invalid)?,
                &sources,
                &state,
            )?)
        } else if magic == Some(FROZEN_MAGIC.as_slice()) {
            Some(FrozenSet::decode_local(
                section(&mut input, super::migration_sources::MAX_FROZEN_BYTES)?,
                &sources,
                &state,
            )?)
        } else {
            None
        };
        let snapshot = if magic == Some(SNAPSHOT_MAGIC.as_slice()) {
            Some(snapshot::Snapshot::decode(section(&mut input, MAX_BYTES)?)?)
        } else {
            None
        };
        if !input.is_empty() {
            return Err(invalid());
        }
        let result = Self {
            state_name: name,
            state,
            files,
            sources,
            decryptors,
            frozen,
            snapshot,
            inherited: vec![],
        };
        drop(result.snapshot_groups()?);
        Ok(result)
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
    /// Foreground migration start/re-entry. The caller separately fences current session/Core state.
    pub fn initialize_source(
        &self,
        env: &SyncEnv,
        life: &std::sync::MutexGuard<'_, ()>,
        owner: &Workspace,
        ordinal: u64,
    ) -> Result<super::source_cursor::Restored, AppError> {
        if self.state.local.central.as_ref() != Some(owner) {
            return Err(invalid());
        }
        let plain = self.encode_local()?;
        let restored =
            source_archive::initialize_source(env, life, owner, ordinal, &plain, |outputs| {
                self.files.require_unchanged_after_archive(
                    env,
                    self.state.legacy_v1_backup.as_deref(),
                    outputs,
                )
            })?;
        self.files.require_unchanged_after_archive(
            env,
            self.state.legacy_v1_backup.as_deref(),
            &restored.outputs,
        )?;
        Ok(restored)
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
                &"3".repeat(32),
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
        fs::create_dir_all(root.join("imports")).unwrap();
        let mut retained = state.clone();
        retained.version = records_v3::LOCAL_CONFLICT_STATE_VERSION;
        retained.local.central = None;
        fs::write(
            root.join("sync-state.retained"),
            serde_json::to_vec(&retained).unwrap(),
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
        let retained: SyncStateV3 = serde_json::from_slice(&restored.files.bytes[Path::new("data/sync-state.retained")]).unwrap();
        assert!(retained.local.central.is_none());
        assert_eq!(retained.account.as_ref().unwrap().chain_id, restored.state.account.as_ref().unwrap().chain_id);
        assert!(restored
            .files
            .directories
            .contains(Path::new("data/imports")));
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

#[cfg(all(test, unix))]
mod retained_tests;
