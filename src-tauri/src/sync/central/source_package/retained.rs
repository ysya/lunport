//! Enclosed packages contribute inactive history, never activation or consent.
use super::super::{credentials::DeviceIdentity, migration_library::History, rekey::Checkpoint};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
mod plan;
struct Retained {
    package: Box<Package>,
    plan: Option<plan::Evidence>,
    history: Option<History>,
    whole_history: bool,
    floors: Vec<Checkpoint>,
    controls: Vec<super::super::adoption::captured::ControlMinimum>,
}
const MAX_DEPTH: usize = 8;
const MAX_PACKAGES: usize = 256;
type IdentityReader<'a> = dyn Fn(&Workspace) -> Result<DeviceIdentity, AppError> + 'a;
// Keep large decoded states and parser return slots out of every recursive visitor frame.
#[inline(never)]
fn owned_package(bytes: &[u8]) -> Result<Box<Package>, AppError> {
    Ok(Box::new(Package::decode_local(bytes)?))
}
#[inline(never)]
fn plan_source(bytes: &[u8]) -> Result<String, AppError> {
    Ok(super::super::migration_history::Plan::captured_binding(bytes)?.2)
}
#[inline(never)]
fn captured_group(
    source: &Receipt,
    frames: &[(Receipt, Zeroizing<Vec<u8>>)],
    nested: &Package,
    identities: Option<&IdentityReader<'_>>,
) -> Result<snapshot::Group, AppError> {
    let owner = nested.state.local.central.as_ref().ok_or_else(invalid)?;
    let identity = identities.ok_or_else(invalid)?(owner)?;
    let (_, plain) = frames
        .iter()
        .find(|(r, _)| r == source)
        .ok_or_else(invalid)?;
    let mut prepared = owned_package(plain)?;
    prepared.inherited = nested.inherited.clone();
    let verified = super::super::adoption::captured::read_prepared_group(
        source, frames, &identity, *prepared,
    )?;
    snapshot::Group::captured(source, verified)
}
#[inline(never)]
fn captured_package(
    receipt: &Receipt,
    plain: &[u8],
    frames: &[(Receipt, Zeroizing<Vec<u8>>)],
) -> Result<(Box<Package>, Option<plan::Evidence>, Vec<Receipt>), AppError> {
    let read = |expected: &Receipt| -> Result<Zeroizing<Vec<u8>>, AppError> {
        let (_, plain) = frames
            .iter()
            .find(|(r, _)| r == expected)
            .ok_or_else(invalid)?;
        Ok(Zeroizing::new(plain.to_vec()))
    };
    let locate = |hash: &str| {
        frames
            .iter()
            .find(|(r, _)| r.ciphertext_hash == hash)
            .map(|(r, _)| r.clone())
            .ok_or_else(invalid)
    };
    if super::super::capture_journal::Journal::frame(plain) {
        let (package, ancestors) =
            super::super::capture_journal::Journal::captured_complete(plain, receipt, &read)?;
        Ok((Box::new(package), None, ancestors))
    } else if Package::frame(plain) {
        Ok((owned_package(plain)?, None, vec![]))
    } else {
        let (package, evidence, ancestors) =
            if super::super::migration_journal::Journal::captured_frame(plain) {
                plan::read_journal(receipt, plain, &read, locate)?
            } else {
                plan::read(receipt, plain, &read, locate)?
            };
        Ok((Box::new(package), Some(evidence), ancestors))
    }
}
fn inherit_groups(
    groups: &mut BTreeMap<String, snapshot::Group>,
    package: &Package,
) -> Result<(), AppError> {
    for group in package.snapshot_groups()? {
        let hash = group.key()?;
        if let Some(old) = groups.get(&hash) {
            if old != &group {
                return Err(invalid());
            }
        } else {
            if groups.len() >= MAX_PACKAGES {
                return Err(invalid());
            }
            groups.insert(hash, group);
        }
    }
    Ok(())
}
impl Package {
    fn retained_packages_inner(
        &self,
        identities: Option<&IdentityReader<'_>>,
    ) -> Result<(Vec<Retained>, Vec<snapshot::Group>), AppError> {
        fn visit(
            parent: &Package,
            selected: &Package,
            depth: usize,
            bytes: &mut usize,
            result: &mut Vec<Retained>,
            groups: &mut BTreeMap<String, snapshot::Group>,
            identities: Option<&IdentityReader<'_>>,
        ) -> Result<BTreeSet<String>, AppError> {
            let mut used = BTreeSet::new();
            parent.require_own_supported_files()?;
            inherit_groups(groups, parent)?;
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
            // A later signed capsule can attest the same older operation still present beside it.
            // Read only immediate signed frames here; full graph coverage/budgets are still required.
            for (receipt, plain) in &captured.frames {
                if plain.starts_with(SNAPSHOT_MAGIC) {
                    let package = owned_package(plain)?;
                    require_owner(selected, &package, receipt)?;
                    inherit_groups(groups, &package)?;
                }
            }
            for group in super::super::replacement_archive::captured::read_all(
                &parent.files.bytes,
                &parent.decryptors,
            )?
            .histories
            {
                let key = group.key()?;
                if let Some(existing) = groups.get(&key) {
                    if existing != &group {
                        return Err(invalid());
                    }
                } else {
                    if groups.len() >= MAX_PACKAGES {
                        return Err(invalid());
                    }
                    groups.insert(key, group);
                }
            }
            for state in parent
                .retained_states()?
                .into_iter()
                .filter(|state| parent.needs_state_history(state))
            {
                let key = snapshot::Group::state_key(&state)?;
                let group = match groups.get(&key) {
                    Some(group) => {
                        group.require_state(&state)?;
                        group.clone()
                    }
                    None => {
                        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
                        identities.ok_or_else(invalid)?; // New witnesses are created only by explicit native capture.
                        let captured = if super::super::historical_state::needed(&state) {
                            let identity = identities.ok_or_else(invalid)?(owner)?;
                            super::super::historical_state::read(&state, &identity)?
                        } else {
                            super::super::historical_state::read_public_control(&state)?
                        };
                        snapshot::Group::state_captured(&state, captured)?
                    }
                };
                if groups.len() >= MAX_PACKAGES && !groups.contains_key(&key) {
                    return Err(invalid());
                }
                used.insert(key.clone());
                groups.insert(key, group);
            }
            let mut covered = BTreeSet::new();
            let mut adoption_sources = BTreeMap::new();
            for (_, plain) in &captured.frames {
                if let Some(source) = super::super::adoption::captured::source(plain)? {
                    if adoption_sources
                        .insert(source.ciphertext_hash.clone(), source.clone())
                        .is_some_and(|old| old != source)
                    {
                        return Err(invalid());
                    }
                }
            }
            for (_, source) in adoption_sources {
                let hash = snapshot::captured_group_key(&source, &captured.frames)?;
                let (_, plain) = captured
                    .frames
                    .iter()
                    .find(|(r, _)| r == &source)
                    .ok_or_else(invalid)?;
                let mut nested = owned_package(plain)?;
                require_owner(selected, &nested, &source)?;
                // Visit children under the same enclosing graph budget before using their history.
                let needed = visit(
                    &nested,
                    selected,
                    depth + 1,
                    bytes,
                    result,
                    groups,
                    identities,
                )?;
                nested.inherited = needed
                    .iter()
                    .map(|key| groups.get(key).cloned().ok_or_else(invalid))
                    .collect::<Result<_, _>>()?;
                used.extend(needed);
                let group = match groups.get(&hash) {
                    Some(group) if group.source() == Some(&source) => group.clone(),
                    Some(_) => return Err(invalid()),
                    None => captured_group(&source, &captured.frames, &nested, identities)?,
                };
                group.require_frames(&captured.frames)?;
                if result.len() >= MAX_PACKAGES {
                    return Err(invalid());
                }
                result.push(Retained {
                    package: nested,
                    plan: None,
                    history: Some(group.history()?),
                    whole_history: false,
                    floors: group.floors().to_vec(),
                    controls: group.controls().to_vec(),
                });
                covered.extend(group.admitted().iter().cloned());
                used.insert(hash.clone());
                groups.insert(hash, group);
            }
            let mut referenced = BTreeSet::new();
            for (receipt, plain) in &captured.frames {
                if covered.contains(&receipt.ciphertext_hash) {
                    continue;
                }
                if super::super::capture_journal::Journal::frame(plain) {
                    for receipt in
                        super::super::capture_journal::Journal::captured_references(plain)?
                    {
                        referenced.insert(receipt.ciphertext_hash);
                    }
                } else if super::super::migration_journal::Journal::captured_frame(plain) {
                    for receipt in
                        super::super::migration_journal::Journal::captured_references(plain)?
                    {
                        referenced.insert(receipt.ciphertext_hash);
                    }
                } else if !Package::frame(plain) {
                    referenced.insert(plan_source(plain)?);
                }
            }
            for (receipt, plain) in &captured.frames {
                if covered.contains(&receipt.ciphertext_hash) {
                    continue;
                }
                if referenced.contains(&receipt.ciphertext_hash) {
                    continue;
                }
                if result.len() >= MAX_PACKAGES {
                    return Err(invalid());
                }
                let (mut nested, mut evidence, ancestors) =
                    captured_package(receipt, plain, &captured.frames)?;
                let admitted: BTreeSet<_> = ancestors
                    .iter()
                    .map(|r| r.ciphertext_hash.clone())
                    .chain(std::iter::once(receipt.ciphertext_hash.clone()))
                    .collect();
                covered.extend(ancestors.into_iter().map(|r| r.ciphertext_hash));
                covered.insert(receipt.ciphertext_hash.clone());
                require_owner(selected, &nested, receipt)?;
                let needed = visit(
                    &nested,
                    selected,
                    depth + 1,
                    bytes,
                    result,
                    groups,
                    identities,
                )?;
                nested.inherited = needed
                    .iter()
                    .map(|key| groups.get(key).cloned().ok_or_else(invalid))
                    .collect::<Result<_, _>>()?;
                used.extend(needed);
                if result.len() >= MAX_PACKAGES {
                    return Err(invalid());
                }
                let mut history = None;
                if let Some(plan) = &evidence {
                    let key = snapshot::Group::plan_key(plan.source(), &admitted)?;
                    let group = match groups.get(&key) {
                        Some(group) => {
                            group.require_plan(plan.source(), &admitted)?;
                            Some(group.clone())
                        }
                        None => match identities {
                            Some(identities) => {
                                let owner =
                                    nested.state.local.central.as_ref().ok_or_else(invalid)?;
                                let identity = identities(owner)?;
                                Some(snapshot::Group::planned(
                                    plan.source(),
                                    admitted,
                                    plan.capture(&nested, &identity)?,
                                    owner,
                                )?)
                            }
                            None => None,
                        },
                    };
                    if let Some(group) = group {
                        history = Some(group.history()?);
                        evidence = None;
                        if groups.len() >= MAX_PACKAGES && !groups.contains_key(&key) {
                            return Err(invalid());
                        }
                        used.insert(key.clone());
                        groups.insert(key, group);
                    }
                }
                let whole_history = history.is_some();
                result.push(Retained {
                    package: nested,
                    plan: evidence,
                    history,
                    whole_history,
                    floors: vec![],
                    controls: vec![],
                });
            }
            if captured
                .frames
                .iter()
                .any(|(r, _)| !covered.contains(&r.ciphertext_hash))
            {
                return Err(invalid());
            }
            Ok(used)
        }
        fn require_owner(
            selected: &Package,
            nested: &Package,
            receipt: &Receipt,
        ) -> Result<(), AppError> {
            let owner = nested.state.local.central.as_ref().ok_or_else(invalid)?;
            receipt.matches_selected(owner)?;
            let current = selected.state.local.central.as_ref().ok_or_else(invalid)?;
            if current.control.anchor != owner.control.anchor
                || current.control.profile != owner.control.profile
                || current.control.personal_vault != owner.control.personal_vault
            {
                return Err(invalid());
            }
            selected.sources.require_retained_subset(&nested.sources)
        }
        let mut result = vec![];
        let mut groups = BTreeMap::new();
        let used = visit(self, self, 0, &mut 0, &mut result, &mut groups, identities)?;
        if groups.keys().any(|key| !used.contains(key)) {
            return Err(invalid());
        }
        Ok((result, groups.into_values().collect()))
    }
    fn retained_packages(&self) -> Result<Vec<Retained>, AppError> {
        Ok(self.retained_packages_inner(None)?.0)
    }
    /// Use only currently available scoped identities once. No key is persisted by this operation.
    pub(in crate::sync::central) fn capture_historical_snapshots(
        &mut self,
        signer: &DeviceIdentity,
        identities: &IdentityReader<'_>,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<(), AppError> {
        let (_, groups) = self.retained_packages_inner(Some(identities))?;
        if groups.is_empty() {
            return Ok(());
        }
        let existing = self.snapshot_groups()?;
        if self.snapshot.is_some()
            && existing.len() == groups.len()
            && existing
                .iter()
                .all(|old| groups.iter().any(|group| group == old))
        {
            // Re-entry preserves the exact signed bytes already pinned by the source reservation.
            drop(self.materials(keys, references)?);
            drop(self.structured_history(keys, references)?);
            return Ok(());
        }
        let previous = self.snapshot.take();
        let candidate = snapshot::Snapshot::create(self, signer, groups);
        match candidate {
            Err(error) => {
                self.snapshot = previous;
                Err(error)
            }
            Ok(snapshot) => {
                self.snapshot = Some(snapshot);
                let checked = (|| {
                    drop(self.materials(keys, references)?);
                    drop(self.structured_history(keys, references)?);
                    Ok(())
                })();
                if checked.is_err() {
                    self.snapshot = previous;
                }
                checked
            }
        }
    }
    fn historical_requirements(
        &self,
    ) -> Result<
        (
            Vec<Checkpoint>,
            Vec<super::super::adoption::captured::ControlMinimum>,
        ),
        AppError,
    > {
        let mut floors = crate::sync::record_import::inventory::read_all(
            &self.state,
            &self.files.bytes,
            &self.decryptors,
        )?
        .central_floors;
        let mut controls = vec![];
        for group in self.snapshot_groups()? {
            floors.extend(group.floors().iter().cloned());
            controls.extend(group.controls().iter().cloned());
        }
        for state in self.retained_states()? {
            if let Some(owner) = state.local.central.as_ref() {
                if owner.control.anchor.is_some() {
                    controls.push(super::super::adoption::captured::ControlMinimum {
                        highwater: owner.control.verified_chain()?.highwater(),
                        auth_epoch: owner.control.auth_epoch,
                    });
                }
            }
        }
        for retained in self.retained_packages()? {
            floors.extend(retained.floors);
            controls.extend(retained.controls);
            floors.extend(
                crate::sync::record_import::inventory::read_all(
                    &retained.package.state,
                    &retained.package.files.bytes,
                    &retained.package.decryptors,
                )?
                .central_floors,
            );
            let owner = retained
                .package
                .state
                .local
                .central
                .as_ref()
                .ok_or_else(invalid)?;
            controls.push(super::super::adoption::captured::ControlMinimum {
                highwater: owner.control.verified_chain()?.highwater(),
                auth_epoch: owner.control.auth_epoch,
            });
        }
        floors.sort_by(|a, b| {
            (a.epoch, a.sequence, &a.history_hash).cmp(&(b.epoch, b.sequence, &b.history_hash))
        });
        floors.dedup();
        controls.sort_by(|a, b| {
            (a.highwater.revision, &a.highwater.head, a.auth_epoch).cmp(&(
                b.highwater.revision,
                &b.highwater.head,
                b.auth_epoch,
            ))
        });
        controls.dedup();
        Ok((floors, controls))
    }
    pub(in crate::sync::central) fn has_historical_requirements(&self) -> Result<bool, AppError> {
        let (floors, controls) = self.historical_requirements()?;
        Ok(!floors.is_empty() || !controls.is_empty())
    }
    pub(in crate::sync::central) fn require_historical_owner(&self) -> Result<(), AppError> {
        let owner = self.state.local.central.as_ref().ok_or_else(invalid)?;
        let chain = owner.control.verified_chain()?;
        for minimum in self.historical_requirements()?.1 {
            if owner.control.auth_epoch < minimum.auth_epoch
                || chain.head_at(minimum.highwater.revision as usize)
                    != Some(minimum.highwater.head.as_str())
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(in crate::sync::central) fn historical_floors(&self) -> Result<Vec<Checkpoint>, AppError> {
        Ok(self.historical_requirements()?.0)
    }
    /// Pick only the bridge collection span; every independent hash is checked after the read.
    pub(in crate::sync::central) fn historical_capture_floors(
        &self,
        mut extra: Vec<Checkpoint>,
    ) -> Result<Vec<Checkpoint>, AppError> {
        extra.extend(self.historical_floors()?);
        extra.sort_by(|a, b| {
            (a.epoch, a.sequence, &a.history_hash).cmp(&(b.epoch, b.sequence, &b.history_hash))
        });
        extra.dedup();
        if extra.len() <= 2 {
            return Ok(extra);
        }
        Ok(vec![
            extra.first().ok_or_else(invalid)?.clone(),
            extra.last().ok_or_else(invalid)?.clone(),
        ])
    }
    pub(in crate::sync::central) fn require_historical_read(
        &self,
        read: &super::super::active_read::VerifiedLibrary,
        transcript: &super::super::active_flow::Transcript,
    ) -> Result<(), AppError> {
        let owner = self.state.local.central.as_ref().ok_or_else(invalid)?;
        if read.previous_owner() != owner {
            return Err(invalid());
        }
        let (floors, controls) = self.historical_requirements()?;
        Self::require_historical_prefixes(read, transcript, &floors, &controls)
    }
    pub(in crate::sync::central) fn require_historical_prefixes(
        read: &super::super::active_read::VerifiedLibrary,
        transcript: &super::super::active_flow::Transcript,
        floors: &[Checkpoint],
        controls: &[super::super::adoption::captured::ControlMinimum],
    ) -> Result<(), AppError> {
        if floors.len() > 4096 || controls.len() > 8192 {
            return Err(invalid());
        }
        let vault = read
            .previous_owner()
            .control
            .personal_vault
            .as_ref()
            .ok_or_else(invalid)?;
        for minimum in controls {
            if read.auth_epoch() < minimum.auth_epoch
                || read.chain().head_at(minimum.highwater.revision as usize)
                    != Some(minimum.highwater.head.as_str())
            {
                return Err(invalid());
            }
        }
        for floor in floors {
            let bridges: Vec<_> = transcript
                .bridges
                .iter()
                .filter(|b| b.epoch > floor.epoch)
                .cloned()
                .collect();
            let translated = super::super::replacement_proof::extend_minimums(
                read.chain(),
                vault,
                read.epochs(),
                std::slice::from_ref(floor),
                &bridges,
                read.checkpoint().epoch,
            )?;
            if translated
                .iter()
                .any(|prefix| !read.verifies_prefix(prefix))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(super) fn require_supported_files(&self) -> Result<(), AppError> {
        drop(self.retained_packages()?);
        Ok(())
    }
    pub fn record_inputs(&self) -> Result<Inventory, AppError> {
        drop(self.state_groups()?);
        let mut inventory = self.own_record_inputs()?;
        for retained in self.retained_packages()? {
            let package = retained.package;
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
        for retained in self.retained_packages()? {
            let package = retained.package;
            if let Some(plan) = retained.plan {
                plan.validate(&package, keys, references)?;
            }
            if !retained.whole_history {
                materials =
                    materials.with_retained_materials(package.own_materials(keys, references)?)?;
            }
            if let Some(history) = retained.history {
                materials = materials.with_retained_history(history)?;
            }
        }
        drop(self.record_inputs()?);
        Ok(materials)
    }
    pub fn structured_history(
        &self,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<History, AppError> {
        drop(self.record_inputs()?);
        let mut retained = vec![];
        for source in self.retained_packages()? {
            let package = source.package;
            if let Some(plan) = source.plan {
                plan.validate(&package, keys, references)?;
            }
            if !source.whole_history {
                retained.push(package.own_structured_history(keys, references)?);
            }
            if let Some(history) = source.history {
                retained.push(history);
            }
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
            if ordinal+1==MAX_DEPTH {
                // The exact supported depth succeeds on the default test-thread stack.
                package.materials(&keys,&BTreeMap::new()).unwrap();
                package.structured_history(&keys,&BTreeMap::new()).unwrap();
            }
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
