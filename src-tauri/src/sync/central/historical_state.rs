//! Passive admission of retained central replicas. Never reconstructs a live owner or consent.
use super::{
    adoption::captured::ControlMinimum,
    credentials::DeviceIdentity,
    crypto::{self, RecordEnvelope, VaultKeys, WrappedKeys},
    migration_library::History,
    payload::{self, Data},
    rekey::Checkpoint,
    replica::{Base, Replica},
    trust::VerifiedChain,
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::records_v3::{self, SyncStateV3},
};
use std::collections::BTreeMap;

pub(super) fn needed(state: &SyncStateV3) -> bool {
    state.local.central.as_ref().is_some_and(|o| {
        o.control.cutover
            || o.rotation.is_some()
            || o.recovery.is_some()
            || o.replica.as_ref().is_some_and(|r| {
                !r.current.is_empty()
                    || !r.pending.is_empty()
                    || !r.conflicts.is_empty()
                    || r.checkpoint.sequence > 0
            })
    })
}
pub(super) fn projected(state: &SyncStateV3) -> bool {
    state.local.central_projection.is_some()
        || state
            .local
            .central
            .as_ref()
            .is_some_and(|o| o.control.cutover)
}
/// An empty central owner has only signed public control. Legacy payloads still pass the
/// independent source inventory; no unavailable device secret is needed to verify this proof.
pub(super) fn read_public_control(state: &SyncStateV3) -> Result<Captured, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    if needed(state) {
        return Err(invalid());
    }
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    owner.validate()?;
    let chain = owner.control.verified_chain()?;
    Ok(Captured {
        history: History::empty_retained(),
        floors: owner.replica.iter().map(|r| r.checkpoint.clone()).collect(),
        controls: vec![ControlMinimum {
            highwater: chain.highwater(),
            auth_epoch: owner.control.auth_epoch,
        }],
    })
}
pub(super) struct Captured {
    pub history: History,
    pub floors: Vec<Checkpoint>,
    pub controls: Vec<ControlMinimum>,
}
struct Reader<'a> {
    owner: &'a Workspace,
    chain: VerifiedChain,
    keys: BTreeMap<u64, VaultKeys>,
    rows: History,
    floors: Vec<Checkpoint>,
}
impl Reader<'_> {
    fn wraps(&mut self, identity: &DeviceIdentity, wraps: &[WrappedKeys]) -> Result<(), AppError> {
        let anchor = self.chain.current().anchor();
        for wrap in wraps.iter().filter(|w| w.header.recipient == identity.id) {
            let h = &wrap.header;
            if h.origin != anchor.origin
                || h.account_id != anchor.account_id
                || h.genesis_hash != anchor.genesis_hash
                || h.recipient_key != identity.device().keys.encryption
                || self.owner.control.personal_vault.as_deref() != Some(h.vault_id.as_str())
            {
                return Err(invalid());
            }
            let author = self
                .chain
                .author_at(&h.membership_head, &h.author)
                .ok_or_else(invalid)?;
            let keys = wrap.open(&identity.keys, h, &author.signing)?;
            let epoch = number(&h.key_epoch, false)?;
            if epoch > 65 {
                return Err(invalid());
            }
            if let Some(old) = self.keys.get(&epoch) {
                old.verify_same(&keys)?;
            }
            if let Some(old) = self.keys.values().next() {
                old.verify_index(&keys)?;
            }
            self.keys.insert(epoch, keys);
        }
        Ok(())
    }
    fn envelope(&mut self, envelope: &RecordEnvelope, hash: Option<&str>) -> Result<(), AppError> {
        let h = &envelope.header;
        let anchor = self.chain.current().anchor();
        if h.origin != anchor.origin
            || h.account_id != anchor.account_id
            || h.genesis_hash != anchor.genesis_hash
            || self.owner.control.personal_vault.as_deref() != Some(h.vault_id.as_str())
        {
            return Err(invalid());
        }
        let author = self
            .chain
            .author_at(&h.membership_head, &h.author)
            .ok_or_else(invalid)?;
        let keys = self.keys.get(&number(&h.key_epoch, false)?).ok_or_else(|| AppError::Other(
            "A retained central content epoch cannot be decrypted with the available scoped identity. Original files are retained.".into()))?;
        let plain = envelope.verify(&author.signing)?.open(keys)?;
        if hash.is_some_and(|hash| hash != crypto::hash(&plain)) {
            return Err(invalid());
        }
        let admitted = payload::admit(keys, h, &plain)?;
        self.rows.push_retained(admitted.identity, admitted.data)
    }
    fn base(&mut self, base: &Base) -> Result<(), AppError> {
        self.envelope(&base.version.envelope, Some(&base.content_hash))
    }
    fn replica(&mut self, replica: &Replica) -> Result<(), AppError> {
        replica.validate(&self.chain)?;
        self.floors.push(replica.checkpoint.clone());
        self.floors.extend(replica.minimum.iter().cloned());
        for base in replica.current.values() {
            self.base(base)?;
        }
        for pending in replica.pending.values() {
            self.envelope(&pending.latest.envelope, Some(&pending.latest.content_hash))?;
            if let Some(sent) = &pending.sent {
                self.envelope(&sent.envelope, Some(&sent.content_hash))?;
            }
            if let Some(confirmed) = &pending.confirmed {
                self.base(confirmed)?;
            }
        }
        for conflict in replica.conflicts.values().flatten() {
            if let Some(base) = &conflict.base {
                self.base(base)?;
            }
            self.envelope(&conflict.local.envelope, Some(&conflict.local.content_hash))?;
            self.base(&conflict.remote)?;
        }
        Ok(())
    }
}
/// All scope checks precede use of epoch wraps. Keys remain ephemeral and cannot be serialized.
pub(super) fn read(state: &SyncStateV3, identity: &DeviceIdentity) -> Result<Captured, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    if zeroize::Zeroizing::new(serde_json::to_vec(state).map_err(|_| invalid())?).len() as u64
        > crate::sync::record_runtime::MAX_STATE_BYTES
    {
        return Err(invalid());
    }
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    owner.validate()?;
    if identity.device() != owner.control.device {
        return Err(invalid());
    }
    let mut reader = Reader {
        owner,
        chain: match &owner.recovery {
            Some(super::recovery_state::RecoveryState::Pending { package }) => package
                .source_proof
                .verify(&package.admission.anchor, None)?,
            _ => owner.control.verified_chain()?,
        },
        keys: BTreeMap::new(),
        rows: History::empty_retained(),
        floors: vec![],
    };
    reader.wraps(identity, &owner.own_wraps)?;
    if let Some(bootstrap) = &owner.bootstrap {
        reader.wraps(identity, &bootstrap.wraps)?;
    }
    if let Some(rotation) = &owner.rotation {
        use super::rotation::Journal;
        match rotation {
            Journal::Source { source, rows, .. } => {
                reader.floors.push(source.clone());
                for row in rows {
                    reader.envelope(&row.envelope, None)?;
                }
            }
            Journal::Sending {
                manifest,
                wraps,
                from,
                rows,
                ..
            }
            | Journal::Receiving {
                manifest,
                wraps,
                from,
                rows,
                ..
            } => {
                reader.wraps(identity, wraps)?;
                // Target drafts are retained content, never evidence of server acceptance.
                reader.floors.push(from.clone());
                reader.floors.push(Checkpoint {
                    epoch: number(&manifest.body.from_epoch, false)?,
                    sequence: number(&manifest.body.source_sequence, true)?,
                    history_hash: manifest.body.source_history_hash.clone(),
                });
                for row in rows {
                    reader.envelope(&row.envelope, None)?;
                }
            }
        }
    }
    if let Some(replica) = &owner.replica {
        reader.replica(replica)?;
    }
    if let Some(ledger) = &state.local.central_projection {
        ledger.validate(owner)?;
        ledger.verify_historical_native(owner, &reader.keys)?;
        if state.rotation.is_some()
            || state.pending_account.is_some()
            || state
                .account
                .as_ref()
                .is_some_and(|a| !a.recovery.is_empty())
            || state.spaces.values().any(|s| !s.recovery.is_empty())
        {
            return Err(invalid());
        }
        reader.floors.push(ledger.checkpoint.clone());
        for basis in ledger.bases.values() {
            reader.base(&basis.wire)?;
        }
        // A local pointer may outlive its OS vault entry. Only an existing exact signed receipt
        // can bind it to a retained container; fingerprints alone never select a private version.
        for (id, local) in &state.local.keys {
            let matched = reader.rows.rows().iter().any(|(_, data)| {
                let Data::Key(private) = data else {
                    return false;
                };
                let entry = crate::vault::store::VaultEntry {
                    private_key: private.private().into(),
                    public_key: local.public.public_key.clone(),
                    fingerprint: private.fingerprint.clone(),
                    origin: crate::vault::store::EntryOrigin::Imported,
                    added_at_ms: local.public.created_at_ms,
                };
                ledger
                    .verify_source_material(owner, id, local, &entry)
                    .is_ok()
            });
            if !matched {
                return Err(invalid());
            }
        }
        let mut storage = ledger.storage.clone();
        for id in state.local.keys.keys() {
            storage.insert(
                id.clone(),
                ledger.key_storage(id).ok_or_else(invalid)?.clone(),
            );
        }
        for (id, data) in super::projection_local::public_rows(state, &ledger.catalog, &storage)? {
            reader.rows.push_retained(id, data)?;
        }
    }
    if owner.control.cutover && state.local.central_projection.is_none() {
        return Err(invalid());
    }
    let highwater = reader.chain.highwater();
    let mut controls = vec![ControlMinimum {
        highwater,
        auth_epoch: owner.control.auth_epoch,
    }];
    if let Some(super::recovery_state::RecoveryState::Pending { package }) = &owner.recovery {
        // A proposed Recover node is not accepted control. Constrain only its verified source.
        let source = package
            .source_proof
            .verify(&package.admission.anchor, None)?;
        controls.push(ControlMinimum {
            highwater: source.highwater(),
            auth_epoch: package.admission.authorization_epoch,
        });
        reader.chain = package.admission.verify(&package.proof())?;
        // Recovery workspaces have no current personal_vault, so its signed admission supplies scope.
        let mut admitted_owner = owner.clone();
        admitted_owner.control.personal_vault = Some(package.admission.vault.clone());
        let mut pending = Reader {
            owner: &admitted_owner,
            chain: reader.chain,
            keys: BTreeMap::new(),
            rows: reader.rows,
            floors: reader.floors,
        };
        pending.wraps(identity, &package.wraps)?;
        pending.replica(&package.replica)?;
        reader = Reader {
            owner,
            chain: source,
            keys: BTreeMap::new(),
            rows: pending.rows,
            floors: pending.floors,
        };
    }
    reader.floors.sort_by(|a, b| {
        (a.epoch, a.sequence, &a.history_hash).cmp(&(b.epoch, b.sequence, &b.history_hash))
    });
    reader.floors.dedup();
    Ok(Captured {
        history: reader.rows,
        floors: reader.floors,
        controls,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{crypto::DeviceKeys, payload::Data};
    use super::*;
    use crate::sync::{env::Keychain, testkit::MemKeychain};
    use zeroize::Zeroizing;
    fn identity(state: &SyncStateV3, signer: &DeviceKeys) -> DeviceIdentity {
        let owner = state.local.central.as_ref().unwrap();
        let profile = owner.control.profile.profile().unwrap();
        let keychain = MemKeychain::default();
        let value = Zeroizing::new(serde_json::json!({"version":1,"locator":profile.locator,"id":owner.control.device.id,"keys":&*signer.encode_secret(),"credential":"d".repeat(64)}).to_string());
        keychain
            .set(
                &profile
                    .device_slot("device", owner.identity_slot.as_deref())
                    .unwrap(),
                &value,
            )
            .unwrap();
        DeviceIdentity::load_selected(&keychain, &profile, owner.identity_slot.as_deref(), false)
            .unwrap()
    }
    #[test]
    fn active_projection_pending_ciphertexts_and_dirty_public_cache_are_passive_history() {
        let (state, keys, signer, context, public, entry) =
            super::super::local_material::tests::fixture(true);
        let intent = super::super::local_material::prepare_new(
            &state, &keys, &signer, context, public, &entry,
        )
        .unwrap()
        .intent()
        .unwrap();
        let mut candidate = intent.candidate(&state, &keys, &signer, &entry).unwrap();
        let host = candidate.local.hosts.values_mut().next().unwrap();
        host.record.payload["alias"] = "unsent-local-edit".into();
        let before = candidate.clone();
        let captured = read(&candidate, &identity(&candidate, &signer)).unwrap();
        assert_eq!(candidate, before);
        let rows = captured.history.into_rows();
        assert!(rows
            .iter()
            .any(|(_, data)| matches!(data,Data::Key(p) if p.private()==entry.private_key)));
        assert!(rows
            .iter()
            .any(|(_, data)| matches!(data,Data::Host(h) if h.alias=="unsent-local-edit")));
        assert_eq!(
            captured.floors,
            vec![candidate
                .local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .checkpoint
                .clone()]
        );
        for kind in ["hash", "ciphertext", "key", "scope", "basis-catalog"] {
            let mut damaged = candidate.clone();
            let owner = damaged.local.central.as_mut().unwrap();
            match kind {
                "hash" => {
                    owner
                        .replica
                        .as_mut()
                        .unwrap()
                        .pending
                        .values_mut()
                        .next()
                        .unwrap()
                        .latest
                        .content_hash = "f".repeat(64)
                }
                "ciphertext" => {
                    owner
                        .replica
                        .as_mut()
                        .unwrap()
                        .pending
                        .values_mut()
                        .next()
                        .unwrap()
                        .latest
                        .envelope
                        .ciphertext = "A".repeat(32)
                }
                "key" => owner.own_wraps.clear(),
                "basis-catalog" => {
                    damaged
                        .local
                        .central_projection
                        .as_mut()
                        .unwrap()
                        .catalog
                        .collections[0]
                        .name = "forged-basis-name".into()
                }
                _ => {
                    owner.own_wraps[0].header.recipient_key =
                        DeviceKeys::generate().unwrap().public().encryption
                }
            }
            assert!(
                read(&damaged, &identity(&candidate, &signer)).is_err(),
                "{kind}"
            );
        }
    }
    #[test]
    fn captured_active_backup_survives_old_identity_removal_without_restoring_any_authority() {
        use super::super::{source_capture, source_package::Package};
        use std::{collections::BTreeMap, fs};
        let (device, current_keys, _) = source_capture::tests::fixture(false);
        let env = device.env();
        let (old, old_keys, signer, context, public, entry) =
            super::super::local_material::tests::fixture(true);
        let intent = super::super::local_material::prepare_new(
            &old, &old_keys, &signer, context, public, &entry,
        )
        .unwrap()
        .intent()
        .unwrap();
        let mut old = intent.candidate(&old, &old_keys, &signer, &entry).unwrap();
        let owner = old.local.central.as_mut().unwrap();
        let old_role = owner
            .control
            .profile
            .profile()
            .unwrap()
            .device_slot("device", None)
            .unwrap();
        let before = crate::sync::record_runtime::snapshot(&env).unwrap();
        let path = env
            .state_path
            .parent()
            .unwrap()
            .join("sync-state.active-backup");
        fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let captured =
            source_capture::capture_adoption(&env, &current_keys, &BTreeMap::new(), None).unwrap();
        let bytes = captured.package.encode_local().unwrap();
        device.keychain.delete(&old_role).unwrap();
        let package = Package::decode_local(&bytes).unwrap();
        let history = package
            .structured_history(&current_keys, &BTreeMap::new())
            .unwrap()
            .into_rows();
        assert!(history
            .iter()
            .any(|(_, data)| matches!(data,Data::Key(p) if p.private()==entry.private_key)));
        assert!(package
            .historical_floors()
            .unwrap()
            .iter()
            .any(|c| c.sequence > 0));
        assert_eq!(crate::sync::record_runtime::snapshot(&env).unwrap(), before);
        assert!(
            !package
                .state
                .local
                .central
                .as_ref()
                .unwrap()
                .control
                .cutover
        );
        assert_eq!(package.encode_local().unwrap().as_slice(), bytes.as_slice());
        let mut tampered = Package::decode_local(&bytes).unwrap();
        let key = std::path::Path::new("data/sync-state.active-backup");
        let mut altered = old.clone();
        altered.device_name = "changed-original".into();
        tampered.files.bytes.insert(
            key.into(),
            Zeroizing::new(serde_json::to_vec(&altered).unwrap()),
        );
        assert!(tampered
            .structured_history(&current_keys, &BTreeMap::new())
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), serde_json::to_vec(&old).unwrap());
    }
    #[test]
    fn replacement_archive_retains_signed_history_before_old_identity_is_deleted() {
        use super::super::{replacement_archive, source_capture, source_package::Package};
        use std::{collections::BTreeMap, fs};
        let (device, current_keys, _) = source_capture::tests::fixture(false);
        let env = device.env();
        let (old, old_keys, signer, context, public, entry) =
            super::super::local_material::tests::fixture(true);
        let intent = super::super::local_material::prepare_new(
            &old, &old_keys, &signer, context, public, &entry,
        )
        .unwrap()
        .intent()
        .unwrap();
        let old = intent.candidate(&old, &old_keys, &signer, &entry).unwrap();
        // Model the real pre-replacement source on disk before signing its complete history.
        let current_disk = Zeroizing::new(fs::read(&env.state_path).unwrap());
        fs::write(&env.state_path, serde_json::to_vec(&old).unwrap()).unwrap();
        let receipt = {
            let life = env.runtime.lifecycle.lock().unwrap();
            replacement_archive::prepare(&env, &life, &old, 42, &"8".repeat(32))
                .unwrap()
                .receipt()
                .clone()
        };
        assert!(receipt.history_hash.is_some());
        fs::write(&env.state_path, current_disk.as_slice()).unwrap();
        let root = env
            .state_path
            .parent()
            .unwrap()
            .join("central-recovery-archives");
        let originals: BTreeMap<_, _> = fs::read_dir(&root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), fs::read(e.path()).unwrap())
            })
            .collect();
        assert_eq!(originals.len(), 3);
        let profile = old
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .profile
            .profile()
            .unwrap();
        let role = profile.device_slot("device", None).unwrap();
        let identity_bytes = device.keychain.get(&role).unwrap().unwrap();
        device.keychain.delete(&role).unwrap();
        let restored = replacement_archive::restore(&env, &profile, &receipt).unwrap();
        assert_eq!(restored, old);
        // The archive-side witness needs no old device identity. Restore the selected live key only
        // so foreground capture can authenticate its own invocation; deny historical key loads.
        device.keychain.set(&role, &identity_bytes).unwrap();
        let mut captured =
            source_capture::capture_adoption(&env, &current_keys, &BTreeMap::new(), None).unwrap();
        captured
            .package
            .capture_historical_snapshots(
                &identity(&captured.package.state, &signer),
                &|_| panic!("old identities must not be read when a signed archive witness exists"),
                &current_keys,
                &BTreeMap::new(),
            )
            .unwrap();
        let bytes = captured.package.encode_local().unwrap();
        device.keychain.delete(&role).unwrap();
        let package = Package::decode_local(&bytes).unwrap();
        assert!(package
            .structured_history(&current_keys, &BTreeMap::new())
            .unwrap()
            .into_rows()
            .iter()
            .any(|(_, data)| matches!(data,Data::Key(k) if k.private()==entry.private_key)));
        let after: BTreeMap<_, _> = fs::read_dir(&root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), fs::read(e.path()).unwrap())
            })
            .collect();
        assert_eq!(after, originals);
        let history_path = fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|s| s == "lphist"))
            .unwrap();
        let mut damaged = fs::read(&history_path).unwrap();
        let n = damaged.len() - 1;
        damaged[n] ^= 1;
        fs::write(&history_path, &damaged).unwrap();
        assert!(replacement_archive::restore(&env, &profile, &receipt).is_err());
        assert_eq!(fs::read(&history_path).unwrap(), damaged);
    }
    fn version(
        envelope: RecordEnvelope,
        sequence: u64,
        previous: &str,
    ) -> super::super::rekey::Version {
        let digest = super::super::rekey::envelope_digest(&envelope).unwrap();
        let history_hash = crypto::hash(
            &super::super::wire::canonical(&[
                "lunport-history-v2",
                previous,
                &sequence.to_string(),
                &digest,
            ])
            .unwrap(),
        );
        super::super::rekey::Version {
            revision: (number(&envelope.header.expected_revision, true).unwrap() + 1).to_string(),
            sequence: sequence.to_string(),
            envelope,
            digest,
            history_hash,
        }
    }
    #[test]
    fn sent_confirmed_and_each_conflict_side_remain_independent_passive_versions() {
        use super::super::{
            payload::{Data, Identity},
            wire::RecordHeader,
        };
        let (mut state, keys, signer, _, _, _) =
            super::super::local_material::tests::fixture(false);
        let owner = state.local.central.as_mut().unwrap();
        let chain = owner.control.verified_chain().unwrap();
        let replica = owner.replica.as_mut().unwrap();
        let base = replica
            .current
            .values()
            .find(|v| v.version.envelope.header.kind == "host")
            .unwrap()
            .clone();
        let h = &base.version.envelope.header;
        let plain = base
            .version
            .envelope
            .verify(&signer.public().signing)
            .unwrap()
            .open(&keys)
            .unwrap();
        let admitted = payload::admit(&keys, h, &plain).unwrap();
        let id = admitted.identity;
        let Data::Host(mut host) = admitted.data else {
            panic!()
        };
        let mut header: RecordHeader = h.clone();
        header.expected_revision = base.version.revision.clone();
        header.operation_id = "1".repeat(32);
        host.alias = "local-A".into();
        let a = payload::encode(&id, &Data::Host(host.clone())).unwrap();
        replica
            .enqueue(&chain, &keys, &signer, 1, header.clone(), &a)
            .unwrap();
        let sent = replica
            .prepare_send(&chain, owner.control.auth_epoch, 1, &[])
            .unwrap()
            .remove(0);
        host.alias = "local-B".into();
        header.operation_id = "2".repeat(32);
        let b = payload::encode(&id, &Data::Host(host.clone())).unwrap();
        replica
            .enqueue(&chain, &keys, &signer, 2, header.clone(), &b)
            .unwrap();
        let read_sent = read(&state, &identity(&state, &signer)).unwrap();
        for alias in ["local-A", "local-B"] {
            assert!(read_sent
                .history
                .rows()
                .iter()
                .any(|(_, d)| matches!(d,Data::Host(h) if h.alias==alias)));
        }
        let owner = state.local.central.as_mut().unwrap();
        let replica = owner.replica.as_mut().unwrap();
        let ack = version(
            sent,
            replica.checkpoint.sequence + 1,
            &replica.checkpoint.history_hash,
        );
        host.alias = "remote-C".into();
        header.operation_id = "3".repeat(32);
        header.expected_revision = ack.revision.clone();
        let remote = version(
            crypto::seal_record(
                &keys,
                &signer,
                header,
                &payload::encode(&id, &Data::Host(host)).unwrap(),
            )
            .unwrap(),
            number(&ack.sequence, false).unwrap() + 1,
            &ack.history_hash,
        );
        let cp = Checkpoint {
            epoch: 1,
            sequence: number(&remote.sequence, false).unwrap(),
            history_hash: remote.history_hash.clone(),
        };
        *replica = replica
            .prepare_page(&chain, &keys, &[ack, remote], &cp)
            .unwrap()
            .next;
        assert!(replica.pending.values().any(|p| p.confirmed.is_some()));
        assert!(!replica.conflicts.is_empty());
        let before = state.clone();
        let read = read(&state, &identity(&state, &signer)).unwrap();
        for alias in ["local-A", "local-B", "remote-C", "fixture"] {
            assert!(
                read.history
                    .rows()
                    .iter()
                    .any(|(_, d)| matches!(d,Data::Host(h) if h.alias==alias)),
                "{alias}"
            );
        }
        assert_eq!(state, before);
        let conflict = state
            .local
            .central
            .as_mut()
            .unwrap()
            .replica
            .as_mut()
            .unwrap()
            .conflicts
            .values_mut()
            .next()
            .unwrap();
        conflict[0].local.content_hash = "f".repeat(64);
        assert!(super::read(&state, &identity(&before, &signer)).is_err());
        let _: Identity = id;
    }
    #[test]
    fn rotation_source_sending_and_receiving_use_ephemeral_epoch_keys_and_only_accepted_source_floors(
    ) {
        use super::super::{rekey, rotation::Journal};
        let (mut state, keys, signer, _, _, _) =
            super::super::local_material::tests::fixture(false);
        let owner = state.local.central.as_mut().unwrap();
        owner.control.phase = super::super::client_state::Phase::Rekey;
        let replica = owner.replica.as_ref().unwrap();
        let cp = replica.checkpoint.clone();
        let mut rows: Vec<_> = replica
            .current
            .values()
            .map(|b| b.version.clone())
            .collect();
        rows.sort_by_key(|v| number(&v.sequence, false).unwrap());
        let chain = owner.control.verified_chain().unwrap();
        let head = chain.current().head().to_owned();
        let source = Journal::Source {
            membership_head: head,
            authorization_epoch: owner.control.auth_epoch,
            source: cp.clone(),
            rows: rows.clone(),
        };
        let plan = rekey::prepare(
            &chain,
            &owner.control.device.id,
            &signer,
            &replica.vault,
            owner.control.auth_epoch,
            &keys,
            &cp,
            &cp,
            &rows,
        )
        .unwrap();
        let sending = Journal::sending(owner, plan, &rows).unwrap();
        let receiving = match &sending {
            Journal::Sending {
                manifest,
                wraps,
                from,
                source_suffix,
                rows,
                ..
            } => Journal::Receiving {
                manifest: manifest.clone(),
                wraps: wraps.clone(),
                from: from.clone(),
                source_suffix: source_suffix.clone(),
                rows: rows[..1].to_vec(),
            },
            _ => panic!(),
        };
        for journal in [source, sending, receiving] {
            state.local.central.as_mut().unwrap().rotation = Some(journal);
            let before = state.clone();
            let captured = read(&state, &identity(&state, &signer)).unwrap();
            assert!(!captured.history.into_rows().is_empty());
            assert!(captured.floors.iter().all(|f| f.epoch == 1));
            assert_eq!(state, before);
        }
    }
    #[test]
    fn pending_recovery_keeps_content_without_claiming_the_proposed_recovery_node_as_accepted_control(
    ) {
        let (mut owner, prepared, signer, _) = super::super::recovery_state::tests::prepared(false);
        owner.recovery = Some(super::super::recovery_state::RecoveryState::Pending {
            package: Box::new(prepared.package.clone()),
        });
        let mut state:SyncStateV3=serde_json::from_value(serde_json::json!({"version":8,"device_id":"d".repeat(32),"device_name":"Historical recovery","relay_url":owner.control.profile.origin,"last_sync_ms":null,"last_error":null})).unwrap();
        state.local.central = Some(owner);
        let before = state.clone();
        let captured = read(&state, &identity(&state, &signer)).unwrap();
        assert!(!captured.history.into_rows().is_empty());
        let chain = prepared
            .package
            .source_proof
            .verify(&prepared.package.admission.anchor, None)
            .unwrap();
        assert!(captured
            .controls
            .iter()
            .all(|c| c.highwater == chain.highwater()));
        assert_eq!(state, before);
    }
    #[test]
    #[ignore = "explicit retained central-state 16384-row admission benchmark"]
    fn capacity_retained_rotation_source_admits_16384_versions_and_rejects_16385_without_partial_history(
    ) {
        use super::super::{payload::Data, rotation::Journal};
        let (mut state, keys, signer, _, _, _) =
            super::super::local_material::tests::fixture(false);
        let owner = state.local.central.as_mut().unwrap();
        owner.control.phase = super::super::client_state::Phase::Rekey;
        let replica = owner.replica.as_ref().unwrap();
        let mut rows: Vec<_> = replica
            .current
            .values()
            .map(|b| b.version.clone())
            .collect();
        rows.sort_by_key(|v| number(&v.sequence, false).unwrap());
        let base = rows
            .iter()
            .find(|b| b.envelope.header.kind == "host")
            .unwrap();
        let mut h = base.envelope.header.clone();
        let plain = base
            .envelope
            .verify(&signer.public().signing)
            .unwrap()
            .open(&keys)
            .unwrap();
        let value = payload::admit(&keys, &h, &plain).unwrap();
        let Data::Host(mut host) = value.data else {
            panic!()
        };
        let mut revision = number(&base.revision, false).unwrap();
        while rows.len() < 16384 {
            h.expected_revision = revision.to_string();
            h.operation_id = format!("{:032x}", rows.len() + 100);
            host.alias = format!("retained-version-{}", rows.len());
            let envelope = crypto::seal_record(
                &keys,
                &signer,
                h.clone(),
                &payload::encode(&value.identity, &Data::Host(host.clone())).unwrap(),
            )
            .unwrap();
            rows.push(version(
                envelope,
                rows.len() as u64 + 1,
                &rows.last().unwrap().history_hash,
            ));
            revision += 1;
        }
        let source = super::super::rotation::checkpoint(1, &rows).unwrap();
        let chain = owner.control.verified_chain().unwrap();
        owner.rotation = Some(Journal::Source {
            membership_head: chain.current().head().into(),
            authorization_epoch: owner.control.auth_epoch,
            source,
            rows,
        });
        let before = state.clone();
        let captured = read(&state, &identity(&state, &signer)).unwrap();
        assert_eq!(captured.history.into_rows().len(), 16384);
        let signed = super::super::source_package::snapshot::StateSnapshot::create(
            &state,
            &identity(&state, &signer),
        )
        .unwrap();
        drop(
            super::super::source_package::snapshot::StateSnapshot::decode(signed.bytes())
                .unwrap()
                .verify(&state)
                .unwrap(),
        );
        assert_eq!(state, before);
        if let Some(Journal::Source { source, rows, .. }) =
            &mut state.local.central.as_mut().unwrap().rotation
        {
            source.sequence = 16385;
            rows.push(rows.last().unwrap().clone());
        }
        assert!(read(&state, &identity(&before, &signer)).is_err());
    }
    #[test]
    fn an_already_lost_identity_keeps_the_original_opaque_archive_and_a_later_available_identity_adds_history_without_replacing_it(
    ) {
        use super::super::{replacement_archive, source_capture};
        let (device, _, _) = source_capture::tests::fixture(false);
        let env = device.env();
        let (state, _, _, _, _, _) = super::super::local_material::tests::fixture(true);
        let current_disk = Zeroizing::new(std::fs::read(&env.state_path).unwrap());
        std::fs::write(&env.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let profile = state
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .profile
            .profile()
            .unwrap();
        let role = profile.device_slot("device", None).unwrap();
        let saved = Zeroizing::new(device.keychain.get(&role).unwrap().unwrap());
        device.keychain.delete(&role).unwrap();
        let receipt = {
            let life = env.runtime.lifecycle.lock().unwrap();
            replacement_archive::prepare(&env, &life, &state, 1, &"9".repeat(32))
                .unwrap()
                .receipt()
                .clone()
        };
        assert!(receipt.history_hash.is_none());
        assert_eq!(
            replacement_archive::restore(&env, &profile, &receipt).unwrap(),
            state
        );
        device.keychain.set(&role, &saved).unwrap();
        let upgraded = {
            let life = env.runtime.lifecycle.lock().unwrap();
            replacement_archive::prepare(&env, &life, &state, 1, &"9".repeat(32))
                .unwrap()
                .receipt()
                .clone()
        };
        std::fs::write(&env.state_path, current_disk.as_slice()).unwrap();
        assert!(upgraded.history_hash.is_some());
        assert_eq!(upgraded.context, receipt.context);
        assert_eq!(upgraded.file_hash, receipt.file_hash);
    }
}
