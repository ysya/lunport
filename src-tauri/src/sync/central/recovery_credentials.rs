//! Temporary recovery authority storage. Exact protected readback precedes Core publication.
//! The compact intent excludes the potentially large ciphertext cache and membership history.
use super::{
    bootstrap::RecoveryReveal,
    credentials::Profile,
    crypto,
    membership::SignedMembership,
    owner::OwnerPath,
    recovery::{RecoveryKit, RecoverySeed},
    recovery_state::{Admission, Package, PreparedRecovery, RecoveryState},
    trust::ControlProof,
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};
const CAP: usize = 32768;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    locator: String,
    operation: String,
    #[serde(default)]
    epoch_count: usize,
    #[serde(default)]
    epochs_digest: String,
    admission: Admission,
    node: SignedMembership,
    #[serde(deserialize_with = "read_secret", serialize_with = "write_secret")]
    old_kit: Zeroizing<String>,
    #[serde(deserialize_with = "read_secret", serialize_with = "write_secret")]
    new_kit: Zeroizing<String>,
}
fn read_secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}
fn write_secret<S: Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.as_str().serialize(serializer)
}
impl Drop for Stored {
    fn drop(&mut self) {
        self.old_kit.zeroize();
        self.new_kit.zeroize();
    }
}
impl Stored {
    fn encode(&self) -> Result<Zeroizing<String>, AppError> {
        let encoded = Zeroizing::new(serde_json::to_string(self).map_err(|_| invalid())?);
        if encoded.len() > CAP {
            return Err(invalid());
        }
        Ok(encoded)
    }
    fn scope(&self, profile: &Profile) -> Result<(), AppError> {
        if ![1, 2].contains(&self.version)
            || self.locator != profile.locator
            || self.admission.anchor.origin != profile.origin
            || !super::wire::hex(&self.operation, 32)
        {
            return Err(invalid());
        }
        if self.version == 2
            && (self.epoch_count > 64
                || !super::wire::hex(&self.epochs_digest, 64)
                || self.epoch_count as u64 + 1 != self.admission.checkpoint.epoch)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn prefix(&self) -> super::recovery_revalidation::EpochPrefix {
        super::recovery_revalidation::EpochPrefix {
            count: if self.version == 1 {
                (self.admission.checkpoint.epoch - 1) as usize
            } else {
                self.epoch_count
            },
            digest: (self.version == 2).then(|| self.epochs_digest.clone()),
        }
    }
    fn verify_proof(&self, profile: &Profile, proof: &ControlProof) -> Result<(), AppError> {
        self.scope(profile)?;
        let chain = self.admission.verify(proof)?;
        let revision = chain
            .revision_of(&self.admission.approved_head)
            .ok_or_else(invalid)?;
        if proof.nodes.get(revision - 1) != Some(&self.node) {
            return Err(invalid());
        }
        RecoveryKit::parse(&self.old_kit)?.keys_at(&chain, &self.admission.previous_head)?;
        RecoveryKit::parse(&self.new_kit)?.keys_at(&chain, &self.admission.approved_head)?;
        Ok(())
    }
    fn verify_package(&self, profile: &Profile, package: &Package) -> Result<(), AppError> {
        if self.operation != package.operation
            || self.admission != package.admission
            || self.node != package.node
        {
            return Err(invalid());
        }
        if self.version == 2 {
            self.prefix().verify(&package.epochs)?;
            if self.epoch_count != package.epochs.len() {
                return Err(invalid());
            }
        }
        self.verify_proof(profile, &package.proof())
    }
}
fn slot(owner: &Workspace) -> Result<String, AppError> {
    owner
        .control
        .profile
        .profile()?
        .device_slot("recovery-intent", owner.identity_slot.as_deref())
}
fn load(env: &SyncEnv, owner: &Workspace) -> Result<Option<Stored>, AppError> {
    let profile = owner.control.profile.profile()?;
    env.keychain
        .get(&slot(owner)?)?
        .map(|value| {
            let encoded = Zeroizing::new(value);
            if encoded.len() > CAP {
                return Err(invalid());
            }
            let stored: Stored = serde_json::from_str(&encoded).map_err(|_| invalid())?;
            stored.scope(&profile)?;
            Ok(stored)
        })
        .transpose()
}
fn digest(package: &Package) -> Result<String, AppError> {
    Ok(crypto::hash(
        &serde_json::to_vec(package).map_err(|_| invalid())?,
    ))
}
fn stored_for(
    profile: &Profile,
    package: &Package,
    old_kit: &RecoveryKit,
    new_kit: &RecoveryKit,
) -> Result<Stored, AppError> {
    let stored = Stored {
        version: 2,
        epoch_count: package.epochs.len(),
        epochs_digest: super::recovery_revalidation::EpochPrefix::capture(&package.epochs)?
            .digest
            .ok_or_else(invalid)?,
        locator: profile.locator.clone(),
        operation: package.operation.clone(),
        admission: package.admission.clone(),
        node: package.node.clone(),
        old_kit: old_kit.encode_secret()?,
        new_kit: new_kit.encode_secret()?,
    };
    stored.verify_package(profile, package)?;
    Ok(stored)
}
fn verify_staged_source(
    stored: &Stored,
    profile: &Profile,
    source: &ControlProof,
) -> Result<(), AppError> {
    let revision = number(&stored.node.body.revision, false)?
        .checked_sub(1)
        .ok_or_else(invalid)? as usize;
    let mut proof = ControlProof {
        genesis: source.genesis.clone(),
        nodes: source.nodes.get(..revision).ok_or_else(invalid)?.to_vec(),
    };
    proof.nodes.push(stored.node.clone());
    stored.verify_proof(profile, &proof)
}
/// No Serialize/Clone. Only successful protected readback mints a publication permit.
pub struct Permit {
    path: OwnerPath,
    locator: String,
    operation: String,
    digest: String,
}
/// Caller owns the existing lifecycle gate. An orphan may reuse the same secrets/operation;
/// it cannot silently replace a different stored recovery authority.
pub fn stage(
    env: &SyncEnv,
    before: &Workspace,
    prepared: &PreparedRecovery,
    old_kit: &RecoveryKit,
) -> Result<Permit, AppError> {
    stage_at(env, &OwnerPath::Current, before, prepared, old_kit)
}
pub(super) fn stage_at(
    env: &SyncEnv,
    path: &OwnerPath,
    before: &Workspace,
    prepared: &PreparedRecovery,
    old_kit: &RecoveryKit,
) -> Result<Permit, AppError> {
    if before.recovery.is_some() {
        return Err(invalid());
    }
    if path.snapshot(env)? != *before {
        return Err(crate::sync::runtime::superseded());
    }
    let mut candidate_owner = before.clone();
    candidate_owner.control.pending_request = prepared.package.node.body.enrollment.clone();
    candidate_owner.control.auth_epoch = prepared.package.admission.authorization_epoch;
    prepared.package.validate(&candidate_owner)?;
    let profile = before.control.profile.profile()?;
    let stored = stored_for(&profile, &prepared.package, old_kit, &prepared.kit)?;
    if let Some(previous) = load(env, before)? {
        if previous.operation != stored.operation
            || previous.new_kit.as_str() != stored.new_kit.as_str()
        {
            return Err(AppError::Other(
                "Existing recovery credentials are retained. Resume that recovery operation first."
                    .into(),
            ));
        }
        previous.prefix().verify(&prepared.package.epochs)?;
        if previous.admission != stored.admission || previous.node != stored.node {
            let evidence = prepared.package.revalidation.as_ref().ok_or_else(invalid)?;
            if evidence.previous != previous.admission || evidence.node != previous.node {
                return Err(invalid());
            }
            evidence.verify(&prepared.package)?;
        } else if previous.old_kit.as_str() != stored.old_kit.as_str() {
            return Err(invalid());
        }
    }
    let encoded = stored.encode()?;
    env.keychain.set(&slot(before)?, &encoded)?;
    let checked = load(env, before)?.ok_or_else(invalid)?;
    checked.verify_package(&profile, &prepared.package)?;
    if checked.encode()?.as_str() != encoded.as_str() {
        return Err(invalid());
    }
    Ok(Permit {
        path: path.clone(),
        locator: profile.locator,
        operation: prepared.package.operation.clone(),
        digest: digest(&prepared.package)?,
    })
}
pub fn install(
    env: &SyncEnv,
    before: &Workspace,
    package: &Package,
    permit: Permit,
) -> Result<(), AppError> {
    install_at(env, &OwnerPath::Current, before, package, permit)
}
pub(super) fn install_at(
    env: &SyncEnv,
    path: &OwnerPath,
    before: &Workspace,
    package: &Package,
    permit: Permit,
) -> Result<(), AppError> {
    let profile = before.control.profile.profile()?;
    if &permit.path != path
        || permit.locator != profile.locator
        || permit.operation != package.operation
        || permit.digest != digest(package)?
        || before.recovery.is_some()
    {
        return Err(invalid());
    }
    let mut candidate_owner = before.clone();
    candidate_owner.control.pending_request = package.node.body.enrollment.clone();
    candidate_owner.control.auth_epoch = package.admission.authorization_epoch;
    package.validate(&candidate_owner)?;
    load(env, before)?
        .ok_or_else(invalid)?
        .verify_package(&profile, package)?;
    let mut next = before.clone();
    next.control.pending_request = package.node.body.enrollment.clone();
    next.control.auth_epoch = package.admission.authorization_epoch;
    next.control.phase = super::client_state::Phase::AwaitingApproval;
    next.recovery = Some(RecoveryState::Pending {
        package: Box::new(package.clone()),
    });
    path.publish(env, before, &next)
}
fn publish(env: &SyncEnv, before: &Workspace, next: &Workspace) -> Result<(), AppError> {
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut candidate = records.clone();
        candidate.local.central = Some(next.clone());
        Ok(candidate)
    })?;
    Ok(())
}
fn workspace(env: &SyncEnv) -> Result<Workspace, AppError> {
    record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)
}
fn pending(workspace: &Workspace) -> Result<&Package, AppError> {
    match workspace.recovery.as_ref() {
        Some(RecoveryState::Pending { package }) => Ok(package),
        _ => Err(invalid()),
    }
}
/// A dedicated reveal response. The old kit never leaves native storage.
pub fn reveal(env: &SyncEnv) -> Result<RecoveryReveal, AppError> {
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    reveal_at(env, &OwnerPath::Current)
}
/// Caller owns lifecycle, including when revealing a staged replacement's future kit.
pub(super) fn reveal_at(env: &SyncEnv, path: &OwnerPath) -> Result<RecoveryReveal, AppError> {
    let before = path.snapshot(env)?;
    let package = pending(&before)?;
    let profile = before.control.profile.profile()?;
    let stored = load(env, &before)?.ok_or_else(invalid)?;
    stored.verify_package(&profile, package)?;
    Ok(RecoveryReveal {
        root: package.admission.anchor.genesis_hash.clone(),
        kit: stored.new_kit.to_string(),
    })
}
pub fn confirm_backup(env: &SyncEnv, operation: &str) -> Result<(), AppError> {
    confirm_backup_at(env, &OwnerPath::Current, operation)
}
pub(super) fn confirm_backup_at(
    env: &SyncEnv,
    path: &OwnerPath,
    operation: &str,
) -> Result<(), AppError> {
    let before = path.snapshot(env)?;
    let package = pending(&before)?;
    if package.operation != operation {
        return Err(invalid());
    }
    load(env, &before)?
        .ok_or_else(invalid)?
        .verify_package(&before.control.profile.profile()?, package)?;
    let mut next = before.clone();
    match next.recovery.as_mut() {
        Some(RecoveryState::Pending { package }) => package.backup_confirmed = true,
        _ => return Err(invalid()),
    }
    path.publish(env, &before, &next)
}
pub fn verify_pending(env: &SyncEnv, owner: &Workspace) -> Result<(), AppError> {
    let package = pending(owner)?;
    let profile = owner.control.profile.profile()?;
    match load(env, owner)? {
        Some(stored) => stored.verify_package(&profile, package),
        None if package.submitted && package.backup_confirmed => Ok(()),
        None => Err(invalid()),
    }
}
/// Foreground only. Missing-after-delete is an exact retry; failed deletion/readback keeps writes gated.
pub fn cleanup(env: &SyncEnv) -> Result<(), AppError> {
    cleanup_at(env, &OwnerPath::Current)
}
pub(super) fn cleanup_at(env: &SyncEnv, path: &OwnerPath) -> Result<(), AppError> {
    let before = path.snapshot(env)?;
    let admission = match before.recovery.as_ref() {
        Some(RecoveryState::Accepted {
            admission,
            credentials_cleared: false,
            ..
        }) => admission,
        Some(RecoveryState::Accepted {
            credentials_cleared: true,
            ..
        }) => return Ok(()),
        _ => return Err(invalid()),
    };
    let profile = before.control.profile.profile()?;
    if let Some(stored) = load(env, &before)? {
        if &stored.admission != admission
            || before
                .recovery
                .as_ref()
                .is_none_or(|r| r.operation() != stored.operation)
        {
            return Err(invalid());
        }
        stored.verify_proof(&profile, before.control.proof.as_ref().ok_or_else(invalid)?)?;
        env.keychain.delete(&slot(&before)?)?;
        if env.keychain.get(&slot(&before)?)?.is_some() {
            return Err(invalid());
        }
    }
    let mut next = before.clone();
    match next.recovery.as_mut() {
        Some(RecoveryState::Accepted {
            credentials_cleared,
            ..
        }) => *credentials_cleared = true,
        _ => return Err(invalid()),
    }
    path.publish(env, &before, &next)
}
/// A crash before Core publication may leave compact protected secrets. Re-read all ciphertext
/// before building a fresh journal, while retaining the same new kit and operation identity.
pub struct Orphan {
    pub known: Admission,
    pub node: SignedMembership,
    pub prefix: super::recovery_revalidation::EpochPrefix,
    pub old_kit: RecoveryKit,
    pub seed: RecoverySeed,
    pub operation: String,
}
pub fn resume_orphan(
    env: &SyncEnv,
    before: &Workspace,
    current_proof: &ControlProof,
) -> Result<Option<Orphan>, AppError> {
    resume_orphan_with_kit(env, before, current_proof, None)
}
pub fn resume_orphan_with_kit(
    env: &SyncEnv,
    before: &Workspace,
    current_proof: &ControlProof,
    supplied: Option<&RecoveryKit>,
) -> Result<Option<Orphan>, AppError> {
    if before.recovery.is_some() || before.control.anchor.is_some() {
        return Err(invalid());
    }
    let profile = before.control.profile.profile()?;
    let Some(stored) = load(env, before)? else {
        return Ok(None);
    };
    if stored.admission.anchor.account_id != before.control.account_id {
        return Err(invalid());
    }
    let prior_revision = number(&stored.node.body.revision, false)?
        .checked_sub(1)
        .ok_or_else(invalid)? as usize;
    let mut original = ControlProof {
        genesis: current_proof.genesis.clone(),
        nodes: current_proof
            .nodes
            .get(..prior_revision)
            .ok_or_else(invalid)?
            .to_vec(),
    };
    original.nodes.push(stored.node.clone());
    stored.verify_proof(&profile, &original)?;
    let old_kit = if let Some(supplied) = supplied {
        if supplied.anchor() != &stored.admission.anchor {
            return Err(invalid());
        }
        RecoveryKit::parse(&supplied.encode_secret()?)?
    } else {
        RecoveryKit::parse(&stored.old_kit)?
    };
    old_kit.current_keys(&current_proof.verify(old_kit.anchor(), None)?)?;
    Ok(Some(Orphan {
        known: stored.admission.clone(),
        node: stored.node.clone(),
        prefix: stored.prefix(),
        old_kit,
        seed: RecoveryKit::parse(&stored.new_kit)?.resume_seed(&stored.admission.anchor)?,
        operation: stored.operation.clone(),
    }))
}

/// A protected orphan also reserves this account's recovery path after a failed Core write.
/// Ordinary login/pairing may retain access, but cannot bypass this pending recovery intent.
pub fn has_intent(env: &SyncEnv, owner: &Workspace) -> Result<bool, AppError> {
    let Some(stored) = load(env, owner)? else {
        return Ok(false);
    };
    if stored.admission.anchor.account_id != owner.control.account_id
        || stored.admission.device != owner.control.device
    {
        return Err(invalid());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        env::Keychain,
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    use std::sync::atomic::Ordering;
    fn setup() -> (TestDevice, Workspace, PreparedRecovery, RecoveryKit) {
        let (before, prepared, _, old) = super::super::recovery_state::tests::prepared(false);
        let d = TestDevice::new("recovery", &FakeRelay::new(), &TestClock::new());
        let env = d.env();
        let probe = record_runtime::probe_startup(&env.state_path, "recovery");
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
        record_runtime::mutate_records(&env, |state| {
            let mut next = state.clone();
            next.local.central = Some(before.clone());
            Ok(next)
        })
        .unwrap();
        (d, before, prepared, old)
    }
    #[test]
    fn protected_readback_precedes_core_and_local_edits_survive_installation() {
        let (d, before, prepared, old) = setup();
        let env = d.env();
        let snapshot = record_runtime::snapshot(&env).unwrap();
        let permit = stage(&env, &before, &prepared, &old).unwrap();
        assert_eq!(record_runtime::snapshot(&env).unwrap(), snapshot);
        let profile = before.control.profile.profile().unwrap();
        assert!(has_intent(&env, &before).unwrap());
        let mut wrong = before.clone();
        wrong.control.device.id = "f".repeat(32);
        assert!(has_intent(&env, &wrong).is_err());
        assert!(super::super::controller::session_epoch_matches(
            &before.control,
            before.control.auth_epoch + 1,
            super::super::api::DeviceState::Active
        ));
        assert!(super::super::controller::session_epoch_matches(
            &before.control,
            before.control.auth_epoch + 1,
            super::super::api::DeviceState::Pending
        ));
        let mut anchored = before.control.clone();
        anchored.anchor = Some(prepared.package.admission.anchor.clone());
        for state in [
            super::super::api::DeviceState::Pending,
            super::super::api::DeviceState::Active,
        ] {
            assert!(!super::super::controller::session_epoch_matches(
                &anchored,
                anchored.auth_epoch + 1,
                state
            ));
        }
        assert!(before.control.anchor.is_none());
        assert!(!before.can_upload());
        assert!(!super::super::controller::session_epoch_matches(
            &before.control,
            before.control.auth_epoch - 1,
            super::super::api::DeviceState::Active
        ));

        let resumed = resume_orphan(&env, &before, &prepared.package.source_proof)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.operation, prepared.package.operation);
        let recovered_keys = resumed
            .seed
            .keys(&profile.origin, &before.control.account_id)
            .unwrap();
        let proof = prepared.package.proof();
        let chain = proof.verify(prepared.kit.anchor(), None).unwrap();
        assert_eq!(
            recovered_keys.public(),
            prepared.kit.current_keys(&chain).unwrap().public()
        );
        record_runtime::mutate_records(&env, |state| {
            let mut next = state.clone();
            next.device_name = "local-B".into();
            Ok(next)
        })
        .unwrap();
        install(&env, &before, &prepared.package, permit).unwrap();
        let records = record_runtime::snapshot(&env).unwrap().0;
        assert_eq!(records.device_name, "local-B");
        let encoded = serde_json::to_string(&records).unwrap();
        assert!(!encoded.contains("LPREC2:"));
        assert!(!encoded.contains("old_kit"));
        let shown = reveal(&env).unwrap();
        assert_eq!(shown.kit, prepared.kit.encode_secret().unwrap().as_str());
        assert!(confirm_backup(&env, &"f".repeat(32)).is_err());
        confirm_backup(&env, &prepared.package.operation).unwrap();
        verify_pending(&env, &workspace(&env).unwrap()).unwrap();
        let probe = record_runtime::probe_startup(&env.state_path, "recovery");
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
        let reloaded = workspace(&env).unwrap();
        assert!(pending(&reloaded).unwrap().backup_confirmed);
        assert!(reveal(&env).is_ok());
        assert!(d.keychain.entry(&profile.slot("recovery-intent")).is_some());
    }
    #[test]
    fn denied_or_lost_protected_writes_cannot_mint_a_core_publication_permit() {
        let (d, before, prepared, old) = setup();
        let env = d.env();
        let slot = before
            .control
            .profile
            .profile()
            .unwrap()
            .slot("recovery-intent");
        let snapshot = record_runtime::snapshot(&env).unwrap();
        d.keychain.fail_writes_to(&slot, true);
        assert!(stage(&env, &before, &prepared, &old).is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), snapshot);
        d.keychain.fail_writes_to(&slot, false);
        struct Lost<'a>(&'a dyn Keychain);
        impl Keychain for Lost<'_> {
            fn get(&self, key: &str) -> Result<Option<String>, AppError> {
                self.0.get(key)
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("staging cannot delete credentials")
            }
        }
        let lost = Lost(&d.keychain);
        let missing = SyncEnv {
            keychain: &lost,
            ..d.env()
        };
        assert!(stage(&missing, &before, &prepared, &old).is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), snapshot);
        d.keychain.set(&slot, "corrupted-protected-intent").unwrap();
        assert!(stage(&env, &before, &prepared, &old).is_err());
        assert_eq!(
            d.keychain.entry(&slot).as_deref(),
            Some("corrupted-protected-intent")
        );
    }
    #[test]
    fn a_permit_cannot_publish_a_different_package_or_overwrite_an_existing_kit() {
        let (d, before, prepared, old) = setup();
        let env = d.env();
        let permit = stage(&env, &before, &prepared, &old).unwrap();
        let profile = before.control.profile.profile().unwrap();
        let protected = d.keychain.entry(&profile.slot("recovery-intent"));
        let mut changed = prepared.package.clone();
        changed.operation = "d".repeat(32);
        assert!(install(&env, &before, &changed, permit).is_err());
        let mut different = prepared;
        different.package.operation = "e".repeat(32);
        assert!(stage(&env, &before, &different, &old).is_err());
        assert_eq!(
            d.keychain.entry(&profile.slot("recovery-intent")),
            protected
        );
        assert_eq!(workspace(&env).unwrap(), before);
    }
    fn accept(env: &SyncEnv, prepared: &PreparedRecovery) {
        confirm_backup(env, &prepared.package.operation).unwrap();
        record_runtime::mutate_records(env, |records| {
            let mut next = records.clone();
            match next
                .local
                .central
                .as_mut()
                .unwrap()
                .recovery
                .as_mut()
                .unwrap()
            {
                RecoveryState::Pending { package } => package.submitted = true,
                _ => panic!(),
            }
            Ok(next)
        })
        .unwrap();
        let before = workspace(env).unwrap();
        let next = prepared
            .package
            .accepted(
                &before,
                prepared.package.proof(),
                prepared.package.admission.authorization_epoch + 1,
            )
            .unwrap();
        publish(env, &before, &next).unwrap();
    }
    #[test]
    fn failed_cleanup_or_core_save_preserves_the_gate_and_allows_exact_missing_after_delete_retry()
    {
        let (d, before, prepared, old) = setup();
        let env = d.env();
        let permit = stage(&env, &before, &prepared, &old).unwrap();
        install(&env, &before, &prepared.package, permit).unwrap();
        accept(&env, &prepared);
        let accepted = workspace(&env).unwrap();
        d.keychain.fail_deletes.store(true, Ordering::SeqCst);
        assert!(cleanup(&env).is_err());
        assert_eq!(workspace(&env).unwrap(), accepted);
        assert!(workspace(&env).unwrap().require_key_recipients().is_err());
        d.keychain.fail_deletes.store(false, Ordering::SeqCst);
        struct Retained<'a>(&'a dyn Keychain);
        impl Keychain for Retained<'_> {
            fn get(&self, key: &str) -> Result<Option<String>, AppError> {
                self.0.get(key)
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                panic!("cleanup cannot create credentials")
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
        }
        let retained = Retained(&d.keychain);
        assert!(cleanup(&SyncEnv {
            keychain: &retained,
            ..d.env()
        })
        .is_err());
        assert_eq!(workspace(&env).unwrap(), accepted);
        let directory = tempfile::tempdir().unwrap();
        assert!(cleanup(&SyncEnv {
            state_path: directory.path().to_path_buf(),
            ..d.env()
        })
        .is_err());
        let slot = before
            .control
            .profile
            .profile()
            .unwrap()
            .slot("recovery-intent");
        assert!(d.keychain.entry(&slot).is_none());
        assert_eq!(workspace(&env).unwrap(), accepted);
        cleanup(&env).unwrap();
        cleanup(&env).unwrap();
        workspace(&env).unwrap().require_key_recipients().unwrap();
        assert!(reveal(&env).is_err());
    }
    #[test]
    fn protected_orphan_pins_the_complete_epoch_prefix_as_well_as_the_content_checkpoint() {
        let (before, prepared, _, old) = super::super::recovery_state::tests::prepared(true);
        let d = TestDevice::new("protected-epoch", &FakeRelay::new(), &TestClock::new());
        let env = d.env();
        let probe = record_runtime::probe_startup(&env.state_path, "protected-epoch");
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
        record_runtime::mutate_records(&env, |state| {
            let mut next = state.clone();
            next.local.central = Some(before.clone());
            Ok(next)
        })
        .unwrap();
        stage(&env, &before, &prepared, &old).unwrap();
        let resumed = resume_orphan(&env, &before, &prepared.package.source_proof)
            .unwrap()
            .unwrap();
        assert_eq!(
            resumed.known.checkpoint,
            prepared.package.admission.checkpoint
        );
        resumed.prefix.verify(&prepared.package.epochs).unwrap();
        assert!(resumed.prefix.verify(&[]).is_err());
        let mut fork = prepared.package.epochs.clone();
        fork[0].signature = "AA==".into();
        assert!(resumed.prefix.verify(&fork).is_err());
    }
}

/// Secret inputs for one explicit revalidation. The future kit is always reused, never regenerated.
pub struct RebaseInputs {
    pub old_kit: RecoveryKit,
    pub seed: RecoverySeed,
    pub known: Admission,
    pub prefix: super::recovery_revalidation::EpochPrefix,
}
pub fn rebase_inputs(
    env: &SyncEnv,
    owner: &Workspace,
    source: &ControlProof,
    supplied: Option<&RecoveryKit>,
) -> Result<RebaseInputs, AppError> {
    let old = pending(owner)?;
    old.validate(owner)?;
    let profile = owner.control.profile.profile()?;
    let stored = load(env, owner)?.ok_or_else(invalid)?;
    if stored.operation != old.operation
        || stored.node.body.recovery != old.node.body.recovery
        || stored.admission.device != old.admission.device
        || stored.admission.anchor != old.admission.anchor
    {
        return Err(invalid());
    }
    source.verify(
        &old.admission.anchor,
        Some(
            &old.source_proof
                .verify(&old.admission.anchor, None)?
                .highwater(),
        ),
    )?;
    verify_staged_source(&stored, &profile, source)?;
    let old_kit = if let Some(supplied) = supplied {
        if supplied.anchor() != &old.admission.anchor {
            return Err(invalid());
        }
        RecoveryKit::parse(&supplied.encode_secret()?)?
    } else {
        RecoveryKit::parse(&stored.old_kit)?
    };
    old_kit.current_keys(&source.verify(&old.admission.anchor, None)?)?;
    Ok(RebaseInputs {
        old_kit,
        seed: RecoveryKit::parse(&stored.new_kit)?.resume_seed(&old.admission.anchor)?,
        known: stored.admission.clone(),
        prefix: stored.prefix(),
    })
}
/// The new package and the old Core snapshot are both part of the protected publication receipt.
pub struct RebasePermit {
    path: OwnerPath,
    locator: String,
    operation: String,
    before: String,
    after: String,
}
fn rebase_owner(owner: &Workspace, package: &Package) -> Workspace {
    let mut next = owner.clone();
    next.control.pending_request = package.node.body.enrollment.clone();
    next.control.auth_epoch = package.admission.authorization_epoch;
    next.control.phase = super::client_state::Phase::AwaitingApproval;
    next.recovery = Some(RecoveryState::Pending {
        package: Box::new(package.clone()),
    });
    next
}
pub fn stage_rebase(
    env: &SyncEnv,
    owner: &Workspace,
    prepared: &PreparedRecovery,
    old_kit: &RecoveryKit,
) -> Result<RebasePermit, AppError> {
    stage_rebase_at(env, &OwnerPath::Current, owner, prepared, old_kit)
}
pub(super) fn stage_rebase_at(
    env: &SyncEnv,
    path: &OwnerPath,
    owner: &Workspace,
    prepared: &PreparedRecovery,
    old_kit: &RecoveryKit,
) -> Result<RebasePermit, AppError> {
    if path.snapshot(env)? != *owner {
        return Err(crate::sync::runtime::superseded());
    }
    let old = pending(owner)?;
    let next = rebase_owner(owner, &prepared.package);
    owner.verify_transition(&next)?;
    let profile = owner.control.profile.profile()?;
    let prior = load(env, owner)?.ok_or_else(invalid)?;
    if prior.operation != old.operation
        || prior.admission.anchor != old.admission.anchor
        || prior.admission.device != old.admission.device
        || prior.node.body.recovery != old.node.body.recovery
        || prior.new_kit.as_str() != prepared.kit.encode_secret()?.as_str()
    {
        return Err(invalid());
    }
    verify_staged_source(&prior, &profile, &prepared.package.source_proof)?;
    prior.prefix().verify(&prepared.package.epochs)?;
    prepared
        .package
        .revalidation
        .as_ref()
        .ok_or_else(invalid)?
        .check_minimum(&prepared.package, &prior.admission.checkpoint)?;
    let stored = stored_for(&profile, &prepared.package, old_kit, &prepared.kit)?;
    let encoded = stored.encode()?;
    env.keychain.set(&slot(owner)?, &encoded)?;
    let checked = load(env, owner)?.ok_or_else(invalid)?;
    checked.verify_package(&profile, &prepared.package)?;
    if checked.encode()?.as_str() != encoded.as_str() {
        return Err(invalid());
    }
    Ok(RebasePermit {
        path: path.clone(),
        locator: profile.locator,
        operation: old.operation.clone(),
        before: digest(old)?,
        after: digest(&prepared.package)?,
    })
}
pub fn install_rebase(
    env: &SyncEnv,
    owner: &Workspace,
    package: &Package,
    permit: RebasePermit,
) -> Result<(), AppError> {
    install_rebase_at(env, &OwnerPath::Current, owner, package, permit)
}
pub(super) fn install_rebase_at(
    env: &SyncEnv,
    path: &OwnerPath,
    owner: &Workspace,
    package: &Package,
    permit: RebasePermit,
) -> Result<(), AppError> {
    let profile = owner.control.profile.profile()?;
    if &permit.path != path
        || permit.locator != profile.locator
        || permit.operation != package.operation
        || permit.before != digest(pending(owner)?)?
        || permit.after != digest(package)?
    {
        return Err(invalid());
    }
    load(env, owner)?
        .ok_or_else(invalid)?
        .verify_package(&profile, package)?;
    let next = rebase_owner(owner, package);
    owner.verify_transition(&next)?;
    path.publish(env, owner, &next)
}
