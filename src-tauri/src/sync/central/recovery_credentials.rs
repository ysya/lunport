//! Temporary recovery authority storage. Exact protected readback precedes Core publication.
//! The compact intent excludes the potentially large ciphertext cache and membership history.
use super::{
    bootstrap::RecoveryReveal,
    credentials::Profile,
    crypto,
    membership::SignedMembership,
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
        if self.version != 1
            || self.locator != profile.locator
            || self.admission.anchor.origin != profile.origin
            || !super::wire::hex(&self.operation, 32)
        {
            return Err(invalid());
        }
        Ok(())
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
        self.verify_proof(profile, &package.proof())
    }
}
fn load(env: &SyncEnv, profile: &Profile) -> Result<Option<Stored>, AppError> {
    env.keychain
        .get(&profile.slot("recovery-intent"))?
        .map(|value| {
            let encoded = Zeroizing::new(value);
            if encoded.len() > CAP {
                return Err(invalid());
            }
            let stored: Stored = serde_json::from_str(&encoded).map_err(|_| invalid())?;
            stored.scope(profile)?;
            Ok(stored)
        })
        .transpose()
}
fn digest(package: &Package) -> Result<String, AppError> {
    Ok(crypto::hash(
        &serde_json::to_vec(package).map_err(|_| invalid())?,
    ))
}
/// No Serialize/Clone. Only successful protected readback mints a publication permit.
pub struct Permit {
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
    if before.recovery.is_some() {
        return Err(invalid());
    }
    if record_runtime::snapshot(env)?.0.local.central.as_ref() != Some(before) {
        return Err(crate::sync::runtime::superseded());
    }
    prepared.package.validate(before)?;
    let profile = before.control.profile.profile()?;
    let stored = Stored {
        version: 1,
        locator: profile.locator.clone(),
        operation: prepared.package.operation.clone(),
        admission: prepared.package.admission.clone(),
        node: prepared.package.node.clone(),
        old_kit: old_kit.encode_secret()?,
        new_kit: prepared.kit.encode_secret()?,
    };
    stored.verify_package(&profile, &prepared.package)?;
    if let Some(previous) = load(env, &profile)? {
        if previous.operation != stored.operation
            || previous.old_kit.as_str() != stored.old_kit.as_str()
            || previous.new_kit.as_str() != stored.new_kit.as_str()
        {
            return Err(AppError::Other(
                "Existing recovery credentials are retained. Resume that recovery operation first."
                    .into(),
            ));
        }
    }
    let encoded = stored.encode()?;
    env.keychain
        .set(&profile.slot("recovery-intent"), &encoded)?;
    let checked = load(env, &profile)?.ok_or_else(invalid)?;
    checked.verify_package(&profile, &prepared.package)?;
    if checked.encode()?.as_str() != encoded.as_str() {
        return Err(invalid());
    }
    Ok(Permit {
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
    let profile = before.control.profile.profile()?;
    if permit.locator != profile.locator
        || permit.operation != package.operation
        || permit.digest != digest(package)?
        || before.recovery.is_some()
    {
        return Err(invalid());
    }
    package.validate(before)?;
    load(env, &profile)?
        .ok_or_else(invalid)?
        .verify_package(&profile, package)?;
    let mut next = before.clone();
    next.recovery = Some(RecoveryState::Pending {
        package: Box::new(package.clone()),
    });
    publish(env, before, &next)
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
    let before = workspace(env)?;
    let package = pending(&before)?;
    let profile = before.control.profile.profile()?;
    let stored = load(env, &profile)?.ok_or_else(invalid)?;
    stored.verify_package(&profile, package)?;
    Ok(RecoveryReveal {
        root: package.admission.anchor.genesis_hash.clone(),
        kit: stored.new_kit.to_string(),
    })
}
pub fn confirm_backup(env: &SyncEnv, operation: &str) -> Result<(), AppError> {
    let before = workspace(env)?;
    let package = pending(&before)?;
    if package.operation != operation {
        return Err(invalid());
    }
    load(env, &before.control.profile.profile()?)?
        .ok_or_else(invalid)?
        .verify_package(&before.control.profile.profile()?, package)?;
    let mut next = before.clone();
    match next.recovery.as_mut() {
        Some(RecoveryState::Pending { package }) => package.backup_confirmed = true,
        _ => return Err(invalid()),
    }
    publish(env, &before, &next)
}
pub fn verify_pending(env: &SyncEnv, owner: &Workspace) -> Result<(), AppError> {
    let package = pending(owner)?;
    let profile = owner.control.profile.profile()?;
    match load(env, &profile)? {
        Some(stored) => stored.verify_package(&profile, package),
        None if package.submitted && package.backup_confirmed => Ok(()),
        None => Err(invalid()),
    }
}
/// Foreground only. Missing-after-delete is an exact retry; failed deletion/readback keeps writes gated.
pub fn cleanup(env: &SyncEnv) -> Result<(), AppError> {
    let before = workspace(env)?;
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
    if let Some(stored) = load(env, &profile)? {
        if &stored.admission != admission
            || before
                .recovery
                .as_ref()
                .is_none_or(|r| r.operation() != stored.operation)
        {
            return Err(invalid());
        }
        stored.verify_proof(&profile, before.control.proof.as_ref().ok_or_else(invalid)?)?;
        env.keychain.delete(&profile.slot("recovery-intent"))?;
        if env
            .keychain
            .get(&profile.slot("recovery-intent"))?
            .is_some()
        {
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
    publish(env, &before, &next)
}
/// A crash before Core publication may leave compact protected secrets. Re-read all ciphertext
/// before building a fresh journal, while retaining the same new kit and operation identity.
pub struct Orphan {
    pub old_kit: RecoveryKit,
    pub seed: RecoverySeed,
    pub operation: String,
}
pub fn resume_orphan(
    env: &SyncEnv,
    before: &Workspace,
    current_proof: &ControlProof,
) -> Result<Option<Orphan>, AppError> {
    if before.recovery.is_some() || before.control.anchor.is_some() {
        return Err(invalid());
    }
    let profile = before.control.profile.profile()?;
    let Some(stored) = load(env, &profile)? else {
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
    let old_kit = RecoveryKit::parse(&stored.old_kit)?;
    old_kit.current_keys(&current_proof.verify(old_kit.anchor(), None)?)?;
    Ok(Some(Orphan {
        old_kit,
        seed: RecoveryKit::parse(&stored.new_kit)?.resume_seed(&stored.admission.anchor)?,
        operation: stored.operation.clone(),
    }))
}

/// A protected orphan also reserves this account's recovery path after a failed Core write.
/// Ordinary login/pairing may retain access, but cannot bypass this pending recovery intent.
pub fn has_intent(env: &SyncEnv, owner: &Workspace) -> Result<bool, AppError> {
    let Some(stored) = load(env, &owner.control.profile.profile()?)? else {
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
        assert!(!super::super::controller::session_epoch_matches(
            &before.control,
            before.control.auth_epoch + 1,
            super::super::api::DeviceState::Pending
        ));
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
}
