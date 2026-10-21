//! Explicit replacement preparation. No server authority or identity switch is granted here.
use super::{
    controller,
    credentials::DeviceIdentity,
    crypto,
    membership::Device,
    wire::{hex, invalid},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    TrustedDevice,
    RecoveryKit,
    SyncPassword,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub operation: String,
    pub route: Route,
    pub device: Option<Device>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<Box<Workspace>>,
    /// Retained when a submitted, backup-confirmed Pending journal becomes Accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_confirmation: Option<super::recovery_state::Admission>,
}
impl Intent {
    pub fn validate(&self, owner: &Workspace) -> Result<(), AppError> {
        if !hex(&self.operation, 32) || owner.identity_slot.as_ref() == Some(&self.operation) {
            return Err(invalid());
        }
        if let Some(target) = &self.device {
            target.keys.validate()?;
            if !hex(&target.id, 32)
                || target.id == owner.control.device.id
                || target.keys.signing == owner.control.device.keys.signing
                || target.keys.encryption == owner.control.device.keys.encryption
            {
                return Err(invalid());
            }
        }
        if let Some(candidate) = &self.candidate {
            // A staged owner cannot contain another intent, publish keys, or change the source root.
            if candidate.replacement.is_some()
                || !candidate.replacement_archives.is_empty()
                || candidate.identity_slot.as_ref() != Some(&self.operation)
                || self.device.as_ref() != Some(&candidate.control.device)
                || candidate.control.profile != owner.control.profile
                || candidate.control.account_id != owner.control.account_id
                || candidate.control.cutover
                || candidate.control.library.is_some()
                || candidate.bootstrap.is_some()
                || candidate.rotation.is_some()
                || candidate.replica.as_ref().is_some_and(|replica| {
                    !replica.pending.is_empty() || !replica.conflicts.is_empty()
                })
                || owner.control.anchor.as_ref().is_some_and(|anchor| {
                    candidate
                        .control
                        .anchor
                        .as_ref()
                        .is_some_and(|next| next != anchor)
                })
            {
                return Err(invalid());
            }
            candidate.validate()?;
            match (
                &self.route,
                &candidate.recovery,
                &self.recovery_confirmation,
            ) {
                (Route::TrustedDevice | Route::SyncPassword, None, None) => {}
                (Route::RecoveryKit, None, None) => {}
                (
                    Route::RecoveryKit,
                    Some(super::recovery_state::RecoveryState::Pending { package }),
                    None,
                ) => {
                    if package.operation != self.operation
                        || owner
                            .control
                            .anchor
                            .as_ref()
                            .is_some_and(|anchor| anchor != &package.admission.anchor)
                    {
                        return Err(invalid());
                    }
                }
                (
                    Route::RecoveryKit,
                    Some(super::recovery_state::RecoveryState::Accepted {
                        operation,
                        admission,
                        ..
                    }),
                    Some(confirmed),
                ) if operation == &self.operation && admission == confirmed => {}
                _ => return Err(invalid()),
            }
        } else if self.recovery_confirmation.is_some() {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn verify_transition(&self, next: Option<&Self>) -> Result<(), AppError> {
        let next = next.ok_or_else(invalid)?;
        if self.operation != next.operation
            || self.route != next.route
            || self.device.is_some() && self.device != next.device
        {
            return Err(invalid());
        }
        match (&self.candidate, &next.candidate) {
            (Some(before), Some(after)) => before.verify_transition(after)?,
            (Some(_), None) => return Err(invalid()),
            (None, Some(after)) => {
                if after.control.anchor.is_some()
                    || after.control.proof.is_some()
                    || after.replica.is_some()
                    || after.recovery.is_some()
                    || !after.epochs.is_empty()
                    || !after.observed_epochs.is_empty()
                    || !after.own_wraps.is_empty()
                    || !matches!(
                        after.control.phase,
                        super::client_state::Phase::Setup
                            | super::client_state::Phase::AwaitingApproval
                    )
                {
                    return Err(invalid());
                }
            }
            (None, None) => {}
        }
        if self.recovery_confirmation != next.recovery_confirmation {
            if self.recovery_confirmation.is_some() {
                return Err(invalid());
            }
            let Some(super::recovery_state::RecoveryState::Pending { package }) =
                self.candidate.as_ref().and_then(|c| c.recovery.as_ref())
            else {
                return Err(invalid());
            };
            if !package.backup_confirmed
                || !package.submitted
                || next.recovery_confirmation.as_ref() != Some(&package.admission)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn publish(env: &SyncEnv, before: &Workspace, next: &Workspace) -> Result<(), AppError> {
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut next_records = records.clone();
        next_records.local.central = Some(next.clone());
        Ok(next_records)
    })?;
    Ok(())
}
/// Native preparation only. A later explicit approval/recovery route owns server interaction.
/// Persist the operation BEFORE creating an independent protected identity; retain the old slot.
pub fn prepare(env: &SyncEnv, route: Route) -> Result<Intent, AppError> {
    controller::require_enabled()?;
    let _owner = env.runtime.lifecycle.lock().unwrap();
    let mut before = record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)?;
    if before.replacement.is_none() && env.runtime.central_recovery_read.lock().unwrap().is_some() {
        return Err(AppError::Other("Finish or pause the current recovery verification before replacing this device. Local data is retained.".into()));
    }
    if route == Route::SyncPassword {
        let session = controller::context(env)?;
        if session.profile != before.control.profile
            || session
                .tokens_started
                .elapsed()
                .saturating_add(std::time::Duration::from_secs(5))
                >= session.tokens.expires_in
        {
            return Err(AppError::Other(
                "Sign in again to reconnect this device.".into(),
            ));
        }
        if before.replacement.is_none()
            && before.control.phase != super::client_state::Phase::Revoked
            && before.control.anchor.is_some()
            && !session.device_access_denied
            && session
                .identity
                .as_ref()
                .is_some_and(|id| id.device() == before.control.device)
        {
            return Err(AppError::Other(
                "This device is already connected. Refresh sync status before reconnecting.".into(),
            ));
        }
        // Account login can resume the old public phase, never grant the old device access.
        // Its original identity, trust floors and outbox remain until typed publication.
        if before.control.phase == super::client_state::Phase::SignedOut {
            use super::client_state::Phase;
            let mut next = before.clone();
            next.control.phase = if before.control.anchor.is_some() {
                let chain = before.control.verified_chain()?;
                if before
                    .control
                    .denied_devices
                    .contains(&before.control.device.id)
                    || chain.current().devices().get(&before.control.device.id)
                        != Some(&before.control.device.keys)
                {
                    Phase::Revoked
                } else if before.control.cutover {
                    Phase::Active
                } else {
                    Phase::Enrolled
                }
            } else if before.control.pending_request.is_some() {
                Phase::AwaitingApproval
            } else {
                Phase::Setup
            };
            publish(env, &before, &next)?;
            before = next;
        }
    }
    if before.control.phase == super::client_state::Phase::SignedOut {
        return Err(AppError::Other(
            "Sign in before replacing this device. Local data is retained.".into(),
        ));
    }
    if (before.control.anchor.is_none() && super::recovery_credentials::has_intent(env, &before)?)
        || before.bootstrap.is_some()
        || before.recovery.as_ref().is_some_and(|r| {
            !matches!(
                r,
                super::recovery_state::RecoveryState::Accepted {
                    credentials_cleared: true,
                    ..
                }
            )
        })
    {
        return Err(AppError::Other("Finish the saved account setup or recovery before preparing device replacement. Local data is retained.".into()));
    }
    if let Some(intent) = &before.replacement {
        if intent.route != route {
            return Err(invalid());
        }
    } else {
        let mut next = before.clone();
        next.replacement = Some(Intent {
            operation: crypto::random_id(16)?,
            route,
            device: None,
            candidate: None,
            recovery_confirmation: None,
        });
        publish(env, &before, &next)?;
        before = next;
    }
    let intent = before.replacement.as_ref().ok_or_else(invalid)?;
    let profile = before.control.profile.profile()?;
    let identity = if intent.device.is_some() {
        DeviceIdentity::load_selected(env.keychain, &profile, Some(&intent.operation), true)?
    } else {
        DeviceIdentity::create_replacement(env.keychain, &profile, &intent.operation)?
    };
    let device = identity.device();
    if intent
        .device
        .as_ref()
        .is_some_and(|expected| expected != &device)
    {
        return Err(invalid());
    }
    let mut next = before.clone();
    next.replacement.as_mut().ok_or_else(invalid)?.device = Some(device);
    next.validate()?;
    if before != next {
        publish(env, &before, &next)?;
    }
    next.replacement.ok_or_else(invalid)
}

/// Caller owns the existing lifecycle gate and supplies its independently registered new session.
/// Initialize a staged owner only after exact protected selection/public-device readback.
pub(super) fn initialize_candidate(
    env: &SyncEnv,
    operation: &str,
    session: &super::controller::Session,
) -> Result<Workspace, AppError> {
    let source = record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)?;
    let intent = source.replacement.as_ref().ok_or_else(invalid)?;
    if intent.operation != operation {
        return Err(crate::sync::runtime::superseded());
    }
    let target = intent.device.as_ref().ok_or_else(invalid)?;
    let profile = source.control.profile.profile()?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let device = session.device.as_ref().ok_or_else(invalid)?;
    let stored = DeviceIdentity::load_selected(env.keychain, &profile, Some(operation), true)?;
    if session.device_access_denied
        || source.control.denied_devices.contains(&target.id)
        || session.profile != source.control.profile
        || &identity.device() != target
        || stored.device() != identity.device()
        || stored.credential() != identity.credential()
        || device.account_id != source.control.account_id
        || device.expired()
        || identity.slot(&profile, "device")? != profile.device_slot("device", Some(operation))?
    {
        return Err(invalid());
    }
    if let Some(candidate) = &intent.candidate {
        return Ok((**candidate).clone());
    }
    if device.device_state != super::api::DeviceState::Pending {
        return Err(invalid());
    }
    let mut candidate = Workspace::new(super::client_state::State::new(
        source.control.profile.clone(),
        source.control.account_id.clone(),
        identity.device(),
        device.auth_epoch,
    )?)?;
    candidate.identity_slot = Some(operation.into());
    candidate.validate()?;
    record_runtime::mutate_records(env, |records| {
        let mut next = records.clone();
        let current = next.local.central.as_mut().ok_or_else(invalid)?;
        if current != &source {
            return Err(crate::sync::runtime::superseded());
        }
        current.replacement.as_mut().ok_or_else(invalid)?.candidate =
            Some(Box::new(candidate.clone()));
        Ok(next)
    })?;
    Ok(candidate)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        env::Keychain,
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    fn source() -> TestDevice {
        let d = TestDevice::new("replacement", &FakeRelay::new(), &TestClock::new());
        let env = d.env();
        let probe = record_runtime::probe_startup(&env.state_path, "replacement");
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
        record_runtime::mutate_records(&env, |records| {
            let mut next = records.clone();
            next.local.central = Some(super::super::workspace::tests::enrolled());
            Ok(next)
        })
        .unwrap();
        d
    }
    #[test]
    fn durable_operation_precedes_protected_creation_and_retry_preserves_old_identity_and_local_b()
    {
        let d = source();
        let env = d.env();
        let before = record_runtime::snapshot(&env).unwrap().0;
        let owner = before.local.central.as_ref().unwrap();
        let profile = owner.control.profile.profile().unwrap();
        d.keychain
            .set(&profile.slot("device"), "retained-unreadable-original")
            .unwrap();
        struct CheckOrder<'a> {
            d: &'a TestDevice,
            original: String,
        }
        impl Keychain for CheckOrder<'_> {
            fn get(&self, key: &str) -> Result<Option<String>, AppError> {
                assert_ne!(key, self.original);
                self.d.keychain.get(key)
            }
            fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
                assert_ne!(key, self.original);
                let public = record_runtime::snapshot(&self.d.env())?.0;
                let intent = public
                    .local
                    .central
                    .as_ref()
                    .unwrap()
                    .replacement
                    .as_ref()
                    .unwrap();
                assert!(intent.device.is_none());
                self.d.keychain.set(key, value)?;
                record_runtime::mutate_records(&self.d.env(), |records| {
                    let mut next = records.clone();
                    next.device_name = "local-B-during-protected-write".into();
                    Ok(next)
                })?;
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("preparation never deletes credentials")
            }
        }
        let checked = CheckOrder {
            d: &d,
            original: profile.slot("device"),
        };
        let intent = prepare(
            &SyncEnv {
                keychain: &checked,
                ..d.env()
            },
            Route::RecoveryKit,
        )
        .unwrap();
        assert_eq!(prepare(&env, Route::RecoveryKit).unwrap(), intent);
        let after = record_runtime::snapshot(&env).unwrap().0;
        assert_eq!(after.device_name, "local-B-during-protected-write");
        let ws = after.local.central.as_ref().unwrap();
        assert_eq!(owner.control, ws.control);
        assert_eq!(owner.replica, ws.replica);
        assert_eq!(owner.epochs, ws.epochs);
        assert_eq!(owner.own_wraps, ws.own_wraps);
        assert_eq!(
            d.keychain.entry(&profile.slot("device")).as_deref(),
            Some("retained-unreadable-original")
        );
        assert!(!ws.can_upload());
        assert!(ws.require_key_recipients().is_err());
        let selected =
            DeviceIdentity::load_selected(&d.keychain, &profile, Some(&intent.operation), true)
                .unwrap();
        assert_eq!(intent.device.as_ref(), Some(&selected.device()));
        let encoded = serde_json::to_string(&after).unwrap();
        assert!(!encoded.contains(selected.credential()));
        assert!(!encoded.contains(&*selected.keys.encode_secret()));
        assert!(prepare(&env, Route::TrustedDevice).is_err());
    }
    #[test]
    fn lost_target_core_save_resumes_the_same_protected_identity_and_never_recreates_a_known_missing_target(
    ) {
        let d = source();
        let env = d.env();
        let profile = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap()
            .control
            .profile
            .profile()
            .unwrap();
        struct LoseCore<'a> {
            d: &'a TestDevice,
            retained: std::path::PathBuf,
        }
        impl Keychain for LoseCore<'_> {
            fn get(&self, key: &str) -> Result<Option<String>, AppError> {
                self.d.keychain.get(key)
            }
            fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
                self.d.keychain.set(key, value)?;
                std::fs::rename(&self.d.env().state_path, &self.retained)?;
                std::fs::create_dir(&self.d.env().state_path)?;
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("no credential deletion")
            }
        }
        let retained = env.state_path.with_extension("before-replacement-target");
        let failing = LoseCore {
            d: &d,
            retained: retained.clone(),
        };
        assert!(prepare(
            &SyncEnv {
                keychain: &failing,
                ..d.env()
            },
            Route::TrustedDevice
        )
        .is_err());
        let owner = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        let pending = owner.replacement.as_ref().unwrap();
        assert!(pending.device.is_none());
        let secret =
            DeviceIdentity::load_selected(&d.keychain, &profile, Some(&pending.operation), true)
                .unwrap();
        std::fs::remove_dir(&env.state_path).unwrap();
        std::fs::rename(retained, &env.state_path).unwrap();
        let intent = prepare(&env, Route::TrustedDevice).unwrap();
        assert_eq!(intent.device.as_ref(), Some(&secret.device()));
        let slot = profile.slot(&format!("device-replacement-{}", intent.operation));
        d.keychain.delete(&slot).unwrap();
        let before = record_runtime::snapshot(&env).unwrap();
        assert!(prepare(&env, Route::TrustedDevice).is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        assert!(d.keychain.entry(&slot).is_none());
    }
    #[test]
    fn uncertain_protected_readback_retains_the_operation_and_resumes_the_written_identity() {
        let d = source();
        let env = d.env();
        struct Lost<'a>(&'a dyn Keychain);
        impl Keychain for Lost<'_> {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(None)
            }
            fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
                self.0.set(key, value)
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("no deletion")
            }
        }
        let lost = Lost(&d.keychain);
        assert!(prepare(
            &SyncEnv {
                keychain: &lost,
                ..d.env()
            },
            Route::RecoveryKit
        )
        .is_err());
        let owner = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        let intent = owner.replacement.as_ref().unwrap();
        assert!(intent.device.is_none());
        let profile = owner.control.profile.profile().unwrap();
        let saved =
            DeviceIdentity::load_selected(&d.keychain, &profile, Some(&intent.operation), true)
                .unwrap();
        assert_eq!(
            prepare(&env, Route::RecoveryKit).unwrap().device,
            Some(saved.device())
        );
    }
    #[test]
    fn failed_intent_or_protected_writes_cannot_change_identity_or_erase_replacement_metadata() {
        let d = source();
        let env = d.env();
        let before = record_runtime::snapshot(&env).unwrap();
        struct Denied;
        impl Keychain for Denied {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(None)
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                Err(invalid())
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("no deletion")
            }
        }
        struct Never;
        impl Keychain for Never {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> {
                panic!("failed Core intent must precede any credential access")
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                panic!("failed Core intent must precede credential creation")
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("no deletion")
            }
        }
        let directory = tempfile::tempdir().unwrap();
        assert!(prepare(
            &SyncEnv {
                state_path: directory.path().to_path_buf(),
                keychain: &Never,
                ..d.env()
            },
            Route::RecoveryKit
        )
        .is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        assert!(prepare(
            &SyncEnv {
                keychain: &Denied,
                ..d.env()
            },
            Route::RecoveryKit
        )
        .is_err());
        let retained = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        assert!(retained.replacement.as_ref().unwrap().device.is_none());
        let prepared = prepare(&env, Route::RecoveryKit).unwrap();
        let owner = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        for mutation in 0..5 {
            let mut next = owner.clone();
            match mutation {
                0 => next.replacement = None,
                1 => next.replacement.as_mut().unwrap().operation = "a".repeat(32),
                2 => next.replacement.as_mut().unwrap().route = Route::TrustedDevice,
                3 => next.replacement.as_mut().unwrap().device = None,
                _ => next.identity_slot = Some(prepared.operation.clone()),
            }
            assert!(owner.verify_transition(&next).is_err());
        }
        assert!(super::super::workspace::verify_publication(Some(&owner), None).is_err());
        assert!(super::super::workspace::verify_publication(None, Some(&owner)).is_err());
        let mut next = owner.clone();
        next.identity_slot = Some("../../other".into());
        assert!(next.validate().is_err());
        let probe = record_runtime::probe_startup(&env.state_path, "replacement");
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
        assert_eq!(
            record_runtime::snapshot(&env)
                .unwrap()
                .0
                .local
                .central
                .as_ref(),
            Some(&owner)
        );
    }
}
