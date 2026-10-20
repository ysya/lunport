//! Capture every supported historical image before the old selected identity can disappear.
//! The resulting groups are logical content only, signed/encrypted by the replacement archive.
use super::super::{credentials::DeviceIdentity, inventory_keys::Capture};
use super::*;
use crate::sync::env::NonInteractiveKeychain;
impl Package {
    #[inline(never)]
    pub(in crate::sync::central) fn replacement_history_groups(
        env: &SyncEnv,
        expected: &SyncStateV3,
    ) -> Result<Vec<snapshot::Group>, AppError> {
        let name = env
            .state_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(invalid)?;
        let files = Files::capture(env, expected.legacy_v1_backup.as_deref())?;
        if state(&files, name)? != *expected {
            return Err(crate::sync::runtime::superseded());
        }
        let readonly = NonInteractiveKeychain(env.keychain);
        let observer = Capture::new(&readonly);
        let sources = if super::super::historical_state::projected(expected) {
            legacy_book::historical(expected, &files, &observer)?
        } else {
            let mut account = crate::sync::record_runtime::read_account_keys(expected, &readonly)?;
            let result = Sources::discover(expected, account.as_ref());
            if let Some(keys) = &mut account {
                keys.clear_sensitive();
            }
            result?
        };
        // Observe only the already supported archive/Vault decryptors. Device identities are
        // deliberately read separately and can never enter the serialized decryptor snapshot.
        super::super::migration_materials::observe_vault_images(&files, &observer)?;
        drop(super::super::replacement_archive::captured::read_all(
            &files.bytes,
            &observer,
        )?);
        drop(source_archive::captured::read_all(&files.bytes, &observer)?);
        let decryptors = observer.finish()?;
        let package = Box::new(Self {
            state_name: name.into(),
            state: expected.clone(),
            files,
            sources,
            decryptors,
            frozen: None,
            snapshot: None,
            inherited: vec![],
        });
        let identities = |owner: &Workspace| {
            DeviceIdentity::load_selected(
                &readonly,
                &owner.control.profile.profile()?,
                owner.identity_slot.as_deref(),
                false,
            )
        };
        let (_, mut groups) = package.retained_packages_inner(Some(&identities))?;
        if !groups.iter().any(|g| g.require_state(expected).is_ok()) {
            let owner = expected.local.central.as_ref().ok_or_else(invalid)?;
            let captured = if super::super::replacement_reconciliation::projected(expected) {
                super::super::replacement_reconciliation::capture_projected(
                    expected,
                    &package.files.bytes,
                    &package.decryptors,
                    &identities,
                )?
            } else {
                super::super::historical_state::read(expected, &identities(owner)?)?
            };
            groups.push(snapshot::Group::state_captured(expected, captured)?);
        }
        package
            .files
            .require_unchanged(env, expected.legacy_v1_backup.as_deref())?;
        Ok(groups)
    }
}
