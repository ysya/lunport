//! Continuity checks for a replacement's completed, native-only recovery read.
//! These checks grant neither a device switch nor a Core publication permit.
use super::{
    recovery_read::VerifiedRecovery,
    recovery_revalidation::{finish_bridge, Bridge},
    rekey::Checkpoint,
    replacement::Route,
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::error::AppError;

fn minimum(owner: &Workspace) -> Result<Option<(Checkpoint, String, u64)>, AppError> {
    if let Some(replica) = &owner.replica {
        return Ok(Some((
            replica.checkpoint.clone(),
            replica.creation_head.clone(),
            replica.creation_authorization_epoch,
        )));
    }
    if let Some(approval) = &owner.control.pairing_confirmation {
        let minimum = approval
            .minimums
            .iter()
            .find(|m| m.vault == approval.personal_vault)
            .ok_or_else(invalid)?;
        return Ok(Some((
            Checkpoint {
                epoch: number(&minimum.key_epoch, false)?,
                sequence: number(&minimum.sequence, true)?,
                history_hash: minimum.history_hash.clone(),
            },
            minimum.creation_head.clone(),
            number(&minimum.creation_authorization_epoch, false)?,
        )));
    }
    Ok(None)
}
/// Check the old owner's strongest known floor against a completed fresh-target read.
/// Every cross-epoch source suffix remains bounded; the final coordinate must have been
/// verified by the reader itself, not merely advertised by the service.
pub(super) fn recovery_read(
    owner: &Workspace,
    read: &VerifiedRecovery,
    bridges: &[Bridge],
) -> Result<(), AppError> {
    owner.validate()?;
    let intent = owner.replacement.as_ref().ok_or_else(invalid)?;
    if intent.route != Route::RecoveryKit
        || intent.device.as_ref() != Some(&read.request().device)
        || owner.control.device == read.request().device
        || owner.control.profile != read.previous_owner().control.profile
        || owner.control.account_id != read.previous_owner().control.account_id
        || read.auth_epoch() < owner.control.auth_epoch
        || owner
            .control
            .denied_devices
            .contains(&read.request().device.id)
        || !read.epochs().starts_with(&owner.epochs)
        || !read.epochs().starts_with(&owner.observed_epochs)
        || bridges.len() > 64
    {
        return Err(invalid());
    }
    if let Some(anchor) = &owner.control.anchor {
        if anchor != read.chain().current().anchor() {
            return Err(invalid());
        }
        read.proof()
            .verify(anchor, owner.control.highwater.as_ref())?;
    }
    if let Some(vault) = &owner.control.personal_vault {
        if vault != &read.replica().vault {
            return Err(invalid());
        }
    }
    let Some((mut known, creation, authorization)) = minimum(owner)? else {
        return if bridges.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        };
    };
    if creation != read.replica().creation_head
        || authorization != read.replica().creation_authorization_epoch
        || known.epoch > read.checkpoint().epoch
        || bridges.len() as u64 != read.checkpoint().epoch - known.epoch
    {
        return Err(invalid());
    }
    let mut count = 0usize;
    for bridge in bridges {
        count = count
            .checked_add(bridge.digests.len())
            .ok_or_else(invalid)?;
        if count > 16384 {
            return Err(invalid());
        }
        known = finish_bridge(
            read.chain(),
            &read.replica().vault,
            read.epochs(),
            &known,
            bridge,
        )?;
    }
    if !read.verifies_prefix(&known) {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_recovery_keeps_a_pinned_same_epoch_or_bridged_original_minimum() {
        for rotated in [false, true] {
            let (source, read, bridges) =
                super::super::recovery_read::tests::replacement_fixture(rotated, true);
            recovery_read(&source, &read, &bridges).unwrap();
            if rotated {
                assert!(recovery_read(&source, &read, &[]).is_err());
                let mut changed = bridges.clone();
                changed[0].digests[0].digest = "f".repeat(64);
                assert!(recovery_read(&source, &read, &changed).is_err());
            }
        }
        let (source, read, bridges) =
            super::super::recovery_read::tests::replacement_fixture(false, false);
        assert!(recovery_read(&source, &read, &bridges).is_err());
    }
    #[test]
    fn replacement_read_rejects_an_unrelated_target_route_profile_root_or_stronger_source_floor() {
        let (original, read, bridges) =
            super::super::recovery_read::tests::replacement_fixture(false, true);
        let (mut other_root, _, _) =
            super::super::recovery_read::tests::replacement_fixture(false, true);
        other_root.replacement.as_mut().unwrap().device = Some(read.request().device.clone());
        other_root.validate().unwrap();
        assert_eq!(other_root.control.profile, original.control.profile);
        assert_ne!(other_root.control.anchor, original.control.anchor);
        assert!(recovery_read(&other_root, &read, &bridges).is_err());
        for mutation in 0..6 {
            let mut source = original.clone();
            match mutation {
                0 => source.replacement.as_mut().unwrap().device = None,
                1 => source.replacement.as_mut().unwrap().route = Route::TrustedDevice,
                2 => source
                    .control
                    .denied_devices
                    .insert(read.request().device.id.clone())
                    .then_some(())
                    .unwrap(),
                3 => source.control.profile.oidc.client_id = "other-client".into(),
                4 => source.control.auth_epoch = read.auth_epoch() + 1,
                _ => source.replica.as_mut().unwrap().checkpoint.history_hash = "f".repeat(64),
            }
            assert!(recovery_read(&source, &read, &bridges).is_err());
        }
    }
}
