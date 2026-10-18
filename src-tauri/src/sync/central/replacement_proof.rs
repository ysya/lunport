//! Continuity checks for a replacement's completed, native-only recovery read.
//! These checks grant neither a device switch nor a Core publication permit.
use super::{
    recovery_read::VerifiedRecovery,
    recovery_revalidation::{finish_bridge, Bridge},
    rekey::{Checkpoint, SignedRekey},
    replacement::Route,
    trust::VerifiedChain,
    wire::{hex, invalid, number},
    workspace::Workspace,
};
use crate::error::AppError;

pub(super) fn minimums(
    owner: &Workspace,
) -> Result<Option<(Vec<Checkpoint>, String, u64)>, AppError> {
    if let Some(replica) = &owner.replica {
        let mut floors = vec![replica.checkpoint.clone()];
        if let Some(minimum) = &replica.minimum {
            if minimum.sequence > replica.checkpoint.sequence {
                floors.push(minimum.clone());
            }
        }
        return Ok(Some((
            floors,
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
            vec![Checkpoint {
                epoch: number(&minimum.key_epoch, false)?,
                sequence: number(&minimum.sequence, true)?,
                history_hash: minimum.history_hash.clone(),
            }],
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
    if owner
        .replacement
        .as_ref()
        .is_none_or(|i| i.route != Route::RecoveryKit)
    {
        return Err(invalid());
    }
    for minimum in prefixes(
        owner,
        View {
            before: read.previous_owner(),
            chain: read.chain(),
            proof: read.proof(),
            auth_epoch: read.auth_epoch(),
            checkpoint: read.checkpoint(),
            epochs: read.epochs(),
            replica: read.replica(),
        },
        bridges,
    )? {
        if !read.verifies_prefix(&minimum) {
            return Err(invalid());
        }
    }
    Ok(())
}
struct View<'a> {
    before: &'a Workspace,
    chain: &'a VerifiedChain,
    proof: &'a super::trust::ControlProof,
    auth_epoch: u64,
    checkpoint: &'a Checkpoint,
    epochs: &'a [SignedRekey],
    replica: &'a super::replica::Replica,
}
fn prefixes(
    owner: &Workspace,
    read: View<'_>,
    bridges: &[Bridge],
) -> Result<Vec<Checkpoint>, AppError> {
    owner.validate()?;
    let intent = owner.replacement.as_ref().ok_or_else(invalid)?;
    let target = &read.before.control.device;
    if intent.device.as_ref() != Some(target)
        || &owner.control.device == target
        || owner.control.profile != read.before.control.profile
        || owner.control.account_id != read.before.control.account_id
        || read.auth_epoch < owner.control.auth_epoch
        || owner.control.denied_devices.contains(&target.id)
        || !read.epochs.starts_with(&owner.epochs)
        || !read.epochs.starts_with(&owner.observed_epochs)
        || bridges.len() > 64
    {
        return Err(invalid());
    }
    if let Some(anchor) = &owner.control.anchor {
        if anchor != read.chain.current().anchor() {
            return Err(invalid());
        }
        read.proof
            .verify(anchor, owner.control.highwater.as_ref())?;
    }
    if owner
        .control
        .personal_vault
        .as_ref()
        .is_some_and(|vault| vault != &read.replica.vault)
    {
        return Err(invalid());
    }
    let Some((floors, creation, authorization)) = minimums(owner)? else {
        return if bridges.is_empty() {
            Ok(vec![])
        } else {
            Err(invalid())
        };
    };
    if creation != read.replica.creation_head
        || authorization != read.replica.creation_authorization_epoch
    {
        return Err(invalid());
    }
    extend_minimums(
        read.chain,
        &read.replica.vault,
        read.epochs,
        &floors,
        bridges,
        read.checkpoint.epoch,
    )
}
/// Add original-owner minima before the first active-target page. Existing target minima stay pinned.
pub(super) fn pin_active_read(
    owner: &Workspace,
    read: &mut super::active_read::ReadSession,
    bridges: &[Bridge],
) -> Result<(), AppError> {
    if read.previous_owner().identity_slot.as_ref()
        != owner.replacement.as_ref().map(|i| &i.operation)
    {
        return Err(invalid());
    }
    let minimums = prefixes(
        owner,
        View {
            before: read.previous_owner(),
            chain: read.chain(),
            proof: read.proof(),
            auth_epoch: read.auth_epoch(),
            checkpoint: read.checkpoint(),
            epochs: read.epochs(),
            replica: read.replica(),
        },
        bridges,
    )?;
    read.pin_prefixes(minimums)
}
/// Recheck the latest original owner immediately before authorization/archive publication.
pub(super) fn active_read(
    owner: &Workspace,
    read: &super::active_read::VerifiedLibrary,
    bridges: &[Bridge],
) -> Result<(), AppError> {
    if read.previous_owner().identity_slot.as_ref()
        != owner.replacement.as_ref().map(|i| &i.operation)
    {
        return Err(invalid());
    }
    for minimum in prefixes(
        owner,
        View {
            before: read.previous_owner(),
            chain: read.chain(),
            proof: read.proof(),
            auth_epoch: read.auth_epoch(),
            checkpoint: read.checkpoint(),
            epochs: read.epochs(),
            replica: read.replica(),
        },
        bridges,
    )? {
        if !read.verifies_prefix(&minimum) {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Extend every independently known prefix, including a higher unread OOB minimum.
pub(super) fn extend_minimums(
    chain: &VerifiedChain,
    vault: &str,
    epochs: &[SignedRekey],
    floors: &[Checkpoint],
    bridges: &[Bridge],
    target_epoch: u64,
) -> Result<Vec<Checkpoint>, AppError> {
    if floors.is_empty()
        || floors.len() > 2
        || bridges.len() > 64
        || !(1..=65).contains(&target_epoch)
    {
        return Err(invalid());
    }
    let count = bridges.iter().try_fold(0usize, |count, b| {
        count.checked_add(b.digests.len()).ok_or_else(invalid)
    })?;
    if count > 16384 {
        return Err(invalid());
    }
    let mut minimums = vec![];
    for (index, floor) in floors.iter().enumerate() {
        if index > 0 && (floor.epoch != floors[0].epoch || floor.sequence <= floors[0].sequence) {
            return Err(invalid());
        }
        let mut known = floor.clone();
        if known.epoch > target_epoch || bridges.len() as u64 != target_epoch - known.epoch {
            return Err(invalid());
        }
        for bridge in bridges {
            // One bounded proof may begin before this reader's floor so the same collected
            // source digests can serve both the target and the original owner.
            let mut digests = vec![];
            let mut previous = 0;
            for row in &bridge.digests {
                let sequence = number(&row.sequence, false)?;
                if sequence <= previous || !hex(&row.digest, 64) {
                    return Err(invalid());
                }
                previous = sequence;
                if sequence > known.sequence {
                    digests.push(row.clone());
                }
            }
            known = finish_bridge(
                chain,
                vault,
                epochs,
                &known,
                &Bridge {
                    epoch: bridge.epoch,
                    digests,
                },
            )?;
        }
        if !minimums.contains(&known) {
            minimums.push(known);
        }
    }
    Ok(minimums)
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
    fn an_unread_approval_minimum_does_not_erase_the_already_verified_partial_checkpoint() {
        let (mut source, read, bridges) =
            super::super::recovery_read::tests::replacement_fixture(false, true);
        source.replica.as_mut().unwrap().minimum = Some(read.checkpoint().clone());
        source.validate().unwrap();
        recovery_read(&source, &read, &bridges).unwrap();
        source
            .replica
            .as_mut()
            .unwrap()
            .minimum
            .as_mut()
            .unwrap()
            .history_hash = "f".repeat(64);
        source.validate().unwrap();
        assert!(recovery_read(&source, &read, &bridges).is_err());
        let (mut source, read, bridges) =
            super::super::recovery_read::tests::replacement_fixture(false, false);
        source.replica.as_mut().unwrap().minimum = Some(read.checkpoint().clone());
        source.validate().unwrap();
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
