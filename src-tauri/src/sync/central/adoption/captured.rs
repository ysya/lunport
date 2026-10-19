//! Ephemeral verification only. No saved adoption State, consent, key retention or publication.
use super::super::{
    active_read::VerifiedLibrary, credentials::DeviceIdentity, migration_library::History, payload,
};
use super::*;
use std::collections::BTreeSet;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct ControlMinimum {
    pub highwater: super::super::trust::Highwater,
    pub auth_epoch: u64,
}
pub(in crate::sync::central) struct Captured {
    pub package: Package,
    pub history: History,
    pub floors: Vec<Checkpoint>,
    pub controls: Vec<ControlMinimum>,
    pub admitted: BTreeSet<String>,
}
fn retain(
    history: &mut History,
    read: &VerifiedLibrary,
    rows: impl IntoIterator<Item = super::super::crypto::RecordEnvelope>,
) -> Result<(), AppError> {
    for row in rows {
        let author = read
            .chain()
            .author_at(&row.header.membership_head, &row.header.author)
            .ok_or_else(invalid)?;
        let plain = row.verify(&author.signing)?.open(read.keys())?;
        let admitted = payload::admit(read.keys(), &row.header, &plain)?;
        history.push_retained(admitted.identity, admitted.data)?;
    }
    Ok(())
}
fn transcript(
    history: &mut History,
    floors: &mut Vec<Checkpoint>,
    controls: &mut Vec<ControlMinimum>,
    owner: &Workspace,
    identity: &DeviceIdentity,
    value: &Transcript,
    floor: Option<&Checkpoint>,
) -> Result<VerifiedLibrary, AppError> {
    let read = value.verify(owner, identity, floor)?;
    if read.phase() != "ready" || read.checkpoint().sequence == 0 {
        return Err(invalid());
    }
    retain(
        history,
        &read,
        value
            .pages
            .iter()
            .flat_map(|p| p.records.iter().map(|row| row.envelope.clone())),
    )?;
    floors.push(read.checkpoint().clone());
    controls.push(ControlMinimum {
        highwater: read.chain().highwater(),
        auth_epoch: read.auth_epoch(),
    });
    Ok(read)
}
pub(in crate::sync::central) fn source(bytes: &[u8]) -> Result<Option<Receipt>, AppError> {
    if !bytes.starts_with(MAGIC) {
        return Ok(None);
    }
    let value = super::frame(bytes)?;
    value.source.validate()?;
    Ok(Some(value.source))
}
/// The caller must obtain every frame from the descriptor-captured, AEAD-verified source reader.
/// This value must never substitute for a fresh current-device read or a migration permit.
pub(in crate::sync::central) fn read_group(
    source: &Receipt,
    frames: &[(Receipt, Zeroizing<Vec<u8>>)],
    identity: &DeviceIdentity,
) -> Result<Captured, AppError> {
    let (_, bytes) = frames
        .iter()
        .find(|(receipt, _)| receipt == source)
        .ok_or_else(invalid)?;
    let package = Package::decode_local(bytes)?;
    read_prepared_group(source, frames, identity, package)
}
/// The prepared source may inherit only fully checked logical proofs from its enclosing graph.
/// Its original state/files/keybook/frozen inputs must still exactly match the authenticated frame.
pub(in crate::sync::central) fn read_prepared_group(
    source: &Receipt,
    frames: &[(Receipt, Zeroizing<Vec<u8>>)],
    identity: &DeviceIdentity,
    package: Package,
) -> Result<Captured, AppError> {
    let (_, bytes) = frames
        .iter()
        .find(|(r, _)| r == source)
        .ok_or_else(invalid)?;
    package.require_captured_inputs(&Package::decode_local(bytes)?)?;
    let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
    source.matches_selected(owner)?;
    if identity.device() != owner.control.device {
        return Err(invalid());
    }
    let mut selected = vec![];
    for (receipt, bytes) in frames {
        if !bytes.starts_with(MAGIC) {
            continue;
        }
        let frame = super::frame(bytes)?;
        frame.source.validate()?;
        if frame.source != *source {
            if receipt.operation() == source.operation() {
                return Err(invalid());
            }
            continue;
        }
        receipt.matches_selected(owner)?;
        selected.push((receipt.next_ordinal()?, receipt, frame));
    }
    if selected.is_empty() || selected.len() > 8 {
        return Err(invalid());
    }
    selected.sort_by_key(|(ordinal, _, _)| *ordinal);
    let mut history = History::empty_retained();
    let mut floors = vec![];
    let mut controls = vec![];
    let mut admitted = BTreeSet::new();
    admitted.insert(source.ciphertext_hash.clone());
    let mut previous = source;
    let mut legacy = None;
    let mut remote = None;
    let mut plan: Option<(Receipt, merge::Plan, Checkpoint)> = None;
    let mut finalized = false;
    for (ordinal, receipt, frame) in selected {
        if finalized
            || ordinal
                != previous
                    .next_ordinal()?
                    .checked_add(1)
                    .ok_or_else(invalid)?
            || !receipt.follows(previous)?
        {
            return Err(invalid());
        }
        match frame.body {
            Body::Legacy(value) => {
                if legacy.is_some() || remote.is_some() || package.sources.chains().is_empty() {
                    return Err(invalid());
                }
                let witness = value.witness(owner)?;
                witness.require_inventory(owner, &package.sources, &package.record_inputs()?)?;
                floors.push(witness.checkpoint().clone());
                controls.push(value.control_minimum(owner)?);
                legacy = Some(value);
            }
            Body::Remote(value) => {
                if remote.is_some() || !package.sources.chains().is_empty() && legacy.is_none() {
                    return Err(invalid());
                }
                let read = transcript(
                    &mut history,
                    &mut floors,
                    &mut controls,
                    owner,
                    identity,
                    &value,
                    None,
                )?;
                package.require_historical_read(&read, &value)?;
                if let Some(evidence) = &legacy {
                    evidence.require_read(&read, &value)?;
                }
                remote = Some(read);
            }
            Body::Plan(value) => {
                if plan.is_some() {
                    return Err(invalid());
                }
                let read = remote.as_ref().ok_or_else(invalid)?;
                value.verify(&package, read)?;
                retain(&mut history, read, value.rows.iter().cloned())?;
                plan = Some((receipt.clone(), value, read.checkpoint().clone()));
            }
            Body::Rebase {
                parent,
                transcript: value,
                completed,
                plan: next,
            } => {
                let (old_receipt, prior, floor) = plan.take().ok_or_else(invalid)?;
                if parent != old_receipt {
                    return Err(invalid());
                }
                let read = transcript(
                    &mut history,
                    &mut floors,
                    &mut controls,
                    owner,
                    identity,
                    &value,
                    Some(&floor),
                )?;
                package.require_historical_read(&read, &value)?;
                prior.verify_rebase(&next, &package, &read, &value, completed)?;
                retain(&mut history, &read, next.rows.iter().cloned())?;
                plan = Some((receipt.clone(), next, read.checkpoint().clone()));
            }
            Body::Final(value) => {
                let (_, plan, floor) = plan.as_ref().ok_or_else(invalid)?;
                let read = transcript(
                    &mut history,
                    &mut floors,
                    &mut controls,
                    owner,
                    identity,
                    &value,
                    Some(floor),
                )?;
                package.require_historical_read(&read, &value)?;
                if observed(plan, &value)? != plan.rows.len() {
                    return Err(invalid());
                }
                // Reading remains historical even when every old planned operation was accepted.
                if let Some(evidence) = &legacy {
                    evidence.require_read(&read, &value)?;
                }
                finalized = true;
            }
        }
        admitted.insert(receipt.ciphertext_hash.clone());
        previous = receipt;
    }
    floors.sort_by(|a, b| {
        (a.epoch, a.sequence, &a.history_hash).cmp(&(b.epoch, b.sequence, &b.history_hash))
    });
    floors.dedup();
    Ok(Captured {
        package,
        history,
        floors,
        controls,
        admitted,
    })
}
