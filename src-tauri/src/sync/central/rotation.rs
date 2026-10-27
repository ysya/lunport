//! Durable ciphertext-only rotation work. No content key is serialized into a journal.
use super::{
    crypto::{self, VaultKeys, WrappedKeys},
    payload,
    rekey::{self, Checkpoint, Plan, SignedRekey, SourceDigest, SourceExtension, Version},
    replica::{Conflict, Replica},
    wire::{canonical, invalid, number},
    workspace::{EpochAcceptance, Workspace},
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub enum Journal {
    Source {
        membership_head: String,
        authorization_epoch: u64,
        source: Checkpoint,
        rows: Vec<Version>,
    },
    Sending {
        manifest: SignedRekey,
        wraps: Vec<WrappedKeys>,
        from: Checkpoint,
        source_suffix: Vec<SourceDigest>,
        rows: Vec<Version>,
        verified: u64,
    },
    Receiving {
        manifest: SignedRekey,
        wraps: Vec<WrappedKeys>,
        from: Checkpoint,
        source_suffix: Vec<SourceDigest>,
        rows: Vec<Version>,
    },
}
pub fn checkpoint(epoch: u64, rows: &[Version]) -> Result<Checkpoint, AppError> {
    Ok(Checkpoint {
        epoch,
        sequence: rows.len() as u64,
        history_hash: rows
            .last()
            .map_or_else(|| ZERO.into(), |r| r.history_hash.clone()),
    })
}
/// Validate a complete retained prefix, including per-record revisions and operation uniqueness.
fn verify_rows(workspace: &Workspace, epoch: u64, rows: &[Version]) -> Result<(), AppError> {
    let chain = workspace.control.verified_chain()?;
    let replica = workspace.replica.as_ref().ok_or_else(invalid)?;
    let anchor = chain.current().anchor();
    let mut versions = BTreeMap::new();
    let mut operations = BTreeSet::new();
    let mut hash = ZERO.to_string();
    let mut bytes = 0;
    if rows.len() > 16384 {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let seq = index as u64 + 1;
        let h = &row.envelope.header;
        let previous: Option<&(u64, String)> = versions.get(&h.record_id);
        let revision = previous.map_or(0, |v| v.0) + 1;
        if number(&row.sequence, false)? != seq
            || number(&row.revision, false)? != revision
            || number(&h.expected_revision, true)? != revision - 1
            || previous.is_some_and(|v| v.1 != h.kind)
            || h.origin != anchor.origin
            || h.account_id != anchor.account_id
            || h.genesis_hash != anchor.genesis_hash
            || h.vault_id != replica.vault
            || number(&h.key_epoch, false)? != epoch
            || !operations.insert(&h.operation_id)
            || row.digest != rekey::envelope_digest(&row.envelope)?
        {
            return Err(invalid());
        }
        let author = chain
            .author_at(&h.membership_head, &h.author)
            .ok_or_else(invalid)?;
        row.envelope.verify(&author.signing)?;
        hash = crypto::hash(&canonical(&[
            "lunport-history-v2",
            &hash,
            &seq.to_string(),
            &row.digest,
        ])?);
        if row.history_hash != hash {
            return Err(invalid());
        }
        bytes += serde_json::to_vec(&row.envelope)
            .map_err(|_| invalid())?
            .len();
        versions.insert(h.record_id.clone(), (revision, h.kind.clone()));
        if bytes > 32 * 1024 * 1024 || versions.len() > 4096 {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(super) fn verify_source(
    workspace: &Workspace,
    manifest: &SignedRekey,
    from: &Checkpoint,
    suffix: &[SourceDigest],
) -> Result<bool, AppError> {
    let replica = workspace.replica.as_ref().ok_or_else(invalid)?;
    if from != &replica.checkpoint || suffix.len() > 16384 {
        return Err(invalid());
    }
    let chain = workspace.control.verified_chain()?;
    let mut extension = SourceExtension::new(manifest, &chain, &replica.vault, from)?;
    let total = number(&manifest.body.source_sequence, true)?;
    if replica.minimum.as_ref().is_some_and(|m| m.sequence > total) {
        return Err(invalid());
    }
    let mut claims = BTreeMap::new();
    for pending in replica.pending.values() {
        if let Some(claim) = &pending.claimed {
            let sent = pending.sent.as_ref().ok_or_else(invalid)?;
            if number(&sent.envelope.header.key_epoch, false)? == from.epoch {
                let sequence = number(&claim.sequence, false)?;
                if sequence <= from.sequence
                    || sequence > total
                    || claims.insert(sequence, claim).is_some()
                {
                    return Err(invalid());
                }
            }
        }
    }
    for digest in suffix {
        extension.append(std::slice::from_ref(digest))?;
        let position = extension.position()?;
        if replica.minimum.as_ref().is_some_and(|m| {
            m.sequence == position.sequence && m.history_hash != position.history_hash
        }) {
            return Err(invalid());
        }
        if let Some(claim) = claims.remove(&position.sequence) {
            if claim.digest != digest.digest || claim.history_hash != position.history_hash {
                return Err(invalid());
            }
        }
    }
    if extension.position()?.sequence == total {
        extension.finish()?;
        if !claims.is_empty() {
            return Err(invalid());
        }
        Ok(true)
    } else {
        Ok(false)
    }
}
impl Journal {
    pub fn validate(&self, workspace: &Workspace) -> Result<(), AppError> {
        let replica = workspace.replica.as_ref().ok_or_else(invalid)?;
        let chain = workspace.control.verified_chain()?;
        match self {
            Self::Source {
                membership_head,
                authorization_epoch,
                source,
                rows,
            } => {
                if !chain.has_head(membership_head)
                    || *authorization_epoch == 0
                    || *authorization_epoch > workspace.control.auth_epoch
                    || source.epoch != replica.checkpoint.epoch
                    || source.epoch >= 65
                    || source.sequence > 16384
                    || source.sequence < replica.checkpoint.sequence
                    || rows.len() as u64 > source.sequence
                    || !super::wire::hex(&source.history_hash, 64)
                    || source.sequence == 0 && source.history_hash != ZERO
                    || replica
                        .minimum
                        .as_ref()
                        .is_some_and(|m| m.sequence > source.sequence)
                {
                    return Err(invalid());
                }
                verify_rows(workspace, source.epoch, rows)?;
                if replica.checkpoint.sequence > 0
                    && rows.len() as u64 >= replica.checkpoint.sequence
                    && rows[replica.checkpoint.sequence as usize - 1].history_hash
                        != replica.checkpoint.history_hash
                {
                    return Err(invalid());
                }
                if let Some(minimum) = &replica.minimum {
                    if minimum.sequence > 0
                        && rows.len() as u64 >= minimum.sequence
                        && rows[minimum.sequence as usize - 1].history_hash != minimum.history_hash
                    {
                        return Err(invalid());
                    }
                }
                if rows.len() as u64 == source.sequence
                    && checkpoint(source.epoch, rows)? != *source
                {
                    return Err(invalid());
                }
            }
            Self::Sending {
                manifest,
                wraps,
                from,
                source_suffix,
                rows,
                ..
            }
            | Self::Receiving {
                manifest,
                wraps,
                from,
                source_suffix,
                rows,
            } => {
                rekey::verify_committed_wraps(&chain, manifest, wraps)?;
                if number(&manifest.body.from_epoch, false)? != replica.checkpoint.epoch
                    || number(&manifest.body.to_epoch, false)? > 65
                {
                    return Err(invalid());
                }
                let complete = verify_source(workspace, manifest, from, source_suffix)?;
                let epoch = number(&manifest.body.to_epoch, false)?;
                let total = number(&manifest.body.source_sequence, true)?;
                if rows.len() as u64 > total || !rows.is_empty() && !complete {
                    return Err(invalid());
                }
                verify_rows(workspace, epoch, rows)?;
                if rows.iter().any(|r| {
                    r.envelope.header.membership_head != manifest.body.membership_head
                        || r.envelope.header.author != manifest.body.author
                }) {
                    return Err(invalid());
                }
                if rows.len() as u64 == total
                    && checkpoint(epoch, rows)?.history_hash != manifest.body.target_history_hash
                {
                    return Err(invalid());
                }
                if let Self::Sending { verified, .. } = self {
                    if !complete || rows.len() as u64 != total || *verified > total {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(())
    }
    pub fn sending(
        workspace: &Workspace,
        plan: Plan,
        source_rows: &[Version],
    ) -> Result<Self, AppError> {
        workspace.require_key_recipients()?;
        let from = workspace
            .replica
            .as_ref()
            .ok_or_else(invalid)?
            .checkpoint
            .clone();
        let source_suffix = source_rows
            .iter()
            .skip(from.sequence as usize)
            .map(|r| SourceDigest {
                sequence: r.sequence.clone(),
                digest: r.digest.clone(),
            })
            .collect();
        let next = Self::Sending {
            manifest: plan.manifest,
            wraps: plan.wraps,
            from,
            source_suffix,
            rows: plan.rows,
            verified: 0,
        };
        next.validate(workspace)?;
        Ok(next)
    }
    pub fn verify_transition(
        &self,
        next: Option<&Self>,
        after: &Workspace,
    ) -> Result<(), AppError> {
        if let Self::Source { .. } = self {
            return Ok(());
        }
        let (manifest, wraps, from, suffix, rows) = match self {
            Self::Sending {
                manifest,
                wraps,
                from,
                source_suffix,
                rows,
                ..
            }
            | Self::Receiving {
                manifest,
                wraps,
                from,
                source_suffix,
                rows,
            } => (manifest, wraps, from, source_suffix, rows),
            _ => unreachable!(),
        };
        if after
            .epochs
            .iter()
            .any(|m| m.body.from_epoch == manifest.body.from_epoch)
        {
            return Ok(());
        }
        if next.is_none()
            && after.control.phase == super::client_state::Phase::Rekey
            && after.control.auth_epoch > number(&manifest.body.authorization_epoch, false)?
        {
            // A completed, newer authorization barrier invalidates all old-epoch upload grants.
            // The executor checks current child status (and aborts an old journal if present)
            // before retiring this now-stale ciphertext-only plan.
            return Ok(());
        }
        match (self, next) {
            (
                Self::Sending {
                    verified: before, ..
                },
                Some(Self::Sending {
                    manifest: m,
                    wraps: w,
                    from: f,
                    source_suffix: s,
                    rows: r,
                    verified,
                }),
            ) if m == manifest
                && w == wraps
                && f == from
                && s == suffix
                && r == rows
                && verified >= before =>
            {
                Ok(())
            }
            (
                Self::Receiving { .. },
                Some(Self::Receiving {
                    manifest: m,
                    wraps: w,
                    from: f,
                    source_suffix: s,
                    rows: r,
                }),
            ) if m == manifest
                && w == wraps
                && f == from
                && s.starts_with(suffix)
                && r.starts_with(rows) =>
            {
                Ok(())
            }
            // A different, authenticated committed rotation at this epoch supersedes an upload plan.
            (Self::Sending { .. }, Some(Self::Receiving { manifest: m, .. }))
                if m.body.from_epoch == manifest.body.from_epoch =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}
/// The conflicts the rebuilt history raises: a pending record whose version it changed from `before`'s, unless it confirmed this
/// device's own write (`confirmed`), gains an entry beside those carried over, and keeps only its latest (`replica::keep_latest`).
pub(super) fn note_conflicts(before: &Replica, replica: &mut Replica, confirmed: &BTreeSet<String>) {
    let Replica { pending, current, conflicts, .. } = replica;
    for (id, pending) in pending.iter() {
        if let Some(remote) = current.get(id) {
            if !confirmed.contains(id)
                && remote.content_hash != pending.latest.content_hash
                && before.current.get(id).map(|b| &b.content_hash) != Some(&remote.content_hash)
            {
                let conflict = Conflict {
                    base: before.current.get(id).cloned(),
                    local: pending.latest.clone(),
                    remote: remote.clone(),
                };
                let existing = conflicts.entry(id.clone()).or_default();
                if !existing.iter().any(|c| {
                    c.local.local_revision == conflict.local.local_revision
                        && c.local.content_hash == conflict.local.content_hash
                        && c.remote.content_hash == conflict.remote.content_hash
                }) {
                    existing.push(conflict);
                    super::replica::keep_latest(existing);
                }
            }
        }
    }
}
/// Rebuild a complete authenticated target history before committing the epoch. Local pending B,
/// uncertain sent A and old encrypted conflict versions survive until exact history confirms A.
pub fn activate(
    workspace: &Workspace,
    manifest: &SignedRekey,
    wraps: &[WrappedKeys],
    suffix: &[SourceDigest],
    rows: &[Version],
    keys: &VaultKeys,
) -> Result<Workspace, AppError> {
    let before = workspace.replica.as_ref().ok_or_else(invalid)?;
    if !verify_source(workspace, manifest, &before.checkpoint, suffix)? {
        return Err(invalid());
    }
    let chain = workspace.control.verified_chain()?;
    rekey::verify_committed_wraps(&chain, manifest, wraps)?;
    let epoch = number(&manifest.body.to_epoch, false)?;
    let target = Checkpoint {
        epoch,
        sequence: number(&manifest.body.source_sequence, true)?,
        history_hash: manifest.body.target_history_hash.clone(),
    };
    if checkpoint(epoch, rows)? != target {
        return Err(invalid());
    }
    let mut replica = Replica::join(
        before.vault.clone(),
        before.creation_head.clone(),
        before.creation_authorization_epoch,
        target.clone(),
    )?;
    let mut operations = BTreeMap::new();
    for page in rows.chunks(32) {
        let prepared = replica.prepare_page(&chain, keys, page, &target)?;
        for opened in prepared.opened {
            payload::admit(keys, &opened.version.envelope.header, &opened.plaintext)?;
            operations.insert(
                opened.version.envelope.header.operation_id.clone(),
                (opened.version, crypto::hash(&opened.plaintext)),
            );
        }
        replica = prepared.next;
    }
    replica.pending = before.pending.clone();
    replica.conflicts = before.conflicts.clone();
    let mut confirmed = BTreeSet::new();
    replica.pending.retain(|id, pending| {
        let match_sent = pending.sent.as_ref().and_then(|sent| {
            operations
                .get(&sent.envelope.header.operation_id)
                .map(|r| (sent, r))
        });
        if let Some((sent, (version, hash))) = match_sent {
            let old = &sent.envelope.header;
            let new = &version.envelope.header;
            if hash == &sent.content_hash
                && old.kind == new.kind
                && old.deleted == new.deleted
                && old.expected_revision == new.expected_revision
            {
                let clear = pending.latest.local_revision == sent.local_revision
                    && pending.latest.content_hash == sent.content_hash;
                confirmed.insert(id.clone());
                pending.confirmed = Some(super::replica::Base {
                    version: version.clone(),
                    content_hash: hash.clone(),
                });
                pending.sent = None;
                pending.claimed = None;
                if clear {
                    return false;
                }
            }
        }
        true
    });
    for pending in replica.pending.values() {
        if let Some(sent) = &pending.sent {
            if pending.claimed.is_some()
                || operations.contains_key(&sent.envelope.header.operation_id)
            {
                return Err(invalid());
            }
        }
    }
    note_conflicts(before, &mut replica, &confirmed);
    let mut next = workspace.clone();
    next.rotation = None;
    next.replica = Some(replica);
    next.epochs.push(manifest.clone());
    next.last_epoch_acceptance = Some(EpochAcceptance {
        from: before.checkpoint.clone(),
        manifest: manifest.clone(),
        source_suffix: suffix.to_vec(),
    });
    if let Some(own) = wraps
        .iter()
        .find(|w| w.header.recipient == workspace.control.device.id)
    {
        if !next.own_wraps.contains(own) {
            next.own_wraps.push(own.clone());
        }
    } else {
        return Err(invalid());
    }
    workspace.verify_transition(&next)?;
    Ok(next)
}

/// A later committed epoch may have replaced intermediate ciphertext. Verify each source suffix
/// and pin its signed target checkpoint without pretending the old cache is a rebuilt new epoch.
pub fn bridge(
    workspace: &Workspace,
    manifest: &SignedRekey,
    wraps: &[WrappedKeys],
    suffix: &[SourceDigest],
) -> Result<Workspace, AppError> {
    let before = workspace.replica.as_ref().ok_or_else(invalid)?;
    if !verify_source(workspace, manifest, &before.checkpoint, suffix)? {
        return Err(invalid());
    }
    let chain = workspace.control.verified_chain()?;
    rekey::verify_committed_wraps(&chain, manifest, wraps)?;
    let mut extension = SourceExtension::new(manifest, &chain, &before.vault, &before.checkpoint)?;
    for page in suffix.chunks(256) {
        extension.append(page)?;
    }
    let target = extension.finish()?;
    let mut next = workspace.clone();
    next.rotation = None;
    let replica = next.replica.as_mut().ok_or_else(invalid)?;
    replica.checkpoint = target.clone();
    replica.minimum = Some(target);
    replica.needs_epoch_rebuild = true;
    next.epochs.push(manifest.clone());
    next.last_epoch_acceptance = Some(EpochAcceptance {
        from: before.checkpoint.clone(),
        manifest: manifest.clone(),
        source_suffix: suffix.to_vec(),
    });
    if let Some(own) = wraps
        .iter()
        .find(|w| w.header.recipient == workspace.control.device.id)
    {
        if !next.own_wraps.contains(own) {
            next.own_wraps.push(own.clone());
        }
    } else {
        return Err(invalid());
    }
    workspace.verify_transition(&next)?;
    Ok(next)
}
