//! A revalidation may replace an unacknowledged recovery attempt, never its admitted history floor.
use super::{
    crypto,
    membership::SignedMembership,
    recovery_state::{Admission, Package},
    rekey::{Checkpoint, SignedRekey, SourceDigest, SourceExtension},
    trust::{ControlProof, VerifiedChain},
    wire::{canonical, hex, invalid, number},
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochPrefix {
    pub count: usize,
    pub digest: Option<String>,
}
impl EpochPrefix {
    pub fn capture(epochs: &[SignedRekey]) -> Result<Self, AppError> {
        if epochs.len() > 64 {
            return Err(invalid());
        }
        Ok(Self {
            count: epochs.len(),
            digest: Some(crypto::hash(
                &serde_json::to_vec(epochs).map_err(|_| invalid())?,
            )),
        })
    }
    pub fn verify(&self, epochs: &[SignedRekey]) -> Result<(), AppError> {
        let known = epochs.get(..self.count).ok_or_else(invalid)?;
        if self.count > 64
            || self.digest.as_ref().is_some_and(|digest| {
                Self::capture(known)
                    .ok()
                    .and_then(|prefix| prefix.digest)
                    .as_ref()
                    != Some(digest)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bridge {
    pub epoch: u64,
    pub digests: Vec<SourceDigest>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub previous: Admission,
    pub node: SignedMembership,
    pub bridges: Vec<Bridge>,
    pub tail: Vec<SourceDigest>,
}
pub fn extend(mut known: Checkpoint, digests: &[SourceDigest]) -> Result<Checkpoint, AppError> {
    if digests.len() > 16384 {
        return Err(invalid());
    }
    for row in digests {
        known.sequence += 1;
        if known.sequence > 16384
            || number(&row.sequence, false)? != known.sequence
            || !hex(&row.digest, 64)
        {
            return Err(invalid());
        }
        known.history_hash = crypto::hash(&canonical(&[
            "lunport-history-v2",
            &known.history_hash,
            &known.sequence.to_string(),
            &row.digest,
        ])?);
    }
    Ok(known)
}
pub fn manifest<'a>(epochs: &'a [SignedRekey], target: u64) -> Result<&'a SignedRekey, AppError> {
    if !(2..=65).contains(&target) {
        return Err(invalid());
    }
    let manifest = epochs.get((target - 2) as usize).ok_or_else(invalid)?;
    if number(&manifest.body.to_epoch, false)? != target {
        return Err(invalid());
    }
    Ok(manifest)
}
pub fn bridge_position(
    chain: &VerifiedChain,
    vault: &str,
    epochs: &[SignedRekey],
    from: &Checkpoint,
    bridge: &Bridge,
) -> Result<Checkpoint, AppError> {
    if bridge.epoch != from.epoch + 1 || bridge.digests.len() > 16384 {
        return Err(invalid());
    }
    let mut extension = SourceExtension::new(manifest(epochs, bridge.epoch)?, chain, vault, from)?;
    for rows in bridge.digests.chunks(256) {
        extension.append(rows)?;
    }
    extension.position()
}
pub fn finish_bridge(
    chain: &VerifiedChain,
    vault: &str,
    epochs: &[SignedRekey],
    from: &Checkpoint,
    bridge: &Bridge,
) -> Result<Checkpoint, AppError> {
    let mut extension = SourceExtension::new(manifest(epochs, bridge.epoch)?, chain, vault, from)?;
    if bridge.epoch != from.epoch + 1 || bridge.digests.len() > 16384 {
        return Err(invalid());
    }
    for rows in bridge.digests.chunks(256) {
        extension.append(rows)?;
    }
    extension.finish()
}
/// Native-only bounded bridge progress. A later content epoch never resets the known prefix.
pub struct Work {
    pub current: Checkpoint,
    pub bridges: Vec<Bridge>,
    pending: Option<Bridge>,
    required: Vec<Checkpoint>,
    target_epoch: u64,
}
impl Work {
    pub fn new(
        base: Checkpoint,
        required: Vec<Checkpoint>,
        target_epoch: u64,
    ) -> Result<Self, AppError> {
        if base.epoch == 0
            || base.epoch > target_epoch
            || target_epoch > 65
            || base.sequence > 16384
            || required.len() > 4
            || !hex(&base.history_hash, 64)
        {
            return Err(invalid());
        }
        for minimum in &required {
            if minimum.epoch < base.epoch
                || minimum.epoch > target_epoch
                || minimum.sequence > 16384
                || !hex(&minimum.history_hash, 64)
            {
                return Err(invalid());
            }
        }
        let result = Self {
            current: base.clone(),
            bridges: vec![],
            pending: None,
            required,
            target_epoch,
        };
        result.check(&result.current)?;
        Ok(result)
    }
    fn check(&self, position: &Checkpoint) -> Result<(), AppError> {
        if self.required.iter().any(|minimum| {
            minimum.epoch == position.epoch
                && minimum.sequence == position.sequence
                && minimum.history_hash != position.history_hash
        }) {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn next(
        &mut self,
        chain: &VerifiedChain,
        vault: &str,
        epochs: &[SignedRekey],
    ) -> Result<Option<(u64, u64)>, AppError> {
        while self.current.epoch < self.target_epoch {
            let pending = self.pending.get_or_insert(Bridge {
                epoch: self.current.epoch + 1,
                digests: vec![],
            });
            let position = bridge_position(chain, vault, epochs, &self.current, pending)?;
            self.check(&position)?;
            let pending = self.pending.as_ref().ok_or_else(invalid)?;
            let source = number(&manifest(epochs, pending.epoch)?.body.source_sequence, true)?;
            if position.sequence < source {
                return Ok(Some((pending.epoch, position.sequence)));
            }
            let completed = finish_bridge(chain, vault, epochs, &self.current, pending)?;
            self.check(&completed)?;
            self.current = completed;
            self.bridges.push(self.pending.take().ok_or_else(invalid)?);
        }
        Ok(None)
    }
    pub fn append(
        &mut self,
        chain: &VerifiedChain,
        vault: &str,
        epochs: &[SignedRekey],
        response_manifest: &SignedRekey,
        rows: &[SourceDigest],
    ) -> Result<(), AppError> {
        let pending = self.pending.as_ref().ok_or_else(invalid)?;
        if rows.is_empty()
            || rows.len() > 256
            || manifest(epochs, pending.epoch)? != response_manifest
        {
            return Err(invalid());
        }
        let position = bridge_position(chain, vault, epochs, &self.current, pending)?;
        let mut candidate = pending.clone();
        candidate.digests.extend_from_slice(rows);
        if self.bridges.iter().map(|b| b.digests.len()).sum::<usize>() + candidate.digests.len()
            > 16384
        {
            return Err(invalid());
        }
        let next = bridge_position(chain, vault, epochs, &self.current, &candidate)?;
        let mut check = position;
        for row in rows {
            check = extend(check, std::slice::from_ref(row))?;
            self.check(&check)?;
        }
        if check != next {
            return Err(invalid());
        }
        if next.sequence == number(&response_manifest.body.source_sequence, true)? {
            finish_bridge(chain, vault, epochs, &self.current, &candidate)?;
        }
        self.pending = Some(candidate);
        Ok(())
    }
    pub fn current_prefixes(&self) -> Result<Vec<Checkpoint>, AppError> {
        if self.pending.is_some() || self.current.epoch != self.target_epoch {
            return Err(invalid());
        }
        let mut minimums = vec![self.current.clone()];
        minimums.extend(
            self.required
                .iter()
                .filter(|m| m.epoch == self.target_epoch)
                .cloned(),
        );
        Ok(minimums)
    }
}
impl Evidence {
    /// A stronger protected snapshot may exist after the last Core CAS failed.
    pub fn check_minimum(&self, package: &Package, minimum: &Checkpoint) -> Result<(), AppError> {
        self.verify(package)?;
        let mut position = self.previous.checkpoint.clone();
        if minimum.epoch < position.epoch
            || minimum.epoch == position.epoch && minimum.sequence < position.sequence
        {
            return Ok(());
        }
        let mut found = false;
        let visit = |position: &Checkpoint, found: &mut bool| -> Result<(), AppError> {
            if position.epoch == minimum.epoch && position.sequence == minimum.sequence {
                if position.history_hash != minimum.history_hash {
                    return Err(invalid());
                }
                *found = true;
            }
            Ok(())
        };
        visit(&position, &mut found)?;
        let chain = package
            .source_proof
            .verify(&package.admission.anchor, None)?;
        for bridge in &self.bridges {
            let base = position.clone();
            for row in &bridge.digests {
                position = extend(position, std::slice::from_ref(row))?;
                visit(&position, &mut found)?;
            }
            position = finish_bridge(
                &chain,
                &package.admission.vault,
                &package.epochs,
                &base,
                bridge,
            )?;
            visit(&position, &mut found)?;
        }
        for row in &self.tail {
            position = extend(position, std::slice::from_ref(row))?;
            visit(&position, &mut found)?;
        }
        if !found {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn verify(&self, package: &Package) -> Result<(), AppError> {
        let next = &package.admission;
        if self.previous.anchor != next.anchor
            || self.previous.device != next.device
            || self.previous.vault != next.vault
            || self.node.body.recovery != package.node.body.recovery
            || self.previous.authorization_epoch > next.authorization_epoch
            || self.previous.checkpoint.epoch > next.checkpoint.epoch
            || self.bridges.len() > 64
            || self.previous.request_id == next.request_id
        {
            return Err(invalid());
        }
        let chain = package.source_proof.verify(&next.anchor, None)?;
        let revision = chain
            .revision_of(&self.previous.previous_head)
            .ok_or_else(invalid)?;
        let mut original = ControlProof {
            genesis: package.source_proof.genesis.clone(),
            nodes: package.source_proof.nodes[..revision].to_vec(),
        };
        original.nodes.push(self.node.clone());
        self.previous.verify(&original)?;
        if chain.has_head(&self.previous.approved_head) {
            return Err(invalid());
        }
        let mut known = self.previous.checkpoint.clone();
        let mut count = self.tail.len();
        for bridge in &self.bridges {
            count += bridge.digests.len();
            if count > 16384 {
                return Err(invalid());
            }
            known = finish_bridge(&chain, &next.vault, &package.epochs, &known, bridge)?;
        }
        if known.epoch != next.checkpoint.epoch || extend(known, &self.tail)? != next.checkpoint {
            return Err(invalid());
        }
        Ok(())
    }
}
pub fn verify_replacement(before: &Package, after: &Package) -> Result<(), AppError> {
    let evidence = after.revalidation.as_ref().ok_or_else(invalid)?;
    if before.operation != after.operation
        || after.attempt != before.attempt.checked_add(1).ok_or_else(invalid)?
        || after.submitted
        || before.backup_confirmed != after.backup_confirmed
        || evidence.previous != before.admission
        || evidence.node != before.node
        || before.source_proof.genesis != after.source_proof.genesis
        || !after
            .source_proof
            .nodes
            .starts_with(&before.source_proof.nodes)
        || !after.epochs.starts_with(&before.epochs)
    {
        return Err(invalid());
    }
    evidence.verify(after)
}

#[cfg(test)]
mod tests {
    use super::super::{recovery_read, recovery_state::RecoveryState};
    use super::*;
    fn package(workspace: &super::super::workspace::Workspace) -> &Package {
        match workspace.recovery.as_ref().unwrap() {
            RecoveryState::Pending { package } => package,
            _ => panic!(),
        }
    }
    fn package_mut(state: &mut super::super::workspace::Workspace) -> &mut Package {
        match state.recovery.as_mut().unwrap() {
            RecoveryState::Pending { package } => package,
            _ => panic!(),
        }
    }
    #[test]
    fn replacement_extends_the_old_checkpoint_across_current_history_or_a_committed_epoch() {
        for rotated in [false, true] {
            let (before, after, _, _) = recovery_read::tests::revalidation_fixture(rotated);
            after.validate().unwrap();
            before.verify_transition(&after).unwrap();
            assert_eq!(package(&after).attempt, 1);
            assert!(package(&after).backup_confirmed);
            assert!(!package(&after).submitted);
            assert!(after.control.auth_epoch >= before.control.auth_epoch);
            let stored = serde_json::to_string(&after).unwrap();
            assert!(!stored.contains("LPREC2:"));
            let restored: super::super::workspace::Workspace =
                serde_json::from_str(&stored).unwrap();
            restored.validate().unwrap();
            assert!(after.verify_transition(&before).is_err());
        }
    }
    #[test]
    fn a_replacement_cannot_change_future_authority_attempt_consent_or_history_floor() {
        let (before, mut after, _, _) = recovery_read::tests::revalidation_fixture(false);
        let original = after.clone();
        package_mut(&mut after).attempt = 0;
        assert!(before.verify_transition(&after).is_err());
        after = original.clone();
        package_mut(&mut after).backup_confirmed = false;
        assert!(before.verify_transition(&after).is_err());
        after = original.clone();
        package_mut(&mut after).revalidation.as_mut().unwrap().tail[0].digest = "f".repeat(64);
        assert!(after.validate().is_err());
        after = original.clone();
        package_mut(&mut after)
            .revalidation
            .as_mut()
            .unwrap()
            .tail
            .clear();
        assert!(after.validate().is_err());
        after = original;
        package_mut(&mut after).operation = "e".repeat(32);
        assert!(before.verify_transition(&after).is_err());
    }
    #[test]
    fn committed_epoch_bridges_must_be_complete_ordered_and_match_the_known_source() {
        let (before, mut after, _, _) = recovery_read::tests::revalidation_fixture(true);
        let original = after.clone();
        if let Some(RecoveryState::Pending { package }) = &mut after.recovery {
            package.revalidation.as_mut().unwrap().bridges.clear();
        }
        assert!(after.validate().is_err());
        after = original.clone();
        if let Some(RecoveryState::Pending { package }) = &mut after.recovery {
            package.revalidation.as_mut().unwrap().bridges[0].epoch = 3;
        }
        assert!(after.validate().is_err());
        after = original;
        if let Some(RecoveryState::Pending { package }) = &mut after.recovery {
            package.revalidation.as_mut().unwrap().previous = package.admission.clone();
        }
        assert!(before.verify_transition(&after).is_err());
    }
    #[test]
    fn bridge_work_preserves_a_known_checkpoint_inside_a_source_page() {
        let (before, after, _, _) = recovery_read::tests::revalidation_fixture(true);
        let old = package(&before);
        let new = package(&after);
        let evidence = new.revalidation.as_ref().unwrap();
        let chain = new
            .source_proof
            .verify(&new.admission.anchor, None)
            .unwrap();
        let source = &evidence.bridges[0];
        let minimum = extend(old.admission.checkpoint.clone(), &source.digests).unwrap();
        let mut work =
            Work::new(old.admission.checkpoint.clone(), vec![minimum.clone()], 2).unwrap();
        assert_eq!(
            work.next(&chain, &new.admission.vault, &new.epochs)
                .unwrap(),
            Some((2, 1))
        );
        let commit = manifest(&new.epochs, 2).unwrap();
        work.append(
            &chain,
            &new.admission.vault,
            &new.epochs,
            commit,
            &source.digests,
        )
        .unwrap();
        assert_eq!(
            work.next(&chain, &new.admission.vault, &new.epochs)
                .unwrap(),
            None
        );
        assert_eq!(work.current, new.admission.checkpoint);
        assert_eq!(
            work.current_prefixes().unwrap(),
            vec![new.admission.checkpoint.clone()]
        );
        let mut wrong = minimum;
        wrong.history_hash = "f".repeat(64);
        let mut rejected = Work::new(old.admission.checkpoint.clone(), vec![wrong], 2).unwrap();
        rejected
            .next(&chain, &new.admission.vault, &new.epochs)
            .unwrap();
        assert!(rejected
            .append(
                &chain,
                &new.admission.vault,
                &new.epochs,
                commit,
                &source.digests
            )
            .is_err());
        assert!(rejected.pending.as_ref().unwrap().digests.is_empty());
    }
}
