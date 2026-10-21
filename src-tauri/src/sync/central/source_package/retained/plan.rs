//! A captured upload plan is inert evidence; its plaintext must match its exact complete source.
use super::super::super::{capture_journal::Journal, migration_history::Plan};
use super::*;
pub(super) struct Evidence {
    bytes: Zeroizing<Vec<u8>>,
    source: Receipt,
    journals: Vec<super::super::super::migration_journal::Journal>,
}
impl Evidence {
    pub(super) fn source(&self) -> &Receipt {
        &self.source
    }
    pub(super) fn capture(
        &self,
        package: &Package,
        identity: &DeviceIdentity,
    ) -> Result<History, AppError> {
        let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
        owner.validate()?;
        if identity.device() != owner.control.device {
            return Err(invalid());
        }
        let chain = owner.control.verified_chain()?;
        let epoch = owner
            .replica
            .as_ref()
            .ok_or_else(invalid)?
            .checkpoint
            .epoch
            .to_string();
        let wrap = owner
            .own_wraps
            .iter()
            .find(|w| w.header.key_epoch == epoch)
            .ok_or_else(invalid)?;
        let author = chain
            .author_at(&wrap.header.membership_head, &wrap.header.author)
            .ok_or_else(invalid)?;
        let keys = wrap.open(&identity.keys, &wrap.header, &author.signing)?;
        self.capture_keys(package, &keys)
    }
    pub(super) fn capture_reconnected(
        &self,
        package: &Package,
        read: &super::super::super::active_read::VerifiedLibrary,
    ) -> Result<History, AppError> {
        let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
        super::super::super::historical_state::require_reconnected_owner(owner, read)?;
        if owner.replica.as_ref().ok_or_else(invalid)?.checkpoint.epoch != read.checkpoint().epoch {
            return Err(AppError::Other("A retained central content epoch still needs its original device credentials. Original files are retained.".into()));
        }
        self.capture_keys(package, read.keys())
    }
    fn capture_keys(&self, package: &Package, keys: &VaultKeys) -> Result<History, AppError> {
        let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
        // Only the exact source and complete original progress chain can validate a plan. Its
        // target rows are never promoted to an accepted central checkpoint.
        let context = package.migration_context(&self.source)?;
        let plan = Plan::read_captured(&self.bytes, owner, &keys, &context)?;
        let references = plan.reference_classifications(&keys)?;
        self.validate(package, &keys, &references)?;
        package.structured_history(&keys, &references)
    }
    pub(super) fn validate(
        &self,
        package: &Package,
        keys: &VaultKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<(), AppError> {
        let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
        let context = package.migration_context(&self.source)?;
        let plan = Plan::read_captured(&self.bytes, owner, keys, &context)?;
        let history = package.structured_history(keys, references)?.into_rows();
        plan.matches_history(keys, &history)?;
        let mut previous = None;
        for journal in &self.journals {
            journal.captured_progress(&plan, previous)?;
            previous = Some(journal);
        }
        Ok(())
    }
}
pub(super) fn read(
    receipt: &Receipt,
    bytes: &[u8],
    mut read: impl FnMut(&Receipt) -> Result<Zeroizing<Vec<u8>>, AppError>,
    mut locate: impl FnMut(&str) -> Result<Receipt, AppError>,
) -> Result<(Package, Evidence, Vec<Receipt>), AppError> {
    let (before, cursor, digest, operation) = Plan::captured_binding(bytes)?;
    let source = locate(&digest)?;
    source.matches_selected(&before)?;
    receipt.matches_selected(&before)?;
    if source.operation() != operation || !receipt.follows(&source)? {
        return Err(invalid());
    }
    let (package, ancestors) = if let Some(cursor) = cursor {
        if cursor.receipt() != &source {
            return Err(invalid());
        }
        Journal::captured_source(&cursor, &mut read)?
    } else {
        let plain = read(&source)?;
        if !Package::complete_frame(&plain) {
            return Err(invalid());
        }
        let package = Package::decode_local(&plain)?;
        let initial = locate(package.captured_initial_digest()?)?;
        if !source.follows(&initial)? {
            return Err(invalid());
        }
        package.require_captured_base(&Package::decode_local(&read(&initial)?)?, &initial)?;
        (package, vec![initial, source.clone()])
    };
    if package.state.local.central.as_ref() != Some(&before) {
        return Err(invalid());
    }
    Ok((
        package,
        Evidence {
            bytes: Zeroizing::new(bytes.to_vec()),
            source,
            journals: vec![],
        },
        ancestors,
    ))
}

pub(super) fn read_journal(
    receipt: &Receipt,
    bytes: &[u8],
    mut read: impl FnMut(&Receipt) -> Result<Zeroizing<Vec<u8>>, AppError>,
    mut locate: impl FnMut(&str) -> Result<Receipt, AppError>,
) -> Result<(Package, Evidence, Vec<Receipt>), AppError> {
    use super::super::super::migration_journal::Journal as PlannedJournal;
    let plan_receipt = PlannedJournal::captured_plan(bytes)?;
    let (package, mut evidence, mut required) =
        self::read(&plan_receipt, &read(&plan_receipt)?, &mut read, &mut locate)?;
    required.push(plan_receipt.clone());
    let ancestors = PlannedJournal::captured_references(bytes)?;
    if !ancestors.starts_with(&required) {
        return Err(invalid());
    }
    let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
    for (index, prior) in ancestors.iter().enumerate().skip(required.len()) {
        evidence.journals.push(PlannedJournal::read_captured(
            &read(prior)?,
            prior,
            owner,
            &evidence.source,
            &plan_receipt,
            &ancestors[..index],
        )?);
    }
    evidence.journals.push(PlannedJournal::read_captured(
        bytes,
        receipt,
        owner,
        &evidence.source,
        &plan_receipt,
        &ancestors,
    )?);
    let mut covered = ancestors;
    covered.push(receipt.clone());
    Ok((package, evidence, covered))
}
