//! Inert historical journal checks; never restore protected progress or a publication permit.
use super::*;
impl Journal {
    pub(in crate::sync::central) fn captured_frame(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC)
    }
    pub(in crate::sync::central) fn captured_references(
        bytes: &[u8],
    ) -> Result<Vec<Receipt>, AppError> {
        let journal = Self::decode(bytes)?;
        if journal.ancestors.is_empty() || journal.ancestors.len() > 255 {
            return Err(invalid());
        }
        for receipt in &journal.ancestors {
            receipt.validate()?;
        }
        Ok(journal.ancestors)
    }
    pub(in crate::sync::central) fn captured_plan(bytes: &[u8]) -> Result<Receipt, AppError> {
        let journal = Self::decode(bytes)?;
        journal.plan.validate()?;
        Ok(journal.plan)
    }
    pub(in crate::sync::central) fn read_captured(
        bytes: &[u8],
        receipt: &Receipt,
        owner: &Workspace,
        source: &Receipt,
        plan: &Receipt,
        ancestors: &[Receipt],
    ) -> Result<Self, AppError> {
        let journal = Self::decode(bytes)?;
        journal.lineage(owner)?;
        receipt.matches_selected(owner)?;
        if journal.source != *source
            || journal.plan != *plan
            || journal.ancestors != ancestors
            || !receipt.follows(ancestors.last().ok_or_else(invalid)?)?
        {
            return Err(invalid());
        }
        Ok(journal)
    }
    pub(in crate::sync::central) fn captured_progress(
        &self,
        plan: &super::super::migration_history::CapturedPlan,
        previous: Option<&Self>,
    ) -> Result<(), AppError> {
        plan.progress_after(
            self.progress.as_ref(),
            self.verified.as_ref(),
            previous.and_then(|p| p.progress.as_ref()),
            previous.and_then(|p| p.verified.as_ref()),
        )
    }
}
