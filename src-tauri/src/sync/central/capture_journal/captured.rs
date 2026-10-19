//! Read-only complete historical capture journals. No cursor restoration or signing keys.
use super::*;
impl Journal {
    pub(in crate::sync::central) fn captured_references(
        bytes: &[u8],
    ) -> Result<Vec<Receipt>, AppError> {
        let journal = Self::decode(bytes)?;
        if journal.ancestors.is_empty() || journal.ancestors.len() > 254 {
            return Err(invalid());
        }
        for receipt in &journal.ancestors {
            receipt.validate()?;
        }
        Ok(journal.ancestors)
    }
    pub(in crate::sync::central) fn captured_complete(
        bytes: &[u8],
        receipt: &Receipt,
        mut read: impl FnMut(&Receipt) -> Result<Zeroizing<Vec<u8>>, AppError>,
    ) -> Result<(Package, Vec<Receipt>), AppError> {
        let mut journal = Self::decode(bytes)?;
        let source = Package::decode_local(&read(&journal.source)?)?;
        let owner = source.state.local.central.as_ref().ok_or_else(invalid)?;
        journal.lineage(owner)?;
        receipt.matches_selected(owner)?;
        if !receipt.follows(journal.ancestors.last().ok_or_else(invalid)?)?
            || journal.pending_book.is_some()
        {
            return Err(invalid());
        }
        let (package, _) = journal.captured_inputs(owner, None, &mut read)?;
        let fetching = journal.fetching.ok_or_else(invalid)?;
        if fetching
            .discovered_sources(&package.sources, &package.state)?
            .is_some()
        {
            return Err(invalid());
        }
        Ok((
            package.finish_captured_fetching(fetching)?,
            journal.ancestors,
        ))
    }
}
