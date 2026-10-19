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
    pub(in crate::sync::central) fn captured_source(
        cursor: &Cursor,
        mut read: impl FnMut(&Receipt) -> Result<Zeroizing<Vec<u8>>, AppError>,
    ) -> Result<(Package, Vec<Receipt>), AppError> {
        let bytes = read(cursor.receipt())?;
        let (package, mut ancestors) = if Self::frame(&bytes) {
            Self::captured_complete(&bytes, cursor.receipt(), &mut read)?
        } else {
            if !Package::complete_frame(&bytes) {
                return Err(invalid());
            }
            let parent = cursor.previous().ok_or_else(invalid)?;
            let parent_bytes = read(parent)?;
            if Self::frame(&parent_bytes) {
                let (package, mut ancestors) =
                    Self::captured_complete(&parent_bytes, parent, &mut read)?;
                if package.encode_local()?.as_slice() != bytes.as_slice() {
                    return Err(invalid());
                }
                ancestors.push(parent.clone());
                (package, ancestors)
            } else {
                if cursor.revision() != 2 {
                    return Err(invalid());
                }
                let package = Package::decode_local(&bytes)?;
                package.require_captured_base(&Package::decode_local(&parent_bytes)?, parent)?;
                (package, vec![parent.clone()])
            }
        };
        let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
        cursor.validate(owner)?;
        if cursor.revision() != ancestors.len() as u64 + 1 || cursor.previous() != ancestors.last()
        {
            return Err(invalid());
        }
        if !cursor
            .receipt()
            .follows(ancestors.last().ok_or_else(invalid)?)?
        {
            return Err(invalid());
        }
        ancestors.push(cursor.receipt().clone());
        Ok((package, ancestors))
    }
}
