//! Recover legacy credentials only from complete encrypted source originals. Never interpret
//! an active central public cache as a legacy account, and never release credentials for transport.
use super::*;
use crate::sync::env::Keychain;
struct Budget {
    bytes: usize,
    packages: usize,
    seen: std::collections::BTreeSet<String>,
}
pub(super) fn discover(
    selected: &SyncStateV3,
    files: &Files,
    keys: &dyn Keychain,
) -> Result<Sources, AppError> {
    if !super::super::replacement_reconciliation::projected(selected) {
        return Err(invalid());
    }
    historical(selected, files, keys)
}
/// This reader never grants initial migration, transport, or current-cache authority.
pub(super) fn historical(
    selected: &SyncStateV3,
    files: &Files,
    keys: &dyn Keychain,
) -> Result<Sources, AppError> {
    if !super::super::historical_state::projected(selected) {
        return Err(invalid());
    }
    records_v3::validate_state(selected).map_err(|_| invalid())?;
    let owner = selected.local.central.as_ref().ok_or_else(invalid)?;
    let mut books = vec![];
    visit(
        owner,
        files,
        keys,
        0,
        &mut Budget {
            bytes: 0,
            packages: 0,
            seen: Default::default(),
        },
        &mut books,
    )?;
    if books.is_empty() {
        return Sources::discover(
            &*super::super::replacement_reconciliation::history_view(selected)?,
            None,
        );
    }
    let mut ranked = books
        .into_iter()
        .map(|book| {
            Ok((
                book.chains().len(),
                super::super::crypto::hash(&book.encode_local()?),
                book,
            ))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    ranked.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    let (_, _, selected) = ranked.pop().ok_or_else(invalid)?;
    for (_, _, book) in ranked {
        selected.require_retained_subset(&book)?;
    }
    Ok(selected)
}
fn visit(
    selected: &Workspace,
    files: &Files,
    keys: &dyn Keychain,
    depth: usize,
    budget: &mut Budget,
    books: &mut Vec<Sources>,
) -> Result<(), AppError> {
    let captured = source_archive::captured::read_all(&files.bytes, keys)?;
    if depth >= 8
        && captured
            .frames
            .iter()
            .any(|(r, _)| !budget.seen.contains(&r.ciphertext_hash))
    {
        return Err(invalid());
    }
    for (receipt, plain) in captured.frames {
        if !budget.seen.insert(receipt.ciphertext_hash.clone()) {
            continue;
        }
        budget.bytes = budget.bytes.checked_add(plain.len()).ok_or_else(invalid)?;
        if budget.bytes > MAX_BYTES {
            return Err(invalid());
        }
        if !Package::frame(&plain) {
            continue;
        }
        budget.packages += 1;
        if budget.packages > 256 {
            return Err(invalid());
        }
        let mut input = &plain[8..];
        let name = std::str::from_utf8(section(&mut input, 255)?).map_err(|_| invalid())?;
        let nested_files = Files::decode_local(section(
            &mut input,
            super::super::migration_files::MAX_ARCHIVE_BYTES,
        )?)?;
        let nested_state = state(&nested_files, name)?;
        let owner = nested_state.local.central.as_ref().ok_or_else(invalid)?;
        if owner.control.anchor != selected.control.anchor
            || owner.control.profile != selected.control.profile
            || owner.control.personal_vault != selected.control.personal_vault
        {
            return Err(invalid());
        }
        receipt.matches_selected(owner)?;
        let book = section(&mut input, super::super::migration_sources::MAX_BOOK_BYTES)?;
        let nested_keys = Snapshot::decode_local(section(&mut input, 2 * 1024 * 1024)?)?;
        if !super::super::replacement_reconciliation::projected(&nested_state) {
            let book = Sources::decode_local(book, &nested_state)?;
            if !book.chains().is_empty() {
                books.push(book);
            }
        }
        // This is discovery only. The complete framed package, all trailing sections, graph
        // coverage and signatures are independently admitted before a review or publication.
        visit(
            selected,
            &nested_files,
            &nested_keys,
            depth + 1,
            budget,
            books,
        )?;
    }
    Ok(())
}
