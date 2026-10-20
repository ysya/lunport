//! Read-only recovery of one exact same-step blob whose protected cursor write was interrupted.
use super::*;
use std::collections::BTreeSet;
/// Reuses ciphertext only after authenticating context, contents and the unchanged named files.
/// Unknown or different abandoned data remains an obligation; it is never deleted or excluded.
fn read_next(
    env: &SyncEnv,
    owner: &Workspace,
    previous: &Receipt,
    generation: u64,
    expected: Option<&[u8]>,
    known: &Outputs,
) -> Result<Option<(Archived, Outputs, Zeroizing<Vec<u8>>)>, AppError> {
    previous.matches_selected(owner)?;
    let directory = ArchiveDirectory::open(env, Kind::Source)?;
    let before = directory.names()?;
    let known: BTreeSet<_> = known.files().map(|(p, _)| p.to_path_buf()).collect();
    let prefix = format!("{}-", previous.operation());
    let mut found = None;
    for name in &before {
        let path = std::path::Path::new("data/central-source-archives").join(name);
        if known.contains(&path) || !name.starts_with(&prefix) || !name.ends_with(".lpsource") {
            continue;
        }
        let bytes = directory.read(name)?.ok_or_else(invalid)?;
        if bytes.len() < 12 || bytes.len() > MAX_FILE || !bytes.starts_with(MAGIC) {
            return Err(invalid());
        }
        let length = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
        if length == 0 || length > MAX_HEADER || length > bytes.len() - 12 {
            return Err(invalid());
        }
        let header: Header =
            serde_json::from_slice(&bytes[12..12 + length]).map_err(|_| invalid())?;
        header.aad()?;
        let receipt = Receipt {
            context: header.context,
            ciphertext_hash: crypto::hash(&bytes),
            bytes: bytes.len() as u64,
        };
        receipt.matches_selected(owner)?;
        if !receipt.follows(previous)?
            || receipt.context.filename()? != *name
            || super::super::wire::number(&receipt.context.generation, true)? != generation
        {
            return Err(invalid());
        }
        let (plain, proof) =
            restore_with_outputs(env, &owner.control.profile.profile()?, &receipt)?;
        if expected.is_some_and(|expected| plain.as_slice() != expected) || found.is_some() {
            return Err(invalid());
        }
        found = Some((Archived { receipt }, proof, plain));
    }
    if before != directory.names()? {
        return Err(crate::sync::runtime::superseded());
    }
    Ok(found)
}

pub(in crate::sync::central) fn resume_next(
    env: &SyncEnv,
    owner: &Workspace,
    previous: &Receipt,
    generation: u64,
    expected: &[u8],
    known: &Outputs,
) -> Result<Option<(Archived, Outputs)>, AppError> {
    Ok(
        read_next(env, owner, previous, generation, Some(expected), known)?
            .map(|(archived, outputs, _)| (archived, outputs)),
    )
}
/// Authenticated native bytes only, never permission to exclude an output or advance a cursor.
/// The caller must reconstruct its exact next typed journal before the ordinary store rechecks it.
pub(in crate::sync::central) fn candidate_next(
    env: &SyncEnv,
    owner: &Workspace,
    previous: &Receipt,
    generation: u64,
    known: &Outputs,
) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    Ok(read_next(env, owner, previous, generation, None, known)?.map(|(_, _, plain)| plain))
}
