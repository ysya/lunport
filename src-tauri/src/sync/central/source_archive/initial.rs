//! A protected reservation precedes initial ciphertext. Attachment never grants migration authority.
use super::*;
use crate::sync::central::source_cursor::{Cursor, Restored};
use std::sync::MutexGuard;
const CAP: usize = 16384;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Stage {
    Reserved,
    Complete { receipt: Receipt },
    Attached { receipt: Receipt },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Initial {
    version: u32,
    selection: Option<String>,
    context: Context,
    // Protected native storage only; never a wire field or frontend preview identifier.
    source: String,
    stage: Stage,
}
fn role(owner: &Workspace) -> Result<String, AppError> {
    let profile = owner.control.profile.profile()?;
    if owner.replacement_archives.is_empty() {
        Ok(profile.slot("source-migration-initial"))
    } else {
        profile.device_slot(
            "source-reconciliation-initial",
            owner.identity_slot.as_deref(),
        )
    }
}
impl Initial {
    fn validate(&self, owner: &Workspace) -> Result<(), AppError> {
        self.context.matches_owner(owner)?;
        if self.version != 1
            || self.selection != owner.identity_slot
            || self.context.device != owner.control.device
            || !hex(&self.source, 64)
        {
            return Err(invalid());
        }
        if let Stage::Complete { receipt } | Stage::Attached { receipt } = &self.stage {
            receipt.matches_selected(owner)?;
            if receipt.context != self.context {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn load(env: &SyncEnv, owner: &Workspace) -> Result<Option<Self>, AppError> {
        let Some(encoded) = env
            .keychain
            .get_noninteractive(&role(owner)?)?
            .map(Zeroizing::new)
        else {
            return Ok(None);
        };
        if encoded.len() > CAP {
            return Err(invalid());
        }
        let value: Self = serde_json::from_str(&encoded).map_err(|_| invalid())?;
        value.validate(owner)?;
        Ok(Some(value))
    }
    fn save(
        &self,
        env: &SyncEnv,
        owner: &Workspace,
        before: Option<&Self>,
    ) -> Result<(), AppError> {
        self.validate(owner)?;
        let current = Self::load(env, owner)?;
        if current.as_ref() == Some(self) {
            return Ok(());
        }
        if current.as_ref() != before {
            return Err(crate::sync::runtime::superseded());
        }
        let bytes = Zeroizing::new(serde_json::to_string(self).map_err(|_| invalid())?);
        if bytes.len() > CAP {
            return Err(invalid());
        }
        env.keychain.set_noninteractive(&role(owner)?, &bytes)?;
        if Self::load(env, owner)?.as_ref() != Some(self) {
            return Err(invalid());
        }
        Ok(())
    }
    fn captured(
        &self,
        env: &SyncEnv,
        owner: &Workspace,
    ) -> Result<(Option<Zeroizing<Vec<u8>>>, Outputs), AppError> {
        self.validate(owner)?;
        if let Stage::Complete { receipt } | Stage::Attached { receipt } = &self.stage {
            let (plain, outputs) =
                restore_with_outputs(env, &owner.control.profile.profile()?, receipt)?;
            if crypto::hash(&plain) != self.source {
                return Err(invalid());
            }
            return Ok((Some(plain), outputs));
        }
        let directory = ArchiveDirectory::open(env, Kind::Source)?;
        let name = self.context.filename()?;
        let marker_name = self.context.marker();
        let blob = directory.read(&name)?;
        let marker = directory.read(&marker_name)?;
        let mut files = vec![];
        let mut original = None;
        if let Some(marker) = marker {
            let key = protected_key(env, &owner.control.profile.profile()?, &self.context, false)?;
            if marker.as_slice() != crypto::hash(key.as_slice()).as_bytes() {
                return Err(invalid());
            }
            files.push((
                std::path::Path::new("data/central-source-archives").join(marker_name),
                marker,
            ));
            if let Some(blob) = blob {
                let plain = decode(&self.context, &key, &blob)?;
                if crypto::hash(&plain) != self.source {
                    return Err(invalid());
                }
                original = Some(plain);
                files.push((
                    std::path::Path::new("data/central-source-archives").join(name),
                    blob,
                ));
            }
        } else if blob.is_some() {
            return Err(invalid());
        }
        directory.sync()?;
        Ok((
            original,
            Outputs {
                scope: self.context.scope()?,
                files,
            },
        ))
    }
    fn outputs(&self, env: &SyncEnv, owner: &Workspace, plain: &[u8]) -> Result<Outputs, AppError> {
        if crypto::hash(plain) != self.source {
            return Err(crate::sync::runtime::superseded());
        }
        let (original, outputs) = self.captured(env, owner)?;
        if original
            .as_ref()
            .is_some_and(|bytes| bytes.as_slice() != plain)
        {
            return Err(invalid());
        }
        Ok(outputs)
    }
    /// Only an uncompleted reservation can create a missing blob. Once a receipt exists,
    /// every missing/corrupt input fails closed through the ordinary immutable readback.
    fn materialize(
        &self,
        env: &SyncEnv,
        owner: &Workspace,
        plain: &Zeroizing<Vec<u8>>,
    ) -> Result<Archived, AppError> {
        self.validate(owner)?;
        if crypto::hash(plain) != self.source {
            return Err(crate::sync::runtime::superseded());
        }
        if self.stage != Stage::Reserved {
            return Err(invalid());
        }
        let profile = owner.control.profile.profile()?;
        let directory = ArchiveDirectory::open(env, Kind::Source)?;
        require_namespace(&directory)?;
        let marker = directory.read(&self.context.marker())?;
        let existing = directory.read(&self.context.filename()?)?;
        if marker.is_none() && existing.is_some() {
            return Err(invalid());
        }
        let key_exists = env
            .keychain
            .get_noninteractive(&self.context.key_role(&profile)?)?
            .map(Zeroizing::new);
        if key_exists.is_none() && marker.is_some() {
            return Err(invalid());
        }
        let key = protected_key(env, &profile, &self.context, key_exists.is_none())?;
        let commitment = crypto::hash(key.as_slice());
        match marker {
            Some(marker) if marker.as_slice() == commitment.as_bytes() => {}
            Some(_) => return Err(invalid()),
            None => directory.publish(&self.context.marker(), commitment.as_bytes())?,
        }
        directory.sync()?;
        write(env, &profile, self.context.clone(), plain, false)
    }
}
/// Native capture re-entry only. This supplies no cursor/freeze/consent authority.
pub(in crate::sync::central) struct Inputs {
    initial: Initial,
    pub(in crate::sync::central) original: Option<Zeroizing<Vec<u8>>>,
    pub(in crate::sync::central) outputs: Outputs,
}
impl Inputs {
    pub(in crate::sync::central) fn matches(&self, plain: &[u8]) -> bool {
        crypto::hash(plain) == self.initial.source
    }
}
pub(in crate::sync::central) fn attached(
    env: &SyncEnv,
    owner: &Workspace,
    cursor: &Cursor,
) -> Result<bool, AppError> {
    let saved = Initial::load(env, owner)?.ok_or_else(invalid)?;
    let receipt = match &saved.stage {
        Stage::Complete { receipt } | Stage::Attached { receipt } => receipt,
        Stage::Reserved => return Err(invalid()),
    };
    if cursor.revision() != 1 || cursor.receipt() != receipt {
        return Err(invalid());
    }
    Ok(matches!(saved.stage, Stage::Attached { .. }))
}
pub(in crate::sync::central) fn inputs(
    env: &SyncEnv,
    life: &MutexGuard<'_, ()>,
    owner: &Workspace,
) -> Result<Option<Inputs>, AppError> {
    let Some(initial) = Initial::load(env, owner)? else {
        return Ok(None);
    };
    if Cursor::load(env, life, owner)?.is_some_and(|saved| saved.cursor.revision() != 1) {
        return Err(AppError::Other("This migration has already started. Resume its saved progress before capturing another source.".into()));
    }
    let (original, outputs) = initial.captured(env, owner)?;
    Ok(Some(Inputs {
        initial,
        original,
        outputs,
    }))
}

/// Requires the caller's current-session/source checks and lifecycle owner. No network or events.
/// A restart uses the saved archive ordinal, never a possibly reset in-memory Core generation.
pub(in crate::sync::central) fn initialize_checked(
    env: &SyncEnv,
    life: &MutexGuard<'_, ()>,
    owner: &Workspace,
    ordinal: u64,
    plain: &Zeroizing<Vec<u8>>,
    mut validate: impl FnMut(&Outputs) -> Result<(), AppError>,
) -> Result<Restored, AppError> {
    if plain.is_empty() || plain.len() > MAX_PLAIN {
        return Err(invalid());
    }
    let cursor = Cursor::load(env, life, owner)?;
    let saved = Initial::load(env, owner)?;
    let fresh = saved.is_none();
    let mut initial = match saved {
        Some(initial) => initial,
        None => {
            if cursor.is_some() {
                return Err(invalid());
            }
            let initial = Initial {
                version: 1,
                selection: owner.identity_slot.clone(),
                context: Context::fresh(owner, ordinal)?,
                source: crypto::hash(plain),
                stage: Stage::Reserved,
            };
            initial
        }
    };
    if crypto::hash(plain) != initial.source {
        return Err(crate::sync::runtime::superseded());
    }
    validate(&initial.outputs(env, owner, plain)?)?;
    if fresh {
        initial.save(env, owner, None)?;
    }
    if let Stage::Attached { receipt } = &initial.stage {
        let cursor = cursor.ok_or_else(invalid)?;
        if cursor.cursor.revision() != 1
            || cursor.cursor.receipt() != receipt
            || cursor.bytes.as_slice() != plain.as_slice()
        {
            return Err(invalid());
        }
        return Ok(cursor);
    }
    let archive = match &initial.stage {
        Stage::Reserved => {
            if cursor.is_some() {
                return Err(invalid());
            }
            let archive = initial.materialize(env, owner, plain)?;
            validate(&archive.outputs(env, &owner.control.profile.profile()?, plain)?)?;
            let completed = Initial {
                stage: Stage::Complete {
                    receipt: archive.receipt().clone(),
                },
                ..initial.clone()
            };
            completed.save(env, owner, Some(&initial))?;
            initial = completed;
            archive
        }
        Stage::Complete { receipt } => resume(env, life, owner, receipt, plain)?,
        Stage::Attached { .. } => return Err(invalid()),
    };
    let restored = Cursor::initialize(env, life, owner, &archive)?;
    validate(&restored.outputs)?;
    let attached = Initial {
        stage: Stage::Attached {
            receipt: archive.receipt().clone(),
        },
        ..initial.clone()
    };
    attached.save(env, owner, Some(&initial))?;
    Ok(restored)
}

#[cfg(test)]
fn initialize(
    env: &SyncEnv,
    life: &MutexGuard<'_, ()>,
    owner: &Workspace,
    ordinal: u64,
    plain: &Zeroizing<Vec<u8>>,
) -> Result<Restored, AppError> {
    initialize_checked(env, life, owner, ordinal, plain, |_| Ok(()))
}

#[cfg(all(test, any(unix, windows)))]
mod tests;

/// Any reserved source capture freezes ordinary edits, including an interrupted first write.
pub(in crate::sync::central) fn pending(
    env: &SyncEnv,
    owner: &Workspace,
) -> Result<bool, AppError> {
    Ok(Initial::load(env, owner)?.is_some())
}
