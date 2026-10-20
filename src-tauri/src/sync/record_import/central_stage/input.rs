//! Actual source and proposed projection stay distinct for initial staging.
use super::*;
use crate::sync::central::{credentials::Background, InitialProjection};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialBinding {
    manifest: String,
    source: String,
    shadow: String,
    observed: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    reconciliation: bool,
}
impl InitialBinding {
    pub(super) fn manifest(&self) -> &str {
        &self.manifest
    }
    pub(super) fn observed(&self) -> u64 {
        self.observed
    }
    pub(super) fn matches_source(&self, state: &SyncStateV3) -> Result<bool, AppError> {
        Ok(self.source == state_digest(state)?)
    }
    pub fn validate(&self) -> Result<(), AppError> {
        if !hex(&self.manifest, 64)
            || !hex(&self.source, 64)
            || !hex(&self.shadow, 64)
            || self.observed > central::wire::MAX_SAFE_INTEGER
        {
            return Err(failure("initial stage binding is invalid"));
        }
        Ok(())
    }
}
fn state_digest(state: &SyncStateV3) -> Result<String, AppError> {
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(state).map_err(|_| failure("cannot bind initial stage state"))?,
    );
    Ok(digest(&bytes))
}
#[derive(Clone, Copy)]
pub(super) enum Input<'a> {
    Library(&'a LibraryDelta),
    Initial(&'a InitialProjection),
}
impl<'a> Input<'a> {
    pub fn source(self) -> &'a SyncStateV3 {
        match self {
            Self::Library(delta) => delta.before(),
            Self::Initial(initial) => initial.source(),
        }
    }
    pub fn delta(self) -> &'a LibraryDelta {
        match self {
            Self::Library(delta) => delta,
            Self::Initial(initial) => initial.delta(),
        }
    }
    pub fn binding(self) -> Result<Option<InitialBinding>, AppError> {
        match self {
            Self::Library(_) => Ok(None),
            Self::Initial(initial) => Ok(Some(InitialBinding {
                manifest: initial.manifest().into(),
                source: state_digest(initial.source())?,
                shadow: state_digest(initial.shadow())?,
                observed: initial.observed(),
                reconciliation: initial.reconciliation(),
            })),
        }
    }
    pub fn verify_binding(self, binding: Option<&InitialBinding>) -> Result<(), AppError> {
        if self.binding()?.as_ref() != binding {
            return Err(failure(
                "stage belongs to a different migration input; retained",
            ));
        }
        Ok(())
    }
    pub fn validate_source(self, state: &SyncStateV3) -> Result<(), AppError> {
        match self {
            Self::Library(_) => source(state),
            Self::Initial(initial) => {
                crate::sync::records_v3::validate_state(state)
                    .map_err(|_| failure("invalid initial stage source"))?;
                if state != initial.source()
                    || !initial.reconciliation()
                        && (state.local.central_projection.is_some()
                            || state
                                .local
                                .central
                                .as_ref()
                                .is_none_or(|owner| owner.control.cutover))
                    || initial.reconciliation()
                        && !state
                            .local
                            .central
                            .as_ref()
                            .is_some_and(central::replacement_reconciliation_required)
                {
                    return Err(failure(
                        "initial source changed; all source material is retained",
                    ));
                }
                source(initial.shadow())
            }
        }
    }
}
/// These entry points stage locally only, and cannot invoke a credential prompt.
pub(crate) fn prepare(env: &SyncEnv, initial: &InitialProjection) -> Result<Staged, AppError> {
    with_background(env, |safe| prepare_input(safe, Input::Initial(initial)))
}
pub(crate) fn prepare_reserved(
    env: &SyncEnv,
    prepared: &dyn crate::sync::central::InitialTransaction,
    keys: &crate::sync::central::crypto::VaultKeys,
) -> Result<Staged, AppError> {
    with_background(env, |safe| {
        let paths = Paths::new(safe, prepared.operation())?;
        match fs::symlink_metadata(&paths.dir) {
            Ok(_) => {
                let life = safe.runtime.lifecycle.lock().unwrap();
                let _vault = safe
                    .runtime
                    .vault
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _publication = safe.runtime.format_publication.lock().unwrap();
                let effects = initial_effects_locked(safe, prepared, keys, &life)?;
                if effects.empty() {
                    // Only the exact private empty directory under this sealed reservation
                    // can be removed. Unknown files/directories already failed full readback.
                    fs::remove_dir(&paths.dir)?;
                    let root = paths
                        .dir
                        .parent()
                        .ok_or_else(|| failure("reserved stage has no root"))?;
                    fs::File::open(root)?.sync_all()?;
                    if !prepared.original_import_root() {
                        fs::remove_dir(root)?;
                    }
                    fs::File::open(
                        root.parent()
                            .ok_or_else(|| failure("reserved stage has no parent"))?,
                    )?
                    .sync_all()?;
                    prepared.check_locked(safe, keys, &life)?;
                } else {
                    let mut journal: Journal =
                        serde_json::from_slice(&bounded_read(&paths.journal, MAX_JOURNAL_BYTES)?)
                            .map_err(|_| failure("reserved initial stage journal is unreadable"))?;
                    validate_header(&journal, prepared.operation())?;
                    execute(
                        safe,
                        &paths,
                        &mut journal,
                        Input::Initial(prepared.projection()),
                    )?;
                    drop(initial_effects_locked(safe, prepared, keys, &life)?);
                    return Ok(Staged { journal, paths });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        prepare_with_reservation(
            safe,
            Input::Initial(prepared.projection()),
            Some((prepared, keys)),
        )
    })
}
pub(crate) fn resume(
    env: &SyncEnv,
    operation: &str,
    initial: &InitialProjection,
) -> Result<Staged, AppError> {
    with_background(env, |safe| {
        resume_input(safe, operation, Input::Initial(initial))
    })
}
pub(super) fn with_background<T>(
    env: &SyncEnv,
    action: impl FnOnce(&SyncEnv) -> Result<T, AppError>,
) -> Result<T, AppError> {
    // ScopedKeychain validates the only writable vault-master roles and retains their receipts.
    // Fresh initial libraries may need their first scoped master; every operation stays noninteractive.
    let keychain = Background(env.keychain);
    let safe = SyncEnv {
        doc: env.doc,
        backed_up: env.backed_up,
        retention: env.retention,
        runtime: env.runtime,
        ssh_dir: env.ssh_dir.clone(),
        state_path: env.state_path.clone(),
        home: env.home.clone(),
        keychain: &keychain,
        relays: env.relays,
        events: env.events,
        clock: env.clock,
        platform: env.platform,
    };
    action(&safe)
}
