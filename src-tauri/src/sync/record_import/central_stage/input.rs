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
}
impl InitialBinding {
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
            Self::Initial(initial) => {
                let hash = |state: &SyncStateV3| {
                    serde_json::to_vec(state)
                        .map(|b| digest(&b))
                        .map_err(|_| failure("cannot bind initial stage state"))
                };
                Ok(Some(InitialBinding {
                    manifest: initial.manifest().into(),
                    source: hash(initial.source())?,
                    shadow: hash(initial.shadow())?,
                    observed: initial.observed(),
                }))
            }
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
                    || state.local.central_projection.is_some()
                    || state
                        .local
                        .central
                        .as_ref()
                        .is_none_or(|owner| owner.control.cutover)
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
    prepared: &crate::sync::central::InitialPreparation,
    keys: &crate::sync::central::crypto::VaultKeys,
) -> Result<Staged, AppError> {
    with_background(env, |safe| {
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
fn with_background<T>(
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
