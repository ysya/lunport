//! Local key import and generation. Only encrypted vault material crosses the publication boundary.
use crate::error::AppError;
use crate::sync::env::SyncEnv;
use crate::sync::records_v3::KeySlotPayload;
use crate::vault::generate::KeyAlgorithm;
use crate::vault::store::{EntryOrigin, VaultEntry};
use serde::Serialize;
use zeroize::Zeroizing;
fn check_key_destination(
    env: &SyncEnv,
    invocation: Option<&super::record_import::central_local::Invocation>,
) -> Result<(), AppError> {
    crate::sync::central::migration_flow::require_editable(env)?;
    let core = env.runtime.core.lock().unwrap();
    super::record_import::central_local::check_request(
        super::record_runtime::active_state(&core)?,
        core.generation,
        invocation,
    )
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LocalKeyReceipt {
    pub import_id: String,
    pub key_id: String,
    pub public: KeySlotPayload,
}
/// Explicit native import. Central cutover adds an encrypted outbox; material stays in the protected vault.
pub fn import_local(
    env: &SyncEnv,
    name: &str,
    private: Zeroizing<String>,
    origin: EntryOrigin,
) -> Result<LocalKeyReceipt, AppError> {
    import_local_scoped(env, name, private, origin, None)
}
pub fn import_local_scoped(
    env: &SyncEnv,
    name: &str,
    mut private: Zeroizing<String>,
    origin: EntryOrigin,
    invocation: Option<&super::record_import::central_local::Invocation>,
) -> Result<LocalKeyReceipt, AppError> {
    check_key_destination(env, invocation)?;
    if !crate::sync::slot_rules::valid_slot_name(name) {
        return Err(AppError::Other("local key name is not valid".into()));
    }
    if private.len() as u64 > super::record_import::MAX_PRIVATE_SOURCE_BYTES {
        return Err(AppError::Other(
            "local private material exceeds the supported size limit".into(),
        ));
    }
    let key = crate::vault::material::parse(&private).ok_or_else(|| {
        AppError::Other("local private material is not readable OpenSSH material".into())
    })?;
    if !crate::vault::material::agent_can_sign(key.public_key().key_data())
        || crate::vault::material::unsupported_cipher(&private).is_some()
    {
        return Err(AppError::Other(
            "local private material uses an unsupported key format".into(),
        ));
    }
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|_| AppError::Other("local public identity is not readable".into()))?;
    let fingerprint = key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    drop(key);
    let entry = VaultEntry {
        private_key: std::mem::take(&mut *private),
        public_key,
        fingerprint,
        origin,
        added_at_ms: 0,
    };
    let (receipt, public) = super::record_import::publish_material(env, name, entry, invocation)?;
    let key_id = receipt
        .copied_key_ids
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Other("local key publication has no key receipt".into()))?;
    Ok(LocalKeyReceipt {
        import_id: receipt.import_id,
        key_id,
        public,
    })
}
/// An explicitly chosen file is copied into the Local vault. Its private bytes stay in Rust;
/// the source is never changed, and the same format and publication checks as Paste apply.
pub fn import_local_file(
    env: &SyncEnv,
    name: &str,
    path: &std::path::Path,
) -> Result<LocalKeyReceipt, AppError> {
    import_local_file_scoped(env, name, path, None)
}
pub fn import_local_file_scoped(
    env: &SyncEnv,
    name: &str,
    path: &std::path::Path,
    invocation: Option<&super::record_import::central_local::Invocation>,
) -> Result<LocalKeyReceipt, AppError> {
    check_key_destination(env, invocation)?;
    if !crate::sync::slot_rules::valid_slot_name(name) {
        return Err(AppError::Other("local key name is not valid".into()));
    }
    let bytes =
        super::record_import::bounded_read(path, super::record_import::MAX_PRIVATE_SOURCE_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        AppError::Other("selected file is not readable OpenSSH private key material".into())
    })?;
    import_local_scoped(
        env,
        name,
        Zeroizing::new(text.to_owned()),
        EntryOrigin::Imported,
        invocation,
    )
}
/// Generation stays in memory; the normal explicit Local publication path stores the result.
pub fn generate_local(
    env: &SyncEnv,
    name: &str,
    algorithm: KeyAlgorithm,
    comment: &str,
    passphrase: Option<Zeroizing<String>>,
) -> Result<LocalKeyReceipt, AppError> {
    generate_local_scoped(env, name, algorithm, comment, passphrase, None)
}
pub fn generate_local_scoped(
    env: &SyncEnv,
    name: &str,
    algorithm: KeyAlgorithm,
    comment: &str,
    passphrase: Option<Zeroizing<String>>,
    invocation: Option<&super::record_import::central_local::Invocation>,
) -> Result<LocalKeyReceipt, AppError> {
    check_key_destination(env, invocation)?;
    if !crate::sync::slot_rules::valid_slot_name(name) {
        return Err(AppError::Other("local key name is not valid".into()));
    }
    let private = crate::vault::generate::generate(
        algorithm,
        comment,
        passphrase.as_ref().map(|value| value.as_str()),
    )
    .map_err(|_| AppError::Other("cannot generate a supported local key".into()))?;
    import_local_scoped(env, name, private, EntryOrigin::Generated, invocation)
}
#[cfg(test)]
#[path = "record_keys_tests.rs"]
mod tests;
/// The downloader owns lifecycle. Activation will acquire only vault -> format_publication.
pub fn activate_synced(
    env: &SyncEnv,
    key_id: &str,
    public: KeySlotPayload,
    mut private: Zeroizing<String>,
) -> Result<LocalKeyReceipt, AppError> {
    crate::sync::records_v3::validate_keyslot(key_id, &public)
        .map_err(|_| AppError::Other("synced public key metadata is not valid".into()))?;
    if private.len() as u64 > super::record_import::MAX_PRIVATE_SOURCE_BYTES {
        return Err(AppError::Other(
            "synced private material exceeds the supported size limit".into(),
        ));
    }
    let key = crate::vault::material::parse(&private).ok_or_else(|| {
        AppError::Other("synced private material is not readable OpenSSH material".into())
    })?;
    if !crate::vault::material::agent_can_sign(key.public_key().key_data())
        || crate::vault::material::unsupported_cipher(&private).is_some()
        || key.is_encrypted() != public.has_passphrase
        || Some(key.public_key().key_data().clone())
            != crate::vault::material::public_key_data(&public.public_key)
    {
        return Err(AppError::Other(
            "synced private material does not match authoritative public identity".into(),
        ));
    }
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|_| AppError::Other("synced public identity is not readable".into()))?;
    let fingerprint = key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    drop(key);
    let entry = VaultEntry {
        private_key: std::mem::take(&mut *private),
        public_key,
        fingerprint,
        origin: EntryOrigin::Synced,
        added_at_ms: 0,
    };
    let receipt =
        super::record_import::publish_synced_material(env, key_id, public.clone(), entry)?;
    Ok(LocalKeyReceipt {
        import_id: receipt.import_id,
        key_id: key_id.into(),
        public,
    })
}
