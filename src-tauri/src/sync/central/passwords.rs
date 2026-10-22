//! SSH passwords use their own authenticated ciphertext rows, never public host payloads.
//! No password material is Debug/Serialize or returned by a native command.
use super::{
    crypto::{self, DeviceKeys, VaultKeys},
    payload::{self, Data, Identity},
    wire::{invalid, RecordHeader},
};
use crate::{
    error::AppError,
    sync::{
        env::{Keychain, SyncEnv},
        record_import::central_local::{self, Context, Invocation},
        record_repository::{self as repo, HostView, RecordRevision},
        record_runtime,
        records_v3::{AuthKind, SyncStateV3},
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    hostname: String,
    port: u16,
    user: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Material {
    binding: Binding,
    // A secret random nonce also prevents public semantic hashes from being password verifiers.
    nonce: String,
    #[serde(deserialize_with = "secret")]
    value: Zeroizing<String>,
}
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
impl Material {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.value.is_empty()
            || self.value.len() > 16 * 1024
            || !super::wire::hex(&self.nonce, 32)
            || self.binding.hostname.is_empty()
            || self.binding.hostname.len() > 1024
            || self.binding.hostname.chars().any(char::is_control)
            || self.binding.port == 0
            || self.binding.user.is_empty()
            || self.binding.user.len() > 1024
            || self
                .binding
                .user
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn outgoing(&self) -> impl Serialize + '_ {
        #[derive(Serialize)]
        struct Out<'a> {
            binding: &'a Binding,
            nonce: &'a str,
            value: &'a str,
        }
        Out {
            binding: &self.binding,
            nonce: &self.nonce,
            value: &self.value,
        }
    }
}
fn binding(host: &HostView) -> Result<Binding, AppError> {
    if host.group_error.is_some() {
        return Err(invalid());
    }
    let p = &host.effective_payload;
    let user = if p.user.is_empty() {
        crate::session::os_identity::current_username().map_err(|_| invalid())?
    } else {
        p.user.clone()
    };
    Ok(Binding {
        hostname: p.hostname.clone(),
        port: p.port,
        user,
    })
}
fn identity(host: &HostView) -> Identity {
    Identity {
        kind: "password".into(),
        id: host.host.id.clone(),
        scope: Some(host.host.scope.clone()),
    }
}
fn local_slot(env: &SyncEnv, state: &SyncStateV3, host: &HostView) -> Result<String, AppError> {
    let root = env.state_path.to_str().ok_or_else(invalid)?;
    Ok(format!(
        "host-password:v1:{}",
        crypto::hash(
            &serde_json::to_vec(&(
                root,
                &state.device_id,
                &host.host.id,
                &host.host.scope,
                binding(host)?
            ))
            .map_err(|_| invalid())?
        )
    ))
}
fn open(
    state: &SyncStateV3,
    keys: &VaultKeys,
    envelope: &super::crypto::RecordEnvelope,
    hash: &str,
) -> Result<payload::Admitted, AppError> {
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let chain = owner.control.verified_chain()?;
    let h = &envelope.header;
    let author = chain
        .author_at(&h.membership_head, &h.author)
        .ok_or_else(invalid)?;
    let bytes = envelope.verify(&author.signing)?.open(keys)?;
    if crypto::hash(&bytes) != hash {
        return Err(invalid());
    }
    payload::admit(keys, h, &bytes)
}
/// One durable encrypted operation; a missing OS credential never requests deletion.
pub(super) fn enqueue(
    state: &SyncStateV3,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    id: Identity,
    data: Data,
) -> Result<SyncStateV3, AppError> {
    let before = state.local.central.as_ref().ok_or_else(invalid)?;
    if !before.can_upload() || signer.public() != before.control.device.keys {
        return Err(invalid());
    }
    let anchor = before.control.anchor.as_ref().ok_or_else(invalid)?;
    let opaque = id.opaque(keys)?;
    let bytes = payload::encode(&id, &data)?;
    let mut next = state.clone();
    let owner = next.local.central.as_mut().ok_or_else(invalid)?;
    let chain = owner.control.verified_chain()?;
    let replica = owner.replica.as_mut().ok_or_else(invalid)?;
    let revision = replica.pending.get(&opaque).map_or(Ok(1), |p| {
        p.latest.local_revision.checked_add(1).ok_or_else(invalid)
    })?;
    let header = RecordHeader {
        origin: anchor.origin.clone(),
        account_id: anchor.account_id.clone(),
        genesis_hash: anchor.genesis_hash.clone(),
        vault_id: replica.vault.clone(),
        record_id: opaque,
        key_epoch: replica.checkpoint.epoch.to_string(),
        membership_head: chain.current().head().into(),
        author: owner.control.device.id.clone(),
        operation_id: "0".repeat(32),
        expected_revision: "0".into(),
        kind: "password".into(),
        deleted: matches!(data, Data::Deleted),
    };
    replica.enqueue(&chain, keys, signer, revision, header, &bytes)?;
    Ok(next)
}
/// Adopt only bound local slots or legacy credentials for a locally approved exact identity.
/// Existing wire identities, including tombstones, permanently take precedence over legacy slots.
pub(super) fn adopt_saved(
    env: &SyncEnv,
    state: &SyncStateV3,
    keys: &VaultKeys,
    signer: &DeviceKeys,
) -> Result<SyncStateV3, AppError> {
    let mut next = state.clone();
    let mut captured = 0;
    for host in repo::snapshot(state).map_err(|_| invalid())?.hosts {
        if captured == 32 {
            break;
        }
        if host.effective_payload.auth != AuthKind::Password || host.group_error.is_some() {
            continue;
        }
        let id = identity(&host);
        let opaque = id.opaque(keys)?;
        let replica = next
            .local
            .central
            .as_ref()
            .and_then(|o| o.replica.as_ref())
            .ok_or_else(invalid)?;
        if replica.current.contains_key(&opaque) || replica.pending.contains_key(&opaque) {
            continue;
        }
        let bound = binding(&host)?;
        let saved = env
            .keychain
            .get_noninteractive(&local_slot(env, state, &host)?)?;
        let saved = match saved {
            Some(value) => Some(value),
            None if state
                .local
                .credential_approvals
                .get(&host.host.id)
                .is_some_and(|approval| {
                    approval.hostname == bound.hostname
                        && approval.port == bound.port
                        && approval.user == bound.user
                        && approval.scope == host.host.scope
                        && state.local.central.as_ref().is_some_and(|o| {
                            approval.account_id.as_ref() == Some(&o.control.account_id)
                                && approval.relay_url.as_ref() == Some(&o.control.profile.origin)
                                && approval.device_id == o.control.device.id
                        })
                }) =>
            {
                env.keychain
                    .get_noninteractive(&crate::secrets::host_account(&host.host.id))?
            }
            None => None,
        };
        if let Some(value) = saved.filter(|s| !s.is_empty()) {
            let value=Zeroizing::new(value);
            let material = Material {
                binding: bound,
                nonce: crypto::random_id(16)?,
                value,
            };
            next = enqueue(&next, keys, signer, id, Data::Password(material))?;
            captured += 1;
        }
    }
    Ok(next)
}
/// A deleted host also removes its secret. Endpoint edits retain ciphertext but cannot use it.
pub(super) fn capture_removed(
    state: &SyncStateV3,
    keys: &VaultKeys,
    signer: &DeviceKeys,
) -> Result<SyncStateV3, AppError> {
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    let mut rows = std::collections::BTreeMap::new();
    for (opaque, base) in &replica.current {
        if base.version.envelope.header.kind == "password" {
            rows.insert(
                opaque.clone(),
                open(state, keys, &base.version.envelope, &base.content_hash)?,
            );
        }
    }
    for (opaque, pending) in &replica.pending {
        if pending.latest.envelope.header.kind == "password" {
            rows.insert(
                opaque.clone(),
                open(
                    state,
                    keys,
                    &pending.latest.envelope,
                    &pending.latest.content_hash,
                )?,
            );
        }
    }
    let mut next = state.clone();
    for (_, row) in rows {
        if matches!(row.data, Data::Deleted) {
            continue;
        }
        let live = match repo::get_host(state, &row.identity.id) {
            Ok(host) => Some(host.host.scope) == row.identity.scope,
            Err(repo::RepositoryError::Validation(
                crate::sync::records_v3::RecordValidationError::HostNotFound(_),
            )) => false,
            Err(_) => return Err(invalid()),
        };
        if !live {
            next = enqueue(&next, keys, signer, row.identity, Data::Deleted)?;
        }
    }
    Ok(next)
}
/// Native editor mutation. The submitted password is never an ordinary record DTO.
pub(crate) fn change(
    env: &SyncEnv,
    id: &str,
    expected: &RecordRevision,
    generation: u64,
    invocation: Option<&Invocation>,
    value: Option<&str>,
) -> Result<(), AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    let _publication = env.runtime.format_publication.lock().unwrap();
    record_runtime::writes_allowed(&env.runtime.core.lock().unwrap())?;
    let (state, current_generation) = record_runtime::snapshot(env)?;
    if current_generation != generation {
        return Err(crate::sync::runtime::superseded());
    }
    central_local::check_request(&state, current_generation, invocation)?;
    let host = repo::get_host(&state, id).map_err(|_| invalid())?;
    if &host.revision != expected {
        return Err(crate::sync::runtime::superseded());
    }
    if let Some(value) = value {
        Material {
            binding: binding(&host)?,
            nonce: "0".repeat(32),
            value: Zeroizing::new(value.into()),
        }
        .validate()?;
    }
    if state
        .local
        .central
        .as_ref()
        .is_some_and(|o| o.control.cutover)
    {
        let context = Context::load(env, &state)?;
        let data = match value {
            Some(value) => Data::Password(Material {
                binding: binding(&host)?,
                nonce: crypto::random_id(16)?,
                value: Zeroizing::new(value.into()),
            }),
            None => Data::Deleted,
        };
        let candidate = enqueue(
            &state,
            context.keys(),
            context.signer(),
            identity(&host),
            data,
        )?;
        context.verify(env, &state)?;
        record_runtime::commit_candidate(env, generation, candidate)?;
    } else {
        let slot = local_slot(env, &state, &host)?;
        match value {
            Some(value) => env.keychain.set(&slot, value)?,
            // An empty bound slot is a local tombstone. Removing it would fall back to an
            // unbound legacy credential, possibly owned by a different retained workspace.
            None => env.keychain.set(&slot, "")?,
        }
        if record_runtime::snapshot(env)? != (state, current_generation) {
            return Err(crate::sync::runtime::superseded());
        }
    }
    drop(_publication);
    drop(_life);
    env.events.status();
    env.events.wake();
    Ok(())
}
/// Read only after the broker's locally confirmed host-key decision. Every value remains native.
pub(crate) fn read(env: &SyncEnv, id: &str) -> Result<Option<Zeroizing<String>>, AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    let (state, generation) = record_runtime::snapshot(env)?;
    let host = repo::get_host(&state, id).map_err(|_| invalid())?;
    let Some(owner) = state.local.central.as_ref().filter(|o| o.control.cutover) else {
        let value = match env.keychain.get(&local_slot(env, &state, &host)?)? {
            Some(value) => Some(value),
            None => env.keychain.get(&crate::secrets::host_account(id))?,
        };
        return Ok(value.filter(|s| !s.is_empty()).map(Zeroizing::new));
    };
    let context = Context::load(env, &state)?;
    let expected = identity(&host);
    let opaque = expected.opaque(context.keys())?;
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    if replica.conflicts.contains_key(&opaque) {
        return Ok(None);
    }
    let admitted = if let Some(pending) = replica.pending.get(&opaque) {
        Some(open(
            &state,
            context.keys(),
            &pending.latest.envelope,
            &pending.latest.content_hash,
        )?)
    } else if let Some(base) = replica.current.get(&opaque) {
        Some(open(
            &state,
            context.keys(),
            &base.version.envelope,
            &base.content_hash,
        )?)
    } else {
        None
    };
    let value = match admitted {
        Some(row) if row.identity == expected => match row.data {
            Data::Password(material) if material.binding == binding(&host)? => Some(material.value),
            _ => None,
        },
        Some(_) => return Err(invalid()),
        None => env
            .keychain
            .get(&local_slot(env, &state, &host)?)?
            .filter(|s| !s.is_empty())
            .map(Zeroizing::new),
    };
    context.verify(env, &state)?;
    if record_runtime::snapshot(env)? != (state, generation) {
        return Err(crate::sync::runtime::superseded());
    }
    Ok(value)
}

#[tauri::command]
pub async fn records_password_status(
    app: tauri::AppHandle,
    host_id: String,
) -> Result<bool, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let background = super::credentials::Background(env.keychain);
            let safe = SyncEnv {
                doc: env.doc,
                backed_up: env.backed_up,
                retention: env.retention,
                runtime: env.runtime,
                ssh_dir: env.ssh_dir.clone(),
                state_path: env.state_path.clone(),
                home: env.home.clone(),
                keychain: &background,
                relays: env.relays,
                events: env.events,
                clock: env.clock,
                platform: env.platform,
            };
            read(&safe, &host_id).map(|value| value.is_some())
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_password_change(
    app: tauri::AppHandle,
    host_id: String,
    expected: crate::sync::record_commands::RevisionToken,
    generation: String,
    invocation: Option<Invocation>,
    password: Option<String>,
) -> Result<(), AppError> {
    let password = password.map(Zeroizing::new);
    let expected = expected.revision()?;
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            change(
                env,
                &host_id,
                &expected,
                super::wire::number(&generation, true)?,
                invocation.as_ref(),
                password.as_deref().map(|s| s.as_str()),
            )
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

#[cfg(test)]
#[path = "password_tests.rs"]
mod tests;
