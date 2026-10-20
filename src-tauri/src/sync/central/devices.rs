//! Trusted-device management. Service labels never substitute for the anchored membership chain.
use super::{
    api::{AccountOverview, Api, Control, VaultResource},
    client_state::Phase,
    controller::{self, Status},
    crypto::{self, WrappedKeys},
    membership::{Action, MembershipBody, SignedMembership},
    pairing::{PairingInvite, VaultMinimum},
    wire::{invalid, number, WrapHeader},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroize;
#[derive(Serialize)]
pub struct PairingReveal {
    pub code: String,
    pub expires_at_ms: String,
}
impl Drop for PairingReveal {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}
pub fn pairing_code(env: &SyncEnv) -> Result<PairingReveal, AppError> {
    controller::require_enabled()?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let before = workspace(env)?;
    let session = controller::context(env)?;
    if before.replacement.is_some() || before.control.phase != Phase::AwaitingApproval {
        return Err(invalid());
    }
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let request = before
        .control
        .pending_request
        .as_ref()
        .ok_or_else(invalid)?;
    let pending = controller::load_pairing(
        env,
        &session.profile.profile()?,
        identity,
        &request.request_id,
    )?;
    if before.control.pending_request.as_ref() != Some(pending.request()) {
        return Err(invalid());
    }
    pending.request().verify_live(env.now())?;
    Ok(PairingReveal {
        code: pending.code()?.to_string(),
        expires_at_ms: pending.request().expires_at_ms.clone(),
    })
}
#[derive(Serialize)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub state: String,
    pub fingerprint: String,
    pub current: bool,
}
#[derive(Serialize)]
pub struct Registry {
    pub membership_head: String,
    pub authorization_epoch: String,
    pub devices: Vec<DeviceView>,
}
fn workspace(env: &SyncEnv) -> Result<Workspace, AppError> {
    record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)
}
fn checked_remote(
    env: &SyncEnv,
    api: &Api,
    session: &controller::Session,
    before: &Workspace,
) -> Result<AccountOverview, AppError> {
    let remote = controller::overview(env, api, session)?;
    if remote.proof.as_ref() != before.control.proof.as_ref()
        || remote.auth_epoch != before.control.auth_epoch
    {
        return Err(crate::sync::runtime::superseded());
    }
    Ok(remote)
}
fn remember_denials(
    env: &SyncEnv,
    before: &mut Workspace,
    denied: &[String],
) -> Result<(), AppError> {
    let next = before
        .control
        .remember_denials(denied.iter().map(String::as_str))?;
    if next == before.control {
        return Ok(());
    }
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut records = records.clone();
        records.local.central.as_mut().ok_or_else(invalid)?.control = next.clone();
        Ok(records)
    })?;
    before.control = next;
    env.events.status();
    Ok(())
}
pub fn registry(env: &SyncEnv) -> Result<Registry, AppError> {
    controller::require_enabled()?;
    super::round::check_cooldown(env)?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let mut before = workspace(env)?;
    let session = controller::context(env)?;
    let api = Api::new(&before.control.profile.origin)?;
    let remote = checked_remote(env, &api, &session, &before)?;
    remember_denials(env, &mut before, &remote.denied)?;
    let chain = before.control.verified_chain()?;
    let proof = before.control.proof.as_ref().ok_or_else(invalid)?;
    let mut seen = BTreeMap::from([(
        proof.genesis.first.id.clone(),
        proof.genesis.first.keys.clone(),
    )]);
    for node in &proof.nodes {
        seen.extend(node.body.devices.clone());
    }
    let mut names = BTreeMap::new();
    for d in &remote.devices {
        if seen
            .get(&d.device.id)
            .is_some_and(|keys| keys != &d.device.keys)
            || d.state == "active"
                && chain.current().devices().get(&d.device.id) != Some(&d.device.keys)
        {
            return Err(invalid());
        }
        names.insert(d.device.id.clone(), d.name.clone());
        seen.entry(d.device.id.clone())
            .or_insert_with(|| d.device.keys.clone());
    }
    let denied = &before.control.denied_devices;
    let devices = seen
        .into_iter()
        .map(|(id, keys)| {
            let current = id == before.control.device.id;
            let approved = chain.current().devices().get(&id) == Some(&keys);
            let seen_in_proof = proof.genesis.first.id == id
                || proof.nodes.iter().any(|n| n.body.devices.contains_key(&id));
            DeviceView {
                name: names.remove(&id).unwrap_or_else(|| "Unnamed device".into()),
                state: if denied.contains(&id)
                    && (approved || remote.phase != "ready" || remote.barrier.is_some())
                {
                    "access_blocked"
                } else if approved {
                    "approved"
                } else if seen_in_proof {
                    "revoked"
                } else {
                    "pending"
                }
                .into(),
                fingerprint: crypto::hash(keys.signing.as_bytes()),
                id,
                current,
            }
        })
        .collect();
    Ok(Registry {
        membership_head: chain.current().head().into(),
        authorization_epoch: before.control.auth_epoch.to_string(),
        devices,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultSnapshot {
    vault: String,
    epoch: u64,
    membership_head: String,
    authorization_epoch: String,
    phase: String,
    sequence: String,
    history_hash: String,
}
/// The code commits to the complete request, keys, nonce, root and short expiry. It stays native.
pub fn approve(env: &SyncEnv, code: &str) -> Result<Status, AppError> {
    controller::require_enabled()?;
    if code.len() > 4096 {
        return Err(invalid());
    }
    controller::refresh(env)?;
    super::joining::initialize(env)?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let mut before = workspace(env)?;
    if !matches!(before.control.phase, Phase::Enrolled | Phase::Active) {
        return Err(invalid());
    }
    let session = controller::context(env)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let api = Api::new(&before.control.profile.origin)?;
    let remote = checked_remote(env, &api, &session, &before)?;
    remember_denials(env, &mut before, &remote.denied)?;
    before.require_key_recipients()?;
    let chain = before.control.verified_chain()?;
    if remote.phase != "ready"
        || remote.vaults.len() != 1
        || remote.vaults.values().any(|v| v.rekey)
    {
        return Err(invalid());
    }
    let (request, invite) = remote
        .devices
        .iter()
        .filter_map(|d| d.request.as_ref())
        .find_map(|request| {
            PairingInvite::from_code(code, request, chain.current().anchor(), env.now())
                .ok()
                .map(|invite| (request, invite))
        })
        .ok_or_else(|| {
            AppError::Other(
                "The pairing code is expired or does not match this account's pending request."
                    .into(),
            )
        })?;
    if before.control.denied_devices.contains(&request.device.id) {
        return Err(invalid());
    }
    if chain.current().devices().get(&request.device.id) == Some(&request.device.keys) {
        drop(lifecycle);
        return controller::status(env);
    }
    let replica = before.replica.as_ref().ok_or_else(invalid)?;
    if !replica.baseline_ready() {
        return Err(AppError::Other(
            "Finish verifying this device's existing Vault before approving another device.".into(),
        ));
    }
    let reply = api.vault(
        session.device.as_ref().ok_or_else(invalid)?,
        &replica.vault,
        VaultResource::Metadata,
    )?;
    super::round::require_success(env, &reply)?;
    let metadata: VaultSnapshot = reply.decode()?;
    if metadata.vault != replica.vault
        || metadata.epoch != replica.checkpoint.epoch
        || metadata.phase != "ready"
        || metadata.membership_head != chain.current().head()
        || number(&metadata.authorization_epoch, false)? != before.control.auth_epoch
        || number(&metadata.sequence, true)? != replica.checkpoint.sequence
        || metadata.history_hash != replica.checkpoint.history_hash
    {
        return Err(AppError::Other(
            "Sync and verify the latest Vault history before approving this device.".into(),
        ));
    }
    let own = before
        .own_wraps
        .iter()
        .find(|w| number(&w.header.key_epoch, false).ok() == Some(replica.checkpoint.epoch))
        .ok_or_else(invalid)?;
    let author = chain
        .author_at(&own.header.membership_head, &own.header.author)
        .ok_or_else(invalid)?;
    let keys = own.open(&identity.keys, &own.header, &author.signing)?;
    let mut devices = chain.current().devices().clone();
    devices.insert(request.device.id.clone(), request.device.keys.clone());
    let anchor = chain.current().anchor();
    let node = SignedMembership::sign(
        MembershipBody {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            revision: (chain.current().revision() + 1).to_string(),
            previous_head: chain.current().head().into(),
            author: identity.id.clone(),
            action: Action::Add,
            issued_at_ms: env.now().to_string(),
            enrollment: Some(request.clone()),
            devices,
            recovery: chain.current().recovery().clone(),
        },
        &identity.keys,
    )?;
    let next = chain.current().apply(&node)?;
    let minimum = VaultMinimum {
        vault: replica.vault.clone(),
        creation_head: replica.creation_head.clone(),
        creation_authorization_epoch: replica.creation_authorization_epoch.to_string(),
        key_epoch: replica.checkpoint.epoch.to_string(),
        sequence: replica.checkpoint.sequence.to_string(),
        history_hash: replica.checkpoint.history_hash.clone(),
    };
    let confirmation = invite.confirm(chain.current(), &node, &replica.vault, vec![minimum])?;
    let mut recipients = next.devices().clone();
    recipients.insert("recovery".into(), next.recovery().clone());
    let mut wraps: Vec<WrappedKeys> = vec![];
    for (recipient, public) in recipients {
        wraps.push(crypto::wrap_keys(
            &keys,
            &identity.keys,
            WrapHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: replica.vault.clone(),
                key_epoch: replica.checkpoint.epoch.to_string(),
                membership_head: next.head().into(),
                author: identity.id.clone(),
                recipient,
                recipient_key: public.encryption,
            },
        )?);
    }
    let reply = api.control(session.device.as_ref().ok_or_else(invalid)?,Control::Membership,
        &serde_json::json!({"node":node,"wraps":{&replica.vault:wraps},"confirmation":confirmation}))?;
    super::round::require_success(env, &reply)?;
    drop(lifecycle);
    let status = controller::refresh(env)?;
    if !workspace(env)?
        .control
        .proof
        .as_ref()
        .is_some_and(|p| p.nodes.iter().any(|n| n == &node))
    {
        return Err(AppError::Other(
            "The service has not returned the verified device approval yet. Retry account refresh."
                .into(),
        ));
    }
    Ok(status)
}

#[derive(Serialize)]
pub struct RevokeResult {
    pub status: Status,
    pub access_revoked: bool,
    pub rekey_pending: bool,
    pub barrier_pending: bool,
}
/// Revoke another previously approved device. The UI binds its confirmation to the locally
/// verified membership and full signing fingerprint; intent is durable before any network call.
pub fn revoke(
    env: &SyncEnv,
    device: &str,
    expected_head: &str,
    expected_auth_epoch: &str,
    fingerprint: &str,
) -> Result<RevokeResult, AppError> {
    controller::require_enabled()?;
    super::round::check_cooldown(env)?;
    {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        let mut before = workspace(env)?;
        let chain = before.control.verified_chain()?;
        if device == before.control.device.id
            || !matches!(
                before.control.phase,
                Phase::Enrolled | Phase::Active | Phase::Rekey
            )
            || chain.current().head() != expected_head
            || number(expected_auth_epoch, false)? != before.control.auth_epoch
        {
            return Err(invalid());
        }
        let proof = before.control.proof.as_ref().ok_or_else(invalid)?;
        let public = if proof.genesis.first.id == device {
            Some(&proof.genesis.first.keys)
        } else {
            proof.nodes.iter().find_map(|n| n.body.devices.get(device))
        }
        .ok_or_else(invalid)?;
        if crypto::hash(public.signing.as_bytes()) != fingerprint {
            return Err(invalid());
        }
        remember_denials(env, &mut before, &[device.into()])?;
    }
    // Reconcile an earlier accepted control request (including a lost response) before drafting.
    controller::refresh(env)?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let mut before = workspace(env)?;
    let session = controller::context(env)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let api = Api::new(&before.control.profile.origin)?;
    let remote = checked_remote(env, &api, &session, &before)?;
    remember_denials(env, &mut before, &remote.denied)?;
    let chain = before.control.verified_chain()?;
    if !before.control.denied_devices.contains(device)
        || chain.current().devices().get(&identity.id) != Some(&identity.keys.public())
        || before.control.denied_devices.contains(&identity.id)
    {
        return Err(invalid());
    }
    let mut remaining = chain.current().devices().clone();
    remaining.retain(|id, _| !before.control.denied_devices.contains(id));
    let removing = remaining.len() != chain.current().devices().len();
    if remote.phase == "revocation_pending" || remote.barrier.is_some() {
        let reply = api.control(
            session.device.as_ref().ok_or_else(invalid)?,
            Control::ResumeBarrier,
            &serde_json::json!({}),
        )?;
        super::round::require_success(env, &reply)?;
    } else if removing {
        let node = SignedMembership::sign(
            chain.current().proposal(
                &identity.id,
                Action::Revoke,
                None,
                remaining,
                chain.current().recovery().clone(),
                env.now(),
            ),
            &identity.keys,
        )?;
        // No wraps accompany a revoke. Key rotation begins only after the signed removal and
        // child authorization barriers have been verified through a fresh account snapshot.
        let reply = api.control(
            session.device.as_ref().ok_or_else(invalid)?,
            Control::Membership,
            &serde_json::json!({"node":node,"wraps":{}}),
        )?;
        super::round::require_success(env, &reply)?;
    }
    drop(lifecycle);
    controller::refresh(env)?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let mut after = workspace(env)?;
    let session = controller::context(env)?;
    let remote = checked_remote(env, &api, &session, &after)?;
    remember_denials(env, &mut after, &remote.denied)?;
    let chain = after.control.verified_chain()?;
    let removed = !chain.current().devices().contains_key(device);
    let barrier_pending = remote.phase != "ready" || remote.barrier.is_some();
    Ok(RevokeResult {
        status: controller::status(env)?,
        access_revoked: removed && !barrier_pending,
        barrier_pending,
        rekey_pending: after.control.phase == Phase::Rekey
            || remote.vaults.values().any(|v| v.rekey),
    })
}
