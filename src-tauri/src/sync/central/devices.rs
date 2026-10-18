//! Trusted-device management. Service labels never substitute for the anchored membership chain.
use super::{
    api::{AccountOverview, Api, Control, VaultResource},
    client_state::Phase,
    controller::{self, Status},
    crypto::{self, WrappedKeys},
    membership::{Action, MembershipBody, SignedMembership},
    pairing::{PairingInvite, PendingPairing, VaultMinimum},
    wire::{invalid, number, WrapHeader},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};
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
    if before.control.phase != Phase::AwaitingApproval {
        return Err(invalid());
    }
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let encoded = Zeroizing::new(
        env.keychain
            .get(&session.profile.profile()?.slot("pairing"))?
            .ok_or_else(invalid)?,
    );
    let pending = PendingPairing::restore(&encoded, &identity.device())?;
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
pub fn registry(env: &SyncEnv) -> Result<Registry, AppError> {
    controller::require_enabled()?;
    super::round::check_cooldown(env)?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let before = workspace(env)?;
    let session = controller::context(env)?;
    let api = Api::new(&before.control.profile.origin)?;
    let remote = checked_remote(env, &api, &session, &before)?;
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
    let denied: BTreeSet<_> = remote.denied.iter().collect();
    let devices = seen
        .into_iter()
        .map(|(id, keys)| {
            let current = id == before.control.device.id;
            let approved = chain.current().devices().get(&id) == Some(&keys);
            let seen_in_proof = proof.genesis.first.id == id
                || proof.nodes.iter().any(|n| n.body.devices.contains_key(&id));
            DeviceView {
                name: names.remove(&id).unwrap_or_else(|| "Unnamed device".into()),
                state: if denied.contains(&id) {
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
    let before = workspace(env)?;
    if !matches!(before.control.phase, Phase::Enrolled | Phase::Active) {
        return Err(invalid());
    }
    let session = controller::context(env)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let api = Api::new(&before.control.profile.origin)?;
    let remote = checked_remote(env, &api, &session, &before)?;
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
    reply.success()?;
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
