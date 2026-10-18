//! Crash-resumable first-device setup. The recovery authority is held only in a temporary OS slot.
use super::{
    api::{Api, Control, DeviceState, VaultResource},
    client_state::Phase,
    controller::{self, Session, Status},
    credentials::SessionAttempt,
    crypto::{self, VaultKeys, WrappedKeys},
    membership::{personal_vault_id, Genesis},
    recovery::{RecoveryKit, RecoverySeed},
    replica::Replica,
    trust::ControlProof,
    wire::{invalid, WrapHeader},
    workspace::{BootstrapPackage, Workspace},
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    locator: String,
    workspace: Workspace,
    kit: String,
}
impl Drop for Intent {
    fn drop(&mut self) {
        self.kit.zeroize();
    }
}
impl Intent {
    fn validate(&self, session: &Session) -> Result<(), AppError> {
        let identity = session.identity.as_ref().ok_or_else(invalid)?;
        let device = session.device.as_ref().ok_or_else(invalid)?;
        self.workspace.validate()?;
        if self.version != 1
            || self.locator != session.profile.locator
            || self.workspace.control.profile != session.profile
            || self.workspace.control.account_id != device.account_id
            || self.workspace.control.device != identity.device()
            || self
                .workspace
                .bootstrap
                .as_ref()
                .is_none_or(|p| p.submitted)
        {
            return Err(invalid());
        }
        let chain = self.workspace.control.verified_chain()?;
        RecoveryKit::parse(&self.kit)?.current_keys(&chain)?;
        let own = self.workspace.own_wraps.first().ok_or_else(invalid)?;
        own.open(&identity.keys, &own.header, &identity.keys.public().signing)?;
        Ok(())
    }
}
fn load_intent(env: &SyncEnv, session: &Session) -> Result<Option<Intent>, AppError> {
    let profile = session.profile.profile()?;
    env.keychain
        .get(&profile.slot("bootstrap"))?
        .map(|value| {
            let encoded = Zeroizing::new(value);
            if encoded.len() > 65536 {
                return Err(invalid());
            }
            let intent: Intent = serde_json::from_str(&encoded).map_err(|_| invalid())?;
            intent.validate(session)?;
            Ok(intent)
        })
        .transpose()
}
fn workspace(env: &SyncEnv) -> Result<Workspace, AppError> {
    record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)
}
fn publish(env: &SyncEnv, previous: &Workspace, next: &Workspace) -> Result<(), AppError> {
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(previous) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut records = records.clone();
        records.local.central = Some(next.clone());
        Ok(records)
    })?;
    Ok(())
}
/// A dedicated foreground action. Merely signing in never creates a replacement account root.
pub fn prepare(env: &SyncEnv) -> Result<Status, AppError> {
    controller::require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let session = controller::context(env)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let before = workspace(env)?;
    if before.bootstrap.is_some() {
        let intent = load_intent(env, &session)?.ok_or_else(invalid)?;
        if intent.workspace.bootstrap.as_ref().map(|p| &p.wraps)
            != before.bootstrap.as_ref().map(|p| &p.wraps)
            || intent.workspace.control.anchor != before.control.anchor
        {
            return Err(invalid());
        }
        drop(lifecycle);
        return controller::status(env);
    }
    if before.control.anchor.is_some() || before.control.phase != Phase::Setup {
        return Err(invalid());
    }
    let api = Api::new(&session.profile.origin)?;
    let remote = controller::overview(env, &api, &session)?;
    let intent = match load_intent(env, &session)? {
        Some(intent) => {
            // A crash after persisting the OS intent must resume the same root and kit.
            if remote
                .proof
                .as_ref()
                .is_some_and(|p| Some(p) != intent.workspace.control.proof.as_ref())
            {
                return Err(invalid());
            }
            intent
        }
        None => {
            if remote.proof.is_some()
                || !remote.vaults.is_empty()
                || remote.phase != "ready"
                || remote.device_state != DeviceState::Pending
            {
                return Err(invalid());
            }
            let seed = RecoverySeed::generate()?;
            let recovery = seed.keys(&session.profile.origin, &before.control.account_id)?;
            let (genesis, anchor) = Genesis::create(
                &session.profile.origin,
                &before.control.account_id,
                &identity.id,
                &identity.keys,
                &recovery,
            )?;
            let proof = ControlProof {
                genesis,
                nodes: vec![],
            };
            let chain = proof.verify(&anchor, None)?;
            let kit = seed.bind(&chain)?;
            let vault = personal_vault_id(&anchor)?;
            let keys = VaultKeys::generate()?;
            let mut wraps = vec![];
            for (recipient, public) in [
                (&identity.id[..], identity.keys.public()),
                ("recovery", recovery.public()),
            ] {
                wraps.push(crypto::wrap_keys(
                    &keys,
                    &identity.keys,
                    WrapHeader {
                        origin: anchor.origin.clone(),
                        account_id: anchor.account_id.clone(),
                        genesis_hash: anchor.genesis_hash.clone(),
                        vault_id: vault.clone(),
                        key_epoch: "1".into(),
                        membership_head: chain.current().head().into(),
                        author: identity.id.clone(),
                        recipient: recipient.into(),
                        recipient_key: public.encryption,
                    },
                )?);
            }
            let mut next = before.clone();
            next.control = before.control.prepare_bootstrap(proof, anchor, vault)?;
            next.own_wraps = vec![wraps[0].clone()];
            next.bootstrap = Some(BootstrapPackage {
                wraps,
                submitted: false,
            });
            let intent = Intent {
                version: 1,
                locator: session.profile.locator.clone(),
                workspace: next,
                kit: kit.encode_secret()?.to_string(),
            };
            intent.validate(&session)?;
            let encoded = Zeroizing::new(serde_json::to_string(&intent).map_err(|_| invalid())?);
            let profile = session.profile.profile()?;
            env.keychain.set(&profile.slot("bootstrap"), &encoded)?;
            let readback = load_intent(env, &session)?.ok_or_else(invalid)?;
            if readback.workspace != intent.workspace || readback.kit != intent.kit {
                return Err(invalid());
            }
            intent
        }
    };
    publish(env, &before, &intent.workspace)?;
    drop(lifecycle);
    env.events.status();
    controller::status(env)
}
/// Only this dedicated, user-invoked reveal may expose the offline kit; never put it in status/events.
#[derive(Serialize)]
pub struct RecoveryReveal {
    pub root: String,
    pub kit: String,
}
impl Drop for RecoveryReveal {
    fn drop(&mut self) {
        self.kit.zeroize();
    }
}
pub fn reveal(env: &SyncEnv) -> Result<RecoveryReveal, AppError> {
    controller::require_enabled()?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let session = controller::context(env)?;
    let current = workspace(env)?;
    if current.control.phase != Phase::BackupRequired || current.bootstrap.is_none() {
        return Err(invalid());
    }
    let intent = load_intent(env, &session)?.ok_or_else(invalid)?;
    if intent.workspace.control.anchor != current.control.anchor {
        return Err(invalid());
    }
    RecoveryKit::parse(&intent.kit)?.current_keys(&current.control.verified_chain()?)?;
    Ok(RecoveryReveal {
        root: current
            .control
            .anchor
            .as_ref()
            .ok_or_else(invalid)?
            .genesis_hash
            .clone(),
        kit: intent.kit.clone(),
    })
}
fn register(env: &SyncEnv, session: &Session, api: &Api) -> Result<Session, AppError> {
    super::round::check_cooldown(env)?;
    if session
        .tokens_started
        .elapsed()
        .saturating_add(std::time::Duration::from_secs(5))
        >= session.tokens.expires_in
    {
        return Err(AppError::Other("Sign in again to finish account setup. Your saved recovery kit and local data are retained.".into()));
    }
    let profile = session.profile.profile()?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let attempt =
        SessionAttempt::prepare_with_reset(env.keychain, &profile, identity, env.now(), true)?;
    let records = record_runtime::snapshot(env)?.0;
    let device = match api.register_outcome(
        &profile,
        identity,
        &attempt,
        &session.tokens,
        &records.device_name,
        env.now(),
    )? {
        super::api::RegistrationOutcome::Accepted(device) => device,
        super::api::RegistrationOutcome::Rejected(reply) => {
            super::round::require_success(env, &reply)?;
            return Err(invalid());
        }
    };
    Ok(Session {
        device_access_denied: false,
        profile: session.profile.clone(),
        identity: session.identity.clone(),
        tokens: Arc::clone(&session.tokens),
        device: Some(device),
        tokens_started: session.tokens_started,
    })
}
/// Persist consent before network. A lost bootstrap response is reconciled against the pinned root.
pub fn confirm(env: &SyncEnv, expected_root: &str) -> Result<Status, AppError> {
    controller::require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let session = controller::context(env)?;
    let mut before = workspace(env)?;
    if before.control.phase != Phase::BackupRequired
        || before
            .control
            .anchor
            .as_ref()
            .map(|a| a.genesis_hash.as_str())
            != Some(expected_root)
    {
        return Err(invalid());
    }
    let package = before.bootstrap.as_ref().ok_or_else(invalid)?;
    // If the kit was deleted just before a failed local write, the public submitted intent still
    // permits reconciliation. It never permits showing a new kit or replacing a root.
    match load_intent(env, &session)? {
        Some(intent)
            if intent.workspace.control.anchor == before.control.anchor
                && intent.workspace.bootstrap.as_ref().map(|p| &p.wraps)
                    == Some(&package.wraps) => {}
        None if package.submitted => {}
        _ => return Err(invalid()),
    }
    let mut next = before.clone();
    next.control = next.control.confirm_backup()?;
    next.bootstrap.as_mut().ok_or_else(invalid)?.submitted = true;
    publish(env, &before, &next)?;
    before = next;
    let api = Api::new(&session.profile.origin)?;
    let session = register(env, &session, &api)?;
    #[derive(Serialize)]
    struct Request<'a> {
        genesis: &'a Genesis,
        vault: &'a str,
        wraps: &'a [WrappedKeys],
    }
    let proof = before.control.proof.as_ref().ok_or_else(invalid)?;
    let vault = before.control.personal_vault.as_ref().ok_or_else(invalid)?;
    let package = before.bootstrap.as_ref().ok_or_else(invalid)?;
    let response = api.control(
        session.device.as_ref().ok_or_else(invalid)?,
        Control::Bootstrap,
        &Request {
            genesis: &proof.genesis,
            vault,
            wraps: &package.wraps,
        },
    )?;
    if ![200, 202, 409].contains(&response.status) {
        super::round::require_success(env, &response)?;
    }
    let session = register(env, &session, &api)?;
    let mut remote = controller::overview(env, &api, &session)?;
    remote.proof.as_ref().ok_or_else(invalid)?.verify(
        before.control.anchor.as_ref().ok_or_else(invalid)?,
        before.control.highwater.as_ref(),
    )?;
    if remote.phase == "revocation_pending" {
        api.control(
            session.device.as_ref().ok_or_else(invalid)?,
            Control::ResumeBarrier,
            &serde_json::json!({}),
        )?
        .success()?;
        remote = controller::overview(env, &api, &session)?;
    }
    let remote_proof = remote.proof.take().ok_or_else(invalid)?;
    let chain = remote_proof.verify(
        before.control.anchor.as_ref().ok_or_else(invalid)?,
        before.control.highwater.as_ref(),
    )?;
    if remote.phase != "ready"
        || remote.vaults.len() != 1
        || remote
            .vaults
            .get(vault)
            .is_none_or(|v| v.epoch != 1 || v.rekey)
        || chain.current().revision() != 0
        || session.device.as_ref().ok_or_else(invalid)?.device_state != DeviceState::Active
    {
        return Err(AppError::Other(
            "Account setup is not fully acknowledged. Keep your recovery kit and retry.".into(),
        ));
    }
    let reply = api.vault(
        session.device.as_ref().ok_or_else(invalid)?,
        vault,
        VaultResource::Wrap,
    )?;
    super::round::require_success(env, &reply)?;
    let own: WrappedKeys = reply.decode()?;
    if before.own_wraps.first() != Some(&own) {
        return Err(invalid());
    }
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    own.open(&identity.keys, &own.header, &identity.keys.public().signing)?;
    // Remove the temporary independent recovery authority before enabling any future upload.
    let profile = session.profile.profile()?;
    env.keychain.delete(&profile.slot("bootstrap"))?;
    if env.keychain.get(&profile.slot("bootstrap"))?.is_some() {
        return Err(invalid());
    }
    let mut next = before.clone();
    next.control = next
        .control
        .observe_proof(remote_proof, remote.auth_epoch)?
        .finish_bootstrap()?;
    next.bootstrap = None;
    next.replica = Some(Replica::new(
        vault.clone(),
        chain.current().head().into(),
        remote.auth_epoch,
    )?);
    publish(env, &before, &next)?;
    {
        let mut core = env.runtime.core.lock().unwrap();
        core.central_session = Some(Arc::new(session));
        core.central_user_action = None;
    }
    drop(lifecycle);
    env.runtime.note_activity(env.now());
    env.events.status();
    env.events.wake_implicit();
    controller::status(env)
}

#[cfg(test)]
mod tests {
    use super::super::{
        credentials::Profile,
        oidc::{LoginTokens, OidcConfig},
    };
    use super::*;
    use crate::sync::{
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    use serde_json::json;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };
    struct Fixture {
        device: TestDevice,
        server: mockito::ServerGuard,
        published: Arc<Mutex<Option<Workspace>>>,
        committed: Arc<AtomicBool>,
        posts: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
    }
    impl Fixture {
        fn new() -> Self {
            let d = TestDevice::new("a", &FakeRelay::new(), &TestClock::new());
            let env = d.env();
            let probe = record_runtime::probe_startup(&env.state_path, "central");
            record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
            let mut server = mockito::Server::new();
            let config = OidcConfig {
                issuer: "https://identity.test".into(),
                client_id: "native".into(),
                scopes: vec![],
                audience: Some("api".into()),
            };
            let profile = Profile::new(&server.url(), &config.issuer, "opaque").unwrap();
            let committed = Arc::new(AtomicBool::new(false));
            let c = Arc::clone(&committed);
            let now = env.now();
            server.mock("POST", "/v2/session").with_header("content-type", "application/json")
                .with_body_from_request(move |_| {
                    let active = c.load(Ordering::SeqCst);
                    json!({"account_id":"a".repeat(64),"account_locator":profile.locator,"device_state":if active {"active"} else {"pending"},"auth_epoch":if active {2} else {1},"expires_at_ms":now+300000}).to_string().into_bytes()
                }).create();
            let published: Arc<Mutex<Option<Workspace>>> = Arc::new(Mutex::new(None));
            let state = Arc::clone(&published);
            let c = Arc::clone(&committed);
            server.mock("GET", "/v2/account").with_header("content-type", "application/json")
                .with_body_from_request(move |_| {
                    if c.load(Ordering::SeqCst) {
                        let lock = state.lock().unwrap();let ws = lock.as_ref().unwrap();
                        let vault = ws.control.personal_vault.as_ref().unwrap();
                        json!({"account_id":"a".repeat(64),"device_state":"active","auth_epoch":2,"phase":"ready","proof":ws.control.proof,
                            "genesis_hash":ws.control.anchor.as_ref().unwrap().genesis_hash,"pairing_confirmation":null,"vaults":{vault:{"epoch":1,"rekey":false}}}).to_string().into_bytes()
                    } else { json!({"account_id":"a".repeat(64),"device_state":"pending","auth_epoch":1,"phase":"ready","proof":null,"genesis_hash":null,"pairing_confirmation":null}).to_string().into_bytes() }
                }).create();
            controller::establish(
                &env,
                &server.url(),
                config.clone(),
                LoginTokens {
                    issuer: config.issuer,
                    subject: "opaque".into(),
                    nonce: Zeroizing::new("synthetic nonce".into()),
                    access: Zeroizing::new("synthetic access".into()),
                    refresh: Some(Zeroizing::new("synthetic refresh".into())),
                    expires_in: std::time::Duration::from_secs(300),
                },
                None,
            )
            .unwrap();
            Self {
                device: d,
                server,
                published,
                committed,
                posts: Arc::new(AtomicUsize::new(0)),
                requests: Arc::new(Mutex::new(vec![])),
            }
        }
        fn prepared(&mut self) -> RecoveryReveal {
            prepare(&self.device.env()).unwrap();
            let ws = workspace(&self.device.env()).unwrap();
            *self.published.lock().unwrap() = Some(ws.clone());
            let c = Arc::clone(&self.committed);
            let posts = Arc::clone(&self.posts);
            let requests = Arc::clone(&self.requests);
            self.server
                .mock("POST", "/v2/bootstrap")
                .with_body_from_request(move |r| {
                    posts.fetch_add(1, Ordering::SeqCst);
                    requests
                        .lock()
                        .unwrap()
                        .push(r.utf8_lossy_body().unwrap().into_owned());
                    c.store(true, Ordering::SeqCst);
                    b"{}".to_vec()
                })
                .create();
            self.server
                .mock(
                    "GET",
                    format!(
                        "/v2/vaults/{}/wrap",
                        ws.control.personal_vault.as_ref().unwrap()
                    )
                    .as_str(),
                )
                .with_header("content-type", "application/json")
                .with_body(serde_json::to_string(&ws.own_wraps[0]).unwrap())
                .create();
            reveal(&self.device.env()).unwrap()
        }
    }
    #[test]
    fn backup_confirmation_is_bound_to_the_root_and_does_not_enable_library_upload() {
        let mut f = Fixture::new();
        let kit = f.prepared();
        let env = f.device.env();
        let saved = workspace(&env).unwrap();
        assert!(confirm(&env, &"b".repeat(64)).is_err());
        assert_eq!(f.posts.load(Ordering::SeqCst), 0);
        assert!(!serde_json::to_string(&saved).unwrap().contains("LPREC2:"));
        assert!(!serde_json::to_string(&controller::status(&env).unwrap())
            .unwrap()
            .contains("LPREC2:"));
        assert_eq!(prepare(&env).unwrap().phase, "backup_required");
        assert_eq!(reveal(&env).unwrap().kit, kit.kit);
        let result = confirm(&env, &kit.root).unwrap();
        assert_eq!(result.phase, "enrolled");
        assert!(!result.can_sync);
        let ws = workspace(&env).unwrap();
        assert!(!ws.control.cutover);
        assert!(ws.control.library.is_none());
        assert!(ws.bootstrap.is_none());
        assert!(ws.replica.unwrap().current.is_empty());
        assert!(reveal(&env).is_err());
        assert!(load_intent(&env, &controller::context(&env).unwrap())
            .unwrap()
            .is_none());
        for request in f.requests.lock().unwrap().iter() {
            assert!(!request.contains("LPREC2:"));
            assert!(!request.contains(&kit.kit));
        }
        assert_eq!(f.posts.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn failed_recovery_secret_cleanup_retains_submitted_intent_and_retries_the_same_root() {
        let mut f = Fixture::new();
        let kit = f.prepared();
        let env = f.device.env();
        f.device.keychain.fail_deletes.store(true, Ordering::SeqCst);
        assert!(confirm(&env, &kit.root).is_err());
        let ws = workspace(&env).unwrap();
        assert!(ws.bootstrap.as_ref().unwrap().submitted);
        assert_eq!(ws.control.phase, Phase::BackupRequired);
        assert!(ws.control.recovery_backup_confirmed);
        assert!(!ws.can_upload());
        assert_eq!(reveal(&env).unwrap().kit, kit.kit);
        f.device
            .keychain
            .fail_deletes
            .store(false, Ordering::SeqCst);
        assert_eq!(confirm(&env, &kit.root).unwrap().phase, "enrolled");
        let requests = f.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
    }
    #[test]
    fn an_os_intent_written_before_a_failed_state_save_resumes_without_regenerating_keys() {
        let f = Fixture::new();
        let env = f.device.env();
        let before = workspace(&env).unwrap();
        let backup = env.state_path.with_extension("test-backup");
        std::fs::rename(&env.state_path, &backup).unwrap();
        std::fs::create_dir(&env.state_path).unwrap();
        assert!(prepare(&env).is_err());
        let session = controller::context(&env).unwrap();
        let intent = load_intent(&env, &session).unwrap().unwrap();
        assert_eq!(workspace(&env).unwrap(), before);
        std::fs::remove_dir(&env.state_path).unwrap();
        std::fs::rename(&backup, &env.state_path).unwrap();
        assert_eq!(prepare(&env).unwrap().phase, "backup_required");
        assert_eq!(workspace(&env).unwrap(), intent.workspace);
        assert_eq!(reveal(&env).unwrap().kit, intent.kit);
    }
    #[test]
    fn signing_out_during_backup_keeps_the_same_kit_and_resumes_only_after_signing_in() {
        let mut f = Fixture::new();
        let kit = f.prepared();
        let env = f.device.env();
        f.server
            .mock("POST", "/v2/logout")
            .with_status(204)
            .create();
        let previous = controller::context(&env).unwrap();
        let result = controller::sign_out(&env).unwrap();
        assert_eq!(result.phase, "signed_out");
        assert!(!result.has_session);
        assert!(controller::context(&env).is_err());
        assert!(reveal(&env).is_err());
        let tokens = LoginTokens {
            issuer: previous.tokens.issuer.clone(),
            subject: previous.tokens.subject.clone(),
            nonce: previous.tokens.nonce.clone(),
            access: previous.tokens.access.clone(),
            refresh: previous.tokens.refresh.clone(),
            expires_in: previous.tokens.expires_in,
        };
        let status = controller::establish(
            &env,
            &f.server.url(),
            previous.profile.oidc.clone(),
            tokens,
            None,
        )
        .unwrap();
        assert_eq!(status.phase, "backup_required");
        assert!(!status.can_sync);
        assert_eq!(reveal(&env).unwrap().kit, kit.kit);
    }
    #[test]
    fn reveal_refuses_an_old_kit_after_a_verified_recovery_authority_change() {
        use super::super::{
            crypto::DeviceKeys,
            membership::{Action, SignedMembership},
        };
        let f = Fixture::new();
        prepare(&f.device.env()).unwrap();
        let original = reveal(&f.device.env()).unwrap();
        let session = controller::context(&f.device.env()).unwrap();
        let identity = session.identity.as_ref().unwrap();
        record_runtime::mutate_records(&f.device.env(), |records| {
            let mut records = records.clone();
            let workspace = records.local.central.as_mut().unwrap();
            let chain = workspace.control.verified_chain()?;
            let node = SignedMembership::sign(
                chain.current().proposal(
                    &identity.id,
                    Action::Recovery,
                    None,
                    chain.current().devices().clone(),
                    DeviceKeys::generate()?.public(),
                    f.device.env().now(),
                ),
                &identity.keys,
            )?;
            let mut proof = workspace.control.proof.clone().unwrap();
            proof.nodes.push(node);
            workspace.control = workspace
                .control
                .observe_proof(proof, workspace.control.auth_epoch + 1)?;
            Ok(records)
        })
        .unwrap();
        assert!(reveal(&f.device.env()).is_err());
        assert!(RecoveryKit::parse(&original.kit).is_ok());
    }
}
