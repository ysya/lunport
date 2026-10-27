//! Explicit /v2 transport. Authentication failure never invokes the legacy relay client.
use super::{
    credentials::{DeviceIdentity, Profile, SessionAttempt},
    oidc::{LoginTokens, OidcConfig},
    wire::{hex, invalid, origin},
};
use crate::error::AppError;
use reqwest::{
    blocking::{Body, Client},
    header::{HeaderValue, AUTHORIZATION},
    Method,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    io::Cursor,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const RESPONSE_CAP: usize = 4 * 1024 * 1024;
/// Public status/cooldown only. Body stays Rust-only and is decoded into the expected DTO.
pub struct Reply {
    pub status: u16,
    pub retry_after: Option<Duration>,
    body: Zeroizing<Vec<u8>>,
}
impl Reply {
    #[cfg(test)]
    pub(super) fn for_test(status:u16, body:&impl Serialize)->Self {
        Self { status, retry_after:None, body:Zeroizing::new(serde_json::to_vec(body).unwrap()) }
    }
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, AppError> {
        serde_json::from_slice(&self.body)
            .map_err(|_| AppError::Other("The account service returned invalid data.".into()))
    }
    /// The relay refused the batch because a record's expected revision is no longer current (409 `revision_conflict`,
    /// `relay/src/v2/store.ts`): nothing of it was written, and a pull reads what changed.
    pub fn refused_revision(&self) -> bool {
        #[derive(Deserialize)]
        struct Refusal {
            error: String,
        }
        self.status == 409 && self.decode::<Refusal>().is_ok_and(|refusal| refusal.error == "revision_conflict")
    }
    pub fn success(&self) -> Result<(), AppError> {
        if (200..300).contains(&self.status) {
            return Ok(());
        }
        let message = match self.status {
            401 => "Sign in again to resume synchronization.",
            403 => "This device is not authorized. Check its approval or revocation status.",
            409 => "The account or record changed. Refresh its verified state before retrying.",
            413 => "Synchronization capacity was reached. Local data has been retained.",
            423 => "Synchronization is waiting for device approval or key rotation.",
            429 => "The account service requested a cooldown. Local changes are retained.",
            _ => "The account service is unavailable. Local changes are retained.",
        };
        Err(AppError::Other(message.into()))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub protocol: u32,
    pub features: Vec<String>,
    pub oidc: Option<OidcConfig>,
    #[serde(default)]pub passkey: Option<super::passkey::Config>,
    #[serde(default)]pub default_auth: Option<String>,
}
impl Info {
    pub fn login_for(
        &self,
        service: &str,
        pinned: Option<&super::client_state::ProfileData>,
    ) -> Result<super::authentication::Config, AppError> {
        self.login_for_method(service, pinned, None)
    }
    pub fn login_for_method(
        &self,
        service: &str,
        pinned: Option<&super::client_state::ProfileData>,
        requested: Option<super::authentication::Method>,
    ) -> Result<super::authentication::Config, AppError> {
        use super::authentication::{Config, Method};
        let oidc = self.oidc.as_ref().map(|c| Config::Oidc(c.clone()));
        let passkey = self.passkey.as_ref().map(|c| Config::Passkey(c.clone()));
        if let Some(Config::Passkey(c)) = &passkey {
            if c.origin != service {
                return Err(invalid());
            }
        }
        for config in [oidc.as_ref(), passkey.as_ref()].into_iter().flatten() {
            config.validate()?;
        }
        if let Some(pinned) = pinned {
            if requested.is_some_and(|method| method != pinned.login.method()) {
                return Err(AppError::Other(
                    "This account uses a different sign-in method. Sign in with its saved method."
                        .into(),
                ));
            }
            return if Some(&pinned.login) == oidc.as_ref()
                || Some(&pinned.login) == passkey.as_ref()
            {
                Ok(pinned.login.clone())
            } else {
                Err(AppError::Other("The account service's sign-in settings changed. Verify the service before signing in again.".into()))
            };
        }
        let method = match requested {
            Some(method) => method,
            None => match self.default_auth.as_deref() {
                Some("passkey") => Method::Passkey,
                Some("oidc") | None => Method::Oidc,
                _ => return Err(invalid()),
            },
        };
        match method {
            Method::Passkey => passkey.ok_or_else(|| {
                AppError::Other("This account service does not offer Passkey sign-in.".into())
            }),
            Method::Oidc => oidc.ok_or_else(|| {
                AppError::Other(
                    "This account service has no external sign-in provider configured.".into(),
                )
            }),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Pending,
    Active,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registered {
    account_id: String,
    account_locator: String,
    device_state: DeviceState,
    auth_epoch: u64,
    expires_at_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountOverview {
    pub account_id: String,
    pub auth_epoch: u64,
    pub device_state: DeviceState,
    pub phase: String,
    pub proof: Option<super::trust::ControlProof>,
    pub genesis_hash: Option<String>,
    pub pairing_confirmation: Option<super::pairing::PairingConfirmation>,
    #[serde(default)]
    pub vaults: std::collections::BTreeMap<String, VaultMetadata>,
    #[serde(default)]
    pub denied: Vec<String>,
    #[serde(default)]
    pub devices: Vec<DeviceMetadata>,
    #[serde(default)]
    pub barrier: Option<Barrier>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultMetadata {
    pub epoch: u64,
    pub rekey: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceMetadata {
    pub device: super::membership::Device,
    pub name: String,
    pub state: String,
    pub request: Option<super::membership::Enrollment>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Barrier {
    pub id: String,
    pub acknowledged: usize,
    pub total: usize,
}
impl AccountOverview {
    pub fn validate(&self, session: &DeviceSession) -> Result<(), AppError> {
        if self.account_id != session.account_id
            || self.auth_epoch != session.auth_epoch
            || self.device_state != session.device_state
            || !["ready", "revocation_pending"].contains(&self.phase.as_str())
            || self.vaults.len() > 64
            || self.devices.len() > 128
            || self
                .devices
                .iter()
                .map(|d| &d.device.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.devices.len()
            || self.denied.len() > 1024
            || self
                .vaults
                .iter()
                .any(|(id, v)| !hex(id, 64) || !(1..=65).contains(&v.epoch))
            || self.denied.iter().any(|id| !hex(id, 32))
            || self.devices.iter().any(|d| {
                !hex(&d.device.id, 32)
                    || d.name.len() > 80
                    || d.name.chars().any(char::is_control)
                    || !["active", "pending", "revoked"].contains(&d.state.as_str())
                    || d.device.keys.validate().is_err()
                    || d.request.as_ref().is_some_and(|r| {
                        r.device != d.device
                            || r.account_id != self.account_id
                            || self
                                .proof
                                .as_ref()
                                .is_none_or(|p| r.origin != p.genesis.origin)
                            || self.genesis_hash.as_ref() != Some(&r.genesis_hash)
                            || r.verify_signature().is_err()
                    })
            })
            || self
                .barrier
                .as_ref()
                .is_some_and(|b| b.id.len() > 192 || b.total > 64 || b.acknowledged > b.total)
        {
            return Err(invalid());
        }
        match (&self.proof, &self.genesis_hash) {
            (Some(proof), Some(root))
                if root == &super::crypto::hash(&proof.genesis.canonical()?) => {}
            (None, None) => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
}
/// Opaque bearer is independent of the signing/encryption keys and is never serialized.
pub struct DeviceSession {
    pub account_id: String,
    pub device_state: DeviceState,
    pub auth_epoch: u64,
    bearer: Zeroizing<String>,
    started: Instant,
    lifetime: Duration,
}
impl DeviceSession {
    #[cfg(test)]
    pub(crate) fn synthetic_for_test(account_id:String,device_state:DeviceState,auth_epoch:u64,lifetime:Duration)->Self {
        Self{account_id,device_state,auth_epoch,bearer:Zeroizing::new("synthetic device grant".into()),started:Instant::now(),lifetime}
    }
    pub fn expired(&self) -> bool {
        self.started.elapsed() >= self.lifetime
    }
}
/// Native-only outcome: callers can distinguish an expired attempt from device denial without
/// parsing user-facing error text or falling back to legacy authorization.
pub enum RegistrationOutcome {
    Accepted(DeviceSession),
    Rejected(Reply),
}
pub struct Api {
    origin: String,
    http: Client,
    budget: Option<super::request_budget::Budget>,
}
impl Api {
    pub fn new(service: &str) -> Result<Self, AppError> {
        if !origin(service) {
            return Err(invalid());
        }
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("Lunport/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| AppError::Other("Could not prepare account synchronization.".into()))?;
        Ok(Self {
            origin: service.into(),
            http,
            budget: None,
        })
    }
    pub(super) fn bounded(
        service: &str,
        budget: &super::request_budget::Budget,
    ) -> Result<Self, AppError> {
        let mut api = Self::new(service)?;
        api.budget = Some(budget.clone());
        Ok(api)
    }
    fn request(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Zeroizing<Vec<u8>>>,
        cap: usize,
    ) -> Result<Reply, AppError> {
        let failure = || {
            AppError::Other(
                "Could not contact the account service. Local changes are retained.".into(),
            )
        };
        #[cfg(test)]
        let transport = TEST_TRANSPORT.with(|slot| {
            slot.borrow().as_ref().filter(|(origin, _)| origin == &self.origin)
                .map(|(_, target)| target.clone()).unwrap_or_else(|| self.origin.clone())
        });
        #[cfg(not(test))]
        let transport = &self.origin;
        let mut request = self.http.request(method, format!("{}{path}", transport));
        if let Some(bearer) = bearer {
            let mut header =
                HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|_| invalid())?;
            header.set_sensitive(true);
            request = request.header(AUTHORIZATION, header);
        }
        if let Some(body) = body {
            let size = body.len() as u64;
            request = request
                .header("content-type", "application/json")
                .body(Body::sized(Cursor::new(body), size));
        }
        if let Some(budget) = &self.budget {
            request = request.timeout(budget.reserve()?.min(Duration::from_secs(30)));
        }
        let response = request.send().map_err(|_| failure())?;
        let status = response.status().as_u16();
        if bearer.is_some() && matches!(status, 401 | 403) {
            if let Some(budget) = &self.budget { budget.note_refusal(); }
        }
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .map(|seconds| Duration::from_secs(seconds.clamp(1, 3600)));
        let cap = cap.min(RESPONSE_CAP);
        if response
            .content_length()
            .is_some_and(|length| length > cap as u64)
        {
            return Err(AppError::Other(
                "The account response exceeded its size limit. Local data has been retained."
                    .into(),
            ));
        }
        let body=Zeroizing::new(crate::sync::relay::read_capped(response,cap).map_err(|_|AppError::Other("The account response was incomplete or exceeded its size limit. Local data has been retained.".into()))?);
        Ok(Reply {
            status,
            retry_after,
            body,
        })
    }
    pub fn info(&self) -> Result<Info, AppError> {
        let reply = self.request(Method::GET, "/v1/info", None, None, 65536)?;
        reply.success()?;
        let info: Info = reply.decode()?;
        if info.protocol != 2
            || info.features.len() > 32
            || ![
                "central-accounts",
                "anchored-membership",
                "exact-revision",
                "operation-receipts",
                "paged-history",
                "signed-rekey",
                "paired-checkpoints",
            ]
            .iter()
            .all(|feature| info.features.iter().any(|f| f == feature))
        {
            return Err(AppError::Other(
                "This service does not support the required account protocol.".into(),
            ));
        }
        drop(info.login_for(&self.origin,None)?);
        Ok(info)
    }
    pub fn register(
        &self,
        profile: &Profile,
        identity: &DeviceIdentity,
        attempt: &SessionAttempt,
        tokens: &LoginTokens,
        name: &str,
        now: u64,
    ) -> Result<DeviceSession, AppError> {
        match self.register_outcome(profile, identity, attempt, tokens, name, now)? {
            RegistrationOutcome::Accepted(session) => Ok(session),
            RegistrationOutcome::Rejected(reply) => {
                reply.success()?;
                Err(invalid())
            }
        }
    }
    pub fn register_outcome(
        &self,
        profile: &Profile,
        identity: &DeviceIdentity,
        attempt: &SessionAttempt,
        tokens: &LoginTokens,
        name: &str,
        now: u64,
    ) -> Result<RegistrationOutcome, AppError> {
        if self.origin != profile.origin
            || tokens.issuer != profile.issuer
            || tokens.subject != profile.subject
            || name.len() > 80
            || name.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        #[derive(Serialize)]
        struct Registration<'a> {
            device: super::membership::Device,
            name: &'a str,
            credential: &'a str,
            session_id: &'a str,
            session_secret: &'a str,
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Registration {
                device: identity.device(),
                name,
                credential: identity.credential(),
                session_id: &attempt.id,
                session_secret: attempt.secret(),
            })
            .map_err(|_| invalid())?,
        );
        let started = Instant::now();
        let reply = self.request(
            Method::POST,
            "/v1/session",
            Some(&tokens.access),
            Some(body),
            65536,
        )?;
        if !(200..300).contains(&reply.status) {
            return Ok(RegistrationOutcome::Rejected(reply));
        }
        let registered: Registered = reply.decode()?;
        if registered.account_locator != profile.locator
            || !hex(&registered.account_id, 64)
            || registered.auth_epoch == 0
            || registered.auth_epoch > super::wire::MAX_SAFE_INTEGER
            || registered.expires_at_ms <= now
            || registered.expires_at_ms - now > 305000
        {
            return Err(AppError::Other(
                "The account session could not be bound to this sign-in identity.".into(),
            ));
        }
        Ok(RegistrationOutcome::Accepted(DeviceSession {
            account_id: registered.account_id,
            device_state: registered.device_state,
            auth_epoch: registered.auth_epoch,
            bearer: Zeroizing::new(format!(
                "v2.{}.{}.{}",
                profile.locator,
                attempt.id,
                attempt.secret()
            )),
            started,
            lifetime: Duration::from_millis((registered.expires_at_ms - now).min(300000)),
        }))
    }
    pub fn device_access(
        &self,
        profile: &Profile,
        tokens: &LoginTokens,
    ) -> Result<Reply, AppError> {
        if self.origin != profile.origin
            || tokens.issuer != profile.issuer
            || tokens.subject != profile.subject
        {
            return Err(invalid());
        }
        self.request(
            Method::GET,
            "/v1/device-access",
            Some(&tokens.access),
            None,
            1048576,
        )
    }
    pub fn revoke_device_access(
        &self,
        profile: &Profile,
        tokens: &super::oidc::FreshLoginTokens,
        device: &str,
    ) -> Result<Reply, AppError> {
        let tokens = tokens.tokens();
        if self.origin != profile.origin
            || tokens.issuer != profile.issuer
            || tokens.subject != profile.subject
            || !hex(device, 32)
        {
            return Err(invalid());
        }
        #[derive(Serialize)]
        struct Revoke<'a> {
            device: &'a str,
        }
        let body = Zeroizing::new(serde_json::to_vec(&Revoke { device }).map_err(|_| invalid())?);
        self.request(
            Method::POST,
            "/v1/device-access/revoke",
            Some(&tokens.access),
            Some(body),
            65536,
        )
    }
    fn authenticated(
        &self,
        session: &DeviceSession,
        method: Method,
        path: &str,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Reply, AppError> {
        if session.expired() {
            return Err(AppError::Other(
                "Renew sign-in before synchronizing this device.".into(),
            ));
        }
        self.request(method, path, Some(&session.bearer), body, RESPONSE_CAP)
    }
    pub fn account(&self, session: &DeviceSession) -> Result<Reply, AppError> {
        self.authenticated(session, Method::GET, "/v1/account", None)
    }
    pub(super) fn unlock_registry(&self, session: &DeviceSession) -> Result<Reply, AppError> {
        self.authenticated(session, Method::GET, "/v1/unlock", None)
    }
    pub fn control<T: Serialize>(
        &self,
        session: &DeviceSession,
        action: Control,
        body: &T,
    ) -> Result<Reply, AppError> {
        let bytes = Zeroizing::new(serde_json::to_vec(body).map_err(|_| invalid())?);
        if bytes.len() > RESPONSE_CAP {
            return Err(invalid());
        }
        self.authenticated(session, Method::POST, action.path(), Some(bytes))
    }
    pub fn vault(
        &self,
        session: &DeviceSession,
        vault: &str,
        resource: VaultResource,
    ) -> Result<Reply, AppError> {
        if !hex(vault, 64) {
            return Err(invalid());
        }
        let suffix = match resource {
            VaultResource::Metadata => "metadata".into(),
            VaultResource::Wrap => "wrap".into(),
            VaultResource::Rekey => "rekey".into(),
            VaultResource::EpochWraps { epoch } => {
                if !(2..=65).contains(&epoch) {
                    return Err(invalid());
                }
                format!("rekey/wraps?epoch={epoch}")
            }
            VaultResource::SourceProof { epoch, after } => {
                if epoch < 2 || epoch > super::wire::MAX_SAFE_INTEGER || after > 16384 {
                    return Err(invalid());
                }
                format!("rekey/source?epoch={epoch}&after={after}")
            }
            VaultResource::Receipt { operation } => {
                if !hex(&operation, 32) {
                    return Err(invalid());
                }
                format!("receipt?operation={operation}")
            }
            VaultResource::Records { since } => {
                if since > super::wire::MAX_SAFE_INTEGER {
                    return Err(invalid());
                }
                format!("records?since={since}")
            }
        };
        self.authenticated(
            session,
            Method::GET,
            &format!("/v1/vaults/{vault}/{suffix}"),
            None,
        )
    }
    pub fn rekey<T: Serialize>(
        &self,
        session: &DeviceSession,
        vault: &str,
        action: RekeyAction,
        body: &T,
    ) -> Result<Reply, AppError> {
        if !hex(vault, 64) {
            return Err(invalid());
        }
        let body = Zeroizing::new(serde_json::to_vec(body).map_err(|_| invalid())?);
        if body.len() > RESPONSE_CAP {
            return Err(invalid());
        }
        self.authenticated(
            session,
            Method::POST,
            &format!("/v1/vaults/{vault}/rekey/{}", action.path()),
            Some(body),
        )
    }
    /// Private-ingress-only protocol. Callers retain native inventory/consent and verify replies.
    pub(super) fn migration_status(
        &self,
        session: &DeviceSession,
        vault: &str,
        freeze: bool,
    ) -> Result<Reply, AppError> {
        if !hex(vault, 64) || session.device_state != DeviceState::Active {
            return Err(invalid());
        }
        let suffix = if freeze {
            "migration/freeze"
        } else {
            "migration"
        };
        self.authenticated(
            session,
            Method::GET,
            &format!("/v1/vaults/{vault}/{suffix}"),
            None,
        )
    }
    fn prepare_freeze(
        &self,
        session: &DeviceSession,
        vault: &str,
        sources: &super::migration_sources::Sources,
        intent: &super::migration_freeze::SignedFreeze,
        next: &[String],
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        if !sources.chains().is_empty() || !intent.body.chains.is_empty() || !next.is_empty() {
            return Err(AppError::Other("Legacy chain migration is no longer available. Original local files are retained; import them into a new Records workspace.".into()));
        }
        if session.expired() {
            return Err(AppError::Other(
                "Renew sign-in before synchronizing this device.".into(),
            ));
        }
        if !hex(vault, 64)
            || session.device_state != DeviceState::Active
            || intent.body.origin != self.origin
            || intent.body.account_id != session.account_id
            || intent.body.vault_id != vault
            || intent.body.authorization_epoch != session.auth_epoch.to_string()
        {
            return Err(invalid());
        }
        let body = sources.freeze_body(intent, next)?;
        if body.len() > RESPONSE_CAP {
            return Err(invalid());
        }
        Ok(body)
    }
    /// Only empty-source central library setup can use this route.
    pub(super) fn freeze_sources(
        &self,
        session: &DeviceSession,
        vault: &str,
        sources: &super::migration_sources::Sources,
        intent: &super::migration_freeze::SignedFreeze,
        next: &[String],
    ) -> Result<Reply, AppError> {
        let body = self.prepare_freeze(session, vault, sources, intent, next)?;
        self.authenticated(
            session,
            Method::POST,
            &format!("/v1/vaults/{vault}/migration/freeze"),
            Some(body),
        )
    }
    /// Historical source reads are closed before any network request.
    pub(super) fn frozen_source(
        &self,
        _session: &DeviceSession,
        _owner: &super::workspace::Workspace,
        _sources: &super::migration_sources::Sources,
        _operation: &str,
        _progress: &super::migration_freeze::Progress,
        _minimum: Option<&super::migration_freeze::Known>,
        _chain: &str,
    ) -> Result<Reply, AppError> {
        Err(AppError::Other("Legacy chain source retrieval is no longer available. Original local files are retained.".into()))
    }
    pub(super) fn migration(
        &self,
        session: &DeviceSession,
        vault: &str,
        action: MigrationAction,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Reply, AppError> {
        if !hex(vault, 64)
            || session.device_state != DeviceState::Active
            || body.is_empty()
            || body.len() > RESPONSE_CAP
        {
            return Err(invalid());
        }
        self.authenticated(
            session,
            Method::POST,
            &format!("/v1/vaults/{vault}/migration/{}", action.path()),
            Some(body),
        )
    }
    pub fn push(
        &self,
        session: &DeviceSession,
        vault: &str,
        records: &[super::crypto::RecordEnvelope],
    ) -> Result<Reply, AppError> {
        if !hex(vault, 64) || records.is_empty() || records.len() > 32 {
            return Err(invalid());
        }
        #[derive(Serialize)]
        struct Push<'a> {
            records: &'a [super::crypto::RecordEnvelope],
        }
        let body = Zeroizing::new(serde_json::to_vec(&Push { records }).map_err(|_| invalid())?);
        if body.len() > RESPONSE_CAP {
            return Err(invalid());
        }
        self.authenticated(
            session,
            Method::POST,
            &format!("/v1/vaults/{vault}/records"),
            Some(body),
        )
    }
}
pub enum Control {
    Bootstrap,
    Enrollment,
    Membership,
    CreateVault,
    ResumeBarrier,
    Logout,
    BatchPull,
    RecoveryRead,
    RecoveryHistory,
    RecoverySource,
    Recover,
    UpdateUnlock,
    UnlockJoin,
}
impl Control {
    fn path(&self) -> &'static str {
        match self {
            Self::Bootstrap => "/v1/bootstrap",
            Self::Enrollment => "/v1/enrollment",
            Self::Membership => "/v1/membership",
            Self::CreateVault => "/v1/vaults",
            Self::ResumeBarrier => "/v1/barrier/resume",
            Self::Logout => "/v1/logout",
            Self::BatchPull => "/v1/pull",
            Self::RecoveryRead => "/v1/recovery/wraps",
            Self::RecoveryHistory => "/v1/recovery/history",
            Self::RecoverySource => "/v1/recovery/source",
            Self::Recover => "/v1/recovery/commit",
            Self::UpdateUnlock => "/v1/unlock",
            Self::UnlockJoin => "/v1/unlock/join",
        }
    }
}
pub enum VaultResource {
    Metadata,
    Wrap,
    Records { since: u64 },
    Rekey,
    EpochWraps { epoch: u64 },
    SourceProof { epoch: u64, after: u64 },
    Receipt { operation: String },
}
#[derive(Clone, Copy)]
pub(super) enum MigrationAction {
    Begin,
    Stage,
    Commit,
    Retire,
}
impl MigrationAction {
    fn path(&self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Stage => "stage",
            Self::Commit => "commit",
            Self::Retire => "retire",
        }
    }
}
pub enum RekeyAction {
    Begin,
    Stage,
    Commit,
    Abort,
    Reconcile,
}
impl RekeyAction {
    fn path(&self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Stage => "stage",
            Self::Commit => "commit",
            Self::Abort => "abort",
            Self::Reconcile => "reconcile",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::env::Keychain;
    use serde_json::json;
    use std::{collections::BTreeMap, sync::Mutex};
    #[test]
    fn only_a_revision_conflict_is_a_refused_revision() {
        assert!(Reply::for_test(409, &json!({"error":"revision_conflict","conflicts":[]})).refused_revision());
        assert!(!Reply::for_test(409, &json!({"error":"retry"})).refused_revision());
        assert!(!Reply::for_test(409, &json!({"error":"operation_reused"})).refused_revision());
        assert!(!Reply::for_test(200, &json!({"error":"revision_conflict"})).refused_revision());
    }
    #[derive(Default)]
    struct Memory(Mutex<BTreeMap<String, String>>);
    impl Keychain for Memory {
        fn get(&self, k: &str) -> Result<Option<String>, AppError> {
            Ok(self.0.lock().unwrap().get(k).cloned())
        }
        fn set(&self, k: &str, v: &str) -> Result<(), AppError> {
            self.0.lock().unwrap().insert(k.into(), v.into());
            Ok(())
        }
        fn delete(&self, k: &str) -> Result<(), AppError> {
            self.0.lock().unwrap().remove(k);
            Ok(())
        }
    }
    #[test]
    fn transport_keeps_auth_in_rust_binds_sessions_and_reuses_response_loss_attempts() {
        let mut server = mockito::Server::new();
        let profile = Profile::new(&server.url(), "https://id.test", "opaque").unwrap();
        let memory = Memory::default();
        let identity = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        let attempt = SessionAttempt::prepare(&memory, &profile, &identity, 1000).unwrap();
        let tokens = LoginTokens {
            issuer: profile.issuer.clone(),
            subject: profile.subject.clone(),
            nonce: Zeroizing::new("nonce".into()),
            access: Zeroizing::new("synthetic-access".into()),
            refresh: None,
            expires_in: Duration::from_secs(300),
        };
        let mock=server.mock("POST","/v1/session").match_header("authorization","Bearer synthetic-access").match_body(mockito::Matcher::PartialJson(json!({"credential":identity.credential(),"session_id":attempt.id,"session_secret":attempt.secret()}))).with_header("content-type","application/json").with_body(json!({"account_id":"a".repeat(64),"account_locator":profile.locator,"device_state":"pending","auth_epoch":1,"expires_at_ms":301000}).to_string()).expect(2).create();
        let api = Api::new(&server.url()).unwrap();
        let one = api
            .register(&profile, &identity, &attempt, &tokens, "Test", 1000)
            .unwrap();
        let two = api
            .register(&profile, &identity, &attempt, &tokens, "Test", 1000)
            .unwrap();
        assert_eq!(one.account_id, two.account_id);
        assert_eq!(one.device_state, DeviceState::Pending);
        assert!(!one.expired());
        mock.assert();
        let bearer = format!(
            "Bearer v2.{}.{}.{}",
            profile.locator,
            attempt.id,
            attempt.secret()
        );
        server
            .mock("GET", "/v1/account")
            .match_header("authorization", bearer.as_str())
            .with_status(403)
            .with_body("untrusted echoed secret")
            .create();
        let reply = api.account(&one).unwrap();
        assert_eq!(reply.status, 403);
        assert!(!reply.success().unwrap_err().to_string().contains("echoed"));
    }
    #[test]
    fn legacy_source_credentials_cannot_be_dispatched_to_any_api_origin() {
        use crate::sync::{
            central::{crypto, migration_freeze::SignedFreeze, migration_sources::Sources},
            crypto::ChainKeys,
            records_v3::SyncStateV3,
            state_v2::AccountState,
        };
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let mut server = mockito::Server::new();
        let api = Api::new(&server.url()).unwrap();
        let parent =
            ChainKeys::from_parts(&"3".repeat(64), &"4".repeat(64), &B64.encode([5u8; 32]))
                .unwrap();
        let mut state:SyncStateV3=serde_json::from_value(json!({"version":3,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap();
        state.account = Some(AccountState::new(&parent.chain_id));
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../fixtures/central-source-freeze-v2.json"
        ))
        .unwrap();
        let mut signed: SignedFreeze =
            serde_json::from_value(fixture["first"]["proof"][0]["intent"].clone()).unwrap();
        signed.body.chains = vec![parent.chain_id.clone()];
        signed.body.parent_chain = parent.chain_id.clone();
        signed = SignedFreeze::sign(
            signed.body,
            &crypto::DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap(),
        )
        .unwrap();
        let grant = DeviceSession::synthetic_for_test(
            signed.body.account_id.clone(),
            DeviceState::Active,
            1,
            Duration::from_secs(300),
        );
        let endpoint = format!("/v1/vaults/{}/migration/freeze", signed.body.vault_id);
        let no_send = server
            .mock("POST", endpoint.as_str())
            .with_status(403)
            .expect(0)
            .create();
        let next = vec![parent.chain_id];
        assert!(api
            .freeze_sources(&grant, &signed.body.vault_id, &sources, &signed, &next)
            .is_err());
        no_send.assert();
        // A matching origin does not reopen retired source transport.
        let same = Api::new(&signed.body.origin).unwrap();
        assert!(same
            .prepare_freeze(&grant, &signed.body.vault_id, &sources, &signed, &next)
            .is_err());
        assert!(same
            .prepare_freeze(&grant, &"b".repeat(64), &sources, &signed, &next)
            .is_err());
        for denied in [
            DeviceSession::synthetic_for_test(
                "b".repeat(64),
                DeviceState::Active,
                1,
                Duration::from_secs(300),
            ),
            DeviceSession::synthetic_for_test(
                grant.account_id.clone(),
                DeviceState::Active,
                2,
                Duration::from_secs(300),
            ),
            DeviceSession::synthetic_for_test(
                grant.account_id.clone(),
                DeviceState::Pending,
                1,
                Duration::from_secs(300),
            ),
            DeviceSession::synthetic_for_test(
                grant.account_id.clone(),
                DeviceState::Active,
                1,
                Duration::ZERO,
            ),
        ] {
            assert!(same
                .prepare_freeze(&denied, &signed.body.vault_id, &sources, &signed, &next)
                .is_err());
        }
    }
    #[test]
    fn migration_transport_uses_only_fixed_private_paths_and_retains_safe_denials() {
        let mut server = mockito::Server::new();
        let api = Api::new(&server.url()).unwrap();
        let grant = DeviceSession::synthetic_for_test(
            "a".repeat(64),
            DeviceState::Active,
            1,
            Duration::from_secs(300),
        );
        let vault = "b".repeat(64);
        let legacy = server
            .mock("POST", mockito::Matcher::Regex("^/legacy/v1/".into()))
            .expect(0)
            .create();
        for action in [
            MigrationAction::Begin,
            MigrationAction::Stage,
            MigrationAction::Commit,
            MigrationAction::Retire,
        ] {
            let mock = server
                .mock(
                    "POST",
                    format!("/v1/vaults/{vault}/migration/{}", action.path()).as_str(),
                )
                .match_header("authorization", "Bearer synthetic device grant")
                .match_body("{\"synthetic\":true}")
                .with_status(503)
                .with_body("never echo a credential")
                .expect(1)
                .create();
            let reply = api
                .migration(
                    &grant,
                    &vault,
                    action,
                    Zeroizing::new(b"{\"synthetic\":true}".to_vec()),
                )
                .unwrap();
            assert_eq!(reply.status, 503);
            assert!(!reply
                .success()
                .unwrap_err()
                .to_string()
                .contains("credential"));
            mock.assert();
        }
        for freeze in [true, false] {
            let suffix = if freeze {
                "migration/freeze"
            } else {
                "migration"
            };
            let mock = server
                .mock("GET", format!("/v1/vaults/{vault}/{suffix}").as_str())
                .with_status(403)
                .expect(1)
                .create();
            assert_eq!(
                api.migration_status(&grant, &vault, freeze).unwrap().status,
                403
            );
            mock.assert();
        }
        let pending = DeviceSession::synthetic_for_test(
            "a".repeat(64),
            DeviceState::Pending,
            1,
            Duration::from_secs(300),
        );
        let expired = DeviceSession::synthetic_for_test(
            "a".repeat(64),
            DeviceState::Active,
            1,
            Duration::ZERO,
        );
        for denied in [&pending, &expired] {
            assert!(api.migration_status(denied, &vault, true).is_err());
            assert!(api
                .migration(
                    denied,
                    &vault,
                    MigrationAction::Begin,
                    Zeroizing::new(b"{}".to_vec())
                )
                .is_err());
        }
        assert!(api
            .migration(
                &grant,
                "../bad",
                MigrationAction::Begin,
                Zeroizing::new(b"{}".to_vec())
            )
            .is_err());
        assert!(api
            .migration(
                &grant,
                &vault,
                MigrationAction::Begin,
                Zeroizing::new(vec![0; RESPONSE_CAP + 1])
            )
            .is_err());
        legacy.assert();
    }
    #[test]
    fn rejects_cross_identity_sessions_and_caps_all_response_classes_without_legacy_fallback() {
        let mut server = mockito::Server::new();
        let api = Api::new(&server.url()).unwrap();
        let legacy = server.mock("GET", "/legacy/v1/info").expect(0).create();
        server.mock("GET", "/v1/info").with_status(404).create();
        assert!(api.info().is_err());
        legacy.assert();
        server
            .mock("GET", "/bounded")
            .with_status(500)
            .with_body("a".repeat(65537))
            .create();
        assert!(api
            .request(Method::GET, "/bounded", None, None, 65536)
            .is_err());
        server
            .mock("GET", "/cooldown")
            .with_status(429)
            .with_header("retry-after", "15")
            .with_body("sensitive error")
            .create();
        let reply = api
            .request(Method::GET, "/cooldown", None, None, 65536)
            .unwrap();
        assert_eq!(reply.retry_after, Some(Duration::from_secs(15)));
        assert!(!reply
            .success()
            .unwrap_err()
            .to_string()
            .contains("sensitive"));
        let profile = Profile::new(&server.url(), "https://id.test", "opaque").unwrap();
        let memory = Memory::default();
        let identity = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        let attempt = SessionAttempt::prepare(&memory, &profile, &identity, 1000).unwrap();
        let tokens = LoginTokens {
            issuer: profile.issuer.clone(),
            subject: profile.subject.clone(),
            nonce: Zeroizing::new("nonce".into()),
            access: Zeroizing::new("access".into()),
            refresh: None,
            expires_in: Duration::from_secs(300),
        };
        server.mock("POST","/v1/session").with_header("content-type","application/json").with_body(json!({"account_id":"a".repeat(64),"account_locator":"b".repeat(64),"device_state":"active","auth_epoch":1,"expires_at_ms":301000}).to_string()).create();
        assert!(api
            .register(&profile, &identity, &attempt, &tokens, "Test", 1000)
            .is_err());
        for status in [401u16, 403, 429] {
            let denied = server
                .mock("POST", "/v1/session")
                .with_status(status as usize)
                .with_header("retry-after", "90")
                .with_body("untrusted echoed secret")
                .expect(1)
                .create();
            match api
                .register_outcome(&profile, &identity, &attempt, &tokens, "Test", 1000)
                .unwrap()
            {
                RegistrationOutcome::Rejected(reply) => {
                    assert_eq!(reply.status, status);
                    assert!(!reply.success().unwrap_err().to_string().contains("echoed"));
                    if status == 429 {
                        assert_eq!(reply.retry_after, Some(Duration::from_secs(90)));
                    }
                }
                RegistrationOutcome::Accepted(_) => panic!("rejected session was accepted"),
            }
            denied.assert();
        }
        legacy.assert();
    }
}

#[cfg(test)]
thread_local! {static TEST_TRANSPORT:std::cell::RefCell<Option<(String,String)>>=const{std::cell::RefCell::new(None)};}
/// Exercise the real HTTP adapter while signed test data retains its HTTPS origin.
#[cfg(test)]
pub(super) fn with_test_transport<T>(origin: &str, target: &str, run: impl FnOnce() -> T) -> T {
    assert!(origin.starts_with("https://"));
    let parsed = reqwest::Url::parse(target).unwrap();
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert!(parsed.port().is_some());
    struct Restore(Option<(String, String)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_TRANSPORT.with(|v| *v.borrow_mut() = self.0.take());
        }
    }
    let old = TEST_TRANSPORT.with(|v| v.replace(Some((origin.into(), target.into()))));
    let _restore = Restore(old);
    run()
}
