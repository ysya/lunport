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
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, AppError> {
        serde_json::from_slice(&self.body)
            .map_err(|_| AppError::Other("The account service returned invalid data.".into()))
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
    pub oidc: OidcConfig,
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
    pub fn expired(&self) -> bool {
        self.started.elapsed() >= self.lifetime
    }
}
pub struct Api {
    origin: String,
    http: Client,
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
        })
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
        let mut request = self.http.request(method, format!("{}{path}", self.origin));
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
        let response = request.send().map_err(|_| failure())?;
        let status = response.status().as_u16();
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
        let reply = self.request(Method::GET, "/v2/info", None, None, 65536)?;
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
            ]
            .iter()
            .all(|feature| info.features.iter().any(|f| f == feature))
        {
            return Err(AppError::Other(
                "This service does not support the required account protocol.".into(),
            ));
        }
        info.oidc.validate()?;
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
            "/v2/session",
            Some(&tokens.access),
            Some(body),
            65536,
        )?;
        reply.success()?;
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
        Ok(DeviceSession {
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
        })
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
            "/v2/device-access",
            Some(&tokens.access),
            None,
            1048576,
        )
    }
    pub fn revoke_device_access(
        &self,
        profile: &Profile,
        tokens: &LoginTokens,
        device: &str,
    ) -> Result<Reply, AppError> {
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
            "/v2/device-access/revoke",
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
        self.authenticated(session, Method::GET, "/v2/account", None)
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
            &format!("/v2/vaults/{vault}/{suffix}"),
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
            &format!("/v2/vaults/{vault}/rekey/{}", action.path()),
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
            &format!("/v2/vaults/{vault}/records"),
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
    Recover,
}
impl Control {
    fn path(&self) -> &'static str {
        match self {
            Self::Bootstrap => "/v2/bootstrap",
            Self::Enrollment => "/v2/enrollment",
            Self::Membership => "/v2/membership",
            Self::CreateVault => "/v2/vaults",
            Self::ResumeBarrier => "/v2/barrier/resume",
            Self::Logout => "/v2/logout",
            Self::BatchPull => "/v2/pull",
            Self::RecoveryRead => "/v2/recovery/wraps",
            Self::Recover => "/v2/recovery/commit",
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
        let mock=server.mock("POST","/v2/session").match_header("authorization","Bearer synthetic-access").match_body(mockito::Matcher::PartialJson(json!({"credential":identity.credential(),"session_id":attempt.id,"session_secret":attempt.secret()}))).with_header("content-type","application/json").with_body(json!({"account_id":"a".repeat(64),"account_locator":profile.locator,"device_state":"pending","auth_epoch":1,"expires_at_ms":301000}).to_string()).expect(2).create();
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
            .mock("GET", "/v2/account")
            .match_header("authorization", bearer.as_str())
            .with_status(403)
            .with_body("untrusted echoed secret")
            .create();
        let reply = api.account(&one).unwrap();
        assert_eq!(reply.status, 403);
        assert!(!reply.success().unwrap_err().to_string().contains("echoed"));
    }
    #[test]
    fn rejects_cross_identity_sessions_and_caps_all_response_classes_without_legacy_fallback() {
        let mut server = mockito::Server::new();
        let api = Api::new(&server.url()).unwrap();
        let legacy = server.mock("GET", "/v1/info").expect(0).create();
        server.mock("GET", "/v2/info").with_status(404).create();
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
        server.mock("POST","/v2/session").with_header("content-type","application/json").with_body(json!({"account_id":"a".repeat(64),"account_locator":"b".repeat(64),"device_state":"active","auth_epoch":1,"expires_at_ms":301000}).to_string()).create();
        assert!(api
            .register(&profile, &identity, &attempt, &tokens, "Test", 1000)
            .is_err());
    }
}
