//! The Cloud SQL Admin API (`sqladmin.googleapis.com`, v1) as a database connection uses it. Three calls: an instance's connect settings (its
//! public address, the certificate authority behind its server certificate and the name that certificate is made out to); a client
//! certificate that Cloud SQL signs for a key made for the connection and stamps with the caller's access token, which is what lets the
//! instance sign the caller in with Google IAM instead of a password; and a project's PostgreSQL instances, for the form that adds a
//! database. Every call carries the bearer token of a `TokenSource`, every failure is a `GcpError` sentence, and the `SqlAdmin` trait lets
//! the code that connects script the answers.

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::auth::{user_agent, Token, TokenSource};
use super::pam::parse_rfc3339;
use super::rest::{describe, query, GcpError, HTTP_TIMEOUT};

const SQLADMIN_BASE: &str = "https://sqladmin.googleapis.com";
/// How the sentences name this API (`{account} may not call the Cloud SQL Admin API`).
const API: &str = "Cloud SQL Admin";
/// The most pages of the instance list that are read; a project with more instances than that many pages hold is listed up to there.
const LIST_PAGES: usize = 10;
/// The most characters of the API's own words that a refusal repeats.
const REFUSAL_CHARS: usize = 256;
const KEY_BITS: usize = 2048;
/// The database flag that lets an instance sign in Google accounts (`on`), and the value that does.
const IAM_FLAG: &str = "cloudsql.iam_authentication";

/// A Cloud SQL instance by the parts of its connection name, `project:region:instance`. The Admin API finds an instance by its project and
/// name alone; the region is there to name the connection in sentences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceRef {
    pub project: String,
    pub region: String,
    pub instance: String,
}

/// What an instance's connect settings tell a client that dials it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectSettings {
    /// The instance's public address; `None` when it has none (a private-only instance).
    pub public_ip: Option<IpAddr>,
    /// `serverCaCert.cert` as Cloud SQL sent it. It can hold several PEM certificates, and the connection trusts all of them.
    pub server_ca_pem: String,
    /// The name the server certificate is made out to, without the trailing dot of a DNS name: the first name Cloud SQL lists, else the
    /// legacy single one. `None` for an instance with neither.
    pub dns_name: Option<String>,
    /// The engine and version, such as `POSTGRES_16`; empty when Cloud SQL leaves it out.
    pub database_version: String,
}

/// A client certificate Cloud SQL signed for an `EphemeralKey`. The access token is inside it, so the text is as secret as the token:
/// `Debug` leaves it out.
#[derive(Clone, PartialEq, Eq)]
pub struct EphemeralCert {
    pub cert_pem: String,
    /// When the certificate stops being useful: the earlier of its own expiry and the end of the token inside it.
    pub expires_at: SystemTime,
    /// The Google account the certificate, and the token inside it, belong to, as the token source resolved it.
    pub account: String,
}

impl fmt::Debug for EphemeralCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralCert").field("account", &self.account).field("expires_at", &self.expires_at).field("cert_pem", &"<redacted>").finish()
    }
}

/// A PostgreSQL instance as the New database form lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct InstanceSummary {
    pub name: String,
    pub region: String,
    pub database_version: String,
    /// Whether the instance has a public address.
    pub public_ip: bool,
    /// Whether the instance has a private address.
    pub private_ip: bool,
    /// Whether the instance signs in Google accounts (its `cloudsql.iam_authentication` flag is `on`).
    pub iam_authentication: bool,
}

/// The throwaway RSA key a connection's client certificate is made for. The private half is kept as PKCS#8 bytes that are zeroed when the
/// key is dropped; nothing prints it.
pub struct EphemeralKey {
    public_pem: String,
    private_der: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKey").field("private_key", &"<redacted>").finish_non_exhaustive()
    }
}

impl EphemeralKey {
    /// A new 2048-bit RSA key. Making one takes a moment of computing, so a caller on an async task makes it on the blocking pool.
    pub fn generate() -> Result<EphemeralKey, String> {
        let failed = |error: &dyn fmt::Display| format!("A key for the connection could not be made: {error}");
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, KEY_BITS).map_err(|error| failed(&error))?;
        let public_pem = rsa::RsaPublicKey::from(&private).to_public_key_pem(LineEnding::LF).map_err(|error| failed(&error))?;
        // The key and the document it is encoded into zero themselves when they drop at the end of this function.
        let private_der = private.to_pkcs8_der().map_err(|error| failed(&error))?.to_bytes();
        Ok(EphemeralKey { public_pem, private_der })
    }

    /// The public key as a SubjectPublicKeyInfo PEM (`-----BEGIN PUBLIC KEY-----`), which is what Cloud SQL signs a certificate for.
    pub fn public_pem(&self) -> &str {
        &self.public_pem
    }

    /// The private key as PKCS#8, for the TLS client configuration. This is a copy that the caller owns (`PrivateKeyDer` implements
    /// `Zeroize`, and rustls does not clear what it is given): the key's own bytes are zeroed when the `EphemeralKey` drops.
    pub fn private_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_der.to_vec()))
    }
}

/// The Cloud SQL Admin API calls a database connection makes. `account` names a Google account (an email) or asks for the default one,
/// as for `TokenSource`. The calls block on network round trips (and on the token source), so they are made from a blocking context,
/// `spawn_blocking` or a worker thread, never on an async task's own thread, as the token source's are.
pub trait SqlAdmin: Send + Sync {
    /// The instance's public address, server certificate authority and DNS name.
    fn connect_settings(&self, account: Option<&str>, at: &InstanceRef) -> Result<ConnectSettings, GcpError>;
    /// Has Cloud SQL sign a client certificate for `key`, with the caller's access token inside it: that is what lets the instance sign the
    /// caller in with Google IAM. The certificate's `expires_at` is capped at the token's end, after which the instance no longer signs
    /// anyone in with it.
    fn ephemeral_cert(&self, account: Option<&str>, at: &InstanceRef, key: &EphemeralKey) -> Result<EphemeralCert, GcpError>;
    /// The PostgreSQL instances of `project`, in the order the API lists them (ten pages at most).
    fn list_instances(&self, account: Option<&str>, project: &str) -> Result<Vec<InstanceSummary>, GcpError>;
}

/// `SqlAdmin` over HTTPS. It is separate from `RestClient`, which the broker's `GcpClient` fakes stand for.
pub struct RestSqlAdmin {
    tokens: Arc<dyn TokenSource>,
    http: reqwest::blocking::Client,
    base: String,
}

impl RestSqlAdmin {
    pub fn new(tokens: Arc<dyn TokenSource>) -> RestSqlAdmin {
        RestSqlAdmin::with_base(tokens, SQLADMIN_BASE)
    }

    /// The client against another base URL (tests point it at a mock server).
    pub fn with_base(tokens: Arc<dyn TokenSource>, base: &str) -> RestSqlAdmin {
        RestSqlAdmin::with_timeout(tokens, base, HTTP_TIMEOUT)
    }

    /// `with_base` with the per-call timeout given (a test uses a short one).
    fn with_timeout(tokens: Arc<dyn TokenSource>, base: &str, timeout: Duration) -> RestSqlAdmin {
        let http = reqwest::blocking::Client::builder().timeout(timeout).user_agent(user_agent()).build().expect("the REST client builds from fixed options");
        RestSqlAdmin { tokens, http, base: base.trim_end_matches('/').to_string() }
    }

    fn token(&self, account: Option<&str>) -> Result<Token, GcpError> {
        self.tokens.access_token(account).map_err(GcpError::Auth)
    }

    /// Sends `request` with `token` as its bearer and answers the JSON of a success; any other answer is the error for it.
    fn send(&self, token: &Token, subject: &Subject<'_>, request: reqwest::blocking::RequestBuilder) -> Result<serde_json::Value, GcpError> {
        let response = request.bearer_auth(token.value.as_str()).send().map_err(|error| GcpError::Network(describe(&error)))?;
        let status = response.status().as_u16();
        let body = response.text().map_err(|error| GcpError::Network(describe(&error)))?;
        if (200..300).contains(&status) {
            // What the parser says about a body it cannot read is left out: it quotes the text, and a certificate carries the access token.
            return serde_json::from_str(&body).map_err(|_| GcpError::Malformed(format!("the {API} API did not answer with JSON")));
        }
        Err(refusal(status, &body, token, subject))
    }
}

impl SqlAdmin for RestSqlAdmin {
    fn connect_settings(&self, account: Option<&str>, at: &InstanceRef) -> Result<ConnectSettings, GcpError> {
        let token = self.token(account)?;
        let url = format!("{}/v1/projects/{}/instances/{}/connectSettings", self.base, segment(&at.project), segment(&at.instance));
        let answer = self.send(&token, &Subject::Instance(at), self.http.get(url))?;
        let settings: ConnectSettingsAnswer = read(answer, "the connect settings")?;
        let server_ca_pem = settings
            .server_ca_cert
            .and_then(|cert| cert.cert)
            .filter(|pem| !pem.trim().is_empty())
            .ok_or_else(|| GcpError::Malformed("the connect settings came without a server certificate".to_string()))?;
        let public_ip = settings
            .ip_addresses
            .iter()
            .flatten()
            .find(|mapping| mapping.kind.as_deref() == Some("PRIMARY"))
            .and_then(|mapping| mapping.ip_address.as_deref())
            .filter(|address| !address.is_empty())
            .map(|address| address.parse::<IpAddr>().map_err(|_| GcpError::Malformed("the connect settings carry an address that is not an IP address".to_string())))
            .transpose()?;
        let dns_name = dns_name(settings.dns_names.as_deref().unwrap_or_default(), settings.dns_name.as_deref());
        Ok(ConnectSettings { public_ip, server_ca_pem, dns_name, database_version: settings.database_version.unwrap_or_default() })
    }

    fn ephemeral_cert(&self, account: Option<&str>, at: &InstanceRef, key: &EphemeralKey) -> Result<EphemeralCert, GcpError> {
        let token = self.token(account)?;
        // The colon before the method name is the API's own, not part of the instance name.
        let url = format!("{}/v1/projects/{}/instances/{}:generateEphemeralCert", self.base, segment(&at.project), segment(&at.instance));
        let body = EphemeralRequest { public_key: key.public_pem(), access_token: token.value.as_str() };
        let answer = self.send(&token, &Subject::Instance(at), self.http.post(url).json(&body))?;
        let issued = read::<EphemeralAnswer>(answer, "the certificate")?.ephemeral_cert.unwrap_or_default();
        let cert_pem = issued.cert.filter(|pem| !pem.trim().is_empty()).ok_or_else(|| GcpError::Malformed("the answer carries no certificate".to_string()))?;
        let cert_ends = issued
            .expiration_time
            .as_deref()
            .and_then(parse_rfc3339)
            .ok_or_else(|| GcpError::Malformed("the certificate comes without a valid expiry time".to_string()))?;
        // The token is inside the certificate: when it ends, the instance can no longer sign anyone in with the certificate.
        let expires_at = token.expires_at.map_or(cert_ends, |token_ends| token_ends.min(cert_ends));
        Ok(EphemeralCert { cert_pem, expires_at, account: token.account })
    }

    fn list_instances(&self, account: Option<&str>, project: &str) -> Result<Vec<InstanceSummary>, GcpError> {
        let token = self.token(account)?;
        let list = format!("{}/v1/projects/{}/instances", self.base, segment(project));
        let mut found = Vec::new();
        let mut page_token: Option<String> = None;
        for _ in 0..LIST_PAGES {
            let url = match &page_token {
                Some(page_token) => format!("{list}?{}", query(&[("pageToken", page_token)])),
                None => list.clone(),
            };
            let answer = self.send(&token, &Subject::Project(project), self.http.get(url))?;
            let page: InstancesAnswer = read(answer, "the instance list")?;
            found.extend(page.items.unwrap_or_default().into_iter().filter_map(InstanceAnswer::postgres_summary));
            page_token = page.next_page_token.filter(|next| !next.is_empty());
            if page_token.is_none() {
                break;
            }
        }
        Ok(found)
    }
}

/// What a call is about, for the sentences that name it.
enum Subject<'a> {
    Instance(&'a InstanceRef),
    Project(&'a str),
}

impl Subject<'_> {
    fn project(&self) -> &str {
        match self {
            Subject::Instance(at) => &at.project,
            Subject::Project(project) => project,
        }
    }

    fn not_found(&self) -> String {
        match self {
            Subject::Instance(at) => format!("Cloud SQL has no instance {}:{}:{}.", at.project, at.region, at.instance),
            Subject::Project(project) => format!("Cloud SQL has no project {project}."),
        }
    }
}

/// A name as one segment of a URL path: everything but letters, digits and `-._~:` is percent-encoded, so a name cannot add a segment, a
/// query or a fragment to the request. The colon stays as it is (a project with a domain, `example.com:acme-dev-654321`, has one).
fn segment(name: &str) -> String {
    let mut encoded = String::with_capacity(name.len());
    for byte in name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => encoded.push(char::from(byte)),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// `answer` as the parts of the API's JSON that `what` reads. A mismatch is reported without the parser's own message, which quotes the value
/// it choked on.
fn read<T: DeserializeOwned>(answer: serde_json::Value, what: &str) -> Result<T, GcpError> {
    serde_json::from_value(answer).map_err(|_| GcpError::Malformed(format!("the {API} API's answer about {what} is not in the shape it documents")))
}

/// The error for an answer that is not a success. A `403` that says the API is not enabled is its own sentence, before the generic denial.
fn refusal(status: u16, body: &str, token: &Token, subject: &Subject<'_>) -> GcpError {
    let error = serde_json::from_str::<ErrorAnswer>(body).ok().and_then(|answer| answer.error);
    match status {
        403 if error.as_ref().is_some_and(ErrorBody::says_the_service_is_disabled) => GcpError::Refused {
            api: API,
            message: format!("The Cloud SQL Admin API is not enabled in {}. Enable it in the Google Cloud console, then try again.", subject.project()),
        },
        401 | 403 => GcpError::Denied { api: API, status, account: token.account.clone() },
        404 => GcpError::Refused { api: API, message: subject.not_found() },
        400 => match error.and_then(|error| error.message).and_then(|message| refusal_words(&message, token.value.as_str())) {
            Some(message) => GcpError::Refused { api: API, message },
            None => GcpError::Http { api: API, status },
        },
        _ => GcpError::Http { api: API, status },
    }
}

/// The API's words for a refusal as one line of at most `REFUSAL_CHARS` printable characters: runs of whitespace become one space, other
/// control characters go, and the access token, should the API quote it, is blanked. `None` when nothing is left.
fn refusal_words(message: &str, token: &str) -> Option<String> {
    let message = if token.is_empty() { Cow::Borrowed(message) } else { Cow::Owned(message.replace(token, "[redacted]")) };
    let one_line = message.split_whitespace().collect::<Vec<_>>().join(" ");
    let cut: String = one_line.chars().filter(|c| !c.is_control()).take(REFUSAL_CHARS).collect();
    let cut = cut.trim_end();
    (!cut.is_empty()).then(|| cut.to_string())
}

/// The name the server certificate is made out to: the first non-empty name of `dnsNames`, else the legacy `dnsName`, with one trailing dot
/// (the root label of a DNS name) taken off. This is the name the Go connector hands TLS as the server name.
fn dns_name(names: &[DnsNameMapping], legacy: Option<&str>) -> Option<String> {
    names
        .iter()
        .filter_map(|mapping| mapping.name.as_deref())
        .chain(legacy)
        .map(str::trim)
        .find(|name| !name.is_empty())
        .map(|name| name.strip_suffix('.').unwrap_or(name))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

// The parts of the API's JSON that this client reads. The field names are the API's own (camel case); everything else in an answer is
// ignored, and every field is optional here so that what is missing is decided where it matters.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectSettingsAnswer {
    server_ca_cert: Option<SslCert>,
    ip_addresses: Option<Vec<IpMapping>>,
    database_version: Option<String>,
    dns_name: Option<String>,
    dns_names: Option<Vec<DnsNameMapping>>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SslCert {
    cert: Option<String>,
    expiration_time: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpMapping {
    #[serde(rename = "type")]
    kind: Option<String>,
    ip_address: Option<String>,
}

#[derive(Deserialize)]
struct DnsNameMapping {
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EphemeralAnswer {
    ephemeral_cert: Option<SslCert>,
}

/// The body of `generateEphemeralCert`, named as the API names its fields. The token in it is a secret: this type has no `Debug`.
#[derive(Serialize)]
struct EphemeralRequest<'a> {
    public_key: &'a str,
    access_token: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstancesAnswer {
    items: Option<Vec<InstanceAnswer>>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstanceAnswer {
    name: String,
    region: Option<String>,
    database_version: Option<String>,
    ip_addresses: Option<Vec<IpMapping>>,
    settings: Option<InstanceSettings>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstanceSettings {
    database_flags: Option<Vec<DatabaseFlag>>,
}

#[derive(Deserialize)]
struct DatabaseFlag {
    name: Option<String>,
    value: Option<String>,
}

impl InstanceAnswer {
    /// The instance as the form lists it; `None` for one that is not PostgreSQL (its `databaseVersion` does not start with `POSTGRES_`).
    fn postgres_summary(self) -> Option<InstanceSummary> {
        let database_version = self.database_version.filter(|version| version.starts_with("POSTGRES_"))?;
        let has_address = |kind: &str| self.ip_addresses.iter().flatten().any(|mapping| mapping.kind.as_deref() == Some(kind));
        let iam_authentication = self
            .settings
            .iter()
            .flat_map(|settings| settings.database_flags.iter().flatten())
            .any(|flag| flag.name.as_deref() == Some(IAM_FLAG) && flag.value.as_deref() == Some("on"));
        Some(InstanceSummary {
            name: self.name,
            region: self.region.unwrap_or_default(),
            database_version,
            public_ip: has_address("PRIMARY"),
            private_ip: has_address("PRIVATE"),
            iam_authentication,
        })
    }
}

#[derive(Deserialize)]
struct ErrorAnswer {
    error: Option<ErrorBody>,
}

#[derive(Deserialize)]
struct ErrorBody {
    message: Option<String>,
    details: Option<Vec<ErrorDetail>>,
}

#[derive(Deserialize)]
struct ErrorDetail {
    reason: Option<String>,
}

impl ErrorBody {
    /// Whether one of Google's error details gives `SERVICE_DISABLED` as the reason: the API is switched off in the project.
    fn says_the_service_is_disabled(&self) -> bool {
        self.details.iter().flatten().any(|detail| detail.reason.as_deref() == Some("SERVICE_DISABLED"))
    }
}

#[cfg(test)]
#[path = "cloudsql_tests.rs"]
mod tests;
