//! The blocking client behind the broker's Google calls: OS Login's login profile and key import over one `reqwest::blocking::Client`,
//! and the Privileged Access Manager calls (the grant search, requesting a grant, reading one back) through Google's client library
//! with Lunport's credentials plugged in (`gcp/credentials.rs`). The bearer token comes from a `TokenSource`, every failure is a
//! sentence, and a trait lets the directory tests script the answers.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use google_cloud_gax::paginator::ItemPaginator as _;
use google_cloud_privilegedaccessmanager_v1 as pam_api;

use super::auth::{user_agent, AuthError, TokenSource};
use super::credentials::credentials;
use super::oslogin::{parse_profile, LoginProfile};
use super::pam::Grant;

const OSLOGIN_BASE: &str = "https://oslogin.googleapis.com";
const PAM_BASE: &str = "https://privilegedaccessmanager.googleapis.com";
const PAM_API: &str = "Privileged Access Manager";
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
/// A page of the grant search, which answers every grant the caller ever created on the entitlement (ended ones included) and may hold
/// fewer than asked: every page is read, up to `GRANTS_PAGES`, so the one active grant of someone who requests one every day is found.
const GRANTS_PAGE: i32 = 50;
const GRANTS_PAGES: usize = 10;

/// Why a call to Google did not answer. Every text is a sentence for the person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcpError {
    Auth(AuthError),
    /// `401` or `403`: the account may not call this API (or the token lacks the scope).
    Denied { api: &'static str, status: u16, account: String },
    /// Any other unsuccessful status.
    Http { api: &'static str, status: u16 },
    /// `400`: the API refused what was asked, and said why in its own words (a duration over the entitlement's maximum, a missing
    /// justification).
    Refused { api: &'static str, message: String },
    Network(String),
    /// The answer was not the JSON the API documents.
    Malformed(String),
}

impl fmt::Display for GcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GcpError::Auth(error) => write!(f, "{error}"),
            GcpError::Denied { api, status, account } => write!(f, "{account} may not call the {api} API (HTTP {status})."),
            GcpError::Http { api, status } => write!(f, "The {api} API answered {status}."),
            GcpError::Refused { api, message } => write!(f, "{api} refused the request: {message}."),
            GcpError::Network(text) => write!(f, "Google's API could not be reached: {text}."),
            GcpError::Malformed(text) => write!(f, "Google's API answered with something unexpected: {text}."),
        }
    }
}

impl std::error::Error for GcpError {}

/// The Google calls the broker makes before connecting. `account` names the Google account (an email) or asks for the default one; the
/// calls block (the broker's threads are plain threads) and take a network round trip each.
pub trait GcpClient: Send + Sync {
    fn login_profile(&self, account: Option<&str>, project: &str) -> Result<LoginProfile, GcpError>;
    /// Registers `key_line` (an OpenSSH public key line) with OS Login for `project` and returns the profile as it is afterwards. OS Login
    /// creates the POSIX account on the first import, as `gcloud compute ssh` relies on.
    fn import_ssh_public_key(&self, account: Option<&str>, project: &str, key_line: &str) -> Result<LoginProfile, GcpError>;
    /// The caller's own grants on `entitlement`, whatever their state.
    fn grants(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str) -> Result<Vec<Grant>, GcpError>;
    /// Requests a grant on `entitlement` for `duration_secs` with `justification`, and answers the grant as PAM created it (usually
    /// still `ACTIVATING`).
    fn create_grant(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str, duration_secs: u32, justification: &str) -> Result<Grant, GcpError>;
    /// The grant `name` (`projects/…/grants/…`) as it is now.
    fn get_grant(&self, account: Option<&str>, name: &str) -> Result<Grant, GcpError>;
}

/// `GcpClient` over HTTPS: reqwest for OS Login, the client library for PAM.
pub struct RestClient {
    tokens: Arc<dyn TokenSource>,
    http: reqwest::blocking::Client,
    oslogin_base: String,
    pam_base: String,
    /// The client library is asynchronous; the calls here block on this runtime, as reqwest's blocking client blocks on its own.
    runtime: tokio::runtime::Runtime,
    /// One library client per account (the credentials differ), built on first use.
    pam: Mutex<HashMap<String, pam_api::client::PrivilegedAccessManager>>,
    /// How long one call may take, OS Login's and the library's alike.
    timeout: Duration,
}

impl RestClient {
    pub fn new(tokens: Arc<dyn TokenSource>) -> RestClient {
        RestClient::with_bases(tokens, OSLOGIN_BASE, PAM_BASE)
    }

    /// The client against other base URLs (tests point both at a mock server).
    pub fn with_bases(tokens: Arc<dyn TokenSource>, oslogin_base: &str, pam_base: &str) -> RestClient {
        RestClient::with_bases_and_timeout(tokens, oslogin_base, pam_base, HTTP_TIMEOUT)
    }

    /// `with_bases` with the per-call timeout given (tests use a short one).
    pub fn with_bases_and_timeout(tokens: Arc<dyn TokenSource>, oslogin_base: &str, pam_base: &str, timeout: Duration) -> RestClient {
        let http = reqwest::blocking::Client::builder().timeout(timeout).user_agent(user_agent()).build().expect("the REST client builds from fixed options");
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime builds from fixed options");
        RestClient {
            tokens,
            http,
            oslogin_base: oslogin_base.trim_end_matches('/').to_string(),
            pam_base: pam_base.trim_end_matches('/').to_string(),
            runtime,
            pam: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    /// The account the token source resolves `account` to (the active gcloud account when none is named), for the sentences; a
    /// credentials problem ends here, before the library is asked for anything.
    fn pam_account(&self, account: Option<&str>) -> Result<String, GcpError> {
        self.tokens.access_token(account).map(|token| token.account).map_err(GcpError::Auth)
    }

    /// The library's PAM client for `account`, built once.
    fn pam_client(&self, account: Option<&str>) -> Result<pam_api::client::PrivilegedAccessManager, GcpError> {
        let key = account.unwrap_or("").to_string();
        if let Some(client) = self.pam.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&key) {
            return Ok(client.clone());
        }
        // One call, one timeout, as for OS Login: the library's own retries (ten attempts over a minute by default) are off, since the
        // broker's loops repeat what has to be repeated and look at `cancel` between tries; a call that hangs would otherwise hold a
        // session thread, and the grant gate with it, for as long as the socket lives.
        let built = self.runtime.block_on(async {
            pam_api::client::PrivilegedAccessManager::builder()
                .with_credentials(credentials(Arc::clone(&self.tokens), account.map(str::to_string)))
                .with_endpoint(self.pam_base.clone())
                .with_attempt_timeout(self.timeout)
                .with_retry_policy(google_cloud_gax::retry_policy::NeverRetry)
                .build()
                .await
        });
        let client = built.map_err(|error| GcpError::Network(format!("the {PAM_API} client could not be set up: {error}")))?;
        self.pam.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(key, client.clone());
        Ok(client)
    }

    /// Sends `request` (built once the account is known, since OS Login's URLs carry it) with the bearer token and reads the JSON answer.
    fn call(
        &self,
        api: &'static str,
        account: Option<&str>,
        request: impl FnOnce(&reqwest::blocking::Client, &str) -> reqwest::blocking::RequestBuilder,
    ) -> Result<serde_json::Value, GcpError> {
        let token = self.tokens.access_token(account).map_err(GcpError::Auth)?;
        let response = request(&self.http, &token.account).bearer_auth(token.value.as_str()).send().map_err(|error| GcpError::Network(describe(&error)))?;
        let status = response.status().as_u16();
        let body = response.text().map_err(|error| GcpError::Network(describe(&error)))?;
        match status {
            200..=299 => serde_json::from_str(&body).map_err(|_| GcpError::Malformed(format!("the {api} API did not answer with JSON"))),
            401 | 403 => Err(GcpError::Denied { api, status, account: token.account }),
            _ => Err(GcpError::Http { api, status }),
        }
    }
}

/// The account as a path segment (`frank%40retower.io`).
fn segment(account: &str) -> String {
    url::form_urlencoded::byte_serialize(account.as_bytes()).collect()
}

fn query(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

/// A reqwest error without the URL it carries.
fn describe(error: &reqwest::Error) -> String {
    let text = error.to_string();
    text.split(" for url").next().unwrap_or(&text).trim_end_matches('.').to_string()
}

impl GcpClient for RestClient {
    fn login_profile(&self, account: Option<&str>, project: &str) -> Result<LoginProfile, GcpError> {
        let base = &self.oslogin_base;
        let answer = self.call("OS Login", account, |http, account| http.get(format!("{base}/v1/users/{}/loginProfile?{}", segment(account), query(&[("projectId", project)]))))?;
        parse_profile(&answer)
    }

    fn import_ssh_public_key(&self, account: Option<&str>, project: &str, key_line: &str) -> Result<LoginProfile, GcpError> {
        let base = &self.oslogin_base;
        let body = serde_json::json!({ "key": key_line.trim() });
        let answer = self.call("OS Login", account, |http, account| {
            http.post(format!("{base}/v1/users/{}:importSshPublicKey?{}", segment(account), query(&[("projectId", project)]))).json(&body)
        })?;
        let profile = answer.get("loginProfile").ok_or_else(|| GcpError::Malformed("the key import answered without a login profile".to_string()))?;
        parse_profile(profile)
    }

    fn grants(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str) -> Result<Vec<Grant>, GcpError> {
        let who = self.pam_account(account)?;
        let client = self.pam_client(account)?;
        let parent = entitlement_name(project, location, entitlement);
        self.runtime.block_on(async {
            let mut items = client
                .search_grants()
                .set_parent(parent)
                .set_caller_relationship(pam_api::model::search_grants_request::CallerRelationshipType::HadCreated)
                .set_page_size(GRANTS_PAGE)
                .by_item();
            let mut grants = Vec::new();
            while let Some(item) = items.next().await {
                grants.push(Grant::from(item.map_err(|error| gax_error(&who, error))?));
                if grants.len() >= GRANTS_PAGE as usize * GRANTS_PAGES {
                    break;
                }
            }
            Ok(grants)
        })
    }

    fn create_grant(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str, duration_secs: u32, justification: &str) -> Result<Grant, GcpError> {
        let who = self.pam_account(account)?;
        let client = self.pam_client(account)?;
        let grant = pam_api::model::Grant::new()
            .set_requested_duration(google_cloud_wkt::Duration::clamp(i64::from(duration_secs), 0))
            .set_justification(pam_api::model::Justification::new().set_unstructured_justification(justification));
        self.runtime
            .block_on(client.create_grant().set_parent(entitlement_name(project, location, entitlement)).set_grant(grant).send())
            .map(Grant::from)
            .map_err(|error| gax_error(&who, error))
    }

    fn get_grant(&self, account: Option<&str>, name: &str) -> Result<Grant, GcpError> {
        let who = self.pam_account(account)?;
        let client = self.pam_client(account)?;
        self.runtime.block_on(client.get_grant().set_name(name).send()).map(Grant::from).map_err(|error| gax_error(&who, error))
    }
}

/// `projects/{project}/locations/{location}/entitlements/{entitlement}`: the parent of its grants.
fn entitlement_name(project: &str, location: &str, entitlement: &str) -> String {
    format!("projects/{project}/locations/{location}/entitlements/{entitlement}")
}

/// What the library's error means in Lunport's sentences: a permission refusal names the account, a `400` carries PAM's own words,
/// any other status is just that, and a failure before any status is a network failure.
fn gax_error(account: &str, error: pam_api::Error) -> GcpError {
    match error.http_status_code() {
        Some(status @ (401 | 403)) => GcpError::Denied { api: PAM_API, status, account: account.to_string() },
        Some(400) => {
            let message = error.status().map(|status| status.message.trim().to_string()).filter(|message| !message.is_empty()).unwrap_or_else(|| error.to_string());
            GcpError::Refused { api: PAM_API, message: message.trim_end_matches('.').to_string() }
        }
        Some(status) => GcpError::Http { api: PAM_API, status },
        None => GcpError::Network(error.to_string().trim_end_matches('.').to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::auth::{AuthError, StaticToken, Token, TokenSource};
    use serde_json::json;
    use std::sync::Arc;

    const ACCOUNT: &str = "frank@retower.io";
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGvBwpCj0GQWLW0hG8bQ4qJ8r7ZcXx9x2nH0f0e3Q1aB";

    fn profile_json() -> serde_json::Value {
        json!({
            "name": "users/frank@retower.io",
            "posixAccounts": [{ "primary": true, "username": "frank_retower_io", "operatingSystemType": "LINUX" }],
            "sshPublicKeys": {}
        })
    }

    fn client(server: &mockito::Server) -> RestClient {
        RestClient::with_bases(Arc::new(StaticToken("t0k".into())), &server.url(), &server.url())
    }

    /// Design 2026-10-25: every call to Google is bounded by the 20-second timeout, the library's calls included, and the library does
    /// not retry on its own (the broker's loops do that, watching `cancel`): a PAM server that does not answer in time is a network
    /// failure, reported as soon as the timeout passes.
    #[test]
    fn a_pam_call_that_does_not_answer_in_time_fails_at_once_as_a_network_error() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        // A server that answers every connection two seconds late, with an empty search result.
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request);
                    std::thread::sleep(Duration::from_secs(2));
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
                });
            }
        });
        let client = RestClient::with_bases_and_timeout(Arc::new(StaticToken("t0k".into())), &base, &base, Duration::from_millis(300));
        let started = std::time::Instant::now();
        let result = client.grants(Some("frank@retower.io"), "knowknow-prod", "global", "prod-operate");
        assert!(matches!(result, Err(GcpError::Network(_))), "{result:?}");
        assert!(started.elapsed() < Duration::from_millis(1500), "the library must not retry on its own: {:?}", started.elapsed());
    }

    #[test]
    fn a_login_profile_is_fetched_with_the_project_and_the_bearer_token() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/v1/users/frank%40retower.io/loginProfile")
            .match_query(mockito::Matcher::UrlEncoded("projectId".into(), "eng-dev-396409".into()))
            .match_header("authorization", "Bearer t0k")
            .with_header("content-type", "application/json")
            .with_body(profile_json().to_string())
            .create();
        let profile = client(&server).login_profile(Some(ACCOUNT), "eng-dev-396409").unwrap();
        assert_eq!(profile.username(), Some("frank_retower_io"));
        mock.assert();
    }

    #[test]
    fn a_key_import_posts_the_line_and_returns_the_profile() {
        let mut server = mockito::Server::new();
        let mut returned = profile_json();
        returned["sshPublicKeys"] = json!({ "3b2f": { "key": KEY, "fingerprint": "3b2f" } });
        let mock = server
            .mock("POST", "/v1/users/frank%40retower.io:importSshPublicKey")
            .match_query(mockito::Matcher::UrlEncoded("projectId".into(), "eng-dev-396409".into()))
            .match_header("authorization", "Bearer t0k")
            .match_body(mockito::Matcher::Json(json!({ "key": KEY })))
            .with_header("content-type", "application/json")
            .with_body(json!({ "loginProfile": returned, "details": "Key imported" }).to_string())
            .create();
        let profile = client(&server).import_ssh_public_key(Some(ACCOUNT), "eng-dev-396409", KEY).unwrap();
        assert!(profile.has_key(KEY));
        assert_eq!(profile.username(), Some("frank_retower_io"));
        mock.assert();
    }

    #[test]
    fn a_403_is_denied_naming_the_account_and_api() {
        let mut server = mockito::Server::new();
        server.mock("GET", "/v1/users/frank%40retower.io/loginProfile").match_query(mockito::Matcher::Any).with_status(403).create();
        let error = client(&server).login_profile(Some(ACCOUNT), "eng-dev-396409").unwrap_err();
        assert_eq!(error, GcpError::Denied { api: "OS Login", status: 403, account: ACCOUNT.into() });
        assert_eq!(error.to_string(), "frank@retower.io may not call the OS Login API (HTTP 403).");
        server.mock("GET", "/v1/projects/p/locations/global/entitlements/e/grants:search").match_query(mockito::Matcher::Any).with_status(500).create();
        let error = client(&server).grants(Some(ACCOUNT), "p", "global", "e").unwrap_err();
        assert_eq!(error, GcpError::Http { api: "Privileged Access Manager", status: 500 });
        assert_eq!(error.to_string(), "The Privileged Access Manager API answered 500.");
    }

    #[test]
    fn grants_are_searched_as_the_caller_created_them_and_filtered_here() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/v1/projects/knowknow-prod/locations/global/entitlements/prod-operate/grants:search")
            // The library sends enums by their number (`$alt=json;enum-encoding=int`): HAD_CREATED is 1.
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("callerRelationship".into(), "1".into()),
                mockito::Matcher::UrlEncoded("pageSize".into(), "50".into()),
            ]))
            .match_header("authorization", "Bearer t0k")
            .with_header("content-type", "application/json")
            .with_body(
                json!({ "grants": [
                    { "name": "…/grants/1", "state": "ENDED" },
                    { "name": "…/grants/2", "state": "ACTIVE", "requestedDuration": "1800s", "auditTrail": { "accessGrantTime": "2026-10-25T10:00:00Z" } },
                    { "name": "…/grants/3", "state": "SCHEDULED" }
                ]})
                .to_string(),
            )
            .create();
        let grants = client(&server).grants(Some(ACCOUNT), "knowknow-prod", "global", "prod-operate");
        mock.assert();
        let grants = grants.unwrap();
        assert_eq!(grants.len(), 3);
        assert_eq!(crate::gcp::pam::in_flight(&grants).len(), 2);
    }

    /// The search answers every grant the caller ever created on the entitlement, ended ones included, and a page may hold fewer than
    /// asked: the active grant of someone who requests one every day sits on a later page. Every page is read (mockito answers the
    /// most recently created matching mock, so the page-two mock comes second).
    #[test]
    fn grants_are_read_across_pages() {
        let mut server = mockito::Server::new();
        let path = "/v1/projects/knowknow-prod/locations/global/entitlements/prod-operate/grants:search";
        let first = server
            .mock("GET", path)
            .match_query(mockito::Matcher::UrlEncoded("callerRelationship".into(), "1".into()))
            .with_header("content-type", "application/json")
            .with_body(json!({ "grants": [{ "name": "…/grants/1", "state": "ENDED" }, { "name": "…/grants/2", "state": "ENDED" }], "nextPageToken": "page-two" }).to_string())
            .expect(1)
            .create();
        let second = server
            .mock("GET", path)
            .match_query(mockito::Matcher::UrlEncoded("pageToken".into(), "page-two".into()))
            .with_header("content-type", "application/json")
            .with_body(json!({ "grants": [{ "name": "…/grants/3", "state": "ACTIVE" }] }).to_string())
            .expect(1)
            .create();
        let grants = client(&server).grants(Some(ACCOUNT), "knowknow-prod", "global", "prod-operate").unwrap();
        assert_eq!(grants.iter().map(|grant| grant.state.as_str()).collect::<Vec<_>>(), vec!["ENDED", "ENDED", "ACTIVE"]);
        first.assert();
        second.assert();
    }

    /// Requesting a grant (design 2026-10-25, PAM grant requests): the entitlement as the parent, the duration and the justification
    /// as PAM writes them, and the grant PAM answers, still activating.
    #[test]
    fn create_grant_sends_the_parent_duration_and_justification_and_answers_the_grant() {
        let mut server = mockito::Server::new();
        // The library adds its own query parameters (`$alt=json;enum-encoding=int`, an empty `requestId`); only the path matters here.
        let mock = server
            .mock("POST", "/v1/projects/knowknow-prod/locations/global/entitlements/prod-operate/grants")
            .match_query(mockito::Matcher::Any)
            .match_header("authorization", "Bearer t0k")
            .match_body(mockito::Matcher::PartialJson(json!({ "requestedDuration": "1800s", "justification": { "unstructuredJustification": "restart app-api" } })))
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "name": "projects/knowknow-prod/locations/global/entitlements/prod-operate/grants/42",
                    "state": "ACTIVATING",
                    "requestedDuration": "1800s",
                    "justification": { "unstructuredJustification": "restart app-api" }
                })
                .to_string(),
            )
            .expect(1)
            .create();
        let grant = client(&server).create_grant(Some(ACCOUNT), "knowknow-prod", "global", "prod-operate", 1800, "restart app-api").unwrap();
        assert_eq!(grant.name, "projects/knowknow-prod/locations/global/entitlements/prod-operate/grants/42");
        assert_eq!((grant.state.as_str(), grant.requested_duration.as_deref(), grant.justification.as_deref()), ("ACTIVATING", Some("1800s"), Some("restart app-api")));
        assert_eq!(grant.until(), None, "no grant time yet");
        mock.assert();
    }

    #[test]
    fn a_400_from_pam_is_its_own_sentence() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/v1/projects/knowknow-prod/locations/global/entitlements/prod-operate/grants")
            .match_query(mockito::Matcher::Any)
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(json!({ "error": { "code": 400, "message": "requested_duration exceeds the maximum", "status": "INVALID_ARGUMENT" } }).to_string())
            .expect(1)
            .create();
        let error = client(&server).create_grant(Some(ACCOUNT), "knowknow-prod", "global", "prod-operate", 7200, "x").unwrap_err();
        mock.assert();
        assert_eq!(error, GcpError::Refused { api: "Privileged Access Manager", message: "requested_duration exceeds the maximum".into() });
        assert_eq!(error.to_string(), "Privileged Access Manager refused the request: requested_duration exceeds the maximum.");
    }

    #[test]
    fn get_grant_reads_a_grant_by_name() {
        let mut server = mockito::Server::new();
        let name = "projects/knowknow-prod/locations/global/entitlements/prod-operate/grants/42";
        server
            .mock("GET", format!("/v1/{name}").as_str())
            .match_query(mockito::Matcher::Any)
            .match_header("authorization", "Bearer t0k")
            .with_header("content-type", "application/json")
            .with_body(json!({ "name": name, "state": "ACTIVE", "requestedDuration": "1800s", "auditTrail": { "accessGrantTime": "2027-01-15T08:00:00Z" } }).to_string())
            .create();
        let grant = client(&server).get_grant(Some(ACCOUNT), name).unwrap();
        assert_eq!(grant.state, "ACTIVE");
        assert_eq!(grant.access_grant_time.as_deref(), Some("2027-01-15T08:00:00Z"));
        assert_eq!(grant.until(), Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000 + 1800)));
    }

    #[test]
    fn a_credentials_problem_is_reported_as_such() {
        struct NoCredentials;
        impl TokenSource for NoCredentials {
            fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
                Err(AuthError::NoCredentials { account: account.map(str::to_string), config_dir: "/d".into() })
            }
        }
        let server = mockito::Server::new();
        let client = RestClient::with_bases(Arc::new(NoCredentials), &server.url(), &server.url());
        let error = client.login_profile(Some(ACCOUNT), "eng-dev-396409").unwrap_err();
        assert_eq!(error, GcpError::Auth(AuthError::NoCredentials { account: Some(ACCOUNT.into()), config_dir: "/d".into() }));
        assert!(error.to_string().starts_with("No Google Cloud credentials for frank@retower.io"));
    }
}
