//! The blocking REST client behind the broker's Google calls: OS Login's login profile and key import, PAM's grant search. One
//! `reqwest::blocking::Client`, the bearer token from a `TokenSource`, a sentence per failure, and a trait so the directory tests can
//! script the answers.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::auth::{user_agent, AuthError, TokenSource};
use super::oslogin::{parse_profile, LoginProfile};
use super::pam::{parse_grants, Grant};

const OSLOGIN_BASE: &str = "https://oslogin.googleapis.com";
const PAM_BASE: &str = "https://privilegedaccessmanager.googleapis.com";
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
/// A page of the grant search, which answers every grant the caller ever created on the entitlement (ended ones included) and may hold
/// fewer than asked: every page is read, up to `GRANTS_PAGES`, so the one active grant of someone who requests one every day is found.
const GRANTS_PAGE: &str = "50";
const GRANTS_PAGES: usize = 10;

/// Why a call to Google did not answer. Every text is a sentence for the person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcpError {
    Auth(AuthError),
    /// `401` or `403`: the account may not call this API (or the token lacks the scope).
    Denied { api: &'static str, status: u16, account: String },
    /// Any other unsuccessful status.
    Http { api: &'static str, status: u16 },
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
}

/// `GcpClient` over HTTPS.
pub struct RestClient {
    tokens: Arc<dyn TokenSource>,
    http: reqwest::blocking::Client,
    oslogin_base: String,
    pam_base: String,
}

impl RestClient {
    pub fn new(tokens: Arc<dyn TokenSource>) -> RestClient {
        RestClient::with_bases(tokens, OSLOGIN_BASE, PAM_BASE)
    }

    /// The client against other base URLs (tests point both at a mock server).
    pub fn with_bases(tokens: Arc<dyn TokenSource>, oslogin_base: &str, pam_base: &str) -> RestClient {
        let http = reqwest::blocking::Client::builder().timeout(HTTP_TIMEOUT).user_agent(user_agent()).build().expect("the REST client builds from fixed options");
        RestClient { tokens, http, oslogin_base: oslogin_base.trim_end_matches('/').to_string(), pam_base: pam_base.trim_end_matches('/').to_string() }
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
        let base = &self.pam_base;
        let mut grants = Vec::new();
        let mut page_token: Option<String> = None;
        for _ in 0..GRANTS_PAGES {
            let token = page_token.take();
            let answer = self.call("Privileged Access Manager", account, |http, _| {
                let mut pairs = vec![("callerRelationship", "HAD_CREATED"), ("pageSize", GRANTS_PAGE)];
                if let Some(token) = token.as_deref() {
                    pairs.push(("pageToken", token));
                }
                http.get(format!("{base}/v1/projects/{project}/locations/{location}/entitlements/{entitlement}/grants:search?{}", query(&pairs)))
            })?;
            grants.extend(parse_grants(&answer));
            page_token = answer.get("nextPageToken").and_then(serde_json::Value::as_str).filter(|token| !token.is_empty()).map(str::to_string);
            if page_token.is_none() {
                break;
            }
        }
        Ok(grants)
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
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("callerRelationship".into(), "HAD_CREATED".into()),
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
        let grants = client(&server).grants(Some(ACCOUNT), "knowknow-prod", "global", "prod-operate").unwrap();
        assert_eq!(grants.len(), 3);
        assert_eq!(crate::gcp::pam::in_flight(&grants).len(), 2);
        mock.assert();
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
            .match_query(mockito::Matcher::UrlEncoded("callerRelationship".into(), "HAD_CREATED".into()))
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
