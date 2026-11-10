use super::*;
use crate::gcp::auth::{user_agent, AuthError, StaticToken, Token, TokenSource};
use mockito::Matcher;
use rustls::pki_types::PrivateKeyDer;
use serde_json::json;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const ACCOUNT: &str = "frank@example.com";
const PROJECT: &str = "acme-dev-654321";
const SETTINGS_PATH: &str = "/v1/projects/acme-dev-654321/instances/orders-pg/connectSettings";
const CERT_PATH: &str = "/v1/projects/acme-dev-654321/instances/orders-pg:generateEphemeralCert";
const LIST_PATH: &str = "/v1/projects/acme-dev-654321/instances";
/// The server CA of an instance whose CA hierarchy has two certificates, as one text. The bodies are not certificates: the client keeps
/// the text whole and leaves reading it to the TLS code.
const SERVER_CA: &str = "-----BEGIN CERTIFICATE-----\nc2VydmVyLWNhLW9uZQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nc2VydmVyLWNhLXR3bw==\n-----END CERTIFICATE-----\n";
const CLIENT_CERT: &str = "-----BEGIN CERTIFICATE-----\nY2xpZW50LWNlcnQ=\n-----END CERTIFICATE-----\n";
/// `2027-01-15T09:00:00.123Z`, the expiry the certificate fixture carries (1 800 000 000 seconds are 08:00:00Z that day).
const CERT_EXPIRES: Duration = Duration::from_millis(1_800_003_600_123);

/// One key for the tests that only need a key to send: making an RSA key takes a moment.
fn key() -> &'static EphemeralKey {
    static KEY: OnceLock<EphemeralKey> = OnceLock::new();
    KEY.get_or_init(|| EphemeralKey::generate().expect("a key is made"))
}

fn instance() -> InstanceRef {
    InstanceRef { project: PROJECT.into(), region: "asia-east1".into(), instance: "orders-pg".into() }
}

fn admin(server: &mockito::Server) -> RestSqlAdmin {
    RestSqlAdmin::with_base(Arc::new(StaticToken("t0k".into())), &server.url())
}

/// A token source whose token ends at `expires_at`.
struct Expiring {
    expires_at: Option<SystemTime>,
}

impl TokenSource for Expiring {
    fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
        Ok(Token { value: Zeroizing::new("t0k".into()), account: account.unwrap_or("static@example.com").into(), expires_at: self.expires_at })
    }
}

/// A token source with no usable sign-in.
struct SignedOut;

impl TokenSource for SignedOut {
    fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
        Err(AuthError::SignInExpired { account: account.unwrap_or("static@example.com").into() })
    }
}

fn settings_json() -> serde_json::Value {
    json!({
        "kind": "sql#connectSettings",
        "serverCaCert": { "kind": "sql#sslCert", "cert": SERVER_CA, "expirationTime": "2036-01-01T00:00:00.000Z" },
        "ipAddresses": [{ "type": "PRIMARY", "ipAddress": "203.0.113.10" }, { "type": "PRIVATE", "ipAddress": "198.51.100.5" }],
        "region": "asia-east1",
        "databaseVersion": "POSTGRES_16",
        "backendType": "SECOND_GEN",
        "dnsName": "legacy-name.asia-east1.sql.goog.",
        "dnsNames": [{ "name": "1a2b3c4d5e6f.asia-east1.sql.goog.", "connectionType": "PUBLIC", "dnsScope": "INSTANCE" }],
        "pscEnabled": false
    })
}

/// The connect settings fixture with `dnsNames` and the legacy `dnsName` as given (left out when `None`).
fn settings_with_dns(dns_names: Option<serde_json::Value>, legacy: Option<&str>) -> serde_json::Value {
    let mut body = settings_json();
    let object = body.as_object_mut().unwrap();
    object.remove("dnsNames");
    object.remove("dnsName");
    if let Some(names) = dns_names {
        object.insert("dnsNames".into(), names);
    }
    if let Some(legacy) = legacy {
        object.insert("dnsName".into(), json!(legacy));
    }
    body
}

/// What `connect_settings` makes of a server that answers `body` on the instance's path.
fn read_settings(body: serde_json::Value) -> Result<ConnectSettings, GcpError> {
    let mut server = mockito::Server::new();
    server.mock("GET", SETTINGS_PATH).with_header("content-type", "application/json").with_body(body.to_string()).create();
    admin(&server).connect_settings(Some(ACCOUNT), &instance())
}

fn cert_json(expiration_time: &str) -> serde_json::Value {
    json!({
        "kind": "sql#sslCertsCreateEphemeral",
        "ephemeralCert": { "kind": "sql#sslCert", "cert": CLIENT_CERT, "certSerialNumber": "1", "createTime": "2027-01-15T08:00:00.123Z", "expirationTime": expiration_time }
    })
}

/// What `ephemeral_cert` makes of the fixture certificate, signed with the tokens of `tokens`.
fn issue_cert(tokens: Arc<dyn TokenSource>, body: serde_json::Value) -> Result<EphemeralCert, GcpError> {
    let mut server = mockito::Server::new();
    server.mock("POST", CERT_PATH).with_header("content-type", "application/json").with_body(body.to_string()).create();
    RestSqlAdmin::with_base(tokens, &server.url()).ephemeral_cert(Some(ACCOUNT), &instance(), key())
}

/// One instance of an instance list.
fn instance_json(name: &str, version: &str, iam: Option<&str>, addresses: &[(&str, &str)]) -> serde_json::Value {
    let flags = iam.map(|value| json!([{ "name": "log_connections", "value": "on" }, { "name": "cloudsql.iam_authentication", "value": value }])).unwrap_or_else(|| json!([]));
    json!({
        "kind": "sql#instance",
        "name": name,
        "region": "asia-east1",
        "databaseVersion": version,
        "state": "RUNNABLE",
        "ipAddresses": addresses.iter().map(|(kind, address)| json!({ "type": kind, "ipAddress": address })).collect::<Vec<_>>(),
        "settings": { "tier": "db-custom-2-7680", "databaseFlags": flags }
    })
}

/// Makes every one of the three calls' paths answer `status` with `body`.
fn answer_every_call(server: &mut mockito::Server, status: usize, body: &str) {
    for (method, path) in [("GET", SETTINGS_PATH), ("POST", CERT_PATH), ("GET", LIST_PATH)] {
        server.mock(method, path).match_query(Matcher::Any).with_status(status).with_header("content-type", "application/json").with_body(body).create();
    }
}

/// The errors of the three calls (the connect settings, the certificate, the instance list) against `admin`.
fn errors_of(admin: &RestSqlAdmin, account: Option<&str>) -> [GcpError; 3] {
    [
        admin.connect_settings(account, &instance()).unwrap_err(),
        admin.ephemeral_cert(account, &instance(), key()).unwrap_err(),
        admin.list_instances(account, PROJECT).unwrap_err(),
    ]
}

#[test]
fn the_client_talks_to_googles_endpoint_unless_told_otherwise() {
    let admin = RestSqlAdmin::new(Arc::new(StaticToken("t0k".into())));
    assert_eq!(admin.base, "https://sqladmin.googleapis.com");
    let other = RestSqlAdmin::with_base(Arc::new(StaticToken("t0k".into())), "http://127.0.0.1:1/");
    assert_eq!(other.base, "http://127.0.0.1:1", "a trailing slash is dropped");
}

#[test]
fn connect_settings_reads_the_public_ip_ca_and_dns_name() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", SETTINGS_PATH)
        .match_header("authorization", "Bearer t0k")
        .match_header("user-agent", Matcher::Exact(user_agent()))
        .with_header("content-type", "application/json")
        .with_body(settings_json().to_string())
        .expect(1)
        .create();
    let settings = admin(&server).connect_settings(Some(ACCOUNT), &instance()).unwrap();
    mock.assert();
    assert_eq!(
        settings,
        ConnectSettings {
            public_ip: Some("203.0.113.10".parse().unwrap()),
            // Both certificates, byte for byte: the TLS side trusts every one of them.
            server_ca_pem: SERVER_CA.to_string(),
            // The name of `dnsNames` wins over the legacy `dnsName`, with its trailing dot trimmed.
            dns_name: Some("1a2b3c4d5e6f.asia-east1.sql.goog".into()),
            database_version: "POSTGRES_16".into(),
        }
    );
}

#[test]
fn connect_settings_falls_back_to_the_legacy_dns_name() {
    let legacy = Some("9f8e7d6c5b4a.asia-east1.sql.goog.");
    // No list, an empty list, and a list whose names are all empty.
    for names in [None, Some(json!([])), Some(json!([{ "name": "", "connectionType": "PUBLIC" }, {}]))] {
        let settings = read_settings(settings_with_dns(names.clone(), legacy)).unwrap();
        assert_eq!(settings.dns_name.as_deref(), Some("9f8e7d6c5b4a.asia-east1.sql.goog"), "{names:?}");
    }
}

#[test]
fn connect_settings_take_the_first_non_empty_dns_name_and_trim_only_a_trailing_dot() {
    let names = json!([{ "name": "" }, { "name": "aaaa1111bbbb.asia-east1.sql.goog" }, { "name": "cccc2222dddd.asia-east1.sql.goog." }]);
    let settings = read_settings(settings_with_dns(Some(names), Some("legacy-name.asia-east1.sql.goog."))).unwrap();
    assert_eq!(settings.dns_name.as_deref(), Some("aaaa1111bbbb.asia-east1.sql.goog"));
}

#[test]
fn connect_settings_without_any_dns_name_report_none() {
    assert_eq!(read_settings(settings_with_dns(None, None)).unwrap().dns_name, None);
    assert_eq!(read_settings(settings_with_dns(Some(json!([{ "name": "" }])), Some(""))).unwrap().dns_name, None);
}

#[test]
fn connect_settings_without_a_public_ip_reports_none() {
    let mut body = settings_json();
    // A private address and a replica's outgoing one are not the instance's public address.
    body["ipAddresses"] = json!([{ "type": "PRIVATE", "ipAddress": "198.51.100.5" }, { "type": "OUTGOING", "ipAddress": "203.0.113.77" }]);
    let settings = read_settings(body.clone()).unwrap();
    assert_eq!(settings.public_ip, None);
    assert_eq!(settings.server_ca_pem, SERVER_CA, "the rest is read all the same");
    body.as_object_mut().unwrap().remove("ipAddresses");
    assert_eq!(read_settings(body).unwrap().public_ip, None);
}

#[test]
fn a_public_address_may_be_ipv6() {
    let mut body = settings_json();
    body["ipAddresses"] = json!([{ "type": "PRIMARY", "ipAddress": "2001:db8::10" }]);
    assert_eq!(read_settings(body).unwrap().public_ip, Some("2001:db8::10".parse().unwrap()));
}

#[test]
fn connect_settings_that_cannot_be_used_are_malformed() {
    let malformed = |body: serde_json::Value| match read_settings(body) {
        Err(GcpError::Malformed(text)) => text,
        other => panic!("a malformed answer expected, got {other:?}"),
    };
    // Nothing to check the server's certificate against.
    let mut no_ca = settings_json();
    no_ca.as_object_mut().unwrap().remove("serverCaCert");
    assert!(malformed(no_ca).contains("server certificate"));
    let mut empty_ca = settings_json();
    empty_ca["serverCaCert"] = json!({ "cert": " " });
    assert!(malformed(empty_ca).contains("server certificate"));
    // A primary address that is not an address.
    let mut odd_address = settings_json();
    odd_address["ipAddresses"] = json!([{ "type": "PRIMARY", "ipAddress": "not-an-address" }]);
    assert!(malformed(odd_address).contains("address"));
    // A list that is not a list.
    let mut odd_list = settings_json();
    odd_list["ipAddresses"] = json!("203.0.113.10");
    assert!(malformed(odd_list).contains("connect settings"));
}

#[test]
fn an_answer_that_is_not_json_is_malformed_and_quotes_none_of_it() {
    let mut server = mockito::Server::new();
    server.mock("GET", SETTINGS_PATH).with_body("<html>secret-looking-text</html>").create();
    let error = admin(&server).connect_settings(Some(ACCOUNT), &instance()).unwrap_err();
    assert_eq!(error, GcpError::Malformed("the Cloud SQL Admin API did not answer with JSON".into()));
    assert!(!error.to_string().contains("secret-looking-text"));
}

#[test]
fn ephemeral_cert_sends_the_public_key_and_the_token_and_reads_the_expiry() {
    let key = key();
    assert!(key.public_pem().starts_with("-----BEGIN PUBLIC KEY-----"));
    let mut server = mockito::Server::new();
    let mock = server
        .mock("POST", CERT_PATH)
        .match_header("authorization", "Bearer t0k")
        .match_header("user-agent", Matcher::Exact(user_agent()))
        .match_header("content-type", Matcher::Regex("^application/json".into()))
        // The documented request, and nothing else in it.
        .match_body(Matcher::Json(json!({ "public_key": key.public_pem(), "access_token": "t0k" })))
        .with_header("content-type", "application/json")
        .with_body(cert_json("2027-01-15T09:00:00.123Z").to_string())
        .expect(1)
        .create();
    let cert = admin(&server).ephemeral_cert(Some(ACCOUNT), &instance(), key).unwrap();
    mock.assert();
    assert_eq!(cert, EphemeralCert { cert_pem: CLIENT_CERT.into(), expires_at: UNIX_EPOCH + CERT_EXPIRES, account: ACCOUNT.into() });
}

#[test]
fn the_certificate_belongs_to_the_account_the_token_resolved_to() {
    // No account asked for: the token source decides, and the certificate says who it is for.
    let mut server = mockito::Server::new();
    server.mock("POST", CERT_PATH).with_body(cert_json("2027-01-15T09:00:00.123Z").to_string()).create();
    let cert = admin(&server).ephemeral_cert(None, &instance(), key()).unwrap();
    assert_eq!(cert.account, "static@example.com");
}

#[test]
fn ephemeral_cert_expiry_is_capped_by_the_token_expiry() {
    // The token ends 08:16:40Z, before the certificate's 09:00:00Z: once it does, the instance cannot sign anyone in with the certificate.
    let token_ends = UNIX_EPOCH + Duration::from_secs(1_800_001_000);
    let cert = issue_cert(Arc::new(Expiring { expires_at: Some(token_ends) }), cert_json("2027-01-15T09:00:00.123Z")).unwrap();
    assert_eq!(cert.expires_at, token_ends);
}

#[test]
fn ephemeral_cert_expiry_is_kept_when_the_token_outlives_it_or_has_no_known_end() {
    for expires_at in [None, Some(UNIX_EPOCH + Duration::from_secs(1_800_009_999)), Some(UNIX_EPOCH + CERT_EXPIRES)] {
        let cert = issue_cert(Arc::new(Expiring { expires_at }), cert_json("2027-01-15T09:00:00.123Z")).unwrap();
        assert_eq!(cert.expires_at, UNIX_EPOCH + CERT_EXPIRES, "{expires_at:?}");
    }
}

#[test]
fn a_certificate_answer_without_a_certificate_or_an_expiry_is_malformed() {
    let tokens = || -> Arc<dyn TokenSource> { Arc::new(StaticToken("t0k".into())) };
    let mut no_cert = cert_json("2027-01-15T09:00:00.123Z");
    no_cert["ephemeralCert"].as_object_mut().unwrap().remove("cert");
    let mut no_expiry = cert_json("2027-01-15T09:00:00.123Z");
    no_expiry["ephemeralCert"].as_object_mut().unwrap().remove("expirationTime");
    let bodies = [json!({}), json!({ "ephemeralCert": {} }), no_cert, no_expiry, cert_json("tomorrow"), cert_json("2027-01-15T09:00:00+02:00")];
    for body in bodies {
        let result = issue_cert(tokens(), body.clone());
        assert!(matches!(result, Err(GcpError::Malformed(_))), "{body}: {result:?}");
    }
}

#[test]
fn a_certificate_answer_of_the_wrong_shape_does_not_put_the_certificate_in_the_error() {
    // `ephemeralCert` is text here: serde would quote it in its own message, and the certificate carries the access token.
    let error = issue_cert(Arc::new(StaticToken("t0k".into())), json!({ "ephemeralCert": CLIENT_CERT })).unwrap_err();
    assert!(matches!(error, GcpError::Malformed(_)), "{error:?}");
    assert!(!format!("{error:?} {error}").contains("Y2xpZW50LWNlcnQ="), "{error}");
}

#[test]
fn list_instances_keeps_postgres_instances_and_reads_the_iam_flag() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", LIST_PATH)
        .match_header("authorization", "Bearer t0k")
        .match_header("user-agent", Matcher::Exact(user_agent()))
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "kind": "sql#instancesList",
                "items": [
                    instance_json("orders-pg", "POSTGRES_16", Some("on"), &[("PRIMARY", "203.0.113.10"), ("PRIVATE", "198.51.100.5")]),
                    instance_json("billing-mysql", "MYSQL_8_0", Some("on"), &[("PRIMARY", "203.0.113.20")]),
                    instance_json("reports-pg", "POSTGRES_15", Some("off"), &[("PRIVATE", "198.51.100.9")]),
                ]
            })
            .to_string(),
        )
        .expect(1)
        .create();
    let found = admin(&server).list_instances(Some(ACCOUNT), PROJECT).unwrap();
    mock.assert();
    assert_eq!(
        found,
        vec![
            InstanceSummary { name: "orders-pg".into(), region: "asia-east1".into(), database_version: "POSTGRES_16".into(), public_ip: true, private_ip: true, iam_authentication: true },
            InstanceSummary { name: "reports-pg".into(), region: "asia-east1".into(), database_version: "POSTGRES_15".into(), public_ip: false, private_ip: true, iam_authentication: false },
        ]
    );
}

#[test]
fn list_instances_tolerates_instances_without_settings_or_addresses() {
    let mut server = mockito::Server::new();
    let bare = json!({ "name": "analytics-pg", "region": "asia-east1", "databaseVersion": "POSTGRES_14" });
    // An instance with no settings and no addresses is listed with everything off; one with no version is not PostgreSQL.
    let versionless = json!({ "name": "legacy-box", "region": "asia-east1" });
    server.mock("GET", LIST_PATH).with_body(json!({ "items": [bare, versionless] }).to_string()).create();
    let found = admin(&server).list_instances(Some(ACCOUNT), PROJECT).unwrap();
    assert_eq!(
        found,
        vec![InstanceSummary { name: "analytics-pg".into(), region: "asia-east1".into(), database_version: "POSTGRES_14".into(), public_ip: false, private_ip: false, iam_authentication: false }]
    );
}

#[test]
fn list_instances_of_a_project_without_instances_is_empty() {
    let mut server = mockito::Server::new();
    server.mock("GET", LIST_PATH).with_body(json!({ "kind": "sql#instancesList" }).to_string()).create();
    assert_eq!(admin(&server).list_instances(Some(ACCOUNT), PROJECT).unwrap(), vec![]);
}

#[test]
fn list_instances_follows_page_tokens() {
    let mut server = mockito::Server::new();
    // The first request has no query, so only this mock answers it; the second carries the token and only the other mock matches it.
    let first = server
        .mock("GET", LIST_PATH)
        .with_header("content-type", "application/json")
        .with_body(json!({ "items": [instance_json("orders-pg", "POSTGRES_16", Some("on"), &[("PRIMARY", "203.0.113.10")])], "nextPageToken": "page two/with+odd chars" }).to_string())
        .expect(1)
        .create();
    let second = server
        .mock("GET", LIST_PATH)
        .match_query(Matcher::UrlEncoded("pageToken".into(), "page two/with+odd chars".into()))
        .match_header("authorization", "Bearer t0k")
        .with_header("content-type", "application/json")
        .with_body(json!({ "items": [instance_json("reports-pg", "POSTGRES_15", Some("off"), &[])] }).to_string())
        .expect(1)
        .create();
    let found = admin(&server).list_instances(Some(ACCOUNT), PROJECT).unwrap();
    first.assert();
    second.assert();
    assert_eq!(found.iter().map(|summary| summary.name.as_str()).collect::<Vec<_>>(), ["orders-pg", "reports-pg"]);
}

#[test]
fn list_instances_reads_at_most_ten_pages() {
    let mut server = mockito::Server::new();
    let pages = server
        .mock("GET", LIST_PATH)
        .match_query(Matcher::Any)
        .with_header("content-type", "application/json")
        .with_body(json!({ "items": [instance_json("orders-pg", "POSTGRES_16", Some("on"), &[])], "nextPageToken": "more" }).to_string())
        .expect(10)
        .create();
    let found = admin(&server).list_instances(Some(ACCOUNT), PROJECT).unwrap();
    pages.assert();
    assert_eq!(found.len(), 10, "one instance a page, ten pages");
}

#[test]
fn a_disabled_api_names_the_api_and_project() {
    let mut server = mockito::Server::new();
    // Google's body for a project that has not enabled the API; the project in it is a number, the sentence names the one asked about.
    let body = json!({
        "error": {
            "code": 403,
            "message": "Cloud SQL Admin API has not been used in project 123456789012 before or it is disabled. Enable it by visiting the console, then retry.",
            "errors": [{ "message": "Cloud SQL Admin API has not been used in project 123456789012 before or it is disabled.", "domain": "usageLimits", "reason": "accessNotConfigured" }],
            "status": "PERMISSION_DENIED",
            "details": [
                { "@type": "type.googleapis.com/google.rpc.Help", "links": [{ "description": "Google developers console API activation", "url": "https://console.developers.google.com/apis/api/sqladmin.googleapis.com/overview?project=123456789012" }] },
                { "@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED", "domain": "googleapis.com", "metadata": { "service": "sqladmin.googleapis.com", "consumer": "projects/123456789012" } }
            ]
        }
    });
    answer_every_call(&mut server, 403, &body.to_string());
    let message = "The Cloud SQL Admin API is not enabled in acme-dev-654321. Enable it in the Google Cloud console, then try again.";
    for error in errors_of(&admin(&server), Some(ACCOUNT)) {
        assert_eq!(error, GcpError::Refused { api: "Cloud SQL Admin", message: message.into() });
        assert_eq!(error.to_string(), format!("Cloud SQL Admin refused the request: {message}"), "one period at the end");
    }
}

#[test]
fn an_unknown_instance_names_the_connection() {
    let mut server = mockito::Server::new();
    let body = json!({ "error": { "code": 404, "message": "The Cloud SQL instance does not exist.", "errors": [{ "domain": "global", "reason": "instanceDoesNotExist" }] } });
    answer_every_call(&mut server, 404, &body.to_string());
    let [settings, cert, list] = errors_of(&admin(&server), Some(ACCOUNT));
    let message = "Cloud SQL has no instance acme-dev-654321:asia-east1:orders-pg.";
    for error in [settings, cert] {
        assert_eq!(error, GcpError::Refused { api: "Cloud SQL Admin", message: message.into() });
        assert_eq!(error.to_string(), format!("Cloud SQL Admin refused the request: {message}"));
    }
    // A project listing has no instance to name.
    assert_eq!(list, GcpError::Refused { api: "Cloud SQL Admin", message: "Cloud SQL has no project acme-dev-654321.".into() });
}

#[test]
fn a_forbidden_call_is_denied_naming_the_account_the_token_belongs_to() {
    let mut server = mockito::Server::new();
    // 403 for another reason than a disabled API, with Google's own details, and without a body at all.
    let other_reason = json!({ "error": { "code": 403, "message": "Permission denied", "details": [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "IAM_PERMISSION_DENIED" }] } });
    for body in [other_reason.to_string(), String::new(), "<html>Forbidden</html>".into()] {
        answer_every_call(&mut server, 403, &body);
        // `None` asks for the default account: the sentence names the one the token source resolved (`static@example.com` for the fake).
        for (asked, resolved) in [(Some("ops@example.com"), "ops@example.com"), (None, "static@example.com")] {
            for error in errors_of(&admin(&server), asked) {
                assert_eq!(error, GcpError::Denied { api: "Cloud SQL Admin", status: 403, account: resolved.into() }, "{body}");
            }
        }
    }
    let mut unauthorized = mockito::Server::new();
    answer_every_call(&mut unauthorized, 401, "{}");
    let error = admin(&unauthorized).connect_settings(Some(ACCOUNT), &instance()).unwrap_err();
    assert_eq!(error, GcpError::Denied { api: "Cloud SQL Admin", status: 401, account: ACCOUNT.into() });
    assert_eq!(error.to_string(), "frank@example.com may not call the Cloud SQL Admin API (HTTP 401).");
}

#[test]
fn a_service_disabled_reason_on_a_401_is_still_a_denial() {
    // Only a 403 can mean a disabled API.
    let mut server = mockito::Server::new();
    let body = json!({ "error": { "code": 401, "details": [{ "reason": "SERVICE_DISABLED" }] } });
    answer_every_call(&mut server, 401, &body.to_string());
    assert!(matches!(admin(&server).connect_settings(Some(ACCOUNT), &instance()), Err(GcpError::Denied { status: 401, .. })));
}

#[test]
fn a_400_carries_the_apis_words_on_one_line_cut_to_256_printable_characters() {
    let mut server = mockito::Server::new();
    let long = format!("Invalid request:\n\t{}\u{7} end.", "x".repeat(400));
    answer_every_call(&mut server, 400, &json!({ "error": { "code": 400, "message": long, "status": "INVALID_ARGUMENT" } }).to_string());
    for error in errors_of(&admin(&server), Some(ACCOUNT)) {
        let GcpError::Refused { api, message } = error else { panic!("a refusal expected, got {error:?}") };
        assert_eq!(api, "Cloud SQL Admin");
        assert_eq!(message.chars().count(), 256);
        assert!(message.starts_with("Invalid request: xxxx"), "{message}");
        assert!(message.chars().all(|c| !c.is_control()), "{message:?}");
    }
    // A short message is kept as it is, and the sentence ends in one period only.
    let mut short = mockito::Server::new();
    answer_every_call(&mut short, 400, &json!({ "error": { "code": 400, "message": "Invalid database version." } }).to_string());
    let error = admin(&short).connect_settings(Some(ACCOUNT), &instance()).unwrap_err();
    assert_eq!(error, GcpError::Refused { api: "Cloud SQL Admin", message: "Invalid database version.".into() });
    assert_eq!(error.to_string(), "Cloud SQL Admin refused the request: Invalid database version.");
}

#[test]
fn a_400_that_says_nothing_is_reported_by_its_number() {
    let mut server = mockito::Server::new();
    for body in ["", "{}", r#"{"error":{"code":400}}"#, r#"{"error":{"message":" \n "}}"#] {
        answer_every_call(&mut server, 400, body);
        assert_eq!(admin(&server).connect_settings(Some(ACCOUNT), &instance()).unwrap_err(), GcpError::Http { api: "Cloud SQL Admin", status: 400 }, "{body:?}");
    }
}

#[test]
fn a_refusal_never_repeats_the_access_token() {
    let token = "ya29.fake-access-token-for-the-test";
    let mut server = mockito::Server::new();
    let message = format!("Invalid access_token {token} in the request ({token}).");
    answer_every_call(&mut server, 400, &json!({ "error": { "code": 400, "message": message } }).to_string());
    let admin = RestSqlAdmin::with_base(Arc::new(StaticToken(token.into())), &server.url());
    for error in errors_of(&admin, Some(ACCOUNT)) {
        assert!(!format!("{error:?} {error}").contains(token), "{error}");
        assert_eq!(error, GcpError::Refused { api: "Cloud SQL Admin", message: "Invalid access_token [redacted] in the request ([redacted]).".into() });
    }
}

#[test]
fn other_statuses_are_reported_by_number() {
    for status in [409, 429, 500, 503] {
        let mut server = mockito::Server::new();
        answer_every_call(&mut server, status, r#"{"error":{"message":"details that are not repeated"}}"#);
        for error in errors_of(&admin(&server), Some(ACCOUNT)) {
            assert_eq!(error, GcpError::Http { api: "Cloud SQL Admin", status: status as u16 });
        }
    }
    assert_eq!(GcpError::Http { api: "Cloud SQL Admin", status: 503 }.to_string(), "The Cloud SQL Admin API answered 503.");
}

#[test]
fn a_server_that_cannot_be_reached_is_a_network_error_without_its_address() {
    // A port that was free a moment ago and has no listener now.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let admin = RestSqlAdmin::with_base(Arc::new(StaticToken("t0k".into())), &format!("http://127.0.0.1:{port}"));
    for error in errors_of(&admin, Some(ACCOUNT)) {
        assert!(matches!(error, GcpError::Network(_)), "{error:?}");
        assert!(!error.to_string().contains("127.0.0.1"), "{error}");
    }
}

#[test]
fn a_call_that_does_not_answer_in_time_fails_as_a_network_error() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    // A server that answers every connection two seconds late.
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
    let admin = RestSqlAdmin::with_timeout(Arc::new(StaticToken("t0k".into())), &base, Duration::from_millis(300));
    let started = Instant::now();
    let error = admin.connect_settings(Some(ACCOUNT), &instance()).unwrap_err();
    assert!(matches!(error, GcpError::Network(_)), "{error:?}");
    assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
    // The shipped client waits as long as the other Google calls do.
    assert_eq!(crate::gcp::rest::HTTP_TIMEOUT, Duration::from_secs(20));
}

#[test]
fn a_sign_in_problem_is_reported_before_any_call_is_made() {
    let mut server = mockito::Server::new();
    let calls = [("GET", SETTINGS_PATH), ("POST", CERT_PATH), ("GET", LIST_PATH)].map(|(method, path)| server.mock(method, path).match_query(Matcher::Any).expect(0).create());
    let admin = RestSqlAdmin::with_base(Arc::new(SignedOut), &server.url());
    for error in errors_of(&admin, Some(ACCOUNT)) {
        assert_eq!(error, GcpError::Auth(AuthError::SignInExpired { account: ACCOUNT.into() }));
    }
    for call in &calls {
        call.assert();
    }
}

#[test]
fn a_name_is_one_path_segment_whatever_it_holds() {
    assert_eq!(segment("orders-pg"), "orders-pg");
    assert_eq!(segment("example.com:acme-dev-654321"), "example.com:acme-dev-654321", "a project with a domain keeps its colon");
    assert_eq!(segment("a/b?c=d#e f%g"), "a%2Fb%3Fc%3Dd%23e%20f%25g");
    assert_eq!(segment("é"), "%C3%A9");
    assert_eq!(segment(""), "");
}

#[test]
fn names_cannot_add_a_segment_or_a_query_to_the_request() {
    let odd = InstanceRef { project: "acme/dev?x=1".into(), region: "asia-east1".into(), instance: "orders pg#1".into() };
    let mut server = mockito::Server::new();
    let settings = server.mock("GET", "/v1/projects/acme%2Fdev%3Fx%3D1/instances/orders%20pg%231/connectSettings").with_body(settings_json().to_string()).expect(1).create();
    let cert = server.mock("POST", "/v1/projects/acme%2Fdev%3Fx%3D1/instances/orders%20pg%231:generateEphemeralCert").with_body(cert_json("2027-01-15T09:00:00.123Z").to_string()).expect(1).create();
    let list = server.mock("GET", "/v1/projects/acme%2Fdev%3Fx%3D1/instances").with_body(json!({}).to_string()).expect(1).create();
    let admin = admin(&server);
    admin.connect_settings(Some(ACCOUNT), &odd).unwrap();
    admin.ephemeral_cert(Some(ACCOUNT), &odd, key()).unwrap();
    admin.list_instances(Some(ACCOUNT), &odd.project).unwrap();
    for mock in [settings, cert, list] {
        mock.assert();
    }
}

#[test]
fn ephemeral_keys_are_rsa_2048_with_a_pem_public_key() {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    let first = EphemeralKey::generate().unwrap();
    let second = EphemeralKey::generate().unwrap();
    let pem = first.public_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n") && pem.trim_end().ends_with("-----END PUBLIC KEY-----"), "{pem}");
    let public = rsa::RsaPublicKey::from_public_key_pem(pem).expect("a SubjectPublicKeyInfo PEM of an RSA key");
    assert_eq!(public.n().bits(), 2048);
    assert_eq!(public.e(), &rsa::BigUint::from(65537u32));
    assert_ne!(first.public_pem(), second.public_pem(), "every connection gets a key of its own");
}

#[test]
fn the_private_key_is_pkcs8_for_the_public_key_and_rustls_takes_it() {
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
    let key = key();
    let PrivateKeyDer::Pkcs8(der) = key.private_der() else { panic!("PKCS#8 expected") };
    let private = rsa::RsaPrivateKey::from_pkcs8_der(der.secret_pkcs8_der()).expect("a PKCS#8 RSA private key");
    let derived = rsa::RsaPublicKey::from(&private).to_public_key_pem(LineEnding::LF).unwrap();
    assert_eq!(derived, key.public_pem(), "the private key is the one the certificate is made for");
    // What the TLS side does with it.
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key.private_der()).expect("rustls loads the key");
    assert_eq!(signer.algorithm(), rustls::SignatureAlgorithm::RSA);
}

#[test]
fn an_ephemeral_key_prints_no_key_material() {
    use base64::Engine as _;
    let key = key();
    let PrivateKeyDer::Pkcs8(der) = key.private_der() else { panic!("PKCS#8 expected") };
    let der = der.secret_pkcs8_der();
    let shown = format!("{key:?} {:#?}", key);
    let as_base64 = base64::engine::general_purpose::STANDARD.encode(&der[..24]);
    let as_decimals = format!("{:?}", &der[..8]).trim_matches(['[', ']']).to_string();
    let as_hex: String = der[..8].iter().map(|byte| format!("{byte:02x}")).collect();
    let public_body = key.public_pem().lines().nth(1).unwrap().to_string();
    for material in [as_base64, as_decimals, as_hex, public_body, "BEGIN".to_string()] {
        assert!(!shown.contains(&material), "{material} is in {shown}");
    }
}

#[test]
fn an_ephemeral_cert_prints_no_certificate_text() {
    // The certificate carries the access token, so it is not printed either.
    let cert = EphemeralCert { cert_pem: CLIENT_CERT.into(), expires_at: UNIX_EPOCH + CERT_EXPIRES, account: ACCOUNT.into() };
    let shown = format!("{cert:?} {cert:#?}");
    assert!(shown.contains(ACCOUNT));
    assert!(!shown.contains("BEGIN CERTIFICATE") && !shown.contains("Y2xpZW50LWNlcnQ="), "{shown}");
}
