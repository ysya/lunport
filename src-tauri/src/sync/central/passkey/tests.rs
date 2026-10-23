use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
const ORIGIN: &str = "https://passkey.test";
fn config() -> Config {
    Config {
        origin: ORIGIN.into(),
        rp_id: "passkey.test".into(),
    }
}
#[test]
fn persisted_passkey_profile_remains_valid_after_http_routes_move_to_v1() {
    use crate::sync::central::{
        authentication::Config as LoginConfig, client_state::ProfileData,
        credentials::Profile,
    };
    let issuer = format!("{ORIGIN}/v2/auth/passkey");
    let subject = "c".repeat(64);
    let saved = Profile::new(ORIGIN, &issuer, &subject).unwrap();
    let profile = ProfileData {
        origin: ORIGIN.into(),
        issuer,
        subject,
        locator: saved.locator,
        login: LoginConfig::Passkey(config()),
    };
    profile.profile().unwrap();
}
struct Http {
    begin: Mutex<Option<Value>>,
    exchanges: AtomicUsize,
    refreshes: AtomicUsize,
    subject: Mutex<String>,
    failure: Mutex<bool>,
}
impl Http {
    fn new() -> Self {
        Self {
            begin: Mutex::new(None),
            exchanges: AtomicUsize::new(0),
            refreshes: AtomicUsize::new(0),
            subject: Mutex::new("c".repeat(64)),
            failure: Mutex::new(false),
        }
    }
    fn callback(&self) -> String {
        let body = self.begin.lock().unwrap();
        let b = body.as_ref().unwrap();
        format!(
            "{}?code=lpkc1.{}.{}&state={}",
            b["redirect_uri"].as_str().unwrap(),
            "a".repeat(32),
            "b".repeat(64),
            b["state"].as_str().unwrap()
        )
    }
}
impl SyncHttpClient for Http {
    type Error = std::io::Error;
    fn call(
        &self,
        request: openidconnect::HttpRequest,
    ) -> Result<openidconnect::HttpResponse, Self::Error> {
        assert_eq!(request.method(), openidconnect::http::Method::POST);
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().host(), Some("passkey.test"));
        let body: Value = serde_json::from_slice(request.body()).unwrap();
        let value = match request.uri().path() {
            "/v1/auth/passkey/authorize" => {
                assert!(body["state"].as_str().unwrap().len() >= 32);
                *self.begin.lock().unwrap() = Some(body);
                json!({"url":format!("{ORIGIN}/v1/auth/passkey/page?flow={}#key={}","a".repeat(32),"b".repeat(64)),"expires_in":300})
            }
            "/v1/auth/passkey/exchange" => {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                let begin = self.begin.lock().unwrap();
                let b = begin.as_ref().unwrap();
                assert_eq!(body["redirect_uri"], b["redirect_uri"]);
                assert_eq!(
                    URL_SAFE_NO_PAD.encode(Sha256::digest(
                        body["verifier"].as_str().unwrap().as_bytes()
                    )),
                    b["code_challenge"].as_str().unwrap()
                );
                self.grant()
            }
            "/v1/auth/passkey/refresh" => {
                self.refreshes.fetch_add(1, Ordering::SeqCst);
                assert!(body["refresh_token"]
                    .as_str()
                    .unwrap()
                    .starts_with("lpkr1."));
                self.grant()
            }
            "/v1/auth/passkey/logout" => {
                assert!(body["token"].as_str().unwrap().starts_with("lpkr1."));
                json!({"signed_out":true})
            }
            _ => panic!("unexpected provider request"),
        };
        Ok(openidconnect::http::Response::builder()
            .status(if *self.failure.lock().unwrap() {
                401
            } else {
                200
            })
            .body(serde_json::to_vec(&value).unwrap())
            .unwrap())
    }
}
impl Http {
    fn grant(&self) -> Value {
        json!({"issuer":format!("{ORIGIN}/v2/auth/passkey"),"subject":&*self.subject.lock().unwrap(),"access_token":format!("lpka1.{}.{}","d".repeat(32),"e".repeat(64)),"refresh_token":format!("lpkr1.{}.{}","d".repeat(32),"f".repeat(64)),"expires_in":300})
    }
}
#[test]
fn native_attempt_binds_origin_callback_state_and_pkce_before_accepting_tokens() {
    let http = Http::new();
    let (attempt, url) = Attempt::begin(config(), 41823, None, false, &http).unwrap();
    assert!(url.starts_with(ORIGIN));
    let callback = http.callback();
    let expected = format!("lpkc1.{}.{}", "a".repeat(32), "b".repeat(64));
    assert_eq!(attempt.validate_callback(&callback).unwrap(), expected);
    for bad in [
        callback.replace("127.0.0.1", "localhost"),
        callback.replace("41823", "41824"),
        callback.replace("passkey/callback", "oauth/callback"),
        format!("{callback}&extra=1"),
        format!("{callback}#fragment"),
        callback.replace("state=", "state=bad"),
        callback.replace("code=lpkc1", "code=other"),
    ] {
        assert!(attempt.validate_callback(&bad).is_err(), "{bad}");
    }
    assert_eq!(http.exchanges.load(Ordering::SeqCst), 0);
    let tokens = attempt.finish(&callback, &http).unwrap();
    assert_eq!(tokens.subject, "c".repeat(64));
    assert!(tokens.access.starts_with("lpka1."));
    assert_eq!(http.exchanges.load(Ordering::SeqCst), 1);
}
#[test]
fn fresh_capability_requires_an_explicit_expected_account_and_rejects_a_different_subject() {
    let http = Http::new();
    let profile = super::super::credentials::Profile::new(
        ORIGIN,
        &format!("{ORIGIN}/v2/auth/passkey"),
        &"c".repeat(64),
    )
    .unwrap();
    let (attempt, _) =
        Attempt::begin(config(), 41823, Some(profile.locator.clone()), true, &http).unwrap();
    let callback = http.callback();
    attempt.finish_fresh(&callback, &http).unwrap();
    let (attempt, _) = Attempt::begin(config(), 41823, Some(profile.locator), true, &http).unwrap();
    *http.subject.lock().unwrap() = "d".repeat(64);
    let callback = http.callback();
    assert!(attempt.finish_fresh(&callback, &http).is_err());
    let (attempt, _) = Attempt::begin(config(), 41823, None, false, &http).unwrap();
    let callback = http.callback();
    let calls = http.exchanges.load(Ordering::SeqCst);
    assert!(attempt.finish_fresh(&callback, &http).is_err());
    assert_eq!(http.exchanges.load(Ordering::SeqCst), calls);
}
#[test]
fn protected_background_renewal_uses_the_passkey_endpoint_and_never_replays_uncertain_refresh() {
    use crate::sync::{
        central::{
            authentication::Config as LoginConfig,
            credentials::{self, Profile},
        },
        testkit::MemKeychain,
    };
    let http = Http::new();
    let (attempt, _) = Attempt::begin(config(), 41823, None, false, &http).unwrap();
    let callback = http.callback();
    let tokens = attempt.finish(&callback, &http).unwrap();
    let profile = Profile::new(ORIGIN, &tokens.issuer, &tokens.subject).unwrap();
    let keychain = MemKeychain::default();
    let method = LoginConfig::Passkey(config());
    credentials::save_refresh(&keychain, &profile, &method, &tokens).unwrap();
    credentials::renew(&keychain, &profile, &method, false, &http).unwrap();
    assert_eq!(http.refreshes.load(Ordering::SeqCst), 1);
    *http.failure.lock().unwrap() = true;
    assert!(credentials::renew(&keychain, &profile, &method, false, &http).is_err());
    assert_eq!(http.refreshes.load(Ordering::SeqCst), 2);
    *http.failure.lock().unwrap() = false;
    assert!(credentials::renew(&keychain, &profile, &method, false, &http).is_err());
    assert_eq!(http.refreshes.load(Ordering::SeqCst), 2);
}
#[test]
fn defaults_use_passkey_but_existing_oidc_profiles_never_silently_switch() {
    use crate::sync::central::{
        api::Info, authentication::Config as LoginConfig, client_state::ProfileData,
        credentials::Profile, oidc::OidcConfig,
    };
    let oidc = OidcConfig {
        issuer: "https://identity.test".into(),
        client_id: "native".into(),
        scopes: vec!["openid".into()],
        audience: Some("api".into()),
    };
    let old = Profile::new(ORIGIN, &oidc.issuer, "synthetic").unwrap();
    let profile:ProfileData=serde_json::from_value(json!({"origin":ORIGIN,"issuer":old.issuer,"subject":old.subject,"locator":old.locator,"oidc":oidc})).unwrap();
    profile.profile().unwrap();
    assert!(matches!(profile.login, LoginConfig::Oidc(_)));
    let encoded = serde_json::to_value(&profile).unwrap();
    assert_eq!(encoded["login"]["method"], "oidc");
    assert!(encoded.get("oidc").is_none());
    let mut info: Info = serde_json::from_value(
        json!({"protocol":2,"features":[],"default_auth":"passkey","passkey":config(),"oidc":oidc}),
    )
    .unwrap();
    assert!(matches!(
        info.login_for(ORIGIN, None).unwrap(),
        LoginConfig::Passkey(_)
    ));
    assert!(matches!(
        info.login_for(ORIGIN, Some(&profile)).unwrap(),
        LoginConfig::Oidc(_)
    ));
    use crate::sync::central::authentication::Method;
    assert!(matches!(
        info.login_for_method(ORIGIN, None, Some(Method::Oidc))
            .unwrap(),
        LoginConfig::Oidc(_)
    ));
    assert!(info
        .login_for_method(ORIGIN, Some(&profile), Some(Method::Passkey))
        .is_err());
    info.oidc = None;
    assert!(info.login_for(ORIGIN, Some(&profile)).is_err());
    assert!(info
        .login_for_method(ORIGIN, None, Some(Method::Oidc))
        .is_err());
    info.passkey.as_mut().unwrap().rp_id = "other.test".into();
    assert!(info.login_for(ORIGIN, None).is_err());
}

#[test]
fn logout_uses_only_the_bound_native_credential_and_does_not_require_a_browser() {
    let http = Http::new();
    logout(
        &config(),
        &format!("lpkr1.{}.{}", "d".repeat(32), "f".repeat(64)),
        &http,
    )
    .unwrap();
    assert_eq!(http.exchanges.load(Ordering::SeqCst), 0);
    *http.failure.lock().unwrap() = true;
    assert!(logout(
        &config(),
        &format!("lpkr1.{}.{}", "d".repeat(32), "f".repeat(64)),
        &http
    )
    .is_err());
}
