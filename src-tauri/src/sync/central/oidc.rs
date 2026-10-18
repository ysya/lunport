//! Native OIDC uses the system browser and a public client with PKCE. Tokens stay in Rust.
//! The caller binds a loopback listener before begin(), and consumes one valid callback.
use crate::error::AppError;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    AccessTokenHash, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, SyncHttpClient,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX_OIDC_RESPONSE: usize = 256 * 1024;
fn error(message: &str) -> AppError {
    AppError::Other(message.into())
}
fn endpoint(url: &reqwest::Url) -> bool {
    url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https"
            || cfg!(any(test, feature = "development-profile"))
                && url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub audience: Option<String>,
}
impl OidcConfig {
    pub fn validate(&self) -> Result<(), AppError> {
        let issuer = reqwest::Url::parse(&self.issuer)
            .map_err(|_| error("Invalid sign-in provider configuration."))?;
        if !endpoint(&issuer)
            || issuer.query().is_some()
            || self.client_id.is_empty()
            || self.client_id.len() > 256
            || self.scopes.len() > 16
            || self.scopes.iter().any(|s| {
                s.is_empty()
                    || s.len() > 128
                    || !s.bytes().all(|b| matches!(b,0x21|0x23..=0x5b|0x5d..=0x7e))
            })
            || self
                .audience
                .as_ref()
                .is_some_and(|a| a.is_empty() || a.len() > 1024 || a.chars().any(char::is_control))
        {
            return Err(error("Invalid sign-in provider configuration."));
        }
        Ok(())
    }
}
pub struct BoundedHttp(reqwest::blocking::Client);
impl BoundedHttp {
    pub fn new() -> Result<Self, AppError> {
        reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("Lunport/", env!("CARGO_PKG_VERSION")))
            .build()
            .map(Self)
            .map_err(|_| error("Sign-in network initialization failed."))
    }
}
impl SyncHttpClient for BoundedHttp {
    type Error = std::io::Error;
    fn call(
        &self,
        request: openidconnect::HttpRequest,
    ) -> Result<openidconnect::HttpResponse, Self::Error> {
        let failure = || std::io::Error::other("Identity provider request failed.");
        let url = reqwest::Url::parse(&request.uri().to_string()).map_err(|_| failure())?;
        if !endpoint(&url) {
            return Err(failure());
        }
        let response = self
            .0
            .request(request.method().clone(), url)
            .headers(request.headers().clone())
            .body(request.body().clone())
            .send()
            .map_err(|_| failure())?;
        if response
            .content_length()
            .is_some_and(|size| size > MAX_OIDC_RESPONSE as u64)
        {
            return Err(failure());
        }
        let status = response.status();
        let headers = response.headers().clone();
        let body =
            crate::sync::relay::read_capped(response, MAX_OIDC_RESPONSE).map_err(|_| failure())?;
        let mut output = openidconnect::http::Response::builder()
            .status(status)
            .body(body)
            .map_err(|_| failure())?;
        *output.headers_mut() = headers;
        Ok(output)
    }
}
/// No Debug or Serialize; access/refresh credentials are never a frontend DTO.
pub struct LoginTokens {
    pub issuer: String,
    pub subject: String,
    pub nonce: Zeroizing<String>,
    pub access: Zeroizing<String>,
    pub refresh: Option<Zeroizing<String>>,
    pub expires_in: Duration,
}
pub struct LoginAttempt {
    config: OidcConfig,
    metadata: CoreProviderMetadata,
    redirect: RedirectUrl,
    state: CsrfToken,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    started: Instant,
}
impl LoginAttempt {
    pub fn begin(
        config: OidcConfig,
        port: u16,
        http: &impl SyncHttpClient,
    ) -> Result<(Self, String), AppError> {
        config.validate()?;
        if port == 0 {
            return Err(error("Bind the local sign-in callback before starting."));
        }
        let metadata = CoreProviderMetadata::discover(
            &IssuerUrl::new(config.issuer.clone())
                .map_err(|_| error("Invalid sign-in provider."))?,
            http,
        )
        .map_err(|_| error("Could not verify the sign-in provider."))?;
        if !endpoint(metadata.authorization_endpoint().url())
            || metadata.token_endpoint().is_none_or(|u| !endpoint(u.url()))
        {
            return Err(error("The sign-in provider requires secure endpoints."));
        }
        let redirect = RedirectUrl::new(format!("http://127.0.0.1:{port}/oauth/callback"))
            .map_err(|_| error("Invalid local sign-in callback."))?;
        let client = CoreClient::from_provider_metadata(
            metadata.clone(),
            ClientId::new(config.client_id.clone()),
            None,
        )
        .set_redirect_uri(redirect.clone());
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                openidconnect::core::CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge)
            .add_scope(Scope::new("openid".into()));
        let mut unique = BTreeSet::from(["openid".to_string()]);
        for scope in &config.scopes {
            if unique.insert(scope.clone()) {
                request = request.add_scope(Scope::new(scope.clone()));
            }
        }
        if let Some(audience) = &config.audience {
            request = request.add_extra_param("audience", audience);
        }
        let (url, state, nonce) = request.url();
        Ok((
            Self {
                config,
                metadata,
                redirect,
                state,
                nonce,
                verifier,
                started: Instant::now(),
            },
            url.to_string(),
        ))
    }
    pub fn validate_callback(&self, callback: &str) -> Result<String, AppError> {
        if self.started.elapsed() > Duration::from_secs(10 * 60) || callback.len() > 16 * 1024 {
            return Err(error("Sign-in expired. Start again."));
        }
        let callback =
            reqwest::Url::parse(callback).map_err(|_| error("Invalid sign-in callback."))?;
        if callback.origin() != self.redirect.url().origin()
            || callback.path() != self.redirect.url().path()
            || callback.fragment().is_some()
            || !callback.username().is_empty()
            || callback.password().is_some()
        {
            return Err(error("Invalid sign-in callback."));
        }
        let mut query = BTreeMap::new();
        for (key, value) in callback.query_pairs() {
            if query.insert(key.into_owned(), value.into_owned()).is_some() {
                return Err(error("Ambiguous sign-in callback."));
            }
        }
        if query.contains_key("error")
            || query
                .get("state")
                .is_none_or(|value| CsrfToken::new(value.clone()) != self.state)
            || query
                .get("iss")
                .is_some_and(|issuer| issuer != &self.config.issuer)
        {
            return Err(error("Sign-in response could not be verified."));
        }
        query
            .remove("code")
            .filter(|code| {
                !code.is_empty() && code.len() <= 4096 && !code.chars().any(char::is_control)
            })
            .ok_or_else(|| error("Sign-in response has no valid authorization code."))
    }
    pub fn finish(
        self,
        callback: &str,
        http: &impl SyncHttpClient,
    ) -> Result<LoginTokens, AppError> {
        let code = self.validate_callback(callback)?;
        let client = CoreClient::from_provider_metadata(
            self.metadata,
            ClientId::new(self.config.client_id),
            None,
        )
        .set_redirect_uri(self.redirect);
        let response = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| error("The sign-in provider has no token endpoint."))?
            .set_pkce_verifier(self.verifier)
            .request(http)
            .map_err(|_| error("Sign-in exchange failed. Start again."))?;
        let id_token = response
            .id_token()
            .ok_or_else(|| error("The sign-in provider returned no identity proof."))?;
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &self.nonce)
            .map_err(|_| error("The sign-in identity proof is invalid."))?;
        if let Some(expected) = claims.access_token_hash() {
            let algorithm = id_token
                .signing_alg()
                .map_err(|_| error("Invalid sign-in signature."))?;
            let key = id_token
                .signing_key(&verifier)
                .map_err(|_| error("Invalid sign-in key."))?;
            if AccessTokenHash::from_token(response.access_token(), algorithm, key)
                .map_err(|_| error("Invalid access-token proof."))?
                != *expected
            {
                return Err(error("Invalid access-token proof."));
            }
        }
        let subject = claims.subject().as_str();
        if subject.is_empty() || subject.len() > 512 {
            return Err(error(
                "The sign-in provider returned an invalid account identity.",
            ));
        }
        Ok(LoginTokens {
            issuer: self.config.issuer,
            subject: subject.into(),
            nonce: Zeroizing::new(self.nonce.secret().clone()),
            access: Zeroizing::new(response.access_token().secret().clone()),
            refresh: response
                .refresh_token()
                .map(|r| Zeroizing::new(r.secret().clone())),
            expires_in: response.expires_in().unwrap_or(Duration::from_secs(300)),
        })
    }
}
/// Provider refresh rotation/reuse detection remains the provider's responsibility.
/// A refreshed ID token, when present, may omit nonce; a present nonce must match the original.
pub fn refresh(
    config: &OidcConfig,
    subject: &str,
    nonce: &str,
    secret: &str,
    http: &impl SyncHttpClient,
) -> Result<LoginTokens, AppError> {
    config.validate()?;
    if subject.is_empty() || subject.len() > 512 || secret.is_empty() || secret.len() > 16384 {
        return Err(error("Stored sign-in credential is invalid."));
    }
    let metadata = CoreProviderMetadata::discover(
        &IssuerUrl::new(config.issuer.clone()).map_err(|_| error("Invalid sign-in provider."))?,
        http,
    )
    .map_err(|_| error("Could not verify the sign-in provider."))?;
    if metadata.token_endpoint().is_none_or(|u| !endpoint(u.url())) {
        return Err(error("The sign-in provider requires secure endpoints."));
    }
    let client =
        CoreClient::from_provider_metadata(metadata, ClientId::new(config.client_id.clone()), None);
    let response = client
        .exchange_refresh_token(&RefreshToken::new(secret.into()))
        .map_err(|_| error("The sign-in provider has no token endpoint."))?
        .request(http)
        .map_err(|_| error("Sign-in renewal failed. Sign in again."))?;
    if let Some(token) = response.id_token() {
        let verifier = client.id_token_verifier();
        let expected = Nonce::new(nonce.into());
        let claims = token
            .claims(&verifier, |actual: Option<&Nonce>| {
                if actual.is_some_and(|actual| actual != &expected) {
                    Err("nonce mismatch".into())
                } else {
                    Ok(())
                }
            })
            .map_err(|_| error("Renewed identity proof is invalid."))?;
        if claims.subject().as_str() != subject {
            return Err(error("Sign-in renewal changed account identity."));
        }
        if let Some(expected) = claims.access_token_hash() {
            let algorithm = token
                .signing_alg()
                .map_err(|_| error("Invalid sign-in signature."))?;
            let key = token
                .signing_key(&verifier)
                .map_err(|_| error("Invalid sign-in key."))?;
            if AccessTokenHash::from_token(response.access_token(), algorithm, key)
                .map_err(|_| error("Invalid access-token proof."))?
                != *expected
            {
                return Err(error("Invalid access-token proof."));
            }
        }
    }
    Ok(LoginTokens {
        issuer: config.issuer.clone(),
        subject: subject.into(),
        nonce: Zeroizing::new(nonce.into()),
        access: Zeroizing::new(response.access_token().secret().clone()),
        refresh: Some(Zeroizing::new(
            response
                .refresh_token()
                .map_or(secret, |token| token.secret())
                .into(),
        )),
        expires_in: response.expires_in().unwrap_or(Duration::from_secs(300)),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn setup() -> (mockito::ServerGuard, LoginAttempt, reqwest::Url) {
        setup_with_keys(json!({"keys":[]}))
    }
    fn setup_with_keys(
        jwks: serde_json::Value,
    ) -> (mockito::ServerGuard, LoginAttempt, reqwest::Url) {
        let mut server = mockito::Server::new();
        let issuer = server.url();
        let metadata = json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/jwks"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"]});
        server
            .mock("GET", "/.well-known/openid-configuration")
            .with_header("content-type", "application/json")
            .with_body(metadata.to_string())
            .create();
        server
            .mock("GET", "/jwks")
            .with_header("content-type", "application/json")
            .with_body(jwks.to_string())
            .create();
        let (attempt, url) = LoginAttempt::begin(
            OidcConfig {
                issuer,
                client_id: "public-desktop".into(),
                scopes: vec![
                    "openid".into(),
                    "offline_access".into(),
                    "lunport:sync".into(),
                ],
                audience: Some("lunport-api".into()),
            },
            41234,
            &BoundedHttp::new().unwrap(),
        )
        .unwrap();
        (server, attempt, reqwest::Url::parse(&url).unwrap())
    }
    #[test]
    fn browser_authorization_uses_pkce_state_nonce_and_an_exact_bound_loopback_redirect() {
        let (_server, attempt, url) = setup();
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], "public-desktop");
        assert_eq!(
            query["redirect_uri"],
            "http://127.0.0.1:41234/oauth/callback"
        );
        assert_eq!(query["state"], *attempt.state.secret());
        assert_eq!(query["nonce"], *attempt.nonce.secret());
        assert!(!query.contains_key("client_secret"));
        assert_ne!(query["code_challenge"], *attempt.verifier.secret());
        let mut callback = reqwest::Url::parse("http://127.0.0.1:41234/oauth/callback").unwrap();
        callback
            .query_pairs_mut()
            .append_pair("code", "synthetic-code")
            .append_pair("state", attempt.state.secret());
        assert_eq!(
            attempt.validate_callback(callback.as_str()).unwrap(),
            "synthetic-code"
        );
        for value in [
            callback.as_str().replace(":41234/", ":41235/"),
            callback.as_str().replace("/oauth/callback", "/other"),
            format!("{}&state=duplicate", callback),
            format!("{}&iss=https%3A%2F%2Fwrong.example", callback),
            format!("{}#fragment", callback),
        ] {
            assert!(attempt.validate_callback(&value).is_err());
        }
    }
    #[test]
    fn invalid_state_or_provider_error_never_reaches_the_token_endpoint() {
        let (_server, attempt, _) = setup();
        let callback = "http://127.0.0.1:41234/oauth/callback?code=synthetic&state=wrong";
        assert!(attempt
            .finish(callback, &BoundedHttp::new().unwrap())
            .is_err());
    }
    #[test]
    fn provider_body_cap_and_redirect_policy_apply_before_parsing() {
        let mut server = mockito::Server::new();
        let issuer = server.url();
        let http = BoundedHttp::new().unwrap();
        let request = || {
            openidconnect::http::Request::builder()
                .uri(format!("{issuer}/large"))
                .body(Vec::new())
                .unwrap()
        };
        server
            .mock("GET", "/large")
            .with_body(" ".repeat(MAX_OIDC_RESPONSE + 1))
            .create();
        assert!(http.call(request()).is_err());
        server
            .mock("GET", "/redirect")
            .with_status(302)
            .with_header("location", &format!("{issuer}/must-not-fetch"))
            .create();
        let response = http
            .call(
                openidconnect::http::Request::builder()
                    .uri(format!("{issuer}/redirect"))
                    .body(Vec::new())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(response.status(), 302);
    }
    #[test]
    fn verified_exchange_checks_issuer_audience_nonce_signature_expiry_and_access_hash() {
        use openidconnect::{
            core::{
                CoreIdToken, CoreIdTokenClaims, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
            },
            AccessToken, Audience, EmptyAdditionalClaims, JsonWebKeyId, PrivateSigningKey,
            StandardClaims, SubjectIdentifier,
        };
        use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::LineEnding};
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let pem = private.to_pkcs1_pem(LineEnding::LF).unwrap();
        let signing =
            CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new("test-key".into())))
                .unwrap();
        let public = serde_json::to_value(signing.as_verification_key()).unwrap();
        for mode in [
            "valid",
            "issuer",
            "audience",
            "nonce",
            "signature",
            "expired",
            "access_hash",
        ] {
            let (mut server, attempt, _) = setup_with_keys(json!({"keys":[public.clone()]}));
            let refresh_config = attempt.config.clone();
            let refresh_nonce = attempt.nonce.secret().clone();
            let now = std::time::SystemTime::now();
            let mut claims = CoreIdTokenClaims::new(
                IssuerUrl::new(if mode == "issuer" {
                    "https://wrong.example".into()
                } else {
                    server.url()
                })
                .unwrap(),
                vec![Audience::new(
                    if mode == "audience" {
                        "wrong-client"
                    } else {
                        "public-desktop"
                    }
                    .into(),
                )],
                (if mode == "expired" {
                    now - Duration::from_secs(60)
                } else {
                    now + Duration::from_secs(300)
                })
                .into(),
                now.into(),
                StandardClaims::new(SubjectIdentifier::new("opaque-subject".into())),
                EmptyAdditionalClaims {},
            );
            claims = claims.set_nonce(Some(if mode == "nonce" {
                Nonce::new("wrong-nonce".into())
            } else {
                attempt.nonce.clone()
            }));
            let access = AccessToken::new(
                if mode == "access_hash" {
                    "different-access"
                } else {
                    "synthetic-access"
                }
                .into(),
            );
            let token = CoreIdToken::new(
                claims,
                &signing,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                Some(&access),
                None,
            )
            .unwrap();
            let mut token = token.to_string();
            if mode == "signature" {
                let position = token.rfind('.').unwrap() + 1;
                let replacement = if &token[position..position + 1] == "A" {
                    "B"
                } else {
                    "A"
                };
                token.replace_range(position..position + 1, replacement);
            }
            let refresh_id_token = token.clone();
            let mock=server.mock("POST","/token").match_body(mockito::Matcher::AllOf(vec![mockito::Matcher::UrlEncoded("grant_type".into(),"authorization_code".into()),mockito::Matcher::UrlEncoded("code_verifier".into(),attempt.verifier.secret().clone()),mockito::Matcher::UrlEncoded("client_id".into(),"public-desktop".into())]))
                .with_header("content-type","application/json").with_body(json!({"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":300,"id_token":token}).to_string()).create();
            let mut callback =
                reqwest::Url::parse("http://127.0.0.1:41234/oauth/callback").unwrap();
            callback
                .query_pairs_mut()
                .append_pair("code", "synthetic-code")
                .append_pair("state", attempt.state.secret());
            let result = attempt.finish(callback.as_str(), &BoundedHttp::new().unwrap());
            if mode == "valid" {
                let tokens = result.ok().expect("valid OIDC flow rejected");
                assert_eq!(tokens.subject, "opaque-subject");
                assert_eq!(tokens.issuer, server.url());
                assert_eq!(tokens.expires_in, Duration::from_secs(300));
                assert_eq!(&*tokens.access, "synthetic-access");
                assert_eq!(
                    tokens.refresh.as_deref().map(|s| s.as_str()),
                    Some("synthetic-refresh")
                );
                let renewed=server.mock("POST","/token").match_body(mockito::Matcher::AllOf(vec![mockito::Matcher::UrlEncoded("grant_type".into(),"refresh_token".into()),mockito::Matcher::UrlEncoded("refresh_token".into(),"synthetic-refresh".into()),mockito::Matcher::UrlEncoded("client_id".into(),"public-desktop".into())])).with_header("content-type","application/json").with_body(json!({"access_token":"synthetic-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":300,"id_token":refresh_id_token}).to_string()).expect(3).create();
                let http = BoundedHttp::new().unwrap();
                let refreshed = refresh(
                    &refresh_config,
                    "opaque-subject",
                    &refresh_nonce,
                    "synthetic-refresh",
                    &http,
                )
                .ok()
                .expect("valid refresh rejected");
                assert_eq!(
                    refreshed.refresh.as_deref().map(|v| v.as_str()),
                    Some("rotated-refresh")
                );
                assert!(refresh(
                    &refresh_config,
                    "changed-subject",
                    &refresh_nonce,
                    "synthetic-refresh",
                    &http
                )
                .is_err());
                assert!(refresh(
                    &refresh_config,
                    "opaque-subject",
                    "wrong-nonce",
                    "synthetic-refresh",
                    &http
                )
                .is_err());
                renewed.assert();
            } else {
                assert!(result.is_err(), "accepted {mode}");
            }
            mock.assert();
        }
    }
}
