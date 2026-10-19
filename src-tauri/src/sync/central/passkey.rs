//! Built-in native account login: service-origin WebAuthn, one-use code and S256 PKCE.
use super::{
    crypto,
    oidc::{FreshLoginTokens, LoginTokens},
    wire::{hex, invalid, origin},
};
use crate::error::AppError;
use openidconnect::SyncHttpClient;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub origin: String,
    pub rp_id: String,
}
impl Config {
    pub fn validate(&self) -> Result<(), AppError> {
        let url = reqwest::Url::parse(&self.origin).map_err(|_| invalid())?;
        if !origin(&self.origin)
            || url.scheme() != "https"
            || url.host_str() != Some(self.rp_id.as_str())
            || self.rp_id.is_empty()
            || self.rp_id.parse::<std::net::IpAddr>().is_ok()
        {
            return Err(invalid());
        }
        Ok(())
    }
}
fn request<T: Serialize, R: serde::de::DeserializeOwned>(
    config: &Config,
    path: &str,
    body: &T,
    http: &impl SyncHttpClient,
) -> Result<R, AppError> {
    config.validate()?;
    let body = Zeroizing::new(serde_json::to_vec(body).map_err(|_| invalid())?);
    let request = openidconnect::http::Request::builder()
        .method("POST")
        .uri(format!("{}/v2/auth/passkey/{path}", config.origin))
        .header("content-type", "application/json")
        .body(body.to_vec())
        .map_err(|_| invalid())?;
    let response = http.call(request).map_err(|_| {
        AppError::Other(
            "Could not complete passkey sign-in. Return to the app to try again.".into(),
        )
    })?;
    if response.status() != 200 && response.status() != 201 {
        return Err(AppError::Other(
            "Passkey sign-in expired or could not be verified. Start sign-in again.".into(),
        ));
    }
    if response.body().len() > 32768 {
        return Err(invalid());
    }
    let bytes = Zeroizing::new(response.into_body());
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    issuer: String,
    subject: String,
    #[serde(deserialize_with = "secret")]
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    refresh_token: Zeroizing<String>,
    expires_in: u64,
}
fn secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn tokens(config: &Config, grant: Grant, nonce: &str) -> Result<LoginTokens, AppError> {
    fn token(value: &str, prefix: &str) -> bool {
        let p: Vec<_> = value.split('.').collect();
        p.len() == 3 && p[0] == prefix && hex(p[1], 32) && hex(p[2], 64)
    }
    if grant.issuer != format!("{}/v2/auth/passkey", config.origin)
        || !hex(&grant.subject, 64)
        || grant.expires_in == 0
        || grant.expires_in > 300
        || !token(&grant.access_token, "lpka1")
        || !token(&grant.refresh_token, "lpkr1")
    {
        return Err(invalid());
    }
    Ok(LoginTokens {
        issuer: grant.issuer,
        subject: grant.subject,
        nonce: Zeroizing::new(nonce.into()),
        access: grant.access_token,
        refresh: Some(grant.refresh_token),
        expires_in: Duration::from_secs(grant.expires_in),
    })
}
pub struct Attempt {
    config: Config,
    state: Zeroizing<String>,
    verifier: Zeroizing<String>,
    redirect: String,
    started: Instant,
    fresh: bool,
    expected: Option<String>,
}
impl Attempt {
    pub fn begin(
        config: Config,
        port: u16,
        expected: Option<String>,
        fresh: bool,
        http: &impl SyncHttpClient,
    ) -> Result<(Self, String), AppError> {
        config.validate()?;
        if port == 0 || expected.as_ref().is_some_and(|s| !hex(s, 64)) {
            return Err(invalid());
        }
        let state = Zeroizing::new(crypto::random_id(32)?);
        let verifier = Zeroizing::new(crypto::random_id(32)?);
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sha2::{Digest, Sha256};
        #[derive(Serialize)]
        struct Begin<'a> {
            code_challenge: String,
            redirect_uri: &'a str,
            state: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            expected_locator: Option<&'a str>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Begun {
            url: String,
            expires_in: u64,
        }
        let redirect = format!("http://127.0.0.1:{port}/passkey/callback");
        let begun: Begun = request(
            &config,
            "authorize",
            &Begin {
                code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                redirect_uri: &redirect,
                state: &state,
                expected_locator: expected.as_deref(),
            },
            http,
        )?;
        let url = reqwest::Url::parse(&begun.url).map_err(|_| invalid())?;
        if url.query_pairs().count() != 1 {
            return Err(invalid());
        }
        let query: BTreeMap<_, _> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if url.origin().ascii_serialization() != config.origin
            || url.path() != "/v2/auth/passkey/page"
            || !url.username().is_empty()
            || url.password().is_some()
            || query.len() != 1
            || query.get("flow").is_none_or(|s| !hex(s, 32))
            || url
                .fragment()
                .and_then(|s| s.strip_prefix("key="))
                .is_none_or(|s| !hex(s, 64))
            || begun.expires_in == 0
            || begun.expires_in > 300
        {
            return Err(invalid());
        }
        Ok((
            Self {
                config,
                state,
                verifier,
                redirect,
                started: Instant::now(),
                fresh,
                expected,
            },
            begun.url,
        ))
    }
    pub fn validate_callback(&self, value: &str) -> Result<String, AppError> {
        self.callback(value)
    }
    fn callback(&self, value: &str) -> Result<String, AppError> {
        if self.started.elapsed() > Duration::from_secs(300) || value.len() > 4096 {
            return Err(invalid());
        }
        let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
        let target = reqwest::Url::parse(&self.redirect).map_err(|_| invalid())?;
        let pairs: Vec<_> = url.query_pairs().collect();
        if url.origin() != target.origin()
            || url.path() != target.path()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || pairs.len() != 2
        {
            return Err(invalid());
        }
        let query: BTreeMap<_, _> = pairs
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if query.get("state").map(String::as_str) != Some(self.state.as_str()) {
            return Err(invalid());
        }
        let code = query.get("code").ok_or_else(invalid)?;
        let parts: Vec<_> = code.split('.').collect();
        if parts.len() != 3 || parts[0] != "lpkc1" || !hex(parts[1], 32) || !hex(parts[2], 64) {
            return Err(invalid());
        }
        Ok(code.clone())
    }
    pub fn finish(
        self,
        callback: &str,
        http: &impl SyncHttpClient,
    ) -> Result<LoginTokens, AppError> {
        let code = Zeroizing::new(self.callback(callback)?);
        #[derive(Serialize)]
        struct Exchange<'a> {
            code: &'a str,
            verifier: &'a str,
            redirect_uri: &'a str,
        }
        let grant: Grant = request(
            &self.config,
            "exchange",
            &Exchange {
                code: &code,
                verifier: &self.verifier,
                redirect_uri: &self.redirect,
            },
            http,
        )?;
        let tokens = tokens(&self.config, grant, &self.state)?;
        if let Some(expected) = &self.expected {
            if super::credentials::Profile::new(
                &self.config.origin,
                &tokens.issuer,
                &tokens.subject,
            )?
            .locator
                != *expected
            {
                return Err(invalid());
            }
        }
        Ok(tokens)
    }
    pub fn finish_fresh(
        self,
        callback: &str,
        http: &impl SyncHttpClient,
    ) -> Result<FreshLoginTokens, AppError> {
        if !self.fresh || self.expected.is_none() {
            return Err(invalid());
        }
        self.finish(callback, http)
            .map(|tokens| FreshLoginTokens::from_passkey(Fresh(tokens)))
    }
}
pub(super) struct Fresh(LoginTokens);
impl Fresh {
    pub(super) fn into_tokens(self) -> LoginTokens {
        self.0
    }
}
pub fn refresh(
    config: &Config,
    subject: &str,
    nonce: &str,
    secret: &str,
    http: &impl SyncHttpClient,
) -> Result<LoginTokens, AppError> {
    #[derive(Serialize)]
    struct Refresh<'a> {
        refresh_token: &'a str,
    }
    let grant: Grant = request(
        config,
        "refresh",
        &Refresh {
            refresh_token: secret,
        },
        http,
    )?;
    let tokens = tokens(config, grant, nonce)?;
    if tokens.subject != subject {
        return Err(invalid());
    }
    Ok(tokens)
}

/// Best-effort remote family revocation; callers must complete durable local sign-out first.
pub fn logout(config: &Config, secret: &str, http: &impl SyncHttpClient) -> Result<(), AppError> {
    #[derive(Serialize)]
    struct Logout<'a> {
        token: &'a str,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LoggedOut {
        signed_out: bool,
    }
    let result: LoggedOut = request(config, "logout", &Logout { token: secret }, http)?;
    if !result.signed_out {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
