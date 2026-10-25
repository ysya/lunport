//! Lunport's credentials behind Google's client library (design 2026-10-25, PAM grant requests): the library asks a `CredentialsProvider`
//! for its request headers, and this one answers with a bearer token from the same `TokenSource` the tunnel and the OS Login calls use,
//! so the account rules (gcloud's sign-in files, the active account, a named account) and their sentences stay Lunport's.
//!
//! The library's documentation presents `CredentialsProvider` as a hook for mocking and expects applications to use its own credential
//! types (application default credentials, a user-account JSON). It is public API all the same, and the only way to keep one credential
//! source for the tunnel, OS Login and PAM; should a release close it, `google_cloud_auth::credentials::user_account::Builder` fed with the
//! legacy credentials file's contents is the fallback.

use std::fmt;
use std::sync::Arc;

use google_cloud_auth::credentials::{CacheableResource, Credentials, CredentialsProvider, EntityTag};
use google_cloud_auth::errors::CredentialsError;
use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use http::Extensions;

use super::auth::TokenSource;

/// A `TokenSource` as the client library sees it: one `Authorization: Bearer` header per request. The source caches and refreshes the
/// token itself, so every answer is a fresh resource (no entity-tag reuse).
pub struct BearerCredentials {
    tokens: Arc<dyn TokenSource>,
    account: Option<String>,
}

impl BearerCredentials {
    pub fn new(tokens: Arc<dyn TokenSource>, account: Option<String>) -> BearerCredentials {
        BearerCredentials { tokens, account }
    }
}

impl fmt::Debug for BearerCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerCredentials").field("account", &self.account).finish_non_exhaustive()
    }
}

impl CredentialsProvider for BearerCredentials {
    async fn headers(&self, _extensions: Extensions) -> Result<CacheableResource<HeaderMap>, CredentialsError> {
        // The source is synchronous (it may read files and call the token service): the blocking pool, as the tunnel does.
        let tokens = Arc::clone(&self.tokens);
        let account = self.account.clone();
        let token = tokio::task::spawn_blocking(move || tokens.access_token(account.as_deref()))
            .await
            .map_err(|_| CredentialsError::from_msg(true, "the token request was interrupted"))?
            .map_err(|error| CredentialsError::from_msg(error.is_retryable(), error.to_string()))?;
        let mut value = HeaderValue::from_str(&format!("Bearer {}", token.value.as_str()))
            .map_err(|_| CredentialsError::from_msg(false, "the access token is not a valid header value"))?;
        value.set_sensitive(true);
        let mut data = HeaderMap::new();
        data.insert(AUTHORIZATION, value);
        Ok(CacheableResource::New { entity_tag: EntityTag::new(), data })
    }

    async fn universe_domain(&self) -> Option<String> {
        None
    }
}

/// The library's `Credentials` over Lunport's token source, for `account` (or the default account when `None`).
pub fn credentials(tokens: Arc<dyn TokenSource>, account: Option<String>) -> Credentials {
    Credentials::from(BearerCredentials::new(tokens, account))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::auth::{AuthError, StaticToken, Token, TokenSource};
    use http::Extensions;
    use std::sync::Arc;

    /// A token source that refuses with a fixed error.
    struct Refusing(AuthError);

    impl TokenSource for Refusing {
        fn access_token(&self, _account: Option<&str>) -> Result<Token, AuthError> {
            Err(self.0.clone())
        }
    }

    #[tokio::test]
    async fn the_provider_answers_a_bearer_header_from_the_token_source() {
        let credentials = credentials(Arc::new(StaticToken("t0k".into())), Some("frank@retower.io".into()));
        let answer = credentials.headers(Extensions::new()).await.expect("a header");
        let google_cloud_auth::credentials::CacheableResource::New { data, .. } = answer else { panic!("a fresh header, not a cache hit") };
        let value = data.get("authorization").expect("an authorization header");
        assert_eq!(value.to_str().unwrap(), "Bearer t0k");
        assert!(value.is_sensitive(), "the token must not be logged");
        assert_eq!(credentials.universe_domain().await, None);
    }

    #[tokio::test]
    async fn a_token_failure_is_a_credentials_error_that_says_why() {
        let credentials = credentials(Arc::new(Refusing(AuthError::SignInExpired { account: "frank@retower.io".into() })), None);
        let error = credentials.headers(Extensions::new()).await.unwrap_err();
        assert!(error.to_string().contains("run `gcloud auth login frank@retower.io`"), "{error}");
    }
}
