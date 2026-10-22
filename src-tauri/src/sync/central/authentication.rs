//! Explicit account login method. Authentication never supplies E2EE content keys.
use super::{oidc::OidcConfig, passkey::Config as PasskeyConfig};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "config",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Config {
    Oidc(OidcConfig),
    Passkey(PasskeyConfig),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Passkey,
    Oidc,
}
impl Config {
    pub fn method(&self) -> Method {
        match self {
            Self::Passkey(_) => Method::Passkey,
            Self::Oidc(_) => Method::Oidc,
        }
    }
}
impl From<OidcConfig> for Config {
    fn from(config: OidcConfig) -> Self {
        Self::Oidc(config)
    }
}
impl Config {
    pub fn validate(&self) -> Result<(), AppError> {
        match self {
            Self::Oidc(c) => c.validate(),
            Self::Passkey(c) => c.validate(),
        }
    }
    pub fn issuer(&self) -> String {
        match self {
            Self::Oidc(c) => c.issuer.clone(),
            Self::Passkey(c) => format!("{}/v1/auth/passkey", c.origin),
        }
    }
    pub fn client_id(&self) -> &str {
        match self {
            Self::Oidc(c) => &c.client_id,
            Self::Passkey(_) => "lunport-native-passkey",
        }
    }
}
pub fn deserialize_legacy<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Config, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Stored {
        Current(Config),
        Legacy(OidcConfig),
    }
    Stored::deserialize(d).map(|s| match s {
        Stored::Current(c) => c,
        Stored::Legacy(c) => Config::Oidc(c),
    })
}
