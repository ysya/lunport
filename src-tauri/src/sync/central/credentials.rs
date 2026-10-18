//! OS-protected device/refresh credentials. No secret structure is a frontend DTO or Debug.
use super::{
    crypto::{hash, random_id, DeviceKeys},
    membership::Device,
    oidc::{self, LoginTokens, OidcConfig},
    wire::{canonical, hex, invalid, origin},
};
use crate::{error::AppError, sync::env::Keychain};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub origin: String,
    pub issuer: String,
    pub subject: String,
    pub locator: String,
}
impl Profile {
    pub fn new(service: &str, issuer: &str, subject: &str) -> Result<Self, AppError> {
        if !origin(service) || subject.is_empty() || subject.len() > 512 {
            return Err(invalid());
        }
        OidcConfig {
            issuer: issuer.into(),
            client_id: "validation".into(),
            scopes: vec![],
            audience: None,
        }
        .validate()?;
        Ok(Self {
            origin: service.into(),
            issuer: issuer.into(),
            subject: subject.into(),
            locator: hash(&canonical(&[
                "lunport-account-locator-v2",
                service,
                issuer,
                subject,
            ])?),
        })
    }
    fn slot(&self, kind: &str) -> String {
        format!("central:v2:{kind}:{}", self.locator)
    }
}
pub struct DeviceIdentity {
    pub id: String,
    pub keys: DeviceKeys,
    credential: Zeroizing<String>,
}
impl DeviceIdentity {
    pub fn device(&self) -> Device {
        Device {
            id: self.id.clone(),
            keys: self.keys.public(),
        }
    }
    pub(crate) fn credential(&self) -> &str {
        &self.credential
    }
    pub fn load_or_create(
        keychain: &dyn Keychain,
        profile: &Profile,
        interactive: bool,
    ) -> Result<Self, AppError> {
        let slot = profile.slot("device");
        let saved = if interactive {
            keychain.get(&slot)
        } else {
            keychain.get_noninteractive(&slot)
        }?;
        if let Some(encoded) = saved {
            return Self::decode(&Zeroizing::new(encoded), profile);
        }
        if !interactive {
            return Err(AppError::Other(
                "Sign in to prepare this device's secure credentials.".into(),
            ));
        }
        let identity = Self {
            id: random_id(16)?,
            keys: DeviceKeys::generate()?,
            credential: Zeroizing::new(random_id(32)?),
        };
        #[derive(Serialize)]
        struct Stored<'a> {
            version: u32,
            locator: &'a str,
            id: &'a str,
            keys: &'a str,
            credential: &'a str,
        }
        let keys = identity.keys.encode_secret();
        let encoded = Zeroizing::new(
            serde_json::to_string(&Stored {
                version: 1,
                locator: &profile.locator,
                id: &identity.id,
                keys: &keys,
                credential: &identity.credential,
            })
            .map_err(|_| invalid())?,
        );
        keychain.set(&slot, &encoded)?;
        // Never publish a device registration until its only copy of private identity is durable.
        let confirmed = Zeroizing::new(keychain.get(&slot)?.ok_or_else(|| {
            AppError::Other("The device identity was not saved securely.".into())
        })?);
        let verified = Self::decode(&confirmed, profile)?;
        if verified.id != identity.id
            || verified.keys.public() != identity.keys.public()
            || verified.credential != identity.credential
        {
            return Err(AppError::Other(
                "The saved device identity could not be verified.".into(),
            ));
        }
        Ok(identity)
    }
    fn decode(encoded: &str, profile: &Profile) -> Result<Self, AppError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            version: u32,
            locator: String,
            id: String,
            keys: String,
            credential: String,
        }
        impl Drop for Stored {
            fn drop(&mut self) {
                self.keys.zeroize();
                self.credential.zeroize();
            }
        }
        if encoded.len() > 4096 {
            return Err(invalid());
        }
        let stored: Stored = serde_json::from_str(encoded).map_err(|_| invalid())?;
        if stored.version != 1
            || stored.locator != profile.locator
            || !hex(&stored.id, 32)
            || !hex(&stored.credential, 64)
        {
            return Err(invalid());
        }
        Ok(Self {
            id: stored.id.clone(),
            keys: DeviceKeys::decode_secret(&stored.keys)?,
            credential: Zeroizing::new(stored.credential.clone()),
        })
    }
}
/// Persist before registration so a lost response reuses the same server session ID and expiry.
pub struct SessionAttempt {
    pub id: String,
    secret: Zeroizing<String>,
}
impl SessionAttempt {
    pub(crate) fn secret(&self) -> &str {
        &self.secret
    }
    pub fn prepare(
        keychain: &dyn Keychain,
        profile: &Profile,
        device: &DeviceIdentity,
        now: u64,
    ) -> Result<Self, AppError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            version: u32,
            device: String,
            id: String,
            secret: String,
            created: u64,
        }
        impl Drop for Stored {
            fn drop(&mut self) {
                self.secret.zeroize();
            }
        }
        let slot = profile.slot("session-attempt");
        if let Some(encoded) = keychain.get(&slot)? {
            let encoded = Zeroizing::new(encoded);
            if encoded.len() > 4096 {
                return Err(invalid());
            }
            let stored: Stored = serde_json::from_str(&encoded).map_err(|_| invalid())?;
            if stored.version != 1
                || stored.device != device.id
                || !hex(&stored.id, 32)
                || !hex(&stored.secret, 64)
            {
                return Err(invalid());
            }
            if now >= stored.created && now - stored.created < 300000 {
                return Ok(Self {
                    id: stored.id.clone(),
                    secret: Zeroizing::new(stored.secret.clone()),
                });
            }
        }
        let result = Self {
            id: random_id(16)?,
            secret: Zeroizing::new(random_id(32)?),
        };
        #[derive(Serialize)]
        struct Save<'a> {
            version: u32,
            device: &'a str,
            id: &'a str,
            secret: &'a str,
            created: u64,
        }
        let encoded = Zeroizing::new(
            serde_json::to_string(&Save {
                version: 1,
                device: &device.id,
                id: &result.id,
                secret: &result.secret,
                created: now,
            })
            .map_err(|_| invalid())?,
        );
        keychain.set(&slot, &encoded)?;
        Ok(result)
    }
}
/// Identity fields are nonsecret; nonce/refresh are cleared when their temporary parse is dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshEntry {
    version: u32,
    locator: String,
    client_id: String,
    nonce: String,
    refresh: String,
}
impl Drop for RefreshEntry {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.refresh.zeroize();
    }
}
pub fn save_refresh(
    keychain: &dyn Keychain,
    profile: &Profile,
    config: &OidcConfig,
    tokens: &LoginTokens,
) -> Result<(), AppError> {
    if tokens.issuer != profile.issuer
        || tokens.subject != profile.subject
        || config.issuer != profile.issuer
    {
        return Err(invalid());
    }
    let secret = tokens.refresh.as_ref().ok_or_else(|| {
        AppError::Other(
            "The sign-in provider did not allow background renewal. Sign in again.".into(),
        )
    })?;
    if secret.is_empty() || secret.len() > 16384 || tokens.nonce.len() > 4096 {
        return Err(invalid());
    }
    #[derive(Serialize)]
    struct Stored<'a> {
        version: u32,
        locator: &'a str,
        client_id: &'a str,
        nonce: &'a str,
        refresh: &'a str,
    }
    let encoded = Zeroizing::new(
        serde_json::to_string(&Stored {
            version: 1,
            locator: &profile.locator,
            client_id: &config.client_id,
            nonce: &tokens.nonce,
            refresh: secret,
        })
        .map_err(|_| invalid())?,
    );
    if encoded.len() > 32768 {
        return Err(invalid());
    }
    keychain.set(&profile.slot("refresh"), &encoded)
}
pub fn renew(
    keychain: &dyn Keychain,
    profile: &Profile,
    config: &OidcConfig,
    interactive: bool,
    http: &impl openidconnect::SyncHttpClient,
) -> Result<LoginTokens, AppError> {
    if profile.issuer != config.issuer {
        return Err(invalid());
    }
    let slot = profile.slot("refresh");
    let encoded = Zeroizing::new(
        if interactive {
            keychain.get(&slot)
        } else {
            keychain.get_noninteractive(&slot)
        }?
        .ok_or_else(|| {
            AppError::Other("Sign in again to resume account synchronization.".into())
        })?,
    );
    if encoded.len() > 32768 {
        return Err(invalid());
    }
    let stored: RefreshEntry = serde_json::from_str(&encoded).map_err(|_| invalid())?;
    if stored.version != 1
        || stored.locator != profile.locator
        || stored.client_id != config.client_id
        || stored.refresh.is_empty()
        || stored.refresh.len() > 16384
        || stored.nonce.len() > 4096
    {
        return Err(invalid());
    }
    let tokens = oidc::refresh(
        config,
        &profile.subject,
        &stored.nonce,
        &stored.refresh,
        http,
    )?;
    // Persist a provider-rotated refresh before using the new access token. Failure requires sign-in,
    // rather than retrying an already-consumed refresh family or silently continuing without durability.
    save_refresh(keychain, profile, config, &tokens)?;
    Ok(tokens)
}
pub fn forget_session_attempt(keychain: &dyn Keychain, profile: &Profile) -> Result<(), AppError> {
    keychain.delete(&profile.slot("session-attempt"))
}
pub fn forget_refresh(keychain: &dyn Keychain, profile: &Profile) -> Result<(), AppError> {
    keychain.delete(&profile.slot("refresh"))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex};
    #[derive(Default)]
    struct Memory {
        values: Mutex<BTreeMap<String, String>>,
        writes: Mutex<usize>,
    }
    impl Keychain for Memory {
        fn get(&self, key: &str) -> Result<Option<String>, AppError> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
            *self.writes.lock().unwrap() += 1;
            self.values.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<(), AppError> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
    }
    fn profile() -> Profile {
        Profile::new("https://relay.test", "https://id.test", "opaque-subject").unwrap()
    }
    #[test]
    fn identity_survives_restart_and_account_service_boundaries_never_reuse_it() {
        let memory = Memory::default();
        let profile = profile();
        let first = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        let second = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        assert_eq!(first.device(), second.device());
        assert_eq!(first.credential(), second.credential());
        assert_eq!(*memory.writes.lock().unwrap(), 1);
        let other = Profile::new("https://other.test", &profile.issuer, &profile.subject).unwrap();
        let different = DeviceIdentity::load_or_create(&memory, &other, true).unwrap();
        assert_ne!(first.id, different.id);
        assert_ne!(first.keys.public(), different.keys.public());
        assert!(DeviceIdentity::load_or_create(&memory, &profile, false).is_err());
        assert_eq!(*memory.writes.lock().unwrap(), 2);
    }
    #[test]
    fn registration_retries_reuse_a_durable_attempt_until_its_short_lifetime_ends() {
        let memory = Memory::default();
        let profile = profile();
        let identity = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        let first = SessionAttempt::prepare(&memory, &profile, &identity, 1000).unwrap();
        let retry = SessionAttempt::prepare(&memory, &profile, &identity, 1100).unwrap();
        assert_eq!(first.id, retry.id);
        assert_eq!(first.secret(), retry.secret());
        let renewed = SessionAttempt::prepare(&memory, &profile, &identity, 301001).unwrap();
        assert_ne!(first.id, renewed.id);
        assert_ne!(first.secret(), renewed.secret());
    }
    #[test]
    fn unreadable_or_corrupt_credentials_are_not_replaced_with_a_fresh_identity() {
        let memory = Memory::default();
        let profile = profile();
        memory
            .values
            .lock()
            .unwrap()
            .insert(profile.slot("device"), "corrupt retained value".into());
        assert!(DeviceIdentity::load_or_create(&memory, &profile, true).is_err());
        assert_eq!(*memory.writes.lock().unwrap(), 0);
        assert_eq!(
            memory.get(&profile.slot("device")).unwrap().unwrap(),
            "corrupt retained value"
        );
    }
    #[test]
    fn provider_rotation_is_persisted_before_access_is_returned_and_client_mismatch_cannot_send_it()
    {
        use serde_json::json;
        let mut provider = mockito::Server::new();
        let issuer = provider.url();
        provider.mock("GET","/.well-known/openid-configuration").with_header("content-type","application/json").with_body(json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/jwks"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}).to_string()).create();
        provider
            .mock("GET", "/jwks")
            .with_header("content-type", "application/json")
            .with_body("{\"keys\":[]}")
            .create();
        let exchange=provider.mock("POST","/token").match_body(mockito::Matcher::UrlEncoded("refresh_token".into(),"old-refresh".into())).with_header("content-type","application/json").with_body(json!({"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":300}).to_string()).expect(1).create();
        let memory = Memory::default();
        let profile = Profile::new("https://relay.test", &issuer, "opaque-subject").unwrap();
        let config = OidcConfig {
            issuer,
            client_id: "native".into(),
            scopes: vec![],
            audience: Some("api".into()),
        };
        let tokens = LoginTokens {
            issuer: profile.issuer.clone(),
            subject: profile.subject.clone(),
            nonce: Zeroizing::new("nonce".into()),
            access: Zeroizing::new("old-access".into()),
            refresh: Some(Zeroizing::new("old-refresh".into())),
            expires_in: std::time::Duration::from_secs(300),
        };
        save_refresh(&memory, &profile, &config, &tokens).unwrap();
        let http = oidc::BoundedHttp::new().unwrap();
        let wrong = OidcConfig {
            client_id: "another-client".into(),
            ..config.clone()
        };
        assert!(renew(&memory, &profile, &wrong, true, &http).is_err());
        let refreshed = renew(&memory, &profile, &config, true, &http).unwrap();
        assert_eq!(&*refreshed.access, "new-access");
        let persisted = memory.get(&profile.slot("refresh")).unwrap().unwrap();
        assert!(persisted.contains("new-refresh"));
        assert!(!persisted.contains("old-refresh"));
        assert!(!persisted.contains("new-access"));
        exchange.assert();
    }
    #[test]
    fn refresh_is_scoped_to_exact_issuer_subject_and_client_and_logout_preserves_device_keys() {
        let memory = Memory::default();
        let profile = profile();
        let original = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        let config = OidcConfig {
            issuer: profile.issuer.clone(),
            client_id: "native".into(),
            scopes: vec![],
            audience: Some("api".into()),
        };
        let tokens = LoginTokens {
            issuer: profile.issuer.clone(),
            subject: profile.subject.clone(),
            nonce: Zeroizing::new("nonce".into()),
            access: Zeroizing::new("access".into()),
            refresh: Some(Zeroizing::new("refresh".into())),
            expires_in: std::time::Duration::from_secs(300),
        };
        save_refresh(&memory, &profile, &config, &tokens).unwrap();
        let stored = memory.get(&profile.slot("refresh")).unwrap().unwrap();
        assert!(!stored.contains("access"));
        assert!(stored.contains("refresh"));
        let wrong = Profile::new(&profile.origin, &profile.issuer, "another-user").unwrap();
        assert!(save_refresh(&memory, &wrong, &config, &tokens).is_err());
        forget_refresh(&memory, &profile).unwrap();
        assert!(memory.get(&profile.slot("refresh")).unwrap().is_none());
        assert_eq!(
            DeviceIdentity::load_or_create(&memory, &profile, true)
                .unwrap()
                .device(),
            original.device()
        );
    }
}
