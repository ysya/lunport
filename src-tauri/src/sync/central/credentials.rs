//! OS-protected device/refresh credentials. No secret structure is a frontend DTO or Debug.
use super::{
    crypto::{hash, random_id, DeviceKeys},
    membership::Device,
    oidc::{self, LoginTokens, OidcConfig},
    wire::{canonical, hex, invalid, origin},
};
use super::authentication::Config as LoginConfig;
use crate::{error::AppError, sync::env::Keychain};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
/// Central renewal may update pre-existing credentials without allowing a prompt or unlock.
/// The generic SSH NonInteractiveKeychain intentionally remains read-only.
pub struct Background<'a>(pub &'a dyn Keychain);
impl Keychain for Background<'_> {
    fn get(&self, key: &str) -> Result<Option<String>, AppError> {
        self.0.get_noninteractive(key)
    }
    fn get_noninteractive(&self, key: &str) -> Result<Option<String>, AppError> {
        self.0.get_noninteractive(key)
    }
    fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
        self.0.set_noninteractive(key, value)
    }
    fn set_noninteractive(&self, key: &str, value: &str) -> Result<(), AppError> {
        self.0.set_noninteractive(key, value)
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        Err(AppError::Other(
            "needs interaction: credential deletion requires a foreground action".into(),
        ))
    }
}
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
    pub(crate) fn slot(&self, kind: &str) -> String {
        format!("central:v2:{kind}:{}", self.locator)
    }
    pub(crate) fn device_slot(
        &self,
        kind: &str,
        replacement: Option<&str>,
    ) -> Result<String, AppError> {
        match replacement {
            Some(id) if hex(id, 32) => Ok(self.slot(&format!("{kind}-replacement-{id}"))),
            Some(_) => Err(invalid()),
            None => Ok(self.slot(kind)),
        }
    }
}
pub struct DeviceIdentity {
    pub id: String,
    pub keys: DeviceKeys,
    credential: Zeroizing<String>,
    // Native storage selection, never serialized as private identity material.
    replacement: Option<String>,
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
    pub fn load(
        keychain: &dyn Keychain,
        profile: &Profile,
        interactive: bool,
    ) -> Result<Self, AppError> {
        Self::load_selected(keychain, profile, None, interactive)
    }
    /// Public state may select only the default slot or an explicit, validated replacement
    /// operation. It can never turn an arbitrary frontend string into a credential account.
    pub fn load_selected(
        keychain: &dyn Keychain,
        profile: &Profile,
        replacement: Option<&str>,
        interactive: bool,
    ) -> Result<Self, AppError> {
        let slot = Self::identity_slot(profile, replacement)?;
        let saved = if interactive {
            keychain.get(&slot)
        } else {
            keychain.get_noninteractive(&slot)
        }?;
        let encoded=Zeroizing::new(saved.ok_or_else(||AppError::Other("This device's account keys are unavailable. Sign in again and reconnect with your sync password; local data is retained.".into()))?);
        let mut identity = Self::decode(&encoded, profile)?;
        identity.replacement = replacement.map(str::to_string);
        Ok(identity)
    }
    pub(crate) fn slot(&self, profile: &Profile, kind: &str) -> Result<String, AppError> {
        profile.device_slot(kind, self.replacement.as_deref())
    }
    pub fn load_or_create(
        keychain: &dyn Keychain,
        profile: &Profile,
        interactive: bool,
    ) -> Result<Self, AppError> {
        Self::load_or_create_slot(keychain, profile, None, interactive)
    }
    /// Explicit recovery only: preserve the old/default identity even when missing or corrupt.
    /// A durable operation ID must be recorded before calling; retry reads the very same slot.
    pub fn create_replacement(
        keychain: &dyn Keychain,
        profile: &Profile,
        operation: &str,
    ) -> Result<Self, AppError> {
        Self::load_or_create_slot(keychain, profile, Some(operation), true)
    }
    fn identity_slot(profile: &Profile, replacement: Option<&str>) -> Result<String, AppError> {
        profile.device_slot("device", replacement)
    }
    fn load_or_create_slot(
        keychain: &dyn Keychain,
        profile: &Profile,
        replacement: Option<&str>,
        interactive: bool,
    ) -> Result<Self, AppError> {
        let slot = Self::identity_slot(profile, replacement)?;

        let saved = if interactive {
            keychain.get(&slot)
        } else {
            keychain.get_noninteractive(&slot)
        }?;
        if let Some(encoded) = saved {
            let mut identity = Self::decode(&Zeroizing::new(encoded), profile)?;
            identity.replacement = replacement.map(str::to_string);
            return Ok(identity);
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
            replacement: replacement.map(str::to_string),
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
            replacement: None,
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
        Self::prepare_with_reset(keychain, profile, device, now, false)
    }
    pub fn prepare_with_reset(
        keychain: &dyn Keychain,
        profile: &Profile,
        device: &DeviceIdentity,
        now: u64,
        reset: bool,
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
        let slot = device.slot(profile, "session-attempt")?;
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
            if !reset && now >= stored.created && now - stored.created < 300000 {
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
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RefreshState {
    Ready,
    InFlight,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshEntry {
    version: u32,
    locator: String,
    client_id: String,
    nonce: String,
    refresh: String,
    #[serde(default)]
    state: Option<RefreshState>,
}
impl Drop for RefreshEntry {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.refresh.zeroize();
    }
}
pub fn save_refresh<C: Clone+Into<LoginConfig>>(
    keychain: &dyn Keychain,
    profile: &Profile,
    config: &C,
    tokens: &LoginTokens,
) -> Result<(), AppError> {
    let config: LoginConfig=config.clone().into();
    if tokens.issuer != profile.issuer
        || tokens.subject != profile.subject
        || config.issuer() != profile.issuer
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
    store_refresh(
        keychain,
        profile,
        &config,
        &tokens.nonce,
        secret,
        RefreshState::Ready,
    )
}
fn store_refresh<C: Clone+Into<LoginConfig>>(
    keychain: &dyn Keychain,
    profile: &Profile,
    config: &C,
    nonce: &str,
    refresh: &str,
    state: RefreshState,
) -> Result<(), AppError> {
    let config: LoginConfig=config.clone().into();
    #[derive(Serialize)]
    struct Stored<'a> {
        version: u32,
        locator: &'a str,
        client_id: &'a str,
        nonce: &'a str,
        refresh: &'a str,
        state: RefreshState,
    }
    let encoded = Zeroizing::new(
        serde_json::to_string(&Stored {
            version: 2,
            locator: &profile.locator,
            client_id: config.client_id(),
            nonce,
            refresh,
            state,
        })
        .map_err(|_| invalid())?,
    );
    if encoded.len() > 32768 {
        return Err(invalid());
    }
    let slot = profile.slot("refresh");
    keychain.set(&slot, &encoded)?;
    let persisted = Zeroizing::new(keychain.get(&slot)?.ok_or_else(invalid)?);
    if *persisted != *encoded {
        return Err(invalid());
    }
    Ok(())
}
/// Caller serializes refresh/sign-in/logout with the owning SyncRuntime lifecycle lock.
pub fn renew<C: Clone+Into<LoginConfig>>(
    keychain: &dyn Keychain,
    profile: &Profile,
    config: &C,
    interactive: bool,
    http: &impl openidconnect::SyncHttpClient,
) -> Result<LoginTokens, AppError> {
    let config: LoginConfig=config.clone().into();
    if profile.issuer != config.issuer() {
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
    if !matches!(
        (stored.version, stored.state),
        (1, None) | (2, Some(RefreshState::Ready | RefreshState::InFlight))
    ) || stored.locator != profile.locator
        || stored.client_id != config.client_id()
        || stored.refresh.is_empty()
        || stored.refresh.len() > 16384
        || stored.nonce.len() > 4096
    {
        return Err(invalid());
    }
    if stored.state == Some(RefreshState::InFlight) {
        return Err(AppError::Other("Sign in again: the previous credential renewal was interrupted. Local data is retained.".into()));
    }
    // Mark the old family durably before any provider request. A response loss, crash or failed
    // rotated-token save leaves InFlight, so a restart cannot replay the potentially consumed token.
    let background = Background(keychain);
    let writer: &dyn Keychain = if interactive { keychain } else { &background };
    store_refresh(writer, profile, &config, &stored.nonce, &stored.refresh, RefreshState::InFlight)
        .map_err(|_| AppError::Other("Sign in again: credential renewal could not be prepared securely. Local data is retained.".into()))?;
    let tokens = match &config {
        LoginConfig::Oidc(c)=>oidc::refresh(c,&profile.subject,&stored.nonce,&stored.refresh,http),
        LoginConfig::Passkey(c)=>super::passkey::refresh(c,&profile.subject,&stored.nonce,&stored.refresh,http),
    }
    .map_err(|_| {
        AppError::Other(
            "Sign in again: account credential renewal did not complete. Local data is retained."
                .into(),
        )
    })?;
    // Persist and read back the new family before exposing access. Any uncertain attempt retains
    // InFlight; it cannot be replayed by a later worker or after a crash.
    save_refresh(writer, profile, &config, &tokens).map_err(|_| AppError::Other(
        "Sign in again: the renewed account credential could not be saved securely. Local data is retained.".into()))?;
    Ok(tokens)
}
pub fn forget_session_attempt(
    keychain: &dyn Keychain,
    profile: &Profile,
    replacement: Option<&str>,
) -> Result<(), AppError> {
    keychain.delete(&profile.device_slot("session-attempt", replacement)?)
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
    struct NoPrompt<'a>(&'a Memory, bool);
    impl Keychain for NoPrompt<'_> {
        fn get(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("interactive credential read from background")
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("interactive credential update from background")
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("interactive credential delete from background")
        }
        fn get_noninteractive(&self, key: &str) -> Result<Option<String>, AppError> {
            self.0.get(key)
        }
        fn set_noninteractive(&self, key: &str, value: &str) -> Result<(), AppError> {
            if !self.1 || self.0.get(key)?.is_none() {
                return Err(invalid());
            }
            self.0.set(key, value)
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
    fn explicit_replacement_is_independent_durable_retryable_and_never_overwrites_the_old_slot() {
        let memory = Memory::default();
        let profile = profile();
        let old = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        let saved = memory.get(&profile.slot("device")).unwrap();
        let operation = "1".repeat(32);
        let replacement =
            DeviceIdentity::create_replacement(&memory, &profile, &operation).unwrap();
        assert_ne!(replacement.id, old.id);
        assert_ne!(replacement.keys.public(), old.keys.public());
        assert_ne!(replacement.credential(), old.credential());
        let retry = DeviceIdentity::create_replacement(&memory, &profile, &operation).unwrap();
        assert_eq!(retry.device(), replacement.device());
        assert_eq!(retry.credential(), replacement.credential());
        let strict = NoPrompt(&memory, false);
        let background = Background(&strict);
        assert_eq!(
            DeviceIdentity::load_selected(&background, &profile, Some(&operation), false)
                .unwrap()
                .device(),
            replacement.device()
        );
        assert!(
            DeviceIdentity::load_selected(&background, &profile, Some(&"2".repeat(32)), false)
                .is_err()
        );
        assert!(DeviceIdentity::create_replacement(&memory, &profile, "invalid/slot").is_err());
        assert_eq!(*memory.writes.lock().unwrap(), 2);
        assert_eq!(memory.get(&profile.slot("device")).unwrap(), saved);
        let slot = DeviceIdentity::identity_slot(&profile, Some(&operation)).unwrap();
        memory.set(&slot, "corrupt replacement").unwrap();
        assert!(DeviceIdentity::create_replacement(&memory, &profile, &operation).is_err());
        assert_eq!(
            memory.get(&slot).unwrap().as_deref(),
            Some("corrupt replacement")
        );
        memory
            .set(&profile.slot("device"), "corrupt old identity")
            .unwrap();
        let next = DeviceIdentity::create_replacement(&memory, &profile, &"3".repeat(32)).unwrap();
        assert_ne!(next.id, replacement.id);
        assert_eq!(
            memory.get(&profile.slot("device")).unwrap().as_deref(),
            Some("corrupt old identity")
        );
        assert!(DeviceIdentity::load(&memory, &profile, true).is_err());
    }
    #[test]
    fn replacement_requires_successful_readback_before_its_identity_can_be_used() {
        struct Lost<'a>(&'a Memory);
        impl Keychain for Lost<'_> {
            fn get(&self, key: &str) -> Result<Option<String>, AppError> {
                self.0.get(key)
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("replacement must not delete credentials")
            }
        }
        let memory = Memory::default();
        let profile = profile();
        let old = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        assert!(
            DeviceIdentity::create_replacement(&Lost(&memory), &profile, &"4".repeat(32)).is_err()
        );
        assert_eq!(
            DeviceIdentity::load(&memory, &profile, true)
                .unwrap()
                .device(),
            old.device()
        );
        assert_eq!(*memory.writes.lock().unwrap(), 1);
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
    fn session_renewal_and_auth_epoch_reset_use_only_explicit_background_operations() {
        let memory = Memory::default();
        let profile = profile();
        let identity = DeviceIdentity::load_or_create(&memory, &profile, true).unwrap();
        let first = SessionAttempt::prepare(&memory, &profile, &identity, 1000).unwrap();
        let strict = NoPrompt(&memory, true);
        let background = Background(&strict);
        let retry = SessionAttempt::prepare(&background, &profile, &identity, 1100).unwrap();
        assert_eq!(first.id, retry.id);
        let reset =
            SessionAttempt::prepare_with_reset(&background, &profile, &identity, 1200, true)
                .unwrap();
        assert_ne!(first.id, reset.id);
        let expired = SessionAttempt::prepare(&background, &profile, &identity, 301201).unwrap();
        assert_ne!(reset.id, expired.id);
        assert!(DeviceIdentity::load_or_create(&background, &profile, false).is_ok());
        assert!(background.delete("anything").is_err());
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
        // Compatibility: old ready credentials are upgraded to v2 before their first renewal.
        let mut legacy: serde_json::Value =
            serde_json::from_str(&memory.get(&profile.slot("refresh")).unwrap().unwrap()).unwrap();
        legacy["version"] = json!(1);
        legacy.as_object_mut().unwrap().remove("state");
        memory
            .set(&profile.slot("refresh"), &legacy.to_string())
            .unwrap();
        let wrong = OidcConfig {
            client_id: "another-client".into(),
            ..config.clone()
        };
        assert!(renew(&memory, &profile, &wrong, true, &http).is_err());
        let refreshed = renew(&NoPrompt(&memory, true), &profile, &config, false, &http).unwrap();
        assert_eq!(&*refreshed.access, "new-access");
        let persisted = memory.get(&profile.slot("refresh")).unwrap().unwrap();
        assert!(persisted.contains("new-refresh"));
        assert!(!persisted.contains("old-refresh"));
        assert!(!persisted.contains("new-access"));
        exchange.assert();
        let lost=provider.mock("POST","/token").match_body(mockito::Matcher::UrlEncoded("refresh_token".into(),"new-refresh".into()))
            .with_header("content-type","application/json").with_body(json!({"access_token":"must-not-be-returned","refresh_token":"unsaved-rotation","token_type":"Bearer","expires_in":300}).to_string()).expect(1).create();
        // A denied preflight update cannot send the refresh token to the provider.
        assert!(renew(&NoPrompt(&memory, false), &profile, &config, false, &http).is_err());
        assert_eq!(
            memory.get(&profile.slot("refresh")).unwrap().unwrap(),
            persisted
        );
        struct FailAfterMarker<'a>(&'a Memory, std::sync::atomic::AtomicUsize);
        impl Keychain for FailAfterMarker<'_> {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> {
                panic!("interactive read");
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                panic!("interactive write");
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("interactive delete");
            }
            fn get_noninteractive(&self, key: &str) -> Result<Option<String>, AppError> {
                self.0.get(key)
            }
            fn set_noninteractive(&self, key: &str, value: &str) -> Result<(), AppError> {
                if self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    self.0.set(key, value)
                } else {
                    Err(AppError::Other("synthetic secure storage failure".into()))
                }
            }
        }
        let failing = FailAfterMarker(&memory, std::sync::atomic::AtomicUsize::new(0));
        let error = match renew(&failing, &profile, &config, false, &http) {
            Ok(_) => panic!("unsaved rotated token escaped"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Sign in again"));
        assert!(!error.contains("must-not-be-returned"));
        assert!(!error.contains("unsaved-rotation"));
        let pending = memory.get(&profile.slot("refresh")).unwrap().unwrap();
        assert!(pending.contains("in_flight"));
        assert!(pending.contains("new-refresh"));
        assert!(!pending.contains("unsaved-rotation"));
        // A cold retry with a now-writable keychain must still refuse the consumed old family.
        assert!(renew(&NoPrompt(&memory, true), &profile, &config, false, &http).is_err());
        assert_eq!(
            memory.get(&profile.slot("refresh")).unwrap().unwrap(),
            pending
        );
        lost.assert();
        // An explicit new browser sign-in may replace an uncertain family. Losing its next token
        // response after the provider received the request must still require another sign-in.
        let fresh = LoginTokens {
            issuer: profile.issuer.clone(),
            subject: profile.subject.clone(),
            nonce: Zeroizing::new("new-sign-in-nonce".into()),
            access: Zeroizing::new("fresh-access".into()),
            refresh: Some(Zeroizing::new("fresh-session-refresh".into())),
            expires_in: std::time::Duration::from_secs(300),
        };
        save_refresh(&memory, &profile, &config, &fresh).unwrap();
        let response_lost = provider.mock("POST", "/token")
            .match_body(mockito::Matcher::UrlEncoded("refresh_token".into(), "fresh-session-refresh".into()))
            .with_header("content-type", "application/json")
            .with_body(json!({"access_token":"lost-access","refresh_token":"lost-rotation","token_type":"Bearer","expires_in":300}).to_string())
            .expect(1).create();
        struct LoseTokenResponse<'a>(&'a oidc::BoundedHttp);
        impl openidconnect::SyncHttpClient for LoseTokenResponse<'_> {
            type Error = std::io::Error;
            fn call(
                &self,
                request: openidconnect::HttpRequest,
            ) -> Result<openidconnect::HttpResponse, Self::Error> {
                let token = request.uri().path() == "/token";
                let response = openidconnect::SyncHttpClient::call(self.0, request)?;
                if token {
                    Err(std::io::Error::other(
                        "synthetic response loss after delivery",
                    ))
                } else {
                    Ok(response)
                }
            }
        }
        assert!(renew(
            &NoPrompt(&memory, true),
            &profile,
            &config,
            false,
            &LoseTokenResponse(&http)
        )
        .is_err());
        let pending = memory.get(&profile.slot("refresh")).unwrap().unwrap();
        assert!(pending.contains("in_flight"));
        assert!(pending.contains("fresh-session-refresh"));
        assert!(!pending.contains("lost-rotation"));
        assert!(renew(&NoPrompt(&memory, true), &profile, &config, false, &http).is_err());
        response_lost.assert();
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
