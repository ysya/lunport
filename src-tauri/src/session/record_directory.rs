//! Records adapter for the broker. SyncCore remains the only mutable/persistent owner.
use crate::session::directory::{DirectoryError, GrantNeed, GrantReceipt, HostDirectory, PinnedKey, Prepared};
use crate::session::protocol::HostQuery;
use crate::gcp::rest::GcpClient;
use crate::ssh::{AuthMethod, Hop, HopRef, HostId, HostKey, IapTarget, Target, Transport};
use crate::sync::transports::{self, HostTransport, TransportKind};
use crate::sync::record_repository::{
    self as repo, HostEndpoint, HostReadiness, HostView, KeyView, RepositoryError,
};
use crate::sync::records_v3::{AuthKind, RecordValidationError, StoredHostKey, SyncStateV3};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::time::{Duration, SystemTime};

pub struct RecordSources {
    pub snapshot: Box<dyn Fn() -> Result<SyncStateV3, DirectoryError> + Send + Sync>,
    /// Verify actual vault material against this snapshot's authoritative public metadata.
    pub material: Box<dyn Fn(&KeyView) -> Result<bool, DirectoryError> + Send + Sync>,
    pub username: Box<dyn Fn() -> Result<String, DirectoryError> + Send + Sync>,
    /// Commit under SyncCore: endpoint/previous-key CAS, durable save, then memory replacement.
    pub pin: Box<
        dyn Fn(
                &HostId,
                &HostEndpoint,
                Option<&StoredHostKey>,
                &StoredHostKey,
            ) -> Result<(), DirectoryError>
            + Send
            + Sync,
    >,
}
type ConfirmedPin = dyn Fn(
        &HopRef,
        Option<&HostKey>,
        &HostKey,
        &super::connect::CancelToken,
        &(dyn Fn() -> Result<(), DirectoryError> + Sync),
    ) -> Result<(), DirectoryError>
    + Send
    + Sync;
type PasswordReader = dyn Fn(&HopRef, &dyn crate::sync::env::Keychain) -> Result<Option<crate::ssh::Secret>, DirectoryError> + Send + Sync;
pub struct RecordDirectory {
    sources: RecordSources,
    confirmed_pin: Option<Box<ConfirmedPin>>,
    password_reader: Option<Box<PasswordReader>>,
    /// Google, for `prepare` (OS Login, PAM); `None` in builds and tests without it.
    gcp: Option<Box<dyn GcpClient>>,
    /// Where a grant request's justification and duration are kept for next time; `None` forgets them.
    grant_memory: Option<Box<GrantMemory>>,
}
/// When a grant was given, as the broker counts it: its grant time, never ahead of `now` (Google's clock may run ahead); `now` for a
/// grant still activating; nothing for a grant with no time that is not activating (design 2026-10-25, PAM grant requests).
fn repository_error(error: RepositoryError) -> DirectoryError {
    match error {
        RepositoryError::Validation(RecordValidationError::HostNotFound(id)) => {
            DirectoryError::NotFound(format!("No saved host matches {id}."))
        }
        RepositoryError::Validation(RecordValidationError::AmbiguousAlias(alias)) => {
            DirectoryError::Ambiguous(format!("Several hosts use {alias}; connect with --id."))
        }
        error => DirectoryError::Unsupported(format!("The saved records need review: {error}")),
    }
}
fn endpoint(host: &HostView) -> HostEndpoint {
    HostEndpoint {
        hostname: host.effective_payload.hostname.clone(),
        port: host.effective_payload.port,
    }
}
pub(super) fn stored(key: &HostKey) -> StoredHostKey {
    StoredHostKey {
        algorithm: key.algorithm.clone(),
        public_key: B64.encode(&key.public_key),
        fingerprint: key.fingerprint.clone(),
        pinned_at_ms: 0,
        pinned_by_device_id: String::new(),
    }
}
pub(super) fn pinned_key(pin: &StoredHostKey) -> Result<PinnedKey, DirectoryError> {
    let line = format!("{} {}", pin.algorithm, pin.public_key);
    let key = HostKey::from_openssh_line(&line)
        .filter(|key| key.fingerprint == pin.fingerprint)
        .ok_or_else(|| DirectoryError::Failed("The saved host key is unreadable.".into()))?;
    Ok(PinnedKey {
        key,
        pinned_at_ms: pin.pinned_at_ms,
    })
}
/// Writes what a grant request taught a host's transport: `(host, justification, duration_secs)` (design 2026-10-25, PAM grant requests).
pub type GrantMemory = dyn Fn(&HostId, &str, u32) -> Result<(), DirectoryError> + Send + Sync;

impl RecordDirectory {
    pub fn new(sources: RecordSources) -> Self {
        Self {
            sources,
            confirmed_pin: None,
            password_reader: None,
            gcp: None,
            grant_memory: None,
        }
    }
    pub(crate) fn with_grant_memory(mut self, remember: Box<GrantMemory>) -> Self {
        self.grant_memory = Some(remember);
        self
    }

    /// `HostDirectory::request_grant` with the pacing given (the trait method uses the design's 2 s and 60 s; tests hurry). A grant that
    /// appeared since `prepare` looked (another connection, the panel) is used instead of requested: PAM refuses a second request with
    /// the same scope. What the person gave is remembered on the transport for next time, whether or not the memory can be written.
    pub(crate) fn request_grant_with(
        &self,
        need: &GrantNeed,
        justification: &str,
        duration_secs: u32,
        cancel: &super::connect::CancelToken,
        poll_every: Duration,
        wait: Duration,
    ) -> Result<GrantReceipt, DirectoryError> {
        let gcp = self.gcp.as_deref().ok_or_else(|| DirectoryError::Failed("Google Cloud access is not configured in this build.".into()))?;
        let place = crate::gcp::pam::Entitlement { account: need.account.as_deref(), project: &need.project, location: &need.location, entitlement: &need.entitlement };
        // A failed memory write does not fail the request: the grant exists either way.
        let remember = || {
            if let Some(remember) = &self.grant_memory {
                let _ = remember(&need.host, justification, duration_secs);
            }
        };
        let grant = crate::gcp::pam::request_and_wait(gcp, &place, justification, duration_secs, &remember, poll_every, wait, &|| cancel.is_cancelled()).map_err(|error| match error {
            crate::gcp::pam::RequestError::Cancelled => DirectoryError::Failed(error.sentence(&need.entitlement)),
            other => DirectoryError::Denied(other.sentence(&need.entitlement)),
        })?;
        let (granted_at, active_until) = crate::gcp::pam::active_span(&grant, SystemTime::now(), duration_secs);
        Ok(GrantReceipt { entitlement: need.entitlement.clone(), granted_at, active_until })
    }
    pub(crate) fn with_password_reader(mut self, read: Box<PasswordReader>) -> Self {
        self.password_reader = Some(read);
        self
    }
    pub(crate) fn with_confirmed_pin(mut self, pin: Box<ConfirmedPin>) -> Self {
        self.confirmed_pin = Some(pin);
        self
    }
    pub(crate) fn with_gcp(mut self, gcp: Box<dyn GcpClient>) -> Self {
        self.gcp = Some(gcp);
        self
    }
    fn host(&self, id: &HostId) -> Result<HostView, DirectoryError> {
        repo::get_host(&(self.sources.snapshot)()?, id.as_str()).map_err(repository_error)
    }
    fn checked_host(&self, hop: &HopRef) -> Result<HostView, DirectoryError> {
        let host = self.host(&hop.id)?;
        if host.group_error.is_some()
            || host.effective_payload.hostname != hop.hostname
            || host.effective_payload.port != hop.port
            || if host.effective_payload.user.is_empty() { (self.sources.username)()? != hop.user } else { host.effective_payload.user != hop.user }
        {
            return Err(DirectoryError::Failed(format!(
                "The endpoint of {} changed while connecting; connect again.",
                hop.id
            )));
        }
        Ok(host)
    }
    fn write_pin(
        &self,
        host: HostView,
        previous: Option<&HostKey>,
        key: &HostKey,
    ) -> Result<(), DirectoryError> {
        let expected = host.host.payload.host_key.as_ref();
        if let Some(pin) = expected {
            let current = pinned_key(pin)?.key;
            // Even an identical pin needs a durable receipt; memory may still be unsaved.
            if current != *key && previous != Some(&current) {
                return Err(DirectoryError::Failed(format!(
                    "The pinned key of {} changed before confirmation.",
                    host.host.id
                )));
            }
        } else if previous.is_some() {
            return Err(DirectoryError::Failed(format!(
                "The pinned key of {} changed before confirmation.",
                host.host.id
            )));
        }
        (self.sources.pin)(
            &HostId::from(host.host.id.as_str()),
            &endpoint(&host),
            expected,
            &stored(key),
        )
    }
}
impl RecordDirectory {
    fn resolve_material(
        &self,
        query: &HostQuery,
        verify_material: bool,
        host_key_only: bool,
    ) -> Result<Target, DirectoryError> {
        let state = (self.sources.snapshot)()?;
        let host = match query {
            HostQuery::Id(id) => repo::get_host(&state, id),
            HostQuery::Alias(alias) => repo::find_by_alias(&state, alias),
        }
        .map_err(repository_error)?;
        let route = repo::resolve_host_chain(&state, &host.host.id).map_err(repository_error)?;
        let mut hops = Vec::with_capacity(route.len());
        let mut os_user = None;
        let last = route.len().saturating_sub(1);
        for (index, view) in route.into_iter().enumerate() {
            let probe = host_key_only && index == last;
            match view.readiness {
                HostReadiness::Ready => {}
                HostReadiness::NeedsKey(_) | HostReadiness::KeyConflict(_) if probe => {}
                HostReadiness::NeedsKey(ref id) => {
                    return Err(DirectoryError::Unsupported(format!(
                        "{} needs key {id} on this device.",
                        view.host.payload.alias
                    )))
                }
                HostReadiness::KeyConflict(ref id) => {
                    return Err(DirectoryError::Unsupported(format!(
                        "Key {id} has conflicting public identities."
                    )))
                }
                HostReadiness::NeedsReview => {
                    return Err(DirectoryError::Unsupported(format!(
                        "{} needs its imported settings or route reviewed.",
                        view.host.payload.alias
                    )))
                }
            }
            let p = &view.effective_payload;
            let auth = if probe {
                AuthMethod::Interactive
            } else {
                match p.auth {
                    AuthKind::Key => {
                        let id = p.key_id.as_ref().ok_or_else(|| {
                            DirectoryError::Unsupported("The host has no key reference.".into())
                        })?;
                        let key = repo::resolve_key(&state, id).map_err(repository_error)?;
                        if verify_material && !(self.sources.material)(&key)? {
                            return Err(DirectoryError::Unsupported(format!(
                                "{} needs key {id} material on this device.",
                                p.alias
                            )));
                        }
                        AuthMethod::Key { key_id: id.clone() }
                    }
                    AuthKind::Password => AuthMethod::Password,
                    AuthKind::Interactive => AuthMethod::Interactive,
                }
            };
            let user = if p.user.is_empty() {
                if os_user.is_none() {
                    let user = (self.sources.username)()?;
                    if user.is_empty() || user.chars().any(|c| c.is_whitespace() || c.is_control())
                    {
                        return Err(DirectoryError::Failed(
                            "The operating system did not provide a valid username.".into(),
                        ));
                    }
                    os_user = Some(user);
                }
                os_user.as_ref().unwrap().clone()
            } else {
                p.user.clone()
            };
            let mut hop = Hop::new(&view.host.id, &p.alias, &p.hostname, p.port, &user, auth);
            hop.connect_timeout = Duration::from_secs(u64::from(p.connect_timeout_secs));
            hop.keepalive_every = Duration::from_secs(u64::from(p.keepalive_secs));
            hop.keepalive_max_missed = p.keepalive_max_missed;
            hop.pinned = p
                .host_key
                .as_ref()
                .map(pinned_key)
                .transpose()?
                .map(|pin| pin.key);
            if hop.pinned.as_ref().is_some_and(|key| !super::credential_approval::matches(&state, &hop.reference(), key)) {
                hop.pinned = None;
            }
            hops.push(hop);
        }
        // A device-local transport (design 2026-10-25) replaces the first hop's TCP connection. It cannot carry a later hop, which is
        // reached through the hop before it.
        for (index, hop) in hops.iter_mut().enumerate() {
            let Some(HostTransport { kind: TransportKind::GcpIap { project, zone, instance, interface, account, .. }, .. }) = transports::get(&state, hop.id.as_str()) else {
                continue;
            };
            if index > 0 {
                return Err(DirectoryError::Unsupported(format!("{} connects through Google Cloud IAP and cannot be reached through a jump host.", hop.alias)));
            }
            hop.transport = Transport::GcpIap(IapTarget { project, zone, instance, interface, account, url_root: None });
        }
        Ok(Target { hops })
    }
}
impl HostDirectory for RecordDirectory {
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        self.resolve_material(query, true, false)
    }
    fn resolve_public(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        self.resolve_material(query, false, false)
    }
    fn resolve_host_key(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        self.resolve_material(query, false, true)
    }
    /// For a first hop through Google Cloud IAP (design 2026-10-25): the PAM grant check, then OS Login. The key is registered when the
    /// profile lacks it or has no POSIX account yet (`gcloud compute ssh` does the same; the import creates the account), and the
    /// profile's username must be the one the host is saved with: nothing here changes the target, so the identity checks that compare
    /// the hop's user keep their meaning.
    fn prepare(&self, target: &Target, public_key: &dyn Fn(&str) -> Option<String>, cancel: &super::connect::CancelToken) -> Result<Prepared, DirectoryError> {
        let nothing = Prepared::default();
        let Some(hop) = target.hops.first() else { return Ok(nothing) };
        if !matches!(hop.transport, Transport::GcpIap(_)) {
            return Ok(nothing);
        }
        let state = (self.sources.snapshot)()?;
        let Some(HostTransport { kind: TransportKind::GcpIap { project, account, os_login, pam, .. }, .. }) = transports::get(&state, hop.id.as_str()) else {
            return Ok(nothing);
        };
        if !os_login && pam.is_none() {
            return Ok(nothing);
        }
        let gcp = self.gcp.as_deref().ok_or_else(|| DirectoryError::Failed("Google Cloud access is not configured in this build.".into()))?;
        let cancelled = || DirectoryError::Failed("The connection was cancelled.".into());
        let denied = |error: crate::gcp::rest::GcpError| DirectoryError::Denied(error.to_string());
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let who = account.as_deref().unwrap_or("the active gcloud account");
        let mut prepared = nothing;
        if let Some(pam) = &pam {
            let mut in_flight = false;
            for entitlement in &pam.entitlements {
                let grants = gcp.grants(account.as_deref(), &project, &pam.location, entitlement).map_err(denied)?;
                let current = crate::gcp::pam::in_flight(&grants);
                if !current.is_empty() {
                    in_flight = true;
                    // IAP can take about 1½ minutes to see a grant: the broker waits on IAP, and says so, after a grant this young. The
                    // freshest in-flight grant dates it; one still activating, or timed by a clock ahead of this one, is as fresh as now.
                    let now = SystemTime::now();
                    let dated = current.iter().filter_map(|grant| crate::gcp::pam::granted_at(grant, now)).max();
                    prepared.recent_grant = dated.is_some_and(|granted| now.duration_since(granted).map_or(true, |age| age <= Duration::from_secs(120)));
                    prepared.granted_at = dated;
                    break;
                }
            }
            if !in_flight {
                return Err(DirectoryError::GrantNeeded(GrantNeed {
                    host: hop.id.clone(),
                    account: account.clone(),
                    project: project.clone(),
                    location: pam.location.clone(),
                    entitlement: pam.entitlements[0].clone(),
                    entitlements: pam.entitlements.clone(),
                    duration_secs: pam.duration_secs,
                    justification: pam.justification.clone(),
                }));
            }
            if cancel.is_cancelled() {
                return Err(cancelled());
            }
        }
        if os_login {
            let mut profile = gcp.login_profile(account.as_deref(), &project).map_err(denied)?;
            if let AuthMethod::Key { key_id } = &hop.auth {
                if let Some(line) = public_key(key_id) {
                    if profile.username().is_none() || !profile.has_key(&line) {
                        if cancel.is_cancelled() {
                            return Err(cancelled());
                        }
                        profile = gcp.import_ssh_public_key(account.as_deref(), &project, &line).map_err(denied)?;
                    }
                }
            }
            match profile.username() {
                None => {
                    return Err(DirectoryError::Denied(format!("OS Login has no POSIX account for {who} in {project}; the project may not have OS Login enabled.")));
                }
                Some(name) if name != hop.user => {
                    return Err(DirectoryError::Denied(format!(
                        "OS Login names {who} {name} on {project}, but the host is saved with user {}; save that username into the host (Use OS Login username in the host's Google Cloud transport).",
                        hop.user
                    )));
                }
                Some(_) => {}
            }
        }
        Ok(prepared)
    }
    fn request_grant(&self, need: &GrantNeed, justification: &str, duration_secs: u32, cancel: &super::connect::CancelToken) -> Result<GrantReceipt, DirectoryError> {
        self.request_grant_with(need, justification, duration_secs, cancel, Duration::from_secs(2), Duration::from_secs(60))
    }
    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        self.host(host)?
            .host
            .payload
            .host_key
            .as_ref()
            .map(pinned_key)
            .transpose()
    }
    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
        self.write_pin(self.host(host)?, None, key)
    }
    fn replace_pin(
        &self,
        host: &HostId,
        previous: &HostKey,
        key: &HostKey,
    ) -> Result<(), DirectoryError> {
        self.write_pin(self.host(host)?, Some(previous), key)
    }
    fn pinned_for(&self, hop: &HopRef) -> Result<Option<PinnedKey>, DirectoryError> {
        let host = self.checked_host(hop)?;
        let pin = host.host.payload.host_key.as_ref().map(pinned_key).transpose()?;
        let state = (self.sources.snapshot)()?;
        Ok(pin.filter(|pin| super::credential_approval::matches(&state, hop, &pin.key)))
    }
    fn password_authorized(&self, hop: &HopRef, server_key: Option<&HostKey>) -> Result<bool, DirectoryError> {
        Ok(self.pinned_for(hop)?.is_some_and(|pin| Some(&pin.key) == server_key))
    }
    fn pin_for(&self, hop: &HopRef, key: &HostKey) -> Result<(), DirectoryError> {
        self.write_pin(self.checked_host(hop)?, None, key)
    }
    fn replace_pin_for(
        &self,
        hop: &HopRef,
        previous: &HostKey,
        key: &HostKey,
    ) -> Result<(), DirectoryError> {
        self.write_pin(self.checked_host(hop)?, Some(previous), key)
    }
    fn pin_confirmed(
        &self,
        hop: &HopRef,
        previous: Option<&HostKey>,
        key: &HostKey,
        cancel: &super::connect::CancelToken,
        guard: &(dyn Fn() -> Result<(), DirectoryError> + Sync),
    ) -> Result<(), DirectoryError> {
        if let Some(pin) = &self.confirmed_pin {
            return pin(hop, previous, key, cancel, guard);
        }
        guard()?;
        if cancel.is_cancelled() {
            return Err(DirectoryError::Failed(
                "The connection was cancelled.".into(),
            ));
        }
        self.write_pin(self.checked_host(hop)?, previous, key)
    }
    fn saved_password(&self, hop: &HopRef, keychain: &dyn crate::sync::env::Keychain) -> Result<Option<crate::ssh::Secret>, DirectoryError> {
        self.checked_host(hop)?;
        if let Some(read) = &self.password_reader {return read(hop,keychain);}
        keychain.get(&self.password_account(&hop.id)).map(|value|value.map(zeroize::Zeroizing::new)).map_err(|_|DirectoryError::Failed("The saved password is unavailable.".into()))
    }
    fn password_account(&self, host: &HostId) -> String {
        format!("host:{}", host.as_str())
    }
}
#[cfg(test)]
#[path = "record_directory_tests.rs"]
mod tests;
