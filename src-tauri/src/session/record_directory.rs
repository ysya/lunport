//! Records adapter for the broker. SyncCore remains the only mutable/persistent owner.
use crate::session::directory::{DirectoryError, HostDirectory, PinnedKey};
use crate::session::protocol::HostQuery;
use crate::ssh::{AuthMethod, Hop, HopRef, HostId, HostKey, Target};
use crate::sync::record_repository::{
    self as repo, HostEndpoint, HostReadiness, HostView, KeyView, RepositoryError,
};
use crate::sync::records_v3::{AuthKind, RecordValidationError, StoredHostKey, SyncStateV3};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::time::Duration;

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
pub struct RecordDirectory {
    sources: RecordSources,
}

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
fn stored(key: &HostKey) -> StoredHostKey {
    StoredHostKey {
        algorithm: key.algorithm.clone(),
        public_key: B64.encode(&key.public_key),
        fingerprint: key.fingerprint.clone(),
        pinned_at_ms: 0,
        pinned_by_device_id: String::new(),
    }
}
fn pinned_key(pin: &StoredHostKey) -> Result<PinnedKey, DirectoryError> {
    let line = format!("{} {}", pin.algorithm, pin.public_key);
    let key = HostKey::from_openssh_line(&line)
        .filter(|key| key.fingerprint == pin.fingerprint)
        .ok_or_else(|| DirectoryError::Failed("The saved host key is unreadable.".into()))?;
    Ok(PinnedKey {
        key,
        pinned_at_ms: pin.pinned_at_ms,
    })
}
impl RecordDirectory {
    pub fn new(sources: RecordSources) -> Self {
        Self { sources }
    }
    fn host(&self, id: &HostId) -> Result<HostView, DirectoryError> {
        repo::get_host(&(self.sources.snapshot)()?, id.as_str()).map_err(repository_error)
    }
    fn checked_host(&self, hop: &HopRef) -> Result<HostView, DirectoryError> {
        let host = self.host(&hop.id)?;
        if host.group_error.is_some()
            || host.effective_payload.hostname != hop.hostname
            || host.effective_payload.port != hop.port
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
impl HostDirectory for RecordDirectory {
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        let state = (self.sources.snapshot)()?;
        let host = match query {
            HostQuery::Id(id) => repo::get_host(&state, id),
            HostQuery::Alias(alias) => repo::find_by_alias(&state, alias),
        }
        .map_err(repository_error)?;
        let route = repo::resolve_host_chain(&state, &host.host.id).map_err(repository_error)?;
        let mut hops = Vec::with_capacity(route.len());
        let mut os_user = None;
        for view in route {
            match view.readiness {
                HostReadiness::Ready => {}
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
            let auth = match p.auth {
                AuthKind::Key => {
                    let id = p.key_id.as_ref().ok_or_else(|| {
                        DirectoryError::Unsupported("The host has no key reference.".into())
                    })?;
                    let key = repo::resolve_key(&state, id).map_err(repository_error)?;
                    if !(self.sources.material)(&key)? {
                        return Err(DirectoryError::Unsupported(format!(
                            "{} needs key {id} material on this device.",
                            p.alias
                        )));
                    }
                    AuthMethod::Key { key_id: id.clone() }
                }
                AuthKind::Password => AuthMethod::Password,
                AuthKind::Interactive => AuthMethod::Interactive,
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
            hops.push(hop);
        }
        Ok(Target { hops })
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
        self.checked_host(hop)?
            .host
            .payload
            .host_key
            .as_ref()
            .map(pinned_key)
            .transpose()
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
    fn password_account(&self, host: &HostId) -> String {
        format!("host:{}", host.as_str())
    }
}
#[cfg(test)]
#[path = "record_directory_tests.rs"]
mod tests;
