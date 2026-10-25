//! Verify a server key with the normal native trust flow, stopping before destination login.
use super::{
    auth::Owner,
    connect::{CancelToken, Connector},
    directory::{DirectoryError, HostDirectory, PinnedKey},
    protocol::HostQuery,
};
use crate::ssh::{
    AuthError, AuthSource, ConnectError, HopRef, HostId, HostKey, HostKeyPolicy, HostKeyVerdict,
    Prompt, RsaHash, Secret, Session, Signature, SshEngine, Target,
};
use serde::Serialize;
use std::{sync::Mutex, time::Instant};

#[derive(Clone, Debug, Serialize)]
pub struct VerifiedHostKey {
    pub host_id: String,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub trusted: bool,
}

fn identity(mut target: Target) -> Target {
    for hop in &mut target.hops {
        hop.pinned = None;
    }
    target
}
struct ProbeDirectory<'a> {
    inner: &'a dyn HostDirectory,
    expected: Target,
    query: &'a HostQuery,
}
impl ProbeDirectory<'_> {
    fn checked(&self) -> Result<Target, DirectoryError> {
        let target = self.inner.resolve_host_key(self.query)?;
        if identity(target.clone()) != self.expected {
            return Err(DirectoryError::Failed(
                "Connection settings changed; verify the server identity again.".into(),
            ));
        }
        Ok(target)
    }
}
impl HostDirectory for ProbeDirectory<'_> {
    fn resolve(&self, _: &HostQuery) -> Result<Target, DirectoryError> {
        self.checked()
    }
    fn pinned(&self, id: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        self.inner.pinned(id)
    }
    fn pin(&self, id: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
        self.inner.pin(id, key)
    }
    fn replace_pin(&self, id: &HostId, old: &HostKey, key: &HostKey) -> Result<(), DirectoryError> {
        self.inner.replace_pin(id, old, key)
    }
    fn pinned_for(&self, hop: &HopRef) -> Result<Option<PinnedKey>, DirectoryError> {
        self.inner.pinned_for(hop)
    }
    fn pin_for(&self, hop: &HopRef, key: &HostKey) -> Result<(), DirectoryError> {
        self.inner.pin_for(hop, key)
    }
    fn replace_pin_for(
        &self,
        hop: &HopRef,
        old: &HostKey,
        key: &HostKey,
    ) -> Result<(), DirectoryError> {
        self.inner.replace_pin_for(hop, old, key)
    }
    fn pin_confirmed(
        &self,
        hop: &HopRef,
        old: Option<&HostKey>,
        key: &HostKey,
        cancel: &CancelToken,
        guard: &(dyn Fn() -> Result<(), DirectoryError> + Sync),
    ) -> Result<(), DirectoryError> {
        self.inner.pin_confirmed(hop, old, key, cancel, &|| {
            guard()?;
            self.checked().map(|_| ())
        })
    }
    fn password_authorized(&self, hop: &HopRef, server_key: Option<&HostKey>) -> Result<bool, DirectoryError> {
        self.checked()?;
        self.inner.password_authorized(hop, server_key)
    }
    fn saved_password(&self, hop:&HopRef, keychain:&dyn crate::sync::env::Keychain)->Result<Option<Secret>,DirectoryError>{
        self.checked()?;
        let password=self.inner.saved_password(hop,keychain)?;
        self.checked()?;
        Ok(password)
    }
    fn password_account(&self, id: &HostId) -> String {
        self.inner.password_account(id)
    }
    fn prepare(&self, target: &Target, public_key: &dyn Fn(&str) -> Option<String>, cancel: &CancelToken) -> Result<super::directory::Prepared, DirectoryError> {
        // A fingerprint check asks nobody for a grant (design 2026-10-25, PAM grant requests): a needed grant is the refusal.
        self.inner.prepare(target, public_key, cancel).map_err(DirectoryError::for_automation)
    }
}

struct StopBeforeLogin<'a> {
    inner: &'a dyn AuthSource,
    destination: &'a HostId,
}
impl AuthSource for StopBeforeLogin<'_> {
    fn public_key(&self, id: &str) -> Option<String> {
        self.inner.public_key(id)
    }
    fn sign(&self, id: &str, data: &[u8], hash: Option<RsaHash>) -> Result<Signature, AuthError> {
        self.inner.sign(id, data, hash)
    }
    fn password(&self, hop: &HopRef) -> Option<Secret> {
        if &hop.id == self.destination {
            None
        } else {
            self.inner.password(hop)
        }
    }
    fn interactive(
        &self,
        hop: &HopRef,
        prompts: &[Prompt],
        deadline: Instant,
    ) -> Option<Vec<Secret>> {
        if &hop.id == self.destination {
            None
        } else {
            self.inner.interactive(hop, prompts, deadline)
        }
    }
    fn banner(&self, hop: &HopRef, text: &str) {
        self.inner.banner(hop, text)
    }
}
struct ProbePolicy<'a> {
    inner: &'a dyn HostKeyPolicy,
    destination: &'a HostId,
    verified: &'a Mutex<Option<(HopRef, HostKey)>>,
}
impl HostKeyPolicy for ProbePolicy<'_> {
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict {
        let verdict = self.inner.check(hop, key);
        if &hop.id == self.destination && verdict == HostKeyVerdict::Pinned {
            *self.verified.lock().unwrap() = Some((hop.clone(), key.clone()));
            // Force the engine to stop before it requests any destination credentials.
            HostKeyVerdict::Unknown
        } else {
            verdict
        }
    }
}
struct ProbeEngine<'a> {
    inner: &'a dyn SshEngine,
    guard: &'a (dyn Fn() -> Result<(), String> + Sync),
    completed: Mutex<Option<(HopRef, HostKey)>>,
}
impl SshEngine for ProbeEngine<'_> {
    fn connect(
        &self,
        target: &Target,
        policy: &dyn HostKeyPolicy,
        auth: &dyn AuthSource,
    ) -> Result<Box<dyn Session>, ConnectError> {
        (self.guard)().map_err(|why| ConnectError::BadJumpChain { why })?;
        let destination = &target
            .hops
            .last()
            .ok_or_else(|| ConnectError::BadJumpChain {
                why: "No destination.".into(),
            })?
            .id;
        let verified = Mutex::new(None);
        let probe = ProbePolicy {
            inner: policy,
            destination,
            verified: &verified,
        };
        let auth = StopBeforeLogin {
            inner: auth,
            destination,
        };
        match self.inner.connect(target, &probe, &auth) {
            Err(ConnectError::HostKeyUnknown { hop, key })
                if &hop.id == destination
                    && verified
                        .lock()
                        .unwrap()
                        .as_ref()
                        .is_some_and(|(h, k)| h == &hop && k == &key) =>
            {
                *self.completed.lock().unwrap() = Some((hop.clone(), key));
                Err(ConnectError::Protocol {
                    hop,
                    text: "Server identity verified; destination login was not attempted.".into(),
                })
            }
            Ok(session) => {
                session.close();
                Err(ConnectError::BadJumpChain {
                    why: "Host-key verification unexpectedly opened a session; it was closed."
                        .into(),
                })
            }
            other => other,
        }
    }
}

pub fn verify(
    connector: &Connector<'_>,
    query: &HostQuery,
    owner: &dyn Owner,
    cancel: &CancelToken,
) -> Result<VerifiedHostKey, String> {
    if cancel.is_cancelled() {
        return Err("Server identity verification was canceled.".into());
    }
    let expected = identity(
        connector
            .directory
            .resolve_host_key(query)
            .map_err(|e| e.to_string())?,
    );
    let directory = ProbeDirectory {
        inner: connector.directory,
        expected,
        query,
    };
    let guard = || {
        if cancel.is_cancelled() {
            return Err("Server identity verification was canceled.".into());
        }
        directory.checked().map(|_| ()).map_err(|e| e.to_string())
    };
    let engine = ProbeEngine {
        inner: connector.engine,
        guard: &guard,
        completed: Mutex::new(None),
    };
    let probe = Connector {
        engine: &engine,
        directory: &directory,
        keys: connector.keys,
        keychain: connector.keychain,
        confirmer: connector.confirmer,
    };
    let result = probe.connect(query, owner, cancel);
    if cancel.is_cancelled() {
        return Err("Server identity verification was canceled.".into());
    }
    let current = directory.checked().map_err(|e| e.to_string())?;
    match engine.completed.into_inner().unwrap() {
        Some((hop, key))
            if current
                .hops
                .iter()
                .any(|h| h.id == hop.id && h.pinned.as_ref() == Some(&key)) =>
        {
            Ok(VerifiedHostKey {
                host_id: hop.id.as_str().into(),
                alias: hop.alias,
                hostname: hop.hostname,
                port: hop.port,
                algorithm: key.algorithm,
                fingerprint: key.fingerprint,
                trusted: true,
            })
        }
        Some(_) => Err(
            "The saved server key changed during verification. Verify the current identity again."
                .into(),
        ),
        None => Err(result
            .err()
            .map(|e| e.text)
            .unwrap_or_else(|| "Server identity was not verified.".into())),
    }
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
