//! The broker's directory: the Records directory, reached under the sync lifecycle lock so an account, server or migration change
//! never runs in the middle of a request, and refused while the workspace is not a Records library (a saved OpenSSH workspace that
//! was not imported yet, or a blocked state).
use super::directory::{DirectoryError, GrantNeed, GrantReceipt, HostDirectory, PinnedKey, Prepared};
use super::protocol::HostQuery;
use crate::ssh::{HopRef, HostId, HostKey, Target};
use crate::sync::record_runtime::RuntimeFormat;
use std::sync::Arc;

pub struct FormatDirectory {
    pub lifecycle: Arc<std::sync::Mutex<()>>,
    pub mode: Box<dyn Fn() -> RuntimeFormat + Send + Sync>,
    pub records: Arc<dyn HostDirectory>,
}

const NOT_RECORDS: &str = "Import the existing workspace into the library, or resolve the blocked state, before connecting.";
impl FormatDirectory {
    fn with_active<T>(
        &self,
        f: impl FnOnce(&dyn HostDirectory) -> Result<T, DirectoryError>,
    ) -> Result<T, DirectoryError> {
        let _guard = self.lifecycle.lock().unwrap();
        f(self.active()?)
    }
    fn active(&self) -> Result<&dyn HostDirectory, DirectoryError> {
        match (self.mode)() {
            RuntimeFormat::Records => Ok(self.records.as_ref()),
            _ => Err(DirectoryError::Unsupported(NOT_RECORDS.into())),
        }
    }
    /// Checks the format under lifecycle and hands the directory back to be called outside it (a call that waits on Google or on an
    /// OS authorization must not hold lifecycle).
    fn chosen(&self) -> Result<Arc<dyn HostDirectory>, DirectoryError> {
        let _lifecycle = self.lifecycle.lock().unwrap();
        self.active()?;
        Ok(self.records.clone())
    }
}
impl HostDirectory for FormatDirectory {
    fn resolve_host_key(&self,q:&HostQuery)->Result<Target,DirectoryError>{self.with_active(|d|d.resolve_host_key(q))}
    fn resolve_public(&self,q:&HostQuery)->Result<Target,DirectoryError>{self.with_active(|d|d.resolve_public(q))}
    fn resolve(&self, q: &HostQuery) -> Result<Target, DirectoryError> {
        self.with_active(|d| d.resolve(q))
    }
    fn pinned(&self, id: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        self.with_active(|d| d.pinned(id))
    }
    fn pin(&self, id: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
        self.with_active(|d| d.pin(id, key))
    }
    fn replace_pin(
        &self,
        id: &HostId,
        previous: &HostKey,
        key: &HostKey,
    ) -> Result<(), DirectoryError> {
        self.with_active(|d| d.replace_pin(id, previous, key))
    }
    fn pinned_for(&self, hop: &HopRef) -> Result<Option<PinnedKey>, DirectoryError> {
        self.with_active(|d| d.pinned_for(hop))
    }
    fn pin_for(&self, hop: &HopRef, key: &HostKey) -> Result<(), DirectoryError> {
        self.with_active(|d| d.pin_for(hop, key))
    }
    fn replace_pin_for(
        &self,
        hop: &HopRef,
        old: &HostKey,
        key: &HostKey,
    ) -> Result<(), DirectoryError> {
        self.with_active(|d| d.replace_pin_for(hop, old, key))
    }
    fn pin_confirmed(
        &self,
        hop: &HopRef,
        previous: Option<&HostKey>,
        key: &HostKey,
        cancel: &super::connect::CancelToken,
        guard: &(dyn Fn() -> Result<(), DirectoryError> + Sync),
    ) -> Result<(), DirectoryError> {
        // Request guards may themselves resolve through this adapter; never run them under lifecycle.
        guard()?;
        let records = {
            let _lifecycle = self.lifecycle.lock().unwrap();
            if (self.mode)() != RuntimeFormat::Records {
                return Err(DirectoryError::Unsupported(
                    "The workspace changed before host-key confirmation.".into(),
                ));
            }
            self.records.clone()
        };
        records.pin_confirmed(hop, previous, key, cancel, guard)
    }
    fn password_authorized(&self, hop: &HopRef, server_key: Option<&HostKey>) -> Result<bool, DirectoryError> {
        self.with_active(|d| d.password_authorized(hop, server_key))
    }
    fn prepare(&self, target: &Target, public_key: &dyn Fn(&str) -> Option<String>, cancel: &super::connect::CancelToken) -> Result<Prepared, DirectoryError> {
        // Google may take seconds to answer: choose the directory under lifecycle, call it outside.
        self.chosen()?.prepare(target, public_key, cancel)
    }
    fn request_grant(&self, need: &GrantNeed, justification: &str, duration_secs: u32, cancel: &super::connect::CancelToken) -> Result<GrantReceipt, DirectoryError> {
        // The request waits on Google for up to a minute: choose the directory under lifecycle, call it outside, as `prepare` does.
        self.chosen()?.request_grant(need, justification, duration_secs, cancel)
    }
    fn saved_password(&self, hop: &HopRef, keychain: &dyn crate::sync::env::Keychain) -> Result<Option<crate::ssh::Secret>, DirectoryError> {
        // Records' native reader owns lifecycle while checking its exact saved owner. Never
        // hold this adapter's lifecycle across that protected read or an OS authorization.
        self.chosen()?.saved_password(hop, keychain)
    }
    fn password_account(&self, id: &HostId) -> String {
        self.active()
            .map(|d| d.password_account(id))
            .unwrap_or_else(|_| format!("host:{}", id.as_str()))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Fake(&'static str);
    impl HostDirectory for Fake {
        fn resolve(&self, _: &HostQuery) -> Result<Target, DirectoryError> {
            Err(DirectoryError::NotFound(self.0.into()))
        }
        fn pinned(&self, _: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
            Ok(None)
        }
        fn pin(&self, _: &HostId, _: &HostKey) -> Result<(), DirectoryError> {
            panic!("endpoint context must be forwarded")
        }
        fn replace_pin(&self, _: &HostId, _: &HostKey, _: &HostKey) -> Result<(), DirectoryError> {
            panic!("endpoint context must be forwarded")
        }
        fn pinned_for(&self, hop: &HopRef) -> Result<Option<PinnedKey>, DirectoryError> {
            Err(DirectoryError::Failed(format!(
                "{}:{}:{}",
                self.0, hop.hostname, hop.port
            )))
        }
        fn password_account(&self, id: &HostId) -> String {
            format!("{}:{}", self.0, id)
        }
        fn saved_password(&self, _: &HopRef, _: &dyn crate::sync::env::Keychain) -> Result<Option<crate::ssh::Secret>,DirectoryError> {
            Ok(Some(zeroize::Zeroizing::new(format!("{} native saved password",self.0))))
        }
    }
    fn fixture() -> (FormatDirectory, Arc<Mutex<RuntimeFormat>>) {
        let mode = Arc::new(Mutex::new(RuntimeFormat::Legacy));
        let read = mode.clone();
        (
            FormatDirectory {
                lifecycle: Arc::default(),
                mode: Box::new(move || *read.lock().unwrap()),
                records: Arc::new(Fake("records")),
            },
            mode,
        )
    }
    #[test]
    fn an_existing_broker_reaches_records_once_the_workspace_is_imported() {
        let (d, mode) = fixture();
        let q = HostQuery::Alias("web".into());
        assert!(matches!(d.resolve(&q), Err(DirectoryError::Unsupported(_))));
        assert_eq!(d.password_account(&HostId::from("id")), "host:id");
        *mode.lock().unwrap() = RuntimeFormat::Records;
        assert_eq!(
            d.resolve(&q).unwrap_err(),
            DirectoryError::NotFound("records".into())
        );
        assert_eq!(d.password_account(&HostId::from("id")), "records:id");
        let hop=crate::ssh::Hop::new("id","web","fixture.invalid",22,"fixture",crate::ssh::AuthMethod::Password).reference();
        let keychain=crate::sync::testkit::MemKeychain::default();
        assert_eq!(d.saved_password(&hop,&keychain).unwrap().as_deref().map(String::as_str),Some("records native saved password"));
        *mode.lock().unwrap()=RuntimeFormat::Blocked;
        assert!(d.saved_password(&hop,&keychain).is_err());
    }
    #[test]
    fn blocked_and_saved_legacy_workspaces_cannot_resolve_or_read_pins() {
        let (d, mode) = fixture();
        for m in [RuntimeFormat::Blocked, RuntimeFormat::Legacy] {
            *mode.lock().unwrap() = m;
            assert!(matches!(
                d.resolve(&HostQuery::Id("id".into())),
                Err(DirectoryError::Unsupported(_))
            ));
            assert!(d.pinned(&HostId::from("id")).is_err());
        }
    }
    #[test]
    fn endpoint_aware_reads_reach_the_current_adapter() {
        let (d, mode) = fixture();
        *mode.lock().unwrap() = RuntimeFormat::Records;
        let hop = HopRef {
            id: HostId::from("id"),
            alias: "web".into(),
            hostname: "changed.example".into(),
            port: 2200,
            user: "user".into(),
        };
        assert_eq!(
            d.pinned_for(&hop).unwrap_err(),
            DirectoryError::Failed("records:changed.example:2200".into())
        );
    }
    #[test]
    fn prepare_reaches_the_active_directory_outside_the_lifecycle_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Notes {
            lifecycle: Arc<Mutex<()>>,
            calls: AtomicUsize,
        }
        impl HostDirectory for Notes {
            fn resolve(&self, _: &HostQuery) -> Result<Target, DirectoryError> {
                Err(DirectoryError::NotFound("notes".into()))
            }
            fn pinned(&self, _: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
                Ok(None)
            }
            fn pin(&self, _: &HostId, _: &HostKey) -> Result<(), DirectoryError> {
                panic!("not used")
            }
            fn replace_pin(&self, _: &HostId, _: &HostKey, _: &HostKey) -> Result<(), DirectoryError> {
                panic!("not used")
            }
            fn password_account(&self, id: &HostId) -> String {
                format!("notes:{id}")
            }
            fn prepare(&self, _: &Target, _: &dyn Fn(&str) -> Option<String>, _: &super::super::connect::CancelToken) -> Result<Prepared, DirectoryError> {
                // Google may take seconds to answer: the adapter must not hold the lifecycle while it waits.
                assert!(self.lifecycle.try_lock().is_ok(), "prepare ran under the lifecycle lock");
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(Prepared::default())
            }
        }
        let lifecycle: Arc<Mutex<()>> = Arc::default();
        let records = Arc::new(Notes { lifecycle: Arc::clone(&lifecycle), calls: AtomicUsize::new(0) });
        let mode = Arc::new(Mutex::new(RuntimeFormat::Records));
        let read = mode.clone();
        let d = FormatDirectory { lifecycle, mode: Box::new(move || *read.lock().unwrap()), records: records.clone() };
        let target = Target { hops: vec![crate::ssh::Hop::new("id", "web", "fixture.invalid", 22, "fixture", crate::ssh::AuthMethod::Password)] };
        let cancel = super::super::connect::CancelToken::default();
        d.prepare(&target, &|_| None, &cancel).unwrap();
        assert_eq!(records.calls.load(Ordering::SeqCst), 1);
        *mode.lock().unwrap() = RuntimeFormat::Blocked;
        assert!(matches!(d.prepare(&target, &|_| None, &cancel), Err(DirectoryError::Unsupported(_))));
        assert_eq!(records.calls.load(Ordering::SeqCst), 1);
    }
}
