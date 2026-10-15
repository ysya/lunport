//! A broker survives a confirmed cutover; every request uses the current single runtime owner.
use super::directory::{DirectoryError, HostDirectory, PinnedKey};
use super::protocol::HostQuery;
use crate::ssh::{HopRef, HostId, HostKey, Target};
use crate::sync::record_runtime::RuntimeFormat;
use std::sync::Arc;

pub struct FormatDirectory {
    pub lifecycle: Arc<std::sync::Mutex<()>>,
    pub mode: Box<dyn Fn() -> (RuntimeFormat, bool) + Send + Sync>,
    pub legacy: Arc<dyn HostDirectory>,
    pub records: Arc<dyn HostDirectory>,
}
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
            (RuntimeFormat::Records, _) => Ok(self.records.as_ref()),
            (RuntimeFormat::Legacy, false) => Ok(self.legacy.as_ref()),
            _ => Err(DirectoryError::Unsupported(
                "Choose a workspace or resolve the blocked state before connecting.".into(),
            )),
        }
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
        let lifecycle = self.lifecycle.lock().unwrap();
        match (self.mode)() {
            (RuntimeFormat::Records, _) => {
                let records = self.records.clone();
                drop(lifecycle);
                records.pin_confirmed(hop, previous, key, cancel, guard)
            }
            (RuntimeFormat::Legacy, false) => {
                self.legacy
                    .pin_confirmed(hop, previous, key, cancel, &|| Ok(()))
            }
            _ => Err(DirectoryError::Unsupported(
                "The workspace changed before host-key confirmation.".into(),
            )),
        }
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
    }
    fn fixture() -> (FormatDirectory, Arc<Mutex<(RuntimeFormat, bool)>>) {
        let mode = Arc::new(Mutex::new((RuntimeFormat::Legacy, false)));
        let read = mode.clone();
        (
            FormatDirectory {
                lifecycle: Arc::default(),
                mode: Box::new(move || *read.lock().unwrap()),
                legacy: Arc::new(Fake("legacy")),
                records: Arc::new(Fake("records")),
            },
            mode,
        )
    }
    #[test]
    fn an_existing_broker_switches_to_records_without_legacy_fallback() {
        let (d, mode) = fixture();
        let q = HostQuery::Alias("web".into());
        assert_eq!(
            d.resolve(&q).unwrap_err(),
            DirectoryError::NotFound("legacy".into())
        );
        *mode.lock().unwrap() = (RuntimeFormat::Records, false);
        assert_eq!(
            d.resolve(&q).unwrap_err(),
            DirectoryError::NotFound("records".into())
        );
        assert_eq!(d.password_account(&HostId::from("id")), "records:id");
    }
    #[test]
    fn blocked_and_pending_legacy_modes_cannot_resolve_or_read_pins() {
        let (d, mode) = fixture();
        for m in [
            (RuntimeFormat::Blocked, false),
            (RuntimeFormat::Legacy, true),
        ] {
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
        *mode.lock().unwrap() = (RuntimeFormat::Records, false);
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
}
