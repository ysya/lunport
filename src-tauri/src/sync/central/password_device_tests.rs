//! Real native two-device password sync; only disposable credentials and loopback transport.
use super::*;
use crate::sync::{
    central::{automatic, passwords},
    env::Keychain,
    record_import::central_local,
    record_repository as repo,
    records_v3::{HostPayload, HostScope},
    testkit::MemKeychain,
};
const HOST: &str = "000000000000b001";
const SSH_PASSWORD: &str = " synthetic SSH password ∎ with spaces ";
#[inline(never)]
fn device(name: &str) -> Box<TestDevice> {
    let d = Box::new(TestDevice::new(name, &FakeRelay::new(), &TestClock::new()));
    d.keychain
        .windows_credentials
        .store(true, std::sync::atomic::Ordering::SeqCst);
    crate::sync::testkit::private_directory(d.env().state_path.parent().unwrap());
    d
}
fn settle(d: &TestDevice) {
    for step in 0..40 {
        automatic::step(&d.env()).unwrap_or_else(|e| {
            panic!(
                "settle {step} at {} phase {:?}: {e}",
                d.env().state_path.display(),
                record_runtime::snapshot(&d.env())
                    .unwrap()
                    .0
                    .local
                    .central
                    .as_ref()
                    .map(|o| (
                        &o.control.phase,
                        o.can_upload(),
                        o.replacement.is_some(),
                        o.rotation.is_some(),
                        o.observed_epochs.len(),
                        o.epochs.len()
                    ))
            )
        });
        if controller::status(&d.env()).unwrap().can_sync {
            for _ in 0..2 {
                automatic::step(&d.env()).unwrap();
            }
            return;
        }
    }
    panic!("library never became ready");
}
fn save(d: &TestDevice, value: Option<&str>) {
    let (s, g) = record_runtime::snapshot(&d.env()).unwrap();
    let host = repo::get_host(&s, HOST).unwrap();
    let invocation = central_local::invocation(&s).map(|i| i.with_generation(g));
    passwords::change(
        &d.env(),
        HOST,
        &host.revision,
        g,
        invocation.as_ref(),
        value,
    )
    .unwrap();
}
struct NoPrompt<'a>(&'a MemKeychain);
impl Keychain for NoPrompt<'_> {
    fn get(&self, _: &str) -> Result<Option<String>, crate::error::AppError> {
        panic!("background password read prompted")
    }
    fn set(&self, _: &str, _: &str) -> Result<(), crate::error::AppError> {
        panic!("background password write prompted")
    }
    fn delete(&self, _: &str) -> Result<(), crate::error::AppError> {
        panic!("background password deletion prompted")
    }
    fn get_noninteractive(&self, key: &str) -> Result<Option<String>, crate::error::AppError> {
        self.0.get_noninteractive(key)
    }
    fn set_noninteractive(&self, key: &str, value: &str) -> Result<(), crate::error::AppError> {
        self.0.set_noninteractive(key, value)
    }
}
#[test]
fn ssh_password_sync_adopts_local_values_updates_deletes_and_never_restores_stale_os_credentials() {
    let service = Service::automatic();
    super::super::api::with_test_transport(&service.origin, &service.server.url(), || {
        let first = device("password-source");
        let peer = device("password-receiver");
        service.login(&first);
        let payload:HostPayload=serde_json::from_value(json!({"schema":2,"alias":"password-host","hostname":"ssh-password.invalid","user":"fixture","port":22,"auth":"password"})).unwrap();
        crate::sync::record_commands::edit_records(&first.env(), |s, now| {
            repo::create_host(s, HOST, HostScope::Local, payload.clone(), now)
                .map_err(|_| super::super::wire::invalid())
        })
        .unwrap();
        first.keychain.set(&crate::secrets::host_account(HOST),"unbound legacy password").unwrap();
        save(&first, None);
        assert!(passwords::read(&first.env(),HOST).unwrap().is_none());
        assert_eq!(first.keychain.get(&crate::secrets::host_account(HOST)).unwrap().as_deref(),Some("unbound legacy password"));
        save(&first, Some(SSH_PASSWORD));
        assert_eq!(
            passwords::read(&first.env(), HOST)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some(SSH_PASSWORD)
        );
        automatic::start(&first.env()).unwrap();
        automatic::password(&first.env(), "synthetic library unlock password").unwrap();
        settle(&first);
        assert!(service
            .state
            .lock()
            .unwrap()
            .history
            .iter()
            .any(|r| r.envelope.header.kind == "password"));
        service.login(&peer);
        automatic::start(&peer.env()).unwrap();
        automatic::password(&peer.env(), "synthetic library unlock password").unwrap();
        settle(&peer);
        settle(&first);
        assert_eq!(
            passwords::read(&peer.env(), HOST)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some(SSH_PASSWORD)
        );
        let safe = NoPrompt(&peer.keychain);
        let background = crate::sync::env::SyncEnv {
            keychain: &safe,
            ..peer.env()
        };
        assert_eq!(
            passwords::read(
                &crate::sync::env::SyncEnv {
                    keychain: &super::super::credentials::Background(&safe),
                    ..peer.env()
                },
                HOST
            )
            .unwrap()
            .as_deref()
            .map(String::as_str),
            Some(SSH_PASSWORD)
        );
        super::super::round::sync_once(&background).unwrap();
        save(&peer, Some("updated SSH password"));
        settle(&peer);
        settle(&first);
        assert_eq!(
            passwords::read(&first.env(), HOST)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("updated SSH password")
        );
        // A trusted-device edit must not send the old password to a different endpoint or user.
        for field in ["hostname", "user", "port"] {
            let (s, _) = record_runtime::snapshot(&peer.env()).unwrap();
            let host = repo::get_host(&s, HOST).unwrap();
            let original = host.host.payload;
            let mut changed = original.clone();
            match field {
                "hostname" => changed.hostname = "other.invalid".into(),
                "user" => changed.user = "other-user".into(),
                _ => changed.port = 2222,
            };
            crate::sync::record_commands::edit_records(&peer.env(), |s, now| {
                let h = repo::get_host(s, HOST).unwrap();
                repo::update_host(s, HOST, &h.revision, changed.clone(), now)
                    .map_err(|_| super::super::wire::invalid())
            })
            .unwrap();
            assert!(
                passwords::read(&peer.env(), HOST).unwrap().is_none(),
                "{field}"
            );
            crate::sync::record_commands::edit_records(&peer.env(), |s, now| {
                let h = repo::get_host(s, HOST).unwrap();
                repo::update_host(s, HOST, &h.revision, original.clone(), now)
                    .map_err(|_| super::super::wire::invalid())
            })
            .unwrap();
        }
        first
            .keychain
            .set(
                &crate::secrets::host_account(HOST),
                "stale source credential",
            )
            .unwrap();
        peer.keychain
            .set(
                &crate::secrets::host_account(HOST),
                "stale receiver credential",
            )
            .unwrap();
        save(&first, None);
        settle(&first);
        settle(&peer);
        settle(&first);
        assert!(passwords::read(&first.env(), HOST).unwrap().is_none());
        assert!(passwords::read(&peer.env(), HOST).unwrap().is_none());
        for d in [&first, &peer] {
            let s = record_runtime::snapshot(&d.env()).unwrap().0;
            let state_json = serde_json::to_string(&s).unwrap();
            let public =
                serde_json::to_string(&crate::sync::record_commands::overview(&d.env()).unwrap())
                    .unwrap();
            let (export, _, _) =
                crate::sync::records_v3::importer::saved_hosts::export_state(&s).unwrap();
            for text in [state_json.as_str(), public.as_str(), export.as_str()] {
                assert!(!text.contains(SSH_PASSWORD));
                assert!(!text.contains("updated SSH password"));
                assert!(!text.contains("stale source credential"));
            }
        }
        let cloud = serde_json::to_string(&service.state.lock().unwrap().history).unwrap();
        assert!(!cloud.contains(SSH_PASSWORD));
        assert!(!cloud.contains("updated SSH password"));
        controller::sign_out(&peer.env()).unwrap();
        assert!(passwords::read(&peer.env(), HOST).is_err());
    });
}
