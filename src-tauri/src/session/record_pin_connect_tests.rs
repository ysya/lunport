//! The real connection must continue after trust even when a sync round finishes during pinning.
use super::*;
use crate::session::{
    connect::Connector,
    format_directory::FormatDirectory,
    protocol::HostQuery,
    record_directory::{RecordDirectory, RecordSources},
    testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
};
use crate::ssh::{
    russh_engine::{EngineOptions, RusshEngine},
    testing::{fixture::Server, harness::tools},
};
use crate::sync::{
    records_v3::{AuthKind, KeySlotPayload, LocalKeyMetadata},
    slot_rules::test_keys,
    testkit::{HookedConnector, Hooks},
};
use std::{sync::Arc, time::Duration};

const HOST: &str = "0000000000000001";
const KEY: &str = "11111111111111111111111111111111";

#[test]
fn trusting_an_unknown_or_changed_shared_host_connects_to_openssh_despite_background_sync() {
    let Some(tools) = tools() else { return };
    for changed_key in [false, true] {
        let server = Server::start(&tools, &["LogLevel INFO"]);
        let device = record_round::tests::pin_fixture();
        record_runtime::mutate_records(&device.env(), |state| {
            let mut next = state.clone();
            let public = ssh_key::PublicKey::from_openssh(&server.key.public_line).unwrap();
            next.local.keys.insert(
                KEY.into(),
                LocalKeyMetadata {
                    vault_id: KEY.into(),
                    public: KeySlotPayload {
                        schema: 2,
                        name: "loopback".into(),
                        public_key: server.key.public_line.clone(),
                        fingerprint: public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                        key_type: public.algorithm().to_string(),
                        has_passphrase: false,
                        created_at_ms: 1,
                        origin_device_id: next.device_id.clone(),
                    },
                },
            );
            let host = repo::get_host(&next, HOST).unwrap();
            let mut payload = host.host.payload;
            payload.hostname = "127.0.0.1".into();
            payload.port = server.sshd.port;
            payload.user = server.sshd.user.clone();
            payload.auth = AuthKind::Key;
            payload.key_id = Some(KEY.into());
            repo::update_host(&next, HOST, &host.revision, payload, 4).map_err(failed)
        })
        .unwrap();
        if changed_key {
            record_runtime::mutate_records(&device.env(), |state| {
                repo::pin_host_key(
                    state,
                    HOST,
                    &repo::HostEndpoint {
                        hostname: "127.0.0.1".into(),
                        port: server.sshd.port,
                    },
                    None,
                    crate::session::record_directory::stored(
                        &HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap(),
                    ),
                    5,
                )
                .map_err(failed)
                .and_then(|next| crate::session::credential_approval::approve(next, &crate::ssh::HopRef {
                    id: HOST.into(), alias: "web".into(), hostname: "127.0.0.1".into(),
                    port: server.sshd.port, user: server.sshd.user.clone(),
                }, &HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap()).map_err(failed))
            })
            .unwrap();
        }
        let background = device.clone();
        let relay = Arc::new(HookedConnector::new(
            &device.relay,
            Hooks {
                before_pull: Some(Box::new(move || {
                    assert!(background.runtime.lifecycle.try_lock().is_ok());
                    let report = record_round::sync_once(&background.env()).unwrap();
                    assert!(
                        report.pushed > 0,
                        "exercise actual background upload receipts"
                    );
                })),
                ..Default::default()
            },
        ));
        let read = device.clone();
        let pin = device.clone();
        let records = RecordDirectory::new(RecordSources {
            snapshot: Box::new(move || {
                record_runtime::snapshot(&read.env())
                    .map(|(s, _)| s)
                    .map_err(|e| DirectoryError::Failed(e.to_string()))
            }),
            material: Box::new(|_| Ok(true)),
            username: Box::new(|| panic!("use the explicitly saved login")),
            pin: Box::new(|_, _, _, _| panic!("use confirmed pin persistence")),
        })
        .with_confirmed_pin(Box::new(move |hop, previous, key, cancel, guard| {
            let mut env = pin.env();
            env.relays = relay.as_ref();
            super::confirm(&env, hop, previous, key, env.keychain, cancel, guard)
                .map_err(|e| DirectoryError::Failed(e.to_string()))
        }));
        let mode = device.clone();
        let directory = FormatDirectory {
            lifecycle: device.runtime.lifecycle.clone(),
            mode: Box::new(move || {
                let core = mode.runtime.core.lock().unwrap();
                (core.format, core.legacy_paused)
            }),
            legacy: Arc::new(FakeDirectory::new()),
            records: Arc::new(records),
        };
        let engine = RusshEngine::with_options(EngineOptions {
            worker_threads: 2,
            ..Default::default()
        });
        let keys = FakeKeys::new().with_key(KEY, "loopback", &server.key.private_text);
        let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &directory,
            keys: &keys,
            keychain: &device.keychain,
            confirmer: &confirmer,
        };
        let owner = FakeOwner::default();
        for _ in 0..2 {
            let connected = connector
                .connect(&HostQuery::Id(HOST.into()), &owner, &CancelToken::default())
                .unwrap();
            let result = connected
                .session
                .exec("printf sync-pin-ok", Duration::from_secs(10), 1024)
                .unwrap();
            assert_eq!(result.stdout, b"sync-pin-ok");
            connected.session.close();
        }
        assert_eq!(
            confirmer.asked().len(),
            1,
            "trust once; matching pin reconnects without prompting"
        );
        assert_eq!(confirmer.asked()[0].changed.is_some(), changed_key);
        assert_eq!(
            owner.notices.lock().unwrap().as_slice(),
            ["Waiting for you to confirm web's host key in Lunport."]
        );
        let current = record_runtime::snapshot(&device.env()).unwrap().0;
        assert_eq!(
            repo::get_host(&current, HOST)
                .unwrap()
                .host
                .payload
                .host_key
                .unwrap()
                .fingerprint,
            server.host_key().fingerprint
        );
        assert!(
            server.sshd.log().contains("Accepted publickey"),
            "the actual destination accepted login"
        );
    }
}
