use super::*;
use crate::session::testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
use crate::ssh::{
    fake::{default_server_key, FakeEngine, FakeLogin, FakeMethods},
    AuthMethod,
};
use crate::sync::testkit::MemKeychain;

fn run(
    directory: &dyn HostDirectory,
    engine: &dyn SshEngine,
    confirmer: &dyn super::super::connect::HostKeyConfirmer,
    owner: &FakeOwner,
    cancel: &CancelToken,
) -> Result<VerifiedHostKey, String> {
    verify(
        &Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            directory,
            engine,
            confirmer,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
        },
        &HostQuery::Alias("web".into()),
        owner,
        cancel,
    )
}
#[test]
fn unknown_key_needs_exact_human_trust_and_never_prepares_destination_credentials() {
    for auth in [
        AuthMethod::Password,
        AuthMethod::Key {
            key_id: "missing-private-key".into(),
        },
    ] {
        let directory = FakeDirectory::new().with_host("web", auth);
        let engine =
            FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("not-supplied")));
        let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
        let owner = FakeOwner::default();
        let verified = run(
            &directory,
            &engine,
            &confirmer,
            &owner,
            &CancelToken::default(),
        )
        .unwrap();
        assert!(verified.trusted);
        assert_eq!(verified.fingerprint, default_server_key().fingerprint);
        assert_eq!(confirmer.asked().len(), 1);
        assert!(
            owner.asked().is_empty(),
            "no password, private-key unlock or destination login"
        );
        assert!(
            engine.events().is_empty(),
            "no authenticated session, exec or shell"
        );
        assert!(directory.pinned(&HostId::from("id-web")).unwrap().is_some());
        assert!(
            run(
                &directory,
                &engine,
                &FakeConfirmer::default(),
                &owner,
                &CancelToken::default()
            )
            .is_ok(),
            "matching saved key needs no new trust decision"
        );
    }
}
#[test]
fn refusal_wrong_fingerprint_and_cancellation_never_pin_or_retry_forever() {
    for decision in [
        Decision::Refuse,
        Decision::TrustFingerprint("SHA256:wrong".into()),
    ] {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Password);
        let engine = FakeEngine::new();
        let confirmer = FakeConfirmer::deciding(vec![decision]);
        assert!(run(
            &directory,
            &engine,
            &confirmer,
            &FakeOwner::default(),
            &CancelToken::default()
        )
        .is_err());
        assert_eq!(confirmer.asked().len(), 1);
        assert!(directory.pinned(&HostId::from("id-web")).unwrap().is_none());
        assert!(engine.events().is_empty());
    }
    let cancel = CancelToken::default();
    cancel.cancel();
    let directory = FakeDirectory::new().with_host("web", AuthMethod::Password);
    let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
    assert!(run(
        &directory,
        &FakeEngine::new(),
        &confirmer,
        &FakeOwner::default(),
        &cancel
    )
    .is_err());
    assert!(confirmer.asked().is_empty());
}
#[test]
fn a_changed_algorithm_still_requires_the_native_replacement_decision() {
    let old = HostKey::from_openssh_line(crate::sync::slot_rules::test_keys::ECDSA_PUBLIC).unwrap();
    let directory = FakeDirectory::new()
        .with_host("web", AuthMethod::Password)
        .with_pin("web", old.clone());
    let refused = FakeConfirmer::deciding(vec![Decision::Refuse]);
    assert!(run(
        &directory,
        &FakeEngine::new(),
        &refused,
        &FakeOwner::default(),
        &CancelToken::default()
    )
    .is_err());
    assert_eq!(
        directory
            .pinned(&HostId::from("id-web"))
            .unwrap()
            .unwrap()
            .key,
        old
    );
    let trusted = FakeConfirmer::deciding(vec![Decision::Trust]);
    assert!(run(
        &directory,
        &FakeEngine::new(),
        &trusted,
        &FakeOwner::default(),
        &CancelToken::default()
    )
    .is_ok());
    assert_eq!(trusted.asked().len(), 1);
    assert_eq!(
        directory
            .pinned(&HostId::from("id-web"))
            .unwrap()
            .unwrap()
            .key,
        default_server_key()
    );
}
#[test]
fn jump_credentials_are_allowed_but_destination_credentials_are_never_requested() {
    let directory = FakeDirectory::new()
        .with_host("gate", AuthMethod::Password)
        .with_host_via(
            "web",
            AuthMethod::Key {
                key_id: "missing".into(),
            },
            &["gate"],
        )
        .with_pin("gate", default_server_key());
    let engine = FakeEngine::new().with_login_for(
        "gate",
        FakeLogin::Server(FakeMethods::password("gate-password")),
    );
    let owner = FakeOwner::typing(&["gate-password"]);
    assert!(run(
        &directory,
        &engine,
        &FakeConfirmer::deciding(vec![Decision::Trust]),
        &owner,
        &CancelToken::default()
    )
    .is_ok());
    assert_eq!(owner.asked().len(), 1, "only the jump host may need login");
    assert!(owner.questions()[0].contains("gate"));
    assert!(engine.events().is_empty());
}
#[cfg(unix)]
#[test]
fn real_openssh_handshake_verifies_without_any_destination_authentication() {
    use crate::ssh::{
        russh_engine::{EngineOptions, RusshEngine},
        testing::{fixture::Server, harness::tools},
    };
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &["LogLevel DEBUG1"]);
    let directory = FakeDirectory::new().with_hop(server.hop_with(
        "web",
        server.sshd.port,
        AuthMethod::Key {
            key_id: "not-in-vault".into(),
        },
    ));
    let engine = RusshEngine::with_options(EngineOptions {
        worker_threads: 2,
        ..Default::default()
    });
    let owner = FakeOwner::default();
    let verified = run(
        &directory,
        &engine,
        &FakeConfirmer::deciding(vec![Decision::Trust]),
        &owner,
        &CancelToken::default(),
    )
    .unwrap();
    assert_eq!(verified.fingerprint, server.host_key().fingerprint);
    assert!(owner.asked().is_empty());
    let log = server.sshd.log();
    assert!(
        log.contains("Connection from"),
        "the handshake must reach the actual server: {log}"
    );
    assert!(
        !log.contains("Accepted publickey") && !log.contains("Accepted password"),
        "{log}"
    );
    assert!(
        !log.contains("Starting session") && !log.contains("userauth-request"),
        "the server saw only the handshake: {log}"
    );
}

#[test]
fn replacing_the_saved_pin_during_the_final_handshake_cannot_report_trusted() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Replace<'a> {
        directory: &'a FakeDirectory,
        rounds: AtomicUsize,
        inner: FakeEngine,
        replacement: HostKey,
    }
    impl SshEngine for Replace<'_> {
        fn connect(
            &self,
            t: &Target,
            p: &dyn HostKeyPolicy,
            a: &dyn AuthSource,
        ) -> Result<Box<dyn Session>, ConnectError> {
            let result = self.inner.connect(t, p, a);
            if self.rounds.fetch_add(1, Ordering::SeqCst) == 1 {
                self.directory
                    .replace_pin(
                        &HostId::from("id-web"),
                        &default_server_key(),
                        &self.replacement,
                    )
                    .unwrap();
            }
            result
        }
    }
    let directory = FakeDirectory::new().with_host("web", AuthMethod::Password);
    let replacement =
        HostKey::from_openssh_line(crate::sync::slot_rules::test_keys::ECDSA_PUBLIC).unwrap();
    let engine = Replace {
        directory: &directory,
        rounds: AtomicUsize::new(0),
        inner: FakeEngine::new(),
        replacement: replacement.clone(),
    };
    let result = run(
        &directory,
        &engine,
        &FakeConfirmer::deciding(vec![Decision::Trust]),
        &FakeOwner::default(),
        &CancelToken::default(),
    );
    assert!(result.unwrap_err().contains("saved server key changed"));
    assert_eq!(
        directory
            .pinned(&HostId::from("id-web"))
            .unwrap()
            .unwrap()
            .key,
        replacement
    );
    assert_eq!(
        engine.rounds.load(Ordering::SeqCst),
        2,
        "no automatic retry or replacement of the newer pin"
    );
}
