use super::*;
use crate::session::auth::KeyStore;
use crate::sync::slot_rules::test_keys::PLAIN_PUBLIC;
#[cfg(unix)]
mod shell {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        process::{Command, Output},
        time::{Duration, Instant},
    };
    fn run(home: &tempfile::TempDir, public: &str) -> Output {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script(public).unwrap())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", home.path())
            .output()
            .unwrap()
    }
    fn setup(bytes: &[u8]) -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join(".ssh")).unwrap();
        fs::write(home.path().join(".ssh/authorized_keys"), bytes).unwrap();
        home
    }
    #[test]
    fn preserves_unterminated_content_and_second_invocation_is_noop() {
        let home = setup(b"# sentinel without newline");
        let output = run(&home, PLAIN_PUBLIC);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"SSHELTER_ADDED\n");
        let path = home.path().join(".ssh/authorized_keys");
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            bytes,
            format!("# sentinel without newline\n{PLAIN_PUBLIC}\n").as_bytes()
        );
        let again = run(&home, PLAIN_PUBLIC);
        assert!(again.status.success());
        assert_eq!(again.stdout, b"SSHELTER_PRESENT\n");
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    #[test]
    fn preserves_plain_and_restricted_duplicate_without_unrestricted_append() {
        for line in [
            format!("{PLAIN_PUBLIC} existing comment\n"),
            format!("restrict,command=\"echo hello world\" {PLAIN_PUBLIC} restricted\n"),
        ] {
            let home = setup(line.as_bytes());
            let output = run(&home, PLAIN_PUBLIC);
            assert!(output.status.success());
            assert_eq!(output.stdout, b"SSHELTER_PRESENT\n");
            assert_eq!(
                fs::read(home.path().join(".ssh/authorized_keys")).unwrap(),
                line.as_bytes()
            );
        }
    }
    fn crlf_duplicate(prefix: &str, comment: &str) {
        let original = format!("# original sentinel\r\n{prefix}{PLAIN_PUBLIC}{comment}\r\n");
        let home = setup(original.as_bytes());
        let output = run(&home, PLAIN_PUBLIC);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"SSHELTER_PRESENT\n");
        assert_eq!(
            fs::read(home.path().join(".ssh/authorized_keys")).unwrap(),
            original.as_bytes(),
            "CRLF matching must not rewrite original bytes or add an unrestricted duplicate"
        );
    }
    #[test]
    fn crlf_plain_without_comment_preserves_bytes() {
        crlf_duplicate("", "");
    }
    #[test]
    fn crlf_plain_with_comment_preserves_bytes() {
        crlf_duplicate("", " existing comment");
    }
    #[test]
    fn crlf_restricted_without_comment_preserves_bytes() {
        crlf_duplicate("restrict,from=\"192.0.2.0/24\" ", "");
    }
    #[test]
    fn crlf_restricted_with_comment_preserves_bytes() {
        crlf_duplicate("restrict,from=\"192.0.2.0/24\" ", " existing comment");
    }
    #[test]
    fn comment_and_quoted_command_do_not_count_as_authorized_identity() {
        for line in [
            format!("# {PLAIN_PUBLIC}\n"),
            format!(
                "command=\"echo {PLAIN_PUBLIC}\" {}\n",
                crate::sync::slot_rules::test_keys::ENC_PUBLIC
            ),
        ] {
            let home = setup(line.as_bytes());
            let output = run(&home, PLAIN_PUBLIC);
            assert!(output.status.success());
            assert_eq!(output.stdout, b"SSHELTER_ADDED\n");
            let bytes = fs::read_to_string(home.path().join(".ssh/authorized_keys")).unwrap();
            assert!(bytes.starts_with(&line));
            assert!(bytes.ends_with(&format!("{PLAIN_PUBLIC}\n")));
        }
    }
    #[test]
    fn refuses_existing_and_dangling_symlinks_and_non_file_paths() {
        for leaf in [".ssh", ".ssh/authorized_keys"] {
            for dangling in [false, true] {
                let home = tempfile::tempdir().unwrap();
                let outside = tempfile::tempdir().unwrap();
                let target = outside.path().join("target");
                if !dangling {
                    if leaf == ".ssh" {
                        fs::create_dir(&target).unwrap();
                        fs::write(target.join("authorized_keys"), b"outside").unwrap();
                    } else {
                        fs::write(&target, b"outside").unwrap();
                    }
                }
                if leaf != ".ssh" {
                    fs::create_dir(home.path().join(".ssh")).unwrap();
                }
                symlink(&target, home.path().join(leaf)).unwrap();
                assert!(!run(&home, PLAIN_PUBLIC).status.success());
                if !dangling {
                    assert_eq!(
                        fs::read(if leaf == ".ssh" {
                            target.join("authorized_keys")
                        } else {
                            target
                        })
                        .unwrap(),
                        b"outside"
                    );
                } else {
                    assert!(!target.exists());
                }
            }
        }
        let home = setup(b"sentinel");
        fs::remove_file(home.path().join(".ssh/authorized_keys")).unwrap();
        fs::create_dir(home.path().join(".ssh/authorized_keys")).unwrap();
        assert!(!run(&home, PLAIN_PUBLIC).status.success());
        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join(".ssh"), b"sentinel").unwrap();
        assert!(!run(&home, PLAIN_PUBLIC).status.success());
        assert_eq!(fs::read(home.path().join(".ssh")).unwrap(), b"sentinel");
    }
    #[test]
    fn creates_secure_permissions_and_bounded_lock_does_not_touch_file() {
        let home = tempfile::tempdir().unwrap();
        assert!(run(&home, PLAIN_PUBLIC).status.success());
        for (p, mode) in [(".ssh", 0o700), (".ssh/authorized_keys", 0o600)] {
            assert_eq!(
                fs::metadata(home.path().join(p))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
        }
        fs::create_dir(home.path().join(".ssh/.sshelter-deploy-lock")).unwrap();
        let before = fs::read(home.path().join(".ssh/authorized_keys")).unwrap();
        let start = Instant::now();
        let output = run(&home, PLAIN_PUBLIC);
        assert!(!output.status.success());
        assert!(start.elapsed() < Duration::from_secs(8));
        assert_eq!(
            fs::read(home.path().join(".ssh/authorized_keys")).unwrap(),
            before
        );
    }
    #[test]
    fn command_contains_canonical_public_identity_only() {
        let command = script(&format!(
            "{PLAIN_PUBLIC} comment-$(touch pwned)' secret-marker"
        ))
        .unwrap();
        assert!(!command.contains("secret-marker"));
        assert!(!command.contains("touch pwned"));
        let home = tempfile::tempdir().unwrap();
        assert!(run(&home, &format!("{PLAIN_PUBLIC} ignored"))
            .status
            .success());
        assert_eq!(
            fs::read_to_string(home.path().join(".ssh/authorized_keys")).unwrap(),
            format!("{PLAIN_PUBLIC}\n")
        );
        assert!(script("not-a-public-key").is_err());
    }
}

use crate::{
    session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
    ssh::{
        fake::{default_server_key, FakeEngine, FakeEvent},
        AuthMethod,
    },
    sync::testkit::MemKeychain,
};
fn result(ended: Ended, exit_code: Option<u32>, output: &[u8]) -> ExecResult {
    ExecResult {
        ended,
        exit_code,
        signal: None,
        stdout: output.to_vec(),
        stderr: vec![],
        truncated: false,
    }
}
#[test]
fn only_known_successful_untruncated_exit_is_installation_success() {
    assert_eq!(
        classify(&result(Ended::Exited, Some(0), b"SSHELTER_ADDED\n")),
        Outcome::Added
    );
    assert_eq!(
        classify(&result(Ended::Exited, Some(0), b"SSHELTER_PRESENT\n")),
        Outcome::AlreadyPresent
    );
    for (end, code) in [
        (Ended::Exited, None),
        (Ended::Disconnected, Some(0)),
        (Ended::Signaled, Some(0)),
        (Ended::Truncated, Some(0)),
    ] {
        assert_eq!(
            classify(&result(end, code, b"SSHELTER_ADDED\n")),
            Outcome::Unknown
        );
    }
    assert_eq!(
        classify(&result(Ended::TimedOut, Some(0), b"SSHELTER_ADDED\n")),
        Outcome::TimedOut
    );
    assert_eq!(
        classify(&result(Ended::Exited, Some(0), b"unexpected")),
        Outcome::Unknown
    );
    assert_eq!(
        classify(&result(Ended::Exited, Some(69), b"")),
        Outcome::UnsupportedShell
    );
    assert_eq!(
        classify(&result(Ended::Exited, Some(70), b"")),
        Outcome::RemoteFailed
    );
    let mut truncated = result(Ended::Exited, Some(0), b"SSHELTER_ADDED\n");
    truncated.truncated = true;
    assert_eq!(classify(&truncated), Outcome::Unknown);
}
#[test]
fn public_preview_then_explicit_confirmation_executes_independent_of_mcp_grants() {
    // No MCP runtime, policy, allowlist, or adapter is involved in this human path.
    let e = FakeEngine::new().with_exec(
        &script(PLAIN_PUBLIC).unwrap(),
        result(Ended::Exited, Some(0), b"SSHELTER_ADDED\n"),
    );
    let d = FakeDirectory::new()
        .with_host(
            "web",
            AuthMethod::Key {
                key_id: "k-plain".into(),
            },
        )
        .with_pin("web", default_server_key());
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &FakeKeys::new(),
        keychain: &MemKeychain::default(),
        confirmer: &FakeConfirmer::default(),
    };
    let runtime = Deployments::default();
    let preview = runtime.preview(&c, "id-web", "k-plain").unwrap();
    assert!(e.events().is_empty());
    assert_eq!(preview.public_key, PLAIN_PUBLIC);
    assert_eq!(preview.route.len(), 1);
    let (review, cancel) = runtime.take(&preview.id, true).unwrap();
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(())).outcome,
        Outcome::Added
    );
    assert!(e
        .events()
        .iter()
        .any(|event| matches!(event, FakeEvent::Exec { .. })));
    assert!(
        runtime.take(&preview.id, true).is_err(),
        "confirmation cannot replay an installation"
    );
}
#[test]
fn cancellation_denial_missing_metadata_and_expired_preview_never_execute() {
    let e = FakeEngine::new();
    let d = FakeDirectory::new()
        .with_host("web", AuthMethod::Password)
        .with_pin("web", default_server_key());
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &FakeKeys::new(),
        keychain: &MemKeychain::default(),
        confirmer: &FakeConfirmer::default(),
    };
    let r = Deployments::default();
    assert!(r.preview(&c, "id-web", "missing").is_err());
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    assert!(matches!(r.take(&p.id, false), Err(Outcome::Denied)));
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    r.cancel(&p.id);
    assert!(matches!(r.take(&p.id, true), Err(Outcome::Canceled)));
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    r.pending.lock().unwrap().get_mut(&p.id).unwrap().deadline =
        InteractionDeadline::after(Duration::ZERO);
    assert!(matches!(r.take(&p.id, true), Err(Outcome::StalePreview)));
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    r.cancel(&p.id);
    assert!(cancel.is_cancelled());
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(())).outcome,
        Outcome::Canceled
    );
    assert!(e.events().is_empty());
}
#[test]
fn same_id_public_identity_change_and_current_workspace_change_reject_before_connect() {
    struct Keys {
        key: Mutex<super::super::auth::VaultKey>,
        fake: FakeKeys,
    }
    impl KeyStore for Keys {
        fn key(&self, _: &str) -> Option<super::super::auth::VaultKey> {
            Some(self.key.lock().unwrap().clone())
        }
        fn private_text(&self, id: &str) -> Result<Option<zeroize::Zeroizing<String>>, String> {
            self.fake.private_text(id)
        }
    }
    let fake = FakeKeys::new();
    let keys = Keys {
        key: Mutex::new(fake.key("k-plain").unwrap()),
        fake,
    };
    let e = FakeEngine::new();
    let d = FakeDirectory::new()
        .with_host(
            "web",
            AuthMethod::Key {
                key_id: "k-plain".into(),
            },
        )
        .with_pin("web", default_server_key());
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &keys,
        keychain: &MemKeychain::default(),
        confirmer: &FakeConfirmer::default(),
    };
    let r = Deployments::default();
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    keys.key.lock().unwrap().public_key = crate::sync::slot_rules::test_keys::ECDSA_PUBLIC.into();
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(())).outcome,
        Outcome::StalePreview
    );
    assert!(e.events().is_empty());
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Err(
            "workspace changed".into()
        ))
        .outcome,
        Outcome::StalePreview
    );
    assert!(e.events().is_empty());
}
#[test]
fn broker_tracks_deployment_cancels_it_on_quit_and_rejects_later_requests() {
    use std::sync::Arc;
    let broker = super::super::broker::Broker::new(
        Arc::new(FakeEngine::new()),
        Arc::new(FakeDirectory::new()),
        Arc::new(FakeKeys::new()),
        Arc::new(MemKeychain::default()),
        Arc::new(FakeConfirmer::default()),
    );
    let cancel = CancelToken::default();
    let registration = broker.register_deployment(cancel.clone()).unwrap();
    assert!(broker.has_sessions());
    broker.end_all(Duration::ZERO);
    assert!(cancel.is_cancelled());
    assert!(
        broker.has_sessions(),
        "quitting must retain registration until worker cleanup"
    );
    drop(registration);
    assert!(!broker.has_sessions());
    assert!(broker.register_deployment(CancelToken::default()).is_err());
}
#[test]
fn completed_exec_with_failed_audit_keeps_outcome_warns_and_never_retries() {
    let home = tempfile::tempdir().unwrap();
    let runtime = crate::mcp::deployment_audit_tests::with_path(
        home.path().join("missing/session-log.jsonl"),
    );
    // A regular file as parent deterministically prevents log publication, even as an administrator.
    std::fs::write(home.path().join("missing"), b"sentinel").unwrap();
    let e = FakeEngine::new().with_exec(
        &script(PLAIN_PUBLIC).unwrap(),
        result(Ended::Exited, Some(0), b"SSHELTER_ADDED\n"),
    );
    let d = FakeDirectory::new()
        .with_host(
            "web",
            AuthMethod::Key {
                key_id: "k-plain".into(),
            },
        )
        .with_pin("web", default_server_key());
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &FakeKeys::new(),
        keychain: &MemKeychain::default(),
        confirmer: &FakeConfirmer::default(),
    };
    let requests = Deployments::default();
    let p = requests.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = requests.take(&p.id, true).unwrap();
    let result = execute_recorded(
        &review,
        &c,
        &FakeOwner::default(),
        &cancel,
        &|| Ok(()),
        &runtime,
    );
    assert_eq!(result.outcome, Outcome::Added);
    assert!(result.audit_error.is_some());
    assert_eq!(
        e.events()
            .iter()
            .filter(|e| matches!(e, FakeEvent::Exec { .. }))
            .count(),
        1
    );
    let entries = crate::mcp::deployment_audit_tests::entries(&runtime);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].client, "deploy");
    assert_eq!(entries[0].outcome, "added");
    assert!(entries[0].detail.is_none());
    assert!(entries[0].command.starts_with("Deploy public key SHA256:"));
    assert!(!entries[0].command.contains("SSHELTER_ADDED"));
}
#[test]
fn authentication_abandonment_timeout_and_host_key_refusal_are_distinct() {
    use crate::session::{auth::Reply, testing::Decision};
    for (reply, outcome) in [
        (Reply::Cancelled, Outcome::AuthAbandoned),
        (Reply::TimedOut, Outcome::TimedOut),
    ] {
        let e = FakeEngine::new();
        let d = FakeDirectory::new()
            .with_host("web", AuthMethod::Password)
            .with_pin("web", default_server_key());
        let c = Connector {
            engine: &e,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let r = Deployments::default();
        let p = r.preview(&c, "id-web", "k-plain").unwrap();
        let (review, cancel) = r.take(&p.id, true).unwrap();
        assert_eq!(
            execute(
                &review,
                &c,
                &FakeOwner::answering(vec![reply]),
                &cancel,
                &|| Ok(())
            )
            .outcome,
            outcome
        );
        assert!(!e
            .events()
            .iter()
            .any(|e| matches!(e, FakeEvent::Exec { .. })));
    }
    let e = FakeEngine::new();
    let d = FakeDirectory::new().with_host(
        "web",
        AuthMethod::Key {
            key_id: "k-plain".into(),
        },
    );
    let confirmer = FakeConfirmer::deciding(vec![Decision::Refuse]);
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &FakeKeys::new(),
        keychain: &MemKeychain::default(),
        confirmer: &confirmer,
    };
    let r = Deployments::default();
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(())).outcome,
        Outcome::HostKeyRefused
    );
    assert!(!e
        .events()
        .iter()
        .any(|e| matches!(e, FakeEvent::Exec { .. })));
}

#[test]
fn inherited_group_endpoint_changes_invalidate_preview_without_host_revision_changes() {
    use crate::session::{
        directory::DirectoryError,
        record_directory::{RecordDirectory, RecordSources},
    };
    use crate::sync::{record_groups, record_repository as repo, records_v3::*};
    let state = SyncStateV3 {
        version: 3,
        device_id: "a".repeat(32),
        device_name: "fixture".into(),
        relay_url: "http://127.0.0.1:8787".into(),
        account: None,
        spaces: Default::default(),
        local: Default::default(),
        rotation: None,
        relay_features: None,
        legacy_v1_backup: None,
        phrase_cleanup_pending: false,
        migration_gate: None,
        shared_writes_blocked: false,
        pending_account: None,
        notices: vec![],
        last_sync_ms: None,
        last_error: None,
    };
    let group = serde_json::from_value(
        serde_json::json!({"schema":1,"name":"Ops","defaults":{"port":2222,"user":"ops"}}),
    )
    .unwrap();
    let state =
        record_groups::create_group(&state, "0000000000000031", HostScope::Local, group, true, 1)
            .unwrap();
    let payload = HostPayload {
        schema: 3,
        group_id: Some("0000000000000031".into()),
        inherit: vec![InheritedField::Port, InheritedField::User],
        alias: "web".into(),
        hostname: "web.example".into(),
        port: 22,
        user: "fallback".into(),
        auth: AuthKind::Password,
        key_id: None,
        jump: vec![],
        keepalive_secs: 30,
        keepalive_max_missed: 3,
        connect_timeout_secs: 15,
        host_key: None,
        tags: vec![],
        notes: String::new(),
        imported: None,
    };
    let state =
        repo::create_host(&state, "0000000000000001", HostScope::Local, payload, 2).unwrap();
    let state = Arc::new(Mutex::new(state));
    let read = state.clone();
    let d = RecordDirectory::new(RecordSources {
        snapshot: Box::new(move || Ok(read.lock().unwrap().clone())),
        material: Box::new(|_| {
            panic!("public deployment resolution must not pre-read private material")
        }),
        username: Box::new(|| Ok("fixture".into())),
        pin: Box::new(|_, _, _, _| {
            Err(DirectoryError::Failed("must not pin stale preview".into()))
        }),
    });
    let e = FakeEngine::new();
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &FakeKeys::new(),
        keychain: &MemKeychain::default(),
        confirmer: &FakeConfirmer::default(),
    };
    let r = Deployments::default();
    let p = r.preview(&c, "0000000000000001", "k-plain").unwrap();
    assert_eq!(p.port, 2222);
    assert_eq!(p.user, "ops");
    let (review, cancel) = r.take(&p.id, true).unwrap();
    let mut s = state.lock().unwrap();
    let revision = repo::get_host(&s, "0000000000000001").unwrap().revision;
    let group = record_groups::list_groups(&s).unwrap().remove(0);
    let mut payload = group.group.payload;
    payload.defaults.port = Some(2223);
    *s = record_groups::update_group(&s, &group.group.id, &group.revision, payload, 3).unwrap();
    assert_eq!(
        repo::get_host(&s, "0000000000000001").unwrap().revision,
        revision
    );
    drop(s);
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(())).outcome,
        Outcome::StalePreview
    );
    assert!(e.events().is_empty());
}

#[derive(Clone)]
struct WaitingSession {
    entered: Arc<std::sync::atomic::AtomicBool>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}
impl crate::ssh::SshEngine for WaitingSession {
    fn connect(
        &self,
        _: &crate::ssh::Target,
        _: &dyn crate::ssh::HostKeyPolicy,
        _: &dyn crate::ssh::AuthSource,
    ) -> Result<Box<dyn crate::ssh::Session>, crate::ssh::ConnectError> {
        Ok(Box::new(self.clone()))
    }
}
impl crate::ssh::Session for WaitingSession {
    fn shell(
        &self,
        _: crate::ssh::Pty,
    ) -> Result<Box<dyn crate::ssh::ShellChannel>, crate::ssh::SessionError> {
        panic!("deployment must not allocate a PTY")
    }
    fn exec(
        &self,
        _: &str,
        timeout: Duration,
        cap: usize,
    ) -> Result<ExecResult, crate::ssh::SessionError> {
        assert_eq!(timeout, Duration::from_secs(60));
        assert_eq!(cap, 8192);
        self.entered.store(true, Ordering::SeqCst);
        let end = std::time::Instant::now() + Duration::from_secs(3);
        while !self.closed.load(Ordering::SeqCst) {
            assert!(std::time::Instant::now() < end);
            std::thread::sleep(Duration::from_millis(2));
        }
        Err(crate::ssh::SessionError::Closed)
    }
    fn is_alive(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }
    fn disconnect_reason(&self) -> Option<crate::ssh::DisconnectReason> {
        None
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}
#[test]
fn ui_cancel_and_quit_close_actual_exec_and_drain_broker_registration() {
    for quit in [false, true] {
        let e = WaitingSession {
            entered: Arc::default(),
            closed: Arc::default(),
        };
        let broker = super::super::broker::Broker::new(
            Arc::new(e.clone()),
            Arc::new(
                FakeDirectory::new()
                    .with_host(
                        "web",
                        AuthMethod::Key {
                            key_id: "k-plain".into(),
                        },
                    )
                    .with_pin("web", default_server_key()),
            ),
            Arc::new(FakeKeys::new()),
            Arc::new(MemKeychain::default()),
            Arc::new(FakeConfirmer::default()),
        );
        let r = Deployments::default();
        let c = broker.connector();
        let p = r.preview(&c, "id-web", "k-plain").unwrap();
        let (review, cancel) = r.take(&p.id, true).unwrap();
        std::thread::scope(|scope| {
            let registration = broker.register_deployment(cancel.clone()).unwrap();
            let worker = scope.spawn(|| {
                let _registration = registration;
                execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(()))
            });
            crate::ssh::testing::eventually("deployment exec entered", 3, || {
                e.entered.load(Ordering::SeqCst)
            });
            assert!(broker.has_sessions());
            if quit {
                broker.end_all(Duration::from_secs(3));
            } else {
                r.cancel(&p.id);
            }
            assert_eq!(worker.join().unwrap().outcome, Outcome::Canceled);
        });
        assert!(e.closed.load(Ordering::SeqCst));
        assert!(!broker.has_sessions());
    }
}
#[test]
fn public_resolution_and_private_authentication_leave_lifecycle_available() {
    use crate::session::{
        directory::{DirectoryError, HostDirectory, PinnedKey},
        format_directory::FormatDirectory,
    };
    struct PublicOnly(FakeDirectory);
    impl HostDirectory for PublicOnly {
        fn password_account(&self, id: &crate::ssh::HostId) -> String {
            self.0.password_account(id)
        }
        fn resolve(&self, _: &HostQuery) -> Result<crate::ssh::Target, DirectoryError> {
            panic!("material preflight must be bypassed")
        }
        fn resolve_public(&self, q: &HostQuery) -> Result<crate::ssh::Target, DirectoryError> {
            self.0.resolve(q)
        }
        fn pinned(&self, id: &crate::ssh::HostId) -> Result<Option<PinnedKey>, DirectoryError> {
            self.0.pinned(id)
        }
        fn pin(
            &self,
            id: &crate::ssh::HostId,
            k: &crate::ssh::HostKey,
        ) -> Result<(), DirectoryError> {
            self.0.pin(id, k)
        }
        fn replace_pin(
            &self,
            id: &crate::ssh::HostId,
            p: &crate::ssh::HostKey,
            k: &crate::ssh::HostKey,
        ) -> Result<(), DirectoryError> {
            self.0.replace_pin(id, p, k)
        }
    }
    struct Keys {
        lifecycle: Arc<Mutex<()>>,
        fake: FakeKeys,
    }
    impl KeyStore for Keys {
        fn key(&self, id: &str) -> Option<super::super::auth::VaultKey> {
            self.fake.key(id)
        }
        fn private_text(&self, id: &str) -> Result<Option<zeroize::Zeroizing<String>>, String> {
            assert!(
                self.lifecycle.try_lock().is_ok(),
                "private material/credential wait must not own lifecycle"
            );
            self.fake.private_text(id)
        }
    }
    let lifecycle = Arc::new(Mutex::new(()));
    let keys = Keys {
        lifecycle: lifecycle.clone(),
        fake: FakeKeys::new(),
    };
    let directory = FormatDirectory {
        lifecycle,
        mode: Box::new(|| (crate::sync::record_runtime::RuntimeFormat::Records, false)),
        legacy: Arc::new(FakeDirectory::new()),
        records: Arc::new(PublicOnly(
            FakeDirectory::new()
                .with_host(
                    "web",
                    AuthMethod::Key {
                        key_id: "k-plain".into(),
                    },
                )
                .with_pin("web", default_server_key()),
        )),
    };
    let e = FakeEngine::new().with_exec(
        &script(PLAIN_PUBLIC).unwrap(),
        result(Ended::Exited, Some(0), b"SSHELTER_ADDED\n"),
    );
    let c = Connector {
        engine: &e,
        directory: &directory,
        keys: &keys,
        keychain: &MemKeychain::default(),
        confirmer: &FakeConfirmer::default(),
    };
    let r = Deployments::default();
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(())).outcome,
        Outcome::Added
    );
}
#[test]
fn selected_key_change_during_host_key_question_prevents_pin_and_exec() {
    use crate::session::{
        auth::VaultKey,
        connect::{HostKeyConfirmer, HostKeyQuestion},
        directory::HostDirectory,
    };
    struct Keys {
        public: Arc<Mutex<String>>,
        fake: FakeKeys,
    }
    impl KeyStore for Keys {
        fn key(&self, id: &str) -> Option<VaultKey> {
            let mut key = self.fake.key(id)?;
            if id == "k-enc" {
                key.public_key = self.public.lock().unwrap().clone();
            }
            Some(key)
        }
        fn private_text(&self, id: &str) -> Result<Option<zeroize::Zeroizing<String>>, String> {
            self.fake.private_text(id)
        }
    }
    struct Change(Arc<Mutex<String>>);
    impl HostKeyConfirmer for Change {
        fn confirm(&self, q: &HostKeyQuestion, _: &CancelToken) -> Option<String> {
            *self.0.lock().unwrap() = crate::sync::slot_rules::test_keys::ECDSA_PUBLIC.into();
            Some(q.fingerprint.clone())
        }
    }
    let public = Arc::new(Mutex::new(
        crate::sync::slot_rules::test_keys::ENC_PUBLIC.into(),
    ));
    let keys = Keys {
        public: public.clone(),
        fake: FakeKeys::new(),
    };
    let e = FakeEngine::new();
    let d = FakeDirectory::new().with_host(
        "web",
        AuthMethod::Key {
            key_id: "k-plain".into(),
        },
    );
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &keys,
        keychain: &MemKeychain::default(),
        confirmer: &Change(public),
    };
    let r = Deployments::default();
    let p = r.preview(&c, "id-web", "k-enc").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(())).outcome,
        Outcome::StalePreview
    );
    assert!(d
        .pinned(&crate::ssh::HostId::from("id-web"))
        .unwrap()
        .is_none());
    assert!(!e
        .events()
        .iter()
        .any(|e| matches!(e, FakeEvent::Exec { .. })));
}
#[test]
fn change_during_connect_closes_session_before_exec() {
    use crate::ssh::{AuthSource, ConnectError, HostKeyPolicy, Session, SshEngine, Target};
    struct Change {
        session: WaitingSession,
        current: std::sync::atomic::AtomicBool,
    }
    impl SshEngine for Change {
        fn connect(
            &self,
            _: &Target,
            _: &dyn HostKeyPolicy,
            _: &dyn AuthSource,
        ) -> Result<Box<dyn Session>, ConnectError> {
            self.current.store(false, Ordering::SeqCst);
            Ok(Box::new(self.session.clone()))
        }
    }
    let e = Change {
        session: WaitingSession {
            entered: Arc::default(),
            closed: Arc::default(),
        },
        current: std::sync::atomic::AtomicBool::new(true),
    };
    let d = FakeDirectory::new()
        .with_host(
            "web",
            AuthMethod::Key {
                key_id: "k-plain".into(),
            },
        )
        .with_pin("web", default_server_key());
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &FakeKeys::new(),
        keychain: &MemKeychain::default(),
        confirmer: &FakeConfirmer::default(),
    };
    let r = Deployments::default();
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    assert_eq!(
        execute(
            &review,
            &c,
            &FakeOwner::default(),
            &cancel,
            &|| if e.current.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err("changed".into())
            }
        )
        .outcome,
        Outcome::StalePreview
    );
    assert!(e.session.closed.load(Ordering::SeqCst));
    assert!(!e.session.entered.load(Ordering::SeqCst));
}
#[test]
fn quit_during_native_auth_question_cancels_question_and_drains() {
    use crate::session::auth_window::{AuthHub, AuthRequest, AuthSurface, NativeOwner};
    struct Surface;
    impl AuthSurface for Surface {
        fn changed(&self, _: &[AuthRequest]) {}
    }
    let e = Arc::new(FakeEngine::new());
    let broker = super::super::broker::Broker::new(
        e.clone(),
        Arc::new(
            FakeDirectory::new()
                .with_host("web", AuthMethod::Password)
                .with_pin("web", default_server_key()),
        ),
        Arc::new(FakeKeys::new()),
        Arc::new(MemKeychain::default()),
        Arc::new(FakeConfirmer::default()),
    );
    let c = broker.connector();
    let r = Deployments::default();
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    let hub = Arc::new(AuthHub::default());
    let owner = NativeOwner {
        hub: hub.clone(),
        surface: Arc::new(Surface),
        request_id: p.id,
        cancel: cancel.clone(),
    };
    std::thread::scope(|scope| {
        let registration = broker.register_deployment(cancel.clone()).unwrap();
        let worker = scope.spawn(|| {
            let _registration = registration;
            execute(&review, &c, &owner, &cancel, &|| Ok(()))
        });
        crate::ssh::testing::eventually("native auth question", 3, || !hub.pending().is_empty());
        assert!(broker.has_sessions());
        broker.end_all(Duration::from_secs(3));
        assert_eq!(worker.join().unwrap().outcome, Outcome::Canceled);
    });
    assert!(hub.pending().is_empty());
    assert!(!broker.has_sessions());
    assert!(!e
        .events()
        .iter()
        .any(|e| matches!(e, FakeEvent::Exec { .. })));
}
#[test]
fn connection_timeout_has_a_distinct_timeout_outcome_without_exec() {
    use crate::session::directory::HostDirectory;
    let d = FakeDirectory::new()
        .with_host(
            "web",
            AuthMethod::Key {
                key_id: "k-plain".into(),
            },
        )
        .with_pin("web", default_server_key());
    let hop = d
        .resolve_public(&HostQuery::Id("id-web".into()))
        .unwrap()
        .hops[0]
        .reference();
    let e = FakeEngine::new().failing_with(crate::ssh::ConnectError::Timeout {
        hop,
        phase: crate::ssh::Phase::Handshake,
    });
    let c = Connector {
        engine: &e,
        directory: &d,
        keys: &FakeKeys::new(),
        keychain: &MemKeychain::default(),
        confirmer: &FakeConfirmer::default(),
    };
    let r = Deployments::default();
    let p = r.preview(&c, "id-web", "k-plain").unwrap();
    let (review, cancel) = r.take(&p.id, true).unwrap();
    assert_eq!(
        execute(&review, &c, &FakeOwner::default(), &cancel, &|| Ok(())).outcome,
        Outcome::TimedOut
    );
    assert!(!e
        .events()
        .iter()
        .any(|e| matches!(e, FakeEvent::Exec { .. })));
}

#[test]
fn deployment_aba_resolve_cannot_connect_or_execute_on_unreviewed_target() {
    use crate::mcp::records::target_binding_tests::{AbaDirectory, RecordingEngine};
    use crate::session::directory::HostDirectory;
    for directory in [AbaDirectory::new(), AbaDirectory::auth_drift()] {
        let engine = RecordingEngine::new(FakeEngine::new().with_exec(
            &script(PLAIN_PUBLIC).unwrap(),
            result(Ended::Exited, Some(0), b"SSHELTER_ADDED\n"),
        ));
        let connector = Connector {
            engine: &engine,
            directory: &directory,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let requests = Deployments::default();
        let preview = requests.preview(&connector, "id-web", "k-plain").unwrap();
        assert_eq!(preview.hostname, "reviewed.example");
        let (review, cancel) = requests.take(&preview.id, true).unwrap();
        let result = execute(&review, &connector, &FakeOwner::default(), &cancel, &|| {
            Ok(())
        });
        assert!(directory.returned_b());
        assert_eq!(
            directory
                .resolve_public(&HostQuery::Id("id-web".into()))
                .unwrap()
                .hops[0]
                .hostname,
            "reviewed.example"
        );
        assert!(
            engine.targets.lock().unwrap().is_empty(),
            "unreviewed B must not reach the inner engine: {:?}",
            engine.targets.lock().unwrap()
        );
        assert!(!engine
            .inner
            .events()
            .iter()
            .any(|event| matches!(event, FakeEvent::Exec { .. })));
        assert_eq!(result.outcome, Outcome::StalePreview);
    }
}

#[test]
fn deployment_legitimate_new_pin_and_interactive_password_fallback_still_execute() {
    use crate::mcp::records::target_binding_tests::RecordingEngine;
    use crate::session::{directory::HostDirectory, testing::Decision};
    use crate::ssh::fake::{FakeLogin, FakeMethods};
    for fallback in [false, true] {
        let auth = if fallback {
            crate::ssh::AuthMethod::Interactive
        } else {
            AuthMethod::Key {
                key_id: "k-plain".into(),
            }
        };
        let directory = FakeDirectory::new().with_host("web", auth.clone());
        let fake = FakeEngine::new().with_exec(
            &script(PLAIN_PUBLIC).unwrap(),
            result(Ended::Exited, Some(0), b"SSHELTER_ADDED\n"),
        );
        let engine = RecordingEngine::new(if fallback {
            fake.with_login(FakeLogin::Server(FakeMethods::password("fixture-password")))
        } else {
            fake
        });
        let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
        let connector = Connector {
            engine: &engine,
            directory: &directory,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &confirmer,
        };
        let requests = Deployments::default();
        let preview = requests.preview(&connector, "id-web", "k-plain").unwrap();
        let (review, cancel) = requests.take(&preview.id, true).unwrap();
        let owner = FakeOwner::typing(&["fixture-password"]);
        assert_eq!(
            execute(&review, &connector, &owner, &cancel, &|| Ok(())).outcome,
            Outcome::Added
        );
        assert!(directory
            .pinned(&crate::ssh::HostId::from("id-web"))
            .unwrap()
            .is_some());
        let actual = engine.targets.lock().unwrap();
        assert_eq!(actual.first().unwrap().hops[0].auth, auth);
        assert!(actual.last().unwrap().hops[0].pinned.is_some());
        if fallback {
            assert_eq!(actual.last().unwrap().hops[0].auth, AuthMethod::Password);
            assert_eq!(owner.asked().len(), 1);
        }
        assert_eq!(
            directory
                .resolve(&HostQuery::Id("id-web".into()))
                .unwrap()
                .hops[0]
                .auth,
            auth
        );
        assert_eq!(
            engine
                .inner
                .events()
                .iter()
                .filter(|event| matches!(event, FakeEvent::Exec { .. }))
                .count(),
            1
        );
    }
}
