use super::*;
use crate::session::{
    directory::{DirectoryError, HostDirectory, PinnedKey},
    testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
};
use crate::ssh::{
    fake::{default_server_key, FakeEngine, FakeEvent},
    HostId, HostKey,
};
use crate::sync::testkit::MemKeychain;

/// Both execution paths resolve preview A, preflight A, actual connection B, then current A again.
pub(crate) struct AbaDirectory {
    a: Target,
    b: Target,
    reads: AtomicU64,
    returned_b: AtomicBool,
}
impl AbaDirectory {
    pub(crate) fn new() -> Self {
        let directory = FakeDirectory::new()
            .with_host(
                "web",
                AuthMethod::Key {
                    key_id: "k-plain".into(),
                },
            )
            .with_address("web", "reviewed.example", 22)
            .with_pin("web", default_server_key());
        let a = directory.resolve(&HostQuery::Id("id-web".into())).unwrap();
        let mut b = a.clone();
        b.hops[0].hostname = "unreviewed.example".into();
        Self {
            a,
            b,
            reads: AtomicU64::new(0),
            returned_b: AtomicBool::new(false),
        }
    }
    pub(crate) fn auth_drift() -> Self {
        let mut directory = Self::new();
        directory.a.hops[0].auth = AuthMethod::Interactive;
        directory.b = directory.a.clone();
        directory.b.hops[0].auth = AuthMethod::Password;
        directory
    }
    pub(crate) fn returned_b(&self) -> bool {
        self.returned_b.load(Ordering::SeqCst)
    }
}
impl HostDirectory for AbaDirectory {
    fn resolve(&self, _: &HostQuery) -> Result<Target, DirectoryError> {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 2 {
            self.returned_b.store(true, Ordering::SeqCst);
            Ok(self.b.clone())
        } else {
            Ok(self.a.clone())
        }
    }
    fn pinned(&self, _: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        Ok(Some(PinnedKey {
            key: default_server_key(),
            pinned_at_ms: 1,
        }))
    }
    fn pin(&self, _: &HostId, _: &HostKey) -> Result<(), DirectoryError> {
        panic!("pre-pinned fixture must not write pins")
    }
    fn replace_pin(&self, _: &HostId, _: &HostKey, _: &HostKey) -> Result<(), DirectoryError> {
        panic!("pre-pinned fixture must not replace pins")
    }
    fn password_account(&self, id: &HostId) -> String {
        format!("host:{id}")
    }
}
pub(crate) struct RecordingEngine {
    pub(crate) inner: FakeEngine,
    pub(crate) targets: Mutex<Vec<Target>>,
}
impl RecordingEngine {
    pub(crate) fn new(inner: FakeEngine) -> Self {
        Self {
            inner,
            targets: Mutex::new(vec![]),
        }
    }
}
impl SshEngine for RecordingEngine {
    fn connect(
        &self,
        target: &Target,
        pins: &dyn HostKeyPolicy,
        auth: &dyn AuthSource,
    ) -> Result<Box<dyn Session>, ConnectError> {
        self.targets.lock().unwrap().push(target.clone());
        self.inner.connect(target, pins, auth)
    }
}
#[test]
fn mcp_aba_resolve_cannot_connect_or_execute_on_unreviewed_target() {
    for directory in [AbaDirectory::new(), AbaDirectory::auth_drift()] {
        let engine = RecordingEngine::new(FakeEngine::new());
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &directory,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let runtime = McpRuntime::default();
        {
            let mut policy = runtime.policy.lock().unwrap();
            policy.enabled = true;
            policy.allowed_hosts.insert("id-web".into());
        }
        let result = execute(
            &runtime,
            &connector,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| ApprovalDecision::Allow,
        );
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
        assert!(result.is_err());
    }
}

#[test]
fn actual_engine_target_binding_rejects_endpoint_route_key_and_auth_drift() {
    use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
    let directory = AbaDirectory::new();
    let keys = FakeKeys::new();
    let approved = ApprovedTarget::capture(&directory.a, &keys).unwrap();
    approved.check_resolved(&directory.a, &keys).unwrap();
    let mut candidates = vec![];
    for field in ["hostname", "port", "user", "route", "key", "auth"] {
        let mut changed = directory.a.clone();
        match field {
            "hostname" => changed.hops[0].hostname = "unreviewed.example".into(),
            "port" => changed.hops[0].port = 2222,
            "user" => changed.hops[0].user = "other".into(),
            "route" => {
                let mut jump = changed.hops[0].clone();
                jump.id = HostId::from("jump");
                changed.hops.insert(0, jump);
            }
            "key" => {
                changed.hops[0].auth = AuthMethod::Key {
                    key_id: "k-enc".into(),
                }
            }
            "auth" => changed.hops[0].auth = AuthMethod::Password,
            _ => unreachable!(),
        }
        candidates.push((field, changed));
    }
    for (field, actual) in candidates {
        let inner = RecordingEngine::new(FakeEngine::new());
        // Current state remains the approved A; only the actual engine argument changes.
        let check = |target: &Target| {
            approved.check_resolved(&directory.a, &keys)?;
            approved.check_connected(target, &keys)
        };
        let engine = CheckedEngine {
            inner: &inner,
            check: &check,
        };
        assert!(
            engine
                .connect(&actual, TestPolicy::trusting().as_ref(), &VaultAuth::new())
                .is_err(),
            "{field}"
        );
        assert!(
            inner.targets.lock().unwrap().is_empty(),
            "{field} must not reach inner engine"
        );
    }
}

#[test]
fn resolved_auth_is_strict_while_connected_binding_only_permits_interactive_password_and_pins() {
    let keys = FakeKeys::new();
    let mut target = AbaDirectory::new().a;
    target.hops[0].auth = AuthMethod::Interactive;
    target.hops[0].pinned = None;
    let approved = ApprovedTarget::capture(&target, &keys).unwrap();
    let mut adapted = target.clone();
    adapted.hops[0].auth = AuthMethod::Password;
    adapted.hops[0].pinned = Some(default_server_key());
    assert!(
        approved.check_resolved(&adapted, &keys).is_err(),
        "initial directory auth drift must never be treated as connector adaptation"
    );
    assert!(approved.check_connected(&adapted, &keys).is_ok());
    adapted.hops[0].hostname = "different.example".into();
    assert!(approved.check_connected(&adapted, &keys).is_err());
    let mut password = target.clone();
    password.hops[0].auth = AuthMethod::Password;
    assert!(
        ApprovedTarget::capture(&password, &keys)
            .unwrap()
            .check_connected(&target, &keys)
            .is_err(),
        "the inverse Password to Interactive change is not an allowed adaptation"
    );
}

#[test]
fn mcp_legitimate_new_pin_and_explicit_interactive_password_fallback_still_execute() {
    use crate::session::testing::Decision;
    use crate::ssh::fake::{FakeLogin, FakeMethods};
    for fallback in [false, true] {
        let auth = if fallback {
            AuthMethod::Interactive
        } else {
            AuthMethod::Key {
                key_id: "k-plain".into(),
            }
        };
        let directory = FakeDirectory::new().with_host("web", auth.clone());
        let fake = if fallback {
            FakeEngine::new()
                .with_login(FakeLogin::Server(FakeMethods::password("fixture-password")))
        } else {
            FakeEngine::new()
        };
        let engine = RecordingEngine::new(fake);
        let keys = FakeKeys::new();
        let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
        let owner = FakeOwner::typing(&["fixture-password"]);
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &directory,
            keys: &keys,
            keychain: &MemKeychain::default(),
            confirmer: &confirmer,
        };
        let runtime = McpRuntime::default();
        {
            let mut policy = runtime.policy.lock().unwrap();
            policy.enabled = true;
            policy.allowed_hosts.insert("id-web".into());
        }
        let output = execute(
            &runtime,
            &connector,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &owner,
            &|_| ApprovalDecision::Allow,
        )
        .unwrap();
        assert_eq!(output["ended"], "exited");
        assert!(directory.pinned(&HostId::from("id-web")).unwrap().is_some());
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
            auth,
            "saved auth remains unchanged"
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
