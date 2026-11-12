use super::*;
use crate::session::database_ports::tests::{wait_until, FakeUpstream, Warming, PASSWORD};
use crate::session::database_ports::{ensure_password, password_account, NotReady};
use crate::session::databases::DatabaseStep;
use crate::session::directory::HostDirectory;
use crate::session::testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
use crate::ssh::{
    fake::{default_server_key, FakeEngine},
    AuthMethod, Hop, HostId,
};
use crate::sync::testkit::{MemKeychain, TestClock, TestDevice};
use crate::sync::transports::PamCheck;
use std::sync::atomic::AtomicUsize;
use zeroize::Zeroizing;

const DEV: &str = "00000000000000b1";
const STAGING: &str = "00000000000000b2";
const PROD: &str = "00000000000000b3";
/// How long the tests let a start wait: it answers as soon as the port runs or fails.
const WAIT: Duration = Duration::from_secs(10);

fn device() -> TestDevice {
    device_with(|state| state)
}
/// A device whose fresh records `edit` changes before they are activated.
fn device_with(edit: impl FnOnce(SyncStateV3) -> SyncStateV3) -> TestDevice {
    let d = TestDevice::new("databases", &TestClock::new());
    let record_runtime::StartupProbe::Records { mut state, .. } = record_runtime::probe_startup(&d.env().state_path, "databases") else {
        panic!("fresh records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records { state: Box::new(edit(*state)), fresh: false },
    )
    .unwrap();
    d
}
fn runtime(mode: ApprovalMode) -> McpRuntime {
    let r = McpRuntime::default();
    *r.policy.lock().unwrap() = McpPolicy { enabled: true, approval_mode: mode, ..Default::default() };
    r
}
fn snapshot_of(d: &TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
/// A host saved through `create_host` and allowed for the client when `allowed`: its id.
fn host(d: &TestDevice, r: &McpRuntime, alias: &str, allowed: bool) -> String {
    let input = json!({"alias": alias, "hostname": format!("{alias}.example.com"), "user": "deploy"});
    let value = management::create(&d.env(), r, &input, RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Allow).unwrap();
    let id = value["host"]["id"].as_str().unwrap().to_string();
    if allowed {
        r.policy.lock().unwrap().allowed_hosts.insert(id.clone());
    }
    id
}
/// A database of the fixtures, its instance named as it is, in `acme-dev-654321` (`acme-prod-123456` for prod), offered on `port` and
/// reached through the host `via`, or on its public IP.
fn orders(id: &str, name: &str, environment: DatabaseEnvironment, via: Option<&str>, port: u16) -> SavedDatabase {
    SavedDatabase {
        id: id.into(),
        name: name.into(),
        engine: DatabaseEngine::Postgres,
        project: if environment == DatabaseEnvironment::Prod { "acme-prod-123456" } else { "acme-dev-654321" }.into(),
        region: "asia-east1".into(),
        instance: name.into(),
        environment,
        network: if via.is_some() { DatabaseNetwork::Private } else { DatabaseNetwork::Public },
        via_host: via.map(str::to_owned),
        account: Some("frank@example.com".into()),
        default_database: "postgres".into(),
        pam: None,
        local_port: Some(port),
    }
}
/// A database saved outside MCP, as the Databases page saves it.
fn save_directly(d: &TestDevice, database: &SavedDatabase) {
    crate::sync::record_commands::edit_records(&d.env(), |state, now| {
        let current = databases::view(state).into_iter().find(|row| row.database.id == database.id).map(|row| row.database);
        databases::set(state, &database.id, current.as_ref(), Some(database.clone()), now).map_err(|e| AppError::Other(e.to_string()))
    })
    .unwrap();
}
fn orders_dev() -> SavedDatabase {
    orders(DEV, "orders-dev", DatabaseEnvironment::Dev, None, 6543)
}
/// The library of the tests: `orders-dev` on its public IP, `orders-staging` through web-1, which the client may use, and `orders-prod`
/// through web-2, which it may not. Answers the ids of web-1 and web-2.
fn library(d: &TestDevice, r: &McpRuntime) -> (String, String) {
    let web1 = host(d, r, "web-1", true);
    let web2 = host(d, r, "web-2", false);
    save_directly(d, &orders_dev());
    save_directly(d, &orders(STAGING, "orders-staging", DatabaseEnvironment::Staging, Some(&web1), 6544));
    save_directly(d, &orders(PROD, "orders-prod", DatabaseEnvironment::Prod, Some(&web2), 6545));
    (web1, web2)
}
fn saved(d: &TestDevice) -> Vec<SavedDatabase> {
    databases::view(&snapshot_of(d)).into_iter().map(|row| row.database).collect()
}
fn saved_one(d: &TestDevice, id: &str) -> SavedDatabase {
    saved(d).into_iter().find(|database| database.id == id).expect("the database is saved")
}
fn never(_: &McpPendingRequest) -> ApprovalDecision {
    panic!("no window")
}
fn allow(_: &McpPendingRequest) -> ApprovalDecision {
    ApprovalDecision::Allow
}
fn no_start(_: &SavedDatabase, _: AiAsker) -> Result<(), String> {
    panic!("nothing starts")
}
fn rows_of(q: &McpPendingRequest) -> Vec<(String, String)> {
    q.host_proposal.as_ref().unwrap().settings.clone()
}
fn kind_of(q: &McpPendingRequest) -> String {
    q.host_proposal.as_ref().unwrap().kind.clone()
}
fn row(label: &str, value: &str) -> (String, String) {
    (label.to_string(), value.to_string())
}
fn last_entry(r: &McpRuntime) -> McpAuditEntry {
    r.recent.lock().unwrap().front().unwrap().clone()
}
fn outcomes(r: &McpRuntime) -> Vec<String> {
    r.recent.lock().unwrap().iter().map(|entry| entry.outcome.clone()).collect()
}
/// How many database requests were audited.
fn audited(r: &McpRuntime) -> usize {
    r.recent.lock().unwrap().iter().filter(|entry| entry.database.is_some()).count()
}
fn stop_of(entry: &McpAuditEntry) -> Option<(McpStopKind, Option<McpWindow>)> {
    entry.stop.as_ref().map(|stop| (stop.kind, stop.window))
}
/// The ports of the tests, over an upstream that opens the way at once unless a test scripts its warm-up.
fn ports() -> (DatabasePorts, Arc<FakeUpstream>) {
    let upstream = Arc::new(FakeUpstream::default());
    (DatabasePorts::new(upstream.clone()), upstream)
}
/// Starts `database` as the Databases page does (on a port the system picks, so that the tests run side by side) and waits until it runs.
fn run_here(ports: &DatabasePorts, database: &SavedDatabase) {
    let anywhere = SavedDatabase { local_port: Some(0), ..database.clone() };
    ports.start(&anywhere, Zeroizing::new(PASSWORD.into()), CancelToken::default(), Box::new(()), None).unwrap();
    wait_until("the database runs", || ports.live(&database.id).phase == DatabasePhase::Running);
}
/// Stops the database `id` and waits until its port is closed.
fn stopped(ports: &DatabasePorts, id: &str) {
    ports.stop(id);
    wait_until("the port stopped", || !ports.running(id));
}

/// The page's Start as `start_database` asks it in the tests: the database on a port the system picks, with the tests' password. The AI
/// client each start was given is noted.
struct Starts<'a> {
    ports: &'a DatabasePorts,
    given: Mutex<Vec<AiAsker>>,
}
impl<'a> Starts<'a> {
    fn on(ports: &'a DatabasePorts) -> Self {
        Starts { ports, given: Mutex::new(Vec::new()) }
    }
    fn start(&self, database: &SavedDatabase, ai: AiAsker) -> Result<(), String> {
        self.given.lock().unwrap().push(ai.clone());
        let anywhere = SavedDatabase { local_port: Some(0), ..database.clone() };
        self.ports.start(&anywhere, Zeroizing::new(PASSWORD.into()), CancelToken::default(), Box::new(()), Some(ai))
    }
    fn given(&self) -> Vec<AiAsker> {
        self.given.lock().unwrap().clone()
    }
}

/// The fakes a start resolves the route host through: web-1 reached directly with the vault's plain key, its server key pinned when
/// `pinned`.
struct Route {
    engine: FakeEngine,
    directory: FakeDirectory,
    keys: FakeKeys,
    keychain: MemKeychain,
    confirmer: FakeConfirmer,
}
impl Route {
    fn to(web: &str, pinned: bool) -> Route {
        let directory = FakeDirectory::new().with_hop(Hop::new(web, "web-1", "web-1.example.com", 22, "deploy", AuthMethod::Key { key_id: "k-plain".into() }));
        if pinned {
            directory.pin(&HostId::from(web), &default_server_key()).unwrap();
        }
        Route { engine: FakeEngine::new(), directory, keys: FakeKeys::new(), keychain: MemKeychain::default(), confirmer: FakeConfirmer::default() }
    }
    /// The route whose host key window decides `decisions`.
    fn deciding(self, decisions: Vec<Decision>) -> Route {
        Route { confirmer: FakeConfirmer::deciding(decisions), ..self }
    }
    fn connector(&self) -> Connector<'_> {
        Connector {
            engine: &self.engine,
            directory: &self.directory,
            keys: &self.keys,
            keychain: &self.keychain,
            confirmer: &self.confirmer,
            grants: crate::session::grants::GrantGates::for_tests(),
        }
    }
}

fn claude() -> RequestContext {
    RequestContext { requested_by: vec!["Terminal".into(), "claude".into()], ..Default::default() }
}

// ---- list_databases ----

#[test]
fn list_shows_public_databases_and_those_through_allowed_hosts() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    library(&d, &r);
    // The port passwords this device keeps, and the one a running port holds.
    for id in [DEV, STAGING, PROD] {
        ensure_password(&d.keychain, id).unwrap();
    }
    run_here(&ports, &orders_dev());
    let listed = list(&d.env(), &r, &ports).unwrap();
    let rows = listed["databases"].as_array().unwrap();
    let names: Vec<&str> = rows.iter().map(|database| database["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["orders-dev", "orders-staging"]);
    let dev = &rows[0];
    assert_eq!(dev["id"], DEV);
    assert_eq!(dev["route"], "public IP");
    assert_eq!(dev["environment"], "dev");
    assert_eq!(dev["connection_name"], "acme-dev-654321:asia-east1:orders-dev");
    assert_eq!(dev["status"], json!({"phase": "running", "step": null, "error": null}));
    let port = ports.live(DEV).port.unwrap();
    assert_eq!(dev["local_address"], format!("127.0.0.1:{port}"), "where the running port listens");
    let staging = &rows[1];
    assert_eq!(staging["route"], "through web-1");
    assert_eq!(staging["status"]["phase"], "stopped");
    assert_eq!(staging["local_address"], "127.0.0.1:6544");
    assert_eq!((staging["default_database"].as_str(), staging["account"].as_str()), (Some("postgres"), Some("frank@example.com")));
    assert_eq!((&staging["grant"], &staging["synced"]), (&Value::Null, &json!(false)));
    let text = listed.to_string();
    assert!(!text.to_lowercase().contains("password"), "{text}");
    assert!(!text.contains(PASSWORD), "{text}");
    for id in [DEV, STAGING, PROD] {
        let kept = d.keychain.entry(&password_account(id)).unwrap();
        assert!(!text.contains(&kept), "{text}");
    }
    stopped(&ports, DEV);
    r.policy.lock().unwrap().enabled = false;
    assert_eq!(list(&d.env(), &r, &ports).unwrap_err(), "MCP access is disabled.");
}

#[test]
fn a_database_through_a_hidden_host_answers_as_missing() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let (ports, _) = ports();
    let (web, _) = library(&d, &r);
    let route = Route::to(&web, true);
    for key in ["orders-prod", PROD] {
        let unknown = format!("No database this client may use is named or identified as '{key}'.");
        let named = json!({"database": key});
        for result in [
            update(&d.env(), &r, &ports, &json!({"database": key, "environment": "dev"}), RequestContext::default(), &CancelToken::default(), &never),
            delete(&d.env(), &r, &ports, &d.keychain, &named, RequestContext::default(), &CancelToken::default(), &never),
            start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &named, RequestContext::default(), &CancelToken::default(), &never, &no_start, WAIT),
            stop(&d.env(), &r, &ports, &named, RequestContext::default(), &CancelToken::default()),
        ] {
            assert_eq!(result.unwrap_err(), unknown);
        }
    }
    // One running here is not the client's to stop either.
    run_here(&ports, &saved_one(&d, PROD));
    assert_eq!(
        stop(&d.env(), &r, &ports, &json!({"database": "orders-prod"}), RequestContext::default(), &CancelToken::default()).unwrap_err(),
        "No database this client may use is named or identified as 'orders-prod'."
    );
    assert!(ports.running(PROD));
    stopped(&ports, PROD);
    assert_eq!(saved(&d).len(), 3);
    assert_eq!(audited(&r), 0, "nothing was asked or done");
}

// ---- create_database ----

#[test]
fn create_asks_and_saves_on_allow() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    let web = host(&d, &r, "web-1", true);
    let input = json!({
        "name": "orders-staging",
        "connection_name": "acme-dev-654321:asia-east1:orders-staging",
        "environment": "staging",
        "account": null,
        "pam": {"entitlements": ["orders-operate"]},
        "via_host": "web-1",
    });
    let asked = AtomicUsize::new(0);
    let value = create(&d.env(), &r, &ports, &input, RequestContext::default(), &CancelToken::default(), &|q| {
        asked.fetch_add(1, Ordering::SeqCst);
        assert!(saved(&d).is_empty(), "nothing saved before consent");
        assert_eq!(kind_of(q), proposal_kinds::CREATE_DATABASE);
        assert_eq!((q.alias.as_str(), q.host_id.as_deref()), ("orders-staging", Some(web.as_str())));
        assert_eq!((q.hostname.as_deref(), q.user.as_deref(), q.port.as_deref()), (None, None, None));
        assert!(r.records_active.lock().unwrap().values().any(|(key, _)| *key == web), "the request is registered under its route host");
        assert_eq!(
            rows_of(q),
            vec![
                row("Name", "orders-staging"),
                row("Connection name", "acme-dev-654321:asia-east1:orders-staging"),
                row("Environment", "Staging"),
                row("Route", &format!("Through web-1 ({web})")),
                row("Default database", "postgres"),
                row("Google account", "gcloud's active account"),
                row("Grant check", "orders-operate (global, 30 min)"),
                row("Local port", "127.0.0.1:6543"),
                row("Storage", "This device's library"),
            ]
        );
        ApprovalDecision::Allow
    })
    .unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    let all = saved(&d);
    assert_eq!(all.len(), 1);
    let database = &all[0];
    assert_eq!((database.network, database.via_host.as_deref(), database.local_port), (DatabaseNetwork::Private, Some(web.as_str()), Some(6543)));
    assert_eq!((database.project.as_str(), database.region.as_str(), database.instance.as_str()), ("acme-dev-654321", "asia-east1", "orders-staging"));
    assert_eq!((database.environment, database.account.as_deref(), database.default_database.as_str()), (DatabaseEnvironment::Staging, None, "postgres"));
    assert_eq!(database.pam, Some(PamCheck { entitlements: vec!["orders-operate".into()], location: "global".into(), duration_secs: 1800, justification: None }));
    assert_eq!(value["database"]["id"], database.id.as_str());
    assert_eq!(value["database"]["route"], "through web-1");
    assert_eq!(value["message"], "Database saved. Start it with start_database.");
    let entry = last_entry(&r);
    assert_eq!((entry.outcome.as_str(), entry.review), ("database_created", Some(McpReview::Approved)));
    assert_eq!((entry.database.as_deref(), entry.host_id.as_deref(), entry.alias.as_str()), (Some("orders-staging"), Some(web.as_str()), "web-1"));
    assert!(entry.command.is_empty());
    assert!(r.records_active.lock().unwrap().is_empty());
    assert!(!ports.running(&database.id), "saving does not start it");
}

#[test]
fn create_denied_saves_nothing() {
    for (decision, sentence, review) in [
        (ApprovalDecision::Deny, "Database creation was denied.", Some(McpReview::Refused)),
        (ApprovalDecision::TimedOut, "Database creation approval timed out.", Some(McpReview::NoAnswer)),
        (ApprovalDecision::Cancel, "Database creation was canceled.", None),
    ] {
        let d = device();
        // Auto-log never covers a save.
        let r = runtime(ApprovalMode::AutoLog);
        let (ports, _) = ports();
        let input = json!({"name": "orders-dev", "connection_name": "acme-dev-654321:asia-east1:orders-dev", "environment": "dev"});
        let error = create(&d.env(), &r, &ports, &input, RequestContext::default(), &CancelToken::default(), &|q| {
            assert_eq!(q.host_id, None, "a database on its public IP goes through no host");
            assert!(r.records_active.lock().unwrap().values().any(|(key, _)| key.starts_with("database:")), "registered under its record");
            decision
        })
        .unwrap_err();
        assert_eq!(error, sentence);
        assert!(saved(&d).is_empty());
        let entry = last_entry(&r);
        assert_eq!((entry.outcome.as_str(), entry.review), ("database_not_created", review));
        assert_eq!((entry.database.as_deref(), entry.host_id.as_deref(), entry.alias.as_str()), (Some("orders-dev"), None, ""));
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}

#[test]
fn create_through_a_host_the_client_may_not_use_is_refused_before_asking() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    host(&d, &r, "web-1", true);
    let web2 = host(&d, &r, "web-2", false);
    for via in ["web-2", web2.as_str()] {
        let input = json!({"name": "orders-prod", "connection_name": "acme-prod-123456:asia-east1:orders-prod", "environment": "prod", "via_host": via});
        let error = create(&d.env(), &r, &ports, &input, RequestContext::default(), &CancelToken::default(), &never).unwrap_err();
        assert_eq!(error, format!("host '{web2}' is not allowed for AI access"));
    }
    assert!(saved(&d).is_empty());
    assert_eq!(audited(&r), 0, "no window opened");
}

#[test]
fn a_new_database_is_offered_on_the_first_free_port_from_6543() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    library(&d, &r);
    let new = |extra: Value| {
        let mut input = json!({"name": "orders-qa", "connection_name": "acme-dev-654321:asia-east1:orders-qa", "environment": "dev"});
        input.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        input
    };
    let value = create(&d.env(), &r, &ports, &new(json!({})), RequestContext::default(), &CancelToken::default(), &|q| {
        assert!(rows_of(q).contains(&row("Local port", "127.0.0.1:6546")), "{:?}", rows_of(q));
        ApprovalDecision::Allow
    })
    .unwrap();
    assert_eq!(value["database"]["local_address"], "127.0.0.1:6546", "6543 to 6545 are taken");
    let refused = create(&d.env(), &r, &ports, &new(json!({"name": "orders-qa-2", "local_port": 80})), RequestContext::default(), &CancelToken::default(), &never);
    assert_eq!(refused.unwrap_err(), "Choose a local port from 1024 to 65535.");
    create(&d.env(), &r, &ports, &new(json!({"name": "orders-qa-3", "local_port": 7000})), RequestContext::default(), &CancelToken::default(), &allow).unwrap();
    assert!(saved(&d).iter().any(|database| database.name == "orders-qa-3" && database.local_port == Some(7000)));
}

/// The window says a new database is saved where the library keeps it: in the library, which syncs, once it uses central sync; on this
/// device alone otherwise, with an account on the older chain-mode sync as well.
#[test]
fn the_storage_row_says_where_the_library_keeps_the_database() {
    let chain_mode = |mut state: SyncStateV3| {
        state.account = Some(crate::sync::state_v2::AccountState::new(&"a".repeat(64)));
        state
    };
    for (d, storage, synced) in [
        (device_with(chain_mode), "This device's library", false),
        (device_with(crate::sync::transports::tests::in_central_mode), "Synced library", true),
    ] {
        let r = runtime(ApprovalMode::Ask);
        let (ports, _) = ports();
        let input = json!({"name": "orders-dev", "connection_name": "acme-dev-654321:asia-east1:orders-dev", "environment": "dev"});
        create(&d.env(), &r, &ports, &input, RequestContext::default(), &CancelToken::default(), &|q| {
            assert!(rows_of(q).contains(&row("Storage", storage)), "{:?}", rows_of(q));
            ApprovalDecision::Allow
        })
        .unwrap();
        assert_eq!(list(&d.env(), &r, &ports).unwrap()["databases"][0]["synced"], synced, "{storage}");
        assert_eq!(databases::has_library_rows(&snapshot_of(&d)), synced, "{storage}: kept in the account's rows only when synced");
    }
}

#[test]
fn invalid_settings_are_refused_before_the_window() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    host(&d, &r, "web-1", true);
    let base = json!({"name": "orders-dev", "connection_name": "acme-dev-654321:asia-east1:orders-dev", "environment": "dev"});
    let with = |field: &str, value: Value| {
        let mut input = base.clone();
        input[field] = value;
        input
    };
    for (input, sentence) in [
        (with("connection_name", json!("acme-dev-654321/orders-dev")), "Enter the connection name as project:region:instance."),
        (with("connection_name", json!("Acme:asia-east1:orders-dev")), "Enter a Google Cloud project id."),
        (with("name", json!("  ")), "Enter a database name (up to 128 characters)."),
        (with("account", json!("frank")), "Enter the Google account as an email address."),
        (with("pam", json!({"entitlements": []})), "Enter at least one PAM entitlement."),
        (with("environment", json!("production")), SETTINGS_ONLY),
        (with("password", json!("hunter2")), SETTINGS_ONLY),
        (with("pam", json!({"entitlements": ["orders-operate"], "justification": "hunter2"})), SETTINGS_ONLY),
        (json!({"name": "orders-dev", "environment": "dev"}), SETTINGS_ONLY),
    ] {
        let error = create(&d.env(), &r, &ports, &input, RequestContext::default(), &CancelToken::default(), &never).unwrap_err();
        assert_eq!(error, sentence, "{input}");
        assert!(!error.contains("hunter2"));
    }
    assert!(saved(&d).is_empty());
    assert_eq!(audited(&r), 0, "nothing to audit: no window opened");
}

/// A library whose writes are paused refuses a change with its own sentence before any window, and a database it holds does not start.
#[test]
fn a_library_that_cannot_take_the_change_refuses_it_before_the_window() {
    let d = device_with(crate::sync::transports::tests::in_central_mode);
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    let web = host(&d, &r, "web-1", true);
    save_directly(&d, &orders_dev());
    record_runtime::mutate_records(&d.env(), |state| {
        let mut next = state.clone();
        next.shared_writes_blocked = true;
        Ok(next)
    })
    .unwrap();
    let paused = crate::sync::transports::SYNC_PAUSED;
    let new = json!({"name": "orders-qa", "connection_name": "acme-dev-654321:asia-east1:orders-qa", "environment": "dev"});
    assert_eq!(create(&d.env(), &r, &ports, &new, RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), paused);
    let to_prod = json!({"database": "orders-dev", "environment": "prod"});
    assert_eq!(update(&d.env(), &r, &ports, &to_prod, RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), paused);
    let named = json!({"database": "orders-dev"});
    assert_eq!(delete(&d.env(), &r, &ports, &d.keychain, &named, RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), paused);
    let route = Route::to(&web, true);
    let error = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &named, RequestContext::default(), &CancelToken::default(), &never, &no_start, WAIT).unwrap_err();
    assert_eq!(error, "This database needs a sync review in Lunport before it can start.");
    assert_eq!(audited(&r), 0);
}

// ---- update_database ----

#[test]
fn update_shows_old_and_new_and_refuses_a_running_database() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    library(&d, &r);
    let to_prod = json!({"database": "orders-dev", "environment": "prod"});
    let value = update(&d.env(), &r, &ports, &to_prod, RequestContext::default(), &CancelToken::default(), &|q| {
        assert_eq!(kind_of(q), proposal_kinds::UPDATE_DATABASE);
        assert_eq!(rows_of(q), vec![row("Environment", "Dev → Prod")]);
        assert_eq!(saved_one(&d, DEV).environment, DatabaseEnvironment::Dev, "nothing saved before consent");
        ApprovalDecision::Allow
    })
    .unwrap();
    assert_eq!(saved_one(&d, DEV), SavedDatabase { environment: DatabaseEnvironment::Prod, ..orders_dev() }, "only the environment changed");
    assert_eq!(value["database"]["environment"], "prod");
    assert_eq!(value["message"], "Database saved.");
    let entry = last_entry(&r);
    assert_eq!((entry.outcome.as_str(), entry.review, entry.database.as_deref()), ("database_updated", Some(McpReview::Approved), Some("orders-dev")));
    // The same update, of the database running here: refused before any window, in the sentence the page gets.
    run_here(&ports, &saved_one(&d, DEV));
    let stop_first = "Stop orders-dev before you change it.";
    assert_eq!(update(&d.env(), &r, &ports, &to_prod, RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), stop_first);
    let named = json!({"database": "orders-dev"});
    assert_eq!(delete(&d.env(), &r, &ports, &d.keychain, &named, RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), stop_first);
    assert_eq!(audited(&r), 1);
    stopped(&ports, DEV);
}

#[test]
fn an_update_moves_a_database_to_its_public_ip_and_drops_what_is_given_as_null() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    let (web, web2) = library(&d, &r);
    let pam = PamCheck { entitlements: vec!["orders-operate".into()], location: "global".into(), duration_secs: 3600, justification: None };
    save_directly(&d, &SavedDatabase { pam: Some(pam), ..saved_one(&d, STAGING) });
    // Through a host the client may not use: refused before the window.
    let to_web2 = json!({"database": "orders-staging", "via_host": "web-2"});
    assert_eq!(update(&d.env(), &r, &ports, &to_web2, RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), format!("host '{web2}' is not allowed for AI access"));
    let input = json!({"database": "orders-staging", "via_host": null, "pam": null, "account": null});
    update(&d.env(), &r, &ports, &input, RequestContext::default(), &CancelToken::default(), &|q| {
        assert_eq!(q.host_id.as_deref(), Some(web.as_str()), "the host the database leaves");
        assert_eq!(
            rows_of(q),
            vec![
                row("Route", &format!("Through web-1 ({web}) → Public IP")),
                row("Google account", "frank@example.com → gcloud's active account"),
                row("Grant check", "orders-operate (global, 60 min) → None"),
            ]
        );
        ApprovalDecision::Allow
    })
    .unwrap();
    let database = saved_one(&d, STAGING);
    assert_eq!((database.network, database.via_host, database.pam, database.account), (DatabaseNetwork::Public, None, None, None));
    // A grant check given replaces the whole check: without a length, a grant asks for 30 minutes.
    update(&d.env(), &r, &ports, &json!({"database": "orders-staging", "pam": {"entitlements": ["orders-read"], "location": "us-central1"}}), RequestContext::default(), &CancelToken::default(), &|q| {
        assert_eq!(rows_of(q), vec![row("Grant check", "None → orders-read (us-central1, 30 min)")]);
        ApprovalDecision::Allow
    })
    .unwrap();
    // And back through web-1.
    update(&d.env(), &r, &ports, &json!({"database": STAGING, "via_host": "web-1"}), RequestContext::default(), &CancelToken::default(), &allow).unwrap();
    let database = saved_one(&d, STAGING);
    assert_eq!((database.network, database.via_host.as_deref()), (DatabaseNetwork::Private, Some(web.as_str())));
    for (input, sentence) in [
        (json!({"database": "orders-staging"}), "Provide at least one setting to change."),
        (json!({"database": "orders-staging", "environment": "staging"}), "Nothing would change."),
        (json!({"database": "orders-staging", "password": "hunter2"}), SETTINGS_ONLY),
        (json!({"database": "orders-staging", "local_port": 80}), "Choose a local port from 1024 to 65535."),
    ] {
        assert_eq!(update(&d.env(), &r, &ports, &input, RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), sentence, "{input}");
    }
}

#[test]
fn a_policy_change_or_an_edit_during_the_window_saves_nothing() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    let (web, _) = library(&d, &r);
    let to_dev = json!({"database": "orders-staging", "environment": "dev"});
    // AI access to the route host is taken away while the window is open, as AI Access does: the request is withdrawn.
    let error = update(&d.env(), &r, &ports, &to_dev, RequestContext::default(), &CancelToken::default(), &|_| {
        r.policy.lock().unwrap().allowed_hosts.remove(&web);
        r.cancel_records(Some(&web));
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, "MCP request was canceled.");
    assert_eq!(stop_of(&last_entry(&r)), Some((McpStopKind::Canceled, None)));
    // Taken away without the request being withdrawn: the save checks it again.
    r.policy.lock().unwrap().allowed_hosts.insert(web.clone());
    let error = update(&d.env(), &r, &ports, &to_dev, RequestContext::default(), &CancelToken::default(), &|_| {
        r.policy.lock().unwrap().allowed_hosts.remove(&web);
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, format!("host '{web}' is not allowed for AI access"));
    r.policy.lock().unwrap().allowed_hosts.insert(web.clone());
    // Changed in the Databases page while the window was open: the approval does not cover the new one.
    let error = update(&d.env(), &r, &ports, &to_dev, RequestContext::default(), &CancelToken::default(), &|_| {
        save_directly(&d, &SavedDatabase { default_database: "orders".into(), ..saved_one(&d, STAGING) });
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, "The database changed while the request was open; read it again and retry.");
    let database = saved_one(&d, STAGING);
    assert_eq!((database.environment, database.default_database.as_str()), (DatabaseEnvironment::Staging, "orders"), "the other change stands");
    assert_eq!(outcomes(&r)[..3], ["database_not_updated", "database_not_updated", "database_not_updated"]);
}

// ---- delete_database ----

#[test]
fn delete_asks_and_removes_the_record_and_password() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let (ports, _) = ports();
    library(&d, &r);
    let password = ensure_password(&d.keychain, DEV).unwrap();
    let account = password_account(DEV);
    let named = json!({"database": "orders-dev"});
    let error = delete(&d.env(), &r, &ports, &d.keychain, &named, RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Deny).unwrap_err();
    assert_eq!(error, "Database deletion was denied.");
    assert_eq!(saved(&d).len(), 3);
    assert_eq!(d.keychain.entry(&account).as_deref(), Some(password.as_str()), "a refused delete keeps the password");
    assert_eq!(last_entry(&r).outcome, "database_not_deleted");
    let value = delete(&d.env(), &r, &ports, &d.keychain, &named, RequestContext::default(), &CancelToken::default(), &|q| {
        assert_eq!(kind_of(q), proposal_kinds::DELETE_DATABASE);
        let rows = rows_of(q);
        for expected in [row("Name", "orders-dev"), row("Route", "Public IP"), row("Local port", "127.0.0.1:6543")] {
            assert!(rows.contains(&expected), "{expected:?} in {rows:?}");
        }
        assert_eq!(saved(&d).len(), 3, "still there before consent");
        ApprovalDecision::Allow
    })
    .unwrap();
    assert_eq!(value, json!({"database": null, "message": "Database deleted."}));
    assert!(saved(&d).iter().all(|database| database.id != DEV));
    assert_eq!(d.keychain.entry(&account), None, "its port password went with it");
    let entry = last_entry(&r);
    assert_eq!((entry.outcome.as_str(), entry.review), ("database_deleted", Some(McpReview::Approved)));
    assert_eq!((entry.database.as_deref(), entry.host_id.as_deref(), entry.alias.as_str()), (Some("orders-dev"), None, ""));
}

// ---- start_database ----

#[test]
fn start_in_ask_mode_asks_then_starts_naming_the_client() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, upstream) = ports();
    let (web, _) = library(&d, &r);
    let route = Route::to(&web, true);
    let starts = Starts::on(&ports);
    let asked = AtomicUsize::new(0);
    let value = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-staging"}), claude(), &CancelToken::default(), &|q| {
        asked.fetch_add(1, Ordering::SeqCst);
        assert_eq!(kind_of(q), proposal_kinds::START_DATABASE);
        assert_eq!((q.alias.as_str(), q.host_id.as_deref()), ("orders-staging", Some(web.as_str())));
        assert!(rows_of(q).contains(&row("Route", &format!("Through web-1 ({web})"))), "{:?}", rows_of(q));
        assert!(r.records_active.lock().unwrap().values().any(|(key, _)| *key == web), "registered under the route host");
        assert!(starts.given().is_empty(), "nothing starts before consent");
        ApprovalDecision::Allow
    }, &|database, ai| starts.start(database, ai), WAIT)
    .unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    let client = AiAsker { client: "Terminal → claude".into(), unreviewed: None };
    assert_eq!(starts.given(), vec![client.clone()]);
    assert_eq!(*upstream.warmed_for.lock().unwrap(), vec![Some(client)], "the questions on the way name the client");
    let port = ports.live(STAGING).port.unwrap();
    assert_eq!(value["database"]["status"]["phase"], "running");
    assert_eq!(value["database"]["local_address"], format!("127.0.0.1:{port}"));
    assert_eq!(value["message"], format!("Database running on 127.0.0.1:{port}. Apps sign in with its port password, which the person copies from Lunport; no tool returns it."));
    assert!(!value.to_string().contains(PASSWORD));
    let entry = last_entry(&r);
    assert_eq!((entry.outcome.as_str(), entry.review, entry.stop), ("database_started", Some(McpReview::Approved), None));
    assert_eq!((entry.database.as_deref(), entry.host_id.as_deref(), entry.alias.as_str()), (Some("orders-staging"), Some(web.as_str()), "web-1"));
    assert!(r.records_active.lock().unwrap().is_empty());
    stopped(&ports, STAGING);
}

#[test]
fn start_in_auto_log_mode_starts_without_asking() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let (ports, _) = ports();
    let (web, _) = library(&d, &r);
    let route = Route::to(&web, true);
    let starts = Starts::on(&ports);
    let value = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": DEV}), claude(), &CancelToken::default(), &never, &|database, ai| {
        let registered = format!("database:{DEV}");
        assert!(r.records_active.lock().unwrap().values().any(|(key, _)| *key == registered), "a database on its public IP is registered under its record");
        starts.start(database, ai)
    }, WAIT)
    .unwrap();
    assert_eq!(value["database"]["status"]["phase"], "running");
    assert_eq!(starts.given(), vec![AiAsker { client: "Terminal → claude".into(), unreviewed: Some(Unreviewed::Database) }]);
    assert!(route.confirmer.asked().is_empty(), "a database on its public IP has no route host to verify");
    let entry = last_entry(&r);
    assert_eq!((entry.outcome.as_str(), entry.review), ("database_started", Some(McpReview::AutoLog)));
    assert_eq!((entry.host_id.as_deref(), entry.alias.as_str()), (None, ""));
    stopped(&ports, DEV);
}

#[test]
fn start_answers_starting_after_the_wait() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let (ports, upstream) = ports();
    library(&d, &r);
    // The way does not open: the person has not answered the Request-a-grant window yet.
    *upstream.warming.lock().unwrap() = Warming { steps: vec![DatabaseStep::Grant], holds: true, ..Warming::default() };
    let starts = Starts::on(&ports);
    let route = Route::to("0000000000000000", true);
    let value = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-dev"}), RequestContext::default(), &CancelToken::default(), &never, &|database, ai| starts.start(database, ai), Duration::from_millis(300))
        .unwrap();
    assert_eq!(value["database"]["status"]["phase"], "starting");
    assert_eq!(value["database"]["status"]["step"], "grant");
    assert_eq!(value["message"], "The database is still starting; read list_databases for its state.");
    let entry = last_entry(&r);
    assert_eq!((entry.outcome.as_str(), entry.stop, entry.review), ("database_starting", None, Some(McpReview::AutoLog)));
    assert!(ports.running(DEV), "it goes on starting");
    // Asked again, it is answered as it is.
    let again = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-dev"}), RequestContext::default(), &CancelToken::default(), &never, &no_start, WAIT).unwrap();
    assert_eq!(again["message"], "orders-dev is already starting; read list_databases for its state.");
    stopped(&ports, DEV);
}

#[test]
fn start_failure_returns_the_sentence() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let (ports, upstream) = ports();
    let (web, _) = library(&d, &r);
    let failing = Some(NotReady::Failed("Could not connect through web-1: Connection refused.".into()));
    *upstream.warming.lock().unwrap() = Warming { steps: vec![DatabaseStep::Connect], failing, ..Warming::default() };
    let route = Route::to(&web, true);
    let starts = Starts::on(&ports);
    let error = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-staging"}), RequestContext::default(), &CancelToken::default(), &never, &|database, ai| starts.start(database, ai), WAIT)
        .unwrap_err();
    assert_eq!(error, "The database could not start: Could not connect through web-1: Connection refused.");
    let entry = last_entry(&r);
    assert_eq!(entry.outcome, "database_not_started");
    assert_eq!(stop_of(&entry), Some((McpStopKind::Error, None)));
    assert_eq!(ports.live(STAGING).phase, DatabasePhase::Error);
}

#[test]
fn a_start_canceled_while_the_database_starts_stops_it() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let (ports, upstream) = ports();
    library(&d, &r);
    *upstream.warming.lock().unwrap() = Warming { steps: vec![DatabaseStep::Grant], holds: true, ..Warming::default() };
    let route = Route::to("0000000000000000", true);
    let starts = Starts::on(&ports);
    let cancel = CancelToken::default();
    let error = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-dev"}), RequestContext::default(), &cancel, &never, &|database, ai| {
        starts.start(database, ai)?;
        // The client goes away while the database starts.
        cancel.cancel();
        Ok(())
    }, WAIT)
    .unwrap_err();
    assert_eq!(error, "Database start was canceled.");
    wait_until("the port stopped", || !ports.running(DEV));
    assert_eq!(ports.live(DEV).phase, DatabasePhase::Stopped);
    let entry = last_entry(&r);
    assert_eq!((entry.outcome.as_str(), stop_of(&entry)), ("database_not_started", Some((McpStopKind::Canceled, None))));
}

#[test]
fn a_start_the_person_does_not_allow_starts_nothing() {
    for (decision, sentence) in [
        (ApprovalDecision::Deny, "Database start was denied."),
        (ApprovalDecision::TimedOut, "Database start approval timed out."),
        (ApprovalDecision::Cancel, "Database start was canceled."),
    ] {
        let d = device();
        let r = runtime(ApprovalMode::Ask);
        let (ports, _) = ports();
        let (web, _) = library(&d, &r);
        let route = Route::to(&web, true);
        let error = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-staging"}), RequestContext::default(), &CancelToken::default(), &|_| decision, &no_start, WAIT).unwrap_err();
        assert_eq!(error, sentence);
        assert_eq!(last_entry(&r).outcome, "database_not_started");
        assert!(!ports.running(STAGING));
    }
}

#[test]
fn a_database_running_already_or_changed_during_the_window_is_not_started() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    let (web, _) = library(&d, &r);
    let route = Route::to(&web, true);
    run_here(&ports, &orders_dev());
    let value = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-dev"}), RequestContext::default(), &CancelToken::default(), &never, &no_start, WAIT).unwrap();
    assert_eq!(value["message"], "orders-dev is already running.");
    assert_eq!(value["database"]["status"]["phase"], "running");
    stopped(&ports, DEV);
    let error = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-dev"}), RequestContext::default(), &CancelToken::default(), &|_| {
        save_directly(&d, &SavedDatabase { environment: DatabaseEnvironment::Prod, ..orders_dev() });
        ApprovalDecision::Allow
    }, &no_start, WAIT)
    .unwrap_err();
    assert_eq!(error, "The database changed while the request was open; read it again and retry.");
    // A database that offers no local port has nothing to start, and the person is not asked.
    save_directly(&d, &SavedDatabase { local_port: None, ..saved_one(&d, DEV) });
    let error = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-dev"}), RequestContext::default(), &CancelToken::default(), &never, &no_start, WAIT).unwrap_err();
    assert_eq!(error, "Turn on Let other apps connect and choose a port first.");
}

/// A server key of the route host that this device has not verified is decided in Lunport's trust window, which names the client, before
/// the database starts: in both modes, after the start's own approval in Ask mode.
#[test]
fn a_new_server_key_of_the_route_host_is_asked_naming_the_client_before_the_database_starts() {
    for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
        let d = device();
        let r = runtime(mode);
        let (ports, _) = ports();
        let (web, _) = library(&d, &r);
        let route = Route::to(&web, false).deciding(vec![Decision::Trust]);
        let starts = Starts::on(&ports);
        let approve = |_: &McpPendingRequest| {
            assert!(route.confirmer.asked().is_empty(), "the start's approval comes before the key");
            ApprovalDecision::Allow
        };
        start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-staging"}), claude(), &CancelToken::default(), &approve, &|database, ai| {
            assert_eq!(route.confirmer.asked().len(), 1, "the key is decided before the database starts");
            starts.start(database, ai)
        }, WAIT)
        .unwrap();
        let asked = route.confirmer.asked();
        assert_eq!((asked.len(), asked[0].alias.as_str()), (1, "web-1"), "{mode:?}");
        let client = AiAsker { client: "Terminal → claude".into(), unreviewed: (mode == ApprovalMode::AutoLog).then_some(Unreviewed::Database) };
        assert_eq!(asked[0].ai, Some(client), "{mode:?}");
        assert_eq!(route.directory.pinned(&HostId::from(web.as_str())).unwrap().map(|pin| pin.key), Some(default_server_key()), "{mode:?}");
        assert_eq!(outcomes(&r)[..2], ["database_started", "host_key_verified"], "{mode:?}");
        stopped(&ports, STAGING);
    }
}

#[test]
fn a_refused_server_key_of_the_route_host_starts_nothing() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let (ports, _) = ports();
    let (web, _) = library(&d, &r);
    let route = Route::to(&web, false).deciding(vec![Decision::Refuse]);
    let error = start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-staging"}), RequestContext::default(), &CancelToken::default(), &never, &no_start, WAIT).unwrap_err();
    assert_eq!(error, "The server key of web-1 was denied in Lunport's trust window; nothing was saved and the database did not start.");
    assert_eq!(route.directory.pinned(&HostId::from(web.as_str())).unwrap(), None);
    assert_eq!(outcomes(&r)[..2], ["database_not_started", "host_key_not_verified"]);
    assert_eq!(stop_of(&last_entry(&r)), Some((McpStopKind::Refused, Some(McpWindow::ServerKey))));
    assert!(!ports.running(STAGING));
}

/// A database serves the person's apps: once started, it keeps running when AI access to its host ends, and the client no longer sees it.
#[test]
fn a_database_the_client_started_keeps_running_when_ai_access_to_its_host_ends() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let (ports, _) = ports();
    let (web, _) = library(&d, &r);
    let route = Route::to(&web, true);
    let starts = Starts::on(&ports);
    start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &json!({"database": "orders-staging"}), RequestContext::default(), &CancelToken::default(), &never, &|database, ai| starts.start(database, ai), WAIT)
        .unwrap();
    r.policy.lock().unwrap().allowed_hosts.remove(&web);
    r.cancel_records(Some(&web));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(ports.live(STAGING).phase, DatabasePhase::Running);
    let names: Vec<String> = list(&d.env(), &r, &ports).unwrap()["databases"].as_array().unwrap().iter().map(|database| database["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, ["orders-dev"]);
    stopped(&ports, STAGING);
}

// ---- stop_database ----

#[test]
fn stop_never_asks_and_stops() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    let (web, _) = library(&d, &r);
    run_here(&ports, &saved_one(&d, STAGING));
    let named = json!({"database": "orders-staging"});
    let value = stop(&d.env(), &r, &ports, &named, RequestContext::default(), &CancelToken::default()).unwrap();
    assert_eq!(value["message"], "Database stopped.");
    assert_eq!(value["database"]["status"]["phase"], "stopped");
    assert!(!ports.running(STAGING));
    let entry = last_entry(&r);
    assert_eq!((entry.outcome.as_str(), entry.review, entry.stop), ("database_stopped", Some(McpReview::NotAsked), None));
    assert_eq!((entry.database.as_deref(), entry.host_id.as_deref(), entry.alias.as_str()), (Some("orders-staging"), Some(web.as_str()), "web-1"));
    let value = stop(&d.env(), &r, &ports, &named, RequestContext::default(), &CancelToken::default()).unwrap();
    assert_eq!(value["message"], "The database is not running.");
    assert_eq!(audited(&r), 1, "nothing stopped, nothing audited");
}

// ---- What the tools take and say ----

#[test]
fn no_tool_takes_a_password_or_more_than_its_database() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let (ports, _) = ports();
    let (web, _) = library(&d, &r);
    let route = Route::to(&web, true);
    let with_password = json!({"database": "orders-dev", "password": "hunter2"});
    for result in [
        delete(&d.env(), &r, &ports, &d.keychain, &with_password, RequestContext::default(), &CancelToken::default(), &never),
        start(&d.env(), &r, &ports, &route.connector(), &FakeOwner::default(), &with_password, RequestContext::default(), &CancelToken::default(), &never, &no_start, WAIT),
        stop(&d.env(), &r, &ports, &with_password, RequestContext::default(), &CancelToken::default()),
        stop(&d.env(), &r, &ports, &json!({"name": "orders-dev"}), RequestContext::default(), &CancelToken::default()),
    ] {
        assert_eq!(result.unwrap_err(), DATABASE_ONLY);
    }
    for tool in tool_definitions() {
        let schema = &tool["inputSchema"];
        assert_eq!(schema["additionalProperties"], false, "{tool}");
        let fields: Vec<&String> = schema["properties"].as_object().unwrap().keys().collect();
        assert!(fields.iter().all(|field| !field.contains("password")), "{fields:?}");
    }
}

#[test]
fn the_tools_are_listed_with_their_words_and_hints() {
    let tools = tool_definitions();
    let listed: Vec<(&str, &str)> = tools.iter().map(|tool| (tool["name"].as_str().unwrap(), tool["description"].as_str().unwrap())).collect();
    assert_eq!(
        listed,
        vec![
            ("list_databases", "List the saved Cloud SQL databases this client may use: name, environment, connection name, route, status and local address. A database reached through a host is listed only when that host is allowed for AI access. Never returns port passwords."),
            ("create_database", "Propose a new saved Cloud SQL for PostgreSQL database. connection_name is project:region:instance; environment is dev, staging or prod; via_host names an allowed host to reach the instance's private IP through (omit it for the public IP). Lunport always asks the user before saving, including in Auto-log mode. Does not start the database or connect."),
            ("update_database", "Propose changes to a saved database this client may use. A field given replaces that field only: via_host null switches to the public IP, pam null removes the grant check. Lunport always asks the user before saving and shows each change as old → new. A running database must be stopped first."),
            ("delete_database", "Propose deleting a saved database this client may use, with its port password on this computer. Lunport always asks the user. A running database must be stopped first."),
            ("start_database", "Start a saved database's local port. Lunport requests the grants it needs, connects through its host and gets the Cloud SQL certificate, asking the user in its own windows. Follows Ask or Auto-log like start_tunnel. Answers when the port runs or fails, or after 90 seconds while it is still starting. Apps connect with the port password, which no tool returns."),
            ("stop_database", "Stop a saved database's local port and close its connections. Never asks."),
        ]
    );
    let hints = |name: &str| {
        let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
        let hint = |key: &str| tool["annotations"][key].as_bool().unwrap();
        (hint("readOnlyHint"), hint("destructiveHint"), hint("idempotentHint"), hint("openWorldHint"))
    };
    assert_eq!(hints("list_databases"), (true, false, true, false));
    assert_eq!(hints("create_database"), (false, false, false, false));
    assert_eq!(hints("update_database"), (false, false, false, false));
    assert_eq!(hints("delete_database"), (false, true, true, false));
    assert_eq!(hints("start_database"), (false, false, true, true));
    assert_eq!(hints("stop_database"), (false, true, true, false));
    let required = |name: &str| tools.iter().find(|tool| tool["name"] == name).unwrap()["inputSchema"]["required"].clone();
    assert_eq!(required("create_database"), json!(["name", "connection_name", "environment"]));
    for name in ["update_database", "delete_database", "start_database", "stop_database"] {
        assert_eq!(required(name), json!(["database"]), "{name}");
    }
}

#[test]
fn the_server_instructions_say_how_databases_are_reached() {
    let response = handle_mcp_message(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})).unwrap();
    let instructions = response["result"]["instructions"].as_str().unwrap();
    assert!(instructions.ends_with(
        "Databases on a public IP, and databases reached through permitted hosts, can be listed; create_database, update_database and delete_database always need native human approval; start_database follows Ask or Auto-log like start_tunnel, and stop_database never asks. No tool returns or accepts a database port password."
    ), "{instructions}");
}
