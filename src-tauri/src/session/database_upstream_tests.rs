//! `CloudSqlUpstream` tried against a scripted Google, a certificate authority made for the test, a clock of the test's own and scripted
//! sessions to the library's hosts, alone and behind a port that the apps connect to.

use super::*;
use crate::gcp::cloudsql::{ConnectSettings, EphemeralCert, EphemeralKey, InstanceRef, InstanceSummary};
use crate::gcp::oslogin::LoginProfile;
use crate::gcp::pam::{duration_text, rfc3339, Grant};
use crate::gcp::rest::GcpError;
use crate::session::auth::Reply;
use crate::session::database_ports::tests::{cancel_request, fake_cloud_sql, orders, running, t0, wait_until, Answer, App, Clock, CONNECTION, IAM_USER, ID, LIMIT, PASSWORD};
use crate::session::database_ports::{DatabasePorts, NotReady, Prepared};
use crate::session::databases::DatabasePhase;
use crate::session::protocol::QuestionKind;
use crate::session::testing::FakeOwner;
use crate::ssh::forward::{ForwardKind, ForwardSpec, ForwardStatus, Forwarder};
use crate::ssh::{DisconnectReason, ExecResult, Pty, Session, SessionError, ShellChannel};
use crate::sync::databases::tests::{state, ROUTE_HOST};
use crate::sync::databases::{DatabaseEnvironment, DatabaseNetwork};
use crate::sync::records_v3::{HostPayload, HostScope};
use crate::sync::transports::PamCheck;
use futures_util::FutureExt;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Instant;

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
/// What the person answers in the Request-a-grant window: thirty minutes, and why.
const ANSWER: &str = "30\nCheck unpaid orders";
const OPERATE: &str = "projects/acme-prod-123456/locations/global/entitlements/prod-operate";
/// The addresses of the instance the tests dial: the public one, and the private one that only a host of the library reaches.
const PUBLIC_IP: &str = "203.0.113.10";
const PRIVATE_IP: &str = "198.51.100.10";
/// The port the forwards of the scripted sessions listen on.
const FORWARD_PORT: u16 = 40123;

/// Google's PAM as the tests script it: the grants the account holds on prod-operate. A requested grant is active at once, dated by the
/// test's clock.
struct Pam {
    clock: Clock,
    held: Mutex<Vec<Grant>>,
    looked: AtomicUsize,
    created: AtomicUsize,
}

impl Pam {
    /// A grant in `state` for thirty minutes, given at `granted_at`.
    fn grant(&self, state: &str, granted_at: SystemTime) -> Grant {
        Grant {
            name: format!("{OPERATE}/grants/{state}"),
            state: state.into(),
            requested_duration: Some("1800s".into()),
            access_grant_time: Some(rfc3339(granted_at)),
            justification: None,
        }
    }
}

impl GcpClient for Pam {
    fn login_profile(&self, _: Option<&str>, _: &str) -> Result<LoginProfile, GcpError> {
        Err(GcpError::Network("OS Login is not scripted".into()))
    }

    fn import_ssh_public_key(&self, _: Option<&str>, _: &str, _: &str) -> Result<LoginProfile, GcpError> {
        Err(GcpError::Network("OS Login is not scripted".into()))
    }

    fn grants(&self, _: Option<&str>, _: &str) -> Result<Vec<Grant>, GcpError> {
        self.looked.fetch_add(1, Ordering::SeqCst);
        Ok(self.held.lock().unwrap().clone())
    }

    fn create_grant(&self, _: Option<&str>, entitlement: &str, duration_secs: u32, justification: &str) -> Result<Grant, GcpError> {
        self.created.fetch_add(1, Ordering::SeqCst);
        let grant = Grant {
            name: format!("{entitlement}/grants/requested"),
            state: "ACTIVE".into(),
            requested_duration: Some(duration_text(duration_secs)),
            access_grant_time: Some(rfc3339(self.clock.now())),
            justification: Some(justification.into()),
        };
        self.held.lock().unwrap().push(grant.clone());
        Ok(grant)
    }

    fn get_grant(&self, _: Option<&str>, name: &str) -> Result<Grant, GcpError> {
        self.held.lock().unwrap().iter().find(|grant| grant.name == name).cloned().ok_or_else(|| GcpError::Network("no such grant".into()))
    }
}

type Authority = CertifiedIssuer<'static, KeyPair>;

/// A certificate authority made for the test: it stands for the instance's server CA and signs the client certificates.
fn authority() -> Authority {
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Cloud SQL test CA");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

/// The name an instance's server certificate is made out to, in the tests.
fn dns_name(instance: &str) -> String {
    format!("{instance}.asia-east1.sql.goog")
}

/// The Cloud SQL Admin API as the tests script it: an instance's connect settings, and for every key a certificate signed by `authority`
/// that is good for an hour of the test's clock, for `account`. When `holding` is set, the first certificate request waits until
/// `released` is (at most `LIMIT`), so that a test can hold a fetch half done.
#[derive(Default)]
struct Admin {
    authority: Option<Authority>,
    clock: Option<Clock>,
    account: Mutex<String>,
    settings: AtomicUsize,
    certificates: AtomicUsize,
    holding: AtomicBool,
    released: AtomicBool,
    /// The connect settings fail with this.
    failing: Mutex<Option<GcpError>>,
    /// The connect settings carry no DNS name, as those of an instance may not.
    nameless: AtomicBool,
}

impl Admin {
    fn authority(&self) -> &Authority {
        self.authority.as_ref().expect("an authority")
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
    }
}

impl SqlAdmin for Admin {
    fn connect_settings(&self, _: Option<&str>, at: &InstanceRef) -> Result<ConnectSettings, GcpError> {
        self.settings.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.failing.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(ConnectSettings {
            public_ip: Some(PUBLIC_IP.parse().unwrap()),
            private_ip: Some(PRIVATE_IP.parse().unwrap()),
            server_ca_pem: self.authority().pem(),
            dns_name: (!self.nameless.load(Ordering::SeqCst)).then(|| dns_name(&at.instance)),
            database_version: "POSTGRES_16".into(),
            region: at.region.clone(),
        })
    }

    fn ephemeral_cert(&self, _: Option<&str>, _: &InstanceRef, key: &EphemeralKey) -> Result<EphemeralCert, GcpError> {
        let first = self.certificates.fetch_add(1, Ordering::SeqCst) == 0;
        if first && self.holding.load(Ordering::SeqCst) {
            let end = Instant::now() + LIMIT;
            while !self.released.load(Ordering::SeqCst) && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let key = KeyPair::try_from(&key.private_der()).expect("rcgen reads the connection's key");
        let mut params = CertificateParams::default();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, self.authority()).unwrap();
        let clock = self.clock.as_ref().expect("a clock");
        Ok(EphemeralCert { cert_pem: cert.pem(), expires_at: clock.now() + HOUR, account: self.account.lock().unwrap().clone() })
    }

    fn list_instances(&self, _: Option<&str>, _: &str) -> Result<Vec<InstanceSummary>, GcpError> {
        Ok(Vec::new())
    }
}

/// The recording owner of a test, shared with the test that reads what it was asked and told.
struct Shared(Arc<FakeOwner>);

impl Owner for Shared {
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        self.0.ask(kind, text, echo, deadline)
    }

    fn host_key_notice(&self, text: &str) {
        self.0.host_key_notice(text);
    }

    fn banner(&self, text: &str) {
        self.0.banner(text);
    }
}

/// What a test sees of a scripted session to a host of the library once the upstream owns the session: whether its connection is up,
/// whether the upstream closed it, the forwards it was asked for, and what the status of its forward says.
struct HostEnd {
    alive: AtomicBool,
    closed: AtomicBool,
    forwards: Mutex<Vec<ForwardSpec>>,
    /// Whether its forward's listener runs.
    running: AtomicBool,
    /// Whether the upstream stopped its forward.
    stopped: AtomicBool,
    /// The most recent connection error its forward reports.
    forward_error: Mutex<Option<String>>,
    /// The port its forward reports.
    port: Mutex<u16>,
    /// What it refuses a forward with.
    refusal: Mutex<Option<SessionError>>,
}

impl HostEnd {
    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    fn forwards(&self) -> Vec<ForwardSpec> {
        self.forwards.lock().unwrap().clone()
    }

    /// The connection to the host is lost, as when the host goes away.
    fn lose(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }
}

/// A session to a host of the library as the tests script it: `HostEnd` says what happens to it.
struct Scripted(Arc<HostEnd>);

impl Session for Scripted {
    fn forward(&self, spec: &ForwardSpec) -> Result<Box<dyn Forwarder>, SessionError> {
        self.0.forwards.lock().unwrap().push(spec.clone());
        match self.0.refusal.lock().unwrap().clone() {
            Some(refusal) => Err(refusal),
            None => Ok(Box::new(ScriptedForward(Arc::clone(&self.0)))),
        }
    }

    fn shell(&self, _: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
        Err(SessionError::Channel("No shell is scripted.".into()))
    }

    fn exec(&self, _: &str, _: Duration, _: usize) -> Result<ExecResult, SessionError> {
        Err(SessionError::Channel("No command is scripted.".into()))
    }

    fn is_alive(&self) -> bool {
        self.0.alive.load(Ordering::SeqCst)
    }

    fn disconnect_reason(&self) -> Option<DisconnectReason> {
        None
    }

    fn close(&self) {
        self.0.alive.store(false, Ordering::SeqCst);
        self.0.closed.store(true, Ordering::SeqCst);
    }
}

/// The forward of a scripted session. It listens on nothing and carries nothing: it runs while its listener does, it is not stopped and
/// its session lives, and reports the port and the error its `HostEnd` holds.
struct ScriptedForward(Arc<HostEnd>);

impl Forwarder for ScriptedForward {
    fn status(&self) -> ForwardStatus {
        let end = &self.0;
        let running = end.running.load(Ordering::SeqCst) && !end.stopped() && end.alive.load(Ordering::SeqCst);
        ForwardStatus { running, port: *end.port.lock().unwrap(), connections: 0, error: end.forward_error.lock().unwrap().clone() }
    }

    fn stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
    }
}

/// The way to the library's hosts as the tests script it: every open is recorded with the host it names, and answered with the next
/// failure scripted, else with a new scripted session that lives until it is closed or lost.
struct FakeLink {
    opened: Mutex<Vec<String>>,
    failures: Mutex<VecDeque<String>>,
    /// Whether an open cancels the connection it is for before it answers, as a port that stops meanwhile does.
    cancels: AtomicBool,
    /// What the forwards of the next sessions are refused with.
    refusal: Mutex<Option<SessionError>>,
    /// The far ends of the sessions it opened, in order.
    ends: Mutex<Vec<Arc<HostEnd>>>,
}

impl FakeLink {
    fn new() -> FakeLink {
        FakeLink { opened: Mutex::default(), failures: Mutex::default(), cancels: AtomicBool::new(false), refusal: Mutex::default(), ends: Mutex::default() }
    }

    /// The hosts it opened a session to, by their ids, in order.
    fn opened(&self) -> Vec<String> {
        self.opened.lock().unwrap().clone()
    }

    /// The far end of the session it opened `index`th, counted from 0.
    fn end(&self, index: usize) -> Arc<HostEnd> {
        Arc::clone(&self.ends.lock().unwrap()[index])
    }
}

impl HostLink for FakeLink {
    fn open(&self, host_id: &str, _: &dyn Owner, cancel: &CancelToken) -> Result<Box<dyn Session>, String> {
        self.opened.lock().unwrap().push(host_id.to_string());
        if self.cancels.load(Ordering::SeqCst) {
            cancel.cancel();
        }
        if let Some(failure) = self.failures.lock().unwrap().pop_front() {
            return Err(failure);
        }
        let end = Arc::new(HostEnd {
            alive: AtomicBool::new(true),
            closed: AtomicBool::new(false),
            forwards: Mutex::default(),
            running: AtomicBool::new(true),
            stopped: AtomicBool::new(false),
            forward_error: Mutex::default(),
            port: Mutex::new(FORWARD_PORT),
            refusal: Mutex::new(self.refusal.lock().unwrap().clone()),
        });
        self.ends.lock().unwrap().push(Arc::clone(&end));
        Ok(Box::new(Scripted(end)))
    }
}

/// Whether `done` holds within two seconds, looked at every 10 ms: a path closes its session, and stops a forward it no longer keeps, on a
/// thread of its own.
fn soon(done: impl Fn() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The library of the tests: `web-1`, saved as the host `ROUTE_HOST`, which `routed()` databases are reached through.
fn library() -> SyncStateV3 {
    let web: HostPayload = serde_json::from_value(json!({"schema": 2, "alias": "web-1", "hostname": "fixture.invalid", "auth": "password"})).unwrap();
    repo::create_host(&state(), ROUTE_HOST, HostScope::Local, web, 1).unwrap()
}

/// Google, the clock, the person and the library's hosts a `CloudSqlUpstream` is tried against, and what it dialled.
struct Cloud {
    clock: Clock,
    pam: Arc<Pam>,
    admin: Arc<Admin>,
    /// gcloud's active account.
    active: Arc<Mutex<Option<String>>>,
    owner: Arc<FakeOwner>,
    remembered: Arc<Mutex<Vec<(String, String, u32)>>>,
    link: Arc<FakeLink>,
    dialled: Arc<Mutex<Vec<(SocketAddr, ServerName<'static>)>>>,
    /// How many of the next dials Cloud SQL refuses.
    refusing: Arc<Mutex<usize>>,
    /// What every dial fails with: its kind and its words.
    failing: Arc<Mutex<Option<(io::ErrorKind, String)>>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Cloud {
    /// Google with no grant held, and `owner` at the window.
    fn new(owner: FakeOwner) -> Cloud {
        let clock = Clock::new();
        Cloud {
            pam: Arc::new(Pam { clock: clock.clone(), held: Mutex::new(Vec::new()), looked: AtomicUsize::new(0), created: AtomicUsize::new(0) }),
            admin: Arc::new(Admin { authority: Some(authority()), clock: Some(clock.clone()), account: Mutex::new(IAM_USER.into()), ..Admin::default() }),
            clock,
            active: Arc::new(Mutex::new(Some(IAM_USER.into()))),
            owner: Arc::new(owner),
            remembered: Arc::default(),
            link: Arc::new(FakeLink::new()),
            dialled: Arc::default(),
            refusing: Arc::default(),
            failing: Arc::default(),
            received: Arc::default(),
        }
    }

    /// The upstream over them. It dials the fake Cloud SQL, and records where it dialled.
    fn upstream(&self) -> CloudSqlUpstream {
        let owner = Arc::clone(&self.owner);
        let clock = self.clock.clone();
        let active = Arc::clone(&self.active);
        let remembered = Arc::clone(&self.remembered);
        let (dialled, refusing, failing, received) = (Arc::clone(&self.dialled), Arc::clone(&self.refusing), Arc::clone(&self.failing), Arc::clone(&self.received));
        CloudSqlUpstream {
            gcp: self.pam.clone(),
            sql: self.admin.clone(),
            gates: Arc::new(GrantGates::default()),
            make_owner: Arc::new(move |_: &CancelToken| -> Box<dyn Owner + Send> { Box::new(Shared(Arc::clone(&owner))) }),
            now: Arc::new(move || clock.now()),
            active_account: Arc::new(move || active.lock().unwrap().clone()),
            library: Arc::new(|| -> Result<SyncStateV3, String> { Ok(library()) }),
            remember: Arc::new(move |name: &str, justification: &str, secs: u32| {
                remembered.lock().unwrap().push((name.to_string(), justification.to_string(), secs));
            }),
            link: Arc::clone(&self.link) as Arc<dyn HostLink>,
            dial: Arc::new(move |address: SocketAddr, _config: Arc<ClientConfig>, name: ServerName<'static>| -> BoxFuture<'static, io::Result<BoxStream>> {
                dialled.lock().unwrap().push((address, name));
                let failure = failing.lock().unwrap().clone();
                let refused = {
                    let mut left = refusing.lock().unwrap();
                    let refused = *left > 0;
                    if refused {
                        *left -= 1;
                    }
                    refused
                };
                let received = Arc::clone(&received);
                Box::pin(async move {
                    if let Some((kind, words)) = failure {
                        return Err(io::Error::new(kind, words));
                    }
                    if refused {
                        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "Cloud SQL refused the connection."));
                    }
                    let (near, far) = tokio::io::duplex(64 * 1024);
                    tokio::spawn(fake_cloud_sql(far, Answer::SignsIn, received, Arc::default()));
                    Ok(Box::new(near) as BoxStream)
                })
            }),
            routes: Mutex::default(),
            generations: AtomicU64::new(1),
        }
    }

    fn certificates(&self) -> usize {
        self.admin.certificates.load(Ordering::SeqCst)
    }

    fn looked(&self) -> usize {
        self.pam.looked.load(Ordering::SeqCst)
    }
}

/// The prod database of the fixtures with a grant check on prod-operate.
fn guarded() -> SavedDatabase {
    SavedDatabase {
        pam: Some(PamCheck { entitlements: vec!["prod-operate".into()], location: "global".into(), duration_secs: 1800, justification: None }),
        ..orders()
    }
}

/// `orders()` reached over its private IP, through a host of the library.
fn routed() -> SavedDatabase {
    SavedDatabase { network: DatabaseNetwork::Private, via_host: Some(ROUTE_HOST.into()), ..orders() }
}

/// Where a dial to the instance at `ip` is expected to go: Cloud SQL takes its TLS connections on port 3307.
fn instance_at(ip: &str) -> SocketAddr {
    format!("{ip}:3307").parse().unwrap()
}

/// Where a dial through a host goes: the loopback end of the forward, at `port`.
fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

/// The forward a session to the host is asked for: from a port the system picks on 127.0.0.1 to Cloud SQL's port on the instance's private
/// address.
fn forward_to_the_instance() -> ForwardSpec {
    ForwardSpec { kind: ForwardKind::Local, bind_address: "127.0.0.1".into(), port: 0, target_host: PRIVATE_IP.into(), target_port: 3307 }
}

/// The name the certificate of the instance of `orders()` is checked against.
fn the_instances_name() -> ServerName<'static> {
    ServerName::try_from(dns_name("orders-pg")).unwrap()
}

/// The database user a connection got ready as, or why it could not.
fn user(prepared: Result<Prepared, NotReady>) -> Result<String, NotReady> {
    prepared.map(|prepared| prepared.iam_user)
}

#[test]
fn the_certificate_is_renewed_four_minutes_before_it_expires() {
    assert_eq!(REFRESH_AHEAD, Duration::from_secs(4 * 60));
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    assert_eq!(user(upstream.prepare(&orders(), &cancel)), Ok(IAM_USER.to_string()));
    assert_eq!(cloud.certificates(), 1);
    // The certificate is good for an hour: it is used until four minutes before that.
    cloud.clock.at(HOUR - REFRESH_AHEAD - Duration::from_secs(1));
    assert_eq!(user(upstream.prepare(&orders(), &cancel)), Ok(IAM_USER.to_string()));
    assert_eq!(cloud.certificates(), 1, "still the first certificate");
    cloud.clock.at(HOUR - REFRESH_AHEAD);
    assert_eq!(user(upstream.prepare(&orders(), &cancel)), Ok(IAM_USER.to_string()));
    assert_eq!(cloud.certificates(), 2, "renewed four minutes ahead");
    // The new one came at that moment and is good for an hour from then.
    let renewed = HOUR - REFRESH_AHEAD;
    cloud.clock.at(renewed + HOUR - REFRESH_AHEAD - Duration::from_secs(1));
    upstream.prepare(&orders(), &cancel).unwrap();
    assert_eq!(cloud.certificates(), 2);
    cloud.clock.at(renewed + HOUR - REFRESH_AHEAD);
    upstream.prepare(&orders(), &cancel).unwrap();
    assert_eq!(cloud.certificates(), 3);
    assert!(cloud.owner.asked().is_empty() && cloud.looked() == 0, "a database without a grant check asks nothing of PAM");
}

#[test]
fn the_grant_is_checked_again_every_five_minutes_and_when_it_ends() {
    let cloud = Cloud::new(FakeOwner::default());
    // Given ten minutes ago for thirty: twenty minutes left.
    *cloud.pam.held.lock().unwrap() = vec![cloud.pam.grant("ACTIVE", t0() - 10 * MINUTE)];
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    upstream.prepare(&guarded(), &cancel).unwrap();
    assert_eq!(cloud.looked(), 1);
    cloud.clock.at(5 * MINUTE - Duration::from_secs(1));
    upstream.prepare(&guarded(), &cancel).unwrap();
    assert_eq!(cloud.looked(), 1, "a check younger than five minutes is trusted");
    cloud.clock.at(5 * MINUTE);
    upstream.prepare(&guarded(), &cancel).unwrap();
    assert_eq!(cloud.looked(), 2, "checked again after five minutes");
    cloud.clock.at(19 * MINUTE);
    upstream.prepare(&guarded(), &cancel).unwrap();
    assert_eq!(cloud.looked(), 3);
    // Past its end the grant is checked by every connection, even while PAM has not ended it yet.
    cloud.clock.at(20 * MINUTE);
    upstream.prepare(&guarded(), &cancel).unwrap();
    upstream.prepare(&guarded(), &cancel).unwrap();
    assert_eq!(cloud.looked(), 5);
    assert!(cloud.owner.asked().is_empty(), "the grant held throughout");
    assert_eq!(cloud.certificates(), 1, "and the certificate was kept");
}

#[test]
fn a_grant_that_ended_drops_the_cached_certificate_and_asks_again() {
    let cloud = Cloud::new(FakeOwner::typing(&[ANSWER]));
    *cloud.pam.held.lock().unwrap() = vec![cloud.pam.grant("ACTIVE", t0() - 10 * MINUTE)];
    let ports = DatabasePorts::new(Arc::new(cloud.upstream()));
    let port = running(&ports, &guarded());
    let mut open = App::signed_in(port);
    open.round_trip(b"select 1");
    assert!(cloud.owner.asked().is_empty(), "the grant was held");
    assert_eq!(cloud.certificates(), 1);
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(instance_at(PUBLIC_IP), ServerName::try_from(dns_name("orders-pg")).unwrap())], "the instance, by its name");
    // The grant ends; the certificate, good for an hour, would still be.
    *cloud.pam.held.lock().unwrap() = vec![cloud.pam.grant("ENDED", t0() - 10 * MINUTE)];
    cloud.clock.at(21 * MINUTE);
    let mut next = App::signed_in(port);
    let asked = cloud.owner.asked();
    assert_eq!(asked.len(), 1, "the person was asked for a grant");
    assert_eq!(asked[0].kind, QuestionKind::Grant);
    assert_eq!(cloud.pam.created.load(Ordering::SeqCst), 1, "and one was requested");
    assert_eq!(*cloud.remembered.lock().unwrap(), vec![(OPERATE.to_string(), "Check unpaid orders".to_string(), 1800)]);
    assert_eq!(cloud.certificates(), 2, "the certificate had under the ended grant was not used again");
    next.round_trip(b"select 2");
    // The connection that was open all along goes on.
    open.round_trip(b"select 3");
    assert_eq!(cloud.received.lock().unwrap().len(), 2);
}

#[test]
fn another_account_or_another_database_is_not_served_what_was_had_for_the_one_before() {
    let cloud = Cloud::new(FakeOwner::default());
    *cloud.pam.held.lock().unwrap() = vec![cloud.pam.grant("ACTIVE", t0() - 10 * MINUTE)];
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    // Saved without an account: gcloud's active account signs in.
    let active = SavedDatabase { account: None, ..guarded() };
    assert_eq!(user(upstream.prepare(&active, &cancel)), Ok(IAM_USER.to_string()));
    assert_eq!((cloud.looked(), cloud.certificates()), (1, 1));
    // The token source's credentials change under the active account, which reads the same: the certificate that replaces the first one
    // near its end comes for another account, so the grant, checked for the account before, is checked again before it is used.
    *cloud.admin.account.lock().unwrap() = "ops@example.com".into();
    *cloud.pam.held.lock().unwrap() = vec![cloud.pam.grant("ACTIVE", t0() + 50 * MINUTE)];
    cloud.clock.at(HOUR - REFRESH_AHEAD);
    assert_eq!(user(upstream.prepare(&active, &cancel)), Ok("ops@example.com".to_string()));
    assert_eq!(cloud.certificates(), 2);
    assert_eq!(cloud.looked(), 3, "checked when its time was up, and again for the new account");
    upstream.prepare(&active, &cancel).unwrap();
    assert_eq!((cloud.looked(), cloud.certificates()), (3, 2), "then trusted as before");
    // The same database saved anew for another instance gets nothing that was had for the one before, however fresh.
    let moved = SavedDatabase { instance: "billing-pg".into(), ..active.clone() };
    upstream.prepare(&moved, &cancel).unwrap();
    assert_eq!((cloud.looked(), cloud.certificates()), (4, 3));
}

#[test]
fn a_changed_account_drops_the_cached_certificate() {
    let cloud = Cloud::new(FakeOwner::default());
    *cloud.pam.held.lock().unwrap() = vec![cloud.pam.grant("ACTIVE", t0() - 10 * MINUTE)];
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    // Saved without an account: gcloud's active account signs in.
    let active = SavedDatabase { account: None, ..guarded() };
    assert_eq!(user(upstream.prepare(&active, &cancel)), Ok(IAM_USER.to_string()));
    upstream.prepare(&active, &cancel).unwrap();
    assert_eq!((cloud.looked(), cloud.certificates()), (1, 1), "kept while the account stays");
    // The person makes ops@example.com gcloud's active account. The certificate is fresh, but frank's: it goes, and so does the grant check.
    *cloud.active.lock().unwrap() = Some("ops@example.com".into());
    *cloud.admin.account.lock().unwrap() = "ops@example.com".into();
    cloud.clock.at(MINUTE);
    assert_eq!(user(upstream.prepare(&active, &cancel)), Ok("ops@example.com".to_string()));
    assert_eq!((cloud.looked(), cloud.certificates()), (2, 2), "the grant was checked and a certificate fetched for ops@example.com");
    upstream.prepare(&active, &cancel).unwrap();
    assert_eq!((cloud.looked(), cloud.certificates()), (2, 2), "then kept for it");
    // A database saved with an account signs in as that one, whatever gcloud's active account is.
    let saved_with_one = guarded();
    upstream.prepare(&saved_with_one, &cancel).unwrap();
    *cloud.active.lock().unwrap() = Some("frank@example.com".into());
    upstream.prepare(&saved_with_one, &cancel).unwrap();
    assert_eq!(cloud.certificates(), 3, "one certificate for the database saved with frank@example.com");
}

#[test]
fn a_cancel_request_through_cloud_sql_uses_the_cached_certificate() {
    let cloud = Cloud::new(FakeOwner::default());
    let ports = DatabasePorts::new(Arc::new(cloud.upstream()));
    let port = running(&ports, &orders());
    // Before any connection there is no certificate: the request is dropped.
    let mut early = App::connect(port);
    early.send(&cancel_request());
    assert!(early.closed());
    assert!(cloud.dialled.lock().unwrap().is_empty());
    App::signed_in(port).round_trip(b"select pg_sleep(60)");
    let mut cancel = App::connect(port);
    cancel.send(&cancel_request());
    assert!(cancel.closed());
    assert_eq!(cloud.received.lock().unwrap().last(), Some(&cancel_request()));
    assert_eq!(cloud.certificates(), 1, "no certificate is fetched for a cancel request");
}

#[test]
fn a_failed_dial_is_followed_by_a_new_certificate() {
    let cloud = Cloud::new(FakeOwner::default());
    let ports = DatabasePorts::new(Arc::new(cloud.upstream()));
    let port = running(&ports, &orders());
    // Cloud SQL refuses the first dial, as it does a certificate it does not take.
    *cloud.refusing.lock().unwrap() = 1;
    let mut refused = App::connect(port);
    refused.startup(&[("user", "frank"), ("database", "orders")]);
    refused.asked_for_password();
    refused.password(PASSWORD);
    assert_eq!(refused.error(), ("08006".to_string(), format!("Lunport could not reach {CONNECTION}: Cloud SQL refused the connection.")));
    assert_eq!(cloud.certificates(), 1);
    // The next connection does not dial with that certificate again: it gets a new one, and gets in.
    App::signed_in(port).round_trip(b"select 1");
    assert_eq!(cloud.certificates(), 2);
    assert_eq!(cloud.dialled.lock().unwrap().len(), 2);
}

#[test]
fn a_host_route_dials_the_forward_on_loopback() {
    let cloud = Cloud::new(FakeOwner::default());
    // An instance without a DNS name: its certificate is checked against `project:instance`, however the connection reaches it.
    cloud.admin.nameless.store(true, Ordering::SeqCst);
    let ports = DatabasePorts::new(Arc::new(cloud.upstream()));
    let port = running(&ports, &routed());
    App::signed_in(port).round_trip(b"select 1");
    assert_eq!(cloud.link.opened(), vec![ROUTE_HOST.to_string()], "one session, to web-1 by its id");
    // The session forwards a port of 127.0.0.1 to port 3307 of the instance's private address, and the connection dials that port. The
    // certificate is still checked against the instance's name, not the address.
    assert_eq!(cloud.link.end(0).forwards(), vec![forward_to_the_instance()]);
    let identity = ServerIdentity { dns_name: None, project: "acme-prod-123456".into(), instance: "orders-pg".into() };
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(loopback(FORWARD_PORT), server_name(&identity))]);
    assert_eq!(cloud.certificates(), 1);
}

#[test]
fn a_database_saved_anew_over_another_route_is_dialled_at_the_address_of_its_new_one() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    let name = the_instances_name;
    let public = upstream.prepare(&orders(), &cancel).unwrap();
    let _dialling = upstream.connect(ID, Some(public.material));
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(instance_at(PUBLIC_IP), name())]);
    // Saved anew to go through a host, it is not served what was had for its public address, fresh as that is: it reaches the private
    // address through the host.
    let through_a_host = upstream.prepare(&routed(), &cancel).unwrap();
    assert_ne!(through_a_host.material, public.material);
    assert_eq!(cloud.certificates(), 2);
    let _dialling = upstream.connect(ID, Some(through_a_host.material));
    assert_eq!(cloud.link.end(0).forwards(), vec![forward_to_the_instance()]);
    // And back to its public address, as it was: the session to the host goes with the route it had.
    let public_again = upstream.prepare(&orders(), &cancel).unwrap();
    assert_eq!(cloud.certificates(), 3);
    assert!(soon(|| cloud.link.end(0).closed()), "the session to the host is closed");
    let _dialling = upstream.connect(ID, Some(public_again.material));
    assert_eq!(
        *cloud.dialled.lock().unwrap(),
        vec![(instance_at(PUBLIC_IP), name()), (loopback(FORWARD_PORT), name()), (instance_at(PUBLIC_IP), name())]
    );
}

#[test]
fn a_public_route_opens_no_session() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let prepared = upstream.prepare(&orders(), &CancelToken::default()).unwrap();
    let _dialling = upstream.connect(ID, Some(prepared.material));
    assert!(cloud.link.opened().is_empty(), "no host was connected to");
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(instance_at(PUBLIC_IP), the_instances_name())]);
}

#[test]
fn connections_share_one_session_while_it_lives() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    for _ in 0..2 {
        let prepared = upstream.prepare(&routed(), &cancel).unwrap();
        let _dialling = upstream.connect(ID, Some(prepared.material));
    }
    assert_eq!(cloud.link.opened(), vec![ROUTE_HOST.to_string()], "one session");
    assert_eq!(cloud.link.end(0).forwards(), vec![forward_to_the_instance()], "and one forward on it");
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(loopback(FORWARD_PORT), the_instances_name()); 2]);
    assert!(!cloud.link.end(0).closed());
}

#[test]
fn a_dropped_session_is_opened_again_by_the_next_connection() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    upstream.prepare(&routed(), &cancel).unwrap();
    cloud.link.end(0).lose();
    let prepared = upstream.prepare(&routed(), &cancel).unwrap();
    assert_eq!(cloud.link.opened(), vec![ROUTE_HOST.to_string(); 2], "the next connection opens a second session");
    assert!(soon(|| cloud.link.end(0).closed()), "and the first is closed");
    assert_eq!(cloud.link.end(1).forwards(), vec![forward_to_the_instance()], "the forward goes on the second one");
    let _dialling = upstream.connect(ID, Some(prepared.material));
    assert_eq!(cloud.dialled.lock().unwrap().last(), Some(&(loopback(FORWARD_PORT), the_instances_name())));
    assert_eq!(cloud.certificates(), 1, "the certificate stays: it was not the session's");
}

#[test]
fn a_failed_open_names_the_host() {
    let cloud = Cloud::new(FakeOwner::default());
    cloud.link.failures.lock().unwrap().push_back("Permission denied (publickey).".into());
    let upstream = cloud.upstream();
    let error = user(upstream.prepare(&routed(), &CancelToken::default())).unwrap_err();
    assert_eq!(error, NotReady::Failed("Could not connect through web-1: Permission denied (publickey).".into()));
    assert_eq!(cloud.certificates(), 0, "no certificate is fetched for a connection that cannot get through");
}

#[test]
fn a_route_host_missing_from_the_library_is_refused() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    // The host it was saved with has been deleted from the library since.
    let orphaned = SavedDatabase { via_host: Some("00000000000000ff".into()), ..routed() };
    let error = user(upstream.prepare(&orphaned, &CancelToken::default())).unwrap_err();
    assert_eq!(error, NotReady::Failed("Orders connects through a host that is no longer in your library. Choose another host in its settings.".into()));
    assert!(cloud.link.opened().is_empty(), "nothing was connected to");
}

#[test]
fn a_session_opened_after_cancel_is_closed() {
    let cloud = Cloud::new(FakeOwner::default());
    // The port stops while the session opens: the connection is cancelled, and the session opens anyway.
    cloud.link.cancels.store(true, Ordering::SeqCst);
    let upstream = cloud.upstream();
    let error = user(upstream.prepare(&routed(), &CancelToken::default())).unwrap_err();
    assert_eq!(error, NotReady::Failed("The connection was cancelled.".into()));
    assert!(soon(|| cloud.link.end(0).closed()), "the session is closed");
    assert!(locked(&locked(&upstream.routes)[ID].path).is_none(), "and the route keeps no path");
}

#[test]
fn release_closes_the_session() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    upstream.prepare(&routed(), &cancel).unwrap();
    upstream.release(ID);
    assert!(soon(|| cloud.link.end(0).closed()), "the session is closed");
    assert!(cloud.link.end(0).stopped(), "after its forward was stopped");
    upstream.prepare(&routed(), &cancel).unwrap();
    assert_eq!(cloud.link.opened().len(), 2, "the next connection opens a new one");
    assert!(!cloud.link.end(1).closed());
}

#[test]
fn two_databases_through_one_host_open_a_session_each() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    let billing = SavedDatabase { id: "00000000000000d2".into(), name: "Billing".into(), instance: "billing-pg".into(), ..routed() };
    upstream.prepare(&routed(), &cancel).unwrap();
    upstream.prepare(&billing, &cancel).unwrap();
    assert_eq!(cloud.link.opened(), vec![ROUTE_HOST.to_string(); 2], "a session each, both to web-1");
    assert_eq!(cloud.link.end(0).forwards(), vec![forward_to_the_instance()]);
    assert_eq!(cloud.link.end(1).forwards(), vec![forward_to_the_instance()]);
    // One of them stops: the other's session stays.
    upstream.release(ID);
    assert!(soon(|| cloud.link.end(0).closed()));
    assert!(!cloud.link.end(1).closed());
}

#[test]
fn a_forward_that_cannot_open_names_the_instance_and_the_host() {
    let cloud = Cloud::new(FakeOwner::default());
    *cloud.link.refusal.lock().unwrap() = Some(SessionError::Channel("Could not listen on 127.0.0.1:0: Too many open files (os error 24)".into()));
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    let error = user(upstream.prepare(&routed(), &cancel)).unwrap_err();
    assert_eq!(
        error,
        NotReady::Failed(format!("Could not reach {CONNECTION} through web-1: SSH error: Could not listen on 127.0.0.1:0: Too many open files (os error 24)"))
    );
    // The session stays up; the next connection's forward opens, but on no port, and is not kept either.
    let end = cloud.link.end(0);
    *end.refusal.lock().unwrap() = None;
    *end.port.lock().unwrap() = 0;
    let error = user(upstream.prepare(&routed(), &cancel)).unwrap_err();
    assert_eq!(error, NotReady::Failed(format!("Could not reach {CONNECTION} through web-1: No local port was opened for it.")));
    assert!(soon(|| end.stopped()), "the forward without a port is stopped");
    assert_eq!(cloud.link.opened().len(), 1, "on the one session");
    assert!(!end.closed());
}

#[test]
fn connect_without_an_open_path_asks_to_connect_again() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let prepared = upstream.prepare(&routed(), &CancelToken::default()).unwrap();
    // The forward's listener ends before the connection dials it.
    cloud.link.end(0).running.store(false, Ordering::SeqCst);
    let dialling = upstream.connect(ID, Some(prepared.material));
    assert_eq!(dialling.material, None, "the certificate was not dialled with, so it is not taken back");
    let error = dialling.stream.now_or_never().expect("it fails at once").err().expect("it fails");
    assert_eq!(error.to_string(), "the connection through the host is not open. Connect again.");
    assert!(cloud.dialled.lock().unwrap().is_empty(), "nothing was dialled");
}

/// The error a connection through a host fails with when its dial fails with `kind` and `words`, while the path's forward reports
/// `forward_error` as its latest.
fn dial_error_through_the_host(kind: io::ErrorKind, words: &str, forward_error: Option<&str>) -> io::Error {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let prepared = upstream.prepare(&routed(), &CancelToken::default()).unwrap();
    *cloud.link.end(0).forward_error.lock().unwrap() = forward_error.map(str::to_string);
    *cloud.failing.lock().unwrap() = Some((kind, words.to_string()));
    let error = upstream.connect(ID, Some(prepared.material)).stream.now_or_never().expect("it fails at once").err().expect("it fails");
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(loopback(FORWARD_PORT), the_instances_name())]);
    error
}

#[test]
fn a_host_route_dial_error_names_the_host_not_the_loopback() {
    // The host could not open the way to the instance, and the dial, which sees only the loopback end of the forward, gave up.
    let words = format!("The TLS handshake with Cloud SQL at {} did not finish within 10s.", loopback(FORWARD_PORT));
    let error = dial_error_through_the_host(io::ErrorKind::TimedOut, &words, Some("Channel open failure: connect failed"));
    assert_eq!(error.to_string(), format!("web-1 could not reach {PRIVATE_IP}:3307: Channel open failure: connect failed"));
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "of the kind the dial failed with");
}

#[test]
fn a_host_route_dial_error_without_a_forward_error_says_cloud_sql_did_not_answer() {
    // The dial gave up at the loopback end of the forward, which its words name.
    let words = format!("Cloud SQL did not answer at {} within 10s.", loopback(FORWARD_PORT));
    let error = dial_error_through_the_host(io::ErrorKind::TimedOut, &words, None);
    assert_eq!(error.to_string(), format!("Cloud SQL at {PRIVATE_IP}:3307 did not answer through web-1."));
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "of the kind the dial failed with");
    // The forward ended the connection during the TLS handshake: not as Cloud SQL closing it.
    let error = dial_error_through_the_host(io::ErrorKind::UnexpectedEof, "tls handshake eof", None);
    assert_eq!(error.to_string(), format!("Cloud SQL at {PRIVATE_IP}:3307 did not answer through web-1."));
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
}

#[test]
fn a_tls_failure_through_a_host_keeps_its_reason() {
    // The instance's certificate is not made out to the name it is checked against. The reason names no address, and it is what the person
    // needs to see.
    let error = dial_error_through_the_host(io::ErrorKind::InvalidData, "invalid peer certificate: NotValidForName", None);
    assert_eq!(error.to_string(), "invalid peer certificate: NotValidForName");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_refused_dial_through_a_host_keeps_its_reason() {
    // The forward's listener went away after the connection looked it up.
    let error = dial_error_through_the_host(io::ErrorKind::ConnectionRefused, "Connection refused (os error 61)", None);
    assert_eq!(error.to_string(), "Connection refused (os error 61)");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
}

#[test]
fn an_app_is_told_which_host_could_not_reach_the_instance() {
    let cloud = Cloud::new(FakeOwner::default());
    let ports = DatabasePorts::new(Arc::new(cloud.upstream()));
    let port = running(&ports, &routed());
    App::signed_in(port).round_trip(b"select 1");
    // The host can no longer reach the instance. The forward closes each connection it takes, which the dial reads as an end of file in
    // the TLS handshake; the app is not told that Cloud SQL closed it.
    *cloud.link.end(0).forward_error.lock().unwrap() = Some("Channel open failure: connect failed".into());
    *cloud.failing.lock().unwrap() = Some((io::ErrorKind::UnexpectedEof, "tls handshake eof".into()));
    let mut app = App::connect(port);
    app.startup(&[("user", "frank"), ("database", "orders")]);
    app.asked_for_password();
    app.password(PASSWORD);
    let sentence = format!("Lunport could not reach {CONNECTION}: web-1 could not reach {PRIVATE_IP}:3307: Channel open failure: connect failed.");
    assert_eq!(app.error(), ("08006".to_string(), sentence));
}

#[test]
fn an_app_is_told_a_connection_google_could_not_get_ready_from_a_refused_sign_in() {
    let cloud = Cloud::new(FakeOwner::default());
    let ports = DatabasePorts::new(Arc::new(cloud.upstream()));
    let port = running(&ports, &orders());
    let refused = |error: GcpError| {
        *cloud.admin.failing.lock().unwrap() = Some(error);
        let mut app = App::connect(port);
        app.startup(&[("user", "frank"), ("database", "orders")]);
        app.asked_for_password();
        app.password(PASSWORD);
        app.error()
    };
    // No such instance: a connection failure.
    let unknown = GcpError::Refused { api: "Cloud SQL Admin", message: format!("Cloud SQL has no instance {CONNECTION}.") };
    assert_eq!(refused(unknown), ("08006".to_string(), format!("Cloud SQL Admin refused the request: Cloud SQL has no instance {CONNECTION}.")));
    // An account that may not connect: a refused sign-in.
    let denied = GcpError::Denied { api: "Cloud SQL Admin", status: 403, account: IAM_USER.into() };
    assert_eq!(refused(denied), ("28000".to_string(), "frank@example.com may not call the Cloud SQL Admin API (HTTP 403).".to_string()));
    assert!(cloud.dialled.lock().unwrap().is_empty(), "Cloud SQL was not dialled");
}

#[test]
fn connections_that_start_together_share_one_certificate() {
    let cloud = Cloud::new(FakeOwner::default());
    cloud.admin.holding.store(true, Ordering::SeqCst);
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    let users = std::thread::scope(|scope| {
        let first = scope.spawn(|| upstream.prepare(&orders(), &cancel));
        wait_until("the first connection fetches", || cloud.certificates() == 1);
        let second = scope.spawn(|| upstream.prepare(&orders(), &cancel));
        // Were the second not waiting for the first one's fetch, it would be fetching too by now.
        let end = Instant::now() + Duration::from_millis(300);
        while cloud.admin.settings.load(Ordering::SeqCst) < 2 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(2));
        }
        cloud.admin.release();
        (user(first.join().unwrap()), user(second.join().unwrap()))
    });
    assert_eq!(users, (Ok(IAM_USER.to_string()), Ok(IAM_USER.to_string())));
    assert_eq!(cloud.admin.settings.load(Ordering::SeqCst), 1, "one fetch");
    assert_eq!(cloud.certificates(), 1, "one certificate for both");
}

#[test]
fn a_late_forget_leaves_newer_material_in_place() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    let first = upstream.prepare(&orders(), &cancel).unwrap().material;
    assert_eq!(upstream.connect(ID, Some(first)).material, Some(first));
    // A connection dials with it and waits for Cloud SQL's answer; meanwhile the certificate is renewed for the next connections.
    cloud.clock.at(HOUR - REFRESH_AHEAD);
    let second = upstream.prepare(&orders(), &cancel).unwrap().material;
    assert_ne!(first, second);
    // The first connection fails late: only what it dialled with goes.
    upstream.forget(ID, first);
    assert_eq!(upstream.connect(ID, Some(second)).material, Some(second));
    assert_eq!(upstream.prepare(&orders(), &cancel).unwrap().material, second);
    assert_eq!(cloud.certificates(), 2, "nothing was fetched for the failure of the connection before");
    // A failure with the newer material takes that back.
    upstream.forget(ID, second);
    assert_eq!(upstream.connect(ID, None).material, None);
}

#[test]
fn a_connection_dials_the_material_its_preparing_got() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    // Saved without an account: gcloud's active account signs in.
    let active = SavedDatabase { account: None, ..orders() };
    let frank = upstream.prepare(&active, &cancel).unwrap();
    assert_eq!(frank.iam_user, IAM_USER);
    // Before that connection dials, the person makes ops@example.com gcloud's active account, and another connection gets ready as ops.
    *cloud.active.lock().unwrap() = Some("ops@example.com".into());
    *cloud.admin.account.lock().unwrap() = "ops@example.com".into();
    let ops = upstream.prepare(&active, &cancel).unwrap();
    assert_eq!(ops.iam_user, "ops@example.com");
    assert_ne!(ops.material, frank.material);
    // The first connection would sign in as frank@example.com with ops@example.com's certificate: it dials nothing and is told to
    // connect again, and the material of the second stays.
    let stale = upstream.connect(ID, Some(frank.material));
    assert_eq!(stale.material, None);
    let error = stale.stream.now_or_never().expect("it fails at once").err().expect("it fails");
    assert_eq!(error.to_string(), "no certificate is ready for it. Connect again.");
    assert!(cloud.dialled.lock().unwrap().is_empty(), "nothing was dialled");
    // The second dials with its own, and so does a cancel request, which takes the material the database has now.
    assert_eq!(upstream.connect(ID, Some(ops.material)).material, Some(ops.material));
    assert_eq!(upstream.connect(ID, None).material, Some(ops.material));
    assert_eq!(cloud.dialled.lock().unwrap().len(), 2);
}

#[test]
fn a_prepare_that_finishes_after_the_database_changed_leaves_nothing_for_it() {
    let cloud = Cloud::new(FakeOwner::default());
    cloud.admin.holding.store(true, Ordering::SeqCst);
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    let prod = orders();
    // The same database, stopped, saved anew as a dev database on another instance, and started again.
    let dev = SavedDatabase { environment: DatabaseEnvironment::Dev, instance: "orders-dev-pg".into(), ..orders() };
    std::thread::scope(|scope| {
        // A connection of the port before is still on its way: its fetch for the prod instance is half done.
        let stale = scope.spawn(|| upstream.prepare(&prod, &cancel));
        wait_until("the stale fetch is under way", || cloud.certificates() == 1);
        assert_eq!(user(upstream.prepare(&dev, &cancel)), Ok(IAM_USER.to_string()), "a connection to the new database gets ready meanwhile");
        cloud.admin.release();
        assert_eq!(user(stale.join().unwrap()), Ok(IAM_USER.to_string()));
    });
    assert_eq!(cloud.certificates(), 2);
    // The new database's connections dial the dev instance: the stale fetch left nothing for them.
    cloud.dialled.lock().unwrap().clear();
    let _dialling = upstream.connect(ID, None);
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(instance_at(PUBLIC_IP), ServerName::try_from(dns_name("orders-dev-pg")).unwrap())]);
}

#[test]
fn a_stopped_or_deleted_database_keeps_no_password_or_certificate() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = Arc::new(cloud.upstream());
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    App::signed_in(port).round_trip(b"select 1");
    assert_eq!(*ports.held_password(ID), PASSWORD);
    assert!(locked(&upstream.routes)[ID].kept.lock().unwrap().dial.is_some(), "the certificate is kept while the port runs");
    ports.stop(ID);
    wait_until("the port stopped", || ports.live(ID).phase == DatabasePhase::Stopped);
    assert!(ports.held_password(ID).is_empty(), "the stopped port keeps no password");
    assert!(!locked(&upstream.routes).contains_key(ID), "nor what its connections had: the certificate and its key");
    // A database that does not run is deleted: what was had for it goes too.
    upstream.prepare(&orders(), &CancelToken::default()).unwrap();
    assert!(locked(&upstream.routes).contains_key(ID));
    ports.release(ID);
    assert!(!locked(&upstream.routes).contains_key(ID));
}

#[test]
fn a_grant_the_person_requests_is_asked_for_once_remembered_and_then_held_for_the_connections() {
    let cloud = Cloud::new(FakeOwner::typing(&[ANSWER]));
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    assert_eq!(upstream.request_grant(&guarded(), &cancel), Ok(()));
    let asked = cloud.owner.asked();
    assert_eq!(asked.len(), 1, "the person was asked once");
    assert_eq!(asked[0].kind, QuestionKind::Grant);
    assert_eq!(cloud.pam.created.load(Ordering::SeqCst), 1, "and one grant was requested with the answer");
    assert_eq!(*cloud.remembered.lock().unwrap(), vec![(OPERATE.to_string(), "Check unpaid orders".to_string(), 1800)], "what they answered is remembered on this device");
    // The grant is held now: the next connection to the database asks nothing more and requests nothing.
    assert!(user(upstream.prepare(&guarded(), &cancel)).is_ok());
    assert_eq!(cloud.owner.asked().len(), 1);
    assert_eq!(cloud.pam.created.load(Ordering::SeqCst), 1);
}

#[test]
fn a_grant_request_that_gets_no_answer_requests_nothing_and_says_how_to_by_hand() {
    // The person is not at the window: the question ends without an answer.
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let error = upstream.request_grant(&guarded(), &CancelToken::default()).unwrap_err();
    assert!(error.starts_with("No active Privileged Access Manager grant for prod-operate on acme-prod-123456. Request one (for example gcloud pam grants create"), "{error}");
    assert_eq!(cloud.owner.asked().len(), 1);
    assert_eq!(cloud.pam.created.load(Ordering::SeqCst), 0);
    assert!(cloud.remembered.lock().unwrap().is_empty());
}

#[test]
fn a_database_without_a_grant_check_is_refused_before_the_person_is_asked() {
    let cloud = Cloud::new(FakeOwner::typing(&[ANSWER]));
    let upstream = cloud.upstream();
    assert_eq!(upstream.request_grant(&orders(), &CancelToken::default()), Err("This database requires no grant.".to_string()));
    assert!(cloud.owner.asked().is_empty());
    assert_eq!(cloud.looked(), 0);
}

/// The person at the Request-a-grant window, who answers once `followers` more requests wait behind the question.
struct Patient {
    inner: Arc<FakeOwner>,
    gates: Arc<GrantGates>,
    followers: usize,
}

impl Owner for Patient {
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        let end = Instant::now() + Duration::from_secs(5);
        while self.gates.waiting() < self.followers && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(2));
        }
        self.inner.ask(kind, text, echo, deadline)
    }

    fn host_key_notice(&self, text: &str) {
        self.inner.host_key_notice(text);
    }

    fn banner(&self, text: &str) {
        self.inner.banner(text);
    }
}

#[test]
fn a_grant_asked_for_on_the_page_and_by_a_connection_at_once_is_asked_for_once() {
    let cloud = Cloud::new(FakeOwner::typing(&[ANSWER]));
    let mut upstream = cloud.upstream();
    let (gates, owner) = (Arc::clone(&upstream.gates), Arc::clone(&cloud.owner));
    // Whoever leads is answered only once the other waits behind the question.
    upstream.make_owner = Arc::new(move |_: &CancelToken| -> Box<dyn Owner + Send> {
        Box::new(Patient { inner: Arc::clone(&owner), gates: Arc::clone(&gates), followers: 1 })
    });
    let cancel = CancelToken::default();
    let (page, connection) = std::thread::scope(|scope| {
        let page = scope.spawn(|| upstream.request_grant(&guarded(), &cancel));
        let connection = scope.spawn(|| upstream.prepare(&guarded(), &cancel));
        (page.join().unwrap(), connection.join().unwrap())
    });
    assert_eq!(page, Ok(()));
    assert_eq!(user(connection), Ok(IAM_USER.to_string()));
    assert_eq!(cloud.owner.asked().len(), 1, "one question for both");
    assert_eq!(cloud.pam.created.load(Ordering::SeqCst), 1, "one request for both");
    assert_eq!(cloud.remembered.lock().unwrap().len(), 1, "one memory for both");
}
