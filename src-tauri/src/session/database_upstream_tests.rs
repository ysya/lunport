//! `CloudSqlUpstream` tried against a scripted Google, a certificate authority made for the test and a clock of the test's own, alone and
//! behind a port that the apps connect to.

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
use crate::sync::databases::tests::{state, ROUTE_HOST};
use crate::sync::databases::{DatabaseEnvironment, DatabaseNetwork};
use crate::sync::transports::PamCheck;
use futures_util::FutureExt;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
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
            dns_name: Some(dns_name(&at.instance)),
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

/// Google, the clock and the person a `CloudSqlUpstream` is tried against, and what it dialled.
struct Cloud {
    clock: Clock,
    pam: Arc<Pam>,
    admin: Arc<Admin>,
    /// gcloud's active account.
    active: Arc<Mutex<Option<String>>>,
    owner: Arc<FakeOwner>,
    remembered: Arc<Mutex<Vec<(String, String, u32)>>>,
    dialled: Arc<Mutex<Vec<(SocketAddr, ServerName<'static>)>>>,
    /// How many of the next dials Cloud SQL refuses.
    refusing: Arc<Mutex<usize>>,
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
            dialled: Arc::default(),
            refusing: Arc::default(),
            received: Arc::default(),
        }
    }

    /// The upstream over them. It dials the fake Cloud SQL, and records where it dialled.
    fn upstream(&self) -> CloudSqlUpstream {
        let owner = Arc::clone(&self.owner);
        let clock = self.clock.clone();
        let active = Arc::clone(&self.active);
        let remembered = Arc::clone(&self.remembered);
        let (dialled, refusing, received) = (Arc::clone(&self.dialled), Arc::clone(&self.refusing), Arc::clone(&self.received));
        CloudSqlUpstream {
            gcp: self.pam.clone(),
            sql: self.admin.clone(),
            gates: Arc::new(GrantGates::default()),
            make_owner: Arc::new(move |_: &CancelToken| -> Box<dyn Owner + Send> { Box::new(Shared(Arc::clone(&owner))) }),
            now: Arc::new(move || clock.now()),
            active_account: Arc::new(move || active.lock().unwrap().clone()),
            library: Arc::new(|| -> Result<SyncStateV3, String> { Ok(state()) }),
            remember: Arc::new(move |name: &str, justification: &str, secs: u32| {
                remembered.lock().unwrap().push((name.to_string(), justification.to_string(), secs));
            }),
            dial: Arc::new(move |address: SocketAddr, _config: Arc<ClientConfig>, name: ServerName<'static>| -> BoxFuture<'static, io::Result<BoxStream>> {
                dialled.lock().unwrap().push((address, name));
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
fn a_database_reached_through_a_host_is_dialled_at_the_instances_private_address() {
    let cloud = Cloud::new(FakeOwner::default());
    let ports = DatabasePorts::new(Arc::new(cloud.upstream()));
    let port = running(&ports, &routed());
    App::signed_in(port).round_trip(b"select 1");
    // Port 3307 of the private address, and the certificate is still checked against the instance's name, not the address.
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(instance_at(PRIVATE_IP), ServerName::try_from(dns_name("orders-pg")).unwrap())]);
    assert_eq!(cloud.certificates(), 1);
}

#[test]
fn a_database_saved_anew_over_another_route_is_dialled_at_the_address_of_its_new_one() {
    let cloud = Cloud::new(FakeOwner::default());
    let upstream = cloud.upstream();
    let cancel = CancelToken::default();
    let name = || ServerName::try_from(dns_name("orders-pg")).unwrap();
    let public = upstream.prepare(&orders(), &cancel).unwrap();
    let _dialling = upstream.connect(ID, Some(public.material));
    assert_eq!(*cloud.dialled.lock().unwrap(), vec![(instance_at(PUBLIC_IP), name())]);
    // Saved anew to go through a host, it is not served what was had for its public address, fresh as that is.
    let through_a_host = upstream.prepare(&routed(), &cancel).unwrap();
    assert_ne!(through_a_host.material, public.material);
    assert_eq!(cloud.certificates(), 2);
    let _dialling = upstream.connect(ID, Some(through_a_host.material));
    // And back to its public address, as it was.
    let public_again = upstream.prepare(&orders(), &cancel).unwrap();
    assert_eq!(cloud.certificates(), 3);
    let _dialling = upstream.connect(ID, Some(public_again.material));
    assert_eq!(
        *cloud.dialled.lock().unwrap(),
        vec![(instance_at(PUBLIC_IP), name()), (instance_at(PRIVATE_IP), name()), (instance_at(PUBLIC_IP), name())]
    );
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
