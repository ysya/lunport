//! What a connection to a saved database needs from Google before it is dialled: whether a Privileged Access Manager grant is needed and
//! held, a grant requested the way a host's is (one question for the connections that need the same grant, in Lunport's Request-a-grant
//! window), and the connection material: the instance's connect settings and a client certificate Cloud SQL signs for a key made for the
//! connection.
//!
//! Every call here blocks (PAM and the Cloud SQL Admin API are network round trips, and a grant request waits for the person), so they run
//! on a blocking thread, as `SqlAdmin` and `TokenSource` do, never on an async task's own thread.

use std::net::IpAddr;
use std::time::{Instant, SystemTime};

use super::auth::Owner;
use super::connect::CancelToken;
use super::directory::refusal_sentence;
use super::grants::{self, ask_and_request, current_grant, pause, request_active_grant, GateKey, GrantGates, ACTIVE_WITHIN, POLL_EVERY};
use super::protocol::GrantPrompt;
use crate::gcp::cloudsql::{ConnectSettings, EphemeralCert, EphemeralKey, InstanceRef, SqlAdmin};
use crate::gcp::pam::{Entitlement, EntitlementName};
use crate::gcp::rest::{GcpClient, GcpError};
use crate::sync::databases::SavedDatabase;
use crate::sync::pam_records;
use crate::sync::records_v3::SyncStateV3;
use crate::sync::transports::PamCheck;

pub(crate) use super::grants::Grace;

/// Whether a database's connection may go ahead as far as its grant is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantState {
    /// The database asks for no grant.
    NotNeeded,
    /// A grant is in flight. `recent`: it was given moments ago, so Cloud SQL may not have seen it yet. `until`: when its access ends,
    /// for a grant PAM dated.
    Held { recent: bool, until: Option<SystemTime> },
    /// The database asks for a grant and none is in flight.
    Needed,
}

/// Whether `db` asks for a grant and one is in flight at `now`, tested as a host's connection tests it: the first of the entitlements
/// that holds a grant in flight decides. Blocks on a PAM call for each entitlement it looks at, so it runs on a blocking thread. The
/// error is Google's sentence (`sentence`).
pub(crate) fn grant_state(gcp: &dyn GcpClient, db: &SavedDatabase, now: SystemTime) -> Result<GrantState, String> {
    let Some(pam) = &db.pam else { return Ok(GrantState::NotNeeded) };
    match current_grant(gcp, db.account.as_deref(), &db.project, pam, now).map_err(|error| sentence(&error))? {
        Some(current) => Ok(GrantState::Held { recent: current.recent, until: current.until }),
        None => Ok(GrantState::Needed),
    }
}

/// Gets the grant `db` asks for, through the app's gates (`gates`): connections that need the same grant at once, a host's among them,
/// ask the person once. The one that leads asks in Lunport's Request-a-grant window (five minutes; the question starts from what `state`
/// remembers for the entitlement, else from the database's own length and nothing to prefill), requests the grant with the answer, waits up to
/// a minute for it to become active, tells `owner` what was got and hands the answer to `remember` (the entitlement's full name, the
/// justification and the length in seconds; a memory that cannot be written is `remember`'s to ignore). The others take its outcome.
/// Cancel, no answer in time, a client that went away or an answer that is not one end with the sentence that names the gcloud command.
/// Blocks until the grant is had or the request ends (for as long as the person takes to answer, and then for the request), so it runs on
/// a blocking thread.
pub(crate) fn obtain_grant(
    gates: &GrantGates,
    gcp: &dyn GcpClient,
    owner: &dyn Owner,
    state: &SyncStateV3,
    db: &SavedDatabase,
    remember: &dyn Fn(&str, &str, u32),
    cancel: &CancelToken,
) -> Result<(), String> {
    let Some(pam) = &db.pam else { return Err("This database requires no grant.".to_string()) };
    let Some(first) = pam.entitlements.first() else { return Err("This database's grant check names no PAM entitlement.".to_string()) };
    let name = EntitlementName::in_project(&db.project, &pam.location, first).full();
    let memory = pam_records::memory(state, &name);
    let prompt = GrantPrompt {
        project: db.project.clone(),
        entitlement: first.clone(),
        minutes: memory.as_ref().map_or(pam.duration_secs, |memory| memory.duration_secs) / 60,
        justification: memory.map(|memory| memory.justification),
    };
    let key = gate_key(db, pam, first);
    let refusal = refusal_sentence(&pam.entitlements, first, &pam.location, &db.project);
    gates.obtain(key, cancel, &refusal, || {
        ask_and_request(
            owner,
            &prompt,
            || refusal.clone(),
            |answer| {
                let duration_secs = answer.minutes * 60;
                let place = Entitlement { account: db.account.as_deref(), name: &name };
                let remembered = || remember(&name, &answer.justification, duration_secs);
                request_active_grant(gcp, &place, first, &answer.justification, duration_secs, &remembered, cancel, POLL_EVERY, ACTIVE_WITHIN)
                    .map_err(|error| error.sentence(first))
            },
        )
    })
}

/// The gate of the grant `db` asks for on `entitlement` (one of `pam`'s, by its id): the very one a host's connection takes when its route
/// names the same account, project, location and entitlement (`GateKey::of`), so that the two ask the person once.
fn gate_key(db: &SavedDatabase, pam: &PamCheck, entitlement: &str) -> GateKey {
    GateKey::new(db.account.as_deref(), &db.project, &pam.location, entitlement)
}

/// What a connection to the database needs from Google, fetched together.
#[derive(Debug)]
pub(crate) struct Material {
    pub settings: ConnectSettings,
    /// The instance's public address, which the connection dials (`settings.public_ip`, which an instance Lunport connects to has).
    pub ip: IpAddr,
    /// The client certificate Cloud SQL signed for `key`, with the account's access token inside it.
    pub cert: EphemeralCert,
    pub key: EphemeralKey,
    /// The database user the certificate's account signs in as (`iam_user`).
    pub iam_user: String,
}

/// The calls to Google that a refusal right after a grant may mean "not yet" for: they are tried again while the grace lasts.
struct Attempts<'a> {
    /// The grant the connection relies on became active moments ago.
    recent_grant: bool,
    grace: Grace,
    /// When a call was first refused: the grace counts from there, however long the calls before it took.
    refused_since: Option<Instant>,
    cancel: &'a CancelToken,
}

impl Attempts<'_> {
    /// Runs `call` until it works. A 403 right after a grant is tried again every `grace.step` until `grace.span` has passed since the
    /// first refusal: Google may not have applied the grant yet. Any other failure (a 401 says the token is no good, which no grant
    /// explains), a 403 long after the grant and a 403 that outlasts the grace end it with their sentence; a cancelled connection ends it
    /// with `grants::CANCELLED`.
    fn run<T>(&mut self, mut call: impl FnMut() -> Result<T, GcpError>) -> Result<T, String> {
        loop {
            if self.cancel.is_cancelled() {
                return Err(grants::CANCELLED.to_string());
            }
            let error = match call() {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };
            let too_soon = self.recent_grant && matches!(error, GcpError::Denied { status: 403, .. });
            if too_soon && self.refused_since.get_or_insert_with(Instant::now).elapsed() < self.grace.span {
                if !pause(self.cancel, self.grace.step) {
                    return Err(grants::CANCELLED.to_string());
                }
                continue;
            }
            let text = sentence(&error);
            return Err(if too_soon { format!("{}; the grant became active moments ago, and Google may not have applied it yet.", text.trim_end_matches('.')) } else { text });
        }
    }
}

/// The material for a connection to `db`: its connect settings, a new key and a certificate Cloud SQL signs for that key. `recent_grant`
/// (`GrantState::Held`) says the grant it relies on was given moments ago, and a 403 is then tried again as `grace` allows. An instance
/// without a public address is refused: Lunport connects over the public one. Blocks on the Cloud SQL Admin API, on making the key and
/// while it waits to try again, so it runs on a blocking thread.
pub(crate) fn fetch_material(sql: &dyn SqlAdmin, db: &SavedDatabase, recent_grant: bool, grace: Grace, cancel: &CancelToken) -> Result<Material, String> {
    let at = InstanceRef { project: db.project.clone(), region: db.region.clone(), instance: db.instance.clone() };
    let account = db.account.as_deref();
    let mut attempts = Attempts { recent_grant, grace, refused_since: None, cancel };
    let settings = attempts.run(|| sql.connect_settings(account, &at))?;
    let Some(ip) = settings.public_ip else {
        return Err(format!("{} has no public IP. Lunport connects over public IP in this release.", db.connection_name()));
    };
    let key = EphemeralKey::generate()?;
    let cert = attempts.run(|| sql.ephemeral_cert(account, &at, &key))?;
    let user = iam_user(&cert.account);
    Ok(Material { settings, ip, cert, key, iam_user: user })
}

/// The database user an IAM account signs in as: its email, and for a service account the email without `.gserviceaccount.com`.
pub(crate) fn iam_user(account: &str) -> String {
    account.strip_suffix(".gserviceaccount.com").unwrap_or(account).to_string()
}

/// The sentence for a failed Google call: each error's own words, which for a sign-in that expired or is missing name the
/// `gcloud auth login` to run, as they do for a host.
pub(crate) fn sentence(error: &GcpError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::auth::AuthError;
    use crate::gcp::cloudsql::{InstanceRef, InstanceSummary};
    use crate::gcp::pam::{duration_text, rfc3339, EntitlementName, Grant};
    use crate::session::auth::Reply;
    use crate::session::directory::GrantNeed;
    use crate::session::protocol::{GrantPrompt, QuestionKind};
    use crate::session::testing::{grant_need, FakeOwner};
    use crate::sync::databases::tests::{database, state};
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant, UNIX_EPOCH};
    use zeroize::Zeroizing;

    const ID: &str = "00000000000000d1";
    const ACCOUNT: &str = "frank@example.com";
    const CONNECTION: &str = "acme-prod-123456:asia-east1:orders-pg";
    const OPERATE: &str = "projects/acme-prod-123456/locations/global/entitlements/prod-operate";
    /// What the person answers in the Request-a-grant window: thirty minutes, and why.
    const ANSWER: &str = "30\nCheck unpaid orders";
    const NOTICE: &str = "Requested a 30-minute prod-operate grant on acme-prod-123456; active until ";
    const CANCELLED: &str = "The connection was cancelled.";

    /// A moment the tests share: 2027-01-15T08:00:00Z.
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    /// `now` less `seconds`, as PAM writes a grant time.
    fn ago(seconds: u64) -> String {
        rfc3339(now() - Duration::from_secs(seconds))
    }

    /// The prod database of the fixtures with a grant check on `prod-operate` or `prod-admin`.
    fn guarded() -> SavedDatabase {
        SavedDatabase {
            pam: Some(PamCheck { entitlements: vec!["prod-operate".into(), "prod-admin".into()], location: "global".into(), duration_secs: 1800, justification: None }),
            ..database(ID)
        }
    }

    fn grant(state: &str, granted: Option<String>) -> Grant {
        Grant { name: format!("{OPERATE}/grants/{state}"), state: state.into(), requested_duration: Some("1800s".into()), access_grant_time: granted, justification: None }
    }

    fn denied() -> GcpError {
        GcpError::Denied { api: "Cloud SQL Admin", status: 403, account: ACCOUNT.into() }
    }

    fn expired() -> GcpError {
        GcpError::Auth(AuthError::SignInExpired { account: ACCOUNT.into() })
    }

    /// A scripted Google: the grants each entitlement holds (by id), the state a requested grant starts in, and every call made. A grant
    /// that is requested is held from then on, as PAM has it.
    struct Google {
        held: Mutex<HashMap<String, Vec<Grant>>>,
        created_as: &'static str,
        broken: Option<GcpError>,
        calls: Mutex<Vec<String>>,
    }

    impl Default for Google {
        fn default() -> Google {
            Google { held: Mutex::new(HashMap::new()), created_as: "ACTIVE", broken: None, calls: Mutex::new(Vec::new()) }
        }
    }

    impl Google {
        fn holding(self, entitlement: &str, grants: Vec<Grant>) -> Google {
            self.held.lock().unwrap().insert(entitlement.into(), grants);
            self
        }

        fn creating(self, state: &'static str) -> Google {
            Google { created_as: state, ..self }
        }

        fn broken_by(self, error: GcpError) -> Google {
            Google { broken: Some(error), ..self }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        /// How many grants were requested.
        fn created(&self) -> usize {
            self.calls().iter().filter(|call| call.starts_with("create ")).count()
        }
    }

    fn id_of(name: &str) -> String {
        EntitlementName::parse(name).expect("a well-formed entitlement name").id
    }

    impl GcpClient for Google {
        fn login_profile(&self, _: Option<&str>, _: &str) -> Result<crate::gcp::oslogin::LoginProfile, GcpError> {
            Err(GcpError::Network("OS Login is not scripted".into()))
        }

        fn import_ssh_public_key(&self, _: Option<&str>, _: &str, _: &str) -> Result<crate::gcp::oslogin::LoginProfile, GcpError> {
            Err(GcpError::Network("OS Login is not scripted".into()))
        }

        fn grants(&self, account: Option<&str>, entitlement: &str) -> Result<Vec<Grant>, GcpError> {
            let id = id_of(entitlement);
            self.calls.lock().unwrap().push(format!("grants {} {id}", account.unwrap_or("-")));
            if let Some(error) = &self.broken {
                return Err(error.clone());
            }
            Ok(self.held.lock().unwrap().get(&id).cloned().unwrap_or_default())
        }

        fn create_grant(&self, account: Option<&str>, entitlement: &str, duration_secs: u32, justification: &str) -> Result<Grant, GcpError> {
            let id = id_of(entitlement);
            self.calls.lock().unwrap().push(format!("create {} {id} {duration_secs} {justification}", account.unwrap_or("-")));
            let created = Grant {
                name: format!("{entitlement}/grants/1"),
                state: self.created_as.into(),
                requested_duration: Some(duration_text(duration_secs)),
                access_grant_time: (self.created_as == "ACTIVE").then(|| rfc3339(SystemTime::now())),
                justification: Some(justification.into()),
            };
            self.held.lock().unwrap().entry(id).or_default().push(created.clone());
            Ok(created)
        }

        fn get_grant(&self, account: Option<&str>, name: &str) -> Result<Grant, GcpError> {
            self.calls.lock().unwrap().push(format!("get {} {name}", account.unwrap_or("-")));
            let held = self.held.lock().unwrap();
            held.values().flatten().find(|grant| grant.name == name).cloned().ok_or_else(|| GcpError::Network("no such grant".into()))
        }
    }

    fn settings() -> ConnectSettings {
        ConnectSettings {
            public_ip: Some("198.51.100.5".parse().unwrap()),
            server_ca_pem: "-----BEGIN CERTIFICATE-----\nc2VydmVyLWNh\n-----END CERTIFICATE-----\n".into(),
            dns_name: Some("a1b2c3.asia-east1.sql.goog".into()),
            database_version: "POSTGRES_16".into(),
        }
    }

    fn certificate(account: &str) -> EphemeralCert {
        EphemeralCert { cert_pem: "-----BEGIN CERTIFICATE-----\nY2xpZW50\n-----END CERTIFICATE-----\n".into(), expires_at: now() + Duration::from_secs(3600), account: account.into() }
    }

    /// A scripted Cloud SQL Admin API: each call takes the next answer of its script, the last one again and again; the calls made and the
    /// public keys the certificates were asked for are recorded.
    struct Admin {
        settings: Mutex<VecDeque<Result<ConnectSettings, GcpError>>>,
        certs: Mutex<VecDeque<Result<EphemeralCert, GcpError>>>,
        calls: Mutex<Vec<String>>,
        keys: Mutex<Vec<String>>,
    }

    impl Admin {
        fn answering(settings: Vec<Result<ConnectSettings, GcpError>>, certs: Vec<Result<EphemeralCert, GcpError>>) -> Admin {
            Admin { settings: Mutex::new(settings.into()), certs: Mutex::new(certs.into()), calls: Mutex::new(Vec::new()), keys: Mutex::new(Vec::new()) }
        }

        /// An instance that signs the certificate at once.
        fn working() -> Admin {
            Admin::answering(vec![Ok(settings())], vec![Ok(certificate(ACCOUNT))])
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn certificates_asked(&self) -> usize {
            self.calls().iter().filter(|call| call.starts_with("cert ")).count()
        }
    }

    fn next<T: Clone>(script: &Mutex<VecDeque<T>>) -> T {
        let mut script = script.lock().unwrap();
        if script.len() > 1 {
            script.pop_front().expect("an answer")
        } else {
            script.front().cloned().expect("a scripted answer")
        }
    }

    impl SqlAdmin for Admin {
        fn connect_settings(&self, account: Option<&str>, at: &InstanceRef) -> Result<ConnectSettings, GcpError> {
            self.calls.lock().unwrap().push(format!("settings {} {}:{}:{}", account.unwrap_or("-"), at.project, at.region, at.instance));
            next(&self.settings)
        }

        fn ephemeral_cert(&self, account: Option<&str>, at: &InstanceRef, key: &EphemeralKey) -> Result<EphemeralCert, GcpError> {
            self.calls.lock().unwrap().push(format!("cert {} {}:{}:{}", account.unwrap_or("-"), at.project, at.region, at.instance));
            self.keys.lock().unwrap().push(key.public_pem().to_string());
            next(&self.certs)
        }

        fn list_instances(&self, _: Option<&str>, _: &str) -> Result<Vec<InstanceSummary>, GcpError> {
            Ok(Vec::new())
        }
    }

    /// What the app writes to the grant memory, as the callbacks it is given.
    #[derive(Default)]
    struct Memory(Mutex<Vec<(String, String, u32)>>);

    impl Memory {
        fn remember(&self, name: &str, justification: &str, duration_secs: u32) {
            self.0.lock().unwrap().push((name.into(), justification.into(), duration_secs));
        }

        fn all(&self) -> Vec<(String, String, u32)> {
            self.0.lock().unwrap().clone()
        }
    }

    /// The person at the terminal: they answer once `followers` more connections wait behind the question, so that the connections do
    /// need one grant at the same moment. `asking` is set as the question is put, `leaving` is the connection whose client goes away as
    /// they answer.
    struct Person<'a> {
        inner: FakeOwner,
        gates: &'a GrantGates,
        followers: usize,
        asking: AtomicBool,
        leaving: Option<CancelToken>,
    }

    impl<'a> Person<'a> {
        fn new(inner: FakeOwner, gates: &'a GrantGates, followers: usize) -> Person<'a> {
            Person { inner, gates, followers, asking: AtomicBool::new(false), leaving: None }
        }
    }

    impl Owner for Person<'_> {
        fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
            self.asking.store(true, Ordering::SeqCst);
            let end = Instant::now() + Duration::from_secs(5);
            while self.gates.waiting() < self.followers && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(2));
            }
            if let Some(connection) = &self.leaving {
                connection.cancel();
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

    fn obtain(gates: &GrantGates, google: &Google, owner: &dyn Owner, state: &SyncStateV3, memory: &Memory) -> Result<(), String> {
        obtain_grant(gates, google, owner, state, &guarded(), &|name, justification, secs| memory.remember(name, justification, secs), &CancelToken::default())
    }

    /// Two connections that need the same grant at the same moment, with `person` at the terminal of both.
    fn two_connections(gates: &GrantGates, google: &Google, person: &Person<'_>, memory: &Memory) -> (Result<(), String>, Result<(), String>) {
        std::thread::scope(|scope| {
            let first = scope.spawn(|| obtain(gates, google, person, &state(), memory));
            let second = scope.spawn(|| obtain(gates, google, person, &state(), memory));
            (first.join().unwrap(), second.join().unwrap())
        })
    }

    fn fast() -> Grace {
        Grace { span: Duration::from_secs(5), step: Duration::from_millis(5) }
    }

    fn gcloud_refusal() -> String {
        "No active Privileged Access Manager grant for prod-operate or prod-admin on acme-prod-123456. Request one (for example gcloud pam grants create --entitlement=prod-operate --requested-duration=30m --justification=\"…\" --location=global --project=acme-prod-123456) and connect again.".to_string()
    }

    #[test]
    fn a_database_without_pam_needs_no_grant() {
        let google = Google::default();
        assert_eq!(grant_state(&google, &database(ID), now()), Ok(GrantState::NotNeeded));
        assert!(google.calls().is_empty(), "there is nothing to ask Google");
    }

    #[test]
    fn a_current_grant_counts_and_a_fresh_one_is_recent() {
        let state_of = |grants: Vec<Grant>| grant_state(&Google::default().holding("prod-operate", grants), &guarded(), now());
        let until = |seconds: u64| Some(now() + Duration::from_secs(seconds));
        // Given ten minutes ago for half an hour: in force for twenty more minutes, and not fresh.
        assert_eq!(state_of(vec![grant("ACTIVE", Some(ago(600)))]), Ok(GrantState::Held { recent: false, until: until(1200) }));
        // Given thirty seconds ago: fresh, which is what lets Cloud SQL's refusal be put down to a grant it has not seen yet.
        assert_eq!(state_of(vec![grant("ACTIVE", Some(ago(30)))]), Ok(GrantState::Held { recent: true, until: until(1770) }));
        // Still activating, it is as fresh as now and lasts as long as it was requested for: fifteen minutes here, not the thirty that the
        // database asks for by default (another device, or gcloud, requested it for another length).
        let short = Grant { requested_duration: Some("900s".into()), ..grant("ACTIVATING", None) };
        assert_eq!(state_of(vec![short]), Ok(GrantState::Held { recent: true, until: until(900) }));
        // One that says no length of its own gets the database's.
        let unsaid = Grant { requested_duration: None, ..grant("ACTIVATING", None) };
        assert_eq!(state_of(vec![unsaid]), Ok(GrantState::Held { recent: true, until: until(1800) }));
        // A grant time ahead of this clock (Google's is ahead) is fresh too, and ends when the grant says.
        let ahead = rfc3339(now() + Duration::from_secs(30));
        assert_eq!(state_of(vec![grant("ACTIVE", Some(ahead))]), Ok(GrantState::Held { recent: true, until: until(1830) }));
        // The freshest of several grants dates it.
        assert_eq!(state_of(vec![grant("ACTIVE", Some(ago(600))), grant("ACTIVE", Some(ago(30)))]), Ok(GrantState::Held { recent: true, until: until(1770) }));
        // A grant PAM did not date holds, and has no end to give.
        assert_eq!(state_of(vec![grant("ACTIVE", None)]), Ok(GrantState::Held { recent: false, until: None }));
        // Grants that give nothing now are none: ended, denied, revoked, and one that waits for an approver.
        for gone in ["ENDED", "DENIED", "REVOKED", "APPROVAL_AWAITED"] {
            assert_eq!(state_of(vec![grant(gone, None)]), Ok(GrantState::Needed), "{gone}");
        }
        assert_eq!(state_of(Vec::new()), Ok(GrantState::Needed));
    }

    #[test]
    fn the_entitlements_are_looked_at_in_order_until_one_holds_a_grant() {
        let google = Google::default().holding("prod-admin", vec![grant("ACTIVE", Some(ago(600)))]);
        assert_eq!(grant_state(&google, &guarded(), now()), Ok(GrantState::Held { recent: false, until: Some(now() + Duration::from_secs(1200)) }));
        assert_eq!(google.calls(), vec![format!("grants {ACCOUNT} prod-operate"), format!("grants {ACCOUNT} prod-admin")]);
        let google = Google::default().holding("prod-operate", vec![grant("ACTIVE", Some(ago(600)))]).holding("prod-admin", vec![grant("ACTIVE", Some(ago(30)))]);
        assert_eq!(grant_state(&google, &guarded(), now()), Ok(GrantState::Held { recent: false, until: Some(now() + Duration::from_secs(1200)) }), "the first entitlement with a grant decides");
        assert_eq!(google.calls(), vec![format!("grants {ACCOUNT} prod-operate")], "and the others are not asked");
        // A database saved without an account asks as gcloud's active account.
        let google = Google::default();
        grant_state(&google, &SavedDatabase { account: None, ..guarded() }, now()).unwrap();
        assert_eq!(google.calls()[0], "grants - prod-operate");
    }

    #[test]
    fn a_missing_grant_asks_once_for_two_connections() {
        let (gates, google, memory) = (GrantGates::default(), Google::default(), Memory::default());
        let person = Person::new(FakeOwner::typing(&[ANSWER]), &gates, 1);
        let (first, second) = two_connections(&gates, &google, &person, &memory);
        assert_eq!((first, second), (Ok(()), Ok(())));
        assert_eq!(person.inner.asked().len(), 1, "one question for both");
        assert_eq!(google.created(), 1, "one request for both");
        assert_eq!(memory.all().len(), 1, "one memory for both");
        let notices = person.inner.notices.lock().unwrap().clone();
        assert_eq!(notices.iter().filter(|notice| notice.starts_with(NOTICE)).count(), 1, "the one who asked is told what it got: {notices:?}");
    }

    #[test]
    fn a_declined_question_tells_the_waiting_connection_the_refusal_too() {
        let (gates, google, memory) = (GrantGates::default(), Google::default(), Memory::default());
        let person = Person::new(FakeOwner::answering(vec![Reply::Cancelled]), &gates, 1);
        let (first, second) = two_connections(&gates, &google, &person, &memory);
        assert_eq!((first, second), (Err(gcloud_refusal()), Err(gcloud_refusal())));
        assert_eq!(person.inner.asked().len(), 1, "the waiter asked nothing");
        assert_eq!(google.created(), 0);
    }

    /// Hosts and databases share a gate only while they name a grant the same way: by the account, the project, the location and the id of
    /// the entitlement (not its full name).
    #[test]
    fn a_host_and_a_database_that_need_the_same_grant_take_the_same_gate() {
        let db = guarded();
        let pam = db.pam.clone().expect("a grant check");
        // What a host's connection reports when its route names the same account, project, location and first entitlement (`prepare`).
        let need = GrantNeed { account: db.account.clone(), location: pam.location.clone(), entitlements: pam.entitlements.clone(), ..grant_need("web", &db.project) };
        assert_eq!(need.entitlement, "prod-operate");
        assert_eq!(GateKey::of(&need), gate_key(&db, &pam, "prod-operate"));
        // Another account, project, location or entitlement is another grant.
        let others = [
            gate_key(&SavedDatabase { account: Some("ops@example.com".into()), ..db.clone() }, &pam, "prod-operate"),
            gate_key(&SavedDatabase { account: None, ..db.clone() }, &pam, "prod-operate"),
            gate_key(&SavedDatabase { project: "acme-dev-654321".into(), ..db.clone() }, &pam, "prod-operate"),
            gate_key(&db, &PamCheck { location: "europe-west1".into(), ..pam.clone() }, "prod-operate"),
            gate_key(&db, &pam, "prod-admin"),
        ];
        for other in &others {
            assert_ne!(&GateKey::of(&need), other);
        }
    }

    /// The connection that leads goes away (its client is gone) as the person answers: the request ends there, and the connection that
    /// waited on it is told how to request a grant itself, not that a connection that was not its own was cancelled.
    #[test]
    fn a_lead_whose_connection_was_cancelled_leaves_the_waiting_connection_the_refusal() {
        let (gates, google, memory) = (GrantGates::default(), Google::default(), Memory::default());
        let lead_cancel = CancelToken::default();
        let mut person = Person::new(FakeOwner::typing(&[ANSWER]), &gates, 1);
        person.leaving = Some(lead_cancel.clone());
        let (lead, follower) = std::thread::scope(|scope| {
            let lead = scope.spawn(|| obtain_grant(&gates, &google, &person, &state(), &guarded(), &|name, justification, secs| memory.remember(name, justification, secs), &lead_cancel));
            let end = Instant::now() + Duration::from_secs(5);
            while !person.asking.load(Ordering::SeqCst) && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(2));
            }
            let follower = scope.spawn(|| obtain(&gates, &google, &person, &state(), &memory));
            (lead.join().unwrap(), follower.join().unwrap())
        });
        assert_eq!(lead, Err(CANCELLED.to_string()));
        assert_eq!(follower, Err(gcloud_refusal()));
        assert_eq!(google.created(), 0, "nothing was requested for a connection that is gone");
    }

    #[test]
    fn the_answer_in_lunports_window_is_what_is_requested_and_remembered() {
        let (gates, google, memory) = (GrantGates::default(), Google::default(), Memory::default());
        let owner = FakeOwner::typing(&[ANSWER]);
        obtain(&gates, &google, &owner, &state(), &memory).expect("the grant is had");
        let asked = owner.asked();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].kind, QuestionKind::Grant);
        assert!(asked[0].echo);
        let wait = asked[0].deadline.expect("the question has a deadline").saturating_duration_since(Instant::now());
        assert!(wait > Duration::from_secs(290) && wait <= Duration::from_secs(300), "five minutes: {wait:?}");
        // With nothing remembered the window offers the database's own length and nothing to prefill.
        let prompt = GrantPrompt::from_text(&asked[0].text).expect("the question carries the prompt");
        assert_eq!(prompt, GrantPrompt { project: "acme-prod-123456".into(), entitlement: "prod-operate".into(), minutes: 30, justification: None });
        // What the person answered is what was requested, for the entitlement the database lists first, as the account it is saved with.
        assert_eq!(google.created(), 1);
        assert!(google.calls().contains(&format!("create {ACCOUNT} prod-operate 1800 Check unpaid orders")), "{:?}", google.calls());
        // ... and what is remembered for the next question, once, under the entitlement's full name.
        assert_eq!(memory.all(), vec![(OPERATE.to_string(), "Check unpaid orders".to_string(), 1800)]);
        let notices = owner.notices.lock().unwrap().clone();
        assert!(notices.len() == 1 && notices[0].starts_with(NOTICE) && notices[0].ends_with('.'), "{notices:?}");
    }

    #[test]
    fn the_question_starts_from_what_was_last_asked_for_on_the_entitlement() {
        let remembered = crate::sync::pam_records::remember(&state(), OPERATE, "restart orders-pg", 2700, None, 1).expect("a memory is written");
        let (gates, google, memory) = (GrantGates::default(), Google::default(), Memory::default());
        let owner = FakeOwner::answering(vec![Reply::Cancelled]);
        let _ = obtain(&gates, &google, &owner, &remembered, &memory);
        let prompt = GrantPrompt::from_text(&owner.asked()[0].text).expect("the question carries the prompt");
        assert_eq!((prompt.minutes, prompt.justification.as_deref()), (45, Some("restart orders-pg")));
        // Another entitlement's memory is that entitlement's.
        let other = crate::sync::pam_records::remember(&state(), "projects/acme-prod-123456/locations/global/entitlements/prod-admin", "audit", 600, None, 1).expect("a memory is written");
        let owner = FakeOwner::answering(vec![Reply::Cancelled]);
        let _ = obtain(&gates, &google, &owner, &other, &memory);
        let prompt = GrantPrompt::from_text(&owner.asked()[0].text).expect("the question carries the prompt");
        assert_eq!((prompt.minutes, prompt.justification), (30, None));
    }

    #[test]
    fn a_question_nobody_answers_ends_with_the_gcloud_refusal_and_requests_nothing() {
        for reply in [Reply::Cancelled, Reply::TimedOut, Reply::Gone, Reply::Answer(Zeroizing::new("thirty\nnot a number".to_string()))] {
            let (gates, google, memory) = (GrantGates::default(), Google::default(), Memory::default());
            let owner = FakeOwner::answering(vec![reply]);
            assert_eq!(obtain(&gates, &google, &owner, &state(), &memory), Err(gcloud_refusal()));
            assert_eq!(google.created(), 0, "nothing was requested");
            assert!(memory.all().is_empty(), "nothing was remembered");
            assert!(owner.notices.lock().unwrap().is_empty(), "nothing to tell");
        }
    }

    #[test]
    fn a_refused_request_ends_with_its_sentence() {
        let (gates, google, memory) = (GrantGates::default(), Google::default().creating("DENIED"), Memory::default());
        let owner = FakeOwner::typing(&[ANSWER]);
        assert_eq!(obtain(&gates, &google, &owner, &state(), &memory), Err("The prod-operate grant did not become active (state: DENIED).".to_string()));
        assert!(owner.notices.lock().unwrap().is_empty(), "no grant was had");
        // Google refusing the call is said in Google's words.
        let (gates, google) = (GrantGates::default(), Google::default().broken_by(denied()));
        let owner = FakeOwner::typing(&[ANSWER]);
        assert_eq!(obtain(&gates, &google, &owner, &state(), &memory), Err(denied().to_string()));
    }

    #[test]
    fn a_grant_that_appeared_meanwhile_is_used_instead_of_requested() {
        // Another connection, or the Google Cloud page, requested one between the look and the question: PAM refuses a second request with
        // the same scope.
        let (gates, memory) = (GrantGates::default(), Memory::default());
        let google = Google::default().holding("prod-operate", vec![grant("ACTIVE", Some(rfc3339(SystemTime::now())))]);
        let owner = FakeOwner::typing(&[ANSWER]);
        assert_eq!(obtain(&gates, &google, &owner, &state(), &memory), Ok(()));
        assert_eq!(google.created(), 0, "nothing was requested");
        assert!(memory.all().is_empty(), "and nothing is remembered for a request that was not made");
    }

    #[test]
    fn a_database_without_a_grant_check_has_nothing_to_request() {
        let (gates, google, memory) = (GrantGates::default(), Google::default(), Memory::default());
        let owner = FakeOwner::default();
        let error = obtain_grant(&gates, &google, &owner, &state(), &database(ID), &|name, justification, secs| memory.remember(name, justification, secs), &CancelToken::default());
        assert_eq!(error, Err("This database requires no grant.".to_string()));
        assert!(owner.asked().is_empty() && google.calls().is_empty());
    }

    #[test]
    fn the_material_is_a_new_key_the_settings_and_a_certificate_signed_for_that_key() {
        let admin = Admin::working();
        let material = fetch_material(&admin, &guarded(), false, fast(), &CancelToken::default()).expect("the material is had");
        assert_eq!(material.settings, settings());
        assert_eq!(Some(material.ip), settings().public_ip, "the address it dials");
        assert_eq!(material.cert, certificate(ACCOUNT));
        assert_eq!(material.iam_user, ACCOUNT);
        assert_eq!(admin.calls(), vec![format!("settings {ACCOUNT} {CONNECTION}"), format!("cert {ACCOUNT} {CONNECTION}")]);
        assert_eq!(*admin.keys.lock().unwrap(), vec![material.key.public_pem().to_string()], "the certificate was asked for the key that comes with it");
        // Every fetch makes a key of its own.
        let again = fetch_material(&admin, &guarded(), false, fast(), &CancelToken::default()).expect("the material is had");
        assert_ne!(again.key.public_pem(), material.key.public_pem());
    }

    #[test]
    fn the_database_user_is_the_one_of_the_account_the_certificate_belongs_to() {
        let admin = Admin::answering(vec![Ok(settings())], vec![Ok(certificate("orders-sa@acme-prod-123456.iam.gserviceaccount.com"))]);
        let material = fetch_material(&admin, &guarded(), false, fast(), &CancelToken::default()).expect("the material is had");
        assert_eq!(material.iam_user, "orders-sa@acme-prod-123456.iam");
    }

    #[test]
    fn a_denied_certificate_right_after_a_grant_is_retried_until_it_works() {
        let admin = Admin::answering(vec![Ok(settings())], vec![Err(denied()), Err(denied()), Ok(certificate(ACCOUNT))]);
        let material = fetch_material(&admin, &guarded(), true, fast(), &CancelToken::default()).expect("the third try works");
        assert_eq!(material.cert, certificate(ACCOUNT));
        assert_eq!(admin.certificates_asked(), 3);
        assert_eq!(admin.calls().iter().filter(|call| call.starts_with("settings ")).count(), 1, "the settings are not asked again");
        let keys = admin.keys.lock().unwrap().clone();
        assert!(keys.iter().all(|key| *key == keys[0]), "the key is made once");
    }

    #[test]
    fn denied_settings_right_after_a_grant_are_retried_too() {
        let admin = Admin::answering(vec![Err(denied()), Ok(settings())], vec![Ok(certificate(ACCOUNT))]);
        fetch_material(&admin, &guarded(), true, fast(), &CancelToken::default()).expect("the second try works");
        assert_eq!(admin.calls().iter().filter(|call| call.starts_with("settings ")).count(), 2);
    }

    #[test]
    fn a_denied_certificate_long_after_the_grant_is_reported_at_once() {
        let admin = Admin::answering(vec![Ok(settings())], vec![Err(denied()), Ok(certificate(ACCOUNT))]);
        let error = fetch_material(&admin, &guarded(), false, fast(), &CancelToken::default()).unwrap_err();
        assert_eq!(error, "frank@example.com may not call the Cloud SQL Admin API (HTTP 403).");
        assert_eq!(admin.certificates_asked(), 1, "not asked again");
    }

    #[test]
    fn a_certificate_that_stays_denied_after_a_recent_grant_says_the_grant_may_not_be_applied_yet() {
        let admin = Admin::answering(vec![Ok(settings())], vec![Err(denied())]);
        let grace = Grace { span: Duration::from_millis(60), step: Duration::from_millis(5) };
        let started = Instant::now();
        let error = fetch_material(&admin, &guarded(), true, grace, &CancelToken::default()).unwrap_err();
        assert!(started.elapsed() >= grace.span, "tried for the whole grace");
        assert_eq!(error, "frank@example.com may not call the Cloud SQL Admin API (HTTP 403); the grant became active moments ago, and Google may not have applied it yet.");
        assert!(admin.certificates_asked() > 1, "and tried again meanwhile");
    }

    /// A 401 says the token is no good, which a grant that has not propagated cannot explain: it is reported at once, and its sentence
    /// does not blame the grant.
    #[test]
    fn a_401_right_after_a_grant_is_reported_at_once() {
        let unauthorized = || GcpError::Denied { api: "Cloud SQL Admin", status: 401, account: ACCOUNT.into() };
        let sentence_of_it = "frank@example.com may not call the Cloud SQL Admin API (HTTP 401).";
        let admin = Admin::answering(vec![Ok(settings())], vec![Err(unauthorized()), Ok(certificate(ACCOUNT))]);
        assert_eq!(fetch_material(&admin, &guarded(), true, fast(), &CancelToken::default()).unwrap_err(), sentence_of_it);
        assert_eq!(admin.certificates_asked(), 1, "the certificate is not asked for again");
        let admin = Admin::answering(vec![Err(unauthorized()), Ok(settings())], vec![Ok(certificate(ACCOUNT))]);
        assert_eq!(fetch_material(&admin, &guarded(), true, fast(), &CancelToken::default()).unwrap_err(), sentence_of_it);
        assert_eq!(admin.calls().len(), 1, "the settings are not asked for again, and nothing else is asked");
    }

    #[test]
    fn only_a_403_is_retried_even_right_after_a_grant() {
        for error in [GcpError::Network("timed out".into()), GcpError::Http { api: "Cloud SQL Admin", status: 500 }, GcpError::Refused { api: "Cloud SQL Admin", message: "Cloud SQL has no instance acme-prod-123456:asia-east1:orders-pg.".into() }] {
            let admin = Admin::answering(vec![Ok(settings())], vec![Err(error.clone())]);
            assert_eq!(fetch_material(&admin, &guarded(), true, fast(), &CancelToken::default()).unwrap_err(), error.to_string());
            assert_eq!(admin.certificates_asked(), 1, "{error}");
        }
    }

    #[test]
    fn an_instance_without_a_public_ip_is_refused_with_a_sentence() {
        let private = ConnectSettings { public_ip: None, ..settings() };
        let admin = Admin::answering(vec![Ok(private)], vec![Ok(certificate(ACCOUNT))]);
        let error = fetch_material(&admin, &guarded(), false, fast(), &CancelToken::default()).unwrap_err();
        assert_eq!(error, "acme-prod-123456:asia-east1:orders-pg has no public IP. Lunport connects over public IP in this release.");
        assert_eq!(admin.certificates_asked(), 0, "no certificate is asked for an instance that cannot be dialled");
    }

    #[test]
    fn a_cancelled_connection_makes_no_more_calls() {
        let admin = Admin::answering(vec![Ok(settings())], vec![Err(denied())]);
        let cancel = CancelToken::default();
        cancel.cancel();
        assert_eq!(fetch_material(&admin, &guarded(), true, fast(), &cancel).unwrap_err(), CANCELLED);
        assert!(admin.calls().is_empty());
        // Cancelled while it is waiting to try again.
        let cancel = CancelToken::default();
        let slow = Grace { span: Duration::from_secs(60), step: Duration::from_millis(20) };
        let error = std::thread::scope(|scope| {
            let fetching = scope.spawn(|| fetch_material(&admin, &guarded(), true, slow, &cancel));
            let end = Instant::now() + Duration::from_secs(5);
            while admin.certificates_asked() < 2 && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(2));
            }
            cancel.cancel();
            fetching.join().unwrap()
        })
        .unwrap_err();
        assert_eq!(error, CANCELLED);
    }

    #[test]
    fn an_expired_sign_in_becomes_the_gcloud_sentence() {
        let sentence_of_it = "Google sign-in for frank@example.com has expired or was revoked; run `gcloud auth login frank@example.com` and connect again.";
        assert_eq!(sentence(&expired()), sentence_of_it);
        assert!(sentence(&expired()).contains("gcloud auth login frank@example.com"));
        // Every call that can meet the expired sign-in says so.
        assert_eq!(grant_state(&Google::default().broken_by(expired()), &guarded(), now()), Err(sentence_of_it.to_string()));
        let (gates, memory) = (GrantGates::default(), Memory::default());
        let owner = FakeOwner::typing(&[ANSWER]);
        assert_eq!(obtain(&gates, &Google::default().broken_by(expired()), &owner, &state(), &memory), Err(sentence_of_it.to_string()));
        let admin = Admin::answering(vec![Err(expired())], vec![Ok(certificate(ACCOUNT))]);
        assert_eq!(fetch_material(&admin, &guarded(), true, fast(), &CancelToken::default()).unwrap_err(), sentence_of_it);
        assert_eq!(admin.calls().len(), 1, "a sign-in that has to be redone is not retried");
        // Any other error keeps its own words.
        assert_eq!(sentence(&denied()), denied().to_string());
        assert_eq!(sentence(&GcpError::Network("timed out".into())), "Google's API could not be reached: timed out.");
    }

    #[test]
    fn service_account_users_drop_the_gserviceaccount_suffix() {
        assert_eq!(iam_user("orders-sa@acme-prod-123456.iam.gserviceaccount.com"), "orders-sa@acme-prod-123456.iam");
        assert_eq!(iam_user("frank@example.com"), "frank@example.com");
        assert_eq!(iam_user("ops@example.com"), "ops@example.com");
        // Only the suffix goes, and only at the end.
        assert_eq!(iam_user("a.gserviceaccount.com@example.com"), "a.gserviceaccount.com@example.com");
    }
}
