//! How the local ports of the saved databases reach Cloud SQL: the grant a database asks for, the connection material the Cloud SQL Admin
//! API signs, and the TLS dial to the instance, kept for a database's next connections while they last. A database reached through a host
//! of the library is dialled through an SSH session to that host (`HostPath`), kept while the database runs and the session lives.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use futures_util::future::BoxFuture;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tauri::Manager;

use super::auth::{label, Owner};
use super::auth_window::{NativeOwner, TauriAuthSurface};
use super::broker::Broker;
use super::connect::CancelToken;
use super::database_access::{fetch_material, grant_state, obtain_grant, Grace, GrantState};
use super::database_path::{BrokerLink, HostLink, HostPath};
use super::database_ports::{locked, BoxStream, Dialling, NotReady, Prepared, Upstream};
use super::grants::GrantGates;
use super::tunnels::snapshot;
use crate::error::AppError;
use crate::gcp::cloudsql::SqlAdmin;
use crate::gcp::cloudsql_tls::{self, client_config, server_name, ServerIdentity};
use crate::gcp::rest::GcpClient;
use crate::state::AppState;
use crate::sync::databases::SavedDatabase;
use crate::sync::record_repository as repo;
use crate::sync::records_v3::SyncStateV3;

/// How long before a client certificate stops being useful a connection gets a new one.
pub const REFRESH_AHEAD: Duration = Duration::from_secs(4 * 60);
/// How long a check that a grant is held is trusted at most.
const GRANT_RECHECK: Duration = Duration::from_secs(5 * 60);
/// What a connection is refused with when the port stopped while its session to the host opened.
const CANCELLED: &str = "The connection was cancelled.";
/// Why a connection through a host could not get its forward when the database stopped meanwhile and took the session along.
const PATH_CLOSED: &str = "The connection to the host closed. Connect again.";
/// What a connection that has no material to dial with fails with.
const NO_CERTIFICATE: &str = "no certificate is ready for it. Connect again.";
/// What a connection through a host fails with when the forward it would dial does not run.
const PATH_NOT_OPEN: &str = "the connection through the host is not open. Connect again.";

/// Makes the owner that asks the person on behalf of a connection that `cancel` cancels.
type MakeOwner = Arc<dyn Fn(&CancelToken) -> Box<dyn Owner + Send> + Send + Sync>;
/// Dials an instance: the address to dial, the TLS configuration of the connection, and the name its certificate must be made out to.
type Dialer = Arc<dyn Fn(SocketAddr, Arc<ClientConfig>, ServerName<'static>) -> BoxFuture<'static, io::Result<BoxStream>> + Send + Sync>;

/// How the app's ports reach Cloud SQL. The grant a database asks for is requested through the gates hosts use, so that a host and a
/// database that need the same grant ask the person once; the connection material comes from the Cloud SQL Admin API. Both are kept for a
/// database's next connections while they last: a check that the grant is held for five minutes at most and never past the grant's end,
/// the material until `REFRESH_AHEAD` before its certificate stops being useful. Both are for the Google account the connections sign in
/// as, and go when it changes; a grant that ended takes the material had under it along. A database reached through a host shares one
/// session to that host among its connections, opened once the grant is had and opened again when it dies, and closed when the database
/// stops; the connections dial the loopback end of a forward on it to the instance's private address.
pub(crate) struct CloudSqlUpstream {
    gcp: Arc<dyn GcpClient>,
    sql: Arc<dyn SqlAdmin>,
    gates: Arc<GrantGates>,
    make_owner: MakeOwner,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    /// gcloud's active account as it is now, which a database saved without an account signs in as.
    active_account: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    /// The library as it is now, whose grant memory a grant question starts from.
    library: Arc<dyn Fn() -> Result<SyncStateV3, String> + Send + Sync>,
    /// Remembers a grant the person asked for: the entitlement's full name, the justification and the length in seconds.
    remember: Arc<dyn Fn(&str, &str, u32) + Send + Sync>,
    /// Opens the session to the host a database is reached through, as connecting to that host does.
    link: Arc<dyn HostLink>,
    dial: Dialer,
    /// What each database's connections share, by the database's id.
    routes: Mutex<HashMap<String, Arc<Route>>>,
    /// The number of the next material fetched, counted from 1.
    generations: AtomicU64,
}

/// What the connections to one database, as it was saved, share. A database saved anew (another account, instance, grant check or route)
/// gets a route of its own: a connection still on its way with the route before cannot leave anything in it.
///
/// Its locks are taken in the order `CloudSqlUpstream::routes`, `opening`, `fetching`, `kept`, `path`, each after the ones before it. Only
/// `opening` is held while the person may be asked (the questions of the host's login), and never `kept` or `path`, which async code takes.
struct Route {
    database: SavedDatabase,
    /// Held while the material is fetched, so that connections that start together share one fetch.
    fetching: Mutex<()>,
    kept: Mutex<Kept>,
    /// Held by a connection through a host from the moment it looks at the path until its forward is had: connections that start together
    /// share one session and one forward, and the path a connection got ready on is the one its forward goes on.
    opening: Mutex<()>,
    /// The session to the host the database is reached through, with its forward to the instance, while it lives. It is taken out, which
    /// closes it, when the database stops or is saved anew.
    path: Mutex<Option<HostPath>>,
}

/// What was had for a database, kept for its next connections.
#[derive(Default)]
struct Kept {
    grant: Option<CheckedGrant>,
    dial: Option<Dial>,
    /// The Google account of the last certificate, as the token source resolved it.
    account: Option<String>,
}

impl Kept {
    /// Lets go of what was had for another account than `account`, the one the connections sign in as now (`None`: gcloud has no active
    /// account, and the token source falls back to its default credentials).
    fn keep_for(&mut self, account: &Option<String>) {
        let other = self.grant.as_ref().is_some_and(|check| check.for_account != *account) || self.dial.as_ref().is_some_and(|dial| dial.for_account != *account);
        if other {
            *self = Kept::default();
        }
    }
}

/// A check that found the grant held. One that found it given moments before is not kept: every connection checks such a grant again, so
/// that the time Google is given to see it ends when the grant is no longer that fresh.
struct CheckedGrant {
    /// The account the connections signed in as when it was checked.
    for_account: Option<String>,
    until: Option<SystemTime>,
    checked_at: SystemTime,
}

impl CheckedGrant {
    /// Whether the check still stands at `now`: it is younger than `GRANT_RECHECK`, and the grant has not reached its end.
    fn stands(&self, now: SystemTime) -> bool {
        now < self.checked_at + GRANT_RECHECK && self.until.is_none_or(|until| now < until)
    }
}

/// What a connection dials the instance with.
struct Dial {
    /// Which material this is: a connection that failed with it takes back this one only.
    generation: u64,
    /// The account the connections signed in as when it was fetched.
    for_account: Option<String>,
    iam_user: String,
    /// When the certificate stops being useful (`EphemeralCert::expires_at`).
    expires_at: SystemTime,
    /// The address the connections dial, on port `cloudsql_tls::PORT`: the instance's public one, or its private one for a database
    /// reached through a host (`Material::ip`).
    ip: IpAddr,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}

impl CloudSqlUpstream {
    /// The upstream of the app's ports: Google's APIs through the app's clients, the broker's grant gates and its connector for the hosts
    /// databases are reached through, a person's questions in Lunport's windows (a person starts a port, as a person starts a tunnel), and
    /// this device's grant memory.
    pub(crate) fn for_app(app: &tauri::AppHandle, broker: &Broker) -> CloudSqlUpstream {
        let state = app.state::<AppState>();
        let hub = Arc::clone(&state.session.auth_questions);
        let requests = AtomicU64::new(0);
        let (for_owner, for_library, for_memory) = (app.clone(), app.clone(), app.clone());
        CloudSqlUpstream {
            gcp: state.gcp.clone(),
            sql: Arc::clone(&state.sqladmin),
            gates: broker.grants(),
            make_owner: Arc::new(move |cancel: &CancelToken| -> Box<dyn Owner + Send> {
                Box::new(NativeOwner {
                    ai: None,
                    hub: Arc::clone(&hub),
                    surface: Arc::new(TauriAuthSurface { app: for_owner.clone() }),
                    request_id: format!("database-{}", requests.fetch_add(1, Ordering::Relaxed)),
                    cancel: cancel.clone(),
                })
            }),
            now: Arc::new(SystemTime::now),
            // Two small files of gcloud's, read for every connection: what the token source signs in as when it is given no account.
            active_account: Arc::new(|| crate::gcp::auth::active_account(&super::transports::gcloud_config_dir())),
            library: Arc::new(move || snapshot(&for_library)),
            // What the person asked for is remembered for the entitlement on this device, as for a host; a memory that cannot be written
            // does not fail the connection.
            remember: Arc::new(move |name: &str, justification: &str, duration_secs: u32| {
                let _ = crate::sync::engine::with_env(&for_memory, |env| {
                    let now = env.now();
                    crate::sync::record_runtime::mutate_records(env, |state| {
                        Ok(crate::sync::pam_records::remember(state, name, justification, duration_secs, None, now).unwrap_or_else(|| state.clone()))
                    })?;
                    env.events.wake();
                    Ok::<_, AppError>(())
                });
            }),
            link: Arc::new(BrokerLink { app: app.clone() }),
            dial: Arc::new(|address: SocketAddr, config: Arc<ClientConfig>, name: ServerName<'static>| -> BoxFuture<'static, io::Result<BoxStream>> {
                Box::pin(async move { cloudsql_tls::dial(address, config, name).await.map(|stream| Box::new(stream) as BoxStream) })
            }),
            routes: Mutex::default(),
            generations: AtomicU64::new(1),
        }
    }

    /// What `db`'s connections share: a new route when `db` was saved anew since the last one. The route it replaces closes its path now,
    /// as a database that stops does.
    fn route(&self, db: &SavedDatabase) -> Arc<Route> {
        let mut routes = locked(&self.routes);
        if let Some(route) = routes.get(&db.id).filter(|route| route.database == *db) {
            return Arc::clone(route);
        }
        let route = Arc::new(Route { database: db.clone(), fetching: Mutex::new(()), kept: Mutex::default(), opening: Mutex::new(()), path: Mutex::new(None) });
        if let Some(before) = routes.insert(db.id.clone(), Arc::clone(&route)) {
            drop(locked(&before.path).take());
        }
        route
    }

    /// Whether the grant `db` asks for is held for `account`; PAM is asked when the last check no longer stands. When none is, the material
    /// had under the grant that ended goes, and the person is asked for a grant in Lunport's window. Answers whether the grant was given
    /// moments ago.
    fn grant(&self, db: &SavedDatabase, route: &Route, account: &Option<String>, cancel: &CancelToken) -> Result<bool, NotReady> {
        if db.pam.is_none() {
            return Ok(false);
        }
        let now = (self.now)();
        if locked(&route.kept).grant.as_ref().is_some_and(|check| check.for_account == *account && check.stands(now)) {
            return Ok(false);
        }
        match grant_state(self.gcp.as_ref(), db, now)? {
            GrantState::NotNeeded => Ok(false),
            GrantState::Held { recent, until } => {
                locked(&route.kept).grant = (!recent).then(|| CheckedGrant { for_account: account.clone(), until, checked_at: now });
                Ok(recent)
            }
            GrantState::Needed => {
                {
                    let mut kept = locked(&route.kept);
                    kept.grant = None;
                    kept.dial = None;
                }
                // However the request ended, the grant was not had: the connection's grant is refused.
                self.request_grant(db, cancel).map_err(NotReady::Refused)?;
                Ok(true)
            }
        }
    }

    /// Asks the person for the grant `db` needs and requests it, as a connection does when none is held: through the app's gates, in
    /// Lunport's Request-a-grant window, remembering on this device what they answered. Answers when the grant is active, or with the
    /// sentence of why not. Blocks until then (for as long as the person takes to answer, and then for the request), so it runs on a
    /// blocking thread.
    pub(crate) fn request_grant(&self, db: &SavedDatabase, cancel: &CancelToken) -> Result<(), String> {
        let library = (self.library)()?;
        let owner = (self.make_owner)(cancel);
        let remember = |name: &str, justification: &str, duration_secs: u32| (self.remember)(name, justification, duration_secs);
        obtain_grant(&self.gates, self.gcp.as_ref(), owner.as_ref(), &library, db, &remember, cancel)
    }

    /// The database user of `db`'s connections as `account`, the number of the material to dial it with and the instance address it dials,
    /// kept until `REFRESH_AHEAD` before its certificate stops being useful and fetched anew after that (`recent_grant`: the grant it relies
    /// on was given moments ago). Also answers whether the new certificate is for another account than the last one although `account`
    /// reads the same: the token source's credentials changed under it, and the grant was checked for the other account.
    fn material(&self, db: &SavedDatabase, route: &Route, account: &Option<String>, recent_grant: bool, cancel: &CancelToken) -> Result<(String, u64, IpAddr, bool), NotReady> {
        let _fetching = locked(&route.fetching);
        let usable = |dial: &&Dial| dial.for_account == *account && (self.now)() + REFRESH_AHEAD < dial.expires_at;
        if let Some(dial) = locked(&route.kept).dial.as_ref().filter(usable) {
            return Ok((dial.iam_user.clone(), dial.generation, dial.ip, false));
        }
        let material = fetch_material(self.sql.as_ref(), db, recent_grant, Grace::default(), cancel)?;
        let identity = ServerIdentity { dns_name: material.settings.dns_name.clone(), project: db.project.clone(), instance: db.instance.clone() };
        let config = client_config(&material.settings, &material.cert, &material.key, &identity).map_err(NotReady::Failed)?;
        let mut kept = locked(&route.kept);
        let other_account = kept.account.as_ref().is_some_and(|before| *before != material.cert.account);
        if other_account {
            kept.grant = None;
        }
        kept.account = Some(material.cert.account.clone());
        let generation = self.generations.fetch_add(1, Ordering::Relaxed);
        kept.dial = Some(Dial {
            generation,
            for_account: account.clone(),
            iam_user: material.iam_user.clone(),
            expires_at: material.cert.expires_at,
            ip: material.ip,
            config,
            name: server_name(&identity),
        });
        Ok((material.iam_user.clone(), generation, material.ip, other_account))
    }

    /// The alias of `host`, the host `db` is reached through, with `route`'s path to it live: the live one is kept, and a dead one is replaced
    /// by a session the link opens now (dropping the dead one closes it). The caller holds `route.opening`. It blocks for as long as the
    /// connect takes, the questions the host's login asks of the person included.
    fn path(&self, db: &SavedDatabase, route: &Route, host: &str, cancel: &CancelToken) -> Result<String, NotReady> {
        {
            let mut path = locked(&route.path);
            if let Some(live) = path.as_ref().filter(|path| path.alive()) {
                return Ok(live.alias().to_string());
            }
            drop(path.take());
        }
        let library = (self.library)().map_err(NotReady::Failed)?;
        let Ok(view) = repo::get_host(&library, host) else {
            return Err(NotReady::Failed(format!(
                "{} connects through a host that is no longer in your library. Choose another host in its settings.",
                label(&db.name)
            )));
        };
        let alias = view.host.payload.alias;
        let owner = (self.make_owner)(cancel);
        let opened = self.link.open(host, owner.as_ref(), cancel);
        if cancel.is_cancelled() {
            // A session that opened anyway goes with a path of its own, which closes it.
            drop(opened.map(|session| HostPath::new(session, alias)));
            return Err(NotReady::Failed(CANCELLED.to_string()));
        }
        let session = opened.map_err(|sentence| NotReady::Failed(format!("Could not connect through {}: {sentence}", label(&alias))))?;
        *locked(&route.path) = Some(HostPath::new(session, alias.clone()));
        Ok(alias)
    }

    /// Has `route`'s path forward a port of 127.0.0.1 to the instance at `ip`, unless such a forward runs already. `alias` is the host's, as
    /// `path` answered it. The caller holds `route.opening`.
    fn forward(&self, db: &SavedDatabase, route: &Route, alias: &str, ip: IpAddr) -> Result<(), NotReady> {
        let mut path = locked(&route.path);
        let forwarded = match path.as_mut() {
            Some(path) => path.forward_to(ip).map(drop),
            // Only a database that stops, or is saved anew, takes the path away meanwhile.
            None => Err(PATH_CLOSED.to_string()),
        };
        forwarded.map_err(|reason| NotReady::Failed(format!("Could not reach {} through {}: {reason}", db.connection_name(), label(alias))))
    }
}

/// A connection that fails at once with `sentence` and dials nothing.
fn failing(kind: io::ErrorKind, sentence: &'static str) -> Dialling {
    Dialling { material: None, stream: Box::pin(async move { Err(io::Error::new(kind, sentence)) }) }
}

/// A dial through the host `alias` to the instance at `ip` that failed, said as the person knows the way there: the host and the instance's
/// address, never the loopback end of the forward, which is all the dial itself saw. The forward's latest error says why the host could not
/// reach the instance, when it has one. The error keeps the kind of the dial's own, but for an end of file: the forward ends a connection
/// it could not carry that way, and the port would tell the app that Cloud SQL closed it.
fn through_host(route: &Route, alias: &str, ip: IpAddr, error: io::Error) -> io::Error {
    let instance = SocketAddr::new(ip, cloudsql_tls::PORT);
    let reason = locked(&route.path).as_ref().and_then(|path| path.forward_error(ip));
    let sentence = match reason {
        Some(reason) => format!("{} could not reach {instance}: {reason}", label(alias)),
        None => format!("Cloud SQL at {instance} did not answer through {}.", label(alias)),
    };
    let kind = match error.kind() {
        io::ErrorKind::UnexpectedEof => io::ErrorKind::ConnectionAborted,
        kind => kind,
    };
    io::Error::new(kind, sentence)
}

impl Upstream for CloudSqlUpstream {
    fn prepare(&self, db: &SavedDatabase, cancel: &CancelToken) -> Result<Prepared, NotReady> {
        let route = self.route(db);
        // The account the connection signs in as: the database's own, else gcloud's active one, which the person can switch at any time.
        let account = db.account.clone().or_else(|| (self.active_account)());
        locked(&route.kept).keep_for(&account);
        let mut checked_for_new_account = false;
        loop {
            let recent_grant = self.grant(db, &route, &account, cancel)?;
            // Through a host, the session to it comes after the grant and before the material, and `opening` is held until the forward is
            // had.
            let through = match db.route_host() {
                Some(host) => {
                    let opening = locked(&route.opening);
                    Some((opening, self.path(db, &route, host, cancel)?))
                }
                None => None,
            };
            let (iam_user, material, ip, other_account) = self.material(db, &route, &account, recent_grant, cancel)?;
            // A certificate for another account than the last one is used once the grant was checked for its account.
            if other_account && db.pam.is_some() && !checked_for_new_account {
                checked_for_new_account = true;
                continue;
            }
            if let Some((_opening, alias)) = through {
                self.forward(db, &route, &alias, ip)?;
            }
            return Ok(Prepared { iam_user, material });
        }
    }

    fn connect(&self, db_id: &str, material: Option<u64>) -> Dialling {
        let route = locked(&self.routes).get(db_id).cloned();
        // The material the connection got ready with, or none: another certificate could be for another account than its user.
        let target = route.as_ref().and_then(|route| {
            let kept = locked(&route.kept);
            let dial = kept.dial.as_ref().filter(|dial| material.is_none_or(|material| dial.generation == material))?;
            Some((dial.generation, dial.ip, Arc::clone(&dial.config), dial.name.clone()))
        });
        let (Some(route), Some((generation, ip, config, name))) = (route, target) else {
            return failing(io::ErrorKind::NotFound, NO_CERTIFICATE);
        };
        if route.database.route_host().is_none() {
            return Dialling { material: Some(generation), stream: (self.dial)(SocketAddr::new(ip, cloudsql_tls::PORT), config, name) };
        }
        // Through a host, the connection dials the loopback end of the path's forward to the instance. This runs in async code: the forward
        // is looked up here, never opened.
        let forward = locked(&route.path).as_ref().and_then(|path| Some((path.port_for(ip)?, path.alias().to_string())));
        let Some((port, alias)) = forward else {
            // Not dialled with, the material stays for the next connection.
            return failing(io::ErrorKind::NotConnected, PATH_NOT_OPEN);
        };
        let dialling = (self.dial)(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port), config, name);
        Dialling { material: Some(generation), stream: Box::pin(async move { dialling.await.map_err(|error| through_host(&route, &alias, ip, error)) }) }
    }

    fn forget(&self, db_id: &str, material: u64) {
        if let Some(route) = locked(&self.routes).get(db_id) {
            let mut kept = locked(&route.kept);
            if kept.dial.as_ref().is_some_and(|dial| dial.generation == material) {
                kept.dial = None;
            }
        }
    }

    fn release(&self, db_id: &str) {
        // A connection still on its way keeps the route it started with; what it gets goes with it. The path through a host is closed now
        // all the same.
        let mut routes = locked(&self.routes);
        if let Some(route) = routes.get(db_id) {
            drop(locked(&route.path).take());
        }
        routes.remove(db_id);
    }
}

#[cfg(test)]
#[path = "database_upstream_tests.rs"]
mod tests;
