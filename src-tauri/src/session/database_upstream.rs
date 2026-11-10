//! How the local ports of the saved databases reach Cloud SQL: the grant a database asks for, the connection material the Cloud SQL Admin
//! API signs, and the TLS dial to the instance, kept for a database's next connections while they last.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use futures_util::future::BoxFuture;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tauri::Manager;

use super::auth::Owner;
use super::auth_window::{NativeOwner, TauriAuthSurface};
use super::broker::Broker;
use super::connect::CancelToken;
use super::database_access::{fetch_material, grant_state, obtain_grant, Grace, GrantState};
use super::database_ports::{locked, BoxStream, Dialling, Prepared, Upstream};
use super::grants::GrantGates;
use super::tunnels::snapshot;
use crate::error::AppError;
use crate::gcp::cloudsql::SqlAdmin;
use crate::gcp::cloudsql_tls::{self, client_config, server_name, ServerIdentity};
use crate::gcp::rest::GcpClient;
use crate::state::AppState;
use crate::sync::databases::SavedDatabase;
use crate::sync::records_v3::SyncStateV3;

/// How long before a client certificate stops being useful a connection gets a new one.
pub const REFRESH_AHEAD: Duration = Duration::from_secs(4 * 60);
/// How long a check that a grant is held is trusted at most.
const GRANT_RECHECK: Duration = Duration::from_secs(5 * 60);

/// Makes the owner that asks the person on behalf of a connection that `cancel` cancels.
type MakeOwner = Arc<dyn Fn(&CancelToken) -> Box<dyn Owner + Send> + Send + Sync>;
/// Dials an instance: its public address, the TLS configuration of the connection, and the name its certificate must be made out to.
type Dialer = Arc<dyn Fn(IpAddr, Arc<ClientConfig>, ServerName<'static>) -> BoxFuture<'static, io::Result<BoxStream>> + Send + Sync>;

/// How the app's ports reach Cloud SQL. The grant a database asks for is requested through the gates hosts use, so that a host and a
/// database that need the same grant ask the person once; the connection material comes from the Cloud SQL Admin API. Both are kept for a
/// database's next connections while they last: a check that the grant is held for five minutes at most and never past the grant's end,
/// the material until `REFRESH_AHEAD` before its certificate stops being useful. Both are for the Google account the connections sign in
/// as, and go when it changes; a grant that ended takes the material had under it along.
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
    dial: Dialer,
    /// What each database's connections share, by the database's id.
    routes: Mutex<HashMap<String, Arc<Route>>>,
    /// The number of the next material fetched, counted from 1.
    generations: AtomicU64,
}

/// What the connections to one database, as it was saved, share. A database saved anew (another account, instance or grant check) gets a
/// route of its own: a connection still on its way with the route before cannot leave anything in it.
struct Route {
    database: SavedDatabase,
    /// Held while the material is fetched, so that connections that start together share one fetch.
    fetching: Mutex<()>,
    kept: Mutex<Kept>,
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
    ip: IpAddr,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}

impl CloudSqlUpstream {
    /// The upstream of the app's ports: Google's APIs through the app's clients, the broker's grant gates, a person's questions in
    /// Lunport's windows (a person starts a port, as a person starts a tunnel), and this device's grant memory.
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
            dial: Arc::new(|ip: IpAddr, config: Arc<ClientConfig>, name: ServerName<'static>| -> BoxFuture<'static, io::Result<BoxStream>> {
                Box::pin(async move { cloudsql_tls::dial(ip, config, name).await.map(|stream| Box::new(stream) as BoxStream) })
            }),
            routes: Mutex::default(),
            generations: AtomicU64::new(1),
        }
    }

    /// What `db`'s connections share: a new route when `db` was saved anew since the last one.
    fn route(&self, db: &SavedDatabase) -> Arc<Route> {
        let mut routes = locked(&self.routes);
        if let Some(route) = routes.get(&db.id).filter(|route| route.database == *db) {
            return Arc::clone(route);
        }
        let route = Arc::new(Route { database: db.clone(), fetching: Mutex::new(()), kept: Mutex::default() });
        routes.insert(db.id.clone(), Arc::clone(&route));
        route
    }

    /// Whether the grant `db` asks for is held for `account`; PAM is asked when the last check no longer stands. When none is, the material
    /// had under the grant that ended goes, and the person is asked for a grant in Lunport's window. Answers whether the grant was given
    /// moments ago.
    fn grant(&self, db: &SavedDatabase, route: &Route, account: &Option<String>, cancel: &CancelToken) -> Result<bool, String> {
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
                let library = (self.library)()?;
                let owner = (self.make_owner)(cancel);
                let remember = |name: &str, justification: &str, duration_secs: u32| (self.remember)(name, justification, duration_secs);
                obtain_grant(&self.gates, self.gcp.as_ref(), owner.as_ref(), &library, db, &remember, cancel)?;
                Ok(true)
            }
        }
    }

    /// The database user of `db`'s connections as `account`, and the number of the material to dial it with, kept until `REFRESH_AHEAD`
    /// before its certificate stops being useful and fetched anew after that (`recent_grant`: the grant it relies on was given moments
    /// ago). Also answers whether the new certificate is for another account than the last one although `account` reads the same: the
    /// token source's credentials changed under it, and the grant was checked for the other account.
    fn material(&self, db: &SavedDatabase, route: &Route, account: &Option<String>, recent_grant: bool, cancel: &CancelToken) -> Result<(String, u64, bool), String> {
        let _fetching = locked(&route.fetching);
        let usable = |dial: &&Dial| dial.for_account == *account && (self.now)() + REFRESH_AHEAD < dial.expires_at;
        if let Some(dial) = locked(&route.kept).dial.as_ref().filter(usable) {
            return Ok((dial.iam_user.clone(), dial.generation, false));
        }
        let material = fetch_material(self.sql.as_ref(), db, recent_grant, Grace::default(), cancel)?;
        let identity = ServerIdentity { dns_name: material.settings.dns_name.clone(), project: db.project.clone(), instance: db.instance.clone() };
        let config = client_config(&material.settings, &material.cert, &material.key, &identity)?;
        let ip = material.settings.public_ip.ok_or_else(|| format!("{} has no public IP.", db.connection_name()))?;
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
            ip,
            config,
            name: server_name(&identity),
        });
        Ok((material.iam_user.clone(), generation, other_account))
    }
}

impl Upstream for CloudSqlUpstream {
    fn prepare(&self, db: &SavedDatabase, cancel: &CancelToken) -> Result<Prepared, String> {
        let route = self.route(db);
        // The account the connection signs in as: the database's own, else gcloud's active one, which the person can switch at any time.
        let account = db.account.clone().or_else(|| (self.active_account)());
        locked(&route.kept).keep_for(&account);
        let mut checked_for_new_account = false;
        loop {
            let recent_grant = self.grant(db, &route, &account, cancel)?;
            let (iam_user, material, other_account) = self.material(db, &route, &account, recent_grant, cancel)?;
            // A certificate for another account than the last one is used once the grant was checked for its account.
            if other_account && db.pam.is_some() && !checked_for_new_account {
                checked_for_new_account = true;
                continue;
            }
            return Ok(Prepared { iam_user, material });
        }
    }

    fn connect(&self, db_id: &str, material: Option<u64>) -> Dialling {
        let route = locked(&self.routes).get(db_id).cloned();
        // The material the connection got ready with, or none: another certificate could be for another account than its user.
        let target = route.and_then(|route| {
            let kept = locked(&route.kept);
            let dial = kept.dial.as_ref().filter(|dial| material.is_none_or(|material| dial.generation == material))?;
            Some((dial.generation, dial.ip, Arc::clone(&dial.config), dial.name.clone()))
        });
        match target {
            Some((generation, ip, config, name)) => Dialling { material: Some(generation), stream: (self.dial)(ip, config, name) },
            None => Dialling {
                material: None,
                stream: Box::pin(async { Err(io::Error::new(io::ErrorKind::NotFound, "no certificate is ready for it. Connect again.")) }),
            },
        }
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
        // A connection still on its way keeps the route it started with; what it gets goes with it.
        locked(&self.routes).remove(db_id);
    }
}

#[cfg(test)]
#[path = "database_upstream_tests.rs"]
mod tests;
