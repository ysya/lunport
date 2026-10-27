use super::*;
use crate::gcp::pam::Grant;
use crate::gcp::rest::GcpError;
use crate::gcp::oslogin::LoginProfile;
use crate::sync::transports::PamCheck;
use std::collections::BTreeMap;
use std::sync::Mutex;

const H1: &str = "0000000000000001";
const H2: &str = "0000000000000002";
const FRANK: &str = "frank@example.com";
const OPS: &str = "ops@example.com";
const OPERATE: &str = "projects/acme-prod-123456/locations/global/entitlements/prod-operate";
const ADMIN: &str = "projects/acme-prod-123456/locations/global/entitlements/prod-admin";
const DEV: &str = "projects/acme-dev-654321/locations/global/entitlements/dev-operate";
const BREAK_GLASS: &str = "folders/123456789012/locations/global/entitlements/break-glass";

fn route(host: &str, account: Option<&str>, entitlements: &[&str]) -> HostTransport {
    HostTransport {
        host_id: host.into(),
        kind: TransportKind::GcpIap {
            project: "acme-prod-123456".into(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic0".into(),
            account: account.map(str::to_string),
            os_login: false,
            pam: Some(PamCheck { entitlements: entitlements.iter().map(|e| e.to_string()).collect(), location: "global".into(), duration_secs: 2700, justification: None }),
        },
    }
}

fn scope(id: &str, parent: &str, account: Option<&str>) -> PamScope {
    PamScope { id: id.into(), parent: parent.into(), location: "global".into(), account: account.map(str::to_string) }
}

fn info(name: &str, approval: bool) -> EntitlementInfo {
    EntitlementInfo { name: name.into(), max_duration_secs: Some(3600), needs_approval: approval, roles: vec![("roles/container.developer".into(), "projects/acme-dev-654321".into())] }
}

/// Google as the Access tab sees it: what each scope's search finds (or the API's refusal), each entitlement's grants, and every call.
#[derive(Default)]
struct Google {
    found: BTreeMap<String, Result<Vec<EntitlementInfo>, String>>,
    grants: BTreeMap<String, Vec<Grant>>,
    calls: Mutex<Vec<String>>,
}

impl GcpClient for Google {
    fn login_profile(&self, _: Option<&str>, _: &str) -> Result<LoginProfile, GcpError> {
        panic!("the Access tab never reads OS Login")
    }
    fn import_ssh_public_key(&self, _: Option<&str>, _: &str, _: &str) -> Result<LoginProfile, GcpError> {
        panic!("the Access tab never imports a key")
    }
    fn grants(&self, account: Option<&str>, name: &str) -> Result<Vec<Grant>, GcpError> {
        self.calls.lock().unwrap().push(format!("grants {} {name}", account.unwrap_or("-")));
        Ok(self.grants.get(name).cloned().unwrap_or_default())
    }
    fn create_grant(&self, _: Option<&str>, _: &str, _: u32, _: &str) -> Result<Grant, GcpError> {
        panic!("the overview requests nothing")
    }
    fn get_grant(&self, _: Option<&str>, _: &str) -> Result<Grant, GcpError> {
        panic!("the overview reads no grant back")
    }
    fn search_entitlements(&self, account: Option<&str>, scope: &str) -> Result<Vec<EntitlementInfo>, GcpError> {
        self.calls.lock().unwrap().push(format!("search {} {scope}", account.unwrap_or("-")));
        match self.found.get(scope) {
            Some(Ok(found)) => Ok(found.clone()),
            Some(Err(message)) => Err(GcpError::Refused { api: "Privileged Access Manager", message: message.clone() }),
            None => Ok(vec![]),
        }
    }
}

fn grant(state: &str) -> Grant {
    Grant { name: "g".into(), state: state.into(), requested_duration: Some("1800s".into()), access_grant_time: None, justification: None }
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn names(overview: &PamOverview) -> Vec<(Option<&str>, &str)> {
    overview.entitlements.iter().map(|row| (row.account.as_deref(), row.name.as_str())).collect()
}

/// Design 2026-10-27: routes' projects are searched as their accounts (none: the active one), added scopes as theirs, each place once;
/// every entitlement found or named by a route is a row, one per account and name, with the hosts that need it.
#[test]
fn the_overview_searches_route_and_added_scopes_and_lists_each_entitlement_once_per_account() {
    let mut google = Google::default();
    google.found.insert("projects/acme-prod-123456/locations/global".into(), Ok(vec![info(OPERATE, false)]));
    google.found.insert("projects/acme-dev-654321/locations/global".into(), Ok(vec![info(DEV, false)]));
    google.found.insert("folders/123456789012/locations/global".into(), Ok(vec![info(BREAK_GLASS, true)]));
    let routes = [route(H1, None, &["prod-operate", "prod-admin"]), route(H2, Some(FRANK), &["prod-operate"])];
    let added = [scope("00000000000000a1", "projects/acme-dev-654321", None), scope("00000000000000a2", "folders/123456789012", Some(OPS))];
    let overview = overview(&google, Some(FRANK), &routes, &added, &[], later());
    let searches: Vec<String> = google.calls.lock().unwrap().iter().filter(|call| call.starts_with("search")).cloned().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    assert_eq!(
        searches,
        [
            "search frank@example.com projects/acme-dev-654321/locations/global",
            "search frank@example.com projects/acme-prod-123456/locations/global",
            "search ops@example.com folders/123456789012/locations/global",
        ],
        "a route without an account is the active account's, and shares its place with the route that names it"
    );
    assert_eq!(names(&overview), [(Some(FRANK), DEV), (Some(FRANK), ADMIN), (Some(FRANK), OPERATE), (Some(OPS), BREAK_GLASS)], "by account, then name");
    let operate = overview.entitlements.iter().find(|row| row.name == OPERATE).unwrap();
    assert_eq!(operate.host_ids, [H1, H2]);
    assert_eq!((operate.parent.as_str(), operate.entitlement.as_str(), operate.max_duration_secs), ("projects/acme-prod-123456", "prod-operate", Some(3600)));
    assert_eq!(operate.default_duration_secs, 2700, "the route's default length");
    let admin = overview.entitlements.iter().find(|row| row.name == ADMIN).unwrap();
    assert_eq!((admin.max_duration_secs, admin.roles.len()), (None, 0), "named by a route, not returned by the search: listed all the same");
    let glass = overview.entitlements.iter().find(|row| row.name == BREAK_GLASS).unwrap();
    assert!(glass.needs_approval && glass.host_ids.is_empty());
    assert_eq!(glass.default_duration_secs, 1800);
    assert_eq!(overview.scopes.iter().map(|scope| (scope.from_routes, scope.parent.as_str())).collect::<Vec<_>>(), [
        (true, "projects/acme-prod-123456"),
        (false, "projects/acme-dev-654321"),
        (false, "folders/123456789012"),
    ]);
    assert_eq!(overview.scopes[0].host_ids, [H1, H2]);
}

#[test]
fn a_failed_search_is_said_on_its_scope_and_the_routes_entitlements_stay() {
    let mut google = Google::default();
    google.found.insert("projects/acme-prod-123456/locations/global".into(), Err("frank@example.com lacks privilegedaccessmanager.entitlements.search".into()));
    let overview = overview(&google, Some(FRANK), &[route(H1, None, &["prod-operate"])], &[], &[], later());
    assert!(overview.scopes[0].message.as_deref().is_some_and(|message| message.contains("lacks")));
    assert_eq!(names(&overview), [(Some(FRANK), OPERATE)]);
}

#[test]
fn each_row_has_its_grants_state_and_memory() {
    let mut google = Google::default();
    google.grants.insert(OPERATE.into(), vec![grant("ENDED"), grant("APPROVAL_AWAITED")]);
    google.grants.insert(ADMIN.into(), vec![grant("ACTIVATING")]);
    let memory = GrantRequestMemory { name: OPERATE.into(), justification: "restart app-api".into(), duration_secs: 3600 };
    let overview = overview(&google, Some(FRANK), &[route(H1, None, &["prod-operate", "prod-admin"])], &[], std::slice::from_ref(&memory), later());
    let state = |name: &str| overview.entitlements.iter().find(|row| row.name == name).map(|row| (row.state.clone(), row.memory.clone())).unwrap();
    assert_eq!(state(OPERATE), ("approval_awaited".into(), Some(memory)));
    assert_eq!(state(ADMIN), ("activating".into(), None));
}

#[test]
fn past_the_deadline_nothing_more_is_asked_and_every_row_says_so() {
    let google = Google::default();
    let overview = overview(&google, Some(FRANK), &[route(H1, None, &["prod-operate"])], &[], &[], Instant::now());
    assert!(google.calls.lock().unwrap().is_empty());
    assert_eq!(overview.scopes[0].message.as_deref(), Some(LATE));
    assert_eq!((overview.entitlements[0].state.as_str(), overview.entitlements[0].message.as_deref()), ("error", Some(LATE)));
}

/// `gcp_pam_request` asks only for what the tab lists: a route's entitlement as its account, or one in a listed place.
#[test]
fn only_a_listed_entitlement_may_be_requested() {
    let routes = [route(H1, None, &["prod-operate"])];
    let added = [scope("00000000000000a1", "folders/123456789012", Some(OPS))];
    assert!(listed(OPERATE, Some(FRANK), Some(FRANK), &routes, &added), "a route's, as the active account");
    assert!(listed(OPERATE, None, Some(FRANK), &routes, &added), "none is the active account");
    assert!(listed(ADMIN, Some(FRANK), Some(FRANK), &routes, &added), "in the place the route uses");
    assert!(!listed(OPERATE, Some(OPS), Some(FRANK), &routes, &added), "another account");
    assert!(listed(BREAK_GLASS, Some(OPS), Some(FRANK), &routes, &added), "in an added scope, as its account");
    assert!(!listed(BREAK_GLASS, Some(FRANK), Some(FRANK), &routes, &added));
    assert!(!listed(DEV, Some(FRANK), Some(FRANK), &routes, &added), "a place nobody listed");
    assert!(!listed("projects/x", Some(FRANK), Some(FRANK), &routes, &added));
}

#[test]
fn suggestions_are_the_ids_the_search_finds_and_none_when_it_fails() {
    let mut google = Google::default();
    google.found.insert("projects/acme-dev-654321/locations/global".into(), Ok(vec![info(DEV, false), info("projects/acme-dev-654321/locations/global/entitlements/dev-admin", true)]));
    assert_eq!(suggestions(&google, Some(FRANK), "acme-dev-654321", "global"), ["dev-admin", "dev-operate"]);
    google.found.insert("projects/acme-dev-654321/locations/global".into(), Err("no".into()));
    assert!(suggestions(&google, Some(FRANK), "acme-dev-654321", "global").is_empty());
}
