//! Privileged Access Manager grants (`privilegedaccessmanager.googleapis.com` v1): the caller's own grants on one entitlement, and which of
//! them are in flight. The REST call lives in `gcp::rest`; the broker checks for a grant before it opens a tunnel to a production host,
//! so the person reads "no grant" instead of IAP's bare 4033.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::rest::{GcpClient, GcpError};

/// One grant, as much of it as the broker reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub name: String,
    /// `ACTIVE`, `SCHEDULED`, `ENDED`, … (the API's `state`).
    pub state: String,
    /// `1800s`, as the API writes durations.
    pub requested_duration: Option<String>,
    /// `auditTrail.accessGrantTime`, RFC 3339, once access was given.
    pub access_grant_time: Option<String>,
    /// `justification.unstructuredJustification`: what the person wrote when requesting.
    pub justification: Option<String>,
}

impl Grant {
    /// When access ends: the grant time plus the requested duration; `None` until access was given.
    pub fn until(&self) -> Option<SystemTime> {
        let granted = parse_rfc3339(self.access_grant_time.as_deref()?)?;
        let seconds: f64 = self.requested_duration.as_deref()?.strip_suffix('s')?.parse().ok()?;
        Some(granted + Duration::from_secs_f64(seconds.max(0.0)))
    }

    /// Whether nothing more will happen to the grant without a person: every state but `ACTIVATING`, `ACTIVE` and `SCHEDULED`
    /// (`APPROVAL_AWAITED` included: Lunport does not wait for an approver).
    pub fn is_final(&self) -> bool {
        !matches!(self.state.as_str(), "ACTIVATING" | "ACTIVE" | "SCHEDULED")
    }
}

/// A duration as PAM writes it (`1800s`).
pub fn duration_text(seconds: u32) -> String {
    format!("{seconds}s")
}

/// The grants of a `grants:search` answer as JSON (the fixtures' shape); the live client answers typed grants through `From`.
#[cfg(test)]
pub fn parse_grants(value: &serde_json::Value) -> Vec<Grant> {
    let text = |value: &serde_json::Value, name: &str| value.get(name).and_then(serde_json::Value::as_str).map(str::to_string);
    value
        .get("grants")
        .and_then(serde_json::Value::as_array)
        .map(|grants| {
            grants
                .iter()
                .map(|grant| Grant {
                    name: text(grant, "name").unwrap_or_default(),
                    state: text(grant, "state").unwrap_or_default(),
                    requested_duration: text(grant, "requestedDuration"),
                    access_grant_time: grant.get("auditTrail").and_then(|trail| text(trail, "accessGrantTime")),
                    justification: grant.get("justification").and_then(|justification| text(justification, "unstructuredJustification")),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The client library's grant as the broker reads it: the state by its API name, the duration as `<seconds>s`, the grant time as the
/// RFC 3339 text the library would write (so `granted_within` parses it as it parses the fixtures).
impl From<google_cloud_privilegedaccessmanager_v1::model::Grant> for Grant {
    fn from(grant: google_cloud_privilegedaccessmanager_v1::model::Grant) -> Grant {
        let granted = grant.audit_trail.as_ref().and_then(|trail| trail.access_grant_time.as_ref());
        Grant {
            name: grant.name.clone(),
            state: grant.state.name().map(str::to_string).unwrap_or_else(|| format!("{:?}", grant.state)),
            requested_duration: grant.requested_duration.as_ref().map(|duration| duration_text(u32::try_from(duration.seconds()).unwrap_or(0))),
            access_grant_time: granted.and_then(|time| serde_json::to_value(time).ok()).and_then(|value| value.as_str().map(str::to_string)),
            justification: grant.justification.as_ref().and_then(|justification| justification.unstructured_justification().cloned()),
        }
    }
}

/// The grants that give access now or are about to: `ACTIVE`, `ACTIVATING`, `SCHEDULED`.
pub fn in_flight(grants: &[Grant]) -> Vec<&Grant> {
    grants.iter().filter(|grant| matches!(grant.state.as_str(), "ACTIVE" | "ACTIVATING" | "SCHEDULED")).collect()
}

/// Whether the grant's access was given within `window` before `now` (IAP can take a while to honour a fresh grant). A grant time ahead
/// of `now` is a grant just given by a clock that runs ahead of this one: recent. The broker dates grants with `granted_at` now; this
/// stays for its test of the time parsing.
#[cfg(test)]
pub fn granted_within(grant: &Grant, now: SystemTime, window: Duration) -> bool {
    grant
        .access_grant_time
        .as_deref()
        .and_then(parse_rfc3339)
        .is_some_and(|granted| now.duration_since(granted).map_or(true, |age| age <= window))
}

/// When the grant's access was given, as far as this computer can tell: the grant time (never ahead of `now`), or `now` for a grant
/// still activating (its time comes with activation); `None` for a grant PAM did not date.
pub fn granted_at(grant: &Grant, now: SystemTime) -> Option<SystemTime> {
    match grant.access_grant_time.as_deref().and_then(parse_rfc3339) {
        Some(time) => Some(time.min(now)),
        None if grant.state == "ACTIVATING" => Some(now),
        None => None,
    }
}

/// When an active grant's access began and ends: from its own times, else from `now` and the duration that was asked for.
pub fn active_span(grant: &Grant, now: SystemTime, duration_secs: u32) -> (SystemTime, SystemTime) {
    let began = granted_at(grant, now).unwrap_or(now);
    let length = grant.until().and_then(|until| until.duration_since(began).ok()).unwrap_or(Duration::from_secs(u64::from(duration_secs)));
    (began, began + length)
}

/// Where a grant lives: the caller's account (or gcloud's active one) and the entitlement's full name
/// (`EntitlementName::full`).
pub struct Entitlement<'a> {
    pub account: Option<&'a str>,
    pub name: &'a str,
}

/// An entitlement's full name, in parts: its parent (`projects/<id>`, `folders/<number>` or `organizations/<number>`), its location and
/// its id. Entitlements live on any of the three (design 2026-10-27, The Access tab); a route's always on its project.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntitlementName {
    pub parent: String,
    pub location: String,
    pub id: String,
}

/// A resource id as Google spells locations and entitlement ids: a lower-case letter, then lower-case letters, digits and hyphens, at
/// most 63 characters, not ending in a hyphen.
pub fn is_resource_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !text.ends_with('-')
}

/// A project id (6–30 lower-case letters, digits and hyphens, starting with a letter, not ending with a hyphen), optionally after a
/// `domain.example:` prefix as older Google Workspace projects have it, or a project number.
pub fn is_project_id(text: &str) -> bool {
    let id = match text.rsplit_once(':') {
        Some((domain, id)) if !domain.is_empty() && domain.split('.').all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')) => id,
        Some(_) => return false,
        None => text,
    };
    let numeric = (6..=20).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit());
    numeric || ((6..=30).contains(&id.len()) && is_resource_id(id))
}

/// A parent PAM entitlements live on: `projects/<project id>`, `folders/<number>` or `organizations/<number>`.
pub fn is_parent(text: &str) -> bool {
    let number = |id: &str| (1..=20).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit());
    match text.split_once('/') {
        Some(("projects", id)) => is_project_id(id),
        Some(("folders" | "organizations", id)) => number(id),
        _ => false,
    }
}

impl EntitlementName {
    /// The entitlement `id` in `location` of `project`, as a route names it.
    pub fn in_project(project: &str, location: &str, id: &str) -> EntitlementName {
        EntitlementName { parent: format!("projects/{project}"), location: location.to_string(), id: id.to_string() }
    }

    /// `<parent>/locations/<location>/entitlements/<id>` read back into its parts, when every part is well-formed.
    pub fn parse(name: &str) -> Option<EntitlementName> {
        let (scope, id) = name.rsplit_once("/entitlements/")?;
        let (parent, location) = scope.rsplit_once("/locations/")?;
        (is_parent(parent) && is_resource_id(location) && is_resource_id(id)).then(|| EntitlementName { parent: parent.into(), location: location.into(), id: id.into() })
    }

    /// `<parent>/locations/<location>/entitlements/<id>`: what PAM calls the entitlement, and the parent of its grants.
    pub fn full(&self) -> String {
        format!("{}/locations/{}/entitlements/{}", self.parent, self.location, self.id)
    }

    /// `<parent>/locations/<location>`: where the entitlement is searched for.
    pub fn scope(&self) -> String {
        format!("{}/locations/{}", self.parent, self.location)
    }
}

/// What an entitlement search learns of one entitlement the caller may request (design 2026-10-27, The Access tab).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntitlementInfo {
    /// The full name (`EntitlementName::full`).
    pub name: String,
    /// The most a request may ask for, when the entitlement says.
    pub max_duration_secs: Option<u32>,
    /// Whether a request waits for an approver (the entitlement has an approval workflow).
    pub needs_approval: bool,
    /// What a grant gives: each role, with the resource it is granted on.
    pub roles: Vec<(String, String)>,
}

impl From<google_cloud_privilegedaccessmanager_v1::model::Entitlement> for EntitlementInfo {
    fn from(entitlement: google_cloud_privilegedaccessmanager_v1::model::Entitlement) -> EntitlementInfo {
        let max_duration_secs = entitlement.max_request_duration.as_ref().and_then(|duration| u32::try_from(duration.seconds()).ok()).filter(|secs| *secs > 0);
        let roles = entitlement
            .privileged_access
            .as_ref()
            .and_then(|access| access.gcp_iam_access())
            .map(|iam| iam.role_bindings.iter().map(|binding| (binding.role.clone(), short_resource(&iam.resource))).collect())
            .unwrap_or_default();
        EntitlementInfo { name: entitlement.name.clone(), max_duration_secs, needs_approval: entitlement.approval_workflow.as_ref().is_some_and(|workflow| workflow.approval_workflow.is_some()), roles }
    }
}

/// A resource as IAM names it (`//cloudresourcemanager.googleapis.com/projects/acme-prod-123456`), without the service:
/// `projects/acme-prod-123456`.
pub fn short_resource(resource: &str) -> String {
    match resource.strip_prefix("//").and_then(|rest| rest.split_once('/')) {
        Some((service, path)) if service.ends_with(".googleapis.com") => path.to_string(),
        _ => resource.to_string(),
    }
}

/// The grants waiting for an approver: `APPROVAL_AWAITED`. Such a grant gives no access, but PAM refuses another request on the same
/// entitlement while it waits, so the Access tab's Request grant is off for it.
pub fn pending(grants: &[Grant]) -> Vec<&Grant> {
    grants.iter().filter(|grant| grant.state == "APPROVAL_AWAITED").collect()
}

/// How a grant request ended short of an active grant.
#[derive(Debug)]
pub enum RequestError {
    /// `cancelled` said so between steps.
    Cancelled,
    /// The API refused a call.
    Api(GcpError),
    /// The grant reached a state nothing more will come of without a person (`APPROVAL_AWAITED` included).
    NotActive { state: String },
    /// The grant was still on its way when the wait ran out.
    TimedOut { state: String },
}

impl RequestError {
    /// The sentence for the person, naming the entitlement (design 2026-10-25, PAM grant requests).
    pub fn sentence(&self, entitlement: &str) -> String {
        match self {
            RequestError::Cancelled => "The connection was cancelled.".to_string(),
            RequestError::Api(error) => error.to_string(),
            RequestError::NotActive { state } => {
                let why = if state == "APPROVAL_AWAITED" { "; Lunport does not wait for an approver" } else { "" };
                format!("The {entitlement} grant did not become active (state: {state}){why}.")
            }
            RequestError::TimedOut { state } => format!("The {entitlement} grant did not become active within a minute (state: {state}); try connecting again."),
        }
    }
}

/// Requests a grant on `place` for `duration_secs` with `justification` (or takes the one already in flight there, the most recent),
/// tells `remember` once a request was made, and reads the grant back every `poll_every` until it is `ACTIVE`, for at most `wait`.
/// `cancelled` is looked at between steps. The connect and the Google Cloud panel both request through here (design 2026-10-25).
///
/// With `approver` set (the Access tab, design 2026-10-27), a grant that waits for an approver is the answer, not a failure: a request
/// that lands in `APPROVAL_AWAITED`, or one already waiting there, is returned at once, since nothing more happens without the
/// approver. The connect never sets it: it does not wait for an approver.
#[allow(clippy::too_many_arguments)]
pub fn request_and_wait(
    gcp: &dyn GcpClient,
    place: &Entitlement<'_>,
    justification: &str,
    duration_secs: u32,
    remember: &dyn Fn(),
    poll_every: Duration,
    wait: Duration,
    cancelled: &dyn Fn() -> bool,
    approver: bool,
) -> Result<Grant, RequestError> {
    if cancelled() {
        return Err(RequestError::Cancelled);
    }
    let found = gcp.grants(place.account, place.name).map_err(RequestError::Api)?;
    let now = SystemTime::now();
    let waiting = if approver { pending(&found).into_iter().next().cloned() } else { None };
    let mut grant = match in_flight(&found).into_iter().max_by_key(|grant| granted_at(grant, now).unwrap_or(UNIX_EPOCH)) {
        Some(existing) => existing.clone(),
        None if waiting.is_some() => return Ok(waiting.expect("checked")),
        None => {
            let created = gcp.create_grant(place.account, place.name, duration_secs, justification).map_err(RequestError::Api)?;
            remember();
            created
        }
    };
    let deadline = Instant::now() + wait;
    loop {
        if cancelled() {
            return Err(RequestError::Cancelled);
        }
        if grant.state == "ACTIVE" || approver && grant.state == "APPROVAL_AWAITED" {
            return Ok(grant);
        }
        if grant.is_final() {
            return Err(RequestError::NotActive { state: grant.state });
        }
        if Instant::now() >= deadline {
            return Err(RequestError::TimedOut { state: grant.state });
        }
        std::thread::sleep(poll_every);
        grant = gcp.get_grant(place.account, &grant.name).map_err(RequestError::Api)?;
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, the only shape Google's APIs write. Anything else is `None`.
pub fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-');
    let (year, month, day): (i64, u32, u32) = (date.next()?.parse().ok()?, date.next()?.parse().ok()?, date.next()?.parse().ok()?);
    if date.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (clock, fraction) = time.split_once('.').map_or((time, None), |(clock, fraction)| (clock, Some(fraction)));
    let mut clock = clock.split(':');
    let (hour, minute, second): (u64, u64, u64) = (clock.next()?.parse().ok()?, clock.next()?.parse().ok()?, clock.next()?.parse().ok()?);
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let nanos = match fraction {
        Some(digits) if !digits.is_empty() && digits.len() <= 9 && digits.bytes().all(|byte| byte.is_ascii_digit()) => {
            digits.parse::<u64>().ok()? * 10u64.pow(9 - digits.len() as u32)
        }
        Some(_) => return None,
        None => 0,
    };
    let days = days_from_civil(year, month, day);
    let seconds = days.checked_mul(86_400)?.checked_add((hour * 3600 + minute * 60 + second) as i64)?;
    let seconds = u64::try_from(seconds).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_nanos(nanos))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_index = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `parse_rfc3339` backwards, to the second, for tests that need a grant time near now (Hinnant's `civil_from_days`).
#[cfg(test)]
pub fn rfc3339(time: SystemTime) -> String {
    let seconds = time.duration_since(UNIX_EPOCH).expect("after the epoch").as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let clock = seconds.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", clock / 3600, clock % 3600 / 60, clock % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn grant(state: &str, granted: Option<&str>) -> Grant {
        Grant { name: format!("projects/acme-prod-123456/locations/global/entitlements/prod-operate/grants/{state}"), state: state.into(), requested_duration: Some("1800s".into()), access_grant_time: granted.map(str::to_string), justification: None }
    }

    #[test]
    fn entitlement_names_are_read_back_into_their_parts_on_any_parent() {
        let name = EntitlementName::in_project("acme-prod-123456", "global", "prod-operate");
        assert_eq!(name.full(), "projects/acme-prod-123456/locations/global/entitlements/prod-operate");
        assert_eq!(EntitlementName::parse(&name.full()), Some(name.clone()));
        assert_eq!(name.scope(), "projects/acme-prod-123456/locations/global");
        for good in [
            "folders/123456789012/locations/global/entitlements/break-glass",
            "organizations/987654321098/locations/asia-east1/entitlements/org-admin",
            "projects/example.com:acme-dev-654321/locations/global/entitlements/dev",
        ] {
            assert_eq!(EntitlementName::parse(good).map(|name| name.full()).as_deref(), Some(good));
        }
        for bad in [
            "projects/acme/locations/global/entitlements/x",
            "folders/abc/locations/global/entitlements/x",
            "projects/acme-dev-654321/locations/Global/entitlements/x",
            "projects/acme-dev-654321/locations/global/entitlements/",
            "projects/acme-dev-654321/locations/global",
            "billingAccounts/1/locations/global/entitlements/x",
        ] {
            assert_eq!(EntitlementName::parse(bad), None, "{bad}");
        }
        assert!(is_parent("projects/123456789") && !is_parent("projects/") && !is_parent("folders/"));
    }

    #[test]
    fn a_grant_waiting_for_an_approver_is_pending_and_never_in_flight() {
        let grants: Vec<Grant> = ["APPROVAL_AWAITED", "ACTIVE", "DENIED"].iter().map(|state| grant(state, None)).collect();
        assert_eq!(pending(&grants).iter().map(|grant| grant.state.as_str()).collect::<Vec<_>>(), ["APPROVAL_AWAITED"]);
        assert_eq!(in_flight(&grants).iter().map(|grant| grant.state.as_str()).collect::<Vec<_>>(), ["ACTIVE"]);
    }

    #[test]
    fn grants_in_flight_are_active_activating_or_scheduled() {
        let grants: Vec<Grant> = ["ENDED", "ACTIVE", "SCHEDULED", "ACTIVATING", "DENIED", "REVOKED", "APPROVAL_AWAITED"].iter().map(|state| grant(state, None)).collect();
        let states: Vec<&str> = in_flight(&grants).iter().map(|grant| grant.state.as_str()).collect();
        assert_eq!(states, vec!["ACTIVE", "SCHEDULED", "ACTIVATING"]);
    }

    #[test]
    fn grants_are_parsed_from_the_search_response() {
        let json = json!({
            "grants": [
                { "name": "projects/acme-prod-123456/locations/global/entitlements/prod-operate/grants/1", "state": "ENDED", "requestedDuration": "1800s" },
                { "name": "projects/acme-prod-123456/locations/global/entitlements/prod-operate/grants/2", "state": "ACTIVE", "requestedDuration": "3600s",
                  "auditTrail": { "accessGrantTime": "2026-10-25T10:00:00.123456Z" }, "requester": "frank@example.com" }
            ]
        });
        let grants = parse_grants(&json);
        assert_eq!(grants.len(), 2);
        assert_eq!((grants[1].state.as_str(), grants[1].requested_duration.as_deref(), grants[1].access_grant_time.as_deref()), ("ACTIVE", Some("3600s"), Some("2026-10-25T10:00:00.123456Z")));
        assert_eq!(grants[0].access_grant_time, None);
        assert!(parse_grants(&json!({})).is_empty());
    }

    #[test]
    fn a_grant_active_for_under_two_minutes_is_recent() {
        // 1 800 000 000 seconds after the epoch is 2027-01-15T08:00:00Z.
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let window = Duration::from_secs(120);
        assert!(granted_within(&grant("ACTIVE", Some("2027-01-15T07:59:00Z")), now, window));
        assert!(granted_within(&grant("ACTIVE", Some("2027-01-15T07:59:30.5Z")), now, window));
        assert!(!granted_within(&grant("ACTIVE", Some("2027-01-15T07:50:00Z")), now, window));
        // A grant time ahead of this clock is a grant just given by a clock that runs ahead: recent.
        assert!(granted_within(&grant("ACTIVE", Some("2027-01-15T08:00:30Z")), now, window));
        assert!(!granted_within(&grant("ACTIVE", None), now, window));
        assert!(!granted_within(&grant("ACTIVE", Some("yesterday")), now, window));
        // Access ends when the requested duration has passed since it was given; a grant not yet given has no end.
        assert_eq!(grant("ACTIVE", Some("2027-01-15T08:00:00Z")).until(), Some(now + Duration::from_secs(1800)));
        assert_eq!(grant("ACTIVATING", None).until(), None);
        assert!(grant("ENDED", None).is_final() && grant("APPROVAL_AWAITED", None).is_final() && !grant("ACTIVATING", None).is_final());
        assert_eq!(duration_text(1800), "1800s");
        assert_eq!(parse_rfc3339("2027-01-15T08:00:00Z"), Some(now));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(UNIX_EPOCH));
        assert_eq!(parse_rfc3339("2027-13-01T00:00:00Z"), None);
        // The test formatter is the parser backwards, to the second.
        assert_eq!(rfc3339(now), "2027-01-15T08:00:00Z");
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29T00:00:00Z");
        let whole_second = UNIX_EPOCH + Duration::from_secs(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        assert_eq!(parse_rfc3339(&rfc3339(whole_second)), Some(whole_second));
    }
}
