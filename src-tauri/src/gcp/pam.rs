//! Privileged Access Manager grants (`privilegedaccessmanager.googleapis.com` v1): the caller's own grants on one entitlement, and which of
//! them are in flight. The REST call lives in `gcp::rest`; the broker checks for a grant before it opens a tunnel to a production host,
//! so the person reads "no grant" instead of IAP's bare 4033.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
}

/// The grants of a `grants:search` answer; an answer without any is empty.
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
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The grants that give access now or are about to: `ACTIVE`, `ACTIVATING`, `SCHEDULED`.
pub fn in_flight(grants: &[Grant]) -> Vec<&Grant> {
    grants.iter().filter(|grant| matches!(grant.state.as_str(), "ACTIVE" | "ACTIVATING" | "SCHEDULED")).collect()
}

/// Whether the grant's access was given within `window` before `now` (IAP can take a while to honour a fresh grant).
pub fn granted_within(grant: &Grant, now: SystemTime, window: Duration) -> bool {
    grant
        .access_grant_time
        .as_deref()
        .and_then(parse_rfc3339)
        .is_some_and(|granted| now.duration_since(granted).is_ok_and(|age| age <= window))
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
    let year_of_era = (year - era * 400) as i64;
    let month_index = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn grant(state: &str, granted: Option<&str>) -> Grant {
        Grant { name: format!("projects/knowknow-prod/locations/global/entitlements/prod-operate/grants/{state}"), state: state.into(), requested_duration: Some("1800s".into()), access_grant_time: granted.map(str::to_string) }
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
                { "name": "projects/knowknow-prod/locations/global/entitlements/prod-operate/grants/1", "state": "ENDED", "requestedDuration": "1800s" },
                { "name": "projects/knowknow-prod/locations/global/entitlements/prod-operate/grants/2", "state": "ACTIVE", "requestedDuration": "3600s",
                  "auditTrail": { "accessGrantTime": "2026-10-25T10:00:00.123456Z" }, "requester": "frank@retower.io" }
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
        assert!(!granted_within(&grant("ACTIVE", None), now, window));
        assert!(!granted_within(&grant("ACTIVE", Some("yesterday")), now, window));
        assert_eq!(parse_rfc3339("2027-01-15T08:00:00Z"), Some(now));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(UNIX_EPOCH));
        assert_eq!(parse_rfc3339("2027-13-01T00:00:00Z"), None);
        let _ = SystemTime::now();
    }
}
