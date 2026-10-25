//! Device-local transports: how this device reaches a saved host when not over plain TCP (design 2026-10-25, Google Cloud IAP). One
//! `Meta` record per host, `transport:<host-id>`, in the envelope tunnel rules use, so a later step can publish them; until then they live
//! in `local.transports` only, so `set` consults neither the account nor opaque shadows, and an account join leaves them alone. Saving
//! the first one raises the local state version to `STATE_VERSION`, which an older Lunport refuses to open.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::record::{record_key, LocalRecord, Record, RecordKind};
use super::record_repository::{self as repo, RepositoryError};
use super::records_v3::{self, SyncStateV3};

pub const PREFIX: &str = "transport:";
pub const STATE_VERSION: u32 = records_v3::TRANSPORT_STATE_VERSION;
const MAX_ENTITLEMENTS: usize = 8;

/// A host's transport: which host, and how this device reaches it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostTransport {
    pub host_id: String,
    pub kind: TransportKind,
}

/// The ways a host can be reached other than TCP. One variant so far.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/", tag = "type", rename_all = "snake_case"))]
pub enum TransportKind {
    /// A Google Cloud IAP TCP-forwarding tunnel to a GCE instance.
    GcpIap {
        project: String,
        zone: String,
        instance: String,
        #[serde(default = "default_interface")]
        interface: String,
        /// The Google account whose gcloud credentials are used; `None` for gcloud's active account.
        #[serde(default)]
        account: Option<String>,
        /// Register the host's key with OS Login when needed and check the username before connecting.
        #[serde(default)]
        os_login: bool,
        /// Require an in-flight Privileged Access Manager grant before connecting.
        #[serde(default)]
        pam: Option<PamCheck>,
    },
}

/// Which PAM entitlements may carry the grant, and where they live.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamCheck {
    pub entitlements: Vec<String>,
    #[serde(default = "default_location")]
    pub location: String,
    /// How long a grant requested from Lunport asks for: seconds, whole minutes, 1–480 minutes; 30 minutes at first (design 2026-10-25,
    /// PAM grant requests).
    #[serde(default = "default_duration")]
    pub duration_secs: u32,
    /// The justification last sent with a request, offered again next time.
    #[serde(default)]
    pub justification: Option<String>,
}

fn default_interface() -> String {
    "nic0".to_string()
}

fn default_location() -> String {
    "global".to_string()
}

fn default_duration() -> u32 {
    30 * 60
}

/// The longest grant Lunport asks for; PAM's own maximum (the entitlement's) applies on top, in PAM's words.
const MAX_DURATION_SECS: u32 = 480 * 60;
const MAX_JUSTIFICATION_CHARS: usize = 512;

impl HostTransport {
    /// One sentence about the first field that is not acceptable, else `Ok`.
    pub fn validate(&self) -> Result<(), String> {
        if !records_v3::is_host_id(&self.host_id) {
            return Err("Invalid host identity.".into());
        }
        let TransportKind::GcpIap { project, zone, instance, interface, account, pam, .. } = &self.kind;
        if !is_project(project) {
            return Err("Enter the Google Cloud project id.".into());
        }
        if !is_resource_name(zone) {
            return Err("Enter the zone of the instance.".into());
        }
        if !is_resource_name(instance) {
            return Err("Enter the instance name.".into());
        }
        if !is_interface(interface) {
            return Err("Enter a network interface such as nic0.".into());
        }
        if account.as_deref().is_some_and(|account| !is_email(account)) {
            return Err("Enter the Google account as an email address.".into());
        }
        if let Some(pam) = pam {
            if pam.entitlements.is_empty() {
                return Err("Enter at least one PAM entitlement.".into());
            }
            if pam.entitlements.len() > MAX_ENTITLEMENTS {
                return Err(format!("Enter at most {MAX_ENTITLEMENTS} PAM entitlements."));
            }
            if !pam.entitlements.iter().all(|entitlement| is_resource_name(entitlement)) {
                return Err("Enter PAM entitlement ids such as prod-operate.".into());
            }
            if !is_resource_name(&pam.location) {
                return Err("Enter the PAM location, such as global.".into());
            }
            if pam.duration_secs < 60 || pam.duration_secs > MAX_DURATION_SECS || pam.duration_secs % 60 != 0 {
                return Err("Enter a grant duration between 1 and 480 minutes.".into());
            }
            if pam.justification.as_deref().is_some_and(|text| text.chars().count() > MAX_JUSTIFICATION_CHARS || text.chars().any(char::is_control)) {
                return Err("Keep the justification under 512 characters on one line.".into());
            }
        }
        Ok(())
    }
}

/// A project id (`eng-dev-396409`: 6–30 characters, lowercase letters, digits and dashes, starting with a letter) or a project number.
fn is_project(text: &str) -> bool {
    let number = (6..=20).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit());
    let id = (6..=30).contains(&text.len())
        && text.starts_with(|c: char| c.is_ascii_lowercase())
        && !text.ends_with('-')
        && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    number || id
}

/// A GCE-style resource name: 1–63 characters, lowercase letters, digits and dashes, starting with a letter, not ending with a dash.
fn is_resource_name(text: &str) -> bool {
    (1..=63).contains(&text.len())
        && text.starts_with(|c: char| c.is_ascii_lowercase())
        && !text.ends_with('-')
        && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `nic0` … `nic7`.
fn is_interface(text: &str) -> bool {
    text.strip_prefix("nic").is_some_and(|rest| rest.len() == 1 && rest.bytes().all(|byte| (b'0'..=b'7').contains(&byte)))
}

/// A Google account as an email address, in the characters an address and a directory name share: the account names a directory under
/// gcloud's config (`legacy_credentials/<account>/adc.json`), so no path separators, colons, whitespace or control characters. The
/// frontend's `transportProblem` applies the same rule.
pub(crate) fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else { return false };
    let local_ok = !local.is_empty() && local.chars().all(|c| c.is_ascii_alphanumeric() || "._%+'-".contains(c));
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2 && labels.iter().all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    text.len() <= 254 && local_ok && domain_ok
}

/// The record payload: `{ "schema": 1, "transport": … }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Payload {
    pub schema: u32,
    pub transport: HostTransport,
}

pub fn is_id(id: &str) -> bool {
    id.strip_prefix(PREFIX).is_some_and(records_v3::is_host_id)
}

pub fn wire_id(host_id: &str) -> String {
    format!("{PREFIX}{host_id}")
}

/// The transport a live record holds, when the record is one of ours, names the host its id names and passes validation.
pub fn decode(record: &Record) -> Option<HostTransport> {
    if record.deleted || record.kind != RecordKind::Meta || !is_id(&record.id) {
        return None;
    }
    let payload: Payload = serde_json::from_value(record.payload.clone()).ok()?;
    (payload.schema == 1 && wire_id(&payload.transport.host_id) == record.id && payload.transport.validate().is_ok()).then_some(payload.transport)
}

/// Whether a stored record is well-formed: a tombstone with no payload, or a live record that decodes.
pub fn valid(record: &Record) -> bool {
    record.kind == RecordKind::Meta
        && is_id(&record.id)
        && record.version > 0
        && super::slot_rules::is_slot_id(&record.device_id)
        && if record.deleted { record.payload.is_null() } else { decode(record).is_some() }
}

/// Every live transport on this device.
pub fn view(state: &SyncStateV3) -> Vec<HostTransport> {
    state.local.transports.values().filter_map(|row| decode(&row.record)).collect()
}

/// The transport of one host, if it has one.
pub fn get(state: &SyncStateV3, host_id: &str) -> Option<HostTransport> {
    state.local.transports.get(&record_key(RecordKind::Meta, &wire_id(host_id))).and_then(|row| decode(&row.record))
}

/// Whether the map holds anything, tombstones included: they too need the state version.
pub fn has_data(state: &SyncStateV3) -> bool {
    !state.local.transports.is_empty()
}

/// Saves (`Some`) or removes (`None`) the transport of `host_id`, provided `expected` is what is stored now: the compare-and-set the
/// editor relies on. The result is the next state; the version is raised to `STATE_VERSION`.
pub fn set(state: &SyncStateV3, host_id: &str, expected: Option<&HostTransport>, transport: Option<HostTransport>, now: u64) -> Result<SyncStateV3, RepositoryError> {
    if !records_v3::is_host_id(host_id) {
        return Err(repo::invalid("transport", host_id, "Invalid host identity."));
    }
    if get(state, host_id).as_ref() != expected {
        return Err(repo::invalid("transport", host_id, "This host's transport changed meanwhile. Refresh and try again."));
    }
    if let Some(transport) = &transport {
        transport.validate().map_err(|reason| repo::invalid("transport", host_id, &reason))?;
        if transport.host_id != host_id {
            return Err(repo::invalid("transport", host_id, "The transport names another host."));
        }
    }
    write(state, host_id, transport, now)
}

/// What a grant request taught the transport (design 2026-10-25, PAM grant requests): the duration asked for and the justification
/// given, offered again next time. Written without a compare-and-set (the panel may be showing the transport meanwhile); `validate`'s
/// rules apply to what is remembered.
pub fn remember_grant_request(state: &SyncStateV3, host_id: &str, justification: &str, duration_secs: u32, now: u64) -> Result<SyncStateV3, RepositoryError> {
    let Some(mut transport) = get(state, host_id) else { return Err(repo::invalid("transport", host_id, "This host has no transport.")) };
    let TransportKind::GcpIap { pam, .. } = &mut transport.kind;
    let Some(pam) = pam.as_mut() else { return Err(repo::invalid("transport", host_id, "This transport requires no grant.")) };
    pam.justification = Some(justification.to_string());
    pam.duration_secs = duration_secs;
    transport.validate().map_err(|reason| repo::invalid("transport", host_id, &reason))?;
    write(state, host_id, Some(transport), now)
}

fn write(state: &SyncStateV3, host_id: &str, transport: Option<HostTransport>, now: u64) -> Result<SyncStateV3, RepositoryError> {
    let wire = wire_id(host_id);
    let key = record_key(RecordKind::Meta, &wire);
    let previous = state.local.transports.get(&key);
    let payload = match &transport {
        Some(transport) => serde_json::to_value(Payload { schema: 1, transport: transport.clone() }).expect("a transport serializes"),
        None => serde_json::Value::Null,
    };
    let earlier: Vec<&Record> = previous.map(|row| &row.record).into_iter().collect();
    let mut record = repo::ordered_record(state, &wire, payload, transport.is_none(), now, &earlier)?;
    record.kind = RecordKind::Meta;
    let mut next = state.clone();
    next.local.transports.insert(key, LocalRecord { record, seq: previous.map_or(0, |row| row.seq), dirty: false });
    next.version = next.version.max(STATE_VERSION);
    Ok(next)
}

/// Transports are device-local whatever the host's scope: leaving an account keeps the transport of every host that stays on this device
/// (a live record in `next.local.hosts`), under the new local id the leave plan gave a space host (`host_ids`: old → new), and drops the
/// transports of the hosts that go. `next`'s map starts empty.
pub fn preserve_on_leave(before: &SyncStateV3, next: &mut SyncStateV3, host_ids: &BTreeMap<String, String>, now: u64) -> Result<(), RepositoryError> {
    next.local.transports.clear();
    for mut transport in view(before) {
        if let Some(local_id) = host_ids.get(&transport.host_id) {
            transport.host_id = local_id.clone();
        }
        let stays = next.local.hosts.get(&record_key(RecordKind::Host, &transport.host_id)).is_some_and(|host| !host.record.deleted);
        if !stays {
            continue;
        }
        let host_id = transport.host_id.clone();
        *next = write(next, &host_id, Some(transport), now)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "transports_tests.rs"]
mod tests;
