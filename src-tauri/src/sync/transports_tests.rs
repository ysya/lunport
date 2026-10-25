use super::*;
use crate::sync::records_v3::{decode_state, validate_state, DecodedState, SyncStateV3, CENTRAL_STATE_VERSION};
use serde_json::json;
use std::collections::BTreeMap;

const A: &str = "0000000000000001";
const B: &str = "0000000000000002";
const C: &str = "0000000000000003";

fn state() -> SyncStateV3 {
    serde_json::from_value(json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap()
}

fn iap(host: &str) -> HostTransport {
    HostTransport {
        host_id: host.into(),
        kind: TransportKind::GcpIap {
            project: "eng-dev-396409".into(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic0".into(),
            account: Some("frank@retower.io".into()),
            os_login: true,
            pam: None,
        },
    }
}

fn with_zone(mut transport: HostTransport, new_zone: &str) -> HostTransport {
    let TransportKind::GcpIap { zone, .. } = &mut transport.kind;
    *zone = new_zone.into();
    transport
}

#[test]
fn a_saved_transport_is_read_back_by_host_and_raises_the_state_version() {
    let base = state();
    assert_eq!(get(&base, A), None);
    assert!(!has_data(&base));
    let next = set(&base, A, None, Some(iap(A)), 10).unwrap();
    assert_eq!(next.version, STATE_VERSION);
    assert_eq!(STATE_VERSION, 9);
    assert_eq!(get(&next, A), Some(iap(A)));
    assert_eq!(get(&next, B), None);
    assert_eq!(view(&next), vec![iap(A)]);
    assert!(has_data(&next));
    assert_eq!(next.local.hosts, base.local.hosts, "hosts are untouched");
    let text = serde_json::to_string(&next).unwrap();
    let DecodedState::V3(restored) = decode_state(&text).unwrap() else { panic!("the state decodes") };
    assert_eq!(get(&restored, A), Some(iap(A)));
    assert!(text.contains("\"transport:0000000000000001\""), "{text}");
}

#[test]
fn saving_requires_the_displayed_value() {
    let one = set(&state(), A, None, Some(iap(A)), 1).unwrap();
    assert!(set(&one, A, None, Some(iap(A)), 2).is_err(), "somebody saved first");
    let changed = with_zone(iap(A), "asia-east1-c");
    assert!(set(&one, A, Some(&changed), Some(iap(A)), 2).is_err(), "the displayed value is stale");
    let two = set(&one, A, Some(&iap(A)), Some(changed.clone()), 2).unwrap();
    assert_eq!(get(&two, A), Some(changed));
    assert!(set(&two, A, Some(&iap(A)), Some(iap(B)), 3).is_err(), "a transport names its own host");
}

#[test]
fn deleting_leaves_a_tombstone_and_no_view() {
    let one = set(&state(), A, None, Some(iap(A)), 1).unwrap();
    let gone = set(&one, A, Some(&iap(A)), None, 2).unwrap();
    assert_eq!(get(&gone, A), None);
    assert!(view(&gone).is_empty());
    let row = gone.local.transports.values().next().expect("the tombstone stays");
    assert!(row.record.deleted && row.record.payload.is_null());
    assert!(has_data(&gone), "a tombstone still needs the state version");
    validate_state(&gone).unwrap();
    assert!(set(&gone, A, Some(&iap(A)), None, 3).is_err(), "what is gone cannot be the displayed value");
    let again = set(&gone, A, None, Some(iap(A)), 4).unwrap();
    assert_eq!(get(&again, A), Some(iap(A)));
    assert!(again.local.transports.values().next().unwrap().record.version > row.record.version, "the record's version keeps growing");
}

#[test]
fn an_empty_map_leaves_the_version_alone_and_a_populated_one_needs_version_9() {
    let base = state();
    validate_state(&base).unwrap();
    assert_eq!(base.version, 4);
    let mut populated = set(&base, A, None, Some(iap(A)), 1).unwrap();
    validate_state(&populated).unwrap();
    populated.version = CENTRAL_STATE_VERSION;
    assert!(validate_state(&populated).is_err(), "a transport needs state version 9");
    assert!(decode_state(&serde_json::to_string(&populated).unwrap()).is_err());
}

#[test]
fn validation_rejects_bad_fields() {
    /// The validation sentence after `mutate` has changed the IAP fields of a good transport.
    fn edit(mutate: impl Fn(&mut String, &mut String, &mut String, &mut String, &mut Option<String>, &mut Option<PamCheck>)) -> Option<String> {
        let mut transport = iap(A);
        let TransportKind::GcpIap { project, zone, instance, interface, account, pam, .. } = &mut transport.kind;
        mutate(project, zone, instance, interface, account, pam);
        transport.validate().err()
    }
    fn pam(entitlements: &[&str], location: &str) -> Option<PamCheck> {
        Some(PamCheck { entitlements: entitlements.iter().map(|e| e.to_string()).collect(), location: location.into(), duration_secs: 1800, justification: None })
    }
    assert_eq!(iap(A).validate(), Ok(()));
    let mut other_host = iap(A);
    other_host.host_id = "nope".into();
    assert_eq!(other_host.validate(), Err("Invalid host identity.".to_string()));
    assert_eq!(edit(|p, _, _, _, _, _| *p = "Eng".into()), Some("Enter the Google Cloud project id.".to_string()));
    assert_eq!(edit(|p, _, _, _, _, _| *p = "123".into()), Some("Enter the Google Cloud project id.".to_string()));
    assert_eq!(edit(|p, _, _, _, _, _| *p = "834470760514".into()), None, "a project number is fine");
    assert_eq!(edit(|_, z, _, _, _, _| *z = "asia east1".into()), Some("Enter the zone of the instance.".to_string()));
    assert_eq!(edit(|_, _, i, _, _, _| *i = String::new()), Some("Enter the instance name.".to_string()));
    assert_eq!(edit(|_, _, _, n, _, _| *n = "eth0".into()), Some("Enter a network interface such as nic0.".to_string()));
    assert_eq!(edit(|_, _, _, n, _, _| *n = "nic7".into()), None);
    assert_eq!(edit(|_, _, _, _, a, _| *a = Some("frank".into())), Some("Enter the Google account as an email address.".to_string()));
    // The account names a directory under gcloud's config (`legacy_credentials/<account>/adc.json`): no path characters.
    for traversal in ["../../tmp/x@example.com", "/etc/x@example.com", "a\\b@example.com", "a:b@example.com", "a@b/c.example.com"] {
        assert_eq!(edit(|_, _, _, _, a, _| *a = Some(traversal.into())), Some("Enter the Google account as an email address.".to_string()), "{traversal}");
    }
    assert!(is_email("first.last+tag@sub.example.com") && is_email("o'brien_1@example.io") && !is_email("a@b"));
    assert_eq!(edit(|_, _, _, _, a, _| *a = None), None);
    assert_eq!(edit(|_, _, _, _, _, p| *p = pam(&[], "global")), Some("Enter at least one PAM entitlement.".to_string()));
    assert_eq!(edit(|_, _, _, _, _, p| *p = pam(&["prod-operate", "prod-admin"], "global")), None);
    assert_eq!(edit(|_, _, _, _, _, p| *p = pam(&["Prod"], "global")), Some("Enter PAM entitlement ids such as prod-operate.".to_string()));
    assert_eq!(edit(|_, _, _, _, _, p| *p = pam(&["prod-operate"], "Global")), Some("Enter the PAM location, such as global.".to_string()));
    assert_eq!(edit(|_, _, _, _, _, p| *p = pam(&["a", "b", "c", "d", "e", "f", "g", "h", "i"], "global")), Some("Enter at most 8 PAM entitlements.".to_string()));
}

/// A transport with the PAM check of the design's example, for the grant-request tests.
fn with_pam(host: &str) -> HostTransport {
    let mut transport = iap(host);
    let TransportKind::GcpIap { pam, .. } = &mut transport.kind;
    *pam = Some(PamCheck { entitlements: vec!["prod-operate".into()], location: "global".into(), duration_secs: 1800, justification: None });
    transport
}

/// Design 2026-10-25 (PAM grant requests): the transport remembers the duration and the last justification, with defaults an older
/// record (without the fields) decodes to, and rules a request cannot break.
#[test]
fn pam_defaults_decode_for_an_older_record_and_validate() {
    let one = set(&state(), A, None, Some(with_pam(A)), 1).unwrap();
    let mut older = one.local.transports.values().next().unwrap().record.clone();
    let pam = older.payload["transport"]["kind"]["pam"].as_object_mut().unwrap();
    pam.remove("duration_secs");
    pam.remove("justification");
    let TransportKind::GcpIap { pam: Some(decoded), .. } = decode(&older).expect("an older record has defaults").kind else { panic!("a PAM check") };
    assert_eq!((decoded.duration_secs, decoded.justification), (1800, None));
    let problem = |duration_secs: u32, justification: Option<&str>| {
        let mut transport = with_pam(A);
        let TransportKind::GcpIap { pam: Some(pam), .. } = &mut transport.kind else { unreachable!() };
        pam.duration_secs = duration_secs;
        pam.justification = justification.map(str::to_string);
        transport.validate().err()
    };
    let minutes = Some("Enter a grant duration between 1 and 480 minutes.".to_string());
    assert_eq!(problem(30, None), minutes);
    assert_eq!(problem(28_860, None), minutes);
    assert_eq!(problem(90, None), minutes, "whole minutes only");
    assert_eq!(problem(60, None), None);
    assert_eq!(problem(28_800, None), None);
    let line = Some("Keep the justification under 512 characters on one line.".to_string());
    assert_eq!(problem(1800, Some(&"x".repeat(513))), line);
    assert_eq!(problem(1800, Some("restart\napp-api")), line);
    assert_eq!(problem(1800, Some("restart app-api")), None);
}

#[test]
fn remember_grant_request_keeps_everything_else_and_needs_a_pam_check() {
    let saved = set(&state(), A, None, Some(with_pam(A)), 1).unwrap();
    let next = remember_grant_request(&saved, A, "restart app-api", 3600, 2).unwrap();
    let rows = view(&next);
    assert_eq!(rows.len(), 1);
    let TransportKind::GcpIap { pam: Some(pam), project, .. } = &rows[0].kind else { panic!("a PAM check") };
    assert_eq!((pam.justification.as_deref(), pam.duration_secs, pam.entitlements.as_slice()), (Some("restart app-api"), 3600, &["prod-operate".to_string()][..]));
    assert_eq!(project, "eng-dev-396409");
    assert_eq!(next.version, STATE_VERSION);
    assert_eq!(get(&next, A).as_ref(), rows.first(), "the remembered record is what compare-and-set sees");
    assert!(remember_grant_request(&next, A, "x", 30, 3).is_err(), "the rules apply to what is remembered too");
    assert!(remember_grant_request(&set(&state(), A, None, Some(iap(A)), 1).unwrap(), A, "x", 1800, 2).is_err(), "no PAM check to remember for");
    assert!(remember_grant_request(&state(), A, "x", 1800, 2).is_err(), "no transport");
}

#[test]
fn a_payload_with_an_unknown_field_or_schema_is_not_decoded() {
    let one = set(&state(), A, None, Some(iap(A)), 1).unwrap();
    let record = one.local.transports.values().next().unwrap().record.clone();
    assert_eq!(decode(&record), Some(iap(A)));
    assert!(valid(&record));
    assert_eq!(record.payload["transport"]["kind"]["type"], json!("gcp_iap"));
    let mut newer = record.clone();
    newer.payload["schema"] = json!(2);
    assert_eq!(decode(&newer), None);
    let mut extra = record.clone();
    extra.payload["transport"]["kind"]["surprise"] = json!(true);
    assert_eq!(decode(&extra), None);
    let mut other_host = record.clone();
    other_host.payload["transport"]["host_id"] = json!(B);
    assert_eq!(decode(&other_host), None, "the record id and the payload must name the same host");
    assert!(!valid(&other_host));
    let mut defaults = record.clone();
    let kind = defaults.payload["transport"]["kind"].as_object_mut().unwrap();
    kind.remove("interface");
    kind.remove("account");
    kind.remove("os_login");
    kind.remove("pam");
    let decoded = decode(&defaults).expect("optional fields have defaults");
    let TransportKind::GcpIap { interface, account, os_login, pam, .. } = decoded.kind;
    assert_eq!((interface.as_str(), account, os_login, pam), ("nic0", None, false, None));
}

/// A host record in `state.local.hosts`, as the leave plan writes the hosts that stay on this device.
fn with_local_host(mut state: SyncStateV3, id: &str) -> SyncStateV3 {
    let record = Record {
        kind: RecordKind::Host,
        id: id.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: state.device_id.clone(),
        deleted: false,
        payload: json!({"schema":2,"alias":format!("host-{id}"),"hostname":"fixture.invalid","auth":"password"}),
    };
    state.local.hosts.insert(record_key(RecordKind::Host, id), LocalRecord { record, seq: 0, dirty: false });
    state
}

/// Transports are device-local whatever the host's scope: leaving an account keeps the transport of every host that stays on this
/// device, under the host's new id when the leave plan gave it one (a space host), and drops the transports of hosts that go.
#[test]
fn leaving_an_account_keeps_the_transports_of_the_hosts_that_stay_and_drops_the_rest() {
    const LOCAL: &str = "0000000000000004";
    let before = set(&set(&set(&state(), A, None, Some(iap(A)), 1).unwrap(), B, None, Some(iap(B)), 2).unwrap(), LOCAL, None, Some(iap(LOCAL)), 3).unwrap();
    // A (a space host) stays as C; LOCAL (a local-scope host) stays as itself; B goes.
    let mut next = with_local_host(with_local_host(state(), C), LOCAL);
    let host_ids: BTreeMap<String, String> = [(A.to_string(), C.to_string())].into_iter().collect();
    preserve_on_leave(&before, &mut next, &host_ids, 4).unwrap();
    assert_eq!(view(&next), vec![HostTransport { host_id: C.into(), ..iap(A) }, iap(LOCAL)]);
    assert_eq!(next.version, STATE_VERSION);
    let mut nothing = state();
    preserve_on_leave(&before, &mut nothing, &BTreeMap::new(), 4).unwrap();
    assert!(view(&nothing).is_empty(), "no host stays, no transport stays");
    assert_eq!(nothing.version, 4, "no transport, no version bump");
}
