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

pub(crate) fn iap(host: &str) -> HostTransport {
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

pub(crate) fn with_zone(mut transport: HostTransport, new_zone: &str) -> HostTransport {
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
    // The refusal reads as the sentence itself wherever it is shown (R16), not as a wrapped validation reason.
    assert_eq!(set(&one, A, None, Some(iap(A)), 2).unwrap_err(), RepositoryError::RouteChanged, "somebody saved first");
    let changed = with_zone(iap(A), "asia-east1-c");
    assert_eq!(set(&one, A, Some(&changed), Some(iap(A)), 2).unwrap_err().to_string(), ROUTE_CHANGED, "the displayed value is stale");
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
pub(crate) fn with_pam(host: &str) -> HostTransport {
    let mut transport = iap(host);
    let TransportKind::GcpIap { pam, .. } = &mut transport.kind;
    *pam = Some(PamCheck { entitlements: vec!["prod-operate".into()], location: "global".into(), duration_secs: 1800, justification: None });
    transport
}

/// Design 2026-10-25 (PAM grant requests), as design 2026-10-26 (Grant requests) revises it: the route keeps the grant length, and the
/// last justification is no longer kept in it (the device remembers that, see `remember_grant_request_writes_device_memory_not_the_route`),
/// though a record an earlier release wrote can still carry one. A record without the fields decodes to the defaults, and the length and
/// a justification found in the route keep the rules a request cannot break.
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

/// The sentence a refused edit carries.
fn reason(error: RepositoryError) -> String {
    match error {
        RepositoryError::Validation(records_v3::RecordValidationError::Invalid { reason, .. }) => reason,
        other => panic!("not a validation sentence: {other:?}"),
    }
}

/// Design 2026-10-26 (Grant requests): what a request teaches stays on this device, beside the route, in the state's own map. The route
/// is not edited, so a request never touches what the host's route syncs.
#[test]
fn remember_grant_request_writes_device_memory_not_the_route() {
    let saved = set(&state(), A, None, Some(with_pam(A)), 1).unwrap();
    assert_eq!(grant_memory(&saved, A), None, "nothing is remembered before a request");
    let next = remember_grant_request(&saved, A, "Deploy hotfix", 45 * 60, 2).unwrap();
    assert_eq!(get(&next, A), get(&saved, A), "the route is untouched");
    assert_eq!(next.local.transports, saved.local.transports, "so is its record, down to the version it carries");
    assert_eq!(grant_memory(&next, A), Some(GrantMemory { justification: "Deploy hotfix".into(), duration_secs: 2700 }));
    assert_eq!(grant_memory(&next, B), None, "memory is per host");
    assert!(next.version >= SYNC_STATE_VERSION);
    validate_state(&next).unwrap();
}

#[test]
fn grant_memory_below_version_ten_is_refused() {
    let mut remembered = remember_grant_request(&set(&state(), A, None, Some(with_pam(A)), 1).unwrap(), A, "x", 60, 2).unwrap();
    assert_eq!((SYNC_STATE_VERSION, remembered.version), (10, 10), "a request raises the version to 10");
    remembered.version = records_v3::TRANSPORT_STATE_VERSION;
    assert!(validate_state(&remembered).is_err());
    assert!(decode_state(&serde_json::to_string(&remembered).unwrap()).is_err(), "an older Lunport's version does not open it either");
}

/// A request replaces what the host remembered before and leaves every other host's memory, and every route, alone.
#[test]
fn a_later_request_replaces_the_memory_of_its_host_only() {
    let both = set(&set(&state(), A, None, Some(with_pam(A)), 1).unwrap(), B, None, Some(with_pam(B)), 2).unwrap();
    let first = remember_grant_request(&both, A, "restart app-api", 1800, 3).unwrap();
    let other = remember_grant_request(&first, B, "rotate certs", 600, 4).unwrap();
    let second = remember_grant_request(&other, A, "Deploy hotfix", 3600, 5).unwrap();
    assert_eq!(grant_memory(&second, A), Some(GrantMemory { justification: "Deploy hotfix".into(), duration_secs: 3600 }));
    assert_eq!(grant_memory(&second, B), Some(GrantMemory { justification: "rotate certs".into(), duration_secs: 600 }));
    assert_eq!(second.local.transports, both.local.transports, "no request edits a route");
    assert_eq!(second.local.transport_grants.len(), 2);
}

/// The checks `remember_grant_request` made before are still made: a host with a route that requires a grant, and the form's rules.
#[test]
fn remember_grant_request_needs_a_route_that_requires_a_grant() {
    let without_pam = set(&state(), A, None, Some(iap(A)), 1).unwrap();
    assert_eq!(reason(remember_grant_request(&without_pam, A, "x", 1800, 2).unwrap_err()), "This transport requires no grant.");
    assert_eq!(reason(remember_grant_request(&state(), A, "x", 1800, 2).unwrap_err()), "This host has no transport.");
    let other_host = set(&state(), B, None, Some(with_pam(B)), 1).unwrap();
    assert_eq!(reason(remember_grant_request(&other_host, A, "x", 1800, 2).unwrap_err()), "This host has no transport.", "another host's route is not this host's");
    let gone = set(&set(&state(), A, None, Some(with_pam(A)), 1).unwrap(), A, Some(&with_pam(A)), None, 2).unwrap();
    assert_eq!(reason(remember_grant_request(&gone, A, "x", 1800, 3).unwrap_err()), "This host has no transport.", "a removed route is no route");
}

#[test]
fn a_remembered_request_obeys_the_request_rules() {
    let saved = set(&state(), A, None, Some(with_pam(A)), 1).unwrap();
    let problem = |justification: &str, duration_secs: u32| remember_grant_request(&saved, A, justification, duration_secs, 2).err().map(reason);
    let minutes = Some("Enter a grant duration between 1 and 480 minutes.".to_string());
    assert_eq!(problem("x", 30), minutes);
    assert_eq!(problem("x", 90), minutes, "whole minutes only");
    assert_eq!(problem("x", 28_860), minutes);
    assert_eq!(problem("x", 60), None);
    assert_eq!(problem("x", 28_800), None);
    assert_eq!(problem("", 1800), Some("Enter a justification.".to_string()));
    let line = Some("Keep the justification under 512 characters on one line.".to_string());
    assert_eq!(problem(&"x".repeat(513), 1800), line);
    assert_eq!(problem("restart\napp-api", 1800), line);
    assert_eq!(problem(&"x".repeat(512), 1800), None);
    assert_eq!(saved.local.transport_grants.len(), 0, "a refusal remembers nothing");
}

/// What the state file may hold under `local.transport_grants`, whoever wrote it: a host id, a justification and a duration of the form.
#[test]
fn validation_rejects_bad_grant_memory() {
    let remembering = |host: &str, justification: &str, duration_secs: u32| {
        let mut state = state();
        state.version = SYNC_STATE_VERSION;
        state.local.transport_grants.insert(host.into(), GrantMemory { justification: justification.into(), duration_secs });
        state
    };
    assert!(validate_state(&remembering(A, "restart app-api", 1800)).is_ok());
    for host in ["", "nope", "000000000000000G", "transport:0000000000000001", "00000000000000011"] {
        assert!(validate_state(&remembering(host, "x", 60)).is_err(), "host {host:?}");
    }
    assert!(validate_state(&remembering(A, "", 60)).is_err(), "a justification has something in it");
    assert!(validate_state(&remembering(A, &"x".repeat(512), 60)).is_ok());
    assert!(validate_state(&remembering(A, &"x".repeat(513), 60)).is_err());
    for text in ["two\nlines", "tab\there", "bell\u{7}", "carriage\rreturn"] {
        assert!(validate_state(&remembering(A, text, 60)).is_err(), "justification {text:?}");
    }
    for duration in [0, 30, 59, 90, 1801, 28_801, 28_860, u32::MAX] {
        assert!(validate_state(&remembering(A, "x", duration)).is_err(), "duration {duration}");
    }
    for duration in [60, 1800, 28_800] {
        assert!(validate_state(&remembering(A, "x", duration)).is_ok(), "duration {duration}");
    }
}

/// Version 10 is what holds grant memory and what a library's synced route rows need (those arrive with a later step); a device-local
/// route alone stays at version 9, so a state that never asked for a grant keeps opening in the releases that know version 9.
#[test]
fn only_grant_memory_and_synced_route_rows_need_version_ten() {
    use crate::sync::state_v2::AccountState;
    assert!(!needs_sync_version(&state()));
    let local = set(&state(), A, None, Some(with_pam(A)), 1).unwrap();
    assert!(has_data(&local) && !needs_sync_version(&local), "a device-local route needs version 9 only");
    assert!(needs_sync_version(&remember_grant_request(&local, A, "x", 60, 2).unwrap()));
    let route_row = local.local.transports.values().next().unwrap().clone();
    let with_account_row = |row: LocalRecord| {
        let mut synced = state();
        let mut account = AccountState::new(&"a".repeat(64));
        account.records.insert(record_key(row.record.kind, &row.record.id), row);
        synced.account = Some(account);
        synced
    };
    assert!(needs_sync_version(&with_account_row(route_row.clone())), "a route synced with the library");
    let mut tunnel = route_row;
    tunnel.record.id = format!("tunnel:{A}");
    assert!(!needs_sync_version(&with_account_row(tunnel)), "another kind of library row does not");
}

#[test]
fn the_state_file_holds_grant_memory_only_once_there_is_some() {
    let value = serde_json::to_value(state()).unwrap();
    assert!(value["local"].get("transport_grants").is_none(), "{value}");
    let remembered = remember_grant_request(&set(&state(), A, None, Some(with_pam(A)), 1).unwrap(), A, "restart app-api", 1800, 2).unwrap();
    let text = serde_json::to_string(&remembered).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["local"]["transport_grants"], json!({ A: { "justification": "restart app-api", "duration_secs": 1800 } }));
    let DecodedState::V3(restored) = decode_state(&text).unwrap() else { panic!("the state decodes") };
    assert_eq!(*restored, remembered);
    let mut extra = value;
    extra["local"]["transport_grants"][A]["surprise"] = json!(true);
    assert!(decode_state(&extra.to_string()).is_err(), "an unknown field is not read past");
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

// ---- Routes in a library that uses central sync (design 2026-10-26, Inside Lunport, routes take tunnel rules' central path) ----

const HOST: &str = A;
const OTHER: &str = B;

/// `state` in a library that uses central sync: its central owner has cut over, and its account keeps the library's rows.
pub(crate) fn in_central_mode(mut state: SyncStateV3) -> SyncStateV3 {
    let mut central = crate::sync::central::workspace::tests::enrolled();
    central.control.cutover = true;
    state.version = state.version.max(CENTRAL_STATE_VERSION);
    state.local.central = Some(central);
    state.account = Some(crate::sync::state_v2::AccountState::new(&"a".repeat(64)));
    state
}

/// A library that uses central sync, holding `host`.
pub(crate) fn central_with_host(host: &str) -> SyncStateV3 {
    in_central_mode(with_local_host(state(), host))
}

/// A library on the older chain-mode sync, holding `host`: an account, no central sync.
fn chain_account_with_host(host: &str) -> SyncStateV3 {
    let mut state = with_local_host(state(), host);
    state.account = Some(crate::sync::state_v2::AccountState::new(&"a".repeat(64)));
    state
}

/// `state` with library tunnels, names at their longest, added until the Catalog it publishes no longer fits in one record.
pub(crate) fn filled_past_the_limit_with_tunnels(mut state: SyncStateV3) -> SyncStateV3 {
    use crate::sync::central::payload::{catalog_fits, Catalog};
    for n in 0..256 {
        let rule: crate::sync::tunnel_rules::TunnelRule = serde_json::from_value(json!({"id":format!("{:016x}", 0x1000 + n),"name":"t".repeat(128),"host_id":HOST,
            "forward":{"kind":"local","bind_address":"127.0.0.1","port":15432,"target_host":"db.internal","target_port":5432}})).unwrap();
        let id = crate::sync::tunnel_rules::wire_id(&rule.id);
        let record = Record { kind: RecordKind::Meta, id: id.clone(), version: 1, updated_at_ms: 1, device_id: state.device_id.clone(), deleted: false, payload: json!({"schema":1,"rule":rule}) };
        state.account.as_mut().unwrap().records.insert(record_key(RecordKind::Meta, &id), LocalRecord { record, seq: 0, dirty: false });
        if !catalog_fits(&crate::sync::central::catalog_of(&state, &Catalog::default(), false).unwrap()) {
            return state;
        }
    }
    panic!("256 tunnels still fit in one record");
}

/// `state` with `route` saved on this device alone, as Lunport saved it before its library used central sync, whatever the library
/// uses now.
pub(crate) fn saved_on_this_device(state: &SyncStateV3, route: &HostTransport) -> SyncStateV3 {
    write(state, &route.host_id, Some(route.clone()), 1).unwrap()
}

/// `state` with the library's writes blocked, as while an account operation is pending.
fn blocked(mut state: SyncStateV3) -> SyncStateV3 {
    state.shared_writes_blocked = true;
    state
}

#[test]
fn in_central_mode_a_route_is_a_dirty_account_row_and_reads_back_from_there() {
    let state = central_with_host(HOST);
    let next = set(&state, HOST, None, Some(iap(HOST)), 1).unwrap();
    assert!(next.local.transports.is_empty());
    let row = &next.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, &wire_id(HOST))];
    assert!(row.dirty);
    assert_eq!(get(&next, HOST), Some(iap(HOST)));
    assert!(synced(&next, HOST));
    assert_eq!(view(&next), vec![iap(HOST)]);
    assert_eq!(next.version, SYNC_STATE_VERSION, "a route of the library needs version 10");
    validate_state(&next).unwrap();
}

#[test]
fn a_chain_mode_account_keeps_routes_on_this_device() {
    let next = set(&chain_account_with_host(HOST), HOST, None, Some(iap(HOST)), 1).unwrap();
    assert!(next.local.transports.contains_key(&record_key(RecordKind::Meta, &wire_id(HOST))));
    assert!(!synced(&next, HOST));
    assert!(next.account.as_ref().unwrap().records.is_empty(), "the chain-mode account is left alone");
    assert_eq!(next.version, STATE_VERSION);
}

#[test]
fn a_full_catalog_refuses_one_more_route_but_always_allows_removal() {
    let state = set(&central_with_host(HOST), HOST, None, Some(iap(HOST)), 1).unwrap();
    let full = filled_past_the_limit_with_tunnels(central_with_host(OTHER));
    assert_eq!(set(&full, OTHER, None, Some(iap(OTHER)), 2).unwrap_err().to_string(), NO_ROOM);
    let crowded = filled_past_the_limit_with_tunnels(state);
    assert!(set(&crowded, HOST, Some(&iap(HOST)), None, 3).is_ok(), "removal never fails the check");
}

#[test]
fn a_blocked_library_refuses_route_edits() {
    let state = blocked(central_with_host(HOST));
    assert!(matches!(set(&state, HOST, None, Some(iap(HOST)), 1), Err(RepositoryError::ReadOnlyAccount)));
    assert!(set(&blocked(chain_account_with_host(HOST)), HOST, None, Some(iap(HOST)), 1).is_ok(), "a route on this device obeys no library's block");
}

/// Design 2026-10-26 (Tests): version 10 is what a library's route rows need, as grant memory does, so a state holding one, tombstones
/// included, below it is refused; and the state file's route rows are validated as its tunnel rows are.
#[test]
fn a_library_route_row_below_version_ten_or_failing_its_rules_is_refused() {
    let synced = set(&central_with_host(HOST), HOST, None, Some(iap(HOST)), 1).unwrap();
    assert_eq!(synced.version, SYNC_STATE_VERSION);
    validate_state(&synced).unwrap();
    let mut older = synced.clone();
    older.version = records_v3::TRANSPORT_STATE_VERSION;
    assert!(validate_state(&older).is_err());
    assert!(decode_state(&serde_json::to_string(&older).unwrap()).is_err(), "an older Lunport's version does not open it either");
    let mut removed = set(&synced, HOST, Some(&iap(HOST)), None, 2).unwrap();
    validate_state(&removed).unwrap();
    removed.version = records_v3::TRANSPORT_STATE_VERSION;
    assert!(validate_state(&removed).is_err(), "a tombstone needs version 10 too");
    let mut other_host = synced;
    let row = other_host.account.as_mut().unwrap().records.get_mut(&record_key(RecordKind::Meta, &wire_id(HOST))).unwrap();
    row.record.payload["transport"]["host_id"] = json!(OTHER);
    assert!(validate_state(&other_host).is_err(), "a row whose payload names another host than its id");
}

/// R7: a library holds at most `MAX_ROUTES` routes. One more is refused with the room sentence rather than the Catalog's own refusal,
/// and a library holding that many still takes an edit.
#[test]
fn a_library_holding_the_most_routes_refuses_another_but_takes_an_edit() {
    let hosts: Vec<String> = (0..MAX_ROUTES).map(|n| format!("{:016x}", 0x1000 + n)).collect();
    let full = hosts.iter().fold(central_with_host(HOST), |state, host| set(&state, host, None, Some(iap(host)), 1).unwrap());
    assert_eq!(view(&full).len(), MAX_ROUTES);
    assert_eq!(set(&full, HOST, None, Some(iap(HOST)), 2).unwrap_err().to_string(), NO_ROOM);
    let first = hosts[0].as_str();
    assert!(set(&full, first, Some(&iap(first)), Some(with_zone(iap(first), "asia-east1-c")), 2).is_ok());
}

/// R7: a Catalog that cannot be built refuses the save with its own sentence.
#[test]
fn a_library_whose_catalog_cannot_be_built_refuses_a_route_with_that_reason() {
    let mut state = central_with_host(HOST);
    // A collection row for a collection this device does not hold.
    let id = "b".repeat(64);
    let record = Record { kind: RecordKind::Space, id: id.clone(), version: 1, updated_at_ms: 1, device_id: state.device_id.clone(), deleted: false, payload: json!({"schema":1,"name":"Work"}) };
    state.account.as_mut().unwrap().records.insert(record_key(RecordKind::Space, &id), LocalRecord { record, seq: 0, dirty: false });
    assert_eq!(reason(set(&state, HOST, None, Some(iap(HOST)), 1).unwrap_err()), "Invalid central sync protocol data.");
}

/// A route saved on this device before its library moved to central sync is read until the library holds one. A save or a removal
/// writes the library's row and drops this device's copy, which could otherwise come back once the library's row is a tombstone.
#[test]
fn a_route_saved_on_this_device_gives_way_to_the_librarys_row() {
    let state = in_central_mode(set(&with_local_host(state(), HOST), HOST, None, Some(iap(HOST)), 1).unwrap());
    assert_eq!(get(&state, HOST), Some(iap(HOST)));
    assert!(!synced(&state, HOST), "saved on this computer only, until the library holds it");
    let changed = with_zone(iap(HOST), "asia-east1-c");
    let saved = set(&state, HOST, Some(&iap(HOST)), Some(changed.clone()), 2).unwrap();
    assert!(saved.local.transports.is_empty());
    assert_eq!((get(&saved, HOST), synced(&saved, HOST)), (Some(changed), true));
    let removed = set(&state, HOST, Some(&iap(HOST)), None, 2).unwrap();
    assert_eq!(get(&removed, HOST), None, "this device's copy does not come back");
    assert!(view(&removed).is_empty() && !synced(&removed, HOST));
    let row = &removed.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, &wire_id(HOST))];
    assert!(row.dirty && row.record.deleted, "a tombstone for the next capture to publish");
}

/// R10: removing a route forgets what grant requests taught this device about its host, whether the route was this device's or the
/// library's. An edit keeps it.
#[test]
fn removing_a_route_forgets_the_grant_memory_of_its_host() {
    for base in [state(), central_with_host(A)] {
        let both = set(&set(&base, A, None, Some(with_pam(A)), 1).unwrap(), B, None, Some(with_pam(B)), 2).unwrap();
        let remembered = remember_grant_request(&remember_grant_request(&both, A, "restart app-api", 1800, 3).unwrap(), B, "rotate certs", 600, 4).unwrap();
        let removed = set(&remembered, A, Some(&with_pam(A)), None, 5).unwrap();
        assert_eq!(grant_memory(&removed, A), None);
        assert_eq!(grant_memory(&removed, B), Some(GrantMemory { justification: "rotate certs".into(), duration_secs: 600 }), "another host's memory stays");
        let edited = set(&remembered, A, Some(&with_pam(A)), Some(with_zone(with_pam(A), "asia-east1-c")), 5).unwrap();
        assert!(grant_memory(&edited, A).is_some(), "an edit keeps it");
    }
}

// ---- What this device keeps by host id follows its hosts (design 2026-10-26, Existing routes move in; Leaving sync) ----

/// A host id no fixture holds before a leave or an adoption gives it to a host.
const NEW: &str = "0000000000000005";

/// `rekey_local` moves each entry this device keeps for a host the map names, a route or a removed one's tombstone, and what grant
/// requests taught it about that host, to the id the map gives the host; the ids the map does not name keep theirs.
#[test]
fn rekeying_moves_routes_and_grant_memory_to_the_ids_the_map_gives_their_hosts() {
    const MOVED: &str = "0000000000000006";
    let routes = set(&set(&state(), A, None, Some(with_pam(A)), 1).unwrap(), B, None, Some(iap(B)), 2).unwrap();
    let removed = set(&set(&routes, C, None, Some(iap(C)), 3).unwrap(), C, Some(&iap(C)), None, 4).unwrap();
    let mut rekeyed = remember_grant_request(&removed, A, "restart app-api", 1800, 5).unwrap();
    let host_ids = BTreeMap::from([(A.to_string(), NEW.to_string()), (C.to_string(), MOVED.to_string())]);
    rekey_local(&mut rekeyed, &host_ids, 6).unwrap();
    assert_eq!(view(&rekeyed), vec![iap(B), HostTransport { host_id: NEW.into(), ..with_pam(A) }]);
    assert_eq!(get(&rekeyed, A), None);
    assert_eq!(grant_memory(&rekeyed, NEW), Some(GrantMemory { justification: "restart app-api".into(), duration_secs: 1800 }));
    assert_eq!(grant_memory(&rekeyed, A), None, "the memory moved with its host");
    let keys: Vec<String> = rekeyed.local.transports.keys().cloned().collect();
    assert_eq!(keys, [B, NEW, MOVED].map(|host| record_key(RecordKind::Meta, &wire_id(host))));
    assert!(rekeyed.local.transports[&record_key(RecordKind::Meta, &wire_id(MOVED))].record.deleted, "a tombstone moves as it is");
    validate_state(&rekeyed).unwrap();
}

/// Leaving `before`'s account as `record_leave::resume_locked` does: the hosts the leave plan keeps under new ids (`moves`: old → new)
/// become this device's own, the account and its collections go, and then `preserve_on_leave` runs.
fn leave_preserving(before: &SyncStateV3, moves: &[(&str, &str)]) -> SyncStateV3 {
    let mut next = moves.iter().fold(before.clone(), |next, (_, new)| with_local_host(next, new));
    next.account = None;
    next.spaces.clear();
    let host_ids = moves.iter().map(|(old, new)| (old.to_string(), new.to_string())).collect();
    preserve_on_leave(before, &mut next, &host_ids, 9).unwrap();
    next
}

/// Design 2026-10-26 (Leaving sync): the library's route for a host that stays is kept as a route saved on this device, under the
/// host's new id. The account itself goes before `preserve_on_leave` runs, as in `record_leave`.
#[test]
fn leaving_keeps_a_synced_route_of_a_preserved_host_as_a_local_route() {
    let central = set(&central_with_host(HOST), HOST, None, Some(iap(HOST)), 1).unwrap();
    assert!(synced(&central, HOST));
    let left = leave_preserving(&central, &[(HOST, NEW)]);
    assert_eq!(get(&left, NEW).map(|t| t.kind), Some(iap(HOST).kind));
    assert!(left.local.transports.contains_key(&record_key(RecordKind::Meta, &wire_id(NEW))), "kept as a route saved on this device");
    assert_eq!(get(&left, HOST), None);
    validate_state(&left).unwrap();
}

/// R8: what grant requests taught this device follows the hosts that stay, under their new ids, and goes with the hosts that go.
#[test]
fn leaving_keeps_the_grant_memory_of_the_hosts_that_stay_under_their_new_ids() {
    let routes = set(&set(&central_with_host(HOST), HOST, None, Some(with_pam(HOST)), 1).unwrap(), OTHER, None, Some(with_pam(OTHER)), 2).unwrap();
    let remembered = remember_grant_request(&remember_grant_request(&routes, HOST, "restart app-api", 1800, 3).unwrap(), OTHER, "rotate certs", 600, 4).unwrap();
    // OTHER's host is not in the library, so it does not stay.
    let left = leave_preserving(&remembered, &[(HOST, NEW)]);
    assert_eq!(grant_memory(&left, NEW), Some(GrantMemory { justification: "restart app-api".into(), duration_secs: 1800 }));
    assert_eq!(grant_memory(&left, HOST), None, "the memory moved with its host");
    assert_eq!((get(&left, OTHER), grant_memory(&left, OTHER)), (None, None), "a host that goes takes both with it");
    validate_state(&left).unwrap();
}

/// R22: what an adoption or a replacement keeps of a source's routes. Every route that applies there, the library's as well as this
/// device's own, becomes one saved on this device under its host's new id, with its grant memory; a route or memory whose host the map
/// does not name goes, and so does a tombstone, which is no route.
#[test]
fn routes_follow_the_merged_hosts_as_this_devices_own() {
    const MOVED: &str = "0000000000000006";
    const REMOVED: &str = "0000000000000007";
    // HOST's route is the library's; OTHER's and C's are this device's own; REMOVED holds a tombstone. The merge carries HOST, OTHER
    // and REMOVED, not C.
    let library = set(&central_with_host(HOST), HOST, None, Some(with_pam(HOST)), 1).unwrap();
    let own = write(&saved_on_this_device(&saved_on_this_device(&library, &iap(OTHER)), &with_pam(C)), REMOVED, None, 2).unwrap();
    let source = remember_grant_request(&remember_grant_request(&own, HOST, "restart app-api", 1800, 3).unwrap(), C, "rotate certs", 600, 4).unwrap();
    let host_ids = BTreeMap::from([(HOST.to_string(), NEW.to_string()), (OTHER.to_string(), MOVED.to_string()), (REMOVED.to_string(), "0000000000000008".to_string())]);
    // The candidate's account holds the next library's rows; the routes kept here must not join them.
    let mut next = in_central_mode(state());
    follow_hosts(&source, &mut next, &host_ids, 5).unwrap();
    assert_eq!(view(&next), vec![HostTransport { host_id: NEW.into(), ..with_pam(HOST) }, HostTransport { host_id: MOVED.into(), ..iap(OTHER) }]);
    assert!(!synced(&next, NEW) && !has_library_rows(&next), "the library's route is this device's own now");
    let keys: Vec<String> = next.local.transports.keys().cloned().collect();
    assert_eq!(keys, [NEW, MOVED].map(|host| record_key(RecordKind::Meta, &wire_id(host))), "no tombstone and nothing for C");
    assert_eq!(grant_memory(&next, NEW), Some(GrantMemory { justification: "restart app-api".into(), duration_secs: 1800 }));
    assert_eq!(next.local.transport_grants.len(), 1, "C's memory goes with its host");
}

// ---- A route saved with its host (design 2026-10-26, Commands) ----

/// The route half of a combined host save names no host: the command that carries it supplies the id. It saves, removes, or refuses on
/// an `expected` that is not the route now.
#[test]
fn a_route_change_saves_removes_or_refuses_on_a_stale_expected_value() {
    let state = with_local_host(state(), HOST);
    let saved = apply_route_change(&state, HOST, &RouteChange { expected: None, kind: Some(iap(HOST).kind) }, 1).unwrap();
    assert_eq!(get(&saved, HOST), Some(iap(HOST)));
    let stale = RouteChange { expected: None, kind: Some(with_zone(iap(HOST), "asia-east1-a").kind) };
    assert_eq!(apply_route_change(&saved, HOST, &stale, 2).unwrap_err().to_string(), ROUTE_CHANGED);
    let removed = apply_route_change(&saved, HOST, &RouteChange { expected: Some(iap(HOST)), kind: None }, 3).unwrap();
    assert_eq!(get(&removed, HOST), None);
}

/// The route displayed has to be this host's: another host's route is never the one a save was shown.
#[test]
fn a_route_change_expecting_another_hosts_route_is_stale() {
    let both = set(&set(&with_local_host(state(), HOST), HOST, None, Some(iap(HOST)), 1).unwrap(), OTHER, None, Some(iap(OTHER)), 2).unwrap();
    let change = RouteChange { expected: Some(iap(OTHER)), kind: None };
    assert_eq!(apply_route_change(&both, HOST, &change, 3).unwrap_err(), RepositoryError::RouteChanged);
    assert_eq!(get(&both, HOST), Some(iap(HOST)), "nothing was removed");
}

/// A change that leaves the route as it is writes nothing: a save of the host alone must not leave a tombstone for a route that never
/// was (it would raise the state version for someone who never used a route), nor publish a route kept on this device alone. A display
/// that is stale is refused all the same.
#[test]
fn a_route_change_that_changes_nothing_writes_nothing() {
    let bare = with_local_host(state(), HOST);
    let nothing = RouteChange { expected: None, kind: None };
    assert_eq!(apply_route_change(&bare, HOST, &nothing, 1).unwrap(), bare, "no route to remove: no tombstone and no version");
    assert_eq!(apply_route_change(&central_with_host(HOST), HOST, &nothing, 1).unwrap(), central_with_host(HOST), "nor a tombstone row in the library");
    let kept = saved_on_this_device(&in_central_mode(bare.clone()), &iap(HOST));
    let unchanged = RouteChange { expected: Some(iap(HOST)), kind: Some(iap(HOST).kind) };
    assert_eq!(apply_route_change(&kept, HOST, &unchanged, 2).unwrap(), kept, "saving the host does not publish the route it keeps");
    assert!(!synced(&kept, HOST));
    assert_eq!(apply_route_change(&bare, HOST, &unchanged, 3).unwrap_err(), RepositoryError::RouteChanged, "the route displayed is gone");
}

/// The JSON a webview sends: the route displayed and the route to save, and nothing else (the host is the command's).
#[test]
fn a_route_change_decodes_from_what_the_editor_sends() {
    let kind = serde_json::to_value(iap(HOST).kind).unwrap();
    let save: RouteChange = serde_json::from_value(json!({"expected": null, "kind": kind})).unwrap();
    assert_eq!((save.expected, save.kind), (None, Some(iap(HOST).kind)));
    let remove: RouteChange = serde_json::from_value(json!({"expected": serde_json::to_value(iap(HOST)).unwrap(), "kind": null})).unwrap();
    assert_eq!((remove.expected, remove.kind), (Some(iap(HOST)), None));
    assert!(serde_json::from_value::<RouteChange>(json!({"expected": null, "kind": null, "host_id": HOST})).is_err(), "a change names no host");
}

/// R16 and R18: a refused route write reads as a sentence where it is shown. The blocked library's is the host editor's own.
#[test]
fn a_refused_route_write_reads_as_a_sentence() {
    let change = RouteChange { expected: None, kind: Some(iap(HOST).kind) };
    let paused = apply_route_change(&blocked(central_with_host(HOST)), HOST, &change, 1).unwrap_err();
    assert_eq!(paused, RepositoryError::ReadOnlyAccount);
    assert_eq!(refusal(paused), "Sync changes are paused while account data is reviewed.");
    let full = filled_past_the_limit_with_tunnels(central_with_host(OTHER));
    assert_eq!(refusal(apply_route_change(&full, OTHER, &RouteChange { expected: None, kind: Some(iap(OTHER).kind) }, 1).unwrap_err()), NO_ROOM);
    let saved = apply_route_change(&with_local_host(state(), HOST), HOST, &change, 1).unwrap();
    assert_eq!(refusal(apply_route_change(&saved, HOST, &change, 2).unwrap_err()), ROUTE_CHANGED);
}

/// Final review (minor): a route an earlier release saved kept the justification of its last grant request, and the host editor sends
/// the route back as it displayed it. The library's row leaves the justification out, as the Catalog does, so the route read back after
/// the save is the one saved, not one the next projection changes under the editor.
#[test]
fn the_librarys_row_leaves_out_the_justification_an_earlier_release_kept() {
    let mut legacy = with_pam(HOST);
    let TransportKind::GcpIap { pam: Some(pam), .. } = &mut legacy.kind else { unreachable!("with_pam has a PAM check") };
    pam.justification = Some("restart app-api".into());
    let kept = saved_on_this_device(&central_with_host(HOST), &legacy);
    assert_eq!(get(&kept, HOST), Some(legacy.clone()), "this device's own copy keeps it");
    let edited = with_zone(legacy.clone(), "asia-east1-c");
    let saved = set(&kept, HOST, Some(&legacy), Some(edited), 2).unwrap();
    assert_eq!(get(&saved, HOST), Some(with_zone(with_pam(HOST), "asia-east1-c")));
    let row = &saved.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, &wire_id(HOST))];
    assert_eq!(row.record.payload["transport"]["kind"]["pam"]["justification"], serde_json::Value::Null);
    assert!(synced(&saved, HOST) && saved.local.transports.is_empty());
}
