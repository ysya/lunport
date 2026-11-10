//! Two-phase human-confirmed Records host-key persistence.
use super::{connect::CancelToken, directory::DirectoryError};
use crate::{
    error::AppError,
    ssh::{HopRef, HostKey},
    sync::{
        env::SyncEnv,
        record_repository as repo, record_round, record_runtime,
        records_v3::SyncStateV3,
    },
};

fn failed(error: impl std::fmt::Display) -> AppError {
    AppError::Other(error.to_string())
}
fn live(cancel: &CancelToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        Err(failed("The connection was cancelled."))
    } else {
        Ok(())
    }
}
/// Pure current-snapshot identity: scope, effective route, revisions and authoritative key metadata.
type PinIdentity = (Vec<repo::HostView>, Vec<(String, Option<repo::KeyView>)>);
fn identity(state: &SyncStateV3, id: &str) -> Result<PinIdentity, AppError> {
    let route = repo::resolve_host_chain(state, id).map_err(failed)?;
    let keys = route
        .iter()
        .filter_map(|host| host.effective_payload.key_id.as_deref())
        .map(|id| {
            // A handshake-only probe may verify an endpoint before its login key is
            // installed. Bind the missing identity too: adding or replacing its
            // public metadata during approval must invalidate this snapshot.
            let key = match repo::resolve_key(state, id) {
                Ok(key) => Some(key),
                Err(repo::RepositoryError::KeyNotFound(_)) => None,
                Err(error) => return Err(failed(error)),
            };
            Ok((id.to_owned(), key))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((route, keys))
}

fn central_identity(state:&SyncStateV3)->Option<(&str,&str,&str)> {
    state.local.central.as_ref().filter(|c|c.control.cutover).map(|c|
        (c.control.profile.origin.as_str(),c.control.account_id.as_str(),c.control.device.id.as_str()))
}
fn require_approved_identity(
    current: &SyncStateV3,
    captured: &SyncStateV3,
    id: &str,
    approved: &PinIdentity,
) -> Result<(), AppError> {
    if central_identity(current)!=central_identity(captured)
        || current.device_id != captured.device_id
        || current.relay_url != captured.relay_url
        || current.account.as_ref().map(|a| &a.chain_id)
            != captured.account.as_ref().map(|a| &a.chain_id)
        || &identity(current, id)? != approved
    {
        return Err(failed("The confirmed route or key changed; connect again."));
    }
    Ok(())
}

pub(crate) fn confirm(
    env: &SyncEnv,
    hop: &HopRef,
    previous: Option<&HostKey>,
    key: &HostKey,
    cancel: &CancelToken,
    guard: &(dyn Fn() -> Result<(), DirectoryError> + Sync),
) -> Result<(), AppError> {
    live(cancel)?;
    let captured = {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        record_round::preflight_local(env)?;
        record_runtime::snapshot(env)?.0
    };
    let host = repo::get_host(&captured, hop.id.as_str()).map_err(failed)?;
    if host.group_error.is_some()
        || host.effective_payload.hostname != hop.hostname
        || host.effective_payload.port != hop.port
        || (!host.effective_payload.user.is_empty() && host.effective_payload.user != hop.user)
    {
        return Err(failed("The confirmed endpoint changed; connect again."));
    }
    let expected = host.host.payload.host_key.as_ref();
    let current = expected
        .map(super::record_directory::pinned_key)
        .transpose()
        .map_err(failed)?;
    match current.as_ref().map(|p| &p.key) {
        // A key confirmed as new never replaces a saved one, approved on this device or not: a pin another device saved is asked about as
        // the changed key it is, and `previous` names it.
        Some(current) if current != key && previous != Some(current) => {
            return Err(failed("The confirmed host key changed; connect again."))
        }
        None if previous.is_some() => {
            return Err(failed("The confirmed host key changed; connect again."))
        }
        _ => {}
    }
    let approved = identity(&captured, hop.id.as_str())?;
    // Guards may resolve through FormatDirectory. All callbacks and external IO stay outside lifecycle.
    guard().map_err(failed)?;
    live(cancel)?;
    let pinned_at_ms = env.now();
    {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        record_round::require_no_pending_migration(env)?;
        let (current, _) = record_runtime::snapshot(env)?;
        require_approved_identity(&current, &captured, hop.id.as_str(), &approved)?;
        live(cancel)?;
        // No caller guards or credential/network IO under publication/core. Validate and pin against
        // the same latest state: unrelated sync receipts must neither fail nor be overwritten.
        let _publication = env.runtime.format_publication.lock().unwrap();
        record_runtime::mutate_records(env, |current| {
            require_approved_identity(current, &captured, hop.id.as_str(), &approved)?;
            live(cancel)?;
            repo::pin_host_key(
                current,
                hop.id.as_str(),
                &repo::HostEndpoint {
                    hostname: hop.hostname.clone(),
                    port: hop.port,
                },
                expected,
                super::record_directory::stored(key),
                pinned_at_ms,
            )
            .map_err(failed)
            .and_then(|next| super::credential_approval::approve(next, hop, key).map_err(failed))
        })?;
    }
    env.events.wake();
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "record_pin_connect_tests.rs"]
mod connect_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        records_v3::{HostPayload, HostScope},
        testkit::{TestClock, TestDevice},
    };
    const HOST: &str = "0000000000000001";
    fn device() -> TestDevice {
        let d = TestDevice::new("pin-probe", &TestClock::new());
        let record_runtime::StartupProbe::Records { state, .. } =
            record_runtime::probe_startup(&d.env().state_path, "pin-probe")
        else {
            panic!("records")
        };
        record_runtime::activate_probe(
            &mut d.runtime.core.lock().unwrap(),
            record_runtime::StartupProbe::Records {
                state,
                fresh: false,
            },
        )
        .unwrap();
        record_runtime::mutate_records(&d.env(),|s|{
            let payload:HostPayload=serde_json::from_value(serde_json::json!({"schema":2,"alias":"web","hostname":"fixture.invalid","auth":"key","key_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})).unwrap();
            repo::create_host(s,HOST,HostScope::Local,payload,1).map_err(failed)
        }).unwrap();
        d
    }
    fn hop() -> HopRef {
        HopRef {
            id: crate::ssh::HostId::from(HOST),
            alias: "web".into(),
            hostname: "fixture.invalid".into(),
            port: 22,
            user: "ops".into(),
        }
    }
    #[test]
    fn a_verified_endpoint_can_be_pinned_before_its_login_key_is_installed() {
        let d = device();
        let env = d.env();
        let key = crate::ssh::fake::default_server_key();
        confirm(
            &env,
            &hop(),
            None,
            &key,
            &CancelToken::default(),
            &|| Ok(()),
        )
        .unwrap();
        let state = record_runtime::snapshot(&env).unwrap().0;
        let saved = repo::get_host(&state, HOST).unwrap();
        assert_eq!(
            saved.host.payload.host_key.unwrap().fingerprint,
            key.fingerprint
        );
        assert!(matches!(saved.readiness, repo::HostReadiness::NeedsKey(_)));
    }
    /// A pin saved for the host without this device's approval, as one another device saved arrives here, dated 7.
    fn save_unapproved(env: &SyncEnv, key: &HostKey) {
        record_runtime::mutate_records(env, |s| {
            repo::pin_host_key(
                s,
                HOST,
                &repo::HostEndpoint { hostname: "fixture.invalid".into(), port: 22 },
                None,
                super::super::record_directory::stored(key),
                7,
            )
            .map_err(failed)
        })
        .unwrap();
    }
    fn saved_pin(env: &SyncEnv) -> Option<crate::sync::records_v3::StoredHostKey> {
        let state = record_runtime::snapshot(env).unwrap().0;
        repo::get_host(&state, HOST).unwrap().host.payload.host_key
    }
    /// A key trusted as new (`previous: None`) never replaces a pin saved for the host, even one this device
    /// has not approved (another device saved it): the person was not shown that pin. Accepted as the changed key it is (`previous` names
    /// the saved pin), the key replaces the pin and is approved here.
    #[test]
    fn a_key_trusted_as_new_never_replaces_a_saved_pin_this_device_has_not_approved() {
        let d = device();
        let env = d.env();
        let saved = HostKey::from_openssh_line(crate::sync::slot_rules::test_keys::ECDSA_PUBLIC).unwrap();
        let key = crate::ssh::fake::default_server_key();
        save_unapproved(&env, &saved);
        let refused = confirm(&env, &hop(), None, &key, &CancelToken::default(), &|| Ok(()));
        assert_eq!(refused.map_err(|error| error.to_string()), Err("The confirmed host key changed; connect again.".to_string()));
        assert_eq!(saved_pin(&env).map(|pin| pin.fingerprint), Some(saved.fingerprint.clone()), "the saved pin stays");
        let state = record_runtime::snapshot(&env).unwrap().0;
        assert!(!state.local.credential_approvals.contains_key(HOST), "nothing was approved");

        confirm(&env, &hop(), Some(&saved), &key, &CancelToken::default(), &|| Ok(())).unwrap();
        assert_eq!(saved_pin(&env).map(|pin| pin.fingerprint), Some(key.fingerprint.clone()));
        let state = record_runtime::snapshot(&env).unwrap().0;
        assert!(super::super::credential_approval::matches(&state, &hop(), &key));
    }
    /// Another device replaced the saved pin while the changed-key window showed the old one: accepting the key against the pin the person
    /// was shown writes nothing and approves nothing.
    #[test]
    fn accepting_a_changed_key_against_a_saved_pin_that_was_replaced_meanwhile_writes_nothing() {
        let d = device();
        let env = d.env();
        let shown = HostKey::from_openssh_line(crate::sync::slot_rules::test_keys::ECDSA_PUBLIC).unwrap();
        let meanwhile = HostKey::from_openssh_line(crate::sync::slot_rules::test_keys::RSA_PUBLIC).unwrap();
        save_unapproved(&env, &shown);
        record_runtime::mutate_records(&env, |s| {
            let current = repo::get_host(s, HOST).map_err(failed)?.host.payload.host_key;
            repo::pin_host_key(
                s,
                HOST,
                &repo::HostEndpoint { hostname: "fixture.invalid".into(), port: 22 },
                current.as_ref(),
                super::super::record_directory::stored(&meanwhile),
                8,
            )
            .map_err(failed)
        })
        .unwrap();
        let key = crate::ssh::fake::default_server_key();
        let refused = confirm(&env, &hop(), Some(&shown), &key, &CancelToken::default(), &|| Ok(()));
        assert_eq!(refused.map_err(|error| error.to_string()), Err("The confirmed host key changed; connect again.".to_string()));
        assert_eq!(saved_pin(&env).map(|pin| (pin.fingerprint, pin.pinned_at_ms)), Some((meanwhile.fingerprint.clone(), 8)));
        let state = record_runtime::snapshot(&env).unwrap().0;
        assert!(!state.local.credential_approvals.contains_key(HOST), "nothing was approved");
    }
    /// The very key another device saved is approved here as it is (`previous: None`): its pin keeps the date it was saved with, and only
    /// this device's approval is added.
    #[test]
    fn the_saved_key_itself_is_approved_here_without_rewriting_its_pin() {
        let d = device();
        let env = d.env();
        let key = crate::ssh::fake::default_server_key();
        save_unapproved(&env, &key);
        let before = saved_pin(&env).unwrap();
        confirm(&env, &hop(), None, &key, &CancelToken::default(), &|| Ok(())).unwrap();
        let after = saved_pin(&env).unwrap();
        assert_eq!((after.fingerprint.as_str(), after.pinned_at_ms), (key.fingerprint.as_str(), 7));
        assert_eq!(after, before, "the pin is not written again");
        let state = record_runtime::snapshot(&env).unwrap().0;
        assert!(super::super::credential_approval::matches(&state, &hop(), &key));
    }
    #[test]
    fn a_central_host_can_be_locally_approved_without_legacy_credentials_or_network() {
        let d=device();let env=d.env();
        record_runtime::mutate_records(&env,|current| {
            let mut next=current.clone();let mut central=crate::sync::central::workspace::tests::enrolled();
            central.control.cutover=true;next.local.central=Some(central);Ok(next)
        }).unwrap();
        let key=crate::ssh::fake::default_server_key();
        confirm(&env,&hop(),None,&key,&CancelToken::default(),&||Ok(())).unwrap();
        let state=record_runtime::snapshot(&env).unwrap().0;
        let central=&state.local.central.as_ref().unwrap().control;
        let receipt=&state.local.credential_approvals[HOST];
        assert_eq!(receipt.account_id.as_deref(),Some(central.account_id.as_str()));
        assert_eq!(receipt.relay_url.as_deref(),Some(central.profile.origin.as_str()));
        assert_eq!(receipt.device_id,central.device.id);
        assert!(super::super::credential_approval::matches(&state,&hop(),&key));
    }
    #[test]
    fn canceled_or_changed_probe_never_commits_an_endpoint_pin() {
        for change in [true, false] {
            let d = device();
            let env = d.env();
            let cancel = CancelToken::default();
            let count = std::sync::atomic::AtomicUsize::new(0);
            let result = confirm(
                &env,
                &hop(),
                None,
                &crate::ssh::fake::default_server_key(),
                &cancel,
                &|| {
                    if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        if change {
                            crate::sync::record_commands::edit_records(&env, |s, now| {
                                let view = repo::get_host(s, HOST).map_err(failed)?;
                                let mut payload = view.host.payload;
                                payload.hostname = "changed.invalid".into();
                                repo::update_host(s, HOST, &view.revision, payload, now)
                                    .map_err(failed)
                            })
                            .unwrap();
                        } else {
                            cancel.cancel();
                        }
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            let state = record_runtime::snapshot(&env).unwrap().0;
            assert!(repo::get_host(&state, HOST)
                .unwrap()
                .host
                .payload
                .host_key
                .is_none());
        }
    }
}
