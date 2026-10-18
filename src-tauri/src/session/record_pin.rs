//! Two-phase human-confirmed Records host-key persistence.
use super::{connect::CancelToken, directory::DirectoryError};
use crate::{
    error::AppError,
    ssh::{HopRef, HostKey},
    sync::{
        env::{Keychain, SyncEnv},
        record_repository as repo, record_round, record_runtime,
        records_v3::{HostScope, SyncStateV3},
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
    credentials: &dyn Keychain,
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
        Some(current) if current != key && previous != Some(current)
            && (previous.is_some() || super::credential_approval::matches(&captured, hop, current)) => {
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
    let prepared = if central_identity(&captured).is_none() && matches!(host.host.scope, HostScope::Space { .. }) {
        Some(record_round::prepare_account_gate(
            env,
            credentials,
            captured.clone(),
        )?)
    } else {
        None
    };
    guard().map_err(failed)?;
    live(cancel)?;
    let pinned_at_ms = env.now();
    {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        record_round::require_no_pending_migration(env)?;
        let (current, _) = record_runtime::snapshot(env)?;
        require_approved_identity(&current, &captured, hop.id.as_str(), &approved)?;
        live(cancel)?;
        if let Some(prepared) = prepared {
            // A background pull/upload receipt may advance generation without changing this
            // approval. Merge the authenticated account proof into current state, then check
            // the exact route, key authority and prior pin again in the atomic pin transaction.
            record_round::publish_prepared_account_gate(env, prepared)?.ensure_compatible()?;
        }
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
        fake_relay::FakeRelay,
        records_v3::HostPayload,
        testkit::{TestClock, TestDevice},
    };
    const HOST: &str = "0000000000000001";
    fn device() -> TestDevice {
        let d = TestDevice::new("pin-probe", &FakeRelay::new(), &TestClock::new());
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
            &d.keychain,
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
    #[test]
    fn a_central_host_can_be_locally_approved_without_legacy_credentials_or_network() {
        struct Forbidden;
        impl Keychain for Forbidden {
            fn get(&self,_:&str)->Result<Option<String>,AppError>{panic!("legacy credential read")}
            fn set(&self,_:&str,_:&str)->Result<(),AppError>{panic!("legacy credential write")}
            fn delete(&self,_:&str)->Result<(),AppError>{panic!("legacy credential delete")}
        }
        let d=device();let env=d.env();
        record_runtime::mutate_records(&env,|current| {
            let mut next=current.clone();let mut central=crate::sync::central::workspace::tests::enrolled();
            central.control.cutover=true;next.local.central=Some(central);Ok(next)
        }).unwrap();
        let key=crate::ssh::fake::default_server_key();
        confirm(&env,&hop(),None,&key,&Forbidden,&CancelToken::default(),&||Ok(())).unwrap();
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
                &d.keychain,
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
