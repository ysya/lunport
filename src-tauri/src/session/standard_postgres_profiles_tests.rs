use super::*;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

const FIXTURE_PASSWORD: &str = "synthetic-password-sentinel";

#[derive(Default)]
struct TestCredentials {
    values: RefCell<BTreeMap<String, String>>,
    get_calls: Cell<usize>,
    fail_set: Cell<bool>,
    fail_delete: Cell<bool>,
    after_set: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl Credentials for TestCredentials {
    fn get(&self, id: &str) -> Result<Option<String>, String> {
        self.get_calls.set(self.get_calls.get() + 1);
        Ok(self.values.borrow().get(id).cloned())
    }

    fn set(&self, id: &str, value: &str) -> Result<(), String> {
        self.values.borrow_mut().insert(id.into(), value.into());
        if let Some(after_set) = self.after_set.borrow_mut().take() {
            after_set();
        }
        if self.fail_set.get() {
            return Err(CREDENTIAL_SAVE_FAILED.into());
        }
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), String> {
        if self.fail_delete.get() {
            return Err("fixture cannot delete".into());
        }
        self.values.borrow_mut().remove(id);
        Ok(())
    }
}

fn draft() -> StandardPostgresDraft {
    StandardPostgresDraft {
        name: "Fixture PostgreSQL".into(),
        host: "database.example.com".into(),
        port: 5432,
        database: "fixture".into(),
        username: "frank".into(),
        via_host: None,
    }
}

fn save(
    root: &Path,
    credentials: &TestCredentials,
    current: Option<&StandardPostgresProfile>,
    draft: StandardPostgresDraft,
    password: Option<&str>,
    forget_password: bool,
) -> Result<StandardPostgresProfile, String> {
    let mut store = Store::open(root)?;
    store.save(
        Save {
            id: current.map(|profile| profile.id.clone()),
            expected_revision: current.map(|profile| profile.revision.clone()),
            expected_route: None,
            draft,
            password: password.map(|value| Zeroizing::new(value.into())),
            forget_password,
        },
        credentials,
        None,
    )
}

#[test]
fn duplicate_names_survive_restart_and_deleting_one_leaves_the_other() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    let first = save(
        dir.path(),
        &credentials,
        None,
        draft(),
        Some(FIXTURE_PASSWORD),
        false,
    )
    .unwrap();
    let second = save(dir.path(), &credentials, None, draft(), None, false).unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(first.name, second.name);
    assert!(first.id.starts_with("postgres-"));
    let path = dir.path().join(FILE_NAME);
    assert!(!fs::read_to_string(&path)
        .unwrap()
        .contains(FIXTURE_PASSWORD));
    let wire = serde_json::to_value(&first).unwrap();
    assert_eq!(wire["has_password"], true);
    assert!(wire.get("password").is_none() && wire.get("credential_id").is_none());
    let mut restarted = Store::open(dir.path()).unwrap();
    assert_eq!(restarted.list(None).len(), 2);
    assert_eq!(credentials.get_calls.get(), 0);
    restarted
        .delete(&first.id, &first.revision, &credentials)
        .unwrap();
    assert_eq!(restarted.list(None), [second]);
    assert!(credentials.values.borrow().is_empty());
}

#[test]
fn display_name_edits_keep_the_password_and_connection_edits_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    let first = save(
        dir.path(),
        &credentials,
        None,
        draft(),
        Some(FIXTURE_PASSWORD),
        false,
    )
    .unwrap();
    let mut renamed = draft();
    renamed.name = "Renamed fixture".into();
    let updated = save(
        dir.path(),
        &credentials,
        Some(&first),
        renamed.clone(),
        None,
        false,
    )
    .unwrap();
    assert_ne!(updated.revision, first.revision);
    assert!(updated.has_password);
    assert_eq!(credentials.values.borrow().len(), 1);
    assert_eq!(
        save(dir.path(), &credentials, Some(&first), draft(), None, false),
        Err(STALE.into())
    );
    renamed.host = "other.example.com".into();
    let changed = save(
        dir.path(),
        &credentials,
        Some(&updated),
        renamed,
        None,
        false,
    )
    .unwrap();
    assert!(!changed.has_password);
    assert!(credentials.values.borrow().is_empty());
}

#[test]
fn ephemeral_passwords_avoid_the_key_store_and_missing_entries_ask_again() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    let saved = save(
        dir.path(),
        &credentials,
        None,
        draft(),
        Some(FIXTURE_PASSWORD),
        false,
    )
    .unwrap();
    credentials.values.borrow_mut().clear();
    let store = Store::open(dir.path()).unwrap();
    let profile = store.get(&saved.id).unwrap();
    assert_eq!(
        profile
            .password(Some("one-time-password".into()), &credentials)
            .unwrap(),
        "one-time-password",
    );
    assert_eq!(credentials.get_calls.get(), 0);
    assert_eq!(
        profile.password(None, &credentials),
        Err(PASSWORD_REQUIRED.into())
    );
    assert_eq!(credentials.get_calls.get(), 1);
}

#[test]
fn invalid_and_future_documents_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    for invalid in [
        r#"{"version":100,"profiles":{},"pending_cleanup":[]}"#,
        r#"{"version":1,"profiles":{},"pending_cleanup":["host:web-1"]}"#,
        "{{",
    ] {
        fs::write(&path, invalid).unwrap();
        assert!(Store::open(dir.path()).is_err());
        let attempted = save(
            dir.path(),
            &TestCredentials::default(),
            None,
            draft(),
            None,
            false,
        );
        assert!(attempted.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
    }
}

#[test]
fn malformed_endpoints_are_refused_before_saving_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    for host in [
        "postgres://database.example.com",
        "frank@database.example.com",
        "/var/run/postgresql",
        "database.example.com:5432",
        "db.example.com\n",
        "[2001:db8::1]",
        "::1%lo",
        "a..example.com",
        "-a.example.com",
        "192.0.2.999",
    ] {
        let mut invalid = draft();
        invalid.host = host.into();
        assert!(
            save(
                dir.path(),
                &credentials,
                None,
                invalid,
                Some(FIXTURE_PASSWORD),
                false
            )
            .is_err(),
            "{host}"
        );
    }
    let mut invalid = draft();
    invalid.port = 0;
    assert!(save(dir.path(), &credentials, None, invalid, None, false).is_err());
    assert!(credentials.values.borrow().is_empty());

    for host in ["database.example.com", "web-1", "192.0.2.10", "2001:db8::1"] {
        let mut valid = draft();
        valid.host = host.into();
        assert!(
            save(dir.path(), &credentials, None, valid, None, false).is_ok(),
            "{host}"
        );
    }
}

#[test]
fn simultaneous_edits_against_the_same_revision_have_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let first = save(
        dir.path(),
        &TestCredentials::default(),
        None,
        draft(),
        None,
        false,
    )
    .unwrap();
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let edit = || {
            barrier.wait();
            let mut changed = draft();
            changed.name = "Updated".into();
            save(
                dir.path(),
                &TestCredentials::default(),
                Some(&first),
                changed,
                None,
                false,
            )
        };
        let first = scope.spawn(edit);
        let second = scope.spawn(edit);
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(STALE.into()))
            .count(),
        1
    );
}

#[test]
fn failed_key_write_preserves_the_old_password_and_retries_abandoned_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    let saved = save(
        dir.path(),
        &credentials,
        None,
        draft(),
        Some(FIXTURE_PASSWORD),
        false,
    )
    .unwrap();
    credentials.fail_set.set(true);
    credentials.fail_delete.set(true);
    assert_eq!(
        save(
            dir.path(),
            &credentials,
            Some(&saved),
            draft(),
            Some("abandoned"),
            false
        ),
        Err(CREDENTIAL_SAVE_FAILED.into()),
    );
    assert_eq!(credentials.values.borrow().len(), 2);
    credentials.fail_set.set(false);
    credentials.fail_delete.set(false);

    {
        let store = Store::open(dir.path()).unwrap();
        let profile = store.get(&saved.id).unwrap();
        assert_eq!(profile.revision, saved.revision);
        assert_eq!(
            profile.password(None, &credentials).unwrap(),
            FIXTURE_PASSWORD
        );
    }
    let updated = save(dir.path(), &credentials, Some(&saved), draft(), None, false).unwrap();
    assert!(updated.has_password);
    assert_eq!(
        credentials
            .values
            .borrow()
            .values()
            .cloned()
            .collect::<Vec<_>>(),
        [FIXTURE_PASSWORD]
    );
}

#[test]
fn failed_metadata_commit_rolls_back_the_staged_password() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    let saved = save(
        dir.path(),
        &credentials,
        None,
        draft(),
        Some(FIXTURE_PASSWORD),
        false,
    )
    .unwrap();
    let path = dir.path().join(FILE_NAME);
    let interrupted = dir.path().join("interrupted.json");
    let replace_path = path.clone();
    let original_path = interrupted.clone();
    credentials.after_set.replace(Some(Box::new(move || {
        fs::rename(&replace_path, &original_path).unwrap();
        fs::create_dir(&replace_path).unwrap();
    })));
    assert!(save(
        dir.path(),
        &credentials,
        Some(&saved),
        draft(),
        Some("replacement"),
        false
    )
    .is_err());
    fs::remove_dir(&path).unwrap();
    fs::rename(interrupted, &path).unwrap();
    let store = Store::open(dir.path()).unwrap();
    let profile = store.get(&saved.id).unwrap();
    assert_eq!(profile.revision, saved.revision);
    assert_eq!(
        profile.password(None, &credentials).unwrap(),
        FIXTURE_PASSWORD
    );
    assert_eq!(credentials.values.borrow().len(), 1);
}

#[test]
fn failed_key_deletion_leaves_a_retryable_id_after_the_profile_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    let saved = save(
        dir.path(),
        &credentials,
        None,
        draft(),
        Some(FIXTURE_PASSWORD),
        false,
    )
    .unwrap();
    credentials.fail_delete.set(true);
    {
        let mut store = Store::open(dir.path()).unwrap();
        store
            .delete(&saved.id, &saved.revision, &credentials)
            .unwrap();
        assert!(store.get(&saved.id).is_err());
    }
    assert_eq!(credentials.values.borrow().len(), 1);
    credentials.fail_delete.set(false);
    let saved = save(dir.path(), &credentials, None, draft(), None, false).unwrap();
    assert!(!saved.has_password);
    assert!(credentials.values.borrow().is_empty());
}

const ROUTE_HOST: &str = "0123456789abcdef";
const BASTION: &str = "0123456789abcdee";

fn route_host(jump: Vec<String>) -> records_v3::HostPayload {
    serde_json::from_value(serde_json::json!({
        "schema": 2,
        "alias": "web-1",
        "hostname": "web-1.example.com",
        "user": "ops",
        "auth": "password",
        "jump": jump,
    }))
    .unwrap()
}

fn with_route_host(state: &SyncStateV3, scope: HostScope) -> SyncStateV3 {
    record_repository::create_host(state, ROUTE_HOST, scope, route_host(Vec::new()), 10).unwrap()
}

fn routed_save(
    store: &mut Store,
    credentials: &TestCredentials,
    current: Option<&StandardPostgresProfile>,
    state: &SyncStateV3,
    password: Option<&str>,
    expected_route: Option<String>,
) -> Result<StandardPostgresProfile, String> {
    let mut draft = draft();
    draft.via_host = Some(ROUTE_HOST.into());
    store.save(
        Save {
            id: current.map(|profile| profile.id.clone()),
            expected_revision: current.map(|profile| profile.revision.clone()),
            expected_route,
            draft,
            password: password.map(|value| Zeroizing::new(value.into())),
            forget_password: false,
        },
        credentials,
        Some(state),
    )
}

#[test]
fn a_same_id_host_remapped_to_another_scope_requires_reselection_and_password_reentry() {
    let pristine = crate::sync::databases::tests::state();
    let local = with_route_host(&pristine, HostScope::Local);

    let mut shared = pristine.clone();
    shared.account = Some(crate::sync::state_v2::AccountState::new(&"a".repeat(64)));
    let space_id = "b".repeat(64);
    shared.spaces.insert(
        space_id.clone(),
        records_v3::SpaceStateV3 {
            selected: true,
            baseline_established: true,
            ..Default::default()
        },
    );
    let shared = with_route_host(&shared, HostScope::Space { space_id });

    let credentials = TestCredentials::default();
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let profile = routed_save(
        &mut store,
        &credentials,
        None,
        &local,
        Some(FIXTURE_PASSWORD),
        None,
    )
    .unwrap();
    assert_eq!(store.list(Some(&local)), [profile.clone()]);
    for state in [&pristine, &shared] {
        let view = store.list(Some(state)).pop().unwrap();
        assert!(view.route_unavailable);
        assert!(!view.has_password);
        assert_eq!(
            store
                .get(&profile.id)
                .unwrap()
                .current_route(Some(state))
                .err()
                .unwrap(),
            ROUTE_GONE
        );
    }
    assert!(routed_save(
        &mut store,
        &credentials,
        Some(&profile),
        &pristine,
        None,
        None
    )
    .is_err());
    assert!(routed_save(
        &mut store,
        &credentials,
        Some(&profile),
        &shared,
        Some("replacement"),
        None
    )
    .is_err());
    assert!(routed_save(
        &mut store,
        &credentials,
        Some(&profile),
        &shared,
        Some("replacement"),
        profile.route_revision.clone()
    )
    .is_err());
    assert_eq!(credentials.values.borrow().len(), 1);
    let new_route = store.list(Some(&shared))[0].route_revision.clone();
    assert!(new_route.is_some());
    let reselected = routed_save(
        &mut store,
        &credentials,
        Some(&profile),
        &shared,
        None,
        new_route,
    )
    .unwrap();
    assert!(!reselected.route_unavailable);
    assert!(!reselected.has_password);
    assert!(credentials.values.borrow().is_empty());
}

#[test]
fn a_changed_jump_chain_cannot_pass_as_the_pinned_route() {
    let state = crate::sync::databases::tests::state();
    let mut bastion = route_host(Vec::new());
    bastion.alias = "bastion".into();
    bastion.hostname = "bastion.example.com".into();
    let state =
        record_repository::create_host(&state, BASTION, HostScope::Local, bastion, 9).unwrap();
    let state = record_repository::create_host(
        &state,
        ROUTE_HOST,
        HostScope::Local,
        route_host(vec![BASTION.into()]),
        10,
    )
    .unwrap();

    let route = Route::resolve(Some(&state), ROUTE_HOST).unwrap();
    let mut connected = ssh::Target {
        hops: vec![
            ssh::Hop::new(
                BASTION,
                "bastion",
                "bastion.example.com",
                22,
                "ops",
                ssh::AuthMethod::Password,
            ),
            ssh::Hop::new(
                ROUTE_HOST,
                "web-1",
                "web-1.example.com",
                22,
                "ops",
                ssh::AuthMethod::Password,
            ),
        ],
    };
    assert!(route.matches(&connected));
    connected.hops[0].hostname = "changed.example.com".into();
    assert!(!route.matches(&connected));

    let current = record_repository::get_host(&state, BASTION).unwrap();
    let mut changed = current.host.payload;
    changed.hostname = "changed.example.com".into();
    let changed =
        record_repository::update_host(&state, BASTION, &current.revision, changed, 11).unwrap();
    assert_ne!(
        Route::resolve(Some(&changed), ROUTE_HOST).unwrap().pin,
        route.pin
    );
}

#[test]
fn old_cloud_sql_record_writes_and_host_exports_leave_local_profiles_intact() {
    use crate::sync::databases as cloud;
    use crate::sync::records_v3::{
        decode_state, importer::saved_hosts::export_state, DecodedState,
    };

    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    let root = dir.path().join("standard-postgres");
    let public_id = "00000000000000d1";
    let private_id = "00000000000000d2";
    let state = with_route_host(&cloud::tests::state(), HostScope::Local);
    let state = cloud::set(
        &state,
        public_id,
        None,
        Some(cloud::tests::database(public_id)),
        11,
    )
    .unwrap();
    let private = cloud::tests::through_host(private_id);
    let state = cloud::set(&state, private_id, None, Some(private.clone()), 12).unwrap();
    let sync_file = dir.path().join("sync-state.json");
    let initial_sync = serde_json::to_string(&state).unwrap();
    fs::write(&sync_file, &initial_sync).unwrap();

    let saved = {
        let mut store = Store::open(&root).unwrap();
        routed_save(
            &mut store,
            &credentials,
            None,
            &state,
            Some(FIXTURE_PASSWORD),
            None,
        )
        .unwrap()
    };
    let original_profile = fs::read(root.join(FILE_NAME)).unwrap();
    let unchanged = fs::read_to_string(&sync_file).unwrap();
    assert_eq!(unchanged, initial_sync);
    let DecodedState::V3(old_reader) = decode_state(&unchanged).unwrap() else {
        panic!("expected Records state");
    };
    assert_eq!(state.version, old_reader.version);
    assert_eq!(cloud::view(&old_reader).len(), 2);

    let mut updated = private.clone();
    updated.name = "Changed in the Cloud SQL editor".into();
    let updated = cloud::set(&old_reader, private_id, Some(&private), Some(updated), 13).unwrap();
    fs::write(&sync_file, serde_json::to_vec(&updated).unwrap()).unwrap();
    let (exported, hosts, _) = export_state(&updated).unwrap();
    assert_eq!(hosts, 1);
    for contents in [exported, fs::read_to_string(&sync_file).unwrap()] {
        assert!(!contents.contains(FIXTURE_PASSWORD));
        assert!(!contents.contains(&saved.id));
    }

    let reopened = Store::open(&root).unwrap();
    assert_eq!(reopened.list(Some(&updated)), [saved]);
    assert_eq!(fs::read(root.join(FILE_NAME)).unwrap(), original_profile);
}

#[test]
fn explicit_forget_and_other_connection_fields_discard_the_old_credential() {
    for (port, database, username, forget_password) in [
        (5433, "fixture", "frank", false),
        (5432, "altered", "frank", false),
        (5432, "fixture", "ops", false),
        (5432, "fixture", "frank", true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let credentials = TestCredentials::default();
        let saved = save(
            dir.path(),
            &credentials,
            None,
            draft(),
            Some(FIXTURE_PASSWORD),
            false,
        )
        .unwrap();
        let edited = StandardPostgresDraft {
            port,
            database: database.into(),
            username: username.into(),
            ..draft()
        };
        let edited = save(
            dir.path(),
            &credentials,
            Some(&saved),
            edited,
            None,
            forget_password,
        )
        .unwrap();
        assert!(!edited.has_password);
        assert!(credentials.values.borrow().is_empty());
        let mut store = Store::open(dir.path()).unwrap();
        assert_eq!(
            store.delete(&saved.id, &saved.revision, &credentials),
            Err(STALE.into())
        );
        assert_eq!(store.list(None), [edited]);
    }
}

#[test]
fn changed_endpoint_accepts_only_the_explicit_replacement_password() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = TestCredentials::default();
    let saved = save(
        dir.path(),
        &credentials,
        None,
        draft(),
        Some(FIXTURE_PASSWORD),
        false,
    )
    .unwrap();
    let edited = StandardPostgresDraft {
        host: "other.example.com".into(),
        ..draft()
    };
    let replacement = "synthetic-replacement-password";
    let edited = save(
        dir.path(),
        &credentials,
        Some(&saved),
        edited,
        Some(replacement),
        false,
    )
    .unwrap();
    assert!(edited.has_password);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        store
            .get(&edited.id)
            .unwrap()
            .password(None, &credentials)
            .unwrap(),
        replacement
    );
    assert_eq!(credentials.values.borrow().len(), 1);
}

#[cfg(unix)]
#[test]
fn the_local_metadata_is_private_and_a_dangling_symlink_is_not_an_empty_store() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("standard-postgres");
    let credentials = TestCredentials::default();
    save(&root, &credentials, None, draft(), None, false).unwrap();
    let path = root.join(FILE_NAME);
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_file(&path).unwrap();
    symlink(dir.path().join("missing.json"), &path).unwrap();
    assert_eq!(
        save(&root, &credentials, None, draft(), None, false),
        Err(INVALID_STORE.into())
    );
    assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
}
