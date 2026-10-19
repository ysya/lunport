use super::*;
use crate::sync::{
    central::inventory_keys::Snapshot,
    fake_relay::FakeRelay,
    testkit::{TestClock, TestDevice},
};
struct Fixture {
    device: TestDevice,
    selected: SyncStateV3,
    files: BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    keys: Snapshot,
    operation: String,
}
fn fixture(copy: bool) -> Fixture {
    let device = TestDevice::new("import-inventory", &FakeRelay::new(), &TestClock::new());
    let env = device.env();
    let probe = record_runtime::probe_startup(&env.state_path, "import-inventory");
    record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
    record_runtime::save_active(&env.state_path, &record_runtime::snapshot(&env).unwrap().0)
        .unwrap();
    let source = device.home.path().join("external-config");
    let private = device.home.path().join("external-private");
    fs::write(&private, crate::sync::slot_rules::test_keys::encrypted()).unwrap();
    fs::write(
        &source,
        format!(
            "Host imported
 HostName imported.invalid
 User fixture
 IdentityFile {}
",
            private.display()
        ),
    )
    .unwrap();
    let mut prepared = prepare(&source, &ImportOptions::new(device.home.path().into())).unwrap();
    if copy {
        let id = prepared.preview().key_references[0].key_id.clone();
        select_key_copy(&mut prepared, &id).unwrap();
    }
    let receipt = confirm(&env, prepared).unwrap();
    let base = Path::new("data/imports").join(&receipt.import_id);
    let directory = env
        .state_path
        .parent()
        .unwrap()
        .join("imports")
        .join(&receipt.import_id);
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        files.insert(
            base.join(entry.file_name()),
            Zeroizing::new(fs::read(entry.path()).unwrap()),
        );
    }
    let journal: Journal = serde_json::from_slice(&files[&base.join("journal.json")]).unwrap();
    let mut keys = vec![];
    if let Some(account) = &journal.staged_key_account {
        for role in [
            account.clone(),
            format!("migration:{}:{account}", receipt.import_id),
        ] {
            if let Some(value) = device.keychain.entry(&role) {
                keys.push(serde_json::json!({"role":role,"value":value}));
            }
        }
    }
    let encoded =
        Zeroizing::new(serde_json::to_vec(&serde_json::json!({"version":1,"keys":keys})).unwrap());
    let keys = Snapshot::decode_local(&encoded).unwrap();
    let selected = record_runtime::snapshot(&env).unwrap().0;
    fs::remove_file(source).unwrap();
    fs::remove_file(private).unwrap();
    Fixture {
        device,
        selected,
        files,
        keys,
        operation: receipt.import_id,
    }
}
#[test]
fn actual_completed_host_and_private_imports_read_only_captured_evidence_without_replaying_current()
{
    for copy in [false, true] {
        let mut fixture = fixture(copy);
        let before = fs::read(&fixture.device.env().state_path).unwrap();
        fixture.selected.local.hosts.clear();
        fixture.selected.local.keys.clear();
        fixture
            .device
            .keychain
            .fail_reads
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let images = read_all(&fixture.selected, &fixture.files, &fixture.keys).unwrap();
        assert_eq!(images.states.len(), 2);
        assert!(images.states[0].local.hosts.is_empty());
        assert_eq!(images.states[1].local.hosts.len(), 1);
        assert_eq!(images.states[1].local.keys.len(), usize::from(copy));
        assert_eq!(images.admitted, fixture.files.keys().cloned().collect());
        assert!(fixture.selected.local.hosts.is_empty() && fixture.selected.local.keys.is_empty());
        assert_eq!(fs::read(&fixture.device.env().state_path).unwrap(), before);
    }
}
#[test]
fn unfinished_missing_unknown_or_changed_evidence_never_becomes_admitted_import_history() {
    for case in [
        "pending",
        "receipt",
        "missing-original",
        "missing-stage",
        "staged-receipt",
        "host",
        "vault",
        "material",
        "unknown",
        "master-role",
        "incomplete",
    ] {
        let mut fixture = fixture(true);
        let base = Path::new("data/imports").join(&fixture.operation);
        let journal_path = base.join("journal.json");
        let mut journal: Journal = serde_json::from_slice(&fixture.files[&journal_path]).unwrap();
        match case {
            "pending" => journal.phase = Phase::Staged,
            "receipt" => {
                fixture.selected.local.import_receipts.clear();
            }
            "missing-original" => {
                fixture.files.remove(&base.join("original-state.json"));
            }
            "missing-stage" => {
                fixture.files.remove(&base.join("state.json"));
            }
            "staged-receipt" => {
                let mut state: SyncStateV3 =
                    serde_json::from_slice(&fixture.files[&base.join("state.json")]).unwrap();
                state.local.import_receipts.clear();
                fixture.files.insert(
                    base.join("state.json"),
                    Zeroizing::new(serde_json::to_vec(&state).unwrap()),
                );
            }
            "host" => journal.hosts[0].payload.alias = "unconfirmed-host".into(),
            "vault" => journal.staged_vault_digest = Some("0".repeat(64)),
            "material" => journal.copies.values_mut().next().unwrap().digest = "0".repeat(64),
            "unknown" => {
                fixture.files.insert(
                    base.join("unknown-private-input"),
                    Zeroizing::new(b"PRIVATE-SENTINEL".to_vec()),
                );
            }
            "master-role" => {
                fixture.files.insert(
                    base.join("master-receipts.json"),
                    Zeroizing::new(br#"["password:host"]"#.to_vec()),
                );
            }
            _ => journal.completed_keys.clear(),
        }
        fixture.files.insert(
            journal_path,
            Zeroizing::new(serde_json::to_vec(&journal).unwrap()),
        );
        let error = read_all(&fixture.selected, &fixture.files, &fixture.keys)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE-SENTINEL"), "{case}");
    }
}

#[test]
fn actual_completed_central_local_intent_normalizes_ciphertext_without_replaying_publication() {
    use crate::sync::{record_import::central_local, record_keys};
    let device = central_local::tests::fixture();
    let env = device.env();
    let (before, generation) = record_runtime::snapshot(&env).unwrap();
    let scope = central_local::invocation(&before)
        .unwrap()
        .with_generation(generation);
    let raw = crate::sync::slot_rules::test_keys::encrypted();
    record_keys::import_local_scoped(
        &env,
        "historical-local-key",
        Zeroizing::new(raw.clone()),
        EntryOrigin::Imported,
        Some(&scope),
    )
    .unwrap();
    let selected = record_runtime::snapshot(&env).unwrap().0;
    let root = env.state_path.parent().unwrap().join("imports");
    let operation = fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    let base = Path::new("data/imports").join(&operation);
    let mut files = BTreeMap::new();
    for e in fs::read_dir(root.join(&operation)).unwrap() {
        let e = e.unwrap();
        files.insert(
            base.join(e.file_name()),
            Zeroizing::new(fs::read(e.path()).unwrap()),
        );
    }
    let journal: Journal = serde_json::from_slice(&files[&base.join("journal.json")]).unwrap();
    let mut roles = BTreeSet::new();
    if let Some(role) = &journal.staged_key_account {
        roles.insert(role.clone());
        roles.insert(format!("migration:{operation}:{role}"));
    }
    let entries: Vec<_> = roles
        .into_iter()
        .filter_map(|role| {
            device
                .keychain
                .entry(&role)
                .map(|value| serde_json::json!({"role":role,"value":value}))
        })
        .collect();
    let keys = Snapshot::decode_local(&Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({"version":1,"keys":entries})).unwrap(),
    ))
    .unwrap();
    let exact = fs::read(&env.state_path).unwrap();
    let read = read_all(&selected, &files, &keys).unwrap();
    assert_eq!(read.states.len(), 2);
    let historical = &read.states[1];
    assert_eq!(historical, &selected);
    assert_eq!(
        historical
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending
            .len(),
        2
    );
    assert_eq!(fs::read(&env.state_path).unwrap(), exact);
    for case in ["ciphertext", "hash", "stage", "scope"] {
        let mut files = files.clone();
        let mut j = journal.clone();
        if case == "stage" {
            let mut staged: SyncStateV3 =
                serde_json::from_slice(&files[&base.join("state.json")]).unwrap();
            staged.device_name = "substituted-stage".into();
            files.insert(
                base.join("state.json"),
                Zeroizing::new(serde_json::to_vec(&staged).unwrap()),
            );
        } else {
            let mut value = serde_json::to_value(j.central_intent.take().unwrap()).unwrap();
            match case {
                "ciphertext" => {
                    value["pending"][1]["latest"]["envelope"]["ciphertext"] =
                        "A".repeat(32).into()
                }
                "hash" => value["pending"][1]["latest"]["content_hash"] = "f".repeat(64).into(),
                _ => value["receipt"]["body"]["identity_slot"] = "e".repeat(32).into(),
            };
            j.central_intent = Some(serde_json::from_value(value).unwrap());
        }
        files.insert(
            base.join("journal.json"),
            Zeroizing::new(serde_json::to_vec(&j).unwrap()),
        );
        assert!(read_all(&selected, &files, &keys).is_err(), "{case}");
    }
}
