use super::*;
use crate::sync::crypto::{self, ChainKeys};
use crate::sync::record::{record_key, LocalRecord, Record, RecordKind};
use crate::sync::record_merge;
use crate::sync::records_v3::importer::{self, ImportOptions};
use crate::sync::state_v2::SlotSource;
use serde_json::{json, Value};
use zeroize::Zeroize;

pub(super) struct Input {
    pub state: SyncStateV3,
    pub kind: String,
    pub generation: u64,
    pub state_digest: String,
    pub legacy_v1: Option<crate::sync::state::SyncState>,
    pub legacy_v2: Option<crate::sync::state_v2::SyncStateV2>,
    pub code: Zeroizing<String>,
    pub documents: Vec<DocumentSource>,
    pub original: Option<Zeroizing<Vec<u8>>>,
}
struct ProtectedJson(Value);
impl Drop for ProtectedJson {
    fn drop(&mut self) {
        clear(&mut self.0);
    }
}
fn clear(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => {
            for v in a {
                clear(v)
            }
        }
        Value::Object(o) => {
            for v in o.values_mut() {
                clear(v)
            }
        }
        _ => {}
    }
    *v = Value::Null;
}
/// Decode bounded public legacy rows; every secret JSON lifetime is cleared before return.
pub(super) fn open_public(keys: &ChainKeys, e: &Envelope) -> Result<Option<Record>, AppError> {
    if e.ciphertext.len() > MAX_RECORD_BYTES || e.nonce.len() > 256 {
        return Err(failure(
            "migration source record exceeds its supported limit",
        ));
    }
    let bytes = Zeroizing::new(
        crypto::open(
            keys,
            &e.kind,
            &e.id_hash,
            &crypto::Sealed {
                id_hash: e.id_hash.clone(),
                nonce: e.nonce.clone(),
                ciphertext: e.ciphertext.clone(),
            },
        )
        .map_err(|_| failure("migration source cannot be decrypted"))?,
    );
    let value = ProtectedJson(
        serde_json::from_slice(&bytes)
            .map_err(|_| failure("migration source record is malformed"))?,
    );
    let kind = value
        .0
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("migration source identity is malformed"))?;
    let id = value
        .0
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("migration source identity is malformed"))?;
    let deleted = value
        .0
        .get("deleted")
        .and_then(Value::as_bool)
        .ok_or_else(|| failure("migration source identity is malformed"))?;
    if kind != e.kind || crypto::id_hash(keys, kind, id) != e.id_hash || deleted != e.deleted {
        return Err(failure(
            "migration source identity does not match its envelope",
        ));
    }
    if RecordKind::parse(kind).is_some_and(|k| k.is_secret()) {
        if value
            .0
            .get("payload")
            .and_then(|p| p.get("schema"))
            .and_then(Value::as_u64)
            != Some(1)
            && !deleted
        {
            return Err(failure("migration known secret schema is unsupported"));
        }
        return Ok(None);
    }
    if RecordKind::parse(kind).is_none() {
        return Ok(None);
    }
    if value.0.get("payload").is_some_and(|p| {
        p.get("private_key").is_some()
            || p.get("password").is_some()
            || p.get("passphrase").is_some()
    }) {
        return Err(failure("migration public source contains secret fields"));
    }
    if kind == "meta" && id.starts_with(crate::sync::record::ROTATION_META_PREFIX) {
        return Err(failure("account rotation prevents migration"));
    }
    let record: Record = serde_json::from_value(value.0.clone())
        .map_err(|_| failure("migration public source is malformed"))?;
    if serde_json::to_string(&record.payload)
        .map_err(|_| failure("migration public source is malformed"))?
        .contains("PRIVATE KEY-----")
    {
        return Err(failure("migration public source contains private material"));
    }
    Ok(Some(record))
}
pub(super) fn snapshot(
    env: &SyncEnv,
    entered: Option<Zeroizing<String>>,
) -> Result<Input, AppError> {
    let original = read_optional(&env.state_path, MAX_STATE_BYTES)?;
    let state_digest = digest(original.as_ref().map_or(&[][..], |b| b.as_slice()));
    let disk = original
        .as_ref()
        .map(|bytes| {
            std::str::from_utf8(bytes)
                .map_err(|_| failure("migration source state is malformed; original retained"))
                .and_then(|text| {
                    records_v3::decode_state(text).map_err(|_| {
                        failure("migration source state is newer or invalid; original retained")
                    })
                })
        })
        .transpose()?;
    let (kind, state, v1, v2, generation, staged) = {
        let core = env.runtime.core.lock().unwrap();
        if core.save_blocked.is_some()
            || core.generation == u64::MAX
            || core.swap_pending
            || core.unsaved
        {
            return Err(failure("migration source state is not durably writable"));
        }
        match core.format {
            RuntimeFormat::Legacy => {
                if let Some(old) = &core.legacy {
                    let mut state =
                        fresh_from(env, &old.device_id, &old.device_name, &old.relay_url)?;
                    state.phrase_cleanup_pending = old.phrase_cleanup_pending;
                    (
                        "legacy_v1".into(),
                        state,
                        Some(old.clone()),
                        None,
                        core.generation,
                        None,
                    )
                } else {
                    let old = core
                        .state
                        .clone()
                        .ok_or_else(|| failure("legacy migration source is unavailable"))?;
                    let mut state =
                        fresh_from(env, &old.device_id, &old.device_name, &old.relay_url)?;
                    state.relay_features = old.relay_features.clone();
                    state.legacy_v1_backup = old.legacy_v1_backup.clone();
                    state.phrase_cleanup_pending = old.phrase_cleanup_pending;
                    state.notices = old.notices.clone();
                    (
                        "legacy_v2".into(),
                        state,
                        None,
                        Some(old),
                        core.generation,
                        None,
                    )
                }
            }
            RuntimeFormat::Records => {
                let state = record_runtime::active_state(&core)?.clone();
                if state.rotation.is_some() {
                    return Err(failure("account rotation prevents migration"));
                }
                let (kind, staged) = if let Some(op) = &state.pending_account {
                    if op.kind != crate::sync::record_account::PendingAccountKind::JoinAccount {
                        return Err(failure("another account operation prevents migration"));
                    }
                    crate::sync::record_account::validate_pending(op)?;
                    ("pending_join", op.staged_code_account.clone())
                } else if state.account.is_none() {
                    ("new_join", None)
                } else {
                    ("records_account", None)
                };
                (kind.into(), state, None, None, core.generation, staged)
            }
            RuntimeFormat::Blocked => return Err(failure("a blocked state cannot be migrated")),
        }
    };
    if let Some(disk) = disk {
        let coherent = match disk {
            records_v3::DecodedState::V1(d) => v1.as_ref().is_some_and(|s| s == &*d),
            records_v3::DecodedState::V2(d) => v2.as_ref().is_some_and(|s| s == &*d),
            records_v3::DecodedState::V3(d) => v1.is_none() && v2.is_none() && state == *d,
        };
        if !coherent {
            return Err(failure(
                "migration state changed outside its runtime; reload the source before preview",
            ));
        }
    }
    // A Legacy workspace is imported from its local files: the account it may have joined lived on the chain relay retired in
    // 1.11.4, so neither that account's sync code, its rotation nor its schema has a say any more.
    let local_only = entered.is_none() && (v1.is_some() || v2.is_some());
    if !local_only
        && state
            .account
            .as_ref()
            .is_some_and(|a| a.remote_schema_version.is_some_and(|n| n > 3))
    {
        return Err(failure(
            "a known newer account cannot be migrated by this version",
        ));
    }
    let code = if local_only {
        Zeroizing::new(String::new())
    } else {
        match entered {
            Some(code) => Zeroizing::new(
                crypto::normalize_mnemonic(&code)
                    .map_err(|_| failure("migration sync code is invalid"))?,
            ),
            None => {
                let name = staged
                    .as_deref()
                    .unwrap_or(crate::sync::state::MNEMONIC_ACCOUNT);
                if let Some(op) = &state.pending_account {
                    if name != format!("sync:records-pending:{}", op.id) {
                        return Err(failure("migration staged code identity is invalid"));
                    }
                }
                Zeroizing::new(
                    env.keychain
                        .get(name)
                        .map_err(|_| failure("migration sync code cannot be read"))?
                        .ok_or_else(|| {
                            failure("enter the sync code to preview account migration")
                        })?,
                )
            }
        }
    };
    if !code.is_empty() {
        let keys =
            crypto::derive_account(&code).map_err(|_| failure("migration sync code is invalid"))?;
        if let Some(account) = v2
            .as_ref()
            .and_then(|s| s.account.as_ref())
            .or(state.account.as_ref())
            .or(state.pending_account.as_ref().map(|p| &p.prepared_account))
        {
            if account.chain_id != keys.chain_id {
                return Err(failure("migration sync code belongs to another account"));
            }
        }
        if let Some(v1) = &v1 {
            if v1.chain_id.as_deref().is_some_and(|id| {
                crypto::derive_keys(&code).map_or(true, |keys| keys.chain_id != id)
            }) {
                return Err(failure(
                    "migration sync code belongs to another legacy chain",
                ));
            }
        }
    }
    Ok(Input {
        state,
        kind,
        generation,
        state_digest,
        legacy_v1: v1,
        legacy_v2: v2,
        code,
        documents: documents(env)?,
        original,
    })
}
fn fresh_from(env: &SyncEnv, id: &str, name: &str, url: &str) -> Result<SyncStateV3, AppError> {
    let crate::sync::record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(
            &env.state_path.with_file_name(".migration-missing-probe"),
            name,
        )
    else {
        return Err(failure("migration profile cannot create record state"));
    };
    state.device_id = id.into();
    state.relay_url = url.into();
    Ok(*state)
}
fn stable_key_id(space: &str, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"sshelter-legacy-key-reference-v1");
    for v in [space, value] {
        h.update((v.len() as u64).to_be_bytes());
        h.update(v.as_bytes());
    }
    hex(&h.finalize()[..16])
}
pub(in crate::sync) fn key_options(
    home: &Path,
    space: &str,
    old: &[Record],
    slots: &BTreeMap<String, String>,
) -> ImportOptions {
    let mut o = ImportOptions::new(home.into());
    for r in old {
        o.key_ids.insert(
            format!("missing key for {}", r.id),
            stable_key_id(space, &r.id),
        );
        let text = r.payload.get("text").and_then(Value::as_str).unwrap_or("");
        let (items, _) = crate::config::parser::parse_file(text);
        fn visit(
            items: &[crate::config::model::Item],
            home: &Path,
            space: &str,
            slots: &BTreeMap<String, String>,
            o: &mut ImportOptions,
        ) {
            for i in items {
                match i {
                    crate::config::model::Item::Host(h) => visit(&h.body, home, space, slots, o),
                    crate::config::model::Item::Directive(d) if d.key == "identityfile" => {
                        let id = crate::sync::slot_rules::slot_file_of_value(&d.value)
                            .and_then(|f| slots.get(&f).cloned())
                            .unwrap_or_else(|| stable_key_id(space, &d.value));
                        let path =
                            match crate::sync::slot_rules::resolve_identity_value(&d.value, home) {
                                crate::sync::slot_rules::IdentityTarget::Slot(f) => {
                                    Some(home.join(crate::sync::slot_rules::SLOT_DIR).join(f))
                                }
                                crate::sync::slot_rules::IdentityTarget::File(p) => Some(p),
                                _ => None,
                            };
                        if let Some(p) = path {
                            o.key_ids
                                .insert(p.to_string_lossy().into_owned(), id.clone());
                        }
                        o.key_ids.insert(d.value.clone(), id);
                    }
                    _ => {}
                }
            }
        }
        visit(&items, home, space, slots, &mut o);
    }
    o
}
/// Full immutable baselines plus original local source identity; no writes or private-file reads. A source with a sync code
/// belonged to a chain account, which needs the retired chain relay.
pub(super) fn build(env: &SyncEnv, input: Input, id: &str) -> Result<PreparedMigration, AppError> {
    if !input.code.is_empty() {
        return Err(failure(super::CHAIN_RETIRED));
    }
    build_local(env, input, id)
}
fn row(kind: RecordKind, id: &str, device: &str, now: u64, payload: Value) -> Record {
    Record {
        kind,
        id: id.into(),
        version: 1,
        updated_at_ms: now,
        device_id: device.into(),
        deleted: false,
        payload,
    }
}
fn diag(code: &str, host_id: Option<String>, space_id: Option<String>) -> MigrationDiagnostic {
    MigrationDiagnostic {
        code: code.into(),
        host_id,
        space_id,
    }
}
fn add_vault_metadata(
    env: &SyncEnv,
    input: &Input,
    state: &mut SyncStateV3,
    diagnostics: &mut Vec<MigrationDiagnostic>,
) -> Result<(), AppError> {
    let path = crate::vault::store::vault_path(&env.state_path);
    let vault = crate::vault::store::read_vault(&path, env.keychain)
        .map_err(|_| failure("original vault is not safely readable; it was retained"))?;
    for id in vault.ids() {
        vault
            .get(&id)
            .map_err(|_| failure("original vault material cannot be validated; it was retained"))?;
    }
    if let Some(old) = &input.legacy_v2 {
        for (id, slot) in &old.key_slots {
            let Some(SlotSource::Vault {
                fingerprint,
                public_key,
                has_passphrase,
            }) = &slot.source
            else {
                continue;
            };
            let Some(entry) = vault
                .get(id)
                .map_err(|_| failure("original vault material cannot be read"))?
            else {
                diagnostics.push(diag("vault_material_missing", None, None));
                continue;
            };
            if records_v3::key_material_matches(
                &KeySlotPayload {
                    schema: 2,
                    name: slot
                        .payload
                        .as_ref()
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "imported".into()),
                    public_key: public_key.clone(),
                    fingerprint: fingerprint.clone(),
                    key_type: crate::vault::material::parse(&entry.private_key)
                        .map(|k| k.public_key().algorithm().to_string())
                        .ok_or_else(|| failure("original vault material is unsupported"))?,
                    has_passphrase: *has_passphrase,
                    created_at_ms: entry.added_at_ms,
                    origin_device_id: state.device_id.clone(),
                },
                &entry.public_key,
                &entry.fingerprint,
            )
            .is_err()
            {
                return Err(failure(
                    "original vault material does not match its public identity",
                ));
            }
            let parsed = crate::vault::material::parse(&entry.private_key)
                .ok_or_else(|| failure("original vault material is unsupported"))?;
            if parsed.is_encrypted() != *has_passphrase
                || crate::vault::material::public_key_data(public_key)
                    != Some(parsed.public_key().key_data().clone())
            {
                return Err(failure("original vault encryption identity does not match"));
            }
            let public = KeySlotPayload {
                schema: 2,
                name: slot
                    .payload
                    .as_ref()
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "imported".into()),
                public_key: public_key.clone(),
                fingerprint: fingerprint.clone(),
                key_type: parsed.public_key().algorithm().to_string(),
                has_passphrase: *has_passphrase,
                created_at_ms: slot
                    .payload
                    .as_ref()
                    .map_or(entry.added_at_ms, |p| p.created_at_ms),
                origin_device_id: state.device_id.clone(),
            };
            records_v3::validate_keyslot(id, &public)
                .map_err(|_| failure("original vault metadata is invalid"))?;
            state.local.keys.insert(
                id.clone(),
                records_v3::LocalKeyMetadata {
                    vault_id: id.clone(),
                    public,
                },
            );
        }
    }
    Ok(())
}
fn legacy_input(input: &Input) -> bool {
    input.legacy_v1.is_some() || input.legacy_v2.is_some()
}

fn comparable_host(mut payload: records_v3::HostPayload) -> records_v3::HostPayload {
    if let Some(imported) = &mut payload.imported {
        imported.source.clear();
        imported.at_ms = 0;
    }
    payload
}

/// Managed file edits are compared with the retained legacy template, never with newer typed edits.
fn managed_templates(
    env: &SyncEnv,
    input: &Input,
    state: &SyncStateV3,
    options: &mut ImportOptions,
) -> Result<BTreeMap<PathBuf, (String, BTreeMap<String, records_v3::HostPayload>)>, AppError> {
    let mut files = BTreeMap::new();
    if let Some(old) = &input.legacy_v2 {
        for (space_id, space) in &old.spaces {
            if state.spaces.contains_key(space_id) {
                // Older states may have pre-slug filenames; only a single filename is accepted.
                if Path::new(&space.file_name).components().count() != 1
                    || !matches!(
                        Path::new(&space.file_name).components().next(),
                        Some(std::path::Component::Normal(_))
                    )
                {
                    return Err(failure("legacy managed source filename is invalid"));
                }
                let path = env.ssh_dir.join("sshelter").join(&space.file_name);
                if path.exists() {
                    files.insert(
                        fs::canonicalize(path)
                            .map_err(|_| failure("legacy managed source cannot be resolved"))?,
                        space_id.clone(),
                    );
                }
            }
        }
    }
    if input.legacy_v1.is_some() && !input.code.is_empty() {
        let path = env.ssh_dir.join("sshelter/hosts.config");
        if path.exists() {
            files.insert(
                fs::canonicalize(path)
                    .map_err(|_| failure("legacy managed source cannot be resolved"))?,
                crypto::derive_space0(&input.code)?.chain_id,
            );
        }
    }
    let mut out = BTreeMap::new();
    let slots = input
        .legacy_v2
        .as_ref()
        .map(|old| {
            old.key_slots
                .iter()
                .map(|(id, slot)| (slot.file_name.clone(), id.clone()))
                .collect()
        })
        .unwrap_or_default();
    for (path, space_id) in files {
        let keys = if input.legacy_v1.is_some() {
            crypto::derive_space0(&input.code)?
        } else {
            let account_keys = crypto::derive_account(&input.code)?;
            record_merge::space_keys(
                state
                    .account
                    .as_ref()
                    .ok_or_else(|| failure("legacy managed account is unavailable"))?,
                &account_keys,
                &space_id,
            )?
            .ok_or_else(|| failure("legacy managed space identity is unavailable"))?
        };
        let mut records = Vec::new();
        for sealed in state.spaces[&space_id].sealed.values() {
            if sealed.envelope.kind == "host" {
                if let Some(record) = open_public(&keys, &sealed.envelope)? {
                    if record.payload.get("schema").and_then(Value::as_u64) == Some(1) {
                        records.push(record);
                    }
                }
            }
        }
        if let Some(v1) = &input.legacy_v1 {
            records.extend(
                v1.records
                    .values()
                    .filter(|r| r.record.kind == RecordKind::Host)
                    .map(|r| r.record.clone()),
            );
        }
        let old_options = key_options(&options.home, &space_id, &records, &slots);
        options.key_ids.extend(old_options.key_ids.clone());
        let preview = importer::preview_legacy_records(&records, &space_id, &old_options)
            .map_err(|_| failure("legacy managed template requires review"))?;
        let templates = preview
            .candidates
            .into_iter()
            .map(|h| (h.payload.alias.clone(), comparable_host(h.payload)))
            .collect();
        out.insert(path, (space_id, templates));
    }
    Ok(out)
}

/// Hash one immutable file preview and retain changed managed entries as Local review copies.
fn local_sources(
    env: &SyncEnv,
    input: &Input,
    state: &mut SyncStateV3,
    diagnostics: &mut Vec<MigrationDiagnostic>,
) -> Result<String, AppError> {
    let mut sources = BTreeMap::new();
    if !legacy_input(input) {
        return Ok(digest(&serde_json::to_vec(&sources).unwrap()));
    }
    for file in &input.documents {
        let text = &file.text;
        let disk = read_optional(Path::new(&file.source), MAX_LOCAL_SOURCE_BYTES)?;
        sources.insert(file.source.clone(),json!({"memory":file.memory_digest,"disk":digest(disk.as_ref().map_or(&[][..],|b|b.as_slice()))}));
        if disk.as_ref().map(|b| b.as_slice()) != Some(text.as_bytes()) {
            let (items, _) = crate::config::parser::parse_file(&text);
            let records:Vec<_>=items.into_iter().filter_map(|item|if let crate::config::model::Item::Host(h)=item{let alias=h.patterns.first()?.clone();Some(row(RecordKind::Host,&alias,&state.device_id,0,json!({"schema":1,"text":crate::config::serialize::serialize_items(&[crate::config::model::Item::Host(h)],true)})))}else{None}).collect();
            let space =
                digest(format!("local-document:{}:{}", state.device_id, file.source).as_bytes());
            let options = key_options(
                env.home.as_deref().unwrap_or(Path::new("/")),
                &space,
                &records,
                &BTreeMap::new(),
            );
            let preview = importer::preview_legacy_records(&records, &space, &options)
                .map_err(|_| failure("unsaved document source requires review"))?;
            for h in preview.candidates {
                diagnostics.push(diag(
                    "unsaved_document_copy_retained",
                    Some(h.id.clone()),
                    None,
                ));
                state.local.hosts.insert(
                    record_key(RecordKind::Host, &h.id),
                    LocalRecord {
                        record: row(
                            RecordKind::Host,
                            &h.id,
                            &state.device_id,
                            0,
                            serde_json::to_value(h.payload).unwrap(),
                        ),
                        seq: 0,
                        dirty: false,
                    },
                );
            }
        }
    }
    let main = env.ssh_dir.join("config");
    let mut options = ImportOptions::new(env.home.clone().unwrap_or(crate::fsutil::home_dir()?));
    let managed = managed_templates(env, input, state, &mut options)?;
    if main.exists() {
        if let Some(old) = &input.legacy_v2 {
            for (id, slot) in &old.key_slots {
                options.key_ids.insert(
                    home_slot(env, &slot.file_name)?
                        .to_string_lossy()
                        .into_owned(),
                    id.clone(),
                );
            }
        }
        let preview = importer::preview_file(&main, &options)
            .map_err(|_| failure("local configuration source requires review"))?;
        sources.insert("local-files".into(), json!(preview.provenance));
        let mut ids = BTreeMap::new();
        let mut managed_sources = BTreeMap::new();
        for h in &preview.candidates {
            let source = h
                .payload
                .imported
                .as_ref()
                .and_then(|i| fs::canonicalize(&i.source).ok());
            let target = if let Some((space, _)) = source.as_ref().and_then(|p| managed.get(p)) {
                managed_sources.insert(h.id.clone(), source.unwrap());
                space.clone()
            } else {
                digest(format!("local-files:{}", state.device_id).as_bytes())
            };
            ids.insert(
                h.id.clone(),
                records_v3::migration_host_id(&target, &h.payload.alias)
                    .map_err(|_| failure("local configuration identity is invalid"))?,
            );
        }
        let mut retained = BTreeSet::new();
        for h in &preview.candidates {
            if let Some(path) = managed_sources.get(&h.id) {
                let (space, templates) = &managed[path];
                let mut actual = h.payload.clone();
                for jump in &mut actual.jump {
                    *jump = ids
                        .get(jump)
                        .ok_or_else(|| failure("local jump source identity is missing"))?
                        .clone();
                }
                if templates.get(&h.payload.alias) == Some(&comparable_host(actual)) {
                    continue;
                }
                let local_space =
                    digest(format!("local-managed:{}:{space}", state.device_id).as_bytes());
                ids.insert(
                    h.id.clone(),
                    records_v3::migration_host_id(&local_space, &h.payload.alias)
                        .map_err(|_| failure("managed review identity is invalid"))?,
                );
                retained.insert(h.id.clone());
            }
        }
        for mut h in preview.candidates {
            if managed_sources.contains_key(&h.id) && !retained.contains(&h.id) {
                continue;
            }
            if retained.contains(&h.id) {
                diagnostics.push(diag(
                    "managed_file_copy_retained",
                    Some(ids[&h.id].clone()),
                    None,
                ));
            }
            h.id = ids[&h.id].clone();
            for jump in &mut h.payload.jump {
                *jump = ids
                    .get(jump)
                    .ok_or_else(|| failure("local jump source identity is missing"))?
                    .clone();
            }
            if state
                .spaces
                .values()
                .flat_map(|s| s.records.values())
                .any(|r| {
                    r.record.payload.get("alias").and_then(Value::as_str) == Some(&h.payload.alias)
                        && r.record.payload.get("hostname").and_then(Value::as_str)
                            == Some(&h.payload.hostname)
                        && r.record
                            .payload
                            .get("port")
                            .and_then(Value::as_u64)
                            .unwrap_or(22)
                            == h.payload.port as u64
                        && r.record
                            .payload
                            .get("user")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            == h.payload.user
                        && r.record.payload.get("auth").and_then(Value::as_str)
                            == Some(match h.payload.auth {
                                records_v3::AuthKind::Password => "password",
                                records_v3::AuthKind::Key => "key",
                                records_v3::AuthKind::Interactive => "interactive",
                            })
                        && h.payload.jump.is_empty()
                        && r.record
                            .payload
                            .get("jump")
                            .and_then(Value::as_array)
                            .is_none_or(Vec::is_empty)
                })
            {
                diagnostics.push(diag("local_source_matches_synced_host", None, None));
                continue;
            }
            if state.local.hosts.values().any(|r| {
                r.record.payload.get("alias").and_then(Value::as_str) == Some(&h.payload.alias)
            }) {
                diagnostics.push(diag("local_alias_source_retained", None, None));
                continue;
            }
            state.local.hosts.insert(
                record_key(RecordKind::Host, &h.id),
                LocalRecord {
                    record: row(
                        RecordKind::Host,
                        &h.id,
                        &state.device_id,
                        0,
                        serde_json::to_value(h.payload).unwrap(),
                    ),
                    seq: 0,
                    dirty: false,
                },
            );
        }
    }
    Ok(digest(&serde_json::to_vec(&sources).unwrap()))
}

fn home_slot(env: &SyncEnv, file: &str) -> Result<PathBuf, AppError> {
    Ok(env
        .home
        .clone()
        .unwrap_or(crate::fsutil::home_dir()?)
        .join(crate::sync::slot_rules::SLOT_DIR)
        .join(file))
}
/// The OpenSSH configuration files the migration reads (the main file and its Include files, as the importer resolves them), kept
/// as the journal's evidence copies. The retired Legacy editor could also hand over unsaved edits; nothing edits these files any
/// more, so the copy is the file on disk.
fn documents(env: &SyncEnv) -> Result<Vec<DocumentSource>, AppError> {
    let main = env.ssh_dir.join("config");
    if !main.exists() {
        return Ok(Vec::new());
    }
    let options = ImportOptions::new(env.home.clone().unwrap_or(crate::fsutil::home_dir()?));
    let preview = importer::preview_file(&main, &options)
        .map_err(|_| failure("local configuration source requires review"))?;
    if preview.provenance.len() > 128 {
        return Err(failure("legacy document source exceeds the file limit"));
    }
    let mut out = Vec::new();
    let mut total = 0usize;
    for file in &preview.provenance {
        let bytes = read_optional(&file.path, MAX_LOCAL_SOURCE_BYTES)?
            .ok_or_else(|| failure("local configuration source changed; preview it again"))?;
        let text = String::from_utf8(bytes.to_vec())
            .map_err(|_| failure("local configuration source is not text"))?;
        total = total.saturating_add(text.len());
        if total as u64 > MAX_LOCAL_SOURCE_BYTES || text.contains("PRIVATE KEY-----") {
            return Err(failure(
                "legacy document source is oversized or contains private material",
            ));
        }
        let text_digest = digest(text.as_bytes());
        out.push(DocumentSource {
            source: file.path.to_string_lossy().into_owned(),
            disk_digest: text_digest.clone(),
            memory_digest: text_digest,
            text,
        });
    }
    Ok(out)
}
/// A journal keeps a document's digest, not its text: a resumed migration copies the file again, which must still be the one the
/// preview read. A journal from an older build may name unsaved editor edits; they are gone, so it needs review.
pub(super) fn document_text(
    _env: &SyncEnv,
    source: &str,
    expected: &str,
) -> Result<String, AppError> {
    let bytes = read_optional(Path::new(source), MAX_LOCAL_SOURCE_BYTES)?.ok_or_else(|| {
        failure("unsaved migration document source is unavailable; retained journal requires review")
    })?;
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| {
        failure("unsaved migration document source changed; retained journal requires review")
    })?;
    if digest(text.as_bytes()) != expected {
        return Err(failure(
            "unsaved migration document source changed; retained journal requires review",
        ));
    }
    Ok(text)
}

fn build_local(env: &SyncEnv, input: Input, id: &str) -> Result<PreparedMigration, AppError> {
    let mut candidate = input.state.clone();
    let mut diagnostics = Vec::new();
    add_vault_metadata(env, &input, &mut candidate, &mut diagnostics)?;
    let local_source_digest = local_sources(env, &input, &mut candidate, &mut diagnostics)?;
    let pins = read_optional(
        &env.state_path.with_file_name("host-pins.json"),
        MAX_LOCAL_SOURCE_BYTES,
    )?;
    let pins_digest = digest(pins.as_ref().map_or(&[][..], |b| b.as_slice()));
    let source_digest = digest(
        &serde_json::to_vec(
            &json!({"state":input.state_digest,"local":local_source_digest,"pins":pins_digest}),
        )
        .unwrap(),
    );
    records_v3::validate_state(&candidate)
        .map_err(|_| failure("local migration candidate is invalid"))?;
    let preview = MigrationPreview {
        source_digest: source_digest.clone(),
        source_kind: input.kind.clone(),
        account_schema: 0,
        selected_space_ids: vec![],
        host_count: candidate.local.hosts.len(),
        key_count: candidate.local.keys.len(),
        diagnostics,
        can_confirm: true,
    };
    let documents = input.documents.clone();
    let original_state_bytes = input.original.clone();
    Ok(PreparedMigration {
        preview,
        input,
        plan: MigrationPlan {
            migration_id: id.into(),
            source_digest,
            candidate,
            chains: BTreeMap::new(),
            legacy_digests: BTreeMap::new(),
            local_source_digest,
            pins_digest,
            space_identities: BTreeMap::new(),
            original_state_bytes,
            documents,
        },
    })
}
pub(super) fn verify_local(env: &SyncEnv, j: &Journal, code: &str) -> Result<(), AppError> {
    let input = snapshot(
        env,
        if code.is_empty() {
            None
        } else {
            Some(Zeroizing::new(code.into()))
        },
    )?;
    let mut candidate = j.plan.candidate.clone();
    let mut diagnostics = Vec::new();
    let actual = local_sources(env, &input, &mut candidate, &mut diagnostics)?;
    let pins = if legacy_input(&input) {
        read_optional(
            &env.state_path.with_file_name("host-pins.json"),
            MAX_LOCAL_SOURCE_BYTES,
        )?
    } else {
        None
    };
    if actual != j.plan.local_source_digest
        || digest(pins.as_ref().map_or(&[][..], |b| b.as_slice())) != j.plan.pins_digest
    {
        return Err(failure("local migration source changed after confirmation; original files and journal were retained"));
    }
    Ok(())
}
