//! Captured bytes only: no paths are followed and no key or archive can be created here.
use super::*;
use crate::sync::env::Keychain;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
const ROOT: &str = "data/central-recovery-archives";
const MAX_ARCHIVES: usize = 64;
const MAX_PLAIN: usize = 128 * 1024 * 1024;
pub(in crate::sync::central) struct Captured {
    pub states: Vec<SyncStateV3>,
    pub admitted: BTreeSet<PathBuf>,
}
/// All entries must have a supported interpretation. A key marker alone is unfinished input.
pub(in crate::sync::central) fn read_all(
    files: &BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    keys: &dyn Keychain,
) -> Result<Captured, AppError> {
    let root = Path::new(ROOT);
    let mut result = Captured {
        states: vec![],
        admitted: BTreeSet::new(),
    };
    let mut used_markers = BTreeSet::new();
    let mut markers = BTreeSet::new();
    let mut total = 0usize;
    for (path, bytes) in files.iter().filter(|(path, _)| path.starts_with(root)) {
        if path.parent() != Some(root) {
            return Err(invalid());
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(invalid)?;
        if let Some(operation) = name.strip_suffix("-key.sha256") {
            if !hex(operation, 32)
                || bytes.len() != 64
                || !std::str::from_utf8(bytes).is_ok_and(|s| hex(s, 64))
            {
                return Err(invalid());
            }
            markers.insert(path.clone());
            continue;
        }
        if result.states.len() >= MAX_ARCHIVES
            || bytes.len() < 12
            || bytes.len() as u64 > MAX_FILE
            || &bytes[..8] != MAGIC
        {
            return Err(invalid());
        }
        let length = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
        if length > MAX_HEADER || bytes.len() < 12 + length {
            return Err(invalid());
        }
        let header: Header =
            serde_json::from_slice(&bytes[12..12 + length]).map_err(|_| invalid())?;
        let context = &header.context;
        context.validate()?;
        if context.filename()? != name {
            return Err(invalid());
        }
        total = total
            .checked_add(context.plaintext_bytes as usize)
            .ok_or_else(invalid)?;
        if total > MAX_PLAIN {
            return Err(invalid());
        }
        let slot = format!(
            "central:v2:replacement-archive-{}:{}",
            context.operation, context.locator
        );
        let value = Zeroizing::new(keys.get(&slot)?.ok_or_else(invalid)?);
        let key = parse_key(context, &value)?;
        let marker = root.join(format!("{}-key.sha256", context.operation));
        if files
            .get(&marker)
            .is_none_or(|bytes| bytes.as_slice() != crypto::hash(key.as_slice()).as_bytes())
        {
            return Err(invalid());
        }
        let plain = decode(context, &key, bytes)?;
        let state: SyncStateV3 = serde_json::from_slice(&plain).map_err(|_| invalid())?;
        records_v3::validate_state(&state).map_err(|_| invalid())?;
        if !state
            .local
            .central
            .as_ref()
            .is_some_and(|w| context.matches(w))
        {
            return Err(invalid());
        }
        result.states.push(state);
        result.admitted.insert(path.clone());
        used_markers.insert(marker);
    }
    if markers != used_markers {
        return Err(invalid());
    }
    result.admitted.extend(markers);
    Ok(result)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sync::{
        central::{
            inventory_keys::{Capture, Snapshot},
            migration_files::Files,
            payload::Data,
            source_capture,
            source_package::Package,
        },
        record::{record_key, LocalRecord, Record, RecordKind},
    };
    use std::fs;
    #[test]
    fn captured_recovery_state_is_admitted_without_live_keys_files_or_activation() {
        let (device, keys, _) = source_capture::tests::fixture(false);
        let env = device.env();
        let mut old = record_runtime::snapshot(&env).unwrap().0;
        let id = "1".repeat(16);
        let record = LocalRecord {
            record: Record {
                kind: RecordKind::Host,
                id: id.clone(),
                version: 1,
                updated_at_ms: 1,
                device_id: old.device_id.clone(),
                deleted: false,
                payload: serde_json::json!({"schema":2,"alias":"archived-only","hostname":"synthetic.invalid","auth":"password"}),
            },
            seq: 0,
            dirty: true,
        };
        old.local
            .hosts
            .insert(record_key(RecordKind::Host, &id), record);
        let receipt = {
            let life = env.runtime.lifecycle.lock().unwrap();
            prepare(&env, &life, &old, 1, &"a".repeat(32)).unwrap()
        };
        let before = record_runtime::snapshot(&env).unwrap();
        let captured = source_capture::capture(&env, &keys, &BTreeMap::new()).unwrap();
        let encoded = captured.package.encode_local().unwrap();
        let files = Files::capture(&env, None).unwrap();
        let observer = Capture::new(&device.keychain);
        let read = read_all(&files.bytes, &observer).unwrap();
        assert_eq!(read.states, vec![old]);
        assert_eq!(read.admitted.len(), 2);
        let snapshot = observer.finish().unwrap();
        let stored = Snapshot::decode_local(&snapshot.encode_local().unwrap()).unwrap();
        let role = format!(
            "central:v2:replacement-archive-{}:{}",
            receipt.context.operation, receipt.context.locator
        );
        device.keychain.delete(&role).unwrap();
        fs::remove_dir_all(
            env.state_path
                .parent()
                .unwrap()
                .join("central-recovery-archives"),
        )
        .unwrap();
        assert!(read_all(&files.bytes, &device.keychain).is_err());
        assert_eq!(
            read_all(&files.bytes, &stored).unwrap().admitted,
            read.admitted
        );
        let restored = Package::decode_local(&encoded).unwrap();
        let history = restored
            .structured_history(&keys, &BTreeMap::new())
            .unwrap();
        assert!(history
            .into_rows()
            .iter()
            .any(|(_, data)| matches!(data,Data::Host(h) if h.alias=="archived-only")));
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
    }
    #[test]
    fn missing_marker_wrong_scope_unknown_entry_and_ciphertext_damage_never_return_partial_states()
    {
        let (device, _, _) = source_capture::tests::fixture(false);
        let env = device.env();
        let state = record_runtime::snapshot(&env).unwrap().0;
        let receipt = {
            let life = env.runtime.lifecycle.lock().unwrap();
            prepare(&env, &life, &state, 1, &"b".repeat(32)).unwrap()
        };
        let files = Files::capture(&env, None).unwrap();
        for case in [
            "missing", "marker", "blob", "extra", "name", "scope", "orphan",
        ] {
            let mut bytes = files.bytes.clone();
            let archive = Path::new(ROOT).join(receipt.context.filename().unwrap());
            let marker = Path::new(ROOT).join(format!("{}-key.sha256", receipt.context.operation));
            match case {
                "missing" => {
                    bytes.remove(&marker);
                }
                "marker" => {
                    bytes.insert(marker, Zeroizing::new(vec![b'0'; 64]));
                }
                "blob" => {
                    let v = bytes.get_mut(&archive).unwrap();
                    let i = v.len() - 1;
                    v[i] ^= 1;
                }
                "extra" => {
                    bytes.insert(Path::new(ROOT).join("unknown"), Zeroizing::new(vec![1]));
                }
                "name" => {
                    let v = bytes.remove(&archive).unwrap();
                    bytes.insert(Path::new(ROOT).join("different.lparch"), v);
                }
                "orphan" => {
                    bytes.remove(&archive);
                }
                _ => {
                    let role = format!(
                        "central:v2:replacement-archive-{}:{}",
                        receipt.context.operation, receipt.context.locator
                    );
                    device.keychain.set(&role,&serde_json::json!({"version":1,"scope":"f".repeat(64),"key":B64.encode([1u8;32])}).to_string()).unwrap();
                }
            }
            assert!(read_all(&bytes, &device.keychain).is_err(), "{case}");
        }
    }
}
