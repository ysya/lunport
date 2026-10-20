//! Authenticate captured capsules without following paths or accessing a live runtime.
use super::*;
use crate::sync::env::Keychain;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
const ROOT: &str = "data/central-source-archives";
pub(in crate::sync::central) struct Captured {
    pub frames: Vec<(Receipt, Zeroizing<Vec<u8>>)>,
    pub admitted: BTreeSet<PathBuf>,
}
pub(in crate::sync::central) fn read_all(
    files: &BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    keys: &dyn Keychain,
) -> Result<Captured, AppError> {
    let root = Path::new(ROOT);
    let mut result = Captured {
        frames: vec![],
        admitted: BTreeSet::new(),
    };
    let mut markers = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut total = 0usize;
    for (path, bytes) in files.iter().filter(|(path, _)| path.starts_with(root)) {
        if path.parent() != Some(root) {
            return Err(invalid());
        }
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(invalid)?;
        if let Some(op) = name.strip_suffix("-key.sha256") {
            if !hex(op, 32)
                || bytes.len() != 64
                || !std::str::from_utf8(bytes).is_ok_and(|v| hex(v, 64))
            {
                return Err(invalid());
            }
            markers.insert(path.clone());
            continue;
        }
        if result.frames.len() >= MAX_OUTPUTS
            || bytes.len() < 12
            || bytes.len() > MAX_FILE
            || !bytes.starts_with(MAGIC)
        {
            return Err(invalid());
        }
        let length = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
        if length == 0 || length > MAX_HEADER || bytes.len() < 12 + length {
            return Err(invalid());
        }
        let header: Header =
            serde_json::from_slice(&bytes[12..12 + length]).map_err(|_| invalid())?;
        let context = &header.context;
        header.aad()?;
        if context.filename()? != name {
            return Err(invalid());
        }
        total = total
            .checked_add(header.plaintext_bytes as usize)
            .ok_or_else(invalid)?;
        if total > MAX_PLAIN {
            return Err(invalid());
        }
        let slot = format!(
            "central:v2:source-archive-{}:{}",
            context.operation, context.locator
        );
        let encoded = Zeroizing::new(keys.get(&slot)?.ok_or_else(invalid)?);
        let key = parse_key(&encoded, &context.scope()?)?;
        let marker = root.join(context.marker());
        if files
            .get(&marker)
            .is_none_or(|v| v.as_slice() != crypto::hash(key.as_slice()).as_bytes())
        {
            return Err(invalid());
        }
        let plain = decode(context, &key, bytes)?;
        let receipt = Receipt {
            context: context.clone(),
            ciphertext_hash: crypto::hash(bytes),
            bytes: bytes.len() as u64,
        };
        receipt.validate()?;
        result.frames.push((receipt, plain));
        result.admitted.insert(path.clone());
        used.insert(marker);
    }
    if markers != used {
        return Err(invalid());
    }
    result.admitted.extend(markers);
    Ok(result)
}
