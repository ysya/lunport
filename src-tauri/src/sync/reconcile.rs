//! 記錄的加解密編碼(spec §5.3)與遠端 host 記錄要套到檔案的效果。一輪同步的合併規則在 `merge`。

use crate::error::AppError;
use crate::sync::crypto::{self, ChainKeys, Sealed};
use crate::sync::record::{Envelope, Record, RecordKind};
use crate::sync::relay::PushItem;

/// 遠端 host 記錄要套到 space 檔的效果。沒有第三種:格式不支援的記錄只會被略過。
#[derive(Clone, Debug, PartialEq)]
pub enum HostEffect {
    Upsert { alias: String, text: String },
    /// 只有驗證過的 `deleted = true` 才會產生。
    Delete { alias: String },
}

impl HostEffect {
    pub fn alias(&self) -> &str {
        match self {
            HostEffect::Upsert { alias, .. } | HostEffect::Delete { alias } => alias,
        }
    }
}

/// 記錄 → 上傳項目(整筆記錄 JSON 加密;`deleted` 明文供中繼算配額)。
pub fn encode(keys: &ChainKeys, record: &Record, base_seq: u64) -> Result<PushItem, AppError> {
    let plaintext = serde_json::to_vec(record).map_err(|e| AppError::Other(format!("cannot serialize record: {e}")))?;
    let sealed = crypto::seal(keys, record.kind.as_str(), &record.id, &plaintext)?;
    Ok(PushItem {
        id_hash: sealed.id_hash,
        kind: record.kind.as_str().to_string(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        deleted: record.deleted,
        base_seq,
    })
}

/// envelope → 記錄;kind 與 id_hash 都必須和明文相符,否則視為損毀。
pub fn decode(keys: &ChainKeys, env: &Envelope) -> Result<Record, AppError> {
    let kind = RecordKind::parse(&env.kind).ok_or_else(|| AppError::Other(format!("unknown record kind '{}'", env.kind)))?;
    let sealed = Sealed { id_hash: env.id_hash.clone(), nonce: env.nonce.clone(), ciphertext: env.ciphertext.clone() };
    let plaintext = crypto::open(keys, &env.kind, &env.id_hash, &sealed)?;
    let record: Record =
        serde_json::from_slice(&plaintext).map_err(|e| AppError::Other(format!("record payload is unreadable: {e}")))?;
    if record.kind != kind || crypto::id_hash(keys, record.kind.as_str(), &record.id) != env.id_hash {
        return Err(AppError::Other("record identity does not match its envelope".to_string()));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(alias: &str) -> Record {
        Record {
            kind: RecordKind::Host,
            id: alias.to_string(),
            version: 1,
            updated_at_ms: 5,
            device_id: "dev-a".into(),
            deleted: false,
            payload: serde_json::json!({ "schema": 1, "text": format!("Host {alias}\n") }),
        }
    }

    fn envelope(item: PushItem, kind: &str) -> Envelope {
        Envelope { id_hash: item.id_hash, kind: kind.to_string(), seq: 1, nonce: item.nonce, ciphertext: item.ciphertext, deleted: item.deleted }
    }

    #[test]
    fn records_round_trip_and_only_their_own_key_and_identity_open_them() {
        let keys = ChainKeys::generate().unwrap();
        let item = encode(&keys, &host("web"), 3).unwrap();
        assert_eq!((item.kind.as_str(), item.base_seq), ("host", 3));
        assert!(!item.ciphertext.contains("Host web"));
        assert_eq!(decode(&keys, &envelope(item.clone(), "host")).unwrap(), host("web"));
        assert!(decode(&ChainKeys::generate().unwrap(), &envelope(item.clone(), "host")).is_err(), "another chain's key");
        assert!(decode(&keys, &envelope(item.clone(), "meta")).is_err(), "the kind is bound to the envelope");
        assert!(decode(&keys, &envelope(item, "future")).is_err(), "unknown kinds are never decoded");
    }
}
