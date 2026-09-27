//! 記錄模型與合併規則(spec §3.2、§6)。純資料,不碰 I/O。

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordKind {
    Host,
    Key,
    Password,
    Device,
    Meta,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Host => "host",
            RecordKind::Key => "key",
            RecordKind::Password => "password",
            RecordKind::Device => "device",
            RecordKind::Meta => "meta",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "host" => Some(RecordKind::Host),
            "key" => Some(RecordKind::Key),
            "password" => Some(RecordKind::Password),
            "device" => Some(RecordKind::Device),
            "meta" => Some(RecordKind::Meta),
            _ => None,
        }
    }
}

/// 一筆解密後的記錄。`payload` 依 kind 對應 `HostPayload` 等結構。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub kind: RecordKind,
    pub id: String,
    pub version: u64,
    pub updated_at_ms: u64,
    pub device_id: String,
    pub deleted: bool,
    pub payload: Value,
}

/// 本機快取的記錄:附上最後看到的中繼序號與是否尚未上傳。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalRecord {
    pub record: Record,
    pub seq: u64,
    pub dirty: bool,
}

pub fn record_key(kind: RecordKind, id: &str) -> String {
    format!("{}:{}", kind.as_str(), id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    KeepLocal,
    TakeRemote,
    /// 遠端較新且本機有未上傳修改 —— 呼叫端應通知使用者。
    RemoteWinsOverDirtyLocal,
}

/// 記錄層級 LWW:時間戳大者勝;同時間 tombstone 勝,再比 device_id 字典序小者勝。
pub fn merge(local: Option<&LocalRecord>, remote: &Record) -> MergeOutcome {
    let Some(local) = local else {
        return MergeOutcome::TakeRemote;
    };
    let mine = &local.record;
    let remote_wins = match remote.updated_at_ms.cmp(&mine.updated_at_ms) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => match (remote.deleted, mine.deleted) {
            (true, false) => true,
            (false, true) => false,
            _ => remote.device_id < mine.device_id,
        },
    };
    if !remote_wins {
        MergeOutcome::KeepLocal
    } else if local.dirty {
        MergeOutcome::RemoteWinsOverDirtyLocal
    } else {
        MergeOutcome::TakeRemote
    }
}

/// 中繼往返的密文信封(wire 格式 camelCase,對應 relay Worker 與 Task 5 的 client)。
/// 也是 `SyncState.sealed` 保留「本版不處理的種類」時的原樣儲存格式。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub id_hash: String,
    pub kind: String,
    pub seq: u64,
    pub nonce: String,
    pub ciphertext: String,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostPayload {
    pub schema: u32,
    /// 整個 Host 區塊的原始文字(lossless)。
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DevicePayload {
    pub schema: u32,
    pub name: String,
    pub platform: String,
    pub joined_at_ms: u64,
    pub last_seen_ms: u64,
    /// 這台裝置持有的同步金鑰 id(Phase B 才會填)。
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetaPayload {
    pub schema_version: u32,
    pub created_by_app_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, updated: u64, device: &str, deleted: bool) -> Record {
        Record {
            kind: RecordKind::Host,
            id: id.to_string(),
            version: 1,
            updated_at_ms: updated,
            device_id: device.to_string(),
            deleted,
            payload: serde_json::json!({ "schema": 1, "text": "Host x\n" }),
        }
    }

    fn local(record: Record, dirty: bool) -> LocalRecord {
        LocalRecord { record, seq: 3, dirty }
    }

    #[test]
    fn kind_round_trips_as_lowercase_strings() {
        assert_eq!(serde_json::to_string(&RecordKind::Password).unwrap(), "\"password\"");
        assert_eq!(RecordKind::Meta.as_str(), "meta");
        assert_eq!(record_key(RecordKind::Host, "web-1"), "host:web-1");
    }

    #[test]
    fn remote_is_taken_when_nothing_is_local() {
        assert_eq!(merge(None, &rec("a", 10, "dev-b", false)), MergeOutcome::TakeRemote);
    }

    #[test]
    fn newer_remote_wins_and_flags_dirty_local_loss() {
        let mine = local(rec("a", 10, "dev-a", false), false);
        assert_eq!(merge(Some(&mine), &rec("a", 11, "dev-b", false)), MergeOutcome::TakeRemote);
        let dirty = local(rec("a", 10, "dev-a", false), true);
        assert_eq!(
            merge(Some(&dirty), &rec("a", 11, "dev-b", false)),
            MergeOutcome::RemoteWinsOverDirtyLocal
        );
    }

    #[test]
    fn older_remote_never_overwrites() {
        let mine = local(rec("a", 10, "dev-a", false), true);
        assert_eq!(merge(Some(&mine), &rec("a", 9, "dev-b", false)), MergeOutcome::KeepLocal);
    }

    #[test]
    fn equal_timestamps_break_ties_by_device_id_then_tombstone() {
        let mine = local(rec("a", 10, "dev-b", false), false);
        // 字典序小的裝置贏。
        assert_eq!(merge(Some(&mine), &rec("a", 10, "dev-a", false)), MergeOutcome::TakeRemote);
        assert_eq!(merge(Some(&mine), &rec("a", 10, "dev-c", false)), MergeOutcome::KeepLocal);
        // 同時間 tombstone 優先於修改,不論裝置。
        assert_eq!(merge(Some(&mine), &rec("a", 10, "dev-z", true)), MergeOutcome::TakeRemote);
        let mine_deleted = local(rec("a", 10, "dev-z", true), false);
        assert_eq!(merge(Some(&mine_deleted), &rec("a", 10, "dev-a", false)), MergeOutcome::KeepLocal);
    }

    #[test]
    fn payloads_serialize_with_schema() {
        let p = HostPayload { schema: SCHEMA_VERSION, text: "Host a\n".into() };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["schema"], 1);
        let back: HostPayload = serde_json::from_value(v).unwrap();
        assert_eq!(back.text, "Host a\n");
    }

    #[test]
    fn envelope_uses_camel_case_wire_names() {
        let env = Envelope {
            id_hash: "h".into(),
            kind: "host".into(),
            seq: 3,
            nonce: "n".into(),
            ciphertext: "c".into(),
            deleted: false,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("\"idHash\":\"h\""), "got {json}");
        assert!(!json.contains("id_hash"));
        assert_eq!(serde_json::from_str::<Envelope>(&json).unwrap(), env);
    }
}
