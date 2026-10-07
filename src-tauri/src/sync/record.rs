//! 記錄模型與合併規則(spec §3.2、§6)。純資料,不碰 I/O。
//! Sync v2(spaces spec §4.1、§4.2)加上帳戶 chain 的 `space` / `spacekey` 種類與它們的 payload。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppError;
use crate::sync::crypto::ChainKeys;

/// payload 的 `schema`(host/device/space/spacekey 皆為 1)與 v1 chain `meta` 的 `schema_version`。
pub const SCHEMA_VERSION: u32 = 1;
/// 帳戶 chain 的格式版本:`meta` `"account"` 的 `schema_version`(spec §4.1)。chain 上的值比它新 → 這台只讀。
pub const ACCOUNT_SCHEMA_VERSION: u32 = 2;
/// 帳戶 chain 上帳戶 `meta` 記錄的 id。
pub const ACCOUNT_META_ID: &str = "account";
/// 更換同步碼標記的 `meta` id 前綴,後接發起裝置的 device_id(spec §4.1、§7.5)。
pub const ROTATION_META_PREFIX: &str = "rotation:";
/// space0(v1 升級建立的第一個 space)的名稱與 slug(spec §5.2)。
pub const SPACE0_NAME: &str = "Synced";
pub const SPACE0_SLUG: &str = "synced";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordKind {
    Host,
    /// 帳戶 chain:同步的私鑰(id = 插槽 id;祕密,SP3 spec §4.1)。
    Key,
    Password,
    Device,
    Meta,
    /// 帳戶 chain:一個 space 的名稱與 slug(id = space id)。
    Space,
    /// 帳戶 chain:一個 space 的權杖與金鑰(id = space id;wire 名稱 `spacekey`)。
    SpaceKey,
    /// 帳戶 chain:一個金鑰插槽(id = 插槽 id;wire 名稱 `keyslot`;SP3 spec §4.1)。
    KeySlot,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Host => "host",
            RecordKind::Key => "key",
            RecordKind::Password => "password",
            RecordKind::Device => "device",
            RecordKind::Meta => "meta",
            RecordKind::Space => "space",
            RecordKind::SpaceKey => "spacekey",
            RecordKind::KeySlot => "keyslot",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "host" => Some(RecordKind::Host),
            "key" => Some(RecordKind::Key),
            "password" => Some(RecordKind::Password),
            "device" => Some(RecordKind::Device),
            "meta" => Some(RecordKind::Meta),
            "space" => Some(RecordKind::Space),
            "spacekey" => Some(RecordKind::SpaceKey),
            "keyslot" => Some(RecordKind::KeySlot),
            _ => None,
        }
    }

    /// 明文含祕密的種類(`spacekey` 的權杖與金鑰;v1 預留的 key/password):狀態檔只能保存它們的密文 envelope,
    /// 解密只在記憶體(spec §3、§4.4)。
    pub fn is_secret(self) -> bool {
        matches!(self, RecordKind::Key | RecordKind::Password | RecordKind::SpaceKey)
    }
}

/// 一筆解密後的記錄。`payload` 依 kind 對應 `HostPayload` 等結構。
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub kind: RecordKind,
    pub id: String,
    pub version: u64,
    pub updated_at_ms: u64,
    pub device_id: String,
    pub deleted: bool,
    pub payload: Value,
}

/// 手寫 `Debug`:`kind.is_secret()` 的記錄(`spacekey` 等)payload 是明文祕密,只印佔位字樣。
/// 內含 `Record` 的 `LocalRecord`、`SyncState`、`Merged` 等 derive 出來的 `Debug` 也因此不會洩漏。
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut shown = f.debug_struct("Record");
        shown
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("version", &self.version)
            .field("updated_at_ms", &self.updated_at_ms)
            .field("device_id", &self.device_id)
            .field("deleted", &self.deleted);
        if self.kind.is_secret() {
            shown.field("payload", &format_args!("<redacted>"));
        } else {
            shown.field("payload", &self.payload);
        }
        shown.finish()
    }
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
    /// 這台勾選的 space id(spec §4.1)。v1 的裝置記錄沒有這個欄位 → 空;空的時候不寫出,v1 payload 的內容不變。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spaces: Vec<String>,
    /// 這台的插槽裡是哪把金鑰(SP3 spec §4.1)。空的時候不寫出,SP1 的 payload 內容不變;SP1 讀到會略過這個欄位。
    /// 不能用 `keys`:SP1 把它當 `Vec<String>` 解析。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<crate::sync::slot_rules::DeviceSlot>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetaPayload {
    pub schema_version: u32,
    pub created_by_app_version: String,
}

impl MetaPayload {
    /// 帳戶 chain 的 `meta` `"account"`(spec §4.1):`{ schema_version: 2, created_by_app_version }`。
    pub fn account(app_version: &str) -> Self {
        Self { schema_version: ACCOUNT_SCHEMA_VERSION, created_by_app_version: app_version.to_string() }
    }
}

/// `space` 記錄的 payload(帳戶 chain;id = space id = 該 space 的 chain id,spec §4.1)。刪除 = tombstone。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpacePayload {
    pub schema: u32,
    /// 顯示名稱;UI 盡量避免重名,但不作為一致性保證。
    pub name: String,
    /// 只用來組檔名(spec §4.3),不要求唯一。
    pub slug: String,
    pub created_at_ms: u64,
    /// 更換同步碼後指向舊的 space id(spec §7.5)。
    #[serde(default)]
    pub previous_id: Option<String>,
}

impl SpacePayload {
    /// space0 的確定值(spec §5.2):兩台同時從 v1 升級的電腦寫出相同的 payload。
    pub fn space0() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            name: SPACE0_NAME.to_string(),
            slug: SPACE0_SLUG.to_string(),
            created_at_ms: 0,
            previous_id: None,
        }
    }
}

/// `spacekey` 記錄的 payload(帳戶 chain;id = space id):該 space 的權杖與金鑰,`enc_key` 為標準 base64
/// (spec §4.1)。明文是祕密:只在記憶體解開,狀態檔只存帳戶金鑰加密的 envelope;`Debug` 不印出權杖與金鑰。
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SpaceKeyPayload {
    pub schema: u32,
    pub auth_token: String,
    pub enc_key: String,
}

impl std::fmt::Debug for SpaceKeyPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpaceKeyPayload").field("schema", &self.schema).finish_non_exhaustive()
    }
}

impl SpaceKeyPayload {
    pub fn from_keys(keys: &ChainKeys) -> Self {
        Self { schema: SCHEMA_VERSION, auth_token: keys.auth_token.clone(), enc_key: keys.enc_key_b64() }
    }

    /// 還原成這個 space 的 chain 金鑰;`space_id` = 記錄 id = chain id。格式不對 → Err(`ChainKeys::from_parts`)。
    pub fn to_keys(&self, space_id: &str) -> Result<ChainKeys, AppError> {
        ChainKeys::from_parts(space_id, &self.auth_token, &self.enc_key)
    }
}

/// 更換同步碼的標記(`meta`,id = `rotation:<device_id>`):只出現在被淘汰的舊帳戶 chain(spec §4.1、§7.5)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RotationMarkerPayload {
    pub rotated_at_ms: u64,
    pub by_device_id: String,
    pub by_device_name: String,
}

/// 這台裝置的更換標記 id:`rotation:<device_id>`。
pub fn rotation_meta_id(device_id: &str) -> String {
    format!("{ROTATION_META_PREFIX}{device_id}")
}

/// `rotation:<device_id>` → `Some(device_id)`;帳戶 meta 或其他 id → None。
pub fn rotation_marker_device(meta_id: &str) -> Option<&str> {
    meta_id.strip_prefix(ROTATION_META_PREFIX).filter(|device| !device.is_empty())
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

    #[test]
    fn space_kinds_use_their_wire_names_and_unknown_kinds_stay_unknown() {
        assert_eq!(serde_json::to_string(&RecordKind::Space).unwrap(), "\"space\"");
        assert_eq!(serde_json::to_string(&RecordKind::SpaceKey).unwrap(), "\"spacekey\"");
        for kind in [RecordKind::Host, RecordKind::Device, RecordKind::Meta, RecordKind::Space, RecordKind::SpaceKey] {
            assert_eq!(RecordKind::parse(kind.as_str()), Some(kind));
            assert_eq!(serde_json::from_str::<RecordKind>(&format!("\"{}\"", kind.as_str())).unwrap(), kind);
        }
        // 未知種類照 v1 規則:不解析(呼叫端以原始密文保存在 sealed)。
        assert_eq!(RecordKind::parse("future"), None);
        assert!(serde_json::from_str::<RecordKind>("\"future\"").is_err());
        assert_eq!(record_key(RecordKind::SpaceKey, "ab"), "spacekey:ab");
    }

    #[test]
    fn only_secret_kinds_must_stay_sealed() {
        assert!(RecordKind::SpaceKey.is_secret());
        assert!(RecordKind::Key.is_secret());
        assert!(RecordKind::Password.is_secret());
        for kind in [RecordKind::Host, RecordKind::Device, RecordKind::Meta, RecordKind::Space] {
            assert!(!kind.is_secret(), "{kind:?}");
        }
    }

    #[test]
    fn device_payload_spaces_default_to_empty_and_keep_v1_payloads_unchanged() {
        // v1 的裝置記錄沒有 spaces。
        let v1 = serde_json::json!({ "schema": 1, "name": "A", "platform": "macos", "joined_at_ms": 1, "last_seen_ms": 2, "keys": [] });
        let device: DevicePayload = serde_json::from_value(v1.clone()).unwrap();
        assert!(device.spaces.is_empty());
        // 沒勾選任何 space 時不寫出欄位:v1 的裝置記錄序列化後完全不變。
        assert_eq!(serde_json::to_value(&device).unwrap(), v1);
        let mut picked = device;
        picked.spaces = vec!["a".repeat(64)];
        let back: DevicePayload = serde_json::from_value(serde_json::to_value(&picked).unwrap()).unwrap();
        assert_eq!(back.spaces, vec!["a".repeat(64)]);
    }

    #[test]
    fn keyslot_kind_round_trips_and_is_not_secret() {
        assert_eq!(RecordKind::KeySlot.as_str(), "keyslot");
        assert_eq!(RecordKind::parse("keyslot"), Some(RecordKind::KeySlot));
        assert!(!RecordKind::KeySlot.is_secret());
        assert!(RecordKind::Key.is_secret());
    }

    /// SP1 的 `DevicePayload` 沒有 `slots`:SP3 寫出的裝置記錄,SP1 照樣讀得懂(未知欄位略過);`slots` 空的時候不寫出。
    #[test]
    fn device_slots_are_invisible_to_sp1_and_omitted_when_empty() {
        #[derive(serde::Deserialize)]
        struct Sp1DevicePayload {
            #[allow(dead_code)]
            name: String,
            #[serde(default)]
            #[allow(dead_code)]
            keys: Vec<String>,
        }
        let payload = DevicePayload {
            schema: 1,
            name: "MacBook".into(),
            platform: "macos".into(),
            joined_at_ms: 1,
            last_seen_ms: 2,
            keys: Vec::new(),
            spaces: Vec::new(),
            slots: vec![crate::sync::slot_rules::DeviceSlot { slot_id: "0".repeat(32), fingerprint: None, synced_copy: true, in_vault: false }],
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert!(serde_json::from_value::<Sp1DevicePayload>(json.clone()).is_ok());
        assert_eq!(serde_json::from_value::<DevicePayload>(json).unwrap(), payload);
        let empty = serde_json::to_value(DevicePayload { slots: Vec::new(), ..payload }).unwrap();
        assert!(empty.get("slots").is_none());
    }

    #[test]
    fn space0_payload_is_the_fixed_value_from_the_spec() {
        assert_eq!(
            serde_json::to_value(SpacePayload::space0()).unwrap(),
            serde_json::json!({ "schema": 1, "name": "Synced", "slug": "synced", "created_at_ms": 0, "previous_id": null })
        );
        // previous_id 缺席 = None(serde default)。
        let p: SpacePayload =
            serde_json::from_value(serde_json::json!({ "schema": 1, "name": "Work", "slug": "work", "created_at_ms": 5 })).unwrap();
        assert_eq!(p.previous_id, None);
    }

    #[test]
    fn account_meta_and_rotation_markers() {
        let meta = MetaPayload::account("0.17.0");
        assert_eq!(meta.schema_version, 2);
        assert_eq!(meta.created_by_app_version, "0.17.0");
        assert_eq!(rotation_meta_id("dev-a"), "rotation:dev-a");
        assert_eq!(rotation_marker_device("rotation:dev-a"), Some("dev-a"));
        assert_eq!(rotation_marker_device(ACCOUNT_META_ID), None);
        assert_eq!(rotation_marker_device("rotation:"), None);
        let marker = RotationMarkerPayload { rotated_at_ms: 9, by_device_id: "dev-a".into(), by_device_name: "MacBook-A".into() };
        assert_eq!(
            serde_json::to_value(&marker).unwrap(),
            serde_json::json!({ "rotated_at_ms": 9, "by_device_id": "dev-a", "by_device_name": "MacBook-A" })
        );
    }

    #[test]
    fn space_key_payload_round_trips_and_never_debug_prints_its_secrets() {
        let keys = ChainKeys::generate().unwrap();
        let payload = SpaceKeyPayload::from_keys(&keys);
        assert_eq!(payload.schema, 1);
        let back = payload.to_keys(&keys.chain_id).unwrap();
        assert_eq!(back.auth_token, keys.auth_token);
        assert_eq!(back.enc_key_b64(), keys.enc_key_b64());
        // space id 就是 chain id:被竄改成路徑就拒絕。
        assert!(payload.to_keys("../escape").is_err());
        let shown = format!("{payload:?}");
        assert!(!shown.contains(&keys.auth_token) && !shown.contains(&payload.enc_key), "{shown}");
    }

    #[test]
    fn space_records_go_through_the_v1_record_codec() {
        // 記錄加密與 v1 相同(spec §5.3):`reconcile::encode`/`decode` 直接處理新種類。
        use crate::sync::reconcile::{decode, encode};
        let account = ChainKeys::generate().unwrap();
        let space = ChainKeys::generate().unwrap();
        let record = Record {
            kind: RecordKind::SpaceKey,
            id: space.chain_id.clone(),
            version: 1,
            updated_at_ms: 10,
            device_id: "dev-a".into(),
            deleted: false,
            payload: serde_json::to_value(SpaceKeyPayload::from_keys(&space)).unwrap(),
        };
        let item = encode(&account, &record, 0).unwrap();
        assert_eq!(item.kind, "spacekey");
        assert!(!item.ciphertext.contains(&space.auth_token));
        let env = Envelope { id_hash: item.id_hash, kind: item.kind, seq: 1, nonce: item.nonce, ciphertext: item.ciphertext, deleted: false };
        assert_eq!(decode(&account, &env).unwrap(), record);
        assert!(decode(&space, &env).is_err(), "only the account key opens spacekey records");
    }

    #[test]
    fn record_debug_never_prints_the_payload_of_secret_kinds() {
        let keys = ChainKeys::generate().unwrap();
        let record = Record {
            kind: RecordKind::SpaceKey,
            id: keys.chain_id.clone(),
            version: 1,
            updated_at_ms: 10,
            device_id: "dev-a".into(),
            deleted: false,
            payload: serde_json::to_value(SpaceKeyPayload::from_keys(&keys)).unwrap(),
        };
        let local = LocalRecord { record: record.clone(), seq: 1, dirty: false };
        // `Record` 自己,以及內含它的 `LocalRecord`(含 pretty 格式),都不能印出權杖與金鑰。
        for shown in [format!("{record:?}"), format!("{local:#?}")] {
            assert!(!shown.contains(&keys.auth_token), "{shown}");
            assert!(!shown.contains(&keys.enc_key_b64()), "{shown}");
        }
        // 非祕密種類照常印出 payload,除錯才看得到內容。
        let host = Record { kind: RecordKind::Host, payload: serde_json::json!({ "schema": 1, "text": "Host web" }), ..record };
        assert!(format!("{host:?}").contains("Host web"));
    }
}
