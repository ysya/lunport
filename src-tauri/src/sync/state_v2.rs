//! Sync v2 的本機狀態(spec §4.4):`sync-state.json` 升為 `version: 2`(0600,`atomic_write`),路徑同 v1
//! (`state::state_path`)。只保存帳戶、這台勾選的 space 與這台的金鑰插槽;space 的權杖與金鑰、同步的私鑰只以帳戶金鑰
//! 加密的 envelope 落地(`AccountState::sealed`),在記憶體解開。讀到 `version: 1` 的檔案 → `LoadedState::Legacy`
//! (交給 v1 升級,spec §7.6),不解析成 v2。

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::fsutil;
use crate::sync::approval::ApprovalSignature;
use crate::sync::crypto::ChainKeys;
use crate::sync::reconcile::{decode, encode};
use crate::sync::record::{Envelope, LocalRecord, Record, RotationMarkerPayload, ACCOUNT_SCHEMA_VERSION};
use crate::sync::relay::{PushItem, RelayInfo};
use crate::sync::slot_files::LinkKind;
use crate::sync::slot_rules::KeySlotPayload;
use crate::sync::state::{SyncState as LegacyState, DEFAULT_RELAY_URL};

pub const STATE_VERSION_V2: u32 = 2;
/// 更換同步碼時新同步碼暫存的 keychain account(spec §7.5);現行的同步碼在 `state::MNEMONIC_ACCOUNT`。
pub const NEXT_MNEMONIC_ACCOUNT: &str = "sync:mnemonic-next";
/// v1 狀態檔在升級時的備份(spec §7.6 第 5 步),與 `sync-state.json` 同目錄。
pub const LEGACY_BACKUP_FILE: &str = "sync-state.v1-backup.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyncStateV2 {
    pub version: u32,
    pub device_id: String,
    pub device_name: String,
    /// 只能在未加入時更改(cursor 與 seq 屬於某一個 relay,spec §7.3)。
    pub relay_url: String,
    /// None = 未加入帳戶。
    #[serde(default)]
    pub account: Option<AccountState>,
    /// 這台勾選的 space,key = space id。未勾選的 space 只存在帳戶的 `space`/`spacekey` 記錄中(spec §4.4)。
    #[serde(default)]
    pub spaces: BTreeMap<String, SpaceState>,
    /// 更換同步碼進行中(spec §7.5):下次啟動依它接續。
    #[serde(default)]
    pub rotation: Option<RotationProgress>,
    /// v1 狀態檔的備份檔名(v1 升級之後,spec §7.6)。
    #[serde(default)]
    pub legacy_v1_backup: Option<String>,
    /// 最近一次 `GET /v1/info` 的結果(spec §6.4)。
    #[serde(default)]
    pub relay_features: Option<RelayFeatures>,
    /// 離開帳戶時 keychain 裡的同步碼刪不掉:持久化這個待辦,重啟後仍顯示重試(同 v1,spec §7.3)。
    #[serde(default)]
    pub phrase_cleanup_pending: bool,
    pub last_sync_ms: Option<u64>,
    pub last_error: Option<String>,
    /// 這台的金鑰插槽(SP3 spec §4.3),key = 插槽 id。只含公開資訊與本機路徑。離開帳戶時保留(插槽檔留在原地)。
    #[serde(default)]
    pub key_slots: BTreeMap<String, LocalSlot>,
    /// 等使用者看過才清掉的提示(v1 升級說明、別台刪了 space、改名被擋下、新同步碼……;spec §7.2、§7.5、§8)。讀檔時略過
    /// 這版不認得的種類(`known_notices`),降版之後狀態檔照樣讀得回來。
    #[serde(default, deserialize_with = "known_notices")]
    pub notices: Vec<SyncNotice>,
}

impl SyncStateV2 {
    pub fn fresh(device_name: &str) -> Result<Self, AppError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| AppError::Other(format!("cannot create device id: {e}")))?;
        Ok(Self {
            version: STATE_VERSION_V2,
            device_id: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            device_name: device_name.to_string(),
            relay_url: DEFAULT_RELAY_URL.to_string(),
            account: None,
            spaces: BTreeMap::new(),
            rotation: None,
            legacy_v1_backup: None,
            relay_features: None,
            phrase_cleanup_pending: false,
            last_sync_ms: None,
            last_error: None,
            key_slots: BTreeMap::new(),
            notices: Vec::new(),
        })
    }

    pub fn joined(&self) -> bool {
        self.account.is_some()
    }

    /// 帳戶 chain 用了比本 app 新的格式:只套用可理解的記錄、不上傳(同 v1)。
    pub fn read_only(&self) -> bool {
        self.account
            .as_ref()
            .and_then(|a| a.remote_schema_version)
            .is_some_and(|v| v > ACCOUNT_SCHEMA_VERSION)
    }

    /// 這台偵測到帳戶已被更換同步碼(spec §7.5):非 None 時不做任何網路寫入。
    pub fn frozen(&self) -> Option<&FreezeInfo> {
        self.account.as_ref().and_then(|a| a.frozen.as_ref())
    }
}

/// 帳戶 chain 的區段(spec §4.4)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountState {
    pub chain_id: String,
    /// 已套用到本機的最大 relay 序號。
    pub cursor_seq: u64,
    /// 剛加入後 false:第一輪以帳戶 chain 為準(同 v1 基線輪)。
    #[serde(default)]
    pub baseline_established: bool,
    /// 帳戶 `meta` 的 `schema_version`;比 `ACCOUNT_SCHEMA_VERSION` 新 → 唯讀。
    #[serde(default)]
    pub remote_schema_version: Option<u32>,
    /// 偵測到帳戶已被更換同步碼(spec §7.5)。
    #[serde(default)]
    pub frozen: Option<FreezeInfo>,
    /// device / space / meta / keyslot 的明文記錄,key = `record_key(kind, id)`。
    #[serde(default)]
    pub records: BTreeMap<String, LocalRecord>,
    /// `spacekey`、`key`(SP3)與未知種類的密文,key = `sealed_key(kind, id_hash)`。
    #[serde(default)]
    pub sealed: BTreeMap<String, SealedRecord>,
    /// 這台刪除的 space 還沒 `DELETE` 的 chain(spec §7.2):tombstone 之前那份 `spacekey` 的密文(帳戶金鑰加密,
    /// 權杖只在記憶體解開)。tombstone 上傳之後才刪 chain —— 別台先收到 tombstone,不會看到「chain 不見了」。
    #[serde(default)]
    pub chain_deletes: Vec<SealedRecord>,
}

impl AccountState {
    pub fn new(chain_id: &str) -> Self {
        Self {
            chain_id: chain_id.to_string(),
            cursor_seq: 0,
            baseline_established: false,
            remote_schema_version: None,
            frozen: None,
            records: BTreeMap::new(),
            sealed: BTreeMap::new(),
            chain_deletes: Vec::new(),
        }
    }
}

/// `AccountState::sealed` 的 key:`"{kind}:{id_hash}"`(同 v1 的 `sealed`)。
pub fn sealed_key(kind: &str, id_hash: &str) -> String {
    format!("{kind}:{id_hash}")
}

/// 不能以明文保存的記錄(spec §3、§4.4):relay 的密文 envelope 原樣保存(`envelope.seq` = relay 序號)。這台寫出、
/// 還沒上傳的(例如新 space 的 `spacekey`)`dirty` = true:上傳的就是這份密文,`envelope.seq` 當 base_seq。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SealedRecord {
    pub envelope: Envelope,
    #[serde(default)]
    pub dirty: bool,
}

impl SealedRecord {
    /// 以 `keys`(帳戶金鑰)加密一筆記錄並標為 dirty;`seq` = 本機最後看到的該記錄序號(新記錄為 0)。
    pub fn seal(keys: &ChainKeys, record: &Record, seq: u64) -> Result<Self, AppError> {
        let item = encode(keys, record, seq)?;
        Ok(Self {
            envelope: Envelope {
                id_hash: item.id_hash,
                kind: item.kind,
                seq,
                nonce: item.nonce,
                ciphertext: item.ciphertext,
                deleted: item.deleted,
            },
            dirty: true,
        })
    }

    /// 只在記憶體解開(LWW 合併、取出 space 金鑰);kind 與 id_hash 必須與明文相符(`reconcile::decode`)。
    pub fn open(&self, keys: &ChainKeys) -> Result<Record, AppError> {
        decode(keys, &self.envelope)
    }

    /// 上傳項目:這份密文原樣上傳,base_seq = `envelope.seq`。
    pub fn push_item(&self) -> PushItem {
        PushItem {
            id_hash: self.envelope.id_hash.clone(),
            kind: self.envelope.kind.clone(),
            nonce: self.envelope.nonce.clone(),
            ciphertext: self.envelope.ciphertext.clone(),
            deleted: self.envelope.deleted,
            base_seq: self.envelope.seq,
        }
    }

    /// 在 `AccountState::sealed` 裡的 key。
    pub fn key(&self) -> String {
        sealed_key(&self.envelope.kind, &self.envelope.id_hash)
    }
}

/// 一個插槽在這台電腦上的狀況(SP3 spec §4.3)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalSlot {
    /// 插槽檔名(`<name>-<插槽 id 前 8>`)。
    pub file_name: String,
    /// 插槽裡放的是什麼;None = 這台還沒有它的金鑰。
    #[serde(default)]
    pub source: Option<SlotSource>,
    /// 最近一次維護這個插槽的錯誤(給使用者看;只有路徑與原因,不含金鑰內容)。
    #[serde(default)]
    pub last_error: Option<String>,
    /// 已經為「這台需要金鑰」發過 `SyncNotice::KeysNeeded`(每個插槽只發一次)。
    #[serde(default)]
    pub asked: bool,
    /// 最後看到的 `keyslot` payload:帳戶裡找不到這個插槽時(例如在沒有 SP3 的電腦上更換了同步碼)據此補寫(spec §6.6)。
    #[serde(default)]
    pub payload: Option<KeySlotPayload>,
    /// 這台電腦自己把哪一把金鑰(指紋)上傳成這個插槽的同步金鑰:只有這台的使用者在這台選了同步它(建立插槽時選「Sync key」、
    /// 或之後的「Sync this key」「Sync the new key」)才會設定,帳戶裡別人的變更不會動它。補寫 `key`(spec §6.6)時,連到本機金鑰的
    /// 插槽只認它:`payload` 是帳戶裡最新的 `keyslot`,帳戶裡的任何成員都改得動(改成 `synced`、填上公開的指紋),證明不了使用者
    /// 同意把這把私鑰交出去。None = 這台沒有為這個插槽上傳過金鑰。建立或加入另一個帳戶時清掉(`account::install_account`:記錄學到的帳戶
    /// `learned_in` 不是加入的那一個):在別的帳戶裡同意的,不算同意上傳到這個帳戶;用同一個同步碼重新加入同一個帳戶照舊。更換同步碼是同一個
    /// 帳戶的延續,也照舊(`rotation::install_new_account`)。
    #[serde(default)]
    pub uploaded_fingerprint: Option<String>,
    /// 這個插槽的連結收起來了:沒有主機用到而拿掉了連結檔,或路徑上被換成了別的檔案(`slots::park_link`);有主機用到的 symlink 插槽,
    /// 路徑上不是指到記錄裡原檔的 symlink 也一樣(`slots::maintain`)。`source` 的 `Linked` 記錄還在(原檔、`origin`、使用者的挑選),
    /// 但這筆記錄現在不擁有插槽路徑上的任何東西。再用到的時候,路徑空著才重新連結(然後清掉這個旗標;路徑上正好是自己的 symlink 就
    /// 認回它);路徑上有別的東西(別的插槽放的、使用者的檔案)就不碰、回報擋路,也不認它是自己的。插槽被刪除時,收起來的記錄只忘掉,
    /// 不移除、也不收編路徑上的檔案。
    #[serde(default)]
    pub parked: bool,
    /// 這筆記錄是在哪一個帳戶學到的(帳戶 chain id,`AccountState::chain_id`):這台在那個帳戶裡第一次看到這個插槽(`slots::reconcile` 建立記錄)、
    /// 在那裡建立它(`slot_setup::create_slot`)、落地或改用了那裡的同步金鑰(`slots::reconcile`、`slots::use_synced`)、在那裡選了同步它
    /// (`slots::set_mode`),或在那裡第一次為它挑了金鑰、沿用了它(`slots::pick`、`slot_setup::reuse_slot`)。補寫帳戶裡不見的插槽
    /// (`slots::republish`,spec §6.6)只做在現在這個帳戶學到的記錄:離開之後建立或加入的另一個帳戶,收不到在之前的帳戶學到的 `keyslot`,
    /// 也收不到那裡同步來的私鑰。
    ///
    /// 帳戶裡之後出現同 id 的 `keyslot`,不會把記錄改記成那個帳戶:這台在新帳戶的 `device.slots` 列著留下來的插槽 id,新帳戶的成員可以發佈一個
    /// 同 id 的插槽,讓舊帳戶同步來的副本看起來像是新帳戶的。只有更換同步碼(`rotation::install_new_account`:更換的那台一定改記;重新加入的電腦,
    /// 新帳戶要接續舊帳戶的 space)把舊 chain 改記成新的。None = 不知道(這個欄位之前寫的狀態檔):當成「不是現在的帳戶」,不補寫。
    #[serde(default)]
    pub learned_in: Option<String>,
}

/// 插槽裡放的東西(SP3 spec §4.2)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SlotSource {
    /// 連到這台的一把金鑰:建立插槽的那台(`origin`)連到原檔,其他電腦連到使用者挑的那把。
    Linked { path: String, link: LinkKind, fingerprint: Option<String>, origin: bool },
    /// 同步來的私鑰(檔案就在插槽裡)。
    SyncedCopy { fingerprint: String },
}

/// 一個這台勾選的 space(spec §4.4)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceState {
    /// `spaces` 只保存勾選的 space,所以平常是 true;取消勾選做到一半(已移出 Include、檔案還沒刪掉)時是 false,
    /// 下一輪據此做完(spec §4.3 的順序)。
    pub selected: bool,
    /// `space_files::space_file_name` 產生的檔名;使用前以 `space_files::space_file_path` 驗證。
    pub file_name: String,
    pub cursor_seq: u64,
    /// 剛勾選後 false:第一輪以 space chain 為準(spec §7.2,同 v1 基線輪)。
    #[serde(default)]
    pub baseline_established: bool,
    /// host 的明文記錄,key = `record_key(Host, alias)`。
    #[serde(default)]
    pub records: BTreeMap<String, LocalRecord>,
    /// 等待本機核准的遠端記錄,key = alias(spec §7.4);同一 alias 的較新版本取代舊的。
    #[serde(default)]
    pub pending_approvals: BTreeMap<String, PendingApproval>,
    /// 只屬於這個 space 的錯誤(違反不變式、寫入失敗;spec §9):這個 space 暫停,其他照常。
    #[serde(default)]
    pub last_error: Option<String>,
    /// 使用者拒絕套用的遠端版本,key = alias(spec §7.4「拒絕」):不進快取、不寫檔,只記版本資訊。之後本機修改這台
    /// 主機時,新版本以它為基準(版本號、時間戳、base_seq)照 LWW 蓋過它;收到這個 alias 的較新遠端記錄就清掉。
    #[serde(default)]
    pub declined: BTreeMap<String, DeclinedVersion>,
    /// 只為了重新上傳才標成 dirty 的記錄 key(v1 升級帶進 space0 的已同步記錄,spec §7.6;relay 歷史倒退、整份重傳時原本
    /// 乾淨的記錄):它們輸給較新的遠端版本不是「本機修改被覆蓋」,不發 `sync://conflict`。上傳成功或被遠端取代就移出。
    #[serde(default)]
    pub republish: BTreeSet<String>,
    /// relay 回報這個 space 的 chain 不存在、帳戶卻仍有這個 space(spec §9):暫停,等使用者選「重建」或「刪除」。
    #[serde(default)]
    pub missing: bool,
    /// 改名被擋下時的目標檔名(spec §4.3、§9):每一輪都會重試改名,同一個目標仍被擋時不再重複提示(使用者可能已經
    /// 看過、關掉了);改名成功或不再需要改名就清掉。
    #[serde(default)]
    pub rename_blocked: Option<String>,
}

impl SpaceState {
    pub fn new(file_name: &str) -> Self {
        Self {
            selected: true,
            file_name: file_name.to_string(),
            cursor_seq: 0,
            baseline_established: false,
            records: BTreeMap::new(),
            pending_approvals: BTreeMap::new(),
            last_error: None,
            declined: BTreeMap::new(),
            republish: BTreeSet::new(),
            missing: false,
            rename_blocked: None,
        }
    }
}

/// 被拒絕的遠端版本(`SpaceState::declined`):本機之後的修改以它為基準。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeclinedVersion {
    pub version: u64,
    pub updated_at_ms: u64,
    /// 記錄在 relay 上的序號(下一次本機版本的 base_seq)。
    pub seq: u64,
}

/// 要讓使用者看到、看過才清掉的提示(`SyncStateV2::notices`;同時以 `sync://notice` 發出)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncNotice {
    /// v1 升級完成(spec §7.6、§8):space「Synced」可改名、其他電腦也要更新;含 `Include` 的區塊留在 `kept_file`;使用者自己放在
    /// `~/.ssh/sshelter/` 的檔案(v1 只有 `hosts.config` 那個 token 是我們的)改成本機檔案,新的完整路徑在 `moved_files`(通常是空的;
    /// 升級中斷後重跑時只列得出這一輪搬的)。`moved_files` 是後來加的欄位:讀舊版寫的狀態檔時缺欄位 = 空。
    Upgraded {
        kept_file: Option<String>,
        kept_hosts: Vec<String>,
        #[serde(default)]
        moved_files: Vec<String>,
    },
    /// 別台刪除了這台勾選的 space:檔案已備份並移除(spec §7.2)。
    SpaceDeleted { name: String, by_device: String },
    /// 改名時新檔名已有檔案:保留舊檔名、不覆蓋(spec §4.3、§9)。同一個目標只提示一次(`SpaceState::rename_blocked`)。
    RenameBlocked { space_id: String, name: String, file_name: String },
    /// 這台的 space 檔改成本機檔案(spec §7.3 離開帳戶;更換同步碼時新帳戶沒有接續的勾選 space 也一樣,§7.5):它們已搬到
    /// `~/.ssh/sshelter-local/`、主 config 以一般的 Include 引入,ssh 照常讀得到,不再同步;`kept_files` 是新的完整路徑。之後建立或
    /// 加入帳戶都不會再動它們,可以用搬移精靈搬進新帳戶的 space。
    LeftAccount { kept_files: Vec<String> },
    /// 這台完成了更換同步碼:請顯示並保存新同步碼(spec §7.5 第 7 步)。
    NewSyncCode,
    /// 另一台電腦也更換了同步碼(spec §7.5「兩台同時更換」)。
    OtherRotation { devices: Vec<String> },
    /// 這台同步的主機用到留在別台電腦的金鑰:請在這台挑一把(SP3 spec §6.7;每個插槽只提示一次)。
    KeysNeeded { names: Vec<String> },
}

/// `SyncStateV2::notices` 的讀法:逐則讀,這版不認得(較新版本寫的種類)或讀不懂的提示略過。狀態檔裡其他 enum 讀不懂就是
/// 整份讀不懂(檔案會被擱到一旁)—— 提示不值得這樣:從 beta 降回正式版之後,狀態檔仍要讀得回來。
fn known_notices<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<SyncNotice>, D::Error> {
    let raw = Vec::<serde_json::Value>::deserialize(deserializer)?;
    Ok(raw.into_iter().filter_map(|v| serde_json::from_value(v).ok()).collect())
}

/// 一筆保留未套用、等待核准的遠端記錄(spec §7.4)。不進 `SpaceState::records`,所以下一輪的本機 diff 不會把它
/// 當成本機修改推回去;核准時連同 `seq` 一起進 `records` 並寫檔,拒絕時丟棄。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingApproval {
    pub record: Record,
    /// 記錄在 relay 上的序號。
    pub seq: u64,
    /// 記錄的區塊文字(payload 的 `text`)。
    pub text: String,
    /// 目前已套用的本機區塊(沒有 → 空簽章)與新文字的簽章;UI 依此標出差異。
    pub applied: ApprovalSignature,
    pub incoming: ApprovalSignature,
    /// 寫入這筆記錄的裝置名稱;帳戶裡查不到時是它的 device id。
    pub from_device: String,
}

/// 這台偵測到的更換同步碼(spec §7.5)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FreezeInfo {
    pub detected_at_ms: u64,
    /// 帳戶 chain 上的更換標記(`meta` `rotation:*`)。只收到 push `409 frozen`、還沒拉到標記時是空的;兩個以上 =
    /// 多台電腦同時更換了同步碼。
    #[serde(default)]
    pub markers: Vec<RotationMarkerPayload>,
}

/// 最近一次 `GET /v1/info` 的結果(spec §6.4)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelayFeatures {
    /// 查的是哪個 relay URL:URL 改了就要重查。
    pub url: String,
    /// relay 回報的版本;None = 舊版 relay(沒有 `GET /v1/info`)。
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub features: Vec<String>,
    pub checked_at_ms: u64,
}

impl RelayFeatures {
    pub fn from_info(url: &str, info: &RelayInfo, checked_at_ms: u64) -> Self {
        Self { url: url.to_string(), version: info.version.clone(), features: info.features.clone(), checked_at_ms }
    }

    pub fn supports(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

/// 更換同步碼走到哪一步(spec §7.5 的編號)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum RotationStep {
    /// 第 1 步完成:新同步碼在 keychain(`NEXT_MNEMONIC_ACCOUNT`),每個 space 的新位置與金鑰在 `spaces`。可取消。
    Prepared,
    /// 第 2 步完成:這台的 dirty 記錄都已上傳。可取消。
    LocalChangesSent,
    /// 第 3 步:寫標記與凍結。**寫標記之前**就先存成這一步 —— 從這裡起其他電腦會被擋下,不能取消,只能做完。
    Freezing,
    /// 第 3 步完成:標記已寫入、舊帳戶與所有舊 space chain 已凍結。第 4、5 步(從 relay 取完整快照、建立與複製)。
    Copying,
    /// 第 5 步完成:新帳戶的記錄都已寫入。第 6 步刪除舊 space chain。
    Deleting,
    /// 第 6 步完成:第 7 步切換 keychain 與狀態。
    Switching,
}

/// 一個舊 space 在新帳戶的位置與金鑰。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RotatedSpace {
    /// 新 space 的 chain id(明文,用來寫 `previous_id` 與對照勾選)。
    pub new_space_id: String,
    /// 新 space 的 `spacekey` 記錄(id = 新 space id),以**新帳戶金鑰**加密(spec §7.5 第 1 步);第 5 步原樣上傳。
    pub sealed_key: SealedRecord,
}

/// 更換同步碼的進度(spec §7.5):可中斷、可接續。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RotationProgress {
    pub step: RotationStep,
    pub started_at_ms: u64,
    /// 新帳戶的 chain id(由 keychain 的新同步碼推導):接續時核對 keychain 裡的新碼屬於這次更換。
    pub new_account_chain_id: String,
    /// 舊 space id → 新位置與金鑰;帳戶內**每個** space 都有,含這台沒勾選的。
    #[serde(default)]
    pub spaces: BTreeMap<String, RotatedSpace>,
    /// 第 5 步已 `PUT` 的新 chain id(含新帳戶 chain)。
    #[serde(default)]
    pub created: BTreeSet<String>,
    /// 第 5 步記錄已全部複製到新 chain 的舊 space id。
    #[serde(default)]
    pub copied: BTreeSet<String>,
    /// 第 6 步已 `DELETE` 的舊 space id。
    #[serde(default)]
    pub deleted: BTreeSet<String>,
    /// 建立 chain 遇到 `429`(每 IP 每小時 20 次建立):暫停到這個時間再自動接續(spec §6.6、§7.5)。
    #[serde(default)]
    pub paused_until_ms: Option<u64>,
}

impl RotationProgress {
    pub fn new(new_account_chain_id: &str, started_at_ms: u64) -> Self {
        Self {
            step: RotationStep::Prepared,
            started_at_ms,
            new_account_chain_id: new_account_chain_id.to_string(),
            spaces: BTreeMap::new(),
            created: BTreeSet::new(),
            copied: BTreeSet::new(),
            deleted: BTreeSet::new(),
            paused_until_ms: None,
        }
    }

    /// 只能在第 3 步之前取消:還沒寫標記、沒凍結任何東西(spec §7.5)。
    pub fn cancellable(&self) -> bool {
        matches!(self.step, RotationStep::Prepared | RotationStep::LocalChangesSent)
    }
}

/// `load` 的結果。
#[derive(Debug)]
pub enum LoadedState {
    /// 檔案不存在。
    Missing,
    /// `version: 1`:v1 的狀態檔,以 v1 型別解析,交給 v1 升級(spec §7.6)。
    Legacy(Box<LegacyState>),
    Current(Box<SyncStateV2>),
}

fn unreadable(e: serde_json::Error) -> AppError {
    AppError::Other(format!("sync state is unreadable: {e}"))
}

/// 狀態檔的 `version`。只看這個欄位:新版的欄位不該讓整個反序列化失敗、給出誤導的訊息。
fn state_version(bytes: &[u8]) -> Result<u32, AppError> {
    #[derive(Deserialize)]
    struct Probe {
        version: u32,
    }
    serde_json::from_slice::<Probe>(bytes).map(|probe| probe.version).map_err(unreadable)
}

/// 讀 `sync-state.json`。錯誤分類沿用 v1 的(spec §4.4、v1 §6):讀不到
/// (I/O)→ `AppError::Io`(檔案留在原地、這個 session 不寫狀態);內容讀不懂、版本不認得或比本 app 新 →
/// `AppError::Other`(改名保留、之後照常存新狀態)。
pub fn load(path: &Path) -> Result<LoadedState, AppError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(LoadedState::Missing),
        Err(e) => return Err(AppError::Io(e)),
    };
    match state_version(&bytes)? {
        1 => serde_json::from_slice(&bytes).map(|s| LoadedState::Legacy(Box::new(s))).map_err(unreadable),
        STATE_VERSION_V2 => serde_json::from_slice(&bytes).map(|s| LoadedState::Current(Box::new(s))).map_err(unreadable),
        v if v > STATE_VERSION_V2 => Err(AppError::Other(format!(
            "sync state was written by a newer SSHelter (version {v}); update the app"
        ))),
        v => Err(AppError::Other(format!("sync state has an unknown version ({v})"))),
    }
}

/// 寫入狀態檔(0600)。明文的記錄區有祕密種類的記錄 → 錯誤,什麼都不寫(`refuse_plaintext_secrets`)。
pub fn save(path: &Path, state: &SyncStateV2) -> Result<(), AppError> {
    refuse_plaintext_secrets(state)?;
    if let Some(dir) = path.parent() {
        fsutil::ensure_dir_secure(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| AppError::Other(format!("cannot serialize sync state: {e}")))?;
    fsutil::atomic_write(path, &bytes, 0o600)
}

/// 狀態檔不含明文祕密(spec §3、§4.4):`spacekey`(與 v1 預留的 `key`、`password`,`RecordKind::is_secret`)只能以
/// `SealedRecord` 落地。明文的記錄區 —— 帳戶與每個 space 的 `records`、每一筆 `pending_approvals` —— 出現這類記錄一定是
/// bug:拒絕寫入,訊息只說種類,絕不帶 payload。
fn refuse_plaintext_secrets(state: &SyncStateV2) -> Result<(), AppError> {
    let account = state.account.iter().flat_map(|a| a.records.values().map(|local| &local.record));
    let spaces = state.spaces.values().flat_map(|space| {
        space.records.values().map(|local| &local.record).chain(space.pending_approvals.values().map(|p| &p.record))
    });
    match account.chain(spaces).find(|record| record.kind.is_secret()) {
        Some(record) => Err(AppError::Other(format!(
            "refusing to write a {} record into the sync state in plaintext",
            record.kind.as_str()
        ))),
        None => Ok(()),
    }
}

/// v1 升級第 5 步(spec §7.6):v1 狀態檔原樣複製成同目錄的 `sync-state.v1-backup.json`(0600),回傳檔名
/// (記在 `legacy_v1_backup`)。在 v2 狀態寫進 `state_path` 之前呼叫。來源不是 `version: 1`(例如已經寫成 v2)→ 錯誤、
/// 不寫備份:v1 的備份不能被別的東西蓋掉。
pub fn back_up_legacy(state_path: &Path) -> Result<String, AppError> {
    let bytes = std::fs::read(state_path)?;
    let version = state_version(&bytes)?;
    if version != 1 {
        return Err(AppError::Other(format!("refusing to back up a sync state that is not version 1 (version {version})")));
    }
    fsutil::atomic_write(&state_path.with_file_name(LEGACY_BACKUP_FILE), &bytes, 0o600)?;
    Ok(LEGACY_BACKUP_FILE.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::approval::signature;
    use crate::sync::record::{record_key, RecordKind, SpaceKeyPayload};
    use crate::sync::slot_rules::SlotMode;

    fn host(alias: &str, text: &str) -> Record {
        Record {
            kind: RecordKind::Host,
            id: alias.to_string(),
            version: 1,
            updated_at_ms: 10,
            device_id: "dev-b".to_string(),
            deleted: false,
            payload: serde_json::json!({ "schema": 1, "text": text }),
        }
    }

    fn spacekey_record(space: &ChainKeys) -> Record {
        Record {
            kind: RecordKind::SpaceKey,
            id: space.chain_id.clone(),
            version: 1,
            updated_at_ms: 10,
            device_id: "dev-a".to_string(),
            deleted: false,
            payload: serde_json::to_value(SpaceKeyPayload::from_keys(space)).unwrap(),
        }
    }

    /// 帳戶、space、待核准、更換同步碼、relay 功能都填上的狀態。每個欄位都不是預設值:來回存讀才驗得出漏存、改名或被
    /// 預設值蓋掉的欄位。
    fn full_state() -> SyncStateV2 {
        let account_keys = ChainKeys::generate().unwrap();
        let space_keys = ChainKeys::generate().unwrap();
        let mut s = SyncStateV2::fresh("MacBook").unwrap();
        s.relay_url = "https://relay.example.com".to_string();
        s.phrase_cleanup_pending = true;
        s.last_sync_ms = Some(42);
        s.last_error = Some("relay returned HTTP 500".to_string());
        s.notices = vec![
            SyncNotice::Upgraded {
                kept_file: Some("kept-3fa2c1d9.config".to_string()),
                kept_hosts: vec!["web".to_string()],
                moved_files: vec!["/Users/me/.ssh/sshelter-local/mine.config".to_string()],
            },
            SyncNotice::Upgraded { kept_file: None, kept_hosts: Vec::new(), moved_files: Vec::new() },
            SyncNotice::SpaceDeleted { name: "Work".to_string(), by_device: "MacBook-B".to_string() },
            SyncNotice::RenameBlocked {
                space_id: space_keys.chain_id.clone(),
                name: "Work".to_string(),
                file_name: "work-3fa2c1d9.config".to_string(),
            },
            SyncNotice::LeftAccount { kept_files: vec!["/Users/me/.ssh/sshelter-local/work.config".to_string()] },
            SyncNotice::NewSyncCode,
            SyncNotice::OtherRotation { devices: vec!["MacBook-B".to_string()] },
        ];
        let mut account = AccountState::new(&account_keys.chain_id);
        account.cursor_seq = 7;
        account.baseline_established = true;
        account.remote_schema_version = Some(2);
        account.frozen = Some(FreezeInfo {
            detected_at_ms: 11,
            markers: vec![RotationMarkerPayload { rotated_at_ms: 10, by_device_id: "dev-b".into(), by_device_name: "MacBook-B".into() }],
        });
        let space_record = Record {
            kind: RecordKind::Space,
            id: space_keys.chain_id.clone(),
            version: 3,
            updated_at_ms: 12,
            device_id: "dev-a".to_string(),
            deleted: false,
            payload: serde_json::json!({ "schema": 1, "name": "Work", "slug": "work", "created_at_ms": 5, "previous_id": null }),
        };
        account
            .records
            .insert(record_key(RecordKind::Space, &space_keys.chain_id), LocalRecord { record: space_record, seq: 6, dirty: true });
        let sealed = SealedRecord::seal(&account_keys, &spacekey_record(&space_keys), 0).unwrap();
        account.sealed.insert(sealed.key(), sealed);
        // 這台刪除、還沒 `DELETE` 的 space:tombstone 之前那份 `spacekey` 的密文(relay 序號 4)。
        let gone_keys = ChainKeys::generate().unwrap();
        account.chain_deletes.push(SealedRecord::seal(&account_keys, &spacekey_record(&gone_keys), 4).unwrap());
        s.account = Some(account);
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        space.selected = false;
        space.cursor_seq = 9;
        space.baseline_established = true;
        space.last_error = Some("the space file could not be read".to_string());
        space.declined.insert("db".to_string(), DeclinedVersion { version: 4, updated_at_ms: 800, seq: 9 });
        space.republish.insert(record_key(RecordKind::Host, "web"));
        space.missing = true;
        space.rename_blocked = Some("work-renamed-3fa2c1d9.config".to_string());
        let web = host("web", "Host web\n  HostName 10.0.0.1\n");
        space.records.insert(record_key(RecordKind::Host, "web"), LocalRecord { record: web, seq: 3, dirty: false });
        let incoming = "Host web\n  ProxyCommand nc %h 22\n";
        space.pending_approvals.insert(
            "web".to_string(),
            PendingApproval {
                record: host("web", incoming),
                seq: 4,
                text: incoming.to_string(),
                applied: signature("Host web\n  HostName 10.0.0.1\n"),
                incoming: signature(incoming),
                from_device: "MacBook-B".to_string(),
            },
        );
        s.spaces.insert(space_keys.chain_id.clone(), space);
        let mut rotation = RotationProgress::new(&"c".repeat(64), 100);
        rotation.step = RotationStep::Copying;
        rotation.spaces.insert(
            space_keys.chain_id.clone(),
            RotatedSpace { new_space_id: "d".repeat(64), sealed_key: SealedRecord::seal(&account_keys, &spacekey_record(&space_keys), 0).unwrap() },
        );
        rotation.created.insert("c".repeat(64));
        rotation.copied.insert(space_keys.chain_id.clone());
        rotation.deleted.insert("e".repeat(64));
        rotation.paused_until_ms = Some(3_600_000);
        s.rotation = Some(rotation);
        s.relay_features = Some(RelayFeatures {
            url: "https://relay.example.com".to_string(),
            version: Some("0.2.0".to_string()),
            features: vec!["pull-batch".to_string(), "freeze".to_string()],
            checked_at_ms: 50,
        });
        s.legacy_v1_backup = Some(LEGACY_BACKUP_FILE.to_string());
        // 兩種插槽來源都有,`LocalSlot` 的每個欄位在其中一筆裡都不是預設值(`parked` 只有連結的記錄用得到)。
        s.key_slots.insert(
            "3fa2c1d90123456789abcdef01234567".to_string(),
            LocalSlot {
                file_name: "id_mac-3fa2c1d9".to_string(),
                source: Some(SlotSource::SyncedCopy { fingerprint: "SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew".to_string() }),
                last_error: Some("The key this slot points to is gone: /home/f/.ssh/id_mac.".to_string()),
                asked: true,
                payload: Some(KeySlotPayload {
                    schema: 1,
                    name: "id_mac".to_string(),
                    mode: SlotMode::Own,
                    origin_device_id: "dev-a".to_string(),
                    created_at_ms: 5,
                    public_key: None,
                    fingerprint: None,
                    key_type: None,
                    has_passphrase: None,
                }),
                uploaded_fingerprint: Some("SHA256:vUthAmDZoxYXCTAPEZUn5qtWSMHWQCEcUfpnyM05mMs".to_string()),
                parked: false,
                learned_in: Some(account_keys.chain_id.clone()),
            },
        );
        s.key_slots.insert(
            "0123456789abcdef0123456789abcdef".to_string(),
            LocalSlot {
                file_name: "work-01234567".to_string(),
                source: Some(SlotSource::Linked {
                    path: "C:\\Users\\f\\.ssh\\work".to_string(),
                    link: LinkKind::HardLink,
                    fingerprint: Some("SHA256:vUthAmDZoxYXCTAPEZUn5qtWSMHWQCEcUfpnyM05mMs".to_string()),
                    origin: false,
                }),
                last_error: None,
                asked: false,
                payload: None,
                uploaded_fingerprint: None,
                parked: true,
                learned_in: None,
            },
        );
        s
    }

    #[test]
    fn fresh_state_is_version_2_and_not_joined() {
        let s = SyncStateV2::fresh("MacBook").unwrap();
        assert_eq!(s.version, 2);
        assert_eq!(s.device_id.len(), 32);
        assert_eq!(s.relay_url, DEFAULT_RELAY_URL);
        assert!(!s.joined() && !s.read_only() && s.frozen().is_none());
        assert!(s.spaces.is_empty() && s.rotation.is_none() && s.key_slots.is_empty());
        assert!(s.legacy_v1_backup.is_none() && s.relay_features.is_none() && !s.phrase_cleanup_pending);
        assert!(s.last_sync_ms.is_none() && s.last_error.is_none() && s.notices.is_empty());
        // 新勾選的 space:勾選中、從頭開始、第一輪以 chain 為準(基線)。
        let space = SpaceState::new("work-3fa2c1d9.config");
        assert_eq!((space.file_name.as_str(), space.cursor_seq), ("work-3fa2c1d9.config", 0));
        assert!(space.selected && !space.baseline_established && space.last_error.is_none());
        assert!(space.records.is_empty() && space.pending_approvals.is_empty());
        assert!(space.declined.is_empty() && space.republish.is_empty() && !space.missing && space.rename_blocked.is_none());
    }

    #[test]
    fn a_v2_state_round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let s = full_state();
        save(&path, &s).unwrap();
        match load(&path).unwrap() {
            LoadedState::Current(back) => assert_eq!(*back, s),
            other => panic!("expected a v2 state, got {other:?}"),
        }
    }

    /// SP3 之前寫的狀態檔沒有 `key_slots`,讀進來是空的;有 `key_slots` 的狀態檔照樣讀得回來。
    #[test]
    fn key_slots_default_to_empty_and_round_trip() {
        let mut state = SyncStateV2::fresh("MacBook").unwrap();
        let mut json = serde_json::to_value(&state).unwrap();
        json.as_object_mut().unwrap().remove("key_slots");
        let old: SyncStateV2 = serde_json::from_value(json).unwrap();
        assert!(old.key_slots.is_empty());

        state.key_slots.insert(
            "3fa2c1d90123456789abcdef01234567".into(),
            LocalSlot {
                file_name: "id_mac-3fa2c1d9".into(),
                source: Some(SlotSource::Linked {
                    path: "/home/f/.ssh/id_mac".into(),
                    link: crate::sync::slot_files::LinkKind::Symlink,
                    fingerprint: None,
                    origin: true,
                }),
                last_error: None,
                asked: false,
                payload: None,
                uploaded_fingerprint: Some("SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew".into()),
                parked: true,
                learned_in: Some("a".repeat(64)),
            },
        );
        let back: SyncStateV2 = serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
        assert_eq!(back.key_slots, state.key_slots);

        // 沒有 `uploaded_fingerprint` 的記錄(這個欄位之前寫的狀態檔)讀進來是 None:沒有人同意過上傳,不會補寫私鑰。沒有 `parked` 的
        // 記錄讀進來是 false:連結還在原位(收起來之前的版本不會收起連結)。沒有 `learned_in` 的記錄讀進來是 None:不知道是在哪個帳戶學到的,
        // 當成不是現在的帳戶(不補寫)。
        let mut json = serde_json::to_value(&state).unwrap();
        let entry = json["key_slots"]["3fa2c1d90123456789abcdef01234567"].as_object_mut().unwrap();
        entry.remove("uploaded_fingerprint");
        entry.remove("parked");
        entry.remove("learned_in");
        let older: SyncStateV2 = serde_json::from_value(json).unwrap();
        let older = &older.key_slots["3fa2c1d90123456789abcdef01234567"];
        assert_eq!((older.uploaded_fingerprint.as_deref(), older.parked, older.learned_in.as_deref()), (None, false, None));
    }

    #[test]
    fn notices_of_a_kind_this_version_does_not_know_are_skipped_not_fatal() {
        // 較新版本寫的提示種類(或讀不懂的一則):降版之後狀態檔照樣讀得回來,只略過那幾則。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let mut json = serde_json::to_value(SyncStateV2::fresh("A").unwrap()).unwrap();
        json["notices"] = serde_json::json!([
            { "kind": "from_a_newer_version", "detail": 1 },
            { "kind": "new_sync_code" },
            { "kind": "space_deleted", "name": "Work" }
        ]);
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        match load(&path).unwrap() {
            LoadedState::Current(back) => assert_eq!(back.notices, vec![SyncNotice::NewSyncCode]),
            other => panic!("expected a v2 state, got {other:?}"),
        }
    }

    #[test]
    fn an_upgraded_notice_written_before_moved_files_existed_still_loads() {
        // 舊版寫的 `upgraded` 提示沒有 `moved_files`:缺欄位 = 空,提示照樣讀得回來(讀不懂的提示會被整則略過,使用者就看不到升級說明了)。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let mut json = serde_json::to_value(SyncStateV2::fresh("A").unwrap()).unwrap();
        json["notices"] = serde_json::json!([
            { "kind": "upgraded", "kept_file": "/home/me/.ssh/sshelter-v1-kept.config", "kept_hosts": ["jump"] }
        ]);
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        match load(&path).unwrap() {
            LoadedState::Current(back) => assert_eq!(
                back.notices,
                vec![SyncNotice::Upgraded {
                    kept_file: Some("/home/me/.ssh/sshelter-v1-kept.config".to_string()),
                    kept_hosts: vec!["jump".to_string()],
                    moved_files: Vec::new(),
                }]
            ),
            other => panic!("expected a v2 state, got {other:?}"),
        }
    }

    #[test]
    fn a_v1_state_file_is_reported_as_legacy_not_parsed_into_v2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let mut v1 = crate::sync::state::SyncState::fresh("Box").unwrap();
        v1.chain_id = Some("ab".repeat(32));
        v1.cursor_seq = 9;
        std::fs::write(&path, serde_json::to_vec_pretty(&v1).unwrap()).unwrap();
        match load(&path).unwrap() {
            LoadedState::Legacy(back) => assert_eq!(*back, v1),
            other => panic!("expected the v1 state, got {other:?}"),
        }
    }

    #[test]
    fn missing_unreadable_and_newer_files_are_classified_like_v1() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(load(&dir.path().join("nope.json")).unwrap(), LoadedState::Missing));
        let path = dir.path().join("sync-state.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(load(&path), Err(AppError::Other(m)) if m.contains("unreadable")));
        std::fs::write(&path, br#"{"version": 2}"#).unwrap();
        assert!(matches!(load(&path), Err(AppError::Other(m)) if m.contains("unreadable")), "v2 without its fields");
        // 只有必要欄位的 v2 檔案(較舊的版本寫的;之後才加的欄位都不在):讀得回來,缺的欄位是預設值。
        let minimal = format!(
            r#"{{"version": 2, "device_id": "d", "device_name": "A", "relay_url": "https://relay.example.com",
                "account": {{"chain_id": "{a}", "cursor_seq": 3}},
                "spaces": {{"{b}": {{"selected": true, "file_name": "work-3fa2c1d9.config", "cursor_seq": 4}}}},
                "rotation": {{"step": "copying", "started_at_ms": 1, "new_account_chain_id": "{c}"}},
                "relay_features": {{"url": "https://relay.example.com", "checked_at_ms": 2}}}}"#,
            a = "a".repeat(64),
            b = "b".repeat(64),
            c = "c".repeat(64)
        );
        std::fs::write(&path, minimal).unwrap();
        let LoadedState::Current(s) = load(&path).unwrap() else { panic!("expected a v2 state") };
        assert!(!s.phrase_cleanup_pending && s.legacy_v1_backup.is_none() && s.last_sync_ms.is_none() && s.last_error.is_none());
        assert!(s.notices.is_empty());
        let account = s.account.as_ref().unwrap();
        assert_eq!(account.cursor_seq, 3);
        assert!(!account.baseline_established && account.remote_schema_version.is_none() && account.frozen.is_none());
        assert!(account.records.is_empty() && account.sealed.is_empty() && account.chain_deletes.is_empty());
        let space = &s.spaces["b".repeat(64).as_str()];
        assert!(space.selected && space.cursor_seq == 4 && !space.baseline_established && space.last_error.is_none());
        assert!(space.records.is_empty() && space.pending_approvals.is_empty());
        assert!(space.declined.is_empty() && space.republish.is_empty() && !space.missing && space.rename_blocked.is_none());
        let rotation = s.rotation.as_ref().unwrap();
        assert_eq!(rotation.step, RotationStep::Copying);
        assert!(rotation.spaces.is_empty() && rotation.created.is_empty() && rotation.copied.is_empty() && rotation.deleted.is_empty());
        assert!(rotation.paused_until_ms.is_none());
        let features = s.relay_features.as_ref().unwrap();
        assert!(features.version.is_none() && features.features.is_empty());
        std::fs::write(&path, br#"{"version": 3}"#).unwrap();
        assert!(matches!(load(&path), Err(AppError::Other(m)) if m.contains("newer")));
        std::fs::write(&path, br#"{"version": 0}"#).unwrap();
        assert!(matches!(load(&path), Err(AppError::Other(_))));
        // 讀不到(這裡是目錄):I/O 錯誤,呼叫端把檔案留在原地。
        assert!(matches!(load(dir.path()), Err(AppError::Io(_))));
    }

    #[test]
    fn space_keys_are_only_ever_stored_sealed() {
        let account = ChainKeys::generate().unwrap();
        let space = ChainKeys::generate().unwrap();
        let record = spacekey_record(&space);
        let sealed = SealedRecord::seal(&account, &record, 0).unwrap();
        assert!(sealed.dirty);
        assert_eq!(sealed.key(), sealed_key("spacekey", &crate::sync::crypto::id_hash(&account, "spacekey", &space.chain_id)));
        let mut s = SyncStateV2::fresh("A").unwrap();
        let mut section = AccountState::new(&account.chain_id);
        section.sealed.insert(sealed.key(), sealed.clone());
        s.account = Some(section);
        let text = serde_json::to_string(&s).unwrap();
        assert!(!text.contains(&space.auth_token), "the space token never reaches the state file");
        assert!(!text.contains(&space.enc_key_b64()), "the space key never reaches the state file");
        // 在記憶體解開;上傳的就是存著的密文,base_seq = envelope.seq。
        assert_eq!(sealed.open(&account).unwrap(), record);
        assert!(sealed.open(&space).is_err());
        let item = sealed.push_item();
        assert_eq!((item.ciphertext.as_str(), item.base_seq, item.kind.as_str()), (sealed.envelope.ciphertext.as_str(), 0, "spacekey"));
        assert_eq!(sealed_key("spacekey", "ab"), "spacekey:ab");
        // tombstone(刪除 space)以 relay 序號 5 封存:上傳項目就是存著的密文,kind、id_hash、nonce、deleted、base_seq 全對得上。
        let mut tombstone = spacekey_record(&space);
        tombstone.deleted = true;
        tombstone.version = 2;
        let gone = SealedRecord::seal(&account, &tombstone, 5).unwrap();
        assert!(gone.dirty);
        assert_eq!(gone.envelope.seq, 5);
        assert_eq!(
            gone.push_item(),
            PushItem {
                id_hash: crate::sync::crypto::id_hash(&account, "spacekey", &space.chain_id),
                kind: "spacekey".to_string(),
                nonce: gone.envelope.nonce.clone(),
                ciphertext: gone.envelope.ciphertext.clone(),
                deleted: true,
                base_seq: 5,
            }
        );
        assert_ne!(gone.envelope.nonce, sealed.envelope.nonce);
        assert_eq!(gone.open(&account).unwrap(), tombstone);
        // 明文的記錄區出現祕密種類(B3 的 bug):帳戶的 records、space 的 records、pending_approvals 都一樣 —— save 拒絕、
        // 什麼都不寫,訊息不帶 payload。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let plaintext = LocalRecord { record: record.clone(), seq: 1, dirty: true };
        let mut in_account = s.clone();
        in_account.account.as_mut().unwrap().records.insert(record_key(RecordKind::SpaceKey, &space.chain_id), plaintext.clone());
        let mut in_space = s.clone();
        let mut space_section = SpaceState::new("work-3fa2c1d9.config");
        space_section.records.insert(record_key(RecordKind::SpaceKey, &space.chain_id), plaintext);
        in_space.spaces.insert(space.chain_id.clone(), space_section);
        let mut pending = s.clone();
        let mut pending_section = SpaceState::new("work-3fa2c1d9.config");
        pending_section.pending_approvals.insert(
            "web".to_string(),
            PendingApproval {
                record: record.clone(),
                seq: 1,
                text: String::new(),
                applied: ApprovalSignature::default(),
                incoming: ApprovalSignature::default(),
                from_device: "MacBook-B".to_string(),
            },
        );
        pending.spaces.insert(space.chain_id.clone(), pending_section);
        let mut password = s.clone();
        let mut secret = host("web", "x");
        secret.kind = RecordKind::Password;
        password.account.as_mut().unwrap().records.insert(record_key(RecordKind::Password, "web"), LocalRecord { record: secret, seq: 1, dirty: false });
        for leak in [in_account, in_space, pending, password] {
            let error = save(&path, &leak).unwrap_err().to_string();
            assert!(error.contains("in plaintext"), "{error}");
            assert!(!error.contains(&space.auth_token) && !error.contains(&space.enc_key_b64()), "{error}");
            assert!(!path.exists(), "nothing was written");
        }
        save(&path, &s).unwrap();
    }

    #[test]
    fn read_only_and_frozen_follow_the_account_section() {
        let mut s = SyncStateV2::fresh("A").unwrap();
        s.account = Some(AccountState::new(&"a".repeat(64)));
        assert!(s.joined() && !s.read_only() && s.frozen().is_none());
        // 剛加入的帳戶:從頭開始、第一輪以 chain 為準、還沒有任何記錄。
        let joined = s.account.as_ref().unwrap();
        assert_eq!((joined.chain_id.as_str(), joined.cursor_seq), ("a".repeat(64).as_str(), 0));
        assert!(!joined.baseline_established && joined.remote_schema_version.is_none());
        assert!(joined.records.is_empty() && joined.sealed.is_empty() && joined.chain_deletes.is_empty());
        // 唯讀的界線:chain 上的格式版本比本 app 新才唯讀;一樣新或比較舊都照常。
        for (version, read_only) in [(ACCOUNT_SCHEMA_VERSION - 1, false), (ACCOUNT_SCHEMA_VERSION, false), (ACCOUNT_SCHEMA_VERSION + 1, true)] {
            s.account.as_mut().unwrap().remote_schema_version = Some(version);
            assert_eq!(s.read_only(), read_only, "remote schema version {version}");
        }
        let account = s.account.as_mut().unwrap();
        account.remote_schema_version = Some(ACCOUNT_SCHEMA_VERSION + 1);
        account.frozen = Some(FreezeInfo {
            detected_at_ms: 5,
            markers: vec![RotationMarkerPayload { rotated_at_ms: 4, by_device_id: "dev-b".into(), by_device_name: "MacBook-B".into() }],
        });
        assert!(s.read_only());
        assert_eq!(s.frozen().unwrap().markers[0].by_device_name, "MacBook-B");
    }

    #[test]
    fn relay_features_remember_which_relay_they_describe() {
        let info = RelayInfo { version: Some("0.2.0".into()), features: vec!["pull-batch".into(), "freeze".into()] };
        let f = RelayFeatures::from_info("https://relay.example.com", &info, 9);
        assert_eq!(f.url, "https://relay.example.com");
        assert_eq!((f.version.as_deref(), f.features.clone(), f.checked_at_ms), (Some("0.2.0"), info.features.clone(), 9));
        assert!(f.supports("freeze") && f.supports("pull-batch") && !f.supports("other"));
        // 只認完整的功能名稱,不是前綴。
        assert!(!f.supports("pull") && !f.supports("pull-batch-v2") && !f.supports(""));
        let old = RelayFeatures::from_info("https://old.example.com", &RelayInfo::default(), 9);
        assert_eq!(old.version, None);
        assert!(!old.supports("pull-batch"));
    }

    #[test]
    fn a_rotation_can_be_cancelled_only_before_anything_is_frozen() {
        let mut r = RotationProgress::new(&"c".repeat(64), 1);
        // 剛開始的更換:第 1 步,還沒建立、複製、刪除任何 chain,可以取消。
        assert_eq!((r.step, r.started_at_ms, r.new_account_chain_id.as_str()), (RotationStep::Prepared, 1, "c".repeat(64).as_str()));
        assert!(r.spaces.is_empty() && r.created.is_empty() && r.copied.is_empty() && r.deleted.is_empty());
        assert!(r.paused_until_ms.is_none() && r.cancellable());
        for (step, cancellable) in [
            (RotationStep::Prepared, true),
            (RotationStep::LocalChangesSent, true),
            (RotationStep::Freezing, false),
            (RotationStep::Copying, false),
            (RotationStep::Deleting, false),
            (RotationStep::Switching, false),
        ] {
            r.step = step;
            assert_eq!(r.cancellable(), cancellable, "{step:?}");
        }
        assert_eq!(serde_json::to_string(&RotationStep::LocalChangesSent).unwrap(), "\"local_changes_sent\"");
    }

    #[test]
    fn the_v1_backup_is_a_private_copy_next_to_the_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        std::fs::write(&path, br#"{"version": 1}"#).unwrap();
        assert_eq!(back_up_legacy(&path).unwrap(), LEGACY_BACKUP_FILE);
        // 檔名跨版本沿用(升級後的版本靠它找到備份),不能改。
        assert_eq!(LEGACY_BACKUP_FILE, "sync-state.v1-backup.json");
        let backup = dir.path().join(LEGACY_BACKUP_FILE);
        assert_eq!(std::fs::read(&backup).unwrap(), br#"{"version": 1}"#);
        // 來源不是 v1(已經寫成 v2、讀不懂):錯誤,原本的 v1 備份不被蓋掉。
        save(&path, &SyncStateV2::fresh("A").unwrap()).unwrap();
        assert!(back_up_legacy(&path).is_err());
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(back_up_legacy(&path).is_err());
        assert_eq!(std::fs::read(&backup).unwrap(), br#"{"version": 1}"#);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_state_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        save(&path, &SyncStateV2::fresh("A").unwrap()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn the_next_sync_code_has_its_own_keychain_entry() {
        assert_ne!(NEXT_MNEMONIC_ACCOUNT, crate::sync::state::MNEMONIC_ACCOUNT);
        // keychain 的 account 名稱跨版本沿用(中斷的更換靠它接續),不能改。
        assert_eq!(NEXT_MNEMONIC_ACCOUNT, "sync:mnemonic-next");
    }
}
