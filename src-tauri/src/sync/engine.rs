//! 同步引擎:背景執行緒 + 一輪的順序(spec §6)+ `SyncCore`(generation/狀態/金鑰同一把鎖)+ 存檔當下
//! 規劃本機編輯 + 在 doc 鎖內把 reconcile 的效果「套用 + 發布」成一個交易 + Tauri commands。
//! 網路與檔案的邊界:網路只在同步執行緒或 `spawn_blocking` 裡、不持有 doc/core;寫檔時才鎖 doc。
//! 鎖順序固定:lifecycle → doc → backed_up → core。

use std::cell::Cell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use crate::config::commands::{load_doc_migrated, persist_file};
use crate::config::model::Item;
use crate::config::serialize::serialize_items;
use crate::error::AppError;
use crate::fsutil::Fingerprint;
use crate::state::AppState;
use crate::sync::crypto::{self, ChainKeys};
use crate::sync::hosts_file::{self, HostBlockText};
use crate::sync::reconcile::{self, HostEffect};
use crate::sync::record::{record_key, DevicePayload, LocalRecord, MetaPayload, Record, RecordKind, SCHEMA_VERSION};
use crate::sync::relay::RelayClient;
use crate::sync::state::{self as sync_state, SyncState};

const SYNC_INTERVAL: Duration = Duration::from_secs(45);
const SUPERSEDED: &str = "sync round superseded by a newer chain state";
const READ_ONLY_MESSAGE: &str = "this sync chain uses a newer format; update SSHelter to keep syncing";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncDevice {
    pub id: String,
    pub name: String,
    pub platform: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub joined_at_ms: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub last_seen_ms: u64,
    pub is_this: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncStatus {
    pub joined: bool,
    /// chain id 前 8 個 hex,只作辨識用。
    pub chain_short: Option<String>,
    pub device_id: String,
    pub device_name: String,
    pub relay_url: String,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub last_sync_ms: Option<u64>,
    pub last_error: Option<String>,
    /// 尚未上傳的記錄數。
    #[cfg_attr(test, ts(type = "number"))]
    pub pending: u64,
    pub read_only: bool,
    pub devices: Vec<SyncDevice>,
    pub managed_file: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub hosts_in_sync: u64,
    /// Leave 之後助記詞還留在 keychain(刪除失敗):UI 顯示警示與重試。
    pub phrase_cleanup_pending: bool,
}

/// generation / 狀態 / 金鑰永遠一起快照、一起替換(spec §6):分開鎖會出現「新 generation + 舊狀態」。
/// `unsaved`:記憶體裡的狀態還沒成功寫進 `sync-state.json`(例如存檔 hook 寫狀態失敗)—— 下一輪在任何
/// 網路操作前先重存,失敗就停下(dirty 記錄必須先落盤,spec §6)。
pub struct SyncCore {
    pub generation: u64,
    pub state: Option<SyncState>,
    pub keys: Option<ChainKeys>,
    pub unsaved: bool,
}

/// Tauri 管理的同步執行期狀態。
pub struct SyncRuntime {
    pub core: Mutex<SyncCore>,
    /// Create/Join/Leave 與改 relay URL 全程互斥(含前置檢查、網路等待、keychain 讀寫;都在 spawn_blocking
    /// 裡):舊 Leave 不可能刪掉新 Join 剛存的助記詞,兩個 Join 不可能同時通過檢查,Join 驗證中途也換不掉
    /// 它驗證的 relay。
    lifecycle: Mutex<()>,
    syncing: AtomicBool,
}

impl Default for SyncRuntime {
    fn default() -> Self {
        Self {
            core: Mutex::new(SyncCore { generation: 0, state: None, keys: None, unsaved: false }),
            lifecycle: Mutex::new(()),
            syncing: AtomicBool::new(false),
        }
    }
}

thread_local! {
    static ENGINE_WRITING: Cell<bool> = const { Cell::new(false) };
}

/// 引擎自己套用遠端效果時寫受管檔:`persist_file` → `note_file_written` 不可把這次寫入當成本機編輯
/// (否則遠端內容會以「現在」的時間戳被當成本機修改重新上傳)。RAII:離開作用域(含 panic)就復原。
struct EngineWrite;

impl EngineWrite {
    fn begin() -> Self {
        ENGINE_WRITING.with(|w| w.set(true));
        EngineWrite
    }
}

impl Drop for EngineWrite {
    fn drop(&mut self) {
        ENGINE_WRITING.with(|w| w.set(false));
    }
}

fn engine_writing() -> bool {
    ENGINE_WRITING.with(|w| w.get())
}

/// 喚醒背景執行緒的通道;由 `persist_file` 與 commands 共用,故放全域。
static WAKER: OnceLock<Mutex<Option<Sender<()>>>> = OnceLock::new();

pub fn wake() {
    if let Some(slot) = WAKER.get() {
        if let Some(tx) = slot.lock().unwrap().as_ref() {
            let _ = tx.send(());
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn superseded() -> AppError {
    AppError::Other(SUPERSEDED.to_string())
}

/// 受管檔的不變式(spec §3.1/§6):只放具名、互不重複的 Host 區塊。違反時整輪停在讀檔階段(不 diff、
/// 不套用、不上傳),狀態列顯示要搬走/刪掉哪個區塊 —— 有了這個不變式,驗證過的遠端效果套用時不可能失敗。
pub fn check_managed_items(items: &[Item]) -> Result<(), AppError> {
    let mut seen = BTreeSet::new();
    for item in items {
        if let Item::Host(h) = item {
            if !hosts_file::is_syncable_block(&h.patterns) {
                return Err(AppError::Other(format!(
                    "the synced hosts file contains 'Host {}', which uses wildcard patterns; move that block to your main config",
                    h.patterns.join(" ")
                )));
            }
            if let Some(alias) = h.patterns.first() {
                if !seen.insert(alias.clone()) {
                    return Err(AppError::Other(format!(
                        "the synced hosts file defines '{alias}' more than once; remove the duplicate"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// 把 reconcile 的效果套到區塊列表。回傳(是否改了任何東西, 套不上的 alias);壞掉的效果不中斷其他效果。
pub fn apply_effects_to_items(items: &mut Vec<Item>, effects: &[HostEffect]) -> (bool, Vec<String>) {
    let mut changed = false;
    let mut failed = Vec::new();
    for effect in effects {
        let result = match effect {
            HostEffect::Upsert { alias, text } => hosts_file::apply_host_text(items, alias, text),
            HostEffect::Delete { alias } => Ok(hosts_file::remove_host_block(items, alias)),
        };
        match result {
            Ok(c) => changed |= c,
            Err(_) => failed.push(effect.alias().to_string()),
        }
    }
    (changed, failed)
}

pub fn status_from(state: &SyncState, managed_file: &str) -> SyncStatus {
    let devices = state
        .records
        .values()
        .filter(|l| l.record.kind == RecordKind::Device && !l.record.deleted)
        .filter_map(|l| {
            let p: DevicePayload = serde_json::from_value(l.record.payload.clone()).ok()?;
            Some(SyncDevice {
                id: l.record.id.clone(),
                name: p.name,
                platform: p.platform,
                joined_at_ms: p.joined_at_ms,
                last_seen_ms: p.last_seen_ms,
                is_this: l.record.id == state.device_id,
            })
        })
        .collect();
    SyncStatus {
        joined: state.joined(),
        chain_short: state.chain_id.as_ref().map(|c| c.chars().take(8).collect()),
        device_id: state.device_id.clone(),
        device_name: state.device_name.clone(),
        relay_url: state.relay_url.clone(),
        last_sync_ms: state.last_sync_ms,
        last_error: state.last_error.clone(),
        pending: state.records.values().filter(|l| l.dirty).count() as u64,
        read_only: state.read_only(),
        devices,
        managed_file: managed_file.to_string(),
        hosts_in_sync: state.records.values().filter(|l| l.record.kind == RecordKind::Host && !l.record.deleted).count() as u64,
        phrase_cleanup_pending: state.phrase_cleanup_pending,
    }
}

/// `persist_file` 只有路徑與 doc、沒有 AppHandle;`note_file_written` 靠它找到 SyncRuntime。只在 `initialize`
/// 設定 —— 單元測試裡沒有,存檔 hook 就什麼都不做。
static APP: OnceLock<AppHandle> = OnceLock::new();

fn managed_path() -> Result<PathBuf, AppError> {
    Ok(hosts_file::managed_path(&crate::keys::ssh_dir()?))
}

/// 持久化 core 裡的狀態(呼叫端已持有 core 鎖),並維護 `unsaved`:失敗時記下,下一輪在網路操作前先重存。
fn save_core(core: &mut SyncCore) -> Result<(), AppError> {
    let result = match core.state.as_ref() {
        Some(s) => sync_state::state_path().and_then(|path| sync_state::save(&path, s)),
        None => Ok(()),
    };
    core.unsaved = result.is_err();
    result
}

/// `persist_file` 寫完任何檔案後呼叫(呼叫端持有 doc 鎖,鎖順序 doc → core)。只處理受管同步檔:
/// app 的編輯在**存檔當下**就變成 dirty 記錄(時間戳 = 存檔時間),立刻持久化,並換 generation 讓在途
/// 輪次的舊快照作廢(spec §6)。引擎自己套用遠端效果的寫入(`EngineWrite`)不算本機編輯。未加入、
/// 基線輪還沒跑、或受管檔違反不變式時不規劃(交給同步輪次處理/顯示),但加入中一律換 generation。
pub fn note_file_written(path: &Path, items: &[Item]) {
    let Some(app) = APP.get() else { return };
    let Ok(ssh_dir) = crate::keys::ssh_dir() else { return };
    if path != hosts_file::managed_path(&ssh_dir) || engine_writing() {
        return;
    }
    {
        let state = app.state::<AppState>();
        let mut core = state.sync.core.lock().unwrap();
        let now = now_ms();
        let valid = check_managed_items(items).is_ok();
        let (joined, planned) = match core.state.as_mut() {
            Some(s) if s.joined() && s.baseline_established => {
                let planned = if valid {
                    reconcile::plan_local(s, &hosts_file::blocks_of(items), |_| now, now, std::env::consts::OS)
                } else {
                    0 // 違反不變式:不規劃,下一輪會停在驗證錯誤
                };
                (true, planned)
            }
            Some(s) => (s.joined(), 0),
            None => (false, 0),
        };
        // 加入中的任何受管檔 app 寫入都讓在途輪次的舊快照作廢 —— 包括把檔案改成違反不變式的寫入。
        if joined {
            core.generation += 1;
        }
        if planned > 0 {
            if let Err(e) = save_core(&mut core) {
                // SSH 檔已寫成功,只是同步狀態沒存下來:顯示在狀態列;`unsaved` 讓下一輪在任何網路操作前先重存。
                if let Some(s) = core.state.as_mut() {
                    s.last_error = Some(format!("sync state could not be saved after a local edit: {e}"));
                }
            }
        }
    }
    wake();
}

/// 確保受管檔存在、主 config 有 Include(置頂)、且 doc 已載入受管檔。回傳受管檔路徑。
fn ensure_managed_loaded(app: &AppHandle) -> Result<PathBuf, AppError> {
    let ssh_dir = crate::keys::ssh_dir()?;
    let managed = hosts_file::ensure_managed_file(&ssh_dir)?;
    let state = app.state::<AppState>();
    let mut doc_lock = state.doc.lock().unwrap();
    let mut backed_up = state.backed_up.lock().unwrap();
    let retention = *state.backup_retention.lock().unwrap();
    let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let main_path = doc.files[0].path.clone();
    if hosts_file::ensure_include(&mut doc.files[0].items) {
        persist_file(doc, 0, &mut backed_up, retention)?;
    }
    if !doc.files.iter().any(|f| f.path == managed) {
        *doc_lock = Some(load_doc_migrated(&main_path)?);
    }
    Ok(managed)
}

/// gather 的結果:區塊 + 當時的檔案指紋(套用前要再比一次)+ 檔案 mtime(外部編輯的時間戳)。
struct Gathered {
    blocks: Vec<HostBlockText>,
    fingerprint: Fingerprint,
    modified_ms: u64,
}

/// 取出受管檔目前的區塊並檢查不變式。磁碟若已被手改(指紋不同)先重載,避免用過期的 in-memory 內容。
fn gather_blocks(app: &AppHandle, managed: &Path) -> Result<Gathered, AppError> {
    let state = app.state::<AppState>();
    let mut doc_lock = state.doc.lock().unwrap();
    let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let idx = doc
        .files
        .iter()
        .position(|f| f.path == managed)
        .ok_or_else(|| AppError::Other("synced hosts file is not loaded".to_string()))?;
    if crate::fsutil::has_changed(managed, &doc.files[idx].fingerprint).unwrap_or(true) {
        let main_path = doc.files[0].path.clone();
        *doc_lock = Some(load_doc_migrated(&main_path)?);
    }
    let doc = doc_lock.as_ref().expect("just loaded");
    let idx = doc.files.iter().position(|f| f.path == managed).ok_or_else(|| AppError::Other("synced hosts file vanished".to_string()))?;
    let items = &doc.files[idx].items;
    check_managed_items(items)?;
    // 外部編輯的時間戳 = 檔案 mtime(整檔的近似值,spec §6 明示);拿不到就退回現在。
    let modified_ms = std::fs::metadata(managed)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or_else(now_ms);
    Ok(Gathered { blocks: hosts_file::blocks_of(items), fingerprint: doc.files[idx].fingerprint.clone(), modified_ms })
}

enum Applied {
    /// 效果已寫入(或沒有要寫的)、合併狀態已在記憶體發布;`wrote` = 真的寫了檔案;`save_error` = 狀態沒能寫進
    /// 磁碟(`unsaved` 已標記,下一輪網路前重存)。檔案已經改了,所以 tray 與通知照樣要做,呼叫端之後才停下。
    Committed { wrote: bool, save_error: Option<AppError> },
    /// 受管檔在 gather 之後變過(UI 存檔、外部編輯或 persist 的 Conflict):本輪作廢、立刻重跑。
    FileChanged,
}

/// 套用與發布是同一個交易(spec §6):全程持有 doc 鎖 —— 比 generation → 比指紋(不論有沒有效果,每次
/// 發布前都比)→ 在副本上套效果(全有或全無)→ 寫檔 → 發布合併狀態。所有會換 generation 的路徑都先拿
/// doc 鎖,所以這段不會被插隊,不會出現「檔案已寫入遠端內容、快取卻被拒絕」。tray 與事件都在**鎖放掉之後**
/// 才做:建立 tray menu 會同步等待主執行緒,持 doc 鎖呼叫會和主執行緒上等 doc 鎖的 command 互等(死鎖)。
fn apply_and_commit(
    app: &AppHandle,
    managed: &Path,
    generation: u64,
    gathered: &Fingerprint,
    effects: &[HostEffect],
    next: &SyncState,
) -> Result<Applied, AppError> {
    let state = app.state::<AppState>();
    let mut doc_lock = state.doc.lock().unwrap();
    if state.sync.core.lock().unwrap().generation != generation {
        return Err(superseded());
    }
    let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let idx = doc
        .files
        .iter()
        .position(|f| f.path == managed)
        .ok_or_else(|| AppError::Other("synced hosts file is not loaded".to_string()))?;
    // in-memory 指紋不同 = app 自己在網路期間存過檔;磁碟指紋不同 = 外部編輯。兩者都丟棄本輪 ——
    // 沒有效果要寫時也一樣(spec §6:發布前一律比對)。
    if doc.files[idx].fingerprint != *gathered
        || crate::fsutil::has_changed(managed, &doc.files[idx].fingerprint).unwrap_or(true)
    {
        return Ok(Applied::FileChanged);
    }
    let mut wrote = false;
    let mut tray: Option<Vec<String>> = None;
    if !effects.is_empty() {
        let mut items = doc.files[idx].items.clone();
        let (changed, failed) = apply_effects_to_items(&mut items, effects);
        if !failed.is_empty() {
            // 受管檔已通過不變式、遠端文字已通過 validate_host_text:走到這裡是 bug。全有或全無 ——
            // 什麼都不寫、不發布,cursor 不前進,錯誤顯示在狀態列,下一輪重試。(只報數量,不報主機名。)
            return Err(AppError::Other(format!(
                "{} synced host record(s) could not be applied; nothing was changed",
                failed.len()
            )));
        }
        if changed {
            let expected = serialize_items(&items, doc.files[idx].trailing_newline);
            let original = std::mem::replace(&mut doc.files[idx].items, items);
            let written = {
                let mut backed_up = state.backed_up.lock().unwrap();
                let retention = *state.backup_retention.lock().unwrap();
                let _engine = EngineWrite::begin(); // 這次寫入不是本機編輯
                persist_file(doc, idx, &mut backed_up, retention)
            };
            if let Err(e) = written {
                // 先退回舊區塊,再從磁碟重載讓兩邊一致。
                doc.files[idx].items = original;
                let main_path = doc.files[0].path.clone();
                match load_doc_migrated(&main_path) {
                    Ok(fresh) => *doc_lock = Some(fresh),
                    Err(reload) => {
                        // 重載也失敗:in-memory 不能再當真,整份作廢;放掉鎖後發 sync://applied,前端會重新載入。
                        *doc_lock = None;
                        drop(doc_lock);
                        let _ = app.emit("sync://applied", &0usize);
                        return Err(AppError::Other(format!("{e}; reloading the config afterwards also failed: {reload}")));
                    }
                }
                // 磁碟上是不是剛寫的內容?是 → 寫入其實已提交(例如 atomic_write 成功、只是讀指紋失敗),照常
                // 發布合併狀態 —— 否則下一輪會把已套用的遠端內容誤判成本機修改;否 → 沒寫進去,本輪作廢。
                let committed = std::fs::read_to_string(managed).map(|t| t == expected).unwrap_or(false);
                if !committed {
                    return match e {
                        AppError::Conflict(_) => Ok(Applied::FileChanged),
                        other => Err(other),
                    };
                }
            }
            wrote = true;
            tray = doc_lock.as_ref().map(crate::tray::tray_aliases);
        }
    }
    // 仍持有 doc 鎖:generation 在這段期間不可能變,再比一次當防線,然後發布合併狀態。記憶體裡的快取一定要
    // 跟著檔案走(否則下一輪會把已套用的遠端內容當成本機修改);存檔失敗只標 `unsaved`,不撤回發布。
    let save_error = {
        let mut core = state.sync.core.lock().unwrap();
        if core.generation != generation {
            return Err(superseded());
        }
        core.state = Some(next.clone());
        save_core(&mut core).err()
    };
    drop(doc_lock);
    if let Some(aliases) = tray {
        let _ = crate::tray::rebuild_tray(app, &aliases);
    }
    Ok(Applied::Committed { wrote, save_error })
}

fn save_state(app: &AppHandle) -> Result<(), AppError> {
    let state = app.state::<AppState>();
    let mut core = state.sync.core.lock().unwrap();
    save_core(&mut core)
}

/// 狀態在鎖內組好,放掉鎖之後才發事件(不在持鎖時呼叫任何 Tauri API)。
fn emit_status(app: &AppHandle) {
    let managed = managed_path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let status = {
        let state = app.state::<AppState>();
        let core = state.sync.core.lock().unwrap();
        core.state.as_ref().map(|s| status_from(s, &managed))
    };
    if let Some(status) = status {
        let _ = app.emit("sync://status", &status);
    }
}

/// 不寫檔的回寫(本機 diff、push 結果):generation 變了就丟棄,絕不覆蓋。
fn commit_state(app: &AppHandle, generation: u64, s: &SyncState) -> Result<(), AppError> {
    let state = app.state::<AppState>();
    let mut core = state.sync.core.lock().unwrap();
    if core.generation != generation {
        return Err(superseded());
    }
    core.state = Some(s.clone());
    save_core(&mut core)
}

/// 一輪(spec §6 的順序)。`generation`/`s`/`keys` 是 `sync_once` 在同一把 core 鎖內取得的快照(進來之前
/// 狀態已確定落盤:`sync_once` 會先補存 `unsaved`,補不成就不跑)。
/// 回 `SUPERSEDED` 表示被 lifecycle / 狀態命令 / 存檔當下的規劃搶先,不是錯誤。
fn run_round(app: &AppHandle, generation: u64, mut s: SyncState, keys: ChainKeys) -> Result<(), AppError> {
    let managed = ensure_managed_loaded(app)?;
    let gathered = gather_blocks(app, &managed)?; // 含受管檔不變式檢查
    let now = now_ms();
    let platform = std::env::consts::OS;
    let relay = RelayClient::new(&s.relay_url, &keys.auth_token)?;

    // 0. 基線輪(剛 Join):不做本機 diff,以 chain 為準套用 —— chain 上已 tombstone、本機同步檔卻還
    //    留著的區塊會被移除(先備份)。否則 Leave 後保留的舊區塊會以「現在」的時間戳復活遠端的刪除。
    //    成功後立刻再跑一輪,本機獨有的區塊才當外部編輯上傳。
    if !s.baseline_established {
        let merged = reconcile::pull_merge(&s, &keys, &relay)?;
        let mut next = merged.state;
        next.baseline_established = true;
        next.last_sync_ms = Some(now);
        next.last_error = next.read_only().then(|| READ_ONLY_MESSAGE.to_string());
        if let Applied::Committed { wrote, save_error } =
            apply_and_commit(app, &managed, generation, &gathered.fingerprint, &merged.host_effects, &next)?
        {
            if wrote {
                let _ = app.emit("sync://applied", &merged.host_effects.len());
            }
            if let Some(e) = save_error {
                return Err(e); // 狀態沒落盤:停下,下一輪先補存
            }
        }
        wake();
        return Ok(());
    }

    // 1. 外部編輯(app 的存檔已在存檔當下規劃過)→ dirty,時間戳 = 檔案 mtime(近似,spec §6)。
    let external_at = gathered.modified_ms.min(now);
    if reconcile::plan_local(&mut s, &gathered.blocks, |_| external_at, now, platform) > 0 {
        commit_state(app, generation, &s)?;
    }

    // 2. 網路:不持有任何鎖。
    let merged = reconcile::pull_merge(&s, &keys, &relay)?;

    // 3. 套用 + 發布(同一交易)。受管檔在網路期間變過 → 整輪丟棄(cursor 不前進),立刻重跑。
    let next = merged.state;
    match apply_and_commit(app, &managed, generation, &gathered.fingerprint, &merged.host_effects, &next)? {
        Applied::FileChanged => {
            wake();
            return Ok(());
        }
        Applied::Committed { wrote, save_error } => {
            if wrote {
                let _ = app.emit("sync://applied", &merged.host_effects.len());
            }
            if !merged.conflicts.is_empty() {
                let _ = app.emit("sync://conflict", &merged.conflicts);
            }
            if let Some(e) = save_error {
                return Err(e); // 不在未落盤的狀態上 push;下一輪先補存
            }
        }
    }
    s = next;

    // 4. 推送(唯讀模式內部略過)。部分成功也要持久化,所以先 commit 再看結果。被換代搶先時 push 結果
    //    會遺失 —— 下一輪自己的記錄以 KeepLocal 合併、更新 seq 後重送一次,結果一致(只是多傳一次)。
    let pushed = reconcile::push_dirty(&mut s, &keys, &relay);
    s.last_sync_ms = Some(now);
    if pushed.is_ok() {
        s.last_error = s.read_only().then(|| READ_ONLY_MESSAGE.to_string());
    }
    commit_state(app, generation, &s)?;
    if pushed?.conflicts > 0 {
        wake(); // 下一輪 pull 會拿到中繼版本再合併。
    }
    Ok(())
}

/// 一輪同步。錯誤寫進 last_error 並發事件,永不 panic;被搶先(SUPERSEDED)不算錯誤。
pub fn sync_once(app: &AppHandle) -> Result<(), AppError> {
    let state = app.state::<AppState>();
    if state.sync.syncing.swap(true, Ordering::SeqCst) {
        return Ok(()); // 已在同步中
    }
    // 先補存上次沒寫進磁碟的狀態 —— 不論是否加入中(例如 Leave 或未加入時改設定的存檔失敗)。
    // 然後 generation / 狀態 / 金鑰一次快照(同一把鎖):不可能拿到「新 generation + 舊狀態」。
    let (snapshot, save_error) = {
        let mut core = state.sync.core.lock().unwrap();
        let save_error = if core.unsaved { save_core(&mut core).err() } else { None };
        let snapshot = match (core.state.as_ref(), core.keys.as_ref()) {
            (Some(s), Some(k)) if s.joined() => Some((core.generation, s.clone(), k.clone())),
            _ => None,
        };
        (snapshot, save_error)
    };
    let result = match (snapshot, save_error) {
        // 狀態還寫不進磁碟:不在未落盤的狀態上做任何網路操作(spec §6)。
        (Some((generation, _, _)), Some(e)) => Err((generation, e)),
        (Some((generation, s, keys)), None) => run_round(app, generation, s, keys).map_err(|e| (generation, e)),
        (None, _) => Ok(()),
    };
    state.sync.syncing.store(false, Ordering::SeqCst);
    let outcome = match result {
        Ok(()) => Ok(()),
        Err((_, AppError::Other(m))) if m == SUPERSEDED => Ok(()),
        Err((generation, e)) => {
            // 錯誤只記在產生它的那一代狀態上:舊 chain 的逾時不能寫進新 chain(spec §6)。
            let mut core = state.sync.core.lock().unwrap();
            if core.generation == generation {
                if let Some(s) = core.state.as_mut() {
                    s.last_error = Some(e.to_string());
                }
                let _ = save_core(&mut core);
            }
            Err(e)
        }
    };
    emit_status(app);
    outcome
}

fn worker_loop(app: AppHandle, rx: Receiver<()>) {
    loop {
        match rx.recv_timeout(SYNC_INTERVAL) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {
                let _ = sync_once(&app);
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// 啟動:載入狀態與助記詞,派生金鑰,開背景執行緒。狀態損毀不阻擋 app 啟動。
pub fn initialize(app: &AppHandle) -> Result<(), AppError> {
    let _ = APP.set(app.clone());
    let state = app.state::<AppState>();
    let mut loaded = match sync_state::state_path().and_then(|p| sync_state::load(&p)) {
        Ok(Some(s)) => s,
        Ok(None) => SyncState::fresh(&default_device_name())?,
        Err(e) => {
            let mut s = SyncState::fresh(&default_device_name())?;
            s.last_error = Some(e.to_string());
            s
        }
    };
    let mut keys = None;
    if loaded.joined() {
        match sync_state::load_mnemonic() {
            Ok(Some(words)) => keys = crypto::derive_keys(&words).ok(),
            _ => loaded.last_error = Some("recovery phrase is missing from the keychain; leave and rejoin the chain".to_string()),
        }
    }
    {
        let mut core = state.sync.core.lock().unwrap();
        core.state = Some(loaded);
        core.keys = keys;
    }
    let (tx, rx) = mpsc::channel();
    *WAKER.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(tx);
    let handle = app.clone();
    std::thread::Builder::new()
        .name("sshelter-sync".into())
        .spawn(move || worker_loop(handle, rx))
        .map_err(AppError::Io)?;
    wake();
    Ok(())
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("SSHelter on {}", std::env::consts::OS))
}

fn with_state<T>(app: &AppHandle, f: impl FnOnce(&mut SyncState) -> Result<T, AppError>) -> Result<T, AppError> {
    let state = app.state::<AppState>();
    let mut core = state.sync.core.lock().unwrap();
    let s = core.state.as_mut().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    f(s)
}

/// 只動狀態的命令:先拿 doc 鎖(與 apply_and_commit 的交易互斥,順序 doc → core),在同一個 core 臨界區
/// 「換 generation + 改狀態 + 持久化」。在途輪次的整份狀態副本會因 generation 不同而被丟棄。
fn mutate_state<T>(app: &AppHandle, f: impl FnOnce(&mut SyncState) -> Result<T, AppError>) -> Result<T, AppError> {
    let state = app.state::<AppState>();
    let _doc = state.doc.lock().unwrap();
    let mut core = state.sync.core.lock().unwrap();
    core.generation += 1;
    let out = {
        let s = core.state.as_mut().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        f(s)?
    };
    save_core(&mut core)?;
    Ok(out)
}

fn current_status(app: &AppHandle) -> Result<SyncStatus, AppError> {
    let managed = managed_path()?.to_string_lossy().into_owned();
    with_state(app, |s| Ok(status_from(s, &managed)))
}

/// spawn_blocking 的 JoinHandle 錯誤(執行緒被取消等)→ AppError。
fn join_error(e: tauri::Error) -> AppError {
    AppError::Other(format!("sync task failed: {e}"))
}

#[derive(Clone, Copy)]
enum ChainEntry {
    Create,
    Join,
}

/// 建立或加入 chain 的共同流程。**呼叫端已持有 lifecycle 鎖**(全程,含網路與 keychain)。
/// 驗證/建立 → 存助記詞 → 在 doc 鎖內、同一個 core 臨界區換 generation/狀態/金鑰 → 準備受管檔 → 喚醒。
fn enter_chain(app: &AppHandle, words: &str, device_name: &str, mode: ChainEntry) -> Result<SyncStatus, AppError> {
    let keys = crypto::derive_keys(words)?;
    let relay_url = with_state(app, |s| Ok(s.relay_url.clone()))?;
    let relay = RelayClient::new(&relay_url, &keys.auth_token)?;
    match mode {
        // 只有 Create 用 PUT(冪等建立)。
        ChainEntry::Create => relay.create_chain(&keys.chain_id)?,
        // Join 只驗證:404 = 這組助記詞沒有對應的 chain。絕不 PUT —— 否則任何 checksum 正確的
        // 助記詞都會靜靜建出一條新 chain,而不是回報錯誤。
        ChainEntry::Join => {
            relay.pull(&keys.chain_id, 0).map_err(|e| match e {
                AppError::NotFound(_) => AppError::NotFound(
                    "no sync chain matches this recovery phrase (check the words and the relay URL)".to_string(),
                ),
                other => other,
            })?;
        }
    }
    sync_state::store_mnemonic(words)?;
    let now = now_ms();
    let state = app.state::<AppState>();
    {
        // doc 鎖:與 apply_and_commit 的交易互斥;core 鎖:generation/狀態/金鑰一次換掉(spec §6)。
        let _doc = state.doc.lock().unwrap();
        let mut core = state.sync.core.lock().unwrap();
        core.generation += 1;
        let s = core.state.as_mut().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        s.chain_id = Some(keys.chain_id.clone());
        s.device_name = device_name.trim().to_string();
        s.cursor_seq = 0;
        s.records.clear();
        s.sealed.clear();
        s.remote_schema_version = None;
        // Create 的 chain 是空的,基線輪沒有意義;Join 要先以 chain 為準(spec §6 基線輪)。
        s.baseline_established = matches!(mode, ChainEntry::Create);
        s.phrase_cleanup_pending = false;
        s.last_sync_ms = None;
        s.last_error = None;
        let me = reconcile::own_device_record(s, now, std::env::consts::OS);
        s.records.insert(record_key(RecordKind::Device, &s.device_id), LocalRecord { record: me, seq: 0, dirty: true });
        if matches!(mode, ChainEntry::Create) {
            let meta = Record {
                kind: RecordKind::Meta,
                id: "chain".to_string(),
                version: 1,
                updated_at_ms: now,
                device_id: s.device_id.clone(),
                deleted: false,
                payload: serde_json::to_value(MetaPayload {
                    schema_version: SCHEMA_VERSION,
                    created_by_app_version: env!("CARGO_PKG_VERSION").to_string(),
                })
                .expect("MetaPayload serializes"),
            };
            s.records.insert(record_key(RecordKind::Meta, "chain"), LocalRecord { record: meta, seq: 0, dirty: true });
        }
        core.keys = Some(keys);
        save_core(&mut core)?;
    }
    ensure_managed_loaded(app)?;
    wake();
    current_status(app)
}

/// 離開 chain。**呼叫端已持有 lifecycle 鎖**。先作廢在途輪次並清掉 chain 狀態(確保停止同步),再刪
/// keychain;keychain 刪不掉要回報並持久化重試旗標,不得宣稱已清乾淨。未加入時只做 keychain 重試。
fn leave_chain(app: &AppHandle, delete_remote: bool) -> Result<SyncStatus, AppError> {
    let state = app.state::<AppState>();
    let (joined, chain, keys, relay_url) = {
        let core = state.sync.core.lock().unwrap();
        let s = core.state.as_ref();
        (
            s.is_some_and(|s| s.joined()),
            s.and_then(|s| s.chain_id.clone()),
            core.keys.clone(),
            s.map(|s| s.relay_url.clone()).unwrap_or_default(),
        )
    };
    if joined {
        if delete_remote {
            if let (Some(chain), Some(keys)) = (chain, keys) {
                RelayClient::new(&relay_url, &keys.auth_token)?.delete_chain(&chain)?;
            }
        }
        // doc 鎖內、同一個 core 臨界區:在途的舊輪次不可能再寫檔、也不可能把已離開的 chain 放回來。
        let _doc = state.doc.lock().unwrap();
        let mut core = state.sync.core.lock().unwrap();
        core.generation += 1;
        core.keys = None;
        if let Some(s) = core.state.as_mut() {
            s.chain_id = None;
            s.cursor_seq = 0;
            s.records.clear();
            s.sealed.clear();
            s.remote_schema_version = None;
            s.baseline_established = false;
            s.last_sync_ms = None;
            s.last_error = None;
        }
        // 寫檔失敗也不中止:下面照樣清 keychain —— 重啟時就算磁碟上的舊狀態還是 joined,沒有助記詞就派生不出
        // 金鑰、不會恢復同步;`unsaved` 讓 worker 在儲存恢復後補寫「已離開」。錯誤在最後回報。
        let _ = save_core(&mut core);
    }
    // keychain 清理(仍在 lifecycle 鎖內:新 Join 不可能穿插)。結果持久化,重啟後警示與重試入口仍在。
    let cleared = sync_state::clear_mnemonic();
    with_state(app, |s| {
        s.phrase_cleanup_pending = cleared.is_err();
        Ok(())
    })?;
    let saved = save_state(app);
    emit_status(app);
    if let Err(e) = cleared {
        return Err(AppError::Other(format!(
            "left the sync chain, but the recovery phrase could not be removed from the keychain ({e}); use \"Remove phrase\" to retry"
        )));
    }
    if let Err(e) = saved {
        return Err(AppError::Other(format!(
            "left the sync chain, but the sync state could not be saved ({e}); it will be retried automatically"
        )));
    }
    current_status(app)
}

#[tauri::command]
pub fn sync_status(app: AppHandle) -> Result<SyncStatus, AppError> {
    current_status(&app)
}

/// 網路在 spawn_blocking 裡(`reqwest::blocking` 不能在 tokio runtime 內呼叫);lifecycle 鎖涵蓋前置檢查。
#[tauri::command]
pub async fn sync_create_chain(app: AppHandle, device_name: String) -> Result<String, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        let _lifecycle = state.sync.lifecycle.lock().unwrap();
        if with_state(&handle, |s| Ok(s.joined()))? {
            return Err(AppError::Other("already in a sync chain; leave it first".to_string()));
        }
        let words = crypto::generate_mnemonic()?;
        enter_chain(&handle, &words, &device_name, ChainEntry::Create)?;
        Ok(words)
    })
    .await
    .map_err(join_error)?
}

#[tauri::command]
pub async fn sync_join_chain(app: AppHandle, words: String, device_name: String) -> Result<SyncStatus, AppError> {
    let normalized = crypto::normalize_mnemonic(&words)?;
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        let _lifecycle = state.sync.lifecycle.lock().unwrap();
        if with_state(&handle, |s| Ok(s.joined()))? {
            return Err(AppError::Other("already in a sync chain; leave it first".to_string()));
        }
        enter_chain(&handle, &normalized, &device_name, ChainEntry::Join)
    })
    .await
    .map_err(join_error)?
}

/// keychain 讀取在 spawn_blocking 裡:同步 command 跑在主執行緒上,不在那裡做可能卡住的 I/O。
#[tauri::command]
pub async fn sync_show_words(app: AppHandle) -> Result<String, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if !with_state(&handle, |s| Ok(s.joined()))? {
            return Err(AppError::Other("not in a sync chain".to_string()));
        }
        sync_state::load_mnemonic()?.ok_or_else(|| AppError::Other("recovery phrase is not in the keychain".to_string()))
    })
    .await
    .map_err(join_error)?
}

#[tauri::command]
pub async fn sync_leave_chain(app: AppHandle, delete_remote: bool) -> Result<SyncStatus, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        let _lifecycle = state.sync.lifecycle.lock().unwrap();
        leave_chain(&handle, delete_remote)
    })
    .await
    .map_err(join_error)?
}

#[tauri::command]
pub fn sync_now(app: AppHandle) -> Result<(), AppError> {
    wake();
    let _ = app;
    Ok(())
}

/// relay URL 只能在未加入時更改(spec §6):cursor 與每筆 seq 都屬於某一個 relay。持 lifecycle 鎖,Join
/// 驗證中途換不掉它驗證的 relay;鎖可能要等一段網路時間,所以在 spawn_blocking 裡。
#[tauri::command]
pub async fn sync_set_relay_url(app: AppHandle, url: String) -> Result<SyncStatus, AppError> {
    let normalized = RelayClient::validate_url(&url)?; // 純驗證,不建 client
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        let _lifecycle = state.sync.lifecycle.lock().unwrap();
        mutate_state(&handle, |s| {
            if s.joined() {
                return Err(AppError::Other(
                    "leave the sync chain before switching relays, then create or join on the new relay".to_string(),
                ));
            }
            s.relay_url = normalized;
            s.last_error = None;
            Ok(())
        })?;
        current_status(&handle)
    })
    .await
    .map_err(join_error)?
}

/// `mutate_state` 會等 doc 鎖並寫磁碟:放進 spawn_blocking,不在主執行緒上等鎖(spec §6)。
#[tauri::command]
pub async fn sync_set_device_name(app: AppHandle, name: String) -> Result<SyncStatus, AppError> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::Other("device name cannot be empty".to_string()));
    }
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let now = now_ms();
        mutate_state(&handle, |s| {
            s.device_name = name;
            if s.joined() {
                let me = reconcile::own_device_record(s, now, std::env::consts::OS);
                let key = record_key(RecordKind::Device, &s.device_id);
                let seq = s.records.get(&key).map(|l| l.seq).unwrap_or(0);
                s.records.insert(key, LocalRecord { record: me, seq, dirty: true });
            }
            Ok(())
        })?;
        wake();
        current_status(&handle)
    })
    .await
    .map_err(join_error)?
}

/// 只把裝置從清單移除(tombstone 它的 device 記錄)。**不是撤權**:它若還有助記詞就會繼續同步
/// (spec §2);UI 文案必須如此說明。
#[tauri::command]
pub async fn sync_forget_device(app: AppHandle, device_id: String) -> Result<SyncStatus, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let now = now_ms();
        mutate_state(&handle, |s| {
            if device_id == s.device_id {
                return Err(AppError::Other("use Leave chain to remove this device".to_string()));
            }
            let key = record_key(RecordKind::Device, &device_id);
            let Some(local) = s.records.get(&key).cloned() else {
                return Err(AppError::NotFound(format!("device {device_id} is not in this chain")));
            };
            let mut record = local.record;
            record.version += 1;
            record.updated_at_ms = crate::sync::planner::next_timestamp(now, Some(record.updated_at_ms));
            record.device_id = s.device_id.clone();
            record.deleted = true;
            s.records.insert(key, LocalRecord { record, seq: local.seq, dirty: true });
            Ok(())
        })?;
        wake();
        current_status(&handle)
    })
    .await
    .map_err(join_error)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::parse_file;

    #[test]
    fn effects_are_applied_in_order_and_report_whether_anything_changed() {
        let (mut items, _) = parse_file("Host a\n  User x\n\nHost b\n");
        let effects = vec![
            HostEffect::Upsert { alias: "a".into(), text: "Host a\n  User y\n\n".into() },
            HostEffect::Delete { alias: "b".into() },
            HostEffect::Upsert { alias: "c".into(), text: "Host c\n".into() },
        ];
        let (changed, failed) = apply_effects_to_items(&mut items, &effects);
        assert!(changed);
        assert!(failed.is_empty());
        assert_eq!(serialize_items(&items, true), "Host a\n  User y\n\nHost c\n");
        assert_eq!(apply_effects_to_items(&mut items, &[]), (false, Vec::new()));
    }

    #[test]
    fn a_broken_effect_does_not_stop_the_others_and_is_reported_by_alias() {
        // 純函式的回報語意;引擎本身把任何失敗當成全有或全無的中止(見 apply_and_commit)。
        let (mut items, _) = parse_file("Host a\nHost web *.internal\n  User ops\n");
        let effects = vec![
            HostEffect::Upsert { alias: "web".into(), text: "Host web\n  User root\n".into() },
            HostEffect::Upsert { alias: "bad".into(), text: "# not a host\n".into() },
            HostEffect::Upsert { alias: "ok".into(), text: "Host ok\n".into() },
        ];
        let (changed, failed) = apply_effects_to_items(&mut items, &effects);
        assert!(changed);
        assert_eq!(failed, vec!["web".to_string(), "bad".to_string()]);
        let text = serialize_items(&items, true);
        assert!(text.contains("Host ok"));
        assert!(text.contains("Host web *.internal\n  User ops\n"), "local wildcard block untouched");
        assert!(!text.contains("User root"));
    }

    #[test]
    fn managed_file_must_hold_only_named_unique_hosts() {
        let ok = parse_file("# synced\n\nHost a\n  User x\nHost b b.example.com\n").0;
        assert!(check_managed_items(&ok).is_ok());
        let wildcard = parse_file("Host a\nHost web *.internal\n").0;
        assert!(check_managed_items(&wildcard).unwrap_err().to_string().contains("wildcard"));
        let negated = parse_file("Host web !prod\n").0;
        assert!(check_managed_items(&negated).is_err());
        let dup = parse_file("Host a\n  User x\nHost a\n").0;
        assert!(check_managed_items(&dup).unwrap_err().to_string().contains("more than once"));
    }

    #[test]
    fn engine_writes_are_flagged_only_inside_the_guard() {
        assert!(!engine_writing());
        {
            let _write = EngineWrite::begin();
            assert!(engine_writing());
        }
        assert!(!engine_writing());
    }

    #[test]
    fn status_reflects_state_without_a_chain() {
        let mut s = SyncState::fresh("Box").unwrap();
        s.phrase_cleanup_pending = true; // Leave 時 keychain 刪不掉:持久化在狀態裡
        let status = status_from(&s, "/tmp/hosts.config");
        assert!(!status.joined);
        assert_eq!(status.device_name, "Box");
        assert_eq!(status.pending, 0);
        assert!(status.devices.is_empty());
        assert!(status.phrase_cleanup_pending);
        assert!(!status.read_only);
    }

    #[test]
    fn status_lists_devices_pending_counts_and_read_only() {
        let mut s = SyncState::fresh("Box").unwrap();
        s.chain_id = Some("ab".repeat(32));
        s.remote_schema_version = Some(SCHEMA_VERSION + 1);
        let me = reconcile::own_device_record(&s, 5, "macos");
        s.records.insert(record_key(RecordKind::Device, &s.device_id), LocalRecord { record: me, seq: 1, dirty: true });
        let host = Record {
            kind: RecordKind::Host,
            id: "web".into(),
            version: 1,
            updated_at_ms: 5,
            device_id: s.device_id.clone(),
            deleted: false,
            payload: serde_json::json!({ "schema": 1, "text": "Host web\n" }),
        };
        s.records.insert(record_key(RecordKind::Host, "web"), LocalRecord { record: host, seq: 0, dirty: true });
        let status = status_from(&s, "/tmp/hosts.config");
        assert!(status.joined);
        assert_eq!(status.chain_short.as_deref(), Some("abababab"));
        assert_eq!(status.pending, 2);
        assert_eq!(status.hosts_in_sync, 1);
        assert_eq!(status.devices.len(), 1);
        assert!(status.devices[0].is_this);
        assert!(status.read_only);
        assert!(!status.phrase_cleanup_pending);
    }
}
