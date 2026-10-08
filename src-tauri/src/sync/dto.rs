//! Sync v2 給前端的資料形狀(ts-rs 匯出到 `src/bindings/`):事件 payload、Settings → Sync 的狀態(`SyncOverview`)
//! 與待核准清單。u64 一律以 `number` 匯出。狀態從 core 的快照組出,不持有任何鎖做 I/O。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::sync::approval::ApprovalSignature;
use crate::sync::env::SyncEnv;
use crate::sync::files::space_path;
use crate::sync::hosts_file::blocks_of;
use crate::sync::merge::{devices, space_deleted_by, space_entries};
use crate::sync::record::RecordKind;
use crate::sync::relay::{FEATURE_FREEZE, FEATURE_PULL_BATCH};
use crate::sync::space_files::stray_space_files;
use crate::sync::spaces::review_digest;
use crate::sync::state_v2::{RotationStep, SyncNotice};

/// `sync://conflict` 的一項(spec §7.1 第 8 步):這台未上傳的修改被別台較新的版本取代。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncConflict {
    pub space_id: String,
    pub space_name: String,
    pub aliases: Vec<String>,
}

/// `sync://approval` 的一項(spec §7.4):這一輪新保留、等待核准的主機。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ApprovalNotice {
    pub space_id: String,
    pub space_name: String,
    pub aliases: Vec<String>,
}

/// 最近一次 `GET /v1/info`(spec §6.4、§8)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncRelayView {
    pub url: String,
    /// relay 回報的版本;None = 舊版 relay(沒有 `GET /v1/info`)。
    pub version: Option<String>,
    /// 有批次查詢;false → 逐條查詢,UI 提示「relay 可以更新」。
    pub batch_pull: bool,
    /// 有凍結;false → 「更換同步碼」停用並說明要先更新 relay。
    pub freeze: bool,
}

/// 這台偵測到同步碼已被更換(spec §7.5):請使用者輸入新同步碼。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncFrozenView {
    #[cfg_attr(test, ts(type = "number"))]
    pub detected_at_ms: u64,
    /// 更換了同步碼的裝置名稱;空 = 還只知道 relay 拒絕了上傳。兩個以上 = 多台同時更換,輸入其中一組即可。
    pub by_devices: Vec<String>,
}

/// 這台正在更換同步碼(spec §7.5)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncRotationView {
    pub step: RotationStep,
    /// 只有第 3 步(凍結)之前可以取消。
    pub cancellable: bool,
    /// 建立 chain 被限流:暫停到這個時間後自動接續。
    #[cfg_attr(test, ts(type = "number | null"))]
    pub paused_until_ms: Option<u64>,
}

/// 帳戶裡的一台裝置(spec §8)。Forget 只是從清單移除,不是撤權。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncDeviceView {
    pub id: String,
    pub name: String,
    pub platform: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub joined_at_ms: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub last_seen_ms: u64,
    pub is_this: bool,
    /// 這台裝置勾選的 space id。
    pub spaces: Vec<String>,
}

/// 帳戶裡的一個 space(spec §8),依 Include 清單的順序。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncSpaceView {
    pub id: String,
    pub name: String,
    /// 這台有勾選(同步下來成為一個檔案)。
    pub selected: bool,
    /// 勾選時的檔名與完整路徑(`~/.ssh/sshelter/<slug>-<id8>.config`)。
    pub file_name: Option<String>,
    pub file_path: Option<String>,
    /// 勾選時的主機數;沒勾選的 space 這台不知道。
    #[cfg_attr(test, ts(type = "number | null"))]
    pub hosts: Option<u64>,
    #[cfg_attr(test, ts(type = "number"))]
    pub pending_uploads: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub approvals: u64,
    /// 剛勾選、第一輪(基線輪)還沒完成:這段期間不要搬主機進來。
    pub first_sync_pending: bool,
    /// relay 上的 chain 不見了、帳戶卻仍有它(spec §9):提供「重建」或「刪除」。
    pub missing: bool,
    /// 只屬於這個 space 的錯誤(違反不變式、寫入失敗)。
    pub last_error: Option<String>,
    #[cfg_attr(test, ts(type = "number"))]
    pub created_at_ms: u64,
    /// 勾選了這個 space 的裝置名稱。
    pub synced_on: Vec<String>,
}

/// 一個金鑰插槽(SP3 spec §7.2),依名稱排序。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncKeySlotView {
    pub id: String,
    /// 插槽名稱;來自別台電腦,UI 以 `revealHidden` 顯示。
    pub name: String,
    pub mode: crate::sync::slot_rules::SlotMode,
    /// `synced` 的金鑰指紋;`own` 為 null。
    pub fingerprint: Option<String>,
    pub key_type: Option<String>,
    /// 帳戶裡同步的那把金鑰有沒有 passphrase(`synced` 才有;`own` 為 null)。
    pub has_passphrase: Option<bool>,
    /// 這台按「Sync this key」或「Sync the new key」會上傳的那把金鑰(這台插槽裡的,不是帳戶裡現在同步的那把)有沒有 passphrase;
    /// 這台不提供那兩個動作、或讀不到那把金鑰 → null。上傳之前的確認以它說明。
    pub local_has_passphrase: Option<bool>,
    /// 建立插槽的電腦名稱。
    pub origin_device: String,
    pub origin_is_this: bool,
    /// 主機 `IdentityFile` 的值(`~/.ssh/sshelter/keys/<file>`)。
    pub value: String,
    /// 這台用到它的主機:勾選的 space 裡的,以及整份 config 裡的其他主機(主 config、`~/.ssh/sshelter-local/`……)。
    pub hosts: Vec<String>,
    pub status: SlotStatusView,
    /// 其他電腦的插槽狀況(它們的 `device.slots`)。
    pub devices: Vec<SlotDeviceView>,
    /// 帳戶裡還有這個插槽。false = 帳戶裡已經沒有(被刪除,或離開之後建立、加入了別的帳戶),這台還留著它的檔案:同步、挑金鑰這些動作都不適用,
    /// 只能刪除沒有主機用到的副本。
    pub in_account: bool,
    /// 這台只在 SSHelter(私鑰在保管庫,經 agent 提供;金鑰保管庫 spec §4.3)。
    pub in_vault: bool,
    /// 這台用的是檔案(SP3 的連結或同步來的副本):更新前留下的,或保管庫用不了時暫時落地的(金鑰保管庫 spec §4.3、§11)。畫面標「File for now」,
    /// 「Move」把它搬進保管庫。agent 永遠放不下的金鑰(安全金鑰與 DSA、解不開的加密方式、讀不懂的、舊式 PEM)不算:它們只能留在檔案,不標、Move 也不碰;
    /// 現在讀不到金鑰(原檔不見)的還算,Move 會說明原因。
    pub file_for_now: bool,
    /// 這台保管庫裡的這把金鑰有沒有 passphrase(`SlotSource::Vault`);金鑰不在保管庫 → None。「Export private key…」只在沒有時提供加一個。
    pub vault_has_passphrase: Option<bool>,
    /// 這台自己加進 SSHelter、不在任何帳戶的金鑰(`LocalSlot::local_only`;畫面標「This computer only」)。
    pub local_only: bool,
    /// 插槽建立的時間(`KeySlotPayload::created_at_ms`;只在這台的金鑰 = 加進 SSHelter 的時間)。
    #[cfg_attr(test, ts(type = "number"))]
    pub created_at_ms: u64,
    /// 這台還是檔案、而且永遠搬不進保管庫的原因(`slots::move_refusal`);其他 None。
    pub stays_file: Option<String>,
}

/// 插槽在這台電腦上的狀態(SP3 spec §7.2、§7.3)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SlotStatusView {
    /// 插槽裡有金鑰;`file` = 這台實際用的檔案(連到的金鑰,或插槽本身的副本)。
    Ready { file: String, synced_copy: bool, fingerprint: Option<String> },
    /// 這台需要金鑰:`own` 要使用者挑(`waiting_for_sync` = false),`synced` 的私鑰還沒到(true)。
    NeedsKey { waiting_for_sync: bool },
    /// 沒有主機用到,但這台還留著同步來的副本或複製檔(可以刪除)。
    NotInUse { file: String },
    /// 這台沒有主機用到它。
    NotUsedHere,
    /// 插槽有同步的金鑰,這台用的卻是另一把(本機挑的,或舊的副本):可以改用。
    SyncedAvailable { file: String },
    /// 目前同步的那把是這台上傳的,這台連到的金鑰之後換成了另一把;其他電腦還是上一把。
    SourceChanged { file: String },
    Error { message: String },
}

/// 另一台電腦的插槽狀況。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SlotDeviceView {
    pub name: String,
    pub fingerprint: Option<String>,
    pub synced_copy: bool,
    /// 那台的金鑰在 SSHelter 的保管庫裡(那台是 2a 以後的版本)。
    pub in_vault: bool,
}

/// 「Move」搬不進保管庫的一把(金鑰保管庫 spec §8):插槽 id、名稱(來自帳戶,畫面以 `revealHidden` 顯示)與原因。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct MoveFailure {
    pub slot_id: String,
    pub name: String,
    pub message: String,
}

/// 「Move」做完的結果:最新的狀態,與搬不進去的那些。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct MoveIntoVaultResult {
    pub overview: SyncOverview,
    pub failed: Vec<MoveFailure>,
}

/// Settings → Sync 的全部狀態(`sync_overview` 與 `sync://status`)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SyncOverview {
    pub joined: bool,
    /// 帳戶 chain id 的前 8 個 hex,只作辨識。
    pub account_short: Option<String>,
    pub device_id: String,
    pub device_name: String,
    pub relay_url: String,
    pub relay: Option<SyncRelayView>,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub last_sync_ms: Option<u64>,
    pub last_error: Option<String>,
    /// 帳戶用了比這版新的格式:只讀,不上傳。
    pub read_only: bool,
    /// v1 升級還沒完成(spec §7.6)。
    pub upgrading: bool,
    pub frozen: Option<SyncFrozenView>,
    pub rotation: Option<SyncRotationView>,
    pub devices: Vec<SyncDeviceView>,
    pub spaces: Vec<SyncSpaceView>,
    #[cfg_attr(test, ts(type = "number"))]
    pub pending_uploads: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub approvals_waiting: u64,
    /// `~/.ssh/sshelter/` 裡不在 Include 清單上的 `.config` 檔:OpenSSH 不讀,只提示(spec §4.3)。
    pub stray_files: Vec<String>,
    /// 帳戶裡的金鑰插槽與這台還留著副本的舊插槽(SP3 spec §7.2)。
    pub key_slots: Vec<SyncKeySlotView>,
    /// 等使用者看過的提示,`sync_dismiss_notice(index)` 清掉。
    pub notices: Vec<SyncNotice>,
    /// 離開帳戶時同步碼刪不掉:顯示警示與重試。
    pub phrase_cleanup_pending: bool,
}

/// 一筆等待核准的主機(`sync_pending_approvals`;spec §7.4、§8 的審核對話框)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PendingApprovalView {
    pub space_id: String,
    pub space_name: String,
    pub alias: String,
    /// 這一版的內容指紋(`spaces::review_digest`):核准 / 拒絕時連同 `alias` 送回(`ReviewedVersion`)—— 只處理使用者看過的
    /// 這一版。序號與版本號都可能指到別的內容(relay 的歷史倒退、兩台寫出同一個版本號),所以以內容認。
    pub digest: String,
    /// 要套用的完整區塊。
    pub text: String,
    /// 目前 space 檔裡的區塊;None = 這台還沒有這台主機。
    pub current_text: Option<String>,
    /// 目前區塊與新區塊的核准簽章(UI 標出受管制的行與差異)。
    pub applied: ApprovalSignature,
    pub incoming: ApprovalSignature,
    pub from_device: String,
    #[cfg_attr(test, ts(type = "number"))]
    pub updated_at_ms: u64,
}

/// 審核對話框送回的一筆(`sync_approve` / `sync_reject`):使用者看過的那一版 —— `PendingApprovalView` 的 `alias` 與 `digest`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ReviewedVersion {
    pub alias: String,
    pub digest: String,
}

/// `sync_approve` / `sync_reject` 的結果(spec §7.4)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ReviewOutcome {
    /// 實際處理了幾台:核准 = 套用的主機數,拒絕 = 丟棄的版本數。
    #[cfg_attr(test, ts(type = "number"))]
    pub applied: u64,
    /// 略過的主機:使用者看過的版本已經不是待核准的那一版(被較新的取代、已處理或已不在清單上)。較新的版本留在清單上;
    /// UI 顯示「已變更,請重新確認」並重新讀 `sync_pending_approvals`。
    pub changed: Vec<String>,
    /// 動作之後的最新狀態(同其他 command 回傳的 `SyncOverview`)。
    pub overview: SyncOverview,
}

/// 組出 `SyncOverview`(spec §8)。先後短暫持有 core 鎖與 doc 鎖(不同時持有;呼叫端只可以持有 lifecycle 鎖 —— 鎖的順序 lifecycle → doc → … → core);
/// 讀目錄與金鑰檔在鎖外。
pub fn overview(env: &SyncEnv) -> Result<SyncOverview, AppError> {
    let (s, keys, upgrading) = {
        let core = env.runtime.core.lock().unwrap();
        let s = core.state.clone().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        (s, core.account_keys.clone(), core.legacy.is_some())
    };
    let account = s.account.as_ref();
    let device_list: Vec<SyncDeviceView> = account
        .map(devices)
        .unwrap_or_default()
        .into_iter()
        .map(|(id, p)| SyncDeviceView {
            is_this: id == s.device_id,
            id,
            name: p.name,
            platform: p.platform,
            joined_at_ms: p.joined_at_ms,
            last_seen_ms: p.last_seen_ms,
            spaces: p.spaces,
        })
        .collect();
    let synced_on = |space_id: &str| -> Vec<String> {
        device_list.iter().filter(|d| d.spaces.iter().any(|x| x == space_id)).map(|d| d.name.clone()).collect()
    };
    let mut spaces: Vec<SyncSpaceView> = Vec::new();
    let entries = account.map(space_entries).unwrap_or_default();
    for entry in &entries {
        let deleted = entry.deleted || match (account, keys.as_ref()) {
            (Some(a), Some(k)) => space_deleted_by(a, k, &entry.id).is_some(),
            _ => false,
        };
        if deleted {
            continue;
        }
        let local = s.spaces.get(&entry.id).filter(|sp| sp.selected);
        spaces.push(SyncSpaceView {
            id: entry.id.clone(),
            name: entry.name.clone(),
            selected: local.is_some(),
            file_name: local.map(|sp| sp.file_name.clone()),
            file_path: local.and_then(|sp| space_path(env, &sp.file_name).ok()).map(|p| p.to_string_lossy().into_owned()),
            hosts: local.map(|sp| sp.records.values().filter(|l| l.record.kind == RecordKind::Host && !l.record.deleted).count() as u64),
            pending_uploads: local.map(|sp| sp.records.values().filter(|l| l.dirty).count() as u64).unwrap_or(0),
            approvals: local.map(|sp| sp.pending_approvals.len() as u64).unwrap_or(0),
            first_sync_pending: local.is_some_and(|sp| !sp.baseline_established),
            missing: local.is_some_and(|sp| sp.missing),
            last_error: local.and_then(|sp| sp.last_error.clone()),
            created_at_ms: entry.created_at_ms,
            synced_on: synced_on(&entry.id),
        });
    }
    let listed: Vec<String> = s.spaces.values().filter(|sp| sp.selected).map(|sp| sp.file_name.clone()).collect();
    let stray_files = if s.joined() { stray_space_files(&env.ssh_dir, &listed).unwrap_or_default() } else { Vec::new() };
    let account_dirty = account
        .map(|a| a.records.values().filter(|l| l.dirty).count() + a.sealed.values().filter(|x| x.dirty).count())
        .unwrap_or(0) as u64;
    // 有帳戶、帳戶金鑰卻還沒載入:照舊不列(分不出帳戶裡的插槽在這台的狀態)。沒有帳戶:這台留著的插槽照樣列出(`views`;離開帳戶之後,它們的金鑰
    // 多半就在這台的保管庫裡,`ssh` 照常經 agent 用著它們)。
    let key_slots = match env.ssh_dir.parent() {
        Some(home) if account.is_none() || keys.is_some() => {
            // 整份 config 裡用到的插槽(短暫拿 doc 鎖;這裡沒有持有 doc 鎖或它之後的鎖)。config 還沒載入時當成沒有,只影響顯示:刪除副本自己會再查。
            let in_use = crate::sync::slots::config_slot_uses(env).unwrap_or_default();
            crate::sync::slots::views(&s, keys.as_ref(), home, &in_use)
        }
        _ => Vec::new(),
    };
    Ok(SyncOverview {
        joined: s.joined(),
        account_short: account.map(|a| a.chain_id.chars().take(8).collect()),
        device_id: s.device_id.clone(),
        device_name: s.device_name.clone(),
        relay_url: s.relay_url.clone(),
        relay: s.relay_features.as_ref().filter(|f| f.url == s.relay_url).map(|f| SyncRelayView {
            url: f.url.clone(),
            version: f.version.clone(),
            batch_pull: f.supports(FEATURE_PULL_BATCH),
            freeze: f.supports(FEATURE_FREEZE),
        }),
        last_sync_ms: s.last_sync_ms,
        last_error: s.last_error.clone(),
        read_only: s.read_only(),
        upgrading,
        frozen: s.frozen().map(|f| SyncFrozenView {
            detected_at_ms: f.detected_at_ms,
            by_devices: f.markers.iter().map(|m| m.by_device_name.clone()).collect(),
        }),
        rotation: s.rotation.as_ref().map(|r| SyncRotationView {
            step: r.step,
            cancellable: r.cancellable(),
            paused_until_ms: r.paused_until_ms,
        }),
        pending_uploads: account_dirty + spaces.iter().map(|v| v.pending_uploads).sum::<u64>(),
        approvals_waiting: spaces.iter().map(|v| v.approvals).sum(),
        devices: device_list,
        spaces,
        stray_files,
        key_slots,
        notices: s.notices.clone(),
        phrase_cleanup_pending: s.phrase_cleanup_pending,
    })
}

/// 等待核准的主機(spec §7.4 的審核對話框):每一筆附上目前 space 檔裡的區塊。
pub fn pending_approvals(env: &SyncEnv) -> Result<Vec<PendingApprovalView>, AppError> {
    let s = env.runtime.core.lock().unwrap().state.clone().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    let names: BTreeMap<String, String> =
        s.account.as_ref().map(space_entries).unwrap_or_default().into_iter().map(|e| (e.id, e.name)).collect();
    let mut current: BTreeMap<(String, String), String> = BTreeMap::new();
    {
        let doc_lock = env.doc.lock().unwrap();
        if let Some(doc) = doc_lock.as_ref() {
            for (id, sp) in s.spaces.iter().filter(|(_, sp)| !sp.pending_approvals.is_empty()) {
                let Ok(path) = space_path(env, &sp.file_name) else { continue };
                if let Some(file) = doc.files.iter().find(|f| f.path == path) {
                    for block in blocks_of(&file.items) {
                        current.insert((id.clone(), block.alias), block.text);
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for (id, sp) in &s.spaces {
        for (alias, p) in &sp.pending_approvals {
            out.push(PendingApprovalView {
                space_id: id.clone(),
                space_name: names.get(id).cloned().unwrap_or_else(|| id.chars().take(8).collect()),
                alias: alias.clone(),
                digest: review_digest(p),
                text: p.text.clone(),
                current_text: current.get(&(id.clone(), alias.clone())).cloned(),
                applied: p.applied.clone(),
                incoming: p.incoming.clone(),
                from_device: p.from_device.clone(),
                updated_at_ms: p.record.updated_at_ms,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::round::tests::{pair, settle};
    use crate::sync::spaces::create_space;

    #[test]
    fn the_overview_lists_spaces_devices_and_waiting_approvals() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        a.save_in_app(&a.space_path(&personal), "Host web\n  ProxyCommand nc %h 22\n");
        settle(&a);
        settle(&b);
        let o = overview(&b.env()).unwrap();
        assert!(o.joined && !o.upgrading && o.frozen.is_none());
        assert_eq!(o.account_short.as_deref().map(str::len), Some(8));
        assert_eq!(o.devices.len(), 2);
        assert!(o.devices.iter().any(|d| d.is_this && d.name == "MacBook-B" && d.spaces == vec![personal.clone()]));
        assert_eq!(o.spaces.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(), vec!["Personal", "Work"]);
        let p = &o.spaces[0];
        assert!(p.selected && p.file_path.as_deref().is_some_and(|f| f.ends_with(".config")));
        assert_eq!((p.hosts, p.approvals), (Some(0), 1), "the ProxyCommand host waits for approval");
        assert_eq!(p.synced_on.len(), 2);
        let w = o.spaces.iter().find(|v| v.id == work).unwrap();
        assert!(!w.selected && w.hosts.is_none() && w.file_name.is_none());
        assert_eq!(o.approvals_waiting, 1);
        assert!(o.relay.as_ref().is_some_and(|r| r.batch_pull && r.freeze && r.version.is_some()));
        let pending = pending_approvals(&b.env()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!((pending[0].alias.as_str(), pending[0].from_device.as_str()), ("web", "MacBook-A"));
        assert_eq!(pending[0].current_text, None);
        assert_eq!(pending[0].incoming.gated[0].keyword, "proxycommand");
        // 對話框顯示的版本:核准 / 拒絕時連同 alias 送回的就是它的內容指紋。
        let state = b.state();
        assert_eq!(pending[0].digest, review_digest(&state.spaces[&personal].pending_approvals["web"]));
        // 不在清單上的檔案只提示。
        std::fs::write(b.ssh_dir().join("sshelter").join("old-12345678.config"), "").unwrap();
        assert_eq!(overview(&b.env()).unwrap().stray_files, vec!["old-12345678.config".to_string()]);
    }
}
