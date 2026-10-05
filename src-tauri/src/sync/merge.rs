//! Sync v2 的記錄層(spec §7.1、§7.4):帳戶與 space 區段各自的本機 diff、合併與上傳。純函式 —— 不碰檔案與
//! Tauri;網路只在 `push_outgoing`(經 `RelayApi`)。規則沿用 v1:記錄層級 LWW、cursor 只跟 pull 的
//! watermark、解不開或格式不對的遠端記錄略過且不進快取、watermark 倒退就整份重傳。v2 多了:帳戶記錄依
//! `RecordKind::is_secret` 分流到明文 `records` 與密文 `sealed`、更換標記的偵測、危險設定的保留待核准。

use serde_json::Value;

use crate::error::AppError;
use crate::sync::approval::{needs_approval, signature};
use crate::sync::crypto::{id_hash, is_chain_id, ChainKeys};
use crate::sync::hosts_file::{is_syncable_alias, validate_host_text, HostBlockText};
use crate::sync::planner::{detect_local_changes, next_timestamp};
use crate::sync::reconcile::{decode, encode, HostEffect};
use crate::sync::record::{
    merge, record_key, rotation_marker_device, DevicePayload, HostPayload, LocalRecord, MergeOutcome, MetaPayload,
    Record, RecordKind, RotationMarkerPayload, SpaceKeyPayload, SpacePayload, ACCOUNT_META_ID, SCHEMA_VERSION,
};
use crate::sync::relay::{PullResponse, PushItem, PushOutcome, PushResult, RelayApi, RelayError};
use crate::sync::slot_rules::{is_slot_id, valid_key_payload, valid_slot_payload, DeviceSlot, KeyPayload, KeySlotPayload};
use crate::sync::space_files::{include_order, include_tokens};
use crate::sync::state_v2::{sealed_key, AccountState, DeclinedVersion, PendingApproval, SealedRecord, SpaceState};

/// 裝置心跳的間隔(同 v1)。
const HEARTBEAT_MS: u64 = 60 * 60 * 1000;
/// 每批上傳的上限(spec §7.1 第 7 步,同 v1):≤ 200 筆且 ≤ 512 KiB。
const PUSH_BATCH_ITEMS: usize = 200;
const PUSH_BATCH_BYTES: usize = 512 * 1024;

// ── space 區段:本機 diff ────────────────────────────────────────────────────────────────────────

/// 等待核准或被拒絕的遠端版本中,這台已知最新的一版(版本號、時間戳、序號各取最大)。
fn known_remote(space: &SpaceState, alias: &str) -> Option<DeclinedVersion> {
    let pending = space
        .pending_approvals
        .get(alias)
        .map(|p| DeclinedVersion { version: p.record.version, updated_at_ms: p.record.updated_at_ms, seq: p.seq });
    let declined = space.declined.get(alias).cloned();
    match (pending, declined) {
        (Some(a), Some(b)) => Some(DeclinedVersion {
            version: a.version.max(b.version),
            updated_at_ms: a.updated_at_ms.max(b.updated_at_ms),
            seq: a.seq.max(b.seq),
        }),
        (a, b) => a.or(b),
    }
}

/// 一個 space 的本機 diff(spec §7.1 第 3 步;存檔當下的規劃也用它):space 檔目前的區塊對快取 → dirty 記錄,保留
/// seq 當 base_seq。等待核准(`pending_approvals`)或被拒絕(`declined`)的遠端版本也是「這台已知的版本」:新的本機
/// 版本以三者中最新的版本號、時間戳與序號為基準 —— 本機修改照 LWW 蓋過它們,推送也不會因為 base_seq 過舊而一直
/// 衝突。產生了本機版本的 alias,待核准與拒絕記錄一併清掉(被較新的本機版本取代)。回傳產生的記錄數。
pub fn plan_hosts(space: &mut SpaceState, blocks: &[HostBlockText], device_id: &str, changed_at: impl Fn(&str) -> u64) -> usize {
    let aliases: Vec<String> = space.pending_approvals.keys().chain(space.declined.keys()).cloned().collect();
    let mut view = space.records.clone();
    for alias in &aliases {
        let Some(known) = known_remote(space, alias) else { continue };
        let key = record_key(RecordKind::Host, alias);
        match view.get_mut(&key) {
            Some(local) => {
                local.record.version = local.record.version.max(known.version);
                local.record.updated_at_ms = local.record.updated_at_ms.max(known.updated_at_ms);
            }
            // 本機沒有這台主機:以一筆已刪除的佔位記錄代表「已知的版本」,檔案裡出現它時才算新版本。
            None => {
                let placeholder = Record {
                    kind: RecordKind::Host,
                    id: alias.clone(),
                    version: known.version,
                    updated_at_ms: known.updated_at_ms,
                    device_id: String::new(),
                    deleted: true,
                    payload: Value::Null,
                };
                view.insert(key, LocalRecord { record: placeholder, seq: known.seq, dirty: false });
            }
        }
    }
    let mut planned = 0;
    for record in detect_local_changes(&view, blocks, device_id, changed_at) {
        let key = record_key(record.kind, &record.id);
        let known_seq = known_remote(space, &record.id).map(|k| k.seq).unwrap_or(0);
        let seq = space.records.get(&key).map(|l| l.seq).unwrap_or(0).max(known_seq);
        space.pending_approvals.remove(&record.id);
        space.declined.remove(&record.id);
        space.republish.remove(&key);
        space.records.insert(key, LocalRecord { record, seq, dirty: true });
        planned += 1;
    }
    planned
}

// ── space 區段:合併 ──────────────────────────────────────────────────────────────────────────

/// `merge_space` 的結果。`section` 是合併後的新區段(含 cursor);呼叫端在指紋守衛下把 `effects` 寫進 space 檔成功
/// 之後才採用它 —— 失敗就整份丟棄,下一輪重拉。
#[derive(Clone, Debug)]
pub struct SpaceMerged {
    pub section: SpaceState,
    pub effects: Vec<HostEffect>,
    /// 本機未上傳的修改被較新的遠端版本取代的 alias。
    pub conflicts: Vec<String>,
    /// 這次新保留、等待核准的 alias(spec §7.4)。
    pub held: Vec<String>,
    /// 解不開、身分不符、不是 host、文字不合法(含 `Include`、wildcard)而略過的記錄數。
    pub skipped: u32,
}

/// 一個 space 拉到的記錄 → LWW 合併(spec §7.1 第 4 步、§7.4)。`applied` = space 檔目前的區塊(核准簽章比較的對象);
/// `device_name` 把寫入者的 device id 換成顯示名稱。遠端的 `Upsert` 若含受管制的設定且簽章和目前的區塊不同,就
/// **保留不套用**:放進 `pending_approvals`(同一 alias 的較新版本取代舊的),不產生效果、不進快取 —— 下一輪的
/// 本機 diff 才不會把它當成本機修改推回去;cursor 照常推進。本機未上傳的修改輸給較新的遠端版本時(不論套用或
/// 保留)不再上傳,並列入 `conflicts`(`republish` 裡的記錄除外)。遠端刪除與不含受管制設定的修改照常套用,並清掉
/// 同一 alias 的待核准與拒絕記錄。同一版(版本號與時間戳相同)從頭再拉到時(space 檔重新長出、relay 的歷史倒退、chain
/// 重建):拒絕過的仍是拒絕;還在等核准的那一筆照舊、只換成這次的序號,不再列進 `held`(不發新的核准事件)—— 它的內容
/// 指紋(`spaces::review_digest`)不含序號,開著的審核對話框照樣對得上。
pub fn merge_space(
    section: &SpaceState,
    keys: &ChainKeys,
    pulled: &PullResponse,
    applied: &[HostBlockText],
    device_name: impl Fn(&str) -> String,
) -> SpaceMerged {
    let mut next = section.clone();
    let mut out = SpaceMerged { section: SpaceState::new(""), effects: Vec::new(), conflicts: Vec::new(), held: Vec::new(), skipped: 0 };
    for env in &pulled.records {
        // space chain 只放 host 記錄(spec §4.2):其他種類一律略過,不保存。
        let record = match decode(keys, env) {
            Ok(r) if env.kind == RecordKind::Host.as_str() && is_syncable_alias(&r.id) => r,
            _ => {
                out.skipped += 1;
                continue;
            }
        };
        let key = record_key(RecordKind::Host, &record.id);
        let outcome = merge(next.records.get(&key), &record);
        if outcome == MergeOutcome::KeepLocal {
            // 本機較新:把 seq 更新到 relay 現況,下次推送才不會再撞 conflict。
            if let Some(local) = next.records.get_mut(&key) {
                local.seq = env.seq;
            }
            continue;
        }
        let lost_local_edit = outcome == MergeOutcome::RemoteWinsOverDirtyLocal && !next.republish.contains(&key);
        let alias = record.id.clone();
        if record.deleted {
            next.pending_approvals.remove(&alias);
            next.declined.remove(&alias);
            next.republish.remove(&key);
            if lost_local_edit {
                out.conflicts.push(alias.clone());
            }
            out.effects.push(HostEffect::Delete { alias });
            next.records.insert(key, LocalRecord { record, seq: env.seq, dirty: false });
            continue;
        }
        let text = match serde_json::from_value::<HostPayload>(record.payload.clone()) {
            Ok(p) if validate_host_text(&alias, &p.text).is_ok() => p.text,
            // 格式不支援 / 文字不合法(含 `Include`、帶引號的 keyword、wildcard):不套用、不進快取、絕不當成刪除。
            _ => {
                out.skipped += 1;
                continue;
            }
        };
        // 同一版又拉到了(space 檔重新長出、relay 的歷史倒退或 chain 重建之後從頭再拉;版本號與時間戳都相同):拒絕過的仍是拒絕、
        // 還在等核准的仍在等,都不再問一次(待核准那一筆照舊,只換成這次的序號;內容指紋不含序號,開著的對話框照樣對得上)。本機
        // 那一版留著:只為了重新上傳才標成 dirty 的(歷史倒退)不再推 —— relay 上已經有較新的這一版。真的有本機修改輸給它時照下面
        // 的一般規則(衝突、重新保留)。
        if !lost_local_edit {
            let same = |version: u64, updated_at_ms: u64| version == record.version && updated_at_ms == record.updated_at_ms;
            let declined = next.declined.get_mut(&alias).filter(|d| same(d.version, d.updated_at_ms));
            let seen = declined.is_some();
            if let Some(d) = declined {
                d.seq = env.seq;
            }
            let pending = next.pending_approvals.get_mut(&alias).filter(|p| same(p.record.version, p.record.updated_at_ms));
            let seen = seen || pending.is_some();
            if let Some(p) = pending {
                p.seq = env.seq;
            }
            if seen {
                if let Some(local) = next.records.get_mut(&key) {
                    local.dirty = false;
                }
                next.republish.remove(&key);
                continue;
            }
        }
        next.declined.remove(&alias);
        next.republish.remove(&key);
        if lost_local_edit {
            out.conflicts.push(alias.clone());
        }
        let current = applied.iter().find(|b| b.alias == alias).map(|b| b.text.as_str());
        if needs_approval(&text, current) {
            // 保留:檔案與快取的內容都不動;本機未上傳的修改已輸給它,不再上傳。
            if let Some(local) = next.records.get_mut(&key) {
                local.dirty = false;
            }
            let pending = PendingApproval {
                applied: signature(current.unwrap_or("")),
                incoming: signature(&text),
                from_device: device_name(&record.device_id),
                seq: env.seq,
                text,
                record,
            };
            next.pending_approvals.insert(alias.clone(), pending);
            out.held.push(alias);
            continue;
        }
        next.pending_approvals.remove(&alias);
        out.effects.push(HostEffect::Upsert { alias, text });
        next.records.insert(key, LocalRecord { record, seq: env.seq, dirty: false });
    }
    if pulled.latest_seq < section.cursor_seq {
        // relay 的歷史倒退了(自架的 relay 從舊備份還原):同 v1,cursor 歸零、每筆快取的記錄以 seq 0 重新上傳 ——
        // relay 上還有的先回 conflict、合併之後才覆寫,不會蓋掉還原之後別台寫的新版。待核准與拒絕的版本記的序號
        // 也屬於舊歷史(本機修改時會當成 base_seq),一併歸零。原本乾淨的記錄只是為了讓 relay 重新長出來才重傳,
        // 記進 `republish`:它們輸給還原之後的新版,不算本機修改被覆蓋;本機真的還沒上傳的修改照舊算衝突。
        next.cursor_seq = 0;
        for (key, local) in next.records.iter_mut() {
            if !local.dirty {
                next.republish.insert(key.clone());
            }
            local.seq = 0;
            local.dirty = true;
        }
        for pending in next.pending_approvals.values_mut() {
            pending.seq = 0;
        }
        for declined in next.declined.values_mut() {
            declined.seq = 0;
        }
    } else {
        next.cursor_seq = pulled.latest_seq;
    }
    out.section = next;
    out
}

/// 基線輪要寫回 space 檔的本機版本(還沒上傳的修改,另加核准的那一版):space 檔不見了或被清空、從 chain 重新長出時
/// 保留下來、檔案裡卻沒有的 host 記錄 ——
/// - 還沒上傳的修改:合併之後仍是 dirty(仍贏 LWW)。dirty 的 tombstone 不產生效果(照常推送)。
/// - 有待核准或被拒絕的版本的 alias:這台目前套用的那一版(快取裡乾淨的記錄,`files::reset_space_for_rematerialize` 留下來的)。
///   chain 上較新的那一版還在等核准、或已經被拒絕,基線輪不會套用它 —— 主機不能因此從檔案消失。
pub fn unpushed_host_effects(section: &SpaceState, blocks: &[HostBlockText]) -> Vec<HostEffect> {
    let reviewed = |alias: &str| section.pending_approvals.contains_key(alias) || section.declined.contains_key(alias);
    section
        .records
        .values()
        .filter(|l| l.record.kind == RecordKind::Host && !l.record.deleted && (l.dirty || reviewed(&l.record.id)))
        .filter(|l| !blocks.iter().any(|b| b.alias == l.record.id))
        .filter_map(|l| {
            let text = serde_json::from_value::<HostPayload>(l.record.payload.clone()).ok()?.text;
            validate_host_text(&l.record.id, &text).ok()?;
            Some(HostEffect::Upsert { alias: l.record.id.clone(), text })
        })
        .collect()
}

// ── 帳戶區段 ─────────────────────────────────────────────────────────────────────────────────

/// 帳戶裡的一個 space(`space` 記錄;tombstone 也列出,`deleted` = true)。
#[derive(Clone, Debug, PartialEq)]
pub struct SpaceEntry {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_at_ms: u64,
    pub previous_id: Option<String>,
    pub deleted: bool,
    /// 最後寫入這筆 `space` 記錄的裝置。
    pub updated_by: String,
}

/// 帳戶裡的 space(含 tombstone),依 Include 清單的順序(名稱不分大小寫 → 名稱 → id)。payload 讀不懂的略過;
/// tombstone 若沒有 payload,名稱是空字串。
pub fn space_entries(account: &AccountState) -> Vec<SpaceEntry> {
    let mut out: Vec<SpaceEntry> = account
        .records
        .values()
        .filter(|l| l.record.kind == RecordKind::Space && is_chain_id(&l.record.id))
        .filter_map(|l| {
            let payload = serde_json::from_value::<SpacePayload>(l.record.payload.clone()).ok();
            if payload.is_none() && !l.record.deleted {
                return None;
            }
            let payload = payload.unwrap_or(SpacePayload {
                schema: SCHEMA_VERSION,
                name: String::new(),
                slug: String::new(),
                created_at_ms: 0,
                previous_id: None,
            });
            Some(SpaceEntry {
                id: l.record.id.clone(),
                name: payload.name,
                slug: payload.slug,
                created_at_ms: payload.created_at_ms,
                previous_id: payload.previous_id,
                deleted: l.record.deleted,
                updated_by: l.record.device_id.clone(),
            })
        })
        .collect();
    out.sort_by(|a, b| include_order((&a.name, &a.id), (&b.name, &b.id)));
    out
}

pub fn space_entry(account: &AccountState, space_id: &str) -> Option<SpaceEntry> {
    space_entries(account).into_iter().find(|e| e.id == space_id)
}

/// `spacekey` 在 `sealed` 裡的 key(以帳戶金鑰算的 id_hash)。
pub fn space_key_slot(account_keys: &ChainKeys, space_id: &str) -> String {
    sealed_key(RecordKind::SpaceKey.as_str(), &id_hash(account_keys, RecordKind::SpaceKey.as_str(), space_id))
}

/// 在記憶體解開一個 space 的權杖與金鑰。沒有、已刪除或讀不懂 → None(這個 space 不能同步)。
pub fn space_keys(account: &AccountState, account_keys: &ChainKeys, space_id: &str) -> Option<ChainKeys> {
    let sealed = account.sealed.get(&space_key_slot(account_keys, space_id))?;
    let record = sealed.open(account_keys).ok()?;
    if record.deleted || record.id != space_id {
        return None;
    }
    serde_json::from_value::<SpaceKeyPayload>(record.payload).ok()?.to_keys(space_id).ok()
}

/// 這個 space 是否已從帳戶刪除;是的話回傳刪除它的裝置 id。`space` 記錄是 tombstone,或 `spacekey` 記錄是 tombstone
/// 都算:刪除與別台的改名同時發生時,改名可能贏了 `space` 記錄的 LWW,`spacekey` 的 tombstone 卻仍在 —— 沒有金鑰的
/// space 無法再同步,所以每台都一致地把它當成已刪除(刪除優先)。`spacekey` 還沒到的 space 不算刪除。
pub fn space_deleted_by(account: &AccountState, account_keys: &ChainKeys, space_id: &str) -> Option<String> {
    if let Some(l) = account.records.get(&record_key(RecordKind::Space, space_id)).filter(|l| l.record.deleted) {
        return Some(l.record.device_id.clone());
    }
    let record = account.sealed.get(&space_key_slot(account_keys, space_id))?.open(account_keys).ok()?;
    record.deleted.then_some(record.device_id)
}

/// 帳戶裡未刪除的裝置記錄(id, payload)。
pub fn devices(account: &AccountState) -> Vec<(String, DevicePayload)> {
    account
        .records
        .values()
        .filter(|l| l.record.kind == RecordKind::Device && !l.record.deleted)
        .filter_map(|l| Some((l.record.id.clone(), serde_json::from_value(l.record.payload.clone()).ok()?)))
        .collect()
}

/// 裝置顯示名稱;帳戶裡查不到時就是 device id。
pub fn device_name(account: &AccountState, device_id: &str) -> String {
    devices(account)
        .into_iter()
        .find(|(id, _)| id == device_id)
        .map(|(_, p)| p.name)
        .unwrap_or_else(|| device_id.to_string())
}

/// 帳戶區段裡寫一筆這台產生的明文記錄(`space` / `device` / `meta` / `keyslot`):版本號與時間戳接在前一版之後、
/// 保留 seq、標 dirty。
pub fn put_account_record(
    account: &mut AccountState,
    kind: RecordKind,
    id: &str,
    payload: Value,
    deleted: bool,
    device_id: &str,
    now_ms: u64,
) {
    let key = record_key(kind, id);
    let previous = account.records.get(&key);
    let record = Record {
        kind,
        id: id.to_string(),
        version: previous.map(|l| l.record.version + 1).unwrap_or(1),
        updated_at_ms: next_timestamp(now_ms, previous.map(|l| l.record.updated_at_ms)),
        device_id: device_id.to_string(),
        deleted,
        payload,
    };
    let seq = previous.map(|l| l.seq).unwrap_or(0);
    account.records.insert(key, LocalRecord { record, seq, dirty: true });
}

/// 寫一筆 `spacekey` 記錄(祕密,spec §4.1):以帳戶金鑰加密後放進 `sealed`(dirty),明文只在記憶體。
/// `space_keys` = None 寫 tombstone(不帶任何祕密)。版本號、時間戳與 seq 接在前一版之後。金鑰必須就是這個 space 的
/// (`chain_id` 等於 `space_id`),否則回錯誤、什麼都不寫。
pub fn put_space_key(
    account: &mut AccountState,
    account_keys: &ChainKeys,
    space_id: &str,
    space_keys: Option<&ChainKeys>,
    device_id: &str,
    now_ms: u64,
) -> Result<(), AppError> {
    // 另一條 chain 的金鑰記在這個 space 的 id 底下,別台讀到之後會拿錯的權杖去連這個 space。
    if space_keys.is_some_and(|k| k.chain_id != space_id) {
        return Err(AppError::Other("the space key does not belong to that space".to_string()));
    }
    let slot = space_key_slot(account_keys, space_id);
    let previous = account.sealed.get(&slot).and_then(|s| s.open(account_keys).ok().map(|r| (r, s.envelope.seq)));
    let record = Record {
        kind: RecordKind::SpaceKey,
        id: space_id.to_string(),
        version: previous.as_ref().map(|(r, _)| r.version + 1).unwrap_or(1),
        updated_at_ms: next_timestamp(now_ms, previous.as_ref().map(|(r, _)| r.updated_at_ms)),
        device_id: device_id.to_string(),
        deleted: space_keys.is_none(),
        payload: match space_keys {
            Some(k) => serde_json::to_value(SpaceKeyPayload::from_keys(k)).expect("SpaceKeyPayload serializes"),
            None => Value::Null,
        },
    };
    let sealed = SealedRecord::seal(account_keys, &record, previous.map(|(_, seq)| seq).unwrap_or(0))?;
    account.sealed.insert(slot, sealed);
    Ok(())
}

/// 這台的 `device` 記錄(spec §4.1):v1 的欄位加上這台勾選的 space id(呼叫端排好序)。`joined_at_ms` 沿用前一版。
pub fn own_device_record(
    account: &AccountState,
    device_id: &str,
    device_name: &str,
    platform: &str,
    spaces: &[String],
    now_ms: u64,
) -> Record {
    let key = record_key(RecordKind::Device, device_id);
    let previous = account.records.get(&key).map(|l| &l.record);
    let previous_payload = previous.and_then(|r| serde_json::from_value::<DevicePayload>(r.payload.clone()).ok());
    let joined_at_ms = previous_payload.as_ref().map(|p| p.joined_at_ms).unwrap_or(now_ms);
    // 插槽清單由 `set_device_slots` 維護;心跳與勾選變更沿用前一版(SP3 spec §4.1)。
    let slots = previous_payload.map(|p| p.slots).unwrap_or_default();
    Record {
        kind: RecordKind::Device,
        id: device_id.to_string(),
        version: previous.map(|r| r.version + 1).unwrap_or(1),
        updated_at_ms: next_timestamp(now_ms, previous.map(|r| r.updated_at_ms)),
        device_id: device_id.to_string(),
        deleted: false,
        payload: serde_json::to_value(DevicePayload {
            schema: SCHEMA_VERSION,
            name: device_name.to_string(),
            platform: platform.to_string(),
            joined_at_ms,
            last_seen_ms: now_ms,
            keys: Vec::new(),
            spaces: spaces.to_vec(),
            slots,
        })
        .expect("DevicePayload serializes"),
    }
}

/// 心跳與勾選變更:快取裡這台的裝置記錄超過一小時沒更新,或名稱、平台、勾選的 space 和現況不同,就寫一版新的
/// (dirty)。回傳是否寫了。
pub fn plan_device(
    account: &mut AccountState,
    device_id: &str,
    device_name: &str,
    platform: &str,
    spaces: &[String],
    now_ms: u64,
) -> bool {
    let key = record_key(RecordKind::Device, device_id);
    let current = account
        .records
        .get(&key)
        .filter(|l| !l.record.deleted)
        .and_then(|l| serde_json::from_value::<DevicePayload>(l.record.payload.clone()).ok());
    let up_to_date = current.is_some_and(|p| {
        now_ms.saturating_sub(p.last_seen_ms) < HEARTBEAT_MS && p.name == device_name && p.platform == platform && p.spaces == spaces
    });
    if up_to_date {
        return false;
    }
    let record = own_device_record(account, device_id, device_name, platform, spaces, now_ms);
    let seq = account.records.get(&key).map(|l| l.seq).unwrap_or(0);
    account.records.insert(key, LocalRecord { record, seq, dirty: true });
    true
}

/// 這台的插槽清單(SP3 spec §4.1)和裝置記錄裡的不同時,寫一版新的(dirty;其他欄位沿用現況,`last_seen_ms` 更新)。
/// 這台還沒有裝置記錄(`plan_device` 還沒寫)時什麼都不做。回傳是否寫了。
pub fn set_device_slots(account: &mut AccountState, device_id: &str, slots: Vec<DeviceSlot>, now_ms: u64) -> bool {
    let key = record_key(RecordKind::Device, device_id);
    let Some(local) = account.records.get(&key).filter(|l| !l.record.deleted) else { return false };
    let Ok(mut payload) = serde_json::from_value::<DevicePayload>(local.record.payload.clone()) else { return false };
    if payload.slots == slots {
        return false;
    }
    payload.slots = slots;
    payload.last_seen_ms = now_ms;
    let record = Record {
        kind: RecordKind::Device,
        id: device_id.to_string(),
        version: local.record.version + 1,
        updated_at_ms: next_timestamp(now_ms, Some(local.record.updated_at_ms)),
        device_id: device_id.to_string(),
        deleted: false,
        payload: serde_json::to_value(payload).expect("DevicePayload serializes"),
    };
    let seq = local.seq;
    account.records.insert(key, LocalRecord { record, seq, dirty: true });
    true
}

/// `merge_account` 的結果。`markers` 非空 = 帳戶已被更換同步碼(spec §7.5):呼叫端**不採用** `section`,只記下
/// `frozen`、停止這一輪。
#[derive(Clone, Debug)]
pub struct AccountMerged {
    pub section: AccountState,
    pub markers: Vec<RotationMarkerPayload>,
    pub skipped: u32,
}

/// 帳戶 chain 上的記錄是否可以進快取:space / spacekey 的 id 必須是 64 字元小寫 hex(之後會組進檔名與 URL),
/// keyslot / key 的 id 必須是插槽 id(32 字元小寫 hex;插槽檔名由它組成),payload 必須讀得懂(tombstone 除外;
/// keyslot 與 key 另外要通過 `slot_rules` 的規則)。
fn valid_account_record(record: &Record) -> bool {
    let parses = |ok: bool| record.deleted || ok;
    match record.kind {
        RecordKind::Space => {
            is_chain_id(&record.id) && parses(serde_json::from_value::<SpacePayload>(record.payload.clone()).is_ok())
        }
        RecordKind::SpaceKey => {
            is_chain_id(&record.id)
                && parses(
                    serde_json::from_value::<SpaceKeyPayload>(record.payload.clone())
                        .ok()
                        .is_some_and(|p| p.to_keys(&record.id).is_ok()),
                )
        }
        RecordKind::Device => parses(serde_json::from_value::<DevicePayload>(record.payload.clone()).is_ok()),
        RecordKind::Meta if record.id == ACCOUNT_META_ID => {
            parses(serde_json::from_value::<MetaPayload>(record.payload.clone()).is_ok())
        }
        RecordKind::Meta if rotation_marker_device(&record.id).is_some() => {
            parses(serde_json::from_value::<RotationMarkerPayload>(record.payload.clone()).is_ok())
        }
        RecordKind::Meta => true,
        RecordKind::KeySlot => {
            is_slot_id(&record.id)
                && parses(
                    serde_json::from_value::<KeySlotPayload>(record.payload.clone())
                        .ok()
                        .is_some_and(|p| valid_slot_payload(&p)),
                )
        }
        RecordKind::Key => {
            is_slot_id(&record.id)
                && parses(
                    serde_json::from_value::<KeyPayload>(record.payload.clone())
                        .ok()
                        .is_some_and(|p| valid_key_payload(&p)),
                )
        }
        _ => false,
    }
}

/// 帳戶 chain 拉到的記錄 → 合併(spec §7.1 第 4–5 步)。`device` / `space` / `meta` / `keyslot` 解密進 `records`;
/// `spacekey` 與 `key`(SP3)只在記憶體解開比較,保存的是密文(`sealed`);其他種類(含未知)原樣存進 `sealed`、
/// 永不解密。拉到的 `meta` `rotation:*`(未刪除)收進 `markers`。
pub fn merge_account(section: &AccountState, keys: &ChainKeys, pulled: &PullResponse) -> AccountMerged {
    let mut next = section.clone();
    let mut markers = Vec::new();
    let mut skipped = 0;
    for env in &pulled.records {
        let kind = RecordKind::parse(&env.kind);
        match kind {
            Some(
                RecordKind::Device
                | RecordKind::Meta
                | RecordKind::Space
                | RecordKind::SpaceKey
                | RecordKind::KeySlot
                | RecordKind::Key,
            ) => {}
            _ => {
                // 本版不處理的種類:密文原樣保存,不解密、不刪除(spec §4.1)。
                next.sealed.insert(sealed_key(&env.kind, &env.id_hash), SealedRecord { envelope: env.clone(), dirty: false });
                continue;
            }
        }
        let record = match decode(keys, env) {
            Ok(r) if valid_account_record(&r) => r,
            _ => {
                skipped += 1;
                continue;
            }
        };
        if record.kind == RecordKind::Meta && rotation_marker_device(&record.id).is_some() && !record.deleted {
            if let Ok(marker) = serde_json::from_value::<RotationMarkerPayload>(record.payload.clone()) {
                markers.push(marker);
            }
        }
        if matches!(record.kind, RecordKind::SpaceKey | RecordKind::Key) {
            let slot = sealed_key(&env.kind, &env.id_hash);
            let local = next.sealed.get(&slot).and_then(|s| {
                s.open(keys).ok().map(|r| LocalRecord { record: r, seq: s.envelope.seq, dirty: s.dirty })
            });
            match merge(local.as_ref(), &record) {
                MergeOutcome::KeepLocal => {
                    if let Some(s) = next.sealed.get_mut(&slot) {
                        s.envelope.seq = env.seq;
                    }
                }
                _ => {
                    next.sealed.insert(slot, SealedRecord { envelope: env.clone(), dirty: false });
                }
            }
            continue;
        }
        let key = record_key(record.kind, &record.id);
        match merge(next.records.get(&key), &record) {
            MergeOutcome::KeepLocal => {
                if let Some(local) = next.records.get_mut(&key) {
                    local.seq = env.seq;
                }
            }
            _ => {
                if record.kind == RecordKind::Meta && record.id == ACCOUNT_META_ID {
                    if let Ok(meta) = serde_json::from_value::<MetaPayload>(record.payload.clone()) {
                        next.remote_schema_version = Some(meta.schema_version);
                    }
                }
                next.records.insert(key, LocalRecord { record, seq: env.seq, dirty: false });
            }
        }
    }
    if pulled.latest_seq < section.cursor_seq {
        // 同 `merge_space`:relay 倒退,整份以 seq 0 重新上傳(未知種類的密文不是這台寫的,不重推)。
        next.cursor_seq = 0;
        for local in next.records.values_mut() {
            local.seq = 0;
            local.dirty = true;
        }
        let resent = [RecordKind::SpaceKey.as_str(), RecordKind::Key.as_str()];
        for sealed in next.sealed.values_mut().filter(|s| resent.contains(&s.envelope.kind.as_str())) {
            sealed.envelope.seq = 0;
            sealed.dirty = true;
        }
    } else {
        next.cursor_seq = pulled.latest_seq;
    }
    AccountMerged { section: next, markers, skipped }
}

// ── 上傳 ────────────────────────────────────────────────────────────────────────────────────

/// 一筆要上傳的記錄;`key` 是它在區段裡的 key(`records` 或 `sealed`)。上傳結果靠 `version` / `updated_at_ms`
/// (明文記錄)或密文本身(`sealed`)對回區段 —— 推送期間記錄若已被換掉,就不動它。
#[derive(Clone, Debug)]
pub struct Outgoing {
    pub key: String,
    pub item: PushItem,
    pub version: u64,
    pub updated_at_ms: u64,
}

pub fn space_outgoing(section: &SpaceState, keys: &ChainKeys) -> Result<Vec<Outgoing>, AppError> {
    section
        .records
        .iter()
        .filter(|(_, l)| l.dirty)
        .map(|(key, l)| {
            Ok(Outgoing {
                key: key.clone(),
                item: encode(keys, &l.record, l.seq)?,
                version: l.record.version,
                updated_at_ms: l.record.updated_at_ms,
            })
        })
        .collect()
}

/// 帳戶區段的 dirty 記錄:明文記錄加密後上傳,`sealed` 的 dirty 密文原樣上傳。
pub fn account_outgoing(section: &AccountState, keys: &ChainKeys) -> Result<Vec<Outgoing>, AppError> {
    let mut out: Vec<Outgoing> = section
        .records
        .iter()
        .filter(|(_, l)| l.dirty)
        .map(|(key, l)| {
            Ok(Outgoing {
                key: key.clone(),
                item: encode(keys, &l.record, l.seq)?,
                version: l.record.version,
                updated_at_ms: l.record.updated_at_ms,
            })
        })
        .collect::<Result<_, AppError>>()?;
    out.extend(
        section
            .sealed
            .iter()
            .filter(|(_, s)| s.dirty)
            .map(|(key, s)| Outgoing { key: key.clone(), item: s.push_item(), version: 0, updated_at_ms: 0 }),
    );
    Ok(out)
}

/// 推送的結果:被接受的(key, relay 序號)、衝突筆數、是否撞到凍結的 chain、讓上傳提早結束的錯誤。
#[derive(Debug, Default)]
#[must_use = "apply `accepted` first (apply_pushed_*), then handle `frozen`, then `error`"]
pub struct Pushed {
    /// relay 已經收下的記錄。就算後面的批次失敗(`error`)也保留 —— 呼叫端一定要先套用它們(`apply_pushed_*`):不然這些
    /// relay 已經有的記錄下一輪又會整批重送(chain 的額度滿了的話,每一輪都在重寫前面的批次)。
    pub accepted: Vec<(String, u64)>,
    pub conflicts: usize,
    /// `409 frozen`(spec §6.4):這一批之後的都沒送,呼叫端停止這一輪的所有上傳、保留 dirty。凍結之前收下的批次仍在
    /// `accepted`。
    pub frozen: bool,
    /// 上傳在某一批失敗(`429`、`413`、`5xx`、連不上、回應和請求對不上):那一批與之後的都沒有被確認收下,仍是 dirty,下一輪
    /// 重送;之前的批次記在 `accepted`。呼叫端先套用 `accepted`,再把 `error` 當成一次失敗的上傳處理(退避、記錄)。
    pub error: Option<RelayError>,
}

/// 分批上傳(每批 ≤ 200 筆且 ≤ 512 KiB,絕不送空的上傳)。衝突的保持 dirty,下一輪 pull 拿到 relay 的版本再合併。
/// 在第一個失敗的批次停下:前面的批次 relay 已經收下,那些記錄留在 `accepted`、失敗的錯誤放進 `error` —— 呼叫端必須先
/// 套用 `accepted`(`apply_pushed_space` / `apply_pushed_account`),再把 `error` 當成一次失敗的上傳處理。chain 被凍結就
/// 立刻停下(`frozen`)。relay 的回答和這一批的筆數對不上時,整批的答案都不採用、記為 `BadResponse`。`accepted` 只更新
/// 該筆的 seq —— 絕不推進 cursor。
pub fn push_outgoing(relay: &dyn RelayApi, chain_id: &str, token: &str, outgoing: &[Outgoing]) -> Pushed {
    let mut pushed = Pushed::default();
    let mut start = 0;
    while start < outgoing.len() {
        let mut end = start;
        let mut bytes = 0usize;
        while end < outgoing.len() {
            let size = outgoing[end].item.ciphertext.len() + outgoing[end].item.nonce.len();
            if end > start && (end - start >= PUSH_BATCH_ITEMS || bytes + size > PUSH_BATCH_BYTES) {
                break;
            }
            bytes += size;
            end += 1;
        }
        let batch = &outgoing[start..end];
        let items: Vec<PushItem> = batch.iter().map(|o| o.item.clone()).collect();
        match relay.push(chain_id, token, &items) {
            Err(e) => {
                pushed.error = Some(e);
                return pushed;
            }
            Ok(PushOutcome::Frozen) => {
                pushed.frozen = true;
                return pushed;
            }
            Ok(PushOutcome::Applied(results)) => {
                // 答案必須和這一批一一對上(`RelayClient` 已經檢查過一次,這裡是第二道防線):逐筆 zip 會把結果算到錯的
                // 記錄上、或悄悄漏掉幾筆,所以對不上就整批不採用。
                if results.len() != batch.len() {
                    pushed.error = Some(RelayError::BadResponse(format!(
                        "a push of {} records was answered with {} results",
                        batch.len(),
                        results.len()
                    )));
                    return pushed;
                }
                for (o, result) in batch.iter().zip(results) {
                    match result {
                        PushResult::Accepted { seq } => pushed.accepted.push((o.key.clone(), seq)),
                        PushResult::Conflict { .. } => pushed.conflicts += 1,
                    }
                }
            }
        }
        start = end;
    }
    pushed
}

pub fn apply_pushed_space(section: &mut SpaceState, outgoing: &[Outgoing], pushed: &Pushed) {
    for (key, seq) in &pushed.accepted {
        let Some(o) = outgoing.iter().find(|o| &o.key == key) else { continue };
        if let Some(local) = section.records.get_mut(key) {
            if local.record.version == o.version && local.record.updated_at_ms == o.updated_at_ms {
                local.seq = *seq;
                local.dirty = false;
                section.republish.remove(key);
            }
        }
    }
}

pub fn apply_pushed_account(section: &mut AccountState, outgoing: &[Outgoing], pushed: &Pushed) {
    for (key, seq) in &pushed.accepted {
        let Some(o) = outgoing.iter().find(|o| &o.key == key) else { continue };
        if let Some(local) = section.records.get_mut(key) {
            if local.record.version == o.version && local.record.updated_at_ms == o.updated_at_ms {
                local.seq = *seq;
                local.dirty = false;
            }
        } else if let Some(sealed) = section.sealed.get_mut(key) {
            if sealed.envelope.ciphertext == o.item.ciphertext {
                sealed.envelope.seq = *seq;
                sealed.dirty = false;
            }
        }
    }
}

/// 這台勾選的 space(id、名稱、檔名),依 Include 清單的順序(`space_files::include_order`)。檔名來自狀態;名稱來自帳戶的 `space` 記錄(查不到就用 id)。
/// 主 config 的 Include 清單(`selected_include_tokens`)與搬移時的 space 檔順序(`migrate::selected_space_files`)都從這裡來,順序只有這一份。
pub fn selected_space_refs(
    account: Option<&AccountState>,
    spaces: &std::collections::BTreeMap<String, SpaceState>,
) -> Vec<crate::sync::space_files::SpaceFileRef> {
    let mut refs: Vec<crate::sync::space_files::SpaceFileRef> = spaces
        .iter()
        .filter(|(_, s)| s.selected)
        .map(|(id, s)| crate::sync::space_files::SpaceFileRef {
            space_id: id.clone(),
            name: account.and_then(|a| space_entry(a, id)).map(|e| e.name).unwrap_or_else(|| id.clone()),
            file_name: s.file_name.clone(),
        })
        .collect();
    refs.sort_by(|a, b| include_order((&a.name, &a.space_id), (&b.name, &b.space_id)));
    refs
}

/// 這台勾選的 space 的 Include 清單(spec §4.3 的順序,`selected_space_refs`)。
pub fn selected_include_tokens(account: Option<&AccountState>, spaces: &std::collections::BTreeMap<String, SpaceState>) -> Result<Vec<String>, AppError> {
    include_tokens(&selected_space_refs(account, spaces))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::record::{rotation_meta_id, Envelope};
    use crate::sync::relay::{BatchPullEntry, BatchPullItem, RelayInfo};

    fn keys() -> ChainKeys {
        ChainKeys::generate().unwrap()
    }

    fn block(alias: &str, text: &str) -> HostBlockText {
        HostBlockText { alias: alias.to_string(), text: text.to_string() }
    }

    fn host(alias: &str, text: Option<&str>, updated_at_ms: u64, device: &str) -> Record {
        Record {
            kind: RecordKind::Host,
            id: alias.to_string(),
            version: 1,
            updated_at_ms,
            device_id: device.to_string(),
            deleted: text.is_none(),
            payload: text.map_or(Value::Null, |t| serde_json::json!({ "schema": 1, "text": t })),
        }
    }

    /// 一批「relay 上的」記錄:依序給 seq 1、2、3……
    fn pulled(keys: &ChainKeys, records: &[Record], latest: u64) -> PullResponse {
        let records = records
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let item = encode(keys, r, 0).unwrap();
                Envelope {
                    id_hash: item.id_hash,
                    kind: item.kind,
                    seq: i as u64 + 1,
                    nonce: item.nonce,
                    ciphertext: item.ciphertext,
                    deleted: item.deleted,
                }
            })
            .collect();
        PullResponse { records, latest_seq: latest }
    }

    fn name_of(id: &str) -> String {
        format!("name-of-{id}")
    }

    const PROXY: &str = "Host web\n  ProxyCommand nc %h 22\n";

    #[test]
    fn local_edits_become_dirty_records_with_their_own_change_times() {
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        assert_eq!(plan_hosts(&mut space, &[block("web", "Host web\n"), block("db", "Host db\n")], "dev-a", |a| if a == "web" { 100 } else { 300 }), 2);
        assert_eq!(space.records["host:web"].record.updated_at_ms, 100);
        assert_eq!(space.records["host:db"].record.updated_at_ms, 300);
        assert!(space.records.values().all(|l| l.dirty && l.seq == 0));
        // 不變就不產生;消失 → tombstone 一次。
        assert_eq!(plan_hosts(&mut space, &[block("web", "Host web\n"), block("db", "Host db\n")], "dev-a", |_| 400), 0);
        assert_eq!(plan_hosts(&mut space, &[block("web", "Host web\n")], "dev-a", |_| 500), 1);
        assert!(space.records["host:db"].record.deleted);
        assert_eq!(plan_hosts(&mut space, &[block("web", "Host web\n")], "dev-a", |_| 600), 0);
    }

    #[test]
    fn a_pending_or_declined_remote_version_is_the_base_for_the_next_local_edit() {
        let k = keys();
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        let mut local = host("web", Some("Host web\n"), 100, "dev-a");
        local.version = 2;
        space.records.insert("host:web".into(), LocalRecord { record: local, seq: 3, dirty: false });
        // 別台把 web 改成含 ProxyCommand(時間 900):保留待核准,seq 7。
        let mut remote = host("web", Some(PROXY), 900, "dev-b");
        remote.version = 5;
        let mut p = pulled(&k, &[remote], 7);
        p.records[0].seq = 7;
        let merged = merge_space(&space, &k, &p, &[block("web", "Host web\n")], name_of);
        assert_eq!(merged.held, vec!["web".to_string()]);
        let mut space = merged.section;
        // 本機時鐘落後(時間 200)時改了 web:新版本仍要排在待核准的版本之後,以它的 seq 為 base。
        assert_eq!(plan_hosts(&mut space, &[block("web", "Host web\n  User me\n")], "dev-a", |_| 200), 1);
        let planned = &space.records["host:web"];
        assert_eq!(planned.record.version, 6);
        assert_eq!(planned.record.updated_at_ms, 901);
        assert_eq!(planned.seq, 7);
        assert!(space.pending_approvals.is_empty(), "a newer local edit supersedes the pending version");
        // 拒絕過的版本(本機沒有這台主機)也一樣:之後在本機建立它,以拒絕的版本為基準。
        let mut fresh = SpaceState::new("work-3fa2c1d9.config");
        fresh.declined.insert("db".into(), DeclinedVersion { version: 4, updated_at_ms: 800, seq: 9 });
        assert_eq!(plan_hosts(&mut fresh, &[], "dev-a", |_| 100), 0, "a declined version alone plans nothing");
        assert_eq!(plan_hosts(&mut fresh, &[block("db", "Host db\n")], "dev-a", |_| 100), 1);
        let planned = &fresh.records["host:db"];
        assert_eq!((planned.record.version, planned.record.updated_at_ms, planned.seq), (5, 801, 9));
        assert!(!planned.record.deleted);
        assert!(fresh.declined.is_empty());
    }

    #[test]
    fn remote_hosts_merge_by_lww_and_report_lost_local_edits() {
        let k = keys();
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        space.records.insert("host:web".into(), LocalRecord { record: host("web", Some("Host web\n  User a\n"), 100, "dev-a"), seq: 1, dirty: true });
        space.records.insert("host:db".into(), LocalRecord { record: host("db", Some("Host db\n"), 500, "dev-a"), seq: 2, dirty: true });
        space.records.insert("host:old".into(), LocalRecord { record: host("old", Some("Host old\n"), 50, "dev-a"), seq: 3, dirty: false });
        let p = pulled(
            &k,
            &[
                host("web", Some("Host web\n  User b\n"), 200, "dev-b"), // 遠端較新,本機有未上傳的修改 → 衝突
                host("db", Some("Host db\n  User b\n"), 400, "dev-b"),   // 本機較新 → 保留本機、更新 seq
                host("old", None, 60, "dev-b"),                          // 遠端刪除
                host("new", Some("Host new\n"), 70, "dev-b"),
            ],
            4,
        );
        let m = merge_space(&space, &k, &p, &[], name_of);
        assert_eq!(m.conflicts, vec!["web".to_string()]);
        assert_eq!(
            m.effects,
            vec![
                HostEffect::Upsert { alias: "web".into(), text: "Host web\n  User b\n".into() },
                HostEffect::Delete { alias: "old".into() },
                HostEffect::Upsert { alias: "new".into(), text: "Host new\n".into() },
            ]
        );
        assert!(!m.section.records["host:web"].dirty);
        assert!(m.section.records["host:db"].dirty);
        assert_eq!(m.section.records["host:db"].seq, 2, "the relay's seq for db");
        assert_eq!(m.section.cursor_seq, 4);
        // 只為重新上傳才 dirty 的記錄(v1 升級)輸了不算衝突。
        space.republish.insert("host:web".into());
        let quiet = merge_space(&space, &k, &p, &[], name_of);
        assert!(quiet.conflicts.is_empty());
        assert!(!quiet.section.republish.contains("host:web"));
    }

    #[test]
    fn risky_remote_changes_are_held_for_approval_and_never_applied_or_cached() {
        let k = keys();
        let space = SpaceState::new("work-3fa2c1d9.config");
        let m = merge_space(&space, &k, &pulled(&k, &[host("web", Some(PROXY), 100, "dev-b")], 1), &[], name_of);
        assert!(m.effects.is_empty());
        assert_eq!(m.held, vec!["web".to_string()]);
        assert!(!m.section.records.contains_key("host:web"), "a held record never reaches the cache");
        let pending = &m.section.pending_approvals["web"];
        assert_eq!(pending.text, PROXY);
        assert_eq!(pending.seq, 1);
        assert_eq!(pending.from_device, "name-of-dev-b");
        assert_eq!(pending.applied, signature(""));
        assert_eq!(pending.incoming.gated[0].keyword, "proxycommand");
        assert_eq!(m.section.cursor_seq, 1, "the cursor still moves on");
        // 本機已有相同簽章的區塊:照常套用。
        let same = merge_space(&space, &k, &pulled(&k, &[host("web", Some("Host web\n  ProxyCommand nc %h 22\n  User x\n"), 100, "dev-b")], 1), &[block("web", PROXY)], name_of);
        assert!(same.held.is_empty());
        assert_eq!(same.effects.len(), 1);
    }

    #[test]
    fn a_newer_version_replaces_a_pending_one_and_a_safe_or_deleting_one_clears_it() {
        let k = keys();
        let space = SpaceState::new("work-3fa2c1d9.config");
        let held = merge_space(&space, &k, &pulled(&k, &[host("web", Some(PROXY), 100, "dev-b")], 1), &[], name_of).section;
        // 較新、也要核准的版本:取代舊的 pending。
        let newer = "Host web\n  ProxyCommand nc evil.example 22\n";
        let mut p = pulled(&k, &[host("web", Some(newer), 200, "dev-c")], 2);
        p.records[0].seq = 2;
        let m = merge_space(&held, &k, &p, &[], name_of);
        assert_eq!(m.section.pending_approvals["web"].text, newer);
        assert_eq!(m.section.pending_approvals["web"].from_device, "name-of-dev-c");
        // 較新、不含受管制設定的版本:直接套用,pending 清掉。
        let mut p = pulled(&k, &[host("web", Some("Host web\n  User x\n"), 300, "dev-c")], 3);
        p.records[0].seq = 3;
        let m2 = merge_space(&m.section, &k, &p, &[], name_of);
        assert!(m2.section.pending_approvals.is_empty());
        assert_eq!(m2.effects, vec![HostEffect::Upsert { alias: "web".into(), text: "Host web\n  User x\n".into() }]);
        // 遠端刪除:照常套用,pending 清掉。
        let mut p = pulled(&k, &[host("web", None, 300, "dev-c")], 3);
        p.records[0].seq = 3;
        let m3 = merge_space(&m.section, &k, &p, &[], name_of);
        assert!(m3.section.pending_approvals.is_empty());
        assert_eq!(m3.effects, vec![HostEffect::Delete { alias: "web".into() }]);
    }

    #[test]
    fn a_newer_remote_record_clears_a_declined_version() {
        let k = keys();
        let declined = || {
            let mut space = SpaceState::new("work-3fa2c1d9.config");
            space.declined.insert("web".into(), DeclinedVersion { version: 4, updated_at_ms: 800, seq: 9 });
            space
        };
        let from_relay = |record: Record| {
            let mut p = pulled(&k, &[record], 10);
            p.records[0].seq = 10;
            p
        };
        // 較新、不含受管制設定的版本:套用,拒絕記錄清掉。
        let m = merge_space(&declined(), &k, &from_relay(host("web", Some("Host web\n  User x\n"), 900, "dev-b")), &[], name_of);
        assert!(m.section.declined.is_empty());
        assert_eq!(m.effects, vec![HostEffect::Upsert { alias: "web".into(), text: "Host web\n  User x\n".into() }]);
        // 較新、又要核准的版本:拒絕記錄清掉,改成等待核准(重新問一次)。
        let m = merge_space(&declined(), &k, &from_relay(host("web", Some(PROXY), 900, "dev-b")), &[], name_of);
        assert!(m.section.declined.is_empty());
        assert_eq!(m.held, vec!["web".to_string()]);
        assert_eq!(m.section.pending_approvals["web"].seq, 10);
        // 遠端刪除:同樣清掉。
        let m = merge_space(&declined(), &k, &from_relay(host("web", None, 900, "dev-b")), &[], name_of);
        assert!(m.section.declined.is_empty());
        assert_eq!(m.effects, vec![HostEffect::Delete { alias: "web".into() }]);
        // 別台主機的新版本不影響 web 的拒絕記錄。
        let m = merge_space(&declined(), &k, &from_relay(host("db", Some("Host db\n"), 900, "dev-b")), &[], name_of);
        assert_eq!(m.section.declined["web"], DeclinedVersion { version: 4, updated_at_ms: 800, seq: 9 });
    }

    #[test]
    fn the_declined_or_waiting_version_pulled_again_is_not_asked_again() {
        let k = keys();
        // 本機套用的是 web 與 db 較舊的那一版;別台把兩台都改成要核准的版本(seq 7、8)。
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        space.records.insert("host:web".into(), LocalRecord { record: host("web", Some("Host web\n"), 100, "dev-a"), seq: 3, dirty: false });
        space.records.insert("host:db".into(), LocalRecord { record: host("db", Some("Host db\n"), 100, "dev-a"), seq: 4, dirty: false });
        let (web, db) = (host("web", Some(PROXY), 900, "dev-b"), host("db", Some("Host db\n  ForwardAgent yes\n"), 901, "dev-b"));
        let at = |seqs: [u64; 2], latest: u64| {
            let mut p = pulled(&k, &[web.clone(), db.clone()], latest);
            p.records[0].seq = seqs[0];
            p.records[1].seq = seqs[1];
            p
        };
        let blocks = [block("web", "Host web\n"), block("db", "Host db\n")];
        let first = merge_space(&space, &k, &at([7, 8], 8), &blocks, name_of);
        assert_eq!(first.held, vec!["web".to_string(), "db".to_string()]);
        // 拒絕 web;db 還在等。
        let mut space = first.section;
        let rejected = space.pending_approvals.remove("web").unwrap();
        space.declined.insert("web".into(), DeclinedVersion { version: rejected.record.version, updated_at_ms: rejected.record.updated_at_ms, seq: 7 });
        let waiting = space.pending_approvals["db"].clone();
        // 同樣兩版從頭再拉一次(space 檔重新長出、relay 的歷史倒退之後),拿到新的序號,檔案是空的。
        space.cursor_seq = 0;
        let again = merge_space(&space, &k, &at([11, 12], 12), &[], name_of);
        assert!(again.held.is_empty(), "neither version is asked again");
        assert!(again.effects.is_empty() && again.conflicts.is_empty());
        assert_eq!(again.section.declined["web"], DeclinedVersion { version: rejected.record.version, updated_at_ms: 900, seq: 11 }, "still declined, at its new seq");
        let db_now = &again.section.pending_approvals["db"];
        assert_eq!((db_now.seq, &db_now.record, &db_now.applied), (12, &waiting.record, &waiting.applied), "the same entry still waits");
        assert_eq!(again.section.records["host:web"].record.payload["text"], "Host web\n", "the version this device applied stays");
        assert_eq!(again.section.cursor_seq, 12);
        // 歷史倒退之後只為了重新上傳才 dirty 的本機那一版:relay 上已經有較新的這一版,不再推它。
        let mut republishing = space.clone();
        for (key, local) in republishing.records.iter_mut() {
            local.dirty = true;
            republishing.republish.insert(key.clone());
        }
        let again = merge_space(&republishing, &k, &at([11, 12], 12), &[], name_of);
        assert!(again.held.is_empty() && again.conflicts.is_empty());
        assert!(again.section.records.values().all(|l| !l.dirty) && again.section.republish.is_empty());
        // 版本不同(較新的一版)照舊再問一次(`a_newer_remote_record_clears_a_declined_version`)。
        let mut newer = web.clone();
        newer.updated_at_ms = 950;
        let m = merge_space(&space, &k, &pulled(&k, &[newer], 13), &[], name_of);
        assert_eq!(m.held, vec!["web".to_string()]);
        assert!(m.section.declined.is_empty());
    }

    #[test]
    fn unpushed_local_hosts_missing_from_the_file_are_written_back() {
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        let live = |alias: &str, dirty: bool| LocalRecord { record: host(alias, Some(format!("Host {alias}\n").as_str()), 100, "dev-a"), seq: 1, dirty };
        space.records.insert("host:gone".into(), live("gone", true));
        space.records.insert("host:also".into(), live("also", true));
        // 不產生效果的:檔案裡已經有的、已經上傳的(乾淨)、dirty 的 tombstone、文字不合法的、不是 host 的。
        space.records.insert("host:here".into(), live("here", true));
        space.records.insert("host:synced".into(), live("synced", false));
        space.records.insert("host:dead".into(), LocalRecord { record: host("dead", None, 100, "dev-a"), seq: 1, dirty: true });
        space.records.insert(
            "host:bad".into(),
            LocalRecord { record: host("bad", Some("Host bad\n  Include /tmp/evil.config\n"), 100, "dev-a"), seq: 1, dirty: true },
        );
        let mut device = live("dev", true);
        device.record.kind = RecordKind::Device;
        space.records.insert("device:dev".into(), device);
        let effects = unpushed_host_effects(&space, &[block("here", "Host here\n")]);
        assert_eq!(
            effects,
            vec![
                HostEffect::Upsert { alias: "also".into(), text: "Host also\n".into() },
                HostEffect::Upsert { alias: "gone".into(), text: "Host gone\n".into() },
            ],
            "in key order"
        );
        assert!(unpushed_host_effects(&space, &[block("here", "Host here\n"), block("gone", "Host gone\n"), block("also", "Host also\n")]).is_empty());
        // 乾淨的記錄裡,有待核准或被拒絕的版本的 alias:這台目前套用的那一版也寫回(較新的那一版不會被套用)。
        space.declined.insert("synced".into(), DeclinedVersion { version: 2, updated_at_ms: 900, seq: 9 });
        let all = [block("here", "Host here\n"), block("gone", "Host gone\n"), block("also", "Host also\n")];
        assert_eq!(unpushed_host_effects(&space, &all), vec![HostEffect::Upsert { alias: "synced".into(), text: "Host synced\n".into() }]);
    }

    #[test]
    fn a_held_change_beats_an_older_unpushed_local_edit() {
        let k = keys();
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        space.records.insert("host:web".into(), LocalRecord { record: host("web", Some("Host web\n  User a\n"), 100, "dev-a"), seq: 1, dirty: true });
        let m = merge_space(&space, &k, &pulled(&k, &[host("web", Some(PROXY), 200, "dev-b")], 2), &[block("web", "Host web\n  User a\n")], name_of);
        assert_eq!(m.held, vec!["web".to_string()]);
        assert_eq!(m.conflicts, vec!["web".to_string()]);
        let local = &m.section.records["host:web"];
        assert!(!local.dirty, "the older local edit is not pushed over the newer remote one");
        assert_eq!(local.record.payload["text"], "Host web\n  User a\n", "the cache keeps the applied text");
        assert!(m.effects.is_empty());
    }

    #[test]
    fn forbidden_wildcard_broken_and_foreign_records_are_skipped_and_not_cached() {
        let k = keys();
        let space = SpaceState::new("work-3fa2c1d9.config");
        let mut device = host("dev", Some("x"), 1, "dev-b");
        device.kind = RecordKind::Device;
        let records = [
            host("web", Some("Host web\n  Include /tmp/evil.config\n"), 1, "dev-b"),
            host("db", Some("Host db\n  \"ProxyCommand\" nc evil 22\n"), 1, "dev-b"),
            // B2 的 `forbidden_directive` 擋下的其他種類:行首的 `=`、OpenSSH 讀法不同的 Host 行、會交給 shell 的值、
            // 看不見的字元 —— 同樣略過、不進快取,也不會被當成要核准的修改。
            host("app", Some("Host app\n  =Include /tmp/evil.config\n"), 1, "dev-b"),
            host("api", Some("Host api#x *\n  HostName attacker.example.net\n"), 1, "dev-b"),
            host("sh", Some("Host sh\n  HostName \"a$(echo X >&2)b\"\n  ProxyCommand true %h\n"), 1, "dev-b"),
            host("nb", Some("Host nb\n  ForwardAgent no\u{a0}\n"), 1, "dev-b"),
            host("*", Some("Host *\n  User root\n"), 1, "dev-b"),
            host("bad", Some("# not a host\n"), 1, "dev-b"),
            device,
        ];
        let mut p = pulled(&k, &records, 10);
        p.records.push(Envelope { id_hash: "ff".repeat(32), kind: "host".into(), seq: 10, nonce: "!!".into(), ciphertext: "!!".into(), deleted: false });
        let m = merge_space(&space, &k, &p, &[], name_of);
        assert_eq!(m.skipped, 10);
        assert!(m.effects.is_empty() && m.held.is_empty());
        assert!(m.section.records.is_empty());
        assert_eq!(m.section.cursor_seq, 10);
    }

    #[test]
    fn a_relay_watermark_that_went_backwards_marks_everything_for_reupload() {
        let k = keys();
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        space.cursor_seq = 9;
        space.records.insert("host:web".into(), LocalRecord { record: host("web", Some("Host web\n"), 1, "dev-a"), seq: 8, dirty: false });
        let m = merge_space(&space, &k, &PullResponse { records: Vec::new(), latest_seq: 3 }, &[], name_of);
        assert_eq!(m.section.cursor_seq, 0);
        assert!(m.section.records.values().all(|l| l.seq == 0 && l.dirty));
        let mut account = AccountState::new(&k.chain_id);
        account.cursor_seq = 9;
        let sk = keys();
        put_space_key(&mut account, &k, &sk.chain_id, Some(&sk), "dev-a", 5).unwrap();
        for s in account.sealed.values_mut() {
            s.dirty = false;
            s.envelope.seq = 8;
        }
        let a = merge_account(&account, &k, &PullResponse { records: Vec::new(), latest_seq: 2 });
        assert_eq!(a.section.cursor_seq, 0);
        assert!(a.section.sealed.values().all(|s| s.dirty && s.envelope.seq == 0));
    }

    #[test]
    fn a_rolled_back_relay_forgets_every_old_sequence_and_does_not_turn_clean_records_into_conflicts() {
        let k = keys();
        // 一個等待核准的版本(relay 上的 seq 8)、一個拒絕過的版本(seq 9)、一筆已同步的記錄(seq 8)、一筆本機還沒上傳的
        // 修改(seq 7)。
        let mut p = pulled(&k, &[host("app", Some("Host app\n  ProxyCommand nc %h 22\n"), 900, "dev-b")], 8);
        p.records[0].seq = 8;
        let mut space = merge_space(&SpaceState::new("work-3fa2c1d9.config"), &k, &p, &[], name_of).section;
        space.cursor_seq = 9;
        space.declined.insert("old".into(), DeclinedVersion { version: 4, updated_at_ms: 800, seq: 9 });
        space.records.insert("host:web".into(), LocalRecord { record: host("web", Some("Host web\n"), 100, "dev-a"), seq: 8, dirty: false });
        space.records.insert("host:db".into(), LocalRecord { record: host("db", Some("Host db\n  User me\n"), 100, "dev-a"), seq: 7, dirty: true });
        assert_eq!(space.pending_approvals["app"].seq, 8);

        let rolled = merge_space(&space, &k, &PullResponse { records: Vec::new(), latest_seq: 3 }, &[], name_of).section;
        assert_eq!(rolled.cursor_seq, 0);
        assert!(rolled.records.values().all(|l| l.seq == 0 && l.dirty));
        // 待核准與拒絕的版本記的也是舊歷史裡的序號:不歸零的話,之後本機修改會拿它們當 base_seq,以過高的序號蓋掉還原之後別台
        // 寫的新版,而且不會收到 conflict。
        assert_eq!(rolled.pending_approvals["app"].seq, 0);
        assert_eq!(rolled.declined["old"].seq, 0);
        // 原本乾淨的記錄只是為了讓 relay 重新長出來才重傳:進 `republish`。本機真的還沒上傳的修改不算。
        assert_eq!(rolled.republish.iter().cloned().collect::<Vec<_>>(), vec!["host:web".to_string()]);

        // 之後別台寫了新版:web 輸了不算本機修改被覆蓋,真正還沒上傳的 db 才是衝突。
        let newer = pulled(&k, &[host("db", Some("Host db\n  User b\n"), 500, "dev-b"), host("web", Some("Host web\n  User b\n"), 500, "dev-b")], 4);
        let m = merge_space(&rolled, &k, &newer, &[], name_of);
        assert_eq!(m.conflicts, vec!["db".to_string()]);
        assert!(!m.section.republish.contains("host:web"));
        // 還原之後在本機修改那兩台主機:新版本的 base_seq 是 0,不是還原之前的序號。
        let mut after = rolled.clone();
        let blocks = [block("web", "Host web\n"), block("db", "Host db\n  User me\n"), block("app", "Host app\n  User me\n"), block("old", "Host old\n")];
        assert_eq!(plan_hosts(&mut after, &blocks, "dev-a", |_| 100), 2);
        assert_eq!((after.records["host:app"].seq, after.records["host:old"].seq), (0, 0));
    }

    fn account_record(kind: RecordKind, id: &str, payload: Value, updated_at_ms: u64) -> Record {
        Record { kind, id: id.to_string(), version: 1, updated_at_ms, device_id: "dev-b".into(), deleted: false, payload }
    }

    #[test]
    fn account_records_are_split_into_plain_records_and_sealed_secrets() {
        let k = keys();
        let space = keys();
        let space_payload = serde_json::to_value(SpacePayload { schema: 1, name: "Work".into(), slug: "work".into(), created_at_ms: 5, previous_id: None }).unwrap();
        let records = [
            account_record(RecordKind::Space, &space.chain_id, space_payload.clone(), 10),
            account_record(RecordKind::SpaceKey, &space.chain_id, serde_json::to_value(SpaceKeyPayload::from_keys(&space)).unwrap(), 10),
            account_record(RecordKind::Meta, ACCOUNT_META_ID, serde_json::to_value(MetaPayload::account("0.17.0")).unwrap(), 10),
            account_record(RecordKind::Space, "../../etc", space_payload, 10), // id 不是 chain id → 略過
        ];
        let mut p = pulled(&k, &records, 6);
        p.records.push(Envelope { id_hash: "ee".repeat(32), kind: "future".into(), seq: 5, nonce: "n".into(), ciphertext: "c".into(), deleted: false });
        let m = merge_account(&AccountState::new(&k.chain_id), &k, &p);
        assert_eq!(m.skipped, 1);
        assert!(m.markers.is_empty());
        assert_eq!(m.section.remote_schema_version, Some(2));
        assert_eq!(space_entries(&m.section).iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), vec!["Work"]);
        assert_eq!(space_keys(&m.section, &k, &space.chain_id).unwrap().auth_token, space.auth_token);
        assert!(m.section.sealed.contains_key(&format!("future:{}", "ee".repeat(32))));
        let text = serde_json::to_string(&m.section).unwrap();
        assert!(!text.contains(&space.auth_token) && !text.contains(&space.enc_key_b64()), "secrets never reach the state");
        // 本機較新的 spacekey:保留本機,只更新 seq。
        let mut mine = m.section.clone();
        put_space_key(&mut mine, &k, &space.chain_id, Some(&space), "dev-a", 99).unwrap();
        let again = merge_account(&mine, &k, &pulled(&k, &records[1..2], 6));
        let slot = space_key_slot(&k, &space.chain_id);
        assert!(again.section.sealed[&slot].dirty);
        assert_eq!(again.section.sealed[&slot].envelope.seq, 1);
    }

    #[test]
    fn rotation_markers_are_reported() {
        let k = keys();
        let marker = RotationMarkerPayload { rotated_at_ms: 9, by_device_id: "dev-b".into(), by_device_name: "MacBook-B".into() };
        let m = merge_account(
            &AccountState::new(&k.chain_id),
            &k,
            &pulled(&k, &[account_record(RecordKind::Meta, &rotation_meta_id("dev-b"), serde_json::to_value(&marker).unwrap(), 9)], 1),
        );
        assert_eq!(m.markers, vec![marker]);
    }

    #[test]
    fn the_device_record_carries_the_selected_spaces_and_a_heartbeat() {
        let mut account = AccountState::new(&"a".repeat(64));
        let spaces = vec!["b".repeat(64)];
        assert!(plan_device(&mut account, "dev-a", "Box", "macos", &spaces, 1_000));
        let record = &account.records["device:dev-a"];
        assert!(record.dirty);
        let payload: DevicePayload = serde_json::from_value(record.record.payload.clone()).unwrap();
        assert_eq!(payload.spaces, spaces);
        assert!(!plan_device(&mut account, "dev-a", "Box", "macos", &spaces, 2_000), "nothing changed");
        assert!(plan_device(&mut account, "dev-a", "Box", "macos", &[], 3_000), "the selection changed");
        assert!(plan_device(&mut account, "dev-a", "Box", "macos", &[], 3_000 + HEARTBEAT_MS), "hourly heartbeat");
        let payload: DevicePayload = serde_json::from_value(account.records["device:dev-a"].record.payload.clone()).unwrap();
        assert_eq!(payload.joined_at_ms, 1_000, "joined_at_ms is kept");
    }

    #[test]
    fn devices_lists_live_readable_device_records_and_a_name_falls_back_to_the_id() {
        let mut account = AccountState::new(&"a".repeat(64));
        assert!(plan_device(&mut account, "dev-a", "Box", "macos", &[], 1_000));
        assert!(plan_device(&mut account, "dev-b", "Laptop", "linux", &[], 2_000));
        // 不列出:已刪除的裝置(payload 讀得懂也一樣)、payload 讀不懂的記錄、不是 device 的記錄。
        let old = DevicePayload { schema: 1, name: "Old".into(), platform: "macos".into(), joined_at_ms: 1, last_seen_ms: 1, keys: Vec::new(), spaces: Vec::new(), slots: Vec::new() };
        put_account_record(&mut account, RecordKind::Device, "dev-gone", serde_json::to_value(old).unwrap(), true, "dev-a", 3);
        put_account_record(&mut account, RecordKind::Device, "dev-junk", serde_json::json!({ "unexpected": true }), false, "dev-a", 4);
        put_account_record(&mut account, RecordKind::Meta, ACCOUNT_META_ID, serde_json::to_value(MetaPayload::account("0.17.0")).unwrap(), false, "dev-a", 5);
        let listed: Vec<(String, String)> = devices(&account).into_iter().map(|(id, payload)| (id, payload.name)).collect();
        assert_eq!(listed, vec![("dev-a".to_string(), "Box".to_string()), ("dev-b".to_string(), "Laptop".to_string())]);
        assert_eq!(device_name(&account, "dev-b"), "Laptop");
        // 查不到名稱(已刪除、讀不懂、不存在)就是 device id 本身。
        for id in ["dev-gone", "dev-junk", "nobody"] {
            assert_eq!(device_name(&account, id), id);
        }
    }

    #[test]
    fn space_key_tombstones_carry_no_secret() {
        let k = keys();
        let space = keys();
        let mut account = AccountState::new(&k.chain_id);
        put_space_key(&mut account, &k, &space.chain_id, Some(&space), "dev-a", 5).unwrap();
        put_space_key(&mut account, &k, &space.chain_id, None, "dev-a", 6).unwrap();
        let record = account.sealed[&space_key_slot(&k, &space.chain_id)].open(&k).unwrap();
        assert!(record.deleted);
        assert_eq!(record.version, 2);
        assert_eq!(record.payload, Value::Null);
        assert!(space_keys(&account, &k, &space.chain_id).is_none());
    }

    #[test]
    fn a_space_key_that_belongs_to_another_chain_is_refused() {
        let k = keys();
        let (space, other) = (keys(), keys());
        let mut account = AccountState::new(&k.chain_id);
        // 另一條 chain 的權杖與金鑰不能記在這個 space 的 id 底下:讀到這筆 `spacekey` 的電腦會拿錯的權杖去連這個 space。
        let error = put_space_key(&mut account, &k, &space.chain_id, Some(&other), "dev-a", 5).unwrap_err().to_string();
        assert!(account.sealed.is_empty(), "nothing was written");
        assert!(!error.contains(&other.auth_token) && !error.contains(&space.auth_token), "{error}");
        // tombstone 不帶金鑰,沒有對不對得上的問題;對得上的金鑰照常寫入。
        put_space_key(&mut account, &k, &space.chain_id, None, "dev-a", 6).unwrap();
        put_space_key(&mut account, &k, &space.chain_id, Some(&space), "dev-a", 7).unwrap();
        assert_eq!(space_keys(&account, &k, &space.chain_id).unwrap().auth_token, space.auth_token);
    }

    #[test]
    fn a_space_is_deleted_when_either_of_its_records_is_a_tombstone() {
        let k = keys();
        let space = keys();
        let mut account = AccountState::new(&k.chain_id);
        let payload = serde_json::to_value(SpacePayload { schema: 1, name: "Work".into(), slug: "work".into(), created_at_ms: 1, previous_id: None }).unwrap();
        put_account_record(&mut account, RecordKind::Space, &space.chain_id, payload.clone(), false, "dev-a", 1);
        assert_eq!(space_deleted_by(&account, &k, &space.chain_id), None, "a key that has not arrived is not a delete");
        put_space_key(&mut account, &k, &space.chain_id, Some(&space), "dev-a", 1).unwrap();
        assert_eq!(space_deleted_by(&account, &k, &space.chain_id), None);
        put_space_key(&mut account, &k, &space.chain_id, None, "dev-b", 2).unwrap();
        assert_eq!(space_deleted_by(&account, &k, &space.chain_id).as_deref(), Some("dev-b"), "a live name with a deleted key");
        put_account_record(&mut account, RecordKind::Space, &space.chain_id, payload, true, "dev-c", 3);
        assert_eq!(space_deleted_by(&account, &k, &space.chain_id).as_deref(), Some("dev-c"));
    }

    #[test]
    fn pushes_are_batched_and_accepted_records_become_clean() {
        let relay = FakeRelay::new();
        let k = keys();
        relay.create_chain(&k.chain_id, &k.auth_token).unwrap();
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        let blocks: Vec<HostBlockText> = (0..450).map(|i| block(&format!("h{i}"), &format!("Host h{i}\n"))).collect();
        plan_hosts(&mut space, &blocks, "dev-a", |_| 100);
        let outgoing = space_outgoing(&space, &k).unwrap();
        let pushed = push_outgoing(relay.as_ref(), &k.chain_id, &k.auth_token, &outgoing);
        assert!(pushed.error.is_none() && !pushed.frozen);
        assert_eq!(pushed.accepted.len(), 450);
        assert_eq!(relay.calls().iter().filter(|c| c.starts_with("push:")).count(), 3, "200 + 200 + 50");
        apply_pushed_space(&mut space, &outgoing, &pushed);
        assert!(space.records.values().all(|l| !l.dirty && l.seq > 0));
        // 同一批再推一次(base_seq 0 的舊版):relay 較新 → 衝突、保持 dirty。
        let mut stale = SpaceState::new("work-3fa2c1d9.config");
        plan_hosts(&mut stale, &blocks[..1], "dev-b", |_| 50);
        let stale_out = space_outgoing(&stale, &k).unwrap();
        let pushed = push_outgoing(relay.as_ref(), &k.chain_id, &k.auth_token, &stale_out);
        assert!(pushed.error.is_none());
        assert_eq!((pushed.accepted.len(), pushed.conflicts), (0, 1));
        apply_pushed_space(&mut stale, &stale_out, &pushed);
        assert!(stale.records["host:h0"].dirty);
    }

    #[test]
    fn a_frozen_chain_stops_the_upload() {
        let relay = FakeRelay::new();
        let k = keys();
        relay.create_chain(&k.chain_id, &k.auth_token).unwrap();
        relay.freeze_chain(&k.chain_id, &k.auth_token).unwrap();
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        plan_hosts(&mut space, &[block("web", "Host web\n")], "dev-a", |_| 100);
        let outgoing = space_outgoing(&space, &k).unwrap();
        let pushed = push_outgoing(relay.as_ref(), &k.chain_id, &k.auth_token, &outgoing);
        assert!(pushed.frozen);
        assert!(pushed.error.is_none(), "a frozen chain is not a failed push");
        assert!(pushed.accepted.is_empty());
        assert!(relay.rows(&k.chain_id).is_empty(), "nothing is written to a frozen chain");
    }

    /// 照劇本回答 `push` 的 relay(其他呼叫都不該發生):測 `push_outgoing` 面對各種答案時的處理。劇本用完還有批次要送,
    /// 就是 `push_outgoing` 多送了。
    struct Scripted(std::cell::RefCell<std::collections::VecDeque<Result<PushOutcome, RelayError>>>);

    impl Scripted {
        fn new(answers: Vec<Result<PushOutcome, RelayError>>) -> Self {
            Self(std::cell::RefCell::new(answers.into()))
        }

        fn unused(&self) -> usize {
            self.0.borrow().len()
        }
    }

    impl RelayApi for Scripted {
        fn info(&self) -> Result<RelayInfo, RelayError> {
            unreachable!("only push is scripted")
        }
        fn create_chain(&self, _: &str, _: &str) -> Result<(), RelayError> {
            unreachable!("only push is scripted")
        }
        fn delete_chain(&self, _: &str, _: &str) -> Result<(), RelayError> {
            unreachable!("only push is scripted")
        }
        fn freeze_chain(&self, _: &str, _: &str) -> Result<(), RelayError> {
            unreachable!("only push is scripted")
        }
        fn pull(&self, _: &str, _: &str, _: u64) -> Result<PullResponse, RelayError> {
            unreachable!("only push is scripted")
        }
        fn pull_batch(&self, _: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError> {
            unreachable!("only push is scripted")
        }
        fn push(&self, _: &str, _: &str, _: &[PushItem]) -> Result<PushOutcome, RelayError> {
            self.0.borrow_mut().pop_front().expect("push_outgoing sent a batch nobody scripted")
        }
    }

    /// relay 收下一批裡的 `n` 筆(seq 1..=n)。
    fn accepted(n: u64) -> PushOutcome {
        PushOutcome::Applied((1..=n).map(|seq| PushResult::Accepted { seq }).collect())
    }

    /// 450 筆 dirty 的主機記錄 = 三批(200 + 200 + 50)。
    fn three_batches_of_dirty_hosts(keys: &ChainKeys) -> (SpaceState, Vec<Outgoing>) {
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        let blocks: Vec<HostBlockText> = (0..450).map(|i| block(&format!("h{i}"), &format!("Host h{i}\n"))).collect();
        plan_hosts(&mut space, &blocks, "dev-a", |_| 100);
        let outgoing = space_outgoing(&space, keys).unwrap();
        (space, outgoing)
    }

    #[test]
    fn a_failed_batch_keeps_what_the_earlier_batches_got_accepted() {
        let relay = FakeRelay::new();
        let k = keys();
        relay.create_chain(&k.chain_id, &k.auth_token).unwrap();
        let (mut space, outgoing) = three_batches_of_dirty_hosts(&k);
        // chain 的額度滿了:第一批照常收下,第二批起回 413。
        relay.set_push_quota(Some(1));
        let pushed = push_outgoing(relay.as_ref(), &k.chain_id, &k.auth_token, &outgoing);
        assert!(matches!(pushed.error, Some(RelayError::QuotaExceeded)), "{:?}", pushed.error);
        assert!(!pushed.frozen);
        assert_eq!(pushed.accepted.len(), 200, "the first batch was accepted");
        assert!(pushed.accepted.iter().map(|(key, _)| key).eq(outgoing[..200].iter().map(|o| &o.key)), "exactly the first batch, in order");
        assert_eq!(relay.calls().iter().filter(|c| c.starts_with("push:")).count(), 2, "it stops at the failing batch");
        assert_eq!(relay.rows(&k.chain_id).len(), 200);
        // 呼叫端先套用被收下的 200 筆:正好這些變乾淨,其餘 250 筆仍是 dirty。
        apply_pushed_space(&mut space, &outgoing, &pushed);
        assert!(pushed.accepted.iter().all(|(key, seq)| !space.records[key].dirty && space.records[key].seq == *seq));
        assert_eq!(space.records.values().filter(|l| !l.dirty).count(), 200);
        // 額度恢復之後下一輪只送剩下的 250 筆(200 + 50),不會重送前面的。
        let rest = space_outgoing(&space, &k).unwrap();
        assert_eq!(rest.len(), 250);
        relay.set_push_quota(None);
        relay.clear_calls();
        let again = push_outgoing(relay.as_ref(), &k.chain_id, &k.auth_token, &rest);
        assert!(again.error.is_none());
        assert_eq!((again.accepted.len(), again.conflicts), (250, 0));
        assert_eq!(relay.calls().iter().filter(|c| c.starts_with("push:")).count(), 2);
        apply_pushed_space(&mut space, &rest, &again);
        assert!(space.records.values().all(|l| !l.dirty && l.seq > 0));
        assert_eq!(relay.rows(&k.chain_id).len(), 450);
    }

    #[test]
    fn a_push_that_stops_halfway_reports_the_error_and_the_batches_before_it() {
        let k = keys();
        let (_, outgoing) = three_batches_of_dirty_hosts(&k);
        for failure in [RelayError::RateLimited, RelayError::Http(503), RelayError::Unreachable("down".to_string()), RelayError::QuotaExceeded] {
            let expected = format!("{failure:?}");
            let relay = Scripted::new(vec![Ok(accepted(200)), Err(failure)]);
            let pushed = push_outgoing(&relay, &k.chain_id, &k.auth_token, &outgoing);
            assert_eq!(pushed.accepted.len(), 200, "{expected}");
            assert_eq!(format!("{:?}", pushed.error.as_ref().expect("the failure is reported")), expected);
            assert!(!pushed.frozen);
            assert_eq!(relay.unused(), 0, "the third batch is never sent");
        }
        // 第一批就失敗:什麼都沒收下,錯誤照樣經 `error` 回報。
        let relay = Scripted::new(vec![Err(RelayError::RateLimited)]);
        let pushed = push_outgoing(&relay, &k.chain_id, &k.auth_token, &outgoing);
        assert!(pushed.accepted.is_empty() && matches!(pushed.error, Some(RelayError::RateLimited)));
        // 中途才發現 chain 被凍結:前面收下的保留、`frozen` 為真、不是錯誤,後面的不送。
        let relay = Scripted::new(vec![Ok(accepted(200)), Ok(PushOutcome::Frozen)]);
        let pushed = push_outgoing(&relay, &k.chain_id, &k.auth_token, &outgoing);
        assert_eq!(pushed.accepted.len(), 200);
        assert!(pushed.frozen && pushed.error.is_none());
        assert_eq!(relay.unused(), 0);
        // 衝突不是失敗:那幾筆保持 dirty(不在 accepted)、只計數,後面的批次照送。
        let conflict = |o: &Outgoing| PushResult::Conflict {
            current: Envelope { id_hash: o.item.id_hash.clone(), kind: "host".into(), seq: 9, nonce: "n".into(), ciphertext: "c".into(), deleted: false },
        };
        let first: Vec<PushResult> = outgoing[..200].iter().map(conflict).collect();
        let relay = Scripted::new(vec![Ok(PushOutcome::Applied(first)), Ok(accepted(200)), Ok(accepted(50))]);
        let pushed = push_outgoing(&relay, &k.chain_id, &k.auth_token, &outgoing);
        assert_eq!((pushed.accepted.len(), pushed.conflicts), (250, 200));
        assert!(pushed.error.is_none() && !pushed.frozen);
        assert_eq!(relay.unused(), 0);
    }

    #[test]
    fn an_answer_that_does_not_line_up_with_the_batch_is_an_error_and_none_of_it_is_applied() {
        let k = keys();
        let (_, outgoing) = three_batches_of_dirty_hosts(&k);
        // 第一批的答案少一筆、或多一筆:整批不採用(逐筆 zip 會把結果算到錯的記錄上、或悄悄漏掉一筆),記為 BadResponse、停止。
        for answered in [199, 201] {
            let relay = Scripted::new(vec![Ok(accepted(answered))]);
            let pushed = push_outgoing(&relay, &k.chain_id, &k.auth_token, &outgoing);
            assert!(pushed.accepted.is_empty(), "{answered} results for 200 records: none of them is trusted");
            assert!(matches!(pushed.error, Some(RelayError::BadResponse(_))), "{:?}", pushed.error);
            assert!(!pushed.frozen && pushed.conflicts == 0);
            assert_eq!(relay.unused(), 0);
        }
        // 第二批才對不上:第一批照樣保留。錯誤訊息只有筆數,沒有記錄的內容。
        let relay = Scripted::new(vec![Ok(accepted(200)), Ok(accepted(0))]);
        let pushed = push_outgoing(&relay, &k.chain_id, &k.auth_token, &outgoing);
        assert_eq!(pushed.accepted.len(), 200);
        let Some(RelayError::BadResponse(message)) = &pushed.error else { panic!("{:?}", pushed.error) };
        assert_eq!(message, "a push of 200 records was answered with 0 results");
    }

    #[test]
    fn a_batch_is_cut_at_512_kib_even_with_far_fewer_than_200_records() {
        let k = keys();
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        // 12 筆、每筆密文約 60 KB(在 relay 單筆 64 KiB 的上限之下):512 KiB 放得下 8 筆,所以是 8 + 4,不是一批。
        let big = "x".repeat(45_000);
        let blocks: Vec<HostBlockText> = (0..12).map(|i| block(&format!("h{i:02}"), &format!("Host h{i:02}\n  # {big}\n"))).collect();
        plan_hosts(&mut space, &blocks, "dev-a", |_| 100);
        let outgoing = space_outgoing(&space, &k).unwrap();
        let size = outgoing[0].item.ciphertext.len() + outgoing[0].item.nonce.len();
        assert!(outgoing.iter().all(|o| o.item.ciphertext.len() + o.item.nonce.len() == size));
        assert!(size < 64 * 1024, "{size}");
        assert_eq!(PUSH_BATCH_BYTES / size, 8, "the fixture fits 8 records into 512 KiB ({size} bytes each)");
        // 額度只夠第一批:被收下的正好是 8 筆,第一批就是在位元組的上限切的。
        let relay = FakeRelay::new();
        relay.create_chain(&k.chain_id, &k.auth_token).unwrap();
        relay.set_push_quota(Some(1));
        let first = push_outgoing(relay.as_ref(), &k.chain_id, &k.auth_token, &outgoing);
        assert_eq!(first.accepted.len(), 8);
        assert!(matches!(first.error, Some(RelayError::QuotaExceeded)));
        // 沒有額度限制:兩次 push(8 + 4)送完 12 筆。
        let relay = FakeRelay::new();
        relay.create_chain(&k.chain_id, &k.auth_token).unwrap();
        let all = push_outgoing(relay.as_ref(), &k.chain_id, &k.auth_token, &outgoing);
        assert!(all.error.is_none());
        assert_eq!(all.accepted.len(), 12);
        assert_eq!(relay.calls().iter().filter(|c| c.starts_with("push:")).count(), 2);
    }

    #[test]
    fn account_uploads_include_dirty_sealed_space_keys() {
        let relay = FakeRelay::new();
        let k = keys();
        relay.create_chain(&k.chain_id, &k.auth_token).unwrap();
        let space = keys();
        let mut account = AccountState::new(&k.chain_id);
        put_account_record(&mut account, RecordKind::Meta, ACCOUNT_META_ID, serde_json::to_value(MetaPayload::account("0.17.0")).unwrap(), false, "dev-a", 5);
        put_space_key(&mut account, &k, &space.chain_id, Some(&space), "dev-a", 5).unwrap();
        let outgoing = account_outgoing(&account, &k).unwrap();
        assert_eq!(outgoing.len(), 2);
        let pushed = push_outgoing(relay.as_ref(), &k.chain_id, &k.auth_token, &outgoing);
        assert!(pushed.error.is_none());
        apply_pushed_account(&mut account, &outgoing, &pushed);
        assert!(account.records.values().all(|l| !l.dirty));
        assert!(account.sealed.values().all(|s| !s.dirty && s.envelope.seq > 0));
        // relay 上的就是同一份密文:另一台拉下來能解開。
        let back = merge_account(&AccountState::new(&k.chain_id), &k, &relay.pull(&k.chain_id, &k.auth_token, 0).unwrap());
        assert_eq!(space_keys(&back.section, &k, &space.chain_id).unwrap().auth_token, space.auth_token);
    }

    #[test]
    fn include_tokens_follow_the_account_names() {
        let k = keys();
        let (a, b) = (keys(), keys());
        let mut account = AccountState::new(&k.chain_id);
        for (id, name) in [(&a.chain_id, "Work"), (&b.chain_id, "home")] {
            let payload = SpacePayload { schema: 1, name: name.into(), slug: crate::sync::space_files::slugify(name), created_at_ms: 1, previous_id: None };
            put_account_record(&mut account, RecordKind::Space, id, serde_json::to_value(payload).unwrap(), false, "dev-a", 1);
        }
        let mut spaces = std::collections::BTreeMap::new();
        for (id, name) in [(&a.chain_id, "work"), (&b.chain_id, "home")] {
            spaces.insert(id.clone(), SpaceState::new(&crate::sync::space_files::space_file_name(name, id).unwrap()));
        }
        let tokens = selected_include_tokens(Some(&account), &spaces).unwrap();
        assert_eq!(tokens.len(), 2);
        assert!(tokens[0].contains("home-"), "home sorts before Work: {tokens:?}");
        spaces.get_mut(&a.chain_id).unwrap().selected = false;
        assert_eq!(selected_include_tokens(Some(&account), &spaces).unwrap().len(), 1, "a half-unselected space is not listed");
    }
}
