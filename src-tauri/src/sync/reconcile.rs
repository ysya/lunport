//! 一輪同步拆成三段純函式(spec §6):`plan_local`(本機 diff + 心跳,呼叫端立刻持久化)→
//! `pull_merge`(拉取、解密、LWW 合併;回傳「合併後的狀態」與要套到檔案的效果,呼叫端在指紋
//! 守衛下套用成功後才採用)→ `push_dirty`(分批上傳;只更新每筆的 seq,絕不動 cursor)。
//! 不碰檔案、不碰 Tauri;中繼以 trait 注入,測試用記憶體假中繼模擬多台裝置。

use crate::error::AppError;
use crate::sync::crypto::{self, ChainKeys, Sealed};
use crate::sync::hosts_file::{is_syncable_alias, validate_host_text, HostBlockText};
use crate::sync::planner::{detect_local_changes, next_timestamp};
use crate::sync::record::{
    merge, record_key, DevicePayload, Envelope, HostPayload, LocalRecord, MergeOutcome, MetaPayload, Record, RecordKind,
    SCHEMA_VERSION,
};
use crate::sync::relay::{PullResponse, PushItem, PushResult};
use crate::sync::state::SyncState;

/// 中繼抽象:引擎只依賴 pull/push,測試以記憶體實作模擬多台裝置。
pub trait Relay {
    fn pull(&self, chain_id: &str, since: u64) -> Result<PullResponse, AppError>;
    fn push(&self, chain_id: &str, items: &[PushItem]) -> Result<Vec<PushResult>, AppError>;
}

impl Relay for crate::sync::relay::RelayClient {
    fn pull(&self, chain_id: &str, since: u64) -> Result<PullResponse, AppError> {
        crate::sync::relay::RelayClient::pull(self, chain_id, since)
    }
    fn push(&self, chain_id: &str, items: &[PushItem]) -> Result<Vec<PushResult>, AppError> {
        crate::sync::relay::RelayClient::push(self, chain_id, items)
    }
}

/// 遠端 host 記錄要套到受管檔的效果。沒有第三種:格式不支援的記錄只會被略過。
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

/// `pull_merge` 的結果。`state` 是合併後的完整新狀態(含 `cursor_seq`);呼叫端在指紋守衛下
/// 把 `host_effects` 寫進檔案成功後才用它取代 runtime 的狀態 —— 失敗就整份丟棄,下一輪重拉。
#[derive(Clone, Debug)]
pub struct Merged {
    pub state: SyncState,
    pub host_effects: Vec<HostEffect>,
    /// 本機未上傳的修改被較新的遠端蓋掉的 alias。
    pub conflicts: Vec<String>,
    /// 解不開/身分不符/格式不支援/wildcard 而略過的 envelope 數。
    pub skipped: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Pushed {
    pub accepted: usize,
    /// 中繼比本機新的筆數:本輪不處理,呼叫端應立刻再跑一輪(pull 會拿到)。
    pub conflicts: usize,
}

const HEARTBEAT_MS: u64 = 60 * 60 * 1000;
const PUSH_BATCH_ITEMS: usize = 200;
const PUSH_BATCH_BYTES: usize = 512 * 1024;
/// 本版會解密進 `records` 的種類;其他一律原樣留在 `sealed`。
const HANDLED_KINDS: [RecordKind; 3] = [RecordKind::Host, RecordKind::Device, RecordKind::Meta];

pub fn own_device_record(state: &SyncState, now_ms: u64, platform: &str) -> Record {
    let key = record_key(RecordKind::Device, &state.device_id);
    let previous = state.records.get(&key).map(|l| &l.record);
    let joined_at_ms = previous
        .and_then(|r| serde_json::from_value::<DevicePayload>(r.payload.clone()).ok())
        .map(|p| p.joined_at_ms)
        .unwrap_or(now_ms);
    Record {
        kind: RecordKind::Device,
        id: state.device_id.clone(),
        version: previous.map(|r| r.version + 1).unwrap_or(1),
        updated_at_ms: next_timestamp(now_ms, previous.map(|r| r.updated_at_ms)),
        device_id: state.device_id.clone(),
        deleted: false,
        payload: serde_json::to_value(DevicePayload {
            schema: SCHEMA_VERSION,
            name: state.device_name.clone(),
            platform: platform.to_string(),
            joined_at_ms,
            last_seen_ms: now_ms,
            keys: Vec::new(),
        })
        .expect("DevicePayload serializes"),
    }
}

/// 第一段:本機 diff → dirty 記錄(保留既有 seq 當 base_seq),加上至多每小時一次的裝置心跳。
/// `changed_at(alias)` 是該區塊的修改時間(app 存檔當下或外部編輯的檔案 mtime),記錄的時間戳用它;
/// 心跳才用 `now_ms`。呼叫端必須在任何網路操作前把 state 持久化:重試沿用同一版本與時間戳。
pub fn plan_local(
    state: &mut SyncState,
    current: &[HostBlockText],
    changed_at: impl Fn(&str) -> u64,
    now_ms: u64,
    platform: &str,
) -> usize {
    let mut changed = 0;
    for record in detect_local_changes(&state.records, current, &state.device_id, changed_at) {
        let key = record_key(record.kind, &record.id);
        let seq = state.records.get(&key).map(|l| l.seq).unwrap_or(0);
        state.records.insert(key, LocalRecord { record, seq, dirty: true });
        changed += 1;
    }
    let device_key = record_key(RecordKind::Device, &state.device_id);
    let stale = state
        .records
        .get(&device_key)
        .and_then(|l| serde_json::from_value::<DevicePayload>(l.record.payload.clone()).ok())
        .map(|p| now_ms.saturating_sub(p.last_seen_ms) >= HEARTBEAT_MS)
        .unwrap_or(true);
    if stale {
        let record = own_device_record(state, now_ms, platform);
        let seq = state.records.get(&device_key).map(|l| l.seq).unwrap_or(0);
        state.records.insert(device_key, LocalRecord { record, seq, dirty: true });
        changed += 1;
    }
    changed
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
    let kind = RecordKind::parse(&env.kind)
        .ok_or_else(|| AppError::Other(format!("unknown record kind '{}'", env.kind)))?;
    let sealed = Sealed { id_hash: env.id_hash.clone(), nonce: env.nonce.clone(), ciphertext: env.ciphertext.clone() };
    let plaintext = crypto::open(keys, &env.kind, &env.id_hash, &sealed)?;
    let record: Record = serde_json::from_slice(&plaintext)
        .map_err(|e| AppError::Other(format!("record payload is unreadable: {e}")))?;
    if record.kind != kind || crypto::id_hash(keys, record.kind.as_str(), &record.id) != env.id_hash {
        return Err(AppError::Other("record identity does not match its envelope".to_string()));
    }
    Ok(record)
}

/// 遠端 host 記錄 → 效果。tombstone → Delete;文字通過 `validate_host_text`(只含一個具名 Host 區塊、
/// alias 相符、無 wildcard)→ Upsert;其他 → None(略過,且不進快取 —— 否則套用失敗的記錄會在
/// 下一輪被當成「快取有、檔案沒有」而產生 tombstone,把別台的主機刪掉)。
fn host_effect(record: &Record) -> Option<HostEffect> {
    if !is_syncable_alias(&record.id) {
        return None;
    }
    if record.deleted {
        return Some(HostEffect::Delete { alias: record.id.clone() });
    }
    let text = serde_json::from_value::<HostPayload>(record.payload.clone()).ok()?.text;
    validate_host_text(&record.id, &text).ok()?;
    Some(HostEffect::Upsert { alias: record.id.clone(), text })
}

#[derive(Default)]
struct Accumulator {
    host_effects: Vec<HostEffect>,
    conflicts: Vec<String>,
    skipped: u32,
}

/// 把一筆遠端記錄合併進狀態副本;host 記錄的效果與衝突收進 accumulator。
fn take_remote(state: &mut SyncState, record: Record, seq: u64, acc: &mut Accumulator) {
    let key = record_key(record.kind, &record.id);
    match merge(state.records.get(&key), &record) {
        MergeOutcome::KeepLocal => {
            // 本機較新:把 seq 更新到中繼現況,下次 push 才不會再撞 conflict。
            if let Some(local) = state.records.get_mut(&key) {
                local.seq = seq;
            }
        }
        outcome => {
            if record.kind == RecordKind::Host {
                match host_effect(&record) {
                    Some(effect) => {
                        if outcome == MergeOutcome::RemoteWinsOverDirtyLocal {
                            acc.conflicts.push(record.id.clone());
                        }
                        acc.host_effects.push(effect);
                    }
                    None => {
                        // 格式不支援 / 文字不合法 / wildcard:不套用、不覆蓋本機快取、絕不當成刪除。
                        acc.skipped += 1;
                        return;
                    }
                }
            }
            if record.kind == RecordKind::Meta {
                if let Ok(meta) = serde_json::from_value::<MetaPayload>(record.payload.clone()) {
                    state.remote_schema_version = Some(meta.schema_version);
                }
            }
            state.records.insert(key, LocalRecord { record, seq, dirty: false });
        }
    }
}

/// 第二段:pull → 解密 → LWW 合併。純函式:回傳合併後的新狀態,不改傳入的 state。
pub fn pull_merge(state: &SyncState, keys: &ChainKeys, relay: &dyn Relay) -> Result<Merged, AppError> {
    let chain_id = state.chain_id.clone().ok_or_else(|| AppError::Other("not in a sync chain".to_string()))?;
    let pulled = relay.pull(&chain_id, state.cursor_seq)?;
    let mut next = state.clone();
    let mut acc = Accumulator::default();
    for env in &pulled.records {
        match RecordKind::parse(&env.kind) {
            Some(kind) if HANDLED_KINDS.contains(&kind) => match decode(keys, env) {
                Ok(record) => take_remote(&mut next, record, env.seq, &mut acc),
                Err(_) => acc.skipped += 1,
            },
            _ => {
                // 本版不處理的種類(key/password/未知):原樣保留、永不解密(spec §2/§6)。
                next.sealed.insert(format!("{}:{}", env.kind, env.id_hash), env.clone());
            }
        }
    }
    // cursor 只跟 pull 的 watermark 走。不取 max:cursor 會停在中繼要很久才到得了的序號,這段期間別台裝置寫入
    // 的記錄全部被跳過。
    if pulled.latest_seq < state.cursor_seq {
        // watermark 比 cursor 還小 = 中繼的歷史倒退了(自架的中繼從舊備份還原、或被重置):中繼上可能少了我們
        // 早就看過、甚至是我們自己推上去的記錄。只把 cursor 歸零重拉補不回來 —— 本機勝出的乾淨記錄會保留、卻
        // 永遠不再上傳,中繼(與之後加入的裝置)就一直缺著。所以 cursor 歸零,並把每一筆快取的記錄
        // (host/device/meta)標成 `seq = 0`、dirty:接下來的輪次從 0 重拉(KeepLocal 把 seq 更新成中繼現況、
        // 遠端較新的照常取代本機),再把中繼缺的推回去(中繼沒有那一列 → 新建)。`seq = 0` 讓中繼上還有的
        // 記錄先回 conflict、經過一次合併才覆寫,不會蓋掉還原之後別台裝置寫的新版。代價:一次整份重傳;遠端
        // 較新的主機會以「覆寫了本機修改」通知(本機的 dirty 是這裡標的)。`sealed` 裡的密文不重推(Phase B
        // 種類的已知限制)。偵測不到的情況:中繼還原之後、我們 pull 之前,中繼的序號已經追到 ≥ 我們的 cursor
        // (別台裝置推了夠多)—— watermark 看起來正常,中間那段記錄照樣被跳過;要分辨得出來,中繼得有 epoch
        // (協定變更)。
        next.cursor_seq = 0;
        for local in next.records.values_mut() {
            local.seq = 0;
            local.dirty = true;
        }
    } else {
        next.cursor_seq = pulled.latest_seq;
    }
    Ok(Merged { state: next, host_effects: acc.host_effects, conflicts: acc.conflicts, skipped: acc.skipped })
}

/// 基線輪要寫回受管檔的本機修改(純函式)。受管檔不見了或被清空、從 chain 重新長出時
/// (`engine::reset_hosts_for_rematerialize`),還沒上傳的 host 記錄會留在快取裡;合併之後仍是 dirty 的就是
/// 還贏 LWW 的本機修改(輸的已經被遠端版取代、不再 dirty)—— 中繼上只有較舊的版本(KeepLocal,不產生效果)
/// 或根本沒有,不寫回的話檔案裡就少了它們。所以:dirty、未刪除、而受管檔目前的區塊(`blocks`)裡沒有這個
/// alias 的 host 記錄 → 以記錄自己的 alias 與文字 Upsert。dirty 的 tombstone 不產生效果(照常推送);乾淨的
/// 記錄交給 chain;檔案裡已經有的區塊不動。文字經過與遠端記錄相同的檢查(`host_effect`),所以套用不會失敗。
/// 剛 Join 的快取裡沒有 host 記錄,結果一定是空的。
pub fn unpushed_host_effects(state: &SyncState, blocks: &[HostBlockText]) -> Vec<HostEffect> {
    state
        .records
        .values()
        .filter(|l| l.dirty && l.record.kind == RecordKind::Host && !l.record.deleted)
        .filter(|l| !blocks.iter().any(|b| b.alias == l.record.id))
        .filter_map(|l| host_effect(&l.record))
        .collect()
}

fn send_batch(
    state: &mut SyncState,
    relay: &dyn Relay,
    chain_id: &str,
    batch: &[(String, PushItem)],
    pushed: &mut Pushed,
) -> Result<(), AppError> {
    let items: Vec<PushItem> = batch.iter().map(|(_, item)| item.clone()).collect();
    let results = relay.push(chain_id, &items)?;
    if results.len() != items.len() {
        return Err(AppError::Other("relay answered with the wrong number of results".to_string()));
    }
    for ((key, _), result) in batch.iter().zip(results) {
        match result {
            PushResult::Accepted { seq } => {
                if let Some(local) = state.records.get_mut(key) {
                    local.seq = seq;
                    local.dirty = false;
                }
                pushed.accepted += 1;
            }
            // 中繼比本機新:保持 dirty,下一輪 pull 會拿到中繼版本再合併(spec §6 第 5 步)。
            PushResult::Conflict { .. } => pushed.conflicts += 1,
        }
    }
    Ok(())
}

/// 第三段:分批上傳 dirty 記錄。accepted 只更新該筆 seq/dirty,**絕不推進 cursor**;唯讀模式不上傳。
pub fn push_dirty(state: &mut SyncState, keys: &ChainKeys, relay: &dyn Relay) -> Result<Pushed, AppError> {
    let chain_id = state.chain_id.clone().ok_or_else(|| AppError::Other("not in a sync chain".to_string()))?;
    let mut pushed = Pushed::default();
    if state.read_only() {
        return Ok(pushed);
    }
    let dirty_keys: Vec<String> = state.records.iter().filter(|(_, l)| l.dirty).map(|(k, _)| k.clone()).collect();
    let mut batch: Vec<(String, PushItem)> = Vec::new();
    let mut batch_bytes = 0usize;
    for key in dirty_keys {
        let Some(local) = state.records.get(&key) else { continue };
        let item = encode(keys, &local.record, local.seq)?;
        let size = item.ciphertext.len() + item.nonce.len();
        if !batch.is_empty() && (batch.len() >= PUSH_BATCH_ITEMS || batch_bytes + size > PUSH_BATCH_BYTES) {
            send_batch(state, relay, &chain_id, &batch, &mut pushed)?;
            batch.clear();
            batch_bytes = 0;
        }
        batch_bytes += size;
        batch.push((key, item));
    }
    if !batch.is_empty() {
        send_batch(state, relay, &chain_id, &batch, &mut pushed)?;
    }
    Ok(pushed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// 記憶體假中繼,語意與 relay Worker 相同:單調 seq、stale base_seq → conflict。
    #[derive(Default)]
    struct FakeRelay {
        rows: RefCell<BTreeMap<String, Envelope>>,
        latest: RefCell<u64>,
        push_calls: RefCell<u32>,
    }

    impl Relay for FakeRelay {
        fn pull(&self, _chain: &str, since: u64) -> Result<PullResponse, AppError> {
            let mut records: Vec<Envelope> = self.rows.borrow().values().filter(|e| e.seq > since).cloned().collect();
            records.sort_by_key(|e| e.seq);
            Ok(PullResponse { records, latest_seq: *self.latest.borrow() })
        }

        fn push(&self, _chain: &str, items: &[PushItem]) -> Result<Vec<PushResult>, AppError> {
            *self.push_calls.borrow_mut() += 1;
            let mut out = Vec::new();
            for item in items {
                let mut rows = self.rows.borrow_mut();
                if let Some(current) = rows.get(&item.id_hash) {
                    if current.seq > item.base_seq {
                        out.push(PushResult::Conflict { current: current.clone() });
                        continue;
                    }
                }
                *self.latest.borrow_mut() += 1;
                let seq = *self.latest.borrow();
                rows.insert(
                    item.id_hash.clone(),
                    Envelope {
                        id_hash: item.id_hash.clone(),
                        kind: item.kind.clone(),
                        seq,
                        nonce: item.nonce.clone(),
                        ciphertext: item.ciphertext.clone(),
                        deleted: item.deleted,
                    },
                );
                out.push(PushResult::Accepted { seq });
            }
            Ok(out)
        }
    }

    fn keys() -> ChainKeys {
        crypto::derive_keys(WORDS).unwrap()
    }

    fn device(name: &str) -> SyncState {
        let mut s = SyncState::fresh(name).unwrap();
        s.chain_id = Some(keys().chain_id);
        s.device_id = format!("{:0<32}", name); // 固定、可預期的字典序
        s
    }

    fn block(alias: &str, text: &str) -> HostBlockText {
        HostBlockText { alias: alias.to_string(), text: text.to_string() }
    }

    fn upsert(alias: &str, text: &str) -> HostEffect {
        HostEffect::Upsert { alias: alias.to_string(), text: text.to_string() }
    }

    /// 模擬引擎一輪(不碰檔案):plan_local → pull_merge → 採用合併狀態 → push_dirty。
    fn round(state: &mut SyncState, relay: &FakeRelay, blocks: &[HostBlockText], now: u64) -> (Merged, Pushed) {
        let k = keys();
        plan_local(state, blocks, |_| now, now, "test");
        let merged = pull_merge(state, &k, relay).unwrap();
        *state = merged.state.clone();
        let pushed = push_dirty(state, &k, relay).unwrap();
        (merged, pushed)
    }

    /// 模擬的受管檔:效果寫進區塊列表(Upsert 取代或附加、Delete 移除),同引擎的 apply_and_commit。
    fn apply_to(file: &mut Vec<HostBlockText>, effects: &[HostEffect]) {
        for effect in effects {
            match effect {
                HostEffect::Upsert { alias, text } => match file.iter_mut().find(|b| &b.alias == alias) {
                    Some(existing) => existing.text = text.clone(),
                    None => file.push(block(alias, text)),
                },
                HostEffect::Delete { alias } => file.retain(|b| &b.alias != alias),
            }
        }
    }

    /// `round` 加上把效果寫回模擬的受管檔:下一輪的本機 diff 看到的就是寫回之後的檔案。
    fn sync(state: &mut SyncState, relay: &FakeRelay, file: &mut Vec<HostBlockText>, now: u64) -> (Merged, Pushed) {
        let (merged, pushed) = round(state, relay, file.as_slice(), now);
        apply_to(file, &merged.host_effects);
        (merged, pushed)
    }

    /// 依 alias 排序後的 (alias, text),比對檔案內容用。
    fn sorted(file: &[HostBlockText]) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = file.iter().map(|b| (b.alias.clone(), b.text.clone())).collect();
        out.sort();
        out
    }

    fn pair(alias: &str, text: &str) -> (String, String) {
        (alias.to_string(), text.to_string())
    }

    fn host_record(id: &str, payload: serde_json::Value, deleted: bool) -> Record {
        Record { kind: RecordKind::Host, id: id.into(), version: 1, updated_at_ms: 1, device_id: "z".into(), deleted, payload }
    }

    #[test]
    fn host_created_on_a_arrives_on_b() {
        let relay = FakeRelay::default();
        let mut a = device("a");
        let mut b = device("b");
        let (m, p) = round(&mut a, &relay, &[block("web", "Host web\n")], 100);
        assert!(m.host_effects.is_empty());
        assert_eq!(p.accepted, 2, "host + device heartbeat");
        assert!(!a.records["host:web"].dirty);
        let (m, _) = round(&mut b, &relay, &[], 200);
        assert_eq!(m.host_effects, vec![upsert("web", "Host web\n")]);
        assert!(b.records.contains_key("host:web"));
        assert!(b.cursor_seq > 0);
    }

    #[test]
    fn edits_and_deletes_flow_both_ways() {
        let relay = FakeRelay::default();
        let mut a = device("a");
        let mut b = device("b");
        round(&mut a, &relay, &[block("web", "Host web\n")], 100);
        round(&mut b, &relay, &[], 200);
        // B 修改後 A 收到新文字;A 刪除後 B 收到移除。
        round(&mut b, &relay, &[block("web", "Host web\n  User x\n")], 300);
        let (m, _) = round(&mut a, &relay, &[block("web", "Host web\n")], 400);
        assert_eq!(m.host_effects, vec![upsert("web", "Host web\n  User x\n")]);
        let (m, _) = round(&mut a, &relay, &[], 500);
        assert!(m.host_effects.is_empty());
        let (m, _) = round(&mut b, &relay, &[block("web", "Host web\n  User x\n")], 600);
        assert_eq!(m.host_effects, vec![HostEffect::Delete { alias: "web".into() }]);
    }

    #[test]
    fn concurrent_edit_is_resolved_by_timestamp_and_reported() {
        let relay = FakeRelay::default();
        let mut a = device("a");
        let mut b = device("b");
        round(&mut a, &relay, &[block("web", "Host web\n")], 100);
        round(&mut b, &relay, &[], 150);
        // 兩邊離線各改一次:A 較早(200)、B 較晚(300)。A 先推;B 這輪 pull 到 A 的版本但自己較新 → B 勝。
        round(&mut a, &relay, &[block("web", "Host web\n  User a\n")], 200);
        let (mb, _) = round(&mut b, &relay, &[block("web", "Host web\n  User b\n")], 300);
        assert!(mb.host_effects.is_empty(), "B keeps its own newer text");
        assert!(mb.conflicts.is_empty());
        let (ma, _) = round(&mut a, &relay, &[block("web", "Host web\n  User a\n")], 400);
        assert_eq!(ma.host_effects, vec![upsert("web", "Host web\n  User b\n")]);
        // C 離線改(時間 460),同時 B 又改(時間 900)並先推:C 的未上傳修改被較新的遠端蓋掉 → conflicts。
        let mut c = device("c");
        round(&mut c, &relay, &[], 450);
        round(&mut b, &relay, &[block("web", "Host web\n  User bb\n")], 900);
        let (mc, _) = round(&mut c, &relay, &[block("web", "Host web\n  User c\n")], 460);
        assert_eq!(mc.conflicts, vec!["web".to_string()]);
        assert_eq!(mc.host_effects, vec![upsert("web", "Host web\n  User bb\n")]);
        assert!(!c.records["host:web"].dirty);
    }

    #[test]
    fn push_conflict_is_deferred_to_the_next_round() {
        let relay = FakeRelay::default();
        let k = keys();
        let mut a = device("a");
        let mut b = device("b");
        round(&mut a, &relay, &[block("web", "Host web\n")], 100);
        round(&mut b, &relay, &[], 150);
        // B:pull 之後、push 之前,A 又推了新版(時間 400)。
        plan_local(&mut b, &[block("web", "Host web\n  User b\n")], |_| 300, 300, "test");
        let merged = pull_merge(&b, &k, &relay).unwrap();
        b = merged.state;
        round(&mut a, &relay, &[block("web", "Host web\n  User a\n")], 400);
        let pushed = push_dirty(&mut b, &k, &relay).unwrap();
        assert_eq!(pushed.conflicts, 1);
        assert!(b.records["host:web"].dirty, "stays dirty until the next round merges the relay version");
        // 下一輪:A 的版本(400)較新 → B 收到效果、列入 conflicts、不再 dirty。
        let (m, _) = round(&mut b, &relay, &[block("web", "Host web\n  User b\n")], 500);
        assert_eq!(m.conflicts, vec!["web".to_string()]);
        assert_eq!(m.host_effects, vec![upsert("web", "Host web\n  User a\n")]);
        assert!(!b.records["host:web"].dirty);
    }

    #[test]
    fn cursor_only_follows_the_pull_watermark() {
        let relay = FakeRelay::default();
        let k = keys();
        let mut a = device("a");
        let mut b = device("b");
        round(&mut a, &relay, &[], 100);
        let cursor_before = a.cursor_seq;
        round(&mut b, &relay, &[block("x", "Host x\n"), block("y", "Host y\n")], 200);
        // A 推自己的變更:拿到比 B 的記錄更大的 seq,但 cursor 不能跳過 B 的記錄。
        plan_local(&mut a, &[block("z", "Host z\n")], |_| 300, 300, "test");
        push_dirty(&mut a, &k, &relay).unwrap();
        assert_eq!(a.cursor_seq, cursor_before);
        let (m, _) = round(&mut a, &relay, &[block("z", "Host z\n")], 400);
        let mut aliases: Vec<&str> = m.host_effects.iter().map(|e| e.alias()).collect();
        aliases.sort();
        assert_eq!(aliases, vec!["x", "y"]);
    }

    #[test]
    fn a_relay_watermark_that_went_backwards_resets_the_cursor() {
        let relay = FakeRelay::default();
        let k = keys();
        let mut a = device("a");
        let mut b = device("b");
        round(&mut a, &relay, &[block("web", "Host web\n")], 100);
        round(&mut b, &relay, &[], 200);
        round(&mut b, &relay, &[], 300);
        assert_eq!(b.cursor_seq, 3);
        // 自架中繼從舊備份還原:只剩 seq 1,watermark 退回 1。
        relay.rows.borrow_mut().retain(|_, e| e.seq <= 1);
        *relay.latest.borrow_mut() = 1;
        let m = pull_merge(&b, &k, &relay).unwrap();
        assert_eq!(m.state.cursor_seq, 0, "a cursor past the relay's watermark is reset, never kept");
        assert!(m.host_effects.is_empty());
        // 每一筆快取的記錄都要重新上傳(中繼可能少了它們),而且以 seq 0 為基準:中繼上還有的先衝突、合併後才覆寫。
        assert!(!m.state.records.is_empty());
        assert!(m.state.records.values().all(|l| l.seq == 0 && l.dirty), "every cached record is re-uploaded");
        b = m.state;
        // 還原之後 A 再寫一台,拿到的 seq(2)比 B 原本的 cursor 小:只有從頭重拉才收得到。已經套用過的記錄
        // 再合併一次不產生任何效果(冪等)。
        plan_local(&mut a, &[block("web", "Host web\n"), block("db", "Host db\n")], |_| 400, 400, "test");
        push_dirty(&mut a, &k, &relay).unwrap();
        let m = pull_merge(&b, &k, &relay).unwrap();
        assert_eq!(m.host_effects, vec![upsert("db", "Host db\n")]);
        assert_eq!(m.state.cursor_seq, 2);
    }

    #[test]
    fn a_relay_restored_from_an_older_backup_is_repaired_from_this_device() {
        let relay = FakeRelay::default();
        let k = keys();
        let (mut a, mut b) = (device("a"), device("b"));
        let (mut file_a, mut file_b) = (vec![block("web", "Host web\n"), block("db", "Host db\n")], Vec::new());
        // 1. 兩台裝置同步幾台主機;記下中繼這時的樣子(之後的「備份」)。
        sync(&mut a, &relay, &mut file_a, 100);
        sync(&mut b, &relay, &mut file_b, 200);
        let backup = (relay.rows.borrow().clone(), *relay.latest.borrow());
        // A 改了 web、加了 app;兩台都同步到最新。
        file_a[0].text = "Host web\n  User deploy\n".to_string();
        file_a.push(block("app", "Host app\n"));
        sync(&mut a, &relay, &mut file_a, 300);
        sync(&mut b, &relay, &mut file_b, 400);
        sync(&mut a, &relay, &mut file_a, 500);
        assert_eq!(sorted(&file_b), sorted(&file_a), "B has everything before the restore");
        assert!(a.cursor_seq > backup.1, "A has seen records the backup does not hold");

        // 2. 自架中繼從舊備份還原:較新的記錄(A 的新版 web、app)不見了,watermark 退回 A 的 cursor 之下。
        *relay.rows.borrow_mut() = backup.0;
        *relay.latest.borrow_mut() = backup.1;

        // 3. A 的下一次 pull 偵測到倒退:cursor 歸零、每一筆記錄都要重新上傳。
        let detected = pull_merge(&a, &k, &relay).unwrap();
        assert_eq!(detected.state.cursor_seq, 0);
        assert!(detected.state.records.values().all(|l| l.seq == 0 && l.dirty));
        assert!(detected.host_effects.is_empty(), "nothing in A's file changes");
        // A 照常跑幾輪,直到沒有東西要上傳:中繼缺的推回去,中繼還有的先衝突、重拉合併後再推。
        for now in [600, 700, 800] {
            let (m, _) = sync(&mut a, &relay, &mut file_a, now);
            assert!(m.host_effects.is_empty(), "the repair never changes A's own file");
        }
        assert!(a.records.values().all(|l| !l.dirty), "everything the relay lost was uploaded again");

        // 4. 新加入的 C 拉到完整的主機集合,含 A 在備份之後才寫的新版 web 與 app。
        let (mut c, mut file_c) = (device("c"), Vec::new());
        sync(&mut c, &relay, &mut file_c, 900);
        assert_eq!(
            sorted(&file_c),
            vec![pair("app", "Host app\n"), pair("db", "Host db\n"), pair("web", "Host web\n  User deploy\n")]
        );
    }

    #[test]
    fn the_rollback_repair_never_overwrites_a_newer_write_made_after_the_restore() {
        let relay = FakeRelay::default();
        let (mut a, mut b) = (device("a"), device("b"));
        let (mut file_a, mut file_b) = (vec![block("web", "Host web\n"), block("db", "Host db\n")], Vec::new());
        sync(&mut a, &relay, &mut file_a, 100);
        sync(&mut b, &relay, &mut file_b, 200);
        let backup = (relay.rows.borrow().clone(), *relay.latest.borrow());
        // 備份之後 A 改了 web、加了 app,兩台都同步到最新:A 快取裡 web 的 seq 比備份裡的任何序號都大。
        file_a[0].text = "Host web\n  User a\n".to_string();
        file_a.push(block("app", "Host app\n"));
        sync(&mut a, &relay, &mut file_a, 300);
        sync(&mut b, &relay, &mut file_b, 400);
        sync(&mut a, &relay, &mut file_a, 450);
        *relay.rows.borrow_mut() = backup.0;
        *relay.latest.borrow_mut() = backup.1;
        // 還原之後、A 發現之前,B 又改了 web 並推上去:它在中繼上拿到的 seq 比 A 快取裡那筆的 seq 還小,
        // watermark 仍在 A 的 cursor 之下。
        file_b.iter_mut().find(|blk| blk.alias == "web").unwrap().text = "Host web\n  User b\n".to_string();
        plan_local(&mut b, &file_b, |_| 480, 480, "test");
        assert_eq!(push_dirty(&mut b, &keys(), &relay).unwrap().accepted, 1);
        assert!(*relay.latest.borrow() < a.cursor_seq);
        assert!(*relay.latest.borrow() < a.records["host:web"].seq, "a push based on A's old seq would be accepted");
        // A 偵測到倒退、重新上傳:以 seq 0 為基準,中繼上 B 的新版先回衝突、合併後寫回 A 的檔案 —— 不會被 A 的
        // 舊版蓋掉。(這一筆會以「覆寫了本機修改」通知:A 的 dirty 是偵測倒退時標的。)
        for now in [500, 600, 700] {
            sync(&mut a, &relay, &mut file_a, now);
        }
        assert!(a.records.values().all(|l| !l.dirty));
        assert!(file_a.contains(&block("web", "Host web\n  User b\n")), "A takes B's newer web: {file_a:?}");
        let (mut c, mut file_c) = (device("c"), Vec::new());
        sync(&mut c, &relay, &mut file_c, 900);
        assert_eq!(
            sorted(&file_c),
            vec![pair("app", "Host app\n"), pair("db", "Host db\n"), pair("web", "Host web\n  User b\n")]
        );
    }

    fn cached_host(alias: &str, text: Option<&str>, dirty: bool) -> (String, LocalRecord) {
        let record = Record {
            kind: RecordKind::Host,
            id: alias.into(),
            version: 2,
            updated_at_ms: 50,
            device_id: "z".into(),
            deleted: text.is_none(),
            payload: text.map_or(serde_json::Value::Null, |t| serde_json::json!({ "schema": 1, "text": t })),
        };
        (record_key(RecordKind::Host, alias), LocalRecord { record, seq: 3, dirty })
    }

    #[test]
    fn only_unpushed_edits_missing_from_the_file_are_written_back() {
        let mut s = device("a");
        s.records.extend([
            cached_host("edited", Some("Host edited\n  User me\n"), true), // 離線修改、檔案裡沒有 → 寫回
            cached_host("dropped", None, true),                            // 離線刪除 → 不寫回(照常推送)
            cached_host("clean", Some("Host clean\n"), false),             // 已上傳 → 交給 chain
            cached_host("present", Some("Host present\n  User me\n"), true), // 檔案裡已有 → 不動
            cached_host("broken", Some("# not a host\n"), true),           // 文字套不上 → 不寫回
        ]);
        let me = own_device_record(&s, 5, "test");
        s.records.insert(record_key(RecordKind::Device, &s.device_id), LocalRecord { record: me, seq: 0, dirty: true });
        let file = [block("present", "Host present\n")];
        assert_eq!(unpushed_host_effects(&s, &file), vec![upsert("edited", "Host edited\n  User me\n")]);
        // 剛 Join:快取沒有 host 記錄,沒有任何效果。
        assert!(unpushed_host_effects(&device("b"), &[]).is_empty());
    }

    #[test]
    fn an_offline_edit_survives_restoring_a_vanished_synced_file_from_the_chain() {
        let relay = FakeRelay::default();
        let k = keys();
        let (mut a, mut b) = (device("a"), device("b"));
        let (mut file_a, mut file_b) = (vec![block("web", "Host web\n"), block("db", "Host db\n")], Vec::new());
        sync(&mut a, &relay, &mut file_a, 100);
        sync(&mut b, &relay, &mut file_b, 200);
        // 中繼連不上時 A 改了 web:存檔當下規劃成 dirty,但沒推出去。
        file_a[0].text = "Host web\n  User offline\n".to_string();
        plan_local(&mut a, &file_a, |_| 300, 300, "test");
        assert!(a.records["host:web"].dirty);
        // hosts.config 不見了:引擎改成從 chain 重新長出(檔案重建成空的),下一輪是基線輪。
        crate::sync::engine::reset_hosts_for_rematerialize(&mut a);
        let mut file_a: Vec<HostBlockText> = Vec::new();
        let merged = pull_merge(&a, &k, &relay).unwrap();
        let mut effects = merged.host_effects.clone();
        effects.extend(unpushed_host_effects(&merged.state, &file_a));
        apply_to(&mut file_a, &effects);
        a = merged.state;
        // 檔案裡有 chain 上的每一台主機,web 是 A 的離線版本(不是 chain 上較舊的那份)。
        assert_eq!(sorted(&file_a), vec![pair("db", "Host db\n"), pair("web", "Host web\n  User offline\n")]);
        // 下一輪照常把修改推出去,B 收到它(不是衝突)。
        sync(&mut a, &relay, &mut file_a, 400);
        assert!(a.records.values().all(|l| !l.dirty));
        let (m, _) = sync(&mut b, &relay, &mut file_b, 500);
        assert_eq!(m.host_effects, vec![upsert("web", "Host web\n  User offline\n")]);
        assert!(m.conflicts.is_empty());
    }

    #[test]
    fn undecryptable_envelopes_are_skipped_not_fatal() {
        let relay = FakeRelay::default();
        relay.rows.borrow_mut().insert(
            "ff".repeat(32),
            Envelope { id_hash: "ff".repeat(32), kind: "host".into(), seq: 1, nonce: "!!".into(), ciphertext: "!!".into(), deleted: false },
        );
        *relay.latest.borrow_mut() = 1;
        let a = device("a");
        let m = pull_merge(&a, &keys(), &relay).unwrap();
        assert_eq!(m.skipped, 1);
        assert_eq!(m.state.cursor_seq, 1);
        assert!(m.host_effects.is_empty());
    }

    #[test]
    fn unsupported_kinds_are_kept_sealed_not_decoded() {
        let relay = FakeRelay::default();
        let k = keys();
        // 一筆合法加密的 password 記錄(Phase A 不處理)與一筆未知種類。
        let secret = Record { kind: RecordKind::Password, id: "web".into(), version: 1, updated_at_ms: 1, device_id: "z".into(), deleted: false, payload: serde_json::json!("hunter2") };
        relay.push("x", &[encode(&k, &secret, 0).unwrap()]).unwrap();
        relay.rows.borrow_mut().insert(
            "ee".repeat(32),
            Envelope { id_hash: "ee".repeat(32), kind: "future".into(), seq: 2, nonce: "n".into(), ciphertext: "c".into(), deleted: false },
        );
        *relay.latest.borrow_mut() = 2;
        let a = device("a");
        let m = pull_merge(&a, &k, &relay).unwrap();
        assert_eq!(m.skipped, 0);
        assert_eq!(m.state.sealed.len(), 2);
        assert!(m.state.sealed.keys().any(|key| key.starts_with("password:")));
        assert!(m.state.sealed.contains_key(&format!("future:{}", "ee".repeat(32))));
        assert!(m.state.records.values().all(|l| l.record.kind != RecordKind::Password));
        let text = serde_json::to_string(&m.state).unwrap();
        assert!(!text.contains("hunter2"), "secret payload must never reach the state");
        assert_eq!(m.state.cursor_seq, 2);
    }

    #[test]
    fn unparseable_host_payload_is_skipped_not_deleted() {
        let relay = FakeRelay::default();
        let k = keys();
        let mut a = device("a");
        round(&mut a, &relay, &[block("web", "Host web\n")], 100);
        // 合法加密、但 payload 缺 text 的 host 記錄,時間比本機新。
        let mut broken = host_record("web", serde_json::json!({ "schema": 1 }), false);
        broken.updated_at_ms = 999;
        relay.push("x", &[encode(&k, &broken, a.records["host:web"].seq).unwrap()]).unwrap();
        let m = pull_merge(&a, &k, &relay).unwrap();
        assert!(m.host_effects.is_empty(), "never turns a bad payload into a delete");
        assert_eq!(m.skipped, 1);
        assert_eq!(m.state.records["host:web"], a.records["host:web"], "local cache untouched");
    }

    #[test]
    fn wildcard_records_from_remote_are_skipped() {
        let relay = FakeRelay::default();
        let k = keys();
        let star = host_record("*", serde_json::json!({ "schema": 1, "text": "Host *\n  User root\n" }), false);
        relay.push("x", &[encode(&k, &star, 0).unwrap()]).unwrap();
        let a = device("a");
        let m = pull_merge(&a, &k, &relay).unwrap();
        assert!(m.host_effects.is_empty());
        assert_eq!(m.skipped, 1);
    }

    #[test]
    fn invalid_host_text_is_skipped_and_not_cached() {
        let relay = FakeRelay::default();
        let k = keys();
        // payload 結構正確、但文字不是合法區塊 / alias 不符 / 夾帶 Match:合併前就擋掉,不進快取、不產生效果。
        let comment = host_record("web", serde_json::json!({ "schema": 1, "text": "# just a comment\n" }), false);
        let mismatch = host_record("db", serde_json::json!({ "schema": 1, "text": "Host other\n" }), false);
        let extra = host_record("app", serde_json::json!({ "schema": 1, "text": "Host app\n  User a\nMatch all\n  User b\n" }), false);
        relay
            .push("x", &[encode(&k, &comment, 0).unwrap(), encode(&k, &mismatch, 0).unwrap(), encode(&k, &extra, 0).unwrap()])
            .unwrap();
        let a = device("a");
        let m = pull_merge(&a, &k, &relay).unwrap();
        assert!(m.host_effects.is_empty());
        assert_eq!(m.skipped, 3);
        assert!(!m.state.records.contains_key("host:web"));
        assert!(!m.state.records.contains_key("host:db"));
        assert!(!m.state.records.contains_key("host:app"));
        // 下一輪的本機 diff 因此不會把它們當成「快取有、檔案沒有」而產生 tombstone。
        let mut s = m.state;
        assert_eq!(plan_local(&mut s, &[], |_| 100, 100, "test"), 1, "only the device heartbeat");
    }

    #[test]
    fn newer_schema_puts_this_device_in_read_only_mode_persistently() {
        let relay = FakeRelay::default();
        let k = keys();
        let meta = Record {
            kind: RecordKind::Meta,
            id: "chain".into(),
            version: 1,
            updated_at_ms: 1,
            device_id: "z".into(),
            deleted: false,
            payload: serde_json::to_value(MetaPayload { schema_version: SCHEMA_VERSION + 1, created_by_app_version: "9.9.9".into() }).unwrap(),
        };
        relay.push("x", &[encode(&k, &meta, 0).unwrap()]).unwrap();
        let mut a = device("a");
        let (m, p) = round(&mut a, &relay, &[block("web", "Host web\n")], 100);
        assert!(m.state.read_only());
        assert_eq!(p.accepted, 0, "nothing is pushed in read-only mode");
        assert!(a.records["host:web"].dirty);
        // 下一輪 pull 不再帶 meta,仍然唯讀(從持久化的 remote_schema_version 判斷)。
        let (m, p) = round(&mut a, &relay, &[block("web", "Host web\n")], 200);
        assert!(m.state.read_only());
        assert_eq!(p.accepted, 0);
        assert!(a.records["host:web"].dirty);
    }

    #[test]
    fn device_heartbeat_is_uploaded_and_visible_to_others() {
        let relay = FakeRelay::default();
        let mut a = device("a");
        let mut b = device("b");
        round(&mut a, &relay, &[], 100);
        round(&mut b, &relay, &[], 200);
        let seen: Vec<_> = b.records.values().filter(|l| l.record.kind == RecordKind::Device).map(|l| l.record.id.clone()).collect();
        assert!(seen.contains(&a.device_id));
        assert!(seen.contains(&b.device_id));
    }

    #[test]
    fn pushes_are_batched_by_count() {
        let relay = FakeRelay::default();
        let mut a = device("a");
        let blocks: Vec<HostBlockText> = (0..450).map(|i| block(&format!("h{i}"), &format!("Host h{i}\n"))).collect();
        let (_, p) = round(&mut a, &relay, &blocks, 100);
        assert_eq!(p.accepted, 451, "450 hosts + device heartbeat");
        assert_eq!(*relay.push_calls.borrow(), 3, "200 + 200 + 51");
        assert!(a.records.values().all(|l| !l.dirty));
    }
}
