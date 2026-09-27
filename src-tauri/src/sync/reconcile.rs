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
    // cursor 只跟 pull 的 watermark 走。
    next.cursor_seq = next.cursor_seq.max(pulled.latest_seq);
    Ok(Merged { state: next, host_effects: acc.host_effects, conflicts: acc.conflicts, skipped: acc.skipped })
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
