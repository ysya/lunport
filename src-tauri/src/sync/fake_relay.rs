//! 記憶體假 relay(只在測試建置):語意與 relay Worker 相同 —— 每條 chain 一個權杖、單調 seq、base_seq 過舊回
//! conflict、凍結後 push 一律 `Frozen`、批次查詢逐項回 `ok` / `not_found` / `rate_limited` / `deferred`。多台裝置的
//! 引擎共用同一個實例,測試就能決定性地重現兩台同時升級、更換同步碼時第三台還在推送等情境。另外可以注入:舊版 relay
//! (沒有批次查詢與凍結)、離線、批次的回應預算(第幾項之後 deferred)、單條 chain 的限流、整批 `429`、上傳與建立
//! chain 的 `429`、儲存額度滿了(前幾次上傳照常、之後回 `413`)。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::error::AppError;
use crate::sync::crypto::is_chain_id;
use crate::sync::record::Envelope;
use crate::sync::relay::{
    BatchPullEntry, BatchPullItem, BatchPullResult, PullResponse, PushItem, PushOutcome, PushResult, RelayApi,
    RelayError, RelayInfo, FEATURE_FREEZE, FEATURE_PULL_BATCH, MAX_BATCH_PULL,
};

#[derive(Default)]
struct FakeChain {
    token: String,
    rows: BTreeMap<String, Envelope>,
    latest: u64,
    frozen: bool,
}

#[derive(Default)]
struct Inner {
    chains: BTreeMap<String, FakeChain>,
    legacy: bool,
    offline: bool,
    /// 批次查詢每次最多執行幾項,其餘回 `deferred`(第一項一律執行,同 relay 的預算規則)。
    budget: Option<usize>,
    rate_limited: BTreeSet<String>,
    batch_429: u32,
    batch_5xx: u32,
    create_429: u32,
    push_429: u32,
    /// 還能寫入幾次上傳,用完之後每次上傳都回 `413`(chain 的儲存額度已滿)。`None` = 不限制。
    push_quota: Option<u32>,
    /// 這些 chain 的 Durable Object 會丟例外:單條查詢回 `500`,含它的批次整批 `500`(relay 不逐項 catch)。
    broken: BTreeSet<String>,
    calls: Vec<String>,
}

pub struct FakeRelay {
    inner: Mutex<Inner>,
}

/// 呼叫紀錄用的縮寫:前 8 個字元。依字元切、不是依位元組 —— 非 ASCII 的輸入不會在多位元組字元中間切開而 panic。
fn short(chain: &str) -> String {
    chain.chars().take(8).collect()
}

impl FakeRelay {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(Inner::default()) })
    }

    /// 舊版 relay:`GET /v1/info` 404(沒有任何功能)、`POST /v1/pull` 404、freeze 404。
    pub fn set_legacy(&self, legacy: bool) {
        self.inner.lock().unwrap().legacy = legacy;
    }

    /// 連不上:每個呼叫都回 `Unreachable`。
    pub fn set_offline(&self, offline: bool) {
        self.inner.lock().unwrap().offline = offline;
    }

    /// 批次查詢每次只執行前 `items` 項,其餘 `deferred`。
    pub fn set_budget(&self, items: Option<usize>) {
        self.inner.lock().unwrap().budget = items;
    }

    /// 這條 chain 在批次裡回 `rate_limited`、單條 pull 回 `429`。
    pub fn set_rate_limited(&self, chain: &str, limited: bool) {
        let mut inner = self.inner.lock().unwrap();
        if limited {
            inner.rate_limited.insert(chain.to_string());
        } else {
            inner.rate_limited.remove(chain);
        }
    }

    /// 接下來 `times` 次批次查詢整批回 `429`。
    pub fn fail_batches_with_429(&self, times: u32) {
        self.inner.lock().unwrap().batch_429 = times;
    }

    /// 接下來 `times` 次批次查詢整批回 `500`。
    pub fn fail_batches_with_5xx(&self, times: u32) {
        self.inner.lock().unwrap().batch_5xx = times;
    }

    /// 這條 chain 壞掉(或修好):單條查詢回 `500`,含它的批次整批 `500`。
    pub fn set_broken(&self, chain: &str, broken: bool) {
        let mut inner = self.inner.lock().unwrap();
        if broken {
            inner.broken.insert(chain.to_string());
        } else {
            inner.broken.remove(chain);
        }
    }

    /// 接下來 `times` 次上傳回 `429`。
    pub fn fail_pushes_with_429(&self, times: u32) {
        self.inner.lock().unwrap().push_429 = times;
    }

    /// 儲存額度:前 `ok_pushes` 次(通過權杖與凍結檢查的)上傳照常,之後每次上傳都回 `413`(`QuotaExceeded`,chain 的
    /// 儲存額度已滿)、什麼都不寫;`None` = 不限制。relay 先檢查權杖與凍結才算用量,所以不存在的 chain 仍回 `NotFound`、
    /// 凍結的 chain 仍回 `Frozen`。**算的是上傳的次數,不是用量**(所有 chain 共用一個計數):Worker 依實際寫入的位元組算,一次
    /// 每筆都衝突、什麼都沒寫的上傳在滿了的 chain 上仍回 200,這裡卻一樣用掉一次、滿了就回 413 —— 測試不能靠這個替身判斷「只有衝突
    /// 的上傳」在額度滿了時的結果。
    pub fn set_push_quota(&self, ok_pushes: Option<u32>) {
        self.inner.lock().unwrap().push_quota = ok_pushes;
    }

    /// 接下來 `times` 次建立 chain 回 `429`(每 IP 每小時 20 次建立)。
    pub fn fail_creates_with_429(&self, times: u32) {
        self.inner.lock().unwrap().create_429 = times;
    }

    pub fn exists(&self, chain: &str) -> bool {
        self.inner.lock().unwrap().chains.contains_key(chain)
    }

    pub fn is_frozen(&self, chain: &str) -> bool {
        self.inner.lock().unwrap().chains.get(chain).is_some_and(|c| c.frozen)
    }

    /// chain 上的列(依 seq 排序);chain 不存在 → 空。
    pub fn rows(&self, chain: &str) -> Vec<Envelope> {
        let inner = self.inner.lock().unwrap();
        let mut rows: Vec<Envelope> = inner.chains.get(chain).map(|c| c.rows.values().cloned().collect()).unwrap_or_default();
        rows.sort_by_key(|e| e.seq);
        rows
    }

    /// 呼叫紀錄:`info`、`create:<id8>`、`delete:<id8>`、`freeze:<id8>`、`pull:<id8>`、`push:<id8>`、
    /// `batch:<id8>,<id8>,…`(依請求順序)。
    pub fn calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().calls.clone()
    }

    pub fn clear_calls(&self) {
        self.inner.lock().unwrap().calls.clear();
    }

    /// relay 閒置 180 天把一條 chain 整條清除(連 `meta` 與凍結一起消失,spec §6.2):之後對它的請求都回 `NotFound`。
    pub fn expire(&self, chain: &str) {
        self.inner.lock().unwrap().chains.remove(chain);
    }

    /// 自架 relay 從舊備份還原:只留 seq ≤ `keep` 的列,watermark 退回 `keep`。
    pub fn roll_back(&self, chain: &str, keep: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(c) = inner.chains.get_mut(chain) {
            c.rows.retain(|_, e| e.seq <= keep);
            c.latest = keep;
        }
    }

    fn pull_chain(inner: &Inner, chain: &str, token: &str, since: u64) -> Result<PullResponse, RelayError> {
        if inner.broken.contains(chain) {
            return Err(RelayError::Http(500));
        }
        let c = inner.chains.get(chain).filter(|c| c.token == token).ok_or(RelayError::NotFound)?;
        if inner.rate_limited.contains(chain) {
            return Err(RelayError::RateLimited);
        }
        let mut records: Vec<Envelope> = c.rows.values().filter(|e| e.seq > since).cloned().collect();
        records.sort_by_key(|e| e.seq);
        Ok(PullResponse { records, latest_seq: c.latest })
    }
}

fn check(chain: &str, token: &str) -> Result<(), RelayError> {
    if is_chain_id(chain) && is_chain_id(token) {
        Ok(())
    } else {
        Err(RelayError::InvalidRequest("chain id and token must be 64 lowercase hex characters".to_string()))
    }
}

/// 與 `RelayClient` 送出前的檢查相同(relay 的上限):每次 push 1–200 筆、同一批裡沒有重複的 `id_hash`。引擎若送出
/// 違規的請求,測試會看到和真 client 一樣的 `InvalidRequest`。
const MAX_PUSH_ITEMS: usize = 200;
/// cursor 是 JavaScript 的 safe integer(2^53 − 1),同 `RelayClient`。
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn check_push(items: &[PushItem]) -> Result<(), RelayError> {
    if items.is_empty() || items.len() > MAX_PUSH_ITEMS {
        return Err(RelayError::InvalidRequest(format!("a push takes 1 to {MAX_PUSH_ITEMS} records")));
    }
    let mut seen = BTreeSet::new();
    if !items.iter().all(|item| seen.insert(item.id_hash.as_str())) {
        return Err(RelayError::InvalidRequest("a record appears twice in one push".to_string()));
    }
    Ok(())
}

fn check_cursor(since: u64) -> Result<(), RelayError> {
    if since > MAX_SAFE_INTEGER {
        return Err(RelayError::InvalidRequest("a pull cursor is out of range".to_string()));
    }
    Ok(())
}

/// 批次查詢送出前的檢查,同 `RelayClient`:≤ 64 項、chain 不重複、chain 與權杖是 64 字元小寫 hex、`since` 是 safe integer。
fn check_batch(items: &[BatchPullItem]) -> Result<(), RelayError> {
    if items.len() > MAX_BATCH_PULL {
        return Err(RelayError::InvalidRequest(format!("a batch pull takes at most {MAX_BATCH_PULL} chains")));
    }
    let mut seen = BTreeSet::new();
    for item in items {
        check(&item.chain, &item.token)?;
        check_cursor(item.since)?;
        if !seen.insert(item.chain.as_str()) {
            return Err(RelayError::InvalidRequest("a chain appears twice in one batch pull".to_string()));
        }
    }
    Ok(())
}

impl RelayApi for FakeRelay {
    fn info(&self) -> Result<RelayInfo, RelayError> {
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push("info".to_string());
        if inner.offline {
            return Err(RelayError::Unreachable("offline".to_string()));
        }
        if inner.legacy {
            return Ok(RelayInfo::default());
        }
        Ok(RelayInfo { version: Some("0.2.0".to_string()), features: vec![FEATURE_PULL_BATCH.to_string(), FEATURE_FREEZE.to_string()] })
    }

    fn create_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        check(chain_id, token)?;
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(format!("create:{}", short(chain_id)));
        if inner.offline {
            return Err(RelayError::Unreachable("offline".to_string()));
        }
        if inner.create_429 > 0 {
            inner.create_429 -= 1;
            return Err(RelayError::RateLimited);
        }
        match inner.chains.get(chain_id) {
            Some(c) if c.token == token => Ok(()),
            Some(_) => Err(RelayError::NotFound),
            None => {
                inner.chains.insert(chain_id.to_string(), FakeChain { token: token.to_string(), ..FakeChain::default() });
                Ok(())
            }
        }
    }

    fn delete_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        check(chain_id, token)?;
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(format!("delete:{}", short(chain_id)));
        if inner.offline {
            return Err(RelayError::Unreachable("offline".to_string()));
        }
        match inner.chains.get_mut(chain_id) {
            // 凍結的 chain:刪掉記錄但維持凍結(之後 `PUT` 回 200、push 照樣 409),還沒換同步碼的電腦仍會被擋下。
            Some(c) if c.token == token && c.frozen => {
                c.rows.clear();
                Ok(())
            }
            Some(c) if c.token == token => {
                inner.chains.remove(chain_id);
                Ok(())
            }
            _ => Err(RelayError::NotFound),
        }
    }

    fn freeze_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        check(chain_id, token)?;
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(format!("freeze:{}", short(chain_id)));
        if inner.offline {
            return Err(RelayError::Unreachable("offline".to_string()));
        }
        if inner.legacy {
            return Err(RelayError::NotFound);
        }
        match inner.chains.get_mut(chain_id) {
            Some(c) if c.token == token => {
                c.frozen = true;
                Ok(())
            }
            _ => Err(RelayError::NotFound),
        }
    }

    fn pull(&self, chain_id: &str, token: &str, since: u64) -> Result<PullResponse, RelayError> {
        check(chain_id, token)?;
        check_cursor(since)?;
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(format!("pull:{}", short(chain_id)));
        if inner.offline {
            return Err(RelayError::Unreachable("offline".to_string()));
        }
        Self::pull_chain(&inner, chain_id, token, since)
    }

    fn pull_batch(&self, items: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        // 和 `RelayClient` 一樣先檢查請求,違規的就不送出:不進呼叫紀錄,也不會因為離線或舊版 relay 而換成別種錯誤。
        check_batch(items)?;
        let mut inner = self.inner.lock().unwrap();
        inner.calls.push(format!("batch:{}", items.iter().map(|i| short(&i.chain)).collect::<Vec<_>>().join(",")));
        if inner.offline {
            return Err(RelayError::Unreachable("offline".to_string()));
        }
        if inner.legacy {
            return Err(RelayError::Unsupported(FEATURE_PULL_BATCH));
        }
        if inner.batch_429 > 0 {
            inner.batch_429 -= 1;
            return Err(RelayError::RateLimited);
        }
        if inner.batch_5xx > 0 || items.iter().any(|i| inner.broken.contains(&i.chain)) {
            inner.batch_5xx = inner.batch_5xx.saturating_sub(1);
            return Err(RelayError::Http(500));
        }
        Ok(items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let result = if inner.budget.is_some_and(|n| i >= n.max(1)) {
                    BatchPullResult::Deferred
                } else {
                    match Self::pull_chain(&inner, &item.chain, &item.token, item.since) {
                        Ok(resp) => BatchPullResult::Ok(resp),
                        Err(RelayError::RateLimited) => BatchPullResult::RateLimited,
                        Err(_) => BatchPullResult::NotFound,
                    }
                };
                BatchPullEntry { chain: item.chain.clone(), result }
            })
            .collect())
    }

    fn push(&self, chain_id: &str, token: &str, items: &[PushItem]) -> Result<PushOutcome, RelayError> {
        check(chain_id, token)?;
        check_push(items)?;
        let mut guard = self.inner.lock().unwrap();
        // 換成一般的可變參照:下面要同時借用 `chains` 與 `push_quota`,經 guard 的話欄位無法分開借用。
        let inner = &mut *guard;
        inner.calls.push(format!("push:{}", short(chain_id)));
        if inner.offline {
            return Err(RelayError::Unreachable("offline".to_string()));
        }
        if inner.push_429 > 0 {
            inner.push_429 -= 1;
            return Err(RelayError::RateLimited);
        }
        let c = inner.chains.get_mut(chain_id).filter(|c| c.token == token).ok_or(RelayError::NotFound)?;
        if c.frozen {
            return Ok(PushOutcome::Frozen);
        }
        // 儲存額度(`set_push_quota`):relay 在凍結檢查之後才算用量,滿了整批回 413、什麼都不寫。
        if let Some(left) = inner.push_quota.as_mut() {
            if *left == 0 {
                return Err(RelayError::QuotaExceeded);
            }
            *left -= 1;
        }
        let mut out = Vec::new();
        for item in items {
            if let Some(current) = c.rows.get(&item.id_hash) {
                if current.seq > item.base_seq {
                    out.push(PushResult::Conflict { current: current.clone() });
                    continue;
                }
            }
            c.latest += 1;
            let seq = c.latest;
            c.rows.insert(
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
        Ok(PushOutcome::Applied(out))
    }
}

/// `RelayConnector` 給引擎的 relay(測試裡所有裝置共用同一個 `FakeRelay`)。
pub struct FakeRelayHandle(pub Arc<FakeRelay>);

impl RelayApi for FakeRelayHandle {
    fn info(&self) -> Result<RelayInfo, RelayError> {
        self.0.info()
    }
    fn create_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        self.0.create_chain(chain_id, token)
    }
    fn delete_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        self.0.delete_chain(chain_id, token)
    }
    fn freeze_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        self.0.freeze_chain(chain_id, token)
    }
    fn pull(&self, chain_id: &str, token: &str, since: u64) -> Result<PullResponse, RelayError> {
        self.0.pull(chain_id, token, since)
    }
    fn pull_batch(&self, items: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError> {
        self.0.pull_batch(items)
    }
    fn push(&self, chain_id: &str, token: &str, items: &[PushItem]) -> Result<PushOutcome, RelayError> {
        self.0.push(chain_id, token, items)
    }
}

/// relay URL 沒設定時同 production:拒絕。
pub fn connect(relay: &Arc<FakeRelay>, base_url: &str) -> Result<Box<dyn RelayApi>, AppError> {
    if base_url.trim().is_empty() {
        return Err(AppError::Other("no relay URL".to_string()));
    }
    Ok(Box::new(FakeRelayHandle(Arc::clone(relay))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn item(id: &str, base: u64) -> PushItem {
        PushItem { id_hash: id.to_string(), kind: "host".into(), nonce: "n".into(), ciphertext: "c".into(), deleted: false, base_seq: base }
    }

    #[test]
    fn the_fake_relay_follows_the_worker_rules() {
        let relay = FakeRelay::new();
        let (a, b, t, other) = (hex('a'), hex('b'), hex('1'), hex('2'));
        relay.create_chain(&a, &t).unwrap();
        relay.create_chain(&a, &t).unwrap(); // 已存在、權杖相符:Ok
        assert!(matches!(relay.create_chain(&a, &other), Err(RelayError::NotFound)));
        assert!(matches!(relay.pull(&a, &other, 0), Err(RelayError::NotFound)), "a wrong token looks like a missing chain");
        // push:新列接受;base_seq 過舊 → conflict。
        assert_eq!(relay.push(&a, &t, &[item("h1", 0)]).unwrap(), PushOutcome::Applied(vec![PushResult::Accepted { seq: 1 }]));
        assert!(matches!(&relay.push(&a, &t, &[item("h1", 0)]).unwrap(), PushOutcome::Applied(r) if matches!(r[0], PushResult::Conflict { .. })));
        assert_eq!(relay.push(&a, &t, &[item("h1", 1)]).unwrap(), PushOutcome::Applied(vec![PushResult::Accepted { seq: 2 }]));
        assert_eq!(relay.pull(&a, &t, 0).unwrap().latest_seq, 2);
        // 和真 client 一樣在送出前拒絕:空的、超過 200 筆、同一批重複的 push;超出 safe integer 的 cursor。
        assert!(matches!(relay.push(&a, &t, &[]), Err(RelayError::InvalidRequest(_))));
        assert!(matches!(relay.push(&a, &t, &[item("h5", 0), item("h5", 0)]), Err(RelayError::InvalidRequest(_))));
        let many: Vec<PushItem> = (0..201).map(|i| item(&format!("m{i}"), 0)).collect();
        assert!(matches!(relay.push(&a, &t, &many), Err(RelayError::InvalidRequest(_))));
        assert!(matches!(relay.pull(&a, &t, MAX_SAFE_INTEGER + 1), Err(RelayError::InvalidRequest(_))));
        let past = vec![BatchPullItem { chain: a.clone(), token: t.clone(), since: MAX_SAFE_INTEGER + 1 }];
        assert!(matches!(relay.pull_batch(&past), Err(RelayError::InvalidRequest(_))));
        assert_eq!(relay.pull(&a, &t, 0).unwrap().latest_seq, 2, "nothing was written");
        // 批次:not_found、rate_limited、deferred(預算)。
        relay.create_chain(&b, &t).unwrap();
        relay.set_rate_limited(&b, true);
        let batch = |since| vec![
            BatchPullItem { chain: a.clone(), token: t.clone(), since },
            BatchPullItem { chain: b.clone(), token: t.clone(), since },
            BatchPullItem { chain: hex('c'), token: t.clone(), since },
        ];
        let entries = relay.pull_batch(&batch(0)).unwrap();
        assert!(matches!(&entries[0].result, BatchPullResult::Ok(r) if r.records.len() == 1));
        assert_eq!(entries[1].result, BatchPullResult::RateLimited);
        assert_eq!(entries[2].result, BatchPullResult::NotFound);
        relay.set_budget(Some(1));
        let entries = relay.pull_batch(&batch(0)).unwrap();
        assert!(matches!(entries[0].result, BatchPullResult::Ok(_)));
        assert_eq!((entries[1].result.clone(), entries[2].result.clone()), (BatchPullResult::Deferred, BatchPullResult::Deferred));
        relay.set_budget(None);
        relay.fail_batches_with_429(1);
        assert!(matches!(relay.pull_batch(&batch(0)), Err(RelayError::RateLimited)));
        assert!(relay.pull_batch(&batch(0)).is_ok());
        // 凍結:push 一律 Frozen、不寫入;pull 照常。刪除凍結的 chain 只清掉記錄,它仍然凍結:之後 `PUT` 照樣成功
        // (200,不是一條新的可寫 chain)、push 仍是 Frozen。沒凍結的 chain 刪除後重建就是全新的。
        relay.freeze_chain(&a, &t).unwrap();
        assert_eq!(relay.push(&a, &t, &[item("h2", 0)]).unwrap(), PushOutcome::Frozen);
        assert_eq!(relay.rows(&a).len(), 1);
        relay.delete_chain(&a, &t).unwrap();
        assert!(relay.rows(&a).is_empty() && relay.is_frozen(&a));
        relay.create_chain(&a, &t).unwrap();
        assert_eq!(relay.push(&a, &t, &[item("h3", 0)]).unwrap(), PushOutcome::Frozen);
        let fresh = hex('d');
        relay.create_chain(&fresh, &t).unwrap();
        relay.delete_chain(&fresh, &t).unwrap();
        assert!(!relay.exists(&fresh));
        // 儲存額度(413):前 n 次上傳照常,之後每次都回 QuotaExceeded、什麼都不寫。relay 先檢查權杖與凍結才算用量:不存在的
        // chain 仍是 NotFound、凍結的 chain 仍是 Frozen;`None` 解除限制。
        let full = hex('e');
        relay.create_chain(&full, &t).unwrap();
        relay.set_push_quota(Some(1));
        assert!(matches!(relay.push(&full, &t, &[item("q1", 0)]).unwrap(), PushOutcome::Applied(_)));
        assert!(matches!(relay.push(&full, &t, &[item("q2", 0)]), Err(RelayError::QuotaExceeded)));
        assert_eq!(relay.rows(&full).len(), 1, "a refused push writes nothing");
        assert!(matches!(relay.push(&hex('f'), &t, &[item("q3", 0)]), Err(RelayError::NotFound)));
        relay.freeze_chain(&full, &t).unwrap();
        assert_eq!(relay.push(&full, &t, &[item("q4", 0)]).unwrap(), PushOutcome::Frozen);
        relay.set_push_quota(None);
        let roomy = hex('9');
        relay.create_chain(&roomy, &t).unwrap();
        assert!(matches!(relay.push(&roomy, &t, &[item("q5", 0)]).unwrap(), PushOutcome::Applied(_)));
        // 壞掉的 chain:單條 500,含它的批次整批 500。
        relay.set_broken(&b, true);
        assert!(matches!(relay.pull(&b, &t, 0), Err(RelayError::Http(500))));
        relay.set_rate_limited(&b, false);
        assert!(matches!(relay.pull_batch(&batch(0)), Err(RelayError::Http(500))));
        relay.set_broken(&b, false);
        relay.fail_batches_with_5xx(1);
        assert!(matches!(relay.pull_batch(&batch(0)), Err(RelayError::Http(500))));
        assert!(relay.pull_batch(&batch(0)).is_ok());
        // 舊版 relay:沒有批次查詢與凍結。
        relay.set_legacy(true);
        assert_eq!(relay.info().unwrap(), RelayInfo::default());
        assert!(matches!(relay.pull_batch(&batch(0)), Err(RelayError::Unsupported(_))));
        assert!(matches!(relay.freeze_chain(&b, &t), Err(RelayError::NotFound)));
        assert!(relay.calls().iter().any(|c| c.starts_with("batch:aaaaaaaa,bbbbbbbb,cccccccc")));
        // 批次請求先過送出前的檢查(同 `RelayClient`):違規的請求就算離線、又是舊版 relay 也是 InvalidRequest,而且根本沒送出
        // —— 呼叫紀錄裡沒有它;非 ASCII 的 chain id 也不會讓縮寫 panic。
        relay.clear_calls();
        relay.set_offline(true);
        let weird = vec![BatchPullItem { chain: "abcdefgé".to_string(), token: t.clone(), since: 0 }];
        assert!(matches!(relay.pull_batch(&weird), Err(RelayError::InvalidRequest(_))));
        let twice = vec![
            BatchPullItem { chain: a.clone(), token: t.clone(), since: 0 },
            BatchPullItem { chain: a.clone(), token: t.clone(), since: 0 },
        ];
        assert!(matches!(relay.pull_batch(&twice), Err(RelayError::InvalidRequest(_))));
        let too_many: Vec<BatchPullItem> =
            (0..=MAX_BATCH_PULL).map(|i| BatchPullItem { chain: format!("{i:064x}"), token: t.clone(), since: 0 }).collect();
        assert!(matches!(relay.pull_batch(&too_many), Err(RelayError::InvalidRequest(_))));
        assert!(relay.calls().is_empty(), "a refused request is never sent");
        // 合法的批次照舊:離線先於舊版 relay,並且記進呼叫紀錄。
        assert!(matches!(relay.pull_batch(&batch(0)), Err(RelayError::Unreachable(_))));
        assert_eq!(relay.calls().len(), 1);
        relay.set_offline(false);
        assert_eq!(short("abcdefgéxyz"), "abcdefgé", "the abbreviation cuts at characters, not bytes");
    }
}
