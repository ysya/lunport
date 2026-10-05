//! 中繼 HTTP client(Sync v2 spec §6)。只搬密文;所有錯誤都映射成錯誤值,絕不 panic。
//! 使用 blocking client:同步引擎跑在自己的 std 執行緒。**不可在 tokio runtime 內呼叫**
//! (`reqwest::blocking` 會 panic);Tauri command 要用 `tauri::async_runtime::spawn_blocking`。
//! `RelayClient`(spec §6.4)不綁權杖,每次呼叫帶入該 chain 的權杖;批次查詢、凍結、版本資訊;錯誤是型別化的
//! `RelayError`。引擎經由 `RelayApi` trait 使用它(測試以記憶體假中繼 `fake_relay` 實作同一個 trait)。

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::sync::crypto::is_chain_id;
pub use crate::sync::record::Envelope;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// `POST /v1/pull` 一次最多幾條 chain(spec §6.1);更多就由呼叫端分批。
pub const MAX_BATCH_PULL: usize = 64;
/// 一次上傳最多幾筆(relay 的 `MAX_ITEMS_PER_PUSH`)。
const MAX_PUSH_ITEMS: usize = 200;
/// cursor 與 relay 序號的上限:relay 以 JavaScript 的 safe integer 檢查 `since`(spec §6.1),序號也不會超過它。
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// `GET /v1/info` 回報的功能名稱(spec §6.3)。
pub const FEATURE_PULL_BATCH: &str = "pull-batch";
pub const FEATURE_FREEZE: &str = "freeze";
/// 輪詢間隔的下限與每條 chain 的增量(spec §6.4)。
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(45);
const POLL_INTERVAL_PER_CHAIN: Duration = Duration::from_secs(2);
/// `429` 之後的退避:90 秒起每次加倍,最長 15 分鐘(spec §6.4)。`backoff_delay` 把加倍的次數以 `.min(10)` 封頂:
/// 90 秒 × 2^9 早已超過 15 分鐘的上限,不封頂的話連續 65 輪以上會讓 `<<` 的位移量超過 63(debug 建置直接 panic)。
const FIRST_BACKOFF_SECS: u64 = 90;
const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushItem {
    pub id_hash: String,
    pub kind: String,
    pub nonce: String,
    pub ciphertext: String,
    pub deleted: bool,
    /// 本機最後看到的該記錄序號(新記錄為 0);中繼較新則回 conflict。
    pub base_seq: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PushResult {
    Accepted { seq: u64 },
    Conflict { current: Envelope },
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum WirePushResult {
    Ok { seq: u64 },
    Conflict { current: Envelope },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WirePushResponse {
    results: Vec<WirePushResult>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullResponse {
    pub records: Vec<Envelope>,
    pub latest_seq: u64,
}

fn push_results(body: WirePushResponse) -> Vec<PushResult> {
    body.results
        .into_iter()
        .map(|r| match r {
            WirePushResult::Ok { seq } => PushResult::Accepted { seq },
            WirePushResult::Conflict { current } => PushResult::Conflict { current },
        })
        .collect()
}

/// 一般的輪詢間隔(spec §6.4):max(45 秒, 2 秒 × 本輪要查的 chain 數);chain 數含帳戶 chain。
/// 單台電腦每小時的 `pull` 項數因此維持在約 1,800 以下。
pub fn poll_interval(chains: usize) -> Duration {
    let chains = u32::try_from(chains).unwrap_or(u32::MAX);
    MIN_POLL_INTERVAL.max(POLL_INTERVAL_PER_CHAIN.saturating_mul(chains))
}

/// 閒置時的輪詢間隔:relay 的配額有限(Cloudflare Workers Free 每天 100,000 次 Durable Object 請求;每次輪詢 = 1 次
/// 限流計數 + 批次裡每條 chain 1 次),視窗不在前景、最近也沒有操作的電腦約每 5 分鐘查一次就好。
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// 這段時間內有操作(app 存檔、Sync 命令、視窗回到前景)就算「正在用」。
pub const ACTIVE_WINDOW: Duration = Duration::from_secs(5 * 60);

/// 連續 `consecutive_failures` 輪以 `429`(整批或 `rate_limited`)、relay `5xx` 或 keychain 失敗收尾之後的退避(spec §6.4):90 秒起每輪加倍,最長 15 分鐘;沒有失敗 → 0。
/// 同步引擎的背景執行緒在這段時間內不讓順便的喚醒(存檔、視窗取得焦點)提早開始一輪(`engine::wake_implicit`)。
pub fn backoff_delay(consecutive_failures: u32) -> Duration {
    match consecutive_failures {
        0 => Duration::ZERO,
        n => Duration::from_secs(FIRST_BACKOFF_SECS << (n.min(10) - 1)).min(MAX_BACKOFF),
    }
}

/// 下一輪之前等多久(spec §6.4 + relay 配額):
/// - 正在用(`focused`,或 `ACTIVE_WINDOW` 內有操作 —— `last_activity_ms` 比 `now_ms` 晚也算,但晚超過一個 `ACTIVE_WINDOW`
///   的不算:那是時鐘倒退之後留下的舊戳記,算的話間隔會一直是一般間隔,直到時鐘追上它):一般間隔 max(45 秒, 2 秒 × chain 數);
/// - 閒置:max(5 分, 2 秒 × chain 數);
/// - `consecutive_failures` = 連續以 `429`(整批或 `rate_limited`)或 relay `5xx` 收尾的輪數:`backoff_delay`,但不短於上面的間隔。成功一輪後呼叫端把計數歸零。
///   被限流時絕不立刻重試。
pub fn next_poll_delay(chains: usize, focused: bool, last_activity_ms: u64, now_ms: u64, consecutive_failures: u32) -> Duration {
    let window = ACTIVE_WINDOW.as_millis() as u64;
    let recent = last_activity_ms <= now_ms.saturating_add(window) && now_ms.saturating_sub(last_activity_ms) < window;
    let active = focused || recent;
    let normal = if active { poll_interval(chains) } else { IDLE_POLL_INTERVAL.max(poll_interval(chains)) };
    normal.max(backoff_delay(consecutive_failures))
}

/// relay 的 HTTP client:不跟隨 redirect —— 避免 https → http 降級把 bearer token 送上明文連線。
fn http_client() -> Result<reqwest::blocking::Client, AppError> {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("sshelter/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AppError::Other(format!("cannot build HTTP client: {e}")))
}

/// v2 client 的錯誤。訊息絕不含權杖(權杖只在 `Authorization` header 或批次的 body 裡)。
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// 404:chain 不存在或權杖不符(relay 刻意不區分)。
    #[error("sync chain not found on the relay (or the sync code does not match)")]
    NotFound,
    /// 429:整個請求被限流(每 IP 或每 chain);呼叫端依 spec §6.4 退避。
    #[error("the relay is rate-limiting this device; try again later")]
    RateLimited,
    /// 413:請求太大(單筆密文超過 64 KiB、上傳的 body 超過 1 MiB、批次查詢的 body 超過 64 KiB),或 chain 的儲存額度已滿
    /// —— relay 對這幾種都回 413,分不出來。
    #[error("the relay refused the request: too large or over the storage quota")]
    QuotaExceeded,
    /// relay 沒有這個端點(舊版 relay 對 `POST /v1/pull` 回 404)。
    #[error("the relay does not support {0} yet; update the relay")]
    Unsupported(&'static str),
    /// 請求不合規格(批次超過 64 項、chain 重複、chain id 或權杖不是 64 字元小寫 hex、`since` 太大、上傳是空的、超過 200 筆
    /// 或同一個 `id_hash` 出現兩次):沒有送出。
    #[error("invalid relay request: {0}")]
    InvalidRequest(String),
    /// 其他 HTTP 狀態(含 3xx:不跟隨 redirect)。
    #[error("relay returned HTTP {0}")]
    Http(u16),
    /// 連不上(DNS、連線、逾時,含讀回應 body 時逾時或連線中途斷掉)。訊息可能含 URL,不含權杖。
    #[error("cannot reach the sync relay: {0}")]
    Unreachable(String),
    /// 回應讀不懂、與請求對不上(筆數、順序),或序號超出 safe integer 的範圍。
    #[error("relay sent an unexpected response: {0}")]
    BadResponse(String),
}

impl From<RelayError> for AppError {
    fn from(e: RelayError) -> Self {
        let message = e.to_string();
        match e {
            RelayError::NotFound => AppError::NotFound(message),
            _ => AppError::Other(message),
        }
    }
}

/// `GET /v1/info` 的結果(spec §6.3)。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayInfo {
    /// relay 回報的版本;None = 舊版 relay(沒有這個端點,也就沒有任何新功能)。
    pub version: Option<String>,
    pub features: Vec<String>,
}

impl RelayInfo {
    pub fn supports(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

#[derive(Deserialize)]
struct WireInfo {
    relay: String,
    version: String,
    features: Vec<String>,
}

/// `POST /v1/pull` 的一項(wire 欄位就是 `chain`、`token`、`since`)。`Debug` 不印出權杖。
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BatchPullItem {
    pub chain: String,
    pub token: String,
    pub since: u64,
}

impl std::fmt::Debug for BatchPullItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchPullItem").field("chain", &self.chain).field("since", &self.since).finish_non_exhaustive()
    }
}

/// 批次查詢裡一條 chain 的結果(spec §6.1)。
#[derive(Clone, Debug, PartialEq)]
pub enum BatchPullResult {
    /// 與 `GET /v1/chains/{id}/records?since=` 相同的內容。
    Ok(PullResponse),
    /// chain 不存在或權杖不符。
    NotFound,
    /// 這條 chain 超過每分鐘 120 次的限制。
    RateLimited,
    /// 這批回應已達預算、這項沒有執行:cursor 不推進,呼叫端把它排在下一批最前面立刻再查(spec §6.4)。
    Deferred,
}

/// 批次查詢的一項結果;順序與請求相同,`chain` 已核對過。
#[derive(Clone, Debug, PartialEq)]
pub struct BatchPullEntry {
    pub chain: String,
    pub result: BatchPullResult,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WireBatchEntry {
    Ok {
        chain: String,
        records: Vec<Envelope>,
        #[serde(rename = "latestSeq")]
        latest_seq: u64,
    },
    NotFound {
        chain: String,
    },
    RateLimited {
        chain: String,
    },
    Deferred {
        chain: String,
    },
}

#[derive(Deserialize)]
struct WireBatchResponse {
    results: Vec<WireBatchEntry>,
}

/// 上傳的結果(spec §6.2、§6.4)。
#[derive(Clone, Debug, PartialEq)]
pub enum PushOutcome {
    /// 每項的結果,順序同請求(筆數已核對)。
    Applied(Vec<PushResult>),
    /// `409 { "status": "frozen" }`:chain 已被凍結(更換同步碼),什麼都沒寫入。呼叫端立刻停止這一輪的所有上傳、
    /// 保留 dirty,下一輪拉帳戶 chain 確認更換標記。
    Frozen,
}

#[derive(Deserialize)]
struct WireStatus {
    status: String,
}

/// v2 中繼抽象(spec §6):引擎只依賴它,測試以記憶體假中繼實作。語意見 `RelayClient` 的實作。
pub trait RelayApi {
    /// `GET /v1/info`:舊版 relay(404)→ `RelayInfo::default()`。
    fn info(&self) -> Result<RelayInfo, RelayError>;
    /// `PUT /v1/chains/{id}`:建立(201)或已存在且權杖相符(200)都是 Ok。
    fn create_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError>;
    fn delete_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError>;
    /// `POST /v1/chains/{id}/freeze`:冪等。舊版 relay 也回 404 —— 呼叫前先確認 `RelayInfo` 有 `freeze`。
    fn freeze_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError>;
    fn pull(&self, chain_id: &str, token: &str, since: u64) -> Result<PullResponse, RelayError>;
    /// `POST /v1/pull`:1–64 項(空的不發請求,回空)。結果順序與請求相同。
    fn pull_batch(&self, items: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError>;
    fn push(&self, chain_id: &str, token: &str, items: &[PushItem]) -> Result<PushOutcome, RelayError>;
}

/// v2 client(spec §6.4):不綁權杖,每次呼叫帶入該 chain 的權杖。
pub struct RelayClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl RelayClient {
    /// 只接受 `https://`;`http://` 僅限 loopback host(本機 `wrangler dev`)。回傳去掉尾斜線的正規化
    /// URL。純驗證、不建 client:A3 的 `sync_set_relay_url` 在 tokio 執行緒上也能用。bearer token 有
    /// 整條 chain 的讀寫刪權限,明文送出等於把 chain 交給網路上的任何人。
    pub fn validate_url(base_url: &str) -> Result<String, AppError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        let url = reqwest::Url::parse(trimmed)
            .map_err(|_| AppError::Other("relay URL must be a full URL such as https://relay.example.com".to_string()))?;
        // `Url::host_str` 對 IPv6 回含中括號的 "[::1]"。
        let loopback = matches!(url.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]"));
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            "http" => {
                return Err(AppError::Other(
                    "relay URL must use https:// (plain http is only allowed for 127.0.0.1 / localhost)".to_string(),
                ))
            }
            _ => return Err(AppError::Other("relay URL must start with https://".to_string())),
        }
        // endpoint 是用字串接在 base 後面的:query/fragment 會把 `/v1/...` 吞掉,userinfo 沒有理由出現。
        if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
            return Err(AppError::Other("relay URL must not contain a query, fragment or credentials".to_string()));
        }
        Ok(trimmed.to_string())
    }

    pub fn new(base_url: &str) -> Result<Self, AppError> {
        Ok(Self { base_url: Self::validate_url(base_url)?, http: http_client()? })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// chain id 與權杖都必須是 64 字元小寫 hex:chain id 會被組進 URL,格式不對的請求根本不送出。
fn check_chain(chain_id: &str, token: &str) -> Result<(), RelayError> {
    if is_chain_id(chain_id) && is_chain_id(token) {
        Ok(())
    } else {
        Err(RelayError::InvalidRequest("chain id and token must be 64 lowercase hex characters".to_string()))
    }
}

/// 請求送不出去(DNS、連線、逾時)。reqwest 的錯誤訊息可能含 URL(chain id),不含權杖。
fn unreachable_error(e: reqwest::Error) -> RelayError {
    RelayError::Unreachable(e.to_string())
}

/// 非預期狀態碼的統一映射:404 = chain 不存在或權杖不符(relay 刻意不區分)。
fn status_error(code: u16) -> RelayError {
    match code {
        404 => RelayError::NotFound,
        413 => RelayError::QuotaExceeded,
        429 => RelayError::RateLimited,
        other => RelayError::Http(other),
    }
}

/// 先把整個 body 讀完再解析。讀不完(逾時、連線中途斷掉)是連線的問題 → `Unreachable`,呼叫端照「連不上」處理,不會當成
/// relay 送來壞資料(reqwest 0.13 的 `Response::json` 把這兩種都包成 decode 錯誤,分不出來,所以不用它);讀完了卻不是
/// 預期的 JSON → `BadResponse`。訊息只有位置,不帶 body 的內容。
fn read_json<T: serde::de::DeserializeOwned>(resp: reqwest::blocking::Response) -> Result<T, RelayError> {
    let body = read_body(resp)?;
    serde_json::from_slice(body.as_ref()).map_err(|e| {
        RelayError::BadResponse(format!("the answer is not the expected JSON (line {}, column {})", e.line(), e.column()))
    })
}

/// 讀完整個 body:讀不完(逾時、連線中途斷掉)→ `Unreachable`(見 `read_json`)。
fn read_body(resp: reqwest::blocking::Response) -> Result<impl AsRef<[u8]>, RelayError> {
    resp.bytes().map_err(|e| {
        RelayError::Unreachable(if e.is_timeout() {
            "the relay's answer timed out".to_string()
        } else {
            "the connection broke off while reading the relay's answer".to_string()
        })
    })
}

/// `since` 必須是 relay 認得的 safe integer(spec §6.1);超出範圍就不送出。
fn check_cursor(since: u64) -> Result<(), RelayError> {
    if since > MAX_SAFE_INTEGER {
        return Err(RelayError::InvalidRequest("a pull cursor is out of range".to_string()));
    }
    Ok(())
}

/// relay 回來的序號(`latestSeq` 與每筆的 `seq`)都要在 safe integer 的範圍內。呼叫端把 `latestSeq` 存成下一輪的 `since`:
/// 一個超出範圍的值會讓之後每一次查詢都在送出前被 `check_cursor` 擋下(批次時整批),那條 chain 永遠卡住 —— 所以當成讀不懂
/// 的回應,cursor 不推進。
fn checked_seqs(resp: PullResponse) -> Result<PullResponse, RelayError> {
    if resp.latest_seq > MAX_SAFE_INTEGER || resp.records.iter().any(|r| r.seq > MAX_SAFE_INTEGER) {
        return Err(RelayError::BadResponse("the relay answered with a sequence number out of range".to_string()));
    }
    Ok(resp)
}

/// 上傳結果裡的序號(接受後的 `seq`、衝突時 relay 上那一版的 `seq`)同樣要在 safe integer 的範圍內:呼叫端把它們存成快取
/// 的序號與之後上傳的 `base_seq`,和 `checked_seqs` 同一個理由 —— 超出範圍就當成讀不懂的回應。
fn checked_push_results(results: Vec<PushResult>) -> Result<Vec<PushResult>, RelayError> {
    let out_of_range = |result: &PushResult| match result {
        PushResult::Accepted { seq } => *seq > MAX_SAFE_INTEGER,
        PushResult::Conflict { current } => current.seq > MAX_SAFE_INTEGER,
    };
    if results.iter().any(out_of_range) {
        return Err(RelayError::BadResponse("the relay answered a push with a sequence number out of range".to_string()));
    }
    Ok(results)
}

/// 上傳送出前的檢查(relay 的規則):1–200 筆、同一個 `id_hash` 不重複。違反的請求 relay 只會回 400,還白白用掉每 IP 的
/// 請求額度。
fn check_push(items: &[PushItem]) -> Result<(), RelayError> {
    if items.is_empty() || items.len() > MAX_PUSH_ITEMS {
        return Err(RelayError::InvalidRequest(format!("a push takes 1 to {MAX_PUSH_ITEMS} records")));
    }
    let mut seen = HashSet::new();
    if !items.iter().all(|item| seen.insert(item.id_hash.as_str())) {
        return Err(RelayError::InvalidRequest("a record appears twice in one push".to_string()));
    }
    Ok(())
}

/// 批次查詢送出前的檢查(spec §6.1):≤ 64 項、chain 不重複、chain 與權杖是 64 字元小寫 hex、`since` 是 safe integer。
fn check_batch(items: &[BatchPullItem]) -> Result<(), RelayError> {
    if items.len() > MAX_BATCH_PULL {
        return Err(RelayError::InvalidRequest(format!("a batch pull takes at most {MAX_BATCH_PULL} chains")));
    }
    let mut seen = HashSet::new();
    for item in items {
        check_chain(&item.chain, &item.token)?;
        check_cursor(item.since)?;
        if !seen.insert(item.chain.as_str()) {
            return Err(RelayError::InvalidRequest("a chain appears twice in one batch pull".to_string()));
        }
    }
    Ok(())
}

/// 每項的結果必須和請求一一對上(筆數與順序)—— 對不上就整批不採用,絕不把記錄算到別條 chain 上。
fn batch_entries(items: &[BatchPullItem], body: WireBatchResponse) -> Result<Vec<BatchPullEntry>, RelayError> {
    if body.results.len() != items.len() {
        return Err(RelayError::BadResponse("the batch pull answered a different number of chains".to_string()));
    }
    items
        .iter()
        .zip(body.results)
        .map(|(item, entry)| {
            let (chain, result) = match entry {
                WireBatchEntry::Ok { chain, records, latest_seq } => {
                    (chain, BatchPullResult::Ok(checked_seqs(PullResponse { records, latest_seq })?))
                }
                WireBatchEntry::NotFound { chain } => (chain, BatchPullResult::NotFound),
                WireBatchEntry::RateLimited { chain } => (chain, BatchPullResult::RateLimited),
                WireBatchEntry::Deferred { chain } => (chain, BatchPullResult::Deferred),
            };
            if chain != item.chain {
                return Err(RelayError::BadResponse("the batch pull answered chains out of order".to_string()));
            }
            Ok(BatchPullEntry { chain, result })
        })
        .collect()
}

impl RelayApi for RelayClient {
    fn info(&self) -> Result<RelayInfo, RelayError> {
        let resp = self.http.get(self.url("/v1/info")).send().map_err(unreachable_error)?;
        match resp.status().as_u16() {
            200 => {
                let wire: WireInfo = read_json(resp)?;
                if wire.relay != "sshelter-relay" {
                    return Err(RelayError::BadResponse("this server is not an SSHelter relay".to_string()));
                }
                Ok(RelayInfo { version: Some(wire.version), features: wire.features })
            }
            // 舊版 relay 沒有這個端點(router 的 not found):沒有批次查詢、沒有凍結。
            404 => Ok(RelayInfo::default()),
            code => Err(status_error(code)),
        }
    }

    fn create_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        check_chain(chain_id, token)?;
        let resp = self
            .http
            .put(self.url(&format!("/v1/chains/{chain_id}")))
            .bearer_auth(token)
            .json(&serde_json::json!({}))
            .send()
            .map_err(unreachable_error)?;
        match resp.status() {
            s if s.is_success() => Ok(()),
            s => Err(status_error(s.as_u16())),
        }
    }

    fn delete_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        check_chain(chain_id, token)?;
        let resp = self
            .http
            .delete(self.url(&format!("/v1/chains/{chain_id}")))
            .bearer_auth(token)
            .send()
            .map_err(unreachable_error)?;
        match resp.status() {
            s if s.is_success() => Ok(()),
            s => Err(status_error(s.as_u16())),
        }
    }

    fn freeze_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        check_chain(chain_id, token)?;
        let resp = self
            .http
            .post(self.url(&format!("/v1/chains/{chain_id}/freeze")))
            .bearer_auth(token)
            .send()
            .map_err(unreachable_error)?;
        match resp.status() {
            s if s.is_success() => Ok(()),
            s => Err(status_error(s.as_u16())),
        }
    }

    fn pull(&self, chain_id: &str, token: &str, since: u64) -> Result<PullResponse, RelayError> {
        check_chain(chain_id, token)?;
        check_cursor(since)?;
        let resp = self
            .http
            .get(self.url(&format!("/v1/chains/{chain_id}/records?since={since}")))
            .bearer_auth(token)
            .send()
            .map_err(unreachable_error)?;
        match resp.status().as_u16() {
            200 => checked_seqs(read_json(resp)?),
            code => Err(status_error(code)),
        }
    }

    fn pull_batch(&self, items: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        check_batch(items)?;
        // 不帶 `Authorization`:每項的權杖在 body 裡(spec §6.1)。
        let resp = self.http.post(self.url("/v1/pull")).json(items).send().map_err(unreachable_error)?;
        match resp.status().as_u16() {
            200 => batch_entries(items, read_json(resp)?),
            // 舊版 relay 沒有這個端點。
            404 => Err(RelayError::Unsupported(FEATURE_PULL_BATCH)),
            code => Err(status_error(code)),
        }
    }

    fn push(&self, chain_id: &str, token: &str, items: &[PushItem]) -> Result<PushOutcome, RelayError> {
        check_chain(chain_id, token)?;
        check_push(items)?;
        let resp = self
            .http
            .post(self.url(&format!("/v1/chains/{chain_id}/records")))
            .bearer_auth(token)
            .json(items)
            .send()
            .map_err(unreachable_error)?;
        match resp.status().as_u16() {
            200 => {
                let results = checked_push_results(push_results(read_json(resp)?))?;
                if results.len() != items.len() {
                    return Err(RelayError::BadResponse("the relay answered a push with the wrong number of results".to_string()));
                }
                Ok(PushOutcome::Applied(results))
            }
            // 凍結的 chain 一律回 `409 { "status": "frozen" }`;其他 409 不認。body 讀不完(逾時、斷線)是連線的問題,
            // 和其他回應一樣是 `Unreachable`。
            409 => match serde_json::from_slice::<WireStatus>(read_body(resp)?.as_ref()) {
                Ok(body) if body.status == "frozen" => Ok(PushOutcome::Frozen),
                _ => Err(RelayError::Http(409)),
            },
            code => Err(status_error(code)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Matcher;

    fn item(id: &str, base: u64) -> PushItem {
        PushItem {
            id_hash: id.to_string(),
            kind: "host".to_string(),
            nonce: "bm9uY2U=".to_string(),
            ciphertext: "Y2lwaGVy".to_string(),
            deleted: false,
            base_seq: base,
        }
    }

    #[test]
    fn rejects_relay_url_without_scheme() {
        assert!(RelayClient::new("sync.example.com").is_err());
        assert!(RelayClient::new("").is_err());
    }

    #[test]
    fn rejects_plain_http_except_loopback() {
        // 權杖有整條 chain 的權限:非 loopback 一律要 https。
        assert!(RelayClient::new("http://sync.example.com").is_err());
        assert!(RelayClient::new("http://10.0.0.5:8787").is_err());
        assert!(RelayClient::new("ftp://sync.example.com").is_err());
        assert!(RelayClient::new("https://sync.example.com").is_ok());
        assert!(RelayClient::new("http://127.0.0.1:8787").is_ok());
        assert!(RelayClient::new("http://localhost:8787/").is_ok());
        assert!(RelayClient::new("http://[::1]:8787").is_ok());
    }

    #[test]
    fn validate_url_normalizes_without_building_a_client() {
        assert_eq!(RelayClient::validate_url(" https://relay.example.com/ ").unwrap(), "https://relay.example.com");
        assert_eq!(RelayClient::validate_url("https://relay.example.com/prefix/").unwrap(), "https://relay.example.com/prefix");
        assert!(RelayClient::validate_url("http://relay.example.com").is_err());
        // endpoint 用字串接在後面:query / fragment / userinfo 都拒絕。
        assert!(RelayClient::validate_url("https://relay.example.com/#x").is_err());
        assert!(RelayClient::validate_url("https://relay.example.com/?a=1").is_err());
        assert!(RelayClient::validate_url("https://user:pw@relay.example.com").is_err());
    }

    // ── v2 client ────────────────────────────────────────────────────────────

    fn hex(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn batch_item(chain: &str, token: &str, since: u64) -> BatchPullItem {
        BatchPullItem { chain: chain.to_string(), token: token.to_string(), since }
    }

    #[test]
    fn each_call_carries_its_own_chain_token() {
        let mut server = mockito::Server::new();
        let (a, b, ta, tb) = (hex('a'), hex('b'), hex('1'), hex('2'));
        let put = server
            .mock("PUT", format!("/v1/chains/{a}").as_str())
            .match_header("authorization", format!("Bearer {ta}").as_str())
            .with_status(201)
            .with_body("{}")
            .create();
        let delete = server
            .mock("DELETE", format!("/v1/chains/{b}").as_str())
            .match_header("authorization", format!("Bearer {tb}").as_str())
            .with_status(204)
            .create();
        let client = RelayClient::new(&server.url()).unwrap();
        let relay: &dyn RelayApi = &client;
        relay.create_chain(&a, &ta).unwrap();
        relay.delete_chain(&b, &tb).unwrap();
        put.assert();
        delete.assert();
    }

    #[test]
    fn info_reports_version_and_features_and_an_old_relay_has_none() {
        let mut current = mockito::Server::new();
        current
            .mock("GET", "/v1/info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"relay":"sshelter-relay","version":"0.2.0","features":["pull-batch","freeze"]}"#)
            .create();
        let info = RelayClient::new(&current.url()).unwrap().info().unwrap();
        assert_eq!(info.version.as_deref(), Some("0.2.0"));
        assert!(info.supports(FEATURE_PULL_BATCH) && info.supports(FEATURE_FREEZE));

        let mut old = mockito::Server::new();
        old.mock("GET", "/v1/info").with_status(404).create();
        let info = RelayClient::new(&old.url()).unwrap().info().unwrap();
        assert_eq!(info, RelayInfo::default());
        assert!(!info.supports(FEATURE_PULL_BATCH) && !info.supports(FEATURE_FREEZE));

        let mut foreign = mockito::Server::new();
        foreign.mock("GET", "/v1/info").with_status(200).with_body(r#"{"relay":"other","version":"1","features":[]}"#).create();
        assert!(matches!(RelayClient::new(&foreign.url()).unwrap().info(), Err(RelayError::BadResponse(_))));

        let mut busy = mockito::Server::new();
        busy.mock("GET", "/v1/info").with_status(429).create();
        assert!(matches!(RelayClient::new(&busy.url()).unwrap().info(), Err(RelayError::RateLimited)));
    }

    #[test]
    fn freeze_succeeds_on_204_and_a_wrong_token_is_not_found() {
        let mut server = mockito::Server::new();
        let (a, b, ta) = (hex('a'), hex('b'), hex('1'));
        let frozen = server
            .mock("POST", format!("/v1/chains/{a}/freeze").as_str())
            .match_header("authorization", format!("Bearer {ta}").as_str())
            .with_status(204)
            .create();
        server.mock("POST", format!("/v1/chains/{b}/freeze").as_str()).with_status(404).create();
        let client = RelayClient::new(&server.url()).unwrap();
        client.freeze_chain(&a, &ta).unwrap();
        frozen.assert();
        assert!(matches!(client.freeze_chain(&b, &ta), Err(RelayError::NotFound)));
    }

    #[test]
    fn push_reports_a_frozen_chain_distinctly() {
        let mut server = mockito::Server::new();
        let (a, b, c, t) = (hex('a'), hex('b'), hex('c'), hex('1'));
        server.mock("POST", format!("/v1/chains/{a}/records").as_str()).with_status(409).with_body(r#"{"status":"frozen"}"#).create();
        server.mock("POST", format!("/v1/chains/{b}/records").as_str()).with_status(409).with_body(r#"{"error":"other"}"#).create();
        server.mock("POST", format!("/v1/chains/{c}/records").as_str()).with_status(413).create();
        let client = RelayClient::new(&server.url()).unwrap();
        assert_eq!(client.push(&a, &t, &[item("h1", 0)]).unwrap(), PushOutcome::Frozen);
        assert!(matches!(client.push(&b, &t, &[item("h1", 0)]), Err(RelayError::Http(409))));
        // relay 對太大的請求與額度已滿都回 413,分不出來:訊息兩種都說。
        let err = client.push(&c, &t, &[item("h1", 0)]).unwrap_err();
        assert!(matches!(err, RelayError::QuotaExceeded));
        assert_eq!(err.to_string(), "the relay refused the request: too large or over the storage quota");
    }

    #[test]
    fn push_parses_results_and_refuses_a_short_answer() {
        let mut server = mockito::Server::new();
        let (a, t) = (hex('a'), hex('1'));
        server
            .mock("POST", format!("/v1/chains/{a}/records").as_str())
            .match_header("authorization", format!("Bearer {t}").as_str())
            .with_status(200)
            .with_body(r#"{"results":[{"status":"ok","seq":12}],"latestSeq":12}"#)
            .create();
        let client = RelayClient::new(&server.url()).unwrap();
        assert_eq!(
            client.push(&a, &t, &[item("h1", 0)]).unwrap(),
            PushOutcome::Applied(vec![PushResult::Accepted { seq: 12 }])
        );
        assert!(matches!(client.push(&a, &t, &[item("h1", 0), item("h2", 0)]), Err(RelayError::BadResponse(_))));
        // 200 筆是 relay 的上限,照樣送出(這裡的假 relay 只回一筆結果,所以是 BadResponse 而不是 InvalidRequest)。
        let most: Vec<PushItem> = (0..200).map(|i| item(&format!("{i:064x}"), 0)).collect();
        assert!(matches!(client.push(&a, &t, &most), Err(RelayError::BadResponse(_))));
    }

    #[test]
    fn pull_maps_status_codes_to_typed_errors() {
        let mut server = mockito::Server::new();
        let (a, b, c, d, e, t) = (hex('a'), hex('b'), hex('c'), hex('d'), hex('e'), hex('1'));
        server
            .mock("GET", format!("/v1/chains/{a}/records?since=5").as_str())
            .match_header("authorization", format!("Bearer {t}").as_str())
            .with_status(200)
            .with_body(r#"{"records":[{"idHash":"h1","kind":"host","seq":6,"nonce":"n","ciphertext":"c","deleted":false}],"latestSeq":6}"#)
            .create();
        server.mock("GET", format!("/v1/chains/{b}/records?since=0").as_str()).with_status(404).create();
        server.mock("GET", format!("/v1/chains/{c}/records?since=0").as_str()).with_status(429).create();
        server.mock("GET", format!("/v1/chains/{d}/records?since=0").as_str()).with_status(500).create();
        server.mock("GET", format!("/v1/chains/{e}/records?since=0").as_str()).with_status(200).with_body("not json").create();
        let client = RelayClient::new(&server.url()).unwrap();
        assert_eq!(client.pull(&a, &t, 5).unwrap().latest_seq, 6);
        assert!(matches!(client.pull(&b, &t, 0), Err(RelayError::NotFound)));
        assert!(matches!(client.pull(&c, &t, 0), Err(RelayError::RateLimited)));
        assert!(matches!(client.pull(&d, &t, 0), Err(RelayError::Http(500))));
        assert!(matches!(client.pull(&e, &t, 0), Err(RelayError::BadResponse(_))));
    }

    #[test]
    fn batch_pull_sends_no_authorization_and_parses_every_status() {
        let mut server = mockito::Server::new();
        let (a, b, c, d, t) = (hex('a'), hex('b'), hex('c'), hex('d'), hex('1'));
        let items = vec![batch_item(&a, &t, 3), batch_item(&b, &t, 0), batch_item(&c, &t, 0), batch_item(&d, &t, 7)];
        let m = server
            .mock("POST", "/v1/pull")
            .match_header("authorization", Matcher::Missing)
            .match_body(Matcher::Json(serde_json::json!([
                { "chain": a, "token": t, "since": 3 },
                { "chain": b, "token": t, "since": 0 },
                { "chain": c, "token": t, "since": 0 },
                { "chain": d, "token": t, "since": 7 },
            ])))
            .with_status(200)
            .with_body(
                serde_json::json!({ "results": [
                    { "chain": a, "status": "ok", "records": [
                        { "idHash": "h1", "kind": "host", "seq": 4, "nonce": "n", "ciphertext": "c", "deleted": false }
                    ], "latestSeq": 4 },
                    { "chain": b, "status": "not_found" },
                    { "chain": c, "status": "rate_limited" },
                    { "chain": d, "status": "deferred" },
                ]})
                .to_string(),
            )
            .create();
        let entries = RelayClient::new(&server.url()).unwrap().pull_batch(&items).unwrap();
        m.assert();
        assert_eq!(entries.iter().map(|e| e.chain.as_str()).collect::<Vec<_>>(), vec![a.as_str(), b.as_str(), c.as_str(), d.as_str()]);
        match &entries[0].result {
            BatchPullResult::Ok(resp) => {
                assert_eq!(resp.latest_seq, 4);
                assert_eq!(resp.records[0].id_hash, "h1");
            }
            other => panic!("expected ok, got {other:?}"),
        }
        assert_eq!(entries[1].result, BatchPullResult::NotFound);
        assert_eq!(entries[2].result, BatchPullResult::RateLimited);
        assert_eq!(entries[3].result, BatchPullResult::Deferred);
    }

    #[test]
    fn batch_pull_refuses_answers_that_do_not_line_up_with_the_request() {
        let (a, b, t) = (hex('a'), hex('b'), hex('1'));
        let items = vec![batch_item(&a, &t, 0), batch_item(&b, &t, 0)];
        for body in [
            // 順序對調
            serde_json::json!({ "results": [{ "chain": b, "status": "not_found" }, { "chain": a, "status": "not_found" }] }),
            // 少一項
            serde_json::json!({ "results": [{ "chain": a, "status": "not_found" }] }),
            // 不認得的狀態
            serde_json::json!({ "results": [{ "chain": a, "status": "maybe" }, { "chain": b, "status": "not_found" }] }),
        ] {
            let mut server = mockito::Server::new();
            server.mock("POST", "/v1/pull").with_status(200).with_body(body.to_string()).create();
            let result = RelayClient::new(&server.url()).unwrap().pull_batch(&items);
            assert!(matches!(result, Err(RelayError::BadResponse(_))), "{body}");
        }
    }

    #[test]
    fn batch_pull_maps_whole_batch_errors() {
        let items = vec![batch_item(&hex('a'), &hex('1'), 0)];
        for (status, check) in [
            (429, (|e: &RelayError| matches!(e, RelayError::RateLimited)) as fn(&RelayError) -> bool),
            (404, |e| matches!(e, RelayError::Unsupported(FEATURE_PULL_BATCH))),
            (400, |e| matches!(e, RelayError::Http(400))),
        ] {
            let mut server = mockito::Server::new();
            server.mock("POST", "/v1/pull").with_status(status).create();
            let err = RelayClient::new(&server.url()).unwrap().pull_batch(&items).unwrap_err();
            assert!(check(&err), "{status}: {err:?}");
        }
    }

    #[test]
    fn requests_that_break_the_relay_rules_are_never_sent() {
        let mut server = mockito::Server::new();
        let never = server.mock("POST", Matcher::Any).expect(0).create();
        let never_get = server.mock("GET", Matcher::Any).expect(0).create();
        let client = RelayClient::new(&server.url()).unwrap();
        let (a, t) = (hex('a'), hex('f'));
        assert!(client.pull_batch(&[]).unwrap().is_empty(), "nothing to ask: no request");
        let too_many: Vec<BatchPullItem> = (0..65).map(|i| batch_item(&format!("{i:064x}"), &t, 0)).collect();
        assert!(matches!(client.pull_batch(&too_many), Err(RelayError::InvalidRequest(_))));
        assert!(matches!(client.pull_batch(&[batch_item(&a, &t, 0), batch_item(&a, &t, 1)]), Err(RelayError::InvalidRequest(_))));
        assert!(matches!(client.pull_batch(&[batch_item(&a, &t.to_uppercase(), 0)]), Err(RelayError::InvalidRequest(_))));
        assert!(matches!(client.pull_batch(&[batch_item(&a, &t, MAX_SAFE_INTEGER + 1)]), Err(RelayError::InvalidRequest(_))));
        assert!(matches!(client.push("../../v1/pull", &t, &[item("h1", 0)]), Err(RelayError::InvalidRequest(_))));
        assert!(matches!(client.freeze_chain(&a, "tok"), Err(RelayError::InvalidRequest(_))));
        // 單一 chain 的查詢:cursor 一樣不能超過 safe integer。
        assert!(matches!(client.pull(&a, &t, MAX_SAFE_INTEGER + 1), Err(RelayError::InvalidRequest(_))));
        // 上傳:空的、超過 200 筆、同一個 id_hash 兩次。
        assert!(matches!(client.push(&a, &t, &[]), Err(RelayError::InvalidRequest(_))));
        let too_many: Vec<PushItem> = (0..201).map(|i| item(&format!("{i:064x}"), 0)).collect();
        assert!(matches!(client.push(&a, &t, &too_many), Err(RelayError::InvalidRequest(_))));
        assert!(matches!(client.push(&a, &t, &[item("h1", 0), item("h2", 0), item("h1", 3)]), Err(RelayError::InvalidRequest(_))));
        never.assert();
        never_get.assert();
    }

    #[test]
    fn sequence_numbers_beyond_the_safe_integer_range_are_refused() {
        // relay 回來的 `latestSeq` 會被存成下一輪的 `since`:超出 safe integer 的值會讓那條 chain(批次時整批)之後每一次查詢
        // 都在送出前被擋下,永遠卡住 —— 所以整個回應不採用。
        let big = MAX_SAFE_INTEGER + 1;
        let (a, b, c, t) = (hex('a'), hex('b'), hex('c'), hex('1'));
        let record = |seq: u64| serde_json::json!({ "idHash": "h1", "kind": "host", "seq": seq, "nonce": "n", "ciphertext": "c", "deleted": false });
        let mut server = mockito::Server::new();
        for (chain, body) in [
            (&a, serde_json::json!({ "records": [], "latestSeq": big })),
            (&b, serde_json::json!({ "records": [record(big)], "latestSeq": 5 })),
            (&c, serde_json::json!({ "records": [record(MAX_SAFE_INTEGER)], "latestSeq": MAX_SAFE_INTEGER })),
        ] {
            server.mock("GET", format!("/v1/chains/{chain}/records?since=0").as_str()).with_status(200).with_body(body.to_string()).create();
        }
        let client = RelayClient::new(&server.url()).unwrap();
        assert!(matches!(client.pull(&a, &t, 0), Err(RelayError::BadResponse(_))));
        assert!(matches!(client.pull(&b, &t, 0), Err(RelayError::BadResponse(_))));
        assert_eq!(client.pull(&c, &t, 0).unwrap().latest_seq, MAX_SAFE_INTEGER, "the bound itself is fine");
        // 批次查詢:任何一項的序號超出範圍 → 整批不採用。
        for entry in [
            serde_json::json!({ "chain": a, "status": "ok", "records": [], "latestSeq": big }),
            serde_json::json!({ "chain": a, "status": "ok", "records": [record(big)], "latestSeq": 5 }),
        ] {
            let mut server = mockito::Server::new();
            let body = serde_json::json!({ "results": [entry.clone(), { "chain": b, "status": "not_found" }] });
            server.mock("POST", "/v1/pull").with_status(200).with_body(body.to_string()).create();
            let result = RelayClient::new(&server.url()).unwrap().pull_batch(&[batch_item(&a, &t, 0), batch_item(&b, &t, 0)]);
            assert!(matches!(result, Err(RelayError::BadResponse(_))), "{entry}");
        }
        // 上傳的回應:接受後的 `seq` 與衝突時 relay 上那一版的 `seq` 也一樣(會被存成快取的序號與之後的 base_seq)。
        for (answer, ok) in [
            (serde_json::json!({ "status": "ok", "seq": big }), false),
            (serde_json::json!({ "status": "conflict", "current": record(big) }), false),
            (serde_json::json!({ "status": "ok", "seq": MAX_SAFE_INTEGER }), true),
            (serde_json::json!({ "status": "conflict", "current": record(MAX_SAFE_INTEGER) }), true),
        ] {
            let mut server = mockito::Server::new();
            let body = serde_json::json!({ "results": [answer.clone()], "latestSeq": 5 });
            server.mock("POST", format!("/v1/chains/{a}/records").as_str()).with_status(200).with_body(body.to_string()).create();
            let result = RelayClient::new(&server.url()).unwrap().push(&a, &t, &[item("h1", 0)]);
            assert_eq!(result.is_ok(), ok, "{answer}: {result:?}");
            if !ok {
                assert!(matches!(result, Err(RelayError::BadResponse(_))), "{answer}");
            }
        }
    }

    /// 只接一次連線的 127.0.0.1 伺服器:讀完請求(header 與 `Content-Length` 的 body),寫出 `head`(狀態列、header 與一部分
    /// body),然後 `hold` 時一直等到 client 斷線,否則立刻斷線。
    fn half_answer(head: &'static str, hold: bool) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (mut request, mut buf) = (Vec::new(), [0u8; 1024]);
            let complete = |request: &[u8]| {
                let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
                let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length = head.lines().find_map(|l| l.strip_prefix("content-length:")).map_or(0, |v| v.trim().parse().unwrap_or(0));
                request.len() >= end + 4 + length
            };
            while !complete(&request) {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            stream.write_all(head.as_bytes()).unwrap();
            stream.flush().unwrap();
            while hold && matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
        });
        (url, server)
    }

    #[test]
    fn an_answer_that_breaks_off_or_times_out_is_unreachable_not_bad() {
        let (a, t) = (hex('a'), hex('1'));
        const PARTIAL: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"records\":";
        // 宣告 100 bytes、只送了一部分就斷線:連線的問題,不是 relay 送來壞資料。
        let (url, server) = half_answer(PARTIAL, false);
        let err = RelayClient::new(&url).unwrap().pull(&a, &t, 0).unwrap_err();
        server.join().unwrap();
        assert!(matches!(err, RelayError::Unreachable(_)), "{err:?}");
        // header 到了、body 停住:讀 body 逾時(這裡的 client 只等 300 毫秒,正式的是 20 秒)。
        let (url, server) = half_answer(PARTIAL, true);
        let client = RelayClient {
            base_url: url,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_millis(300))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        };
        let started = std::time::Instant::now();
        let err = client.pull(&a, &t, 0).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(client);
        server.join().unwrap();
        assert!(matches!(&err, RelayError::Unreachable(m) if m.contains("timed out")), "{err:?}");
        assert!(!err.to_string().contains(&t));
        // 對照組:body 完整、只是不是預期的 JSON → BadResponse,訊息不帶 body 的內容。
        let (url, server) = half_answer("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nsecret-stuff!", false);
        let err = RelayClient::new(&url).unwrap().pull(&a, &t, 0).unwrap_err();
        server.join().unwrap();
        assert!(matches!(&err, RelayError::BadResponse(m) if !m.contains("secret")), "{err:?}");
        // 上傳的 409:body 讀不完一樣是連線的問題(不是「別的 409」);完整的非凍結 409 才是 `Http(409)`。
        const PARTIAL_409: &str = "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"status\":";
        let (url, server) = half_answer(PARTIAL_409, false);
        let err = RelayClient::new(&url).unwrap().push(&a, &t, &[item("h1", 0)]).unwrap_err();
        server.join().unwrap();
        assert!(matches!(err, RelayError::Unreachable(_)), "{err:?}");
        let (url, server) = half_answer(PARTIAL_409, true);
        let client = RelayClient {
            base_url: url,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_millis(300))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        };
        let err = client.push(&a, &t, &[item("h1", 0)]).unwrap_err();
        drop(client);
        server.join().unwrap();
        assert!(matches!(&err, RelayError::Unreachable(m) if m.contains("timed out")), "{err:?}");
        let (url, server) = half_answer("HTTP/1.1 409 Conflict\r\nContent-Length: 17\r\n\r\n{\"status\":\"busy\"}", false);
        let err = RelayClient::new(&url).unwrap().push(&a, &t, &[item("h1", 0)]).unwrap_err();
        server.join().unwrap();
        assert!(matches!(err, RelayError::Http(409)), "{err:?}");
    }

    #[test]
    fn redirects_are_never_followed() {
        // 307/308 會讓 client 把同一個請求(單一 chain 的 bearer token、批次查詢 body 裡每條 chain 的權杖)再送一次:
        // 絕不跟隨,轉向的目的地一次都不能被碰到。
        let mut elsewhere = mockito::Server::new();
        let never_post = elsewhere.mock("POST", Matcher::Any).expect(0).create();
        let never_get = elsewhere.mock("GET", Matcher::Any).expect(0).create();
        let (a, t) = (hex('a'), hex('1'));
        let records = format!("/v1/chains/{a}/records");
        let pull = format!("{records}?since=0");
        let mut relay = mockito::Server::new();
        relay.mock("POST", "/v1/pull").with_status(307).with_header("location", &format!("{}/v1/pull", elsewhere.url())).create();
        relay.mock("GET", pull.as_str()).with_status(308).with_header("location", &format!("{}{pull}", elsewhere.url())).create();
        relay.mock("POST", records.as_str()).with_status(307).with_header("location", &format!("{}{records}", elsewhere.url())).create();
        let client = RelayClient::new(&relay.url()).unwrap();
        assert!(matches!(client.pull_batch(&[batch_item(&a, &t, 0)]), Err(RelayError::Http(307))));
        assert!(matches!(client.pull(&a, &t, 0), Err(RelayError::Http(308))));
        assert!(matches!(client.push(&a, &t, &[item("h1", 0)]), Err(RelayError::Http(307))));
        never_post.assert();
        never_get.assert();
    }

    #[test]
    fn the_poll_interval_grows_with_the_number_of_chains() {
        assert_eq!(poll_interval(0), Duration::from_secs(45));
        // spec 的例子:10 個 space(加帳戶 11 條)→ 45 秒;64 個(65 條)→ 130 秒。
        assert_eq!(poll_interval(11), Duration::from_secs(45));
        assert_eq!(poll_interval(65), Duration::from_secs(130));
        assert_eq!(poll_interval(usize::MAX), Duration::from_secs(2) * u32::MAX);
    }

    #[test]
    fn the_poll_delay_follows_activity_and_backs_off_after_failures() {
        const NOW: u64 = 10_000_000;
        let active = |failures| next_poll_delay(1, true, 0, NOW, failures).as_secs();
        assert_eq!(active(0), 45);
        assert_eq!(active(1), 90);
        assert_eq!(active(2), 180);
        assert_eq!(active(3), 360);
        assert_eq!(active(4), 720);
        assert_eq!(active(5), 900);
        assert_eq!(active(u32::MAX), 900);
        // 退避本身(同步引擎的存檔、視窗取得焦點要等的那一段):不含輪詢間隔,沒有失敗就是 0;連續很多輪也不會 panic。
        let secs = |failures| backoff_delay(failures).as_secs();
        assert_eq!((secs(0), secs(1), secs(2), secs(3), secs(4), secs(5), secs(6), secs(u32::MAX)), (0, 90, 180, 360, 720, 900, 900, 900));
        // 視窗不在前景,但幾分鐘內有操作:照樣是一般間隔。
        assert_eq!(next_poll_delay(1, false, NOW - 60_000, NOW, 0).as_secs(), 45);
        // 閒置:約每 5 分鐘一次;退避不會比閒置間隔短。
        assert_eq!(next_poll_delay(1, false, NOW - 10 * 60_000, NOW, 0).as_secs(), 300);
        assert_eq!(next_poll_delay(1, false, 0, NOW, 1).as_secs(), 300);
        assert_eq!(next_poll_delay(1, false, 0, NOW, 3).as_secs(), 360);
        // chain 多的時候,一般間隔本身就比第一次退避長。
        assert_eq!(next_poll_delay(65, true, 0, NOW, 1).as_secs(), 130);
        // 時鐘倒退(最後操作在「未來」):不到一個視窗以內的當成正在用。
        assert_eq!(next_poll_delay(1, false, NOW + 5_000, NOW, 0).as_secs(), 45);
        assert_eq!(next_poll_delay(1, false, NOW + 5 * 60_000, NOW, 0).as_secs(), 45);
        // 更遠的(時鐘倒退很多之後留下的舊戳記)不理它:否則間隔會一直是一般間隔,直到時鐘追上它。視窗在前景時照樣是一般間隔。
        assert_eq!(next_poll_delay(1, false, NOW + 5 * 60_000 + 1, NOW, 0).as_secs(), 300);
        assert_eq!(next_poll_delay(1, false, NOW + 60 * 60_000, NOW, 0).as_secs(), 300);
        assert_eq!(next_poll_delay(1, true, NOW + 60 * 60_000, NOW, 0).as_secs(), 45);
    }

    #[test]
    fn v2_errors_and_debug_output_never_contain_the_token() {
        let (a, t) = (hex('a'), hex('7'));
        let client = RelayClient::new("http://127.0.0.1:9").unwrap();
        let started = std::time::Instant::now();
        let err = client.pull(&a, &t, 0).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10), "connect timeout");
        assert!(matches!(err, RelayError::Unreachable(_)));
        assert!(!err.to_string().contains(&t));
        assert!(!format!("{:?}", batch_item(&a, &t, 0)).contains(&t));
        // 轉成 AppError:404 仍是 NotFound(呼叫端據此分辨「chain 不在了」)。
        assert!(matches!(AppError::from(RelayError::NotFound), AppError::NotFound(_)));
        assert!(matches!(AppError::from(RelayError::RateLimited), AppError::Other(_)));
    }
}
