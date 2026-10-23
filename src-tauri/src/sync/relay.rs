//! Historical chain state types and local test interfaces. Production chain HTTP transport is retired.

use std::io::Read;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
pub use crate::sync::record::Envelope;

/// `POST /legacy/v1/pull` 一次最多幾條 chain(spec §6.1);更多就由呼叫端分批。
pub const MAX_BATCH_PULL: usize = 64;
/// 一次上傳最多幾筆(relay 的 `MAX_ITEMS_PER_PUSH`)。
/// `GET /legacy/v1/info` 回報的功能名稱(spec §6.3)。
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

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PullResponse {
    pub records: Vec<Envelope>,
    pub latest_seq: u64,
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
    /// relay 沒有這個端點(舊版 relay 對 `POST /legacy/v1/pull` 回 404)。
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

/// `GET /legacy/v1/info` 的結果(spec §6.3)。
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

/// `POST /legacy/v1/pull` 的一項(wire 欄位就是 `chain`、`token`、`since`)。`Debug` 不印出權杖。
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
    /// 與 `GET /legacy/v1/chains/{id}/records?since=` 相同的內容。
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

/// 上傳的結果(spec §6.2、§6.4)。
#[derive(Clone, Debug, PartialEq)]
pub enum PushOutcome {
    /// 每項的結果,順序同請求(筆數已核對)。
    Applied(Vec<PushResult>),
    /// `409 { "status": "frozen" }`:chain 已被凍結(更換同步碼),什麼都沒寫入。呼叫端立刻停止這一輪的所有上傳、
    /// 保留 dirty,下一輪拉帳戶 chain 確認更換標記。
    Frozen,
}

/// v2 中繼抽象(spec §6):引擎只依賴它,測試以記憶體假中繼實作。語意見 `RelayClient` 的實作。
pub trait RelayApi {
    /// `GET /legacy/v1/info`:舊版 relay(404)→ `RelayInfo::default()`。
    fn info(&self) -> Result<RelayInfo, RelayError>;
    /// `PUT /legacy/v1/chains/{id}`:建立(201)或已存在且權杖相符(200)都是 Ok。
    fn create_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError>;
    fn delete_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError>;
    /// `POST /legacy/v1/chains/{id}/freeze`:冪等。舊版 relay 也回 404 —— 呼叫前先確認 `RelayInfo` 有 `freeze`。
    fn freeze_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError>;
    fn pull(&self, chain_id: &str, token: &str, since: u64) -> Result<PullResponse, RelayError>;
    /// `POST /legacy/v1/pull`:1–64 項(空的不發請求,回空)。結果順序與請求相同。
    fn pull_batch(&self, items: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError>;
    fn push(&self, chain_id: &str, token: &str, items: &[PushItem]) -> Result<PushOutcome, RelayError>;
}

/// Historical state still validates saved origins, but this build cannot send chain requests.
pub fn validate_url(base_url: &str) -> Result<String, AppError> {
    let trimmed = base_url.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(trimmed)
        .map_err(|_| AppError::Other("relay URL must be a full URL such as https://relay.example.com".to_string()))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]"));
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => return Err(AppError::Other("relay URL must use https:// (plain http is only allowed for 127.0.0.1 / localhost)".to_string())),
        _ => return Err(AppError::Other("relay URL must start with https://".to_string())),
    }
    if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::Other("relay URL must not contain a query, fragment or credentials".to_string()));
    }
    Ok(trimmed.to_string())
}

/// Shared bounded response reader used by central account and OIDC transports.
pub(crate) fn read_capped(reader: impl Read, limit: usize) -> Result<Vec<u8>, RelayError> {
    let mut body = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut body).map_err(|error| {
        let timed_out = error.kind() == std::io::ErrorKind::TimedOut
            || error.get_ref().and_then(|source| source.downcast_ref::<reqwest::Error>()).is_some_and(reqwest::Error::is_timeout);
        RelayError::Unreachable(if timed_out {
            "the response timed out".into()
        } else {
            "the connection broke off while reading the response".into()
        })
    })?;
    if body.len() > limit {
        return Err(RelayError::BadResponse("the response exceeds the size limit".into()));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{read_capped, validate_url, RelayError};

    #[test]
    fn historical_origin_validation_rejects_credentials_and_unprotected_hosts() {
        assert_eq!(validate_url(" https://relay.example.com/ ").unwrap(), "https://relay.example.com");
        assert!(validate_url("http://relay.example.com").is_err());
        assert!(validate_url("https://user:pw@relay.example.com").is_err());
        assert!(validate_url("https://relay.example.com/?token=x").is_err());
    }

    #[test]
    fn bounded_reader_rejects_actual_bytes_beyond_limit() {
        assert_eq!(read_capped(&b"1234"[..], 4).unwrap(), b"1234");
        assert!(matches!(read_capped(&b"12345"[..], 4), Err(RelayError::BadResponse(_))));
    }
}
