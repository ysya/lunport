//! 中繼 HTTP client(spec §5)。只搬密文;所有錯誤映射成 `AppError`,絕不 panic。
//! 使用 blocking client:同步引擎跑在自己的 std 執行緒。**不可在 tokio runtime 內呼叫**
//! (`reqwest::blocking` 會 panic);Tauri command 要用 `tauri::async_runtime::spawn_blocking`。

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
pub use crate::sync::record::Envelope;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

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

pub struct RelayClient {
    base_url: String,
    auth_token: String,
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

    pub fn new(base_url: &str, auth_token: &str) -> Result<Self, AppError> {
        let base_url = Self::validate_url(base_url)?;
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("sshelter/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            // 不跟隨 redirect:避免 https → http 降級把 bearer token 送上明文連線。
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AppError::Other(format!("cannot build HTTP client: {e}")))?;
        Ok(Self {
            base_url,
            auth_token: auth_token.to_string(),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// 統一狀態碼映射:404 = chain 不存在或 token 不符(中繼刻意不區分)。
    fn check(resp: reqwest::blocking::Response) -> Result<reqwest::blocking::Response, AppError> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let code = status.as_u16();
        match code {
            404 => Err(AppError::NotFound("sync chain not found on the relay (or wrong recovery phrase)".to_string())),
            413 => Err(AppError::Other("relay refused the upload: chain storage quota exceeded".to_string())),
            429 => Err(AppError::Other("relay is rate-limiting this chain; try again later".to_string())),
            _ => Err(AppError::Other(format!("relay returned HTTP {code}"))),
        }
    }

    fn send_err(e: reqwest::Error) -> AppError {
        // reqwest 錯誤訊息可能含 URL,但不含 token(token 在 header)。
        AppError::Other(format!("cannot reach the sync relay: {e}"))
    }

    pub fn create_chain(&self, chain_id: &str) -> Result<(), AppError> {
        let resp = self
            .http
            .put(self.url(&format!("/v1/chains/{chain_id}")))
            .bearer_auth(&self.auth_token)
            .json(&serde_json::json!({}))
            .send()
            .map_err(Self::send_err)?;
        Self::check(resp).map(|_| ())
    }

    pub fn push(&self, chain_id: &str, items: &[PushItem]) -> Result<Vec<PushResult>, AppError> {
        let resp = self
            .http
            .post(self.url(&format!("/v1/chains/{chain_id}/records")))
            .bearer_auth(&self.auth_token)
            .json(items)
            .send()
            .map_err(Self::send_err)?;
        let body: WirePushResponse = Self::check(resp)?
            .json()
            .map_err(|e| AppError::Other(format!("relay sent an unreadable push response: {e}")))?;
        Ok(body
            .results
            .into_iter()
            .map(|r| match r {
                WirePushResult::Ok { seq } => PushResult::Accepted { seq },
                WirePushResult::Conflict { current } => PushResult::Conflict { current },
            })
            .collect())
    }

    pub fn pull(&self, chain_id: &str, since: u64) -> Result<PullResponse, AppError> {
        let resp = self
            .http
            .get(self.url(&format!("/v1/chains/{chain_id}/records?since={since}")))
            .bearer_auth(&self.auth_token)
            .send()
            .map_err(Self::send_err)?;
        Self::check(resp)?
            .json()
            .map_err(|e| AppError::Other(format!("relay sent an unreadable pull response: {e}")))
    }

    pub fn delete_chain(&self, chain_id: &str) -> Result<(), AppError> {
        let resp = self
            .http
            .delete(self.url(&format!("/v1/chains/{chain_id}")))
            .bearer_auth(&self.auth_token)
            .send()
            .map_err(Self::send_err)?;
        Self::check(resp).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn create_chain_sends_bearer_and_accepts_2xx() {
        let mut server = mockito::Server::new();
        let m = server
            .mock("PUT", "/v1/chains/abc")
            .match_header("authorization", "Bearer tok")
            .with_status(201)
            .with_body("{}")
            .create();
        let client = RelayClient::new(&server.url(), "tok").unwrap();
        client.create_chain("abc").unwrap();
        m.assert();
    }

    #[test]
    fn push_parses_accepted_and_conflict_results() {
        let mut server = mockito::Server::new();
        server
            .mock("POST", "/v1/chains/abc/records")
            .match_header("authorization", "Bearer tok")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"results":[{"status":"ok","seq":12},{"status":"conflict","current":{"idHash":"h2","kind":"host","seq":9,"nonce":"n","ciphertext":"c","deleted":true}}],"latestSeq":12}"#,
            )
            .create();
        let client = RelayClient::new(&server.url(), "tok").unwrap();
        let results = client.push("abc", &[item("h1", 0), item("h2", 3)]).unwrap();
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0], PushResult::Accepted { seq: 12 }));
        match &results[1] {
            PushResult::Conflict { current } => {
                assert_eq!(current.id_hash, "h2");
                assert_eq!(current.seq, 9);
                assert!(current.deleted);
            }
            other => panic!("expected conflict, got {other:?}"),
        }
    }

    #[test]
    fn pull_sends_since_and_parses_envelopes() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/v1/chains/abc/records?since=5")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"records":[{"idHash":"h1","kind":"host","seq":6,"nonce":"n","ciphertext":"c","deleted":false}],"latestSeq":6}"#)
            .create();
        let client = RelayClient::new(&server.url(), "tok").unwrap();
        let resp = client.pull("abc", 5).unwrap();
        assert_eq!(resp.latest_seq, 6);
        assert_eq!(resp.records.len(), 1);
        assert_eq!(resp.records[0].kind, "host");
    }

    #[test]
    fn unknown_chain_or_bad_token_is_not_found() {
        let mut server = mockito::Server::new();
        server.mock("GET", "/v1/chains/abc/records?since=0").with_status(404).create();
        let client = RelayClient::new(&server.url(), "tok").unwrap();
        assert!(matches!(client.pull("abc", 0), Err(AppError::NotFound(_))));
    }

    #[test]
    fn server_errors_and_garbage_bodies_become_errors_not_panics() {
        let mut server = mockito::Server::new();
        server.mock("GET", "/v1/chains/a/records?since=0").with_status(500).with_body("boom").create();
        server.mock("GET", "/v1/chains/b/records?since=0").with_status(200).with_body("not json").create();
        let client = RelayClient::new(&server.url(), "tok").unwrap();
        assert!(client.pull("a", 0).is_err());
        assert!(client.pull("b", 0).is_err());
    }

    #[test]
    fn unreachable_relay_fails_fast() {
        // 127.0.0.1:9 幾乎不會有人聽;connect timeout 2s 內必須回錯。
        let client = RelayClient::new("http://127.0.0.1:9", "tok").unwrap();
        let started = std::time::Instant::now();
        assert!(client.pull("abc", 0).is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn rejects_relay_url_without_scheme() {
        assert!(RelayClient::new("sync.example.com", "tok").is_err());
        assert!(RelayClient::new("", "tok").is_err());
    }

    #[test]
    fn rejects_plain_http_except_loopback() {
        // bearer token 有整條 chain 的權限:非 loopback 一律要 https。
        assert!(RelayClient::new("http://sync.example.com", "tok").is_err());
        assert!(RelayClient::new("http://10.0.0.5:8787", "tok").is_err());
        assert!(RelayClient::new("ftp://sync.example.com", "tok").is_err());
        assert!(RelayClient::new("https://sync.example.com", "tok").is_ok());
        assert!(RelayClient::new("http://127.0.0.1:8787", "tok").is_ok());
        assert!(RelayClient::new("http://localhost:8787/", "tok").is_ok());
        assert!(RelayClient::new("http://[::1]:8787", "tok").is_ok());
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
}
