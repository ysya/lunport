//! Bound loopback OAuth callback. No custom HTTP parser and no credentials in the webview.
use super::{authentication::Config as LoginConfig, oidc::{FreshLoginTokens, LoginAttempt as OidcAttempt, LoginTokens, OidcConfig}};
use crate::error::AppError;
use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    net::TcpListener,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;
use tokio::{
    sync::{oneshot, Semaphore},
    task::JoinSet,
};
const LOGIN_TTL: Duration = Duration::from_secs(600);
enum LoginAttempt { Oidc(OidcAttempt), Passkey(super::passkey::Attempt) }
impl LoginAttempt {
    fn validate_callback(&self,value:&str)->Result<String,AppError>{match self{Self::Oidc(a)=>a.validate_callback(value),Self::Passkey(a)=>a.validate_callback(value)}}
    fn finish(self,value:&str,http:&impl openidconnect::SyncHttpClient)->Result<LoginTokens,AppError>{match self{Self::Oidc(a)=>a.finish(value,http),Self::Passkey(a)=>a.finish(value,http)}}
    fn finish_fresh(self,value:&str,http:&impl openidconnect::SyncHttpClient)->Result<FreshLoginTokens,AppError>{match self{Self::Oidc(a)=>a.finish_fresh(value,http),Self::Passkey(a)=>a.finish_fresh(value,http)}}
}
fn error(message: &str) -> AppError {
    AppError::Other(message.into())
}
#[derive(Clone)]
pub struct LoginCancellation(Arc<Mutex<Option<oneshot::Sender<()>>>>);
impl LoginCancellation {
    pub fn cancel(&self) {
        if let Some(sender) = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = sender.send(());
        }
    }
}
/// Drop/cancel stops accepting requests and lets an already-written success response drain.
pub struct BrowserLogin {
    receiver: mpsc::Receiver<(LoginAttempt, String)>,
    cancel: LoginCancellation,
    started: Instant,
}
impl BrowserLogin {
    pub fn begin(
        config: impl Into<LoginConfig>,
        http: &impl openidconnect::SyncHttpClient,
    ) -> Result<(Self, String), AppError> {
        Self::begin_mode(config.into(), http, false, None)
    }
    pub fn begin_fresh(
        config: impl Into<LoginConfig>,
        http: &impl openidconnect::SyncHttpClient,
    ) -> Result<(Self, String), AppError> {
        Self::begin_mode(config.into(), http, true, None)
    }
    pub fn begin_fresh_for(config:LoginConfig,expected:&str,http:&impl openidconnect::SyncHttpClient)->Result<(Self,String),AppError>{Self::begin_mode(config,http,true,Some(expected.into()))}
    fn begin_mode(
        config: LoginConfig,
        http: &impl openidconnect::SyncHttpClient,
        fresh: bool,
        expected: Option<String>,
    ) -> Result<(Self, String), AppError> {
        // Bind before discovery/authorization URL construction; never race a separately chosen port.
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| error("Could not bind the local sign-in callback."))?;
        let authority = listener
            .local_addr()
            .map_err(|_| error("Could not bind the local sign-in callback."))?
            .to_string();
        listener
            .set_nonblocking(true)
            .map_err(|_| error("Could not prepare the local sign-in callback."))?;
        let port = listener
            .local_addr()
            .map_err(|_| error("Invalid local callback."))?
            .port();
        let (attempt,url)=match config {
            LoginConfig::Oidc(config)=>{
                let (a,url)=if fresh{OidcAttempt::begin_fresh(config,port,http)?}else{OidcAttempt::begin(config,port,http)?};
                (LoginAttempt::Oidc(a),url)
            },
            LoginConfig::Passkey(config)=>{let(a,url)=super::passkey::Attempt::begin(config,port,expected,fresh,http)?;(LoginAttempt::Passkey(a),url)},
        };
        let attempt = Arc::new(Mutex::new(Some(attempt)));
        let (sender, receiver) = mpsc::sync_channel(1);
        let (cancel, stop) = oneshot::channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| error("Could not start local sign-in."))?;
        std::thread::Builder::new().name("lunport-sign-in".into()).spawn(move || {
            runtime.block_on(async move {
                let Ok(listener)=tokio::net::TcpListener::from_std(listener) else {return;};
                let permits=Arc::new(Semaphore::new(4));
                let mut tasks=JoinSet::new();
                let deadline=tokio::time::sleep(LOGIN_TTL);tokio::pin!(deadline);tokio::pin!(stop);
                loop {
                    tokio::select! {
                        _=&mut stop=>break,
                        _=&mut deadline=>break,
                        Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                        incoming=listener.accept()=>{
                            let Ok((stream,peer))=incoming else {break;};
                            if !peer.ip().is_loopback() {continue;}
                            let Ok(permit)=Arc::clone(&permits).try_acquire_owned() else {continue;};
                            let attempt=Arc::clone(&attempt);let sender=sender.clone();let authority=authority.clone();
                            tasks.spawn(async move {
                                let _permit=permit;
                                let service=service_fn(move |request| std::future::ready(callback(request,&authority,&attempt,&sender)));
                                let (read,write)=stream.into_split();
                                // A read budget before the parser is a hard wire limit; parser buffer capacity alone is not.
                                let io=tokio::io::join(read.take(16384),write);
                                let mut builder=hyper::server::conn::http1::Builder::new();
                                builder.keep_alive(false).max_headers(16).max_buf_size(16384);
                                let _=tokio::time::timeout(Duration::from_secs(5),builder.serve_connection(TokioIo::new(io),service)).await;
                            });
                        }
                    }
                }
                drop(listener);
                // Response contains no code/state/token. Do not drop it mid-write on successful login.
                let _=tokio::time::timeout(Duration::from_secs(1),async {while tasks.join_next().await.is_some(){}}).await;
                tasks.abort_all();
            });
        }).map_err(|_|error("Could not start local sign-in."))?;
        Ok((
            Self {
                receiver,
                cancel: LoginCancellation(Arc::new(Mutex::new(Some(cancel)))),
                started: Instant::now(),
            },
            url,
        ))
    }
    pub fn finish(
        mut self,
        http: &impl openidconnect::SyncHttpClient,
    ) -> Result<LoginTokens, AppError> {
        let (attempt, callback) = self.receive_callback()?;
        attempt.finish(&callback, http)
    }
    pub fn finish_fresh(
        mut self,
        http: &impl openidconnect::SyncHttpClient,
    ) -> Result<FreshLoginTokens, AppError> {
        let (attempt, callback) = self.receive_callback()?;
        attempt.finish_fresh(&callback, http)
    }
    fn receive_callback(&mut self) -> Result<(LoginAttempt, String), AppError> {
        let remaining = LOGIN_TTL.saturating_sub(self.started.elapsed());
        let received = self
            .receiver
            .recv_timeout(remaining)
            .map_err(|_| error("Sign-in expired or was cancelled. Start again."))?;
        self.cancel();
        Ok(received)
    }
    pub fn cancellation(&self) -> LoginCancellation {
        self.cancel.clone()
    }
    pub fn cancel(&mut self) {
        self.cancel.cancel();
    }
    #[cfg(test)]
    fn take_callback(&self) -> (LoginAttempt, String) {
        self.receiver.recv_timeout(Duration::from_secs(3)).unwrap()
    }
}
impl Drop for BrowserLogin {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn reply(status: StatusCode) -> Response<Full<Bytes>> {
    let text = if status == StatusCode::OK {
        "Lunport sign-in received. You can close this tab and return to the app."
    } else {
        "This sign-in response could not be accepted. Return to Lunport to continue."
    };
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .header(
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        .header("x-content-type-options", "nosniff")
        .body(Full::new(Bytes::from_static(text.as_bytes())))
        .expect("static response")
}
fn callback(
    request: Request<hyper::body::Incoming>,
    authority: &str,
    attempt: &Mutex<Option<LoginAttempt>>,
    sender: &mpsc::SyncSender<(LoginAttempt, String)>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != hyper::Method::GET
        || !matches!(request.uri().path(),"/oauth/callback"|"/passkey/callback")
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request
            .headers()
            .get_all(hyper::header::HOST)
            .iter()
            .count()
            != 1
        || request
            .headers()
            .get(hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            != Some(authority)
        || request
            .headers()
            .contains_key(hyper::header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .is_some_and(|v| v.as_bytes() != b"0")
    {
        return Ok(reply(StatusCode::BAD_REQUEST));
    }
    let url = format!("http://{authority}{}", request.uri());
    let mut pending = attempt
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(current) = pending.as_ref() else {
        return Ok(reply(StatusCode::GONE));
    };
    // Invalid unsolicited requests do not consume the user's legitimate pending login.
    if current.validate_callback(&url).is_err() {
        return Ok(reply(StatusCode::BAD_REQUEST));
    }
    let current = pending.take().expect("checked pending attempt");
    let status = if sender.try_send((current, url)).is_ok() {
        StatusCode::OK
    } else {
        StatusCode::GONE
    };
    Ok(reply(status))
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn setup() -> (mockito::ServerGuard, BrowserLogin, reqwest::Url) {
        let mut provider = mockito::Server::new();
        let issuer = provider.url();
        provider.mock("GET","/.well-known/openid-configuration").with_header("content-type","application/json").with_body(json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/jwks"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}).to_string()).create();
        provider
            .mock("GET", "/jwks")
            .with_header("content-type", "application/json")
            .with_body("{\"keys\":[]}")
            .create();
        let (login, url) = BrowserLogin::begin(
            OidcConfig {
                issuer,
                client_id: "native".into(),
                scopes: vec![],
                audience: Some("api".into()),
            },
            &super::super::oidc::BoundedHttp::new().unwrap(),
        )
        .unwrap();
        (provider, login, reqwest::Url::parse(&url).unwrap())
    }
    #[test]
    fn listener_is_bound_loopback_single_use_and_invalid_requests_cannot_consume_it() {
        let (_provider, login, url) = setup();
        let query: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let callback = format!(
            "{}?code=synthetic&state={}",
            query["redirect_uri"], query["state"]
        );
        assert_eq!(
            client
                .get(callback.replace(&query["state"], "wrong"))
                .send()
                .unwrap()
                .status(),
            400
        );
        assert_eq!(
            client
                .get(&callback)
                .header("Host", "attacker.test")
                .send()
                .unwrap()
                .status(),
            400
        );
        assert_eq!(client.post(&callback).send().unwrap().status(), 400);
        assert_eq!(
            client
                .get(callback.replace("/oauth/callback", "/other"))
                .send()
                .unwrap()
                .status(),
            400
        );
        let response = client.get(&callback).send().unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let text = response.text().unwrap();
        assert!(!text.contains(&query["state"]));
        assert!(!text.contains("synthetic"));
        let (attempt, accepted) = login.take_callback();
        assert_eq!(attempt.validate_callback(&accepted).unwrap(), "synthetic");
        assert_eq!(client.get(&callback).send().unwrap().status(), 410);
    }
    #[test]
    fn an_external_cancel_handle_stops_a_login_owned_by_a_waiting_background_task() {
        let (_provider, login, _url) = setup();
        let cancel = login.cancellation();
        let (sender, receiver) = mpsc::sync_channel(1);
        let task = std::thread::spawn(move || {
            let http = super::super::oidc::BoundedHttp::new().unwrap();
            sender.send(login.finish(&http).is_err()).unwrap();
        });
        cancel.cancel();
        cancel.cancel();
        assert!(receiver.recv_timeout(Duration::from_secs(3)).unwrap());
        task.join().unwrap();
    }
    #[test]
    fn oversized_headers_do_not_consume_the_login_and_cancel_closes_the_listener() {
        let (_provider, mut login, url) = setup();
        let query: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        let callback = format!(
            "{}?code=synthetic&state={}",
            query["redirect_uri"], query["state"]
        );
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let response = client
            .get(&callback)
            .header("X-Large", "a".repeat(20000))
            .send();
        assert!(response.is_err() || response.unwrap().status() != 200);
        assert_eq!(client.get(&callback).send().unwrap().status(), 200);
        login.cancel();
        // Give the cancellation task bounded time; no real keychain or remote provider is used.
        let address = reqwest::Url::parse(&query["redirect_uri"])
            .unwrap()
            .socket_addrs(|| None)
            .unwrap()[0];
        for _ in 0..100 {
            if std::net::TcpStream::connect_timeout(&address, Duration::from_millis(10)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("cancelled listener remained open");
    }
}
