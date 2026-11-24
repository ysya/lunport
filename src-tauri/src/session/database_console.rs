//! A database console's session: one read-only PostgreSQL connection on a Cloud SQL stream, kept while its tab is
//! open. It runs statements one at a time, keeps their rows for paging and export, and cancels the running one on
//! request. It knows nothing of how the stream was dialled: it takes the stream and a way to dial a cancel connection.

// The console's commands, which are the only callers outside the tests, come with the console's window.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::future::{join_all, BoxFuture};
use futures_util::{FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;
use tokio_postgres::error::{ErrorPosition, SqlState};
use tokio_postgres::{CancelToken, Client, Config, NoTls, SimpleQueryMessage};

use super::database_ports::BoxStream;
use super::database_query::valid_sql_within;

/// Whether the session holds Cloud SQL's read-only lock, or only defaults its transactions to read-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum ReadOnlyMode {
    Locked,
    NotLocked,
}

/// A console session that signed in and confirmed it is read-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ConsoleOpened {
    pub read_only: ReadOnlyMode,
    pub iam_user: String,
    pub server_version: String,
}

/// What opening a console answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsoleOpen {
    Opened(ConsoleOpened),
    /// The instance refused Cloud SQL's read-only lock; the person may open the session without it.
    LockUnsupported { message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ConsoleColumn {
    pub name: String,
    pub type_name: String,
}

/// Which limit cut a result short.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum Truncation {
    Rows,
    Bytes,
}

/// What running one statement answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsoleRun {
    /// A statement with columns. `row_count` counts the rows Lunport kept; `first_page` holds the first `PAGE_ROWS`.
    Rows {
        result_id: u32,
        columns: Vec<ConsoleColumn>,
        row_count: u32,
        truncated: Option<Truncation>,
        elapsed_ms: u32,
        first_page: Vec<Vec<Option<String>>>,
    },
    Done { command_tag: String, elapsed_ms: u32 },
    Failed { message: String, sqlstate: Option<String>, position: Option<u32>, elapsed_ms: u32 },
    Canceled { elapsed_ms: u32 },
}

/// What a console session tells its tab without being asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsoleEvent {
    Ended { message: String },
}

pub(crate) const PAGE_ROWS: usize = 200;
pub(crate) const MAX_STATEMENT_BYTES: usize = 256 * 1024;
pub(crate) const MAX_RESULT_ROWS: usize = 10_000;
pub(crate) const MAX_RESULT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_KEPT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_STATEMENT_INBOUND: usize = 96 * 1024 * 1024;
pub(crate) const SIGN_IN_WITHIN: Duration = Duration::from_secs(35);
pub(crate) const CANCEL_WITHIN: Duration = Duration::from_secs(10);

const APPLICATION_NAME: &str = "Lunport Console";
const LOCK_FLAG: &str = "cloudsql_session_read_only";
const BUSY: &str = "A statement is still running. Cancel it or wait for it.";
const ENDED: &str = "The connection ended. Reconnect to go on.";
const ENDED_CLEANLY: &str = "The connection ended.";
const NOT_CONFIRMED: &str = "Lunport could not confirm that this session is read-only, so it closed it.";
const LOCK_UNSUPPORTED: &str = "This instance does not support Cloud SQL's read-only lock.";
const SIGN_IN_TIMED_OUT: &str = "Cloud SQL sign-in timed out.";
const CANCEL_DID_NOT_STOP: &str =
    "The query did not stop after Cancel, so Lunport closed the connection. Reconnect to go on.";
const CANCEL_UNREACHABLE: &str =
    "Lunport could not reach Cloud SQL to cancel the query. It goes on running; close the tab to end the session.";
const RESULT_GONE: &str = "This result is no longer kept. Run the statement again.";
const SCHEMA_TOO_LARGE: &str = "The schema is too large to read.";
/// What a kept value costs beyond its text, so that a result of many NULLs still counts toward the byte limits.
const CELL_OVERHEAD: usize = std::mem::size_of::<Option<String>>();
/// The longest CommandComplete tag Lunport keeps; real tags are a word or two and a count.
const MAX_TAG_BYTES: usize = 64;

fn read_limit_sentence() -> String {
    format!(
        "The answer was larger than {} MiB, so Lunport closed the connection. Add a LIMIT and reconnect.",
        MAX_STATEMENT_INBOUND / (1024 * 1024)
    )
}

/// Dials a new connection to the same instance for a cancel request.
pub(crate) type CancelDial = Arc<dyn Fn() -> BoxFuture<'static, io::Result<BoxStream>> + Send + Sync>;

pub(crate) struct ConsoleLogin {
    pub iam_user: String,
    pub database: String,
    pub read_only: ReadOnlyMode,
}

#[derive(Debug)]
pub(crate) enum OpenError {
    /// The instance does not know Cloud SQL's read-only lock.
    LockUnsupported(String),
    Failed(String),
}

/// The sentence a session ended with. The first one set wins: the driver's own end, the read limit, or a Cancel that did
/// not stop the statement.
struct Ended(watch::Sender<Option<String>>);

impl Ended {
    fn new() -> Self {
        Ended(watch::Sender::new(None))
    }
    fn set(&self, sentence: &str) {
        self.0.send_if_modified(|ended| {
            if ended.is_some() {
                return false;
            }
            *ended = Some(sentence.to_string());
            true
        });
    }
    fn get(&self) -> Option<String> {
        self.0.borrow().clone()
    }
    fn is_set(&self) -> bool {
        self.0.borrow().is_some()
    }
    fn wait(&self) -> BoxFuture<'static, String> {
        let mut ended = self.0.subscribe();
        async move {
            match ended.wait_for(Option::is_some).await {
                Ok(sentence) => sentence.clone().unwrap_or_default(),
                Err(_) => ENDED_CLEANLY.to_string(),
            }
        }
        .boxed()
    }
}

/// Follows the backend's message framing to keep the latest CommandComplete tag, which `tokio-postgres` reduces to a
/// row count.
#[derive(Default)]
struct Frames {
    header: [u8; 5],
    header_len: usize,
    body_left: usize,
    tag: Vec<u8>,
    last_tag: Option<String>,
}

impl Frames {
    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.header_len < self.header.len() {
                let take = (self.header.len() - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + take].copy_from_slice(&bytes[..take]);
                self.header_len += take;
                bytes = &bytes[take..];
                if self.header_len == self.header.len() {
                    let length = u32::from_be_bytes([self.header[1], self.header[2], self.header[3], self.header[4]]);
                    self.body_left = (length as usize).saturating_sub(4);
                    self.tag.clear();
                    if self.body_left == 0 {
                        self.finish();
                    }
                }
                continue;
            }
            let take = self.body_left.min(bytes.len());
            if self.header[0] == b'C' {
                let keep = take.min(MAX_TAG_BYTES.saturating_sub(self.tag.len()));
                self.tag.extend_from_slice(&bytes[..keep]);
            }
            self.body_left -= take;
            bytes = &bytes[take..];
            if self.body_left == 0 {
                self.finish();
            }
        }
    }

    fn finish(&mut self) {
        if self.header[0] == b'C' {
            let tag = self.tag.split(|byte| *byte == 0).next().unwrap_or_default();
            self.last_tag = Some(String::from_utf8_lossy(tag).into_owned());
        }
        self.header_len = 0;
    }
}

/// What the session's read side shares with the session: the bytes one statement may still read, and the framing.
struct Wire {
    limit: usize,
    remaining: AtomicUsize,
    frames: Mutex<Frames>,
    ended: Arc<Ended>,
}

impl Wire {
    /// Gives the next statement the whole read budget and forgets the last tag.
    fn reset(&self) {
        self.remaining.store(self.limit, Ordering::SeqCst);
        self.frames.lock().unwrap().last_tag = None;
    }
    fn last_tag(&self) -> Option<String> {
        self.frames.lock().unwrap().last_tag.clone()
    }
}

/// The session's stream: reads past the statement's budget end the session with the read-limit sentence.
struct StatementBudget {
    inner: BoxStream,
    wire: Arc<Wire>,
}

impl AsyncRead for StatementBudget {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let allowed = self.wire.remaining.load(Ordering::SeqCst);
        // One byte past the budget is enough to know the answer is larger than it.
        let mut scratch = [0u8; 8192];
        let limit = output.remaining().min(scratch.len()).min(allowed.saturating_add(1));
        let mut read = ReadBuf::new(&mut scratch[..limit]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let bytes = read.filled();
                if bytes.len() > allowed {
                    let sentence = read_limit_sentence();
                    self.wire.ended.set(&sentence);
                    return Poll::Ready(Err(io::Error::other(sentence)));
                }
                self.wire.remaining.fetch_sub(bytes.len(), Ordering::SeqCst);
                self.wire.frames.lock().unwrap().feed(bytes);
                output.put_slice(bytes);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for StatementBudget {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The statement on the wire now, as a cancel request sees it.
struct Running {
    /// When the first cancel request for this statement was sent.
    cancel_sent: watch::Sender<Option<Instant>>,
    /// Whether the person's Cancel sent one.
    by_person: AtomicBool,
}

#[derive(Default)]
struct RunState {
    running: Option<Arc<Running>>,
    /// Signals for cancel connections still open; the next statement waits for them to close.
    closing: Vec<oneshot::Receiver<()>>,
}

struct KeptResult {
    columns: Vec<ConsoleColumn>,
    rows: Vec<Vec<Option<String>>>,
}

#[derive(Default)]
struct Results {
    next_id: u32,
    kept: BTreeMap<u32, KeptResult>,
    bytes: usize,
}

struct Inner {
    client: Client,
    cancel_token: CancelToken,
    cancel_dial: CancelDial,
    /// Serializes everything sent on the connection.
    serial: tokio::sync::Mutex<()>,
    /// Whether a person's `run` is under way, waiting or running.
    person_running: AtomicBool,
    state: Mutex<RunState>,
    results: Mutex<Results>,
    wire: Arc<Wire>,
    ended: Arc<Ended>,
    driver: tokio::task::AbortHandle,
}

impl Inner {
    /// Ends the session with `sentence`, unless it already ended with another.
    fn end(&self, sentence: &str) {
        self.ended.set(sentence);
        self.driver.abort();
    }

    /// The sentence for a statement that lost its connection: the read limit when that ended it, otherwise the ended
    /// sentence.
    fn lost(&self) -> String {
        self.end(ENDED);
        let read_limit = read_limit_sentence();
        match self.ended.get() {
            Some(sentence) if sentence == read_limit => read_limit,
            _ => ENDED.to_string(),
        }
    }

    /// Waits for earlier cancel connections to close, so that a late cancel request cannot reach the statement about
    /// to be sent, then marks that statement as running.
    async fn begin(&self) -> Arc<Running> {
        let closing = std::mem::take(&mut self.state.lock().unwrap().closing);
        if !closing.is_empty() {
            let _ = tokio::time::timeout(CANCEL_WITHIN, join_all(closing)).await;
        }
        let running = Arc::new(Running { cancel_sent: watch::Sender::new(None), by_person: AtomicBool::new(false) });
        self.state.lock().unwrap().running = Some(running.clone());
        self.wire.reset();
        running
    }

    /// Registers a cancel for `target` while it is still the running statement.
    fn register_cancel(&self, target: Option<&Arc<Running>>) -> Option<(Arc<Running>, oneshot::Sender<()>)> {
        let mut state = self.state.lock().unwrap();
        let running = state.running.clone()?;
        if target.is_some_and(|target| !Arc::ptr_eq(target, &running)) {
            return None;
        }
        let (closed, closing) = oneshot::channel();
        state.closing.push(closing);
        Some((running, closed))
    }

    fn is_running(&self, target: &Arc<Running>) -> bool {
        self.state.lock().unwrap().running.as_ref().is_some_and(|running| Arc::ptr_eq(running, target))
    }

    /// Dials a cancel connection and sends the cancel request for `target`. It answers once the request was sent; a
    /// task then waits for the server to close the cancel connection and signals `closed`.
    async fn send_cancel(
        self: Arc<Self>,
        target: Arc<Running>,
        closed: oneshot::Sender<()>,
        by_person: bool,
    ) -> Result<(), String> {
        let mut stream = (self.cancel_dial)().await.map_err(|_| CANCEL_UNREACHABLE.to_string())?;
        if !self.is_running(&target) {
            return Ok(());
        }
        // Marked before the request goes out, so the statement's answer never arrives before the mark.
        let was_person = by_person && target.by_person.swap(true, Ordering::SeqCst);
        if self.cancel_token.cancel_query_raw(&mut stream, NoTls).await.is_err() {
            if by_person && !was_person {
                target.by_person.store(false, Ordering::SeqCst);
            }
            return Err(CANCEL_UNREACHABLE.to_string());
        }
        target.cancel_sent.send_if_modified(|sent| {
            if sent.is_some() {
                return false;
            }
            *sent = Some(Instant::now());
            true
        });
        tokio::spawn(async move {
            let mut rest = [0u8; 64];
            let _ = tokio::time::timeout(CANCEL_WITHIN, async {
                while stream.read(&mut rest).await.unwrap_or(0) > 0 {}
            })
            .await;
            let _ = closed.send(());
        });
        Ok(())
    }

    /// Sends `sql` as a simple query and keeps its rows up to `caps`. Past a cap it sends a cancel request and reads the
    /// rest of the answer without keeping it. Err is the sentence of a session that ended.
    async fn stream(
        self: &Arc<Self>,
        sql: &str,
        running: &Arc<Running>,
        bound: &mut (impl std::future::Future<Output = ()> + Unpin),
        caps: Caps,
    ) -> Result<Streamed, String> {
        let mut streamed = Streamed { rows: Vec::new(), bytes: 0, truncated: None, error: None };
        let messages = match self.client.simple_query_raw(sql).await {
            Ok(messages) => messages,
            Err(error) if error.as_db_error().is_some() => {
                streamed.error = Some(error);
                return Ok(streamed);
            }
            Err(_) => return Err(self.lost()),
        };
        tokio::pin!(messages);
        loop {
            let next = tokio::select! {
                next = messages.next() => next,
                () = &mut *bound => {
                    self.end(CANCEL_DID_NOT_STOP);
                    return Err(CANCEL_DID_NOT_STOP.to_string());
                }
            };
            match next {
                None => break,
                Some(Ok(SimpleQueryMessage::Row(row))) => {
                    if streamed.truncated.is_some() {
                        continue;
                    }
                    let values: Vec<Option<String>> = (0..row.len())
                        .map(|index| match row.try_get(index) {
                            Ok(value) => value.map(str::to_string),
                            Err(_) => Some(char::REPLACEMENT_CHARACTER.to_string()),
                        })
                        .collect();
                    let size: usize = values.iter().map(|value| value.as_ref().map_or(0, String::len) + CELL_OVERHEAD).sum();
                    let past = if streamed.rows.len() >= caps.rows {
                        Some(Truncation::Rows)
                    } else if streamed.bytes + size > caps.bytes {
                        Some(Truncation::Bytes)
                    } else {
                        None
                    };
                    if let Some(truncation) = past {
                        streamed.truncated = Some(truncation);
                        if let Some((target, closed)) = self.register_cancel(Some(running)) {
                            tokio::spawn(self.clone().send_cancel(target, closed, false));
                        }
                        continue;
                    }
                    streamed.bytes += size;
                    streamed.rows.push(values);
                }
                Some(Ok(_)) => {}
                Some(Err(error)) if error.as_db_error().is_some() => {
                    streamed.error = Some(error);
                    break;
                }
                Some(Err(_)) => return Err(self.lost()),
            }
        }
        Ok(streamed)
    }
}

struct Caps {
    rows: usize,
    bytes: usize,
}

struct Streamed {
    rows: Vec<Vec<Option<String>>>,
    bytes: usize,
    truncated: Option<Truncation>,
    /// The server error the statement ended with.
    error: Option<tokio_postgres::Error>,
}

/// Resolves `CANCEL_WITHIN` after the first cancel request for the statement was sent; never when none was.
async fn cancel_bound(mut sent: watch::Receiver<Option<Instant>>) {
    let sent_at = sent.wait_for(Option::is_some).await.ok().and_then(|at| *at);
    let Some(at) = sent_at else {
        return std::future::pending().await;
    };
    tokio::time::sleep_until(at + CANCEL_WITHIN).await;
}

/// Clears the person's busy mark when their `run` ends, however it ends.
struct PersonRun<'a>(&'a AtomicBool);

impl Drop for PersonRun<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Clears the running statement when its run ends, before the connection is free for the next one.
struct RunningStatement<'a>(&'a Inner);

impl Drop for RunningStatement<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().running = None;
    }
}

fn elapsed_ms(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
}

fn failed(error: &tokio_postgres::Error, started: Instant) -> ConsoleRun {
    let db = error.as_db_error();
    ConsoleRun::Failed {
        message: db.map_or_else(|| error.to_string(), |db| db.message().to_string()),
        sqlstate: db.map(|db| db.code().code().to_string()),
        position: match db.and_then(|db| db.position()) {
            Some(ErrorPosition::Original(position)) => Some(*position),
            _ => None,
        },
        elapsed_ms: elapsed_ms(started),
    }
}

fn console_config(login: &ConsoleLogin) -> Config {
    let mut config = Config::new();
    config
        .user(&login.iam_user)
        .dbname(&login.database)
        .application_name(APPLICATION_NAME)
        .options(match login.read_only {
            ReadOnlyMode::Locked => "-c cloudsql_session_read_only=locked",
            ReadOnlyMode::NotLocked => "-c default_transaction_read_only=on",
        });
    config
}

fn sign_in_error(error: &tokio_postgres::Error, mode: ReadOnlyMode) -> OpenError {
    match error.as_db_error() {
        Some(db)
            if mode == ReadOnlyMode::Locked
                && *db.code() == SqlState::UNDEFINED_OBJECT
                && db.message().contains(LOCK_FLAG) =>
        {
            OpenError::LockUnsupported(LOCK_UNSUPPORTED.to_string())
        }
        Some(db) => OpenError::Failed(db.message().to_string()),
        None => OpenError::Failed(error.to_string()),
    }
}

/// Reads the setting that makes the session read-only and requires its read-only value.
async fn confirm_read_only(client: &Client, mode: ReadOnlyMode) -> Result<(), OpenError> {
    let (setting, expected) = match mode {
        ReadOnlyMode::Locked => (LOCK_FLAG, "locked"),
        ReadOnlyMode::NotLocked => ("default_transaction_read_only", "on"),
    };
    let not_confirmed = || OpenError::Failed(NOT_CONFIRMED.to_string());
    let messages = client.simple_query(&format!("SHOW {setting}")).await.map_err(|_| not_confirmed())?;
    let values: Vec<Option<String>> = messages
        .iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(row.try_get(0).ok().flatten().map(str::to_string)),
            _ => None,
        })
        .collect();
    if values == [Some(expected.to_string())] {
        Ok(())
    } else {
        Err(not_confirmed())
    }
}

/// A persistent read-only PostgreSQL session on one stream.
pub(crate) struct ConsoleConnection {
    inner: Arc<Inner>,
}

impl Drop for ConsoleConnection {
    fn drop(&mut self) {
        self.inner.end(ENDED_CLEANLY);
    }
}

impl ConsoleConnection {
    /// Signs in on `stream`, checks the read-only setting and answers the connection with a future that resolves with
    /// the sentence the connection ended with.
    pub(crate) async fn open(
        stream: BoxStream,
        login: ConsoleLogin,
        cancel_dial: CancelDial,
    ) -> Result<(ConsoleConnection, ConsoleOpened, BoxFuture<'static, String>), OpenError> {
        Self::open_within(stream, login, cancel_dial, MAX_STATEMENT_INBOUND).await
    }

    /// `open` with a smaller read budget per statement.
    #[cfg(test)]
    pub(crate) async fn open_with_budget(
        stream: BoxStream,
        login: ConsoleLogin,
        cancel_dial: CancelDial,
        inbound: usize,
    ) -> Result<(ConsoleConnection, ConsoleOpened, BoxFuture<'static, String>), OpenError> {
        Self::open_within(stream, login, cancel_dial, inbound).await
    }

    async fn open_within(
        stream: BoxStream,
        login: ConsoleLogin,
        cancel_dial: CancelDial,
        inbound: usize,
    ) -> Result<(ConsoleConnection, ConsoleOpened, BoxFuture<'static, String>), OpenError> {
        let deadline = Instant::now() + SIGN_IN_WITHIN;
        let ended = Arc::new(Ended::new());
        let wire = Arc::new(Wire {
            limit: inbound,
            remaining: AtomicUsize::new(inbound),
            frames: Mutex::new(Frames::default()),
            ended: ended.clone(),
        });
        let budgeted = StatementBudget { inner: stream, wire: wire.clone() };
        let (client, connection) = tokio::time::timeout_at(deadline, console_config(&login).connect_raw(budgeted, NoTls))
            .await
            .map_err(|_| OpenError::Failed(SIGN_IN_TIMED_OUT.to_string()))?
            .map_err(|error| sign_in_error(&error, login.read_only))?;
        let server_version = connection.parameter("server_version").unwrap_or_default().to_string();
        let driver_ended = ended.clone();
        let driver = tokio::spawn(async move {
            let sentence = match connection.await {
                Ok(()) => ENDED_CLEANLY.to_string(),
                Err(error) => error.to_string(),
            };
            driver_ended.set(&sentence);
        })
        .abort_handle();
        let confirmed = tokio::time::timeout_at(deadline, confirm_read_only(&client, login.read_only))
            .await
            .unwrap_or_else(|_| Err(OpenError::Failed(SIGN_IN_TIMED_OUT.to_string())));
        if let Err(error) = confirmed {
            driver.abort();
            return Err(error);
        }
        let opened = ConsoleOpened {
            read_only: login.read_only,
            iam_user: login.iam_user,
            server_version,
        };
        let ended_future = ended.wait();
        let inner = Arc::new(Inner {
            cancel_token: client.cancel_token(),
            client,
            cancel_dial,
            serial: tokio::sync::Mutex::new(()),
            person_running: AtomicBool::new(false),
            state: Mutex::new(RunState::default()),
            results: Mutex::new(Results::default()),
            wire,
            ended,
            driver,
        });
        Ok((ConsoleConnection { inner }, opened, ended_future))
    }

    /// Runs one statement of the person's. `fresh` drops the session's earlier results first.
    pub(crate) async fn run(&self, sql: &str, fresh: bool) -> Result<ConsoleRun, String> {
        let inner = &self.inner;
        if inner.ended.is_set() {
            return Err(ENDED.to_string());
        }
        valid_sql_within(sql, MAX_STATEMENT_BYTES).map_err(|error| error.to_string())?;
        if inner.person_running.swap(true, Ordering::SeqCst) {
            return Err(BUSY.to_string());
        }
        let _person = PersonRun(&inner.person_running);
        let _serial = inner.serial.lock().await;
        if inner.ended.is_set() {
            return Err(ENDED.to_string());
        }
        if fresh {
            let mut results = inner.results.lock().unwrap();
            results.kept.clear();
            results.bytes = 0;
        }
        let running = inner.begin().await;
        let _statement = RunningStatement(inner);
        let started = Instant::now();
        let mut bound = Box::pin(cancel_bound(running.cancel_sent.subscribe()));

        // Preparing first refuses a second statement in the same text and names the result's columns.
        let prepared = tokio::select! {
            prepared = inner.client.prepare(sql) => prepared,
            () = &mut bound => {
                inner.end(CANCEL_DID_NOT_STOP);
                return Err(CANCEL_DID_NOT_STOP.to_string());
            }
        };
        let columns: Vec<ConsoleColumn> = match prepared {
            Ok(statement) => statement
                .columns()
                .iter()
                .map(|column| ConsoleColumn { name: column.name().to_string(), type_name: column.type_().name().to_string() })
                .collect(),
            Err(error) if error.as_db_error().is_some() => return Ok(failed(&error, started)),
            Err(_) => return Err(inner.lost()),
        };

        let room = MAX_RESULT_BYTES.min(MAX_KEPT_BYTES.saturating_sub(inner.results.lock().unwrap().bytes));
        let streamed = inner.stream(sql, &running, &mut bound, Caps { rows: MAX_RESULT_ROWS, bytes: room }).await?;
        if let Some(error) = &streamed.error {
            let canceled = error.code() == Some(&SqlState::QUERY_CANCELED) && running.by_person.load(Ordering::SeqCst);
            if streamed.truncated.is_none() {
                return Ok(if canceled {
                    ConsoleRun::Canceled { elapsed_ms: elapsed_ms(started) }
                } else {
                    failed(error, started)
                });
            }
        }
        if columns.is_empty() {
            return Ok(ConsoleRun::Done {
                command_tag: inner.wire.last_tag().unwrap_or_default(),
                elapsed_ms: elapsed_ms(started),
            });
        }
        let first_page = streamed.rows.iter().take(PAGE_ROWS).cloned().collect();
        let row_count = u32::try_from(streamed.rows.len()).unwrap_or(u32::MAX);
        let mut results = inner.results.lock().unwrap();
        let result_id = results.next_id;
        results.next_id = results.next_id.wrapping_add(1);
        results.bytes += streamed.bytes;
        results.kept.insert(result_id, KeptResult { columns: columns.clone(), rows: streamed.rows });
        Ok(ConsoleRun::Rows {
            result_id,
            columns,
            row_count,
            truncated: streamed.truncated,
            elapsed_ms: elapsed_ms(started),
            first_page,
        })
    }

    /// The `PAGE_ROWS` rows of `result_id` from `offset` on.
    pub(crate) fn page(&self, result_id: u32, offset: u32) -> Result<Vec<Vec<Option<String>>>, String> {
        let results = self.inner.results.lock().unwrap();
        let kept = results.kept.get(&result_id).ok_or_else(|| RESULT_GONE.to_string())?;
        Ok(kept.rows.iter().skip(offset as usize).take(PAGE_ROWS).cloned().collect())
    }

    /// Sends the cancel request for the statement running now and answers once it was sent; Ok and nothing sent when
    /// none runs. Err is the sentence of a cancel that could not be dialled; the statement and the session go on.
    pub(crate) async fn cancel(&self) -> Result<(), String> {
        let Some((target, closed)) = self.inner.register_cancel(None) else {
            return Ok(());
        };
        self.inner.clone().send_cancel(target, closed, true).await
    }

    /// The kept rows of `result_id`, for export and schema reading.
    pub(crate) fn kept(&self, result_id: u32) -> Result<(Vec<ConsoleColumn>, Vec<Vec<Option<String>>>), String> {
        let results = self.inner.results.lock().unwrap();
        let kept = results.kept.get(&result_id).ok_or_else(|| RESULT_GONE.to_string())?;
        Ok((kept.columns.clone(), kept.rows.clone()))
    }

    /// Runs `sql` and keeps no result: for internal catalog reads. No row limit; past `MAX_KEPT_BYTES` it answers
    /// Err("The schema is too large to read.").
    pub(crate) async fn read_rows(&self, sql: &str) -> Result<Vec<Vec<Option<String>>>, String> {
        let inner = &self.inner;
        if inner.ended.is_set() {
            return Err(ENDED.to_string());
        }
        let _serial = inner.serial.lock().await;
        if inner.ended.is_set() {
            return Err(ENDED.to_string());
        }
        let running = inner.begin().await;
        let _statement = RunningStatement(inner);
        let mut bound = Box::pin(cancel_bound(running.cancel_sent.subscribe()));
        let streamed = inner.stream(sql, &running, &mut bound, Caps { rows: usize::MAX, bytes: MAX_KEPT_BYTES }).await?;
        if streamed.truncated.is_some() {
            return Err(SCHEMA_TOO_LARGE.to_string());
        }
        if let Some(error) = streamed.error {
            return Err(error.as_db_error().map_or_else(|| error.to_string(), |db| db.message().to_string()));
        }
        Ok(streamed.rows)
    }
}

#[cfg(test)]
#[path = "database_console_tests.rs"]
mod tests;
