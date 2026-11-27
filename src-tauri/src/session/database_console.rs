//! A database console's session: one read-only PostgreSQL connection on a Cloud SQL stream, kept while its tab is
//! open. It runs statements one at a time, keeps their rows for paging and export, and cancels the running one on
//! request. `ConsoleConnection` knows nothing of how the stream was dialled: it takes the stream and a way to dial a
//! cancel connection. The app's sessions (`Consoles`) and their commands, at the end, dial it through a Cloud SQL
//! upstream of each tab's own.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::future::{join_all, BoxFuture};
use futures_util::{FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::{ErrorPosition, SqlState};
use tauri::Manager;
use tokio_postgres::{CancelToken as QueryCancelToken, Client, Config, NoTls, SimpleQueryMessage};
use zeroize::Zeroizing;

use super::connect::CancelToken;
use super::database_console_schema::{csv, json, read_schema, write_replacing, ExportFormat, SchemaTree};
use super::database_ports::{unreachable, BoxStream, Dialling, NotReady, Prepared, Upstream};
use super::database_query::valid_sql_within;
use super::database_upstream::CloudSqlUpstream;
use super::databases::started_broker;
use super::{postgres_transport, standard_postgres_profiles};
use super::tunnels::{main_only, snapshot};
use crate::state::AppState;
use crate::sync::databases::SavedDatabase;

/// How the console keeps a session read-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum ReadOnlyMode {
    Locked,
    NotLocked,
    Standard,
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
const CONNECTION_LOST: &str = "The connection to Cloud SQL was lost.";
const NOT_CONFIRMED: &str = "Lunport could not confirm that this session is read-only, so it closed it.";
const LOCK_UNSUPPORTED: &str = "This instance does not support Cloud SQL's read-only lock.";
const SIGN_IN_TIMED_OUT: &str = "Cloud SQL sign-in timed out.";
const CANCEL_DID_NOT_STOP: &str =
    "The query did not stop after Cancel, so Lunport closed the connection. Reconnect to go on.";
const CANCEL_UNREACHABLE: &str =
    "Lunport could not reach Cloud SQL to cancel the query. It goes on running; close the tab to end the session.";
const RESULT_GONE: &str = "This result is no longer kept. Run the statement again.";
const SCHEMA_TOO_LARGE: &str = "The schema is too large to read.";
const NO_COPY: &str = "The console cannot run COPY with STDIN or STDOUT. Use the local port and psql for that.";
/// What a kept value costs beyond its text, so that a result of many NULLs still counts toward the byte limits.
const CELL_OVERHEAD: usize = std::mem::size_of::<Option<String>>();
/// The longest CommandComplete tag Lunport keeps; real tags are a word or two and a count.
const MAX_TAG_BYTES: usize = 64;

/// The sentence a connection error ends a session with: the server's own message when the server ended it.
fn ended_sentence(error: &tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("The connection ended: {}.", db.message().trim_end_matches('.')),
        None if error.is_closed() => ENDED_CLEANLY.to_string(),
        None => CONNECTION_LOST.to_string(),
    }
}

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
    /// Whether the statement is the person's; Cancel never reaches Lunport's own catalog reads.
    person: bool,
    /// When the first cancel request for this statement was sent.
    cancel_sent: watch::Sender<Option<Instant>>,
    /// Whether the person's Cancel sent one.
    by_person: AtomicBool,
}

#[derive(Default)]
struct RunState {
    /// The person's run under way, waiting or running: whether they asked to cancel it.
    person: Option<Arc<AtomicBool>>,
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
    cancel_token: QueryCancelToken,
    cancel_dial: CancelDial,
    /// Serializes everything sent on the connection.
    serial: tokio::sync::Mutex<()>,
    state: Mutex<RunState>,
    results: Mutex<Results>,
    wire: Arc<Wire>,
    ended: Arc<Ended>,
    driver: tokio::task::AbortHandle,
    read_only: ReadOnlyMode,
}

impl Inner {
    /// Drops every kept result, as a statement that starts a run does.
    fn drop_results(&self) {
        let mut results = self.results.lock().unwrap();
        results.kept.clear();
        results.bytes = 0;
    }

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
    /// to be sent, then marks that statement as running. `person` is the person's cancel mark for their run; None
    /// answers a run the person canceled while it waited, which then sends nothing.
    async fn begin(&self, person: Option<&AtomicBool>) -> Option<Arc<Running>> {
        let closing = std::mem::take(&mut self.state.lock().unwrap().closing);
        if !closing.is_empty() {
            let _ = tokio::time::timeout(CANCEL_WITHIN, join_all(closing)).await;
        }
        let mut state = self.state.lock().unwrap();
        if person.is_some_and(|canceled| canceled.load(Ordering::SeqCst)) {
            return None;
        }
        let running = Arc::new(Running {
            person: person.is_some(),
            cancel_sent: watch::Sender::new(None),
            by_person: AtomicBool::new(false),
        });
        state.running = Some(running.clone());
        self.wire.reset();
        Some(running)
    }

    /// Registers a cancel for `target` while it is still the running statement.
    fn register_cancel(&self, target: &Arc<Running>) -> Option<oneshot::Sender<()>> {
        let mut state = self.state.lock().unwrap();
        if !state.running.as_ref().is_some_and(|running| Arc::ptr_eq(running, target)) {
            return None;
        }
        let (closed, closing) = oneshot::channel();
        state.closing.push(closing);
        Some(closed)
    }

    /// Marks the person's run as canceled and, when its statement is on the wire, registers a cancel for it. None when
    /// there is nothing to send: no run of the person's, or one still waiting, which `begin` then stops.
    fn register_person_cancel(&self) -> Option<(Arc<Running>, oneshot::Sender<()>)> {
        let mut state = self.state.lock().unwrap();
        state.person.as_ref()?.store(true, Ordering::SeqCst);
        let running = state.running.clone().filter(|running| running.person)?;
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
        let mut stream = match (self.cancel_dial)().await {
            Ok(stream) => stream,
            Err(_) => return self.cancel_delivery_failed(&target),
        };
        if !self.is_running(&target) {
            return Ok(());
        }
        // Marked before the request goes out, so the statement's answer never arrives before the mark.
        let was_person = by_person && target.by_person.swap(true, Ordering::SeqCst);
        // A cancel connection that takes the request and never lets it out does not hold Cancel either.
        let sent = tokio::time::timeout(CANCEL_WITHIN, self.cancel_token.cancel_query_raw(&mut stream, NoTls)).await;
        if !matches!(sent, Ok(Ok(()))) {
            if by_person && !was_person {
                target.by_person.store(false, Ordering::SeqCst);
            }
            return self.cancel_delivery_failed(&target);
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

    fn cancel_delivery_failed(&self, target: &Arc<Running>) -> Result<(), String> {
        if self.read_only != ReadOnlyMode::Standard {
            return Err(CANCEL_UNREACHABLE.to_string());
        }
        if !self.is_running(target) {
            return Ok(());
        }
        let message = "Lunport could not send the PostgreSQL cancellation, so it closed the session.";
        self.end(message);
        Err(message.to_string())
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
                        if let Some(closed) = self.register_cancel(running) {
                            tokio::spawn(self.clone().send_cancel(running.clone(), closed, false));
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

/// Clears the person's run when it ends, however it ends.
struct PersonRun<'a>(&'a Inner);

impl Drop for PersonRun<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().person = None;
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

/// A server error that ended the person's statement: Canceled when it is the cancel the person sent.
fn server_error(error: &tokio_postgres::Error, running: &Running, started: Instant) -> ConsoleRun {
    if error.code() == Some(&SqlState::QUERY_CANCELED) && running.by_person.load(Ordering::SeqCst) {
        ConsoleRun::Canceled { elapsed_ms: elapsed_ms(started) }
    } else {
        failed(error, started)
    }
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
            ReadOnlyMode::NotLocked | ReadOnlyMode::Standard => "-c default_transaction_read_only=on",
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
        None => OpenError::Failed(ended_sentence(error)),
    }
}

/// Reads the setting that makes the session read-only and requires its read-only value.
async fn confirm_read_only(client: &Client, mode: ReadOnlyMode) -> Result<(), OpenError> {
    let (setting, expected) = match mode {
        ReadOnlyMode::Locked => (LOCK_FLAG, "locked"),
        ReadOnlyMode::NotLocked | ReadOnlyMode::Standard => ("default_transaction_read_only", "on"),
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

/// What `copies_through_the_client` sees of a statement outside parentheses.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    /// A bare word, in upper case: a keyword or an unquoted name.
    Word(String),
    Dot,
    /// Anything else: a literal, a quoted name, an operator, an opening parenthesis.
    Other,
}

/// Whether a byte goes on a bare word: a letter, a digit, `_`, `$` or any byte of a character past ASCII.
fn word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

/// The end of a quoted run that starts after its opening `quote` at `from`: a doubled quote stays inside, and with `backslashes` a
/// backslash takes the byte after it along.
fn quoted_end(bytes: &[u8], from: usize, quote: u8, backslashes: bool) -> usize {
    let mut at = from;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' if backslashes => at += 2,
            byte if byte == quote => {
                if bytes.get(at + 1) == Some(&quote) {
                    at += 2;
                } else {
                    return at + 1;
                }
            }
            _ => at += 1,
        }
    }
    bytes.len()
}

/// The tokens of `sql` outside parentheses, past its comments, string literals (with `''`, `E'…'` and `$tag$…$tag$`) and quoted names.
fn top_level_tokens(sql: &str) -> Vec<Token> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut depth = 0usize;
    let mut at = 0;
    let mut push = |depth: usize, token: Token| {
        if depth == 0 {
            tokens.push(token);
        }
    };
    while at < bytes.len() {
        let rest = &bytes[at..];
        match rest[0] {
            byte if byte.is_ascii_whitespace() => at += 1,
            b'-' if rest.starts_with(b"--") => {
                at += rest.iter().position(|byte| *byte == b'\n').unwrap_or(rest.len());
            }
            b'/' if rest.starts_with(b"/*") => {
                let mut nested = 0usize;
                while at < bytes.len() {
                    if bytes[at..].starts_with(b"/*") {
                        nested += 1;
                        at += 2;
                    } else if bytes[at..].starts_with(b"*/") {
                        nested -= 1;
                        at += 2;
                        if nested == 0 {
                            break;
                        }
                    } else {
                        at += 1;
                    }
                }
            }
            b'\'' => {
                at = quoted_end(bytes, at + 1, b'\'', false);
                push(depth, Token::Other);
            }
            b'"' => {
                at = quoted_end(bytes, at + 1, b'"', false);
                push(depth, Token::Other);
            }
            b'$' => {
                // `$tag$` opens a dollar-quoted literal that the same `$tag$` closes; `$1` is a parameter.
                let len = rest[1..].iter().take_while(|byte| word_byte(**byte) && **byte != b'$').count();
                let opens = rest.get(1 + len) == Some(&b'$') && (len == 0 || !rest[1].is_ascii_digit());
                if opens {
                    let tag = &rest[..len + 2];
                    let body = at + tag.len();
                    at = bytes[body..].windows(tag.len()).position(|window| window == tag).map_or(bytes.len(), |end| body + end + tag.len());
                } else {
                    at += 1 + rest[1..].iter().take_while(|byte| byte.is_ascii_digit()).count();
                }
                push(depth, Token::Other);
            }
            b'(' => {
                push(depth, Token::Other);
                depth += 1;
                at += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                at += 1;
            }
            b'.' => {
                push(depth, Token::Dot);
                at += 1;
            }
            byte if word_byte(byte) => {
                let len = rest.iter().take_while(|byte| word_byte(**byte)).count();
                let word = &rest[..len];
                at += len;
                if word.eq_ignore_ascii_case(b"e") && bytes.get(at) == Some(&b'\'') {
                    at = quoted_end(bytes, at + 1, b'\'', true);
                    push(depth, Token::Other);
                } else {
                    push(depth, Token::Word(String::from_utf8_lossy(word).to_ascii_uppercase()));
                }
            }
            _ => {
                push(depth, Token::Other);
                at += 1;
            }
        }
    }
    tokens
}

/// Whether `sql`, one statement, is a COPY whose rows go through the client: its first `TO` or `FROM` outside parentheses names
/// `STDOUT` or `STDIN` (PostgreSQL takes either word for the client, both ways). The console's simple queries cannot carry such a copy, so
/// it never sends one. A COPY to or from a file, and a statement that only mentions COPY in a literal or a comment, are not such a copy.
fn copies_through_the_client(sql: &str) -> bool {
    let tokens = top_level_tokens(sql);
    if tokens.first() != Some(&Token::Word("COPY".into())) {
        return false;
    }
    // A keyword after a dot is a name: `public.from`.
    let direction = (1..tokens.len()).find(|&index| {
        matches!(&tokens[index], Token::Word(word) if word == "TO" || word == "FROM") && tokens[index - 1] != Token::Dot
    });
    direction.is_some_and(|index| matches!(tokens.get(index + 1), Some(Token::Word(word)) if word == "STDOUT" || word == "STDIN"))
}

struct AbortOnDrop(Option<tokio::task::AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(driver) = self.0.take() {
            driver.abort();
        }
    }
}

const STANDARD_QUERY_FORMS: &str = "Run one read query (SELECT, WITH, VALUES, or TABLE).";
const ROLLBACK_FAILED: &str = "Lunport could not finish the read-only transaction, so it closed the session.";

fn standard_query_form(sql: &str) -> bool {
    let tokens = top_level_tokens(sql);
    matches!(tokens.first(), Some(Token::Word(word)) if matches!(word.as_str(), "SELECT" | "WITH" | "VALUES" | "TABLE"))
        && !tokens.iter().any(|token| matches!(token, Token::Word(word) if word == "INTO"))
}

/// The console owns this transaction, including when the IPC task is dropped while it is open.
struct ReadTransaction<'a> {
    inner: &'a Inner,
    finished: bool,
}

impl ReadTransaction<'_> {
    async fn rollback(mut self) -> Result<(), String> {
        let inner = self.inner;
        if inner.ended.is_set() {
            return Err(ENDED.to_string());
        }
        // Stop new cancels from targeting the transaction cleanup and wait for ones already sent.
        let closing = {
            let mut state = inner.state.lock().unwrap();
            state.running = None;
            std::mem::take(&mut state.closing)
        };
        tokio::time::timeout(CANCEL_WITHIN, async {
            join_all(closing).await;
            inner.wire.reset();
            inner.client.batch_execute("ROLLBACK").await
        })
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| ROLLBACK_FAILED.to_string())?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for ReadTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.inner.end(ROLLBACK_FAILED);
        }
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
    /// Ends the session now, although a command still holds it: a statement on the wire loses its connection and answers the ended
    /// sentence, as it does when the connection drops. Its future is neither dropped nor raced.
    pub(crate) fn close(&self) {
        self.inner.end(ENDED_CLEANLY);
    }

    /// The cancel token of the session while one of the person's statements is on the wire; None otherwise, and for Lunport's own
    /// catalog reads.
    fn running_person_statement(&self) -> Option<QueryCancelToken> {
        let state = self.inner.state.lock().unwrap();
        state.running.as_ref().filter(|running| running.person).map(|_| self.inner.cancel_token.clone())
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
        Self::open_within(stream, login, cancel_dial, MAX_STATEMENT_INBOUND, None).await
    }

    /// `open` with a smaller read budget per statement.
    #[cfg(test)]
    pub(crate) async fn open_with_budget(
        stream: BoxStream,
        login: ConsoleLogin,
        cancel_dial: CancelDial,
        inbound: usize,
    ) -> Result<(ConsoleConnection, ConsoleOpened, BoxFuture<'static, String>), OpenError> {
        Self::open_within(stream, login, cancel_dial, inbound, None).await
    }

    async fn open_within(
        stream: BoxStream,
        login: ConsoleLogin,
        cancel_dial: CancelDial,
        inbound: usize,
        password: Option<String>,
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
        let mut config = console_config(&login);
        if login.read_only == ReadOnlyMode::Standard {
            // The standard transport has already negotiated and verified TLS.
            config.ssl_mode(SslMode::Disable);
            if let Some(password) = password {
                let password = Zeroizing::new(password);
                config.password(password.as_bytes());
            }
        }
        let (client, connection) = tokio::time::timeout_at(deadline, config.connect_raw(budgeted, NoTls))
            .await
            .map_err(|_| OpenError::Failed(SIGN_IN_TIMED_OUT.to_string()))?
            .map_err(|error| {
                if login.read_only == ReadOnlyMode::Standard {
                    OpenError::Failed("PostgreSQL sign-in failed. Check the database, user, and password.".to_string())
                } else {
                    sign_in_error(&error, login.read_only)
                }
            })?;
        let server_version = connection.parameter("server_version").unwrap_or_default().to_string();
        let driver_ended = ended.clone();
        let mut driver = AbortOnDrop(Some(tokio::spawn(async move {
            let sentence = match connection.await {
                Ok(()) => ENDED_CLEANLY.to_string(),
                Err(error) => ended_sentence(&error),
            };
            driver_ended.set(&sentence);
        })
        .abort_handle()));
        let confirmed = tokio::time::timeout_at(deadline, confirm_read_only(&client, login.read_only))
            .await
            .unwrap_or_else(|_| Err(OpenError::Failed(SIGN_IN_TIMED_OUT.to_string())));
        confirmed?;
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
            state: Mutex::new(RunState::default()),
            results: Mutex::new(Results::default()),
            wire,
            ended,
            driver: driver.0.take().expect("the new console has a driver"),
            read_only: login.read_only,
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
        let canceled = {
            let mut state = inner.state.lock().unwrap();
            if state.person.is_some() {
                return Err(BUSY.to_string());
            }
            let canceled = Arc::new(AtomicBool::new(false));
            state.person = Some(canceled.clone());
            canceled
        };
        let _person = PersonRun(inner);
        let _serial = inner.serial.lock().await;
        if inner.ended.is_set() {
            return Err(ENDED.to_string());
        }
        let standard = inner.read_only == ReadOnlyMode::Standard;
        let refused = if standard && !standard_query_form(sql) {
            Some(STANDARD_QUERY_FORMS)
        } else if !standard && copies_through_the_client(sql) {
            Some(NO_COPY)
        } else {
            None
        };
        if let Some(message) = refused {
            if fresh {
                inner.drop_results();
            }
            return Ok(ConsoleRun::Failed { message: message.to_string(), sqlstate: None, position: None, elapsed_ms: 0 });
        }
        let Some(running) = inner.begin(Some(&canceled)).await else {
            return Ok(ConsoleRun::Canceled { elapsed_ms: 0 });
        };
        let _statement = RunningStatement(inner);
        if fresh {
            inner.drop_results();
        }
        let started = Instant::now();
        let mut bound = Box::pin(cancel_bound(running.cancel_sent.subscribe()));

        if standard {
            let transaction = ReadTransaction { inner, finished: false };
            let result = tokio::select! {
                begin = inner.client.batch_execute("BEGIN READ ONLY") => match begin {
                    Ok(()) => {
                        if canceled.load(Ordering::SeqCst) {
                            Ok(ConsoleRun::Canceled { elapsed_ms: elapsed_ms(started) })
                        } else {
                            self.run_query(sql, &running, started, &mut bound).await
                        }
                    }
                    Err(error) if error.as_db_error().is_some() => Ok(server_error(&error, &running, started)),
                    Err(_) => Err(inner.lost()),
                },
                () = &mut bound => {
                    inner.end(CANCEL_DID_NOT_STOP);
                    Err(CANCEL_DID_NOT_STOP.to_string())
                }
            };
            if !inner.ended.is_set() {
                transaction.rollback().await?;
            }
            return result;
        }
        self.run_query(sql, &running, started, &mut bound).await
    }

    async fn run_query(
        &self,
        sql: &str,
        running: &Arc<Running>,
        started: Instant,
        bound: &mut (impl std::future::Future<Output = ()> + Unpin),
    ) -> Result<ConsoleRun, String> {
        let inner = &self.inner;
        // Preparing first refuses a second statement in the same text and names the result's columns.
        let prepared = tokio::select! {
            prepared = inner.client.prepare(sql) => prepared,
            () = &mut *bound => {
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
            Err(error) if error.as_db_error().is_some() => return Ok(server_error(&error, running, started)),
            Err(_) => return Err(inner.lost()),
        };

        if inner.read_only == ReadOnlyMode::Standard {
            if columns.is_empty() {
                return Ok(ConsoleRun::Failed { message: STANDARD_QUERY_FORMS.to_string(), sqlstate: None, position: None, elapsed_ms: elapsed_ms(started) });
            }
            if inner.state.lock().unwrap().person.as_ref().is_some_and(|canceled| canceled.load(Ordering::SeqCst)) {
                return Ok(ConsoleRun::Canceled { elapsed_ms: elapsed_ms(started) });
            }
        }
        let room = MAX_RESULT_BYTES.min(MAX_KEPT_BYTES.saturating_sub(inner.results.lock().unwrap().bytes));
        let streamed = inner.stream(sql, running, bound, Caps { rows: MAX_RESULT_ROWS, bytes: room }).await?;
        if let Some(error) = &streamed.error {
            if streamed.truncated.is_none() {
                return Ok(server_error(error, running, started));
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

    /// Cancels the person's run. When its statement is on the wire it sends the cancel request and answers once it was
    /// sent; a run still waiting for the connection answers Canceled without sending its statement. Ok and nothing sent
    /// when no run of the person's is under way; Lunport's own catalog reads are never canceled. Err is the sentence of
    /// a cancel that could not be dialled; the statement and the session go on.
    pub(crate) async fn cancel(&self) -> Result<(), String> {
        let Some((target, closed)) = self.inner.register_person_cancel() else {
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

    /// Writes the kept rows of `result_id` to `path` as CSV or JSON: the rows Lunport kept, not a re-run of the query.
    pub(crate) fn export(&self, result_id: u32, format: ExportFormat, path: &std::path::Path) -> Result<(), String> {
        let (columns, rows) = self.kept(result_id)?;
        let content = match format {
            ExportFormat::Csv => csv(&columns, &rows),
            ExportFormat::Json => json(&columns, &rows),
        };
        write_replacing(path, &content)
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
        let running = inner.begin(None).await.expect("only the person's runs are canceled before they start");
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

// ---- The app's console sessions ----

/// How many console sessions the app keeps open or opening at once, one for each tab.
pub(crate) const MAX_CONSOLE_SESSIONS: usize = 8;
const CONSOLE_CLOSED: &str = "This console is closed. Open it again from Databases.";
const TOO_MANY_CONSOLES: &str = "Close a tab before opening another (maximum 8).";
const DATABASE_GONE: &str = "This database is no longer in the library.";
/// What an open answers when its tab closed while it was under way.
const OPEN_CANCELLED: &str = "The console was closed while it opened.";
/// How often an open under way looks whether its tab closed.
const CLOSED_POLL: Duration = Duration::from_millis(50);

/// One open of a tab's session: the workspace's generation it began in, and a number of its own, so that two opens of one tab never
/// share one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ticket {
    generation: u64,
    serial: u64,
}

/// Ends the session a slot that left the registry held, outside the registry's lock: its connection closes and its route is released (now,
/// or once the cancel request for a statement still running went out), although a command still running on it holds it.
fn end_removed(session: Option<Arc<ConsoleSession>>) {
    if let Some(session) = session {
        session.end();
    }
}

/// A tab's place among the app's sessions.
enum Slot {
    /// An open is under way: closing the tab cancels it.
    Opening { ticket: Ticket, cancel: CancelToken },
    Open(Arc<ConsoleSession>),
}

/// The app's console sessions, by the id of the tab the frontend made. A session dropped here closes its connection, and its route
/// through `ConsoleSession`'s drop; nothing here blocks, so the main thread may close them all.
#[derive(Default)]
pub(crate) struct Consoles {
    entries: Mutex<HashMap<String, Slot>>,
    /// Bumped by `close_all`, as a reloaded workspace does: an open that began before it is never installed.
    generation: AtomicU64,
    serial: AtomicU64,
}

impl Slot {
    /// Ends the slot: an open under way is cancelled, and an open session is handed back to be ended outside the registry's lock.
    fn end(self) -> Option<Arc<ConsoleSession>> {
        match self {
            Slot::Opening { cancel, .. } => {
                cancel.cancel();
                None
            }
            Slot::Open(session) => Some(session),
        }
    }
}

impl Consoles {
    /// Registers an opening session. Its ticket is unique per begin (the generation together with a serial), so a second open of the same
    /// id (Reconnect, React StrictMode) gets a ticket of its own, and only that ticket's `finish` is installed. The second open replaces
    /// the first: an open under way is cancelled, and an open session is dropped.
    pub(crate) fn begin(&self, id: &str) -> Result<(Ticket, CancelToken), String> {
        let mut entries = self.entries.lock().unwrap();
        if !entries.contains_key(id) && entries.len() >= MAX_CONSOLE_SESSIONS {
            return Err(TOO_MANY_CONSOLES.to_string());
        }
        let ticket = Ticket { generation: self.generation.load(Ordering::SeqCst), serial: self.serial.fetch_add(1, Ordering::SeqCst) };
        let cancel = CancelToken::default();
        let before = entries.insert(id.to_string(), Slot::Opening { ticket, cancel: cancel.clone() });
        drop(entries);
        end_removed(before.and_then(Slot::end));
        Ok((ticket, cancel))
    }

    /// Installs `session` as the tab's when `ticket` is still its open. False, and the session is dropped, after close, close_all or a
    /// newer begin.
    pub(crate) fn finish(&self, id: &str, ticket: Ticket, session: Arc<ConsoleSession>) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let current = ticket.generation == self.generation.load(Ordering::SeqCst)
            && matches!(entries.get(id), Some(Slot::Opening { ticket: opening, .. }) if *opening == ticket);
        if !current {
            drop(entries);
            session.end();
            return false;
        }
        entries.insert(id.to_string(), Slot::Open(session));
        true
    }

    /// Takes the tab's place back from an open that ended without a session, unless a newer open has it.
    pub(crate) fn abandon(&self, id: &str, ticket: Ticket) {
        let mut entries = self.entries.lock().unwrap();
        if matches!(entries.get(id), Some(Slot::Opening { ticket: opening, .. }) if *opening == ticket) {
            entries.remove(id);
        }
    }

    pub(crate) fn get(&self, id: &str) -> Result<Arc<ConsoleSession>, String> {
        match self.entries.lock().unwrap().get(id) {
            Some(Slot::Open(session)) => Ok(session.clone()),
            _ => Err(CONSOLE_CLOSED.to_string()),
        }
    }

    /// Cancels an opening session, or drops an open one.
    pub(crate) fn close(&self, id: &str) {
        let removed = self.entries.lock().unwrap().remove(id);
        end_removed(removed.and_then(Slot::end));
    }

    /// Ends every session, as `embedded::Terminals::close_all` does for the terminals: the generation is bumped, so that no open under way
    /// is installed after it.
    pub(crate) fn close_all(&self) {
        let removed: Vec<Slot> = {
            let mut entries = self.entries.lock().unwrap();
            self.generation.fetch_add(1, Ordering::SeqCst);
            entries.drain().map(|(_, slot)| slot).collect()
        };
        for slot in removed {
            end_removed(slot.end());
        }
    }
}

/// Takes a tab's place back when its open ends without installing a session.
struct OpeningGuard<'a> {
    consoles: &'a Consoles,
    id: &'a str,
    ticket: Ticket,
}

impl Drop for OpeningGuard<'_> {
    fn drop(&mut self) {
        self.consoles.abandon(self.id, self.ticket);
    }
}

/// A tab's open session, and the upstream it was dialled through, which is the tab's own.
pub(crate) struct ConsoleSession {
    pub connection: ConsoleConnection,
    cloud_route: Option<(Arc<dyn Upstream>, String)>,
    /// Whether the route was released: by `end`, or by the drop.
    released: AtomicBool,
}

impl ConsoleSession {
    pub(crate) fn new(connection: ConsoleConnection, upstream: Arc<dyn Upstream>, db_id: String) -> ConsoleSession {
        ConsoleSession { connection, cloud_route: Some((upstream, db_id)), released: AtomicBool::new(false) }
    }

    fn standard(connection: ConsoleConnection) -> ConsoleSession {
        ConsoleSession { connection, cloud_route: None, released: AtomicBool::new(false) }
    }

    /// Ends the session as its tab closes: a statement of the person's still running is canceled, the connection closes and the route is
    /// released, while a command may still hold the session: now, or once the cancel request went out. Nothing here blocks or waits.
    fn end(&self) {
        let releasing = self.cancel_running();
        self.connection.close();
        if !releasing {
            self.release();
        }
    }

    /// Sends a cancel request for the person's running statement, so that the server stops it rather than running it until it next
    /// writes. It is dialled only with the material the database's connections keep: a refresh would build a route again inside the
    /// upstream being released. The request goes out on a task of its own, bounded by `CANCEL_WITHIN`, and a failure is dropped, since the
    /// tab is gone. A host route's stream is dialled only once that task polls it, through the path the release closes, so the task releases
    /// the route itself once the request went out, failed or ran out of time. True when that task took the release over; the session counts
    /// as released from now on, so neither a later release nor the drop releases it again.
    fn cancel_running(&self) -> bool {
        let Some(token) = self.connection.running_person_statement() else {
            return false;
        };
        let (stream, release) = match &self.cloud_route {
            Some((upstream, db_id)) => {
                let Dialling { material, stream } = upstream.connect(db_id, None);
                if material.is_none() {
                    return false;
                }
                (stream, Some((upstream.clone(), db_id.clone())))
            }
            None => ((self.connection.inner.cancel_dial)(), None),
        };
        if self.released.swap(true, Ordering::SeqCst) {
            // Released already: the path the stream would go through is closed.
            return true;
        }
        tauri::async_runtime::spawn(async move {
            let _ = tokio::time::timeout(CANCEL_WITHIN, async move {
                let mut stream = stream.await?;
                token.cancel_query_raw(&mut stream, NoTls).await.map_err(io::Error::other)
            })
            .await;
            if let Some((upstream, db_id)) = release {
                upstream.release(&db_id);
            }
        });
        true
    }

    /// Releases the session's route once. For a host route that drops the `HostPath`, which closes its forward and SSH session on a
    /// thread of its own.
    fn release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            if let Some((upstream, db_id)) = &self.cloud_route {
                upstream.release(db_id);
            }
        }
    }
}

impl Drop for ConsoleSession {
    fn drop(&mut self) {
        self.release();
    }
}

/// Cancels its token when it goes, however the future that holds it ends.
struct CancelOnDrop(CancelToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// The cancel dial of an app's console: `connect` dials with the material the database's connections have now. When none is kept (a
/// certificate past its use, or one a grant's end took along), `refresh` gets new material on a blocking thread, asking nobody, and the
/// dial is made again. All of it is bounded by `within`: past it the refresh is cancelled and the dial fails, which Cancel says it could
/// not reach Cloud SQL.
pub(crate) fn dial_for_cancel(
    connect: Arc<dyn Fn() -> Dialling + Send + Sync>,
    refresh: Arc<dyn Fn(&CancelToken) -> Result<(), NotReady> + Send + Sync>,
    within: Duration,
) -> CancelDial {
    Arc::new(move || {
        let (connect, refresh) = (connect.clone(), refresh.clone());
        async move {
            let cancel = CancelToken::default();
            let _cancel_on_exit = CancelOnDrop(cancel.clone());
            let dial = async {
                let first = connect();
                if first.material.is_some() {
                    return first.stream.await;
                }
                drop(first);
                tokio::task::spawn_blocking(move || refresh(&cancel))
                    .await
                    .map_err(io::Error::other)?
                    .map_err(|not_ready| io::Error::other(not_ready.sentence().to_string()))?;
                connect().stream.await
            };
            tokio::time::timeout(within, dial)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Cloud SQL did not answer the cancel connection in time."))?
        }
        .boxed()
    })
}

/// Resolves once `cancel` is set, looking every `CLOSED_POLL`.
pub(super) async fn cancelled(cancel: &CancelToken) {
    while !cancel.is_cancelled() {
        tokio::time::sleep(CLOSED_POLL).await;
    }
}

/// Signs in to `db` over `upstream`, with the material `prepared` got, for the tab whose open `cancel` cancels. A dial or sign-in that
/// fails takes that material back (`Upstream::forget`): a certificate Cloud SQL refused shows only then.
async fn sign_in(
    upstream: &Arc<CloudSqlUpstream>,
    db: &SavedDatabase,
    prepared: Prepared,
    read_only: ReadOnlyMode,
    cancel: &CancelToken,
) -> Result<(ConsoleConnection, ConsoleOpened, BoxFuture<'static, String>), OpenError> {
    let Dialling { material, stream } = upstream.connect(&db.id, Some(prepared.material));
    let forget = || {
        if let Some(material) = material {
            upstream.forget(&db.id, material);
        }
    };
    let dialled = tokio::select! {
        dialled = tokio::time::timeout(SIGN_IN_WITHIN, stream) => dialled,
        () = cancelled(cancel) => return Err(OpenError::Failed(OPEN_CANCELLED.to_string())),
    };
    let stream = match dialled {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            forget();
            return Err(OpenError::Failed(unreachable(&db.connection_name(), &error)));
        }
        Err(_) => {
            forget();
            return Err(OpenError::Failed(SIGN_IN_TIMED_OUT.to_string()));
        }
    };
    let login = ConsoleLogin { iam_user: prepared.iam_user, database: db.default_database.clone(), read_only };
    let (connecting, refreshing, id, saved) = (upstream.clone(), upstream.clone(), db.id.clone(), db.clone());
    // The cancel dial refreshes with the database as it was opened: one saved anew would take the route, and the host session the
    // console rides on, along.
    let cancel_dial = dial_for_cancel(
        Arc::new(move || connecting.connect(&id, None)),
        Arc::new(move |cancel: &CancelToken| refreshing.refresh_quietly(&saved, cancel)),
        CANCEL_WITHIN,
    );
    let opened = tokio::select! {
        opened = ConsoleConnection::open(stream, login, cancel_dial) => opened,
        () = cancelled(cancel) => return Err(OpenError::Failed(OPEN_CANCELLED.to_string())),
    };
    if let Err(OpenError::Failed(_)) = &opened {
        forget();
    }
    opened
}

/// The saved database `id` as the library holds it now. It blocks on the library.
fn saved_database(app: &tauri::AppHandle, id: &str) -> Result<SavedDatabase, String> {
    crate::sync::databases::view(&snapshot(app)?)
        .into_iter()
        .map(|row| row.database)
        .find(|database| database.id == id)
        .ok_or_else(|| DATABASE_GONE.to_string())
}

fn consoles(app: &tauri::AppHandle) -> Arc<Consoles> {
    Arc::clone(&app.state::<AppState>().session.consoles)
}

type OpenedSession = (ConsoleSession, ConsoleOpened, BoxFuture<'static, String>);

async fn open_standard(
    app: tauri::AppHandle,
    id: String,
    password: Option<String>,
    expected_revision: Option<String>,
    cancel: &CancelToken,
) -> Result<OpenedSession, String> {
    let lookup = app.clone();
    let (profile, password) = tokio::task::spawn_blocking(move || {
        standard_postgres_profiles::open_profile(&lookup, &id, expected_revision.as_deref(), password)
    })
    .await
    .map_err(|_| "Could not load the PostgreSQL connection.".to_string())??;
    let mut password = Zeroizing::new(password);
    let (stream, cancel_dial) = postgres_transport::open(&app, &profile, cancel).await?;
    let check = profile.clone();
    tokio::task::spawn_blocking(move || standard_postgres_profiles::check_current(&app, &check))
        .await
        .map_err(|_| "Could not verify the PostgreSQL connection.".to_string())??;
    if cancel.is_cancelled() {
        return Err(OPEN_CANCELLED.to_string());
    }
    let login = ConsoleLogin { iam_user: profile.username, database: profile.database, read_only: ReadOnlyMode::Standard };
    let (connection, opened, ended) = tokio::select! {
        result = ConsoleConnection::open_within(stream, login, cancel_dial, MAX_STATEMENT_INBOUND, Some(std::mem::take(&mut *password))) => {
            result.map_err(|error| match error {
                OpenError::Failed(message) | OpenError::LockUnsupported(message) => message,
            })?
        }
        () = cancelled(cancel) => return Err(OPEN_CANCELLED.to_string()),
    };
    Ok((ConsoleSession::standard(connection), opened, ended))
}

/// Opens a tab's read-only session to a saved database through a route of its own. `events` is told when the session ends.
#[tauri::command]
pub async fn database_console_open(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: String,
    database_id: String,
    read_only: ReadOnlyMode,
    password: Option<String>,
    expected_revision: Option<String>,
    events: tauri::ipc::Channel<ConsoleEvent>,
) -> Result<ConsoleOpen, String> {
    main_only(&window, "Database")?;
    let consoles = consoles(&app);
    let (ticket, cancel) = consoles.begin(&id)?;
    let _opening = OpeningGuard { consoles: &consoles, id: &id, ticket };
    let (session, opened, ended) = if database_id.starts_with("postgres-") {
        open_standard(app, database_id, password, expected_revision, &cancel).await?
    } else {
        if read_only == ReadOnlyMode::Standard || password.is_some() || expected_revision.is_some() {
            return Err("Choose a matching database connection type.".to_string());
        }
        match open_cloud(app, database_id, read_only, &cancel).await {
            Ok(session) => session,
            Err(OpenError::LockUnsupported(message)) => return Ok(ConsoleOpen::LockUnsupported { message }),
            Err(OpenError::Failed(message)) => return Err(message),
        }
    };
    if !consoles.finish(&id, ticket, Arc::new(session)) {
        return Err(CONSOLE_CLOSED.to_string());
    }
    tauri::async_runtime::spawn(async move {
        let message = ended.await;
        let _ = events.send(ConsoleEvent::Ended { message });
    });
    Ok(ConsoleOpen::Opened(opened))
}

async fn open_cloud(
    app: tauri::AppHandle,
    database_id: String,
    read_only: ReadOnlyMode,
    cancel: &CancelToken,
) -> Result<OpenedSession, OpenError> {
    let preparing = cancel.clone();
    let (upstream, db, prepared) = tauri::async_runtime::spawn_blocking(move || {
        let db = saved_database(&app, &database_id)?;
        let broker = started_broker(&app)?;
        let upstream = Arc::new(CloudSqlUpstream::for_app(&app, &broker));
        match upstream.prepare(&db, &preparing) {
            Ok(prepared) => Ok((upstream, db, prepared)),
            Err(not_ready) => {
                upstream.release(&db.id);
                Err(not_ready.sentence().to_string())
            }
        }
    })
    .await
    .map_err(|error| OpenError::Failed(error.to_string()))?
    .map_err(OpenError::Failed)?;
    let (connection, opened, ended) = match sign_in(&upstream, &db, prepared, read_only, cancel).await {
        Ok(signed_in) => signed_in,
        Err(error) => {
            upstream.release(&db.id);
            return Err(error);
        }
    };
    Ok((ConsoleSession::new(connection, upstream, db.id), opened, ended))
}

#[tauri::command]
pub fn database_console_close(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<(), String> {
    main_only(&window, "Database")?;
    consoles(&app).close(&id);
    Ok(())
}

#[tauri::command]
pub async fn database_console_run(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String, sql: String, fresh: bool) -> Result<ConsoleRun, String> {
    main_only(&window, "Database")?;
    let session = consoles(&app).get(&id)?;
    session.connection.run(&sql, fresh).await
}

#[tauri::command]
pub fn database_console_page(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String, result_id: u32, offset: u32) -> Result<Vec<Vec<Option<String>>>, String> {
    main_only(&window, "Database")?;
    consoles(&app).get(&id)?.connection.page(result_id, offset)
}

#[tauri::command]
pub async fn database_console_cancel(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<(), String> {
    main_only(&window, "Database")?;
    let session = consoles(&app).get(&id)?;
    session.connection.cancel().await
}

#[tauri::command]
pub async fn database_console_schema(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<SchemaTree, String> {
    main_only(&window, "Database")?;
    let session = consoles(&app).get(&id)?;
    read_schema(&session.connection).await
}

/// Writes the kept rows of `result_id` to `path`, the file the save dialog chose.
#[tauri::command]
pub async fn database_console_export(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: String,
    result_id: u32,
    format: ExportFormat,
    path: String,
) -> Result<(), String> {
    main_only(&window, "Database")?;
    let session = consoles(&app).get(&id)?;
    tauri::async_runtime::spawn_blocking(move || session.connection.export(result_id, format, std::path::Path::new(&path)))
        .await
        .map_err(|error| error.to_string())?
}

#[cfg(test)]
#[path = "database_console_tests.rs"]
mod tests;
