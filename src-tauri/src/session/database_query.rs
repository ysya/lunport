//! A short-lived PostgreSQL client on Lunport's Cloud SQL TLS stream. It never uses the local application port or its password.

use futures_util::TryStreamExt;
use serde::Serialize;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tauri::AppHandle;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::{Config, NoTls, SimpleQueryMessage};

use super::connect::CancelToken;
use super::database_ports::{BoxStream, Upstream};
use super::database_upstream::CloudSqlUpstream;
use super::protocol::AiAsker;
use crate::sync::databases::SavedDatabase;

const MAX_SQL_BYTES: usize = 16 * 1024;
const MAX_ROWS: usize = 100;
const MAX_RESULT_BYTES: usize = 256 * 1024;
const MAX_INBOUND_BYTES: usize = 512 * 1024;
const STATEMENT_TIMEOUT_MS: u32 = 30_000;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(35);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SqlMode {
    Read,
    Write,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SqlError {
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    Failed(String),
    #[error("The write outcome is uncertain because the database connection ended before it answered. Check the database before retrying. {0}")]
    Uncertain(String),
}

/// Bound decoded PostgreSQL traffic before the client can buffer a large result row.
struct InboundCap {
    inner: BoxStream,
    remaining: usize,
}
impl InboundCap {
    fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            remaining: MAX_INBOUND_BYTES,
        }
    }
}
impl AsyncRead for InboundCap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.remaining == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Cloud SQL response exceeds the 512 KiB read limit.",
            )));
        }
        let mut scratch = [0u8; 8192];
        let limit = output.remaining().min(self.remaining).min(scratch.len());
        let mut read = ReadBuf::new(&mut scratch[..limit]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let bytes = read.filled().len();
                output.put_slice(read.filled());
                self.remaining -= bytes;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncWrite for InboundCap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Open a private Cloud SQL TLS stream with the existing IAM, PAM and Host route machinery.
pub(crate) async fn run_direct(
    app: AppHandle,
    database: SavedDatabase,
    sql: String,
    mode: SqlMode,
    ai: AiAsker,
    cancel: CancelToken,
    recheck: impl Fn() -> Result<(), String>,
) -> Result<SqlResult, SqlError> {
    valid_sql(&sql)?;
    if cancel.is_cancelled() {
        return Err(SqlError::Rejected("Request canceled.".into()));
    }
    let broker = super::databases::started_broker(&app).map_err(SqlError::Failed)?;
    let prepared_db = database.clone();
    let preparation_cancel = cancel.clone();
    let (upstream, prepared) = tokio::task::spawn_blocking(move || {
        let upstream = CloudSqlUpstream::for_app(&app, &broker);
        let prepared = upstream
            .prepare_for_ai(&prepared_db, &preparation_cancel, &ai)
            .map_err(|error| SqlError::Failed(error.sentence().to_string()))?;
        Ok::<_, SqlError>((upstream, prepared))
    })
    .await
    .map_err(|error| SqlError::Failed(error.to_string()))??;
    if cancel.is_cancelled() {
        return Err(SqlError::Rejected("Request canceled.".into()));
    }
    recheck().map_err(SqlError::Rejected)?;
    let dial = upstream.connect(&database.id, Some(prepared.material));
    let stream = tokio::time::timeout(NETWORK_TIMEOUT, dial.stream)
        .await
        .map_err(|_| SqlError::Failed("Cloud SQL connection timed out.".into()))?
        .map_err(|error| SqlError::Failed(error.to_string()))?;
    if cancel.is_cancelled() {
        return Err(SqlError::Rejected("Request canceled.".into()));
    }
    recheck().map_err(SqlError::Rejected)?;
    let result = run_on_stream_checked(
        stream,
        &prepared.iam_user,
        &database.default_database,
        &sql,
        mode,
        Some(&cancel),
        Some(&recheck),
    )
    .await;
    if cancel.is_cancelled() && mode == SqlMode::Write {
        return Err(SqlError::Uncertain(
            "The request was canceled while the write was running.".into(),
        ));
    }
    if cancel.is_cancelled() {
        return Err(SqlError::Rejected("Request canceled.".into()));
    }
    result
}

#[derive(Debug, Serialize)]
pub(crate) struct SqlResult {
    pub columns: Vec<String>,
    pub column_types: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    pub truncated: bool,
    pub affected_rows: Option<u64>,
}

fn valid_sql(sql: &str) -> Result<(), SqlError> {
    if sql.trim().is_empty()
        || sql.len() > MAX_SQL_BYTES
        || sql.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t')
                || crate::session::auth::is_deceptive_format(c)
        })
    {
        return Err(SqlError::Rejected("Provide one SQL statement of at most 16 KiB without control or deceptive format characters.".into()));
    }
    Ok(())
}

pub(crate) fn validate_sql(sql: &str) -> Result<(), SqlError> {
    valid_sql(sql)
}

fn client_config(iam_user: &str, database: &str, mode: SqlMode) -> Config {
    let mut config = Config::new();
    config
        .user(iam_user)
        .dbname(database)
        .application_name("Lunport AI");
    let options = match mode {
        SqlMode::Read => format!(
            "-c statement_timeout={STATEMENT_TIMEOUT_MS} -c cloudsql_session_read_only=locked"
        ),
        SqlMode::Write => format!("-c statement_timeout={STATEMENT_TIMEOUT_MS}"),
    };
    config.options(&options);
    config
}

#[cfg(test)]
pub(crate) async fn run_on_stream(
    stream: BoxStream,
    iam_user: &str,
    database: &str,
    sql: &str,
    mode: SqlMode,
) -> Result<SqlResult, SqlError> {
    run_on_stream_checked(stream, iam_user, database, sql, mode, None, None).await
}

async fn wait_cancel(cancel: Option<&CancelToken>) {
    let Some(cancel) = cancel else {
        std::future::pending::<()>().await;
        return;
    };
    while !cancel.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn run_on_stream_checked(
    stream: BoxStream,
    iam_user: &str,
    database: &str,
    sql: &str,
    mode: SqlMode,
    cancel: Option<&CancelToken>,
    recheck: Option<&dyn Fn() -> Result<(), String>>,
) -> Result<SqlResult, SqlError> {
    valid_sql(sql)?;
    let config = client_config(iam_user, database, mode);
    let (client, connection) = tokio::time::timeout(
        NETWORK_TIMEOUT,
        config.connect_raw(InboundCap::new(stream), NoTls),
    )
    .await
    .map_err(|_| SqlError::Failed("Cloud SQL sign-in timed out.".into()))?
    .map_err(|error| SqlError::Failed(error.to_string()))?;
    let driver = tokio::spawn(async move { connection.await });
    let result = async {
        // Preparing through the extended protocol rejects a second statement before execution.
        let statement = tokio::time::timeout(NETWORK_TIMEOUT, client.prepare(sql)).await
            .map_err(|_| SqlError::Failed("SQL preparation timed out.".into()))?
            .map_err(|error| SqlError::Rejected(error.to_string()))?;
        if let Some(recheck) = recheck { recheck().map_err(SqlError::Rejected)?; }
        if mode == SqlMode::Write {
            if !statement.columns().is_empty() { return Err(SqlError::Rejected("Write statements must not return rows. Remove RETURNING and retry.".into())); }
            if cancel.is_some_and(CancelToken::is_cancelled) { return Err(SqlError::Rejected("Request canceled before execution.".into())); }
            let affected = tokio::select! {
                result = tokio::time::timeout(NETWORK_TIMEOUT, client.execute(&statement, &[])) => result,
                () = wait_cancel(cancel) => return Err(SqlError::Uncertain("The request was canceled while the write was running.".into())),
            }
                .map_err(|_| SqlError::Uncertain("The database did not answer before the timeout.".into()))?
                .map_err(|error| {
                if error.code().is_some() { SqlError::Rejected(error.to_string()) } else { SqlError::Uncertain(error.to_string()) }
            })?;
            return Ok(SqlResult { columns: vec![], column_types: vec![], rows: vec![], truncated: false, affected_rows: Some(affected) });
        }
        let columns = statement.columns().iter().map(|column| column.name().to_string()).collect();
        let column_types = statement.columns().iter().map(|column| column.type_().name().to_string()).collect();
        let mut result = SqlResult { columns, column_types, rows: Vec::new(), truncated: false, affected_rows: None };
        let mut bytes = serde_json::to_vec(&result).map_err(|error| SqlError::Failed(error.to_string()))?.len();
        if bytes + 16 > MAX_RESULT_BYTES { return Err(SqlError::Rejected("Query column metadata exceeds the response limit.".into())); }
        let messages = tokio::select! {
            result = tokio::time::timeout(NETWORK_TIMEOUT, client.simple_query_raw(sql)) => result,
            () = wait_cancel(cancel) => return Err(SqlError::Rejected("Request canceled.".into())),
        }
            .map_err(|_| SqlError::Failed("SQL query timed out.".into()))?
            .map_err(|error| SqlError::Failed(error.to_string()))?;
        tokio::pin!(messages);
        while let Some(message) = tokio::select! {
            result = tokio::time::timeout(NETWORK_TIMEOUT, messages.try_next()) => result,
            () = wait_cancel(cancel) => return Err(SqlError::Rejected("Request canceled.".into())),
        }
            .map_err(|_| SqlError::Failed("SQL query timed out.".into()))?
            .map_err(|error| SqlError::Failed(error.to_string()))? {
            if let SimpleQueryMessage::Row(row) = message {
                if result.rows.len() >= MAX_ROWS {
                    result.truncated = true;
                    break;
                }
                let values: Vec<Option<String>> = (0..row.len()).map(|index| row.get(index).map(str::to_string)).collect();
                let row_bytes = serde_json::to_vec(&values).map_err(|error| SqlError::Failed(error.to_string()))?.len() + 1;
                if bytes + row_bytes + 16 > MAX_RESULT_BYTES {
                    result.truncated = true;
                    break;
                }
                bytes += row_bytes;
                result.rows.push(values);
            }
        }
        Ok(result)
    }.await;
    driver.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn inbound_limit_stops_a_large_row_before_postgres_can_buffer_it() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let writer = tokio::spawn(async move {
            let _ = peer.write_all(&vec![b'x'; MAX_INBOUND_BYTES + 1]).await;
        });
        let mut limited = InboundCap::new(Box::new(client));
        let mut received = Vec::new();
        let error = limited.read_to_end(&mut received).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(received.len(), MAX_INBOUND_BYTES);
        writer.abort();
    }

    fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind];
        bytes.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    async fn read_frame(peer: &mut tokio::io::DuplexStream) -> (u8, Vec<u8>) {
        let mut header = [0u8; 5];
        peer.read_exact(&mut header).await.unwrap();
        let size = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut body = vec![0; size - 4];
        peer.read_exact(&mut body).await.unwrap();
        (header[0], body)
    }

    fn text_column() -> Vec<u8> {
        let mut body = 1u16.to_be_bytes().to_vec();
        body.extend_from_slice(b"answer\0");
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&25u32.to_be_bytes());
        body.extend_from_slice(&(-1i16).to_be_bytes());
        body.extend_from_slice(&(-1i32).to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body
    }

    #[tokio::test]
    async fn direct_read_uses_locked_cloud_sql_session_and_returns_text_rows() {
        let (client, mut peer) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let mut length = [0u8; 4];
            peer.read_exact(&mut length).await.unwrap();
            let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
            peer.read_exact(&mut startup).await.unwrap();
            let startup = String::from_utf8_lossy(&startup);
            assert!(startup.contains("frank@example.com"));
            assert!(startup.contains("cloudsql_session_read_only=locked"));
            assert!(!startup.contains("password"));
            peer.write_all(&frame(b'R', &0u32.to_be_bytes()))
                .await
                .unwrap();
            peer.write_all(&frame(b'Z', b"I")).await.unwrap();

            loop {
                let (kind, _) = read_frame(&mut peer).await;
                if kind == b'S' {
                    break;
                }
            }
            peer.write_all(&frame(b'1', &[])).await.unwrap();
            peer.write_all(&frame(b't', &0u16.to_be_bytes()))
                .await
                .unwrap();
            peer.write_all(&frame(b'T', &text_column())).await.unwrap();
            peer.write_all(&frame(b'Z', b"I")).await.unwrap();

            loop {
                let (kind, body) = read_frame(&mut peer).await;
                if kind == b'Q' {
                    assert_eq!(body, b"SELECT 1\0");
                    break;
                }
            }
            peer.write_all(&frame(b'T', &text_column())).await.unwrap();
            let mut row = 1u16.to_be_bytes().to_vec();
            row.extend_from_slice(&1u32.to_be_bytes());
            row.push(b'1');
            peer.write_all(&frame(b'D', &row)).await.unwrap();
            peer.write_all(&frame(b'C', b"SELECT 1\0")).await.unwrap();
            peer.write_all(&frame(b'Z', b"I")).await.unwrap();
        });

        let result = run_on_stream(
            Box::new(client),
            "frank@example.com",
            "postgres",
            "SELECT 1",
            SqlMode::Read,
        )
        .await
        .unwrap();
        assert_eq!(result.columns, vec!["answer"]);
        assert_eq!(result.rows, vec![vec![Some("1".into())]]);
        assert!(!result.truncated);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn lost_write_response_reports_uncertain_outcome() {
        let (client, mut peer) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let mut length = [0u8; 4];
            peer.read_exact(&mut length).await.unwrap();
            let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
            peer.read_exact(&mut startup).await.unwrap();
            assert!(!String::from_utf8_lossy(&startup).contains("cloudsql_session_read_only"));
            peer.write_all(&frame(b'R', &0u32.to_be_bytes()))
                .await
                .unwrap();
            peer.write_all(&frame(b'Z', b"I")).await.unwrap();
            loop {
                let (kind, _) = read_frame(&mut peer).await;
                if kind == b'S' {
                    break;
                }
            }
            peer.write_all(&frame(b'1', &[])).await.unwrap();
            peer.write_all(&frame(b't', &0u16.to_be_bytes()))
                .await
                .unwrap();
            peer.write_all(&frame(b'n', &[])).await.unwrap();
            peer.write_all(&frame(b'Z', b"I")).await.unwrap();
            loop {
                let (kind, _) = read_frame(&mut peer).await;
                if kind == b'S' {
                    break;
                }
            }
            // The write may have committed before the connection was lost.
        });
        let error = run_on_stream(
            Box::new(client),
            "frank@example.com",
            "postgres",
            "UPDATE items SET checked = true",
            SqlMode::Write,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SqlError::Uncertain(_)), "{error:?}");
        server.await.unwrap();
    }
}
