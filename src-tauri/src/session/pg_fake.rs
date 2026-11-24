//! A scriptable fake PostgreSQL server for tests: helpers that speak enough of the v3 wire protocol over a
//! `tokio::io::duplex` peer for `tokio-postgres` to prepare and run statements against it.

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// One backend or frontend message: the type byte, the length (which counts itself), then the body.
pub(crate) fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// Reads one typed message from the client.
pub(crate) async fn read_frame(peer: &mut DuplexStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];
    peer.read_exact(&mut header).await.unwrap();
    let size = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
    let mut body = vec![0; size - 4];
    peer.read_exact(&mut body).await.unwrap();
    (header[0], body)
}

/// Reads the startup message (length-prefixed, no type byte) and returns it as lossy text, without answering it.
pub(crate) async fn read_startup(peer: &mut DuplexStream) -> String {
    let mut length = [0u8; 4];
    peer.read_exact(&mut length).await.unwrap();
    let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
    peer.read_exact(&mut startup).await.unwrap();
    String::from_utf8_lossy(&startup).into_owned()
}

/// Reads the startup message (length-prefixed, no type byte), answers AuthenticationOk, a `server_version`
/// ParameterStatus, BackendKeyData (process id 7, secret key 11) and ReadyForQuery, and returns the startup message as
/// lossy text.
pub(crate) async fn accept_startup(peer: &mut DuplexStream) -> String {
    let text = read_startup(peer).await;
    peer.write_all(&frame(b'R', &0u32.to_be_bytes()))
        .await
        .unwrap();
    peer.write_all(&frame(b'S', b"server_version\x0016.4\x00"))
        .await
        .unwrap();
    let mut key_data = 7u32.to_be_bytes().to_vec();
    key_data.extend_from_slice(&11u32.to_be_bytes());
    peer.write_all(&frame(b'K', &key_data)).await.unwrap();
    peer.write_all(&frame(b'Z', b"I")).await.unwrap();
    text
}

/// Reads the CancelRequest a cancel connection carries (length 16, request code 80877102, process id, secret key) and
/// returns its process id and secret key. The client sends nothing else and never waits for an answer.
pub(crate) async fn read_cancel_request(peer: &mut DuplexStream) -> (i32, i32) {
    let mut request = [0u8; 16];
    peer.read_exact(&mut request).await.unwrap();
    assert_eq!(i32::from_be_bytes(request[0..4].try_into().unwrap()), 16);
    assert_eq!(i32::from_be_bytes(request[4..8].try_into().unwrap()), 80_877_102);
    (
        i32::from_be_bytes(request[8..12].try_into().unwrap()),
        i32::from_be_bytes(request[12..16].try_into().unwrap()),
    )
}

/// A RowDescription body for text-format columns, each given as a name and a type OID.
pub(crate) fn row_description(columns: &[(&str, u32)]) -> Vec<u8> {
    let mut body = (columns.len() as u16).to_be_bytes().to_vec();
    for (name, oid) in columns {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&oid.to_be_bytes());
        body.extend_from_slice(&(-1i16).to_be_bytes());
        body.extend_from_slice(&(-1i32).to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
    }
    body
}

/// A DataRow body of text values; `None` is SQL NULL.
pub(crate) fn data_row(values: &[Option<&str>]) -> Vec<u8> {
    let mut body = (values.len() as u16).to_be_bytes().to_vec();
    for value in values {
        match value {
            Some(text) => {
                body.extend_from_slice(&(text.len() as i32).to_be_bytes());
                body.extend_from_slice(text.as_bytes());
            }
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    body
}

/// An ErrorResponse body with severity, SQLSTATE, message and, when given, the error position.
pub(crate) fn error_response(sqlstate: &str, message: &str, position: Option<u32>) -> Vec<u8> {
    let mut body = Vec::new();
    let mut field = |code: u8, text: &str| {
        body.push(code);
        body.extend_from_slice(text.as_bytes());
        body.push(0);
    };
    field(b'S', "ERROR");
    field(b'V', "ERROR");
    field(b'C', sqlstate);
    field(b'M', message);
    if let Some(position) = position {
        field(b'P', &position.to_string());
    }
    body.push(0);
    body
}

/// Answers CloseComplete and ReadyForQuery: what a Close batch (Close, Sync) gets. `tokio-postgres` sends one when a
/// prepared statement is dropped.
async fn answer_close(peer: &mut DuplexStream) {
    peer.write_all(&frame(b'3', &[])).await.unwrap();
    peer.write_all(&frame(b'Z', b"I")).await.unwrap();
}

/// Waits for the batch `Client::prepare` sends (Parse, Describe, Sync) and answers ParseComplete, ParameterDescription
/// with no parameters, RowDescription (NoData when `columns` is empty), then ReadyForQuery. It reads the frames up to
/// each Sync without checking them, and answers a Close batch that comes first.
pub(crate) async fn answer_prepare(peer: &mut DuplexStream, columns: &[(&str, u32)]) {
    loop {
        let mut batch = Vec::new();
        loop {
            let (kind, _) = read_frame(peer).await;
            if kind == b'S' {
                break;
            }
            batch.push(kind);
        }
        if batch.contains(&b'P') {
            break;
        }
        if batch.contains(&b'C') {
            answer_close(peer).await;
        }
    }
    peer.write_all(&frame(b'1', &[])).await.unwrap();
    peer.write_all(&frame(b't', &0u16.to_be_bytes()))
        .await
        .unwrap();
    if columns.is_empty() {
        peer.write_all(&frame(b'n', &[])).await.unwrap();
    } else {
        peer.write_all(&frame(b'T', &row_description(columns)))
            .await
            .unwrap();
    }
    peer.write_all(&frame(b'Z', b"I")).await.unwrap();
}

/// Reads frames until a simple Query (`Q`) arrives and returns its SQL. It skips other frames, and answers a Close
/// batch that comes first.
pub(crate) async fn expect_query(peer: &mut DuplexStream) -> String {
    let mut batch = Vec::new();
    loop {
        let (kind, body) = read_frame(peer).await;
        match kind {
            b'Q' => {
                let sql = body.strip_suffix(&[0]).unwrap_or(&body);
                return String::from_utf8_lossy(sql).into_owned();
            }
            b'S' => {
                if batch.contains(&b'C') && !batch.contains(&b'P') {
                    answer_close(peer).await;
                }
                batch.clear();
            }
            other => batch.push(other),
        }
    }
}
