use super::*;
use crate::session::pg_fake::*;
use futures_util::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};

fn login(read_only: ReadOnlyMode) -> ConsoleLogin {
    ConsoleLogin {
        iam_user: "frank@example.com".into(),
        database: "orders".into(),
        read_only,
    }
}

/// A cancel dial that hands the test the server end of every cancel connection it opens.
fn cancel_line() -> (CancelDial, mpsc::UnboundedReceiver<DuplexStream>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let dial: CancelDial = Arc::new(move || {
        let (client, server) = tokio::io::duplex(1024);
        let _ = sender.send(server);
        async move { Ok(Box::new(client) as BoxStream) }.boxed()
    });
    (dial, receiver)
}

fn unreachable_dial() -> CancelDial {
    Arc::new(|| async { Err(io::Error::other("no route to the instance")) }.boxed())
}

/// Answers a `SHOW` query with one text row.
async fn answer_show(peer: &mut DuplexStream, name: &str, value: &str) {
    assert_eq!(expect_query(peer).await, format!("SHOW {name}"));
    peer.write_all(&frame(b'T', &row_description(&[(name, 25)])))
        .await
        .unwrap();
    peer.write_all(&frame(b'D', &data_row(&[Some(value)])))
        .await
        .unwrap();
    peer.write_all(&frame(b'C', b"SHOW\0")).await.unwrap();
    peer.write_all(&frame(b'Z', b"I")).await.unwrap();
}

/// The answer to a simple query: its RowDescription, the rows, CommandComplete and ReadyForQuery, in one write.
fn rows_answer(columns: &[(&str, u32)], rows: &[Vec<Option<String>>], tag: &str) -> Vec<u8> {
    let mut bytes = frame(b'T', &row_description(columns));
    for row in rows {
        let values: Vec<Option<&str>> = row.iter().map(Option::as_deref).collect();
        bytes.extend(frame(b'D', &data_row(&values)));
    }
    bytes.extend(frame(b'C', format!("{tag}\0").as_bytes()));
    bytes.extend(frame(b'Z', b"I"));
    bytes
}

/// Answers one statement as `run` sends it: the prepare, then the simple query, with `rows`.
async fn answer_statement(peer: &mut DuplexStream, sql: &str, columns: &[(&str, u32)], rows: &[Vec<Option<String>>]) {
    answer_prepare(peer, columns).await;
    assert_eq!(expect_query(peer).await, sql);
    let tag = format!("SELECT {}", rows.len());
    peer.write_all(&rows_answer(columns, rows, &tag)).await.unwrap();
}

fn one_row() -> Vec<Vec<Option<String>>> {
    vec![vec![Some("1".into())]]
}

/// Opens a locked console on a fresh duplex and hands back the fake's end.
async fn opened(dial: CancelDial) -> (Arc<ConsoleConnection>, BoxFuture<'static, String>, DuplexStream) {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let (open, ()) = tokio::join!(
        ConsoleConnection::open(Box::new(client), login(ReadOnlyMode::Locked), dial),
        async {
            accept_startup(&mut peer).await;
            answer_show(&mut peer, "cloudsql_session_read_only", "locked").await;
        }
    );
    let (console, _, ended) = open.unwrap();
    (Arc::new(console), ended, peer)
}

/// Reads whatever the client still sends until it closes the connection.
async fn read_until_closed(peer: &mut DuplexStream) {
    let mut rest = [0u8; 1024];
    while peer.read(&mut rest).await.unwrap_or(0) > 0 {}
}

#[tokio::test]
async fn open_locks_the_session_and_checks_the_lock() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let (open, startup) = tokio::join!(
        ConsoleConnection::open(Box::new(client), login(ReadOnlyMode::Locked), unreachable_dial()),
        async {
            let startup = accept_startup(&mut peer).await;
            answer_show(&mut peer, "cloudsql_session_read_only", "locked").await;
            startup
        }
    );
    assert!(startup.contains("cloudsql_session_read_only=locked"), "{startup}");
    assert!(startup.contains("Lunport Console"), "{startup}");
    assert!(startup.contains("frank@example.com"), "{startup}");
    let (_console, opened, _ended) = open.unwrap();
    assert_eq!(
        opened,
        ConsoleOpened {
            read_only: ReadOnlyMode::Locked,
            iam_user: "frank@example.com".into(),
            server_version: "16.4".into(),
        }
    );
    let json = serde_json::to_value(ConsoleOpen::Opened(opened)).unwrap();
    assert_eq!(json["kind"], "opened");
    assert_eq!(json["read_only"], "locked");
}

#[tokio::test]
async fn open_not_locked_uses_default_transaction_read_only() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let (open, startup) = tokio::join!(
        ConsoleConnection::open(Box::new(client), login(ReadOnlyMode::NotLocked), unreachable_dial()),
        async {
            let startup = accept_startup(&mut peer).await;
            answer_show(&mut peer, "default_transaction_read_only", "on").await;
            startup
        }
    );
    assert!(startup.contains("default_transaction_read_only=on"), "{startup}");
    assert!(!startup.contains("cloudsql_session_read_only"), "{startup}");
    let (_console, opened, _ended) = open.unwrap();
    assert_eq!(opened.read_only, ReadOnlyMode::NotLocked);
}

#[tokio::test]
async fn a_lock_that_reads_otherwise_closes_the_session() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let (open, ()) = tokio::join!(
        ConsoleConnection::open(Box::new(client), login(ReadOnlyMode::Locked), unreachable_dial()),
        async {
            accept_startup(&mut peer).await;
            answer_show(&mut peer, "cloudsql_session_read_only", "off").await;
        }
    );
    match open {
        Err(OpenError::Failed(message)) => assert_eq!(
            message,
            "Lunport could not confirm that this session is read-only, so it closed it."
        ),
        other => panic!("{:?}", other.map(|(_, opened, _)| opened)),
    }
    read_until_closed(&mut peer).await;
}

#[tokio::test]
async fn an_unsupported_lock_is_told_apart() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let (open, ()) = tokio::join!(
        ConsoleConnection::open(Box::new(client), login(ReadOnlyMode::Locked), unreachable_dial()),
        async {
            read_startup(&mut peer).await;
            let refusal = error_response(
                "42704",
                "unrecognized configuration parameter \"cloudsql_session_read_only\"",
                None,
            );
            peer.write_all(&frame(b'E', &refusal)).await.unwrap();
        }
    );
    match open {
        Err(OpenError::LockUnsupported(message)) => {
            assert!(message.contains("does not support Cloud SQL's read-only lock"), "{message}");
            let json = serde_json::to_value(ConsoleOpen::LockUnsupported { message }).unwrap();
            assert_eq!(json["kind"], "lock_unsupported");
        }
        other => panic!("{:?}", other.map(|(_, opened, _)| opened)),
    }
}

#[tokio::test]
async fn rows_come_back_in_pages_of_200() {
    let (console, _ended, mut peer) = opened(unreachable_dial()).await;
    let rows: Vec<Vec<Option<String>>> = (0..450)
        .map(|index| {
            let note = match index % 3 {
                0 => None,
                1 => Some(String::new()),
                _ => Some(format!("note {index}")),
            };
            vec![Some(index.to_string()), note]
        })
        .collect();
    let script = rows.clone();
    let fake = tokio::spawn(async move {
        answer_statement(&mut peer, "SELECT id, note FROM orders", &[("id", 23), ("note", 25)], &script).await;
        peer
    });

    let ConsoleRun::Rows { result_id, columns, row_count, truncated, first_page, .. } =
        console.run("SELECT id, note FROM orders", true).await.unwrap()
    else {
        panic!("not rows");
    };
    assert_eq!(row_count, 450);
    assert_eq!(truncated, None);
    assert_eq!(
        columns,
        vec![
            ConsoleColumn { name: "id".into(), type_name: "int4".into() },
            ConsoleColumn { name: "note".into(), type_name: "text".into() },
        ]
    );
    assert_eq!(first_page.len(), 200);
    assert_eq!(first_page[0], vec![Some("0".into()), None]);
    assert_eq!(first_page[1], vec![Some("1".into()), Some(String::new())]);
    assert_eq!(console.page(result_id, 200).unwrap().len(), 200);
    assert_eq!(console.page(result_id, 400).unwrap(), rows[400..].to_vec());
    assert!(console.page(result_id, 450).unwrap().is_empty());
    let (kept_columns, kept_rows) = console.kept(result_id).unwrap();
    assert_eq!(kept_columns, columns);
    assert_eq!(kept_rows, rows);
    fake.await.unwrap();
}

#[tokio::test]
async fn a_statement_without_rows_answers_its_tag() {
    let (console, _ended, mut peer) = opened(unreachable_dial()).await;
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[]).await;
        assert_eq!(expect_query(&mut peer).await, "SET search_path = public");
        peer.write_all(&frame(b'C', b"SET\0")).await.unwrap();
        peer.write_all(&frame(b'Z', b"I")).await.unwrap();
        peer
    });
    match console.run("SET search_path = public", true).await.unwrap() {
        ConsoleRun::Done { command_tag, .. } => assert_eq!(command_tag, "SET"),
        other => panic!("{other:?}"),
    }
    fake.await.unwrap();
}

#[tokio::test]
async fn a_server_error_answers_its_sqlstate_and_position() {
    let (console, _ended, mut peer) = opened(unreachable_dial()).await;
    let fake = tokio::spawn(async move {
        loop {
            if read_frame(&mut peer).await.0 == b'S' {
                break;
            }
        }
        let refusal = error_response("42P01", "relation \"nope\" does not exist", Some(15));
        peer.write_all(&frame(b'E', &refusal)).await.unwrap();
        peer.write_all(&frame(b'Z', b"I")).await.unwrap();
        answer_statement(&mut peer, "SELECT 1", &[("?column?", 23)], &one_row()).await;
        peer
    });
    match console.run("SELECT * FROM nope", true).await.unwrap() {
        ConsoleRun::Failed { message, sqlstate, position, .. } => {
            assert_eq!(message, "relation \"nope\" does not exist");
            assert_eq!(sqlstate.as_deref(), Some("42P01"));
            assert_eq!(position, Some(15));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        console.run("SELECT 1", true).await.unwrap(),
        ConsoleRun::Rows { row_count: 1, .. }
    ));
    fake.await.unwrap();
}

#[tokio::test]
async fn a_result_past_the_row_limit_is_truncated_and_the_session_goes_on() {
    let (dial, mut dials) = cancel_line();
    let (console, _ended, mut peer) = opened(dial).await;
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("id", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT id FROM events");
        let mut answer = frame(b'T', &row_description(&[("id", 23)]));
        for index in 0..=MAX_RESULT_ROWS {
            answer.extend(frame(b'D', &data_row(&[Some(&index.to_string())])));
        }
        peer.write_all(&answer).await.unwrap();
        let mut cancel = dials.recv().await.unwrap();
        assert_eq!(read_cancel_request(&mut cancel).await, (7, 11));
        drop(cancel);
        let canceled = error_response("57014", "canceling statement due to user request", None);
        peer.write_all(&frame(b'E', &canceled)).await.unwrap();
        peer.write_all(&frame(b'Z', b"I")).await.unwrap();
        answer_statement(&mut peer, "SELECT 1", &[("?column?", 23)], &one_row()).await;
        peer
    });
    match console.run("SELECT id FROM events", true).await.unwrap() {
        ConsoleRun::Rows { row_count, truncated, first_page, .. } => {
            assert_eq!(row_count, 10_000);
            assert_eq!(truncated, Some(Truncation::Rows));
            assert_eq!(first_page.len(), PAGE_ROWS);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        console.run("SELECT 1", false).await.unwrap(),
        ConsoleRun::Rows { row_count: 1, truncated: None, .. }
    ));
    fake.await.unwrap();
}

#[tokio::test]
async fn fresh_drops_earlier_results() {
    let (console, _ended, mut peer) = opened(unreachable_dial()).await;
    let fake = tokio::spawn(async move {
        answer_statement(&mut peer, "SELECT 1", &[("?column?", 23)], &one_row()).await;
        answer_statement(&mut peer, "SELECT 1", &[("?column?", 23)], &one_row()).await;
        peer
    });
    let ConsoleRun::Rows { result_id: first, .. } = console.run("SELECT 1", true).await.unwrap() else {
        panic!("not rows");
    };
    let ConsoleRun::Rows { result_id: second, .. } = console.run("SELECT 1", true).await.unwrap() else {
        panic!("not rows");
    };
    assert_eq!(
        console.page(first, 0).unwrap_err(),
        "This result is no longer kept. Run the statement again."
    );
    assert_eq!(console.page(second, 0).unwrap(), one_row());
    fake.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_late_cancel_never_reaches_the_next_statement() {
    let (dial, mut dials) = cancel_line();
    let (console, _ended, mut peer) = opened(dial).await;
    let (running_tx, running_rx) = oneshot::channel();
    let (cancel_read_tx, cancel_read_rx) = oneshot::channel();
    let (closed_tx, mut closed_rx) = oneshot::channel();
    let cancel_side = tokio::spawn(async move {
        let mut cancel = dials.recv().await.unwrap();
        assert_eq!(read_cancel_request(&mut cancel).await, (7, 11));
        cancel_read_tx.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        closed_tx.send(()).unwrap();
        drop(cancel);
    });
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("?column?", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT 1");
        running_tx.send(()).unwrap();
        cancel_read_rx.await.unwrap();
        // The statement ends on its own after the cancel request was sent.
        peer.write_all(&rows_answer(&[("?column?", 23)], &one_row(), "SELECT 1"))
            .await
            .unwrap();
        answer_prepare(&mut peer, &[("?column?", 23)]).await;
        assert!(
            closed_rx.try_recv().is_ok(),
            "the next statement went out while the cancel connection was still open"
        );
        assert_eq!(expect_query(&mut peer).await, "SELECT 2");
        peer.write_all(&rows_answer(&[("?column?", 23)], &[vec![Some("2".into())]], "SELECT 1"))
            .await
            .unwrap();
        peer
    });

    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT 1", true).await }
    });
    running_rx.await.unwrap();
    console.cancel().await.unwrap();
    assert!(matches!(running.await.unwrap().unwrap(), ConsoleRun::Rows { row_count: 1, .. }));
    assert!(matches!(
        console.run("SELECT 2", true).await.unwrap(),
        ConsoleRun::Rows { row_count: 1, .. }
    ));
    cancel_side.await.unwrap();
    fake.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_cancel_that_does_not_stop_ends_the_session() {
    let (dial, mut dials) = cancel_line();
    let (console, ended, mut peer) = opened(dial).await;
    let (running_tx, running_rx) = oneshot::channel();
    let cancel_side = tokio::spawn(async move {
        let mut cancel = dials.recv().await.unwrap();
        assert_eq!(read_cancel_request(&mut cancel).await, (7, 11));
    });
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("?column?", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT pg_sleep(600)");
        running_tx.send(()).unwrap();
        // The statement never stops; the fake answers nothing more.
        read_until_closed(&mut peer).await;
    });

    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT pg_sleep(600)", true).await }
    });
    running_rx.await.unwrap();
    let sent = tokio::time::Instant::now();
    console.cancel().await.unwrap();
    let stop = "The query did not stop after Cancel, so Lunport closed the connection. Reconnect to go on.";
    assert_eq!(running.await.unwrap().unwrap_err(), stop);
    assert!(sent.elapsed() >= CANCEL_WITHIN);
    assert_eq!(ended.await, stop);
    assert_eq!(
        console.run("SELECT 1", true).await.unwrap_err(),
        "The connection ended. Reconnect to go on."
    );
    cancel_side.await.unwrap();
    fake.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_cancel_that_cannot_be_dialed_keeps_the_session() {
    let (console, ended, mut peer) = opened(unreachable_dial()).await;
    let (running_tx, running_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("?column?", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT 1");
        running_tx.send(()).unwrap();
        finish_rx.await.unwrap();
        peer.write_all(&rows_answer(&[("?column?", 23)], &one_row(), "SELECT 1"))
            .await
            .unwrap();
        answer_statement(&mut peer, "SELECT 2", &[("?column?", 23)], &one_row()).await;
        peer
    });

    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT 1", true).await }
    });
    running_rx.await.unwrap();
    assert_eq!(
        console.cancel().await.unwrap_err(),
        "Lunport could not reach Cloud SQL to cancel the query. It goes on running; close the tab to end the session."
    );
    // No cancel request went out, so no Cancel bound runs: the statement may take longer than it.
    tokio::time::advance(CANCEL_WITHIN + Duration::from_secs(1)).await;
    assert!(!running.is_finished(), "the statement ended before its answer");
    finish_tx.send(()).unwrap();
    assert!(matches!(running.await.unwrap().unwrap(), ConsoleRun::Rows { row_count: 1, .. }));
    assert!(matches!(
        console.run("SELECT 2", true).await.unwrap(),
        ConsoleRun::Rows { row_count: 1, .. }
    ));
    assert!(ended.now_or_never().is_none(), "the session ended");
    fake.await.unwrap();
}

#[tokio::test]
async fn a_run_waits_for_a_catalog_read() {
    let (console, _ended, mut peer) = opened(unreachable_dial()).await;
    let (reading_tx, reading_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let catalog = "SELECT nspname FROM pg_catalog.pg_namespace";
    let fake = tokio::spawn(async move {
        assert_eq!(expect_query(&mut peer).await, catalog);
        reading_tx.send(()).unwrap();
        release_rx.await.unwrap();
        assert!(
            read_frame(&mut peer).now_or_never().is_none(),
            "the run's statement went out during the catalog read"
        );
        peer.write_all(&rows_answer(&[("nspname", 25)], &[vec![Some("public".into())]], "SELECT 1"))
            .await
            .unwrap();
        answer_statement(&mut peer, "SELECT 1", &[("?column?", 23)], &one_row()).await;
        peer
    });

    let reading = tokio::spawn({
        let console = console.clone();
        async move { console.read_rows(catalog).await }
    });
    reading_rx.await.unwrap();
    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT 1", true).await }
    });
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(!running.is_finished(), "the run did not wait for the catalog read");
    release_tx.send(()).unwrap();
    assert_eq!(reading.await.unwrap().unwrap(), vec![vec![Some("public".to_string())]]);
    assert!(matches!(running.await.unwrap().unwrap(), ConsoleRun::Rows { row_count: 1, .. }));
    fake.await.unwrap();
}

#[tokio::test]
async fn a_dropped_connection_ends_the_session() {
    let (console, ended, peer) = opened(unreachable_dial()).await;
    drop(peer);
    let message = ended.await;
    assert_eq!(message, "The connection ended.");
    let json = serde_json::to_value(ConsoleEvent::Ended { message }).unwrap();
    assert_eq!(json["kind"], "ended");
    assert_eq!(
        console.run("SELECT 1", true).await.unwrap_err(),
        "The connection ended. Reconnect to go on."
    );
}

#[tokio::test]
async fn an_answer_past_the_read_limit_ends_the_session() {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let (open, ()) = tokio::join!(
        ConsoleConnection::open_with_budget(
            Box::new(client),
            login(ReadOnlyMode::Locked),
            unreachable_dial(),
            64 * 1024,
        ),
        async {
            accept_startup(&mut peer).await;
            answer_show(&mut peer, "cloudsql_session_read_only", "locked").await;
        }
    );
    let (console, _opened, ended) = open.unwrap();
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("payload", 25)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT payload FROM events");
        let wide = "x".repeat(1024);
        let rows: Vec<Vec<Option<String>>> = (0..200).map(|_| vec![Some(wide.clone())]).collect();
        // Lunport closes the connection part way through, so the write may fail.
        let _ = peer.write_all(&rows_answer(&[("payload", 25)], &rows, "SELECT 200")).await;
        read_until_closed(&mut peer).await;
    });
    let limit = "The answer was larger than 96 MiB, so Lunport closed the connection. Add a LIMIT and reconnect.";
    assert_eq!(console.run("SELECT payload FROM events", true).await.unwrap_err(), limit);
    assert_eq!(ended.await, limit);
    assert_eq!(
        console.run("SELECT 1", true).await.unwrap_err(),
        "The connection ended. Reconnect to go on."
    );
    fake.await.unwrap();
}

#[tokio::test]
async fn a_second_run_while_one_runs_is_refused() {
    let (console, _ended, mut peer) = opened(unreachable_dial()).await;
    let (running_tx, running_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("?column?", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT 1");
        running_tx.send(()).unwrap();
        finish_rx.await.unwrap();
        peer.write_all(&rows_answer(&[("?column?", 23)], &one_row(), "SELECT 1"))
            .await
            .unwrap();
        peer
    });

    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT 1", true).await }
    });
    running_rx.await.unwrap();
    assert_eq!(
        console.run("SELECT 2", false).await.unwrap_err(),
        "A statement is still running. Cancel it or wait for it."
    );
    finish_tx.send(()).unwrap();
    assert!(matches!(running.await.unwrap().unwrap(), ConsoleRun::Rows { row_count: 1, .. }));
    fake.await.unwrap();
}

/// An ErrorResponse with severity FATAL, as a server sends before it closes a session.
fn fatal_response(sqlstate: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (code, text) in [(b'S', "FATAL"), (b'V', "FATAL"), (b'C', sqlstate), (b'M', message)] {
        body.push(code);
        body.extend_from_slice(text.as_bytes());
        body.push(0);
    }
    body.push(0);
    body
}

#[tokio::test]
async fn a_server_fatal_while_idle_ends_the_session_with_its_message() {
    let (console, ended, mut peer) = opened(unreachable_dial()).await;
    let fatal = fatal_response("57P05", "terminating connection due to idle-session timeout");
    peer.write_all(&frame(b'E', &fatal)).await.unwrap();
    drop(peer);
    assert_eq!(
        ended.await,
        "The connection ended: terminating connection due to idle-session timeout."
    );
    assert_eq!(
        console.run("SELECT 1", true).await.unwrap_err(),
        "The connection ended. Reconnect to go on."
    );
}

#[tokio::test]
async fn a_cancel_during_the_rows_answers_canceled() {
    let (dial, mut dials) = cancel_line();
    let (console, _ended, mut peer) = opened(dial).await;
    let (running_tx, running_rx) = oneshot::channel();
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("id", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT id FROM events");
        let mut answer = frame(b'T', &row_description(&[("id", 23)]));
        answer.extend(frame(b'D', &data_row(&[Some("1")])));
        peer.write_all(&answer).await.unwrap();
        running_tx.send(()).unwrap();
        let mut cancel = dials.recv().await.unwrap();
        assert_eq!(read_cancel_request(&mut cancel).await, (7, 11));
        drop(cancel);
        let canceled = error_response("57014", "canceling statement due to user request", None);
        peer.write_all(&frame(b'E', &canceled)).await.unwrap();
        peer.write_all(&frame(b'Z', b"I")).await.unwrap();
        peer
    });
    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT id FROM events", true).await }
    });
    running_rx.await.unwrap();
    console.cancel().await.unwrap();
    assert!(matches!(running.await.unwrap().unwrap(), ConsoleRun::Canceled { .. }));
    fake.await.unwrap();
}

#[tokio::test]
async fn a_cancel_during_the_prepare_answers_canceled() {
    let (dial, mut dials) = cancel_line();
    let (console, _ended, mut peer) = opened(dial).await;
    let (preparing_tx, preparing_rx) = oneshot::channel();
    let fake = tokio::spawn(async move {
        // Parse waits, as it does on a lock, until the cancel request arrives.
        loop {
            if read_frame(&mut peer).await.0 == b'S' {
                break;
            }
        }
        preparing_tx.send(()).unwrap();
        let mut cancel = dials.recv().await.unwrap();
        assert_eq!(read_cancel_request(&mut cancel).await, (7, 11));
        drop(cancel);
        let canceled = error_response("57014", "canceling statement due to user request", None);
        peer.write_all(&frame(b'E', &canceled)).await.unwrap();
        peer.write_all(&frame(b'Z', b"I")).await.unwrap();
        peer
    });
    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT id FROM orders", true).await }
    });
    preparing_rx.await.unwrap();
    console.cancel().await.unwrap();
    assert!(matches!(running.await.unwrap().unwrap(), ConsoleRun::Canceled { .. }));
    fake.await.unwrap();
}

#[tokio::test]
async fn a_cancel_the_person_did_not_send_answers_failed() {
    let (console, _ended, mut peer) = opened(unreachable_dial()).await;
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("?column?", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT pg_sleep(600)");
        let timeout = error_response("57014", "canceling statement due to statement timeout", None);
        peer.write_all(&frame(b'E', &timeout)).await.unwrap();
        peer.write_all(&frame(b'Z', b"I")).await.unwrap();
        peer
    });
    match console.run("SELECT pg_sleep(600)", true).await.unwrap() {
        ConsoleRun::Failed { message, sqlstate, .. } => {
            assert_eq!(message, "canceling statement due to statement timeout");
            assert_eq!(sqlstate.as_deref(), Some("57014"));
        }
        other => panic!("{other:?}"),
    }
    fake.await.unwrap();
}

#[tokio::test]
async fn a_cancel_while_the_run_waits_for_a_catalog_read_cancels_the_run_only() {
    let (dial, mut dials) = cancel_line();
    let (console, _ended, mut peer) = opened(dial).await;
    let (reading_tx, reading_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let catalog = "SELECT nspname FROM pg_catalog.pg_namespace";
    let fake = tokio::spawn(async move {
        assert_eq!(expect_query(&mut peer).await, catalog);
        reading_tx.send(()).unwrap();
        release_rx.await.unwrap();
        peer.write_all(&rows_answer(&[("nspname", 25)], &[vec![Some("public".into())]], "SELECT 1"))
            .await
            .unwrap();
        peer
    });

    let reading = tokio::spawn({
        let console = console.clone();
        async move { console.read_rows(catalog).await }
    });
    reading_rx.await.unwrap();
    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT 1", true).await }
    });
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    console.cancel().await.unwrap();
    assert!(dials.try_recv().is_err(), "the cancel reached the catalog read");
    release_tx.send(()).unwrap();
    assert_eq!(reading.await.unwrap().unwrap(), vec![vec![Some("public".to_string())]]);
    assert!(matches!(running.await.unwrap().unwrap(), ConsoleRun::Canceled { .. }));
    let mut peer = fake.await.unwrap();
    assert!(
        read_frame(&mut peer).now_or_never().is_none(),
        "the canceled statement went out"
    );
}

#[tokio::test]
async fn a_cancel_while_the_run_waits_for_a_cancel_to_close_cancels_the_run() {
    let (dial, mut dials) = cancel_line();
    let (console, _ended, mut peer) = opened(dial).await;
    let (running_tx, running_rx) = oneshot::channel();
    let (cancel_read_tx, cancel_read_rx) = oneshot::channel();
    let (close_tx, close_rx) = oneshot::channel::<()>();
    let cancel_side = tokio::spawn(async move {
        let mut cancel = dials.recv().await.unwrap();
        assert_eq!(read_cancel_request(&mut cancel).await, (7, 11));
        cancel_read_tx.send(()).unwrap();
        close_rx.await.unwrap();
        drop(cancel);
        assert!(dials.try_recv().is_err(), "a second cancel was dialled");
    });
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("?column?", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT 1");
        running_tx.send(()).unwrap();
        cancel_read_rx.await.unwrap();
        peer.write_all(&rows_answer(&[("?column?", 23)], &one_row(), "SELECT 1"))
            .await
            .unwrap();
        peer
    });

    let first = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT 1", true).await }
    });
    running_rx.await.unwrap();
    console.cancel().await.unwrap();
    assert!(matches!(first.await.unwrap().unwrap(), ConsoleRun::Rows { row_count: 1, .. }));
    let second = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT 2", true).await }
    });
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(!second.is_finished(), "the run did not wait for the cancel connection to close");
    console.cancel().await.unwrap();
    close_tx.send(()).unwrap();
    assert!(matches!(second.await.unwrap().unwrap(), ConsoleRun::Canceled { .. }));
    cancel_side.await.unwrap();
    let mut peer = fake.await.unwrap();
    assert!(
        read_frame(&mut peer).now_or_never().is_none(),
        "the canceled statement went out"
    );
}

#[tokio::test(start_paused = true)]
async fn a_cancel_request_that_cannot_be_sent_keeps_the_session() {
    // The cancel connection takes one byte and then nothing more: the request never gets out.
    let (held_tx, held_rx) = oneshot::channel();
    let held = Arc::new(Mutex::new(Some(held_tx)));
    let dial: CancelDial = Arc::new(move || {
        let (client, server) = tokio::io::duplex(1);
        if let Some(held) = held.lock().unwrap().take() {
            let _ = held.send(server);
        }
        async move { Ok(Box::new(client) as BoxStream) }.boxed()
    });
    let (console, _ended, mut peer) = opened(dial).await;
    let (running_tx, running_rx) = oneshot::channel();
    let (answer_tx, answer_rx) = oneshot::channel::<()>();
    let fake = tokio::spawn(async move {
        answer_prepare(&mut peer, &[("?column?", 23)]).await;
        assert_eq!(expect_query(&mut peer).await, "SELECT pg_sleep(5)");
        running_tx.send(()).unwrap();
        answer_rx.await.unwrap();
        peer.write_all(&rows_answer(&[("?column?", 23)], &one_row(), "SELECT 1")).await.unwrap();
        peer
    });
    let running = tokio::spawn({
        let console = console.clone();
        async move { console.run("SELECT pg_sleep(5)", true).await }
    });
    running_rx.await.unwrap();
    let asked = tokio::time::Instant::now();
    assert_eq!(console.cancel().await.unwrap_err(), CANCEL_UNREACHABLE);
    assert!(asked.elapsed() >= CANCEL_WITHIN, "it gave up only after its bound");
    let _server_end = held_rx.await.unwrap();
    // The statement goes on and its answer comes back as rows: the session was not ended.
    answer_tx.send(()).unwrap();
    assert!(matches!(running.await.unwrap().unwrap(), ConsoleRun::Rows { row_count: 1, .. }));
    drop(fake.await.unwrap());
}

// ---- The cancel dial of an app's console ----

/// A connect that answers no material the first `without` times, then a stream.
fn connects(without: usize) -> (Arc<dyn Fn() -> Dialling + Send + Sync>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let connect = Arc::new(move || {
        let call = counted.fetch_add(1, Ordering::SeqCst);
        if call < without {
            return Dialling { material: None, stream: async { Err(io::Error::new(io::ErrorKind::NotFound, "no certificate")) }.boxed() };
        }
        let (client, _server) = tokio::io::duplex(64);
        Dialling { material: Some(1), stream: async move { Ok(Box::new(client) as BoxStream) }.boxed() }
    });
    (connect, calls)
}

#[tokio::test]
async fn a_cancel_dial_without_material_refreshes_it_and_dials_again() {
    let (connect, calls) = connects(1);
    let refreshed = Arc::new(AtomicUsize::new(0));
    let counted = refreshed.clone();
    let dial = dial_for_cancel(connect, Arc::new(move |_: &CancelToken| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }), CANCEL_WITHIN);
    assert!(dial().await.is_ok());
    assert_eq!((calls.load(Ordering::SeqCst), refreshed.load(Ordering::SeqCst)), (2, 1));
    // With material kept, nothing is refreshed.
    assert!(dial().await.is_ok());
    assert_eq!((calls.load(Ordering::SeqCst), refreshed.load(Ordering::SeqCst)), (3, 1));
}

#[tokio::test]
async fn a_cancel_dial_that_cannot_refresh_fails() {
    let (connect, calls) = connects(usize::MAX);
    let dial = dial_for_cancel(connect, Arc::new(|_: &CancelToken| Err(NotReady::Refused("A grant is needed.".into()))), CANCEL_WITHIN);
    assert!(dial().await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "nothing was dialled again");
}

#[tokio::test]
async fn a_cancel_dial_gives_up_within_its_bound_and_stops_the_refresh() {
    let (connect, _calls) = connects(usize::MAX);
    let stopped = Arc::new(AtomicBool::new(false));
    let seen = stopped.clone();
    // A refresh that waits behind a grant window another connection opened, until it is cancelled.
    let dial = dial_for_cancel(connect, Arc::new(move |cancel: &CancelToken| {
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while !cancel.is_cancelled() && std::time::Instant::now() < end {
            std::thread::sleep(Duration::from_millis(2));
        }
        seen.store(cancel.is_cancelled(), Ordering::SeqCst);
        Err(NotReady::Failed("cancelled".into()))
    }), Duration::from_millis(100));
    let started = std::time::Instant::now();
    let error = dial().await.err().expect("it gave up");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    let end = std::time::Instant::now() + Duration::from_secs(2);
    while !stopped.load(Ordering::SeqCst) && std::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(stopped.load(Ordering::SeqCst), "the refresh was cancelled");
}

// ---- The app's console sessions ----

const CLOSED_SENTENCE: &str = "This console is closed. Open it again from Databases.";
const LIMIT_SENTENCE: &str = "Close a tab before opening another (maximum 8).";

/// An upstream that dials nothing and records the databases it was told to release.
#[derive(Default)]
struct Releases(Mutex<Vec<String>>);

impl Releases {
    fn released(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

impl Upstream for Releases {
    fn prepare(&self, _: &crate::sync::databases::SavedDatabase, _: &CancelToken) -> Result<Prepared, NotReady> {
        Err(NotReady::Failed("No preparation is scripted.".into()))
    }

    fn connect(&self, _: &str, _: Option<u64>) -> Dialling {
        Dialling { material: None, stream: async { Err(io::Error::other("No dial is scripted.")) }.boxed() }
    }

    fn forget(&self, _: &str, _: u64) {}

    fn release(&self, db_id: &str) {
        self.0.lock().unwrap().push(db_id.to_string());
    }
}

/// An open session of the database `db-orders`, on a fresh fake, whose route `releases` records.
async fn session(releases: &Arc<Releases>) -> (Arc<ConsoleSession>, DuplexStream) {
    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let (open, ()) = tokio::join!(
        ConsoleConnection::open(Box::new(client), login(ReadOnlyMode::Locked), unreachable_dial()),
        async {
            accept_startup(&mut peer).await;
            answer_show(&mut peer, "cloudsql_session_read_only", "locked").await;
        }
    );
    let (connection, _, _) = open.unwrap();
    let upstream: Arc<dyn Upstream> = releases.clone();
    (Arc::new(ConsoleSession { connection, upstream, db_id: "db-orders".into() }), peer)
}

#[tokio::test]
async fn closing_an_opening_session_cancels_it() {
    let consoles = Consoles::default();
    let releases = Arc::new(Releases::default());
    let (ticket, cancel) = consoles.begin("t1").unwrap();
    assert!(!cancel.is_cancelled());
    consoles.close("t1");
    assert!(cancel.is_cancelled(), "the open was cancelled");
    // Its open finishes late: the session is not kept, and its route is released.
    let (late, _peer) = session(&releases).await;
    assert!(!consoles.finish("t1", ticket, late));
    assert_eq!(consoles.get("t1").err().as_deref(), Some(CLOSED_SENTENCE));
    assert_eq!(releases.released(), vec!["db-orders".to_string()]);
}

#[tokio::test]
async fn an_open_after_close_all_is_dropped() {
    let consoles = Consoles::default();
    let releases = Arc::new(Releases::default());
    let (open_ticket, _) = consoles.begin("t1").unwrap();
    let (open, _open_peer) = session(&releases).await;
    assert!(consoles.finish("t1", open_ticket, open));
    let (ticket, cancel) = consoles.begin("t2").unwrap();
    consoles.close_all();
    assert!(cancel.is_cancelled());
    assert_eq!(releases.released().len(), 1, "the open session was dropped");
    let (late, _peer) = session(&releases).await;
    assert!(!consoles.finish("t2", ticket, late));
    assert_eq!(consoles.get("t2").err().as_deref(), Some(CLOSED_SENTENCE));
    assert_eq!(consoles.get("t1").err().as_deref(), Some(CLOSED_SENTENCE));
    assert_eq!(releases.released().len(), 2);
}

#[tokio::test]
async fn a_ninth_session_is_refused() {
    let consoles = Consoles::default();
    let tickets: Vec<Ticket> = (1..=8).map(|n| consoles.begin(&format!("t{n}")).unwrap().0).collect();
    assert_eq!(consoles.begin("t9").err().as_deref(), Some(LIMIT_SENTENCE));
    // A tab that opens again counts once.
    assert!(consoles.begin("t1").is_ok());
    // A failed open frees its place; a stale ticket frees nothing.
    consoles.abandon("t1", tickets[0]);
    assert_eq!(consoles.begin("t9").err().as_deref(), Some(LIMIT_SENTENCE));
    consoles.abandon("t2", tickets[1]);
    assert!(consoles.begin("t9").is_ok());
}

#[tokio::test]
async fn a_reopened_id_ignores_the_first_open() {
    let consoles = Consoles::default();
    let releases = Arc::new(Releases::default());
    let (first, _) = consoles.begin("t1").unwrap();
    consoles.close("t1");
    let (second, _) = consoles.begin("t1").unwrap();
    assert_ne!(first, second);
    let (s1, _peer1) = session(&releases).await;
    let (s2, _peer2) = session(&releases).await;
    assert!(!consoles.finish("t1", first, s1));
    assert!(consoles.finish("t1", second, s2.clone()));
    assert!(Arc::ptr_eq(&consoles.get("t1").unwrap(), &s2));
    // The same holds without a close in between, as React StrictMode opens a tab twice.
    let (third, _) = consoles.begin("t2").unwrap();
    let (fourth, _) = consoles.begin("t2").unwrap();
    let (s3, _peer3) = session(&releases).await;
    let (s4, _peer4) = session(&releases).await;
    assert!(!consoles.finish("t2", third, s3));
    assert!(consoles.finish("t2", fourth, s4.clone()));
    assert!(Arc::ptr_eq(&consoles.get("t2").unwrap(), &s4));
}

#[tokio::test]
async fn closing_a_session_releases_its_route() {
    let consoles = Consoles::default();
    let releases = Arc::new(Releases::default());
    let (ticket, _) = consoles.begin("t1").unwrap();
    let (open, _peer) = session(&releases).await;
    assert!(consoles.finish("t1", ticket, open));
    assert!(consoles.get("t1").is_ok());
    assert!(releases.released().is_empty());
    consoles.close("t1");
    assert_eq!(releases.released(), vec!["db-orders".to_string()]);
    assert_eq!(consoles.get("t1").err().as_deref(), Some(CLOSED_SENTENCE));
    consoles.close("t1");
    consoles.close_all();
    assert_eq!(releases.released().len(), 1, "released once");
}
