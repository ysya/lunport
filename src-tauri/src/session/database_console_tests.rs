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

#[tokio::test]
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
    assert!(!message.is_empty());
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
