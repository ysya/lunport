//! Task 3e, part 2: "every channel has a reader". The spec (§6.3) says russh stalls the whole connection behind a channel nobody reads, and that
//! the maintainer declined to change it. The first test is the discipline that works; the second measures what really happens without it.

use std::time::Duration;

use russh::ChannelMsg;
use russh_spike::client::exec;
use russh_spike::fixture::Server;
use russh_spike::harness::tools;
use russh_spike::{fact, within};

/// A second channel works while the first one prints without end, as long as something reads the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_channel_works_while_the_first_is_drained_in_the_background() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let connection = server.session().await;

    let mut busy = connection.handle.channel_open_session().await.unwrap();
    busy.exec(true, "yes spike").await.unwrap();
    let reader = tokio::spawn(async move {
        let mut bytes = 0usize;
        while let Some(message) = busy.wait().await {
            if let ChannelMsg::Data { data } = message {
                bytes += data.len();
            }
        }
        bytes
    });

    let out = within(20, "exec next to a busy channel", exec(&connection.handle, "echo alive")).await.unwrap();
    assert_eq!(out.text(), "alive\n");
    reader.abort();
}

/// A fact, not a requirement: the same, but nobody reads the busy channel. Does the neighbour still get its answer within 8 seconds,
/// and what happens to the busy one once somebody starts reading?
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an observation for the report: run with --ignored --nocapture"]
async fn observe_an_unread_channel_next_to_a_working_one() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let connection = server.session().await;

    let mut unread = connection.handle.channel_open_session().await.unwrap();
    unread.exec(true, "yes spike").await.unwrap();
    // Give the server time to fill russh's window and queue for the unread channel.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let neighbour = tokio::time::timeout(Duration::from_secs(8), exec(&connection.handle, "echo alive")).await;
    fact("channels.unread_neighbour.answered_within_8s", neighbour.is_ok());

    let mut resumed = 0usize;
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(message) = unread.wait().await {
            if let ChannelMsg::Data { data } = message {
                resumed += data.len();
            }
        }
    })
    .await;
    fact("channels.unread_neighbour.bytes_read_once_a_reader_started", resumed);
}
