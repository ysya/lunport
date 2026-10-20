//! The WebView's terminal is a protocol-1 broker client, just like the CLI. SSH,
//! native authentication, host-key checks and app shutdown remain broker-owned.
//! Only the main WebView can open/control these sessions. No shell command API.
use super::protocol::{
    self, ClientKind, ClientMessage, Frame, HostQuery, PtyRequest, ServerMessage,
};
use crate::{ipc::server::Stream, state::AppState};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};
use tauri::{
    ipc::{Channel, Response},
    Manager,
};
use zeroize::Zeroizing;

const MAX_SESSIONS: usize = 8;
const INPUT_CHUNK: usize = 16 * 1024;
const OUTPUT_WINDOW: u64 = 256 * 1024;
const ACK_TIMEOUT: Duration = Duration::from_secs(15);
type Sink = Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>;

#[derive(Default)]
pub struct Terminals {
    entries: Mutex<HashMap<String, Arc<Terminal>>>,
    generation: AtomicU64,
}
enum Input {
    Data(Zeroizing<Vec<u8>>),
    Resize(u16, u16),
}
#[derive(Default)]
struct Flow {
    sent: u64,
    acked: u64,
}
struct Terminal {
    input: mpsc::SyncSender<Input>,
    closer: Stream,
    closed: AtomicBool,
    flow: Mutex<Flow>,
    changed: Condvar,
}
impl Terminal {
    fn stop(&self) {
        self.closed.store(true, Ordering::Release);
        self.changed.notify_all();
        #[cfg(unix)]
        let _ = self.closer.shutdown(std::net::Shutdown::Both);
        #[cfg(windows)]
        self.closer.hang_up();
    }
    fn reserve(&self, bytes: usize) -> Result<(), String> {
        let deadline = Instant::now() + ACK_TIMEOUT;
        let mut flow = self.flow.lock().unwrap();
        while flow.sent - flow.acked + bytes as u64 > OUTPUT_WINDOW {
            if self.closed.load(Ordering::Acquire) {
                return Err("Terminal closed".into());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(
                    "Terminal stopped consuming output. Reconnect to start a new shell.".into(),
                );
            }
            flow = self.changed.wait_timeout(flow, remaining).unwrap().0;
        }
        flow.sent += bytes as u64;
        Ok(())
    }
    fn acknowledge(&self, total: u64) -> Result<(), String> {
        let mut flow = self.flow.lock().unwrap();
        if total < flow.acked || total > flow.sent {
            return Err("Invalid terminal acknowledgement".into());
        }
        flow.acked = total;
        self.changed.notify_all();
        Ok(())
    }
}
impl Terminals {
    pub fn close_all(&self) {
        let entries = self.entries.lock().unwrap();
        self.generation.fetch_add(1, Ordering::AcqRel);
        for terminal in entries.values() {
            terminal.stop();
        }
    }
    fn get(&self, id: &str) -> Result<Arc<Terminal>, String> {
        self.entries
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| "Terminal session has ended".into())
    }
    fn close(&self, id: &str) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(terminal) = entries.remove(id) {
            terminal.stop();
        }
    }
    fn forget(&self, id: &str, owner: &Arc<Terminal>) {
        let mut entries = self.entries.lock().unwrap();
        if entries
            .get(id)
            .is_some_and(|current| Arc::ptr_eq(current, owner))
        {
            entries.remove(id);
        }
    }
    fn open(
        self: &Arc<Self>,
        id: String,
        host: HostQuery,
        cols: u16,
        rows: u16,
        mut stream: Stream,
        sink: Sink,
        generation: u64,
    ) -> Result<(), String> {
        if id.is_empty()
            || id.len() > 64
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid terminal ID".into());
        }
        let mut entries = self.entries.lock().unwrap();
        if generation != self.generation.load(Ordering::Acquire) {
            return Err("The workspace was reloaded before this terminal opened".into());
        }
        if entries.len() >= MAX_SESSIONS || entries.contains_key(&id) {
            return Err("Close a terminal before opening another (maximum 8).".into());
        }
        let (sender, receiver) = mpsc::sync_channel(32);
        let terminal = Arc::new(Terminal {
            input: sender,
            closer: stream.try_clone().map_err(|e| e.to_string())?,
            closed: AtomicBool::new(false),
            flow: Mutex::new(Flow::default()),
            changed: Condvar::new(),
        });
        let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
        #[cfg(unix)]
        writer
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        protocol::write_control(
            &mut writer,
            &ClientMessage::Hello {
                client: ClientKind::Connect,
                version: protocol::PROTOCOL_VERSION,
                client_info: None,
            },
        )
        .map_err(|e| e.to_string())?;
        protocol::write_control(
            &mut writer,
            &ClientMessage::OpenShell {
                host,
                pty: PtyRequest {
                    cols,
                    rows,
                    term: "xterm-256color".into(),
                },
            },
        )
        .map_err(|e| e.to_string())?;
        entries.insert(id.clone(), Arc::clone(&terminal));
        drop(entries);
        let input_owner = Arc::clone(&terminal);
        let input_sink = Arc::clone(&sink);
        if let Err(error) = std::thread::Builder::new().name("embedded-terminal-input".into()).spawn(move || {
            while !input_owner.closed.load(Ordering::Acquire) {
                let input = match receiver.recv_timeout(Duration::from_millis(250)) {
                    Ok(input) => input,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(_) => break,
                };
                let result = match input {
                    Input::Data(bytes) => protocol::write_data(&mut writer, &bytes),
                    Input::Resize(cols, rows) => protocol::write_control(&mut writer, &ClientMessage::WindowChange { cols, rows }),
                };
                if result.is_err() {
                    let _ = control(&input_sink, serde_json::json!({"type":"bridge_error","text":"Input could not reach the SSH session. Reconnect before continuing."}));
                    input_owner.stop();
                    break;
                }
            }
        }) {
            terminal.stop(); self.entries.lock().unwrap().remove(&id); return Err(error.to_string());
        }
        let registry = Arc::clone(self);
        let reader_id = id.clone();
        let reader_owner = Arc::clone(&terminal);
        let result = std::thread::Builder::new()
            .name("embedded-terminal-output".into())
            .spawn(move || {
                let result = relay_output(&mut stream, &reader_owner, &sink);
                if let Err(text) = result {
                    if !reader_owner.closed.load(Ordering::Acquire) {
                        let _ = control(
                            &sink,
                            serde_json::json!({"type":"bridge_error","text":text}),
                        );
                    }
                }
                let _ = control(&sink, serde_json::json!({"type":"closed"}));
                reader_owner.stop();
                registry.forget(&reader_id, &reader_owner);
            });
        if let Err(error) = result {
            terminal.stop();
            self.entries.lock().unwrap().remove(&id);
            return Err(error.to_string());
        }
        Ok(())
    }
}
// One ordered binary channel: 0 = raw terminal bytes, 1 = JSON lifecycle event.
// Keeping both on one channel preserves the final output before Exited/closed.
fn control(sink: &Sink, event: serde_json::Value) -> Result<(), String> {
    let mut packet = vec![1];
    packet.extend(serde_json::to_vec(&event).map_err(|e| e.to_string())?);
    sink(packet)
}
fn relay_output(
    reader: &mut impl std::io::Read,
    terminal: &Terminal,
    sink: &Sink,
) -> Result<(), String> {
    while let Some(frame) = protocol::read_frame(reader)
        .map_err(|_| "The SSH terminal transport ended unexpectedly".to_string())?
    {
        match frame {
            Frame::Data(bytes) => {
                // Bound every WebView message, even if a future broker emits larger frames.
                for chunk in bytes.chunks(protocol::DATA_CHUNK) {
                    terminal.reserve(chunk.len())?;
                    let mut packet = Vec::with_capacity(chunk.len() + 1);
                    packet.push(0);
                    packet.extend_from_slice(chunk);
                    sink(packet)?;
                }
            }
            Frame::Control(bytes) => {
                let message: ServerMessage = protocol::decode(&bytes)?;
                control(
                    sink,
                    serde_json::to_value(message).map_err(|e| e.to_string())?,
                )?;
            }
        }
    }
    Ok(())
}
fn main_only(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() != "main" {
        return Err("Terminal sessions belong to the main workspace".into());
    }
    Ok(())
}
fn dimensions(cols: u16, rows: u16) -> Result<(), String> {
    if cols == 0 || rows == 0 || cols > 1000 || rows > 500 {
        return Err("Invalid terminal dimensions".into());
    }
    Ok(())
}
#[tauri::command]
pub async fn terminal_open(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: String,
    host: HostQuery,
    cols: u16,
    rows: u16,
    output: Channel<Response>,
) -> Result<(), String> {
    main_only(&window)?;
    dimensions(cols, rows)?;
    let generation = app
        .state::<AppState>()
        .session
        .embedded
        .generation
        .load(Ordering::Acquire);
    tauri::async_runtime::spawn_blocking(move || {
        super::app::start(&app);
        let state = app.state::<AppState>();
        if !matches!(
            *state.session.status.lock().unwrap(),
            super::app::BrokerStatus::Running
        ) {
            return Err(
                "Could not start the SSH service. Quit other Lunport instances and try again."
                    .into(),
            );
        }
        #[cfg(unix)]
        let stream = Stream::connect(super::socket_path(
            &crate::fsutil::app_data_root().map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let stream = crate::ipc::pipe_windows::connect(
            &super::pipe_name().map_err(|e| e.to_string())?,
            Duration::from_secs(5),
        )
        .map_err(|e| e.to_string())?;
        state.session.embedded.open(
            id,
            host,
            cols,
            rows,
            stream,
            Arc::new(move |bytes| output.send(Response::new(bytes)).map_err(|e| e.to_string())),
            generation,
        )
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub fn terminal_write(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    main_only(&window)?;
    let data = Zeroizing::new(data);
    if data.len() > INPUT_CHUNK {
        return Err("Terminal input chunk is too large".into());
    }
    let terminal = app.state::<AppState>().session.embedded.get(&id)?;
    if terminal.closed.load(Ordering::Acquire) {
        return Err("Terminal session has ended".into());
    }
    terminal
        .input
        .try_send(Input::Data(data))
        .map_err(|_| "Terminal input is busy; reconnect before continuing".into())
}
#[tauri::command]
pub fn terminal_resize(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    main_only(&window)?;
    dimensions(cols, rows)?;
    app.state::<AppState>()
        .session
        .embedded
        .get(&id)?
        .input
        .try_send(Input::Resize(cols, rows))
        .map_err(|_| "Terminal input is busy".into())
}
#[tauri::command]
pub fn terminal_ack(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: String,
    total: u64,
) -> Result<(), String> {
    main_only(&window)?;
    app.state::<AppState>()
        .session
        .embedded
        .get(&id)?
        .acknowledge(total)
}
#[tauri::command]
pub fn terminal_close(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: String,
) -> Result<(), String> {
    main_only(&window)?;
    app.state::<AppState>().session.embedded.close(&id);
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    fn terminal() -> Terminal {
        let (stream, _) = UnixStream::pair().unwrap();
        Terminal {
            input: mpsc::sync_channel(1).0,
            closer: stream,
            closed: AtomicBool::new(false),
            flow: Mutex::new(Flow::default()),
            changed: Condvar::new(),
        }
    }
    #[test]
    fn a_pending_open_cannot_leak_a_session_after_workspace_reload() {
        let registry = Arc::new(Terminals::default());
        let generation = registry.generation.load(Ordering::Acquire);
        registry.close_all();
        let (client, _peer) = UnixStream::pair().unwrap();
        let sink: Sink = Arc::new(|_| Ok(()));
        let error = registry
            .open(
                "old-page".into(),
                HostQuery::Alias("web".into()),
                80,
                24,
                client,
                sink,
                generation,
            )
            .unwrap_err();
        assert!(error.contains("reloaded"));
        assert!(registry.entries.lock().unwrap().is_empty());
    }
    #[test]
    fn reconnect_releases_its_slot_before_the_old_reader_finishes() {
        let registry = Arc::new(Terminals::default());
        for index in 0..MAX_SESSIONS {
            registry
                .entries
                .lock()
                .unwrap()
                .insert(index.to_string(), Arc::new(terminal()));
        }
        let old = registry.get("0").unwrap();
        registry.close("0");
        assert!(old.closed.load(Ordering::Acquire));
        let (client, _peer) = UnixStream::pair().unwrap();
        registry
            .open(
                "0".into(),
                HostQuery::Alias("web".into()),
                80,
                24,
                client,
                Arc::new(|_| Ok(())),
                0,
            )
            .unwrap();
        assert_eq!(registry.entries.lock().unwrap().len(), MAX_SESSIONS);
        registry.forget("0", &old);
        assert!(
            registry.get("0").is_ok(),
            "old cleanup must not remove the replacement"
        );
        registry.close_all();
    }
    #[test]
    fn output_budget_requires_consumption_and_close_wakes_a_blocked_reader() {
        let terminal = Arc::new(terminal());
        terminal.reserve(OUTPUT_WINDOW as usize).unwrap();
        assert!(terminal.acknowledge(OUTPUT_WINDOW + 1).is_err());
        terminal.acknowledge(10).unwrap();
        assert!(terminal.acknowledge(9).is_err());
        terminal.reserve(10).unwrap();
        let waiting = Arc::clone(&terminal);
        let thread = std::thread::spawn(move || waiting.reserve(1));
        terminal.stop();
        assert!(thread.join().unwrap().is_err());
    }
    #[test]
    fn raw_bytes_and_final_exit_share_one_ordered_channel() {
        let terminal = terminal();
        let mut frames = Vec::new();
        protocol::write_data(&mut frames, &[0x1b, 0xe4, 0xb8]).unwrap();
        protocol::write_data(&mut frames, &[0xad, 0xff]).unwrap();
        protocol::write_control(
            &mut frames,
            &ServerMessage::Exited {
                code: Some(7),
                signal: None,
            },
        )
        .unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::clone(&output);
        let sink: Sink = Arc::new(move |bytes| {
            received.lock().unwrap().push(bytes);
            Ok(())
        });
        relay_output(&mut frames.as_slice(), &terminal, &sink).unwrap();
        let packets = output.lock().unwrap();
        assert_eq!(packets[0], [0, 0x1b, 0xe4, 0xb8]);
        assert_eq!(packets[1], [0, 0xad, 0xff]);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&packets[2][1..]).unwrap()["code"],
            7
        );
    }
    #[test]
    fn real_ssh_shell_input_resize_output_and_exit() {
        real_shell(HostQuery::Id("id-preview".into()));
    }
    #[test]
    fn real_ssh_shell_accepts_legacy_alias_queries() {
        real_shell(HostQuery::Alias("preview".into()));
    }
    fn real_shell(host: HostQuery) {
        use crate::{
            session::{
                broker::Broker,
                testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys},
            },
            ssh::{
                russh_engine::RusshEngine,
                testing::{fixture::Server, harness},
                AuthMethod, Hop,
            },
            sync::testkit::MemKeychain,
        };
        let Some(tools) = harness::tools() else {
            return;
        };
        let server = Server::start(&tools, &[crate::ssh::testing::fixture::SH_SHELL]);
        let directory = FakeDirectory::new()
            .with_hop(Hop::new(
                "id-preview",
                "preview",
                "127.0.0.1",
                server.sshd.port,
                &server.sshd.user,
                AuthMethod::Key {
                    key_id: "preview-key".into(),
                },
            ))
            .with_pin("preview", server.host_key());
        let broker = Broker::new(
            Arc::new(RusshEngine::new()),
            Arc::new(directory),
            Arc::new(FakeKeys::new().with_key("preview-key", "preview", &server.key.private_text)),
            Arc::new(MemKeychain::default()),
            Arc::new(FakeConfirmer::deciding(vec![Decision::Trust])),
        );
        let (client, peer) = UnixStream::pair().unwrap();
        let broker_thread = {
            let broker = Arc::clone(&broker);
            std::thread::spawn(move || broker.serve(peer, Some(std::process::id())))
        };
        let registry = Arc::new(Terminals::default());
        let (output, received) = mpsc::channel();
        registry
            .open(
                "test-preview".into(),
                host,
                100,
                35,
                client,
                Arc::new(move |bytes| output.send(bytes).map_err(|e| e.to_string())),
                0,
            )
            .unwrap();
        let mut bytes = Vec::new();
        let mut ack = 0;
        let mut issued = false;
        let mut opened = false;
        let mut exit_code = None;
        loop {
            let packet = received.recv_timeout(Duration::from_secs(15)).unwrap_or_else(|error| panic!("SSH preview output: {error}; opened={issued}, exit={exit_code:?}, output={:?}", String::from_utf8_lossy(&bytes)));
            if packet[0] == 0 {
                bytes.extend_from_slice(&packet[1..]);
                ack += (packet.len() - 1) as u64;
                if let Ok(terminal) = registry.get("test-preview") {
                    let _ = terminal.acknowledge(ack);
                }
                // Wait for the shell's line editor, not merely SSH's shell-request reply.
                if opened && !issued && bytes.windows(2).any(|pair| pair == b"$ ") {
                    let terminal = registry.get("test-preview").unwrap();
                    terminal.input.send(Input::Resize(117, 52)).unwrap();
                    terminal.input.send(Input::Data(Zeroizing::new(b"printf '\\033[32mLUNPORT_\\351\\200\\243\\347\\267\\232\\346\\210\\220\\345\\212\\237\\033[0m\\n'; stty size; exit 7\r".to_vec()))).unwrap();
                    issued = true;
                }
            } else {
                let event: serde_json::Value = serde_json::from_slice(&packet[1..]).unwrap();
                match event["type"].as_str().unwrap() {
                    "opened" => opened = true,
                    "exited" => exit_code = event["code"].as_u64(),
                    "closed" => break,
                    "bridge_error" => panic!("{event}"),
                    _ => {}
                }
            }
        }
        assert!(issued);
        assert_eq!(exit_code, Some(7));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\x1b[32mLUNPORT_連線成功\x1b[0m"), "{text:?}");
        assert!(text.contains("52 117"), "remote PTY resized: {text:?}");
        broker_thread.join().unwrap();
        crate::ssh::testing::eventually("preview registry cleaned", 3, || {
            registry.entries.lock().unwrap().is_empty()
        });
        assert!(!broker.has_sessions());
    }
}
