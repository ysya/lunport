//! The local IPC protocol between the broker and its clients (own-ssh spec §7.1). A frame is `u32 length | u8 type | payload`, the
//! length big-endian and counting the type byte and the payload. A control frame (`CONTROL`) carries one JSON message; a data frame
//! (`DATA`) carries raw bytes: keystrokes from the client, terminal output (stdout and stderr merged by the PTY) from the broker.
//!
//! This version speaks the shell subset: client → broker `hello`, `open_shell`, `window_change`, `answer`, `close` and data; broker →
//! client `opened`, `question`, `event`, `exited` and data. `exec` and the MCP client are phase 2: they are read, so that the broker can
//! refuse them by name. Both sides are this same executable, but after an update the CLI on disk can be newer than the app that is
//! running, so `hello` carries `PROTOCOL_VERSION`.

use std::fmt;
use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The version of this protocol; `hello` carries it, and the broker refuses another.
pub const PROTOCOL_VERSION: u32 = 1;
/// MCP uses version 2; version 1 Connect keeps its original framing.
pub const MCP_PROTOCOL_VERSION: u32 = 2;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpClientMessage { McpCall { method:String, #[serde(default)] params:serde_json::Value }, Close }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpServerMessage { McpResult { result:Option<serde_json::Value>, error:Option<String> } }

/// A frame whose payload is one JSON message.
pub const CONTROL: u8 = 1;
/// A frame whose payload is raw bytes.
pub const DATA: u8 = 2;
/// The largest frame (type byte and payload) either side sends or reads: 1 MiB. A length beyond it ends the connection.
pub const MAX_FRAME: usize = 1 << 20;
/// Terminal output and keystrokes travel in data frames of at most this many bytes.
pub const DATA_CHUNK: usize = 32 * 1024;

/// One frame as read. The payload is zeroed when the frame is dropped: an `answer` carries a password, and keystrokes can be one too.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Control(Zeroizing<Vec<u8>>),
    Data(Zeroizing<Vec<u8>>),
}

/// Why a frame could not be read. Every one of them ends the connection: the stream is out of step and nothing after it can be trusted.
#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    /// The length says more than `MAX_FRAME`.
    TooLarge(usize),
    UnknownType(u8),
    /// A length of 0: not even a type byte.
    Empty,
    /// The stream ended inside a frame.
    Truncated,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Io(error) => write!(f, "the connection failed: {error}"),
            FrameError::TooLarge(length) => write!(f, "a frame of {length} bytes is larger than the limit of {MAX_FRAME}"),
            FrameError::UnknownType(kind) => write!(f, "a frame of an unknown type ({kind})"),
            FrameError::Empty => write!(f, "an empty frame"),
            FrameError::Truncated => write!(f, "the connection ended in the middle of a frame"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Fills `buf` from `reader`. `Ok(false)` when the stream ended before the first byte; the end of the stream after that is `Truncated`.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool, FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FrameError::Io(error)),
        }
    }
    Ok(true)
}

/// Reads one frame. `Ok(None)`: the other side closed the stream cleanly, between two frames.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Frame>, FrameError> {
    let mut header = [0u8; 4];
    if !read_full(reader, &mut header)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > MAX_FRAME {
        return Err(FrameError::TooLarge(length));
    }
    let mut kind = [0u8; 1];
    if !read_full(reader, &mut kind)? {
        return Err(FrameError::Truncated);
    }
    let mut payload = Zeroizing::new(vec![0u8; length - 1]);
    if !payload.is_empty() && !read_full(reader, &mut payload)? {
        return Err(FrameError::Truncated);
    }
    match kind[0] {
        CONTROL => Ok(Some(Frame::Control(payload))),
        DATA => Ok(Some(Frame::Data(payload))),
        other => Err(FrameError::UnknownType(other)),
    }
}

/// Writes one frame in one `write_all`, so that a frame is never interleaved with another writer's (the writers share a lock anyway).
pub fn write_frame(writer: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() + 1 > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("a frame of {} bytes is larger than the limit of {MAX_FRAME}", payload.len() + 1)));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(payload.len() + 5));
    frame.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(payload);
    writer.write_all(&frame)?;
    writer.flush()
}

/// Writes one control message.
pub fn write_control<T: Serialize>(writer: &mut impl Write, message: &T) -> io::Result<()> {
    let json = Zeroizing::new(serde_json::to_vec(message).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?);
    write_frame(writer, CONTROL, &json)
}

/// Writes raw bytes in one data frame (`bytes` must fit in `MAX_FRAME`; senders split at `DATA_CHUNK`).
pub fn write_data(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    write_frame(writer, DATA, bytes)
}

/// Reads a control message. The error text never quotes the payload: serde's messages can include the value it choked on, and an
/// `answer` carries a password.
pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T, String> {
    serde_json::from_slice(payload).map_err(|_| "a control message Lunport does not understand".to_string())
}

/// Who is connecting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// `sshelter connect`.
    Connect,
    /// The MCP adapter (phase 2).
    Mcp,
}

/// Which saved host: by alias, or by host id (spec §7.1; an alias that several hosts share is refused, and the client is told to use the id).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostQuery {
    Alias(String),
    Id(String),
}

impl fmt::Display for HostQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostQuery::Alias(alias) => f.write_str(alias),
            HostQuery::Id(id) => write!(f, "the host with the id {id}"),
        }
    }
}

/// The terminal a shell is opened for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyRequest {
    pub cols: u16,
    pub rows: u16,
    /// `$TERM` of the client's terminal.
    pub term: String,
}

/// A message from a client.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// The first message on a connection. `client_info` is what an MCP client says about itself (phase 2).
    Hello {
        client: ClientKind,
        version: u32,
        #[serde(default)]
        client_info: Option<serde_json::Value>,
    },
    OpenShell { host: HostQuery, pty: PtyRequest },
    /// A command without a terminal (phase 2). Read so that it can be refused by name; its fields are not looked at.
    Exec {},
    /// The client's terminal was resized.
    WindowChange { cols: u16, rows: u16 },
    /// The answer to a `question`: `value`, or `cancel` (the person pressed Ctrl-C or Ctrl-D).
    Answer {
        question_id: String,
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        cancel: bool,
    },
    /// The client is leaving: end the session.
    Close,
    /// A message type this version does not know.
    #[serde(other)]
    Unknown,
}

/// An answer's value can be a password, so the debug form leaves it out.
impl fmt::Debug for ClientMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientMessage::Hello { client, version, client_info } => {
                f.debug_struct("Hello").field("client", client).field("version", version).field("client_info", client_info).finish()
            }
            ClientMessage::OpenShell { host, pty } => f.debug_struct("OpenShell").field("host", host).field("pty", pty).finish(),
            ClientMessage::Exec {} => f.write_str("Exec"),
            ClientMessage::WindowChange { cols, rows } => f.debug_struct("WindowChange").field("cols", cols).field("rows", rows).finish(),
            ClientMessage::Answer { question_id, value, cancel } => f
                .debug_struct("Answer")
                .field("question_id", question_id)
                .field("value", &value.as_ref().map(|_| "<hidden>"))
                .field("cancel", cancel)
                .finish(),
            ClientMessage::Close => f.write_str("Close"),
            ClientMessage::Unknown => f.write_str("Unknown"),
        }
    }
}

/// What a question asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionKind {
    /// Not a question: the host key is being confirmed in the app's window (spec §7.2); the client shows the text and sends no answer.
    HostKeyNotice,
    Passphrase,
    Password,
    Interactive,
    /// Lunport's own question (design 2026-10-25, PAM grant requests): `text` is a `GrantPrompt` as JSON, the answer a `GrantAnswer`
    /// as encoded. It is answered in the app's window, never typed at a terminal.
    Grant,
}

/// A question for the person at the client's terminal (spec §7.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Question {
    pub question_id: String,
    pub kind: QuestionKind,
    pub text: String,
    /// Whether what the person types may be shown.
    pub echo: bool,
    /// Milliseconds the answer is waited for, from when the question was sent; `None` for a notice. A later answer is not used: the login
    /// has been abandoned by then.
    pub deadline_ms: Option<u64>,
}

/// What a `QuestionKind::Grant` question asks about: the grant a connection needs, with the length and justification to prefill the
/// window (what this computer last asked for on the host, else the route's default length and no justification). It travels as the
/// question's `text` (JSON) and, with the `kind` word `grant`, in `AuthRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct GrantPrompt {
    pub project: String,
    pub entitlement: String,
    pub minutes: u32,
    pub justification: Option<String>,
}

impl GrantPrompt {
    pub fn to_text(&self) -> String {
        serde_json::to_string(self).expect("a grant prompt is plain data")
    }

    pub fn from_text(text: &str) -> Option<GrantPrompt> {
        serde_json::from_str(text).ok()
    }

    /// The sentence the window shows above the form.
    pub fn sentence(&self) -> String {
        format!("No active Privileged Access Manager grant for {} on {}.", self.entitlement, self.project)
    }
}

/// The longest grant the window lets a person ask for, in minutes, and the longest justification: the limits of the grant memory
/// (`sync::transports`), so that what the person answers can always be remembered on this computer.
pub const MAX_GRANT_MINUTES: u32 = 480;
pub const MAX_GRANT_JUSTIFICATION_CHARS: usize = 512;

/// The answer to a `QuestionKind::Grant` question: both fields of the form, encoded as `<minutes>\n<justification>` so that they travel in
/// the one answer string the question channel carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantAnswer {
    pub minutes: u32,
    pub justification: String,
}

impl GrantAnswer {
    /// The window encodes (`mcp-flow.ts`); the broker only decodes. Tests build answers with this.
    #[cfg(test)]
    pub fn encode(&self) -> String {
        format!("{}\n{}", self.minutes, self.justification)
    }

    /// `None` for anything but a whole number of minutes from 1 to `MAX_GRANT_MINUTES` and a justification with something in it, of
    /// one line and at most `MAX_GRANT_JUSTIFICATION_CHARS`.
    pub fn decode(text: &str) -> Option<GrantAnswer> {
        let (minutes, justification) = text.split_once('\n')?;
        let minutes: u32 = minutes.trim().parse().ok()?;
        if !(1..=MAX_GRANT_MINUTES).contains(&minutes) {
            return None;
        }
        let justification = justification.trim();
        if justification.is_empty() || justification.chars().count() > MAX_GRANT_JUSTIFICATION_CHARS || justification.chars().any(char::is_control) {
            return None;
        }
        Some(GrantAnswer { minutes, justification: justification.to_string() })
    }
}

/// Something that happened, for the client to show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Connected,
    /// The connection ended without the shell reporting how; `reason` is the sentence to show (spec §11).
    Disconnected { reason: String },
    /// Something failed; `text` is the sentence to show (spec §11), `kind` a short word for programs (`kinds`).
    Error { kind: String, text: String },
    /// The server's banner, with control characters already replaced.
    Banner { text: String },
}

/// The `kind` words of `Event::Error`.
pub mod kinds {
    /// A frame or message the broker cannot read, or a protocol version it does not speak.
    pub const PROTOCOL: &str = "protocol";
    /// Something this version does not do yet (exec, MCP clients).
    pub const UNSUPPORTED: &str = "unsupported";
    /// The saved host could not be found or used.
    pub const HOST: &str = "host";
    /// The host key was not confirmed, or changed and was refused.
    pub const HOST_KEY: &str = "host_key";
    /// Login failed or was abandoned.
    pub const AUTH: &str = "auth";
    /// The host could not be reached, or another connection failure.
    pub const CONNECT: &str = "connect";
    /// The shell could not be started.
    pub const SHELL: &str = "shell";
    /// Input did not reach the server in time.
    pub const INPUT: &str = "input";
}

/// A message from the broker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The shell is open: raw mode and data from here on.
    Opened { session_id: String },
    Question(Question),
    Event(Event),
    /// The shell ended: its exit code, or the signal that killed it; both `None` when it ended without either (a lost connection, which
    /// an `event{disconnected}` explains). Never a disconnect reported as 0.
    Exited { code: Option<u32>, signal: Option<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames_of(bytes: &[u8]) -> Vec<Result<Option<Frame>, String>> {
        let mut reader = bytes;
        let mut all = Vec::new();
        loop {
            let next = read_frame(&mut reader).map_err(|error| error.to_string());
            let end = !matches!(next, Ok(Some(_)));
            all.push(next);
            if end {
                return all;
            }
        }
    }

    #[test]
    fn a_grant_answer_round_trips_and_rejects_nonsense() {
        let answer = GrantAnswer { minutes: 30, justification: "restart app-api".into() };
        assert_eq!(answer.encode(), "30\nrestart app-api");
        assert_eq!(GrantAnswer::decode("30\nrestart app-api"), Some(answer.clone()));
        assert_eq!(GrantAnswer::decode(" 30\n  restart app-api \n"), Some(answer), "both fields are trimmed");
        assert_eq!(GrantAnswer::decode("480\nlong"), Some(GrantAnswer { minutes: 480, justification: "long".into() }));
        let long = format!("30\n{}", "x".repeat(513));
        for nonsense in ["0\nx", "481\nx", "30\n", "30\n   ", "thirty", "", "30", "-5\nx", "1.5\nx", "30\ntwo\nlines", "30\nbell\u{7}", long.as_str()] {
            assert_eq!(GrantAnswer::decode(nonsense), None, "{nonsense:?}");
        }
        assert_eq!(GrantAnswer::decode(&format!("30\n{}", "x".repeat(512))).map(|answer| answer.justification.len()), Some(512));
        // The window's limits are the grant memory's, so that an answer can always be remembered on this computer.
        assert_eq!(MAX_GRANT_MINUTES * 60, crate::sync::transports::MAX_DURATION_SECS);
        assert_eq!(MAX_GRANT_JUSTIFICATION_CHARS, crate::sync::transports::MAX_JUSTIFICATION_CHARS);
        let prompt = GrantPrompt { project: "knowknow-prod".into(), entitlement: "prod-operate".into(), minutes: 30, justification: Some("restart app-api".into()) };
        assert_eq!(GrantPrompt::from_text(&prompt.to_text()), Some(prompt));
        assert_eq!(GrantPrompt::from_text("No active grant."), None);
        assert_eq!(serde_json::to_string(&QuestionKind::Grant).unwrap(), r#""grant""#);
    }

    #[test]
    fn frames_come_back_in_order_and_a_clean_end_between_frames_is_none() {
        let mut stream = Vec::new();
        write_control(&mut stream, &ClientMessage::Close).unwrap();
        write_data(&mut stream, b"ls -l\r").unwrap();
        write_data(&mut stream, b"").unwrap();
        assert_eq!(
            frames_of(&stream),
            vec![
                Ok(Some(Frame::Control(Zeroizing::new(br#"{"type":"close"}"#.to_vec())))),
                Ok(Some(Frame::Data(Zeroizing::new(b"ls -l\r".to_vec())))),
                Ok(Some(Frame::Data(Zeroizing::new(Vec::new())))),
                Ok(None),
            ]
        );
    }

    /// `u32 length | u8 type | payload`, big-endian; the length counts the type byte and the payload.
    #[test]
    fn a_frame_is_a_big_endian_length_that_counts_the_type_byte_then_the_type_then_the_payload() {
        let mut stream = Vec::new();
        write_data(&mut stream, b"hi").unwrap();
        assert_eq!(stream, [0, 0, 0, 3, DATA, b'h', b'i']);
        let mut stream = Vec::new();
        write_frame(&mut stream, CONTROL, b"{}").unwrap();
        assert_eq!(stream, [0, 0, 0, 3, CONTROL, b'{', b'}']);
    }

    /// A length beyond the limit is refused from the header alone: nothing is allocated for it and nothing more is read.
    #[test]
    fn a_frame_over_the_limit_is_refused_from_its_header_and_never_written() {
        let mut header = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        header.push(DATA);
        let mut reader = header.as_slice();
        assert!(matches!(read_frame(&mut reader), Err(FrameError::TooLarge(length)) if length == MAX_FRAME + 1));
        assert_eq!(reader, [DATA], "the payload was not read");

        let mut sink = Vec::new();
        let error = write_data(&mut sink, &vec![0; MAX_FRAME]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(sink.is_empty(), "nothing of a frame that does not fit is written");
        assert!(write_data(&mut sink, &vec![0; MAX_FRAME - 1]).is_ok(), "the type byte and MAX_FRAME - 1 bytes fit");
        assert_eq!(sink.len(), MAX_FRAME + 4, "the length, the type byte and the payload");
    }

    #[test]
    fn a_stream_that_ends_inside_a_frame_is_truncated_and_odd_frames_are_errors() {
        assert!(matches!(read_frame(&mut [0u8, 0].as_slice()), Err(FrameError::Truncated)), "inside the length");
        assert!(matches!(read_frame(&mut [0u8, 0, 0, 5, DATA, b'a'].as_slice()), Err(FrameError::Truncated)), "inside the payload");
        assert!(matches!(read_frame(&mut [0u8, 0, 0, 0].as_slice()), Err(FrameError::Empty)), "a frame without even a type");
        assert!(matches!(read_frame(&mut [0u8, 0, 0, 1, 9].as_slice()), Err(FrameError::UnknownType(9))));
    }

    #[test]
    fn client_messages_read_and_write_as_the_spec_names_them() {
        let cases: Vec<(&str, ClientMessage)> = vec![
            (
                r#"{"type":"hello","client":"connect","version":1,"client_info":null}"#,
                ClientMessage::Hello { client: ClientKind::Connect, version: 1, client_info: None },
            ),
            (
                r#"{"type":"open_shell","host":{"alias":"web"},"pty":{"cols":120,"rows":40,"term":"xterm-256color"}}"#,
                ClientMessage::OpenShell { host: HostQuery::Alias("web".into()), pty: PtyRequest { cols: 120, rows: 40, term: "xterm-256color".into() } },
            ),
            (
                r#"{"type":"open_shell","host":{"id":"0123456789abcdef"},"pty":{"cols":80,"rows":24,"term":"dumb"}}"#,
                ClientMessage::OpenShell { host: HostQuery::Id("0123456789abcdef".into()), pty: PtyRequest { cols: 80, rows: 24, term: "dumb".into() } },
            ),
            (r#"{"type":"window_change","cols":100,"rows":30}"#, ClientMessage::WindowChange { cols: 100, rows: 30 }),
            (
                r#"{"type":"answer","question_id":"q1","value":"hunter2","cancel":false}"#,
                ClientMessage::Answer { question_id: "q1".into(), value: Some("hunter2".into()), cancel: false },
            ),
            (r#"{"type":"answer","question_id":"q2","value":null,"cancel":true}"#, ClientMessage::Answer { question_id: "q2".into(), value: None, cancel: true }),
            (r#"{"type":"close"}"#, ClientMessage::Close),
        ];
        for (json, message) in cases {
            assert_eq!(decode::<ClientMessage>(json.as_bytes()), Ok(message.clone()), "{json}");
            assert_eq!(serde_json::to_string(&message).unwrap(), json);
        }
        // Phase 2's messages and the fields 1b does not know are read, so the broker can refuse them by name.
        assert_eq!(
            decode::<ClientMessage>(br#"{"type":"exec","host":{"alias":"web"},"command":"uptime","timeout_secs":60}"#),
            Ok(ClientMessage::Exec {})
        );
        assert_eq!(decode::<ClientMessage>(br#"{"type":"hello","client":"mcp","version":2,"client_info":{"name":"claude"}}"#).map(|m| matches!(m, ClientMessage::Hello { client: ClientKind::Mcp, version: 2, .. })), Ok(true));
        assert_eq!(decode::<ClientMessage>(br#"{"type":"teleport"}"#), Ok(ClientMessage::Unknown));
        assert_eq!(decode::<ClientMessage>(br#"{"type":"answer","question_id":"q3"}"#), Ok(ClientMessage::Answer { question_id: "q3".into(), value: None, cancel: false }), "value and cancel may be left out");
    }

    #[test]
    fn server_messages_read_and_write_as_the_spec_names_them() {
        let cases: Vec<(&str, ServerMessage)> = vec![
            (r#"{"type":"opened","session_id":"7"}"#, ServerMessage::Opened { session_id: "7".into() }),
            (
                r#"{"type":"question","question_id":"q1","kind":"password","text":"deploy@web's password: ","echo":false,"deadline_ms":60000}"#,
                ServerMessage::Question(Question { question_id: "q1".into(), kind: QuestionKind::Password, text: "deploy@web's password: ".into(), echo: false, deadline_ms: Some(60_000) }),
            ),
            (
                r#"{"type":"question","question_id":"q2","kind":"host_key_notice","text":"Waiting for you to confirm web's host key in Lunport.","echo":false,"deadline_ms":null}"#,
                ServerMessage::Question(Question {
                    question_id: "q2".into(),
                    kind: QuestionKind::HostKeyNotice,
                    text: "Waiting for you to confirm web's host key in Lunport.".into(),
                    echo: false,
                    deadline_ms: None,
                }),
            ),
            (r#"{"type":"event","event":"connected"}"#, ServerMessage::Event(Event::Connected)),
            (r#"{"type":"event","event":"disconnected","reason":"Connection to web lost."}"#, ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost.".into() })),
            (r#"{"type":"event","event":"error","kind":"auth","text":"Authentication failed."}"#, ServerMessage::Event(Event::Error { kind: "auth".into(), text: "Authentication failed.".into() })),
            (r#"{"type":"event","event":"banner","text":"Authorized use only.\n"}"#, ServerMessage::Event(Event::Banner { text: "Authorized use only.\n".into() })),
            (r#"{"type":"exited","code":3,"signal":null}"#, ServerMessage::Exited { code: Some(3), signal: None }),
            (r#"{"type":"exited","code":null,"signal":"KILL"}"#, ServerMessage::Exited { code: None, signal: Some("KILL".into()) }),
        ];
        for (json, message) in cases {
            assert_eq!(decode::<ServerMessage>(json.as_bytes()), Ok(message.clone()), "{json}");
            assert_eq!(serde_json::to_string(&message).unwrap(), json);
        }
    }

    /// An answer can carry a password: it never shows in debug output, and a message that does not parse is not quoted back.
    #[test]
    fn an_answer_keeps_its_value_out_of_debug_output_and_error_text() {
        let answer = ClientMessage::Answer { question_id: "q1".into(), value: Some("hunter2".into()), cancel: false };
        let shown = format!("{answer:?}");
        assert!(!shown.contains("hunter2") && shown.contains("q1"), "{shown}");
        // serde's own text for this one would quote the value it choked on: `invalid type: string "hunter2", expected a boolean`.
        let error = decode::<ClientMessage>(br#"{"type":"answer","question_id":"q1","value":"hunter2","cancel":"hunter2"}"#).unwrap_err();
        assert!(!error.contains("hunter2"), "{error}");
        assert_eq!(error, "a control message Lunport does not understand");
    }

    /// A frame's payload can be a password (an answer, or keystrokes): its debug form does not show it. `Frame` derives `Debug`, and the
    /// payload is hidden by `Zeroizing`'s own (zeroize 1.9.1 prints no content): this keeps it so.
    #[test]
    fn a_frame_hides_its_payload_in_debug_output() {
        for frame in [Frame::Control(Zeroizing::new(b"hunter2".to_vec())), Frame::Data(Zeroizing::new(b"hunter2".to_vec()))] {
            let shown = format!("{frame:?}");
            assert!(!shown.contains("hunter2") && !shown.contains("104, 117"), "{shown}");
        }
    }

    /// A reader that gives one byte at a time, and is interrupted twice on the way (a signal): the frame comes back whole.
    #[test]
    fn a_frame_read_a_byte_at_a_time_with_interruptions_comes_back_whole() {
        struct Trickle {
            bytes: Vec<u8>,
            at: usize,
            interruptions: usize,
        }
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.at == 2 && self.interruptions < 2 {
                    self.interruptions += 1;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let Some(byte) = self.bytes.get(self.at) else { return Ok(0) };
                buf[0] = *byte;
                self.at += 1;
                Ok(1)
            }
        }
        let mut stream = Vec::new();
        write_control(&mut stream, &ClientMessage::Close).unwrap();
        let mut reader = Trickle { bytes: stream, at: 0, interruptions: 0 };
        assert_eq!(read_frame(&mut reader).unwrap(), Some(Frame::Control(Zeroizing::new(br#"{"type":"close"}"#.to_vec()))));
        assert_eq!(reader.interruptions, 2);
        assert_eq!(read_frame(&mut reader).unwrap(), None, "and then a clean end");
    }

    /// The ends of a frame: the stream ending after the length and before the type byte is a frame cut short; a frame of exactly
    /// `MAX_FRAME` is read back whole; a reader that fails (not an interruption) is a failed connection.
    #[test]
    fn a_frame_cut_after_its_length_is_truncated_one_of_exactly_the_limit_is_read_and_a_failed_read_is_io() {
        assert!(matches!(read_frame(&mut [0u8, 0, 0, 2].as_slice()), Err(FrameError::Truncated)), "between the length and the type byte");

        let mut stream = Vec::new();
        write_data(&mut stream, &vec![7; MAX_FRAME - 1]).unwrap();
        match read_frame(&mut stream.as_slice()) {
            Ok(Some(Frame::Data(payload))) => assert!(payload.len() == MAX_FRAME - 1 && payload.iter().all(|byte| *byte == 7)),
            other => panic!("a frame of MAX_FRAME bytes: {:?}", other.map(|frame| frame.map(|_| "another frame"))),
        }

        struct Fails;
        impl Read for Fails {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::ConnectionReset))
            }
        }
        assert!(matches!(read_frame(&mut Fails), Err(FrameError::Io(error)) if error.kind() == io::ErrorKind::ConnectionReset));
    }

    /// JSON that is not a message of either side is an error, with the one sentence that quotes nothing.
    #[test]
    fn json_that_is_not_a_message_does_not_decode() {
        for json in [&b"{}"[..], b"[]", br#""x""#, br#"{"type":1}"#] {
            let shown = String::from_utf8_lossy(json);
            assert_eq!(decode::<ClientMessage>(json), Err("a control message Lunport does not understand".to_string()), "{shown}");
            assert_eq!(decode::<ServerMessage>(json), Err("a control message Lunport does not understand".to_string()), "{shown}");
        }
    }
}
