//! The client's side of one session (own-ssh spec §7.3), with no I/O of its own: it is told what happened (`Input`) and answers with
//! what to do (`Action`); `run.rs` does the reading and writing. Until the shell is open the terminal stays as it was, so Ctrl-C still
//! stops the program; questions are asked with the terminal in its prompt mode; once the shell is open the terminal is raw and every
//! key goes to the shell; at the end the terminal is put back before anything is printed. Every text the broker wrote (a notice, a
//! question, a banner, an error) goes through `printable` before it is printed: the CLI does not trust the broker it talks to.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use super::terminal::Mode;
use crate::session::protocol::{kinds, ClientKind, ClientMessage, Event, HostQuery, PtyRequest, Question, QuestionKind, ServerMessage, DATA_CHUNK, PROTOCOL_VERSION};

/// What happened.
pub enum Input {
    /// A control message from the broker.
    Message(ServerMessage),
    /// Terminal output from the broker.
    Output(Vec<u8>),
    /// The broker closed the connection.
    Closed,
    /// Bytes the person typed (a password, at a question). They are wiped wherever they are dropped: `Zeroizing` does it, so no path
    /// of the loop (a discarded line, an input that arrives after the end) has to remember to.
    Stdin(Zeroizing<Vec<u8>>),
    /// Standard input ended (Ctrl-D on an empty line, at a question).
    StdinEnd,
    /// The terminal was resized.
    Resize(u16, u16),
    /// Ctrl-C while the terminal was not raw (SIGINT).
    Interrupt,
    /// The program was told to stop, or its terminal went away (SIGTERM, SIGHUP, SIGQUIT): the signal's number.
    Stop(i32),
    /// A thread of the program itself (the keys, the signals, the broker's frames) panicked or could not start: nothing would read from
    /// it any more, so the program ends. The panic hook has put the terminal back by then.
    Failed,
}

/// What was typed may be a password, so the debug form leaves it out (as `ClientMessage`'s does for an answer); the rest prints as a
/// derived `Debug` would.
impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Input::Message(message) => f.debug_tuple("Message").field(message).finish(),
            Input::Output(bytes) => f.debug_tuple("Output").field(bytes).finish(),
            Input::Closed => f.write_str("Closed"),
            Input::Stdin(_) => f.write_str("Stdin(<hidden>)"),
            Input::StdinEnd => f.write_str("StdinEnd"),
            Input::Resize(cols, rows) => f.debug_tuple("Resize").field(cols).field(rows).finish(),
            Input::Interrupt => f.write_str("Interrupt"),
            Input::Stop(signal) => f.debug_tuple("Stop").field(signal).finish(),
            Input::Failed => f.write_str("Failed"),
        }
    }
}

/// What to do.
#[derive(PartialEq, Eq)]
pub enum Action {
    /// A message for the broker. Nothing in it is secret: the answer to a question is `Answer`.
    Send(ClientMessage),
    /// The answer to a question, typed by the person (a password, a passphrase, a code), for the broker as the protocol's answer message.
    /// The text stays in a `Zeroizing` string from the keys to here, and is wiped when the action is dropped, after it has been written.
    Answer { question_id: String, value: Zeroizing<String> },
    /// Keystrokes for the shell: they can be a password too (typed at a prompt the shell shows), so the debug form says how many and
    /// leaves them out. Whoever writes them out wipes them (`run.rs`).
    SendData(Vec<u8>),
    Stdout(Vec<u8>),
    Stderr(String),
    /// Set the terminal's mode; `true` throws away what was typed ahead first.
    Mode(Mode, bool),
    Exit(i32),
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Send(message) => f.debug_tuple("Send").field(message).finish(),
            Action::Answer { question_id, .. } => f.debug_struct("Answer").field("question_id", question_id).field("value", &format_args!("<hidden>")).finish(),
            Action::SendData(bytes) => write!(f, "SendData(<{} bytes>)", bytes.len()),
            Action::Stdout(bytes) => f.debug_tuple("Stdout").field(bytes).finish(),
            Action::Stderr(text) => f.debug_tuple("Stderr").field(text).finish(),
            Action::Mode(mode, discard_input) => f.debug_tuple("Mode").field(mode).field(discard_input).finish(),
            Action::Exit(code) => f.debug_tuple("Exit").field(code).finish(),
        }
    }
}

/// Text the broker wrote, made safe to print on a terminal: the same rule as the broker's own `session::auth::printable`, written out
/// again on purpose. The CLI on disk can be another version than the broker it talks to, and a path of the broker once missed the rule;
/// the CLI should not owe what it prints to the broker having checked it. CRLF becomes LF, and every other control character (C0, DEL
/// and C1: an escape sequence could rewrite the screen or erase the line in front of the text) becomes `?`. So do the bidirectional
/// controls and the line and paragraph separators (`is_deceptive_format`), which are not control characters. Tabs and line feeds stay,
/// and a line feed is the only line break left. The shell's own data is not text and never goes through here.
pub fn printable(text: &str) -> String {
    text.replace("\r\n", "\n").chars().map(|c| if (c.is_control() && c != '\n' && c != '\t') || is_deceptive_format(c) { '?' } else { c }).collect()
}

/// The characters `printable` replaces although they are not control characters: the bidirectional marks (U+061C, U+200E, U+200F),
/// embeddings and overrides (U+202A to U+202E) and isolates (U+2066 to U+2069) make text read in another order than it is written (after
/// U+202E the characters `drowssap` are shown as `password`), and some terminals may break the line at U+2028 and U+2029.
fn is_deceptive_format(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The message that cancels a question (the person pressed Ctrl-C or Ctrl-D, or the question was replaced).
fn cancel(question_id: String) -> Action {
    Action::Send(ClientMessage::Answer { question_id, value: None, cancel: true })
}

/// What is said when a thread of the program panicked (the panic itself was reported by the hook, which put the terminal back first).
const THREAD_FAILED: &str = "sshelter: an internal error stopped this session.";

/// What the person typed before the shell opened is kept for it (as OpenSSH's typeahead reaches the shell), up to this many bytes.
const TYPEAHEAD_LIMIT: usize = 64 * 1024;

/// The buffer an answer is collected in is reserved this large when the question is asked. A `Vec` that grows frees its old allocation
/// with what was typed in it, unwiped; no answer needs more (a longer one is moved by hand, see `keep`).
const ANSWER_CAPACITY: usize = 1024;

/// Adds what was typed to the answer being collected, in a buffer that does not move while a password is typed; one that outgrows its
/// reserve moves to a bigger buffer by hand, and the old one is wiped as it is dropped.
fn keep(line: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    if line.capacity() - line.len() < bytes.len() {
        let mut bigger = Zeroizing::new(Vec::with_capacity((line.len() + bytes.len()).next_power_of_two()));
        bigger.extend_from_slice(&line[..]);
        *line = bigger;
    }
    line.extend_from_slice(bytes);
}

enum Phase {
    Connecting,
    /// A question is on the terminal; the answer is collected until Enter.
    Asking { question_id: String, echo: bool, line: Zeroizing<Vec<u8>>, after: Mode },
    Open,
    Ended,
}

/// The exit status of `sshelter connect` for a shell that ended with `code` or was killed by `signal` (spec §7.3): the shell's own
/// status; for a signal 128 + its number, as a shell reports it; 255 when it ended without either (a lost connection), as ssh does.
pub fn exit_code(code: Option<u32>, signal: Option<&str>) -> i32 {
    match (code, signal) {
        (Some(code), _) => code.min(255) as i32,
        (None, Some(signal)) => signal_number(signal).map(|number| 128 + number).unwrap_or(255),
        (None, None) => 255,
    }
}

/// The local number of a signal named as SSH names it (RFC 4254 §6.10, without `SIG`).
fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "ABRT" => libc::SIGABRT,
        "ALRM" => libc::SIGALRM,
        "FPE" => libc::SIGFPE,
        "HUP" => libc::SIGHUP,
        "ILL" => libc::SIGILL,
        "INT" => libc::SIGINT,
        "KILL" => libc::SIGKILL,
        "PIPE" => libc::SIGPIPE,
        "QUIT" => libc::SIGQUIT,
        "SEGV" => libc::SIGSEGV,
        "TERM" => libc::SIGTERM,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        _ => return None,
    })
}

/// The client of one session.
pub struct Client {
    phase: Phase,
    /// Bytes typed before the shell opened. Reserved in full at the start, so that it does not move while it grows.
    typeahead: Zeroizing<Vec<u8>>,
    /// What to say when it ends: why the connection ended or failed.
    reason: Option<String>,
}

impl Client {
    /// A client that opens a shell on `host` for a terminal of type `term` and size `size`; the actions say hello and ask for the shell.
    pub fn start(host: HostQuery, term: String, size: (u16, u16)) -> (Client, Vec<Action>) {
        let client = Client { phase: Phase::Connecting, typeahead: Zeroizing::new(Vec::with_capacity(TYPEAHEAD_LIMIT)), reason: None };
        let actions = vec![
            Action::Send(ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }),
            Action::Send(ClientMessage::OpenShell { host, pty: PtyRequest { cols: size.0, rows: size.1, term } }),
        ];
        (client, actions)
    }

    /// The mode the terminal is in while no question is on it; while one is, the mode it goes back to when that question ends.
    fn resting_mode(&self) -> Mode {
        match &self.phase {
            Phase::Open => Mode::Raw,
            Phase::Asking { after, .. } => *after,
            Phase::Connecting | Phase::Ended => Mode::Cooked,
        }
    }

    pub fn handle(&mut self, input: Input) -> Vec<Action> {
        if matches!(self.phase, Phase::Ended) {
            return Vec::new();
        }
        match input {
            Input::Message(message) => self.message(message),
            Input::Output(bytes) => vec![Action::Stdout(bytes)],
            Input::Closed => {
                let reason = self.reason.take().unwrap_or_else(|| "The connection to SSHelter ended.".to_string());
                self.finish(false, Some(reason), 255)
            }
            Input::Stdin(bytes) => self.typed(&bytes),
            Input::StdinEnd | Input::Interrupt if matches!(self.phase, Phase::Asking { .. }) => self.answer(None),
            Input::Interrupt => self.finish(true, None, 130),
            Input::StdinEnd => self.finish(true, None, 128 + libc::SIGHUP),
            Input::Resize(cols, rows) => vec![Action::Send(ClientMessage::WindowChange { cols, rows })],
            Input::Stop(signal) => self.finish(true, None, 128 + signal),
            Input::Failed => self.finish(true, Some(THREAD_FAILED.to_string()), 255),
        }
    }

    fn message(&mut self, message: ServerMessage) -> Vec<Action> {
        match message {
            ServerMessage::Opened { .. } => self.opened(),
            ServerMessage::Question(Question { kind: QuestionKind::HostKeyNotice, text, .. }) => vec![Action::Stderr(format!("{}\n", printable(&text)))],
            ServerMessage::Question(Question { question_id, text, echo, .. }) => self.ask(question_id, &text, echo),
            ServerMessage::Event(Event::Banner { text }) => {
                let text = printable(&text);
                let text = if text.ends_with('\n') { text } else { format!("{text}\n") };
                vec![Action::Stderr(text)]
            }
            ServerMessage::Event(Event::Error { kind, text }) if kind == kinds::INPUT && matches!(self.phase, Phase::Open) => {
                // The terminal is raw, so nothing turns a line feed into a line break: it has to be said.
                vec![Action::Stderr(format!("\r\n[{}]\r\n", printable(&text).replace('\n', "\r\n")))]
            }
            ServerMessage::Event(Event::Error { text, .. }) | ServerMessage::Event(Event::Disconnected { reason: text }) => {
                self.reason = Some(printable(&text));
                Vec::new()
            }
            ServerMessage::Event(Event::Connected) => Vec::new(),
            ServerMessage::Exited { code, signal } => {
                let reason = self.reason.take();
                self.finish(false, reason, exit_code(code, signal.as_deref()))
            }
        }
    }

    /// The shell is open: the terminal goes raw, and what was typed while connecting goes to it.
    fn opened(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        // A question still on the terminal is over (the broker does not open the shell under an unanswered question, but if it did):
        // it is cancelled, and what was typed for it is thrown away with the terminal's pending input, so that it cannot become input
        // of the shell.
        let over_a_question = if let Phase::Asking { question_id, .. } = &self.phase {
            actions.push(Action::Stderr("\n".to_string()));
            actions.push(cancel(question_id.clone()));
            true
        } else {
            false
        };
        self.phase = Phase::Open;
        actions.push(Action::Mode(Mode::Raw, over_a_question));
        // Typeahead is typed text like any other: it goes out in data frames of at most DATA_CHUNK bytes.
        for chunk in self.typeahead.chunks(DATA_CHUNK) {
            actions.push(Action::SendData(chunk.to_vec()));
        }
        self.typeahead.zeroize();
        actions
    }

    /// Puts a question on the terminal, in the prompt mode that fits it.
    fn ask(&mut self, question_id: String, text: &str, echo: bool) -> Vec<Action> {
        let mut actions = Vec::new();
        // The terminal goes back to what it was before the first question, not to the mode of one that was cancelled on the way; the
        // cancelled question's prompt is still on the line, so the new one starts on a line of its own.
        let after = self.resting_mode();
        if let Phase::Asking { question_id: superseded, .. } = &self.phase {
            actions.push(Action::Stderr("\n".to_string()));
            actions.push(cancel(superseded.clone()));
        }
        self.typeahead.zeroize();
        self.phase = Phase::Asking { question_id, echo, line: Zeroizing::new(Vec::with_capacity(ANSWER_CAPACITY)), after };
        actions.push(Action::Mode(Mode::Prompt { echo }, true));
        actions.push(Action::Stderr(printable(text)));
        actions
    }

    fn typed(&mut self, bytes: &[u8]) -> Vec<Action> {
        match &mut self.phase {
            Phase::Connecting => {
                let room = TYPEAHEAD_LIMIT.saturating_sub(self.typeahead.len());
                self.typeahead.extend_from_slice(&bytes[..bytes.len().min(room)]);
                Vec::new()
            }
            Phase::Asking { line, .. } => {
                keep(line, bytes);
                match line.iter().position(|byte| *byte == b'\n' || *byte == b'\r') {
                    Some(end) => {
                        let answer = Zeroizing::new(String::from_utf8_lossy(&line[..end]).into_owned());
                        self.answer(Some(answer))
                    }
                    None => Vec::new(),
                }
            }
            Phase::Open => bytes.chunks(DATA_CHUNK).map(|chunk| Action::SendData(chunk.to_vec())).collect(),
            Phase::Ended => Vec::new(),
        }
    }

    /// Ends the question on the terminal: with the answer, or cancelled (`None`).
    ///
    /// The password goes on in the `Zeroizing` string it was collected in, inside `Action::Answer`; whoever writes the action out
    /// (`run.rs`) writes it from there, and it is wiped when the action is dropped.
    fn answer(&mut self, answer: Option<Zeroizing<String>>) -> Vec<Action> {
        let (question_id, echo, after) = match std::mem::replace(&mut self.phase, Phase::Connecting) {
            Phase::Asking { question_id, echo, after, .. } => (question_id, echo, after),
            other => {
                // No question is on the terminal: there is nothing to answer, and nothing changes.
                self.phase = other;
                return Vec::new();
            }
        };
        self.phase = if after == Mode::Raw { Phase::Open } else { Phase::Connecting };
        let mut actions = Vec::new();
        if !echo || answer.is_none() {
            // The Enter of a hidden answer (or the Ctrl-C) did not move to the next line.
            actions.push(Action::Stderr("\n".to_string()));
        }
        actions.push(match answer {
            Some(value) => Action::Answer { question_id, value },
            None => cancel(question_id),
        });
        actions.push(Action::Mode(after, false));
        actions
    }

    /// The end: the terminal is put back first, so that nothing after it can leave it raw (a broker that stopped reading blocks the write
    /// that tells it); then the broker is told when it is the program that leaves (`close`), the reason is printed on a line of its own,
    /// and the program exits.
    fn finish(&mut self, close: bool, reason: Option<String>, code: i32) -> Vec<Action> {
        // The cursor is not at the start of a line while the shell is open (it can be anywhere in what the shell wrote), nor while a
        // question's prompt is on it, whatever the terminal was before the question.
        let mid_line = matches!(self.phase, Phase::Open | Phase::Asking { .. });
        self.phase = Phase::Ended;
        let mut actions = vec![Action::Mode(Mode::Cooked, false)];
        if close {
            actions.push(Action::Send(ClientMessage::Close));
        }
        if let Some(reason) = reason {
            actions.push(Action::Stderr(if mid_line { format!("\n{reason}\n") } else { format!("{reason}\n") }));
        }
        actions.push(Action::Exit(code));
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started() -> Client {
        Client::start(HostQuery::Alias("web".into()), "xterm-256color".into(), (80, 24)).0
    }

    fn opened() -> Client {
        let mut client = started();
        client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() }));
        client
    }

    fn question(id: &str, kind: QuestionKind, text: &str, echo: bool) -> Input {
        Input::Message(ServerMessage::Question(Question { question_id: id.into(), kind, text: text.into(), echo, deadline_ms: Some(60_000) }))
    }

    #[test]
    fn it_says_hello_and_asks_for_a_shell_of_the_terminals_type_and_size() {
        let (_, actions) = Client::start(HostQuery::Id("0123456789abcdef".into()), "screen-256color".into(), (132, 43));
        assert_eq!(
            actions,
            [
                Action::Send(ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }),
                Action::Send(ClientMessage::OpenShell { host: HostQuery::Id("0123456789abcdef".into()), pty: PtyRequest { cols: 132, rows: 43, term: "screen-256color".into() } }),
            ]
        );
    }

    #[test]
    fn once_the_shell_is_open_the_terminal_is_raw_and_keys_output_and_resizes_pass_through() {
        let mut client = started();
        assert_eq!(client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() })), [Action::Mode(Mode::Raw, false)]);
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"ls\r".to_vec()))), [Action::SendData(b"ls\r".to_vec())]);
        assert_eq!(client.handle(Input::Output(b"file\r\n".to_vec())), [Action::Stdout(b"file\r\n".to_vec())]);
        assert_eq!(client.handle(Input::Resize(100, 30)), [Action::Send(ClientMessage::WindowChange { cols: 100, rows: 30 })]);
        let pasted = vec![b'x'; DATA_CHUNK + 10];
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(pasted))).len(), 2, "a large paste goes out in data frames of at most DATA_CHUNK bytes");
    }

    /// What was typed while connecting reaches the shell once it is open (OpenSSH behaves the same).
    #[test]
    fn typeahead_reaches_the_shell_once_it_opens() {
        let mut client = started();
        assert!(client.handle(Input::Stdin(Zeroizing::new(b"uptime\n".to_vec()))).is_empty());
        assert_eq!(client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() })), [Action::Mode(Mode::Raw, false), Action::SendData(b"uptime\n".to_vec())]);
    }

    /// The payloads of the data frames in `actions`, in order.
    fn data_frames(actions: &[Action]) -> Vec<Vec<u8>> {
        actions.iter().filter_map(|action| if let Action::SendData(bytes) = action { Some(bytes.clone()) } else { None }).collect()
    }

    /// The protocol says keystrokes travel in data frames of at most DATA_CHUNK bytes: typeahead is no different.
    #[test]
    fn typeahead_goes_out_in_data_frames_of_at_most_data_chunk_bytes() {
        for (typed, sizes) in [(3, vec![3]), (DATA_CHUNK, vec![DATA_CHUNK]), (DATA_CHUNK + 5, vec![DATA_CHUNK, 5]), (2 * DATA_CHUNK, vec![DATA_CHUNK, DATA_CHUNK])] {
            let mut client = started();
            client.handle(Input::Stdin(Zeroizing::new(vec![b'x'; typed])));
            let actions = client.handle(opens());
            assert_eq!(actions[0], Action::Mode(Mode::Raw, false));
            let frames = data_frames(&actions);
            assert_eq!(frames.iter().map(Vec::len).collect::<Vec<_>>(), sizes, "{typed} bytes typed ahead");
            assert_eq!(actions.len(), 1 + frames.len(), "nothing else: the data frames follow the mode");
        }
    }

    /// What is typed while connecting is kept up to 64 KiB (the first 64 KiB: the rest is dropped).
    #[test]
    fn typeahead_is_kept_up_to_its_limit_and_the_rest_is_dropped() {
        let mut client = started();
        client.handle(Input::Stdin(Zeroizing::new(vec![b'a'; 40 * 1024])));
        client.handle(Input::Stdin(Zeroizing::new(vec![b'b'; 40 * 1024])));
        client.handle(Input::Stdin(Zeroizing::new(b"more".to_vec())));
        let kept = data_frames(&client.handle(opens())).concat();
        let mut expected = vec![b'a'; 40 * 1024];
        expected.extend(vec![b'b'; 24 * 1024]);
        assert_eq!(kept.len(), 64 * 1024);
        assert!(kept == expected, "the first 64 KiB are kept, as they were typed");
    }

    /// Spec §7.3: a question leaves raw mode (or the terminal as it was), asks without echo for a password, sends the answer and goes
    /// back; typeahead is thrown away, so it cannot become the password.
    #[test]
    fn a_password_question_is_asked_without_echo_and_the_answer_is_sent() {
        let mut client = started();
        client.handle(Input::Stdin(Zeroizing::new(b"ls\n".to_vec())));
        assert_eq!(
            client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false)),
            [Action::Mode(Mode::Prompt { echo: false }, true), Action::Stderr("deploy@web's password: ".into())]
        );
        assert!(client.handle(Input::Stdin(Zeroizing::new(b"hunt".to_vec()))).is_empty(), "the answer is collected until Enter");
        assert_eq!(
            client.handle(Input::Stdin(Zeroizing::new(b"er2\n".to_vec()))),
            [
                Action::Stderr("\n".into()),
                answered("q1", "hunter2"),
                Action::Mode(Mode::Cooked, false),
            ]
        );
        assert_eq!(client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() })), [Action::Mode(Mode::Raw, false)], "the typeahead from before the question is gone");
    }

    #[test]
    fn a_code_question_shows_what_is_typed_and_a_question_in_the_open_shell_goes_back_to_raw() {
        let mut client = opened();
        assert_eq!(client.handle(question("q2", QuestionKind::Interactive, "(deploy@web) Code: ", true))[0], Action::Mode(Mode::Prompt { echo: true }, true));
        assert_eq!(
            client.handle(Input::Stdin(Zeroizing::new(b"123456\r\n".to_vec()))),
            [answered("q2", "123456"), Action::Mode(Mode::Raw, false)]
        );
    }

    #[test]
    fn ctrl_c_or_ctrl_d_at_a_question_cancels_it() {
        for input in [Input::Interrupt, Input::StdinEnd] {
            let mut client = started();
            client.handle(question("q1", QuestionKind::Passphrase, "Enter the passphrase for the key laptop: ", false));
            assert_eq!(
                client.handle(input),
                [Action::Stderr("\n".into()), Action::Send(ClientMessage::Answer { question_id: "q1".into(), value: None, cancel: true }), Action::Mode(Mode::Cooked, false)]
            );
        }
    }

    #[test]
    fn the_host_key_notice_and_a_banner_are_printed_and_need_no_answer() {
        let mut client = started();
        assert_eq!(
            client.handle(question("q1", QuestionKind::HostKeyNotice, "Waiting for you to confirm web's host key in SSHelter.", false)),
            [Action::Stderr("Waiting for you to confirm web's host key in SSHelter.\n".into())]
        );
        assert_eq!(client.handle(Input::Message(ServerMessage::Event(Event::Banner { text: "Authorized use only.".into() }))), [Action::Stderr("Authorized use only.\n".into())]);
    }

    /// Spec §7.3: the terminal is put back before anything else, then the program exits with the shell's status.
    #[test]
    fn the_shells_exit_status_becomes_the_programs_after_the_terminal_is_put_back() {
        let mut client = opened();
        assert_eq!(client.handle(Input::Message(ServerMessage::Exited { code: Some(3), signal: None })), [Action::Mode(Mode::Cooked, false), Action::Exit(3)]);
        assert!(client.handle(Input::Output(b"late".to_vec())).is_empty(), "nothing after the end");
    }

    #[test]
    fn a_lost_connection_is_said_on_a_line_of_its_own_and_exits_255() {
        let mut client = opened();
        assert!(client.handle(Input::Message(ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost (no response for 120 seconds).".into() }))).is_empty());
        assert_eq!(
            client.handle(Input::Message(ServerMessage::Exited { code: None, signal: None })),
            [Action::Mode(Mode::Cooked, false), Action::Stderr("\nConnection to web lost (no response for 120 seconds).\n".into()), Action::Exit(255)]
        );
    }

    #[test]
    fn a_failed_connect_prints_the_reason_and_exits_255() {
        let mut client = started();
        client.handle(Input::Message(ServerMessage::Event(Event::Error { kind: kinds::HOST.into(), text: "No saved host is called web.".into() })));
        assert_eq!(
            client.handle(Input::Message(ServerMessage::Exited { code: None, signal: None })),
            [Action::Mode(Mode::Cooked, false), Action::Stderr("No saved host is called web.\n".into()), Action::Exit(255)]
        );
    }

    #[test]
    fn input_that_did_not_reach_the_server_is_said_inline_and_the_shell_goes_on() {
        let mut client = opened();
        let error = Event::Error { kind: kinds::INPUT.into(), text: "What you typed did not reach web in time: the connection is not responding.".into() };
        assert_eq!(client.handle(Input::Message(ServerMessage::Event(error))), [Action::Stderr("\r\n[What you typed did not reach web in time: the connection is not responding.]\r\n".into())]);
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"x".to_vec()))), [Action::SendData(b"x".to_vec())]);
    }

    #[test]
    fn the_broker_going_away_or_a_signal_ends_the_program_with_the_terminal_put_back() {
        let mut client = opened();
        assert_eq!(client.handle(Input::Closed), [Action::Mode(Mode::Cooked, false), Action::Stderr("\nThe connection to SSHelter ended.\n".into()), Action::Exit(255)]);
        let mut client = opened();
        assert_eq!(client.handle(Input::Stop(libc::SIGTERM)), [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Exit(128 + libc::SIGTERM)]);
        let mut client = started();
        assert_eq!(client.handle(Input::Interrupt), [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Exit(130)], "Ctrl-C while connecting stops it");
    }

    /// Spec §7.3: the end of input outside a question is the terminal going away, like SIGHUP. The terminal is put back before the broker
    /// is told: a broker that stopped reading would block the write, and the terminal would stay raw under a program that is stuck.
    #[test]
    fn the_end_of_input_outside_a_question_is_the_terminal_going_away_and_the_terminal_is_put_back_before_the_broker_is_told() {
        let hangup = [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Exit(129)]; // 128 + SIGHUP
        assert_eq!(started().handle(Input::StdinEnd), hangup);
        assert_eq!(opened().handle(Input::StdinEnd), hangup);
        assert_eq!(opened().handle(Input::Stop(libc::SIGHUP)), hangup);
    }

    /// A thread of the program itself panicked (the panic hook has put the terminal back by then, and nothing would read from that
    /// thread any more): the program ends with 255, as for a lost connection, the terminal put back first and the broker told.
    #[test]
    fn a_failed_thread_ends_the_program_with_255_the_terminal_put_back_and_the_broker_told() {
        let reason = "sshelter: an internal error stopped this session.";
        assert_eq!(
            opened().handle(Input::Failed),
            [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Stderr(format!("\n{reason}\n")), Action::Exit(255)],
            "the cursor is somewhere in what the shell wrote"
        );
        assert_eq!(
            started().handle(Input::Failed),
            [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Stderr(format!("{reason}\n")), Action::Exit(255)]
        );
        let mut client = opened();
        client.handle(Input::Failed);
        assert!(client.handle(Input::Output(b"late".to_vec())).is_empty(), "nothing after the end");
    }

    fn event(event: Event) -> Input {
        Input::Message(ServerMessage::Event(event))
    }

    fn error(kind: &str, text: &str) -> Input {
        event(Event::Error { kind: kind.into(), text: text.into() })
    }

    fn exited() -> Input {
        Input::Message(ServerMessage::Exited { code: None, signal: None })
    }

    fn opens() -> Input {
        Input::Message(ServerMessage::Opened { session_id: "1".into() })
    }

    fn answered(id: &str, value: &str) -> Action {
        Action::Answer { question_id: id.into(), value: Zeroizing::new(value.to_string()) }
    }

    fn cancelled(id: &str) -> Action {
        Action::Send(ClientMessage::Answer { question_id: id.into(), value: None, cancel: true })
    }

    /// What a hostile (or a broken, or an older) broker could send: an escape sequence (it clears the screen), a carriage return (it
    /// overwrites the line), the 8-bit CSI (a C1 control), a right-to-left override, and the tab and the line feed, which are fine.
    const HOSTILE: &str = "a\u{1b}[2Jb\rc\u{9b}d\u{202e}e\tf\ng";
    /// `HOSTILE` as the CLI prints it.
    const SAFE: &str = "a?[2Jb?c?d?e\tf\ng";

    // Every text the broker sends is cleaned before the CLI prints it (a binding ruling: the CLI on disk can be another version than the
    // running broker, and several paths of the broker once missed it): one test for each place a text is printed.

    #[test]
    fn the_host_key_notice_is_printed_without_control_characters() {
        let mut client = started();
        assert_eq!(client.handle(question("n1", QuestionKind::HostKeyNotice, HOSTILE, false)), [Action::Stderr(format!("{SAFE}\n"))]);
    }

    #[test]
    fn a_question_is_asked_without_control_characters() {
        let mut client = started();
        assert_eq!(
            client.handle(question("q1", QuestionKind::Interactive, HOSTILE, true)),
            [Action::Mode(Mode::Prompt { echo: true }, true), Action::Stderr(SAFE.into())]
        );
    }

    #[test]
    fn a_banner_is_printed_without_control_characters() {
        let mut client = started();
        assert_eq!(client.handle(event(Event::Banner { text: HOSTILE.into() })), [Action::Stderr(format!("{SAFE}\n"))]);
    }

    /// The terminal is raw while the shell is open, so a line feed needs its carriage return or the next line starts where this one ended.
    #[test]
    fn the_inline_input_error_is_printed_without_control_characters_and_with_whole_line_breaks() {
        let mut client = opened();
        assert_eq!(client.handle(error(kinds::INPUT, HOSTILE)), [Action::Stderr("\r\n[a?[2Jb?c?d?e\tf\r\ng]\r\n".into())]);
    }

    #[test]
    fn the_reason_at_the_end_is_cleaned_when_it_is_kept_and_printed_without_control_characters() {
        for kept in [error(kinds::CONNECT, HOSTILE), event(Event::Disconnected { reason: HOSTILE.into() })] {
            let mut client = opened();
            assert!(client.handle(kept).is_empty());
            assert_eq!(client.reason.as_deref(), Some(SAFE), "cleaned when it is kept");
            assert_eq!(client.handle(exited()), [Action::Mode(Mode::Cooked, false), Action::Stderr(format!("\n{SAFE}\n")), Action::Exit(255)]);
        }
    }

    /// A banner ends with a line feed of its own, and one that already ends with a line (feed or CRLF) gets no second.
    #[test]
    fn a_banner_ends_with_exactly_one_line_feed() {
        for (banner, printed) in [("Authorized use only.", "Authorized use only.\n"), ("Authorized use only.\n", "Authorized use only.\n"), ("One.\r\nTwo.\r\n", "One.\nTwo.\n")] {
            let mut client = started();
            assert_eq!(client.handle(event(Event::Banner { text: banner.into() })), [Action::Stderr(printed.into())], "{banner:?}");
        }
    }

    /// There is no shell to say "what you typed" about before it opens, and no raw terminal to print inline on: kept for the end like
    /// any other error.
    #[test]
    fn an_input_error_before_the_shell_opens_is_kept_for_the_end_and_not_printed_inline() {
        let mut client = started();
        assert!(client.handle(error(kinds::INPUT, "What you typed did not reach web in time.")).is_empty());
        assert_eq!(
            client.handle(exited()),
            [Action::Mode(Mode::Cooked, false), Action::Stderr("What you typed did not reach web in time.\n".into()), Action::Exit(255)]
        );
    }

    /// The rule, character by character: what is replaced, what stays, and what a line break is.
    #[test]
    fn printable_replaces_controls_and_bidirectional_marks_and_keeps_text_in_every_script() {
        let mut replaced: Vec<char> = ('\u{0}'..='\u{1f}').filter(|c| *c != '\n' && *c != '\t').collect();
        replaced.push('\u{7f}');
        replaced.extend('\u{80}'..='\u{9f}');
        replaced.extend(['\u{061C}', '\u{200E}', '\u{200F}', '\u{2028}', '\u{2029}']);
        replaced.extend('\u{202A}'..='\u{202E}');
        replaced.extend('\u{2066}'..='\u{2069}');
        for c in replaced {
            assert_eq!(printable(&format!("a{c}b")), "a?b", "U+{:04X}", c as u32);
        }
        assert_eq!(printable("one\r\ntwo\rthree\n\r"), "one\ntwo?three\n?", "CRLF is a line break and a lone CR is a control character");
        assert_eq!(printable("Password\u{202E}: \u{2066}ssap\u{2069}\u{200F}"), "Password?: ?ssap??");

        let kept = [
            "\u{0643}\u{0644}\u{0645}\u{0629}",                                 // Arabic letters
            "\u{05E1}\u{05D9}\u{05E1}\u{05DE}\u{05D4}",                         // Hebrew letters
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}", // Persian with a zero-width non-joiner
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}",                      // an emoji family, joined by zero-width joiners
            "\u{5BC6}\u{78BC} \u{e9} \u{fc}",                                   // Chinese and accented Latin letters
            "a\tb\nc",                                                          // the tab and the line feed
            "\u{2027}\u{202F}",                                                 // the characters just outside the replaced ranges
        ];
        for text in kept {
            assert_eq!(printable(text), text);
        }
    }

    /// The CLI's rule is the broker's, written out twice on purpose; this keeps the two the same, for every character there is.
    #[test]
    fn printable_is_the_same_rule_as_the_brokers() {
        let mut text = String::new();
        for c in '\0'..=char::MAX {
            text.clear();
            text.push('a');
            text.push(c);
            text.push_str("b\r\nc\rd\r\r\ne");
            assert_eq!(printable(&text), crate::session::auth::printable(&text), "U+{:04X}", c as u32);
        }
    }

    /// The prompt is still on the line when the session ends under it (the broker gave up waiting for the answer, or the app quit): the
    /// reason must not be printed after the prompt, but on a line of its own.
    #[test]
    fn an_end_while_a_question_is_on_the_terminal_starts_on_a_line_of_its_own() {
        for mut client in [started(), opened()] {
            client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
            client.handle(error(kinds::AUTH, "Authentication for web was abandoned (the password prompt timed out)."));
            assert_eq!(
                client.handle(exited()),
                [Action::Mode(Mode::Cooked, false), Action::Stderr("\nAuthentication for web was abandoned (the password prompt timed out).\n".into()), Action::Exit(255)]
            );
        }
        let mut client = started();
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
        assert_eq!(
            client.handle(Input::Closed),
            [Action::Mode(Mode::Cooked, false), Action::Stderr("\nThe connection to SSHelter ended.\n".into()), Action::Exit(255)]
        );
    }

    /// Not something the broker does (it waits for each answer), but the terminal must not be left in the first question's mode, nor the
    /// open shell lose its raw mode, if a second question arrives: the first is cancelled, and what comes after both is what came before.
    #[test]
    fn a_second_question_cancels_the_first_and_the_terminal_goes_back_to_what_it_was_before_both() {
        let mut client = started();
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
        assert_eq!(
            client.handle(question("q2", QuestionKind::Interactive, "Code: ", true)),
            [Action::Stderr("\n".into()), cancelled("q1"), Action::Mode(Mode::Prompt { echo: true }, true), Action::Stderr("Code: ".into())]
        );
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"123456\n".to_vec()))), [answered("q2", "123456"), Action::Mode(Mode::Cooked, false)]);
        assert!(client.handle(Input::Stdin(Zeroizing::new(b"ls\n".to_vec()))).is_empty(), "connecting again: what is typed is kept for the shell");
        assert_eq!(client.handle(opens()), [Action::Mode(Mode::Raw, false), Action::SendData(b"ls\n".to_vec())]);

        let mut client = opened();
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
        assert_eq!(
            client.handle(question("q2", QuestionKind::Interactive, "Code: ", true)),
            [Action::Stderr("\n".into()), cancelled("q1"), Action::Mode(Mode::Prompt { echo: true }, true), Action::Stderr("Code: ".into())]
        );
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"123456\n".to_vec()))), [answered("q2", "123456"), Action::Mode(Mode::Raw, false)]);
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"ls\r".to_vec()))), [Action::SendData(b"ls\r".to_vec())], "the shell is open again");
    }

    /// Nor does the broker open the shell under an unanswered question; if it did, the question is over, and what was typed for it must
    /// not become input of the shell (the terminal's pending input is thrown away).
    #[test]
    fn a_shell_that_opens_over_a_question_cancels_it_and_throws_away_what_was_typed_for_it() {
        let mut client = started();
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
        assert!(client.handle(Input::Stdin(Zeroizing::new(b"hun".to_vec()))).is_empty());
        assert_eq!(client.handle(opens()), [Action::Stderr("\n".into()), cancelled("q1"), Action::Mode(Mode::Raw, true)]);
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"ls\r".to_vec()))), [Action::SendData(b"ls\r".to_vec())], "only what is typed from now on reaches the shell");
    }

    #[test]
    fn an_answer_with_no_question_on_the_terminal_does_nothing() {
        let mut client = opened();
        assert!(client.answer(None).is_empty());
        assert!(matches!(client.phase, Phase::Open), "the open shell stays open");
        let mut client = started();
        assert!(client.answer(Some(Zeroizing::new("x".to_string()))).is_empty());
        assert!(matches!(client.phase, Phase::Connecting));
    }

    /// What was typed may be a password: the debug form of the input, and of the action that carries it on, leaves it out (as the debug
    /// form of `ClientMessage` leaves out an answer), while what is not typed stays as readable as a derived `Debug` makes it.
    #[test]
    fn what_is_typed_is_not_printed_by_debug() {
        assert_eq!(format!("{:?}", Input::Stdin(Zeroizing::new(b"hunter2\n".to_vec()))), "Stdin(<hidden>)");
        assert_eq!(format!("{:?}", Action::SendData(b"hunter2\n".to_vec())), "SendData(<8 bytes>)", "how many, not which");
        let answer = answered("q1", "hunter2");
        assert_eq!(format!("{answer:?}"), "Answer { question_id: \"q1\", value: <hidden> }");
        let sent = Action::Send(ClientMessage::Answer { question_id: "q1".into(), value: Some("hunter2".into()), cancel: false });
        assert!(!format!("{sent:?}").contains("hunter2"), "the debug form of the protocol's own message hides it too");

        assert_eq!(format!("{:?}", Input::Output(vec![104, 105])), "Output([104, 105])");
        assert_eq!(format!("{:?}", Input::Message(ServerMessage::Opened { session_id: "1".into() })), "Message(Opened { session_id: \"1\" })");
        assert_eq!(format!("{:?}", [Input::Closed, Input::StdinEnd, Input::Interrupt, Input::Failed]), "[Closed, StdinEnd, Interrupt, Failed]");
        assert_eq!(format!("{:?}", [Input::Resize(100, 30), Input::Stop(15)]), "[Resize(100, 30), Stop(15)]");
        assert_eq!(format!("{:?}", Action::Stdout(vec![104, 105])), "Stdout([104, 105])");
        assert_eq!(format!("{:?}", Action::Stderr("pw: ".into())), "Stderr(\"pw: \")");
        assert_eq!(format!("{:?}", [Action::Mode(Mode::Raw, true), Action::Exit(3)]), "[Mode(Raw, true), Exit(3)]");
        assert_eq!(format!("{:?}", Action::Send(ClientMessage::Close)), "Send(Close)");
    }

    /// Whether the first `len` bytes of the allocation of `buffer` (they held what was typed, though `buffer` is empty now) are all zero.
    fn wiped(buffer: &Zeroizing<Vec<u8>>, len: usize) -> bool {
        assert!(buffer.capacity() >= len, "the buffer was moved away, not wiped");
        // SAFETY: the allocation has at least `len` bytes (just checked), and they were written when they were typed, so they are
        // initialised whatever `buffer.len()` says; this reads what a buffer that was only `clear`ed would still hold.
        unsafe { std::slice::from_raw_parts(buffer.as_ptr(), len) }.iter().all(|byte| *byte == 0)
    }

    /// `clear` leaves what was typed in the buffer's memory; a question must not leave typeahead there, nor the shell opening.
    #[test]
    fn typeahead_is_wiped_from_memory_when_a_question_throws_it_away_and_when_the_shell_takes_it() {
        let mut client = started();
        client.handle(Input::Stdin(Zeroizing::new(b"hunter2\n".to_vec())));
        client.handle(question("q1", QuestionKind::Password, "pw: ", false));
        assert!(wiped(&client.typeahead, 8), "thrown away by a question");

        let mut client = started();
        client.handle(Input::Stdin(Zeroizing::new(b"uptime\n".to_vec())));
        client.handle(opens());
        assert!(wiped(&client.typeahead, 7), "sent to the shell");
    }

    fn line_of(client: &Client) -> &Zeroizing<Vec<u8>> {
        match &client.phase {
            Phase::Asking { line, .. } => line,
            _ => panic!("no question is on the terminal"),
        }
    }

    /// A `Vec` that grows frees its old allocation with what was typed in it, unwiped: typeahead and a password are typed into buffers that
    /// are reserved before the first key, and do not move while the keys come.
    #[test]
    fn typeahead_and_an_answer_are_collected_in_buffers_that_do_not_move_while_they_grow() {
        let mut client = started();
        let typeahead = client.typeahead.as_ptr();
        for _ in 0..70 {
            client.handle(Input::Stdin(Zeroizing::new(vec![b'x'; 1000])));
        }
        assert_eq!(client.typeahead.as_ptr(), typeahead, "reallocated: the freed copies keep what was typed");
        assert_eq!(client.typeahead.len(), 64 * 1024);

        client.handle(question("q1", QuestionKind::Password, "pw: ", false));
        let line = line_of(&client).as_ptr();
        assert!(line_of(&client).capacity() >= 1024);
        client.handle(Input::Stdin(Zeroizing::new(vec![b'p'; 1000])));
        assert_eq!(line_of(&client).as_ptr(), line, "reallocated: the freed copy keeps the password");
    }

    /// An answer that outgrows its buffer moves to a bigger one (the old is wiped); it must still arrive whole.
    #[test]
    fn an_answer_longer_than_the_reserved_buffer_is_still_sent_whole() {
        let mut client = started();
        client.handle(question("q1", QuestionKind::Passphrase, "Enter the passphrase for the key laptop: ", false));
        for piece in [vec![b'a'; 1500], vec![b'b'; 700], vec![b'c'; 2000]] {
            assert!(client.handle(Input::Stdin(Zeroizing::new(piece))).is_empty());
        }
        let actions = client.handle(Input::Stdin(Zeroizing::new(b"\n".to_vec())));
        let expected = format!("{}{}{}", "a".repeat(1500), "b".repeat(700), "c".repeat(2000));
        assert_eq!(actions, [Action::Stderr("\n".into()), answered("q1", &expected), Action::Mode(Mode::Cooked, false)]);
    }

    /// The shell's own bytes are not the CLI's to change: that is what a terminal program is for, and they need not be text at all.
    #[test]
    fn the_shells_own_output_is_passed_through_untouched() {
        let mut client = opened();
        let output = b"\x1b[2J\r\n\xc2\x9b\xe2\x80\xae\x07\x00\x9b\xff".to_vec();
        assert_eq!(client.handle(Input::Output(output.clone())), [Action::Stdout(output)]);
    }

    /// A terminal that does not turn Enter into a line feed (ICRNL off) delivers a carriage return.
    #[test]
    fn an_answer_ends_at_a_bare_carriage_return_as_well() {
        let mut client = started();
        client.handle(question("q1", QuestionKind::Interactive, "(deploy@web) Code: ", true));
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"123456\r".to_vec()))), [answered("q1", "123456"), Action::Mode(Mode::Cooked, false)]);
    }

    /// What was typed at a question that shows it is still on the line, so the cancelled question ends its line too.
    #[test]
    fn cancelling_a_question_that_shows_what_is_typed_ends_its_line_too() {
        let mut client = started();
        client.handle(question("q1", QuestionKind::Interactive, "(deploy@web) Code: ", true));
        assert!(client.handle(Input::Stdin(Zeroizing::new(b"12".to_vec()))).is_empty());
        assert_eq!(client.handle(Input::Interrupt), [Action::Stderr("\n".into()), cancelled("q1"), Action::Mode(Mode::Cooked, false)]);
    }

    #[test]
    fn the_connected_event_changes_nothing_for_the_terminal() {
        let mut client = started();
        assert!(client.handle(event(Event::Connected)).is_empty());
        assert!(client.handle(Input::Stdin(Zeroizing::new(b"ls\n".to_vec()))).is_empty(), "still connecting: what is typed is kept for the shell");
        assert_eq!(client.handle(opens()), [Action::Mode(Mode::Raw, false), Action::SendData(b"ls\n".to_vec())]);
    }

    /// Spec §7.3 / plan 1b R10: the shell's status, 128 + the signal's number for a signal (as a shell reports it), 255 for neither.
    #[test]
    fn exit_codes_follow_the_shell_and_a_signal_is_128_plus_its_number() {
        assert_eq!(exit_code(Some(0), None), 0);
        assert_eq!(exit_code(Some(42), None), 42);
        assert_eq!(exit_code(Some(70_000), None), 255, "more than a status can say is 255");
        assert_eq!(exit_code(None, Some("KILL")), 137);
        assert_eq!(exit_code(None, Some("TERM")), 143);
        assert_eq!(exit_code(None, Some("HUP")), 129);
        assert_eq!(exit_code(None, Some("WINCH")), 255, "a signal SSH does not name");
        assert_eq!(exit_code(None, None), 255, "a lost connection, as ssh");
    }
}
