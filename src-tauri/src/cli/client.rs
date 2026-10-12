//! The client's side of one session (own-ssh spec §7.3), with no I/O of its own: it is told what happened (`Input`) and answers with
//! what to do (`Action`); `run.rs` does the reading and writing. Until the shell is open the terminal stays as it was, so Ctrl-C still
//! stops the program; questions are asked with the terminal in its prompt mode; once the shell is open the terminal is raw and every
//! key goes to the shell; at the end the terminal is put back before anything is printed. Every text the broker wrote (a notice, a
//! question, a banner, an error) goes through `printable` before it is printed: the CLI does not trust the broker it talks to.

use zeroize::Zeroizing;

use super::terminal::Mode;
use crate::session::protocol::{kinds, ClientKind, ClientMessage, Event, HostQuery, PtyRequest, Question, QuestionKind, ServerMessage, DATA_CHUNK, PROTOCOL_VERSION};

/// What happened.
#[derive(Debug)]
pub enum Input {
    /// A control message from the broker.
    Message(ServerMessage),
    /// Terminal output from the broker.
    Output(Vec<u8>),
    /// The broker closed the connection.
    Closed,
    /// Bytes the person typed.
    Stdin(Vec<u8>),
    /// Standard input ended (Ctrl-D on an empty line, at a question).
    StdinEnd,
    /// The terminal was resized.
    Resize(u16, u16),
    /// Ctrl-C while the terminal was not raw (SIGINT).
    Interrupt,
    /// The program was told to stop, or its terminal went away (SIGTERM, SIGHUP): the signal's number.
    Stop(i32),
}

/// What to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Send(ClientMessage),
    SendData(Vec<u8>),
    Stdout(Vec<u8>),
    Stderr(String),
    /// Set the terminal's mode; `true` throws away what was typed ahead first.
    Mode(Mode, bool),
    Exit(i32),
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

/// What the person typed before the shell opened is kept for it (as OpenSSH's typeahead reaches the shell), up to this many bytes.
const TYPEAHEAD_LIMIT: usize = 64 * 1024;

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
    /// Bytes typed before the shell opened.
    typeahead: Zeroizing<Vec<u8>>,
    /// What to say when it ends: why the connection ended or failed.
    reason: Option<String>,
}

impl Client {
    /// A client that opens a shell on `host` for a terminal of type `term` and size `size`; the actions say hello and ask for the shell.
    pub fn start(host: HostQuery, term: String, size: (u16, u16)) -> (Client, Vec<Action>) {
        let client = Client { phase: Phase::Connecting, typeahead: Zeroizing::new(Vec::new()), reason: None };
        let actions = vec![
            Action::Send(ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }),
            Action::Send(ClientMessage::OpenShell { host, pty: PtyRequest { cols: size.0, rows: size.1, term } }),
        ];
        (client, actions)
    }

    fn mode(&self) -> Mode {
        match self.phase {
            Phase::Open => Mode::Raw,
            Phase::Asking { echo, .. } => Mode::Prompt { echo },
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
                self.finish(Some(reason), 255)
            }
            Input::Stdin(bytes) => self.typed(&bytes),
            Input::StdinEnd | Input::Interrupt if matches!(self.phase, Phase::Asking { .. }) => self.answer(None),
            Input::Interrupt => {
                let mut actions = vec![Action::Send(ClientMessage::Close)];
                actions.extend(self.finish(None, 130));
                actions
            }
            Input::StdinEnd => {
                let mut actions = vec![Action::Send(ClientMessage::Close)];
                actions.extend(self.finish(None, 128 + libc::SIGHUP));
                actions
            }
            Input::Resize(cols, rows) => vec![Action::Send(ClientMessage::WindowChange { cols, rows })],
            Input::Stop(signal) => {
                let mut actions = vec![Action::Send(ClientMessage::Close)];
                actions.extend(self.finish(None, 128 + signal));
                actions
            }
        }
    }

    fn message(&mut self, message: ServerMessage) -> Vec<Action> {
        match message {
            ServerMessage::Opened { .. } => {
                self.phase = Phase::Open;
                let mut actions = vec![Action::Mode(Mode::Raw, false)];
                if !self.typeahead.is_empty() {
                    actions.push(Action::SendData(std::mem::take(&mut *self.typeahead)));
                }
                actions
            }
            ServerMessage::Question(Question { kind: QuestionKind::HostKeyNotice, text, .. }) => vec![Action::Stderr(format!("{}\n", printable(&text)))],
            ServerMessage::Question(Question { question_id, text, echo, .. }) => {
                let after = self.mode();
                self.typeahead.clear();
                self.phase = Phase::Asking { question_id, echo, line: Zeroizing::new(Vec::new()), after };
                vec![Action::Mode(Mode::Prompt { echo }, true), Action::Stderr(printable(&text))]
            }
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
                self.finish(reason, exit_code(code, signal.as_deref()))
            }
        }
    }

    fn typed(&mut self, bytes: &[u8]) -> Vec<Action> {
        match &mut self.phase {
            Phase::Connecting => {
                let room = TYPEAHEAD_LIMIT.saturating_sub(self.typeahead.len());
                self.typeahead.extend_from_slice(&bytes[..bytes.len().min(room)]);
                Vec::new()
            }
            Phase::Asking { line, .. } => {
                line.extend_from_slice(bytes);
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
    fn answer(&mut self, answer: Option<Zeroizing<String>>) -> Vec<Action> {
        let Phase::Asking { question_id, echo, after, .. } = std::mem::replace(&mut self.phase, Phase::Connecting) else { return Vec::new() };
        self.phase = if after == Mode::Raw { Phase::Open } else { Phase::Connecting };
        let mut actions = Vec::new();
        if !echo || answer.is_none() {
            // The Enter of a hidden answer (or the Ctrl-C) did not move to the next line.
            actions.push(Action::Stderr("\n".to_string()));
        }
        let message = match answer {
            Some(answer) => ClientMessage::Answer { question_id, value: Some(answer.to_string()), cancel: false },
            None => ClientMessage::Answer { question_id, value: None, cancel: true },
        };
        actions.push(Action::Send(message));
        actions.push(Action::Mode(after, false));
        actions
    }

    /// The end: the terminal is put back first, then the reason is printed on a line of its own, then the program exits.
    fn finish(&mut self, reason: Option<String>, code: i32) -> Vec<Action> {
        let was_open = matches!(self.phase, Phase::Open) || matches!(self.phase, Phase::Asking { after: Mode::Raw, .. });
        self.phase = Phase::Ended;
        let mut actions = vec![Action::Mode(Mode::Cooked, false)];
        if let Some(reason) = reason {
            actions.push(Action::Stderr(if was_open { format!("\n{reason}\n") } else { format!("{reason}\n") }));
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
        assert_eq!(client.handle(Input::Stdin(b"ls\r".to_vec())), [Action::SendData(b"ls\r".to_vec())]);
        assert_eq!(client.handle(Input::Output(b"file\r\n".to_vec())), [Action::Stdout(b"file\r\n".to_vec())]);
        assert_eq!(client.handle(Input::Resize(100, 30)), [Action::Send(ClientMessage::WindowChange { cols: 100, rows: 30 })]);
        let pasted = vec![b'x'; DATA_CHUNK + 10];
        assert_eq!(client.handle(Input::Stdin(pasted)).len(), 2, "a large paste goes out in data frames of at most DATA_CHUNK bytes");
    }

    /// What was typed while connecting reaches the shell once it is open (OpenSSH behaves the same).
    #[test]
    fn typeahead_reaches_the_shell_once_it_opens() {
        let mut client = started();
        assert!(client.handle(Input::Stdin(b"uptime\n".to_vec())).is_empty());
        assert_eq!(client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() })), [Action::Mode(Mode::Raw, false), Action::SendData(b"uptime\n".to_vec())]);
    }

    /// Spec §7.3: a question leaves raw mode (or the terminal as it was), asks without echo for a password, sends the answer and goes
    /// back; typeahead is thrown away, so it cannot become the password.
    #[test]
    fn a_password_question_is_asked_without_echo_and_the_answer_is_sent() {
        let mut client = started();
        client.handle(Input::Stdin(b"ls\n".to_vec()));
        assert_eq!(
            client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false)),
            [Action::Mode(Mode::Prompt { echo: false }, true), Action::Stderr("deploy@web's password: ".into())]
        );
        assert!(client.handle(Input::Stdin(b"hunt".to_vec())).is_empty(), "the answer is collected until Enter");
        assert_eq!(
            client.handle(Input::Stdin(b"er2\n".to_vec())),
            [
                Action::Stderr("\n".into()),
                Action::Send(ClientMessage::Answer { question_id: "q1".into(), value: Some("hunter2".into()), cancel: false }),
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
            client.handle(Input::Stdin(b"123456\r\n".to_vec())),
            [Action::Send(ClientMessage::Answer { question_id: "q2".into(), value: Some("123456".into()), cancel: false }), Action::Mode(Mode::Raw, false)]
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
        assert_eq!(client.handle(Input::Stdin(b"x".to_vec())), [Action::SendData(b"x".to_vec())]);
    }

    #[test]
    fn the_broker_going_away_or_a_signal_ends_the_program_with_the_terminal_put_back() {
        let mut client = opened();
        assert_eq!(client.handle(Input::Closed), [Action::Mode(Mode::Cooked, false), Action::Stderr("\nThe connection to SSHelter ended.\n".into()), Action::Exit(255)]);
        let mut client = opened();
        assert_eq!(client.handle(Input::Stop(libc::SIGTERM)), [Action::Send(ClientMessage::Close), Action::Mode(Mode::Cooked, false), Action::Exit(128 + libc::SIGTERM)]);
        let mut client = started();
        assert_eq!(client.handle(Input::Interrupt), [Action::Send(ClientMessage::Close), Action::Mode(Mode::Cooked, false), Action::Exit(130)], "Ctrl-C while connecting stops it");
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

    /// The shell's own bytes are not the CLI's to change: that is what a terminal program is for.
    #[test]
    fn the_shells_own_output_is_passed_through_untouched() {
        let mut client = opened();
        let output = b"\x1b[2J\r\n\xc2\x9b\xe2\x80\xae\x07\x00".to_vec();
        assert_eq!(client.handle(Input::Output(output.clone())), [Action::Stdout(output)]);
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
