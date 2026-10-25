//! The client's side of one session (own-ssh spec §7.3), with no I/O of its own: it is told what happened (`Input`) and answers with
//! what to do (`Action`); `run.rs` does the reading and writing. Until the shell is open the terminal stays as it was, so Ctrl-C still
//! stops the program; questions are asked with the terminal in its prompt mode; once the shell is open the terminal is raw and every
//! key goes to the shell; at the end the terminal is put back before anything is printed. Every text the broker wrote (a notice, a
//! question, a banner, an error) goes through `printable` before it is printed: the CLI does not trust the broker it talks to.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use super::signal;
use super::terminal::{Mode, QUESTION_READ_ENDS_ITS_LINE};
use crate::session::protocol::{kinds, ClientKind, ClientMessage, Event, HostQuery, PtyRequest, Question, QuestionKind, ServerMessage, DATA_CHUNK, PROTOCOL_VERSION};

/// What happened.
pub enum Input {
    /// A control message from the broker.
    Message(ServerMessage),
    /// Terminal output from the broker.
    Output(Vec<u8>),
    /// The broker closed the connection.
    Closed,
    /// The broker sent a control message this version of the CLI cannot read. Within one protocol version (`hello` checked it) that is
    /// a bug of the app, and the session cannot go on without it: a question in it would wait, unanswered, for the broker's deadline.
    Unreadable,
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
    /// The program runs again after it was stopped (SIGCONT; Ctrl-Z put the terminal back, and the signal thread has set the mode again):
    /// a question on the terminal is asked again, from the start, as OpenSSH's readpassphrase does.
    Continue,
}

/// What was typed may be a password, so the debug form leaves it out (as `ClientMessage`'s does for an answer); the rest prints as a
/// derived `Debug` would.
impl fmt::Debug for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Input::Message(message) => f.debug_tuple("Message").field(message).finish(),
            Input::Output(bytes) => f.debug_tuple("Output").field(bytes).finish(),
            Input::Closed => f.write_str("Closed"),
            Input::Unreadable => f.write_str("Unreadable"),
            Input::Stdin(_) => f.write_str("Stdin(<hidden>)"),
            Input::StdinEnd => f.write_str("StdinEnd"),
            Input::Resize(cols, rows) => f.debug_tuple("Resize").field(cols).field(rows).finish(),
            Input::Interrupt => f.write_str("Interrupt"),
            Input::Stop(signal) => f.debug_tuple("Stop").field(signal).finish(),
            Input::Failed => f.write_str("Failed"),
            Input::Continue => f.write_str("Continue"),
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
    /// After a change of mode that left a question: a line break of the CLI's own, unless the terminal ended the question's line itself,
    /// which only the change of mode can tell (the Windows console ends it when a line read of the question ends:
    /// `QUESTION_READ_ENDS_ITS_LINE`, `Tty::question_line_ended`). Only where the terminal can end the line itself.
    EndQuestionLine,
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
            Action::EndQuestionLine => f.write_str("EndQuestionLine"),
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

/// What `sshelter connect` was asked for (spec §7.3): the host, and whether a failure before the shell opens waits for Enter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub host: HostQuery,
    /// `--pause-on-error`: when the connection fails before the shell opens, the reason stays on the terminal under `PAUSE_PROMPT` and the
    /// program exits once Enter is pressed. Lunport's Connect gives it to a terminal that runs the command as its window's program, which
    /// would close the window, and the reason with it, as the program ends (spec §7.4).
    pub pause_on_error: bool,
}

impl From<HostQuery> for Request {
    fn from(host: HostQuery) -> Request {
        Request { host, pause_on_error: false }
    }
}

/// What `--pause-on-error` puts under the reason of a failure before the shell opened (spec §7.3, §11). It says what Enter does to the
/// program, not to the window: Windows Terminal, among others, may keep a window whose program ended with an error.
pub const PAUSE_PROMPT: &str = "Press Enter to exit.";

/// The terminal's mode while `PAUSE_PROMPT` waits for Enter (`Client::pause_prompt`): a question's, so that the keys are read (the Windows
/// console reads nothing while it is cooked), with what is typed hidden. Enter is all the pause needs, and after a failed login a password
/// typed again by habit must not be shown.
const PAUSE_MODE: Mode = Mode::Prompt { echo: false };

/// What is said when a thread of the program panicked (the panic itself was reported by the hook, which put the terminal back first).
const THREAD_FAILED: &str = "sshelter: an internal error stopped this session.";

/// What is said when the broker sent a control message this CLI cannot read (`Input::Unreadable`).
const UNREADABLE: &str = "Lunport sent a message this version of sshelter cannot read. Quit Lunport and open it again.";

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
    /// A question is on the terminal (`prompt`, as it was printed); the answer is collected until Enter.
    Asking { question_id: String, echo: bool, line: Zeroizing<Vec<u8>>, after: Mode, prompt: String },
    Open,
    /// `--pause-on-error`: the connection failed before the shell opened, its reason and `PAUSE_PROMPT` are on the terminal, and the
    /// program exits with `code` once Enter is pressed (`Client::paused`).
    Pausing { code: i32 },
    Ended,
}

/// The exit status of `sshelter connect` for a shell that ended with `code` or was killed by `signal` (spec §7.3): the shell's own
/// status; for a signal 128 + its number, as a shell reports it; 255 when it ended without either (a lost connection), as ssh does.
pub fn exit_code(code: Option<u32>, signal: Option<&str>) -> i32 {
    match (code, signal) {
        (Some(code), _) => code.min(255) as i32,
        (None, Some(name)) => signal::number(name).map(|number| 128 + number).unwrap_or(255),
        (None, None) => 255,
    }
}

/// The client of one session.
pub struct Client {
    phase: Phase,
    /// Bytes typed before the shell opened. Reserved in full at the start, so that it does not move while it grows.
    typeahead: Zeroizing<Vec<u8>>,
    /// What to say when it ends: why the connection ended or failed.
    reason: Option<String>,
    /// `Request::pause_on_error`.
    pause_on_error: bool,
    /// The person cancelled the question that was on the terminal (Ctrl-C, or the end of input) and no question was asked since: the
    /// broker gives the connect up after it, and that end is the person's, so it does not pause.
    cancelled: bool,
}

impl Client {
    /// A client that opens a shell on the host `request` names for a terminal of type `term` and size `size`; the actions say hello and ask
    /// for the shell.
    pub fn start(request: impl Into<Request>, term: String, size: (u16, u16)) -> (Client, Vec<Action>) {
        let Request { host, pause_on_error } = request.into();
        let typeahead = Zeroizing::new(Vec::with_capacity(TYPEAHEAD_LIMIT));
        let client = Client { phase: Phase::Connecting, typeahead, reason: None, pause_on_error, cancelled: false };
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
            Phase::Connecting | Phase::Pausing { .. } | Phase::Ended => Mode::Cooked,
        }
    }

    pub fn handle(&mut self, input: Input) -> Vec<Action> {
        match self.phase {
            Phase::Ended => return Vec::new(),
            Phase::Pausing { code } => return self.paused(input, code),
            Phase::Connecting | Phase::Asking { .. } | Phase::Open => {}
        }
        match input {
            Input::Message(message) => self.message(message),
            Input::Output(bytes) => vec![Action::Stdout(bytes)],
            Input::Closed => {
                let reason = self.reason.take().unwrap_or_else(|| "The connection to Lunport ended.".to_string());
                self.finish(false, Some(reason), 255)
            }
            // The broker sees the stream end when the program exits: no `close` is needed.
            Input::Unreadable => self.finish(false, Some(UNREADABLE.to_string()), 255),
            Input::Stdin(bytes) => self.typed(&bytes),
            // The end of input at a question is a line of its own on Windows (Ctrl-Z and Enter: the console ended the line), Ctrl-D on
            // Unix (the terminal did not); Ctrl-C does not end the line.
            Input::StdinEnd if matches!(self.phase, Phase::Asking { .. }) => {
                self.cancelled = true;
                self.answer(None, QUESTION_READ_ENDS_ITS_LINE)
            }
            Input::Interrupt if matches!(self.phase, Phase::Asking { .. }) => {
                self.cancelled = true;
                self.answer(None, false)
            }
            Input::Interrupt => self.finish(true, None, 130),
            Input::StdinEnd => self.finish(true, None, 128 + signal::HUP),
            Input::Resize(cols, rows) => vec![Action::Send(ClientMessage::WindowChange { cols, rows })],
            Input::Stop(signal) => self.finish(true, None, 128 + signal),
            Input::Failed => self.finish(true, Some(THREAD_FAILED.to_string()), 255),
            Input::Continue => self.continued(),
        }
    }

    fn message(&mut self, message: ServerMessage) -> Vec<Action> {
        match message {
            ServerMessage::Opened { .. } => self.opened(),
            ServerMessage::Question(Question { kind: QuestionKind::HostKeyNotice, text, .. }) => vec![Action::Stderr(format!("{}\n", printable(&text)))],
            // A grant is requested in Lunport's window, never typed here: a broker without a window is told so at once, and its connect
            // fails with the refusal sentence instead of waiting for an answer nobody can give.
            ServerMessage::Question(Question { kind: QuestionKind::Grant, question_id, .. }) => vec![cancel(question_id)],
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
        self.cancelled = false;
        let prompt = printable(text);
        actions.push(Action::Mode(Mode::Prompt { echo }, true));
        actions.push(Action::Stderr(prompt.clone()));
        self.phase = Phase::Asking { question_id, echo, line: Zeroizing::new(Vec::with_capacity(ANSWER_CAPACITY)), after, prompt };
        actions
    }

    /// The program runs again after a stop. A question on the terminal starts over: what was collected of its answer is wiped, what was
    /// typed meanwhile is thrown away with the terminal's pending input, and the prompt is printed again (the shell printed its own
    /// lines while the program was stopped). Anything else goes on as it was.
    fn continued(&mut self) -> Vec<Action> {
        match &mut self.phase {
            Phase::Asking { echo, line, prompt, .. } => {
                line.zeroize();
                vec![Action::Mode(Mode::Prompt { echo: *echo }, true), Action::Stderr(prompt.clone())]
            }
            Phase::Connecting | Phase::Open | Phase::Pausing { .. } | Phase::Ended => Vec::new(),
        }
    }

    fn typed(&mut self, bytes: &[u8]) -> Vec<Action> {
        match &mut self.phase {
            Phase::Connecting => {
                let room = TYPEAHEAD_LIMIT.saturating_sub(self.typeahead.len());
                self.typeahead.extend_from_slice(&bytes[..bytes.len().min(room)]);
                Vec::new()
            }
            Phase::Asking { line, echo, .. } => {
                let echo = *echo;
                keep(line, bytes);
                match line.iter().position(|byte| *byte == b'\n' || *byte == b'\r') {
                    Some(end) => {
                        let answer = Zeroizing::new(String::from_utf8_lossy(&line[..end]).into_owned());
                        // The Enter moved the terminal to the next line where it shows the answer, and where the terminal ends a
                        // question's line whatever it shows (the Windows console); a Unix terminal that hides the answer did not move.
                        self.answer(Some(answer), echo || QUESTION_READ_ENDS_ITS_LINE)
                    }
                    None => Vec::new(),
                }
            }
            Phase::Open => bytes.chunks(DATA_CHUNK).map(|chunk| Action::SendData(chunk.to_vec())).collect(),
            Phase::Pausing { .. } | Phase::Ended => Vec::new(),
        }
    }

    /// Ends the question on the terminal: with the answer, or cancelled (`None`). `line_ended`: what ended it moved the terminal to the
    /// next line; otherwise the CLI starts the next line itself.
    ///
    /// The password goes on in the `Zeroizing` string it was collected in, inside `Action::Answer`; whoever writes the action out
    /// (`run.rs`) writes it from there, and it is wiped when the action is dropped.
    fn answer(&mut self, answer: Option<Zeroizing<String>>, line_ended: bool) -> Vec<Action> {
        let (question_id, after) = match std::mem::replace(&mut self.phase, Phase::Connecting) {
            Phase::Asking { question_id, after, .. } => (question_id, after),
            other => {
                // No question is on the terminal: there is nothing to answer, and nothing changes.
                self.phase = other;
                return Vec::new();
            }
        };
        self.phase = if after == Mode::Raw { Phase::Open } else { Phase::Connecting };
        let mut actions = Vec::new();
        if !line_ended {
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
    /// and the program exits. With `--pause-on-error`, an end with a reason that neither the program nor the person chose (the broker
    /// ended the session or went away, or sent what the CLI cannot read; not the end that follows a question the person cancelled) and
    /// that comes before the shell opened does not exit yet: the broker is told `close` at once (nothing more is said to it, and its
    /// connection is not kept for as long as the pause lasts), and `PAUSE_PROMPT` follows the reason (`Phase::Pausing`).
    fn finish(&mut self, close: bool, reason: Option<String>, code: i32) -> Vec<Action> {
        // The cursor is not at the start of a line while the shell is open (it can be anywhere in what the shell wrote), nor while a
        // question's prompt is on it, whatever the terminal was before the question: unless the terminal ends the question's line when its
        // read ends, as the Windows console does when this end throws what was typed away (`QUESTION_READ_ENDS_ITS_LINE`). Whether it did
        // is known only once the mode was changed (no line read of the question may have been in progress), so there the loop starts the
        // line when the console has not (`Action::EndQuestionLine`).
        let mid_line = match self.phase {
            Phase::Open => true,
            Phase::Asking { .. } => !QUESTION_READ_ENDS_ITS_LINE,
            Phase::Connecting | Phase::Pausing { .. } | Phase::Ended => false,
        };
        // What was typed for a question and not sent (a part of a password, or of a code) was meant for Lunport: it is thrown away with
        // what the terminal holds, as readpassphrase does, or the shell that gets the terminal next reads it, shows it on its line and
        // keeps it in its history. Outside a question what is typed is the shell's, and stays.
        let at_a_question = matches!(self.phase, Phase::Asking { .. });
        // The shell has opened when the terminal rests raw: in the open shell, and at a question asked there. Without a reason there is
        // nothing to keep on the screen (the app quit while the shell was being opened, and the remote's end came first).
        let pause = self.pause_on_error && !close && !self.cancelled && reason.is_some() && self.resting_mode() != Mode::Raw;
        self.phase = if pause { Phase::Pausing { code } } else { Phase::Ended };
        let mut actions = vec![Action::Mode(Mode::Cooked, at_a_question)];
        if close || pause {
            actions.push(Action::Send(ClientMessage::Close));
        }
        if let Some(reason) = reason {
            if at_a_question && QUESTION_READ_ENDS_ITS_LINE {
                actions.push(Action::EndQuestionLine);
            }
            actions.push(Action::Stderr(if mid_line { format!("\n{reason}\n") } else { format!("{reason}\n") }));
        }
        if pause {
            actions.extend(Self::pause_prompt());
        } else {
            actions.push(Action::Exit(code));
        }
        actions
    }

    /// The pause's prompt, in a question's mode with what is typed hidden (`PAUSE_MODE`), what was typed before thrown away: a line typed
    /// while connecting must not end the pause before its prompt was seen.
    fn pause_prompt() -> [Action; 2] {
        [Action::Mode(PAUSE_MODE, true), Action::Stderr(PAUSE_PROMPT.to_string())]
    }

    /// `--pause-on-error`, with the reason and `PAUSE_PROMPT` on the terminal (`Phase::Pausing`): Enter ends the program with the failure's
    /// status `code`. The other ways out end it at once, with the status they give anywhere else (Ctrl-C 130, a stop signal or the terminal
    /// gone 128 + the signal, Ctrl-D 128 + SIGHUP, a thread that failed 255). The program's last words start a line of their own below the
    /// prompt, unless the terminal moved there itself: the Windows console does when a line read ends, on Enter or on a line that starts
    /// with Ctrl-Z (`QUESTION_READ_ENDS_ITS_LINE`); the hidden Enter on a Unix terminal does not. SIGCONT (after Ctrl-Z) puts the prompt up
    /// again, as it does a question's. Nothing else changes anything: the broker was told `close`, and its last frames, its end and a
    /// resize are not waited for. The terminal is put back at the exit (`run.rs`).
    fn paused(&mut self, input: Input, code: i32) -> Vec<Action> {
        let line = |ended: bool| (!ended).then(|| "\n".to_string());
        let (said, status) = match input {
            Input::Stdin(bytes) if bytes.iter().any(|byte| *byte == b'\n' || *byte == b'\r') => (line(QUESTION_READ_ENDS_ITS_LINE), code),
            Input::Interrupt => (line(false), 130),
            Input::Stop(signal) => (line(false), 128 + signal),
            Input::StdinEnd => (line(QUESTION_READ_ENDS_ITS_LINE), 128 + signal::HUP),
            Input::Failed => (Some(format!("\n{THREAD_FAILED}\n")), 255),
            Input::Continue => return Self::pause_prompt().into(),
            Input::Stdin(_) | Input::Message(_) | Input::Output(_) | Input::Closed | Input::Unreadable | Input::Resize(..) => return Vec::new(),
        };
        self.phase = Phase::Ended;
        said.map(Action::Stderr).into_iter().chain([Action::Exit(status)]).collect()
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
        assert_eq!(
            data_frames(&client.handle(Input::Stdin(Zeroizing::new(pasted)))).iter().map(Vec::len).collect::<Vec<_>>(),
            [DATA_CHUNK, 10],
            "a large paste goes out in data frames of at most DATA_CHUNK bytes"
        );
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
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"er2\n".to_vec()))), hidden_answer("q1", "hunter2", Mode::Cooked));
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

    /// Ctrl-C at a question, and the end of input (Ctrl-D on Unix, a line that starts with Ctrl-Z on Windows), cancel it. The CLI ends the
    /// question's line itself after Ctrl-C, and after Ctrl-D (the terminal did not); not after Ctrl-Z, whose Enter ended the line already
    /// (the Windows console ends a question's line when its line read ends: `QUESTION_READ_ENDS_ITS_LINE`).
    #[test]
    fn ctrl_c_or_ctrl_d_at_a_question_cancels_it() {
        for (input, line_ended) in [(Input::Interrupt, false), (Input::StdinEnd, QUESTION_READ_ENDS_ITS_LINE)] {
            let mut client = started();
            client.handle(question("q1", QuestionKind::Passphrase, "Enter the passphrase for the key laptop: ", false));
            let mut expected = if line_ended { vec![] } else { vec![Action::Stderr("\n".into())] };
            expected.extend([cancelled("q1"), Action::Mode(Mode::Cooked, false)]);
            assert_eq!(client.handle(input), expected);
        }
    }

    #[test]
    fn the_host_key_notice_and_a_banner_are_printed_and_need_no_answer() {
        let mut client = started();
        assert_eq!(
            client.handle(question("q1", QuestionKind::HostKeyNotice, "Waiting for you to confirm web's host key in Lunport.", false)),
            [Action::Stderr("Waiting for you to confirm web's host key in Lunport.\n".into())]
        );
        assert_eq!(client.handle(Input::Message(ServerMessage::Event(Event::Banner { text: "Authorized use only.".into() }))), [Action::Stderr("Authorized use only.\n".into())]);
    }

    /// A grant is requested in Lunport's window, never typed at the terminal: a broker without a window (none in the app) is told so at once,
    /// so that the connect fails with the refusal sentence instead of waiting five minutes for an answer nobody can give.
    #[test]
    fn a_grant_question_cannot_be_answered_in_the_terminal_and_is_cancelled() {
        use crate::session::protocol::GrantPrompt;
        let mut client = started();
        let prompt = GrantPrompt { project: "acme-prod-123456".into(), entitlement: "prod-operate".into(), minutes: 30, justification: None };
        assert_eq!(client.handle(question("g1", QuestionKind::Grant, &prompt.to_text(), true)), [cancel("g1".into())]);
        assert!(matches!(client.phase, Phase::Connecting), "no prompt mode is opened for it");
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
        assert_eq!(client.handle(Input::Closed), [Action::Mode(Mode::Cooked, false), Action::Stderr("\nThe connection to Lunport ended.\n".into()), Action::Exit(255)]);
        let mut client = opened();
        assert_eq!(client.handle(Input::Stop(signal::TERM)), [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Exit(128 + signal::TERM)]);
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
        assert_eq!(opened().handle(Input::Stop(signal::HUP)), hangup);
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

    /// A control message the CLI cannot read is a bug of the app within one protocol version (`hello` checked the version): the session
    /// ends, with a sentence that says what to do, as the broker ends a connection that sends it one it cannot read (`kinds::PROTOCOL`),
    /// instead of going on without it.
    #[test]
    fn a_message_the_cli_cannot_read_ends_the_session_with_a_sentence() {
        const SENTENCE: &str = "Lunport sent a message this version of sshelter cannot read. Quit Lunport and open it again.";
        assert_eq!(started().handle(Input::Unreadable), [Action::Mode(Mode::Cooked, false), Action::Stderr(format!("{SENTENCE}\n")), Action::Exit(255)]);
        assert_eq!(
            opened().handle(Input::Unreadable),
            [Action::Mode(Mode::Cooked, false), Action::Stderr(format!("\n{SENTENCE}\n")), Action::Exit(255)],
            "the cursor is somewhere in what the shell wrote"
        );
    }

    /// A client started with `--pause-on-error` (Lunport's Connect, in a terminal that closes its window with the program).
    fn pausing() -> Client {
        Client::start(Request { host: HostQuery::Alias("web".into()), pause_on_error: true }, "xterm-256color".into(), (80, 24)).0
    }

    /// A `pausing` client at the pause: the broker went away before the shell opened.
    fn paused() -> Client {
        let mut client = pausing();
        client.handle(Input::Closed);
        assert!(matches!(client.phase, Phase::Pausing { code: 255 }));
        client
    }

    fn typed(text: &str) -> Input {
        Input::Stdin(Zeroizing::new(text.as_bytes().to_vec()))
    }

    /// The pause ended by Enter, with `code`: the hidden Enter does not move a Unix terminal to the next line, so the CLI does; the
    /// Windows console moves there itself when the line read ends (`QUESTION_READ_ENDS_ITS_LINE`).
    fn entered(code: i32) -> Vec<Action> {
        let mut actions = if QUESTION_READ_ENDS_ITS_LINE { vec![] } else { vec![Action::Stderr("\n".into())] };
        actions.push(Action::Exit(code));
        actions
    }

    /// Spec §7.3, `--pause-on-error`: a connection that fails before the shell opens leaves its reason on the terminal, the broker is told
    /// `close` at once (nothing more is said to it), and the prompt asks for Enter in the mode of a question that hides what is typed (the
    /// Windows console reads nothing while it is cooked; a password typed again by habit is not shown), what was typed before thrown
    /// away; the program exits with the failure's status only once Enter is pressed. What comes meanwhile (the broker's end, a resize, a
    /// line not ended yet) changes nothing.
    #[test]
    fn with_pause_on_error_a_failure_before_the_shell_opens_waits_for_enter() {
        assert_eq!(PAUSE_PROMPT, "Press Enter to exit.");
        let mut client = pausing();
        assert!(client.handle(error(kinds::HOST, "No saved host is called web.")).is_empty());
        assert_eq!(
            client.handle(exited()),
            [
                Action::Mode(Mode::Cooked, false),
                Action::Send(ClientMessage::Close),
                Action::Stderr("No saved host is called web.\n".into()),
                Action::Mode(Mode::Prompt { echo: false }, true),
                Action::Stderr(PAUSE_PROMPT.into()),
            ]
        );
        for meanwhile in [Input::Closed, Input::Unreadable, Input::Resize(100, 30), Input::Output(b"late".to_vec()), exited(), opens(), typed("par")] {
            let said = format!("{meanwhile:?}");
            assert!(client.handle(meanwhile).is_empty(), "{said} changes nothing at the pause");
        }
        assert_eq!(client.handle(typed("tial\n")), entered(255), "the line typed meanwhile ends with Enter");
        assert!(client.handle(typed("\n")).is_empty(), "nothing after the end");
    }

    /// The broker going away, and a message the CLI cannot read, pause like any other failure before the shell opens; the Windows console
    /// gives Enter as CRLF.
    #[test]
    fn with_pause_on_error_the_broker_going_away_or_a_message_the_cli_cannot_read_waits_for_enter() {
        let mut client = pausing();
        assert_eq!(
            client.handle(Input::Closed),
            [
                Action::Mode(Mode::Cooked, false),
                Action::Send(ClientMessage::Close),
                Action::Stderr("The connection to Lunport ended.\n".into()),
                Action::Mode(Mode::Prompt { echo: false }, true),
                Action::Stderr(PAUSE_PROMPT.into()),
            ]
        );
        assert_eq!(client.handle(typed("\r\n")), entered(255));
        let mut client = pausing();
        assert_eq!(
            client.handle(Input::Unreadable),
            [
                Action::Mode(Mode::Cooked, false),
                Action::Send(ClientMessage::Close),
                Action::Stderr(format!("{UNREADABLE}\n")),
                Action::Mode(Mode::Prompt { echo: false }, true),
                Action::Stderr(PAUSE_PROMPT.into()),
            ]
        );
        assert_eq!(client.handle(typed("\r")), entered(255));
    }

    /// A failure under a question (the broker gave up on it) ends the question as any end under one does (what was typed for it is thrown
    /// away, the reason on a line of its own), then asks for Enter.
    #[test]
    fn with_pause_on_error_a_failure_under_a_question_ends_the_question_then_waits_for_enter() {
        let mut client = pausing();
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
        client.handle(typed("hun"));
        assert!(client.handle(error(kinds::AUTH, "Authentication for web was abandoned (no answer in time).")).is_empty());
        assert_eq!(
            client.handle(exited()),
            joined(vec![
                vec![Action::Mode(Mode::Cooked, true), Action::Send(ClientMessage::Close)],
                under_a_question("Authentication for web was abandoned (no answer in time)."),
                vec![Action::Mode(Mode::Prompt { echo: false }, true), Action::Stderr(PAUSE_PROMPT.into())],
            ])
        );
        assert_eq!(client.handle(typed("\n")), entered(255));
    }

    /// The pause is for a failure the person did not choose, before the shell opened: Ctrl-C, Ctrl-D, a stop signal and a thread that failed
    /// end the program at once as they do without `--pause-on-error`, and so does every end once the shell has opened, a question asked in
    /// the open shell included.
    #[test]
    fn the_pause_is_only_for_a_failure_before_the_shell_opens_that_the_person_did_not_choose() {
        let ends = || [Input::Interrupt, Input::StdinEnd, Input::Stop(signal::TERM), Input::Failed];
        for (with, without) in ends().into_iter().zip(ends()) {
            let said = format!("{with:?}");
            assert_eq!(pausing().handle(with), started().handle(without), "{said} while connecting");
        }
        let opened_pausing = || {
            let mut client = pausing();
            client.handle(opens());
            client
        };
        let after_open = || [Input::Closed, Input::Unreadable, Input::Message(ServerMessage::Exited { code: Some(3), signal: None }), Input::Interrupt, Input::Failed];
        for (with, without) in after_open().into_iter().zip(after_open()) {
            let said = format!("{with:?}");
            assert_eq!(opened_pausing().handle(with), opened().handle(without), "{said} once the shell is open");
        }
        let mut client = opened_pausing();
        client.handle(question("q2", QuestionKind::Interactive, "(deploy@web) Code: ", true));
        let mut plain = opened();
        plain.handle(question("q2", QuestionKind::Interactive, "(deploy@web) Code: ", true));
        assert_eq!(client.handle(Input::Closed), plain.handle(Input::Closed), "a question in the open shell is after the shell opened");
    }

    /// At the pause, Ctrl-C, Ctrl-D, a stop signal (the window closed, SIGTERM) and a thread that failed end the program at once, with the
    /// status they give anywhere else, on a line of its own (the prompt is the last line; the Windows console moves to the next one itself
    /// when a line that starts with Ctrl-Z ends its read); SIGCONT puts the prompt up again.
    #[test]
    fn at_the_pause_other_ends_end_the_program_at_once_on_a_line_of_their_own() {
        for (input, code) in [(Input::Interrupt, 130), (Input::Stop(signal::HUP), 129), (Input::Stop(signal::TERM), 128 + signal::TERM)] {
            let said = format!("{input:?}");
            assert_eq!(paused().handle(input), [Action::Stderr("\n".into()), Action::Exit(code)], "{said}");
        }
        let ended_by_its_line = if QUESTION_READ_ENDS_ITS_LINE { vec![] } else { vec![Action::Stderr("\n".into())] };
        assert_eq!(paused().handle(Input::StdinEnd), joined(vec![ended_by_its_line, vec![Action::Exit(129)]]));
        assert_eq!(paused().handle(Input::Failed), [Action::Stderr(format!("\n{THREAD_FAILED}\n")), Action::Exit(255)]);
        let mut client = paused();
        assert_eq!(client.handle(Input::Continue), [Action::Mode(Mode::Prompt { echo: false }, true), Action::Stderr(PAUSE_PROMPT.into())]);
        assert_eq!(client.handle(typed("\n")), entered(255));
    }

    /// A question the person cancelled (Ctrl-C, or the end of input) makes the broker give the connect up: that end is the person's and
    /// does not pause, as Ctrl-C while connecting does not. A question asked after it makes a later failure the broker's again.
    #[test]
    fn the_end_after_a_question_the_person_cancelled_does_not_pause() {
        let abandoned = "Authentication for web was abandoned (the password was not given).";
        for cancel in [Input::Interrupt, Input::StdinEnd] {
            let mut client = pausing();
            client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
            client.handle(cancel);
            client.handle(error(kinds::AUTH, abandoned));
            assert_eq!(client.handle(exited()), [Action::Mode(Mode::Cooked, false), Action::Stderr(format!("{abandoned}\n")), Action::Exit(255)]);
        }
        let mut client = pausing();
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
        client.handle(Input::Interrupt);
        client.handle(question("q2", QuestionKind::Interactive, "(deploy@web) Code: ", true));
        client.handle(error(kinds::AUTH, "Authentication failed for deploy@web (tried: keyboard-interactive)."));
        let actions = client.handle(exited());
        assert_eq!(actions.last(), Some(&Action::Stderr(PAUSE_PROMPT.into())), "{actions:?}");
    }

    /// An end with no reason (the app quit while the shell was being opened, and the remote's own end came first) has nothing to keep on
    /// the screen: it does not pause.
    #[test]
    fn an_end_without_a_reason_does_not_pause() {
        let mut client = pausing();
        assert_eq!(client.handle(Input::Message(ServerMessage::Exited { code: Some(3), signal: None })), [Action::Mode(Mode::Cooked, false), Action::Exit(3)]);
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

    /// The hidden answer `value` to `id` sent: after a line break of the CLI's own when the terminal did not end the line on Enter (a Unix
    /// terminal; the Windows console does: `QUESTION_READ_ENDS_ITS_LINE`), then the mode the question goes back to, `after`.
    fn hidden_answer(id: &str, value: &str, after: Mode) -> Vec<Action> {
        let mut actions = if QUESTION_READ_ENDS_ITS_LINE { vec![] } else { vec![Action::Stderr("\n".into())] };
        actions.extend([answered(id, value), Action::Mode(after, false)]);
        actions
    }

    /// What the CLI says at an end that comes under a question: on a line of its own, which it starts itself; on a terminal that ends the
    /// question's line when a line read of it ends (the Windows console: `QUESTION_READ_ENDS_ITS_LINE`), only if no line read ended, which
    /// only the change of mode tells (`Action::EndQuestionLine`).
    fn under_a_question(text: &str) -> Vec<Action> {
        if QUESTION_READ_ENDS_ITS_LINE {
            vec![Action::EndQuestionLine, Action::Stderr(format!("{text}\n"))]
        } else {
            vec![Action::Stderr(format!("\n{text}\n"))]
        }
    }

    /// `parts`, one after the other.
    fn joined(parts: Vec<Vec<Action>>) -> Vec<Action> {
        parts.into_iter().flatten().collect()
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
                joined(vec![
                    vec![Action::Mode(Mode::Cooked, true)],
                    under_a_question("Authentication for web was abandoned (the password prompt timed out)."),
                    vec![Action::Exit(255)],
                ])
            );
        }
        let mut client = started();
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
        assert_eq!(
            client.handle(Input::Closed),
            joined(vec![vec![Action::Mode(Mode::Cooked, true)], under_a_question("The connection to Lunport ended."), vec![Action::Exit(255)]])
        );
    }

    /// The actions with which the session ends when `inputs` come while a question is on the terminal (`echo` or not; asked while connecting,
    /// or in the open shell when `in_the_shell`), after a part of an answer was typed without Enter.
    fn ending_under_a_question(echo: bool, in_the_shell: bool, inputs: Vec<Input>) -> Vec<Action> {
        let mut client = if in_the_shell { opened() } else { started() };
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", echo));
        assert!(client.handle(Input::Stdin(Zeroizing::new(b"hun".to_vec()))).is_empty());
        inputs.into_iter().map(|input| client.handle(input)).last().unwrap()
    }

    /// What was typed at a question and not sent yet (a part of a password: no Enter yet) was meant for Lunport. However the session ends
    /// under the question, the terminal is put back with what it holds thrown away, as readpassphrase does: otherwise the shell that gets
    /// the terminal next reads it, shows it on its line and keeps it in its history (measured with bash 5 and zsh 5.9). One case for each
    /// way the program ends; the questions that show what is typed, and those asked in the open shell, the same.
    #[test]
    fn an_end_under_a_question_throws_away_what_was_typed_for_it() {
        const ABANDONED: &str = "Authentication for web was abandoned (the password prompt timed out).";
        const LOST: &str = "Connection to web lost (early eof).";
        let on_its_own_line = under_a_question;
        type Case = (&'static str, fn() -> Vec<Input>, Vec<Action>);
        let cases: Vec<Case> = vec![
            ("SIGTERM", || vec![Input::Stop(signal::TERM)], vec![Action::Send(ClientMessage::Close), Action::Exit(143)]),
            ("SIGHUP, or the terminal went away", || vec![Input::Stop(signal::HUP)], vec![Action::Send(ClientMessage::Close), Action::Exit(129)]),
            ("SIGQUIT", || vec![Input::Stop(signal::QUIT)], vec![Action::Send(ClientMessage::Close), Action::Exit(131)]),
            ("a thread of the program failed", || vec![Input::Failed], joined(vec![vec![Action::Send(ClientMessage::Close)], on_its_own_line(THREAD_FAILED), vec![Action::Exit(255)]])),
            ("the broker went away", || vec![Input::Closed], joined(vec![on_its_own_line("The connection to Lunport ended."), vec![Action::Exit(255)]])),
            ("the broker ended the session", || vec![exited()], vec![Action::Exit(255)]),
            ("the broker's error, then the end", || vec![error(kinds::AUTH, ABANDONED), exited()], joined(vec![on_its_own_line(ABANDONED), vec![Action::Exit(255)]])),
            ("the connection was lost", || vec![event(Event::Disconnected { reason: LOST.into() }), exited()], joined(vec![on_its_own_line(LOST), vec![Action::Exit(255)]])),
        ];
        for (how, inputs, rest) in &cases {
            let mut expected = vec![Action::Mode(Mode::Cooked, true)];
            expected.extend(rest.iter().map(|action| match action {
                Action::Send(message) => Action::Send(message.clone()),
                Action::Stderr(text) => Action::Stderr(text.clone()),
                Action::EndQuestionLine => Action::EndQuestionLine,
                Action::Exit(code) => Action::Exit(*code),
                other => panic!("not in an end: {other:?}"),
            }));
            for (echo, in_the_shell) in [(false, false), (true, false), (false, true)] {
                assert_eq!(ending_under_a_question(echo, in_the_shell, inputs()), expected, "{how}; echo {echo}, in the shell {in_the_shell}");
            }
        }
    }

    /// Outside a question what is typed is the shell's (or kept for it while connecting): an end does not throw it away, as OpenSSH's
    /// own end does not.
    #[test]
    fn an_end_outside_a_question_keeps_what_was_typed() {
        assert_eq!(opened().handle(Input::Stop(signal::TERM)), [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Exit(143)]);
        assert_eq!(started().handle(exited()), [Action::Mode(Mode::Cooked, false), Action::Exit(255)]);
        let mut client = started();
        client.handle(question("q1", QuestionKind::Password, "deploy@web's password: ", false));
        client.handle(Input::Interrupt);
        assert_eq!(client.handle(exited()), [Action::Mode(Mode::Cooked, false), Action::Exit(255)], "the question was cancelled before the end");
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
        assert!(client.answer(None, false).is_empty());
        assert!(matches!(client.phase, Phase::Open), "the open shell stays open");
        let mut client = started();
        assert!(client.answer(Some(Zeroizing::new("x".to_string())), true).is_empty());
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
        assert_eq!(
            format!("{:?}", [Input::Closed, Input::Unreadable, Input::StdinEnd, Input::Interrupt, Input::Failed, Input::Continue]),
            "[Closed, Unreadable, StdinEnd, Interrupt, Failed, Continue]"
        );
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
        assert_eq!(actions, hidden_answer("q1", &expected, Mode::Cooked));
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

    /// Ctrl-Z at a question, then `fg`: the question starts over, as OpenSSH's readpassphrase does. Its prompt mode is set again (echo
    /// off for a password: a job-control shell puts its own modes back, with echo on) and throws away what was typed meanwhile, the prompt
    /// is printed again, and what was collected of the answer before the stop is gone: only what is typed now is the answer.
    #[test]
    fn a_question_starts_over_when_the_program_continues_after_a_stop() {
        for (echo, after) in [(false, Mode::Cooked), (true, Mode::Raw)] {
            let mut client = if after == Mode::Raw { opened() } else { started() };
            client.handle(question("q1", QuestionKind::Password, "deploy@web's\u{1b}[2J password: ", echo));
            assert!(client.handle(Input::Stdin(Zeroizing::new(b"hun".to_vec()))).is_empty(), "a part of the answer, ended by Ctrl-D");
            assert_eq!(
                client.handle(Input::Continue),
                [Action::Mode(Mode::Prompt { echo }, true), Action::Stderr("deploy@web's?[2J password: ".into())],
                "echo {echo}: asked again, the prompt as it was printed the first time"
            );
            assert!(line_of(&client).is_empty(), "what was collected before the stop is gone");
            let expected = if echo { vec![answered("q1", "ter2"), Action::Mode(after, false)] } else { hidden_answer("q1", "ter2", after) };
            assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"ter2\n".to_vec()))), expected, "only what is typed after the stop");
        }
    }

    /// Without a question on the terminal there is nothing to ask again: the signal thread has set the mode again (raw for the shell),
    /// and the shell goes on.
    #[test]
    fn continuing_without_a_question_changes_nothing() {
        assert!(started().handle(Input::Continue).is_empty());
        let mut client = opened();
        assert!(client.handle(Input::Continue).is_empty());
        assert_eq!(client.handle(Input::Stdin(Zeroizing::new(b"ls\r".to_vec()))), [Action::SendData(b"ls\r".to_vec())], "the shell is still open");
        client.handle(Input::Stop(signal::TERM));
        assert!(client.handle(Input::Continue).is_empty(), "nothing after the end");
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
