//! The I/O of `sshelter connect` (own-ssh spec §7.3). Threads of their own read the broker's frames, the person's keys and the signals
//! (SIGWINCH, SIGINT, SIGTERM, SIGHUP, SIGQUIT), and put what happened in one queue; the loop takes it out in order, the client
//! (`client.rs`) says what to do with each, and the loop does it without waiting on anything that can stall: what goes to the terminal
//! and what goes to the broker is written by a writer thread of each. A terminal that is slow, or a broker that stops reading (it does,
//! for as long as a shell does not take what was typed), holds up its own writer and nothing else: keys reach the broker while output
//! waits for the terminal, and a signal is handled at once.
//!
//! What waits for the terminal is bounded: a frame from the broker counts against a budget until the terminal has taken it, and the
//! thread that reads the frames waits while the budget is spent; the broker, and SSH's window behind it, then push back on the remote,
//! as OpenSSH's window does. A size that waits for the broker gives way to a newer one.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use super::client::{Action, Client, Input};
use super::terminal::Tty;
use crate::session::protocol::{decode, read_frame, write_control, write_data, write_frame, ClientMessage, Frame, HostQuery, ServerMessage, CONTROL};

/// How much of the broker's output may be on its way to the terminal at a time (read from the broker, not written to the terminal yet).
const OUTPUT_IN_FLIGHT: usize = 256 * 1024;
/// How long a change of the terminal's mode waits for what was written before it to reach the terminal.
const MODE_WAIT: Duration = Duration::from_secs(1);
/// How long the end waits, in all, for the last output, what the CLI says at the end, and `close` to be written.
const END_WAIT: Duration = Duration::from_millis(1500);

/// Runs one session over `stream`, connected to the broker, until it ends; returns the program's exit code. `inputs` brings the keys,
/// resizes and signals (`stdin_thread`, `signal_thread`); the broker's frames join it from a thread started here. What is written to
/// `stdout` and `stderr` (the terminal) is written by a thread of its own, and so is what is written to the broker.
pub fn run(stream: UnixStream, host: HostQuery, term: String, tty: &mut Tty, inputs: (Inputs, Queue), stdout: Box<dyn Write + Send>, mut stderr: Box<dyn Write + Send>) -> i32 {
    let (inputs, queue) = inputs;
    let size = tty.size().unwrap_or((80, 24));
    let Ok(reader) = stream.try_clone() else {
        let _ = writeln!(stderr, "The connection to SSHelter failed.");
        return 255;
    };
    let terminal = TerminalWriter::start(stdout, stderr, &inputs);
    let broker = BrokerWriter::start(stream, &inputs);
    spawn_worker("sshelter-broker", inputs, move |inputs| read_broker(reader, &inputs));
    let mut the_loop = Loop { tty, queue, terminal, broker };
    let (mut client, actions) = Client::start(host, term, size);
    if let Some(code) = the_loop.perform(actions, None) {
        return code;
    }
    while let Some(Queued { input, credit }) = the_loop.queue.next() {
        let actions = client.handle(input);
        if let Some(code) = the_loop.perform(actions, credit) {
            return code;
        }
    }
    255
}

/// The loop's side of a run: the terminal's modes, the queue, and the two writers.
struct Loop<'a> {
    tty: &'a mut Tty,
    queue: Queue,
    terminal: TerminalWriter,
    broker: BrokerWriter,
}

impl Loop<'_> {
    /// Does what the client said, in order; `Some(code)` when it is time to exit. Nothing here waits on the broker, and the terminal is
    /// waited for only before its mode changes and at the end, each time for a bounded time. `credit` is what the frame from the broker
    /// that led to `actions` counts against the output's budget: it is given back once what the actions showed has been written to the
    /// terminal, or at once if they showed nothing. A broker that no longer takes what is written is a broker that went away: its end of
    /// the connection arrives as `Input::Closed` from the reader.
    fn perform(&mut self, actions: Vec<Action>, credit: Option<Credit>) -> Option<i32> {
        // The end (its last action exits) waits for its writes for END_WAIT in all.
        let end = matches!(actions.last(), Some(Action::Exit(_))).then(|| Instant::now() + END_WAIT);
        let wait = |most: Duration| end.map_or(most, |end| end.saturating_duration_since(Instant::now()).min(most));
        let mut shown = false;
        for action in actions {
            match action {
                Action::Send(ClientMessage::WindowChange { cols, rows }) => {
                    self.broker.size(cols, rows);
                }
                Action::Send(message) => {
                    self.broker.post(Post::Message(message));
                }
                Action::Answer { question_id, value } => {
                    // The password stays in `value`, which is wiped when the writer drops it, after writing it; `write_answer` wipes the rest.
                    self.broker.post(Post::Answer { question_id, value });
                }
                Action::SendData(bytes) => {
                    // Keystrokes can be a password too (typed at a prompt the shell shows): wiped when the writer drops them.
                    self.broker.post(Post::Data(Zeroizing::new(bytes)));
                }
                Action::Stdout(bytes) => {
                    self.terminal.show(Show::Output(bytes));
                    shown = true;
                }
                Action::Stderr(text) => {
                    self.terminal.show(Show::Said(text));
                    shown = true;
                }
                Action::Mode(mode, discard_input) => {
                    // What was written before the change belongs to the mode it was written in (a banner before raw mode, the shell's
                    // output before the end), unless the terminal does not take it in time: that does not keep the mode from changing.
                    self.terminal.written(wait(MODE_WAIT));
                    if let Err(error) = self.tty.set_mode(mode, discard_input) {
                        self.terminal.show(Show::Said(format!("sshelter: cannot set the terminal: {error}\n")));
                        shown = true;
                    }
                    if discard_input {
                        self.queue.forget_typed();
                    }
                }
                Action::Exit(code) => {
                    // The last output, what the CLI says at the end and `close` are written first, unless they cannot be in time.
                    self.terminal.written(wait(END_WAIT));
                    self.broker.written(wait(END_WAIT));
                    self.tty.restore();
                    return Some(code);
                }
            }
        }
        if let Some(credit) = credit.filter(|_| shown) {
            self.terminal.show(Show::Release(credit));
        }
        None
    }
}

/// The broker's output on its way to the terminal: counted when it is read, given back when it has been written to the terminal, or
/// dropped (`Credit`). The thread that reads it waits while the budget is spent, so that what the terminal cannot take yet stays in the
/// broker, and in SSH's window behind it.
struct Budget {
    limit: usize,
    used: Mutex<usize>,
    freed: Condvar,
}

impl Budget {
    fn new(limit: usize) -> Arc<Budget> {
        Arc::new(Budget { limit, used: Mutex::new(0), freed: Condvar::new() })
    }

    fn used(&self) -> MutexGuard<'_, usize> {
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts `bytes`, after waiting while the budget is spent. What is larger than the whole budget is let through when nothing else
    /// is counted (it would wait for ever otherwise).
    fn take(self: &Arc<Self>, bytes: usize) -> Credit {
        let mut used = self.used();
        while *used > 0 && *used + bytes > self.limit {
            used = self.freed.wait(used).unwrap_or_else(PoisonError::into_inner);
        }
        *used += bytes;
        Credit { budget: Arc::clone(self), bytes }
    }
}

/// Bytes counted against a budget until this is dropped.
struct Credit {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Drop for Credit {
    fn drop(&mut self) {
        let mut used = self.budget.used();
        *used = used.saturating_sub(self.bytes);
        drop(used);
        self.budget.freed.notify_all();
    }
}

/// An input on its way to the loop, with what it counts against its budget.
pub struct Queued {
    input: Input,
    credit: Option<Credit>,
}

/// Where the program's threads put what happened (the keys, the broker's frames, the signals), for the loop to take in order.
#[derive(Clone)]
pub struct Inputs {
    sender: Sender<Queued>,
    output: Arc<Budget>,
}

/// The loop is gone: nothing takes inputs any more.
#[derive(Debug, PartialEq, Eq)]
pub struct LoopGone;

impl Inputs {
    /// Puts `input` in the queue.
    pub fn send(&self, input: Input) -> Result<(), LoopGone> {
        self.queue(input, None)
    }

    fn queue(&self, input: Input, credit: Option<Credit>) -> Result<(), LoopGone> {
        // An input the loop will not take is dropped here, and what it counts is given back with it.
        self.sender.send(Queued { input, credit }).map_err(|_| LoopGone)
    }

    /// A frame from the broker, of `bytes` bytes: waits while too much of the broker's output has not reached the terminal yet.
    fn from_broker(&self, input: Input, bytes: usize) -> Result<(), LoopGone> {
        let credit = self.output.take(bytes);
        self.queue(input, Some(credit))
    }
}

/// The loop's end of the queue: what the threads put in it, and what the loop took out to look at and put back in front.
pub struct Queue {
    receiver: Receiver<Queued>,
    kept: VecDeque<Queued>,
}

/// A new queue: its `Inputs` for the threads that fill it, its `Queue` for the loop.
pub fn queue() -> (Inputs, Queue) {
    let (sender, receiver) = std::sync::mpsc::channel();
    let inputs = Inputs { sender, output: Budget::new(OUTPUT_IN_FLIGHT) };
    (inputs, Queue { receiver, kept: VecDeque::new() })
}

impl Queue {
    /// The next input, in the order it was queued; `None` once every thread that fills the queue is gone.
    fn next(&mut self) -> Option<Queued> {
        self.kept.pop_front().or_else(|| self.receiver.recv().ok())
    }

    /// Throws away what the person typed and the keys thread has already queued; everything else stays, in order. (What is thrown away
    /// is wiped as it is dropped, see `Input::Stdin`.) A question switches the terminal throwing away what the terminal has not delivered
    /// yet, but a line the keys thread had read before that is in the queue (behind the question), where the terminal cannot reach it and
    /// the question would take it as its answer. A line the thread has read but not queued yet at this moment is not caught: it arrives
    /// after, as typed text.
    fn forget_typed(&mut self) {
        while let Ok(queued) = self.receiver.try_recv() {
            self.kept.push_back(queued);
        }
        self.kept.retain(|queued| !matches!(queued.input, Input::Stdin(_)));
    }
}

/// Waits until `mark` has been reached by a writer, or `wait` has passed; whether it was. `give` hands the mark to the writer, and says
/// whether it could (a writer that is gone has nothing left to write).
fn wait_for_mark(give: impl FnOnce(SyncSender<()>) -> bool, wait: Duration) -> bool {
    let (mark, reached) = std::sync::mpsc::sync_channel(1);
    give(mark) && reached.recv_timeout(wait).is_ok()
}

/// What the terminal's writer is given, in order.
enum Show {
    /// The shell's output, for standard output.
    Output(Vec<u8>),
    /// What the CLI says, for standard error.
    Said(String),
    /// Given back once everything given before it has been written.
    Release(Credit),
    /// Told once everything given before it has been written.
    Mark(SyncSender<()>),
}

/// The writer of the terminal: standard output and standard error, in the order they were given, on a thread of its own.
struct TerminalWriter {
    jobs: Sender<Show>,
}

impl TerminalWriter {
    fn start(mut stdout: Box<dyn Write + Send>, mut stderr: Box<dyn Write + Send>, inputs: &Inputs) -> TerminalWriter {
        let (jobs, given) = std::sync::mpsc::channel::<Show>();
        spawn_worker("sshelter-terminal", inputs.clone(), move |_| {
            // An output that failed (a pipe nobody reads any more) is not written to again; what is given for it is dropped, so that nothing
            // waits for it.
            let (mut stdout_works, mut stderr_works) = (true, true);
            for job in given {
                match job {
                    Show::Output(bytes) => stdout_works = stdout_works && stdout.write_all(&bytes).and_then(|()| stdout.flush()).is_ok(),
                    Show::Said(text) => stderr_works = stderr_works && stderr.write_all(text.as_bytes()).and_then(|()| stderr.flush()).is_ok(),
                    Show::Release(credit) => drop(credit),
                    Show::Mark(reached) => {
                        let _ = reached.send(());
                    }
                }
            }
        });
        TerminalWriter { jobs }
    }

    fn show(&self, job: Show) {
        let _ = self.jobs.send(job);
    }

    /// Waits until everything given so far has been written, or `wait` has passed; whether it has.
    fn written(&self, wait: Duration) -> bool {
        wait_for_mark(|mark| self.jobs.send(Show::Mark(mark)).is_ok(), wait)
    }
}

/// What the broker's writer is given, in order.
enum Post {
    Message(ClientMessage),
    /// The answer to a question: the password stays in `value`, which is wiped when the job is dropped, after it has been written.
    Answer { question_id: String, value: Zeroizing<String> },
    /// Keystrokes for the shell, wiped when the job is dropped.
    Data(Zeroizing<Vec<u8>>),
    /// The terminal's size: the latest one given (`BrokerWriter::size`), as it is when this is reached.
    Size,
    /// Told once everything given before it has been written.
    Mark(SyncSender<()>),
}

/// The writer of the connection to the broker, on a thread of its own. The broker reads what a client writes on the thread that writes
/// it to the shell, and a shell that does not take it holds that thread for up to 30 seconds: this thread waits then, not the loop.
struct BrokerWriter {
    jobs: Sender<Post>,
    /// The latest size given that has not been written yet.
    size: Arc<Mutex<Option<(u16, u16)>>>,
}

impl BrokerWriter {
    fn start(mut stream: UnixStream, inputs: &Inputs) -> BrokerWriter {
        let (jobs, given) = std::sync::mpsc::channel::<Post>();
        let size = Arc::new(Mutex::new(None));
        let latest = Arc::clone(&size);
        spawn_worker("sshelter-to-broker", inputs.clone(), move |_| {
            // Once a write fails the broker is gone (the reader tells the loop); nothing more is written, and what is given is dropped.
            let mut gone = false;
            for job in given {
                let written = match job {
                    Post::Mark(reached) => {
                        let _ = reached.send(());
                        continue;
                    }
                    _ if gone => continue,
                    Post::Message(message) => write_control(&mut stream, &message),
                    Post::Answer { question_id, value } => write_answer(&mut stream, &question_id, &value),
                    Post::Data(bytes) => write_data(&mut stream, &bytes),
                    Post::Size => match latest.lock().unwrap_or_else(PoisonError::into_inner).take() {
                        Some((cols, rows)) => write_control(&mut stream, &ClientMessage::WindowChange { cols, rows }),
                        None => Ok(()),
                    },
                };
                gone = written.is_err();
            }
        });
        BrokerWriter { jobs, size }
    }

    fn post(&self, job: Post) {
        let _ = self.jobs.send(job);
    }

    /// The terminal's size for the broker. A size that has not been written yet gives way to this one, in its place: only the latest
    /// counts, and a broker that does not read cannot make sizes pile up.
    fn size(&self, cols: u16, rows: u16) {
        let waiting = self.size.lock().unwrap_or_else(PoisonError::into_inner).replace((cols, rows)).is_some();
        if !waiting {
            self.post(Post::Size);
        }
    }

    /// Waits until everything given so far has been written, or `wait` has passed; whether it has.
    fn written(&self, wait: Duration) -> bool {
        wait_for_mark(|mark| self.jobs.send(Post::Mark(mark)).is_ok(), wait)
    }
}

/// Reads the broker's frames into the queue until the connection ends, or the loop is gone. A frame counts against the output budget
/// until the terminal has taken what it brought; while the budget is spent, nothing more is read.
fn read_broker(mut reader: UnixStream, inputs: &Inputs) {
    loop {
        let (input, bytes) = match read_frame(&mut reader) {
            Ok(Some(Frame::Control(payload))) => match decode::<ServerMessage>(&payload) {
                Ok(message) => (Input::Message(message), payload.len()),
                Err(_) => continue,
            },
            Ok(Some(Frame::Data(mut payload))) => {
                let output = std::mem::take(&mut *payload);
                let bytes = output.len();
                (Input::Output(output), bytes)
            }
            Ok(None) | Err(_) => (Input::Closed, 0),
        };
        let closed = matches!(input, Input::Closed);
        if inputs.from_broker(input, bytes).is_err() || closed {
            return;
        }
    }
}

/// The protocol's answer message (`ClientMessage::Answer` with a value) written from borrowed strings, so that the password is not
/// copied into a message that would have to be wiped; `an_answer_is_the_protocols_message_byte_for_byte_and_fits_the_buffer_it_is_built_in`
/// keeps the two the same.
#[derive(Serialize)]
struct AnswerJson<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    question_id: &'a str,
    value: &'a str,
    cancel: bool,
}

/// How many bytes the JSON of an answer can take: a byte of either string takes six at most (`\u00XX`), the rest of the message 60.
fn answer_room(question_id: &str, value: &str) -> usize {
    64 + 6 * (question_id.len() + value.len())
}

/// The JSON of an answer. It is built in a buffer that has room for all of it from the start, because a `Vec` that grows frees its old
/// allocation with a part of the password in it, and the buffer is wiped when it is dropped.
fn answer_json(question_id: &str, value: &str) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut json = Zeroizing::new(Vec::with_capacity(answer_room(question_id, value)));
    serde_json::to_writer(&mut *json, &AnswerJson { kind: "answer", question_id, value, cancel: false })?;
    Ok(json)
}

/// Writes the answer to a question as one control frame. The password is in three places for a moment: the caller's string (wiped by
/// whoever owns it), the JSON (wiped here) and the frame `write_frame` builds from it (wiped there).
fn write_answer(writer: &mut impl Write, question_id: &str, value: &str) -> std::io::Result<()> {
    write_frame(writer, CONTROL, &answer_json(question_id, value)?)
}

/// Reads the person's keys into the queue until standard input ends (or the program does).
pub fn stdin_thread(inputs: Inputs) {
    // Not through `std::io::stdin()`: its buffer keeps a copy of what is read through it, for as long as the program runs, unless the
    // read is at least as large as that buffer (8 KiB; measured: a read of 8191 bytes leaves what was typed in it, one of 8192 does
    // not), and what is typed can be a password. A duplicate of the descriptor is read directly, with no buffer of std's in between.
    match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(descriptor) => keys_thread(std::fs::File::from(descriptor), inputs),
        Err(_) => keys_thread(std::io::stdin(), inputs),
    }
}

/// `read_keys` on a thread of its own.
fn keys_thread(source: impl Read + Send + 'static, inputs: Inputs) {
    spawn_worker("sshelter-keys", inputs, move |inputs| read_keys(source, &inputs));
}

/// Queues what `source` (the terminal) delivers, as typed text; a read of nothing is the end of input (Ctrl-D), and a failed one is
/// the end of the terminal. Returns when the terminal failed or the loop is gone.
fn read_keys(mut source: impl Read, inputs: &Inputs) {
    let mut buf = [0u8; 4096];
    loop {
        let input = match source.read(&mut buf) {
            // A question ends on Ctrl-D; the next question reads again.
            Ok(0) => Input::StdinEnd,
            Ok(count) => {
                let typed = Input::Stdin(Zeroizing::new(buf[..count].to_vec()));
                // What was typed may be a password: the copy that stays on this stack is wiped as well.
                buf[..count].zeroize();
                typed
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = inputs.send(Input::StdinEnd);
                return;
            }
        };
        if inputs.send(input).is_err() {
            return;
        }
    }
}

/// Starts `work` on a thread of its own. If that thread panics (the panic hook has put the terminal back by then), or cannot be started,
/// the queue is told (`Input::Failed`) and the program ends: the loop would otherwise go on, in the mode the terminal was in, with nobody
/// reading the keys or the signals or the broker, or writing to the terminal or the broker.
fn spawn_worker(name: &str, inputs: Inputs, work: impl FnOnce(Inputs) + Send + 'static) {
    let failed = inputs.clone();
    let started = std::thread::Builder::new().name(name.to_string()).spawn(move || {
        let _watch = Watch(inputs.clone());
        work(inputs);
    });
    if started.is_err() {
        let _ = failed.send(Input::Failed);
    }
}

/// Dropped by a thread that is unwinding from a panic, it tells the queue.
struct Watch(Inputs);

impl Drop for Watch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = self.0.send(Input::Failed);
        }
    }
}

/// What the queue is told when `signal` stops the program or cancels a question: Ctrl-C cancels the question on the terminal (and ends
/// the program when there is none); every other signal ends it, with the number its exit status (128 + n) is made of.
fn input_for(signal: i32) -> Input {
    if signal == libc::SIGINT {
        Input::Interrupt
    } else {
        Input::Stop(signal)
    }
}

/// Turns the signals into inputs: a resize (SIGWINCH, read with `size`), Ctrl-C (SIGINT), Ctrl-backslash (SIGQUIT), and the end of the
/// terminal or a request to stop (SIGHUP, SIGTERM). A question keeps `ISIG` on (Ctrl-C cancels it), so Ctrl-backslash at a hidden
/// password would deliver SIGQUIT too, and its default action ends the program with echo still off: neither the panic hook nor `Drop`
/// run on a signal. With handlers in place none of them ends the program on its own: the client decides, and the terminal is put back
/// first.
pub fn signal_thread(inputs: Inputs, size: impl Fn() -> Option<(u16, u16)> + Send + 'static) -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    // The handlers are installed here, before the thread runs: a signal that comes right after this returns finds them in place.
    let (mut resize, mut interrupt, mut terminate, mut hangup, mut quit) = runtime.block_on(async {
        Ok::<_, std::io::Error>((
            signal(SignalKind::window_change())?,
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
            signal(SignalKind::quit())?,
        ))
    })?;
    spawn_worker("sshelter-signals", inputs, move |inputs| {
        runtime.block_on(async move {
            loop {
                let input = tokio::select! {
                    _ = resize.recv() => match size() {
                        Some((cols, rows)) => Input::Resize(cols, rows),
                        None => continue,
                    },
                    _ = interrupt.recv() => input_for(libc::SIGINT),
                    _ = terminate.recv() => input_for(libc::SIGTERM),
                    _ = hangup.recv() => input_for(libc::SIGHUP),
                    _ = quit.recv() => input_for(libc::SIGQUIT),
                };
                if inputs.send(input).is_err() {
                    return;
                }
            }
        })
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::cli::terminal::fake::FakeTermios;
    use crate::cli::terminal::{Mode, TermiosApi};
    use crate::session::broker::Broker;
    use crate::session::connect::HostKeyConfirmer;
    use crate::session::directory::HostDirectory;
    use crate::session::protocol::Event;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods};
    use crate::ssh::testing::eventually;
    use crate::ssh::{AuthMethod, Exit, SshEngine};
    use crate::sync::env::Keychain;
    use crate::sync::testkit::MemKeychain;

    /// A `Write` the test can read while the run goes on.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    /// A terminal that takes no output until it is let go: a window that froze, or a pipe nobody reads.
    #[derive(Clone, Default)]
    struct Stalled {
        let_go: Arc<(Mutex<bool>, std::sync::Condvar)>,
        shown: Shared,
    }

    impl Stalled {
        fn let_go(&self) {
            *self.let_go.0.lock().unwrap() = true;
            self.let_go.1.notify_all();
        }
    }

    impl Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut let_go = self.let_go.0.lock().unwrap();
            while !*let_go {
                let_go = self.let_go.1.wait(let_go).unwrap();
            }
            drop(let_go);
            self.shown.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Setup {
        engine: Arc<FakeEngine>,
        termios: Arc<FakeTermios>,
        keys: Inputs,
        stdout: Shared,
        stderr: Shared,
        run: std::thread::JoinHandle<i32>,
    }

    /// A terminal that, when the CLI switches it to a question's prompt mode and throws the typeahead away, has a line arrive in the
    /// queue: one the keys thread had read and queued just before the switch, behind the question.
    struct FeedsAtFlush {
        inner: Arc<FakeTermios>,
        queue: Inputs,
        line: Mutex<Option<Vec<u8>>>,
    }

    impl TermiosApi for FeedsAtFlush {
        fn get(&self) -> std::io::Result<libc::termios> {
            self.inner.get()
        }
        fn set(&self, termios: &libc::termios, discard_input: bool) -> std::io::Result<()> {
            if discard_input {
                if let Some(line) = self.line.lock().unwrap().take() {
                    self.queue.send(Input::Stdin(Zeroizing::new(line))).unwrap();
                }
            }
            self.inner.set(termios, discard_input)
        }
        fn size(&self) -> Option<(u16, u16)> {
            self.inner.size()
        }
    }

    /// `sshelter connect web` against a broker over `engine` and `directory`, on the other end of a socket pair, with a fake terminal.
    fn connect(engine: FakeEngine, directory: FakeDirectory, keychain: MemKeychain) -> Setup {
        connect_typing_ahead(engine, directory, keychain, None)
    }

    /// `connect`, and `typed_ahead` arrives in the queue as the terminal is flushed for the first question.
    fn connect_typing_ahead(engine: FakeEngine, directory: FakeDirectory, keychain: MemKeychain, typed_ahead: Option<&[u8]>) -> Setup {
        let engine = Arc::new(engine);
        let broker = Broker::new(
            Arc::clone(&engine) as Arc<dyn SshEngine>,
            Arc::new(directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new()),
            Arc::new(keychain) as Arc<dyn Keychain>,
            Arc::new(FakeConfirmer::default()) as Arc<dyn HostKeyConfirmer>,
        );
        let (ours, theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || broker.serve(theirs, None));
        let termios = FakeTermios::new();
        let (inputs, queue) = queue();
        let (stdout, stderr) = (Shared::default(), Shared::default());
        let terminal: Arc<dyn TermiosApi> = match typed_ahead {
            Some(line) => Arc::new(FeedsAtFlush { inner: Arc::clone(&termios), queue: inputs.clone(), line: Mutex::new(Some(line.to_vec())) }),
            None => Arc::clone(&termios) as Arc<dyn TermiosApi>,
        };
        let run = {
            let (inputs, stdout, stderr) = (inputs.clone(), stdout.clone(), stderr.clone());
            std::thread::spawn(move || {
                let mut tty = Tty::new(terminal).unwrap();
                run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (inputs, queue), Box::new(stdout), Box::new(stderr))
            })
        };
        Setup { engine, termios, keys: inputs, stdout, stderr, run }
    }

    fn finish(setup: Setup) -> (i32, Setup) {
        eventually("the run to end", 10, || setup.run.is_finished());
        let Setup { engine, termios, keys, stdout, stderr, run } = setup;
        let code = run.join().unwrap();
        (code, Setup { engine, termios, keys, stdout, stderr, run: std::thread::spawn(|| 0) })
    }

    fn raw(termios: &FakeTermios) -> bool {
        termios.now().c_lflag & libc::ICANON == 0
    }

    /// A run where the test plays the broker: it has taken `hello` and `open_shell` from the CLI, and `broker` is its end.
    struct ByHand {
        termios: Arc<FakeTermios>,
        keys: Inputs,
        run: std::thread::JoinHandle<i32>,
        broker: UnixStream,
    }

    /// `sshelter connect web` with the test as the broker, a fake terminal `termios`, and the terminal's output and error.
    fn by_hand(termios: Arc<FakeTermios>, stdout: Box<dyn Write + Send>, stderr: Box<dyn Write + Send>) -> ByHand {
        let (ours, mut broker) = UnixStream::pair().unwrap();
        let (inputs, queue) = queue();
        let run = {
            let (termios, inputs) = (Arc::clone(&termios), inputs.clone());
            std::thread::spawn(move || {
                let mut tty = Tty::new(termios).unwrap();
                run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (inputs, queue), stdout, stderr)
            })
        };
        for expected in ["Hello", "OpenShell"] {
            let message = next_message(&mut broker);
            assert!(format!("{message:?}").starts_with(expected), "{message:?}");
        }
        ByHand { termios, keys: inputs, run, broker }
    }

    /// The next control message the CLI wrote to the broker, skipping data frames.
    fn next_message(broker: &mut UnixStream) -> ClientMessage {
        loop {
            match read_frame(broker) {
                Ok(Some(Frame::Control(payload))) => return decode::<ClientMessage>(&payload).unwrap(),
                Ok(Some(Frame::Data(_))) => continue,
                other => panic!("no message from the CLI: {:?}", other.map(|frame| frame.map(|_| "a frame"))),
            }
        }
    }

    fn opened() -> ServerMessage {
        ServerMessage::Opened { session_id: "1".into() }
    }

    impl ByHand {
        fn tell(&mut self, message: ServerMessage) {
            write_control(&mut self.broker, &message).unwrap();
        }

        fn open(&mut self) {
            self.tell(opened());
            eventually("the terminal to be raw", 10, || raw(&self.termios));
        }

        /// The run's end, which must come within `within` of now.
        fn ends_within(self, within: Duration) -> (i32, Arc<FakeTermios>) {
            let asked = Instant::now();
            eventually("the run to end", 10, || self.run.is_finished());
            assert!(asked.elapsed() < within, "the run took {:?} to end", asked.elapsed());
            (self.run.join().unwrap(), self.termios)
        }
    }

    #[test]
    fn the_cli_opens_a_shell_relays_keys_and_output_and_exits_with_the_shells_status() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let setup = connect(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), keychain);
        eventually("the terminal to be raw", 10, || raw(&setup.termios));
        setup.keys.send(Input::Stdin(Zeroizing::new(b"ls\r".to_vec()))).unwrap();
        eventually("the keys to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::ShellInput(b"ls\r".to_vec())));
        let remote = setup.engine.shells().remove(0);
        remote.print(b"file.txt\r\n");
        eventually("the output to reach the terminal", 10, || setup.stdout.text() == "file.txt\r\n");
        setup.keys.send(Input::Resize(100, 30)).unwrap();
        eventually("the resize to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::WindowChange { cols: 100, rows: 30 }));
        remote.end(Exit::Code(3));
        let (code, setup) = finish(setup);
        assert_eq!(code, 3);
        assert!(setup.termios.is_start(&setup.termios.now()), "the terminal is as it was");
        assert_eq!(setup.stderr.text(), "");
    }

    #[test]
    fn a_question_is_asked_at_the_terminal_and_the_answer_gets_in() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let setup = connect(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, MemKeychain::default());
        eventually("the question", 10, || setup.stderr.text() == "deploy@web's password: ");
        let prompt = setup.termios.sets.lock().unwrap().last().copied().unwrap();
        assert!(prompt.1, "typeahead thrown away");
        assert_eq!((prompt.0.c_lflag & libc::ECHO, prompt.0.c_lflag & libc::ICANON), (0, libc::ICANON), "no echo, line editing on");
        setup.keys.send(Input::Stdin(Zeroizing::new(b"right\n".to_vec()))).unwrap();
        eventually("the shell to open", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).end(Exit::Code(0));
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }

    #[test]
    fn a_host_that_cannot_be_reached_is_said_and_the_status_is_255() {
        let setup = connect(FakeEngine::new(), FakeDirectory::new(), MemKeychain::default());
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (255, "No saved host is called web.\n".to_string()));
        assert_eq!(setup.termios.sets.lock().unwrap().iter().filter(|(termios, _)| !setup.termios.is_start(termios)).count(), 0, "the terminal was never changed");
    }

    /// The terminal is closed (SIGHUP) while the shell runs: the CLI tells the broker, puts the terminal back and ends; the broker closes
    /// the session.
    #[test]
    fn a_closed_terminal_ends_the_session() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let setup = connect(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), keychain);
        eventually("the terminal to be raw", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).print(b"$ ");
        setup.keys.send(Input::Stop(libc::SIGHUP)).unwrap();
        let (code, setup) = finish(setup);
        assert_eq!(code, 128 + libc::SIGHUP);
        assert!(setup.termios.is_start(&setup.termios.now()));
        eventually("the session to be closed", 10, || setup.engine.events().contains(&FakeEvent::Closed));
    }

    /// Every signal the CLI takes over becomes the input that ends the session the way a shell would report it: the terminal is put back
    /// first, the broker is told, and the status is 128 + the signal's number (131 for SIGQUIT, which Ctrl-backslash sends at a question).
    #[test]
    fn each_signal_the_cli_takes_over_ends_the_session_with_128_plus_its_number() {
        use crate::cli::client::Client;
        assert_eq!(128 + libc::SIGQUIT, 131);
        for (signal, status) in [(libc::SIGINT, 130), (libc::SIGTERM, 143), (libc::SIGHUP, 129), (libc::SIGQUIT, 131)] {
            let (mut client, _) = Client::start(HostQuery::Alias("web".into()), "xterm-256color".into(), (80, 24));
            client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() }));
            assert_eq!(client.handle(input_for(signal)), [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Exit(status)], "signal {signal}");
        }
    }

    /// The next input the queue holds, within ten seconds.
    fn next_input(queue: &Queue) -> Input {
        queue.receiver.recv_timeout(Duration::from_secs(10)).expect("an input within 10 s").input
    }

    /// The handlers are process-wide and stay for the life of the process, so the test that raises the signals for real runs alone, in a
    /// process of its own (`rerun_alone`); a signal that was not taken over would end that process, and the test with it.
    #[test]
    fn the_signals_the_cli_takes_over_reach_the_queue_instead_of_ending_the_program() {
        use crate::ssh::testing::{is_child, rerun_alone};
        const NAME: &str = "cli::run::tests::the_signals_the_cli_takes_over_reach_the_queue_instead_of_ending_the_program";
        if !is_child() {
            rerun_alone(NAME);
            return;
        }
        let (inputs, queue) = queue();
        signal_thread(inputs, || Some((100, 30))).expect("the handlers are installed");
        let next = |signal: i32| {
            // SAFETY: `raise` only sends the signal to this thread, and every signal raised here has a handler by now.
            assert_eq!(unsafe { libc::raise(signal) }, 0);
            next_input(&queue)
        };
        assert!(matches!(next(libc::SIGWINCH), Input::Resize(100, 30)));
        assert!(matches!(next(libc::SIGINT), Input::Interrupt));
        assert!(matches!(next(libc::SIGTERM), Input::Stop(libc::SIGTERM)));
        assert!(matches!(next(libc::SIGHUP), Input::Stop(libc::SIGHUP)));
        assert!(matches!(next(libc::SIGQUIT), Input::Stop(libc::SIGQUIT)));
        // A panic on the signal thread (here: in the callback that reads the size) is told to the queue as well.
        let (failing, told) = super::queue();
        signal_thread(failing, || panic!("the size failed")).expect("a second set of handlers");
        assert!(matches!(next(libc::SIGWINCH), Input::Resize(100, 30)));
        assert!(matches!(next_input(&told), Input::Failed));
    }

    /// The keys thread read a line and queued it behind the question before the terminal was flushed for it: the flush cannot reach a
    /// line that is already in the queue, so the loop drops it, and it is not taken as the answer.
    #[test]
    fn a_line_queued_just_before_a_question_is_not_taken_as_its_answer() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let setup = connect_typing_ahead(engine, directory, MemKeychain::default(), Some(b"hunter2\n"));
        eventually("the question", 10, || setup.stderr.text().starts_with("deploy@web's password: "));
        // The queue is in order: once this output has been printed, whatever was queued before it has been looked at.
        setup.keys.send(Input::Output(b"marker".to_vec())).unwrap();
        eventually("the marker", 10, || setup.stdout.text() == "marker");
        assert_eq!(setup.stderr.text(), "deploy@web's password: ", "the question still waits for its answer");
        let prompt = setup.termios.now();
        assert_eq!((prompt.c_lflag & libc::ECHO, prompt.c_lflag & libc::ICANON), (0, libc::ICANON), "still the prompt mode");
        setup.keys.send(Input::Stdin(Zeroizing::new(b"right\n".to_vec()))).unwrap();
        eventually("the shell to open", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).end(Exit::Code(0));
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }

    /// What was typed and queued is dropped when a question flushes the terminal; every other input stays, in the order it came, and
    /// what is typed after the flush is the question's.
    #[test]
    fn forgetting_the_typed_keeps_every_other_input_in_order() {
        let (inputs, mut queue) = queue();
        inputs.send(Input::Output(b"a".to_vec())).unwrap();
        inputs.send(Input::Stdin(Zeroizing::new(b"hunter2\n".to_vec()))).unwrap();
        inputs.send(Input::Resize(100, 30)).unwrap();
        inputs.send(Input::Stdin(Zeroizing::new(b"more".to_vec()))).unwrap();
        inputs.send(Input::StdinEnd).unwrap();
        queue.forget_typed();
        inputs.send(Input::Stdin(Zeroizing::new(b"after".to_vec()))).unwrap();
        drop(inputs);
        let rest: Vec<Input> = std::iter::from_fn(|| queue.next().map(|queued| queued.input)).collect();
        assert_eq!(format!("{rest:?}"), "[Output([97]), Resize(100, 30), StdinEnd, Stdin(<hidden>)]");
        assert!(matches!(&rest[3], Input::Stdin(bytes) if &bytes[..] == b"after"), "typed after the flush: the question's own");
    }

    /// What was typed may be a password: it is wiped wherever it is dropped, whichever path of the loop drops it. That is the type's doing,
    /// so this fails to compile if what `Input::Stdin` or `Action::Answer` carries stops being wiped on drop.
    #[test]
    fn what_was_typed_is_wiped_wherever_it_is_dropped() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let Input::Stdin(typed) = Input::Stdin(Zeroizing::new(b"hunter2\n".to_vec())) else { unreachable!() };
        wiped_on_drop(&typed);
        let Action::Answer { value, .. } = (Action::Answer { question_id: "q1".into(), value: Zeroizing::new("hunter2".to_string()) }) else { unreachable!() };
        wiped_on_drop(&value);
        let Post::Data(keys) = Post::Data(Zeroizing::new(b"hunter2\n".to_vec())) else { unreachable!() };
        wiped_on_drop(&keys);
    }

    /// A source of keys that is whatever the closure says each read is.
    struct Keyboard<F>(F);

    impl<F: FnMut(&mut [u8]) -> std::io::Result<usize>> Read for Keyboard<F> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            (self.0)(buf)
        }
    }

    /// Everything the queue holds now, in order.
    fn queued(queue: &Queue) -> Vec<Input> {
        std::iter::from_fn(|| queue.receiver.try_recv().ok().map(|queued| queued.input)).collect()
    }

    #[test]
    fn the_keys_are_queued_as_typed_and_the_end_of_input_is_told_and_a_failing_terminal_ends_the_thread() {
        // One read at a time: what is typed, an interrupted read, the end of input (Ctrl-D: a read of 0 bytes), more, then a failure.
        let mut script = std::collections::VecDeque::from([Ok(b"ls\r".to_vec()), Err(std::io::ErrorKind::Interrupted.into()), Ok(vec![]), Ok(b"x".to_vec())]);
        let keyboard = Keyboard(move |buf: &mut [u8]| match script.pop_front() {
            Some(Ok(bytes)) => {
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Some(Err(error)) => Err(error),
            None => Err(std::io::Error::other("the terminal went away")),
        });
        let (inputs, queue) = queue();
        read_keys(keyboard, &inputs);
        let queued = queued(&queue);
        assert_eq!(format!("{queued:?}"), "[Stdin(<hidden>), StdinEnd, Stdin(<hidden>), StdinEnd]", "an interrupted read is read again; the failure is the end");
        assert!(matches!(&queued[0], Input::Stdin(bytes) if &bytes[..] == b"ls\r"));
        assert!(matches!(&queued[2], Input::Stdin(bytes) if &bytes[..] == b"x"));
    }

    #[test]
    fn the_keys_thread_stops_when_the_loop_is_gone() {
        let (inputs, queue) = queue();
        drop(queue);
        // A keyboard that never stops typing: the thread has to be the one that stops.
        let keyboard = Keyboard(|buf: &mut [u8]| {
            buf[0] = b'x';
            Ok(1)
        });
        read_keys(keyboard, &inputs);
    }

    #[test]
    fn a_worker_that_panics_tells_the_queue_and_one_that_returns_does_not() {
        let (inputs, mut queue) = queue();
        spawn_worker("test-quiet", inputs.clone(), |_| {});
        spawn_worker("test-panics", inputs.clone(), |_| panic!("the worker failed"));
        drop(inputs);
        // The queue ends when both workers are gone.
        let told: Vec<String> = std::iter::from_fn(|| queue.next().map(|queued| format!("{:?}", queued.input))).collect();
        assert_eq!(told, ["Failed"]);
    }

    /// A panic on the thread that reads the keys: the panic hook puts the terminal back, but the loop would go on reading from nobody. It
    /// ends the program instead, with 255, the terminal as it was, and the broker told.
    #[test]
    fn a_panic_on_a_thread_of_the_program_ends_the_run_with_255_the_terminal_put_back_and_the_broker_told() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let setup = connect(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), keychain);
        eventually("the terminal to be raw", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).print(b"$ ");
        let keyboard = Keyboard(|_: &mut [u8]| -> std::io::Result<usize> { panic!("the keyboard failed") });
        keys_thread(keyboard, setup.keys.clone());
        let (code, setup) = finish(setup);
        assert_eq!(code, 255);
        assert!(setup.termios.is_start(&setup.termios.now()), "the terminal is as it was");
        assert_eq!(setup.stderr.text(), "\nsshelter: an internal error stopped this session.\n");
        eventually("the session to be closed", 10, || setup.engine.events().contains(&FakeEvent::Closed));
    }

    /// A broker that stops reading (it does, for up to 30 s, while a shell does not take what was typed) holds up the writer of what goes
    /// to it, not the loop: SIGTERM still ends the program, at once, with the terminal put back.
    #[test]
    fn a_broker_that_stops_reading_does_not_keep_a_signal_from_ending_the_program() {
        let mut hand = by_hand(FakeTermios::new(), Box::new(Shared::default()), Box::new(Shared::default()));
        hand.open();
        // Far more is typed than the connection holds; the broker reads none of it.
        for _ in 0..256 {
            hand.keys.send(Input::Stdin(Zeroizing::new(vec![b'y'; 16 * 1024]))).unwrap();
        }
        std::thread::sleep(Duration::from_millis(300));
        hand.keys.send(Input::Stop(libc::SIGTERM)).unwrap();
        let (code, termios) = hand.ends_within(Duration::from_secs(3));
        assert_eq!(code, 143);
        assert!(termios.is_start(&termios.now()), "the terminal is as it was");
    }

    /// A terminal that takes no output (a frozen window, a pipe nobody reads) holds up the writer of the terminal, not the loop: SIGTERM
    /// still ends the program, within the end's waits, with the terminal put back.
    #[test]
    fn a_terminal_that_takes_no_output_does_not_keep_a_signal_from_ending_the_program() {
        let stdout = Stalled::default();
        let mut hand = by_hand(FakeTermios::new(), Box::new(stdout.clone()), Box::new(Shared::default()));
        hand.open();
        let mut remote = hand.broker.try_clone().unwrap();
        let printing = std::thread::spawn(move || {
            for _ in 0..64 {
                if write_data(&mut remote, &[b'x'; 32 * 1024]).is_err() {
                    return;
                }
            }
        });
        std::thread::sleep(Duration::from_millis(300));
        hand.keys.send(Input::Stop(libc::SIGTERM)).unwrap();
        let (code, termios) = hand.ends_within(MODE_WAIT + END_WAIT + Duration::from_secs(1));
        assert_eq!(code, 143);
        assert!(termios.is_start(&termios.now()), "the terminal is as it was");
        stdout.let_go();
        let _ = printing.join();
    }

    /// The remote prints far faster than the terminal takes it (here: not at all). What waits for the terminal is bounded: the CLI stops
    /// reading, so the broker (and SSH's window behind it) push back on the remote. And a key does not wait behind that output: Ctrl-C
    /// reaches the broker at once, as OpenSSH sends it.
    #[test]
    fn keys_overtake_output_that_waits_for_the_terminal_and_what_waits_is_bounded() {
        let stdout = Stalled::default();
        let mut hand = by_hand(FakeTermios::new(), Box::new(stdout.clone()), Box::new(Shared::default()));
        hand.open();
        let written = Arc::new(AtomicUsize::new(0));
        let printing = {
            let (mut remote, written) = (hand.broker.try_clone().unwrap(), Arc::clone(&written));
            std::thread::spawn(move || {
                // 8 MiB of output, at most: the CLI used to take all of it, whatever the terminal did.
                for _ in 0..256 {
                    if write_data(&mut remote, &[b'x'; 32 * 1024]).is_err() {
                        return;
                    }
                    written.fetch_add(32 * 1024, Ordering::SeqCst);
                }
            })
        };
        eventually("the remote to be held back", 10, || {
            let before = written.load(Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
            written.load(Ordering::SeqCst) == before
        });
        let held_back_at = written.load(Ordering::SeqCst);
        assert!(held_back_at <= 2 * 1024 * 1024, "{held_back_at} bytes of output were taken while the terminal took none");
        let typed = Instant::now();
        hand.keys.send(Input::Stdin(Zeroizing::new(b"\x03".to_vec()))).unwrap();
        hand.broker.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        loop {
            match read_frame(&mut hand.broker) {
                Ok(Some(Frame::Data(bytes))) if &bytes[..] == b"\x03" => break,
                Ok(Some(_)) => continue,
                other => panic!("Ctrl-C did not reach the broker: {:?}", other.map(|frame| frame.map(|_| "a frame"))),
            }
        }
        assert!(typed.elapsed() < Duration::from_secs(1), "Ctrl-C took {:?}", typed.elapsed());
        // The terminal takes the output again: all of it is shown, and the session ends.
        stdout.let_go();
        printing.join().unwrap();
        hand.tell(ServerMessage::Exited { code: Some(130), signal: None });
        let (code, _) = hand.ends_within(Duration::from_secs(5));
        assert_eq!(code, 130);
        assert_eq!(stdout.shown.len(), 8 * 1024 * 1024, "nothing was lost");
    }

    /// A terminal that writes what it is given only after a while, and notes for each write whether the terminal was raw by then.
    #[derive(Clone)]
    struct Noting {
        termios: Arc<FakeTermios>,
        notes: Arc<Mutex<Vec<(String, bool)>>>,
    }

    impl Write for Noting {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_millis(100));
            self.notes.lock().unwrap().push((String::from_utf8_lossy(bytes).into_owned(), raw(&self.termios)));
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What was written before a change of mode reaches the terminal in the mode it was written for, although a thread of its own writes it:
    /// a banner before the shell opens is printed before the terminal goes raw (raw, its line feed would not start a new line).
    #[test]
    fn what_was_written_before_a_change_of_mode_reaches_the_terminal_first() {
        let termios = FakeTermios::new();
        let stderr = Noting { termios: Arc::clone(&termios), notes: Arc::default() };
        let mut hand = by_hand(Arc::clone(&termios), Box::new(Shared::default()), Box::new(stderr.clone()));
        hand.tell(ServerMessage::Event(Event::Banner { text: "Authorized use only.".into() }));
        hand.open();
        assert_eq!(*stderr.notes.lock().unwrap(), [("Authorized use only.\n".to_string(), false)]);
        hand.tell(ServerMessage::Exited { code: Some(0), signal: None });
        assert_eq!(hand.ends_within(Duration::from_secs(5)).0, 0);
    }

    /// A terminal that takes what is written to it slowly.
    #[derive(Clone, Default)]
    struct Slow(Shared);

    impl Write for Slow {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_millis(200));
            self.0.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The end waits for what was written before it, the terminal's mode put back in between: the last output of the shell, and then
    /// why the session ended, are all on the terminal when the program exits, even on a terminal that is slow to take them.
    #[test]
    fn the_last_output_and_the_reason_reach_the_terminal_before_the_program_exits() {
        let (stdout, stderr) = (Shared::default(), Slow::default());
        let mut hand = by_hand(FakeTermios::new(), Box::new(stdout.clone()), Box::new(stderr.clone()));
        hand.open();
        for _ in 0..32 {
            write_data(&mut hand.broker, &[b'x'; 32 * 1024]).unwrap();
        }
        hand.tell(ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost.".into() }));
        hand.tell(ServerMessage::Exited { code: None, signal: None });
        assert_eq!(hand.ends_within(Duration::from_secs(5)).0, 255);
        assert_eq!(stdout.len(), 1024 * 1024);
        assert_eq!(stderr.0.text(), "\nConnection to web lost.\n");
    }

    /// Sizes given while the broker does not read do not pile up: the latest takes the place of the one that waits.
    #[test]
    fn a_size_waiting_for_the_broker_gives_way_to_a_newer_one() {
        let (ours, mut broker) = UnixStream::pair().unwrap();
        let (inputs, _queue) = queue();
        let writer = BrokerWriter::start(ours, &inputs);
        // The broker does not read: the writer is held by a write larger than the connection holds.
        writer.post(Post::Data(Zeroizing::new(vec![b'x'; 512 * 1024])));
        for size in 1..=100 {
            writer.size(size, size);
        }
        broker.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(matches!(read_frame(&mut broker), Ok(Some(Frame::Data(bytes))) if bytes.len() == 512 * 1024));
        assert!(matches!(next_message(&mut broker), ClientMessage::WindowChange { cols: 100, rows: 100 }));
        broker.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        assert!(read_frame(&mut broker).is_err(), "nothing more: one size, the latest");
    }

    /// A budget holds back what does not fit until what it counts is given back; what is larger than the whole budget gets through when
    /// nothing else is counted.
    #[test]
    fn a_budget_holds_back_what_does_not_fit_until_room_is_given_back() {
        let budget = Budget::new(100);
        let first = budget.take(60);
        let second = {
            let budget = Arc::clone(&budget);
            std::thread::spawn(move || budget.take(50))
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(!second.is_finished(), "60 + 50 does not fit in 100");
        drop(first);
        eventually("room for the second", 5, || second.is_finished());
        drop(second.join().unwrap());
        assert_eq!(*budget.used(), 0);
        let large = {
            let budget = Arc::clone(&budget);
            std::thread::spawn(move || budget.take(1000))
        };
        eventually("a large item through an empty budget", 5, || large.is_finished());
        assert_eq!(*budget.used(), 1000);
        drop(large.join().unwrap());
        assert_eq!(*budget.used(), 0);
    }

    /// What `Action::Answer` puts on the wire is the protocol's answer message, byte for byte (the CLI writes it from borrowed strings so
    /// that the password is in no message it would have to wipe), and it is built in a buffer that has room for it from the start: a
    /// `Vec` that grows frees its old allocation with a part of the password in it.
    #[test]
    fn an_answer_is_the_protocols_message_byte_for_byte_and_fits_the_buffer_it_is_built_in() {
        let controls = "\u{1}".repeat(50);
        for value in ["hunter2", "", "x".repeat(300).as_str(), "quote\" back\\slash tab\t \u{e9} \u{5bc6}\u{78bc} \u{1f511}", controls.as_str()] {
            for question_id in ["q1", "", "0123456789abcdef0123456789abcdef0123"] {
                let json = answer_json(question_id, value).unwrap();
                let protocol = serde_json::to_vec(&ClientMessage::Answer { question_id: question_id.into(), value: Some(value.into()), cancel: false }).unwrap();
                assert_eq!(&json[..], &protocol[..], "{question_id:?} {value:?}");
                assert!(json.len() <= answer_room(question_id, value), "{} bytes in a room of {}", json.len(), answer_room(question_id, value));
                assert!(json.capacity() >= answer_room(question_id, value));
            }
        }
        // The worst case is what the room is for: a control character takes six bytes in JSON, and the rest of the message at most 64.
        let json = answer_json("", &controls).unwrap();
        assert_eq!(json.len(), 6 * controls.len() + 60);
        assert!(answer_room("", &controls) >= json.len());
    }

    /// A long password with characters JSON has to escape gets to the broker whole.
    #[test]
    fn a_long_password_with_awkward_characters_gets_in_whole() {
        let password = format!("p\"w\\ tab\t \u{5bc6}\u{78bc} {}", "x".repeat(300));
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let setup = connect(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password(&password))), directory, MemKeychain::default());
        eventually("the question", 10, || setup.stderr.text() == "deploy@web's password: ");
        setup.keys.send(Input::Stdin(Zeroizing::new(format!("{password}\n").into_bytes()))).unwrap();
        eventually("the shell to open", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).end(Exit::Code(0));
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }
}
