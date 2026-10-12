//! The I/O of `sshelter connect` (own-ssh spec §7.3). Threads of their own read the broker's frames, the person's keys and the signals
//! (SIGWINCH, SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP, SIGCONT), and put what happened in one queue; the loop takes it out in order,
//! the client (`client.rs`) says what to do with each, and the loop does it without waiting on anything that can stall: what goes to
//! the terminal and what goes to the broker is written by a writer thread of each. A terminal that is slow, or a broker that stops
//! reading (it does, for as long as a shell does not take what was typed), holds up its own writer and nothing else: keys reach the
//! broker while output waits for the terminal, and a signal is handled at once.
//!
//! Nothing piles up in the CLI without a bound. A frame from the broker counts against a budget until the terminal has taken it, and
//! the thread that reads the frames waits while the budget is spent. The broker's relay then waits to write to the CLI and stops taking
//! from the engine's queue for the shell, which never waits (spec §6.3): once that queue is full, the output that does not fit is
//! dropped, and the stream says in a line how many bytes are missing. SSH's window is not involved, and the remote is not slowed down.
//! What was typed counts against another budget until the broker has taken it, and the keys stay in the terminal meanwhile. A size
//! that waits for the broker gives way to a newer one. And a watchdog ends the program when its loop does not (`Watchdog`).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use super::client::{Action, Client, Input};
use super::terminal::{Restorer, Tty};
use crate::session::protocol::{decode, read_frame, write_control, write_data, write_frame, ClientMessage, Frame, HostQuery, ServerMessage, CONTROL};

/// How much of the broker's output may be on its way to the terminal at a time (read from the broker, not written to the terminal yet).
const OUTPUT_IN_FLIGHT: usize = 256 * 1024;
/// How much of what was typed may be on its way to the broker at a time.
const KEYS_IN_FLIGHT: usize = 64 * 1024;
/// How long a change of the terminal's mode waits for what was written before it to reach the terminal.
const MODE_WAIT: Duration = Duration::from_secs(1);
/// How long an end the program decides waits, in all, for the last output, what the CLI says at the end, and `close` to be written; and
/// how long an end the session came to waits for a terminal that takes nothing.
const END_WAIT: Duration = Duration::from_millis(1500);
/// How long the watchdog gives the loop to end the program after a signal that ends it, or after the terminal went away.
pub const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long the watchdog waits for a change of the terminal in progress before it puts the terminal back all the same.
const WATCHDOG_TERMINAL_WAIT: Duration = Duration::from_millis(200);
/// How often the keys thread looks whether the terminal went away while it waits for the broker to take what was typed.
const HANGUP_CHECK: Duration = Duration::from_millis(250);
/// How long, at most, the terminal writer waits at a time for a terminal that would not take more (its descriptor non-blocking).
const WRITABLE_WAIT_MS: i32 = 100;
/// How much the terminal writer writes at a time: it notes that it got on after each piece, so that a slow terminal is told from one that
/// takes nothing.
const PIECE: usize = 4096;
/// How often a wait for the terminal writer looks whether the writer still gets on.
const MOVING_CHECK: Duration = Duration::from_millis(100);

/// Runs one session over `stream`, connected to the broker, until it ends; returns the program's exit code. `inputs` brings the keys,
/// resizes and signals (`stdin_thread`, `signal_thread`); the broker's frames join it from a thread started here. What is written to
/// `stdout` and `stderr` (the terminal) is written by a thread of its own, and so is what is written to the broker.
pub fn run(stream: UnixStream, host: HostQuery, term: String, tty: &mut Tty, inputs: (Inputs, Queue), stdout: impl Into<Output>, stderr: impl Into<Output>) -> i32 {
    let (inputs, queue) = inputs;
    let (stdout, mut stderr) = (stdout.into(), stderr.into());
    let size = tty.size().unwrap_or((80, 24));
    let Ok(reader) = stream.try_clone() else {
        let _ = stderr.write_whole(b"The connection to SSHelter failed.\n");
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
    /// waited for only before its mode changes and at the end, each time for a bounded time. `credit` is what the input that led to
    /// `actions` counts against its budget: it is given back once what the input brought has been written where it goes (the broker's
    /// output to the terminal, what was typed to the broker), or at once if it went nowhere. A broker that no longer takes what is
    /// written is a broker that went away: its end of the connection arrives as `Input::Closed` from the reader.
    fn perform(&mut self, actions: Vec<Action>, credit: Option<Credit>) -> Option<i32> {
        // An end (its last action exits) that the program decides tells the broker `close` (a signal, the terminal gone, a failure of its
        // own): its writes wait END_WAIT in all. An end the session came to (the shell exited; the broker ended the session, or went
        // away) waits for the terminal to take what the shell printed last for as long as the terminal goes on taking it, as OpenSSH
        // writes all of it before it exits; it gives up only when the terminal takes nothing for END_WAIT. What waits for the terminal
        // is at most the output's budget, so that wait ends too.
        let ends = matches!(actions.last(), Some(Action::Exit(_)));
        let leaving = actions.iter().any(|action| matches!(action, Action::Send(ClientMessage::Close)));
        let deadline = (ends && leaving).then(|| Instant::now() + END_WAIT);
        let wait = |most: Duration| deadline.map_or(most, |deadline| deadline.saturating_duration_since(Instant::now()).min(most));
        let shown_out = |terminal: &TerminalWriter, most: Duration| {
            if ends && !leaving {
                terminal.written_while_moving(END_WAIT)
            } else {
                terminal.written(wait(most))
            }
        };
        let (mut shown, mut posted) = (false, false);
        for action in actions {
            match action {
                Action::Send(ClientMessage::WindowChange { cols, rows }) => {
                    self.broker.size(cols, rows);
                    posted = true;
                }
                Action::Send(message) => {
                    self.broker.post(Post::Message(message));
                    posted = true;
                }
                Action::Answer { question_id, value } => {
                    // The password stays in `value`, which is wiped when the writer drops it, after writing it; `write_answer` wipes the rest.
                    self.broker.post(Post::Answer { question_id, value });
                    posted = true;
                }
                Action::SendData(bytes) => {
                    // Keystrokes can be a password too (typed at a prompt the shell shows): wiped when the writer drops them.
                    self.broker.post(Post::Data(Zeroizing::new(bytes)));
                    posted = true;
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
                    shown_out(&self.terminal, MODE_WAIT);
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
                    shown_out(&self.terminal, END_WAIT);
                    self.broker.written(wait(END_WAIT));
                    self.tty.restore();
                    return Some(code);
                }
            }
        }
        match credit {
            Some(credit) if credit.toward() == Toward::Terminal && shown => self.terminal.show(Show::Release(credit)),
            Some(credit) if credit.toward() == Toward::Broker && posted => self.broker.post(Post::Release(credit)),
            _ => {}
        }
        None
    }
}

/// Where what a budget counts is written out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Toward {
    /// The broker's output, to the terminal.
    Terminal,
    /// What was typed, to the broker.
    Broker,
}

/// Bytes of one kind on their way through the program: counted when they are read, given back when they have been written where they
/// go, or dropped (`Credit`). The thread that reads them waits while the budget is spent, so that what cannot be written yet is not
/// read: the keys stay in the terminal, and the broker's output in the broker (what becomes of it there: the module's doc).
struct Budget {
    limit: usize,
    toward: Toward,
    used: Mutex<usize>,
    freed: Condvar,
}

impl Budget {
    fn new(limit: usize, toward: Toward) -> Arc<Budget> {
        Arc::new(Budget { limit, toward, used: Mutex::new(0), freed: Condvar::new() })
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

    /// Waits until the budget is not spent. `still_wanted` is asked every `every` meanwhile; `false` from it stops the wait, and is
    /// returned.
    fn wait_room(&self, every: Duration, mut still_wanted: impl FnMut() -> bool) -> bool {
        let mut used = self.used();
        while *used >= self.limit {
            let (now, waited) = self.freed.wait_timeout(used, every).unwrap_or_else(PoisonError::into_inner);
            used = now;
            if waited.timed_out() && *used >= self.limit {
                drop(used);
                if !still_wanted() {
                    return false;
                }
                used = self.used();
            }
        }
        true
    }

    /// Counts `bytes` without waiting (the reader waited for room before it read them).
    fn charge(self: &Arc<Self>, bytes: usize) -> Credit {
        *self.used() += bytes;
        Credit { budget: Arc::clone(self), bytes }
    }
}

/// Bytes counted against a budget until this is dropped.
struct Credit {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Credit {
    fn toward(&self) -> Toward {
        self.budget.toward
    }
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
    keys: Arc<Budget>,
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

    /// What was typed. The keys thread waited for room in the budget before it read it.
    fn typed(&self, bytes: Zeroizing<Vec<u8>>) -> Result<(), LoopGone> {
        let credit = self.keys.charge(bytes.len());
        self.queue(Input::Stdin(bytes), Some(credit))
    }

    /// The end of input (Ctrl-D at a question). It counts as a byte of the keys' budget: a terminal that read as nothing again and again
    /// without saying it hung up could not fill the queue with them.
    fn input_ended(&self) -> Result<(), LoopGone> {
        let credit = self.keys.charge(1);
        self.queue(Input::StdinEnd, Some(credit))
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
    let inputs = Inputs { sender, output: Budget::new(OUTPUT_IN_FLIGHT, Toward::Terminal), keys: Budget::new(KEYS_IN_FLIGHT, Toward::Broker) };
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

/// One of the terminal's streams (standard output, standard error) as the terminal writer writes it, with its descriptor when it has
/// one. Another program may have left the terminal's descriptor non-blocking (it is shared, so the CLI does not change it back): a write
/// that would block then says so instead of waiting, and the writer waits on the descriptor until the terminal takes more, as a
/// blocking write would have.
pub struct Output {
    writer: Box<dyn Write + Send>,
    descriptor: Option<RawFd>,
}

impl Output {
    /// A stream with a descriptor to wait on.
    pub fn of<W: Write + AsRawFd + Send + 'static>(writer: W) -> Output {
        let descriptor = Some(writer.as_raw_fd());
        Output { writer: Box::new(writer), descriptor }
    }

    /// Writes all of `bytes`, waiting out the writes that would block. An error of any other kind is the end of the stream (a pipe nobody
    /// reads any more, a terminal that went away).
    fn write_whole(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut rest = bytes;
        while !rest.is_empty() {
            match self.writer.write(rest) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => rest = &rest[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait_writable()?,
                Err(error) => return Err(error),
            }
        }
        loop {
            match self.writer.flush() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait_writable()?,
                flushed => return flushed,
            }
        }
    }

    /// Waits, for a while at most, until the stream takes more. A stream whose other end went away is the end of it.
    fn wait_writable(&mut self) -> io::Result<()> {
        let Some(descriptor) = self.descriptor else {
            // Nothing to wait on (a stream of a test): a moment.
            std::thread::sleep(Duration::from_millis(1));
            return Ok(());
        };
        if poll_for(descriptor, libc::POLLOUT, WRITABLE_WAIT_MS)? & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the terminal went away"));
        }
        Ok(())
    }
}

impl<W: Write + Send + 'static> From<W> for Output {
    /// A stream without a descriptor (a test's).
    fn from(writer: W) -> Output {
        Output { writer: Box::new(writer), descriptor: None }
    }
}

/// The writer of the terminal: standard output and standard error, in the order they were given, on a thread of its own.
struct TerminalWriter {
    jobs: Sender<Show>,
    /// When the writer last got on: took a job, or wrote a piece of one.
    moved: Arc<Mutex<Instant>>,
}

impl TerminalWriter {
    fn start(stdout: impl Into<Output>, stderr: impl Into<Output>, inputs: &Inputs) -> TerminalWriter {
        let (mut stdout, mut stderr) = (stdout.into(), stderr.into());
        let (jobs, given) = std::sync::mpsc::channel::<Show>();
        let moved = Arc::new(Mutex::new(Instant::now()));
        let moving = Arc::clone(&moved);
        spawn_worker("sshelter-terminal", inputs.clone(), move |_| {
            let got_on = || *moving.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
            // What a job brings is written a piece at a time, and each piece written counts as getting on.
            let write = |output: &mut Output, bytes: &[u8]| -> io::Result<()> {
                for piece in bytes.chunks(PIECE) {
                    output.write_whole(piece)?;
                    got_on();
                }
                Ok(())
            };
            // A stream that failed (a pipe nobody reads any more, a terminal that went away) is not written to again; what is given for it
            // is dropped, so that nothing waits for it. A write that would block is not a failure (`Output::write_whole`).
            let (mut stdout_works, mut stderr_works) = (true, true);
            for job in given {
                got_on();
                match job {
                    Show::Output(bytes) => stdout_works = stdout_works && write(&mut stdout, &bytes).is_ok(),
                    Show::Said(text) => stderr_works = stderr_works && write(&mut stderr, text.as_bytes()).is_ok(),
                    Show::Release(credit) => drop(credit),
                    Show::Mark(reached) => {
                        let _ = reached.send(());
                    }
                }
            }
        });
        TerminalWriter { jobs, moved }
    }

    fn show(&self, job: Show) {
        let _ = self.jobs.send(job);
    }

    /// Waits until everything given so far has been written, or `wait` has passed; whether it has.
    fn written(&self, wait: Duration) -> bool {
        wait_for_mark(|mark| self.jobs.send(Show::Mark(mark)).is_ok(), wait)
    }

    /// Waits until everything given so far has been written, for as long as the writer gets on: a slow terminal is waited for, one that
    /// has taken nothing for `stall` is not. Whether everything was written.
    fn written_while_moving(&self, stall: Duration) -> bool {
        let (mark, reached) = std::sync::mpsc::sync_channel(1);
        if self.jobs.send(Show::Mark(mark)).is_err() {
            return false;
        }
        loop {
            match reached.recv_timeout(MOVING_CHECK) {
                Ok(()) => return true,
                Err(RecvTimeoutError::Timeout) if self.moved.lock().unwrap_or_else(PoisonError::into_inner).elapsed() < stall => {}
                Err(_) => return false,
            }
        }
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
    /// Given back once everything given before it has been written.
    Release(Credit),
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
                    Post::Release(credit) => {
                        drop(credit);
                        continue;
                    }
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

/// Where the keys come from: the terminal on standard input (`TerminalKeys`), or a fake one in tests.
trait Keys: Read {
    /// Waits until something can be read. Called when a read found nothing on a terminal that does not wait for keys (another program
    /// left the descriptor non-blocking: the descriptor is shared, so the CLI does not change it back).
    fn wait_readable(&mut self) -> io::Result<()>;
    /// Whether the terminal went away (its window was closed), looked at without waiting.
    fn hung_up(&mut self) -> bool;
}

/// The terminal on standard input, read through `source`; `descriptor` is where `source` reads.
struct TerminalKeys<R> {
    source: R,
    descriptor: RawFd,
}

impl<R: Read> Read for TerminalKeys<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.source.read(buf)
    }
}

impl<R: Read> Keys for TerminalKeys<R> {
    fn wait_readable(&mut self) -> io::Result<()> {
        poll_for(self.descriptor, libc::POLLIN, -1).map(|_| ())
    }

    fn hung_up(&mut self) -> bool {
        poll_for(self.descriptor, libc::POLLIN, 0).is_ok_and(|events| events & libc::POLLHUP != 0)
    }
}

/// `poll` for `events` on `descriptor`, for up to `timeout_ms` milliseconds (-1: as long as it takes); the events it saw (none: 0).
fn poll_for(descriptor: RawFd, events: libc::c_short, timeout_ms: i32) -> io::Result<libc::c_short> {
    let mut entry = libc::pollfd { fd: descriptor, events, revents: 0 };
    loop {
        // SAFETY: one valid `pollfd`, and its count.
        let ready = unsafe { libc::poll(&mut entry, 1, timeout_ms) };
        if ready >= 0 {
            return Ok(if ready == 0 { 0 } else { entry.revents });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Reads the person's keys into the queue until the terminal goes away, or the program ends. A terminal that went away ends the session
/// as SIGHUP does (`Input::Stop`), and `hung_up` is called then (the program arms its watchdog).
pub fn stdin_thread(inputs: Inputs, hung_up: impl FnOnce() + Send + 'static) {
    // Not through `std::io::stdin()`: its buffer keeps a copy of what is read through it, for as long as the program runs, unless the
    // read is at least as large as that buffer (8 KiB; measured: a read of 8191 bytes leaves what was typed in it, one of 8192 does
    // not), and what is typed can be a password. A duplicate of the descriptor is read directly, with no buffer of std's in between.
    match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(descriptor) => {
            let raw = descriptor.as_raw_fd();
            keys_thread(TerminalKeys { source: std::fs::File::from(descriptor), descriptor: raw }, inputs, hung_up);
        }
        Err(_) => keys_thread(TerminalKeys { source: std::io::stdin(), descriptor: libc::STDIN_FILENO }, inputs, hung_up),
    }
}

/// `read_keys` on a thread of its own; a terminal that went away is told to the queue as SIGHUP would be.
fn keys_thread(mut source: impl Keys + Send + 'static, inputs: Inputs, hung_up: impl FnOnce() + Send + 'static) {
    spawn_worker("sshelter-keys", inputs, move |inputs| {
        if read_keys(&mut source, &inputs) == KeysEnd::HungUp && inputs.send(Input::Stop(libc::SIGHUP)).is_ok() {
            hung_up();
        }
    });
}

/// Why `read_keys` returned.
#[derive(Debug, PartialEq, Eq)]
enum KeysEnd {
    /// The loop is gone.
    LoopGone,
    /// The terminal failed (the end of input was told).
    Failed,
    /// The terminal went away.
    HungUp,
}

/// Queues what `source` (the terminal) delivers, as typed text. A read of nothing is the end of input (Ctrl-D at a question, once at
/// each), unless the terminal says it hung up (POLLHUP): a closed window reads as nothing, again and again, and says so (measured on
/// macOS; Linux reads it as EIO, or as nothing with POLLHUP once the terminal is hung up). A hang-up seen while the keys wait for the
/// broker ends the thread too. A failed read is the end of the terminal.
fn read_keys(source: &mut impl Keys, inputs: &Inputs) -> KeysEnd {
    let mut buf = [0u8; 4096];
    loop {
        // While what was typed before waits for the broker, the keys stay in the terminal; it is looked at for a hang-up meanwhile.
        if !inputs.keys.wait_room(HANGUP_CHECK, || !source.hung_up()) {
            return KeysEnd::HungUp;
        }
        match source.read(&mut buf) {
            Ok(0) if source.hung_up() => return KeysEnd::HungUp,
            Ok(0) => {
                // A question ends on Ctrl-D; the next question reads again.
                if inputs.input_ended().is_err() {
                    return KeysEnd::LoopGone;
                }
            }
            Ok(count) => {
                let typed = Zeroizing::new(buf[..count].to_vec());
                // What was typed may be a password: the copy that stays on this stack is wiped as well.
                buf[..count].zeroize();
                if inputs.typed(typed).is_err() {
                    return KeysEnd::LoopGone;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if source.wait_readable().is_err() {
                    let _ = inputs.send(Input::StdinEnd);
                    return KeysEnd::Failed;
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => return KeysEnd::HungUp,
            Err(_) => {
                let _ = inputs.send(Input::StdinEnd);
                return KeysEnd::Failed;
            }
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
/// first. A signal that ends the program arms `watchdog`, which ends it if the loop does not.
///
/// Ctrl-Z (SIGTSTP, at a question or while connecting; `kill -TSTP` too) stops the program as OpenSSH does, with the terminal put back
/// (`terminal`) for the shell; SIGCONT sets the program's mode again, since the shell does not, and the client asks a question on the
/// terminal again (`Input::Continue`) and sends the size, which may have changed while the program was stopped.
pub fn signal_thread(inputs: Inputs, terminal: Restorer, watchdog: Watchdog, size: impl Fn() -> Option<(u16, u16)> + Send + 'static) -> std::io::Result<()> {
    signals(inputs, terminal, watchdog, size, stop_for_real)
}

/// `signal_thread`, stopping the program with `stop` (tests stop it in other ways).
fn signals(inputs: Inputs, terminal: Restorer, watchdog: Watchdog, size: impl Fn() -> Option<(u16, u16)> + Send + 'static, stop: impl Fn() + Send + 'static) -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    // The handlers are installed here, before the thread runs: a signal that comes right after this returns finds them in place.
    let (mut resize, mut interrupt, mut terminate, mut hangup, mut quit, mut suspend, mut continued) = runtime.block_on(async {
        Ok::<_, std::io::Error>((
            signal(SignalKind::window_change())?,
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
            signal(SignalKind::quit())?,
            signal(SignalKind::from_raw(libc::SIGTSTP))?,
            signal(SignalKind::from_raw(libc::SIGCONT))?,
        ))
    })?;
    spawn_worker("sshelter-signals", inputs, move |inputs| {
        let sized = |inputs: &Inputs| match size() {
            Some((cols, rows)) => inputs.send(Input::Resize(cols, rows)),
            None => Ok(()),
        };
        let ends = |inputs: &Inputs, signal: i32| {
            inputs.send(input_for(signal))?;
            watchdog.arm(128 + signal);
            Ok(())
        };
        runtime.block_on(async {
            loop {
                let told: Result<(), LoopGone> = tokio::select! {
                    _ = resize.recv() => sized(&inputs),
                    _ = interrupt.recv() => inputs.send(input_for(libc::SIGINT)),
                    _ = terminate.recv() => ends(&inputs, libc::SIGTERM),
                    _ = hangup.recv() => ends(&inputs, libc::SIGHUP),
                    _ = quit.recv() => ends(&inputs, libc::SIGQUIT),
                    _ = suspend.recv() => {
                        terminal.suspend(&stop);
                        Ok(())
                    }
                    _ = continued.recv() => {
                        terminal.resume();
                        inputs.send(Input::Continue).and_then(|()| sized(&inputs))
                    }
                };
                if told.is_err() {
                    return;
                }
            }
        })
    });
    Ok(())
}

/// Stops the program the way SIGTSTP does without a handler, as OpenSSH's readpassphrase does: the default action is put back for a
/// moment and the signal sent again. The program stops before `kill` returns, and goes on from there when it is continued (SIGCONT). In
/// a process group no shell looks after (an orphaned one) the system discards the stop, as it would without the handler.
fn stop_for_real() {
    // SAFETY: `sigaction` with structures that are wholly initialised (zeroed, then the default action and an empty mask); the handler
    // that was in place (tokio's) is put back as it was.
    unsafe {
        let mut default: libc::sigaction = std::mem::zeroed();
        default.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut default.sa_mask);
        let mut handler: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGTSTP, &default, &mut handler) != 0 {
            return;
        }
        libc::kill(libc::getpid(), libc::SIGTSTP);
        libc::sigaction(libc::SIGTSTP, &handler, std::ptr::null_mut());
    }
}

/// Ends the program when its loop does not. Once armed (a signal that ends the program, or the terminal gone), it gives the loop a
/// grace time to end the program; after that it puts the terminal back and ends the program itself, with the status the loop would have
/// given (128 + the signal's number). The loop waits on nothing for long, but a terminal that blocks a change of its mode, or a mistake,
/// must not leave a program that ignores SIGTERM with the terminal raw.
#[derive(Clone)]
pub struct Watchdog {
    alarm: Arc<Alarm>,
    grace: Duration,
}

#[derive(Default)]
struct Alarm {
    state: Mutex<AlarmState>,
    changed: Condvar,
}

#[derive(Default)]
struct AlarmState {
    /// When to end the program, and with what status.
    set: Option<(Instant, i32)>,
    /// The run is over: the program exits on its own.
    off: bool,
}

impl Watchdog {
    /// Starts the thread that waits for the alarm: `terminal` is put back, and `exit` ends the program, `grace` after the alarm was set
    /// (`arm`) unless the run is over by then (`stand_down`).
    pub fn start(terminal: Restorer, grace: Duration, exit: impl FnOnce(i32) + Send + 'static) -> std::io::Result<Watchdog> {
        let alarm = Arc::new(Alarm::default());
        let watching = Arc::clone(&alarm);
        std::thread::Builder::new().name("sshelter-watchdog".to_string()).spawn(move || {
            if let Some(code) = watching.wait_for_its_time() {
                // The terminal stays put back until the program has ended: the loop cannot set its mode again meanwhile.
                let _held = terminal.hold_restored(WATCHDOG_TERMINAL_WAIT);
                exit(code);
            }
        })?;
        Ok(Watchdog { alarm, grace })
    }

    /// The program is to end with `code`; unless the run is over within the grace time, the watchdog ends it. Only the first alarm
    /// counts.
    pub fn arm(&self, code: i32) {
        let mut state = self.alarm.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.set.is_none() {
            state.set = Some((Instant::now() + self.grace, code));
        }
        drop(state);
        self.alarm.changed.notify_all();
    }

    /// The run is over: the program exits on its own, and the watchdog has nothing more to do.
    pub fn stand_down(&self) {
        self.alarm.state.lock().unwrap_or_else(PoisonError::into_inner).off = true;
        self.alarm.changed.notify_all();
    }
}

impl Alarm {
    /// Waits until the alarm's time has come (its status), or the run is over (`None`).
    fn wait_for_its_time(&self) -> Option<i32> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if state.off {
                return None;
            }
            state = match state.set {
                None => self.changed.wait(state).unwrap_or_else(PoisonError::into_inner),
                Some((at, code)) => {
                    let now = Instant::now();
                    if now >= at {
                        return Some(code);
                    }
                    self.changed.wait_timeout(state, at - now).unwrap_or_else(PoisonError::into_inner).0
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::cli::terminal::fake::{describe, FakeTermios};
    use crate::cli::terminal::{self, attributes, Mode, TermiosApi};
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
        /// The run's exit code, and whether the terminal was back as it was when `run` returned (`restored_when_run_returns`).
        run: std::thread::JoinHandle<(i32, bool)>,
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
            let (inputs, stdout, stderr, termios) = (inputs.clone(), stdout.clone(), stderr.clone(), Arc::clone(&termios));
            std::thread::spawn(move || {
                let mut tty = Tty::new(terminal).unwrap();
                let code = run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (inputs, queue), Box::new(stdout), Box::new(stderr));
                (code, restored_when_run_returns(&termios))
            })
        };
        Setup { engine, termios, keys: inputs, stdout, stderr, run }
    }

    /// Whether the terminal is as it was at the start, looked at as soon as `run` returns: before the `Tty` is dropped, whose `Drop` puts
    /// the terminal back as well and would hide a run that did not.
    fn restored_when_run_returns(termios: &FakeTermios) -> bool {
        termios.is_start(&termios.now())
    }

    /// The run's end: its exit code, whether it put the terminal back itself, and the rest of the setup.
    fn finish(setup: Setup) -> (i32, bool, Setup) {
        eventually("the run to end", 10, || setup.run.is_finished());
        let Setup { engine, termios, keys, stdout, stderr, run } = setup;
        let (code, restored) = run.join().unwrap();
        (code, restored, Setup { engine, termios, keys, stdout, stderr, run: std::thread::spawn(|| (0, true)) })
    }

    fn raw(termios: &FakeTermios) -> bool {
        termios.now().c_lflag & libc::ICANON == 0
    }

    /// A run where the test plays the broker: it has taken `hello` and `open_shell` from the CLI, and `broker` is its end.
    struct ByHand {
        termios: Arc<FakeTermios>,
        keys: Inputs,
        /// The run's exit code, and whether the terminal was back as it was when `run` returned.
        run: std::thread::JoinHandle<(i32, bool)>,
        broker: UnixStream,
    }

    /// `sshelter connect web` with the test as the broker, a fake terminal `termios`, and the terminal's output and error.
    fn by_hand(termios: Arc<FakeTermios>, stdout: Box<dyn Write + Send>, stderr: Box<dyn Write + Send>) -> ByHand {
        let (ours, mut broker) = UnixStream::pair().unwrap();
        let (inputs, queue) = queue();
        let run = {
            let (termios, inputs) = (Arc::clone(&termios), inputs.clone());
            std::thread::spawn(move || {
                let mut tty = Tty::new(termios.clone()).unwrap();
                let code = run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (inputs, queue), stdout, stderr);
                (code, restored_when_run_returns(&termios))
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

        /// The run's end, which must come within `within` of now: its exit code, and whether it put the terminal back itself.
        fn ends_within(self, within: Duration) -> (i32, bool) {
            let asked = Instant::now();
            eventually("the run to end", 10, || self.run.is_finished());
            assert!(asked.elapsed() < within, "the run took {:?} to end", asked.elapsed());
            self.run.join().unwrap()
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
        let (code, restored, setup) = finish(setup);
        assert_eq!(code, 3);
        assert!(restored, "the terminal is as it was");
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
        let (code, _, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }

    #[test]
    fn a_host_that_cannot_be_reached_is_said_and_the_status_is_255() {
        let setup = connect(FakeEngine::new(), FakeDirectory::new(), MemKeychain::default());
        let (code, _, setup) = finish(setup);
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
        let (code, restored, setup) = finish(setup);
        assert_eq!(code, 128 + libc::SIGHUP);
        assert!(restored, "the terminal is as it was");
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

    /// What the signal thread of a test is given: a terminal of its own in `mode`, and a watchdog that records the status it would end the
    /// program with.
    struct SignalSetup {
        termios: Arc<FakeTermios>,
        tty: Tty,
        watchdog: Watchdog,
        exits: std::sync::mpsc::Receiver<i32>,
    }

    fn signal_setup(mode: Mode) -> SignalSetup {
        let termios = FakeTermios::new();
        let mut tty = Tty::new(termios.clone()).unwrap();
        tty.set_mode(mode, false).unwrap();
        let (exit, exits) = std::sync::mpsc::channel();
        let watchdog = Watchdog::start(tty.restorer(), STOP_GRACE, move |code| exit.send(code).unwrap()).unwrap();
        SignalSetup { termios, tty, watchdog, exits }
    }

    /// The next input the queue holds, within ten seconds.
    fn next_input(queue: &Queue) -> Input {
        queue.receiver.recv_timeout(Duration::from_secs(10)).expect("an input within 10 s").input
    }

    /// The handlers are process-wide and stay for the life of the process, so the test that raises the signals for real runs alone, in a
    /// process of its own (`rerun_alone`); a signal that was not taken over would end that process, and the test with it. Ctrl-Z
    /// (SIGTSTP) does not stop this process here (the stop is replaced): `ctrl_z_really_stops_the_program_and_sigcont_runs_it_again`
    /// stops one for real.
    #[test]
    fn the_signals_the_cli_takes_over_reach_the_queue_instead_of_ending_the_program() {
        use crate::ssh::testing::{is_child, rerun_alone};
        const NAME: &str = "cli::run::tests::the_signals_the_cli_takes_over_reach_the_queue_instead_of_ending_the_program";
        if !is_child() {
            rerun_alone(NAME);
            return;
        }
        let setup = signal_setup(Mode::Prompt { echo: false });
        let (inputs, queue) = queue();
        let (stopped, stops) = std::sync::mpsc::channel();
        let at_the_stop = Arc::clone(&setup.termios);
        let stop = move || stopped.send(at_the_stop.now()).unwrap();
        signals(inputs, setup.tty.restorer(), setup.watchdog.clone(), || Some((100, 30)), stop).expect("the handlers are installed");
        let raise = |signal: i32| {
            // SAFETY: `raise` only sends the signal to this thread, and every signal raised here has a handler by now.
            assert_eq!(unsafe { libc::raise(signal) }, 0);
        };
        let next = |signal: i32| {
            raise(signal);
            next_input(&queue)
        };
        assert!(matches!(next(libc::SIGWINCH), Input::Resize(100, 30)));
        assert!(matches!(next(libc::SIGINT), Input::Interrupt));

        // Ctrl-Z at a hidden password: the program stops with the terminal as it was at the start (echo on, for the shell), and the
        // password's mode is set again after; SIGCONT sets it again (the shell put its own back), asks the question again and sends the
        // size, which may have changed meanwhile.
        raise(libc::SIGTSTP);
        let while_stopped = stops.recv_timeout(Duration::from_secs(10)).expect("stopped");
        assert!(setup.termios.is_start(&while_stopped), "stopped with the terminal put back: {}", describe(&while_stopped));
        let hidden = attributes(&setup.termios.start, Mode::Prompt { echo: false });
        eventually("the mode to be set again", 10, || describe(&setup.termios.now()) == describe(&hidden));
        setup.termios.set(&setup.termios.start, false).unwrap(); // the shell's own modes, echo on
        assert!(matches!(next(libc::SIGCONT), Input::Continue));
        assert!(matches!(next_input(&queue), Input::Resize(100, 30)));
        assert_eq!(describe(&setup.termios.now()), describe(&hidden), "echo is off again");

        // The signals that end the program arm the watchdog, which ends it (here: says it would) if the loop does not.
        let armed = Instant::now();
        assert!(matches!(next(libc::SIGTERM), Input::Stop(libc::SIGTERM)));
        assert!(matches!(next(libc::SIGHUP), Input::Stop(libc::SIGHUP)));
        assert!(matches!(next(libc::SIGQUIT), Input::Stop(libc::SIGQUIT)));
        assert_eq!(setup.exits.recv_timeout(Duration::from_secs(10)), Ok(128 + libc::SIGTERM), "the first one counts");
        assert!(armed.elapsed() >= STOP_GRACE);
        assert!(setup.termios.is_start(&setup.termios.now()), "the watchdog put the terminal back");

        // A panic on the signal thread (here: in the callback that reads the size) is told to the queue as well.
        let other = signal_setup(Mode::Cooked);
        let (failing, told) = super::queue();
        signals(failing, other.tty.restorer(), other.watchdog.clone(), || panic!("the size failed"), || {}).expect("a second set of handlers");
        assert!(matches!(next(libc::SIGWINCH), Input::Resize(100, 30)));
        assert!(matches!(next_input(&told), Input::Failed));
    }

    /// The variable that tells the test below that it is the process that stops.
    const STOPPING_CHILD: &str = "SSHELTER_TEST_STOPPING_CHILD";

    /// Ctrl-Z for real: the program stops (the process, all of it), with the terminal put back; it runs again when it is continued, and
    /// then sets its mode again and asks the question again. The process that stops is a child of the test in a process group of its
    /// own, as a job of a shell is (a stop in a group no shell looks after would be discarded); the test continues it after a pause, as
    /// `fg` does.
    #[test]
    fn ctrl_z_really_stops_the_program_and_sigcont_runs_it_again() {
        const NAME: &str = "cli::run::tests::ctrl_z_really_stops_the_program_and_sigcont_runs_it_again";
        const PAUSE: Duration = Duration::from_millis(500);
        if std::env::var_os(STOPPING_CHILD).is_none() {
            use std::os::unix::process::CommandExt;
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", NAME, "--nocapture", "--test-threads=1"]).env(STOPPING_CHILD, "1").process_group(0);
            command.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped());
            let mut child = crate::process::spawn(&mut command).unwrap();
            let pid = child.id() as libc::pid_t;
            let mut stderr = child.stderr.take().unwrap();
            let said = std::thread::spawn(move || {
                let mut text = String::new();
                let _ = stderr.read_to_string(&mut text);
                text
            });
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut stops = 0;
            let status = loop {
                assert!(Instant::now() < deadline, "the child did not end within a minute");
                let mut status = 0;
                // SAFETY: waits on this test's own child; WNOHANG returns at once.
                match unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) } {
                    0 => std::thread::sleep(Duration::from_millis(10)),
                    reported if reported == pid && libc::WIFSTOPPED(status) => {
                        assert_eq!(libc::WSTOPSIG(status), libc::SIGTSTP, "stopped as Ctrl-Z stops a program");
                        stops += 1;
                        std::thread::sleep(PAUSE);
                        // SAFETY: continues this test's own child.
                        assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
                    }
                    reported if reported == pid => break status,
                    _ => panic!("waitpid failed: {}", std::io::Error::last_os_error()),
                }
            };
            let said = said.join().unwrap();
            assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "the child failed:\n{said}");
            assert_eq!(stops, 1, "stopped once:\n{said}");
            return;
        }
        let setup = signal_setup(Mode::Prompt { echo: false });
        let (inputs, queue) = queue();
        signal_thread(inputs, setup.tty.restorer(), setup.watchdog.clone(), || Some((100, 30))).expect("the handlers are installed");
        let stopped_at = Instant::now();
        // SAFETY: `raise` sends SIGTSTP to this thread, and it has a handler by now.
        assert_eq!(unsafe { libc::raise(libc::SIGTSTP) }, 0);
        assert!(matches!(next_input(&queue), Input::Continue));
        assert!(stopped_at.elapsed() >= PAUSE, "the program was stopped until it was continued");
        let hidden = attributes(&setup.termios.start, Mode::Prompt { echo: false });
        let sets: Vec<String> = setup.termios.sets.lock().unwrap().iter().map(|(termios, _)| describe(termios)).collect();
        assert_eq!(sets[..3], [describe(&hidden), describe(&setup.termios.start), describe(&hidden)], "put back for the stop, set again after");
        assert_eq!(describe(&setup.termios.now()), describe(&hidden));
        assert!(matches!(next_input(&queue), Input::Resize(100, 30)));
    }

    /// The watchdog ends the program (here: says it would) a grace time after it was armed, with the terminal put back and what was typed
    /// thrown away, unless the run was over by then.
    #[test]
    fn the_watchdog_ends_a_program_whose_loop_does_not_end_it() {
        let setup = signal_setup(Mode::Raw);
        let (exit, exits) = std::sync::mpsc::channel();
        let watchdog = Watchdog::start(setup.tty.restorer(), Duration::from_millis(300), move |code| exit.send(code).unwrap()).unwrap();
        let armed = Instant::now();
        watchdog.arm(143);
        watchdog.arm(129);
        assert_eq!(exits.recv_timeout(Duration::from_secs(10)), Ok(143), "the first alarm counts");
        assert!(armed.elapsed() >= Duration::from_millis(300));
        let (last, discarded) = *setup.termios.sets.lock().unwrap().last().unwrap();
        assert!(setup.termios.is_start(&last) && discarded, "put back, and what was typed thrown away");

        let (exit, exits) = std::sync::mpsc::channel();
        let watchdog = Watchdog::start(setup.tty.restorer(), Duration::from_millis(100), move |code| exit.send(code).unwrap()).unwrap();
        watchdog.arm(143);
        watchdog.stand_down();
        assert!(exits.recv_timeout(Duration::from_millis(500)).is_err(), "the run was over: nothing to end");
        let (exit, exits) = std::sync::mpsc::channel();
        let watchdog = Watchdog::start(setup.tty.restorer(), Duration::from_millis(100), move |code| exit.send(code).unwrap()).unwrap();
        watchdog.stand_down();
        watchdog.arm(143);
        assert!(exits.recv_timeout(Duration::from_millis(500)).is_err());
        setup.watchdog.stand_down();
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
        let (code, _, setup) = finish(setup);
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
        inputs.typed(Zeroizing::new(b"more".to_vec())).unwrap();
        inputs.send(Input::StdinEnd).unwrap();
        queue.forget_typed();
        assert_eq!(*inputs.keys.used(), 0, "what the dropped keys counted is given back");
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

    /// A source of keys whose reads are whatever the closure says; it can be told that the terminal hung up.
    struct Keyboard<F> {
        read: F,
        hung_up: Arc<AtomicBool>,
        waits: Arc<AtomicUsize>,
    }

    impl<F: FnMut(&mut [u8]) -> std::io::Result<usize>> Keyboard<F> {
        fn new(read: F) -> Keyboard<F> {
            Keyboard { read, hung_up: Arc::default(), waits: Arc::default() }
        }
    }

    impl<F: FnMut(&mut [u8]) -> std::io::Result<usize>> Read for Keyboard<F> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            (self.read)(buf)
        }
    }

    impl<F: FnMut(&mut [u8]) -> std::io::Result<usize>> Keys for Keyboard<F> {
        fn wait_readable(&mut self) -> std::io::Result<()> {
            self.waits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn hung_up(&mut self) -> bool {
            self.hung_up.load(Ordering::SeqCst)
        }
    }

    /// A keyboard that plays `script`, one read at a time, then fails (the terminal went away).
    fn scripted(script: Vec<std::io::Result<Vec<u8>>>) -> Keyboard<impl FnMut(&mut [u8]) -> std::io::Result<usize>> {
        let mut script = VecDeque::from(script);
        Keyboard::new(move |buf: &mut [u8]| match script.pop_front() {
            Some(Ok(bytes)) => {
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Some(Err(error)) => Err(error),
            None => Err(std::io::Error::other("the terminal went away")),
        })
    }

    /// `work` on a thread of its own, which must end within `seconds`: a test of a loop that must stop fails instead of hanging.
    fn ends_within<T: Send + 'static>(seconds: u64, what: &str, work: impl FnOnce() -> T + Send + 'static) -> T {
        let thread = std::thread::spawn(work);
        eventually(what, seconds, || thread.is_finished());
        thread.join().unwrap()
    }

    /// Everything the queue holds now, in order.
    fn queued(queue: &Queue) -> Vec<Input> {
        std::iter::from_fn(|| queue.receiver.try_recv().ok().map(|queued| queued.input)).collect()
    }

    #[test]
    fn the_keys_are_queued_as_typed_and_the_end_of_input_is_told_and_a_failing_terminal_ends_the_thread() {
        // One read at a time: what is typed, an interrupted read, the end of input (Ctrl-D: a read of 0 bytes), more, then a failure.
        let mut keyboard = scripted(vec![Ok(b"ls\r".to_vec()), Err(std::io::ErrorKind::Interrupted.into()), Ok(vec![]), Ok(b"x".to_vec())]);
        let (inputs, queue) = queue();
        assert_eq!(read_keys(&mut keyboard, &inputs), KeysEnd::Failed);
        let queued = queued(&queue);
        assert_eq!(format!("{queued:?}"), "[Stdin(<hidden>), StdinEnd, Stdin(<hidden>), StdinEnd]", "an interrupted read is read again; the failure is the end");
        assert!(matches!(&queued[0], Input::Stdin(bytes) if &bytes[..] == b"ls\r"));
        assert!(matches!(&queued[2], Input::Stdin(bytes) if &bytes[..] == b"x"));
    }

    /// A terminal descriptor another program left non-blocking reads as "nothing yet" (EAGAIN) when nothing was typed: that is not the end
    /// of input; the keys thread waits until there is something to read, and reads it.
    #[test]
    fn a_terminal_left_non_blocking_is_waited_for_not_taken_for_the_end_of_input() {
        let mut keyboard = scripted(vec![Err(std::io::ErrorKind::WouldBlock.into()), Err(std::io::ErrorKind::WouldBlock.into()), Ok(b"ls\r".to_vec())]);
        let waits = Arc::clone(&keyboard.waits);
        let (inputs, queue) = queue();
        assert_eq!(read_keys(&mut keyboard, &inputs), KeysEnd::Failed);
        assert_eq!(waits.load(Ordering::SeqCst), 2, "waited for something to read, twice");
        let queued = queued(&queue);
        assert_eq!(format!("{queued:?}"), "[Stdin(<hidden>), StdinEnd]");
        assert!(matches!(&queued[0], Input::Stdin(bytes) if &bytes[..] == b"ls\r"));
    }

    /// A closed window: on macOS the terminal reads as nothing, at once and for ever, and says it hung up (POLLHUP; measured); on Linux
    /// it reads as EIO. The keys thread stops there, and tells nothing more.
    #[test]
    fn the_keys_thread_stops_when_the_terminal_hangs_up_instead_of_reading_nothing_for_ever() {
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        let mut keyboard = Keyboard::new(move |_: &mut [u8]| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        });
        keyboard.hung_up.store(true, Ordering::SeqCst);
        let (inputs, queue) = queue();
        assert_eq!(ends_within(5, "the keys thread to stop", move || read_keys(&mut keyboard, &inputs)), KeysEnd::HungUp);
        assert_eq!(format!("{:?}", queued(&queue)), "[]");
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        let mut keyboard = scripted(vec![Ok(b"x".to_vec()), Err(std::io::Error::from_raw_os_error(libc::EIO))]);
        let (inputs, queue) = super::queue();
        assert_eq!(read_keys(&mut keyboard, &inputs), KeysEnd::HungUp);
        assert_eq!(format!("{:?}", queued(&queue)), "[Stdin(<hidden>)]");
    }

    /// Reads of nothing that the terminal does not call a hang-up are ends of input, however many come in a row (Ctrl-D at one question
    /// after another). Were a closed terminal ever to read as nothing for ever without saying so, they could not pile up: each counts
    /// against the keys' budget, so at most so many wait in the queue, and the thread waits for room, looking for a hang-up meanwhile.
    #[test]
    fn ends_of_input_in_a_row_are_not_a_hang_up_and_do_not_pile_up_without_bound() {
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        let mut keyboard = Keyboard::new(move |_: &mut [u8]| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        });
        let hung_up = Arc::clone(&keyboard.hung_up);
        let (inputs, queue) = queue();
        let budget = Arc::clone(&inputs.keys);
        let thread = std::thread::spawn(move || read_keys(&mut keyboard, &inputs));
        eventually("the keys' budget to be spent", 10, || *budget.used() >= KEYS_IN_FLIGHT);
        std::thread::sleep(Duration::from_millis(300));
        assert!(!thread.is_finished(), "not a hang-up");
        assert_eq!(reads.load(Ordering::SeqCst), KEYS_IN_FLIGHT, "an end of input for each byte of the budget, then a wait for room");
        // Two taken out (not all: each one taken out makes room for another).
        for _ in 0..2 {
            assert!(matches!(queue.receiver.try_recv().map(|queued| queued.input), Ok(Input::StdinEnd)));
        }
        hung_up.store(true, Ordering::SeqCst);
        eventually("the keys thread to stop", 5, || thread.is_finished());
        assert_eq!(thread.join().unwrap(), KeysEnd::HungUp);
    }

    /// The terminal went away: the session ends as for SIGHUP (no SIGHUP may come: a terminal's session leader that does not pass it on),
    /// and the program's watchdog is armed.
    #[test]
    fn a_terminal_that_went_away_ends_the_session_as_sighup_does() {
        let keyboard = Keyboard::new(|_: &mut [u8]| Ok(0));
        keyboard.hung_up.store(true, Ordering::SeqCst);
        let (inputs, queue) = queue();
        let (told, hung_up) = std::sync::mpsc::channel();
        keys_thread(keyboard, inputs, move || told.send(()).unwrap());
        assert!(hung_up.recv_timeout(Duration::from_secs(5)).is_ok(), "the watchdog is armed");
        assert_eq!(format!("{:?}", queued(&queue)), "[Stop(1)]");
    }

    /// While what was typed before waits for the broker (the budget is spent), nothing more is read: the keys stay in the terminal. The
    /// terminal is still looked at meanwhile, and a hang-up ends the wait.
    #[test]
    fn the_keys_wait_in_the_terminal_while_the_broker_does_not_take_them_and_a_hang_up_still_ends_the_wait() {
        let (inputs, queue) = queue();
        let budget = Arc::clone(&inputs.keys);
        let waiting = budget.charge(KEYS_IN_FLIGHT);
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        let mut keyboard = Keyboard::new(move |buf: &mut [u8]| {
            counted.fetch_add(1, Ordering::SeqCst);
            buf.fill(b'x');
            Ok(buf.len())
        });
        let hung_up = Arc::clone(&keyboard.hung_up);
        let thread = std::thread::spawn(move || read_keys(&mut keyboard, &inputs));
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(reads.load(Ordering::SeqCst), 0, "nothing is read while the budget is spent");
        drop(waiting);
        // What is read now stays in the queue (nobody takes it to the broker): it spends the budget again, and the reads stop.
        eventually("the budget to be spent again", 5, || *budget.used() >= KEYS_IN_FLIGHT);
        let reads_now = reads.load(Ordering::SeqCst);
        assert_eq!(reads_now, KEYS_IN_FLIGHT / 4096, "read until the budget was spent, no more");
        hung_up.store(true, Ordering::SeqCst);
        eventually("the keys thread to stop", 5, || thread.is_finished());
        assert_eq!(thread.join().unwrap(), KeysEnd::HungUp);
        assert_eq!(reads.load(Ordering::SeqCst), reads_now, "nothing more was read");
        drop(queue);
    }

    /// The loop is gone, the keyboard never stops: the thread has to be the one that stops (and the test fails, not hangs, if it does not).
    #[test]
    fn the_keys_thread_stops_when_the_loop_is_gone() {
        let (inputs, queue) = queue();
        drop(queue);
        let mut keyboard = Keyboard::new(|buf: &mut [u8]| {
            buf[0] = b'x';
            Ok(1)
        });
        assert_eq!(ends_within(5, "the keys thread to stop", move || read_keys(&mut keyboard, &inputs)), KeysEnd::LoopGone);
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
        let keyboard = Keyboard::new(|_: &mut [u8]| -> std::io::Result<usize> { panic!("the keyboard failed") });
        keys_thread(keyboard, setup.keys.clone(), || {});
        let (code, restored, setup) = finish(setup);
        assert_eq!(code, 255);
        assert!(restored, "the terminal is as it was");
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
        let (code, restored) = hand.ends_within(Duration::from_secs(3));
        assert_eq!(code, 143);
        assert!(restored, "the terminal is as it was");
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
        let (code, restored) = hand.ends_within(MODE_WAIT + END_WAIT + Duration::from_secs(1));
        assert_eq!(code, 143);
        assert!(restored, "the terminal is as it was");
        stdout.let_go();
        let _ = printing.join();
    }

    /// The remote prints far faster than the terminal takes it (here: not at all). What waits for the terminal in the CLI is bounded: the
    /// CLI stops reading its connection, and the broker's writes to it wait (the broker's relay then stops taking from the engine's queue,
    /// which drops what does not fit; spec §6.3). And a key does not wait behind that output: Ctrl-C reaches the broker at once, as
    /// OpenSSH sends it.
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
        eventually("the broker's writes to wait", 10, || {
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

    /// A terminal that takes `rate` bytes a second: each write takes its share of the time.
    #[derive(Clone)]
    struct Paced {
        shown: Shared,
        rate: f64,
    }

    impl Write for Paced {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_secs_f64(bytes.len() as f64 / self.rate));
            self.shown.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A session that ends at the broker's (here the connection was lost) waits, before the program exits, for the terminal to take what
    /// the shell printed last, for as long as it goes on taking it (OpenSSH writes all of it before it exits), and then for why the
    /// session ended. Here the terminal takes 100 KiB a second, so what waits for it when the end comes (up to the output's budget,
    /// 256 KiB) takes longer than the end's wait for an end the program decides (END_WAIT).
    #[test]
    fn the_last_output_and_the_reason_reach_a_slow_terminal_before_the_program_exits() {
        let (stdout, stderr) = (Paced { shown: Shared::default(), rate: 100.0 * 1024.0 }, Slow::default());
        let mut hand = by_hand(FakeTermios::new(), Box::new(stdout.clone()), Box::new(stderr.clone()));
        hand.open();
        let mut remote = hand.broker.try_clone().unwrap();
        // On a thread of its own: the CLI takes the output as fast as the terminal does, and this waits with it.
        let printing = std::thread::spawn(move || {
            for _ in 0..10 {
                write_data(&mut remote, &[b'x'; 32 * 1024]).unwrap();
            }
            write_control(&mut remote, &ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost.".into() })).unwrap();
            write_control(&mut remote, &ServerMessage::Exited { code: None, signal: None }).unwrap();
        });
        assert_eq!(hand.ends_within(Duration::from_secs(10)).0, 255);
        printing.join().unwrap();
        assert_eq!(stdout.shown.len(), 320 * 1024, "all of the shell's last output");
        assert_eq!(stderr.0.text(), "\nConnection to web lost.\n");
    }

    /// A terminal that takes nothing does not keep a session that ended from ending: the end waits for the terminal only while it takes
    /// something, and goes on after END_WAIT without.
    #[test]
    fn a_terminal_that_takes_nothing_does_not_keep_a_session_that_ended_from_ending() {
        let stdout = Stalled::default();
        let mut hand = by_hand(FakeTermios::new(), Box::new(stdout.clone()), Box::new(Shared::default()));
        hand.open();
        let mut remote = hand.broker.try_clone().unwrap();
        let printing = std::thread::spawn(move || {
            for _ in 0..4 {
                write_data(&mut remote, &[b'x'; 32 * 1024]).unwrap();
            }
            write_control(&mut remote, &ServerMessage::Exited { code: Some(0), signal: None }).unwrap();
        });
        let (code, restored) = hand.ends_within(2 * END_WAIT + Duration::from_secs(1));
        assert_eq!(code, 0);
        assert!(restored, "the terminal is as it was");
        stdout.let_go();
        printing.join().unwrap();
    }

    /// A terminal whose descriptor another program left non-blocking: a write that would block says so (`WouldBlock`) instead of waiting,
    /// here three times before each write it takes, and it takes at most a kilobyte at a time (a pty takes about that much).
    struct LeftNonBlocking {
        shown: Shared,
        refusals: usize,
    }

    impl Write for LeftNonBlocking {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.refusals < 3 {
                self.refusals += 1;
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            self.refusals = 0;
            self.shown.write(&bytes[..bytes.len().min(1024)])
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A write that would block is not a terminal that failed: the writer waits and writes on, and every byte is shown, in order, on
    /// standard output and on standard error. (It used to stop writing for good: a kilobyte shown, and nothing more while the session
    /// lived.)
    #[test]
    fn a_terminal_left_non_blocking_is_shown_every_byte_in_order() {
        let (stdout, stderr) = (Shared::default(), Shared::default());
        let (inputs, _queue) = queue();
        let writer = TerminalWriter::start(
            Box::new(LeftNonBlocking { shown: stdout.clone(), refusals: 0 }),
            Box::new(LeftNonBlocking { shown: stderr.clone(), refusals: 0 }),
            &inputs,
        );
        let output: Vec<u8> = (0..96 * 1024u32).map(|i| (i % 251) as u8).collect();
        for chunk in output.chunks(32 * 1024) {
            writer.show(Show::Output(chunk.to_vec()));
        }
        writer.show(Show::Said("sshelter: said after the output\n".into()));
        assert!(writer.written(Duration::from_secs(10)), "all of it written");
        assert!(*stdout.0.lock().unwrap() == output, "{} of {} bytes shown, or not in order", stdout.len(), output.len());
        assert_eq!(stderr.text(), "sshelter: said after the output\n");
    }

    /// A real descriptor left non-blocking, taken from slowly: the writer waits on it (POLLOUT) until it takes more, and nothing is lost.
    #[test]
    fn a_non_blocking_descriptor_is_waited_on_until_it_takes_more() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let (inputs, _queue) = queue();
        let writer = TerminalWriter::start(Output::of(ours), Box::new(Shared::default()), &inputs);
        let output: Vec<u8> = (0..1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        for chunk in output.chunks(32 * 1024) {
            writer.show(Show::Output(chunk.to_vec()));
        }
        let length = output.len();
        // The terminal reads slowly; it stops when nothing has come for a while (a writer that gave up), so that the test fails, not hangs.
        theirs.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let reading = std::thread::spawn(move || {
            let (mut shown, mut buf) = (Vec::new(), [0u8; 8192]);
            while shown.len() < length {
                std::thread::sleep(Duration::from_millis(1));
                match theirs.read(&mut buf) {
                    Ok(count) if count > 0 => shown.extend_from_slice(&buf[..count]),
                    _ => break,
                }
            }
            shown
        });
        assert!(writer.written(Duration::from_secs(20)), "all of it written");
        let shown = reading.join().unwrap();
        assert!(shown == output, "{} of {} bytes shown, or not in order", shown.len(), output.len());
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
        let budget = Budget::new(100, Toward::Terminal);
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
        let large = ends_within(5, "a large item through an empty budget", {
            let budget = Arc::clone(&budget);
            move || budget.take(1000)
        });
        assert_eq!(*budget.used(), 1000);
        drop(large);
        assert!(budget.wait_room(Duration::from_millis(10), || panic!("not asked: there is room")));
        let full = budget.charge(100);
        assert!(!budget.wait_room(Duration::from_millis(10), || false), "stopped waiting when told to");
        drop(full);
    }

    /// A pty: its controller (the terminal emulator's end, where keys are typed) and its device (the program's terminal).
    fn pty() -> (std::fs::File, std::fs::File) {
        use std::os::fd::FromRawFd;
        // `openpty` does not open its descriptors close-on-exec: while they are opened and marked, no other test may start a process,
        // which would keep the controller open (and the terminal from hanging up) for as long as it runs.
        crate::process::without_spawns(|| {
            let (mut controller, mut device): (libc::c_int, libc::c_int) = (-1, -1);
            // SAFETY: openpty fills in the two descriptors; the name, attributes and size are optional.
            assert_eq!(unsafe { libc::openpty(&mut controller, &mut device, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) }, 0);
            for descriptor in [controller, device] {
                // SAFETY: a descriptor just opened here; only FD_CLOEXEC is set.
                assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) }, 0);
            }
            // SAFETY: both descriptors were just opened, and are owned here.
            unsafe { (std::fs::File::from_raw_fd(controller), std::fs::File::from_raw_fd(device)) }
        })
    }

    /// What a terminal holds for whoever reads it next (the shell, after the program): read with line editing off, as a shell's line
    /// editor reads, without waiting. A partial line becomes readable then.
    fn left_in(device: &std::fs::File) -> Vec<u8> {
        let descriptor = device.as_raw_fd();
        let mut raw = terminal::read_attributes(descriptor).unwrap();
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;
        terminal::write_attributes(descriptor, &raw, false).unwrap();
        let mut buf = [0u8; 64];
        let count = (&*device).read(&mut buf).unwrap_or(0);
        buf[..count].to_vec()
    }

    /// What was typed at a question and not sent (`hunt`: a part of a password, no Enter yet) was meant for SSHelter. When the session
    /// ends under the question (here the broker ends it, as when the question's deadline passes), the terminal is put back with what it
    /// holds thrown away, as readpassphrase does: the shell that gets the terminal next would read it, show it on its line and keep it in
    /// its history (measured with bash 5 and zsh 5.9). The real terminal calls, on a pty.
    #[test]
    fn what_was_typed_at_a_question_does_not_reach_the_shell_when_the_session_ends_under_it() {
        use crate::session::protocol::{kinds, Question, QuestionKind};
        let (mut controller, device) = pty();
        let descriptor = device.as_raw_fd();
        let (ours, mut broker) = UnixStream::pair().unwrap();
        let (inputs, queue) = queue();
        let run = std::thread::spawn(move || {
            let mut tty = Tty::new(Arc::new(DeviceTermios(descriptor))).unwrap();
            run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (inputs, queue), Box::new(Shared::default()), Box::new(Shared::default()))
        });
        for expected in ["Hello", "OpenShell"] {
            assert!(format!("{:?}", next_message(&mut broker)).starts_with(expected));
        }
        let question = Question { question_id: "q1".into(), kind: QuestionKind::Password, text: "deploy@web's password: ".into(), echo: false, deadline_ms: Some(60_000) };
        write_control(&mut broker, &ServerMessage::Question(question)).unwrap();
        eventually("the question's mode, echo off", 10, || terminal::read_attributes(descriptor).unwrap().c_lflag & libc::ECHO == 0);
        controller.write_all(b"hunt").unwrap();
        let abandoned = Event::Error { kind: kinds::AUTH.into(), text: "Authentication for web was abandoned (the password prompt timed out).".into() };
        write_control(&mut broker, &ServerMessage::Event(abandoned)).unwrap();
        write_control(&mut broker, &ServerMessage::Exited { code: None, signal: None }).unwrap();
        eventually("the run to end", 10, || run.is_finished());
        assert_eq!(run.join().unwrap(), 255);
        assert_eq!(String::from_utf8_lossy(&left_in(&device)), "", "what was typed for the question is gone");
    }

    /// Ctrl-D at a question is the end of input, once at each question: two in a row at two questions are two cancels, not a closed
    /// terminal, and the broker decides what comes after. A closed window (the pty's controller closed) still ends the session as SIGHUP
    /// does. The program's own calls: the keys read from a pty's device, which is the terminal of the run too.
    #[test]
    fn ctrl_d_at_two_questions_cancels_both_and_a_closed_window_still_ends_the_session_with_129() {
        use crate::session::protocol::{Question, QuestionKind};
        let (mut controller, device) = pty();
        // Kept open until the end: the run's terminal is this descriptor, which the keys thread's own would close when it ends.
        let kept = device.try_clone().unwrap();
        let descriptor = kept.as_raw_fd();
        let (ours, mut broker) = UnixStream::pair().unwrap();
        let (inputs, queue) = queue();
        let stderr = Shared::default();
        let run = {
            let (inputs, stderr) = (inputs.clone(), stderr.clone());
            std::thread::spawn(move || {
                let mut tty = Tty::new(Arc::new(DeviceTermios(descriptor))).unwrap();
                run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (inputs, queue), Box::new(Shared::default()), Box::new(stderr))
            })
        };
        keys_thread(TerminalKeys { source: device, descriptor }, inputs, || {});
        for _ in ["Hello", "OpenShell"] {
            next_message(&mut broker);
        }
        for (id, prompt) in [("q1", "deploy@web's password: "), ("q2", "deploy@web's password again: ")] {
            let question = Question { question_id: id.into(), kind: QuestionKind::Password, text: prompt.into(), echo: false, deadline_ms: Some(60_000) };
            write_control(&mut broker, &ServerMessage::Question(question)).unwrap();
            eventually("the question on the terminal", 10, || stderr.text().ends_with(prompt));
            controller.write_all(b"\x04").unwrap();
            let cancel = next_message(&mut broker);
            assert!(matches!(&cancel, ClientMessage::Answer { question_id, value: None, cancel: true } if question_id == id), "{id}: {cancel:?}");
        }
        crate::process::without_spawns(|| drop(controller));
        eventually("the run to end", 10, || run.is_finished());
        assert_eq!(run.join().unwrap(), 128 + libc::SIGHUP);
        assert!(matches!(next_message(&mut broker), ClientMessage::Close));
        drop(kept);
    }

    /// A terminal that went away (its window closed) at a question: setting it, the flush of what it holds included, fails. The end does
    /// not stop at that: the program ends with its status all the same.
    #[test]
    fn an_end_at_a_question_on_a_terminal_that_went_away_still_ends_with_its_status() {
        struct WentAway(Arc<FakeTermios>, AtomicBool);
        impl TermiosApi for WentAway {
            fn get(&self) -> std::io::Result<libc::termios> {
                self.0.get()
            }
            fn set(&self, termios: &libc::termios, discard_input: bool) -> std::io::Result<()> {
                if self.1.load(Ordering::SeqCst) {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
                self.0.set(termios, discard_input)
            }
            fn size(&self) -> Option<(u16, u16)> {
                None
            }
        }
        use crate::session::protocol::{Question, QuestionKind};
        let fake = FakeTermios::new();
        let terminal = Arc::new(WentAway(Arc::clone(&fake), AtomicBool::new(false)));
        let (ours, mut broker) = UnixStream::pair().unwrap();
        let (inputs, queue) = queue();
        let run = {
            let (terminal, inputs) = (Arc::clone(&terminal), inputs.clone());
            std::thread::spawn(move || {
                let mut tty = Tty::new(terminal).unwrap();
                run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (inputs, queue), Box::new(Shared::default()), Box::new(Shared::default()))
            })
        };
        for _ in ["Hello", "OpenShell"] {
            next_message(&mut broker);
        }
        let question = Question { question_id: "q1".into(), kind: QuestionKind::Password, text: "pw: ".into(), echo: false, deadline_ms: Some(60_000) };
        write_control(&mut broker, &ServerMessage::Question(question)).unwrap();
        eventually("the question's mode", 10, || fake.now().c_lflag & libc::ECHO == 0);
        terminal.1.store(true, Ordering::SeqCst);
        inputs.send(Input::Stop(libc::SIGHUP)).unwrap();
        eventually("the run to end", 10, || run.is_finished());
        assert_eq!(run.join().unwrap(), 129);
    }

    /// The real terminal's keys: a closed window is seen as hung up (a pty whose other end was closed), and a descriptor left non-blocking
    /// is waited on until a key arrives.
    #[test]
    fn the_terminal_says_when_it_hung_up_and_is_waited_on_until_a_key_arrives() {
        let (controller, device) = pty();
        let mut raw_mode = Tty::new(Arc::new(DeviceTermios(device.as_raw_fd()))).unwrap();
        raw_mode.set_mode(Mode::Raw, false).unwrap();
        let descriptor = device.as_raw_fd();
        // SAFETY: a valid descriptor; only O_NONBLOCK is added.
        unsafe { libc::fcntl(descriptor, libc::F_SETFL, libc::fcntl(descriptor, libc::F_GETFL) | libc::O_NONBLOCK) };
        let mut keys = TerminalKeys { source: &device, descriptor };
        assert!(!keys.hung_up());
        assert_eq!(keys.read(&mut [0u8; 8]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        let typing = {
            let mut controller = controller.try_clone().unwrap();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                controller.write_all(b"k").unwrap();
            })
        };
        keys.wait_readable().unwrap();
        let mut key = [0u8; 8];
        assert_eq!(keys.read(&mut key).unwrap(), 1);
        typing.join().unwrap();
        // A process that another test is starting has a copy of every descriptor until its program runs (close-on-exec or not): the
        // window is closed once no start is under way, so that no copy of the controller outlives it.
        crate::process::without_spawns(|| drop(controller));
        eventually("the closed window to be seen", 5, || keys.hung_up());
    }

    /// A pty's device as the program's terminal, through the same calls as the terminal on standard input.
    struct DeviceTermios(RawFd);

    impl TermiosApi for DeviceTermios {
        fn get(&self) -> std::io::Result<libc::termios> {
            terminal::read_attributes(self.0)
        }
        fn set(&self, termios: &libc::termios, discard_input: bool) -> std::io::Result<()> {
            terminal::write_attributes(self.0, termios, discard_input)
        }
        fn size(&self) -> Option<(u16, u16)> {
            terminal::read_size(self.0)
        }
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
        let (code, _, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }
}
