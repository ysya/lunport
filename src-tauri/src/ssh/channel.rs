//! The plumbing between an engine's channel reader and the thread that reads a shell (own-ssh spec §6.3): a bounded byte queue that
//! never holds the connection back, the cell that carries the shell's exit, and `QueuedShell`, the `ShellChannel` built from them.
//! Engine-neutral: the russh engine and the fake engine both fill the same pieces.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use super::error::SessionError;
use super::traits::ShellChannel;
use super::types::Exit;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What one read of the queue produced.
#[derive(Debug, PartialEq, Eq)]
pub enum QueueRead {
    /// This many bytes were copied into the caller's buffer.
    Bytes(usize),
    /// Nothing arrived before the deadline; the queue is still open.
    Timeout,
    /// The queue is closed and everything in it has been read.
    Closed,
}

struct QueueState {
    chunks: VecDeque<Vec<u8>>,
    /// How much of the first chunk has been read already.
    front_read: usize,
    /// Bytes queued and not read yet.
    bytes: usize,
    closed: bool,
    dropped: u64,
    /// Dropped bytes the stream does not mention yet.
    unannounced: u64,
}

/// Chunks are merged into the last queued chunk while it stays within this many bytes. A writer that sends one byte at a time (a slow
/// program, or a server doing it on purpose) would otherwise cost a whole `Vec` per byte, about 40 times the bytes it sends.
pub const MERGE_LIMIT: usize = 16 * 1024;

/// A byte queue with a size limit. The producer (the engine's channel reader) must never wait: russh stalls the whole connection behind a
/// channel nobody reads. So when the reader is slower than the server (a paused terminal) and the queue is full, new chunks are
/// discarded and counted instead, and the connection keeps going. The stream says so with a one-line notice that tells how many bytes
/// are missing: in front of the next chunk that is kept, or as soon as the reader has caught up, whichever comes first.
///
/// While the queue is open it holds at most `capacity` bytes plus one notice (a notice is 72 bytes plus the digits of the count), and
/// `close` can add a second one. The exception is an empty queue, which accepts a chunk of any size, so a chunk larger than `capacity` is
/// taken whole and progress is always possible. Small chunks are merged (`MERGE_LIMIT`), so the memory the queue uses follows the bytes
/// it holds, not the number of pushes. The queue has one reading thread: `push` wakes a single waiting reader.
pub struct ByteQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
    capacity: usize,
}

impl ByteQueue {
    pub fn new(capacity: usize) -> Arc<ByteQueue> {
        Arc::new(ByteQueue {
            state: Mutex::new(QueueState { chunks: VecDeque::new(), front_read: 0, bytes: 0, closed: false, dropped: 0, unannounced: 0 }),
            ready: Condvar::new(),
            capacity,
        })
    }

    fn notice(bytes: u64) -> Vec<u8> {
        format!("\r\n[SSHelter dropped {bytes} bytes of output because the terminal fell behind]\r\n").into_bytes()
    }

    /// Queues `chunk` after the others: merged into the last chunk while that stays within `MERGE_LIMIT`, else as a chunk of its own.
    /// Merging only ever grows the end of a chunk, so the read position in the first chunk stays valid.
    fn append(state: &mut QueueState, chunk: Vec<u8>) {
        state.bytes += chunk.len();
        match state.chunks.back_mut() {
            Some(back) if back.len() + chunk.len() <= MERGE_LIMIT => back.extend_from_slice(&chunk),
            _ => state.chunks.push_back(chunk),
        }
    }

    /// Announces a gap the stream has not mentioned yet; the reader has caught up, so there is room for the notice now.
    fn announce_gap(state: &mut QueueState) {
        if state.unannounced > 0 {
            let notice = ByteQueue::notice(state.unannounced);
            state.unannounced = 0;
            ByteQueue::append(state, notice);
        }
    }

    /// Appends `chunk` unless the queue is closed or the chunk would grow the queued bytes past `capacity`. The bound is `capacity` plus one
    /// notice while the queue is open (the notice that goes in front of the first chunk kept after a gap is not part of the check) and up to
    /// two notices at `close`; a notice is 72 bytes plus the digits of the count. An empty queue accepts a chunk of any size, so a chunk
    /// larger than `capacity` is taken whole and progress is always possible. Returns false when the chunk was not kept; a chunk dropped for
    /// lack of room is added to `dropped_bytes`, a chunk refused because the queue is closed is not. An empty chunk queues nothing: it is
    /// accepted while the queue is open and refused once it is closed.
    pub fn push(&self, chunk: Vec<u8>) -> bool {
        let mut state = locked(&self.state);
        if state.closed {
            return false;
        }
        if chunk.is_empty() {
            return true;
        }
        if state.bytes != 0 && state.bytes + chunk.len() > self.capacity {
            state.dropped += chunk.len() as u64;
            state.unannounced += chunk.len() as u64;
            return false;
        }
        ByteQueue::announce_gap(&mut state);
        ByteQueue::append(&mut state, chunk);
        self.ready.notify_one();
        true
    }

    /// No more chunks will come. What is queued can still be read (after a notice, if bytes were dropped since the last one).
    pub fn close(&self) {
        let mut state = locked(&self.state);
        if state.closed {
            return;
        }
        ByteQueue::announce_gap(&mut state);
        state.closed = true;
        self.ready.notify_all();
    }

    /// Copies queued bytes into `buf` (at most `buf.len()`, possibly part of a chunk), waiting until `deadline` for some to arrive; with
    /// no deadline it waits for as long as the queue is open and empty. An empty `buf` reads nothing.
    pub fn read_until(&self, buf: &mut [u8], deadline: Option<Instant>) -> QueueRead {
        if buf.is_empty() {
            return QueueRead::Bytes(0);
        }
        let mut state = locked(&self.state);
        loop {
            // Bytes were dropped and the reader has read everything else: the notice goes out now, not with the next output, which may
            // never come.
            if state.chunks.is_empty() {
                ByteQueue::announce_gap(&mut state);
            }
            if let Some(front) = state.chunks.front() {
                let taken = (front.len() - state.front_read).min(buf.len());
                buf[..taken].copy_from_slice(&front[state.front_read..state.front_read + taken]);
                let finished = state.front_read + taken == front.len();
                state.bytes -= taken;
                if finished {
                    state.chunks.pop_front();
                    state.front_read = 0;
                } else {
                    state.front_read += taken;
                }
                return QueueRead::Bytes(taken);
            }
            if state.closed {
                return QueueRead::Closed;
            }
            state = match deadline {
                None => self.ready.wait(state).unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return QueueRead::Timeout;
                    }
                    self.ready.wait_timeout(state, deadline - now).unwrap_or_else(PoisonError::into_inner).0
                }
            };
        }
    }

    /// How many bytes were discarded because the reader fell behind.
    pub fn dropped_bytes(&self) -> u64 {
        locked(&self.state).dropped
    }

    /// How many chunks the queue holds (tests of the merging).
    #[cfg(test)]
    fn chunk_count(&self) -> usize {
        locked(&self.state).chunks.len()
    }
}

/// Holds how a shell ended, once. The first value set wins.
pub struct ExitCell {
    value: Mutex<Option<Exit>>,
}

impl ExitCell {
    pub fn new() -> Arc<ExitCell> {
        Arc::new(ExitCell { value: Mutex::new(None) })
    }

    pub fn set(&self, exit: Exit) {
        let mut value = locked(&self.value);
        if value.is_none() {
            *value = Some(exit);
        }
    }

    pub fn get(&self) -> Option<Exit> {
        locked(&self.value).clone()
    }
}

/// The write side of a shell, supplied by the engine.
pub trait ShellInput: Send + Sync {
    /// Sends `bytes` to the shell's stdin. May wait while the connection's flow control makes the engine wait; the engine bounds that.
    fn write(&self, bytes: &[u8]) -> Result<(), SessionError>;
    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError>;
    /// Closes the channel (the connection stays up). After this the engine's reader must finish, setting the exit first and closing the queue
    /// second, so that a `read` blocked on the queue returns 0: `QueuedShell::close` only calls this and does not close the queue itself.
    fn close(&self);
}

/// A `ShellChannel` made of an engine's `ShellInput`, the `ByteQueue` its channel reader fills and the `ExitCell` it sets. The reader
/// sets the exit first and closes the queue second, so a `read` that returns 0 always finds `exited()` filled in.
pub struct QueuedShell {
    input: Box<dyn ShellInput>,
    output: Arc<ByteQueue>,
    exit: Arc<ExitCell>,
}

impl QueuedShell {
    pub fn new(input: Box<dyn ShellInput>, output: Arc<ByteQueue>, exit: Arc<ExitCell>) -> QueuedShell {
        QueuedShell { input, output, exit }
    }

    /// `ShellChannel::read` with a deadline instead of an open end: for tests and for callers that must also watch something else.
    pub fn read_until(&self, buf: &mut [u8], deadline: Instant) -> QueueRead {
        self.output.read_until(buf, Some(deadline))
    }
}

impl ShellChannel for QueuedShell {
    fn write(&self, data: &[u8]) -> Result<(), SessionError> {
        self.input.write(data)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, SessionError> {
        debug_assert!(!buf.is_empty(), "ShellChannel::read needs a non-empty buffer: Ok(0) means the shell has ended");
        match self.output.read_until(buf, None) {
            QueueRead::Bytes(count) => Ok(count),
            // A read without a deadline never times out; the arm only keeps the match exhaustive.
            QueueRead::Closed | QueueRead::Timeout => Ok(0),
        }
    }

    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
        self.input.window_change(cols, rows)
    }

    fn exited(&self) -> Option<Exit> {
        self.exit.get()
    }

    fn close(&self) {
        self.input.close()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    fn soon() -> Option<Instant> {
        Some(Instant::now() + Duration::from_millis(50))
    }

    fn read_all(queue: &ByteQueue) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = [0u8; 64];
        while let QueueRead::Bytes(count) = queue.read_until(&mut buf, soon()) {
            all.extend_from_slice(&buf[..count]);
        }
        all
    }

    /// Runs a test body on its own thread and gives it 10 s: a body stuck in a blocking call (a push that waits, a read that is never woken)
    /// fails the test instead of hanging the suite.
    fn bounded(body: impl FnOnce() + Send + 'static) {
        let (finished, done) = std::sync::mpsc::channel();
        let runner = std::thread::spawn(move || {
            body();
            let _ = finished.send(());
        });
        match done.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => runner.join().unwrap(),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("the test body did not finish within 10 s: a call is blocked"),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => std::panic::resume_unwind(runner.join().unwrap_err()),
        }
    }

    #[test]
    fn chunks_come_out_in_the_order_they_went_in_and_a_small_buffer_gets_part_of_a_chunk() {
        bounded(|| {
            let queue = ByteQueue::new(1024);
            assert!(queue.push(b"hello world".to_vec()));
            assert!(queue.push(b"!".to_vec()));
            let mut buf = [0u8; 5];
            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(5));
            assert_eq!(&buf, b"hello");
            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(5));
            assert_eq!(&buf, b" worl");
            // The two pushes were merged into one chunk (see `MERGE_LIMIT`), so the last read gets the end of both.
            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(2));
            assert_eq!(&buf[..2], b"d!");
            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Timeout);
            assert_eq!(queue.read_until(&mut [], soon()), QueueRead::Bytes(0), "an empty buffer reads nothing and does not wait");
        });
    }

    /// A writer that sends one byte at a time (a slow program, or a server doing it on purpose) must not cost a `Vec` per byte: small
    /// chunks are merged into the last one while it stays within `MERGE_LIMIT`, so the number of chunks follows the bytes, not the pushes.
    #[test]
    fn small_chunks_are_merged_so_their_count_follows_the_bytes_and_not_the_pushes() {
        let queue = ByteQueue::new(64 * 1024);
        for index in 0..20_000u32 {
            assert!(queue.push(vec![(index % 251) as u8]));
        }
        assert_eq!(queue.chunk_count(), 2, "16 KiB in the first chunk, the rest in a second");
        let all = read_all(&queue);
        assert_eq!(all.len(), 20_000);
        assert!(all.iter().enumerate().all(|(index, byte)| *byte == (index as u32 % 251) as u8), "the bytes come out in the order they went in");
    }

    #[test]
    fn a_chunk_is_not_merged_into_one_it_would_grow_past_the_merge_limit_and_a_big_chunk_stays_whole() {
        let queue = ByteQueue::new(1024 * 1024);
        assert!(queue.push(vec![1; MERGE_LIMIT]));
        assert!(queue.push(vec![2; 1]));
        assert_eq!(queue.chunk_count(), 2, "the full chunk takes nothing more");
        assert!(queue.push(vec![3; MERGE_LIMIT + 4000]));
        assert_eq!(queue.chunk_count(), 3, "a chunk bigger than the limit is queued as it is, not split");
        let all = read_all(&queue);
        assert_eq!(all.len(), 2 * MERGE_LIMIT + 4001);
        assert_eq!((all[MERGE_LIMIT - 1], all[MERGE_LIMIT], all[MERGE_LIMIT + 1]), (1, 2, 3));
    }

    /// A gap is announced as soon as the reader has caught up, not only when more output arrives: a program that went quiet after the
    /// terminal fell behind must not leave the user looking at output with a hole in it and no word about it.
    #[test]
    fn a_reader_that_catches_up_after_a_gap_is_told_about_it_at_once() {
        bounded(|| {
            let queue = ByteQueue::new(8);
            assert!(queue.push(b"AAAAAA".to_vec()));
            assert!(!queue.push(b"BBBBBB".to_vec()), "the terminal fell behind");
            let mut buf = [0u8; 128];
            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(6), "the reader catches up");
            match queue.read_until(&mut buf, soon()) {
                QueueRead::Bytes(count) => assert_eq!(
                    std::str::from_utf8(&buf[..count]).unwrap(),
                    "\r\n[SSHelter dropped 6 bytes of output because the terminal fell behind]\r\n"
                ),
                other => panic!("the gap must be announced without waiting for more output, got {other:?}"),
            }
            assert!(queue.push(b"C".to_vec()));
            assert_eq!(read_all(&queue), b"C", "the gap is announced once");
        });
    }

    #[test]
    fn a_full_queue_drops_new_chunks_and_counts_them_instead_of_waiting() {
        bounded(|| {
            let queue = ByteQueue::new(10);
            assert!(queue.push(vec![1; 6]));
            let started = Instant::now();
            assert!(!queue.push(vec![2; 6]), "6 + 6 bytes do not fit in 10");
            assert!(started.elapsed() < Duration::from_millis(500), "a full queue must not make the producer wait");
            assert_eq!(queue.dropped_bytes(), 6);
            assert!(queue.push(vec![3; 4]), "4 bytes still fit next to the 6 queued");
            assert_eq!(queue.dropped_bytes(), 6, "only the chunk that did not fit was counted");
        });
    }

    #[test]
    fn an_empty_queue_takes_a_chunk_bigger_than_its_capacity() {
        bounded(|| {
            let queue = ByteQueue::new(4);
            assert!(queue.push(vec![9; 100]));
            assert_eq!(queue.dropped_bytes(), 0);
            assert!(!queue.push(vec![9; 1]), "but nothing fits next to it");
            assert_eq!(queue.dropped_bytes(), 1);
        });
    }

    #[test]
    fn the_stream_says_how_much_is_missing_before_the_next_chunk_it_keeps() {
        bounded(|| {
            let queue = ByteQueue::new(8);
            assert!(queue.push(b"AAAAAA".to_vec()));
            assert!(!queue.push(b"BBBBBB".to_vec()));
            assert!(!queue.push(b"CCCC".to_vec()));
            assert_eq!(queue.dropped_bytes(), 10);
            let mut buf = [0u8; 64];
            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Bytes(6), "the reader catches up");
            assert!(queue.push(b"DD".to_vec()));
            let rest = String::from_utf8(read_all(&queue)).unwrap();
            assert_eq!(rest, "\r\n[SSHelter dropped 10 bytes of output because the terminal fell behind]\r\nDD");
            assert!(queue.push(b"EE".to_vec()));
            assert_eq!(read_all(&queue), b"EE", "the gap is announced once");
        });
    }

    #[test]
    fn closing_announces_a_gap_that_nothing_followed_and_then_reports_closed() {
        bounded(|| {
            let queue = ByteQueue::new(4);
            queue.push(b"1234".to_vec());
            assert!(!queue.push(b"5678".to_vec()));
            queue.close();
            assert!(!queue.push(b"too late".to_vec()), "nothing is accepted after close");
            assert!(!queue.push(Vec::new()), "not even an empty chunk");
            assert_eq!(queue.dropped_bytes(), 4, "a push after close is not a drop for lack of room");
            let mut buf = [0u8; 128];
            let mut all = Vec::new();
            loop {
                match queue.read_until(&mut buf, soon()) {
                    QueueRead::Bytes(count) => all.extend_from_slice(&buf[..count]),
                    QueueRead::Closed => break,
                    QueueRead::Timeout => panic!("a closed queue must not time out"),
                }
            }
            assert_eq!(String::from_utf8(all).unwrap(), "1234\r\n[SSHelter dropped 4 bytes of output because the terminal fell behind]\r\n");
            assert_eq!(queue.read_until(&mut buf, soon()), QueueRead::Closed);
        });
    }

    #[test]
    fn a_waiting_reader_wakes_when_a_chunk_arrives_and_when_the_queue_closes() {
        let queue = ByteQueue::new(1024);
        let (results, seen) = std::sync::mpsc::channel();
        let reader = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || {
                // No deadline: the open-ended wait is what is under test, so it runs on its own thread and the test waits for it with a timeout.
                let mut buf = [0u8; 16];
                let _ = results.send(queue.read_until(&mut buf, None));
                let _ = results.send(queue.read_until(&mut buf, None));
            })
        };
        let wait = Duration::from_secs(5);
        std::thread::sleep(Duration::from_millis(100)); // let the reader reach its wait
        queue.push(b"hello".to_vec());
        assert_eq!(seen.recv_timeout(wait), Ok(QueueRead::Bytes(5)), "a chunk wakes a waiting reader (the queue is still open)");
        std::thread::sleep(Duration::from_millis(100)); // the reader is back in its wait: only close()'s notify can wake it now
        queue.close();
        assert_eq!(seen.recv_timeout(wait), Ok(QueueRead::Closed), "closing wakes a waiting reader");
        reader.join().unwrap();
    }

    #[test]
    fn the_first_exit_wins() {
        let cell = ExitCell::new();
        assert_eq!(cell.get(), None);
        cell.set(Exit::Code(3));
        cell.set(Exit::Signal("KILL".into()));
        assert_eq!(cell.get(), Some(Exit::Code(3)));
    }

    struct CountingInput {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        resizes: Arc<Mutex<Vec<(u16, u16)>>>,
        closes: Arc<AtomicUsize>,
    }

    impl ShellInput for CountingInput {
        fn write(&self, bytes: &[u8]) -> Result<(), SessionError> {
            locked(&self.writes).push(bytes.to_vec());
            Ok(())
        }
        fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
            locked(&self.resizes).push((cols, rows));
            Ok(())
        }
        fn close(&self) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_shell_forwards_to_its_input_reads_from_its_queue_and_finds_the_exit_when_the_read_ends() {
        bounded(|| {
            let (writes, resizes, closes) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicUsize::new(0)));
            let input = CountingInput { writes: Arc::clone(&writes), resizes: Arc::clone(&resizes), closes: Arc::clone(&closes) };
            let (queue, cell) = (ByteQueue::new(1024), ExitCell::new());
            let shell = QueuedShell::new(Box::new(input), Arc::clone(&queue), Arc::clone(&cell));

            shell.write(b"ls\n").unwrap();
            shell.window_change(120, 40).unwrap();
            shell.close();
            assert_eq!(*locked(&writes), vec![b"ls\n".to_vec()]);
            assert_eq!(*locked(&resizes), vec![(120, 40)]);
            assert_eq!(closes.load(Ordering::SeqCst), 1);

            queue.push(b"prompt$ ".to_vec());
            let mut buf = [0u8; 32];
            assert_eq!(shell.read(&mut buf), Ok(8));
            assert_eq!(&buf[..8], b"prompt$ ");
            assert_eq!(shell.read_until(&mut buf, Instant::now() + Duration::from_millis(30)), QueueRead::Timeout);
            assert_eq!(shell.exited(), None);

            cell.set(Exit::Code(0));
            queue.close();
            assert_eq!(shell.read(&mut buf), Ok(0), "0 means the shell has ended");
            assert_eq!(shell.exited(), Some(Exit::Code(0)), "and the exit is there by then");
        });
    }
}
