//! A real console (plan 1b-3 Task 3): what the Windows keys reader is built on, measured and kept as a regression test, and the reader,
//! the console's restore on a panic, and the console's own reads and wakes (`StdConsole`) on a real console. Each case runs again in a
//! child process with a console of its own (`CREATE_NEW_CONSOLE`: the console of the process that runs the tests is never touched), where
//! the test types into that console's input buffer itself (`WriteConsoleInputW`, where a terminal's keys arrive too) and reads its screen
//! buffer to see what was shown.
//!
//! What was measured on the CI runner (GitHub's Windows image, conhost, 2026-10-13; the cases below keep it so):
//! - A `ReadConsoleW` in progress holds up none of the console's other calls, on its own handle, a duplicate of it, or another handle:
//!   `GetConsoleMode`, `SetConsoleMode`, `FlushConsoleInputBuffer`, `GetNumberOfConsoleInputEvents`, a wait on the handle,
//!   `WriteConsoleInputW` and the screen buffer's calls all return at once, under a raw read and under a line read. So the restores (the
//!   end of a run, the panic hook, the watchdog) never wait for a key, and the console layer needs no handles of its own.
//! - A read in progress keeps what it started as across a change of mode: a raw read takes the next key at once, unshown, also after the
//!   mode changed to a question's; a line read keeps the line typed into it, which `FlushConsoleInputBuffer` does not reach ("hunt" typed
//!   before the question, then "er2" and Enter at it: the read gives "hunter2"). What is typed after the change is shown as the new mode
//!   says. So no read may span a change of mode (`console.rs`).
//! - A cancelled read (`CancelIoEx`, `CancelSynchronousIo`) returns at once (TRUE, no characters, ERROR_OPERATION_ABORTED), but lives on in
//!   the console: the next key (raw) or line (a line read) goes to it, not to the read after it. An Enter written into the input buffer
//!   ends a read in progress, line or raw, and the next read takes the next key: that is how a change of mode ends a read.
//! - Ctrl-C written as a record is a character (a key pressed on the keyboard is what the console turns into the event);
//!   `GenerateConsoleCtrlEvent` reaches the handler, and does not end a line read in progress.
//! - A line read without echo is not kept in the console's history (the up arrow does not bring it back); one with echo is. The Enter of a
//!   line read without echo still moves the cursor to the next line.
//! - The input handle is signalled while the buffer holds any record (a focus event too, which a raw read then waits past).
//! - Raw mode with virtual terminal input gives an arrow as `ESC [ A`; a surrogate pair typed as two records comes in one read.
//! - Once the console is freed, a read in progress fails (ERROR_ACCESS_DENIED), and so does every read after it (ERROR_INVALID_HANDLE).
//! - (Fix round 1, measured in a console shared with another process, as the shell shares its console with `sshelter connect`.) A read a
//!   process leaves in progress when it ends ends with it: neither a raw read nor a hidden line read with "hun" typed into it takes the
//!   key or the line typed next, and "hun" never shows; so `sshelter connect`'s own end, which leaves its keys thread in a read, leaves
//!   the next key to the shell.
//! - (Final wave, measured the same way.) So does a read on the console input the process was given as its standard input
//!   (`StdConsole::new`'s standard handle: `sshelter connect` reads the input its shell and `sshelter-cli.exe` hand it), an input that
//!   stays open when the process ends (the process that started it keeps a handle of the same input, and reads it next): a raw read and a
//!   hidden line read with "hun" typed into it, left by a process that returns or that the watchdog ends from another thread, take
//!   nothing of what is typed next. A cancelled read on that same input does live on and take the next key, so the check sees one that
//!   lives on.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, TRUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleCP, GetConsoleMode, GetConsoleOutputCP,
    GetConsoleScreenBufferInfo, GetNumberOfConsoleInputEvents, GetStdHandle, ReadConsoleOutputCharacterW, ReadConsoleW, SetConsoleCP,
    SetConsoleCtrlHandler, SetConsoleMode, SetConsoleOutputCP, WriteConsoleInputW, WriteConsoleW, CONSOLE_SCREEN_BUFFER_INFO, COORD,
    CTRL_BREAK_EVENT, CTRL_C_EVENT, INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess, WaitForSingleObject};
use windows_sys::Win32::System::IO::CancelIoEx;

use super::client::Input;
use super::console::{input_mode, ConsoleApi, Mode, Setting};
use super::inputs_windows::{take_over_control_events, ConsoleText};
use super::run::{console_keys_thread, queue, ControlEvents, Output, Over, Watchdog};
use super::terminal::{restore_on_panic, StdConsole, Tty};
use crate::ssh::testing::{is_child, rerun_alone_reading, rerun_alone_with};

/// The virtual-key codes the tests type (winuser.h): Enter, and the up arrow.
const VK_RETURN: u16 = 0x0D;
const VK_UP: u16 = 0x26;

/// Time for a read on another thread to be under way.
const SETTLE: Duration = Duration::from_millis(300);
/// How long a call may take that does not wait (it returns at once; this is a guard against a loaded runner).
const AT_ONCE: Duration = Duration::from_millis(1000);
/// How long a read is given that has what it waits for.
const DONE: Duration = Duration::from_secs(5);

/// A console handle that can cross threads (a raw `HANDLE` is a pointer). A child never closes them: a handle with a read stuck on it is
/// not closed under that read, and the process ends with the case.
#[derive(Clone, Copy)]
struct H(usize);

impl H {
    fn raw(self) -> HANDLE {
        self.0 as HANDLE
    }
}

/// Opens `CONIN$` or `CONOUT$` of this process's console: a file object of its own each time.
fn open(name: &str) -> H {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: a NUL-terminated name that outlives the call; no security attributes, no template.
    let handle = unsafe {
        CreateFileW(wide.as_ptr(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, ptr::null(), OPEN_EXISTING, 0, ptr::null_mut())
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE, "{name}: {}", std::io::Error::last_os_error());
    H(handle as usize)
}

/// `open`, as a handle that is closed when it is dropped.
fn owned(name: &str) -> OwnedHandle {
    // SAFETY: a handle `open` has just opened, which nothing else owns.
    unsafe { OwnedHandle::from_raw_handle(open(name).raw() as _) }
}

fn last_error() -> u32 {
    // SAFETY: reads this thread's last error.
    unsafe { GetLastError() }
}

fn mode_of(handle: H) -> Result<u32, u32> {
    let mut mode = 0;
    // SAFETY: a u32 GetConsoleMode writes.
    if unsafe { GetConsoleMode(handle.raw(), &mut mode) } == 0 {
        return Err(last_error());
    }
    Ok(mode)
}

fn set_mode(handle: H, mode: u32) -> Result<(), u32> {
    // SAFETY: a plain value for a console handle.
    if unsafe { SetConsoleMode(handle.raw(), mode) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

fn flush(handle: H) -> Result<(), u32> {
    // SAFETY: discards what the input buffer holds.
    if unsafe { FlushConsoleInputBuffer(handle.raw()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

fn events(handle: H) -> Result<u32, u32> {
    let mut count = 0;
    // SAFETY: a u32 the call writes.
    if unsafe { GetNumberOfConsoleInputEvents(handle.raw(), &mut count) } == 0 {
        return Err(last_error());
    }
    Ok(count)
}

/// A key's press and release.
fn key(vk: u16, ch: u16) -> [INPUT_RECORD; 2] {
    let event = |down: bool| {
        let mut record = INPUT_RECORD { EventType: KEY_EVENT as u16, ..Default::default() };
        record.Event.KeyEvent = KEY_EVENT_RECORD {
            bKeyDown: BOOL::from(down),
            wRepeatCount: 1,
            wVirtualKeyCode: vk,
            wVirtualScanCode: 0,
            uChar: KEY_EVENT_RECORD_0 { UnicodeChar: ch },
            dwControlKeyState: 0,
        };
        record
    };
    [event(true), event(false)]
}

/// Types `text` into the console through `handle`, as if its keys were pressed (lower-case letters, digits, `\r` as Enter).
fn type_text(handle: H, text: &str) {
    let records: Vec<INPUT_RECORD> = text
        .encode_utf16()
        .flat_map(|c| match c {
            0x0d => key(VK_RETURN, 0x0d),
            c if (u16::from(b'a')..=u16::from(b'z')).contains(&c) => key(c - 32, c),
            c => key(c, c),
        })
        .collect();
    type_records(handle, &records);
}

fn type_records(handle: H, records: &[INPUT_RECORD]) {
    if records.is_empty() {
        return;
    }
    let mut written = 0;
    // SAFETY: `records` is valid for its length.
    let done = unsafe { WriteConsoleInputW(handle.raw(), records.as_ptr(), records.len() as u32, &mut written) };
    assert_ne!(done, 0, "WriteConsoleInputW: {}", std::io::Error::last_os_error());
}

/// What one `ReadConsoleW` returned: whether it succeeded, the text it read, and the thread's last error after it.
#[derive(Debug, PartialEq, Eq)]
struct Read {
    ok: bool,
    text: String,
    error: u32,
}

/// A `ReadConsoleW` of up to 64 characters on `handle`, on a thread of its own; its result arrives on the receiver.
fn read_on_a_thread(handle: H) -> (mpsc::Receiver<Read>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut buf = [0u16; 64];
        let mut chars = 0u32;
        // SAFETY: clears this thread's last error, so that what the read leaves there is its own.
        unsafe { SetLastError(0) };
        // SAFETY: `buf` holds 64 characters; no read control.
        let ok = unsafe { ReadConsoleW(handle.raw(), buf.as_mut_ptr().cast(), 64, &mut chars, ptr::null()) } != 0;
        let error = last_error();
        let _ = tx.send(Read { ok, text: String::from_utf16_lossy(&buf[..(chars as usize).min(64)]), error });
    });
    (rx, thread)
}

/// Whether `call`, on a thread of its own, returns within `AT_ONCE`.
fn returns_at_once<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> bool {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(call());
    });
    rx.recv_timeout(AT_ONCE).is_ok()
}

fn cursor(out: H) -> (i16, i16) {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: plain data the call fills in.
    unsafe { GetConsoleScreenBufferInfo(out.raw(), &mut info) };
    (info.dwCursorPosition.X, info.dwCursorPosition.Y)
}

/// The text of row `y` of the screen buffer, without the blanks at its end.
fn row(out: H, y: i16) -> String {
    let mut buf = [0u16; 100];
    let mut read = 0u32;
    // SAFETY: `buf` holds 100 characters.
    unsafe { ReadConsoleOutputCharacterW(out.raw(), buf.as_mut_ptr(), buf.len() as u32, COORD { X: 0, Y: y }, &mut read) };
    String::from_utf16_lossy(&buf[..read as usize]).trim_end().to_string()
}

/// Starts a line of its own on the screen, labelled, so that what each step shows is on a row of its own.
fn new_line(out: H, label: &str) {
    let text: Vec<u16> = format!("\r\n[{label}] ").encode_utf16().collect();
    let mut written = 0;
    // SAFETY: `text` is valid for its length.
    unsafe { WriteConsoleW(out.raw(), text.as_ptr(), text.len() as u32, &mut written, ptr::null()) };
}

/// The console of a child: its input buffer through a handle that never reads (`control`), its screen buffer, and the input modes the
/// console layer sets, from the input mode the console started with.
struct Console {
    control: H,
    out: H,
    raw: u32,
    hidden: u32,
    shown: u32,
}

impl Console {
    fn new() -> Console {
        let control = open("CONIN$");
        let start = mode_of(control).expect("the child's console");
        Console {
            control,
            out: open("CONOUT$"),
            raw: input_mode(start, Mode::Raw),
            hidden: input_mode(start, Mode::Prompt { echo: false }),
            shown: input_mode(start, Mode::Prompt { echo: true }),
        }
    }

    /// A read in `mode`, under way on a handle of its own, the input buffer empty when it started.
    fn reading(&self, mode: u32, label: &str) -> (H, mpsc::Receiver<Read>, std::thread::JoinHandle<()>) {
        set_mode(self.control, mode).unwrap();
        flush(self.control).unwrap();
        new_line(self.out, label);
        let h = open("CONIN$");
        let (read, thread) = read_on_a_thread(h);
        std::thread::sleep(SETTLE);
        assert!(read.try_recv().is_err(), "{label}: the read waits");
        (h, read, thread)
    }
}

/// What a read gave, within `DONE`.
fn gave(read: &mpsc::Receiver<Read>) -> String {
    let read = read.recv_timeout(DONE).expect("the read returned");
    assert!(read.ok, "the read failed: {read:?}");
    read.text
}

/// The console control events the handler saw.
static EVENTS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

unsafe extern "system" fn record_event(event: u32) -> BOOL {
    EVENTS.lock().unwrap_or_else(PoisonError::into_inner).push(event);
    TRUE
}

/// The four settings of the console a `Tty` puts back: the input's mode, the output's, and the two code pages.
fn settings() -> (u32, u32, u32, u32) {
    // SAFETY: GetConsoleCP and GetConsoleOutputCP take nothing and read this process's console.
    let (input_cp, output_cp) = unsafe { (GetConsoleCP(), GetConsoleOutputCP()) };
    (mode_of(open("CONIN$")).unwrap(), mode_of(open("CONOUT$")).unwrap(), input_cp, output_cp)
}

/// A read through `console` (`StdConsole::read`) on a thread of its own: what it gave, as text, arrives on the receiver.
fn read_through(console: &Arc<StdConsole>) -> mpsc::Receiver<std::io::Result<String>> {
    let (tx, rx) = mpsc::channel();
    let reader = Arc::clone(console);
    std::thread::spawn(move || {
        let mut buf = [0u16; 64];
        let _ = tx.send(reader.read(&mut buf).map(|count| String::from_utf16_lossy(&buf[..count])));
    });
    rx
}

/// The console of this process as `sshelter connect` takes it (`StdConsole::new`), saying when the keys thread starts a read.
struct Watched {
    console: StdConsole,
    reading: AtomicBool,
}

impl ConsoleApi for Watched {
    fn get(&self, setting: Setting) -> io::Result<u32> {
        self.console.get(setting)
    }

    fn set(&self, setting: Setting, value: u32) -> io::Result<()> {
        self.console.set(setting, value)
    }

    fn flush_input(&self) -> io::Result<()> {
        self.console.flush_input()
    }

    fn size(&self) -> Option<(u16, u16)> {
        self.console.size()
    }

    fn read(&self, buf: &mut [u16]) -> io::Result<usize> {
        self.reading.store(true, Ordering::SeqCst);
        self.console.read(buf)
    }

    fn wake(&self) -> io::Result<()> {
        self.console.wake()
    }
}

/// A program the case `a_read_left_on_the_given_input_takes_nothing` runs, ending as `sshelter connect` ends with its keys thread in a
/// read: the console of the standard input this process was given (`StdConsole::new`, a handle of an input the process that started it
/// keeps), taken over and set to `mode` through the real gate, its keys thread reading, `typed` typed into that read (through `control`,
/// a handle that never reads); then the process ends with the read in progress, by returning once the console was put back and the
/// `Tty` dropped (the end of `session`), or by the watchdog's exit from a thread of its own (`by_the_watchdog`: the console put back for
/// good, then `process::exit`, while this thread waits).
fn end_with_a_read(control: H, mode: Mode, typed: &str, by_the_watchdog: bool) {
    // SAFETY: GetStdHandle only reads this process's standard input handle.
    let given = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let watched = Arc::new(Watched { console: StdConsole::new(), reading: AtomicBool::new(false) });
    assert_eq!(watched.console.input(), given, "the keys are read from the standard input this process was given");
    let mut tty = Tty::new(watched.clone()).expect("the given input is the console's");
    tty.take_over().unwrap();
    tty.set_mode(mode, true).unwrap();
    let (inputs, _queue) = queue();
    console_keys_thread(inputs, tty.keys(), || {});
    crate::ssh::testing::eventually("the keys thread to read", 10, || watched.reading.load(Ordering::SeqCst));
    // The read itself under way (the flag is set just before it), then what is typed into it.
    std::thread::sleep(SETTLE);
    type_text(control, typed);
    std::thread::sleep(SETTLE);
    if by_the_watchdog {
        let watchdog = Watchdog::start(tty.restorer(), Duration::ZERO, |_| std::process::exit(0)).unwrap();
        watchdog.arm(129);
        std::thread::sleep(DONE * 4);
        panic!("the watchdog did not end the process");
    }
    tty.restore();
    drop(tty);
}

/// One case, in a child with a console of its own.
fn case(name: &str) {
    let console = Console::new();
    let control = console.control;
    match name {
        // A read in progress holds up none of the console's calls on its handle (the restores never wait for a key).
        "calls_do_not_wait_for_a_read" => {
            for (label, mode) in [("raw", console.raw), ("line", console.shown)] {
                let (h, read, _thread) = console.reading(mode, label);
                assert!(returns_at_once(move || mode_of(h)), "{label}: GetConsoleMode");
                assert!(returns_at_once(move || set_mode(h, mode)), "{label}: SetConsoleMode");
                assert!(returns_at_once(move || flush(h)), "{label}: FlushConsoleInputBuffer");
                assert!(returns_at_once(move || events(h)), "{label}: GetNumberOfConsoleInputEvents");
                type_text(control, "k\r");
                gave(&read);
            }
        }
        // A raw read in progress when the mode becomes a question's: it takes the next key at once, unshown.
        "a_raw_read_spans_a_change_of_mode" => {
            let (_h, read, _thread) = console.reading(console.raw, "raw spans");
            set_mode(control, console.hidden).unwrap();
            flush(control).unwrap();
            let before = cursor(console.out);
            type_text(control, "x");
            assert_eq!(gave(&read), "x", "still a raw read");
            assert_eq!(cursor(console.out), before, "and unshown");
        }
        // A line read with echo in progress, "hunt" typed into it; then a question's mode without echo, the input flushed, "er2" and Enter:
        // the flush did not reach "hunt".
        "a_line_read_spans_a_change_of_mode" => {
            let (_h, read, _thread) = console.reading(console.shown, "line spans");
            type_text(control, "hunt");
            std::thread::sleep(SETTLE);
            set_mode(control, console.hidden).unwrap();
            flush(control).unwrap();
            type_text(control, "er2\r");
            assert_eq!(gave(&read), "hunter2\r\n", "the line typed ahead is a part of the answer");
        }
        // A cancelled read returns, but takes the next key, which the read after it does not get; the key after that it does.
        "a_cancelled_read_takes_the_next_key" => {
            let (h, read, _thread) = console.reading(console.raw, "cancelled");
            // SAFETY: cancels this process's I/O on a valid handle.
            assert_ne!(unsafe { CancelIoEx(h.raw(), ptr::null()) }, 0);
            let cancelled = read.recv_timeout(DONE).expect("the cancelled read returned");
            assert_eq!((cancelled.ok, cancelled.text.as_str()), (true, ""), "{cancelled:?}");
            let (_h, next, _thread) = console.reading(console.raw, "after it");
            type_text(control, "a");
            assert!(next.recv_timeout(AT_ONCE).is_err(), "the cancelled read took the key");
            type_text(control, "b");
            assert_eq!(gave(&next), "b");
        }
        // The console's own wake (`StdConsole::wake`, an Enter in the input buffer) ends a line read with what was typed into it, and a raw
        // read; the read after either takes the next key. Its reads (`StdConsole::read`) are the console's.
        "a_woken_read_ends_and_the_next_read_takes_the_next_key" => {
            let std_console = Arc::new(StdConsole::opened().unwrap());
            for (label, mode, typed, woken, next_typed) in
                [("line", console.shown, "hunt", "hunt\r\n", ("a\r", "a\r\n")), ("raw", console.raw, "", "\r", ("a", "a"))]
            {
                set_mode(control, mode).unwrap();
                flush(control).unwrap();
                new_line(console.out, label);
                let read = read_through(&std_console);
                std::thread::sleep(SETTLE);
                type_text(control, typed);
                std::thread::sleep(SETTLE);
                std_console.wake().unwrap();
                assert_eq!(read.recv_timeout(DONE).expect("woken").unwrap(), woken, "{label}");
                let next = read_through(&std_console);
                std::thread::sleep(SETTLE);
                type_text(control, next_typed.0);
                assert_eq!(next.recv_timeout(DONE).expect("the next read").unwrap(), next_typed.1, "{label}: nothing of the wake is left");
            }
        }
        // A read through the console (`StdConsole::read`) that ends without a character, as Ctrl-C ends a line read and as a cancel ends any
        // read, gives nothing: it is not the console gone.
        "an_aborted_read_through_the_console_gives_nothing" => {
            let std_console = Arc::new(StdConsole::opened().unwrap());
            for (label, mode) in [("line", console.hidden), ("raw", console.raw)] {
                set_mode(control, mode).unwrap();
                flush(control).unwrap();
                let read = read_through(&std_console);
                std::thread::sleep(SETTLE);
                // SAFETY: cancels this process's I/O on the console's input handle, which `std_console` keeps open.
                assert_ne!(unsafe { CancelIoEx(std_console.input(), ptr::null()) }, 0, "{label}");
                assert_eq!(read.recv_timeout(DONE).expect("the read returned").unwrap(), "", "{label}");
            }
        }
        // `GenerateConsoleCtrlEvent` reaches the handler and does not end a line read: a change of mode after it must end the read.
        "a_generated_ctrl_c_does_not_end_a_line_read" => {
            // SAFETY: a handler of the right signature, for the rest of this process.
            assert_ne!(unsafe { SetConsoleCtrlHandler(Some(record_event), TRUE) }, 0);
            let (_h, read, _thread) = console.reading(console.hidden, "ctrl-c");
            // SAFETY: CTRL_C_EVENT to every process on this console: this one only, which has a handler.
            assert_ne!(unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) }, 0);
            crate::ssh::testing::eventually("the handler to see the event", 10, || {
                EVENTS.lock().unwrap_or_else(PoisonError::into_inner).contains(&CTRL_C_EVENT)
            });
            assert!(read.recv_timeout(AT_ONCE).is_err(), "the line read goes on");
            type_text(control, "\r");
            assert_eq!(gave(&read), "\r\n");
        }
        // A line read without echo is not offered again by the up arrow; one with echo is.
        "a_hidden_line_is_not_in_the_history" => {
            for (label, mode, line, recalled) in [("hidden", console.hidden, "secret1\r", "\r\n"), ("shown", console.shown, "visible1\r", "visible1\r\n")] {
                let (_h, read, _thread) = console.reading(mode, label);
                type_text(control, line);
                gave(&read);
                let (_h, recall, _thread) = console.reading(console.shown, "recall");
                let mut records = key(VK_UP, 0).to_vec();
                records.extend(key(VK_RETURN, 0x0d));
                type_records(control, &records);
                assert_eq!(gave(&recall), recalled, "{label}");
            }
        }
        // The keys reader on a real console: raw keys reach the queue; a change to a question's mode ends the raw read in progress, whose
        // Enter is not typed text; the answer is read as a line, unshown; raw keys again after it. And the console back at its start.
        "the_keys_reader_on_a_real_console" => {
            let start = settings();
            let mut tty = Tty::new(Arc::new(StdConsole::opened().unwrap())).unwrap();
            tty.set_mode(Mode::Raw, false).unwrap();
            let (inputs, mut queue) = queue();
            console_keys_thread(inputs, tty.keys(), || {});
            let typed = |queue: &mut super::run::Queue| match queue.next_within(DONE) {
                Some(Input::Stdin(bytes)) => String::from_utf8(bytes.to_vec()).unwrap(),
                other => panic!("not typed text: {other:?}"),
            };
            type_text(control, "ls\r");
            assert_eq!(typed(&mut queue), "ls\r");
            std::thread::sleep(SETTLE);
            new_line(console.out, "password");
            let (x, y) = cursor(console.out);
            tty.set_mode(Mode::Prompt { echo: false }, true).unwrap();
            type_text(control, "pw\r");
            assert_eq!(typed(&mut queue), "pw\r\n", "the answer, and nothing of the raw read the change ended");
            assert_eq!(row(console.out, y), "[password]", "the answer was not shown ({x},{y})");
            // The client leaves the line break after a hidden answer to the console (`QUESTION_READ_ENDS_ITS_LINE`): its Enter ended the line.
            assert_eq!(cursor(console.out), (0, y + 1), "the hidden answer's Enter ended its line");
            tty.set_mode(Mode::Raw, false).unwrap();
            type_text(control, "q");
            assert_eq!(typed(&mut queue), "q");
            drop(tty);
            assert_eq!(settings(), start, "the console is back at its start");
        }
        // Spec §7.3: a panic puts the console back (the hook `restore_on_panic` installs), all four settings, after the console was taken
        // over and set raw; the panic is then reported as usual (the parent looks for its message).
        "a_panic_puts_the_real_console_back" => {
            let start = settings();
            let mut tty = Tty::new(Arc::new(StdConsole::opened().unwrap())).unwrap();
            restore_on_panic(tty.restorer());
            tty.take_over().unwrap();
            tty.set_mode(Mode::Raw, false).unwrap();
            assert_ne!(settings(), start, "the console was changed");
            assert!(std::thread::spawn(|| panic!("a thread of the program failed")).join().is_err());
            assert_eq!(settings(), start, "the panic put the console back");
            // Not dropped: its restore would hide a hook that did not.
            std::mem::forget(tty);
        }
        // A read in progress when the console is freed fails, and so does a read after it.
        "a_freed_console_fails_its_reads" => {
            let (h, read, _thread) = console.reading(console.raw, "freed");
            // SAFETY: detaches this process from its console; only `h` is used after it, to see how a read fails.
            assert_ne!(unsafe { FreeConsole() }, 0);
            assert!(!read.recv_timeout(DONE).expect("the read returned").ok);
            let (again, _thread) = read_on_a_thread(h);
            assert!(!again.recv_timeout(DONE).expect("the read returned").ok);
        }
        // The input handle is signalled while the buffer holds a record, and not once it is empty.
        "the_input_is_signalled_while_it_holds_a_record" => {
            set_mode(control, console.raw).unwrap();
            flush(control).unwrap();
            // SAFETY: waits of zero only look at the handle's state.
            let signalled = || unsafe { WaitForSingleObject(control.raw(), 0) } == 0;
            assert!(!signalled(), "empty");
            type_text(control, "z");
            assert!(signalled(), "a key");
            flush(control).unwrap();
            assert!(!signalled(), "flushed");
        }
        // Fix round 1: a session that ends under a hidden question (`Mode::Cooked`, throwing what was typed away) leaves nothing behind:
        // what was typed into the question's read is not shown and not given to the loop, and no read is left in progress (one would
        // take what is typed next, and show it once the console echoes again).
        "an_end_under_a_question_leaves_nothing_behind" => {
            let mut tty = Tty::new(Arc::new(StdConsole::opened().unwrap())).unwrap();
            tty.set_mode(Mode::Prompt { echo: false }, true).unwrap();
            let (inputs, mut queue) = queue();
            console_keys_thread(inputs, tty.keys(), || {});
            new_line(console.out, "question");
            let (_, y) = cursor(console.out);
            std::thread::sleep(SETTLE);
            type_text(control, "hun");
            std::thread::sleep(SETTLE);
            tty.set_mode(Mode::Cooked, true).unwrap();
            // The client prints the reason of such an end without a line break of its own when the console ended the question's line
            // (`QUESTION_READ_ENDS_ITS_LINE`): the Enter that ended the read did, and the console layer says so.
            assert_eq!(cursor(console.out), (0, y + 1), "the Enter that ended the question's read ended its line");
            assert!(tty.question_line_ended(), "the console layer says that the question's line was ended");
            type_text(control, "x");
            std::thread::sleep(SETTLE);
            assert!(queue.next_within(AT_ONCE).is_none(), "nothing typed at the question reached the loop");
            assert_eq!(row(console.out, y), "[question]", "nothing typed was shown");
            // A read of the test's own takes what was typed after the end: no read of the question is left to take it.
            set_mode(control, console.raw).unwrap();
            let (read, _thread) = read_on_a_thread(open("CONIN$"));
            assert_eq!(gave(&read), "x");
            drop(tty);
        }
        // Fix round 1, measured: a read another process left in progress when it ended, in the console this one shares with it (the
        // shell's console, after `sshelter connect` ended), takes nothing of what is typed next: neither a raw read, nor a hidden line read
        // with a part of a password typed into it. The process that leaves them is this test binary again, run without a console of its
        // own, so that it shares this one.
        "a_read_an_ended_process_left_takes_nothing" => {
            let leave = |grandchild: &str| {
                rerun_alone_with(NAME, |command| {
                    command.env(CASE, grandchild);
                })
            };
            set_mode(control, console.raw).unwrap();
            flush(control).unwrap();
            leave("leave_a_raw_read");
            let (read, _thread) = read_on_a_thread(open("CONIN$"));
            type_text(control, "a");
            let first = read.recv_timeout(AT_ONCE);
            let later = if first.is_err() {
                type_text(control, "b");
                format!("; after a second key: {:?}", read.recv_timeout(DONE))
            } else {
                String::new()
            };
            assert!(matches!(&first, Ok(read) if read.text == "a"), "the raw read's first key: {first:?}{later}");
            set_mode(control, console.hidden).unwrap();
            flush(control).unwrap();
            new_line(console.out, "after the hidden read");
            let (_, y) = cursor(console.out);
            leave("leave_a_hidden_line_read");
            set_mode(control, console.shown).unwrap();
            let (read, _thread) = read_on_a_thread(open("CONIN$"));
            type_text(control, "x\r");
            let line = read.recv_timeout(AT_ONCE);
            assert!(matches!(&line, Ok(read) if read.text == "x\r\n"), "the line read after it: {line:?}");
            assert!(!row(console.out, y).contains("hun"), "the part typed into the ended read is not shown: {:?}", row(console.out, y));
        }
        // The process that `a_read_an_ended_process_left_takes_nothing` runs: it ends with a raw read in progress.
        "leave_a_raw_read" => {
            let (read, _thread) = read_on_a_thread(open("CONIN$"));
            std::thread::sleep(SETTLE);
            assert!(read.try_recv().is_err(), "the raw read waits");
        }
        // The same, with a hidden line read in progress, "hun" typed into it.
        "leave_a_hidden_line_read" => {
            let (read, _thread) = read_on_a_thread(open("CONIN$"));
            std::thread::sleep(SETTLE);
            type_text(control, "hun");
            std::thread::sleep(SETTLE);
            assert!(read.try_recv().is_err(), "the line read waits, \"hun\" in its line");
        }
        // Fix round 1: what is typed after `sshelter connect` ended is the shell's, whole: the program's own end (its run puts the console
        // back, then its `Tty` goes) leaves no read of its own in the console it shares with the shell, also when it ended under a hidden
        // question with a part of the answer typed.
        "the_keys_after_the_cli_ended_are_the_shells" => {
            let end = |grandchild: &str| {
                rerun_alone_with(NAME, |command| {
                    command.env(CASE, grandchild);
                })
            };
            end("end_in_the_shell");
            set_mode(control, console.raw).unwrap();
            let (read, _thread) = read_on_a_thread(open("CONIN$"));
            type_text(control, "a");
            assert_eq!(read.recv_timeout(AT_ONCE).map(|read| read.text), Ok("a".to_string()), "the first key after the end");
            new_line(console.out, "after the question");
            let (_, y) = cursor(console.out);
            end("end_under_a_question");
            set_mode(control, console.shown).unwrap();
            let (read, _thread) = read_on_a_thread(open("CONIN$"));
            type_text(control, "x\r");
            assert_eq!(read.recv_timeout(AT_ONCE).map(|read| read.text), Ok("x\r\n".to_string()), "the first line after the end");
            assert!(!row(console.out, y).contains("hun"), "{:?}", row(console.out, y));
        }
        // The process that `the_keys_after_the_cli_ended_are_the_shells` runs: `sshelter connect`'s console, keys and end, in raw mode.
        "end_in_the_shell" => {
            let mut tty = Tty::new(Arc::new(StdConsole::opened().unwrap())).unwrap();
            tty.take_over().unwrap();
            tty.set_mode(Mode::Raw, false).unwrap();
            let (inputs, _queue) = queue();
            console_keys_thread(inputs, tty.keys(), || {});
            std::thread::sleep(SETTLE);
            // As the run's end and then the session's: the console put back, and the `Tty` gone.
            tty.restore();
            drop(tty);
        }
        // The same, at a hidden question with "hun" typed into its answer, ended as the client ends a session under a question.
        "end_under_a_question" => {
            let mut tty = Tty::new(Arc::new(StdConsole::opened().unwrap())).unwrap();
            tty.take_over().unwrap();
            tty.set_mode(Mode::Prompt { echo: false }, true).unwrap();
            let (inputs, _queue) = queue();
            console_keys_thread(inputs, tty.keys(), || {});
            std::thread::sleep(SETTLE);
            type_text(control, "hun");
            std::thread::sleep(SETTLE);
            tty.set_mode(Mode::Cooked, true).unwrap();
            tty.restore();
            drop(tty);
        }
        // Final wave (F9): the same on the input the ending process was GIVEN as its standard input, the way `sshelter connect`
        // reads the console input its shell and `sshelter-cli.exe` hand it (`StdConsole::new`, the standard handle). That input stays
        // open when the process ends (this process, its "shell", keeps a handle of the same input and reads it next), so a read left in
        // progress could live on with the input rather than end with the process. First the check is shown to see a read that lives on (a
        // cancelled one, on this input); then the program ends with its keys thread in a read: raw, and a hidden line read with "hun"
        // typed into it, each by returning once its console was put back and by the watchdog's exit from another thread. Each time the
        // next raw read on this input gets the next key, the next line read the next line, and "hun" is not shown.
        "a_read_left_on_the_given_input_takes_nothing" => {
            let original = mode_of(control).unwrap();
            let given = owned("CONIN$");
            let shells = H(given.as_raw_handle() as usize);
            // A read that lives on takes the key typed next: so a cancelled one does, on this input.
            set_mode(control, console.raw).unwrap();
            flush(control).unwrap();
            let (cancelled, _thread) = read_on_a_thread(shells);
            std::thread::sleep(SETTLE);
            // SAFETY: cancels this process's I/O on a handle it keeps open.
            assert_ne!(unsafe { CancelIoEx(shells.raw(), ptr::null()) }, 0);
            cancelled.recv_timeout(DONE).expect("the cancelled read returned");
            let (next, _thread) = read_on_a_thread(shells);
            type_text(control, "a");
            assert!(next.recv_timeout(AT_ONCE).is_err(), "the cancelled read took the key");
            type_text(control, "b");
            assert_eq!(gave(&next), "b");
            let end = |program: &str| {
                set_mode(control, original).unwrap();
                flush(control).unwrap();
                let stdin = Stdio::from(given.try_clone().expect("another handle of the same input"));
                rerun_alone_reading(NAME, stdin, |command| {
                    command.env(CASE, program);
                });
            };
            let mut failed = Vec::new();
            for program in ["a_raw_read_at_the_end", "a_raw_read_at_the_watchdogs_exit"] {
                new_line(console.out, program);
                end(program);
                set_mode(control, console.raw).unwrap();
                let (read, _thread) = read_on_a_thread(shells);
                type_text(control, "a");
                match read.recv_timeout(AT_ONCE) {
                    Ok(read) if read.text == "a" => {}
                    first => {
                        type_text(control, "b");
                        failed.push(format!("{program}: the next raw read got {first:?}; after another key, {:?}", read.recv_timeout(DONE)));
                    }
                }
            }
            for program in ["a_hidden_line_read_at_the_end", "a_hidden_line_read_at_the_watchdogs_exit"] {
                new_line(console.out, program);
                let (_, y) = cursor(console.out);
                end(program);
                set_mode(control, console.shown).unwrap();
                let (read, _thread) = read_on_a_thread(shells);
                type_text(control, "x\r");
                match read.recv_timeout(AT_ONCE) {
                    Ok(read) if read.text == "x\r\n" => {}
                    first => {
                        type_text(control, "y\r");
                        failed.push(format!("{program}: the next line read got {first:?}; after another line, {:?}", read.recv_timeout(DONE)));
                    }
                }
                if row(console.out, y).contains("hun") {
                    failed.push(format!("{program}: what was typed into the ended read was shown: {:?}", row(console.out, y)));
                }
            }
            assert!(failed.is_empty(), "a read the program left took what was typed after it:\n{}", failed.join("\n"));
        }
        // The programs `a_read_left_on_the_given_input_takes_nothing` runs.
        "a_raw_read_at_the_end" => end_with_a_read(control, Mode::Raw, "", false),
        "a_raw_read_at_the_watchdogs_exit" => end_with_a_read(control, Mode::Raw, "", true),
        "a_hidden_line_read_at_the_end" => end_with_a_read(control, Mode::Prompt { echo: false }, "hun", false),
        "a_hidden_line_read_at_the_watchdogs_exit" => end_with_a_read(control, Mode::Prompt { echo: false }, "hun", true),
        // Spec §7.3: the console is given whole characters: what the terminal writer writes to it (`Output::console` over `ConsoleText`,
        // `WriteConsoleW`) shows a character whole when it was cut between two writes, here é (two bytes) and € (three). Written as they
        // come, each write on its own, the cut characters show as U+FFFD: so a cut one would show here.
        "a_character_cut_between_two_writes_reaches_the_console_whole" => {
            let text = "\u{e9} \u{20ac} x".as_bytes();
            let pieces = [&text[..1], &text[1..4], &text[4..]];
            new_line(console.out, "whole");
            let (_, y) = cursor(console.out);
            let mut output = Output::console(ConsoleText::new(owned("CONOUT$")));
            for piece in pieces {
                output.write_as_the_writer(piece).unwrap();
            }
            output.end_as_the_writer().unwrap();
            assert_eq!(row(console.out, y), "[whole] \u{e9} \u{20ac} x");
            new_line(console.out, "cut");
            let (_, y) = cursor(console.out);
            let mut cut = ConsoleText::new(owned("CONOUT$"));
            for piece in pieces {
                std::io::Write::write_all(&mut cut, piece).unwrap();
            }
            assert!(row(console.out, y).contains('\u{fffd}'), "{:?}", row(console.out, y));
        }
        // The real control handler (`inputs_windows::take_over_control_events`): the console's Ctrl-C and Ctrl-Break reach the loop as an
        // interrupt, and the program goes on.
        "the_control_handler_takes_ctrl_c_and_ctrl_break" => {
            let tty = Tty::new(Arc::new(StdConsole::opened().unwrap())).unwrap();
            let (inputs, mut queue) = queue();
            // Armed, the watchdog would end the program `grace` after (once it held the console put back, 200 ms at most): it says so
            // here instead, and the test waits past that.
            let (alarm, alarms) = mpsc::channel();
            let watchdog = Watchdog::start(tty.restorer(), Duration::from_millis(300), move |code| {
                let _ = alarm.send(code);
            })
            .unwrap();
            take_over_control_events(ControlEvents::new(inputs, watchdog.clone(), Over::default())).unwrap();
            for event in [CTRL_C_EVENT, CTRL_BREAK_EVENT] {
                // SAFETY: the event to every process on this console: this one only, which has the handler.
                assert_ne!(unsafe { GenerateConsoleCtrlEvent(event, 0) }, 0);
                assert!(matches!(queue.next_within(DONE), Some(Input::Interrupt)), "event {event}");
            }
            assert_eq!(alarms.recv_timeout(Duration::from_secs(1)), Err(mpsc::RecvTimeoutError::Timeout), "the watchdog was armed");
            watchdog.stand_down();
        }
        other => panic!("no case {other}"),
    }
}

/// The variable that names the case a child runs.
const CASE: &str = "SSHELTER_TEST_CONSOLE_CASE";

/// The cases, each in a child with a console of its own: a read one case leaves waiting cannot take the keys of the next. Every case
/// runs, and the test fails with all that failed.
/// The test's full name, which a child runs again (and a case of its own, again, for a process that shares its console).
const NAME: &str = "cli::real_console_tests::a_real_console_works_as_the_keys_reader_needs";

#[test]
fn a_real_console_works_as_the_keys_reader_needs() {
    if is_child() {
        case(&std::env::var(CASE).expect("the case"));
        return;
    }
    // winbase.h: a console of its own for the child.
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let cases = [
        "calls_do_not_wait_for_a_read",
        "a_raw_read_spans_a_change_of_mode",
        "a_line_read_spans_a_change_of_mode",
        "a_cancelled_read_takes_the_next_key",
        "a_woken_read_ends_and_the_next_read_takes_the_next_key",
        "an_aborted_read_through_the_console_gives_nothing",
        "a_generated_ctrl_c_does_not_end_a_line_read",
        "a_hidden_line_is_not_in_the_history",
        "the_keys_reader_on_a_real_console",
        "a_panic_puts_the_real_console_back",
        "a_freed_console_fails_its_reads",
        "the_input_is_signalled_while_it_holds_a_record",
        "an_end_under_a_question_leaves_nothing_behind",
        "a_read_an_ended_process_left_takes_nothing",
        "the_keys_after_the_cli_ended_are_the_shells",
        "a_read_left_on_the_given_input_takes_nothing",
        "a_character_cut_between_two_writes_reaches_the_console_whole",
        "the_control_handler_takes_ctrl_c_and_ctrl_break",
    ];
    let started = Instant::now();
    let failed: Vec<String> = cases
        .into_iter()
        .filter_map(|name| {
            let ran = std::panic::catch_unwind(|| {
                rerun_alone_with(NAME, |command| {
                    use std::os::windows::process::CommandExt;
                    command.creation_flags(CREATE_NEW_CONSOLE).env(CASE, name);
                })
            });
            let said = match ran {
                Ok(said) => said,
                Err(panic) => {
                    let why = panic.downcast_ref::<String>().cloned().or_else(|| panic.downcast_ref::<&str>().map(|text| text.to_string()));
                    return Some(format!("{name}: {}", why.unwrap_or_default()));
                }
            };
            // The hook `restore_on_panic` installs hands the panic on to the hook before it, which reports it as usual.
            let reported = name != "a_panic_puts_the_real_console_back" || said.contains("a thread of the program failed");
            (!reported).then(|| format!("{name}: the panic was not reported:\n{said}"))
        })
        .collect();
    assert!(failed.is_empty(), "{} of {} cases failed ({:?}):\n{}", failed.len(), cases.len(), started.elapsed(), failed.join("\n"));
}

/// The variable that names the directory of the pair `the_pair_in_a_console_of_its_own` runs: `sshelter-cli.exe` and the `sshelter.exe`
/// beside it (on CI the debug build's, in test-windows.yml, and each installer's release build, in windows-bundle-check.yml).
const PAIR: &str = "SSHELTER_TEST_PAIR";

/// The compiled profile of the external pair, which can differ from this test binary.
const PAIR_PROFILE: &str = "SSHELTER_TEST_PAIR_PROFILE";

fn pair_profile() -> crate::app_profile::AppProfile {
    match std::env::var(PAIR_PROFILE).as_deref() {
        Ok("development") => crate::app_profile::AppProfile::Development,
        Ok("production") => crate::app_profile::AppProfile::Production,
        _ => panic!("{PAIR_PROFILE} must name the external pair's profile: development or production"),
    }
}

/// The full name of `the_pair_in_a_console_of_its_own`, which its children run again.
const PAIR_TEST: &str = "cli::real_console_tests::the_pair_in_a_console_of_its_own";

/// Final wave (F10): `sshelter connect`'s way into a console as a terminal gives it, which no other test takes: the console helper
/// started in a console of its own with that console's own buffers as its standard input, output and error (not a test's pipes), as a
/// shell in the console starts a program, and `sshelter.exe` on the console handles it inherits through the helper (`StdConsole::new`'s
/// standard handles; a release build is a GUI program, which attaches to the helper's console first). Each case runs in a child with a
/// console of its own, which reads what the console's screen shows once the pair has ended:
/// - `sshelter-cli.exe connect`: the usage on the console, and 2;
/// - `sshelter-cli.exe connect web` while SSHelter's session pipe exists and another owner made it (the Administrators group: the CI
///   runner is elevated): the refusal on the console, and 1. On the way the pair attached to the console, read its standard handles as a
///   console (`Tty::new`) and refused the pipe in the broker's connect (it did open that very pipe), and it started no SSHelter;
/// - the pair's helper next to a stand-in `sshelter.exe` (this test binary) that changes the console and is ended from outside, as the NSIS
///   installer ends every `sshelter.exe` at an install, an update and an uninstall: once it has ended the helper puts the console's four
///   settings back, which the program alone leaves changed, and leaves with its exit code.
///
/// A CI step runs it (`--ignored`) with `SSHELTER_TEST_PAIR` naming the pair's directory
/// and `SSHELTER_TEST_PAIR_PROFILE` naming its compiled profile.
#[test]
#[ignore = "runs the console pair in the directory SSHELTER_TEST_PAIR names (a CI step)"]
fn the_pair_in_a_console_of_its_own() {
    if is_child() {
        pair_case(&std::env::var(CASE).expect("the case"));
        return;
    }
    let dir = PathBuf::from(std::env::var_os(PAIR).expect("SSHELTER_TEST_PAIR names the directory of sshelter-cli.exe and sshelter.exe"));
    for program in ["sshelter-cli.exe", "sshelter.exe"] {
        assert!(dir.join(program).is_file(), "{program} is not in {}", dir.display());
    }
    // winbase.h: a console of its own for the child.
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    for case in [
        "the_usage_on_the_console",
        "a_pipe_another_owner_made_is_refused_on_the_console",
        "the_helper_puts_back_the_console_a_killed_program_changed",
    ] {
        let said = rerun_alone_with(PAIR_TEST, |command| {
            use std::os::windows::process::CommandExt;
            command.arg("--include-ignored").creation_flags(CREATE_NEW_CONSOLE).env(CASE, case);
        });
        eprintln!("{case} ({}):\n{said}", dir.display());
    }
}

/// One case of `the_pair_in_a_console_of_its_own`, in a child with a console of its own.
fn pair_case(name: &str) {
    let dir = PathBuf::from(std::env::var_os(PAIR).expect("the pair's directory"));
    match name {
        "the_usage_on_the_console" => {
            let (code, screen) = run_the_pair(&dir, &["connect"]);
            eprintln!("sshelter-cli.exe connect ended with {code}; the console shows:\n{screen}");
            assert!(screen.contains("usage: sshelter connect <alias>"), "the usage is not on the console:\n{screen}");
            assert!(screen.contains("sshelter connect --id <host id>"), "the usage is not on the console:\n{screen}");
            assert_eq!(code, 2);
        }
        "a_pipe_another_owner_made_is_refused_on_the_console" => {
            let profile = pair_profile();
            let role = profile.pipe_role(crate::app_profile::IpcRole::Session);
            let name = crate::ipc::pipe_windows::pipe_name_for(role).expect("the external pair's session pipe name");
            let squatter = crate::ipc::pipe_windows::testing::squat_as_administrators(&name)
                .expect("the Administrators group can own the pipe: the runner is elevated");
            let (code, screen) = run_the_pair(&dir, &["connect", "web"]);
            eprintln!("sshelter-cli.exe connect web ended with {code}; the console shows:\n{screen}");
            let started = sshelters_left();
            assert!(started.is_empty(), "an SSHelter was started (process ids {started:?}), and is stopped now");
            assert!(a_client_came(&squatter), r"sshelter.exe did not open \\.\pipe\{name}");
            let label = match profile {
                crate::app_profile::AppProfile::Production => "session",
                crate::app_profile::AppProfile::Development => "dev",
            };
            let refused = format!(r"Another program is using SSHelter's {label} pipe (\\.\pipe\{name})");
            assert!(screen.contains(&refused), "the refusal is not on the console:\n{screen}");
            assert_eq!(code, 1);
        }
        // Residual R2 (own-ssh spec §7.3): a `sshelter.exe` ended from outside puts nothing back; its helper does, once it has ended.
        // The pair's helper is copied next to a stand-in `sshelter.exe` (`KILLED_PROGRAM`). First the stand-in alone: the console's four
        // settings are left changed, so the check sees a console that was not put back. Then through the helper, as a terminal runs it.
        "the_helper_puts_back_the_console_a_killed_program_changed" => {
            let before = settings();
            let scratch = tempfile::tempdir().expect("a scratch directory");
            let helper = scratch.path().join("sshelter-cli.exe");
            let program = scratch.path().join("sshelter.exe");
            std::fs::copy(dir.join("sshelter-cli.exe"), &helper).expect("a copy of the pair's helper");
            std::fs::copy(std::env::current_exe().expect("this test binary"), &program).expect("this test binary as sshelter.exe");
            let killed = |path: &Path| {
                let mut command = std::process::Command::new(path);
                command.args(["--exact", PAIR_TEST, "--nocapture", "--test-threads=1", "--include-ignored"]).env(CASE, KILLED_PROGRAM);
                run_in_this_console(&mut command)
            };

            let (code, screen) = killed(&program);
            let left = settings();
            eprintln!("sshelter.exe alone ended with {code}; the console's settings were {before:?}, and are {left:?}");
            assert_eq!(code, KILLED as i32, "the stand-in did not end as it should; the console shows:\n{screen}");
            let changed = [before.0 != left.0, before.1 != left.1, before.2 != left.2, before.3 != left.3];
            assert_eq!(changed, [true; 4], "the stand-in did not change every setting: {before:?}, then {left:?}");
            put_back(before);
            assert_eq!(settings(), before, "this process put the console back itself");

            let (code, screen) = killed(&helper);
            let after = settings();
            eprintln!("sshelter-cli.exe ended with {code}; the console's settings were {before:?}, and are {after:?}");
            assert_eq!(code, KILLED as i32, "the helper did not leave with its program's exit code; the console shows:\n{screen}");
            assert_eq!(after, before, "the helper did not put the console back once its program had ended");
        }
        // The stand-in `sshelter.exe`, run alone and by the helper. As `sshelter connect`, it takes over the console of the standard
        // handles it was given (`StdConsole::new`) and sets raw mode (the input's mode and the output's); it changes both code pages too,
        // each to another than the console started with (`sshelter connect` sets the output's to UTF-8 and leaves the input's; the helper
        // keeps all four). Then it is ended from outside, as the NSIS installer ends it (`TerminateProcess`): no way out of it runs, so
        // nothing of its own puts the console back.
        KILLED_PROGRAM => {
            // SAFETY: GetStdHandle only reads this process's standard handles; GetConsoleCP and GetConsoleOutputCP read its console.
            let (input, output, input_cp, output_cp) =
                unsafe { (GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE), GetConsoleCP(), GetConsoleOutputCP()) };
            let console = Arc::new(StdConsole::new());
            assert_eq!((console.input(), console.output()), (input, output), "the console is that of the standard handles given");
            let mut tty = Tty::new(console).expect("the standard input is the console's");
            tty.take_over().expect("the console takes virtual terminal sequences");
            tty.set_mode(Mode::Raw, false).expect("raw mode");
            let other = |code_page: u32| if code_page == 437 { 850 } else { 437 };
            // SAFETY: plain values for this process's console.
            unsafe {
                assert_ne!(SetConsoleCP(other(input_cp)), 0, "{}", io::Error::last_os_error());
                assert_ne!(SetConsoleOutputCP(other(output_cp)), 0, "{}", io::Error::last_os_error());
            }
            std::mem::forget(tty);
            // SAFETY: ends this process, as another process's TerminateProcess would.
            unsafe { TerminateProcess(GetCurrentProcess(), KILLED) };
            std::thread::sleep(DONE);
            panic!("TerminateProcess did not end this process");
        }
        other => panic!("no case {other}"),
    }
}

/// The program `the_helper_puts_back_the_console_a_killed_program_changed` runs as `sshelter.exe` (a case of `pair_case` that this test
/// binary runs as that program, not one of the test's own).
const KILLED_PROGRAM: &str = "a_program_that_changes_the_console_and_is_killed";

/// The exit code `KILLED_PROGRAM` is ended with: one of its own, which neither the helper (1) nor a failed test (101) leaves with.
const KILLED: u32 = 77;

/// Puts this process's console back to `settings` (as `settings()` reads them).
fn put_back((input_mode, output_mode, input_cp, output_cp): (u32, u32, u32, u32)) {
    set_mode(open("CONIN$"), input_mode).expect("the input's mode");
    set_mode(open("CONOUT$"), output_mode).expect("the output's mode");
    // SAFETY: plain values for this process's console.
    unsafe {
        assert_ne!(SetConsoleCP(input_cp), 0, "{}", io::Error::last_os_error());
        assert_ne!(SetConsoleOutputCP(output_cp), 0, "{}", io::Error::last_os_error());
    }
}

/// Runs `sshelter-cli.exe` of `dir` with `args` in this process's console (`run_in_this_console`).
fn run_the_pair(dir: &Path, args: &[&str]) -> (i32, String) {
    let mut command = std::process::Command::new(dir.join("sshelter-cli.exe"));
    command.args(args);
    run_in_this_console(&mut command)
}

/// Runs `command` in this process's console, as a shell there runs a program: its standard input, output and error are the console's own
/// buffers (this process's are the test's pipes). Its exit code, and what the console's screen shows once it has ended.
fn run_in_this_console(command: &mut std::process::Command) -> (i32, String) {
    let output = owned("CONOUT$");
    command
        .stdin(Stdio::from(owned("CONIN$")))
        .stdout(Stdio::from(output.try_clone().expect("another handle of the screen buffer")))
        .stderr(Stdio::from(output));
    let name = Path::new(command.get_program()).file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let mut program = crate::process::spawn(command).unwrap_or_else(|error| panic!("{name} does not start: {error}"));
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        match program.try_wait().expect("the program's status") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = program.kill();
                panic!("{name} did not end within a minute; the console shows:\n{}", screen());
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    (status.code().expect("the program's exit code"), screen())
}

/// What the screen buffer of this process's console shows, from its first row to the cursor's: rows joined by line breaks, except where a
/// line fills a row to its last column and goes on in the next.
fn screen() -> String {
    let out = owned("CONOUT$");
    let handle = out.as_raw_handle() as HANDLE;
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: plain data the call fills in.
    assert_ne!(unsafe { GetConsoleScreenBufferInfo(handle, &mut info) }, 0, "{}", io::Error::last_os_error());
    let width = usize::try_from(info.dwSize.X).unwrap_or(0).max(1);
    let mut text = String::new();
    for y in 0..=info.dwCursorPosition.Y {
        let mut cells = vec![0u16; width];
        let mut read = 0u32;
        // SAFETY: `cells` holds `width` characters.
        unsafe { ReadConsoleOutputCharacterW(handle, cells.as_mut_ptr(), width as u32, COORD { X: 0, Y: y }, &mut read) };
        let row = String::from_utf16_lossy(&cells[..(read as usize).min(width)]);
        let filled = read as usize == width && !row.ends_with(' ');
        text.push_str(row.trim_end());
        if !filled {
            text.push('\n');
        }
    }
    text
}

/// Whether a client opened `pipe`, the squatter's first instance (in overlapped mode, and never connected by the squatter): a
/// `ConnectNamedPipe` now finds a client there, or one that came and went (the pipe is closing), or none yet (it would wait; it is
/// cancelled).
fn a_client_came(pipe: &OwnedHandle) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, FALSE};
    use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
    use windows_sys::Win32::System::Threading::CreateEventW;
    use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
    let handle = pipe.as_raw_handle() as HANDLE;
    // SAFETY: a manual-reset event without a name or security attributes; owned below.
    let event = unsafe { CreateEventW(ptr::null(), TRUE, FALSE, ptr::null()) };
    assert!(!event.is_null(), "{}", io::Error::last_os_error());
    // SAFETY: the event just made, which nothing else owns.
    let event = unsafe { OwnedHandle::from_raw_handle(event as _) };
    let mut overlapped = OVERLAPPED { hEvent: event.as_raw_handle() as HANDLE, ..Default::default() };
    // Only through this pointer from here on, as in `ipc::pipe_windows::accept`.
    let overlapped: *mut OVERLAPPED = &mut overlapped;
    // SAFETY: an instance in overlapped mode; `overlapped` and its event live until the connect is over (waited for below if it waits).
    if unsafe { ConnectNamedPipe(handle, overlapped) } != 0 {
        return true;
    }
    match last_error() {
        ERROR_PIPE_CONNECTED | ERROR_NO_DATA => true,
        ERROR_IO_PENDING => {
            let mut transferred = 0u32;
            // SAFETY: cancels the connect started above, then waits for it to be over, so that `overlapped` is not used after this.
            unsafe {
                CancelIoEx(handle, overlapped);
                // A client that came at that very moment connected it all the same.
                GetOverlappedResult(handle, overlapped, &mut transferred, TRUE) != 0
            }
        }
        error => panic!("ConnectNamedPipe: {}", io::Error::from_raw_os_error(error as i32)),
    }
}

/// The processes called `sshelter.exe` that are running (their ids). Once the pair has ended, any is an SSHelter it started: each is
/// stopped, so that it does not outlive the test.
fn sshelters_left() -> Vec<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    let mut found = Vec::new();
    // SAFETY: Toolhelp's iteration of the processes, `dwSize` set before the first call; the snapshot and every process handle are closed.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        assert_ne!(snapshot, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let length = entry.szExeFile.iter().position(|&unit| unit == 0).unwrap_or(entry.szExeFile.len());
            if String::from_utf16_lossy(&entry.szExeFile[..length]).eq_ignore_ascii_case("sshelter.exe") {
                found.push(entry.th32ProcessID);
            }
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        for &id in &found {
            let process = OpenProcess(PROCESS_TERMINATE, 0, id);
            if !process.is_null() {
                TerminateProcess(process, 1);
                CloseHandle(process);
            }
        }
    }
    found
}
