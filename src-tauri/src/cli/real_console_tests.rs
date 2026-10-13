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

use std::ptr;
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, TRUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleCP, GetConsoleMode, GetConsoleOutputCP,
    GetConsoleScreenBufferInfo, GetNumberOfConsoleInputEvents, ReadConsoleOutputCharacterW, ReadConsoleW, SetConsoleCtrlHandler,
    SetConsoleMode, WriteConsoleInputW, WriteConsoleW, CONSOLE_SCREEN_BUFFER_INFO, COORD, CTRL_C_EVENT, INPUT_RECORD, KEY_EVENT,
    KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::IO::CancelIoEx;

use super::client::Input;
use super::console::{input_mode, ConsoleApi, Mode};
use super::run::{console_keys_thread, queue};
use super::terminal::{restore_on_panic, StdConsole, Tty};
use crate::ssh::testing::{is_child, rerun_alone_with};

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
        other => panic!("no case {other}"),
    }
}

/// The variable that names the case a child runs.
const CASE: &str = "SSHELTER_TEST_CONSOLE_CASE";

/// The cases, each in a child with a console of its own: a read one case leaves waiting cannot take the keys of the next. Every case
/// runs, and the test fails with all that failed.
#[test]
fn a_real_console_works_as_the_keys_reader_needs() {
    const NAME: &str = "cli::real_console_tests::a_real_console_works_as_the_keys_reader_needs";
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
