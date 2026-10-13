//! A real console, measured (plan 1b-3 Task 3; the review of Task 2 asked for it before the keys are read on Windows): what a
//! `ReadConsoleW` in progress on one thread does to the console calls of another, and what a change of mode does to a read in progress.
//! The test runs again in a child process that has a console of its own (`CREATE_NEW_CONSOLE`), where it types into that console's
//! input buffer itself (`WriteConsoleInputW`, as a terminal's keys arrive there) and reads the screen buffer to see what was echoed.
//!
//! PROBE: this first version only reports what it saw (`FACT` lines) and fails, so that the CI log shows the facts.

use std::ptr;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, SetLastError, DUPLICATE_SAME_ACCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, TRUE,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleMode, GetConsoleScreenBufferInfo,
    GetNumberOfConsoleInputEvents, ReadConsoleOutputCharacterW, ReadConsoleW, SetConsoleCtrlHandler, SetConsoleMode, WriteConsoleInputW,
    WriteConsoleW, CONSOLE_SCREEN_BUFFER_INFO, COORD, CTRL_C_EVENT, INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
    LEFT_CTRL_PRESSED,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, WaitForSingleObject};
use windows_sys::Win32::System::IO::{CancelIoEx, CancelSynchronousIo};

use crate::cli::console::{input_mode, Mode};
use crate::ssh::testing::{fact, is_child, rerun_alone_with};

/// The virtual-key codes the tests type (winuser.h): Enter, the up arrow, and the letter C (with Ctrl, Ctrl-C).
const VK_RETURN: u16 = 0x0D;
const VK_UP: u16 = 0x26;
const VK_C: u16 = 0x43;

/// A console handle that can cross threads (a raw `HANDLE` is a pointer). The child never closes them: a handle with a read stuck on it
/// is not closed under that read, and the process ends at the end of the test.
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

/// Another handle on the same file object as `handle`.
fn duplicate(handle: H) -> H {
    let mut copy: HANDLE = ptr::null_mut();
    // SAFETY: duplicates a valid handle of this process into this process, with the same access.
    let done = unsafe { DuplicateHandle(GetCurrentProcess(), handle.raw(), GetCurrentProcess(), &mut copy, 0, 0, DUPLICATE_SAME_ACCESS) };
    assert_ne!(done, 0, "DuplicateHandle: {}", std::io::Error::last_os_error());
    H(copy as usize)
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
fn key(vk: u16, ch: u16, ctrl: u32) -> [INPUT_RECORD; 2] {
    let event = |down: bool| {
        let mut record = INPUT_RECORD { EventType: KEY_EVENT as u16, ..Default::default() };
        record.Event.KeyEvent = KEY_EVENT_RECORD {
            bKeyDown: BOOL::from(down),
            wRepeatCount: 1,
            wVirtualKeyCode: vk,
            wVirtualScanCode: 0,
            uChar: KEY_EVENT_RECORD_0 { UnicodeChar: ch },
            dwControlKeyState: ctrl,
        };
        record
    };
    [event(true), event(false)]
}

/// The keys that type `text` (lower-case letters, digits, Enter for `\r`).
fn keys_of(text: &str) -> Vec<INPUT_RECORD> {
    text.encode_utf16()
        .flat_map(|c| match c {
            0x0d => key(VK_RETURN, 0x0d, 0),
            c if (u16::from(b'a')..=u16::from(b'z')).contains(&c) => key(c - 32, c, 0),
            c => key(c, c, 0),
        })
        .collect()
}

/// Puts `records` in the console's input buffer through `handle`, as if they were typed.
fn type_records(handle: H, records: &[INPUT_RECORD]) -> Result<u32, u32> {
    let mut written = 0;
    // SAFETY: `records` is valid for its length.
    if unsafe { WriteConsoleInputW(handle.raw(), records.as_ptr(), records.len() as u32, &mut written) } == 0 {
        return Err(last_error());
    }
    Ok(written)
}

fn type_text(handle: H, text: &str) {
    type_records(handle, &keys_of(text)).expect("WriteConsoleInputW");
}

/// What one `ReadConsoleW` returned.
#[derive(Debug)]
struct Read {
    ok: bool,
    chars: u32,
    error: u32,
    text: String,
}

impl std::fmt::Display for Read {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ok={} chars={} error={} text={:?}", self.ok, self.chars, self.error, self.text)
    }
}

/// A `ReadConsoleW` of up to `size` characters on `handle`, on a thread of its own; its result arrives on the receiver.
fn read_on_a_thread(handle: H, size: u32) -> (mpsc::Receiver<Read>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut buf = vec![0u16; size as usize];
        let mut chars = 0u32;
        // SAFETY: clears this thread's last error, so that what the read leaves there is its own.
        unsafe { SetLastError(0) };
        // SAFETY: `buf` holds `size` characters; no read control.
        let ok = unsafe { ReadConsoleW(handle.raw(), buf.as_mut_ptr().cast(), size, &mut chars, ptr::null()) } != 0;
        let error = last_error();
        let text = String::from_utf16_lossy(&buf[..(chars as usize).min(buf.len())]);
        let _ = tx.send(Read { ok, chars, error, text });
    });
    (rx, thread)
}

/// Runs `call` on a thread of its own: its result, with how long it took, arrives on the receiver.
fn timed<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> mpsc::Receiver<(T, Duration)> {
    let (tx, rx) = mpsc::channel();
    let started = Instant::now();
    std::thread::spawn(move || {
        let result = call();
        let _ = tx.send((result, started.elapsed()));
    });
    rx
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

/// Starts a new line on the screen, so that each measurement's echo is on a row of its own.
fn new_line(out: H, label: &str) {
    let text: Vec<u16> = format!("\r\n[{label}] ").encode_utf16().collect();
    let mut written = 0;
    // SAFETY: `text` is valid for its length.
    unsafe { WriteConsoleW(out.raw(), text.as_ptr(), text.len() as u32, &mut written, ptr::null()) };
}

/// How a call on a thread of its own came out: in time, or still blocked after `within`.
fn outcome<T: std::fmt::Debug>(rx: &mpsc::Receiver<(T, Duration)>, within: Duration) -> String {
    match rx.recv_timeout(within) {
        Ok((result, took)) => format!("returned {result:?} after {} ms", took.as_millis()),
        Err(_) => format!("still blocked after {} ms", within.as_millis()),
    }
}

fn read_outcome(rx: &mpsc::Receiver<Read>, within: Duration) -> String {
    match rx.recv_timeout(within) {
        Ok(read) => format!("returned {read}"),
        Err(_) => format!("still pending after {} ms", within.as_millis()),
    }
}

/// The console control events the handler saw.
static EVENTS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

unsafe extern "system" fn record_event(event: u32) -> BOOL {
    EVENTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(event);
    TRUE
}

fn events_seen() -> Vec<u32> {
    std::mem::take(&mut *EVENTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}

const SETTLE: Duration = Duration::from_millis(300);
const BLOCKED: Duration = Duration::from_millis(1000);
const DONE: Duration = Duration::from_millis(3000);

/// The measurement itself, in the child.
fn measure() {
    let control = open("CONIN$");
    let out = open("CONOUT$");
    let start = mode_of(control).expect("the child's console input");
    let raw = input_mode(start, Mode::Raw);
    let hidden = input_mode(start, Mode::Prompt { echo: false });
    let shown = input_mode(start, Mode::Prompt { echo: true });
    fact("start_input_mode", format!("{start:#06x}"));
    fact("set_raw_mode", format!("{:?}", set_mode(control, raw)));
    fact("start_output_mode", format!("{:?}", mode_of(out).map(|mode| format!("{mode:#06x}"))));

    // A raw read waits on a fresh handle `h` of its own; the mode was set and the buffer emptied through `control`.
    let pending_raw = |label: &str| {
        set_mode(control, raw).unwrap();
        flush(control).unwrap();
        new_line(out, label);
        let h = open("CONIN$");
        let (read, thread) = read_on_a_thread(h, 64);
        std::thread::sleep(SETTLE);
        let pending = read.try_recv().is_err();
        (h, read, thread, pending)
    };

    // (i) Calls on the handle a read waits on, on a duplicate of it (the same file object), and on another handle (another file object).
    type Call = fn(H) -> String;
    let calls: [(&str, Call); 5] = [
        ("GetConsoleMode", |h| format!("{:?}", mode_of(h))),
        ("SetConsoleMode", |h| format!("{:?}", mode_of(h).and_then(|mode| set_mode(h, mode)))),
        ("FlushConsoleInputBuffer", |h| format!("{:?}", flush(h))),
        ("GetNumberOfConsoleInputEvents", |h| format!("{:?}", events(h))),
        ("WaitForSingleObject0", |h| {
            // SAFETY: a wait of zero only looks at the handle's state.
            format!("{}", unsafe { WaitForSingleObject(h.raw(), 0) })
        }),
    ];
    for (name, call) in calls {
        for kind in ["same", "duplicate", "other"] {
            let (h, read, _thread, pending) = pending_raw(&format!("i {name} {kind}"));
            let target = match kind {
                "same" => h,
                "duplicate" => duplicate(h),
                _ => open("CONIN$"),
            };
            let result = timed(move || call(target));
            let first = outcome(&result, BLOCKED);
            type_text(control, "k");
            let read_result = read_outcome(&read, DONE);
            let after = if first.starts_with("still") { outcome(&result, DONE) } else { "-".to_string() };
            fact(&format!("i_{name}_{kind}"), format!("read pending first: {pending}; call: {first}; read after a key: {read_result}; call after the key: {after}"));
            if read_result.starts_with("still") {
                // SAFETY: cancels this process's I/O on a valid handle, so that the stuck read does not take the next measurement's keys.
                unsafe { CancelIoEx(h.raw(), ptr::null()) };
                fact(&format!("i_{name}_{kind}_cancelled"), read_outcome(&read, DONE));
            }
            let _ = flush(control);
        }
    }
    // WriteConsoleInputW through the handle a raw read waits on.
    {
        let (h, read, _thread, pending) = pending_raw("i WriteConsoleInputW same");
        let result = timed(move || type_records(h, &keys_of("w")));
        let first = outcome(&result, BLOCKED);
        let read_result = read_outcome(&read, DONE);
        fact("i_WriteConsoleInputW_same", format!("read pending first: {pending}; call: {first}; read: {read_result}"));
        if read_result.starts_with("still") {
            type_text(control, "k");
            fact("i_WriteConsoleInputW_same_after_key", format!("read: {}; call: {}", read_outcome(&read, DONE), outcome(&result, DONE)));
        }
    }
    // The output while a read waits on the input.
    {
        let (_h, read, _thread, _pending) = pending_raw("i output");
        let info = timed(move || cursor(out));
        fact("i_output_GetConsoleScreenBufferInfo", outcome(&info, BLOCKED));
        let write = timed(move || new_line(out, "written while a read waits"));
        fact("i_output_WriteConsoleW", outcome(&write, BLOCKED));
        type_text(control, "k");
        let _ = read_outcome(&read, DONE);
    }

    // (ii-a) A raw read in progress, then a switch to a question's mode without echo: is the read still raw?
    {
        let (_h, read, _thread, pending) = pending_raw("ii-a");
        set_mode(control, hidden).unwrap();
        flush(control).unwrap();
        let (x0, y0) = cursor(out);
        type_text(control, "x");
        let first = read_outcome(&read, Duration::from_millis(700));
        let (x1, y1) = cursor(out);
        fact("ii_a_raw_read_then_hidden_prompt", format!("pending first: {pending}; after 'x': {first}; cursor {x0},{y0} -> {x1},{y1}; row {:?}", row(out, y1)));
        if first.starts_with("still") {
            type_text(control, "y\r");
            let second = read_outcome(&read, DONE);
            let (x2, y2) = cursor(out);
            fact("ii_a_after_enter", format!("{second}; cursor -> {x2},{y2}; row {:?}", row(out, y0)));
        }
    }

    // (ii-b) A line read with echo in progress, "hunt" typed into its line; then a question's mode without echo, and the buffer flushed;
    // then "er2" and Enter. What is shown, and what the read returns.
    {
        set_mode(control, shown).unwrap();
        flush(control).unwrap();
        new_line(out, "ii-b");
        let h = open("CONIN$");
        let (read, _thread) = read_on_a_thread(h, 64);
        std::thread::sleep(SETTLE);
        let (_, y0) = cursor(out);
        type_text(control, "hunt");
        std::thread::sleep(SETTLE);
        let typed_shown = row(out, y0);
        set_mode(control, hidden).unwrap();
        let flushed = flush(control);
        type_text(control, "er2\r");
        let result = read_outcome(&read, DONE);
        fact("ii_b_echo_line_then_hidden_and_flush", format!("row after 'hunt': {typed_shown:?}; flush {flushed:?}; read: {result}; row after 'er2' Enter: {:?}", row(out, y0)));
    }

    // Cancelling a read in progress: CancelIoEx on its handle, and CancelSynchronousIo on its thread; a raw read, and a line read with
    // "hunt" typed into its line (does the line go back to the buffer, or is it gone?).
    for how in ["CancelIoEx", "CancelSynchronousIo"] {
        for line in [false, true] {
            set_mode(control, if line { shown } else { raw }).unwrap();
            flush(control).unwrap();
            new_line(out, &format!("cancel {how} line={line}"));
            let h = open("CONIN$");
            let (read, thread) = read_on_a_thread(h, 64);
            std::thread::sleep(SETTLE);
            if line {
                type_text(control, "hunt");
                std::thread::sleep(SETTLE);
            }
            let cancelled = match how {
                // SAFETY: cancels this process's I/O on a valid handle.
                "CancelIoEx" => (unsafe { CancelIoEx(h.raw(), ptr::null()) }, last_error()),
                _ => {
                    use std::os::windows::io::AsRawHandle;
                    // SAFETY: cancels the synchronous I/O of a thread this test started, which is still running.
                    (unsafe { CancelSynchronousIo(thread.as_raw_handle() as HANDLE) }, last_error())
                }
            };
            let result = read_outcome(&read, DONE);
            let left = events(control);
            let mut again = "-".to_string();
            if line {
                let (read2, _t2) = read_on_a_thread(open("CONIN$"), 64);
                std::thread::sleep(SETTLE);
                type_text(control, "\r");
                again = read_outcome(&read2, DONE);
            }
            fact(&format!("cancel_{how}_line_{line}"), format!("call: {cancelled:?}; read: {result}; events left: {left:?}; next line read after Enter: {again}"));
            if result.starts_with("still") {
                type_text(control, "k\r");
                fact(&format!("cancel_{how}_line_{line}_after_key"), read_outcome(&read, DONE));
            }
        }
    }

    // Ctrl-C at a line read with processed input (a question): the key typed, then the event generated.
    // SAFETY: a handler with the right signature, for the rest of the process.
    fact("ctrl_handler_installed", unsafe { SetConsoleCtrlHandler(Some(record_event), TRUE) });
    {
        set_mode(control, hidden).unwrap();
        flush(control).unwrap();
        new_line(out, "ctrl-c line");
        let h = open("CONIN$");
        let (read, _thread) = read_on_a_thread(h, 64);
        std::thread::sleep(SETTLE);
        type_records(control, &key(VK_C, 0x03, LEFT_CTRL_PRESSED)).unwrap();
        let first = read_outcome(&read, BLOCKED);
        std::thread::sleep(SETTLE);
        fact("ctrl_c_key_at_line_read", format!("read: {first}; events: {:?}; events left in the buffer: {:?}", events_seen(), events(control)));
        if first.starts_with("still") {
            // SAFETY: CTRL_C_EVENT to every process on this console: this one, which has a handler.
            let generated = unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) };
            let second = read_outcome(&read, DONE);
            std::thread::sleep(SETTLE);
            fact("ctrl_c_generated_at_line_read", format!("generated {generated}; read: {second}; events: {:?}", events_seen()));
            if second.starts_with("still") {
                type_text(control, "\r");
                fact("ctrl_c_line_read_after_enter", read_outcome(&read, DONE));
            }
        }
    }
    {
        let (_h, read, _thread, _pending) = pending_raw("ctrl-c raw");
        type_records(control, &key(VK_C, 0x03, LEFT_CTRL_PRESSED)).unwrap();
        let first = read_outcome(&read, DONE);
        std::thread::sleep(SETTLE);
        fact("ctrl_c_key_at_raw_read", format!("read: {first}; events: {:?}", events_seen()));
    }

    // The console's history: is a line read without echo (a password) offered again by the up arrow at the next line read?
    for (label, first_mode, first_text) in [("hidden", hidden, "secret1\r"), ("shown", shown, "visible1\r")] {
        set_mode(control, first_mode).unwrap();
        flush(control).unwrap();
        new_line(out, &format!("history {label}"));
        let (read, _t) = read_on_a_thread(open("CONIN$"), 64);
        std::thread::sleep(SETTLE);
        type_text(control, first_text);
        let typed = read_outcome(&read, DONE);
        set_mode(control, shown).unwrap();
        new_line(out, &format!("history {label} recalled"));
        let (recall, _t) = read_on_a_thread(open("CONIN$"), 64);
        std::thread::sleep(SETTLE);
        let mut records = key(VK_UP, 0, 0).to_vec();
        records.extend(keys_of("\r"));
        type_records(control, &records).unwrap();
        fact(&format!("history_{label}"), format!("line: {typed}; up arrow and Enter at the next line read: {}", read_outcome(&recall, DONE)));
    }

    // The input handle is signalled while the buffer holds input.
    {
        set_mode(control, raw).unwrap();
        flush(control).unwrap();
        // SAFETY: a wait of zero only looks at the handle's state.
        let empty = unsafe { WaitForSingleObject(control.raw(), 0) };
        type_text(control, "z");
        // SAFETY: as above.
        let holding = unsafe { WaitForSingleObject(control.raw(), 0) };
        fact("wait_on_input", format!("empty buffer: {empty}; after a key: {holding}"));
        flush(control).unwrap();
    }

    // An arrow key in raw mode with virtual terminal input.
    {
        let (_h, read, _thread, _pending) = pending_raw("vt arrow");
        type_records(control, &key(VK_UP, 0, 0)).unwrap();
        fact("raw_vt_up_arrow", read_outcome(&read, DONE));
    }

    // Last: the console goes away (FreeConsole) under a raw read, then a read on the same handle.
    {
        let (h, read, _thread, _pending) = pending_raw("free");
        // SAFETY: detaches this process from its console; nothing of the console is used after this but `h`, to see how it fails.
        let freed = timed(|| unsafe { FreeConsole() });
        let freed = outcome(&freed, DONE);
        let first = read_outcome(&read, DONE);
        let (again, _t) = read_on_a_thread(h, 64);
        fact("free_console_under_a_read", format!("FreeConsole: {freed}; the read: {first}; a read after: {}", read_outcome(&again, DONE)));
    }
}

/// PROBE: the measurement's facts, shown by failing.
#[test]
fn a_read_in_progress_and_the_consoles_other_calls() {
    const NAME: &str = "cli::real_console_tests::a_read_in_progress_and_the_consoles_other_calls";
    if is_child() {
        measure();
        return;
    }
    // winbase.h: a console of its own for the child.
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let said = rerun_alone_with(NAME, |command| {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NEW_CONSOLE);
    });
    let facts: Vec<&str> = said.lines().filter(|line| line.starts_with("FACT ")).collect();
    panic!("PROBE, the facts:\n{}", facts.join("\n"));
}
