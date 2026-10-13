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
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, TRUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleMode, GetConsoleScreenBufferInfo,
    GetNumberOfConsoleInputEvents, ReadConsoleOutputCharacterW, ReadConsoleW, SetConsoleCtrlHandler, SetConsoleMode, WriteConsoleInputW,
    WriteConsoleW, CONSOLE_SCREEN_BUFFER_INFO, COORD, CTRL_C_EVENT, FOCUS_EVENT, FOCUS_EVENT_RECORD, INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD,
    KEY_EVENT_RECORD_0, LEFT_CTRL_PRESSED,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::IO::CancelIoEx;

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

/// The console of a child: its input buffer through a handle that never reads (`control`), its screen buffer, and its modes.
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
        let out = open("CONOUT$");
        let start = mode_of(control).expect("the child's console input");
        fact("start_input_mode", format!("{start:#06x}"));
        Console {
            control,
            out,
            raw: input_mode(start, Mode::Raw),
            hidden: input_mode(start, Mode::Prompt { echo: false }),
            shown: input_mode(start, Mode::Prompt { echo: true }),
        }
    }

    /// A read of `mode` waiting on a handle of its own, the input buffer empty when it started.
    fn pending(&self, mode: u32, label: &str) -> (H, mpsc::Receiver<Read>, std::thread::JoinHandle<()>) {
        set_mode(self.control, mode).unwrap();
        flush(self.control).unwrap();
        new_line(self.out, label);
        let h = open("CONIN$");
        let (read, thread) = read_on_a_thread(h, 64);
        std::thread::sleep(SETTLE);
        assert!(read.try_recv().is_err(), "{label}: the read waits");
        (h, read, thread)
    }

    /// The row the cursor is on.
    fn row(&self) -> String {
        row(self.out, cursor(self.out).1)
    }
}

/// One measurement, in a child with a console of its own (`scenario` names it).
fn measure(scenario: &str) {
    let console = Console::new();
    let (control, out) = (console.control, console.out);
    match scenario {
        // (i) The console's calls through the handle a line read waits on (a raw read was measured in round 1: none waited).
        "same_handle_under_a_line_read" => {
            let (h, read, _thread) = console.pending(console.shown, "same handle");
            let mode = timed(move || mode_of(h));
            fact("line_read_GetConsoleMode_same", outcome(&mode, BLOCKED));
            let hidden = console.hidden;
            let set = timed(move || set_mode(h, hidden));
            fact("line_read_SetConsoleMode_same", outcome(&set, BLOCKED));
            let flushed = timed(move || flush(h));
            fact("line_read_Flush_same", outcome(&flushed, BLOCKED));
            type_text(control, "ok\r");
            fact("line_read_then", read_outcome(&read, DONE));
        }
        // (ii) A raw read in progress when the mode changes to a question's without echo: what the next key does.
        "raw_read_spans_a_switch" => {
            let (_h, read, _thread) = console.pending(console.raw, "raw spans");
            set_mode(control, console.hidden).unwrap();
            flush(control).unwrap();
            let (x0, y0) = cursor(out);
            type_text(control, "x");
            let first = read_outcome(&read, Duration::from_millis(700));
            fact("raw_read_spans_a_switch", format!("after 'x': {first}; cursor {x0},{y0} -> {:?}; row {:?}", cursor(out), console.row()));
        }
        // (ii) A line read with echo in progress, "hunt" in its line; the mode changes to a question's without echo and the input is flushed;
        // then "er2" and Enter.
        "line_read_spans_a_switch" => {
            let (_h, read, _thread) = console.pending(console.shown, "line spans");
            type_text(control, "hunt");
            std::thread::sleep(SETTLE);
            let shown_before = console.row();
            set_mode(control, console.hidden).unwrap();
            let flushed = flush(control);
            type_text(control, "er2\r");
            let result = read_outcome(&read, DONE);
            fact("line_read_spans_a_switch", format!("row after 'hunt': {shown_before:?}; flush {flushed:?}; read: {result}; row after: {:?}", row(out, cursor(out).1 - 1)));
        }
        // Cancelling a read, and the read after it: does the cancelled read still take keys?
        "cancel_raw_then_read" | "cancel_line_then_read" => {
            let line = scenario == "cancel_line_then_read";
            let mode = if line { console.shown } else { console.raw };
            let (h, read, _thread) = console.pending(mode, scenario);
            if line {
                type_text(control, "hunt");
                std::thread::sleep(SETTLE);
            }
            // SAFETY: cancels this process's I/O on a valid handle.
            let cancelled = unsafe { CancelIoEx(h.raw(), ptr::null()) };
            fact("cancelled_read", format!("CancelIoEx {cancelled}; read: {}; events left {:?}", read_outcome(&read, DONE), events(control)));
            let (_h2, next, _thread2) = console.pending(mode, "next");
            type_text(control, if line { "a\r" } else { "a" });
            let first = read_outcome(&next, BLOCKED);
            fact("next_read_after_a_key", format!("{first}; events left {:?}", events(control)));
            if first.starts_with("still") {
                type_text(control, if line { "b\r" } else { "b" });
                fact("next_read_after_a_second_key", read_outcome(&next, DONE));
            }
        }
        // Waking a read with a key of the program's own: Enter for a line read ("hunt" typed into it), a key for a raw read; then the next
        // read takes the next key.
        "wake_line_with_enter" | "wake_raw_with_a_key" => {
            let line = scenario == "wake_line_with_enter";
            let mode = if line { console.shown } else { console.raw };
            let (_h, read, _thread) = console.pending(mode, scenario);
            if line {
                type_text(control, "hunt");
                std::thread::sleep(SETTLE);
            }
            let (_, y0) = cursor(out);
            type_records(control, &keys_of(if line { "\r" } else { "x" })).unwrap();
            fact("woken_read", format!("{}; rows {:?} / {:?}; cursor {:?}", read_outcome(&read, DONE), row(out, y0), row(out, y0 + 1), cursor(out)));
            let (_h2, next, _thread2) = console.pending(mode, "next");
            type_text(control, if line { "a\r" } else { "a" });
            fact("next_read", format!("{}; events left {:?}", read_outcome(&next, DONE), events(control)));
            // The same with echo off.
            if line {
                let (_h3, read, _thread3) = console.pending(console.hidden, "hidden wake");
                type_text(control, "pw");
                std::thread::sleep(SETTLE);
                let (x0, y0) = cursor(out);
                type_text(control, "\r");
                fact("woken_hidden_read", format!("{}; cursor {x0},{y0} -> {:?}; row {:?}", read_outcome(&read, DONE), cursor(out), row(out, y0)));
            }
        }
        // Ctrl-C at a line read with processed input (a question): typed, then generated.
        "ctrl_c_at_a_line_read" => {
            // SAFETY: a handler with the right signature, for the rest of the process.
            unsafe { SetConsoleCtrlHandler(Some(record_event), TRUE) };
            let (_h, read, _thread) = console.pending(console.hidden, "ctrl-c typed");
            type_records(control, &key(VK_C, 0x03, LEFT_CTRL_PRESSED)).unwrap();
            let first = read_outcome(&read, BLOCKED);
            std::thread::sleep(SETTLE);
            fact("ctrl_c_typed_at_a_line_read", format!("read: {first}; events: {:?}; events left {:?}", events_seen(), events(control)));
            if first.starts_with("still") {
                type_text(control, "\r");
                fact("ctrl_c_typed_then_enter", read_outcome(&read, DONE));
            }
            let (_h, read, _thread) = console.pending(console.hidden, "ctrl-c generated");
            // SAFETY: CTRL_C_EVENT to every process on this console: this one, which has a handler.
            let generated = unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) };
            let second = read_outcome(&read, DONE);
            std::thread::sleep(SETTLE);
            fact("ctrl_c_generated_at_a_line_read", format!("generated {generated}; read: {second}; events: {:?}", events_seen()));
            if second.starts_with("still") {
                type_text(control, "\r");
                fact("ctrl_c_generated_then_enter", read_outcome(&read, DONE));
            } else {
                let (_h, next, _thread) = console.pending(console.hidden, "after ctrl-c");
                type_text(control, "a\r");
                fact("read_after_ctrl_c", read_outcome(&next, DONE));
            }
            let (_h, read, _thread) = console.pending(console.raw, "ctrl-c raw");
            type_records(control, &key(VK_C, 0x03, LEFT_CTRL_PRESSED)).unwrap();
            let third = read_outcome(&read, DONE);
            std::thread::sleep(SETTLE);
            fact("ctrl_c_typed_at_a_raw_read", format!("read: {third}; events: {:?}", events_seen()));
        }
        // The console's history: is a line read without echo (a password) offered again by the up arrow at the next line read?
        "history" => {
            for (label, first_mode, first_text) in [("hidden", console.hidden, "secret1\r"), ("shown", console.shown, "visible1\r")] {
                let (_h, read, _thread) = console.pending(first_mode, label);
                type_text(control, first_text);
                let typed = read_outcome(&read, DONE);
                let (_h, recall, _thread) = console.pending(console.shown, "recalled");
                let mut records = key(VK_UP, 0, 0).to_vec();
                records.extend(keys_of("\r"));
                type_records(control, &records).unwrap();
                fact(&format!("history_{label}"), format!("line: {typed}; up arrow and Enter at the next line read: {}", read_outcome(&recall, DONE)));
            }
        }
        // The input handle is signalled while the buffer holds input; a record that is not a key signals it too.
        "wait_on_input" => {
            set_mode(control, console.raw).unwrap();
            flush(control).unwrap();
            // SAFETY: waits of zero only look at the handle's state.
            let state = || unsafe { WaitForSingleObject(control.raw(), 0) };
            let empty = state();
            type_text(control, "z");
            let holding = state();
            flush(control).unwrap();
            let flushed = state();
            let mut focus = INPUT_RECORD { EventType: FOCUS_EVENT as u16, ..Default::default() };
            focus.Event.FocusEvent = FOCUS_EVENT_RECORD { bSetFocus: TRUE };
            type_records(control, &[focus]).unwrap();
            let focused = state();
            let (read, _thread) = read_on_a_thread(open("CONIN$"), 64);
            let read_focus = read_outcome(&read, BLOCKED);
            fact("wait_on_input", format!("empty {empty}; after a key {holding}; flushed {flushed}; after a focus record {focused}; a raw read then: {read_focus}; events left {:?}", events(control)));
        }
        // Keys in raw mode with virtual terminal input: an arrow, Ctrl-Z, and a character outside the basic plane typed as its two halves.
        "raw_keys" => {
            let (_h, read, _thread) = console.pending(console.raw, "arrow");
            type_records(control, &key(VK_UP, 0, 0)).unwrap();
            fact("raw_up_arrow", read_outcome(&read, DONE));
            let (_h, read, _thread) = console.pending(console.raw, "pair");
            let mut halves = key(0, 0xD83D, 0).to_vec();
            halves.extend(key(0, 0xDD11, 0));
            type_records(control, &halves).unwrap();
            fact("raw_surrogate_pair", read_outcome(&read, DONE));
            let (_h, read, _thread) = console.pending(console.hidden, "ctrl-z line");
            let mut line = key(0x5A, 0x1A, LEFT_CTRL_PRESSED).to_vec();
            line.extend(keys_of("\r"));
            type_records(control, &line).unwrap();
            fact("line_ctrl_z_enter", read_outcome(&read, DONE));
        }
        // The console goes away (FreeConsole) under a raw read, then a read on the same handle.
        "free_console" => {
            let (h, read, _thread) = console.pending(console.raw, "free");
            // SAFETY: detaches this process from its console; nothing of the console is used after this but `h`, to see how it fails.
            let freed = timed(|| unsafe { FreeConsole() });
            let freed = outcome(&freed, DONE);
            let first = read_outcome(&read, DONE);
            let (again, _t) = read_on_a_thread(h, 64);
            fact("free_console_under_a_read", format!("FreeConsole: {freed}; the read: {first}; a read after: {}", read_outcome(&again, DONE)));
        }
        other => panic!("no scenario {other}"),
    }
}

/// The variable that names the measurement a child makes.
const SCENARIO: &str = "SSHELTER_TEST_CONSOLE_SCENARIO";

/// PROBE: the measurement's facts, shown by failing. Each scenario runs in a child of its own, with a console of its own: a read one
/// scenario leaves waiting cannot take the keys of the next.
#[test]
fn a_read_in_progress_and_the_consoles_other_calls() {
    const NAME: &str = "cli::real_console_tests::a_read_in_progress_and_the_consoles_other_calls";
    if is_child() {
        measure(&std::env::var(SCENARIO).expect("the scenario"));
        return;
    }
    // winbase.h: a console of its own for the child.
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let scenarios = [
        "same_handle_under_a_line_read",
        "raw_read_spans_a_switch",
        "line_read_spans_a_switch",
        "cancel_raw_then_read",
        "cancel_line_then_read",
        "wake_line_with_enter",
        "wake_raw_with_a_key",
        "ctrl_c_at_a_line_read",
        "history",
        "wait_on_input",
        "raw_keys",
        "free_console",
    ];
    let mut facts = Vec::new();
    for scenario in scenarios {
        let said = std::panic::catch_unwind(|| {
            rerun_alone_with(NAME, |command| {
                use std::os::windows::process::CommandExt;
                command.creation_flags(CREATE_NEW_CONSOLE).env(SCENARIO, scenario);
            })
        });
        match said {
            Ok(said) => facts.extend(said.lines().filter(|line| line.starts_with("FACT ")).map(|line| format!("[{scenario}] {line}"))),
            Err(panic) => facts.push(format!("[{scenario}] FAILED: {:?}", panic.downcast_ref::<String>().map(String::as_str).or(panic.downcast_ref::<&str>().copied()))),
        }
    }
    panic!("PROBE, the facts:\n{}", facts.join("\n"));
}
