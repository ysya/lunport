//! The console `sshelter connect` runs in on Windows (own-ssh spec §7.3, the Windows bullet), served as `cli::terminal`: the modes, the
//! `Tty` and its `Restorer`, and the keys read without spanning a change of mode, are the platform-neutral part's (`console.rs`, tested on
//! every platform), and this file adds the console of this process (`StdConsole`), through windows-sys.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{ERROR_OPERATION_ABORTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, TRUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, GetConsoleCP, GetConsoleMode, GetConsoleOutputCP, GetConsoleScreenBufferInfo, GetStdHandle, ReadConsoleW,
    SetConsoleCP, SetConsoleMode, SetConsoleOutputCP, WriteConsoleInputW, CONSOLE_SCREEN_BUFFER_INFO, INPUT_RECORD, KEY_EVENT,
    KEY_EVENT_RECORD, KEY_EVENT_RECORD_0, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

use super::console::window_size;
#[cfg(test)]
pub(crate) use super::console::fake;
pub use super::console::{
    input_mode, output_mode, restore_on_panic, ConsoleApi, ConsoleKeys, KeysRead, Mode, Restorer, Setting, Settings, Tty,
};

/// The Enter key's virtual-key code (winuser.h, `VK_RETURN`).
const VK_RETURN: u16 = 0x0D;

/// Whether the console moves to the next line when a question's line read ends, whatever the read shows. It does: for the Enter of a
/// hidden answer too (measured, `real_console_tests`), and for the Enter with which the console layer ends a question's read when the
/// session ends under the question (`Tty::set_mode` throwing what was typed away), so the client does not start the next line itself
/// (`client.rs`). A Unix terminal does not (`terminal.rs`).
pub const QUESTION_READ_ENDS_ITS_LINE: bool = true;

/// The console of this process: its input buffer and its active screen buffer.
///
/// The input is standard input. A pipe or a file there is not a console, and `Tty::new` refuses it (`sshelter connect needs a
/// terminal.`, spec §7.3). Only a process that has no standard input at all (a GUI program can start without one) has the console's
/// input buffer opened by name (`CONIN$`). The output is standard output when that is the console's screen buffer, and the active
/// screen buffer opened by name (`CONOUT$`) otherwise (standard output redirected, or none): the output's mode and the window's size
/// are the console's, wherever the output goes.
pub struct StdConsole {
    input: Buffer,
    output: Buffer,
}

/// One of the console's buffers.
enum Buffer {
    /// A standard handle of the process, looked up at each use as std's standard I/O does; not closed here.
    Standard(STD_HANDLE),
    /// A buffer opened by name, closed with the `StdConsole`.
    Opened(OwnedHandle),
}

impl Buffer {
    fn handle(&self) -> HANDLE {
        match self {
            // SAFETY: GetStdHandle only reads this process's standard handle (null or INVALID_HANDLE_VALUE when there is none, which the
            // console calls then refuse).
            Buffer::Standard(which) => unsafe { GetStdHandle(*which) },
            Buffer::Opened(handle) => handle.as_raw_handle() as HANDLE,
        }
    }
}

impl StdConsole {
    pub fn new() -> StdConsole {
        let input = match standard(STD_INPUT_HANDLE) {
            Some(_) => Buffer::Standard(STD_INPUT_HANDLE),
            None => open("CONIN$").map_or(Buffer::Standard(STD_INPUT_HANDLE), Buffer::Opened),
        };
        let output = match standard(STD_OUTPUT_HANDLE) {
            Some(handle) if console_mode(handle).is_ok() => Buffer::Standard(STD_OUTPUT_HANDLE),
            _ => open("CONOUT$").map_or(Buffer::Standard(STD_OUTPUT_HANDLE), Buffer::Opened),
        };
        StdConsole { input, output }
    }

    /// The console's input buffer, which the keys are read from (`ReadConsoleW`).
    pub fn input(&self) -> HANDLE {
        self.input.handle()
    }

    /// The console's screen buffer.
    pub fn output(&self) -> HANDLE {
        self.output.handle()
    }

    /// The console of this process through its buffers opened by name (`CONIN$`, `CONOUT$`), whatever the standard handles are: a test
    /// in a process with a console of its own, whose standard handles are the pipes of the process that started it.
    #[cfg(test)]
    pub(crate) fn opened() -> io::Result<StdConsole> {
        Ok(StdConsole { input: Buffer::Opened(open("CONIN$")?), output: Buffer::Opened(open("CONOUT$")?) })
    }
}

impl ConsoleApi for StdConsole {
    fn get(&self, setting: Setting) -> io::Result<u32> {
        match setting {
            Setting::InputMode => console_mode(self.input()).map_err(|error| io::Error::other(format!("standard input is not a console ({error})"))),
            Setting::OutputMode => console_mode(self.output()),
            // SAFETY: GetConsoleCP takes nothing and reads the input code page of the console this process is attached to.
            Setting::InputCodePage => code_page(unsafe { GetConsoleCP() }),
            // SAFETY: GetConsoleOutputCP takes nothing and reads the output code page of the console this process is attached to.
            Setting::OutputCodePage => code_page(unsafe { GetConsoleOutputCP() }),
        }
    }

    fn set(&self, setting: Setting, value: u32) -> io::Result<()> {
        // SAFETY: plain values for this process's console; a handle that is not a console buffer makes the call fail, nothing more.
        done(unsafe {
            match setting {
                Setting::InputMode => SetConsoleMode(self.input(), value),
                Setting::OutputMode => SetConsoleMode(self.output(), value),
                Setting::InputCodePage => SetConsoleCP(value),
                Setting::OutputCodePage => SetConsoleOutputCP(value),
            }
        })
    }

    fn flush_input(&self) -> io::Result<()> {
        // SAFETY: as in `set`; it only discards what the input buffer holds.
        done(unsafe { FlushConsoleInputBuffer(self.input()) })
    }

    fn size(&self) -> Option<(u16, u16)> {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        // SAFETY: `info` is plain data that GetConsoleScreenBufferInfo fills in on success.
        if unsafe { GetConsoleScreenBufferInfo(self.output(), &mut info) } == 0 {
            return None;
        }
        let window = info.srWindow;
        window_size(window.Left, window.Top, window.Right, window.Bottom)
    }

    /// A read that gives no character gives nothing, not the end: ReadConsoleW succeeds with no characters, ERROR_OPERATION_ABORTED left
    /// as the last error, when a read is cancelled (measured, `real_console_tests`), and so, CPython's console reader expects, when Ctrl-C
    /// pressed on the keyboard ends a line read (not measured: a Ctrl-C written into the input buffer is a character; the manual
    /// checklist has the keyboard's). A failure with that error, and a count past the buffer (CPython's reader guards against both),
    /// give nothing too: neither is the console gone.
    fn read(&self, buf: &mut [u16]) -> io::Result<usize> {
        let length = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut read = 0u32;
        // SAFETY: `buf` holds `length` UTF-16 units, at most what ReadConsoleW writes; `read` is a u32 it writes; no read control.
        if let Err(error) = done(unsafe { ReadConsoleW(self.input(), buf.as_mut_ptr().cast(), length, &mut read, ptr::null()) }) {
            if error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
                return Ok(0);
            }
            return Err(error);
        }
        let read = read as usize;
        Ok(if read > buf.len() { 0 } else { read })
    }

    /// The Enter key pressed (a key-down record, as a keyboard's is first), which ends a line read and a raw one.
    fn wake(&self) -> io::Result<()> {
        let mut enter = INPUT_RECORD { EventType: KEY_EVENT as u16, ..Default::default() };
        enter.Event.KeyEvent = KEY_EVENT_RECORD {
            bKeyDown: TRUE,
            wRepeatCount: 1,
            wVirtualKeyCode: VK_RETURN,
            wVirtualScanCode: 0,
            uChar: KEY_EVENT_RECORD_0 { UnicodeChar: u16::from(b'\r') },
            dwControlKeyState: 0,
        };
        let mut written = 0u32;
        // SAFETY: one record, valid for the call; `written` is a u32 the call writes.
        done(unsafe { WriteConsoleInputW(self.input(), &enter, 1, &mut written) })
    }
}

/// The standard handle `which`, when the process has one.
fn standard(which: STD_HANDLE) -> Option<HANDLE> {
    // SAFETY: as in `Buffer::handle`.
    let handle = unsafe { GetStdHandle(which) };
    (!handle.is_null() && handle != INVALID_HANDLE_VALUE).then_some(handle)
}

/// The mode of the console buffer `handle`; an error when it is not a console buffer.
fn console_mode(handle: HANDLE) -> io::Result<u32> {
    let mut mode = 0;
    // SAFETY: `mode` is a u32 that GetConsoleMode writes on success; a handle that is not a console buffer makes it fail, nothing more.
    done(unsafe { GetConsoleMode(handle, &mut mode) })?;
    Ok(mode)
}

/// Opens the console buffer `name` (`CONIN$`, `CONOUT$`) for reading and writing, shared, as CreateFileW's documentation says for
/// consoles.
fn open(name: &str) -> io::Result<OwnedHandle> {
    let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; no security attributes, no template.
    let handle = unsafe {
        CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, ptr::null(), OPEN_EXISTING, 0, ptr::null_mut())
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle CreateFileW has just opened and nothing else owns; CloseHandle closes it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

/// A code page from GetConsoleCP or GetConsoleOutputCP, which return 0 when they fail.
fn code_page(value: u32) -> io::Result<u32> {
    if value == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// The result of a console call that says whether it succeeded.
fn done(succeeded: BOOL) -> io::Result<()> {
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
    use windows_sys::Win32::System::Console as win32;

    use super::super::console;
    use super::*;

    /// The flags the platform-neutral part spells out as numbers are Windows' own.
    #[test]
    fn the_console_flags_are_windows_own() {
        let flags = [
            ("ENABLE_PROCESSED_INPUT", console::ENABLE_PROCESSED_INPUT, win32::ENABLE_PROCESSED_INPUT),
            ("ENABLE_LINE_INPUT", console::ENABLE_LINE_INPUT, win32::ENABLE_LINE_INPUT),
            ("ENABLE_ECHO_INPUT", console::ENABLE_ECHO_INPUT, win32::ENABLE_ECHO_INPUT),
            ("ENABLE_VIRTUAL_TERMINAL_INPUT", console::ENABLE_VIRTUAL_TERMINAL_INPUT, win32::ENABLE_VIRTUAL_TERMINAL_INPUT),
            ("ENABLE_PROCESSED_OUTPUT", console::ENABLE_PROCESSED_OUTPUT, win32::ENABLE_PROCESSED_OUTPUT),
            ("ENABLE_VIRTUAL_TERMINAL_PROCESSING", console::ENABLE_VIRTUAL_TERMINAL_PROCESSING, win32::ENABLE_VIRTUAL_TERMINAL_PROCESSING),
            ("DISABLE_NEWLINE_AUTO_RETURN", console::DISABLE_NEWLINE_AUTO_RETURN, win32::DISABLE_NEWLINE_AUTO_RETURN),
            ("ENABLE_WINDOW_INPUT", fake::ENABLE_WINDOW_INPUT, win32::ENABLE_WINDOW_INPUT),
            ("ENABLE_MOUSE_INPUT", fake::ENABLE_MOUSE_INPUT, win32::ENABLE_MOUSE_INPUT),
            ("ENABLE_INSERT_MODE", fake::ENABLE_INSERT_MODE, win32::ENABLE_INSERT_MODE),
            ("ENABLE_QUICK_EDIT_MODE", fake::ENABLE_QUICK_EDIT_MODE, win32::ENABLE_QUICK_EDIT_MODE),
            ("ENABLE_EXTENDED_FLAGS", fake::ENABLE_EXTENDED_FLAGS, win32::ENABLE_EXTENDED_FLAGS),
            ("ENABLE_AUTO_POSITION", fake::ENABLE_AUTO_POSITION, win32::ENABLE_AUTO_POSITION),
            ("ENABLE_WRAP_AT_EOL_OUTPUT", fake::ENABLE_WRAP_AT_EOL_OUTPUT, win32::ENABLE_WRAP_AT_EOL_OUTPUT),
            ("ENABLE_LVB_GRID_WORLDWIDE", fake::ENABLE_LVB_GRID_WORLDWIDE, win32::ENABLE_LVB_GRID_WORLDWIDE),
        ];
        for (name, ours, windows) in flags {
            assert_eq!(ours, windows, "{name}");
        }
    }

    /// A console refuses a mode flag it does not know with ERROR_INVALID_PARAMETER (Microsoft's sign of an older console), and std
    /// reads that as `InvalidInput`: the take-over's `Unsupported` (no virtual terminal sequences) and raw mode's fallback without
    /// xterm's line endings go by it.
    #[test]
    fn a_refused_mode_flag_reads_as_invalid_input() {
        assert_eq!(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32).kind(), io::ErrorKind::InvalidInput);
    }

    /// Spec §7.3: standard input that is not a console is refused at the start (the CLI then says `sshelter connect needs a
    /// terminal.`), with a clear error, before anything about the console is changed. First a pipe of the test's own as the input,
    /// whatever this process's standard input is; then this process's own console, when its standard input is not a console either.
    /// On CI (a job's standard input is a pipe) that second half must run.
    #[test]
    fn a_real_console_handle_is_refused_when_input_is_a_pipe() {
        let (reader, _writer) = std::io::pipe().unwrap();
        let piped = StdConsole { input: Buffer::Opened(reader.into()), output: Buffer::Standard(STD_OUTPUT_HANDLE) };
        let refused = Tty::new(Arc::new(piped)).err().expect("a pipe is not a console");
        assert!(refused.to_string().starts_with("standard input is not a console ("), "{refused}");

        match standard(STD_INPUT_HANDLE) {
            Some(input) if console_mode(input).is_err() => {
                let refused = Tty::new(Arc::new(StdConsole::new())).err().expect("this process's standard input is not a console");
                assert!(refused.to_string().starts_with("standard input is not a console ("), "{refused}");
            }
            input if std::env::var_os("CI").is_some() => {
                panic!("on CI standard input is a pipe, and here it is {}", if input.is_some() { "a console" } else { "missing" })
            }
            // A run by hand in a console window, or a process without a standard input: nothing there to refuse.
            _ => eprintln!("this process's standard input is a console, or missing: only the test's own pipe was refused"),
        }
    }
}
