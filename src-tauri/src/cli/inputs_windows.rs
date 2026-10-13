//! The Windows calls of `sshelter connect` beyond the console's modes (own-ssh spec §7.3, the Windows bullet): the console a release
//! build attaches to, the console's control events, and the console as the terminal's output. What these do, without the Windows calls,
//! is tested on every platform: the control events in `run::ControlEvents` and `console_inputs::control`, the output's whole characters
//! in `run::Output::console`.

use std::io::{self, Write};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle};
use std::ptr;
use std::sync::{Arc, Mutex, PoisonError};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{FALSE, HANDLE, INVALID_HANDLE_VALUE, TRUE};
use windows_sys::Win32::System::Console::{
    AttachConsole, GetConsoleMode, GetStdHandle, SetConsoleCtrlHandler, WriteConsoleW, ATTACH_PARENT_PROCESS, STD_HANDLE,
};

use super::run::{ControlEvents, Output};
use super::terminal::StdConsole;

/// Attaches this process to the console of the process that started it, when it has none: a release build is a GUI program, which
/// `sshelter-cli.exe` starts in its console (spec §7.3). A process that has a console already (a debug build is a console program) is
/// refused with ERROR_ACCESS_DENIED and keeps its own; one whose parent has none stays without, and the console check then says that
/// `sshelter connect` needs a terminal.
pub fn attach_console() {
    // SAFETY: no pointers; it attaches this process to its parent's console, or fails and changes nothing.
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
}

/// What the control handler does with the events, from `take_over_control_events` on.
static CONTROL: Mutex<Option<Arc<ControlEvents>>> = Mutex::new(None);

/// Takes the console's control events over (`SetConsoleCtrlHandler`): from now on Ctrl-C, Ctrl-Break and the console closed (log-off
/// and shut-down too) do what `events` says, instead of ending the process the default way, which would leave the console as the
/// program set it. Installed after the console was attached (attaching sets the process's handlers aside), and before the console is
/// changed.
pub fn take_over_control_events(events: ControlEvents) -> io::Result<()> {
    *CONTROL.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(events));
    // SAFETY: a handler routine of the right signature, which stays for the life of the process.
    if unsafe { SetConsoleCtrlHandler(Some(on_control_event), TRUE) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The handler routine. Windows runs it on a thread of its own, for each event.
unsafe extern "system" fn on_control_event(event: u32) -> BOOL {
    let events = CONTROL.lock().unwrap_or_else(PoisonError::into_inner).clone();
    match events {
        Some(events) if events.handle(event) => TRUE,
        _ => FALSE,
    }
}

/// The console's screen buffer as the terminal's output: UTF-8 in, as whole characters (`Output::console` holds back one cut at the end
/// of a piece), written as UTF-16 (`WriteConsoleW`), so that the console's output code page plays no part in what is shown.
pub struct ConsoleText(OwnedHandle);

impl Write for ConsoleText {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let text: Vec<u16> = String::from_utf8_lossy(bytes).encode_utf16().collect();
        let mut rest = &text[..];
        while !rest.is_empty() {
            let count = u32::try_from(rest.len()).unwrap_or(u32::MAX);
            let mut written = 0u32;
            // SAFETY: `rest` holds `count` UTF-16 units; `written` is a u32 the call writes; the reserved pointer is null.
            if unsafe { WriteConsoleW(self.0.as_raw_handle() as HANDLE, rest.as_ptr(), count, &mut written, ptr::null()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            rest = &rest[(written as usize).min(rest.len())..];
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Standard output or standard error (`which`) for the terminal's writer, on a handle of its own, as the Unix `own_writer` has it:
/// std's handle takes a lock while it writes, and a writer stuck on a console that takes nothing (a selection holds its output) would
/// hold it. The console's screen buffer gets UTF-16 (`ConsoleText`); a stream sent elsewhere (a file, a pipe) gets the bytes as they
/// are; a process without the stream writes to the console's screen buffer (`StdConsole::output`). Std's own handle only when no handle
/// of its own can be had.
pub fn own_output(which: STD_HANDLE, console: &StdConsole) -> Output {
    // SAFETY: GetStdHandle only reads this process's standard handle.
    let standard = unsafe { GetStdHandle(which) };
    let usable = |handle: HANDLE| !handle.is_null() && handle != INVALID_HANDLE_VALUE;
    let target = if usable(standard) { standard } else { console.output() };
    let owned = usable(target)
        .then(|| {
            // SAFETY: a handle of this process that stays open during the call (a standard handle, or the console's own).
            unsafe { BorrowedHandle::borrow_raw(target as _) }.try_clone_to_owned().ok()
        })
        .flatten();
    match owned {
        Some(handle) if is_console(&handle) => Output::console(ConsoleText(handle)),
        Some(handle) => Output::from(std::fs::File::from(handle)),
        None if which == windows_sys::Win32::System::Console::STD_ERROR_HANDLE => Output::from(io::stderr()),
        None => Output::from(io::stdout()),
    }
}

/// Whether `handle` is a console buffer.
fn is_console(handle: &OwnedHandle) -> bool {
    let mut mode = 0;
    // SAFETY: `mode` is a u32 GetConsoleMode writes; a handle that is not a console buffer makes it fail, nothing more.
    unsafe { GetConsoleMode(handle.as_raw_handle() as HANDLE, &mut mode) != FALSE }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::Console as win32;

    use crate::cli::console_inputs;

    /// The control events the platform-neutral part spells out as numbers are Windows' own.
    #[test]
    fn the_control_events_are_windows_own() {
        let events = [
            ("CTRL_C_EVENT", console_inputs::CTRL_C_EVENT, win32::CTRL_C_EVENT),
            ("CTRL_BREAK_EVENT", console_inputs::CTRL_BREAK_EVENT, win32::CTRL_BREAK_EVENT),
            ("CTRL_CLOSE_EVENT", console_inputs::CTRL_CLOSE_EVENT, win32::CTRL_CLOSE_EVENT),
            ("CTRL_LOGOFF_EVENT", console_inputs::CTRL_LOGOFF_EVENT, win32::CTRL_LOGOFF_EVENT),
            ("CTRL_SHUTDOWN_EVENT", console_inputs::CTRL_SHUTDOWN_EVENT, win32::CTRL_SHUTDOWN_EVENT),
        ];
        for (name, ours, windows) in events {
            assert_eq!(ours, windows, "{name}");
        }
    }
}
