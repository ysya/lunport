//! Helpers for child processes that run behind the desktop UI.
//!
//! A GUI-subsystem process has no console on Windows. Starting a console
//! program from it without `CREATE_NO_WINDOW` makes Windows create a transient
//! Command Prompt window, even when stdout/stderr are piped. Commands launched
//! intentionally *inside a terminal* must not use this helper.

use std::ffi::OsStr;
use std::process::Command;

/// Build a background command that never creates a console window on Windows.
pub fn background_command<S: AsRef<OsStr>>(program: S) -> Command {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        let mut command = Command::new(program);
        // WinBase.h: CREATE_NO_WINDOW. Keep this local so hiding background
        // processes does not require a Windows-only runtime dependency.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }

    #[cfg(not(target_os = "windows"))]
    {
        Command::new(program)
    }
}
