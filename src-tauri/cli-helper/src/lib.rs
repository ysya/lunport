//! `sshelter-cli.exe`: the console program Windows terminals run to reach SSHelter (own-ssh spec §7.3, §7.4).
//!
//! Release `sshelter.exe` is a GUI program (`windows_subsystem = "windows"`): a shell does not wait for it, and a Windows Terminal tab
//! gives it no console. The helper is a console program, so the terminal gives it a console and waits for it. It runs the
//! `sshelter.exe` in its own directory with exactly its own arguments and its standard input, output and error, waits for it, and leaves
//! with its exit code; `sshelter.exe connect` attaches to the helper's console. Ctrl-C and Ctrl-Break go to every program on a console
//! and are `sshelter.exe`'s to handle, so the helper ignores them and keeps waiting.
//!
//! Std only, no dependencies. It builds everywhere, so its tests run everywhere; outside Windows it only says that it is for Windows.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// SSHelter's own executable, which the helper runs from its own directory.
pub const TARGET: &str = "sshelter.exe";

/// What the helper says outside Windows, where it has nothing to do.
pub const NOT_WINDOWS: &str = "sshelter-cli is for Windows; run sshelter connect instead.";

/// `sshelter.exe` in `dir`, or what the helper says when it is not there (`sshelter-cli: cannot find sshelter.exe in <dir>.`).
pub fn target_in(dir: &Path) -> Result<PathBuf, String> {
    let target = dir.join(TARGET);
    if target.is_file() {
        Ok(target)
    } else {
        Err(format!("sshelter-cli: cannot find {TARGET} in {}.", dir.display()))
    }
}

/// Runs `target` with exactly `args` (no shell: each one reaches it as it is) and the helper's standard input, output and error, waits
/// for it, and returns its exit code. A target that cannot be started is said on `stderr`, and 1.
#[allow(clippy::disallowed_methods)] // src-tauri/clippy.toml is about the app's spawns (crate::process); the helper has only this one.
pub fn relay(target: &Path, args: &[OsString], stderr: &mut dyn Write) -> i32 {
    match Command::new(target).args(args).status() {
        Ok(status) => exit_code(status),
        Err(error) => {
            let _ = writeln!(stderr, "sshelter-cli: cannot start {}: {error}.", target.display());
            1
        }
    }
}

/// The target's exit code. A Windows program always has one (all 32 bits of it come back); elsewhere, where only the tests relay, a
/// program ended by a signal has none: 1.
fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

/// The console control events the helper ignores (wincon.h): the ones `sshelter.exe` handles.
const CTRL_C_EVENT: u32 = 0;
const CTRL_BREAK_EVENT: u32 = 1;

/// Whether the helper's console control handler takes `event` (and does nothing with it): Ctrl-C and Ctrl-Break. Closing the console,
/// logging off and shutting down go on to the default handler, which ends the helper as it ends every program on the console.
pub fn ignores(event: u32) -> bool {
    event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT
}

/// The helper with `args` (its arguments after its own name); returns its exit code. It finds `sshelter.exe` in its own directory, stops
/// Ctrl-C and Ctrl-Break from ending it (before the target starts, so at no moment can a Ctrl-C end the helper and leave `sshelter.exe`
/// running), and relays. Without its handler it does not start: a Ctrl-C would end it and give the terminal back to the shell while
/// `sshelter.exe` still reads the console.
#[cfg(windows)]
pub fn run(args: &[OsString], stderr: &mut dyn Write) -> i32 {
    let dir = match own_directory() {
        Ok(dir) => dir,
        Err(error) => {
            let _ = writeln!(stderr, "sshelter-cli: cannot find its own directory: {error}.");
            return 1;
        }
    };
    let target = match target_in(&dir) {
        Ok(target) => target,
        Err(sentence) => {
            let _ = writeln!(stderr, "{sentence}");
            return 1;
        }
    };
    if let Err(error) = console::ignore_ctrl_c_and_break() {
        let _ = writeln!(stderr, "sshelter-cli: cannot ignore Ctrl-C and Ctrl-Break: {error}.");
        return 1;
    }
    relay(&target, args, stderr)
}

/// Outside Windows: there is no `sshelter.exe` to run (`sshelter connect` is used directly).
#[cfg(not(windows))]
pub fn run(_args: &[OsString], stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(stderr, "{NOT_WINDOWS}");
    1
}

/// The directory of the helper's own executable.
#[cfg(windows)]
fn own_directory() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent().map(Path::to_path_buf).ok_or_else(|| std::io::Error::other(format!("{} has no directory", exe.display())))
}

#[cfg(windows)]
mod console {
    // From consoleapi.h; std links kernel32 already. A handler routine is not inherited by the target, unlike the flag that
    // `SetConsoleCtrlHandler(NULL, TRUE)` sets: `sshelter.exe` gets its Ctrl-C.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(event: u32) -> i32>, add: i32) -> i32;
    }

    /// The handler: TRUE (handled, nothing more happens to the helper) for Ctrl-C and Ctrl-Break, FALSE (the next handler, finally the
    /// default one) for the rest.
    unsafe extern "system" fn handler(event: u32) -> i32 {
        i32::from(super::ignores(event))
    }

    pub fn ignore_ctrl_c_and_break() -> std::io::Result<()> {
        // SAFETY: `handler` has the PHANDLER_ROUTINE signature and lives as long as the process; it only reads its argument.
        if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new empty directory under the system's temporary directory, removed with everything in it when dropped (the helper has no
    /// dependencies, so no tempfile).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let dir = std::env::temp_dir().join(format!("sshelter-cli-unit-{}-{name}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn without_sshelter_exe_beside_it_the_helper_says_where_it_looked() {
        let scratch = Scratch::new("missing");
        let sentence = format!("sshelter-cli: cannot find sshelter.exe in {}.", scratch.0.display());
        assert_eq!(target_in(&scratch.0), Err(sentence.clone()));
        // A directory by that name is not the program either.
        std::fs::create_dir(scratch.0.join("sshelter.exe")).unwrap();
        assert_eq!(target_in(&scratch.0), Err(sentence));
    }

    #[test]
    fn the_sshelter_exe_beside_it_is_what_the_helper_runs() {
        let scratch = Scratch::new("present");
        std::fs::write(scratch.0.join("sshelter.exe"), b"").unwrap();
        assert_eq!(target_in(&scratch.0), Ok(scratch.0.join("sshelter.exe")));
    }

    /// A target that cannot be started at all: the helper says so and exits 1.
    #[test]
    fn a_target_that_cannot_start_is_reported_with_1() {
        let scratch = Scratch::new("unstartable");
        let missing = scratch.0.join("sshelter.exe");
        let mut said = Vec::new();
        assert_eq!(relay(&missing, &[OsString::from("connect")], &mut said), 1);
        let said = String::from_utf8(said).unwrap();
        assert!(said.starts_with(&format!("sshelter-cli: cannot start {}: ", missing.display())), "{said:?}");
        assert!(said.ends_with(".\n"), "{said:?}");
    }

    /// Ctrl-C and Ctrl-Break are `sshelter.exe`'s (the console sends them to every program on it): the helper handles them by doing nothing.
    /// Closing the console, logging off and shutting down go on to the default handler, which ends the helper as it ends everything else.
    #[test]
    fn the_helper_ignores_ctrl_c_and_ctrl_break_and_nothing_else() {
        // CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT (wincon.h).
        assert!(ignores(0));
        assert!(ignores(1));
        for event in [2, 5, 6] {
            assert!(!ignores(event), "{event}");
        }
    }

    /// Outside Windows the helper has nothing to run: it says so, and 1.
    #[cfg(not(windows))]
    #[test]
    fn outside_windows_the_helper_only_says_it_is_for_windows() {
        let mut said = Vec::new();
        assert_eq!(run(&[OsString::from("connect"), OsString::from("web")], &mut said), 1);
        assert_eq!(String::from_utf8(said).unwrap(), format!("{NOT_WINDOWS}\n"));
    }
}
