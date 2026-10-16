//! `sshelter-cli.exe`: the console program Windows terminals run to reach Lunport (own-ssh spec §7.3, §7.4).
//!
//! Release `sshelter.exe` is a GUI program (`windows_subsystem = "windows"`): a shell does not wait for it, and a Windows Terminal tab
//! gives it no console. The helper is a console program, so the terminal gives it a console and waits for it. It runs the
//! `sshelter.exe` in its own directory with exactly its own arguments and its standard input, output and error, waits for it, and leaves
//! with its exit code; `sshelter.exe connect` attaches to the helper's console. Ctrl-C and Ctrl-Break go to every program on a console
//! and are `sshelter.exe`'s to handle, so the helper ignores them and keeps waiting. Before it starts `sshelter.exe` the helper reads the
//! console's four settings that `sshelter.exe connect` changes (the modes of the buffers behind its standard input and output, both code
//! pages), and it puts them back once `sshelter.exe` has ended: `sshelter.exe` puts them back on every way out it has, but one ended from
//! outside has none (the NSIS installer ends every `sshelter.exe` of the user at an install, an in-app update and an uninstall).
//!
//! Std only, no dependencies. It builds everywhere, so its tests run everywhere; outside Windows it only says that it is for Windows.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// Lunport's own executable, which the helper runs from its own directory.
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

/// One of the four settings of the console that `sshelter.exe connect` changes while it runs, and puts back on every way out it has
/// (own-ssh spec §7.3). A `sshelter.exe` ended from outside has no way out: the NSIS installer ends every `sshelter.exe` of the user, a
/// session's too, at each install, in-app update and uninstall. So the helper keeps the four as well (`keeping_the_console`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    /// The mode of the console's input buffer, through the helper's standard input (`GetConsoleMode`, `SetConsoleMode`).
    InputMode,
    /// The mode of the console's screen buffer, through the helper's standard output.
    OutputMode,
    /// The console's input code page (`GetConsoleCP`, `SetConsoleCP`).
    InputCodePage,
    /// The console's output code page (`GetConsoleOutputCP`, `SetConsoleOutputCP`).
    OutputCodePage,
}

impl Setting {
    /// All four, in the order they are put back: the input's mode first, which the shell needs most (echo, line editing), as
    /// `sshelter.exe` puts them back.
    pub const ALL: [Setting; 4] = [Setting::InputMode, Setting::OutputMode, Setting::InputCodePage, Setting::OutputCodePage];
}

/// Reading and setting the four settings of a console: the helper's own on Windows, a fake in the tests.
pub trait ConsoleSettings {
    /// The value `setting` has now; an error when there is none to keep: the standard handle is not a console (a pipe, a file, none),
    /// or the process has no console.
    fn get(&self, setting: Setting) -> std::io::Result<u32>;
    /// Sets `setting` to `value`.
    fn set(&self, setting: Setting, value: u32) -> std::io::Result<()>;
}

/// Runs `child` (the relay to `sshelter.exe`) with `console`'s settings kept: each one that can be read is read before `child` starts and
/// put back once it has ended, whatever it ended with. Where `sshelter.exe` put the console back itself, the same settings are set again
/// and nothing changes; where it was ended from outside it put nothing back, and the shell gets its console as it was all the same. A
/// setting that cannot be read is left alone (a standard handle that is not a console is not the console's to set), and one that cannot
/// be put back does not stop the others.
pub fn keeping_the_console(console: &dyn ConsoleSettings, child: impl FnOnce() -> i32) -> i32 {
    let kept: Vec<(Setting, u32)> =
        Setting::ALL.into_iter().filter_map(|setting| console.get(setting).ok().map(|value| (setting, value))).collect();
    let code = child();
    for (setting, value) in kept {
        let _ = console.set(setting, value);
    }
    code
}

/// The helper with `args` (its arguments after its own name); returns its exit code. It finds `sshelter.exe` in its own directory, stops
/// Ctrl-C and Ctrl-Break from ending it (before the target starts, so at no moment can a Ctrl-C end the helper and leave `sshelter.exe`
/// running), and relays, keeping the console's settings for the shell (`keeping_the_console`). Without its handler it does not start: a
/// Ctrl-C would end it and give the terminal back to the shell while `sshelter.exe` still reads the console.
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
    keeping_the_console(&console::Standard, || relay(&target, args, stderr))
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
    use std::io;

    use super::{ConsoleSettings, Setting};

    /// A handle (winnt.h).
    type Handle = *mut std::ffi::c_void;

    /// The standard input and output handles (processenv.h: `(DWORD)-10`, `(DWORD)-11`).
    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;

    // From consoleapi.h, consoleapi2.h and processenv.h; std links kernel32 already. A handler routine is not inherited by the target,
    // unlike the flag that `SetConsoleCtrlHandler(NULL, TRUE)` sets: `sshelter.exe` gets its Ctrl-C.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(event: u32) -> i32>, add: i32) -> i32;
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(console: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(console: Handle, mode: u32) -> i32;
        fn GetConsoleCP() -> u32;
        fn SetConsoleCP(code_page: u32) -> i32;
        fn GetConsoleOutputCP() -> u32;
        fn SetConsoleOutputCP(code_page: u32) -> i32;
    }

    /// The helper's console: the buffers behind its standard input and output, which `sshelter.exe` inherits and changes (a mode belongs
    /// to the buffer, whichever handle sets it), and the console's code pages.
    pub struct Standard;

    impl ConsoleSettings for Standard {
        fn get(&self, setting: Setting) -> io::Result<u32> {
            match setting {
                Setting::InputMode => mode(STD_INPUT_HANDLE),
                Setting::OutputMode => mode(STD_OUTPUT_HANDLE),
                // SAFETY: GetConsoleCP takes nothing and reads the input code page of this process's console (0 when it has none).
                Setting::InputCodePage => code_page(unsafe { GetConsoleCP() }),
                // SAFETY: GetConsoleOutputCP takes nothing and reads the output code page of this process's console (0 when it has none).
                Setting::OutputCodePage => code_page(unsafe { GetConsoleOutputCP() }),
            }
        }

        fn set(&self, setting: Setting, value: u32) -> io::Result<()> {
            // SAFETY: GetStdHandle only reads this process's standard handle; the other calls take plain values for that handle and this
            // process's console, and a handle that is not a console buffer, or no console, makes them fail, nothing more.
            let done = unsafe {
                match setting {
                    Setting::InputMode => SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), value),
                    Setting::OutputMode => SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), value),
                    Setting::InputCodePage => SetConsoleCP(value),
                    Setting::OutputCodePage => SetConsoleOutputCP(value),
                }
            };
            if done == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// The mode of the console buffer behind the standard handle `which`; an error when that is not a console buffer (a pipe or a file),
    /// or there is no handle (null, or INVALID_HANDLE_VALUE: GetConsoleMode refuses both).
    fn mode(which: u32) -> io::Result<u32> {
        let mut mode = 0;
        // SAFETY: GetStdHandle only reads this process's standard handle; `mode` is a u32 that GetConsoleMode writes on success.
        if unsafe { GetConsoleMode(GetStdHandle(which), &mut mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(mode)
    }

    /// A code page as GetConsoleCP and GetConsoleOutputCP give it: 0 is a failure, which a process without a console gets.
    fn code_page(value: u32) -> io::Result<u32> {
        if value == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
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

    /// What the fake console was asked, in order, and what the child changed in between.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        Get(Setting),
        Set(Setting, u32),
        /// The child (`sshelter.exe`) set this, on the same console.
        ChildSet(Setting, u32),
    }

    /// A console in memory. A setting with no value cannot be read, and is not set either: the helper's standard handle there is not a
    /// console (a pipe, a file, none), or the process has no console at all. A set of a setting in `refused` fails.
    struct FakeConsole {
        values: std::cell::RefCell<[Option<u32>; 4]>,
        refused: Vec<Setting>,
        calls: std::cell::RefCell<Vec<Call>>,
    }

    impl FakeConsole {
        fn new(values: [Option<u32>; 4]) -> FakeConsole {
            FakeConsole { values: std::cell::RefCell::new(values), refused: Vec::new(), calls: std::cell::RefCell::new(Vec::new()) }
        }

        fn refusing(mut self, refused: &[Setting]) -> FakeConsole {
            self.refused = refused.to_vec();
            self
        }

        /// What the child does to the console: sets each setting that the console has to `values`.
        fn child_sets(&self, values: [u32; 4]) {
            for (setting, value) in Setting::ALL.into_iter().zip(values) {
                if let Some(now) = &mut self.values.borrow_mut()[index(setting)] {
                    *now = value;
                    self.calls.borrow_mut().push(Call::ChildSet(setting, value));
                }
            }
        }

        fn now(&self) -> [Option<u32>; 4] {
            *self.values.borrow()
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }

        /// The calls the helper made itself (not the child's).
        fn helper_calls(&self) -> Vec<Call> {
            self.calls().into_iter().filter(|call| !matches!(call, Call::ChildSet(..))).collect()
        }
    }

    fn index(setting: Setting) -> usize {
        Setting::ALL.iter().position(|each| *each == setting).unwrap()
    }

    impl ConsoleSettings for FakeConsole {
        fn get(&self, setting: Setting) -> std::io::Result<u32> {
            self.calls.borrow_mut().push(Call::Get(setting));
            self.values.borrow()[index(setting)].ok_or_else(|| std::io::Error::other("not a console"))
        }

        fn set(&self, setting: Setting, value: u32) -> std::io::Result<()> {
            self.calls.borrow_mut().push(Call::Set(setting, value));
            if self.refused.contains(&setting) {
                return Err(std::io::Error::other("refused"));
            }
            match &mut self.values.borrow_mut()[index(setting)] {
                Some(now) => {
                    *now = value;
                    Ok(())
                }
                None => Err(std::io::Error::other("not a console")),
            }
        }
    }

    /// A classic console as a new window has it: the input's usual mode (processed, line, echo, insert, quick edit, extended flags,
    /// auto position), the output's (processed, wrap at the end of a line), and the United States' OEM code page in and out.
    const START: [Option<u32>; 4] = [Some(0x01F7), Some(0x0003), Some(437), Some(437)];
    /// What `sshelter.exe connect` leaves the console in while a shell is open: raw input (no line input, echo or processed input; keys as
    /// virtual terminal sequences), virtual terminal output with xterm's line endings, and UTF-8 out. It leaves the input's code page as
    /// it was; another program could change that too.
    const RAW: [u32; 4] = [0x01F7 & !0x0007 | 0x0200, 0x0003 | 0x0004 | 0x0008, 65001, 65001];

    fn sets_of(values: [Option<u32>; 4]) -> Vec<Call> {
        Setting::ALL.into_iter().zip(values).filter_map(|(setting, value)| value.map(|value| Call::Set(setting, value))).collect()
    }

    /// The helper reads the four settings before `sshelter.exe` starts and puts each back once it has ended, the input's mode first, and
    /// whatever it ended with: its own exit (0, the usage's 2, a lost connection's 255), a signal's code (130), or a kill from outside,
    /// which gives `sshelter.exe` no way out of its own (the installer's; STATUS_CONTROL_C_EXIT too).
    #[test]
    fn the_console_is_put_back_after_the_child_whatever_it_ended_with() {
        for code in [0, 1, 2, 130, 255, 0xC000_013A_u32 as i32] {
            let console = FakeConsole::new(START);
            let ended = keeping_the_console(&console, || {
                console.child_sets(RAW);
                code
            });
            assert_eq!(ended, code, "the child's exit code is the helper's");
            assert_eq!(console.now(), START, "{code}: the console is back as it was");
            let mut expected: Vec<Call> = Setting::ALL.into_iter().map(Call::Get).collect();
            expected.extend(Setting::ALL.into_iter().zip(RAW).map(|(setting, value)| Call::ChildSet(setting, value)));
            expected.extend(sets_of(START));
            assert_eq!(console.calls(), expected, "{code}: read before the child, put back after it");
        }
    }

    /// A standard handle that is not a console (a pipe, a file, none) has no mode of the console's to keep: the helper sets nothing
    /// through it. A process with no console at all has nothing to keep.
    #[test]
    fn a_handle_that_is_not_a_console_is_left_alone() {
        let input_piped = [None, START[1], START[2], START[3]];
        let output_to_a_file = [START[0], None, START[2], START[3]];
        let no_console = [None; 4];
        for start in [input_piped, output_to_a_file, no_console] {
            let console = FakeConsole::new(start);
            assert_eq!(keeping_the_console(&console, || {
                console.child_sets(RAW);
                7
            }), 7);
            assert_eq!(console.now(), start, "{start:?}");
            let mut expected: Vec<Call> = Setting::ALL.into_iter().map(Call::Get).collect();
            expected.extend(sets_of(start));
            assert_eq!(console.helper_calls(), expected, "{start:?}: only what was read is set");
        }
    }

    /// A setting the console does not take back does not stop the others from being put back.
    #[test]
    fn a_setting_that_cannot_be_put_back_does_not_stop_the_others() {
        for refused in [&[Setting::InputMode][..], &[Setting::OutputMode, Setting::InputCodePage], &[Setting::OutputCodePage]] {
            let console = FakeConsole::new(START).refusing(refused);
            keeping_the_console(&console, || {
                console.child_sets(RAW);
                255
            });
            let expected: Vec<Call> = Setting::ALL.into_iter().map(Call::Get).chain(sets_of(START)).collect();
            assert_eq!(console.helper_calls(), expected, "{refused:?}: every setting is put back, in order");
            for (setting, value) in Setting::ALL.into_iter().zip(RAW) {
                let now = console.now()[index(setting)];
                let wanted = if refused.contains(&setting) { Some(value) } else { START[index(setting)] };
                assert_eq!(now, wanted, "{refused:?}: {setting:?}");
            }
        }
    }

    /// A `sshelter.exe` that put the console back itself, as every way out of it does: putting the same settings back changes nothing.
    #[test]
    fn a_console_the_child_put_back_itself_stays_as_it_is() {
        let console = FakeConsole::new(START);
        keeping_the_console(&console, || {
            console.child_sets(RAW);
            console.child_sets(START.map(Option::unwrap));
            0
        });
        assert_eq!(console.now(), START);
        assert_eq!(console.helper_calls(), Setting::ALL.into_iter().map(Call::Get).chain(sets_of(START)).collect::<Vec<_>>());
    }
}
