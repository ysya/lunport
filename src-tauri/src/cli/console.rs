//! The console `sshelter connect` runs in on Windows (own-ssh spec §7.3, the Windows bullet), apart from the Windows calls: the modes
//! the console is set to, and the `Tty` and `Restorer` that set them and put the console back. On Windows `terminal_windows.rs` adds
//! the real console and serves this as `cli::terminal`, with the surface the Unix `terminal.rs` has, so that the loop (`run.rs`) uses
//! either. Compiled on Windows and in the tests of every platform: the logic is tested against a fake console on macOS and Linux too.
//!
//! A console has four settings the program changes: the input's mode, the output's mode, and the input's and the output's code page.
//! All four are read at the start, and nothing is changed until the console is taken over (`Tty::take_over`, once every way out can
//! put it back): a program ended the default way before that, by Ctrl-C while SSHelter starts, leaves the console as it was. The
//! take-over sets the output to take virtual terminal sequences, and UTF-8. Each `Mode` then sets the input's mode and the output's,
//! always from the modes of the start: raw mode gives the output xterm's line endings (a line feed that does not return the carriage),
//! as OpenSSH's raw mode turns a Unix terminal's `OPOST` off; the other modes keep the line endings of the start, so the CLI's own lines
//! start at the left margin, as `ONLCR` makes them on Unix. Once the console was taken over every way out puts the four back as they
//! were: the end of the program, a dropped `Tty`, a panic (`restore_on_panic`), and the watchdog that ends a program whose loop does
//! not (`Restorer::hold_restored`). Windows has no Ctrl-Z stop, so nothing is suspended and resumed as on Unix.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once, PoisonError, TryLockError};
use std::time::{Duration, Instant};

// The console mode flags this layer sets or clears (wincon.h), as plain numbers so that it builds everywhere; on Windows they are
// pinned against windows-sys (`terminal_windows.rs`).

/// Input: Ctrl-C is a signal, and the console handles the other control keys (in a line, backspace and Enter too).
pub const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
/// Input: a read returns a whole line, which the console edits.
pub const ENABLE_LINE_INPUT: u32 = 0x0002;
/// Input: what is typed in a line is shown.
pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
/// Input: keys arrive as virtual terminal sequences (arrows, function keys, Ctrl and Alt with a key).
pub const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
/// Output: control characters (backspace, tab, carriage return, line feed) are acted on; virtual terminal sequences need it.
pub const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
/// Output: virtual terminal sequences are acted on (colours, cursor moves, the alternate screen).
pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
/// Output: line endings as xterm has them (spec §7.3): a line feed does not return the carriage, as the flag's name says, and a
/// character in a line's last column waits there for the next one, as its documentation says. Raw mode only, on a console that has it.
pub const DISABLE_NEWLINE_AUTO_RETURN: u32 = 0x0008;
/// The UTF-8 code page.
pub const CP_UTF8: u32 = 65001;

/// What the console is set to: the input's mode, and the output's line endings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The input as it was when the program started, and the output's line endings too.
    Cooked,
    /// Every key goes to the shell as it is pressed, as virtual terminal sequences: no line editing, no echo, and Ctrl-C is a key. The
    /// shell's output has xterm's line endings.
    Raw,
    /// A question: the console edits the line and Ctrl-C is a signal; what is typed is shown only when `echo`.
    Prompt { echo: bool },
}

/// One of the four settings of a console the program changes, and puts back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Setting {
    /// The mode of the console's input buffer (`GetConsoleMode` and `SetConsoleMode` on the input).
    InputMode,
    /// The mode of the console's screen buffer (`GetConsoleMode` and `SetConsoleMode` on the output).
    OutputMode,
    /// `GetConsoleCP` and `SetConsoleCP`.
    InputCodePage,
    /// `GetConsoleOutputCP` and `SetConsoleOutputCP`.
    OutputCodePage,
}

impl Setting {
    /// All four, in the order they are put back: the input's mode first, which the shell needs most (echo, line editing).
    pub const ALL: [Setting; 4] = [Setting::InputMode, Setting::OutputMode, Setting::InputCodePage, Setting::OutputCodePage];
}

/// A value for each of the four settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub input_mode: u32,
    pub output_mode: u32,
    pub input_code_page: u32,
    pub output_code_page: u32,
}

impl Settings {
    /// The value of `setting`.
    pub fn of(&self, setting: Setting) -> u32 {
        match setting {
            Setting::InputMode => self.input_mode,
            Setting::OutputMode => self.output_mode,
            Setting::InputCodePage => self.input_code_page,
            Setting::OutputCodePage => self.output_code_page,
        }
    }
}

/// Reading and setting a console's four settings, throwing away what was typed, and reading the window's size. The real one is the
/// console of this process (`StdConsole`, on Windows); tests use a fake.
pub trait ConsoleApi: Send + Sync {
    /// The value `setting` has now.
    fn get(&self, setting: Setting) -> io::Result<u32>;
    /// Sets `setting` to `value`, at once.
    fn set(&self, setting: Setting, value: u32) -> io::Result<()>;
    /// Throws away what was typed and not read yet (`FlushConsoleInputBuffer`).
    fn flush_input(&self) -> io::Result<()>;
    /// Columns and rows of the window; `None` when they cannot be read.
    fn size(&self) -> Option<(u16, u16)>;
}

/// The input's mode for `mode`, from the input's mode the console had at the start (`original`), never from the mode it has now: a
/// mode is the same value whatever was set before it, and `Cooked` is the start exactly.
pub fn input_mode(original: u32, mode: Mode) -> u32 {
    match mode {
        Mode::Cooked => original,
        // No line input, no echo, no processed input (Ctrl-C is a key), virtual terminal input; every other flag as at the start:
        // mouse, insert mode, quick edit and `ENABLE_EXTENDED_FLAGS` (whether the console takes those two from the value at all),
        // window input.
        Mode::Raw => (original & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT,
        Mode::Prompt { echo } => {
            let line = (original | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & !ENABLE_VIRTUAL_TERMINAL_INPUT;
            if echo {
                line | ENABLE_ECHO_INPUT
            } else {
                line & !ENABLE_ECHO_INPUT
            }
        }
    }
}

/// The output's mode for `mode`, from the output's mode the console had at the start (`original`), never from the mode it has now:
/// virtual terminal sequences (with the processing they need) in every mode, and xterm's line endings in raw mode. Every other flag as
/// at the start, the line endings of the start too outside raw mode.
pub fn output_mode(original: u32, mode: Mode) -> u32 {
    let terminal = original | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    match mode {
        Mode::Raw => terminal | DISABLE_NEWLINE_AUTO_RETURN,
        Mode::Cooked | Mode::Prompt { .. } => terminal,
    }
}

/// The columns and rows of a console window whose edges, in cells of its screen buffer, are `left`, `top`, `right` and `bottom`, both
/// ends included (`srWindow` from `GetConsoleScreenBufferInfo`). The window, not the buffer, which keeps the lines scrolled away. `None`
/// for a window that is empty or wider or taller than a size can say.
pub fn window_size(left: i16, top: i16, right: i16, bottom: i16) -> Option<(u16, u16)> {
    let cells = |from: i16, to: i16| u16::try_from(i32::from(to) - i32::from(from) + 1).ok().filter(|&count| count > 0);
    Some((cells(left, right)?, cells(top, bottom)?))
}

/// The console of this run. Dropping it puts the console back as it was, once it was taken over.
pub struct Tty {
    console: Arc<Console>,
}

/// What a `Tty` and its `Restorer`s share: the console, its settings of the start, and the mode it is in now. Every change of the
/// console is made holding `now`, so the program's threads change it one at a time and none undoes another's half way: the loop takes
/// the console over and sets a mode (`Tty`); the watchdog puts the console back for good before it ends the program
/// (`Restorer::hold_restored`).
struct Console {
    api: Arc<dyn ConsoleApi>,
    start: Settings,
    /// The mode once the console is taken over (its output set for a terminal, UTF-8); `None` before, and once it is put back.
    now: Mutex<Option<Mode>>,
    /// Whether the console may differ from the start: set just before the take-over's first change, cleared just after the four
    /// settings are put back. Every restore goes by it: nothing is put back before the take-over, and a restore that cannot wait for
    /// `now` still knows, even half way through a take-over (a panic can come there, on this very thread).
    changed: AtomicBool,
    /// The console refused xterm's line endings once: raw mode's output goes without them from then on.
    plain_line_endings: AtomicBool,
}

impl Console {
    fn now(&self) -> MutexGuard<'_, Option<Mode>> {
        self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the console over, for the holder of `now`: the output for a terminal, the way cooked mode has it, then UTF-8 (the console
    /// turns the bytes written to it into characters with the output's code page). A console that refuses virtual terminal sequences as
    /// an invalid parameter (the legacy console) is `Unsupported`. What a take-over that fails half way set is put back.
    fn take_over(&self) -> io::Result<()> {
        self.changed.store(true, Ordering::SeqCst);
        if let Err(error) = self.api.set(Setting::OutputMode, output_mode(self.start.output_mode, Mode::Cooked)) {
            self.changed.store(false, Ordering::SeqCst);
            if error.kind() == io::ErrorKind::InvalidInput {
                let unsupported = format!("the console does not support virtual terminal sequences ({error})");
                return Err(io::Error::new(io::ErrorKind::Unsupported, unsupported));
            }
            return Err(error);
        }
        if let Err(error) = self.api.set(Setting::OutputCodePage, CP_UTF8) {
            let _ = self.api.set(Setting::OutputMode, self.start.output_mode);
            self.changed.store(false, Ordering::SeqCst);
            return Err(error);
        }
        Ok(())
    }

    /// Sets the output's mode for `mode`, for the holder of `now`. A console that refuses xterm's line endings as an invalid parameter
    /// (an older Windows 10 does not know `DISABLE_NEWLINE_AUTO_RETURN`; Microsoft's example of enabling virtual terminal processing
    /// falls back to the sequences alone) gets raw mode's output without them: once refused, and at once from then on.
    fn set_output(&self, mode: Mode) -> io::Result<()> {
        let output = output_mode(self.start.output_mode, mode);
        if mode != Mode::Raw {
            return self.api.set(Setting::OutputMode, output);
        }
        if !self.plain_line_endings.load(Ordering::SeqCst) {
            match self.api.set(Setting::OutputMode, output) {
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => self.plain_line_endings.store(true, Ordering::SeqCst),
                done => return done,
            }
        }
        self.api.set(Setting::OutputMode, output & !DISABLE_NEWLINE_AUTO_RETURN)
    }

    /// Puts the four settings back as they were at the start; with `discard_input`, what was typed and not read yet is thrown away
    /// first. A setting that cannot be put back does not keep the others from being, nor does input that cannot be thrown away.
    fn put_back_all(&self, discard_input: bool) {
        if discard_input {
            let _ = self.api.flush_input();
        }
        for setting in Setting::ALL {
            let _ = self.api.set(setting, self.start.of(setting));
        }
    }

    /// Puts the console back, for the holder of `now`, if it may have been changed.
    fn put_back(&self, now: &mut Option<Mode>, discard_input: bool) {
        if self.changed.load(Ordering::SeqCst) {
            self.put_back_all(discard_input);
            self.changed.store(false, Ordering::SeqCst);
        }
        *now = None;
    }

    /// Puts the console back without `now`, which another thread holds (or this one, in the middle of a change a panic broke into),
    /// if it may have been changed. `now` is left to its holder.
    fn put_back_unheld(&self, discard_input: bool) {
        if self.changed.load(Ordering::SeqCst) {
            self.put_back_all(discard_input);
        }
    }
}

impl Tty {
    /// Reads the console's four settings as they are now: what every mode is made from and every restore goes back to. Changes nothing
    /// (the console is taken over later: `take_over`). Fails when the input is not a console.
    pub fn new(api: Arc<dyn ConsoleApi>) -> io::Result<Tty> {
        // The input first: one that is not a console is refused before anything else is asked.
        let start = Settings {
            input_mode: api.get(Setting::InputMode)?,
            output_mode: api.get(Setting::OutputMode)?,
            input_code_page: api.get(Setting::InputCodePage)?,
            output_code_page: api.get(Setting::OutputCodePage)?,
        };
        let console =
            Console { api, start, now: Mutex::new(None), changed: AtomicBool::new(false), plain_line_endings: AtomicBool::new(false) };
        Ok(Tty { console: Arc::new(console) })
    }

    /// Takes the console over, once every way out can put it back (the program's control handler is in place): the output for a
    /// terminal, in cooked mode, and UTF-8; the input stays as it was. Until then the console is as it was at the start, and a program
    /// ended the default way leaves it so. A console that refuses virtual terminal sequences (the legacy console) is
    /// `io::ErrorKind::Unsupported`, and says so; a take-over that fails puts back what it set. Taking over a console taken over already
    /// changes nothing.
    pub fn take_over(&mut self) -> io::Result<()> {
        let mut now = self.console.now();
        if now.is_none() {
            self.console.take_over()?;
            *now = Some(Mode::Cooked);
        }
        Ok(())
    }

    pub fn mode(&self) -> Mode {
        self.console.now().unwrap_or(Mode::Cooked)
    }

    /// Sets `mode`: the input's mode, then the output's. `discard_input` throws away what was typed ahead first (a question must not
    /// take typeahead as its answer). A console not taken over (yet, or any more: `restore`, a panic on another thread) is taken over
    /// first, so no mode is set without it. An output's mode that cannot be set does not undo the input's, which is what keeps a password
    /// from being shown: the mode is set, and the error returned.
    pub fn set_mode(&mut self, mode: Mode, discard_input: bool) -> io::Result<()> {
        let console = &self.console;
        let mut now = console.now();
        if now.is_none() {
            console.take_over()?;
            *now = Some(Mode::Cooked);
        }
        if discard_input {
            // What was typed is thrown away when the console can; one that went away may not, and the mode is set all the same (the end
            // of the program must not stop at that).
            let _ = console.api.flush_input();
        }
        console.api.set(Setting::InputMode, input_mode(console.start.input_mode, mode))?;
        *now = Some(mode);
        console.set_output(mode)
    }

    pub fn size(&self) -> Option<(u16, u16)> {
        self.console.api.size()
    }

    /// Back to the four settings of the start, if the console was taken over.
    pub fn restore(&mut self) {
        let mut now = self.console.now();
        self.console.put_back(&mut now, false);
    }

    /// What puts the console back from elsewhere: the panic hook, the watchdog.
    pub fn restorer(&self) -> Restorer {
        Restorer { console: Arc::clone(&self.console) }
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Puts a console back to its settings of the start, from wherever the program is.
#[derive(Clone)]
pub struct Restorer {
    console: Arc<Console>,
}

impl Restorer {
    /// Puts the console back, if it was taken over. It does not wait for a change another thread is making: a panic can come while
    /// this very thread is making one.
    pub fn restore(&self) {
        match self.console.now.try_lock() {
            Ok(mut now) => self.console.put_back(&mut now, false),
            Err(TryLockError::Poisoned(poisoned)) => self.console.put_back(&mut poisoned.into_inner(), false),
            Err(TryLockError::WouldBlock) => self.console.put_back_unheld(false),
        }
    }

    /// Puts the console back for good: the program is about to end (the watchdog ends it when its loop does not). What was typed and
    /// not read yet is thrown away: at a question it is a part of a password, which the shell would read after the program. A console
    /// not taken over has nothing to put back or throw away. No mode is set while the returned hold lives. A change another thread is
    /// making is waited for up to `wait`; one that takes longer does not keep the console from being put back, without the hold (`None`).
    pub fn hold_restored(&self, wait: Duration) -> Option<MutexGuard<'_, Option<Mode>>> {
        let deadline = Instant::now() + wait;
        loop {
            let mut now = match self.console.now.try_lock() {
                Ok(now) => now,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(TryLockError::WouldBlock) => {
                    self.console.put_back_unheld(true);
                    return None;
                }
            };
            self.console.put_back(&mut now, true);
            return Some(now);
        }
    }
}

static PANIC_RESTORER: Mutex<Option<Restorer>> = Mutex::new(None);
static PANIC_HOOK: Once = Once::new();

/// From now on a panic, on any thread, first puts the console back, then reports as usual: the message lands on a console that edits
/// lines and echoes again. The latest `restorer` counts.
pub fn restore_on_panic(restorer: Restorer) {
    *PANIC_RESTORER.lock().unwrap_or_else(PoisonError::into_inner) = Some(restorer);
    PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_registered(&PANIC_RESTORER);
            previous(info);
        }));
    });
}

/// The panic hook's first step: the console of the restorer `registered` holds (the latest one given to `restore_on_panic`) is put
/// back, without waiting for a change in progress.
fn restore_registered(registered: &Mutex<Option<Restorer>>) {
    if let Some(restorer) = registered.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
        restorer.restore();
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    // The other flags of a console's modes, which this layer leaves as they were (wincon.h; pinned against windows-sys on Windows).

    /// Input: changes of the buffer's size are reported in the input buffer.
    pub const ENABLE_WINDOW_INPUT: u32 = 0x0008;
    /// Input: mouse events are reported in the input buffer.
    pub const ENABLE_MOUSE_INPUT: u32 = 0x0010;
    /// Input: what is typed in a line is inserted rather than typed over.
    pub const ENABLE_INSERT_MODE: u32 = 0x0020;
    /// Input: the mouse selects and copies text.
    pub const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;
    /// Input: a mode set carries insert mode and quick edit (without it, they stay as they are).
    pub const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
    /// Input: one of the modes a console reports that the documentation does not describe.
    pub const ENABLE_AUTO_POSITION: u32 = 0x0100;
    /// Output: at the end of a line the cursor moves to the next one.
    pub const ENABLE_WRAP_AT_EOL_OUTPUT: u32 = 0x0002;
    /// Output: grid lines and reverse video in every code page.
    pub const ENABLE_LVB_GRID_WORLDWIDE: u32 = 0x0010;

    /// The input's mode of a console as it usually starts: lines edited, echoed and processed, mouse, insert mode and quick edit (with
    /// the extended flags that carry them), auto position; no window input, no virtual terminal input.
    pub const USUAL_INPUT: u32 = ENABLE_PROCESSED_INPUT
        | ENABLE_LINE_INPUT
        | ENABLE_ECHO_INPUT
        | ENABLE_MOUSE_INPUT
        | ENABLE_INSERT_MODE
        | ENABLE_QUICK_EDIT_MODE
        | ENABLE_EXTENDED_FLAGS
        | ENABLE_AUTO_POSITION;
    /// The output's mode of a new screen buffer: both of the classic output modes.
    pub const USUAL_OUTPUT: u32 = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;

    /// A call made to the console.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Call {
        Get(Setting),
        Set(Setting, u32),
        FlushInput,
    }

    /// A console that records every call made to it and keeps the values set; a test can change its size and make calls fail. Its
    /// locks are taken whether or not they are poisoned: a test whose assertion fails still drops its `Tty`, which puts the console
    /// back, and a second panic there would abort every test in the process.
    pub struct FakeConsole {
        pub start: Settings,
        now: Mutex<Settings>,
        calls: Mutex<Vec<Call>>,
        pub size: Mutex<Option<(u16, u16)>>,
        failing: Mutex<(fn(&Call) -> bool, io::ErrorKind)>,
    }

    impl FakeConsole {
        /// A console with the usual modes and two code pages the program does not use: each of the four values differs from the
        /// others and from what the program sets, so that a value put back in the wrong place, or not at all, shows.
        pub fn new() -> Arc<FakeConsole> {
            let start = Settings { input_mode: USUAL_INPUT, output_mode: USUAL_OUTPUT, input_code_page: 437, output_code_page: 850 };
            FakeConsole::starting(start)
        }

        pub fn starting(start: Settings) -> Arc<FakeConsole> {
            Arc::new(FakeConsole {
                start,
                now: Mutex::new(start),
                calls: Mutex::new(Vec::new()),
                size: Mutex::new(Some((80, 24))),
                failing: Mutex::new((|_| false, io::ErrorKind::Other)),
            })
        }

        /// From now on the calls `fails` says yes to fail (a console going away, say), and change nothing; they are recorded all the
        /// same.
        pub fn fail(&self, fails: fn(&Call) -> bool) {
            *self.failing.lock().unwrap_or_else(PoisonError::into_inner) = (fails, io::ErrorKind::Other);
        }

        /// From now on the calls `refuses` says yes to are refused the way a console refuses a mode flag it does not know: an invalid
        /// parameter (ERROR_INVALID_PARAMETER, which std reads as `InvalidInput`); they change nothing and are recorded all the same.
        pub fn refuse(&self, refuses: fn(&Call) -> bool) {
            *self.failing.lock().unwrap_or_else(PoisonError::into_inner) = (refuses, io::ErrorKind::InvalidInput);
        }

        /// The four settings as they are now.
        pub fn now(&self) -> Settings {
            *self.now.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Every call made so far, in order.
        pub fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }

        /// The calls that change the console, in order: the settings set (or tried) and the input thrown away.
        pub fn changes(&self) -> Vec<Call> {
            self.calls().into_iter().filter(|call| !matches!(call, Call::Get(_))).collect()
        }

        fn call(&self, call: Call) -> io::Result<()> {
            self.calls.lock().unwrap_or_else(PoisonError::into_inner).push(call);
            let (fails, kind) = *self.failing.lock().unwrap_or_else(PoisonError::into_inner);
            if fails(&call) {
                return Err(io::Error::new(kind, format!("{call:?} failed")));
            }
            Ok(())
        }
    }

    impl ConsoleApi for FakeConsole {
        fn get(&self, setting: Setting) -> io::Result<u32> {
            self.call(Call::Get(setting))?;
            Ok(self.now().of(setting))
        }

        fn set(&self, setting: Setting, value: u32) -> io::Result<()> {
            self.call(Call::Set(setting, value))?;
            let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
            match setting {
                Setting::InputMode => now.input_mode = value,
                Setting::OutputMode => now.output_mode = value,
                Setting::InputCodePage => now.input_code_page = value,
                Setting::OutputCodePage => now.output_code_page = value,
            }
            Ok(())
        }

        fn flush_input(&self) -> io::Result<()> {
            self.call(Call::FlushInput)
        }

        fn size(&self) -> Option<(u16, u16)> {
            *self.size.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::fake::*;
    use super::*;

    /// A mode in hex, for comparisons whose failures show the flags.
    fn hex(mode: u32) -> String {
        format!("{mode:#06x}")
    }

    /// The output's mode in raw mode on a console with the usual one: virtual terminal sequences, and xterm's line endings.
    const RAW_OUTPUT: u32 = USUAL_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    /// The output's mode at a question and in cooked mode on a console with the usual one: virtual terminal sequences, and a line feed
    /// that returns the carriage, as at the start.
    const COOKED_OUTPUT: u32 = USUAL_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    /// Raw mode on a console with the usual input mode.
    const USUAL_RAW: u32 = ENABLE_MOUSE_INPUT
        | ENABLE_INSERT_MODE
        | ENABLE_QUICK_EDIT_MODE
        | ENABLE_EXTENDED_FLAGS
        | ENABLE_AUTO_POSITION
        | ENABLE_VIRTUAL_TERMINAL_INPUT;

    /// The calls that put the four settings of `start` back, in their order: the input's mode first.
    fn put_back(start: Settings) -> Vec<Call> {
        vec![
            Call::Set(Setting::InputMode, start.input_mode),
            Call::Set(Setting::OutputMode, start.output_mode),
            Call::Set(Setting::InputCodePage, start.input_code_page),
            Call::Set(Setting::OutputCodePage, start.output_code_page),
        ]
    }

    /// The ways out of a run, each given the run's `Tty`.
    fn ways_out() -> [(&'static str, fn(Tty)); 4] {
        [
            ("a dropped Tty", drop),
            ("Tty::restore", |mut tty| tty.restore()),
            ("the panic hook's Restorer::restore", |tty| tty.restorer().restore()),
            ("the watchdog's Restorer::hold_restored", |tty| drop(tty.restorer().hold_restored(Duration::from_secs(1)))),
        ]
    }

    /// A console the program has, in raw mode.
    fn raw_console() -> (Arc<FakeConsole>, Tty) {
        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        tty.set_mode(Mode::Raw, false).unwrap();
        assert_eq!(console.now(), Settings { input_mode: USUAL_RAW, output_mode: RAW_OUTPUT, output_code_page: CP_UTF8, ..console.start });
        (console, tty)
    }

    /// Spec §7.3: raw input takes the keys as they are typed (no line input), unshown (no echo), with Ctrl-C a key like any other (no
    /// processed input), as virtual terminal sequences. Every other flag stays as the console had it at the start: mouse, insert mode,
    /// quick edit and the extended flags that carry those two, window input, and flags this layer does not know of. Whole modes are
    /// compared, from several modes of the start.
    #[test]
    fn raw_input_takes_the_keys_as_they_are_typed_and_leaves_every_other_flag_as_it_was() {
        let line = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
        let left_raw = ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT;
        let cases = [
            (USUAL_INPUT, USUAL_RAW),
            (0, ENABLE_VIRTUAL_TERMINAL_INPUT),
            (u32::MAX, !line),
            // Quick edit and insert mode off.
            (line | ENABLE_EXTENDED_FLAGS, ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT),
            // Left raw by another program.
            (left_raw, left_raw),
        ];
        for (start, raw) in cases {
            assert_eq!(hex(input_mode(start, Mode::Raw)), hex(raw), "from {}", hex(start));
        }
    }

    /// A question: the console reads and edits a line and Ctrl-C is a signal (it cancels the question); keys are not sequences, so the
    /// console's own line editing has them; what is typed is shown exactly when `echo`. Every other flag as at the start.
    #[test]
    fn a_question_edits_a_line_and_shows_what_is_typed_only_with_echo() {
        let line = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT;
        let extended = ENABLE_EXTENDED_FLAGS;
        // The mode of the start, then the question's without echo and with it.
        let cases = [
            (USUAL_INPUT, USUAL_INPUT & !ENABLE_ECHO_INPUT, USUAL_INPUT),
            (0, line, line | ENABLE_ECHO_INPUT),
            (u32::MAX, !(ENABLE_ECHO_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT), !ENABLE_VIRTUAL_TERMINAL_INPUT),
            // Left raw by another program.
            (extended | ENABLE_VIRTUAL_TERMINAL_INPUT, extended | line, extended | line | ENABLE_ECHO_INPUT),
        ];
        for (start, hidden, shown) in cases {
            assert_eq!(hex(input_mode(start, Mode::Prompt { echo: false })), hex(hidden), "from {}", hex(start));
            assert_eq!(hex(input_mode(start, Mode::Prompt { echo: true })), hex(shown), "from {}", hex(start));
        }
    }

    #[test]
    fn cooked_is_the_input_mode_of_the_start_exactly() {
        for start in [USUAL_INPUT, 0, u32::MAX, ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT] {
            assert_eq!(hex(input_mode(start, Mode::Cooked)), hex(start));
        }
    }

    /// Spec §7.3, the way OpenSSH's raw mode turns `OPOST` off and the other modes keep the start's `ONLCR`: the output takes virtual
    /// terminal sequences (with the processing they need) in every mode, and xterm's line endings in raw mode only (a line feed that
    /// does not return the carriage, for the shell's output). At a question and in cooked mode a line feed returns the carriage as it did
    /// at the start, so the CLI's own lines start at the left margin. Every other flag as at the start; whole modes are compared.
    #[test]
    fn the_output_ends_lines_as_xterm_does_in_raw_mode_only() {
        let terminal = ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        let (xterm, grid) = (DISABLE_NEWLINE_AUTO_RETURN, ENABLE_LVB_GRID_WORLDWIDE);
        // The output's mode of the start, then raw mode's, then the other modes'.
        let cases = [
            (USUAL_OUTPUT, RAW_OUTPUT, COOKED_OUTPUT),
            (0, terminal | xterm, terminal),
            (grid, grid | terminal | xterm, grid | terminal),
            // A console another program left with xterm's line endings keeps them outside raw mode too, as Unix keeps the start's OPOST.
            (USUAL_OUTPUT | xterm, RAW_OUTPUT, RAW_OUTPUT),
            (u32::MAX, u32::MAX, u32::MAX),
        ];
        for (start, raw, other) in cases {
            assert_eq!(hex(output_mode(start, Mode::Raw)), hex(raw), "raw from {}", hex(start));
            for mode in [Mode::Prompt { echo: false }, Mode::Prompt { echo: true }, Mode::Cooked] {
                assert_eq!(hex(output_mode(start, mode)), hex(other), "{mode:?} from {}", hex(start));
            }
        }
    }

    /// Spec §7.3: at the start the four settings are only read, the input first (input that is not a console is refused before anything
    /// else is asked). Nothing is changed before the take-over, so nothing is put back before it either, whichever way out: a Ctrl-C that
    /// ends the program the default way while SSHelter starts leaves the console as it was. The watchdog still gets its hold.
    #[test]
    fn a_new_tty_only_reads_the_console_and_puts_nothing_back() {
        let read = Setting::ALL.map(Call::Get);
        for (way_out, leave) in ways_out() {
            let console = FakeConsole::new();
            let tty = Tty::new(console.clone()).unwrap();
            assert_eq!(tty.mode(), Mode::Cooked);
            leave(tty);
            assert_eq!(console.calls(), read, "{way_out}: read, and nothing set or thrown away");
        }
        let tty = Tty::new(FakeConsole::new()).unwrap();
        assert!(tty.restorer().hold_restored(Duration::from_secs(1)).is_some(), "the watchdog holds the console all the same");
    }

    /// Spec §7.3: the take-over (once every way out can put the console back) sets the output for a terminal, the way cooked mode has
    /// it (virtual terminal sequences, a line feed returning the carriage), then UTF-8; the input stays as it was. A second take-over
    /// changes nothing. From then on a mode sets the input's mode and the output's, and the code page stays.
    #[test]
    fn taking_over_sets_the_output_for_a_terminal_then_utf_8_once() {
        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        tty.take_over().unwrap();
        tty.take_over().unwrap();
        let start = console.start;
        assert_eq!(console.changes(), [Call::Set(Setting::OutputMode, COOKED_OUTPUT), Call::Set(Setting::OutputCodePage, CP_UTF8)]);
        assert_eq!(console.now(), Settings { output_mode: COOKED_OUTPUT, output_code_page: CP_UTF8, ..start });
        assert_eq!(tty.mode(), Mode::Cooked);
        tty.set_mode(Mode::Raw, false).unwrap();
        assert_eq!(console.changes()[2..], [Call::Set(Setting::InputMode, USUAL_RAW), Call::Set(Setting::OutputMode, RAW_OUTPUT)]);
        assert_eq!(console.now(), Settings { input_mode: USUAL_RAW, output_mode: RAW_OUTPUT, output_code_page: CP_UTF8, ..start });
    }

    /// Nothing sets a mode without the take-over: a mode set first takes the console over, then throws the typeahead away and sets the
    /// input's mode and the output's.
    #[test]
    fn a_mode_set_before_the_take_over_takes_the_console_over_first() {
        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        tty.set_mode(Mode::Prompt { echo: false }, true).unwrap();
        assert_eq!(
            console.changes(),
            [
                Call::Set(Setting::OutputMode, COOKED_OUTPUT),
                Call::Set(Setting::OutputCodePage, CP_UTF8),
                Call::FlushInput,
                Call::Set(Setting::InputMode, USUAL_INPUT & !ENABLE_ECHO_INPUT),
                Call::Set(Setting::OutputMode, COOKED_OUTPUT),
            ]
        );
        drop(tty);
        assert_eq!(console.now(), console.start);
    }

    /// The UTF-8 code page's identifier, as Microsoft lists it (windows-sys has the constant behind a feature the app does not enable).
    #[test]
    fn utf_8_is_code_page_65001() {
        assert_eq!(CP_UTF8, 65001);
    }

    /// Every mode comes from the modes of the start, never from the mode before it: a mode is the same values whatever came before (raw,
    /// a question, raw again: raw's values again), and cooked is the input's mode of the start exactly. The input's mode of the start has
    /// virtual terminal input on here, so that all four input modes differ.
    #[test]
    fn every_mode_comes_from_the_start_never_from_the_mode_before() {
        let others = ENABLE_MOUSE_INPUT | ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS;
        let line = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT;
        let start = line | ENABLE_ECHO_INPUT | others | ENABLE_VIRTUAL_TERMINAL_INPUT;
        let console = FakeConsole::starting(Settings { input_mode: start, ..FakeConsole::new().start });
        let mut tty = Tty::new(console.clone()).unwrap();
        let (raw, hidden, shown) = (others | ENABLE_VIRTUAL_TERMINAL_INPUT, line | others, line | ENABLE_ECHO_INPUT | others);
        let sequence = [
            (Mode::Raw, raw, RAW_OUTPUT),
            (Mode::Prompt { echo: false }, hidden, COOKED_OUTPUT),
            (Mode::Raw, raw, RAW_OUTPUT),
            (Mode::Prompt { echo: true }, shown, COOKED_OUTPUT),
            (Mode::Cooked, start, COOKED_OUTPUT),
            (Mode::Prompt { echo: false }, hidden, COOKED_OUTPUT),
            (Mode::Raw, raw, RAW_OUTPUT),
            (Mode::Cooked, start, COOKED_OUTPUT),
        ];
        for (mode, input, output) in sequence {
            tty.set_mode(mode, false).unwrap();
            assert_eq!(tty.mode(), mode);
            let changes = console.changes();
            let expected = [Call::Set(Setting::InputMode, input), Call::Set(Setting::OutputMode, output)];
            assert_eq!(changes[changes.len() - 2..], expected, "{mode:?}: input {}, output {}", hex(input), hex(output));
        }
    }

    /// A question throws away what was typed before it (a part of a password typed ahead must not become the answer) before its mode
    /// is set; raw mode keeps what was typed for the shell.
    #[test]
    fn a_question_throws_the_typeahead_away_before_its_mode_is_set() {
        let (console, mut tty) = raw_console();
        let before = console.changes().len();
        tty.set_mode(Mode::Prompt { echo: false }, true).unwrap();
        let hidden = USUAL_INPUT & !ENABLE_ECHO_INPUT;
        let question = [Call::FlushInput, Call::Set(Setting::InputMode, hidden), Call::Set(Setting::OutputMode, COOKED_OUTPUT)];
        assert_eq!(console.changes()[before..], question);
        tty.set_mode(Mode::Raw, false).unwrap();
        assert_eq!(console.changes()[before + 3..], [Call::Set(Setting::InputMode, USUAL_RAW), Call::Set(Setting::OutputMode, RAW_OUTPUT)]);
    }

    /// Input that cannot be thrown away (a console going away) does not keep the mode from being set: the end of the program must not
    /// stop at it.
    #[test]
    fn input_that_cannot_be_thrown_away_does_not_keep_the_mode_from_being_set() {
        let (console, mut tty) = raw_console();
        console.fail(|call| *call == Call::FlushInput);
        tty.set_mode(Mode::Cooked, true).unwrap();
        assert_eq!(console.now(), Settings { output_mode: COOKED_OUTPUT, output_code_page: CP_UTF8, ..console.start });
    }

    /// An output's mode that cannot be set does not undo the input's mode, which is what keeps a password from being shown: the error
    /// is returned, the mode is the one asked for, and the console is put back all the same at the end.
    #[test]
    fn an_output_that_cannot_be_set_leaves_the_input_in_its_mode() {
        let (console, mut tty) = raw_console();
        console.fail(|call| matches!(call, Call::Set(Setting::OutputMode, COOKED_OUTPUT)));
        assert!(tty.set_mode(Mode::Prompt { echo: false }, true).is_err());
        assert_eq!(tty.mode(), Mode::Prompt { echo: false });
        assert_eq!(console.now().input_mode, USUAL_INPUT & !ENABLE_ECHO_INPUT);
        drop(tty);
        assert_eq!(console.now(), console.start);
    }

    /// Spec §7.3: input that is not a console (a pipe, a file) is refused at the start, and nothing about the console is changed.
    #[test]
    fn input_that_is_not_a_console_is_refused_and_nothing_is_changed() {
        let console = FakeConsole::new();
        console.fail(|call| *call == Call::Get(Setting::InputMode));
        assert!(Tty::new(console.clone()).is_err());
        assert_eq!(console.calls(), [Call::Get(Setting::InputMode)], "nothing else read, nothing set");
    }

    /// A console without virtual terminal sequences (the legacy console refuses the flag as an invalid parameter) cannot be taken
    /// over, nor can a mode be set on it; the error says why (`Unsupported`), so that the CLI can say it. Nothing was set, so nothing is
    /// put back.
    #[test]
    fn a_console_without_virtual_terminal_sequences_is_not_taken_over() {
        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        console.refuse(|call| matches!(call, Call::Set(Setting::OutputMode, _)));
        let refused = tty.take_over().unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::Unsupported);
        assert!(refused.to_string().starts_with("the console does not support virtual terminal sequences ("), "{refused}");
        assert_eq!(tty.set_mode(Mode::Raw, false).unwrap_err().kind(), io::ErrorKind::Unsupported);
        drop(tty);
        assert_eq!(console.changes(), [Call::Set(Setting::OutputMode, COOKED_OUTPUT); 2], "tried twice, nothing put back");
        assert_eq!(console.now(), console.start);
    }

    /// A take-over that fails half way (UTF-8 refused) puts back what it set, and the error is the console's; one that fails at the
    /// output's mode for another reason than a flag the console does not know is not called unsupported.
    #[test]
    fn a_take_over_that_fails_half_way_puts_back_what_it_set() {
        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        console.fail(|call| matches!(call, Call::Set(Setting::OutputCodePage, CP_UTF8)));
        assert_eq!(tty.take_over().unwrap_err().kind(), io::ErrorKind::Other);
        let start = console.start;
        assert_eq!(
            console.changes(),
            [
                Call::Set(Setting::OutputMode, COOKED_OUTPUT),
                Call::Set(Setting::OutputCodePage, CP_UTF8),
                Call::Set(Setting::OutputMode, start.output_mode),
            ]
        );
        assert_eq!(console.now(), start);
        drop(tty);
        assert_eq!(console.changes().len(), 3, "nothing more to put back");

        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        console.fail(|call| matches!(call, Call::Set(Setting::OutputMode, _)));
        assert_eq!(tty.take_over().unwrap_err().kind(), io::ErrorKind::Other);
    }

    /// A console that takes virtual terminal sequences but refuses xterm's line endings (an older Windows 10 refuses
    /// `DISABLE_NEWLINE_AUTO_RETURN` as an invalid parameter, as Microsoft's example of enabling virtual terminal processing allows for)
    /// still has a raw mode: raw mode's output without them, after one refusal, and at once from then on. Only that refusal is taken so:
    /// another failure is the error, not tried again.
    #[test]
    fn a_console_that_refuses_xterm_line_endings_has_a_raw_mode_without_them() {
        let plain = RAW_OUTPUT & !DISABLE_NEWLINE_AUTO_RETURN;
        let hidden = USUAL_INPUT & !ENABLE_ECHO_INPUT;
        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        tty.take_over().unwrap();
        console.refuse(|call| *call == Call::Set(Setting::OutputMode, RAW_OUTPUT));
        for mode in [Mode::Raw, Mode::Prompt { echo: false }, Mode::Raw] {
            tty.set_mode(mode, false).unwrap();
        }
        assert_eq!(
            console.changes()[2..],
            [
                Call::Set(Setting::InputMode, USUAL_RAW),
                Call::Set(Setting::OutputMode, RAW_OUTPUT),
                Call::Set(Setting::OutputMode, plain),
                Call::Set(Setting::InputMode, hidden),
                Call::Set(Setting::OutputMode, COOKED_OUTPUT),
                Call::Set(Setting::InputMode, USUAL_RAW),
                Call::Set(Setting::OutputMode, plain),
            ]
        );
        assert_eq!(tty.mode(), Mode::Raw);

        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        tty.take_over().unwrap();
        console.fail(|call| *call == Call::Set(Setting::OutputMode, RAW_OUTPUT));
        assert_eq!(tty.set_mode(Mode::Raw, false).unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(console.changes().last(), Some(&Call::Set(Setting::OutputMode, RAW_OUTPUT)), "not tried again");
    }

    /// Spec §7.3: a dropped `Tty` and `Tty::restore` put all four settings back, the input's mode first. Once they are back there is
    /// nothing more to put back.
    #[test]
    fn dropping_or_restoring_the_tty_puts_all_four_settings_back() {
        let (console, tty) = raw_console();
        let before = console.changes().len();
        drop(tty);
        assert_eq!(console.changes()[before..], put_back(console.start));
        assert_eq!(console.now(), console.start);

        let (console, mut tty) = raw_console();
        let before = console.changes().len();
        tty.restore();
        assert_eq!(console.changes()[before..], put_back(console.start));
        assert_eq!(console.now(), console.start);
        assert_eq!(tty.mode(), Mode::Cooked);
        drop(tty);
        assert_eq!(console.changes().len(), before + 4, "nothing more to put back");
    }

    /// The take-over set the output: a console taken over and never given a mode has all four settings put back all the same.
    #[test]
    fn a_console_taken_over_is_put_back_without_a_mode_set() {
        let console = FakeConsole::new();
        let mut tty = Tty::new(console.clone()).unwrap();
        tty.take_over().unwrap();
        drop(tty);
        assert_eq!(console.changes()[2..], put_back(console.start));
        assert_eq!(console.now(), console.start);
    }

    /// The restores that cannot wait for a change in progress (the panic hook's, and the watchdog's once it has waited) go by whether
    /// the console may have been changed: nothing before the take-over begins, all four from its first change on, before the take-over
    /// has recorded it (a panic can come half way through it).
    #[test]
    fn a_restore_that_cannot_wait_puts_back_only_a_console_that_was_changed() {
        let console = FakeConsole::new();
        let tty = Tty::new(console.clone()).unwrap();
        let restorer = tty.restorer();
        let held = tty.console.now();
        let other = restorer.clone();
        std::thread::spawn(move || other.restore()).join().unwrap();
        let other = restorer.clone();
        assert!(std::thread::spawn(move || other.hold_restored(Duration::from_millis(50)).is_none()).join().unwrap());
        assert_eq!(console.changes(), [], "nothing was changed, nothing is put back");

        // The holder of the console has made the take-over's changes and not recorded them yet.
        tty.console.take_over().unwrap();
        let before = console.changes().len();
        let other = restorer.clone();
        std::thread::spawn(move || other.restore()).join().unwrap();
        assert_eq!(console.changes()[before..], put_back(console.start));
        let before = console.changes().len();
        assert!(std::thread::spawn(move || restorer.hold_restored(Duration::from_millis(50)).is_none()).join().unwrap());
        let mut expected = vec![Call::FlushInput];
        expected.extend(put_back(console.start));
        assert_eq!(console.changes()[before..], expected);
        drop(held);
    }

    /// The panic hook's way out (`Restorer::restore`): all four settings back, without waiting for a change another thread is making
    /// (a panic can come while this very thread is making one).
    #[test]
    fn the_restorer_puts_all_four_back_without_waiting_for_a_change_in_progress() {
        let (console, tty) = raw_console();
        let restorer = tty.restorer();
        let held = tty.console.now();
        let before = console.changes().len();
        let (done, finished) = mpsc::channel();
        let other = std::thread::spawn(move || {
            restorer.restore();
            done.send(()).unwrap();
        });
        finished.recv_timeout(Duration::from_secs(5)).expect("the restorer does not wait for a change in progress");
        other.join().unwrap();
        assert_eq!(console.changes()[before..], put_back(console.start));
        assert_eq!(console.now(), console.start);
        drop(held);
    }

    /// The watchdog's way out (`Restorer::hold_restored`): what was typed and not read yet is thrown away first (at a question, a part
    /// of a password the shell would read), then all four settings are put back, and no mode is set while the hold lives.
    #[test]
    fn the_watchdog_throws_the_typeahead_away_puts_all_four_back_and_holds_the_console() {
        let (console, mut tty) = raw_console();
        let restorer = tty.restorer();
        let before = console.changes().len();
        let hold = restorer.hold_restored(Duration::from_secs(1)).expect("nobody else holds it");
        let mut expected = vec![Call::FlushInput];
        expected.extend(put_back(console.start));
        assert_eq!(console.changes()[before..], expected);
        let the_loop = std::thread::spawn(move || {
            tty.set_mode(Mode::Raw, false).unwrap();
            tty
        });
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(console.now(), console.start, "the loop's change waits for the hold");
        drop(hold);
        drop(the_loop.join().unwrap());
        assert_eq!(console.now(), console.start);
    }

    /// A change that does not end (a console that does not answer) does not keep the watchdog from putting the console back.
    #[test]
    fn the_watchdog_does_not_wait_for_ever_for_a_change_in_progress() {
        let (console, tty) = raw_console();
        let restorer = tty.restorer();
        let held = tty.console.now();
        let before = console.changes().len();
        let started = Instant::now();
        let other = std::thread::spawn(move || restorer.hold_restored(Duration::from_millis(100)).is_some());
        assert!(!other.join().unwrap(), "no hold: another thread has the console");
        assert!(started.elapsed() >= Duration::from_millis(100));
        let mut expected = vec![Call::FlushInput];
        expected.extend(put_back(console.start));
        assert_eq!(console.changes()[before..], expected, "put back all the same");
        drop(held);
    }

    /// Spec §7.3: a panic puts the console back before its message is printed. The hook's first step runs here directly, on a restorer
    /// registered as `restore_on_panic` registers it; tests do not install the hook: a Unix test build has the termios layer's hook too,
    /// installed under its own `Once`, and two installers at once can lose one hook (taking the previous hook and setting the new one is
    /// not one step). With nothing else holding the console it puts back exactly the four settings, the input's mode first, and throws
    /// nothing away.
    #[test]
    fn the_panic_hook_puts_exactly_the_four_settings_back() {
        let (console, tty) = raw_console();
        let before = console.changes().len();
        restore_registered(&Mutex::new(Some(tty.restorer())));
        assert_eq!(console.changes()[before..], put_back(console.start));
        assert_eq!(console.now(), console.start);
        restore_registered(&Mutex::new(None));
        drop(tty);
        assert_eq!(console.changes().len(), before + 4, "nothing registered, and nothing more to put back");
    }

    /// A way out whose first call fails still makes the others: a setting that cannot be put back (and input that cannot be thrown
    /// away) does not keep the other settings from being put back, whichever way out it is.
    #[test]
    fn a_setting_that_cannot_be_put_back_does_not_keep_the_others_from_being() {
        for (way_out, leave) in ways_out() {
            let (console, tty) = raw_console();
            console.fail(|call| matches!(call, Call::FlushInput | Call::Set(Setting::InputMode, _)));
            leave(tty);
            let start = console.start;
            assert_eq!(console.now(), Settings { input_mode: USUAL_RAW, ..start }, "{way_out}: all but the input's mode back");
            assert!(console.changes().contains(&Call::Set(Setting::InputMode, start.input_mode)), "{way_out}: the input's mode tried");
        }
    }

    /// After the console was put back (a panic on another thread, say), a mode set takes the console over again first, then sets the
    /// input's mode and the output's; and it is put back again at the end.
    #[test]
    fn a_mode_set_after_the_console_was_put_back_takes_it_over_again() {
        let (console, mut tty) = raw_console();
        tty.restorer().restore();
        assert_eq!(console.now(), console.start);
        let before = console.changes().len();
        tty.set_mode(Mode::Raw, false).unwrap();
        assert_eq!(
            console.changes()[before..],
            [
                Call::Set(Setting::OutputMode, COOKED_OUTPUT),
                Call::Set(Setting::OutputCodePage, CP_UTF8),
                Call::Set(Setting::InputMode, USUAL_RAW),
                Call::Set(Setting::OutputMode, RAW_OUTPUT),
            ]
        );
        drop(tty);
        assert_eq!(console.now(), console.start);
    }

    /// Spec §7.3: the size is the window's (the part of the screen buffer shown), both ends included.
    #[test]
    fn the_size_is_the_window_s_both_ends_included() {
        assert_eq!(window_size(0, 0, 79, 23), Some((80, 24)));
        assert_eq!(window_size(0, 270, 119, 299), Some((120, 30)), "a window scrolled down its buffer");
        assert_eq!(window_size(10, 5, 9, 5), None, "no column");
        assert_eq!(window_size(0, 5, 79, 4), None, "no row");
        assert_eq!(window_size(i16::MIN, 0, i16::MAX, 0), None, "more columns than a size can say");
        let console = FakeConsole::new();
        let tty = Tty::new(console.clone()).unwrap();
        assert_eq!(tty.size(), Some((80, 24)));
        *console.size.lock().unwrap() = None;
        assert_eq!(tty.size(), None);
    }
}
