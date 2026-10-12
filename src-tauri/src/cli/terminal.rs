//! The terminal `sshelter connect` runs in (own-ssh spec §7.3): its modes and its size, through termios (`libc`, already a dependency
//! on Unix). Raw while the shell runs, the way OpenSSH sets it; a prompt mode for questions (line editing on, echo off for a password);
//! cooked otherwise. The mode the terminal had at the start comes back on every way out: the end of the program, a dropped `Tty`, a
//! panic (`restore_on_panic`), the watchdog that ends a program whose loop does not (`Restorer::hold_restored`), and a stop (Ctrl-Z,
//! `Restorer::suspend`), after which the program's mode is set again when it continues (`Restorer::resume`).

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, Once, PoisonError, TryLockError};
use std::time::{Duration, Instant};

/// What the terminal is set to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// As it was when the program started.
    Cooked,
    /// Every key goes to the shell as it is pressed; no echo, no signals from the keyboard, no output processing.
    Raw,
    /// A question: lines are edited and signals work as usual; what is typed is shown only when `echo`.
    Prompt { echo: bool },
}

/// Reading and setting the terminal's attributes (termios) and reading its size. The real one works on standard input; tests use a fake.
pub trait TermiosApi: Send + Sync {
    fn get(&self) -> io::Result<libc::termios>;
    /// Sets the attributes, at once; with `discard_input`, what was typed and not read yet is thrown away first.
    fn set(&self, termios: &libc::termios, discard_input: bool) -> io::Result<()>;
    /// Columns and rows; `None` when it cannot be read.
    fn size(&self) -> Option<(u16, u16)>;
}

/// The attributes for `mode`, from the ones the terminal had at the start.
pub fn attributes(original: &libc::termios, mode: Mode) -> libc::termios {
    let mut termios = *original;
    match mode {
        Mode::Cooked => {}
        Mode::Raw => {
            // OpenSSH's enter_raw_mode (sshtty.c): input bytes untouched, no flow control keys, no line editing, echo or keyboard signals,
            // no output processing.
            termios.c_iflag |= libc::IGNPAR;
            termios.c_iflag &= !(libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::ICRNL | libc::IXON | libc::IXANY | libc::IXOFF);
            // OpenSSH clears IUCLC where the system has it (`#ifdef IUCLC`): Linux would turn typed capitals into lower case.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                termios.c_iflag &= !libc::IUCLC;
            }
            termios.c_lflag &= !(libc::ISIG | libc::ICANON | libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::IEXTEN);
            termios.c_oflag &= !libc::OPOST;
            termios.c_cc[libc::VMIN] = 1;
            termios.c_cc[libc::VTIME] = 0;
        }
        Mode::Prompt { echo } => {
            termios.c_lflag |= libc::ICANON | libc::ISIG;
            if echo {
                termios.c_lflag |= libc::ECHO;
            } else {
                termios.c_lflag &= !(libc::ECHO | libc::ECHONL);
            }
        }
    }
    termios
}

/// The terminal of this run. Dropping it puts the terminal back as it was.
pub struct Tty {
    terminal: Arc<Terminal>,
}

/// What a `Tty` and its `Restorer`s share: the terminal, its attributes of the start, and the mode it is in now. Every change of the
/// terminal is made holding `mode`, so the program's threads change it one at a time and none undoes another's half way: the loop sets
/// a mode (`Tty`); the signal thread puts the terminal back for a stop and sets the mode again when the program continues
/// (`Restorer::suspend`, `Restorer::resume`); the watchdog puts it back for good before it ends the program (`Restorer::hold_restored`).
struct Terminal {
    api: Arc<dyn TermiosApi>,
    original: libc::termios,
    mode: Mutex<Mode>,
}

impl Terminal {
    fn mode(&self) -> MutexGuard<'_, Mode> {
        self.mode.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets `mode` again, the mode the program was in when it stopped. A question's prompt mode throws away what was typed meanwhile,
    /// as it does when the question is asked (OpenSSH's readpassphrase does the same when it starts over after a stop).
    fn set_again(&self, mode: Mode) {
        if mode != Mode::Cooked {
            let _ = self.api.set(&attributes(&self.original, mode), matches!(mode, Mode::Prompt { .. }));
        }
    }
}

impl Tty {
    /// Remembers the terminal's attributes as they are now: they are what `Mode::Cooked` and every restore go back to.
    pub fn new(api: Arc<dyn TermiosApi>) -> io::Result<Tty> {
        let original = api.get()?;
        Ok(Tty { terminal: Arc::new(Terminal { api, original, mode: Mutex::new(Mode::Cooked) }) })
    }

    pub fn mode(&self) -> Mode {
        *self.terminal.mode()
    }

    /// Sets `mode`; `discard_input` throws away what was typed ahead first (a question must not take typeahead as its answer).
    pub fn set_mode(&mut self, mode: Mode, discard_input: bool) -> io::Result<()> {
        let mut current = self.terminal.mode();
        self.terminal.api.set(&attributes(&self.terminal.original, mode), discard_input)?;
        *current = mode;
        Ok(())
    }

    pub fn size(&self) -> Option<(u16, u16)> {
        self.terminal.api.size()
    }

    /// Back to the attributes of the start.
    pub fn restore(&mut self) {
        let mut current = self.terminal.mode();
        if *current != Mode::Cooked {
            let _ = self.terminal.api.set(&self.terminal.original, false);
            *current = Mode::Cooked;
        }
    }

    /// What puts the terminal back from elsewhere: the panic hook, the watchdog, the signal thread.
    pub fn restorer(&self) -> Restorer {
        Restorer { terminal: Arc::clone(&self.terminal) }
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Puts a terminal back to its attributes of the start, from wherever the program is, and stops the program with its terminal put back.
#[derive(Clone)]
pub struct Restorer {
    terminal: Arc<Terminal>,
}

impl Restorer {
    /// Puts the terminal back. It does not wait for a change another thread is making: a panic can come while this very thread is
    /// making one.
    pub fn restore(&self) {
        match self.terminal.mode.try_lock() {
            Ok(mut current) => self.put_back(&mut current, false),
            Err(TryLockError::Poisoned(poisoned)) => self.put_back(&mut poisoned.into_inner(), false),
            Err(TryLockError::WouldBlock) => {
                let _ = self.terminal.api.set(&self.terminal.original, false);
            }
        }
    }

    /// Puts the terminal back for good: the program is about to end (the watchdog ends it when its loop does not). What was typed and not
    /// read yet is thrown away: at a question it is a part of a password, which the shell would read after the program. No mode is set
    /// while the returned hold lives. A change another thread is making is waited for up to `wait`; one that takes longer does not keep
    /// the terminal from being put back, without the hold (`None`).
    pub fn hold_restored(&self, wait: Duration) -> Option<MutexGuard<'_, Mode>> {
        let deadline = Instant::now() + wait;
        loop {
            let mut current = match self.terminal.mode.try_lock() {
                Ok(current) => current,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(TryLockError::WouldBlock) => {
                    let _ = self.terminal.api.set(&self.terminal.original, true);
                    return None;
                }
            };
            self.put_back(&mut current, true);
            return Some(current);
        }
    }

    /// Ctrl-Z (SIGTSTP), on the signal thread: the terminal is put back as it was at the start, `stop` stops the program (the shell has
    /// the terminal meanwhile), and when `stop` returns the program runs again and its mode is set again. The terminal is held all along,
    /// so the loop cannot set its mode between the putting back and the stop. At a question, what was typed and not read yet is thrown
    /// away before the stop, as OpenSSH's readpassphrase does: a part of a password must not reach the shell.
    pub fn suspend(&self, stop: impl FnOnce()) {
        let current = self.terminal.mode();
        let mode = *current;
        if mode != Mode::Cooked {
            let _ = self.terminal.api.set(&self.terminal.original, matches!(mode, Mode::Prompt { .. }));
        }
        stop();
        self.terminal.set_again(mode);
        drop(current);
    }

    /// The program runs again after a stop (SIGCONT): the mode it is in is set again, since a job-control shell (bash 5, zsh 5.9) puts its
    /// own modes back when it continues a job, not the job's. Returns that mode.
    pub fn resume(&self) -> Mode {
        let current = self.terminal.mode();
        self.terminal.set_again(*current);
        *current
    }

    fn put_back(&self, current: &mut Mode, discard_input: bool) {
        let _ = self.terminal.api.set(&self.terminal.original, discard_input);
        *current = Mode::Cooked;
    }
}

static PANIC_RESTORER: Mutex<Option<Restorer>> = Mutex::new(None);
static PANIC_HOOK: Once = Once::new();

/// From now on a panic, on any thread, first puts the terminal back, then reports as usual: the message lands on a terminal that
/// echoes again and starts at the left margin. The latest `restorer` counts.
pub fn restore_on_panic(restorer: Restorer) {
    *PANIC_RESTORER.lock().unwrap_or_else(PoisonError::into_inner) = Some(restorer);
    PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(restorer) = PANIC_RESTORER.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
                restorer.restore();
            }
            previous(info);
        }));
    });
}

/// The terminal on standard input.
#[cfg(unix)]
pub struct StdinTermios;

#[cfg(unix)]
impl TermiosApi for StdinTermios {
    fn get(&self) -> io::Result<libc::termios> {
        // SAFETY: `termios` is plain data that tcgetattr fills in completely on success.
        unsafe {
            let mut termios: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut termios) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(termios)
        }
    }

    fn set(&self, termios: &libc::termios, discard_input: bool) -> io::Result<()> {
        // Not `TCSAFLUSH`: it first waits until the terminal has taken all the output written to it, and a terminal that does not take it
        // (a frozen window) would keep a question from being asked, or the watchdog from putting the terminal back and ending the
        // program. What was typed is thrown away at once (`tcflush`), and the attributes are set at once.
        // SAFETY: a valid descriptor; `tcflush` only discards what the terminal holds.
        if discard_input && unsafe { libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a valid termios for a valid descriptor.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, termios) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn size(&self) -> Option<(u16, u16)> {
        // SAFETY: TIOCGWINSZ fills a winsize.
        unsafe {
            let mut size: libc::winsize = std::mem::zeroed();
            (libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut size) == 0 && size.ws_col > 0 && size.ws_row > 0).then_some((size.ws_col, size.ws_row))
        }
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;

    // The flags raw mode clears, as OpenSSH's enter_raw_mode lists them (`IGNPAR` is the one it sets). The fake terminal starts with every
    // one of them on and every one of the `KEPT_*` flags, which raw mode must leave alone, on too, so that a test can compare whole
    // structures: a flag raw mode forgets to clear, or clears without being asked to, shows.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const RAW_CLEARS_IFLAG: libc::tcflag_t = libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::ICRNL | libc::IXON | libc::IXANY | libc::IXOFF | libc::IUCLC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub const RAW_CLEARS_IFLAG: libc::tcflag_t = libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::ICRNL | libc::IXON | libc::IXANY | libc::IXOFF;
    pub const RAW_CLEARS_OFLAG: libc::tcflag_t = libc::OPOST;
    pub const RAW_CLEARS_LFLAG: libc::tcflag_t = libc::ISIG | libc::ICANON | libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::IEXTEN;
    pub const KEPT_IFLAG: libc::tcflag_t = libc::BRKINT | libc::INPCK | libc::IMAXBEL;
    pub const KEPT_OFLAG: libc::tcflag_t = libc::ONLCR;
    pub const KEPT_CFLAG: libc::tcflag_t = libc::CS8 | libc::CREAD | libc::HUPCL;
    pub const KEPT_LFLAG: libc::tcflag_t = libc::ECHOCTL | libc::ECHOKE | libc::NOFLSH | libc::TOSTOP;

    /// A terminal that records every change of attributes; its size can be changed by the test.
    pub struct FakeTermios {
        pub start: libc::termios,
        pub sets: Mutex<Vec<(libc::termios, bool)>>,
        pub size: Mutex<Option<(u16, u16)>>,
    }

    impl FakeTermios {
        pub fn new() -> Arc<FakeTermios> {
            let mut start = bare();
            start.c_iflag = RAW_CLEARS_IFLAG | KEPT_IFLAG;
            start.c_oflag = RAW_CLEARS_OFLAG | KEPT_OFLAG;
            start.c_cflag = KEPT_CFLAG;
            start.c_lflag = RAW_CLEARS_LFLAG | KEPT_LFLAG;
            // Raw mode sets these two; the keys are the usual ones, and nothing changes them.
            start.c_cc[libc::VMIN] = 4;
            start.c_cc[libc::VTIME] = 7;
            for (index, key) in [(libc::VINTR, 3), (libc::VQUIT, 28), (libc::VERASE, 127), (libc::VEOF, 4), (libc::VSTART, 17), (libc::VSTOP, 19)] {
                start.c_cc[index] = key;
            }
            Arc::new(FakeTermios { start, sets: Mutex::new(Vec::new()), size: Mutex::new(Some((80, 24))) })
        }

        /// The attributes set last, or the start's.
        pub fn now(&self) -> libc::termios {
            self.sets.lock().unwrap().last().map(|(termios, _)| *termios).unwrap_or(self.start)
        }

        /// Whether `termios` is the start in every attribute.
        pub fn is_start(&self, termios: &libc::termios) -> bool {
            describe(termios) == describe(&self.start)
        }
    }

    /// A terminal with every flag off and every key unset.
    pub fn bare() -> libc::termios {
        // SAFETY: an all-zero termios is valid plain data.
        unsafe { std::mem::zeroed() }
    }

    /// All the attributes there are to compare, as text: libc's `termios` has no `PartialEq` or `Debug` (and its speeds and line
    /// discipline are not on every system), and a failing comparison should show the flags in hex.
    pub fn describe(termios: &libc::termios) -> String {
        format!("iflag {:#x}, oflag {:#x}, cflag {:#x}, lflag {:#x}, cc {:?}", termios.c_iflag, termios.c_oflag, termios.c_cflag, termios.c_lflag, termios.c_cc)
    }

    impl TermiosApi for FakeTermios {
        fn get(&self) -> io::Result<libc::termios> {
            Ok(self.start)
        }
        fn set(&self, termios: &libc::termios, discard_input: bool) -> io::Result<()> {
            self.sets.lock().unwrap().push((*termios, discard_input));
            Ok(())
        }
        fn size(&self) -> Option<(u16, u16)> {
            *self.size.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{bare, describe, FakeTermios, KEPT_IFLAG, KEPT_LFLAG, KEPT_OFLAG, RAW_CLEARS_LFLAG};
    use super::*;

    /// OpenSSH's enter_raw_mode (sshtty.c), applied to a terminal that has every flag it touches the other way round: input bytes
    /// untouched (no stripping, no mapping of CR and NL, no flow control keys), no line editing, echo or keyboard signals, no output
    /// processing, a read returns every byte at once. Whole structures are compared, so a flag raw mode forgets or invents shows.
    #[test]
    fn raw_mode_is_openssh_s_raw_mode_flag_by_flag() {
        let api = FakeTermios::new();
        let raw = attributes(&api.start, Mode::Raw);
        let mut expected = api.start;
        expected.c_iflag = KEPT_IFLAG | libc::IGNPAR;
        expected.c_oflag = KEPT_OFLAG;
        expected.c_lflag = KEPT_LFLAG;
        expected.c_cc[libc::VMIN] = 1;
        expected.c_cc[libc::VTIME] = 0;
        assert_eq!(describe(&raw), describe(&expected));
        assert_ne!(describe(&raw), describe(&api.start), "the start is not raw already");
    }

    #[test]
    fn cooked_is_the_start_in_every_attribute() {
        let api = FakeTermios::new();
        assert_eq!(describe(&attributes(&api.start, Mode::Cooked)), describe(&api.start));
        assert!(api.is_start(&attributes(&api.start, Mode::Cooked)));
        assert!(!api.is_start(&attributes(&api.start, Mode::Raw)));
    }

    /// A password is typed with line editing and signals on and echo off, and a newline is not echoed either (`ECHONL`); everything else
    /// stays as the terminal had it.
    #[test]
    fn a_password_question_edits_lines_and_hides_what_is_typed() {
        let api = FakeTermios::new();
        let mut expected = api.start;
        expected.c_lflag = (RAW_CLEARS_LFLAG & !(libc::ECHO | libc::ECHONL)) | KEPT_LFLAG;
        assert_eq!(describe(&attributes(&api.start, Mode::Prompt { echo: false })), describe(&expected));
    }

    #[test]
    fn a_code_question_edits_lines_and_shows_what_is_typed() {
        let api = FakeTermios::new();
        assert_eq!(describe(&attributes(&api.start, Mode::Prompt { echo: true })), describe(&api.start), "a terminal at its start already does");
    }

    /// A question turns on what it needs whatever the terminal was when the program started (say, left raw by another program).
    #[test]
    fn a_question_turns_line_editing_and_signals_on_when_the_start_had_them_off() {
        let start = bare();
        let mut expected = start;
        expected.c_lflag = libc::ICANON | libc::ISIG;
        assert_eq!(describe(&attributes(&start, Mode::Prompt { echo: false })), describe(&expected));
        expected.c_lflag |= libc::ECHO;
        assert_eq!(describe(&attributes(&start, Mode::Prompt { echo: true })), describe(&expected));
    }

    #[test]
    fn the_terminal_is_put_back_when_the_tty_is_dropped_and_on_restore() {
        let api = FakeTermios::new();
        {
            let mut tty = Tty::new(api.clone()).unwrap();
            tty.set_mode(Mode::Raw, false).unwrap();
            assert_eq!(tty.mode(), Mode::Raw);
            tty.set_mode(Mode::Prompt { echo: false }, true).unwrap();
            assert!(api.sets.lock().unwrap().last().unwrap().1, "a question throws away the typeahead");
        }
        assert!(api.is_start(&api.now()), "dropped: back to the start");

        let mut tty = Tty::new(api.clone()).unwrap();
        tty.set_mode(Mode::Raw, false).unwrap();
        tty.restore();
        assert!(api.is_start(&api.now()));
        let count = api.sets.lock().unwrap().len();
        drop(tty);
        assert_eq!(api.sets.lock().unwrap().len(), count, "nothing more to put back");
    }

    /// Ctrl-Z: the shell gets the terminal back as it was at the start for the time the program is stopped, and the program's mode is
    /// set again when it runs again: raw for an open shell, the question's prompt mode (echo off for a password) at a question. At a
    /// question, what was typed and not read yet (a part of a password) is thrown away before the stop, and again when it is asked
    /// again; raw mode keeps what was typed for the shell.
    #[test]
    fn a_stop_puts_the_terminal_back_while_stopped_and_sets_the_mode_again_after() {
        for (mode, at_a_question) in [(Mode::Raw, false), (Mode::Prompt { echo: false }, true), (Mode::Prompt { echo: true }, true)] {
            let api = FakeTermios::new();
            let mut tty = Tty::new(api.clone()).unwrap();
            tty.set_mode(mode, false).unwrap();
            let mut while_stopped = None;
            tty.restorer().suspend(|| while_stopped = Some(*api.sets.lock().unwrap().last().unwrap()));
            let (stopped_with, discarded) = while_stopped.expect("stopped");
            assert!(api.is_start(&stopped_with), "{mode:?}: the start's attributes while stopped");
            assert_eq!(discarded, at_a_question, "{mode:?}: what was typed at a question is thrown away");
            let (after, discarded) = *api.sets.lock().unwrap().last().unwrap();
            assert_eq!(describe(&after), describe(&attributes(&api.start, mode)), "{mode:?}: the mode is set again");
            assert_eq!(discarded, at_a_question);
            assert_eq!(tty.mode(), mode);
        }
    }

    /// While connecting the terminal is as it was at the start: a stop has nothing to put back, and nothing to set again.
    #[test]
    fn a_stop_in_the_mode_of_the_start_changes_nothing() {
        let api = FakeTermios::new();
        let tty = Tty::new(api.clone()).unwrap();
        let mut stopped = false;
        tty.restorer().suspend(|| stopped = true);
        assert!(stopped);
        assert!(api.sets.lock().unwrap().is_empty());
    }

    /// The loop cannot set its mode between the putting back and the stop (the program would stop with the terminal raw) nor while the
    /// program is stopped: its change waits until the mode has been set again, and is made after.
    #[test]
    fn the_loop_cannot_change_the_mode_while_a_stop_holds_the_terminal() {
        let api = FakeTermios::new();
        let mut tty = Tty::new(api.clone()).unwrap();
        tty.set_mode(Mode::Prompt { echo: false }, false).unwrap();
        let restorer = tty.restorer();
        let (go, started) = std::sync::mpsc::channel();
        let the_loop = std::thread::spawn(move || {
            started.recv().unwrap();
            tty.set_mode(Mode::Raw, false).unwrap();
            tty
        });
        restorer.suspend(|| {
            go.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            assert!(api.is_start(&api.now()), "still put back while stopped: the loop waits");
        });
        let tty = the_loop.join().unwrap();
        let sets = api.sets.lock().unwrap().clone();
        let n = sets.len();
        assert_eq!(describe(&sets[n - 2].0), describe(&attributes(&api.start, Mode::Prompt { echo: false })), "set again first");
        assert_eq!(describe(&sets[n - 1].0), describe(&attributes(&api.start, Mode::Raw)), "then the loop's change");
        assert_eq!(tty.mode(), Mode::Raw);
    }

    /// The program continued (SIGCONT) after the shell had put its own modes back: the program's mode is set again.
    #[test]
    fn after_a_stop_the_mode_is_set_again_whatever_the_shell_left() {
        let api = FakeTermios::new();
        let mut tty = Tty::new(api.clone()).unwrap();
        tty.set_mode(Mode::Prompt { echo: false }, false).unwrap();
        api.set(&api.start, false).unwrap(); // the shell's own modes: echo on
        assert_eq!(tty.restorer().resume(), Mode::Prompt { echo: false });
        assert_eq!(describe(&api.now()), describe(&attributes(&api.start, Mode::Prompt { echo: false })));
        tty.restore();
        let count = api.sets.lock().unwrap().len();
        assert_eq!(tty.restorer().resume(), Mode::Cooked, "the mode of the start is the shell's: nothing to set again");
        assert_eq!(api.sets.lock().unwrap().len(), count);
    }

    /// The watchdog puts the terminal back for good: what was typed is thrown away, and no mode is set while it holds the terminal.
    #[test]
    fn the_watchdog_puts_the_terminal_back_and_holds_it() {
        let api = FakeTermios::new();
        let mut tty = Tty::new(api.clone()).unwrap();
        tty.set_mode(Mode::Raw, false).unwrap();
        let restorer = tty.restorer();
        let hold = restorer.hold_restored(Duration::from_secs(1)).expect("nobody else holds it");
        let (last, discarded) = *api.sets.lock().unwrap().last().unwrap();
        assert!(api.is_start(&last) && discarded);
        let the_loop = std::thread::spawn(move || {
            tty.set_mode(Mode::Raw, false).unwrap();
            tty
        });
        std::thread::sleep(Duration::from_millis(200));
        assert!(api.is_start(&api.now()), "the loop's change waits for the hold");
        drop(hold);
        drop(the_loop.join().unwrap());
    }

    /// A change that does not end (a terminal that does not answer) does not keep the watchdog from putting the terminal back.
    #[test]
    fn the_watchdog_does_not_wait_for_ever_for_a_change_in_progress() {
        let api = FakeTermios::new();
        let tty = Tty::new(api.clone()).unwrap();
        let restorer = tty.restorer();
        let held = tty.terminal.mode();
        let started = Instant::now();
        let other = std::thread::spawn(move || restorer.hold_restored(Duration::from_millis(100)).is_some());
        assert!(!other.join().unwrap(), "no hold: another thread has the terminal");
        assert!(started.elapsed() >= Duration::from_millis(100));
        let (last, discarded) = *api.sets.lock().unwrap().last().unwrap();
        assert!(api.is_start(&last) && discarded, "put back all the same");
        drop(held);
    }

    /// Spec §7.3: every way out, a panic too, puts the terminal back, before the panic message is printed.
    #[test]
    fn a_panic_puts_the_terminal_back() {
        let api = FakeTermios::new();
        let mut tty = Tty::new(api.clone()).unwrap();
        tty.set_mode(Mode::Raw, false).unwrap();
        restore_on_panic(tty.restorer());
        let crashed = std::thread::spawn(|| panic!("the CLI failed")).join();
        assert!(crashed.is_err());
        assert!(api.is_start(&api.now()), "the hook restored the terminal");
    }
}
