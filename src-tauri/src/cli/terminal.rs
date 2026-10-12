//! The terminal `sshelter connect` runs in (own-ssh spec §7.3): its modes and its size, through termios (`libc`, already a dependency
//! on Unix). Raw while the shell runs, the way OpenSSH sets it; a prompt mode for questions (line editing on, echo off for a password);
//! cooked otherwise. The mode the terminal had at the start comes back on every way out: the end of the program, a dropped `Tty`, and a
//! panic (`restore_on_panic`).

use std::io;
use std::sync::{Arc, Mutex, Once, PoisonError};

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
    /// Sets the attributes; with `discard_input`, what was typed and not read yet is thrown away first (`TCSAFLUSH`).
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
    api: Arc<dyn TermiosApi>,
    original: libc::termios,
    mode: Mode,
}

impl Tty {
    /// Remembers the terminal's attributes as they are now: they are what `Mode::Cooked` and every restore go back to.
    pub fn new(api: Arc<dyn TermiosApi>) -> io::Result<Tty> {
        let original = api.get()?;
        Ok(Tty { api, original, mode: Mode::Cooked })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Sets `mode`; `discard_input` throws away what was typed ahead first (a question must not take typeahead as its answer).
    pub fn set_mode(&mut self, mode: Mode, discard_input: bool) -> io::Result<()> {
        self.api.set(&attributes(&self.original, mode), discard_input)?;
        self.mode = mode;
        Ok(())
    }

    pub fn size(&self) -> Option<(u16, u16)> {
        self.api.size()
    }

    /// Back to the attributes of the start.
    pub fn restore(&mut self) {
        if self.mode != Mode::Cooked {
            let _ = self.api.set(&self.original, false);
            self.mode = Mode::Cooked;
        }
    }

    /// What a panic hook needs to put the terminal back.
    pub fn restorer(&self) -> Restorer {
        Restorer { api: Arc::clone(&self.api), original: self.original }
    }
}

impl Drop for Tty {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Puts a terminal back to its attributes of the start, from wherever the program is.
#[derive(Clone)]
pub struct Restorer {
    api: Arc<dyn TermiosApi>,
    original: libc::termios,
}

impl Restorer {
    pub fn restore(&self) {
        let _ = self.api.set(&self.original, false);
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
        let when = if discard_input { libc::TCSAFLUSH } else { libc::TCSANOW };
        // SAFETY: a valid termios for a valid descriptor.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, when, termios) } != 0 {
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
