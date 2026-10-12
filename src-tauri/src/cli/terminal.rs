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

    /// A terminal that records every change of attributes; its size can be changed by the test.
    pub struct FakeTermios {
        pub start: libc::termios,
        pub sets: Mutex<Vec<(libc::termios, bool)>>,
        pub size: Mutex<Option<(u16, u16)>>,
    }

    impl FakeTermios {
        pub fn new() -> Arc<FakeTermios> {
            // SAFETY: an all-zero termios is valid plain data; the flags below make it look like a terminal in its usual mode.
            let mut start: libc::termios = unsafe { std::mem::zeroed() };
            start.c_iflag = libc::ICRNL | libc::IXON;
            start.c_oflag = libc::OPOST;
            start.c_lflag = libc::ICANON | libc::ISIG | libc::ECHO | libc::IEXTEN;
            start.c_cc[libc::VMIN] = 4;
            Arc::new(FakeTermios { start, sets: Mutex::new(Vec::new()), size: Mutex::new(Some((80, 24))) })
        }

        /// The attributes set last, or the start's.
        pub fn now(&self) -> libc::termios {
            self.sets.lock().unwrap().last().map(|(termios, _)| *termios).unwrap_or(self.start)
        }

        pub fn is_start(&self, termios: &libc::termios) -> bool {
            (termios.c_iflag, termios.c_oflag, termios.c_lflag, termios.c_cc[libc::VMIN]) == (self.start.c_iflag, self.start.c_oflag, self.start.c_lflag, self.start.c_cc[libc::VMIN])
        }
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
    use super::fake::FakeTermios;
    use super::*;

    #[test]
    fn raw_mode_is_openssh_s_raw_mode_and_cooked_is_the_start() {
        let api = FakeTermios::new();
        let raw = attributes(&api.start, Mode::Raw);
        assert_eq!(raw.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN), 0, "no line editing, echo or keyboard signals");
        assert_eq!(raw.c_iflag & (libc::ICRNL | libc::IXON), 0, "Enter stays a carriage return and Ctrl-S goes to the shell");
        assert_eq!(raw.c_oflag & libc::OPOST, 0, "output is passed through");
        assert_eq!((raw.c_cc[libc::VMIN], raw.c_cc[libc::VTIME]), (1, 0), "a read returns every byte at once");
        assert!(api.is_start(&attributes(&api.start, Mode::Cooked)));
    }

    #[test]
    fn a_question_edits_lines_and_hides_a_password_but_shows_a_code() {
        let api = FakeTermios::new();
        let secret = attributes(&api.start, Mode::Prompt { echo: false });
        assert_eq!(secret.c_lflag & (libc::ICANON | libc::ISIG), libc::ICANON | libc::ISIG);
        assert_eq!(secret.c_lflag & (libc::ECHO | libc::ECHONL), 0);
        let shown = attributes(&api.start, Mode::Prompt { echo: true });
        assert_eq!(shown.c_lflag & libc::ECHO, libc::ECHO);
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
