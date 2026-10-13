//! The signal numbers `sshelter connect` uses (own-ssh spec §7.3): the status it exits with when a signal ends it (128 + the number),
//! and the status of a remote shell a signal killed (128 + the number of the signal SSH names, as a shell reports it). On macOS and
//! Linux they are the system's own numbers (a test pins each against libc); Windows has no signals of its own, and gets the numbers POSIX
//! and Linux give them, so that `sshelter connect` exits with the same statuses there (130 for Ctrl-C, 129 for a closed console, 143 for
//! a request to stop).

/// The terminal went away (Unix), or the console was closed (Windows).
pub const HUP: i32 = 1;
/// Ctrl-C (and Ctrl-Break on Windows).
pub const INT: i32 = 2;
/// Ctrl-backslash (Unix only).
pub const QUIT: i32 = 3;
/// A request to stop (Unix), or log-off and shut-down (Windows).
pub const TERM: i32 = 15;

/// The user signals, which macOS numbers differently from Linux.
#[cfg(target_os = "macos")]
const USR1: i32 = 30;
#[cfg(target_os = "macos")]
const USR2: i32 = 31;
#[cfg(not(target_os = "macos"))]
const USR1: i32 = 10;
#[cfg(not(target_os = "macos"))]
const USR2: i32 = 12;

/// The number of a signal named as SSH names it (RFC 4254 §6.10, without `SIG`); `None` for a name SSH does not give.
pub fn number(name: &str) -> Option<i32> {
    Some(match name {
        "ABRT" => 6,
        "ALRM" => 14,
        "FPE" => 8,
        "HUP" => HUP,
        "ILL" => 4,
        "INT" => INT,
        "KILL" => 9,
        "PIPE" => 13,
        "QUIT" => QUIT,
        "SEGV" => 11,
        "TERM" => TERM,
        "USR1" => USR1,
        "USR2" => USR2,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names RFC 4254 §6.10 gives.
    const NAMES: [&str; 13] = ["ABRT", "ALRM", "FPE", "HUP", "ILL", "INT", "KILL", "PIPE", "QUIT", "SEGV", "TERM", "USR1", "USR2"];

    /// On macOS and Linux every number is the system's own: no exit status changes with the table.
    #[cfg(unix)]
    #[test]
    fn every_number_is_the_systems_own_on_unix() {
        assert_eq!((HUP, INT, QUIT, TERM), (libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM));
        let system = [
            libc::SIGABRT,
            libc::SIGALRM,
            libc::SIGFPE,
            libc::SIGHUP,
            libc::SIGILL,
            libc::SIGINT,
            libc::SIGKILL,
            libc::SIGPIPE,
            libc::SIGQUIT,
            libc::SIGSEGV,
            libc::SIGTERM,
            libc::SIGUSR1,
            libc::SIGUSR2,
        ];
        for (name, signal) in NAMES.into_iter().zip(system) {
            assert_eq!(number(name), Some(signal), "SIG{name}");
        }
    }

    /// Windows gets the numbers POSIX and Linux give: the statuses of spec §7.3 (130, 129, 143) on every platform, and a remote shell
    /// killed by a user signal reported as on Linux.
    #[test]
    fn the_statuses_are_the_same_on_every_platform() {
        assert_eq!((128 + INT, 128 + HUP, 128 + QUIT, 128 + TERM), (130, 129, 131, 143));
        assert_eq!(number("KILL"), Some(9));
        if cfg!(not(target_os = "macos")) {
            assert_eq!((number("USR1"), number("USR2")), (Some(10), Some(12)));
        }
        for name in NAMES {
            assert!(number(name).is_some_and(|signal| (1..=31).contains(&signal)), "SIG{name}");
        }
    }

    #[test]
    fn a_name_ssh_does_not_give_has_no_number() {
        for name in ["WINCH", "SIGTERM", "term", "", "UNKNOWN"] {
            assert_eq!(number(name), None, "{name:?}");
        }
    }
}
