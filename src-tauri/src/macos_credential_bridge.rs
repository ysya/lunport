//! The credential migration's way to helper v1, which hands items only to a parent signed as the app was before 2.0.0. The bridge
//! (`signing/legacy/credential-bridge.c`) is signed that way and accepts only this app as its parent; it starts the helper v1 the app
//! names, checks it, and relays one request to it. The app installs both from their embedded bytes as it installs any credential
//! program, and sends the bridge only gets and deletes that forbid authorization UI, so nothing through the bridge lets macOS ask the
//! user anything. An item helper v1 may not reach without asking, and a chain that refuses to work on this computer, need the user's
//! permission instead (`needs_permission`): helper v2's adopt moves those once the user allows it.

use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use super::transport::{self, greet, header, receive, start, validate_input, Greeting, Response, Running, StartFailure};
use super::{frozen, refused, HelperSpec, Operation, EMBEDDED_BRIDGE, EMBEDDED_HELPER_V1, NOT_FOUND};
use crate::error::AppError;

/// How long the app waits for each read from the bridge: more than the 10 seconds the bridge gives helper v1 to answer a request that
/// forbids authorization UI, so that a silent helper is reported by the bridge rather than by this timeout.
const ANSWER: Duration = Duration::from_secs(20);
/// How long the bridge has to exit once its channel ended, before it is stopped.
const EXIT_GRACE: Duration = Duration::from_secs(2);
/// The longest helper v1 path the bridge takes, in bytes.
const MAX_PATH: usize = 1023;

/// What starts every error that means the user's permission is needed: helper v1 may not reach the item without asking, or the chain to
/// it refuses to work on this computer. Helper v2's adopt goes around both.
const PERMISSION: &str = "credential bridge: macOS needs your permission to move it: ";
/// What starts every error that means no answer came from helper v1 through the bridge, in a way that may pass by the next attempt.
const NO_ANSWER: &str = "credential bridge: helper v1 could not be reached: ";
/// What a saved value that is not text says: no retry makes it one.
const NOT_TEXT: &str = "credential bridge: the saved value is not text";

fn failure(message: impl std::fmt::Display) -> AppError {
    // Messages describe the operation, never its account, request or response.
    AppError::Other(format!("credential bridge: {message}"))
}

fn not_allowed(cause: &str) -> AppError {
    AppError::Other(format!("{PERMISSION}{cause}"))
}

fn unanswered(cause: impl std::fmt::Display) -> AppError {
    AppError::Other(format!("{NO_ANSWER}{cause}"))
}

/// Whether `error`, from `Session::get` or `Session::delete`, means the item needs the user's permission to move (helper v2's adopt):
/// helper v1 may not reach it without asking, which a request through the bridge never lets macOS do, or the bridge, or helper v1
/// behind it, refuses the chain on this computer.
pub(crate) fn needs_permission(error: &AppError) -> bool {
    matches!(error, AppError::Other(message) if message.starts_with(PERMISSION))
}

/// Whether `error`, from `Session::get` or `Session::delete`, means no answer came from helper v1 through the bridge (the bridge could
/// not be started, stopped early, or did not answer in time), in a way that may pass by the next attempt.
pub(crate) fn chain_failed(error: &AppError) -> bool {
    matches!(error, AppError::Other(message) if message.starts_with(NO_ANSWER))
}

/// `error`, which kept a session from opening, as no answer from helper v1 (`chain_failed`): like a bridge that keeps failing, it
/// reaches the permission sheet after a few attempts.
pub(crate) fn unreachable(error: AppError) -> AppError {
    if chain_failed(&error) {
        error
    } else {
        unanswered(error)
    }
}

/// Whether `error`, from `Session::get`, means the item can never be read: its value is not text.
pub(crate) fn unreadable_for_good(error: &AppError) -> bool {
    matches!(error, AppError::Other(message) if message == NOT_TEXT)
}

/// The bridge and helper v1, installed in the data root, and what the app pins of the bridge. Each request starts the bridge anew.
pub(crate) struct Session {
    bridge: PathBuf,
    spec: HelperSpec,
    helper: PathBuf,
    helper_magic: &'static [u8; 8],
}

impl Session {
    /// Installs the embedded bridge and helper v1 in this profile's data root, the same way the app installs every credential program,
    /// each checked against its spec (`super::bridge`, `super::helper_v1`). Only a signed Production build embeds them.
    pub(crate) fn open(bridge: &HelperSpec, v1: &HelperSpec) -> Result<Self, AppError> {
        let bridge_bytes = frozen(bridge, EMBEDDED_BRIDGE)?;
        let v1_bytes = frozen(v1, EMBEDDED_HELPER_V1)?;
        let root = crate::fsutil::app_data_root()?;
        crate::fsutil::ensure_dir_secure(&root)?;
        Self::open_in(&root, bridge, bridge_bytes, v1, v1_bytes)
    }

    /// `open`, installing in `root`.
    fn open_in(root: &Path, bridge: &HelperSpec, bridge_bytes: &[u8], v1: &HelperSpec, v1_bytes: &[u8]) -> Result<Self, AppError> {
        let install = |spec: &HelperSpec, bytes: &[u8]| {
            transport::install(root, spec, bytes).map_err(|_| {
                unanswered("cannot safely install the bridge and helper v1; check this device's application-data permissions")
            })
        };
        let helper = install(v1, v1_bytes)?;
        helper_path(&helper)?;
        Ok(Self { bridge: install(bridge, bridge_bytes)?, spec: bridge.clone(), helper, helper_magic: v1.magic() })
    }

    /// What helper v1 holds for `account` under the service versions before 2.0.0 saved under: `None` when it holds nothing.
    pub(crate) fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        got(self.relay(Operation::Get, account)?)
    }

    /// Asks helper v1 to delete what it holds for `account`; nothing there is fine.
    pub(crate) fn delete(&self, account: &str) -> Result<(), AppError> {
        deleted(self.relay(Operation::Delete, account)?)
    }

    /// Starts the bridge, checks that the live process is the signed bridge, sends it one request for helper v1 (`envelope`) and reads
    /// helper v1's answer, which the bridge relays only once helper v1 has exited and only with exit code 0.
    fn relay(&self, operation: Operation, account: &str) -> Result<Response, AppError> {
        if !matches!(operation, Operation::Get | Operation::Delete) {
            return Err(failure("the app sends the bridge only gets and deletes; nothing was sent"));
        }
        validate_input(operation, account, &[]).map_err(failure)?;
        let request = envelope(self.spec.magic(), helper_path(&self.helper)?, self.helper_magic, operation, account);
        let mut started = start(&self.bridge, ANSWER).map_err(|failed| match failed {
            StartFailure::Channel => unanswered("cannot create a private channel to the bridge"),
            StartFailure::Spawn => unanswered("cannot start the bridge"),
        })?;
        match greet(&mut started, &self.spec) {
            Ok(()) => {}
            // The bridge writes nothing to a parent it refuses: its exit code says why.
            Err(Greeting::Silent) => return Err(stopped(finish(&mut started.child))),
            Err(Greeting::NotPinned) => return Err(not_allowed("the running bridge is not the signed one Lunport pins; nothing was sent")),
        }
        if started.socket.write_all(&request).and_then(|_| started.socket.shutdown(std::net::Shutdown::Write)).is_err() {
            return Err(stopped(finish(&mut started.child)));
        }
        let response = receive(&mut started.socket, operation);
        match (response, finish(&mut started.child)) {
            (Ok(response), Some(0)) => Ok(response),
            (Err(_), Some(0)) => Err(unanswered("the bridge did not relay a complete answer")),
            (_, code) => Err(stopped(code)),
        }
    }
}

/// The bridge's request: its magic, the length (big-endian) and bytes of helper v1's path, then one complete helper v1 frame for
/// `operation` on `account`, without data and forbidding authorization UI.
fn envelope(magic: &[u8; 8], helper: &[u8], helper_magic: &[u8; 8], operation: Operation, account: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + helper.len() + 18 + account.len());
    frame.extend_from_slice(magic);
    frame.extend_from_slice(&(helper.len() as u32).to_be_bytes());
    frame.extend_from_slice(helper);
    frame.extend_from_slice(&header(helper_magic, operation, true, account.len(), 0));
    frame.extend_from_slice(account.as_bytes());
    frame
}

/// `path` as the bridge takes a helper path: absolute, 1 to 1023 bytes, without NUL.
fn helper_path(path: &Path) -> Result<&[u8], AppError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute() || bytes.is_empty() || bytes.len() > MAX_PATH || bytes.contains(&0) {
        return Err(unanswered("helper v1 is installed where the bridge cannot start it: its path is too long"));
    }
    Ok(bytes)
}

/// The bridge's exit code once it has exited: it has `EXIT_GRACE` after its channel ended, then it is stopped. `None` when it had
/// to be stopped, or a signal ended it.
fn finish(child: &mut Running) -> Option<i32> {
    let step = Duration::from_millis(20);
    for _ in 0..(EXIT_GRACE.as_millis() / step.as_millis()) {
        match child.0.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) => std::thread::sleep(step),
            Err(_) => return None,
        }
    }
    let _ = child.0.kill();
    let _ = child.0.wait();
    None
}

/// What the bridge's exit code says when it relayed nothing (`credential-bridge.c` documents each). A chain that refuses to work on
/// this computer (helper v1 refuses the bridge, the bridge refuses this app, the helper at the path is not the pinned one) needs the
/// user's permission instead; any other failure may pass by the next attempt (`chain_failed`).
fn stopped(code: Option<i32>) -> AppError {
    match code {
        Some(75) => not_allowed("helper v1 did not accept the bridge as its parent; nothing was relayed"),
        Some(77) => not_allowed("the bridge did not accept Lunport as its parent; nothing was sent"),
        Some(78) => not_allowed("the program installed as helper v1 is not the pinned one; nothing was relayed"),
        Some(64) => unanswered("the bridge refused the request as malformed; nothing was relayed"),
        Some(69) => unanswered("the bridge could not start helper v1; nothing was relayed"),
        Some(71) => unanswered("the bridge ran out of memory or process resources; nothing was relayed"),
        Some(74) => unanswered("the bridge lost its channel to Lunport, or a later check failed; nothing was relayed"),
        Some(76) => unanswered("helper v1 stopped without a complete answer"),
        Some(code) => unanswered(format!("the bridge stopped with exit code {code}")),
        None => unanswered("the bridge did not answer in time"),
    }
}

/// Helper v1's answer to a get: the value (text), nothing, or why not.
fn got(response: Response) -> Result<Option<Zeroizing<String>>, AppError> {
    match response.status {
        0 => text(response.data).map(Some),
        NOT_FOUND => Ok(None),
        status if refused(status) => Err(not_allowed("helper v1 may not read it without asking")),
        other => Err(failure(format!("helper v1 could not read it (OSStatus {other})"))),
    }
}

/// Helper v1's answer to a delete: gone (or never there), or why not.
fn deleted(response: Response) -> Result<(), AppError> {
    match response.status {
        0 | NOT_FOUND => Ok(()),
        status if refused(status) => Err(not_allowed("helper v1 may not delete it without asking")),
        other => Err(failure(format!("helper v1 could not delete it (OSStatus {other})"))),
    }
}

fn text(data: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, AppError> {
    std::str::from_utf8(&data).map(|text| Zeroizing::new(text.to_owned())).map_err(|_| AppError::Other(NOT_TEXT.into()))
}

#[cfg(test)]
mod tests {
    use super::super::{bridge, helper_v1};
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const BRIDGE_PATH: &str = "credential-helper/bridge/Lunport Credential Bridge";
    const V1_PATH: &str = "credential-helper/v1/Lunport Credential Helper";

    fn response(status: i32, data: &[u8]) -> Response {
        Response { status, data: Zeroizing::new(data.to_vec()) }
    }

    /// One request to the bridge: its magic, helper v1's path, then a helper v1 frame that forbids authorization UI.
    #[test]
    fn a_bridge_request_is_its_envelope_around_one_helper_v1_frame() {
        let request = envelope(bridge().magic(), b"/data/v1/Helper", helper_v1().magic(), Operation::Get, "host:web");
        assert_eq!(
            request,
            [&b"LPKB0001\x00\x00\x00\x0f/data/v1/Helper"[..], b"LPKC0001\x01\x01\x00\x00\x00\x08\x00\x00\x00\x00host:web"].concat()
        );
        let delete = envelope(bridge().magic(), b"/h", helper_v1().magic(), Operation::Delete, "vault:key");
        assert_eq!(delete, [&b"LPKB0001\x00\x00\x00\x02/h"[..], b"LPKC0001\x03\x01\x00\x00\x00\x09\x00\x00\x00\x00vault:key"].concat());
    }

    #[test]
    fn the_bridge_takes_an_absolute_helper_path_of_at_most_1023_bytes() {
        assert_eq!(helper_path(Path::new("/data/v1/Helper")).unwrap(), b"/data/v1/Helper");
        let longest = format!("/{}", "a".repeat(MAX_PATH - 1));
        assert_eq!(helper_path(Path::new(&longest)).unwrap().len(), MAX_PATH);
        assert!(helper_path(Path::new(&format!("/{}", "a".repeat(MAX_PATH)))).is_err());
        assert!(helper_path(Path::new("relative/Helper")).is_err());
        assert!(helper_path(Path::new("")).is_err());
    }

    /// Every documented exit code of the bridge reads as what happened; the chain refusing to work on this computer needs the user's
    /// permission, anything else may pass.
    #[test]
    fn each_exit_code_of_the_bridge_says_what_happened() {
        let says = |code: Option<i32>| {
            let error = stopped(code);
            assert!(!(needs_permission(&error) && chain_failed(&error)), "{error}");
            (needs_permission(&error), error.to_string())
        };
        for (code, words) in [
            (75, "helper v1 did not accept the bridge as its parent"),
            (77, "the bridge did not accept Lunport as its parent"),
            (78, "not the pinned one"),
        ] {
            let (permission, message) = says(Some(code));
            assert!(permission && message.contains(words), "{code}: {message}");
            assert!(!chain_failed(&stopped(Some(code))));
        }
        for (code, words) in [
            (Some(64), "malformed"),
            (Some(69), "could not start helper v1"),
            (Some(71), "out of memory"),
            (Some(74), "lost its channel"),
            (Some(76), "helper v1 stopped"),
            (Some(3), "exit code 3"),
            (None, "did not answer in time"),
        ] {
            let (permission, message) = says(code);
            assert!(!permission && message.contains(words), "{code:?}: {message}");
            assert!(chain_failed(&stopped(code)), "no answer came, and that may pass: {message}");
            assert!(message.starts_with("credential bridge: "), "{message}");
        }
    }

    /// Helper v1's statuses, relayed unchanged: a refusal needs the user's permission (adopt), a value that is not text never becomes
    /// one, a missing item is nothing to move.
    #[test]
    fn helper_v1_answers_through_the_bridge() {
        assert_eq!(got(response(0, b"hunter2")).unwrap().as_deref().map(String::as_str), Some("hunter2"));
        assert_eq!(got(response(NOT_FOUND, b"")).unwrap(), None);
        for status in [-128, -25293, -25308] {
            let refusal = got(response(status, b"")).unwrap_err();
            assert!(needs_permission(&refusal) && !unreadable_for_good(&refusal), "{refusal}");
            assert!(needs_permission(&deleted(response(status, b"")).unwrap_err()));
        }
        let damaged = got(response(0, &[0xff, 0xfe])).unwrap_err();
        assert!(unreadable_for_good(&damaged) && !needs_permission(&damaged), "{damaged}");
        let other = got(response(-34018, b"")).unwrap_err();
        assert!(!needs_permission(&other) && !unreadable_for_good(&other) && other.to_string().contains("OSStatus -34018"));
        // Helper v1 answered, whatever it said.
        for answered in [got(response(-128, b"")).unwrap_err(), damaged, other] {
            assert!(!chain_failed(&answered), "{answered}");
        }
        assert!(deleted(response(0, b"")).is_ok() && deleted(response(NOT_FOUND, b"")).is_ok());
        assert!(!needs_permission(&deleted(response(-34018, b"")).unwrap_err()));
    }

    /// A bridge and a helper v1 for this test: `bridge_script` and `v1_bytes` stand in for their programs.
    fn session(root: &Path, bridge_script: &str) -> Session {
        let v1_bytes = b"helper v1 stand-in";
        let bridge = HelperSpec::fixture(BRIDGE_PATH, b"LPKB0001", 1, bridge_script.as_bytes());
        let v1 = HelperSpec::fixture(V1_PATH, b"LPKC0001", 1, v1_bytes);
        Session::open_in(root, &bridge, bridge_script.as_bytes(), &v1, v1_bytes).unwrap()
    }

    #[test]
    fn the_bridge_and_helper_v1_are_installed_each_in_its_own_folder() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let opened = session(temp.path(), "#!/bin/sh\nexit 77\n");
        assert_eq!(opened.bridge, temp.path().join(BRIDGE_PATH));
        assert_eq!(opened.helper, temp.path().join(V1_PATH));
        assert_eq!(fs::metadata(&opened.bridge).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::read(&opened.helper).unwrap(), b"helper v1 stand-in");
        // Bytes that are not the programs the specs pin are not installed.
        let other = HelperSpec::fixture(BRIDGE_PATH, b"LPKB0001", 1, b"another program");
        let v1 = HelperSpec::fixture(V1_PATH, b"LPKC0001", 1, b"helper v1 stand-in");
        let refused = Session::open_in(temp.path(), &other, b"not that program", &v1, b"helper v1 stand-in");
        assert!(refused.is_err());
    }

    /// The bridge writes nothing to a parent it refuses and exits 77: the app says so, and that needs the user's permission.
    #[test]
    fn a_bridge_that_refuses_this_app_says_why() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let opened = session(temp.path(), "#!/bin/sh\nexit 77\n");
        let failure = opened.get("host:web-1").unwrap_err();
        assert!(needs_permission(&failure) && failure.to_string().contains("did not accept Lunport"), "{failure}");
        let failure = opened.delete("host:web-1").unwrap_err();
        assert!(needs_permission(&failure), "{failure}");
    }

    /// A bridge that stops before it greets, for a reason that may pass, or that cannot be started at all, got no answer from helper
    /// v1: that may pass by the next attempt, and asks nobody for permission.
    #[test]
    fn a_bridge_that_stops_early_or_cannot_start_got_no_answer() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let opened = session(temp.path(), "#!/bin/sh\nexit 69\n");
        let failure = opened.get("host:web-1").unwrap_err();
        assert!(chain_failed(&failure) && !needs_permission(&failure) && failure.to_string().contains("could not start helper v1"), "{failure}");
        fs::remove_file(&opened.bridge).unwrap();
        let failure = opened.delete("host:web-1").unwrap_err();
        assert!(chain_failed(&failure) && failure.to_string().contains("cannot start the bridge"), "{failure}");
    }

    /// A program at the bridge's path that greets as another program, or is not the signed bridge, is sent nothing.
    #[test]
    fn a_bridge_that_is_not_the_signed_one_is_sent_nothing() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let received = temp.path().join("received");
        for hello in ["LPKC0001", "LPKB0001"] {
            let _ = fs::remove_file(&received);
            let script = format!("#!/bin/sh\nprintf '%s' '{hello}'\nexec /bin/cat > '{}'\n", received.display());
            let opened = session(temp.path(), &script);
            let failure = opened.get("host:web-1").unwrap_err();
            assert!(needs_permission(&failure) && failure.to_string().contains("nothing was sent"), "{hello}: {failure}");
            assert_eq!(fs::read(&received).unwrap_or_default(), b"", "{hello}: nothing reaches it");
        }
    }

    /// A session that cannot be opened (helper v1 or the bridge cannot be installed, its path is too long for the bridge) got no answer
    /// from helper v1 either: like a bridge that keeps failing, it reaches the permission sheet after a few attempts.
    #[test]
    fn a_session_that_cannot_be_opened_got_no_answer() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let bridge = HelperSpec::fixture(BRIDGE_PATH, b"LPKB0001", 1, b"the bridge");
        let v1 = HelperSpec::fixture(V1_PATH, b"LPKC0001", 1, b"helper v1");
        let failure = Session::open_in(temp.path(), &bridge, b"another program", &v1, b"helper v1").err().expect("not installed");
        assert!(chain_failed(&failure) && !needs_permission(&failure), "{failure}");
        let opened = unreachable(AppError::Other("the data folder cannot be found".into()));
        assert!(chain_failed(&opened) && opened.to_string().contains("the data folder cannot be found"), "{opened}");
        assert_eq!(unreachable(stopped(None)).to_string(), stopped(None).to_string(), "said once");
    }

    /// Only gets and deletes ever go to the bridge, and a malformed one starts nothing.
    #[test]
    fn only_well_formed_gets_and_deletes_go_to_the_bridge() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let started = temp.path().join("started");
        let opened = session(temp.path(), &format!("#!/bin/sh\n: > '{}'\nexit 77\n", started.display()));
        for operation in [Operation::Set, Operation::Adopt] {
            assert!(opened.relay(operation, "host:web-1").unwrap_err().to_string().contains("only gets and deletes"));
        }
        for account in ["", "a\0b"] {
            assert!(opened.get(account).is_err());
        }
        assert!(opened.get(&"a".repeat(transport::MAX_ACCOUNT + 1)).is_err());
        assert!(!started.exists(), "the bridge was not even started");
        assert!(opened.get("host:web-1").is_err());
        assert!(started.exists(), "a well-formed get starts it");
    }

    /// Only a signed Production build embeds the bridge and helper v1: this build opens no session, before it touches the data root.
    #[cfg(any(debug_assertions, feature = "development-profile"))]
    #[test]
    fn a_development_build_opens_no_session() {
        let failure = Session::open(&bridge(), &helper_v1()).err().expect("no session");
        assert!(failure.to_string().contains("only signed Production builds"), "{failure}");
    }

    /// Only the disposable CI runner signs this test binary as the app, with the project certificate. It reaches the frozen helper v1
    /// through the frozen bridge, both read from the checkout (the bytes a Production build embeds), as the credential migration does,
    /// and asks about an account no item has: nothing is created, changed or asked, and no item's data is read.
    #[test]
    #[ignore = "requires a disposable macOS runner and a test executable signed as the app"]
    fn native_frozen_bridge_probe() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(std::env::var("RUNNER_OS").as_deref(), Ok("macOS"));
        let run = std::env::var("GITHUB_RUN_ID").unwrap();
        assert!(!run.is_empty() && run.bytes().all(|b| b.is_ascii_digit()));
        let account = format!("lunport-ci-bridge-{run}");
        let committed = |path: &str| fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap();
        let bridge_bytes = committed("signing/legacy/credential-bridge.bin");
        let v1_bytes = committed("signing/legacy/credential-helper-v1.bin");
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let session = Session::open_in(temp.path(), &bridge(), &bridge_bytes, &helper_v1(), &v1_bytes).unwrap();
        // The whole chain answered: the bridge accepted this app, helper v1 accepted the bridge, and each pin held.
        assert_eq!(session.get(&account).unwrap(), None);
        session.delete(&account).unwrap();
        assert_eq!(session.get(&account).unwrap(), None);
    }
}
