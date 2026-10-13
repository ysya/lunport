//! The helper's relay against a real program: this test binary itself. Started with `SSHELTER_CLI_TEST_RECORD` set, it is the program
//! at the end of the relay: it writes the arguments it was given to that file and exits with the code in `SSHELTER_CLI_TEST_EXIT`.
//! Otherwise it runs the tests below, which start it through `sshelter_cli::relay` and, on Windows, through the built `sshelter-cli.exe`
//! next to a copy of it named `sshelter.exe`. It has no test harness (Cargo.toml): a harness would read the program's arguments as its own
//! options and test filters.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Set for the program at the end of the relay: the file it writes its arguments to.
const RECORD: &str = "SSHELTER_CLI_TEST_RECORD";
/// The exit code that program leaves with.
const EXIT: &str = "SSHELTER_CLI_TEST_EXIT";

fn main() {
    if let Some(record) = std::env::var_os(RECORD) {
        be_the_target(Path::new(&record));
    }
    let tests: &[(&str, fn())] = &[
        ("arguments_reach_the_target_untouched", arguments_reach_the_target_untouched),
        ("the_exit_code_comes_back", the_exit_code_comes_back),
        #[cfg(windows)]
        ("the_built_helper_runs_the_sshelter_exe_beside_it", the_built_helper_runs_the_sshelter_exe_beside_it),
        #[cfg(not(windows))]
        ("outside_windows_the_built_helper_only_says_it_is_for_windows", outside_windows_the_built_helper_only_says_it_is_for_windows),
    ];
    println!("\nrunning {} tests", tests.len());
    for (name, test) in tests {
        test();
        println!("test {name} ... ok");
    }
    println!("\ntest result: ok. {} passed\n", tests.len());
}

/// The program at the end of the relay: writes down what it was given and leaves with the exit code it was told.
fn be_the_target(record: &Path) -> ! {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    std::fs::write(record, format!("{args:?}")).expect("the target writes down its arguments");
    let code = std::env::var(EXIT).ok().and_then(|code| code.parse().ok()).unwrap_or(0);
    std::process::exit(code)
}

/// Arguments that a shell, or quoting done wrong, would change — spaces, quotes, backslashes before a quote and at the end, an empty one,
/// a leading dash, `%PATH%`, `^`, `&` and `|`, a tab and a newline, text that is not ASCII, and one that is not text at all — reach the
/// program exactly as the helper got them.
fn arguments_reach_the_target_untouched() {
    let scratch = Scratch::new("arguments");
    let record = scratch.0.join("record");
    let args = awkward_arguments();
    let code = as_target(&record, 0, || sshelter_cli::relay(&this_program(), &args, &mut std::io::stderr()));
    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&record).unwrap(), format!("{args:?}"));
}

/// The program's exit code is the helper's: `sshelter connect`'s 2 for the usage, 130 for Ctrl-C, 255 for a lost connection, and on
/// Windows any 32-bit code (here STATUS_CONTROL_C_EXIT).
fn the_exit_code_comes_back() {
    let scratch = Scratch::new("codes");
    let record = scratch.0.join("record");
    let mut codes = vec![0, 1, 2, 7, 129, 130, 255];
    if cfg!(windows) {
        codes.push(0xC000_013A_u32 as i32);
    }
    for code in codes {
        let relayed = as_target(&record, code, || sshelter_cli::relay(&this_program(), &[OsString::from("connect")], &mut std::io::stderr()));
        assert_eq!(relayed, code);
    }
}

/// The built `sshelter-cli.exe` in a directory with a space in its name, next to a `sshelter.exe` (a copy of this program): it runs it
/// with its own arguments and leaves with its exit code. Without the `sshelter.exe` it says where it looked, and 1.
#[cfg(windows)]
fn the_built_helper_runs_the_sshelter_exe_beside_it() {
    let scratch = Scratch::new("installed");
    let dir = scratch.0.join("Program Files").join("SSHelter");
    std::fs::create_dir_all(&dir).unwrap();
    let helper = dir.join("sshelter-cli.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_sshelter-cli"), &helper).unwrap();
    std::fs::copy(this_program(), dir.join("sshelter.exe")).unwrap();
    let record = scratch.0.join("record");
    let args = awkward_arguments();
    let run = std::process::Command::new(&helper).args(&args).env(RECORD, &record).env(EXIT, "2").output().unwrap();
    assert_eq!(run.status.code(), Some(2), "{run:?}");
    assert_eq!(std::fs::read_to_string(&record).unwrap(), format!("{args:?}"));

    std::fs::remove_file(dir.join("sshelter.exe")).unwrap();
    let run = std::process::Command::new(&helper).arg("connect").output().unwrap();
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    let said = String::from_utf8(run.stderr).unwrap();
    // The helper names its directory as Windows gives it its own path, which can spell it differently (short names): compare the
    // directories themselves.
    let named = said
        .strip_prefix("sshelter-cli: cannot find sshelter.exe in ")
        .and_then(|rest| rest.strip_suffix(".\n"))
        .unwrap_or_else(|| panic!("{said:?}"));
    assert_eq!(std::fs::canonicalize(named).unwrap(), std::fs::canonicalize(&dir).unwrap(), "{said:?}");
}

/// Outside Windows the built helper only says that it is for Windows, and 1.
#[cfg(not(windows))]
fn outside_windows_the_built_helper_only_says_it_is_for_windows() {
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_sshelter-cli")).args(["connect", "web"]).output().unwrap();
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    assert_eq!(String::from_utf8(run.stderr).unwrap(), format!("{}\n", sshelter_cli::NOT_WINDOWS));
}

/// The arguments of `arguments_reach_the_target_untouched`.
fn awkward_arguments() -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "connect",
        "--id",
        "two words",
        "say \"hi\"",
        "",
        "trailing\\",
        "back\\\"slash",
        "\\\\server\\share dir\\",
        "%PATH%",
        "a^b&c|d<e>f",
        "'single'",
        "-x",
        "tab\there",
        "new\nline",
        "naïve 日本 🙂",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.push(not_text());
    args
}

/// An argument that is not text: bytes that are not UTF-8 on Unix, a lone surrogate on Windows.
#[cfg(unix)]
fn not_text() -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(b"w\xffb".to_vec())
}

#[cfg(windows)]
fn not_text() -> OsString {
    use std::os::windows::ffi::OsStringExt;
    OsString::from_wide(&[0x77, 0xD800, 0x62])
}

/// Runs `f` with this program set up as the target: it will write its arguments to `record` and exit with `code`. (The variables are
/// inherited by the target; this binary runs its tests on one thread, so setting them is safe.)
fn as_target<T>(record: &Path, code: i32, f: impl FnOnce() -> T) -> T {
    let _ = std::fs::remove_file(record);
    std::env::set_var(RECORD, record);
    std::env::set_var(EXIT, code.to_string());
    let result = f();
    std::env::remove_var(RECORD);
    std::env::remove_var(EXIT);
    result
}

fn this_program() -> PathBuf {
    std::env::current_exe().unwrap()
}

/// A new empty directory under the system's temporary directory, removed with everything in it when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("sshelter-cli-relay-{}-{name}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
