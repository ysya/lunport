//! `sshelter-cli.exe` (src/lib.rs). A console program: no `windows_subsystem` attribute, on purpose — the terminal has to give it a
//! console and wait for it.

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    std::process::exit(sshelter_cli::run(&args, &mut std::io::stderr()));
}
