//! The macOS preferences domain, copied from the old name to the new one beside the WebKit store. Best effort: a failure is noted in
//! the journal and nothing waits for it.

use std::path::PathBuf;

/// A macOS preferences domain under both names, and the old domain's file.
#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct Preferences {
    pub old_domain: String,
    pub new_domain: String,
    pub old_file: PathBuf,
}

/// Copies the preferences of the old name into the new one's when the old ones exist and the new name has none, and says whether it
/// did. It goes through `defaults`, that is through cfprefsd, which caches preference domains: so it reads settings an earlier version
/// has not written to its file yet, and a process that has read the new domain already sees the copy. Copying the file itself
/// gives neither.
#[cfg(target_os = "macos")]
pub(crate) fn copy(preferences: &Preferences) -> Result<bool, String> {
    if !std::fs::metadata(&preferences.old_file).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0) {
        return Ok(false);
    }
    let old = defaults(&["export", &preferences.old_domain, "-"], None)?;
    if has_no_settings(&old)? {
        return Ok(false);
    }
    // Settings the new name has already stay as they are.
    if !has_no_settings(&defaults(&["export", &preferences.new_domain, "-"], None)?)? {
        return Ok(false);
    }
    defaults(&["import", &preferences.new_domain, "-"], Some(old))?;
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn copy(_: &Preferences) -> Result<bool, String> {
    Ok(false)
}

/// Whether the property list `bytes` (what `defaults export` writes) holds no setting.
#[cfg(target_os = "macos")]
fn has_no_settings(bytes: &[u8]) -> Result<bool, String> {
    let value =
        plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(|error| format!("cannot read the preferences: {error}"))?;
    Ok(value.as_dictionary().is_none_or(|settings| settings.is_empty()))
}

/// The longest a `defaults` command may take: a start must not hang on it.
#[cfg(target_os = "macos")]
const DEFAULTS_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Runs `/usr/bin/defaults` with `args`, `input` on its standard input, and returns its standard output.
#[cfg(target_os = "macos")]
fn defaults(args: &[&str], input: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut command = Command::new("/usr/bin/defaults");
    command
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = crate::process::spawn(&mut command).map_err(|error| format!("cannot run defaults: {error}"))?;
    let (mut stdin, mut stdout) = (child.stdin.take(), child.stdout.take());
    // One thread feeds the input and then reads the output, so that a large property list can fill neither pipe while this one waits.
    let io = std::thread::Builder::new()
        .name(crate::identity::thread_name("migration-defaults"))
        .spawn(move || -> std::io::Result<Vec<u8>> {
            if let (Some(input), Some(pipe)) = (input, stdin.as_mut()) {
                pipe.write_all(&input)?;
            }
            drop(stdin);
            let mut output = Vec::new();
            if let Some(pipe) = stdout.as_mut() {
                pipe.read_to_end(&mut output)?;
            }
            Ok(output)
        })
        .map_err(|error| format!("cannot run defaults: {error}"))?;
    let deadline = Instant::now() + DEFAULTS_WAIT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            stopped => {
                // Stopped, so that its pipes close and the thread above ends.
                let _ = child.kill();
                let _ = child.wait();
                break Err(match stopped {
                    Err(error) => format!("cannot wait for defaults: {error}"),
                    _ => format!("defaults {} did not finish", args[0]),
                });
            }
        }
    };
    let output = io.join().map_err(|_| "defaults' output was lost".to_string())?;
    let status = status?;
    if !status.success() {
        return Err(format!("defaults {} failed ({status})", args[0]));
    }
    output.map_err(|error| format!("cannot talk to defaults: {error}"))
}
