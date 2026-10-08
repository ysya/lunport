//! Helpers for child processes that run behind the desktop UI.
//!
//! A GUI-subsystem process has no console on Windows. Starting a console
//! program from it without `CREATE_NO_WINDOW` makes Windows create a transient
//! Command Prompt window, even when stdout/stderr are piped. Commands launched
//! intentionally *inside a terminal* must not use this helper.

use std::ffi::OsStr;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{PoisonError, RwLock};

/// Build a background command that never creates a console window on Windows.
pub fn background_command<S: AsRef<OsStr>>(program: S) -> Command {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        let mut command = Command::new(program);
        // WinBase.h: CREATE_NO_WINDOW. Keep this local so hiding background
        // processes does not require a Windows-only runtime dependency.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }

    #[cfg(not(target_os = "windows"))]
    {
        Command::new(program)
    }
}

/// spawn 與「不能被子程序拿走的 fd」之間的鎖。spawn 拿共用的一份(彼此不擋),`without_spawns` 拿獨占的一份。
///
/// 為什麼要鎖:spawn 的時候,子程序拿到父程序**所有** fd 的複本,CLOEXEC 的也一樣,要到它換成新程式時才關掉(macOS 的 posix_spawn
/// 在核心裡先複製整張 fd 表,載入新程式時才關;Linux 的 execve 甚至在 spawn 回來之後才關)。這段期間另一條執行緒關掉自己那一份,
/// 東西其實還開著:socket 還在聽、檔案鎖還沒放。macOS 更糟:`socket()`、`accept()` 沒有原子的 CLOEXEC,std 建好之後才另外設,
/// 中間 spawn 出去的子程序拿到的是**沒有** CLOEXEC 的複本,一直帶到它結束。子程序握著 agent 的 listening socket,SSHelter 結束
/// 之後 ssh 仍連得上、卻沒人回應,就卡住。
///
/// 所以:這個 crate 的 spawn 都經過 `spawn`/`output`(clippy.toml 擋掉直接呼叫;spawn 完就放鎖,子程序跑多久都不擋);建立或接受
/// 這種 fd 的地方包在 `without_spawns` 裡:那段時間沒有子程序被建立,建好時 CLOEXEC 也已經設好。在裡面建立、也在裡面關掉的 fd,
/// 沒有任何子程序拿得到。
static SPAWNING: RwLock<()> = RwLock::new(());

/// `command.spawn()`,但不會跟 `without_spawns` 同時進行。
#[allow(clippy::disallowed_methods)] // 唯一直接 spawn 的地方
pub fn spawn(command: &mut Command) -> std::io::Result<Child> {
    let _spawning = SPAWNING.read().unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}

/// 同 `command.output()`(stdin 接 null、stdout 與 stderr 收下來),spawn 經過 `spawn`;等子程序結束時不拿鎖。
pub fn output(command: &mut Command) -> std::io::Result<Output> {
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    spawn(command)?.wait_with_output()
}

/// 執行 `f`,期間沒有經過 `spawn` 的 spawn 在進行,也不會開始。`f` 不能 spawn(會鎖死),也不該等太久(spawn 都在等它)。
pub fn without_spawns<T>(f: impl FnOnce() -> T) -> T {
    let _quiet = SPAWNING.write().unwrap_or_else(PoisonError::into_inner);
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn quick_command() -> Command {
        #[cfg(windows)]
        {
            let mut command = Command::new("cmd");
            command.args(["/C", "exit"]);
            command
        }
        #[cfg(not(windows))]
        Command::new("true")
    }

    /// `without_spawns` 執行期間,別的執行緒的 spawn 等著;結束之後 spawn 照常進行。
    #[test]
    fn a_spawn_waits_until_without_spawns_is_done() {
        let (spawned_tx, spawned) = mpsc::channel();
        let spawner = without_spawns(|| {
            let spawner = std::thread::spawn(move || {
                let mut child = spawn(&mut quick_command()).unwrap();
                spawned_tx.send(()).unwrap();
                child.wait().unwrap()
            });
            assert!(spawned.recv_timeout(Duration::from_millis(300)).is_err(), "no spawn while without_spawns runs");
            spawner
        });
        spawned.recv_timeout(Duration::from_secs(10)).expect("the spawn goes ahead afterwards");
        assert!(spawner.join().unwrap().success());
    }

    /// `output` 同 `Command::output`:收下 stdout 與 stderr,stdin 是空的。
    #[cfg(unix)]
    #[test]
    fn output_captures_both_streams_and_gives_an_empty_stdin() {
        let out = output(Command::new("sh").args(["-c", "cat; printf out; printf err >&2"])).unwrap();
        assert!(out.status.success());
        assert_eq!((out.stdout.as_slice(), out.stderr.as_slice()), (&b"out"[..], &b"err"[..]));
    }
}
