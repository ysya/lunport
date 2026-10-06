//! 發出請求的程式(金鑰保管庫 spec §5.4):從連上 agent 的程序往上找父程序。只是推測:同一使用者的程式可以偽造,所以只用來分組記住核准
//! 與顯示,不當成安全保證。完整的命令列不保存。

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    /// 執行檔的實際路徑(macOS 的 `proc_pidpath`,Linux 的 `/proc/<pid>/exe`,Windows 的 `QueryFullProcessImageNameW`)。
    pub path: Option<String>,
    /// argv(只用來找直譯器的腳本;Windows 不取)。
    pub argv: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// 顯示用的名稱,由外到內(最外層的 App 在前,連上 agent 的程序在後)。
    pub chain: Vec<String>,
    /// 記住核准用:`<App 的路徑>|<程式的路徑>[ + <腳本>]`。
    pub identity: String,
}

const SKIP: &[&str] = &[
    "ssh", "ssh-keygen", "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "nu", "pwsh", "powershell", "cmd", "login", "env", "sudo",
];
const SYSTEM: &[&str] = &["launchd", "init", "systemd", "explorer", "services", "wininit", "svchost", "system"];
const INTERPRETERS: &[&str] = &["node", "python", "python3", "ruby", "perl", "bun", "deno"];

/// 路徑的檔名(`/` 與 `\` 都當分隔),去掉 `.exe`(大小寫都算,Windows 的檔名不分大小寫)。
fn file_name(path: &str) -> &str {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    // 檔名可以有多位元組的字:切之前先確認那個位置是字元的邊界。
    match name.len().checked_sub(4) {
        Some(cut) if name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(".exe") => &name[..cut],
        _ => name,
    }
}

/// `…/<X>.app/Contents/MacOS/<exe>` → `X`(bundle 的主程式);其他(bundle 裡的其他執行檔)→ None。
fn bundle_name(path: &str) -> Option<&str> {
    let parts: Vec<&str> = path.split('/').collect();
    let n = parts.len();
    (n >= 4 && parts[n - 2] == "MacOS" && parts[n - 3] == "Contents" && parts[n - 4].ends_with(".app"))
        .then(|| parts[n - 4].trim_end_matches(".app"))
}

fn base_lower(p: &ProcInfo) -> Option<String> {
    p.path.as_deref().map(|path| file_name(path).to_ascii_lowercase())
}

fn is_system(p: &ProcInfo) -> bool {
    p.pid <= 1 || base_lower(p).is_some_and(|b| SYSTEM.contains(&b.as_str()))
}

fn is_skipped(p: &ProcInfo) -> bool {
    base_lower(p).is_some_and(|b| SKIP.contains(&b.as_str()) || b.starts_with('-'))
}

fn is_interpreter(base: &str) -> bool {
    INTERPRETERS.contains(&base) || base.starts_with("python3.")
}

fn display(p: &ProcInfo) -> String {
    let path = p.path.as_deref().unwrap_or("?");
    bundle_name(path).map(str::to_string).unwrap_or_else(|| file_name(path).to_string())
}

/// 由程序鏈(`chain[0]` 是連上 agent 的程序,往後是父程序)算出名稱鏈與識別值;認不出來 → None。
pub fn identify(chain: &[ProcInfo]) -> Option<Program> {
    let useful: Vec<&ProcInfo> = chain.iter().take_while(|p| !is_system(p)).filter(|p| p.path.is_some()).collect();
    let program = useful.iter().find(|p| !is_skipped(p))?;
    let app = useful
        .iter()
        .rev()
        .find(|p| p.path.as_deref().and_then(bundle_name).is_some())
        .or_else(|| useful.last())?;
    let program_path = program.path.clone()?;
    let base = file_name(&program_path).to_ascii_lowercase();
    let program_id = if is_interpreter(&base) {
        let inline = program.argv.iter().skip(1).any(|a| a == "-e" || a == "-c" || a == "--eval");
        match program.argv.iter().skip(1).find(|a| !a.starts_with('-')) {
            _ if inline => format!("{program_path} + <inline>"),
            Some(script) => format!("{program_path} + {script}"),
            None => program_path.clone(),
        }
    } else {
        program_path.clone()
    };
    Some(Program {
        chain: useful.iter().rev().map(|p| display(p)).collect(),
        identity: format!("{}|{}", app.path.clone()?, program_id),
    })
}

/// 從 `pid` 往上找父程序(最多 64 層)。讀不到的程序(已經結束)→ 鏈到那裡為止;一開始就讀不到 → 空的。
pub fn process_chain(pid: u32) -> Vec<ProcInfo> {
    let mut out = Vec::new();
    let mut current = pid;
    while out.len() < 64 {
        let Some(info) = proc_info(current) else { break };
        let parent = info.ppid;
        let stop = current <= 1 || parent == current;
        out.push(info);
        if stop {
            break;
        }
        current = parent;
    }
    out
}

#[cfg(target_os = "macos")]
fn proc_info(pid: u32) -> Option<ProcInfo> {
    let pid = i32::try_from(pid).ok()?;
    // SAFETY: `proc_bsdinfo` is plain old data; `proc_pidinfo` fills at most `size` bytes.
    let info = unsafe {
        let mut info = std::mem::zeroed::<libc::proc_bsdinfo>();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let n = libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut libc::c_void, size);
        (n == size).then_some(info)?
    };
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is `PROC_PIDPATHINFO_MAXSIZE` bytes long.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    let path = (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned());
    Some(ProcInfo { pid: pid as u32, ppid: info.pbi_ppid, path, argv: macos_argv(pid).unwrap_or_default() })
}

/// `KERN_PROCARGS2`:`int argc`、執行時給的路徑與 NUL 填充、`argv[0..argc]`、環境變數。
#[cfg(target_os = "macos")]
fn macos_argv(pid: i32) -> Option<Vec<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: sysctl with a null buffer only reports the size; the second call fills at most `size` bytes.
    unsafe {
        if libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
    }
    let mut buf = vec![0u8; size];
    unsafe {
        if libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr() as *mut libc::c_void, &mut size, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
    }
    buf.truncate(size);
    let argc = i32::from_ne_bytes(buf.get(0..4)?.try_into().ok()?);
    let mut rest = &buf[4..];
    let nul = rest.iter().position(|&b| b == 0)?;
    rest = &rest[nul..];
    while rest.first() == Some(&0) {
        rest = &rest[1..];
    }
    let mut argv = Vec::new();
    for _ in 0..argc.max(0) {
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        argv.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        rest = &rest[(end + 1).min(rest.len())..];
    }
    Some(argv)
}

/// Linux:執行中的檔案被換掉(例如套件更新)之後,`/proc/<pid>/exe` 讀到「<原路徑> (deleted)」。
#[cfg(any(target_os = "linux", test))]
fn without_deleted_suffix(path: String) -> String {
    match path.strip_suffix(" (deleted)") {
        Some(original) => original.to_string(),
        None => path,
    }
}

#[cfg(target_os = "linux")]
fn proc_info(pid: u32) -> Option<ProcInfo> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid …`:comm 可能含空白與括號,從最後一個 `)` 之後讀。
    let after = &stat[stat.rfind(')')? + 1..];
    let ppid = after.split_whitespace().nth(1)?.parse().ok()?;
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| without_deleted_suffix(p.display().to_string()));
    let argv = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| bytes.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
        .unwrap_or_default();
    Some(ProcInfo { pid, ppid, path, argv })
}

#[cfg(windows)]
fn proc_info(pid: u32) -> Option<ProcInfo> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
    // SAFETY: standard Toolhelp iteration; `dwSize` is set before the first call; every handle is closed.
    let ppid = unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            if entry.th32ProcessID == pid {
                found = Some(entry.th32ParentProcessID);
                break;
            }
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        found?
    };
    // SAFETY: the handle is checked and closed; the buffer length is passed in and updated by the call.
    let path = unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            None
        } else {
            let mut buf = vec![0u16; 32768];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(handle);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    };
    Some(ProcInfo { pid, ppid, path, argv: Vec::new() })
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn proc_info(_pid: u32) -> Option<ProcInfo> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, ppid: u32, path: &str, argv: &[&str]) -> ProcInfo {
        ProcInfo { pid, ppid, path: Some(path.to_string()), argv: argv.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn claude_code_running_ssh_names_the_app_and_the_program() {
        let chain = vec![
            p(50, 40, "/usr/bin/ssh", &["ssh", "web"]),
            p(40, 30, "/bin/zsh", &["zsh", "-c", "ssh web"]),
            p(30, 20, "/Users/u/Library/Application Support/Claude/claude-code/2.1/x/claude.app/Contents/MacOS/claude", &["claude"]),
            p(20, 10, "/Applications/Claude.app/Contents/Helpers/disclaimer", &["disclaimer"]),
            p(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude", &["Claude"]),
            p(1, 0, "/sbin/launchd", &["launchd"]),
        ];
        let program = identify(&chain).unwrap();
        assert_eq!(program.chain, vec!["Claude", "disclaimer", "claude", "zsh", "ssh"]);
        assert_eq!(
            program.identity,
            "/Applications/Claude.app/Contents/MacOS/Claude|/Users/u/Library/Application Support/Claude/claude-code/2.1/x/claude.app/Contents/MacOS/claude"
        );
    }

    #[test]
    fn git_from_a_terminal_is_git_not_xcode_and_is_told_apart_from_claudes_git() {
        let terminal = vec![
            p(60, 50, "/usr/bin/ssh", &["ssh"]),
            p(50, 40, "/Applications/Xcode.app/Contents/Developer/usr/bin/git", &["git", "fetch"]),
            p(40, 30, "/bin/zsh", &["-zsh"]),
            p(30, 20, "/usr/bin/login", &["login"]),
            p(20, 1, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", &["Terminal"]),
            p(1, 0, "/sbin/launchd", &[]),
        ];
        let program = identify(&terminal).unwrap();
        assert_eq!(program.chain, vec!["Terminal", "login", "zsh", "git", "ssh"]);
        assert_eq!(program.identity, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal|/Applications/Xcode.app/Contents/Developer/usr/bin/git");

        let claude = vec![
            p(60, 50, "/usr/bin/ssh", &["ssh"]),
            p(50, 40, "/Applications/Xcode.app/Contents/Developer/usr/bin/git", &["git", "fetch"]),
            p(40, 10, "/bin/zsh", &["zsh"]),
            p(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude", &["Claude"]),
            p(1, 0, "/sbin/launchd", &[]),
        ];
        assert_ne!(identify(&claude).unwrap().identity, program.identity, "the same git under another app is another program");
    }

    #[test]
    fn interpreters_add_their_script_or_inline() {
        let script = vec![
            p(50, 40, "/usr/bin/ssh", &[]),
            p(40, 10, "/opt/node/bin/node", &["node", "--no-warnings", "/x/tool.js", "--flag"]),
            p(10, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2", &[]),
            p(1, 0, "/sbin/launchd", &[]),
        ];
        assert_eq!(identify(&script).unwrap().identity, "/Applications/iTerm.app/Contents/MacOS/iTerm2|/opt/node/bin/node + /x/tool.js");
        let inline = vec![
            p(50, 40, "/usr/bin/ssh", &[]),
            p(40, 10, "/usr/bin/python3.12", &["python3", "-c", "import os"]),
            p(10, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2", &[]),
        ];
        assert_eq!(identify(&inline).unwrap().identity, "/Applications/iTerm.app/Contents/MacOS/iTerm2|/usr/bin/python3.12 + <inline>");
    }

    #[test]
    fn windows_paths_and_system_parents() {
        let chain = vec![
            p(50, 40, r"C:\Windows\System32\OpenSSH\ssh.exe", &[]),
            p(40, 30, r"C:\Program Files\PowerShell\7\pwsh.exe", &[]),
            p(30, 20, r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe", &[]),
            p(20, 4, r"C:\Windows\explorer.exe", &[]),
        ];
        let program = identify(&chain).unwrap();
        assert_eq!(program.chain, vec!["WindowsTerminal", "pwsh", "ssh"]);
        assert_eq!(
            program.identity,
            r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe|C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe"
        );
    }

    #[test]
    fn a_windows_exe_in_any_case_is_named_and_skipped_like_the_lowercase_one() {
        let chain = vec![
            p(50, 40, r"C:\Windows\System32\OpenSSH\SSH.Exe", &[]),
            p(40, 30, r"C:\Program Files\PowerShell\7\pwsh.exe", &[]),
            p(30, 20, r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe", &[]),
            p(20, 4, r"C:\Windows\explorer.exe", &[]),
        ];
        let program = identify(&chain).unwrap();
        assert_eq!(program.chain, vec!["WindowsTerminal", "pwsh", "SSH"], "the extension goes, the file's own case stays");
        assert_eq!(
            program.identity,
            r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe|C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe",
            "SSH.Exe is skipped like ssh.exe, so the program is the same one"
        );
    }

    #[test]
    fn file_name_drops_exe_in_any_case_and_never_cuts_inside_a_character() {
        assert_eq!(file_name(r"C:\x\ssh.exe"), "ssh");
        assert_eq!(file_name(r"C:\x\SSH.EXE"), "SSH");
        assert_eq!(file_name(r"C:\x\Ssh.eXe"), "Ssh");
        assert_eq!(file_name("/usr/bin/ssh"), "ssh", "no extension, nothing to drop");
        assert_eq!(file_name("/usr/bin/exe"), "exe", "`exe` without the dot is a name, not an extension");
        assert_eq!(file_name("/opt/日本.Exe"), "日本");
        assert_eq!(file_name("/opt/日本語"), "日本語", "the fourth byte from the end is inside a character: no slicing there");
        assert_eq!(file_name("/opt/a日本"), "a日本");
    }

    #[test]
    fn nothing_useful_is_unknown() {
        assert_eq!(identify(&[]), None);
        assert_eq!(identify(&[p(1, 0, "/sbin/launchd", &[])]), None);
        assert_eq!(identify(&[ProcInfo { pid: 9, ppid: 1, path: None, argv: vec![] }]), None, "a process we cannot read");
    }

    #[cfg(unix)]
    #[test]
    fn the_current_process_chain_starts_with_this_test_binary() {
        let chain = process_chain(std::process::id());
        assert!(!chain.is_empty());
        assert_eq!(chain[0].pid, std::process::id());
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        let path = std::path::PathBuf::from(chain[0].path.clone().unwrap()).canonicalize().unwrap();
        assert_eq!(path, exe);
        assert!(chain.len() >= 2, "it has a parent");
    }

    #[test]
    fn a_process_that_is_gone_gives_an_empty_chain() {
        assert!(process_chain(u32::MAX - 7).is_empty());
    }

    #[test]
    fn a_replaced_linux_executable_keeps_its_original_path() {
        assert_eq!(without_deleted_suffix("/usr/bin/bash (deleted)".to_string()), "/usr/bin/bash");
        assert_eq!(without_deleted_suffix("/usr/bin/bash".to_string()), "/usr/bin/bash");
        assert_eq!(without_deleted_suffix("/opt/a (deleted)/bin/x".to_string()), "/opt/a (deleted)/bin/x", "only a suffix is dropped");
    }
}
