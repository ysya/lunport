//! 發出請求的程式(金鑰保管庫 spec §5.4):從連上 agent 的程序往上找父程序。只是推測:同一使用者的程式可以偽造,所以只用來分組記住核准
//! 與顯示,不當成安全保證。完整的命令列不保存。

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    /// 執行檔的實際路徑(macOS 的 `proc_pidpath`,Linux 的 `/proc/<pid>/exe`,Windows 的 `QueryFullProcessImageNameW`)。
    pub path: Option<String>,
    /// argv 裡規則用得到的部分(`needed_args`):`argv[0]`,直譯器再多留到腳本或內嵌程式碼的選項為止;完整的命令列不保存。Windows 不取。
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
/// 直譯器執行的東西內嵌程式碼的選項。`-p`(node 印出結果)與 `-E`(perl)也是;程式碼本身不保存。
const INLINE_FLAGS: &[&str] = &["-c", "-e", "-E", "-p", "--eval", "--print"];

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

/// 跳過的程序:名稱在 SKIP 清單裡,或是 login shell(`argv[0]` 開頭是 `-`,例如 `-zsh`、`-xonsh`;檔名本身不會有 `-`)。
fn is_skipped(p: &ProcInfo) -> bool {
    base_lower(p).is_some_and(|b| SKIP.contains(&b.as_str())) || p.argv.first().is_some_and(|a| a.starts_with('-'))
}

fn is_interpreter(base: &str) -> bool {
    INTERPRETERS.contains(&base) || base.starts_with("python3.")
}

/// 直譯器執行的是什麼:第一個非選項引數之前先遇到內嵌程式碼的選項 → `<inline>`;否則第一個非選項引數(腳本)。
fn interpreted(argv: &[String]) -> Option<String> {
    for arg in argv.iter().skip(1) {
        if INLINE_FLAGS.contains(&arg.as_str()) {
            return Some("<inline>".to_string());
        }
        if !arg.starts_with('-') {
            return Some(arg.clone());
        }
    }
    None
}

/// 只留下規則用得到的引數:每個程序留 `argv[0]`(看是不是 login shell);直譯器再留到第一個內嵌程式碼的選項或第一個非選項引數(腳本)為止,
/// 之後的不留。完整的命令列可能含祕密。
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn needed_args(path: Option<&str>, argv: Vec<String>) -> Vec<String> {
    let interpreter = path.is_some_and(|p| is_interpreter(&file_name(p).to_ascii_lowercase()));
    let mut kept = Vec::new();
    for (i, arg) in argv.into_iter().enumerate() {
        let last = (i == 0 && !interpreter) || (i > 0 && (INLINE_FLAGS.contains(&arg.as_str()) || !arg.starts_with('-')));
        kept.push(arg);
        if last {
            break;
        }
    }
    kept
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
    let program_id = match is_interpreter(&base).then(|| interpreted(&program.argv)).flatten() {
        Some(what) => format!("{program_path} + {what}"),
        None => program_path.clone(),
    };
    Some(Program {
        chain: useful.iter().rev().map(|p| display(p)).collect(),
        identity: format!("{}|{}", app.path.clone()?, program_id),
    })
}

/// 從 `pid` 往上找父程序(最多 64 層)。讀不到的程序(已經結束,或沒有權限讀)→ 鏈到那裡為止;一開始就讀不到 → 空的。
/// 到 PID 1、父程序是自己、或父程序已經在鏈裡(Windows 不會重新指定父程序,舊的 PID 可能繞回來)也停。
pub fn process_chain(pid: u32) -> Vec<ProcInfo> {
    walk(pid, proc_info)
}

/// `pid` 的執行檔名稱(小寫、去掉 `.exe`);讀不到(程序已經結束)→ None。
pub fn executable_base(pid: u32) -> Option<String> {
    base_lower(&proc_info(pid)?)
}

/// `process_chain` 的走法;讀一個程序的函式由呼叫端給(測試用假的)。
fn walk(pid: u32, mut read: impl FnMut(u32) -> Option<ProcInfo>) -> Vec<ProcInfo> {
    let mut out: Vec<ProcInfo> = Vec::new();
    let mut current = pid;
    while out.len() < 64 {
        let Some(info) = read(current) else { break };
        let parent = info.ppid;
        out.push(info);
        if current <= 1 || out.iter().any(|p| p.pid == parent) {
            break;
        }
        current = parent;
    }
    out
}

/// `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)` 的結果(`<sys/proc_info.h>` 的 `struct proc_bsdshortinfo`;鎖定的 libc 0.2.186 還沒有它)。
/// 不用 `PROC_PIDTBSDINFO`:它讀 root 擁有的程序(終端機分頁底下的 `/usr/bin/login`)會 EPERM,鏈就斷在那裡;短版一般使用者都讀得到。
#[cfg(target_os = "macos")]
#[repr(C)]
struct ShortBsdInfo {
    pid: u32,
    ppid: u32,
    pgid: u32,
    status: u32,
    comm: [u8; 16],
    flags: u32,
    uid: u32,
    gid: u32,
    ruid: u32,
    rgid: u32,
    svuid: u32,
    svgid: u32,
    rfu: u32,
}

#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<ShortBsdInfo>() == 64);

#[cfg(target_os = "macos")]
const PROC_PIDT_SHORTBSDINFO: libc::c_int = 13;

#[cfg(target_os = "macos")]
fn proc_info(pid: u32) -> Option<ProcInfo> {
    let pid = i32::try_from(pid).ok()?;
    // SAFETY: `ShortBsdInfo` is plain old data; `proc_pidinfo` fills at most `size` bytes.
    let info = unsafe {
        let mut info = std::mem::zeroed::<ShortBsdInfo>();
        let size = std::mem::size_of::<ShortBsdInfo>() as libc::c_int;
        let n = libc::proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &mut info as *mut _ as *mut libc::c_void, size);
        (n == size).then_some(info)?
    };
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is `PROC_PIDPATHINFO_MAXSIZE` bytes long.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    let path = (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned());
    let argv = needed_args(path.as_deref(), macos_argv(pid).unwrap_or_default());
    Some(ProcInfo { pid: pid as u32, ppid: info.ppid, path, argv })
}

/// `KERN_PROCARGS2` 的內容(格式見 `parse_procargs2`)。
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
    parse_procargs2(&buf)
}

/// `KERN_PROCARGS2` 的內容:`int argc`、執行時給的路徑與 NUL 填充、`argv[0..argc]`、環境變數。`argc` 比緩衝區裡真正有的多時
/// (資料壞了)讀到緩衝區用完就停,不會為了很大的 `argc` 配置大量空字串。
#[cfg(any(target_os = "macos", test))]
fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(0..4)?.try_into().ok()?);
    let mut rest = &buf[4..];
    let nul = rest.iter().position(|&b| b == 0)?;
    rest = &rest[nul..];
    while rest.first() == Some(&0) {
        rest = &rest[1..];
    }
    let mut argv = Vec::new();
    for _ in 0..argc.max(0) {
        if rest.is_empty() {
            break;
        }
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
    // `comm` 最長 15 個位元組,可能剛好斷在多位元組字的中間:讀位元組再寬鬆地轉成字串(`read_to_string` 會失敗,程序就被當成不存在)。
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let stat = String::from_utf8_lossy(&stat);
    // `pid (comm) state ppid …`:comm 可能含空白與括號,從最後一個 `)` 之後讀。
    let after = &stat[stat.rfind(')')? + 1..];
    let ppid = after.split_whitespace().nth(1)?.parse().ok()?;
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| without_deleted_suffix(p.display().to_string()));
    let args: Vec<String> = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| bytes.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
        .unwrap_or_default();
    let argv = needed_args(path.as_deref(), args);
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

    /// identity 裡程式的那一段(`|` 之後):程式是 `path`、引數是 `argv`,夾在 ssh 與 iTerm2 之間。
    fn program_part(path: &str, argv: &[&str]) -> String {
        let chain = vec![
            p(50, 40, "/usr/bin/ssh", &["ssh"]),
            p(40, 10, path, argv),
            p(10, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2", &["iTerm2"]),
        ];
        identify(&chain).unwrap().identity.split_once('|').unwrap().1.to_string()
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
    fn an_interpreter_is_inline_only_when_the_flag_comes_before_the_script() {
        assert_eq!(program_part("/usr/bin/python3", &["python3", "tool.py", "-c", "cfg"]), "/usr/bin/python3 + tool.py");
        assert_eq!(program_part("/usr/bin/python3", &["python3", "-c", "code"]), "/usr/bin/python3 + <inline>");
        assert_eq!(program_part("/opt/node/bin/node", &["node", "-p", "process.env.X"]), "/opt/node/bin/node + <inline>");
        assert_eq!(program_part("/usr/bin/perl", &["perl", "-E", "say 1"]), "/usr/bin/perl + <inline>");
        assert_eq!(program_part("/opt/node/bin/node", &["node", "--no-warnings", "/x/tool.js", "--flag"]), "/opt/node/bin/node + /x/tool.js");
        assert_eq!(program_part("/opt/node/bin/node", &["node", "tool.js", "-e", "staging"]), "/opt/node/bin/node + tool.js");
        assert_eq!(
            program_part("/usr/bin/python3", &["python3", "/usr/bin/ansible-playbook", "site.yml", "-e", "@vars.yml"]),
            "/usr/bin/python3 + /usr/bin/ansible-playbook"
        );
        assert_eq!(program_part("/usr/bin/python3", &["python3"]), "/usr/bin/python3", "no script: the interpreter alone");
        assert_eq!(program_part("/usr/bin/python3", &["python3", "-u", "-B"]), "/usr/bin/python3", "options only: no script");
    }

    #[test]
    fn a_login_shell_is_marked_by_a_dash_in_argv0_not_in_its_path() {
        let chain = vec![
            p(60, 50, "/usr/bin/ssh", &["ssh"]),
            p(50, 40, "/opt/homebrew/bin/xonsh", &["-xonsh"]),
            p(40, 30, "/usr/bin/login", &["login", "-fp", "u"]),
            p(30, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2", &["iTerm2"]),
            p(1, 0, "/sbin/launchd", &[]),
        ];
        let program = identify(&chain).unwrap();
        assert_eq!(program.chain, vec!["iTerm", "login", "xonsh", "ssh"]);
        assert_eq!(program.identity, "/Applications/iTerm.app/Contents/MacOS/iTerm2|/Applications/iTerm.app/Contents/MacOS/iTerm2");
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_the_arguments_the_rules_read_are_kept() {
        assert_eq!(needed_args(Some("/bin/zsh"), strings(&["-zsh", "-c", "secret"])), strings(&["-zsh"]));
        assert_eq!(needed_args(Some("/usr/bin/python3"), strings(&["python3", "-c", "secret"])), strings(&["python3", "-c"]));
        assert_eq!(
            needed_args(Some("/opt/node/bin/node"), strings(&["node", "--no-warnings", "/x/tool.js", "--token", "t"])),
            strings(&["node", "--no-warnings", "/x/tool.js"])
        );
        assert_eq!(needed_args(Some("/usr/bin/python3.12"), strings(&["python3", "tool.py", "-c", "x"])), strings(&["python3", "tool.py"]));
        assert_eq!(needed_args(Some("/usr/bin/python3"), strings(&["python3"])), strings(&["python3"]));
        assert_eq!(needed_args(Some("/usr/bin/python3"), strings(&["python3", "-u", "-B"])), strings(&["python3", "-u", "-B"]), "options only: nothing to cut");
        assert_eq!(needed_args(Some(r"C:\x\Node.EXE"), strings(&["node", "app.js", "--token", "t"])), strings(&["node", "app.js"]), "an interpreter in any case");
        assert_eq!(needed_args(None, strings(&["whatever", "--token", "t"])), strings(&["whatever"]), "no path: not known to be an interpreter");
        assert!(needed_args(Some("/bin/zsh"), vec![]).is_empty());
    }

    #[test]
    fn keeping_fewer_arguments_never_changes_the_identity() {
        let cases: &[(&str, &[&str])] = &[
            ("/usr/bin/python3", &["python3", "tool.py", "-c", "cfg"]),
            ("/usr/bin/python3", &["python3", "-c", "code"]),
            ("/opt/node/bin/node", &["node", "--no-warnings", "/x/tool.js", "--token", "t"]),
            ("/opt/node/bin/node", &["node", "-p", "process.env.X"]),
            ("/usr/bin/perl", &["perl", "-E", "say 1"]),
            ("/usr/bin/python3", &["python3"]),
            ("/usr/bin/python3", &["python3", "-u", "-B"]),
            ("/opt/homebrew/bin/xonsh", &["-xonsh", "-c", "secret"]),
            ("/usr/bin/git", &["git", "fetch", "origin"]),
        ];
        for (path, argv) in cases {
            let kept = needed_args(Some(path), strings(argv));
            let kept: Vec<&str> = kept.iter().map(String::as_str).collect();
            assert_eq!(program_part(path, &kept), program_part(path, argv), "{path} {argv:?}");
        }
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

    /// `executable_base` 讀出的名稱:小寫、沒有 `.exe`(Windows 的 `SSH.EXE` 與 `ssh.exe` 是同一個程式),讀不到路徑 → None。
    #[test]
    fn the_base_name_is_lowercase_and_has_no_exe_extension() {
        assert_eq!(base_lower(&p(1, 0, r"C:\Windows\System32\OpenSSH\SSH.EXE", &[])).as_deref(), Some("ssh"));
        assert_eq!(base_lower(&p(1, 0, "/usr/bin/ssh", &[])).as_deref(), Some("ssh"));
        assert_eq!(base_lower(&p(1, 0, "/opt/homebrew/bin/SSH-Add", &[])).as_deref(), Some("ssh-add"));
        assert_eq!(base_lower(&ProcInfo { pid: 1, ppid: 0, path: None, argv: vec![] }), None);
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

    #[cfg(unix)]
    #[test]
    fn pid_1_is_readable_so_the_walk_can_pass_root_owned_parents() {
        assert!(!process_chain(1).is_empty(), "launchd / init is readable");
    }

    #[cfg(unix)]
    #[test]
    fn a_live_process_keeps_only_what_the_rules_read_of_its_command_line() {
        // `read line; : secret-token`:兩個指令,shell 不會直接換成別的程式;它停在內建的 read(等 stdin,我們不關),不會留下子程序。
        let mut child = std::process::Command::new("sh")
            .args(["-c", "read line; : secret-token"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let chain = process_chain(pid);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!chain.is_empty(), "a child of ours is readable");
        assert_eq!(chain[0].pid, pid);
        assert_eq!(chain[0].argv, vec!["sh"], "only argv[0] of a program that is not an interpreter");
        assert!(chain.iter().all(|p| p.argv.iter().all(|a| !a.contains("secret-token"))));
    }

    #[cfg(unix)]
    #[test]
    fn the_executable_base_name_of_a_live_process_and_of_a_gone_one() {
        let base = executable_base(std::process::id()).unwrap();
        assert!(!base.is_empty() && !base.contains('/'));
        assert_eq!(executable_base(u32::MAX - 7), None);
    }

    /// 別的程序(連上通道的 ssh 就是別的程序):名稱是它自己的執行檔,結束之後讀不到。期望值用 PATH 上找到的 `sleep` 解開 symlink 後的檔名
    /// (系統回報的是真正的路徑,例如 busybox 的 applet 是 `busybox`)。
    #[cfg(unix)]
    #[test]
    fn the_executable_base_of_another_live_process_is_its_own_file_name() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let base = executable_base(pid);
        child.kill().unwrap();
        child.wait().unwrap();
        let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap()).map(|dir| dir.join("sleep")).find(|p| p.is_file()).unwrap();
        let expected = sleep.canonicalize().unwrap().file_name().unwrap().to_string_lossy().to_ascii_lowercase();
        assert_eq!(base, Some(expected));
        assert_eq!(executable_base(pid), None, "gone once it has been waited for");
    }

    #[test]
    fn a_process_that_is_gone_gives_an_empty_chain() {
        #[cfg(unix)]
        let mut child = std::process::Command::new("true").spawn().unwrap();
        #[cfg(windows)]
        let mut child = std::process::Command::new("cmd").args(["/C", "exit"]).spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        drop(child);
        assert!(process_chain(pid).is_empty());
    }

    /// `KERN_PROCARGS2` 的內容:`int argc`、執行時給的路徑、`padding` 個 NUL(含結尾那個)、之後的資料。
    fn procargs2(argc: i32, exec_path: &str, padding: usize, rest: &[u8]) -> Vec<u8> {
        let mut buf = argc.to_ne_bytes().to_vec();
        buf.extend_from_slice(exec_path.as_bytes());
        buf.extend(std::iter::repeat(0u8).take(padding));
        buf.extend_from_slice(rest);
        buf
    }

    #[test]
    fn procargs2_gives_argv_and_ignores_the_environment() {
        let buf = procargs2(2, "/opt/node/bin/node", 5, b"node\0/x/tool.js\0HOME=/Users/u\0TOKEN=secret\0");
        assert_eq!(parse_procargs2(&buf), Some(strings(&["node", "/x/tool.js"])));
    }

    #[test]
    fn procargs2_with_a_huge_argc_stops_where_the_buffer_ends() {
        let buf = procargs2(3_000_000, "/x", 2, b"a\0b\0c\0d\0");
        let argv = parse_procargs2(&buf).unwrap();
        assert!(argv.len() <= 8, "{} items out of an 8-byte tail", argv.len());
        assert_eq!(argv, strings(&["a", "b", "c", "d"]));
    }

    #[test]
    fn procargs2_that_does_not_parse_is_none_or_empty() {
        assert_eq!(parse_procargs2(&procargs2(1, "/x/no-nul-after-this", 0, b"")), None, "no NUL after the exec path");
        assert_eq!(parse_procargs2(&[1, 0]), None, "shorter than the argc field");
        assert_eq!(parse_procargs2(&[]), None);
        assert_eq!(parse_procargs2(&procargs2(-5, "/x", 1, b"a\0")), Some(vec![]), "a negative argc reads nothing");
        assert_eq!(parse_procargs2(&procargs2(0, "/x", 1, b"HOME=/\0")), Some(vec![]));
    }

    fn fake(pid: u32, ppid: u32) -> Option<ProcInfo> {
        Some(ProcInfo { pid, ppid, path: Some(format!("/x/{pid}")), argv: vec![] })
    }

    fn pids(chain: &[ProcInfo]) -> Vec<u32> {
        chain.iter().map(|p| p.pid).collect()
    }

    #[test]
    fn the_walk_stops_when_a_parent_is_already_in_the_chain() {
        let chain = walk(10, |pid| match pid {
            10 => fake(10, 20),
            20 => fake(20, 10),
            _ => None,
        });
        assert_eq!(pids(&chain), vec![10, 20]);
    }

    #[test]
    fn an_endless_chain_is_cut_at_64() {
        let chain = walk(100, |pid| fake(pid, pid + 1));
        assert_eq!(chain.len(), 64);
        assert_eq!((chain[0].pid, chain[63].pid), (100, 163));
    }

    #[test]
    fn a_process_that_is_its_own_parent_stops() {
        assert_eq!(pids(&walk(7, |pid| fake(pid, pid))), vec![7]);
    }

    #[test]
    fn an_unreadable_parent_ends_the_chain() {
        let chain = walk(10, |pid| if pid == 10 { fake(10, 20) } else { None });
        assert_eq!(pids(&chain), vec![10]);
        assert!(walk(10, |_| None).is_empty());
    }

    #[test]
    fn the_walk_ends_at_pid_1_and_never_reads_pid_0() {
        let chain = walk(5, |pid| match pid {
            5 => fake(5, 1),
            1 => fake(1, 0),
            _ => unreachable!("pid {pid} must not be read"),
        });
        assert_eq!(pids(&chain), vec![5, 1]);
    }

    #[test]
    fn a_replaced_linux_executable_keeps_its_original_path() {
        assert_eq!(without_deleted_suffix("/usr/bin/bash (deleted)".to_string()), "/usr/bin/bash");
        assert_eq!(without_deleted_suffix("/usr/bin/bash".to_string()), "/usr/bin/bash");
        assert_eq!(without_deleted_suffix("/opt/a (deleted)/bin/x".to_string()), "/opt/a (deleted)/bin/x", "only a suffix is dropped");
    }
}
