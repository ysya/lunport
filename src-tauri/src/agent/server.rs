//! agent 的端點(金鑰保管庫 spec §4.4、§5.1):Unix socket,或 Windows 的 named pipe(`pipe_windows`)。一個使用者只有一個 agent:先拿到
//! `<agent 目錄>/lock` 的 SSHelter 提供,持有到行程結束(當掉也由系統釋放),另一個 SSHelter 不開、什麼都不碰。每條連線一條執行緒(同 MCP bridge)。

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::error::AppError;
use crate::sync::slot_files;

/// 同時處理的連線上限;超過的直接關掉(同一使用者的程式可以一直連上來)。
pub const MAX_CONNECTIONS: usize = 64;

/// 一條連線的串流。
#[cfg(unix)]
pub type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type Stream = std::fs::File;

/// 處理一條連線(在連線自己的執行緒裡):串流與對方的 PID(拿不到 → None)。
pub type Handler = Arc<dyn Fn(Stream, Option<u32>) + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Started {
    Running,
    /// 另一個 SSHelter 已經在提供 agent。
    OtherInstance,
}

/// 拿 `dir/lock` 的鎖;別的 SSHelter 拿著 → None。`dir` 一併建好(只有目前使用者能存取)。
pub(crate) fn take_lock(dir: &Path) -> Result<Option<File>, AppError> {
    slot_files::ensure_keys_dir(dir)?;
    let file = OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => Err(e.into()),
    }
}

/// 交給連線自己的執行緒;超過上限就關掉。
pub(crate) fn dispatch(stream: Stream, pid: Option<u32>, active: &Arc<AtomicUsize>, handle: &Handler) {
    struct Slot(Arc<AtomicUsize>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
        active.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let slot = Slot(Arc::clone(active));
    let handle = Arc::clone(handle);
    // spawn 失敗時 closure(連同 `slot` 與串流)被丟掉:計數照樣減回去,連線關掉。
    let _ = std::thread::Builder::new().name("sshelter-agent-connection".to_string()).spawn(move || {
        let _slot = slot;
        handle(stream, pid);
    });
}

/// Unix socket 路徑的上限(含結尾的 NUL):macOS 104、Linux 108(spec §4.4、§15)。
#[cfg(unix)]
const SUN_PATH_MAX: usize = if cfg!(target_os = "macos") { 104 } else { 108 };

/// 一條連線兩則訊息之間最多閒置多久(等核准視窗時沒有在讀,不算):ssh 認證完就關掉它的 agent 連線,閒置的連線不該一直佔著
/// `MAX_CONNECTIONS` 的名額。Windows 的 pipe(`File`)沒有讀取逾時,不設。
#[cfg(unix)]
pub(crate) const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// socket 路徑放不放得進 `sun_path`;放不進就說清楚(`bind` 自己的錯誤訊息看不出原因)。
#[cfg(unix)]
pub(crate) fn check_socket_path(sock: &Path) -> Result<(), AppError> {
    let length = sock.as_os_str().len();
    if length + 1 > SUN_PATH_MAX {
        return Err(AppError::Other(format!(
            "The agent's socket path is too long ({length} bytes; the limit is {}): {}",
            SUN_PATH_MAX - 1,
            sock.display()
        )));
    }
    Ok(())
}

/// 在 `dir`(`~/.ssh/sshelter/agent`)開 `sock`,接受同一使用者的連線,每條交給 `handle`。另一個 SSHelter 已經在提供 → `OtherInstance`;
/// 沒人接聽的舊 `sock`(上次當掉留下的)由拿到鎖的這一個換掉。
#[cfg(unix)]
pub fn listen_unix(dir: &Path, handle: Handler) -> Result<Started, AppError> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let sock = dir.join("sock");
    check_socket_path(&sock)?;
    let Some(lock) = take_lock(dir)? else { return Ok(Started::OtherInstance) };
    match std::fs::remove_file(&sock) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // 建 socket 與接受連線都在 `without_spawns` 裡:macOS 的 socket 建好之後才另外設 CLOEXEC,中間 spawn 出去的子程序會一直握著它,
    // SSHelter 結束之後 ssh 連得上卻沒人回應(見 `crate::process`)。
    let listener = crate::process::without_spawns(|| UnixListener::bind(&sock))?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    // 等連線時不拿鎖(`wait_for_connection`),有連線了才在鎖裡 accept;所以 listener 是 nonblocking,沒接到就回去等。
    listener.set_nonblocking(true)?;
    std::thread::Builder::new().name("sshelter-agent".to_string()).spawn(move || {
        // 鎖跟著 listener 持有到行程結束。
        let _lock = lock;
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            wait_for_connection(&listener);
            let stream = match crate::process::without_spawns(|| listener.accept()) {
                Ok((stream, _)) => stream,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => continue,
                Err(_) => {
                    // 例如檔案描述元用完:稍等再接,不要空轉。
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
            };
            // macOS 接受的連線沿用 listener 的 nonblocking;連線本身要會等(讀取逾時才有作用)。
            if stream.set_nonblocking(false).is_err() {
                continue;
            }
            // 不是同一個使用者:直接關掉。
            let Ok(pid) = peer(&stream) else { continue };
            let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
            dispatch(stream, pid, &active, &handle);
        }
    })?;
    Ok(Started::Running)
}

/// 等到 `listener` 有連線可接,不拿任何鎖。被訊號打斷就回來(呼叫端的 accept 會沒接到,回來再等);出錯、或醒來卻沒有連線,先稍等,不要空轉。
#[cfg(unix)]
fn wait_for_connection(listener: &std::os::unix::net::UnixListener) {
    use std::os::fd::AsRawFd;
    let mut fd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    // SAFETY: one pollfd, valid for the call; the listener keeps its fd open.
    let rc = unsafe { libc::poll(&mut fd, 1, -1) };
    let interrupted = rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted;
    if !interrupted && (rc < 0 || fd.revents & libc::POLLIN == 0) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// 對方是同一個使用者(有效 UID)時回傳它的 PID(拿不到 → None);不是 → Err。
#[cfg(target_os = "macos")]
pub(crate) fn peer(stream: &std::os::unix::net::UnixStream) -> Result<Option<u32>, ()> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: getpeereid writes two integers; geteuid has no preconditions.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 || uid != unsafe { libc::geteuid() } {
        return Err(());
    }
    let local_pid = |option: libc::c_int| {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: the buffer is one pid_t and `len` says so.
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, option, &mut pid as *mut _ as *mut libc::c_void, &mut len) };
        (rc == 0 && pid > 0).then_some(pid as u32)
    };
    Ok(local_pid(libc::LOCAL_PEEREPID).or_else(|| local_pid(libc::LOCAL_PEERPID)))
}

#[cfg(target_os = "linux")]
pub(crate) fn peer(stream: &std::os::unix::net::UnixStream) -> Result<Option<u32>, ()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `ucred` is plain old data; getsockopt fills at most `len` bytes.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len)
    };
    if rc != 0 || cred.uid != unsafe { libc::geteuid() } {
        return Err(());
    }
    Ok(u32::try_from(cred.pid).ok().filter(|pid| *pid > 0))
}

/// 其他 Unix:認不出對方,一律關掉。
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
pub(crate) fn peer(_stream: &std::os::unix::net::UnixStream) -> Result<Option<u32>, ()> {
    Err(())
}

/// 兩個平台的端點測試共用:不提供任何金鑰的 authority,以及把對方 PID 送出來再服務連線的 handler。
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::mpsc::Sender;
    use std::sync::{Arc, Mutex};

    use ssh_key::public::KeyData;

    use super::Handler;
    use crate::agent::session::{serve, SignAuthority, SignRequest};

    pub struct NoKeys;

    impl SignAuthority for NoKeys {
        fn identities(&self) -> Vec<(KeyData, String)> {
            Vec::new()
        }
        fn sign(&self, _request: &SignRequest) -> Option<Vec<u8>> {
            None
        }
    }

    pub fn serving(pids: Sender<Option<u32>>) -> Handler {
        let pids = Mutex::new(pids);
        Arc::new(move |mut stream, pid| {
            let _ = pids.lock().unwrap().send(pid);
            let _ = serve(&mut stream, &NoKeys);
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::testing::serving;
    use super::*;
    use crate::agent::protocol::{read_frame, write_frame, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENT_IDENTITIES_ANSWER};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::mpsc;
    use std::time::Duration;

    /// macOS 的暫存目錄路徑很長,socket 路徑有 104 bytes 的上限:測試用 /tmp 底下的短目錄。
    fn short_dir() -> tempfile::TempDir {
        tempfile::Builder::new().prefix("sa").tempdir_in("/tmp").unwrap()
    }

    fn identities(sock: &Path) -> u8 {
        let mut stream = UnixStream::connect(sock).unwrap();
        write_frame(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        read_frame(&mut stream).unwrap().unwrap()[0]
    }

    #[test]
    fn serves_owner_only_and_hands_over_the_peer_pid() {
        let dir = short_dir();
        let agent = dir.path().join("agent");
        let (tx, rx) = mpsc::channel();
        assert_eq!(listen_unix(&agent, serving(tx)).unwrap(), Started::Running);
        assert_eq!(identities(&agent.join("sock")), SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        assert_eq!(std::fs::metadata(&agent).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(agent.join("sock")).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn a_second_agent_does_not_start_and_the_first_keeps_serving() {
        let dir = short_dir();
        let agent = dir.path().join("agent");
        let (tx, _rx) = mpsc::channel();
        assert_eq!(listen_unix(&agent, serving(tx.clone())).unwrap(), Started::Running);
        assert_eq!(listen_unix(&agent, serving(tx)).unwrap(), Started::OtherInstance);
        assert_eq!(identities(&agent.join("sock")), SSH_AGENT_IDENTITIES_ANSWER, "the first one still answers");
    }

    #[test]
    fn a_stale_socket_left_by_a_crash_is_replaced() {
        let dir = short_dir();
        let agent = dir.path().join("agent");
        std::fs::create_dir_all(&agent).unwrap();
        // 綁好就丟掉。在 `without_spawns` 裡:同時 spawn 出去的子程序拿到 listener 的複本,丟掉之後它還在聽(見 `crate::process`)。
        crate::process::without_spawns(|| drop(UnixListener::bind(agent.join("sock")).unwrap()));
        assert!(UnixStream::connect(agent.join("sock")).is_err(), "nobody answers on it");
        let (tx, _rx) = mpsc::channel();
        assert_eq!(listen_unix(&agent, serving(tx)).unwrap(), Started::Running);
        assert_eq!(identities(&agent.join("sock")), SSH_AGENT_IDENTITIES_ANSWER);
    }

    #[test]
    fn a_socket_path_over_the_limit_is_refused_with_a_clear_message() {
        let dir = short_dir();
        let agent = dir.path().join("a".repeat(120));
        let (tx, _rx) = mpsc::channel();
        let err = listen_unix(&agent, serving(tx)).unwrap_err().to_string();
        assert!(err.contains("too long"), "{err}");
        assert!(!agent.exists(), "nothing was created");
    }

    /// 鎖持有到拿著它的 `File` 放掉(行程死掉時由系統放掉,同一個效果);放掉之後下一個 SSHelter 拿得到。整段在 `without_spawns` 裡:鎖檔有
    /// CLOEXEC,但開著的時候 spawn 出去的子程序在換成新程式之前也握著它,鎖要到那時才放(見 `crate::process`)。
    #[test]
    fn the_lock_is_held_until_its_holder_lets_go() {
        let dir = short_dir();
        let agent = dir.path().join("agent");
        crate::process::without_spawns(|| {
            let first = take_lock(&agent).unwrap().expect("nobody holds it yet");
            assert!(take_lock(&agent).unwrap().is_none(), "held");
            drop(first);
            assert!(take_lock(&agent).unwrap().is_some(), "free once the holder is gone");
        });
    }

    /// 上限含結尾的 NUL:剛好放得進 `sun_path` 的路徑(`SUN_PATH_MAX - 1` 個位元組)系統真的 bind 得起來,多一個位元組系統拒絕、
    /// `check_socket_path` 也擋下。
    #[test]
    fn the_socket_path_limit_counts_the_nul_like_the_system_does() {
        let dir = short_dir();
        let base = dir.path().as_os_str().len();
        let at_limit = dir.path().join("x".repeat(SUN_PATH_MAX - 2 - base));
        assert_eq!(at_limit.as_os_str().len(), SUN_PATH_MAX - 1);
        assert!(check_socket_path(&at_limit).is_ok());
        UnixListener::bind(&at_limit).expect("the system takes a path of SUN_PATH_MAX - 1 bytes");

        let over = dir.path().join("x".repeat(SUN_PATH_MAX - 1 - base));
        assert_eq!(over.as_os_str().len(), SUN_PATH_MAX);
        assert!(check_socket_path(&over).is_err());
        assert!(UnixListener::bind(&over).is_err(), "and refuses one byte more");
    }

    /// 滿載時再來的連線立刻關掉、不跑 handler;有空位時 handler 在自己的執行緒跑,跑完把名額還回去。
    #[test]
    fn a_full_agent_hangs_up_and_a_finished_connection_gives_its_slot_back() {
        use std::io::Read;
        use std::time::Instant;
        let ran = Arc::new(AtomicUsize::new(0));
        let handler: Handler = {
            let ran = Arc::clone(&ran);
            Arc::new(move |_stream, _pid| {
                ran.fetch_add(1, Ordering::SeqCst);
            })
        };
        let active = Arc::new(AtomicUsize::new(MAX_CONNECTIONS));

        let (mut ours, theirs) = UnixStream::pair().unwrap();
        dispatch(theirs, None, &active, &handler);
        assert_eq!(ours.read(&mut [0u8; 1]).unwrap(), 0, "hung up at once");
        assert_eq!(active.load(Ordering::SeqCst), MAX_CONNECTIONS, "a refused connection keeps no slot");
        assert_eq!(ran.load(Ordering::SeqCst), 0, "the handler never ran");

        active.store(MAX_CONNECTIONS - 1, Ordering::SeqCst);
        let (_ours, theirs) = UnixStream::pair().unwrap();
        dispatch(theirs, None, &active, &handler);
        let deadline = Instant::now() + Duration::from_secs(5);
        while (ran.load(Ordering::SeqCst) == 0 || active.load(Ordering::SeqCst) != MAX_CONNECTIONS - 1) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(active.load(Ordering::SeqCst), MAX_CONNECTIONS - 1, "the finished connection gave its slot back");
    }

    /// listener 是 nonblocking(在鎖裡 accept,見 `listen_unix`),接受的連線不是:macOS 的連線會沿用 listener 的設定,那樣 handler 讀不到資料就會
    /// 出錯而不是等。連線帶著 CLOEXEC。
    #[test]
    fn an_accepted_connection_blocks_and_closes_on_exec() {
        use std::os::fd::AsRawFd;
        let dir = short_dir();
        let agent = dir.path().join("agent");
        let (tx, rx) = mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        let handler: Handler = Arc::new(move |stream, _pid| {
            let fd = stream.as_raw_fd();
            // SAFETY: fcntl only reads the flags of an open fd.
            let (status, descriptor) = unsafe { (libc::fcntl(fd, libc::F_GETFL), libc::fcntl(fd, libc::F_GETFD)) };
            let _ = tx.lock().unwrap().send((status & libc::O_NONBLOCK, descriptor & libc::FD_CLOEXEC));
        });
        assert_eq!(listen_unix(&agent, handler).unwrap(), Started::Running);
        let _client = UnixStream::connect(agent.join("sock")).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), (0, libc::FD_CLOEXEC));
    }

    /// 閒置的連線不能一直佔著名額:每條接受的連線都帶著 5 分鐘的讀取逾時。
    #[test]
    fn an_accepted_connection_carries_the_idle_timeout() {
        let dir = short_dir();
        let agent = dir.path().join("agent");
        let (tx, rx) = mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        let handler: Handler = Arc::new(move |stream, _pid| {
            let _ = tx.lock().unwrap().send(stream.read_timeout().unwrap());
        });
        assert_eq!(listen_unix(&agent, handler).unwrap(), Started::Running);
        let _client = UnixStream::connect(agent.join("sock")).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(IDLE_TIMEOUT));
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(5 * 60));
    }
}
