//! 引擎測試的替身(只在測試建置):一台「裝置」= 暫存的家目錄(`.ssh/config`、`data/` 裡的狀態檔)+ 自己的 core 鎖 +
//! 記憶體 keychain + 記錄下來的事件;多台裝置可以共用一個 `TestClock`。絕不碰真正的家目錄、keychain 或網路。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::AppError;
use crate::sync::env::{Clock, Keychain, SyncEnv, SyncEvents};
use crate::sync::runtime::SyncRuntime;
use crate::sync::state_v2::SyncStateV2;

/// 測試狀態裡的 relay URL(the chain relay is retired; old states still carry one).
pub const RELAY_URL: &str = "https://relay.test";

/// Prepare an owned private fixture directory using this test platform's permission model.
/// No real home or credential store is involved.
pub(crate) fn private_directory(path: &Path) {
    crate::fsutil::ensure_dir_secure(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    crate::sync::slot_files_windows::restrict_to_owner(path, true).unwrap();
}

/// An explicit inherited read ACE keeps Windows ACL regressions meaningful even
/// when the runner's temporary root already grants access only to its owner.
#[cfg(windows)]
pub(crate) fn inherited_windows_directory(path: &Path) {
    let output = std::process::Command::new("icacls")
        .arg(path)
        .args(["/grant", "*S-1-5-18:(OI)(CI)R"])
        .output()
        .unwrap();
    assert!(output.status.success(), "cannot prepare inherited ACL fixture");
}

/// A saved records library with an inherited Group and 17 hosts, for the Windows native startup regressions. Only the public state may be
/// exported; nothing is in the keychain.
#[cfg(windows)]
pub(crate) fn grouped_library_fixture() -> Arc<TestDevice> {
    use crate::sync::{record_groups, record_repository as repo, record_runtime, records_v3::*};
    let device = Arc::new(TestDevice::new("native-startup", &TestClock::new()));
    let env = device.env();
    let probe = record_runtime::probe_startup(&env.state_path, "native-startup");
    record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
    record_runtime::mutate_records(&env, |state| {
        let mut next = record_groups::create_group(
            state, "ffffffffffffffff", HostScope::Local,
            serde_json::from_value(serde_json::json!({"schema":1,"name":"Synced Group","defaults":{"user":"ops"}})).unwrap(),
            true, 10,
        ).map_err(|e| AppError::Other(e.to_string()))?;
        for i in 1..=17 {
            next = repo::create_host(
                &next, &format!("{i:016x}"), HostScope::Local,
                serde_json::from_value(serde_json::json!({"schema":3,"alias":format!("host-{i}"),"hostname":"fixture.invalid","auth":"password","group_id":"ffffffffffffffff","inherit":["user"]})).unwrap(),
                11,
            ).map_err(|e| AppError::Other(e.to_string()))?;
        }
        Ok(next)
    }).unwrap();
    device
}

/// 每讀一次就前進 1 ms 的時鐘:多台裝置的時間戳因此嚴格依呼叫順序遞增,LWW 的結果可預期。
pub struct TestClock(AtomicU64);

impl TestClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(1_700_000_000_000)))
    }

    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

/// 記憶體 keychain;`fail_reads` / `fail_deletes` 模擬整個 keychain 上鎖或被拒,`fail_writes_to` 讓指定的 account 寫不進去。
#[derive(Default)]
pub struct MemKeychain {
    entries: Mutex<BTreeMap<String, String>>,
    pub fail_reads: AtomicBool,
    pub fail_deletes: AtomicBool,
    pub windows_credentials: AtomicBool,
    windows: crate::secrets::credential_blob::tests::Fixture,
    failing_writes: Mutex<BTreeSet<String>>,
}

impl MemKeychain {
    pub fn entry(&self, account: &str) -> Option<String> {
        if self.windows_credentials.load(Ordering::SeqCst) {
            return crate::secrets::credential_blob::get(&self.windows.slot(account), "synthetic OS store", account).ok().flatten();
        }
        self.entries.lock().unwrap().get(account).cloned()
    }

    /// 之後對 `account` 的 `set` 一律失敗(`fail` = false 恢復):其他 account 照常寫得進去,例如暫存的新同步碼寫得進去、換成
    /// 正式的同步碼卻寫不進去。
    pub fn fail_writes_to(&self, account: &str, fail: bool) {
        let mut failing = self.failing_writes.lock().unwrap();
        if fail {
            failing.insert(account.to_string());
        } else {
            failing.remove(account);
        }
    }
}

impl Keychain for MemKeychain {
    fn get_noninteractive(&self,account:&str)->Result<Option<String>,AppError>{self.get(account)}
    fn set_noninteractive(&self,account:&str,secret:&str)->Result<(),AppError>{self.set(account,secret)}
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(AppError::Other("keychain error: locked".to_string()));
        }
        if self.windows_credentials.load(Ordering::SeqCst) {
            return crate::secrets::credential_blob::get(&self.windows.slot(account), "synthetic OS store", account);
        }
        Ok(self.entries.lock().unwrap().get(account).cloned())
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        if self.failing_writes.lock().unwrap().contains(account) {
            return Err(AppError::Other("keychain error: denied".to_string()));
        }
        if self.windows_credentials.load(Ordering::SeqCst) {
            return crate::secrets::credential_blob::set(&self.windows.slot(account), "synthetic OS store", account, secret);
        }
        self.entries.lock().unwrap().insert(account.to_string(), secret.to_string());
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        if self.fail_deletes.load(Ordering::SeqCst) {
            return Err(AppError::Other("keychain error: denied".to_string()));
        }
        if self.windows_credentials.load(Ordering::SeqCst) {
            return crate::secrets::credential_blob::delete(&self.windows.slot(account));
        }
        self.entries.lock().unwrap().remove(account);
        Ok(())
    }
}

/// 測試裝置的事件:沒有視窗或背景執行緒要通知。
#[derive(Default)]
pub struct QuietEvents;

impl SyncEvents for QuietEvents {
    fn status(&self) {}
    fn wake(&self) {}
}

/// 一台測試裝置。它從一份(只供讀取的)Legacy v2 狀態開始,與一台還沒選工作區的舊安裝相同;測試自己啟動 Records。
pub struct TestDevice {
    pub home: tempfile::TempDir,
    pub runtime: SyncRuntime,
    pub keychain: MemKeychain,
    pub events: QuietEvents,
    pub clock: Arc<TestClock>,
}

impl TestDevice {
    /// 主 config 只有一行註解的裝置。
    pub fn new(name: &str, clock: &Arc<TestClock>) -> Self {
        Self::with_main_config(name, clock, "# main\n")
    }

    /// 自訂主 config 內容的裝置。device id 由名稱決定(`<name>` 補 0 到 32 字元),relay URL 是 `RELAY_URL`。
    pub fn with_main_config(name: &str, clock: &Arc<TestClock>, main: &str) -> Self {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
        std::fs::write(home.path().join(".ssh").join("config"), main).unwrap();
        let mut state = SyncStateV2::fresh(name).unwrap();
        state.device_id = format!("{name:0<32}");
        state.relay_url = RELAY_URL.to_string();
        let device = Self {
            home,
            runtime: SyncRuntime::default(),
            keychain: MemKeychain::default(),
            events: QuietEvents,
            clock: Arc::clone(clock),
        };
        device.runtime.core.lock().unwrap().state = Some(state);
        device
    }

    pub fn env(&self) -> SyncEnv<'_> {
        SyncEnv {
            runtime: &self.runtime,
            ssh_dir: self.ssh_dir(),
            state_path: self.home.path().join("data").join("sync-state.json"),
            home: Some(self.home.path().to_path_buf()),
            keychain: &self.keychain,
            events: &self.events,
            clock: self.clock.as_ref(),
            platform: "test",
        }
    }

    pub fn ssh_dir(&self) -> PathBuf {
        self.home.path().join(".ssh")
    }

    /// The ssh_config the native startup regressions check is left alone.
    #[cfg(windows)]
    pub fn main_path(&self) -> PathBuf {
        self.ssh_dir().join("config")
    }
}
