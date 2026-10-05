//! 引擎測試的替身(只在測試建置):一台「裝置」= 暫存的家目錄(`.ssh/config`、`.ssh/sshelter/`、`data/` 裡的
//! 狀態檔)+ 自己的 doc / core 鎖 + 記憶體 keychain + 記錄下來的事件;多台裝置共用一個 `FakeRelay` 與一個
//! `TestClock`。`HookedConnector` 在某一個 relay 呼叫的那一刻插進另一件事(背景執行緒的一輪、app 裡的存檔),跨執行緒的
//! 交錯因此能決定性地重現。絕不碰真正的家目錄、keychain 或網路。

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::commands::persist_file;
use crate::config::model::SshConfigDoc;
use crate::config::parser::parse_file;
use crate::error::AppError;
use crate::sync::crypto::ChainKeys;
use crate::sync::dto::{ApprovalNotice, SyncConflict};
use crate::sync::env::{Clock, Keychain, RelayConnector, SyncEnv, SyncEvents};
use crate::sync::fake_relay::{self, FakeRelay};
use crate::sync::files::note_written;
use crate::sync::merge::{put_account_record, put_space_key};
use crate::sync::record::{RecordKind, SpacePayload};
use crate::sync::relay::{BatchPullEntry, BatchPullItem, PullResponse, PushItem, PushOutcome, RelayApi, RelayError, RelayInfo};
use crate::sync::runtime::{SyncCore, SyncRuntime};
use crate::sync::space_files::{slugify, space_file_name};
use crate::sync::state_v2::{AccountState, SpaceState, SyncNotice, SyncStateV2};

/// 測試裡的 relay URL(假 relay 不看它,只拒絕空字串)。
pub const RELAY_URL: &str = "https://relay.test";

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
    failing_writes: Mutex<BTreeSet<String>>,
}

impl MemKeychain {
    pub fn entry(&self, account: &str) -> Option<String> {
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
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(AppError::Other("keychain error: locked".to_string()));
        }
        Ok(self.entries.lock().unwrap().get(account).cloned())
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        if self.failing_writes.lock().unwrap().contains(account) {
            return Err(AppError::Other("keychain error: denied".to_string()));
        }
        self.entries.lock().unwrap().insert(account.to_string(), secret.to_string());
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        if self.fail_deletes.load(Ordering::SeqCst) {
            return Err(AppError::Other("keychain error: denied".to_string()));
        }
        self.entries.lock().unwrap().remove(account);
        Ok(())
    }
}

/// 記下引擎發出的每個事件。
#[derive(Default)]
pub struct RecordingEvents {
    statuses: AtomicUsize,
    /// 全部的喚醒(`wake` 與 `wake_implicit`);`implicit` 是其中順便的那幾次。
    wakes: AtomicUsize,
    implicit: AtomicUsize,
    pub applied: Mutex<Vec<usize>>,
    pub conflicts: Mutex<Vec<SyncConflict>>,
    pub approvals: Mutex<Vec<ApprovalNotice>>,
    pub notices: Mutex<Vec<SyncNotice>>,
}

impl RecordingEvents {
    pub fn statuses(&self) -> usize {
        self.statuses.load(Ordering::SeqCst)
    }
    /// 全部的喚醒次數(含順便的)。
    pub fn wakes(&self) -> usize {
        self.wakes.load(Ordering::SeqCst)
    }
    /// 其中順便的喚醒(存檔 hook 等,`SyncEvents::wake_implicit`)。
    pub fn implicit_wakes(&self) -> usize {
        self.implicit.load(Ordering::SeqCst)
    }
}

impl SyncEvents for RecordingEvents {
    fn status(&self) {
        self.statuses.fetch_add(1, Ordering::SeqCst);
    }
    fn applied(&self, hosts: usize) {
        self.applied.lock().unwrap().push(hosts);
    }
    fn conflict(&self, conflicts: &[SyncConflict]) {
        self.conflicts.lock().unwrap().extend_from_slice(conflicts);
    }
    fn approval(&self, waiting: &[ApprovalNotice]) {
        self.approvals.lock().unwrap().extend_from_slice(waiting);
    }
    fn notice(&self, notice: &SyncNotice) {
        self.notices.lock().unwrap().push(notice.clone());
    }
    fn wake(&self) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_implicit(&self) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
        self.implicit.fetch_add(1, Ordering::SeqCst);
    }
}

/// 記下 `applied` 被呼叫的當下 doc / backed_up / core 三把鎖是不是都空著 —— 引擎的通知一律在放掉所有鎖之後(`wake`
/// 除外)—— 與 `wake` 被呼叫了幾次。用法:`let probe = AppliedProbe::new(&d); let mut env = d.env(); env.events = &probe;`
pub struct AppliedProbe<'a> {
    doc: &'a Mutex<Option<SshConfigDoc>>,
    backed_up: &'a Mutex<HashSet<PathBuf>>,
    core: &'a Mutex<SyncCore>,
    pub all_free: Mutex<Vec<bool>>,
    wakes: AtomicUsize,
}

impl<'a> AppliedProbe<'a> {
    pub fn new(d: &'a TestDevice) -> Self {
        Self { doc: &d.doc, backed_up: &d.backed_up, core: &d.runtime.core, all_free: Mutex::new(Vec::new()), wakes: AtomicUsize::new(0) }
    }

    pub fn wakes(&self) -> usize {
        self.wakes.load(Ordering::SeqCst)
    }
}

impl SyncEvents for AppliedProbe<'_> {
    fn status(&self) {}
    fn applied(&self, _hosts: usize) {
        let free = self.doc.try_lock().is_ok() && self.backed_up.try_lock().is_ok() && self.core.try_lock().is_ok();
        self.all_free.lock().unwrap().push(free);
    }
    fn conflict(&self, _conflicts: &[SyncConflict]) {}
    fn approval(&self, _waiting: &[ApprovalNotice]) {}
    fn notice(&self, _notice: &SyncNotice) {}
    fn wake(&self) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct FakeConnector(pub Arc<FakeRelay>);

impl RelayConnector for FakeConnector {
    fn connect(&self, base_url: &str) -> Result<Box<dyn RelayApi>, AppError> {
        fake_relay::connect(&self.0, base_url)
    }
}

/// 在某一個 relay 呼叫的那一刻插進來的事:另一個執行緒剛好在那時做的事(背景執行緒的一輪、app 裡的存檔)。只跑一次。要用到
/// 裝置的話,把裝置包在 `Arc` 裡、clone 一份進來。
pub type Hook = Box<dyn FnOnce() + Send>;

/// `HookedConnector` 的插入點:建立 / 刪除 chain 之前、上傳 / 批次查詢之後(relay 已經回答了,呼叫端還沒拿到結果)。
#[derive(Default)]
pub struct Hooks {
    pub before_create: Option<Hook>,
    pub before_delete: Option<Hook>,
    pub after_push: Option<Hook>,
    pub after_batch: Option<Hook>,
}

/// 共用的 `FakeRelay`,加上 `Hooks`:用法是 `let mut env = d.env(); env.relays = &connector;`,讓兩件事在決定性的時間點交錯。
pub struct HookedConnector {
    relay: Arc<FakeRelay>,
    hooks: Arc<Mutex<Hooks>>,
}

impl HookedConnector {
    pub fn new(relay: &Arc<FakeRelay>, hooks: Hooks) -> Self {
        Self { relay: Arc::clone(relay), hooks: Arc::new(Mutex::new(hooks)) }
    }
}

impl RelayConnector for HookedConnector {
    fn connect(&self, base_url: &str) -> Result<Box<dyn RelayApi>, AppError> {
        if base_url.trim().is_empty() {
            return Err(AppError::Other("no relay URL".to_string()));
        }
        Ok(Box::new(HookedRelay { inner: Arc::clone(&self.relay), hooks: Arc::clone(&self.hooks) }))
    }
}

struct HookedRelay {
    inner: Arc<FakeRelay>,
    hooks: Arc<Mutex<Hooks>>,
}

impl HookedRelay {
    /// 取出並執行一個插入點(先放掉 `hooks` 的鎖:插進來的事可能又碰到 relay)。
    fn run(&self, pick: impl FnOnce(&mut Hooks) -> Option<Hook>) {
        let hook = pick(&mut self.hooks.lock().unwrap());
        if let Some(hook) = hook {
            hook();
        }
    }
}

impl RelayApi for HookedRelay {
    fn info(&self) -> Result<RelayInfo, RelayError> {
        self.inner.info()
    }
    fn create_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        self.run(|h| h.before_create.take());
        self.inner.create_chain(chain_id, token)
    }
    fn delete_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        self.run(|h| h.before_delete.take());
        self.inner.delete_chain(chain_id, token)
    }
    fn freeze_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
        self.inner.freeze_chain(chain_id, token)
    }
    fn pull(&self, chain_id: &str, token: &str, since: u64) -> Result<PullResponse, RelayError> {
        self.inner.pull(chain_id, token, since)
    }
    fn pull_batch(&self, items: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError> {
        let out = self.inner.pull_batch(items);
        self.run(|h| h.after_batch.take());
        out
    }
    fn push(&self, chain_id: &str, token: &str, items: &[PushItem]) -> Result<PushOutcome, RelayError> {
        let out = self.inner.push(chain_id, token, items);
        self.run(|h| h.after_push.take());
        out
    }
}

/// 一台測試裝置。
pub struct TestDevice {
    pub home: tempfile::TempDir,
    pub doc: Mutex<Option<SshConfigDoc>>,
    pub backed_up: Mutex<HashSet<PathBuf>>,
    pub retention: Mutex<Option<usize>>,
    pub runtime: SyncRuntime,
    pub keychain: MemKeychain,
    pub events: RecordingEvents,
    pub relay: Arc<FakeRelay>,
    pub clock: Arc<TestClock>,
    connector: FakeConnector,
}

impl TestDevice {
    /// 主 config 只有一行註解的裝置。
    pub fn new(name: &str, relay: &Arc<FakeRelay>, clock: &Arc<TestClock>) -> Self {
        Self::with_main_config(name, relay, clock, "# main\n")
    }

    /// 自訂主 config 內容的裝置。device id 由名稱決定(`<name>` 補 0 到 32 字元),relay URL 是 `RELAY_URL`。
    pub fn with_main_config(name: &str, relay: &Arc<FakeRelay>, clock: &Arc<TestClock>, main: &str) -> Self {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
        std::fs::write(home.path().join(".ssh").join("config"), main).unwrap();
        let mut state = SyncStateV2::fresh(name).unwrap();
        state.device_id = format!("{name:0<32}");
        state.relay_url = RELAY_URL.to_string();
        let device = Self {
            home,
            doc: Mutex::new(None),
            backed_up: Mutex::new(HashSet::new()),
            retention: Mutex::new(None),
            runtime: SyncRuntime::default(),
            keychain: MemKeychain::default(),
            events: RecordingEvents::default(),
            relay: Arc::clone(relay),
            clock: Arc::clone(clock),
            connector: FakeConnector(Arc::clone(relay)),
        };
        device.runtime.core.lock().unwrap().state = Some(state);
        device.reload();
        device
    }

    pub fn env(&self) -> SyncEnv<'_> {
        SyncEnv {
            doc: &self.doc,
            backed_up: &self.backed_up,
            retention: &self.retention,
            runtime: &self.runtime,
            ssh_dir: self.ssh_dir(),
            state_path: self.home.path().join("data").join("sync-state.json"),
            home: Some(self.home.path().to_path_buf()),
            keychain: &self.keychain,
            relays: &self.connector,
            events: &self.events,
            clock: self.clock.as_ref(),
            platform: "test",
        }
    }

    pub fn ssh_dir(&self) -> PathBuf {
        self.home.path().join(".ssh")
    }

    pub fn main_path(&self) -> PathBuf {
        self.ssh_dir().join("config")
    }

    /// 前端的 `config_load`:從磁碟整份重新載入 doc。
    pub fn reload(&self) {
        let doc = self.env().load_doc(&self.main_path()).unwrap();
        *self.doc.lock().unwrap() = Some(doc);
        self.backed_up.lock().unwrap().clear();
    }

    pub fn state(&self) -> SyncStateV2 {
        self.runtime.core.lock().unwrap().state.clone().expect("sync state")
    }

    pub fn read(&self, path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    pub fn main_config(&self) -> String {
        self.read(&self.main_path())
    }

    /// 這台勾選的 space 檔路徑(依狀態裡的檔名)。
    pub fn space_path(&self, space_id: &str) -> PathBuf {
        let file_name = self.state().spaces[space_id].file_name.clone();
        crate::sync::space_files::space_file_path(&self.ssh_dir(), &file_name).unwrap()
    }

    /// app 以外的編輯(另一個編輯器):直接改磁碟。
    pub fn write_externally(&self, path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
    }

    /// 在 app 裡存檔(同 `config_save_host` 等命令):改 doc → `persist_file` → 存檔 hook。檔案必須已載入 doc。
    pub fn save_in_app(&self, path: &Path, text: &str) {
        let env = self.env();
        let mut doc_lock = self.doc.lock().unwrap();
        let doc = doc_lock.as_mut().expect("config loaded");
        let idx = doc.files.iter().position(|f| f.path == path).expect("the file is loaded");
        let (items, trailing_newline) = parse_file(text);
        doc.files[idx].items = items;
        doc.files[idx].trailing_newline = trailing_newline;
        let mut backed_up = self.backed_up.lock().unwrap();
        persist_file(doc, idx, &mut backed_up, None).unwrap();
        note_written(&env, path, &doc.files[idx].items);
    }

    /// 直接把狀態設成「已加入一個帳戶、勾選了這些 space」(基線已建立),不經過 relay。回傳 space id(依參數順序)。
    pub fn join_with_spaces(&self, names: &[&str]) -> Vec<String> {
        let account_keys = ChainKeys::generate().unwrap();
        let now = self.clock.now_ms();
        let mut core = self.runtime.core.lock().unwrap();
        let s = core.state.as_mut().unwrap();
        let mut account = AccountState::new(&account_keys.chain_id);
        account.baseline_established = true;
        let mut ids = Vec::new();
        for name in names {
            let keys = ChainKeys::generate().unwrap();
            let payload = SpacePayload { schema: 1, name: name.to_string(), slug: slugify(name), created_at_ms: now, previous_id: None };
            put_account_record(&mut account, RecordKind::Space, &keys.chain_id, serde_json::to_value(payload).unwrap(), false, &s.device_id, now);
            put_space_key(&mut account, &account_keys, &keys.chain_id, Some(&keys), &s.device_id, now).unwrap();
            let mut space = SpaceState::new(&space_file_name(&slugify(name), &keys.chain_id).unwrap());
            space.baseline_established = true;
            s.spaces.insert(keys.chain_id.clone(), space);
            ids.push(keys.chain_id);
        }
        s.account = Some(account);
        core.account_keys = Some(account_keys);
        ids
    }
}
