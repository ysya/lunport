//! agent 的決定(金鑰保管庫 spec §5.2、§5.3、§5.5、§5.6):列出哪些金鑰、簽不簽、要不要問、passphrase 與解開的私鑰。不碰 Tauri:金鑰清單、
//! 保管庫、keychain、時鐘、known_hosts 與核准視窗都經 `AgentHost`(production 是 `agent::AppAgentHost`)。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use ssh_key::public::KeyData;
use ssh_key::HashAlg;
use zeroize::Zeroizing;

use crate::agent::approval::{remember_minutes, verdict, ApprovalCache, ApprovalKey, KeyProtection, Verdict};
use crate::agent::peer::Program;
use crate::agent::prompt::{AgentApprovalAnswer, AgentApprovalRequest, APPROVAL_TIMEOUT};
use crate::agent::session::{SignAuthority, SignRequest};
use crate::error::AppError;
use crate::sync::env::Keychain;
use crate::sync::state_v2::{SlotSource, SyncStateV2};
use crate::vault::material::{self, Material, OpenError};
use crate::vault::store::AgentSettings;

/// 輸錯幾次就拒絕這次請求(spec §5.5)。
pub const PASSPHRASE_ATTEMPTS: usize = 3;
pub const WRONG_PASSPHRASE: &str = "That passphrase didn't work.";

/// 記在這台的 passphrase 在 keychain 的 account(spec §4.3)。
pub fn passphrase_account(slot_id: &str) -> String {
    format!("vault:passphrase:{slot_id}")
}

/// 這台只在 SSHelter 的一把金鑰(同步狀態裡 `SlotSource::Vault` 的插槽):列出金鑰、比對簽章請求都不必開保管庫。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKey {
    pub slot_id: String,
    /// 顯示名稱:插槽的名稱,沒有就用插槽檔名。
    pub name: String,
    pub fingerprint: String,
    pub public_key: String,
    pub has_passphrase: bool,
}

/// 同步狀態裡這台只在 SSHelter 的金鑰(依插槽 id)。
pub fn vault_keys(state: &SyncStateV2) -> Vec<VaultKey> {
    state
        .key_slots
        .iter()
        .filter_map(|(id, local)| match &local.source {
            Some(SlotSource::Vault { fingerprint, public_key, has_passphrase }) => Some(VaultKey {
                slot_id: id.clone(),
                name: local
                    .payload
                    .as_ref()
                    .map(|p| p.name.clone())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| local.file_name.clone()),
                fingerprint: fingerprint.clone(),
                public_key: public_key.clone(),
                has_passphrase: *has_passphrase,
            }),
            _ => None,
        })
        .collect()
}

/// known_hosts 的內容裡,這把主機金鑰第一個能顯示的名稱(`[host]:port` 顯示成 `host:port`)。雜湊過的名稱(`|1|…`)、萬用字元與否定的
/// pattern 不算;`@cert-authority`、`@revoked` 的行不算。
pub fn host_name_in(known_hosts: &str, host_key: &KeyData) -> Option<String> {
    for line in known_hosts.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(names), Some(kind), Some(blob)) = (fields.next(), fields.next(), fields.next()) else { continue };
        if material::public_key_data(&format!("{kind} {blob}")).as_ref() != Some(host_key) {
            continue;
        }
        let shown = names.split(',').find(|name| !name.starts_with('|') && !name.starts_with('!') && !name.contains(['*', '?']));
        if let Some(name) = shown {
            return Some(match name.strip_prefix('[').and_then(|rest| rest.split_once("]:")) {
                Some((host, port)) => format!("{host}:{port}"),
                None => name.to_string(),
            });
        }
    }
    None
}

/// agent 與外界的邊界(production:`agent::AppAgentHost`;測試:替身)。
pub trait AgentHost: Send + Sync {
    /// 這台只在 SSHelter 的金鑰。
    fn keys(&self) -> Vec<VaultKey>;
    /// 保管庫裡這把金鑰的私鑰原文(有 passphrase 的仍是加密狀態)。
    fn private_key(&self, slot_id: &str) -> Result<Option<Zeroizing<String>>, AppError>;
    /// 這台的 agent 設定(保管庫檔頭)。讀不到時要往嚴格的一邊退(`always_ask`),不能退回預設值:預設值允許記住核准,而更嚴的設定正好讀不到
    /// (production:`AppAgentHost::settings`)。
    fn settings(&self) -> AgentSettings;
    fn keychain(&self) -> &dyn Keychain;
    fn now_ms(&self) -> u64;
    /// 顯示用的主機名稱(known_hosts)。
    fn host_name(&self, host_key: &KeyData) -> Option<String>;
    /// 問使用者(核准視窗,最多 60 秒);逾時或沒有回答 → None。
    fn ask(&self, request: AgentApprovalRequest) -> Option<AgentApprovalAnswer>;
}

/// Connect 的一次性通道(spec §5.6):只提供這把金鑰,已經核准。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub slot_id: String,
}

/// 解開的私鑰(沒記住 passphrase 的金鑰):留到記住的時間結束(spec §5.5)。
struct Unlocked {
    material: Arc<Material>,
    expires_ms: u64,
}

impl Unlocked {
    /// 還沒到期(到期的那一刻就算到期,同 `ApprovalCache`)。
    fn live(&self, now_ms: u64) -> bool {
        self.expires_ms > now_ms
    }
}

/// 等第一個請求最多多久:它可能先跳核准視窗,再跳最多 `PASSPHRASE_ATTEMPTS` 次只要 passphrase 的視窗,每個最多 `APPROVAL_TIMEOUT`;
/// 再加一點讀保管庫與解密的時間。有上限:主機的呼叫卡住(例如 keychain 的存取對話框)時,等的執行緒不會永遠掛著。
const SHARED_ANSWER_WAIT: Duration = Duration::from_secs(APPROVAL_TIMEOUT.as_secs() * (PASSPHRASE_ATTEMPTS as u64 + 1) + 10);

/// 正在問的「金鑰 × 主機 × 程式」:同時到的相同請求等這一個答案(spec §5.3)。
#[derive(Default)]
struct Pending {
    answer: Mutex<Option<bool>>,
    done: Condvar,
    followers: AtomicUsize,
}

impl Pending {
    fn finish(&self, allowed: bool) {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = Some(allowed);
        self.done.notify_all();
    }

    /// 等第一個請求的答案,最多 `SHARED_ANSWER_WAIT`(第一個請求可能連跳好幾個視窗);等不到(主機卡住)當成拒絕。
    fn wait(&self) -> bool {
        self.followers.fetch_add(1, Ordering::SeqCst);
        let answer = self.answer.lock().unwrap_or_else(PoisonError::into_inner);
        let (answer, _) = self
            .done
            .wait_timeout_while(answer, SHARED_ANSWER_WAIT, |answer| answer.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        answer.unwrap_or(false)
    }
}

/// 第一個請求問完(或 panic)時,讓等它的請求拿到答案,並從 `asking` 拿掉。
struct First<'a> {
    broker: &'a Broker,
    key: ApprovalKey,
    pending: Arc<Pending>,
    allowed: bool,
}

impl Drop for First<'_> {
    fn drop(&mut self) {
        self.broker.asking.lock().unwrap_or_else(PoisonError::into_inner).remove(&self.key);
        self.pending.finish(self.allowed);
    }
}

/// agent 在記憶體裡的狀態(`AgentRuntime::broker`):記住的核准、解開的私鑰、正在問的請求。到期的由 `expire` 丟掉(執行期每分鐘呼叫一次),
/// 螢幕鎖定(Plan 3)時 `clear`;SSHelter 結束時跟著行程消失。
#[derive(Default)]
pub struct Broker {
    approvals: Mutex<ApprovalCache>,
    unlocked: Mutex<HashMap<String, Unlocked>>,
    asking: Mutex<HashMap<ApprovalKey, Arc<Pending>>>,
}

/// 視窗裡顯示的使用者名稱最多幾個字元:它來自 ssh 送來的資料,可能很長。
const MAX_SHOWN_CHARS: usize = 256;

/// 最多 `max` 個字元,超過的部分換成「…」。
fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

/// 視窗的回答:passphrase 一拿到就包進 `Zeroizing`,不管有沒有允許、用不用得到,放掉時都會清掉。
struct Answer {
    allow: bool,
    remember: bool,
    passphrase: Option<Zeroizing<String>>,
    remember_passphrase: bool,
}

impl From<AgentApprovalAnswer> for Answer {
    fn from(answer: AgentApprovalAnswer) -> Self {
        Answer {
            allow: answer.allow,
            remember: answer.remember,
            passphrase: answer.passphrase.map(Zeroizing::new),
            remember_passphrase: answer.remember_passphrase,
        }
    }
}

/// 使用者已經允許(或是 Connect)、請求卻還是被拒絕:原因記到 stderr。只有插槽 id 與原因,不含金鑰內容、passphrase 與簽的資料。
fn refused(slot_id: &str, why: impl std::fmt::Display) {
    eprintln!("[agent] refused a request for slot {slot_id}: {why}");
}

/// 記在 keychain 的 passphrase(沒有或讀不到 → None);一拿到就包進 `Zeroizing`。
fn remembered_passphrase(host: &dyn AgentHost, slot_id: &str) -> Option<Zeroizing<String>> {
    host.keychain().get(&passphrase_account(slot_id)).ok().flatten().map(Zeroizing::new)
}

/// 這把金鑰的公鑰,只限 agent 簽得了的種類(`material::agent_can_sign`:Ed25519、ECDSA、RSA):`sk-*`(FIDO)與 DSA 的金鑰不列出,
/// 也不比對簽章請求,免得使用者核准之後才發現簽不出來。
fn signable_public_key(key: &VaultKey) -> Option<KeyData> {
    material::public_key_data(&key.public_key).filter(material::agent_can_sign)
}

/// 一個簽章請求要顯示的一切。
struct Ask<'a> {
    key: &'a VaultKey,
    request: &'a SignRequest,
    program: Option<&'a Program>,
    host_fingerprint: Option<String>,
    host_display: Option<String>,
    minutes: u32,
}

impl Ask<'_> {
    fn prompt(&self, preapproved: bool, needs_passphrase: bool, rememberable: bool, passphrase_error: Option<String>) -> AgentApprovalRequest {
        AgentApprovalRequest {
            id: String::new(),
            key_name: self.key.name.clone(),
            key_fingerprint: self.key.fingerprint.clone(),
            program_chain: self.program.map(|p| p.chain.clone()).unwrap_or_default(),
            user: self.request.user.as_deref().map(|user| shorten(user, MAX_SHOWN_CHARS)),
            host: self.host_display.clone(),
            host_fingerprint: self.host_fingerprint.clone(),
            rememberable,
            remember_minutes: self.minutes,
            needs_passphrase,
            passphrase_error,
            preapproved,
        }
    }

    /// 解開的私鑰就是請求指名的那一把嗎?保管庫裡的內容跟記錄的公鑰對不上(被換掉或壞掉了)就不能用:視窗沒顯示過的金鑰不簽。
    fn names(&self, material: &Material) -> bool {
        let same = material.key_data() == self.request.key;
        if !same {
            refused(&self.key.slot_id, "the vault entry is not the key the request names");
        }
        same
    }
}

impl Broker {
    /// 列出的金鑰:這台只在 SSHelter 的金鑰(而且是 agent 簽得了的種類);一次性通道只列它那一把。列出不必核准(公鑰不是祕密)。
    pub fn identities(&self, host: &dyn AgentHost, grant: Option<&Grant>) -> Vec<(KeyData, String)> {
        host.keys()
            .into_iter()
            .filter(|key| grant.is_none_or(|g| g.slot_id == key.slot_id))
            .filter_map(|key| signable_public_key(&key).map(|data| (data, key.name)))
            .collect()
    }

    /// 簽或不簽:回傳 signature blob,不簽 → None。可能等核准視窗。
    pub fn sign(&self, host: &dyn AgentHost, request: &SignRequest, program: Option<&Program>, grant: Option<&Grant>) -> Option<Vec<u8>> {
        // 轉送到遠端的 agent:一律拒絕(spec §3、§5.2)。
        if request.forwarded {
            return None;
        }
        let keys = host.keys();
        // Connect 的授權依插槽 id 找金鑰:兩個插槽可能放同一把公鑰,只比公鑰會找到另一個插槽;沒有授權才用公鑰找。
        let names_the_request = |k: &&VaultKey| signable_public_key(k).as_ref() == Some(&request.key);
        let key = match grant {
            Some(grant) => keys.iter().find(|k| k.slot_id == grant.slot_id).filter(names_the_request)?,
            None => keys.iter().find(names_the_request)?,
        };
        let settings = host.settings();
        let host_fingerprint = request.host_key.as_ref().map(|k| k.fingerprint(HashAlg::Sha256).to_string());
        let host_display = request
            .host_key
            .as_ref()
            .zip(host_fingerprint.as_ref())
            .map(|(k, fingerprint)| host.host_name(k).unwrap_or_else(|| fingerprint.clone()));
        let ask = Ask { key, request, program, host_fingerprint, host_display, minutes: remember_minutes(&settings) };
        let material = if grant.is_some() {
            // Connect:已經核准,不跳核准視窗、不算進記住的核准;只可能要 passphrase。
            self.unlock(host, &ask, None)?
        } else {
            self.approve(host, &ask, &settings)?
        };
        // 每一條路都會經過的一道關,不能當成多餘的拿掉:沒有加密的金鑰、用 keychain 裡記住的 passphrase 解開的金鑰,`unlock` 都是不經 `names` 就回傳,
        // 只有輸入 passphrase 的那條路在存下來之前先查過一次。保管庫裡的內容跟記錄的公鑰對不上,就不用視窗沒顯示過的金鑰簽。
        if !ask.names(&material) {
            return None;
        }
        match material.sign(&request.data, request.flags) {
            Ok(blob) => Some(blob),
            Err(e) => {
                refused(&key.slot_id, e);
                None
            }
        }
    }

    /// 忘掉記住的核准與解開的私鑰(螢幕鎖定;spec §5.3)。鎖中毒也照樣清:清除不能因為別的執行緒 panic 過就做不到。
    pub fn clear(&self) {
        self.approvals.lock().unwrap_or_else(PoisonError::into_inner).clear();
        self.unlocked.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }

    /// 把到期的記住的核准與解開的私鑰丟掉(spec §5.5:時間到就清除,不等下一個請求)。agent 的執行期每分鐘呼叫一次。
    pub fn expire(&self, now_ms: u64) {
        self.approvals.lock().unwrap_or_else(PoisonError::into_inner).prune(now_ms);
        self.unlocked.lock().unwrap_or_else(PoisonError::into_inner).retain(|_, u| u.live(now_ms));
    }

    /// 核准這次請求並解開私鑰;沒有允許(拒絕、逾時、passphrase 錯三次)→ None。
    fn approve(&self, host: &dyn AgentHost, ask: &Ask, settings: &AgentSettings) -> Option<Arc<Material>> {
        let approval_key = match (&ask.host_fingerprint, ask.program) {
            (Some(host_fingerprint), Some(program)) => Some(ApprovalKey {
                key_fingerprint: ask.key.fingerprint.clone(),
                host_fingerprint: host_fingerprint.clone(),
                program: program.identity.clone(),
            }),
            // 未知的主機或認不出的程式:問,而且不記住(spec §5.3、§5.4)。
            _ => None,
        };
        let now = host.now_ms();
        let remembered = approval_key.as_ref().is_some_and(|k| self.approvals.lock().unwrap().is_remembered(k, now));
        match verdict(KeyProtection::default(), settings, approval_key.is_some(), remembered) {
            Verdict::Remembered => self.unlock(host, ask, None),
            Verdict::Ask { rememberable: false } => self.ask_and_unlock(host, ask, None),
            Verdict::Ask { rememberable: true } => match approval_key {
                Some(approval_key) => self.ask_once(host, ask, approval_key),
                None => self.ask_and_unlock(host, ask, None),
            },
        }
    }

    /// 同一個「金鑰 × 主機 × 程式」同時只問一次:第一個請求問,其他的等它的答案(允許就各自解開、簽章)。
    fn ask_once(&self, host: &dyn AgentHost, ask: &Ask, approval_key: ApprovalKey) -> Option<Arc<Material>> {
        let (pending, first) = {
            let mut asking = self.asking.lock().unwrap();
            match asking.get(&approval_key) {
                Some(pending) => (Arc::clone(pending), false),
                None => {
                    let pending = Arc::new(Pending::default());
                    asking.insert(approval_key.clone(), Arc::clone(&pending));
                    (pending, true)
                }
            }
        };
        if !first {
            return if pending.wait() { self.unlock(host, ask, None) } else { None };
        }
        let mut first = First { broker: self, key: approval_key, pending, allowed: false };
        // 上一個相同的請求可能在這個請求查過之後才記住:再查一次(時間先取好,鎖裡不呼叫主機)。
        let now = host.now_ms();
        let remembered = self.approvals.lock().unwrap().is_remembered(&first.key, now);
        let material = if remembered {
            self.unlock(host, ask, None)
        } else {
            self.ask_and_unlock(host, ask, Some(&first.key))
        };
        first.allowed = material.is_some();
        material
    }

    /// 跳核准視窗,需要 passphrase 就一起問。允許了才解開私鑰;要記住的,解開之後才記住。
    fn ask_and_unlock(&self, host: &dyn AgentHost, ask: &Ask, approval_key: Option<&ApprovalKey>) -> Option<Arc<Material>> {
        let needs_passphrase = ask.key.has_passphrase
            && self.cached(&ask.key.slot_id, &ask.request.key, host.now_ms()).is_none()
            && remembered_passphrase(host, &ask.key.slot_id).is_none();
        let answer = Answer::from(host.ask(ask.prompt(false, needs_passphrase, approval_key.is_some(), None))?);
        if !answer.allow {
            return None;
        }
        let supplied = answer.passphrase.filter(|_| needs_passphrase).map(|passphrase| (passphrase, answer.remember_passphrase));
        let material = self.unlock(host, ask, supplied)?;
        if let (Some(key), true) = (approval_key, answer.remember) {
            self.remember(key.clone(), &ask.key.slot_id, host.now_ms(), ask.minutes);
        }
        Some(material)
    }

    /// 解開這把金鑰:記憶體裡解開的 → 不需要 passphrase → keychain 記住的 passphrase(不對就刪掉)→ 核准視窗帶回來的(`supplied`)或
    /// 再問(`preapproved`:只要 passphrase),一共三次。使用者已經允許卻打不開的原因記到 stderr(`refused`)。
    fn unlock(&self, host: &dyn AgentHost, ask: &Ask, mut supplied: Option<(Zeroizing<String>, bool)>) -> Option<Arc<Material>> {
        let slot_id = &ask.key.slot_id;
        if let Some(material) = self.cached(slot_id, &ask.request.key, host.now_ms()) {
            return Some(material);
        }
        let text = match host.private_key(slot_id) {
            Ok(Some(text)) => text,
            Ok(None) => {
                refused(slot_id, "the vault has no entry for this key");
                return None;
            }
            Err(e) => {
                refused(slot_id, format!("cannot read the key from the vault: {e}"));
                return None;
            }
        };
        match material::open(&text, None) {
            Ok(material) => return Some(Arc::new(material)),
            Err(OpenError::NeedsPassphrase) => {}
            Err(e) => {
                refused(slot_id, format!("cannot open the key: {e:?}"));
                return None;
            }
        }
        let account = passphrase_account(slot_id);
        if supplied.is_none() {
            if let Some(saved) = remembered_passphrase(host, slot_id) {
                match material::open(&text, Some(&saved)) {
                    Ok(material) => return Some(Arc::new(material)),
                    Err(OpenError::WrongPassphrase) => {
                        if let Err(e) = host.keychain().delete(&account) {
                            eprintln!("[agent] cannot forget the stale remembered passphrase of slot {slot_id}: {e}");
                        }
                    }
                    Err(e) => {
                        refused(slot_id, format!("cannot open the key: {e:?}"));
                        return None;
                    }
                }
            }
        }
        let mut error = None;
        for _ in 0..PASSPHRASE_ATTEMPTS {
            let (passphrase, remember) = match supplied.take() {
                Some(given) => given,
                None => {
                    let answer = Answer::from(host.ask(ask.prompt(true, true, false, error.take()))?);
                    if !answer.allow {
                        return None;
                    }
                    (answer.passphrase.unwrap_or_default(), answer.remember_passphrase)
                }
            };
            match material::open(&text, Some(&passphrase)) {
                Ok(material) => {
                    // 存進 keychain、留在記憶體之前先確認這就是請求指名的那一把:對不上的內容什麼都不留。
                    if !ask.names(&material) {
                        return None;
                    }
                    let material = Arc::new(material);
                    // 記住了:每次簽章時才用它解開,不留解開的私鑰(spec §5.5)。存不進 keychain 就留在記憶體。
                    let saved = remember && host.keychain().set(&account, &passphrase).is_ok();
                    if !saved {
                        let expires_ms = host.now_ms().saturating_add(u64::from(ask.minutes) * 60_000);
                        self.unlocked.lock().unwrap().insert(slot_id.clone(), Unlocked { material: Arc::clone(&material), expires_ms });
                    }
                    return Some(material);
                }
                Err(OpenError::WrongPassphrase) => error = Some(WRONG_PASSPHRASE.to_string()),
                Err(e) => {
                    refused(slot_id, format!("cannot open the key: {e:?}"));
                    return None;
                }
            }
        }
        None
    }

    /// 這個插槽在記憶體裡解開的私鑰,限請求指名的這把(`key`)。插槽放的金鑰換過(Keep a file → 另一把金鑰 → Only in SSHelter,插槽 id 沒變)時,
    /// 這個插槽的舊項目已經不是它的金鑰:丟掉、回傳 None,不拿舊的擋住新的(`names` 會拒絕它,`needs_passphrase` 也會因為它而不問新金鑰的 passphrase)。
    fn cached(&self, slot_id: &str, key: &KeyData, now_ms: u64) -> Option<Arc<Material>> {
        let mut unlocked = self.unlocked.lock().unwrap();
        unlocked.retain(|_, u| u.live(now_ms));
        if let Some(opened) = unlocked.get(slot_id) {
            if opened.material.key_data() == *key {
                return Some(Arc::clone(&opened.material));
            }
            unlocked.remove(slot_id);
        }
        None
    }

    /// 記住核准;這把金鑰解開的私鑰至少留到這個核准到期(spec §5.5)。
    fn remember(&self, key: ApprovalKey, slot_id: &str, now_ms: u64, minutes: u32) {
        self.approvals.lock().unwrap().remember(key, now_ms, minutes);
        let until = now_ms.saturating_add(u64::from(minutes) * 60_000);
        if let Some(unlocked) = self.unlocked.lock().unwrap().get_mut(slot_id) {
            unlocked.expires_ms = unlocked.expires_ms.max(until);
        }
    }

    /// 正在等別人答案的請求數(測試用)。
    #[cfg(test)]
    fn waiting(&self) -> usize {
        self.asking.lock().unwrap().values().map(|p| p.followers.load(Ordering::SeqCst)).sum()
    }

    /// 記在記憶體裡的核准數與解開的私鑰數(測試用;還沒清掉的過期項目也算)。
    #[cfg(test)]
    fn kept(&self) -> (usize, usize) {
        (self.approvals.lock().unwrap().len(), self.unlocked.lock().unwrap().len())
    }
}

/// 一條連線的 `SignAuthority`:連上的程式(連線時辨識一次,`peer`)與一次性通道的授權。
pub struct Connection<'a> {
    pub broker: &'a Broker,
    pub host: &'a dyn AgentHost,
    pub program: Option<Program>,
    pub grant: Option<Grant>,
}

impl SignAuthority for Connection<'_> {
    fn identities(&self) -> Vec<(KeyData, String)> {
        self.broker.identities(self.host, self.grant.as_ref())
    }

    fn sign(&self, request: &SignRequest) -> Option<Vec<u8>> {
        self.broker.sign(self.host, request, self.program.as_ref(), self.grant.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;
    use crate::sync::testkit::MemKeychain;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::time::Instant;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const ENC_ID: &str = "fedcba9876543210fedcba9876543210";

    struct FakeHost {
        keys: Vec<VaultKey>,
        private: HashMap<String, String>,
        settings: AgentSettings,
        keychain: MemKeychain,
        now: AtomicU64,
        names: HashMap<String, String>,
        answers: Mutex<VecDeque<Option<AgentApprovalAnswer>>>,
        asked: Mutex<Vec<AgentApprovalRequest>>,
        /// `ask` 回答之前先等這道閘門打開(平行的測試把它關起來)。
        gate: Mutex<bool>,
        opened: Condvar,
    }

    impl FakeHost {
        fn new() -> Self {
            let key = |slot_id: &str, name: &str, public: &str, fingerprint: &str, has_passphrase: bool| VaultKey {
                slot_id: slot_id.into(),
                name: name.into(),
                fingerprint: fingerprint.into(),
                public_key: public.into(),
                has_passphrase,
            };
            FakeHost {
                keys: vec![
                    key(ID, "id_mac", test_keys::PLAIN_PUBLIC, test_keys::PLAIN_FINGERPRINT, false),
                    key(ENC_ID, "id_enc", test_keys::ENC_PUBLIC, test_keys::ENC_FINGERPRINT, true),
                ],
                private: HashMap::from([(ID.to_string(), test_keys::plain()), (ENC_ID.to_string(), test_keys::encrypted())]),
                settings: AgentSettings::default(),
                keychain: MemKeychain::default(),
                now: AtomicU64::new(1_000),
                names: HashMap::new(),
                answers: Mutex::new(VecDeque::new()),
                asked: Mutex::new(Vec::new()),
                gate: Mutex::new(true),
                opened: Condvar::new(),
            }
        }

        fn answer(&self, answer: Option<AgentApprovalAnswer>) {
            self.answers.lock().unwrap().push_back(answer);
        }

        fn asked(&self) -> Vec<AgentApprovalRequest> {
            self.asked.lock().unwrap().clone()
        }

        fn advance(&self, ms: u64) {
            self.now.fetch_add(ms, Ordering::SeqCst);
        }
    }

    impl AgentHost for FakeHost {
        fn keys(&self) -> Vec<VaultKey> {
            self.keys.clone()
        }
        fn private_key(&self, slot_id: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            Ok(self.private.get(slot_id).cloned().map(Zeroizing::new))
        }
        fn settings(&self) -> AgentSettings {
            self.settings.clone()
        }
        fn keychain(&self) -> &dyn Keychain {
            &self.keychain
        }
        fn now_ms(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
        fn host_name(&self, host_key: &KeyData) -> Option<String> {
            self.names.get(&host_key.fingerprint(HashAlg::Sha256).to_string()).cloned()
        }
        fn ask(&self, request: AgentApprovalRequest) -> Option<AgentApprovalAnswer> {
            self.asked.lock().unwrap().push(request);
            let open = self.gate.lock().unwrap();
            drop(self.opened.wait_while(open, |open| !*open).unwrap());
            self.answers.lock().unwrap().pop_front().flatten()
        }
    }

    fn allow(remember: bool) -> Option<AgentApprovalAnswer> {
        Some(AgentApprovalAnswer { allow: true, remember, ..Default::default() })
    }

    fn with_passphrase(passphrase: &str, remember_passphrase: bool) -> Option<AgentApprovalAnswer> {
        Some(AgentApprovalAnswer { allow: true, remember: true, passphrase: Some(passphrase.into()), remember_passphrase })
    }

    fn program(identity: &str) -> Program {
        Program { chain: vec![identity.into(), "ssh".into()], identity: identity.into() }
    }

    fn host_key() -> KeyData {
        material::public_key_data(test_keys::ECDSA_PUBLIC).unwrap()
    }

    fn request(public: &str, host: Option<KeyData>) -> SignRequest {
        SignRequest {
            key: material::public_key_data(public).unwrap(),
            data: b"to sign".to_vec(),
            flags: 0,
            user: Some("root".into()),
            host_key: host,
            forwarded: false,
        }
    }

    fn verifies(public: &str, blob: &[u8]) -> bool {
        use signature::Verifier;
        use ssh_encoding::Decode;
        let signature = ssh_key::Signature::decode(&mut &blob[..]).unwrap();
        material::public_key_data(public).unwrap().verify(b"to sign", &signature).is_ok()
    }

    /// 等條件成立,最多 5 秒(不然出錯時平行的測試會卡住)。
    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn vault_keys_come_from_vault_slots_only() {
        let mut state = SyncStateV2::fresh("mac").unwrap();
        let slot = |file: &str, source: Option<SlotSource>| crate::sync::state_v2::LocalSlot {
            file_name: file.into(),
            source,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
        };
        let vault = SlotSource::Vault {
            fingerprint: test_keys::PLAIN_FINGERPRINT.into(),
            public_key: test_keys::PLAIN_PUBLIC.into(),
            has_passphrase: false,
        };
        state.key_slots.insert(ID.into(), slot("id_mac-01234567", Some(vault)));
        state.key_slots.insert(ENC_ID.into(), slot("other-fedcba98", Some(SlotSource::SyncedCopy { fingerprint: "SHA256:x".into() })));
        let keys = vault_keys(&state);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].slot_id, ID);
        assert_eq!(keys[0].name, "id_mac-01234567", "no payload: the slot file name");
        assert_eq!(keys[0].public_key, test_keys::PLAIN_PUBLIC);
    }

    #[test]
    fn identities_list_the_vault_keys_and_a_grant_lists_only_its_own() {
        let broker = Broker::default();
        let host = FakeHost::new();
        let all = broker.identities(&host, None);
        assert_eq!(all.iter().map(|(_, name)| name.as_str()).collect::<Vec<_>>(), vec!["id_mac", "id_enc"]);
        let one = broker.identities(&host, Some(&Grant { slot_id: ENC_ID.into() }));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].0, material::public_key_data(test_keys::ENC_PUBLIC).unwrap());
    }

    #[test]
    fn a_remembered_approval_is_reused_for_the_same_program_and_host_only() {
        let broker = Broker::default();
        let host = FakeHost::new();
        let claude = program("claude");
        host.answer(allow(true));
        let blob = broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&claude), None).unwrap();
        assert!(verifies(test_keys::PLAIN_PUBLIC, &blob));
        let first = &host.asked()[0];
        assert!(first.rememberable && !first.needs_passphrase && !first.preapproved);
        assert_eq!(first.program_chain, vec!["claude", "ssh"]);
        assert_eq!(first.user.as_deref(), Some("root"));
        assert_eq!(first.remember_minutes, 240);
        assert_eq!(first.host_fingerprint, Some(host_key().fingerprint(HashAlg::Sha256).to_string()));

        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&claude), None).is_some());
        assert_eq!(host.asked().len(), 1, "remembered: no second prompt");

        host.answer(allow(false));
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("iterm2")), None).is_some());
        assert_eq!(host.asked().len(), 2, "another program asks again");

        host.advance(240 * 60_000);
        host.answer(allow(false));
        broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&claude), None);
        assert_eq!(host.asked().len(), 3, "expired after the remember window");
    }

    #[test]
    fn an_unknown_host_or_program_always_asks_and_is_never_remembered() {
        let broker = Broker::default();
        let host = FakeHost::new();
        for _ in 0..2 {
            host.answer(allow(true));
            assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, None), Some(&program("claude")), None).is_some());
        }
        for _ in 0..2 {
            host.answer(allow(true));
            assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), None, None).is_some());
        }
        let asked = host.asked();
        assert_eq!(asked.len(), 4);
        assert!(asked.iter().all(|r| !r.rememberable));
        assert_eq!(asked[0].host, None);
        assert!(asked[2].program_chain.is_empty());
    }

    #[test]
    fn this_computers_always_ask_setting_is_never_remembered() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        host.settings.always_ask = true;
        for _ in 0..2 {
            host.answer(allow(true));
            broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        }
        assert_eq!(host.asked().len(), 2);
        assert!(!host.asked()[0].rememberable);
    }

    #[test]
    fn deny_timeout_forwarding_and_unknown_keys_refuse() {
        let broker = Broker::default();
        let host = FakeHost::new();
        let claude = program("claude");
        host.answer(Some(AgentApprovalAnswer { allow: false, remember: true, ..Default::default() }));
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&claude), None).is_none());
        host.answer(None);
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&claude), None).is_none(), "timed out");
        assert_eq!(host.asked().len(), 2, "a denial is not remembered");

        let mut forwarded = request(test_keys::PLAIN_PUBLIC, Some(host_key()));
        forwarded.forwarded = true;
        assert!(broker.sign(&host, &forwarded, Some(&claude), None).is_none());
        assert!(broker.sign(&host, &request(test_keys::ECDSA_PUBLIC, Some(host_key())), Some(&claude), None).is_none(), "not a vault key");
        assert_eq!(host.asked().len(), 2, "neither asks");
    }

    #[test]
    fn the_host_shows_its_known_hosts_name_or_its_fingerprint() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        host.answer(allow(false));
        broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("a")), None);
        assert_eq!(host.asked()[0].host, Some(host_key().fingerprint(HashAlg::Sha256).to_string()));
        host.names.insert(host_key().fingerprint(HashAlg::Sha256).to_string(), "web".into());
        host.answer(allow(false));
        broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("b")), None);
        assert_eq!(host.asked()[1].host.as_deref(), Some("web"));
    }

    #[test]
    fn known_hosts_names_skip_hashed_names_patterns_and_markers() {
        let key = host_key();
        let line = |names: &str| format!("{names} {}\n", test_keys::ECDSA_PUBLIC);
        assert_eq!(host_name_in(&line("web,10.0.0.5"), &key).as_deref(), Some("web"));
        assert_eq!(host_name_in(&line("[web]:2222"), &key).as_deref(), Some("web:2222"));
        assert_eq!(host_name_in(&line("|1|c2FsdA==|aGFzaA==,lab"), &key).as_deref(), Some("lab"));
        assert_eq!(host_name_in(&line("|1|c2FsdA==|aGFzaA=="), &key), None);
        assert_eq!(host_name_in(&line("*.lab,!x"), &key), None);
        assert_eq!(host_name_in(&format!("@cert-authority *.lab {}\n# web\n", test_keys::ECDSA_PUBLIC), &key), None);
        assert_eq!(host_name_in(&format!("web {}\n", test_keys::PLAIN_PUBLIC), &key), None, "another key");
    }

    #[test]
    fn a_passphrase_is_asked_with_the_approval_and_kept_in_memory_for_the_remember_window() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.answer(with_passphrase("test-passphrase", false));
        let blob = broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        assert!(verifies(test_keys::ENC_PUBLIC, &blob));
        assert!(host.asked()[0].needs_passphrase);
        assert_eq!(host.keychain.entry(&passphrase_account(ENC_ID)), None, "not remembered on this computer");

        host.answer(allow(false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("iterm2")), None).unwrap();
        assert!(!host.asked()[1].needs_passphrase, "still open in memory");

        host.advance(240 * 60_000);
        host.answer(with_passphrase("test-passphrase", false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("iterm2")), None).unwrap();
        assert!(host.asked()[2].needs_passphrase, "the opened key is dropped when the window ends");
    }

    #[test]
    fn three_wrong_passphrases_refuse_and_a_right_retry_signs() {
        let broker = Broker::default();
        let host = FakeHost::new();
        for _ in 0..3 {
            host.answer(with_passphrase("wrong", false));
        }
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_none());
        let asked = host.asked();
        assert_eq!(asked.len(), 3);
        assert!(asked[1].preapproved && asked[1].needs_passphrase && !asked[1].rememberable);
        assert_eq!(asked[1].passphrase_error.as_deref(), Some(WRONG_PASSPHRASE));

        host.answer(with_passphrase("wrong", false));
        host.answer(with_passphrase("test-passphrase", false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_some());
        assert!(!host.asked()[3].preapproved, "the failed attempt was not remembered as an approval");
    }

    #[test]
    fn a_remembered_passphrase_lives_in_the_keychain_not_in_memory() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.answer(with_passphrase("test-passphrase", true));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        assert_eq!(host.keychain.entry(&passphrase_account(ENC_ID)).as_deref(), Some("test-passphrase"));

        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        assert_eq!(host.asked().len(), 1, "approval remembered, passphrase from the keychain");

        host.keychain.delete(&passphrase_account(ENC_ID)).unwrap();
        host.answer(with_passphrase("test-passphrase", false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        let unlock = &host.asked()[1];
        assert!(unlock.preapproved && unlock.needs_passphrase, "the opened key was never kept in memory");
    }

    #[test]
    fn a_stale_remembered_passphrase_is_forgotten_and_asked_again() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.keychain.set(&passphrase_account(ENC_ID), "old").unwrap();
        host.answer(allow(false));
        host.answer(with_passphrase("test-passphrase", false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_some());
        let asked = host.asked();
        assert!(!asked[0].needs_passphrase, "the keychain had one");
        assert!(asked[1].preapproved && asked[1].needs_passphrase && asked[1].passphrase_error.is_none());
        assert_eq!(host.keychain.entry(&passphrase_account(ENC_ID)), None, "the wrong one is gone");
    }

    #[test]
    fn a_connect_grant_skips_the_approval_and_asks_only_for_a_passphrase() {
        let broker = Broker::default();
        let host = FakeHost::new();
        let grant = Grant { slot_id: ID.into() };
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), None, Some(&grant)).is_some());
        assert!(host.asked().is_empty());
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), None, Some(&grant)).is_none(), "only the granted key");

        let grant = Grant { slot_id: ENC_ID.into() };
        host.answer(with_passphrase("test-passphrase", false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), None, Some(&grant)).is_some());
        let asked = host.asked();
        assert!(asked[0].preapproved && asked[0].needs_passphrase && !asked[0].rememberable);

        host.answer(allow(false));
        broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("claude")), None);
        assert_eq!(host.asked().len(), 2, "a grant is not a remembered approval");
    }

    #[test]
    fn identical_requests_at_the_same_time_share_one_prompt() {
        let broker = Arc::new(Broker::default());
        let host = Arc::new(FakeHost::new());
        *host.gate.lock().unwrap() = false;
        host.answer(allow(false));
        let sign = |broker: Arc<Broker>, host: Arc<FakeHost>| {
            std::thread::spawn(move || {
                broker.sign(host.as_ref(), &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("git")), None)
            })
        };
        let first = sign(Arc::clone(&broker), Arc::clone(&host));
        wait_until("the first request is asking", || !host.asked().is_empty());
        let others: Vec<_> = (0..3).map(|_| sign(Arc::clone(&broker), Arc::clone(&host))).collect();
        wait_until("three requests wait for its answer", || broker.waiting() >= 3);
        *host.gate.lock().unwrap() = true;
        host.opened.notify_all();
        assert!(first.join().unwrap().is_some());
        for other in others {
            assert!(other.join().unwrap().is_some(), "the shared answer allowed it");
        }
        assert_eq!(host.asked().len(), 1, "one prompt for all four");
    }

    #[test]
    fn a_very_long_user_name_is_shortened_for_the_window() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.answer(allow(false));
        let mut long = request(test_keys::PLAIN_PUBLIC, Some(host_key()));
        long.user = Some("u".repeat(5000));
        broker.sign(&host, &long, Some(&program("claude")), None);
        let shown = host.asked()[0].user.clone().unwrap();
        assert_eq!(shown.chars().count(), 257);
        assert!(shown.ends_with('…'));
    }

    #[test]
    fn clear_forgets_approvals_and_opened_keys() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.answer(with_passphrase("test-passphrase", false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        broker.clear();
        host.answer(with_passphrase("test-passphrase", false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        let again = &host.asked()[1];
        assert!(!again.preapproved && again.needs_passphrase, "asks for the approval and the passphrase again");
    }

    // 邊界情況:共用的詢問被拒絕或視窗 panic、解開的私鑰的壽命、keychain 存不進去、顯示名稱、`Connection`。

    /// 另開一條執行緒簽一個 `git` 發出的請求(平行的測試用)。
    fn sign_in_thread<H: AgentHost + 'static>(broker: &Arc<Broker>, host: &Arc<H>) -> std::thread::JoinHandle<Option<Vec<u8>>> {
        let (broker, host) = (Arc::clone(broker), Arc::clone(host));
        std::thread::spawn(move || broker.sign(host.as_ref(), &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("git")), None))
    }

    /// 第一次被問就在核准視窗裡 panic 的主機(閘門打開之後才 panic);之後的詢問交給 `FakeHost`。
    struct PanicsOnce {
        host: FakeHost,
        armed: AtomicBool,
    }

    impl AgentHost for PanicsOnce {
        fn keys(&self) -> Vec<VaultKey> {
            self.host.keys()
        }
        fn private_key(&self, slot_id: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            self.host.private_key(slot_id)
        }
        fn settings(&self) -> AgentSettings {
            self.host.settings()
        }
        fn keychain(&self) -> &dyn Keychain {
            self.host.keychain()
        }
        fn now_ms(&self) -> u64 {
            self.host.now_ms()
        }
        fn host_name(&self, host_key: &KeyData) -> Option<String> {
            self.host.host_name(host_key)
        }
        fn ask(&self, request: AgentApprovalRequest) -> Option<AgentApprovalAnswer> {
            if !self.armed.swap(false, Ordering::SeqCst) {
                return self.host.ask(request);
            }
            self.host.asked.lock().unwrap().push(request);
            let open = self.host.gate.lock().unwrap();
            drop(self.host.opened.wait_while(open, |open| !*open).unwrap());
            panic!("the window failed");
        }
    }

    #[test]
    fn a_denied_shared_prompt_refuses_every_request_waiting_on_it() {
        let broker = Arc::new(Broker::default());
        let host = Arc::new(FakeHost::new());
        *host.gate.lock().unwrap() = false;
        host.answer(Some(AgentApprovalAnswer { allow: false, remember: true, ..Default::default() }));
        let first = sign_in_thread(&broker, &host);
        wait_until("the first request is asking", || !host.asked().is_empty());
        let others: Vec<_> = (0..3).map(|_| sign_in_thread(&broker, &host)).collect();
        wait_until("three requests wait for its answer", || broker.waiting() >= 3);
        *host.gate.lock().unwrap() = true;
        host.opened.notify_all();
        assert!(first.join().unwrap().is_none());
        for other in others {
            assert!(other.join().unwrap().is_none(), "the shared denial refused it");
        }
        assert_eq!(host.asked().len(), 1, "one prompt for all four");
        assert_eq!(broker.waiting(), 0, "nobody is left waiting");

        host.answer(allow(false));
        assert!(broker.sign(host.as_ref(), &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("git")), None).is_some());
        assert_eq!(host.asked().len(), 2, "a denial is not remembered: the next request asks again");
    }

    #[test]
    fn a_window_that_panics_leaves_nobody_waiting_and_nothing_stuck() {
        let broker = Arc::new(Broker::default());
        let host = Arc::new(PanicsOnce { host: FakeHost::new(), armed: AtomicBool::new(true) });
        *host.host.gate.lock().unwrap() = false;
        let started = Instant::now();
        let first = sign_in_thread(&broker, &host);
        wait_until("the first request is asking", || !host.host.asked().is_empty());
        let others: Vec<_> = (0..2).map(|_| sign_in_thread(&broker, &host)).collect();
        wait_until("two requests wait for its answer", || broker.waiting() >= 2);
        *host.host.gate.lock().unwrap() = true;
        host.host.opened.notify_all();
        assert!(first.join().is_err(), "the window's panic reaches the request that asked");
        for other in others {
            assert_eq!(other.join().unwrap(), None, "refused, not left waiting");
        }
        assert!(started.elapsed() < Duration::from_secs(30), "released at once, not when their wait ran out");
        assert_eq!(broker.waiting(), 0, "the key is not stuck in the waiting table");

        host.host.answer(allow(false));
        assert!(broker.sign(host.as_ref(), &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("git")), None).is_some());
    }

    #[test]
    fn a_later_remembered_approval_keeps_the_opened_key_open_as_long_as_it_lasts() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.answer(with_passphrase("test-passphrase", false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        host.advance(100 * 60_000);
        host.answer(allow(true));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("iterm2")), None).unwrap();
        // 250 分鐘:claude 的核准到期了,iterm2 的(340 分鐘到期)還在,所以解開的私鑰也還在。
        host.advance(150 * 60_000);
        host.answer(allow(false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        let asked = host.asked();
        assert_eq!(asked.len(), 3, "claude's own approval had expired");
        assert!(!asked[2].needs_passphrase, "the later approval extended how long the key stays open");
    }

    #[test]
    fn a_passphrase_the_keychain_will_not_keep_leaves_the_opened_key_in_memory() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.keychain.fail_writes_to(&passphrase_account(ENC_ID), true);
        host.answer(with_passphrase("test-passphrase", true));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        assert_eq!(host.keychain.entry(&passphrase_account(ENC_ID)), None, "the keychain refused it");

        host.answer(allow(false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("iterm2")), None).unwrap();
        assert!(!host.asked()[1].needs_passphrase, "so the opened key stayed in memory instead");
    }

    #[test]
    fn a_vault_key_is_named_after_its_slot_when_the_slot_has_a_name() {
        use crate::sync::slot_rules::{KeySlotPayload, SlotMode};
        let slot = |file: &str, name: &str| crate::sync::state_v2::LocalSlot {
            file_name: file.into(),
            source: Some(SlotSource::Vault {
                fingerprint: test_keys::PLAIN_FINGERPRINT.into(),
                public_key: test_keys::PLAIN_PUBLIC.into(),
                has_passphrase: false,
            }),
            last_error: None,
            asked: false,
            payload: Some(KeySlotPayload {
                schema: 1,
                name: name.into(),
                mode: SlotMode::Own,
                origin_device_id: "d".repeat(32),
                created_at_ms: 0,
                public_key: None,
                fingerprint: None,
                key_type: None,
                has_passphrase: None,
            }),
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
        };
        let mut state = SyncStateV2::fresh("mac").unwrap();
        state.key_slots.insert(ID.into(), slot("id_mac-01234567", "Work laptop"));
        state.key_slots.insert(ENC_ID.into(), slot("nameless-fedcba98", ""));
        let names: HashMap<String, String> = vault_keys(&state).into_iter().map(|key| (key.slot_id, key.name)).collect();
        assert_eq!(names[ID], "Work laptop");
        assert_eq!(names[ENC_ID], "nameless-fedcba98", "an empty name falls back to the slot file name");
    }

    #[test]
    fn a_connection_decides_with_its_own_program_and_grant() {
        let broker = Broker::default();
        let host = FakeHost::new();
        let claude = Connection { broker: &broker, host: &host, program: Some(program("claude")), grant: None };
        assert_eq!(claude.identities().len(), 2);
        host.answer(allow(true));
        assert!(claude.sign(&request(test_keys::PLAIN_PUBLIC, Some(host_key()))).is_some());
        assert!(claude.sign(&request(test_keys::PLAIN_PUBLIC, Some(host_key()))).is_some());
        assert_eq!(host.asked().len(), 1, "the connection's program is the one the approval is remembered for");

        let connect = Connection { broker: &broker, host: &host, program: None, grant: Some(Grant { slot_id: ENC_ID.into() }) };
        assert_eq!(connect.identities().len(), 1, "a grant lists only its own key");
        assert!(connect.sign(&request(test_keys::PLAIN_PUBLIC, Some(host_key()))).is_none(), "and signs only with it");
        assert_eq!(host.asked().len(), 1, "without asking");
    }

    // agent 簽不了的金鑰、保管庫裡對不上的內容、核准的主機與金鑰、使用者允許之後的拒絕、等待的上限、到期與中毒的鎖。

    /// 在替身主機上加一把沒有 passphrase 的金鑰。
    fn add_key(host: &mut FakeHost, slot_id: &str, name: &str, public: &str, fingerprint: &str, private: String) {
        host.keys.push(VaultKey {
            slot_id: slot_id.into(),
            name: name.into(),
            fingerprint: fingerprint.into(),
            public_key: public.into(),
            has_passphrase: false,
        });
        host.private.insert(slot_id.into(), private);
    }

    #[test]
    fn keys_the_agent_cannot_sign_with_are_neither_listed_nor_matched() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        let (sk, dsa) = (test_keys::sk_public(), test_keys::dsa_public());
        assert!(material::public_key_data(&sk).is_some() && material::public_key_data(&dsa).is_some(), "the fixtures are valid public keys");
        add_key(&mut host, &"1".repeat(32), "id_sk", &sk, "SHA256:sk", test_keys::plain());
        add_key(&mut host, &"2".repeat(32), "id_dsa", &dsa, "SHA256:dsa", test_keys::plain());
        let names: Vec<String> = broker.identities(&host, None).into_iter().map(|(_, name)| name).collect();
        assert_eq!(names, vec!["id_mac", "id_enc"], "only Ed25519, ECDSA and RSA keys are listed");
        for public in [&sk, &dsa] {
            assert!(broker.sign(&host, &request(public, Some(host_key())), Some(&program("claude")), None).is_none());
        }
        assert!(host.asked().is_empty(), "and nobody is asked about them");
    }

    #[test]
    fn ed25519_ecdsa_and_rsa_vault_keys_are_listed_and_sign() {
        use crate::vault::material::SSH_AGENT_RSA_SHA2_256;
        let broker = Broker::default();
        let mut host = FakeHost::new();
        let (ecdsa_id, rsa_id) = ("3".repeat(32), "4".repeat(32));
        add_key(&mut host, &ecdsa_id, "id_ecdsa", test_keys::ECDSA_PUBLIC, test_keys::ECDSA_FINGERPRINT, test_keys::ecdsa());
        add_key(&mut host, &rsa_id, "id_rsa", test_keys::RSA_PUBLIC, test_keys::RSA_FINGERPRINT, test_keys::rsa());
        let names: Vec<String> = broker.identities(&host, None).into_iter().map(|(_, name)| name).collect();
        assert_eq!(names, vec!["id_mac", "id_enc", "id_ecdsa", "id_rsa"]);
        for (public, slot_id, flags) in [(test_keys::ECDSA_PUBLIC, ecdsa_id, 0), (test_keys::RSA_PUBLIC, rsa_id, SSH_AGENT_RSA_SHA2_256)] {
            let mut ask = request(public, Some(host_key()));
            ask.flags = flags;
            let blob = broker.sign(&host, &ask, None, Some(&Grant { slot_id })).unwrap();
            assert!(verifies(public, &blob));
        }
    }

    #[test]
    fn a_vault_entry_that_is_not_the_recorded_key_never_signs() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        // 保管庫裡這個插槽放的是另一把金鑰(被換掉或壞掉了)。
        host.private.insert(ID.to_string(), test_keys::ecdsa());
        host.answer(allow(false));
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_none());
        assert_eq!(host.asked().len(), 1, "the window was shown for the recorded key");

        host.private.insert(ID.to_string(), test_keys::plain());
        host.answer(allow(false));
        let blob = broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        assert!(verifies(test_keys::PLAIN_PUBLIC, &blob), "once the entry is the recorded key again it signs");
    }

    #[test]
    fn a_mismatched_entry_keeps_nothing_it_was_opened_with() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        // 記錄說這是那把 RSA 金鑰,保管庫裡放的卻是加密過的 ed25519 金鑰。
        host.keys[1].public_key = test_keys::RSA_PUBLIC.into();
        host.keys[1].fingerprint = test_keys::RSA_FINGERPRINT.into();
        host.answer(with_passphrase("test-passphrase", true));
        assert!(broker.sign(&host, &request(test_keys::RSA_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_none());
        assert_eq!(host.keychain.entry(&passphrase_account(ENC_ID)), None, "its passphrase is not saved");

        host.answer(with_passphrase("test-passphrase", true));
        assert!(broker.sign(&host, &request(test_keys::RSA_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_none());
        let asked = host.asked();
        assert_eq!(asked.len(), 2, "the approval was not remembered either");
        assert!(!asked[1].preapproved && asked[1].needs_passphrase, "and the opened key was not kept");
    }

    /// `unlock` 用 keychain 裡記住的 passphrase 解開時不經 `names` 就回傳(沒有加密的金鑰也一樣):`sign` 最後那一道 `names` 要擋下內容跟記錄不符的金鑰,
    /// 不能因為看起來多餘就拿掉。
    #[test]
    fn a_key_opened_with_the_remembered_passphrase_is_still_checked_against_the_recorded_key() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        // 記錄說 `ENC_ID` 這個插槽是 RSA 金鑰(有 passphrase),保管庫裡放的卻是加密過的 ed25519 金鑰,而 keychain 記著它的 passphrase。
        host.keys[1].public_key = test_keys::RSA_PUBLIC.into();
        host.keys[1].fingerprint = test_keys::RSA_FINGERPRINT.into();
        host.keychain.set(&passphrase_account(ENC_ID), "test-passphrase").unwrap();
        host.answer(allow(false));
        assert!(broker.sign(&host, &rsa_request(), Some(&program("claude")), None).is_none(), "the entry is not the recorded key, so nothing is signed");
        assert_eq!(host.asked().len(), 1, "the window was shown for the recorded key");
        assert!(!host.asked()[0].needs_passphrase, "the remembered passphrase opened the entry, which is how it got past `unlock`");
        assert_eq!(broker.kept().1, 0, "and nothing was kept open");
    }

    #[test]
    fn a_remembered_approval_is_for_that_host_and_that_key_only() {
        let broker = Broker::default();
        let host = FakeHost::new();
        let claude = program("claude");
        host.answer(allow(true));
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&claude), None).is_some());

        let elsewhere = material::public_key_data(test_keys::RSA_PUBLIC).unwrap();
        host.answer(allow(false));
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(elsewhere)), Some(&claude), None).is_some());
        assert_eq!(host.asked().len(), 2, "another host asks again");

        host.answer(with_passphrase("test-passphrase", false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&claude), None).is_some());
        let asked = host.asked();
        assert_eq!(asked.len(), 3, "another key asks again");
        // 這把金鑰有 passphrase,不管核准記沒記住都會問一次:要是整個核准視窗,而不只是問 passphrase,才算核准沒記住。
        assert!(!asked[2].preapproved, "with the whole approval window, not only for the passphrase");

        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&claude), None).is_some());
        assert_eq!(host.asked().len(), 3, "and the first approval is still remembered");
    }

    #[test]
    fn a_key_that_cannot_be_opened_after_the_user_allowed_is_refused() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        host.private.remove(ID);
        host.answer(allow(false));
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_none(), "no vault entry");
        host.private.insert(ID.to_string(), "not a key".to_string());
        host.answer(allow(false));
        assert!(broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_none(), "unreadable");
        assert_eq!(host.asked().len(), 2, "the user was asked both times");
    }

    #[test]
    fn a_stale_remembered_passphrase_that_cannot_be_forgotten_is_still_asked_again() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.keychain.set(&passphrase_account(ENC_ID), "old").unwrap();
        host.keychain.fail_deletes.store(true, Ordering::SeqCst);
        host.answer(allow(false));
        host.answer(with_passphrase("test-passphrase", false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_some());
        assert_eq!(host.keychain.entry(&passphrase_account(ENC_ID)).as_deref(), Some("old"), "the keychain refused the delete");
    }

    #[test]
    fn waiters_outlast_the_longest_thing_the_first_request_can_do() {
        // 最長的路:核准視窗沒帶 passphrase,接著每一次輸入的 passphrase 都不對。
        let broker = Broker::default();
        let host = FakeHost::new();
        host.answer(allow(false));
        for _ in 0..PASSPHRASE_ATTEMPTS {
            host.answer(with_passphrase("wrong", false));
        }
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_none());
        let windows = host.asked().len();
        assert_eq!(windows, PASSPHRASE_ATTEMPTS + 1, "the approval window, then one window per attempt");
        assert!(SHARED_ANSWER_WAIT > APPROVAL_TIMEOUT * u32::try_from(windows).unwrap(), "each window may take its whole timeout");
    }

    #[test]
    fn expire_drops_what_has_run_out_without_waiting_for_the_next_request() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.answer(with_passphrase("test-passphrase", false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        assert_eq!(broker.kept(), (1, 1), "one remembered approval and one opened key");

        host.advance(240 * 60_000 - 1);
        broker.expire(host.now_ms());
        assert_eq!(broker.kept(), (1, 1), "the window has not ended yet");

        host.advance(1);
        broker.expire(host.now_ms());
        assert_eq!(broker.kept(), (0, 0), "both are dropped when the window ends, with no request in between");

        host.answer(with_passphrase("test-passphrase", false));
        broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).unwrap();
        let again = &host.asked()[1];
        assert!(!again.preapproved && again.needs_passphrase, "asks for the approval and the passphrase again");
    }

    #[test]
    fn clear_and_expire_survive_a_poisoned_lock() {
        let broker = Arc::new(Broker::default());
        let (a, b) = (Arc::clone(&broker), Arc::clone(&broker));
        // 兩把鎖都在持有的執行緒 panic 時中毒。
        assert!(std::thread::spawn(move || {
            let _guard = a.approvals.lock().unwrap();
            panic!("poisons the approvals lock");
        })
        .join()
        .is_err());
        assert!(std::thread::spawn(move || {
            let _guard = b.unlocked.lock().unwrap();
            panic!("poisons the opened keys lock");
        })
        .join()
        .is_err());
        broker.expire(0);
        broker.clear();
    }

    // 插槽放的金鑰換過(Keep a file → 另一把金鑰 → Only in SSHelter,插槽 id 沒變)與 Connect 的授權依插槽 id 找金鑰。

    /// 把 `ENC_ID` 這個插槽換成沒有 passphrase 的 RSA 金鑰:記錄(公鑰、指紋)與保管庫裡的私鑰都換了,插槽 id 不變。
    fn swap_in_the_rsa_key(host: &mut FakeHost) {
        host.keys[1].public_key = test_keys::RSA_PUBLIC.into();
        host.keys[1].fingerprint = test_keys::RSA_FINGERPRINT.into();
        host.keys[1].has_passphrase = false;
        host.private.insert(ENC_ID.to_string(), test_keys::rsa());
    }

    /// 簽 RSA 金鑰的請求(要 SHA-256 的簽章)。
    fn rsa_request() -> SignRequest {
        let mut rsa = request(test_keys::RSA_PUBLIC, Some(host_key()));
        rsa.flags = material::SSH_AGENT_RSA_SHA2_256;
        rsa
    }

    #[test]
    fn a_slots_new_key_signs_after_its_own_approval_while_the_old_key_is_still_open() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        host.answer(with_passphrase("test-passphrase", false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_some());
        assert_eq!(broker.kept().1, 1, "setup: the passphrase key stays open in memory");

        swap_in_the_rsa_key(&mut host);
        host.answer(allow(false));
        let blob = broker.sign(&host, &rsa_request(), Some(&program("claude")), None).expect("the slot's new key signs; the old opened key must not block it");
        assert!(verifies(test_keys::RSA_PUBLIC, &blob));
        let asked = host.asked();
        assert_eq!(asked.len(), 2, "the new key asked for its own approval; the old key's remembered approval is not its");
        assert_eq!(asked[1].key_fingerprint, test_keys::RSA_FINGERPRINT);
        assert_eq!(broker.kept().1, 0, "the old key's opened entry is gone");
    }

    #[test]
    fn a_connect_grant_on_a_slot_whose_key_changed_signs_with_the_new_key() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        host.answer(with_passphrase("test-passphrase", false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_some());

        swap_in_the_rsa_key(&mut host);
        let blob = broker
            .sign(&host, &rsa_request(), None, Some(&Grant { slot_id: ENC_ID.into() }))
            .expect("Connect on the slot's new key signs; the old opened key must not block it");
        assert!(verifies(test_keys::RSA_PUBLIC, &blob));
        assert_eq!(host.asked().len(), 1, "a grant asks for nothing (the new key has no passphrase)");
        assert_eq!(broker.kept().1, 0, "the old key's opened entry is gone");
    }

    #[test]
    fn a_stale_opened_key_does_not_hide_the_passphrase_the_slots_new_key_needs() {
        let broker = Broker::default();
        let host = FakeHost::new();
        // 記憶體裡留著的是這個插槽 id 以前的金鑰(沒有 passphrase 的那把 ed25519);插槽現在放的是有 passphrase 的金鑰。
        let old = Arc::new(material::open(&test_keys::plain(), None).unwrap());
        broker.unlocked.lock().unwrap().insert(ENC_ID.to_string(), Unlocked { material: old, expires_ms: u64::MAX });
        host.answer(with_passphrase("test-passphrase", false));
        let blob = broker
            .sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None)
            .expect("the window asks for the passphrase of the key the slot holds now");
        assert!(verifies(test_keys::ENC_PUBLIC, &blob));
        assert!(host.asked()[0].needs_passphrase, "the old opened key is not this key, so the passphrase is asked");
    }

    #[test]
    fn an_opened_key_is_still_reused_while_the_slot_holds_that_key() {
        let broker = Broker::default();
        let host = FakeHost::new();
        host.answer(with_passphrase("test-passphrase", false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("claude")), None).is_some());
        host.answer(allow(false));
        assert!(broker.sign(&host, &request(test_keys::ENC_PUBLIC, Some(host_key())), Some(&program("iterm2")), None).is_some());
        assert!(!host.asked()[1].needs_passphrase, "the same key is still open in memory");
        assert_eq!(broker.kept().1, 1, "and its entry was not dropped");
    }

    #[test]
    fn a_connect_grant_finds_its_key_by_slot_id_when_two_slots_hold_the_same_public_key() {
        let broker = Broker::default();
        let mut host = FakeHost::new();
        let second = "5".repeat(32);
        add_key(&mut host, &second, "id_mac_again", test_keys::PLAIN_PUBLIC, test_keys::PLAIN_FINGERPRINT, test_keys::plain());
        let blob = broker
            .sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), None, Some(&Grant { slot_id: second.clone() }))
            .expect("the grant is for the second slot, which holds the requested key");
        assert!(verifies(test_keys::PLAIN_PUBLIC, &blob));
        assert!(host.asked().is_empty());
        assert!(
            broker.sign(&host, &request(test_keys::PLAIN_PUBLIC, Some(host_key())), None, Some(&Grant { slot_id: "6".repeat(32) })).is_none(),
            "a grant for a slot that holds no vault key signs nothing"
        );
    }
}
