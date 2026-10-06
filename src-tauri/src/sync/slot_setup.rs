//! SP3:還沒設定的金鑰(候選)與建立插槽(spec `docs/superpowers/specs/2026-10-05-sp3-key-slots-design.md` §5、§6.1、
//! §7.1)。主機的改寫只換 `IdentityFile` 那一行的值,經 `persist_file` 寫回(存檔 hook 照一般修改上傳)。之前的帳戶留下的插槽
//! (`KeptSlot`)也是候選,設定時就地放進目前的帳戶(`adopt_slot`)。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::commands::persist_file;
use crate::config::model::{Item, SshConfigDoc};
use crate::error::AppError;
use crate::sync::account::account_ready;
use crate::sync::crypto::ChainKeys;
use crate::sync::env::SyncEnv;
use crate::sync::merge::space_entry;
use crate::sync::migrate::{refuse_while_sync_inactive, selected_space_files};
use crate::sync::runtime::mutate;
use crate::sync::slot_files::{self, LinkKind};
use crate::sync::slot_rules::{
    default_slot_name, inspect_private_key, new_slot_id, resolve_identity_value, slot_file_name, slot_file_of_value, slot_value,
    valid_slot_name, IdentityTarget, KeySlotPayload, SlotMode, SLOT_DIR, SLOT_SCHEMA,
};
use crate::sync::slots::{
    account_still_ready, contested_and_not_held, file_name_in_use, in_the_way_message, land, landable_key, learned_now, live_slots,
    local_key_fingerprint, put_key_secret, put_slot, slot, slot_record_exists, source_gone_message, write_linked_public, CONTESTED_MESSAGE,
};
use crate::sync::state_v2::{LocalSlot, SlotSource, SyncStateV2};

/// 一台用到候選金鑰的主機。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct CandidateHost {
    pub alias: String,
    /// 主機所在 space 的名稱(來自帳戶;UI 以 `revealHidden` 顯示)。
    pub space_name: String,
    /// 那一行 `IdentityFile` 目前的值(會被改寫的就是它)。
    pub value: String,
    /// 不改寫的原因(同名主機有不只一份,spec §5);null = 會改寫。
    pub locked: Option<String>,
}

/// 一把用在同步主機上、還沒有插槽的本機金鑰(或可以直接沿用的插槽)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct KeyCandidate {
    /// 這台電腦上金鑰檔的完整路徑(`IdentityFile` 解析出來的)。之前的帳戶留下的插槽(`kept_slot`)是它的金鑰:連到的金鑰檔,或插槽裡同步來的副本。
    pub path: String,
    /// 預設的插槽名稱:金鑰檔名;之前的帳戶留下的插槽是它自己的名稱(不能改)。
    pub default_name: String,
    pub fingerprint: Option<String>,
    pub has_passphrase: Option<bool>,
    /// 不能同步的原因(只能 Keep on this computer);null = 可以同步。
    pub unsyncable: Option<String>,
    /// 已經有這把金鑰的插槽:這台建立或挑過、連到同一個檔案的,或帳戶裡同指紋的 `synced` 插槽(spec §6.1 第 1 步:直接
    /// 沿用,不再詢問)。和帳戶裡另一個插槽同檔名、這台又沒有握著的插槽在這台不能用,不列在這裡。
    pub existing_slot: Option<String>,
    pub hosts: Vec<CandidateHost>,
    /// 之前的帳戶留下的插槽(spec §7.1):「Sync key」與「Keep on this computer」把它就地放進這個帳戶(`adopt_slot`),不建立新插槽、不改名。
    /// 同一把金鑰有好幾個時,是掃描時先遇到的那一個,用到其他那些的主機改指到它。null = 不是。
    pub kept_slot: Option<KeptSlot>,
}

/// 之前的帳戶留下的插槽(`KeyCandidate.kept_slot`;`kept_lookup`):離開帳戶之後建立或加入了另一個帳戶,`~/.ssh/sshelter-local/` 裡用到它的主機
/// 又被搬進新帳戶的 space。新帳戶裡沒有它(N1:不會自己寫進去),要不要放進去由使用者在這裡決定。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct KeptSlot {
    /// 插槽 id;放進帳戶之後也是它。
    pub id: String,
    /// 插槽檔名(`<name>-<id8>`):用到它的主機照舊指著 `~/.ssh/sshelter/keys/<file_name>`。
    pub file_name: String,
    /// 插槽裡是這台在之前的帳戶裡同步來的副本;否則連到這台的一把金鑰。
    pub synced_copy: bool,
}

/// `IdentityFile` 的值無法自動設定的主機(§5)。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct UnsupportedIdentity {
    pub alias: String,
    pub value: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct KeyCandidates {
    pub keys: Vec<KeyCandidate>,
    pub unsupported: Vec<UnsupportedIdentity>,
}

/// 使用者對一把金鑰的決定。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyDecision {
    /// 「Sync key」:建立 `synced` 插槽並上傳私鑰。
    Sync { name: String },
    /// 「Keep on this computer」:建立 `own` 插槽。
    Keep { name: String },
    /// 沿用既有的插槽(`KeyCandidate.existing_slot`)。
    Reuse { slot_id: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct KeyChoice {
    /// `KeyCandidate.path`。
    pub path: String,
    pub decision: KeyDecision,
}

pub const LOCKED_REASON: &str = "This host has more than one copy; SSHelter changes it once only one copy is left.";

/// 已經有插槽的金鑰收到「Sync key」或「Keep on this computer」(`setup_keys`)。
pub const ALREADY_SET_UP_MESSAGE: &str = "This key already has a key slot, so no second one was made.";

/// 「沿用」指定的插槽不是這把金鑰的(`KeyCandidate.existing_slot`)。
pub const OTHER_SLOT_MESSAGE: &str = "That key slot is for a different key.";

/// 主機指到之前的帳戶留下的插槽,而目前的帳戶裡有別的插槽用了同一個檔名(不分大小寫):分不出主機指的是哪一個,不自動設定(列在
/// 「Can't set up automatically」)。
pub const KEPT_CONTESTED_REASON: &str = "Another key slot in this sync account uses the same file name.";

/// 之前的帳戶留下的插槽在掃描之後變了(`adopt_slot`):什麼都沒寫。
pub const KEPT_CHANGED_MESSAGE: &str = "That key slot changed since the list was read; nothing was set up.";

/// 「Sync key」或「Keep on this computer」的那把金鑰已經不在候選裡(`setup_keys`;期間被設定好了,或主機變了):什麼都沒做。
pub const SET_UP_MEANWHILE_MESSAGE: &str = "This key was set up in the meantime; nothing changed.";

fn home_of(env: &SyncEnv) -> Result<PathBuf, AppError> {
    env.ssh_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| AppError::Other("cannot determine the home directory".to_string()))
}

/// 兩個路徑是不是同一個檔案(都要存在)。
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// 金鑰檔在插槽目錄(`keys_dir`)裡:同步來的副本、插槽的連結本身之類 —— 之後可能被刪掉(「Delete copy」)或換掉。路徑本身在目錄裡,或解析 symlink
/// 之後在目錄裡,都算。沿用插槽時不連到這樣的檔案,改成落地帳戶裡的金鑰(`reuse_slot`),所以也只建議沿用落地得了的插槽(`existing_slot_for`)。
fn in_keys_dir(path: &Path, keys_dir: &Path) -> bool {
    path.starts_with(keys_dir)
        || matches!((std::fs::canonicalize(path), std::fs::canonicalize(keys_dir)), (Ok(path), Ok(dir)) if path.starts_with(&dir))
}

/// 存在的私鑰檔(第一行是 `-----BEGIN … PRIVATE KEY-----`;大於 64 KiB 的不讀)。
pub(crate) fn is_private_key_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if !meta.is_file() || meta.len() > 64 * 1024 {
        return false;
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.lines().next().map(|l| l.trim().starts_with("-----BEGIN ") && l.contains("PRIVATE KEY")))
        .unwrap_or(false)
}

/// 每個 pattern 在整份 config(所有檔案)出現在幾個 Host 區塊;超過一個的主機不改寫(SP1 FA3)。
fn alias_counts(doc: &SshConfigDoc) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for file in &doc.files {
        for item in &file.items {
            if let Item::Host(host) = item {
                for pattern in &host.patterns {
                    *counts.entry(pattern.clone()).or_insert(0) += 1;
                }
            }
        }
    }
    counts
}

fn locked(patterns: &[String], counts: &BTreeMap<String, usize>) -> bool {
    patterns.iter().any(|p| counts.get(p).copied().unwrap_or(0) > 1)
}

/// 已經有這把金鑰的插槽:這台建立或挑過、連到同一個檔案的(帳戶裡仍在);或帳戶裡同指紋的 `synced` 插槽。和帳戶裡另一個插槽
/// 同檔名、這台又沒有握著的插槽(`contested_and_not_held`)在這台不能用,不建議沿用。金鑰檔在插槽目錄裡的(`in_slot_dir`,例如之前的帳戶留下的
/// 同步副本)沿用時要落地帳戶裡的金鑰(`reuse_slot`):同指紋的 `synced` 插槽,帳戶裡它的 `key` 要解得開、通過落地前的檢查才算(`account_keys` 是
/// None 時解不開,不算)—— 不然沿用只會讓能連線的主機改指到沒有金鑰的插槽。
fn existing_slot_for(
    state: &SyncStateV2,
    key: &Path,
    fingerprint: Option<&str>,
    in_slot_dir: bool,
    account_keys: Option<&ChainKeys>,
) -> Option<String> {
    let account = state.account.as_ref()?;
    let live = live_slots(account);
    let usable = |id: &str| !contested_and_not_held(state, id);
    let linked = state.key_slots.iter().find(|(id, local)| {
        live.iter().any(|(l, _)| l == *id)
            && usable(id)
            && matches!(&local.source, Some(SlotSource::Linked { path, .. }) if same_file(Path::new(path), key))
    });
    if let Some((id, _)) = linked {
        return Some(id.clone());
    }
    let fingerprint = fingerprint?;
    let landable = |id: &str, payload: &KeySlotPayload| account_keys.is_some_and(|keys| landable_key(account, keys, id, payload).is_ok());
    live.into_iter()
        .find(|(id, p)| {
            p.mode == SlotMode::Synced
                && p.fingerprint.as_deref() == Some(fingerprint)
                && usable(id)
                && (!in_slot_dir || landable(id, p))
        })
        .map(|(id, _)| id)
}

fn candidate_for(key: &Path, state: &SyncStateV2, account_keys: Option<&ChainKeys>, keys_dir: &Path) -> KeyCandidate {
    let text = std::fs::read_to_string(key).unwrap_or_default();
    let inspected = inspect_private_key(&text);
    let fingerprint = inspected.as_ref().ok().map(|f| f.fingerprint.clone()).or_else(|| local_key_fingerprint(key));
    KeyCandidate {
        path: key.display().to_string(),
        default_name: default_slot_name(key.file_name().and_then(|n| n.to_str()).unwrap_or("key")),
        existing_slot: existing_slot_for(state, key, fingerprint.as_deref(), in_keys_dir(key, keys_dir), account_keys),
        fingerprint,
        has_passphrase: inspected.as_ref().ok().map(|f| f.has_passphrase),
        unsyncable: inspected.err().map(|e| e.message().to_string()),
        hosts: Vec::new(),
        kept_slot: None,
    }
}

/// `keys` 裡金鑰檔是 `key` 的候選(同一個檔案,`same_file`);沒有就新增一個。回傳它的位置。
fn candidate_index(
    keys: &mut Vec<KeyCandidate>,
    key: &Path,
    state: &SyncStateV2,
    account_keys: Option<&ChainKeys>,
    keys_dir: &Path,
) -> usize {
    match keys.iter().position(|c| same_file(Path::new(&c.path), key)) {
        Some(i) => i,
        None => {
            keys.push(candidate_for(key, state, account_keys, keys_dir));
            keys.len() - 1
        }
    }
}

/// 主機的 `IdentityFile` 指到插槽檔時,那是不是之前的帳戶留下的插槽(`kept_lookup`)。
enum KeptLookup {
    /// 不是:帳戶裡的插槽(每一輪照常維護),或這台設定不了的(讀不到私鑰……,交給 lint)。
    No,
    /// 是,但目前的帳戶裡有別的插槽用了同一個檔名(不分大小寫):分不出主機指的是哪一個。
    Contested,
    /// 是:插槽、這台讀得到的私鑰檔(候選的金鑰)、插槽的名稱。
    Kept { slot: KeptSlot, key: PathBuf, name: String },
}

/// 之前的帳戶留下的插槽(spec §7.1):這台檔名是 `file` 的插槽記錄,目前的帳戶裡沒有它的任何記錄(還在的或 tombstone),它不是在目前的帳戶學到的
/// (不知道的也算不是,`LocalSlot::learned_in`),連結沒有收起來(`parked`:插槽路徑上可能是使用者的檔案,直接指到金鑰檔的主機不能改指到那裡),
/// 而且這台讀得到它的私鑰(`kept_key`)。名稱組不回同一個檔名的記錄不算(`kept_name`)。帳戶裡另一個還在的插槽用了同一個檔名(不分大小寫)→
/// `Contested`。只讀狀態與金鑰檔。
fn kept_lookup(state: &SyncStateV2, file: &str, keys_dir: &Path) -> KeptLookup {
    let Some(account) = state.account.as_ref() else { return KeptLookup::No };
    let found = state.key_slots.iter().find_map(|(id, local)| {
        if local.file_name != file
            || local.parked
            || slot_record_exists(account, id)
            || local.learned_in.as_deref() == Some(account.chain_id.as_str())
        {
            return None;
        }
        let name = kept_name(id, local)?;
        let key = kept_key(local, keys_dir)?;
        let synced_copy = matches!(local.source, Some(SlotSource::SyncedCopy { .. }));
        Some(KeptLookup::Kept { slot: KeptSlot { id: id.clone(), file_name: local.file_name.clone(), synced_copy }, key, name })
    });
    match found {
        Some(_) if file_name_in_use(account, file) => KeptLookup::Contested,
        Some(kept) => kept,
        None => KeptLookup::No,
    }
}

/// 之前的帳戶留下的插槽的名稱(放進帳戶時沿用,不改名):最後看到的 `keyslot` 的名稱,沒有的話是檔名去掉結尾的 `-<id8>`。不合規、或組不回記錄的
/// 檔名 → None。
fn kept_name(id: &str, local: &LocalSlot) -> Option<String> {
    let name = match &local.payload {
        Some(payload) => payload.name.clone(),
        None => local.file_name.strip_suffix(&format!("-{}", id.get(..8)?))?.to_string(),
    };
    (valid_slot_name(&name) && slot_file_name(&name, id) == local.file_name).then_some(name)
}

/// 這台讀得到的、之前的帳戶留下的插槽的私鑰檔:連到的金鑰檔(`Linked`,要是私鑰檔),或插槽裡同步來的副本(`SyncedCopy`,要仍是記錄裡那個指紋的
/// 私鑰)。其他(沒有來源、檔案不見或換了)→ None。
fn kept_key(local: &LocalSlot, keys_dir: &Path) -> Option<PathBuf> {
    match local.source.as_ref()? {
        SlotSource::Linked { path, .. } => Some(PathBuf::from(path)).filter(|key| is_private_key_file(key)),
        SlotSource::SyncedCopy { fingerprint } => {
            let copy = keys_dir.join(&local.file_name);
            let recorded = is_private_key_file(&copy)
                && std::fs::read_to_string(&copy).is_ok_and(|text| inspect_private_key(&text).is_ok_and(|f| f.fingerprint == *fingerprint));
            recorded.then_some(copy)
        }
    }
}

/// 候選裡之前的帳戶留下的插槽的檔名:指到插槽路徑的主機(`scan` 只會把之前的帳戶留下的插槽的主機收進候選)。
fn kept_files(candidate: &KeyCandidate) -> Vec<String> {
    candidate.hosts.iter().filter_map(|h| slot_file_of_value(&h.value)).collect()
}

/// 掃描 doc 裡這台勾選的 space 檔(只讀:不改 doc 與狀態,但會讀金鑰檔;呼叫端持有 doc 鎖)。指到本機私鑰檔的主機依金鑰檔分組;指到之前的帳戶留下的
/// 插槽的主機(`kept_lookup`)依那個插槽的私鑰檔分組,和直接指到同一個檔案的主機是同一個候選。候選的名稱是之前的帳戶留下的插槽的名稱(先遇到的那一個,
/// `kept_slot`)。
fn scan(
    doc: &SshConfigDoc,
    space_files: &[(String, PathBuf)],
    state: &SyncStateV2,
    account_keys: Option<&ChainKeys>,
    home: &Path,
) -> KeyCandidates {
    let counts = alias_counts(doc);
    let keys_dir = home.join(SLOT_DIR);
    let mut keys: Vec<KeyCandidate> = Vec::new();
    let mut unsupported = Vec::new();
    for (space_id, path) in space_files {
        let Some(file) = doc.files.iter().find(|f| &f.path == path) else { continue };
        let space_name = state
            .account
            .as_ref()
            .and_then(|a| space_entry(a, space_id))
            .map(|e| e.name)
            .unwrap_or_else(|| space_id.clone());
        for item in &file.items {
            let Item::Host(host) = item else { continue };
            let Some(alias) = host.patterns.first().cloned() else { continue };
            let lock = locked(&host.patterns, &counts).then(|| LOCKED_REASON.to_string());
            for line in &host.body {
                let Item::Directive(d) = line else { continue };
                if d.key != "identityfile" || d.serializes_as_comment() {
                    continue;
                }
                let host = || CandidateHost { alias: alias.clone(), space_name: space_name.clone(), value: d.value.clone(), locked: lock.clone() };
                match resolve_identity_value(&d.value, home) {
                    IdentityTarget::Slot(file) => match kept_lookup(state, &file, &keys_dir) {
                        KeptLookup::No => {}
                        KeptLookup::Contested => unsupported.push(UnsupportedIdentity {
                            alias: alias.clone(),
                            value: d.value.clone(),
                            reason: KEPT_CONTESTED_REASON.to_string(),
                        }),
                        KeptLookup::Kept { slot, key, name } => {
                            let candidate = {
                                let index = candidate_index(&mut keys, &key, state, account_keys, &keys_dir);
                                &mut keys[index]
                            };
                            if candidate.kept_slot.is_none() {
                                candidate.kept_slot = Some(slot);
                                candidate.default_name = name;
                            }
                            candidate.hosts.push(host());
                        }
                    },
                    IdentityTarget::Unsupported(reason) => unsupported.push(UnsupportedIdentity {
                        alias: alias.clone(),
                        value: d.value.clone(),
                        reason: reason.to_string(),
                    }),
                    IdentityTarget::File(key) => {
                        if !is_private_key_file(&key) {
                            continue; // 不存在或不是私鑰:交給 lint
                        }
                        let index = candidate_index(&mut keys, &key, state, account_keys, &keys_dir);
                        keys[index].hosts.push(host());
                    }
                }
            }
        }
    }
    KeyCandidates { keys, unsupported }
}

/// 這台勾選、而且第一輪同步已經跑完(`SpaceState::baseline_established`)的 space 檔(space id, 路徑;順序同 `selected_space_files`)。只有它們參與
/// 設定(候選的掃描與主機的改寫都只看它們):第一輪還沒跑完的 space,存檔 hook 不為它規劃任何記錄(`files::note_written`),而第一輪以 chain
/// 為準 —— 在這之前改寫的主機會被寫回 chain 的版本,改寫就白費了(插槽還在,主機卻悄悄變回原樣)。搬移精靈與側邊欄搬移對這種 space 也是拒絕
/// (`migrate::refuse_before_first_sync`)。它們的主機在那個 space 的第一輪之後的下一次掃描才會出現。旗標在取得勾選清單之後才讀(最新的值)。
fn ready_space_files(env: &SyncEnv) -> Vec<(String, PathBuf)> {
    let selected = selected_space_files(env.runtime, &env.ssh_dir);
    let core = env.runtime.core.lock().unwrap();
    let Some(state) = core.state.as_ref() else { return Vec::new() };
    selected.into_iter().filter(|(id, _)| state.spaces.get(id).is_some_and(|sp| sp.baseline_established)).collect()
}

/// 這台勾選、第一輪同步已經跑完(`ready_space_files`)的 space 檔裡,指到本機私鑰、還沒有插槽的 `IdentityFile`(依金鑰檔分組;之前的帳戶留下的插槽也是,
/// `scan`),以及無法自動設定的值。第一輪還沒跑完的 space 的主機既不是候選、也不列在無法自動設定的清單裡。鎖:先短暫拿 core 取快照,再拿 doc。
pub fn key_candidates(env: &SyncEnv) -> Result<KeyCandidates, AppError> {
    Ok(scan_now(env)?.0)
}

/// `key_candidates`,連同掃描用的狀態快照(`setup_keys` 要知道掃描時之前的帳戶留下的插槽記錄是什麼樣子)。沒有候選可掃(不在帳戶裡、config 還沒載入)時
/// 快照是 None。
fn scan_now(env: &SyncEnv) -> Result<(KeyCandidates, Option<SyncStateV2>), AppError> {
    let home = home_of(env)?;
    let (state, account_keys) = {
        let core = env.runtime.core.lock().unwrap();
        (core.state.clone(), core.account_keys.clone())
    };
    let Some(state) = state else { return Ok((KeyCandidates::default(), None)) };
    if state.account.is_none() {
        return Ok((KeyCandidates::default(), None));
    }
    let space_files = ready_space_files(env);
    let doc_lock = env.doc.lock().unwrap();
    let Some(doc) = doc_lock.as_ref() else { return Ok((KeyCandidates::default(), None)) };
    let found = scan(doc, &space_files, &state, account_keys.as_ref(), &home);
    Ok((found, Some(state)))
}

/// 設定好的一把金鑰(`rewrite_in`):金鑰檔(`KeyCandidate.path`)、主機要改指到的插槽檔名,以及同一個候選裡之前的帳戶留下的插槽的檔名(`kept_files`)。
struct Planned {
    key: PathBuf,
    file: String,
    kept_files: Vec<String>,
}

/// 把 `planned` 的主機改寫成指到它的插槽(`Planned::file`):指到金鑰檔的,以及指到同一個候選裡之前的帳戶留下的另一個插槽的(已經指到 `file` 的不動)。
/// 只換那一行的值,被 FA3 鎖住的主機不動;改了的檔案逐一經 `persist`。回傳改寫了的 alias(依出現順序)。
fn rewrite_in(
    doc: &mut SshConfigDoc,
    space_files: &[PathBuf],
    home: &Path,
    planned: &[Planned],
    mut persist: impl FnMut(&mut SshConfigDoc, usize) -> Result<(), AppError>,
) -> Result<Vec<String>, AppError> {
    let counts = alias_counts(doc);
    let mut rewritten: Vec<String> = Vec::new();
    for idx in 0..doc.files.len() {
        if !space_files.contains(&doc.files[idx].path) {
            continue;
        }
        let mut changed = false;
        for item in doc.files[idx].items.iter_mut() {
            let Item::Host(host) = item else { continue };
            if locked(&host.patterns, &counts) {
                continue;
            }
            let alias = host.patterns.first().cloned().unwrap_or_default();
            for line in host.body.iter_mut() {
                let Item::Directive(d) = line else { continue };
                if d.key != "identityfile" || d.serializes_as_comment() {
                    continue;
                }
                let to = match resolve_identity_value(&d.value, home) {
                    IdentityTarget::File(target) => planned.iter().find(|p| same_file(&p.key, &target)),
                    IdentityTarget::Slot(file) => planned.iter().find(|p| p.kept_files.contains(&file)).filter(|p| p.file != file),
                    IdentityTarget::Unsupported(_) => None,
                };
                let Some(to) = to else { continue };
                d.value = slot_value(&to.file);
                d.dirty = true;
                changed = true;
                if !rewritten.contains(&alias) {
                    rewritten.push(alias.clone());
                }
            }
        }
        if changed {
            persist(doc, idx)?;
        }
    }
    Ok(rewritten)
}

/// 依使用者的決定建立或沿用插槽,再改寫用到那些金鑰的主機(SP3 spec §6.1;插槽一定先就位,主機才改寫)。`active` = 這個
/// 行程跑著同步引擎(`engine::engine_active`;改寫的主機要靠它上傳)。回傳改寫了的 alias。決定裡的路徑不在目前的候選裡時:沿用(對話框自己送的、
/// 畫面上的舊資料)略過;「Sync key」與「Keep on this computer」(使用者按的)整個拒絕(`SET_UP_MEANWHILE_MESSAGE`)—— 在做任何一個決定之前就檢查,
/// 一起送來的決定一個都不做,對話框也不會顯示成功。
///
/// 只有第一輪同步已經跑完的 space 參與(`ready_space_files`):候選只來自它們的主機,改寫也只動它們的檔案 —— 其他 space 的主機照舊指到金鑰檔,
/// 等那個 space 的第一輪之後,下一次掃描會列出它們、直接沿用已建好的插槽。
///
/// 任何一個決定做不成(名字不合規、金鑰不能同步、插槽路徑上有別人的東西……)就在那裡回錯誤:那個決定什麼都沒留下,後面的決定
/// 與所有主機的改寫都不做;前面的決定已經建好的插槽留著,下一次掃描會建議沿用(和改寫撞到 `Conflict` 時一樣)。
///
/// 更換同步碼進行中(第 2 步起)、或這台已被別台擋下時整個拒絕(`account_ready`,說明同 space 的操作):建立插槽要寫 `keyslot`/`key`,那些記錄之後
/// 會隨舊帳戶區段一起被換掉(原因見 `slots::account_still_ready`)。一開始就檢查 —— 讀任何檔案、連結、改寫主機之前;`create_slot` 提交的 core 臨界區裡再檢查一次。
///
/// 之前的帳戶留下的插槽(`KeyCandidate.kept_slot`)收到「Sync key」或「Keep on this computer」:不建立新插槽,就地放進這個帳戶(`adopt_slot`;決定裡的
/// 名稱不用,對話框也不讓改)。指到同一個候選裡之前的帳戶留下的其他插槽的主機,一樣改指到設定好的插槽(`rewrite_in`)。
pub fn setup_keys(env: &SyncEnv, active: bool, choices: Vec<KeyChoice>) -> Result<Vec<String>, AppError> {
    refuse_while_sync_inactive(active, env.runtime)?;
    let account_keys = {
        let core = env.runtime.core.lock().unwrap();
        let s = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        account_ready(s, core.account_keys.as_ref())?;
        core.account_keys.clone().expect("checked by account_ready")
    };
    let home = home_of(env)?;
    let keys_dir = home.join(SLOT_DIR);
    let (current, scanned) = scan_now(env)?;
    let listed = |path: &str| current.keys.iter().find(|c| same_file(Path::new(&c.path), Path::new(path)));
    if choices.iter().any(|c| !matches!(c.decision, KeyDecision::Reuse { .. }) && listed(&c.path).is_none()) {
        return Err(AppError::Other(SET_UP_MEANWHILE_MESSAGE.to_string()));
    }
    let mut planned: Vec<Planned> = Vec::new();
    for choice in choices {
        let Some(candidate) = listed(&choice.path) else { continue };
        let file = match (choice.decision, &candidate.kept_slot) {
            (KeyDecision::Reuse { slot_id }, _) => reuse_slot(env, &account_keys, &keys_dir, candidate, &slot_id)?,
            // 已經有插槽的金鑰不建立第二個(spec §6.1 第 1 步:這把金鑰已經決定過了,前端對它送的是 Reuse)。畫面上的舊資料才會走到這裡(例如重新
            // 讀取失敗之後又按了一次):拒絕、什麼都不動。不靜靜地改成沿用 —— 那個插槽是同步還是留在這台,不一定是使用者這次選的,成功的 toast 會說錯。
            (KeyDecision::Sync { .. } | KeyDecision::Keep { .. }, _) if candidate.existing_slot.is_some() => {
                return Err(AppError::Other(ALREADY_SET_UP_MESSAGE.to_string()));
            }
            (decision, Some(kept)) => {
                let local = scanned
                    .as_ref()
                    .and_then(|s| s.key_slots.get(&kept.id))
                    .ok_or_else(|| AppError::Other(KEPT_CHANGED_MESSAGE.to_string()))?;
                adopt_slot(env, &account_keys, candidate, kept, local, matches!(decision, KeyDecision::Sync { .. }))?
            }
            (KeyDecision::Sync { name }, None) => create_slot(env, &account_keys, &keys_dir, candidate, name, true)?,
            (KeyDecision::Keep { name }, None) => create_slot(env, &account_keys, &keys_dir, candidate, name, false)?,
        };
        planned.push(Planned { key: PathBuf::from(&candidate.path), file, kept_files: kept_files(candidate) });
    }
    if planned.is_empty() {
        return Ok(Vec::new());
    }
    rewrite_hosts(env, &home, &planned)
}

/// 改寫用到 `planned` 裡那些金鑰的主機,經 `persist_file` 寫回。鎖(doc、backed_up)只在內層區塊裡持有:通知(`applied` 會重建 tray、
/// 同步等待主執行緒)要在全部放掉之後才發,同搬移精靈(`migrate::move_hosts_into_space`)。
fn rewrite_hosts(env: &SyncEnv, home: &Path, planned: &[Planned]) -> Result<Vec<String>, AppError> {
    let result = {
        let mut doc_lock = env.doc.lock().unwrap();
        let mut backed_up = env.backed_up.lock().unwrap();
        let retention = env.retention();
        // 只改寫第一輪同步已經跑完的 space 的主機(`ready_space_files`)。清單在持有 doc 鎖時才取、不沿用掃描時的結果:掃描之後 space 可能又退回了基線輪
        // (`prepare_files` 在 doc 鎖裡做這件事,持有 doc 鎖時它不會發生)。
        let space_files: Vec<PathBuf> = ready_space_files(env).into_iter().map(|(_, path)| path).collect();
        let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        let main_path = doc.files[0].path.clone();
        let result = rewrite_in(doc, &space_files, home, planned, |doc, idx| persist_file(doc, idx, &mut backed_up, retention));
        if result.is_err() {
            // 記憶體裡的 doc 已改、磁碟沒寫成:重載讓兩邊一致(同搬移精靈);插槽留著,下一次掃描會建議沿用。
            drop(backed_up);
            *doc_lock = env.load_doc(&main_path).ok();
        }
        result
    };
    env.events.applied(0);
    env.events.wake();
    result
}

/// 把一個空著的插槽路徑連到 `source`,再從那把金鑰自己寫 `<slot>.pub`(`slots::write_linked_public`)。插槽路徑上已經有東西 —— 沒有任何
/// 記錄說它是 SSHelter 放的(spec §4.2:只有本機狀態記錄是 SSHelter 放的東西才可以被取代;`slot_files::link` 會原子地取代路徑上
/// 原本的任何東西)—— 就不連結,回 `in_the_way_message`。`.pub` 寫不進去就把剛放的連結收回。回傳連結的種類。
fn link_free_slot(keys_dir: &Path, slot_path: &Path, source: &Path) -> Result<LinkKind, AppError> {
    if slot_files::occupied(slot_path) {
        return Err(AppError::Other(in_the_way_message(slot_path)));
    }
    slot_files::ensure_keys_dir(keys_dir)?;
    let link = slot_files::link(source, slot_path)?;
    if let Err(e) = write_linked_public(slot_path, source) {
        let _ = slot_files::remove_slot(slot_path);
        return Err(e);
    }
    Ok(link)
}

/// 沿用既有的插槽(`KeyDecision::Reuse`)。主機改寫之前,這台的插槽檔就要在位(spec §6.1 第 4 步)。回傳插槽檔名。
/// - 和帳戶裡另一個插槽同檔名、這台又沒有握著的(`contested_and_not_held`):拒絕,什麼都不動。
/// - 不是候選帶著的那個插槽(`KeyCandidate.existing_slot`;畫面上的舊資料,或另一把金鑰的插槽):拒絕,什麼都不動 —— 不然這把金鑰的主機會改指到
///   另一把金鑰的插槽,或另一個插槽在這台連到這把金鑰。
/// - 這台已經握著它(有來源、連結沒收起來):它放的金鑰還在插槽路徑上(`held_in_place`)就照舊,什麼都不動,之後每一輪維護它;不在就拒絕、主機不改寫。
/// - 這台還沒有它的金鑰,或連結收起來了(`LocalSlot::parked`):現在就連到使用者選的這把金鑰、寫 `.pub`、記下來(清掉 `parked`)。插槽路徑上
///   已經有東西(收起來的連結不擁有路徑上的任何東西)就不連結,回 `in_the_way_message`,主機也不改寫。
/// - 例外:候選的金鑰檔在插槽目錄裡(`in_keys_dir`,例如之前的帳戶同步來、留在這台的副本),沿用的又是 `synced` 插槽 —— 不連到那個檔案:它之後可能被
///   刪掉(舊的記錄沒有主機用了,「Delete copy」)或換掉,這個插槽就斷了。改成先把帳戶裡的金鑰落地到這個插槽(同每一輪的 `land_into`:私鑰要通過指紋
///   檢查,路徑上有別的東西就擋路,`.pub` 一起寫;私鑰還要就是候選的那一把),記成同步來的副本,主機才改寫。任何一步做不成就拒絕,主機不改寫。
fn reuse_slot(env: &SyncEnv, account_keys: &ChainKeys, keys_dir: &Path, candidate: &KeyCandidate, slot_id: &str) -> Result<String, AppError> {
    let state = env
        .runtime
        .core
        .lock()
        .unwrap()
        .state
        .clone()
        .ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    let payload = state
        .account
        .as_ref()
        .and_then(|a| slot(a, slot_id))
        .ok_or_else(|| AppError::Other("that key slot no longer exists".to_string()))?;
    if contested_and_not_held(&state, slot_id) {
        return Err(AppError::Other(CONTESTED_MESSAGE.to_string()));
    }
    if candidate.existing_slot.as_deref() != Some(slot_id) {
        return Err(AppError::Other(OTHER_SLOT_MESSAGE.to_string()));
    }
    let file = slot_file_name(&payload.name, slot_id);
    if let Some(held) = state.key_slots.get(slot_id).filter(|l| l.source.is_some() && !l.parked) {
        held_in_place(held, &file, keys_dir)?;
        return Ok(file);
    }
    let chain = state.account.as_ref().map(|a| a.chain_id.clone()).unwrap_or_default();
    if in_keys_dir(Path::new(&candidate.path), keys_dir) && payload.mode == SlotMode::Synced {
        return land_reused_slot(env, account_keys, &state, keys_dir, candidate, slot_id, &payload, &file, &chain);
    }
    let slot_path = keys_dir.join(&file);
    // 連結用的路徑與記進 `Linked` 的路徑出自同一個字串(`candidate.path`):`slots::maintain` 每一輪(Unix)確認 symlink 正好指到記錄的路徑。
    let link = link_free_slot(keys_dir, &slot_path, Path::new(&candidate.path))?;
    let result = mutate(env, |s| {
        // 這台第一次有這個插槽的記錄:是在快照裡插槽所在的帳戶學到的(提交時帳戶換了就不記)。已經有的記錄(收起來的)照舊。
        let learned_here = learned_now(s, &chain);
        let local = s.key_slots.entry(slot_id.to_string()).or_insert_with(|| LocalSlot {
            file_name: file.clone(),
            source: None,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: learned_here,
            copy_from_another_account: false,
        });
        // 收起來的記錄原本就是這台建立的(`origin`)就還是;其他電腦連到自己挑的金鑰,不是。
        let origin = matches!(&local.source, Some(SlotSource::Linked { origin: true, .. }));
        local.file_name = file.clone();
        local.source = Some(SlotSource::Linked { path: candidate.path.clone(), link, fingerprint: candidate.fingerprint.clone(), origin });
        local.last_error = None;
        local.payload = Some(payload.clone());
        local.parked = false;
        Ok(())
    });
    if let Err(e) = result {
        let _ = slot_files::remove_slot(&slot_path);
        return Err(e);
    }
    Ok(file)
}

/// `reuse_slot` 的例外(候選的金鑰檔在插槽目錄裡):把帳戶裡的金鑰落地到要沿用的插槽 `<keys_dir>/<file>`,記下來,回傳插槽檔名;主機之後才改寫。私鑰在帳戶裡
/// 沒有、通不過指紋檢查(`landable_key`),或不是候選的那一把(主機會換成另一把金鑰)→ 拒絕;插槽路徑上有別的東西 → 擋路(`land`,同每一輪)。記錄寫不進去
/// 就把剛落地的檔案收回。記錄是快照裡插槽所在的帳戶的(`learned_now`;提交時帳戶換了就不改記),副本是那個帳戶的(`copy_from_another_account`)。
#[allow(clippy::too_many_arguments)]
fn land_reused_slot(
    env: &SyncEnv,
    account_keys: &ChainKeys,
    state: &SyncStateV2,
    keys_dir: &Path,
    candidate: &KeyCandidate,
    slot_id: &str,
    payload: &KeySlotPayload,
    file: &str,
    chain: &str,
) -> Result<String, AppError> {
    let account = state.account.as_ref().ok_or_else(|| AppError::Other("that key slot no longer exists".to_string()))?;
    let (secret, facts) = landable_key(account, account_keys, slot_id, payload)
        .map_err(|e| AppError::Other(e.unwrap_or_else(|| "this key isn't synced".to_string())))?;
    if candidate.fingerprint.as_deref() != Some(facts.fingerprint.as_str()) {
        return Err(AppError::Other(OTHER_SLOT_MESSAGE.to_string()));
    }
    let slot_path = keys_dir.join(file);
    let was_free = !slot_files::occupied(&slot_path);
    let fingerprint = land(&secret, payload, keys_dir, &slot_path).map_err(AppError::Other)?;
    let result = mutate(env, |s| {
        let learned_here = learned_now(s, chain);
        let local = s.key_slots.entry(slot_id.to_string()).or_insert_with(|| LocalSlot {
            file_name: file.to_string(),
            source: None,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: learned_here.clone(),
            copy_from_another_account: false,
        });
        local.file_name = file.to_string();
        local.source = Some(SlotSource::SyncedCopy { fingerprint: fingerprint.clone() });
        local.payload = Some(payload.clone());
        local.last_error = None;
        local.parked = false;
        if learned_here.is_some() {
            local.learned_in = learned_here;
        }
        local.copy_from_another_account = local.learned_in.as_deref() != Some(chain);
        Ok(())
    });
    if let Err(e) = result {
        if was_free {
            let _ = slot_files::remove_slot(&slot_path);
        }
        return Err(e);
    }
    Ok(file.to_string())
}

/// 這台握著的插槽(`reuse_slot` 的捷徑:什麼都不動、直接改寫主機)放的金鑰,現在是不是真的在插槽路徑 `<keys_dir>/<file>` 上:記錄的檔名就是 `file`
/// (帳戶裡改了名的話,這筆記錄說的是舊路徑,下一輪才從頭來過),連到的原檔還在(`Linked`),同步來的副本還在(`SyncedCopy`)。不是的話回
/// `source_gone_message`(沒有金鑰的那個路徑):改寫主機只會讓一台能連線的主機改指到沒有金鑰的插槽。
fn held_in_place(held: &LocalSlot, file: &str, keys_dir: &Path) -> Result<(), AppError> {
    let slot_path = keys_dir.join(file);
    let gone = |path: &Path| Err(AppError::Other(source_gone_message(&path.display().to_string())));
    if held.file_name != file {
        return gone(&slot_path);
    }
    match &held.source {
        Some(SlotSource::Linked { path, .. }) if !Path::new(path).is_file() => gone(Path::new(path)),
        Some(SlotSource::SyncedCopy { .. }) if !slot_path.is_file() => gone(&slot_path),
        _ => Ok(()),
    }
}

/// 之前的帳戶留下的插槽(`KeyCandidate.kept_slot`)就地放進這個帳戶(spec §7.1):同一個 id、同一個名稱與檔名,不建立新插槽、不改名,用到它的主機
/// 不改寫。`scanned` = 掃描時的那筆記錄。「Sync key」上傳的是現在檔案裡的這把(同 `create_slot`:先讀、先檢查;同步來的副本還要仍是記錄裡的那一把,
/// 否則同下回 `KEPT_CHANGED_MESSAGE`);「Keep on this computer」不讀私鑰。
///
/// 提交的 core 臨界區裡先確認帳戶(`account_still_ready`),再確認掃描之後那筆記錄沒變:還在、檔名與來源相同、連結沒有收起來、仍不是在這個帳戶學到的、
/// 帳戶裡仍沒有這個 id 的記錄(還在的或 tombstone)、檔名仍沒有別的插槽在用(不分大小寫)—— 任何一項變了就什麼都不寫,回 `KEPT_CHANGED_MESSAGE`。
/// 帳戶記錄先寫 `key`(會失敗的先做),再寫 `keyslot`(來源裝置是這台、時間是現在)。本機記錄換上新的 payload、記成在這個帳戶學到的,同意上傳的是
/// 剛上傳的那把(Keep 沒有);同步來的副本標成之前的帳戶的(`copy_from_another_account`:它的位元組不是從這個帳戶收到的)。來源、插槽檔與連結都不動。
/// 回傳插槽檔名。
fn adopt_slot(
    env: &SyncEnv,
    account_keys: &ChainKeys,
    candidate: &KeyCandidate,
    kept: &KeptSlot,
    scanned: &LocalSlot,
    sync: bool,
) -> Result<String, AppError> {
    let changed = || AppError::Other(KEPT_CHANGED_MESSAGE.to_string());
    let name = kept_name(&kept.id, scanned).ok_or_else(changed)?;
    let now = env.now();
    let uploaded = if sync {
        let text = std::fs::read_to_string(&candidate.path)?;
        let facts = inspect_private_key(&text).map_err(|e| AppError::Other(e.message().to_string()))?;
        if matches!(&scanned.source, Some(SlotSource::SyncedCopy { fingerprint }) if *fingerprint != facts.fingerprint) {
            return Err(changed());
        }
        Some((text, facts))
    } else {
        None
    };
    mutate(env, |s| {
        // 在任何修改之前(`mutate` 的閉包回 Err 時,已經做的修改不會復原)。
        account_still_ready(s, account_keys)?;
        let account = s.account.as_ref().ok_or_else(changed)?;
        let unchanged = s.key_slots.get(&kept.id).is_some_and(|local| {
            local.file_name == scanned.file_name
                && local.source == scanned.source
                && !local.parked
                && local.learned_in.as_deref() != Some(account.chain_id.as_str())
        }) && !slot_record_exists(account, &kept.id)
            && !file_name_in_use(account, &scanned.file_name);
        if !unchanged {
            return Err(changed());
        }
        let device_id = s.device_id.clone();
        let (Some(account), Some(local)) = (s.account.as_mut(), s.key_slots.get_mut(&kept.id)) else { return Err(changed()) };
        // 會失敗的先做:`mutate` 的閉包回 Err 時,已經做的修改不會復原。
        if let Some((text, _)) = &uploaded {
            put_key_secret(account, account_keys, &kept.id, Some(text), &device_id, now)?;
        }
        let facts = uploaded.as_ref().map(|(_, facts)| facts);
        let payload = KeySlotPayload {
            schema: SLOT_SCHEMA,
            name: name.clone(),
            mode: if sync { SlotMode::Synced } else { SlotMode::Own },
            origin_device_id: device_id.clone(),
            created_at_ms: now,
            public_key: facts.map(|f| f.public_key.clone()),
            fingerprint: facts.map(|f| f.fingerprint.clone()),
            key_type: facts.map(|f| f.key_type.clone()),
            has_passphrase: facts.map(|f| f.has_passphrase),
        };
        put_slot(account, &kept.id, Some(&payload), &device_id, now);
        local.payload = Some(payload);
        // `account_still_ready` 確認過:這就是 `account_keys` 的帳戶。
        local.learned_in = Some(account_keys.chain_id.clone());
        // 只有選了「Sync key」,上傳的這把才算這台同意上傳的(補寫 `key` 時只認它,見 `LocalSlot::uploaded_fingerprint`)。
        local.uploaded_fingerprint = facts.map(|f| f.fingerprint.clone());
        // 同步來的副本的位元組是在之前的帳戶收到的,不是這個帳戶(補寫 `key` 時只有上面那個同意算數,見 `slots::republish`)。
        local.copy_from_another_account = matches!(local.source, Some(SlotSource::SyncedCopy { .. }));
        local.last_error = None;
        local.asked = false;
        Ok(())
    })?;
    Ok(scanned.file_name.clone())
}

/// 建立一個新插槽:本機插槽先連到原檔(與 `.pub`),再寫帳戶記錄與本機狀態;記錄寫不進去就把連結收回。回傳插槽檔名。
/// 插槽 id 是剛產生的隨機值,但路徑上有東西一樣不連結(`link_free_slot`)。
fn create_slot(
    env: &SyncEnv,
    account_keys: &ChainKeys,
    keys_dir: &Path,
    candidate: &KeyCandidate,
    name: String,
    sync: bool,
) -> Result<String, AppError> {
    if !valid_slot_name(&name) {
        return Err(AppError::Other(format!(
            "\"{name}\" can't be used as a key name: use letters, digits, '.', '_' or '-', start with a letter or digit, and don't end with .pub"
        )));
    }
    // 「Sync key」上傳的是現在檔案裡的這把金鑰:先讀、先檢查(PEM、太大、讀不懂的在這裡就擋下,什麼都還沒建立)。「Keep」不讀私鑰。
    let uploaded = if sync {
        let text = std::fs::read_to_string(&candidate.path)?;
        let facts = inspect_private_key(&text).map_err(|e| AppError::Other(e.message().to_string()))?;
        Some((text, facts))
    } else {
        None
    };
    let slot_id = new_slot_id()?;
    let file = slot_file_name(&name, &slot_id);
    let slot_path = keys_dir.join(&file);
    // 連結用的路徑與記進 `Linked` 的路徑出自同一個字串(`candidate.path`):`slots::maintain` 每一輪(Unix)確認 symlink 正好指到記錄的路徑。
    let link = link_free_slot(keys_dir, &slot_path, Path::new(&candidate.path))?;
    let now = env.now();
    let result = mutate(env, |s| {
        // 提交的臨界區裡再確認一次(`account_still_ready`),在任何修改之前:`setup_keys` 一開始的檢查之後同步輪次可能已經記下 `frozen`。回 Err 的話,
        // 剛連結的插槽由下面收回。
        account_still_ready(s, account_keys)?;
        let device_id = s.device_id.clone();
        let account = s.account.as_mut().ok_or_else(|| AppError::Other("join a sync account first".to_string()))?;
        // 會失敗的先做:`mutate` 的閉包回 Err 時,已經做的修改不會復原。
        if let Some((text, _)) = &uploaded {
            put_key_secret(account, account_keys, &slot_id, Some(text), &device_id, now)?;
        }
        let facts = uploaded.as_ref().map(|(_, facts)| facts);
        let payload = KeySlotPayload {
            schema: SLOT_SCHEMA,
            name: name.clone(),
            mode: if sync { SlotMode::Synced } else { SlotMode::Own },
            origin_device_id: device_id.clone(),
            created_at_ms: now,
            public_key: facts.map(|f| f.public_key.clone()),
            fingerprint: facts.map(|f| f.fingerprint.clone()),
            key_type: facts.map(|f| f.key_type.clone()),
            has_passphrase: facts.map(|f| f.has_passphrase),
        };
        put_slot(account, &slot_id, Some(&payload), &device_id, now);
        s.key_slots.insert(
            slot_id.clone(),
            LocalSlot {
                file_name: file.clone(),
                source: Some(SlotSource::Linked {
                    path: candidate.path.clone(),
                    link,
                    fingerprint: facts.map(|f| f.fingerprint.clone()).or_else(|| candidate.fingerprint.clone()),
                    origin: true,
                }),
                last_error: None,
                asked: false,
                payload: Some(payload),
                // 只有使用者在這台選了「Sync key」,上傳的這把金鑰才算是這台自己上傳的(補寫 `key` 時只認它,見 `LocalSlot::uploaded_fingerprint`)。
                uploaded_fingerprint: facts.map(|f| f.fingerprint.clone()),
                parked: false,
                // 在這個帳戶建立的(`account_still_ready` 確認過帳戶就是 `account_keys` 的那一個)。
                learned_in: Some(account_keys.chain_id.clone()),
                copy_from_another_account: false,
            },
        );
        Ok(())
    });
    if let Err(e) = result {
        let _ = slot_files::remove_slot(&slot_path);
        return Err(e);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::account::create_account;
    use crate::sync::dto::SlotStatusView;
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::round::tests::{pair, settle};
    use crate::sync::slot_rules::{public_path, test_keys, REASON_PUBLIC_KEY, REASON_TOKENS};
    use crate::sync::slots::live_slots;
    use crate::sync::slots::tests::{refused, FrozenWhenCommitting};
    use crate::sync::testkit::{AppliedProbe, TestClock, TestDevice};

    /// 一台已建立帳戶的裝置(Personal),主 config 是 `main`;回傳(裝置、Personal 的 id)。
    fn device(main: &str) -> (TestDevice, String) {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, main);
        create_account(&a.env(), "MacBook-A").unwrap();
        settle(&a);
        let personal = a.state().spaces.keys().next().unwrap().clone();
        (a, personal)
    }

    fn put_key(d: &TestDevice, name: &str, text: &str) -> PathBuf {
        let path = d.ssh_dir().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn home(d: &TestDevice) -> PathBuf {
        d.ssh_dir().parent().unwrap().to_path_buf()
    }

    fn keep(path: &Path, name: &str) -> KeyChoice {
        KeyChoice { path: path.display().to_string(), decision: KeyDecision::Keep { name: name.into() } }
    }

    fn sync(path: &Path, name: &str) -> KeyChoice {
        KeyChoice { path: path.display().to_string(), decision: KeyDecision::Sync { name: name.into() } }
    }

    fn reuse(path: &Path, slot_id: &str) -> KeyChoice {
        KeyChoice { path: path.display().to_string(), decision: KeyDecision::Reuse { slot_id: slot_id.into() } }
    }

    /// 帳戶裡憑空多一個 `synced` 插槽記錄(別台、或帳戶裡的任何成員發佈的;金鑰是 `test_keys::plain()`),這台沒有它的任何本機記錄。
    fn publish_synced(d: &TestDevice, id: &str, name: &str) {
        let env = d.env();
        let now = env.now();
        mutate(&env, |s| {
            let me = s.device_id.clone();
            let payload = KeySlotPayload {
                schema: SLOT_SCHEMA,
                name: name.into(),
                mode: SlotMode::Synced,
                origin_device_id: "f".repeat(32),
                created_at_ms: 5,
                public_key: Some(test_keys::PLAIN_PUBLIC.into()),
                fingerprint: Some(test_keys::PLAIN_FINGERPRINT.into()),
                key_type: Some("ssh-ed25519".into()),
                has_passphrase: Some(false),
            };
            put_slot(s.account.as_mut().unwrap(), id, Some(&payload), &me, now);
            Ok(())
        })
        .unwrap();
    }

    /// 把一個勾選的 space 標成第一輪同步還沒跑完(`false`)或已經跑完(`true`):直接改記憶體裡的狀態(同 `files.rs` 的測試)。
    fn set_baseline(d: &TestDevice, space_id: &str, established: bool) {
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(space_id).unwrap().baseline_established = established;
    }

    /// 這台用 Keep 為 `id_mac` 設定了插槽;之後主機又指回金鑰檔本身,一輪之後沒有主機用到它 —— 連結收起來了(`parked`)。
    /// 回傳(裝置、space 檔、金鑰檔、插槽 id、插槽路徑)。
    fn parked_slot() -> (TestDevice, PathBuf, PathBuf, String, PathBuf) {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]).unwrap();
        let id = live_slots(a.state().account.as_ref().unwrap())[0].0.clone();
        let link = home(&a).join(SLOT_DIR).join(slot_file_name("id_mac", &id));
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        settle(&a);
        assert!(a.state().key_slots[&id].parked && !slot_files::occupied(&link), "setup: no host uses the slot, so its link is put away");
        (a, space, key, id, link)
    }

    #[test]
    fn candidates_group_hosts_by_key_and_list_what_cannot_be_set_up() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        a.save_in_app(
            &a.space_path(&personal),
            &format!(
                "Host web\n  IdentityFile ~/.ssh/id_mac\nHost db\n  identityfile = \"{}\"   # spelled out\nHost proxy\n  IdentityFile ~/.ssh/%h\nHost agent\n  IdentityFile ~/.ssh/id_mac.pub\nHost gone\n  IdentityFile ~/.ssh/missing\n",
                key.display()
            ),
        );
        let found = key_candidates(&a.env()).unwrap();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        let candidate = &found.keys[0];
        assert_eq!(candidate.path, key.display().to_string());
        assert_eq!(candidate.default_name, "id_mac");
        assert_eq!(candidate.fingerprint.as_deref(), Some(test_keys::PLAIN_FINGERPRINT));
        assert_eq!(candidate.has_passphrase, Some(false));
        assert_eq!(candidate.unsyncable, None);
        assert_eq!(candidate.existing_slot, None);
        let hosts: Vec<(&str, &str)> = candidate.hosts.iter().map(|h| (h.alias.as_str(), h.value.as_str())).collect();
        assert_eq!(hosts, vec![("web", "~/.ssh/id_mac"), ("db", format!("\"{}\"", key.display()).as_str())]);
        assert!(candidate.hosts.iter().all(|h| h.space_name == "Personal" && h.locked.is_none()));
        let unsupported: Vec<(&str, &str)> = found.unsupported.iter().map(|u| (u.alias.as_str(), u.reason.as_str())).collect();
        assert_eq!(unsupported, vec![("proxy", REASON_TOKENS), ("agent", REASON_PUBLIC_KEY)]);
    }

    #[test]
    fn keeping_a_key_creates_an_own_slot_links_it_and_rewrites_only_those_lines() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        a.save_in_app(
            &a.space_path(&personal),
            &format!("Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/id_mac\nHost db\n  identityfile = \"{}\"   # spelled out\n", key.display()),
        );
        let rewritten = setup_keys(&a.env(), true, vec![keep(&key, "personal")]).unwrap();
        assert_eq!(rewritten, vec!["web".to_string(), "db".to_string()]);

        let slots = live_slots(a.state().account.as_ref().unwrap());
        assert_eq!(slots.len(), 1);
        let (id, payload) = &slots[0];
        assert_eq!((payload.name.as_str(), payload.mode), ("personal", SlotMode::Own));
        let file = slot_file_name("personal", id);
        assert_eq!(
            a.read(&a.space_path(&personal)),
            format!("Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/sshelter/keys/{file}\nHost db\n  identityfile = ~/.ssh/sshelter/keys/{file}   # spelled out\n")
        );
        let local = &a.state().key_slots[id];
        assert_eq!(local.source, Some(SlotSource::Linked { path: key.display().to_string(), link: local_link_kind(), fingerprint: Some(test_keys::PLAIN_FINGERPRINT.into()), origin: true }));
        assert_eq!(std::fs::read_to_string(home(&a).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
        assert!(key_candidates(&a.env()).unwrap().keys.is_empty(), "nothing left to set up");
        // 一輪之後,改寫的主機已上傳。
        settle(&a);
        assert!(a.state().spaces[&personal].records.values().all(|l| !l.dirty));
    }

    #[cfg(unix)]
    fn local_link_kind() -> crate::sync::slot_files::LinkKind {
        crate::sync::slot_files::LinkKind::Symlink
    }
    #[cfg(not(unix))]
    fn local_link_kind() -> crate::sync::slot_files::LinkKind {
        crate::sync::slot_files::LinkKind::HardLink
    }

    #[test]
    fn a_synced_key_reaches_the_other_computer() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let key = put_key(&a, "id_mac", &test_keys::plain());
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        setup_keys(&a.env(), true, vec![sync(&key, "id_mac")]).unwrap();
        settle(&a);
        settle(&b);
        let id = live_slots(b.state().account.as_ref().unwrap())[0].0.clone();
        let landed = home(&b).join(SLOT_DIR).join(slot_file_name("id_mac", &id));
        assert_eq!(std::fs::read_to_string(landed).unwrap(), test_keys::plain());
    }

    #[test]
    fn the_same_key_on_another_computer_reuses_the_synced_slot() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let key = put_key(&a, "id_mac", &test_keys::plain());
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        setup_keys(&a.env(), true, vec![sync(&key, "id_mac")]).unwrap();
        settle(&a);
        settle(&b);
        let id = live_slots(b.state().account.as_ref().unwrap())[0].0.clone();
        // B 自己也有同一把金鑰(別的檔名),又加了一台主機用它。
        let copy = put_key(&b, "same_key", &test_keys::plain());
        let text = b.read(&b.space_path(&personal));
        b.save_in_app(&b.space_path(&personal), &format!("{text}Host db\n  IdentityFile ~/.ssh/same_key\n"));
        let found = key_candidates(&b.env()).unwrap();
        assert_eq!(found.keys[0].existing_slot.as_deref(), Some(id.as_str()));
        setup_keys(&b.env(), true, vec![KeyChoice { path: copy.display().to_string(), decision: KeyDecision::Reuse { slot_id: id.clone() } }]).unwrap();
        assert_eq!(live_slots(b.state().account.as_ref().unwrap()).len(), 1, "no second slot");
        assert!(b.read(&b.space_path(&personal)).contains(&format!("Host db\n  IdentityFile ~/.ssh/sshelter/keys/{}", slot_file_name("id_mac", &id))));
    }

    #[test]
    fn a_host_with_more_than_one_copy_is_locked() {
        let (a, personal) = device("# main\nHost web\n  HostName 1.1.1.1\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_mac\nHost db\n  IdentityFile ~/.ssh/id_mac\n");
        let found = key_candidates(&a.env()).unwrap();
        let locked: Vec<(&str, Option<&str>)> = found.keys[0].hosts.iter().map(|h| (h.alias.as_str(), h.locked.as_deref())).collect();
        assert_eq!(locked, vec![("web", Some(LOCKED_REASON)), ("db", None)]);
        assert_eq!(setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]).unwrap(), vec!["db".to_string()]);
        assert!(a.read(&a.space_path(&personal)).starts_with("Host web\n  IdentityFile ~/.ssh/id_mac\n"));
    }

    #[test]
    fn a_conflict_while_rewriting_leaves_the_slot_ready_to_reuse() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        // 另一個編輯器改了檔案,app 還沒重載:改寫會撞到 Conflict。
        a.write_externally(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\nHost other\n  HostName 9.9.9.9\n");
        assert!(matches!(setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]), Err(AppError::Conflict(_))));
        let id = live_slots(a.state().account.as_ref().unwrap())[0].0.clone();
        // doc 已從磁碟重載;下一次掃描把它當成可以沿用的插槽。
        let found = key_candidates(&a.env()).unwrap();
        assert_eq!(found.keys[0].existing_slot.as_deref(), Some(id.as_str()));

        // 兩次掃描之間跑了一輪同步:沒有主機用到這個插槽,連結收起來了(`parked`)。它還是同一個可以沿用的插槽,沿用時再連起來。
        settle(&a);
        let link = home(&a).join(SLOT_DIR).join(slot_file_name("id_mac", &id));
        assert!(a.state().key_slots[&id].parked && !slot_files::occupied(&link), "the round put the unused link away");
        let found = key_candidates(&a.env()).unwrap();
        assert_eq!(found.keys[0].existing_slot.as_deref(), Some(id.as_str()));

        setup_keys(&a.env(), true, vec![KeyChoice { path: key.display().to_string(), decision: KeyDecision::Reuse { slot_id: id.clone() } }]).unwrap();
        assert!(a.read(&space).starts_with(&format!("Host web\n  IdentityFile ~/.ssh/sshelter/keys/{}\n", slot_file_name("id_mac", &id))));
        assert_eq!(live_slots(a.state().account.as_ref().unwrap()).len(), 1);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain(), "the slot is in place");
        assert!(!a.state().key_slots[&id].parked);
    }

    /// 這台已經握著的插槽(連結在位、沒收起來)沿用的時候什麼都不動:改寫撞到 `Conflict` 之後(沒有跑同步)再要求沿用,
    /// 本機記錄一個欄位都沒變,主機照常改寫完。
    #[test]
    fn reusing_a_slot_this_computer_holds_leaves_its_record_alone_and_rewrites_the_hosts() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        a.write_externally(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n# edited elsewhere\n");
        assert!(matches!(setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]), Err(AppError::Conflict(_))));
        let id = live_slots(a.state().account.as_ref().unwrap())[0].0.clone();
        let held = a.state().key_slots[&id].clone();
        assert!(held.source.is_some() && !held.parked, "{held:?}");

        assert_eq!(setup_keys(&a.env(), true, vec![reuse(&key, &id)]).unwrap(), vec!["web".to_string()]);
        assert_eq!(a.state().key_slots[&id], held, "a slot that is already held is not touched");
        assert_eq!(a.read(&space), format!("Host web\n  IdentityFile ~/.ssh/sshelter/keys/{}\n# edited elsewhere\n", slot_file_name("id_mac", &id)));
        assert_eq!(live_slots(a.state().account.as_ref().unwrap()).len(), 1);
    }

    #[test]
    fn keys_that_cannot_be_synced_can_still_be_kept() {
        let (a, personal) = device("# main\n");
        let pem = format!("{}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n{}\n", concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), concat!("-----END RSA ", "PRIVATE KEY-----"));
        let key = put_key(&a, "id_rsa", &pem);
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_rsa\n");
        let found = key_candidates(&a.env()).unwrap();
        assert_eq!(found.keys[0].unsyncable.as_deref(), Some(crate::sync::slot_rules::Unsyncable::NotOpenSsh.message()));
        let refused = setup_keys(&a.env(), true, vec![sync(&key, "id_rsa")]).unwrap_err().to_string();
        assert_eq!(refused, crate::sync::slot_rules::Unsyncable::NotOpenSsh.message());
        assert!(live_slots(a.state().account.as_ref().unwrap()).is_empty(), "nothing was created");
        setup_keys(&a.env(), true, vec![keep(&key, "id_rsa")]).unwrap();
        assert_eq!(live_slots(a.state().account.as_ref().unwrap())[0].1.mode, SlotMode::Own);
    }

    #[test]
    fn setup_needs_the_sync_engine_and_a_valid_name() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        assert!(setup_keys(&a.env(), false, vec![keep(&key, "id_mac")]).is_err(), "no engine in this process");
        assert!(setup_keys(&a.env(), true, vec![keep(&key, "../x")]).is_err());
        assert!(live_slots(a.state().account.as_ref().unwrap()).is_empty());
    }

    // ── 控制者的裁定新增的測試(沿用既有插槽的各種情況、`uploaded_fingerprint`、鎖)──────────────────────

    /// 只有「Sync key」記錄這台自己上傳了哪把金鑰(`uploaded_fingerprint`);「Keep on this computer」不記。新插槽不是收起來的。
    #[test]
    fn only_a_sync_choice_records_the_key_this_computer_uploaded() {
        let (a, personal) = device("# main\n");
        let mac = put_key(&a, "id_mac", &test_keys::plain());
        let work = put_key(&a, "id_work", &test_keys::ecdsa());
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_mac\nHost jump\n  IdentityFile ~/.ssh/id_work\n");
        setup_keys(&a.env(), true, vec![sync(&mac, "id_mac"), keep(&work, "id_work")]).unwrap();

        let state = a.state();
        let slots = live_slots(state.account.as_ref().unwrap());
        let id_of = |mode: SlotMode| slots.iter().find(|(_, p)| p.mode == mode).map(|(id, _)| id.clone()).unwrap();
        let (synced, own) = (id_of(SlotMode::Synced), id_of(SlotMode::Own));
        assert_eq!(state.key_slots[&synced].uploaded_fingerprint.as_deref(), Some(test_keys::PLAIN_FINGERPRINT), "the key it uploaded");
        assert_eq!(state.key_slots[&own].uploaded_fingerprint, None, "a kept key is never uploaded");
        assert!(state.key_slots.values().all(|l| !l.parked));
        let chain = state.account.as_ref().unwrap().chain_id.clone();
        assert!(state.key_slots.values().all(|l| l.learned_in.as_deref() == Some(chain.as_str())), "both were made in this account");
        // 同步的金鑰上傳了(記錄與密文都在帳戶裡),狀態檔裡卻只有密文。
        assert!(crate::sync::slots::open_key_secret(state.account.as_ref().unwrap(), &a.runtime.core.lock().unwrap().account_keys.clone().unwrap(), &synced).is_some());
        let saved = std::fs::read_to_string(a.home.path().join("data").join("sync-state.json")).unwrap();
        assert!(!saved.contains(test_keys::PLAIN_BODY[1]), "the state file never holds the private key");
    }

    /// 這台沒有紀錄的插槽,路徑上已經有使用者自己的檔案(例如重灌之後留下的):第一次沿用不連結、不寫 `.pub`、不改寫主機,
    /// 說明擋路的檔案;移開之後同一個選擇照常做完。
    #[test]
    fn a_file_in_the_slot_path_stops_the_first_reuse_before_anything_is_linked_or_rewritten() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        let id = new_slot_id().unwrap();
        publish_synced(&a, &id, "id_mac");
        let file = slot_file_name("id_mac", &id);
        let path = home(&a).join(SLOT_DIR).join(&file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "mine").unwrap();
        assert_eq!(key_candidates(&a.env()).unwrap().keys[0].existing_slot.as_deref(), Some(id.as_str()));

        let before = a.read(&space);
        let refused = setup_keys(&a.env(), true, vec![reuse(&key, &id)]).unwrap_err().to_string();
        assert_eq!(refused, in_the_way_message(&path));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "mine", "the user's file is not replaced");
        assert!(!slot_files::occupied(&public_path(&path)), "and no .pub is written beside it");
        assert_eq!(a.read(&space), before, "the host is not rewritten");
        assert!(!a.state().key_slots.contains_key(&id), "nothing is recorded for a link that was never made");

        std::fs::remove_file(&path).unwrap();
        assert_eq!(setup_keys(&a.env(), true, vec![reuse(&key, &id)]).unwrap(), vec!["web".to_string()]);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::plain());
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        assert_eq!(a.read(&space), format!("Host web\n  IdentityFile ~/.ssh/sshelter/keys/{file}\n"));
        let local = a.state().key_slots[&id].clone();
        assert!(matches!(&local.source, Some(SlotSource::Linked { origin: false, .. })), "{local:?}");
        assert_eq!((local.uploaded_fingerprint.as_deref(), local.parked), (None, false));
        assert_eq!(local.learned_in, a.state().account.map(|a| a.chain_id), "the first reuse records the account the slot is in");
    }

    /// 三條路建好的插槽(第一次沿用別台發佈的、Sync、Keep)都以連結時用的那個路徑記錄:下一輪維護(Unix 上會檢查連結正好指到記錄的路徑)
    /// 找到的就是剛放好的連結,沒有錯誤、沒有收起來,狀態是 Ready。
    #[test]
    fn slots_set_up_here_are_still_ready_after_the_next_round() {
        let (a, personal) = device("# main\n");
        let mac = put_key(&a, "id_mac", &test_keys::plain());
        let work = put_key(&a, "id_work", &test_keys::ecdsa());
        let enc = put_key(&a, "id_enc", &test_keys::encrypted());
        a.save_in_app(
            &a.space_path(&personal),
            "Host web\n  IdentityFile ~/.ssh/id_mac\nHost jump\n  IdentityFile ~/.ssh/id_work\nHost db\n  IdentityFile ~/.ssh/id_enc\n",
        );
        // 普通金鑰的 `synced` 插槽是別台發佈的:這台沒有它的記錄,沿用就是第一次沿用(連到這台自己的那把)。
        let published = new_slot_id().unwrap();
        publish_synced(&a, &published, "id_mac");
        let choices = vec![reuse(&mac, &published), sync(&work, "id_work"), keep(&enc, "id_enc")];
        assert_eq!(setup_keys(&a.env(), true, choices).unwrap(), vec!["web".to_string(), "jump".to_string(), "db".to_string()]);
        settle(&a);

        let state = a.state();
        assert_eq!(state.key_slots.len(), 3);
        for (id, local) in &state.key_slots {
            assert!(local.last_error.is_none() && !local.parked, "{id}: {local:?}");
        }
        let shown = crate::sync::dto::overview(&a.env()).unwrap().key_slots;
        assert_eq!(shown.len(), 3);
        assert!(shown.iter().all(|v| matches!(v.status, SlotStatusView::Ready { synced_copy: false, .. })), "{shown:?}");
    }

    /// 收起來的連結(沒有主機用到而拿掉了連結檔)在沿用的時候先連回去,才改寫主機(spec §6.1 第 4 步):改寫撞到 `Conflict` 的時候,
    /// 插槽也已經在位、記錄也不再是收起來的;再來一次就把主機改寫完。
    #[test]
    fn a_parked_slot_is_linked_again_before_its_hosts_are_rewritten() {
        let (a, space, key, id, link) = parked_slot();
        let file = slot_file_name("id_mac", &id);
        a.write_externally(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n# edited elsewhere\n");
        assert_eq!(key_candidates(&a.env()).unwrap().keys[0].existing_slot.as_deref(), Some(id.as_str()));
        assert!(matches!(setup_keys(&a.env(), true, vec![reuse(&key, &id)]), Err(AppError::Conflict(_))), "the rewrite meets the outside edit");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain(), "the slot was put back before the rewrite was tried");
        assert_eq!(std::fs::read_to_string(public_path(&link)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        let local = a.state().key_slots[&id].clone();
        assert!(!local.parked && local.last_error.is_none(), "{local:?}");
        assert!(matches!(&local.source, Some(SlotSource::Linked { origin: true, .. })), "it is still the slot this computer created: {local:?}");
        assert_eq!(a.read(&space), "Host web\n  IdentityFile ~/.ssh/id_mac\n# edited elsewhere\n", "the host is untouched");

        assert_eq!(setup_keys(&a.env(), true, vec![reuse(&key, &id)]).unwrap(), vec!["web".to_string()]);
        assert_eq!(a.read(&space), format!("Host web\n  IdentityFile ~/.ssh/sshelter/keys/{file}\n# edited elsewhere\n"));
        assert_eq!(live_slots(a.state().account.as_ref().unwrap()).len(), 1);
    }

    /// 收起來的連結不擁有路徑上的任何東西:路徑上現在有使用者自己的檔案,就不連結、不改寫主機,說明擋路的檔案;記錄還是收起來的。
    #[test]
    fn a_file_where_a_parked_link_used_to_be_stops_its_reuse() {
        let (a, space, key, id, link) = parked_slot();
        std::fs::write(&link, "mine").unwrap();
        let before = a.read(&space);
        let refused = setup_keys(&a.env(), true, vec![reuse(&key, &id)]).unwrap_err().to_string();
        assert_eq!(refused, in_the_way_message(&link));
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "mine");
        assert_eq!(a.read(&space), before);
        assert!(a.state().key_slots[&id].parked, "still not this slot's path");
    }

    /// 已經有插槽的金鑰(`existing_slot`)收到「Sync key」或「Keep on this computer」(畫面上的舊資料:重新讀取失敗之後又按了一次):不建立第二個
    /// 插槽、不上傳、不改寫主機,說明這把金鑰已經有插槽。沿用那個插槽照常可以。
    #[test]
    fn a_key_that_already_has_a_slot_is_never_given_a_second_one() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]).unwrap();
        let id = live_slots(a.state().account.as_ref().unwrap())[0].0.clone();
        // 又一台主機指到同一把金鑰:候選帶著那個插槽。
        a.save_in_app(&space, &format!("{}Host db\n  IdentityFile ~/.ssh/id_mac\n", a.read(&space)));
        assert_eq!(key_candidates(&a.env()).unwrap().keys[0].existing_slot.as_deref(), Some(id.as_str()));

        for choice in [sync(&key, "again"), keep(&key, "again")] {
            refused(&a, ALREADY_SET_UP_MESSAGE, || setup_keys(&a.env(), true, vec![choice]).map(|_| ()));
        }
        let state = a.state();
        assert_eq!(live_slots(state.account.as_ref().unwrap()).len(), 1, "no second slot");
        assert!(state.account.as_ref().unwrap().sealed.keys().all(|k| !k.starts_with("key:")), "and no key was uploaded");
        assert_eq!(setup_keys(&a.env(), true, vec![reuse(&key, &id)]).unwrap(), vec!["db".to_string()]);
    }

    /// 「沿用」只能沿用候選帶著的那個插槽(`existing_slot`):別的插槽 id(畫面上的舊資料,或另一把金鑰的插槽)拒絕,什麼都不連、不寫、不改寫 ——
    /// 不然這把金鑰的主機會改指到另一把金鑰的插槽,或把另一個插槽連到這把金鑰。
    #[test]
    fn reuse_takes_only_the_slot_the_candidate_names() {
        let (a, personal) = device("# main\n");
        let mac = put_key(&a, "id_mac", &test_keys::plain());
        let work = put_key(&a, "id_work", &test_keys::ecdsa());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\nHost jump\n  IdentityFile ~/.ssh/id_work\n");
        setup_keys(&a.env(), true, vec![keep(&work, "id_work")]).unwrap();
        let work_slot = live_slots(a.state().account.as_ref().unwrap())[0].0.clone();
        // `id_mac` 還沒有插槽;`id_work` 又多了一台主機,候選帶著它自己的插槽。
        a.save_in_app(&space, &format!("{}Host db\n  IdentityFile ~/.ssh/id_work\n", a.read(&space)));
        let found = key_candidates(&a.env()).unwrap();
        let slot_of = |key: &Path| found.keys.iter().find(|k| k.path == key.display().to_string()).map(|k| k.existing_slot.clone());
        assert_eq!((slot_of(&mac), slot_of(&work)), (Some(None), Some(Some(work_slot.clone()))));
        // 另一個(帳戶裡別台發佈的)插槽。
        let published = new_slot_id().unwrap();
        publish_synced(&a, &published, "elsewhere");

        refused(&a, OTHER_SLOT_MESSAGE, || setup_keys(&a.env(), true, vec![reuse(&mac, &work_slot)]).map(|_| ()));
        refused(&a, OTHER_SLOT_MESSAGE, || setup_keys(&a.env(), true, vec![reuse(&work, &published)]).map(|_| ()));
        assert_eq!(setup_keys(&a.env(), true, vec![reuse(&work, &work_slot)]).unwrap(), vec!["db".to_string()]);
    }

    /// 這台握著的插槽,沿用的捷徑(什麼都不動、直接改寫主機)只在它放的金鑰真的還在插槽路徑上時才走:連到的原檔不見了,或帳戶裡把插槽改了名(記錄說的是
    /// 舊路徑),就不改寫主機 —— 不然一台能連線的主機會改指到沒有金鑰的插槽 —— 說明哪裡沒有金鑰。
    #[test]
    fn reusing_a_held_slot_whose_key_is_not_in_place_leaves_the_hosts_alone() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        setup_keys(&a.env(), true, vec![sync(&key, "id_mac")]).unwrap();
        let id = live_slots(a.state().account.as_ref().unwrap())[0].0.clone();
        let held = a.state().key_slots[&id].clone();
        assert!(held.source.is_some() && !held.parked);

        // 原檔被搬走了;另一台主機用的是同一把金鑰的另一份(能連線)。同指紋的同步插槽就是建議沿用的那一個。
        let copy = put_key(&a, "id_mac_copy", &test_keys::plain());
        std::fs::remove_file(&key).unwrap();
        a.save_in_app(&space, &format!("{}Host db\n  IdentityFile ~/.ssh/id_mac_copy\n", a.read(&space)));
        assert_eq!(key_candidates(&a.env()).unwrap().keys[0].existing_slot.as_deref(), Some(id.as_str()));
        refused(&a, &source_gone_message(&key.display().to_string()), || setup_keys(&a.env(), true, vec![reuse(&copy, &id)]).map(|_| ()));

        // 原檔回來了,但帳戶裡的插槽改了名:記錄說的是舊路徑,新路徑上什麼都沒有。
        std::fs::write(&key, test_keys::plain()).unwrap();
        publish_synced(&a, &id, "renamed");
        let renamed = home(&a).join(SLOT_DIR).join(slot_file_name("renamed", &id));
        refused(&a, &source_gone_message(&renamed.display().to_string()), || setup_keys(&a.env(), true, vec![reuse(&copy, &id)]).map(|_| ()));
        assert!(a.read(&space).contains("Host db\n  IdentityFile ~/.ssh/id_mac_copy\n"), "db keeps its working key");
    }

    /// 和帳戶裡另一個插槽同檔名、這台又沒有握著的插槽:不建議沿用(`existing_slot` 是 None)、直接要求沿用也拒絕,什麼都不連、不寫、不改寫。
    #[test]
    fn a_slot_that_shares_its_file_name_and_is_not_held_here_is_never_linked() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        // 帳戶裡的成員發佈了兩個同名、同 id 前 8 字元的插槽(都帶著這把金鑰的指紋):這台一個都沒握著。
        let (x, y) = (format!("3fa2c1d9{}", "0".repeat(24)), format!("3fa2c1d9{}", "f".repeat(24)));
        publish_synced(&a, &x, "id_mac");
        publish_synced(&a, &y, "id_mac");
        let state = a.state();
        assert!(contested_and_not_held(&state, &x) && contested_and_not_held(&state, &y));
        assert_eq!(key_candidates(&a.env()).unwrap().keys[0].existing_slot, None, "a slot this computer cannot use is not offered");

        let before = a.read(&space);
        for id in [&x, &y] {
            assert_eq!(setup_keys(&a.env(), true, vec![reuse(&key, id)]).unwrap_err().to_string(), CONTESTED_MESSAGE);
        }
        let path = home(&a).join(SLOT_DIR).join(slot_file_name("id_mac", &x));
        assert!(!slot_files::occupied(&path) && !slot_files::occupied(&public_path(&path)), "nothing is linked or written");
        assert_eq!(a.read(&space), before, "the host is not rewritten");
        assert!(a.state().key_slots.is_empty());
        // 帳戶裡沒有(或已刪除)的插槽也不能沿用。
        let gone = setup_keys(&a.env(), true, vec![reuse(&key, "ffffffffffffffffffffffffffffffff")]).unwrap_err().to_string();
        assert_eq!(gone, "that key slot no longer exists");
        assert_eq!(a.read(&space), before);
    }

    /// 通知(`applied`)一律在放掉 doc、backed_up、core 三把鎖之後才發 —— 成功與改寫撞到 `Conflict` 重載 doc 的兩條路徑都一樣。
    #[test]
    fn setup_tells_the_app_only_after_every_lock_is_released() {
        for conflict in [false, true] {
            let (a, personal) = device("# main\n");
            let key = put_key(&a, "id_mac", &test_keys::plain());
            let space = a.space_path(&personal);
            a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
            if conflict {
                a.write_externally(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n# edited elsewhere\n");
            }
            let probe = AppliedProbe::new(&a);
            let mut env = a.env();
            env.events = &probe;
            let out = setup_keys(&env, true, vec![keep(&key, "id_mac")]);
            assert_eq!(out.is_err(), conflict, "{out:?}");
            assert_eq!(*probe.all_free.lock().unwrap(), vec![true], "one applied(0), sent with no lock held (conflict: {conflict})");
            assert_eq!(probe.wakes(), 1, "conflict: {conflict}");
        }
    }

    /// 第一輪同步還沒跑完(`baseline_established == false`)的 space:存檔 hook 不為它規劃記錄(`files::note_written`),第一輪以 chain 為準 ——
    /// 這時改寫的主機會被寫回原樣。它的主機不列為候選、也不列在無法自動設定的清單裡,設定時也不改寫(什麼都不建立);那個 space 的第一輪之後,
    /// 下一次掃描才出現。
    #[test]
    fn hosts_in_a_space_that_has_not_finished_its_first_sync_are_neither_offered_nor_rewritten() {
        let (a, personal) = device("# main\n");
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let space = a.space_path(&personal);
        let text = "Host web\n  IdentityFile ~/.ssh/id_mac\nHost proxy\n  IdentityFile ~/.ssh/%h\nHost agent\n  IdentityFile ~/.ssh/id_mac.pub\n";
        a.save_in_app(&space, text);
        set_baseline(&a, &personal, false);

        let found = key_candidates(&a.env()).unwrap();
        assert!(found.keys.is_empty() && found.unsupported.is_empty(), "{found:?}");
        refused(&a, SET_UP_MEANWHILE_MESSAGE, || setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]).map(|_| ()));
        assert!(live_slots(a.state().account.as_ref().unwrap()).is_empty(), "no slot is created for a key nothing offered");
        assert!(a.state().key_slots.is_empty());
        assert_eq!(a.read(&space), text, "the file is not touched");

        // 第一輪跑完之後(這裡直接標成已建立):下一次掃描才出現,設定也照常做完。
        set_baseline(&a, &personal, true);
        let found = key_candidates(&a.env()).unwrap();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        assert_eq!(found.keys[0].hosts.iter().map(|h| h.alias.as_str()).collect::<Vec<_>>(), vec!["web"]);
        assert_eq!(found.unsupported.iter().map(|u| u.alias.as_str()).collect::<Vec<_>>(), vec!["proxy", "agent"]);
        assert_eq!(setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]).unwrap(), vec!["web".to_string()]);
    }

    /// 同一把金鑰被已經跑完第一輪的 space 與還沒跑完的 space 的主機用到:設定只改寫前者的主機(後者照舊指到金鑰檔,不會被它的第一輪悄悄還原),
    /// 後者的第一輪之後,下一次掃描把它們列出來、直接沿用剛建好的插槽。
    #[test]
    fn the_rewrite_covers_only_spaces_that_have_finished_their_first_sync() {
        let (a, personal) = device("# main\n");
        let work = crate::sync::spaces::create_space(&a.env(), "Work").unwrap();
        let key = put_key(&a, "id_mac", &test_keys::plain());
        let (personal_file, work_file) = (a.space_path(&personal), a.space_path(&work));
        a.save_in_app(&personal_file, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        a.save_in_app(&work_file, "Host db\n  IdentityFile ~/.ssh/id_mac\n");
        set_baseline(&a, &work, false);

        let found = key_candidates(&a.env()).unwrap();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        assert_eq!(found.keys[0].hosts.iter().map(|h| h.alias.as_str()).collect::<Vec<_>>(), vec!["web"], "only the finished space's host is offered");
        assert_eq!(setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]).unwrap(), vec!["web".to_string()]);
        let id = live_slots(a.state().account.as_ref().unwrap())[0].0.clone();
        let file = slot_file_name("id_mac", &id);
        assert_eq!(a.read(&personal_file), format!("Host web\n  IdentityFile ~/.ssh/sshelter/keys/{file}\n"));
        assert_eq!(a.read(&work_file), "Host db\n  IdentityFile ~/.ssh/id_mac\n", "the space that has not finished its first sync is left alone");

        set_baseline(&a, &work, true);
        let found = key_candidates(&a.env()).unwrap();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        assert_eq!(found.keys[0].existing_slot.as_deref(), Some(id.as_str()), "the slot just made is offered for reuse");
        assert_eq!(found.keys[0].hosts.iter().map(|h| h.alias.as_str()).collect::<Vec<_>>(), vec!["db"]);
        assert_eq!(setup_keys(&a.env(), true, vec![reuse(&key, &id)]).unwrap(), vec!["db".to_string()]);
        assert_eq!(a.read(&work_file), format!("Host db\n  IdentityFile ~/.ssh/sshelter/keys/{file}\n"));
        assert_eq!(live_slots(a.state().account.as_ref().unwrap()).len(), 1, "no second slot");
    }

    // ── 更換同步碼期間,建立插槽(寫 `keyslot`/`key`)要等(和 space 的操作一樣檢查 `account::account_ready`)──────────

    /// 更換同步碼進行中(第 2 步起)與這台已被別台擋下時,設定金鑰 —— 建立插槽會寫 `keyslot`/`key` —— 一律拒絕,說明和 space 的操作一樣:帳戶區段之後會被整個
    /// 換掉,寫進去的記錄不是被丟掉、就是被較舊的版本取代。拒絕時什麼都沒建立、沒連結、沒改寫主機,狀態與 `~/.ssh` 底下的檔案都不動。
    #[test]
    fn setup_is_refused_during_a_sync_code_change_and_on_a_computer_that_missed_it() {
        use crate::sync::account::{FROZEN_MESSAGE, ROTATING_MESSAGE};
        let (_relay, _clock, a, b, _words, personal) = pair();
        // 各有一把只在自己這台的金鑰,各有一台主機指到它(同一個 space)。
        let mac = put_key(&a, "id_mac", &test_keys::plain());
        let work = put_key(&b, "id_work", &test_keys::ecdsa());
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        settle(&a);
        settle(&b);
        b.save_in_app(&b.space_path(&personal), &format!("{}Host db\n  IdentityFile ~/.ssh/id_work\n", b.read(&b.space_path(&personal))));
        settle(&b);
        settle(&a);
        assert_eq!(key_candidates(&a.env()).unwrap().keys.len(), 1, "setup: A is offered its own key");
        assert_eq!(key_candidates(&b.env()).unwrap().keys.len(), 1, "setup: B is offered its own key");

        // A 更換同步碼:從準備好(第 2 步之前)到切換之前,每一步都擋 —— 「Sync key」與「Keep on this computer」一樣。
        crate::sync::rotation::start_rotation(&a.env()).unwrap();
        let mut steps = 0;
        while a.state().rotation.is_some() {
            refused(&a, ROTATING_MESSAGE, || setup_keys(&a.env(), true, vec![sync(&mac, "id_mac")]).map(|_| ()));
            refused(&a, ROTATING_MESSAGE, || setup_keys(&a.env(), true, vec![keep(&mac, "id_mac")]).map(|_| ()));
            let _ = crate::sync::round::sync_once(&a.env()); // 推進一步
            steps += 1;
            assert!(steps <= 10, "the sync code change never finished");
        }
        assert_eq!(steps, 5, "every step of the change was checked");
        assert!(live_slots(a.state().account.as_ref().unwrap()).is_empty() && a.state().key_slots.is_empty(), "nothing was created");

        // B 還沒輸入新同步碼:這台已被擋下。
        settle(&b);
        assert!(b.state().frozen().is_some(), "setup: B noticed the change");
        refused(&b, FROZEN_MESSAGE, || setup_keys(&b.env(), true, vec![sync(&work, "id_work")]).map(|_| ()));
        refused(&b, FROZEN_MESSAGE, || setup_keys(&b.env(), true, vec![keep(&work, "id_work")]).map(|_| ()));
        assert!(live_slots(b.state().account.as_ref().unwrap()).is_empty() && b.state().key_slots.is_empty(), "nothing was created");
    }

    /// 鎖外的檢查之後、`create_slot` 寫帳戶記錄之前 —— 它讀時鐘的那一刻 —— 同步輪次剛好記下了 `frozen`:提交的 core 臨界區裡再擋一次(同
    /// `spaces::still_ready`),帳戶記錄與本機狀態都不寫,剛連結的插槽(與 `.pub`)收回,主機不改寫。
    #[test]
    fn a_freeze_recorded_just_before_a_slot_is_created_leaves_nothing_behind() {
        use crate::sync::account::FROZEN_MESSAGE;
        for synced in [true, false] {
            let (a, personal) = device("# main\n");
            let key = put_key(&a, "id_mac", &test_keys::plain());
            let space = a.space_path(&personal);
            a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\n");
            let (before, hosts) = (a.state(), a.read(&space));

            let racing = FrozenWhenCommitting(&a);
            let mut env = a.env();
            env.clock = &racing;
            let choice = if synced { sync(&key, "id_mac") } else { keep(&key, "id_mac") };
            assert_eq!(setup_keys(&env, true, vec![choice]).unwrap_err().to_string(), FROZEN_MESSAGE, "synced: {synced}");
            let mut after = a.state();
            assert!(after.frozen().is_some(), "the freeze the round recorded is there");
            after.account.as_mut().unwrap().frozen = None;
            assert_eq!(after, before, "no record and no local state was written (synced: {synced})");
            assert_eq!(a.read(&space), hosts, "the host was not rewritten (synced: {synced})");
            let keys_dir = home(&a).join(SLOT_DIR);
            assert!(!keys_dir.exists() || std::fs::read_dir(&keys_dir).unwrap().next().is_none(), "the link and its .pub were taken back (synced: {synced})");
        }
    }

    // ── 之前的帳戶留下的插槽(spec §7.1:離開之後建立或加入另一個帳戶,再把主機搬進新帳戶的 space)──────────────────────

    /// `kept_after_a_move` 之後的情況。
    struct Kept {
        relay: std::sync::Arc<FakeRelay>,
        /// 留著之前帳戶的插槽記錄、`web` 被搬進新帳戶 space 的那一台。
        d: TestDevice,
        /// 新帳戶的另一台。
        c: TestDevice,
        /// 新帳戶的 Personal。
        next: String,
        /// 新帳戶的帳戶金鑰。
        keys: ChainKeys,
        id: String,
        file: String,
    }

    impl Kept {
        /// 這台的金鑰檔(只有在帳戶 A 建立插槽的那台有)。
        fn key(&self) -> PathBuf {
            self.d.ssh_dir().join("id_mac")
        }
        /// `d` 上這個插槽的路徑。
        fn slot_path(&self, d: &TestDevice) -> PathBuf {
            home(d).join(SLOT_DIR).join(&self.file)
        }
        /// 這台的新帳戶 Personal 檔。
        fn space(&self) -> PathBuf {
            self.d.space_path(&self.next)
        }
        /// `web` 的 `IdentityFile` 值。
        fn value(&self) -> String {
            slot_value(&self.file)
        }
        fn offered(&self) -> KeyCandidates {
            key_candidates(&self.d.env()).unwrap()
        }
    }

    /// 帳戶 A:A 有 `~/.ssh/id_mac`,`web` 用它,A 選了「Sync key」、插槽名稱是 `mac`(和金鑰檔名不同);B 落地了同步來的副本。`copy` = B(否則 A)
    /// 離開 A、和新的第三台 C 換到另一個帳戶(`join` = 加入 C 建立的,否則自己建立),再用搬移精靈把 `~/.ssh/sshelter-local/` 裡的 `web` 搬進新帳戶的
    /// Personal。新帳戶裡沒有這個插槽(N1:不會自己寫進去)。
    fn kept_after_a_move(copy: bool, join: bool) -> Kept {
        use crate::sync::slots::tests::{move_to_another_account, move_web_into};
        let (relay, clock, a, b, _words, personal) = pair();
        let key = put_key(&a, "id_mac", &test_keys::plain());
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/id_mac\n");
        setup_keys(&a.env(), true, vec![sync(&key, "mac")]).unwrap();
        settle(&a);
        settle(&b);
        let id = live_slots(a.state().account.as_ref().unwrap())[0].0.clone();
        let file = slot_file_name("mac", &id);
        let d = if copy { b } else { a };
        assert_eq!(std::fs::read_to_string(home(&d).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain(), "setup: the slot holds the key");
        let c = TestDevice::new("c", &relay, &clock);
        let (next, keys) = move_to_another_account(&d, &c, join);
        move_web_into(&d, &next);
        settle(&c);
        Kept { relay, d, c, next, keys, id, file }
    }

    fn aliases_and_values(candidate: &KeyCandidate) -> Vec<(String, String)> {
        candidate.hosts.iter().map(|h| (h.alias.clone(), h.value.clone())).collect()
    }

    /// 帳戶裡還在的插槽的 id(依名稱)。
    fn live_ids(account: &crate::sync::state_v2::AccountState) -> Vec<String> {
        live_slots(account).into_iter().map(|(id, _)| id).collect()
    }

    /// 之前的帳戶留下、連到這台金鑰的插槽:`web` 搬進新帳戶的 space 之後,「Sync key」對話框問這把金鑰 —— 候選是金鑰檔本身、帶著那個插槽(`kept_slot`),
    /// 名稱是插槽的名稱(不是金鑰檔名),`web` 列著它的插槽路徑;新帳戶裡還什麼都沒有。「Sync key」就地放進新帳戶:同一個 id、`synced`、這把金鑰的
    /// 指紋與私鑰,不建立第二個插槽;`web` 一個字都不改;這台記下記錄是新帳戶的、同意上傳的是這把;新帳戶的另一台在同一個路徑落地這把金鑰。
    fn a_linked_slot_from_the_previous_account_is_offered_and_synced_in_place(join: bool) {
        use crate::sync::slots::tests::account_on_relay;
        use crate::sync::slots::{key_secret_key, open_key_secret, slot_record_exists};
        let k = kept_after_a_move(false, join);
        let found = k.offered();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        let candidate = &found.keys[0];
        assert_eq!(candidate.path, k.key().display().to_string());
        assert_eq!(candidate.kept_slot, Some(KeptSlot { id: k.id.clone(), file_name: k.file.clone(), synced_copy: false }));
        assert_eq!(candidate.default_name, "mac", "the slot's own name, not the key file's");
        assert_eq!((candidate.existing_slot.as_deref(), candidate.fingerprint.as_deref()), (None, Some(test_keys::PLAIN_FINGERPRINT)));
        assert_eq!(aliases_and_values(candidate), vec![("web".to_string(), k.value())]);
        assert!(found.unsupported.is_empty(), "{found:?}");
        let theirs = account_on_relay(&k.relay, &k.keys);
        assert!(!slot_record_exists(&theirs, &k.id) && !theirs.sealed.contains_key(&key_secret_key(&k.keys, &k.id)), "nothing is in the new account yet");

        let before = k.d.read(&k.space());
        assert_eq!(setup_keys(&k.d.env(), true, vec![sync(&k.key(), "mac")]).unwrap(), Vec::<String>::new());
        assert_eq!(k.d.read(&k.space()), before, "web keeps its IdentityFile");
        assert_eq!(live_ids(k.d.state().account.as_ref().unwrap()), vec![k.id.clone()], "the setup itself writes the slot under its own id");
        let local = k.d.state().key_slots[&k.id].clone();
        assert_eq!(local.learned_in.as_deref(), Some(k.keys.chain_id.as_str()), "the record now belongs to the new account");
        assert_eq!(local.uploaded_fingerprint.as_deref(), Some(test_keys::PLAIN_FINGERPRINT), "the key this computer chose to upload here");
        assert!(matches!(&local.source, Some(SlotSource::Linked { origin: true, .. })), "the link is left as it was: {local:?}");
        settle(&k.d);
        let theirs = account_on_relay(&k.relay, &k.keys);
        let payload = slot(&theirs, &k.id).expect("the slot is in the new account under the same id");
        assert_eq!((payload.name.as_str(), payload.mode, payload.fingerprint.as_deref()), ("mac", SlotMode::Synced, Some(test_keys::PLAIN_FINGERPRINT)));
        assert_eq!(open_key_secret(&theirs, &k.keys, &k.id).as_deref(), Some(test_keys::plain().as_str()), "and so is its key");
        assert_eq!(live_ids(&theirs), vec![k.id.clone()], "no second slot");
        settle(&k.c);
        assert_eq!(std::fs::read_to_string(k.slot_path(&k.c)).unwrap(), test_keys::plain(), "the other computer lands it at the same path");
        assert_eq!(std::fs::read_to_string(k.slot_path(&k.d)).unwrap(), test_keys::plain(), "and web still reaches it here");
        assert!(k.offered().keys.is_empty(), "nothing is left to ask");
    }

    #[test]
    fn a_linked_slot_from_the_previous_account_is_synced_in_place_into_an_account_joined_later() {
        a_linked_slot_from_the_previous_account_is_offered_and_synced_in_place(true);
    }

    #[test]
    fn a_linked_slot_from_the_previous_account_is_synced_in_place_into_an_account_created_later() {
        a_linked_slot_from_the_previous_account_is_offered_and_synced_in_place(false);
    }

    /// 同上,選「Keep on this computer」:新帳戶裡是同一個 id 的 `own` 插槽、沒有私鑰;這台不算同意上傳;新帳戶的另一台要在那裡挑一把金鑰。
    #[test]
    fn keeping_a_slot_from_the_previous_account_makes_it_an_own_slot_in_place() {
        use crate::sync::slots::tests::account_on_relay;
        use crate::sync::slots::key_secret_key;
        let k = kept_after_a_move(false, true);
        let before = k.d.read(&k.space());
        assert_eq!(setup_keys(&k.d.env(), true, vec![keep(&k.key(), "mac")]).unwrap(), Vec::<String>::new());
        assert_eq!(k.d.read(&k.space()), before);
        assert_eq!(live_ids(k.d.state().account.as_ref().unwrap()), vec![k.id.clone()], "the setup itself writes the slot under its own id");
        let local = k.d.state().key_slots[&k.id].clone();
        assert_eq!((local.learned_in.as_deref(), local.uploaded_fingerprint.as_deref()), (Some(k.keys.chain_id.as_str()), None));
        settle(&k.d);
        let theirs = account_on_relay(&k.relay, &k.keys);
        assert_eq!(slot(&theirs, &k.id).map(|p| (p.name, p.mode, p.fingerprint)), Some(("mac".to_string(), SlotMode::Own, None)));
        assert_eq!(live_ids(&theirs), vec![k.id.clone()], "no second slot");
        assert!(!theirs.sealed.contains_key(&key_secret_key(&k.keys, &k.id)), "no key goes up");
        settle(&k.c);
        let row = crate::sync::dto::overview(&k.c.env()).unwrap().key_slots.into_iter().find(|v| v.id == k.id).expect("the other computer lists the slot");
        assert_eq!(row.status, SlotStatusView::NeedsKey { waiting_for_sync: false });
        assert!(!slot_files::occupied(&k.slot_path(&k.c)));
    }

    /// 之前的帳戶同步來、留在這台的副本(B):候選是那個副本本身(`synced_copy`),名稱是插槽的名稱。「Sync key」把它放進新帳戶(同一個 id、副本的
    /// 指紋與私鑰,這台記下同意上傳的是它),新帳戶的另一台落地它;「Keep on this computer」放成 `own`,沒有私鑰。這台的副本都不動。
    fn a_synced_copy_from_the_previous_account_is_set_up_in_place(sync_it: bool) {
        use crate::sync::slots::tests::account_on_relay;
        use crate::sync::slots::{key_secret_key, open_key_secret};
        let k = kept_after_a_move(true, true);
        let copy = k.slot_path(&k.d);
        let found = k.offered();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        let candidate = &found.keys[0];
        assert_eq!(candidate.path, copy.display().to_string());
        assert_eq!(candidate.kept_slot, Some(KeptSlot { id: k.id.clone(), file_name: k.file.clone(), synced_copy: true }));
        assert_eq!(candidate.default_name, "mac");
        assert_eq!(aliases_and_values(candidate), vec![("web".to_string(), k.value())]);

        let choice = if sync_it { sync(&copy, "mac") } else { keep(&copy, "mac") };
        assert_eq!(setup_keys(&k.d.env(), true, vec![choice]).unwrap(), Vec::<String>::new());
        assert_eq!(live_ids(k.d.state().account.as_ref().unwrap()), vec![k.id.clone()], "the setup itself writes the slot under its own id");
        let local = k.d.state().key_slots[&k.id].clone();
        assert_eq!(local.source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }), "the copy stays as it is");
        assert!(local.copy_from_another_account, "its bytes came from the previous account");
        assert_eq!(local.learned_in.as_deref(), Some(k.keys.chain_id.as_str()));
        assert_eq!(local.uploaded_fingerprint.as_deref(), sync_it.then_some(test_keys::PLAIN_FINGERPRINT));
        settle(&k.d);
        settle(&k.c);
        let theirs = account_on_relay(&k.relay, &k.keys);
        let payload = slot(&theirs, &k.id).expect("the same id in the new account");
        assert_eq!(payload.name, "mac");
        assert_eq!(live_ids(&theirs), vec![k.id.clone()], "no second slot");
        if sync_it {
            assert_eq!((payload.mode, payload.fingerprint.as_deref()), (SlotMode::Synced, Some(test_keys::PLAIN_FINGERPRINT)));
            assert_eq!(open_key_secret(&theirs, &k.keys, &k.id).as_deref(), Some(test_keys::plain().as_str()));
            assert_eq!(std::fs::read_to_string(k.slot_path(&k.c)).unwrap(), test_keys::plain(), "the other computer lands it");
        } else {
            assert_eq!((payload.mode, payload.fingerprint), (SlotMode::Own, None));
            assert!(!theirs.sealed.contains_key(&key_secret_key(&k.keys, &k.id)), "no key goes up");
            assert!(!slot_files::occupied(&k.slot_path(&k.c)));
        }
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain(), "web still reaches the copy here");
    }

    #[test]
    fn a_synced_copy_from_the_previous_account_is_synced_in_place() {
        a_synced_copy_from_the_previous_account_is_set_up_in_place(true);
    }

    #[test]
    fn a_synced_copy_from_the_previous_account_is_kept_in_place_as_an_own_slot() {
        a_synced_copy_from_the_previous_account_is_set_up_in_place(false);
    }

    /// 不提供(候選與「Can't set up automatically」都沒有它,`web` 留給每一輪的維護與 lint):新帳戶裡已經有這個 id 的記錄(還在的或 tombstone),
    /// 或記錄是在新帳戶學到的。直接改記憶體裡的狀態,不跑同步。
    #[test]
    fn a_slot_from_the_previous_account_is_not_offered_once_the_new_account_has_its_id_or_learned_it() {
        use crate::sync::slots::tests::synced_payload;
        let k = kept_after_a_move(false, true);
        assert_eq!(k.offered().keys.len(), 1, "setup: it is offered");
        let chain = k.keys.chain_id.clone();
        let changes: Vec<(&str, Box<dyn Fn(&mut SyncStateV2)>)> = vec![
            ("a live record", Box::new(|s| put_slot(s.account.as_mut().unwrap(), &k.id, Some(&synced_payload("c")), "c", 5))),
            ("a tombstone", Box::new(|s| put_slot(s.account.as_mut().unwrap(), &k.id, None, "c", 5))),
            ("learned in this account", Box::new(|s| s.key_slots.get_mut(&k.id).unwrap().learned_in = Some(chain.clone()))),
        ];
        for (what, change) in changes {
            let saved = k.d.state();
            change(k.d.runtime.core.lock().unwrap().state.as_mut().unwrap());
            let found = k.offered();
            assert!(found.keys.is_empty() && found.unsupported.is_empty(), "{what}: {found:?}");
            k.d.runtime.core.lock().unwrap().state = Some(saved);
            assert_eq!(k.offered().keys.len(), 1, "{what}: offered again once it is back");
        }
    }

    /// 不提供:這台讀不到插槽的私鑰 —— 連到的金鑰檔不是私鑰或不見了,或同步來的副本已經不是記錄裡的那一把(或不見了)。
    #[test]
    fn a_slot_from_the_previous_account_is_not_offered_without_its_key_on_this_computer() {
        let k = kept_after_a_move(false, true);
        assert_eq!(k.offered().keys.len(), 1, "setup: the linked key is offered");
        for (what, text) in [("not a private key", Some("not a key\n")), ("missing", None)] {
            match text {
                Some(text) => std::fs::write(k.key(), text).unwrap(),
                None => std::fs::remove_file(k.key()).unwrap(),
            }
            let found = k.offered();
            assert!(found.keys.is_empty() && found.unsupported.is_empty(), "a linked key that is {what}: {found:?}");
        }

        let k = kept_after_a_move(true, true);
        let copy = k.slot_path(&k.d);
        assert_eq!(k.offered().keys.len(), 1, "setup: the synced copy is offered");
        for (what, text) in [("another key", Some(test_keys::ecdsa())), ("missing", None)] {
            match text {
                Some(text) => std::fs::write(&copy, text).unwrap(),
                None => std::fs::remove_file(&copy).unwrap(),
            }
            let found = k.offered();
            assert!(found.keys.is_empty() && found.unsupported.is_empty(), "a synced copy that is {what}: {found:?}");
        }
    }

    /// 新帳戶裡有別的插槽用了同一個檔名(只差大小寫,macOS 與 Windows 上是同一個檔案):`web` 的插槽路徑分不出指的是哪一個,不提供,列在
    /// 「Can't set up automatically」並說明。
    #[test]
    fn a_slot_from_the_previous_account_whose_file_name_another_slot_uses_is_not_set_up() {
        use crate::sync::slots::tests::own_payload;
        let k = kept_after_a_move(false, true);
        let other = (0u32..).map(|n| format!("{}{n:024x}", &k.id[..8])).find(|id| *id != k.id).unwrap();
        let payload = KeySlotPayload { name: "MAC".into(), ..own_payload("c") };
        assert_eq!(slot_file_name("MAC", &other).to_ascii_lowercase(), k.file, "setup: the same file name but for case");
        mutate(&k.d.env(), |s| {
            put_slot(s.account.as_mut().unwrap(), &other, Some(&payload), "c", 5);
            Ok(())
        })
        .unwrap();
        let found = k.offered();
        assert!(found.keys.is_empty(), "{found:?}");
        assert_eq!(found.unsupported, vec![UnsupportedIdentity { alias: "web".into(), value: k.value(), reason: KEPT_CONTESTED_REASON.into() }]);
    }

    /// 新帳戶裡已經有這把金鑰的 `synced` 插槽(同指紋,另一台發佈的):候選帶著它(`existing_slot`),照常不問、直接沿用 —— `web` 改指到它。連到這台
    /// 金鑰的(A)照舊:那個插槽連到這台的金鑰;之前帳戶的插槽沒有主機用了,下一輪收掉。
    #[test]
    fn a_linked_slot_from_the_previous_account_gives_way_to_the_new_accounts_slot_for_the_same_key() {
        use crate::sync::slots::tests::{device_id, publish, synced_payload};
        let k = kept_after_a_move(false, true);
        let theirs = new_slot_id().unwrap();
        publish(&k.c, &theirs, &synced_payload(&device_id(&k.c)), Some(&test_keys::plain()));
        settle(&k.c);
        settle(&k.d);
        let found = k.offered();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        assert_eq!(found.keys[0].existing_slot.as_deref(), Some(theirs.as_str()));
        assert_eq!(found.keys[0].kept_slot.as_ref().map(|s| s.id.as_str()), Some(k.id.as_str()));

        let before = k.d.read(&k.space());
        assert_eq!(setup_keys(&k.d.env(), true, vec![reuse(&k.key(), &theirs)]).unwrap(), vec!["web".to_string()]);
        let file = slot_file_name("id_mac", &theirs);
        assert_eq!(k.d.read(&k.space()), before.replace(&k.value(), &slot_value(&file)), "web now uses the new account's slot");
        let path = home(&k.d).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::plain());
        assert!(matches!(&k.d.state().key_slots[&theirs].source, Some(SlotSource::Linked { path, .. }) if *path == k.key().display().to_string()));
        settle(&k.d);
        assert!(!k.d.state().key_slots.contains_key(&k.id), "the old slot no host uses is put away");
        assert!(!slot_files::occupied(&k.slot_path(&k.d)));
        assert_eq!(live_slots(k.d.state().account.as_ref().unwrap()).len(), 1, "no slot of the old account went up");
    }

    /// 同上,這台的是之前的帳戶同步來的副本(B):新帳戶的插槽不連到那個舊副本(之後刪掉舊副本會讓它斷掉)—— 先把帳戶裡的金鑰落地到新帳戶的插槽,
    /// `web` 才改指過去。之後刪掉舊副本,新帳戶的插槽照常能用。
    #[test]
    fn reusing_the_new_accounts_slot_never_links_it_to_a_synced_copy_from_the_previous_account() {
        use crate::sync::slots::tests::{device_id, publish, synced_payload};
        let k = kept_after_a_move(true, true);
        let theirs = new_slot_id().unwrap();
        publish(&k.c, &theirs, &synced_payload(&device_id(&k.c)), Some(&test_keys::plain()));
        settle(&k.c);
        settle(&k.d);
        let copy = k.slot_path(&k.d);
        let found = k.offered();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        assert_eq!((found.keys[0].path.as_str(), found.keys[0].existing_slot.as_deref()), (copy.to_str().unwrap(), Some(theirs.as_str())));

        let before = k.d.read(&k.space());
        assert_eq!(setup_keys(&k.d.env(), true, vec![reuse(&copy, &theirs)]).unwrap(), vec!["web".to_string()]);
        let file = slot_file_name("id_mac", &theirs);
        let path = home(&k.d).join(SLOT_DIR).join(&file);
        assert_landed_from_the_account(&k, &theirs, &path);
        assert_eq!(k.d.read(&k.space()), before.replace(&k.value(), &slot_value(&file)), "web now uses the new account's slot");

        settle(&k.d);
        assert_eq!(k.d.state().key_slots[&theirs].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
        crate::sync::slots::delete_copy(&k.d.env(), &k.id).unwrap();
        assert!(!copy.exists(), "the old copy no host uses can go");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::plain(), "and the new account's slot keeps its key");
    }

    /// 直接指到金鑰檔的主機與指到之前帳戶插槽的主機,用的是同一把金鑰:一個候選(先遇到的是直接指到金鑰檔的主機,名稱仍是插槽的名稱)。「Sync key」
    /// 把直接指到金鑰檔的主機改指到那個插槽,`web` 不動。
    #[test]
    fn a_host_using_the_key_file_joins_the_slot_from_the_previous_account() {
        let k = kept_after_a_move(false, true);
        let space = k.space();
        let moved = k.d.read(&space);
        k.d.save_in_app(&space, &format!("Host db\n  IdentityFile ~/.ssh/id_mac\n{moved}"));
        let found = k.offered();
        assert_eq!(found.keys.len(), 1, "one key, one question: {found:?}");
        let candidate = &found.keys[0];
        assert_eq!(aliases_and_values(candidate), vec![("db".to_string(), "~/.ssh/id_mac".to_string()), ("web".to_string(), k.value())]);
        assert_eq!(candidate.kept_slot.as_ref().map(|s| s.id.as_str()), Some(k.id.as_str()));
        assert_eq!(candidate.default_name, "mac", "the slot's name even though db came first");

        assert_eq!(setup_keys(&k.d.env(), true, vec![sync(&k.key(), "mac")]).unwrap(), vec!["db".to_string()]);
        assert_eq!(k.d.read(&space), format!("Host db\n  IdentityFile {}\n{moved}", k.value()), "db now uses the slot, web is as it was");
        assert_eq!(live_slots(k.d.state().account.as_ref().unwrap()).iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), vec![k.id.as_str()]);
    }

    /// 之前的帳戶裡同一把金鑰有兩個插槽,兩台主機各用一個:一個候選,先遇到的那個插槽就地放進新帳戶,另一個插槽的主機改指過來。
    #[test]
    fn hosts_of_every_slot_from_the_previous_account_for_one_key_move_to_the_first_one() {
        use crate::sync::slots::tests::{create_slot_on, move_to_another_account};
        let (relay, clock, a, _b, _words, personal) = pair();
        let (first, first_file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let (second, second_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        a.save_in_app(
            &a.space_path(&personal),
            &format!("Host web\n  IdentityFile ~/.ssh/sshelter/keys/{first_file}\nHost api\n  IdentityFile ~/.ssh/sshelter/keys/{second_file}\n"),
        );
        settle(&a);
        let c = TestDevice::new("c", &relay, &clock);
        let (next, _keys) = move_to_another_account(&a, &c, false);
        let report = crate::sync::migrate::move_hosts_into_space(&a.env(), true, vec!["web".into(), "api".into()], &next, false).unwrap();
        assert_eq!(report.moved.len(), 2);
        settle(&a);

        let found = key_candidates(&a.env()).unwrap();
        assert_eq!(found.keys.len(), 1, "one key, one question: {found:?}");
        let candidate = &found.keys[0];
        let file_of = |h: &CandidateHost| crate::sync::slot_rules::slot_file_of_value(&h.value).unwrap();
        let ((adopted, adopted_file), (_, other_file)) = if file_of(&candidate.hosts[0]) == first_file {
            ((first, first_file), (second, second_file))
        } else {
            ((second, second_file), (first, first_file))
        };
        assert_eq!(candidate.kept_slot.as_ref().map(|s| (s.id.as_str(), s.file_name.as_str())), Some((adopted.as_str(), adopted_file.as_str())), "the first one in scan order");
        let other_host = candidate.hosts[1].alias.clone();

        assert_eq!(setup_keys(&a.env(), true, vec![sync(&a.ssh_dir().join("id_mac"), "id_mac")]).unwrap(), vec![other_host]);
        let text = a.read(&a.space_path(&next));
        assert_eq!(text.matches(&format!("IdentityFile {}", slot_value(&adopted_file))).count(), 2, "both hosts use the slot that went in: {text}");
        assert!(!text.contains(other_file.as_str()), "{text}");
        assert_eq!(live_slots(a.state().account.as_ref().unwrap()).iter().map(|(id, _)| id.clone()).collect::<Vec<_>>(), vec![adopted]);
    }

    /// 掃描之後、提交之前 —— `adopt_slot` 讀時鐘的那一刻,在它讀金鑰與提交之前 —— 做一件事(改狀態,或換掉檔案),只做一次(同
    /// `FrozenWhenCommitting`)。時鐘本身照常走。
    struct ChangedWhenCommitting<'a> {
        device: &'a TestDevice,
        change: &'a (dyn Fn(&mut SyncStateV2) + Send + Sync),
        done: std::sync::atomic::AtomicBool,
    }

    impl crate::sync::env::Clock for ChangedWhenCommitting<'_> {
        fn now_ms(&self) -> u64 {
            if !self.done.swap(true, std::sync::atomic::Ordering::SeqCst) {
                (self.change)(self.device.runtime.core.lock().unwrap().state.as_mut().unwrap());
            }
            crate::sync::env::Clock::now_ms(self.device.clock.as_ref())
        }
    }

    /// 掃描與提交之間狀態變了(`change`):`setup_keys` 回 `message`,除了那個變化什麼都沒寫(狀態、主機、插槽目錄)。之後把記憶體裡的狀態放回原樣
    /// (變化只在記憶體裡,拒絕的提交沒有存檔)。
    fn refused_when_changed_before_the_commit(k: &Kept, choice: KeyChoice, change: &(dyn Fn(&mut SyncStateV2) + Send + Sync), message: &str) {
        let space = k.space();
        let (saved, hosts) = (k.d.state(), k.d.read(&space));
        let mut expected = saved.clone();
        change(&mut expected);
        let listing = || -> std::collections::BTreeSet<PathBuf> { std::fs::read_dir(home(&k.d).join(SLOT_DIR)).unwrap().map(|e| e.unwrap().path()).collect() };
        let keys_dir = listing();
        let racing = ChangedWhenCommitting { device: &k.d, change, done: std::sync::atomic::AtomicBool::new(false) };
        let mut env = k.d.env();
        env.clock = &racing;
        assert_eq!(setup_keys(&env, true, vec![choice]).unwrap_err().to_string(), message);
        assert!(racing.done.load(std::sync::atomic::Ordering::SeqCst), "setup: the change happened");
        assert_eq!(k.d.state(), expected, "nothing but the change itself is in the state");
        assert_eq!(k.d.read(&space), hosts, "web is not rewritten");
        assert_eq!(listing(), keys_dir, "and nothing in the slot directory");
        k.d.runtime.core.lock().unwrap().state = Some(saved);
    }

    /// 掃描之後、讀它之前,之前的帳戶同步來的副本被換成另一把金鑰:「Sync key」不上傳那一把,說明它變了,什麼都不寫。
    #[test]
    fn a_synced_copy_from_the_previous_account_replaced_after_the_scan_is_not_uploaded() {
        let k = kept_after_a_move(true, true);
        let copy = k.slot_path(&k.d);
        let (before, hosts) = (k.d.state(), k.d.read(&k.space()));
        let swap = |_: &mut SyncStateV2| std::fs::write(&copy, test_keys::ecdsa()).unwrap();
        let racing = ChangedWhenCommitting { device: &k.d, change: &swap, done: std::sync::atomic::AtomicBool::new(false) };
        let mut env = k.d.env();
        env.clock = &racing;
        assert_eq!(setup_keys(&env, true, vec![sync(&copy, "mac")]).unwrap_err().to_string(), KEPT_CHANGED_MESSAGE);
        assert!(racing.done.load(std::sync::atomic::Ordering::SeqCst), "setup: the copy was replaced");
        assert_eq!(k.d.state(), before, "nothing is written");
        assert_eq!(k.d.read(&k.space()), hosts);
    }

    /// 掃描之後、提交之前,那個插槽變了 —— 帳戶裡出現了它的記錄(還在的或 tombstone)、記錄改成在這個帳戶學到的、來源變了、帳戶裡有別的插槽用了同一個
    /// 檔名、連結收起來了 ——:不放進帳戶,說明它變了,什麼都不寫。帳戶本身換了、或被擋下:照 `account_still_ready` 拒絕。
    #[test]
    fn a_slot_from_the_previous_account_that_changes_before_the_commit_is_not_set_up() {
        use crate::sync::account::{FROZEN_MESSAGE, NOT_JOINED_MESSAGE};
        use crate::sync::slots::tests::{own_payload, synced_payload};
        let k = kept_after_a_move(false, true);
        let (id, chain) = (k.id.clone(), k.keys.chain_id.clone());
        let clash = (0u32..).map(|n| format!("{}{n:024x}", &id[..8])).find(|other| *other != id).unwrap();
        let clash_payload = KeySlotPayload { name: "MAC".into(), ..own_payload("c") };
        let live = |s: &mut SyncStateV2| put_slot(s.account.as_mut().unwrap(), &id, Some(&synced_payload("c")), "c", 5);
        let tombstone = |s: &mut SyncStateV2| put_slot(s.account.as_mut().unwrap(), &id, None, "c", 5);
        let learned = |s: &mut SyncStateV2| s.key_slots.get_mut(&id).unwrap().learned_in = Some(chain.clone());
        let source = |s: &mut SyncStateV2| {
            if let Some(SlotSource::Linked { fingerprint, .. }) = s.key_slots.get_mut(&id).unwrap().source.as_mut() {
                *fingerprint = None;
            }
        };
        let contested = |s: &mut SyncStateV2| put_slot(s.account.as_mut().unwrap(), &clash, Some(&clash_payload), "c", 5);
        let parked = |s: &mut SyncStateV2| s.key_slots.get_mut(&id).unwrap().parked = true;
        let changes: [&(dyn Fn(&mut SyncStateV2) + Send + Sync); 6] = [&live, &tombstone, &learned, &source, &contested, &parked];
        for change in changes {
            refused_when_changed_before_the_commit(&k, sync(&k.key(), "mac"), change, KEPT_CHANGED_MESSAGE);
        }
        refused_when_changed_before_the_commit(&k, keep(&k.key(), "mac"), &live, KEPT_CHANGED_MESSAGE);

        let other_account = |s: &mut SyncStateV2| s.account = Some(crate::sync::state_v2::AccountState::new(&"e".repeat(64)));
        refused_when_changed_before_the_commit(&k, sync(&k.key(), "mac"), &other_account, NOT_JOINED_MESSAGE);
        let frozen = |s: &mut SyncStateV2| s.account.as_mut().unwrap().frozen = Some(crate::sync::state_v2::FreezeInfo { detected_at_ms: 1, markers: Vec::new() });
        refused_when_changed_before_the_commit(&k, keep(&k.key(), "mac"), &frozen, FROZEN_MESSAGE);
        assert_eq!(k.offered().keys[0].kept_slot.as_ref().map(|s| s.id.as_str()), Some(id.as_str()), "untouched: still offered");
    }

    // ── 修正第 1 輪:同步副本的同意、沿用前先落地、收起來的連結、不在候選裡的決定 ─────────────────────────────

    /// 新帳戶的插槽 `id` 在這台落地了帳戶裡的金鑰(`reuse_slot` 的例外:不連到插槽目錄裡的檔案):`path` 是一般檔案、是那把金鑰,旁邊有它的 `.pub`;
    /// 記錄是同步來的副本(來自這個帳戶,不是之前的帳戶的副本),在這個帳戶學到的。
    fn assert_landed_from_the_account(k: &Kept, id: &str, path: &Path) {
        assert!(!std::fs::symlink_metadata(path).unwrap().file_type().is_symlink(), "nothing is linked to a file in the slot directory");
        assert_eq!(std::fs::read_to_string(path).unwrap(), test_keys::plain(), "the account's key is in the slot");
        assert_eq!(std::fs::read_to_string(public_path(path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        let local = k.d.state().key_slots[id].clone();
        assert_eq!(local.source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }), "{local:?}");
        assert!(!local.copy_from_another_account && !local.parked, "{local:?}");
        assert_eq!(local.learned_in.as_deref(), Some(k.keys.chain_id.as_str()));
    }

    /// 帳戶掉了這個插槽(沒有 SP3 的電腦更換同步碼時沒帶 `keyslot`/`key`;重新加入之後記錄照樣算這個帳戶學到的):在這台狀態的副本上拿掉兩筆記錄,
    /// 跑一次插槽維護。回傳維護之後的帳戶。
    fn after_the_account_loses_the_slot(k: &Kept) -> crate::sync::state_v2::AccountState {
        use crate::sync::record::{record_key, RecordKind};
        use crate::sync::slots::{config_slot_uses, key_secret_key, reconcile};
        let mut state = k.d.state();
        let account = state.account.as_mut().unwrap();
        account.records.remove(&record_key(RecordKind::KeySlot, &k.id));
        account.sealed.remove(&key_secret_key(&k.keys, &k.id));
        reconcile(&mut state, &k.keys, &home(&k.d), &config_slot_uses(&k.d.env()).unwrap(), 1_000);
        state.account.unwrap()
    }

    /// 帳戶裡的成員把插槽 `k.id` 改成 `synced`(名稱不變,同一個插槽檔名)、填上 `payload` 的公鑰與指紋 —— 指紋在 `device.slots` 看得到 ——,`secret`
    /// 是一起寫的私鑰(可以沒有)。成員那台與這台都同步完。
    fn a_member_makes_it_synced(k: &Kept, payload: KeySlotPayload, secret: Option<&str>) {
        use crate::sync::slots::tests::publish;
        publish(&k.c, &k.id, &KeySlotPayload { name: "mac".into(), ..payload }, secret);
        settle(&k.c);
        settle(&k.d);
    }

    /// 之前的帳戶同步來的副本(B)就地放進新帳戶之後,帳戶掉了這個插槽(帳戶裡的成員先把它改成 `synced`、填上這把金鑰的公開指紋):補寫私鑰只在這台的使用者
    /// 在這裡選了「Sync key」的時候。選「Keep on this computer」的,副本的位元組來自之前的帳戶,不是這個帳戶 —— 不上傳。
    fn a_copy_set_up_in_place_is_written_back_only_where_the_user_synced_it(sync_it: bool) {
        use crate::sync::slots::tests::{device_id, synced_payload};
        use crate::sync::slots::{key_secret_key, open_key_secret};
        let k = kept_after_a_move(true, true);
        let copy = k.slot_path(&k.d);
        let choice = if sync_it { sync(&copy, "mac") } else { keep(&copy, "mac") };
        setup_keys(&k.d.env(), true, vec![choice]).unwrap();
        settle(&k.d);
        assert!(k.d.state().key_slots[&k.id].copy_from_another_account, "the copy came from the previous account");
        a_member_makes_it_synced(&k, synced_payload(&device_id(&k.c)), None);

        let account = after_the_account_loses_the_slot(&k);
        assert!(slot(&account, &k.id).is_some(), "the keyslot is written again");
        if sync_it {
            assert_eq!(open_key_secret(&account, &k.keys, &k.id).as_deref(), Some(test_keys::plain().as_str()), "the user synced it here");
        } else {
            assert!(!account.sealed.contains_key(&key_secret_key(&k.keys, &k.id)), "a copy kept on this computer is never uploaded");
        }
    }

    #[test]
    fn a_copy_kept_from_the_previous_account_is_not_uploaded_when_the_account_loses_its_slot() {
        a_copy_set_up_in_place_is_written_back_only_where_the_user_synced_it(false);
    }

    #[test]
    fn a_copy_synced_from_the_previous_account_is_written_back_when_the_account_loses_its_slot() {
        a_copy_set_up_in_place_is_written_back_only_where_the_user_synced_it(true);
    }

    /// 副本換成帳戶裡的金鑰之後(插槽空了、下一輪落地;或「Use the synced key」),它的位元組就是這個帳戶的了:不再標成之前的帳戶的副本,帳戶掉了這個
    /// 插槽時照常補寫私鑰(同 N1 之前,同步來的副本)。
    #[test]
    fn a_copy_replaced_by_the_accounts_key_is_written_back_like_any_synced_copy() {
        use crate::sync::slots::tests::{device_id, ecdsa_payload, synced_payload};
        use crate::sync::slots::open_key_secret;
        for use_synced in [false, true] {
            let k = kept_after_a_move(true, true);
            let copy = k.slot_path(&k.d);
            setup_keys(&k.d.env(), true, vec![keep(&copy, "mac")]).unwrap();
            settle(&k.d);
            assert!(k.d.state().key_slots[&k.id].copy_from_another_account, "setup: the copy came from the previous account");
            let landed = if use_synced {
                // 成員同步了另一把金鑰:這台按「Use the synced key」。
                a_member_makes_it_synced(&k, ecdsa_payload(&device_id(&k.c)), Some(&test_keys::ecdsa()));
                crate::sync::slots::use_synced(&k.d.env(), &k.id).unwrap();
                test_keys::ecdsa()
            } else {
                // 成員同步了同一把金鑰;這台的副本被刪掉,下一輪落地帳戶裡的那一份。
                a_member_makes_it_synced(&k, synced_payload(&device_id(&k.c)), Some(&test_keys::plain()));
                std::fs::remove_file(&copy).unwrap();
                std::fs::remove_file(public_path(&copy)).unwrap();
                settle(&k.d);
                test_keys::plain()
            };
            let local = k.d.state().key_slots[&k.id].clone();
            assert_eq!(std::fs::read_to_string(&copy).unwrap(), landed, "use_synced: {use_synced}");
            assert!(!local.copy_from_another_account, "the bytes are this account's now (use_synced: {use_synced}): {local:?}");
            let account = after_the_account_loses_the_slot(&k);
            assert_eq!(open_key_secret(&account, &k.keys, &k.id).as_deref(), Some(landed.as_str()), "use_synced: {use_synced}");
        }
    }

    /// 新帳戶裡同一把金鑰的 `synced` 插槽沒有 `key`(私鑰還沒到,或成員只寫了 `keyslot`):之前的帳戶同步來的副本不沿用它 —— 沿用時要先落地帳戶裡的金鑰,
    /// 沒有就只會讓能連線的 `web` 改指到空的插槽 —— 改成問要不要把副本就地放進新帳戶(新帳戶裡同一把金鑰因此有兩個插槽)。
    #[test]
    fn a_copy_from_the_previous_account_does_not_reuse_a_slot_whose_key_the_account_lacks() {
        use crate::sync::slots::tests::{device_id, publish, synced_payload};
        let k = kept_after_a_move(true, true);
        let theirs = new_slot_id().unwrap();
        publish(&k.c, &theirs, &synced_payload(&device_id(&k.c)), None);
        settle(&k.c);
        settle(&k.d);
        let found = k.offered();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        assert_eq!(found.keys[0].existing_slot, None, "a slot whose key isn't in the account can't be landed");
        assert_eq!(found.keys[0].kept_slot.as_ref().map(|s| s.id.as_str()), Some(k.id.as_str()), "so the dialog asks");
        let copy = k.slot_path(&k.d);
        refused(&k.d, OTHER_SLOT_MESSAGE, || setup_keys(&k.d.env(), true, vec![reuse(&copy, &theirs)]).map(|_| ()));

        assert_eq!(setup_keys(&k.d.env(), true, vec![sync(&copy, "mac")]).unwrap(), Vec::<String>::new());
        let mut ids = live_ids(k.d.state().account.as_ref().unwrap());
        ids.sort();
        let mut expected = vec![k.id.clone(), theirs.clone()];
        expected.sort();
        assert_eq!(ids, expected, "two slots for the same key");
    }

    /// 沿用新帳戶的插槽時,帳戶裡的金鑰在主機改寫之前就落地了:改寫撞到 `Conflict` 時,插槽已經就位、記錄是同步來的副本;再來一次(這台已經握著它)就把
    /// 主機改寫完。
    #[test]
    fn a_reused_slot_gets_the_accounts_key_before_any_host_is_rewritten() {
        use crate::sync::slots::tests::{device_id, publish, synced_payload};
        let k = kept_after_a_move(true, true);
        let theirs = new_slot_id().unwrap();
        publish(&k.c, &theirs, &synced_payload(&device_id(&k.c)), Some(&test_keys::plain()));
        settle(&k.c);
        settle(&k.d);
        let copy = k.slot_path(&k.d);
        let space = k.space();
        let edited = format!("{}\n# edited elsewhere\n", k.d.read(&space));
        k.d.write_externally(&space, &edited);
        assert!(matches!(setup_keys(&k.d.env(), true, vec![reuse(&copy, &theirs)]), Err(AppError::Conflict(_))));
        let path = home(&k.d).join(SLOT_DIR).join(slot_file_name("id_mac", &theirs));
        assert_landed_from_the_account(&k, &theirs, &path);
        assert_eq!(k.d.read(&space), edited, "web is not rewritten yet");

        assert_eq!(k.offered().keys[0].existing_slot.as_deref(), Some(theirs.as_str()));
        assert_eq!(setup_keys(&k.d.env(), true, vec![reuse(&copy, &theirs)]).unwrap(), vec!["web".to_string()]);
        assert!(k.d.read(&space).contains(&slot_value(&slot_file_name("id_mac", &theirs))));
    }

    /// 沿用新帳戶的插槽、要落地帳戶裡的金鑰,插槽路徑上卻有使用者自己的檔案:不覆蓋、不改寫主機、不記錄,說明擋路的檔案。
    #[test]
    fn a_reused_slot_whose_path_is_taken_is_not_landed_and_no_host_is_rewritten() {
        use crate::sync::slots::tests::{device_id, publish, synced_payload};
        let k = kept_after_a_move(true, true);
        let theirs = new_slot_id().unwrap();
        publish(&k.c, &theirs, &synced_payload(&device_id(&k.c)), Some(&test_keys::plain()));
        settle(&k.c);
        settle(&k.d);
        let path = home(&k.d).join(SLOT_DIR).join(slot_file_name("id_mac", &theirs));
        std::fs::write(&path, "mine").unwrap();
        let copy = k.slot_path(&k.d);
        refused(&k.d, &in_the_way_message(&path), || setup_keys(&k.d.env(), true, vec![reuse(&copy, &theirs)]).map(|_| ()));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "mine");
        assert!(!k.d.state().key_slots.contains_key(&theirs));
    }

    /// 要沿用的 `synced` 插槽是因為這台曾經把它連到這份副本才被建議的(使用者在 Keys 為它挑過這個檔案,後來連結收起來了),帳戶裡它同步的卻是另一把金鑰:
    /// 落地那一把會讓 `web` 悄悄換成別的金鑰 —— 拒絕,什麼都不落地、不改寫。
    #[test]
    fn a_reused_slot_whose_synced_key_is_another_key_is_not_landed() {
        use crate::sync::slots::tests::{device_id, ecdsa_payload, publish};
        let k = kept_after_a_move(true, true);
        let theirs = new_slot_id().unwrap();
        publish(&k.c, &theirs, &ecdsa_payload(&device_id(&k.c)), Some(&test_keys::ecdsa()));
        settle(&k.c);
        settle(&k.d);
        let copy = k.slot_path(&k.d);
        let file = slot_file_name("id_mac", &theirs);
        mutate(&k.d.env(), |s| {
            let payload = s.account.as_ref().and_then(|a| slot(a, &theirs));
            s.key_slots.insert(
                theirs.clone(),
                LocalSlot {
                    file_name: file.clone(),
                    source: Some(SlotSource::Linked { path: copy.display().to_string(), link: LinkKind::Symlink, fingerprint: None, origin: false }),
                    last_error: None,
                    asked: true,
                    payload,
                    uploaded_fingerprint: None,
                    parked: true,
                    learned_in: Some(k.keys.chain_id.clone()),
                    copy_from_another_account: false,
                },
            );
            Ok(())
        })
        .unwrap();
        let found = k.offered();
        assert_eq!(found.keys[0].existing_slot.as_deref(), Some(theirs.as_str()), "setup: suggested because this computer linked it to the copy");
        refused(&k.d, OTHER_SLOT_MESSAGE, || setup_keys(&k.d.env(), true, vec![reuse(&copy, &theirs)]).map(|_| ()));
        assert!(!slot_files::occupied(&home(&k.d).join(SLOT_DIR).join(&file)));
    }

    /// 之前的帳戶留下的插槽連到插槽目錄裡的一個檔案(例如使用者在之前的帳戶為它挑了別的插槽的副本),不是同步來的副本:沿用新帳戶的插槽時一樣不連到它,
    /// 落地帳戶裡的金鑰(看的是候選的金鑰檔在不在插槽目錄裡,不是之前的帳戶留下的是哪一種插槽)。
    #[test]
    fn a_kept_link_to_a_file_in_the_slot_directory_is_not_linked_to_by_a_reused_slot() {
        use crate::sync::slots::tests::{device_id, publish, synced_payload};
        let k = kept_after_a_move(false, true);
        let theirs = new_slot_id().unwrap();
        publish(&k.c, &theirs, &synced_payload(&device_id(&k.c)), Some(&test_keys::plain()));
        settle(&k.c);
        settle(&k.d);
        let keys_dir = home(&k.d).join(SLOT_DIR);
        let spare = keys_dir.join("spare");
        std::fs::write(&spare, test_keys::plain()).unwrap();
        slot_files::link(&spare, &k.slot_path(&k.d)).unwrap();
        mutate(&k.d.env(), |s| {
            if let Some(SlotSource::Linked { path, .. }) = s.key_slots.get_mut(&k.id).unwrap().source.as_mut() {
                *path = spare.display().to_string();
            }
            Ok(())
        })
        .unwrap();
        let found = k.offered();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        assert_eq!(found.keys[0].path, spare.display().to_string());
        assert_eq!(found.keys[0].kept_slot.as_ref().map(|s| s.synced_copy), Some(false), "a link, not a synced copy");
        assert_eq!(found.keys[0].existing_slot.as_deref(), Some(theirs.as_str()));

        assert_eq!(setup_keys(&k.d.env(), true, vec![reuse(&spare, &theirs)]).unwrap(), vec!["web".to_string()]);
        assert_landed_from_the_account(&k, &theirs, &keys_dir.join(slot_file_name("id_mac", &theirs)));
    }

    /// 之前的帳戶留下的插槽,連結收起來了(插槽路徑上是使用者自己的檔案):不是可以就地放進帳戶的插槽。直接指到同一把金鑰的 `db` 是一般的候選 —— 設定時
    /// 建立新的插槽,不會被改指到那個檔案。
    #[test]
    fn a_parked_slot_from_the_previous_account_is_not_offered() {
        let k = kept_after_a_move(false, true);
        let space = k.space();
        let moved = k.d.read(&space);
        k.d.save_in_app(&space, &format!("Host db\n  IdentityFile ~/.ssh/id_mac\n{moved}"));
        std::fs::remove_file(k.slot_path(&k.d)).unwrap();
        std::fs::write(k.slot_path(&k.d), "mine").unwrap();
        settle(&k.d);
        assert!(k.d.state().key_slots[&k.id].parked, "setup: the user's file is in the way, so the link is put away");

        let found = k.offered();
        assert_eq!(found.keys.len(), 1, "{found:?}");
        assert_eq!((found.keys[0].kept_slot.as_ref(), found.keys[0].default_name.as_str()), (None, "id_mac"));
        assert_eq!(aliases_and_values(&found.keys[0]), vec![("db".to_string(), "~/.ssh/id_mac".to_string())]);
        assert_eq!(setup_keys(&k.d.env(), true, vec![sync(&k.key(), "id_mac")]).unwrap(), vec!["db".to_string()]);
        let made = live_ids(k.d.state().account.as_ref().unwrap());
        assert!(made.len() == 1 && made[0] != k.id, "a new slot: {made:?}");
        assert!(k.d.read(&space).starts_with(&format!("Host db\n  IdentityFile {}\n", slot_value(&slot_file_name("id_mac", &made[0])))));
        assert_eq!(std::fs::read_to_string(k.slot_path(&k.d)).unwrap(), "mine", "the user's file is not touched");
    }

    /// 「Sync key」或「Keep on this computer」的那把金鑰已經不在候選裡(期間被設定好了):說明,什麼都不動 —— 一起送來、還在候選裡的決定也不做。沿用照舊略過。
    #[test]
    fn a_sync_or_keep_choice_for_a_key_that_is_no_longer_listed_changes_nothing() {
        let (a, personal) = device("# main\n");
        let mac = put_key(&a, "id_mac", &test_keys::plain());
        let work = put_key(&a, "id_work", &test_keys::ecdsa());
        let space = a.space_path(&personal);
        a.save_in_app(&space, "Host web\n  IdentityFile ~/.ssh/id_mac\nHost jump\n  IdentityFile ~/.ssh/id_work\n");
        setup_keys(&a.env(), true, vec![keep(&mac, "id_mac")]).unwrap();
        let id = live_ids(a.state().account.as_ref().unwrap())[0].clone();
        assert!(key_candidates(&a.env()).unwrap().keys.iter().all(|k| k.path != mac.display().to_string()), "setup: id_mac is set up");

        for choice in [sync(&mac, "id_mac"), keep(&mac, "again")] {
            refused(&a, SET_UP_MEANWHILE_MESSAGE, || setup_keys(&a.env(), true, vec![choice]).map(|_| ()));
        }
        refused(&a, SET_UP_MEANWHILE_MESSAGE, || setup_keys(&a.env(), true, vec![keep(&work, "id_work"), sync(&mac, "id_mac")]).map(|_| ()));
        assert_eq!(setup_keys(&a.env(), true, vec![reuse(&mac, &id)]).unwrap(), Vec::<String>::new(), "a stale reuse is still skipped");
    }
}
