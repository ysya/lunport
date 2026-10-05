//! SP3:還沒設定的金鑰(候選)與建立插槽(spec `docs/superpowers/specs/2026-10-05-sp3-key-slots-design.md` §5、§6.1、
//! §7.1)。主機的改寫只換 `IdentityFile` 那一行的值,經 `persist_file` 寫回(存檔 hook 照一般修改上傳)。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::commands::persist_file;
use crate::config::model::{Item, SshConfigDoc};
use crate::error::AppError;
use crate::sync::crypto::ChainKeys;
use crate::sync::env::SyncEnv;
use crate::sync::merge::space_entry;
use crate::sync::migrate::{refuse_while_sync_inactive, selected_space_files};
use crate::sync::runtime::mutate;
use crate::sync::slot_files::{self, LinkKind};
use crate::sync::slot_rules::{
    default_slot_name, inspect_private_key, new_slot_id, resolve_identity_value, slot_file_name, slot_value, valid_slot_name,
    IdentityTarget, KeySlotPayload, SlotMode, SLOT_DIR, SLOT_SCHEMA,
};
use crate::sync::slots::{
    contested_and_not_held, in_the_way_message, live_slots, local_key_fingerprint, put_key_secret, put_slot, slot,
    write_linked_public, CONTESTED_MESSAGE,
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
    /// 這台電腦上金鑰檔的完整路徑(`IdentityFile` 解析出來的)。
    pub path: String,
    pub default_name: String,
    pub fingerprint: Option<String>,
    pub has_passphrase: Option<bool>,
    /// 不能同步的原因(只能 Keep on this computer);null = 可以同步。
    pub unsyncable: Option<String>,
    /// 已經有這把金鑰的插槽:這台建立或挑過、連到同一個檔案的,或帳戶裡同指紋的 `synced` 插槽(spec §6.1 第 1 步:直接
    /// 沿用,不再詢問)。和帳戶裡另一個插槽同檔名、這台又沒有握著的插槽在這台不能用,不列在這裡。
    pub existing_slot: Option<String>,
    pub hosts: Vec<CandidateHost>,
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

/// 存在的私鑰檔(第一行是 `-----BEGIN … PRIVATE KEY-----`;大於 64 KiB 的不讀)。
fn is_private_key_file(path: &Path) -> bool {
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
/// 同檔名、這台又沒有握著的插槽(`contested_and_not_held`)在這台不能用,不建議沿用。
fn existing_slot_for(state: &SyncStateV2, key: &Path, fingerprint: Option<&str>) -> Option<String> {
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
    live.into_iter()
        .find(|(id, p)| p.mode == SlotMode::Synced && p.fingerprint.as_deref() == Some(fingerprint) && usable(id))
        .map(|(id, _)| id)
}

fn candidate_for(key: &Path, state: &SyncStateV2) -> KeyCandidate {
    let text = std::fs::read_to_string(key).unwrap_or_default();
    let inspected = inspect_private_key(&text);
    let fingerprint = inspected.as_ref().ok().map(|f| f.fingerprint.clone()).or_else(|| local_key_fingerprint(key));
    KeyCandidate {
        path: key.display().to_string(),
        default_name: default_slot_name(key.file_name().and_then(|n| n.to_str()).unwrap_or("key")),
        existing_slot: existing_slot_for(state, key, fingerprint.as_deref()),
        fingerprint,
        has_passphrase: inspected.as_ref().ok().map(|f| f.has_passphrase),
        unsyncable: inspected.err().map(|e| e.message().to_string()),
        hosts: Vec::new(),
    }
}

/// 掃描 doc 裡這台勾選的 space 檔(只讀:不改 doc 與狀態,但會讀金鑰檔;呼叫端持有 doc 鎖)。
fn scan(doc: &SshConfigDoc, space_files: &[(String, PathBuf)], state: &SyncStateV2, home: &Path) -> KeyCandidates {
    let counts = alias_counts(doc);
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
                match resolve_identity_value(&d.value, home) {
                    IdentityTarget::Slot(_) => {}
                    IdentityTarget::Unsupported(reason) => unsupported.push(UnsupportedIdentity {
                        alias: alias.clone(),
                        value: d.value.clone(),
                        reason: reason.to_string(),
                    }),
                    IdentityTarget::File(key) => {
                        if !is_private_key_file(&key) {
                            continue; // 不存在或不是私鑰:交給 lint
                        }
                        let index = match keys.iter().position(|c| same_file(Path::new(&c.path), &key)) {
                            Some(i) => i,
                            None => {
                                keys.push(candidate_for(&key, state));
                                keys.len() - 1
                            }
                        };
                        keys[index].hosts.push(CandidateHost {
                            alias: alias.clone(),
                            space_name: space_name.clone(),
                            value: d.value.clone(),
                            locked: lock.clone(),
                        });
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

/// 這台勾選、第一輪同步已經跑完(`ready_space_files`)的 space 檔裡,指到本機私鑰、還沒有插槽的 `IdentityFile`(依金鑰檔分組),以及無法自動設定的值。
/// 第一輪還沒跑完的 space 的主機既不是候選、也不列在無法自動設定的清單裡。鎖:先短暫拿 core 取快照,再拿 doc。
pub fn key_candidates(env: &SyncEnv) -> Result<KeyCandidates, AppError> {
    let home = home_of(env)?;
    let Some(state) = env.runtime.core.lock().unwrap().state.clone() else { return Ok(KeyCandidates::default()) };
    if state.account.is_none() {
        return Ok(KeyCandidates::default());
    }
    let space_files = ready_space_files(env);
    let doc_lock = env.doc.lock().unwrap();
    let Some(doc) = doc_lock.as_ref() else { return Ok(KeyCandidates::default()) };
    Ok(scan(doc, &space_files, &state, &home))
}

/// 把 `planned`(金鑰檔 → 插槽檔名)的主機改寫成指到插槽:只換那一行的值,被 FA3 鎖住的主機不動;改了的檔案逐一經
/// `persist`。回傳改寫了的 alias(依出現順序)。
fn rewrite_in(
    doc: &mut SshConfigDoc,
    space_files: &[PathBuf],
    home: &Path,
    planned: &[(PathBuf, String)],
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
                let IdentityTarget::File(target) = resolve_identity_value(&d.value, home) else { continue };
                let Some((_, file)) = planned.iter().find(|(key, _)| same_file(key, &target)) else { continue };
                d.value = slot_value(file);
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
/// 行程跑著同步引擎(`engine::engine_active`;改寫的主機要靠它上傳)。決定裡的路徑不在目前的候選裡就略過。回傳改寫了的 alias。
///
/// 只有第一輪同步已經跑完的 space 參與(`ready_space_files`):候選只來自它們的主機,改寫也只動它們的檔案 —— 其他 space 的主機照舊指到金鑰檔,
/// 等那個 space 的第一輪之後,下一次掃描會列出它們、直接沿用已建好的插槽。
///
/// 任何一個決定做不成(名字不合規、金鑰不能同步、插槽路徑上有別人的東西……)就在那裡回錯誤:那個決定什麼都沒留下,後面的決定
/// 與所有主機的改寫都不做;前面的決定已經建好的插槽留著,下一次掃描會建議沿用(和改寫撞到 `Conflict` 時一樣)。
pub fn setup_keys(env: &SyncEnv, active: bool, choices: Vec<KeyChoice>) -> Result<Vec<String>, AppError> {
    refuse_while_sync_inactive(active, env.runtime)?;
    let home = home_of(env)?;
    let keys_dir = home.join(SLOT_DIR);
    let account_keys = env
        .runtime
        .core
        .lock()
        .unwrap()
        .account_keys
        .clone()
        .ok_or_else(|| AppError::Other("join a sync account first".to_string()))?;
    let current = key_candidates(env)?;
    let mut planned: Vec<(PathBuf, String)> = Vec::new();
    for choice in choices {
        let Some(candidate) = current.keys.iter().find(|c| same_file(Path::new(&c.path), Path::new(&choice.path))) else {
            continue;
        };
        let file = match choice.decision {
            KeyDecision::Reuse { slot_id } => reuse_slot(env, &keys_dir, candidate, &slot_id)?,
            KeyDecision::Sync { name } => create_slot(env, &account_keys, &keys_dir, candidate, name, true)?,
            KeyDecision::Keep { name } => create_slot(env, &account_keys, &keys_dir, candidate, name, false)?,
        };
        planned.push((PathBuf::from(&candidate.path), file));
    }
    if planned.is_empty() {
        return Ok(Vec::new());
    }
    rewrite_hosts(env, &home, &planned)
}

/// 改寫用到 `planned` 裡那些金鑰的主機,經 `persist_file` 寫回。鎖(doc、backed_up)只在內層區塊裡持有:通知(`applied` 會重建 tray、
/// 同步等待主執行緒)要在全部放掉之後才發,同搬移精靈(`migrate::move_hosts_into_space`)。
fn rewrite_hosts(env: &SyncEnv, home: &Path, planned: &[(PathBuf, String)]) -> Result<Vec<String>, AppError> {
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
/// - 這台已經握著它(有來源、連結沒收起來):照舊,什麼都不動,之後每一輪維護它。
/// - 這台還沒有它的金鑰,或連結收起來了(`LocalSlot::parked`):現在就連到使用者選的這把金鑰、寫 `.pub`、記下來(清掉 `parked`)。插槽路徑上
///   已經有東西(收起來的連結不擁有路徑上的任何東西)就不連結,回 `in_the_way_message`,主機也不改寫。
fn reuse_slot(env: &SyncEnv, keys_dir: &Path, candidate: &KeyCandidate, slot_id: &str) -> Result<String, AppError> {
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
    let file = slot_file_name(&payload.name, slot_id);
    if state.key_slots.get(slot_id).is_some_and(|l| l.source.is_some() && !l.parked) {
        return Ok(file);
    }
    let slot_path = keys_dir.join(&file);
    // 連結用的路徑與記進 `Linked` 的路徑出自同一個字串(`candidate.path`):`slots::maintain` 每一輪(Unix)確認 symlink 正好指到記錄的路徑。
    let link = link_free_slot(keys_dir, &slot_path, Path::new(&candidate.path))?;
    let result = mutate(env, |s| {
        let local = s.key_slots.entry(slot_id.to_string()).or_insert_with(|| LocalSlot {
            file_name: file.clone(),
            source: None,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
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
        assert_eq!(setup_keys(&a.env(), true, vec![keep(&key, "id_mac")]).unwrap(), Vec::<String>::new());
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
}
