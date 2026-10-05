//! 從 v1 升級(spec §7.6):v2 app 啟動時讀到已加入的 `version: 1` 狀態檔、keychain 有同步碼 → 背景執行緒做一次
//! 升級。可重複執行、結果相同,兩台同時升級也安全:帳戶與 space0 都由同步碼推導(同一個 chain、同一把金鑰),
//! space0 的 `space` payload 是確定值;帳戶上已經有 space0 就沿用(可能已被改名),不再寫一份蓋掉它。
//!
//! 整個升級過程中,任何主機都不能從 ssh 消失。失敗時確實成立的是這些(不是「什麼都沒寫」):
//! - v1 狀態檔一個位元組都不動(只複製一份備份);記憶體裡的 core 狀態到最後一步才換。
//! - 網路階段(推導金鑰、讀帳戶、必要時建立缺的 chain)失敗,本機的檔案一個都沒碰。
//! - 檔案階段照 spec §4.3 的順序:先把主機寫進新檔案、再用一次寫入換主 config 的清單、最後才移除 `hosts.config`(備份好才移除)。
//!   所以任何時刻,ssh 讀得到的主機都還在某個被主 config 列著的檔案裡。失敗時最多留下還沒被列出的新檔,或做到一半的升級
//!   (`hosts.config` 已移除、狀態檔還是 v1):下一輪接著做完,使用者在那之前離開,則由 `account::leave_account` 把它們一併改成本機檔案。
//! - 重跑時,升級的來源由主 config 現在列著什麼決定(`plan_sources`),不看「`hosts.config` 還在不在」或「新檔名有沒有內容」:ssh 不讀的
//!   檔案絕不併進 ssh 會讀的檔案,被取代、被移除的都先備份;使用者在列著的檔案裡做的修改因此不會被舊的內容蓋掉。kept 檔照同一條規則:主 config 列著它才沿用、
//!   接續;沒列著(前一次在換清單之前就失敗了)是 ssh 不讀的舊檔,備份後以這一次要留的內容重寫(沒有東西要留就移除、不列進清單)。
//! - 主 config 換成新清單之後才失敗(移除舊檔、存狀態):doc 重載成磁碟上現在的樣子,放掉所有鎖之後通知前端(`applied(0)`)。

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::MutexGuard;

use crate::config::commands::persist_file;
use crate::config::model::{Directive, Item, SshConfigDoc};
use crate::config::parser::parse_file;
use crate::config::serialize::serialize_items;
use crate::error::AppError;
use crate::fsutil;
use crate::sync::account::{listed_our_files, put_new_space, selected_ids};
use crate::sync::crypto;
use crate::sync::env::SyncEnv;
use crate::sync::hosts_file::{self, forbidden_directive, validate_host_text};
use crate::sync::merge::{merge_account, plan_device, put_account_record, selected_include_tokens, space_deleted_by, space_entry};
use crate::sync::record::{
    record_key, HostPayload, LocalRecord, MetaPayload, RecordKind, SpacePayload, ACCOUNT_META_ID, SPACE0_NAME,
};
use crate::sync::relay::RelayError;
use crate::sync::runtime::{save_core, superseded};
use crate::sync::space_files::{self, space_file_name, KeptFile};
use crate::sync::state::{SyncState as LegacyState, MNEMONIC_ACCOUNT};
use crate::sync::state_v2::{self, AccountState, FreezeInfo, SpaceState, SyncNotice, SyncStateV2};

/// v1 同步檔裡不能進 space0 的區塊(含 `Include` 或帶引號的 keyword)另存的本機檔案(`~/.ssh/` 底下,不在
/// `~/.ssh/sshelter/` 裡 —— 不是「我們的」Include token,之後也不會被 `ensure_include` 收走)。
pub const KEPT_FILE: &str = "sshelter-v1-kept.config";
pub const KEPT_INCLUDE: &str = "~/.ssh/sshelter-v1-kept.config";

/// 只為了確認 chain 還在的查詢所帶的 `since`:JavaScript 的 safe integer 上限(relay 與 client 接受的最大值)。從這個序號之後沒有任何
/// 記錄,回應只剩 `latest_seq`,不必把整條 chain 的記錄再下載一次。
const EXISTS_PROBE_SINCE: u64 = 9_007_199_254_740_991;

/// 測試的插入點(只在測試建置,而且只對目前這個執行緒):`fail_main_write` 讓下一次寫主 config 失敗;`fail_removal` 讓下一次移除檔案失敗;
/// `before_swap` 在檔案階段做完、換狀態之前執行一件事(例如使用者剛好在這時離開)。
#[cfg(test)]
#[derive(Default)]
struct TestHooks {
    fail_main_write: bool,
    fail_removal: bool,
    before_swap: Option<Box<dyn FnOnce()>>,
}

#[cfg(test)]
thread_local! {
    static TEST_HOOKS: std::cell::RefCell<TestHooks> = std::cell::RefCell::new(TestHooks::default());
}

/// 升級前,core 裡給 UI 看的 v2 外殼:沿用 v1 的裝置身分與 relay,還沒有帳戶。
pub fn shell_state(v1: &LegacyState) -> SyncStateV2 {
    let mut s = SyncStateV2::fresh(&v1.device_name).expect("a fresh state only draws a device id");
    s.device_id = v1.device_id.clone();
    s.relay_url = v1.relay_url.clone();
    s.phrase_cleanup_pending = v1.phrase_cleanup_pending;
    s
}

/// 文字裡每個 Host 區塊的第一個 pattern。
fn host_aliases(text: &str) -> Vec<String> {
    parse_file(text).0.iter().filter_map(|i| match i {
        Item::Host(h) => h.patterns.first().cloned(),
        _ => None,
    }).collect()
}

/// v1 同步檔的內容拆成兩份:進 space0 的(其他一切)與留在本機的(含 `Include` 或帶引號 keyword 的 top-level
/// 項目,spec §7.6 第 3 步)。回傳(space0 的內容, 留在本機的內容)。什麼都不進 space0 時內容是空的(不是只有一個換行)。
fn split_v1_file(text: &str) -> (String, String) {
    let (items, trailing_newline) = parse_file(text);
    let (mut synced, mut kept) = (Vec::new(), Vec::new());
    for item in items {
        if forbidden_directive(std::slice::from_ref(&item)).is_some() {
            kept.push(item);
        } else {
            synced.push(item);
        }
    }
    let kept_text = if kept.is_empty() { String::new() } else { serialize_items(&kept, true) };
    let space_text = if synced.is_empty() { String::new() } else { serialize_items(&synced, trailing_newline) };
    (space_text, kept_text)
}

/// 主 config 現在有沒有一行生效中的 top-level Include 列著 kept 檔 —— ssh 讀不讀得到它。
fn lists_kept_include(items: &[Item]) -> bool {
    items.iter().any(|i| {
        matches!(i, Item::Directive(d) if d.key == "include" && d.enabled && d.value.split_whitespace().any(|t| t == KEPT_INCLUDE))
    })
}

/// 主 config 裡、我們那一行 Include 之後,放一行 `Include ~/.ssh/sshelter-v1-kept.config`(已經有就不動)。
fn ensure_kept_include(items: &mut Vec<Item>) -> bool {
    if lists_kept_include(items) {
        return false;
    }
    let ours = items.iter().position(|i| {
        matches!(i, Item::Directive(d) if d.key == "include" && d.enabled && d.value.split_whitespace().any(hosts_file::is_our_include_token))
    });
    let at = match ours {
        Some(i) => i + 1,
        None => items.iter().position(|i| !matches!(i, Item::Blank(_) | Item::Comment(_))).unwrap_or(items.len()),
    };
    items.insert(at, Item::Directive(Directive::new("Include", KEPT_INCLUDE, "")));
    true
}

/// 主 config 的 Include 清單一次改好、一次寫入:使用者自己放在 `~/.ssh/sshelter/` 的檔案改成本機檔案的 token 換掉(`released`,先於
/// `ensure_include`,所以不會被它當成「我們的」token 收走)、space0 的清單(`tokens`,空 = 不列任何 space)、kept 檔的 Include
/// (`keep_include`)在同一份 items 上一起改,只寫一次 —— 磁碟上的清單不是舊的就是新的,不會有「新清單已經換掉 `hosts.config`、kept
/// 檔還沒列進去」的中間狀態(那會讓 kept 的主機從 ssh 消失,而且之後重試還以為「已經列了」就不再寫)。寫入失敗就把記憶體裡的 items 退回
/// 原樣再回 Err(同 `files::write_include`):磁碟沒變、記憶體也沒比磁碟新,下一次重試重新判斷、重新寫。呼叫端持有 doc 與 backed_up 鎖,
/// **不持有** core 鎖(`persist_file` 的存檔 hook 會拿它)。
fn write_lists(
    doc: &mut SshConfigDoc,
    backed_up: &mut HashSet<PathBuf>,
    retention: Option<usize>,
    tokens: &[String],
    keep_include: bool,
    released: &[KeptFile],
) -> Result<(), AppError> {
    let original = doc.files[0].items.clone();
    let mut changed = false;
    if !released.is_empty() {
        let moved: Vec<(String, String)> = released.iter().map(|k| (k.old_token.clone(), k.token.clone())).collect();
        // 沒搬走的我們的 token 還在就留著(`|_| true`):緊接著的 `ensure_include` 會把它們全部收走。
        changed |= hosts_file::release_include(&mut doc.files[0].items, &moved, |_| true);
    }
    changed |= hosts_file::ensure_include(&mut doc.files[0].items, tokens);
    if keep_include {
        changed |= ensure_kept_include(&mut doc.files[0].items);
    }
    if !changed {
        return Ok(());
    }
    #[cfg(test)]
    if TEST_HOOKS.with(|h| std::mem::take(&mut h.borrow_mut().fail_main_write)) {
        doc.files[0].items = original;
        return Err(AppError::Other("injected: the main config could not be written".to_string()));
    }
    if let Err(e) = persist_file(doc, 0, backed_up, retention) {
        doc.files[0].items = original;
        return Err(e);
    }
    Ok(())
}

/// 讀文字檔;檔案不存在 → None。
fn read_if_exists(path: &Path) -> Result<Option<String>, AppError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AppError::Io(e)),
    }
}

/// 移除檔案;本來就不在也算成功。
fn remove_if_exists(path: &Path) -> Result<(), AppError> {
    #[cfg(test)]
    if TEST_HOOKS.with(|h| std::mem::take(&mut h.borrow_mut().fail_removal)) {
        return Err(AppError::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "injected: the file could not be removed")));
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(AppError::Io(e)),
    }
}

/// 覆蓋或移除一個還在的檔案之前,一定要先拿到備份:`fsutil::backup` 暫時查不到檔案時回 None,那就停下、不能沒有備份就繼續
/// (同 `space_files::remove_space_file`)。
pub(crate) fn back_up_first(path: &Path) -> Result<(), AppError> {
    match fsutil::backup(path)? {
        Some(_) => Ok(()),
        None => Err(AppError::Other(format!("{} could not be backed up, so it was left alone", path.display()))),
    }
}

/// 把 `extra`(一段完整的行)接在 kept 檔現在的內容 `existing` 後面。`existing` 裡已經整段在(從某一行的開頭起)就不動 —— 重跑時不重複
/// 接一次,使用者在 kept 檔裡改過、加過的內容也都留著。缺的換行補上;`extra` 是空白的就什麼都不加。
fn append_lines(existing: &str, extra: &str) -> String {
    if extra.trim().is_empty() {
        return existing.to_string();
    }
    let mut extra = extra.to_string();
    if !extra.ends_with('\n') {
        extra.push('\n');
    }
    if existing.starts_with(&extra) || existing.contains(&format!("\n{extra}")) {
        return existing.to_string();
    }
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&extra);
    out
}

/// 前一次(中斷的)升級留在 `~/.ssh/sshelter/` 的 space0 檔:`<slug>-<space0 id 前 8 字元>.config`(slug 是當時帳戶上的名稱,之後可能被別台
/// 改過)。`listed`:主 config 現在有沒有列它(明確列出,或我們目錄的 glob 涵蓋它)—— 列著就是 ssh 現在讀得到的。
#[derive(Debug)]
struct Leftover {
    name: String,
    path: PathBuf,
    text: String,
    listed: bool,
}

/// `~/.ssh/sshelter/` 裡的 space0 候選檔(`Leftover`),依檔名排序;只看一般檔案。讀不了就是錯誤:不能略過一個可能放著主機的檔案。
fn previous_space0_files(ssh_dir: &Path, id8: &str, items: &[Item]) -> Result<Vec<Leftover>, AppError> {
    let entries = match std::fs::read_dir(space_files::spaces_dir(ssh_dir)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(AppError::Io(e)),
    };
    let suffix = format!("-{id8}.config");
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(&suffix) || !space_files::is_space_file_name(&name) || !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let text = std::fs::read_to_string(&path)?;
        let listed = hosts_file::lists_include(items, &format!("{}{name}", space_files::INCLUDE_DIR));
        out.push(Leftover { name, path, text, listed });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// 檔案階段的計畫(`plan_sources`,只讀規劃、不碰檔案)。
#[derive(Debug, Default, PartialEq)]
struct Plan {
    /// space0 檔要寫成這個內容;None = 沿用現在的檔案(沒有就建空檔)。
    space_text: Option<String>,
    /// 要併進 kept 檔的文字。
    keep: Vec<String>,
    /// 主 config 換好清單之後,備份並移除的 space0 候選檔:ssh 不讀的多餘檔案,以及內容已經搬走的舊檔名。
    obsolete: Vec<PathBuf>,
}

/// 升級的來源,由主 config 現在(生效中的 top-level `Include`)列著什麼決定 —— 不看「`hosts.config` 還在不在」或「新檔名有沒有內容」:
/// - 列著 `hosts.config`(v1 的 token,`lists_v1`):`hosts.config` 是來源(正常的第一次升級)。列著的 space0 候選檔(手寫的清單,兩個都列)內容
///   不同才併進 kept 檔 —— ssh 現在兩個都讀,讀得到的東西不能消失。
/// - 沒列 `hosts.config`、列著 space0 候選檔:前一次的升級已經切換過 —— 列著的那個檔案是來源,使用者在裡面的修改都留著(別台改過名就搬到
///   現在的名稱)。`hosts.config`(還在的話)與沒列出的候選檔是 ssh 不讀的多餘檔案,絕不用它們的內容。
/// - 兩個都沒列(使用者拿掉了我們的 Include):照原本的做法 —— `hosts.config` 還在就以它為準,否則用前一次升級留下的 space0 檔。
///
/// ssh 不讀的檔案絕不併進 ssh 會讀的檔案(唯一的例外是最後一種:沒有任何東西列著,那時前一次升級的 space0 檔就是唯一留著主機的地方)。
/// `v1_text` = `hosts.config` 的內容(檔案不在 → None)。
fn plan_sources(v1_text: Option<&str>, lists_v1: bool, space0_gone: bool, file_name: &str, candidates: &[Leftover]) -> Plan {
    let live = |text: &str| !text.trim().is_empty();
    let listed: Vec<&Leftover> = candidates.iter().filter(|c| c.listed).collect();
    // space0 還在時,正好是目標檔名的候選檔不移除(它是來源,或會被 `space_text` 取代);space0 已被刪除就沒有目標檔,全部移除。
    let mut plan = Plan {
        obsolete: candidates.iter().filter(|c| space0_gone || c.name != file_name).map(|c| c.path.clone()).collect(),
        ..Plan::default()
    };
    match v1_text {
        Some(t) if lists_v1 || listed.is_empty() => {
            if space0_gone {
                plan.keep.push(t.to_string());
            } else {
                let (synced, kept) = split_v1_file(t);
                plan.keep.push(kept);
                plan.space_text = Some(synced);
            }
            plan.keep.retain(|text| live(text));
            // 走到這裡 `listed` 不是空的 = 兩個都列。
            for c in &listed {
                if live(&c.text) && plan.space_text.as_deref() != Some(c.text.as_str()) {
                    plan.keep.push(c.text.clone());
                }
            }
        }
        _ if !listed.is_empty() => {
            if space0_gone {
                // space0 已在別台刪除:列著的 space0 檔裡的主機改留在本機。
                plan.keep.extend(listed.iter().map(|c| c.text.clone()));
            } else {
                // 來源:正好是目標檔名而且有內容的優先,其次第一個有內容的,都是空的就照名字第一個。
                let primary = listed
                    .iter()
                    .position(|c| c.name == file_name && live(&c.text))
                    .or_else(|| listed.iter().position(|c| live(&c.text)))
                    .or_else(|| listed.iter().position(|c| c.name == file_name))
                    .unwrap_or(0);
                let source = listed[primary];
                if source.name != file_name {
                    // 別台把 space0 改過名:內容搬到現在的名稱(先寫好新檔名、清單換過去之後才移除舊檔)。
                    plan.space_text = Some(source.text.clone());
                }
                // 其他也列著的檔案(ssh 現在讀得到):內容不同才併進 kept 檔。
                for (i, c) in listed.iter().enumerate() {
                    if i != primary && live(&c.text) && c.text != source.text {
                        plan.keep.push(c.text.clone());
                    }
                }
            }
        }
        _ => {
            // 沒有任何東西列著、`hosts.config` 也不在:前一次升級留下的 space0 檔是唯一留著主機的地方。
            if space0_gone {
                plan.keep.extend(candidates.iter().map(|c| c.text.clone()));
            } else {
                let primary = candidates
                    .iter()
                    .position(|c| c.name == file_name && live(&c.text))
                    .or_else(|| candidates.iter().position(|c| live(&c.text)))
                    .or_else(|| candidates.iter().position(|c| c.name == file_name));
                if let Some(primary) = primary {
                    let source = &candidates[primary];
                    if source.name != file_name {
                        plan.space_text = Some(source.text.clone());
                    }
                    for (i, c) in candidates.iter().enumerate() {
                        if i != primary && live(&c.text) && c.text != source.text {
                            plan.keep.push(c.text.clone());
                        }
                    }
                }
            }
        }
    }
    plan
}

/// 升級進行中使用者離開了(`leave_account` 放棄升級,或別的結構性變更換了 generation):這一輪升級作廢(`superseded`,不是升級的錯誤),
/// 什麼都不再動。呼叫端持有 doc 鎖(順序 doc → core):離開也要先拿 doc 鎖,所以這個檢查之後到這一段做完之前,沒有人能插進來。
fn still_current(env: &SyncEnv, generation: u64) -> Result<(), AppError> {
    let core = env.runtime.core.lock().unwrap();
    if core.generation != generation || core.legacy.is_none() {
        return Err(superseded());
    }
    Ok(())
}

/// doc 不可信了 —— 主 config 的清單已經換了(磁碟上就是新的)之後失敗,或主 config 在載入之後被外部改過:整份重載讓 doc 回到磁碟上現在的樣子
/// (重載不了就丟掉,前端會重載),放掉 doc 鎖(呼叫端要先放掉 backed_up 與 core 鎖)之後通知前端 `applied(0)`(同 `files::prepare_files`),
/// 回傳要顯示的錯誤。
fn refresh_doc_after_failure(env: &SyncEnv, mut doc_lock: MutexGuard<'_, Option<SshConfigDoc>>, main: &Path, error: AppError) -> AppError {
    let error = match env.load_doc(main) {
        Ok(fresh) => {
            *doc_lock = Some(fresh);
            error
        }
        Err(reload) => {
            *doc_lock = None;
            AppError::Other(format!("{error}; reloading the config afterwards also failed: {reload}"))
        }
    };
    drop(doc_lock);
    env.events.applied(0);
    error
}

/// 升級本體(spec §7.6 的 1–5 步;v1 狀態檔的備份提前到檔案階段之前,它只是複製)。成功時 core 換成 v2 狀態(`legacy` 清掉、換 generation、
/// 失敗的輪數歸零)、狀態檔寫成 v2(v1 備份為 `sync-state.v1-backup.json`),回傳 true。doc 還沒載入 → 什麼都不做、回傳 false(config 載入時
/// 會喚醒下一輪)。升級進行中使用者離開了 → `superseded`。網路在鎖外;檔案在 doc 鎖內、照 §4.3 的順序。失敗時什麼成立,見模組說明。
///
/// 被限流(`429`)、relay 出錯(`5xx`)與 keychain 給不出同步碼都算失敗的輪數(`failed_rounds`),`round::next_delay` 依 spec §6.4 退避;每一次 `PUT` 都算進 relay 每 IP
/// 每小時 20 次的建立額度(chain 本來就在也一樣),所以先讀、只建立不在的 chain。使用者自己放在 `~/.ssh/sshelter/`、被我們的 Include 列著的檔案
/// (v1 只有 `hosts.config` 那個 token 是我們的)改成本機檔案(`SyncNotice::Upgraded::moved_files`),不會被新清單收走。
pub fn upgrade_v1(env: &SyncEnv, v1: &LegacyState) -> Result<bool, AppError> {
    if env.doc.lock().unwrap().is_none() {
        return Ok(false);
    }
    // 升級開始時的 generation:之後使用者離開(放棄升級會換 generation、清掉 legacy)就停下,不再動檔案、也不換狀態。
    let generation = env.runtime.core.lock().unwrap().generation;
    let v1_chain = v1.chain_id.clone().ok_or_else(|| AppError::Other("the v1 sync state has not joined a chain".to_string()))?;
    // 失敗的輪數加一(退避,`round::next_delay`;只算這一代的狀態:離開之後換過 generation 就不屬於它)。被限流(`429`)、relay 出錯(`5xx`)與 keychain 給不出同步碼都算。
    let failed_round = || {
        let mut core = env.runtime.core.lock().unwrap();
        if core.generation == generation {
            core.failed_rounds = core.failed_rounds.saturating_add(1);
        }
    };
    // keychain 給不出這組同步碼(讀不到、沒有這個項目、不是這個 chain 的):升級每一輪都要再讀一次,通過系統 keychain 的話可能每一輪都跳出授權視窗 —— 同 relay 錯誤,算失敗的
    // 輪數、退避,不以輪詢的頻率一直重試。
    let words = match env.keychain.get(MNEMONIC_ACCOUNT) {
        Ok(Some(words)) => words,
        Ok(None) => {
            failed_round();
            return Err(AppError::Other("the sync code is missing from the keychain; leave and join again".to_string()));
        }
        Err(e) => {
            failed_round();
            return Err(e);
        }
    };
    if crypto::derive_keys(&words).map(|k| k.chain_id).ok().as_deref() != Some(v1_chain.as_str()) {
        failed_round();
        return Err(AppError::Other(
            "the sync code in the keychain belongs to a different sync chain; leave and join again".to_string(),
        ));
    }
    let account_keys = crypto::derive_account(&words)?;
    let space0 = crypto::derive_space0(&words)?;

    // 1. 先讀帳戶現況,再只建立缺的 chain:別台可能已經升級(甚至改名、刪掉 space0,或已更換同步碼)。`PUT` 回 200 只表示 chain 已存在
    //    (可能已凍結),不代表能寫入:能不能寫以讀到的更換標記與之後 push 的結果為準。
    let relay = env.relay(&v1.relay_url)?;
    let relay_failed = |e: RelayError| -> AppError {
        if matches!(e, RelayError::RateLimited) || matches!(e, RelayError::Http(code) if code >= 500) {
            failed_round();
        }
        e.into()
    };
    let pulled = match relay.pull(&account_keys.chain_id, &account_keys.auth_token, 0) {
        Ok(pulled) => pulled,
        // 帳戶 chain 還不存在(第一台升級的電腦):建立它,再讀一次(別台可能剛好在這之間寫了東西)。
        Err(RelayError::NotFound) => {
            relay.create_chain(&account_keys.chain_id, &account_keys.auth_token).map_err(&relay_failed)?;
            relay.pull(&account_keys.chain_id, &account_keys.auth_token, 0).map_err(&relay_failed)?
        }
        Err(e) => return Err(relay_failed(e)),
    };
    let merged = merge_account(&AccountState::new(&account_keys.chain_id), &account_keys, &pulled);
    let now = env.now();
    let mut account = merged.section;
    account.baseline_established = true;
    if !merged.markers.is_empty() {
        account.frozen = Some(FreezeInfo { detected_at_ms: now, markers: merged.markers });
    }
    if !account.records.contains_key(&record_key(RecordKind::Meta, ACCOUNT_META_ID)) {
        put_account_record(
            &mut account,
            RecordKind::Meta,
            ACCOUNT_META_ID,
            serde_json::to_value(MetaPayload::account(env!("CARGO_PKG_VERSION"))).expect("MetaPayload serializes"),
            false,
            &v1.device_id,
            now,
        );
    }

    // 2. space0 的記錄:帳戶上還沒有才寫(spec §5.2 的確定值);已被刪除就不重建,v1 的主機改留在本機。
    let space0_gone = space_deleted_by(&account, &account_keys, &space0.chain_id).is_some();
    if space_entry(&account, &space0.chain_id).is_none() && !space0_gone {
        put_new_space(&mut account, &account_keys, &space0, &SpacePayload::space0(), &v1.device_id, now)?;
    }
    // space0 的 chain:帳戶沒有標示它被刪掉、也沒被更換同步碼(更換時舊的 space chain 會被刪掉,不能再建一條沒人用的)才確認它還在,不在才建立。
    if !space0_gone && account.frozen.is_none() {
        match relay.pull(&space0.chain_id, &space0.auth_token, EXISTS_PROBE_SINCE) {
            Ok(_) => {}
            Err(RelayError::NotFound) => relay.create_chain(&space0.chain_id, &space0.auth_token).map_err(&relay_failed)?,
            Err(e) => return Err(relay_failed(e)),
        }
    }
    let slug = space_entry(&account, &space0.chain_id).map(|e| e.slug).unwrap_or_else(|| SPACE0_NAME.to_lowercase());
    let file_name = space_file_name(&slug, &space0.chain_id)?;

    // 3. v1 快取裡的 host 記錄 → space0(保留 version、時間戳、device_id、tombstone 與 dirty;全部標 dirty 以 LWW
    //    上傳)。含 `Include` 的區塊不進 space0;v1 `sealed` 裡的 key / password 捨棄。
    let mut space = SpaceState::new(&file_name);
    // v1 的基線輪(Join 之後的第一輪)還沒做完的電腦,space0 也從基線輪開始(以 chain 為準):否則它留在 `hosts.config` 裡的舊內容會被當成「現在」
    // 的本機修改,悄悄蓋過其他電腦已經同步的新內容。做完基線的 v1,一般輪次以 LWW 合併(spec §7.6)。
    space.baseline_established = v1.baseline_established;
    if !space0_gone {
        for local in v1.records.values().filter(|l| l.record.kind == RecordKind::Host) {
            let record = &local.record;
            let allowed = record.deleted
                || serde_json::from_value::<HostPayload>(record.payload.clone())
                    .is_ok_and(|p| validate_host_text(&record.id, &p.text).is_ok());
            if !allowed {
                continue;
            }
            let key = record_key(RecordKind::Host, &record.id);
            if !local.dirty {
                space.republish.insert(key.clone());
            }
            space.records.insert(key, LocalRecord { record: record.clone(), seq: 0, dirty: true });
        }
    }

    // 4. 檔案(doc 鎖內,§4.3 的順序):space0 檔(`hosts.config` 去掉不能同步的區塊)與 kept 檔(留在本機的區塊)先寫好 → 主 config 的 Include
    //    清單用**一次**寫入換成新的(使用者自己的檔案改成本機檔案的 token、space0 檔與 kept 檔一起列進去,v1 的 token 一併收掉)→ 最後備份並移除
    //    `hosts.config`。來源由主 config 現在列著什麼決定(`plan_sources`):前一次升級做到一半就中斷,前一次的 space0 檔就是主機現在的家 ——
    //    沿用它(別台改過名就搬到新檔名;space0 已被刪除就併進 kept 檔),絕不讓它掉出清單,也不讓舊的內容蓋掉使用者在裡面做的修改。
    let hosts_path = hosts_file::managed_path(&env.ssh_dir);
    let v1_token = hosts_file::managed_token();
    let kept_path = env.ssh_dir.join(KEPT_FILE);
    let (kept_file, kept_hosts, moved_files, v1_backup) = {
        let mut doc_lock = env.doc.lock().unwrap();
        // 離開(放棄升級)也要先拿 doc 鎖:從這裡到這一段做完,沒有人能插進來。
        still_current(env, generation)?;
        // v1 狀態檔先備份(只是複製):備份不了就什麼檔案都還沒動。
        let v1_backup = state_v2::back_up_legacy(&env.state_path)?;
        let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        // 下面「主 config 現在列著什麼」要靠 doc:主 config 在載入之後被外部改過就不可信 —— 什麼都還沒動,先整份重載、下一輪重做。
        let main = doc.files[0].path.clone();
        if fsutil::has_changed(&main, &doc.files[0].fingerprint).unwrap_or(true) {
            let stale = AppError::Conflict(main.to_string_lossy().into_owned());
            return Err(refresh_doc_after_failure(env, doc_lock, &main, stale));
        }
        let mut backed_up = env.backed_up.lock().unwrap();
        let retention = env.retention();
        let v1_text = read_if_exists(&hosts_path)?;
        if v1_text.is_some() {
            // 一定要先拿到備份才動任何東西(來源也好、多餘的舊檔也好,只要它還在,最後都會被移除)。
            back_up_first(&hosts_path)?;
        }

        // 規劃(只讀):space0 檔要寫成什麼、要併進 kept 檔的文字、清單換好之後可以移除的舊檔,以及使用者自己的檔案;主 config 有沒有列著 kept 檔(ssh 讀不讀得到它)。
        let (plan, user_files, lists_kept) = {
            let items = &doc.files[0].items;
            let lists_v1 = hosts_file::lists_include(items, &v1_token);
            let candidates = previous_space0_files(&env.ssh_dir, &space0.chain_id[..8], items)?;
            let plan = plan_sources(v1_text.as_deref(), lists_v1, space0_gone, &file_name, &candidates);
            // v1 只有 `hosts.config` 那個 token 是我們的:使用者自己放在 `~/.ssh/sshelter/` 的檔案(也被 Include 列著)是他們的主機 —— 新清單會把
            // 這個目錄底下所有「我們的」token 收走,所以先改成本機檔案(不含 `hosts.config` 與 space0 的候選檔)。
            let user_files: Vec<PathBuf> = listed_our_files(&env.ssh_dir, items)
                .into_iter()
                .filter(|p| {
                    let name = p.file_name();
                    name != hosts_path.file_name() && !candidates.iter().any(|c| Some(c.name.as_str()) == name.and_then(|n| n.to_str()))
                })
                .collect();
            (plan, user_files, lists_kept_include(items))
        };
        let Plan { space_text, keep, obsolete } = plan;

        // kept 檔,同一條規則:ssh 不讀的檔案絕不併進 ssh 會讀的東西。
        // - 主 config 列著它(前一次升級換好了清單、之後才失敗):ssh 現在讀的就是它 —— 要併進去的文字已經整段在裡面就不動(重跑),否則接在後面;使用者在裡面
        //   改過、加過的都留著。
        // - 沒列著(前一次在換清單之前就失敗了,或使用者拿掉了那一行):它是前一次留下的、ssh 不讀的檔案,內容可能已經過時(使用者之後刪了或改了 `hosts.config`
        //   的主機)—— 不沿用:先備份,再以這一次要留的內容(`keep`)重寫;這一次沒有東西要留,就備份後移除、也不列進清單。這樣刪掉的主機不會跟著舊檔回來、
        //   改過的區塊也不會排在舊區塊後面(ssh 用先讀到的),同一個區塊也不會被接上兩次。
        let kept_before = read_if_exists(&kept_path)?;
        let base = if lists_kept { kept_before.clone().unwrap_or_default() } else { String::new() };
        let kept_text = keep.iter().fold(base, |text, extra| append_lines(&text, extra));
        if !kept_text.is_empty() && kept_before.as_deref() != Some(kept_text.as_str()) {
            if kept_before.is_some() {
                back_up_first(&kept_path)?;
            }
            fsutil::atomic_write(&kept_path, kept_text.as_bytes(), 0o600)?;
        } else if kept_text.is_empty() && !lists_kept && kept_before.is_some() {
            // 過時的 kept 檔沒有東西可以接續:ssh 不讀它,留著也不列進清單 —— 備份後移除(同換掉的舊檔)。
            back_up_first(&kept_path)?;
            remove_if_exists(&kept_path)?;
        }
        // 已經列著的 kept 檔照舊列著(即使這次沒有東西要接);沒列著的只有在這一次寫了內容時才列。
        let kept_file = ((lists_kept && kept_before.is_some()) || !kept_text.is_empty()).then(|| kept_path.to_string_lossy().into_owned());

        let tokens = {
            let mut spaces = BTreeMap::new();
            if !space0_gone {
                spaces.insert(space0.chain_id.clone(), space.clone());
            }
            selected_include_tokens(Some(&account), &spaces)?
        };
        let keep_include = kept_file.is_some();
        let mut moved: Vec<KeptFile> = Vec::new();
        let written = {
            // 清單的那一次寫入:使用者的檔案先在 `~/.ssh/sshelter-local/` 以新路徑存在、寫入成功之後才移除舊路徑(失敗就移除新路徑、什麼都沒變)。
            let mut switch = || -> Result<(), AppError> {
                moved = space_files::keep_files_local(&env.ssh_dir, &user_files, |released| {
                    write_lists(doc, &mut backed_up, retention, &tokens, keep_include, released)
                })?;
                Ok(())
            };
            if space0_gone {
                switch()
            } else {
                let target = space_files::space_file_path(&env.ssh_dir, &file_name)?;
                if space_text.is_some() && target.try_exists()? {
                    // 蓋掉現有的 space0 檔之前先備份(`hosts.config` 還在、space0 檔已經有的重跑)。
                    back_up_first(&target)?;
                }
                space_files::add_space_file(&env.ssh_dir, &file_name, space_text.as_deref().map(str::as_bytes), switch).map(|_| ())
            }
        };
        if let Err(e) = written {
            if !matches!(e, AppError::Conflict(_)) {
                return Err(e);
            }
            // 主 config 在載入之後又被外部改過(上面檢查到現在之間;`write_lists` 已把記憶體退回原樣,清單還是舊的、`hosts.config` 仍列著):
            // 整份重載,下一輪在正確的基礎上重做。
            drop(backed_up);
            return Err(refresh_doc_after_failure(env, doc_lock, &main, e));
        }
        // 清單換好了,主機都在被列出的檔案裡:這時才移除舊檔,每一個都先有備份(`hosts.config` 上面已經備份過)。失敗的話磁碟上的清單已經是新的,
        // doc 要重載成那個樣子、前端要知道。
        let removed = (|| -> Result<(), AppError> {
            if v1_text.is_some() {
                remove_if_exists(&hosts_path)?;
            }
            for path in &obsolete {
                back_up_first(path)?;
                remove_if_exists(path)?;
            }
            Ok(())
        })();
        drop(backed_up);
        if let Err(e) = removed {
            return Err(refresh_doc_after_failure(env, doc_lock, &main, e));
        }
        match env.load_doc(&main) {
            Ok(fresh) => *doc_lock = Some(fresh),
            Err(e) => return Err(refresh_doc_after_failure(env, doc_lock, &main, e)),
        }
        let moved_files: Vec<String> = moved.iter().map(|k| k.path.to_string_lossy().into_owned()).collect();
        (kept_file, host_aliases(&kept_text), moved_files, v1_backup)
    };

    // 5. 狀態:core 換成 v2 狀態與帳戶金鑰(v1 狀態檔已在檔案階段之前備份),再寫成 v2。
    let mut state = shell_state(v1);
    state.legacy_v1_backup = Some(v1_backup);
    if !space0_gone {
        state.spaces.insert(space0.chain_id.clone(), space);
    }
    let ids = selected_ids(&state);
    plan_device(&mut account, &v1.device_id, &v1.device_name, env.platform, &ids, now);
    state.account = Some(account);
    let kept_hosts: Vec<String> = kept_hosts.into_iter().filter(|h| !h.is_empty()).collect::<BTreeSet<_>>().into_iter().collect();
    let notice = SyncNotice::Upgraded { kept_file, kept_hosts, moved_files };
    state.notices.push(notice.clone());
    #[cfg(test)]
    if let Some(hook) = TEST_HOOKS.with(|h| h.borrow_mut().before_swap.take()) {
        hook();
    }
    {
        let doc_lock = env.doc.lock().unwrap();
        let mut core = env.runtime.core.lock().unwrap();
        // 檔案階段之後、換狀態之前使用者離開了:離開的結果才算數,升級不能再把一個已加入的狀態蓋回去。
        if core.generation != generation || core.legacy.is_none() {
            return Err(superseded());
        }
        core.generation += 1;
        core.conflict_streak = 0;
        core.failed_rounds = 0;
        core.batch_failures = 0;
        // 新狀態是由 v1 的外殼重組的,`relay_features` 是空的:這個行程「查過 relay」的記錄也要清掉。不清的話,升級期間按過「Check relay」之後 `GET /v1/info` 不會再查
        // (`round::relay_supports_batch`),`SyncOverview::relay` 一直是 null。
        core.relay_checked = None;
        core.state = Some(state);
        core.legacy = None;
        core.account_keys = Some(account_keys);
        let saved = save_core(&mut core, &env.state_path);
        drop(core);
        if let Err(e) = saved {
            // 狀態在記憶體裡已經是升級後的(`unsaved`,下一輪先補寫),只是沒寫進磁碟;檔案已經換了:doc 重載、前端要知道。
            let main = doc_lock.as_ref().map(|d| d.files[0].path.clone()).unwrap_or_else(|| env.ssh_dir.join("config"));
            return Err(refresh_doc_after_failure(env, doc_lock, &main, e));
        }
    }
    env.events.notice(&notice);
    env.events.applied(0);
    env.events.wake();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::account::{create_account, leave_account, BEFORE_LEAVE};
    use crate::sync::env::Keychain;
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::hosts_file::blocks_of;
    use crate::sync::merge::space_entries;
    use crate::sync::record::{HostPayload, Record};
    use crate::sync::round::tests::settle;
    use crate::sync::round::{next_delay, sync_once};
    use crate::sync::runtime::is_superseded;
    use crate::sync::spaces::{delete_space, rename_space};
    use crate::sync::state::SyncState;
    use crate::sync::testkit::{AppliedProbe, HookedConnector, Hooks, TestClock, TestDevice, RELAY_URL};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// v1 的狀態檔(`version: 1`)。
    fn write_v1(path: &std::path::Path, v1: &SyncState) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(v1).unwrap()).unwrap();
    }

    const MAIN: &str = "# main\nInclude ~/.ssh/sshelter/hosts.config\nHost local\n";

    /// 一台已加入 v1 chain 的裝置:`hosts.config` 的每個區塊都是 v1 快取裡已同步的記錄(兩台的 metadata 相同,
    /// 就像經過 v1 同步),狀態檔是 v1,keychain 有同步碼,core 等著升級。
    fn v1_device(name: &str, relay: &Arc<FakeRelay>, clock: &Arc<TestClock>, hosts: &str) -> (TestDevice, SyncState) {
        v1_device_with_main(name, relay, clock, MAIN, hosts)
    }

    /// 同 `v1_device`,主 config 自訂(例如 v1 的使用者自己多列了一個 Include)。
    fn v1_device_with_main(name: &str, relay: &Arc<FakeRelay>, clock: &Arc<TestClock>, main: &str, hosts: &str) -> (TestDevice, SyncState) {
        let d = TestDevice::with_main_config(name, relay, clock, main);
        let dir = d.ssh_dir().join("sshelter");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hosts.config"), hosts).unwrap();
        d.reload();
        d.keychain.set(MNEMONIC_ACCOUNT, WORDS).unwrap();
        let mut v1 = SyncState::fresh(name).unwrap();
        v1.device_id = format!("{name:0<32}");
        v1.relay_url = RELAY_URL.to_string();
        v1.chain_id = Some(crypto::derive_keys(WORDS).unwrap().chain_id);
        v1.baseline_established = true;
        for (i, block) in blocks_of(&parse_file(hosts).0).into_iter().enumerate() {
            let record = Record {
                kind: RecordKind::Host,
                id: block.alias.clone(),
                version: 1,
                updated_at_ms: 1_600_000_000_000 + i as u64,
                device_id: "v1-origin".into(),
                deleted: false,
                payload: serde_json::to_value(HostPayload { schema: 1, text: block.text }).unwrap(),
            };
            v1.records.insert(record_key(RecordKind::Host, &block.alias), LocalRecord { record, seq: i as u64 + 1, dirty: false });
        }
        write_v1(&d.env().state_path, &v1);
        {
            let mut core = d.runtime.core.lock().unwrap();
            core.state = Some(shell_state(&v1));
            core.legacy = Some(v1.clone());
        }
        (d, v1)
    }

    fn space0() -> String {
        crypto::derive_space0(WORDS).unwrap().chain_id
    }

    #[test]
    fn an_upgrade_moves_the_v1_hosts_into_space0_and_keeps_include_blocks_local() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\n  HostName 10.0.0.1\nHost jump\n  Include ~/.ssh/jump.config\nHost db\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        let id = space0();
        let file = format!("synced-{}.config", &id[..8]);
        assert_eq!(d.read(&d.ssh_dir().join("sshelter").join(&file)), "Host web\n  HostName 10.0.0.1\nHost db\n");
        assert_eq!(d.read(&d.ssh_dir().join(KEPT_FILE)), "Host jump\n  Include ~/.ssh/jump.config\n");
        assert_eq!(d.main_config(), format!("# main\nInclude ~/.ssh/sshelter/{file}\nInclude {KEPT_INCLUDE}\nHost local\n"));
        assert!(!hosts_file::managed_path(&d.ssh_dir()).exists(), "hosts.config is backed up and removed");
        // 狀態檔已是 v2;v1 的原檔另存。
        let env = d.env();
        assert!(matches!(state_v2::load(&env.state_path).unwrap(), state_v2::LoadedState::Current(_)));
        let backup = env.state_path.with_file_name(state_v2::LEGACY_BACKUP_FILE);
        assert!(matches!(state_v2::load(&backup).unwrap(), state_v2::LoadedState::Legacy(_)));
        let s = d.state();
        assert_eq!(s.legacy_v1_backup.as_deref(), Some(state_v2::LEGACY_BACKUP_FILE));
        assert_eq!(s.device_id, v1.device_id);
        let sp = &s.spaces[&id];
        assert_eq!(sp.records.keys().cloned().collect::<Vec<_>>(), vec!["host:db".to_string(), "host:web".to_string()]);
        assert!(sp.records.values().all(|l| l.dirty && l.record.device_id == "v1-origin"), "v1 metadata is kept");
        assert_eq!(sp.republish.len(), 2);
        let entries = space_entries(s.account.as_ref().unwrap());
        assert_eq!(entries.iter().map(|e| (e.name.as_str(), e.created_at_ms)).collect::<Vec<_>>(), vec![("Synced", 0)]);
        assert_eq!(
            s.notices,
            vec![SyncNotice::Upgraded {
                kept_file: Some(d.ssh_dir().join(KEPT_FILE).to_string_lossy().into_owned()),
                kept_hosts: vec!["jump".into()],
                moved_files: Vec::new(),
            }]
        );
        assert!(d.runtime.core.lock().unwrap().legacy.is_none());
        // 一般輪次以 LWW 上傳。
        settle(&d);
        assert_eq!(relay.rows(&id).len(), 2);
    }

    #[test]
    fn two_devices_upgrading_at_once_end_up_in_the_same_space0_without_conflicts() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\n  HostName 10.0.0.1\nHost db\n";
        let (a, v1a) = v1_device("a", &relay, &clock, hosts);
        let (b, v1b) = v1_device("b", &relay, &clock, hosts);
        assert!(upgrade_v1(&a.env(), &v1a).unwrap());
        assert!(upgrade_v1(&b.env(), &v1b).unwrap());
        for _ in 0..2 {
            settle(&a);
            settle(&b);
        }
        let id = space0();
        assert!(a.state().spaces.contains_key(&id) && b.state().spaces.contains_key(&id));
        assert_eq!(space_entries(a.state().account.as_ref().unwrap()).len(), 1, "one space0, not two");
        assert!(a.events.conflicts.lock().unwrap().is_empty() && b.events.conflicts.lock().unwrap().is_empty());
        assert!(a.state().spaces[&id].records.values().all(|l| !l.dirty));
        assert!(b.state().spaces[&id].records.values().all(|l| !l.dirty));
        // 之後照常同步。
        a.save_in_app(&a.space_path(&id), "Host web\n  HostName 10.0.0.2\nHost db\n");
        settle(&a);
        settle(&b);
        assert_eq!(b.read(&b.space_path(&id)), "Host web\n  HostName 10.0.0.2\nHost db\n");
    }

    #[test]
    fn an_upgrade_can_run_again_with_the_same_result() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        let (main, kept) = (d.main_config(), d.read(&d.ssh_dir().join(KEPT_FILE)));
        let space_file = d.read(&d.space_path(&space0()));
        // 狀態還沒寫成 v2 就中斷了:下次啟動又讀到 v1 狀態,`hosts.config` 已經移除。
        write_v1(&d.env().state_path, &v1);
        d.runtime.core.lock().unwrap().legacy = Some(v1.clone());
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(d.main_config(), main);
        assert_eq!(d.read(&d.ssh_dir().join(KEPT_FILE)), kept);
        assert_eq!(d.read(&d.space_path(&space0())), space_file);
        assert_eq!(d.state().spaces.keys().cloned().collect::<Vec<_>>(), vec![space0()]);
        assert_eq!(space_entries(d.state().account.as_ref().unwrap()).len(), 1);
    }

    #[test]
    fn a_failed_upgrade_leaves_v1_untouched_and_is_retried() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, _) = v1_device("a", &relay, &clock, "Host web\n");
        relay.set_offline(true);
        assert!(sync_once(&d.env()).is_err());
        assert!(d.state().last_error.unwrap().starts_with("SSHelter could not upgrade this device's sync yet"));
        assert!(hosts_file::managed_path(&d.ssh_dir()).exists());
        assert_eq!(d.main_config(), MAIN);
        assert!(matches!(state_v2::load(&d.env().state_path).unwrap(), state_v2::LoadedState::Legacy(_)));
        // 升級完成前不接受會改狀態的命令。
        assert!(crate::sync::account::create_account(&d.env(), "A").is_err());
        assert_eq!(d.keychain.entry(MNEMONIC_ACCOUNT).as_deref(), Some(WORDS), "the sync code is untouched");
        relay.set_offline(false);
        sync_once(&d.env()).unwrap();
        assert!(d.state().joined());
        settle(&d);
        assert_eq!(relay.rows(&space0()).len(), 1);
    }

    #[test]
    fn a_space0_renamed_elsewhere_is_kept_and_a_deleted_one_is_not_recreated() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (a, v1a) = v1_device("a", &relay, &clock, "Host web\n");
        upgrade_v1(&a.env(), &v1a).unwrap();
        settle(&a);
        rename_space(&a.env(), &space0(), "Servers").unwrap();
        settle(&a);
        let (b, v1b) = v1_device("b", &relay, &clock, "Host web\n");
        upgrade_v1(&b.env(), &v1b).unwrap();
        settle(&b);
        assert_eq!(space_entries(b.state().account.as_ref().unwrap())[0].name, "Servers", "B did not rename it back");
        assert!(b.space_path(&space0()).ends_with(format!("servers-{}.config", &space0()[..8])));
        delete_space(&a.env(), &space0()).unwrap();
        settle(&a);
        let (c, v1c) = v1_device("c", &relay, &clock, "Host web\nHost mine\n");
        upgrade_v1(&c.env(), &v1c).unwrap();
        let s = c.state();
        assert!(s.spaces.is_empty(), "a deleted space0 is not recreated");
        assert_eq!(c.read(&c.ssh_dir().join(KEPT_FILE)), "Host web\nHost mine\n");
        assert_eq!(c.main_config(), format!("# main\nInclude {KEPT_INCLUDE}\nHost local\n"));
        assert!(matches!(&s.notices[..], [SyncNotice::Upgraded { kept_hosts, .. }] if kept_hosts == &vec!["mine".to_string(), "web".to_string()]));
    }

    // ── 修正輪(審查):ssh 讀得到的主機,在升級之前、之中、之後(含失敗、當機、重跑、離開)都不能悄悄消失 ──

    /// ssh 現在讀得到的主機:從磁碟整份重新載入主 config(含 Include 的檔案),列出主 config 以外每個檔案裡 Host 區塊的別名
    /// (排序;同一台出現兩次就列兩次)。
    fn ssh_hosts(d: &TestDevice) -> Vec<String> {
        let doc = d.env().load_doc(&d.main_path()).unwrap();
        let mut hosts: Vec<String> = doc
            .files
            .iter()
            .skip(1)
            .flat_map(|f| f.items.iter())
            .filter_map(|i| match i {
                Item::Host(h) => h.patterns.first().cloned(),
                _ => None,
            })
            .collect();
        hosts.sort();
        hosts
    }

    /// 記憶體裡(doc)的主 config 序列化之後的內容。
    fn in_memory_main(d: &TestDevice) -> String {
        let doc = d.doc.lock().unwrap();
        let file = &doc.as_ref().unwrap().files[0];
        serialize_items(&file.items, file.trailing_newline)
    }

    /// 記憶體裡的 doc 現在載入的檔案(檔名):前端與引擎看到的樣子。
    fn memory_files(d: &TestDevice) -> Vec<String> {
        let doc = d.doc.lock().unwrap();
        doc.as_ref().unwrap().files.iter().map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned()).collect()
    }

    /// 磁碟上的主 config 有一行 Include 列出這個路徑。
    fn lists(d: &TestDevice, token: &str) -> bool {
        d.main_config().lines().any(|l| {
            let mut words = l.split_whitespace();
            words.next().is_some_and(|k| k.eq_ignore_ascii_case("include")) && words.any(|t| t == token)
        })
    }

    fn space0_token(slug: &str) -> String {
        format!("~/.ssh/sshelter/{slug}-{}.config", &space0()[..8])
    }

    fn space0_path(d: &TestDevice, slug: &str) -> std::path::PathBuf {
        d.ssh_dir().join("sshelter").join(format!("{slug}-{}.config", &space0()[..8]))
    }

    /// 升級做到一半就中斷了(檔案已經換好、狀態還沒寫成 v2),app 重新啟動:磁碟上還是 v1 狀態檔,core 是 v1 的外殼加上等著升級的 legacy。
    fn restart_before_the_state_was_saved(d: &TestDevice, v1: &SyncState) {
        write_v1(&d.env().state_path, v1);
        let mut core = d.runtime.core.lock().unwrap();
        core.state = Some(shell_state(v1));
        core.account_keys = None;
        core.legacy = Some(v1.clone());
    }

    /// 下一次寫主 config 失敗(磁碟已滿、被掃毒軟體鎖住之類)。
    fn fail_next_main_write() {
        TEST_HOOKS.with(|h| h.borrow_mut().fail_main_write = true);
    }

    /// 下一次移除檔案失敗(換了清單之後移除舊檔時被擋下,例如檔案被鎖住)。
    fn fail_next_removal() {
        TEST_HOOKS.with(|h| h.borrow_mut().fail_removal = true);
    }

    /// 檔案階段做完、換狀態之前插進一件事。
    fn before_swap(hook: impl FnOnce() + 'static) {
        TEST_HOOKS.with(|h| h.borrow_mut().before_swap = Some(Box::new(hook)));
    }

    /// 這個檔案的備份做不出來(備份鏡像目錄的位置被一個一般檔案擋住)。
    fn make_backups_of_fail(path: &std::path::Path) {
        let dir = fsutil::backup_dir_for(path).unwrap();
        std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
        std::fs::write(&dir, b"in the way").unwrap();
    }

    /// v1 狀態檔的備份做不出來(備份檔的路徑被一個目錄擋住)。回傳擋路的目錄。
    fn block_the_v1_state_backup(d: &TestDevice) -> std::path::PathBuf {
        let blocker = d.env().state_path.with_file_name(state_v2::LEGACY_BACKUP_FILE);
        std::fs::create_dir_all(blocker.join("x")).unwrap();
        blocker
    }

    #[test]
    fn a_failed_main_config_write_leaves_the_v1_hosts_listed_and_the_retry_lists_the_kept_file() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\n  HostName 10.0.0.1\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        fail_next_main_write();
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        // 磁碟上與記憶體裡:`hosts.config` 仍然列著,主 config 一個字都沒變;每一台主機照樣讀得到。
        assert_eq!(d.main_config(), MAIN);
        assert_eq!(in_memory_main(&d), MAIN);
        assert!(hosts_file::managed_path(&d.ssh_dir()).exists());
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"]);
        assert!(matches!(state_v2::load(&d.env().state_path).unwrap(), state_v2::LoadedState::Legacy(_)));
        // 重試:space0 與 kept 檔一起列進去,然後才移除 `hosts.config`。
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert!(lists(&d, &space0_token("synced")) && lists(&d, KEPT_INCLUDE));
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"]);
        assert!(!hosts_file::managed_path(&d.ssh_dir()).exists());
    }

    #[test]
    fn a_failed_main_config_write_never_hides_the_hosts_when_space0_was_deleted_elsewhere() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (a, v1a) = v1_device("a", &relay, &clock, "Host web\n");
        upgrade_v1(&a.env(), &v1a).unwrap();
        settle(&a);
        delete_space(&a.env(), &space0()).unwrap();
        settle(&a);
        let (c, v1c) = v1_device("c", &relay, &clock, "Host web\nHost mine\n");
        fail_next_main_write();
        assert!(upgrade_v1(&c.env(), &v1c).is_err());
        assert_eq!(c.main_config(), MAIN, "the v1 file is still the one the list names");
        assert_eq!(ssh_hosts(&c), vec!["mine", "web"]);
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        assert!(lists(&c, KEPT_INCLUDE));
        assert_eq!(ssh_hosts(&c), vec!["mine", "web"]);
    }

    #[test]
    fn a_retry_keeps_what_the_user_added_to_the_kept_file_that_the_main_config_lists() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        // 第一次換好了清單(space0 檔與 kept 檔都列進去了),移除 `hosts.config` 時被擋下:ssh 現在讀的就是 kept 檔。使用者在這之間往它加了一台。
        fail_next_removal();
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        assert!(lists(&d, KEPT_INCLUDE));
        let kept = d.ssh_dir().join(KEPT_FILE);
        std::fs::write(&kept, "Host jump\n  Include ~/.ssh/jump.config\nHost extra\n").unwrap();
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(d.read(&kept), "Host jump\n  Include ~/.ssh/jump.config\nHost extra\n", "nothing is overwritten and nothing is added twice");
        assert_eq!(ssh_hosts(&d), vec!["extra", "jump", "web"]);
        assert!(!hosts_file::managed_path(&d.ssh_dir()).exists());
    }

    /// 這個檔案的備份(`.bak`)內容,舊的在前(備份放在 ssh 看不到的鏡像目錄,`fsutil::backup_dir_for`)。
    fn backups_of(path: &std::path::Path) -> Vec<String> {
        let dir = fsutil::backup_dir_for(path).unwrap();
        let prefix = format!("{}.", path.file_name().unwrap().to_string_lossy());
        let mut found: Vec<(String, String)> = std::fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|e| {
                        let name = e.file_name().to_string_lossy().into_owned();
                        name.starts_with(&prefix) && name.ends_with(".bak")
                    })
                    .map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read_to_string(e.path()).unwrap()))
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        found.into_iter().map(|(_, text)| text).collect()
    }

    #[test]
    fn a_kept_file_the_main_config_does_not_list_never_brings_back_a_host_the_user_deleted() {
        // 探針 KA:第一次升級寫好了 kept 檔、換清單時失敗 —— 清單還列著 `hosts.config`,沒有人讀 kept 檔。使用者在這之間把 jump 從 `hosts.config` 刪了:重跑不能
        // 把舊的 kept 檔列進去(ssh 不讀的檔案,絕不併進 ssh 會讀的東西)。
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        fail_next_main_write();
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        let kept = d.ssh_dir().join(KEPT_FILE);
        assert_eq!(d.read(&kept), "Host jump\n  Include ~/.ssh/jump.config\n");
        assert!(!lists(&d, KEPT_INCLUDE));
        d.save_in_app(&hosts_file::managed_path(&d.ssh_dir()), "Host web\n");
        assert_eq!(ssh_hosts(&d), vec!["web"]);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["web"], "the deleted host stays deleted");
        assert!(!lists(&d, KEPT_INCLUDE) && !kept.exists(), "nothing is left to keep: the stale file is not listed and is gone");
        assert_eq!(backups_of(&kept), vec!["Host jump\n  Include ~/.ssh/jump.config\n".to_string()], "it was backed up before it was removed");
        assert!(matches!(&d.state().notices[..], [SyncNotice::Upgraded { kept_file: None, kept_hosts, .. }] if kept_hosts.is_empty()), "{:?}", d.state().notices);
    }

    #[test]
    fn a_kept_file_the_main_config_does_not_list_is_rewritten_from_this_attempt_so_the_users_edit_wins() {
        // 探針 KB:使用者改的是 jump 而不是刪掉它。以前 kept 檔裡是「舊的區塊、再接上改過的區塊」,ssh 用先讀到的舊區塊;現在重寫成這一次要留的內容。
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        fail_next_main_write();
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        let kept = d.ssh_dir().join(KEPT_FILE);
        let edited = "Host jump\n  Include ~/.ssh/jump.config\n  User edited\n";
        d.save_in_app(&hosts_file::managed_path(&d.ssh_dir()), &format!("Host web\n{edited}"));
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(d.read(&kept), edited, "the kept file holds the edited block once, not the old one first");
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"]);
        assert!(lists(&d, KEPT_INCLUDE));
        assert_eq!(backups_of(&kept), vec!["Host jump\n  Include ~/.ssh/jump.config\n".to_string()]);
    }

    #[test]
    fn a_kept_file_from_a_failed_attempt_is_rewritten_so_no_block_is_in_it_twice() {
        // K1:兩次嘗試都還看得到 `hosts.config`,第二次之前 space0 在別台被刪了 —— 整份 `hosts.config` 都要留在本機。kept 檔裡已經有第一次寫的那一部分:不能再接一次。
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (a, v1a) = v1_device("a", &relay, &clock, "Host web\n");
        upgrade_v1(&a.env(), &v1a).unwrap();
        settle(&a);
        let hosts = "Host web\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (c, v1c) = v1_device("c", &relay, &clock, hosts);
        fail_next_main_write();
        assert!(upgrade_v1(&c.env(), &v1c).is_err());
        delete_space(&a.env(), &space0()).unwrap();
        settle(&a);
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        assert_eq!(c.read(&c.ssh_dir().join(KEPT_FILE)), hosts, "the whole file, once");
        assert_eq!(ssh_hosts(&c), vec!["jump", "web"]);
        assert!(lists(&c, KEPT_INCLUDE));
    }

    #[test]
    fn a_v1_state_that_cannot_be_backed_up_stops_the_upgrade_before_any_file_changes() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost jump\n  Include ~/.ssh/jump.config\n");
        let blocker = block_the_v1_state_backup(&d);
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        assert_eq!(d.main_config(), MAIN);
        assert!(hosts_file::managed_path(&d.ssh_dir()).exists());
        assert!(!space0_path(&d, "synced").exists() && !d.ssh_dir().join(KEPT_FILE).exists(), "no file was written");
        assert!(matches!(state_v2::load(&d.env().state_path).unwrap(), state_v2::LoadedState::Legacy(_)));
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"]);
        std::fs::remove_dir_all(&blocker).unwrap();
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"]);
    }

    #[test]
    fn a_v1_file_that_cannot_be_backed_up_is_left_alone_and_nothing_else_changes() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost jump\n  Include ~/.ssh/jump.config\n");
        make_backups_of_fail(&hosts_file::managed_path(&d.ssh_dir()));
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        assert_eq!(d.main_config(), MAIN);
        assert!(hosts_file::managed_path(&d.ssh_dir()).exists());
        assert!(!space0_path(&d, "synced").exists() && !d.ssh_dir().join(KEPT_FILE).exists(), "no file was written");
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"]);
    }

    #[test]
    fn an_empty_v1_file_gives_an_empty_space0_file() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "");
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(d.read(&space0_path(&d, "synced")), "");
        assert!(!d.ssh_dir().join(KEPT_FILE).exists());
        assert_eq!(d.main_config(), format!("# main\nInclude {}\nHost local\n", space0_token("synced")));
    }

    #[test]
    fn a_rerun_after_space0_was_deleted_elsewhere_keeps_the_hosts_the_first_attempt_listed() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (a, v1a) = v1_device("a", &relay, &clock, "Host web\n");
        upgrade_v1(&a.env(), &v1a).unwrap();
        settle(&a);
        let (c, v1c) = v1_device("c", &relay, &clock, "Host web\nHost mine\n");
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        restart_before_the_state_was_saved(&c, &v1c);
        delete_space(&a.env(), &space0()).unwrap();
        settle(&a);
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        // space0 沒了:第一次升級列在 space0 檔裡的主機,改留在本機的 kept 檔。
        assert_eq!(ssh_hosts(&c), vec!["mine", "web"]);
        assert!(lists(&c, KEPT_INCLUDE) && !lists(&c, &space0_token("synced")));
        assert_eq!(c.read(&c.ssh_dir().join(KEPT_FILE)), "Host web\nHost mine\n");
        assert!(!space0_path(&c, "synced").exists(), "the old space0 file was backed up and removed");
        assert!(c.state().spaces.is_empty());
        assert!(matches!(&c.state().notices[..], [SyncNotice::Upgraded { kept_file: Some(_), kept_hosts, .. }] if kept_hosts == &vec!["mine".to_string(), "web".to_string()]));
    }

    #[test]
    fn a_rerun_after_space0_was_renamed_elsewhere_moves_the_first_attempts_file_to_the_new_name() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (a, v1a) = v1_device("a", &relay, &clock, "Host web\n");
        upgrade_v1(&a.env(), &v1a).unwrap();
        settle(&a);
        let (c, v1c) = v1_device("c", &relay, &clock, "Host web\nHost mine\n");
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        restart_before_the_state_was_saved(&c, &v1c);
        rename_space(&a.env(), &space0(), "Servers").unwrap();
        settle(&a);
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        assert_eq!(c.read(&space0_path(&c, "servers")), "Host web\nHost mine\n");
        assert!(!space0_path(&c, "synced").exists(), "the old name was backed up and removed");
        assert!(lists(&c, &space0_token("servers")) && !lists(&c, &space0_token("synced")));
        assert_eq!(ssh_hosts(&c), vec!["mine", "web"]);
        assert_eq!(c.state().spaces[&space0()].file_name, format!("servers-{}.config", &space0()[..8]));
    }

    #[test]
    fn a_rerun_after_an_interrupted_rename_leaves_one_file_not_two() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (a, v1a) = v1_device("a", &relay, &clock, "Host web\n");
        upgrade_v1(&a.env(), &v1a).unwrap();
        settle(&a);
        let (c, v1c) = v1_device("c", &relay, &clock, "Host web\nHost mine\n");
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        restart_before_the_state_was_saved(&c, &v1c);
        rename_space(&a.env(), &space0(), "Servers").unwrap();
        settle(&a);
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        // 搬到新檔名的那次升級在移除舊檔之前就中斷了:兩個檔案都在、內容相同。
        std::fs::write(space0_path(&c, "synced"), "Host web\nHost mine\n").unwrap();
        restart_before_the_state_was_saved(&c, &v1c);
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        assert!(!space0_path(&c, "synced").exists(), "the duplicate old file was backed up and removed");
        assert_eq!(c.read(&space0_path(&c, "servers")), "Host web\nHost mine\n");
        assert_eq!(ssh_hosts(&c), vec!["mine", "web"]);
    }

    #[test]
    fn leaving_after_an_interrupted_upgrade_keeps_the_hosts_the_first_attempt_listed() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\nHost mine\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (c, v1c) = v1_device("c", &relay, &clock, hosts);
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        restart_before_the_state_was_saved(&c, &v1c);
        leave_account(&c.env(), false).unwrap();
        assert!(c.runtime.core.lock().unwrap().legacy.is_none(), "the upgrade is abandoned");
        // space0 檔(升級已經用它取代 `hosts.config` 列在清單上)改成本機檔案;kept 檔本來就不在我們的目錄裡,照舊列著。
        let kept = crate::sync::space_files::local_dir(&c.ssh_dir()).join(format!("synced-{}.config", &space0()[..8]));
        assert_eq!(c.read(&kept), "Host web\nHost mine\n");
        assert!(!space0_path(&c, "synced").exists());
        assert!(lists(&c, KEPT_INCLUDE));
        assert_eq!(ssh_hosts(&c), vec!["jump", "mine", "web"]);
        assert_eq!(c.state().notices, vec![SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }]);
        // 之後建立帳戶:它們不再是「我們的」token,第一次寫清單不會把它們收走。
        create_account(&c.env(), "C").unwrap();
        assert_eq!(ssh_hosts(&c), vec!["jump", "mine", "web"]);
    }

    #[test]
    fn a_rotated_account_gets_no_new_space0_chain_and_the_hosts_stay_listed() {
        use crate::sync::merge::{account_outgoing, push_outgoing};
        use crate::sync::record::{rotation_meta_id, RotationMarkerPayload};
        use crate::sync::relay::RelayApi;
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // 另一台已經更換同步碼:舊帳戶 chain 上有更換標記而且已凍結(舊的 space chain 更換時就刪了)。
        let keys = crypto::derive_account(WORDS).unwrap();
        relay.create_chain(&keys.chain_id, &keys.auth_token).unwrap();
        let mut rotated = AccountState::new(&keys.chain_id);
        let marker = RotationMarkerPayload { rotated_at_ms: 5, by_device_id: "other".into(), by_device_name: "Other".into() };
        put_account_record(&mut rotated, RecordKind::Meta, &rotation_meta_id("other"), serde_json::to_value(marker).unwrap(), false, "other", 5);
        let outgoing = account_outgoing(&rotated, &keys).unwrap();
        assert!(push_outgoing(relay.as_ref(), &keys.chain_id, &keys.auth_token, &outgoing).error.is_none());
        relay.freeze_chain(&keys.chain_id, &keys.auth_token).unwrap();
        relay.clear_calls();
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost mine\n");
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert!(d.state().frozen().is_some(), "this device learns the code was changed");
        assert!(!relay.exists(&space0()) && !relay.calls().iter().any(|c| c.starts_with("create:")), "{:?}", relay.calls());
        assert_eq!(ssh_hosts(&d), vec!["mine", "web"]);
        assert!(d.state().spaces[&space0()].records.values().all(|l| l.dirty), "the hosts wait for the new sync code");
    }

    #[test]
    fn an_upgrade_from_a_v1_whose_first_sync_never_finished_does_not_overwrite_the_other_devices() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (a, v1a) = v1_device("a", &relay, &clock, "Host web\n  HostName 10.0.0.2\n");
        upgrade_v1(&a.env(), &v1a).unwrap();
        settle(&a);
        clock.advance(60_000);
        // B:重新加入的 v1,留著離開之前的舊區塊;它在 v1 的第一輪(基線輪)還沒做完。
        let (b, mut v1b) = v1_device("b", &relay, &clock, "Host web\n  HostName 10.0.0.1-stale\nHost db\n");
        v1b.records.clear();
        v1b.baseline_established = false;
        restart_before_the_state_was_saved(&b, &v1b);
        assert!(upgrade_v1(&b.env(), &v1b).unwrap());
        assert!(!b.state().spaces[&space0()].baseline_established, "space0 starts from the baseline round too");
        for _ in 0..2 {
            settle(&b);
            settle(&a);
        }
        let id = space0();
        assert_eq!(a.read(&a.space_path(&id)), "Host web\n  HostName 10.0.0.2\nHost db\n", "the stale block did not win");
        assert_eq!(b.read(&b.space_path(&id)), "Host web\n  HostName 10.0.0.2\nHost db\n");
        assert!(a.events.conflicts.lock().unwrap().is_empty() && b.events.conflicts.lock().unwrap().is_empty());
    }

    #[test]
    fn a_main_config_changed_behind_the_upgrades_back_is_reloaded_and_the_front_end_is_told() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost jump\n  Include ~/.ssh/jump.config\n");
        d.write_externally(&d.main_path(), &format!("{MAIN}Host extra\n"));
        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        let err = upgrade_v1(&env, &v1).unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true], "applied(0) is sent once, after every lock is released");
        assert_eq!(in_memory_main(&d), d.main_config(), "the doc is the disk again");
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"], "nothing was switched yet");
        assert!(!space0_path(&d, "synced").exists() && !d.ssh_dir().join(KEPT_FILE).exists(), "the stale doc is caught before any file is written");
        // 下一輪不必等前端重載:以磁碟上的內容重做,外部加的那一行留著。
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert!(d.main_config().ends_with("Host local\nHost extra\n"), "{}", d.main_config());
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"]);
    }

    #[test]
    fn upgrade_failures_from_a_limiting_or_failing_relay_back_off_and_a_success_clears_them() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, _) = v1_device("a", &relay, &clock, "Host web\n");
        d.runtime.focused.store(true, Ordering::SeqCst);
        let failed_rounds = || d.runtime.core.lock().unwrap().failed_rounds;
        relay.fail_creates_with_429(2);
        assert!(sync_once(&d.env()).is_err());
        assert_eq!((failed_rounds(), next_delay(&d.env())), (1, Duration::from_secs(90)));
        assert!(sync_once(&d.env()).is_err());
        assert_eq!((failed_rounds(), next_delay(&d.env())), (2, Duration::from_secs(180)));
        // relay 出錯(`5xx`)一樣算;連不上不算(那不是被限流、也不是 relay 出錯)。
        let account = crypto::derive_account(WORDS).unwrap().chain_id;
        relay.set_broken(&account, true);
        assert!(sync_once(&d.env()).is_err());
        assert_eq!((failed_rounds(), next_delay(&d.env())), (3, Duration::from_secs(360)));
        relay.set_broken(&account, false);
        relay.set_offline(true);
        assert!(sync_once(&d.env()).is_err());
        assert_eq!(failed_rounds(), 3);
        relay.set_offline(false);
        sync_once(&d.env()).unwrap();
        assert!(d.state().joined());
        assert_eq!(failed_rounds(), 0, "a finished upgrade clears the count");
    }

    #[test]
    fn a_keychain_that_cannot_give_the_sync_code_counts_as_failed_rounds_and_backs_off() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, _) = v1_device("a", &relay, &clock, "Host web\n");
        d.runtime.focused.store(true, Ordering::SeqCst);
        let failed_rounds = || d.runtime.core.lock().unwrap().failed_rounds;
        // 讀不到(上鎖、被拒):升級每一輪都要再讀一次 —— 不能以輪詢的頻率一直重試(通過系統 keychain 可能每一輪都跳出授權視窗)。
        d.keychain.fail_reads.store(true, Ordering::SeqCst);
        for (round, seconds) in [(1, 90), (2, 180), (3, 360)] {
            assert!(sync_once(&d.env()).is_err());
            assert_eq!((failed_rounds(), next_delay(&d.env())), (round, Duration::from_secs(seconds)));
            assert!(crate::sync::round::backoff_window(&d.env()) > Duration::ZERO);
        }
        d.keychain.fail_reads.store(false, Ordering::SeqCst);
        // 讀得到、卻沒有這個項目,或不是這個 chain 的同步碼:一樣只有使用者能處理,一樣退避。
        d.keychain.delete(MNEMONIC_ACCOUNT).unwrap();
        assert!(sync_once(&d.env()).is_err());
        assert_eq!(failed_rounds(), 4);
        d.keychain.set(MNEMONIC_ACCOUNT, &crypto::generate_mnemonic().unwrap()).unwrap();
        assert!(sync_once(&d.env()).is_err());
        assert_eq!(failed_rounds(), 5);
        assert!(d.state().last_error.unwrap().contains("different sync chain"));
        // 補回正確的同步碼:升級做完,計數歸零。
        d.keychain.set(MNEMONIC_ACCOUNT, WORDS).unwrap();
        sync_once(&d.env()).unwrap();
        assert!(d.state().joined());
        assert_eq!((failed_rounds(), crate::sync::round::backoff_window(&d.env())), (0, Duration::ZERO));
    }

    #[test]
    fn the_upgrade_creates_only_the_chains_that_are_missing_and_never_recreates_a_deleted_space0() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let creates = || relay.calls().iter().filter(|c| c.starts_with("create:")).count();
        let (a, v1a) = v1_device("a", &relay, &clock, "Host web\n");
        upgrade_v1(&a.env(), &v1a).unwrap();
        assert_eq!(creates(), 2, "the first device creates the account and space0");
        settle(&a);
        // 兩條 chain 都在:另一台升級、或升級失敗後重試,都不再 `PUT`(每一次都算進每 IP 每小時 20 次的建立額度)。
        relay.clear_calls();
        let (b, v1b) = v1_device("b", &relay, &clock, "Host web\n");
        let blocker = block_the_v1_state_backup(&b);
        assert!(upgrade_v1(&b.env(), &v1b).is_err());
        std::fs::remove_dir_all(&blocker).unwrap();
        assert!(upgrade_v1(&b.env(), &v1b).unwrap());
        assert_eq!(creates(), 0);
        // space0 在別台被刪掉:不重建,relay 上不會多出一條沒人用的 chain。
        delete_space(&a.env(), &space0()).unwrap();
        settle(&a);
        assert!(!relay.exists(&space0()));
        relay.clear_calls();
        let (c, v1c) = v1_device("c", &relay, &clock, "Host web\nHost mine\n");
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        assert_eq!(creates(), 0);
        assert!(!relay.exists(&space0()));
    }

    #[test]
    fn leaving_while_the_upgrade_talks_to_the_relay_stops_it_as_superseded() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, _) = v1_device("a", &relay, &clock, "Host web\nHost mine\n");
        let d = Arc::new(d);
        let leaver = Arc::clone(&d);
        let connector = HookedConnector::new(
            &relay,
            Hooks { before_create: Some(Box::new(move || leave_account(&leaver.env(), false).unwrap())), ..Hooks::default() },
        );
        let mut env = d.env();
        env.relays = &connector;
        // 使用者在升級連 relay 的時候離開了:不是升級的錯誤,也不留「could not upgrade」。
        sync_once(&env).unwrap();
        assert!(!d.state().joined() && d.runtime.core.lock().unwrap().legacy.is_none());
        assert_eq!(d.state().last_error, None);
        assert!(matches!(state_v2::load(&d.env().state_path).unwrap(), state_v2::LoadedState::Current(_)), "the state on disk is the leave's");
        // 升級沒有再動任何檔案:`hosts.config` 是離開搬到本機的,主機一直讀得到。
        assert!(!space0_path(&d, "synced").exists() && !d.ssh_dir().join(KEPT_FILE).exists());
        assert_eq!(ssh_hosts(&d), vec!["mine", "web"]);
    }

    #[test]
    fn leaving_between_the_files_and_the_state_swap_stops_the_upgrade_as_superseded() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost mine\n");
        let d = Arc::new(d);
        let leaver = Arc::clone(&d);
        before_swap(move || leave_account(&leaver.env(), false).unwrap());
        let err = upgrade_v1(&d.env(), &v1).unwrap_err();
        assert!(is_superseded(&err), "{err:?}");
        // 結果是離開的,不是升級的:未加入、沒有 `Upgraded`,升級換上的 space0 檔改成本機檔案,主機一直讀得到。
        assert!(!d.state().joined() && d.runtime.core.lock().unwrap().legacy.is_none());
        assert!(matches!(&d.state().notices[..], [SyncNotice::LeftAccount { .. }]), "{:?}", d.state().notices);
        assert_eq!(ssh_hosts(&d), vec!["mine", "web"]);
        assert!(matches!(state_v2::load(&d.env().state_path).unwrap(), state_v2::LoadedState::Current(_)));
    }

    #[test]
    fn a_rerun_still_lists_the_kept_hosts() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        restart_before_the_state_was_saved(&d, &v1);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        let kept_file = Some(d.ssh_dir().join(KEPT_FILE).to_string_lossy().into_owned());
        assert_eq!(d.state().notices, vec![SyncNotice::Upgraded { kept_file, kept_hosts: vec!["jump".into()], moved_files: Vec::new() }]);
    }

    // ── 修正輪 2:主 config 現在列著什麼,決定升級用哪個檔案;使用者自己的檔案、被擋下的移除、離開,都不能讓主機從 ssh 消失 ──

    /// 一個 space0 候選檔(`plan_sources` 的輸入)。
    fn leftover(name: &str, text: &str, listed: bool) -> Leftover {
        Leftover { name: name.to_string(), path: PathBuf::from("/ssh/sshelter").join(name), text: text.to_string(), listed }
    }

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(|n| PathBuf::from("/ssh/sshelter").join(n)).collect()
    }

    #[test]
    fn the_source_follows_what_the_main_config_lists() {
        const NEW: &str = "servers-aaaaaaaa.config";
        const OLD: &str = "synced-aaaaaaaa.config";
        let plan = |v1: Option<&str>, lists_v1: bool, gone: bool, candidates: &[Leftover]| plan_sources(v1, lists_v1, gone, NEW, candidates);
        // 列著 `hosts.config`:它是來源;沒列出的候選檔是 ssh 不讀的多餘檔案,移除、絕不併進 kept 檔(目標檔名那個會被取代,不移除)。
        let p = plan(Some("Host a\n"), true, false, &[leftover(NEW, "Host stale\n", false), leftover(OLD, "Host stale\n", false)]);
        assert_eq!(p, Plan { space_text: Some("Host a\n".into()), keep: vec![], obsolete: paths(&[OLD]) });
        // 沒列 `hosts.config`、列著前一次升級的 space0 檔:那個檔案是來源(使用者的修改在裡面),`hosts.config` 的內容一個字都不用。
        let p = plan(Some("Host old\n"), false, false, &[leftover(NEW, "Host edited\n", true), leftover(OLD, "Host stale\n", false)]);
        assert_eq!(p, Plan { space_text: None, keep: vec![], obsolete: paths(&[OLD]) });
        // 列著的是舊檔名(別台改過名):內容搬到現在的名稱,舊名稱清單換好之後移除;沒列出的新名稱複本被取代、不當來源。
        let p = plan(None, false, false, &[leftover(NEW, "Host stale\n", false), leftover(OLD, "Host edited\n", true)]);
        assert_eq!(p, Plan { space_text: Some("Host edited\n".into()), keep: vec![], obsolete: paths(&[OLD]) });
        // 兩個都列(手寫):`hosts.config` 是來源;列著的 space0 檔內容不同才併進 kept 檔,相同就不必。
        let p = plan(Some("Host a\n"), true, false, &[leftover(NEW, "Host b\n", true)]);
        assert_eq!(p, Plan { space_text: Some("Host a\n".into()), keep: vec!["Host b\n".into()], obsolete: vec![] });
        let p = plan(Some("Host a\n"), true, false, &[leftover(NEW, "Host a\n", true)]);
        assert_eq!(p, Plan { space_text: Some("Host a\n".into()), keep: vec![], obsolete: vec![] });
        // 兩個都沒列:`hosts.config` 還在就以它為準;不在就用前一次留下的 space0 檔(沒有任何東西讀得到它,照原本的做法)。
        let p = plan(Some("Host a\n"), false, false, &[leftover(OLD, "Host stale\n", false)]);
        assert_eq!(p, Plan { space_text: Some("Host a\n".into()), keep: vec![], obsolete: paths(&[OLD]) });
        let p = plan(None, false, false, &[leftover(OLD, "Host prev\n", false)]);
        assert_eq!(p, Plan { space_text: Some("Host prev\n".into()), keep: vec![], obsolete: paths(&[OLD]) });
        // space0 已被刪除:來源的內容全部改留在本機(kept 檔),所有候選檔(含目標檔名那個)清單換好之後移除。
        let p = plan(Some("Host a\nHost b\n"), true, true, &[leftover(NEW, "Host a\n", false)]);
        assert_eq!(p, Plan { space_text: None, keep: vec!["Host a\nHost b\n".into()], obsolete: paths(&[NEW]) });
        let p = plan(Some("Host old\n"), false, true, &[leftover(NEW, "Host edited\n", true), leftover(OLD, "Host stale\n", false)]);
        assert_eq!(p, Plan { space_text: None, keep: vec!["Host edited\n".into()], obsolete: paths(&[NEW, OLD]) });
    }

    #[test]
    fn a_hosts_config_that_could_not_be_removed_never_overwrites_what_the_user_adds_next() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost mine\n");
        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        fail_next_removal();
        let err = upgrade_v1(&env, &v1).unwrap_err();
        assert!(matches!(err, AppError::Io(_)), "{err:?}");
        // 清單已經換了:doc 重載成磁碟上現在的樣子(不再載入 `hosts.config`),前端在放掉所有鎖之後才被通知。
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true]);
        assert_eq!(memory_files(&d), vec!["config".to_string(), format!("synced-{}.config", &space0()[..8])]);
        assert!(hosts_file::managed_path(&d.ssh_dir()).exists(), "the removal was refused");
        assert_eq!(ssh_hosts(&d), vec!["mine", "web"]);
        // 這時使用者在列著的 space0 檔裡加了一台:下一輪不能用還留著的 `hosts.config` 把它蓋掉。
        d.save_in_app(&space0_path(&d, "synced"), "Host web\nHost mine\nHost added\n");
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(d.read(&space0_path(&d, "synced")), "Host web\nHost mine\nHost added\n");
        assert_eq!(ssh_hosts(&d), vec!["added", "mine", "web"]);
        assert!(!hosts_file::managed_path(&d.ssh_dir()).exists(), "the leftover is backed up and removed");
    }

    #[test]
    fn a_hosts_config_left_behind_after_the_switch_never_overwrites_the_users_edits() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\nHost mine\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        // 當機:`hosts.config` 沒被移除(還在、已不在清單上),狀態還是 v1。
        std::fs::write(hosts_file::managed_path(&d.ssh_dir()), hosts).unwrap();
        restart_before_the_state_was_saved(&d, &v1);
        // 使用者在 app 裡改了 space0 檔(改 web、刪 mine、加 added)與 kept 檔。
        let kept = d.ssh_dir().join(KEPT_FILE);
        d.save_in_app(&space0_path(&d, "synced"), "Host web\n  User changed\nHost added\n");
        d.save_in_app(&kept, "Host jump\n  ProxyJump bastion\n");
        assert_eq!(ssh_hosts(&d), vec!["added", "jump", "web"]);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["added", "jump", "web"], "no edit reverted, no deleted host back");
        assert_eq!(d.read(&space0_path(&d, "synced")), "Host web\n  User changed\nHost added\n");
        assert_eq!(d.read(&kept), "Host jump\n  ProxyJump bastion\n", "nothing is appended twice");
        assert!(!hosts_file::managed_path(&d.ssh_dir()).exists());
    }

    /// A 升級並同步、C 升級了一次(檔案換好)、app 重啟(狀態還是 v1)、A 把 space0 改名成 Servers。回傳(A, C, C 的 v1 狀態)。
    fn renamed_after_the_first_attempt(
        relay: &Arc<FakeRelay>,
        clock: &Arc<TestClock>,
        a_hosts: &str,
        c_hosts: &str,
    ) -> (TestDevice, TestDevice, SyncState) {
        let (a, v1a) = v1_device("a", relay, clock, a_hosts);
        upgrade_v1(&a.env(), &v1a).unwrap();
        settle(&a);
        let (c, v1c) = v1_device("c", relay, clock, c_hosts);
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        restart_before_the_state_was_saved(&c, &v1c);
        rename_space(&a.env(), &space0(), "Servers").unwrap();
        settle(&a);
        (a, c, v1c)
    }

    #[test]
    fn an_unlisted_leftover_never_overrides_the_file_the_main_config_lists() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (_a, c, v1c) = renamed_after_the_first_attempt(&relay, &clock, "Host web\n", "Host web\n  User root\nHost mine\n");
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        // 搬到新檔名的那次升級在移除舊檔之前就中斷了:舊名稱的複本還在(沒列出,ssh 不讀)。
        std::fs::write(space0_path(&c, "synced"), "Host web\n  User root\nHost mine\n").unwrap();
        restart_before_the_state_was_saved(&c, &v1c);
        // 使用者改了列著的新檔:拿掉 web 的 `User root`、刪掉 mine。
        c.save_in_app(&space0_path(&c, "servers"), "Host web\n");
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        assert_eq!(c.read(&space0_path(&c, "servers")), "Host web\n");
        assert!(!c.ssh_dir().join(KEPT_FILE).exists(), "the stale copy is not merged into what ssh reads");
        assert!(!space0_path(&c, "synced").exists(), "it is backed up and removed");
        assert_eq!(ssh_hosts(&c), vec!["web"], "the deleted host stays deleted");
    }

    #[test]
    fn a_rename_whose_list_switch_failed_keeps_what_the_user_edited_in_the_still_listed_old_file() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (_a, c, v1c) =
            renamed_after_the_first_attempt(&relay, &clock, "Host web\n  HostName 10.0.0.1\n", "Host web\n  HostName 10.0.0.1\nHost mine\n");
        // 搬到新檔名:新檔名寫好了、清單沒換成(寫主 config 失敗),列著的還是舊檔名。
        fail_next_main_write();
        assert!(upgrade_v1(&c.env(), &v1c).is_err());
        assert!(space0_path(&c, "servers").exists() && lists(&c, &space0_token("synced")) && !lists(&c, &space0_token("servers")));
        // 使用者改了列著的舊檔:web 換了 HostName、mine 刪掉。新檔名那份是還沒人讀的舊複本。
        c.save_in_app(&space0_path(&c, "synced"), "Host web\n  HostName 10.0.0.9\n");
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        assert_eq!(c.read(&space0_path(&c, "servers")), "Host web\n  HostName 10.0.0.9\n", "the edit moved to the new name");
        assert!(!space0_path(&c, "synced").exists() && !c.ssh_dir().join(KEPT_FILE).exists());
        assert!(lists(&c, &space0_token("servers")) && !lists(&c, &space0_token("synced")));
        assert_eq!(ssh_hosts(&c), vec!["web"], "the deleted host does not come back");
    }

    #[test]
    fn an_old_name_that_could_not_be_removed_never_comes_back_over_the_users_edit() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (_a, c, v1c) = renamed_after_the_first_attempt(&relay, &clock, "Host web\n", "Host web\n  User root\nHost mine\n");
        // 清單換成新檔名了,舊檔名卻移除不掉(檔案被鎖住)。
        fail_next_removal();
        assert!(upgrade_v1(&c.env(), &v1c).is_err());
        assert!(lists(&c, &space0_token("servers")) && space0_path(&c, "synced").exists());
        // 使用者改了列著的新檔。
        c.save_in_app(&space0_path(&c, "servers"), "Host web\n");
        assert!(upgrade_v1(&c.env(), &v1c).unwrap());
        assert_eq!(c.read(&space0_path(&c, "servers")), "Host web\n");
        assert!(!c.ssh_dir().join(KEPT_FILE).exists(), "the old copy is not merged into what ssh reads");
        assert!(!space0_path(&c, "synced").exists());
        assert_eq!(ssh_hosts(&c), vec!["web"]);
    }

    #[test]
    fn when_the_main_config_lists_both_files_nothing_ssh_reads_is_lost() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // 手寫的清單同時列著 `hosts.config` 與前一次升級的 space0 檔(內容不同):ssh 現在兩個都讀。
        let main = format!("# main\nInclude ~/.ssh/sshelter/hosts.config {}\nHost local\n", space0_token("synced"));
        let (d, v1) = v1_device_with_main("a", &relay, &clock, &main, "Host web\n");
        std::fs::write(space0_path(&d, "synced"), "Host web\nHost extra\n").unwrap();
        d.reload();
        assert_eq!(ssh_hosts(&d), vec!["extra", "web", "web"]);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        // `hosts.config` 是來源;列著的 space0 檔內容不同,它的區塊併進 kept 檔,ssh 讀得到的一台都沒少。
        assert_eq!(d.read(&space0_path(&d, "synced")), "Host web\n");
        assert_eq!(d.read(&d.ssh_dir().join(KEPT_FILE)), "Host web\nHost extra\n");
        assert_eq!(ssh_hosts(&d), vec!["extra", "web", "web"]);
    }

    #[test]
    fn without_our_include_the_v1_file_is_still_the_source_and_so_is_the_previous_attempts_file() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // 使用者拿掉了我們的 Include:ssh 讀不到 `hosts.config`;升級照原本的做法以它為準。
        let (d, v1) = v1_device_with_main("a", &relay, &clock, "# main\nHost local\n", "Host web\nHost mine\n");
        assert_eq!(ssh_hosts(&d), Vec::<String>::new());
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["mine", "web"]);
        // 之後 `hosts.config` 已經不在、使用者又拿掉清單裡的 space0 檔:前一次留下的 space0 檔是唯一留著主機的地方 —— 重新列進去。
        d.write_externally(&d.main_path(), "# main\nHost local\n");
        d.reload();
        restart_before_the_state_was_saved(&d, &v1);
        assert_eq!(ssh_hosts(&d), Vec::<String>::new());
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["mine", "web"]);
        assert!(lists(&d, &space0_token("synced")));
    }

    #[test]
    fn a_v1_users_own_file_under_the_sshelter_directory_stays_in_ssh() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // v1 只有 `hosts.config` 那個 token 是我們的:使用者自己的 `Include ~/.ssh/sshelter/mine.config` 一直讀得到。
        let main = "# main\nInclude ~/.ssh/sshelter/hosts.config\nInclude ~/.ssh/sshelter/mine.config\nHost local\n";
        let (d, v1) = v1_device_with_main("a", &relay, &clock, main, "Host web\n");
        std::fs::write(d.ssh_dir().join("sshelter").join("mine.config"), "Host minehost\n").unwrap();
        d.reload();
        assert_eq!(ssh_hosts(&d), vec!["minehost", "web"]);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["minehost", "web"], "the new list does not strip it");
        let moved = space_files::local_dir(&d.ssh_dir()).join("mine.config");
        assert_eq!(d.read(&moved), "Host minehost\n");
        assert!(!d.ssh_dir().join("sshelter").join("mine.config").exists());
        assert_eq!(d.main_config(), format!("# main\nInclude {}\nInclude ~/.ssh/sshelter-local/mine.config\nHost local\n", space0_token("synced")));
        // 提示列出搬走的檔案的新路徑。
        let moved_files = vec![moved.to_string_lossy().into_owned()];
        assert!(matches!(&d.state().notices[..], [SyncNotice::Upgraded { kept_file: None, moved_files: m, .. }] if *m == moved_files), "{:?}", d.state().notices);
    }

    #[test]
    fn a_handwritten_glob_over_the_sshelter_directory_keeps_the_users_files_in_ssh() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let main = "# main\nInclude ~/.ssh/sshelter/*.config\nHost local\n";
        let (d, v1) = v1_device_with_main("a", &relay, &clock, main, "Host web\n");
        let dir = d.ssh_dir().join("sshelter");
        std::fs::write(dir.join("mine.config"), "Host minehost\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "not a config\n").unwrap();
        d.reload();
        assert_eq!(ssh_hosts(&d), vec!["minehost", "web"]);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["minehost", "web"]);
        assert_eq!(d.read(&space_files::local_dir(&d.ssh_dir()).join("mine.config")), "Host minehost\n");
        assert_eq!(d.read(&dir.join("notes.txt")), "not a config\n", "only files the Include reads are touched");
        assert_eq!(d.main_config(), format!("# main\nInclude {}\nInclude ~/.ssh/sshelter-local/mine.config\nHost local\n", space0_token("synced")));
    }

    #[test]
    fn a_users_own_file_on_the_same_include_line_as_hosts_config_stays_in_ssh() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let main = "# main\nInclude ~/.ssh/sshelter/hosts.config ~/.ssh/sshelter/mine.config ~/.ssh/other.config\nHost local\n";
        let (d, v1) = v1_device_with_main("a", &relay, &clock, main, "Host web\n");
        std::fs::write(d.ssh_dir().join("sshelter").join("mine.config"), "Host minehost\n").unwrap();
        d.reload();
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["minehost", "web"]);
        // 一行裡我們的 token(`hosts.config`)被收走、使用者的檔案換成本機路徑留在原處,其他 token 照舊。
        assert_eq!(
            d.main_config(),
            format!("# main\nInclude {}\nInclude ~/.ssh/sshelter-local/mine.config ~/.ssh/other.config\nHost local\n", space0_token("synced"))
        );
    }

    #[test]
    fn a_failed_main_config_write_moves_none_of_the_users_files() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let main = "# main\nInclude ~/.ssh/sshelter/hosts.config\nInclude ~/.ssh/sshelter/mine.config\nHost local\n";
        let (d, v1) = v1_device_with_main("a", &relay, &clock, main, "Host web\n");
        let mine = d.ssh_dir().join("sshelter").join("mine.config");
        std::fs::write(&mine, "Host minehost\n").unwrap();
        d.reload();
        fail_next_main_write();
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        // 搬檔案與換清單是同一次寫入:失敗時新路徑移除、舊檔原地、清單沒變。
        assert_eq!(d.read(&mine), "Host minehost\n");
        assert!(!space_files::local_dir(&d.ssh_dir()).join("mine.config").exists());
        assert_eq!(d.main_config(), main);
        assert_eq!(in_memory_main(&d), main);
        assert_eq!(ssh_hosts(&d), vec!["minehost", "web"]);
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert_eq!(ssh_hosts(&d), vec!["minehost", "web"]);
        assert!(!mine.exists() && space_files::local_dir(&d.ssh_dir()).join("mine.config").exists());
    }

    #[test]
    fn a_state_that_cannot_be_saved_at_the_swap_still_tells_the_front_end_and_leaves_a_fresh_doc() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost jump\n  Include ~/.ssh/jump.config\n");
        // 檔案階段做完之後,狀態檔所在的 `data` 被一個一般檔案擋住:換狀態時存不了。
        let data = d.env().state_path.parent().unwrap().to_path_buf();
        before_swap(move || {
            std::fs::remove_dir_all(&data).unwrap();
            std::fs::write(&data, b"in the way").unwrap();
        });
        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        assert!(upgrade_v1(&env, &v1).is_err());
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true], "applied(0) is sent after every lock is released");
        // 記憶體裡已經是升級後的狀態(沒寫進磁碟,下一輪先補寫);doc 是磁碟上現在的樣子;主機都在。
        assert!(d.state().joined() && d.runtime.core.lock().unwrap().unsaved);
        assert_eq!(in_memory_main(&d), d.main_config());
        assert!(!memory_files(&d).contains(&"hosts.config".to_string()));
        assert_eq!(ssh_hosts(&d), vec!["jump", "web"]);
    }

    #[test]
    fn leaving_after_the_upgrade_finished_first_moves_the_joined_files_and_says_so() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let hosts = "Host web\nHost mine\nHost jump\n  Include ~/.ssh/jump.config\n";
        let (d, v1) = v1_device("a", &relay, &clock, hosts);
        let d = Arc::new(d);
        let upgrader = Arc::clone(&d);
        let extra = d.ssh_dir().join("sshelter").join("extra.config");
        let extra_path = extra.clone();
        // 使用者按離開、離開還沒拿到 doc 鎖的時候,背景的升級剛好做完了(狀態已經是已加入)。離開要在拿到 doc 鎖之後才決定「放棄升級」與否:
        // 這時 `legacy` 已經是空的,走已加入的離開 —— 搬這台勾選的 space 檔,`LeftAccount` 列得出它。這時主 config 多了一個手寫的 Include
        // (不是 space 檔):只有放棄升級才會把「Include 列著的每個檔案」搬走,已加入的離開不碰它。
        BEFORE_LEAVE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                assert!(upgrade_v1(&upgrader.env(), &v1).unwrap());
                std::fs::write(&extra_path, "Host extra\n").unwrap();
                let (old, new) = (format!("Include {}", space0_token("synced")), format!("Include {} ~/.ssh/sshelter/extra.config", space0_token("synced")));
                upgrader.save_in_app(&upgrader.main_path(), &upgrader.main_config().replacen(&old, &new, 1));
            }))
        });
        leave_account(&d.env(), false).unwrap();
        let kept = space_files::local_dir(&d.ssh_dir()).join(format!("synced-{}.config", &space0()[..8]));
        assert_eq!(d.read(&kept), "Host web\nHost mine\n");
        assert_eq!(d.read(&extra), "Host extra\n", "an ordinary leave does not move what only the Include lists");
        assert_eq!(ssh_hosts(&d), vec!["extra", "jump", "mine", "web"]);
        assert!(!d.state().joined() && d.keychain.entry(MNEMONIC_ACCOUNT).is_none());
        let notices = d.state().notices;
        assert!(
            matches!(&notices[..], [SyncNotice::Upgraded { .. }, SyncNotice::LeftAccount { kept_files }] if *kept_files == vec![kept.to_string_lossy().into_owned()]),
            "{notices:?}"
        );
    }

    #[test]
    fn a_v1_users_include_below_the_sshelter_directory_stays_in_ssh() {
        // 探針 S / S2:使用者自己的 Include 指到 `~/.ssh/sshelter/` 的子目錄,或經 `..` 指到 `~/.ssh/`:不是我們的 token(spec §4.3),升級換的新清單不收走。
        for (token, file) in [("~/.ssh/sshelter/sub/mine.config", "sshelter/sub/mine.config"), ("~/.ssh/sshelter/../outside.config", "outside.config")] {
            let (relay, clock) = (FakeRelay::new(), TestClock::new());
            let main = format!("# main\nInclude ~/.ssh/sshelter/hosts.config\nInclude {token}\nHost local\n");
            let (d, v1) = v1_device_with_main("a", &relay, &clock, &main, "Host web\n");
            let path = d.ssh_dir().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "Host minehost\n").unwrap();
            d.reload();
            assert_eq!(ssh_hosts(&d), vec!["minehost", "web"]);
            assert!(upgrade_v1(&d.env(), &v1).unwrap());
            assert_eq!(ssh_hosts(&d), vec!["minehost", "web"], "{token}");
            assert_eq!(d.read(&path), "Host minehost\n", "the file stays where the user put it");
            assert_eq!(d.main_config(), format!("# main\nInclude {}\nInclude {token}\nHost local\n", space0_token("synced")));
            assert!(matches!(&d.state().notices[..], [SyncNotice::Upgraded { moved_files, .. }] if moved_files.is_empty()), "{:?}", d.state().notices);
        }
    }

    #[test]
    fn leaving_after_an_upgrade_that_could_not_remove_hosts_config_drops_the_stale_file_instead_of_keeping_it() {
        // 探針 L:升級換好清單(space0 檔取代 `hosts.config`)、移除 `hosts.config` 被擋下,狀態還是 v1 —— 使用者離開。`hosts.config` 沒有任何 Include 讀它(內容是舊的):
        // 備份後移除,不改成本機檔案、也不列進 `LeftAccount`;以前它被搬進 `~/.ssh/sshelter-local/` 還被說成留下的主機,之後搬移精靈匯入它會把舊的、已刪的主機帶回來。
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost mine\n");
        fail_next_removal();
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        let stale = hosts_file::managed_path(&d.ssh_dir());
        assert!(stale.exists() && !lists(&d, "~/.ssh/sshelter/hosts.config"), "left behind, no longer listed");
        // 使用者之後在列著的 space0 檔裡刪了 mine:`hosts.config` 裡的 mine 是舊的。
        d.save_in_app(&space0_path(&d, "synced"), "Host web\n");
        // 升級那次嘗試留下的備份先清掉:接下來看到的備份,就是離開這一次做的。
        std::fs::remove_dir_all(fsutil::backup_dir_for(&stale).unwrap()).unwrap();
        leave_account(&d.env(), false).unwrap();
        let local = space_files::local_dir(&d.ssh_dir());
        let kept = local.join(format!("synced-{}.config", &space0()[..8]));
        assert_eq!(d.read(&kept), "Host web\n");
        assert!(!stale.exists() && !local.join("hosts.config").exists(), "the stale file is gone, not kept as a local file");
        assert_eq!(backups_of(&stale), vec!["Host web\nHost mine\n".to_string()], "it was backed up before it was removed");
        assert_eq!(d.state().notices, vec![SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }], "never named in the notice");
        assert_eq!(ssh_hosts(&d), vec!["web"], "the deleted host does not come back");
        assert!(!d.state().joined() && d.runtime.core.lock().unwrap().legacy.is_none());
    }

    #[test]
    fn a_stale_hosts_config_that_cannot_be_backed_up_is_left_alone_and_leaving_still_works() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\nHost mine\n");
        fail_next_removal();
        assert!(upgrade_v1(&d.env(), &v1).is_err());
        let stale = hosts_file::managed_path(&d.ssh_dir());
        // 備份的位置被一個一般檔案擋住:沒有備份,絕不移除。
        let mirror = fsutil::backup_dir_for(&stale).unwrap();
        std::fs::remove_dir_all(&mirror).unwrap();
        std::fs::write(&mirror, b"in the way").unwrap();
        leave_account(&d.env(), false).unwrap();
        assert_eq!(d.read(&stale), "Host web\nHost mine\n", "no backup, so it stays where it was");
        assert!(!space_files::local_dir(&d.ssh_dir()).join("hosts.config").exists());
        assert!(!d.state().joined() && matches!(&d.state().notices[..], [SyncNotice::LeftAccount { kept_files }] if kept_files.len() == 1));
        assert_eq!(ssh_hosts(&d), vec!["mine", "web"]);
    }

    #[test]
    fn the_upgrade_swap_asks_the_relay_for_its_features_again() {
        // `GET /v1/info` 每個行程、每個 relay URL 只查一次(`relay_checked`)。升級換狀態時 `relay_features` 清掉了,`relay_checked` 也要清:
        // 否則升級期間按過「Check relay」之後,這個行程不會再查,`SyncOverview::relay` 一直是 null。
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, v1) = v1_device("a", &relay, &clock, "Host web\n");
        crate::sync::account::check_relay(&d.env()).unwrap();
        assert_eq!(d.runtime.core.lock().unwrap().relay_checked.as_deref(), Some(RELAY_URL));
        assert!(upgrade_v1(&d.env(), &v1).unwrap());
        assert!(d.state().relay_features.is_none(), "the swap starts from a state that has not asked yet");
        assert!(d.runtime.core.lock().unwrap().relay_checked.is_none(), "so the process must ask again");
        relay.clear_calls();
        let _ = sync_once(&d.env());
        assert!(relay.calls().contains(&"info".to_string()), "{:?}", relay.calls());
        assert!(d.state().relay_features.is_some());
        assert!(crate::sync::dto::overview(&d.env()).unwrap().relay.is_some());
    }

    #[test]
    fn leaving_after_a_failed_upgrade_clears_the_upgrade_error_and_the_backoff() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let (d, _) = v1_device("a", &relay, &clock, "Host web\n");
        relay.fail_creates_with_429(1);
        assert!(sync_once(&d.env()).is_err());
        assert_eq!(d.runtime.core.lock().unwrap().failed_rounds, 1);
        d.keychain.delete(MNEMONIC_ACCOUNT).unwrap();
        assert!(sync_once(&d.env()).is_err());
        let message = d.state().last_error.unwrap();
        assert!(message.starts_with("SSHelter could not upgrade this device's sync yet") && message.contains("leave and join again"), "{message}");
        // 照說明離開:離開之後的狀態不該還帶著「could not upgrade」與退避的計數。
        leave_account(&d.env(), false).unwrap();
        assert!(!d.state().joined());
        assert_eq!(d.state().last_error, None);
        assert_eq!(d.runtime.core.lock().unwrap().failed_rounds, 0);
    }
}
