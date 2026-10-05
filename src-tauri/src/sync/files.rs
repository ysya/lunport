//! Space 檔在 in-memory doc 與磁碟上的處理(spec §4.3、§7.1):準備檔案與 Include 清單、讀取並檢查每個 space 檔、
//! 以 space 為單位的「套用 + 發布」交易、存檔當下的規劃。所有寫檔都在 doc 鎖內;呼叫 `persist_file` 時**不持有**
//! core 鎖(存檔 hook 會拿它)。引擎自己的寫入以 `EngineWrite` 標記,存檔 hook 不把它當成本機編輯。

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::config::commands::persist_file;
use crate::config::model::{ConfigFile, Item, SshConfigDoc};
use crate::config::serialize::serialize_items;
use crate::error::AppError;
use crate::fsutil::{self, Fingerprint};
use crate::sync::env::SyncEnv;
use crate::sync::hosts_file::{self, HostBlockText};
use crate::sync::merge::{plan_hosts, selected_include_tokens};
use crate::sync::reconcile::HostEffect;
use crate::sync::record::RecordKind;
use crate::sync::runtime::{save_core, superseded};
use crate::sync::space_files;
use crate::sync::state_v2::SpaceState;

thread_local! {
    static ENGINE_WRITING: Cell<bool> = const { Cell::new(false) };
}

/// 引擎自己套用遠端效果時寫 space 檔:`persist_file` → 存檔 hook 不可把這次寫入當成本機編輯(否則遠端內容會以
/// 「現在」的時間戳被當成本機修改重新上傳)。RAII:離開作用域(含 panic)就復原。
pub(crate) struct EngineWrite;

impl EngineWrite {
    pub(crate) fn begin() -> Self {
        ENGINE_WRITING.with(|w| w.set(true));
        EngineWrite
    }
}

impl Drop for EngineWrite {
    fn drop(&mut self) {
        ENGINE_WRITING.with(|w| w.set(false));
    }
}

pub(crate) fn engine_writing() -> bool {
    ENGINE_WRITING.with(|w| w.get())
}

/// 同步檔的不變式(spec §3.1/§6;Sync v2 以 space 為單位):只放具名、互不重複的 Host 區塊,且沒有 `Include` 或帶引號的
/// keyword 等 `hosts_file::Forbidden` 的每一種(另有行首的 `=`、會交給 shell 的值、看不見的字元、OpenSSH 讀法不同的
/// Host/Match 行;Sync v2 spec §4.3、§7.4)。違反時這個檔案停在讀檔階段(不 diff、不套用、不上傳),狀態列顯示要搬走/
/// 刪掉哪個區塊 —— 驗證過的遠端效果因此套用時不可能失敗。
pub fn check_managed_items(items: &[Item]) -> Result<(), AppError> {
    let mut seen = BTreeSet::new();
    for item in items {
        if let Item::Host(h) = item {
            if !hosts_file::is_syncable_block(&h.patterns) {
                return Err(AppError::Other(format!(
                    "the synced hosts file contains 'Host {}', which uses wildcard patterns; move that block to your main config",
                    h.patterns.join(" ")
                )));
            }
            if let Some(alias) = h.patterns.first() {
                if !seen.insert(alias.clone()) {
                    return Err(AppError::Other(format!(
                        "the synced hosts file defines '{alias}' more than once; remove the duplicate"
                    )));
                }
            }
        }
    }
    // 不允許的 directive(`hosts_file::Forbidden` 的每一種,從 Include、帶引號的 keyword 到 Host/Match 行;spec §4.3、§7.4):整個檔案都查,含 top-level。
    if let Some(f) = hosts_file::forbidden_directive(items) {
        return Err(AppError::Other(format!(
            "the synced hosts file contains {}, which synced hosts cannot use; move that block to your main config",
            f.describe()
        )));
    }
    Ok(())
}

/// 把效果套到區塊列表。回傳(是否改了任何東西, 套不上的 alias);壞掉的效果不中斷其他效果。
pub fn apply_effects_to_items(items: &mut Vec<Item>, effects: &[HostEffect]) -> (bool, Vec<String>) {
    let mut changed = false;
    let mut failed = Vec::new();
    for effect in effects {
        let result = match effect {
            HostEffect::Upsert { alias, text } => hosts_file::apply_host_text(items, alias, text),
            HostEffect::Delete { alias } => Ok(hosts_file::remove_host_block(items, alias)),
        };
        match result {
            Ok(c) => changed |= c,
            Err(_) => failed.push(effect.alias().to_string()),
        }
    }
    (changed, failed)
}

/// in-memory 的內容是否正是磁碟上的 bytes:用 `persist_file` 的同一個 serializer 與 `trailing_newline` 序列化後
/// 逐 byte 比對(parser 是 lossless 的,從磁碟載入或剛寫入的內容一定相等)。
pub(crate) fn items_match_disk(items: &[Item], trailing_newline: bool, disk: &[u8]) -> bool {
    serialize_items(items, trailing_newline).as_bytes() == disk
}

/// 只比指紋不夠:app 的某次寫入「先改 doc、寫檔才失敗」時,磁碟沒變、指紋照樣相符,in-memory 卻已經比磁碟新。
/// 讀不到檔一律當成不相符。
pub(crate) fn memory_matches_disk(file: &ConfigFile) -> bool {
    std::fs::read(&file.path).is_ok_and(|disk| items_match_disk(&file.items, file.trailing_newline, &disk))
}

/// `<ssh_dir>/sshelter/<file_name>`;狀態檔讀回來的檔名一律先經 `space_files::space_file_path` 驗證。
pub fn space_path(env: &SyncEnv, file_name: &str) -> Result<PathBuf, AppError> {
    space_files::space_file_path(&env.ssh_dir, file_name)
}

/// 主 config 最頂端的 Include 清單換成 `tokens`,有變才寫檔(spec §4.3)。呼叫端持有 doc 與 backed_up 鎖、**不持有**
/// core 鎖。
///
/// 全有或全無:寫檔失敗(`Conflict`:主 config 在載入之後被外部改過;或 I/O 錯誤)就把 in-memory 的項目退回原樣再回
/// Err。不退回的話 doc 比磁碟新 —— 下一次呼叫看到「清單已經是對的」就回 Ok、什麼都沒寫,呼叫端(取消勾選、改名)接著把
/// 磁碟上的清單還列著的 space 檔刪掉或改名,破壞 spec §4.3「清單絕不列出不存在的檔案」的順序。`Conflict` 之後磁碟與
/// doc 仍然不一致(磁碟被改過):呼叫端要整份重載(`prepare_files` 會)。
pub fn write_include(
    doc: &mut SshConfigDoc,
    backed_up: &mut HashSet<PathBuf>,
    retention: Option<usize>,
    tokens: &[String],
) -> Result<(), AppError> {
    let original = doc.files[0].items.clone();
    if hosts_file::ensure_include(&mut doc.files[0].items, tokens) {
        if let Err(e) = persist_file(doc, 0, backed_up, retention) {
            doc.files[0].items = original;
            return Err(e);
        }
    }
    Ok(())
}

/// 載入 doc 時讀得進來的檔案(`config::include` 的規則:一般檔案、讀得到、是 UTF-8 文字)。讀不進來的(斷掉的 symlink、目錄、
/// 沒有權限、不是文字)重載了也不會出現在 doc 裡 —— 為它重載只會每一輪都重載一次;它在讀檔時(`gather`)變成那個 space 的錯誤。
fn loadable(path: &Path) -> bool {
    path.is_file() && std::fs::read_to_string(path).is_ok()
}

/// 快取裡有未刪除的 host 記錄(已上傳的或還沒上傳的都算)。
fn holds_live_hosts(space: &SpaceState) -> bool {
    space.records.values().any(|l| l.record.kind == RecordKind::Host && !l.record.deleted)
}

/// space 檔不見了(以 space 為單位沿用 v1 的規則,spec §7.1):基線已建立、快取裡有未刪除的主機 → 不能做本機 diff
/// (重建出來的空檔會把每一台主機都變成刪除推給所有裝置),要從 chain 重新長出。
pub fn space_vanished(space: &SpaceState) -> bool {
    space.baseline_established && holds_live_hosts(space)
}

/// space 檔還在、卻一個 Host 區塊都沒有(被清空):同 `space_vanished`。
pub fn space_emptied(blocks: &[HostBlockText], space: &SpaceState) -> bool {
    blocks.is_empty() && space_vanished(space)
}

/// 從 chain 重新長出一個 space 檔:丟掉已上傳的 host 記錄、保留還沒上傳的,
/// cursor 歸零、回到基線輪。待核准與拒絕的記錄保留;它們的 alias 在快取裡的那一版(這台目前套用的、乾淨的記錄)也保留 —— chain 上
/// 較新的那一版還在等核准或已被拒絕,基線輪不會套用它;這一版由基線輪寫回檔案(`merge::unpushed_host_effects`),主機不會從檔案消失。
pub fn reset_space_for_rematerialize(space: &mut SpaceState) {
    let reviewed: BTreeSet<String> = space.pending_approvals.keys().chain(space.declined.keys()).cloned().collect();
    space.records.retain(|_, l| l.record.kind != RecordKind::Host || l.dirty || reviewed.contains(&l.record.id));
    space.cursor_seq = 0;
    space.baseline_established = false;
}

/// `prepare_files` 的結果。
#[derive(Debug, Default, PartialEq)]
pub struct Prepared {
    /// 整份重載了 in-memory doc:呼叫端放掉所有鎖之後通知前端(`events.applied(0)`)。
    pub reloaded: bool,
    /// space 檔不見了、已改成從 chain 重新長出的 space(已存檔、已換 generation):這一輪到此為止。
    pub rematerialized: Vec<String>,
}

/// 準備每個勾選的 space 檔(spec §4.3、§7.1)。doc 還沒載入或沒加入帳戶 → `Ok(None)`,什麼都不碰。
/// 1. 勾選的 space 檔不在就建空檔(0600,目錄 0700;`space_files::create_empty_space_file`:剛出現的檔案或斷掉的 symlink 不會被
///    取代,已經有了就留著)
///    —— 先建檔、再列進 Include。檔案不見了而快取裡有未刪除的主機(`space_vanished`)時,**先**把那個 space 改成從 chain
///    重新長出、換 generation、存檔,存成功才建空檔(空檔一旦存在,之後就分不出「檔案不見了」和「主機都刪光了」)。
/// 2. 主 config 最頂端那一行 Include 換成目前勾選的清單(沒有勾選就移除)。寫不進去(`write_include` 已把 in-memory 退回
///    原樣)就在這裡停下、**不刪任何檔案**;若是 `Conflict`(主 config 在載入之後被外部改過)還要整份重載,並在放掉所有鎖
///    之後自己 `events.applied(0)`(沒有 `Prepared` 可以帶這個旗標)再回 Err —— 下一輪以磁碟上的內容重做。
/// 3. 取消勾選做到一半(`selected` = false)的 space:已不在清單上 → 備份並刪檔,再刪掉它的狀態。
/// 4. 有勾選的 space 檔還沒載入 doc(剛建立、剛改名)、刪了檔,或 Include 那一行改了(手寫的 glob 換成明確清單之後,doc 裡
///    還留著 ssh 已經不讀的檔案;同 v1)→ 整份重載。重載也載不進來的檔案(`loadable`:斷掉的 symlink 等)不算「還沒載入」:
///    否則每一輪都重載一次,它留給讀檔變成那個 space 的錯誤。
pub fn prepare_files(env: &SyncEnv) -> Result<Option<Prepared>, AppError> {
    let mut doc_lock = env.doc.lock().unwrap();
    let Some(doc) = doc_lock.as_mut() else { return Ok(None) };
    let mut backed_up = env.backed_up.lock().unwrap();
    let retention = env.retention();
    let spaces = match env.runtime.core.lock().unwrap().state.as_ref() {
        Some(s) if s.joined() => s.spaces.clone(),
        _ => return Ok(None),
    };
    let mut prepared = Prepared::default();
    for (id, space) in spaces.iter().filter(|(_, s)| s.selected) {
        let path = space_path(env, &space.file_name)?;
        // 只有「確定不存在」才算不見了:查不到 metadata 是錯誤,不能拿空檔蓋掉既有內容。
        if path.try_exists()? {
            continue;
        }
        if space_vanished(space) {
            let mut core = env.runtime.core.lock().unwrap();
            if let Some(s) = core.state.as_mut().and_then(|s| s.spaces.get_mut(id)) {
                reset_space_for_rematerialize(s);
            }
            core.generation += 1; // 持有 doc 鎖:在途輪次的舊快照作廢
            save_core(&mut core, &env.state_path)?;
            prepared.rematerialized.push(id.clone());
        }
        space_files::create_empty_space_file(&path)?;
    }
    let tokens = {
        let core = env.runtime.core.lock().unwrap();
        let s = core.state.as_ref().ok_or_else(superseded)?;
        selected_include_tokens(s.account.as_ref(), &s.spaces)?
    };
    let include_before = doc.files[0].fingerprint.clone();
    if let Err(e) = write_include(doc, &mut backed_up, retention, &tokens) {
        if !matches!(e, AppError::Conflict(_)) {
            return Err(e);
        }
        // 主 config 在載入之後被外部改過:磁碟上的清單沒動(取消勾選的檔案還列在上面,所以一個也不能刪),in-memory 的
        // 也已退回原樣。整份重載讓 doc 回到磁碟上的內容,下一輪就能在正確的基礎上重寫清單;通知在放掉所有鎖之後。
        let main = doc.files[0].path.clone();
        let error = match env.load_doc(&main) {
            Ok(fresh) => {
                *doc_lock = Some(fresh);
                e
            }
            Err(reload) => {
                *doc_lock = None;
                AppError::Other(format!("{e}; reloading the config afterwards also failed: {reload}"))
            }
        };
        drop(backed_up);
        drop(doc_lock);
        env.events.applied(0);
        return Err(error);
    }
    // 主 config 真的被寫了(指紋換了)= Include 清單變了:doc 是照舊的清單載入的,可能還留著 ssh 已經不讀的檔案。
    let include_changed = doc.files[0].fingerprint != include_before;
    let mut removed = false;
    for (id, space) in spaces.iter().filter(|(_, s)| !s.selected) {
        space_files::remove_space_file(&env.ssh_dir, &space.file_name, || Ok(()))?;
        let mut core = env.runtime.core.lock().unwrap();
        if let Some(s) = core.state.as_mut() {
            s.spaces.remove(id);
        }
        core.generation += 1;
        save_core(&mut core, &env.state_path)?;
        removed = true;
    }
    let unloaded = spaces
        .values()
        .filter(|s| s.selected)
        .filter_map(|s| space_path(env, &s.file_name).ok())
        .any(|p| !doc.files.iter().any(|f| f.path == p) && loadable(&p));
    if unloaded || removed || include_changed {
        let main = doc.files[0].path.clone();
        *doc_lock = Some(env.load_doc(&main)?);
        prepared.reloaded = true;
    }
    Ok(Some(prepared))
}

/// 一個 space 檔讀到的內容:區塊、當時的指紋(套用前要再比一次)、檔案 mtime(外部編輯的時間戳)。
#[derive(Clone, Debug)]
pub struct Gathered {
    pub blocks: Vec<HostBlockText>,
    pub fingerprint: Fingerprint,
    pub modified_ms: u64,
}

/// 每個 space 的讀檔結果:Err = 違反不變式或讀不到(訊息給狀態列)。
pub type GatherResults = BTreeMap<String, Result<Gathered, String>>;

/// 讀取每個 space 檔並檢查不變式(spec §7.1 第 2 步)。任何一個 space 檔被手改過(指紋不同)或 in-memory 內容
/// 不是磁碟上的內容,先整份重載一次。每個 space 各自回 Ok 或 Err(違反不變式或讀不到 —— 只暫停那個 space)。
/// 回傳(每個 space 的結果, 是否重載了 doc)。
pub fn gather(
    env: &SyncEnv,
    spaces: &[(String, PathBuf)],
) -> Result<(GatherResults, bool), AppError> {
    let mut doc_lock = env.doc.lock().unwrap();
    let doc = doc_lock.as_ref().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let stale = spaces.iter().any(|(_, path)| {
        doc.files
            .iter()
            .find(|f| &f.path == path)
            .is_some_and(|f| fsutil::has_changed(path, &f.fingerprint).unwrap_or(true) || !memory_matches_disk(f))
    });
    let mut reloaded = false;
    if stale {
        let main = doc.files[0].path.clone();
        *doc_lock = Some(env.load_doc(&main)?);
        reloaded = true;
    }
    let doc = doc_lock.as_ref().expect("just loaded");
    let mut out = BTreeMap::new();
    for (id, path) in spaces {
        let result = match doc.files.iter().find(|f| &f.path == path) {
            None => Err("the space file could not be read; make sure it is a readable text file".to_string()),
            Some(f) => match check_managed_items(&f.items) {
                Err(e) => Err(e.to_string()),
                Ok(()) => {
                    // 外部編輯的時間戳 = 檔案 mtime(整檔的近似值,同 v1);拿不到就退回現在。
                    let modified_ms = std::fs::metadata(path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or_else(|| env.now());
                    Ok(Gathered { blocks: hosts_file::blocks_of(&f.items), fingerprint: f.fingerprint.clone(), modified_ms })
                }
            },
        };
        out.insert(id.clone(), result);
    }
    Ok((out, reloaded))
}

/// `apply_and_commit_space` 的結果。
#[derive(Debug)]
pub enum Applied {
    /// 效果已寫入(或沒有要寫的)、這個 space 的新區段已發布;`wrote` = 真的寫了檔;`save_error` = 狀態沒能寫進磁碟
    /// (`unsaved` 已標記)。檔案已經改了,所以通知照樣要做,呼叫端之後才停下。
    Committed { wrote: bool, save_error: Option<AppError> },
    /// space 檔在讀取之後變過(app 存檔、外部編輯或 `persist_file` 的 Conflict):這個 space 本輪作廢,立刻重跑。
    FileChanged,
}

/// 一個 space 的「套用 + 發布」交易(spec §7.1 第 6 步,全有或全無):全程持有 doc
/// 鎖 —— 比 generation → 比讀取時的指紋(不論有沒有效果都比)→ 在副本上套效果 → 寫檔 → 只把**這個 space 的區段**
/// 換成 `next`(局部提交,spec §12 #8)。寫檔失敗先退回、再從磁碟重載:磁碟上若正是剛寫的內容(寫入其實已提交)就
/// 照常發布,否則本 space 作廢。通知在鎖放掉之後(`events.applied(0)`:doc 重載過)。
///
/// 整個區段換成 `next`(只保留 `rename_blocked`)之所以安全,靠這個不變式:**其他執行緒上任何會寫 space 區段的路徑都換
/// generation**(`mutate`、`prepare_files`、`note_written`,或在 doc 鎖內自己換)。同步輪次自己用 `commit` 寫的(本機
/// diff 與暫停、`space_error`、`missing`、上傳結果)都在同一個執行緒上、與這裡依序發生:`next` 由那些寫入之後的工作副本
/// 算出,上傳結果在這裡發布之後才寫。`rename_blocked` 由帳戶那一步寫(不換 generation),所以這裡保留最新的;其他欄位在本輪
/// 開始之後被別的執行緒動過,generation 就變了,這裡會先被 `superseded()` 擋下、不會發布。往後新增的寫入者若在別的執行緒
/// 又不換 generation,就必須像 `rename_blocked` 一樣在這裡保留。
pub fn apply_and_commit_space(
    env: &SyncEnv,
    generation: u64,
    space_id: &str,
    path: &Path,
    gathered: &Fingerprint,
    effects: &[HostEffect],
    next: &SpaceState,
) -> Result<Applied, AppError> {
    let mut doc_lock = env.doc.lock().unwrap();
    if env.runtime.core.lock().unwrap().generation != generation {
        return Err(superseded());
    }
    let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let idx = doc
        .files
        .iter()
        .position(|f| f.path == path)
        .ok_or_else(|| AppError::Other("the space file is not loaded".to_string()))?;
    if doc.files[idx].fingerprint != *gathered
        || fsutil::has_changed(path, &doc.files[idx].fingerprint).unwrap_or(true)
        || !memory_matches_disk(&doc.files[idx])
    {
        return Ok(Applied::FileChanged);
    }
    let mut wrote = false;
    if !effects.is_empty() {
        let mut items = doc.files[idx].items.clone();
        let (changed, failed) = apply_effects_to_items(&mut items, effects);
        if !failed.is_empty() {
            // space 檔已通過不變式、遠端文字已通過 validate_host_text:走到這裡是 bug。全有或全無(只報數量)。
            return Err(AppError::Other(format!(
                "{} synced host record(s) could not be applied; nothing was changed",
                failed.len()
            )));
        }
        if changed {
            // 新建的 space 檔是空的、沒有結尾換行:第一次寫入主機時補上,檔案才是一般文字檔的樣子。
            let original_newline = doc.files[idx].trailing_newline;
            doc.files[idx].trailing_newline = original_newline || doc.files[idx].items.is_empty();
            let expected = serialize_items(&items, doc.files[idx].trailing_newline);
            let original = std::mem::replace(&mut doc.files[idx].items, items);
            let written = {
                let mut backed_up = env.backed_up.lock().unwrap();
                let retention = env.retention();
                let _engine = EngineWrite::begin();
                persist_file(doc, idx, &mut backed_up, retention)
            };
            if let Err(e) = written {
                doc.files[idx].items = original;
                doc.files[idx].trailing_newline = original_newline;
                let main = doc.files[0].path.clone();
                match env.load_doc(&main) {
                    Ok(fresh) => *doc_lock = Some(fresh),
                    Err(reload) => {
                        *doc_lock = None;
                        drop(doc_lock);
                        env.events.applied(0);
                        return Err(AppError::Other(format!("{e}; reloading the config afterwards also failed: {reload}")));
                    }
                }
                let committed = std::fs::read_to_string(path).map(|t| t == expected).unwrap_or(false);
                if !committed {
                    drop(doc_lock);
                    env.events.applied(0);
                    return match e {
                        AppError::Conflict(_) => Ok(Applied::FileChanged),
                        other => Err(other),
                    };
                }
            }
            wrote = true;
        }
    }
    // 仍持有 doc 鎖:generation 在這段期間不可能變,再比一次當防線,然後只發布這個 space 的區段。
    let save_error = {
        let mut core = env.runtime.core.lock().unwrap();
        if core.generation != generation {
            return Err(superseded());
        }
        let section = core.state.as_mut().and_then(|s| s.spaces.get_mut(space_id)).ok_or_else(superseded)?;
        // 改名被擋的記號由帳戶那一步(`spaces::reconcile_space_files`)維護,這一輪的合併結果不碰它:保留最新的,否則
        // 本輪開始時的快照會把它蓋掉、下一輪又重複提示。
        let rename_blocked = section.rename_blocked.take();
        *section = next.clone();
        section.rename_blocked = rename_blocked;
        save_core(&mut core, &env.state_path).err()
    };
    Ok(Applied::Committed { wrote, save_error })
}

/// 存檔 hook 的本體(spec §7.1「note_file_written」):app 寫完任何檔案後,呼叫端持有 doc 鎖時呼叫(鎖順序 doc →
/// core)。依路徑找出所屬的 space,在**存檔當下**把這次編輯規劃成 dirty 記錄(時間戳 = 存檔時間)、持久化,並換
/// generation 讓在途輪次的舊快照作廢。引擎自己的寫入(`EngineWrite`)、不屬於任何勾選 space 的檔案都不算。基線輪
/// 還沒跑或檔案違反不變式時不規劃(交給同步輪次),但一樣換 generation。唯一發出的通知是最後的 `events.wake_implicit()`(存檔是順便的喚醒:退避期間不會提早開始
/// 一輪,spec §6.4):它在呼叫端還持有 doc(與 backed_up)鎖時發出,所以必須是不阻塞的送出(見 `env::SyncEvents`)。
pub fn note_written(env: &SyncEnv, path: &Path, items: &[Item]) {
    if engine_writing() {
        return;
    }
    let now = env.now();
    env.runtime.note_activity(now);
    {
        let mut core = env.runtime.core.lock().unwrap();
        let Some(s) = core.state.as_mut().filter(|s| s.joined()) else { return };
        let Some(space_id) = s
            .spaces
            .iter()
            .find(|(_, sp)| sp.selected && space_files::space_file_path(&env.ssh_dir, &sp.file_name).is_ok_and(|p| p == path))
            .map(|(id, _)| id.clone())
        else {
            return;
        };
        let device_id = s.device_id.clone();
        let space = s.spaces.get_mut(&space_id).expect("found above");
        let planned = if space.baseline_established && check_managed_items(items).is_ok() {
            plan_hosts(space, &hosts_file::blocks_of(items), &device_id, |_| now)
        } else {
            0
        };
        core.generation += 1;
        if planned > 0 {
            if let Err(e) = save_core(&mut core, &env.state_path) {
                // 檔案已寫成功,只是同步狀態沒存下來:`unsaved` 讓下一輪在任何網路操作前先重存。
                if let Some(s) = core.state.as_mut() {
                    s.last_error = Some(format!("sync state could not be saved after a local edit: {e}"));
                }
            }
        }
    }
    env.events.wake_implicit();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::parse_file;
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::record::{record_key, LocalRecord, Record};
    use crate::sync::testkit::{AppliedProbe, TestClock, TestDevice};

    fn host(alias: &str, deleted: bool, dirty: bool) -> (String, LocalRecord) {
        let record = Record {
            kind: RecordKind::Host,
            id: alias.into(),
            version: 1,
            updated_at_ms: 5,
            device_id: "dev-a".into(),
            deleted,
            payload: serde_json::json!({ "schema": 1, "text": format!("Host {alias}\n") }),
        };
        (record_key(RecordKind::Host, alias), LocalRecord { record, seq: 3, dirty })
    }

    #[test]
    fn effects_are_applied_in_order_and_report_whether_anything_changed() {
        let (mut items, _) = parse_file("Host a\n  User x\n\nHost b\n");
        let effects = vec![
            HostEffect::Upsert { alias: "a".into(), text: "Host a\n  User y\n\n".into() },
            HostEffect::Delete { alias: "b".into() },
            HostEffect::Upsert { alias: "c".into(), text: "Host c\n".into() },
        ];
        let (changed, failed) = apply_effects_to_items(&mut items, &effects);
        assert!(changed);
        assert!(failed.is_empty());
        assert_eq!(serialize_items(&items, true), "Host a\n  User y\n\nHost c\n");
        assert_eq!(apply_effects_to_items(&mut items, &[]), (false, Vec::new()));
    }

    #[test]
    fn a_broken_effect_does_not_stop_the_others_and_is_reported_by_alias() {
        // 純函式的回報語意;引擎本身把任何失敗當成全有或全無的中止(見 `apply_and_commit_space`)。
        let (mut items, _) = parse_file("Host a\nHost web *.internal\n  User ops\n");
        let effects = vec![
            HostEffect::Upsert { alias: "web".into(), text: "Host web\n  User root\n".into() },
            HostEffect::Upsert { alias: "bad".into(), text: "# not a host\n".into() },
            HostEffect::Upsert { alias: "ok".into(), text: "Host ok\n".into() },
        ];
        let (changed, failed) = apply_effects_to_items(&mut items, &effects);
        assert!(changed);
        assert_eq!(failed, vec!["web".to_string(), "bad".to_string()]);
        let text = serialize_items(&items, true);
        assert!(text.contains("Host ok"));
        assert!(text.contains("Host web *.internal\n  User ops\n"), "local wildcard block untouched");
        assert!(!text.contains("User root"));
    }

    #[test]
    fn managed_file_must_hold_only_named_unique_hosts() {
        let ok = parse_file("# synced\n\nHost a\n  User x\nHost b b.example.com\n").0;
        assert!(check_managed_items(&ok).is_ok());
        let wildcard = parse_file("Host a\nHost web *.internal\n").0;
        assert!(check_managed_items(&wildcard).unwrap_err().to_string().contains("wildcard"));
        let negated = parse_file("Host web !prod\n").0;
        assert!(check_managed_items(&negated).is_err());
        let dup = parse_file("Host a\n  User x\nHost a\n").0;
        assert!(check_managed_items(&dup).unwrap_err().to_string().contains("more than once"));
    }

    #[test]
    fn managed_file_may_not_contain_forbidden_directives() {
        let in_block = parse_file("Host a\n  Include ~/.ssh/extra.config\n").0;
        assert!(check_managed_items(&in_block).unwrap_err().to_string().contains("Include"));
        let top_level = parse_file("Include ~/.ssh/extra.config\nHost a\n").0;
        assert!(check_managed_items(&top_level).is_err());
        let quoted = parse_file("Host a\n  \"ProxyCommand\" nc evil.example 22\n").0;
        assert!(check_managed_items(&quoted).unwrap_err().to_string().contains("quoted keyword"));
        // 行首的 `=`:OpenSSH 略過它、把下一個詞當成 keyword;解析器的 keyword 是空字串。
        let leading_equals = parse_file("Host a\n  =Include ~/.ssh/extra.config\n").0;
        assert!(check_managed_items(&leading_equals).unwrap_err().to_string().contains("starting with '='"));
        // 訊息不回顯 keyword 或那一行:keyword 可能夾著值(`IdentityFile"/path"`),訊息會進狀態列與 last_error。
        let carries_a_value = parse_file("Host a\n  IdentityFile\"/Users/me/.ssh/id_work\"\n").0;
        let message = check_managed_items(&carries_a_value).unwrap_err().to_string();
        assert!(message.contains("quoted keyword") && !message.contains("id_work"), "{message}");
        assert!(check_managed_items(&parse_file("Host a\n  # Include ~/.ssh/extra.config\n").0).is_ok());
        // Host / Match 那一行 OpenSSH 讀到的 pattern 與解析器不同:`Host web#x *` 對解析器是具名的 `web`(通過 wildcard 檢查),
        // OpenSSH 讀到的卻是 `web#x` 與 `*`。訊息不回顯那一行。
        let glued = parse_file("Host a\nHost web#x *\n  HostName attacker.example.net\n").0;
        let message = check_managed_items(&glued).unwrap_err().to_string();
        assert!(message.contains("a Host line that OpenSSH reads differently") && !message.contains("attacker"), "{message}");
        let glued_match = parse_file("Host a\nMatch host a#x,*\n  User root\n").0;
        assert!(check_managed_items(&glued_match).unwrap_err().to_string().contains("a Match line that OpenSSH reads differently"));
        assert!(check_managed_items(&parse_file("Host web # office\n  User a\nMatch host web # c\n  User b\n").0).is_ok());
    }

    #[test]
    fn managed_file_may_not_contain_values_ssh_would_hand_to_a_shell_or_invisible_characters() {
        // `HostName` / `User` / `HostKeyAlias` / `ProxyJump` 的值會被 ssh 原樣展開進指令:整個檔案都查,含 top-level 與
        // Match 區塊內;訊息只說是哪個 keyword,不回顯值(它會進狀態列與 last_error)。
        for text in [
            "Host a\n  HostName \"secret.example$(id)\"\n",
            "User \"secret$(id)\"\nHost a\n",
            "Host a\nMatch all\n  ProxyJump \"secret.example;id\"\n",
        ] {
            let message = check_managed_items(&parse_file(text).0).unwrap_err().to_string();
            assert!(message.contains("value with characters ssh would pass to a shell"), "{message}");
            assert!(message.ends_with("which synced hosts cannot use; move that block to your main config"), "{message}");
            assert!(!message.contains("secret"), "{message}");
        }
        // OpenSSH 不把非 ASCII 的空白與控制字元當成空白,解析器與簽章卻會把它們吃掉。
        let invisible = parse_file("Host a\n  ForwardAgent no\u{a0}\n").0;
        let message = check_managed_items(&invisible).unwrap_err().to_string();
        assert!(message.contains("non-ASCII space or control character"), "{message}");
        // 正常的值與 CRLF 的檔案照常通過。
        assert!(check_managed_items(&parse_file("Host a\n  HostName 10.0.0.5 # office\n  User deploy\n  ProxyJump bastion,user@jump:2222\n").0).is_ok());
        assert!(check_managed_items(&parse_file("Host a\r\n  HostName 10.0.0.5\r\n  User deploy\r\n").0).is_ok());
    }

    #[test]
    fn in_memory_items_must_match_the_disk_bytes_exactly() {
        let text = "Host web\n  HostName 10.0.0.1\n\nHost db\n";
        let (mut items, trailing_newline) = parse_file(text);
        assert!(items_match_disk(&items, trailing_newline, text.as_bytes()));
        // 少了結尾換行 = 不同的 bytes。
        assert!(!items_match_disk(&items, false, text.as_bytes()));
        // doc 被改了、寫檔卻沒成功:in-memory 比磁碟新。
        hosts_file::apply_host_text(&mut items, "app", "Host app\n").unwrap();
        assert!(!items_match_disk(&items, trailing_newline, text.as_bytes()));
        // 空檔。
        let (empty, trailing) = parse_file("");
        assert!(items_match_disk(&empty, trailing, b""));
    }

    #[test]
    fn a_disk_file_matches_its_freshly_loaded_items_and_not_an_unsaved_edit() {
        // 只用暫存目錄。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.config");
        std::fs::write(&path, "Host web\n  User x\n").unwrap();
        let (items, trailing_newline) = parse_file(&std::fs::read_to_string(&path).unwrap());
        let mut file = ConfigFile {
            path: path.clone(),
            items,
            trailing_newline,
            fingerprint: fsutil::file_fingerprint(&path).unwrap(),
        };
        assert!(memory_matches_disk(&file));
        hosts_file::remove_host_block(&mut file.items, "web");
        assert!(!memory_matches_disk(&file), "an edit that never reached the disk");
        std::fs::remove_file(&path).unwrap();
        assert!(!memory_matches_disk(&file), "an unreadable file never counts as matching");
    }

    #[test]
    fn engine_writes_are_flagged_only_inside_the_guard() {
        assert!(!engine_writing());
        {
            let _write = EngineWrite::begin();
            assert!(engine_writing());
        }
        assert!(!engine_writing());
    }

    #[test]
    fn space_files_are_created_before_they_are_listed_and_listed_in_name_order() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::with_main_config("a", &relay, &clock, "# main\nInclude ~/.ssh/sshelter/hosts.config\nHost local\n");
        let ids = d.join_with_spaces(&["Work", "home"]);
        let prepared = prepare_files(&d.env()).unwrap().unwrap();
        assert!(prepared.reloaded && prepared.rematerialized.is_empty());
        let (work, home) = (d.space_path(&ids[0]), d.space_path(&ids[1]));
        assert_eq!(d.read(&work), "");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&work).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let line = format!(
            "Include ~/.ssh/sshelter/{} ~/.ssh/sshelter/{}",
            home.file_name().unwrap().to_string_lossy(),
            work.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(d.main_config(), format!("# main\n{line}\nHost local\n"), "the v1 token is replaced, names sort case-insensitively");
        let loaded: Vec<PathBuf> = d.doc.lock().unwrap().as_ref().unwrap().files.iter().map(|f| f.path.clone()).collect();
        assert!(loaded.contains(&work) && loaded.contains(&home));
        // 第二次:什麼都不用做。
        assert_eq!(prepare_files(&d.env()).unwrap().unwrap(), Prepared::default());
    }

    #[test]
    fn a_half_unselected_space_is_unlisted_then_backed_up_and_deleted() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work", "Home"]);
        prepare_files(&d.env()).unwrap();
        let work = d.space_path(&ids[0]);
        d.write_externally(&work, "Host a\n");
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&ids[0]).unwrap().selected = false;
        let prepared = prepare_files(&d.env()).unwrap().unwrap();
        assert!(prepared.reloaded);
        assert!(!work.exists());
        assert!(!d.main_config().contains(&work.file_name().unwrap().to_string_lossy().to_string()));
        assert!(!d.state().spaces.contains_key(&ids[0]));
        assert!(d.state().spaces.contains_key(&ids[1]));
        // 刪檔之前先備份:備份在 `fsutil::backups_root()` 的鏡像目錄(測試建置是暫存目錄),內容就是刪除前的檔案。
        let name = work.file_name().unwrap().to_string_lossy().to_string();
        let backups: Vec<PathBuf> = std::fs::read_dir(fsutil::backup_dir_for(&work).unwrap())
            .expect("the backup directory exists")
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(&name))
            .collect();
        assert_eq!(backups.len(), 1, "{backups:?}");
        assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), "Host a\n");
    }

    #[test]
    fn a_vanished_space_file_is_restored_from_the_chain_and_the_other_spaces_are_untouched() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work", "Home"]);
        prepare_files(&d.env()).unwrap();
        {
            let mut core = d.runtime.core.lock().unwrap();
            let s = core.state.as_mut().unwrap();
            for id in &ids {
                let space = s.spaces.get_mut(id).unwrap();
                space.cursor_seq = 9;
                space.records.extend([host("web", false, false), host("edited", false, true), host("old", true, false)]);
            }
        }
        std::fs::remove_file(d.space_path(&ids[0])).unwrap();
        let before = d.runtime.core.lock().unwrap().generation;
        let prepared = prepare_files(&d.env()).unwrap().unwrap();
        assert_eq!(prepared.rematerialized, vec![ids[0].clone()]);
        assert!(d.runtime.core.lock().unwrap().generation > before);
        let s = d.state();
        let work = &s.spaces[&ids[0]];
        assert_eq!((work.cursor_seq, work.baseline_established), (0, false));
        assert_eq!(work.records.keys().cloned().collect::<Vec<_>>(), vec!["host:edited".to_string()], "only the unpushed edit is kept");
        assert_eq!(s.spaces[&ids[1]].cursor_seq, 9, "the other space is untouched");
        assert!(d.space_path(&ids[0]).exists(), "recreated empty after the reset was saved");
        // 已經在基線輪(剛重設、或剛勾選):重建空檔沒有風險,不再重設。
        std::fs::remove_file(d.space_path(&ids[0])).unwrap();
        assert!(prepare_files(&d.env()).unwrap().unwrap().rematerialized.is_empty());
    }

    #[test]
    fn a_rematerialized_space_keeps_the_version_it_applied_of_hosts_waiting_for_review() {
        use crate::sync::approval::signature;
        use crate::sync::state_v2::{DeclinedVersion, PendingApproval};
        let mut space = SpaceState::new("work-3fa2c1d9.config");
        space.cursor_seq = 9;
        space.baseline_established = true;
        space.records.extend([host("web", false, false), host("db", false, false), host("old", false, false), host("edited", false, true)]);
        // web 的較新版本被拒絕了,db 的較新版本還在等核准:這台套用的那一版要留著,基線輪才寫得回檔案。
        space.declined.insert("web".into(), DeclinedVersion { version: 2, updated_at_ms: 900, seq: 9 });
        let text = "Host db\n  ForwardAgent yes\n".to_string();
        let record = host("db", false, false).1.record;
        space.pending_approvals.insert(
            "db".into(),
            PendingApproval { record, seq: 8, applied: signature("Host db\n"), incoming: signature(&text), text, from_device: "MacBook-B".into() },
        );
        reset_space_for_rematerialize(&mut space);
        assert_eq!(space.records.keys().map(String::as_str).collect::<Vec<_>>(), vec!["host:db", "host:edited", "host:web"]);
        assert_eq!((space.cursor_seq, space.baseline_established), (0, false));
        assert!(space.declined.contains_key("web") && space.pending_approvals.contains_key("db"));
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_at_a_space_file_stays_and_becomes_that_spaces_read_error_without_reloads() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work", "Home"]);
        prepare_files(&d.env()).unwrap();
        {
            let mut core = d.runtime.core.lock().unwrap();
            let work = core.state.as_mut().unwrap().spaces.get_mut(&ids[0]).unwrap();
            work.cursor_seq = 9;
            work.records.extend([host("web", false, false)]);
        }
        let (work, home) = (d.space_path(&ids[0]), d.space_path(&ids[1]));
        let target = d.home.path().join("gone.config");
        std::fs::remove_file(&work).unwrap();
        std::os::unix::fs::symlink(&target, &work).unwrap();
        let link = || std::fs::symlink_metadata(&work).unwrap().file_type().is_symlink() && std::fs::read_link(&work).unwrap() == target;
        let both = [(ids[0].clone(), work.clone()), (ids[1].clone(), home.clone())];
        // 連到的檔案不見了:從 chain 重新長出 —— 但絕不拿一個空檔取代那個 symlink,也不在它指的地方建檔。
        assert_eq!(prepare_files(&d.env()).unwrap().unwrap().rematerialized, vec![ids[0].clone()]);
        assert!(link() && !target.exists());
        let (results, _) = gather(&d.env(), &both).unwrap();
        assert!(results[&ids[0]].as_ref().unwrap_err().contains("could not be read"));
        // 之後每一輪:沒有要做的事,也不再整份重載 doc(重載了它也載不進來);那個 space 停在讀不到,另一個照常。
        for _ in 0..2 {
            assert_eq!(prepare_files(&d.env()).unwrap().unwrap(), Prepared::default());
            let (results, reloaded) = gather(&d.env(), &both).unwrap();
            assert!(!reloaded);
            assert!(results[&ids[0]].is_err() && results[&ids[1]].is_ok());
        }
        assert!(link());
    }

    #[test]
    fn an_invariant_violation_pauses_only_that_space() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work", "Home"]);
        prepare_files(&d.env()).unwrap();
        let (work, home) = (d.space_path(&ids[0]), d.space_path(&ids[1]));
        d.write_externally(&work, "Host a\n  Include ~/.ssh/extra.config\n");
        d.write_externally(&home, "Host b\n  User me\n");
        let (results, reloaded) = gather(&d.env(), &[(ids[0].clone(), work), (ids[1].clone(), home)]).unwrap();
        assert!(reloaded, "files edited outside the app are reloaded first");
        assert!(results[&ids[0]].as_ref().unwrap_err().contains("Include"));
        let ok = results[&ids[1]].as_ref().unwrap();
        assert_eq!(ok.blocks, vec![HostBlockText { alias: "b".into(), text: "Host b\n  User me\n".into() }]);
    }

    #[test]
    fn app_saves_are_planned_at_once_and_engine_writes_are_not() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work"]);
        prepare_files(&d.env()).unwrap();
        let work = d.space_path(&ids[0]);
        let before = d.runtime.core.lock().unwrap().generation;
        d.save_in_app(&work, "Host web\n  HostName 10.0.0.1\n");
        let s = d.state();
        assert!(s.spaces[&ids[0]].records["host:web"].dirty);
        assert!(d.runtime.core.lock().unwrap().generation > before);
        assert_eq!(d.events.wakes(), 1);
        assert_eq!(d.events.implicit_wakes(), 1, "a save is an implicit wake: it waits out a rate-limit backoff (spec §6.4)");
        // 引擎自己的寫入不算本機編輯。
        {
            let _engine = EngineWrite::begin();
            note_written(&d.env(), &work, &parse_file("Host other\n").0);
        }
        assert!(!d.state().spaces[&ids[0]].records.contains_key("host:other"));
        // 主 config 等其他檔案不算。
        note_written(&d.env(), &d.main_path(), &parse_file("Host x\n").0);
        assert!(!d.state().spaces[&ids[0]].records.contains_key("host:x"));
        // 基線輪還沒跑:不規劃,但仍換 generation。
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&ids[0]).unwrap().baseline_established = false;
        let before = d.runtime.core.lock().unwrap().generation;
        note_written(&d.env(), &work, &parse_file("Host fresh\n").0);
        assert!(!d.state().spaces[&ids[0]].records.contains_key("host:fresh"));
        assert!(d.runtime.core.lock().unwrap().generation > before);
    }

    #[test]
    fn a_space_commit_writes_the_file_and_publishes_only_that_space() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work", "Home"]);
        prepare_files(&d.env()).unwrap();
        let work = d.space_path(&ids[0]);
        let generation = d.runtime.core.lock().unwrap().generation;
        let (results, _) = gather(&d.env(), &[(ids[0].clone(), work.clone())]).unwrap();
        let fingerprint = results[&ids[0]].as_ref().unwrap().fingerprint.clone();
        let mut next = d.state().spaces[&ids[0]].clone();
        next.cursor_seq = 42;
        // 這一輪開始之後,帳戶那一步記下了改名被擋:發布本 space 的合併結果時保留它。
        let blocked = Some(format!("lab-{}.config", &ids[0][..8]));
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&ids[0]).unwrap().rename_blocked = blocked.clone();
        let effects = vec![HostEffect::Upsert { alias: "web".into(), text: "Host web\n".into() }];
        match apply_and_commit_space(&d.env(), generation, &ids[0], &work, &fingerprint, &effects, &next).unwrap() {
            Applied::Committed { wrote, save_error } => assert!(wrote && save_error.is_none()),
            other => panic!("expected a commit, got {other:?}"),
        }
        assert_eq!(d.read(&work), "Host web\n", "the first host written into an empty file ends with a newline");
        let s = d.state();
        assert_eq!(s.spaces[&ids[0]].cursor_seq, 42);
        assert_eq!(s.spaces[&ids[0]].rename_blocked, blocked);
        assert_eq!(s.spaces[&ids[1]].cursor_seq, 0);
        // 檔案在讀取之後被改過:本 space 作廢。
        d.write_externally(&work, "Host web\n  User x\n");
        let again = apply_and_commit_space(&d.env(), generation, &ids[0], &work, &fingerprint, &[], &next).unwrap();
        assert!(matches!(again, Applied::FileChanged));
        // generation 變了:被搶先。
        d.runtime.core.lock().unwrap().generation += 1;
        assert!(apply_and_commit_space(&d.env(), generation, &ids[0], &work, &fingerprint, &[], &next)
            .is_err_and(|e| crate::sync::runtime::is_superseded(&e)));
    }

    #[test]
    fn a_failed_include_write_leaves_the_in_memory_list_as_it_was_so_the_next_call_writes_again() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let original = "# main\nInclude ~/.ssh/sshelter/old-aaaaaaaa.config\nHost local\n";
        let d = TestDevice::with_main_config("a", &relay, &clock, original);
        // 載入之後主 config 被另一個編輯器改過:`persist_file` 回 Conflict。
        d.write_externally(&d.main_path(), "# main\n# edited elsewhere\n");
        let tokens = vec!["~/.ssh/sshelter/new-bbbbbbbb.config".to_string()];
        let mut doc_lock = d.doc.lock().unwrap();
        let doc = doc_lock.as_mut().unwrap();
        let mut backed_up = d.backed_up.lock().unwrap();
        for attempt in 1..=2 {
            let err = write_include(doc, &mut backed_up, None, &tokens).unwrap_err();
            assert!(matches!(err, AppError::Conflict(_)), "attempt {attempt}: {err:?}");
            assert_eq!(
                serialize_items(&doc.files[0].items, doc.files[0].trailing_newline),
                original,
                "attempt {attempt}: the list in memory must stay the one the disk had when it was loaded, or the next call thinks it is already written"
            );
        }
        assert_eq!(d.read(&d.main_path()), "# main\n# edited elsewhere\n", "the external edit is never overwritten");
    }

    #[test]
    fn a_conflicting_include_rewrite_keeps_the_unselected_file_and_heals_on_the_next_call() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work", "Home"]);
        prepare_files(&d.env()).unwrap();
        let work = d.space_path(&ids[0]);
        let listed = work.file_name().unwrap().to_string_lossy().to_string();
        d.write_externally(&work, "Host a\n");
        // 取消勾選做到一半,主 config 同時被另一個編輯器改過:新的 Include 清單寫不進去。
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&ids[0]).unwrap().selected = false;
        let edited = format!("{}# edited elsewhere\n", d.main_config());
        d.write_externally(&d.main_path(), &edited);
        let first = prepare_files(&d.env());
        assert!(matches!(first, Err(AppError::Conflict(_))), "{first:?}");
        assert_eq!(d.read(&work), "Host a\n", "the file stays while the list on the disk still names it");
        assert_eq!(d.main_config(), edited, "nothing was written over the external edit");
        assert!(d.state().spaces.contains_key(&ids[0]), "the state is kept with the file");
        // 下一次:絕不能因為「清單看起來已經對了」就刪掉磁碟上的清單還列著的檔案。
        let second = prepare_files(&d.env());
        if !work.exists() {
            assert!(
                !d.main_config().contains(&listed),
                "the space file was deleted while the list on the disk still names it ({second:?})"
            );
        }
        // 重載之後 doc 與磁碟一致,這次寫得進去:清單先換掉、檔案才備份並刪除,外部的編輯保留。
        assert!(second.unwrap().unwrap().reloaded);
        assert!(!work.exists());
        assert!(!d.main_config().contains(&listed) && d.main_config().contains("# edited elsewhere"));
        assert!(!d.state().spaces.contains_key(&ids[0]));
    }

    #[test]
    fn a_conflicting_include_rewrite_reloads_the_doc_and_reports_it_once_every_lock_is_free() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work", "Home"]);
        prepare_files(&d.env()).unwrap();
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&ids[0]).unwrap().selected = false;
        d.write_externally(&d.main_path(), &format!("{}# edited elsewhere\n", d.main_config()));
        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        let out = prepare_files(&env);
        assert!(matches!(out, Err(AppError::Conflict(_))), "{out:?}");
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true], "one applied(0), sent after the doc, backed_up and core locks were released");
        // doc 已經是磁碟上的內容(含外部編輯),指紋是新的。
        let doc = d.doc.lock().unwrap();
        let main = &doc.as_ref().unwrap().files[0];
        assert!(memory_matches_disk(main) && !fsutil::has_changed(&main.path, &main.fingerprint).unwrap());
        assert!(serialize_items(&main.items, main.trailing_newline).contains("# edited elsewhere"));
    }

    #[test]
    fn a_conflict_on_a_main_config_that_cannot_be_reloaded_drops_the_doc_and_says_so() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work", "Home"]);
        prepare_files(&d.env()).unwrap();
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&ids[0]).unwrap().selected = false;
        std::fs::remove_file(d.main_path()).unwrap();
        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        let message = prepare_files(&env).unwrap_err().to_string();
        assert!(message.contains("reloading the config afterwards also failed"), "{message}");
        assert!(d.doc.lock().unwrap().is_none(), "an in-memory doc that cannot be trusted is dropped; the front end reloads it");
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true]);
        assert!(d.space_path(&ids[0]).exists(), "the unselected file is still there");
    }

    #[test]
    fn rewriting_the_include_list_reloads_the_doc_so_files_ssh_no_longer_reads_drop_out() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::with_main_config("a", &relay, &clock, "# main\nInclude ~/.ssh/sshelter/*.config\nHost local\n");
        let ids = d.join_with_spaces(&["Work"]);
        let work = d.space_path(&ids[0]);
        let stray = work.with_file_name("stray.config");
        std::fs::create_dir_all(work.parent().unwrap()).unwrap();
        d.write_externally(&work, "");
        d.write_externally(&stray, "Host stray\n");
        d.reload(); // 手寫的 glob 把兩個檔案都載進 doc
        let loaded = |p: &Path| d.doc.lock().unwrap().as_ref().unwrap().files.iter().any(|f| f.path == p);
        assert!(loaded(&work) && loaded(&stray));
        let prepared = prepare_files(&d.env()).unwrap().unwrap();
        assert!(prepared.reloaded, "the Include line changed, so the doc is reloaded even though every space file was already loaded");
        assert_eq!(
            d.main_config(),
            format!("# main\nInclude ~/.ssh/sshelter/{}\nHost local\n", work.file_name().unwrap().to_string_lossy())
        );
        assert!(loaded(&work) && !loaded(&stray), "ssh no longer reads the stray file through the list, so neither does the doc");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_space_write_voids_the_commit_reloads_the_doc_and_reports_after_the_locks_are_free() {
        use std::os::unix::fs::PermissionsExt;
        // 測試結束(含斷言失敗)一定把目錄權限還回去,暫存目錄才清得掉。
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work"]);
        prepare_files(&d.env()).unwrap();
        let work = d.space_path(&ids[0]);
        let dir = work.parent().unwrap().to_path_buf();
        let generation = d.runtime.core.lock().unwrap().generation;
        let (results, _) = gather(&d.env(), &[(ids[0].clone(), work.clone())]).unwrap();
        let fingerprint = results[&ids[0]].as_ref().unwrap().fingerprint.clone();
        let mut next = d.state().spaces[&ids[0]].clone();
        next.cursor_seq = 42;
        let _restore = Restore(dir.clone());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        // root 不受目錄權限限制:這個環境測不了寫檔失敗,略過。
        let probe_file = dir.join(".root-probe");
        if std::fs::File::create(&probe_file).is_ok() {
            let _ = std::fs::remove_file(&probe_file);
            return;
        }
        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        let effects = vec![HostEffect::Upsert { alias: "web".into(), text: "Host web\n".into() }];
        let out = apply_and_commit_space(&env, generation, &ids[0], &work, &fingerprint, &effects, &next);
        assert!(matches!(out, Err(AppError::Io(_))), "{out:?}");
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true], "applied(0) after the doc was reloaded, with every lock free");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // 磁碟、狀態、generation 都沒動;doc 是重載後的,和磁碟一致。
        assert_eq!(d.read(&work), "");
        assert_eq!(d.state().spaces[&ids[0]].cursor_seq, 0, "nothing was published");
        assert_eq!(d.runtime.core.lock().unwrap().generation, generation);
        {
            let doc = d.doc.lock().unwrap();
            let file = doc.as_ref().unwrap().files.iter().find(|f| f.path == work).unwrap();
            assert!(memory_matches_disk(file) && !fsutil::has_changed(&work, &file.fingerprint).unwrap());
        }
        // 目錄恢復可寫之後,同一個交易就能提交。
        let (results, _) = gather(&d.env(), &[(ids[0].clone(), work.clone())]).unwrap();
        let fingerprint = results[&ids[0]].as_ref().unwrap().fingerprint.clone();
        let out = apply_and_commit_space(&d.env(), generation, &ids[0], &work, &fingerprint, &effects, &next).unwrap();
        assert!(matches!(out, Applied::Committed { wrote: true, .. }), "{out:?}");
        assert_eq!(d.read(&work), "Host web\n");
    }

    #[test]
    fn a_doc_ahead_of_the_disk_voids_the_commit_and_is_reloaded_by_the_next_gather() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work"]);
        prepare_files(&d.env()).unwrap();
        let work = d.space_path(&ids[0]);
        d.write_externally(&work, "Host web\n");
        let (first, reloaded) = gather(&d.env(), &[(ids[0].clone(), work.clone())]).unwrap();
        assert!(reloaded, "the external edit is picked up first");
        let fingerprint = first[&ids[0]].as_ref().unwrap().fingerprint.clone();
        // app 的某次寫入先改了 doc、寫檔卻失敗:磁碟沒變、指紋照樣相符,in-memory 卻比磁碟新。
        {
            let mut doc_lock = d.doc.lock().unwrap();
            let file = doc_lock.as_mut().unwrap().files.iter_mut().find(|f| f.path == work).unwrap();
            hosts_file::apply_host_text(&mut file.items, "app", "Host app\n").unwrap();
            assert!(!memory_matches_disk(file) && !fsutil::has_changed(&work, &file.fingerprint).unwrap());
        }
        let generation = d.runtime.core.lock().unwrap().generation;
        let next = d.state().spaces[&ids[0]].clone();
        // 有沒有效果都一樣:不能把遠端內容連同沒寫進磁碟的 app 修改一起寫下去,也不能發布。
        let none: &[HostEffect] = &[];
        let some = vec![HostEffect::Upsert { alias: "db".into(), text: "Host db\n".into() }];
        for effects in [none, &some[..]] {
            let out = apply_and_commit_space(&d.env(), generation, &ids[0], &work, &fingerprint, effects, &next).unwrap();
            assert!(matches!(out, Applied::FileChanged), "{out:?}");
        }
        assert_eq!(d.read(&work), "Host web\n", "nothing was written");
        // 下一輪的 gather 重載 doc:沒寫進磁碟的修改被丟掉,讀到的是磁碟上的區塊。
        let (again, reloaded) = gather(&d.env(), &[(ids[0].clone(), work.clone())]).unwrap();
        assert!(reloaded);
        let aliases: Vec<&str> = again[&ids[0]].as_ref().unwrap().blocks.iter().map(|b| b.alias.as_str()).collect();
        assert_eq!(aliases, vec!["web"]);
        assert!(!gather(&d.env(), &[(ids[0].clone(), work)]).unwrap().1, "once the doc matches the disk again nothing is reloaded");
    }

    #[test]
    fn an_app_edit_whose_state_cannot_be_saved_stays_planned_in_memory_and_is_flagged_for_the_next_round() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let ids = d.join_with_spaces(&["Work"]);
        prepare_files(&d.env()).unwrap();
        let work = d.space_path(&ids[0]);
        // 狀態檔所在的 `data` 被一個一般檔案擋住:存不了(任何平台、包括 root 都一樣)。
        std::fs::write(d.home.path().join("data"), b"in the way").unwrap();
        d.save_in_app(&work, "Host web\n  HostName 10.0.0.1\n");
        assert_eq!(d.read(&work), "Host web\n  HostName 10.0.0.1\n", "the file itself was written");
        let s = d.state();
        assert!(s.spaces[&ids[0]].records["host:web"].dirty, "the edit is planned in memory");
        assert!(d.runtime.core.lock().unwrap().unsaved, "the failed save is remembered: the next round saves before it touches the network");
        assert!(s.last_error.as_deref().unwrap().starts_with("sync state could not be saved after a local edit"), "{:?}", s.last_error);
        assert_eq!((d.events.wakes(), d.events.implicit_wakes()), (1, 1), "the round still gets woken (an implicit wake)");
    }

    #[test]
    fn an_empty_space_file_is_never_created_over_a_file_that_is_already_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sshelter").join("work-aaaaaaaa.config");
        assert!(space_files::create_empty_space_file(&path).unwrap(), "created, and the missing directory with it");
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        // 檢查與建立之間剛出現的檔案(使用者從備份還原的):留著它,不蓋掉。
        std::fs::write(&path, "Host kept\n").unwrap();
        assert!(!space_files::create_empty_space_file(&path).unwrap(), "someone put a file there first");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "Host kept\n");
    }
}
