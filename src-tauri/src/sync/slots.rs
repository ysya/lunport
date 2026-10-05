//! SP3 金鑰插槽的引擎(spec `docs/superpowers/specs/2026-10-05-sp3-key-slots-design.md` §4、§6):帳戶裡 `keyslot` 與
//! `key` 記錄的讀寫、每一輪在這台維護插槽(`reconcile`)與給 UI 的插槽檢視(`views`)、模式切換與挑選(Task 6)。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::model::Item;
use crate::config::parser::parse_file;
use crate::error::AppError;
use crate::sync::crypto::{id_hash, ChainKeys};
use crate::sync::dto::{SlotDeviceView, SlotStatusView, SyncKeySlotView};
use crate::sync::merge::{device_name, devices, put_account_record, set_device_slots};
use crate::sync::planner::next_timestamp;
use crate::sync::record::{record_key, HostPayload, Record, RecordKind};
use crate::sync::slot_files::{self, LinkKind};
use crate::sync::slot_rules::{
    inspect_private_key, parse_public_key, public_path, slot_file_name, slot_file_of_value, slot_value, valid_key_payload,
    valid_slot_payload, DeviceSlot, KeyPayload, KeySlotPayload, SlotMode, SLOT_DIR, SLOT_SCHEMA,
};
use crate::sync::state_v2::{sealed_key, AccountState, LocalSlot, SealedRecord, SlotSource, SyncNotice, SyncStateV2};

// ── 帳戶記錄 ──────────────────────────────────────────────────────────────────────────────────

/// 帳戶裡未刪除、讀得懂的插槽(id, payload),依名稱、id 排序。
pub fn live_slots(account: &AccountState) -> Vec<(String, KeySlotPayload)> {
    let mut out: Vec<(String, KeySlotPayload)> = account
        .records
        .values()
        .filter(|l| l.record.kind == RecordKind::KeySlot && !l.record.deleted)
        .filter_map(|l| {
            let payload: KeySlotPayload = serde_json::from_value(l.record.payload.clone()).ok()?;
            valid_slot_payload(&payload).then(|| (l.record.id.clone(), payload))
        })
        .collect();
    out.sort_by(|a, b| (a.1.name.as_str(), a.0.as_str()).cmp(&(b.1.name.as_str(), b.0.as_str())));
    out
}

pub fn slot(account: &AccountState, slot_id: &str) -> Option<KeySlotPayload> {
    live_slots(account).into_iter().find(|(id, _)| id == slot_id).map(|(_, p)| p)
}

/// 帳戶裡有沒有這個插槽的記錄(含 tombstone)。
pub fn slot_record_exists(account: &AccountState, slot_id: &str) -> bool {
    account.records.contains_key(&record_key(RecordKind::KeySlot, slot_id))
}

/// 寫一筆 `keyslot`(dirty)。`None` = tombstone。
pub fn put_slot(account: &mut AccountState, slot_id: &str, payload: Option<&KeySlotPayload>, device_id: &str, now_ms: u64) {
    let value = payload.map(|p| serde_json::to_value(p).expect("KeySlotPayload serializes")).unwrap_or(Value::Null);
    put_account_record(account, RecordKind::KeySlot, slot_id, value, payload.is_none(), device_id, now_ms);
}

/// 一個插槽的 `key` 在 `sealed` 裡的 key(以帳戶金鑰算的 id_hash)。
pub fn key_secret_key(account_keys: &ChainKeys, slot_id: &str) -> String {
    sealed_key(RecordKind::Key.as_str(), &id_hash(account_keys, RecordKind::Key.as_str(), slot_id))
}

/// 寫一筆 `key`(祕密,SP3 spec §4.1):以帳戶金鑰加密後放進 `sealed`(dirty),明文只在記憶體。`None` = tombstone
/// (不帶任何祕密)。版本號、時間戳與 seq 接在前一版之後(同 `merge::put_space_key`)。
pub fn put_key_secret(
    account: &mut AccountState,
    account_keys: &ChainKeys,
    slot_id: &str,
    private_key: Option<&str>,
    device_id: &str,
    now_ms: u64,
) -> Result<(), AppError> {
    let key = key_secret_key(account_keys, slot_id);
    let previous = account.sealed.get(&key).and_then(|s| s.open(account_keys).ok().map(|r| (r, s.envelope.seq)));
    let record = Record {
        kind: RecordKind::Key,
        id: slot_id.to_string(),
        version: previous.as_ref().map(|(r, _)| r.version + 1).unwrap_or(1),
        updated_at_ms: next_timestamp(now_ms, previous.as_ref().map(|(r, _)| r.updated_at_ms)),
        device_id: device_id.to_string(),
        deleted: private_key.is_none(),
        payload: match private_key {
            Some(text) => serde_json::to_value(KeyPayload { schema: SLOT_SCHEMA, private_key: text.to_string() })
                .expect("KeyPayload serializes"),
            None => Value::Null,
        },
    };
    let sealed = SealedRecord::seal(account_keys, &record, previous.map(|(_, seq)| seq).unwrap_or(0))?;
    account.sealed.insert(key, sealed);
    Ok(())
}

/// 在記憶體解開一個插槽的私鑰。沒有、已刪除或讀不懂 → None。
pub fn open_key_secret(account: &AccountState, account_keys: &ChainKeys, slot_id: &str) -> Option<String> {
    let record = account.sealed.get(&key_secret_key(account_keys, slot_id))?.open(account_keys).ok()?;
    if record.deleted || record.id != slot_id {
        return None;
    }
    let payload: KeyPayload = serde_json::from_value(record.payload).ok()?;
    valid_key_payload(&payload).then_some(payload.private_key)
}

// ── 每一輪在這台維護插槽(SP3 spec §6.2–§6.6)──────────────────────────────────────────────────
//
// 一個檔案是不是 SSHelter 放的,只看這個插槽 id 自己的本機記錄(`SyncStateV2::key_slots[id]`),不看檔名:插槽檔名
// (`<name>-<id8>`)不保證在插槽 id 之間唯一,帳戶裡的成員可以發佈同名、同 id 前 8 字元的另一個插槽。從主機的
// `IdentityFile` 值取得的檔名(`slot_hosts`、`identity_slot_files`)只當查詢的 key,絕不拿來組出要寫入或移除的路徑。

pub const MISMATCH_MESSAGE: &str = "The synced key didn't match and was not written.";

pub fn in_the_way_message(path: &Path) -> String {
    format!("A file SSHelter didn't create is in the way: {}. Move it, then sync again.", path.display())
}

pub fn source_gone_message(path: &str) -> String {
    format!("The key this slot points to is gone: {path}.")
}

/// 一個 Host 區塊文字裡,指到插槽的 `IdentityFile`(插槽檔名)。註解掉的行不算。
pub fn identity_slot_files(text: &str) -> Vec<String> {
    let (items, _) = parse_file(text);
    let mut out = Vec::new();
    for item in &items {
        let Item::Host(host) = item else { continue };
        for line in &host.body {
            if let Item::Directive(d) = line {
                if d.key == "identityfile" && !d.serializes_as_comment() {
                    out.extend(slot_file_of_value(&d.value));
                }
            }
        }
    }
    out
}

/// 這台勾選的 space 裡、未刪除的主機中,用到各插槽(依插槽檔名)的 alias(排序、不重複)。等待核准的主機不算。
pub fn slot_hosts(state: &SyncStateV2) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for space in state.spaces.values().filter(|sp| sp.selected) {
        for local in space.records.values().filter(|l| l.record.kind == RecordKind::Host && !l.record.deleted) {
            let Ok(payload) = serde_json::from_value::<HostPayload>(local.record.payload.clone()) else { continue };
            for file in identity_slot_files(&payload.text) {
                out.entry(file).or_default().insert(local.record.id.clone());
            }
        }
    }
    out.into_iter().map(|(file, hosts)| (file, hosts.into_iter().collect())).collect()
}

/// 本機一把金鑰的指紋:OpenSSH 格式從私鑰讀;其他格式讀旁邊的 `.pub`;都讀不到 → None。
pub fn local_key_fingerprint(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    if let Ok(facts) = inspect_private_key(&text) {
        return Some(facts.fingerprint);
    }
    let public = std::fs::read_to_string(public_path(path)).ok()?;
    parse_public_key(public.lines().next()?).map(|(_, fingerprint)| fingerprint)
}

/// 一輪插槽維護的結果:要發的通知(呼叫端用 `add_notice` 存進狀態並發出)、狀態是否變了。
#[derive(Debug, Default)]
pub struct SlotRound {
    pub notices: Vec<SyncNotice>,
    pub changed: bool,
}

/// 把通知加進狀態的 `notices`。「這台需要金鑰」至多一則:新名稱併進還沒關掉的那一則(前端的「Keys for this computer」
/// 因此只開一次);其他種類一樣的不重複加。
pub fn add_notice(notices: &mut Vec<SyncNotice>, notice: &SyncNotice) {
    if let SyncNotice::KeysNeeded { names } = notice {
        if let Some(SyncNotice::KeysNeeded { names: open }) = notices.iter_mut().find(|n| matches!(n, SyncNotice::KeysNeeded { .. })) {
            for name in names {
                if !open.contains(name) {
                    open.push(name.clone());
                }
            }
            return;
        }
    }
    if !notices.contains(notice) {
        notices.push(notice.clone());
    }
}

/// 依合併後的帳戶與 space 記錄,維護這台的插槽(SP3 spec §6.2–§6.6)。檔案系統的動作在這裡做(呼叫端不持有任何鎖);
/// 狀態的變更寫進 `state`(`key_slots` 與帳戶的 `device.slots`、補寫的 `keyslot`/`key`),由呼叫端提交。`home` = 家目錄。
pub fn reconcile(state: &mut SyncStateV2, account_keys: &ChainKeys, home: &Path, now_ms: u64) -> SlotRound {
    let mut round = SlotRound::default();
    let needed = slot_hosts(state);
    let device_id = state.device_id.clone();
    let keys_dir = home.join(SLOT_DIR);
    let Some(account) = state.account.as_mut() else { return round };
    let live = live_slots(account);
    let mut asked = Vec::new();

    for (id, payload) in &live {
        let file = slot_file_name(&payload.name, id);
        let path = keys_dir.join(&file);
        let before = state.key_slots.get(id).cloned();
        let mut local = before.clone().unwrap_or_else(|| LocalSlot {
            file_name: file.clone(),
            source: None,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
        });
        if local.file_name != file {
            // 插槽建立之後不改名(spec §1 非目標),帳戶裡的名稱卻變了(只有帳戶裡的惡意成員寫得出來):這個插槽記著的檔案在舊路徑,
            // 以後不再碰它們;新路徑上的東西不屬於這個插槽(它的記錄指的是舊路徑),從頭來過 —— 不能拿新路徑去替換或移除別人的檔案。
            local.file_name = file.clone();
            local.source = None;
            local.parked = false;
            local.last_error = None;
        }
        local.payload = Some(payload.clone());
        let is_needed = needed.contains_key(&file);
        if is_needed {
            maintain(&mut local, id, payload, account, account_keys, &keys_dir, &path);
            if local.source.is_none() && local.last_error.is_none() && payload.mode == SlotMode::Own && !local.asked {
                local.asked = true;
                asked.push(payload.name.clone());
            }
        } else {
            park_link(&mut local, &path);
        }
        if !is_needed && local.source.is_none() {
            // 這台沒用到、也沒留東西:不記。
            round.changed |= state.key_slots.remove(id).is_some();
        } else if before.as_ref() != Some(&local) {
            state.key_slots.insert(id.clone(), local);
            round.changed = true;
        }
    }

    // 這台記著、帳戶裡卻沒有的插槽。已刪除的(tombstone):移除連結、副本留著。完全找不到記錄而主機還用著:補寫(spec §6.6,
    // 例如在沒有 SP3 的電腦上更換了同步碼)。
    let gone: Vec<String> = state.key_slots.keys().filter(|id| !live.iter().any(|(l, _)| l == *id)).cloned().collect();
    for id in gone {
        let mut local = state.key_slots[&id].clone();
        let path = keys_dir.join(&local.file_name);
        if !slot_record_exists(account, &id) && needed.contains_key(&local.file_name) {
            if let Some(payload) = local.payload.clone() {
                republish(account, account_keys, &id, &payload, &local, &path, &device_id, now_ms);
                round.changed = true;
                continue;
            }
        }
        let before = local.clone();
        drop_link(&mut local, &path);
        if local.source.is_none() {
            state.key_slots.remove(&id);
            round.changed = true;
        } else if local != before {
            state.key_slots.insert(id, local);
            round.changed = true;
        }
    }

    let slots: Vec<DeviceSlot> =
        state.key_slots.iter().filter_map(|(id, l)| device_slot(id, l, needed.contains_key(&l.file_name))).collect();
    round.changed |= set_device_slots(account, &device_id, slots, now_ms);
    if !asked.is_empty() {
        round.notices.push(SyncNotice::KeysNeeded { names: asked });
    }
    round
}

/// 這台的 `device.slots` 裡這個插槽那一項。連結(symlink / hard link)只在有主機用到、而且連結真的在插槽路徑上的時候才列:
/// 收起來的(`LocalSlot::parked`,`park_link`)連結,插槽路徑上現在沒有這個插槽的東西;複製檔與同步來的副本是真的放在插槽裡的
/// 金鑰,一直列著。
fn device_slot(slot_id: &str, local: &LocalSlot, needed: bool) -> Option<DeviceSlot> {
    match &local.source {
        Some(SlotSource::Linked { link, fingerprint, .. }) => ((needed && !local.parked) || *link == LinkKind::Copy)
            .then(|| DeviceSlot { slot_id: slot_id.to_string(), fingerprint: fingerprint.clone(), synced_copy: false }),
        Some(SlotSource::SyncedCopy { fingerprint }) => {
            Some(DeviceSlot { slot_id: slot_id.to_string(), fingerprint: Some(fingerprint.clone()), synced_copy: true })
        }
        None => None,
    }
}

/// 一個 `Linked` 來源在插槽路徑上的連結檔,能不能拿掉。只看這個插槽自己的本機記錄(記著的連結種類與原檔),不看檔名。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkFate {
    /// 是 SSHelter 放的連結(或路徑上已經沒有東西),拿掉它不會讓任何金鑰消失。
    Removable,
    /// 記錄說這裡是 SSHelter 建的 symlink、現在卻是一般檔案(使用者自己換上的):不是 SSHelter 放的,不碰。
    NotOurs,
    /// hard link 的原檔不見了,或內容和它不同(原檔被換成另一把):這個名字可能是那份金鑰僅存的名字,不拿掉,記成複製檔。
    LastName,
}

/// `link` 這種連結的檔案,在 `path` 上能怎麼處置;複製檔(`Copy`)永遠不拿掉 → None。`source` = 記錄的原檔。
fn link_fate(link: LinkKind, source: &str, path: &Path) -> Option<LinkFate> {
    match link {
        LinkKind::Copy => None,
        LinkKind::Symlink => {
            let ours = !slot_files::occupied(path) || std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
            Some(if ours { LinkFate::Removable } else { LinkFate::NotOurs })
        }
        LinkKind::HardLink => {
            if !slot_files::occupied(path) {
                return Some(LinkFate::Removable);
            }
            // 原檔還在、內容和插槽裡的一樣:拿掉這個名字,金鑰還留在原檔。
            let original = PathBuf::from(source);
            let same = original.is_file()
                && slot_files::content_sha256(path).is_some_and(|sha| slot_files::content_sha256(&original).as_ref() == Some(&sha));
            Some(if same { LinkFate::Removable } else { LinkFate::LastName })
        }
    }
}

/// 只拿掉插槽路徑上的連結檔;`.pub` 留著(同一個插槽下次用到時只要重新連結)。已經不存在不算錯。
fn remove_link_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// 連結檔不拿掉了:記成複製檔(Keys 列為 Not in use,使用者可以刪除),原檔、`.pub` 都不動。
fn keep_as_copy(local: &mut LocalSlot) {
    if let Some(SlotSource::Linked { link, .. }) = local.source.as_mut() {
        *link = LinkKind::Copy;
    }
}

/// 帳戶裡還有、這台沒有主機用到的插槽:只拿掉連結檔(symlink,或原檔還在而且內容相同的 hard link;原檔不動),`LocalSlot` 的
/// 記錄留著 —— `Linked` 來源、`origin`、使用者的挑選不能因為暫時沒有主機用到(主機的 `IdentityFile` 暫時拿掉、space 檔重新長出來)
/// 就忘掉,用到的時候 `maintain` 重新連結,不會再問使用者。拿掉之後記錄標成 `parked`:它不再擁有插槽路徑上的東西 —— 之後那裡出現的
/// 任何東西(別的插槽放的副本、使用者的檔案)都不是它的,這裡不看、不碰,也不把它記成這個插槽的複製檔。永遠不拿掉一把金鑰的最後
/// 一個名字:原檔不見或內容不同的 hard link 留在原地、記成複製檔(那是這個插槽放的,沒有收起來)。複製檔與同步來的副本本來就不拿掉
/// (私鑰不自動刪除);使用者自己換在 symlink 位置上的一般檔案也不碰,記錄同樣標成 `parked`。
fn park_link(local: &mut LocalSlot, path: &Path) {
    if local.parked {
        // 已經收起來了:路徑上現在的東西不是這個插槽的,不看、不碰;用到它的時候才有的錯誤(擋路)現在不必再顯示。
        local.last_error = None;
        return;
    }
    let Some(SlotSource::Linked { path: source, link, .. }) = &local.source else { return };
    match link_fate(*link, source, path) {
        None => {}
        Some(LinkFate::NotOurs) => local.parked = true,
        Some(LinkFate::LastName) => keep_as_copy(local),
        Some(LinkFate::Removable) => {
            if let Err(e) = remove_link_file(path) {
                local.last_error = Some(e.to_string());
                return;
            }
            local.parked = true;
        }
    }
    local.last_error = None;
}

/// 帳戶裡已經沒有的插槽(tombstone,或整筆記錄都不見):移除連結(連同 `.pub`)、忘掉這筆記錄;同步來的副本與複製檔留著
/// (私鑰不自動刪除)。原檔不見或內容不同的 hard link 不拿掉、記成複製檔(記錄也留著,Keys 列為 Not in use);使用者自己換在
/// symlink 位置上的一般檔案不碰,只忘掉記錄。收起來的記錄(`parked`)不擁有路徑上的任何東西:只忘掉記錄,不移除、也不收編
/// 那裡現在的檔案(它可能是別的插槽放的副本,或使用者的檔案)。
fn drop_link(local: &mut LocalSlot, path: &Path) {
    let Some(SlotSource::Linked { path: source, link, .. }) = &local.source else { return };
    if local.parked {
        local.source = None;
        local.parked = false;
        local.last_error = None;
        return;
    }
    match link_fate(*link, source, path) {
        None => return,
        Some(LinkFate::LastName) => keep_as_copy(local),
        Some(LinkFate::NotOurs) => local.source = None,
        Some(LinkFate::Removable) => {
            if let Err(e) = slot_files::remove_slot(path) {
                local.last_error = Some(e.to_string());
                return;
            }
            local.source = None;
        }
    }
    local.last_error = None;
}

/// 這台需要的插槽:連結的確認原檔還在、hard link 與複製跟上原檔;副本被刪掉就重放;空的就試著落地。收起來的連結(`parked`)只在
/// 路徑空著的時候重新連結。
fn maintain(
    local: &mut LocalSlot,
    slot_id: &str,
    payload: &KeySlotPayload,
    account: &AccountState,
    account_keys: &ChainKeys,
    keys_dir: &Path,
    path: &Path,
) {
    match local.source.clone() {
        Some(SlotSource::Linked { path: source, link, origin, .. }) => {
            let source_path = PathBuf::from(&source);
            // 收起來的連結:路徑上現在的東西不是這個插槽的(別的插槽放的副本、使用者的檔案)—— 不覆蓋、不認它是自己的,回報擋路,
            // 記錄維持收起來。例外:上一輪已經重新連結、狀態卻沒存下來(`commit` 被搶先),路徑上正好是 `link` 會做出來的 symlink。
            if local.parked && slot_files::occupied(path) {
                let own_link = link == LinkKind::Symlink && std::fs::read_link(path).is_ok_and(|target| target == source_path);
                if !own_link {
                    local.last_error = Some(in_the_way_message(path));
                    return;
                }
            }
            if !source_path.is_file() {
                local.last_error = Some(source_gone_message(&source));
                return;
            }
            // hard link 與複製不會跟著原檔走:內容不同(原檔被換掉)就重新連結;任何一種,插槽不見了都重建。
            let stale = !slot_files::occupied(path)
                || (link != LinkKind::Symlink && slot_files::content_sha256(path) != slot_files::content_sha256(&source_path));
            let link = if stale {
                match slot_files::ensure_keys_dir(keys_dir).and_then(|()| slot_files::link(&source_path, path)) {
                    Ok(kind) => kind,
                    Err(e) => {
                        local.last_error = Some(e.to_string());
                        return;
                    }
                }
            } else {
                link
            };
            local.source = Some(SlotSource::Linked { path: source, link, fingerprint: local_key_fingerprint(&source_path), origin });
            local.parked = false;
            local.last_error = None;
        }
        Some(SlotSource::SyncedCopy { .. }) if slot_files::occupied(path) => local.last_error = None,
        // 副本被刪掉了:同步的金鑰還在就放回去。
        Some(SlotSource::SyncedCopy { .. }) | None => {
            local.source = None;
            land_into(local, slot_id, payload, account, account_keys, keys_dir, path);
        }
    }
}

/// 空的插槽:`synced` 而且私鑰到了就落地;`own` 等使用者挑,私鑰還沒到就等下一輪。
fn land_into(
    local: &mut LocalSlot,
    slot_id: &str,
    payload: &KeySlotPayload,
    account: &AccountState,
    account_keys: &ChainKeys,
    keys_dir: &Path,
    path: &Path,
) {
    local.last_error = None;
    if payload.mode != SlotMode::Synced {
        return;
    }
    let Some(secret) = open_key_secret(account, account_keys, slot_id) else { return };
    match land(&secret, payload, keys_dir, path) {
        Ok(fingerprint) => local.source = Some(SlotSource::SyncedCopy { fingerprint }),
        Err(message) => local.last_error = Some(message),
    }
}

/// 把同步的私鑰寫進空的插槽(spec §6.2):指紋要和插槽記錄一致。插槽路徑上已經有東西時,只有內容完全相同(上一輪寫了
/// 檔案、狀態卻沒存下來)才當成自己的,其他一律不覆蓋。錯誤訊息只帶路徑與原因。
///
/// `.pub` 之後會被 deploy 複製進伺服器的 authorized_keys,所以只能來自通過指紋檢查的這把私鑰(`facts.public_key`),
/// 不取自記錄上的 `public_key`(spec §3:帳戶裡的成員只能改變主機用哪把金鑰);而且一定在指紋檢查通過之後才寫。
fn land(secret: &str, payload: &KeySlotPayload, keys_dir: &Path, path: &Path) -> Result<String, String> {
    let facts = inspect_private_key(secret).map_err(|_| MISMATCH_MESSAGE.to_string())?;
    if payload.fingerprint.as_deref() != Some(facts.fingerprint.as_str()) {
        return Err(MISMATCH_MESSAGE.to_string());
    }
    if slot_files::occupied(path) {
        if std::fs::read(path).ok().as_deref() != Some(secret.as_bytes()) {
            return Err(in_the_way_message(path));
        }
    } else {
        slot_files::ensure_keys_dir(keys_dir).map_err(|e| e.to_string())?;
        slot_files::write_private(path, secret.as_bytes()).map_err(|e| e.to_string())?;
    }
    slot_files::write_public(path, &facts.public_key).map_err(|e| e.to_string())?;
    Ok(facts.fingerprint)
}

/// 補寫帳戶裡不見的插槽(spec §6.6):`keyslot` 用最後看到的 payload;原本是 `synced`、而這台讀得到同指紋的私鑰時,
/// `key` 一起補。
///
/// 「原本是 `synced`」不能由 `payload` 判斷:那是帳戶裡最新的 `keyslot`,帳戶裡的任何成員都能把別台的 `own` 插槽改成 `synced`、
/// 填上公開的公鑰與指紋,再讓帳戶掉了這個插槽 —— 這台若照做,就把使用者選擇留在這台的私鑰上傳給對方(spec §1、§3)。所以連到
/// 本機金鑰的插槽,只在那把金鑰正是這台自己上傳過的(`LocalSlot::uploaded_fingerprint`,只由這台使用者的選擇設定)才補 `key`;
/// 同步來的副本照舊(位元組來自帳戶、通過了指紋檢查,不是這台使用者的私鑰),但路徑上現在的檔案必須還是記錄裡的那一把
/// (`SyncedCopy::fingerprint`)—— 那個位置可能被換成了別的檔案(別的插槽放的、使用者的),不能因為它剛好符合帳戶裡最新的 payload
/// 就上傳。
#[allow(clippy::too_many_arguments)]
fn republish(
    account: &mut AccountState,
    account_keys: &ChainKeys,
    slot_id: &str,
    payload: &KeySlotPayload,
    local: &LocalSlot,
    path: &Path,
    device_id: &str,
    now_ms: u64,
) {
    put_slot(account, slot_id, Some(payload), device_id, now_ms);
    if payload.mode != SlotMode::Synced {
        return;
    }
    let readable = match &local.source {
        Some(SlotSource::Linked { path: source, .. }) => std::fs::read_to_string(source).ok().filter(|text| {
            inspect_private_key(text).is_ok_and(|f| local.uploaded_fingerprint.as_deref() == Some(f.fingerprint.as_str()))
        }),
        Some(SlotSource::SyncedCopy { fingerprint }) => std::fs::read_to_string(path)
            .ok()
            .filter(|text| inspect_private_key(text).is_ok_and(|f| f.fingerprint == *fingerprint)),
        None => None,
    };
    let matching = readable.filter(|text| {
        inspect_private_key(text).is_ok_and(|f| payload.fingerprint.as_deref() == Some(f.fingerprint.as_str()))
    });
    if let Some(text) = matching {
        if let Err(e) = put_key_secret(account, account_keys, slot_id, Some(&text), device_id, now_ms) {
            eprintln!("[sync] could not restore a key slot's key: {e}");
        }
    }
}

// ── 給 UI 的插槽檢視(SP3 spec §7.2、§7.3)─────────────────────────────────────────────────────

/// 帳戶裡的插槽(依名稱),加上帳戶裡已經沒有、這台還留著副本的(Not in use)。
pub fn views(state: &SyncStateV2, account_keys: &ChainKeys, home: &Path) -> Vec<SyncKeySlotView> {
    let Some(account) = state.account.as_ref() else { return Vec::new() };
    let needed = slot_hosts(state);
    let all_devices = devices(account);
    let keys_dir = home.join(SLOT_DIR);
    let live = live_slots(account);
    let view = |id: &str, payload: &KeySlotPayload, status: SlotStatusView, hosts: Vec<String>| SyncKeySlotView {
        id: id.to_string(),
        name: payload.name.clone(),
        mode: payload.mode,
        fingerprint: payload.fingerprint.clone(),
        key_type: payload.key_type.clone(),
        has_passphrase: payload.has_passphrase,
        origin_device: device_name(account, &payload.origin_device_id),
        origin_is_this: payload.origin_device_id == state.device_id,
        value: slot_value(&slot_file_name(&payload.name, id)),
        hosts,
        status,
        devices: all_devices
            .iter()
            .filter(|(device, _)| *device != state.device_id)
            .filter_map(|(_, p)| {
                p.slots.iter().find(|s| s.slot_id == id).map(|s| SlotDeviceView {
                    name: p.name.clone(),
                    fingerprint: s.fingerprint.clone(),
                    synced_copy: s.synced_copy,
                })
            })
            .collect(),
    };
    let mut out = Vec::new();
    for (id, payload) in &live {
        let file = slot_file_name(&payload.name, id);
        let has_secret = account.sealed.get(&key_secret_key(account_keys, id)).is_some_and(|s| !s.envelope.deleted);
        let status = slot_status(state.key_slots.get(id), payload, needed.contains_key(&file), has_secret, &keys_dir.join(&file));
        out.push(view(id, payload, status, needed.get(&file).cloned().unwrap_or_default()));
    }
    for (id, local) in &state.key_slots {
        if live.iter().any(|(l, _)| l == id) {
            continue;
        }
        let (Some(_), Some(payload)) = (&local.source, &local.payload) else { continue };
        let file = keys_dir.join(&local.file_name).display().to_string();
        out.push(view(id, payload, SlotStatusView::NotInUse { file }, Vec::new()));
    }
    out
}

/// 一個帳戶裡的插槽在這台的狀態。錯誤優先;`synced` 的插槽,這台用的若不是同步的那把,依情況是 SourceChanged(這台是
/// 來源)或 SyncedAvailable。
pub fn slot_status(
    local: Option<&LocalSlot>,
    payload: &KeySlotPayload,
    needed: bool,
    has_secret: bool,
    slot_path: &Path,
) -> SlotStatusView {
    if let Some(message) = local.and_then(|l| l.last_error.clone()) {
        return SlotStatusView::Error { message };
    }
    let here = slot_path.display().to_string();
    let synced = payload.mode == SlotMode::Synced;
    match local.and_then(|l| l.source.as_ref()) {
        Some(SlotSource::Linked { path, link, fingerprint, origin }) => {
            if synced && *origin && fingerprint != &payload.fingerprint {
                SlotStatusView::SourceChanged { file: path.clone() }
            } else if synced && !origin && has_secret && fingerprint != &payload.fingerprint {
                SlotStatusView::SyncedAvailable { file: path.clone() }
            } else if !needed {
                // 連結沒有主機用到就收起來了(`park_link`),插槽裡沒有東西;只有複製檔是真的放在插槽裡的金鑰,可以刪除。
                if *link == LinkKind::Copy {
                    SlotStatusView::NotInUse { file: here }
                } else {
                    SlotStatusView::NotUsedHere
                }
            } else {
                SlotStatusView::Ready { file: path.clone(), synced_copy: false, fingerprint: fingerprint.clone() }
            }
        }
        Some(SlotSource::SyncedCopy { fingerprint }) => {
            if synced && has_secret && Some(fingerprint) != payload.fingerprint.as_ref() {
                SlotStatusView::SyncedAvailable { file: here }
            } else if !needed {
                SlotStatusView::NotInUse { file: here }
            } else {
                SlotStatusView::Ready { file: here, synced_copy: true, fingerprint: Some(fingerprint.clone()) }
            }
        }
        None if needed => SlotStatusView::NeedsKey { waiting_for_sync: synced },
        None => SlotStatusView::NotUsedHere,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sync::merge::{account_outgoing, merge_account, plan_device, set_device_slots, Outgoing};
    use crate::sync::record::{DevicePayload, Envelope, LocalRecord};
    use crate::sync::relay::PullResponse;
    use crate::sync::slot_rules::{test_keys, DeviceSlot, SlotMode, MAX_PRIVATE_KEY_BYTES};
    use crate::sync::state_v2::{AccountState, LoadedState, SyncStateV2};

    use crate::sync::dto::{ApprovalNotice, SlotDeviceView, SlotStatusView, SyncConflict};
    use crate::sync::env::SyncEvents;
    use crate::sync::record::HostPayload;
    use crate::sync::round::tests::{pair, settle};
    use crate::sync::runtime::mutate;
    use crate::sync::slot_files::{self, LinkKind};
    use crate::sync::slot_rules::{default_slot_name, inspect_private_key, new_slot_id, public_path, slot_file_name, SLOT_DIR};
    use crate::sync::state_v2::{LocalSlot, SlotSource, SpaceState, SyncNotice};
    use crate::sync::testkit::TestDevice;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Mutex;

    pub(crate) const SLOT_ID: &str = "3fa2c1d90123456789abcdef01234567";

    pub(crate) fn synced_payload(origin: &str) -> KeySlotPayload {
        KeySlotPayload {
            schema: SLOT_SCHEMA,
            name: "id_mac".into(),
            mode: SlotMode::Synced,
            origin_device_id: origin.into(),
            created_at_ms: 5,
            public_key: Some(test_keys::PLAIN_PUBLIC.into()),
            fingerprint: Some(test_keys::PLAIN_FINGERPRINT.into()),
            key_type: Some("ssh-ed25519".into()),
            has_passphrase: Some(false),
        }
    }

    /// 把一台的 dirty 上傳項目當成另一台拉到的內容(seq 從 1 起)。
    fn pulled(items: &[Outgoing], latest_seq: u64) -> PullResponse {
        PullResponse {
            records: items
                .iter()
                .enumerate()
                .map(|(i, o)| Envelope {
                    id_hash: o.item.id_hash.clone(),
                    kind: o.item.kind.clone(),
                    seq: i as u64 + 1,
                    nonce: o.item.nonce.clone(),
                    ciphertext: o.item.ciphertext.clone(),
                    deleted: o.item.deleted,
                })
                .collect(),
            latest_seq,
        }
    }

    /// SP3 之前的版本拉到 `keyslot` 時的存法:不認得這個種類,密文原樣放進 `sealed`(不解密、不是 dirty、序號是 relay 給的),
    /// cursor 照常前進。
    fn kept_sealed_by_an_older_build(account: &mut AccountState, items: &[Outgoing]) {
        for env in pulled(items, items.len() as u64).records {
            account.sealed.insert(sealed_key(&env.kind, &env.id_hash), SealedRecord { envelope: env, dirty: false });
        }
    }

    #[test]
    fn a_slot_and_its_key_reach_another_device_and_the_key_stays_sealed() {
        let keys = ChainKeys::generate().unwrap();
        let mut a = AccountState::new(&keys.chain_id);
        put_slot(&mut a, SLOT_ID, Some(&synced_payload("a")), "a", 10);
        put_key_secret(&mut a, &keys, SLOT_ID, Some(&test_keys::plain()), "a", 10).unwrap();
        let items = account_outgoing(&a, &keys).unwrap();
        assert_eq!(items.len(), 2);

        let b = merge_account(&AccountState::new(&keys.chain_id), &keys, &pulled(&items, 2)).section;
        assert_eq!(live_slots(&b), vec![(SLOT_ID.to_string(), synced_payload("a"))]);
        assert!(b.records.keys().all(|k| !k.starts_with("key:")), "the key never lands in the plaintext records");
        assert_eq!(open_key_secret(&b, &keys, SLOT_ID).as_deref(), Some(test_keys::plain().as_str()));
    }

    #[test]
    fn key_records_merge_last_writer_wins_in_memory() {
        let keys = ChainKeys::generate().unwrap();
        let mut a = AccountState::new(&keys.chain_id);
        put_key_secret(&mut a, &keys, SLOT_ID, Some(&test_keys::plain()), "a", 10).unwrap();
        let older = account_outgoing(&a, &keys).unwrap();

        // b 之後寫了自己的版本(還沒上傳):拉到 a 的舊版本不能蓋掉它。
        let mut b = AccountState::new(&keys.chain_id);
        put_key_secret(&mut b, &keys, SLOT_ID, Some(&test_keys::ecdsa()), "b", 20).unwrap();
        let merged = merge_account(&b, &keys, &pulled(&older, 1)).section;
        assert_eq!(open_key_secret(&merged, &keys, SLOT_ID).as_deref(), Some(test_keys::ecdsa().as_str()));

        // 反過來:遠端較新就取遠端。
        let mut c = AccountState::new(&keys.chain_id);
        put_key_secret(&mut c, &keys, SLOT_ID, Some(&test_keys::ecdsa()), "c", 5).unwrap();
        let merged = merge_account(&c, &keys, &pulled(&older, 1)).section;
        assert_eq!(open_key_secret(&merged, &keys, SLOT_ID).as_deref(), Some(test_keys::plain().as_str()));
    }

    #[test]
    fn a_relay_rollback_reuploads_key_records() {
        let keys = ChainKeys::generate().unwrap();
        let mut a = AccountState::new(&keys.chain_id);
        put_key_secret(&mut a, &keys, SLOT_ID, Some(&test_keys::plain()), "a", 10).unwrap();
        for sealed in a.sealed.values_mut() {
            sealed.dirty = false;
            sealed.envelope.seq = 7;
        }
        a.cursor_seq = 7;
        let merged = merge_account(&a, &keys, &PullResponse { records: Vec::new(), latest_seq: 2 }).section;
        let sealed = merged.sealed.get(&key_secret_key(&keys, SLOT_ID)).unwrap();
        assert!(sealed.dirty);
        assert_eq!(sealed.envelope.seq, 0);
    }

    #[test]
    fn unreadable_slot_records_are_skipped() {
        let keys = ChainKeys::generate().unwrap();
        let mut a = AccountState::new(&keys.chain_id);
        put_slot(&mut a, SLOT_ID, Some(&KeySlotPayload { name: "../escape".into(), ..synced_payload("a") }), "a", 10);
        put_slot(&mut a, "not-a-slot-id", Some(&synced_payload("a")), "a", 10);
        let merged = merge_account(&AccountState::new(&keys.chain_id), &keys, &pulled(&account_outgoing(&a, &keys).unwrap(), 2));
        assert_eq!(merged.skipped, 2);
        assert!(live_slots(&merged.section).is_empty());
    }

    #[test]
    fn unreadable_key_records_are_skipped_and_not_kept() {
        let keys = ChainKeys::generate().unwrap();
        let mut a = AccountState::new(&keys.chain_id);
        // id 不是插槽 id、私鑰超過上限、私鑰是空的。
        put_key_secret(&mut a, &keys, "not-a-slot-id", Some(&test_keys::plain()), "a", 10).unwrap();
        put_key_secret(&mut a, &keys, SLOT_ID, Some(&"A".repeat(MAX_PRIVATE_KEY_BYTES + 1)), "a", 10).unwrap();
        put_key_secret(&mut a, &keys, "0123456789abcdef0123456789abcdef", Some(""), "a", 10).unwrap();
        let merged = merge_account(&AccountState::new(&keys.chain_id), &keys, &pulled(&account_outgoing(&a, &keys).unwrap(), 3));
        assert_eq!(merged.skipped, 3);
        assert!(merged.section.sealed.is_empty(), "a key record that is not valid is not kept, not even sealed");
        assert_eq!(open_key_secret(&merged.section, &keys, SLOT_ID), None);
    }

    #[test]
    fn a_newer_tombstone_removes_the_slot_and_its_key_on_another_device() {
        let keys = ChainKeys::generate().unwrap();
        let mut b = AccountState::new(&keys.chain_id);
        put_slot(&mut b, SLOT_ID, Some(&synced_payload("a")), "a", 10);
        put_key_secret(&mut b, &keys, SLOT_ID, Some(&test_keys::plain()), "a", 10).unwrap();
        // a 之後刪掉了插槽與金鑰:兩筆 tombstone。
        let mut a = b.clone();
        put_slot(&mut a, SLOT_ID, None, "a", 20);
        put_key_secret(&mut a, &keys, SLOT_ID, None, "a", 20).unwrap();
        let deletes = account_outgoing(&a, &keys).unwrap();
        assert!(deletes.len() == 2 && deletes.iter().all(|o| o.item.deleted));

        let merged = merge_account(&b, &keys, &pulled(&deletes, 2));
        assert_eq!(merged.skipped, 0);
        assert!(live_slots(&merged.section).is_empty());
        assert!(slot_record_exists(&merged.section, SLOT_ID), "the tombstone is kept");
        assert_eq!(open_key_secret(&merged.section, &keys, SLOT_ID), None);
    }

    #[test]
    fn a_keyslot_an_older_build_kept_sealed_shows_up_at_the_next_merge() {
        let keys = ChainKeys::generate().unwrap();
        // 另一台建立了一個插槽(連同它的金鑰)、又刪掉了另一個(tombstone)。
        let deleted = "0123456789abcdef0123456789abcdef";
        let mut a = AccountState::new(&keys.chain_id);
        put_slot(&mut a, SLOT_ID, Some(&synced_payload("a")), "a", 10);
        put_key_secret(&mut a, &keys, SLOT_ID, Some(&test_keys::plain()), "a", 10).unwrap();
        put_slot(&mut a, deleted, None, "a", 11);

        // 這台在更新之前拉到它們:舊版不認得 `keyslot`,密文原樣存進 `sealed`,cursor 已經在它們之後 —— 之後的增量拉取不會再拉到。
        let mut b = AccountState::new(&keys.chain_id);
        kept_sealed_by_an_older_build(&mut b, &account_outgoing(&a, &keys).unwrap());
        b.cursor_seq = 3;
        assert!(live_slots(&b).is_empty(), "nothing reads a sealed keyslot");
        let stored = sealed_key(RecordKind::KeySlot.as_str(), &id_hash(&keys, RecordKind::KeySlot.as_str(), SLOT_ID));
        let stored_seq = b.sealed[&stored].envelope.seq;

        // 更新之後的第一輪(什麼都沒拉到)就讓插槽出現,`sealed` 不再留它們。
        let empty_pull = PullResponse { records: Vec::new(), latest_seq: 3 };
        let merged = merge_account(&b, &keys, &empty_pull);
        assert_eq!(merged.skipped, 0);
        assert_eq!(live_slots(&merged.section), vec![(SLOT_ID.to_string(), synced_payload("a"))]);
        assert!(slot_record_exists(&merged.section, deleted), "the tombstone is promoted as a tombstone");
        let promoted = &merged.section.records[&record_key(RecordKind::KeySlot, SLOT_ID)];
        assert_eq!((promoted.seq, promoted.dirty), (stored_seq, false), "it came from the relay: nothing to upload");
        assert_eq!(merged.section.cursor_seq, 3);
        // `sealed` 只剩 `key`:它在 `sealed` 裡的位置和 SP3 一樣,舊版存的就讀得到。
        assert_eq!(merged.section.sealed.keys().collect::<Vec<_>>(), vec![&key_secret_key(&keys, SLOT_ID)]);
        assert_eq!(open_key_secret(&merged.section, &keys, SLOT_ID).as_deref(), Some(test_keys::plain().as_str()));
        // 再一輪什麼都不變。
        assert_eq!(merge_account(&merged.section, &keys, &empty_pull).section, merged.section);
    }

    #[test]
    fn a_stored_keyslot_that_cannot_be_read_is_dropped_not_promoted() {
        let keys = ChainKeys::generate().unwrap();
        // 讀得懂的一筆、名稱不合規的一筆(帳戶裡的惡意成員寫的)、別的帳戶金鑰加密的一筆(解不開)。
        let mut a = AccountState::new(&keys.chain_id);
        put_slot(&mut a, SLOT_ID, Some(&synced_payload("a")), "a", 10);
        put_slot(&mut a, "0123456789abcdef0123456789abcdef", Some(&KeySlotPayload { name: "../escape".into(), ..synced_payload("a") }), "a", 10);
        let mut b = AccountState::new(&keys.chain_id);
        kept_sealed_by_an_older_build(&mut b, &account_outgoing(&a, &keys).unwrap());
        let stranger = ChainKeys::generate().unwrap();
        let mut c = AccountState::new(&stranger.chain_id);
        put_slot(&mut c, "89abcdef0123456789abcdef01234567", Some(&synced_payload("c")), "c", 10);
        kept_sealed_by_an_older_build(&mut b, &account_outgoing(&c, &stranger).unwrap());
        assert_eq!(b.sealed.len(), 3);

        let merged = merge_account(&b, &keys, &PullResponse { records: Vec::new(), latest_seq: 0 });
        assert_eq!(merged.skipped, 2);
        assert_eq!(live_slots(&merged.section), vec![(SLOT_ID.to_string(), synced_payload("a"))]);
        assert_eq!(merged.section.records.len(), 1, "the unreadable ones are not promoted");
        assert!(merged.section.sealed.is_empty(), "and not kept sealed either");
    }

    #[test]
    fn a_stored_keyslot_is_merged_by_last_writer_wins_with_the_record_already_there() {
        let keys = ChainKeys::generate().unwrap();
        let named = |name: &str| KeySlotPayload { name: name.into(), ..synced_payload("a") };
        // 舊版存下的版本:時間 20、名稱 `stored`,relay 序號 4。
        let mut remote = AccountState::new(&keys.chain_id);
        put_slot(&mut remote, SLOT_ID, Some(&named("stored")), "a", 20);
        let mut base = AccountState::new(&keys.chain_id);
        kept_sealed_by_an_older_build(&mut base, &account_outgoing(&remote, &keys).unwrap());
        for sealed in base.sealed.values_mut() {
            sealed.envelope.seq = 4;
        }
        let empty_pull = PullResponse { records: Vec::new(), latest_seq: 4 };

        // 這台的現況比較舊(時間 10):存下的版本取代它,seq 是 relay 的、不用再上傳。
        let mut older = base.clone();
        put_slot(&mut older, SLOT_ID, Some(&named("here")), "b", 10);
        let merged = merge_account(&older, &keys, &empty_pull).section;
        let local = &merged.records[&record_key(RecordKind::KeySlot, SLOT_ID)];
        assert_eq!((slot(&merged, SLOT_ID).unwrap().name.as_str(), local.seq, local.dirty), ("stored", 4, false));

        // 現況比較新(時間 30):現況留著、仍要上傳,只是 seq 跟上 relay 的(下一次上傳才不會撞 conflict)。
        let mut newer = base.clone();
        put_slot(&mut newer, SLOT_ID, Some(&named("here")), "b", 30);
        let merged = merge_account(&newer, &keys, &empty_pull).section;
        let local = &merged.records[&record_key(RecordKind::KeySlot, SLOT_ID)];
        assert_eq!((slot(&merged, SLOT_ID).unwrap().name.as_str(), local.seq, local.dirty), ("here", 4, true));
        assert!(merged.sealed.is_empty());
        // 現況的 seq 已經比存下的那筆還新(9):不往回退,不然上傳的 base_seq 比 relay 的舊,會一直撞 conflict。
        newer.records.get_mut(&record_key(RecordKind::KeySlot, SLOT_ID)).unwrap().seq = 9;
        let merged = merge_account(&newer, &keys, &empty_pull).section;
        assert_eq!(merged.records[&record_key(RecordKind::KeySlot, SLOT_ID)].seq, 9);
    }

    #[test]
    fn the_state_file_never_holds_a_private_key_in_plaintext() {
        let keys = ChainKeys::generate().unwrap();
        let mut state = SyncStateV2::fresh("MacBook").unwrap();
        let mut account = AccountState::new(&keys.chain_id);
        put_key_secret(&mut account, &keys, SLOT_ID, Some(&test_keys::plain()), &state.device_id, 10).unwrap();
        state.account = Some(account);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        crate::sync::state_v2::save(&path, &state).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        for line in test_keys::PLAIN_BODY {
            assert!(!text.contains(line), "a line of the private key is in the state file");
        }
        // 不是因為什麼都沒存才通過:密文那一筆在檔案裡,讀回來之後以帳戶金鑰還解得開。
        assert!(text.contains(&key_secret_key(&keys, SLOT_ID)), "the sealed key record is in the state file");
        let LoadedState::Current(back) = crate::sync::state_v2::load(&path).unwrap() else { panic!("expected a v2 state") };
        assert_eq!(open_key_secret(back.account.as_ref().unwrap(), &keys, SLOT_ID).as_deref(), Some(test_keys::plain().as_str()));
    }

    #[test]
    fn a_private_key_stays_out_of_debug_output_and_error_messages() {
        let keys = ChainKeys::generate().unwrap();
        let mut state = SyncStateV2::fresh("MacBook").unwrap();
        let mut account = AccountState::new(&keys.chain_id);
        put_key_secret(&mut account, &keys, SLOT_ID, Some(&test_keys::plain()), &state.device_id, 10).unwrap();
        // 在記憶體解開的記錄:payload 就是私鑰。
        let record = account.sealed[&key_secret_key(&keys, SLOT_ID)].open(&keys).unwrap();
        state.account = Some(account);
        let assert_hidden = |shown: &str, what: &str| {
            for line in test_keys::PLAIN_BODY {
                assert!(!shown.contains(line), "a line of the private key is in {what}");
            }
        };
        assert_hidden(&format!("{record:?}"), "the Debug output of the record");
        assert_hidden(&format!("{state:?}"), "the Debug output of the state");

        // `key` 記錄出現在明文的記錄區一定是 bug:`save` 拒絕、什麼都不寫,訊息只說種類。
        state.account.as_mut().unwrap().records.insert(record_key(RecordKind::Key, SLOT_ID), LocalRecord { record, seq: 0, dirty: true });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let error = crate::sync::state_v2::save(&path, &state).unwrap_err().to_string();
        assert!(error.contains("in plaintext"), "{error}");
        assert_hidden(&error, "the error message");
        assert!(!path.exists(), "nothing was written");
    }

    #[test]
    fn a_key_record_continues_after_its_previous_version_and_its_tombstone_carries_no_secret() {
        let keys = ChainKeys::generate().unwrap();
        let mut account = AccountState::new(&keys.chain_id);
        let slot = key_secret_key(&keys, SLOT_ID);
        put_key_secret(&mut account, &keys, SLOT_ID, Some(&test_keys::plain()), "a", 100).unwrap();
        let first = account.sealed[&slot].open(&keys).unwrap();
        assert_eq!((first.version, first.updated_at_ms, account.sealed[&slot].envelope.seq), (1, 100, 0));
        // relay 收下了(序號 7):下一版接在它之後 —— 版本號加一、以 7 當 base_seq,本機時鐘落後時時間戳仍然單調。
        let sent = account.sealed.get_mut(&slot).unwrap();
        sent.dirty = false;
        sent.envelope.seq = 7;
        put_key_secret(&mut account, &keys, SLOT_ID, Some(&test_keys::ecdsa()), "a", 50).unwrap();
        let second = account.sealed[&slot].open(&keys).unwrap();
        assert_eq!((second.version, second.updated_at_ms), (2, 101));
        assert!(account.sealed[&slot].dirty);
        assert_eq!(account.sealed[&slot].envelope.seq, 7);
        assert_eq!(open_key_secret(&account, &keys, SLOT_ID).as_deref(), Some(test_keys::ecdsa().as_str()));

        // 刪除 = tombstone:不帶任何祕密,也讀不到金鑰。
        put_key_secret(&mut account, &keys, SLOT_ID, None, "a", 200).unwrap();
        let tombstone = account.sealed[&slot].open(&keys).unwrap();
        assert!(tombstone.deleted && tombstone.payload.is_null());
        assert_eq!(tombstone.version, 3);
        assert!(account.sealed[&slot].envelope.deleted && account.sealed[&slot].dirty);
        assert_eq!(account.sealed[&slot].envelope.seq, 7);
        assert_eq!(open_key_secret(&account, &keys, SLOT_ID), None);
    }

    #[test]
    fn slots_are_listed_by_name_and_a_tombstone_is_a_record_but_not_a_slot() {
        let keys = ChainKeys::generate().unwrap();
        let mut account = AccountState::new(&keys.chain_id);
        assert!(!slot_record_exists(&account, SLOT_ID));
        assert_eq!(slot(&account, SLOT_ID), None);

        // `work` 的 id 最小:依名稱排序時它排在最後,不是依記錄的 key。
        let (work, other) = ("00000000000000000000000000000001", "0123456789abcdef0123456789abcdef");
        put_slot(&mut account, work, Some(&KeySlotPayload { name: "work".into(), ..synced_payload("a") }), "a", 10);
        put_slot(&mut account, SLOT_ID, Some(&synced_payload("a")), "a", 10);
        put_slot(&mut account, other, Some(&synced_payload("b")), "b", 10);
        let order: Vec<(String, String)> = live_slots(&account).into_iter().map(|(id, p)| (id, p.name)).collect();
        assert_eq!(
            order,
            vec![(other.to_string(), "id_mac".to_string()), (SLOT_ID.to_string(), "id_mac".to_string()), (work.to_string(), "work".to_string())]
        );
        assert_eq!(slot(&account, SLOT_ID), Some(synced_payload("a")));
        assert_eq!(slot(&account, "ffffffffffffffffffffffffffffffff"), None);

        // 刪除是 tombstone:記錄還在(`slot_record_exists`),但不再是一個插槽。
        put_slot(&mut account, SLOT_ID, None, "a", 20);
        assert!(slot_record_exists(&account, SLOT_ID));
        assert_eq!(slot(&account, SLOT_ID), None);
        assert_eq!(live_slots(&account).len(), 2);
    }

    #[test]
    fn device_slots_survive_the_heartbeat() {
        let keys = ChainKeys::generate().unwrap();
        let mut account = AccountState::new(&keys.chain_id);
        assert!(plan_device(&mut account, "a", "MacBook", "macos", &[], 1_000));
        let slots = vec![DeviceSlot { slot_id: SLOT_ID.into(), fingerprint: Some(test_keys::PLAIN_FINGERPRINT.into()), synced_copy: false }];
        assert!(set_device_slots(&mut account, "a", slots.clone(), 2_000));
        assert!(!set_device_slots(&mut account, "a", slots.clone(), 3_000), "unchanged slots write nothing");
        // 一小時後的心跳(plan_device)重寫裝置記錄:slots 照樣保留。
        assert!(plan_device(&mut account, "a", "MacBook", "macos", &[], 2_000 + 60 * 60 * 1000));
        let payload: DevicePayload = serde_json::from_value(account.records["device:a"].record.payload.clone()).unwrap();
        assert_eq!(payload.slots, slots);
    }

    #[test]
    fn writing_device_slots_needs_a_device_record_and_changes_nothing_else() {
        let mut account = AccountState::new(&"a".repeat(64));
        let slots = vec![DeviceSlot { slot_id: SLOT_ID.into(), fingerprint: None, synced_copy: true }];
        // 這台還沒有裝置記錄(`plan_device` 還沒寫):什麼都不寫。
        assert!(!set_device_slots(&mut account, "a", slots.clone(), 500));
        assert!(account.records.is_empty());

        let spaces = vec!["b".repeat(64)];
        assert!(plan_device(&mut account, "a", "MacBook", "macos", &spaces, 5_000));
        // 本機時鐘落後(1_000 < 5_000):新版本的時間戳仍然單調。
        assert!(set_device_slots(&mut account, "a", slots.clone(), 1_000));
        let local = &account.records["device:a"];
        assert!(local.dirty);
        assert_eq!((local.record.version, local.record.updated_at_ms, local.record.device_id.as_str()), (2, 5_001, "a"));
        let payload: DevicePayload = serde_json::from_value(local.record.payload.clone()).unwrap();
        assert_eq!((payload.name.as_str(), payload.platform.as_str(), payload.joined_at_ms), ("MacBook", "macos", 5_000));
        assert_eq!((payload.spaces, payload.slots), (spaces, slots));
    }

    // ── 每一輪在這台維護插槽(SP3 Task 4)──────────────────────────────────────────────────────

    fn home(d: &TestDevice) -> PathBuf {
        d.ssh_dir().parent().unwrap().to_path_buf()
    }

    fn account_keys(d: &TestDevice) -> ChainKeys {
        let env = d.env();
        let keys = env.runtime.core.lock().unwrap().account_keys.clone().expect("joined");
        keys
    }

    /// 在 `d` 上建立一個插槽(Task 5 的 `setup_keys` 之前,直接寫記錄與連結):金鑰檔放在 `~/.ssh/<key_file>`,插槽連到它。
    /// 回傳(插槽 id、插槽檔名)。
    pub(crate) fn create_slot_on(d: &TestDevice, mode: SlotMode, key_text: &str, key_file: &str) -> (String, String) {
        let source = d.ssh_dir().join(key_file);
        std::fs::write(&source, key_text).unwrap();
        let facts = inspect_private_key(key_text).ok();
        let (id, name) = (new_slot_id().unwrap(), default_slot_name(key_file));
        let file = slot_file_name(&name, &id);
        let keys_dir = home(d).join(SLOT_DIR);
        slot_files::ensure_keys_dir(&keys_dir).unwrap();
        let link = slot_files::link(&source, &keys_dir.join(&file)).unwrap();
        let keys = account_keys(d);
        let env = d.env();
        let now = env.now();
        mutate(&env, |s| {
            let device_id = s.device_id.clone();
            let synced = mode == SlotMode::Synced;
            let payload = KeySlotPayload {
                schema: SLOT_SCHEMA,
                name: name.clone(),
                mode,
                origin_device_id: device_id.clone(),
                created_at_ms: now,
                public_key: synced.then(|| facts.clone().unwrap().public_key),
                fingerprint: synced.then(|| facts.clone().unwrap().fingerprint),
                key_type: synced.then(|| facts.clone().unwrap().key_type),
                has_passphrase: synced.then(|| facts.clone().unwrap().has_passphrase),
            };
            let account = s.account.as_mut().unwrap();
            put_slot(account, &id, Some(&payload), &device_id, now);
            if synced {
                put_key_secret(account, &keys, &id, Some(key_text), &device_id, now)?;
            }
            s.key_slots.insert(
                id.clone(),
                LocalSlot {
                    file_name: file.clone(),
                    source: Some(SlotSource::Linked {
                        path: source.to_string_lossy().into_owned(),
                        link,
                        fingerprint: facts.as_ref().map(|f| f.fingerprint.clone()),
                        origin: true,
                    }),
                    last_error: None,
                    asked: false,
                    payload: Some(payload),
                    // 這台的使用者選了「Sync key」:這把金鑰是這台自己上傳的(`own` 沒有)。
                    uploaded_fingerprint: synced.then(|| facts.clone().unwrap().fingerprint),
                    parked: false,
                },
            );
            Ok(())
        })
        .unwrap();
        (id, file)
    }

    /// 在 app 裡把 Personal 的主機 `web` 指到插槽(存檔 → 上傳)。
    pub(crate) fn use_slot(d: &TestDevice, personal: &str, file: &str) {
        d.save_in_app(&d.space_path(personal), &format!("Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/sshelter/keys/{file}\n"));
    }

    /// 同 `use_slot`,主機 `web` 同時用好幾個插槽(每個一行 `IdentityFile`)。
    fn use_slots(d: &TestDevice, personal: &str, files: &[&str]) {
        let lines: String = files.iter().map(|file| format!("  IdentityFile ~/.ssh/sshelter/keys/{file}\n")).collect();
        d.save_in_app(&d.space_path(personal), &format!("Host web\n  HostName 10.0.0.1\n{lines}"));
    }

    /// 在 `d` 的帳戶裡直接寫一個插槽記錄與(可選的)金鑰,不建立本機插槽、不動主機:別台(或帳戶裡的任何成員)建立的插槽。
    fn publish(d: &TestDevice, id: &str, payload: &KeySlotPayload, secret: Option<&str>) {
        let keys = account_keys(d);
        let env = d.env();
        let now = env.now();
        mutate(&env, |s| {
            let me = s.device_id.clone();
            let account = s.account.as_mut().unwrap();
            put_slot(account, id, Some(payload), &me, now);
            match secret {
                Some(text) => put_key_secret(account, &keys, id, Some(text), &me, now),
                None => Ok(()),
            }
        })
        .unwrap();
    }

    /// 刪除一個插槽:`keyslot` 與 `key` 都寫成 tombstone。
    fn unpublish(d: &TestDevice, id: &str) {
        let keys = account_keys(d);
        let env = d.env();
        let now = env.now();
        mutate(&env, |s| {
            let me = s.device_id.clone();
            let account = s.account.as_mut().unwrap();
            put_slot(account, id, None, &me, now);
            put_key_secret(account, &keys, id, None, &me, now)
        })
        .unwrap();
    }

    /// `test_keys::ecdsa()` 那把金鑰的 `synced` 記錄(名稱同 `synced_payload`,所以插槽檔名也一樣)。
    fn ecdsa_payload(origin: &str) -> KeySlotPayload {
        KeySlotPayload {
            public_key: Some(test_keys::ECDSA_PUBLIC.into()),
            fingerprint: Some(test_keys::ECDSA_FINGERPRINT.into()),
            key_type: Some("ecdsa-sha2-nistp256".into()),
            ..synced_payload(origin)
        }
    }

    fn own_payload(origin: &str) -> KeySlotPayload {
        KeySlotPayload { mode: SlotMode::Own, public_key: None, fingerprint: None, key_type: None, has_passphrase: None, ..synced_payload(origin) }
    }

    fn device_id(d: &TestDevice) -> String {
        d.state().device_id
    }

    /// `observer` 看到的 `device` 的插槽清單(來自帳戶裡那台的 `device` 記錄)。
    fn device_slots_seen_by(observer: &TestDevice, device: &TestDevice) -> Vec<DeviceSlot> {
        let id = device_id(device);
        let state = observer.state();
        crate::sync::merge::devices(state.account.as_ref().unwrap()).into_iter().find(|(d, _)| *d == id).expect("the device is listed").1.slots
    }

    /// 兩把測試金鑰的私鑰本體,任何一行都不在 `shown` 裡。公鑰本來就會出現在狀態裡(`keyslot` 的 `public_key`);ecdsa 的公鑰段
    /// 長到整整一行私鑰本體都落在它裡面 —— 那一行不算外洩。
    fn assert_key_hidden(shown: &str, what: &str) {
        for line in test_keys::PLAIN_BODY.iter().chain(test_keys::ECDSA_BODY) {
            if test_keys::PLAIN_PUBLIC.contains(line) || test_keys::ECDSA_PUBLIC.contains(line) {
                continue;
            }
            assert!(!shown.contains(line), "a line of a private key is in {what}");
        }
    }

    fn view_of(d: &TestDevice) -> Vec<SyncKeySlotView> {
        views(&d.state(), &account_keys(d), &home(d))
    }

    #[test]
    fn finds_the_hosts_that_use_each_slot() {
        assert_eq!(
            identity_slot_files("Host web\n  identityfile = \"~/.ssh/sshelter/keys/a-11111111\"\n  # IdentityFile ~/.ssh/sshelter/keys/b-22222222\n  IdentityFile ~/.ssh/id_mac\n"),
            vec!["a-11111111".to_string()]
        );
    }

    #[test]
    fn every_spelling_of_a_slot_value_counts_and_other_identity_files_do_not() {
        let text = "Host web\n  IdentityFile %d/.ssh/sshelter/keys/a-11111111\n  IDENTITYFILE\t~/.ssh/sshelter/keys/b-22222222   # work\n  IdentityFile ~/.ssh/sshelter/keys/sub/c-33333333\n  IdentityFile /home/x/.ssh/sshelter/keys/d-44444444\n  IdentityFile ~/.ssh/sshelter/keys/\n  HostName ~/.ssh/sshelter/keys/e-55555555\n";
        assert_eq!(identity_slot_files(text), vec!["a-11111111".to_string(), "b-22222222".to_string()]);
        assert!(identity_slot_files("").is_empty());
    }

    fn host_record(alias: &str, text: &str, deleted: bool) -> LocalRecord {
        LocalRecord {
            record: Record {
                kind: RecordKind::Host,
                id: alias.to_string(),
                version: 1,
                updated_at_ms: 1,
                device_id: "a".into(),
                deleted,
                payload: serde_json::to_value(HostPayload { schema: 1, text: text.to_string() }).unwrap(),
            },
            seq: 0,
            dirty: false,
        }
    }

    #[test]
    fn hosts_count_for_a_slot_only_from_selected_spaces_and_live_hosts() {
        let uses = |file: &str| format!("Host x\n  IdentityFile ~/.ssh/sshelter/keys/{file}\n");
        let mut state = SyncStateV2::fresh("MacBook").unwrap();
        let mut selected = SpaceState::new("personal-11111111.config");
        selected.records.insert(record_key(RecordKind::Host, "web"), host_record("web", &uses("a-11111111"), false));
        selected.records.insert(
            record_key(RecordKind::Host, "db"),
            host_record("db", &format!("{}  # IdentityFile ~/.ssh/sshelter/keys/b-22222222\n", uses("a-11111111")), false),
        );
        selected.records.insert(record_key(RecordKind::Host, "old"), host_record("old", &uses("a-11111111"), true));
        selected.records.insert(record_key(RecordKind::Host, "plain"), host_record("plain", "Host plain\n  IdentityFile ~/.ssh/id_mac\n", false));
        selected.records.insert(record_key(RecordKind::Host, "app"), host_record("app", &uses("c-33333333"), false));
        let mut left = SpaceState::new("work-22222222.config");
        left.selected = false;
        left.records.insert(record_key(RecordKind::Host, "laptop"), host_record("laptop", &uses("d-44444444"), false));
        state.spaces.insert("p".repeat(64), selected);
        state.spaces.insert("w".repeat(64), left);
        assert_eq!(
            slot_hosts(&state),
            BTreeMap::from([
                ("a-11111111".to_string(), vec!["db".to_string(), "web".to_string()]),
                ("c-33333333".to_string(), vec!["app".to_string()]),
            ]),
            "a deleted host, a commented line, another IdentityFile and a space this computer left do not count"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_synced_key_lands_on_the_other_computer() {
        use std::os::unix::fs::PermissionsExt;
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);

        let landed = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&landed).unwrap(), test_keys::plain());
        assert_eq!(std::fs::metadata(&landed).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(public_path(&landed)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        assert_eq!(b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));

        let b_view = views(&b.state(), &account_keys(&b), &home(&b));
        assert_eq!(b_view.len(), 1);
        assert_eq!(b_view[0].hosts, vec!["web".to_string()]);
        assert_eq!(b_view[0].origin_device, "MacBook-A");
        assert!(!b_view[0].origin_is_this);
        assert!(matches!(b_view[0].status, SlotStatusView::Ready { synced_copy: true, .. }), "{:?}", b_view[0].status);
        assert_eq!(crate::sync::dto::overview(&b.env()).unwrap().key_slots, b_view);

        // A 收到 B 的 `device.slots`。
        settle(&a);
        let a_view = views(&a.state(), &account_keys(&a), &home(&a));
        assert!(matches!(a_view[0].status, SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", a_view[0].status);
        assert_eq!(
            a_view[0].devices,
            vec![SlotDeviceView { name: "MacBook-B".into(), fingerprint: Some(test_keys::PLAIN_FINGERPRINT.into()), synced_copy: true }]
        );
    }

    #[test]
    fn an_own_key_slot_asks_the_other_computer_once() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);

        let local = b.state().key_slots[&id].clone();
        assert_eq!(local.source, None);
        assert!(local.asked);
        assert!(!home(&b).join(SLOT_DIR).join(&file).exists());
        let asked = SyncNotice::KeysNeeded { names: vec!["id_mac".into()] };
        assert_eq!(b.state().notices.iter().filter(|n| **n == asked).count(), 1);
        assert_eq!(b.events.notices.lock().unwrap().iter().filter(|n| **n == asked).count(), 1);

        let _ = crate::sync::round::sync_once(&b.env());
        assert_eq!(b.events.notices.lock().unwrap().iter().filter(|n| **n == asked).count(), 1, "asked only once");
        let view = views(&b.state(), &account_keys(&b), &home(&b));
        assert_eq!(view[0].status, SlotStatusView::NeedsKey { waiting_for_sync: false });
    }

    #[test]
    fn keys_needed_notices_merge_into_one() {
        // 還沒關掉的那一則收下新名稱:前端的「Keys for this computer」只開一次、按一次 Done 就結束。
        let mut notices = vec![SyncNotice::NewSyncCode, SyncNotice::KeysNeeded { names: vec!["id_mac".into()] }];
        add_notice(&mut notices, &SyncNotice::KeysNeeded { names: vec!["id_mac".into(), "work".into()] });
        assert_eq!(
            notices,
            vec![SyncNotice::NewSyncCode, SyncNotice::KeysNeeded { names: vec!["id_mac".into(), "work".into()] }]
        );
        // 其他種類照舊:一樣的不重複加。
        add_notice(&mut notices, &SyncNotice::NewSyncCode);
        assert_eq!(notices.len(), 2);
        let mut empty = Vec::new();
        add_notice(&mut empty, &SyncNotice::KeysNeeded { names: vec!["id_mac".into()] });
        assert_eq!(empty, vec![SyncNotice::KeysNeeded { names: vec!["id_mac".into()] }]);
    }

    #[test]
    fn a_file_in_the_slot_path_is_never_overwritten() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let theirs = home(&b).join(SLOT_DIR).join(&file);
        std::fs::create_dir_all(theirs.parent().unwrap()).unwrap();
        std::fs::write(&theirs, "mine").unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);

        assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "mine");
        assert_eq!(b.state().key_slots[&id].last_error, Some(in_the_way_message(&theirs)));
        let view = views(&b.state(), &account_keys(&b), &home(&b));
        assert_eq!(view[0].status, SlotStatusView::Error { message: in_the_way_message(&theirs) });
        // 錯誤訊息只帶路徑,不帶金鑰。
        assert!(!in_the_way_message(&theirs).contains(test_keys::PLAIN_BODY[1]));
    }

    #[test]
    fn a_key_without_its_slot_writes_nothing_until_the_slot_arrives() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let keys = account_keys(&a);
        let id = new_slot_id().unwrap();
        let file = slot_file_name("id_mac", &id);
        let env = a.env();
        let now = env.now();
        mutate(&env, |s| {
            let me = s.device_id.clone();
            put_key_secret(s.account.as_mut().unwrap(), &keys, &id, Some(&test_keys::plain()), &me, now)
        })
        .unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        assert!(!home(&b).join(SLOT_DIR).join(&file).exists());
        assert!(b.state().key_slots.is_empty());

        mutate(&env, |s| {
            let me = s.device_id.clone();
            put_slot(s.account.as_mut().unwrap(), &id, Some(&synced_payload(&me)), &me, now + 1);
            Ok(())
        })
        .unwrap();
        settle(&a);
        settle(&b);
        assert_eq!(std::fs::read_to_string(home(&b).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
    }

    #[test]
    fn a_deleted_slot_removes_links_and_keeps_copies() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);

        let keys = account_keys(&a);
        let env = a.env();
        let now = env.now();
        mutate(&env, |s| {
            let me = s.device_id.clone();
            let account = s.account.as_mut().unwrap();
            put_slot(account, &id, None, &me, now);
            put_key_secret(account, &keys, &id, None, &me, now)
        })
        .unwrap();
        settle(&a);
        settle(&b);

        assert!(!slot_files::occupied(&home(&a).join(SLOT_DIR).join(&file)), "A's link is removed");
        assert!(a.ssh_dir().join("id_mac").exists(), "the key it pointed to is untouched");
        assert!(!a.state().key_slots.contains_key(&id));
        let copy = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain(), "B keeps its copy");
        let view = views(&b.state(), &account_keys(&b), &home(&b));
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].status, SlotStatusView::NotInUse { file: copy.display().to_string() });
    }

    #[test]
    fn a_key_written_before_a_lost_commit_is_adopted() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        // 檔案寫了、狀態沒存下來:拿掉 B 對插槽的記錄,下一輪不能把自己寫的檔案當成擋路的。
        mutate(&b.env(), |s| {
            s.key_slots.clear();
            Ok(())
        })
        .unwrap();
        let _ = crate::sync::round::sync_once(&b.env());
        let local = b.state().key_slots[&id].clone();
        assert_eq!(local.last_error, None);
        assert_eq!(local.source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
        let _ = file;
    }

    #[test]
    fn a_changed_key_on_the_origin_is_reported_and_not_uploaded() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        settle(&a);

        let view = views(&a.state(), &account_keys(&a), &home(&a));
        assert!(matches!(view[0].status, SlotStatusView::SourceChanged { .. }), "{:?}", view[0].status);
        let account = a.state().account.unwrap();
        assert_eq!(open_key_secret(&account, &account_keys(&a), &id).as_deref(), Some(test_keys::plain().as_str()));
    }

    // ── 落地的規則:公鑰、指紋、擋路的檔案(計畫裁定)────────────────────────────────────────────

    #[test]
    fn the_pub_file_comes_from_the_private_key_that_passed_the_fingerprint_check() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        let path = keys_dir.join("id_mac-3fa2c1d9");
        // 記錄上的 `public_key` 是別把金鑰的、`fingerprint` 卻是這把私鑰的。這種 payload 進不了快取(`valid_slot_payload`),
        // 所以直接餵 `land`:`.pub` 之後會被 deploy 複製進伺服器的 authorized_keys,只能來自通過指紋檢查的那把私鑰。
        let payload = KeySlotPayload { public_key: Some(test_keys::ECDSA_PUBLIC.into()), ..synced_payload("a") };
        assert_eq!(land(&test_keys::plain(), &payload, &keys_dir, &path).unwrap(), test_keys::PLAIN_FINGERPRINT);
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::plain());
    }

    #[test]
    fn a_key_that_fails_the_check_writes_nothing_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("keys");
        let path = keys_dir.join("id_mac-3fa2c1d9");
        let pem = format!("{}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n{}\n", concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), concat!("-----END RSA ", "PRIVATE KEY-----"));
        // 指紋對不上(記錄是 plain 的、金鑰是 ecdsa)、不是 OpenSSH 格式、根本不是金鑰、超過大小。
        for secret in [test_keys::ecdsa(), pem, "garbage".to_string(), "A".repeat(MAX_PRIVATE_KEY_BYTES + 1)] {
            assert_eq!(land(&secret, &synced_payload("a"), &keys_dir, &path), Err(MISMATCH_MESSAGE.to_string()));
            assert!(!keys_dir.exists(), "not even the directory is created");
        }
        // 記錄本身沒有指紋(`own`):不是同步的金鑰,不落地。
        assert_eq!(land(&test_keys::plain(), &own_payload("a"), &keys_dir, &path), Err(MISMATCH_MESSAGE.to_string()));
        assert!(!keys_dir.exists());
    }

    #[test]
    fn a_synced_key_that_does_not_match_its_record_is_refused_and_never_shown() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let id = new_slot_id().unwrap();
        let file = slot_file_name("id_mac", &id);
        // 記錄說這是 ecdsa 那把,`key` 裡放的卻是 plain:帳戶裡的成員寫得出這種東西。
        publish(&a, &id, &ecdsa_payload(&device_id(&a)), Some(&test_keys::plain()));
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);

        let slot_path = home(&b).join(SLOT_DIR).join(&file);
        assert!(!slot_files::occupied(&slot_path) && !slot_files::occupied(&public_path(&slot_path)));
        let local = b.state().key_slots[&id].clone();
        assert_eq!((local.source, local.last_error.as_deref()), (None, Some(MISMATCH_MESSAGE)));
        assert_eq!(view_of(&b)[0].status, SlotStatusView::Error { message: MISMATCH_MESSAGE.to_string() });
        // 拒收的金鑰不會出現在任何看得到的地方。
        assert_key_hidden(&std::fs::read_to_string(b.home.path().join("data").join("sync-state.json")).unwrap(), "the state file");
        assert_key_hidden(&serde_json::to_string(&crate::sync::dto::overview(&b.env()).unwrap()).unwrap(), "the overview");
        assert_key_hidden(&format!("{:?}{:?}", b.state(), b.events.notices.lock().unwrap()), "Debug output");
    }

    #[test]
    fn a_landed_key_never_reaches_the_state_file_the_overview_or_the_events() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (_id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let landed = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(landed).unwrap(), test_keys::plain(), "the key did land");

        assert_key_hidden(&std::fs::read_to_string(b.home.path().join("data").join("sync-state.json")).unwrap(), "the state file");
        assert_key_hidden(&serde_json::to_string(&crate::sync::dto::overview(&b.env()).unwrap()).unwrap(), "the overview");
        assert_key_hidden(&format!("{:?}{:?}", b.state(), b.events.notices.lock().unwrap()), "Debug output");
        assert_key_hidden(&format!("{:?}", view_of(&b)), "the slot views");
    }

    // 插槽檔名(`<name>-<id8>`)不保證在插槽 id 之間唯一:帳戶裡的成員可以發佈同名、同 id 前 8 字元的另一個插槽。
    // 一個檔案是不是 SSHelter 放的,只看這個插槽 id 自己的本機記錄,不看檔名。

    #[test]
    fn two_slots_with_the_same_file_name_never_overwrite_each_others_copy() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (first, second) = (format!("3fa2c1d9{}", "0".repeat(24)), format!("3fa2c1d9{}", "f".repeat(24)));
        let file = slot_file_name("id_mac", &first);
        assert_eq!(file, slot_file_name("id_mac", &second));
        let me = device_id(&a);
        publish(&a, &first, &synced_payload(&me), Some(&test_keys::plain()));
        publish(&a, &second, &ecdsa_payload(&me), Some(&test_keys::ecdsa()));
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);

        let landed = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&landed).unwrap(), test_keys::plain(), "the one that was first on this computer keeps the path");
        let state = b.state();
        assert_eq!(state.key_slots[&first].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
        assert_eq!(state.key_slots[&second].source, None);
        assert_eq!(state.key_slots[&second].last_error, Some(in_the_way_message(&landed)));

        // 另一個被刪掉:第一個的檔案不動。
        unpublish(&a, &second);
        settle(&a);
        settle(&b);
        assert_eq!(std::fs::read_to_string(&landed).unwrap(), test_keys::plain());
        assert!(b.state().key_slots.contains_key(&first) && !b.state().key_slots.contains_key(&second));
        // 第一個被刪掉:副本留著(不是 SSHelter 放的連結),也不會被另一個覆蓋 —— 另一個重新發佈,仍然擋在外面。
        publish(&a, &second, &ecdsa_payload(&me), Some(&test_keys::ecdsa()));
        unpublish(&a, &first);
        settle(&a);
        settle(&b);
        assert_eq!(std::fs::read_to_string(&landed).unwrap(), test_keys::plain());
        assert_eq!(b.state().key_slots[&second].last_error, Some(in_the_way_message(&landed)));
    }

    #[test]
    fn a_slot_with_the_same_file_name_never_replaces_or_removes_the_link_of_another_slot() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        // 同名、同 id 前 8 字元、最後一個字元不同。
        let mut chars: Vec<char> = id.chars().collect();
        chars[31] = if chars[31] == '0' { '1' } else { '0' };
        let other: String = chars.into_iter().collect();
        assert!(other != id && slot_file_name("id_mac", &other) == file);
        publish(&a, &other, &ecdsa_payload(&device_id(&a)), Some(&test_keys::ecdsa()));
        use_slot(&a, &personal, &file);
        settle(&a);

        let link = home(&a).join(SLOT_DIR).join(&file);
        let source = a.ssh_dir().join("id_mac");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain(), "the link still reaches the first slot's key");
        #[cfg(unix)]
        assert_eq!(std::fs::read_link(&link).unwrap(), source);
        assert!(matches!(&a.state().key_slots[&id].source, Some(SlotSource::Linked { origin: true, .. })));
        assert_eq!(a.state().key_slots[&other].last_error, Some(in_the_way_message(&link)));

        // 第二個被刪掉:它從來沒有放過東西,第一個的連結不動。
        unpublish(&a, &other);
        settle(&a);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain());
        assert!(!a.state().key_slots.contains_key(&other));
        // 第一個被刪掉:只移除它自己的連結,它指到的金鑰不動;路徑空出來之後,另一個才放得進去。
        publish(&a, &other, &ecdsa_payload(&device_id(&a)), Some(&test_keys::ecdsa()));
        unpublish(&a, &id);
        settle(&a);
        assert_eq!(std::fs::read_to_string(&source).unwrap(), test_keys::plain(), "the key the link pointed to is untouched");
        settle(&a);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::ecdsa());
        assert_eq!(std::fs::read_to_string(&source).unwrap(), test_keys::plain());
    }

    #[test]
    #[cfg(unix)]
    fn a_slot_renamed_in_the_account_never_makes_this_computer_touch_the_new_path() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let old_link = home(&a).join(SLOT_DIR).join(&file);
        assert!(slot_files::occupied(&old_link));

        // 帳戶裡的惡意成員把這個插槽改名(spec 沒有改名):新名稱的路徑上正好有使用者自己的東西(連到另一把金鑰的 symlink)。
        let new_file = slot_file_name("renamed", &id);
        let theirs = home(&a).join(SLOT_DIR).join(&new_file);
        let work_key = a.ssh_dir().join("id_work");
        std::fs::write(&work_key, test_keys::ecdsa()).unwrap();
        std::os::unix::fs::symlink(&work_key, &theirs).unwrap();
        publish(&a, &id, &KeySlotPayload { name: "renamed".into(), ..own_payload(&device_id(&a)) }, None);
        settle(&a);
        settle(&a);

        assert_eq!(std::fs::read_link(&theirs).unwrap(), work_key, "what is at the new path is not this slot's: it stays");
        assert_eq!(std::fs::read_to_string(&work_key).unwrap(), test_keys::ecdsa());
        assert!(slot_files::occupied(&old_link), "the files this slot recorded are left where they are, for the hosts that still name them");
        assert_eq!(std::fs::read_to_string(&old_link).unwrap(), test_keys::plain());
        // 主機寫的還是舊名稱:新名稱沒有主機用到,這台也不再記著這個插槽。
        assert!(!a.state().key_slots.contains_key(&id));
        assert_eq!(view_of(&a)[0].status, SlotStatusView::NotUsedHere);
    }

    #[test]
    #[cfg(unix)]
    fn a_file_the_user_put_in_place_of_the_link_is_not_removed_when_the_slot_goes_unused() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        // 使用者自己把插槽上的 symlink 換成一份金鑰(SSHelter 沒有放它)。
        let slot_path = home(&a).join(SLOT_DIR).join(&file);
        std::fs::remove_file(&slot_path).unwrap();
        std::fs::write(&slot_path, test_keys::ecdsa()).unwrap();
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);

        assert_eq!(std::fs::read_to_string(&slot_path).unwrap(), test_keys::ecdsa(), "not removed");
        assert!(matches!(&a.state().key_slots[&id].source, Some(SlotSource::Linked { origin: true, .. })), "the record is kept like any parked link");
        assert!(a.state().key_slots[&id].parked, "but it does not own the user's file");
        assert_eq!(view_of(&a)[0].status, SlotStatusView::NotUsedHere);
        assert_eq!(std::fs::read_to_string(a.ssh_dir().join("id_mac")).unwrap(), test_keys::plain());

        // 又用到了:那個檔案擋路,不是「連到原檔」。
        use_slot(&a, &personal, &file);
        settle(&a);
        assert_eq!(view_of(&a)[0].status, SlotStatusView::Error { message: in_the_way_message(&slot_path) });
        assert_eq!(std::fs::read_to_string(&slot_path).unwrap(), test_keys::ecdsa());
    }

    /// 把 `create_slot_on` 做出來的連結換成真正的 hard link(Windows 上 `slot_files::link` 做的就是這個),狀態記成 `HardLink`。
    fn make_it_a_hard_link(d: &TestDevice, id: &str, file: &str, key_file: &str) {
        let slot_path = home(d).join(SLOT_DIR).join(file);
        std::fs::remove_file(&slot_path).unwrap();
        std::fs::hard_link(d.ssh_dir().join(key_file), &slot_path).unwrap();
        mutate(&d.env(), |s| {
            if let Some(SlotSource::Linked { link, .. }) = s.key_slots.get_mut(id).and_then(|l| l.source.as_mut()) {
                *link = LinkKind::HardLink;
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn a_hard_link_that_is_the_last_name_of_a_key_is_not_removed_when_the_slot_goes_unused() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let ssh = a.ssh_dir();
        // 三個 hard link 的插槽:原檔還在、原檔被刪了、原檔被換成另一把。
        let (kept_id, kept_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_kept");
        let (gone_id, gone_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_gone");
        let (swap_id, swap_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_swap");
        for (id, file, key) in [(&kept_id, &kept_file, "id_kept"), (&gone_id, &gone_file, "id_gone"), (&swap_id, &swap_file, "id_swap")] {
            make_it_a_hard_link(&a, id, file, key);
        }
        use_slots(&a, &personal, &[&kept_file, &gone_file, &swap_file]);
        settle(&a);
        let slot = |file: &str| home(&a).join(SLOT_DIR).join(file);
        // 使用者刪了一個原檔、把另一個換成別把金鑰(寫新檔再 rename:舊的內容只剩插槽裡的 hard link)。
        std::fs::remove_file(ssh.join("id_gone")).unwrap();
        std::fs::write(ssh.join("id_swap.new"), test_keys::ecdsa()).unwrap();
        std::fs::rename(ssh.join("id_swap.new"), ssh.join("id_swap")).unwrap();

        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);

        // 原檔還在、內容相同:只拿掉這個名字,金鑰還在原檔;記錄留著。
        assert!(!slot_files::occupied(&slot(&kept_file)));
        assert_eq!(std::fs::read_to_string(ssh.join("id_kept")).unwrap(), test_keys::plain());
        assert!(matches!(&a.state().key_slots[&kept_id].source, Some(SlotSource::Linked { link: LinkKind::HardLink, origin: true, .. })));
        assert!(a.state().key_slots[&kept_id].parked);
        // 原檔不見、原檔換成別把:插槽裡的 hard link 可能是那把金鑰僅存的名字 —— 留著,記成複製檔(它在路徑上,是這個插槽的,沒有收起來)。
        for (id, file) in [(&gone_id, &gone_file), (&swap_id, &swap_file)] {
            assert_eq!(std::fs::read_to_string(slot(file)).unwrap(), test_keys::plain(), "the old key bytes are still there");
            assert!(matches!(&a.state().key_slots[id].source, Some(SlotSource::Linked { link: LinkKind::Copy, .. })));
            assert_eq!(a.state().key_slots[id].last_error, None);
            assert!(!a.state().key_slots[id].parked);
        }
        let shown = view_of(&a);
        let status_of = |id: &str| shown.iter().find(|v| v.id == id).unwrap().status.clone();
        assert_eq!(status_of(&kept_id), SlotStatusView::NotUsedHere);
        assert_eq!(status_of(&gone_id), SlotStatusView::NotInUse { file: slot(&gone_file).display().to_string() });
        assert_eq!(status_of(&swap_id), SlotStatusView::NotInUse { file: slot(&swap_file).display().to_string() });
        // `device.slots`:收起來的連結不列,放著金鑰的兩個複製檔照列。
        let listed: Vec<String> = device_slots_seen_by(&a, &a).into_iter().map(|d| d.slot_id).collect();
        assert!(!listed.contains(&kept_id) && listed.contains(&gone_id) && listed.contains(&swap_id), "{listed:?}");

        // 收起來的那個又用到了:重新連結,記錄(含 `origin`)不變。
        use_slots(&a, &personal, &[&kept_file]);
        settle(&a);
        assert_eq!(std::fs::read_to_string(slot(&kept_file)).unwrap(), test_keys::plain());
        assert!(matches!(&a.state().key_slots[&kept_id].source, Some(SlotSource::Linked { origin: true, .. })));
    }

    #[test]
    fn a_deleted_slot_keeps_a_hard_link_that_is_the_last_name_of_its_key() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (kept_id, kept_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_kept");
        let (gone_id, gone_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_gone");
        make_it_a_hard_link(&a, &kept_id, &kept_file, "id_kept");
        make_it_a_hard_link(&a, &gone_id, &gone_file, "id_gone");
        use_slots(&a, &personal, &[&kept_file, &gone_file]);
        settle(&a);
        std::fs::remove_file(a.ssh_dir().join("id_gone")).unwrap();
        // 兩個插槽都被別台刪除了(tombstone),主機還用著。
        unpublish(&a, &kept_id);
        unpublish(&a, &gone_id);
        settle(&a);

        let slot = |file: &str| home(&a).join(SLOT_DIR).join(file);
        // 原檔還在:移除連結、忘掉記錄(和 symlink 一樣)。
        assert!(!slot_files::occupied(&slot(&kept_file)));
        assert!(!a.state().key_slots.contains_key(&kept_id));
        // 原檔不見了:插槽裡的 hard link 是這把金鑰僅存的名字,不拿掉;記成複製檔,Keys 列為 Not in use(可以刪除)。
        assert_eq!(std::fs::read_to_string(slot(&gone_file)).unwrap(), test_keys::plain());
        assert!(matches!(&a.state().key_slots[&gone_id].source, Some(SlotSource::Linked { link: LinkKind::Copy, .. })));
        let shown = view_of(&a);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].id, gone_id);
        assert_eq!(shown[0].status, SlotStatusView::NotInUse { file: slot(&gone_file).display().to_string() });
    }

    // ── 收起來的連結(`park_link`)不擁有路徑上的東西 ───────────────────────────────────────────────

    /// A 上一個已經收起來的 `own` 插槽(沒有主機用到,連結檔已經拿掉):`hard_link` 決定記錄的連結種類(hard link 在 Windows 上才會做出來,
    /// 這裡用真的 hard link)。回傳(A、Personal 的 id、插槽 id、插槽檔名)。
    fn a_parked_slot(hard_link: bool) -> (TestDevice, String, String, String) {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        if hard_link {
            make_it_a_hard_link(&a, &id, &file, "id_mac");
        }
        use_slot(&a, &personal, &file);
        settle(&a);
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        assert!(!slot_files::occupied(&home(&a).join(SLOT_DIR).join(&file)), "the link file is gone");
        assert!(a.state().key_slots[&id].parked, "and the record says so");
        (a, personal, id, file)
    }

    #[test]
    fn a_file_at_a_parked_links_path_is_never_overwritten_when_the_slot_is_used_again() {
        for hard_link in [false, true] {
            let (a, personal, id, file) = a_parked_slot(hard_link);
            let path = home(&a).join(SLOT_DIR).join(&file);
            // 收起來的連結的位置上,使用者(或別的程式)放了一個檔案。
            std::fs::write(&path, "mine").unwrap();

            // 還是沒有主機用到:不看它、不碰它,也不把它記成這個插槽的複製檔。
            settle(&a);
            settle(&a);
            let local = a.state().key_slots[&id].clone();
            assert!(local.parked, "hard_link={hard_link}: {local:?}");
            assert!(matches!(&local.source, Some(SlotSource::Linked { link, .. }) if *link != LinkKind::Copy), "hard_link={hard_link}: {local:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "mine");

            // 又用到了:擋路,檔案不動,記錄還是收起來的,不列在 `device.slots`。
            use_slot(&a, &personal, &file);
            settle(&a);
            let local = a.state().key_slots[&id].clone();
            assert_eq!(local.last_error, Some(in_the_way_message(&path)), "hard_link={hard_link}");
            assert!(local.parked);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "mine", "hard_link={hard_link}: not relinked over it");
            assert_eq!(view_of(&a)[0].status, SlotStatusView::Error { message: in_the_way_message(&path) });
            assert_eq!(device_slots_seen_by(&a, &a), Vec::new());

            // 主機又不用了:不再回報擋路(那是用到它的時候才有的問題),檔案還是不動。
            a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
            settle(&a);
            assert_eq!(a.state().key_slots[&id].last_error, None);
            assert_eq!(view_of(&a)[0].status, SlotStatusView::NotUsedHere);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "mine");

            // 用到、使用者把檔案移走:路徑空著,重新連結,錯誤與收起來的旗標都清掉。
            use_slot(&a, &personal, &file);
            settle(&a);
            std::fs::remove_file(&path).unwrap();
            settle(&a);
            let local = a.state().key_slots[&id].clone();
            assert!(!local.parked && local.last_error.is_none(), "hard_link={hard_link}: {local:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::plain());
            assert_eq!(device_slots_seen_by(&a, &a).len(), 1);
        }
    }

    #[test]
    fn a_tombstoned_parked_slot_forgets_its_record_and_leaves_the_file_at_its_path_alone() {
        for hard_link in [false, true] {
            let (a, _personal, id, file) = a_parked_slot(hard_link);
            let path = home(&a).join(SLOT_DIR).join(&file);
            std::fs::write(&path, "mine").unwrap();
            unpublish(&a, &id);
            settle(&a);

            assert_eq!(std::fs::read_to_string(&path).unwrap(), "mine", "hard_link={hard_link}: not removed");
            assert!(!a.state().key_slots.contains_key(&id), "hard_link={hard_link}: forgotten, not adopted as this slot's copy");
            assert!(view_of(&a).is_empty());
            assert_eq!(std::fs::read_to_string(a.ssh_dir().join("id_mac")).unwrap(), test_keys::plain());
        }
    }

    #[test]
    fn a_member_cannot_make_a_parked_link_relink_over_another_slots_copy() {
        for hard_link in [false, true] {
            let (a, personal, x, file) = a_parked_slot(hard_link);
            let path = home(&a).join(SLOT_DIR).join(&file);
            // 帳戶裡的成員發佈同名、同 id 前 8 字元、排在 X 前面的 Z,以他自己的金鑰同步,再讓主機用到這個檔案。
            let z = format!("{}{}", &x[..8], "0".repeat(24));
            assert!(z < x && slot_file_name("id_mac", &z) == file);
            publish(&a, &z, &ecdsa_payload("a-member"), Some(&test_keys::ecdsa()));
            use_slot(&a, &personal, &file);
            settle(&a);

            // Z 放進空著的路徑;X 不能再連結蓋過去,也不能被當成放著自己的金鑰。
            assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa(), "hard_link={hard_link}: Z's copy is still there");
            let state = a.state();
            assert_eq!(state.key_slots[&z].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::ECDSA_FINGERPRINT.into() }));
            assert_eq!(state.key_slots[&x].last_error, Some(in_the_way_message(&path)), "hard_link={hard_link}");
            assert!(state.key_slots[&x].parked);
            let listed: Vec<String> = device_slots_seen_by(&a, &a).into_iter().map(|d| d.slot_id).collect();
            assert_eq!(listed, vec![z.clone()], "only Z is in the slot");

            // 成員把 Z 的記錄改成 plain 的公鑰與指紋,帳戶又掉了兩個插槽(沒有 SP3 的電腦更換了同步碼):X 的金鑰不會被當成 Z 的 `key` 上傳。
            publish(&a, &z, &synced_payload("a-member"), None);
            settle(&a);
            let keys = account_keys(&a);
            let mut state = a.state();
            let account = state.account.as_mut().unwrap();
            for id in [&x, &z] {
                account.records.remove(&record_key(RecordKind::KeySlot, id));
                account.sealed.remove(&key_secret_key(&keys, id));
            }
            reconcile(&mut state, &keys, &home(&a), 1_000);
            let account = state.account.as_ref().unwrap();
            for id in [&x, &z] {
                assert_eq!(open_key_secret(account, &keys, id), None, "hard_link={hard_link}: no private key is uploaded for {id}");
                assert!(!account.sealed.contains_key(&key_secret_key(&keys, id)));
            }
        }
    }

    #[test]
    fn a_synced_copy_whose_file_is_no_longer_the_recorded_key_is_not_uploaded_as_the_slots_key() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        // B 的副本被換成了別把金鑰(使用者的檔案,或別的插槽放的),記錄還說這是 plain 的;帳戶裡的成員同時把插槽的指紋改成那一把。
        std::fs::write(home(&b).join(SLOT_DIR).join(&file), test_keys::ecdsa()).unwrap();
        publish(&a, &id, &ecdsa_payload(&device_id(&a)), None);
        settle(&a);
        settle(&b);
        let local = b.state().key_slots[&id].clone();
        assert_eq!(local.source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
        assert_eq!(local.payload.and_then(|p| p.fingerprint).as_deref(), Some(test_keys::ECDSA_FINGERPRINT), "this computer saw the flip");

        // 帳戶掉了這個插槽:路徑上現在的檔案不是記錄裡的那一把,不能當成這個插槽的 `key` 上傳。
        let keys = account_keys(&b);
        let mut state = b.state();
        let account = state.account.as_mut().unwrap();
        account.records.remove(&record_key(RecordKind::KeySlot, &id));
        account.sealed.remove(&key_secret_key(&keys, &id));
        assert!(reconcile(&mut state, &keys, &home(&b), 1_000).changed);
        let account = state.account.as_ref().unwrap();
        assert!(slot(account, &id).is_some(), "the keyslot is written again");
        assert!(!account.sealed.contains_key(&key_secret_key(&keys, &id)), "no key record at all");
    }

    #[test]
    fn a_parked_slot_that_is_renamed_in_the_account_starts_over_not_parked() {
        let (a, personal, id, _file) = a_parked_slot(false);
        // 帳戶裡的成員把插槽改名(spec 沒有改名),主機用到新名稱的路徑:這個插槽記著的舊路徑從此不再碰,新路徑從頭來過。
        publish(&a, &id, &KeySlotPayload { name: "renamed".into(), ..own_payload(&device_id(&a)) }, None);
        use_slot(&a, &personal, &slot_file_name("renamed", &id));
        settle(&a);
        let local = a.state().key_slots[&id].clone();
        assert_eq!((&local.source, local.parked, local.asked), (&None, false, true), "{local:?}");
    }

    #[test]
    #[cfg(unix)]
    fn a_parked_link_that_was_made_again_before_the_state_was_saved_is_recognised() {
        let (a, personal, id, file) = a_parked_slot(false);
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        // 上一輪重新連結了、狀態卻沒存下來(`commit` 被搶先):路徑上正好是連結會做出來的 symlink,就是這個插槽自己的。
        std::os::unix::fs::symlink(&source, &path).unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        let local = a.state().key_slots[&id].clone();
        assert!(!local.parked && local.last_error.is_none(), "{local:?}");
        assert_eq!(std::fs::read_link(&path).unwrap(), source);
        assert_eq!(device_slots_seen_by(&a, &a).len(), 1);

        // 指到別把金鑰的 symlink 就不是了。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        assert!(a.state().key_slots[&id].parked && !slot_files::occupied(&path));
        let other = a.ssh_dir().join("id_work");
        std::fs::write(&other, test_keys::ecdsa()).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        assert_eq!(a.state().key_slots[&id].last_error, Some(in_the_way_message(&path)));
        assert_eq!(std::fs::read_link(&path).unwrap(), other, "not replaced");
    }

    // ── 維護:連結、副本、通知 ──────────────────────────────────────────────────────────────────

    #[test]
    fn a_slot_no_host_uses_is_parked_without_its_link_and_a_synced_copy_stays() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let (link, copy) = (home(&a).join(SLOT_DIR).join(&file), home(&b).join(SLOT_DIR).join(&file));
        assert!(slot_files::occupied(&link) && slot_files::occupied(&copy));
        assert_eq!(device_slots_seen_by(&a, &a).len(), 1);
        let linked = a.state().key_slots[&id].clone();

        // 主機改成不再用插槽(兩台都不再需要它)。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        settle(&b);

        assert!(!slot_files::occupied(&link), "the link is removed");
        assert_eq!(std::fs::read_to_string(a.ssh_dir().join("id_mac")).unwrap(), test_keys::plain(), "the key it pointed to is untouched");
        assert_eq!(
            a.state().key_slots[&id],
            LocalSlot { parked: true, ..linked },
            "the record stays: the link, its origin and the key synced from here are not forgotten"
        );
        assert_eq!(view_of(&a)[0].status, SlotStatusView::NotUsedHere);
        assert_eq!(device_slots_seen_by(&a, &a), Vec::new(), "a parked link is not listed: nothing is in the slot");

        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain(), "a synced copy is never removed on its own");
        assert_eq!(view_of(&b)[0].status, SlotStatusView::NotInUse { file: copy.display().to_string() });
        assert_eq!(device_slots_seen_by(&a, &b).len(), 1, "B still has its copy");
    }

    #[test]
    fn a_slot_unused_for_a_round_is_linked_again_with_its_origin_and_nobody_is_asked() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        // `own` 插槽的來源電腦:連結和「這台是來源」就是這台的全部記錄,忘掉就得再問使用者一次(spec §1「之後不再問」)。
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let link = home(&a).join(SLOT_DIR).join(&file);
        slot_files::write_public(&link, test_keys::PLAIN_PUBLIC).unwrap();
        let linked = a.state().key_slots[&id].clone();
        assert!(matches!(&linked.source, Some(SlotSource::Linked { origin: true, .. })));

        // 主機的 `IdentityFile` 暫時拿掉(例如編輯到一半存檔)。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        assert!(!slot_files::occupied(&link), "only the link file is removed");
        assert!(slot_files::occupied(&public_path(&link)), "the .pub stays for the next time");
        assert_eq!(a.state().key_slots[&id], LocalSlot { parked: true, ..linked.clone() }, "the record is kept, marked as parked");
        assert_eq!(view_of(&a)[0].status, SlotStatusView::NotUsedHere);
        assert_eq!(device_slots_seen_by(&a, &a), Vec::new());
        // 收起來之後什麼都沒變的一輪:不寫新版本、不要求提交。
        let keys = account_keys(&a);
        let mut state = a.state();
        let before = state.clone();
        let quiet = reconcile(&mut state, &keys, &home(&a), 9_000);
        assert!(!quiet.changed && quiet.notices.is_empty());
        assert_eq!(state, before);

        // 又用到了:重新連結,記錄(含 `origin`)不變,沒有人被問。
        use_slot(&a, &personal, &file);
        settle(&a);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain());
        assert_eq!(a.state().key_slots[&id], linked);
        assert!(matches!(view_of(&a)[0].status, SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", view_of(&a)[0].status);
        assert_eq!(device_slots_seen_by(&a, &a).len(), 1);
        assert!(a.state().notices.is_empty() && a.events.notices.lock().unwrap().is_empty(), "no KeysNeeded for a slot this computer already has");
    }

    #[test]
    fn an_unused_slot_does_not_keep_showing_an_error_from_when_it_was_needed() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let source = a.ssh_dir().join("id_mac");
        std::fs::remove_file(&source).unwrap();
        settle(&a);
        assert!(matches!(view_of(&a)[0].status, SlotStatusView::Error { .. }), "{:?}", view_of(&a)[0].status);

        // 主機不再用到它:沒有什麼需要使用者處理的,記錄(連結、來源路徑)留著。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        assert_eq!(a.state().key_slots[&id].last_error, None);
        assert_eq!(view_of(&a)[0].status, SlotStatusView::NotUsedHere);
        assert!(matches!(&a.state().key_slots[&id].source, Some(SlotSource::Linked { path, .. }) if *path == source.to_string_lossy()));
    }

    #[test]
    fn a_space_file_that_grows_back_does_not_make_the_origin_forget_its_link() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        // 另一個 space 讓這一輪照常做完:Personal 的 space 檔被清空、重新長出來的那一輪,它的主機暫時不在快取裡。
        let work = crate::sync::spaces::create_space(&a.env(), "Work").unwrap();
        a.save_in_app(&a.space_path(&work), "Host db\n");
        settle(&a);
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let linked = a.state().key_slots[&id].clone();
        let link = home(&a).join(SLOT_DIR).join(&file);

        a.write_externally(&a.space_path(&personal), "");
        settle(&a);
        settle(&a);

        assert!(a.read(&a.space_path(&personal)).contains(&file), "the host is back");
        assert_eq!(a.state().key_slots[&id], linked, "still the origin's link, not a copy of the synced key");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain());
        #[cfg(unix)]
        assert_eq!(std::fs::read_link(&link).unwrap(), a.ssh_dir().join("id_mac"));
        assert!(a.state().notices.is_empty());
    }

    #[test]
    fn a_synced_copy_the_user_deleted_is_put_back_while_a_host_uses_it() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let copy = home(&b).join(SLOT_DIR).join(&file);
        std::fs::remove_file(&copy).unwrap();
        std::fs::remove_file(public_path(&copy)).unwrap();

        settle(&b);
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain());
        assert_eq!(std::fs::read_to_string(public_path(&copy)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        assert_eq!(b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
    }

    #[test]
    fn a_link_whose_key_is_gone_says_so_and_recovers_when_the_key_is_back() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let source = a.ssh_dir().join("id_mac");
        std::fs::remove_file(&source).unwrap();
        settle(&a);

        let shown = source.to_string_lossy().into_owned();
        assert_eq!(view_of(&a)[0].status, SlotStatusView::Error { message: source_gone_message(&shown) });
        assert!(matches!(a.state().key_slots[&id].source, Some(SlotSource::Linked { .. })), "the record of the link stays");

        std::fs::write(&source, test_keys::plain()).unwrap();
        settle(&a);
        assert_eq!(a.state().key_slots[&id].last_error, None);
        assert!(matches!(view_of(&a)[0].status, SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", view_of(&a)[0].status);
    }

    #[test]
    #[cfg(unix)]
    fn a_link_that_was_removed_is_made_again_and_a_copy_follows_its_source() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let (slot_path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        let is_symlink = |p: &std::path::Path| std::fs::symlink_metadata(p).unwrap().file_type().is_symlink();

        // 插槽被刪掉了:下一輪重新連結。
        std::fs::remove_file(&slot_path).unwrap();
        settle(&a);
        assert!(is_symlink(&slot_path) && std::fs::read_to_string(&slot_path).unwrap() == test_keys::plain());

        // Windows 的複製檔(這裡在 Unix 上手動做出來,狀態記著 `Copy`):內容還和原檔一樣就不動它。
        std::fs::remove_file(&slot_path).unwrap();
        std::fs::write(&slot_path, test_keys::plain()).unwrap();
        mutate(&a.env(), |s| {
            if let Some(SlotSource::Linked { link, .. }) = s.key_slots.get_mut(&id).and_then(|l| l.source.as_mut()) {
                *link = LinkKind::Copy;
            }
            Ok(())
        })
        .unwrap();
        settle(&a);
        assert!(!is_symlink(&slot_path), "a copy that still matches its source is left alone");
        // 原檔換成另一把:複製不會跟著走,下一輪重新連結,指紋跟著更新。
        std::fs::write(&source, test_keys::ecdsa()).unwrap();
        settle(&a);
        assert!(is_symlink(&slot_path));
        assert_eq!(std::fs::read_to_string(&slot_path).unwrap(), test_keys::ecdsa());
        match &a.state().key_slots[&id].source {
            Some(SlotSource::Linked { link: LinkKind::Symlink, fingerprint, .. }) => {
                assert_eq!(fingerprint.as_deref(), Some(test_keys::ECDSA_FINGERPRINT));
            }
            other => panic!("expected a symlink to the new key, got {other:?}"),
        }
    }

    #[test]
    fn a_new_synced_key_is_offered_to_a_computer_with_the_old_copy_and_never_forced_on_it() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let copy = home(&b).join(SLOT_DIR).join(&file);

        // A 換了金鑰、把新的一把同步出去(`key` 與 `keyslot` 一起更新)。
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        publish(&a, &id, &ecdsa_payload(&device_id(&a)), Some(&test_keys::ecdsa()));
        settle(&a);
        settle(&b);

        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain(), "B's copy is not replaced");
        assert_eq!(b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
        assert_eq!(view_of(&b)[0].status, SlotStatusView::SyncedAvailable { file: copy.display().to_string() });
        // A 連到的就是同步的那把:沒有事。
        assert_eq!(
            view_of(&a)[0].status,
            SlotStatusView::Ready {
                file: a.ssh_dir().join("id_mac").to_string_lossy().into_owned(),
                synced_copy: false,
                fingerprint: Some(test_keys::ECDSA_FINGERPRINT.into())
            }
        );
    }

    #[test]
    fn the_device_record_lists_each_slot_and_a_quiet_round_changes_nothing() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        settle(&a);
        let slot_of = |synced_copy| DeviceSlot { slot_id: id.clone(), fingerprint: Some(test_keys::PLAIN_FINGERPRINT.into()), synced_copy };
        assert_eq!(device_slots_seen_by(&a, &a), vec![slot_of(false)]);
        assert_eq!(device_slots_seen_by(&a, &b), vec![slot_of(true)]);
        assert_eq!(device_slots_seen_by(&b, &a), vec![slot_of(false)]);

        // 什麼都沒變的一輪:不寫新版本、不要求提交、不發通知。
        for d in [&a, &b] {
            let keys = account_keys(d);
            let mut state = d.state();
            let before = state.clone();
            let round = reconcile(&mut state, &keys, &home(d), 5_000);
            assert!(!round.changed && round.notices.is_empty());
            assert_eq!(state, before);
        }
    }

    #[test]
    fn a_slot_missing_from_the_account_is_written_again_while_a_host_uses_it() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let keys = account_keys(&a);
        // 沒有 SP3 的電腦更換了同步碼:新帳戶沒有這個插槽的兩筆記錄,這台的 `key_slots` 還記著它。
        let mut state = a.state();
        let payload = state.key_slots[&id].payload.clone().expect("the last payload seen is remembered");
        let account = state.account.as_mut().unwrap();
        account.records.remove(&record_key(RecordKind::KeySlot, &id));
        account.sealed.remove(&key_secret_key(&keys, &id));
        assert!(!slot_record_exists(account, &id) && live_slots(account).is_empty());

        let round = reconcile(&mut state, &keys, &home(&a), 1_000);
        assert!(round.changed);
        let account = state.account.as_ref().unwrap();
        assert_eq!(slot(account, &id), Some(payload));
        assert!(account.records[&record_key(RecordKind::KeySlot, &id)].dirty, "it goes up with this round");
        assert_eq!(open_key_secret(account, &keys, &id).as_deref(), Some(test_keys::plain().as_str()));
        assert!(account.sealed[&key_secret_key(&keys, &id)].dirty);
        // 補寫之後的下一輪什麼都不再動。
        assert!(!reconcile(&mut state, &keys, &home(&a), 2_000).changed);
    }

    #[test]
    fn a_computer_holding_a_copy_publishes_a_slot_the_account_lost() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        // 在沒有 SP3 的電腦上更換同步碼之後,新帳戶裡沒有插槽記錄:直接從 B 的帳戶快取拿掉它們來模擬。
        let keys = account_keys(&b);
        mutate(&b.env(), |s| {
            let account = s.account.as_mut().unwrap();
            account.records.remove(&record_key(RecordKind::KeySlot, &id));
            account.sealed.remove(&key_secret_key(&keys, &id));
            Ok(())
        })
        .unwrap();
        let _ = crate::sync::round::sync_once(&b.env());
        let account = b.state().account.unwrap();
        assert_eq!(slot(&account, &id).map(|p| p.mode), Some(SlotMode::Synced));
        assert_eq!(open_key_secret(&account, &keys, &id).as_deref(), Some(test_keys::plain().as_str()));
        // 是從 B 手上的副本補的:副本還在、狀態不變。
        assert_eq!(std::fs::read_to_string(home(&b).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
        assert!(matches!(b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { .. })));
    }

    #[test]
    fn a_key_this_computer_never_chose_to_sync_is_not_uploaded_when_a_member_flips_its_slot_to_synced() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let keys = account_keys(&a);
        // 這台的 `own` 插槽連到 `id_mac`:使用者選的是「Keep on this computer」。
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        assert_eq!(a.state().key_slots[&id].uploaded_fingerprint, None);

        // 帳戶裡的成員把它改成 `synced`,填上這把金鑰的公鑰與指紋(公開的資訊:`device.slots` 就列著指紋)。
        publish(&a, &id, &synced_payload("a-member"), None);
        settle(&a);
        let local = a.state().key_slots[&id].clone();
        assert_eq!(local.payload.as_ref().map(|p| p.mode), Some(SlotMode::Synced), "this computer saw the flip");
        assert_eq!(local.uploaded_fingerprint, None, "but a change in the account never sets the consent");

        // 之後帳戶掉了這個插槽(沒有 SP3 的電腦更換了同步碼),主機還用著。
        let account_lost_it = |uploaded: Option<&str>| {
            let mut state = a.state();
            state.key_slots.get_mut(&id).unwrap().uploaded_fingerprint = uploaded.map(String::from);
            let account = state.account.as_mut().unwrap();
            account.records.remove(&record_key(RecordKind::KeySlot, &id));
            account.sealed.remove(&key_secret_key(&keys, &id));
            state
        };
        // `keyslot` 補回去,私鑰一個位元組都不上傳:連 `key` 的密文都沒有。
        let mut state = account_lost_it(None);
        assert!(reconcile(&mut state, &keys, &home(&a), 1_000).changed);
        let account = state.account.as_ref().unwrap();
        assert!(slot(account, &id).is_some(), "the keyslot is written again");
        assert!(!account.sealed.contains_key(&key_secret_key(&keys, &id)), "no key record at all");
        assert_eq!(open_key_secret(account, &keys, &id), None);

        // 同樣的狀態,只差這台的使用者選過在這裡同步這把金鑰:才補 `key`。
        let mut state = account_lost_it(Some(test_keys::PLAIN_FINGERPRINT));
        reconcile(&mut state, &keys, &home(&a), 2_000);
        assert_eq!(open_key_secret(state.account.as_ref().unwrap(), &keys, &id).as_deref(), Some(test_keys::plain().as_str()));
        // 選過的是另一把金鑰:連到的這把不上傳。
        let mut state = account_lost_it(Some(test_keys::ECDSA_FINGERPRINT));
        reconcile(&mut state, &keys, &home(&a), 3_000);
        assert_eq!(open_key_secret(state.account.as_ref().unwrap(), &keys, &id), None);
    }

    #[test]
    fn a_missing_slot_is_written_again_only_as_far_as_this_computer_can_vouch_for() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let keys = account_keys(&a);
        let (own_id, own_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_own");
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slots(&a, &personal, &[&own_file, &file]);
        settle(&a);
        // 沒有 SP3 的電腦更換了同步碼:新帳戶沒有這些插槽的記錄,這台的 `key_slots` 還記著它們。
        let without_records = |ids: &[&str]| {
            let mut state = a.state();
            let account = state.account.as_mut().unwrap();
            for id in ids {
                account.records.remove(&record_key(RecordKind::KeySlot, id));
                account.sealed.remove(&key_secret_key(&keys, id));
            }
            state
        };

        // `own`:只有 `keyslot`,沒有 `key`。
        let mut state = without_records(&[&own_id]);
        assert!(reconcile(&mut state, &keys, &home(&a), 1_000).changed);
        let account = state.account.as_ref().unwrap();
        assert!(slot(account, &own_id).is_some());
        assert!(!account.sealed.contains_key(&key_secret_key(&keys, &own_id)));

        // `synced`、可是這台連到的金鑰已經不是記錄上的那一把:`keyslot` 補回去,不把別把金鑰當成它的 `key` 上傳。
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        let mut state = without_records(&[&id]);
        assert!(reconcile(&mut state, &keys, &home(&a), 2_000).changed);
        let account = state.account.as_ref().unwrap();
        assert!(slot(account, &id).is_some());
        assert_eq!(open_key_secret(account, &keys, &id), None);
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::plain()).unwrap();

        // 已經刪除的插槽(tombstone 還在)不補寫。
        let mut state = a.state();
        let me = state.device_id.clone();
        let account = state.account.as_mut().unwrap();
        put_slot(account, &id, None, &me, 500);
        put_key_secret(account, &keys, &id, None, &me, 500).unwrap();
        reconcile(&mut state, &keys, &home(&a), 3_000);
        assert_eq!(slot(state.account.as_ref().unwrap(), &id), None, "a deleted slot stays deleted");

        // 沒有主機用到的也不補寫,這台也不再記著它。
        let mut state = without_records(&[&own_id]);
        a_host_stops_using(&mut state, &own_file);
        reconcile(&mut state, &keys, &home(&a), 4_000);
        assert!(!slot_record_exists(state.account.as_ref().unwrap(), &own_id), "nobody uses it: it is not written again");
        assert!(!state.key_slots.contains_key(&own_id));
    }

    /// 直接在一份狀態副本上讓所有主機都不再用到 `file` 這個插槽。
    fn a_host_stops_using(state: &mut SyncStateV2, file: &str) {
        for space in state.spaces.values_mut() {
            for local in space.records.values_mut() {
                if let Ok(mut payload) = serde_json::from_value::<HostPayload>(local.record.payload.clone()) {
                    payload.text = payload.text.replace(file, "elsewhere");
                    local.record.payload = serde_json::to_value(payload).unwrap();
                }
            }
        }
    }

    #[test]
    fn a_keyslot_deleted_before_this_computer_saw_it_writes_nothing_even_if_a_host_points_at_it() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let id = new_slot_id().unwrap();
        let file = slot_file_name("id_mac", &id);
        publish(&a, &id, &synced_payload(&device_id(&a)), Some(&test_keys::plain()));
        use_slot(&a, &personal, &file);
        unpublish(&a, &id);
        settle(&a);
        settle(&b);
        for d in [&a, &b] {
            assert!(!slot_files::occupied(&home(d).join(SLOT_DIR).join(&file)), "no half-written files");
            assert!(d.state().key_slots.is_empty() && view_of(d).is_empty());
        }
    }

    #[test]
    fn a_computer_that_joins_later_gets_the_key_in_its_first_round() {
        let (relay, clock) = (crate::sync::fake_relay::FakeRelay::new(), crate::sync::testkit::TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        let words = crate::sync::account::create_account(&a.env(), "MacBook-A").unwrap();
        settle(&a);
        let personal = a.state().spaces.keys().next().unwrap().clone();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);

        // 之後才加入的電腦:勾選 space 之後的第一輪(基線輪)主機一出現,金鑰就落地。
        let b = TestDevice::new("b", &relay, &clock);
        crate::sync::account::join_account(&b.env(), &words, "MacBook-B").unwrap();
        crate::sync::spaces::select_space(&b.env(), &personal).unwrap();
        let _ = crate::sync::round::sync_once(&b.env());
        assert!(b.read(&b.space_path(&personal)).contains(&file), "the host is there");
        assert_eq!(std::fs::read_to_string(home(&b).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
        assert_eq!(b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
    }

    #[test]
    fn slots_that_need_a_key_are_asked_in_one_notice_and_later_ones_join_it() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let me = device_id(&a);
        let names = ["work", "id_mac", "zeta"];
        let ids = [new_slot_id().unwrap(), new_slot_id().unwrap(), new_slot_id().unwrap()];
        let files: Vec<String> = ids.iter().zip(names).map(|(id, name)| slot_file_name(name, id)).collect();
        for (id, name) in ids.iter().zip(names) {
            publish(&a, id, &KeySlotPayload { name: name.into(), ..own_payload(&me) }, None);
        }
        use_slots(&a, &personal, &[&files[0], &files[1]]);
        settle(&a);
        settle(&b);
        let asked = |names: &[&str]| SyncNotice::KeysNeeded { names: names.iter().map(|n| n.to_string()).collect() };
        assert_eq!(b.state().notices, vec![asked(&["id_mac", "work"])], "one notice, the names in the order the slots are listed");

        // 之後第三個也需要金鑰:併進還沒關掉的那一則;發出的事件只帶新的名稱。
        use_slots(&a, &personal, &[&files[0], &files[1], &files[2]]);
        settle(&a);
        settle(&b);
        assert_eq!(b.state().notices, vec![asked(&["id_mac", "work", "zeta"])]);
        assert_eq!(*b.events.notices.lock().unwrap(), vec![asked(&["id_mac", "work"]), asked(&["zeta"])]);
    }

    #[test]
    fn a_synced_slot_whose_key_has_not_arrived_waits_without_asking() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let id = new_slot_id().unwrap();
        let file = slot_file_name("id_mac", &id);
        publish(&a, &id, &synced_payload(&device_id(&a)), None);
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let slot_path = home(&b).join(SLOT_DIR).join(&file);
        assert!(!slot_files::occupied(&slot_path));
        assert_eq!(view_of(&b)[0].status, SlotStatusView::NeedsKey { waiting_for_sync: true });
        assert!(!b.state().key_slots[&id].asked);
        assert!(b.state().notices.is_empty() && b.events.notices.lock().unwrap().is_empty(), "a synced key is on its way: nobody is asked");

        // 金鑰到了:落地。
        let keys = account_keys(&a);
        let env = a.env();
        let now = env.now();
        mutate(&env, |s| {
            let me = s.device_id.clone();
            put_key_secret(s.account.as_mut().unwrap(), &keys, &id, Some(&test_keys::plain()), &me, now)
        })
        .unwrap();
        settle(&a);
        settle(&b);
        assert_eq!(std::fs::read_to_string(&slot_path).unwrap(), test_keys::plain());
        assert!(matches!(view_of(&b)[0].status, SlotStatusView::Ready { synced_copy: true, .. }));
    }

    /// 發出 `notice` 的當下 doc / backed_up / core 三把鎖是不是都空著(引擎的通知一律在放掉所有鎖之後)。
    struct LockProbe<'a> {
        d: &'a TestDevice,
        free: Mutex<Vec<bool>>,
    }

    impl SyncEvents for LockProbe<'_> {
        fn status(&self) {}
        fn applied(&self, _hosts: usize) {}
        fn conflict(&self, _conflicts: &[SyncConflict]) {}
        fn approval(&self, _waiting: &[ApprovalNotice]) {}
        fn notice(&self, _notice: &SyncNotice) {
            let free = self.d.doc.try_lock().is_ok() && self.d.backed_up.try_lock().is_ok() && self.d.runtime.core.try_lock().is_ok();
            self.free.lock().unwrap().push(free);
        }
        fn wake(&self) {}
    }

    #[test]
    fn the_keys_needed_notice_is_stored_before_it_is_sent_and_sent_with_no_lock_held() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (_id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let probe = LockProbe { d: &b, free: Mutex::new(Vec::new()) };
        let mut env = b.env();
        env.events = &probe;
        crate::sync::round::sync_once(&env).unwrap();
        assert_eq!(*probe.free.lock().unwrap(), vec![true]);
        assert_eq!(b.state().notices, vec![SyncNotice::KeysNeeded { names: vec!["id_mac".into()] }], "already in the state when it is sent");
    }

    #[test]
    fn local_key_fingerprints_come_from_the_key_or_else_from_the_pub_file_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        let openssh = dir.path().join("id_mac");
        std::fs::write(&openssh, test_keys::plain()).unwrap();
        assert_eq!(local_key_fingerprint(&openssh).as_deref(), Some(test_keys::PLAIN_FINGERPRINT));

        // 舊式 PEM:從私鑰讀不出公鑰,改讀旁邊的 `.pub`。
        let pem = dir.path().join("id_rsa");
        std::fs::write(&pem, format!("{}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n{}\n", concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), concat!("-----END RSA ", "PRIVATE KEY-----"))).unwrap();
        assert_eq!(local_key_fingerprint(&pem), None);
        std::fs::write(public_path(&pem), format!("{} me@host\n", test_keys::ECDSA_PUBLIC)).unwrap();
        assert_eq!(local_key_fingerprint(&pem).as_deref(), Some(test_keys::ECDSA_FINGERPRINT));
        std::fs::write(public_path(&pem), "this is not a public key\n").unwrap();
        assert_eq!(local_key_fingerprint(&pem), None);
        assert_eq!(local_key_fingerprint(&dir.path().join("missing")), None);
    }

    #[test]
    fn slot_status_names_every_state() {
        let slot_path = PathBuf::from("/h/.ssh/sshelter/keys/id_mac-3fa2c1d9");
        let here = slot_path.display().to_string();
        let source = "/h/.ssh/id_mac".to_string();
        let (synced, own) = (synced_payload("a"), own_payload("a"));
        let local = |source: Option<SlotSource>, error: Option<&str>| LocalSlot {
            file_name: "id_mac-3fa2c1d9".into(),
            source,
            last_error: error.map(String::from),
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
        };
        let linked = |fingerprint: Option<&str>, origin: bool, link: LinkKind| SlotSource::Linked {
            path: "/h/.ssh/id_mac".into(),
            link,
            fingerprint: fingerprint.map(String::from),
            origin,
        };
        let copy = |fingerprint: &str| SlotSource::SyncedCopy { fingerprint: fingerprint.into() };
        let status = |l: Option<&LocalSlot>, p: &KeySlotPayload, needed, has_secret| slot_status(l, p, needed, has_secret, &slot_path);
        let (same, other) = (test_keys::PLAIN_FINGERPRINT, test_keys::ECDSA_FINGERPRINT);

        // 錯誤優先於一切。
        let broken = local(Some(copy(same)), Some("boom"));
        assert_eq!(status(Some(&broken), &synced, true, true), SlotStatusView::Error { message: "boom".into() });
        // 還沒有東西:需要 → 等金鑰(synced 是「還沒到」、own 是「請挑」);不需要 → 這台沒用到。
        assert_eq!(status(None, &synced, true, false), SlotStatusView::NeedsKey { waiting_for_sync: true });
        assert_eq!(status(None, &own, true, false), SlotStatusView::NeedsKey { waiting_for_sync: false });
        assert_eq!(status(Some(&local(None, None)), &synced, true, true), SlotStatusView::NeedsKey { waiting_for_sync: true });
        assert_eq!(status(None, &synced, false, true), SlotStatusView::NotUsedHere);
        // 連到金鑰:來源電腦且指紋還對 → Ready;換了金鑰 → SourceChanged;其他電腦連到的和同步的不同 → 可以改用同步的。
        let origin = local(Some(linked(Some(same), true, LinkKind::Symlink)), None);
        assert_eq!(status(Some(&origin), &synced, true, true), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: Some(same.into()) });
        let changed = local(Some(linked(Some(other), true, LinkKind::Symlink)), None);
        assert_eq!(status(Some(&changed), &synced, true, true), SlotStatusView::SourceChanged { file: source.clone() });
        let own_origin = local(Some(linked(None, true, LinkKind::Symlink)), None);
        assert_eq!(status(Some(&own_origin), &own, true, false), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: None });
        let picked = local(Some(linked(Some(other), false, LinkKind::Symlink)), None);
        assert_eq!(status(Some(&picked), &synced, true, true), SlotStatusView::SyncedAvailable { file: source.clone() });
        assert_eq!(status(Some(&picked), &synced, true, false), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: Some(other.into()) }, "no synced key to offer");
        assert_eq!(status(Some(&picked), &own, true, false), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: Some(other.into()) });
        // 沒有主機用到:連結已經收起來了(插槽裡沒有東西)→ 這台沒用到;複製檔是真的放在插槽裡的金鑰 → 可以刪除。
        assert_eq!(status(Some(&origin), &synced, false, true), SlotStatusView::NotUsedHere);
        let hard = local(Some(linked(Some(same), true, LinkKind::HardLink)), None);
        assert_eq!(status(Some(&hard), &synced, false, true), SlotStatusView::NotUsedHere);
        assert_eq!(status(Some(&own_origin), &own, false, false), SlotStatusView::NotUsedHere);
        let copied = local(Some(linked(Some(same), true, LinkKind::Copy)), None);
        assert_eq!(status(Some(&copied), &synced, false, true), SlotStatusView::NotInUse { file: here.clone() });
        assert_eq!(status(Some(&copied), &own, false, false), SlotStatusView::NotInUse { file: here.clone() });
        // 同步來的副本:同一把 → Ready;同步的換了 → 有新的;沒有主機用到 → NotInUse;停止同步(own)之後照舊使用。
        let held = local(Some(copy(same)), None);
        assert_eq!(status(Some(&held), &synced, true, true), SlotStatusView::Ready { file: here.clone(), synced_copy: true, fingerprint: Some(same.into()) });
        assert_eq!(status(Some(&held), &ecdsa_payload("a"), true, true), SlotStatusView::SyncedAvailable { file: here.clone() });
        assert_eq!(status(Some(&held), &ecdsa_payload("a"), true, false), SlotStatusView::Ready { file: here.clone(), synced_copy: true, fingerprint: Some(same.into()) });
        assert_eq!(status(Some(&held), &synced, false, true), SlotStatusView::NotInUse { file: here.clone() });
        assert_eq!(status(Some(&held), &own, true, false), SlotStatusView::Ready { file: here.clone(), synced_copy: true, fingerprint: Some(same.into()) });
    }

    #[test]
    fn views_list_slots_by_name_and_keep_the_copy_of_a_slot_that_is_gone() {
        let (_relay, _clock, a, _b, _words, _personal) = pair();
        let me = device_id(&a);
        // `work` 的 id 最小:依名稱排序,不是依 id。
        let (work, mine, gone) = ("00000000000000000000000000000001", SLOT_ID, "ffffffffffffffffffffffffffffffff");
        publish(&a, work, &KeySlotPayload { name: "work".into(), ..own_payload(&me) }, None);
        publish(&a, mine, &synced_payload(&me), Some(&test_keys::plain()));
        // 帳戶裡已經沒有、這台還留著副本的插槽(別台刪除了):排在最後。
        mutate(&a.env(), |s| {
            s.key_slots.insert(
                gone.to_string(),
                LocalSlot {
                    file_name: "old-ffffffff".into(),
                    source: Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }),
                    last_error: None,
                    asked: true,
                    payload: Some(KeySlotPayload { name: "old".into(), ..synced_payload(&me) }),
                    uploaded_fingerprint: None,
                    parked: false,
                },
            );
            // 沒有 payload、或沒有放東西的記錄不顯示。
            s.key_slots.insert("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(), LocalSlot { file_name: "x-eeeeeeee".into(), source: None, last_error: None, asked: false, payload: None, uploaded_fingerprint: None, parked: false });
            Ok(())
        })
        .unwrap();

        let view = view_of(&a);
        assert_eq!(view.iter().map(|v| (v.name.as_str(), v.id.as_str())).collect::<Vec<_>>(), vec![("id_mac", mine), ("work", work), ("old", gone)]);
        assert_eq!(view[0].value, format!("~/.ssh/sshelter/keys/id_mac-{}", &mine[..8]));
        assert_eq!((view[0].mode, view[0].origin_device.as_str(), view[0].origin_is_this), (SlotMode::Synced, "MacBook-A", true));
        assert_eq!(view[0].fingerprint.as_deref(), Some(test_keys::PLAIN_FINGERPRINT));
        assert_eq!((view[1].mode, view[1].fingerprint.clone(), view[1].has_passphrase), (SlotMode::Own, None, None));
        let kept = home(&a).join(SLOT_DIR).join("old-ffffffff").display().to_string();
        assert_eq!(view[2].status, SlotStatusView::NotInUse { file: kept });
        assert!(view[2].hosts.is_empty());
    }
}
