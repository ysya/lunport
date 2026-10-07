//! SP3 金鑰插槽的引擎(spec `docs/superpowers/specs/2026-10-05-sp3-key-slots-design.md` §4、§6):帳戶裡 `keyslot` 與
//! `key` 記錄的讀寫、每一輪在這台維護插槽(`reconcile`)與給 UI 的插槽檢視(`views`)、模式切換與挑選(Task 6),以及只在 SSHelter 的
//! 插槽(金鑰保管庫 spec §4.3:`SlotSource::Vault`,`set_delivery`)。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::model::{Directive, Item, SshConfigDoc};
use crate::config::parser::parse_file;
use crate::error::AppError;
use crate::sync::account::{account_ready, NOT_JOINED_MESSAGE};
use crate::sync::crypto::{id_hash, ChainKeys};
use crate::sync::dto::{SlotDeviceView, SlotStatusView, SyncKeySlotView};
use crate::sync::env::SyncEnv;
use crate::sync::merge::{device_name, devices, put_account_record, set_device_slots};
use crate::sync::planner::next_timestamp;
use crate::sync::record::{record_key, HostPayload, Record, RecordKind};
use crate::sync::runtime::{mutate, SyncRuntime};
use crate::sync::slot_files::{self, LinkKind};
use crate::sync::slot_rules::{
    inspect_private_key, parse_public_key, public_path, resolve_identity_value, slot_file_name, slot_file_of_value, slot_value,
    valid_key_payload, valid_slot_payload, DeviceSlot, IdentityTarget, KeyFacts, KeyPayload, KeySlotPayload, SlotMode, SLOT_DIR,
    SLOT_SCHEMA,
};
use crate::sync::state_v2::{sealed_key, AccountState, LocalSlot, SealedRecord, SlotSource, SyncNotice, SyncStateV2};
use crate::vault::store::{vault_path, with_vault, EntryOrigin, VaultEntry};

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

/// 帳戶裡這個插槽的私鑰,而且通過落地前的檢查(`check_synced_key`:讀得懂、指紋等於插槽記錄的):(私鑰、從它讀出的資訊)。私鑰在帳戶裡沒有
/// (或解不開)→ `Err(None)`;解得開卻對不上 → `Err(Some(MISMATCH_MESSAGE))`。
pub(crate) fn landable_key(
    account: &AccountState,
    account_keys: &ChainKeys,
    slot_id: &str,
    payload: &KeySlotPayload,
) -> Result<(String, KeyFacts), Option<String>> {
    let secret = open_key_secret(account, account_keys, slot_id).ok_or(None)?;
    let facts = check_synced_key(&secret, payload).map_err(Some)?;
    Ok((secret, facts))
}

// ── 只在 SSHelter 的插槽(金鑰保管庫 spec §4.3、§4.4、§11)──────────────────────────────────────────
//
// 「Only in SSHelter」= `SlotSource::Vault`:私鑰在保管庫(`vault.json`),插槽目錄只放 `<file>.pub`,插槽路徑本身沒有檔案,`ssh` 經 SSHelter
// 的 agent 取用。每一輪只維護 `.pub`、回報擋路的檔案,從不把私鑰落地到這樣的插槽(`maintain`);保管庫裡不見的那一筆從帳戶放回去
// (`recover_vault_entry`);補寫帳戶裡的 `key` 時照 SP3 的同意規則讀保管庫裡的私鑰(`republish`)。搬進、搬出保管庫是使用者的動作(`set_delivery`)。

/// 同步的一輪用到的保管庫:補寫帳戶裡的 `key`(SP3 spec §6.6)要讀私鑰;「只在 SSHelter」的插槽要確認保管庫裡還有它,沒有就從帳戶放回去
/// (金鑰保管庫 spec §11)。`holds` 只讀檔案裡的 id,不讀 keychain;`private_key` 與 `restore` 才開保管庫。
pub trait VaultKeys {
    fn private_key(&self, slot_id: &str) -> Option<(Zeroizing<String>, EntryOrigin)>;
    /// 保管庫裡有沒有這一筆;保管庫讀不了(格式不認得、讀不懂、I/O 錯誤)→ None,呼叫端什麼都不做。
    fn holds(&self, slot_id: &str) -> Option<bool>;
    /// 放回一筆(從帳戶取回的同步金鑰)。
    fn restore(&self, slot_id: &str, entry: &VaultEntry) -> Result<(), AppError>;
}

/// 沒有保管庫可讀(測試、或只處理檔案來源的呼叫端)。
pub struct NoVault;

impl VaultKeys for NoVault {
    fn private_key(&self, _slot_id: &str) -> Option<(Zeroizing<String>, EntryOrigin)> {
        None
    }

    fn holds(&self, _slot_id: &str) -> Option<bool> {
        None
    }

    fn restore(&self, _slot_id: &str, _entry: &VaultEntry) -> Result<(), AppError> {
        Err(AppError::Other("SSHelter's vault is not available here".to_string()))
    }
}

/// 經 `SyncEnv` 開保管庫(`vault::store::with_vault`)。開不了(keychain 鎖著、檔案讀不懂)就當成沒有。
pub struct EnvVault<'a, 'b> {
    pub env: &'a SyncEnv<'b>,
}

impl VaultKeys for EnvVault<'_, '_> {
    fn private_key(&self, slot_id: &str) -> Option<(Zeroizing<String>, EntryOrigin)> {
        let path = vault_path(&self.env.state_path);
        with_vault(self.env.runtime, &path, self.env.keychain, self.env.now(), |vault| vault.get(slot_id))
            .ok()
            .flatten()
            .map(|entry| (Zeroizing::new(entry.private_key.clone()), entry.origin))
    }

    fn holds(&self, slot_id: &str) -> Option<bool> {
        crate::vault::store::stored_ids(&vault_path(&self.env.state_path)).ok().map(|ids| ids.contains(slot_id))
    }

    fn restore(&self, slot_id: &str, entry: &VaultEntry) -> Result<(), AppError> {
        let path = vault_path(&self.env.state_path);
        Ok(with_vault(self.env.runtime, &path, self.env.keychain, self.env.now(), |vault| vault.put(self.env.keychain, slot_id, entry))?)
    }
}

pub const VAULT_ENTRY_LOST: &str = "This key was lost from SSHelter's vault. Pick it again on this computer.";

/// 只在 SSHelter 的插槽,保管庫裡卻沒有它(保管庫檔讀不懂、或 `vault:key` 不見而搬到旁邊之後;金鑰保管庫 spec §11):帳戶裡有同一把同步金鑰
/// 就放回保管庫;沒有就讓這台回到「還沒有金鑰」,之後照 SP3 的流程落地同步的金鑰或請使用者挑。保管庫讀不了(`holds` 是 None)就不動。
///
/// 放回去的那一筆一律記成 `Imported`:記錄分不出那把原本是這台自己的金鑰還是從這個帳戶同步來的,記成 `Synced` 的話,之後補寫 `key`(`republish`)
/// 就不必這台的同意了。放回成功不動 `last_error`(這一輪 `maintain` 的擋路訊息照舊顯示),放不回去才記下原因。
fn recover_vault_entry(
    local: &mut LocalSlot,
    slot_id: &str,
    account: &AccountState,
    account_keys: &ChainKeys,
    now_ms: u64,
    vault: &dyn VaultKeys,
) {
    let Some(SlotSource::Vault { fingerprint, .. }) = &local.source else { return };
    if vault.holds(slot_id) != Some(false) {
        return;
    }
    let restored = open_key_secret(account, account_keys, slot_id).and_then(|text| {
        let facts = inspect_private_key(&text).ok()?;
        (&facts.fingerprint == fingerprint).then(|| VaultEntry {
            private_key: text.clone(),
            public_key: facts.public_key.clone(),
            fingerprint: facts.fingerprint.clone(),
            origin: EntryOrigin::Imported,
            added_at_ms: now_ms,
        })
    });
    match restored {
        Some(entry) => {
            if let Err(e) = vault.restore(slot_id, &entry) {
                local.last_error = Some(e.to_string());
            }
        }
        None => {
            local.source = None;
            local.last_error = Some(VAULT_ENTRY_LOST.to_string());
        }
    }
}

/// 這台「只在 SSHelter」的插槽檔名(`SlotSource::Vault`):`agent::wiring` 據此列出要走 agent 的主機。
pub fn vault_slot_files(state: &SyncStateV2) -> BTreeSet<String> {
    state
        .key_slots
        .values()
        .filter(|local| matches!(local.source, Some(SlotSource::Vault { .. })))
        .map(|local| local.file_name.clone())
        .collect()
}

pub const VAULT_FIRST_MESSAGE: &str = "This key is only in SSHelter. Choose Keep a file first.";

/// 保管庫裡這個插槽的那一筆不是記錄裡的那一把(指紋不同):不拿它當成這個插槽的金鑰(`vault_text`、`set_delivery`)。
pub const VAULT_MISMATCH_MESSAGE: &str = "The key in SSHelter's vault doesn't match this slot.";

// ── 每一輪在這台維護插槽(SP3 spec §6.2–§6.6)──────────────────────────────────────────────────
//
// 一個檔案是不是 SSHelter 放的,只看這個插槽 id 自己的本機記錄(`SyncStateV2::key_slots[id]`),不看檔名:插槽檔名
// (`<name>-<id8>`)不保證在插槽 id 之間唯一,帳戶裡的成員可以發佈同名、同 id 前 8 字元的另一個插槽。從主機的
// `IdentityFile` 值取得的檔名(`slot_hosts`、`identity_slot_files`)只當查詢的 key,絕不拿來組出要寫入或移除的路徑。
// 同一個檔名有兩個以上還在的插槽時,主機的 `IdentityFile` 分不出指的是哪一個:只有這台已經握著的那個照常維護,其他的在這台
// 什麼都不做(`contested_and_not_held`)—— 否則成員的插槽可以在使用者的插槽空出來的那一刻,把自己的金鑰與 `.pub` 放上去。

pub const MISMATCH_MESSAGE: &str = "The synced key didn't match and was not written.";

/// 和帳戶裡另一個插槽同檔名、這台又沒有握著的插槽的狀態(`contested_and_not_held`)。
pub const CONTESTED_MESSAGE: &str = "Another key slot in your account uses the same file name, so this one isn't used on this computer.";

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

/// 整份 config(主 config 與它 Include 的每一個檔案 —— 不只勾選的 space 檔,也有主 config 自己的主機、離開帳戶後搬到 `~/.ssh/sshelter-local/`
/// 的檔案)裡,啟用中的 `IdentityFile` 指到的插槽檔名 → 用到它的 Host alias(排序、不重複)。不在 Host 區塊裡的(檔案開頭的全域設定、Match
/// 區塊)也算用到,只是沒有 alias。插槽路徑的每一種寫法都算(`~/`、`%d/`、絕對路徑、反斜線):值解析之後正好是插槽目錄(`home` 底下的
/// `SLOT_DIR`)裡的一個檔案。註解掉的行不算。只讀 doc,不碰檔案系統。
///
/// spec §4.2 只在「插槽不再被任何主機使用」時移除連結;「需要」(落地同步的金鑰、問使用者要金鑰、補寫帳戶記錄)仍只看勾選的 space(`slot_hosts`,§6.2)。
pub fn config_slot_hosts(doc: &SshConfigDoc, home: &Path) -> BTreeMap<String, Vec<String>> {
    let keys_dir = home.join(SLOT_DIR);
    let slot_file = |d: &Directive| -> Option<String> {
        if d.key != "identityfile" || d.serializes_as_comment() {
            return None;
        }
        match resolve_identity_value(&d.value, home) {
            IdentityTarget::Slot(file) => Some(file),
            IdentityTarget::File(path) if path.parent() == Some(keys_dir.as_path()) => {
                path.file_name().and_then(|name| name.to_str()).map(String::from)
            }
            _ => None,
        }
    };
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for file in &doc.files {
        for item in &file.items {
            let (alias, body) = match item {
                Item::Directive(d) => {
                    if let Some(file) = slot_file(d) {
                        out.entry(file).or_default();
                    }
                    continue;
                }
                Item::Host(host) => (host.patterns.first(), &host.body),
                Item::Match(block) => (None, &block.body),
                Item::Blank(_) | Item::Comment(_) => continue,
            };
            for line in body {
                let Item::Directive(d) = line else { continue };
                if let Some(file) = slot_file(d) {
                    out.entry(file).or_default().extend(alias.cloned());
                }
            }
        }
    }
    out.into_iter().map(|(file, hosts)| (file, hosts.into_iter().collect())).collect()
}

/// 這台整份 config 裡用到的插槽(`config_slot_hosts`)。只在算的時候短暫拿 doc 鎖(順序 lifecycle → doc → backed_up → retention → core:呼叫端不得持有
/// doc 之後的任何鎖),不在鎖裡做任何檔案系統的動作。config 還沒載入 → None(呼叫端不知道哪些插槽有主機用到)。
pub fn config_slot_uses(env: &SyncEnv) -> Option<BTreeMap<String, Vec<String>>> {
    let home = env.ssh_dir.parent()?;
    let doc_lock = env.doc.lock().unwrap();
    doc_lock.as_ref().map(|doc| config_slot_hosts(doc, home))
}

/// 本機一把金鑰的(公鑰、指紋):OpenSSH 格式從私鑰讀(不需要 passphrase);其他格式讀旁邊 `.pub` 的第一行;都讀不到 → None。
/// 公鑰是正規化的 `<type> <base64>`(沒有 comment)。
fn local_key_public(path: &Path) -> Option<(String, String)> {
    let text = std::fs::read_to_string(path).ok()?;
    if let Ok(facts) = inspect_private_key(&text) {
        return Some((facts.public_key, facts.fingerprint));
    }
    let public = std::fs::read_to_string(public_path(path)).ok()?;
    parse_public_key(public.lines().next()?)
}

/// 本機一把金鑰的指紋:OpenSSH 格式從私鑰讀;其他格式讀旁邊的 `.pub`;都讀不到 → None。
pub fn local_key_fingerprint(path: &Path) -> Option<String> {
    local_key_public(path).map(|(_, fingerprint)| fingerprint)
}

/// 連結、重新連結或認回一個插槽(`Linked` 來源)的時候,重寫插槽旁的 `<slot>.pub`:內容只來自連到的那把金鑰自己 —— 從原檔的私鑰
/// 推出公鑰;推不出來(舊式 PEM 之類)就用原檔旁邊 `<source>.pub` 的第一行(正規化);都沒有就把 `<slot>.pub` 拿掉。沒有 `.pub` 比
/// 錯的好:OpenSSH 先從 `<金鑰檔>.pub` 讀公鑰,`ssh-copy-id -i <slot>` 也會把 `<slot>.pub` 送進伺服器的 authorized_keys,這個檔案不能
/// 是別的插槽(或別人)放在這個位置的。插槽目錄要已經建好(`slot_files::ensure_keys_dir`)。建立插槽(Task 5)與挑選金鑰(Task 6)
/// 也用它。
pub fn write_linked_public(slot: &Path, source: &Path) -> Result<(), AppError> {
    match local_key_public(source) {
        Some((public_key, _)) => slot_files::write_public(slot, &public_key),
        None => Ok(remove_if_present(&public_path(slot))?),
    }
}

/// 帳戶裡還在的插槽,各插槽檔名有幾個插槽在用。檔名不分大小寫:macOS 與 Windows 的檔案系統預設不分,`ID_MAC-3fa2c1d9` 與
/// `id_mac-3fa2c1d9` 在那裡是同一個檔案(插槽名稱只有 ASCII 字元)。
fn file_name_uses(live: &[(String, KeySlotPayload)]) -> BTreeMap<String, usize> {
    let mut uses = BTreeMap::new();
    for (id, payload) in live {
        *uses.entry(slot_file_name(&payload.name, id).to_ascii_lowercase()).or_default() += 1;
    }
    uses
}

/// 帳戶裡有沒有還在的插槽用了插槽檔名 `file`(不分大小寫,同 `file_name_uses`)。
pub fn file_name_in_use(account: &AccountState, file: &str) -> bool {
    file_name_uses(&live_slots(account)).contains_key(&file.to_ascii_lowercase())
}

/// 這台的同步帳戶裡還在的插槽的檔名;不在帳戶裡是空的。`config::intel::config_lint` 用它說明缺檔的插槽路徑(spec §7.3):帳戶裡有這個插槽,還是沒有。
/// 只短暫拿 core 鎖;`config_lint` 放掉之後才拿 doc 鎖(同 `slot_setup::key_candidates`)。
pub fn account_slot_files(runtime: &SyncRuntime) -> BTreeSet<String> {
    let core = runtime.core.lock().unwrap();
    let Some(account) = core.state.as_ref().and_then(|s| s.account.as_ref()) else { return BTreeSet::new() };
    live_slots(account).iter().map(|(id, payload)| slot_file_name(&payload.name, id)).collect()
}

/// 插槽檔名 `file` 也被帳戶裡另一個還在的插槽用了(不分大小寫,見 `file_name_uses`),而這台沒有握著這個插槽:`local`(這個插槽 id
/// 的本機記錄)在這個檔名上沒有來源(收起來的連結、同步來的副本、複製檔都算有)。
fn contested(uses: &BTreeMap<String, usize>, local: Option<&LocalSlot>, file: &str) -> bool {
    let held = local.is_some_and(|l| l.file_name == file && l.source.is_some());
    uses.get(&file.to_ascii_lowercase()).is_some_and(|n| *n > 1) && !held
}

/// 這個插槽在這台不能用:帳戶裡另一個還在的插槽用了同一個插槽檔名(帳戶裡的成員做得出來),而這台沒有握著它(這個插槽 id 的本機
/// 記錄在這個檔名上沒有來源;收起來的連結也算握著)。這樣的插槽每一輪都不落地、不連結、不問使用者要金鑰,插槽路徑上的東西一律
/// 不碰,狀態是 `CONTESTED_MESSAGE`;使用者對它的動作(挑金鑰、改用同步的金鑰、刪除副本)也要先問這裡,是的話就拒絕。帳戶裡沒有
/// (或已刪除)的插槽 → false。
pub fn contested_and_not_held(state: &SyncStateV2, slot_id: &str) -> bool {
    let Some(account) = state.account.as_ref() else { return false };
    let live = live_slots(account);
    let Some((_, payload)) = live.iter().find(|(id, _)| id == slot_id) else { return false };
    contested(&file_name_uses(&live), state.key_slots.get(slot_id), &slot_file_name(&payload.name, slot_id))
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
///
/// 兩種「用到」:勾選的 space 裡的主機用到的插槽是這台「需要」的(`slot_hosts`,spec §6.2)—— 只有它們會落地同步的金鑰、問使用者要金鑰、
/// 補寫帳戶裡不見的記錄;`in_use`(`config_slot_hosts`:整份 config 裡用到的,含主 config 與 `~/.ssh/sshelter-local/` 的主機)只決定連結留不留 ——
/// 任何主機用到的插槽都照常維護、不收起來,帳戶裡完全找不到的也不移除(spec §4.2:沒有任何主機用到、或 `keyslot` 被刪除才移除連結)。
///
/// `vault` = 這台的保管庫(金鑰保管庫 spec §4.3、§11):有主機用到的「只在 SSHelter」的插槽,每一輪確認保管庫裡還有它(`recover_vault_entry`);
/// 補寫這樣的插槽的 `key` 時從這裡讀私鑰(`republish`)。
pub fn reconcile_with_vault(
    state: &mut SyncStateV2,
    account_keys: &ChainKeys,
    home: &Path,
    in_use: &BTreeMap<String, Vec<String>>,
    now_ms: u64,
    vault: &dyn VaultKeys,
) -> SlotRound {
    let mut round = SlotRound::default();
    let needed = slot_hosts(state);
    let used = |file: &str| needed.contains_key(file) || in_use.contains_key(file);
    let device_id = state.device_id.clone();
    let keys_dir = home.join(SLOT_DIR);
    let Some(account) = state.account.as_mut() else { return round };
    let live = live_slots(account);
    let uses = file_name_uses(&live);
    let mut asked = Vec::new();

    for (id, payload) in &live {
        let file = slot_file_name(&payload.name, id);
        let path = keys_dir.join(&file);
        let before = state.key_slots.get(id).cloned();
        // 這台第一次看到這個插槽:記錄是在現在這個帳戶學到的。已經有的記錄不改記(`LocalSlot::learned_in`):留下來的舊帳戶記錄不會因為帳戶裡
        // 出現同 id 的插槽就變成這個帳戶的。
        let mut local = before.clone().unwrap_or_else(|| LocalSlot {
            file_name: file.clone(),
            source: None,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: Some(account.chain_id.clone()),
            copy_from_another_account: false,
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
        if contested(&uses, Some(&local), &file) {
            // 另一個插槽用了同一個檔名,這台又沒有握著這一個:不落地、不連結,插槽路徑上的東西一律不碰,也不問使用者要金鑰。
            local.last_error = Some(CONTESTED_MESSAGE.to_string());
        } else if used(&file) {
            if maintain(&mut local, &keys_dir, &path) {
                if is_needed {
                    land_into(&mut local, id, payload, account, account_keys, &keys_dir, &path);
                } else {
                    // 只有不在勾選的 space 裡的主機用到:同步的金鑰不落地到這裡(spec §6.2),等使用者挑。
                    local.last_error = None;
                }
            }
            recover_vault_entry(&mut local, id, account, account_keys, now_ms, vault);
            if is_needed && local.source.is_none() && local.last_error.is_none() && payload.mode == SlotMode::Own && !local.asked {
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

    // 這台記著、帳戶裡卻沒有的插槽。已刪除的(tombstone):移除連結、副本留著。完全找不到記錄而勾選的 space 裡的主機還用著:補寫(spec §6.6,
    // 例如在沒有 SP3 的電腦上更換了同步碼)—— 只補寫在這個帳戶學到的記錄(`republish`)。完全找不到記錄、只有不在勾選的 space 裡的主機用著(離開
    // 之後建立或加入了別的帳戶,`~/.ssh/sshelter-local/` 的主機還指著它),或在別的帳戶學到的記錄(那些主機之後被搬進這個帳戶的 space 也一樣):
    // 連結與記錄留著、照常維護(不落地、不補寫),那些主機在這台照常能連線(spec §4.2)。
    let gone: Vec<String> = state.key_slots.keys().filter(|id| !live.iter().any(|(l, _)| l == *id)).cloned().collect();
    for id in gone {
        let mut local = state.key_slots[&id].clone();
        let path = keys_dir.join(&local.file_name);
        let recorded = slot_record_exists(account, &id);
        if !recorded && needed.contains_key(&local.file_name) {
            if let Some(payload) = local.payload.clone() {
                if republish(account, account_keys, &id, &payload, &local, &path, &device_id, now_ms, vault) {
                    round.changed = true;
                    continue;
                }
            }
        }
        let before = local.clone();
        if !recorded && used(&local.file_name) {
            maintain(&mut local, &keys_dir, &path);
        } else {
            drop_link(&mut local, &path);
        }
        recover_vault_entry(&mut local, &id, account, account_keys, now_ms, vault);
        if local.source.is_none() {
            state.key_slots.remove(&id);
            round.changed = true;
        } else if local != before {
            state.key_slots.insert(id, local);
            round.changed = true;
        }
    }

    let slots: Vec<DeviceSlot> = state.key_slots.iter().filter_map(|(id, l)| device_slot(id, l, used(&l.file_name))).collect();
    round.changed |= set_device_slots(account, &device_id, slots, now_ms);
    if !asked.is_empty() {
        round.notices.push(SyncNotice::KeysNeeded { names: asked });
    }
    round
}

/// 不讀保管庫的版本(補寫時讀不到保管庫裡的私鑰):測試與只處理檔案來源的呼叫端用。
pub fn reconcile(
    state: &mut SyncStateV2,
    account_keys: &ChainKeys,
    home: &Path,
    in_use: &BTreeMap<String, Vec<String>>,
    now_ms: u64,
) -> SlotRound {
    reconcile_with_vault(state, account_keys, home, in_use, now_ms, &NoVault)
}

/// 這台的 `device.slots` 裡這個插槽那一項。連結(symlink / hard link)只在有主機用到(`used`:勾選的 space 或整份 config 裡的任何主機)、
/// 而且連結真的在插槽路徑上的時候才列:收起來的(`LocalSlot::parked`,`park_link`)連結,插槽路徑上現在沒有這個插槽的東西;複製檔與同步來的
/// 副本是真的放在插槽裡的金鑰,一直列著。保管庫裡的金鑰(`SlotSource::Vault`)也一直列著,記成 SSHelter 保管的副本(`synced_copy`)。
fn device_slot(slot_id: &str, local: &LocalSlot, used: bool) -> Option<DeviceSlot> {
    match &local.source {
        Some(SlotSource::Linked { link, fingerprint, .. }) => ((used && !local.parked) || *link == LinkKind::Copy)
            .then(|| DeviceSlot { slot_id: slot_id.to_string(), fingerprint: fingerprint.clone(), synced_copy: false }),
        Some(SlotSource::SyncedCopy { fingerprint }) => {
            Some(DeviceSlot { slot_id: slot_id.to_string(), fingerprint: Some(fingerprint.clone()), synced_copy: true })
        }
        Some(SlotSource::Vault { fingerprint, .. }) => {
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

/// 拿掉一個檔案;已經不存在不算錯。
fn remove_if_present(path: &Path) -> std::io::Result<()> {
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

/// 帳戶裡還有、這台沒有主機用到的插槽:只拿掉連結檔(symlink,或原檔還在而且內容相同的 hard link;原檔不動)與旁邊自己的 `.pub`,
/// `LocalSlot` 的記錄留著 —— `Linked` 來源、`origin`、使用者的挑選不能因為暫時沒有主機用到(主機的 `IdentityFile` 暫時拿掉、space 檔
/// 重新長出來)就忘掉,用到的時候 `maintain` 重新連結(並從自己的金鑰重寫 `.pub`),不會再問使用者。拿掉之後記錄標成 `parked`:它不再
/// 擁有插槽路徑上的東西 —— 之後那裡出現的任何東西(別的插槽放的副本與 `.pub`、使用者的檔案)都不是它的,這裡不看、不碰,也不把它記成
/// 這個插槽的複製檔。永遠不拿掉一把金鑰的最後一個名字:原檔不見或內容不同的 hard link 留在原地、記成複製檔(那是這個插槽放的,沒有收起來)。
/// 複製檔與同步來的副本本來就不拿掉(私鑰不自動刪除);使用者自己換在 symlink 位置上的一般檔案也不碰(連同旁邊的 `.pub`),記錄同樣標成
/// `parked`。
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
            // 真的拿掉自己的連結時,連同旁邊自己的 `.pub` 一起拿掉:空著的插槽路徑旁不留 `.pub`(別的插槽落地時自己會寫,這個插槽重新連結
            // 時從自己的金鑰重寫)。路徑上本來就沒有東西時什麼都不動 —— 旁邊的 `.pub` 不能確定是自己的。
            if slot_files::occupied(path) {
                if let Err(e) = slot_files::remove_slot(path) {
                    local.last_error = Some(e.to_string());
                    return;
                }
            }
            local.parked = true;
        }
    }
    local.last_error = None;
}

/// 帳戶裡已經沒有的插槽(tombstone;或整筆記錄都不見、這台也沒有任何主機用到):移除連結(連同 `.pub`)、忘掉這筆記錄;同步來的副本與複製檔留著
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

/// 這台有主機用到的插槽,維護這台已經放進去的東西:連結的確認原檔還在、hard link 與複製跟上原檔。收起來的連結(`parked`)只在路徑空著的
/// 時候重新連結;symlink 的插槽路徑上不是自己的 symlink 就是擋路(記錄收起來)。回傳 true = 插槽裡沒有這台的東西(沒有來源,或同步來的副本
/// 被刪掉了;`source` 已清掉):要不要落地同步的金鑰由呼叫端決定 —— 只有勾選的 space 用到的插槽才落地(`land_into`,spec §6.2)。
/// 只在 SSHelter 的插槽(`SlotSource::Vault`)只維護 `.pub`、回報擋路的檔案,一律回 false:私鑰在保管庫,從不落地到插槽路徑上。
fn maintain(local: &mut LocalSlot, keys_dir: &Path, path: &Path) -> bool {
    match local.source.clone() {
        Some(SlotSource::Linked { path: source, link, origin, fingerprint: recorded }) => {
            let source_path = PathBuf::from(&source);
            // 插槽路徑上的東西是不是這筆記錄自己的。收起來的連結什麼都不擁有;symlink 的插槽,路徑上要正好是指到記錄裡原檔的 symlink
            // (`slot_files::link` 做的就是這個)。不是的話 —— 別的插槽放的副本、使用者換上的檔案、指到別處的 symlink —— 不覆蓋、不認它,
            // 回報擋路,記錄收起來:它不擁有路徑上的東西,不列在 `device.slots`,之後沒有主機用到或插槽被刪除時也不碰那個檔案。收起來的
            // 記錄碰到正好是自己的 symlink(上一輪重新連結了、狀態卻沒存下來 —— `commit` 被搶先;或使用者把連結放回來了)就認回它。
            // hard link 與複製分辨不出是不是自己的,照舊(內容和原檔不同就重新連結)。
            let mut recognised = false;
            if slot_files::occupied(path) && (local.parked || link == LinkKind::Symlink) {
                let own_link = link == LinkKind::Symlink && std::fs::read_link(path).is_ok_and(|target| target == source_path);
                if !own_link {
                    local.parked = true;
                    local.last_error = Some(in_the_way_message(path));
                    return false;
                }
                recognised = local.parked;
            }
            if !source_path.is_file() {
                local.last_error = Some(source_gone_message(&source));
                return false;
            }
            // hard link 與複製不會跟著原檔走:內容不同(原檔被換掉)就重新連結;任何一種,插槽不見了都重建。
            let stale = !slot_files::occupied(path)
                || (link != LinkKind::Symlink && slot_files::content_sha256(path) != slot_files::content_sha256(&source_path));
            let fingerprint = local_key_fingerprint(&source_path);
            // 連結、重新連結、認回的時候,插槽旁的 `.pub` 一律從連到的這把金鑰自己重寫:這個位置上留著的 `.pub` 可能是別的插槽(或別人)放的,
            // 之後 OpenSSH 與 `ssh-copy-id -i <slot>` 讀的就是它。在連結之前寫:寫不進去就不連結,下一輪再試。原檔就地換成另一把金鑰的時候
            // (指紋和記錄的不同)也一樣:symlink 跟著原檔走、hard link 和原檔共用內容,插槽不必重新連結,`.pub` 卻還是上一把的 —— OpenSSH
            // 先讀 `<slot>.pub`,和私鑰對不上就不能用(「Sync the new key」之前,這台自己就連不上了)。
            if stale || recognised || fingerprint != recorded {
                if let Err(e) = slot_files::ensure_keys_dir(keys_dir).and_then(|()| write_linked_public(path, &source_path)) {
                    local.last_error = Some(e.to_string());
                    return false;
                }
            }
            let link = if stale {
                match slot_files::link(&source_path, path) {
                    Ok(kind) => kind,
                    Err(e) => {
                        local.last_error = Some(e.to_string());
                        return false;
                    }
                }
            } else {
                link
            };
            local.source = Some(SlotSource::Linked { path: source, link, fingerprint, origin });
            local.parked = false;
            local.last_error = None;
            false
        }
        Some(SlotSource::Vault { public_key, .. }) => {
            // 只在 SSHelter:插槽路徑上不該有檔案(`ssh` 會先讀它)。出現了就擋路、不碰;`.pub` 不見或不對就從記錄重寫。
            if slot_files::occupied(path) {
                local.last_error = Some(in_the_way_message(path));
                return false;
            }
            let current = std::fs::read_to_string(public_path(path)).ok();
            if current.as_deref().map(str::trim) != Some(public_key.trim()) {
                if let Err(e) = slot_files::ensure_keys_dir(keys_dir).and_then(|()| slot_files::write_public(path, &public_key)) {
                    local.last_error = Some(e.to_string());
                    return false;
                }
            }
            local.last_error = None;
            false
        }
        Some(SlotSource::SyncedCopy { .. }) if slot_files::occupied(path) => {
            local.last_error = None;
            false
        }
        // 副本被刪掉了(或還沒有東西):由呼叫端決定要不要把同步的金鑰放進去。
        Some(SlotSource::SyncedCopy { .. }) | None => {
            local.source = None;
            true
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
        Ok(fingerprint) => {
            local.source = Some(SlotSource::SyncedCopy { fingerprint });
            // 插槽裡的私鑰來自這個帳戶:記錄是這個帳戶的(`LocalSlot::learned_in`),副本也是(`LocalSlot::copy_from_another_account`)。
            local.learned_in = Some(account.chain_id.clone());
            local.copy_from_another_account = false;
        }
        Err(message) => local.last_error = Some(message),
    }
}

/// 把同步的私鑰寫進空的插槽(spec §6.2):指紋要和插槽記錄一致。插槽路徑上已經有東西時,只有內容完全相同(上一輪寫了
/// 檔案、狀態卻沒存下來)才當成自己的,其他一律不覆蓋。錯誤訊息只帶路徑與原因。
///
/// `.pub` 之後會被 deploy 複製進伺服器的 authorized_keys,所以只能來自通過指紋檢查的這把私鑰(`facts.public_key`),
/// 不取自記錄上的 `public_key`(spec §3:帳戶裡的成員只能改變主機用哪把金鑰);而且一定在指紋檢查通過之後才寫。
pub(crate) fn land(secret: &str, payload: &KeySlotPayload, keys_dir: &Path, path: &Path) -> Result<String, String> {
    let facts = check_synced_key(secret, payload)?;
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

/// 同步的私鑰能不能放進插槽(spec §6.2):讀得懂,而且指紋和插槽記錄一致。錯誤訊息不帶金鑰。
pub(crate) fn check_synced_key(secret: &str, payload: &KeySlotPayload) -> Result<KeyFacts, String> {
    let facts = inspect_private_key(secret).map_err(|_| MISMATCH_MESSAGE.to_string())?;
    if payload.fingerprint.as_deref() != Some(facts.fingerprint.as_str()) {
        return Err(MISMATCH_MESSAGE.to_string());
    }
    Ok(facts)
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
///
/// 同步來的副本也要是從這個帳戶收到的:之前的帳戶留下、就地放進這個帳戶的副本(`LocalSlot::copy_from_another_account`)位元組來自之前的帳戶,
/// 只有這台的使用者在這裡選了同步它(`uploaded_fingerprint` 是它的指紋)才補 `key` —— 選了「Keep on this computer」的,成員之後把插槽改成 `synced`、
/// 填上 `device.slots` 看得到的指紋,再讓帳戶掉了它,也不上傳。
///
/// 補寫的一定是這個帳戶自己掉了的記錄(N1):在別的帳戶學到的記錄(`LocalSlot::learned_in` 不是現在的帳戶;不知道的也算)什麼都不寫 ——
/// 離開帳戶 A、建立或加入另一個帳戶之後,`~/.ssh/sshelter-local/` 裡用到 A 的插槽的主機被搬進新帳戶的 space,新帳戶裡當然沒有那個插槽;
/// 照寫的話,A 的插槽與私鑰(這台選了同步的那把,或 A 同步來的副本)就進了新帳戶、落地到新帳戶的每一台電腦。回傳有沒有寫(沒寫的,呼叫端照常維護)。
///
/// 只在 SSHelter 的金鑰(`SlotSource::Vault`)從保管庫讀(`vault`),規則同上:這台同意上傳過的那把(`uploaded_fingerprint`),或從這個帳戶
/// 同步來、不是之前的帳戶留下的(保管庫那一筆的來源是 `Synced`,`copy_from_another_account` 是 false)。保管庫裡那一筆的私鑰本身也要是記錄裡的
/// 那一把(以私鑰推出的指紋):同意與來源說的都是記錄裡的金鑰,不是保管庫裡剛好放著的另一把。只在 `holds` 說保管庫讀得懂、有這一筆時才開它
/// (開讀不懂的保管庫會把檔案搬到旁邊,一輪同步不做這件事)。
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
    vault: &dyn VaultKeys,
) -> bool {
    if local.learned_in.as_deref() != Some(account.chain_id.as_str()) {
        return false;
    }
    put_slot(account, slot_id, Some(payload), device_id, now_ms);
    if payload.mode != SlotMode::Synced {
        return true;
    }
    let readable = match &local.source {
        Some(SlotSource::Linked { path: source, .. }) => std::fs::read_to_string(source).ok().filter(|text| {
            inspect_private_key(text).is_ok_and(|f| local.uploaded_fingerprint.as_deref() == Some(f.fingerprint.as_str()))
        }),
        Some(SlotSource::SyncedCopy { fingerprint })
            if !local.copy_from_another_account || local.uploaded_fingerprint.as_deref() == Some(fingerprint.as_str()) =>
        {
            std::fs::read_to_string(path).ok().filter(|text| inspect_private_key(text).is_ok_and(|f| f.fingerprint == *fingerprint))
        }
        // 保管庫裡的私鑰:這台同意上傳過的那把,或從這個帳戶同步來、不是之前的帳戶留下的;而且就是記錄裡的那一把。先只讀 id(`holds`)確認
        // 保管庫讀得懂、有這一筆,才開它(`private_key`):一輪同步絕不讓讀不懂的保管庫檔被搬到旁邊。
        Some(SlotSource::Vault { fingerprint, .. }) => (vault.holds(slot_id) == Some(true))
            .then(|| vault.private_key(slot_id))
            .flatten()
            .and_then(|(text, origin)| {
                let recorded = inspect_private_key(&text).is_ok_and(|f| f.fingerprint == *fingerprint);
                let consented = local.uploaded_fingerprint.as_deref() == Some(fingerprint.as_str());
                let from_this_account = origin == EntryOrigin::Synced && !local.copy_from_another_account;
                (recorded && (consented || from_this_account)).then(|| text.to_string())
            }),
        Some(SlotSource::SyncedCopy { .. }) | None => None,
    };
    let matching = readable.filter(|text| {
        inspect_private_key(text).is_ok_and(|f| payload.fingerprint.as_deref() == Some(f.fingerprint.as_str()))
    });
    if let Some(text) = matching {
        if let Err(e) = put_key_secret(account, account_keys, slot_id, Some(&text), device_id, now_ms) {
            eprintln!("[sync] could not restore a key slot's key: {e}");
        }
    }
    true
}

// ── 給 UI 的插槽檢視(SP3 spec §7.2、§7.3)─────────────────────────────────────────────────────

/// 帳戶裡的插槽(依名稱),加上帳戶裡已經沒有、這台還留著東西的(`in_account` = false):被刪除的插槽留下的副本(Not in use),以及帳戶裡完全
/// 找不到、這台的主機還用著的(離開之後建立或加入了別的帳戶,`~/.ssh/sshelter-local/` 的主機還指著它;`kept_status`,不能刪除)。和別的插槽
/// 同檔名、這台又沒有握著的插槽,狀態一律是 `CONTESTED_MESSAGE`(不論有沒有主機用到)。`in_use` = 整份 config 裡用到的插槽(`config_slot_hosts`):
/// 那些主機也列在 `hosts`,帳戶裡的插槽有任何主機用到就不是「沒有用到」。
pub fn views(state: &SyncStateV2, account_keys: &ChainKeys, home: &Path, in_use: &BTreeMap<String, Vec<String>>) -> Vec<SyncKeySlotView> {
    let Some(account) = state.account.as_ref() else { return Vec::new() };
    let needed = slot_hosts(state);
    let all_devices = devices(account);
    let keys_dir = home.join(SLOT_DIR);
    let live = live_slots(account);
    let uses = file_name_uses(&live);
    let used = |file: &str| needed.contains_key(file) || in_use.contains_key(file);
    // 用到這個插槽檔名的主機:勾選的 space 裡的與整份 config 裡的,排序、不重複。
    let hosts = |file: &str| -> Vec<String> {
        let all: BTreeSet<&String> = needed.get(file).into_iter().chain(in_use.get(file)).flatten().collect();
        all.into_iter().cloned().collect()
    };
    let view = |id: &str, payload: &KeySlotPayload, status: SlotStatusView, hosts: Vec<String>, local_has_passphrase: Option<bool>, in_account: bool| {
        SyncKeySlotView {
            id: id.to_string(),
            name: payload.name.clone(),
            mode: payload.mode,
            fingerprint: payload.fingerprint.clone(),
            key_type: payload.key_type.clone(),
            has_passphrase: payload.has_passphrase,
            local_has_passphrase,
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
            in_account,
            in_vault: state.key_slots.get(id).is_some_and(|l| matches!(l.source, Some(SlotSource::Vault { .. }))),
        }
    };
    let mut out = Vec::new();
    for (id, payload) in &live {
        let file = slot_file_name(&payload.name, id);
        let local = state.key_slots.get(id);
        let status = if contested(&uses, local, &file) {
            SlotStatusView::Error { message: CONTESTED_MESSAGE.to_string() }
        } else {
            let has_secret = account.sealed.get(&key_secret_key(account_keys, id)).is_some_and(|s| !s.envelope.deleted);
            slot_status(local, payload, needed.contains_key(&file), used(&file), has_secret, &keys_dir.join(&file))
        };
        // 「Sync this key」(`own` 而且 Ready)與「Sync the new key」(SourceChanged)上傳的是這台插槽裡的那把,不是帳戶裡現在的那把:
        // 上傳之前的確認說明的是它有沒有 passphrase。其他的列不提供上傳,不讀金鑰。
        let uploads = matches!(status, SlotStatusView::SourceChanged { .. })
            || (payload.mode == SlotMode::Own && matches!(status, SlotStatusView::Ready { .. }));
        let local_has_passphrase = if uploads { local_key_passphrase(local, &keys_dir) } else { None };
        out.push(view(id, payload, status, hosts(&file), local_has_passphrase, true));
    }
    for (id, local) in &state.key_slots {
        if live.iter().any(|(l, _)| l == id) {
            continue;
        }
        let (Some(source), Some(payload)) = (&local.source, &local.payload) else { continue };
        let path = keys_dir.join(&local.file_name);
        // 帳戶裡完全找不到、這台的主機還用著(`reconcile` 因此留著它):Ready 或錯誤,不能刪。被刪除的(tombstone)照 spec §4.2:連結已經移除,
        // 留下的副本與複製檔是 Not in use(主機還指著它的話,刪除副本會被拒絕)。
        if !slot_record_exists(account, id) && used(&local.file_name) {
            out.push(view(id, payload, kept_status(local, source, &path), hosts(&local.file_name), None, false));
        } else {
            out.push(view(id, payload, SlotStatusView::NotInUse { file: path.display().to_string() }, Vec::new(), None, false));
        }
    }
    out
}

/// 帳戶裡已經沒有、這台的主機還用著的插槽(`views`)在這台的狀態:錯誤,或插槽裡放著的金鑰(Ready)。帳戶裡沒有它,不和帳戶裡的金鑰比較
/// (同步、挑金鑰的動作都不適用),主機還用著,也不能刪除。
fn kept_status(local: &LocalSlot, source: &SlotSource, slot_path: &Path) -> SlotStatusView {
    if let Some(message) = &local.last_error {
        return SlotStatusView::Error { message: message.clone() };
    }
    match source {
        SlotSource::Linked { path, fingerprint, .. } => {
            SlotStatusView::Ready { file: path.clone(), synced_copy: false, fingerprint: fingerprint.clone() }
        }
        SlotSource::SyncedCopy { fingerprint } => {
            SlotStatusView::Ready { file: slot_path.display().to_string(), synced_copy: true, fingerprint: Some(fingerprint.clone()) }
        }
        SlotSource::Vault { fingerprint, .. } => {
            SlotStatusView::Ready { file: slot_path.display().to_string(), synced_copy: false, fingerprint: Some(fingerprint.clone()) }
        }
    }
}

/// 這台插槽裡那把金鑰(`readable_key`:連到的金鑰,或仍是記錄裡那一把的同步副本)有沒有 passphrase;讀不到、讀不懂 → None。每次組 overview
/// 都可能跑,所以先確認它是不超過 64 KiB 的私鑰檔(`slot_setup::is_private_key_file`:一般檔案),不會卡在 FIFO 之類的檔案上。只在 SSHelter 的
/// 金鑰看記錄(`SlotSource::Vault::has_passphrase`),不開保管庫。
fn local_key_passphrase(local: Option<&LocalSlot>, keys_dir: &Path) -> Option<bool> {
    let local = local?;
    let file = match local.source.as_ref()? {
        SlotSource::Linked { path, .. } => PathBuf::from(path),
        SlotSource::SyncedCopy { .. } => keys_dir.join(&local.file_name),
        SlotSource::Vault { has_passphrase, .. } => return Some(*has_passphrase),
    };
    if !crate::sync::slot_setup::is_private_key_file(&file) {
        return None;
    }
    readable_key(Some(local), keys_dir).and_then(|text| inspect_private_key(&text).ok()).map(|facts| facts.has_passphrase)
}

/// 一個帳戶裡的插槽在這台的狀態。錯誤優先;`synced` 的插槽,這台連到的若不是同步的那把:目前同步的那把是這台上傳的
/// (`LocalSlot::uploaded_fingerprint`),表示這台自己的金鑰之後換了 → SourceChanged(「Sync the new key」);不是這台上傳的(建立插槽的
/// 那台也一樣:別台同步了自己的金鑰,這台的金鑰並沒有換)→ SyncedAvailable。
///
/// `needed` = 勾選的 space 裡有主機用到(`slot_hosts`);`used` = 這台有任何主機用到(也算整份 config 裡的,`config_slot_hosts`;一定包含 `needed`)。
/// 有主機用到的插槽不是 NotUsedHere / NotInUse(副本不能刪)。只有不在勾選的 space 裡的主機用到、這台又沒有它的金鑰時,同步的金鑰不會落地過來
/// (spec §6.2),所以是「請挑一把」,不是「等同步的金鑰」。
pub fn slot_status(
    local: Option<&LocalSlot>,
    payload: &KeySlotPayload,
    needed: bool,
    used: bool,
    has_secret: bool,
    slot_path: &Path,
) -> SlotStatusView {
    if let Some(message) = local.and_then(|l| l.last_error.clone()) {
        return SlotStatusView::Error { message };
    }
    let here = slot_path.display().to_string();
    let synced = payload.mode == SlotMode::Synced;
    let uploaded_current = local
        .and_then(|l| l.uploaded_fingerprint.as_deref())
        .is_some_and(|uploaded| payload.fingerprint.as_deref() == Some(uploaded));
    match local.and_then(|l| l.source.as_ref()) {
        Some(SlotSource::Linked { path, link, fingerprint, .. }) => {
            let differs = synced && fingerprint != &payload.fingerprint;
            if differs && uploaded_current {
                SlotStatusView::SourceChanged { file: path.clone() }
            } else if differs && has_secret {
                SlotStatusView::SyncedAvailable { file: path.clone() }
            } else if !used {
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
            } else if !used {
                SlotStatusView::NotInUse { file: here }
            } else {
                SlotStatusView::Ready { file: here, synced_copy: true, fingerprint: Some(fingerprint.clone()) }
            }
        }
        Some(SlotSource::Vault { fingerprint, .. }) => {
            // 同連到本機金鑰的插槽:目前同步的那把是這台上傳的,保管庫裡的卻是另一把 → 這台的金鑰換了(「Sync the new key」上傳保管庫裡的那把)。
            let differs = synced && Some(fingerprint) != payload.fingerprint.as_ref();
            if differs && uploaded_current {
                SlotStatusView::SourceChanged { file: here }
            } else if differs && has_secret {
                SlotStatusView::SyncedAvailable { file: here }
            } else if !used {
                SlotStatusView::NotInUse { file: here }
            } else {
                SlotStatusView::Ready { file: here, synced_copy: false, fingerprint: Some(fingerprint.clone()) }
            }
        }
        None if needed => SlotStatusView::NeedsKey { waiting_for_sync: synced },
        None if used => SlotStatusView::NeedsKey { waiting_for_sync: false },
        None => SlotStatusView::NotUsedHere,
    }
}

// ── 使用者的動作(SP3 spec §6.3、§7.2)─────────────────────────────────────────────────────────
//
// 和每一輪的維護一樣,插槽路徑上的東西是不是 SSHelter 放的,只看這個插槽 id 自己的本機記錄(spec §4.2):挑金鑰與改用同步的金鑰
// 只換掉記錄擁有的東西(`occupant`),其他的一律回 `in_the_way_message`;刪除副本只刪路徑上仍是記錄裡那一份的副本。被換掉的金鑰
// 改名保留(`retire_key`,計畫裁定 3;spec §1 私鑰不自動刪除),只有連結本身直接拿掉。和帳戶裡另一個插槽同檔名、這台又沒有握著的
// 插槽(`contested_and_not_held`)一律拒絕。拒絕的時候,檔案與狀態都不動。只在 SSHelter 的插槽(`SlotSource::Vault`)不挑金鑰、不改用
// 同步的金鑰(`refuse_in_vault`):保管庫裡的私鑰可能是那把金鑰僅存的一份,換掉就沒了;要先改回檔案(`set_delivery`),被換掉的金鑰才照上面
// 改名保留。

pub const IN_USE_MESSAGE: &str = "Hosts on this computer still use this key; change them first.";

pub fn not_here_message(device: &str) -> String {
    format!("Do this on a computer that has this key, such as {device}.")
}

fn not_found() -> AppError {
    AppError::NotFound("that key slot no longer exists".to_string())
}

fn contested_error() -> AppError {
    AppError::Other(CONTESTED_MESSAGE.to_string())
}

/// 讀這台插槽裡的私鑰:連到的金鑰(這台的使用者連給這個插槽的那把),或同步來的副本。副本只認這筆記錄自己的路徑上、仍是記錄裡那一把
/// 的檔案(同 `republish`):那個位置可能被換成了別的檔案(使用者的、別的插槽放的),不能把它當成這個插槽的金鑰上傳。只在 SSHelter 的
/// 金鑰不在檔案裡 → None(要它的呼叫端自己讀保管庫,`vault_text`)。
fn readable_key(local: Option<&LocalSlot>, keys_dir: &Path) -> Option<String> {
    let local = local?;
    match local.source.as_ref()? {
        SlotSource::Linked { path, .. } => std::fs::read_to_string(path).ok(),
        SlotSource::SyncedCopy { fingerprint } => std::fs::read_to_string(keys_dir.join(&local.file_name))
            .ok()
            .filter(|text| inspect_private_key(text).is_ok_and(|f| f.fingerprint == *fingerprint)),
        SlotSource::Vault { .. } => None,
    }
}

/// 保管庫裡這個插槽的私鑰原文。那一筆要是記錄裡的那一把(`fingerprint` = `SlotSource::Vault` 的指紋),不是就拒絕(`VAULT_MISMATCH_MESSAGE`),
/// 不拿別把當成這個插槽的金鑰。
fn vault_text(env: &SyncEnv, slot_id: &str, fingerprint: &str) -> Result<Option<String>, AppError> {
    let path = vault_path(&env.state_path);
    let Some(entry) = with_vault(env.runtime, &path, env.keychain, env.now(), |vault| vault.get(slot_id))? else { return Ok(None) };
    if entry.fingerprint != fingerprint {
        return Err(AppError::Other(VAULT_MISMATCH_MESSAGE.to_string()));
    }
    Ok(Some(entry.private_key.clone()))
}

/// 只在 SSHelter 的插槽(`SlotSource::Vault`)不接受挑金鑰與改用同步的金鑰(`VAULT_FIRST_MESSAGE`):保管庫裡的私鑰可能是那把金鑰僅存的
/// 一份,換掉就沒了。使用者先「Keep a file」改回檔案(`set_delivery`),之後挑金鑰、改用同步的金鑰照 SP3 把被換掉的那把改名保留。
/// 在動作讀檔、動到任何東西之前檢查(快照之後立刻)。
fn refuse_in_vault(state: &SyncStateV2, slot_id: &str) -> Result<(), AppError> {
    if state.key_slots.get(slot_id).is_some_and(|l| matches!(l.source, Some(SlotSource::Vault { .. }))) {
        return Err(AppError::Other(VAULT_FIRST_MESSAGE.to_string()));
    }
    Ok(())
}

/// 會寫帳戶記錄的動作(`set_mode`、`slot_setup::create_slot`)要等更換同步碼:進行中(第 2 步起)或這台已被別台擋下時,帳戶區段之後會被整個換掉 ——
/// 複製讀的是 relay 上凍結的舊記錄,切換與重新加入又把整個區段換成新的 —— 這時寫進去的記錄不是被丟掉、就是被較舊的版本取代:使用者看到成功,新帳戶卻沒有
/// 那個變更(「Stop syncing」的 `key` tombstone 就是這樣掉的:新帳戶裡的 `key` 還在,之後每一台加入或重新加入的電腦都落地那把私鑰)。
///
/// 檢查和 space 的操作一樣(`account::account_ready`,同樣的說明):動作最前面 —— 讀檔、連結、寫記錄之前 —— 對快照呼叫 `account_ready` 一次;
/// 提交的 core 臨界區裡呼叫這個函式再檢查一次(`mutate` 的閉包拿不到 core,所以用快照時的帳戶金鑰):鎖外的快照之後同步輪次可能已經記下 `frozen`
/// (它只拿 core 鎖),帳戶也必須仍是快照時的那一個(同 `spaces::still_ready`)。不寫帳戶記錄的動作(挑金鑰、改用同步的金鑰、刪除副本)不檢查。
pub fn account_still_ready(s: &SyncStateV2, account_keys: &ChainKeys) -> Result<(), AppError> {
    account_ready(s, Some(account_keys))?;
    match s.account.as_ref() {
        Some(account) if account.chain_id == account_keys.chain_id => Ok(()),
        _ => Err(AppError::Other(NOT_JOINED_MESSAGE.to_string())),
    }
}

/// 使用者的動作提交時(`mutate` 的閉包裡),帳戶還是快照時的那一個(`chain_id`,動作看到的插槽就在它裡面):回傳它,記成記錄學到的帳戶
/// (`LocalSlot::learned_in`)。帳戶在快照之後換了(離開、加入,或背景的更換同步碼切換了帳戶)→ None:這個動作是在之前的帳戶裡做的,不記成現在的。
pub(crate) fn learned_now(s: &SyncStateV2, chain_id: &str) -> Option<String> {
    s.account.as_ref().filter(|a| a.chain_id == chain_id).map(|a| a.chain_id.clone())
}

/// 快照:(狀態、帳戶金鑰、家目錄)。
fn snapshot(env: &SyncEnv) -> Result<(SyncStateV2, ChainKeys, PathBuf), AppError> {
    let core = env.runtime.core.lock().unwrap();
    let state = core.state.clone().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    let keys = core.account_keys.clone().ok_or_else(|| AppError::Other("join a sync account first".to_string()))?;
    drop(core);
    let home = env.ssh_dir.parent().map(Path::to_path_buf).ok_or_else(|| AppError::Other("cannot determine the home directory".to_string()))?;
    Ok((state, keys, home))
}

/// 使用者的動作要在插槽路徑上放新的東西之前,路徑上現在的東西對這個插槽 id 自己的本機記錄來說是什麼(spec §4.2)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Occupant {
    /// 路徑上沒有東西。
    Empty,
    /// 這個插槽自己的連結:正好指到記錄原檔的 symlink,或原檔還在、內容相同的 hard link。換掉或拿掉它,沒有任何金鑰會消失。
    OwnLink,
    /// 這個插槽放在路徑上的金鑰本身:同步來的副本、複製檔,或原檔不見、內容不同的 hard link(可能是那把金鑰僅存的名字)。換掉之前
    /// 改名保留(`retire_key`),不刪除。
    OwnKey,
    /// 不是這個插槽的:這台沒有它的記錄、記錄沒有來源或記著別的檔名、記錄收起來了(`parked`),或是 symlink 的記錄、路徑上卻不是指到
    /// 記錄原檔的 symlink(同 `maintain` 每一輪的檢查);只在 SSHelter 的記錄(`SlotSource::Vault`)在插槽路徑上什麼都不擁有。不覆蓋、不移除。
    NotOurs,
}

/// 插槽檔名 `file` 的路徑 `path` 上現在的東西(`Occupant`),只依這個插槽 id 的本機記錄 `local` 判斷。
fn occupant(local: Option<&LocalSlot>, file: &str, path: &Path) -> Occupant {
    if !slot_files::occupied(path) {
        return Occupant::Empty;
    }
    let Some(local) = local.filter(|l| l.file_name == file && !l.parked) else { return Occupant::NotOurs };
    match &local.source {
        None => Occupant::NotOurs,
        Some(SlotSource::Vault { .. }) => Occupant::NotOurs,
        Some(SlotSource::SyncedCopy { .. }) => Occupant::OwnKey,
        Some(SlotSource::Linked { path: source, link: LinkKind::Symlink, .. }) => {
            if std::fs::read_link(path).is_ok_and(|target| target.as_path() == Path::new(source)) {
                Occupant::OwnLink
            } else {
                Occupant::NotOurs
            }
        }
        Some(SlotSource::Linked { path: source, link, .. }) => match link_fate(*link, source, path) {
            Some(LinkFate::Removable) => Occupant::OwnLink,
            Some(LinkFate::NotOurs) => Occupant::NotOurs,
            Some(LinkFate::LastName) | None => Occupant::OwnKey,
        },
    }
}

/// 把插槽路徑上的金鑰(連同 `.pub`)改名保留成 `<file>.previous-<內容雜湊的前 8 字元>`(計畫裁定 3;spec §1 私鑰不自動刪除)。
fn retire_key(path: &Path) -> Result<(), AppError> {
    let tag = slot_files::content_sha256(path).map(|h| h[..8].to_string()).unwrap_or_else(|| "old".to_string());
    slot_files::retire(path, &tag).map(|_| ())
}

/// 改成同步(`own` → `synced`;建立插槽的那台換了金鑰後的「Sync the new key」也是它)或停止同步(`synced` → `own`,
/// `key` 寫 tombstone;別台的副本留著)。同步要在讀得到這把私鑰的電腦上做(只在 SSHelter 的金鑰從保管庫讀,`vault_text`),並在這台的
/// 插槽記錄上記下上傳的是哪一把(`LocalSlot::uploaded_fingerprint`:補寫 `key` 時只認它),記錄也從此是這個帳戶的(`LocalSlot::learned_in`:
/// 同意是在這個帳戶給的);停止同步清掉同意。更換同步碼進行中、或這台已被別台擋下時拒絕(`account_ready`,提交時再檢查一次;原因見
/// `account_still_ready`):什麼都不讀、不寫。
pub fn set_mode(env: &SyncEnv, slot_id: &str, mode: SlotMode) -> Result<(), AppError> {
    let (state, keys, home) = snapshot(env)?;
    account_ready(&state, Some(&keys))?;
    let account = state.account.as_ref().ok_or_else(not_found)?;
    let payload = slot(account, slot_id).ok_or_else(not_found)?;
    let not_here = || AppError::Other(not_here_message(&device_name(account, &payload.origin_device_id)));
    let text = match mode {
        SlotMode::Synced => Some(match state.key_slots.get(slot_id).and_then(|l| l.source.as_ref()) {
            Some(SlotSource::Vault { fingerprint, .. }) => vault_text(env, slot_id, fingerprint)?.ok_or_else(not_here)?,
            _ => readable_key(state.key_slots.get(slot_id), &home.join(SLOT_DIR)).ok_or_else(not_here)?,
        }),
        SlotMode::Own => None,
    };
    let facts = match &text {
        Some(t) => Some(inspect_private_key(t).map_err(|e| AppError::Other(e.message().to_string()))?),
        None => None,
    };
    let now = env.now();
    mutate(env, |s| {
        // 提交的臨界區裡再確認一次(`account_still_ready`),在任何修改之前:快照之後同步輪次可能已經記下 `frozen`。
        account_still_ready(s, &keys)?;
        let device_id = s.device_id.clone();
        let local = s.key_slots.get_mut(slot_id);
        // 會失敗的先做:`mutate` 的閉包回 Err 時,已經做的修改不會復原。上傳的那把要記在這台的插槽記錄上,記錄不見了就什麼都不寫。
        if facts.is_some() && local.is_none() {
            return Err(not_here());
        }
        let account = s.account.as_mut().ok_or_else(not_found)?;
        if text.is_some() || account.sealed.contains_key(&key_secret_key(&keys, slot_id)) {
            put_key_secret(account, &keys, slot_id, text.as_deref(), &device_id, now)?;
        }
        let next = KeySlotPayload {
            mode,
            public_key: facts.as_ref().map(|f| f.public_key.clone()),
            fingerprint: facts.as_ref().map(|f| f.fingerprint.clone()),
            key_type: facts.as_ref().map(|f| f.key_type.clone()),
            has_passphrase: facts.as_ref().map(|f| f.has_passphrase),
            ..payload.clone()
        };
        put_slot(account, slot_id, Some(&next), &device_id, now);
        if let Some(local) = local {
            local.uploaded_fingerprint = facts.as_ref().map(|f| f.fingerprint.clone());
            if facts.is_some() {
                // `account_still_ready` 確認過:這就是快照裡、插槽所在的那個帳戶。
                local.learned_in = Some(keys.chain_id.clone());
            }
        }
        Ok(())
    })?;
    env.events.wake();
    Ok(())
}

/// 在這台為插槽挑一把金鑰(本機挑的優先,spec §6.2)。路徑上只有這個插槽自己的東西可以換掉(`occupant`):自己的連結由
/// `slot_files::link` 原子地換成新的;同步來的副本、複製檔與可能是某把金鑰僅存名字的 hard link 先改名保留(計畫裁定 3)。連結之後
/// `.pub` 從挑的這把金鑰重寫;記錄的路徑就是連結用的那個(每一輪在 Unix 上確認 symlink 正好指到它)。`.pub` 或記錄寫不進去就把剛放的
/// 連結收回,下一輪依原本的記錄維護。這台同意上傳過的那把(`uploaded_fingerprint`)不變:挑的金鑰不會因此被上傳。記錄在哪個帳戶學到的
/// (`learned_in`)也不變;這台還沒有記錄的話,就是快照裡插槽所在的帳戶(提交時帳戶換了就不記)。只在 SSHelter 的插槽拒絕(`refuse_in_vault`)。
pub fn pick(env: &SyncEnv, slot_id: &str, path: &str) -> Result<(), AppError> {
    let source = PathBuf::from(path);
    if !source.is_absolute() || !crate::sync::slot_setup::is_private_key_file(&source) {
        return Err(AppError::Other(format!("{path} isn't a private key file")));
    }
    let (state, keys, home) = snapshot(env)?;
    refuse_in_vault(&state, slot_id)?;
    let account = state.account.as_ref().ok_or_else(not_found)?;
    let payload = slot(account, slot_id).ok_or_else(not_found)?;
    if contested_and_not_held(&state, slot_id) {
        return Err(contested_error());
    }
    let keys_dir = home.join(SLOT_DIR);
    let file = slot_file_name(&payload.name, slot_id);
    let slot_path = keys_dir.join(&file);
    match occupant(state.key_slots.get(slot_id), &file, &slot_path) {
        Occupant::NotOurs => return Err(AppError::Other(in_the_way_message(&slot_path))),
        Occupant::OwnKey => retire_key(&slot_path)?,
        Occupant::Empty | Occupant::OwnLink => {}
    }
    slot_files::ensure_keys_dir(&keys_dir)?;
    let link = slot_files::link(&source, &slot_path)?;
    if let Err(e) = write_linked_public(&slot_path, &source) {
        let _ = slot_files::remove_slot(&slot_path);
        return Err(e);
    }
    let fingerprint = local_key_fingerprint(&source);
    let result = mutate(env, |s| {
        let origin = payload.origin_device_id == s.device_id;
        let learned_here = learned_now(s, &keys.chain_id);
        let existing = s.key_slots.get(slot_id);
        let uploaded_fingerprint = existing.and_then(|l| l.uploaded_fingerprint.clone());
        let learned_in = match existing {
            Some(l) => l.learned_in.clone(),
            None => learned_here,
        };
        s.key_slots.insert(
            slot_id.to_string(),
            LocalSlot {
                file_name: file.clone(),
                source: Some(SlotSource::Linked { path: path.to_string(), link, fingerprint: fingerprint.clone(), origin }),
                last_error: None,
                asked: true,
                payload: Some(payload.clone()),
                uploaded_fingerprint,
                parked: false,
                learned_in,
                copy_from_another_account: false,
            },
        );
        Ok(())
    });
    if let Err(e) = result {
        let _ = slot_files::remove_slot(&slot_path);
        return Err(e);
    }
    env.events.wake();
    Ok(())
}

/// 改用同步的金鑰(狀態 SyncedAvailable)。同步的金鑰先通過指紋檢查,對不上就什麼都不動。這台在插槽裡放了東西的話,只換掉這個插槽
/// 自己的(`occupant`):自己的連結拿掉(連到的金鑰本身不動),舊副本、複製檔與可能是某把金鑰僅存名字的 hard link 改名保留(計畫裁定 3);
/// 路徑上的東西不是它的(收起來的記錄、symlink 不是指到記錄的原檔……)就擋路。這台沒有在插槽裡放東西的話,同每一輪,`land` 只寫進空著
/// 的路徑。落地之後的記錄不是收起來的,是快照裡那個帳戶的(`learned_in`:插槽裡的私鑰來自那裡;提交時帳戶換了就不改記),副本也不再是之前的帳戶的
/// (`copy_from_another_account`)。只在 SSHelter 的插槽拒絕(`refuse_in_vault`):保管庫裡那把可能是它僅存的一份。
pub fn use_synced(env: &SyncEnv, slot_id: &str) -> Result<(), AppError> {
    let (state, keys, home) = snapshot(env)?;
    refuse_in_vault(&state, slot_id)?;
    let account = state.account.as_ref().ok_or_else(not_found)?;
    let payload = slot(account, slot_id).ok_or_else(not_found)?;
    if contested_and_not_held(&state, slot_id) {
        return Err(contested_error());
    }
    let secret = (payload.mode == SlotMode::Synced)
        .then(|| open_key_secret(account, &keys, slot_id))
        .flatten()
        .ok_or_else(|| AppError::Other("this key isn't synced".to_string()))?;
    check_synced_key(&secret, &payload).map_err(AppError::Other)?;
    let keys_dir = home.join(SLOT_DIR);
    let file = slot_file_name(&payload.name, slot_id);
    let slot_path = keys_dir.join(&file);
    let local = state.key_slots.get(slot_id);
    if local.is_some_and(|l| l.source.is_some()) {
        match occupant(local, &file, &slot_path) {
            Occupant::NotOurs => return Err(AppError::Other(in_the_way_message(&slot_path))),
            Occupant::OwnLink => slot_files::remove_slot(&slot_path)?,
            Occupant::OwnKey => retire_key(&slot_path)?,
            Occupant::Empty => {}
        }
    }
    let fingerprint = land(&secret, &payload, &keys_dir, &slot_path).map_err(AppError::Other)?;
    mutate(env, |s| {
        let learned_here = learned_now(s, &keys.chain_id);
        let local = s.key_slots.entry(slot_id.to_string()).or_insert_with(|| LocalSlot {
            file_name: file.clone(),
            source: None,
            last_error: None,
            asked: true,
            payload: Some(payload.clone()),
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
        });
        local.source = Some(SlotSource::SyncedCopy { fingerprint: fingerprint.clone() });
        local.last_error = None;
        local.parked = false;
        if learned_here.is_some() {
            local.learned_in = learned_here;
        }
        // 副本的位元組來自快照裡的帳戶:記錄學到的就是它時,這份副本是那個帳戶的(提交時帳戶換了,就當成別的帳戶的)。
        local.copy_from_another_account = local.learned_in.as_deref() != Some(keys.chain_id.as_str());
        Ok(())
    })?;
    env.events.wake();
    Ok(())
}

/// 插槽路徑 `path` 上的檔案還是不是這筆記錄放的那一份副本(刪除副本之前)。只看檔案本身的位元組,不看旁邊的 `.pub`:那是 SSHelter 從記錄的
/// 金鑰寫的,私鑰的檔案被換掉時它還留著(`local_key_fingerprint` 對讀不懂的私鑰會改讀它,所以這裡不用它)。同步來的副本一定是 OpenSSH 格式:
/// 以檔案本身推出的指紋等於記錄的指紋。複製檔:內容和記錄的原檔相同,或以檔案本身推出的指紋等於記錄的指紋(記錄沒有指紋就只看內容)。
fn holds_recorded_copy(copy: &SlotSource, path: &Path) -> bool {
    let own_fingerprint = || std::fs::read_to_string(path).ok().and_then(|text| inspect_private_key(&text).ok()).map(|f| f.fingerprint);
    match copy {
        SlotSource::SyncedCopy { fingerprint } => own_fingerprint().as_ref() == Some(fingerprint),
        SlotSource::Linked { path: original, link: LinkKind::Copy, fingerprint, .. } => {
            let same_bytes = matches!(
                (slot_files::content_sha256(path), slot_files::content_sha256(Path::new(original))),
                (Some(here), Some(there)) if here == there
            );
            same_bytes || fingerprint.as_ref().is_some_and(|recorded| own_fingerprint().as_ref() == Some(recorded))
        }
        SlotSource::Linked { .. } => false,
        SlotSource::Vault { .. } => false,
    }
}

/// 刪除沒有主機用到的副本(同步來的,或 Windows 上的複製檔)與它的 `.pub`。用得到的插槽不能刪:勾選的 space 裡的主機,以及整份 config 裡的任何
/// 主機(主 config、`~/.ssh/sshelter-local/`……,`config_slot_uses`;config 還沒載入就不知道有沒有,不刪)。路徑上的檔案必須還是這筆記錄放的那一份
/// (`holds_recorded_copy`);不是(使用者換上的、別的插槽放的)就擋路,什麼都不刪。副本已經不在了:只忘掉記錄,旁邊的 `.pub` 不能確定是
/// 自己的,不碰(同 `park_link`)。只在 SSHelter 的金鑰(`SlotSource::Vault`):插槽路徑上有檔案就擋路;否則拿掉保管庫裡那一筆與插槽旁的
/// `.pub`(那是這筆記錄每一輪維護的),再忘掉記錄。
pub fn delete_copy(env: &SyncEnv, slot_id: &str) -> Result<(), AppError> {
    let (state, _keys, home) = snapshot(env)?;
    if contested_and_not_held(&state, slot_id) {
        return Err(contested_error());
    }
    let local = state.key_slots.get(slot_id).ok_or_else(not_found)?;
    let in_use = config_slot_uses(env).ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    if slot_hosts(&state).contains_key(&local.file_name) || in_use.contains_key(&local.file_name) {
        return Err(AppError::Other(IN_USE_MESSAGE.to_string()));
    }
    if matches!(local.source, Some(SlotSource::Vault { .. })) {
        let path = home.join(SLOT_DIR).join(&local.file_name);
        if slot_files::occupied(&path) {
            return Err(AppError::Other(in_the_way_message(&path)));
        }
        with_vault(env.runtime, &vault_path(&env.state_path), env.keychain, env.now(), |vault| vault.remove(slot_id))?;
        let _ = std::fs::remove_file(public_path(&path));
        mutate(env, |s| {
            s.key_slots.remove(slot_id);
            Ok(())
        })?;
        env.events.wake();
        return Ok(());
    }
    let copy = match &local.source {
        Some(copy @ (SlotSource::SyncedCopy { .. } | SlotSource::Linked { link: LinkKind::Copy, .. })) => copy,
        _ => return Err(not_found()),
    };
    let path = home.join(SLOT_DIR).join(&local.file_name);
    if slot_files::occupied(&path) {
        if !holds_recorded_copy(copy, &path) {
            return Err(AppError::Other(in_the_way_message(&path)));
        }
        slot_files::remove_slot(&path)?;
    }
    mutate(env, |s| {
        s.key_slots.remove(slot_id);
        Ok(())
    })?;
    env.events.wake();
    Ok(())
}

/// 這台的插槽改成只在 SSHelter(`vault` = true:私鑰放進保管庫,插槽目錄只留 `.pub`)或改回檔案(插槽路徑放私鑰的副本,保管庫不再留它)。
/// 使用者自己的原檔一律不碰;插槽路徑上可能是某把金鑰僅存名字的 hard link 或複製檔,改名保留(`retire_key`)而不刪除。
///
/// 搬進保管庫:先放進保管庫,再處理插槽路徑上這個插槽自己的東西 —— 連結現在就拿掉(金鑰還在原檔;之後的步驟失敗,記錄還是連結,下一輪照它
/// 重新連結),複製檔與可能是僅存名字的 hard link 改名保留;同步來的副本要等記錄提交之後才拿掉(只拿掉私鑰,`.pub` 留著)。先刪的話,之後的步驟
/// 一失敗,記錄還說插槽裡有副本、檔案卻不見了,帳戶裡沒有這把金鑰時(Stop syncing 之後、之前的帳戶留下的副本)它只剩保管庫裡一筆沒有記錄用到的。
/// 兩次檢查之間出現在路徑上的檔案不是這個插槽的:擋路,不碰。
///
/// 改回檔案:保管庫那一筆要是記錄裡的那一把(`VAULT_MISMATCH_MESSAGE`)。先寫插槽檔與 `.pub`,記錄改成同步來的副本(`SyncedCopy`;保管庫那一筆
/// 不是從這個帳戶同步來的,`copy_from_another_account` 就設成 true,補寫 `key` 時要這台的同意),最後才拿掉保管庫那一筆:拿不掉只留下一筆沒有記錄
/// 用到的(agent 不提供它),不會有記錄說金鑰在保管庫、保管庫裡卻沒有它。`.pub` 寫不進去或提交被拒(記錄還是保管庫的)就收回剛寫的私鑰檔,
/// 不留下一個下一輪被當成擋路的檔案。
///
/// 兩個方向做完都會更新 agent 的設定(`agent::wiring::refresh_env`):`agent/config` 列的主機跟著這個插槽走,第一次需要時 Include 也在這時放進主 config。
/// 更新不成(例如主 config 在載入之後被別的程式改過)只記到 stderr、不讓搬動本身失敗;下一輪同步(`round::run_round` 的 6c)會再做一次。
pub fn set_delivery(env: &SyncEnv, slot_id: &str, vault: bool) -> Result<(), AppError> {
    let (state, _keys, home) = snapshot(env)?;
    if contested_and_not_held(&state, slot_id) {
        return Err(contested_error());
    }
    let local = state.key_slots.get(slot_id).cloned().ok_or_else(not_found)?;
    let keys_dir = home.join(SLOT_DIR);
    let slot_path = keys_dir.join(&local.file_name);
    let vault_file = vault_path(&env.state_path);
    let now = env.now();
    if vault {
        let origin = match &local.source {
            Some(SlotSource::Vault { .. }) => return Ok(()),
            Some(SlotSource::SyncedCopy { .. }) if !local.copy_from_another_account => EntryOrigin::Synced,
            Some(SlotSource::SyncedCopy { .. } | SlotSource::Linked { .. }) => EntryOrigin::Imported,
            None => return Err(AppError::Other("This computer doesn't have this key yet.".to_string())),
        };
        let text = readable_key(Some(&local), &keys_dir)
            .ok_or_else(|| AppError::Other(source_gone_message(&slot_path.display().to_string())))?;
        let facts = inspect_private_key(&text).map_err(|e| AppError::Other(e.message().to_string()))?;
        match occupant(Some(&local), &local.file_name, &slot_path) {
            Occupant::NotOurs => return Err(AppError::Other(in_the_way_message(&slot_path))),
            Occupant::OwnLink | Occupant::OwnKey | Occupant::Empty => {}
        }
        let entry = VaultEntry {
            private_key: text,
            public_key: facts.public_key.clone(),
            fingerprint: facts.fingerprint.clone(),
            origin,
            added_at_ms: now,
        };
        with_vault(env.runtime, &vault_file, env.keychain, now, |v| v.put(env.keychain, slot_id, &entry))?;
        let synced_copy = local.source.as_ref().filter(|source| matches!(source, SlotSource::SyncedCopy { .. }));
        match occupant(Some(&local), &local.file_name, &slot_path) {
            // 第一次檢查之後才出現在路徑上的檔案:不是這個插槽的,不碰(保管庫多了一筆沒有記錄用到的)。
            Occupant::NotOurs => return Err(AppError::Other(in_the_way_message(&slot_path))),
            // 自己的連結:現在就拿掉,金鑰還在原檔。
            Occupant::OwnLink => slot_files::remove_slot(&slot_path)?,
            // 複製檔或可能是僅存名字的 hard link:改名保留。
            Occupant::OwnKey if synced_copy.is_none() => retire_key(&slot_path)?,
            // 同步來的副本:記錄提交之後才拿掉(下面)。
            Occupant::OwnKey | Occupant::Empty => {}
        }
        slot_files::ensure_keys_dir(&keys_dir)?;
        slot_files::write_public(&slot_path, &facts.public_key)?;
        mutate(env, |s| {
            let local = s.key_slots.get_mut(slot_id).ok_or_else(not_found)?;
            local.source = Some(SlotSource::Vault {
                fingerprint: facts.fingerprint.clone(),
                public_key: facts.public_key.clone(),
                has_passphrase: facts.has_passphrase,
            });
            local.last_error = None;
            local.parked = false;
            Ok(())
        })?;
        // 記錄已經說金鑰在保管庫:才拿掉插槽裡同步來的副本(`readable_key` 確認過是記錄裡那一把,同一份剛放進保管庫)。路徑上的檔案要仍是那一份
        // 才刪;拿不掉就留著 —— 下一輪把它當成擋路的檔案回報,什麼都沒少。
        if let Some(copy) = synced_copy {
            if holds_recorded_copy(copy, &slot_path) {
                if let Err(e) = remove_if_present(&slot_path) {
                    eprintln!("[sync] a key moved into SSHelter's vault is still in its slot file: {e}");
                }
            }
        }
    } else {
        let Some(SlotSource::Vault { fingerprint: recorded, .. }) = &local.source else { return Ok(()) };
        if slot_files::occupied(&slot_path) {
            return Err(AppError::Other(in_the_way_message(&slot_path)));
        }
        let entry = with_vault(env.runtime, &vault_file, env.keychain, now, |v| v.get(slot_id))?
            .ok_or_else(|| AppError::Other("This key is missing from SSHelter's vault.".to_string()))?;
        if entry.fingerprint != *recorded {
            return Err(AppError::Other(VAULT_MISMATCH_MESSAGE.to_string()));
        }
        slot_files::ensure_keys_dir(&keys_dir)?;
        slot_files::write_private(&slot_path, entry.private_key.as_bytes())?;
        // 收回剛寫的私鑰檔(`.pub` 是同一把的,留著):記錄還說金鑰在保管庫、保管庫裡也還有它,留著的話下一輪會把 SSHelter 自己的檔案當成擋路。
        let take_back = || {
            let _ = remove_if_present(&slot_path);
        };
        if let Err(e) = slot_files::write_public(&slot_path, &entry.public_key) {
            take_back();
            return Err(e);
        }
        let from_this_account = entry.origin == EntryOrigin::Synced;
        let fingerprint = entry.fingerprint.clone();
        let committed = mutate(env, |s| {
            let local = s.key_slots.get_mut(slot_id).ok_or_else(not_found)?;
            local.source = Some(SlotSource::SyncedCopy { fingerprint: fingerprint.clone() });
            local.copy_from_another_account = local.copy_from_another_account || !from_this_account;
            local.last_error = None;
            Ok(())
        });
        if let Err(e) = committed {
            // `mutate` 的錯誤分不出「被拒絕、什麼都沒改」與「改了、存檔失敗」:記錄還是保管庫的才收回,改成檔案了就留著。
            if still_in_vault(env, slot_id) {
                take_back();
            }
            return Err(e);
        }
        // 記錄已經是檔案了:保管庫那一筆拿不掉也只是一筆沒有記錄用到的,不影響這台用檔案連線。
        if let Err(e) = with_vault(env.runtime, &vault_file, env.keychain, now, |v| v.remove(slot_id)) {
            eprintln!("[sync] a key kept as a file again is still in SSHelter's vault: {e}");
        }
    }
    if let Err(e) = crate::agent::wiring::refresh_env(env) {
        eprintln!("[agent] could not update the agent config: {e}");
    }
    env.events.wake();
    Ok(())
}

/// 這台現在的狀態裡,這個插槽還是只在 SSHelter(`set_delivery` 的提交失敗之後判斷要不要收回剛寫的檔案)。
fn still_in_vault(env: &SyncEnv, slot_id: &str) -> bool {
    let core = env.runtime.core.lock().unwrap();
    core.state.as_ref().and_then(|s| s.key_slots.get(slot_id)).is_some_and(|l| matches!(l.source, Some(SlotSource::Vault { .. })))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sync::merge::{account_outgoing, merge_account, plan_device, set_device_slots, Outgoing};
    use crate::sync::record::{DevicePayload, Envelope, LocalRecord};
    use crate::sync::relay::PullResponse;
    use crate::sync::slot_rules::{test_keys, DeviceSlot, SlotMode, MAX_PRIVATE_KEY_BYTES};
    use crate::sync::state_v2::{AccountState, LoadedState, SyncStateV2};

    use crate::sync::dto::{ApprovalNotice, SlotStatusView, SyncConflict};
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
                    // 同 `slot_setup::create_slot`:在這個帳戶建立的。
                    learned_in: Some(keys.chain_id.clone()),
                    copy_from_another_account: false,
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
    pub(crate) fn publish(d: &TestDevice, id: &str, payload: &KeySlotPayload, secret: Option<&str>) {
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
    pub(crate) fn ecdsa_payload(origin: &str) -> KeySlotPayload {
        KeySlotPayload {
            public_key: Some(test_keys::ECDSA_PUBLIC.into()),
            fingerprint: Some(test_keys::ECDSA_FINGERPRINT.into()),
            key_type: Some("ecdsa-sha2-nistp256".into()),
            ..synced_payload(origin)
        }
    }

    pub(crate) fn own_payload(origin: &str) -> KeySlotPayload {
        KeySlotPayload { mode: SlotMode::Own, public_key: None, fingerprint: None, key_type: None, has_passphrase: None, ..synced_payload(origin) }
    }

    pub(crate) fn device_id(d: &TestDevice) -> String {
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

    /// 直接呼叫 `reconcile` 的測試只改狀態的副本、不改檔案:除了狀態裡勾選的 space,當成 config 裡沒有別的主機用到插槽。
    const NO_OTHER_HOSTS: BTreeMap<String, Vec<String>> = BTreeMap::new();

    /// 這台的插槽檢視(同 overview:整份 config 裡用到的插槽一起算)。
    fn view_of(d: &TestDevice) -> Vec<SyncKeySlotView> {
        views(&d.state(), &account_keys(d), &home(d), &config_slot_uses(&d.env()).expect("config loaded"))
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

        let b_view = view_of(&b);
        assert_eq!(b_view.len(), 1);
        assert_eq!(b_view[0].hosts, vec!["web".to_string()]);
        assert_eq!(b_view[0].origin_device, "MacBook-A");
        assert!(!b_view[0].origin_is_this);
        assert!(matches!(b_view[0].status, SlotStatusView::Ready { synced_copy: true, .. }), "{:?}", b_view[0].status);
        assert_eq!(crate::sync::dto::overview(&b.env()).unwrap().key_slots, b_view);

        // A 收到 B 的 `device.slots`。
        settle(&a);
        let a_view = view_of(&a);
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
        let view = view_of(&b);
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
        let view = view_of(&b);
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
        let view = view_of(&b);
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

        let view = view_of(&a);
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
    // 一個檔案是不是 SSHelter 放的,只看這個插槽 id 自己的本機記錄,不看檔名;同檔名的插槽,只有這台已經握著的那個照常維護。

    #[test]
    fn two_slots_with_the_same_file_name_never_overwrite_each_others_copy() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (first, second) = (format!("3fa2c1d9{}", "0".repeat(24)), format!("3fa2c1d9{}", "f".repeat(24)));
        let file = slot_file_name("id_mac", &first);
        assert_eq!(file, slot_file_name("id_mac", &second));
        let me = device_id(&a);
        // 第一個先落地,同檔名的第二個之後才出現。
        publish(&a, &first, &synced_payload(&me), Some(&test_keys::plain()));
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        publish(&a, &second, &ecdsa_payload(&me), Some(&test_keys::ecdsa()));
        settle(&a);
        settle(&b);

        let landed = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&landed).unwrap(), test_keys::plain(), "the one this computer holds keeps the path");
        let state = b.state();
        assert_eq!(state.key_slots[&first].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
        assert_eq!(state.key_slots[&second].source, None);
        assert_eq!(state.key_slots[&second].last_error, Some(CONTESTED_MESSAGE.to_string()));

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
        assert_eq!(a.state().key_slots[&other].last_error, Some(CONTESTED_MESSAGE.to_string()));

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
    fn a_member_slot_with_the_same_file_name_never_lands_where_an_active_link_is() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (x, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        write_linked_public(&path, &source).unwrap(); // 建立插槽時寫的 `.pub`(Task 5 的 setup 做的事)
        use_slot(&a, &personal, &file);
        settle(&a);
        // 帳戶裡的成員發佈同名、同 id 前 8 字元、排在 X 前面的 Z,以他自己的金鑰同步。
        let z = format!("{}{}", &x[..8], "0".repeat(24));
        assert!(z < x && slot_file_name("id_mac", &z) == file);
        publish(&a, &z, &ecdsa_payload("a-member"), Some(&test_keys::ecdsa()));
        settle(&a);

        let check = |when: &str| {
            let state = a.state();
            // Z 不落地;它的列只說它在這台不能用,不叫使用者把 X 的連結移開。
            assert_eq!(state.key_slots.get(&z).and_then(|l| l.source.clone()), None, "{when}: Z never lands");
            let shown = view_of(&a);
            let status_of = |id: &str| shown.iter().find(|v| v.id == id).unwrap().status.clone();
            assert_eq!(status_of(&z), SlotStatusView::Error { message: CONTESTED_MESSAGE.into() }, "{when}");
            // X 照常連到自己的金鑰。
            assert!(matches!(status_of(&x), SlotStatusView::Ready { synced_copy: false, .. }), "{when}: {:?}", status_of(&x));
            assert_eq!(std::fs::read_link(&path).ok(), Some(source.clone()), "{when}: X's own link");
            // 插槽路徑上沒有成員的任何東西:私鑰與 `.pub` 都是 X 的。
            assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::plain(), "{when}");
            assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC), "{when}");
            let listed: Vec<String> = device_slots_seen_by(&a, &a).into_iter().map(|d| d.slot_id).collect();
            assert_eq!(listed, vec![x.clone()], "{when}");
            assert!(state.notices.is_empty(), "{when}: nobody is asked for a key");
        };
        check("after Z was published");

        // 使用者還是把 X 的連結移開了(舊版的擋路訊息就是這麼說的):X 重新連結,Z 仍然不落地。
        std::fs::remove_file(&path).unwrap();
        settle(&a);
        check("after X's link was moved away");
    }

    #[test]
    fn a_slot_this_computer_holds_keeps_working_when_another_slot_takes_its_file_name() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (x, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        // A 連到原檔、B 有同步來的副本;之後帳戶裡的成員發佈同名、同 id 前 8 字元、排在 X 前面的 Z(以他自己的金鑰同步)。
        let z = format!("{}{}", &x[..8], "0".repeat(24));
        publish(&a, &z, &ecdsa_payload("a-member"), Some(&test_keys::ecdsa()));
        settle(&a);
        settle(&b);
        let status_of = |d: &TestDevice, id: &str| view_of(d).into_iter().find(|v| v.id == id).unwrap().status;
        for d in [&a, &b] {
            let state = d.state();
            assert!(matches!(status_of(d, &x), SlotStatusView::Ready { .. }), "{:?}", status_of(d, &x));
            assert_eq!(status_of(d, &z), SlotStatusView::Error { message: CONTESTED_MESSAGE.into() });
            assert!(!contested_and_not_held(&state, &x) && contested_and_not_held(&state, &z));
            assert_eq!(std::fs::read_to_string(home(d).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
        }

        // B 的副本被刪掉了:握著它的 X 照常放回自己的金鑰,Z 還是不落地。
        let copy = home(&b).join(SLOT_DIR).join(&file);
        std::fs::remove_file(&copy).unwrap();
        std::fs::remove_file(public_path(&copy)).unwrap();
        settle(&b);
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain());
        assert_eq!(std::fs::read_to_string(public_path(&copy)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        assert_eq!(b.state().key_slots[&x].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
        assert_eq!(b.state().key_slots.get(&z).and_then(|l| l.source.clone()), None);

        // A 的連結收起來過(暫時沒有主機用到)也還是握著:又用到時重新連結。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        let link = home(&a).join(SLOT_DIR).join(&file);
        assert!(a.state().key_slots[&x].parked && !slot_files::occupied(&link));
        assert!(!contested_and_not_held(&a.state(), &x), "a parked link is still held");
        use_slot(&a, &personal, &file);
        settle(&a);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain());
        assert!(!a.state().key_slots[&x].parked);
        assert!(matches!(status_of(&a, &x), SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", status_of(&a, &x));
        assert_eq!(status_of(&a, &z), SlotStatusView::Error { message: CONTESTED_MESSAGE.into() });
    }

    #[test]
    fn slots_that_share_a_file_name_and_are_not_held_here_are_not_used_and_nobody_is_asked() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let me = device_id(&a);
        // 兩對同名、同 id 前 8 字元的插槽,A、B 都還沒有握著任何一個:`synced` 的兩個都帶著金鑰,`own` 的兩個等這台挑。
        let (s1, s2) = (format!("3fa2c1d9{}", "0".repeat(24)), format!("3fa2c1d9{}", "f".repeat(24)));
        let (o1, o2) = (format!("5be0a7c3{}", "0".repeat(24)), format!("5be0a7c3{}", "f".repeat(24)));
        publish(&a, &s1, &synced_payload(&me), Some(&test_keys::plain()));
        publish(&a, &s2, &ecdsa_payload(&me), Some(&test_keys::ecdsa()));
        for o in [&o1, &o2] {
            publish(&a, o, &KeySlotPayload { name: "work".into(), ..own_payload(&me) }, None);
        }
        let (synced_file, own_file) = (slot_file_name("id_mac", &s1), slot_file_name("work", &o1));
        assert!(synced_file == slot_file_name("id_mac", &s2) && own_file == slot_file_name("work", &o2));
        use_slots(&a, &personal, &[&synced_file, &own_file]);
        settle(&a);
        settle(&b);

        let contested_row = SlotStatusView::Error { message: CONTESTED_MESSAGE.into() };
        for d in [&a, &b] {
            for file in [&synced_file, &own_file] {
                let path = home(d).join(SLOT_DIR).join(file);
                assert!(!slot_files::occupied(&path) && !slot_files::occupied(&public_path(&path)), "nothing lands at {file}");
            }
            let state = d.state();
            let shown = view_of(d);
            assert_eq!(shown.len(), 4);
            assert!(shown.iter().all(|v| v.status == contested_row), "{shown:?}");
            assert!([&s1, &s2, &o1, &o2].iter().all(|id| contested_and_not_held(&state, id)));
            assert!(state.key_slots.values().all(|l| l.source.is_none() && !l.asked && l.last_error.as_deref() == Some(CONTESTED_MESSAGE)));
            assert!(state.notices.is_empty() && d.events.notices.lock().unwrap().is_empty(), "nobody is asked for a key");
            assert_eq!(device_slots_seen_by(d, d), Vec::new());
        }

        // 沒有主機用到了:還是說明它們在這台不能用;沒有東西要記。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        settle(&b);
        for d in [&a, &b] {
            assert!(view_of(d).iter().all(|v| v.status == contested_row), "{:?}", view_of(d));
            assert!(d.state().key_slots.is_empty());
        }
        // 帳戶裡沒有的插槽不算。
        assert!(!contested_and_not_held(&a.state(), "ffffffffffffffffffffffffffffffff"));
    }

    #[test]
    fn file_names_that_differ_only_in_case_count_as_the_same_file_name() {
        // macOS 與 Windows 的檔案系統預設不分大小寫:`ID_MAC-<id8>` 和 `id_mac-<id8>` 在那裡是同一個檔案。
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (x, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        // 帳戶裡的成員發佈只差大小寫的 Z(以他自己的金鑰同步),也讓主機用這個寫法。
        let z = format!("{}{}", &x[..8], "0".repeat(24));
        let z_file = slot_file_name("ID_MAC", &z);
        assert!(z_file != file && z_file.eq_ignore_ascii_case(&file));
        publish(&a, &z, &KeySlotPayload { name: "ID_MAC".into(), ..ecdsa_payload("a-member") }, Some(&test_keys::ecdsa()));
        use_slots(&a, &personal, &[&file, &z_file]);
        settle(&a);
        // 使用者把 X 的連結移開了一下:X 重新連結,Z 仍然不落地(不分大小寫的檔案系統上,Z 的路徑就是 X 的路徑)。
        let keys_dir = home(&a).join(SLOT_DIR);
        std::fs::remove_file(keys_dir.join(&file)).unwrap();
        settle(&a);

        let state = a.state();
        let shown = view_of(&a);
        let status_of = |id: &str| shown.iter().find(|v| v.id == id).unwrap().status.clone();
        assert_eq!(status_of(&z), SlotStatusView::Error { message: CONTESTED_MESSAGE.into() });
        assert_eq!(state.key_slots[&z].last_error.as_deref(), Some(CONTESTED_MESSAGE));
        assert_eq!(state.key_slots[&z].source, None, "Z never lands");
        assert!(matches!(status_of(&x), SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", status_of(&x));
        assert_eq!(std::fs::read_to_string(keys_dir.join(&file)).unwrap(), test_keys::plain());
        assert_ne!(std::fs::read_to_string(keys_dir.join(&z_file)).ok(), Some(test_keys::ecdsa()), "the member's key is under neither spelling");
        assert!(contested_and_not_held(&state, &z) && !contested_and_not_held(&state, &x));
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
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        write_linked_public(&path, &source).unwrap(); // 建立插槽時寫的 `.pub`(Task 5 的 setup 做的事)
        use_slot(&a, &personal, &file);
        settle(&a);
        assert!(slot_files::occupied(&public_path(&path)), "the slot has its own .pub while it is linked");
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        assert!(!slot_files::occupied(&path), "the link file is gone");
        assert!(!slot_files::occupied(&public_path(&path)), "and so is its .pub: nothing of this slot is left at an empty path");
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

    /// 帳戶快取裡沒有了這個插槽的兩筆記錄(沒有 SP3 的電腦更換了同步碼:新帳戶裡沒有它們)。
    fn the_account_loses(d: &TestDevice, id: &str) {
        let keys = account_keys(d);
        mutate(&d.env(), |s| {
            let account = s.account.as_mut().unwrap();
            account.records.remove(&record_key(RecordKind::KeySlot, id));
            account.sealed.remove(&key_secret_key(&keys, id));
            Ok(())
        })
        .unwrap();
    }

    /// 收起來的 X(`a_parked_slot`)的路徑上,放著帳戶裡成員的 Z:同名、同 id 前 8 字元、排在 X 前面,以成員自己的 ecdsa 金鑰同步。
    /// X 和 Z 同時在帳戶裡時,這台握著 X(收起來的也算),Z 根本不落地;Z 只在帳戶暫時沒有 X 的那一輪(沒有 SP3 的電腦更換了同步碼)
    /// 放得進空著的路徑,這台隨後補寫 X。回傳(A、Personal 的 id、X、Z、插槽檔名)。
    fn a_member_slot_at_a_parked_path(hard_link: bool) -> (TestDevice, String, String, String, String) {
        let (a, personal, x, file) = a_parked_slot(hard_link);
        let z = format!("{}{}", &x[..8], "0".repeat(24));
        assert!(z < x && slot_file_name("id_mac", &z) == file);
        the_account_loses(&a, &x);
        publish(&a, &z, &ecdsa_payload("a-member"), Some(&test_keys::ecdsa()));
        use_slot(&a, &personal, &file);
        settle(&a);
        let state = a.state();
        assert!(slot(state.account.as_ref().unwrap(), &x).is_some(), "hard_link={hard_link}: this computer wrote X again");
        assert_eq!(state.key_slots[&z].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::ECDSA_FINGERPRINT.into() }));
        (a, personal, x, z, file)
    }

    #[test]
    fn a_member_cannot_make_a_parked_link_relink_over_another_slots_copy() {
        for hard_link in [false, true] {
            let (a, _personal, x, z, file) = a_member_slot_at_a_parked_path(hard_link);
            let path = home(&a).join(SLOT_DIR).join(&file);

            // Z 在空著的路徑上;X 不能再連結蓋過去,也不能被當成放著自己的金鑰。
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
            reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 1_000);
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
        assert!(reconcile(&mut state, &keys, &home(&b), &NO_OTHER_HOSTS, 1_000).changed);
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
    fn a_linked_slots_pub_file_is_never_left_over_from_another_slot() {
        for hard_link in [false, true] {
            // 成員的 Z 放進了收起來的 X 空著的路徑,連旁邊的 `.pub` 也是它的。
            let (a, _personal, x, z, file) = a_member_slot_at_a_parked_path(hard_link);
            let path = home(&a).join(SLOT_DIR).join(&file);
            let pub_path = public_path(&path);
            assert_eq!(std::fs::read_to_string(&pub_path).unwrap(), format!("{}\n", test_keys::ECDSA_PUBLIC), "Z landed with its own .pub");
            assert_eq!(a.state().key_slots[&x].last_error, Some(in_the_way_message(&path)));

            // 成員刪掉 Z;使用者照訊息把擋路的檔案移走(Z 的 `.pub` 留在原地)。
            unpublish(&a, &z);
            settle(&a);
            std::fs::remove_file(&path).unwrap();
            settle(&a);

            // X 重新連結:`.pub` 是 X 自己這把金鑰的,不是成員的 —— `ssh-copy-id -i <slot>` 送出去的就是它。
            let local = a.state().key_slots[&x].clone();
            assert!(!local.parked && local.last_error.is_none(), "hard_link={hard_link}: {local:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::plain());
            assert_eq!(std::fs::read_to_string(&pub_path).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC), "hard_link={hard_link}");
        }
    }

    #[test]
    fn parking_removes_the_pub_file_with_the_link_but_not_beside_a_users_file() {
        // 連結和它的 `.pub` 一起拿掉(`a_parked_slot` 檢查過了,這裡把兩種連結種類的結果再寫明一次)。
        for hard_link in [false, true] {
            let (a, _personal, _id, file) = a_parked_slot(hard_link);
            assert!(!slot_files::occupied(&public_path(&home(&a).join(SLOT_DIR).join(&file))), "hard_link={hard_link}");
        }
        // 使用者把 symlink 換成自己的檔案:那是使用者的,旁邊的 `.pub` 也不碰。
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        write_linked_public(&path, &source).unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "mine").unwrap();
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        assert!(a.state().key_slots[&id].parked);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "mine");
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));

        // 連結已經不在了(使用者自己刪掉的),旁邊有個 `.pub`:沒有拿掉任何連結,那個 `.pub` 不能確定是這個插槽的,不碰。
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        write_linked_public(&path, &source).unwrap();
        std::fs::remove_file(&path).unwrap();
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        assert!(a.state().key_slots[&id].parked && !slot_files::occupied(&path));
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
    }

    #[test]
    fn a_relink_after_the_original_was_replaced_rewrites_the_pub_file_from_the_new_key() {
        for kind in [LinkKind::HardLink, LinkKind::Copy] {
            let (_relay, _clock, a, _b, _words, personal) = pair();
            let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
            let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
            // 這台是 Windows 的情形(在 Unix 上手動做出來):插槽是原檔的 hard link 或複製,旁邊是這把金鑰的 `.pub`。
            std::fs::remove_file(&path).unwrap();
            match kind {
                LinkKind::HardLink => std::fs::hard_link(&source, &path).unwrap(),
                _ => {
                    std::fs::copy(&source, &path).unwrap();
                }
            }
            mutate(&a.env(), |s| {
                if let Some(SlotSource::Linked { link, .. }) = s.key_slots.get_mut(&id).and_then(|l| l.source.as_mut()) {
                    *link = kind;
                }
                Ok(())
            })
            .unwrap();
            write_linked_public(&path, &source).unwrap();
            use_slot(&a, &personal, &file);
            settle(&a);
            assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC), "{kind:?}");

            // 原檔被換成另一把(寫新檔再 rename):hard link 與複製不會跟著走,下一輪重新連結,`.pub` 跟著換成新的這把。
            std::fs::write(a.ssh_dir().join("id_mac.new"), test_keys::ecdsa()).unwrap();
            std::fs::rename(a.ssh_dir().join("id_mac.new"), &source).unwrap();
            settle(&a);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa(), "{kind:?}: relinked");
            assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::ECDSA_PUBLIC), "{kind:?}");
        }
    }

    #[test]
    fn a_linked_key_whose_public_half_cannot_be_derived_gets_no_pub_file_unless_it_has_its_own() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let pem = format!("{}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n{}\n", concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), concat!("-----END RSA ", "PRIVATE KEY-----"));
        let (id, file) = create_slot_on(&a, SlotMode::Own, &pem, "id_old");
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_old"));
        let stop_using = || {
            a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
            settle(&a);
        };
        use_slot(&a, &personal, &file);
        settle(&a);
        stop_using();
        assert!(a.state().key_slots[&id].parked);

        // 別的插槽留在這個位置的 `.pub`;重新連結時推不出這把金鑰的公鑰、原檔旁邊也沒有 `.pub`:不留 `.pub`(沒有比錯的好)。
        slot_files::write_public(&path, test_keys::ECDSA_PUBLIC).unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        assert!(!a.state().key_slots[&id].parked && a.state().key_slots[&id].last_error.is_none());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), pem);
        assert!(!slot_files::occupied(&public_path(&path)), "no .pub is better than another slot's");

        // 原檔旁邊有自己的 `.pub`:下一次連結時用它的第一行(正規化,不帶 comment)。
        std::fs::write(public_path(&source), format!("{} me@host\n", test_keys::PLAIN_PUBLIC)).unwrap();
        stop_using();
        use_slot(&a, &personal, &file);
        settle(&a);
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
    }

    #[test]
    fn write_linked_public_takes_the_public_half_only_from_the_linked_key() {
        let dir = tempfile::tempdir().unwrap();
        let (slot, key) = (dir.path().join("slot-3fa2c1d9"), dir.path().join("id_mac"));
        let pub_of = |p: &Path| std::fs::read_to_string(public_path(p)).ok();
        let line = |public: &str| Some(format!("{public}\n"));
        let pem = format!("{}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n{}\n", concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), concat!("-----END RSA ", "PRIVATE KEY-----"));

        // OpenSSH 私鑰:公鑰從私鑰推出,蓋掉別人放的 `.pub`;原檔旁邊的 `.pub`(這裡故意放別把的)不看。
        std::fs::write(&key, test_keys::plain()).unwrap();
        std::fs::write(public_path(&key), format!("{} lies\n", test_keys::ECDSA_PUBLIC)).unwrap();
        slot_files::write_public(&slot, test_keys::ECDSA_PUBLIC).unwrap();
        write_linked_public(&slot, &key).unwrap();
        assert_eq!(pub_of(&slot), line(test_keys::PLAIN_PUBLIC));
        // 有 passphrase 的 OpenSSH 私鑰也推得出來(公鑰段不加密)。
        std::fs::write(&key, test_keys::encrypted()).unwrap();
        write_linked_public(&slot, &key).unwrap();
        assert_eq!(pub_of(&slot), line(test_keys::ENC_PUBLIC));
        // 舊式 PEM:用原檔旁邊 `.pub` 的第一行(正規化:不帶 comment、不帶第二行)。
        std::fs::write(&key, &pem).unwrap();
        std::fs::write(public_path(&key), format!("{} me@host\n{}\n", test_keys::PLAIN_PUBLIC, test_keys::ECDSA_PUBLIC)).unwrap();
        write_linked_public(&slot, &key).unwrap();
        assert_eq!(pub_of(&slot), line(test_keys::PLAIN_PUBLIC));
        // 原檔旁邊的 `.pub` 讀不懂、沒有、原檔不見:拿掉 `<slot>.pub`;沒有東西可拿掉不是錯誤。
        std::fs::write(public_path(&key), "garbage\n").unwrap();
        write_linked_public(&slot, &key).unwrap();
        assert_eq!(pub_of(&slot), None, "an unreadable .pub beside the key");
        slot_files::write_public(&slot, test_keys::ECDSA_PUBLIC).unwrap();
        std::fs::remove_file(public_path(&key)).unwrap();
        write_linked_public(&slot, &key).unwrap();
        assert_eq!(pub_of(&slot), None, "no .pub beside the key");
        slot_files::write_public(&slot, test_keys::ECDSA_PUBLIC).unwrap();
        std::fs::remove_file(&key).unwrap();
        write_linked_public(&slot, &key).unwrap();
        assert_eq!(pub_of(&slot), None, "no key at all");
        write_linked_public(&slot, &key).unwrap();
    }

    #[test]
    fn a_quiet_round_does_not_rewrite_a_linked_slots_pub_file() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (_id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        let path = home(&a).join(SLOT_DIR).join(&file);
        use_slot(&a, &personal, &file);
        settle(&a);
        // 使用者自己放的 `.pub`(例如帶 comment):沒有連結、重新連結或認回的事件就不重寫它。
        let theirs = format!("{} me@host\n", test_keys::PLAIN_PUBLIC);
        std::fs::write(public_path(&path), &theirs).unwrap();
        settle(&a);
        settle(&a);
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), theirs);
    }

    #[test]
    #[cfg(unix)]
    fn a_parked_link_that_was_made_again_before_the_state_was_saved_is_recognised() {
        let (a, personal, id, file) = a_parked_slot(false);
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        // 上一輪重新連結了、狀態卻沒存下來(`commit` 被搶先):路徑上正好是連結會做出來的 symlink,就是這個插槽自己的。
        std::os::unix::fs::symlink(&source, &path).unwrap();
        slot_files::write_public(&path, test_keys::ECDSA_PUBLIC).unwrap(); // 別人留在這裡的 `.pub`
        use_slot(&a, &personal, &file);
        settle(&a);
        let local = a.state().key_slots[&id].clone();
        assert!(!local.parked && local.last_error.is_none(), "{local:?}");
        assert_eq!(std::fs::read_link(&path).unwrap(), source);
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC), "recognising the link rewrites the .pub too");
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

    #[test]
    #[cfg(unix)]
    fn a_link_replaced_by_another_file_while_in_use_is_in_the_way_until_it_is_back() {
        for foreign_symlink in [false, true] {
            let what = format!("foreign_symlink={foreign_symlink}");
            let (_relay, _clock, a, _b, _words, personal) = pair();
            let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
            let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
            write_linked_public(&path, &source).unwrap();
            use_slot(&a, &personal, &file);
            settle(&a);
            assert_eq!(device_slots_seen_by(&a, &a).len(), 1);

            // 主機還用著,插槽上的 symlink 被換成了別的東西(一般檔案,或指到另一把金鑰的 symlink),旁邊的 `.pub` 也換了。
            let other = a.ssh_dir().join("id_work");
            std::fs::write(&other, test_keys::ecdsa()).unwrap();
            std::fs::remove_file(&path).unwrap();
            if foreign_symlink {
                std::os::unix::fs::symlink(&other, &path).unwrap();
            } else {
                std::fs::write(&path, test_keys::ecdsa()).unwrap();
            }
            slot_files::write_public(&path, test_keys::ECDSA_PUBLIC).unwrap();
            let untouched = |when: &str| {
                assert_eq!(std::fs::symlink_metadata(&path).ok().map(|m| m.file_type().is_symlink()), Some(foreign_symlink), "{what} {when}");
                if foreign_symlink {
                    assert_eq!(std::fs::read_link(&path).unwrap(), other, "{what} {when}");
                }
                assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa(), "{what} {when}");
                assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::ECDSA_PUBLIC), "{what} {when}");
            };
            settle(&a);
            settle(&a);

            // 不是 Ready:擋路,不列在 `device.slots`,檔案不動。
            assert_eq!(a.state().key_slots[&id].last_error, Some(in_the_way_message(&path)), "{what}");
            assert_eq!(view_of(&a)[0].status, SlotStatusView::Error { message: in_the_way_message(&path) }, "{what}");
            assert_eq!(device_slots_seen_by(&a, &a), Vec::new(), "{what}: the slot doesn't hold this computer's key");
            untouched("in the way");
            // 主機暫時不用、再用到:那個檔案一樣不動,一樣擋路。
            a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
            settle(&a);
            untouched("unused");
            use_slot(&a, &personal, &file);
            settle(&a);
            untouched("used again");
            assert_eq!(a.state().key_slots[&id].last_error, Some(in_the_way_message(&path)), "{what}");

            // 使用者把連結放回來:又是 Ready、列回 `device.slots`,旁邊的 `.pub` 從這把金鑰重寫。
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&source, &path).unwrap();
            settle(&a);
            let local = a.state().key_slots[&id].clone();
            assert!(local.last_error.is_none() && !local.parked, "{what}: {local:?}");
            assert!(matches!(view_of(&a)[0].status, SlotStatusView::Ready { synced_copy: false, .. }), "{what}: {:?}", view_of(&a)[0].status);
            assert_eq!(device_slots_seen_by(&a, &a).len(), 1, "{what}");
            assert_eq!(std::fs::read_link(&path).unwrap(), source, "{what}");
            assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC), "{what}");
        }
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
        write_linked_public(&link, &a.ssh_dir().join("id_mac")).unwrap();
        let linked = a.state().key_slots[&id].clone();
        assert!(matches!(&linked.source, Some(SlotSource::Linked { origin: true, .. })));

        // 主機的 `IdentityFile` 暫時拿掉(例如編輯到一半存檔)。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        assert!(!slot_files::occupied(&link), "the link file is removed");
        assert!(!slot_files::occupied(&public_path(&link)), "and the .pub that went with it");
        assert_eq!(a.state().key_slots[&id], LocalSlot { parked: true, ..linked.clone() }, "the record is kept, marked as parked");
        assert_eq!(view_of(&a)[0].status, SlotStatusView::NotUsedHere);
        assert_eq!(device_slots_seen_by(&a, &a), Vec::new());
        // 收起來之後什麼都沒變的一輪:不寫新版本、不要求提交。
        let keys = account_keys(&a);
        let mut state = a.state();
        let before = state.clone();
        let quiet = reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 9_000);
        assert!(!quiet.changed && quiet.notices.is_empty());
        assert_eq!(state, before);

        // 又用到了:重新連結,記錄(含 `origin`)不變,沒有人被問。
        use_slot(&a, &personal, &file);
        settle(&a);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain());
        assert_eq!(std::fs::read_to_string(public_path(&link)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC), "the .pub is written again, from the key itself");
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

    // ── 不在勾選的 space 裡的主機也算用到插槽(spec §4.2:沒有任何主機用到才移除連結)──────────────────────────────

    /// Personal 裡用到插槽的 `web` 與另一台主機 `db`。
    fn web_and_db(file: &str) -> (String, String) {
        let web = format!("Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/sshelter/keys/{file}\n");
        (format!("{web}\nHost db\n  HostName 10.0.0.2\n"), web)
    }

    /// 在 app 裡把 `web` 用「Move to file」搬到主 config:Personal 只剩 `db`,`web` 接在主 config 後面。
    fn move_web_to_the_main_config(d: &TestDevice, personal: &str, web: &str) {
        d.save_in_app(&d.space_path(personal), "Host db\n  HostName 10.0.0.2\n");
        d.save_in_app(&d.main_path(), &format!("{}\n{web}", d.main_config()));
    }

    /// 用到插槽的主機搬出 space、到主 config(space 裡還有別的主機):這台仍有主機用到插槽 —— 連結留著、不收起來,Keys 是 Ready 並列出
    /// 那台主機(不是「Not used on this computer」,lint 也不會叫使用者去 Keys 挑金鑰);之後在 Keys 換的金鑰,下一輪也不會被收掉。
    #[test]
    fn a_host_moved_out_of_its_space_keeps_its_slot_linked() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        let (both, web) = web_and_db(&file);
        a.save_in_app(&a.space_path(&personal), &both);
        settle(&a);
        move_web_to_the_main_config(&a, &personal, &web);
        settle(&a);

        let link = home(&a).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain(), "the host in the main config still reaches its key");
        assert!(!a.state().key_slots[&id].parked);
        let row = view_of(&a).remove(0);
        assert!(matches!(row.status, SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", row.status);
        assert_eq!(row.hosts, vec!["web".to_string()]);
        assert!(row.in_account);
        assert_eq!(device_slots_seen_by(&a, &a).len(), 1, "the link is in place, so this computer's device record lists it");

        // 在 Keys 換一把金鑰(Change…):下一輪照樣留著。
        let other = a.ssh_dir().join("id_other");
        std::fs::write(&other, test_keys::ecdsa()).unwrap();
        pick(&a.env(), &id, &other.display().to_string()).unwrap();
        settle(&a);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::ecdsa(), "the pick is not undone");
        assert!(!a.state().key_slots[&id].parked);
    }

    /// 離開帳戶、再建立一個新帳戶:新帳戶裡沒有這個插槽,搬到 `~/.ssh/sshelter-local/` 的主機還用著它 —— 連結與記錄留著(那些主機照常能連線),
    /// Keys 有它的一列,不能刪除(spec §4.2「離開同步帳戶:插槽目錄原樣保留」)。
    #[test]
    fn hosts_kept_on_this_computer_keep_their_slot_when_a_new_account_is_created() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        crate::sync::account::leave_account(&a.env(), false).unwrap();
        crate::sync::account::create_account(&a.env(), "MacBook-A").unwrap();
        settle(&a);

        let link = home(&a).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain(), "the hosts in sshelter-local still reach their key");
        assert!(a.state().key_slots.contains_key(&id), "the record of the link is kept");
        let rows = view_of(&a);
        let row = rows.iter().find(|r| r.id == id).expect("the Keys dialog lists the slot");
        assert!(matches!(row.status, SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", row.status);
        assert_eq!(row.hosts, vec!["web".to_string()]);
        assert!(!row.in_account, "the new account has no such slot: nothing to sync or pick for it");
        refused(&a, IN_USE_MESSAGE, || delete_copy(&a.env(), &id));
        // 不在任何 space 裡的主機不會讓插槽被補寫進新帳戶(只有勾選的 space 用到的才補寫,spec §6.6)。
        assert!(!slot_record_exists(a.state().account.as_ref().unwrap(), &id));
    }

    /// 離開帳戶、再用同一個同步碼加入,還沒勾選 space:搬到 `~/.ssh/sshelter-local/` 的主機還用著插槽,連結不收起來。
    #[test]
    fn hosts_kept_on_this_computer_keep_their_slot_after_joining_again() {
        let (_relay, _clock, a, _b, words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        crate::sync::account::leave_account(&a.env(), false).unwrap();
        crate::sync::account::join_account(&a.env(), &words, "MacBook-A").unwrap();
        settle(&a);

        let link = home(&a).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), test_keys::plain(), "the link stays while no space uses it yet");
        assert!(!a.state().key_slots[&id].parked);
        let row = view_of(&a).remove(0);
        assert!(matches!(row.status, SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", row.status);
    }

    /// 有同步副本的電腦把用到它的主機搬出 space、到主 config:副本仍有主機用到 —— 不是 Not in use,Delete copy 拒絕,副本留著。
    #[test]
    fn a_synced_copy_a_host_outside_the_spaces_uses_cannot_be_deleted() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let (both, web) = web_and_db(&file);
        a.save_in_app(&a.space_path(&personal), &both);
        settle(&a);
        settle(&b);
        let copy = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain());

        move_web_to_the_main_config(&b, &personal, &web);
        settle(&b);
        let row = view_of(&b).remove(0);
        assert!(matches!(row.status, SlotStatusView::Ready { synced_copy: true, .. }), "{:?}", row.status);
        assert_eq!(row.hosts, vec!["web".to_string()]);
        refused(&b, IN_USE_MESSAGE, || delete_copy(&b.env(), &id));
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain(), "the copy web uses is still there");
    }

    // ── 離開之後換到另一個帳戶:在之前的帳戶學到的插槽不帶過去(N1)──────────────────────────────────────────

    /// `d` 離開帳戶,和 `other` 一起換到另一個帳戶,兩台都勾選它的 Personal 並同步完:`join` = `other` 建立、`d` 加入;否則 `d` 建立、
    /// `other` 加入。回傳(新帳戶的 Personal、新帳戶的帳戶金鑰)。
    pub(crate) fn move_to_another_account(d: &TestDevice, other: &TestDevice, join: bool) -> (String, ChainKeys) {
        let name = d.state().device_name;
        crate::sync::account::leave_account(&d.env(), false).unwrap();
        let (creator, creator_name, joiner, joiner_name) =
            if join { (other, "MacBook-C", d, name.as_str()) } else { (d, name.as_str(), other, "MacBook-C") };
        let words = crate::sync::account::create_account(&creator.env(), creator_name).unwrap();
        settle(creator);
        let personal = creator.state().spaces.keys().next().unwrap().clone();
        crate::sync::account::join_account(&joiner.env(), &words, joiner_name).unwrap();
        crate::sync::spaces::select_space(&joiner.env(), &personal).unwrap();
        settle(joiner);
        settle(creator);
        (personal, account_keys(d))
    }

    /// 搬移精靈(「搬進一個 space」)把 `~/.ssh/sshelter-local/` 裡的 `web` 搬進 `space`,同步完。
    pub(crate) fn move_web_into(d: &TestDevice, space: &str) {
        let report = crate::sync::migrate::move_hosts_into_space(&d.env(), true, vec!["web".to_string()], space, false).unwrap();
        assert_eq!(report.moved, vec!["web".to_string()]);
        settle(d);
    }

    /// relay 上一個帳戶 chain 的內容(以那個帳戶的金鑰讀)。
    pub(crate) fn account_on_relay(relay: &crate::sync::fake_relay::FakeRelay, keys: &ChainKeys) -> AccountState {
        use crate::sync::relay::RelayApi;
        merge_account(&AccountState::new(&keys.chain_id), keys, &relay.pull(&keys.chain_id, &keys.auth_token, 0).unwrap()).section
    }

    /// 插槽 `id_mac` 在帳戶 A 裡是同步的:A 連到自己的金鑰(使用者在這台選了同步它),B 有同步來的副本。其中一台(`origin` = A,否則 B)離開 A、
    /// 換到另一個帳戶(`join` = 加入別人建立的,否則自己建立),再用搬移精靈把 `~/.ssh/sshelter-local/` 裡用到這個插槽的 `web` 搬進新帳戶的 space
    /// (這個插槽路徑現在是金鑰的候選,「Sync key」對話框會問它,見 `slot_setup` 的 `KeptSlot`;但使用者沒有選擇之前什麼都不寫)。新帳戶不是 A 的
    /// 延續:插槽記錄與私鑰都不寫進新帳戶,新帳戶的另一台收到主機、收不到金鑰;這台的主機照常用這個插槽(I1),這台也不再記得在 A 裡同意過上傳。
    fn a_slot_from_the_old_account_stays_out_of_the_next_one(origin: bool, join: bool) {
        let (relay, clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let d = if origin { &a } else { &b };
        let slot_file = |t: &TestDevice| home(t).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(slot_file(d)).unwrap(), test_keys::plain());
        let c = TestDevice::new("c", &relay, &clock);
        let (next, keys) = move_to_another_account(d, &c, join);
        move_web_into(d, &next);
        settle(&c);

        assert!(c.read(&c.space_path(&next)).contains(&file), "the host reaches the other computer of the new account");
        assert!(!slot_file(&c).exists(), "but no key from the old account lands there");
        let theirs = account_on_relay(&relay, &keys);
        assert!(!slot_record_exists(&theirs, &id), "no keyslot in the new account");
        assert!(!theirs.sealed.contains_key(&key_secret_key(&keys, &id)), "no key in the new account");
        let mine = d.state();
        let account = mine.account.as_ref().unwrap();
        assert!(!slot_record_exists(account, &id) && !account.sealed.contains_key(&key_secret_key(&keys, &id)), "nothing waits to go up either");
        assert_eq!(mine.key_slots[&id].uploaded_fingerprint, None, "syncing it in the old account is no consent for the new one");
        assert_eq!(std::fs::read_to_string(slot_file(d)).unwrap(), test_keys::plain(), "web still reaches its key on this computer");
    }

    #[test]
    fn a_key_synced_in_a_left_account_is_not_uploaded_into_an_account_joined_later() {
        a_slot_from_the_old_account_stays_out_of_the_next_one(true, true);
    }

    #[test]
    fn a_key_synced_in_a_left_account_is_not_uploaded_into_an_account_created_later() {
        a_slot_from_the_old_account_stays_out_of_the_next_one(true, false);
    }

    #[test]
    fn a_synced_copy_from_a_left_account_is_not_uploaded_into_an_account_joined_later() {
        a_slot_from_the_old_account_stays_out_of_the_next_one(false, true);
    }

    #[test]
    fn a_synced_copy_from_a_left_account_is_not_uploaded_into_an_account_created_later() {
        a_slot_from_the_old_account_stays_out_of_the_next_one(false, false);
    }

    /// 換到新帳戶之後,新帳戶裡的成員發佈一個和這台留著的插槽同 id、同名的 `keyslot`(這台在新帳戶的 `device.slots` 就列著這個 id):這不讓那筆在
    /// 舊帳戶學到的記錄變成新帳戶的。新帳戶之後掉了這個插槽(例如那位成員更換同步碼時不帶它),這台也不把舊帳戶同步來的私鑰寫進去。
    #[test]
    fn a_member_of_the_next_account_cannot_make_a_slot_from_the_old_one_its_own() {
        let (relay, clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let c = TestDevice::new("c", &relay, &clock);
        let (next, keys) = move_to_another_account(&b, &c, true);
        move_web_into(&b, &next);
        publish(&c, &id, &synced_payload(&device_id(&c)), None);
        settle(&c);
        settle(&b);
        assert!(slot(b.state().account.as_ref().unwrap(), &id).is_some(), "B sees the member's slot");
        assert_eq!(b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));

        let mut state = b.state();
        let account = state.account.as_mut().unwrap();
        account.records.remove(&record_key(RecordKind::KeySlot, &id));
        account.sealed.remove(&key_secret_key(&keys, &id));
        reconcile(&mut state, &keys, &home(&b), &config_slot_uses(&b.env()).unwrap(), 1_000);
        let account = state.account.as_ref().unwrap();
        assert!(!slot_record_exists(account, &id), "nothing is written back for it");
        assert!(!account.sealed.contains_key(&key_secret_key(&keys, &id)), "the copy from the old account is never uploaded");
    }

    /// 離開帳戶 A、再以同一個同步碼加入 A、勾選 Personal:插槽在 A 裡照常(連結在、Ready、在帳戶裡、這台的 `device.slots` 列著它)。同一個帳戶的
    /// 成員還是同一批:這台在 A 裡同意上傳的那把照舊,之後帳戶掉了這個插槽(沒有 SP3 的電腦更換了同步碼)也照常補寫 `keyslot` 與 `key`。
    #[test]
    fn leaving_and_joining_the_same_account_again_keeps_the_slot_working() {
        let (_relay, _clock, a, _b, words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        crate::sync::account::leave_account(&a.env(), false).unwrap();
        crate::sync::account::join_account(&a.env(), &words, "MacBook-A").unwrap();
        crate::sync::spaces::select_space(&a.env(), &personal).unwrap();
        settle(&a);

        assert_eq!(std::fs::read_to_string(home(&a).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
        let row = view_of(&a).into_iter().find(|r| r.id == id).expect("the slot has a row");
        assert!(matches!(row.status, SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", row.status);
        assert!(row.in_account);
        assert_eq!(device_slots_seen_by(&a, &a).iter().map(|s| s.slot_id.as_str()).collect::<Vec<_>>(), vec![id.as_str()]);
        assert_eq!(
            a.state().key_slots[&id].uploaded_fingerprint.as_deref(),
            Some(test_keys::PLAIN_FINGERPRINT),
            "rejoining the same account keeps the consent"
        );

        let keys = account_keys(&a);
        let mut state = a.state();
        let account = state.account.as_mut().unwrap();
        account.records.remove(&record_key(RecordKind::KeySlot, &id));
        account.sealed.remove(&key_secret_key(&keys, &id));
        assert!(reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 1_000).changed);
        let account = state.account.as_ref().unwrap();
        assert_eq!(slot(account, &id).map(|p| p.mode), Some(SlotMode::Synced), "the keyslot is written again into the same account");
        assert_eq!(open_key_secret(account, &keys, &id).as_deref(), Some(test_keys::plain().as_str()), "and so is the key");
    }

    /// 加入帳戶時,只有學到的帳戶就是加入的那一個的記錄留著同意;不知道是在哪個帳戶學到的(這個欄位之前寫的狀態檔)當成別的帳戶的,同意清掉。
    #[test]
    fn rejoining_keeps_the_consent_only_of_records_learned_in_that_account() {
        let (_relay, _clock, a, _b, words, personal) = pair();
        let (known, known_file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let (unknown, unknown_file) = create_slot_on(&a, SlotMode::Synced, &test_keys::ecdsa(), "id_old");
        use_slots(&a, &personal, &[&known_file, &unknown_file]);
        settle(&a);
        mutate(&a.env(), |s| {
            s.key_slots.get_mut(&unknown).unwrap().learned_in = None;
            Ok(())
        })
        .unwrap();
        crate::sync::account::leave_account(&a.env(), false).unwrap();
        crate::sync::account::join_account(&a.env(), &words, "MacBook-A").unwrap();

        let state = a.state();
        assert_eq!(state.key_slots[&known].uploaded_fingerprint.as_deref(), Some(test_keys::PLAIN_FINGERPRINT), "learned in this account");
        assert_eq!(state.key_slots[&unknown].uploaded_fingerprint, None, "learned who knows where");
    }

    /// 補寫只做在這個帳戶學到的記錄(`LocalSlot::learned_in`):同樣一筆帳戶掉了、勾選的 space 還用著的記錄,學到的是別的帳戶、或不知道(這個欄位
    /// 之前寫的狀態檔)就什麼都不寫,記錄與連結照常留著;是這個帳戶才補寫。這台第一次看到插槽、落地它的同步金鑰時,記的就是這個帳戶。
    #[test]
    fn only_a_record_learned_in_this_account_is_written_back_into_it() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let chain = a.state().account.unwrap().chain_id;
        assert_eq!(b.state().key_slots[&id].learned_in.as_deref(), Some(chain.as_str()), "B saw the slot and landed its key in this account");

        let keys = account_keys(&a);
        let lost_with = |learned_in: Option<String>| {
            let mut state = a.state();
            state.key_slots.get_mut(&id).unwrap().learned_in = learned_in;
            let account = state.account.as_mut().unwrap();
            account.records.remove(&record_key(RecordKind::KeySlot, &id));
            account.sealed.remove(&key_secret_key(&keys, &id));
            reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 1_000);
            state
        };
        for elsewhere in [None, Some("b".repeat(64))] {
            let state = lost_with(elsewhere.clone());
            let account = state.account.as_ref().unwrap();
            assert!(!slot_record_exists(account, &id), "no keyslot for a record learned in {elsewhere:?}");
            assert!(!account.sealed.contains_key(&key_secret_key(&keys, &id)), "no key for a record learned in {elsewhere:?}");
            assert!(matches!(state.key_slots[&id].source, Some(SlotSource::Linked { origin: true, .. })), "the record stays");
            assert_eq!(state.key_slots[&id].learned_in, elsewhere, "and is not taken for this account's");
        }
        let state = lost_with(Some(chain));
        assert_eq!(open_key_secret(state.account.as_ref().unwrap(), &keys, &id).as_deref(), Some(test_keys::plain().as_str()));
        assert_eq!(std::fs::read_to_string(home(&a).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
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
            let round = reconcile(&mut state, &keys, &home(d), &NO_OTHER_HOSTS, 5_000);
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

        let round = reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 1_000);
        assert!(round.changed);
        let account = state.account.as_ref().unwrap();
        assert_eq!(slot(account, &id), Some(payload));
        assert!(account.records[&record_key(RecordKind::KeySlot, &id)].dirty, "it goes up with this round");
        assert_eq!(open_key_secret(account, &keys, &id).as_deref(), Some(test_keys::plain().as_str()));
        assert!(account.sealed[&key_secret_key(&keys, &id)].dirty);
        // 補寫之後的下一輪什麼都不再動。
        assert!(!reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 2_000).changed);
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
        assert!(reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 1_000).changed);
        let account = state.account.as_ref().unwrap();
        assert!(slot(account, &id).is_some(), "the keyslot is written again");
        assert!(!account.sealed.contains_key(&key_secret_key(&keys, &id)), "no key record at all");
        assert_eq!(open_key_secret(account, &keys, &id), None);

        // 同樣的狀態,只差這台的使用者選過在這裡同步這把金鑰:才補 `key`。
        let mut state = account_lost_it(Some(test_keys::PLAIN_FINGERPRINT));
        reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 2_000);
        assert_eq!(open_key_secret(state.account.as_ref().unwrap(), &keys, &id).as_deref(), Some(test_keys::plain().as_str()));
        // 選過的是另一把金鑰:連到的這把不上傳。
        let mut state = account_lost_it(Some(test_keys::ECDSA_FINGERPRINT));
        reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 3_000);
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
        assert!(reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 1_000).changed);
        let account = state.account.as_ref().unwrap();
        assert!(slot(account, &own_id).is_some());
        assert!(!account.sealed.contains_key(&key_secret_key(&keys, &own_id)));

        // `synced`、可是這台連到的金鑰已經不是記錄上的那一把:`keyslot` 補回去,不把別把金鑰當成它的 `key` 上傳。
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        let mut state = without_records(&[&id]);
        assert!(reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 2_000).changed);
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
        reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 3_000);
        assert_eq!(slot(state.account.as_ref().unwrap(), &id), None, "a deleted slot stays deleted");

        // 沒有主機用到的也不補寫,這台也不再記著它。
        let mut state = without_records(&[&own_id]);
        a_host_stops_using(&mut state, &own_file);
        reconcile(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 4_000);
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
            learned_in: None,
            copy_from_another_account: false,
        };
        let linked = |fingerprint: Option<&str>, origin: bool, link: LinkKind| SlotSource::Linked {
            path: "/h/.ssh/id_mac".into(),
            link,
            fingerprint: fingerprint.map(String::from),
            origin,
        };
        let copy = |fingerprint: &str| SlotSource::SyncedCopy { fingerprint: fingerprint.into() };
        let status = |l: Option<&LocalSlot>, p: &KeySlotPayload, needed, has_secret| slot_status(l, p, needed, needed, has_secret, &slot_path);
        let (same, other) = (test_keys::PLAIN_FINGERPRINT, test_keys::ECDSA_FINGERPRINT);

        // 錯誤優先於一切。
        let broken = local(Some(copy(same)), Some("boom"));
        assert_eq!(status(Some(&broken), &synced, true, true), SlotStatusView::Error { message: "boom".into() });
        // 還沒有東西:需要 → 等金鑰(synced 是「還沒到」、own 是「請挑」);不需要 → 這台沒用到。
        assert_eq!(status(None, &synced, true, false), SlotStatusView::NeedsKey { waiting_for_sync: true });
        assert_eq!(status(None, &own, true, false), SlotStatusView::NeedsKey { waiting_for_sync: false });
        assert_eq!(status(Some(&local(None, None)), &synced, true, true), SlotStatusView::NeedsKey { waiting_for_sync: true });
        assert_eq!(status(None, &synced, false, true), SlotStatusView::NotUsedHere);
        // 連到金鑰:指紋和同步的那把一樣 → Ready。這台上傳了目前同步的那把、之後自己的金鑰換了 → SourceChanged(不論它是不是建立插槽的
        // 那台);連到的和同步的不同、而目前同步的那把不是這台上傳的 → 可以改用同步的(建立插槽的那台也一樣:它的金鑰沒有換)。
        let origin = local(Some(linked(Some(same), true, LinkKind::Symlink)), None);
        assert_eq!(status(Some(&origin), &synced, true, true), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: Some(same.into()) });
        let uploaded = |fingerprint: &str, to: SlotSource| LocalSlot { uploaded_fingerprint: Some(fingerprint.into()), ..local(Some(to), None) };
        let changed = uploaded(same, linked(Some(other), true, LinkKind::Symlink));
        assert_eq!(status(Some(&changed), &synced, true, true), SlotStatusView::SourceChanged { file: source.clone() });
        assert_eq!(status(Some(&changed), &synced, true, false), SlotStatusView::SourceChanged { file: source.clone() }, "with or without the key record here");
        let changed_elsewhere = uploaded(same, linked(Some(other), false, LinkKind::Symlink));
        assert_eq!(status(Some(&changed_elsewhere), &synced, true, true), SlotStatusView::SourceChanged { file: source.clone() }, "the uploader need not be the origin");
        let not_uploaded = local(Some(linked(Some(other), true, LinkKind::Symlink)), None);
        assert_eq!(status(Some(&not_uploaded), &synced, true, true), SlotStatusView::SyncedAvailable { file: source.clone() }, "an origin that did not upload the synced key");
        assert_eq!(status(Some(&not_uploaded), &synced, true, false), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: Some(other.into()) });
        let uploaded_before = uploaded(other, linked(Some(other), true, LinkKind::Symlink));
        assert_eq!(status(Some(&uploaded_before), &synced, true, true), SlotStatusView::SyncedAvailable { file: source.clone() }, "it uploaded a key that is no longer the synced one");
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

        // 只有不在勾選的 space 裡的主機用到(主 config、`~/.ssh/sshelter-local/`):還是有主機用到 —— 不是 NotUsedHere / NotInUse;這台沒有金鑰時,
        // 同步的金鑰不會落地過來,要使用者挑(不是「等同步的金鑰」)。
        let outside = |l: Option<&LocalSlot>, p: &KeySlotPayload, has_secret| slot_status(l, p, false, true, has_secret, &slot_path);
        assert_eq!(outside(Some(&origin), &synced, true), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: Some(same.into()) });
        assert_eq!(outside(Some(&hard), &synced, true), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: Some(same.into()) });
        assert_eq!(outside(Some(&copied), &own, false), SlotStatusView::Ready { file: source.clone(), synced_copy: false, fingerprint: Some(same.into()) });
        assert_eq!(outside(Some(&held), &synced, true), SlotStatusView::Ready { file: here.clone(), synced_copy: true, fingerprint: Some(same.into()) });
        assert_eq!(outside(None, &synced, true), SlotStatusView::NeedsKey { waiting_for_sync: false });
        assert_eq!(outside(None, &own, false), SlotStatusView::NeedsKey { waiting_for_sync: false });
        assert_eq!(outside(Some(&changed), &synced, true), SlotStatusView::SourceChanged { file: source.clone() }, "the key comparison is the same");
    }

    #[test]
    fn every_enabled_identity_file_in_the_whole_config_counts_as_using_a_slot() {
        use crate::config::model::ConfigFile;
        use crate::fsutil::Fingerprint;
        let file = |path: &str, text: &str| ConfigFile {
            path: PathBuf::from(path),
            items: parse_file(text).0,
            trailing_newline: true,
            fingerprint: Fingerprint { mtime_ms: 0, sha256: String::new() },
        };
        let main = "IdentityFile ~/.ssh/sshelter/keys/global-11111111\nInclude sshelter-local/*\n\nHost web db\n  IdentityFile /h/.ssh/sshelter/keys/a-22222222\n  # IdentityFile ~/.ssh/sshelter/keys/comment-33333333\n\nMatch host x\n  IdentityFile %d/.ssh/sshelter/keys/m-44444444\n";
        let kept = "Host api\n  IdentityFile \"~/.ssh/sshelter/keys/a-22222222\"\n  IdentityFile ~\\.ssh\\sshelter\\keys\\b-55555555\n  IdentityFile ~/.ssh/id_mac\n  IdentityFile ~/.ssh/sshelter/keys/sub/c-66666666\n  HostName ~/.ssh/sshelter/keys/d-77777777\n";
        let mut doc = SshConfigDoc {
            files: vec![
                file("/h/.ssh/config", main),
                file("/h/.ssh/sshelter-local/personal-11111111.config", kept),
                file("/h/.ssh/extra.config", "Host off\n  IdentityFile ~/.ssh/sshelter/keys/off-88888888\n"),
            ],
        };
        // 在 app 裡停用的一行(寫出來是註解):不算。
        let Item::Host(off) = &mut doc.files[2].items[0] else { panic!("a Host block") };
        let Item::Directive(line) = &mut off.body[0] else { panic!("a directive") };
        (line.enabled, line.dirty) = (false, true);
        assert_eq!(
            config_slot_hosts(&doc, Path::new("/h")),
            BTreeMap::from([
                ("a-22222222".to_string(), vec!["api".to_string(), "web".to_string()]),
                ("b-55555555".to_string(), vec!["api".to_string()]),
                ("global-11111111".to_string(), Vec::new()),
                ("m-44444444".to_string(), Vec::new()),
            ]),
            "every file and every spelling of a slot path; a global or Match line has no alias; comments, other keys and other keywords do not count"
        );
    }

    /// 「Sync this key」「Sync the new key」上傳的是這台插槽裡的那把:檢視帶著它有沒有 passphrase(上傳之前的確認說明它),不是帳戶裡同步的那把的。
    #[test]
    fn a_slot_says_whether_the_key_this_computer_would_upload_has_a_passphrase() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (plain_id, plain_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_plain");
        let (enc_id, enc_file) = create_slot_on(&a, SlotMode::Own, &test_keys::encrypted(), "id_enc");
        let (synced_id, synced_file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_synced");
        use_slots(&a, &personal, &[&plain_file, &enc_file, &synced_file]);
        settle(&a);
        let row = |id: &str| view_of(&a).into_iter().find(|r| r.id == id).expect("a row");
        assert_eq!((row(&plain_id).has_passphrase, row(&plain_id).local_has_passphrase), (None, Some(false)));
        assert_eq!((row(&enc_id).has_passphrase, row(&enc_id).local_has_passphrase), (None, Some(true)));
        assert_eq!(row(&synced_id).local_has_passphrase, None, "nothing to upload: this key is the synced one already");

        // 同步之後原檔換成一把有 passphrase 的金鑰:「Sync the new key」說明的是新的那把,不是帳戶裡現在的那把(沒有 passphrase)。
        std::fs::write(a.ssh_dir().join("id_synced"), test_keys::encrypted()).unwrap();
        settle(&a);
        let changed = row(&synced_id);
        assert!(matches!(changed.status, SlotStatusView::SourceChanged { .. }), "{:?}", changed.status);
        assert_eq!((changed.has_passphrase, changed.local_has_passphrase), (Some(false), Some(true)));
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
                    learned_in: None,
                    copy_from_another_account: false,
                },
            );
            // 沒有 payload、或沒有放東西的記錄不顯示。
            s.key_slots.insert("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(), LocalSlot { file_name: "x-eeeeeeee".into(), source: None, last_error: None, asked: false, payload: None, uploaded_fingerprint: None, parked: false, learned_in: None, copy_from_another_account: false });
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

    // ── 使用者的動作:改成同步、停止同步、挑金鑰、改用同步的金鑰、刪除副本(SP3 Task 6)──────────────────────────

    #[test]
    fn stopping_and_restarting_sync_keeps_the_copies() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);

        set_mode(&a.env(), &id, SlotMode::Own).unwrap();
        settle(&a);
        settle(&b);
        let account = a.state().account.unwrap();
        assert_eq!(slot(&account, &id).unwrap().mode, SlotMode::Own);
        assert_eq!(open_key_secret(&account, &account_keys(&a), &id), None, "the key record is a tombstone");
        let copy = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), test_keys::plain(), "B keeps its copy and keeps using it");
        assert!(matches!(view_of(&b)[0].status, SlotStatusView::Ready { synced_copy: true, .. }));

        set_mode(&a.env(), &id, SlotMode::Synced).unwrap();
        let account = a.state().account.unwrap();
        assert_eq!(open_key_secret(&account, &account_keys(&a), &id).as_deref(), Some(test_keys::plain().as_str()));
    }

    #[test]
    fn syncing_needs_the_key_on_this_computer() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let refused = set_mode(&b.env(), &id, SlotMode::Synced).unwrap_err().to_string();
        assert_eq!(refused, not_here_message("MacBook-A"));
    }

    #[test]
    #[cfg(unix)]
    fn a_pick_wins_over_the_synced_copy_until_the_user_switches_back() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let slot_path = home(&b).join(SLOT_DIR).join(&file);

        let mine = b.ssh_dir().join("id_b");
        std::fs::write(&mine, test_keys::ecdsa()).unwrap();
        pick(&b.env(), &id, &mine.display().to_string()).unwrap();
        settle(&b);
        assert_eq!(std::fs::read_link(&slot_path).unwrap(), mine, "the slot links to B's own key");
        let kept: Vec<PathBuf> = std::fs::read_dir(slot_path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().contains(".previous-") && !p.to_string_lossy().ends_with(".pub"))
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), test_keys::plain(), "the synced copy was kept, not deleted");
        assert!(matches!(view_of(&b)[0].status, SlotStatusView::SyncedAvailable { .. }));

        use_synced(&b.env(), &id).unwrap();
        assert_eq!(std::fs::read_to_string(&slot_path).unwrap(), test_keys::plain());
        assert!(std::fs::symlink_metadata(&slot_path).unwrap().file_type().is_file());
        assert!(mine.exists(), "B's own key is untouched");
        assert_eq!(b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
    }

    #[test]
    fn only_copies_nobody_uses_can_be_deleted() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        assert_eq!(delete_copy(&b.env(), &id).unwrap_err().to_string(), IN_USE_MESSAGE);

        // A 讓主機不再用它、並刪除插槽:B 的副本變成 Not in use,可以刪。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
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
        let copy = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(view_of(&b)[0].status, SlotStatusView::NotInUse { file: copy.display().to_string() });
        delete_copy(&b.env(), &id).unwrap();
        assert!(!slot_files::occupied(&home(&b).join(SLOT_DIR).join(&file)));
        assert!(!b.state().key_slots.contains_key(&id));
        assert!(view_of(&b).is_empty());
    }

    #[test]
    fn the_origin_syncs_its_new_key_only_when_asked_and_others_keep_theirs() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        settle(&a);

        set_mode(&a.env(), &id, SlotMode::Synced).unwrap();
        let account = a.state().account.unwrap();
        assert_eq!(slot(&account, &id).unwrap().fingerprint.as_deref(), Some(test_keys::ECDSA_FINGERPRINT));
        assert_eq!(open_key_secret(&account, &account_keys(&a), &id).as_deref(), Some(test_keys::ecdsa().as_str()));
        settle(&a);
        settle(&b);
        // B 的舊副本不被自動換掉(計畫裁定 3),狀態提示可以改用。
        assert_eq!(std::fs::read_to_string(home(&b).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
        assert!(matches!(view_of(&b)[0].status, SlotStatusView::SyncedAvailable { .. }));
    }

    // ── 控制者的裁定:同意上傳、路徑上的東西是誰的、拒絕時什麼都不動、`.pub` 跟著金鑰走 ──────────────────────────

    /// `dir` 底下(遞迴)每一項的樣子:symlink 記目標、一般檔案記內容、目錄記成 `<dir>`。拒絕的動作前後,`~/.ssh` 要一個位元組都不差。
    fn tree(dir: &Path) -> BTreeMap<PathBuf, String> {
        let mut out = BTreeMap::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                out.insert(path.clone(), format!("-> {}", std::fs::read_link(&path).unwrap().display()));
            } else if meta.is_dir() {
                out.insert(path.clone(), "<dir>".to_string());
                out.extend(tree(&path));
            } else {
                out.insert(path.clone(), String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned());
            }
        }
        out
    }

    /// 拒絕的動作:回 `message`,`~/.ssh` 底下的檔案(含插槽目錄)與這台的同步狀態都不動。
    pub(crate) fn refused(d: &TestDevice, message: &str, action: impl FnOnce() -> Result<(), AppError>) {
        let before = (tree(&d.ssh_dir()), d.state());
        assert_eq!(action().unwrap_err().to_string(), message);
        assert_eq!((tree(&d.ssh_dir()), d.state()), before, "a refused action changes nothing ({message})");
    }

    /// 動作讀時鐘的那一刻 —— 它在鎖外的快照與最前面的檢查之後、提交之前(`set_mode`、`slot_setup::create_slot` 都是先讀時鐘再提交)——
    /// 同步輪次剛好記下了 `frozen`(只拿 core 鎖,同 `round::mark_frozen`)。時鐘本身照常走(同一台裝置的時鐘)。
    pub(crate) struct FrozenWhenCommitting<'a>(pub(crate) &'a TestDevice);

    impl crate::sync::env::Clock for FrozenWhenCommitting<'_> {
        fn now_ms(&self) -> u64 {
            let mut core = self.0.runtime.core.lock().unwrap();
            core.state.as_mut().unwrap().account.as_mut().unwrap().frozen =
                Some(crate::sync::state_v2::FreezeInfo { detected_at_ms: 1, markers: Vec::new() });
            drop(core);
            crate::sync::env::Clock::now_ms(self.0.clock.as_ref())
        }
    }

    /// 插槽目錄裡改名保留的私鑰(`<file>.previous-…`,不含 `.pub`)。
    fn kept_keys(keys_dir: &Path) -> Vec<PathBuf> {
        let mut kept: Vec<PathBuf> = std::fs::read_dir(keys_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().contains(".previous-") && !p.to_string_lossy().ends_with(".pub"))
            .collect();
        kept.sort();
        kept
    }

    /// 「Sync this key」與「Sync the new key」記下這台自己上傳的那把金鑰(`LocalSlot::uploaded_fingerprint`,補寫 `key` 時只認它);
    /// 「Stop syncing」清掉。從同步來的副本再同步一次的電腦,記下的是它自己上傳的那把;只是落地同步的金鑰不算上傳。
    #[test]
    fn syncing_here_records_the_key_this_computer_uploaded_and_stopping_clears_it() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let uploaded = |d: &TestDevice| d.state().key_slots[&id].uploaded_fingerprint.clone();
        assert_eq!(uploaded(&a), None, "a kept key was never uploaded");

        set_mode(&a.env(), &id, SlotMode::Synced).unwrap();
        assert_eq!(uploaded(&a).as_deref(), Some(test_keys::PLAIN_FINGERPRINT));
        // 換了金鑰之後的「Sync the new key」:記下的換成新的那把。
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        settle(&a);
        set_mode(&a.env(), &id, SlotMode::Synced).unwrap();
        assert_eq!(uploaded(&a).as_deref(), Some(test_keys::ECDSA_FINGERPRINT));
        settle(&a);
        settle(&b);
        assert_eq!(b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::ECDSA_FINGERPRINT.into() }));
        assert_eq!(uploaded(&b), None, "landing a synced key is not uploading it");

        set_mode(&a.env(), &id, SlotMode::Own).unwrap();
        assert_eq!(uploaded(&a), None, "stopping clears it");
        settle(&a);
        settle(&b);
        // B 從自己的副本再同步一次。
        set_mode(&b.env(), &id, SlotMode::Synced).unwrap();
        assert_eq!(uploaded(&b).as_deref(), Some(test_keys::ECDSA_FINGERPRINT));
        assert_eq!(open_key_secret(b.state().account.as_ref().unwrap(), &account_keys(&b), &id).as_deref(), Some(test_keys::ecdsa().as_str()));
    }

    /// 同步來的副本被換成了別的檔案(使用者的、別的插槽放的):「Sync this key」不把那個檔案當成這個插槽的金鑰上傳(同 `republish`)。
    #[test]
    fn a_synced_copy_that_was_replaced_is_not_uploaded_as_the_slots_key() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_mode(&a.env(), &id, SlotMode::Own).unwrap();
        settle(&a);
        settle(&b);
        std::fs::write(home(&b).join(SLOT_DIR).join(&file), test_keys::ecdsa()).unwrap();
        refused(&b, &not_here_message("MacBook-A"), || set_mode(&b.env(), &id, SlotMode::Synced));
    }

    /// 挑金鑰只取代這個插槽自己的本機記錄擁有的東西(spec §4.2):插槽路徑上的東西,這台沒有這個插槽的記錄、或記錄沒有來源 —— 擋路,
    /// 檔案與狀態都不動。檔案移走之後才連得進去。
    #[test]
    fn picking_never_replaces_a_file_this_slot_has_no_record_of() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        settle(&a);
        settle(&b);
        let path = home(&b).join(SLOT_DIR).join(&file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "mine").unwrap();
        let key = b.ssh_dir().join("id_b");
        std::fs::write(&key, test_keys::ecdsa()).unwrap();
        let picked = key.display().to_string();

        // 沒有主機用到它:B 沒有這個插槽的記錄。
        assert!(!b.state().key_slots.contains_key(&id));
        refused(&b, &in_the_way_message(&path), || pick(&b.env(), &id, &picked));
        // 有主機用到、B 還沒挑:記錄沒有來源。
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        assert_eq!(b.state().key_slots[&id].source, None);
        refused(&b, &in_the_way_message(&path), || pick(&b.env(), &id, &picked));

        std::fs::remove_file(&path).unwrap();
        pick(&b.env(), &id, &picked).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa());
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::ECDSA_PUBLIC));
    }

    /// 收起來的記錄不擁有路徑上的東西:挑金鑰不蓋過那裡的檔案(擋路,什麼都不動);路徑空著才連進去,記錄不再是收起來的,`.pub` 是新挑的
    /// 那把;主機又用到它時照常。
    #[test]
    fn picking_for_a_parked_slot_links_only_into_an_empty_path() {
        for hard_link in [false, true] {
            let (a, personal, id, file) = a_parked_slot(hard_link);
            let path = home(&a).join(SLOT_DIR).join(&file);
            let work = a.ssh_dir().join("id_work");
            std::fs::write(&work, test_keys::ecdsa()).unwrap();
            let picked = work.display().to_string();
            std::fs::write(&path, "mine").unwrap();
            refused(&a, &in_the_way_message(&path), || pick(&a.env(), &id, &picked));

            std::fs::remove_file(&path).unwrap();
            pick(&a.env(), &id, &picked).unwrap();
            let local = a.state().key_slots[&id].clone();
            assert!(!local.parked && local.last_error.is_none(), "hard_link={hard_link}: {local:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa());
            assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::ECDSA_PUBLIC), "hard_link={hard_link}");
            use_slot(&a, &personal, &file);
            settle(&a);
            let local = a.state().key_slots[&id].clone();
            assert!(!local.parked && local.last_error.is_none(), "hard_link={hard_link}: {local:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa());
        }
    }

    /// 和帳戶裡另一個插槽同檔名、這台又沒有握著的插槽:挑金鑰、改用同步的金鑰、刪除副本一律拒絕,什麼都不動。
    #[test]
    fn user_actions_on_a_slot_that_shares_its_file_name_and_is_not_held_here_are_refused() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let me = device_id(&a);
        let (s1, s2) = (format!("3fa2c1d9{}", "0".repeat(24)), format!("3fa2c1d9{}", "f".repeat(24)));
        publish(&a, &s1, &synced_payload(&me), Some(&test_keys::plain()));
        publish(&a, &s2, &ecdsa_payload(&me), Some(&test_keys::ecdsa()));
        let file = slot_file_name("id_mac", &s1);
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let mine = b.ssh_dir().join("id_b");
        std::fs::write(&mine, test_keys::ecdsa()).unwrap();
        let picked = mine.display().to_string();
        for id in [&s1, &s2] {
            assert!(contested_and_not_held(&b.state(), id));
            refused(&b, CONTESTED_MESSAGE, || pick(&b.env(), id, &picked));
            refused(&b, CONTESTED_MESSAGE, || use_synced(&b.env(), id));
            refused(&b, CONTESTED_MESSAGE, || delete_copy(&b.env(), id));
        }
        assert!(!slot_files::occupied(&home(&b).join(SLOT_DIR).join(&file)));
    }

    /// 這個插槽自己的連結(這台建立的)直接換成新挑的金鑰:記下連結時用的那個路徑、`.pub` 從新的金鑰重寫、原本連到的金鑰不動、
    /// 不必保留什麼(連結不是金鑰)。這台同意上傳過的那把(`uploaded_fingerprint`)不變:挑的金鑰不會因此被上傳。下一輪照常。
    #[test]
    #[cfg(unix)]
    fn picking_replaces_this_slots_own_link_and_keeps_what_this_computer_chose_to_upload() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        write_linked_public(&path, &source).unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        let work = a.ssh_dir().join("id_work");
        std::fs::write(&work, test_keys::ecdsa()).unwrap();

        pick(&a.env(), &id, &work.display().to_string()).unwrap();
        assert_eq!(std::fs::read_link(&path).unwrap(), work);
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::ECDSA_PUBLIC));
        assert_eq!(std::fs::read_to_string(&source).unwrap(), test_keys::plain(), "the key it linked to before is untouched");
        assert_eq!(kept_keys(path.parent().unwrap()), Vec::<PathBuf>::new(), "a link holds no key: nothing to keep");
        let local = a.state().key_slots[&id].clone();
        assert_eq!(
            local.source,
            Some(SlotSource::Linked {
                path: work.display().to_string(),
                link: LinkKind::Symlink,
                fingerprint: Some(test_keys::ECDSA_FINGERPRINT.into()),
                origin: true
            })
        );
        assert!(!local.parked && local.last_error.is_none());
        assert_eq!(local.uploaded_fingerprint.as_deref(), Some(test_keys::PLAIN_FINGERPRINT), "a pick does not change what this computer chose to upload");
        assert_eq!(local.learned_in, Some(account_keys(&a).chain_id), "nor the account the record belongs to");

        settle(&a);
        let local = a.state().key_slots[&id].clone();
        assert!(!local.parked && local.last_error.is_none(), "{local:?}");
        assert_eq!(view_of(&a)[0].status, SlotStatusView::SourceChanged { file: work.display().to_string() });
        let account = a.state().account.unwrap();
        assert_eq!(open_key_secret(&account, &account_keys(&a), &id).as_deref(), Some(test_keys::plain().as_str()), "the picked key is not uploaded");
    }

    /// 這台挑的 symlink 被使用者換成了自己的檔案(下一輪還沒跑,狀態還說是連結):挑金鑰與改用同步的金鑰都不蓋過、不移除它
    /// (同每一輪的檢查:symlink 的插槽,路徑上要正好是指到記錄原檔的 symlink)。
    #[test]
    #[cfg(unix)]
    fn a_file_the_user_put_in_place_of_the_slots_link_stops_pick_and_use_synced() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let (path, mine) = (home(&b).join(SLOT_DIR).join(&file), b.ssh_dir().join("id_b"));
        std::fs::write(&mine, test_keys::ecdsa()).unwrap();
        pick(&b.env(), &id, &mine.display().to_string()).unwrap();
        settle(&b);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, test_keys::ecdsa()).unwrap();

        refused(&b, &in_the_way_message(&path), || pick(&b.env(), &id, &mine.display().to_string()));
        refused(&b, &in_the_way_message(&path), || use_synced(&b.env(), &id));
    }

    /// 挑金鑰時狀態寫不進去:剛放的連結收回,記錄還是原本的,下一輪依原本的記錄把插槽放回來 —— 不會留下一個記錄不認得、下一輪被當成
    /// 擋路的連結。
    #[test]
    #[cfg(unix)]
    fn a_pick_whose_state_cannot_be_saved_takes_its_link_back() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        write_linked_public(&path, &source).unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        let before = a.state().key_slots[&id].clone();
        let work = a.ssh_dir().join("id_work");
        std::fs::write(&work, test_keys::ecdsa()).unwrap();

        a.runtime.core.lock().unwrap().save_blocked = Some("the state can't be saved".into());
        assert_eq!(pick(&a.env(), &id, &work.display().to_string()).unwrap_err().to_string(), "the state can't be saved");
        assert!(!slot_files::occupied(&path) && !slot_files::occupied(&public_path(&path)), "the new link is taken back");
        assert_eq!(a.state().key_slots[&id], before);

        a.runtime.core.lock().unwrap().save_blocked = None;
        settle(&a);
        assert_eq!(std::fs::read_link(&path).unwrap(), source, "the next round puts the recorded link back");
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        assert_eq!(a.state().key_slots[&id].last_error, None);
    }

    /// hard link 的原檔被換成了另一把(寫新檔再 rename;Windows 上會這樣):插槽裡的 hard link 可能是舊金鑰僅存的名字。挑別把金鑰時
    /// 它改名保留成 `.previous`,不被蓋掉(spec §1)。
    #[test]
    fn picking_keeps_a_hard_link_that_may_be_the_last_name_of_a_key() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        make_it_a_hard_link(&a, &id, &file, "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let (ssh, path) = (a.ssh_dir(), home(&a).join(SLOT_DIR).join(&file));
        // 原檔換成另一把(舊的內容只剩插槽裡的 hard link),下一輪還沒跑。
        std::fs::write(ssh.join("id_mac.new"), test_keys::ecdsa()).unwrap();
        std::fs::rename(ssh.join("id_mac.new"), ssh.join("id_mac")).unwrap();
        let work = ssh.join("id_work");
        std::fs::write(&work, test_keys::ecdsa()).unwrap();

        pick(&a.env(), &id, &work.display().to_string()).unwrap();
        let kept = kept_keys(path.parent().unwrap());
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), test_keys::plain(), "the old key's bytes are kept");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa());
    }

    /// 「Use the synced key」:這台的舊副本改名保留成 `<file>.previous-<8 hex>`(計畫裁定 3,連同 `.pub`),新的同步金鑰放進插槽,
    /// `.pub` 是新的那把;之後是 Ready。
    #[test]
    fn using_the_synced_key_keeps_the_old_copy_as_a_previous_file() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        settle(&a);
        set_mode(&a.env(), &id, SlotMode::Synced).unwrap();
        settle(&a);
        settle(&b);
        let path = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(view_of(&b)[0].status, SlotStatusView::SyncedAvailable { file: path.display().to_string() });
        let tag = slot_files::content_sha256(&path).unwrap()[..8].to_string();

        use_synced(&b.env(), &id).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa());
        assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::ECDSA_PUBLIC));
        let kept = path.with_file_name(format!("{file}.previous-{tag}"));
        assert_eq!(kept_keys(path.parent().unwrap()), vec![kept.clone()]);
        assert_eq!(std::fs::read_to_string(&kept).unwrap(), test_keys::plain(), "the old copy is kept");
        assert_eq!(std::fs::read_to_string(public_path(&kept)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
        let local = b.state().key_slots[&id].clone();
        assert_eq!(local.source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::ECDSA_FINGERPRINT.into() }));
        settle(&b);
        assert!(matches!(view_of(&b)[0].status, SlotStatusView::Ready { synced_copy: true, .. }), "{:?}", view_of(&b)[0].status);
    }

    /// 收起來的記錄不擁有路徑上的東西:改用同步的金鑰不移除、不蓋過那裡的檔案(擋路,什麼都不動)—— 正好指到它記著的金鑰的 symlink 也一樣
    /// (使用者自己放回去的,或上一輪的狀態沒存下來);路徑空著就落地,記錄不再是收起來的。
    #[test]
    fn using_the_synced_key_never_touches_a_file_at_a_parked_path() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        // B 挑了自己的金鑰,之後沒有主機用到它:連結收起來了。
        let (path, mine) = (home(&b).join(SLOT_DIR).join(&file), b.ssh_dir().join("id_b"));
        std::fs::write(&mine, test_keys::ecdsa()).unwrap();
        pick(&b.env(), &id, &mine.display().to_string()).unwrap();
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        settle(&b);
        assert!(b.state().key_slots[&id].parked && !slot_files::occupied(&path));
        std::fs::write(&path, "mine").unwrap();
        refused(&b, &in_the_way_message(&path), || use_synced(&b.env(), &id));
        #[cfg(unix)]
        {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&mine, &path).unwrap();
            refused(&b, &in_the_way_message(&path), || use_synced(&b.env(), &id));
        }

        std::fs::remove_file(&path).unwrap();
        use_synced(&b.env(), &id).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::plain());
        assert_eq!(std::fs::read_to_string(&mine).unwrap(), test_keys::ecdsa(), "B's own key is untouched");
        let local = b.state().key_slots[&id].clone();
        assert_eq!(local.source, Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }));
        assert!(!local.parked && local.last_error.is_none(), "{local:?}");
    }

    /// 同步的金鑰和插槽記錄對不上(帳戶裡的成員寫得出來):改用同步的金鑰在動到插槽路徑上的任何東西之前就拒絕,副本留在原地。
    #[test]
    fn a_synced_key_that_does_not_match_is_refused_before_anything_is_moved() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        publish(&a, &id, &synced_payload(&device_id(&a)), Some(&test_keys::ecdsa()));
        settle(&a);
        settle(&b);
        refused(&b, MISMATCH_MESSAGE, || use_synced(&b.env(), &id));
        assert_eq!(std::fs::read_to_string(home(&b).join(SLOT_DIR).join(&file)).unwrap(), test_keys::plain());
    }

    /// 「Delete copy」只刪這筆記錄放的那份副本:路徑上的檔案已經不是它(指紋不同:使用者換上的、別的插槽放的)就擋路,什麼都不刪;
    /// 是它就連同 `.pub` 刪掉。
    #[test]
    fn a_copy_is_deleted_only_while_the_file_is_still_that_copy() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        settle(&b);
        let copy = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(view_of(&b)[0].status, SlotStatusView::NotInUse { file: copy.display().to_string() });

        std::fs::write(&copy, test_keys::ecdsa()).unwrap();
        refused(&b, &in_the_way_message(&copy), || delete_copy(&b.env(), &id));

        std::fs::write(&copy, test_keys::plain()).unwrap();
        delete_copy(&b.env(), &id).unwrap();
        assert!(!slot_files::occupied(&copy) && !slot_files::occupied(&public_path(&copy)));
        assert!(!b.state().key_slots.contains_key(&id));
        assert_eq!(view_of(&b)[0].status, SlotStatusView::NotUsedHere);
    }

    /// 複製檔(Windows 建不了連結時;這裡在 Unix 上手動做出來)和同步來的副本一樣,沒有主機用到就可以刪,原檔不動。副本已經不在了:
    /// 只忘掉記錄,旁邊的 `.pub` 不能確定是自己的,不碰(同 `park_link`)。
    #[test]
    fn a_linked_copy_can_be_deleted_and_a_copy_that_is_already_gone_is_just_forgotten() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
        std::fs::remove_file(&path).unwrap();
        std::fs::copy(&source, &path).unwrap();
        mutate(&a.env(), |s| {
            if let Some(SlotSource::Linked { link, .. }) = s.key_slots.get_mut(&id).and_then(|l| l.source.as_mut()) {
                *link = LinkKind::Copy;
            }
            Ok(())
        })
        .unwrap();
        write_linked_public(&path, &source).unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        settle(&b);
        assert_eq!(view_of(&a)[0].status, SlotStatusView::NotInUse { file: path.display().to_string() });

        delete_copy(&a.env(), &id).unwrap();
        assert!(!slot_files::occupied(&path) && !slot_files::occupied(&public_path(&path)));
        assert_eq!(std::fs::read_to_string(&source).unwrap(), test_keys::plain(), "the original is untouched");
        assert!(!a.state().key_slots.contains_key(&id));

        // B 的副本已經被使用者刪掉了(`.pub` 還在):只忘掉記錄。
        let copy = home(&b).join(SLOT_DIR).join(&file);
        std::fs::remove_file(&copy).unwrap();
        delete_copy(&b.env(), &id).unwrap();
        assert!(!b.state().key_slots.contains_key(&id));
        assert_eq!(std::fs::read_to_string(public_path(&copy)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC));
    }

    /// 路徑上的東西是不是這個插槽的,只看它自己的本機記錄:路徑空著;沒有記錄、記錄沒有來源、記著別的檔名、收起來了 —— 都不是它的;
    /// symlink 的記錄,路徑上要正好是指到記錄原檔的 symlink;副本與複製檔是它放的金鑰;hard link 在原檔還有同樣內容時只是連結,
    /// 否則可能是那把金鑰僅存的名字。
    #[test]
    #[cfg(unix)]
    fn what_is_at_a_slot_path_is_this_slots_only_as_its_own_record_says() {
        let dir = tempfile::tempdir().unwrap();
        let (key, other) = (dir.path().join("id_mac"), dir.path().join("id_work"));
        std::fs::write(&key, test_keys::plain()).unwrap();
        std::fs::write(&other, test_keys::ecdsa()).unwrap();
        let file = "id_mac-3fa2c1d9";
        let path = dir.path().join(file);
        let record = |source: Option<SlotSource>, parked: bool| LocalSlot {
            file_name: file.into(),
            source,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked,
            learned_in: None,
            copy_from_another_account: false,
        };
        let linked = |link| Some(SlotSource::Linked { path: key.display().to_string(), link, fingerprint: None, origin: false });
        let at = |local: &LocalSlot| occupant(Some(local), file, &path);
        let symlink = record(linked(LinkKind::Symlink), false);

        assert_eq!(occupant(None, file, &path), Occupant::Empty);
        assert_eq!(at(&record(linked(LinkKind::Symlink), true)), Occupant::Empty, "an empty path, whatever the record says");

        std::os::unix::fs::symlink(&key, &path).unwrap();
        assert_eq!(at(&symlink), Occupant::OwnLink);
        assert_eq!(occupant(None, file, &path), Occupant::NotOurs, "no record");
        assert_eq!(at(&record(None, false)), Occupant::NotOurs, "a record with no source");
        assert_eq!(at(&record(linked(LinkKind::Symlink), true)), Occupant::NotOurs, "a parked record");
        assert_eq!(at(&LocalSlot { file_name: "old-3fa2c1d9".into(), ..symlink.clone() }), Occupant::NotOurs, "a record of another file name");

        // symlink 的記錄:指到別處的 symlink、換成一般檔案都不是它的。
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert_eq!(at(&symlink), Occupant::NotOurs);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, test_keys::plain()).unwrap();
        assert_eq!(at(&symlink), Occupant::NotOurs);
        // 副本與複製檔:插槽放的金鑰本身。
        assert_eq!(at(&record(Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.into() }), false)), Occupant::OwnKey);
        assert_eq!(at(&record(linked(LinkKind::Copy), false)), Occupant::OwnKey);

        // hard link:原檔還有同樣的內容就只是連結;原檔換成另一把(或不見了)就可能是舊金鑰僅存的名字。
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&key, &path).unwrap();
        let hard = record(linked(LinkKind::HardLink), false);
        assert_eq!(at(&hard), Occupant::OwnLink);
        std::fs::write(dir.path().join("new"), test_keys::ecdsa()).unwrap();
        std::fs::rename(dir.path().join("new"), &key).unwrap();
        assert_eq!(at(&hard), Occupant::OwnKey);
        std::fs::remove_file(&key).unwrap();
        assert_eq!(at(&hard), Occupant::OwnKey);
    }

    /// 原檔就地換成另一把金鑰(symlink 跟著走、hard link 共用內容,插槽不必重新連結):旁邊的 `.pub` 也要換成新的那把 —— OpenSSH 先讀
    /// `<slot>.pub`,和私鑰對不上就不能用,「Sync the new key」之前這台就連不上了。
    #[test]
    fn a_key_replaced_in_place_gets_its_new_public_half_beside_the_slot() {
        for hard_link in [false, true] {
            let (_relay, _clock, a, _b, _words, personal) = pair();
            let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
            if hard_link {
                make_it_a_hard_link(&a, &id, &file, "id_mac");
            }
            let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_mac"));
            write_linked_public(&path, &source).unwrap();
            use_slot(&a, &personal, &file);
            settle(&a);

            std::fs::write(&source, test_keys::ecdsa()).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), test_keys::ecdsa(), "hard_link={hard_link}: the slot already has the new key");
            settle(&a);
            assert_eq!(std::fs::read_to_string(public_path(&path)).unwrap(), format!("{}\n", test_keys::ECDSA_PUBLIC), "hard_link={hard_link}");
            assert!(matches!(view_of(&a)[0].status, SlotStatusView::SourceChanged { .. }), "hard_link={hard_link}: {:?}", view_of(&a)[0].status);
        }
    }

    // ── 修正第 1 輪:刪除副本只認檔案本身;「這台的金鑰換了」只告訴上傳了目前同步金鑰的那台 ───────────────────────────

    /// 同步來的副本被換成了別種格式的私鑰(PEM、PKCS#8),旁邊 SSHelter 從記錄的金鑰寫的 `.pub` 還在:那不是這份副本,不刪。辨認副本只看
    /// 檔案本身的位元組(同步來的副本一定是 OpenSSH 格式),不看旁邊的 `.pub`。
    #[test]
    fn a_key_in_another_format_put_over_a_synced_copy_is_never_deleted_as_the_copy() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        settle(&b);
        let copy = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(view_of(&b)[0].status, SlotStatusView::NotInUse { file: copy.display().to_string() });

        for header in [concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), concat!("-----BEGIN ", "PRIVATE KEY-----")] {
            let footer = header.replace("BEGIN", "END");
            std::fs::write(&copy, format!("{header}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n{footer}\n")).unwrap();
            assert_eq!(std::fs::read_to_string(public_path(&copy)).unwrap(), format!("{}\n", test_keys::PLAIN_PUBLIC), "SSHelter's .pub is still beside it");
            refused(&b, &in_the_way_message(&copy), || delete_copy(&b.env(), &id));
        }
    }

    /// 記錄沒有指紋的複製檔(舊式 PEM 金鑰,原檔旁邊也沒有 `.pub`):沒有指紋可比,只認內容和記錄的原檔相同的檔案。路徑上換成了別的檔案 →
    /// 擋路,什麼都不刪;內容和原檔相同才刪,原檔不動。
    #[test]
    fn a_copy_with_no_recorded_fingerprint_is_deleted_only_while_it_holds_its_originals_bytes() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let pem = |body: &str| format!("{}\n{body}\n{}\n", concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), concat!("-----END RSA ", "PRIVATE KEY-----"));
        let original = pem("MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu");
        let (id, file) = create_slot_on(&a, SlotMode::Own, &original, "id_old");
        let (path, source) = (home(&a).join(SLOT_DIR).join(&file), a.ssh_dir().join("id_old"));
        // Windows 建不了連結時的複製檔(這裡在 Unix 上手動做出來,狀態記著 `Copy`)。
        std::fs::remove_file(&path).unwrap();
        std::fs::copy(&source, &path).unwrap();
        mutate(&a.env(), |s| {
            if let Some(SlotSource::Linked { link, .. }) = s.key_slots.get_mut(&id).and_then(|l| l.source.as_mut()) {
                *link = LinkKind::Copy;
            }
            Ok(())
        })
        .unwrap();
        use_slot(&a, &personal, &file);
        settle(&a);
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        let local = a.state().key_slots[&id].clone();
        assert!(matches!(&local.source, Some(SlotSource::Linked { link: LinkKind::Copy, fingerprint: None, .. })), "{local:?}");
        assert_eq!(view_of(&a)[0].status, SlotStatusView::NotInUse { file: path.display().to_string() });

        std::fs::write(&path, pem("MIIBOwIBAAJBAL5anotherkeyAnotherKeyAnotherKeyAnotherKeyAnother0")).unwrap();
        refused(&a, &in_the_way_message(&path), || delete_copy(&a.env(), &id));
        // 讀不到的檔案(指到不存在的地方的 symlink)、原檔也暫時不在:兩邊都沒有內容,不算相同。
        #[cfg(unix)]
        {
            let moved = a.ssh_dir().join("id_old.moved");
            std::fs::rename(&source, &moved).unwrap();
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(a.ssh_dir().join("nowhere"), &path).unwrap();
            refused(&a, &in_the_way_message(&path), || delete_copy(&a.env(), &id));
            std::fs::remove_file(&path).unwrap();
            std::fs::rename(&moved, &source).unwrap();
        }

        std::fs::copy(&source, &path).unwrap();
        delete_copy(&a.env(), &id).unwrap();
        assert!(!slot_files::occupied(&path));
        assert_eq!(std::fs::read_to_string(&source).unwrap(), original, "the original is untouched");
        assert!(!a.state().key_slots.contains_key(&id));
    }

    /// 「This computer's key changed」只告訴上傳了插槽目前同步金鑰的那台:別台把自己挑的金鑰同步進一個 `own` 插槽之後,建立插槽的那台看到的
    /// 是可以改用同步的金鑰(它自己的金鑰沒有換,不該被叫去「Sync the new key」把別台的蓋回來);上傳的那台之後換了金鑰,才是「這台的金鑰換了」。
    #[test]
    fn only_the_computer_that_uploaded_the_synced_key_is_told_its_key_changed() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let mine = b.ssh_dir().join("id_b");
        std::fs::write(&mine, test_keys::ecdsa()).unwrap();
        pick(&b.env(), &id, &mine.display().to_string()).unwrap();
        set_mode(&b.env(), &id, SlotMode::Synced).unwrap();
        settle(&b);
        settle(&a);

        let a_key = a.ssh_dir().join("id_mac").display().to_string();
        assert_eq!(view_of(&a)[0].status, SlotStatusView::SyncedAvailable { file: a_key.clone() }, "A's key did not change");
        assert!(matches!(view_of(&b)[0].status, SlotStatusView::Ready { synced_copy: false, .. }), "{:?}", view_of(&b)[0].status);

        // B 就地換了自己的金鑰:目前同步的那把是 B 上傳的,所以 B 是「這台的金鑰換了」;A 還是可以改用同步的金鑰。
        std::fs::write(&mine, test_keys::encrypted()).unwrap();
        settle(&b);
        settle(&a);
        assert_eq!(view_of(&b)[0].status, SlotStatusView::SourceChanged { file: mine.display().to_string() });
        assert_eq!(view_of(&a)[0].status, SlotStatusView::SyncedAvailable { file: a_key });
    }

    // ── 更換同步碼期間,會寫帳戶記錄的動作要等(和 space 的操作一樣檢查 `account::account_ready`)──────────────

    /// 更換同步碼進行中(第 2 步起,包括卡在 keychain 或被限流的時候)與這台已被別台擋下時,「Stop syncing」「Sync this key」一律拒絕,說明和 space
    /// 的操作一樣:帳戶區段之後會被整個換掉 —— 複製讀的是 relay 上凍結的舊記錄,切換與重新加入又把整個區段換成新的 —— 這時寫進去的記錄不是被丟掉、就是被
    /// 較舊的版本取代,使用者看到成功,新帳戶卻沒有那個變更。拒絕時帳戶記錄、`~/.ssh` 底下的檔案與狀態都不動。
    #[test]
    fn changing_how_a_key_is_shared_is_refused_during_a_sync_code_change_and_on_a_computer_that_missed_it() {
        use crate::sync::account::{FROZEN_MESSAGE, ROTATING_MESSAGE};
        use crate::sync::state_v2::RotationStep;
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (synced, synced_file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let (own, own_file) = create_slot_on(&a, SlotMode::Own, &test_keys::ecdsa(), "id_own");
        use_slots(&a, &personal, &[&synced_file, &own_file]);
        settle(&a);
        settle(&b);
        // 兩個方向都擋:停止同步(同步的插槽)、同步(這台讀得到金鑰的 `own` 插槽)。
        let refuse_both = |d: &TestDevice, message: &str| {
            refused(d, message, || set_mode(&d.env(), &synced, SlotMode::Own));
            refused(d, message, || set_mode(&d.env(), &own, SlotMode::Synced));
        };

        // A 更換同步碼:從準備好(第 2 步之前)到切換之前,每一步都擋。
        crate::sync::rotation::start_rotation(&a.env()).unwrap();
        let mut steps = Vec::new();
        while let Some(rotation) = a.state().rotation {
            steps.push(rotation.step);
            refuse_both(&a, ROTATING_MESSAGE);
            let _ = crate::sync::round::sync_once(&a.env()); // 推進一步
            assert!(steps.len() <= 10, "the sync code change never finished: {steps:?}");
        }
        assert_eq!(
            steps,
            vec![RotationStep::Prepared, RotationStep::LocalChangesSent, RotationStep::Copying, RotationStep::Deleting, RotationStep::Switching]
        );

        // B 還沒輸入新同步碼:這台已被擋下。
        settle(&b);
        assert!(b.state().frozen().is_some(), "setup: B noticed the change");
        refuse_both(&b, FROZEN_MESSAGE);
    }

    /// 鎖外的快照與最前面的檢查之後、提交之前 —— 動作讀時鐘的那一刻 —— 同步輪次剛好記下了 `frozen`:提交的 core 臨界區裡再擋一次(同
    /// `spaces::still_ready`),帳戶記錄與本機狀態都不寫。
    #[test]
    fn a_freeze_recorded_just_before_a_mode_change_commits_stops_it_before_anything_is_written() {
        use crate::sync::account::FROZEN_MESSAGE;
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let before = a.state();
        let racing = FrozenWhenCommitting(&a);
        let mut env = a.env();
        env.clock = &racing;
        assert_eq!(set_mode(&env, &id, SlotMode::Own).unwrap_err().to_string(), FROZEN_MESSAGE);
        let mut after = a.state();
        assert!(after.frozen().is_some(), "the freeze the round recorded is there");
        after.account.as_mut().unwrap().frozen = None;
        assert_eq!(after, before, "no record and no local state was written");
    }

    // ── 只在 SSHelter 的插槽(金鑰保管庫 spec §4.3、§4.4)────────────────────────────────────────────────

    fn vault_entry(d: &TestDevice, id: &str) -> Option<crate::vault::store::VaultEntry> {
        let env = d.env();
        let path = crate::vault::store::vault_path(&env.state_path);
        crate::vault::store::with_vault(env.runtime, &path, env.keychain, 1, |v| v.get(id)).unwrap()
    }

    #[test]
    fn a_synced_copy_moves_into_the_vault_and_back_to_a_file() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let slot = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&slot).unwrap(), test_keys::plain());

        set_delivery(&b.env(), &id, true).unwrap();
        assert!(!slot.exists(), "no private key file is left in the slot");
        assert_eq!(std::fs::read_to_string(public_path(&slot)).unwrap().trim(), test_keys::PLAIN_PUBLIC);
        let entry = vault_entry(&b, &id).expect("the key is in the vault");
        assert_eq!(entry.private_key, test_keys::plain());
        assert_eq!(entry.origin, crate::vault::store::EntryOrigin::Synced);
        assert!(matches!(&b.state().key_slots[&id].source, Some(SlotSource::Vault { fingerprint, .. }) if fingerprint == test_keys::PLAIN_FINGERPRINT));
        assert_eq!(vault_slot_files(&b.state()), BTreeSet::from([file.clone()]));
        assert!(view_of(&b).remove(0).in_vault);

        settle(&b);
        assert!(!slot.exists(), "a round never lands a file into a vault slot");
        assert!(matches!(b.state().key_slots[&id].source, Some(SlotSource::Vault { .. })));

        set_delivery(&b.env(), &id, false).unwrap();
        assert_eq!(std::fs::read_to_string(&slot).unwrap(), test_keys::plain());
        assert!(matches!(&b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint }) if fingerprint == test_keys::PLAIN_FINGERPRINT));
        assert!(vault_entry(&b, &id).is_none(), "the vault no longer holds it");
        assert!(!b.state().key_slots[&id].copy_from_another_account, "it came from this account");
        assert!(vault_slot_files(&b.state()).is_empty());
    }

    #[test]
    fn a_linked_key_moves_into_the_vault_and_the_original_file_stays() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        let original = a.ssh_dir().join("id_mac");
        let slot = home(&a).join(SLOT_DIR).join(&file);

        set_delivery(&a.env(), &id, true).unwrap();
        assert_eq!(std::fs::read_to_string(&original).unwrap(), test_keys::plain(), "the user's own file is untouched");
        assert!(!slot_files::occupied(&slot), "SSHelter's link is gone");
        assert!(public_path(&slot).is_file());
        assert_eq!(vault_entry(&a, &id).unwrap().origin, crate::vault::store::EntryOrigin::Imported);

        set_delivery(&a.env(), &id, false).unwrap();
        assert!(b_copy_flag(&a, &id), "an imported key returns as a copy that still needs this computer's consent to upload");
    }

    fn b_copy_flag(d: &TestDevice, id: &str) -> bool {
        d.state().key_slots[id].copy_from_another_account
    }

    #[test]
    fn a_vault_slot_gets_its_pub_back_and_reports_a_file_in_the_way() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let slot = home(&b).join(SLOT_DIR).join(&file);

        std::fs::remove_file(public_path(&slot)).unwrap();
        settle(&b);
        assert_eq!(std::fs::read_to_string(public_path(&slot)).unwrap().trim(), test_keys::PLAIN_PUBLIC, "the .pub is written again");

        std::fs::write(&slot, "someone else's file").unwrap();
        settle(&b);
        assert_eq!(b.state().key_slots[&id].last_error.as_deref(), Some(in_the_way_message(&slot).as_str()));
        assert_eq!(std::fs::read_to_string(&slot).unwrap(), "someone else's file", "never overwritten");
    }

    #[test]
    fn republish_restores_a_vault_key_from_this_account_but_not_an_imported_one_without_consent() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let keys = account_keys(&b);
        let lost = |d: &TestDevice| {
            let mut state = d.state();
            let account = state.account.as_mut().unwrap();
            account.records.remove(&record_key(RecordKind::KeySlot, &id));
            account.sealed.remove(&key_secret_key(&keys, &id));
            state
        };

        let mut state = lost(&b);
        let env = b.env();
        reconcile_with_vault(&mut state, &keys, &home(&b), &NO_OTHER_HOSTS, 1_000, &EnvVault { env: &env });
        assert_eq!(open_key_secret(state.account.as_ref().unwrap(), &keys, &id).as_deref(), Some(test_keys::plain().as_str()), "a synced key from this account comes back");

        mutate(&b.env(), |s| {
            s.key_slots.get_mut(&id).unwrap().copy_from_another_account = true;
            Ok(())
        })
        .unwrap();
        let mut state = lost(&b);
        let env = b.env();
        reconcile_with_vault(&mut state, &keys, &home(&b), &NO_OTHER_HOSTS, 2_000, &EnvVault { env: &env });
        assert!(slot(state.account.as_ref().unwrap(), &id).is_some(), "the keyslot is written again");
        assert_eq!(open_key_secret(state.account.as_ref().unwrap(), &keys, &id), None, "but no key without consent");
    }

    /// 保管庫裡的金鑰可能是那把金鑰僅存的一份:改用同步的金鑰要先改回檔案(「Keep a file」),之後 SP3 的 `use_synced` 照舊把被換掉的那把改名保留。
    #[test]
    fn using_the_synced_key_on_a_vault_slot_is_refused() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        // A 把另一把金鑰同步進這個插槽。
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        settle(&a);
        set_mode(&a.env(), &id, SlotMode::Synced).unwrap();
        settle(&a);
        settle(&b);
        assert!(matches!(view_of(&b).remove(0).status, SlotStatusView::SyncedAvailable { .. }));

        refused(&b, VAULT_FIRST_MESSAGE, || use_synced(&b.env(), &id));
        assert_eq!(vault_entry(&b, &id).unwrap().private_key, test_keys::plain(), "the vault still holds the plain key");
        assert!(matches!(&b.state().key_slots[&id].source, Some(SlotSource::Vault { fingerprint, .. }) if fingerprint == test_keys::PLAIN_FINGERPRINT));
        assert!(!slot_files::occupied(&home(&b).join(SLOT_DIR).join(&file)), "nothing is written at the slot path");
    }

    #[test]
    fn deleting_an_unused_vault_key_removes_the_entry_and_the_pub() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        b.save_in_app(&b.space_path(&personal), "Host web\n  HostName 1.1.1.1\n");
        settle(&b);
        assert!(matches!(view_of(&b).remove(0).status, SlotStatusView::NotInUse { .. }));

        delete_copy(&b.env(), &id).unwrap();
        assert!(vault_entry(&b, &id).is_none());
        assert!(!public_path(&home(&b).join(SLOT_DIR).join(&file)).exists());
        assert!(!b.state().key_slots.contains_key(&id));
    }

    #[test]
    fn moving_a_key_into_the_vault_wires_its_hosts_to_the_agent() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let home = home(&b);
        let config = std::fs::read_to_string(crate::agent::wiring::agent_config_path(&home)).unwrap();
        assert!(config.starts_with(crate::agent::wiring::HEADER));
        assert!(config.contains("Host web\n  IdentityAgent "));
        let main = std::fs::read_to_string(b.main_path()).unwrap();
        assert!(main.starts_with("Include ~/.ssh/sshelter/agent/config\n"), "{main}");

        // A sync round keeps both Includes, ours first, and the loader never sees agent/config.
        settle(&b);
        settle(&b);
        let main = std::fs::read_to_string(b.main_path()).unwrap();
        let lines: Vec<&str> = main.lines().collect();
        assert_eq!(lines[0], "Include ~/.ssh/sshelter/agent/config");
        // The sync Include comes right after ours; the file's own leading comment (`# main`) is not a read line, so it may sit between them.
        let next = lines.iter().skip(1).find(|line| !line.starts_with('#')).expect("the sync Include is still there");
        assert!(next.starts_with("Include ~/.ssh/sshelter/") && next.ends_with(".config"), "the sync Include comes right after ours: {main}");
        b.reload();
        let doc = b.doc.lock().unwrap();
        assert!(doc.as_ref().unwrap().files.iter().all(|f| f.path != crate::agent::wiring::agent_config_path(&home)));
    }

    #[test]
    fn a_removed_include_is_reported_and_not_added_back() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let main = std::fs::read_to_string(b.main_path()).unwrap();
        std::fs::write(b.main_path(), main.replacen("Include ~/.ssh/sshelter/agent/config\n", "", 1)).unwrap();
        b.reload();
        assert_eq!(crate::agent::wiring::refresh_env(&b.env()).unwrap(), crate::agent::wiring::WiringStatus::IncludeMissing);
        assert!(!std::fs::read_to_string(b.main_path()).unwrap().contains("sshelter/agent/config"));
    }

    /// 每一輪同步結束前都會對一次 agent 的設定:主機同步進來、開始(或不再)用保管庫的金鑰時,`agent/config` 跟著變,不必等使用者再做什麼。
    #[test]
    fn a_sync_round_keeps_the_agent_config_in_step_with_the_hosts() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let config = crate::agent::wiring::agent_config_path(&home(&b));
        let listed = || -> Vec<String> {
            let mut hosts: Vec<String> =
                std::fs::read_to_string(&config).unwrap().lines().filter(|line| line.starts_with("Host ")).map(String::from).collect();
            hosts.sort();
            hosts
        };
        assert_eq!(listed(), ["Host web"]);

        // A 又有一台主機用這個插槽:同步進 B 之後,B 的那一輪就把它列進去。
        let uses = format!("  IdentityFile ~/.ssh/sshelter/keys/{file}\n");
        a.save_in_app(&a.space_path(&personal), &format!("Host web\n  HostName 10.0.0.1\n{uses}Host db\n  HostName 10.0.0.2\n{uses}"));
        settle(&a);
        settle(&b);
        assert_eq!(listed(), ["Host db", "Host web"]);

        // 其中一台改成不用它:列表跟著少一台。
        a.save_in_app(&a.space_path(&personal), &format!("Host web\n  HostName 10.0.0.1\n{uses}Host db\n  HostName 10.0.0.2\n"));
        settle(&a);
        settle(&b);
        assert_eq!(listed(), ["Host web"]);
        assert!(std::fs::read_to_string(b.main_path()).unwrap().starts_with("Include ~/.ssh/sshelter/agent/config\n"));
    }

    /// 改回檔案:主機不再走 agent,`agent/config` 只剩標頭;Include 留著(只有使用者會拿掉它)。
    #[test]
    fn keeping_a_file_again_takes_the_hosts_out_of_the_agent_config_and_leaves_the_include() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let config = crate::agent::wiring::agent_config_path(&home(&b));
        assert!(std::fs::read_to_string(&config).unwrap().contains("Host web\n"));
        let main = std::fs::read_to_string(b.main_path()).unwrap();

        set_delivery(&b.env(), &id, false).unwrap();
        assert_eq!(std::fs::read_to_string(&config).unwrap(), format!("{}\n", crate::agent::wiring::HEADER), "no host is left in it");
        assert_eq!(std::fs::read_to_string(b.main_path()).unwrap(), main, "the Include stays");
    }

    /// 沒有用「只在 SSHelter」的電腦(絕大多數):每一輪的那一步什麼都不留 —— 沒有 agent 的目錄、`agent/config`,主 config 也沒有那一行。
    #[test]
    fn a_computer_that_keeps_its_keys_in_files_never_gets_an_agent_config() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (_id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        settle(&a);
        settle(&b);
        for d in [&a, &b] {
            assert!(!crate::agent::agent_dir(&home(d)).exists(), "no agent directory");
            assert!(!std::fs::read_to_string(d.main_path()).unwrap().contains("sshelter/agent/config"));
        }
    }

    /// 沒有變的一輪不重寫任何檔案:同步的 Include 與 agent 的 Include 各自排好之後,不會每一輪互相搬動(主 config 會被寫兩次),`agent/config` 也不重寫。
    #[test]
    fn a_quiet_round_rewrites_neither_the_main_config_nor_the_agent_config() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        settle(&b);
        let paths = [b.main_path(), crate::agent::wiring::agent_config_path(&home(&b))];
        let before: Vec<String> = paths.iter().map(|path| std::fs::read_to_string(path).unwrap()).collect();
        for path in &paths {
            // 修改時間設回很久以前:之後沒有被重寫,就還是那個值。
            std::fs::File::options().write(true).open(path).unwrap().set_modified(std::time::UNIX_EPOCH).unwrap();
        }

        settle(&b);
        settle(&b);
        for (path, before) in paths.iter().zip(&before) {
            assert_eq!(&std::fs::read_to_string(path).unwrap(), before, "{}", path.display());
            assert_eq!(std::fs::metadata(path).unwrap().modified().unwrap(), std::time::UNIX_EPOCH, "{} was written again", path.display());
        }
    }

    /// 主 config 在載入之後被別的程式改過:agent 的設定更新不了(第一次要把 Include 放進去,存檔會撞上 `Conflict`)也不讓搬進保管庫失敗,別的程式的修改一個字都不動。
    #[test]
    fn a_main_config_edited_elsewhere_does_not_stop_a_key_moving_into_the_vault() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let edited = format!("{}# edited elsewhere\n", std::fs::read_to_string(b.main_path()).unwrap());
        b.write_externally(&b.main_path(), &edited);

        set_delivery(&b.env(), &id, true).unwrap();
        assert!(matches!(b.state().key_slots[&id].source, Some(SlotSource::Vault { .. })), "the key is in the vault");
        assert_eq!(std::fs::read_to_string(b.main_path()).unwrap(), edited, "the edit made elsewhere is never overwritten");
    }

    #[test]
    fn a_lost_vault_entry_comes_back_from_the_account() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        // 保管庫檔不見了(例如 `vault:key` 從 keychain 消失之後被搬到旁邊)。
        std::fs::remove_file(crate::vault::store::vault_path(&b.env().state_path)).unwrap();
        settle(&b);
        assert_eq!(vault_entry(&b, &id).unwrap().private_key, test_keys::plain(), "restored from the account");
        assert_eq!(vault_entry(&b, &id).unwrap().origin, crate::vault::store::EntryOrigin::Imported, "a restored key needs this computer's consent to upload");
        assert!(matches!(b.state().key_slots[&id].source, Some(SlotSource::Vault { .. })));
        assert_eq!(b.state().key_slots[&id].last_error, None);
        assert!(!home(&b).join(SLOT_DIR).join(&file).exists(), "still no private key file in the slot");
    }

    #[test]
    fn a_lost_vault_key_the_account_does_not_have_leaves_the_slot_without_a_key() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        set_delivery(&a.env(), &id, true).unwrap();
        std::fs::remove_file(crate::vault::store::vault_path(&a.env().state_path)).unwrap();
        settle(&a);
        let local = a.state().key_slots.get(&id).cloned();
        assert!(local.as_ref().is_none_or(|l| l.source.is_none()), "no longer delivered from the vault: {local:?}");
        assert!(vault_slot_files(&a.state()).is_empty());
        assert_eq!(std::fs::read_to_string(a.ssh_dir().join("id_mac")).unwrap(), test_keys::plain(), "the user's own file is untouched");
    }

    #[test]
    fn an_unreadable_vault_changes_nothing_in_a_round() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let vault = crate::vault::store::vault_path(&b.env().state_path);
        std::fs::write(&vault, "{ not json").unwrap();
        settle(&b);
        assert!(matches!(b.state().key_slots[&id].source, Some(SlotSource::Vault { .. })), "a round never acts on a vault it cannot read");
        assert_eq!(std::fs::read_to_string(&vault).unwrap(), "{ not json", "and never moves it");

        // 帳戶掉了這個插槽、主機還用著(補寫的路徑):一樣不開讀不懂的保管庫 —— `keyslot` 補回去,私鑰不補,檔案留在原處。
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
        assert!(slot(&account, &id).is_some(), "the keyslot is written again");
        assert_eq!(open_key_secret(&account, &keys, &id), None);
        assert_eq!(std::fs::read_to_string(&vault).unwrap(), "{ not json", "the republish path never moves it either");
        assert!(matches!(b.state().key_slots[&id].source, Some(SlotSource::Vault { .. })));
    }

    #[test]
    fn picking_a_key_for_a_vault_slot_is_refused() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let other = b.ssh_dir().join("id_other");
        std::fs::write(&other, test_keys::ecdsa()).unwrap();
        refused(&b, VAULT_FIRST_MESSAGE, || pick(&b.env(), &id, &other.display().to_string()));
    }

    /// 補寫只在 SSHelter 的金鑰時,保管庫裡那一筆的私鑰本身要是記錄裡的那一把:這台同意上傳的是記錄裡的 plain,保管庫裡放著的卻是 ecdsa
    /// (例如提交失敗留下的)時不上傳 —— 即使這台最後看到的 payload 填的正是 ecdsa 的指紋(帳戶裡的成員改得動)。
    #[test]
    fn republish_never_uploads_a_vault_key_other_than_the_recorded_one() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        set_delivery(&a.env(), &id, true).unwrap();
        assert_eq!(a.state().key_slots[&id].uploaded_fingerprint.as_deref(), Some(test_keys::PLAIN_FINGERPRINT), "setup: A chose to sync the plain key");
        let keys = account_keys(&a);
        let lost = |payload: KeySlotPayload| {
            let mut state = a.state();
            state.key_slots.get_mut(&id).unwrap().payload = Some(payload);
            let account = state.account.as_mut().unwrap();
            account.records.remove(&record_key(RecordKind::KeySlot, &id));
            account.sealed.remove(&key_secret_key(&keys, &id));
            state
        };
        let env = a.env();

        // 保管庫裡是記錄裡的那一把:這台同意過,`key` 補回去。
        let mut state = lost(a.state().key_slots[&id].payload.clone().unwrap());
        reconcile_with_vault(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 1_000, &EnvVault { env: &env });
        assert_eq!(open_key_secret(state.account.as_ref().unwrap(), &keys, &id).as_deref(), Some(test_keys::plain().as_str()));

        // 保管庫裡換成了另一把,最後看到的 payload 也是它的:不上傳。
        let other = crate::vault::store::VaultEntry {
            private_key: test_keys::ecdsa(),
            public_key: test_keys::ECDSA_PUBLIC.to_string(),
            fingerprint: test_keys::ECDSA_FINGERPRINT.to_string(),
            origin: crate::vault::store::EntryOrigin::Imported,
            added_at_ms: 1,
        };
        let vault = crate::vault::store::vault_path(&env.state_path);
        crate::vault::store::with_vault(env.runtime, &vault, env.keychain, 1, |v| v.put(env.keychain, &id, &other)).unwrap();
        let mut state = lost(ecdsa_payload(&device_id(&a)));
        reconcile_with_vault(&mut state, &keys, &home(&a), &NO_OTHER_HOSTS, 2_000, &EnvVault { env: &env });
        let account = state.account.as_ref().unwrap();
        assert!(slot(account, &id).is_some(), "the keyslot is written again");
        assert_eq!(open_key_secret(account, &keys, &id), None, "the vault's other key is never uploaded");
    }

    /// 只回答第一次讀取的 keychain,之後一律讀不到(同上鎖)。
    struct FirstReadOnly<'a> {
        inner: &'a crate::sync::testkit::MemKeychain,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl crate::sync::env::Keychain for FirstReadOnly<'_> {
        fn get(&self, account: &str) -> Result<Option<String>, AppError> {
            if self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                return Err(AppError::Other("keychain error: locked".to_string()));
            }
            self.inner.get(account)
        }
        fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
            self.inner.set(account, secret)
        }
        fn delete(&self, account: &str) -> Result<(), AppError> {
            self.inner.delete(account)
        }
    }

    /// 改回檔案時,記錄先改成檔案、保管庫那一筆之後才拿掉:拿不掉(這裡是那一刻 keychain 讀不到)只留下一筆沒有記錄用到的 —— 不會有記錄說
    /// 金鑰在保管庫、保管庫裡卻沒有它,插槽路徑上剛寫的檔案也不會被當成擋路的檔案。
    #[test]
    fn a_key_kept_as_a_file_again_stays_a_file_when_its_vault_entry_cannot_be_removed() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();

        // keychain 只回答讀出那一筆的那一次,拿掉它的時候開不了保管庫。
        let keychain = FirstReadOnly { inner: &b.keychain, reads: std::sync::atomic::AtomicUsize::new(0) };
        let mut env = b.env();
        env.keychain = &keychain;
        set_delivery(&env, &id, false).unwrap();
        let slot = home(&b).join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(&slot).unwrap(), test_keys::plain(), "the key is a file again");
        assert!(matches!(&b.state().key_slots[&id].source, Some(SlotSource::SyncedCopy { fingerprint }) if fingerprint == test_keys::PLAIN_FINGERPRINT));
        assert!(vault_slot_files(&b.state()).is_empty());
        assert_eq!(vault_entry(&b, &id).map(|e| e.fingerprint.clone()).as_deref(), Some(test_keys::PLAIN_FINGERPRINT), "the vault keeps an entry nothing uses");
        settle(&b);
        assert_eq!(b.state().key_slots[&id].last_error, None, "the file is not reported as in the way");
        assert_eq!(std::fs::read_to_string(&slot).unwrap(), test_keys::plain());
    }

    /// 搬進保管庫時狀態寫不進去:同步來的副本還留在插槽裡,記錄也還是它 —— 記錄提交之後才拿掉插槽裡的私鑰。先刪的話,帳戶裡沒有這把金鑰時
    /// (Stop syncing 之後、之前的帳戶留下的副本),它只剩保管庫裡一筆沒有記錄用到的。
    #[test]
    fn a_synced_copy_stays_until_its_move_into_the_vault_is_saved() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        let slot = home(&b).join(SLOT_DIR).join(&file);
        let before = b.state().key_slots[&id].clone();

        b.runtime.core.lock().unwrap().save_blocked = Some("the state can't be saved".into());
        assert_eq!(set_delivery(&b.env(), &id, true).unwrap_err().to_string(), "the state can't be saved");
        assert_eq!(std::fs::read_to_string(&slot).unwrap(), test_keys::plain(), "the synced copy is still in the slot");
        assert_eq!(b.state().key_slots[&id], before, "the record is still the synced copy");

        b.runtime.core.lock().unwrap().save_blocked = None;
        set_delivery(&b.env(), &id, true).unwrap();
        assert!(!slot_files::occupied(&slot), "once the move is saved, the file goes");
        assert_eq!(std::fs::read_to_string(public_path(&slot)).unwrap().trim(), test_keys::PLAIN_PUBLIC, "and the .pub stays");
        assert!(matches!(b.state().key_slots[&id].source, Some(SlotSource::Vault { .. })));
    }

    /// 改回檔案時狀態寫不進去:剛寫的私鑰檔收回(記錄還說金鑰在保管庫,保管庫裡也還有它),不留下一個下一輪被當成擋路的檔案。
    #[test]
    fn keeping_a_file_whose_state_cannot_be_saved_takes_the_file_back() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);
        set_delivery(&b.env(), &id, true).unwrap();
        let slot = home(&b).join(SLOT_DIR).join(&file);
        let before = b.state().key_slots[&id].clone();

        b.runtime.core.lock().unwrap().save_blocked = Some("the state can't be saved".into());
        assert_eq!(set_delivery(&b.env(), &id, false).unwrap_err().to_string(), "the state can't be saved");
        assert!(!slot_files::occupied(&slot), "the copy just written is taken back");
        assert_eq!(std::fs::read_to_string(public_path(&slot)).unwrap().trim(), test_keys::PLAIN_PUBLIC, "the .pub stays");
        assert_eq!(b.state().key_slots[&id], before);
        assert_eq!(vault_entry(&b, &id).unwrap().private_key, test_keys::plain(), "the vault still holds the key");

        b.runtime.core.lock().unwrap().save_blocked = None;
        settle(&b);
        assert_eq!(b.state().key_slots[&id].last_error, None, "nothing is left in the way");
    }

    /// 保管庫裡那一筆不是記錄裡的那一把(例如提交失敗留下的):改回檔案與「Sync this key」都拒絕,不拿它當成這個插槽的金鑰。
    #[test]
    fn a_vault_entry_that_is_not_the_recorded_key_is_never_used() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        set_delivery(&a.env(), &id, true).unwrap();
        let env = a.env();
        let other = VaultEntry {
            private_key: test_keys::ecdsa(),
            public_key: test_keys::ECDSA_PUBLIC.to_string(),
            fingerprint: test_keys::ECDSA_FINGERPRINT.to_string(),
            origin: EntryOrigin::Imported,
            added_at_ms: 1,
        };
        with_vault(env.runtime, &vault_path(&env.state_path), env.keychain, 1, |v| v.put(env.keychain, &id, &other)).unwrap();

        refused(&a, VAULT_MISMATCH_MESSAGE, || set_delivery(&a.env(), &id, false));
        refused(&a, VAULT_MISMATCH_MESSAGE, || set_mode(&a.env(), &id, SlotMode::Synced));
        assert_eq!(vault_entry(&a, &id).unwrap().private_key, test_keys::ecdsa(), "the vault is left as it was");
    }

    /// 這台上傳了插槽的同步金鑰,之後換了金鑰才搬進保管庫:保管庫裡的那把和帳戶裡同步的不同 —— 同連到本機金鑰的插槽,是「這台的金鑰換了」
    /// (SourceChanged,「Sync the new key」經 `set_mode` 上傳保管庫裡的那把),不是「有同步的金鑰可以用」。
    #[test]
    fn a_vault_key_that_replaced_the_key_this_computer_synced_offers_to_sync_the_new_key() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        std::fs::write(a.ssh_dir().join("id_mac"), test_keys::ecdsa()).unwrap();
        settle(&a);
        assert!(matches!(view_of(&a).remove(0).status, SlotStatusView::SourceChanged { .. }), "setup: as a file it is SourceChanged");

        set_delivery(&a.env(), &id, true).unwrap();
        settle(&a);
        let slot = home(&a).join(SLOT_DIR).join(&file);
        assert_eq!(view_of(&a).remove(0).status, SlotStatusView::SourceChanged { file: slot.display().to_string() });

        set_mode(&a.env(), &id, SlotMode::Synced).unwrap();
        let keys = account_keys(&a);
        assert_eq!(open_key_secret(a.state().account.as_ref().unwrap(), &keys, &id).as_deref(), Some(test_keys::ecdsa().as_str()), "the vault's key is uploaded");
        assert_eq!(a.state().key_slots[&id].uploaded_fingerprint.as_deref(), Some(test_keys::ECDSA_FINGERPRINT));
        settle(&a);
        assert!(matches!(view_of(&a).remove(0).status, SlotStatusView::Ready { synced_copy: false, .. }));
    }

    /// 搬進保管庫時,插槽路徑上可能是某把金鑰僅存名字的 hard link(原檔換成了另一把)與複製檔:改名保留,不刪除;使用者的原檔不動。
    #[test]
    fn moving_into_the_vault_keeps_a_hard_link_or_a_copy_under_another_name() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        let ssh = a.ssh_dir();
        let keys_dir = home(&a).join(SLOT_DIR);
        let (linked_id, linked_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_linked");
        let (copy_id, copy_file) = create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_copy");
        make_it_a_hard_link(&a, &linked_id, &linked_file, "id_linked");
        let copy_path = keys_dir.join(&copy_file);
        std::fs::remove_file(&copy_path).unwrap();
        std::fs::copy(ssh.join("id_copy"), &copy_path).unwrap();
        mutate(&a.env(), |s| {
            if let Some(SlotSource::Linked { link, .. }) = s.key_slots.get_mut(&copy_id).and_then(|l| l.source.as_mut()) {
                *link = LinkKind::Copy;
            }
            Ok(())
        })
        .unwrap();
        use_slots(&a, &personal, &[&linked_file, &copy_file]);
        settle(&a);
        // hard link 的原檔換成另一把(寫新檔再 rename):舊的內容只剩插槽裡的 hard link。下一輪還沒跑。
        std::fs::write(ssh.join("id_linked.new"), test_keys::ecdsa()).unwrap();
        std::fs::rename(ssh.join("id_linked.new"), ssh.join("id_linked")).unwrap();

        for (id, file) in [(&linked_id, &linked_file), (&copy_id, &copy_file)] {
            set_delivery(&a.env(), id, true).unwrap();
            assert!(!slot_files::occupied(&keys_dir.join(file)), "{file}: no private key file is left at the slot path");
            assert!(matches!(a.state().key_slots[id].source, Some(SlotSource::Vault { .. })));
        }
        let kept = kept_keys(&keys_dir);
        assert_eq!(kept.len(), 2, "{kept:?}");
        for kept in &kept {
            assert_eq!(std::fs::read_to_string(kept).unwrap(), test_keys::plain(), "{}: the old bytes are kept under another name", kept.display());
        }
        assert_eq!(std::fs::read_to_string(ssh.join("id_linked")).unwrap(), test_keys::ecdsa(), "the user's files are untouched");
        assert_eq!(std::fs::read_to_string(ssh.join("id_copy")).unwrap(), test_keys::plain());
        assert_eq!(vault_entry(&a, &copy_id).unwrap().private_key, test_keys::plain());
    }

    /// `recover_vault_entry` 的測試用保管庫:`holds` 回固定的答案,`restore` 記下放回的那一筆(插槽 id、來源、指紋);`restore_error` 讓它失敗。
    struct FakeVault {
        holds: Option<bool>,
        restore_error: Option<&'static str>,
        restored: Mutex<Vec<(String, EntryOrigin, String)>>,
    }

    impl FakeVault {
        fn new(holds: Option<bool>) -> Self {
            Self { holds, restore_error: None, restored: Mutex::new(Vec::new()) }
        }
    }

    impl VaultKeys for FakeVault {
        fn private_key(&self, _slot_id: &str) -> Option<(Zeroizing<String>, EntryOrigin)> {
            None
        }

        fn holds(&self, _slot_id: &str) -> Option<bool> {
            self.holds
        }

        fn restore(&self, slot_id: &str, entry: &VaultEntry) -> Result<(), AppError> {
            if let Some(message) = self.restore_error {
                return Err(AppError::Other(message.to_string()));
            }
            self.restored.lock().unwrap().push((slot_id.to_string(), entry.origin, entry.fingerprint.clone()));
            Ok(())
        }
    }

    /// 只在 SSHelter 的插槽記錄(plain 那把)。
    fn vault_record() -> LocalSlot {
        LocalSlot {
            file_name: "id_mac-3fa2c1d9".into(),
            source: Some(SlotSource::Vault {
                fingerprint: test_keys::PLAIN_FINGERPRINT.into(),
                public_key: test_keys::PLAIN_PUBLIC.into(),
                has_passphrase: false,
            }),
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
        }
    }

    /// 保管庫裡沒有這一筆、帳戶裡也沒有這把金鑰:這台回到「還沒有金鑰」,並說明它從保管庫不見了。保管庫讀不了(`holds` 是 None)或還有它:
    /// 什麼都不動。
    #[test]
    fn a_vault_entry_the_account_cannot_restore_leaves_the_slot_without_a_key() {
        let keys = ChainKeys::generate().unwrap();
        let account = AccountState::new(&keys.chain_id);
        let lost = FakeVault::new(Some(false));
        let mut local = vault_record();
        recover_vault_entry(&mut local, SLOT_ID, &account, &keys, 5, &lost);
        assert_eq!(local.source, None);
        assert_eq!(local.last_error.as_deref(), Some(VAULT_ENTRY_LOST));
        assert!(lost.restored.lock().unwrap().is_empty());

        for holds in [None, Some(true)] {
            let vault = FakeVault::new(holds);
            let mut local = vault_record();
            recover_vault_entry(&mut local, SLOT_ID, &account, &keys, 5, &vault);
            assert_eq!(local, vault_record(), "holds = {holds:?}: nothing changes");
            assert!(vault.restored.lock().unwrap().is_empty());
        }
    }

    /// 帳戶裡有同一把金鑰:放回保管庫,記成 `Imported` —— 記錄分不出它原本是這台自己的還是同步來的,之後補寫 `key` 要這台的同意。放回成功不蓋掉
    /// 這一輪 `maintain` 回報的錯誤(擋路);放不回去才記下原因。
    #[test]
    fn a_restored_vault_entry_needs_consent_again_and_keeps_the_rounds_error() {
        let keys = ChainKeys::generate().unwrap();
        let mut account = AccountState::new(&keys.chain_id);
        put_key_secret(&mut account, &keys, SLOT_ID, Some(&test_keys::plain()), "a", 10).unwrap();
        let in_the_way = in_the_way_message(Path::new("/home/f/.ssh/sshelter/keys/id_mac-3fa2c1d9"));

        let vault = FakeVault::new(Some(false));
        let mut local = vault_record();
        local.last_error = Some(in_the_way.clone());
        recover_vault_entry(&mut local, SLOT_ID, &account, &keys, 5, &vault);
        assert_eq!(*vault.restored.lock().unwrap(), vec![(SLOT_ID.to_string(), EntryOrigin::Imported, test_keys::PLAIN_FINGERPRINT.to_string())]);
        assert!(matches!(local.source, Some(SlotSource::Vault { .. })));
        assert_eq!(local.last_error, Some(in_the_way), "a restore that worked hides nothing");

        let failing = FakeVault { restore_error: Some("keychain error: locked"), ..FakeVault::new(Some(false)) };
        let mut local = vault_record();
        recover_vault_entry(&mut local, SLOT_ID, &account, &keys, 5, &failing);
        assert_eq!(local.last_error.as_deref(), Some("keychain error: locked"));
        assert!(matches!(local.source, Some(SlotSource::Vault { .. })));
    }
}
