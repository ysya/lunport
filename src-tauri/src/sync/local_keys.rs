//! 這台自己加進 SSHelter 的金鑰(金鑰保管庫 spec §7.5「New key」「Generate key」、§4.3「沒加入同步帳戶也能用」):貼上的、檔案的、
//! 從 `~/.ssh` 匯入的、在這裡產生的。都放進這台的保管庫,插槽目錄只放 `.pub`,記成只在這台的金鑰(`LocalSlot::local_only`),不寫任何帳戶記錄;
//! 之後同步的主機用到它時,由 SP3 的 Sync key 對話框收編(`slot_setup::adopt_slot`)。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config::model::{Directive, Item, SshConfigDoc};
use crate::error::AppError;
use crate::sync::dto::KeyFilePreview;
use crate::sync::env::SyncEnv;
use crate::sync::runtime::mutate;
use crate::sync::slot_files;
use crate::sync::slot_rules::{
    default_slot_name, inspect_private_key, new_slot_id, public_path, resolve_identity_value, slot_file_name, slot_value, unquote, valid_slot_name,
    IdentityTarget, KeySlotPayload, SlotMode, Unsyncable, REASON_RELATIVE, REASON_TOKENS, SLOT_DIR, SLOT_SCHEMA,
};
use crate::sync::slot_setup::{home_of, is_private_key_file, same_file};
use crate::sync::slots::{agent_refusal, in_the_way_message, live_slots, local_key_fingerprint, local_snapshot, refresh_agent, vault_unreadable_message};
use crate::sync::state_v2::{LocalSlot, SlotSource, SyncStateV2};
use crate::vault::store::{vault_path, with_vault, EntryOrigin, VaultEntry};

pub const MANAGED_FILE_MESSAGE: &str = "SSHelter already manages this file.";
pub const NOT_A_KEY_FILE_MESSAGE: &str = "This file isn't a private key.";

/// Move 留下原檔的原因(`file_kept`;主機改不了的兩個原因帶著主機名稱,在 `point_hosts_at` 組),照 `point_hosts_at` 判斷的先後:沒有載入 config、載入之後 config 在磁碟上變了、
/// 不在 Host 區塊裡的 `IdentityFile` 指到它、解析不了的 `IdentityFile` 可能指到它、它是符號連結。
pub const NO_CONFIG_MESSAGE: &str = "The file stays: SSHelter couldn't check which hosts use it (no config loaded).";
pub const CONFIG_CHANGED_MESSAGE: &str = "The file stays: your SSH config changed on disk since SSHelter loaded it.";
pub const OUTSIDE_A_HOST_BLOCK_MESSAGE: &str = "The file stays: an IdentityFile outside a Host block names it, and SSHelter only switches hosts.";
pub const UNRESOLVED_MESSAGE: &str = "The file stays: an IdentityFile SSHelter can't resolve (a token, a variable or a relative path) may name it.";
pub const LINK_MESSAGE: &str = "The file stays: it's a link to another file, so SSHelter didn't remove either.";
/// 同一件事在 Move 動手之前就看到了(`import_file`):載入的 config 和磁碟上的不一樣,什麼都沒加,重新載入之後再來一次。
pub const RELOAD_FIRST_MESSAGE: &str = "Your SSH config changed on disk since SSHelter loaded it. Reload it, then try again.";

/// 貼上的文字最多收這麼多(私鑰本身的上限是 16 KiB,`inspect_private_key`)。
const MAX_PASTE_BYTES: usize = 64 * 1024;

/// `ssh` 沒寫 `IdentityFile` 時會試的檔名(`~/.ssh/` 底下,ssh_config(5))。
const DEFAULT_IDENTITIES: [&str; 7] = ["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss", "id_dsa"];

/// 加進來之後的結果(`import_file`):新插槽、已經改指到它的主機(存好的檔案裡的;Move 寫檔到一半失敗而留下原檔時,也有前面存好的)、原檔移除了沒、Move 卻留下原檔的原因。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedKey {
    pub slot_id: String,
    pub rewritten_hosts: Vec<String>,
    pub removed_file: bool,
    pub file_kept: Option<String>,
}

/// 名稱不合規(同 `slot_setup::create_slot` 的說法)。
pub(crate) fn bad_name(name: &str) -> AppError {
    AppError::Other(format!(
        "\"{name}\" can't be used as a key name: use letters, digits, '.', '_' or '-', start with a letter or digit, and don't end with .pub"
    ))
}

/// 插槽的名稱(給「已經在 SSHelter」的訊息):payload 的名稱,沒有就用插槽檔名。
fn slot_name(local: &LocalSlot) -> String {
    local.payload.as_ref().map(|p| p.name.clone()).unwrap_or_else(|| local.file_name.clone())
}

/// 已經在 SSHelter 的同一把金鑰(同指紋)的名稱:這台保管庫裡的(`SlotSource::Vault`)、插槽裡放著同步來的副本的(`SlotSource::SyncedCopy`;帳戶裡已經沒有那個插槽、
/// 或根本沒有帳戶的時候,副本還在),或帳戶裡記著這個指紋、還在的插槽。只看狀態、不讀檔案;經連結拿著這把金鑰的插槽要讀它連到的檔案,另由 `already_linked` 看
/// (兩者合起來是 `already_held`)。
pub fn already_in_sshelter(state: &SyncStateV2, fingerprint: &str) -> Option<String> {
    let here = state.key_slots.values().find_map(|local| match &local.source {
        Some(SlotSource::Vault { fingerprint: f, .. } | SlotSource::SyncedCopy { fingerprint: f }) if f == fingerprint => Some(slot_name(local)),
        _ => None,
    });
    here.or_else(|| {
        let account = state.account.as_ref()?;
        live_slots(account).into_iter().find(|(_, p)| p.fingerprint.as_deref() == Some(fingerprint)).map(|(_, p)| p.name)
    })
}

/// 插槽經連結(`SlotSource::Linked`;例如還是「File for now」、連到使用者的 `~/.ssh/id_x` 的 `own` 插槽)拿著的金鑰,也算已經在 SSHelter:連到的檔案現在的指紋
/// (`slots::local_key_fingerprint`:OpenSSH 格式從私鑰的公開段讀,其他格式讀旁邊的 `.pub`,都不需要 passphrase)等於 `fingerprint`;或使用者選的是檔案(`file`)、而它正是
/// 某個插槽連到的(`slot_setup::same_file`),不論內容 —— 把它再加進來、Move 掉,那個插槽的連結就指著一個不見的檔案。連到的檔案現在讀不到(不見了、被換成不是私鑰的東西)
/// 就不算:那個插槽現在沒有拿著任何金鑰。收起來的連結(`LocalSlot::parked`)照算,記錄還指著那個檔案。要讀檔案(讀之前先確認它是不超過 64 KiB 的私鑰檔),
/// 所以和只看狀態的 `already_in_sshelter` 分開。回傳插槽的名稱。
pub fn already_linked(state: &SyncStateV2, fingerprint: &str, file: Option<&Path>) -> Option<String> {
    state.key_slots.values().find_map(|local| {
        let Some(SlotSource::Linked { path, .. }) = &local.source else { return None };
        let linked = Path::new(path);
        let holds_it = || is_private_key_file(linked) && local_key_fingerprint(linked).as_deref() == Some(fingerprint);
        (file.is_some_and(|picked| same_file(linked, picked)) || holds_it()).then(|| slot_name(local))
    })
}

/// 這把金鑰(`fingerprint`)已經在 SSHelter 的哪個插槽裡:這台保管庫裡的、帳戶裡同步的(`already_in_sshelter`),或經連結拿著它的(`already_linked`)。
/// `file` = 使用者選的金鑰檔(貼上的文字沒有)。
fn already_held(state: &SyncStateV2, fingerprint: &str, file: Option<&Path>) -> Option<String> {
    already_in_sshelter(state, fingerprint).or_else(|| already_linked(state, fingerprint, file))
}

fn already_message(name: &str) -> String {
    format!("This key is already in SSHelter as {name}.")
}

/// 把一把私鑰(OpenSSH 格式原文;有 passphrase 的照原樣)加進 SSHelter,成為只在這台的金鑰。回傳新插槽的 id。
/// 先檢查(名稱、格式、agent 用得了、沒有同一把 —— 保管庫裡的、帳戶裡同步的、經連結拿著的,見 `already_held` —— 、插槽路徑空著),再依序放:保管庫 → `.pub` → 狀態;
/// 後面失敗就收回前面放的。不需要帳戶;狀態存不進去的行程(`save_blocked`)在動任何東西之前就拒絕(`local_snapshot`)。
pub fn add_key(env: &SyncEnv, name: &str, text: &str, origin: EntryOrigin) -> Result<String, AppError> {
    add_key_from(env, name, text, origin, None)
}

/// `add_key`,多一個 `picked` = 使用者選的金鑰檔(`import_file`):那個檔案正是某個插槽連到的,也算已經在 SSHelter(`already_linked`)。
fn add_key_from(env: &SyncEnv, name: &str, text: &str, origin: EntryOrigin, picked: Option<&Path>) -> Result<String, AppError> {
    let (state, home) = local_snapshot(env)?;
    if !valid_slot_name(name) {
        return Err(bad_name(name));
    }
    let facts = inspect_private_key(text).map_err(|e| AppError::Other(vault_unreadable_message(e).to_string()))?;
    if let Some(message) = agent_refusal(text, &facts) {
        return Err(AppError::Other(message.to_string()));
    }
    if let Some(existing) = already_held(&state, &facts.fingerprint, picked) {
        return Err(AppError::Other(already_message(&existing)));
    }
    let id = new_slot_id()?;
    let file = slot_file_name(name, &id);
    let keys_dir = home.join(SLOT_DIR);
    let path = keys_dir.join(&file);
    if slot_files::occupied(&path) || slot_files::occupied(&public_path(&path)) {
        return Err(AppError::Other(in_the_way_message(&path)));
    }
    let now = env.now();
    let vault_file = vault_path(&env.state_path);
    let entry = VaultEntry {
        private_key: text.to_string(),
        public_key: facts.public_key.clone(),
        fingerprint: facts.fingerprint.clone(),
        origin,
        added_at_ms: now,
    };
    with_vault(env.runtime, &vault_file, env.keychain, now, |vault| vault.put(env.keychain, &id, &entry))?;
    let take_back = || {
        let _ = std::fs::remove_file(public_path(&path));
        if let Err(e) = with_vault(env.runtime, &vault_file, env.keychain, now, |vault| vault.remove(&id)) {
            eprintln!("[keys] a key that couldn't be added is still in SSHelter's vault: {e}");
        }
    };
    if let Err(e) = slot_files::ensure_keys_dir(&keys_dir).and_then(|()| slot_files::write_public(&path, &facts.public_key)) {
        take_back();
        return Err(e);
    }
    let committed = mutate(env, |s| {
        let device_id = s.device_id.clone();
        s.key_slots.insert(
            id.clone(),
            LocalSlot {
                file_name: file.clone(),
                source: Some(SlotSource::Vault {
                    fingerprint: facts.fingerprint.clone(),
                    public_key: facts.public_key.clone(),
                    has_passphrase: facts.has_passphrase,
                }),
                last_error: None,
                asked: false,
                payload: Some(KeySlotPayload {
                    schema: SLOT_SCHEMA,
                    name: name.to_string(),
                    mode: SlotMode::Own,
                    origin_device_id: device_id,
                    created_at_ms: now,
                    public_key: None,
                    fingerprint: None,
                    key_type: None,
                    has_passphrase: None,
                }),
                uploaded_fingerprint: None,
                parked: false,
                learned_in: None,
                copy_from_another_account: false,
                local_only: true,
            },
        );
        Ok(())
    });
    if let Err(e) = committed {
        // `mutate` 的錯誤分不出「被拒絕、什麼都沒改」與「改了、存檔失敗」:記錄已經在狀態裡就不收回(下一輪補存)。
        let recorded = env.runtime.core.lock().unwrap().state.as_ref().is_some_and(|s| s.key_slots.contains_key(&id));
        if !recorded {
            take_back();
        }
        return Err(e);
    }
    Ok(id)
}

/// 「New key」→ Paste:貼上的文字換行統一成 LF、去掉前後空白,結尾一個換行,再加進來(來源記成匯入)。
pub fn import_text(env: &SyncEnv, name: &str, text: &str) -> Result<String, AppError> {
    if text.len() > MAX_PASTE_BYTES {
        return Err(AppError::Other(vault_unreadable_message(Unsyncable::TooLarge).to_string()));
    }
    // 中間的那一份也含有私鑰,一樣用完就清掉。
    let unified = Zeroizing::new(text.replace("\r\n", "\n"));
    let normalized = Zeroizing::new(format!("{}\n", unified.trim()));
    add_key(env, name, &normalized, EntryOrigin::Imported)
}

/// 使用者選的金鑰檔(檔案對話框、拖放、`~/.ssh` 的「Import」):絕對路徑、私鑰檔(`slot_setup::is_private_key_file`:一般檔案、不超過 64 KiB)、
/// 不在 SSHelter 管的 `~/.ssh/sshelter/` 底下(插槽自己的檔案用「Move」)。
fn key_file(path: &str, home: &Path) -> Result<PathBuf, AppError> {
    let path = PathBuf::from(path);
    let managed = home.join(".ssh").join("sshelter");
    let inside = path.starts_with(&managed)
        || matches!((std::fs::canonicalize(&path), std::fs::canonicalize(&managed)), (Ok(p), Ok(m)) if p.starts_with(&m));
    if inside {
        return Err(AppError::Other(MANAGED_FILE_MESSAGE.to_string()));
    }
    if !path.is_absolute() || !is_private_key_file(&path) {
        return Err(AppError::Other(NOT_A_KEY_FILE_MESSAGE.to_string()));
    }
    Ok(path)
}

/// 選了檔案之後、加進去之前給畫面看的(只讀):預設名稱、指紋、類型、有沒有 passphrase、Move 會改的主機(`hosts_naming`:每一個指到它的 Host 區塊,萬用字元的也算)、
/// 是不是 `ssh` 預設會試的檔名,以及加不進去的原因(`problem`)。
pub fn preview_file(env: &SyncEnv, path: &str) -> Result<KeyFilePreview, AppError> {
    let home = home_of(env)?;
    let file_name = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut preview = KeyFilePreview {
        default_name: default_slot_name(&file_name),
        fingerprint: None,
        key_type: None,
        has_passphrase: None,
        hosts: Vec::new(),
        default_identity: false,
        problem: None,
    };
    let key = match key_file(path, &home) {
        Ok(key) => key,
        Err(e) => {
            preview.problem = Some(e.to_string());
            return Ok(preview);
        }
    };
    preview.default_identity = key.parent() == Some(env.ssh_dir.as_path()) && DEFAULT_IDENTITIES.contains(&file_name.as_str());
    preview.hosts = {
        let doc = env.doc.lock().unwrap();
        doc.as_ref().map(|doc| hosts_naming(doc, &home, &key)).unwrap_or_default()
    };
    let text = Zeroizing::new(std::fs::read_to_string(&key)?);
    match inspect_private_key(&text) {
        Err(e) => preview.problem = Some(vault_unreadable_message(e).to_string()),
        Ok(facts) => {
            preview.problem = agent_refusal(&text, &facts).map(str::to_string).or_else(|| {
                let state = crate::sync::runtime::snapshot(env)?;
                already_held(&state, &facts.fingerprint, Some(&key)).map(|name| already_message(&name))
            });
            preview.fingerprint = Some(facts.fingerprint);
            preview.key_type = Some(facts.key_type);
            preview.has_passphrase = Some(facts.has_passphrase);
        }
    }
    Ok(preview)
}

/// 「New key」→ From a file(與 `~/.ssh` 的「Import」)。`keep_file` = 「Keep the file too」:原檔與主機都不動。否則「Move into SSHelter」:
/// `IdentityFile` 指到這個檔案的主機改指到新的插槽(`point_hosts_at`),全部改好才移除原檔(只有私鑰檔;旁邊的 `.pub` 留著)。還有東西指著它、或它是符號連結
/// (`point_hosts_at` 列的原因)就一台都不改、原檔留著:金鑰照樣加進來了,`file_kept` 說明原因。這個檔案正是某個插槽連到的(`already_linked`)則根本不加。
/// Move 還要先確認載入的 config 沒有在磁碟上變過(`config_changed`):畫面還沒重新載入的外部編輯可能加了一台指到這個檔案的主機,Move 看不到它,刪掉檔案那一台就壞了。
/// 變過就在動任何東西之前拒絕(`RELOAD_FIRST_MESSAGE`,什麼都沒加)。Keep the file too 不動主機,不受影響。
pub fn import_file(env: &SyncEnv, name: &str, path: &str, keep_file: bool) -> Result<ImportedKey, AppError> {
    import_file_with(env, name, path, keep_file, crate::config::commands::persist_file)
}

/// `import_file`,Move 存主機所在的檔案的動作由 `persist` 給(同 `persist_file`;測試用它讓某個檔案存不成)。
fn import_file_with(
    env: &SyncEnv,
    name: &str,
    path: &str,
    keep_file: bool,
    persist: impl FnMut(&mut SshConfigDoc, usize, &mut HashSet<PathBuf>, Option<usize>) -> Result<(), AppError>,
) -> Result<ImportedKey, AppError> {
    let home = home_of(env)?;
    let key = key_file(path, &home)?;
    if !keep_file && env.doc.lock().unwrap().as_ref().is_some_and(config_changed) {
        return Err(AppError::Other(RELOAD_FIRST_MESSAGE.to_string()));
    }
    let text = Zeroizing::new(std::fs::read_to_string(&key)?);
    let slot_id = add_key_from(env, name, &text, EntryOrigin::Imported, Some(&key))?;
    let mut imported = ImportedKey { slot_id: slot_id.clone(), rewritten_hosts: Vec::new(), removed_file: false, file_kept: None };
    if keep_file {
        return Ok(imported);
    }
    match point_hosts_at(env, &home, &key, &slot_file_name(name, &slot_id), persist) {
        Ok(rewritten) => imported.rewritten_hosts = rewritten,
        Err(kept) => {
            imported.rewritten_hosts = kept.switched;
            imported.file_kept = Some(kept.reason);
            return Ok(imported);
        }
    }
    match std::fs::remove_file(&key) {
        Ok(()) => imported.removed_file = true,
        Err(e) => imported.file_kept = Some(format!("The file stays: it couldn't be removed ({e}).")),
    }
    Ok(imported)
}

/// 「Generate key」:在 SSHelter 裡產生一把金鑰(`vault::generate`),加進來成為只在這台的金鑰(來源記成產生的)。名稱先檢查:產生 RSA 要幾秒,
/// 不要白做。
pub fn generate_key(
    env: &SyncEnv,
    name: &str,
    algorithm: crate::vault::generate::KeyAlgorithm,
    comment: &str,
    passphrase: Option<&str>,
) -> Result<String, AppError> {
    if !valid_slot_name(name) {
        return Err(bad_name(name));
    }
    let text = crate::vault::generate::generate(algorithm, comment, passphrase)?;
    add_key(env, name, &text, EntryOrigin::Generated)
}

/// 主機名稱的清單(訊息用)。
fn names(aliases: &[String]) -> String {
    aliases.join(", ")
}

/// 把 `alias` 放進 `list`(已經有就不放)。
fn push_unique(list: &mut Vec<String>, alias: &str) {
    if !list.iter().any(|a| a == alias) {
        list.push(alias.to_string());
    }
}

/// 這一行是不是生效中的 `IdentityFile`、而且指到 `key`(值的解析同主機的 `IdentityFile`,`slot_setup::same_file` 認同一個檔案;寫出來會變成註解的行不算)。
/// 預覽(`hosts_naming`)與 Move(`point_hosts_at`)都靠這一個判斷,兩邊不會各說各的。
fn names_the_key(d: &Directive, home: &Path, key: &Path) -> bool {
    d.key == "identityfile"
        && !d.serializes_as_comment()
        && matches!(resolve_identity_value(&d.value, home), IdentityTarget::File(target) if same_file(&target, key))
}

/// Host 區塊裡一行指到金鑰檔的 `IdentityFile`:那一行在 doc 裡的位置(檔案、區塊、行),與區塊的 pattern。
struct NamingLine {
    file_idx: usize,
    item_idx: usize,
    line_idx: usize,
    patterns: Vec<String>,
}

impl NamingLine {
    /// 主機的名稱:區塊的第一個 pattern(萬用字元的 Host 也是)。
    fn alias(&self) -> String {
        self.patterns.first().cloned().unwrap_or_default()
    }
}

/// doc 裡每一個 Host 區塊(載入的每一個檔案)的、指到 `key` 的 `IdentityFile`,依出現順序。一台主機可以有好幾行,同名的主機也可以有好幾份。
fn host_lines_naming(doc: &SshConfigDoc, home: &Path, key: &Path) -> Vec<NamingLine> {
    let mut out = Vec::new();
    for (file_idx, file) in doc.files.iter().enumerate() {
        for (item_idx, item) in file.items.iter().enumerate() {
            let Item::Host(host) = item else { continue };
            for (line_idx, line) in host.body.iter().enumerate() {
                if matches!(line, Item::Directive(d) if names_the_key(d, home, key)) {
                    out.push(NamingLine { file_idx, item_idx, line_idx, patterns: host.patterns.clone() });
                }
            }
        }
    }
    out
}

/// 給畫面看的主機(`KeyFilePreview::hosts`):`host_lines_naming` 的主機名稱,依出現順序、不重複。沒有東西擋著的時候,Move 改的就是這些(`point_hosts_at`)。
fn hosts_naming(doc: &SshConfigDoc, home: &Path, key: &Path) -> Vec<String> {
    let mut hosts = Vec::new();
    for line in host_lines_naming(doc, home, key) {
        push_unique(&mut hosts, &line.alias());
    }
    hosts
}

/// 不在 Host 區塊裡、指到 `key` 的 `IdentityFile`:載入的任何一個檔案最上層的指令,或 `Match` 區塊裡的。Move 只改主機,改不了這樣的行。
fn names_outside_hosts(doc: &SshConfigDoc, home: &Path, key: &Path) -> bool {
    let names_it = |item: &Item| matches!(item, Item::Directive(d) if names_the_key(d, home, key));
    doc.files.iter().any(|file| {
        file.items.iter().any(|item| match item {
            Item::Match(block) => block.body.iter().any(|line| names_it(line)),
            other => names_it(other),
        })
    })
}

/// 路徑本身是符號連結(`symlink_metadata`:不跟著連結走)。
fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// 載入的 config 和磁碟上的不一樣了(外面的編輯器改過,畫面還沒重新載入):用 app 自己的比對(`config::commands::drift`:載入的每一個檔案 —— Include 進來的也是 ——
/// 目前的內容雜湊對載入時的指紋),比不了(出錯)也算變了。
fn config_changed(doc: &SshConfigDoc) -> bool {
    crate::config::commands::drift(doc).map_or(true, |files| files.iter().any(|file| file.changed))
}

/// 解析不了的 `IdentityFile` 值(`resolve_identity_value` 回 `REASON_TOKENS`:有 `%` token 或 `${VAR}`;或 `REASON_RELATIVE`:相對路徑、`~user/…`)。
/// 指到公鑰(`.pub`)的值不算:它指的不是私鑰檔。
fn is_unresolvable(value: &str, home: &Path) -> bool {
    matches!(resolve_identity_value(value, home), IdentityTarget::Unsupported(reason) if reason == REASON_TOKENS || reason == REASON_RELATIVE)
}

/// 解析不了的 `IdentityFile` 值「可能指到哪些路徑」,寫成 glob pattern(`*` = 什麼都可能,可以跨 `/`;其餘的字元都照字面,以 `glob::Pattern::escape` 跳脫)。
/// 保守:寧可多留一個檔案,也不能刪掉 ssh 還要開的檔案。
/// - 看得懂的先展開:開頭的 `~/`、`%d`、`${HOME}` 是家目錄,`%%` 是一個 `%`;
/// - 其他的 `%` token(`%h`、`%r`……)與 `${VAR}` 換成 `*`;
/// - 相對路徑(ssh 從當時的工作目錄找起)與 `~user/…`(別人的家目錄,也可能就是這個人)換成 `*/<其餘>`,相對路徑開頭的 `./` 與 `../` 先去掉。
/// 兩種分隔字元都當成 `/`(同步的設定可能來自另一種平台)。
fn identity_pattern(value: &str, home: &Path) -> String {
    enum Piece {
        Text(String),
        Any,
    }
    fn text(pieces: &mut Vec<Piece>, more: &str) {
        match pieces.last_mut() {
            Some(Piece::Text(t)) => t.push_str(more),
            _ => pieces.push(Piece::Text(more.to_string())),
        }
    }
    fn any(pieces: &mut Vec<Piece>) {
        if !matches!(pieces.last(), Some(Piece::Any)) {
            pieces.push(Piece::Any);
        }
    }
    let home = home.to_string_lossy().replace('\\', "/");
    let value = unquote(value).replace('\\', "/");
    let mut pieces: Vec<Piece> = Vec::new();
    let mut rest = value.as_str();
    let mut anchored = true; // 路徑從哪裡開始是確定的(或已經是 `*`)
    if let Some(after) = rest.strip_prefix("~/") {
        text(&mut pieces, &format!("{home}/"));
        rest = after;
    } else if rest.starts_with('~') {
        any(&mut pieces);
        text(&mut pieces, "/");
        rest = rest.split_once('/').map_or("", |(_, tail)| tail);
    } else {
        anchored = false; // 先掃完再看是不是相對路徑
    }
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' => match chars.next() {
                Some('%') => text(&mut pieces, "%"),
                Some('d') => text(&mut pieces, &home),
                _ => any(&mut pieces),
            },
            '$' if chars.peek() == Some(&'{') => {
                chars.next();
                let name: String = chars.by_ref().take_while(|&ch| ch != '}').collect();
                if name == "HOME" {
                    text(&mut pieces, &home);
                } else {
                    any(&mut pieces);
                }
            }
            c => text(&mut pieces, c.encode_utf8(&mut [0; 4])),
        }
    }
    if !anchored {
        let absolute = match pieces.first() {
            Some(Piece::Any) => true,
            Some(Piece::Text(t)) => t.starts_with('/') || matches!(t.as_bytes(), [drive, b':', b'/', ..] if drive.is_ascii_alphabetic()),
            None => false,
        };
        if !absolute {
            if let Some(Piece::Text(t)) = pieces.first_mut() {
                let mut trimmed = t.as_str();
                while let Some(tail) = trimmed.strip_prefix("./").or_else(|| trimmed.strip_prefix("../")) {
                    trimmed = tail;
                }
                *t = trimmed.to_string();
            }
            let mut prefixed = vec![Piece::Any, Piece::Text("/".to_string())];
            prefixed.extend(pieces);
            pieces = prefixed;
        }
    }
    pieces
        .iter()
        .map(|piece| match piece {
            Piece::Text(t) => glob::Pattern::escape(t),
            Piece::Any => "*".to_string(),
        })
        .collect()
}

/// `key` 的路徑(寫成 pattern 比對用):選的那個路徑,與解開連結之後的真正路徑(不一樣的話)。分隔字元都換成 `/`。
fn key_forms(key: &Path) -> Vec<String> {
    let mut forms = vec![key.to_string_lossy().replace('\\', "/")];
    if let Ok(real) = std::fs::canonicalize(key) {
        let real = real.to_string_lossy().replace('\\', "/");
        if !forms.contains(&real) {
            forms.push(real);
        }
    }
    forms
}

/// 解析不了的 `IdentityFile` 值可不可能指到金鑰檔(`key_forms`):`identity_pattern` 對得到其中一個路徑(不分大小寫 —— macOS 與 Windows 的檔案系統不分)。
/// pattern 自己組不起來就當成可能:寧可多留一個檔案。
fn could_name(value: &str, home: &Path, key_forms: &[String]) -> bool {
    let options = glob::MatchOptions { case_sensitive: false, require_literal_separator: false, require_literal_leading_dot: false };
    glob::Pattern::new(&identity_pattern(value, home)).map_or(true, |pattern| key_forms.iter().any(|form| pattern.matches_with(form, options)))
}

/// 載入的任何一個檔案裡 —— Host 區塊、`Match` 區塊或最上層 —— 有一行生效中的 `IdentityFile` 是解析不了的(`is_unresolvable`)、而且可能指到 `key`(`could_name`)。
/// 寫出來會變成註解的行不算。Move 認不出這樣的行指到哪裡,也就改不了它,留著檔案是唯一不會讓 ssh 找不到金鑰的做法。
fn unresolved_may_name(doc: &SshConfigDoc, home: &Path, key: &Path) -> bool {
    let forms = key_forms(key);
    let may = |item: &Item| {
        matches!(item, Item::Directive(d)
            if d.key == "identityfile" && !d.serializes_as_comment() && is_unresolvable(&d.value, home) && could_name(&d.value, home, &forms))
    };
    doc.files.iter().any(|file| {
        file.items.iter().any(|item| match item {
            Item::Host(host) => host.body.iter().any(|line| may(line)),
            Item::Match(block) => block.body.iter().any(|line| may(line)),
            other => may(other),
        })
    })
}

/// Move 沒有全部做成時的結果(`point_hosts_at`):原檔留著的原因,與已經改好、存好的主機。原因在改寫之前就看完的話沒有主機;寫檔失敗的話,前面存好的檔案裡的主機已經改指到
/// 新的插槽了(畫面要知道,才能問同步的那些),`reason` 只說沒存成的。
struct Kept {
    reason: String,
    switched: Vec<String>,
}

impl Kept {
    /// 在改寫之前就決定原檔要留著:沒有任何主機改過。
    fn because(reason: impl Into<String>) -> Kept {
        Kept { reason: reason.into(), switched: Vec::new() }
    }
}

/// 要改的一行 `IdentityFile`:在 doc 裡的位置,與主機的名稱。
struct Target {
    file_idx: usize,
    item_idx: usize,
    line_idx: usize,
    alias: String,
}

/// `switch_and_save` 的結果:存好的檔案裡改過的主機(依出現順序、不重複),與第一個存失敗的檔案(連同它後面沒存的檔案)裡的主機和原因。
struct Saved {
    switched: Vec<String>,
    failed: Option<(Vec<String>, AppError)>,
}

/// 把 `targets` 那幾行的值改成 `value`,再一個檔案一個檔案存(`persist`)。第一個存失敗的檔案就停下來:它和後面的檔案沒存,它們的主機算沒改成;前面存好的留著。
fn switch_and_save(
    doc: &mut SshConfigDoc,
    targets: &[Target],
    value: &str,
    mut persist: impl FnMut(&mut SshConfigDoc, usize) -> Result<(), AppError>,
) -> Saved {
    for target in targets {
        if let Item::Host(host) = &mut doc.files[target.file_idx].items[target.item_idx] {
            if let Item::Directive(d) = &mut host.body[target.line_idx] {
                d.value = value.to_string();
                d.dirty = true;
            }
        }
    }
    let mut files: Vec<usize> = targets.iter().map(|target| target.file_idx).collect();
    files.dedup();
    let hosts_in = |files: &[usize]| {
        let mut hosts = Vec::new();
        for target in targets.iter().filter(|target| files.contains(&target.file_idx)) {
            push_unique(&mut hosts, &target.alias);
        }
        hosts
    };
    for (n, &file_idx) in files.iter().enumerate() {
        if let Err(error) = persist(doc, file_idx) {
            return Saved { switched: hosts_in(&files[..n]), failed: Some((hosts_in(&files[n..]), error)) };
        }
    }
    Saved { switched: hosts_in(&files), failed: None }
}

/// 「Move into SSHelter」:載入的每個 config 檔裡,生效的 `IdentityFile` 指到 `key` 的主機改指到插槽 `slot_file`。全有或全無 —— 下面任何一個原因成立,就一台都不改、
/// 回 `Err`(原因),原檔留著(原因在改寫之前就全部看完;依這個順序,同時有好幾個就說最前面的):
/// - 沒有載入 config(`NO_CONFIG_MESSAGE`):看不出哪些主機用到這個檔案,不能當成沒有。
/// - 載入之後 config 在磁碟上變了(`CONFIG_CHANGED_MESSAGE`,`config_changed`):`import_file` 已經先擋過一次(那時什麼都還沒加),這裡是動手前的最後一次確認,在 doc 鎖裡。
///   外面的程式在這之後才改的,`persist_file` 自己的衝突檢查還會擋(下面的寫檔失敗)。
/// - 同名的主機不只一份(改哪一份都不對,同 SP3 的 `slot_setup::rewrite_in`)。
/// - 在勾選了而第一輪還沒跑完的 space 裡(第一輪以 chain 為準,改了會被蓋回去)。
/// - 不在 Host 區塊裡的 `IdentityFile` 指到它(`OUTSIDE_A_HOST_BLOCK_MESSAGE`:檔案最上層或 `Match` 區塊裡),Move 只改主機,原檔一刪那一行就指著不見的檔案。
/// - 解析不了的 `IdentityFile`(token、變數、相對路徑)可能指到它(`UNRESOLVED_MESSAGE`,`unresolved_may_name`)。
/// - 它是符號連結(`LINK_MESSAGE`):連結和它指到的檔案都不動。
/// 寫檔失敗(`switch_and_save`):已存好的檔案留著,記憶體裡的 doc 重載,回 `Err`:`reason` 只名沒存成的主機,`switched` 是存好的檔案裡的主機。只要有檔案存好了(不論後面有沒有失敗),
/// 之後就更新 agent 的設定(那些主機改走 agent)。成功回傳改了的主機(依出現順序、不重複)。存檔的動作由 `persist` 給(同 `persist_file`;測試用它讓某個檔案存不成)。
/// 鎖:先拿 doc、backed_up,勾選的 space 在持有 doc 鎖時才取(短暫拿 core 鎖,同 `slot_setup::rewrite_hosts`:第一輪的旗標在 doc 鎖裡改,取了清單之後才有人退回
/// 基線輪的話,改寫就白費了);存檔 hook 只拿 core。
fn point_hosts_at(
    env: &SyncEnv,
    home: &Path,
    key: &Path,
    slot_file: &str,
    mut persist: impl FnMut(&mut SshConfigDoc, usize, &mut HashSet<PathBuf>, Option<usize>) -> Result<(), AppError>,
) -> Result<Vec<String>, Kept> {
    let result = {
        let mut doc_lock = env.doc.lock().unwrap();
        let mut backed_up = env.backed_up.lock().unwrap();
        let retention = env.retention();
        let selected: Vec<PathBuf> = crate::sync::migrate::selected_space_files(env.runtime, &env.ssh_dir).into_iter().map(|(_, p)| p).collect();
        let ready: Vec<PathBuf> = crate::sync::slot_setup::ready_space_files(env).into_iter().map(|(_, p)| p).collect();
        let Some(doc) = doc_lock.as_mut() else { return Err(Kept::because(NO_CONFIG_MESSAGE)) };
        if config_changed(doc) {
            return Err(Kept::because(CONFIG_CHANGED_MESSAGE));
        }
        let counts = crate::sync::slot_setup::alias_counts(doc);
        let (mut targets, mut locked, mut not_ready) = (Vec::<Target>::new(), Vec::<String>::new(), Vec::<String>::new());
        for line in host_lines_naming(doc, home, key) {
            let alias = line.alias();
            let file_path = &doc.files[line.file_idx].path;
            if crate::sync::slot_setup::locked(&line.patterns, &counts) {
                push_unique(&mut locked, &alias);
            } else if selected.contains(file_path) && !ready.contains(file_path) {
                push_unique(&mut not_ready, &alias);
            } else {
                targets.push(Target { file_idx: line.file_idx, item_idx: line.item_idx, line_idx: line.line_idx, alias });
            }
        }
        if !locked.is_empty() {
            return Err(Kept::because(format!("The file stays: {} have more than one copy, so SSHelter didn't change them.", names(&locked))));
        }
        if !not_ready.is_empty() {
            return Err(Kept::because(format!("The file stays: {} are in a space that hasn't finished its first sync.", names(&not_ready))));
        }
        if names_outside_hosts(doc, home, key) {
            return Err(Kept::because(OUTSIDE_A_HOST_BLOCK_MESSAGE));
        }
        if unresolved_may_name(doc, home, key) {
            return Err(Kept::because(UNRESOLVED_MESSAGE));
        }
        if is_link(key) {
            return Err(Kept::because(LINK_MESSAGE));
        }
        let main_path = doc.files[0].path.clone();
        let saved = switch_and_save(doc, &targets, &slot_value(slot_file), |doc, idx| persist(doc, idx, &mut backed_up, retention));
        match saved.failed {
            None => Ok(saved.switched),
            Some((not_switched, error)) => {
                drop(backed_up);
                *doc_lock = env.load_doc(&main_path).ok();
                Err(Kept { reason: format!("The file stays: {} couldn't be switched ({error}).", names(&not_switched)), switched: saved.switched })
            }
        }
    };
    // 走到這裡的 `Err` 一定是寫檔失敗(其他原因在上面就 `return` 了,什麼都沒動):doc 可能重載過、也可能有檔案已經改了,通知畫面。
    let changed = match &result {
        Ok(hosts) => !hosts.is_empty(),
        Err(_) => true,
    };
    if changed {
        env.events.applied(0);
    }
    let switched_any = match &result {
        Ok(hosts) => !hosts.is_empty(),
        Err(kept) => !kept.switched.is_empty(),
    };
    if switched_any {
        refresh_agent(env);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::round::tests::{pair, settle};
    use crate::sync::runtime::mutate;
    use crate::sync::slot_rules::{public_path, slot_value, test_keys, SlotMode, SLOT_DIR};
    use crate::sync::slots::tests::{create_slot_on, overview_row, vault_entry};
    use crate::sync::slots::{slot_record_exists, VAULT_KEY_TYPE_MESSAGE};
    use crate::sync::state_v2::SlotSource;
    use crate::sync::testkit::{TestClock, TestDevice};
    use crate::vault::store::EntryOrigin;

    fn device(main: &str) -> TestDevice {
        TestDevice::with_main_config("mac", &FakeRelay::new(), &TestClock::new(), main)
    }

    fn key_file(d: &TestDevice, name: &str, text: &str) -> std::path::PathBuf {
        let path = d.ssh_dir().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn slot_dir_files(d: &TestDevice) -> Vec<String> {
        std::fs::read_dir(d.home.path().join(SLOT_DIR))
            .map(|dir| dir.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default()
    }

    /// 貼上的私鑰:換行統一、前後空白去掉,放進保管庫(來源記成匯入),插槽目錄只有 `.pub`,記錄是只在這台的金鑰。
    #[test]
    fn a_pasted_key_becomes_a_key_only_on_this_computer() {
        let d = device("# main\n");
        let pasted = format!("\n\n{}\n  ", test_keys::plain().replace('\n', "\r\n"));
        let id = import_text(&d.env(), "laptop", &pasted).unwrap();

        let entry = vault_entry(&d, &id).expect("in the vault");
        assert_eq!(entry.private_key, test_keys::plain());
        assert_eq!(entry.origin, EntryOrigin::Imported);
        let local = d.state().key_slots[&id].clone();
        assert!(local.local_only);
        assert_eq!(local.learned_in, None);
        assert_eq!(local.payload.as_ref().map(|p| (p.name.as_str(), p.mode)), Some(("laptop", SlotMode::Own)));
        assert!(matches!(&local.source, Some(SlotSource::Vault { fingerprint, has_passphrase: false, .. }) if fingerprint == test_keys::PLAIN_FINGERPRINT));
        let slot = d.home.path().join(SLOT_DIR).join(&local.file_name);
        assert!(!slot.exists(), "only the .pub is in the slot folder");
        assert_eq!(std::fs::read_to_string(public_path(&slot)).unwrap().trim(), test_keys::PLAIN_PUBLIC);
    }

    /// 有 passphrase 的私鑰照原樣放進去(仍是加密的)。
    #[test]
    fn a_pasted_key_with_a_passphrase_keeps_it() {
        let d = device("# main\n");
        let id = import_text(&d.env(), "work", &test_keys::encrypted()).unwrap();
        assert!(matches!(d.state().key_slots[&id].source, Some(SlotSource::Vault { has_passphrase: true, .. })));
        assert_eq!(vault_entry(&d, &id).unwrap().private_key, test_keys::encrypted());
    }

    /// 不是私鑰的文字、agent 用不了的金鑰、不合規的名稱:拒絕,什麼都不寫。
    #[test]
    fn what_cant_go_into_the_vault_is_refused_and_nothing_is_written() {
        let d = device("# main\n");
        let before = d.state();
        let refused = |name: &str, text: &str| import_text(&d.env(), name, text).unwrap_err().to_string();
        assert_eq!(refused("laptop", "hello"), "This isn't an OpenSSH private key SSHelter can read.");
        assert_eq!(refused("sk", &test_keys::security_key()), VAULT_KEY_TYPE_MESSAGE);
        assert_eq!(
            refused("my key", &test_keys::plain()),
            "\"my key\" can't be used as a key name: use letters, digits, '.', '_' or '-', start with a letter or digit, and don't end with .pub"
        );
        assert_eq!(d.state(), before);
        assert!(slot_dir_files(&d).is_empty());
        assert!(crate::vault::store::stored_ids(&crate::vault::store::vault_path(&d.env().state_path)).unwrap().is_empty());
    }

    /// 同一把金鑰不加第二次:說它已經叫什麼(這台保管庫裡的,或帳戶裡同步的插槽)。
    #[test]
    fn the_same_key_twice_is_refused_with_its_name() {
        let d = device("# main\n");
        import_text(&d.env(), "laptop", &test_keys::plain()).unwrap();
        assert_eq!(import_text(&d.env(), "again", &test_keys::plain()).unwrap_err().to_string(), "This key is already in SSHelter as laptop.");

        let (_relay, _clock, a, _b, _words, _personal) = pair();
        create_slot_on(&a, SlotMode::Synced, &test_keys::ecdsa(), "id_ec");
        assert_eq!(import_text(&a.env(), "copy", &test_keys::ecdsa()).unwrap_err().to_string(), "This key is already in SSHelter as id_ec.");
    }

    /// 在帳戶裡加進來的金鑰也不寫任何帳戶記錄。
    #[test]
    fn a_key_added_while_joined_stays_out_of_the_account() {
        let (_relay, _clock, a, _b, _words, _personal) = pair();
        let id = import_text(&a.env(), "laptop", &test_keys::plain()).unwrap();
        settle(&a);
        assert!(!slot_record_exists(a.state().account.as_ref().unwrap(), &id));
        assert!(overview_row(&a, &id).unwrap().local_only);
    }

    /// Generate key:產生的金鑰成為只在這台的金鑰,來源記成產生的;名稱不合規在產生之前就拒絕。
    #[test]
    fn a_generated_key_is_a_key_only_on_this_computer() {
        let d = device("# main\n");
        let id = generate_key(&d.env(), "id_ed25519", crate::vault::generate::KeyAlgorithm::Ed25519, "me@laptop", None).unwrap();
        assert!(d.state().key_slots[&id].local_only);
        assert_eq!(vault_entry(&d, &id).unwrap().origin, EntryOrigin::Generated);
        assert!(generate_key(&d.env(), "bad name", crate::vault::generate::KeyAlgorithm::Ed25519, "", None).is_err());
    }

    /// 產生時給了 passphrase:保管庫裡放的是加密的私鑰,記錄註明有 passphrase,agent 用這個 passphrase 打得開(加密方式在它解得開的清單上)。
    #[test]
    fn a_generated_key_with_a_passphrase_is_kept_encrypted() {
        let d = device("# main\n");
        let id = generate_key(&d.env(), "work", crate::vault::generate::KeyAlgorithm::Ed25519, "me@laptop", Some("correct horse")).unwrap();
        assert!(matches!(d.state().key_slots[&id].source, Some(SlotSource::Vault { has_passphrase: true, .. })));
        let entry = vault_entry(&d, &id).unwrap();
        assert!(crate::vault::material::is_encrypted(&entry.private_key));
        assert!(crate::vault::material::open(&entry.private_key, Some("correct horse")).is_ok());
    }

    /// Keep the file too:原檔、主機都不動。
    #[test]
    fn keeping_the_file_changes_no_host() {
        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        let imported = import_file(&d.env(), "work", &file.display().to_string(), true).unwrap();
        assert!(file.exists());
        assert!(!imported.removed_file);
        assert!(imported.rewritten_hosts.is_empty());
        assert!(d.main_config().contains("IdentityFile ~/.ssh/id_work"));
    }

    /// Move into SSHelter:用到這個檔案的主機改指到新的插槽,原檔移除,`.pub` 留著。
    #[test]
    fn moving_switches_the_hosts_then_removes_the_file() {
        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\nHost db\n  User me\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        std::fs::write(d.ssh_dir().join("id_work.pub"), format!("{}\n", test_keys::PLAIN_PUBLIC)).unwrap();
        let imported = import_file(&d.env(), "work", &file.display().to_string(), false).unwrap();

        assert_eq!(imported.rewritten_hosts, vec!["web".to_string()]);
        assert!(imported.removed_file);
        assert_eq!(imported.file_kept, None);
        assert!(!file.exists());
        assert!(d.ssh_dir().join("id_work.pub").exists(), "the .pub next to it stays");
        let slot_file = d.state().key_slots[&imported.slot_id].file_name.clone();
        assert!(d.main_config().contains(&format!("IdentityFile {}", slot_value(&slot_file))));
    }

    /// 同名的主機有好幾份:一台都不改,原檔留著,金鑰照樣加進來了,說明原因。
    #[test]
    fn a_host_with_several_copies_keeps_the_file() {
        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\nHost web\n  User me\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        let imported = import_file(&d.env(), "work", &file.display().to_string(), false).unwrap();

        assert!(file.exists());
        assert!(!imported.removed_file);
        assert!(imported.rewritten_hosts.is_empty());
        assert_eq!(imported.file_kept.as_deref(), Some("The file stays: web have more than one copy, so SSHelter didn't change them."));
        assert!(d.main_config().contains("IdentityFile ~/.ssh/id_work"));
        assert!(d.state().key_slots.contains_key(&imported.slot_id));
    }

    /// 還沒跑完第一輪的 space 裡的主機:不改(第一輪會把它蓋回去),原檔留著。
    #[test]
    fn a_host_in_a_space_before_its_first_sync_keeps_the_file() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_work\n");
        mutate(&a.env(), |s| {
            s.spaces.get_mut(&personal).unwrap().baseline_established = false;
            Ok(())
        })
        .unwrap();
        let file = key_file(&a, "id_work", &test_keys::plain());
        let imported = import_file(&a.env(), "work", &file.display().to_string(), false).unwrap();

        assert!(file.exists());
        assert_eq!(imported.file_kept.as_deref(), Some("The file stays: web are in a space that hasn't finished its first sync."));
    }

    /// SSHelter 自己管的檔案(插槽目錄裡的)不從這裡加:插槽的檔案用 Move。
    #[test]
    fn a_file_sshelter_manages_is_refused() {
        let d = device("# main\n");
        let dir = d.home.path().join(SLOT_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let managed = dir.join("id_mac-3fa2c1d9");
        std::fs::write(&managed, test_keys::plain()).unwrap();
        assert_eq!(import_file(&d.env(), "x", &managed.display().to_string(), true).unwrap_err().to_string(), MANAGED_FILE_MESSAGE);
        assert_eq!(import_file(&d.env(), "x", "/no/such/key", true).unwrap_err().to_string(), NOT_A_KEY_FILE_MESSAGE);
    }

    /// 預覽:預設名稱、指紋、用到它的主機、`ssh` 預設會試的檔名;加不進去的原因。
    #[test]
    fn the_preview_says_what_adding_the_file_would_do() {
        let d = device("Host web\n  IdentityFile ~/.ssh/id_ed25519\n");
        let file = key_file(&d, "id_ed25519", &test_keys::plain());
        let preview = preview_file(&d.env(), &file.display().to_string()).unwrap();
        assert_eq!(preview.default_name, "id_ed25519");
        assert_eq!(preview.fingerprint.as_deref(), Some(test_keys::PLAIN_FINGERPRINT));
        assert_eq!(preview.key_type.as_deref(), Some("ssh-ed25519"));
        assert_eq!(preview.has_passphrase, Some(false));
        assert_eq!(preview.hosts, vec!["web".to_string()]);
        assert!(preview.default_identity);
        assert_eq!(preview.problem, None);

        import_text(&d.env(), "laptop", &test_keys::plain()).unwrap();
        let again = preview_file(&d.env(), &file.display().to_string()).unwrap();
        assert_eq!(again.problem.as_deref(), Some("This key is already in SSHelter as laptop."));
    }

    // ── 計畫沒有逐字列出的情形:收回、全有或全無、寫檔失敗、預覽的原因 ───────────────────────────────────────────

    fn vault_entries(d: &TestDevice) -> usize {
        crate::vault::store::stored_ids(&crate::vault::store::vault_path(&d.env().state_path)).unwrap().len()
    }

    /// 加進來的金鑰沒有帳戶也被本機維護照顧:一次同步嘗試之後記錄原封不動、沒有錯誤。
    #[test]
    fn an_added_key_is_left_as_it_is_by_a_sync_attempt_without_an_account() {
        let d = device("# main\n");
        let id = import_text(&d.env(), "laptop", &test_keys::plain()).unwrap();
        let before = d.state().key_slots[&id].clone();
        settle(&d);
        assert_eq!(d.state().key_slots[&id], before);
        assert_eq!(before.last_error, None);
    }

    /// 狀態存不進去的行程(`save_blocked`)在動任何東西之前就拒絕:保管庫、插槽目錄、狀態都沒有變。
    #[test]
    fn a_process_that_cannot_save_the_state_adds_nothing() {
        let d = device("# main\n");
        d.runtime.core.lock().unwrap().save_blocked = Some("left in place".to_string());
        let before = d.state();
        assert_eq!(import_text(&d.env(), "laptop", &test_keys::plain()).unwrap_err().to_string(), "left in place");
        assert_eq!(d.state(), before);
        assert!(!d.home.path().join(SLOT_DIR).exists(), "the slot folder wasn't even made");
        assert!(!crate::vault::store::vault_path(&d.env().state_path).exists(), "the vault wasn't even opened for writing");
    }

    /// 記錄被拒絕提交(這裡是 v1 升級還沒完成,`mutate` 什麼都不改):先放好的保管庫那一筆與 `.pub` 都收回,不留下沒有記錄用到的東西。
    #[test]
    fn a_key_whose_record_is_refused_is_taken_back() {
        let d = device("# main\n");
        d.runtime.core.lock().unwrap().legacy = Some(crate::sync::state::SyncState::fresh("mac").unwrap());
        let refused = import_text(&d.env(), "laptop", &test_keys::plain()).unwrap_err().to_string();
        assert_eq!(refused, crate::sync::runtime::UPGRADING_MESSAGE);
        assert!(d.state().key_slots.is_empty());
        assert!(slot_dir_files(&d).is_empty(), "the .pub went again");
        assert_eq!(vault_entries(&d), 0, "and so did the vault entry");
    }

    /// 記錄已經改進記憶體、只是狀態檔寫不進去(`mutate` 的錯誤分不出這兩種):金鑰留著、回錯誤,下一輪補存 —— 不收回保管庫那一筆與 `.pub`,記錄才不會指著不見的東西。
    #[test]
    fn a_key_stays_when_only_saving_the_state_fails() {
        let d = device("# main\n");
        // 狀態檔的位置被一個資料夾佔住:存不了(任何平台、包括 root 都一樣),旁邊的保管庫檔照常寫得進去。
        std::fs::create_dir_all(&d.env().state_path).unwrap();
        assert!(import_text(&d.env(), "laptop", &test_keys::plain()).is_err(), "the state could not be saved");

        assert!(d.runtime.core.lock().unwrap().unsaved, "the next round saves it");
        let state = d.state();
        let (id, local) = state.key_slots.iter().next().expect("the record is in memory");
        assert!(vault_entry(&d, id).is_some(), "the vault entry is still there");
        assert!(public_path(&d.home.path().join(SLOT_DIR).join(&local.file_name)).exists(), "and so is the .pub");
    }

    /// 加不進去的金鑰(名稱不合規、已經在 SSHelter),它的檔案與用到它的主機一個都不動,也不說成功。
    #[test]
    fn a_file_that_cant_be_added_is_left_alone_with_its_hosts() {
        let main = "Host web\n  IdentityFile ~/.ssh/id_work\n";
        let d = device(main);
        let file = key_file(&d, "id_work", &test_keys::plain());
        let path = file.display().to_string();

        assert_eq!(import_file(&d.env(), "my key", &path, false).unwrap_err().to_string(), bad_name("my key").to_string());
        import_text(&d.env(), "laptop", &test_keys::plain()).unwrap();
        assert_eq!(import_file(&d.env(), "work", &path, false).unwrap_err().to_string(), "This key is already in SSHelter as laptop.");

        assert!(file.exists());
        assert_eq!(d.main_config(), main);
        assert_eq!(d.state().key_slots.len(), 1, "only the pasted one is in the state");
        assert_eq!(slot_dir_files(&d).len(), 1, "and has the only .pub in the slot folder");
        assert_eq!(vault_entries(&d), 1, "and the only entry in the vault");
    }

    /// 貼上的文字太大(超過 64 KiB 就不看內容)或私鑰超過 16 KiB:同一句話拒絕,什麼都不寫。
    #[test]
    fn a_paste_that_is_too_large_is_refused() {
        let d = device("# main\n");
        let message = "This key is larger than 16 KiB, which SSHelter's vault doesn't take.";
        assert_eq!(import_text(&d.env(), "big", &"a".repeat(64 * 1024 + 1)).unwrap_err().to_string(), message);
        assert_eq!(import_text(&d.env(), "big", &format!("{}\n{}\n", test_keys::BEGIN, "a".repeat(20 * 1024))).unwrap_err().to_string(), message);
        assert!(slot_dir_files(&d).is_empty());
        assert_eq!(vault_entries(&d), 0);
    }

    /// Move 全有或全無:有一台改不了(同名的主機有好幾份),改得了的也一台都不改 —— config 一個位元組都沒動,也沒有發出「config 變了」的通知。
    #[test]
    fn one_host_that_cant_be_switched_stops_the_move_for_all_of_them() {
        let main = "Host web\n  IdentityFile ~/.ssh/id_work\nHost db\n  IdentityFile ~/.ssh/id_work\nHost db\n  User me\n";
        let d = device(main);
        let file = key_file(&d, "id_work", &test_keys::plain());
        let imported = import_file(&d.env(), "work", &file.display().to_string(), false).unwrap();

        assert!(file.exists());
        assert!(imported.rewritten_hosts.is_empty());
        assert_eq!(imported.file_kept.as_deref(), Some("The file stays: db have more than one copy, so SSHelter didn't change them."));
        assert_eq!(d.main_config(), main, "web wasn't switched either");
        assert!(d.events.applied.lock().unwrap().is_empty());
    }

    /// 同一台主機的好幾行、或好幾份同名的區塊都指到這個檔案:訊息裡的主機名稱只列一次。
    #[test]
    fn a_host_is_named_once_in_the_reason() {
        let d = device("Host db\n  IdentityFile ~/.ssh/id_work\n  IdentityFile ~/.ssh/id_work\nHost db\n  IdentityFile ~/.ssh/id_work\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        let imported = import_file(&d.env(), "work", &file.display().to_string(), false).unwrap();
        assert_eq!(imported.file_kept.as_deref(), Some("The file stays: db have more than one copy, so SSHelter didn't change them."));
    }

    /// Move 改的是載入的每一個 config 檔裡的主機(Include 進來的也是),別把金鑰的主機不動;改完的主機走 agent:`agent/config` 跟著更新,並通知畫面重讀 config。
    #[test]
    fn moving_switches_the_hosts_of_every_loaded_file_and_wires_them_to_the_agent() {
        let d = device("Include ~/.ssh/extra.conf\nHost web\n  IdentityFile ~/.ssh/id_work\n");
        let extra = d.ssh_dir().join("extra.conf");
        std::fs::write(&extra, "Host db\n  IdentityFile ~/.ssh/id_work\nHost other\n  IdentityFile ~/.ssh/id_other\n").unwrap();
        d.reload();
        let file = key_file(&d, "id_work", &test_keys::plain());
        let imported = import_file(&d.env(), "work", &file.display().to_string(), false).unwrap();

        assert_eq!(imported.rewritten_hosts, vec!["web".to_string(), "db".to_string()]);
        assert!(imported.removed_file);
        let value = slot_value(&d.state().key_slots[&imported.slot_id].file_name);
        assert!(d.main_config().contains(&format!("IdentityFile {value}")));
        let included = d.read(&extra);
        assert!(included.contains(&format!("IdentityFile {value}")));
        assert!(included.contains("IdentityFile ~/.ssh/id_other"), "a host using another key is untouched");
        assert_eq!(d.events.applied.lock().unwrap().first(), Some(&0), "the screen is told the config changed");
        let agent = std::fs::read_to_string(crate::agent::wiring::agent_config_path(d.home.path())).unwrap();
        assert!(agent.contains("Host web\n  IdentityAgent ") && agent.contains("Host db\n  IdentityAgent "), "{agent}");
        assert!(!agent.contains("Host other\n"), "{agent}");
    }

    /// 第一輪已經跑完的 space 裡的主機照樣改(只有還沒跑完的才擋)。
    #[test]
    fn a_host_in_a_space_that_finished_its_first_sync_is_switched() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n  IdentityFile ~/.ssh/id_work\n");
        let file = key_file(&a, "id_work", &test_keys::plain());
        let imported = import_file(&a.env(), "work", &file.display().to_string(), false).unwrap();

        assert_eq!(imported.rewritten_hosts, vec!["web".to_string()]);
        assert!(imported.removed_file);
        let value = slot_value(&a.state().key_slots[&imported.slot_id].file_name);
        assert!(a.read(&a.space_path(&personal)).contains(&format!("IdentityFile {value}")));
    }

    /// `import_file` 擋過之後、動手之前 config 又被改了(競爭):`point_hosts_at` 持有 doc 鎖時再確認一次,一台都不改、原檔留著、別人的修改原封不動。載入的 config 裡有主機要改的時候,
    /// 說的是「config 變了」,不是 `persist_file` 撞到衝突的那句;沒有主機要改的時候(看不到新加的主機),也不能當成沒有東西指著它。
    #[test]
    fn a_config_that_changes_before_the_rewrite_keeps_the_file() {
        let persist = crate::config::commands::persist_file;
        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        let edited = "Host web\n  IdentityFile ~/.ssh/id_work\nHost newbox\n  IdentityFile ~/.ssh/id_work\n";
        d.write_externally(&d.main_path(), edited);
        let kept = point_hosts_at(&d.env(), d.home.path(), &file, "work-3fa2c1d9", persist).unwrap_err();
        assert_eq!(kept.reason, "The file stays: your SSH config changed on disk since SSHelter loaded it.");
        assert!(kept.switched.is_empty());
        assert_eq!(d.main_config(), edited, "nothing of ours was written");
        assert!(d.events.applied.lock().unwrap().is_empty(), "nothing changed, so nothing was announced");

        let d = device("Host db\n  HostName 10.0.0.2\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        d.write_externally(&d.main_path(), "Host db\n  HostName 10.0.0.2\nHost newbox\n  IdentityFile ~/.ssh/id_work\n");
        let kept = point_hosts_at(&d.env(), d.home.path(), &file, "work-3fa2c1d9", persist).unwrap_err();
        assert_eq!(kept.reason, "The file stays: your SSH config changed on disk since SSHelter loaded it.");
    }

    /// 寫檔到一半失敗(第二個檔案存不成):第一個檔案已經存好 —— 它的主機改指到新的插槽了,`rewritten_hosts` 列它們(畫面要問同步的那些)、agent 設定跟著更新;
    /// 原因只說沒存成的主機;原檔留著;記憶體裡的 doc 重載成磁碟上的內容,並通知畫面。
    #[test]
    fn a_failed_save_leaves_the_earlier_files_switched_and_names_only_the_rest() {
        let d = device("Include ~/.ssh/extra.conf\nHost web\n  IdentityFile ~/.ssh/id_work\n");
        let extra = d.ssh_dir().join("extra.conf");
        let extra_text = "Host db\n  IdentityFile ~/.ssh/id_work\n";
        std::fs::write(&extra, extra_text).unwrap();
        d.reload();
        let file = key_file(&d, "id_work", &test_keys::plain());
        let mut attempts = Vec::new();
        let imported = import_file_with(&d.env(), "work", &file.display().to_string(), false, |doc, idx, backed_up, retention| {
            attempts.push(idx);
            if idx == 1 {
                return Err(AppError::Other("disk full".to_string()));
            }
            crate::config::commands::persist_file(doc, idx, backed_up, retention)
        })
        .unwrap();

        assert_eq!(attempts, vec![0, 1], "the first file was saved, the second one refused");
        assert_eq!(imported.rewritten_hosts, vec!["web".to_string()], "the host in the saved file now uses the key in SSHelter");
        assert_eq!(imported.file_kept.as_deref(), Some("The file stays: db couldn't be switched (disk full)."));
        assert!(!imported.removed_file && file.exists());
        assert!(d.state().key_slots.contains_key(&imported.slot_id), "the key was added all the same");
        let value = slot_value(&d.state().key_slots[&imported.slot_id].file_name);
        assert!(d.main_config().contains(&format!("IdentityFile {value}")), "{}", d.main_config());
        assert_eq!(d.read(&extra), extra_text, "the second file was not written");
        {
            let doc = d.doc.lock().unwrap();
            assert!(crate::config::commands::drift(doc.as_ref().unwrap()).unwrap().iter().all(|f| !f.changed), "the config was loaded again");
        }
        assert_eq!(*d.events.applied.lock().unwrap(), vec![0], "and the screen was told");
        let agent = std::fs::read_to_string(crate::agent::wiring::agent_config_path(d.home.path())).unwrap();
        assert!(agent.contains("Host web\n  IdentityAgent "), "the agent serves the host that was switched: {agent}");
        assert!(!agent.contains("Host db\n"), "{agent}");
    }

    /// 第一個檔案就存不成:沒有主機改成,原因名全部要改的主機。
    #[test]
    fn a_failed_first_save_switches_nothing() {
        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        let imported = import_file_with(&d.env(), "work", &file.display().to_string(), false, |_, _, _, _| Err(AppError::Other("disk full".to_string()))).unwrap();
        assert!(imported.rewritten_hosts.is_empty() && !imported.removed_file && file.exists());
        assert_eq!(imported.file_kept.as_deref(), Some("The file stays: web couldn't be switched (disk full)."));
        assert!(!crate::agent::wiring::agent_config_path(d.home.path()).exists(), "no host was switched, so the agent has nothing to serve");
    }

    /// 預覽說明加不進去的原因:不是私鑰的檔案、SSHelter 自己管的檔案、舊式 PEM、agent 用不了的金鑰。讀得出來的部分(指紋、類型)照樣給。
    #[test]
    fn the_preview_explains_why_a_file_cant_be_added() {
        let d = device("# main\n");
        let preview = |path: &std::path::Path| preview_file(&d.env(), &path.display().to_string()).unwrap();

        let notes = preview(&key_file(&d, "notes.txt", "hello"));
        assert_eq!(notes.default_name, "notes.txt");
        assert_eq!(notes.problem.as_deref(), Some(NOT_A_KEY_FILE_MESSAGE));
        assert_eq!((notes.fingerprint, notes.key_type, notes.has_passphrase), (None, None, None));

        let managed_dir = d.home.path().join(SLOT_DIR);
        std::fs::create_dir_all(&managed_dir).unwrap();
        let managed = managed_dir.join("id_mac-3fa2c1d9");
        std::fs::write(&managed, test_keys::plain()).unwrap();
        let managed = preview(&managed);
        assert_eq!(managed.default_name, "id_mac-3fa2c1d9");
        assert_eq!(managed.problem.as_deref(), Some(MANAGED_FILE_MESSAGE));
        assert_eq!(managed.fingerprint, None);

        let (begin, end) = (concat!("-----BEGIN ", "RSA", " PRIVATE KEY-----"), concat!("-----END ", "RSA", " PRIVATE KEY-----"));
        let pem = preview(&key_file(&d, "id_old", &format!("{begin}\nbm90IGEga2V5\n{end}\n")));
        assert_eq!(pem.problem.as_deref(), Some("This key isn't in the OpenSSH format. Convert it with ssh-keygen -p -f <file>, then try again."));
        assert_eq!(pem.fingerprint, None);

        let sk = preview(&key_file(&d, "id_sk", &test_keys::security_key()));
        assert_eq!(sk.problem.as_deref(), Some(VAULT_KEY_TYPE_MESSAGE));
        assert_eq!(sk.key_type.as_deref(), Some("sk-ssh-ed25519@openssh.com"));
        assert!(sk.fingerprint.is_some());
        assert_eq!(sk.has_passphrase, Some(false));
        assert!(!sk.default_identity, "id_sk isn't a name ssh tries by itself");
    }

    // ── Move 不刪還有東西指著的檔案(修正第 1 輪):沒載入 config、不在 Host 區塊裡的 `IdentityFile`、連結、插槽連到的檔案 ──────────────

    const OUTSIDE_A_HOST_BLOCK: &str = "The file stays: an IdentityFile outside a Host block names it, and SSHelter only switches hosts.";

    /// 選 `id_work`、Move(不留檔案)。回傳(裝置、檔案、結果)。
    fn move_id_work(d: &TestDevice) -> (std::path::PathBuf, ImportedKey) {
        let file = key_file(d, "id_work", &test_keys::plain());
        let imported = import_file(&d.env(), "work", &file.display().to_string(), false).unwrap();
        (file, imported)
    }

    /// Move 什麼都沒改:金鑰照樣加進來了,原檔留著,`file_kept` 是 `reason`,主 config 一個位元組都沒動,也沒有發出「config 變了」的通知。
    fn assert_kept(d: &TestDevice, file: &std::path::Path, imported: &ImportedKey, reason: &str, main: &str) {
        assert_eq!(imported.file_kept.as_deref(), Some(reason));
        assert!(!imported.removed_file);
        assert!(imported.rewritten_hosts.is_empty());
        assert!(file.exists(), "the file stays");
        assert!(d.state().key_slots.contains_key(&imported.slot_id), "the key was added all the same");
        assert_eq!(d.main_config(), main, "no host was switched");
        assert!(d.events.applied.lock().unwrap().is_empty(), "nothing changed, so nothing was announced");
    }

    /// 沒有載入 config:看不出哪些主機用到這個檔案,不能當成沒有。金鑰照樣加進來,原檔留著。
    #[test]
    fn a_move_without_a_loaded_config_keeps_the_file() {
        let main = "Host web\n  IdentityFile ~/.ssh/id_work\n";
        let d = device(main);
        *d.doc.lock().unwrap() = None;
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, "The file stays: SSHelter couldn't check which hosts use it (no config loaded).", main);
    }

    /// 檔案最上層的 `IdentityFile`(不在任何 Host 區塊裡)指到這個檔案:Move 只改主機,改不了它 —— 一台都不改(連同樣指到這個檔案的 Host 區塊也不改),原檔留著。
    #[test]
    fn an_identityfile_at_the_top_of_a_config_file_keeps_the_file() {
        let main = "IdentityFile ~/.ssh/id_work\nHost web\n  IdentityFile ~/.ssh/id_work\n";
        let d = device(main);
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, OUTSIDE_A_HOST_BLOCK, main);
    }

    /// `Match` 區塊裡的 `IdentityFile` 也一樣。
    #[test]
    fn an_identityfile_in_a_match_block_keeps_the_file() {
        let main = "Host web\n  IdentityFile ~/.ssh/id_work\nMatch host db\n  IdentityFile ~/.ssh/id_work\n";
        let d = device(main);
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, OUTSIDE_A_HOST_BLOCK, main);
    }

    /// 載入的任何一個檔案都算:Include 進來的檔案最上層的 `IdentityFile`;兩個檔案都一個位元組沒動。
    #[test]
    fn an_identityfile_outside_a_host_block_in_an_included_file_keeps_the_file() {
        let main = "Include ~/.ssh/extra.conf\nHost web\n  IdentityFile ~/.ssh/id_work\n";
        let d = device(main);
        let extra = d.ssh_dir().join("extra.conf");
        std::fs::write(&extra, "IdentityFile ~/.ssh/id_work\n").unwrap();
        d.reload();
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, OUTSIDE_A_HOST_BLOCK, main);
        assert_eq!(d.read(&extra), "IdentityFile ~/.ssh/id_work\n");
    }

    /// 不在 Host 區塊裡、但不是指到這個檔案的 `IdentityFile`(別的金鑰)不擋;載入的 config 裡已經關掉(寫出來會變成註解)的那一行也不算。
    #[test]
    fn an_identityfile_outside_a_host_block_that_doesnt_count_doesnt_stop_the_move() {
        let main = "IdentityFile ~/.ssh/id_other\nMatch host db\n  IdentityFile ~/.ssh/id_other\nHost web\n  IdentityFile ~/.ssh/id_work\n";
        let d = device(main);
        let (file, imported) = move_id_work(&d);
        assert_eq!(imported.rewritten_hosts, vec!["web".to_string()]);
        assert!(imported.removed_file && !file.exists());
        let config = d.main_config();
        assert!(config.contains("IdentityFile ~/.ssh/id_other\nMatch host db\n  IdentityFile ~/.ssh/id_other\n"), "{config}");

        let d = device("IdentityFile ~/.ssh/id_work\nHost web\n  IdentityFile ~/.ssh/id_work\n");
        {
            let mut doc = d.doc.lock().unwrap();
            let Some(Item::Directive(top)) = doc.as_mut().unwrap().files[0].items.first_mut() else { panic!("a directive at the top") };
            crate::config::edit::set_directive_enabled(top, false);
        }
        let (file, imported) = move_id_work(&d);
        assert_eq!(imported.rewritten_hosts, vec!["web".to_string()], "{:?}", imported.file_kept);
        assert!(imported.removed_file && !file.exists());
        assert!(d.main_config().contains("# IdentityFile ~/.ssh/id_work\nHost web\n"), "written as a comment: {}", d.main_config());
    }

    /// 不能改的原因有固定的先後:同名的主機有好幾份、第一輪還沒跑完的 space、不在 Host 區塊裡的 `IdentityFile`(、連結:見下面)。同時有好幾個,說最前面的那一個。
    #[test]
    fn the_reasons_to_keep_the_file_come_in_a_fixed_order() {
        let main = "IdentityFile ~/.ssh/id_work\nHost web\n  IdentityFile ~/.ssh/id_work\nHost web\n  User me\n";
        let d = device(main);
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, "The file stays: web have more than one copy, so SSHelter didn't change them.", main);

        let (_relay, _clock, a, _b, _words, personal) = pair();
        let space_text = "IdentityFile ~/.ssh/id_work\nHost web\n  IdentityFile ~/.ssh/id_work\n";
        a.save_in_app(&a.space_path(&personal), space_text);
        mutate(&a.env(), |s| {
            s.spaces.get_mut(&personal).unwrap().baseline_established = false;
            Ok(())
        })
        .unwrap();
        let (file, imported) = move_id_work(&a);
        assert_eq!(imported.file_kept.as_deref(), Some("The file stays: web are in a space that hasn't finished its first sync."));
        assert!(file.exists());
        assert_eq!(a.read(&a.space_path(&personal)), space_text);
    }

    /// 完整的先後(`point_hosts_at`):沒有載入 config、config 在磁碟上變了、同名的主機有好幾份、第一輪還沒跑完的 space、不在 Host 區塊裡的 `IdentityFile`、解析不了的 `IdentityFile`、連結。
    /// 同時有好幾個就說最前面的;這裡看新加的幾個彼此、和它們前後的位置。
    #[test]
    fn the_new_reasons_keep_their_place_in_the_order() {
        let persist = crate::config::commands::persist_file;
        // config 變了,排在同名的主機有好幾份之前。
        let main = "Host web\n  IdentityFile ~/.ssh/id_work\nHost web\n  User me\n";
        let d = device(main);
        let file = key_file(&d, "id_work", &test_keys::plain());
        d.write_externally(&d.main_path(), &format!("{main}# edited elsewhere\n"));
        let kept = point_hosts_at(&d.env(), d.home.path(), &file, "work-3fa2c1d9", persist).unwrap_err();
        assert_eq!(kept.reason, "The file stays: your SSH config changed on disk since SSHelter loaded it.");

        // 不在 Host 區塊裡的 `IdentityFile` 排在解析不了的之前。
        let main = "IdentityFile ~/.ssh/id_work\nHost web\n  IdentityFile ~/.ssh/%h\n";
        let d = device(main);
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, OUTSIDE_A_HOST_BLOCK, main);

        // 解析不了的排在連結之前(連結的原因只在其他原因都不成立的時候才說)。
        #[cfg(unix)]
        {
            let main = "Host web\n  IdentityFile ~/.ssh/%h\n";
            let d = device(main);
            let target = key_file(&d, "work_key", &test_keys::plain());
            let link = d.ssh_dir().join("id_work");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let imported = import_file(&d.env(), "work", &link.display().to_string(), false).unwrap();
            assert_kept(&d, &link, &imported, UNRESOLVED, main);
        }
    }

    /// 預覽列的就是 Move 會改的主機:每一個指到這個檔案的 Host 區塊(萬用字元的 Host 也是),用區塊的第一個 pattern 當名稱,依出現順序、不重複。
    #[test]
    fn the_preview_lists_the_hosts_the_move_switches_wildcards_included() {
        let main = "Host *\n  IdentityFile ~/.ssh/id_work\nHost web db\n  IdentityFile ~/.ssh/id_work\n  IdentityFile \"%d/.ssh/id_work\"\nHost other\n  IdentityFile ~/.ssh/id_other\n";
        let d = device(main);
        let file = key_file(&d, "id_work", &test_keys::plain());
        let path = file.display().to_string();
        let preview = preview_file(&d.env(), &path).unwrap();
        assert_eq!(preview.hosts, vec!["*".to_string(), "web".to_string()]);
        assert_eq!(preview.problem, None);

        let imported = import_file(&d.env(), "work", &path, false).unwrap();
        assert_eq!(imported.rewritten_hosts, preview.hosts, "the move switches what the preview listed");
        assert!(imported.removed_file);
        let value = slot_value(&d.state().key_slots[&imported.slot_id].file_name);
        let config = d.main_config();
        assert!(config.contains(&format!("Host *\n  IdentityFile {value}\n")), "{config}");
        assert!(config.contains(&format!("Host web db\n  IdentityFile {value}\n  IdentityFile {value}\n")), "{config}");
        assert!(config.contains("Host other\n  IdentityFile ~/.ssh/id_other\n"), "{config}");
    }

    /// 經連結拿著這把金鑰的插槽(這裡是 `own`、還是「File for now」連到 `~/.ssh/id_x`)也是「已經在 SSHelter」:貼上、從檔案(Move 或 Keep)、同一把金鑰的另一個檔案,
    /// 都以插槽的名稱拒絕,什麼都不寫,原檔不動。
    #[test]
    fn a_key_a_slot_holds_through_a_link_is_already_in_sshelter() {
        let (_relay, _clock, a, _b, _words, _personal) = pair();
        create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_x");
        let file = a.ssh_dir().join("id_x");
        let path = file.display().to_string();
        let copy = key_file(&a, "id_copy", &test_keys::plain());
        let state = a.state();
        let sorted_folder = || {
            let mut files = slot_dir_files(&a);
            files.sort();
            files
        };
        let folder = sorted_folder();
        let message = "This key is already in SSHelter as id_x.";

        assert_eq!(import_file(&a.env(), "work", &path, false).unwrap_err().to_string(), message, "Move into SSHelter");
        assert_eq!(import_file(&a.env(), "work", &path, true).unwrap_err().to_string(), message, "Keep the file too");
        assert_eq!(import_file(&a.env(), "work", &copy.display().to_string(), false).unwrap_err().to_string(), message, "the same key in another file");
        assert_eq!(import_text(&a.env(), "again", &test_keys::plain()).unwrap_err().to_string(), message, "paste");
        assert_eq!(preview_file(&a.env(), &path).unwrap().problem.as_deref(), Some(message), "the preview says so too");

        assert!(file.exists() && copy.exists(), "both files stay");
        assert_eq!(a.state(), state, "nothing was written to the state");
        assert_eq!(sorted_folder(), folder, "or to the slot folder");
        assert_eq!(vault_entries(&a), 0, "or to the vault");
    }

    /// `already_linked` 直接看:插槽連到的檔案正是使用者選的那個,不論裡面是什麼都算(Move 掉它,插槽的連結就指著不見的檔案);其他一律看連到的檔案現在的指紋
    /// (OpenSSH 格式從私鑰的公開段讀,舊式 PEM 讀旁邊的 `.pub`),沒有選檔案(貼上)也一樣。
    #[test]
    fn a_slot_linked_to_the_picked_file_holds_it_whatever_the_file_says() {
        let d = device("# main\n");
        let linked = key_file(&d, "id_x", "not a key any more");
        let other = key_file(&d, "id_y", &test_keys::ecdsa());
        let id = crate::sync::slot_rules::new_slot_id().unwrap();
        let slot = LocalSlot {
            file_name: format!("laptop-{}", &id[..8]),
            source: Some(SlotSource::Linked { path: linked.display().to_string(), link: crate::sync::slot_files::LinkKind::Symlink, fingerprint: None, origin: true }),
            last_error: None,
            asked: false,
            payload: Some(KeySlotPayload {
                schema: SLOT_SCHEMA,
                name: "laptop".to_string(),
                mode: SlotMode::Own,
                origin_device_id: d.state().device_id,
                created_at_ms: 1,
                public_key: None,
                fingerprint: None,
                key_type: None,
                has_passphrase: None,
            }),
            uploaded_fingerprint: None,
            parked: true,
            learned_in: None,
            copy_from_another_account: false,
            local_only: false,
        };
        mutate(&d.env(), |s| {
            s.key_slots.insert(id.clone(), slot);
            Ok(())
        })
        .unwrap();
        let state = d.state();

        // 檔案裡已經不是金鑰,讀不出指紋:只有「選的就是這個檔案」認得出它(收起來的連結也算)。
        assert_eq!(already_linked(&state, "SHA256:anything", Some(&linked)).as_deref(), Some("laptop"));
        assert_eq!(already_linked(&state, "SHA256:anything", Some(&other)), None, "another file");
        assert_eq!(already_linked(&state, "SHA256:anything", None), None, "a paste has no file");

        // 檔案裡是金鑰:看指紋,選不選檔案都一樣。
        std::fs::write(&linked, test_keys::plain()).unwrap();
        assert_eq!(already_linked(&state, test_keys::PLAIN_FINGERPRINT, None).as_deref(), Some("laptop"));
        assert_eq!(already_linked(&state, test_keys::PLAIN_FINGERPRINT, Some(&other)).as_deref(), Some("laptop"));
        assert_eq!(already_linked(&state, test_keys::ECDSA_FINGERPRINT, None), None, "another key");

        // 舊式 PEM:公開段讀不出來,指紋來自旁邊的 `.pub`。
        let (begin, end) = (concat!("-----BEGIN ", "RSA", " PRIVATE KEY-----"), concat!("-----END ", "RSA", " PRIVATE KEY-----"));
        std::fs::write(&linked, format!("{begin}\nbm90IGEga2V5\n{end}\n")).unwrap();
        assert_eq!(already_linked(&state, test_keys::ECDSA_FINGERPRINT, None), None, "no .pub beside it");
        std::fs::write(public_path(&linked), format!("{} me@host\n", test_keys::ECDSA_PUBLIC)).unwrap();
        assert_eq!(already_linked(&state, test_keys::ECDSA_FINGERPRINT, None).as_deref(), Some("laptop"));

        // 其他來源的插槽不算:這一個不是連結了,就沒有東西指著那個檔案。
        mutate(&d.env(), |s| {
            s.key_slots.get_mut(&id).unwrap().source = None;
            Ok(())
        })
        .unwrap();
        assert_eq!(already_linked(&d.state(), test_keys::ECDSA_FINGERPRINT, Some(&linked)), None);
    }

    /// 連到的檔案現在讀不到(不見了):那個插槽沒有拿著任何金鑰,同一把金鑰可以加進來。
    #[test]
    fn a_link_whose_file_is_gone_holds_no_key() {
        let (_relay, _clock, a, _b, _words, _personal) = pair();
        create_slot_on(&a, SlotMode::Own, &test_keys::plain(), "id_x");
        std::fs::remove_file(a.ssh_dir().join("id_x")).unwrap();
        import_text(&a.env(), "again", &test_keys::plain()).unwrap();
    }

    /// 選的檔案本身是符號連結:連結和它指到的檔案都留著,一台主機都不改(說明原因);金鑰照樣加進來。不在 Host 區塊裡的 `IdentityFile` 的原因排在它前面。
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_keeps_the_link_and_its_target() {
        let main = "Host web\n  IdentityFile ~/.ssh/id_work\n";
        let d = device(main);
        let target = key_file(&d, "work_key", &test_keys::plain());
        let link = d.ssh_dir().join("id_work");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let imported = import_file(&d.env(), "work", &link.display().to_string(), false).unwrap();
        assert_kept(&d, &link, &imported, "The file stays: it's a link to another file, so SSHelter didn't remove either.", main);
        assert!(target.exists(), "and so does what it links to");
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "the link is still a link");

        let main = "IdentityFile ~/.ssh/id_work\nHost web\n  IdentityFile ~/.ssh/id_work\n";
        let d = device(main);
        let target = key_file(&d, "work_key", &test_keys::plain());
        let link = d.ssh_dir().join("id_work");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let imported = import_file(&d.env(), "work", &link.display().to_string(), false).unwrap();
        assert_kept(&d, &link, &imported, OUTSIDE_A_HOST_BLOCK, main);
    }

    // ── 修正第 2 輪:載入之後在外面改過的 config、解析不了的 `IdentityFile`、同一把金鑰的同步副本 ───────────────────────

    const RELOAD_FIRST: &str = "Your SSH config changed on disk since SSHelter loaded it. Reload it, then try again.";
    const UNRESOLVED: &str = "The file stays: an IdentityFile SSHelter can't resolve (a token, a variable or a relative path) may name it.";

    /// 什麼都沒加:狀態沒變,插槽目錄和保管庫檔都沒被建立。
    fn assert_nothing_added(d: &TestDevice, state_before: &crate::sync::state_v2::SyncStateV2) {
        assert_eq!(&d.state(), state_before, "the state is as it was");
        assert!(!d.home.path().join(SLOT_DIR).exists(), "the slot folder wasn't even made");
        assert!(!crate::vault::store::vault_path(&d.env().state_path).exists(), "the vault wasn't even opened for writing");
    }

    /// 別的編輯器在 SSHelter 載入之後加了一台主機、指到這個檔案,畫面還沒重新載入:載入的 config 裡沒有主機指到它,Move 看不到它也沒有檔案要寫(`persist_file` 的衝突檢查
    /// 只護著 Move 自己寫的檔案),刪掉檔案那一台就壞了。載入的 config 和磁碟上的不一樣就在動任何東西之前拒絕(什麼都沒加),重新載入之後再來一次就看得到它。
    #[test]
    fn an_edit_made_outside_sshelter_that_names_the_file_stops_the_move() {
        let d = device("Host db\n  HostName 10.0.0.2\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        let path = file.display().to_string();
        let edited = "Host db\n  HostName 10.0.0.2\nHost newbox\n  IdentityFile ~/.ssh/id_work\n";
        d.write_externally(&d.main_path(), edited);
        let before = d.state();

        assert_eq!(import_file(&d.env(), "work", &path, false).unwrap_err().to_string(), RELOAD_FIRST);
        assert!(file.exists());
        assert_eq!(d.main_config(), edited, "their edit is intact");
        assert_nothing_added(&d, &before);

        d.reload();
        let imported = import_file(&d.env(), "work", &path, false).unwrap();
        assert_eq!(imported.rewritten_hosts, vec!["newbox".to_string()], "after a reload the new host is seen and switched");
        assert!(imported.removed_file && !file.exists());
    }

    /// 載入的任何一個檔案變了都算,也包括 Move 不會寫的(這裡是 Include 進來、載入的時候沒有主機指到這個檔案的那個)。
    #[test]
    fn an_edit_to_a_file_the_move_would_not_write_stops_it_too() {
        let d = device("Include ~/.ssh/extra.conf\nHost web\n  IdentityFile ~/.ssh/id_work\n");
        let extra = d.ssh_dir().join("extra.conf");
        std::fs::write(&extra, "Host db\n  HostName 10.0.0.2\n").unwrap();
        d.reload();
        let file = key_file(&d, "id_work", &test_keys::plain());
        let edited = "Host db\n  HostName 10.0.0.2\nHost newbox\n  IdentityFile ~/.ssh/id_work\n";
        d.write_externally(&extra, edited);
        let (before, main) = (d.state(), d.main_config());

        assert_eq!(import_file(&d.env(), "work", &file.display().to_string(), false).unwrap_err().to_string(), RELOAD_FIRST);
        assert!(file.exists());
        assert_eq!((d.read(&extra), d.main_config()), (edited.to_string(), main));
        assert_nothing_added(&d, &before);
    }

    /// 載入的檔案不見了、或被換成讀不了的東西(一個資料夾):比不了的也算變了。
    #[test]
    fn a_config_file_that_is_gone_or_unreadable_counts_as_changed() {
        let d = device("Include ~/.ssh/extra.conf\nHost web\n  IdentityFile ~/.ssh/id_work\n");
        let extra = d.ssh_dir().join("extra.conf");
        std::fs::write(&extra, "Host db\n  HostName 10.0.0.2\n").unwrap();
        d.reload();
        let file = key_file(&d, "id_work", &test_keys::plain());
        let (path, before) = (file.display().to_string(), d.state());

        std::fs::remove_file(&extra).unwrap();
        assert_eq!(import_file(&d.env(), "work", &path, false).unwrap_err().to_string(), RELOAD_FIRST, "gone");
        std::fs::create_dir(&extra).unwrap();
        assert_eq!(import_file(&d.env(), "work", &path, false).unwrap_err().to_string(), RELOAD_FIRST, "unreadable");
        assert!(file.exists());
        assert_nothing_added(&d, &before);
    }

    /// Keep the file too 不動任何主機,不受影響:照樣加進來,檔案和別人的修改都不動。
    #[test]
    fn keeping_the_file_is_not_stopped_by_an_edit_made_outside_sshelter() {
        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        let edited = "Host web\n  IdentityFile ~/.ssh/id_work\nHost newbox\n  IdentityFile ~/.ssh/id_work\n";
        d.write_externally(&d.main_path(), edited);
        let imported = import_file(&d.env(), "work", &file.display().to_string(), true).unwrap();
        assert!(file.exists() && !imported.removed_file);
        assert!(d.state().key_slots.contains_key(&imported.slot_id));
        assert_eq!(d.main_config(), edited);
    }

    /// `%h` 這樣的 token 可能就是這個檔名(`Host github.com` 的 `~/.ssh/%h`):解析不了的 `IdentityFile` 可能指到它,就留著。
    #[test]
    fn an_identityfile_with_a_token_that_may_name_the_file_keeps_it() {
        let main = "Host *\n  IdentityFile ~/.ssh/%h\n";
        let d = device(main);
        let file = key_file(&d, "github.com", &test_keys::plain());
        let imported = import_file(&d.env(), "gh", &file.display().to_string(), false).unwrap();
        assert_kept(&d, &file, &imported, UNRESOLVED, main);
    }

    /// `${HOME}` 看得懂,就是家目錄:`${HOME}/.ssh/id_work` 指到的正是這個檔案,Move 只改得了看得懂的 Host 區塊裡的值,所以留著;換成 `${OTHER}` 也留著(什麼都可能)。
    #[test]
    fn an_identityfile_with_a_variable_that_names_the_file_keeps_it() {
        let main = "Host web\n  IdentityFile ${HOME}/.ssh/id_work\n";
        let d = device(main);
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, UNRESOLVED, main);

        let main = "Host web\n  IdentityFile ${OTHER}/id_work\n";
        let d = device(main);
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, UNRESOLVED, main);
    }

    /// 相對路徑從哪裡來都可能(ssh 從當時的工作目錄找起):`id_work` 可能就是 `~/.ssh/id_work`。
    #[test]
    fn a_relative_identityfile_keeps_the_file() {
        let main = "Host web\n  IdentityFile id_work\n";
        let d = device(main);
        let (file, imported) = move_id_work(&d);
        assert_kept(&d, &file, &imported, UNRESOLVED, main);
    }

    /// 在 Host 區塊、`Match` 區塊或檔案最上層都算。
    #[test]
    fn an_unresolvable_identityfile_anywhere_keeps_the_file() {
        for main in [
            "Host web\n  IdentityFile ~/.ssh/%h\n",
            "Match host web\n  IdentityFile ~/.ssh/%h\n",
            "IdentityFile ~/.ssh/%h\nHost web\n  HostName 10.0.0.1\n",
        ] {
            let d = device(main);
            let (file, imported) = move_id_work(&d);
            assert_kept(&d, &file, &imported, UNRESOLVED, main);
        }
    }

    /// 解析不了、但不可能指到這個檔案的(`~/.ssh/%h.pem` 不會是 `id_work`),不擋;載入的 config 裡已經關掉(寫出來會變成註解)的那一行也不算。
    #[test]
    fn an_unresolvable_identityfile_that_cant_name_the_file_doesnt_stop_the_move() {
        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\nHost other\n  IdentityFile ~/.ssh/%h.pem\n");
        let (file, imported) = move_id_work(&d);
        assert_eq!(imported.rewritten_hosts, vec!["web".to_string()], "{:?}", imported.file_kept);
        assert!(imported.removed_file && !file.exists());
        assert!(d.main_config().contains("Host other\n  IdentityFile ~/.ssh/%h.pem\n"), "{}", d.main_config());

        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\nHost other\n  IdentityFile ~/.ssh/%h\n");
        {
            let mut doc = d.doc.lock().unwrap();
            let Some(Item::Host(other)) = doc.as_mut().unwrap().files[0].items.get_mut(1) else { panic!("the second block is a host") };
            let Some(Item::Directive(line)) = other.body.first_mut() else { panic!("a directive in it") };
            crate::config::edit::set_directive_enabled(line, false);
        }
        let (file, imported) = move_id_work(&d);
        assert_eq!(imported.rewritten_hosts, vec!["web".to_string()], "{:?}", imported.file_kept);
        assert!(imported.removed_file && !file.exists());
        assert!(d.main_config().contains("# IdentityFile ~/.ssh/%h\n"), "written as a comment: {}", d.main_config());
    }

    /// 插槽裡放著同步來的副本(`SlotSource::SyncedCopy`),不在帳戶還在的插槽裡(這裡沒有帳戶):同一把金鑰也算已經在 SSHelter。
    #[test]
    fn a_synced_copy_in_a_slot_is_already_in_sshelter() {
        let d = device("# main\n");
        let id = crate::sync::slot_rules::new_slot_id().unwrap();
        let slot = LocalSlot {
            file_name: format!("old-{}", &id[..8]),
            source: Some(SlotSource::SyncedCopy { fingerprint: test_keys::PLAIN_FINGERPRINT.to_string() }),
            last_error: None,
            asked: false,
            payload: Some(KeySlotPayload {
                schema: SLOT_SCHEMA,
                name: "old".to_string(),
                mode: SlotMode::Synced,
                origin_device_id: d.state().device_id,
                created_at_ms: 1,
                public_key: Some(test_keys::PLAIN_PUBLIC.to_string()),
                fingerprint: Some(test_keys::PLAIN_FINGERPRINT.to_string()),
                key_type: Some("ssh-ed25519".to_string()),
                has_passphrase: Some(false),
            }),
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
            local_only: false,
        };
        mutate(&d.env(), |s| {
            s.key_slots.insert(id.clone(), slot);
            Ok(())
        })
        .unwrap();
        let before = d.state();

        assert_eq!(import_text(&d.env(), "again", &test_keys::plain()).unwrap_err().to_string(), "This key is already in SSHelter as old.");
        assert_eq!(already_in_sshelter(&before, test_keys::PLAIN_FINGERPRINT).as_deref(), Some("old"));
        assert_eq!(already_in_sshelter(&before, test_keys::ECDSA_FINGERPRINT), None, "another key");
        assert_nothing_added(&d, &before);
    }

    /// 解析不了的 `IdentityFile` 值可能指到哪些路徑:看得懂的先展開(`~`、`%d`、`${HOME}`、`%%`),其他的 token 與變數換成 `*`,相對路徑與 `~user/…` 換成 `*/<其餘>`;
    /// 不分大小寫,兩種分隔字元一樣;字面的字元(`[`、`?`)不是 glob 的意思。
    #[test]
    fn an_unresolvable_value_may_name_the_paths_its_tokens_could_stand_for() {
        let home = Path::new("/home/me");
        let may = |value: &str, key: &str| could_name(value, home, &[key.to_string()]);

        // token 與變數:什麼都可能,但前後的字面部分要對得上。
        assert!(may("~/.ssh/%h", "/home/me/.ssh/github.com"));
        assert!(may("\"~/.ssh/%h\"", "/home/me/.ssh/github.com"), "quoted");
        assert!(may("~/.ssh/id_%r@%h", "/home/me/.ssh/id_git@github.com"));
        assert!(may("${XDG}/ssh/key", "/x/ssh/key"));
        assert!(may("~/.ssh/%h%p", "/home/me/.ssh/x"), "two tokens in a row");
        assert!(!may("~/.ssh/%h.pem", "/home/me/.ssh/id_work"), "the suffix can't match");
        assert!(!may("~/.config/%h", "/home/me/.ssh/id_work"), "another directory");
        // 看得懂的部分展開。
        assert!(may("${HOME}/.ssh/id_work", "/home/me/.ssh/id_work"));
        assert!(!may("${HOME}/.ssh/other", "/home/me/.ssh/id_work"));
        assert!(may("%d/.ssh/%h", "/home/me/.ssh/x"));
        assert!(!may("%d/other/%h", "/home/me/.ssh/x"));
        assert!(!may("%d/.ssh/%h", "/elsewhere/.ssh/x"), "%d is the home folder, not anything");
        assert!(!may("${HOME}/.ssh/id_work", "/elsewhere/.ssh/id_work"), "${{HOME}} is the home folder, not any variable");
        assert!(!may("~/.ssh/%h", "/elsewhere/.ssh/x"), "~/ is the home folder, not anything");
        assert!(may("~/.ssh/100%%%h", "/home/me/.ssh/100%x"), "%% is one percent sign");
        assert!(!may("~/.ssh/100%%%h", "/home/me/.ssh/100x"));
        assert!(may("~/.ssh/${oops", "/home/me/.ssh/anything"), "an unclosed variable is anything to the end");
        assert!(may("~/.ssh/100%", "/home/me/.ssh/100x"), "a lone percent sign is a token");
        // 相對路徑與 `~user/…`。
        assert!(may("id_work", "/home/me/.ssh/id_work"));
        assert!(may("./id_work", "/home/me/.ssh/id_work"));
        assert!(may("../.ssh/id_work", "/home/me/.ssh/id_work"));
        assert!(!may("keys/id_work", "/home/me/.ssh/id_work"));
        assert!(may("keys/id_work", "/home/me/keys/id_work"));
        assert!(may("~bob/.ssh/id_work", "/home/me/.ssh/id_work"));
        assert!(!may("~bob/.ssh/other", "/home/me/.ssh/id_work"));
        assert!(may("%h/id_work", "/home/me/.ssh/id_work"), "starts with a token: anywhere");
        // 大小寫不分,兩種分隔字元一樣。
        assert!(may("ID_WORK", "/home/me/.ssh/id_work"));
        assert!(may("~\\.ssh\\%h", "/home/me/.ssh/x"));
        assert!(could_name("C:\\keys\\%h", Path::new("C:\\Users\\me"), &["C:/keys/x".to_string()]), "a drive path is absolute, not relative");
        assert!(!could_name("C:\\keys\\%h", Path::new("C:\\Users\\me"), &["C:/other/x".to_string()]));
        // 字面的字元就是字面的意思,家目錄裡的也是。
        assert!(may("~/.ssh/a[1]%h", "/home/me/.ssh/a[1]x"));
        assert!(!may("~/.ssh/a[1]%h", "/home/me/.ssh/a1x"));
        assert!(may("~/.ssh/what?%h", "/home/me/.ssh/what?x"));
        assert!(!may("~/.ssh/what?%h", "/home/me/.ssh/whatsx"));
        assert!(could_name("~/.ssh/%h", Path::new("/home/me[1]"), &["/home/me[1]/.ssh/x".to_string()]));
        assert!(!could_name("~/.ssh/%h", Path::new("/home/me[1]"), &["/home/me1/.ssh/x".to_string()]));
        // 路徑有好幾種寫法(選的路徑、解開連結之後的路徑)只要有一種對得上。
        assert!(could_name("~/.ssh/%h", home, &["/elsewhere/x".to_string(), "/home/me/.ssh/x".to_string()]));
    }

    /// 金鑰檔是符號連結:選的路徑和解開連結之後的真正路徑都拿來比,解析不了的值指到哪一個都算。
    #[cfg(unix)]
    #[test]
    fn a_pattern_is_tried_against_the_path_a_link_leads_to_as_well() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join(".ssh")).unwrap();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys").join("work_key"), test_keys::plain()).unwrap();
        let link = root.join(".ssh").join("id_work");
        std::os::unix::fs::symlink(root.join("keys").join("work_key"), &link).unwrap();

        let forms = key_forms(&link);
        assert_eq!(forms, vec![link.display().to_string(), root.join("keys").join("work_key").display().to_string()]);
        assert!(could_name("~/keys/%h", &root, &forms), "the real file is in keys/");
        assert!(could_name("~/.ssh/%h", &root, &forms), "the link is in .ssh/");
        assert!(!could_name("~/other/%h", &root, &forms));
    }
}
