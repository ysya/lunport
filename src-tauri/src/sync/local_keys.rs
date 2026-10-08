//! 這台自己加進 SSHelter 的金鑰(金鑰保管庫 spec §7.5「New key」「Generate key」、§4.3「沒加入同步帳戶也能用」):貼上的、檔案的、
//! 從 `~/.ssh` 匯入的、在這裡產生的。都放進這台的保管庫,插槽目錄只放 `.pub`,記成只在這台的金鑰(`LocalSlot::local_only`),不寫任何帳戶記錄;
//! 之後同步的主機用到它時,由 SP3 的 Sync key 對話框收編(`slot_setup::adopt_slot`)。

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config::model::Item;
use crate::error::AppError;
use crate::sync::dto::KeyFilePreview;
use crate::sync::env::SyncEnv;
use crate::sync::runtime::mutate;
use crate::sync::slot_files;
use crate::sync::slot_rules::{
    default_slot_name, inspect_private_key, new_slot_id, public_path, resolve_identity_value, slot_file_name, slot_value, valid_slot_name,
    IdentityTarget, KeySlotPayload, SlotMode, Unsyncable, SLOT_DIR, SLOT_SCHEMA,
};
use crate::sync::slots::{agent_refusal, in_the_way_message, live_slots, local_snapshot, refresh_agent, vault_unreadable_message};
use crate::sync::state_v2::{LocalSlot, SlotSource, SyncStateV2};
use crate::vault::store::{vault_path, with_vault, EntryOrigin, VaultEntry};

pub const MANAGED_FILE_MESSAGE: &str = "SSHelter already manages this file.";
pub const NOT_A_KEY_FILE_MESSAGE: &str = "This file isn't a private key.";

/// 貼上的文字最多收這麼多(私鑰本身的上限是 16 KiB,`inspect_private_key`)。
const MAX_PASTE_BYTES: usize = 64 * 1024;

/// `ssh` 沒寫 `IdentityFile` 時會試的檔名(`~/.ssh/` 底下,ssh_config(5))。
const DEFAULT_IDENTITIES: [&str; 7] = ["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss", "id_dsa"];

/// 加進來之後的結果(`import_file`):新插槽、改指到它的主機、原檔移除了沒、Move 卻留下原檔的原因。
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

/// 已經在 SSHelter 的同一把金鑰(同指紋)的名稱:這台保管庫裡的(`SlotSource::Vault`),或帳戶裡記著這個指紋、還在的插槽。
pub fn already_in_sshelter(state: &SyncStateV2, fingerprint: &str) -> Option<String> {
    let here = state.key_slots.values().find_map(|local| match &local.source {
        Some(SlotSource::Vault { fingerprint: f, .. }) if f == fingerprint => {
            Some(local.payload.as_ref().map(|p| p.name.clone()).unwrap_or_else(|| local.file_name.clone()))
        }
        _ => None,
    });
    here.or_else(|| {
        let account = state.account.as_ref()?;
        live_slots(account).into_iter().find(|(_, p)| p.fingerprint.as_deref() == Some(fingerprint)).map(|(_, p)| p.name)
    })
}

/// 把一把私鑰(OpenSSH 格式原文;有 passphrase 的照原樣)加進 SSHelter,成為只在這台的金鑰。回傳新插槽的 id。
/// 先檢查(名稱、格式、agent 用得了、沒有同一把、插槽路徑空著),再依序放:保管庫 → `.pub` → 狀態;後面失敗就收回前面放的。
/// 不需要帳戶;狀態存不進去的行程(`save_blocked`)在動任何東西之前就拒絕(`local_snapshot`)。
pub fn add_key(env: &SyncEnv, name: &str, text: &str, origin: EntryOrigin) -> Result<String, AppError> {
    let (state, home) = local_snapshot(env)?;
    if !valid_slot_name(name) {
        return Err(bad_name(name));
    }
    let facts = inspect_private_key(text).map_err(|e| AppError::Other(vault_unreadable_message(e).to_string()))?;
    if let Some(message) = agent_refusal(text, &facts) {
        return Err(AppError::Other(message.to_string()));
    }
    if let Some(existing) = already_in_sshelter(&state, &facts.fingerprint) {
        return Err(AppError::Other(format!("This key is already in SSHelter as {existing}.")));
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
    if !path.is_absolute() || !crate::sync::slot_setup::is_private_key_file(&path) {
        return Err(AppError::Other(NOT_A_KEY_FILE_MESSAGE.to_string()));
    }
    Ok(path)
}

fn home_of(env: &SyncEnv) -> Result<PathBuf, AppError> {
    env.ssh_dir.parent().map(Path::to_path_buf).ok_or_else(|| AppError::Other("cannot determine the home directory".to_string()))
}

/// 選了檔案之後、加進去之前給畫面看的(只讀):預設名稱、指紋、類型、有沒有 passphrase、用到它的主機、是不是 `ssh` 預設會試的檔名,
/// 以及加不進去的原因(`problem`)。
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
        doc.as_ref().map(|doc| crate::keys::hosts_using(doc, &home, &key)).unwrap_or_default()
    };
    let text = Zeroizing::new(std::fs::read_to_string(&key)?);
    match inspect_private_key(&text) {
        Err(e) => preview.problem = Some(vault_unreadable_message(e).to_string()),
        Ok(facts) => {
            preview.problem = agent_refusal(&text, &facts).map(str::to_string).or_else(|| {
                let state = crate::sync::runtime::snapshot(env)?;
                already_in_sshelter(&state, &facts.fingerprint).map(|name| format!("This key is already in SSHelter as {name}."))
            });
            preview.fingerprint = Some(facts.fingerprint);
            preview.key_type = Some(facts.key_type);
            preview.has_passphrase = Some(facts.has_passphrase);
        }
    }
    Ok(preview)
}

/// 「New key」→ From a file(與 `~/.ssh` 的「Import」)。`keep_file` = 「Keep the file too」:原檔與主機都不動。否則「Move into SSHelter」:
/// `IdentityFile` 指到這個檔案的主機改指到新的插槽(`point_hosts_at`),全部改好才移除原檔(只有私鑰檔;旁邊的 `.pub` 留著)。改不了就一台都不改、
/// 原檔留著:金鑰照樣加進來了,`file_kept` 說明原因。
pub fn import_file(env: &SyncEnv, name: &str, path: &str, keep_file: bool) -> Result<ImportedKey, AppError> {
    let home = home_of(env)?;
    let key = key_file(path, &home)?;
    let text = Zeroizing::new(std::fs::read_to_string(&key)?);
    let slot_id = add_key(env, name, &text, EntryOrigin::Imported)?;
    let mut imported = ImportedKey { slot_id: slot_id.clone(), rewritten_hosts: Vec::new(), removed_file: false, file_kept: None };
    if keep_file {
        return Ok(imported);
    }
    match point_hosts_at(env, &home, &key, &slot_file_name(name, &slot_id)) {
        Ok(rewritten) => imported.rewritten_hosts = rewritten,
        Err(reason) => {
            imported.file_kept = Some(reason);
            return Ok(imported);
        }
    }
    match std::fs::remove_file(&key) {
        Ok(()) => imported.removed_file = true,
        Err(e) => imported.file_kept = Some(format!("The file stays: it couldn't be removed ({e}).")),
    }
    Ok(imported)
}

/// 主機名稱的清單(訊息用)。
fn names(aliases: &[String]) -> String {
    aliases.join(", ")
}

/// 「Move into SSHelter」:載入的每個 config 檔裡,生效的 `IdentityFile` 指到 `key` 的主機改指到插槽 `slot_file`。全有或全無:
/// 有一台改不了 —— 同名的主機不只一份(改哪一份都不對,同 SP3 的 `slot_setup::rewrite_in`)、在勾選了而第一輪還沒跑完的 space 裡(第一輪以 chain 為準,
/// 改了會被蓋回去)—— 就一台都不改,回 Err(原因)。寫檔失敗:已寫的留著,記憶體裡的 doc 重載,回 Err(原因)。改了的話,之後更新 agent 的設定
/// (那些主機改走 agent)。回傳改了的主機(依出現順序、不重複)。鎖:先拿 doc、backed_up,勾選的 space 在持有 doc 鎖時才取(短暫拿 core 鎖,同
/// `slot_setup::rewrite_hosts`:第一輪的旗標在 doc 鎖裡改,取了清單之後才有人退回基線輪的話,改寫就白費了);存檔 hook 只拿 core。
fn point_hosts_at(env: &SyncEnv, home: &Path, key: &Path, slot_file: &str) -> Result<Vec<String>, String> {
    let result = {
        let mut doc_lock = env.doc.lock().unwrap();
        let mut backed_up = env.backed_up.lock().unwrap();
        let retention = env.retention();
        let selected: Vec<PathBuf> = crate::sync::migrate::selected_space_files(env.runtime, &env.ssh_dir).into_iter().map(|(_, p)| p).collect();
        let ready: Vec<PathBuf> = crate::sync::slot_setup::ready_space_files(env).into_iter().map(|(_, p)| p).collect();
        let Some(doc) = doc_lock.as_mut() else { return Ok(Vec::new()) };
        let counts = crate::sync::slot_setup::alias_counts(doc);
        let (mut targets, mut locked, mut not_ready, mut rewritten) = (Vec::new(), Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new());
        for (file_idx, file) in doc.files.iter().enumerate() {
            for (item_idx, item) in file.items.iter().enumerate() {
                let Item::Host(host) = item else { continue };
                let alias = host.patterns.first().cloned().unwrap_or_default();
                for (line_idx, line) in host.body.iter().enumerate() {
                    let Item::Directive(d) = line else { continue };
                    if d.key != "identityfile" || d.serializes_as_comment() {
                        continue;
                    }
                    let IdentityTarget::File(target) = resolve_identity_value(&d.value, home) else { continue };
                    if !crate::sync::slot_setup::same_file(&target, key) {
                        continue;
                    }
                    if crate::sync::slot_setup::locked(&host.patterns, &counts) {
                        if !locked.contains(&alias) {
                            locked.push(alias.clone());
                        }
                    } else if selected.contains(&file.path) && !ready.contains(&file.path) {
                        if !not_ready.contains(&alias) {
                            not_ready.push(alias.clone());
                        }
                    } else {
                        targets.push((file_idx, item_idx, line_idx));
                        if !rewritten.contains(&alias) {
                            rewritten.push(alias.clone());
                        }
                    }
                }
            }
        }
        if !locked.is_empty() {
            return Err(format!("The file stays: {} have more than one copy, so SSHelter didn't change them.", names(&locked)));
        }
        if !not_ready.is_empty() {
            return Err(format!("The file stays: {} are in a space that hasn't finished its first sync.", names(&not_ready)));
        }
        let value = slot_value(slot_file);
        for (file_idx, item_idx, line_idx) in &targets {
            if let Item::Host(host) = &mut doc.files[*file_idx].items[*item_idx] {
                if let Item::Directive(d) = &mut host.body[*line_idx] {
                    d.value = value.clone();
                    d.dirty = true;
                }
            }
        }
        let mut files: Vec<usize> = targets.iter().map(|(file_idx, _, _)| *file_idx).collect();
        files.dedup();
        let main_path = doc.files[0].path.clone();
        let failure = files.into_iter().find_map(|idx| crate::config::commands::persist_file(doc, idx, &mut backed_up, retention).err());
        match failure {
            None => Ok(rewritten),
            Some(e) => {
                drop(backed_up);
                *doc_lock = env.load_doc(&main_path).ok();
                Err(format!("The file stays: {} couldn't be switched ({e}).", names(&rewritten)))
            }
        }
    };
    let changed = result.as_ref().map_or(true, |hosts| !hosts.is_empty());
    if changed {
        env.events.applied(0);
    }
    if result.as_ref().is_ok_and(|hosts| !hosts.is_empty()) {
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

    /// 寫檔失敗(這裡是 config 在載入之後被別的程式改過):原檔留著並說明原因,金鑰照樣加進來了;記憶體裡的 doc 重載成磁碟上的內容,別人的修改原封不動。
    #[test]
    fn a_config_changed_by_another_program_keeps_the_file_and_says_why() {
        let d = device("Host web\n  IdentityFile ~/.ssh/id_work\n");
        let file = key_file(&d, "id_work", &test_keys::plain());
        let edited = "Host web\n  IdentityFile ~/.ssh/id_work\n# edited elsewhere\n";
        d.write_externally(&d.main_path(), edited);
        let imported = import_file(&d.env(), "work", &file.display().to_string(), false).unwrap();

        assert!(file.exists());
        assert!(!imported.removed_file);
        assert!(imported.rewritten_hosts.is_empty());
        let reason = imported.file_kept.expect("the reason is given");
        assert!(reason.starts_with("The file stays: web couldn't be switched (") && reason.ends_with(")."), "{reason}");
        assert!(d.state().key_slots.contains_key(&imported.slot_id), "the key was added all the same");
        assert_eq!(d.main_config(), edited, "their edit is intact and nothing of ours was written");
        let doc = d.doc.lock().unwrap();
        assert!(crate::config::commands::drift(doc.as_ref().unwrap()).unwrap().iter().all(|f| !f.changed), "the config was loaded again");
        assert_eq!(*d.events.applied.lock().unwrap(), vec![0], "and the screen was told");
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
}
