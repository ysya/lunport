//! 更換同步碼(spec §7.5):可中斷、可接續的長時間操作,進度在 `SyncStateV2::rotation`,新同步碼暫存在 keychain
//! `sync:mnemonic-next`。背景執行緒每一輪推進一步(`drive_rotation`),每一步完成就持久化,重啟後接著做:
//! 1 準備(`start_rotation`)→ 2 送出本機修改 → 3 標記與凍結 → 4 從凍結的 relay 取完整快照 → 5 建立與複製 →
//! 6 刪除舊 space chain → 7 切換。第 3 步之前可以取消;之後其他電腦已被擋下,只能做完。其他電腦偵測到更換後
//! (`frozen`)以新同步碼重新加入(`rejoin_account`):依 `previous_id` 保留勾選、檔名、待核准項目,未上傳的修改沿用原
//! 時間戳帶進新 space,第一輪以一般 LWW 合併。

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::error::AppError;
use crate::sync::account::{
    account_keys_from_keychain, account_ready, check_relay, keep_files_local, saves_allowed, selected_ids, staged_code_for,
    NOT_JOINED_MESSAGE, NO_ACCOUNT_MESSAGE,
};
use crate::sync::crypto::{self, ChainKeys};
use crate::sync::env::{Keychain, SyncEnv};
use crate::sync::merge::{
    account_outgoing, merge_account, plan_device, push_outgoing, put_account_record, space_deleted_by, space_entries,
    space_keys, SpaceEntry,
};
use crate::sync::reconcile::{decode, encode};
use crate::sync::record::{
    rotation_meta_id, MetaPayload, Record, RecordKind, RotationMarkerPayload, SpaceKeyPayload, SpacePayload,
    ACCOUNT_META_ID, SCHEMA_VERSION,
};
use crate::sync::relay::{PushOutcome, RelayApi, RelayError, FEATURE_FREEZE};
use crate::sync::round::note_backoff;
use crate::sync::runtime::{mutate, save_core};
use crate::sync::space_files;
use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::state_v2::{
    AccountState, FreezeInfo, RotatedSpace, RotationProgress, RotationStep, SealedRecord, SpaceState, SyncNotice,
    SyncStateV2, NEXT_MNEMONIC_ACCOUNT,
};

pub const NO_FREEZE_MESSAGE: &str = "this relay cannot change the sync code yet; update the relay first";
pub const NOT_CANCELLABLE_MESSAGE: &str = "changing the sync code can no longer be cancelled; it will finish on its own";
/// 暫存的新同步碼(`sync:mnemonic-next`)不見了、讀不懂,或不是這次更換的那一組 —— 沒有任何地方還有這組碼 —— 而更換還沒凍結任何東西:
/// 可以取消,再重新開始(`cancel_rotation`)。
const NEXT_CODE_GONE_BEFORE_FREEZE_MESSAGE: &str =
    "the new sync code is missing from the keychain, so this sync code change cannot continue; cancel it and start again";
/// 同上,但已經凍結:不能取消,這次更換再也完成不了。只剩離開這一條路(`account::leave_account` 這時放行)。舊帳戶已凍結、帶著更換標記,`join_account` 拒絕它 ——
/// 其他電腦被擋在沒有人持有的新碼後面,誰也不能再加入舊帳戶,所以出路是離開之後,其中一台建立新的同步帳戶,其他電腦離開舊帳戶、加入新的(不能說「再加入」)。
/// 每一輪都重讀 keychain,所以這句話不叫使用者重啟。
pub(crate) const NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE: &str =
    "the new sync code is missing from the keychain, so this sync code change can never finish and the old sync account can no longer be joined — leave the sync account on this computer, then create a new sync account on one computer; the other computers leave the old account and join the new one";
/// 狀態已經換成新帳戶,keychain 卻還沒收下新碼(上鎖或被拒):新碼暫存在 `sync:mnemonic-next`,SSHelter 沿用它、之後再試(狀態列說明)。
pub const SWAP_PENDING_MESSAGE: &str =
    "the keychain did not accept the new sync code yet; SSHelter keeps the new code and retries, and syncing continues meanwhile";
/// 其他電腦重新加入時,這台勾選的 space 沒有任何一個被輸入的同步碼的帳戶接續。原因不只一種(別的帳戶的碼、同步碼之後又換過、或這台勾選的都是新帳戶沒有
/// 接續的 space —— 例如只剩一個從沒送出去的本機 space),所以不指責這組碼,只說實情與出路:它若是最新的碼,離開(檔案留成本機檔案)再用它加入。
pub const NOT_A_SUCCESSOR_MESSAGE: &str =
    "none of the spaces this computer syncs continue in that sync account; if it is the newest sync code, leave the sync account — your synced files stay as local files that ssh keeps reading — and join with it";
/// 上一次的換碼還沒換進 keychain 時不能再開始一次更換:暫存的碼就是這個帳戶現在的碼,再暫存另一組新碼會蓋掉它。這句話在每一種會顯示的情形都
/// 要是真的:換碼寫不進 keychain 時每一輪都再試,但第 7 步連狀態檔都存不下來時(`swap_pending` 沒設)要等下次啟動 —— 所以只承諾最晚下次啟動。
pub const SWAP_PENDING_BLOCKS_MESSAGE: &str =
    "the new sync code is not saved to the keychain yet; SSHelter finishes that by itself, at the latest the next time it starts — change the sync code again after that";
/// 建立 chain 被限流(每 IP 每小時 20 次)時暫停多久再接續(spec §6.6、§7.5)。
const CREATE_PAUSE_MS: u64 = 60 * 60 * 1000;

/// 推進一步(第 3 至 7 步)的結果。
enum Stepped {
    /// 這一步往下走了(或這次更換已經讓給別台):背景執行緒立刻再跑一輪。
    Advanced,
    /// 什麼都沒前進 —— 建立 chain 被限流而暫停、或這一步在別處已被取消:等下一次輪詢。
    Held,
    /// 什麼都沒前進,但馬上再跑一輪:主 config 在載入之後被外部改過(`Conflict`),doc 已從磁碟重載 —— 同一般輪次,不是要顯示的錯誤、
    /// 也不算失敗的一輪。
    Again,
}

/// 推進一步時的失敗。relay 的錯誤與 keychain 給不出新同步碼要分類(`step_failed`),其他錯誤原樣回傳。
enum StepError {
    Relay(RelayError),
    /// 暫存的新同步碼(`sync:mnemonic-next`)讀不到、不見了或不是這次更換的那一組(`new_words`)。
    Keychain(AppError),
    Other(AppError),
}

impl From<RelayError> for StepError {
    fn from(e: RelayError) -> Self {
        StepError::Relay(e)
    }
}

impl From<AppError> for StepError {
    fn from(e: AppError) -> Self {
        StepError::Other(e)
    }
}

/// 第 3 至 7 步失敗之後,依 relay 的回答分類(同 `round::run_round`):被限流(`429`)或 relay 出錯(`5xx`)算失敗的一輪
/// (`note_backoff`:連續失敗的輪數加一、狀態列說明),這一輪就此結束、不立刻重跑 —— 背景執行緒依 spec §6.4 等 `next_delay`
/// (90 秒起每輪加倍,最長 15 分鐘);請求被 relay 拒絕(儲存額度滿了、不合規格、回答對不上)同樣算失敗,錯誤說明由 `sync_once`
/// 寫進 `last_error`;連不上不算。這幾步凍結之後就不能取消,沒有退避的話永久被拒絕的請求會以一般的間隔一直重試。keychain 給不出新同步碼
/// (`StepError::Keychain`)一樣算失敗的一輪:每一輪都再讀一次,通過系統 keychain 的話可能每一輪都跳出授權視窗,不能以輪詢的頻率一直重試。
fn step_failed(env: &SyncEnv, generation: u64, error: StepError) -> Result<(), AppError> {
    let e = match error {
        StepError::Relay(e) => e,
        StepError::Keychain(e) => {
            count_failed_round(env);
            return Err(e);
        }
        StepError::Other(e) => return Err(e),
    };
    match &e {
        RelayError::RateLimited => {
            note_backoff(env, generation, true, false);
            return Ok(());
        }
        RelayError::Http(code) if *code >= 500 => {
            note_backoff(env, generation, false, true);
            return Ok(());
        }
        RelayError::QuotaExceeded | RelayError::InvalidRequest(_) | RelayError::BadResponse(_) => count_failed_round(env),
        _ => {}
    }
    Err(e.into())
}

/// 連續失敗的輪數加一(退避,`round::next_delay`)。
fn count_failed_round(env: &SyncEnv) {
    let mut core = env.runtime.core.lock().unwrap();
    core.failed_rounds = core.failed_rounds.saturating_add(1);
}

/// 第 3 至 7 步做完了一步:退避的計數歸零、之前失敗留下的說明(被限流、relay 出錯、請求被拒絕)不再適用。第 2 步的收尾由它跑的一般
/// 輪次自己處理(`round::finish`)。`last_error` 只清這一代的狀態(同 `note_backoff`:別的命令換過 generation,說明就不屬於它)。
fn note_progress(env: &SyncEnv, generation: u64) {
    let mut core = env.runtime.core.lock().unwrap();
    core.failed_rounds = 0;
    if core.generation != generation {
        return;
    }
    if core.state.as_mut().is_some_and(|s| s.last_error.take().is_some()) {
        // 存不了就留在記憶體(`unsaved`),下一輪先補寫。
        let _ = save_core(&mut core, &env.state_path);
    }
}

/// 只改 `rotation` 的進度(不換 generation:進度只由背景執行緒推進,取消在 core 鎖內比對步驟)。`f` 回 false 表示這次
/// 轉換不成立(已被取消或步驟不符),什麼都不改。
fn update_rotation(env: &SyncEnv, f: impl FnOnce(&mut RotationProgress) -> bool) -> Result<bool, AppError> {
    let mut core = env.runtime.core.lock().unwrap();
    let Some(rotation) = core.state.as_mut().and_then(|s| s.rotation.as_mut()) else { return Ok(false) };
    if !f(rotation) {
        return Ok(false);
    }
    save_core(&mut core, &env.state_path)?;
    Ok(true)
}

/// 新帳戶的 `spacekey` 記錄(id = 新 space id),以**新帳戶金鑰**加密。
fn new_space_key(new_account: &ChainKeys, space: &ChainKeys, device_id: &str, now_ms: u64) -> Result<SealedRecord, AppError> {
    let record = Record {
        kind: RecordKind::SpaceKey,
        id: space.chain_id.clone(),
        version: 1,
        updated_at_ms: now_ms,
        device_id: device_id.to_string(),
        deleted: false,
        payload: serde_json::to_value(SpaceKeyPayload::from_keys(space)).expect("SpaceKeyPayload serializes"),
    };
    SealedRecord::seal(new_account, &record, 0)
}

/// 帳戶裡還在、而且解得開金鑰的 space。
fn live_spaces(account: &AccountState, keys: &ChainKeys) -> Vec<SpaceEntry> {
    space_entries(account)
        .into_iter()
        .filter(|e| !e.deleted && space_deleted_by(account, keys, &e.id).is_none() && space_keys(account, keys, &e.id).is_some())
        .collect()
}

/// 第 1 步(spec §7.5):relay 要支援凍結 → 產生新同步碼(存 `sync:mnemonic-next`)→ 推導新帳戶 → 為帳戶內**每個**
/// space(含這台沒勾選的)產生新的 chain id、權杖、金鑰,以新帳戶金鑰加密後寫進 `rotation`。背景執行緒接著做。
pub fn start_rotation(env: &SyncEnv) -> Result<(), AppError> {
    let (s, keys) = {
        let core = env.runtime.core.lock().unwrap();
        let s = core.state.clone().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        account_ready(&s, core.account_keys.as_ref())?;
        (s, core.account_keys.clone().expect("checked by account_ready"))
    };
    // 上一次的換碼還沒換進 keychain(暫存的碼就是這個帳戶現在的碼、keychain 裡的同步碼卻不是):再暫存另一組新碼會蓋掉它。暫存的碼只是
    // 沒清掉(keychain 的同步碼也是它)就不算。
    if staged_code_for(env.keychain, &keys.chain_id)?.is_some()
        && account_keys_from_keychain(env.keychain.get(MNEMONIC_ACCOUNT), &keys.chain_id).is_err()
    {
        return Err(AppError::Other(SWAP_PENDING_BLOCKS_MESSAGE.to_string()));
    }
    let supported = match s.relay_features.as_ref().filter(|f| f.url == s.relay_url) {
        Some(f) => f.supports(FEATURE_FREEZE),
        None => check_relay(env)?.supports(FEATURE_FREEZE),
    };
    if !supported {
        return Err(AppError::Other(NO_FREEZE_MESSAGE.to_string()));
    }
    let words = crypto::generate_mnemonic()?;
    let new_account = crypto::derive_account(&words)?;
    let now = env.now();
    let mut progress = RotationProgress::new(&new_account.chain_id, now);
    for entry in live_spaces(s.account.as_ref().expect("joined"), &keys) {
        let space = ChainKeys::generate()?;
        let sealed_key = new_space_key(&new_account, &space, &s.device_id, now)?;
        progress.spaces.insert(entry.id, RotatedSpace { new_space_id: space.chain_id, sealed_key });
    }
    env.keychain.set(NEXT_MNEMONIC_ACCOUNT, &words)?;
    let started = mutate(env, |s| {
        // 鎖外的快照之後(查 relay 的網路呼叫、暫存新碼的期間)同步輪次可能已經記下 `frozen`:在這個臨界區再確認一次(同 `spaces`),
        // 否則會存下一個背景執行緒永遠不推進的更換。
        account_ready(s, Some(&keys))?;
        if s.account.as_ref().map(|a| a.chain_id.as_str()) != Some(keys.chain_id.as_str()) {
            return Err(AppError::Other(NOT_JOINED_MESSAGE.to_string()));
        }
        s.rotation = Some(progress);
        Ok(())
    });
    if let Err(e) = started {
        // 被拒絕、沒有進度了:暫存的新碼不留。進度已經在記憶體裡、只是存檔失敗的話,更換照常進行,新碼要留著。
        if crate::sync::runtime::snapshot(env).is_some_and(|s| s.rotation.is_none()) {
            let _ = env.keychain.delete(NEXT_MNEMONIC_ACCOUNT);
        }
        return Err(e);
    }
    env.events.wake();
    Ok(())
}

/// 取消(spec §7.5):只能在第 3 步之前(還沒寫標記、沒凍結任何東西)。新 chain 在第 5 步才建立,所以這時還沒有要刪的
/// chain;清掉暫存的同步碼,回到原狀。
pub fn cancel_rotation(env: &SyncEnv) -> Result<(), AppError> {
    mutate(env, |s| match s.rotation.as_ref() {
        None => Err(AppError::Other("the sync code is not being changed".to_string())),
        Some(r) if !r.cancellable() => Err(AppError::Other(NOT_CANCELLABLE_MESSAGE.to_string())),
        Some(_) => {
            s.rotation = None;
            Ok(())
        }
    })?;
    env.keychain.delete(NEXT_MNEMONIC_ACCOUNT)?;
    env.events.wake();
    Ok(())
}

/// 暫存的新同步碼(keychain 的 `sync:mnemonic-next`)現在的狀況。
pub(crate) enum NewCode {
    /// 讀得到,推導出的帳戶就是這次更換的新帳戶。
    Ready(String, ChainKeys),
    /// keychain 讀不到(上鎖、被拒):不知道還在不在,之後再試。
    Unreadable(AppError),
    /// 不見了、讀不懂,或屬於別的帳戶:沒有任何地方還有這次更換的新碼,這次更換再也做不完。
    Gone,
}

/// 讀暫存的新同步碼。更換同步碼的各步(`new_words`)與離開(`account::leave_account` 判斷這次更換還做不做得完)用同一個判定。
pub(crate) fn read_new_code(keychain: &dyn Keychain, rotation: &RotationProgress) -> NewCode {
    match keychain.get(NEXT_MNEMONIC_ACCOUNT) {
        Err(e) => NewCode::Unreadable(e),
        Ok(None) => NewCode::Gone,
        Ok(Some(words)) => match crypto::derive_account(&words) {
            Ok(keys) if keys.chain_id == rotation.new_account_chain_id => NewCode::Ready(words, keys),
            _ => NewCode::Gone,
        },
    }
}

/// 新同步碼:`read_new_code` 讀得到的那一組。讀不到時的說明是實情:每一輪都會重讀 keychain(上鎖就解鎖,SSHelter 自己會再試),不叫使用者重啟;
/// 找不回來的說明依能不能取消而不同(第 3 步之前取消再來,凍結之後只能離開)。
fn new_words(env: &SyncEnv, rotation: &RotationProgress) -> Result<(String, ChainKeys), StepError> {
    let message = match read_new_code(env.keychain, rotation) {
        NewCode::Ready(words, keys) => return Ok((words, keys)),
        NewCode::Unreadable(e) => {
            format!("could not read the new sync code from the keychain ({e}); unlock the keychain — SSHelter tries again on every sync")
        }
        NewCode::Gone if rotation.cancellable() => NEXT_CODE_GONE_BEFORE_FREEZE_MESSAGE.to_string(),
        NewCode::Gone => NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE.to_string(),
    };
    Err(StepError::Keychain(AppError::Other(message)))
}

/// 這台還有能上傳、還沒上傳的記錄(帳戶與勾選的 space)。暫停中的 space(違反不變式、chain 不見了、儲存額度滿了或上傳被
/// relay 拒絕 —— 都記在那個 space 的 `last_error`,使用者看得到)送不出去,不擋住更換:它們的 dirty 記錄在切換時照樣帶進
/// 新 space,第一輪再上傳。
fn has_dirty(s: &SyncStateV2) -> bool {
    s.account.as_ref().is_some_and(|a| a.records.values().any(|l| l.dirty) || a.sealed.values().any(|x| x.dirty))
        || s.spaces
            .values()
            .any(|sp| sp.selected && sp.last_error.is_none() && !sp.missing && sp.records.values().any(|l| l.dirty))
}

/// 背景執行緒在 `rotation` 存在時呼叫(取代一般輪次):推進一步。每一步完成就持久化並要求立刻再跑一輪(第 2 步見
/// `send_local_changes`)。第 3 至 7 步失敗時依 relay 的回答退避(`step_failed`);做完一步就把退避的計數與失敗的說明清掉
/// (`note_progress`)。
pub fn drive_rotation(env: &SyncEnv, generation: u64, s: SyncStateV2, keys: ChainKeys) -> Result<(), AppError> {
    let Some(rotation) = s.rotation.clone() else { return Ok(()) };
    if rotation.paused_until_ms.is_some_and(|until| env.now() < until) {
        return Ok(());
    }
    let relay = env.relay(&s.relay_url)?;
    let stepped = match rotation.step {
        RotationStep::Prepared => return send_local_changes(env, generation, s, keys),
        RotationStep::LocalChangesSent => begin_freezing(env, &s, &keys, &rotation, relay.as_ref()),
        RotationStep::Freezing => freeze(env, &s, &keys, relay.as_ref()),
        RotationStep::Copying => copy(env, &s, &keys, &rotation, relay.as_ref()),
        RotationStep::Deleting => delete_old(env, &s, &keys, &rotation, relay.as_ref()),
        RotationStep::Switching => switch(env, &s, &keys, &rotation, relay.as_ref()),
    };
    match stepped {
        Ok(Stepped::Advanced) => {
            note_progress(env, generation);
            env.events.wake();
            Ok(())
        }
        Ok(Stepped::Held) => Ok(()),
        Ok(Stepped::Again) => {
            env.events.wake();
            Ok(())
        }
        Err(e) => step_failed(env, generation, e),
    }
}

/// 第 2 步做完之後:先確認新同步碼還在,存成 `Freezing`,再開始第 3 步。
fn begin_freezing(env: &SyncEnv, s: &SyncStateV2, keys: &ChainKeys, rotation: &RotationProgress, relay: &dyn RelayApi) -> Result<Stepped, StepError> {
    // 凍結之後就不能取消:新碼這時才發現不見了(或不是這次更換的那一組),每台電腦都會被擋在一組沒有人持有的碼後面。所以在還能取消的
    // 時候先讀它 —— 讀不到就停在這一步,使用者可以解鎖 keychain 或取消。
    new_words(env, rotation)?;
    // **寫標記之前**就存成 Freezing:從這裡起不能取消(與取消在同一把鎖內比對步驟)。
    if !update_rotation(env, |r| {
        let ok = r.step == RotationStep::LocalChangesSent;
        if ok {
            r.step = RotationStep::Freezing;
        }
        ok
    })? {
        return Ok(Stepped::Held);
    }
    freeze(env, s, keys, relay)
}

/// 第 2 步:一般輪次把這台的 dirty 記錄送出(`mark_frozen_chains` = false:這台自己正在更換,撞到凍結不記進狀態)。
/// - 拉帳戶時看到別台的更換標記(`RoundOutcome::markers`):對方先開始了,這台還沒寫標記、也還沒凍結任何東西 —— 直接讓給
///   那一次更換(同第 3 步寫不進標記時)。
/// - 撞到凍結的 chain(`frozen`)也算做完:別台已經凍結了,只是送不出去;第 3 步寫標記時會發現並讓步。
/// - 沒有能送的 dirty 記錄了(`has_dirty`)才往下走,而且只有往下走了才要求立刻再跑;以退避收尾的一輪(`backoff`:被限流、
///   relay 出錯)絕不立刻重跑 —— 背景執行緒等 `next_delay`,不會一直對 relay 發請求。
fn send_local_changes(env: &SyncEnv, generation: u64, s: SyncStateV2, keys: ChainKeys) -> Result<(), AppError> {
    let outcome = crate::sync::round::run_round(env, generation, s, keys, false)?;
    if !outcome.markers.is_empty() {
        return yield_to_other_rotation(env, outcome.markers);
    }
    let latest = crate::sync::runtime::snapshot(env).ok_or_else(crate::sync::runtime::superseded)?;
    let advanced = (outcome.frozen || !has_dirty(&latest))
        && update_rotation(env, |r| {
            let ok = r.step == RotationStep::Prepared;
            if ok {
                r.step = RotationStep::LocalChangesSent;
            }
            ok
        })?;
    if advanced && !outcome.backoff {
        env.events.wake();
    }
    Ok(())
}

/// 第 3 步:舊帳戶 chain 寫入 `meta` `rotation:<device_id>` → 凍結舊帳戶 chain → 凍結每個舊 space chain(含這台沒勾選
/// 的、別台剛建立的)。重跑時都是冪等的。舊帳戶在寫標記之前已被別台凍結(另一台先更換了同步碼、這台的標記寫不進去):這台還沒有
/// 擋下任何人 —— 讓給那一次更換:清掉進度與暫存的同步碼,這台記下 `frozen`,請使用者輸入對方的新同步碼。
fn freeze(env: &SyncEnv, s: &SyncStateV2, keys: &ChainKeys, relay: &dyn RelayApi) -> Result<Stepped, StepError> {
    let now = env.now();
    let marker = Record {
        kind: RecordKind::Meta,
        id: rotation_meta_id(&s.device_id),
        version: 1,
        updated_at_ms: now,
        device_id: s.device_id.clone(),
        deleted: false,
        payload: serde_json::to_value(RotationMarkerPayload {
            rotated_at_ms: now,
            by_device_id: s.device_id.clone(),
            by_device_name: s.device_name.clone(),
        })
        .expect("RotationMarkerPayload serializes"),
    };
    match relay.push(&keys.chain_id, &keys.auth_token, &[encode(keys, &marker, 0)?])? {
        // 已有一份(上一次中斷前寫的,id 只有這台會用)也算寫好了。
        PushOutcome::Applied(_) => {}
        // 帳戶已經凍結:是別台先更換了,還是這台上一次做到一半(標記寫了、帳戶凍結了,之後出錯或中斷,進度還停在這一步)?
        // 帳戶上有這台自己的標記就是後者 —— 凍結是冪等的,接著做完;沒有才是別台先凍結,讓給它。
        PushOutcome::Frozen => {
            let markers = old_account_snapshot(keys, relay)?.markers;
            if !markers.iter().any(|m| m.by_device_id == s.device_id) {
                yield_to_other_rotation(env, markers)?;
                return Ok(Stepped::Advanced);
            }
        }
    }
    relay.freeze_chain(&keys.chain_id, &keys.auth_token)?;
    // 帳戶凍結之後內容就不會再變:以 relay 上的帳戶列出 space(含別台剛建立、這台還沒拉到的)。
    let account = old_account_snapshot(keys, relay)?.section;
    for entry in space_entries(&account) {
        if let Some(space) = space_keys(&account, keys, &entry.id) {
            match relay.freeze_chain(&space.chain_id, &space.auth_token) {
                Ok(()) | Err(RelayError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    update_rotation(env, |r| {
        r.step = RotationStep::Copying;
        true
    })?;
    Ok(Stepped::Advanced)
}

/// 另一台先更換了同步碼(第 2 步拉帳戶時看到它的標記,或第 3 步寫不進這台的標記):放棄這一次(還沒凍結任何東西),改成
/// 「其他電腦」的流程 —— 清掉進度與暫存的新同步碼,記下 `frozen` 與 `markers`,請使用者輸入對方的新同步碼。
fn yield_to_other_rotation(env: &SyncEnv, markers: Vec<RotationMarkerPayload>) -> Result<(), AppError> {
    let now = env.now();
    {
        let _doc = env.doc.lock().unwrap();
        let mut core = env.runtime.core.lock().unwrap();
        core.generation += 1;
        if let Some(s) = core.state.as_mut() {
            s.rotation = None;
            if let Some(a) = s.account.as_mut() {
                a.frozen = Some(FreezeInfo { detected_at_ms: now, markers });
            }
        }
        save_core(&mut core, &env.state_path)?;
    }
    let _ = env.keychain.delete(NEXT_MNEMONIC_ACCOUNT);
    Ok(())
}

/// 舊帳戶在 relay 上的完整內容(凍結之後就是最終內容,spec §7.5 第 4 步)。
fn old_account_snapshot(keys: &ChainKeys, relay: &dyn RelayApi) -> Result<crate::sync::merge::AccountMerged, RelayError> {
    Ok(merge_account(&AccountState::new(&keys.chain_id), keys, &relay.pull(&keys.chain_id, &keys.auth_token, 0)?))
}

/// 第 4、5 步:從凍結的 relay 取完整快照(來源是 relay,不是本機快取 —— 包含別台已上傳的修改與這台尚待核准的記錄)
/// → `PUT` 新帳戶與每個新 space chain(`429` 就暫停到下個小時)→ 每個 space 的記錄以新金鑰重新加密上傳(保留
/// version、updated_at_ms、device_id 與 tombstone)→ 新帳戶寫入 `space`(含 `previous_id`)、`spacekey`、這台的
/// `device`、帳戶 `meta`,以及舊帳戶的 `keyslot`(原樣)與 `key`(以新帳戶金鑰重新加密;SP3 spec §6.6)。每完成一個 space 就記下;
/// 重跑時已寫過的列回 conflict,視為已複製。
fn copy(env: &SyncEnv, s: &SyncStateV2, keys: &ChainKeys, rotation: &RotationProgress, relay: &dyn RelayApi) -> Result<Stepped, StepError> {
    let (_, new_account) = new_words(env, rotation)?;
    let old = old_account_snapshot(keys, relay)?.section;
    let live = live_spaces(&old, keys);
    let now = env.now();
    // 第 1 步之後才建立的 space:現在補上它的新位置與金鑰(先存下來,中斷也不會換一組)。
    let mut rotation = rotation.clone();
    for entry in &live {
        if !rotation.spaces.contains_key(&entry.id) {
            let space = ChainKeys::generate()?;
            let rotated = RotatedSpace { new_space_id: space.chain_id.clone(), sealed_key: new_space_key(&new_account, &space, &s.device_id, now)? };
            rotation.spaces.insert(entry.id.clone(), rotated.clone());
            let id = entry.id.clone();
            update_rotation(env, move |r| {
                r.spaces.entry(id).or_insert(rotated);
                true
            })?;
        }
    }
    let new_keys = |old_id: &str| -> Result<ChainKeys, AppError> {
        let rotated = &rotation.spaces[old_id];
        let record = rotated.sealed_key.open(&new_account)?;
        serde_json::from_value::<SpaceKeyPayload>(record.payload)
            .map_err(|_| AppError::Other("a new space key is unreadable".to_string()))?
            .to_keys(&rotated.new_space_id)
    };
    let mut chains: Vec<ChainKeys> = vec![new_account.clone()];
    for entry in &live {
        chains.push(new_keys(&entry.id)?);
    }
    for chain in chains {
        if rotation.created.contains(&chain.chain_id) {
            continue;
        }
        match relay.create_chain(&chain.chain_id, &chain.auth_token) {
            Ok(()) => {
                let id = chain.chain_id.clone();
                update_rotation(env, move |r| {
                    r.created.insert(id);
                    r.paused_until_ms = None;
                    true
                })?;
            }
            Err(RelayError::RateLimited) => {
                let until = now + CREATE_PAUSE_MS;
                update_rotation(env, move |r| {
                    r.paused_until_ms = Some(until);
                    true
                })?;
                // 被限流也算失敗的一輪:暫停期間背景執行緒不必以一般的間隔醒來(狀態列不另外說明 —— 暫停到什麼時候在 `paused_until_ms`)。
                count_failed_round(env);
                return Ok(Stepped::Held);
            }
            Err(e) => return Err(e.into()),
        }
    }
    for entry in &live {
        if rotation.copied.contains(&entry.id) {
            continue;
        }
        let old_keys = space_keys(&old, keys, &entry.id).expect("live spaces have keys");
        let target = new_keys(&entry.id)?;
        let pulled = match relay.pull(&old_keys.chain_id, &old_keys.auth_token, 0) {
            Ok(p) => p,
            // 舊 chain 已經不在(閒置過期,或另一次更換刪掉了):沒有內容可複製。
            Err(RelayError::NotFound) => crate::sync::relay::PullResponse { records: Vec::new(), latest_seq: 0 },
            Err(e) => return Err(e.into()),
        };
        let outgoing = pulled
            .records
            .iter()
            .filter_map(|env| decode(&old_keys, env).ok())
            .filter(|r| r.kind == RecordKind::Host)
            .map(|r| {
                Ok(crate::sync::merge::Outgoing {
                    key: crate::sync::record::record_key(RecordKind::Host, &r.id),
                    item: encode(&target, &r, 0)?,
                    version: r.version,
                    updated_at_ms: r.updated_at_ms,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        if let Some(e) = push_outgoing(relay, &target.chain_id, &target.auth_token, &outgoing).error {
            return Err(e.into());
        }
        let id = entry.id.clone();
        update_rotation(env, move |r| {
            r.copied.insert(id);
            true
        })?;
    }
    // 新帳戶的記錄。
    let mut section = AccountState::new(&new_account.chain_id);
    put_account_record(
        &mut section,
        RecordKind::Meta,
        ACCOUNT_META_ID,
        serde_json::to_value(MetaPayload::account(env!("CARGO_PKG_VERSION"))).expect("MetaPayload serializes"),
        false,
        &s.device_id,
        now,
    );
    let mut selected_new = Vec::new();
    for entry in &live {
        let rotated = &rotation.spaces[&entry.id];
        let payload = SpacePayload {
            schema: SCHEMA_VERSION,
            name: entry.name.clone(),
            slug: entry.slug.clone(),
            created_at_ms: entry.created_at_ms,
            previous_id: Some(entry.id.clone()),
        };
        put_account_record(&mut section, RecordKind::Space, &rotated.new_space_id, serde_json::to_value(payload).expect("SpacePayload serializes"), false, &s.device_id, now);
        section.sealed.insert(rotated.sealed_key.key(), rotated.sealed_key.clone());
        if s.spaces.get(&entry.id).is_some_and(|sp| sp.selected) {
            selected_new.push(rotated.new_space_id.clone());
        }
    }
    selected_new.sort();
    plan_device(&mut section, &s.device_id, &s.device_name, env.platform, &selected_new, now);
    // SP3 spec §6.6:金鑰插槽跟著搬 —— `keyslot` 原樣(含 tombstone,別台才不會把刪掉的插槽補寫回來),`key` 以舊帳戶金鑰
    // 解開、新帳戶金鑰重新加密;版本、時間戳、裝置不變。私鑰只在這個迴圈裡以明文存在於記憶體,離開這裡就是新帳戶金鑰的密文。
    // `key` 在 `merge_account` 時已經解開驗證過,讀不開的(實際上不會有)略過:一筆壞記錄不能卡住已經凍結、不能取消的更換。
    for local in old.records.values().filter(|l| l.record.kind == RecordKind::KeySlot) {
        section.records.insert(
            crate::sync::record::record_key(RecordKind::KeySlot, &local.record.id),
            crate::sync::record::LocalRecord { record: local.record.clone(), seq: 0, dirty: true },
        );
    }
    for sealed in old.sealed.values().filter(|s| s.envelope.kind == RecordKind::Key.as_str()) {
        let Ok(record) = sealed.open(keys) else { continue };
        let moved = SealedRecord::seal(&new_account, &record, 0)?;
        section.sealed.insert(moved.key(), moved);
    }
    let outgoing = account_outgoing(&section, &new_account)?;
    if let Some(e) = push_outgoing(relay, &new_account.chain_id, &new_account.auth_token, &outgoing).error {
        return Err(e.into());
    }
    update_rotation(env, |r| {
        r.step = RotationStep::Deleting;
        true
    })?;
    Ok(Stepped::Advanced)
}

/// 第 6 步:`DELETE` 每個舊 space chain(舊帳戶 chain 保留:凍結、帶著標記,閒置 180 天後清除)。舊帳戶上有**別台**的
/// 更換標記(兩台同時更換)時不刪:另一次更換可能還要從這些 chain 複製,留給 relay 過期清除。
fn delete_old(env: &SyncEnv, s: &SyncStateV2, keys: &ChainKeys, rotation: &RotationProgress, relay: &dyn RelayApi) -> Result<Stepped, StepError> {
    let old = old_account_snapshot(keys, relay)?;
    let concurrent = old.markers.iter().any(|m| m.by_device_id != s.device_id);
    if !concurrent {
        for old_id in rotation.spaces.keys().filter(|id| !rotation.deleted.contains(*id)) {
            if let Some(space) = space_keys(&old.section, keys, old_id) {
                match relay.delete_chain(&space.chain_id, &space.auth_token) {
                    Ok(()) | Err(RelayError::NotFound) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            let id = old_id.clone();
            update_rotation(env, move |r| {
                r.deleted.insert(id);
                true
            })?;
        }
    }
    update_rotation(env, |r| {
        r.step = RotationStep::Switching;
        true
    })?;
    Ok(Stepped::Advanced)
}

/// 依 `previous_id` 把這台勾選的 space 帶進新帳戶(spec §7.5「保留勾選、檔名、待核准項目」):記錄的 seq 屬於舊 chain
/// → 歸零;cursor 歸零、基線已建立(第一輪以一般 LWW 合併,未上傳的修改照原時間戳上傳)。對不到新 space 的不帶。
fn carry_spaces(old: &BTreeMap<String, SpaceState>, mapping: &BTreeMap<String, String>) -> BTreeMap<String, SpaceState> {
    let mut out = BTreeMap::new();
    for (old_id, sp) in old.iter().filter(|(_, sp)| sp.selected) {
        let Some(new_id) = mapping.get(old_id) else { continue };
        let mut sp = sp.clone();
        sp.cursor_seq = 0;
        sp.baseline_established = true;
        sp.missing = false;
        sp.last_error = None;
        for local in sp.records.values_mut() {
            local.seq = 0;
        }
        for pending in sp.pending_approvals.values_mut() {
            pending.seq = 0;
        }
        for declined in sp.declined.values_mut() {
            declined.seq = 0;
        }
        out.insert(new_id.clone(), sp);
    }
    out
}

/// `install_new_account` 沒能(完整)換成新帳戶的原因。
enum InstallError {
    /// 這台勾選、新帳戶沒有接續的 space 的檔案改不成本機檔案:什麼都沒換(doc 已從磁碟重載、`applied(0)` 已發)。呼叫端各自說明 ——
    /// 使用者重新加入要再輸入一次,第 7 步則是背景執行緒自己重試;主 config 被外部改過(`Conflict`)是第 7 步的馬上重跑。
    Kept(AppError),
    Other(AppError),
}

impl From<AppError> for InstallError {
    fn from(e: AppError) -> Self {
        InstallError::Other(e)
    }
}

/// 改成本機檔案失敗的說明;`then` = 接下來怎麼辦(重新加入:請使用者再試一次;第 7 步:背景執行緒自己重試)。
fn kept_error(e: &AppError, then: &str) -> AppError {
    AppError::Other(format!("could not keep this device's synced files as local files ({e}); {then}"))
}

/// 這台勾選、新帳戶卻沒有接續的 space 的檔案(`mapping` 的 key = 新帳戶接續的舊 space id)。以最新的狀態算,呼叫端持有 doc 鎖。
fn unmapped_selected_files(env: &SyncEnv, mapping: &BTreeMap<String, String>) -> Result<Vec<PathBuf>, AppError> {
    let core = env.runtime.core.lock().unwrap();
    let s = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    s.spaces
        .iter()
        .filter(|(id, sp)| sp.selected && !mapping.contains_key(*id))
        .map(|(_, sp)| space_files::space_file_path(&env.ssh_dir, &sp.file_name))
        .collect()
}

/// 換成新帳戶(第 7 步與其他電腦的重新加入共用):在 doc 鎖內、以**最新**的狀態(含期間存檔當下規劃的修改)依
/// `mapping`(舊 space id → 新 space id)帶過勾選的 space,一次換掉並存檔;再把 keychain 的同步碼換成新碼。
///
/// 這台勾選、新帳戶卻沒有接續的 space(更換之前還沒送出去的新 space、期間被別台刪除的)先改成本機檔案(同離開帳戶:
/// `keep_files_local`,搬到 `~/.ssh/sshelter-local/`、主 config 的 Include 原地換成新路徑),**再**讓狀態不再勾選它們 —— 否則下一輪改寫
/// Include 就把它們拿掉,主機從 ssh 消失;留下 `SyncNotice::LeftAccount`。做不到就什麼都不換、回錯誤(doc 已從磁碟重載)。鎖的順序
/// lifecycle → doc → backed_up → core,鎖內不碰網路,事件在放掉所有鎖之後。
///
/// 呼叫端先把新碼暫存在 `sync:mnemonic-next`(更換是第 1 步,重新加入是 `rejoin_account` 驗證之後):在「狀態已換、keychain 還沒換」
/// 之間中斷、或 keychain 寫不進去時,新碼不會丟 —— 啟動流程以它補完(`engine::startup`),這個 session 也每一輪再試(`retry_pending_swap`)。
fn install_new_account(
    env: &SyncEnv,
    words: &str,
    keys: ChainKeys,
    account: AccountState,
    mapping: &BTreeMap<String, String>,
    mut notices: Vec<SyncNotice>,
) -> Result<(), InstallError> {
    let now = env.now();
    {
        let mut doc_lock = env.doc.lock().unwrap();
        let files = unmapped_selected_files(env, mapping)?;
        if !files.is_empty() {
            match keep_files_local(env, &mut doc_lock, &files) {
                Ok(kept) if !kept.is_empty() => {
                    notices.push(SyncNotice::LeftAccount { kept_files: kept.iter().map(|k| k.path.to_string_lossy().into_owned()).collect() });
                }
                Ok(_) => {}
                Err(e) => {
                    drop(doc_lock);
                    env.events.applied(0);
                    return Err(InstallError::Kept(e));
                }
            }
        }
        let mut core = env.runtime.core.lock().unwrap();
        core.generation += 1;
        core.conflict_streak = 0;
        core.failed_rounds = 0;
        core.batch_failures = 0;
        let s = core.state.as_mut().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        s.spaces = carry_spaces(&s.spaces, mapping);
        s.account = Some(account);
        s.rotation = None;
        s.last_error = None;
        s.notices.extend(notices.iter().cloned());
        let ids = selected_ids(s);
        let (me, name) = (s.device_id.clone(), s.device_name.clone());
        plan_device(s.account.as_mut().expect("just set"), &me, &name, env.platform, &ids, now);
        core.account_keys = Some(keys);
        save_core(&mut core, &env.state_path)?;
    }
    // keychain:新碼取代舊碼,再清掉暫存的。換不過去(上鎖或被拒)也不能丟掉新碼 —— 狀態已經是新帳戶了:沿用暫存碼推導的金鑰、暫存的新碼
    // 留著,說明直接記進狀態(不比 generation:上面剛換過,不能讓它被當成上一代的說明而不見),每一輪結束與下次啟動都再試。
    if env.keychain.set(MNEMONIC_ACCOUNT, words).is_ok() {
        let _ = env.keychain.delete(NEXT_MNEMONIC_ACCOUNT);
    } else {
        let mut core = env.runtime.core.lock().unwrap();
        core.swap_pending = true;
        core.swap_failures = 0;
        if let Some(s) = core.state.as_mut() {
            s.last_error = Some(SWAP_PENDING_MESSAGE.to_string());
        }
        // 存不了就留在記憶體(`unsaved`),下一輪先補寫。
        let _ = save_core(&mut core, &env.state_path);
    }
    for notice in &notices {
        env.events.notice(notice);
    }
    Ok(())
}

/// 第 7 步:讀新帳戶(這台剛寫的)→ 狀態改用新帳戶(依 `previous_id` 保留勾選、檔名、待核准項目)→ keychain 的新碼取代
/// 舊碼 → 提示保存新同步碼。再讀一次舊帳戶 chain:有別台的更換標記就提示「另一台電腦也更換了同步碼」。
fn switch(env: &SyncEnv, s: &SyncStateV2, keys: &ChainKeys, rotation: &RotationProgress, relay: &dyn RelayApi) -> Result<Stepped, StepError> {
    let (words, new_account) = new_words(env, rotation)?;
    let pulled = relay.pull(&new_account.chain_id, &new_account.auth_token, 0)?;
    let mut section = merge_account(&AccountState::new(&new_account.chain_id), &new_account, &pulled).section;
    section.baseline_established = true;
    let mapping: BTreeMap<String, String> = rotation
        .spaces
        .iter()
        .filter(|(old, _)| rotation.copied.contains(*old))
        .map(|(old, r)| (old.clone(), r.new_space_id.clone()))
        .collect();
    let mut notices = vec![SyncNotice::NewSyncCode];
    // 讀不到舊帳戶就這一步重來(到 `install_new_account` 為止都能重跑),不略過提示:spec §7.5 第 7 步要求告訴使用者另一台也更換了。
    // 例外是 404:舊帳戶 chain 已經不在(閒置 180 天被 relay 整條清除)—— 沒有標記可讀,就是沒有要提示的,照常切換;不然永遠停在這一步
    // (凍結之後不能取消、也不能離開)。
    let others: Vec<String> = match old_account_snapshot(keys, relay) {
        Ok(old) => old.markers.into_iter().filter(|m| m.by_device_id != s.device_id).map(|m| m.by_device_name).collect(),
        Err(RelayError::NotFound) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    if !others.is_empty() {
        notices.push(SyncNotice::OtherRotation { devices: others });
    }
    match install_new_account(env, &words, new_account, section, &mapping, notices) {
        Ok(()) => {}
        // 主 config 在載入之後被外部改過:doc 已從磁碟重載、`applied(0)` 已發。同一般輪次(`run_round`):不是要顯示的錯誤、不算失敗的一輪,
        // 以磁碟上的內容馬上重做。
        Err(InstallError::Kept(AppError::Conflict(_))) => return Ok(Stepped::Again),
        // 檔案改不成本機檔案、什麼都還沒換:這一步由背景執行緒自己重試,但不要以一般的間隔一直重試;說明不能叫使用者再試一次。
        Err(InstallError::Kept(e)) => {
            count_failed_round(env);
            return Err(kept_error(&e, "SSHelter retries the sync code change by itself").into());
        }
        // 換帳戶之前就失敗了(或換了卻存不了檔):同樣退避。
        Err(InstallError::Other(e)) => {
            count_failed_round(env);
            return Err(e.into());
        }
    }
    env.events.applied(0);
    Ok(Stepped::Advanced)
}

/// `finish_interrupted_switch` 補完換碼的結果。
#[derive(Debug)]
pub struct InterruptedSwitch {
    /// 暫存的新同步碼推導出的帳戶金鑰:狀態已經是這個帳戶,不論 keychain 換成了沒有都用它。
    pub keys: ChainKeys,
    /// keychain 的同步碼已換成新碼、暫存的已清掉。false = keychain 寫不進去:暫存的新碼留著,之後再補(`SyncCore::swap_pending`)。
    pub promoted: bool,
}

/// 啟動時 keychain 的同步碼推導不出狀態裡的帳戶:若暫存的新同步碼(`sync:mnemonic-next`)推導得出,代表換碼在「狀態已切換、keychain
/// 還沒換」之間中斷(更換同步碼的第 7 步,或其他電腦的重新加入)—— 以新碼取代舊碼、清掉暫存。keychain 寫不進去時照樣回傳帳戶金鑰
/// (`promoted` = false)、暫存的新碼留著:不能因為 keychain 一時寫不進去就讓使用者離開再加入。沒有暫存的、它屬於別的帳戶、
/// keychain 讀不到 → None,什麼都不動。
pub fn finish_interrupted_switch(keychain: &dyn Keychain, chain_id: &str) -> Option<InterruptedSwitch> {
    let (words, keys) = staged_code_for(keychain, chain_id).ok().flatten()?;
    let promoted = keychain.set(MNEMONIC_ACCOUNT, &words).is_ok();
    if promoted {
        let _ = keychain.delete(NEXT_MNEMONIC_ACCOUNT);
    }
    Some(InterruptedSwitch { keys, promoted })
}

/// 換碼上次沒成功(`SyncCore::swap_pending`:狀態已經是新帳戶、keychain 的同步碼還是舊的、新碼留在 `sync:mnemonic-next`):再試一次。
/// 背景執行緒每一輪結束時呼叫(沒有待補的就什麼都不做)。補好了就清掉旗標與對應的狀態列說明;還是寫不進去就保持待補,並讓說明留著 ——
/// 一般輪次的收尾把 `last_error` 清掉了,這裡補回去(別的錯誤說明優先,不蓋掉);而且算失敗的輪數、逐次退避(`SyncCore::swap_failures`)。暫存的碼不見了、或已不屬於這個帳戶(離開了、又換了)就沒有
/// 要補的了;keychain 讀不到(上鎖)不知道有沒有,下一輪再試。命令(重新加入、更換同步碼)全程持有 lifecycle 鎖、也會動暫存碼:它們在跑
/// 就下一輪再試,不和它們交錯。
pub fn retry_pending_swap(env: &SyncEnv) {
    let chain = {
        let core = env.runtime.core.lock().unwrap();
        if !core.swap_pending {
            return;
        }
        core.state.as_ref().and_then(|s| s.account.as_ref()).map(|a| a.chain_id.clone())
    };
    let Ok(_lifecycle) = env.runtime.lifecycle.try_lock() else { return };
    let still_pending = match chain.as_deref() {
        None => false,
        Some(chain) => match staged_code_for(env.keychain, chain) {
            Err(_) => true,
            Ok(None) => false,
            Ok(Some((words, _))) => {
                let saved = env.keychain.set(MNEMONIC_ACCOUNT, &words).is_ok();
                if saved {
                    let _ = env.keychain.delete(NEXT_MNEMONIC_ACCOUNT);
                }
                !saved
            }
        },
    };
    let mut core = env.runtime.core.lock().unwrap();
    core.swap_pending = still_pending;
    // 補不上也算失敗的輪數,而且一次比一次退得久(`SyncCore::swap_failures`):寫不進去的 keychain 不該每一輪都被再試一次。這裡在一般輪次的收尾(`round::finish`
    // 已經把 `failed_rounds` 歸零)之後,所以取 `max` —— 別的失敗留下的計數不被蓋小。
    if still_pending {
        core.swap_failures = core.swap_failures.saturating_add(1);
        core.failed_rounds = core.failed_rounds.max(core.swap_failures);
    } else {
        core.swap_failures = 0;
    }
    let Some(s) = core.state.as_mut() else { return };
    let changed = if still_pending {
        let missing = s.last_error.is_none();
        if missing {
            s.last_error = Some(SWAP_PENDING_MESSAGE.to_string());
        }
        missing
    } else if s.last_error.as_deref() == Some(SWAP_PENDING_MESSAGE) {
        s.last_error = None;
        true
    } else {
        false
    };
    if changed {
        // 存不了就留在記憶體(`unsaved`),下一輪先補寫。
        let _ = save_core(&mut core, &env.state_path);
    }
}

/// 其他電腦(spec §7.5):這台已偵測到同步碼被更換(`frozen`),使用者輸入新同步碼 → 驗證新帳戶存在、沒有又被更換
/// → 依 `previous_id` 保留勾選、檔名、待核准項目;本機尚未上傳的 dirty 記錄沿用原時間戳帶進新 space(第一輪是一般
/// LWW 合併,不是基線輪),所以被凍結擋下的修改不會遺失。
pub fn rejoin_account(env: &SyncEnv, words: &str) -> Result<(), AppError> {
    // 同 `create_account` / `join_account` / `leave_account`:沒有同步鎖的行程(別的 SSHelter 行程在跑引擎)、或狀態檔讀不到的 session 不寫狀態 ——
    // 也不該先暫存新碼到共用的 keychain、搬動 `~/.ssh` 的檔案、改寫主 config,最後才在存檔時失敗。
    saves_allowed(env)?;
    let words = crypto::normalize_mnemonic(words)?;
    let s = crate::sync::runtime::snapshot(env).ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    let old_chain = s.account.as_ref().map(|a| a.chain_id.clone());
    if s.frozen().is_none() {
        return Err(AppError::Other("the sync code of this account has not been changed".to_string()));
    }
    let new_account = crypto::derive_account(&words)?;
    if Some(&new_account.chain_id) == old_chain.as_ref() {
        return Err(AppError::Other("that is the old sync code; enter the new one from the device that changed it".to_string()));
    }
    let relay = env.relay(&s.relay_url)?;
    let pulled = match relay.pull(&new_account.chain_id, &new_account.auth_token, 0) {
        Ok(p) => p,
        Err(RelayError::NotFound) => return Err(AppError::NotFound(NO_ACCOUNT_MESSAGE.to_string())),
        Err(e) => return Err(e.into()),
    };
    let merged = merge_account(&AccountState::new(&new_account.chain_id), &new_account, &pulled);
    if let Some(marker) = merged.markers.first() {
        return Err(AppError::Other(format!(
            "this sync code was changed as well, on {}; enter the newest sync code",
            marker.by_device_name
        )));
    }
    let mut section = merged.section;
    section.baseline_established = true;
    let mapping: BTreeMap<String, String> = space_entries(&section)
        .into_iter()
        .filter(|e| !e.deleted)
        .filter_map(|e| e.previous_id.map(|old| (old, e.id)))
        .collect();
    // 這台勾選了 space、卻沒有任何一個被這組同步碼的帳戶接續(`previous_id`):輸入的是別的帳戶的碼,或同步碼之後又換過(只認一步)。
    // 什麼都不改 —— 請使用者離開(檔案留成本機檔案,ssh 照常讀)再用最新的碼加入。
    let selected: Vec<&String> = s.spaces.iter().filter(|(_, sp)| sp.selected).map(|(id, _)| id).collect();
    if !selected.is_empty() && !selected.iter().any(|id| mapping.contains_key(*id)) {
        return Err(AppError::Other(NOT_A_SUCCESSOR_MESSAGE.to_string()));
    }
    // 輸入的碼先暫存在 `sync:mnemonic-next`(同更換同步碼的第 1 步):狀態換成新帳戶、keychain 還沒換的時候中斷(或 keychain 寫不進去),
    // 啟動時以它補完,不必離開再加入。暫存不了就什麼都還沒改。
    env.keychain.set(NEXT_MNEMONIC_ACCOUNT, &words)?;
    let new_chain = new_account.chain_id.clone();
    if let Err(e) = install_new_account(env, &words, new_account, section, &mapping, Vec::new()) {
        // 沒有換成新帳戶(例如檔案改成本機檔案失敗):暫存的碼不留。已經換了(只是存檔或後續失敗)的話它是現在這個帳戶的碼,要留著。
        let switched = crate::sync::runtime::snapshot(env).and_then(|s| s.account).is_some_and(|a| a.chain_id == new_chain);
        if !switched {
            let _ = env.keychain.delete(NEXT_MNEMONIC_ACCOUNT);
        }
        return Err(match e {
            InstallError::Kept(e) => kept_error(&e, "nothing was changed — try again"),
            InstallError::Other(e) => e,
        });
    }
    env.events.applied(0);
    env.events.wake();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::merge::space_entries;
    use crate::sync::record::rotation_meta_id;
    use crate::sync::account::{create_account, show_words, FROZEN_MESSAGE};
    use crate::sync::engine::ANOTHER_ENGINE_MESSAGE;
    use crate::sync::env::Keychain;
    use crate::sync::round::{next_delay, sync_once, RATE_LIMITED_MESSAGE, RELAY_TROUBLE_MESSAGE};
    use crate::sync::round::tests::{pair, settle};
    use crate::sync::space_files;
    use crate::sync::spaces::{create_space, delete_space, unselect_space};
    use crate::sync::state_v2::{self, LoadedState};
    use crate::sync::testkit::{HookedConnector, Hooks, MemKeychain, TestDevice};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    fn step(d: &TestDevice) -> Option<RotationStep> {
        d.state().rotation.map(|r| r.step)
    }

    /// 推進一步(背景執行緒的一輪)。
    fn tick(d: &TestDevice) {
        let _ = sync_once(&d.env());
    }

    /// 推進到更換完成,再跑到沒有要立刻重跑的輪次。
    fn finish(d: &TestDevice) {
        for _ in 0..30 {
            if d.state().rotation.is_none() {
                settle(d);
                return;
            }
            tick(d);
        }
        panic!("the rotation never finished: {:?}", step(d));
    }

    fn new_code(d: &TestDevice) -> String {
        d.keychain.entry(NEXT_MNEMONIC_ACCOUNT).expect("the new sync code waits in the keychain")
    }

    fn entry_named(d: &TestDevice, name: &str) -> SpaceEntry {
        space_entries(d.state().account.as_ref().unwrap()).into_iter().find(|e| e.name == name && !e.deleted).unwrap()
    }

    #[test]
    fn changing_the_sync_code_moves_every_space_to_a_new_account() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        let work = create_space(&a.env(), "Work").unwrap();
        a.save_in_app(&a.space_path(&work), "Host db\n");
        settle(&a);
        let old_account = a.state().account.unwrap().chain_id;
        let personal_file = a.space_path(&personal);
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        assert_eq!(step(&a), Some(RotationStep::Prepared));
        assert_eq!(a.state().rotation.unwrap().spaces.len(), 2, "every space, selected or not");
        finish(&a);
        let s = a.state();
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next.clone()));
        assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
        assert_eq!(s.account.as_ref().unwrap().chain_id, crypto::derive_account(&next).unwrap().chain_id);
        let new_personal = entry_named(&a, "Personal");
        assert_eq!(new_personal.previous_id.as_deref(), Some(personal.as_str()));
        assert_eq!(entry_named(&a, "Work").previous_id.as_deref(), Some(work.as_str()));
        assert_eq!(a.space_path(&new_personal.id), personal_file, "the file name is kept");
        assert_eq!(a.read(&personal_file), "Host web\n");
        assert!(s.notices.contains(&SyncNotice::NewSyncCode));
        // relay:舊帳戶凍結並帶著標記;舊 space chain 的記錄已刪除、但仍然凍結;新 chain 有複製過去的記錄。
        assert!(relay.is_frozen(&old_account));
        for old in [&personal, &work] {
            assert!(relay.rows(old).is_empty() && relay.is_frozen(old));
        }
        assert!(!relay.rows(&new_personal.id).is_empty());
        assert!(!relay.rows(&entry_named(&a, "Work").id).is_empty(), "a space this device does not sync is copied too");
        // 之後照常同步到新 chain。
        a.save_in_app(&personal_file, "Host web\n  User x\n");
        settle(&a);
        assert!(a.state().spaces[&new_personal.id].records.values().all(|l| !l.dirty));
    }

    #[test]
    fn other_devices_freeze_and_rejoin_with_their_unsent_edits() {
        let (relay, _clock, a, b, words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        settle(&b);
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        // B 改了 web 還沒上傳,下一輪就發現帳戶已被更換:不上傳、記下 frozen。
        let file = b.space_path(&personal);
        b.save_in_app(&file, "Host web\n  User b\n");
        relay.clear_calls();
        settle(&b);
        let frozen = b.state().frozen().cloned().unwrap();
        assert_eq!(frozen.markers.iter().map(|m| m.by_device_name.as_str()).collect::<Vec<_>>(), vec!["MacBook-A"]);
        assert!(!relay.calls().iter().any(|c| c.starts_with("push:")));
        // 已刪除的舊 space chain 仍然凍結:就算有電腦沒先拉帳戶就推送,也寫不進去。
        let old_space = {
            let core = b.runtime.core.lock().unwrap();
            space_keys(core.state.as_ref().unwrap().account.as_ref().unwrap(), core.account_keys.as_ref().unwrap(), &personal).unwrap()
        };
        let stale = encode(&old_space, &Record { kind: RecordKind::Host, id: "x".into(), version: 1, updated_at_ms: 1, device_id: "z".into(), deleted: false, payload: serde_json::json!({ "schema": 1, "text": "Host x\n" }) }, 0).unwrap();
        assert_eq!(relay.push(&old_space.chain_id, &old_space.auth_token, &[stale]).unwrap(), PushOutcome::Frozen);
        assert!(rejoin_account(&b.env(), &words).is_err(), "the old code is refused");
        rejoin_account(&b.env(), &next).unwrap();
        let s = b.state();
        assert!(s.frozen().is_none());
        let new_personal = entry_named(&b, "Personal").id;
        assert_eq!(b.space_path(&new_personal), file, "selection and file name follow previous_id");
        assert!(s.spaces[&new_personal].records["host:web"].dirty, "the unsent edit comes along with its timestamp");
        assert_eq!(b.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        settle(&b);
        settle(&a);
        assert_eq!(a.read(&a.space_path(&new_personal)), "Host web\n  User b\n");
    }

    #[test]
    fn the_snapshot_holds_changes_and_held_records_the_rotating_device_never_applied() {
        let (relay, _clock, a, b, _words, personal) = pair();
        // B 先推一台要核准的主機:A 保留它(待核准)。
        b.save_in_app(&b.space_path(&personal), "Host jump\n  ProxyCommand nc %h 22\n");
        settle(&b);
        start_rotation(&a.env()).unwrap();
        tick(&a); // 第 2 步:一般輪次(A 拉到 jump,保留待核准)
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        assert!(a.state().spaces[&personal].pending_approvals.contains_key("jump"));
        // 凍結之前 B 又推了一台:A 從來沒拉到它,快照照樣包含它。
        b.save_in_app(&b.space_path(&personal), "Host jump\n  ProxyCommand nc %h 22\nHost db\n");
        settle(&b);
        tick(&a); // 第 3 步:標記與凍結
        assert_eq!(step(&a), Some(RotationStep::Copying));
        // 凍結之後 B 的修改被擋下。
        b.save_in_app(&b.space_path(&personal), "Host jump\n  ProxyCommand nc %h 22\nHost db\nHost late\n");
        settle(&b);
        assert!(b.state().frozen().is_some());
        finish(&a);
        let new_personal = entry_named(&a, "Personal").id;
        assert!(a.read(&a.space_path(&new_personal)).contains("Host db"), "the change A never pulled was copied");
        assert!(a.state().spaces[&new_personal].pending_approvals.contains_key("jump"), "the held record is still waiting");
        assert!(relay.rows(&new_personal).len() >= 2);
        // B 重新加入:被擋下的修改送進新帳戶。
        rejoin_account(&b.env(), &a.keychain.entry(MNEMONIC_ACCOUNT).unwrap()).unwrap();
        settle(&b);
        settle(&a);
        assert!(a.read(&a.space_path(&new_personal)).contains("Host late"));
    }

    #[test]
    fn a_space_created_elsewhere_during_the_rotation_is_frozen_and_copied_too() {
        let (relay, _clock, a, b, _words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        tick(&a); // 第 2 步之後,A 不會再拉帳戶
        let lab = create_space(&b.env(), "Lab").unwrap();
        b.save_in_app(&b.space_path(&lab), "Host gpu\n");
        settle(&b);
        tick(&a); // 第 3 步
        assert!(relay.is_frozen(&lab), "a space this device never pulled is frozen as well");
        finish(&a);
        let copied = entry_named(&a, "Lab");
        assert_eq!(copied.previous_id.as_deref(), Some(lab.as_str()));
        assert_eq!(relay.rows(&copied.id).len(), 1);
    }

    #[test]
    fn a_rotation_is_cancellable_only_before_freezing_and_resumes_after_a_pause() {
        let (relay, clock, a, _b, _words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        cancel_rotation(&a.env()).unwrap();
        assert!(a.state().rotation.is_none() && a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
        start_rotation(&a.env()).unwrap();
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        cancel_rotation(&a.env()).unwrap();
        start_rotation(&a.env()).unwrap();
        tick(&a);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        assert_eq!(cancel_rotation(&a.env()).unwrap_err().to_string(), NOT_CANCELLABLE_MESSAGE);
        // 建立 chain 被限流:暫停到下個小時,期間什麼都不做,之後自動接續。
        relay.fail_creates_with_429(1);
        tick(&a);
        let paused = a.state().rotation.unwrap();
        assert_eq!(paused.step, RotationStep::Copying);
        assert!(paused.paused_until_ms.is_some());
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 1, "the rate limit counts as a failed round");
        relay.clear_calls();
        tick(&a);
        assert!(relay.calls().is_empty(), "nothing happens while paused");
        clock.advance(2 * CREATE_PAUSE_MS);
        finish(&a);
        assert!(a.state().notices.contains(&SyncNotice::NewSyncCode));
    }

    #[test]
    fn a_device_that_loses_the_race_yields_to_the_other_rotation() {
        let (_relay, _clock, a, b, _words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        start_rotation(&b.env()).unwrap();
        tick(&a);
        tick(&b);
        tick(&a); // A 寫標記並凍結
        tick(&b); // B 的標記寫不進去:讓給 A
        let s = b.state();
        assert!(s.rotation.is_none());
        assert_eq!(s.frozen().unwrap().markers[0].by_device_name, "MacBook-A");
        assert!(b.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
        let next = new_code(&a);
        finish(&a);
        rejoin_account(&b.env(), &next).unwrap();
        assert!(b.state().frozen().is_none());
    }

    #[test]
    fn a_freeze_that_stopped_part_way_is_finished_and_never_yields_to_this_device_itself() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        tick(&a); // 第 2 步
        let old_account = a.state().account.unwrap().chain_id;
        // 中斷一:標記寫好了,relay 在凍結帳戶之前就連不上 —— 進度還停在第 3 步,帳戶還沒凍結。
        let down = relay.clone();
        let hooked = HookedConnector::new(&relay, Hooks { after_push: Some(Box::new(move || down.set_offline(true))), ..Hooks::default() });
        let mut env = a.env();
        env.relays = &hooked;
        let _ = sync_once(&env);
        assert_eq!(step(&a), Some(RotationStep::Freezing));
        assert!(!relay.is_frozen(&old_account), "the marker is written, the account is not frozen yet");
        relay.set_offline(false);
        // 中斷二:帳戶凍結了,讀回帳戶時被限流 —— 進度還是停在第 3 步,而帳戶已經被這台自己凍結。
        relay.set_rate_limited(&old_account, true);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Freezing));
        assert!(relay.is_frozen(&old_account), "this device froze the account");
        // 重跑這一步:帳戶上有這台自己的標記,不是別台先更換 —— 接著做完,不能讓給自己、丟掉新同步碼。
        relay.set_rate_limited(&old_account, false);
        finish(&a);
        let s = a.state();
        assert!(s.frozen().is_none() && s.rotation.is_none(), "{:?}", s.frozen());
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
        assert!(s.notices.contains(&SyncNotice::NewSyncCode));
        assert!(relay.rows(&personal).is_empty() && relay.is_frozen(&personal));
        let new_personal = entry_named(&a, "Personal").id;
        assert_eq!(relay.rows(&new_personal).len(), 1, "the host was copied to the new chain");
        assert_eq!(a.read(&a.space_path(&new_personal)), "Host web\n");
    }

    #[test]
    fn a_marker_seen_while_this_device_still_sends_its_changes_yields_at_once() {
        let (relay, _clock, a, b, _words, personal) = pair();
        // A 開始更換時還有沒上傳的修改:第 2 步要先送出它們。
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        start_rotation(&a.env()).unwrap();
        // B 先做完了第 3 步(寫標記、凍結):A 的第 2 步拉帳戶時就看到 B 的標記。
        start_rotation(&b.env()).unwrap();
        tick(&b);
        tick(&b);
        assert_eq!(step(&b), Some(RotationStep::Copying));
        relay.clear_calls();
        tick(&a);
        // A 還沒寫標記、沒凍結任何東西:讓給 B(不會停在第 2 步),修改留著等輸入 B 的新同步碼。
        let s = a.state();
        assert!(s.rotation.is_none() && a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
        assert_eq!(s.frozen().unwrap().markers[0].by_device_name, "MacBook-B");
        assert!(s.spaces[&personal].records["host:web"].dirty);
        assert!(!relay.calls().iter().any(|c| c.starts_with("push:")), "nothing was uploaded after the marker was seen");
        let next = new_code(&b);
        finish(&b);
        rejoin_account(&a.env(), &next).unwrap();
        settle(&a);
        settle(&b);
        let new_personal = entry_named(&b, "Personal").id;
        assert_eq!(b.read(&b.space_path(&new_personal)), "Host web\n", "A's unsent change arrives in the new account");
    }

    #[test]
    fn a_rate_limited_step_two_waits_for_the_next_poll_instead_of_rerunning_at_once() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        start_rotation(&a.env()).unwrap();
        relay.fail_batches_with_429(3);
        for round in 1..=3 {
            let wakes = a.events.wakes();
            relay.clear_calls();
            tick(&a);
            assert_eq!(step(&a), Some(RotationStep::Prepared), "round {round}");
            assert_eq!(a.events.wakes(), wakes, "round {round}: no immediate rerun after a 429");
            assert_eq!(relay.calls().len(), 1, "round {round}: one rejected batch and nothing else: {:?}", relay.calls());
        }
        // 背景執行緒等的是退避後的間隔(連續 3 輪:6 分鐘)。
        assert!(next_delay(&a.env()).as_secs() >= 360, "{:?}", next_delay(&a.env()));
        // 限流解除之後照常往下走。
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        assert!(a.state().spaces[&personal].records.values().all(|l| !l.dirty));
    }

    #[test]
    fn a_step_two_round_that_cannot_send_anything_does_not_rerun_at_once() {
        let (_relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        start_rotation(&a.env()).unwrap();
        // 另一台把帳戶升到這版讀不懂的格式:這台變成唯讀、送不出任何東西 —— 第 2 步不能往下走,也不能一直立刻重跑。
        a.runtime.core.lock().unwrap().state.as_mut().unwrap().account.as_mut().unwrap().remote_schema_version = Some(u32::MAX);
        let wakes = a.events.wakes();
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Prepared));
        assert_eq!(a.events.wakes(), wakes, "the step did not advance: wait for the next poll");
        assert!(a.state().spaces[&personal].records["host:web"].dirty);
    }

    #[test]
    fn a_space_over_its_storage_limit_does_not_hold_up_the_change() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        start_rotation(&a.env()).unwrap();
        relay.set_push_quota(Some(0));
        let wakes = a.events.wakes();
        tick(&a);
        // 這個 space 的記錄送不出去:錯誤記在 space 上(使用者看得到),第 2 步照樣做完 —— 它們跟著切換帶進新 space。
        let message = a.state().spaces[&personal].last_error.clone().unwrap();
        assert!(message.contains("\"Personal\"") && message.contains("storage limit"), "{message}");
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        assert_eq!(a.events.wakes(), wakes, "the round ended in backoff: the next step waits for the next poll");
        relay.set_push_quota(None);
        finish(&a);
        let new_personal = entry_named(&a, "Personal").id;
        assert_eq!(a.read(&a.space_path(&new_personal)), "Host web\n");
        let s = a.state();
        assert!(s.spaces[&new_personal].records.values().all(|l| !l.dirty), "uploaded to the new chain");
        assert!(s.spaces[&new_personal].last_error.is_none());
        assert!(!relay.rows(&new_personal).is_empty());
    }

    #[test]
    fn concurrent_markers_keep_the_old_chains_and_tell_the_device() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        start_rotation(&a.env()).unwrap();
        tick(&a);
        // 另一台(Y)在 A 凍結之前也寫了標記。
        let keys = a.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        let mut y = AccountState::new(&keys.chain_id);
        let marker = RotationMarkerPayload { rotated_at_ms: 1, by_device_id: "dev-y".into(), by_device_name: "MacBook-Y".into() };
        put_account_record(&mut y, RecordKind::Meta, &rotation_meta_id("dev-y"), serde_json::to_value(marker).unwrap(), false, "dev-y", 1);
        assert!(push_outgoing(relay.as_ref(), &keys.chain_id, &keys.auth_token, &account_outgoing(&y, &keys).unwrap()).error.is_none());
        finish(&a);
        assert!(relay.exists(&personal), "another rotation may still copy the old chains");
        assert!(a.state().notices.contains(&SyncNotice::OtherRotation { devices: vec!["MacBook-Y".into()] }));
    }

    #[test]
    fn the_relay_must_be_able_to_freeze() {
        let (relay, _clock, a, _b, _words, _personal) = pair();
        relay.set_legacy(true);
        a.runtime.core.lock().unwrap().state.as_mut().unwrap().relay_features = None;
        assert_eq!(start_rotation(&a.env()).unwrap_err().to_string(), NO_FREEZE_MESSAGE);
        assert!(a.state().rotation.is_none());
        assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
    }

    #[test]
    fn a_relay_that_limits_or_fails_during_the_copy_slows_the_change_down_until_it_answers() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        a.runtime.focused.store(true, Ordering::SeqCst);
        start_rotation(&a.env()).unwrap();
        tick(&a); // 第 2 步
        tick(&a); // 第 3 步
        assert_eq!(step(&a), Some(RotationStep::Copying));
        let old_account = a.state().account.unwrap().chain_id;
        let failed_rounds = || a.runtime.core.lock().unwrap().failed_rounds;
        assert_eq!((failed_rounds(), next_delay(&a.env())), (0, Duration::from_secs(45)));
        // relay 出錯(`5xx`):這一步沒做完、不立刻重跑,等待的間隔依 spec §6.4 拉長。
        relay.set_broken(&old_account, true);
        let wakes = a.events.wakes();
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        assert_eq!(a.events.wakes(), wakes, "no immediate rerun");
        assert_eq!((failed_rounds(), next_delay(&a.env())), (1, Duration::from_secs(90)));
        assert_eq!(a.state().last_error.as_deref(), Some(RELAY_TROUBLE_MESSAGE));
        // 被限流(`429`)一樣。
        relay.set_broken(&old_account, false);
        relay.set_rate_limited(&old_account, true);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        assert_eq!((failed_rounds(), next_delay(&a.env())), (2, Duration::from_secs(180)));
        assert_eq!(a.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        // 連不上不算失敗的一輪(同一般輪次)。
        relay.set_rate_limited(&old_account, false);
        relay.set_offline(true);
        tick(&a);
        assert_eq!((failed_rounds(), step(&a)), (2, Some(RotationStep::Copying)));
        // 通了:這一步做完,計數歸零、之前留下的說明不再顯示。
        relay.set_offline(false);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Deleting));
        assert_eq!((failed_rounds(), next_delay(&a.env())), (0, Duration::from_secs(45)));
        assert!(a.state().last_error.is_none());
        finish(&a);
    }

    #[test]
    fn a_keychain_that_cannot_give_the_new_code_backs_off_instead_of_retrying_every_poll() {
        use crate::sync::round::backoff_window;
        let (relay, _clock, a, _b, _words, _personal) = pair();
        a.runtime.focused.store(true, Ordering::SeqCst);
        let failed_rounds = || a.runtime.core.lock().unwrap().failed_rounds;
        start_rotation(&a.env()).unwrap();
        tick(&a); // 第 2 步
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        // 第 3 步之前讀新碼(`begin_freezing`):keychain 讀不到 —— 每一輪都失敗,退避到 90 秒、3 分、6 分。
        a.keychain.fail_reads.store(true, Ordering::SeqCst);
        for (round, seconds) in [(1, 90), (2, 180), (3, 360)] {
            tick(&a);
            assert_eq!(step(&a), Some(RotationStep::LocalChangesSent), "round {round}");
            assert_eq!((failed_rounds(), next_delay(&a.env())), (round, Duration::from_secs(seconds)), "round {round}");
            assert!(backoff_window(&a.env()) > Duration::ZERO);
        }
        // 讀得到了:這一步往下走,計數歸零。
        a.keychain.fail_reads.store(false, Ordering::SeqCst);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        assert_eq!((failed_rounds(), backoff_window(&a.env())), (0, Duration::ZERO));
        // 凍結之後新碼不見了(第 5 步讀它):一樣算失敗的一輪、一樣退避,而且說明講的是實情。
        a.keychain.delete(NEXT_MNEMONIC_ACCOUNT).unwrap();
        for (round, seconds) in [(1, 90), (2, 180)] {
            tick(&a);
            assert_eq!(step(&a), Some(RotationStep::Copying));
            assert_eq!((failed_rounds(), next_delay(&a.env())), (round, Duration::from_secs(seconds)));
        }
        assert_eq!(a.state().last_error.as_deref(), Some(NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE));
        // 凍結沒有被重複:舊帳戶只凍結過一次。
        assert!(relay.is_frozen(&a.state().account.unwrap().chain_id));
    }

    #[test]
    fn a_keychain_swap_that_keeps_failing_backs_off_longer_every_round_and_a_landed_swap_clears_it() {
        use crate::sync::round::backoff_window;
        let (_relay, _clock, a, _b, words, _personal) = pair();
        a.runtime.focused.store(true, Ordering::SeqCst);
        let (_old, next) = rotate_until_switching(&a, &words);
        let counts = || {
            let core = a.runtime.core.lock().unwrap();
            (core.failed_rounds, core.swap_failures)
        };
        // 狀態換成新帳戶、keychain 寫不進去:切換的那一輪結束時就重試過一次(失敗)。之後每一輪的重試都再失敗一次 —— 一般輪次的收尾把 `failed_rounds` 歸零,
        // 重試卻要一次比一次退得久,而不是每一輪都停在第一段(90 秒)。
        a.keychain.fail_writes_to(MNEMONIC_ACCOUNT, true);
        tick(&a);
        assert!(swap_pending(&a) && backoff_window(&a.env()) > Duration::ZERO);
        assert_eq!((counts(), next_delay(&a.env())), ((1, 1), Duration::from_secs(90)));
        for (expected, seconds) in [(2, 180), (3, 360), (4, 720)] {
            tick(&a);
            assert_eq!((counts(), next_delay(&a.env())), ((expected, expected), Duration::from_secs(seconds)));
        }
        tick(&a);
        assert_eq!(next_delay(&a.env()), Duration::from_secs(15 * 60), "capped at 15 minutes");
        // 寫得進去了:下一輪補完,旗標、計數與退避都清掉。
        a.keychain.fail_writes_to(MNEMONIC_ACCOUNT, false);
        tick(&a);
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        assert!(!swap_pending(&a));
        assert_eq!((counts(), backoff_window(&a.env())), ((0, 0), Duration::ZERO));
        assert_eq!(next_delay(&a.env()), Duration::from_secs(45));
    }

    #[test]
    fn an_engine_wake_after_progress_is_not_an_implicit_one_and_ends_the_backoff() {
        use crate::sync::round::backoff_window;
        let (relay, _clock, a, _b, _words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        tick(&a);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        // relay 限流:這一步沒做完、不立刻重跑 —— 進入退避。
        let old_account = a.state().account.unwrap().chain_id;
        relay.set_rate_limited(&old_account, true);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        assert!(backoff_window(&a.env()) > Duration::ZERO);
        // 限流解除,這一步做完:失敗的輪數歸零、退避結束,引擎要求的再跑是一般的喚醒(`SyncEvents::wake`)—— 不是順便的喚醒,所以不會被任何退避擋住。
        relay.set_rate_limited(&old_account, false);
        let (wakes, implicit) = (a.events.wakes(), a.events.implicit_wakes());
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Deleting));
        assert_eq!(backoff_window(&a.env()), Duration::ZERO);
        assert!(a.events.wakes() > wakes, "the engine asks for the next step at once");
        assert_eq!(a.events.implicit_wakes(), implicit, "and it is not an implicit wake");
    }

    #[test]
    fn a_request_the_relay_refuses_during_the_copy_backs_off_and_says_why() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        a.runtime.focused.store(true, Ordering::SeqCst);
        // 計數在自己的敘述裡讀:`next_delay` 也要 core 鎖,同一個運算式裡拿兩次會鎖死。
        let failed_rounds = || a.runtime.core.lock().unwrap().failed_rounds;
        start_rotation(&a.env()).unwrap();
        tick(&a);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        relay.set_push_quota(Some(0));
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        assert_eq!((failed_rounds(), next_delay(&a.env())), (1, Duration::from_secs(90)));
        assert_eq!(a.state().last_error, Some(RelayError::QuotaExceeded.to_string()));
        relay.set_push_quota(None);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Deleting));
        assert_eq!(failed_rounds(), 0);
        assert!(a.state().last_error.is_none());
        finish(&a);
    }

    #[test]
    fn a_new_code_that_vanished_stops_the_change_while_it_can_still_be_cancelled() {
        let (relay, _clock, a, _b, _words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        tick(&a); // 第 2 步
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        let old_account = a.state().account.unwrap().chain_id;
        // 暫存的新碼不見了:第 3 步之前就發現 —— 還沒寫標記、沒凍結任何東西,仍然可以取消。
        a.keychain.delete(NEXT_MNEMONIC_ACCOUNT).unwrap();
        relay.clear_calls();
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        assert!(relay.calls().is_empty() && !relay.is_frozen(&old_account), "nothing was written or frozen");
        assert_eq!(a.state().last_error.as_deref(), Some(NEXT_CODE_GONE_BEFORE_FREEZE_MESSAGE), "cancel it and start again");
        assert!(!NEXT_CODE_GONE_BEFORE_FREEZE_MESSAGE.contains("restart"), "every round reads the keychain again");
        // 換成不屬於這次更換的碼也一樣。
        a.keychain.set(NEXT_MNEMONIC_ACCOUNT, &crypto::generate_mnemonic().unwrap()).unwrap();
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        assert!(!relay.is_frozen(&old_account));
        assert_eq!(a.state().last_error.as_deref(), Some(NEXT_CODE_GONE_BEFORE_FREEZE_MESSAGE));
        // keychain 讀不到(上鎖)和「碼不見了」是兩回事:說明叫使用者解鎖,SSHelter 每一輪自己再試 —— 不叫它重啟。
        a.keychain.fail_reads.store(true, Ordering::SeqCst);
        tick(&a);
        let unreadable = a.state().last_error.unwrap();
        assert!(unreadable.starts_with("could not read the new sync code from the keychain ("), "{unreadable}");
        assert!(unreadable.ends_with("unlock the keychain — SSHelter tries again on every sync") && !unreadable.contains("restart"), "{unreadable}");
        assert_eq!(step(&a), Some(RotationStep::LocalChangesSent));
        a.keychain.fail_reads.store(false, Ordering::SeqCst);
        // 碼回來了,就照常往下走。
        a.keychain.set(NEXT_MNEMONIC_ACCOUNT, &next).unwrap();
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        assert!(relay.is_frozen(&old_account));
        finish(&a);
        // 取消的那一條路:碼不見了就取消,回到原狀。
        let (_relay, _clock, c, _d, _words, _personal) = pair();
        start_rotation(&c.env()).unwrap();
        tick(&c);
        c.keychain.delete(NEXT_MNEMONIC_ACCOUNT).unwrap();
        tick(&c);
        cancel_rotation(&c.env()).unwrap();
        assert!(c.state().rotation.is_none());
    }

    #[test]
    fn a_failed_read_of_the_old_account_at_the_switch_is_tried_again_instead_of_skipping_the_notice() {
        let (relay, _clock, a, _b, _words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        tick(&a); // 第 2 步
        let keys = a.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        // 另一台(Y)也寫了標記:第 7 步要提示。
        let mut y = AccountState::new(&keys.chain_id);
        let marker = RotationMarkerPayload { rotated_at_ms: 1, by_device_id: "dev-y".into(), by_device_name: "MacBook-Y".into() };
        put_account_record(&mut y, RecordKind::Meta, &rotation_meta_id("dev-y"), serde_json::to_value(marker).unwrap(), false, "dev-y", 1);
        assert!(push_outgoing(relay.as_ref(), &keys.chain_id, &keys.auth_token, &account_outgoing(&y, &keys).unwrap()).error.is_none());
        for _ in 0..3 {
            tick(&a); // 第 3 步、第 4 至 5 步、第 6 步
        }
        assert_eq!(step(&a), Some(RotationStep::Switching));
        let next = new_code(&a);
        // 第 7 步讀不到舊帳戶:這一步重來,不能略過提示、也不能先換掉帳戶。
        relay.set_broken(&keys.chain_id, true);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Switching));
        assert_eq!(a.state().account.unwrap().chain_id, keys.chain_id, "the account was not switched");
        assert_eq!((a.keychain.entry(NEXT_MNEMONIC_ACCOUNT), a.keychain.entry(MNEMONIC_ACCOUNT).is_some()), (Some(next.clone()), true));
        assert!(!a.state().notices.contains(&SyncNotice::NewSyncCode));
        relay.set_broken(&keys.chain_id, false);
        finish(&a);
        let s = a.state();
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        assert!(s.notices.contains(&SyncNotice::NewSyncCode));
        assert!(s.notices.contains(&SyncNotice::OtherRotation { devices: vec!["MacBook-Y".into()] }));
    }

    /// `start_rotation` 暫存新同步碼的那一刻 —— 鎖外的第一次檢查之後、進度存進狀態之前 —— 同步輪次剛好記下了 `frozen`。
    struct FrozenWhileStaging<'a>(&'a TestDevice);

    impl Keychain for FrozenWhileStaging<'_> {
        fn get(&self, account: &str) -> Result<Option<String>, AppError> {
            self.0.keychain.get(account)
        }
        fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
            if account == NEXT_MNEMONIC_ACCOUNT {
                let mut core = self.0.runtime.core.lock().unwrap();
                core.state.as_mut().unwrap().account.as_mut().unwrap().frozen = Some(FreezeInfo { detected_at_ms: 1, markers: Vec::new() });
            }
            self.0.keychain.set(account, secret)
        }
        fn delete(&self, account: &str) -> Result<(), AppError> {
            self.0.keychain.delete(account)
        }
    }

    #[test]
    fn starting_a_change_is_refused_when_the_account_got_frozen_after_the_first_check() {
        let (_relay, _clock, a, _b, _words, _personal) = pair();
        let racing = FrozenWhileStaging(&a);
        let mut env = a.env();
        env.keychain = &racing;
        assert_eq!(start_rotation(&env).unwrap_err().to_string(), FROZEN_MESSAGE);
        assert!(a.state().rotation.is_none(), "no rotation the worker would never drive");
        assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none(), "the staged code is not left behind");
    }

    /// `a` 更換同步碼,走到第 7 步之前;回傳 (舊碼, 新碼)。
    fn rotate_until_switching(a: &TestDevice, words: &str) -> (String, String) {
        start_rotation(&a.env()).unwrap();
        let next = new_code(a);
        for _ in 0..4 {
            tick(a); // 第 2 步到第 6 步
        }
        assert_eq!(step(a), Some(RotationStep::Switching));
        (words.to_string(), next)
    }

    fn swap_pending(d: &TestDevice) -> bool {
        d.runtime.core.lock().unwrap().swap_pending
    }

    #[test]
    fn a_failed_keychain_swap_at_the_switch_keeps_the_new_code_and_is_retried() {
        let (_relay, _clock, a, _b, words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        let (words, next) = rotate_until_switching(&a, &words);
        // 狀態換成新帳戶了,keychain 的同步碼卻換不過去。
        a.keychain.fail_writes_to(MNEMONIC_ACCOUNT, true);
        tick(&a);
        let s = a.state();
        assert!(s.rotation.is_none());
        assert_eq!(s.account.as_ref().unwrap().chain_id, crypto::derive_account(&next).unwrap().chain_id);
        // 新碼沒有丟:暫存的還在、舊碼還在 keychain;說明記在狀態列(不是被換過的 generation 蓋掉),這個 session 的後續輪次照常同步。
        assert_eq!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT), Some(next.clone()));
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(words));
        assert_eq!(s.last_error.as_deref(), Some(SWAP_PENDING_MESSAGE));
        assert!(swap_pending(&a) && s.notices.contains(&SyncNotice::NewSyncCode));
        assert_eq!(show_words(&a.env()).unwrap(), next, "the user is shown the code that is really in use");
        let new_personal = entry_named(&a, "Personal").id;
        a.save_in_app(&a.space_path(&new_personal), "Host web\n  User x\n");
        settle(&a);
        assert_eq!(a.state().last_error.as_deref(), Some(SWAP_PENDING_MESSAGE), "a finished round does not hide it");
        assert!(a.state().spaces[&new_personal].records.values().all(|l| !l.dirty));
        // 寫得進去了:下一輪補完,旗標與說明都清掉。
        a.keychain.fail_writes_to(MNEMONIC_ACCOUNT, false);
        tick(&a);
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
        assert!(a.state().last_error.is_none() && !swap_pending(&a));
    }

    #[test]
    fn a_swap_that_has_not_landed_holds_back_another_change_and_a_stale_staged_code_does_not() {
        let (_relay, _clock, a, _b, words, _personal) = pair();
        // 暫存著的碼不屬於這個帳戶(之前留下的):不是待補的換碼,不影響顯示同步碼與開始更換。
        a.keychain.set(NEXT_MNEMONIC_ACCOUNT, &crypto::generate_mnemonic().unwrap()).unwrap();
        assert_eq!(show_words(&a.env()).unwrap(), words);
        start_rotation(&a.env()).unwrap();
        cancel_rotation(&a.env()).unwrap();
        let (_old, next) = rotate_until_switching(&a, &words);
        a.keychain.fail_writes_to(MNEMONIC_ACCOUNT, true);
        tick(&a);
        assert!(swap_pending(&a));
        // 新碼還只在暫存裡:這時再開始一次更換會蓋掉它,所以拒絕。
        assert_eq!(start_rotation(&a.env()).unwrap_err().to_string(), SWAP_PENDING_BLOCKS_MESSAGE);
        assert_eq!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT), Some(next.clone()), "the code in use was not overwritten");
        assert!(a.state().rotation.is_none());
        a.keychain.fail_writes_to(MNEMONIC_ACCOUNT, false);
        tick(&a);
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next.clone()));
        // 補完之後可以再更換;暫存的碼就算沒清掉(和正式的同步碼一樣)也不擋。
        a.keychain.set(NEXT_MNEMONIC_ACCOUNT, &next).unwrap();
        start_rotation(&a.env()).unwrap();
        assert_eq!(step(&a), Some(RotationStep::Prepared));
    }

    #[test]
    fn a_rejoin_stages_the_typed_code_so_a_swap_that_never_landed_is_finished_at_startup() {
        let (_relay, _clock, a, b, words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        settle(&b);
        assert!(b.state().frozen().is_some());
        // 輸入新碼:狀態換成新帳戶,keychain 的換碼卻失敗(行程也可能就在這時被關掉)。
        b.keychain.fail_writes_to(MNEMONIC_ACCOUNT, true);
        rejoin_account(&b.env(), &next).unwrap();
        let s = b.state();
        assert!(s.frozen().is_none());
        assert_eq!(b.keychain.entry(MNEMONIC_ACCOUNT), Some(words));
        assert_eq!(b.keychain.entry(NEXT_MNEMONIC_ACCOUNT), Some(next.clone()), "the typed code was staged before the switch");
        assert_eq!(s.last_error.as_deref(), Some(SWAP_PENDING_MESSAGE));
        assert!(swap_pending(&b));
        assert_eq!(show_words(&b.env()).unwrap(), next);
        // 重啟:狀態檔裡已經是新帳戶,啟動時以暫存的碼補完 —— 不必離開再加入。
        let saved = match state_v2::load(&b.env().state_path).unwrap() {
            LoadedState::Current(saved) => *saved,
            other => panic!("expected the saved v2 state, got {other:?}"),
        };
        let chain = saved.account.as_ref().unwrap().chain_id.clone();
        b.keychain.fail_writes_to(MNEMONIC_ACCOUNT, false);
        let done = finish_interrupted_switch(&b.keychain, &chain).expect("the staged code finishes the swap");
        assert!(done.promoted && done.keys.chain_id == chain);
        assert_eq!(b.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        assert!(b.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
    }

    #[test]
    fn a_rejoin_that_cannot_stage_the_code_changes_nothing() {
        let (_relay, _clock, a, b, words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        settle(&b);
        let before = b.state();
        b.keychain.fail_writes_to(NEXT_MNEMONIC_ACCOUNT, true);
        assert!(rejoin_account(&b.env(), &next).is_err());
        assert_eq!(b.state(), before, "the state was not switched");
        assert_eq!(b.keychain.entry(MNEMONIC_ACCOUNT), Some(words));
        // 之後寫得進去了:照常加入。
        b.keychain.fail_writes_to(NEXT_MNEMONIC_ACCOUNT, false);
        rejoin_account(&b.env(), &next).unwrap();
        assert!(b.state().frozen().is_none());
        assert_eq!(b.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
    }

    #[test]
    fn a_staged_code_that_does_not_derive_the_account_is_never_used_or_touched() {
        let keychain = MemKeychain::default();
        let (current, staged) = (crypto::generate_mnemonic().unwrap(), crypto::generate_mnemonic().unwrap());
        keychain.set(MNEMONIC_ACCOUNT, &current).unwrap();
        keychain.set(NEXT_MNEMONIC_ACCOUNT, &staged).unwrap();
        let chain = crypto::derive_account(&current).unwrap().chain_id;
        assert!(finish_interrupted_switch(&keychain, &chain).is_none(), "the staged code belongs to another account");
        assert_eq!((keychain.entry(MNEMONIC_ACCOUNT), keychain.entry(NEXT_MNEMONIC_ACCOUNT)), (Some(current), Some(staged.clone())));
        // 暫存的碼就是這個帳戶的碼:補完。keychain 讀不到(上鎖)時不知道有沒有,不補、也不動。
        let staged_chain = crypto::derive_account(&staged).unwrap().chain_id;
        keychain.fail_reads.store(true, Ordering::SeqCst);
        assert!(finish_interrupted_switch(&keychain, &staged_chain).is_none());
        keychain.fail_reads.store(false, Ordering::SeqCst);
        let done = finish_interrupted_switch(&keychain, &staged_chain).unwrap();
        assert!(done.promoted);
        assert_eq!((keychain.entry(MNEMONIC_ACCOUNT), keychain.entry(NEXT_MNEMONIC_ACCOUNT)), (Some(staged), None));
    }

    /// 主機 `alias` 現在在哪個檔案(ssh 與 app 讀得到的那一個)。
    fn host_file(d: &TestDevice, alias: &str) -> Option<std::path::PathBuf> {
        let doc = d.doc.lock().unwrap();
        let doc = doc.as_ref().unwrap();
        crate::config::include::find_host_file_index(doc, alias).map(|i| doc.files[i].path.clone())
    }

    fn file_name(path: &std::path::Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn rejoining_with_the_code_of_an_unrelated_account_is_refused_and_changes_nothing() {
        let (relay, clock, a, b, words, personal) = pair();
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        settle(&b);
        let file = b.space_path(&personal);
        b.save_in_app(&file, "Host mine\n");
        // 別人的帳戶的碼:這台勾選的 space 沒有一個被它接續。
        let c = TestDevice::new("c", &relay, &clock);
        let other_code = create_account(&c.env(), "MacBook-C").unwrap();
        let (state, main) = (b.state(), b.main_config());
        assert_eq!(rejoin_account(&b.env(), &other_code).unwrap_err().to_string(), NOT_A_SUCCESSOR_MESSAGE);
        assert_eq!(b.state(), state, "nothing changed");
        assert_eq!((b.keychain.entry(MNEMONIC_ACCOUNT), b.keychain.entry(NEXT_MNEMONIC_ACCOUNT)), (Some(words), None));
        assert_eq!((b.main_config(), b.read(&file)), (main, "Host mine\n".to_string()));
        // 正確的碼照常加入。
        rejoin_account(&b.env(), &next).unwrap();
        assert!(b.state().frozen().is_none());
    }

    #[test]
    fn the_refusal_to_rejoin_says_what_is_true_even_when_the_code_is_the_newest_one() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        // 這台勾選的只剩一個從沒送出去的本機 space:新帳戶沒有接續它。輸入的是正確的最新同步碼,照樣被拒絕 —— 出路是離開(檔案留成本機檔案)再用它加入。
        unselect_space(&b.env(), &personal).unwrap();
        let lab = create_space(&b.env(), "Lab").unwrap();
        b.save_in_app(&b.space_path(&lab), "Host gpu\n");
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        settle(&b);
        assert!(b.state().frozen().is_some());
        let state = b.state();
        let err = rejoin_account(&b.env(), &next).unwrap_err().to_string();
        assert_eq!(err, NOT_A_SUCCESSOR_MESSAGE);
        // 不指責這組碼(它是對的):說的是「這台同步的 space 沒有一個在那個帳戶裡接續」,並說明它若是最新的碼該怎麼辦。
        assert!(err.starts_with("none of the spaces this computer syncs continue in that sync account"), "{err}");
        assert!(err.contains("if it is the newest sync code, leave the sync account") && err.ends_with("and join with it"), "{err}");
        assert!(!err.contains("does not continue") && !err.contains("belongs to another"), "{err}");
        assert_eq!(b.state(), state, "nothing changed");
    }

    #[test]
    fn a_rejoin_keeps_a_space_the_new_account_does_not_continue_as_a_local_file_ssh_still_reads() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let personal_file = b.space_path(&personal);
        // B 在這台建立了一個 space、寫了主機,還沒上傳:更換同步碼的快照裡沒有它。
        let lab = create_space(&b.env(), "Lab").unwrap();
        let lab_file = b.space_path(&lab);
        b.save_in_app(&lab_file, "Host gpu\n");
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        settle(&b);
        assert!(b.state().frozen().is_some());
        rejoin_account(&b.env(), &next).unwrap();
        let s = b.state();
        // Lab 的檔案搬到 ~/.ssh/sshelter-local/,主 config 原地改成一般的 Include;ssh(與 app)照常讀得到 gpu。
        let kept = space_files::local_dir(&b.ssh_dir()).join(file_name(&lab_file));
        assert!(!lab_file.exists());
        assert_eq!(b.read(&kept), "Host gpu\n");
        assert!(b.main_config().contains(&format!("Include ~/.ssh/sshelter-local/{}", file_name(&lab_file))), "{}", b.main_config());
        assert_eq!(host_file(&b, "gpu"), Some(kept.clone()));
        assert_eq!(s.notices, vec![SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }]);
        assert_eq!(b.events.notices.lock().unwrap().last(), s.notices.last());
        // 接續的 Personal 照常帶過來。
        let new_personal = entry_named(&b, "Personal").id;
        assert_eq!(s.spaces.keys().collect::<Vec<_>>(), vec![&new_personal]);
        assert_eq!(b.space_path(&new_personal), personal_file);
    }

    /// A 更換同步碼走到第 7 步之前,而 Work 在 A 第 2 步之後被 B 刪掉了:A 凍結之前沒有再拉帳戶,快照裡沒有 Work,A 卻還勾選著它。
    fn rotate_while_work_is_deleted_elsewhere() -> (TestDevice, TestDevice, String, std::path::PathBuf) {
        let (_relay, _clock, a, b, _, _personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        let work_file = a.space_path(&work);
        a.save_in_app(&work_file, "Host db\n");
        settle(&a);
        settle(&b);
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        tick(&a); // 第 2 步:A 拉到的帳戶裡還有 Work
        delete_space(&b.env(), &work).unwrap();
        settle(&b);
        for _ in 0..3 {
            tick(&a); // 第 3 步、第 4 至 5 步、第 6 步
        }
        assert_eq!(step(&a), Some(RotationStep::Switching));
        (a, b, next, work_file)
    }

    #[test]
    fn the_switch_keeps_a_selected_space_the_snapshot_no_longer_has_as_a_local_file() {
        let (a, _b, next, work_file) = rotate_while_work_is_deleted_elsewhere();
        finish(&a);
        let s = a.state();
        let kept = space_files::local_dir(&a.ssh_dir()).join(file_name(&work_file));
        assert!(!work_file.exists());
        assert_eq!(a.read(&kept), "Host db\n");
        assert_eq!(host_file(&a, "db"), Some(kept.clone()), "ssh and the app still read the host");
        assert_eq!(s.notices.last(), Some(&SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }));
        assert!(s.notices.contains(&SyncNotice::NewSyncCode));
        assert_eq!(s.spaces.len(), 1, "only the space the new account continues is synced");
        assert!(space_entries(s.account.as_ref().unwrap()).iter().all(|e| e.name != "Work"));
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
    }

    #[test]
    fn a_space_that_cannot_be_kept_local_stops_the_switch_and_backs_off_until_it_can() {
        let (a, _b, next, work_file) = rotate_while_work_is_deleted_elsewhere();
        let (old_account, words) = (a.state().account.unwrap().chain_id, a.keychain.entry(MNEMONIC_ACCOUNT));
        // `~/.ssh/sshelter-local` 被一個一般檔案佔著:檔案搬不過去(不是主 config 被改過的衝突)。
        let blocker = space_files::local_dir(&a.ssh_dir());
        std::fs::write(&blocker, b"in the way").unwrap();
        let main = a.main_config();
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Switching), "nothing was installed");
        assert_eq!(a.state().account.unwrap().chain_id, old_account);
        assert_eq!((a.keychain.entry(MNEMONIC_ACCOUNT), a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_some()), (words, true));
        assert!(work_file.is_file());
        assert_eq!(a.main_config(), main);
        // 這一步是背景執行緒自己重試:說明不能叫使用者再試一次;退避一輪。
        let message = a.state().last_error.unwrap();
        assert!(message.starts_with("could not keep this device's synced files as local files"), "{message}");
        assert!(message.ends_with("SSHelter retries the sync code change by itself") && !message.contains("try again"), "{message}");
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 1, "a failed switch backs off");
        // 擋路的東西移開:下一次就成功。
        std::fs::remove_file(&blocker).unwrap();
        tick(&a);
        assert!(a.state().rotation.is_none());
        assert_eq!(a.read(&space_files::local_dir(&a.ssh_dir()).join(file_name(&work_file))), "Host db\n");
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
    }

    #[test]
    fn a_main_config_changed_outside_the_app_reruns_the_switch_at_once_and_is_not_a_failed_round() {
        let (a, _b, next, work_file) = rotate_while_work_is_deleted_elsewhere();
        // 主 config 在 app 以外被改過(doc 過時):寫回 Include 時 `persist_file` 回 `Conflict`。同一般輪次:doc 已重載、馬上重跑,
        // 不是要顯示的錯誤、不算失敗的一輪。
        let edited = format!("{}# edited elsewhere\n", a.main_config());
        a.write_externally(&a.main_path(), &edited);
        let (wakes, implicit) = (a.events.wakes(), a.events.implicit_wakes());
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Switching), "nothing was installed");
        assert!(work_file.is_file() && !space_files::local_dir(&a.ssh_dir()).join(file_name(&work_file)).exists());
        assert_eq!(a.main_config(), edited);
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 0, "not a failed round");
        assert!(a.state().last_error.is_none(), "not an error to show: {:?}", a.state().last_error);
        assert!(a.events.wakes() > wakes, "the rerun is asked for at once");
        assert_eq!(a.events.implicit_wakes(), implicit, "an engine rerun is never an implicit wake: it must not wait out a backoff");
        // doc 已從磁碟重載:這一次就成功,外部加的那一行留著。
        tick(&a);
        assert!(a.state().rotation.is_none());
        assert_eq!(a.read(&space_files::local_dir(&a.ssh_dir()).join(file_name(&work_file))), "Host db\n");
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        assert!(a.main_config().ends_with("# edited elsewhere\n"));
    }

    #[test]
    fn a_rejoin_that_cannot_keep_a_space_local_changes_nothing_and_leaves_no_staged_code() {
        let (_relay, _clock, a, b, words, _personal) = pair();
        let lab = create_space(&b.env(), "Lab").unwrap();
        b.save_in_app(&b.space_path(&lab), "Host gpu\n");
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        settle(&b);
        let before = b.state();
        let edited = format!("{}# edited elsewhere\n", b.main_config());
        b.write_externally(&b.main_path(), &edited);
        let err = rejoin_account(&b.env(), &next).unwrap_err();
        assert!(err.to_string().starts_with("could not keep this device's synced files as local files"), "{err}");
        assert_eq!(b.state(), before, "nothing was switched");
        assert_eq!((b.keychain.entry(MNEMONIC_ACCOUNT), b.keychain.entry(NEXT_MNEMONIC_ACCOUNT)), (Some(words), None));
        assert!(b.state().frozen().is_some());
        // doc 已從磁碟重載:再輸入一次就成功。
        rejoin_account(&b.env(), &next).unwrap();
        assert!(b.state().frozen().is_none());
        assert!(matches!(b.state().notices.last(), Some(SyncNotice::LeftAccount { .. })));
    }

    #[test]
    fn a_copy_that_stopped_part_way_is_finished_and_rows_already_written_count_as_copied() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        let hosts: String = (0..250).map(|i| format!("Host h{i}\n")).collect();
        a.save_in_app(&a.space_path(&personal), &hosts);
        settle(&a);
        start_rotation(&a.env()).unwrap();
        tick(&a);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Copying));
        let new_space = a.state().rotation.unwrap().spaces[&personal].new_space_id.clone();
        // 第一批(200 筆)寫進新 chain,第二批碰到儲存額度:這個 space 沒複製完,也還沒記成已複製。
        relay.set_push_quota(Some(1));
        tick(&a);
        let progress = a.state().rotation.unwrap();
        assert_eq!(progress.step, RotationStep::Copying);
        assert!(progress.copied.is_empty());
        assert_eq!(relay.rows(&new_space).len(), 200);
        // 重跑:已經寫過的列回 conflict、算已複製;剩下的補上 —— 沒有重複、也沒有缺。
        relay.set_push_quota(None);
        finish(&a);
        assert_eq!(relay.rows(&new_space).len(), 250);
        assert_eq!(entry_named(&a, "Personal").id, new_space);
        assert_eq!(a.read(&a.space_path(&new_space)), hosts);
    }

    #[test]
    fn a_delete_step_that_stopped_part_way_is_finished_and_deleting_a_chain_twice_is_harmless() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        let work = create_space(&a.env(), "Work").unwrap();
        a.save_in_app(&a.space_path(&work), "Host db\n");
        settle(&a);
        let old_chains: Vec<ChainKeys> = {
            let core = a.runtime.core.lock().unwrap();
            let (s, keys) = (core.state.as_ref().unwrap(), core.account_keys.as_ref().unwrap());
            [&personal, &work].into_iter().map(|id| space_keys(s.account.as_ref().unwrap(), keys, id).unwrap()).collect()
        };
        start_rotation(&a.env()).unwrap();
        for _ in 0..3 {
            tick(&a); // 第 2 步、第 3 步、第 4 至 5 步
        }
        assert_eq!(step(&a), Some(RotationStep::Deleting));
        // 第 6 步依舊 space id 的順序一條一條刪:第一條的 DELETE 失敗,第二條的其實已經到了 relay。
        let order: Vec<String> = a.state().rotation.unwrap().spaces.keys().cloned().collect();
        let chain_of = |id: &String| old_chains[if *id == personal { 0 } else { 1 }].clone();
        let (first, second) = (chain_of(&order[0]), chain_of(&order[1]));
        // 第 6 步的第一個 DELETE 送出去的那一刻 relay 連不上:這一步沒做完,進度還停在這裡。
        let down = relay.clone();
        let hooked = HookedConnector::new(&relay, Hooks { before_delete: Some(Box::new(move || down.set_offline(true))), ..Hooks::default() });
        let mut env = a.env();
        env.relays = &hooked;
        let _ = sync_once(&env);
        assert_eq!(step(&a), Some(RotationStep::Deleting));
        relay.set_offline(false);
        assert!(!relay.rows(&first.chain_id).is_empty(), "the failed DELETE did not reach the relay");
        // 第二條的 DELETE 已經到了 relay、進度卻沒有存下來:它已經是空的、仍然凍結,再刪一次沒有關係。
        relay.delete_chain(&second.chain_id, &second.auth_token).unwrap();
        finish(&a);
        for old in &old_chains {
            assert!(relay.rows(&old.chain_id).is_empty() && relay.is_frozen(&old.chain_id), "an old chain is emptied and stays frozen");
        }
        assert!(a.state().notices.contains(&SyncNotice::NewSyncCode));
    }

    #[test]
    fn a_switch_that_cannot_read_the_new_account_is_rerun_until_it_can() {
        let (relay, _clock, a, _b, words, _personal) = pair();
        let (_old, next) = rotate_until_switching(&a, &words);
        let new_account = crypto::derive_account(&next).unwrap().chain_id;
        let old_account = a.state().account.unwrap().chain_id;
        // 第 7 步一開始讀新帳戶就失敗:什麼都還沒換,退避之後重來。
        relay.set_broken(&new_account, true);
        tick(&a);
        assert_eq!(step(&a), Some(RotationStep::Switching));
        assert_eq!(a.state().account.unwrap().chain_id, old_account, "nothing was installed");
        assert_eq!((a.keychain.entry(MNEMONIC_ACCOUNT), a.keychain.entry(NEXT_MNEMONIC_ACCOUNT)), (Some(words), Some(next.clone())));
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 1);
        relay.set_broken(&new_account, false);
        tick(&a);
        assert!(a.state().rotation.is_none());
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
    }

    #[test]
    fn a_rejoin_that_cannot_find_or_follow_the_new_account_changes_nothing() {
        let (relay, _clock, a, b, words, _personal) = pair();
        // 還沒偵測到更換:不能重新加入。
        assert_eq!(rejoin_account(&b.env(), &words).unwrap_err().to_string(), "the sync code of this account has not been changed");
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        settle(&b);
        let before = b.state();
        let untouched = |b: &TestDevice| {
            assert_eq!(b.state(), before, "nothing changed");
            assert_eq!((b.keychain.entry(MNEMONIC_ACCOUNT), b.keychain.entry(NEXT_MNEMONIC_ACCOUNT)), (Some(words.clone()), None));
        };
        // 沒有這個帳戶(打錯的碼):不暫存、什麼都不改。
        let err = rejoin_account(&b.env(), &crypto::generate_mnemonic().unwrap()).unwrap_err();
        assert!(matches!(&err, AppError::NotFound(m) if m == NO_ACCOUNT_MESSAGE), "{err}");
        untouched(&b);
        // 新帳戶也已經被別台(Y)更換了:請使用者輸入最新的碼。
        let keys = crypto::derive_account(&next).unwrap();
        let mut y = AccountState::new(&keys.chain_id);
        let marker = RotationMarkerPayload { rotated_at_ms: 1, by_device_id: "dev-y".into(), by_device_name: "MacBook-Y".into() };
        put_account_record(&mut y, RecordKind::Meta, &rotation_meta_id("dev-y"), serde_json::to_value(marker).unwrap(), false, "dev-y", 1);
        assert!(push_outgoing(relay.as_ref(), &keys.chain_id, &keys.auth_token, &account_outgoing(&y, &keys).unwrap()).error.is_none());
        let err = rejoin_account(&b.env(), &next).unwrap_err();
        assert_eq!(err.to_string(), "this sync code was changed as well, on MacBook-Y; enter the newest sync code");
        untouched(&b);
    }

    #[test]
    fn the_create_pause_survives_a_restart_and_the_change_carries_on_after_it() {
        let (relay, clock, a, _b, _words, _personal) = pair();
        start_rotation(&a.env()).unwrap();
        tick(&a);
        tick(&a);
        relay.fail_creates_with_429(1);
        tick(&a);
        let paused = a.state().rotation.unwrap();
        assert_eq!(paused.step, RotationStep::Copying);
        assert!(paused.paused_until_ms.is_some());
        // 重啟:狀態檔裡的進度(含暫停到什麼時候)原樣讀回來,金鑰從 keychain 推導。
        let saved = match state_v2::load(&a.env().state_path).unwrap() {
            LoadedState::Current(saved) => *saved,
            other => panic!("expected the saved v2 state, got {other:?}"),
        };
        assert_eq!(saved.rotation.as_ref(), Some(&paused));
        let keys = crypto::derive_account(&a.keychain.entry(MNEMONIC_ACCOUNT).unwrap()).unwrap();
        *a.runtime.core.lock().unwrap() = crate::sync::runtime::SyncCore { state: Some(saved), account_keys: Some(keys), ..Default::default() };
        // 暫停還沒到:什麼都不做;到了就自動接續。
        relay.clear_calls();
        tick(&a);
        assert!(relay.calls().is_empty(), "still paused after the restart");
        clock.advance(2 * CREATE_PAUSE_MS);
        finish(&a);
        assert!(a.state().notices.contains(&SyncNotice::NewSyncCode));
    }

    #[test]
    fn a_rejoin_in_a_process_that_cannot_save_the_sync_state_changes_nothing() {
        let (_relay, _clock, a, b, words, _personal) = pair();
        let lab = create_space(&b.env(), "Lab").unwrap();
        let lab_file = b.space_path(&lab);
        b.save_in_app(&lab_file, "Host gpu\n");
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        settle(&b);
        assert!(b.state().frozen().is_some());
        // 另一個 SSHelter 行程持有同步鎖(`engine::initialize`):這個行程不寫狀態(`save_blocked`)、沒有帳戶金鑰、也不該動共用的 keychain 與 `~/.ssh`。
        {
            let mut core = b.runtime.core.lock().unwrap();
            core.save_blocked = Some(ANOTHER_ENGINE_MESSAGE.to_string());
            core.account_keys = None;
        }
        let (before, main) = (b.state(), b.main_config());
        assert_eq!(rejoin_account(&b.env(), &next).unwrap_err().to_string(), ANOTHER_ENGINE_MESSAGE);
        assert_eq!(
            (b.keychain.entry(MNEMONIC_ACCOUNT), b.keychain.entry(NEXT_MNEMONIC_ACCOUNT)),
            (Some(words), None),
            "the shared keychain is not touched"
        );
        assert!(lab_file.is_file() && !space_files::local_dir(&b.ssh_dir()).exists(), "no file was moved");
        assert_eq!(b.main_config(), main, "~/.ssh/config was not rewritten");
        assert_eq!(b.state(), before, "the state of the process that owns the engine is not touched");
    }

    #[test]
    fn a_vanished_old_account_at_the_switch_means_no_other_markers_and_the_switch_goes_on() {
        let (relay, _clock, a, _b, words, _personal) = pair();
        let old_account = a.state().account.unwrap().chain_id;
        let (_old, next) = rotate_until_switching(&a, &words);
        // 舊帳戶 chain 閒置太久被 relay 整條清除:第 7 步讀它只是為了看有沒有別台的標記 —— 讀不到(404)就是沒有,不能因此永遠停在這一步。
        relay.expire(&old_account);
        tick(&a);
        let s = a.state();
        assert!(s.rotation.is_none(), "the switch went on");
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        assert!(s.notices.contains(&SyncNotice::NewSyncCode));
        assert!(!s.notices.iter().any(|n| matches!(n, SyncNotice::OtherRotation { .. })), "no other markers could be read");
    }

    #[test]
    fn a_switch_that_could_not_save_its_state_leaves_the_swap_to_the_next_start() {
        let (_relay, _clock, a, _b, words, _personal) = pair();
        let (_old, next) = rotate_until_switching(&a, &words);
        // 狀態檔寫不進去(`data` 目錄換成一個一般檔案):狀態只換在記憶體,第 7 步在換 keychain 之前就回了錯。
        let blocker = a.home.path().join("data");
        std::fs::remove_dir_all(&blocker).unwrap();
        std::fs::write(&blocker, b"in the way").unwrap();
        tick(&a);
        assert!(a.runtime.core.lock().unwrap().unsaved);
        assert_eq!((a.keychain.entry(MNEMONIC_ACCOUNT), a.keychain.entry(NEXT_MNEMONIC_ACCOUNT)), (Some(words), Some(next.clone())));
        // 這時沒有輪次會補 keychain,所以拒絕新的更換時不能說「自動再試」:說的是最晚下次啟動就補完。
        assert_eq!(start_rotation(&a.env()).unwrap_err().to_string(), SWAP_PENDING_BLOCKS_MESSAGE);
        assert!(SWAP_PENDING_BLOCKS_MESSAGE.contains("the next time it starts"), "{SWAP_PENDING_BLOCKS_MESSAGE}");
        // 狀態檔寫得進去了(下一輪一開始就補寫)、行程重啟:啟動時以暫存的碼補完 —— 說的就是這件事;之後可以再更換。
        std::fs::remove_file(&blocker).unwrap();
        {
            let mut core = a.runtime.core.lock().unwrap();
            save_core(&mut core, &a.env().state_path).unwrap();
        }
        let saved = match state_v2::load(&a.env().state_path).unwrap() {
            LoadedState::Current(saved) => *saved,
            other => panic!("expected the saved v2 state, got {other:?}"),
        };
        let chain = saved.account.as_ref().unwrap().chain_id.clone();
        let done = finish_interrupted_switch(&a.keychain, &chain).expect("the next start finishes the swap");
        assert!(done.promoted);
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT), Some(next));
        start_rotation(&a.env()).unwrap();
    }

    #[test]
    fn changing_the_sync_code_carries_the_key_slots() {
        use crate::sync::slot_rules::{test_keys, SlotMode, SLOT_DIR};
        use crate::sync::slots::tests::{create_slot_on, use_slot};
        use crate::sync::slots::{live_slots, open_key_secret};
        let (_relay, _clock, a, b, _words, personal) = pair();
        let (id, file) = create_slot_on(&a, SlotMode::Synced, &test_keys::plain(), "id_mac");
        use_slot(&a, &personal, &file);
        settle(&a);
        settle(&b);

        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        finish(&a);
        let account = a.state().account.unwrap();
        assert_eq!(live_slots(&account).iter().map(|(i, _)| i.clone()).collect::<Vec<_>>(), vec![id.clone()]);
        let keys = a.env().runtime.core.lock().unwrap().account_keys.clone().unwrap();
        assert_eq!(open_key_secret(&account, &keys, &id).as_deref(), Some(test_keys::plain().as_str()));

        // B 以新同步碼重新加入:插槽還在,副本照常。
        settle(&b);
        rejoin_account(&b.env(), &next).unwrap();
        settle(&b);
        assert_eq!(live_slots(b.state().account.as_ref().unwrap())[0].0, id);
        let copy = b.ssh_dir().parent().unwrap().join(SLOT_DIR).join(&file);
        assert_eq!(std::fs::read_to_string(copy).unwrap(), test_keys::plain());
    }

    /// `changing_the_sync_code_carries_the_key_slots` 證明不了複製步驟:更換之後這台自己的下一輪會把還有主機在用的插槽補寫回新帳戶
    /// (`slots::reconcile`),複製漏掉了也看不出來。所以這個測試在剛複製完、還沒有任何一輪跑過的時候,直接讀 relay 上的新帳戶
    /// (SP3 spec §6.6):每一筆 `keyslot` 原樣(含 tombstone)、每一筆 `key` 改以新帳戶金鑰加密,version、時間戳、裝置都不變 ——
    /// 沒有主機用到的插槽也一樣(補寫幫不了它們)。
    #[test]
    fn the_copy_carries_every_key_slot_record_and_seals_the_keys_for_the_new_account() {
        use crate::sync::record::record_key;
        use crate::sync::slot_rules::{test_keys, SlotMode};
        use crate::sync::slots::tests::create_slot_on;
        use crate::sync::slots::{key_secret_key, live_slots, open_key_secret, put_key_secret, put_slot, slot, slot_record_exists};
        let (relay, clock, a, b, _words, _personal) = pair();
        // B 建的三個插槽,沒有任何主機用到:同步的(後來又寫過一版)、每台電腦用自己的金鑰的、同步過又刪掉的。
        let (synced, _) = create_slot_on(&b, SlotMode::Synced, &test_keys::plain(), "id_mac");
        let (own, _) = create_slot_on(&b, SlotMode::Own, &test_keys::ecdsa(), "id_own");
        let (gone, _) = create_slot_on(&b, SlotMode::Synced, &test_keys::ecdsa(), "id_old");
        let b_keys = b.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        let b_env = b.env();
        let now = b_env.now();
        mutate(&b_env, |s| {
            let me = s.device_id.clone();
            let account = s.account.as_mut().unwrap();
            let payload = slot(account, &synced).expect("the slot is there");
            put_slot(account, &synced, Some(&payload), &me, now);
            put_key_secret(account, &b_keys, &synced, Some(&test_keys::plain()), &me, now)?;
            put_slot(account, &gone, None, &me, now);
            put_key_secret(account, &b_keys, &gone, None, &me, now)
        })
        .unwrap();
        settle(&b);
        settle(&a);
        // 更換發生在這些記錄寫下很久以後:重新寫一筆的話,時間戳一定對不上。
        clock.advance(60_000);

        let old_keys = a.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        start_rotation(&a.env()).unwrap();
        let next = new_code(&a);
        for _ in 0..3 {
            tick(&a); // 第 2 步、第 3 步、第 4 至 5 步
        }
        assert_eq!(step(&a), Some(RotationStep::Deleting), "the copy is done and no round has run since");

        let new_keys = crypto::derive_account(&next).unwrap();
        let new = merge_account(&AccountState::new(&new_keys.chain_id), &new_keys, &relay.pull(&new_keys.chain_id, &new_keys.auth_token, 0).unwrap()).section;
        let old = old_account_snapshot(&old_keys, relay.as_ref()).unwrap().section;
        let old_slots: Vec<_> = old.records.values().filter(|l| l.record.kind == RecordKind::KeySlot).collect();
        assert_eq!(old_slots.len(), 3, "the three slots, one of them a tombstone");
        for local in old_slots {
            let carried = new.records.get(&record_key(RecordKind::KeySlot, &local.record.id)).expect("every keyslot is carried");
            assert_eq!(carried.record, local.record, "a keyslot arrives as it was: payload, version, timestamp, device, tombstone");
        }
        let old_secrets: Vec<Record> =
            old.sealed.values().filter(|s| s.envelope.kind == RecordKind::Key.as_str()).map(|s| s.open(&old_keys).unwrap()).collect();
        assert_eq!(old_secrets.len(), 2, "the synced slot's key and the deleted slot's tombstone; a slot every computer fills itself has none");
        for record in old_secrets {
            let carried = new.sealed.get(&key_secret_key(&new_keys, &record.id)).expect("every key is carried").open(&new_keys);
            assert_eq!(carried.ok().as_ref(), Some(&record), "a key is sealed again for the new account, nothing else changes");
        }

        // 不是因為什麼都沒有才相等:同步的那把以新帳戶金鑰讀得出來,是 B 寫的第 2 版;刪掉的插槽留著 tombstone,沒有人會把它補寫回來。
        let mut live: Vec<String> = live_slots(&new).into_iter().map(|(id, _)| id).collect();
        live.sort();
        let mut expected = vec![synced.clone(), own.clone()];
        expected.sort();
        assert_eq!(live, expected);
        assert_eq!(open_key_secret(&new, &new_keys, &synced).as_deref(), Some(test_keys::plain().as_str()));
        let carried_key = new.sealed[&key_secret_key(&new_keys, &synced)].open(&new_keys).unwrap();
        assert_eq!((carried_key.version, carried_key.device_id), (2, b.state().device_id));
        assert!(!new.sealed.contains_key(&key_secret_key(&new_keys, &own)), "no key record is made up for a slot that has none");
        assert!(slot_record_exists(&new, &gone) && open_key_secret(&new, &new_keys, &gone).is_none());
        assert!(new.records.keys().all(|k| !k.starts_with("key:")), "a key is never a plaintext record");

        // 做完之後狀態檔裡的金鑰仍是密文。
        finish(&a);
        let text = std::fs::read_to_string(a.env().state_path).unwrap();
        assert!(text.contains(&key_secret_key(&new_keys, &synced)), "the sealed key is in the state file");
        for line in test_keys::PLAIN_BODY {
            assert!(!text.contains(line), "a line of the private key is in the state file");
        }
    }
}
