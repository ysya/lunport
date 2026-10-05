//! SP3 金鑰插槽的引擎(spec `docs/superpowers/specs/2026-10-05-sp3-key-slots-design.md` §4、§6):帳戶裡 `keyslot` 與
//! `key` 記錄的讀寫(本節)、每一輪在這台維護插槽(`reconcile`,Task 4)、模式切換與挑選(Task 6)。

use serde_json::Value;

use crate::error::AppError;
use crate::sync::crypto::{id_hash, ChainKeys};
use crate::sync::merge::put_account_record;
use crate::sync::planner::next_timestamp;
use crate::sync::record::{record_key, Record, RecordKind};
use crate::sync::slot_rules::{valid_key_payload, valid_slot_payload, KeyPayload, KeySlotPayload, SLOT_SCHEMA};
use crate::sync::state_v2::{sealed_key, AccountState, SealedRecord};

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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sync::merge::{account_outgoing, merge_account, plan_device, set_device_slots, Outgoing};
    use crate::sync::record::{DevicePayload, Envelope, LocalRecord};
    use crate::sync::relay::PullResponse;
    use crate::sync::slot_rules::{test_keys, DeviceSlot, SlotMode, MAX_PRIVATE_KEY_BYTES};
    use crate::sync::state_v2::{AccountState, LoadedState, SyncStateV2};

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
}
