//! 本機變更偵測:把受管檔目前的 Host 區塊與快取記錄比對,產生要上傳的新版記錄。
//! 時間戳逐區塊(由呼叫端提供),不是一個整檔的時間。

use std::collections::BTreeMap;

use serde_json::Value;

use crate::sync::hosts_file::HostBlockText;
use crate::sync::record::{record_key, HostPayload, LocalRecord, Record, RecordKind, SCHEMA_VERSION};

/// 時間戳單調:裝置時鐘落後時仍必須大於前一版,否則 LWW 永遠輸。
pub fn next_timestamp(now_ms: u64, previous: Option<u64>) -> u64 {
    match previous {
        Some(p) if p >= now_ms => p + 1,
        _ => now_ms,
    }
}

fn host_text(payload: &Value) -> Option<String> {
    serde_json::from_value::<HostPayload>(payload.clone()).ok().map(|p| p.text)
}

/// 比對受管檔目前的區塊與快取:新增/修改 → 新版記錄;消失 → tombstone(僅一次)。
/// `changed_at(alias)` 是該區塊的修改時間(app 存檔當下或外部編輯的檔案 mtime),由呼叫端提供。
pub fn detect_local_changes(
    cached: &BTreeMap<String, LocalRecord>,
    current: &[HostBlockText],
    device_id: &str,
    changed_at: impl Fn(&str) -> u64,
) -> Vec<Record> {
    let mut out = Vec::new();

    for block in current {
        let key = record_key(RecordKind::Host, &block.alias);
        let previous = cached.get(&key).map(|l| &l.record);
        let unchanged = previous
            .filter(|r| !r.deleted)
            .and_then(|r| host_text(&r.payload))
            .map(|t| t == block.text)
            .unwrap_or(false);
        if unchanged {
            continue;
        }
        out.push(Record {
            kind: RecordKind::Host,
            id: block.alias.clone(),
            version: previous.map(|r| r.version + 1).unwrap_or(1),
            updated_at_ms: next_timestamp(changed_at(&block.alias), previous.map(|r| r.updated_at_ms)),
            device_id: device_id.to_string(),
            deleted: false,
            payload: serde_json::to_value(HostPayload { schema: SCHEMA_VERSION, text: block.text.clone() })
                .expect("HostPayload serializes"),
        });
    }

    for local in cached.values() {
        let r = &local.record;
        if r.kind != RecordKind::Host || r.deleted {
            continue;
        }
        if current.iter().any(|b| b.alias == r.id) {
            continue;
        }
        out.push(Record {
            kind: RecordKind::Host,
            id: r.id.clone(),
            version: r.version + 1,
            updated_at_ms: next_timestamp(changed_at(&r.id), Some(r.updated_at_ms)),
            device_id: device_id.to_string(),
            deleted: true,
            payload: Value::Null,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(alias: &str, text: &str) -> HostBlockText {
        HostBlockText { alias: alias.to_string(), text: text.to_string() }
    }

    fn cached(alias: &str, text: &str, version: u64, updated: u64, deleted: bool) -> (String, LocalRecord) {
        let record = Record {
            kind: RecordKind::Host,
            id: alias.to_string(),
            version,
            updated_at_ms: updated,
            device_id: "dev-a".to_string(),
            deleted,
            payload: serde_json::to_value(HostPayload { schema: SCHEMA_VERSION, text: text.to_string() }).unwrap(),
        };
        (record_key(RecordKind::Host, alias), LocalRecord { record, seq: 1, dirty: false })
    }

    #[test]
    fn timestamps_never_go_backwards() {
        assert_eq!(next_timestamp(100, None), 100);
        assert_eq!(next_timestamp(100, Some(50)), 100);
        // 時鐘落後:必須比前一版大。
        assert_eq!(next_timestamp(100, Some(100)), 101);
        assert_eq!(next_timestamp(100, Some(500)), 501);
    }

    #[test]
    fn new_block_becomes_a_version_one_record() {
        let out = detect_local_changes(&BTreeMap::new(), &[block("a", "Host a\n")], "dev-a", |_| 10);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "a");
        assert_eq!(out[0].version, 1);
        assert_eq!(out[0].updated_at_ms, 10);
        assert!(!out[0].deleted);
        assert_eq!(out[0].payload["text"], "Host a\n");
    }

    #[test]
    fn unchanged_block_produces_nothing_and_changed_block_bumps_version() {
        let mut map = BTreeMap::new();
        let (k, v) = cached("a", "Host a\n", 3, 50, false);
        map.insert(k, v);
        assert!(detect_local_changes(&map, &[block("a", "Host a\n")], "dev-a", |_| 60).is_empty());
        let out = detect_local_changes(&map, &[block("a", "Host a\n  User x\n")], "dev-a", |_| 40);
        assert_eq!(out[0].version, 4);
        assert_eq!(out[0].updated_at_ms, 51, "clock skew must not lose to the previous version");
    }

    #[test]
    fn missing_block_becomes_a_tombstone_only_once() {
        let mut map = BTreeMap::new();
        let (k, v) = cached("gone", "Host gone\n", 1, 5, false);
        map.insert(k, v);
        let out = detect_local_changes(&map, &[], "dev-a", |_| 9);
        assert_eq!(out.len(), 1);
        assert!(out[0].deleted);
        assert_eq!(out[0].version, 2);
        assert_eq!(out[0].updated_at_ms, 9);
        // 已是 tombstone 就不再重複產生。
        let (k, v) = cached("gone", "", 2, 9, true);
        let mut map2 = BTreeMap::new();
        map2.insert(k, v);
        assert!(detect_local_changes(&map2, &[], "dev-a", |_| 20).is_empty());
    }

    #[test]
    fn a_block_that_reappears_after_a_tombstone_is_a_new_version() {
        let mut map = BTreeMap::new();
        let (k, v) = cached("back", "", 2, 9, true);
        map.insert(k, v);
        let out = detect_local_changes(&map, &[block("back", "Host back\n")], "dev-a", |_| 30);
        assert_eq!(out.len(), 1);
        assert!(!out[0].deleted);
        assert_eq!(out[0].version, 3);
    }

    #[test]
    fn other_kinds_in_the_cache_are_ignored() {
        let mut map = BTreeMap::new();
        let (k, mut v) = cached("dev", "", 1, 5, false);
        v.record.kind = RecordKind::Device;
        map.insert(k, v);
        // device 記錄不是主機,消失的區塊清單裡不能出現它。
        assert!(detect_local_changes(&map, &[], "dev-a", |_| 9).is_empty());
    }

    #[test]
    fn each_changed_block_carries_its_own_change_time() {
        // 先改 a(t100)、後改 b(t300),worker 才來收:a 不能被套上 b 的時間。
        let mut map = BTreeMap::new();
        let (k, v) = cached("a", "Host a\n", 1, 10, false);
        map.insert(k, v);
        let (k, v) = cached("b", "Host b\n", 1, 10, false);
        map.insert(k, v);
        let mut out = detect_local_changes(
            &map,
            &[block("a", "Host a\n  User x\n"), block("b", "Host b\n  User y\n")],
            "dev-a",
            |alias| if alias == "a" { 100 } else { 300 },
        );
        out.sort_by(|x, y| x.id.cmp(&y.id));
        assert_eq!(out[0].updated_at_ms, 100);
        assert_eq!(out[1].updated_at_ms, 300);
    }
}
