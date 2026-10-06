//! agent 的核准規則與記住的核准(spec §5.3)。純邏輯:不碰視窗、檔案與時鐘(`now_ms` 由呼叫端給)。

use std::collections::HashMap;

use crate::vault::store::{AgentSettings, DEFAULT_REMEMBER_MINUTES};

/// 「記住」可選的時間(分鐘)。
pub const REMEMBER_CHOICES_MINUTES: [u32; 4] = [15, 60, 240, 720];

/// 這台設定的記住時間;不在可選的值裡(手改的檔案)就用預設。
pub fn remember_minutes(settings: &AgentSettings) -> u32 {
    if REMEMBER_CHOICES_MINUTES.contains(&settings.remember_minutes) {
        settings.remember_minutes
    } else {
        DEFAULT_REMEMBER_MINUTES
    }
}

/// 記住核准的單位:金鑰 × 主機 × 發出請求的程式(spec §5.3、§5.4)。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ApprovalKey {
    pub key_fingerprint: String,
    pub host_fingerprint: String,
    pub program: String,
}

/// 一把金鑰的保護(跟著金鑰同步,`keyprefs`;Plan 1 一律是預設值)。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyProtection {
    pub ask_every_time: bool,
    pub require_user_presence: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// 記住的核准還有效:直接簽。
    Remembered,
    /// 要問;`rememberable` = 視窗可以提供「記住」。
    Ask { rememberable: bool },
}

/// 這次請求要不要問(spec §5.3 的規則 1–3)。「每次都問」的金鑰、這台的「一律每次都問」、未知的主機:一律問,而且不記住。
/// 系統驗證(`require_user_presence`)只在問的時候做,不影響這裡的結果。
pub fn verdict(protection: KeyProtection, settings: &AgentSettings, host_known: bool, remembered: bool) -> Verdict {
    if protection.ask_every_time || settings.always_ask || !host_known {
        return Verdict::Ask { rememberable: false };
    }
    if remembered {
        Verdict::Remembered
    } else {
        Verdict::Ask { rememberable: true }
    }
}

/// 記住的核准(只在記憶體;螢幕鎖定、SSHelter 結束時清除)。值是到期時間(ms)。
#[derive(Default)]
pub struct ApprovalCache {
    entries: HashMap<ApprovalKey, u64>,
}

impl ApprovalCache {
    /// 有沒有還沒到期的核准;順便丟掉所有到期的。
    pub fn is_remembered(&mut self, key: &ApprovalKey, now_ms: u64) -> bool {
        self.entries.retain(|_, expires| *expires > now_ms);
        self.entries.contains_key(key)
    }

    pub fn remember(&mut self, key: ApprovalKey, now_ms: u64, minutes: u32) {
        self.entries.insert(key, now_ms.saturating_add(u64::from(minutes) * 60_000));
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(program: &str) -> ApprovalKey {
        ApprovalKey { key_fingerprint: "SHA256:k".into(), host_fingerprint: "SHA256:h".into(), program: program.into() }
    }

    #[test]
    fn a_remembered_approval_skips_the_prompt_only_when_nothing_forbids_remembering() {
        let settings = AgentSettings::default();
        let open = KeyProtection::default();
        assert_eq!(verdict(open, &settings, true, true), Verdict::Remembered);
        assert_eq!(verdict(open, &settings, true, false), Verdict::Ask { rememberable: true });
        let every_time = KeyProtection { ask_every_time: true, require_user_presence: false };
        assert_eq!(verdict(every_time, &settings, true, true), Verdict::Ask { rememberable: false });
        assert_eq!(verdict(open, &settings, false, true), Verdict::Ask { rememberable: false }, "an unknown host is never remembered");
        let strict = AgentSettings { always_ask: true, ..AgentSettings::default() };
        assert_eq!(verdict(open, &strict, true, true), Verdict::Ask { rememberable: false }, "this computer can only be stricter");
    }

    #[test]
    fn user_presence_does_not_change_the_verdict() {
        let presence = KeyProtection { ask_every_time: false, require_user_presence: true };
        assert_eq!(verdict(presence, &AgentSettings::default(), true, true), Verdict::Remembered);
    }

    #[test]
    fn the_cache_expires_and_is_keyed_by_key_host_and_program() {
        let mut cache = ApprovalCache::default();
        cache.remember(key("claude"), 1_000, 15);
        assert!(cache.is_remembered(&key("claude"), 1_000 + 15 * 60_000 - 1));
        assert!(!cache.is_remembered(&key("iterm2"), 1_000), "another program asks again");
        assert!(!cache.is_remembered(&key("claude"), 1_000 + 15 * 60_000), "expired at the boundary");
        assert_eq!(cache.len(), 0, "expired entries are dropped");
    }

    #[test]
    fn clear_forgets_everything() {
        let mut cache = ApprovalCache::default();
        cache.remember(key("a"), 0, 240);
        cache.remember(key("b"), 0, 240);
        cache.clear();
        assert!(!cache.is_remembered(&key("a"), 1));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn remember_minutes_only_accepts_the_offered_choices() {
        for minutes in REMEMBER_CHOICES_MINUTES {
            assert_eq!(remember_minutes(&AgentSettings { remember_minutes: minutes, always_ask: false }), minutes);
        }
        assert_eq!(remember_minutes(&AgentSettings { remember_minutes: 7, always_ask: false }), DEFAULT_REMEMBER_MINUTES);
    }
}
