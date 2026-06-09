use serde::{Deserialize, Serialize};

use crate::config::model::{HostBlock, Item, SshConfigDoc};

// ─── DTO types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostOption {
    pub keyword: String,
    pub value: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostSummary {
    /// First pattern token, used as the primary identifier in the UI.
    pub alias: String,
    pub patterns: Vec<String>,
    /// The ConfigFile path as a string (lossy UTF-8).
    pub source_file: String,
    /// Parsed from a `#tags:` sentinel comment in the host body.
    pub tags: Vec<String>,
    /// First enabled `HostName` value, if any — for a meaningful, distinct list subtitle.
    pub hostname: Option<String>,
    /// First enabled `User` value, if any.
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostDetail {
    pub alias: String,
    pub patterns: Vec<String>,
    pub source_file: String,
    pub tags: Vec<String>,
    /// Every body Directive in order (comments and blanks are skipped).
    pub options: Vec<HostOption>,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// All hosts across all files, in file then document order.
pub fn host_summaries(doc: &SshConfigDoc) -> Vec<HostSummary> {
    let mut out = Vec::new();
    for cf in &doc.files {
        let source_file = cf.path.to_string_lossy().to_string();
        for item in &cf.items {
            if let Item::Host(h) = item {
                out.push(build_summary(h, &source_file));
            }
        }
    }
    out
}

/// Detail for the first host matching `alias`, or None.
pub fn host_detail(doc: &SshConfigDoc, alias: &str) -> Option<HostDetail> {
    for cf in &doc.files {
        let source_file = cf.path.to_string_lossy().to_string();
        for item in &cf.items {
            if let Item::Host(h) = item {
                if h.patterns.iter().any(|p| p == alias) {
                    return Some(build_detail(h, &source_file));
                }
            }
        }
    }
    None
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn build_summary(h: &HostBlock, source_file: &str) -> HostSummary {
    let alias = h.patterns.first().cloned().unwrap_or_default();
    let tags = parse_tags(&h.body);
    HostSummary {
        alias,
        patterns: h.patterns.clone(),
        source_file: source_file.to_string(),
        tags,
        hostname: first_enabled_value(&h.body, "hostname"),
        user: first_enabled_value(&h.body, "user"),
    }
}

/// First enabled directive value for `key_lower` in a block body (trimmed, non-empty), else None.
fn first_enabled_value(body: &[Item], key_lower: &str) -> Option<String> {
    for item in body {
        if let Item::Directive(d) = item {
            if d.enabled && d.key == key_lower {
                let v = d.value.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn build_detail(h: &HostBlock, source_file: &str) -> HostDetail {
    let alias = h.patterns.first().cloned().unwrap_or_default();
    let tags = parse_tags(&h.body);

    let options = h
        .body
        .iter()
        .filter_map(|item| {
            if let Item::Directive(d) = item {
                Some(HostOption {
                    keyword: d.keyword.clone(),
                    value: d.value.clone(),
                    enabled: d.enabled,
                })
            } else {
                None
            }
        })
        .collect();

    HostDetail {
        alias,
        patterns: h.patterns.clone(),
        source_file: source_file.to_string(),
        tags,
        options,
    }
}

/// Parse `#tags:` sentinel from a block body.
fn parse_tags(body: &[Item]) -> Vec<String> {
    for item in body {
        if let Item::Comment(s) = item {
            let trimmed = s.trim_start();
            if let Some(rest) = trimmed.strip_prefix("#tags:") {
                return rest
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
            }
        }
    }
    Vec::new()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;
    use std::path::PathBuf;

    const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

    fn fixture_path(rel: &str) -> PathBuf {
        PathBuf::from(FIXTURE_DIR).join(rel)
    }

    // ── Test 3: host_summaries returns all hosts in order ─────────────────────

    #[test]
    fn host_summaries_covers_all_files() {
        let doc = load_doc(&fixture_path("inc/config")).expect("load_doc ok");
        let summaries = host_summaries(&doc);

        let aliases: Vec<&str> = summaries.iter().map(|s| s.alias.as_str()).collect();

        // All three hosts must appear.
        assert!(aliases.contains(&"main-a"), "main-a missing");
        assert!(aliases.contains(&"work-1"), "work-1 missing");
        assert!(aliases.contains(&"home-1"), "home-1 missing");

        // work-1's source_file ends with work.conf.
        let work = summaries.iter().find(|s| s.alias == "work-1").unwrap();
        assert!(
            work.source_file.ends_with("work.conf"),
            "work-1 source_file must end with work.conf, got {}",
            work.source_file
        );

        // Tags parsed correctly.
        assert_eq!(work.tags, vec!["prod", "db"], "work-1 tags");

        // Resolved HostName/User surfaced for the list subtitle.
        assert_eq!(work.hostname.as_deref(), Some("work-1.example.com"), "work-1 hostname");
        assert!(work.user.is_some(), "work-1 should expose a User");
    }

    // ── Test 4: host_detail options in order + group/tags ────────────────────

    #[test]
    fn host_detail_work1_options_and_sentinels() {
        let doc = load_doc(&fixture_path("inc/config")).expect("load_doc ok");
        let detail = host_detail(&doc, "work-1").expect("work-1 must be found");

        assert_eq!(detail.alias, "work-1");
        assert_eq!(detail.tags, vec!["prod", "db"]);

        // Options must contain the known directives in order.
        let keywords: Vec<&str> = detail.options.iter().map(|o| o.keyword.as_str()).collect();
        assert!(keywords.contains(&"HostName"), "HostName missing");
        assert!(keywords.contains(&"User"), "User missing");
        assert!(keywords.contains(&"Port"), "Port missing");
        assert!(keywords.contains(&"IdentityFile"), "IdentityFile missing");

        // Verify order (as laid out in the fixture).
        let hn_pos = keywords.iter().position(|&k| k == "HostName").unwrap();
        let user_pos = keywords.iter().position(|&k| k == "User").unwrap();
        let port_pos = keywords.iter().position(|&k| k == "Port").unwrap();
        assert!(hn_pos < user_pos, "HostName before User");
        assert!(user_pos < port_pos, "User before Port");

        // Verify values.
        let hn = detail.options.iter().find(|o| o.keyword == "HostName").unwrap();
        assert_eq!(hn.value, "work-1.example.com");

        let port = detail.options.iter().find(|o| o.keyword == "Port").unwrap();
        assert_eq!(port.value, "2222");

        // All directives enabled by default.
        for opt in &detail.options {
            assert!(opt.enabled, "all options should be enabled, got {:?}", opt.keyword);
        }
    }

    // ── Test 5: host_detail returns None for unknown alias ───────────────────

    #[test]
    fn host_detail_returns_none_for_unknown() {
        let doc = load_doc(&fixture_path("inc/config")).expect("load_doc ok");
        assert!(host_detail(&doc, "no-such-host").is_none());
    }

    // ── Test: ts-rs export (requires `cargo test` to run) ────────────────────
    // The actual assertion is that the .ts files are generated; this test simply
    // exercises the type exports by triggering them via the derive.
    #[test]
    fn ts_export_types_compile() {
        // This test verifies that the TS types can be derived without panicking.
        // The actual file generation happens as a side-effect of `cargo test`.
        let _opt = HostOption {
            keyword: "HostName".to_string(),
            value: "example.com".to_string(),
            enabled: true,
        };
        let _sum = HostSummary {
            alias: "test".to_string(),
            patterns: vec!["test".to_string()],
            source_file: "/tmp/config".to_string(),
            tags: vec![],
            hostname: Some("example.com".to_string()),
            user: None,
        };
        let _det = HostDetail {
            alias: "test".to_string(),
            patterns: vec!["test".to_string()],
            source_file: "/tmp/config".to_string(),
            tags: vec![],
            options: vec![],
        };
    }
}
