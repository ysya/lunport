//! Host discovery: suggest hosts found in ~/.ssh/known_hosts and the Tailscale network that are
//! NOT already present in the loaded ssh_config. Pure parsing/diffing functions are unit-tested;
//! the IO/exec entry point (`discover_all`) is a thin, untested wrapper.

use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::config::model::{Item, SshConfigDoc};

// ─── known_hosts ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct KnownHostEntry {
    pub host: String,
    pub port: Option<u16>,
}

/// Parse ~/.ssh/known_hosts text → plaintext host entries.
///
/// Line splitting/marker handling is shared with the known_hosts editor
/// (`crate::known_hosts::parse_lines`). On top of that, discovery skips hashed entries
/// (`|1|...`, unrecoverable) and expands `[host]:port` bracket form and comma-separated
/// host lists (each taken). Deduped.
pub fn parse_known_hosts(text: &str) -> Vec<KnownHostEntry> {
    let mut out: Vec<KnownHostEntry> = Vec::new();

    for raw in crate::known_hosts::parse_lines(text) {
        // Hashed entries are unrecoverable → skip.
        if raw.hosts.starts_with('|') {
            continue;
        }

        // The first field can be a comma-separated host list.
        for token in raw.hosts.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Some(entry) = parse_host_token(token) {
                if !out.contains(&entry) {
                    out.push(entry);
                }
            }
        }
    }

    out
}

/// Parse a single host token: plain `host`, `[host]:port`, or a bare `host:port` is left as host
/// only if it is the bracket form (OpenSSH only uses brackets when a non-default port is present).
fn parse_host_token(token: &str) -> Option<KnownHostEntry> {
    if let Some(rest) = token.strip_prefix('[') {
        // [host]:port
        if let Some((host, port_str)) = rest.split_once("]:") {
            let host = host.trim();
            if host.is_empty() {
                return None;
            }
            let port = port_str.trim().parse::<u16>().ok();
            return Some(KnownHostEntry {
                host: host.to_string(),
                port,
            });
        }
        // [host] with no port (unusual) — strip a trailing ']'.
        let host = rest.trim_end_matches(']').trim();
        if host.is_empty() {
            return None;
        }
        return Some(KnownHostEntry {
            host: host.to_string(),
            port: None,
        });
    }

    Some(KnownHostEntry {
        host: token.to_string(),
        port: None,
    })
}

// ─── Tailscale ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct TailscalePeer {
    pub host_name: String,
    pub dns_name: String,
    pub online: bool,
}

/// Parse `tailscale status --json` output. Top-level `Self` is skipped; `Peer` is a map of
/// nodekey→peer object. Each peer has `HostName`, `DNSName` (trailing-dot FQDN), `Online`.
/// Tolerant of missing fields.
pub fn parse_tailscale_status(json: &str) -> Vec<TailscalePeer> {
    let value: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let peers = match value.get("Peer").and_then(|p| p.as_object()) {
        Some(m) => m,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    for peer in peers.values() {
        let host_name = peer
            .get("HostName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dns_name = peer
            .get("DNSName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let online = peer
            .get("Online")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        out.push(TailscalePeer {
            host_name,
            dns_name,
            online,
        });
    }
    out
}

// ─── Suggestions ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct Suggestion {
    pub name: String,
    pub host_name: String,
    pub port: Option<u16>,
    /// "known_hosts" | "tailscale"
    pub source: String,
    pub online: Option<bool>,
}

/// Build suggestions NOT already in the doc. A host is "already known" if its HostName or any alias
/// matches an existing config entry (each HostBlock's patterns AND its enabled HostName values,
/// case-insensitive).
pub fn discover(
    doc: &SshConfigDoc,
    known_hosts: &[KnownHostEntry],
    tailscale: &[TailscalePeer],
) -> Vec<Suggestion> {
    let existing = existing_identifiers(doc);
    let is_known = |s: &str| existing.contains(&s.to_lowercase());

    let mut out: Vec<Suggestion> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // known_hosts entries.
    for kh in known_hosts {
        if kh.host.is_empty() || is_known(&kh.host) {
            continue;
        }
        let key = format!("known_hosts:{}", kh.host.to_lowercase());
        if !seen.insert(key) {
            continue;
        }
        out.push(Suggestion {
            name: kh.host.clone(),
            host_name: kh.host.clone(),
            port: kh.port,
            source: "known_hosts".to_string(),
            online: None,
        });
    }

    // Tailscale peers.
    for peer in tailscale {
        let dns_trimmed = peer.dns_name.trim_end_matches('.').to_string();
        let name = if !peer.host_name.is_empty() {
            peer.host_name.clone()
        } else {
            // First label of the DNSName.
            dns_trimmed
                .split('.')
                .next()
                .unwrap_or("")
                .to_string()
        };

        if name.is_empty() && dns_trimmed.is_empty() {
            continue;
        }

        // Already known if either the name or the DNS host matches an existing identifier.
        if is_known(&name) || (!dns_trimmed.is_empty() && is_known(&dns_trimmed)) {
            continue;
        }

        let key = format!("tailscale:{}", name.to_lowercase());
        if !seen.insert(key) {
            continue;
        }

        out.push(Suggestion {
            name,
            host_name: dns_trimmed,
            port: None,
            source: "tailscale".to_string(),
            online: Some(peer.online),
        });
    }

    out
}

/// All lowercase identifiers already present in the doc: every HostBlock pattern plus each block's
/// enabled HostName values.
fn existing_identifiers(doc: &SshConfigDoc) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for cf in &doc.files {
        for item in &cf.items {
            if let Item::Host(h) = item {
                for p in &h.patterns {
                    set.insert(p.to_lowercase());
                }
                for body_item in &h.body {
                    if let Item::Directive(d) = body_item {
                        if d.enabled && d.key == "hostname" {
                            let v = d.value.trim();
                            if !v.is_empty() {
                                set.insert(v.to_lowercase());
                            }
                        }
                    }
                }
            }
        }
    }
    set
}

// ─── IO/exec entry point (thin, not unit-tested) ────────────────────────────────

/// Read ~/.ssh/known_hosts (if present) and run `tailscale status --json` (if the binary exists),
/// then `discover`. Tailscale failures (missing binary / nonzero exit / parse error) are non-fatal.
pub fn discover_all(doc: &SshConfigDoc) -> Vec<Suggestion> {
    let known_hosts = read_known_hosts();
    let tailscale = read_tailscale_status();
    discover(doc, &known_hosts, &tailscale)
}

fn read_known_hosts() -> Vec<KnownHostEntry> {
    let path = match dirs::home_dir() {
        Some(h) => h.join(".ssh").join("known_hosts"),
        None => return Vec::new(),
    };
    if !Path::new(&path).exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_known_hosts(&text),
        Err(_) => Vec::new(),
    }
}

fn read_tailscale_status() -> Vec<TailscalePeer> {
    let output = Command::new("tailscale").args(["status", "--json"]).output();
    match output {
        Ok(out) if out.status.success() => {
            let json = String::from_utf8_lossy(&out.stdout);
            parse_tailscale_status(&json)
        }
        _ => Vec::new(),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;
    use std::path::PathBuf;

    fn doc_with(content: &str) -> SshConfigDoc {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, content).unwrap();
        let doc = load_doc(&path).unwrap();
        std::mem::forget(dir);
        doc
    }

    // ── parse_known_hosts ─────────────────────────────────────────────────────

    #[test]
    fn parse_known_hosts_plain_host() {
        let text = "github.com ssh-ed25519 AAAAC3Nz...\n";
        let entries = parse_known_hosts(text);
        assert_eq!(
            entries,
            vec![KnownHostEntry {
                host: "github.com".to_string(),
                port: None
            }]
        );
    }

    #[test]
    fn parse_known_hosts_bracket_port() {
        let text = "[example.com]:2222 ssh-rsa AAAAB3Nz...\n";
        let entries = parse_known_hosts(text);
        assert_eq!(
            entries,
            vec![KnownHostEntry {
                host: "example.com".to_string(),
                port: Some(2222)
            }]
        );
    }

    #[test]
    fn parse_known_hosts_comma_list() {
        let text = "host1.example.com,192.168.1.10 ssh-ed25519 AAAA...\n";
        let entries = parse_known_hosts(text);
        assert_eq!(
            entries,
            vec![
                KnownHostEntry {
                    host: "host1.example.com".to_string(),
                    port: None
                },
                KnownHostEntry {
                    host: "192.168.1.10".to_string(),
                    port: None
                },
            ]
        );
    }

    #[test]
    fn parse_known_hosts_skips_hashed() {
        let text = "|1|abcdefgh=|ijklmnop= ssh-ed25519 AAAA...\n";
        let entries = parse_known_hosts(text);
        assert!(entries.is_empty(), "hashed entries must be skipped: {entries:?}");
    }

    #[test]
    fn parse_known_hosts_skips_comments_and_blanks() {
        let text = "# a comment\n\n   \nreal.example.com ssh-rsa AAAA...\n";
        let entries = parse_known_hosts(text);
        assert_eq!(
            entries,
            vec![KnownHostEntry {
                host: "real.example.com".to_string(),
                port: None
            }]
        );
    }

    #[test]
    fn parse_known_hosts_skips_revoked_marker_keeps_host() {
        // The `@revoked` marker token is skipped; the host after it is still parsed.
        let text = "@revoked revoked.example.com ssh-rsa AAAA...\n";
        let entries = parse_known_hosts(text);
        assert_eq!(
            entries,
            vec![KnownHostEntry {
                host: "revoked.example.com".to_string(),
                port: None
            }]
        );
    }

    #[test]
    fn parse_known_hosts_dedupes() {
        let text = "dup.example.com k1 A\ndup.example.com k2 B\n";
        let entries = parse_known_hosts(text);
        assert_eq!(entries.len(), 1, "duplicate hosts must be deduped");
    }

    // ── parse_tailscale_status ────────────────────────────────────────────────

    const TS_FIXTURE: &str = r#"{
        "Self": {
            "HostName": "my-laptop",
            "DNSName": "my-laptop.tailnet.ts.net.",
            "Online": true
        },
        "Peer": {
            "nodekey:aaa": {
                "HostName": "server-a",
                "DNSName": "server-a.tailnet.ts.net.",
                "Online": true
            },
            "nodekey:bbb": {
                "HostName": "server-b",
                "DNSName": "server-b.tailnet.ts.net.",
                "Online": false
            }
        }
    }"#;

    #[test]
    fn parse_tailscale_status_two_peers_skips_self() {
        let peers = parse_tailscale_status(TS_FIXTURE);
        assert_eq!(peers.len(), 2, "Self must be skipped, 2 peers expected");

        let a = peers.iter().find(|p| p.host_name == "server-a").unwrap();
        assert_eq!(a.dns_name, "server-a.tailnet.ts.net.");
        assert!(a.online, "server-a should be online");

        let b = peers.iter().find(|p| p.host_name == "server-b").unwrap();
        assert!(!b.online, "server-b should be offline");
    }

    #[test]
    fn parse_tailscale_status_tolerates_missing_fields() {
        let json = r#"{"Peer":{"nodekey:x":{"HostName":"only-name"}}}"#;
        let peers = parse_tailscale_status(json);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].host_name, "only-name");
        assert_eq!(peers[0].dns_name, "");
        assert!(!peers[0].online);
    }

    #[test]
    fn parse_tailscale_status_invalid_json_is_empty() {
        assert!(parse_tailscale_status("not json").is_empty());
    }

    // ── discover ──────────────────────────────────────────────────────────────

    #[test]
    fn discover_filters_existing_by_alias_and_hostname_keeps_new() {
        // doc has Host `web` (alias) with HostName web.example.com, and Host `gh` with
        // HostName github.com.
        let doc = doc_with(
            "Host web\n    HostName web.example.com\nHost gh\n    HostName github.com\n",
        );

        let known_hosts = vec![
            // Matches by HostName of `gh` → filtered.
            KnownHostEntry { host: "github.com".into(), port: None },
            // New host → kept.
            KnownHostEntry { host: "new-box.example.com".into(), port: Some(2222) },
        ];
        let tailscale = vec![
            // Matches existing alias `web` → filtered.
            TailscalePeer {
                host_name: "web".into(),
                dns_name: "web.tailnet.ts.net.".into(),
                online: true,
            },
            // New peer → kept.
            TailscalePeer {
                host_name: "ts-server".into(),
                dns_name: "ts-server.tailnet.ts.net.".into(),
                online: false,
            },
        ];

        let suggestions = discover(&doc, &known_hosts, &tailscale);

        let names: Vec<&str> = suggestions.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"new-box.example.com"), "new known_host kept: {names:?}");
        assert!(names.contains(&"ts-server"), "new tailscale peer kept: {names:?}");
        assert!(!names.contains(&"github.com"), "existing-by-hostname filtered");
        assert!(!names.contains(&"web"), "existing-by-alias filtered");

        // Source + port + online tagging.
        let kh = suggestions.iter().find(|s| s.name == "new-box.example.com").unwrap();
        assert_eq!(kh.source, "known_hosts");
        assert_eq!(kh.port, Some(2222));
        assert_eq!(kh.online, None);

        let ts = suggestions.iter().find(|s| s.name == "ts-server").unwrap();
        assert_eq!(ts.source, "tailscale");
        assert_eq!(ts.host_name, "ts-server.tailnet.ts.net", "trailing dot trimmed");
        assert_eq!(ts.online, Some(false));
    }

    #[test]
    fn discover_matching_is_case_insensitive() {
        let doc = doc_with("Host Web\n    HostName Web.Example.COM\n");
        let known_hosts = vec![KnownHostEntry {
            host: "web.example.com".into(),
            port: None,
        }];
        let suggestions = discover(&doc, &known_hosts, &[]);
        assert!(suggestions.is_empty(), "case-insensitive HostName match must filter");
    }

    #[test]
    fn discover_tailscale_uses_dns_first_label_when_no_hostname() {
        let doc = doc_with("Host other\n    HostName other.example.com\n");
        let tailscale = vec![TailscalePeer {
            host_name: String::new(),
            dns_name: "label-only.tailnet.ts.net.".into(),
            online: true,
        }];
        let suggestions = discover(&doc, &[], &tailscale);
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].name, "label-only");
        assert_eq!(suggestions[0].host_name, "label-only.tailnet.ts.net");
    }

    // ── ts-rs export ──────────────────────────────────────────────────────────

    #[test]
    fn ts_export_suggestion_compiles() {
        let _s = Suggestion {
            name: "x".into(),
            host_name: "x.example.com".into(),
            port: Some(22),
            source: "known_hosts".into(),
            online: Some(true),
        };
        // Touch fixture path helper to avoid unused import warnings in some configs.
        let _ = PathBuf::from("/tmp");
    }
}
