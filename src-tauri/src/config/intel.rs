//! Config intelligence: effective config (`ssh -G`), linting, ProxyJump chain, key hygiene.
//!
//! Security model: `effective_config` spawns `ssh -G` as an argv vector (never `sh -c`). The
//! `alias` MUST be pre-validated by the caller with `crate::connect::validate_alias` (the Tauri
//! command does this) to prevent argument injection. `ssh -G` does NOT connect — it only resolves
//! the effective configuration locally.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::model::{HostBlock, Item, SshConfigDoc};
use crate::error::AppError;

// ─── (a) Effective config via `ssh -G` ────────────────────────────────────────

/// Run `ssh -G [-F config_path] <alias>` and parse the resolved "keyword value" lines.
/// `alias` MUST be pre-validated by the caller. `config_path` lets tests point at a temp config
/// (and the live command passes the loaded main file's path so resolution matches what the user
/// sees). `ssh -G` does NOT connect — pure resolution.
pub fn effective_config(
    alias: &str,
    config_path: Option<&Path>,
) -> Result<Vec<(String, String)>, AppError> {
    let mut cmd = std::process::Command::new("ssh");
    if let Some(path) = config_path {
        cmd.arg("-F").arg(path);
    }
    cmd.arg("-G").arg(alias);

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AppError::NotFound("ssh not found".to_string()));
        }
        Err(e) => return Err(AppError::Io(e)),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first_line = stderr.lines().next().unwrap_or("ssh -G failed").trim();
        return Err(AppError::Other(first_line.to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        // Split on first whitespace → (keyword.to_lowercase(), rest). Keep repeated keys.
        let (keyword, rest) = match line.split_once(char::is_whitespace) {
            Some((k, r)) => (k, r.trim_start()),
            None => (line, ""),
        };
        result.push((keyword.to_lowercase(), rest.to_string()));
    }
    Ok(result)
}

// ─── (b) Lint ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct LintIssue {
    pub severity: String, // "error" | "warning" | "info"
    pub file: String,
    pub alias: Option<String>,
    pub keyword: Option<String>,
    pub message: String,
}

/// Keys allowed to legitimately appear multiple times within a single Host block.
const MULTI_VALUE_KEYS: &[&str] = &[
    "identityfile",
    "localforward",
    "remoteforward",
    "dynamicforward",
    "certificatefile",
    "sendenv",
    "setenv",
];

/// True when a ProxyJump hop string looks like a concrete/literal host (contains '.' or ':')
/// rather than an alias.
fn looks_like_literal_host(hop: &str) -> bool {
    hop.contains('.') || hop.contains(':')
}

/// Strip an optional `user@` prefix and `:port` suffix from a ProxyJump hop, returning the host.
fn hop_host(hop: &str) -> &str {
    let hop = hop.trim();
    let after_user = match hop.rsplit_once('@') {
        Some((_, h)) => h,
        None => hop,
    };
    match after_user.rsplit_once(':') {
        Some((h, _)) => h,
        None => after_user,
    }
}

/// True if `host` exactly matches ANY pattern of any HostBlock in the doc (incl. secondary aliases).
fn doc_defines_alias(doc: &SshConfigDoc, host: &str) -> bool {
    doc.files.iter().any(|f| {
        f.items.iter().any(|item| {
            matches!(item, Item::Host(h) if h.patterns.iter().any(|p| p == host))
        })
    })
}

pub fn lint(doc: &SshConfigDoc) -> Vec<LintIssue> {
    let mut issues = Vec::new();

    // Rule 2 setup: track first-seen alias to flag later (shadowed) definitions.
    let mut seen_aliases: std::collections::HashSet<String> = std::collections::HashSet::new();

    for f in &doc.files {
        let file = f.path.to_string_lossy().into_owned();
        for item in &f.items {
            let Item::Host(host) = item else { continue };
            let alias = host.patterns.first().cloned();

            // ── Rule 2: duplicate Host alias across blocks/files ──
            if let Some(a) = &alias {
                if !seen_aliases.insert(a.clone()) {
                    issues.push(LintIssue {
                        severity: "warning".to_string(),
                        file: file.clone(),
                        alias: alias.clone(),
                        keyword: None,
                        message: format!(
                            "host `{a}` is also defined earlier; later definitions are shadowed"
                        ),
                    });
                }
            }

            // ── Per-directive rules within this block's body ──
            let mut seen_keys: HashMap<String, usize> = HashMap::new();
            for body_item in &host.body {
                let Item::Directive(d) = body_item else {
                    continue;
                };
                // Disabled (commented-out) directives don't take effect — skip for ALL rules,
                // so commenting out a duplicate never flags the remaining active line.
                if !d.enabled {
                    continue;
                }

                // ── Rule 1: duplicate directive within a block ──
                let count = seen_keys.entry(d.key.clone()).or_insert(0);
                *count += 1;
                if *count == 2 && !MULTI_VALUE_KEYS.contains(&d.key.as_str()) {
                    issues.push(LintIssue {
                        severity: "warning".to_string(),
                        file: file.clone(),
                        alias: alias.clone(),
                        keyword: Some(d.keyword.clone()),
                        message: format!(
                            "duplicate `{}` — only the first takes effect (first-match-wins)",
                            d.keyword
                        ),
                    });
                }

                // ── Rule 3: missing IdentityFile path ──
                if d.key == "identityfile" {
                    // Skip values with %tokens (e.g. %d/%h) — can't resolve statically.
                    if !d.value.contains('%') {
                        if let Ok(expanded) = shellexpand::full(&d.value) {
                            if !Path::new(expanded.as_ref()).exists() {
                                issues.push(LintIssue {
                                    severity: "error".to_string(),
                                    file: file.clone(),
                                    alias: alias.clone(),
                                    keyword: Some(d.keyword.clone()),
                                    message: format!("IdentityFile not found: {}", d.value),
                                });
                            }
                        }
                    }
                }

                // ── Rule 4: insecure StrictHostKeyChecking ──
                if d.key == "stricthostkeychecking" && d.value.trim().eq_ignore_ascii_case("no") {
                    issues.push(LintIssue {
                        severity: "warning".to_string(),
                        file: file.clone(),
                        alias: alias.clone(),
                        keyword: Some(d.keyword.clone()),
                        message: "StrictHostKeyChecking no disables host-key verification"
                            .to_string(),
                    });
                }

                // ── Rule 5: ProxyJump references undefined host ──
                if d.key == "proxyjump" {
                    for hop in d.value.split(',') {
                        let host_part = hop_host(hop);
                        // `none` is a reserved ProxyJump value (disables proxying), not a host.
                        if host_part.is_empty() || host_part.eq_ignore_ascii_case("none") {
                            continue;
                        }
                        // Only flag alias-looking hops (no '.'/':') that aren't defined in the doc.
                        if !looks_like_literal_host(host_part)
                            && !doc_defines_alias(doc, host_part)
                        {
                            issues.push(LintIssue {
                                severity: "warning".to_string(),
                                file: file.clone(),
                                alias: alias.clone(),
                                keyword: Some(d.keyword.clone()),
                                message: format!(
                                    "ProxyJump references undefined host `{host_part}`"
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    issues
}

// ─── (c) ProxyJump chain ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ChainNode {
    pub name: String,
    pub defined: bool,
}

/// Find a HostBlock matching `alias` against ANY of its patterns (incl. secondary aliases).
fn find_host_block<'a>(doc: &'a SshConfigDoc, alias: &str) -> Option<&'a HostBlock> {
    for f in &doc.files {
        for item in &f.items {
            if let Item::Host(h) = item {
                if h.patterns.iter().any(|p| p == alias) {
                    return Some(h);
                }
            }
        }
    }
    None
}

/// First enabled `proxyjump` value for a HostBlock, if any.
fn host_proxyjump(host: &HostBlock) -> Option<String> {
    host.body.iter().find_map(|item| {
        if let Item::Directive(d) = item {
            if d.enabled && d.key == "proxyjump" {
                return Some(d.value.clone());
            }
        }
        None
    })
}

/// Whether a chain node `name` should be considered defined: it matches a HostBlock in the doc OR
/// it looks like a literal host (concrete '.'/':' form).
fn node_defined(doc: &SshConfigDoc, name: &str) -> bool {
    doc_defines_alias(doc, name) || looks_like_literal_host(name)
}

/// Resolve the ProxyJump chain for `alias`: [alias, hop1, hop2, ...]. Follows each hop's own
/// ProxyJump (from the doc), expands comma-separated chains left-to-right, depth cap 5, cycle
/// guard. The first node is the alias itself; `defined` reflects the doc (or literal-host shape).
pub fn jump_chain(doc: &SshConfigDoc, alias: &str) -> Vec<ChainNode> {
    const DEPTH_CAP: usize = 5;
    let mut chain = Vec::new();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Work list of names to visit in order; comma-separated hops are pushed onto the front.
    let mut pending = vec![alias.to_string()];

    while let Some(name) = (!pending.is_empty()).then(|| pending.remove(0)) {
        if chain.len() > DEPTH_CAP {
            break;
        }
        if !visited.insert(name.clone()) {
            continue; // cycle guard — skip already-visited node
        }
        chain.push(ChainNode {
            name: name.clone(),
            defined: node_defined(doc, &name),
        });

        // Follow this node's own ProxyJump from the doc, expanding its comma list before the rest.
        if let Some(pj) = find_host_block(doc, &name).and_then(host_proxyjump) {
            let hops: Vec<String> = pj
                .split(',')
                .map(|h| hop_host(h).to_string())
                .filter(|h| !h.is_empty())
                .collect();
            // Prepend the hops so they're followed depth-first from this node.
            for (i, h) in hops.into_iter().enumerate() {
                pending.insert(i, h);
            }
        }
    }

    chain
}

// ─── (d) Key hygiene ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct IdentityFileInfo {
    pub path: String,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct KeyHygiene {
    pub identity_files: Vec<IdentityFileInfo>,
    pub identities_only: bool,
    pub explicit: bool,
}

/// Analyze key hygiene for `alias`, reading from its own HostBlock directives (doc-based).
pub fn key_hygiene(doc: &SshConfigDoc, alias: &str) -> KeyHygiene {
    let mut identity_files = Vec::new();
    let mut identities_only = false;

    if let Some(host) = find_host_block(doc, alias) {
        for item in &host.body {
            let Item::Directive(d) = item else { continue };
            if !d.enabled {
                continue;
            }
            if d.key == "identityfile" {
                // %tokens can't be resolved statically → treat as exists=true to avoid false alarms.
                let (path, exists) = if d.value.contains('%') {
                    (d.value.clone(), true)
                } else {
                    let expanded = shellexpand::full(&d.value)
                        .map(|c| c.into_owned())
                        .unwrap_or_else(|_| d.value.clone());
                    let exists = Path::new(&expanded).exists();
                    (d.value.clone(), exists)
                };
                identity_files.push(IdentityFileInfo { path, exists });
            } else if d.key == "identitiesonly" && d.value.trim().eq_ignore_ascii_case("yes") {
                identities_only = true;
            }
        }
    }

    KeyHygiene {
        explicit: !identity_files.is_empty(),
        identities_only,
        identity_files,
    }
}

// ─── Tauri commands ──────────────────────────────────────────────────────────────

#[tauri::command]
pub fn config_effective(
    state: tauri::State<crate::state::AppState>,
    alias: String,
) -> Result<Vec<(String, String)>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    let doc = doc_lock
        .as_ref()
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    crate::connect::validate_alias(doc, &alias)?;
    let main_path = doc.files.first().map(|f| f.path.clone());
    effective_config(&alias, main_path.as_deref())
}

#[tauri::command]
pub fn config_lint(state: tauri::State<crate::state::AppState>) -> Result<Vec<LintIssue>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    match doc_lock.as_ref() {
        None => Ok(Vec::new()),
        Some(doc) => Ok(lint(doc)),
    }
}

#[tauri::command]
pub fn config_jump_chain(
    state: tauri::State<crate::state::AppState>,
    alias: String,
) -> Result<Vec<ChainNode>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    let doc = doc_lock
        .as_ref()
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    crate::connect::validate_alias(doc, &alias)?;
    Ok(jump_chain(doc, &alias))
}

#[tauri::command]
pub fn config_key_hygiene(
    state: tauri::State<crate::state::AppState>,
    alias: String,
) -> Result<KeyHygiene, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    let doc = doc_lock
        .as_ref()
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    crate::connect::validate_alias(doc, &alias)?;
    Ok(key_hygiene(doc, &alias))
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;

    fn doc_with(content: &str) -> (SshConfigDoc, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, content).unwrap();
        let doc = load_doc(&path).unwrap();
        (doc, dir)
    }

    // ── (a) effective_config ──────────────────────────────────────────────────
    #[test]
    fn effective_config_resolves_keywords() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, "Host probe\n HostName 127.0.0.1\n User x\n Port 2200\n").unwrap();

        let result = match effective_config("probe", Some(&path)) {
            Ok(r) => r,
            Err(AppError::NotFound(m)) if m == "ssh not found" => {
                eprintln!("ssh not found — skipping effective_config assertions");
                return;
            }
            Err(e) => panic!("effective_config failed: {e:?}"),
        };

        assert!(
            result.iter().any(|(k, v)| k == "hostname" && v == "127.0.0.1"),
            "expected hostname 127.0.0.1, got {result:?}"
        );
        assert!(
            result.iter().any(|(k, v)| k == "user" && v == "x"),
            "expected user x, got {result:?}"
        );
        assert!(
            result.iter().any(|(k, v)| k == "port" && v == "2200"),
            "expected port 2200, got {result:?}"
        );
    }

    // ── (b) lint: each rule fires ─────────────────────────────────────────────
    #[test]
    fn lint_flags_each_rule() {
        // Create a real identity file path that exists, and one that does not.
        let keydir = tempfile::tempdir().unwrap();
        let missing = keydir.path().join("nope_key");

        let content = format!(
            "Host dup\n User a\n User b\n\
             Host shadowme\n HostName 1.1.1.1\n\
             Host shadowme\n HostName 2.2.2.2\n\
             Host badkey\n IdentityFile {}\n\
             Host insecure\n StrictHostKeyChecking no\n\
             Host jumper\n ProxyJump undefined-bastion\n",
            missing.display()
        );
        let (doc, _dir) = doc_with(&content);
        let issues = lint(&doc);

        // Rule 1: duplicate directive (User twice in `dup`).
        assert!(
            issues.iter().any(|i| i.alias.as_deref() == Some("dup")
                && i.keyword.as_deref() == Some("User")
                && i.message.contains("first-match-wins")),
            "missing dup-directive issue: {issues:?}"
        );

        // Rule 2: duplicate Host alias — flagged on the LATER one.
        assert!(
            issues.iter().any(|i| i.alias.as_deref() == Some("shadowme")
                && i.message.contains("shadowed")),
            "missing shadowed-host issue: {issues:?}"
        );

        // Rule 3: missing IdentityFile (error).
        assert!(
            issues.iter().any(|i| i.alias.as_deref() == Some("badkey")
                && i.severity == "error"
                && i.message.contains("IdentityFile not found")),
            "missing IdentityFile-not-found issue: {issues:?}"
        );

        // Rule 4: insecure StrictHostKeyChecking.
        assert!(
            issues.iter().any(|i| i.alias.as_deref() == Some("insecure")
                && i.message.contains("disables host-key verification")),
            "missing StrictHostKeyChecking issue: {issues:?}"
        );

        // Rule 5: ProxyJump references undefined host.
        assert!(
            issues.iter().any(|i| i.alias.as_deref() == Some("jumper")
                && i.message.contains("undefined-bastion")),
            "missing ProxyJump-undefined issue: {issues:?}"
        );
    }

    #[test]
    fn lint_clean_config_has_no_issues() {
        // A real key file that exists.
        let keydir = tempfile::tempdir().unwrap();
        let keyfile = keydir.path().join("id_ok");
        std::fs::write(&keyfile, "x").unwrap();

        let content = format!(
            "Host bastion\n HostName 10.0.0.1\n\
             Host web\n HostName 10.0.0.2\n IdentityFile {}\n ProxyJump bastion\n StrictHostKeyChecking yes\n",
            keyfile.display()
        );
        let (doc, _dir) = doc_with(&content);
        let issues = lint(&doc);
        assert!(issues.is_empty(), "clean config should have no issues, got {issues:?}");
    }

    #[test]
    fn lint_multi_value_identityfile_not_flagged_as_dup() {
        let keydir = tempfile::tempdir().unwrap();
        let k1 = keydir.path().join("k1");
        let k2 = keydir.path().join("k2");
        std::fs::write(&k1, "x").unwrap();
        std::fs::write(&k2, "x").unwrap();

        let content = format!(
            "Host multi\n IdentityFile {}\n IdentityFile {}\n",
            k1.display(),
            k2.display()
        );
        let (doc, _dir) = doc_with(&content);
        let issues = lint(&doc);
        assert!(
            !issues.iter().any(|i| i.message.contains("first-match-wins")),
            "two IdentityFile lines must NOT trigger dup-directive: {issues:?}"
        );
    }

    // ── (c) jump_chain ────────────────────────────────────────────────────────
    #[test]
    fn jump_chain_follows_defined_hops() {
        let (doc, _dir) = doc_with(
            "Host a\n ProxyJump b\nHost b\n ProxyJump c\nHost c\n HostName 1.2.3.4\n",
        );
        let chain = jump_chain(&doc, "a");
        let names: Vec<&str> = chain.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"], "chain {chain:?}");
        assert!(chain.iter().all(|n| n.defined), "all defined: {chain:?}");
    }

    #[test]
    fn jump_chain_marks_undefined_hop() {
        let (doc, _dir) = doc_with("Host a\n ProxyJump ghost\n");
        let chain = jump_chain(&doc, "a");
        let names: Vec<&str> = chain.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["a", "ghost"]);
        let ghost = chain.iter().find(|n| n.name == "ghost").unwrap();
        assert!(!ghost.defined, "alias-looking unknown hop is not defined");
    }

    #[test]
    fn jump_chain_terminates_on_self_cycle() {
        let (doc, _dir) = doc_with("Host x\n ProxyJump x\n");
        let chain = jump_chain(&doc, "x");
        // Must terminate (cycle guard): x appears exactly once.
        assert_eq!(chain.len(), 1, "self-cycle must terminate: {chain:?}");
        assert_eq!(chain[0].name, "x");
    }

    #[test]
    fn jump_chain_terminates_on_cross_host_cycle() {
        let (doc, _dir) = doc_with("Host a\n ProxyJump b\nHost b\n ProxyJump a\n");
        let chain = jump_chain(&doc, "a");
        // a→b→(a already visited) — must terminate without looping.
        let names: Vec<&str> = chain.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"], "cross-host cycle must terminate: {chain:?}");
    }

    #[test]
    fn lint_secondary_alias_proxyjump_not_flagged() {
        // `jump-host` is a SECONDARY pattern of the bastion block — must not be "undefined".
        let (doc, _dir) =
            doc_with("Host bastion jump-host\n HostName 10.0.0.1\nHost web\n ProxyJump jump-host\n");
        let undefined: Vec<_> = lint(&doc)
            .into_iter()
            .filter(|i| i.message.contains("ProxyJump references undefined host"))
            .collect();
        assert!(undefined.is_empty(), "secondary alias must not be flagged: {undefined:?}");
    }

    #[test]
    fn lint_proxyjump_none_not_flagged() {
        let (doc, _dir) = doc_with("Host direct\n ProxyJump none\n");
        let undefined: Vec<_> = lint(&doc)
            .into_iter()
            .filter(|i| i.message.contains("ProxyJump references undefined host"))
            .collect();
        assert!(undefined.is_empty(), "`none` is reserved, not a host: {undefined:?}");
    }

    // ── (d) key_hygiene ───────────────────────────────────────────────────────
    #[test]
    fn key_hygiene_explicit_with_identities_only() {
        let keydir = tempfile::tempdir().unwrap();
        let keyfile = keydir.path().join("id_real");
        std::fs::write(&keyfile, "x").unwrap();

        let content = format!(
            "Host k\n IdentityFile {}\n IdentitiesOnly yes\n",
            keyfile.display()
        );
        let (doc, _dir) = doc_with(&content);
        let hy = key_hygiene(&doc, "k");
        assert!(hy.explicit, "explicit when IdentityFile is set");
        assert!(hy.identities_only, "identities_only yes");
        assert_eq!(hy.identity_files.len(), 1);
        assert!(hy.identity_files[0].exists, "real temp file should exist");
    }

    #[test]
    fn key_hygiene_no_identity_file_not_explicit() {
        let (doc, _dir) = doc_with("Host plain\n HostName 1.2.3.4\n");
        let hy = key_hygiene(&doc, "plain");
        assert!(!hy.explicit, "no IdentityFile → not explicit");
        assert!(!hy.identities_only);
        assert!(hy.identity_files.is_empty());
    }

    // ── ts-rs export smoke ────────────────────────────────────────────────────
    #[test]
    fn ts_export_types_compile() {
        let _ = LintIssue {
            severity: "warning".into(),
            file: "/tmp/config".into(),
            alias: Some("web".into()),
            keyword: Some("User".into()),
            message: "x".into(),
        };
        let _ = ChainNode { name: "a".into(), defined: true };
        let _ = IdentityFileInfo { path: "~/.ssh/id".into(), exists: true };
        let _ = KeyHygiene {
            identity_files: vec![],
            identities_only: false,
            explicit: false,
        };
    }
}
