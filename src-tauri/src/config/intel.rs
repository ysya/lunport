//! Config intelligence: effective config (`ssh -G`), linting, ProxyJump chain, key hygiene.
//!
//! Security model: `effective_config` spawns `ssh -G` as an argv vector (never `sh -c`). The
//! `alias` MUST be pre-validated by the caller with `crate::connect::validate_alias` (the Tauri
//! command does this) to prevent argument injection. `ssh -G` does NOT connect — it only resolves
//! the effective configuration locally.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Mutex;

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
    let mut cmd = crate::process::background_command("ssh");
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
    /// Stable kebab-case rule id (e.g. "duplicate-directive") so the frontend can toggle rules.
    pub rule: String,
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

/// `IdentityFile` 展開後的 `path` 算不算「在」:檔案存在,或它是「只在 SSHelter」的插槽(金鑰保管庫 spec §6)—— 插槽路徑上沒有私鑰、只有 `.pub`,
/// 金鑰由 SSHelter 的 agent 提供。`value` 是 `IdentityFile` 原本的值(只有 `~/.ssh/sshelter/keys/<檔名>` 這種寫法才是插槽路徑);一般的 `IdentityFile`
/// 旁邊有 `.pub` 不算。
fn identity_file_present(value: &str, path: &Path) -> bool {
    path.exists() || (crate::sync::slot_rules::slot_file_of_value(value).is_some() && crate::sync::slot_rules::public_path(path).is_file())
}

/// `account_slot_files` = 這台的同步帳戶裡還在的插槽檔名(不在帳戶裡是空的,`sync::slots::account_slot_files`):缺檔的插槽路徑依帳戶裡有沒有這個插槽
/// 說明(SP3 spec §7.3)。
pub fn lint(doc: &SshConfigDoc, account_slot_files: &BTreeSet<String>) -> Vec<LintIssue> {
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
                        rule: "shadowed-host".to_string(),
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
                        rule: "duplicate-directive".to_string(),
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
                    // Skip values with %tokens (e.g. %d/%h) — can't resolve statically. A quoted path is the file inside the quotes
                    // (a key file whose name has a space is written that way).
                    if !d.value.contains('%') {
                        if let Some(expanded) = crate::config::include::expand_token(crate::sync::slot_rules::unquote(&d.value)) {
                            if !identity_file_present(&d.value, Path::new(&expanded)) {
                                issues.push(LintIssue {
                                    rule: "missing-identity-file".to_string(),
                                    severity: "error".to_string(),
                                    file: file.clone(),
                                    alias: alias.clone(),
                                    keyword: Some(d.keyword.clone()),
                                    // 插槽路徑(同步主機的金鑰位置):缺檔時不是讓使用者去找檔案。同步帳戶裡有這個插槽(檔名不分大小寫)→ 到 Keychain 為它挑一把
                                    // 金鑰(同主機清單的標記);沒有(或不在帳戶裡,例如之前的帳戶留下的插槽,SP3 spec §7.1)→ 這台無從為它挑金鑰,要到有這把金鑰的電腦上設定。
                                    message: match crate::sync::slot_rules::slot_file_of_value(&d.value) {
                                        Some(file) if account_slot_files.iter().any(|f| f.eq_ignore_ascii_case(&file)) => {
                                            format!("IdentityFile not found: {} (a synced key slot \u{2014} pick a key for it in Keychain)", d.value)
                                        }
                                        Some(_) => format!(
                                            "IdentityFile not found: {} (a key slot your sync account doesn't have \u{2014} set the key up on the computer that has it)",
                                            d.value
                                        ),
                                        None => format!("IdentityFile not found: {}", d.value),
                                    },
                                });
                            }
                        }
                    }
                }

                // ── Rule 4: insecure StrictHostKeyChecking ──
                if d.key == "stricthostkeychecking" && d.value.trim().eq_ignore_ascii_case("no") {
                    issues.push(LintIssue {
                        rule: "insecure-strict-host-key-checking".to_string(),
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
                                rule: "undefined-proxy-jump".to_string(),
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
                    // A quoted path is the file inside the quotes (as the linter reads it).
                    let unquoted = crate::sync::slot_rules::unquote(&d.value);
                    let expanded = crate::config::include::expand_token(unquoted).unwrap_or_else(|| unquoted.to_string());
                    let exists = identity_file_present(&d.value, Path::new(&expanded));
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
    Ok(lint_current(&state.sync, &state.doc))
}

/// `config_lint` 的本體:帳戶裡的插槽檔名取自同步狀態(`sync::slots::account_slot_files` 只短暫拿 core 鎖),放掉之後才拿 doc 鎖。
pub(crate) fn lint_current(sync: &crate::sync::runtime::SyncRuntime, doc: &Mutex<Option<SshConfigDoc>>) -> Vec<LintIssue> {
    let account_slot_files = crate::sync::slots::account_slot_files(sync);
    let doc_lock = doc.lock().unwrap();
    doc_lock.as_ref().map(|doc| lint(doc, &account_slot_files)).unwrap_or_default()
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
        let issues = lint(&doc, &BTreeSet::new());

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
        let issues = lint(&doc, &BTreeSet::new());
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
        let issues = lint(&doc, &BTreeSet::new());
        assert!(
            !issues.iter().any(|i| i.message.contains("first-match-wins")),
            "two IdentityFile lines must NOT trigger dup-directive: {issues:?}"
        );
    }

    /// 缺檔的插槽路徑:同步帳戶裡有這個插槽(檔名不分大小寫)→ 到 Keychain 為它挑一把金鑰;沒有(或不在任何帳戶裡)→ 到有這把金鑰的電腦上設定。
    #[test]
    fn a_missing_key_slot_says_whether_the_sync_account_has_it() {
        let (doc, _dir) = doc_with("Host web\n IdentityFile ~/.ssh/sshelter/keys/sp3-lint-missing-00000000\n");
        let message = |files: &[&str]| {
            let files: BTreeSet<String> = files.iter().map(|f| f.to_string()).collect();
            lint(&doc, &files).into_iter().find(|i| i.rule == "missing-identity-file").expect("flagged").message
        };
        let in_account = "IdentityFile not found: ~/.ssh/sshelter/keys/sp3-lint-missing-00000000 (a synced key slot \u{2014} pick a key for it in Keychain)";
        let not_in_account = "IdentityFile not found: ~/.ssh/sshelter/keys/sp3-lint-missing-00000000 (a key slot your sync account doesn't have \u{2014} set the key up on the computer that has it)";
        assert_eq!(message(&["sp3-lint-missing-00000000"]), in_account);
        assert_eq!(message(&["SP3-LINT-MISSING-00000000", "x-22222222"]), in_account, "whatever the case of the file name");
        assert_eq!(message(&["sp3-lint-other-11111111"]), not_in_account);
        assert_eq!(message(&[]), not_in_account, "not in an account");
    }

    /// 這份設定(兩個插槽路徑)的家目錄是 `dir`:`v` 只有 `.pub`(只在 SSHelter 的插槽,金鑰保管庫 spec §6),`m` 什麼都沒有。
    fn vault_slot_doc() -> (SshConfigDoc, tempfile::TempDir) {
        let (doc, dir) = doc_with(
            "Host v\n  IdentityFile ~/.ssh/sshelter/keys/vaulted-11111111\nHost m\n  IdentityFile ~/.ssh/sshelter/keys/missing-22222222\n",
        );
        let keys = dir.path().join(".ssh/sshelter/keys");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("vaulted-11111111.pub"), "ssh-ed25519 AAAA test\n").unwrap();
        (doc, dir)
    }

    /// 只在 SSHelter 的插槽:插槽路徑上沒有私鑰、只有 `.pub`,金鑰由 SSHelter 的 agent 提供 —— 不算找不到;`.pub` 也沒有的插槽路徑照舊要報。
    #[test]
    fn a_vault_slot_with_only_its_pub_is_not_a_missing_identity_file() {
        let (doc, dir) = vault_slot_doc();
        let issues = crate::config::include::with_test_home(dir.path(), || lint(&doc, &BTreeSet::new()));
        assert!(
            issues.iter().all(|i| !(i.rule == "missing-identity-file" && i.alias.as_deref() == Some("v"))),
            "{issues:?}"
        );
        assert!(issues.iter().any(|i| i.rule == "missing-identity-file" && i.alias.as_deref() == Some("m")), "{issues:?}");
    }

    /// 只有 `.pub` 的路徑只對插槽路徑成立:一般的 `IdentityFile` 旁邊有 `.pub`、私鑰卻不在,仍是找不到。
    #[test]
    fn a_pub_file_beside_an_ordinary_missing_key_does_not_hide_it() {
        let keydir = tempfile::tempdir().unwrap();
        let key = keydir.path().join("id_gone");
        std::fs::write(keydir.path().join("id_gone.pub"), "ssh-ed25519 AAAA test\n").unwrap();
        let (doc, _dir) = doc_with(&format!("Host g\n  IdentityFile {}\n", key.display()));
        let issues = lint(&doc, &BTreeSet::new());
        assert!(issues.iter().any(|i| i.rule == "missing-identity-file" && i.alias.as_deref() == Some("g")), "{issues:?}");
        let hygiene = key_hygiene(&doc, "g");
        assert!(!hygiene.identity_files[0].exists);
    }

    /// 雙引號裡的金鑰路徑就是引號裡的那個檔案(檔名有空白的金鑰,SSHelter 寫成這樣:`edit::replace_identity_files`):lint 與主機頁(`key_hygiene`)都不把存在的
    /// 檔案當成找不到 —— `~/` 開頭的也一樣。
    #[test]
    fn a_quoted_identity_file_is_the_file_inside_the_quotes() {
        let (doc, dir) = doc_with("Host tilde\n  IdentityFile \"~/.ssh/id_ed25519 copy\"\nHost gone\n  IdentityFile \"~/.ssh/id_gone copy\"\n");
        std::fs::create_dir_all(dir.path().join(".ssh")).unwrap();
        std::fs::write(dir.path().join(".ssh/id_ed25519 copy"), "x").unwrap();
        let keydir = tempfile::tempdir().unwrap();
        let absolute = keydir.path().join("id work");
        std::fs::write(&absolute, "x").unwrap();
        let (abs_doc, _abs_dir) = doc_with(&format!("Host absolute\n  IdentityFile \"{}\"\n", absolute.display()));

        let missing = |doc: &SshConfigDoc| -> Vec<Option<String>> {
            let issues = crate::config::include::with_test_home(dir.path(), || lint(doc, &BTreeSet::new()));
            issues.into_iter().filter(|i| i.rule == "missing-identity-file").map(|i| i.alias).collect()
        };
        assert_eq!(missing(&doc), vec![Some("gone".to_string())], "only the quoted path that really is missing");
        assert!(missing(&abs_doc).is_empty());
        let exists = |doc: &SshConfigDoc, alias: &str| {
            crate::config::include::with_test_home(dir.path(), || key_hygiene(doc, alias)).identity_files.remove(0).exists
        };
        assert!(exists(&doc, "tilde") && exists(&abs_doc, "absolute"));
        assert!(!exists(&doc, "gone"));
    }

    /// 同一條規則給 Keys 的主機頁(`key_hygiene`):只有 `.pub` 的插槽路徑算存在。
    #[test]
    fn key_hygiene_counts_a_vault_slot_with_only_its_pub_as_existing() {
        let (doc, dir) = vault_slot_doc();
        let exists = |alias: &str| {
            crate::config::include::with_test_home(dir.path(), || key_hygiene(&doc, alias)).identity_files.remove(0).exists
        };
        assert!(exists("v"));
        assert!(!exists("m"));
    }

    /// `config_lint` 的接線(`lint_current`):帳戶裡還在的插槽,檔名取自同步狀態。
    #[test]
    fn config_lint_reads_the_slots_of_this_computers_sync_account() {
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::slot_rules::{KeySlotPayload, SlotMode, SLOT_SCHEMA};
        use crate::sync::testkit::{TestClock, TestDevice};
        let main = "Host web\n IdentityFile ~/.ssh/sshelter/keys/sp3-lint-live-00000000\nHost db\n IdentityFile ~/.ssh/sshelter/keys/sp3-lint-gone-11111111\n";
        let d = TestDevice::with_main_config("a", &FakeRelay::new(), &TestClock::new(), main);
        let messages = || -> Vec<(Option<String>, String)> {
            lint_current(&d.runtime, &d.doc)
                .into_iter()
                .filter(|i| i.rule == "missing-identity-file")
                .map(|i| (i.alias, i.message))
                .collect()
        };
        let synced = |file: &str| format!("IdentityFile not found: ~/.ssh/sshelter/keys/{file} (a synced key slot \u{2014} pick a key for it in Keychain)");
        let elsewhere = |file: &str| {
            format!("IdentityFile not found: ~/.ssh/sshelter/keys/{file} (a key slot your sync account doesn't have \u{2014} set the key up on the computer that has it)")
        };
        let web = || Some("web".to_string());
        let db = || Some("db".to_string());
        assert_eq!(
            messages(),
            vec![(web(), elsewhere("sp3-lint-live-00000000")), (db(), elsewhere("sp3-lint-gone-11111111"))],
            "not in an account"
        );

        crate::sync::account::create_account(&d.env(), "MacBook-A").unwrap();
        crate::sync::runtime::mutate(&d.env(), |s| {
            let device = s.device_id.clone();
            let payload = KeySlotPayload {
                schema: SLOT_SCHEMA,
                name: "SP3-LINT-LIVE".into(),
                mode: SlotMode::Own,
                origin_device_id: device.clone(),
                created_at_ms: 5,
                public_key: None,
                fingerprint: None,
                key_type: None,
                has_passphrase: None,
            };
            let account = s.account.as_mut().unwrap();
            crate::sync::slots::put_slot(account, &"0".repeat(32), Some(&payload), &device, 5);
            crate::sync::slots::put_slot(account, &format!("11111111{}", "0".repeat(24)), Some(&KeySlotPayload { name: "sp3-lint-gone".into(), ..payload }), &device, 5);
            crate::sync::slots::put_slot(account, &format!("11111111{}", "0".repeat(24)), None, &device, 6);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            messages(),
            vec![(web(), synced("sp3-lint-live-00000000")), (db(), elsewhere("sp3-lint-gone-11111111"))],
            "the account has the first slot (whatever its case) and only a tombstone of the second"
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
        let undefined: Vec<_> = lint(&doc, &BTreeSet::new())
            .into_iter()
            .filter(|i| i.message.contains("ProxyJump references undefined host"))
            .collect();
        assert!(undefined.is_empty(), "secondary alias must not be flagged: {undefined:?}");
    }

    #[test]
    fn lint_proxyjump_none_not_flagged() {
        let (doc, _dir) = doc_with("Host direct\n ProxyJump none\n");
        let undefined: Vec<_> = lint(&doc, &BTreeSet::new())
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

    // ── (b) lint: stable rule ids ─────────────────────────────────────────────
    #[test]
    fn lint_issues_carry_stable_rule_ids() {
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
        let issues = lint(&doc, &BTreeSet::new());

        let rule_of = |alias: &str| -> String {
            issues
                .iter()
                .find(|i| i.alias.as_deref() == Some(alias))
                .unwrap_or_else(|| panic!("no issue for {alias}: {issues:?}"))
                .rule
                .clone()
        };
        assert_eq!(rule_of("dup"), "duplicate-directive");
        assert_eq!(rule_of("shadowme"), "shadowed-host");
        assert_eq!(rule_of("badkey"), "missing-identity-file");
        assert_eq!(rule_of("insecure"), "insecure-strict-host-key-checking");
        assert_eq!(rule_of("jumper"), "undefined-proxy-jump");
    }

    // ── ts-rs export smoke ────────────────────────────────────────────────────
    #[test]
    fn ts_export_types_compile() {
        let _ = LintIssue {
            rule: "duplicate-directive".into(),
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
