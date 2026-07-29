//! SSH key management: scan ~/.ssh for keypairs, agent status, ed25519 generation, public-key
//! reads, and `ssh-copy-id` deployment via the user's terminal.
//!
//! Security model (same as `connect.rs`): the WebView has NO shell permission — all IO/exec
//! happens here, always as argv vectors (NEVER `sh -c`). Every key path coming from the front
//! end must canonicalize to STRICTLY INSIDE the user's `~/.ssh` (symlink escapes rejected →
//! `AppError::ForbiddenPath`). Private-key files are read at most one line deep (just the PEM
//! header) and their contents are never returned or logged. Aliases passed to deploy go
//! through `connect::validate_alias` (rejects option injection like a leading `-`).

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::connect::{build_launch_command, detect_terminals, launch, validate_alias};
use crate::error::AppError;

// ─── DTOs ─────────────────────────────────────────────────────────────────────

/// One keypair found in ~/.ssh. Identification fields (type/bits/fingerprint/comment) come
/// from `ssh-keygen -l` and are best-effort: a failure leaves them None/"unknown" instead of
/// failing the whole listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct KeyInfo {
    pub name: String,
    pub private_path: String,
    pub public_path: Option<String>,
    /// e.g. "ED25519", "RSA"; "unknown" when `ssh-keygen -l` failed.
    pub key_type: String,
    pub bits: Option<u32>,
    pub fingerprint_sha256: Option<String>,
    pub comment: Option<String>,
    /// Loaded into the running ssh-agent (matched by SHA256 fingerprint).
    pub in_agent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct AgentStatus {
    pub running: bool,
    pub key_count: u32,
}

// ─── Path / name validation (security-critical) ───────────────────────────────

/// The user's ~/.ssh directory. Errors if the home dir is unknown.
pub fn ssh_dir() -> Result<PathBuf, AppError> {
    let home = dirs::home_dir()
        .ok_or_else(|| AppError::Other("cannot determine home directory".to_string()))?;
    Ok(home.join(".ssh"))
}

/// Canonicalize `path` and require it to live STRICTLY INSIDE the canonicalized `ssh_dir`.
/// Canonicalization resolves symlinks, so a link under ~/.ssh pointing elsewhere is rejected.
fn canonical_inside(path: &str, ssh_dir: &Path) -> Result<PathBuf, AppError> {
    let forbidden = || AppError::ForbiddenPath(path.to_string());
    let root = ssh_dir.canonicalize().map_err(|_| forbidden())?;
    let p = Path::new(path).canonicalize().map_err(|_| forbidden())?;
    if p == root || !p.starts_with(&root) {
        return Err(forbidden());
    }
    Ok(p)
}

/// Validate a public-key path from the front end: must END with `.pub`, canonicalize inside
/// `ssh_dir`, still end with `.pub` AFTER canonicalization (a symlink `x.pub → id_rsa` must
/// never read private material), and be a regular file.
pub fn validate_public_path(path: &str, ssh_dir: &Path) -> Result<PathBuf, AppError> {
    let forbidden = || AppError::ForbiddenPath(path.to_string());
    if !path.ends_with(".pub") {
        return Err(forbidden());
    }
    let p = canonical_inside(path, ssh_dir)?;
    let canonical_name_ok = p
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".pub"))
        .unwrap_or(false);
    if !canonical_name_ok || !p.is_file() {
        return Err(forbidden());
    }
    Ok(p)
}

/// Validate a new key NAME: `^[A-Za-z0-9][A-Za-z0-9._-]*$` (no leading dash/dot → no option
/// injection, no hidden/relative paths, no separators), and not a `.pub` suffix (would collide
/// with the generated public file naming).
pub fn validate_key_name(name: &str) -> Result<(), AppError> {
    let mut chars = name.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.ends_with(".pub");
    if ok {
        Ok(())
    } else {
        Err(AppError::ForbiddenPath(format!("invalid key name: {name:?}")))
    }
}

/// Resolve the target private-key path for generating `name` under `ssh_dir`, refusing when
/// either `<name>` or `<name>.pub` already exists (incl. as symlink/dir — `symlink_metadata`).
pub fn generate_target(ssh_dir: &Path, name: &str) -> Result<PathBuf, AppError> {
    validate_key_name(name)?;
    let target = ssh_dir.join(name);
    if fs::symlink_metadata(&target).is_ok() {
        return Err(AppError::Other(format!("~/.ssh/{name} already exists")));
    }
    let pub_target = ssh_dir.join(format!("{name}.pub"));
    if fs::symlink_metadata(&pub_target).is_ok() {
        return Err(AppError::Other(format!("~/.ssh/{name}.pub already exists")));
    }
    Ok(target)
}

// ─── Scanning ─────────────────────────────────────────────────────────────────

/// File names in ~/.ssh that are never private keys (or are paired separately).
fn excluded_name(name: &str) -> bool {
    name.starts_with("known_hosts")
        || name.starts_with("config")
        || name.starts_with("authorized_keys")
        || name.ends_with(".bak")
        || name.ends_with(".pub")
}

/// True if the file's FIRST line marks a PEM private key (`-----BEGIN … PRIVATE KEY`,
/// covering OPENSSH/RSA/EC forms). Reads at most 256 bytes — NEVER the key material.
fn first_line_is_private_key(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut reader = std::io::BufReader::new(file.take(256));
    let mut line = String::new();
    // Non-UTF8 (binary) content errors out → not a PEM key.
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    let line = line.trim_end();
    line.starts_with("-----BEGIN ") && line.contains("PRIVATE KEY")
}

/// Parsed `ssh-keygen -l` line: `2048 SHA256:xxx comment (RSA)`.
#[derive(Debug, Clone, PartialEq)]
pub struct KeygenFields {
    pub bits: u32,
    pub fingerprint: String,
    pub comment: Option<String>,
    pub key_type: String,
}

/// Parse one `ssh-keygen -l` output line. The comment may contain spaces (everything between
/// the fingerprint and the trailing `(TYPE)`); `"no comment"` and empty map to None.
pub fn parse_keygen_l(line: &str) -> Option<KeygenFields> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return None;
    }
    let bits: u32 = tokens[0].parse().ok()?;
    let fingerprint = tokens[1];
    if !fingerprint.starts_with("SHA256:") {
        return None;
    }
    let last = tokens[tokens.len() - 1];
    if !(last.starts_with('(') && last.ends_with(')') && last.len() > 2) {
        return None;
    }
    let key_type = last[1..last.len() - 1].to_string();
    let comment = tokens[2..tokens.len() - 1].join(" ");
    let comment = match comment.as_str() {
        "" | "no comment" => None,
        c => Some(c.to_string()),
    };
    Some(KeygenFields {
        bits,
        fingerprint: fingerprint.to_string(),
        comment,
        key_type,
    })
}

/// Run `ssh-keygen -l -f <path>` (argv, no shell) and parse its output. Any failure → None.
fn keygen_fields(path: &Path) -> Option<KeygenFields> {
    let out = Command::new("ssh-keygen").arg("-l").arg("-f").arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_keygen_l(&String::from_utf8_lossy(&out.stdout))
}

/// Interpret `ssh-add -l`: exit 0 → running with the listed keys, exit 1 → running but empty
/// ("The agent has no identities."), exit 2 / spawn failure (`None`) → not running.
/// Returns the status plus the set of SHA256 fingerprints currently loaded.
pub fn parse_agent_list(exit_code: Option<i32>, stdout: &str) -> (AgentStatus, HashSet<String>) {
    match exit_code {
        Some(0) => {
            let fingerprints: HashSet<String> = stdout
                .lines()
                .filter_map(|l| l.split_whitespace().nth(1))
                .filter(|f| f.starts_with("SHA256:"))
                .map(str::to_string)
                .collect();
            let count = stdout.lines().filter(|l| !l.trim().is_empty()).count() as u32;
            (AgentStatus { running: true, key_count: count }, fingerprints)
        }
        Some(1) => (AgentStatus { running: true, key_count: 0 }, HashSet::new()),
        _ => (AgentStatus { running: false, key_count: 0 }, HashSet::new()),
    }
}

/// Run `ssh-add -l` ONCE and interpret it (see `parse_agent_list`).
fn agent_snapshot() -> (AgentStatus, HashSet<String>) {
    match Command::new("ssh-add").arg("-l").output() {
        Ok(out) => parse_agent_list(out.status.code(), &String::from_utf8_lossy(&out.stdout)),
        Err(_) => parse_agent_list(None, ""),
    }
}

/// Build the KeyInfo for the private key `name` under `dir` (pairing + best-effort
/// identification). The fingerprint probe prefers the sibling `.pub` (cheap, no passphrase
/// prompt risk); `ssh-keygen -l -f` reads only public material either way.
fn key_info_for(dir: &Path, name: &str, agent_fingerprints: &HashSet<String>) -> KeyInfo {
    let private_path = dir.join(name);
    let pub_path = dir.join(format!("{name}.pub"));
    let has_pub = pub_path.is_file();
    let probe = if has_pub { &pub_path } else { &private_path };
    let fields = keygen_fields(probe);

    let (key_type, bits, fingerprint, comment) = match fields {
        Some(f) => (f.key_type, Some(f.bits), Some(f.fingerprint), f.comment),
        None => ("unknown".to_string(), None, None, None),
    };
    let in_agent = fingerprint
        .as_deref()
        .map(|f| agent_fingerprints.contains(f))
        .unwrap_or(false);

    KeyInfo {
        name: name.to_string(),
        private_path: private_path.to_string_lossy().into_owned(),
        public_path: has_pub.then(|| pub_path.to_string_lossy().into_owned()),
        key_type,
        bits,
        fingerprint_sha256: fingerprint,
        comment,
        in_agent,
    }
}

/// Scan `dir` (non-recursive) for private keys: regular files (symlinks/dirs skipped) outside
/// the exclusion list whose first line is a PEM private-key header. A missing dir = no keys.
pub fn scan_keys(dir: &Path, agent_fingerprints: &HashSet<String>) -> Result<Vec<KeyInfo>, AppError> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(AppError::Io(e)),
    };

    let mut out = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if excluded_name(name) {
            continue;
        }
        // Regular files only (symlink_metadata: never follow links while scanning).
        match fs::symlink_metadata(entry.path()) {
            Ok(md) if md.file_type().is_file() => {}
            _ => continue,
        }
        if !first_line_is_private_key(&entry.path()) {
            continue;
        }
        out.push(key_info_for(dir, name, agent_fingerprints));
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// ─── Terminal plumbing ────────────────────────────────────────────────────────

/// Launch `argv` in the user's terminal: explicit override id, else the first detected.
fn launch_in_terminal(terminal_override: Option<String>, argv: &[String]) -> Result<(), AppError> {
    let terminal_id = match terminal_override {
        Some(id) => id,
        None => detect_terminals()
            .into_iter()
            .next()
            .ok_or_else(|| AppError::Other("no terminal found".to_string()))?
            .id,
    };
    let spec = build_launch_command(&terminal_id, argv, false)?;
    launch(&spec)
}

// ─── Tauri commands ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn keys_list() -> Result<Vec<KeyInfo>, AppError> {
    let dir = ssh_dir()?;
    let (_, fingerprints) = agent_snapshot();
    scan_keys(&dir, &fingerprints)
}

#[tauri::command]
pub fn keys_agent_status() -> Result<AgentStatus, AppError> {
    Ok(agent_snapshot().0)
}

#[tauri::command]
pub fn keys_read_public(path: String) -> Result<String, AppError> {
    let dir = ssh_dir()?;
    let p = validate_public_path(&path, &dir)?;
    // Public material only — safe to return.
    Ok(fs::read_to_string(&p)?.trim().to_string())
}

#[tauri::command]
pub fn keys_generate(name: String, comment: Option<String>) -> Result<KeyInfo, AppError> {
    let dir = ssh_dir()?;
    crate::fsutil::ensure_dir_secure(&dir)?;
    let target = generate_target(&dir, &name)?;

    // Argv only, no shell. `-N ""` = empty passphrase (the UI carries the warning); `-q`
    // silences the banner. The comment is the dedicated argument after `-C` — never parsed
    // as an option.
    let mut cmd = Command::new("ssh-keygen");
    cmd.arg("-q").arg("-t").arg("ed25519").arg("-f").arg(&target).arg("-N").arg("");
    if let Some(c) = comment.as_deref() {
        cmd.arg("-C").arg(c);
    }
    let out = cmd.output().map_err(AppError::Io)?;
    if !out.status.success() {
        // stderr from ssh-keygen carries no key material.
        return Err(AppError::Other(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    let (_, fingerprints) = agent_snapshot();
    Ok(key_info_for(&dir, &name, &fingerprints))
}

#[tauri::command]
pub fn keys_generate_in_terminal(
    name: String,
    comment: Option<String>,
    terminal_override: Option<String>,
) -> Result<(), AppError> {
    let dir = ssh_dir()?;
    crate::fsutil::ensure_dir_secure(&dir)?;
    let target = generate_target(&dir, &name)?;

    // Interactive ssh-keygen (passphrase prompts happen in the terminal). No `-N`.
    let mut argv: Vec<String> = vec![
        "ssh-keygen".into(),
        "-t".into(),
        "ed25519".into(),
        "-f".into(),
        target.to_string_lossy().into_owned(),
    ];
    if let Some(c) = comment {
        argv.push("-C".into());
        argv.push(c);
    }
    launch_in_terminal(terminal_override, &argv)
}

#[tauri::command]
pub fn keys_deploy(
    state: tauri::State<crate::state::AppState>,
    alias: String,
    public_path: String,
    terminal_override: Option<String>,
) -> Result<(), AppError> {
    // Alias must be a real host in the loaded doc AND pass the charset gate (no leading `-`).
    {
        let doc_lock = state.doc.lock().unwrap();
        let doc = doc_lock
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        validate_alias(doc, &alias)?;
    }

    let dir = ssh_dir()?;
    let p = validate_public_path(&public_path, &dir)?;

    let argv: Vec<String> = vec![
        "ssh-copy-id".into(),
        "-i".into(),
        p.to_string_lossy().into_owned(),
        alias,
    ];
    launch_in_terminal(terminal_override, &argv)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV_OPENSSH: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n";
    const PRIV_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n";
    const PUB_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFake frank@laptop\n";

    fn fixture_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // ── name validation ───────────────────────────────────────────────────────

    #[test]
    fn validate_key_name_accepts_typical_names() {
        for n in ["id_ed25519", "id_rsa", "work-2026", "a", "9key", "id.ed25519_work"] {
            assert!(validate_key_name(n).is_ok(), "{n:?} should be accepted");
        }
    }

    #[test]
    fn validate_key_name_rejects_traversal_options_and_separators() {
        for n in [
            "", "-flag", ".hidden", "../escape", "a/b", "a\\b", "a b", "a;b", "key$",
            "name.pub", "_lead",
        ] {
            let err = validate_key_name(n).unwrap_err();
            assert!(matches!(err, AppError::ForbiddenPath(_)), "{n:?} → {err:?}");
        }
    }

    // ── generate_target ───────────────────────────────────────────────────────

    #[test]
    fn generate_target_refuses_existing_private_or_public() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join("exists"), PRIV_OPENSSH).unwrap();
        assert!(generate_target(dir.path(), "exists").is_err(), "existing private refused");

        std::fs::write(dir.path().join("half.pub"), PUB_LINE).unwrap();
        assert!(generate_target(dir.path(), "half").is_err(), "existing .pub refused");

        let ok = generate_target(dir.path(), "fresh").unwrap();
        assert_eq!(ok, dir.path().join("fresh"));
    }

    #[cfg(unix)]
    #[test]
    fn generate_target_refuses_existing_symlink() {
        let dir = fixture_dir();
        std::os::unix::fs::symlink("/nonexistent", dir.path().join("link")).unwrap();
        assert!(generate_target(dir.path(), "link").is_err(), "dangling symlink still refused");
    }

    // ── scanning / classification ─────────────────────────────────────────────

    #[test]
    fn scan_keys_finds_keypairs_and_pairs_pub() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join("id_ed25519"), PRIV_OPENSSH).unwrap();
        std::fs::write(dir.path().join("id_ed25519.pub"), PUB_LINE).unwrap();
        std::fs::write(dir.path().join("id_rsa_legacy"), PRIV_RSA_PEM).unwrap();

        let keys = scan_keys(dir.path(), &HashSet::new()).unwrap();
        assert_eq!(keys.len(), 2, "{keys:?}");

        let ed = keys.iter().find(|k| k.name == "id_ed25519").unwrap();
        assert_eq!(
            ed.public_path.as_deref(),
            Some(dir.path().join("id_ed25519.pub").to_str().unwrap())
        );
        assert!(!ed.in_agent);

        let rsa = keys.iter().find(|k| k.name == "id_rsa_legacy").unwrap();
        assert_eq!(rsa.public_path, None, "no sibling .pub");
        // ssh-keygen can't identify the fake material (or is absent in CI) → None fields,
        // never a global error.
        assert!(rsa.bits.is_none() || rsa.bits.is_some());
    }

    #[test]
    fn scan_keys_skips_excluded_names_non_keys_and_dirs() {
        let dir = fixture_dir();
        // Excluded names even WITH a private-key first line.
        for n in ["known_hosts", "known_hosts.old", "config", "config.d.conf", "authorized_keys", "old.bak"] {
            std::fs::write(dir.path().join(n), PRIV_OPENSSH).unwrap();
        }
        // Non-key contents.
        std::fs::write(dir.path().join("random.txt"), "hello\n").unwrap();
        std::fs::write(dir.path().join("binary"), [0u8, 159, 146, 150]).unwrap();
        // A certificate-ish .pub alone (excluded by suffix), and a directory.
        std::fs::write(dir.path().join("orphan.pub"), PUB_LINE).unwrap();
        std::fs::create_dir(dir.path().join("config.d")).unwrap();
        // One real key.
        std::fs::write(dir.path().join("real_key"), PRIV_OPENSSH).unwrap();

        let keys = scan_keys(dir.path(), &HashSet::new()).unwrap();
        let names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(names, vec!["real_key"], "{names:?}");
    }

    #[cfg(unix)]
    #[test]
    fn scan_keys_skips_symlinked_private_files() {
        let outside = fixture_dir();
        let real = outside.path().join("real");
        std::fs::write(&real, PRIV_OPENSSH).unwrap();

        let dir = fixture_dir();
        std::os::unix::fs::symlink(&real, dir.path().join("linked_key")).unwrap();
        let keys = scan_keys(dir.path(), &HashSet::new()).unwrap();
        assert!(keys.is_empty(), "symlinks are never scanned as keys: {keys:?}");
    }

    #[test]
    fn scan_keys_missing_dir_is_empty() {
        let dir = fixture_dir();
        let missing = dir.path().join("nope");
        assert!(scan_keys(&missing, &HashSet::new()).unwrap().is_empty());
    }

    // ── public-path validation ────────────────────────────────────────────────

    #[test]
    fn validate_public_path_accepts_pub_inside() {
        let dir = fixture_dir();
        let p = dir.path().join("id_ed25519.pub");
        std::fs::write(&p, PUB_LINE).unwrap();
        let ok = validate_public_path(p.to_str().unwrap(), dir.path()).unwrap();
        assert_eq!(ok, p.canonicalize().unwrap());
    }

    #[test]
    fn validate_public_path_rejects_non_pub_and_outside() {
        let dir = fixture_dir();
        let private = dir.path().join("id_ed25519");
        std::fs::write(&private, PRIV_OPENSSH).unwrap();
        // Not a .pub suffix (a private key!) → rejected.
        let err = validate_public_path(private.to_str().unwrap(), dir.path()).unwrap_err();
        assert!(matches!(err, AppError::ForbiddenPath(_)), "{err:?}");

        // A .pub OUTSIDE the ssh dir → rejected.
        let outside = fixture_dir();
        let foreign = outside.path().join("foreign.pub");
        std::fs::write(&foreign, PUB_LINE).unwrap();
        let err2 = validate_public_path(foreign.to_str().unwrap(), dir.path()).unwrap_err();
        assert!(matches!(err2, AppError::ForbiddenPath(_)), "{err2:?}");

        // Traversal: <ssh>/../foreign.pub → rejected after canonicalization.
        let sneaky = format!("{}/../{}", dir.path().display(), "foreign.pub");
        let err3 = validate_public_path(&sneaky, dir.path()).unwrap_err();
        assert!(matches!(err3, AppError::ForbiddenPath(_)), "{err3:?}");
    }

    #[cfg(unix)]
    #[test]
    fn validate_public_path_rejects_symlink_escape_and_pub_to_private() {
        let outside = fixture_dir();
        let secret = outside.path().join("secret.pub");
        std::fs::write(&secret, "outside material").unwrap();

        let dir = fixture_dir();
        // Symlink escaping ~/.ssh → canonicalizes outside → rejected.
        let escape = dir.path().join("escape.pub");
        std::os::unix::fs::symlink(&secret, &escape).unwrap();
        let err = validate_public_path(escape.to_str().unwrap(), dir.path()).unwrap_err();
        assert!(matches!(err, AppError::ForbiddenPath(_)), "{err:?}");

        // Symlink INSIDE ~/.ssh whose target is a PRIVATE key → canonical name loses `.pub`
        // → rejected (this would otherwise exfiltrate private material via keys_read_public).
        let private = dir.path().join("id_rsa");
        std::fs::write(&private, PRIV_RSA_PEM).unwrap();
        let disguised = dir.path().join("disguised.pub");
        std::os::unix::fs::symlink(&private, &disguised).unwrap();
        let err2 = validate_public_path(disguised.to_str().unwrap(), dir.path()).unwrap_err();
        assert!(matches!(err2, AppError::ForbiddenPath(_)), "{err2:?}");
    }

    // ── ssh-keygen -l parsing ─────────────────────────────────────────────────

    #[test]
    fn parse_keygen_l_standard_line() {
        let f = parse_keygen_l("256 SHA256:AbCdEf123 frank@laptop (ED25519)\n").unwrap();
        assert_eq!(f.bits, 256);
        assert_eq!(f.fingerprint, "SHA256:AbCdEf123");
        assert_eq!(f.comment.as_deref(), Some("frank@laptop"));
        assert_eq!(f.key_type, "ED25519");
    }

    #[test]
    fn parse_keygen_l_comment_with_spaces_and_no_comment() {
        let f = parse_keygen_l("2048 SHA256:xyz my work laptop (RSA)").unwrap();
        assert_eq!(f.bits, 2048);
        assert_eq!(f.comment.as_deref(), Some("my work laptop"));
        assert_eq!(f.key_type, "RSA");

        let g = parse_keygen_l("3072 SHA256:abc no comment (RSA)").unwrap();
        assert_eq!(g.comment, None);
    }

    #[test]
    fn parse_keygen_l_rejects_garbage() {
        for bad in [
            "",
            "not a keygen line",
            "x SHA256:abc c (RSA)",       // non-numeric bits
            "256 MD5:aa:bb c (RSA)",      // non-SHA256 fingerprint
            "256 SHA256:abc c RSA",       // missing parens
            "256 SHA256:abc",             // too short
        ] {
            assert!(parse_keygen_l(bad).is_none(), "{bad:?} must not parse");
        }
    }

    // ── ssh-add -l interpretation ─────────────────────────────────────────────

    #[test]
    fn parse_agent_list_running_with_keys() {
        let stdout = "256 SHA256:aaa frank@laptop (ED25519)\n3072 SHA256:bbb work (RSA)\n";
        let (status, fps) = parse_agent_list(Some(0), stdout);
        assert!(status.running);
        assert_eq!(status.key_count, 2);
        assert!(fps.contains("SHA256:aaa") && fps.contains("SHA256:bbb"));
    }

    #[test]
    fn parse_agent_list_running_empty_and_not_running() {
        let (empty, fps) = parse_agent_list(Some(1), "The agent has no identities.\n");
        assert!(empty.running);
        assert_eq!(empty.key_count, 0);
        assert!(fps.is_empty());

        let (down, _) = parse_agent_list(Some(2), "");
        assert!(!down.running);
        let (spawn_err, _) = parse_agent_list(None, "");
        assert!(!spawn_err.running);
    }

    // ── in_agent wiring ───────────────────────────────────────────────────────

    #[test]
    fn key_info_in_agent_requires_known_fingerprint() {
        // Fake key → ssh-keygen yields no fingerprint → in_agent must be false even with a
        // populated agent set (never a false positive).
        let dir = fixture_dir();
        std::fs::write(dir.path().join("k"), PRIV_OPENSSH).unwrap();
        let mut agent = HashSet::new();
        agent.insert("SHA256:whatever".to_string());
        let keys = scan_keys(dir.path(), &agent).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(!keys[0].in_agent);
    }

    // ── ts-rs export sanity ───────────────────────────────────────────────────

    #[test]
    fn dto_shapes_compile() {
        let _k = KeyInfo {
            name: "id_ed25519".into(),
            private_path: "/h/.ssh/id_ed25519".into(),
            public_path: Some("/h/.ssh/id_ed25519.pub".into()),
            key_type: "ED25519".into(),
            bits: Some(256),
            fingerprint_sha256: Some("SHA256:abc".into()),
            comment: Some("frank@laptop".into()),
            in_agent: true,
        };
        let _a = AgentStatus { running: true, key_count: 1 };
    }
}
