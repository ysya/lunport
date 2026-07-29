//! known_hosts viewer + safe entry removal — the "host key changed after reinstall" cleanup,
//! i.e. `ssh-keygen -R` without the terminal.
//!
//! Security model (same as `keys.rs` / `connect.rs`): the WebView has NO shell or fs permission —
//! all IO happens here. The known_hosts path is FIXED to `~/.ssh/known_hosts`; v1 accepts NO
//! caller-supplied paths (the front end can only name line indices + expected first fields).
//!
//! Removal design (deliberate): we do NOT shell out to `ssh-keygen -R` at all. `-R` only accepts
//! plain hostnames (not `|1|…` hash tokens), so hashed entries would need a second, different
//! code path anyway. Instead BOTH plain and hashed entries are removed by our own lossless
//! line-removal: re-read the current file, validate every targeted index still holds the expected
//! first field (stale-index guard → `AppError::Conflict` so the UI reloads instead of deleting
//! the wrong line), back up into the mirror dir (`fsutil::backup`), drop exactly those lines, and
//! `fsutil::atomic_write`. One code path, no external-tool parsing surprises, byte-identical
//! preservation of every untouched line, and the backups dir keeps the safety net.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::fsutil;

// ─── Line-level parsing (shared with discover.rs) ─────────────────────────────

/// One syntactically valid known_hosts line, borrowed from the file text.
/// `line_index` is the 0-based FILE line number: comment/blank/malformed lines keep their slots
/// (they are simply not represented), so indices always address the real file.
#[derive(Debug, Clone, PartialEq)]
pub struct RawLine<'a> {
    pub line_index: u32,
    /// `@revoked` / `@cert-authority` when present (any `@…` first token is treated as a marker).
    pub marker: Option<&'a str>,
    /// First (non-marker) field verbatim: comma-joined names, `[host]:port`, or a `|1|…` hash.
    pub hosts: &'a str,
    /// e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`.
    pub key_type: &'a str,
    /// The base64 key blob, verbatim.
    pub key_base64: &'a str,
}

/// Parse the fields of a single known_hosts line. Returns None for comments, blanks, and
/// malformed lines (fewer than `hosts keytype key` fields after the optional marker).
fn parse_fields(line: &str) -> Option<(Option<&str>, &str, &str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let mut fields = trimmed.split_whitespace();
    let mut first = fields.next()?;
    let marker = if first.starts_with('@') {
        let m = first;
        first = fields.next()?;
        Some(m)
    } else {
        None
    };
    let key_type = fields.next()?;
    let key_base64 = fields.next()?;
    Some((marker, first, key_type, key_base64))
}

/// Parse known_hosts text into raw lines, keeping FILE line numbers (see [`RawLine`]).
pub fn parse_lines(text: &str) -> Vec<RawLine<'_>> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            parse_fields(line).map(|(marker, hosts, key_type, key_base64)| RawLine {
                line_index: i as u32,
                marker,
                hosts,
                key_type,
                key_base64,
            })
        })
        .collect()
}

// ─── DTO ──────────────────────────────────────────────────────────────────────

/// One known_hosts entry for the UI. `line_index` addresses the file line (stable as long as the
/// file is unchanged — guarded by the expected-hosts check on removal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct KnownHostEntry {
    pub line_index: u32,
    /// First field verbatim: comma-joined host names, or the `|1|…` hash for hashed entries.
    pub hosts: String,
    pub key_type: String,
    /// `SHA256:<base64-no-padding>` of the key blob (OpenSSH format); None if the blob is not
    /// valid base64.
    pub fingerprint_sha256: Option<String>,
    pub hashed: bool,
    /// `@revoked` / `@cert-authority` when present.
    pub marker: Option<String>,
}

/// OpenSSH-style fingerprint of a base64 key blob: `SHA256:` + unpadded base64 of the SHA-256 of
/// the DECODED blob. Pure Rust (base64 + sha2) — no ssh-keygen dependency.
pub fn fingerprint_sha256(key_base64: &str) -> Option<String> {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(key_base64)
        .ok()?;
    let digest = Sha256::digest(&blob);
    Some(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

/// known_hosts text → UI entries.
pub fn list_entries(text: &str) -> Vec<KnownHostEntry> {
    parse_lines(text)
        .into_iter()
        .map(|raw| KnownHostEntry {
            line_index: raw.line_index,
            hosts: raw.hosts.to_string(),
            key_type: raw.key_type.to_string(),
            fingerprint_sha256: fingerprint_sha256(raw.key_base64),
            hashed: raw.hosts.starts_with('|'),
            marker: raw.marker.map(str::to_string),
        })
        .collect()
}

// ─── Lossless line removal ────────────────────────────────────────────────────

/// Remove the lines at `line_indices` from `text`, returning the new text. Every other byte is
/// preserved exactly (comments, blank lines, odd spacing, trailing newline).
///
/// `expected_hosts` is a parallel array: each index must currently parse to that first field,
/// otherwise the caller's view is stale → `AppError::Conflict` (the UI reloads instead of
/// deleting the wrong line). Out-of-range indices are a Conflict for the same reason (the file
/// shrank since it was listed). Length mismatch / duplicate indices are caller bugs → `Other`.
pub fn remove_lines(
    text: &str,
    line_indices: &[u32],
    expected_hosts: &[String],
) -> Result<String, AppError> {
    if line_indices.len() != expected_hosts.len() {
        return Err(AppError::Other(format!(
            "line_indices ({}) and expected_hosts ({}) must have the same length",
            line_indices.len(),
            expected_hosts.len()
        )));
    }
    let mut remove: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for idx in line_indices {
        if !remove.insert(*idx) {
            return Err(AppError::Other(format!("duplicate line index {idx}")));
        }
    }

    // Segments keep their line terminators, so re-concatenation is byte-identical. `lines()`
    // (used for indices) and `split_inclusive('\n')` agree on line boundaries.
    let segments: Vec<&str> = text.split_inclusive('\n').collect();

    for (idx, expected) in line_indices.iter().zip(expected_hosts) {
        let Some(segment) = segments.get(*idx as usize) else {
            return Err(AppError::Conflict(format!(
                "known_hosts line {idx} no longer exists — reload"
            )));
        };
        let actual = parse_fields(segment).map(|(_, hosts, _, _)| hosts);
        if actual != Some(expected.as_str()) {
            return Err(AppError::Conflict(format!(
                "known_hosts line {idx} changed on disk — reload"
            )));
        }
    }

    Ok(segments
        .iter()
        .enumerate()
        .filter(|(i, _)| !remove.contains(&(*i as u32)))
        .map(|(_, s)| *s)
        .collect())
}

/// Validate + back up (mirror dir) + remove + atomic-write `path`. Returns the removed count.
/// Internal: only the `known_hosts_remove` command (fixed path) is IPC-exposed.
fn remove_from_file(
    path: &Path,
    line_indices: &[u32],
    expected_hosts: &[String],
    retention: Option<usize>,
) -> Result<u32, AppError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AppError::Conflict(format!(
                "{} vanished — reload",
                path.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
    let new_text = remove_lines(&text, line_indices, expected_hosts)?;

    fsutil::backup(path)?;
    if let Some(keep) = retention {
        if let Err(e) = fsutil::prune_backups(path, keep) {
            eprintln!("[known_hosts] prune failed for {}: {e}", path.display());
        }
    }
    fsutil::atomic_write(path, new_text.as_bytes(), 0o600)?;
    Ok(line_indices.len() as u32)
}

// ─── Commands (fixed path — see module docs) ──────────────────────────────────

/// The ONE file these commands operate on: `~/.ssh/known_hosts`. v1 deliberately accepts no
/// caller-supplied paths.
fn known_hosts_path() -> Result<PathBuf, AppError> {
    dirs::home_dir()
        .map(|h| h.join(".ssh").join("known_hosts"))
        .ok_or_else(|| AppError::Other("cannot determine home directory".to_string()))
}

/// 讀取 known_hosts 全文；檔案不存在時回空字串（首次使用的正常狀態）。
pub fn read_known_hosts_text() -> Result<String, AppError> {
    let path = known_hosts_path()?;
    match std::fs::read_to_string(&path) {
        Ok(t) => Ok(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

/// 追加一行到 known_hosts。呼叫端必須先驗證 `line` 的形狀（見 `deploy_trust_host_key`）。
/// 檔案不存在時以 0600 建立，並確保與前一行之間有換行。
pub fn append_known_hosts_line(line: &str) -> Result<(), AppError> {
    let path = known_hosts_path()?;
    let mut text = read_known_hosts_text()?;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(line.trim_end());
    text.push('\n');
    crate::fsutil::atomic_write(&path, text.as_bytes(), 0o600)
}

#[tauri::command]
pub fn known_hosts_list() -> Result<Vec<KnownHostEntry>, AppError> {
    let path = known_hosts_path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(list_entries(&text))
}

#[tauri::command]
pub fn known_hosts_remove(
    state: tauri::State<crate::state::AppState>,
    line_indices: Vec<u32>,
    expected_hosts: Vec<String>,
) -> Result<u32, AppError> {
    let retention = *state.backup_retention.lock().unwrap();
    remove_from_file(
        &known_hosts_path()?,
        &line_indices,
        &expected_hosts,
        retention,
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NjE5AAAAIE5OS0VZ
# a comment line
[gitea.local]:2222,10.0.0.9 ecdsa-sha2-nistp256 QUJDREVGR0g=

|1|kRDjA5tloLanZqUSO6ynIm5XEHI=|tcjT4QcNvY0BB2DBlnQH0v1nyhc= ssh-rsa Tk9UQkFTRTY0IQ==
@revoked old.example.com ssh-rsa UkVWT0tFRA==
malformed-only-two fields
";

    // ── parsing ───────────────────────────────────────────────────────────────

    #[test]
    fn list_entries_plain_hashed_marker_with_file_line_numbers() {
        let entries = list_entries(SAMPLE);
        // Comment (1), blank (3), malformed (6) are skipped, but indices stay FILE line numbers.
        let indices: Vec<u32> = entries.iter().map(|e| e.line_index).collect();
        assert_eq!(indices, vec![0, 2, 4, 5]);

        let plain = &entries[0];
        assert_eq!(plain.hosts, "github.com");
        assert_eq!(plain.key_type, "ssh-ed25519");
        assert!(!plain.hashed);
        assert_eq!(plain.marker, None);

        // Multi-host comma line: the first field is kept VERBATIM (comma-joined, bracket form).
        let multi = &entries[1];
        assert_eq!(multi.hosts, "[gitea.local]:2222,10.0.0.9");
        assert_eq!(multi.key_type, "ecdsa-sha2-nistp256");

        let hashed = &entries[2];
        assert!(hashed.hashed);
        assert_eq!(
            hashed.hosts,
            "|1|kRDjA5tloLanZqUSO6ynIm5XEHI=|tcjT4QcNvY0BB2DBlnQH0v1nyhc="
        );

        let revoked = &entries[3];
        assert_eq!(revoked.marker.as_deref(), Some("@revoked"));
        assert_eq!(revoked.hosts, "old.example.com");
        assert_eq!(revoked.key_type, "ssh-rsa");
    }

    #[test]
    fn parse_lines_skips_comments_blanks_and_malformed() {
        let lines = parse_lines(SAMPLE);
        assert_eq!(lines.len(), 4);
        assert!(
            lines.iter().all(|l| l.line_index != 1 && l.line_index != 3 && l.line_index != 6),
            "comment/blank/malformed lines must not be represented: {lines:?}"
        );
    }

    // ── fingerprint ───────────────────────────────────────────────────────────

    #[test]
    fn fingerprint_matches_known_vector() {
        // Expected value generated with pure Rust right here (independent construction: the
        // fingerprint must hash the DECODED blob, not the base64 text).
        let blob: Vec<u8> = (0u8..=63).collect();
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let expected = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))
        );

        let got = fingerprint_sha256(&key_b64).expect("valid base64 must fingerprint");
        assert_eq!(got, expected);
        assert!(got.starts_with("SHA256:"));
        assert!(!got.ends_with('='), "OpenSSH fingerprints are unpadded base64");
        // Sanity: hashing the base64 TEXT instead of the blob would differ.
        let wrong = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD
                .encode(Sha256::digest(key_b64.as_bytes()))
        );
        assert_ne!(got, wrong);
    }

    #[test]
    fn fingerprint_invalid_base64_is_none() {
        assert_eq!(fingerprint_sha256("not base64 !!!"), None);
        let entries = list_entries("host ssh-rsa ???invalid???\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fingerprint_sha256, None);
    }

    // ── remove_lines ──────────────────────────────────────────────────────────

    #[test]
    fn remove_lines_targets_only_named_lines_byte_identical_otherwise() {
        // Includes a comment with odd spacing and a blank line: both must survive verbatim.
        let new_text = remove_lines(
            SAMPLE,
            &[2],
            &["[gitea.local]:2222,10.0.0.9".to_string()],
        )
        .unwrap();
        let expected = SAMPLE.replace(
            "[gitea.local]:2222,10.0.0.9 ecdsa-sha2-nistp256 QUJDREVGR0g=\n",
            "",
        );
        assert_eq!(new_text, expected);
        assert!(new_text.ends_with('\n'), "trailing newline preserved");
        assert!(new_text.contains("# a comment line\n"));
        assert!(new_text.contains("\n\n"), "blank line preserved");
    }

    #[test]
    fn remove_lines_handles_hashed_entries_by_hash_token() {
        let hash = "|1|kRDjA5tloLanZqUSO6ynIm5XEHI=|tcjT4QcNvY0BB2DBlnQH0v1nyhc=";
        let new_text = remove_lines(SAMPLE, &[4], &[hash.to_string()]).unwrap();
        assert!(!new_text.contains(hash));
        assert_eq!(new_text.lines().count(), SAMPLE.lines().count() - 1);
    }

    #[test]
    fn remove_lines_multiple_indices() {
        let new_text = remove_lines(
            SAMPLE,
            &[0, 5],
            &["github.com".to_string(), "old.example.com".to_string()],
        )
        .unwrap();
        assert!(!new_text.contains("github.com"));
        assert!(!new_text.contains("old.example.com"));
        assert!(new_text.contains("gitea.local"));
        assert_eq!(new_text.lines().count(), SAMPLE.lines().count() - 2);
    }

    #[test]
    fn remove_lines_without_trailing_newline_keeps_other_lines_exact() {
        let text = "a.example ssh-rsa QQ==\nb.example ssh-rsa QQ=="; // no trailing newline
        let out = remove_lines(text, &[1], &["b.example".to_string()]).unwrap();
        assert_eq!(out, "a.example ssh-rsa QQ==\n");
        let out2 = remove_lines(text, &[0], &["a.example".to_string()]).unwrap();
        assert_eq!(out2, "b.example ssh-rsa QQ==", "no newline invented");
    }

    #[test]
    fn remove_lines_stale_first_field_is_conflict() {
        let res = remove_lines(SAMPLE, &[0], &["not-github.com".to_string()]);
        assert!(matches!(res, Err(AppError::Conflict(_))), "got {res:?}");
        // Index pointing at a comment line is also stale (no parseable first field).
        let res = remove_lines(SAMPLE, &[1], &["github.com".to_string()]);
        assert!(matches!(res, Err(AppError::Conflict(_))), "got {res:?}");
    }

    #[test]
    fn remove_lines_out_of_range_is_conflict() {
        let res = remove_lines(SAMPLE, &[999], &["github.com".to_string()]);
        assert!(matches!(res, Err(AppError::Conflict(_))), "got {res:?}");
    }

    #[test]
    fn remove_lines_rejects_length_mismatch_and_duplicates() {
        let res = remove_lines(SAMPLE, &[0, 2], &["github.com".to_string()]);
        assert!(matches!(res, Err(AppError::Other(_))), "got {res:?}");
        let res = remove_lines(
            SAMPLE,
            &[0, 0],
            &["github.com".to_string(), "github.com".to_string()],
        );
        assert!(matches!(res, Err(AppError::Other(_))), "got {res:?}");
    }

    // ── remove_from_file ──────────────────────────────────────────────────────

    #[test]
    fn remove_from_file_backs_up_then_rewrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, SAMPLE).unwrap();

        let removed =
            remove_from_file(&path, &[0], &["github.com".to_string()], None).unwrap();
        assert_eq!(removed, 1);

        // Live file: targeted line gone, everything else intact.
        let live = std::fs::read_to_string(&path).unwrap();
        assert!(!live.contains("github.com"));
        assert!(live.contains("gitea.local"));

        // Backup created in the MIRROR dir (never next to the file) with the ORIGINAL bytes.
        let mirror = fsutil::backup_dir_for(&path).unwrap();
        let backups: Vec<_> = std::fs::read_dir(&mirror)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("known_hosts."))
            .collect();
        assert_eq!(backups.len(), 1, "exactly one backup expected");
        assert_eq!(std::fs::read_to_string(backups[0].path()).unwrap(), SAMPLE);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn remove_from_file_conflict_leaves_file_and_backups_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, SAMPLE).unwrap();

        let res = remove_from_file(&path, &[0], &["stale.example".to_string()], None);
        assert!(matches!(res, Err(AppError::Conflict(_))), "got {res:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SAMPLE);
        // Validation happens BEFORE backup: no backup for a refused removal.
        let mirror = fsutil::backup_dir_for(&path).unwrap();
        assert!(
            !mirror.exists() || std::fs::read_dir(&mirror).unwrap().next().is_none(),
            "no backup may be created on conflict"
        );
    }

    #[test]
    fn remove_from_file_missing_file_is_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let res = remove_from_file(&path, &[0], &["x".to_string()], None);
        assert!(matches!(res, Err(AppError::Conflict(_))), "got {res:?}");
    }
}
