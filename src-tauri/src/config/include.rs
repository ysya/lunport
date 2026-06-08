use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::config::model::{ConfigFile, Item, SshConfigDoc};
use crate::config::parser::parse_file;
use crate::error::AppError;
use crate::fsutil;

/// Load a config file and recursively all files it `Include`s into a multi-file document.
/// Returns the main file first, then included files in load order (depth-first, lexical glob order).
pub fn load_doc(main_path: &Path) -> Result<SshConfigDoc, AppError> {
    let mut files: Vec<ConfigFile> = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    load_recursive(main_path, &mut files, &mut visited, true)?;
    Ok(SshConfigDoc { files })
}

fn load_recursive(
    path: &Path,
    files: &mut Vec<ConfigFile>,
    visited: &mut HashSet<PathBuf>,
    is_root: bool,
) -> Result<(), AppError> {
    // Canonicalize for cycle detection; fall back to absolute if canonicalize fails (file doesn't
    // exist yet in some edge cases, but we still guard with the raw path).
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    if visited.contains(&canonical) {
        return Ok(());
    }
    visited.insert(canonical);

    // The main config must exist (fatal). An INCLUDED file that can't be read (removed mid-scan,
    // permission denied, broken symlink that passed is_file()) is skipped so one bad include never
    // aborts loading the whole config.
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            if is_root {
                return Err(AppError::Io(e));
            }
            return Ok(());
        }
    };
    let (items, trailing_newline) = parse_file(&text);
    let fingerprint = match fsutil::file_fingerprint(path) {
        Ok(f) => f,
        Err(e) => {
            if is_root {
                return Err(e);
            }
            return Ok(());
        }
    };

    let parent = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    // Collect Include directives before pushing (so we don't borrow `items` and `files` at once).
    let include_patterns: Vec<String> = items
        .iter()
        .filter_map(|item| {
            if let Item::Directive(d) = item {
                if d.key == "include" {
                    return Some(d.value.clone());
                }
            }
            None
        })
        .collect();

    // Push this file now (main file first, parent before children).
    files.push(ConfigFile {
        path: path.to_path_buf(),
        items,
        trailing_newline,
        fingerprint,
    });

    // Process includes.
    for pattern_str in &include_patterns {
        // Each include value may contain multiple whitespace-separated patterns.
        for token in pattern_str.split_whitespace() {
            // Expand ~ and environment variables.
            let expanded = match shellexpand::full(token) {
                Ok(s) => s.into_owned(),
                Err(_) => continue,
            };

            // Resolve relative paths against the parent directory of the including file.
            let base_pattern = {
                let ep = Path::new(&expanded);
                if ep.is_absolute() {
                    expanded.clone()
                } else {
                    parent.join(&expanded).to_string_lossy().to_string()
                }
            };

            // Expand wildcards and sort lexically.
            let mut matched_paths: Vec<PathBuf> = match glob::glob(&base_pattern) {
                Ok(entries) => entries
                    .filter_map(|r| r.ok())
                    .filter(|p| p.is_file())
                    .collect(),
                Err(_) => continue,
            };
            matched_paths.sort();

            for matched in matched_paths {
                // Included files are non-root: a failure inside skips that file, not the whole load.
                load_recursive(&matched, files, visited, false)?;
            }
        }
    }

    Ok(())
}

/// Index of the file in `doc.files` whose top-level items contain a Host block matching `alias`
/// (exact pattern token). None if no managed file owns it.
pub fn find_host_file_index(doc: &SshConfigDoc, alias: &str) -> Option<usize> {
    doc.files.iter().position(|cf| {
        cf.items.iter().any(|item| {
            if let Item::Host(h) = item {
                h.patterns.iter().any(|p| p == alias)
            } else {
                false
            }
        })
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

    fn fixture_path(rel: &str) -> PathBuf {
        PathBuf::from(FIXTURE_DIR).join(rel)
    }

    // ── Test 1: load_doc loads main + included files ──────────────────────────

    #[test]
    fn load_doc_loads_main_and_includes() {
        let main = fixture_path("inc/config");
        let doc = load_doc(&main).expect("load_doc should succeed");

        // At least 3 files: main + home.conf + work.conf.
        assert!(
            doc.files.len() >= 3,
            "expected >= 3 files, got {}",
            doc.files.len()
        );

        // First file is the main config.
        assert!(
            doc.files[0].path.ends_with("inc/config"),
            "first file must be main config, got {:?}",
            doc.files[0].path
        );

        // Included files in lexical order: home.conf before work.conf.
        let included_names: Vec<String> = doc.files[1..]
            .iter()
            .map(|cf| {
                cf.path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert_eq!(
            included_names,
            vec!["home.conf", "work.conf"],
            "included files must be in lexical order"
        );

        // Verify each ConfigFile.path is correct (the full path is a real file).
        for cf in &doc.files {
            assert!(cf.path.exists(), "path {:?} must exist", cf.path);
        }
    }

    // ── Test 2: find_host_file_index ─────────────────────────────────────────

    #[test]
    fn find_host_file_index_locates_hosts() {
        let main = fixture_path("inc/config");
        let doc = load_doc(&main).expect("load_doc should succeed");

        let main_idx = find_host_file_index(&doc, "main-a");
        assert_eq!(main_idx, Some(0), "main-a should be in file index 0");

        let work_idx = find_host_file_index(&doc, "work-1");
        assert!(work_idx.is_some(), "work-1 should be found");
        assert!(
            doc.files[work_idx.unwrap()].path.ends_with("work.conf"),
            "work-1 should be in work.conf"
        );

        let none_idx = find_host_file_index(&doc, "nonexistent-host");
        assert_eq!(none_idx, None, "unknown alias should return None");
    }

    // ── Test 3: cycle guard — self-include terminates and loads file once ─────

    #[test]
    fn cycle_guard_self_include_terminates() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");

        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            // Self-referencing include.
            writeln!(f, "Host self-host").unwrap();
            writeln!(f, "    HostName self.example.com").unwrap();
            writeln!(f, "Include config").unwrap();
        }

        let doc = load_doc(&config_path).expect("load_doc must not infinite-loop");

        // File loaded exactly once.
        assert_eq!(doc.files.len(), 1, "cycle-guarded file must appear only once");
        assert_eq!(
            doc.files[0].path.canonicalize().unwrap(),
            config_path.canonicalize().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_include_is_skipped_not_fatal() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        {
            let mut f = std::fs::File::create(&config_path).unwrap();
            // Include FIRST so it's a top-level directive (parser folds post-Host lines into the body).
            writeln!(f, "Include secret.conf").unwrap();
            writeln!(f, "Host main-h").unwrap();
            writeln!(f, "    HostName main.example.com").unwrap();
        }
        // An included file that exists (is_file() passes) but is unreadable.
        let secret = dir.path().join("secret.conf");
        std::fs::write(&secret, "Host secret-h\n").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();

        let doc = load_doc(&config_path).expect("unreadable include must NOT fail the whole load");
        assert_eq!(
            doc.files.len(),
            1,
            "unreadable include is skipped; main still loads"
        );
        assert!(find_host_file_index(&doc, "main-h").is_some());
        assert!(find_host_file_index(&doc, "secret-h").is_none());

        // Restore perms so tempdir cleanup succeeds.
        let _ = std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_root_is_fatal() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        std::fs::write(&config_path, "Host h\n").unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let res = load_doc(&config_path);
        assert!(res.is_err(), "an unreadable MAIN config must be a fatal error");

        let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }
}
