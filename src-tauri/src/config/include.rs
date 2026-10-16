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
    fsutil::check_write(path)?;
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

    validate_include_boundaries(&items, &parent)?;

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
            // SSHelter 自己產生的 agent 設定(金鑰保管庫 spec §6):不是使用者的 config,讀進來會讓主機重複出現。
            if crate::agent::wiring::is_agent_include_token(token) {
                continue;
            }
            // Expand ~ and environment variables.
            let Some(expanded) = expand_token(token) else { continue };

            // Resolve relative paths against the parent directory of the including file.
            let base_pattern = {
                let ep = Path::new(&expanded);
                if ep.is_absolute() {
                    expanded.clone()
                } else {
                    parent.join(&expanded).to_string_lossy().to_string()
                }
            };

            fsutil::check_write(Path::new(&base_pattern))?;

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

/// `~` 與環境變數展開。測試建置可以用 `with_test_home` 把 `~` 指到暫存的家目錄(thread-local):同步引擎的 Include
/// 一律寫成 `~/.ssh/sshelter/...`,測試不能因此讀到開發者真正的家目錄。`config::intel` 展開 `IdentityFile` 的值也用它(插槽路徑同樣是
/// `~/.ssh/sshelter/keys/...`):lint 的測試才能在暫存的家目錄裡放一個只有 `.pub` 的插槽,而不碰真正的 `~/.ssh`。
pub(crate) fn expand_token(token: &str) -> Option<String> {
    #[cfg(test)]
    let home = TEST_HOME.with(|h| h.borrow().clone()).or_else(|| fsutil::home_dir().ok());
    #[cfg(not(test))]
    let home = fsutil::home_dir().ok();
    shellexpand::full_with_context(
        token,
        || home.as_ref().map(|p| p.to_string_lossy()),
        |name| std::env::var(name).map(Some),
    ).ok().map(|s| s.into_owned())
}

pub(crate) fn validate_doc_write_boundaries(doc: &SshConfigDoc) -> Result<(), AppError> {
    for file in &doc.files {
        fsutil::check_write(&file.path)?;
        let parent = file.path.parent().ok_or_else(|| AppError::Other("config has no parent directory".into()))?;
        validate_include_boundaries(&file.items, parent)?;
    }
    Ok(())
}

/// Editable legacy documents cannot retain an Include that escapes the development profile.
/// Validate nested directives as well, even when the legacy loader does not follow their scope.
fn validate_include_boundaries(items: &[Item], parent: &Path) -> Result<(), AppError> {
    if !fsutil::writes_are_confined() {
        return Ok(());
    }
    for item in items {
        match item {
            Item::Directive(d) if d.key == "include" && !d.serializes_as_comment() => {
                for token in d.value.split_whitespace() {
                    if token.contains(['\'', '"', '%']) || (token.starts_with('~') && token != "~" && !token.starts_with("~/")) {
                        return Err(AppError::Other("unsupported Include path in the development profile".into()));
                    }
                    let expanded = expand_token(token).ok_or_else(|| AppError::Other("cannot expand Include path in the development profile".into()))?;
                    let path = Path::new(&expanded);
                    let pattern = if path.is_absolute() { path.to_path_buf() } else { parent.join(path) };
                    fsutil::check_write(&pattern)?;
                    // A wildcard directory may resolve outside even when its final file glob is empty.
                    for prefix in pattern.ancestors() {
                        if prefix != pattern && !prefix.to_string_lossy().contains(['*', '?', '[']) {
                            break;
                        }
                        let entries = glob::glob(&prefix.to_string_lossy()).map_err(|_| AppError::Other("invalid Include pattern in the development profile".into()))?;
                        for entry in entries {
                            let path = entry.map_err(|e| AppError::Other(format!("cannot check Include path: {e}")))?;
                            fsutil::check_write(&path)?;
                        }
                    }
                }
            }
            Item::Host(h) => validate_include_boundaries(&h.body, parent)?,
            Item::Match(m) => validate_include_boundaries(&m.body, parent)?,
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static TEST_HOME: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// 只給測試:在 `f` 執行期間,這個執行緒載入 config 時 `~` 指向 `home`。離開時(包括 `f` panic)一律還原成原本的值。
#[cfg(test)]
pub(crate) fn with_test_home<T>(home: &Path, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<PathBuf>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_HOME.with(|h| *h.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(TEST_HOME.with(|h| h.replace(Some(home.to_path_buf()))));
    f()
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
    #[cfg(unix)]
    #[test]
    fn boundary_unmatched_include_checks_redirected_wildcard_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("linked")).unwrap();
        let main = root.join("config");
        std::fs::write(&main, "Include link*/*.config\n").unwrap();
        fsutil::with_test_write_policy(crate::write_policy::WritePolicy::Confined { root }, || {
            assert!(load_doc(&main).is_err());
        });
        assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
    }

    #[test]
    fn boundary_legacy_loader_rejects_external_main_and_include_forms() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        std::fs::create_dir(&root).unwrap();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, "Host external\n").unwrap();
        let main = root.join("config");
        let policy = crate::write_policy::WritePolicy::Confined { root: root.clone() };
        fsutil::with_test_write_policy(policy.clone(), || assert!(load_doc(&outside).is_err()));
        for token in [outside.display().to_string(), "../outside".into(), "${HOME}/.ssh/config".into(), "~/outside".into(), format!("{}/*", temp.path().join("missing").display())] {
            std::fs::write(&main, format!("Include {token}\nHost local\n")).unwrap();
            with_test_home(temp.path(), || fsutil::with_test_write_policy(policy.clone(), || {
                assert!(load_doc(&main).is_err(), "external token accepted: {token}");
            }));
        }
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "Host external\n");
    }

    #[cfg(unix)]
    #[test]
    fn boundary_legacy_loader_rejects_redirected_and_dangling_includes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        std::fs::create_dir(&root).unwrap();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, "Host external\n").unwrap();
        for (name, target) in [("linked", outside), ("dangling", temp.path().join("missing"))] {
            std::os::unix::fs::symlink(target, root.join(name)).unwrap();
            let main = root.join("config");
            std::fs::write(&main, format!("Include {name}\n")).unwrap();
            fsutil::with_test_write_policy(crate::write_policy::WritePolicy::Confined { root: root.clone() }, || {
                assert!(load_doc(&main).is_err(), "redirected token accepted: {name}");
            });
        }
    }


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

    /// SSHelter 自己產生的 agent 設定(金鑰保管庫 spec §6)不是使用者的 config:`Include` 它的 token 不讀,同一行的其他路徑與其他 Include 照讀。
    /// 讀進來的話,它列的主機會在主機清單裡出現兩次,主機頁也可能打開到產生的那份。
    #[test]
    fn the_generated_agent_config_is_never_loaded() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(ssh.join("sshelter/agent")).unwrap();
        std::fs::write(ssh.join("sshelter/agent/config"), "Host web\n  IdentityAgent ~/.ssh/sshelter/agent/sock\n").unwrap();
        std::fs::write(ssh.join("a.config"), "Host a\n  HostName 10.0.0.1\n").unwrap();
        std::fs::write(ssh.join("b.config"), "Host b\n  HostName 10.0.0.2\n").unwrap();
        std::fs::write(
            ssh.join("config"),
            "Include ~/.ssh/sshelter/agent/config ~/.ssh/a.config\nInclude ~/.ssh/b.config\nHost web\n  HostName 10.0.0.9\n",
        )
        .unwrap();

        let doc = with_test_home(home.path(), || load_doc(&ssh.join("config"))).unwrap();
        let loaded: Vec<PathBuf> = doc.files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(loaded, vec![ssh.join("config"), ssh.join("a.config"), ssh.join("b.config")]);
        assert_eq!(find_host_file_index(&doc, "web"), Some(0), "the host is listed once, from the user's own file");

        // 只是名字像的檔案不是它:照常讀。
        std::fs::write(ssh.join("sshelter/agent/config.bak"), "Host old\n").unwrap();
        std::fs::write(ssh.join("config"), "Include ~/.ssh/sshelter/agent/config.bak\n").unwrap();
        let doc = with_test_home(home.path(), || load_doc(&ssh.join("config"))).unwrap();
        assert_eq!(doc.files.len(), 2);
    }

    #[test]
    fn with_test_home_restores_the_previous_home_even_when_the_closure_panics() {
        let (outer, inner) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let home_of = |dir: &tempfile::TempDir| dir.path().join("x");
        let expanded_home = || expand_token("~/x").map(PathBuf::from);
        assert!(TEST_HOME.with(|h| h.borrow().is_none()));
        with_test_home(outer.path(), || {
            assert_eq!(expanded_home(), Some(home_of(&outer)));
            // 巢狀:離開內層(包括 panic)之後回到外層的家目錄。
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                with_test_home(inner.path(), || {
                    assert_eq!(expanded_home(), Some(home_of(&inner)));
                    panic!("the closure panics");
                })
            }));
            assert!(panicked.is_err());
            assert_eq!(expanded_home(), Some(home_of(&outer)), "the outer home is back after the panic");
        });
        assert!(TEST_HOME.with(|h| h.borrow().is_none()), "and nothing is left over after the outermost call");
    }
}
