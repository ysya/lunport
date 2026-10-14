use super::*;
use std::path::{Path, PathBuf};

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    source: PathBuf,
}
impl Fixture {
    fn new(text: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let source = home.join(".ssh/config");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, text).unwrap();
        Self {
            _dir: dir,
            home,
            source,
        }
    }
    fn options(&self) -> ImportOptions {
        ImportOptions::new(self.home.clone())
    }
    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.home.join(".ssh").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }
}

#[test]
fn explicit_home_relative_globs_and_quoted_includes_are_loaded_in_lexical_order_without_writes() {
    let original = r#"Include conf/*.cfg "with spaces.cfg"
Host local
"#;
    let f = Fixture::new(&original);
    f.file("conf/b.cfg", "Host b\n");
    f.file("conf/a.cfg", "Host a\n");
    f.file("with spaces.cfg", "Host spaced\n");
    let snapshot = source::load(&f.source, &f.options()).unwrap();
    assert_eq!(snapshot.files.len(), 4);
    assert_eq!(snapshot.files[1].path.file_name().unwrap(), "a.cfg");
    assert_eq!(snapshot.files[2].path.file_name().unwrap(), "b.cfg");
    assert_eq!(std::fs::read_to_string(&f.source).unwrap(), original);
    assert!(!f.home.join("sync-state.json").exists());
    assert!(!f.home.join("vault.json").exists());
}

#[test]
fn include_cycles_and_depth_seventeen_are_errors_with_locations() {
    let f = Fixture::new("Include child\n");
    f.file("child", "Include config\n");
    assert!(
        matches!(source::load(&f.source,&f.options()),Err(ImportError::Cycle{location}) if location.line==1)
    );
    let f = Fixture::new("Include d1\n");
    for i in 1..=17 {
        f.file(&format!("d{i}"), &format!("Include d{}\n", i + 1));
    }
    f.file("d18", "Host final\n");
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Limit { limit: "depth", .. })
    ));
}

#[test]
fn source_file_count_and_capped_byte_limits_are_enforced() {
    let f = Fixture::new("Include many/*\n");
    for i in 0..128 {
        f.file(&format!("many/{i:03}"), "# fixture\n");
    }
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Limit { limit: "files", .. })
    ));
    let f = Fixture::new(&"#".repeat(MAX_FILE_BYTES + 1));
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Limit {
            limit: "file bytes",
            ..
        })
    ));
    let f = Fixture::new("Include big*\n");
    for i in 0..4 {
        f.file(&format!("big{i}"), &"#".repeat(MAX_FILE_BYTES));
    }
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Limit {
            limit: "total bytes",
            ..
        })
    ));
}

#[test]
fn environment_values_are_injected_and_managed_sources_are_excluded() {
    let f = Fixture::new("Include ${CONFIG_CHILD}\nInclude managed\nHost local\n");
    let child = f.file("child", "Host child\n");
    let managed = f.file("managed", "Host synced\n");
    let mut options = f.options();
    options
        .env
        .insert("CONFIG_CHILD".into(), child.to_string_lossy().into_owned());
    options.excluded_sources.insert(managed);
    let snapshot = source::load(&f.source, &options).unwrap();
    assert_eq!(snapshot.files.len(), 2);
    assert_eq!(snapshot.files[1].path, child);
    let f = Fixture::new("Include ${UNSET_EXPLICIT_VAR}\nHost local\n");
    let snapshot = source::load(&f.source, &f.options()).unwrap();
    assert!(snapshot.events[0]
        .issue
        .as_ref()
        .is_some_and(|(_, blocks)| *blocks));
}

#[cfg(unix)]
#[test]
fn symlinks_are_deduplicated_and_symlink_cycles_cannot_bypass_the_stack() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new("Include child alias\n");
    let child = f.file("child", "Host child\n");
    symlink(&child, f.home.join(".ssh/alias")).unwrap();
    let snapshot = source::load(&f.source, &f.options()).unwrap();
    assert_eq!(snapshot.files.len(), 2);
    let f = Fixture::new("Include alias\n");
    symlink(&f.source, f.home.join(".ssh/alias")).unwrap();
    assert!(matches!(
        source::load(&f.source, &f.options()),
        Err(ImportError::Cycle { .. })
    ));
}

#[test]
fn private_key_sources_are_rejected_without_exposing_contents() {
    let marker = concat!(
        "-----BEGIN ",
        "OPENSSH",
        " PRIVATE KEY-----\n",
        "sensitive-fixture-body"
    );
    let f = Fixture::new(marker);
    let error = source::load(&f.source, &f.options())
        .err()
        .expect("private material rejected");
    assert!(matches!(error, ImportError::PrivateKeyContent { .. }));
    assert!(!format!("{error:?}").contains("sensitive-fixture-body"));
}
