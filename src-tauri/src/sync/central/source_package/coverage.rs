//! Exact captured path coverage before deriving a structured migration candidate.
//! Archival remains lossless even for unsupported inputs; archival is not semantic admission.
use super::*;
use std::collections::BTreeSet;

impl Package {
    /// Each accepted role has a strict semantic reader in record_inputs/materials. Other trees,
    /// including old encrypted archives and empty unknown import directories, remain blockers.
    pub(super) fn require_own_supported_files(&self) -> Result<(), AppError> {
        self.files.validate_archive()?;
        let imports = crate::sync::record_import::inventory::read_all(
            &self.state,
            &self.files.bytes,
            &self.decryptors,
        )?;
        let migrations =
            crate::sync::record_migration::inventory::read_all(&self.state, &self.files.bytes)?;
        let recovery = super::super::replacement_archive::captured::read_all(
            &self.files.bytes,
            &self.decryptors,
        )?;
        let sources = super::super::source_archive::captured::read_all(&self.files.bytes, &self.decryptors)?;
        let mut directories: BTreeSet<_> = [
            "data",
            "keys",
            "data/imports",
            "data/migrations",
            "data/central-recovery-archives",
            "data/central-source-archives",
        ]
        .into_iter()
        .map(std::path::PathBuf::from)
        .collect();
        for file in imports.admitted.iter().chain(&migrations.admitted) {
            let mut parent = file.parent();
            while let Some(path) = parent {
                directories.insert(path.to_path_buf());
                parent = path.parent();
            }
        }
        for directory in &self.files.directories {
            if !directories.contains(directory) && !directory.starts_with("keys") {
                return Err(unsupported());
            }
        }
        for file in self.files.bytes.keys() {
            if imports.admitted.contains(file)
                || migrations.admitted.contains(file)
                || recovery.admitted.contains(file)
                || sources.admitted.contains(file)
                || file.starts_with("keys")
            {
                continue;
            }
            let name = file
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(invalid)?;
            if file.parent() == Some(Path::new("data"))
                && (name == self.state_name
                    || name.starts_with("sync-state")
                    || self.state.legacy_v1_backup.as_deref() == Some(name)
                    || name.starts_with("vault"))
            {
                continue;
            }
            return Err(unsupported());
        }
        Ok(())
    }
}
fn unsupported() -> AppError {
    AppError::Other("A captured recovery or migration source needs supported normalization before central synchronization. Every original file is retained.".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn opaque_archives_pending_migrations_and_empty_unknown_directories_cannot_be_omitted() {
        for (path, directory) in [
            ("central-source-archives/old.lpsource", false),
            ("central-recovery-archives/old.lparch", false),
            ("migrations/old/journal.json", false),
            ("migrations/empty", true),
            ("imports/empty", true),
        ] {
            let (device, mut package, keys, owner, _) = super::super::tests::fixture();
            let env = device.env();
            let absolute = env.state_path.parent().unwrap().join(path);
            if directory {
                fs::create_dir_all(&absolute).unwrap();
            } else {
                fs::create_dir_all(absolute.parent().unwrap()).unwrap();
                fs::write(&absolute, b"unique retained source").unwrap();
            }
            package.files = Files::capture(&env, None).unwrap();
            let before = package.encode_local().unwrap();
            assert!(
                package.materials(&keys, &BTreeMap::new()).is_err(),
                "{path}"
            );
            assert!(
                package.structured_history(&keys, &BTreeMap::new()).is_err(),
                "{path}"
            );
            assert_eq!(
                package.encode_local().unwrap().as_slice(),
                before.as_slice()
            );
            // Archiving may preserve unsupported input, but cannot turn it into a plan. An
            // unknown entry in the destination archive directory also blocks creation there.
            let life = env.runtime.lifecycle.lock().unwrap();
            if path.starts_with("central-source-archives/") {
                assert!(package.archive(&env, &life, &owner, 0).is_err());
                assert_eq!(fs::read(&absolute).unwrap(), b"unique retained source");
                continue;
            }
            let archive = package.archive(&env, &life, &owner, 0).unwrap();
            let restored = Package::restore(
                &env,
                &owner.control.profile.profile().unwrap(),
                archive.receipt(),
            )
            .unwrap();
            assert_eq!(
                restored.encode_local().unwrap().as_slice(),
                before.as_slice()
            );
            assert!(restored.materials(&keys, &BTreeMap::new()).is_err());
            if !directory {
                assert_eq!(fs::read(&absolute).unwrap(), b"unique retained source");
            }
        }
    }

    #[test]
    fn known_empty_roots_and_managed_key_directories_preserve_complete_coverage() {
        let (device, mut package, keys, _, _) = super::super::tests::fixture();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        for path in [
            "imports",
            "migrations",
            "central-source-archives",
            "central-recovery-archives",
        ] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::create_dir_all(env.ssh_dir.join("sshelter/keys/empty")).unwrap();
        package.files = Files::capture(&env, None).unwrap();
        package.require_supported_files().unwrap();
        package.materials(&keys, &BTreeMap::new()).unwrap();
    }
}
