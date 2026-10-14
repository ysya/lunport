//! Destination checks for accidental development-profile writes.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub enum WritePolicy {
    Unrestricted,
    Confined { root: PathBuf },
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "destination is outside the development data root",
    )
}

fn clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
}

// Resolve existing ancestors, then append only missing normal components. Never create them.
fn projected(path: &Path) -> io::Result<PathBuf> {
    let mut at = path.to_path_buf();
    let mut missing: Vec<OsString> = Vec::new();
    loop {
        match std::fs::canonicalize(&at) {
            Ok(mut resolved) => {
                // Windows can report a child of a regular file as NotFound.
                // Missing suffixes may only be projected below a directory.
                if !missing.is_empty() && !std::fs::metadata(&at)?.is_dir() {
                    return Err(denied());
                }
                for part in missing.iter().rev() {
                    resolved.push(part);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(&at) {
                    // A dangling link is not a missing normal component.
                    Ok(_) => return Err(denied()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                missing.push(at.file_name().ok_or_else(denied)?.to_os_string());
                if !at.pop() {
                    return Err(denied());
                }
            }
            Err(error) => return Err(error),
        }
    }
}

impl WritePolicy {
    pub fn check(&self, path: &Path) -> io::Result<()> {
        let Self::Confined { root } = self else {
            return Ok(());
        };
        if !clean_absolute(root) || !clean_absolute(path) {
            return Err(denied());
        }
        let parent = root.parent().ok_or_else(denied)?;
        let expected = projected(parent)?.join(root.file_name().ok_or_else(denied)?);
        // A link/junction at the root must not redefine the permitted directory.
        if projected(root)? != expected {
            return Err(denied());
        }
        let destination = projected(path)?;
        if destination == expected || destination.starts_with(&expected) {
            Ok(())
        } else {
            Err(denied())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_future_nested_destination_is_allowed_without_creating_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        let policy = WritePolicy::Confined { root: root.clone() };
        policy
            .check(&root.join("sandbox-home/.ssh/sshelter/keys/new"))
            .unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn a_sibling_with_the_same_prefix_is_not_changed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        let outside = temp.path().join("dev-other");
        std::fs::write(&outside, b"keep").unwrap();
        let policy = WritePolicy::Confined { root };
        let result = policy
            .check(&outside)
            .and_then(|()| std::fs::write(&outside, b"changed"));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    }

    #[test]
    fn relative_and_parent_component_paths_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        let policy = WritePolicy::Confined { root: root.clone() };
        assert!(policy.check(Path::new("relative")).is_err());
        assert!(policy.check(&root.join("../outside")).is_err());
    }

    #[test]
    fn a_regular_file_cannot_be_a_destination_parent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("file");
        std::fs::write(&file, b"keep").unwrap();
        let policy = WritePolicy::Confined { root };
        assert!(policy.check(&file.join("child")).is_err());
        assert!(policy.check(&file.join("child/nested")).is_err());
        assert_eq!(std::fs::read(file).unwrap(), b"keep");
    }

    #[test]
    fn production_policy_does_not_restrict_a_destination() {
        WritePolicy::Unrestricted
            .check(Path::new("relative"))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_link_at_the_root_cannot_redefine_the_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let root = temp.path().join("dev");
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        let policy = WritePolicy::Confined { root: root.clone() };
        assert!(policy.check(&root.join("new")).is_err());
        assert!(!outside.join("new").exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_internal_link_outside_the_root_and_a_dangling_link_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("dev");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        std::os::unix::fs::symlink(temp.path().join("missing"), root.join("dangling")).unwrap();
        let policy = WritePolicy::Confined { root: root.clone() };
        assert!(policy.check(&root.join("link/new")).is_err());
        assert!(policy.check(&root.join("dangling/new")).is_err());
        assert!(!outside.join("new").exists());
        assert!(!temp.path().join("missing").exists());
    }
}
