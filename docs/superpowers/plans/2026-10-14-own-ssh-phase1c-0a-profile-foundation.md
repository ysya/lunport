# Own SSH client, plan 1c-0a: profile and path-policy foundations

> For implementation: use superpowers:executing-plans for native execution, or superpowers:subagent-driven-development if the user chooses it. Self-review this written plan before implementing under the user's standing autonomous-execution authorization.

**Goal:** establish a tested, Tauri-independent profile and filesystem policy for development isolation. This part adds the primitives; it does not yet switch the existing app's storage or claim that the app is isolated.

**Architecture:** AppProfile selects immutable names from build flags; AppPaths computes paths from explicit OS roots; WritePolicy checks an existing or future destination without creating it. Existing app, CLI, host-start, Keychain and IPC callers are wired in the next part, after these contracts are verified.

**Tech stack:** existing Rust std and tempfile; a dependency-free Cargo feature. No new crate and no Cargo.lock change.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md, especially §1 and §4. The user approved the written design with “執行”; the later Brave Sync clarification preserves the local-vault/client-encrypted-chain boundary. The user subsequently authorized autonomous execution and industry-grounded decisions while resting. Native execution is selected for this part; subsequent design and plan gates are satisfied by that standing instruction. Record material deviations in the ledger.

## Global constraints

- Work from next/own-ssh; baseline 8f778cb plus the product-goal documentation update. Inspect status before edits and preserve unrelated changes.
- Product code and comments are English; conventional commits; stage exact paths. No push, main integration, release or real migration in this part.
- Never launch the app. Until all 1c-0 wiring and write-boundary work is complete, the legacy file writers still use their current paths.
- No real ~/.ssh, Keychain, agent or relay access. Tests use temp directories; they never mutate HOME, USERPROFILE or the process environment.
- Run Cargo from src-tauri with --offline --locked locally. Use the installed stable toolchain already used by the project. No dependencies are downloaded.
- Whole-suite tests skip secrets::tests::round_trip_set_get_delete and both askpass::tests::env_secret_takes_priority_over_keychain and askpass::tests::missing_account_and_no_env_yields_none. Keep the existing scratch-sshd cleanup checks for runs that start sshd.
- AppProfile::CURRENT is never special-cased for cfg(test). Integration tests verify the non-test library's actual build selection. Explicit profiles make unit tests independent of the current build.
- WritePolicy is an accidental-write boundary, not protection against a hostile same-user process changing directories between the check and an I/O operation. Callers must check every write, not cache an old decision.
- Dev writes will be confined to the development app-data root; its backups also live there. Production retains its existing roaming-data backup path on Windows.

## Review focus

1. Release without the feature must select Production; debug and release with development-profile must select Development, including an independently started CLI.
2. A development root redirected by a symlink/junction must be rejected, rather than treating its new target as the permitted root.
3. Missing ancestors, dangling symlinks and non-directory ancestors must fail without creating or deleting anything outside the root.
4. Production's current path/name contracts must remain exact, including backups under the roaming-data root.
5. Compiling these primitives is not proof that an existing writer uses them; this part must leave runtime switching to the subsequent wiring plan.

## File map

| File | Responsibility |
|---|---|
| src-tauri/src/app_profile.rs | Build-selected names and pure path construction |
| src-tauri/src/write_policy.rs | Filesystem destination checks; std-only, independent of profile selection |
| src-tauri/src/lib.rs | Export the two modules for the binary and the non-test integration target |
| src-tauri/Cargo.toml | Declare the empty development-profile feature |
| src-tauri/tests/app_profile_build.rs | Verify build-mode selection without launching Tauri |
| .github/workflows/test-engine.yml | Run new unit and integration tests on macOS and Linux |
| .github/workflows/test-windows.yml | Run the same tests on Windows |

### Task 1: profile names, build selection and pure paths

**Interfaces:** produces AppProfile::{for_build,identifier,product_name,keychain_service,pipe_role}, CURRENT, IpcRole, and AppPaths::{from_os_roots,data,backups,home,ssh}. The next wiring plan consumes these exact names.

- [ ] Add `pub mod app_profile;` to lib.rs, create app_profile.rs with this failing test, and run `cargo test --offline --locked --lib -- app_profile::`.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_is_selected_for_debug_or_the_explicit_feature() {
        assert_eq!(AppProfile::for_build(false, false), AppProfile::Production);
        assert_eq!(AppProfile::for_build(true, false), AppProfile::Development);
        assert_eq!(AppProfile::for_build(false, true), AppProfile::Development);
        assert_eq!(AppProfile::for_build(true, true), AppProfile::Development);
    }
}
```

Expected red: missing AppProfile. Do not weaken the test to fit the active build.

- [ ] Add the feature under a new `[features]` section in Cargo.toml:

```toml
[features]
development-profile = []
```

- [ ] Add the following implementation above the test module in app_profile.rs:

```rust
//! Build-selected names and pure paths shared by the app and its thin clients.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppProfile {
    Production,
    Development,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcRole {
    Agent,
    Session,
}

pub const CURRENT: AppProfile = AppProfile::for_build(
    cfg!(debug_assertions),
    cfg!(feature = "development-profile"),
);

impl AppProfile {
    pub const fn for_build(debug: bool, development_feature: bool) -> Self {
        if debug || development_feature {
            Self::Development
        } else {
            Self::Production
        }
    }

    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Production => "org.homelab.sshelter",
            Self::Development => "org.homelab.sshelter.dev",
        }
    }

    pub const fn product_name(self) -> &'static str {
        match self {
            Self::Production => "SSHelter",
            Self::Development => "SSHelter Dev",
        }
    }

    pub const fn keychain_service(self) -> &'static str {
        match self {
            Self::Production => "SSHelter",
            Self::Development => "SSHelter Development",
        }
    }

    pub const fn pipe_role(self, role: IpcRole) -> &'static str {
        match (self, role) {
            (Self::Production, IpcRole::Agent) => "agent",
            (Self::Production, IpcRole::Session) => "session",
            (Self::Development, IpcRole::Agent) => "dev-agent",
            (Self::Development, IpcRole::Session) => "dev-session",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPaths {
    data: PathBuf,
    backups: PathBuf,
    home: PathBuf,
}

impl AppPaths {
    pub fn from_os_roots(
        profile: AppProfile,
        local_data: &Path,
        roaming_data: &Path,
        os_home: &Path,
    ) -> Self {
        let data = local_data.join(profile.identifier());
        let (backups, home) = match profile {
            AppProfile::Production => (
                roaming_data.join(profile.identifier()).join("backups"),
                os_home.to_path_buf(),
            ),
            AppProfile::Development => (data.join("backups"), data.join("sandbox-home")),
        };
        Self {
            data,
            backups,
            home,
        }
    }

    pub fn data(&self) -> &Path {
        &self.data
    }
    pub fn backups(&self) -> &Path {
        &self.backups
    }
    pub fn home(&self) -> &Path {
        &self.home
    }
    pub fn ssh(&self) -> PathBuf {
        self.home.join(".ssh")
    }
}
```

- [ ] Add these tests to the same test module:

```rust
#[test]
fn development_has_distinct_services_and_both_pipe_roles() {
    let prod = AppProfile::Production;
    let dev = AppProfile::Development;
    assert_eq!(prod.identifier(), "org.homelab.sshelter");
    assert_eq!(dev.identifier(), "org.homelab.sshelter.dev");
    assert_eq!(prod.product_name(), "SSHelter");
    assert_eq!(dev.product_name(), "SSHelter Dev");
    assert_eq!(prod.keychain_service(), "SSHelter");
    assert_eq!(dev.keychain_service(), "SSHelter Development");
    assert_eq!(prod.pipe_role(IpcRole::Agent), "agent");
    assert_eq!(prod.pipe_role(IpcRole::Session), "session");
    assert_eq!(dev.pipe_role(IpcRole::Agent), "dev-agent");
    assert_eq!(dev.pipe_role(IpcRole::Session), "dev-session");
}

#[test]
fn development_paths_share_one_root_and_production_keeps_roaming_backups() {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join("Local");
    let roaming = temp.path().join("Roaming");
    let home = temp.path().join("User");
    let prod = AppPaths::from_os_roots(AppProfile::Production, &local, &roaming, &home);
    let dev = AppPaths::from_os_roots(AppProfile::Development, &local, &roaming, &home);
    assert_eq!(prod.data(), local.join("org.homelab.sshelter"));
    assert_eq!(prod.backups(), roaming.join("org.homelab.sshelter/backups"));
    assert_eq!(prod.ssh(), home.join(".ssh"));
    assert_eq!(dev.data(), local.join("org.homelab.sshelter.dev"));
    assert_eq!(dev.backups(), dev.data().join("backups"));
    assert_eq!(dev.home(), dev.data().join("sandbox-home"));
    assert_eq!(dev.ssh(), dev.home().join(".ssh"));
    assert!(!local.exists(), "computing paths must not create them");
    assert!(!roaming.exists());
    assert!(!home.exists());
}
```

- [ ] Run `cargo test --offline --locked --lib -- app_profile::` and `cargo metadata --offline --locked --format-version 1`. Require green and an unchanged Cargo.lock.
- [ ] Commit exactly app_profile.rs, lib.rs and Cargo.toml with `feat(profile): define development profile names and paths`.

### Task 2: a destination policy that does not create paths

**Interfaces:** consumes only std paths. Produces WritePolicy::{Unrestricted,Confined} and check(&self, &Path) -> io::Result<()>. Wiring maps PermissionDenied to the existing AppError::ForbiddenPath; other I/O errors retain their cause.

- [ ] Add `pub mod write_policy;` to lib.rs. Create write_policy.rs with the failing tests shown below, then run `cargo test --offline --locked --lib -- write_policy::`.
- [ ] Add this implementation above the test module:

```rust
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
```

- [ ] Use this test module in write_policy.rs:

```rust
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
```

- [ ] Run `cargo test --offline --locked --lib -- write_policy::`. Require every case to pass. Windows root-redirection and caller-level tests belong to the wiring part; no platform-wide isolation claim is made here.
- [ ] Commit write_policy.rs and lib.rs with `feat(profile): add development destination checks`.

### Task 3: verify the actual library build selection

**Interfaces:** consumes app_profile::{CURRENT, AppProfile}. The integration target links the normal library, so cfg(test) cannot conceal a different build profile.

- [ ] Create src-tauri/tests/app_profile_build.rs:

```rust
use sshelter_lib::app_profile::{AppProfile, CURRENT};

#[test]
fn the_normal_library_selects_the_profile_from_this_build() {
    let expected = if cfg!(debug_assertions) || cfg!(feature = "development-profile") {
        AppProfile::Development
    } else {
        AppProfile::Production
    };
    assert_eq!(CURRENT, expected);
}
```

- [ ] Run the three commands below. None launches the app or queries real credentials:

```sh
cargo test --offline --locked --test app_profile_build
cargo test --offline --locked --release --test app_profile_build
cargo test --offline --locked --release --features development-profile --test app_profile_build
```

Expected: one passing test in each build; release alone is Production, release with the feature is Development. Preserve the normal library's configuration; do not make cfg(test) override CURRENT.

- [ ] Commit the integration test with `test(profile): verify debug and release build selection`.

### Task 4: make CI run the new contracts and finish the part

**Interfaces:** consumes app_profile::, write_policy:: and the app_profile_build test target. Existing engine and Windows tests remain in their current filters.

- [ ] In test-engine.yml, replace the macOS test command with:

```yaml
        run: "cargo test --locked --lib -- app_profile:: write_policy:: ssh:: session:: cli:: host_start:: vault::"
```

Replace the Linux scratch-sshd command with:

```yaml
        run: "cargo test --locked --lib -- app_profile:: write_policy:: ssh:: session:: cli:: host_start:: vault:: --skip ssh::engine_tests::login_methods::pam"
```

- [ ] Add this step to both jobs after their scratch-sshd tests (before Linux's PAM-specific test is suitable):

```yaml
      - name: Profile selection in the normal library
        if: ${{ !cancelled() }}
        run: cargo test --locked --test app_profile_build
```

- [ ] In test-windows.yml, keep every existing filter and add app_profile:: and write_policy:: to the Rust unit-test command. The final command is:

```yaml
        run: "cargo test --locked --lib -- app_profile:: write_policy:: sync::slot_rules sync::slot_files vault:: ipc:: agent:: ssh:: session:: cli:: connect::"
```

Add this step after that test command, before building the whole app:

```yaml
      - name: Profile selection in the normal library
        run: cargo test --locked --test app_profile_build
```

- [ ] Locally run the profile/policy tests, all three build-selection commands, and the whole existing lib suite with the three credential-store skips:

```sh
cargo test --offline --locked --lib -- app_profile:: write_policy::
cargo test --offline --locked --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none
```

The first three tasks each supply focused tests; this whole-suite run is the regression gate after the new modules and Cargo feature are in place.

- [ ] Run `git diff --check`; inspect Cargo.lock and generated bindings. Require no lock-file change and no unexpected binding change.
- [ ] Review the patch for runtime scope: changes are new helpers, exports, the Cargo feature, tests and CI filters. fsutil::app_data_root, secrets::SERVICE, keys::ssh_dir, pipe_name wrappers, config loaders and app startup must still be untouched.
- [ ] Commit the workflow changes with `ci(profile): run profile and path-policy tests`.
- [ ] Report local results separately from CI. This part does not authorize pushing to obtain CI; if a push is later authorized, verify the pushed head matches each successful run.

## Completion and next interface boundary

1c-0a is complete when its contracts and local regression checks pass. It is not the complete 1c-0 isolation milestone.
The next wiring plan must use these primitives to replace every current root/service/pipe caller, reject external config and Include paths before legacy writes, guard direct rename/remove/export operations, check Tauri/profile consistency before initialization, disable dev updater/autostart, and prove the normal compiled callers enforce the policy on all three platforms.
Only after that wiring gate is passed may a development app be launched against sandbox data. No migration or schema bump is part of this plan.

## Execution handoff

Recommended method: native execution in this chat. The two focused primitives and one integration test share small interfaces; implementing them in order gives a concrete base for the more extensive wiring review.
Alternative: subagent-driven execution with a separate implementer/reviewer for each task. The user has authorized autonomous continuation; execute natively and record decisions in the ledger.
