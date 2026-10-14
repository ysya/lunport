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
    pub fn verify_configuration(
        self,
        identifier: &str,
        product_name: Option<&str>,
    ) -> Result<(), &'static str> {
        if identifier == self.identifier() && product_name == Some(self.product_name()) {
            Ok(())
        } else {
            Err("build profile and Tauri configuration disagree; use tauri:dev or tauri:build:dev for Development")
        }
    }

    pub const fn allows_os_integrations(self) -> bool {
        matches!(self, Self::Production)
    }

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
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    #[test]
    fn a_profile_mismatch_is_rejected_before_initialization() {
        for profile in [AppProfile::Production, AppProfile::Development] {
            assert!(profile
                .verify_configuration(profile.identifier(), Some(profile.product_name()))
                .is_ok());
            let other = if profile == AppProfile::Production {
                AppProfile::Development
            } else {
                AppProfile::Production
            };
            assert!(profile
                .verify_configuration(other.identifier(), Some(profile.product_name()))
                .is_err());
            assert!(profile
                .verify_configuration(profile.identifier(), Some(other.product_name()))
                .is_err());
            assert!(profile
                .verify_configuration(profile.identifier(), None)
                .is_err());
        }
    }
}
