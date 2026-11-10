//! Build-selected names and pure paths shared by the app and its thin clients. The name values
//! themselves are in `identity`.

use std::path::{Path, PathBuf};

use crate::identity::{self, Identity};

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
    /// Checks that the Tauri configuration this build embeds belongs to the profile it was compiled
    /// for. The error names every value that disagrees.
    ///
    /// Only values that `tauri::generate_context!` keeps in the embedded configuration can be checked
    /// here. It leaves out `bundle.publisher` (and most of the rest of `bundle`), so a build cannot read
    /// the publisher when it starts; the tests compare it in both configuration files with `identity`
    /// instead (`tauri_configs_match_identity`).
    pub fn verify_configuration(
        self,
        identifier: &str,
        product_name: Option<&str>,
        main_binary: Option<&str>,
    ) -> Result<(), String> {
        let expected = self.identity();
        let disagreeing: Vec<&str> = [
            ("identifier", identifier == expected.app_id),
            ("productName", product_name == Some(expected.product_name)),
            ("mainBinaryName", main_binary == Some(expected.main_binary)),
        ]
        .into_iter()
        .filter(|&(_, agrees)| !agrees)
        .map(|(name, _)| name)
        .collect();
        if disagreeing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "build profile and Tauri configuration disagree on {}; use tauri:dev or tauri:build:dev for Development",
                disagreeing.join(", ")
            ))
        }
    }

    /// `verify_configuration` on Tauri's parsed configuration: the one place that picks the checked fields out of it, for the startup
    /// check (on what the binary embeds) and for the tests alike. A value the check starts to read is read here, so that
    /// `the_embedded_configuration_passes_the_startup_check` runs it on the embedded configuration.
    pub(crate) fn verify_tauri_config(self, config: &tauri::utils::config::Config) -> Result<(), String> {
        self.verify_configuration(
            &config.identifier,
            config.product_name.as_deref(),
            config.main_binary_name.as_deref(),
        )
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

    /// The identity values of this profile.
    pub const fn identity(self) -> &'static Identity {
        match self {
            Self::Production => &identity::PRODUCTION,
            Self::Development => &identity::DEVELOPMENT,
        }
    }

    pub const fn identifier(self) -> &'static str {
        self.identity().app_id
    }

    pub const fn product_name(self) -> &'static str {
        self.identity().product_name
    }

    /// The service saved credentials are stored under.
    pub const fn keychain_service(self) -> &'static str {
        self.identity().credential_service
    }

    /// The name of the launch-at-login entry.
    pub const fn autostart_name(self) -> &'static str {
        self.identity().login_item
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
    use crate::identity;

    #[test]
    fn development_is_selected_for_debug_or_the_explicit_feature() {
        assert_eq!(AppProfile::for_build(false, false), AppProfile::Production);
        assert_eq!(AppProfile::for_build(true, false), AppProfile::Development);
        assert_eq!(AppProfile::for_build(false, true), AppProfile::Development);
        assert_eq!(AppProfile::for_build(true, true), AppProfile::Development);
    }

    #[test]
    fn each_profile_reads_its_names_from_its_identity() {
        for (profile, identity) in [
            (AppProfile::Production, &identity::PRODUCTION),
            (AppProfile::Development, &identity::DEVELOPMENT),
        ] {
            assert_eq!(profile.identity(), identity);
            assert_eq!(profile.identifier(), identity.app_id);
            assert_eq!(profile.product_name(), identity.product_name);
            assert_eq!(profile.keychain_service(), identity.credential_service);
            assert_eq!(profile.autostart_name(), identity.login_item);
        }
        assert_eq!(identity::current(), CURRENT.identity());
    }

    #[test]
    fn development_has_distinct_services_and_both_pipe_roles() {
        let prod = AppProfile::Production;
        let dev = AppProfile::Development;
        assert_ne!(prod.identifier(), dev.identifier());
        assert_ne!(prod.product_name(), dev.product_name());
        assert_ne!(prod.keychain_service(), dev.keychain_service());
        assert_ne!(prod.autostart_name(), dev.autostart_name());
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
        assert_eq!(prod.data(), local.join(identity::PRODUCTION.app_id));
        assert_eq!(
            prod.backups(),
            roaming.join(identity::PRODUCTION.app_id).join("backups")
        );
        assert_eq!(prod.ssh(), home.join(".ssh"));
        assert_eq!(dev.data(), local.join(identity::DEVELOPMENT.app_id));
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
    use crate::identity;

    /// A Tauri configuration cannot read Rust, so each shipped file repeats the identity values;
    /// this is the check that the copies still agree with the source.
    #[test]
    fn tauri_configs_match_identity() {
        for (profile, identity, source) in [
            (
                AppProfile::Production,
                &identity::PRODUCTION,
                include_str!("../tauri.conf.json"),
            ),
            (
                AppProfile::Development,
                &identity::DEVELOPMENT,
                include_str!("../tauri.dev.conf.json"),
            ),
        ] {
            let config: serde_json::Value = serde_json::from_str(source).unwrap();
            assert_eq!(config["identifier"], identity.app_id);
            assert_eq!(config["productName"], identity.product_name);
            assert_eq!(config["mainBinaryName"], "lunport");
            assert_eq!(config["mainBinaryName"], identity.main_binary);
            // The only check of the publisher: the binary does not embed it, so the startup check cannot read it.
            assert_eq!(config["bundle"]["publisher"], "ysya");
            assert_eq!(config["bundle"]["publisher"], identity.publisher);
            assert_eq!(config["app"]["windows"][0]["title"], identity.product_name);
            // The startup check accepts the file as Tauri parses it. What the binary embeds is another matter
            // (`the_embedded_configuration_passes_the_startup_check`).
            let parsed: tauri::utils::config::Config = serde_json::from_str(source).unwrap();
            profile.verify_tauri_config(&parsed).unwrap();
        }
    }

    /// `tauri::generate_context!` embeds only part of the configuration file: `bundle.publisher` and most of the rest of `bundle` are
    /// left out. A startup check that read the publisher refused every build, Production included, although the files agree with
    /// `identity` (`tauri_configs_match_identity` reads the files). This runs the check on the configuration the binary really embeds.
    ///
    /// A plain test build has the Development profile (debug assertions) but embeds `tauri.conf.json` unmerged, which is Production's;
    /// the profile to check is therefore the one whose identifier the embedded configuration carries, not `CURRENT`.
    #[test]
    fn the_embedded_configuration_passes_the_startup_check() {
        let context = crate::embedded_context();
        let config = context.config();
        assert!(!config.identifier.is_empty(), "Tauri embeds no identifier");
        assert!(config.product_name.is_some(), "Tauri embeds no productName");
        assert!(config.main_binary_name.is_some(), "Tauri embeds no mainBinaryName");
        let profile = [AppProfile::Production, AppProfile::Development]
            .into_iter()
            .find(|profile| profile.identifier() == config.identifier)
            .unwrap_or_else(|| panic!("the embedded identifier {:?} belongs to no profile", config.identifier));
        if let Err(error) = profile.verify_tauri_config(config) {
            panic!("the startup check refuses the embedded configuration of {profile:?}: {error}");
        }
    }

    const FIELDS: [&str; 3] = ["identifier", "productName", "mainBinaryName"];

    /// `profile`'s own values, except the one named by `field`, which takes `value`.
    fn verify_with(profile: AppProfile, field: &str, value: Option<&str>) -> Result<(), String> {
        let own = profile.identity();
        let pick = |name: &str, fallback: &'static str| {
            if name == field {
                value
            } else {
                Some(fallback)
            }
        };
        profile.verify_configuration(
            pick("identifier", own.app_id).unwrap_or(""),
            pick("productName", own.product_name),
            pick("mainBinaryName", own.main_binary),
        )
    }

    #[test]
    fn a_profile_mismatch_is_rejected_before_initialization() {
        for profile in [AppProfile::Production, AppProfile::Development] {
            let own = profile.identity();
            assert_eq!(
                profile.verify_configuration(
                    own.app_id,
                    Some(own.product_name),
                    Some(own.main_binary)
                ),
                Ok(())
            );
            let other = if profile == AppProfile::Production {
                AppProfile::Development.identity()
            } else {
                AppProfile::Production.identity()
            };
            // Each value on its own, wrong, empty or (where the configuration may omit it) missing:
            // the error names that value and no other.
            for (field, wrong) in [
                ("identifier", vec![Some(other.app_id), Some("")]),
                (
                    "productName",
                    vec![Some(other.product_name), Some(""), None],
                ),
                (
                    "mainBinaryName",
                    vec![Some("another-binary"), Some(""), None],
                ),
            ] {
                for value in wrong {
                    let error = verify_with(profile, field, value).unwrap_err();
                    for named in FIELDS {
                        assert_eq!(
                            error.contains(named),
                            named == field,
                            "{field} = {value:?}: {error:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn every_disagreeing_value_is_named_at_once() {
        let error = AppProfile::Production
            .verify_configuration("x", None, None)
            .unwrap_err();
        for field in FIELDS {
            assert!(error.contains(field), "{field} in {error:?}");
        }
    }
}
