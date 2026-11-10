//! The names this app went by before it became Lunport, kept only so that code which finds and
//! retires what an earlier version left behind can name it. Nothing here is a name this version
//! uses; the current names are in `identity`.
//!
//! Old names may appear only in the few places listed in `scripts/identity-guard.mjs`, which CI
//! runs to enforce it. This module is where Rust code keeps them; a frozen protocol constant stays
//! where it is, marked `frozen-identity:`. Anywhere else, read the value from here instead of
//! writing it again.

use crate::app_profile::{AppProfile, CURRENT};

/// The names one build profile used before the rename.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Legacy {
    /// The old bundle identifier, which also named the old data folder.
    pub app_id: &'static str,
    /// The service saved credentials were stored under.
    pub credential_service: &'static str,
    /// The name of the old launch-at-login entry.
    pub login_item: &'static str,
    /// The old key of the Windows uninstall entry and the product's registry values.
    pub installer_identity: &'static str,
    /// The old Windows installer manufacturer (the second part of the old bundle identifier).
    pub manufacturer: &'static str,
    /// The old main executable, without the `.exe` Windows adds.
    pub main_binary: &'static str,
    /// The old console helper next to the main executable on Windows, without its `.exe`.
    pub console_helper: &'static str,
    /// Began every old named-pipe name; the role and the user's hash followed, joined with `-`.
    pub pipe_prefix: &'static str,
    /// The macOS app bundle names this profile had before `Lunport.app` and `Lunport Dev.app`.
    pub bundle_names: [&'static str; 2],
}

pub const PRODUCTION: Legacy = Legacy {
    app_id: "org.homelab.sshelter",
    credential_service: "SSHelter",
    login_item: "SSHelter",
    installer_identity: "SSHelter",
    manufacturer: "homelab",
    main_binary: "sshelter",
    console_helper: "sshelter-cli",
    pipe_prefix: "sshelter",
    bundle_names: ["SSHelter.app", "sshelter.app"],
};

pub const DEVELOPMENT: Legacy = Legacy {
    app_id: "org.homelab.sshelter.dev",
    credential_service: "SSHelter Development",
    login_item: "SSHelter Dev",
    installer_identity: "SSHelter Dev",
    manufacturer: "homelab",
    main_binary: "sshelter",
    console_helper: "sshelter-cli",
    pipe_prefix: "sshelter",
    bundle_names: ["SSHelter Dev.app", "sshelter Dev.app"],
};

/// The old names of `profile`.
pub const fn of(profile: AppProfile) -> &'static Legacy {
    match profile {
        AppProfile::Production => &PRODUCTION,
        AppProfile::Development => &DEVELOPMENT,
    }
}

/// The old names of the profile this build was compiled for.
pub const fn current() -> &'static Legacy {
    of(CURRENT)
}

/// The server name the MCP setup used for the stdio adapter before it was `lunport`.
pub const MCP_ALIAS: &str = "sshelter";

/// The macOS app bundle names from before `Lunport.app` and `Lunport Dev.app`, both profiles.
/// Code that recognizes an MCP client entry that points into an old bundle matches against these;
/// code that moves the bundle of one profile takes that profile's `bundle_names`.
pub const BUNDLE_NAMES: [&str; 4] = [
    PRODUCTION.bundle_names[0],
    PRODUCTION.bundle_names[1],
    DEVELOPMENT.bundle_names[0],
    DEVELOPMENT.bundle_names[1],
];

/// The SHA-1 of the project's macOS code-signing certificate before the rename, in lowercase hex.
pub const CERT_LEAF_SHA1: &str = "a346b47b8dccb4faeac8aec1ea997535809aeec9";

/// The code-signing identifier of the frozen macOS credential helper, protocol version 1.
pub const HELPER_V1_IDENTIFIER: &str = "org.homelab.sshelter.credential-helper.v1";

/// The code directory hashes of the frozen credential helper v1, in lowercase hex: arm64, then
/// x86_64.
pub const HELPER_V1_CDHASHES: [&str; 2] = [
    "b81014e67d632acee792ce51572884d585544241",
    "dd91d3bea5c08b4e639fb3b0944fdb43520b2127",
];

/// The SHA-256 of the frozen credential helper v1's universal binary, in lowercase hex: the bytes a
/// Production build embeds so that the credential migration can install helper v1 where it is missing.
pub const HELPER_V1_SHA256: &str = "6d74a63293b153fccae754e1c4d38449e5cc26065738fae7d0cfc64dcddf2178";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_and_development_values() {
        assert_eq!(
            PRODUCTION,
            Legacy {
                app_id: "org.homelab.sshelter",
                credential_service: "SSHelter",
                login_item: "SSHelter",
                installer_identity: "SSHelter",
                manufacturer: "homelab",
                main_binary: "sshelter",
                console_helper: "sshelter-cli",
                pipe_prefix: "sshelter",
                bundle_names: ["SSHelter.app", "sshelter.app"],
            }
        );
        assert_eq!(
            DEVELOPMENT,
            Legacy {
                app_id: "org.homelab.sshelter.dev",
                credential_service: "SSHelter Development",
                login_item: "SSHelter Dev",
                installer_identity: "SSHelter Dev",
                manufacturer: "homelab",
                main_binary: "sshelter",
                console_helper: "sshelter-cli",
                pipe_prefix: "sshelter",
                bundle_names: ["SSHelter Dev.app", "sshelter Dev.app"],
            }
        );
    }

    #[test]
    fn each_profile_has_its_own_old_names() {
        assert_eq!(of(AppProfile::Production), &PRODUCTION);
        assert_eq!(of(AppProfile::Development), &DEVELOPMENT);
        assert_eq!(current(), of(CURRENT));
    }

    #[test]
    fn names_that_are_not_per_profile() {
        assert_eq!(MCP_ALIAS, "sshelter");
        assert_eq!(
            BUNDLE_NAMES,
            [
                "SSHelter.app",
                "sshelter.app",
                "SSHelter Dev.app",
                "sshelter Dev.app"
            ]
        );
        // Both profiles' bundle names, and nothing else.
        let per_profile: Vec<&str> = [PRODUCTION, DEVELOPMENT].iter().flat_map(|legacy| legacy.bundle_names).collect();
        assert_eq!(per_profile, BUNDLE_NAMES);
    }

    #[test]
    fn the_old_helper_and_certificate_values() {
        assert_eq!(CERT_LEAF_SHA1, "a346b47b8dccb4faeac8aec1ea997535809aeec9");
        assert_eq!(
            HELPER_V1_IDENTIFIER,
            "org.homelab.sshelter.credential-helper.v1"
        );
        assert_eq!(
            HELPER_V1_CDHASHES,
            [
                "b81014e67d632acee792ce51572884d585544241",
                "dd91d3bea5c08b4e639fb3b0944fdb43520b2127"
            ]
        );
        assert_eq!(HELPER_V1_SHA256, "6d74a63293b153fccae754e1c4d38449e5cc26065738fae7d0cfc64dcddf2178");
        assert!(HELPER_V1_SHA256.len() == 64 && HELPER_V1_SHA256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        for digest in std::iter::once(CERT_LEAF_SHA1).chain(HELPER_V1_CDHASHES) {
            assert!(
                digest.len() == 40
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{digest} is not 40 lowercase hex digits"
            );
        }
    }

    /// The frozen helper v1 is what these values describe: its bytes, manifest and source say the same.
    #[test]
    fn the_helper_values_agree_with_the_frozen_helper() {
        use sha2::{Digest, Sha256};
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../signing/legacy/credential-helper-v1.json")).unwrap();
        assert_eq!(manifest["protocol"], 1);
        assert_eq!(manifest["identifier"], HELPER_V1_IDENTIFIER);
        assert_eq!(manifest["cdhashes"]["arm64"], HELPER_V1_CDHASHES[0]);
        assert_eq!(manifest["cdhashes"]["x86_64"], HELPER_V1_CDHASHES[1]);
        assert_eq!(manifest["artifact_sha256"], HELPER_V1_SHA256);
        let bytes = include_bytes!("../signing/legacy/credential-helper-v1.bin");
        let digest: String = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(digest, HELPER_V1_SHA256);

        let source = include_str!("../signing/legacy/credential-helper-v1.c");
        assert!(source.contains(&format!(
            "identifier \\\"{}\\\" and certificate leaf = H\\\"{}\\\"",
            PRODUCTION.app_id, CERT_LEAF_SHA1
        )));
        assert!(source.contains(&format!(
            "LUNPORT_CREDENTIAL_SERVICE \"{}\"",
            PRODUCTION.credential_service
        )));
    }
}
