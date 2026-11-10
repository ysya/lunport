//! The one place this app's own identity values are written down: the names the operating system
//! sees (application id, credential service, login item, installer entry, executables, pipes and
//! threads). Code reads them from here instead of repeating them.
//!
//! A Tauri configuration file cannot read Rust, so `tauri.conf.json` and `tauri.dev.conf.json`
//! repeat the identifier, product name, main binary name and publisher.
//! `AppProfile::verify_configuration` refuses to start a build whose embedded configuration
//! disagrees with the profile it was compiled for on the identifier, product name or main binary
//! name. Tauri does not embed the publisher, so only the configuration tests check that; they
//! compare all the shipped values with these.
//!
//! Names used before the Lunport rename live only in `legacy_identity`.

use crate::app_profile;

/// The names one build profile uses toward the operating system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Tauri `identifier`: the bundle identifier, which also names the data folder.
    pub app_id: &'static str,
    /// Tauri `productName`: the name people see.
    pub product_name: &'static str,
    /// The service saved credentials are stored under in the operating system's credential store.
    pub credential_service: &'static str,
    /// The name of the launch-at-login entry.
    pub login_item: &'static str,
    /// The Windows installers' key for the uninstall entry and the product's registry values.
    pub installer_identity: &'static str,
    /// Tauri `bundle.publisher`: the publisher (the installers' manufacturer).
    pub publisher: &'static str,
    /// Tauri `mainBinaryName`: the main executable, without the `.exe` Windows adds.
    pub main_binary: &'static str,
    /// The console helper Windows installs next to the main executable, without its `.exe`.
    pub console_helper: &'static str,
    /// Starts every named-pipe name; the role and the user's hash follow, joined with `-`.
    pub pipe_prefix: &'static str,
    /// Starts every thread name; the thread's purpose follows, joined with `-`.
    pub thread_prefix: &'static str,
}

// What both profiles have in common: they differ in where they keep data and credentials,
// never in who publishes them or what the program is called.
const PUBLISHER: &str = "ysya";
const MAIN_BINARY: &str = "lunport";
const CONSOLE_HELPER: &str = "lunport-cli";
const PIPE_PREFIX: &str = "lunport";
const THREAD_PREFIX: &str = "lunport";

pub const PRODUCTION: Identity = Identity {
    app_id: "dev.ysya.lunport",
    product_name: "Lunport",
    credential_service: "Lunport",
    login_item: "Lunport",
    installer_identity: "Lunport",
    publisher: PUBLISHER,
    main_binary: MAIN_BINARY,
    console_helper: CONSOLE_HELPER,
    pipe_prefix: PIPE_PREFIX,
    thread_prefix: THREAD_PREFIX,
};

/// The Development profile runs beside Production, so everything that holds state has a name of
/// its own.
pub const DEVELOPMENT: Identity = Identity {
    app_id: "dev.ysya.lunport.dev",
    product_name: "Lunport Dev",
    credential_service: "Lunport Development",
    login_item: "Lunport Dev",
    installer_identity: "Lunport Dev",
    publisher: PUBLISHER,
    main_binary: MAIN_BINARY,
    console_helper: CONSOLE_HELPER,
    pipe_prefix: PIPE_PREFIX,
    thread_prefix: THREAD_PREFIX,
};

/// The identity of the profile this build was compiled for.
pub const fn current() -> &'static Identity {
    app_profile::CURRENT.identity()
}

/// The name of the thread (or of a runtime's worker threads) that does `purpose`: the thread prefix of this build's identity, a
/// dash, and the purpose.
pub fn thread_name(purpose: &str) -> String {
    format!("{}-{purpose}", current().thread_prefix)
}

/// The code-signing identifier of the macOS credential helper, protocol version 2.
pub const HELPER_V2_IDENTIFIER: &str = "dev.ysya.lunport.credential-helper.v2";

/// The SHA-256 of the frozen credential helper v2's universal binary, in lowercase hex, as its manifest
/// `signing/credential-helper-v2.json` records it. A Production build does not compile with a placeholder
/// (all zeros) here (`macos_credential_helper`).
pub const HELPER_V2_SHA256: &str = "1b4ba95a61d4ebe80037beaae22a5c2d355cad6dfcfa2d67d22cce510822c774";

/// The code directory hashes of the frozen credential helper v2, in lowercase hex: arm64, then x86_64, as
/// its manifest records them.
pub const HELPER_V2_CDHASHES: [&str; 2] = [
    "238f3dea35aef59acb8d16cb4686f583d1f8f673",
    "13c5561e08eef8f6c22b5477bfdeae0e7d26ca93",
];

/// The SHA-1 of the project's macOS code-signing certificate, in lowercase hex: the leaf the
/// credential helper requires of the program that talks to it.
pub const PROJECT_CERT_LEAF_SHA1: &str = "66f062921154fb6fe72e7ee0dfe99d7d804efb03";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_and_development_values() {
        assert_eq!(
            PRODUCTION,
            Identity {
                app_id: "dev.ysya.lunport",
                product_name: "Lunport",
                credential_service: "Lunport",
                login_item: "Lunport",
                installer_identity: "Lunport",
                publisher: "ysya",
                main_binary: "lunport",
                console_helper: "lunport-cli",
                pipe_prefix: "lunport",
                thread_prefix: "lunport",
            }
        );
        assert_eq!(
            DEVELOPMENT,
            Identity {
                app_id: "dev.ysya.lunport.dev",
                product_name: "Lunport Dev",
                credential_service: "Lunport Development",
                login_item: "Lunport Dev",
                installer_identity: "Lunport Dev",
                publisher: "ysya",
                main_binary: "lunport",
                console_helper: "lunport-cli",
                pipe_prefix: "lunport",
                thread_prefix: "lunport",
            }
        );
    }

    #[test]
    fn credential_helper_and_certificate_values() {
        assert_eq!(
            HELPER_V2_IDENTIFIER,
            "dev.ysya.lunport.credential-helper.v2"
        );
        assert_eq!(
            PROJECT_CERT_LEAF_SHA1,
            "66f062921154fb6fe72e7ee0dfe99d7d804efb03"
        );
        assert!(
            PROJECT_CERT_LEAF_SHA1.len() == 40
                && PROJECT_CERT_LEAF_SHA1
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "a certificate leaf is written as 40 lowercase hex digits"
        );
    }

    /// Helper v2's pinned values are its manifest's once it is frozen and committed, and placeholders (all zeros) until then:
    /// never values from anywhere else. A Production build refuses to compile with the placeholders (`macos_credential_helper`).
    #[test]
    fn helper_v2_values_follow_its_manifest() {
        let lowercase_hex = |digest: &str, length: usize| {
            digest.len() == length && digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        assert!(lowercase_hex(HELPER_V2_SHA256, 64), "{HELPER_V2_SHA256}");
        assert!(HELPER_V2_CDHASHES.iter().all(|digest| lowercase_hex(digest, 40)), "{HELPER_V2_CDHASHES:?}");
        let zeros = |digest: &str| digest.bytes().all(|b| b == b'0');
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("signing/credential-helper-v2.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(manifest["protocol"], 2);
                assert_eq!(manifest["identifier"], HELPER_V2_IDENTIFIER);
                assert_eq!(manifest["artifact_sha256"], HELPER_V2_SHA256);
                assert_eq!(manifest["cdhashes"]["arm64"], HELPER_V2_CDHASHES[0]);
                assert_eq!(manifest["cdhashes"]["x86_64"], HELPER_V2_CDHASHES[1]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => assert!(
                zeros(HELPER_V2_SHA256) && HELPER_V2_CDHASHES.iter().all(|digest| zeros(digest)),
                "helper v2 has no manifest yet, so its values must be the placeholders"
            ),
            Err(error) => panic!("cannot read {}: {error}", path.display()),
        }
    }

    /// The certificates in the repository are the ones these values name: `signing/macos-project.pem`, which
    /// `scripts/macos-signing.sh` pins the signing secret to, has the leaf helper v2 requires of the app, and
    /// `signing/legacy/macos-project.pem` has the leaf helper v1 and the bridge to it were signed with. Each file is one public
    /// certificate and nothing else.
    #[test]
    fn the_committed_certificates_have_the_pinned_leaves() {
        use base64::Engine;
        use sha1::{Digest, Sha1};
        let leaf = |pem: &str| {
            // `lines` also ends a line at "\r\n", which a Windows checkout may write.
            let lines: Vec<&str> = pem.lines().filter(|line| !line.trim().is_empty()).collect();
            assert_eq!(pem.matches("-----BEGIN ").count(), 1, "one PEM block");
            assert_eq!(lines.first(), Some(&"-----BEGIN CERTIFICATE-----"));
            assert_eq!(lines.last(), Some(&"-----END CERTIFICATE-----"));
            let body: String = lines.iter().filter(|line| !line.starts_with("-----")).copied().collect();
            let der = base64::engine::general_purpose::STANDARD.decode(body).unwrap();
            Sha1::digest(der).iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        assert_eq!(leaf(include_str!("../signing/macos-project.pem")), PROJECT_CERT_LEAF_SHA1);
        assert_eq!(
            leaf(include_str!("../signing/legacy/macos-project.pem")),
            crate::legacy_identity::CERT_LEAF_SHA1
        );
    }

    #[test]
    fn thread_names_are_the_thread_prefix_a_dash_and_the_purpose() {
        assert_eq!(thread_name("sync"), "lunport-sync");
        assert_eq!(thread_name("ipc-listener"), "lunport-ipc-listener");
        assert_eq!(
            thread_name("ssh"),
            format!("{}-ssh", current().thread_prefix)
        );
        for identity in [&PRODUCTION, &DEVELOPMENT] {
            assert!(!identity.thread_prefix.ends_with('-'), "names add the dash");
            assert!(!identity.pipe_prefix.ends_with('-'), "names add the dash");
        }
    }

    /// The crate names are the main binary's: Tauri takes the name of the program it builds from them (`mainBinaryName` renames the
    /// bundled copy), a debug build on Windows runs `target/debug/<name>.exe`, and the tests link the library by its name.
    #[test]
    fn the_main_crate_is_named_after_the_main_binary() {
        let manifest = include_str!("../Cargo.toml");
        for identity in [&PRODUCTION, &DEVELOPMENT] {
            for name in [
                identity.main_binary.to_string(),
                format!("{}_lib", identity.main_binary),
            ] {
                assert!(
                    manifest.lines().any(|line| line == format!("name = \"{name}\"")),
                    "Cargo.toml names no crate {name}"
                );
            }
        }
    }

    /// The console helper is a crate of its own with no dependencies, so it cannot read these values: its manifest and its target
    /// repeat them.
    #[test]
    fn the_console_helper_crate_repeats_the_identity_values() {
        let manifest = include_str!("../cli-helper/Cargo.toml");
        let source = include_str!("../cli-helper/src/lib.rs");
        for identity in [&PRODUCTION, &DEVELOPMENT] {
            assert!(
                manifest
                    .lines()
                    .any(|line| line == format!("name = \"{}\"", identity.console_helper)),
                "the helper's package is not {}",
                identity.console_helper
            );
            assert!(
                source
                    .lines()
                    .any(|line| line == format!("pub const TARGET: &str = \"{}.exe\";", identity.main_binary)),
                "the helper does not run {}.exe",
                identity.main_binary
            );
        }
    }

    /// The scripts that upgrade and check installs from before 2.0 cannot read Rust, so `scripts/legacy-identity.json` repeats the
    /// old names: each of its fields, for both profiles, holds the `legacy_identity` value. A field the file gains has to be added here.
    #[test]
    fn scripts_legacy_identity_json_matches_legacy_identity() {
        use crate::legacy_identity::{Legacy, DEVELOPMENT as OLD_DEVELOPMENT, PRODUCTION as OLD_PRODUCTION};
        let fields: [(&str, fn(&Legacy) -> &'static str); 7] = [
            ("appId", |legacy| legacy.app_id),
            ("credentialService", |legacy| legacy.credential_service),
            ("loginItem", |legacy| legacy.login_item),
            ("installerIdentity", |legacy| legacy.installer_identity),
            ("manufacturer", |legacy| legacy.manufacturer),
            ("mainBinary", |legacy| legacy.main_binary),
            ("consoleHelper", |legacy| legacy.console_helper),
        ];
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../../scripts/legacy-identity.json")).unwrap();
        for (profile, legacy) in [("production", &OLD_PRODUCTION), ("development", &OLD_DEVELOPMENT)] {
            let values = file[profile]
                .as_object()
                .unwrap_or_else(|| panic!("scripts/legacy-identity.json has no {profile} object"));
            assert!(!values.is_empty(), "scripts/legacy-identity.json has no {profile} values");
            for (field, value) in values {
                let (_, of) = fields
                    .iter()
                    .find(|(name, _)| name == field)
                    .unwrap_or_else(|| panic!("{profile}.{field} of scripts/legacy-identity.json is not compared here"));
                assert_eq!(value, of(legacy), "{profile}.{field} of scripts/legacy-identity.json");
            }
        }
    }

    #[test]
    fn the_profiles_never_share_what_isolates_them() {
        // Two builds on one machine must not share a data folder, credentials or a login item.
        assert_ne!(PRODUCTION.app_id, DEVELOPMENT.app_id);
        assert_ne!(PRODUCTION.product_name, DEVELOPMENT.product_name);
        assert_ne!(
            PRODUCTION.credential_service,
            DEVELOPMENT.credential_service
        );
        assert_ne!(PRODUCTION.login_item, DEVELOPMENT.login_item);
        assert_ne!(
            PRODUCTION.installer_identity,
            DEVELOPMENT.installer_identity
        );
    }
}
