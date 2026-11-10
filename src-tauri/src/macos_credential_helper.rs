//! Production macOS credentials belong to frozen, signed executables. Their bytes are embedded as data so the App bundler cannot
//! re-sign them on each release. Helper v2 keeps this version's credentials (`credential_store`); helper v1, which kept them before
//! 2.0.0, and the bridge the app reaches it through serve only the credential migration (`bridge::Session`). Development keeps its
//! separate native store. No secret reaches argv, disk, logs or an unauthenticated child process.
//!
//! This module pins the programs (`HelperSpec`: the three specs are the only ones) and serves the app's requests; how a program is
//! installed and talked to is in `transport`.
use crate::app_profile::AppProfile;
use crate::error::AppError;
use crate::{identity, legacy_identity};
use zeroize::Zeroizing;

#[path = "macos_credential_bridge.rs"]
pub(crate) mod bridge;
#[path = "macos_credential_transport.rs"]
mod transport;

use transport::Response;

/// errSecItemNotFound: there is no such item.
const NOT_FOUND: i32 = -25300;

/// Whether `status` says macOS did not let a program reach an item: the user did not allow it (errSecUserCanceled,
/// errSecAuthFailed), or the request forbade authorization UI and macOS would have asked (errSecInteractionNotAllowed).
fn refused(status: i32) -> bool {
    matches!(status, -128 | -25293 | -25308)
}

/// One frozen program that speaks the helper framing: where the app installs its bytes, and what the app checks before it trusts
/// the running program. Only `helper_v1`, `helper_v2` and `bridge` make one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HelperSpec {
    path: &'static str,
    requirement: String,
    sha256: &'static str,
    version: u32,
    magic: &'static [u8; 8],
}

impl HelperSpec {
    /// Where the program is installed, relative to the data root: a private folder of its own under `credential-helper`, then the
    /// program's file name (the name macOS shows when it asks the user to allow access).
    pub(crate) fn path(&self) -> &'static str {
        self.path
    }

    /// The code requirement the live program must satisfy before it is sent anything: its signing identifier, the leaf of the
    /// certificate it was signed with and its two code hashes (arm64, x86_64).
    pub(crate) fn requirement(&self) -> &str {
        &self.requirement
    }

    /// The SHA-256 of the program's universal binary, in lowercase hex.
    pub(crate) fn sha256(&self) -> &'static str {
        self.sha256
    }

    /// The protocol version its manifest records. Adopt exists from protocol 2.
    pub(crate) fn version(&self) -> u32 {
        self.version
    }

    /// The 8 bytes the program greets with, which also start every request frame it accepts. No two programs share them, so a
    /// frame meant for one is never accepted by another.
    pub(crate) fn magic(&self) -> &'static [u8; 8] {
        self.magic
    }
}

/// The requirement of a program signed as `identifier` with the certificate whose SHA-1 is `leaf`, and whose code hash is one of
/// `cdhashes`.
fn requirement(identifier: &str, leaf: &str, cdhashes: [&str; 2]) -> String {
    format!(
        "identifier \"{identifier}\" and certificate leaf = H\"{leaf}\" and (cdhash H\"{}\" or cdhash H\"{}\")",
        cdhashes[0], cdhashes[1]
    )
}

/// Helper v2: keeps this version's credentials under `identity::PRODUCTION.credential_service`, accepts only the app as its parent,
/// and can adopt an item from the service versions before 2.0.0 saved under.
pub(crate) fn helper_v2() -> HelperSpec {
    HelperSpec {
        path: "credential-helper/v2/Lunport Credential Helper",
        requirement: requirement(
            identity::HELPER_V2_IDENTIFIER,
            identity::PROJECT_CERT_LEAF_SHA1,
            identity::HELPER_V2_CDHASHES,
        ),
        sha256: identity::HELPER_V2_SHA256,
        version: 2,
        magic: b"LPKC0002",
    }
}

/// Helper v1: kept credentials under the earlier service before 2.0.0 and accepts only a parent signed as the app was then, so the
/// credential migration reaches it through the bridge. It stays where those versions installed it.
pub(crate) fn helper_v1() -> HelperSpec {
    HelperSpec {
        path: "credential-helper/v1/Lunport Credential Helper",
        requirement: requirement(
            legacy_identity::HELPER_V1_IDENTIFIER,
            legacy_identity::CERT_LEAF_SHA1,
            legacy_identity::HELPER_V1_CDHASHES,
        ),
        sha256: legacy_identity::HELPER_V1_SHA256,
        version: 1,
        magic: b"LPKC0001",
    }
}

/// The SHA-256 of the signed bridge's universal binary and its code hashes (arm64, x86_64), as its manifest
/// `signing/legacy/credential-bridge.json` records them.
const BRIDGE_SHA256: &str = "965e7aeb4331ef1eae181348ff4a3ff9de8829bc7da46ed1a8bfc2bae57bf73f";
const BRIDGE_CDHASHES: [&str; 2] = ["fad363f3a0c17ad7b5d5b1a755651368b5d6f878", "041b81c1451d5c59e5da1ceb85d34bff5376b60c"];

/// The bridge: signed as the app was before 2.0.0, it accepts only this app as its parent and relays the credential migration's
/// requests to helper v1, each wrapped in its own frame (`signing/legacy/credential-bridge.c`, `bridge::Session`).
pub(crate) fn bridge() -> HelperSpec {
    HelperSpec {
        path: "credential-helper/bridge/Lunport Credential Bridge",
        requirement: requirement(legacy_identity::PRODUCTION.app_id, legacy_identity::CERT_LEAF_SHA1, BRIDGE_CDHASHES),
        sha256: BRIDGE_SHA256,
        version: 1,
        magic: b"LPKB0001",
    }
}

#[cfg(test)]
impl HelperSpec {
    /// A spec for a stand-in program in a test: `bytes` are the program (their SHA-256 is pinned), it greets with `magic`, and no
    /// signed program satisfies its requirement.
    pub(crate) fn fixture(path: &'static str, magic: &'static [u8; 8], version: u32, bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let sha256: String = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
        let none = "0000000000000000000000000000000000000000";
        Self { path, requirement: requirement("com.example.acme.stand-in", none, [none, none]), sha256: Box::leak(sha256.into_boxed_str()), version, magic }
    }
}

/// The program ordinary credential requests go to. Helper v1 is never a fallback.
fn credential_store() -> HelperSpec {
    helper_v2()
}

/// Whether `digest` is a placeholder for a value only a frozen artifact gives: all zeros.
const fn is_placeholder(digest: &str) -> bool {
    let bytes = digest.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'0' {
            return false;
        }
        index += 1;
    }
    !bytes.is_empty()
}

/// Whether a SHA-256 and both code hashes come from a frozen artifact.
const fn frozen_values(sha256: &str, cdhashes: [&str; 2]) -> bool {
    !is_placeholder(sha256) && !is_placeholder(cdhashes[0]) && !is_placeholder(cdhashes[1])
}

/// Whether a build of `profile` may exist while helper v2's values are as `helper_v2_frozen` says: Production keeps its credentials
/// only with helper v2, so it needs the frozen values; Development never runs a helper.
const fn release_allowed(profile: AppProfile, helper_v2_frozen: bool) -> bool {
    helper_v2_frozen || !matches!(profile, AppProfile::Production)
}

// A Production build made before helper v2 is frozen would have no credential store and must not fall back to helper v1, so it
// does not compile. Debug and test builds are Development builds.
const _: () = assert!(
    release_allowed(
        crate::app_profile::CURRENT,
        frozen_values(identity::HELPER_V2_SHA256, identity::HELPER_V2_CDHASHES)
    ),
    "helper v2 is not frozen: a Production build needs HELPER_V2_SHA256 and HELPER_V2_CDHASHES in identity.rs, from signing/credential-helper-v2.json"
);

// The frozen programs' bytes. Only a Production release build embeds them: it is the only build that runs a helper.
#[cfg(all(not(debug_assertions), not(feature = "development-profile")))]
const EMBEDDED_HELPER_V2: Option<&[u8]> = Some(include_bytes!("../signing/credential-helper-v2.bin"));
#[cfg(any(debug_assertions, feature = "development-profile"))]
const EMBEDDED_HELPER_V2: Option<&[u8]> = None;
#[cfg(all(not(debug_assertions), not(feature = "development-profile")))]
const EMBEDDED_HELPER_V1: Option<&[u8]> = Some(include_bytes!("../signing/legacy/credential-helper-v1.bin"));
#[cfg(any(debug_assertions, feature = "development-profile"))]
const EMBEDDED_HELPER_V1: Option<&[u8]> = None;
#[cfg(all(not(debug_assertions), not(feature = "development-profile")))]
const EMBEDDED_BRIDGE: Option<&[u8]> = Some(include_bytes!("../signing/legacy/credential-bridge.bin"));
#[cfg(any(debug_assertions, feature = "development-profile"))]
const EMBEDDED_BRIDGE: Option<&[u8]> = None;

fn error(message: impl std::fmt::Display) -> AppError {
    // Messages describe the operation, never its account, request or response.
    AppError::Other(format!("credential helper: {message}"))
}

/// The embedded bytes of the program `spec` pins.
fn frozen(spec: &HelperSpec, embedded: Option<&'static [u8]>) -> Result<&'static [u8], AppError> {
    checked(spec, embedded.ok_or_else(|| error("only signed Production builds use the fixed helper"))?)
}

/// `bytes`, if they are the program `spec` pins: they have its SHA-256.
fn checked<'a>(spec: &HelperSpec, bytes: &'a [u8]) -> Result<&'a [u8], AppError> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if is_placeholder(spec.sha256()) || hash != spec.sha256() {
        return Err(error("embedded artifact does not match its pinned hash"));
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Get = 1,
    Set = 2,
    Delete = 3,
    /// Protocol 2: moves one item from the service versions before 2.0.0 saved under to this version's (`adopt`).
    Adopt = 5,
}

/// An ordinary request's result: the data of a successful get (empty for set and delete), `None` when there is no such item.
fn credential(response: Response) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    match response.status {
        0 => Ok(Some(response.data)),
        NOT_FOUND => Ok(None),
        status if refused(status) => Err(error("macOS did not authorize this request. Existing credentials are preserved. Allow Lunport Credential Helper when macOS asks, then retry")),
        other => Err(error(format!("Keychain request failed (OSStatus {other})"))),
    }
}

/// What helper v2's adopt did with one account. Only `Moved` deletes the old item, as its last step; every other outcome leaves the
/// old item as it was. After any outcome the current service may hold a copy, from this request or an earlier one, so a caller reads
/// it before it saves there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Adoption {
    /// The copy under the current service read back with the old item's bytes, then the old item was deleted.
    Moved,
    /// The earlier service has no item for this account (errSecItemNotFound).
    NoOldItem,
    /// The user, or a request that forbade authorization UI, did not allow access to an item (errSecUserCanceled, errSecAuthFailed,
    /// errSecInteractionNotAllowed), either to read the old item or to delete it once copied. Any copy this request made stays under
    /// the current service.
    Refused(i32),
    /// The current service already holds an item for this account that the helper could not confirm holds the same bytes
    /// (errSecDuplicateItem); both are kept as they are.
    Conflict,
    /// The old item holds more than 1 MiB (errSecDataTooLarge).
    TooLarge,
    /// The copy under the current service did not read back identically, or vanished (errSecVerifyFailed).
    NotVerified,
    /// The helper names one service for both sides (errSecParam): a build that must never ship. Nothing was touched.
    Misconfigured,
    /// Any other status.
    Failed(i32),
}

/// What helper v2's adopt status means.
fn adoption(status: i32) -> Adoption {
    match status {
        0 => Adoption::Moved,
        NOT_FOUND => Adoption::NoOldItem,
        status if refused(status) => Adoption::Refused(status),
        -25299 => Adoption::Conflict,
        -25302 => Adoption::TooLarge,
        -67808 => Adoption::NotVerified,
        -50 => Adoption::Misconfigured,
        other => Adoption::Failed(other),
    }
}

/// One ordinary credential request, which helper v2 serves.
fn store(operation: Operation, account: &str, secret: &[u8], no_ui: bool) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    let spec = credential_store();
    let bytes = frozen(&spec, EMBEDDED_HELPER_V2)?;
    credential(transport::request(&spec, bytes, operation, account, secret, no_ui)?)
}

/// Asks helper v2 to move `account`'s item from the service versions before 2.0.0 saved under to this version's (`Adoption`); the
/// secret never leaves the helper. With `no_ui` macOS may not ask the user, so an item helper v2 may not read is `Refused`; without
/// it the app waits for the user's answer as long as the helper does.
pub(crate) fn adopt(account: &str, no_ui: bool) -> Result<Adoption, AppError> {
    let spec = credential_store();
    let bytes = frozen(&spec, EMBEDDED_HELPER_V2)?;
    Ok(adoption(transport::request(&spec, bytes, Operation::Adopt, account, &[], no_ui)?.status))
}

fn utf8(value: Zeroizing<Vec<u8>>) -> Result<String, AppError> {
    std::str::from_utf8(&value)
        .map(str::to_owned)
        .map_err(|_| error("stored credential is not UTF-8"))
}

pub(super) fn get(account: &str) -> Result<Option<String>, AppError> {
    store(Operation::Get, account, &[], false)?.map(utf8).transpose()
}

pub(super) fn set(account: &str, secret: &str) -> Result<(), AppError> {
    store(Operation::Set, account, secret.as_bytes(), false).map(|_| ())
}

pub(super) fn delete(account: &str) -> Result<(), AppError> {
    store(Operation::Delete, account, &[], false).map(|_| ())
}

/// The requests below forbid authorization UI: background work, and the credential migration before the window opens.
pub(crate) fn get_noninteractive(account: &str) -> Result<Option<String>, AppError> {
    store(Operation::Get, account, &[], true)?.map(utf8).transpose()
}
pub(crate) fn set_noninteractive(account: &str, secret: &str) -> Result<(), AppError> {
    store(Operation::Set, account, secret.as_bytes(), true).map(|_| ())
}
#[cfg_attr(test, allow(dead_code))] // For the credential migration, which no test runs against a real helper.
pub(crate) fn delete_noninteractive(account: &str) -> Result<(), AppError> {
    store(Operation::Delete, account, &[], true).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::transport::{exchange, install};
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    /// The requirement every live helper v2 must satisfy: its identifier, the project certificate's leaf and one of its two code
    /// hashes, all read from `identity`.
    #[test]
    fn helper_v2_requirement_pins_identifier_leaf_and_cdhashes() {
        let spec = helper_v2();
        assert_eq!(
            spec.requirement(),
            format!(
                "identifier \"{}\" and certificate leaf = H\"{}\" and (cdhash H\"{}\" or cdhash H\"{}\")",
                identity::HELPER_V2_IDENTIFIER,
                identity::PROJECT_CERT_LEAF_SHA1,
                identity::HELPER_V2_CDHASHES[0],
                identity::HELPER_V2_CDHASHES[1]
            )
        );
        assert!(spec.requirement().starts_with("identifier \"dev.ysya.lunport.credential-helper.v2\" and certificate leaf = H\"66f062921154fb6fe72e7ee0dfe99d7d804efb03\" and (cdhash H\""));
        assert_eq!((spec.sha256(), spec.version(), spec.magic()), (identity::HELPER_V2_SHA256, 2, b"LPKC0002"));
        assert_eq!(spec.path(), "credential-helper/v2/Lunport Credential Helper");
    }

    #[test]
    fn helper_v1_requirement_pins_the_old_identifier_leaf_and_cdhashes() {
        let spec = helper_v1();
        assert_eq!(
            spec.requirement(),
            format!(
                "identifier \"{}\" and certificate leaf = H\"{}\" and (cdhash H\"{}\" or cdhash H\"{}\")",
                legacy_identity::HELPER_V1_IDENTIFIER,
                legacy_identity::CERT_LEAF_SHA1,
                legacy_identity::HELPER_V1_CDHASHES[0],
                legacy_identity::HELPER_V1_CDHASHES[1]
            )
        );
        assert_eq!((spec.sha256(), spec.version(), spec.magic()), (legacy_identity::HELPER_V1_SHA256, 1, b"LPKC0001"));
        assert_eq!(spec.path(), "credential-helper/v1/Lunport Credential Helper");
    }

    /// The bridge is signed as the app was before 2.0.0: the old identifier and certificate leaf, and the code hashes of its signed
    /// artifact (arm64, x86_64).
    #[test]
    fn bridge_requirement_pins_old_identity_leaf_and_cdhashes() {
        let spec = bridge();
        assert_eq!(
            spec.requirement(),
            format!(
                "identifier \"{}\" and certificate leaf = H\"{}\" and (cdhash H\"fad363f3a0c17ad7b5d5b1a755651368b5d6f878\" or cdhash \
                 H\"041b81c1451d5c59e5da1ceb85d34bff5376b60c\")",
                legacy_identity::PRODUCTION.app_id,
                legacy_identity::CERT_LEAF_SHA1,
            )
        );
        assert_eq!(
            (spec.sha256(), spec.version(), spec.magic()),
            ("965e7aeb4331ef1eae181348ff4a3ff9de8829bc7da46ed1a8bfc2bae57bf73f", 1, b"LPKB0001")
        );
        assert!(frozen_values(spec.sha256(), BRIDGE_CDHASHES), "the bridge's values are its signed artifact's, not placeholders");
        assert_eq!(spec.path(), "credential-helper/bridge/Lunport Credential Bridge");
    }

    /// The pinned values are the signed bridge's: its manifest records them, its bytes have that SHA-256, and it was built from the
    /// committed source.
    #[test]
    fn the_bridge_values_agree_with_the_signed_bridge() {
        use sha2::{Digest, Sha256};
        let digest = |bytes: &[u8]| Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
        let manifest: serde_json::Value = serde_json::from_str(include_str!("../signing/legacy/credential-bridge.json")).unwrap();
        assert_eq!(manifest["protocol"], 1);
        assert_eq!(manifest["identifier"], legacy_identity::PRODUCTION.app_id);
        assert_eq!(manifest["artifact_sha256"], BRIDGE_SHA256);
        assert_eq!(manifest["cdhashes"]["arm64"], BRIDGE_CDHASHES[0]);
        assert_eq!(manifest["cdhashes"]["x86_64"], BRIDGE_CDHASHES[1]);
        assert_eq!(digest(include_bytes!("../signing/legacy/credential-bridge.bin")), BRIDGE_SHA256);
        assert_eq!(manifest["source_sha256"], digest(include_bytes!("../signing/legacy/credential-bridge.c")));
        let bytes = include_bytes!("../signing/legacy/credential-bridge.bin");
        assert_eq!(checked(&bridge(), bytes).unwrap(), bytes);
    }

    /// Ordinary credential requests go to helper v2 only; helper v1 is never a fallback.
    #[test]
    fn credentials_are_kept_with_helper_v2() {
        assert_eq!(credential_store(), helper_v2());
        assert_ne!(credential_store().magic(), helper_v1().magic());
        assert_ne!(credential_store().requirement(), helper_v1().requirement());
    }

    /// The frozen sources say what the specs pin: helper v2 accepts the app and keeps its items under this version's credential
    /// service, adopting from the earlier one; the bridge accepts the app and relays only to the pinned helper v1. Each greets
    /// with its spec's magic.
    #[test]
    fn the_frozen_sources_agree_with_their_specs() {
        let helper = include_str!("../signing/credential-helper-v2.c");
        let app = format!(
            "identifier \\\"{}\\\" and certificate leaf = H\\\"{}\\\"",
            identity::PRODUCTION.app_id,
            identity::PROJECT_CERT_LEAF_SHA1
        );
        assert!(helper.contains(&format!("#define LUNPORT_CLIENT_REQUIREMENT \"{app}\"")));
        assert!(helper.contains(&format!("#define LUNPORT_CREDENTIAL_SERVICE \"{}\"", identity::PRODUCTION.credential_service)));
        assert!(helper.contains(&format!("#define LUNPORT_ADOPT_SERVICE \"{}\"", legacy_identity::PRODUCTION.credential_service)));
        assert!(helper.contains(&c_magic(helper_v2().magic())));

        let bridge_source = include_str!("../signing/legacy/credential-bridge.c");
        assert!(bridge_source.contains(&format!("#define LUNPORT_CLIENT_REQUIREMENT \"{app}\"")));
        assert!(bridge_source.contains(&format!(
            "#define LUNPORT_HELPER_REQUIREMENT \"{}\"",
            helper_v1().requirement().replace('"', "\\\"")
        )));
        assert!(bridge_source.contains(&c_magic(bridge().magic())));
        assert!(include_str!("../signing/legacy/credential-helper-v1.c").contains(&c_magic(helper_v1().magic())));
    }

    // How the C sources write their magic: `{'L','P','K','C','0','0','0','2'}`.
    fn c_magic(magic: &[u8; 8]) -> String {
        let letters: Vec<String> = magic.iter().map(|byte| format!("'{}'", *byte as char)).collect();
        format!("{{{}}}", letters.join(","))
    }

    #[test]
    fn frozen_bytes_must_have_the_pinned_sha256() {
        let bytes = include_bytes!("../signing/legacy/credential-helper-v1.bin");
        assert_eq!(checked(&helper_v1(), bytes).unwrap(), bytes);
        assert!(checked(&helper_v1(), b"replaced executable").is_err());
        // Helper v2's pin is its own frozen artifact's SHA-256, which helper v1's bytes do not have.
        assert!(checked(&helper_v2(), bytes).is_err());
    }

    /// Only a Production release build embeds the frozen programs: a Development build has none to install or start, and says so
    /// before it touches the data root.
    #[cfg(any(debug_assertions, feature = "development-profile"))]
    #[test]
    fn a_debug_build_embeds_no_frozen_program() {
        for (spec, embedded) in [(helper_v2(), EMBEDDED_HELPER_V2), (helper_v1(), EMBEDDED_HELPER_V1), (bridge(), EMBEDDED_BRIDGE)] {
            assert!(embedded.is_none());
            let failure = frozen(&spec, embedded).unwrap_err().to_string();
            assert!(failure.contains("only signed Production builds"), "{failure}");
        }
    }

    /// A Production build keeps credentials only with helper v2, so it must not compile with helper v2's placeholders; Development
    /// never runs a helper. The guard itself is a constant evaluated at compile time, so a Development build can test only its parts.
    #[cfg(any(debug_assertions, feature = "development-profile"))]
    #[test]
    fn release_builds_need_the_frozen_helper_v2_values() {
        assert!(is_placeholder("0000000000000000000000000000000000000000"));
        assert!(!is_placeholder("66f062921154fb6fe72e7ee0dfe99d7d804efb03"));
        assert!(!is_placeholder("0000000000000000000000000000000000000001"));
        assert!(!is_placeholder(""));
        let real = ["b81014e67d632acee792ce51572884d585544241", "dd91d3bea5c08b4e639fb3b0944fdb43520b2127"];
        let zero40 = "0000000000000000000000000000000000000000";
        let zero64 = "0000000000000000000000000000000000000000000000000000000000000000";
        let sha256 = "6d74a63293b153fccae754e1c4d38449e5cc26065738fae7d0cfc64dcddf2178";
        assert!(frozen_values(sha256, real));
        assert!(!frozen_values(zero64, real));
        assert!(!frozen_values(sha256, [real[0], zero40]));
        assert!(!frozen_values(sha256, [zero40, real[1]]));
        assert!(!release_allowed(AppProfile::Production, false));
        assert!(release_allowed(AppProfile::Production, true));
        assert!(release_allowed(AppProfile::Development, false));
        // This Development build compiles whatever helper v2's values are.
        assert!(release_allowed(crate::app_profile::CURRENT, false));
    }

    #[test]
    fn adopt_statuses() {
        assert_eq!(adoption(0), Adoption::Moved);
        assert_eq!(adoption(-25300), Adoption::NoOldItem);
        for status in [-128, -25293, -25308] {
            assert_eq!(adoption(status), Adoption::Refused(status));
        }
        assert_eq!(adoption(-25299), Adoption::Conflict);
        assert_eq!(adoption(-25302), Adoption::TooLarge);
        assert_eq!(adoption(-67808), Adoption::NotVerified);
        assert_eq!(adoption(-50), Adoption::Misconfigured);
        assert_eq!(adoption(-34018), Adoption::Failed(-34018));
    }

    #[test]
    fn credential_statuses() {
        let response = |status: i32, data: &[u8]| Response { status, data: Zeroizing::new(data.to_vec()) };
        assert_eq!(credential(response(0, b"value")).unwrap().unwrap().as_slice(), b"value");
        assert!(credential(response(-25300, b"")).unwrap().is_none());
        for status in [-128, -25293, -25308] {
            assert!(credential(response(status, b"")).unwrap_err().to_string().contains("did not authorize"));
        }
        assert!(credential(response(-34018, b"")).unwrap_err().to_string().contains("OSStatus -34018"));
    }

    /// Only the disposable CI runner signs this test binary as the production app. It never runs on a user's login keychain or
    /// changes an item ACL. It reads the frozen helper v2 from the checkout, the bytes a Production build embeds.
    #[test]
    #[ignore = "requires a disposable macOS runner and pinned signed test executable"]
    fn native_frozen_transport_probe() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(std::env::var("RUNNER_OS").as_deref(), Ok("macOS"));
        let run = std::env::var("GITHUB_RUN_ID").unwrap();
        assert!(!run.is_empty() && run.bytes().all(|b| b.is_ascii_digit()));
        let account = format!("lunport-ci-helper-rust-{run}");
        let spec = credential_store();
        let committed = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("signing/credential-helper-v2.bin"))
            .expect("helper v2 is frozen and committed in src-tauri/signing");
        let bytes = checked(&spec, &committed).expect("helper v2's pinned SHA-256 is its frozen artifact's");
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let executable = install(temp.path(), &spec, bytes).unwrap();
        struct Cleanup<'a>(&'a Path, &'a HelperSpec, &'a str);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = exchange(self.0, self.1, Operation::Delete, self.2, &[], true);
            }
        }
        let _cleanup = Cleanup(&executable, &spec, &account);
        let send = |operation, value: &[u8]| {
            credential(exchange(&executable, &spec, operation, &account, value, true).unwrap()).unwrap()
        };
        assert!(send(Operation::Get, &[]).is_none());
        send(Operation::Set, b"public-frozen-rust-fixture");
        assert_eq!(send(Operation::Get, &[]).unwrap().as_slice(), b"public-frozen-rust-fixture");
        let inode = fs::metadata(&executable).unwrap().ino();
        install(temp.path(), &spec, bytes).unwrap();
        assert_eq!(fs::metadata(&executable).unwrap().ino(), inode);
        // Recovery retains the exact same Keychain owner and item contents.
        fs::remove_file(&executable).unwrap();
        install(temp.path(), &spec, bytes).unwrap();
        assert_eq!(send(Operation::Get, &[]).unwrap().as_slice(), b"public-frozen-rust-fixture");
        fs::write(&executable, b"corrupt frozen helper").unwrap();
        install(temp.path(), &spec, bytes).unwrap();
        assert_eq!(send(Operation::Get, &[]).unwrap().as_slice(), b"public-frozen-rust-fixture");
        send(Operation::Set, b"public-replacement-fixture");
        assert_eq!(send(Operation::Get, &[]).unwrap().as_slice(), b"public-replacement-fixture");
        send(Operation::Delete, &[]);
        send(Operation::Delete, &[]);
        assert!(send(Operation::Get, &[]).is_none());
        // Adopt over the same channel: an account the earlier service never held moves nothing and changes nothing.
        let adopted = exchange(&executable, &spec, Operation::Adopt, &account, &[], true).unwrap();
        assert_eq!((adoption(adopted.status), adopted.data.len()), (Adoption::NoOldItem, 0));
        assert!(send(Operation::Get, &[]).is_none());
    }
}
