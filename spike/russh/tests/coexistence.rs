//! Task 1: the app's `ssh-key` 0.6.7 and the `ssh-key` 0.7.0-rc that russh pins live in one build, and agree about a public key.

/// `test_keys::PLAIN_PUBLIC` and `PLAIN_FINGERPRINT` from src-tauri/src/sync/slot_rules.rs (the app's own tests pin them with ssh-key 0.6.7).
const ED25519_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5M9xdffT0p33BD1LiLFTiEvrjv4IZMFADC81ex4ndf";
const ED25519_FINGERPRINT: &str = "SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew";
/// `test_keys::ECDSA_PUBLIC` and `ECDSA_FINGERPRINT`.
const ECDSA_LINE: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEjFNKVD5g/ngM+x8oESowshddffHjvh+l4MYyyXDZMfnXpzylT6xjkTiMop0/8K1KN1+LyseBdXlLj6j5m8mvU=";
const ECDSA_FINGERPRINT: &str = "SHA256:vUthAmDZoxYXCTAPEZUn5qtWSMHWQCEcUfpnyM05mMs";

#[test]
fn both_ssh_key_versions_parse_the_same_public_keys_and_agree_on_the_fingerprints() {
    for (line, expected) in [(ED25519_LINE, ED25519_FINGERPRINT), (ECDSA_LINE, ECDSA_FINGERPRINT)] {
        let app = ssh_key_app::PublicKey::from_openssh(line).expect("ssh-key 0.6.7 parses the line");
        let russh = russh::keys::PublicKey::from_openssh(line).expect("ssh-key 0.7.0-rc parses the line");
        assert_eq!(app.fingerprint(ssh_key_app::HashAlg::Sha256).to_string(), expected);
        assert_eq!(russh.fingerprint(russh::keys::HashAlg::Sha256).to_string(), expected);
    }
}

/// The committed Cargo.lock holds both generations side by side: that is the whole coexistence question.
#[test]
fn the_lock_file_holds_ssh_key_0_6_7_and_a_0_7_release_candidate() {
    let lock = include_str!("../Cargo.lock");
    let versions: Vec<&str> = lock
        .split("[[package]]")
        .filter(|package| package.lines().any(|line| line == "name = \"ssh-key\""))
        .filter_map(|package| package.lines().find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"')))
        .collect();
    assert!(versions.contains(&"0.6.7"), "ssh-key 0.6.7 (the vault's) is missing: {versions:?}");
    assert!(versions.iter().any(|version| version.starts_with("0.7.0-rc.")), "russh's ssh-key 0.7.0-rc is missing: {versions:?}");
}

/// With the app library linked in (the default feature), its public API is callable next to russh. `starts_hidden` is public in src-tauri/src/lib.rs.
#[cfg(feature = "app-vault")]
#[test]
fn the_app_library_is_linked_into_the_same_binary() {
    assert!(sshelter_lib::starts_hidden(Some(std::ffi::OsStr::new("1"))));
}
