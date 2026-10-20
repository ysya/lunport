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

#[test]
fn the_normal_library_enforces_the_profile_on_an_actual_vault_export() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("export");
    std::fs::write(&path, b"keep").unwrap();
    let result = sshelter_lib::vault::export::save_export(&path, &temp.path().join("home"), "fixture");
    match CURRENT {
        AppProfile::Development => {
            assert!(result.is_err());
            assert_eq!(std::fs::read(path).unwrap(), b"keep");
        }
        AppProfile::Production => {
            result.unwrap();
            assert_eq!(std::fs::read(path).unwrap(), b"fixture");
        }
    }
}

#[test]
fn the_normal_library_uses_the_compiled_legacy_ssh_boundary() {
    match CURRENT {
        AppProfile::Development => assert!(CURRENT.require_legacy_ssh().is_err()),
        AppProfile::Production => assert!(CURRENT.require_legacy_ssh().is_ok()),
    }
}

#[test]
fn the_normal_library_exposes_the_shipped_central_sync_capability() {
    assert_eq!(
        sshelter_lib::central_sync_available(),
        cfg!(feature = "central-sync") && cfg!(any(target_os = "macos", target_os = "linux")),
        "Standard desktop builds advertise central sync only where secure publication is supported."
    );
}
