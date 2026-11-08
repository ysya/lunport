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
fn the_normal_library_enforces_the_profile_on_guarded_writes() {
    let temp = tempfile::tempdir().unwrap();
    let result = sshelter_lib::write_policy::check_current_profile(&temp.path().join("export"));
    match CURRENT {
        AppProfile::Development => {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        }
        AppProfile::Production => result.unwrap(),
    }
}

#[test]
fn the_normal_library_exposes_the_shipped_central_sync_capability() {
    assert_eq!(
    sshelter_lib::central_sync_available(),
    cfg!(feature = "central-sync") && cfg!(any(target_os = "macos", target_os = "linux", windows)),
    "Standard desktop builds advertise central sync only where secure publication is supported."
);
}
