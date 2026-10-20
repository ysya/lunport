This small, unpublished crate runs the desktop application's actual Windows
filesystem module and its ACL, junction, stream and atomic-write tests. It supplies
only the test error/write-policy adapters and distinct temporary filenames; no
production code is copied and no user credentials or real data are loaded.

On Windows, run `cargo test --locked --manifest-path src-tauri/windows-sync-check/Cargo.toml`.
The normal desktop suite separately verifies migration, encrypted sync, recovery,
and publication with the application's real services and cryptographic RNG.
