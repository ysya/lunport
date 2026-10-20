
#[path = "../../../src/sync/slot_files_windows.rs"]
pub mod slot_files_windows;
pub mod central {
    pub mod crypto {
        // Only distinct temporary filenames are needed by these isolated fixtures.
        // The production app uses its cryptographic RNG; no content keys are made here.
        pub fn random_id(bytes: usize) -> Result<String, crate::error::AppError> {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            Ok(format!(
                "{:0width$x}",
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                width = bytes * 2
            ))
        }
    }
}
#[path = "../../../src/sync/central_files_windows.rs"]
pub mod central_files_windows;
