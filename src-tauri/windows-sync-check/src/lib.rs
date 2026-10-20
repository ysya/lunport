//! Executes the production Windows filesystem module's tests without a GUI build.
//! Full desktop migration, credentials and sync tests still run separately in CI.
#![cfg(windows)]
#![allow(dead_code)]
mod error {
    #[derive(Debug)]
    pub enum AppError {
        Io(std::io::Error),
    }
    impl From<std::io::Error> for AppError {
        fn from(error: std::io::Error) -> Self {
            Self::Io(error)
        }
    }
}
mod fsutil {
    // Unit fixtures use their own temporary roots, like the app's default test policy.
    pub fn check_write(_: &std::path::Path) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    pub fn check_write_io(_: &std::path::Path) -> std::io::Result<()> {
        Ok(())
    }
}
mod sync;
