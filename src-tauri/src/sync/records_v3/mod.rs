//! Pure records for the own SSH client. This module owns no runtime state or I/O.

mod types;
mod validate;
pub use types::*;
pub use validate::*;

#[cfg(test)]
mod tests;
