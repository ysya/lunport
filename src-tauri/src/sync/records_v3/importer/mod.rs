//! Explicit read-only configuration previews. No config repair, credential access or command execution.
mod source;
mod types;
use std::path::Path;
pub use types::*;

pub fn preview_file(source: &Path, options: &ImportOptions) -> Result<ImportPreview, ImportError> {
    let snapshot = source::load(source, options)?;
    Ok(ImportPreview {
        provenance: snapshot.files,
        source_digest: snapshot.digest,
        ..Default::default()
    })
}
#[cfg(test)]
mod tests;
