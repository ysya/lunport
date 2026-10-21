//! Large Windows credentials. The OS entry pins immutable DPAPI ciphertext.
//! The odd-sized binary reference is disjoint from every legacy UTF-16 password.
use crate::error::AppError;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const NATIVE_BYTES: usize = 2560;
pub(crate) const MAX_VALUE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_BLOB_BYTES: usize = MAX_VALUE_BYTES + 65536;
const MAGIC: &[u8; 8] = b"LPCRD001";
const REFERENCE_BYTES: usize = 81;

/// Native entry and private, bounded, immutable files. DPAPI is supplied by the
/// Windows backend; the test backend models this boundary without OS credentials.
pub(crate) trait Backend {
    fn get_entry(&self) -> Result<Option<Zeroizing<Vec<u8>>>, AppError>;
    fn set_entry(&self, value: &[u8]) -> Result<(), AppError>;
    fn delete_entry(&self) -> Result<(), AppError>;
    fn protect(&self, value: &[u8], entropy: &[u8]) -> Result<Vec<u8>, AppError>;
    fn unprotect(&self, value: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError>;
    fn read_blob(&self, name: &str, limit: usize) -> Result<Vec<u8>, AppError>;
    fn write_blob(&self, name: &str, value: &[u8]) -> Result<(), AppError>;
    fn remove_blob(&self, name: &str) -> Result<(), AppError>;
}
pub(crate) fn invalid() -> AppError {
    AppError::Other(
        "Protected credential data is unavailable or invalid. Local data is retained.".into(),
    )
}
fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
struct Reference {
    entropy: Zeroizing<[u8; 32]>,
    digest: [u8; 32],
    plaintext: usize,
    ciphertext: usize,
}
impl Reference {
    fn name(&self) -> String {
        let hex: String = self.digest.iter().map(|b| format!("{b:02x}")).collect();
        format!("{hex}.cred")
    }
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(REFERENCE_BYTES));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&*self.entropy);
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&(self.plaintext as u32).to_le_bytes());
        out.extend_from_slice(&(self.ciphertext as u32).to_le_bytes());
        out.push(0);
        out
    }
    fn binding(&self, service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let mut out = Zeroizing::new(MAGIC.to_vec());
        out.extend_from_slice(&*self.entropy);
        for field in [service, account] {
            let length = u32::try_from(field.len()).map_err(|_| invalid())?;
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        Ok(out)
    }
}
fn reference(value: &[u8]) -> Result<Option<Reference>, AppError> {
    if value.len() > NATIVE_BYTES {
        return Err(invalid());
    }
    if value.len() % 2 == 0 {
        return Ok(None);
    }
    if value.len() != REFERENCE_BYTES || !value.starts_with(MAGIC) || value[80] != 0 {
        return Err(invalid());
    }
    let plaintext = u32::from_le_bytes(value[72..76].try_into().map_err(|_| invalid())?) as usize;
    let ciphertext = u32::from_le_bytes(value[76..80].try_into().map_err(|_| invalid())?) as usize;
    if plaintext <= NATIVE_BYTES / 2
        || plaintext > MAX_VALUE_BYTES
        || ciphertext == 0
        || ciphertext > MAX_BLOB_BYTES
    {
        return Err(invalid());
    }
    Ok(Some(Reference {
        entropy: Zeroizing::new(value[8..40].try_into().map_err(|_| invalid())?),
        digest: value[40..72].try_into().map_err(|_| invalid())?,
        plaintext,
        ciphertext,
    }))
}
fn legacy(value: &[u8]) -> Result<String, AppError> {
    if value.len() > NATIVE_BYTES || value.len() % 2 != 0 {
        return Err(invalid());
    }
    let units = Zeroizing::new(
        value
            .chunks_exact(2)
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .collect::<Vec<_>>(),
    );
    if char::decode_utf16(units.iter().copied()).any(|c| c.is_err()) {
        return Err(invalid());
    }
    String::from_utf16(&units).map_err(|_| invalid())
}
fn open(
    store: &impl Backend,
    r: &Reference,
    blob: &[u8],
    service: &str,
    account: &str,
) -> Result<Zeroizing<String>, AppError> {
    // Check the exact current OS-pinned bytes before asking DPAPI to decrypt.
    if blob.len() != r.ciphertext || digest(blob) != r.digest {
        return Err(invalid());
    }
    let plaintext = store.unprotect(blob, &r.binding(service, account)?)?;
    if plaintext.len() != r.plaintext {
        return Err(invalid());
    }
    let value = Zeroizing::new(
        std::str::from_utf8(&plaintext)
            .map_err(|_| invalid())?
            .to_owned(),
    );
    if value.encode_utf16().count() <= NATIVE_BYTES / 2 {
        return Err(invalid());
    }
    Ok(value)
}
fn resolve(
    store: &impl Backend,
    raw: &[u8],
    service: &str,
    account: &str,
) -> Result<Zeroizing<String>, AppError> {
    let Some(r) = reference(raw)? else {
        return legacy(raw).map(Zeroizing::new);
    };
    let blob = store
        .read_blob(&r.name(), r.ciphertext)
        .map_err(|_| invalid())?;
    open(store, &r, &blob, service, account)
}
pub(crate) fn get(
    store: &impl Backend,
    service: &str,
    account: &str,
) -> Result<Option<String>, AppError> {
    // Another process may commit and clean the old blob while we read it.
    // Retry only on a changed OS pointer, never on corrupt current data.
    for _ in 0..3 {
        let Some(raw) = store.get_entry()? else {
            return Ok(None);
        };
        let value = resolve(store, &raw, service, account);
        if store.get_entry()?.as_ref().map(|v| v.as_slice()) == Some(raw.as_slice()) {
            return value.map(|mut value| Some(std::mem::take(&mut *value)));
        }
    }
    Err(AppError::Other(
        "The saved credential changed during access. Retry; local data is retained.".into(),
    ))
}
fn cleanup(store: &impl Backend, previous: Option<&[u8]>) {
    if let Some(old) = previous.and_then(|v| reference(v).ok()).flatten() {
        // Its fresh per-write secret entropy is gone from the OS entry. Cleanup
        // failure leaves ciphertext only and must not fail an acknowledged commit.
        let _ = store.remove_blob(&old.name());
    }
}
pub(crate) fn set(
    store: &impl Backend,
    service: &str,
    account: &str,
    value: &str,
) -> Result<(), AppError> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(invalid());
    }
    let previous = store.get_entry()?;
    let raw = if value.encode_utf16().count() <= NATIVE_BYTES / 2 {
        Zeroizing::new(
            value
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
    } else {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *entropy).map_err(|_| invalid())?;
        let mut r = Reference {
            entropy,
            digest: [0; 32],
            plaintext: value.len(),
            ciphertext: 0,
        };
        let blob = store.protect(value.as_bytes(), &r.binding(service, account)?)?;
        if blob.is_empty() || blob.len() > MAX_BLOB_BYTES {
            return Err(invalid());
        }
        r.digest = digest(&blob);
        r.ciphertext = blob.len();
        store.write_blob(&r.name(), &blob)?;
        let saved = store.read_blob(&r.name(), r.ciphertext)?;
        if saved != blob || open(store, &r, &saved, service, account)?.as_str() != value {
            return Err(invalid());
        }
        r.encode()
    };
    // On an ambiguous OS write/readback, retain both blobs: the new pointer may
    // have committed. A cold retry can follow whichever entry the OS retained.
    store.set_entry(&raw)?;
    if store.get_entry()?.as_ref().map(|v| v.as_slice()) != Some(raw.as_slice()) {
        return Err(invalid());
    }
    if previous.as_ref().map(|v| v.as_slice()) != Some(raw.as_slice()) {
        cleanup(store, previous.as_ref().map(|v| v.as_slice()));
    }
    Ok(())
}
pub(crate) fn delete(store: &impl Backend) -> Result<(), AppError> {
    let previous = store.get_entry()?;
    store.delete_entry()?;
    if store.get_entry()?.is_some() {
        return Err(invalid());
    }
    cleanup(store, previous.as_ref().map(|v| v.as_slice()));
    Ok(())
}
#[cfg(test)]
#[path = "credential_blob/tests.rs"]
pub(crate) mod tests;
