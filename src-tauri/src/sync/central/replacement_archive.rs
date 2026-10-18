//! Encrypted, immutable local Core snapshots before explicit identity replacement.
//! Callers hold the existing lifecycle owner and publish a receipt only after durable readback.
use super::{
    credentials::Profile,
    crypto,
    membership::Device,
    wire::{canonical, hex, invalid, number},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{
        env::SyncEnv,
        record_runtime,
        records_v3::{self, SyncStateV3},
    },
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
const MAGIC: &[u8; 8] = b"LPRARC1\0";
const MAX_HEADER: usize = 4096;
const MAX_FILE: u64 = record_runtime::MAX_STATE_BYTES + MAX_HEADER as u64 + 28;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub origin: String,
    pub locator: String,
    pub account: String,
    pub genesis: Option<String>,
    pub device: Device,
    pub operation: String,
    pub generation: String,
    pub plaintext_hash: String,
    pub plaintext_bytes: u64,
}
impl Context {
    fn validate(&self) -> Result<(), AppError> {
        if self.origin.len() > 2048
            || !super::wire::origin(&self.origin)
            || !hex(&self.locator, 64)
            || !hex(&self.account, 64)
            || self.genesis.as_ref().is_some_and(|g| !hex(g, 64))
            || !hex(&self.device.id, 32)
            || !hex(&self.operation, 32)
            || !hex(&self.plaintext_hash, 64)
            || self.plaintext_bytes == 0
            || self.plaintext_bytes > record_runtime::MAX_STATE_BYTES
        {
            return Err(invalid());
        }
        self.device.keys.validate()?;
        number(&self.generation, true)?;
        Ok(())
    }
    fn aad(&self) -> Result<Vec<u8>, AppError> {
        self.validate()?;
        canonical(&[
            "lunport-local-replacement-archive-v1",
            &self.origin,
            &self.locator,
            &self.account,
            self.genesis.as_deref().unwrap_or(""),
            &self.device.id,
            &self.device.keys.signing,
            &self.device.keys.encryption,
            &self.operation,
            &self.generation,
            &self.plaintext_hash,
            &self.plaintext_bytes.to_string(),
        ])
    }
    fn key_scope(&self) -> Result<String, AppError> {
        self.validate()?;
        Ok(crypto::hash(&canonical(&[
            "lunport-local-replacement-archive-key-v1",
            &self.origin,
            &self.locator,
            &self.account,
            self.genesis.as_deref().unwrap_or(""),
            &self.device.id,
            &self.device.keys.signing,
            &self.device.keys.encryption,
            &self.operation,
        ])?))
    }
    fn filename(&self) -> Result<String, AppError> {
        self.validate()?;
        Ok(format!(
            "{}-{}-{}.lparch",
            self.operation, self.generation, self.plaintext_hash
        ))
    }
    fn matches(&self, workspace: &Workspace) -> bool {
        let c = &workspace.control;
        self.origin == c.profile.origin
            && self.locator == c.profile.locator
            && self.account == c.account_id
            && self.genesis.as_deref() == c.anchor.as_ref().map(|a| a.genesis_hash.as_str())
            && self.device == c.device
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub context: Context,
    pub file_hash: String,
}
impl Receipt {
    pub fn validate(&self) -> Result<(), AppError> {
        self.context.validate()?;
        if !hex(&self.file_hash, 64) {
            return Err(invalid());
        }
        Ok(())
    }
}
/// Ephemeral native evidence of durable archival. It cannot be reconstructed from a frontend
/// receipt or deserialized state; a replacement publication must consume it for the exact source.
pub struct Permit {
    receipt: Receipt,
}
impl std::ops::Deref for Permit {
    type Target = Receipt;
    fn deref(&self) -> &Receipt {
        &self.receipt
    }
}
impl Permit {
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    pub fn verify_source(&self, state: &SyncStateV3, generation: u64) -> Result<(), AppError> {
        let plain = Zeroizing::new(serde_json::to_vec(state).map_err(|_| invalid())?);
        if self.context.generation != generation.to_string()
            || self.context.plaintext_bytes != plain.len() as u64
            || self.context.plaintext_hash != crypto::hash(&plain)
            || !state
                .local
                .central
                .as_ref()
                .is_some_and(|w| self.context.matches(w))
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    context: Context,
    nonce: String,
}
fn encode(context: &Context, key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    if plaintext.len() as u64 != context.plaintext_bytes
        || crypto::hash(plaintext) != context.plaintext_hash
    {
        return Err(invalid());
    }
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| invalid())?;
    let header = serde_json::to_vec(&Header {
        context: context.clone(),
        nonce: B64.encode(nonce),
    })
    .map_err(|_| invalid())?;
    if header.len() > MAX_HEADER {
        return Err(invalid());
    }
    let ciphertext = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid())?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &context.aad()?,
            },
        )
        .map_err(|_| invalid())?;
    let mut output = Vec::with_capacity(12 + header.len() + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&(header.len() as u32).to_be_bytes());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}
fn decode(context: &Context, key: &[u8; 32], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
    context.validate()?;
    if bytes.len() < 12 || bytes.len() as u64 > MAX_FILE || &bytes[..8] != MAGIC {
        return Err(invalid());
    }
    let header_len = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
    if header_len > MAX_HEADER
        || bytes.len() as u64 != 12 + header_len as u64 + context.plaintext_bytes + 16
    {
        return Err(invalid());
    }
    let header: Header =
        serde_json::from_slice(&bytes[12..12 + header_len]).map_err(|_| invalid())?;
    if header.context != *context {
        return Err(invalid());
    }
    let nonce = crypto::decode(&header.nonce, 24, 24)?;
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| invalid())?
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &bytes[12 + header_len..],
                    aad: &context.aad()?,
                },
            )
            .map_err(|_| invalid())?,
    );
    if plaintext.len() as u64 != context.plaintext_bytes
        || crypto::hash(&plaintext) != context.plaintext_hash
    {
        return Err(invalid());
    }
    Ok(plaintext)
}
fn archive_key(
    env: &SyncEnv,
    profile: &Profile,
    context: &Context,
    create: bool,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Stored {
        version: u32,
        scope: String,
        key: String,
    }
    impl Drop for Stored {
        fn drop(&mut self) {
            self.key.zeroize();
        }
    }
    let slot = profile.slot(&format!("replacement-archive-{}", context.operation));
    let scope = context.key_scope()?;
    let parse = |encoded: &str| -> Result<Zeroizing<[u8; 32]>, AppError> {
        if encoded.len() > 1024 {
            return Err(invalid());
        }
        let stored: Stored = serde_json::from_str(encoded).map_err(|_| invalid())?;
        if stored.version != 1 || stored.scope != scope {
            return Err(invalid());
        }
        let decoded = Zeroizing::new(crypto::decode(&stored.key, 32, 32)?);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&decoded);
        Ok(key)
    };
    if let Some(value) = env.keychain.get(&slot)? {
        return parse(&Zeroizing::new(value));
    }
    if !create {
        return Err(AppError::Other("The protected key for this recovery archive is unavailable. Original data is retained.".into()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key).map_err(|_| invalid())?;
    let stored = Stored {
        version: 1,
        scope: scope.clone(),
        key: B64.encode(&*key),
    };
    let encoded = Zeroizing::new(serde_json::to_string(&stored).map_err(|_| invalid())?);
    env.keychain.set(&slot, &encoded)?;
    let readback = Zeroizing::new(env.keychain.get(&slot)?.ok_or_else(invalid)?);
    let checked = parse(&readback)?;
    if checked != key {
        return Err(invalid());
    }
    Ok(key)
}
/// Source may contain local-only state and old legacy secrets. It is encrypted under an independent
/// protected OS key, rather than copied as plaintext or encrypted under a lost device identity.
pub fn prepare(
    env: &SyncEnv,
    _owner: &std::sync::MutexGuard<'_, ()>,
    state: &SyncStateV3,
    generation: u64,
    operation: &str,
) -> Result<Permit, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    let workspace = state.local.central.as_ref().ok_or_else(invalid)?;
    let plain = Zeroizing::new(serde_json::to_vec(state).map_err(|_| invalid())?);
    let context = Context {
        origin: workspace.control.profile.origin.clone(),
        locator: workspace.control.profile.locator.clone(),
        account: workspace.control.account_id.clone(),
        genesis: workspace
            .control
            .anchor
            .as_ref()
            .map(|a| a.genesis_hash.clone()),
        device: workspace.control.device.clone(),
        operation: operation.into(),
        generation: generation.to_string(),
        plaintext_hash: crypto::hash(&plain),
        plaintext_bytes: plain.len() as u64,
    };
    context.validate()?;
    let dir = ArchiveDirectory::open(env)?;
    let name = context.filename()?;
    let existing = dir.read(&name)?;
    let profile = workspace.control.profile.profile()?;
    let key = archive_key(env, &profile, &context, existing.is_none())?;
    let bytes = match existing {
        Some(bytes) => {
            if decode(&context, &key, &bytes)?.as_slice() != plain.as_slice() {
                return Err(invalid());
            }
            bytes
        }
        None => {
            let bytes = encode(&context, &key, &plain)?;
            dir.publish(&name, &bytes)?;
            bytes
        }
    };
    dir.sync()?;
    let readback = dir.read(&name)?.ok_or_else(invalid)?;
    if bytes != readback || decode(&context, &key, &readback)?.as_slice() != plain.as_slice() {
        return Err(invalid());
    }
    Ok(Permit {
        receipt: Receipt {
            context,
            file_hash: crypto::hash(&readback),
        },
    })
}
/// No caller-supplied path is accepted. Returning state is native-only; it is not a frontend DTO.
pub fn restore(
    env: &SyncEnv,
    profile: &Profile,
    receipt: &Receipt,
) -> Result<SyncStateV3, AppError> {
    receipt.validate()?;
    if profile.locator != receipt.context.locator || profile.origin != receipt.context.origin {
        return Err(invalid());
    }
    let bytes = ArchiveDirectory::open(env)?
        .read(&receipt.context.filename()?)?
        .ok_or_else(invalid)?;
    if crypto::hash(&bytes) != receipt.file_hash {
        return Err(invalid());
    }
    let key = archive_key(env, profile, &receipt.context, false)?;
    let plain = decode(&receipt.context, &key, &bytes)?;
    let state: SyncStateV3 = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    records_v3::validate_state(&state).map_err(|_| invalid())?;
    if !state
        .local
        .central
        .as_ref()
        .is_some_and(|w| receipt.context.matches(w))
    {
        return Err(invalid());
    }
    Ok(state)
}
#[cfg(unix)]
struct ArchiveDirectory {
    directory: std::fs::File,
    base: std::fs::File,
}
#[cfg(unix)]
impl ArchiveDirectory {
    fn open(env: &SyncEnv) -> Result<Self, AppError> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let parent = env.state_path.parent().ok_or_else(invalid)?;
        crate::fsutil::check_write(&parent.join("central-recovery-archives"))?;
        let parent = std::fs::canonicalize(parent)?;
        crate::fsutil::check_write(&parent.join("central-recovery-archives"))?;
        let mut base = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        use std::os::unix::ffi::OsStrExt;
        for component in parent.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => {
                    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid())?;
                    let fd = unsafe {
                        libc::openat(
                            base.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    base = unsafe { std::fs::File::from_raw_fd(fd) };
                }
                _ => return Err(invalid()),
            }
        }
        let name = std::ffi::CString::new("central-recovery-archives").map_err(|_| invalid())?;
        let made = unsafe { libc::mkdirat(base.as_raw_fd(), name.as_ptr(), 0o700) };
        if made < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe {
            libc::openat(
                base.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let dir = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = dir.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        base.sync_all()?;
        Ok(Self {
            directory: dir,
            base,
        })
    }
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, AppError> {
        use std::{
            io::Read,
            os::fd::{AsRawFd, FromRawFd},
        };
        let name = std::ffi::CString::new(name).map_err(|_| invalid())?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error.into())
            };
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file()
            || metadata.len() > MAX_FILE
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(invalid());
        }
        Ok(Some(bytes))
    }
    fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), AppError> {
        use std::{
            io::Write,
            os::fd::{AsRawFd, FromRawFd},
        };
        let name = std::ffi::CString::new(name).map_err(|_| invalid())?;
        let temporary = std::ffi::CString::new(format!(".pending-{}", crypto::random_id(16)?))
            .map_err(|_| invalid())?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let result: Result<(), AppError> = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            if unsafe {
                libc::linkat(
                    self.directory.as_raw_fd(),
                    temporary.as_ptr(),
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    0,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        })();
        let removed = unsafe { libc::unlinkat(self.directory.as_raw_fd(), temporary.as_ptr(), 0) };
        result?;
        if removed < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.sync()
    }
    fn sync(&self) -> Result<(), AppError> {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        self.directory.sync_all()?;
        let name = std::ffi::CString::new("central-recovery-archives").map_err(|_| invalid())?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.base.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let stat = unsafe { stat.assume_init() };
        let actual = self.directory.metadata()?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_dev as u64 != actual.dev()
            || stat.st_ino as u64 != actual.ino()
            || actual.mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        self.base.sync_all()?;
        Ok(())
    }
}
#[cfg(not(unix))]
struct ArchiveDirectory;
#[cfg(not(unix))]
impl ArchiveDirectory {
    fn open(_: &SyncEnv) -> Result<Self, AppError> {
        Err(AppError::Other("This platform build cannot yet guarantee durable device-recovery archives. Original data is retained.".into()))
    }
    fn read(&self, _: &str) -> Result<Option<Vec<u8>>, AppError> {
        Err(invalid())
    }
    fn publish(&self, _: &str, _: &[u8]) -> Result<(), AppError> {
        Err(invalid())
    }
    fn sync(&self) -> Result<(), AppError> {
        Err(invalid())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sync::{
        env::Keychain,
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    fn source() -> TestDevice {
        let device = TestDevice::new("archive", &FakeRelay::new(), &TestClock::new());
        let probe = record_runtime::probe_startup(&device.env().state_path, "archive");
        record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
        record_runtime::mutate_records(&device.env(), |records| {
            let mut records = records.clone();
            records.local.central = Some(super::super::workspace::tests::enrolled());
            Ok(records)
        })
        .unwrap();
        device
    }
    #[test]
    fn durable_archive_is_encrypted_retryable_scoped_and_does_not_replace_the_live_core() {
        use std::os::unix::fs::PermissionsExt;
        let device = source();
        let before = record_runtime::snapshot(&device.env()).unwrap();
        let profile = before
            .0
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .profile
            .profile()
            .unwrap();
        let owner = device.runtime.lifecycle.lock().unwrap();
        let op = "a".repeat(32);
        let receipt = prepare(&device.env(), &owner, &before.0, before.1, &op).unwrap();
        let retry = prepare(&device.env(), &owner, &before.0, before.1, &op).unwrap();
        assert_eq!(receipt.receipt(), retry.receipt());
        receipt.verify_source(&before.0, before.1).unwrap();
        assert!(receipt.verify_source(&before.0, before.1 + 1).is_err());
        let mut changed = before.0.clone();
        changed.device_name = "changed source".into();
        assert!(receipt.verify_source(&changed, before.1).is_err());
        assert_eq!(
            restore(&device.env(), &profile, &receipt).unwrap(),
            before.0
        );
        assert_eq!(record_runtime::snapshot(&device.env()).unwrap(), before);
        let path = device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("central-recovery-archives")
            .join(receipt.context.filename().unwrap());
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("opaque"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut wrong = receipt.clone();
        wrong.context.operation = "b".repeat(32);
        assert!(restore(&device.env(), &profile, &wrong).is_err());
        let slot = profile.slot(&format!("replacement-archive-{op}"));
        let original = device.keychain.get(&slot).unwrap().unwrap();
        device.keychain.delete(&slot).unwrap();
        assert!(prepare(&device.env(), &owner, &before.0, before.1, &op).is_err());
        assert!(device.keychain.get(&slot).unwrap().is_none());
        device.keychain.set(&slot, &original).unwrap();
        let mut corrupt = raw.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert!(restore(&device.env(), &profile, &receipt).is_err());
        assert!(prepare(&device.env(), &owner, &before.0, before.1, &op).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
        assert_eq!(record_runtime::snapshot(&device.env()).unwrap(), before);
    }
    #[test]
    fn codec_rejects_other_scope_wrong_key_header_changes_and_truncation() {
        let device = source();
        let before = record_runtime::snapshot(&device.env()).unwrap();
        let owner = device.runtime.lifecycle.lock().unwrap();
        let receipt = prepare(&device.env(), &owner, &before.0, before.1, &"c".repeat(32)).unwrap();
        let profile = before
            .0
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .profile
            .profile()
            .unwrap();
        let key = archive_key(&device.env(), &profile, &receipt.context, false).unwrap();
        let plain = Zeroizing::new(serde_json::to_vec(&before.0).unwrap());
        let encoded = encode(&receipt.context, &key, &plain).unwrap();
        assert_eq!(
            decode(&receipt.context, &key, &encoded).unwrap().as_slice(),
            plain.as_slice()
        );
        assert!(decode(&receipt.context, &[9u8; 32], &encoded).is_err());
        let mut scope = receipt.context.clone();
        scope.generation = "999".into();
        assert!(decode(&scope, &key, &encoded).is_err());
        let mut oversized = encoded.clone();
        oversized[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&receipt.context, &key, &oversized).is_err());
        assert!(decode(&receipt.context, &key, &encoded[..encoded.len() - 1]).is_err());
        let mut corrupt = encoded;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(decode(&receipt.context, &key, &corrupt).is_err());
    }
    #[test]
    fn archive_directory_and_file_symlinks_never_redirect_read_or_write() {
        use std::os::unix::fs::symlink;
        let device = source();
        let before = record_runtime::snapshot(&device.env()).unwrap();
        let owner = device.runtime.lifecycle.lock().unwrap();
        let root = device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("central-recovery-archives");
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), &root).unwrap();
        assert!(prepare(&device.env(), &owner, &before.0, before.1, &"d".repeat(32)).is_err());
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
        std::fs::remove_file(&root).unwrap();
        let receipt = prepare(&device.env(), &owner, &before.0, before.1, &"d".repeat(32)).unwrap();
        let path = root.join(receipt.context.filename().unwrap());
        std::fs::remove_file(&path).unwrap();
        let sentinel = outside.path().join("keep");
        std::fs::write(&sentinel, b"UNCHANGED").unwrap();
        symlink(&sentinel, &path).unwrap();
        assert!(prepare(&device.env(), &owner, &before.0, before.1, &"d".repeat(32)).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"UNCHANGED");
        assert_eq!(record_runtime::snapshot(&device.env()).unwrap(), before);
    }
    #[test]
    fn a_detached_archive_directory_cannot_issue_a_durable_receipt() {
        use std::os::unix::fs::PermissionsExt;
        let device = source();
        let directory = ArchiveDirectory::open(&device.env()).unwrap();
        let root = device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("central-recovery-archives");
        let moved = root.with_file_name("moved-archives");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(directory.sync().is_err());
        assert!(std::fs::read_dir(&moved).unwrap().next().is_none());
    }
    #[test]
    fn a_local_b_saved_after_archival_requires_a_new_snapshot_and_preserves_both_sources() {
        let device = source();
        let owner = device.runtime.lifecycle.lock().unwrap();
        let before = record_runtime::snapshot(&device.env()).unwrap();
        let op = "e".repeat(32);
        let first = prepare(&device.env(), &owner, &before.0, before.1, &op).unwrap();
        record_runtime::mutate_records(&device.env(),|records|crate::sync::record_repository::create_host(records,"0000000000000001",crate::sync::records_v3::HostScope::Local,serde_json::from_value(serde_json::json!({"schema":2,"alias":"newer-local-b","hostname":"local.invalid","auth":"password"})).unwrap(),1).map_err(|e|AppError::Other(e.to_string()))).unwrap();
        let latest = record_runtime::snapshot(&device.env()).unwrap();
        assert!(first.verify_source(&latest.0, latest.1).is_err());
        let second = prepare(&device.env(), &owner, &latest.0, latest.1, &op).unwrap();
        assert_ne!(first.context.plaintext_hash, second.context.plaintext_hash);
        second.verify_source(&latest.0, latest.1).unwrap();
        let profile = latest
            .0
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .profile
            .profile()
            .unwrap();
        assert_eq!(restore(&device.env(), &profile, &first).unwrap(), before.0);
        assert_eq!(restore(&device.env(), &profile, &second).unwrap(), latest.0);
        assert_eq!(record_runtime::snapshot(&device.env()).unwrap(), latest);
    }
    #[test]
    fn forbidden_destination_and_failed_key_readback_never_publish_an_archive_or_change_the_source()
    {
        struct Lost;
        impl Keychain for Lost {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(None)
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("archival must not delete a credential")
            }
        }
        let device = source();
        let owner = device.runtime.lifecycle.lock().unwrap();
        let before = record_runtime::snapshot(&device.env()).unwrap();
        let forbidden = tempfile::tempdir().unwrap();
        crate::fsutil::with_test_write_policy(
            crate::write_policy::WritePolicy::Confined {
                root: forbidden.path().to_path_buf(),
            },
            || {
                assert!(
                    prepare(&device.env(), &owner, &before.0, before.1, &"f".repeat(32)).is_err()
                );
            },
        );
        let root = device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("central-recovery-archives");
        assert!(!root.exists());
        let env = SyncEnv {
            keychain: &Lost,
            ..device.env()
        };
        assert!(prepare(&env, &owner, &before.0, before.1, &"f".repeat(32)).is_err());
        assert!(std::fs::read_dir(&root).unwrap().next().is_none());
        assert_eq!(record_runtime::snapshot(&device.env()).unwrap(), before);
    }
}
