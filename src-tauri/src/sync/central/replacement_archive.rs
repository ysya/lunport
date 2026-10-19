//! Encrypted, immutable local Core snapshots before explicit identity replacement.
//! Callers hold the existing lifecycle owner and publish a receipt only after durable readback.
use super::{
    archive_directory::{ArchiveDirectory, Kind as ArchiveKind},
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
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub history_hash: Option<String>,
}
impl Receipt {
    pub fn validate(&self) -> Result<(), AppError> {
        self.context.validate()?;
        if !hex(&self.file_hash, 64) || self.history_hash.as_ref().is_some_and(|h| !hex(h, 64)) {
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
const HISTORY_MAGIC: &[u8;8]=b"LPRAHS1\0";
const MAX_HISTORY_FILE: usize=32*1024*1024+128*1024+MAX_HEADER+28;
fn history_aad(context: &Context) -> Result<Vec<u8>, AppError> {
    let mut aad = b"lunport-replacement-logical-history-v1\0".to_vec();
    aad.extend(context.aad()?);
    Ok(aad)
}
fn encode_history(
    context: &Context,
    key: &[u8; 32],
    plain: &[u8],
) -> Result<Vec<u8>, AppError> {
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
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid())?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &history_aad(context)?,
            },
        )
        .map_err(|_| invalid())?;
    let mut out = Vec::new();
    out.extend_from_slice(HISTORY_MAGIC);
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend(header);
    out.extend(cipher);
    if out.len() > MAX_HISTORY_FILE {
        return Err(invalid());
    }
    Ok(out)
}
fn decode_history(
    context: &Context,
    key: &[u8; 32],
    bytes: &[u8],
    state: &SyncStateV3,
) -> Result<super::source_package::snapshot::Group, AppError> {
    if bytes.len() < 12 || bytes.len() > MAX_HISTORY_FILE || !bytes.starts_with(HISTORY_MAGIC) {
        return Err(invalid());
    }
    let n = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
    if n > MAX_HEADER || bytes.len() < 12 + n + 16 {
        return Err(invalid());
    }
    let h: Header = serde_json::from_slice(&bytes[12..12 + n]).map_err(|_| invalid())?;
    if &h.context != context {
        return Err(invalid());
    }
    let nonce = crypto::decode(&h.nonce, 24, 24)?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| invalid())?
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &bytes[12 + n..],
                    aad: &history_aad(context)?,
                },
            )
            .map_err(|_| invalid())?,
    );
    super::source_package::snapshot::StateSnapshot::decode(&plain)?.verify(state)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKey {
    version: u32,
    scope: String,
    key: String,
}
impl Drop for StoredKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
fn parse_key(context: &Context, value: &str) -> Result<Zeroizing<[u8; 32]>, AppError> {
    if value.len() > 1024 {
        return Err(invalid());
    }
    let stored: StoredKey = serde_json::from_str(value).map_err(|_| invalid())?;
    if stored.version != 1 || stored.scope != context.key_scope()? {
        return Err(invalid());
    }
    let decoded = Zeroizing::new(crypto::decode(&stored.key, 32, 32)?);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
}
pub(in crate::sync::central) mod captured;

fn archive_key(
    env: &SyncEnv,
    profile: &Profile,
    context: &Context,
    create: bool,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let slot = profile.slot(&format!("replacement-archive-{}", context.operation));
    let scope = context.key_scope()?;
    let parse = |value: &str| parse_key(context, value);
    if let Some(value) = env.keychain.get(&slot)? {
        return parse(&Zeroizing::new(value));
    }
    if !create {
        return Err(AppError::Other("The protected key for this recovery archive is unavailable. Original data is retained.".into()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key).map_err(|_| invalid())?;
    let stored = StoredKey {
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
    let dir = ArchiveDirectory::open(env, ArchiveKind::Replacement)?;
    let name = context.filename()?;
    let existing = dir.read(&name)?;
    let profile = workspace.control.profile.profile()?;
    // Local B produces a new filename. Its absence must not authorize replacing the key
    // that still protects generation A. Keep an immutable operation-wide key commitment.
    let marker_name = format!("{operation}-key.sha256");
    let marker = dir.read(&marker_name)?;
    let key = archive_key(
        env,
        &profile,
        &context,
        existing.is_none() && marker.is_none(),
    )?;
    let commitment = crypto::hash(key.as_slice());
    match marker {
        Some(marker) if marker.as_slice() == commitment.as_bytes() => {}
        Some(_) => return Err(invalid()),
        None => dir.publish(&marker_name, commitment.as_bytes())?,
    }
    dir.sync()?;
    if dir.read(&marker_name)?.as_deref() != Some(commitment.as_bytes()) {
        return Err(invalid());
    }
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
    let history_hash = if super::historical_state::needed(state) {
        let history_name = format!("{name}.lphist");
        let history = match dir.read(&history_name)? {
            Some(history) => {
                drop(decode_history(&context, &key, &history, state)?);
                history
            }
            None => {
                let slot = profile.device_slot("device", workspace.identity_slot.as_deref())?;
                if Zeroizing::new(env.keychain.get_noninteractive(&slot)?).is_none() {
                    // Recovery may begin after the old identity was already lost. Preserve the
                    // exact encrypted original; no logical-history completeness is claimed.
                    // A later source merge must still fail closed if it cannot read this history.
                    Vec::new()
                } else {
                    let identity = super::credentials::DeviceIdentity::load_selected(
                        env.keychain,
                        &profile,
                        workspace.identity_slot.as_deref(),
                        false,
                    )?;
                    let snapshot = super::source_package::snapshot::StateSnapshot::create(
                        state, &identity,
                    )?;
                    let bytes = encode_history(&context, &key, snapshot.bytes())?;
                    dir.publish(&history_name, &bytes)?;
                    bytes
                }
            }
        };
        if history.is_empty() {
            None
        } else {
            dir.sync()?;
            let readback = dir.read(&history_name)?.ok_or_else(invalid)?;
            if history != readback {
                return Err(invalid());
            }
            drop(decode_history(&context, &key, &readback, state)?);
            Some(crypto::hash(&readback))
        }
    } else {
        None
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
            history_hash,
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
    let bytes = ArchiveDirectory::open(env, ArchiveKind::Replacement)?
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
    if let Some(hash) = &receipt.history_hash {
        let history = ArchiveDirectory::open(env, ArchiveKind::Replacement)?
            .read(&format!("{}.lphist", receipt.context.filename()?))?
            .ok_or_else(invalid)?;
        if crypto::hash(&history) != *hash {
            return Err(invalid());
        }
        drop(decode_history(&receipt.context, &key, &history, &state)?);
    }
    Ok(state)
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
        // A later local edit uses a different filename but must never replace A's missing key.
        assert!(prepare(&device.env(), &owner, &changed, before.1 + 1, &op).is_err());
        assert!(device.keychain.get(&slot).unwrap().is_none());
        assert_eq!(std::fs::read(&path).unwrap(), raw);
        device.keychain.set(&slot, &original).unwrap();
        let newer = prepare(&device.env(), &owner, &changed, before.1 + 1, &op).unwrap();
        assert_eq!(restore(&device.env(), &profile, &newer).unwrap(), changed);
        assert_eq!(
            restore(&device.env(), &profile, &receipt).unwrap(),
            before.0
        );
        let marker = path.parent().unwrap().join(format!("{op}-key.sha256"));
        let marker_bytes = std::fs::read(&marker).unwrap();
        std::fs::write(&marker, b"invalid marker").unwrap();
        assert!(prepare(&device.env(), &owner, &changed, before.1 + 1, &op).is_err());
        assert_eq!(
            device.keychain.get(&slot).unwrap().as_deref(),
            Some(original.as_str())
        );
        std::fs::write(&marker, &marker_bytes).unwrap();
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
        let directory = ArchiveDirectory::open(&device.env(), ArchiveKind::Replacement).unwrap();
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
