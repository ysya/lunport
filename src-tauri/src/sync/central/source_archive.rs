//! Independently protected local source bytes. Durability is not inventory/cutover authority.
use super::{
    archive_directory::{ArchiveDirectory, Kind},
    client_state::Phase,
    credentials::Profile,
    crypto,
    membership::{Device, TrustAnchor},
    wire::{canonical, hex, invalid, number},
    workspace::Workspace,
};
use crate::{error::AppError, sync::env::SyncEnv};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"LPSARC1\0";
const MAX_HEADER: usize = 4096;
const MAX_PLAIN: usize = 192 * 1024 * 1024;
const MAX_FILE: usize = MAX_PLAIN + MAX_HEADER + 28;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    anchor: TrustAnchor,
    locator: String,
    vault: String,
    device: Device,
    operation: String,
    snapshot: String,
    generation: String,
}
impl Context {
    fn validate(&self) -> Result<(), AppError> {
        if !super::wire::origin(&self.anchor.origin)
            || !self.anchor.origin.starts_with("https://")
            || self.anchor.origin.len() > 2048
            || ![
                &self.anchor.account_id,
                &self.anchor.genesis_hash,
                &self.locator,
                &self.vault,
            ]
            .iter()
            .all(|v| hex(v, 64))
            || !hex(&self.device.id, 32)
            || !hex(&self.operation, 32)
            || !hex(&self.snapshot, 32)
        {
            return Err(invalid());
        }
        self.device.keys.validate()?;
        number(&self.generation, true)?;
        Ok(())
    }
    fn owner(owner: &Workspace) -> Result<(), AppError> {
        owner.validate()?;
        owner.require_key_recipients()?;
        if owner.control.cutover || owner.control.phase != Phase::Enrolled {
            return Err(invalid());
        }
        Ok(())
    }
    fn fresh(owner: &Workspace, generation: u64) -> Result<Self, AppError> {
        Self::owner(owner)?;
        let result = Self {
            anchor: owner.control.anchor.clone().ok_or_else(invalid)?,
            locator: owner.control.profile.locator.clone(),
            vault: owner.control.personal_vault.clone().ok_or_else(invalid)?,
            device: owner.control.device.clone(),
            operation: crypto::random_id(16)?,
            snapshot: crypto::random_id(16)?,
            generation: generation.to_string(),
        };
        result.validate()?;
        Ok(result)
    }
    pub(super) fn matches_owner(&self, owner: &Workspace) -> Result<(), AppError> {
        Self::owner(owner)?;
        self.validate()?;
        if owner.control.anchor.as_ref() != Some(&self.anchor)
            || owner.control.profile.locator != self.locator
            || owner.control.personal_vault.as_ref() != Some(&self.vault)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn matches_profile(&self, profile: &Profile) -> Result<(), AppError> {
        self.validate()?;
        if self.locator != profile.locator || self.anchor.origin != profile.origin {
            return Err(invalid());
        }
        Ok(())
    }
    fn filename(&self) -> Result<String, AppError> {
        self.validate()?;
        Ok(format!("{}-{}.lpsource", self.operation, self.snapshot))
    }
    fn marker(&self) -> String {
        format!("{}-key.sha256", self.operation)
    }
    fn scope(&self) -> Result<String, AppError> {
        self.validate()?;
        Ok(crypto::hash(&canonical(&[
            "lunport-local-source-key-v1",
            &self.anchor.origin,
            &self.locator,
            &self.anchor.account_id,
            &self.anchor.genesis_hash,
            &self.vault,
            &self.device.id,
            &self.device.keys.signing,
            &self.device.keys.encryption,
            &self.operation,
        ])?))
    }
    fn key_role(&self, profile: &Profile) -> Result<String, AppError> {
        self.matches_profile(profile)?;
        Ok(profile.slot(&format!("source-archive-{}", self.operation)))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub context: Context,
    pub ciphertext_hash: String,
    pub bytes: u64,
}
impl Receipt {
    pub fn validate(&self) -> Result<(), AppError> {
        self.context.validate()?;
        if !hex(&self.ciphertext_hash, 64) || self.bytes < 29 || self.bytes > MAX_FILE as u64 {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn operation(&self) -> &str {
        &self.context.operation
    }
}
/// No Clone/Debug/Serialize and no publication methods. A driver must prove complete inventory separately.
pub(super) struct Archived {
    receipt: Receipt,
}
impl Archived {
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    context: Context,
    plaintext_bytes: u64,
    nonce: String,
}
impl Header {
    fn aad(&self) -> Result<Vec<u8>, AppError> {
        self.context.validate()?;
        if self.plaintext_bytes == 0 || self.plaintext_bytes > MAX_PLAIN as u64 {
            return Err(invalid());
        }
        crypto::decode(&self.nonce, 24, 24)?;
        let c = &self.context;
        canonical(&[
            "lunport-local-source-archive-v1",
            &c.anchor.origin,
            &c.locator,
            &c.anchor.account_id,
            &c.anchor.genesis_hash,
            &c.vault,
            &c.device.id,
            &c.device.keys.signing,
            &c.device.keys.encryption,
            &c.operation,
            &c.snapshot,
            &c.generation,
            &self.plaintext_bytes.to_string(),
            &self.nonce,
        ])
    }
}
fn encode(context: &Context, key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, AppError> {
    if plain.is_empty() || plain.len() > MAX_PLAIN {
        return Err(invalid());
    }
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| invalid())?;
    let header = Header {
        context: context.clone(),
        plaintext_bytes: plain.len() as u64,
        nonce: B64.encode(nonce),
    };
    let aad = header.aad()?;
    let bytes = serde_json::to_vec(&header).map_err(|_| invalid())?;
    if bytes.len() > MAX_HEADER {
        return Err(invalid());
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid())?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| invalid())?;
    let mut result = Vec::with_capacity(12 + bytes.len() + cipher.len());
    result.extend_from_slice(MAGIC);
    result.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    result.extend(bytes);
    result.extend(cipher);
    Ok(result)
}
fn decode(context: &Context, key: &[u8; 32], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
    if bytes.len() < 12 || bytes.len() > MAX_FILE || !bytes.starts_with(MAGIC) {
        return Err(invalid());
    }
    let size = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
    if size == 0 || size > MAX_HEADER || bytes.len() < 12 + size {
        return Err(invalid());
    }
    let header: Header = serde_json::from_slice(&bytes[12..12 + size]).map_err(|_| invalid())?;
    let aad = header.aad()?;
    if &header.context != context || bytes.len() != 12 + size + header.plaintext_bytes as usize + 16
    {
        return Err(invalid());
    }
    let nonce = crypto::decode(&header.nonce, 24, 24)?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| invalid())?
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &bytes[12 + size..],
                    aad: &aad,
                },
            )
            .map_err(|_| invalid())?,
    );
    if plain.len() as u64 != header.plaintext_bytes {
        return Err(invalid());
    }
    Ok(plain)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKey {
    version: u32,
    scope: String,
    #[serde(deserialize_with = "key_string", serialize_with = "store_key_string")]
    key: Zeroizing<String>,
}
fn key_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn store_key_string<S: serde::Serializer>(
    value: &Zeroizing<String>,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(value.as_str())
}
fn parse_key(encoded: &str, scope: &str) -> Result<Zeroizing<[u8; 32]>, AppError> {
    if encoded.len() > 1024 {
        return Err(invalid());
    }
    let stored: StoredKey = serde_json::from_str(encoded).map_err(|_| invalid())?;
    if stored.version != 1 || stored.scope != scope {
        return Err(invalid());
    }
    let bytes = Zeroizing::new(crypto::decode(&stored.key, 32, 32)?);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}
fn protected_key(
    env: &SyncEnv,
    profile: &Profile,
    context: &Context,
    fresh: bool,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let role = context.key_role(profile)?;
    let scope = context.scope()?;
    if let Some(encoded) = env.keychain.get_noninteractive(&role)?.map(Zeroizing::new) {
        if fresh {
            return Err(invalid());
        }
        return parse_key(&encoded, &scope);
    }
    if !fresh {
        return Err(AppError::Other(
            "The protected source backup key is unavailable. Original files are retained.".into(),
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key).map_err(|_| invalid())?;
    let stored = StoredKey {
        version: 1,
        scope: scope.clone(),
        key: Zeroizing::new(B64.encode(&*key)),
    };
    let encoded = Zeroizing::new(serde_json::to_string(&stored).map_err(|_| invalid())?);
    env.keychain.set(&role, &encoded)?;
    let readback = Zeroizing::new(
        env.keychain
            .get_noninteractive(&role)?
            .ok_or_else(invalid)?,
    );
    if parse_key(&readback, &scope)? != key {
        return Err(invalid());
    }
    Ok(key)
}
fn write(
    env: &SyncEnv,
    profile: &Profile,
    context: Context,
    plain: &[u8],
    fresh: bool,
) -> Result<Archived, AppError> {
    context.matches_profile(profile)?;
    if plain.is_empty() || plain.len() > MAX_PLAIN {
        return Err(invalid());
    }
    let directory = ArchiveDirectory::open(env, Kind::Source)?;
    let name = context.filename()?;
    let existing = directory.read(&name)?;
    let marker = directory.read(&context.marker())?;
    if fresh && (existing.is_some() || marker.is_some()) || !fresh && marker.is_none() {
        return Err(invalid());
    }
    let key = protected_key(env, profile, &context, fresh)?;
    let commitment = crypto::hash(key.as_slice());
    match marker {
        Some(value) if value.as_slice() == commitment.as_bytes() => {}
        Some(_) => return Err(invalid()),
        None => directory.publish(&context.marker(), commitment.as_bytes())?,
    }
    directory.sync()?;
    if directory.read(&context.marker())?.as_deref() != Some(commitment.as_bytes()) {
        return Err(invalid());
    }
    let bytes = if let Some(bytes) = existing {
        if decode(&context, &key, &bytes)?.as_slice() != plain {
            return Err(invalid());
        }
        bytes
    } else {
        let bytes = encode(&context, &key, plain)?;
        directory.publish(&name, &bytes)?;
        bytes
    };
    directory.sync()?;
    let checked = directory.read(&name)?.ok_or_else(invalid)?;
    if checked != bytes || decode(&context, &key, &checked)?.as_slice() != plain {
        return Err(invalid());
    }
    if protected_key(env, profile, &context, false)? != key {
        return Err(invalid());
    }
    directory.sync()?;
    Ok(Archived {
        receipt: Receipt {
            context,
            ciphertext_hash: crypto::hash(&checked),
            bytes: checked.len() as u64,
        },
    })
}
/// Fresh operation IDs are generated here; a deserialized or caller-chosen operation cannot create a key.
pub(super) fn create(
    env: &SyncEnv,
    _owner: &std::sync::MutexGuard<'_, ()>,
    owner: &Workspace,
    generation: u64,
    plain: &Zeroizing<Vec<u8>>,
) -> Result<Archived, AppError> {
    let context = Context::fresh(owner, generation)?;
    write(env, &owner.control.profile.profile()?, context, plain, true)
}
pub(super) fn next(
    env: &SyncEnv,
    _owner: &std::sync::MutexGuard<'_, ()>,
    owner: &Workspace,
    generation: u64,
    previous: &Receipt,
    plain: &Zeroizing<Vec<u8>>,
) -> Result<Archived, AppError> {
    previous.validate()?;
    previous.context.matches_owner(owner)?;
    let profile = owner.control.profile.profile()?;
    drop(restore(env, &profile, previous)?);
    let mut context = previous.context.clone();
    context.snapshot = crypto::random_id(16)?;
    context.generation = generation.to_string();
    context.validate()?;
    write(env, &profile, context, plain, false)
}
/// Reestablish a readback result after restart; a missing original blob is never reencrypted/replaced.
pub(super) fn resume(
    env: &SyncEnv,
    _owner: &std::sync::MutexGuard<'_, ()>,
    owner: &Workspace,
    receipt: &Receipt,
    expected: &Zeroizing<Vec<u8>>,
) -> Result<Archived, AppError> {
    receipt.context.matches_owner(owner)?;
    let plain = restore(env, &owner.control.profile.profile()?, receipt)?;
    if plain.as_slice() != expected.as_slice() {
        return Err(invalid());
    }
    Ok(Archived {
        receipt: receipt.clone(),
    })
}
/// Authenticated own output only; no caller can supply a filesystem exclusion list.
pub(super) struct Outputs {
    files: [(std::path::PathBuf, Vec<u8>); 2],
}
impl Outputs {
    pub fn files(&self) -> impl Iterator<Item = (&std::path::Path, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_path(), bytes.as_slice()))
    }
}
struct Readback {
    plain: Zeroizing<Vec<u8>>,
    outputs: Outputs,
}
fn readback(env: &SyncEnv, profile: &Profile, receipt: &Receipt) -> Result<Readback, AppError> {
    receipt.validate()?;
    receipt.context.matches_profile(profile)?;
    let directory = ArchiveDirectory::open(env, Kind::Source)?;
    let name = receipt.context.filename()?;
    let marker_name = receipt.context.marker();
    let bytes = directory.read(&name)?.ok_or_else(invalid)?;
    if bytes.len() as u64 != receipt.bytes || crypto::hash(&bytes) != receipt.ciphertext_hash {
        return Err(invalid());
    }
    let key = protected_key(env, profile, &receipt.context, false)?;
    let marker = directory.read(&marker_name)?.ok_or_else(invalid)?;
    if marker.as_slice() != crypto::hash(key.as_slice()).as_bytes() {
        return Err(invalid());
    }
    let plain = decode(&receipt.context, &key, &bytes)?;
    if protected_key(env, profile, &receipt.context, false)? != key {
        return Err(invalid());
    }
    directory.sync()?;
    let root = std::path::Path::new("data/central-source-archives");
    Ok(Readback {
        plain,
        outputs: Outputs {
            files: [(root.join(name), bytes), (root.join(marker_name), marker)],
        },
    })
}
impl Archived {
    pub fn outputs(
        &self,
        env: &SyncEnv,
        profile: &Profile,
        expected: &[u8],
    ) -> Result<Outputs, AppError> {
        let read = readback(env, profile, &self.receipt)?;
        if read.plain.as_slice() != expected {
            return Err(invalid());
        }
        Ok(read.outputs)
    }
}
/// Native bytes only. Never recreates a protected key and accepts no external filesystem path.
pub(super) fn restore(
    env: &SyncEnv,
    profile: &Profile,
    receipt: &Receipt,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    Ok(readback(env, profile, receipt)?.plain)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sync::{
        env::Keychain,
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };
    fn device() -> TestDevice {
        let device = TestDevice::new("source-archive", &FakeRelay::new(), &TestClock::new());
        fs::create_dir_all(device.env().state_path.parent().unwrap()).unwrap();
        device
    }
    fn owner() -> Workspace {
        super::super::workspace::tests::enrolled()
    }
    fn root(env: &SyncEnv) -> std::path::PathBuf {
        env.state_path
            .parent()
            .unwrap()
            .join("central-source-archives")
    }
    #[test]
    fn independent_ciphertext_readback_is_private_retryable_and_preserves_all_prior_snapshots() {
        use std::os::unix::fs::PermissionsExt;
        let device = device();
        let env = device.env();
        let owner = owner();
        let life = env.runtime.lifecycle.lock().unwrap();
        let profile = owner.control.profile.profile().unwrap();
        let plain = Zeroizing::new(
            b"PRIVATE_SOURCE_SENTINEL: original vault, source key and pending data".to_vec(),
        );
        let archive = create(&env, &life, &owner, 0, &plain).unwrap();
        let receipt = archive.receipt();
        let file = root(&env).join(receipt.context.filename().unwrap());
        let bytes = fs::read(&file).unwrap();
        assert!(!bytes
            .windows(b"PRIVATE_SOURCE_SENTINEL:".len())
            .any(|v| v == b"PRIVATE_SOURCE_SENTINEL:"));
        assert!(!String::from_utf8_lossy(&bytes).contains("plaintext_hash"));
        assert!(!serde_json::to_string(receipt)
            .unwrap()
            .contains("PRIVATE_SOURCE_SENTINEL"));
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            restore(&env, &profile, receipt).unwrap().as_slice(),
            plain.as_slice()
        );
        assert_eq!(
            resume(&env, &life, &owner, receipt, &plain)
                .unwrap()
                .receipt(),
            receipt
        );
        let role = receipt.context.key_role(&profile).unwrap();
        let key_before = device.keychain.entry(&role).unwrap();
        let changed = Zeroizing::new(b"PRIVATE_SOURCE_SENTINEL: later local B".to_vec());
        assert!(resume(&env, &life, &owner, receipt, &changed).is_err());
        let next = next(&env, &life, &owner, 1, receipt, &changed).unwrap();
        assert_eq!(next.receipt().operation(), receipt.operation());
        assert_ne!(next.receipt().context.snapshot, receipt.context.snapshot);
        assert_eq!(device.keychain.entry(&role).unwrap(), key_before);
        let nonce = |bytes: &[u8]| {
            let size = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
            serde_json::from_slice::<Header>(&bytes[12..12 + size])
                .unwrap()
                .nonce
        };
        let later = fs::read(root(&env).join(next.receipt().context.filename().unwrap())).unwrap();
        assert_ne!(nonce(&bytes), nonce(&later));

        assert_eq!(fs::read(&file).unwrap(), bytes);
        assert_eq!(
            restore(&env, &profile, next.receipt()).unwrap().as_slice(),
            changed.as_slice()
        );
        assert!(env.runtime.core.lock().unwrap().records.is_none());
    }
    #[test]
    fn missing_marker_key_or_both_never_recreates_a_resume_key_or_replaces_an_archive() {
        for missing in ["marker", "key", "both", "blob"] {
            let device = device();
            let env = device.env();
            let owner = owner();
            let life = env.runtime.lifecycle.lock().unwrap();
            let profile = owner.control.profile.profile().unwrap();
            let plain = Zeroizing::new(b"synthetic unique source".to_vec());
            let archived = create(&env, &life, &owner, 0, &plain).unwrap();
            let receipt = archived.receipt();
            let role = receipt.context.key_role(&profile).unwrap();
            let original = device.keychain.entry(&role);
            let path = root(&env).join(receipt.context.filename().unwrap());
            let bytes = fs::read(&path).unwrap();
            if missing == "marker" || missing == "both" {
                fs::remove_file(root(&env).join(receipt.context.marker())).unwrap();
            }
            if missing == "key" || missing == "both" {
                device.keychain.delete(&role).unwrap();
            }
            if missing == "blob" {
                fs::remove_file(&path).unwrap();
            }
            let before = device.keychain.entry(&role);
            assert!(restore(&env, &profile, receipt).is_err());
            assert!(resume(&env, &life, &owner, receipt, &plain).is_err());
            assert!(next(&env, &life, &owner, 1, receipt, &plain).is_err());
            assert_eq!(device.keychain.entry(&role), before);
            if missing != "blob" {
                assert_eq!(fs::read(&path).unwrap(), bytes);
            } else {
                assert!(!path.exists());
            }
            if missing == "marker" || missing == "blob" {
                assert_eq!(before, original);
            }
        }
    }
    #[test]
    fn malformed_or_wrong_scope_keys_and_unauthorized_receipts_fail_without_repair() {
        let device = device();
        let env = device.env();
        let owner = owner();
        let profile = owner.control.profile.profile().unwrap();
        let life = env.runtime.lifecycle.lock().unwrap();
        let plain = Zeroizing::new(b"source A".to_vec());
        let archived = create(&env, &life, &owner, 0, &plain).unwrap();
        let receipt = archived.receipt();
        let role = receipt.context.key_role(&profile).unwrap();
        let original = device.keychain.entry(&role).unwrap();
        let bytes = fs::read(root(&env).join(receipt.context.filename().unwrap())).unwrap();
        for encoded in [
            "PRIVATE_SENTINEL".into(),
            serde_json::to_string(&StoredKey {
                version: 1,
                scope: "0".repeat(64),
                key: Zeroizing::new(B64.encode([9u8; 32])),
            })
            .unwrap(),
        ] {
            device.keychain.set(&role, &encoded).unwrap();
            let error = restore(&env, &profile, receipt).unwrap_err().to_string();
            assert!(!error.contains("PRIVATE_SENTINEL"));
            assert!(resume(&env, &life, &owner, receipt, &plain).is_err());
            assert_eq!(device.keychain.entry(&role).unwrap(), encoded);
        }
        device.keychain.set(&role, &original).unwrap();
        let other =
            Profile::new(&profile.origin, &profile.issuer, "different native profile").unwrap();
        assert!(restore(&env, &other, receipt).is_err());
        let mut changed = receipt.clone();
        changed.context.anchor.account_id = "b".repeat(64);
        assert!(restore(&env, &profile, &changed).is_err());
        let mut changed = receipt.clone();
        changed.bytes += 1;
        assert!(restore(&env, &profile, &changed).is_err());
        assert_eq!(
            fs::read(root(&env).join(receipt.context.filename().unwrap())).unwrap(),
            bytes
        );
    }
    #[test]
    fn source_codec_authenticates_every_header_field_and_rejects_truncation_wrong_keys_and_extra_fields(
    ) {
        let owner = owner();
        let context = Context::fresh(&owner, 0).unwrap();
        let key = [8u8; 32];
        let bytes = encode(&context, &key, b"unique private source").unwrap();
        assert_eq!(
            decode(&context, &key, &bytes).unwrap().as_slice(),
            b"unique private source"
        );
        assert!(decode(&context, &[9u8; 32], &bytes).is_err());
        for length in [0, 7, 11, bytes.len() - 1] {
            assert!(decode(&context, &key, &bytes[..length]).is_err());
        }
        let size = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let value: serde_json::Value = serde_json::from_slice(&bytes[12..12 + size]).unwrap();
        for change in ["generation", "nonce", "length", "extra"] {
            let mut value = value.clone();
            match change {
                "generation" => value["context"]["generation"] = "1".into(),
                "nonce" => value["nonce"] = B64.encode([1u8; 24]).into(),
                "length" => value["plaintext_bytes"] = (MAX_PLAIN as u64 + 1).into(),
                _ => value["unrecognized"] = "PRIVATE_SENTINEL".into(),
            };
            let header = serde_json::to_vec(&value).unwrap();
            let mut changed = bytes[..8].to_vec();
            changed.extend_from_slice(&(header.len() as u32).to_be_bytes());
            changed.extend(header);
            changed.extend_from_slice(&bytes[12 + size..]);
            assert!(decode(&context, &key, &changed).is_err());
        }
        assert!(encode(&context, &key, b"").is_err());
        let mut changed = context.clone();
        changed.snapshot = "../../escape".into();
        assert!(changed.filename().is_err());
    }
    struct NoPrompt<'a> {
        memory: &'a crate::sync::testkit::MemKeychain,
        allow_creation: bool,
        locked: std::sync::atomic::AtomicBool,
    }
    impl Keychain for NoPrompt<'_> {
        fn get(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("archive reads cannot prompt or fall back to an interactive read")
        }
        fn get_noninteractive(&self, role: &str) -> Result<Option<String>, AppError> {
            assert!(role.starts_with("central:v2:source-archive-"));
            if self.locked.load(Ordering::SeqCst) {
                return Err(AppError::Other(
                    "needs interaction: synthetic locked keychain".into(),
                ));
            }
            self.memory.get(role)
        }
        fn set(&self, role: &str, value: &str) -> Result<(), AppError> {
            assert!(
                self.allow_creation,
                "readback cannot create or repair a protected key"
            );
            assert!(
                self.memory.entry(role).is_none(),
                "fresh creation cannot replace a protected item"
            );
            self.memory.set(role, value)
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("archive cannot erase a protected key")
        }
    }
    #[test]
    fn all_archive_key_reads_are_noninteractive_and_locked_restore_never_falls_back_or_repairs() {
        let device = device();
        let owner = owner();
        let profile = owner.control.profile.profile().unwrap();
        let creation = NoPrompt {
            memory: &device.keychain,
            allow_creation: true,
            locked: std::sync::atomic::AtomicBool::new(false),
        };
        let mut env = device.env();
        env.keychain = &creation;
        let life = env.runtime.lifecycle.lock().unwrap();
        let plain = Zeroizing::new(b"independent private source".to_vec());
        let archived = create(&env, &life, &owner, 0, &plain).unwrap();
        let readonly = NoPrompt {
            memory: &device.keychain,
            allow_creation: false,
            locked: std::sync::atomic::AtomicBool::new(false),
        };
        let mut env = device.env();
        env.keychain = &readonly;
        assert_eq!(
            restore(&env, &profile, archived.receipt())
                .unwrap()
                .as_slice(),
            plain.as_slice()
        );
        assert_eq!(
            archived
                .outputs(&env, &profile, &plain)
                .unwrap()
                .files()
                .count(),
            2
        );
        let role = archived.receipt().context.key_role(&profile).unwrap();
        let stored = device.keychain.entry(&role).unwrap();
        readonly.locked.store(true, Ordering::SeqCst);
        assert!(restore(&env, &profile, archived.receipt()).is_err());
        assert!(archived.outputs(&env, &profile, &plain).is_err());
        assert!(resume(&env, &life, &owner, archived.receipt(), &plain).is_err());
        assert!(next(&env, &life, &owner, 1, archived.receipt(), &plain).is_err());
        assert_eq!(device.keychain.entry(&role).unwrap(), stored);
    }
    struct LostReadback {
        reads: AtomicUsize,
        stored: std::sync::Mutex<Option<String>>,
        lose_on: usize,
    }
    impl Keychain for LostReadback {
        fn get_noninteractive(&self, role: &str) -> Result<Option<String>, AppError> {
            self.get(role)
        }

        fn get(&self, role: &str) -> Result<Option<String>, AppError> {
            assert!(role.starts_with("central:v2:source-archive-"));
            let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            if read >= self.lose_on {
                return Ok(None);
            }
            Ok(self.stored.lock().unwrap().clone())
        }
        fn set(&self, _: &str, value: &str) -> Result<(), AppError> {
            *self.stored.lock().unwrap() = Some(value.into());
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("archive cannot delete a credential")
        }
    }
    #[test]
    fn failed_os_readback_or_a_lost_key_before_final_receipt_never_claims_a_durable_source_backup()
    {
        for lose_on in [2, 3] {
            let device = device();
            let memory = LostReadback {
                reads: AtomicUsize::new(0),
                stored: std::sync::Mutex::new(None),
                lose_on,
            };
            let mut env = device.env();
            env.keychain = &memory;
            let life = env.runtime.lifecycle.lock().unwrap();
            assert!(create(
                &env,
                &life,
                &owner(),
                0,
                &Zeroizing::new(b"synthetic unique source".to_vec())
            )
            .is_err());
            assert!(env.runtime.core.lock().unwrap().records.is_none());
            if lose_on == 2 {
                assert_eq!(fs::read_dir(root(&env)).unwrap().count(), 0);
            }
        }
    }
}
