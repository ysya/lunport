//! russh's `Signer` backed by the app's key vault (`sshelter_lib::vault::material::Material::sign`).
//!
//! The contract, read from russh 0.64.1 (`auth.rs`, `client/encrypted.rs`, `keys/agent/client.rs` on docs.rs):
//! - `to_sign` is `string(session id) || SSH_MSG_USERAUTH_REQUEST ...` with the public key, but no signature yet: exactly the bytes to sign.
//! - the returned buffer must be `to_sign` unchanged, followed by the signature as one SSH string (`u32 length || signature blob`);
//!   russh then cuts the session id off the front and sends the rest. This is what russh's own `AgentClient::sign_request` returns.
//! - `Material::sign` returns the signature blob (`string algorithm || string signature`) the SSH agent protocol uses, so the length prefix is all that is missing.
//! - for RSA the algorithm comes from `hash_alg`: `Some(Sha512)` is flag 4 and `Some(Sha256)` is flag 2 (the agent protocol's flags,
//!   `SSH_AGENT_RSA_SHA2_512` / `_256`), `None` is flag 0, which is `ssh-rsa` (SHA-1). Other key types ignore the flag.

use std::sync::Arc;

use russh::keys::agent::AgentIdentity;
use russh::keys::HashAlg;
use sshelter_lib::vault::material::{Material, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error(transparent)]
    Send(#[from] russh::SendError),
    #[error("the vault could not sign: {0}")]
    Sign(String),
}

pub struct VaultSigner {
    material: Arc<Material>,
    /// How many times russh asked for a signature.
    pub calls: usize,
    /// The flag handed to `Material::sign` the last time.
    pub last_flags: u32,
    /// The algorithm name inside the last signature blob ("ssh-ed25519", "rsa-sha2-512", ...).
    pub last_algorithm: Option<String>,
}

impl VaultSigner {
    pub fn new(material: Material) -> VaultSigner {
        VaultSigner { material: Arc::new(material), calls: 0, last_flags: 0, last_algorithm: None }
    }
}

impl russh::Signer for VaultSigner {
    type Error = SignerError;

    async fn auth_sign(&mut self, key: &AgentIdentity, hash_alg: Option<HashAlg>, to_sign: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        // The agent protocol's flag only means something for RSA keys, but russh hands over its `hash_alg` whatever the key type is.
        let flags = if key.public_key().algorithm().is_rsa() {
            match hash_alg {
                Some(HashAlg::Sha512) => SSH_AGENT_RSA_SHA2_512,
                Some(HashAlg::Sha256) => SSH_AGENT_RSA_SHA2_256,
                _ => 0,
            }
        } else {
            0
        };
        // The design says the vault is called through spawn_blocking from the connection runtime (RSA signing takes milliseconds).
        let material = Arc::clone(&self.material);
        let (to_sign, blob) = tokio::task::spawn_blocking(move || {
            let blob = material.sign(&to_sign, flags).map_err(|error| error.to_string());
            (to_sign, blob)
        })
        .await
        .map_err(|error| SignerError::Sign(error.to_string()))?;
        let blob = blob.map_err(SignerError::Sign)?;

        self.calls += 1;
        self.last_flags = flags;
        self.last_algorithm = algorithm_of(&blob);

        let mut signed = to_sign;
        signed.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        signed.extend_from_slice(&blob);
        Ok(signed)
    }
}

/// The first SSH string of a signature blob: the algorithm name.
fn algorithm_of(blob: &[u8]) -> Option<String> {
    let length = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    String::from_utf8(blob.get(4..4 + length)?.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::algorithm_of;

    #[test]
    fn the_algorithm_is_the_first_ssh_string_of_the_blob() {
        let mut blob = vec![0, 0, 0, 11];
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&[0, 0, 0, 2, 9, 9]);
        assert_eq!(algorithm_of(&blob).as_deref(), Some("ssh-ed25519"));
        assert_eq!(algorithm_of(&[0, 0, 0, 5, b'a']), None, "a length that runs past the end");
        assert_eq!(algorithm_of(&[0, 0]), None, "no room for a length");
    }
}
