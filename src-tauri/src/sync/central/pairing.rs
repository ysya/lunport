//! The out-of-band secret authenticates root adoption in both directions. It is never uploaded.
use super::{
    crypto::{self, DeviceKeys},
    membership::{Action, Device, Enrollment, SignedMembership, TrustAnchor, TrustedMembership},
    trust::{ControlProof, VerifiedChain},
    wire::{canonical, hex, invalid},
};
use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};
type HmacSha256 = Hmac<Sha256>;
const CODE_PREFIX: &str = "LPPAIR2:";
fn anchor(request: &Enrollment) -> TrustAnchor {
    TrustAnchor {
        origin: request.origin.clone(),
        account_id: request.account_id.clone(),
        genesis_hash: request.genesis_hash.clone(),
    }
}
fn request_digest(request: &Enrollment) -> Result<String, AppError> {
    Ok(crypto::hash(&canonical(&[
        "lunport-pairing-request-v2",
        &B64.encode(request.canonical()?),
        &request.signature,
    ])?))
}
fn confirmation_bytes(request: &Enrollment, head: &str) -> Result<Vec<u8>, AppError> {
    if !hex(head, 64) {
        return Err(invalid());
    }
    canonical(&[
        "lunport-pairing-confirmation-v2",
        &B64.encode(request.canonical()?),
        &request.signature,
        head,
    ])
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingConfirmation {
    pub request_id: String,
    pub approved_head: String,
    pub mac: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    version: u32,
    anchor: TrustAnchor,
    request_id: String,
    request_digest: String,
    secret: String,
}
impl Drop for Code {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
/// No Debug/Serialize. Copy code/secure persistence are explicit secret-bearing operations.
pub struct PendingPairing {
    request: Enrollment,
    secret: Zeroizing<Vec<u8>>,
}
pub struct PairingInvite {
    request: Enrollment,
    secret: Zeroizing<Vec<u8>>,
}
impl PendingPairing {
    /// Claimed root is provisional until the approver has proved possession of the OOB secret.
    pub fn begin(
        claimed: &TrustAnchor,
        device_id: &str,
        keys: &DeviceKeys,
        now: u64,
    ) -> Result<Self, AppError> {
        let request = Enrollment::create(claimed, device_id, keys, now)?;
        let mut secret = Zeroizing::new(vec![0; 32]);
        getrandom::fill(&mut secret).map_err(|_| invalid())?;
        Ok(Self { request, secret })
    }
    pub fn request(&self) -> &Enrollment {
        &self.request
    }
    pub fn code(&self) -> Result<Zeroizing<String>, AppError> {
        let code = Code {
            version: 2,
            anchor: anchor(&self.request),
            request_id: self.request.request_id.clone(),
            request_digest: request_digest(&self.request)?,
            secret: B64.encode(&*self.secret),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&code).map_err(|_| invalid())?);
        let base64 = Zeroizing::new(B64.encode(&*encoded));
        Ok(Zeroizing::new(format!("{CODE_PREFIX}{}", &*base64)))
    }
    pub fn encode_secret(&self) -> Result<Zeroizing<String>, AppError> {
        #[derive(Serialize)]
        struct Stored<'a> {
            request: &'a Enrollment,
            secret: &'a str,
        }
        let secret = Zeroizing::new(B64.encode(&*self.secret));
        Ok(Zeroizing::new(
            serde_json::to_string(&Stored {
                request: &self.request,
                secret: &secret,
            })
            .map_err(|_| invalid())?,
        ))
    }
    pub fn restore(encoded: &str, expected: &Device) -> Result<Self, AppError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            request: Enrollment,
            secret: String,
        }
        impl Drop for Stored {
            fn drop(&mut self) {
                self.secret.zeroize();
            }
        }
        if encoded.len() > 8192 {
            return Err(invalid());
        }
        let stored: Stored = serde_json::from_str(encoded).map_err(|_| invalid())?;
        stored.request.verify_signature()?;
        if &stored.request.device != expected {
            return Err(invalid());
        }
        let secret = Zeroizing::new(crypto::decode(&stored.secret, 32, 32)?);
        Ok(Self {
            request: stored.request.clone(),
            secret,
        })
    }
    pub fn accept(
        &self,
        confirmation: &PairingConfirmation,
        proof: &ControlProof,
    ) -> Result<VerifiedChain, AppError> {
        if confirmation.request_id != self.request.request_id {
            return Err(invalid());
        }
        let mut mac = HmacSha256::new_from_slice(&self.secret).map_err(|_| invalid())?;
        mac.update(&confirmation_bytes(
            &self.request,
            &confirmation.approved_head,
        )?);
        mac.verify_slice(&crypto::decode(&confirmation.mac, 32, 32)?)
            .map_err(|_| {
                AppError::Other("This device approval does not match your pairing code.".into())
            })?;
        let chain = proof.verify(&anchor(&self.request), None)?;
        let confirmed = proof.nodes.iter().enumerate().any(|(index, node)| {
            node.body.action == Action::Add
                && node.body.enrollment.as_ref() == Some(&self.request)
                && chain.head_at(index + 1) == Some(confirmation.approved_head.as_str())
        });
        if !confirmed
            || !chain.contains_device(&confirmation.approved_head, &self.request.device)
            || chain.current().devices().get(&self.request.device.id)
                != Some(&self.request.device.keys)
        {
            return Err(invalid());
        }
        Ok(chain)
    }
}
impl PairingInvite {
    /// The request may be fetched from the service, but its full commitment is in the OOB code.
    pub fn from_code(
        code: &str,
        request: &Enrollment,
        trusted: &TrustAnchor,
        now: u64,
    ) -> Result<Self, AppError> {
        if code.len() > 4096 {
            return Err(invalid());
        }
        let encoded = code.trim().strip_prefix(CODE_PREFIX).ok_or_else(invalid)?;
        let bytes = Zeroizing::new(crypto::decode(encoded, 1, 3072)?);
        let parsed: Code = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        request.verify_live(now)?;
        if parsed.version != 2
            || &parsed.anchor != trusted
            || parsed.anchor != anchor(request)
            || parsed.request_id != request.request_id
            || parsed.request_digest != request_digest(request)?
        {
            return Err(AppError::Other(
                "The pairing code belongs to another request or account.".into(),
            ));
        }
        Ok(Self {
            request: request.clone(),
            secret: Zeroizing::new(crypto::decode(&parsed.secret, 32, 32)?),
        })
    }
    pub fn confirm(
        &self,
        previous: &TrustedMembership,
        node: &SignedMembership,
    ) -> Result<PairingConfirmation, AppError> {
        if previous.anchor() != &anchor(&self.request)
            || node.body.action != Action::Add
            || node.body.enrollment.as_ref() != Some(&self.request)
        {
            return Err(invalid());
        }
        let next = previous.apply(node)?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).map_err(|_| invalid())?;
        mac.update(&confirmation_bytes(&self.request, next.head())?);
        Ok(PairingConfirmation {
            request_id: self.request.request_id.clone(),
            approved_head: next.head().into(),
            mac: B64.encode(mac.finalize().into_bytes()),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::super::membership::Genesis;
    use super::*;
    fn keys(seed: u8) -> DeviceKeys {
        DeviceKeys::decode_secret(&B64.encode([seed; 64])).unwrap()
    }
    #[test]
    fn pairing_tag_matches_an_independent_webcrypto_hmac_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let request: Enrollment = serde_json::from_value(fixture["enrollment"].clone()).unwrap();
        let pending = PendingPairing {
            request: request.clone(),
            secret: Zeroizing::new(vec![9u8; 32]),
        };
        let proof = ControlProof {
            genesis: serde_json::from_value(fixture["genesis"].clone()).unwrap(),
            nodes: vec![serde_json::from_value(fixture["membership_nodes"][0].clone()).unwrap()],
        };
        let confirmation = PairingConfirmation {
            request_id: request.request_id,
            approved_head: "fd334f45161778bffe9874f4729c86896429a6711a2a7806a635f672022e5236"
                .into(),
            mac: "Acu8zJlOUAAVgvJWw3l5EKNirF4THJE/TY2sAxEZ1Gs=".into(),
        };
        assert!(pending.accept(&confirmation, &proof).is_ok());
    }
    #[test]
    fn pairing_authenticates_request_and_root_both_ways_and_rejects_a_server_substituted_device_or_confirmation(
    ) {
        let first = keys(1);
        let next = keys(2);
        let recovery = keys(4);
        let (genesis, root) = Genesis::create(
            "https://relay.test",
            &"a".repeat(64),
            &"f".repeat(32),
            &first,
            &recovery,
        )
        .unwrap();
        let previous = genesis.trust(&root).unwrap();
        let pending = PendingPairing::begin(&root, &"d".repeat(32), &next, 1000).unwrap();
        let code = pending.code().unwrap();
        assert!(!serde_json::to_string(pending.request())
            .unwrap()
            .contains(&B64.encode(&*pending.secret)));
        let invite = PairingInvite::from_code(&code, pending.request(), &root, 1100).unwrap();
        let mut members = previous.devices().clone();
        members.insert(
            pending.request.device.id.clone(),
            pending.request.device.keys.clone(),
        );
        let node = SignedMembership::sign(
            previous.proposal(
                &"f".repeat(32),
                Action::Add,
                Some(pending.request.clone()),
                members,
                previous.recovery().clone(),
                1200,
            ),
            &first,
        )
        .unwrap();
        let confirmation = invite.confirm(&previous, &node).unwrap();
        let proof = ControlProof {
            genesis: genesis.clone(),
            nodes: vec![node.clone()],
        };
        let accepted = pending.accept(&confirmation, &proof).unwrap();
        assert_eq!(accepted.current().devices().len(), 2);
        let restored =
            PendingPairing::restore(&pending.encode_secret().unwrap(), &pending.request.device)
                .unwrap();
        assert!(restored.accept(&confirmation, &proof).is_ok());
        let other = Enrollment::create(&root, &"d".repeat(32), &keys(3), 1000).unwrap();
        assert!(PairingInvite::from_code(&code, &other, &root, 1100).is_err());
        assert!(PairingInvite::from_code(
            &code,
            pending.request(),
            &TrustAnchor {
                genesis_hash: "9".repeat(64),
                ..root.clone()
            },
            1100
        )
        .is_err());
        assert!(PairingInvite::from_code(&code, pending.request(), &root, 10000000).is_err());
        let mut tampered = confirmation.clone();
        tampered.approved_head = "9".repeat(64);
        assert!(pending.accept(&tampered, &proof).is_err());
        tampered = confirmation.clone();
        tampered.mac = B64.encode([0; 32]);
        assert!(pending.accept(&tampered, &proof).is_err());
        assert!(pending
            .accept(
                &confirmation,
                &ControlProof {
                    genesis,
                    nodes: vec![]
                }
            )
            .is_err());
        let mut fork = proof.clone();
        fork.nodes[0].signature = B64.encode([0; 64]);
        assert!(pending.accept(&confirmation, &fork).is_err());
    }
    #[test]
    fn rejects_a_supplied_later_revocation_despite_a_valid_earlier_pairing_confirmation() {
        let first = keys(1);
        let next = keys(2);
        let (genesis, root) = Genesis::create(
            "https://relay.test",
            &"a".repeat(64),
            &"f".repeat(32),
            &first,
            &keys(4),
        )
        .unwrap();
        let previous = genesis.trust(&root).unwrap();
        let pending = PendingPairing::begin(&root, &"d".repeat(32), &next, 1000).unwrap();
        let invite =
            PairingInvite::from_code(&pending.code().unwrap(), pending.request(), &root, 1100)
                .unwrap();
        let mut members = previous.devices().clone();
        members.insert(
            pending.request.device.id.clone(),
            pending.request.device.keys.clone(),
        );
        let add = SignedMembership::sign(
            previous.proposal(
                &"f".repeat(32),
                Action::Add,
                Some(pending.request.clone()),
                members,
                previous.recovery().clone(),
                1200,
            ),
            &first,
        )
        .unwrap();
        let confirmation = invite.confirm(&previous, &add).unwrap();
        let added = previous.apply(&add).unwrap();
        let revoke = SignedMembership::sign(
            added.proposal(
                &"f".repeat(32),
                Action::Revoke,
                None,
                previous.devices().clone(),
                previous.recovery().clone(),
                1300,
            ),
            &first,
        )
        .unwrap();
        assert!(pending
            .accept(
                &confirmation,
                &ControlProof {
                    genesis,
                    nodes: vec![add, revoke]
                }
            )
            .is_err());
    }
}
