//! Public signed ciphertext registry. A caller must pin its highwater in protected storage.
use super::{
    crypto::{self, DeviceKeys, PublicKeys},
    membership::TrustAnchor,
    trust::VerifiedChain,
    unlock_envelope::{Binding, Envelope},
    wire::{canonical, hex, invalid, number, MAX_SAFE_INTEGER},
};
use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body {
    pub version: u32,
    pub anchor: TrustAnchor,
    pub revision: String,
    pub previous_digest: String,
    pub membership_head: String,
    pub authorization_epoch: String,
    pub author: String,
    pub recovery: PublicKeys,
    pub slots: Vec<Envelope>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedRegistry {
    pub body: Body,
    pub signature: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Highwater {
    pub revision: u64,
    pub digest: String,
}
pub(super) struct VerifiedRegistry {
    signed: SignedRegistry,
    highwater: Highwater,
}
pub(super) fn slot_id(envelope: &Envelope) -> Result<String, AppError> {
    envelope.header.aad()?;
    Ok(match &envelope.header.binding {
        Binding::Password => "password".into(),
        Binding::NativePrf { credential_hash } => format!("native_prf:{credential_hash}"),
    })
}
fn envelope_canonical(envelope: &Envelope) -> Result<Vec<u8>, AppError> {
    let id = slot_id(envelope)?;
    crypto::decode(&envelope.nonce, 24, 24)?;
    crypto::decode(&envelope.ciphertext, 17, 4112)?;
    let h = &envelope.header;
    canonical(&[
        "lunport-account-unlock-envelope-v1",
        &h.anchor.origin,
        &h.anchor.account_id,
        &h.anchor.genesis_hash,
        &h.generation,
        &id,
        &h.salt,
        &envelope.nonce,
        &envelope.ciphertext,
    ])
}
impl Body {
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if self.version != 1
            || !hex(&self.membership_head, 64)
            || !hex(&self.author, 32)
            || self.slots.is_empty()
            || self.slots.len() > 8
        {
            return Err(invalid());
        }
        self.recovery.validate()?;
        let revision = number(&self.revision, false)?;
        number(&self.authorization_epoch, false)?;
        if if revision == 1 {
            !self.previous_digest.is_empty()
        } else {
            !hex(&self.previous_digest, 64)
        } {
            return Err(invalid());
        }
        let mut previous = String::new();
        let mut slots = Vec::with_capacity(self.slots.len());
        for envelope in &self.slots {
            let bytes = envelope_canonical(envelope)?;
            let id = slot_id(envelope)?;
            if id <= previous
                || envelope.header.anchor != self.anchor
                || number(&envelope.header.generation, false)? > revision
            {
                return Err(invalid());
            }
            previous = id;
            slots.push(B64.encode(bytes));
        }
        let length = slots.len().to_string();
        let mut fields = vec![
            "lunport-account-unlock-registry-v1",
            "1",
            &self.anchor.origin,
            &self.anchor.account_id,
            &self.anchor.genesis_hash,
            &self.revision,
            &self.previous_digest,
            &self.membership_head,
            &self.authorization_epoch,
            &self.author,
            &self.recovery.signing,
            &self.recovery.encryption,
            &length,
        ];
        fields.extend(slots.iter().map(String::as_str));
        canonical(&fields)
    }
}
impl SignedRegistry {
    pub fn digest(&self) -> Result<String, AppError> {
        crypto::decode(&self.signature, 64, 64)?;
        Ok(crypto::hash(&canonical(&[
            "lunport-account-unlock-proof-v1",
            &B64.encode(self.body.canonical()?),
            &self.signature,
        ])?))
    }
    pub fn verify(
        &self,
        chain: &VerifiedChain,
        minimum: Option<&Highwater>,
    ) -> Result<VerifiedRegistry, AppError> {
        let b = &self.body;
        let author = chain
            .author_at(&b.membership_head, &b.author)
            .ok_or_else(invalid)?;
        if &b.anchor != chain.current().anchor()
            || chain.recovery_at(&b.membership_head) != Some(&b.recovery)
        {
            return Err(invalid());
        }
        crypto::verify(&author.signing, &b.canonical()?, &self.signature)?;
        let highwater = Highwater {
            revision: number(&b.revision, false)?,
            digest: self.digest()?,
        };
        if let Some(minimum) = minimum {
            if minimum.revision == 0
                || minimum.revision > MAX_SAFE_INTEGER
                || !hex(&minimum.digest, 64)
                || highwater.revision < minimum.revision
                || highwater.revision == minimum.revision && highwater.digest != minimum.digest
            {
                return Err(AppError::Other(
                    "The account unlock data was rolled back or forked.".into(),
                ));
            }
        }
        Ok(VerifiedRegistry {
            signed: self.clone(),
            highwater,
        })
    }
    pub fn create(
        chain: &VerifiedChain,
        identity: &DeviceKeys,
        author: &str,
        authorization_epoch: u64,
        before: Option<&VerifiedRegistry>,
        slots: Vec<Envelope>,
    ) -> Result<Self, AppError> {
        let current = chain.current();
        if current.devices().get(author) != Some(&identity.public())
            || authorization_epoch == 0
            || authorization_epoch > MAX_SAFE_INTEGER
        {
            return Err(invalid());
        }
        let revision = before
            .map_or(0, |b| b.highwater.revision)
            .checked_add(1)
            .ok_or_else(invalid)?;
        if let Some(before) = before {
            // A proof verified against another root cannot be copied into this registry.
            if &before.signed.body.anchor != current.anchor() {
                return Err(invalid());
            }
        }
        let body = Body {
            version: 1,
            anchor: current.anchor().clone(),
            revision: revision.to_string(),
            previous_digest: before.map_or(String::new(), |b| b.highwater.digest.clone()),
            membership_head: current.head().into(),
            authorization_epoch: authorization_epoch.to_string(),
            author: author.into(),
            recovery: current.recovery().clone(),
            slots,
        };
        for envelope in &body.slots {
            if number(&envelope.header.generation, false)? == revision {
                continue;
            }
            let old = before
                .filter(|b| b.signed.body.recovery == body.recovery)
                .and_then(|b| {
                    b.signed
                        .body
                        .slots
                        .iter()
                        .find(|old| slot_id(old).ok() == slot_id(envelope).ok())
                });
            if old != Some(envelope) {
                return Err(invalid());
            }
        }
        let signature = identity.sign(&body.canonical()?);
        Ok(Self { body, signature })
    }
}
impl VerifiedRegistry {
    pub fn highwater(&self) -> &Highwater {
        &self.highwater
    }
    pub fn signed(&self) -> &SignedRegistry {
        &self.signed
    }
    pub fn uses_current_authority(&self, chain: &VerifiedChain) -> bool {
        &self.signed.body.anchor == chain.current().anchor()
            && &self.signed.body.recovery == chain.current().recovery()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::central::{membership::Genesis, trust::ControlProof};
    fn fixture() -> (SignedRegistry, VerifiedChain, serde_json::Value) {
        let source: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-unlock-v1.json"))
                .unwrap();
        let registry: SignedRegistry = serde_json::from_value(golden["registry"].clone()).unwrap();
        let genesis: Genesis = serde_json::from_value(source["genesis"].clone()).unwrap();
        let proof = ControlProof {
            genesis,
            nodes: vec![],
        };
        let chain = proof.verify(&registry.body.anchor, None).unwrap();
        (registry, chain, golden)
    }
    #[test]
    fn worker_bytes_signatures_and_digest_match_and_highwater_refuses_replay_or_forks() {
        let (registry, chain, golden) = fixture();
        assert_eq!(
            B64.encode(registry.body.canonical().unwrap()),
            golden["canonical_base64"].as_str().unwrap()
        );
        assert_eq!(
            registry.digest().unwrap(),
            golden["digest"].as_str().unwrap()
        );
        let verified = registry.verify(&chain, None).unwrap();
        assert!(verified.uses_current_authority(&chain));
        assert_eq!(verified.signed(), &registry);
        assert!(registry.verify(&chain, Some(verified.highwater())).is_ok());
        let minimum = Highwater {
            revision: 2,
            digest: crypto::hash(b"newer"),
        };
        assert!(registry.verify(&chain, Some(&minimum)).is_err());
        let minimum = Highwater {
            revision: 1,
            digest: crypto::hash(b"fork"),
        };
        assert!(registry.verify(&chain, Some(&minimum)).is_err());
        let mut changed = registry.clone();
        changed.body.slots[0].nonce = B64.encode([8; 24]);
        assert!(changed.verify(&chain, None).is_err());
        let mut changed = registry;
        changed.body.recovery.signing = chain
            .current()
            .devices()
            .values()
            .next()
            .unwrap()
            .signing
            .clone();
        assert!(changed.verify(&chain, None).is_err());
    }
    #[test]
    fn updates_preserve_unchanged_slots_but_cannot_hide_replacements_under_old_generations() {
        let (registry, chain, _) = fixture();
        let before = registry.verify(&chain, None).unwrap();
        let identity = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        let author = &registry.body.author;
        let mut slots = registry.body.slots.clone();
        let next =
            SignedRegistry::create(&chain, &identity, author, 2, Some(&before), slots.clone())
                .unwrap();
        assert_eq!(next.body.revision, "2");
        assert_eq!(next.body.previous_digest, before.highwater().digest);
        assert!(next.verify(&chain, Some(before.highwater())).is_ok());
        slots[0].nonce = B64.encode([7; 24]);
        assert!(
            SignedRegistry::create(&chain, &identity, author, 2, Some(&before), slots.clone())
                .is_err()
        );
        slots[0].header.generation = "2".into();
        assert!(SignedRegistry::create(&chain, &identity, author, 2, Some(&before), slots).is_ok());
    }
}
