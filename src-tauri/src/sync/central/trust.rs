//! Public proofs are serialized; trusted views can only be constructed against a local anchor.
use super::{
    crypto::{hash, PublicKeys},
    membership::{Action, Device, Genesis, SignedMembership, TrustAnchor, TrustedMembership},
    wire::{hex, invalid, MAX_SAFE_INTEGER},
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlProof {
    pub genesis: Genesis,
    pub nodes: Vec<SignedMembership>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Highwater {
    pub revision: u64,
    pub head: String,
}
struct View {
    devices: BTreeMap<String, PublicKeys>,
    recovery: PublicKeys,
}
pub struct VerifiedChain {
    current: TrustedMembership,
    heads: Vec<String>,
    views: BTreeMap<String, View>,
    security_revision: usize,
}
impl ControlProof {
    pub fn verify(
        &self,
        anchor: &TrustAnchor,
        minimum: Option<&Highwater>,
    ) -> Result<VerifiedChain, AppError> {
        if self.nodes.len() > 1024
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > 1048576
        {
            return Err(invalid());
        }
        let mut current = self.genesis.trust(anchor)?;
        let mut heads = vec![current.head().to_string()];
        let mut views = BTreeMap::new();
        views.insert(
            current.head().to_string(),
            View {
                devices: current.devices().clone(),
                recovery: current.recovery().clone(),
            },
        );
        let mut security_revision = 0;
        for (index, node) in self.nodes.iter().enumerate() {
            if !matches!(node.body.action, Action::Add | Action::Unlock) {
                security_revision = index + 1;
            }
            current = current.apply(node)?;
            heads.push(current.head().to_string());
            views.insert(
                current.head().to_string(),
                View {
                    devices: current.devices().clone(),
                    recovery: current.recovery().clone(),
                },
            );
        }
        if let Some(minimum) = minimum {
            if minimum.revision > MAX_SAFE_INTEGER
                || minimum.revision > self.nodes.len() as u64
                || !hex(&minimum.head, 64)
                || heads.get(minimum.revision as usize) != Some(&minimum.head)
            {
                return Err(AppError::Other(
                    "The account proof was rolled back or forked. Local data has been retained."
                        .into(),
                ));
            }
        }
        Ok(VerifiedChain {
            current,
            heads,
            views,
            security_revision,
        })
    }
}
impl VerifiedChain {
    pub fn current(&self) -> &TrustedMembership {
        &self.current
    }
    pub fn highwater(&self) -> Highwater {
        Highwater {
            revision: self.current.revision(),
            head: self.current.head().into(),
        }
    }
    pub fn contains_device(&self, head: &str, device: &Device) -> bool {
        self.views
            .get(head)
            .is_some_and(|view| view.devices.get(&device.id) == Some(&device.keys))
    }
    pub fn has_head(&self, head: &str) -> bool {
        self.views.contains_key(head)
    }
    pub fn security_revision(&self) -> usize {
        self.security_revision
    }
    pub fn revision_of(&self, head: &str) -> Option<usize> {
        self.heads.iter().position(|known| known == head)
    }
    pub fn head_at(&self, revision: usize) -> Option<&str> {
        self.heads.get(revision).map(String::as_str)
    }
    pub fn author_at(&self, head: &str, device: &str) -> Option<&PublicKeys> {
        self.views.get(head)?.devices.get(device)
    }
    pub fn devices_at(&self, head: &str) -> Option<&BTreeMap<String, PublicKeys>> {
        Some(&self.views.get(head)?.devices)
    }
    pub fn recovery_at(&self, head: &str) -> Option<&PublicKeys> {
        Some(&self.views.get(head)?.recovery)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_server_proof_never_replaces_a_local_root_or_highwater_with_an_older_or_forked_view() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let anchor: TrustAnchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
        let proof = ControlProof {
            genesis: serde_json::from_value(fixture["genesis"].clone()).unwrap(),
            nodes: serde_json::from_value(fixture["membership_nodes"].clone()).unwrap(),
        };
        let chain = proof.verify(&anchor, None).unwrap();
        let minimum = chain.highwater();
        assert!(proof.verify(&anchor, Some(&minimum)).is_ok());
        let short = ControlProof {
            genesis: proof.genesis.clone(),
            nodes: proof.nodes[..1].to_vec(),
        };
        assert!(short.verify(&anchor, Some(&minimum)).is_err());
        let wrong = Highwater {
            head: hash(b"fork"),
            ..minimum
        };
        assert!(proof.verify(&anchor, Some(&wrong)).is_err());
        let wrong = TrustAnchor {
            genesis_hash: hash(b"another root"),
            ..anchor
        };
        assert!(proof.verify(&wrong, None).is_err());
    }
}
