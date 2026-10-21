//! A separate additive enrollment, authenticated by a decrypted account unlock authority.
//! It cannot turn a login token, server response or partial replica into device approval.
use super::{
    crypto::{self, DeviceKeys, WrappedKeys},
    membership::{Action, SignedMembership},
    pairing::{PairingConfirmation, PendingPairing},
    recovery::RecoveryKit,
    recovery_read::VerifiedRecovery,
    trust::ControlProof,
    wire::{invalid, WrapHeader},
};
use crate::error::AppError;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub(super) struct Prepared {
    pub node: SignedMembership,
    pub wraps: BTreeMap<String, Vec<WrappedKeys>>,
    pub confirmation: PairingConfirmation,
    pub read_proof: super::recovery::RecoveryReadProof,
}
impl Prepared {
    pub fn create(
        read: &VerifiedRecovery,
        kit: &RecoveryKit,
        identity: &DeviceKeys,
        pending: &PendingPairing,
        now: u64,
    ) -> Result<Self, AppError> {
        read.request().verify_live(now)?;
        if identity.public() != read.request().device.keys || pending.request() != read.request() {
            return Err(invalid());
        }
        let authority = kit.current_keys(read.chain())?;
        let previous = read.chain().current();
        let mut devices = previous.devices().clone();
        if devices
            .insert(read.request().device.id.clone(), identity.public())
            .is_some()
        {
            return Err(invalid());
        }
        let node = SignedMembership::sign(
            previous.proposal(
                "recovery",
                Action::Unlock,
                Some(read.request().clone()),
                devices,
                previous.recovery().clone(),
                now,
            ),
            &authority,
        )?;
        let mut proof = read.proof().clone();
        proof.nodes.push(node.clone());
        let chain = proof.verify(previous.anchor(), Some(&read.chain().highwater()))?;
        let confirmation = pending.confirm_unlock(read, &node)?;
        pending.accept(&confirmation, &proof)?;
        let mut wraps = vec![];
        for (recipient, public) in chain
            .current()
            .devices()
            .iter()
            .map(|(id, key)| (id.as_str(), key))
            .chain(std::iter::once(("recovery", chain.current().recovery())))
        {
            wraps.push(crypto::wrap_keys(
                read.keys(),
                identity,
                WrapHeader {
                    origin: kit.anchor().origin.clone(),
                    account_id: kit.anchor().account_id.clone(),
                    genesis_hash: kit.anchor().genesis_hash.clone(),
                    vault_id: read.replica().vault.clone(),
                    key_epoch: read.checkpoint().epoch.to_string(),
                    membership_head: chain.current().head().into(),
                    author: read.request().device.id.clone(),
                    recipient: recipient.into(),
                    recipient_key: public.encryption.clone(),
                },
            )?);
        }
        Ok(Self {
            node,
            wraps: BTreeMap::from([(read.replica().vault.clone(), wraps)]),
            confirmation,
            read_proof: kit.read_proof(read.chain(), read.request(), read.auth_epoch(), now)?,
        })
    }
    pub fn proof(&self, source: &ControlProof) -> ControlProof {
        let mut proof = source.clone();
        proof.nodes.push(self.node.clone());
        proof
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::central::{recovery_read, wire::MAX_SAFE_INTEGER};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    fn pending(read: &VerifiedRecovery) -> PendingPairing {
        PendingPairing::restore(
            &serde_json::json!({"request":read.request(),"secret":B64.encode([9;32])}).to_string(),
            &read.request().device,
        )
        .unwrap()
    }
    #[test]
    fn complete_read_enrolls_without_losing_devices_or_recovery_and_pins_the_original_data() {
        for rotated in [false, true] {
            let (read, kit, identity) = recovery_read::tests::verified_fresh_case(2, rotated);
            let pending = pending(&read);
            let prepared = Prepared::create(&read, &kit, &identity, &pending, 1000).unwrap();
            let proof = prepared.proof(read.proof());
            let chain = pending.accept(&prepared.confirmation, &proof).unwrap();
            assert_eq!(
                chain.current().devices().len(),
                read.chain().current().devices().len() + 1
            );
            for (id, key) in read.chain().current().devices() {
                assert_eq!(chain.current().devices().get(id), Some(key));
            }
            assert_eq!(
                chain.current().recovery(),
                read.chain().current().recovery()
            );
            let minimum = &prepared.confirmation.minimums[0];
            assert_eq!(minimum.sequence, "2");
            assert_eq!(minimum.history_hash, read.checkpoint().history_hash);
            let wraps = &prepared.wraps[&read.replica().vault];
            assert_eq!(wraps.len(), chain.current().devices().len() + 1);
            let own = wraps
                .iter()
                .find(|w| w.header.recipient == read.request().device.id)
                .unwrap();
            let opened = own
                .open(&identity, &own.header, &identity.public().signing)
                .unwrap();
            opened.verify_same(read.keys()).unwrap();
            let mut bad = prepared.confirmation.clone();
            bad.minimums[0].sequence = "0".into();
            assert!(pending.accept(&bad, &proof).is_err());
            assert!(Prepared::create(
                &read,
                &kit,
                &DeviceKeys::generate().unwrap(),
                &pending,
                1000
            )
            .is_err());
            assert!(Prepared::create(&read, &kit, &identity, &pending, MAX_SAFE_INTEGER).is_err());
        }
    }
}
