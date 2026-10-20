//! Signed control history. Server responses become trusted only against a locally anchored root.
use super::{
    crypto::{self, DeviceKeys, PublicKeys},
    wire::{canonical, hex, invalid, number, origin},
};
use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
const MAX_MEMBERS: usize = 64; // Protocol resource bound, not a promised product capacity.
const ENROLLMENT_TTL_MS: u64 = 15 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub keys: PublicKeys,
}
impl Device {
    fn validate(&self) -> Result<(), AppError> {
        if !hex(&self.id, 32) {
            return Err(invalid());
        }
        self.keys.validate()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchor {
    pub origin: String,
    pub account_id: String,
    pub genesis_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub origin: String,
    pub account_id: String,
    pub nonce: String,
    pub first: Device,
    pub recovery: PublicKeys,
    pub device_signature: String,
    pub recovery_signature: String,
}
impl Genesis {
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if !origin(&self.origin) || !hex(&self.account_id, 64) || !hex(&self.nonce, 64) {
            return Err(invalid());
        }
        self.first.validate()?;
        self.recovery.validate()?;
        if self.first.keys.signing == self.recovery.signing
            || self.first.keys.encryption == self.recovery.encryption
        {
            return Err(invalid());
        }
        canonical(&[
            "lunport-genesis-v2",
            &self.origin,
            &self.account_id,
            &self.nonce,
            &self.first.id,
            &self.first.keys.signing,
            &self.first.keys.encryption,
            &self.recovery.signing,
            &self.recovery.encryption,
        ])
    }
    pub fn create(
        origin: &str,
        account_id: &str,
        first_id: &str,
        first: &DeviceKeys,
        recovery: &DeviceKeys,
    ) -> Result<(Self, TrustAnchor), AppError> {
        let mut genesis = Self {
            origin: origin.into(),
            account_id: account_id.into(),
            nonce: crypto::random_id(32)?,
            first: Device {
                id: first_id.into(),
                keys: first.public(),
            },
            recovery: recovery.public(),
            device_signature: String::new(),
            recovery_signature: String::new(),
        };
        let bytes = genesis.canonical()?;
        genesis.device_signature = first.sign(&bytes);
        genesis.recovery_signature = recovery.sign(&bytes);
        let anchor = TrustAnchor {
            origin: origin.into(),
            account_id: account_id.into(),
            genesis_hash: crypto::hash(&bytes),
        };
        Ok((genesis, anchor))
    }
    /// Anchor comes from local creation, the trusted pairing channel, or an offline recovery kit.
    pub fn trust(&self, anchor: &TrustAnchor) -> Result<TrustedMembership, AppError> {
        let bytes = self.canonical()?;
        if self.origin != anchor.origin
            || self.account_id != anchor.account_id
            || crypto::hash(&bytes) != anchor.genesis_hash
        {
            return Err(invalid());
        }
        crypto::verify(&self.first.keys.signing, &bytes, &self.device_signature)?;
        crypto::verify(&self.recovery.signing, &bytes, &self.recovery_signature)?;
        Ok(TrustedMembership {
            anchor: anchor.clone(),
            revision: 0,
            head: anchor.genesis_hash.clone(),
            devices: BTreeMap::from([(self.first.id.clone(), self.first.keys.clone())]),
            recovery: self.recovery.clone(),
            seen_devices: BTreeMap::from([(self.first.id.clone(), self.first.keys.clone())]),
            seen_recovery: vec![self.recovery.clone()],
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub origin: String,
    pub account_id: String,
    pub genesis_hash: String,
    pub request_id: String,
    pub device: Device,
    pub nonce: String,
    pub created_at_ms: String,
    pub expires_at_ms: String,
    pub signature: String,
}
impl Enrollment {
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if !origin(&self.origin)
            || ![&self.account_id, &self.genesis_hash, &self.nonce]
                .into_iter()
                .all(|s| hex(s, 64))
            || !hex(&self.request_id, 32)
        {
            return Err(invalid());
        }
        self.device.validate()?;
        let created = number(&self.created_at_ms, false)?;
        let expires = number(&self.expires_at_ms, false)?;
        if expires <= created || expires - created > ENROLLMENT_TTL_MS {
            return Err(invalid());
        }
        canonical(&[
            "lunport-enrollment-v2",
            &self.origin,
            &self.account_id,
            &self.genesis_hash,
            &self.request_id,
            &self.device.id,
            &self.device.keys.signing,
            &self.device.keys.encryption,
            &self.nonce,
            &self.created_at_ms,
            &self.expires_at_ms,
        ])
    }
    pub fn create(
        anchor: &TrustAnchor,
        device_id: &str,
        keys: &DeviceKeys,
        now: u64,
    ) -> Result<Self, AppError> {
        let mut request = Self {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            request_id: crypto::random_id(16)?,
            device: Device {
                id: device_id.into(),
                keys: keys.public(),
            },
            nonce: crypto::random_id(32)?,
            created_at_ms: now.to_string(),
            expires_at_ms: now
                .checked_add(10 * 60 * 1000)
                .ok_or_else(invalid)?
                .to_string(),
            signature: String::new(),
        };
        request.signature = keys.sign(&request.canonical()?);
        Ok(request)
    }
    pub fn verify_live(&self, now: u64) -> Result<(), AppError> {
        self.verify_signature()?;
        if now > number(&self.expires_at_ms, false)?
            || number(&self.created_at_ms, false)? > now.saturating_add(5 * 60 * 1000)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn verify_signature(&self) -> Result<(), AppError> {
        crypto::verify(
            &self.device.keys.signing,
            &self.canonical()?,
            &self.signature,
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Add,
    Revoke,
    Recover,
    Recovery,
}
impl Action {
    fn label(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Revoke => "revoke",
            Self::Recover => "recover",
            Self::Recovery => "recovery",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipBody {
    pub origin: String,
    pub account_id: String,
    pub genesis_hash: String,
    pub revision: String,
    pub previous_head: String,
    pub author: String,
    pub action: Action,
    pub issued_at_ms: String,
    pub enrollment: Option<Enrollment>,
    pub devices: BTreeMap<String, PublicKeys>,
    pub recovery: PublicKeys,
}
impl MembershipBody {
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if !origin(&self.origin)
            || ![&self.account_id, &self.genesis_hash, &self.previous_head]
                .into_iter()
                .all(|s| hex(s, 64))
            || self.author != "recovery" && !hex(&self.author, 32)
            || self.devices.len() > MAX_MEMBERS
        {
            return Err(invalid());
        }
        number(&self.revision, false)?;
        number(&self.issued_at_ms, false)?;
        self.recovery.validate()?;
        let mut members = Vec::new();
        for (id, keys) in &self.devices {
            Device {
                id: id.clone(),
                keys: keys.clone(),
            }
            .validate()?;
            members.push((id, &keys.signing, &keys.encryption));
        }
        let request = self
            .enrollment
            .as_ref()
            .map(|e| e.canonical().map(|b| B64.encode(b)))
            .transpose()?
            .unwrap_or_default();
        let signature = self
            .enrollment
            .as_ref()
            .map(|e| e.signature.as_str())
            .unwrap_or("");
        serde_json::to_vec(&(
            "lunport-membership-v2",
            &self.origin,
            &self.account_id,
            &self.genesis_hash,
            &self.revision,
            &self.previous_head,
            &self.author,
            self.action.label(),
            &self.issued_at_ms,
            request,
            signature,
            members,
            &self.recovery.signing,
            &self.recovery.encryption,
        ))
        .map_err(|_| invalid())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMembership {
    pub body: MembershipBody,
    pub signature: String,
}
impl SignedMembership {
    pub fn sign(body: MembershipBody, keys: &DeviceKeys) -> Result<Self, AppError> {
        let signature = keys.sign(&body.canonical()?);
        Ok(Self { body, signature })
    }
}
/// No Deserialize: an untrusted server snapshot cannot manufacture this type.
#[derive(Clone, Debug)]
pub struct TrustedMembership {
    anchor: TrustAnchor,
    revision: u64,
    head: String,
    devices: BTreeMap<String, PublicKeys>,
    recovery: PublicKeys,
    seen_devices: BTreeMap<String, PublicKeys>,
    seen_recovery: Vec<PublicKeys>,
}
impl TrustedMembership {
    pub fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn head(&self) -> &str {
        &self.head
    }
    pub fn devices(&self) -> &BTreeMap<String, PublicKeys> {
        &self.devices
    }
    pub fn recovery(&self) -> &PublicKeys {
        &self.recovery
    }
    pub fn apply(&self, next: &SignedMembership) -> Result<Self, AppError> {
        let body = &next.body;
        let bytes = body.canonical()?;
        if body.origin != self.anchor.origin
            || body.account_id != self.anchor.account_id
            || body.genesis_hash != self.anchor.genesis_hash
            || body.previous_head != self.head
            || number(&body.revision, false)? != self.revision.checked_add(1).ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        let author = if body.action == Action::Recover {
            if body.author != "recovery" {
                return Err(invalid());
            }
            &self.recovery
        } else {
            self.devices.get(&body.author).ok_or_else(invalid)?
        };
        crypto::verify(&author.signing, &bytes, &next.signature)?;
        let same_retained = body
            .devices
            .iter()
            .all(|(id, keys)| self.devices.get(id).is_some_and(|old| old == keys));
        match body.action {
            Action::Add | Action::Recover => {
                let request = body.enrollment.as_ref().ok_or_else(invalid)?;
                request.verify_signature()?;
                let issued = number(&body.issued_at_ms, false)?;
                if request.origin != self.anchor.origin
                    || request.account_id != self.anchor.account_id
                    || request.genesis_hash != self.anchor.genesis_hash
                    || issued < number(&request.created_at_ms, false)?
                    || issued > number(&request.expires_at_ms, false)?
                {
                    return Err(invalid());
                }
                if self.seen_devices.contains_key(&request.device.id)
                    || self
                        .seen_devices
                        .values()
                        .chain(self.seen_recovery.iter())
                        .any(|old| {
                            old.signing == request.device.keys.signing
                                || old.encryption == request.device.keys.encryption
                        })
                {
                    return Err(invalid());
                }
                if body.devices.get(&request.device.id) != Some(&request.device.keys) {
                    return Err(invalid());
                }
                if body.action == Action::Add {
                    if body.recovery != self.recovery
                        || self.devices.contains_key(&request.device.id)
                        || body.devices.len() != self.devices.len() + 1
                        || self
                            .devices
                            .iter()
                            .any(|(id, keys)| body.devices.get(id) != Some(keys))
                    {
                        return Err(invalid());
                    }
                } else if body.devices.len() != 1 || self.devices.contains_key(&request.device.id) {
                    return Err(invalid());
                }
            }
            Action::Revoke => {
                if body.enrollment.is_some()
                    || body.recovery != self.recovery
                    || !same_retained
                    || body.devices.len() >= self.devices.len()
                {
                    return Err(invalid());
                }
            }
            Action::Recovery => {
                if body.enrollment.is_some()
                    || body.devices != self.devices
                    || body.recovery == self.recovery
                {
                    return Err(invalid());
                }
            }
        }
        let mut seen_devices = self.seen_devices.clone();
        if let Some(request) = &body.enrollment {
            seen_devices.insert(request.device.id.clone(), request.device.keys.clone());
        }
        let mut seen_recovery = self.seen_recovery.clone();
        if body.recovery != self.recovery {
            if seen_devices
                .values()
                .chain(seen_recovery.iter())
                .any(|old| {
                    old.signing == body.recovery.signing
                        || old.encryption == body.recovery.encryption
                })
            {
                return Err(invalid());
            }
            seen_recovery.push(body.recovery.clone());
        }
        Ok(Self {
            anchor: self.anchor.clone(),
            revision: self.revision + 1,
            head: crypto::hash(&bytes),
            devices: body.devices.clone(),
            recovery: body.recovery.clone(),
            seen_devices,
            seen_recovery,
        })
    }

    /// New writes must use the current head and epoch; accepted history is a separate path.
    pub fn verify_write<'a>(
        &self,
        envelope: &'a super::crypto::RecordEnvelope,
        vault_id: &str,
        key_epoch: u64,
        actor: &str,
    ) -> Result<super::crypto::VerifiedRecord<'a>, AppError> {
        let header = &envelope.header;
        if header.origin != self.anchor.origin
            || header.account_id != self.anchor.account_id
            || header.genesis_hash != self.anchor.genesis_hash
            || header.vault_id != vault_id
            || number(&header.key_epoch, false)? != key_epoch
            || header.membership_head != self.head
            || header.author != actor
        {
            return Err(invalid());
        }
        let author = self.devices.get(actor).ok_or_else(invalid)?;
        envelope.verify(&author.signing)
    }
    pub fn open_wrap(
        &self,
        wrapped: &super::crypto::WrappedKeys,
        recipient_id: &str,
        recipient: &DeviceKeys,
        vault_id: &str,
        key_epoch: u64,
    ) -> Result<super::crypto::VaultKeys, AppError> {
        let header = &wrapped.header;
        if header.origin != self.anchor.origin
            || header.account_id != self.anchor.account_id
            || header.genesis_hash != self.anchor.genesis_hash
            || header.vault_id != vault_id
            || number(&header.key_epoch, false)? != key_epoch
            || header.membership_head != self.head
            || header.recipient != recipient_id
        {
            return Err(invalid());
        }
        let author = self.devices.get(&header.author).ok_or_else(invalid)?;
        let expected = if recipient_id == "recovery" {
            &self.recovery
        } else {
            self.devices.get(recipient_id).ok_or_else(invalid)?
        };
        if header.recipient_key != expected.encryption || recipient.public() != *expected {
            return Err(invalid());
        }
        wrapped.open(recipient, header, &author.signing)
    }
    pub fn proposal(
        &self,
        author: &str,
        action: Action,
        enrollment: Option<Enrollment>,
        devices: BTreeMap<String, PublicKeys>,
        recovery: PublicKeys,
        now: u64,
    ) -> MembershipBody {
        MembershipBody {
            origin: self.anchor.origin.clone(),
            account_id: self.anchor.account_id.clone(),
            genesis_hash: self.anchor.genesis_hash.clone(),
            revision: (self.revision + 1).to_string(),
            previous_head: self.head.clone(),
            author: author.into(),
            action,
            issued_at_ms: now.to_string(),
            enrollment,
            devices,
            recovery,
        }
    }
}
/// The personal MVP client can infer its expected Vault even when an untrusted registry omits it.
/// This does not prove latest-data completeness; a missing expected Vault is an availability failure.
pub fn personal_vault_id(anchor: &TrustAnchor) -> Result<String, AppError> {
    if !origin(&anchor.origin) || !hex(&anchor.account_id, 64) || !hex(&anchor.genesis_hash, 64) {
        return Err(invalid());
    }
    Ok(crypto::hash(&canonical(&[
        "lunport-personal-vault-v2",
        &anchor.origin,
        &anchor.account_id,
        &anchor.genesis_hash,
    ])?))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_login_or_server_key_replacement_cannot_approve_a_device() {
        let a = DeviceKeys::generate().unwrap();
        let b = DeviceKeys::generate().unwrap();
        let recovery = DeviceKeys::generate().unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://relay.example",
            &"a".repeat(64),
            &"a".repeat(32),
            &a,
            &recovery,
        )
        .unwrap();
        let trusted = genesis.trust(&anchor).unwrap();
        let request = Enrollment::create(&anchor, &"b".repeat(32), &b, 1000).unwrap();
        request.verify_live(1001).unwrap();
        let mut devices = trusted.devices().clone();
        devices.insert(request.device.id.clone(), request.device.keys.clone());
        let body = trusted.proposal(
            &"a".repeat(32),
            Action::Add,
            Some(request.clone()),
            devices.clone(),
            trusted.recovery().clone(),
            1001,
        );
        assert!(trusted
            .apply(&SignedMembership::sign(body.clone(), &b).unwrap())
            .is_err());
        let approved = SignedMembership::sign(body.clone(), &a).unwrap();
        let next = trusted.apply(&approved).unwrap();
        assert_eq!(next.devices.len(), 2);
        let mut replaced = approved.clone();
        replaced
            .body
            .devices
            .get_mut(&"b".repeat(32))
            .unwrap()
            .encryption = a.public().encryption;
        assert!(trusted.apply(&replaced).is_err());
        assert!(next.apply(&approved).is_err());
        let mut wrong = anchor.clone();
        wrong.genesis_hash = "0".repeat(64);
        assert!(genesis.trust(&wrong).is_err());
        assert!(request.verify_live(1000000).is_err());
        // Even a valid active-author signature cannot silently change an existing key.
        let mut changed = body;
        changed.devices.get_mut(&"a".repeat(32)).unwrap().signing = b.public().signing;
        assert!(trusted
            .apply(&SignedMembership::sign(changed, &a).unwrap())
            .is_err());
    }
    #[test]
    fn revoked_authors_and_forked_heads_are_rejected_but_recovery_can_replace_lost_devices() {
        let a = DeviceKeys::generate().unwrap();
        let b = DeviceKeys::generate().unwrap();
        let recovery = DeviceKeys::generate().unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://relay.example",
            &"a".repeat(64),
            &"a".repeat(32),
            &a,
            &recovery,
        )
        .unwrap();
        let trusted = genesis.trust(&anchor).unwrap();
        let revoked = SignedMembership::sign(
            trusted.proposal(
                &"a".repeat(32),
                Action::Revoke,
                None,
                BTreeMap::new(),
                trusted.recovery().clone(),
                1001,
            ),
            &a,
        )
        .unwrap();
        let empty = trusted.apply(&revoked).unwrap();
        let request = Enrollment::create(&anchor, &"b".repeat(32), &b, 2000).unwrap();
        let devices = BTreeMap::from([(request.device.id.clone(), request.device.keys.clone())]);
        let forged = SignedMembership::sign(
            empty.proposal(
                &"a".repeat(32),
                Action::Add,
                Some(request.clone()),
                devices.clone(),
                empty.recovery().clone(),
                2001,
            ),
            &a,
        )
        .unwrap();
        assert!(empty.apply(&forged).is_err());
        let recovered = SignedMembership::sign(
            empty.proposal(
                "recovery",
                Action::Recover,
                Some(request),
                devices,
                empty.recovery().clone(),
                2001,
            ),
            &recovery,
        )
        .unwrap();
        assert_eq!(empty.apply(&recovered).unwrap().devices.len(), 1);
        let mut fork = recovered;
        fork.body.previous_head = anchor.genesis_hash;
        assert!(empty.apply(&fork).is_err());
    }
    #[test]
    fn fixed_fixture_chain_matches_worker_bytes_and_rejects_replay() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let genesis: Genesis = serde_json::from_value(fixture["genesis"].clone()).unwrap();
        let anchor: TrustAnchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
        assert_eq!(
            B64.encode(genesis.canonical().unwrap()),
            fixture["genesis_canonical_base64"].as_str().unwrap()
        );
        let mut state = genesis.trust(&anchor).unwrap();
        let nodes: Vec<SignedMembership> =
            serde_json::from_value(fixture["membership_nodes"].clone()).unwrap();
        for (i, node) in nodes.iter().enumerate() {
            assert_eq!(
                B64.encode(node.body.canonical().unwrap()),
                fixture["membership_canonical_base64"][i].as_str().unwrap()
            );
            state = state.apply(node).unwrap();
        }
        assert_eq!(
            state.head(),
            fixture["current_membership_head"].as_str().unwrap()
        );
        assert_eq!(state.revision(), 2);
        assert_eq!(state.anchor(), &anchor);
        assert!(state.apply(&nodes[0]).is_err());
    }
    #[test]
    fn authenticated_writes_and_wraps_are_bound_to_current_scope_actor_head_and_epoch() {
        use super::super::crypto::{RecordEnvelope, WrappedKeys};
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let genesis: Genesis = serde_json::from_value(fixture["genesis"].clone()).unwrap();
        let anchor: TrustAnchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
        let nodes: Vec<SignedMembership> =
            serde_json::from_value(fixture["membership_nodes"].clone()).unwrap();
        let approved = genesis.trust(&anchor).unwrap().apply(&nodes[0]).unwrap();
        let record: RecordEnvelope = serde_json::from_value(fixture["record"].clone()).unwrap();
        assert!(approved
            .verify_write(&record, &record.header.vault_id, 1, &record.header.author)
            .is_ok());
        assert!(approved
            .verify_write(&record, &record.header.vault_id, 2, &record.header.author)
            .is_err());
        assert!(approved
            .verify_write(&record, &"9".repeat(64), 1, &record.header.author)
            .is_err());
        assert!(approved
            .verify_write(&record, &record.header.vault_id, 1, &"d".repeat(32))
            .is_err());
        let wrapped: WrappedKeys = serde_json::from_value(fixture["wrap"].clone()).unwrap();
        let recipient =
            DeviceKeys::decode_secret(fixture["recipient_secret"].as_str().unwrap()).unwrap();
        assert!(approved
            .open_wrap(
                &wrapped,
                &"d".repeat(32),
                &recipient,
                &wrapped.header.vault_id,
                1
            )
            .is_ok());
        assert!(approved
            .open_wrap(
                &wrapped,
                &"d".repeat(32),
                &recipient,
                &wrapped.header.vault_id,
                2
            )
            .is_err());
        let revoked = approved.apply(&nodes[1]).unwrap();
        assert!(revoked
            .verify_write(&record, &record.header.vault_id, 1, &record.header.author)
            .is_err());
        assert!(revoked
            .open_wrap(
                &wrapped,
                &"d".repeat(32),
                &recipient,
                &wrapped.header.vault_id,
                1
            )
            .is_err());
    }
}
