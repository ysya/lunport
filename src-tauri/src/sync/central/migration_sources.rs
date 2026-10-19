//! Complete known legacy chain discovery. Native-only credentials; no I/O, consent or cutover.
use super::{
    client_state::Phase,
    crypto::DeviceKeys,
    migration_freeze::{Body, Progress, SignedFreeze},
    wire::{hex, invalid, MAX_SAFE_INTEGER},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{
        crypto::{self, ChainKeys},
        record::{Record, RecordKind},
        record_conflicts::{RecordRecovery, RecordVersion},
        records_v3::{self, SyncStateV3},
        state_v2::SealedRecord,
    },
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
const MAX_SOURCES: usize = 65;
pub(super) const MAX_BOOK_BYTES: usize = 4 * 1024 * 1024;
mod archive;
mod records;
mod inventory;
pub(super) use inventory::{Inventory, KeyInput, Scope, Position, Known, KnownData, KnownInput};
mod frozen;
mod frozen_set;
mod reconcile;
pub(super) use frozen::{FrozenSnapshot};
pub(super) use frozen_set::{FrozenSet, MAX_FROZEN_BYTES};
struct Temporary(ChainKeys);
impl Drop for Temporary {
    fn drop(&mut self) {
        self.0.clear_sensitive();
    }
}

struct SourceKey {
    token: Zeroizing<String>,
    encryption: Zeroizing<String>,
}
impl SourceKey {
    fn from_keys(keys: &ChainKeys) -> Self {
        Self {
            token: Zeroizing::new(keys.auth_token.clone()),
            encryption: Zeroizing::new(keys.enc_key_b64()),
        }
    }
    fn same(&self, other: &Self) -> bool {
        self.token == other.token && self.encryption == other.encryption
    }
}
/// This deliberately cannot be serialized, logged or exposed through a command.
pub(super) struct Sources {
    parent: String,
    legacy_origin: Option<String>,
    keys: BTreeMap<String, SourceKey>,
    expected: BTreeSet<String>,
    discovery: Option<Box<archive::Discovery>>,
}
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpaceSecret {
    schema: u32,
    #[serde(deserialize_with = "secret")]
    auth_token: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    enc_key: Zeroizing<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretRecord<'a> {
    kind: &'a str,
    id: &'a str,
    version: u64,
    updated_at_ms: u64,
    device_id: &'a str,
    deleted: bool,
    #[serde(borrow)]
    payload: &'a RawValue,
}
impl Sources {
    /// Read-only historical admission. Never discovers or releases a new transport credential.
    fn historical_subset(&self, state: &SyncStateV3) -> Result<Self, AppError> {
        let subset = if let Some(account) = &state.account {
            if account.chain_id != self.parent {
                return Err(invalid());
            }
            let parent = self.keys.get(&self.parent).ok_or_else(invalid)?;
            let keys = Temporary(
                ChainKeys::from_parts(&self.parent, &parent.token, &parent.encryption)
                    .map_err(|_| invalid())?,
            );
            Self::discover(state, Some(&keys.0))?
        } else {
            Self::discover(state, None)?
        };
        if !subset.parent.is_empty() && subset.legacy_origin != self.legacy_origin
            || subset
                .keys
                .iter()
                .any(|(id, key)| self.keys.get(id).is_none_or(|known| !known.same(key)))
        {
            return Err(invalid());
        }
        Ok(subset)
    }
    pub fn discover(
        state: &SyncStateV3,
        account_keys: Option<&ChainKeys>,
    ) -> Result<Self, AppError> {
        records_v3::validate_state(state).map_err(|_| invalid())?;
        if state.rotation.is_some()
            || state.pending_account.is_some()
            || records_v3::account_migration_pending(state)
            || state.local.central_projection.is_some()
            || state
                .local
                .central
                .as_ref()
                .is_some_and(|w| w.control.cutover)
        {
            return Err(invalid());
        }
        let mut result = Self {
            parent: String::new(),
            legacy_origin: None,
            keys: BTreeMap::new(),
            expected: BTreeSet::new(),
            discovery: None,
        };
        let Some(account) = state.account.as_ref() else {
            if account_keys.is_some() || !state.spaces.is_empty() {
                return Err(invalid());
            }
            return Ok(result);
        };
        let relay = reqwest::Url::parse(&state.relay_url).map_err(|_| invalid())?;
        if !["https", "http"].contains(&relay.scheme())
            || relay.path() != "/"
            || relay.query().is_some()
            || relay.fragment().is_some()
            || !relay.username().is_empty()
            || relay.password().is_some()
        {
            return Err(invalid());
        }
        result.legacy_origin = Some(relay.origin().ascii_serialization());
        let account_keys = account_keys.ok_or_else(invalid)?;
        if account_keys.chain_id != account.chain_id || account.frozen.is_some() {
            return Err(invalid());
        }
        result.parent = account.chain_id.clone();
        result.insert(&account.chain_id, SourceKey::from_keys(account_keys))?;
        for row in account.records.values() {
            result.public(&row.record)?;
        }
        result.expected.extend(state.spaces.keys().cloned());
        for row in account.sealed.values().chain(&account.chain_deletes) {
            result.sealed(row, account_keys)?;
        }
        result.recovery(&account.recovery, account_keys)?;
        // A cached or metadata-only collection cannot disappear simply because its key is missing.
        if result
            .expected
            .iter()
            .any(|chain| !result.keys.contains_key(chain))
        {
            return Err(invalid());
        }
        Ok(result)
    }
    fn insert(&mut self, id: &str, key: SourceKey) -> Result<(), AppError> {
        if !hex(id, 64) || !hex(&key.token, 64) {
            return Err(invalid());
        }
        if let Some(known) = self.keys.get(id) {
            if !known.same(&key) {
                return Err(invalid());
            }
            return Ok(());
        }
        if self.keys.len() >= MAX_SOURCES {
            return Err(invalid());
        }
        self.keys.insert(id.into(), key);
        Ok(())
    }
    fn public(&mut self, row: &Record) -> Result<(), AppError> {
        if row.kind == RecordKind::Space {
            if !hex(&row.id, 64) || row.id == self.parent {
                return Err(invalid());
            }
            self.expected.insert(row.id.clone());
        }
        Ok(())
    }
    fn sealed(&mut self, row: &SealedRecord, account: &ChainKeys) -> Result<(), AppError> {
        if row.envelope.kind != "spacekey" {
            return Ok(());
        }
        let envelope = &row.envelope;
        if envelope.ciphertext.len() > 65536 || envelope.nonce.len() > 256 {
            return Err(invalid());
        }
        let bytes = Zeroizing::new(
            crypto::open(
                account,
                &envelope.kind,
                &envelope.id_hash,
                &crypto::Sealed {
                    id_hash: envelope.id_hash.clone(),
                    nonce: envelope.nonce.clone(),
                    ciphertext: envelope.ciphertext.clone(),
                },
            )
            .map_err(|_| invalid())?,
        );
        let opened: SecretRecord<'_> = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if opened.kind != "spacekey"
            || !hex(opened.id, 64)
            || opened.id == self.parent
            || crypto::id_hash(account, opened.kind, opened.id) != envelope.id_hash
            || opened.deleted != envelope.deleted
            || opened.version == 0
            || opened.version > MAX_SAFE_INTEGER
            || opened.updated_at_ms > MAX_SAFE_INTEGER
            || !hex(opened.device_id, 32)
        {
            return Err(invalid());
        }
        self.expected.insert(opened.id.into());
        if opened.deleted {
            return Ok(());
        }
        let secret: SpaceSecret =
            serde_json::from_str(opened.payload.get()).map_err(|_| invalid())?;
        if secret.schema != 1 {
            return Err(invalid());
        }
        // Validate encoding without returning any plaintext JSON Value or parser diagnostics.
        let _decoded = Zeroizing::new(super::crypto::decode(&secret.enc_key, 32, 32)?);
        self.insert(
            opened.id,
            SourceKey {
                token: secret.auth_token,
                encryption: secret.enc_key,
            },
        )
    }
    fn recovery(&mut self, recovery: &RecordRecovery, account: &ChainKeys) -> Result<(), AppError> {
        let mut visit = |version: &RecordVersion| match version {
            RecordVersion::Public(row) => self.public(&row.record),
            RecordVersion::Sealed(row) => self.sealed(row, account),
        };
        for base in recovery.bases.values() {
            visit(base)?;
        }
        for versions in recovery.conflicts.values() {
            for conflict in versions {
                if let Some(base) = &conflict.base {
                    visit(base)?;
                }
                visit(&conflict.local)?;
                visit(&conflict.remote)?;
            }
        }
        Ok(())
    }
    fn require_service(&self, target: &str) -> Result<(), AppError> {
        if !self.keys.is_empty() && self.legacy_origin.as_deref() != Some(target) {
            return Err(AppError::Other("Migrate on the existing relay origin before changing account services. Original data is retained.".into()));
        }
        Ok(())
    }
    pub fn chains(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
    pub fn intent(
        &self,
        owner: &Workspace,
        signer: &DeviceKeys,
        operation: &str,
        preview: &str,
        previous: Option<&Progress>,
    ) -> Result<SignedFreeze, AppError> {
        owner.validate()?;
        self.require_service(&owner.control.profile.origin)?;
        owner.require_key_recipients()?;
        if owner.control.cutover
            || owner.control.phase != Phase::Enrolled
            || owner.control.device.keys != signer.public()
            || owner.bootstrap.is_some()
            || owner.replacement.is_some()
            || owner.rotation.is_some()
            || owner.recovery.is_some()
            || !owner.replacement_archives.is_empty()
        {
            return Err(invalid());
        }
        let chain = owner.control.verified_chain()?;
        let anchor = chain.current().anchor();
        let vault = owner
            .control
            .personal_vault
            .as_deref()
            .ok_or_else(invalid)?;
        let replica = owner.replica.as_ref().ok_or_else(invalid)?;
        if replica.checkpoint.sequence != 0
            || replica.checkpoint.history_hash != "0".repeat(64)
            || !replica.current.is_empty()
            || !replica.pending.is_empty()
            || !replica.conflicts.is_empty()
            || !replica.baseline_ready()
        {
            return Err(invalid());
        }
        replica.verify_write_authority(
            &chain,
            owner.control.auth_epoch,
            replica.checkpoint.epoch,
            &owner.epochs,
        )?;
        let mut body = Body {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: vault.into(),
            migration_id: operation.into(),
            authorization_epoch: owner.control.auth_epoch.to_string(),
            key_epoch: replica.checkpoint.epoch.to_string(),
            membership_head: chain.current().head().into(),
            author: owner.control.device.id.clone(),
            preview_digest: preview.into(),
            parent_chain: self.parent.clone(),
            revision: "1".into(),
            previous_digest: String::new(),
            chains: self.chains(),
        };
        if let Some(previous) = previous {
            previous.verify(&chain, operation, vault, None)?;
            let last = previous.proof.last().ok_or_else(invalid)?;
            // Return the exact prior intent when no context or source changed; do not burn a revision on retry.
            body.revision = last.intent.body.revision.clone();
            body.previous_digest = last.intent.body.previous_digest.clone();
            if body == last.intent.body {
                return Ok(last.intent.clone());
            }
            body.revision = (previous.proof.len() + 1).to_string();
            body.previous_digest = last.digest.clone();
            body.extends(&last.intent.body, &last.digest)?;
        }
        SignedFreeze::sign(body, signer)
    }
    /// The only explicit old-bearer export: bounded native HTTP bytes, never a persistable DTO.
    pub fn freeze_body(
        &self,
        intent: &SignedFreeze,
        next: &[String],
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        intent.body.canonical()?;
        self.require_service(&intent.body.origin)?;
        if intent.body.chains != self.chains()
            || intent.body.parent_chain != self.parent
            || next.len() > 8
        {
            return Err(invalid());
        }
        #[derive(Serialize)]
        struct Credential<'a> {
            chain: &'a str,
            token: &'a str,
        }
        #[derive(Serialize)]
        struct Request<'a> {
            intent: &'a SignedFreeze,
            credentials: Vec<Credential<'a>>,
        }
        let order = intent.body.source_order();
        let mut last = None;
        let mut credentials = vec![];
        for chain in next {
            let index = order
                .iter()
                .position(|id| *id == chain)
                .ok_or_else(invalid)?;
            if last.is_some_and(|before| index <= before) {
                return Err(invalid());
            }
            let key = self.keys.get(chain).ok_or_else(invalid)?;
            credentials.push(Credential {
                chain,
                token: &key.token,
            });
            last = Some(index);
        }
        serde_json::to_vec(&Request {
            intent,
            credentials,
        })
        .map(Zeroizing::new)
        .map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        record::{record_key, LocalRecord, SpaceKeyPayload, SpacePayload},
        record_conflicts::RecordConflict,
        records_v3::SpaceStateV3,
        state_v2::AccountState,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde_json::json;
    fn state() -> (SyncStateV3, ChainKeys) {
        let parent = ChainKeys::generate().unwrap();
        let mut state: SyncStateV3 = serde_json::from_value(json!({
            "version":7,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example",
            "last_sync_ms":null,"last_error":null
        })).unwrap();
        state.account = Some(AccountState::new(&parent.chain_id));
        (state, parent)
    }
    fn sealed(parent: &ChainKeys, key: &ChainKeys, deleted: bool) -> SealedRecord {
        SealedRecord::seal(
            parent,
            &Record {
                kind: RecordKind::SpaceKey,
                id: key.chain_id.clone(),
                version: 1,
                updated_at_ms: 1,
                device_id: "d".repeat(32),
                deleted,
                payload: if deleted {
                    serde_json::Value::Null
                } else {
                    serde_json::to_value(SpaceKeyPayload::from_keys(key)).unwrap()
                },
            },
            0,
        )
        .unwrap()
    }
    fn collection(state: &mut SyncStateV3, key: &ChainKeys, cached: Option<bool>) {
        let row = Record {
            kind: RecordKind::Space,
            id: key.chain_id.clone(),
            version: 1,
            updated_at_ms: 1,
            device_id: state.device_id.clone(),
            deleted: false,
            payload: serde_json::to_value(SpacePayload {
                schema: 1,
                name: "Synthetic".into(),
                slug: "synthetic".into(),
                created_at_ms: 1,
                previous_id: None,
            })
            .unwrap(),
        };
        state.account.as_mut().unwrap().records.insert(
            record_key(row.kind, &row.id),
            LocalRecord {
                record: row,
                seq: 1,
                dirty: false,
            },
        );
        if let Some(selected) = cached {
            state.spaces.insert(
                key.chain_id.clone(),
                SpaceStateV3 {
                    selected,
                    ..Default::default()
                },
            );
        }
    }
    fn owner() -> (Workspace, DeviceKeys) {
        let mut owner = super::super::workspace::tests::enrolled();
        let replica = owner.replica.as_mut().unwrap();
        replica.current.clear();
        replica.pending.clear();
        replica.conflicts.clear();
        replica.checkpoint.sequence = 0;
        replica.checkpoint.history_hash = "0".repeat(64);
        (
            owner,
            DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap(),
        )
    }
    #[test]
    fn includes_selected_unselected_metadata_only_dirty_retired_and_recovery_sources() {
        let (mut state, parent) = state();
        let all: Vec<_> = (0..6).map(|_| ChainKeys::generate().unwrap()).collect();
        for (index, key) in all.iter().enumerate() {
            collection(
                &mut state,
                key,
                match index {
                    0 => Some(true),
                    1 => Some(false),
                    _ => None,
                },
            );
            let mut row = sealed(&parent, key, false);
            let account = state.account.as_mut().unwrap();
            match index {
                0..=2 => {
                    account.sealed.insert(row.key(), row);
                }
                3 => account.chain_deletes.push(row),
                4 => {
                    row.dirty = false;
                    account
                        .recovery
                        .bases
                        .insert(row.key(), RecordVersion::Sealed(row));
                }
                _ => {
                    row.dirty = false;
                    let clean = RecordVersion::Sealed(row.clone());
                    row.dirty = true;
                    account.recovery.conflicts.insert(
                        row.key(),
                        vec![RecordConflict {
                            base: Some(clean.clone()),
                            local: RecordVersion::Sealed(row),
                            remote: clean,
                        }],
                    );
                }
            }
        }
        records_v3::validate_state(&state).unwrap();
        let source = Sources::discover(&state, Some(&parent)).unwrap();
        assert_eq!(source.chains().len(), 7);
        assert_eq!(source.parent, parent.chain_id);
        for key in &all {
            assert!(source.keys.contains_key(&key.chain_id));
        }
        // Reversing selection never changes source coverage or credentials.
        for space in state.spaces.values_mut() {
            space.selected = !space.selected;
        }
        let again = Sources::discover(&state, Some(&parent)).unwrap();
        assert_eq!(source.chains(), again.chains());
        for (id, key) in source.keys {
            assert!(again.keys[&id].same(&key));
        }
    }
    #[test]
    fn tombstones_require_retained_live_credentials_and_never_discard_the_deleted_source() {
        let (mut state, parent) = state();
        let child = ChainKeys::generate().unwrap();
        collection(&mut state, &child, None);
        let deleted = sealed(&parent, &child, true);
        state
            .account
            .as_mut()
            .unwrap()
            .sealed
            .insert(deleted.key(), deleted);
        assert!(Sources::discover(&state, Some(&parent)).is_err());
        state
            .account
            .as_mut()
            .unwrap()
            .chain_deletes
            .push(sealed(&parent, &child, false));
        assert_eq!(
            Sources::discover(&state, Some(&parent))
                .unwrap()
                .chains()
                .len(),
            2
        );
    }
    #[test]
    fn contradictory_keys_or_unreadable_sealed_rows_block_instead_of_choosing_a_winner() {
        let (mut state, parent) = state();
        let child = ChainKeys::generate().unwrap();
        let original = sealed(&parent, &child, false);
        state
            .account
            .as_mut()
            .unwrap()
            .sealed
            .insert(original.key(), original.clone());
        let other = ChainKeys::from_parts(&child.chain_id, &"f".repeat(64), &B64.encode([8u8; 32]))
            .unwrap();
        let mut conflict = sealed(&parent, &other, false);
        conflict.dirty = false;
        state.account.as_mut().unwrap().recovery.conflicts.insert(
            conflict.key(),
            vec![RecordConflict {
                base: None,
                local: RecordVersion::Sealed(original),
                remote: RecordVersion::Sealed(conflict),
            }],
        );
        assert!(Sources::discover(&state, Some(&parent)).is_err());
        state.account.as_mut().unwrap().recovery = Default::default();
        state
            .account
            .as_mut()
            .unwrap()
            .sealed
            .values_mut()
            .next()
            .unwrap()
            .envelope
            .ciphertext = "A".repeat(64);
        assert!(Sources::discover(&state, Some(&parent)).is_err());
        assert!(Sources::discover(&state, None).is_err());
        assert!(Sources::discover(&state, Some(&ChainKeys::generate().unwrap())).is_err());
    }
    #[test]
    fn missing_cached_or_metadata_source_and_capacity_excess_never_produce_a_partial_inventory() {
        let (mut state, parent) = state();
        let child = ChainKeys::generate().unwrap();
        collection(&mut state, &child, Some(false));
        assert!(Sources::discover(&state, Some(&parent)).is_err());
        state.spaces.clear();
        assert!(Sources::discover(&state, Some(&parent)).is_err());
        state.account.as_mut().unwrap().records.clear();
        for _ in 0..65 {
            let key = ChainKeys::generate().unwrap();
            let row = sealed(&parent, &key, false);
            state
                .account
                .as_mut()
                .unwrap()
                .sealed
                .insert(row.key(), row);
        }
        assert!(Sources::discover(&state, Some(&parent)).is_err());
    }
    #[test]
    fn legacy_bearers_cannot_be_encoded_for_another_service_or_unsupported_relay_endpoint() {
        let (mut state, parent) = state();
        let (owner, signer) = owner();
        let allowed = Sources::discover(&state, Some(&parent)).unwrap();
        let intent = allowed
            .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
            .unwrap();
        for origin in [
            "https://other-relay.example",
            "https://relay.example/another-relay",
            "https://user@relay.example",
            "https://relay.example/?source=other",
            "https://relay.example/#other",
        ] {
            state.relay_url = origin.into();
            if let Ok(source) = Sources::discover(&state, Some(&parent)) {
                assert!(source
                    .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
                    .is_err());
                assert!(source
                    .freeze_body(&intent, &[parent.chain_id.clone()])
                    .is_err());
            }
        }
        state.relay_url = "https://RELAY.example:443/".into();
        let normalized = Sources::discover(&state, Some(&parent)).unwrap();
        assert!(normalized
            .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
            .is_ok());
        assert!(normalized.freeze_body(&intent, &[parent.chain_id]).is_ok());
    }
    #[test]
    fn empty_local_library_has_an_explicit_empty_intent_and_no_legacy_credential() {
        let (mut state, _) = state();
        state.account = None;
        let sources = Sources::discover(&state, None).unwrap();
        let (owner, signer) = owner();
        let intent = sources
            .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
            .unwrap();
        assert!(intent.body.chains.is_empty());
        assert!(intent.body.parent_chain.is_empty());
        let body = sources.freeze_body(&intent, &[]).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded["credentials"], json!([]));
        assert!(!String::from_utf8_lossy(&body).contains("auth_token"));
    }
    #[test]
    fn signed_intent_retries_are_exact_and_extensions_cannot_drop_sources_or_change_preview() {
        let (mut state, parent) = state();
        let first = Sources::discover(&state, Some(&parent)).unwrap();
        let (owner, signer) = owner();
        let operation = "7".repeat(32);
        let preview = "8".repeat(64);
        let intent = first
            .intent(&owner, &signer, &operation, &preview, None)
            .unwrap();
        let progress = Progress {
            proof: vec![super::super::migration_freeze::ProofStep {
                digest: intent.digest().unwrap(),
                intent: intent.clone(),
            }],
            sources: vec![],
            phase: super::super::migration_freeze::Phase::Freezing,
            next: vec![parent.chain_id.clone()],
        };
        assert_eq!(
            first
                .intent(&owner, &signer, &operation, &preview, Some(&progress))
                .unwrap(),
            intent
        );
        let child = ChainKeys::generate().unwrap();
        collection(&mut state, &child, Some(false));
        let row = sealed(&parent, &child, false);
        state
            .account
            .as_mut()
            .unwrap()
            .sealed
            .insert(row.key(), row);
        let extended = Sources::discover(&state, Some(&parent)).unwrap();
        let next = extended
            .intent(&owner, &signer, &operation, &preview, Some(&progress))
            .unwrap();
        assert_eq!(next.body.revision, "2");
        assert_eq!(next.body.chains.len(), 2);
        assert_eq!(next.body.source_order()[0], parent.chain_id);
        assert!(extended
            .intent(
                &owner,
                &signer,
                &operation,
                &"9".repeat(64),
                Some(&progress)
            )
            .is_err());
        let mut larger = progress.clone();
        larger
            .proof
            .push(super::super::migration_freeze::ProofStep {
                digest: next.digest().unwrap(),
                intent: next.clone(),
            });
        larger.next = next
            .body
            .source_order()
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert!(first
            .intent(&owner, &signer, &operation, &preview, Some(&larger))
            .is_err());
        let encoded = extended.freeze_body(&next, &larger.next).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(body["credentials"][0]["chain"], parent.chain_id);
        assert_eq!(body["credentials"][0]["token"], parent.auth_token);
        assert!(!String::from_utf8_lossy(&encoded).contains("enc_key"));
        let mut reverse = larger.next.clone();
        reverse.reverse();
        assert!(extended.freeze_body(&next, &reverse).is_err());
        assert!(extended
            .freeze_body(&next, &[parent.chain_id.clone(), parent.chain_id.clone()])
            .is_err());
        assert!(extended.freeze_body(&next, &["a".repeat(64)]).is_err());
    }
}
