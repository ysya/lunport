//! Pure initial-history encryption. Inventory discovery, consent, I/O and cutover are separate.
use super::{
    client_state::Phase,
    crypto::{self, DeviceKeys, VaultKeys, WrappedKeys},
    migration::{Body, SignedMigration, Source},
    payload::{self, Data, Identity, SharedKeyslot},
    projection,
    rekey::{self, Checkpoint, Version},
    wire::{canonical, invalid, RecordHeader, WrapHeader},
    workspace::Workspace,
};
use crate::error::AppError;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_HISTORY_BYTES: usize = 32 * 1024 * 1024 - 256 * 1024;
const MAX_PAGE_BYTES: usize = 1024 * 1024;
mod archive;

pub(super) struct Context {
    pub operation: String,
    /// Digest of the randomized encrypted local source archive, never plaintext inventory.
    pub inventory_digest: String,
    pub sources: Vec<Source>,
}
/// Ciphertext only, deliberately no frontend/Debug/Serialize representation or publication permit.
pub(super) struct Plan {
    before: Workspace,
    pub manifest: SignedMigration,
    pub rows: Vec<Version>,
    pub wraps: Vec<WrappedKeys>,
    pages: Vec<Range<usize>>,
}
impl Plan {
    pub fn before(&self) -> &Workspace {
        &self.before
    }
    pub fn pages(&self) -> impl Iterator<Item = &[Version]> {
        self.pages.iter().map(|range| &self.rows[range.clone()])
    }
}
pub(super) fn prepare(
    before: &Workspace,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    context: Context,
    history: &[(Identity, Data)],
) -> Result<Plan, AppError> {
    if history.is_empty() || history.len() > 16384 {
        return Err(invalid());
    }
    let chain = archive::target(before, keys, signer)?;
    let replica = before.replica.as_ref().ok_or_else(invalid)?;
    let member = chain.current();
    let anchor = member.anchor();
    let mut body = Body {
        origin: anchor.origin.clone(),
        account_id: anchor.account_id.clone(),
        genesis_hash: anchor.genesis_hash.clone(),
        vault_id: replica.vault.clone(),
        migration_id: context.operation,
        authorization_epoch: before.control.auth_epoch.to_string(),
        key_epoch: "1".into(),
        membership_head: member.head().into(),
        author: before.control.device.id.clone(),
        inventory_digest: context.inventory_digest,
        target_sequence: "1".into(),
        target_history_hash: ZERO.into(),
        wraps_digest: ZERO.into(),
        sources: context.sources,
    };
    body.canonical()?;
    let mut wraps = vec![];
    for (recipient, public) in member
        .devices()
        .iter()
        .map(|(id, keys)| (id.as_str(), keys))
        .chain(std::iter::once(("recovery", member.recovery())))
    {
        wraps.push(crypto::wrap_keys(
            keys,
            signer,
            WrapHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: replica.vault.clone(),
                key_epoch: "1".into(),
                membership_head: member.head().into(),
                author: before.control.device.id.clone(),
                recipient: recipient.into(),
                recipient_key: public.encryption.clone(),
            },
        )?);
    }
    body.wraps_digest = rekey::wraps_digest(&wraps)?;
    let mut rows = vec![];
    let mut revisions = BTreeMap::<String, u64>::new();
    let mut slots = BTreeMap::<String, Option<SharedKeyslot>>::new();
    let mut operations = BTreeSet::new();
    let mut history_hash = ZERO.to_owned();
    let mut total = 0usize;
    let mut pages = vec![];
    let mut start = 0usize;
    let mut page_bytes = 0usize;
    for (identity, data) in history {
        let plaintext = payload::encode(identity, data)?;
        match data {
            Data::Keyslot(slot) => {
                slots.insert(identity.id.clone(), Some(slot.clone()));
            }
            Data::Deleted if identity.kind == "keyslot" => {
                slots.insert(identity.id.clone(), None);
            }
            Data::Key(material) => material.validate_against(
                &identity.id,
                slots
                    .get(&identity.id)
                    .and_then(Option::as_ref)
                    .ok_or_else(invalid)?,
            )?,
            _ => {}
        }
        let record_id = identity.opaque(keys)?;
        let revision = revisions.entry(record_id.clone()).or_default();
        let operation_id = crypto::random_id(16)?;
        if !operations.insert(operation_id.clone()) {
            return Err(invalid());
        }
        let envelope = crypto::seal_record(
            keys,
            signer,
            RecordHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: replica.vault.clone(),
                record_id,
                key_epoch: "1".into(),
                membership_head: member.head().into(),
                author: before.control.device.id.clone(),
                operation_id,
                expected_revision: revision.to_string(),
                kind: identity.kind.clone(),
                deleted: matches!(data, Data::Deleted),
            },
            &plaintext,
        )?;
        *revision += 1;
        let revision_value = *revision;
        let sequence = rows.len() + 1;
        let digest = rekey::envelope_digest(&envelope)?;
        history_hash = crypto::hash(&canonical(&[
            "lunport-history-v2",
            &history_hash,
            &sequence.to_string(),
            &digest,
        ])?);
        let bytes = serde_json::to_vec(&envelope).map_err(|_| invalid())?.len();
        total += bytes;
        if total > MAX_HISTORY_BYTES || revisions.len() > 4096 || bytes > MAX_PAGE_BYTES {
            return Err(invalid());
        }
        if rows.len() > start && (rows.len() - start >= 32 || page_bytes + bytes > MAX_PAGE_BYTES) {
            pages.push(start..rows.len());
            start = rows.len();
            page_bytes = 0;
        }
        page_bytes += bytes;
        rows.push(Version {
            revision: revision_value.to_string(),
            sequence: sequence.to_string(),
            envelope,
            digest,
            history_hash: history_hash.clone(),
        });
    }
    pages.push(start..rows.len());
    let checkpoint = Checkpoint {
        epoch: 1,
        sequence: rows.len() as u64,
        history_hash: history_hash.clone(),
    };
    // Verify and admit every entry, including superseded history, before returning any plan.
    let mut verified = before.clone();
    for range in &pages {
        let page = verified
            .replica
            .as_ref()
            .ok_or_else(invalid)?
            .prepare_page(&chain, keys, &rows[range.clone()], &checkpoint)?;
        for opened in page.opened {
            payload::admit(keys, &opened.version.envelope.header, &opened.plaintext)?;
        }
        verified.replica = Some(page.next);
    }
    let semantic = projection::Plan::inventory(verified, keys)?;
    if !semantic.complete() {
        return Err(invalid());
    }
    body.target_sequence = rows.len().to_string();
    body.target_history_hash = history_hash;
    let manifest = SignedMigration::sign(body, signer)?;
    manifest.verify(
        member,
        before.control.auth_epoch,
        1,
        &replica.vault,
        &before.control.device.id,
    )?;
    Ok(Plan {
        before: before.clone(),
        manifest,
        rows,
        wraps,
        pages,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{
        payload::{Catalog, PrivateMaterial},
        projection::tests::slot,
    };
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use zeroize::Zeroizing;
    pub(in crate::sync::central) fn initial() -> (Workspace, VaultKeys, DeviceKeys) {
        let mut before = super::super::workspace::tests::enrolled();
        let keys = VaultKeys::generate().unwrap();
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        let anchor = before.control.anchor.as_ref().unwrap();
        before.own_wraps = vec![crypto::wrap_keys(
            &keys,
            &signer,
            WrapHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: before.control.personal_vault.clone().unwrap(),
                key_epoch: "1".into(),
                membership_head: before.control.highwater.as_ref().unwrap().head.clone(),
                author: before.control.device.id.clone(),
                recipient: before.control.device.id.clone(),
                recipient_key: signer.public().encryption,
            },
        )
        .unwrap()];
        before.validate().unwrap();
        (before, keys, signer)
    }
    pub(super) fn context() -> Context {
        Context {
            operation: "7".repeat(32),
            inventory_digest: "8".repeat(64),
            sources: vec![],
        }
    }
    fn identity(kind: &str, id: &str) -> Identity {
        Identity {
            kind: kind.into(),
            id: id.into(),
            scope: None,
        }
    }
    fn catalog() -> (Identity, Data) {
        (
            identity("meta", "catalog"),
            Data::Catalog(Catalog {
                collections: vec![],
                group_orders: vec![],
            }),
        )
    }
    pub(super) fn library() -> Vec<(Identity, Data)> {
        let active = crate::sync::slot_rules::test_keys::plain();
        let inactive = crate::sync::slot_rules::test_keys::encrypted();
        vec![
            catalog(),
            (
                identity("keyslot", &"1".repeat(32)),
                Data::Keyslot(slot(&active)),
            ),
            (
                identity("key", &"1".repeat(32)),
                Data::Key(PrivateMaterial::new(Zeroizing::new(active)).unwrap()),
            ),
            (
                identity("keyslot", &"2".repeat(32)),
                Data::Keyslot(slot(&inactive)),
            ),
            (
                identity("key", &"2".repeat(32)),
                Data::Key(PrivateMaterial::new(Zeroizing::new(inactive)).unwrap()),
            ),
            (identity("keyslot", &"2".repeat(32)), Data::Deleted),
        ]
    }
    fn verified(plan: &Plan, keys: &VaultKeys) -> Workspace {
        let mut owner = plan.before().clone();
        let checkpoint = Checkpoint {
            epoch: 1,
            sequence: plan.rows.len() as u64,
            history_hash: plan.manifest.body.target_history_hash.clone(),
        };
        let chain = owner.control.verified_chain().unwrap();
        for rows in plan.pages() {
            owner.replica = Some(
                owner
                    .replica
                    .as_ref()
                    .unwrap()
                    .prepare_page(&chain, keys, rows, &checkpoint)
                    .unwrap()
                    .next,
            );
        }
        owner
    }
    #[test]
    fn exact_private_encryption_and_inactive_history_are_verified_without_activation() {
        let (before, keys, signer) = initial();
        let plan = prepare(&before, &keys, &signer, context(), &library()).unwrap();
        assert_eq!(plan.before(), &before);
        assert!(!plan.before().control.cutover);
        assert_eq!(before.control.phase, Phase::Enrolled);
        assert_eq!(before.replica.as_ref().unwrap().checkpoint.sequence, 0);
        assert_eq!(plan.rows.len(), 6);
        assert_eq!(plan.rows.last().unwrap().revision, "2");
        assert!(plan.rows.last().unwrap().envelope.header.deleted);
        for row in &plan.rows {
            let plaintext = row
                .envelope
                .verify(&signer.public().signing)
                .unwrap()
                .open(&keys)
                .unwrap();
            let admitted = payload::admit(&keys, &row.envelope.header, &plaintext).unwrap();
            if let Data::Key(material) = admitted.data {
                let expected = if admitted.identity.id == "1".repeat(32) {
                    crate::sync::slot_rules::test_keys::plain()
                } else {
                    crate::sync::slot_rules::test_keys::encrypted()
                };
                assert!(material.private() == expected);
            }
        }
        let owner = verified(&plan, &keys);
        let semantic = projection::Plan::inventory(owner.clone(), &keys).unwrap();
        assert!(semantic.complete());
        assert_eq!(semantic.materials().len(), 1);
        assert!(semantic.materials().contains_key(&"1".repeat(32)));
        assert!(!semantic.materials().contains_key(&"2".repeat(32)));
        assert!(projection::Plan::current(owner, &keys).is_err());
        let encoded = serde_json::to_string(
            &serde_json::json!({"rows":plan.rows,"manifest":plan.manifest,"wraps":plan.wraps}),
        )
        .unwrap();
        assert!(!encoded.contains("OPENSSH PRIVATE KEY"));
        assert!(!encoded.contains("private_key"));
    }
    #[test]
    fn fresh_wraps_are_complete_and_open_the_same_existing_keys() {
        let (before, keys, signer) = initial();
        let plan = prepare(&before, &keys, &signer, context(), &[catalog()]).unwrap();
        let chain = before.control.verified_chain().unwrap();
        assert_eq!(plan.wraps.len(), chain.current().devices().len() + 1);
        let own = plan
            .wraps
            .iter()
            .find(|wrap| wrap.header.recipient == before.control.device.id)
            .unwrap();
        assert_ne!(Some(own), before.own_wraps.first());
        own.open(&signer, &own.header, &signer.public().signing)
            .unwrap()
            .verify_same(&keys)
            .unwrap();
        assert_eq!(
            plan.manifest.body.wraps_digest,
            rekey::wraps_digest(&plan.wraps).unwrap()
        );
        plan.manifest
            .verify(
                chain.current(),
                before.control.auth_epoch,
                1,
                before.control.personal_vault.as_ref().unwrap(),
                &before.control.device.id,
            )
            .unwrap();
    }
    #[test]
    fn stale_or_wrong_identity_keys_and_nonempty_target_never_produce_a_plan() {
        let (before, keys, signer) = initial();
        assert!(prepare(
            &before,
            &keys,
            &DeviceKeys::generate().unwrap(),
            context(),
            &[catalog()]
        )
        .is_err());
        assert!(prepare(
            &before,
            &VaultKeys::generate().unwrap(),
            &signer,
            context(),
            &[catalog()]
        )
        .is_err());
        let mut missing = before.clone();
        missing.own_wraps.clear();
        assert!(prepare(&missing, &keys, &signer, context(), &[catalog()]).is_err());
        let mut signed_out = before.clone();
        signed_out.control.phase = Phase::SignedOut;
        assert!(prepare(&signed_out, &keys, &signer, context(), &[catalog()]).is_err());
        let mut active = before.clone();
        active.control.cutover = true;
        active.control = active
            .control
            .approve_library(
                "a".repeat(64),
                active.control.highwater.as_ref().unwrap().head.as_str(),
            )
            .unwrap();
        assert!(prepare(&active, &keys, &signer, context(), &[catalog()]).is_err());
        let plan = prepare(&before, &keys, &signer, context(), &[catalog()]).unwrap();
        assert!(prepare(
            &verified(&plan, &keys),
            &keys,
            &signer,
            context(),
            &[catalog()]
        )
        .is_err());
        let mut bad = context();
        bad.operation = "bad".into();
        assert!(prepare(&before, &keys, &signer, bad, &[catalog()]).is_err());
    }
    #[test]
    fn missing_or_mismatched_material_and_catalog_are_never_omitted() {
        let (before, keys, signer) = initial();
        let private = crate::sync::slot_rules::test_keys::plain();
        let id = "1".repeat(32);
        assert!(prepare(
            &before,
            &keys,
            &signer,
            context(),
            &[
                (identity("keyslot", &id), Data::Keyslot(slot(&private))),
                (
                    identity("key", &id),
                    Data::Key(PrivateMaterial::new(Zeroizing::new(private.clone())).unwrap())
                )
            ]
        )
        .is_err());
        assert!(prepare(
            &before,
            &keys,
            &signer,
            context(),
            &[
                catalog(),
                (identity("keyslot", &id), Data::Keyslot(slot(&private)))
            ]
        )
        .is_err());
        assert!(prepare(
            &before,
            &keys,
            &signer,
            context(),
            &[
                catalog(),
                (
                    identity("key", &id),
                    Data::Key(PrivateMaterial::new(Zeroizing::new(private.clone())).unwrap())
                )
            ]
        )
        .is_err());
        let other = crate::sync::slot_rules::test_keys::ecdsa();
        assert!(prepare(
            &before,
            &keys,
            &signer,
            context(),
            &[
                catalog(),
                (identity("keyslot", &id), Data::Keyslot(slot(&other))),
                (
                    identity("key", &id),
                    Data::Key(PrivateMaterial::new(Zeroizing::new(private)).unwrap())
                )
            ]
        )
        .is_err());
    }
    #[test]
    fn pages_are_bounded_and_every_superseded_revision_is_retained() {
        let (before, keys, signer) = initial();
        let mut rows = vec![catalog()];
        for index in 1..=70 {
            rows.push((Identity { kind: "host".into(), id: format!("{index:016x}"), scope: Some(crate::sync::records_v3::HostScope::Local) }, Data::Host(serde_json::from_value(serde_json::json!({"schema":2,"alias":format!("fixture-{index}"),"hostname":"fixture.invalid","auth":"password"})).unwrap())));
        }
        let plan = prepare(&before, &keys, &signer, context(), &rows).unwrap();
        assert_eq!(plan.rows.len(), 71);
        assert_eq!(plan.pages().count(), 3);
        for page in plan.pages() {
            assert!(page.len() <= 32);
            assert!(
                page.iter()
                    .map(|row| serde_json::to_vec(&row.envelope).unwrap().len())
                    .sum::<usize>()
                    <= MAX_PAGE_BYTES
            );
        }
        assert_eq!(
            verified(&plan, &keys).replica.unwrap().checkpoint.sequence,
            71
        );
    }
    #[test]
    #[ignore = "explicit synthetic migration fixture generation only"]
    fn emit_initial_library_fixture() {
        let (before, keys, signer) = initial();
        let plan = prepare(&before, &keys, &signer, context(), &library()).unwrap();
        let original = prepare(&before, &keys, &signer, context(), &[catalog()]).unwrap();
        let fixture = serde_json::json!({"fixture":"SYNTHETIC MIGRATION KEYS ONLY - never use in an account","manifest":plan.manifest,"rows":plan.rows,"wraps":plan.wraps,"original_wraps":original.wraps,"proof":before.control.proof,"locator":before.control.profile.locator,"device":before.control.device.id});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/central-migration-library-v2.json");
        std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }
}
