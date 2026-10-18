//! Semantic page verification before Core publication. Ciphertext staging and library activation
//! are separate: no plaintext is offered to the legacy repository before whole-library cutover.
use super::{
    crypto::VaultKeys,
    payload::{self, Admitted},
    rekey::{Checkpoint, Version},
    replica::Replica,
    trust::VerifiedChain,
    wire::invalid,
    workspace::Workspace,
};
use crate::error::AppError;
pub struct Change {
    pub version: Version,
    pub payload: Admitted,
}
pub struct CheckedPage {
    pub next: Replica,
    pub publication: Vec<Change>,
    pub publish_baseline: bool,
}
fn current(
    replica: &Replica,
    chain: &VerifiedChain,
    keys: &VaultKeys,
) -> Result<Vec<Change>, AppError> {
    let mut publication = vec![];
    for (id, base) in &replica.current {
        let version = &base.version;
        let h = &version.envelope.header;
        if super::wire::number(&h.key_epoch, false)? != replica.checkpoint.epoch {
            return Err(invalid());
        }
        let author = chain
            .author_at(&h.membership_head, &h.author)
            .ok_or_else(invalid)?;
        let plaintext = version.envelope.verify(&author.signing)?.open(keys)?;
        let admitted = payload::admit(keys, h, &plaintext)?;
        if !replica.pending.contains_key(id) {
            publication.push(Change {
                version: version.clone(),
                payload: admitted,
            });
        }
    }
    Ok(publication)
}
fn publication_allowed(workspace: &Workspace, replica: &Replica, chain: &VerifiedChain) -> bool {
    workspace.replacement.is_none()
        && workspace.require_key_recipients().is_ok()
        && !workspace
            .replacement_archives
            .iter()
            .any(|archive| archive.needs_reconciliation)
        && workspace.control.cloud_writes_allowed()
        && replica.baseline_ready()
        && replica
            .verify_write_authority(
                chain,
                workspace.control.auth_epoch,
                replica.checkpoint.epoch,
                &workspace.epochs,
            )
            .is_ok()
}
pub fn prepare(
    workspace: &Workspace,
    keys: &VaultKeys,
    rows: &[Version],
    advertised: &Checkpoint,
) -> Result<CheckedPage, AppError> {
    workspace.validate()?;
    let chain = workspace.control.verified_chain()?;
    let replica = workspace.replica.as_ref().ok_or_else(invalid)?;
    let page = replica.prepare_page(&chain, keys, rows, advertised)?;
    let active = publication_allowed(workspace, &page.next, &chain);
    let mut publication = vec![];
    for opened in page.opened {
        // Even history superseded within this page is admitted. No valid prefix escapes a later error.
        let admitted = payload::admit(keys, &opened.version.envelope.header, &opened.plaintext)?;
        let id = &opened.version.envelope.header.record_id;
        if active
            && !page.publish_baseline
            && opened.publish
            && page.next.baseline_ready()
            && !page.next.pending.contains_key(id)
            && page
                .next
                .current
                .get(id)
                .is_some_and(|b| b.version == opened.version)
        {
            publication.push(Change {
                version: opened.version,
                payload: admitted,
            });
        }
    }
    if active && page.publish_baseline {
        // A pairing minimum may span pages. Publish the complete verified cache, not just the tail.
        publication = current(&page.next, &chain, keys)?;
    }
    Ok(CheckedPage {
        next: page.next,
        publication,
        publish_baseline: page.publish_baseline,
    })
}
pub fn materialize_current(
    workspace: &Workspace,
    keys: &VaultKeys,
) -> Result<Vec<Change>, AppError> {
    workspace.validate()?;
    let replica = workspace.replica.as_ref().ok_or_else(invalid)?;
    let chain = workspace.control.verified_chain()?;
    if !publication_allowed(workspace, replica, &chain) {
        return Err(invalid());
    }
    current(replica, &chain, keys)
}
#[cfg(test)]
mod tests {
    use super::super::{
        crypto::{self, DeviceKeys},
        payload::{Data, Identity},
        wire::{canonical, RecordHeader},
    };
    use super::*;
    use crate::sync::records_v3::HostScope;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    fn row(ws: &Workspace, keys: &VaultKeys, seq: u64, previous: &str, valid: bool) -> Version {
        let id = Identity {
            kind: "host".into(),
            id: format!("{seq:016x}"),
            scope: Some(HostScope::Local),
        };
        let payload=serde_json::from_value(serde_json::json!({"schema":2,"alias":format!("host-{seq}"),"hostname":"fixture.invalid","auth":"password"})).unwrap();
        let bytes = if valid {
            payload::encode(&id, &Data::Host(payload)).unwrap()
        } else {
            zeroize::Zeroizing::new(serde_json::to_vec(&serde_json::json!({"schema":1,"id":id.id,"scope":id.scope,"payload":{"schema":2,"alias":"bad","hostname":"fixture.invalid","auth":"password","password":"PRIVATE-PASSWORD-SENTINEL"}})).unwrap())
        };
        let anchor = ws.control.anchor.as_ref().unwrap();
        let signer = DeviceKeys::decode_secret(&B64.encode([1; 64])).unwrap();
        let envelope = crypto::seal_record(
            keys,
            &signer,
            RecordHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: ws.replica.as_ref().unwrap().vault.clone(),
                record_id: id.opaque(keys).unwrap(),
                key_epoch: "1".into(),
                membership_head: ws.control.highwater.as_ref().unwrap().head.clone(),
                author: ws.control.device.id.clone(),
                operation_id: format!("{seq:032x}"),
                expected_revision: "0".into(),
                kind: "host".into(),
                deleted: false,
            },
            &bytes,
        )
        .unwrap();
        let digest = super::super::rekey::envelope_digest(&envelope).unwrap();
        let history_hash = crypto::hash(
            &canonical(&["lunport-history-v2", previous, &seq.to_string(), &digest]).unwrap(),
        );
        Version {
            revision: "1".into(),
            sequence: seq.to_string(),
            envelope,
            digest,
            history_hash,
        }
    }
    fn active() -> Workspace {
        let mut ws = super::super::workspace::tests::enrolled();
        ws.control.cutover = true;
        ws.control = ws
            .control
            .approve_library("d".repeat(64), &ws.control.highwater.as_ref().unwrap().head)
            .unwrap();
        ws
    }
    #[test]
    fn replacement_intent_stages_verified_ciphertext_without_publishing_material_or_new_keys() {
        let mut ws = active();
        assert!(ws.can_upload());
        ws.replacement = Some(super::super::replacement::Intent {
            operation: "c".repeat(32),
            route: super::super::replacement::Route::RecoveryKit,
            device: None,
            candidate: None,
            recovery_confirmation: None,
        });
        ws.validate().unwrap();
        assert!(!ws.can_upload());
        assert!(ws.require_key_recipients().is_err());
        let keys = VaultKeys::generate().unwrap();
        let first = row(&ws, &keys, 1, &"0".repeat(64), true);
        let target = Checkpoint {
            epoch: 1,
            sequence: 1,
            history_hash: first.history_hash.clone(),
        };
        let checked = prepare(&ws, &keys, &[first], &target).unwrap();
        assert_eq!(checked.next.current.len(), 1);
        assert!(checked.publication.is_empty());
        ws.replica = Some(checked.next);
        assert!(materialize_current(&ws, &keys).is_err());
    }
    #[test]
    fn semantically_invalid_signed_history_cannot_publish_an_earlier_valid_record() {
        let ws = active();
        let keys = VaultKeys::generate().unwrap();
        let first = row(&ws, &keys, 1, &"0".repeat(64), true);
        let bad = row(&ws, &keys, 2, &first.history_hash, false);
        let advertised = Checkpoint {
            epoch: 1,
            sequence: 2,
            history_hash: bad.history_hash.clone(),
        };
        let original = ws.clone();
        assert!(prepare(&ws, &keys, &[first, bad], &advertised).is_err());
        assert_eq!(ws, original);
    }
    #[test]
    fn enrolled_pre_cutover_stages_only_ciphertext_and_never_offers_library_plaintext() {
        let ws = super::super::workspace::tests::enrolled();
        let keys = VaultKeys::generate().unwrap();
        let row = row(&ws, &keys, 1, &"0".repeat(64), true);
        let advertised = Checkpoint {
            epoch: 1,
            sequence: 1,
            history_hash: row.history_hash.clone(),
        };
        let checked = prepare(&ws, &keys, &[row], &advertised).unwrap();
        assert_eq!(checked.next.current.len(), 1);
        assert!(checked.publication.is_empty());
        assert!(materialize_current(&ws, &keys).is_err());
        assert!(!serde_json::to_string(&checked.next)
            .unwrap()
            .contains("fixture.invalid"));
    }
    #[test]
    fn completing_a_minimum_reopens_the_whole_staged_cache_before_publication() {
        let mut ws = active();
        let keys = VaultKeys::generate().unwrap();
        let first = row(&ws, &keys, 1, &"0".repeat(64), true);
        let second = row(&ws, &keys, 2, &first.history_hash, true);
        let advertised = Checkpoint {
            epoch: 1,
            sequence: 2,
            history_hash: second.history_hash.clone(),
        };
        ws.replica.as_mut().unwrap().minimum = Some(advertised.clone());
        let staging = prepare(&ws, &keys, &[first], &advertised).unwrap();
        assert!(staging.publication.is_empty());
        assert!(!staging.publish_baseline);
        ws.replica = Some(staging.next);
        let completed = prepare(&ws, &keys, &[second], &advertised).unwrap();
        assert!(completed.publish_baseline);
        assert_eq!(completed.publication.len(), 2);
        let versions: std::collections::BTreeMap<_, _> = completed
            .publication
            .iter()
            .map(|change| {
                (
                    change.payload.identity.id.as_str(),
                    change.version.sequence.as_str(),
                )
            })
            .collect();
        assert_eq!(
            versions,
            std::collections::BTreeMap::from([
                ("0000000000000001", "1"),
                ("0000000000000002", "2")
            ])
        );
    }
    #[test]
    fn an_uncovered_authorization_barrier_blocks_plaintext_publication_even_with_active_phase() {
        let mut ws = active();
        ws.control.auth_epoch += 1;
        let keys = VaultKeys::generate().unwrap();
        let row = row(&ws, &keys, 1, &"0".repeat(64), true);
        let advertised = Checkpoint {
            epoch: 1,
            sequence: 1,
            history_hash: row.history_hash.clone(),
        };
        let checked = prepare(&ws, &keys, &[row], &advertised).unwrap();
        assert!(checked.publication.is_empty());
        ws.replica = Some(checked.next);
        assert!(materialize_current(&ws, &keys).is_err());
    }
}
