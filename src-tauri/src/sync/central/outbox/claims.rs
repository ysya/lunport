//! Successful service responses are claims, not signed-history acknowledgement.
use super::super::{
    replica::Receipt,
    wire::{hex, MAX_SAFE_INTEGER},
};
use super::*;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct PushReply {
    receipts: Vec<Receipt>,
    sequence: String,
    history_hash: String,
}
pub(in crate::sync::central) fn candidate(
    owner: &Workspace,
    dispatched: &[RecordEnvelope],
    reply: &PushReply,
) -> Result<Workspace, AppError> {
    owner.validate()?;
    if !owner.control.cutover
        || !owner.can_upload()
        || dispatched.is_empty()
        || dispatched.len() > 32
        || reply.receipts.len() != dispatched.len()
        || !hex(&reply.history_hash, 64)
    {
        return Err(invalid());
    }
    owner.require_key_recipients()?;
    let chain = owner.control.verified_chain()?;
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    replica.verify_write_authority(
        &chain,
        owner.control.auth_epoch,
        replica.checkpoint.epoch,
        &owner.epochs,
    )?;
    let position = number(&reply.sequence, false)?;
    if position > 16384 || position > MAX_SAFE_INTEGER || position < replica.checkpoint.sequence {
        return Err(invalid());
    }
    if position == replica.checkpoint.sequence
        && reply.history_hash != replica.checkpoint.history_hash
    {
        return Err(invalid());
    }
    let mut requested = BTreeMap::new();
    let mut operations = BTreeSet::new();
    for envelope in dispatched {
        let h = &envelope.header;
        let sent = replica
            .pending
            .get(&h.record_id)
            .and_then(|p| p.sent.as_ref())
            .ok_or_else(invalid)?;
        if &sent.envelope != envelope
            || h.author != owner.control.device.id
            || h.membership_head != chain.current().head()
            || number(&h.key_epoch, false)? != replica.checkpoint.epoch
            || requested
                .insert(h.record_id.clone(), h.operation_id.clone())
                .is_some()
            || !operations.insert(h.operation_id.clone())
        {
            return Err(invalid());
        }
    }
    let mut seen = BTreeSet::new();
    for receipt in &reply.receipts {
        if requested.get(&receipt.record_id) != Some(&receipt.operation_id)
            || !seen.insert(receipt.record_id.clone())
            || number(&receipt.sequence, false)? > position
            || number(&receipt.sequence, false)? == position
                && receipt.history_hash != reply.history_hash
        {
            return Err(invalid());
        }
    }
    let mut next = owner.clone();
    for receipt in &reply.receipts {
        next.replica
            .as_mut()
            .ok_or_else(invalid)?
            .note_receipt(&chain, receipt.clone())?;
    }
    next.validate()?;
    Ok(next)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::central::outbox::tests::{accept, fixture};
    fn receipt(envelope: &RecordEnvelope, sequence: u64, hash: &str) -> serde_json::Value {
        serde_json::json!({"operation_id":envelope.header.operation_id,"record_id":envelope.header.record_id,
            "revision":(number(&envelope.header.expected_revision,true).unwrap()+1).to_string(),"sequence":sequence.to_string(),
            "digest":super::super::super::rekey::envelope_digest(envelope).unwrap(),"history_hash":hash})
    }
    fn reply(
        records: &[RecordEnvelope],
        start: &super::super::super::rekey::Checkpoint,
    ) -> serde_json::Value {
        let mut sequence = start.sequence;
        let mut history_hash = start.history_hash.clone();
        let mut receipts = vec![];
        for envelope in records {
            sequence += 1;
            let digest = super::super::super::rekey::envelope_digest(envelope).unwrap();
            history_hash = crypto::hash(
                &super::super::super::wire::canonical(&[
                    "lunport-history-v2",
                    &history_hash,
                    &sequence.to_string(),
                    &digest,
                ])
                .unwrap(),
            );
            receipts.push(receipt(envelope, sequence, &history_hash));
        }
        serde_json::json!({"receipts":receipts,"sequence":sequence.to_string(),"history_hash":history_hash})
    }
    #[test]
    fn a_claim_never_changes_checkpoint_or_releases_private_material_and_history_alone_clears_it() {
        let (mut state, keys, signer, _) = fixture();
        let prepared = prepare(&state, &keys, &signer, None).unwrap();
        let before = prepared.owner.clone();
        let position = before.replica.as_ref().unwrap().checkpoint.clone();
        let response: PushReply =
            serde_json::from_value(reply(&prepared.records, &position)).unwrap();
        let after = candidate(&before, &prepared.records, &response).unwrap();
        let mut expected = before.clone();
        let id = &prepared.records[0].header.record_id;
        expected
            .replica
            .as_mut()
            .unwrap()
            .pending
            .get_mut(id)
            .unwrap()
            .claimed = Some(response.receipts[0].clone());
        assert_eq!(after, expected);
        assert_eq!(after.replica.as_ref().unwrap().checkpoint, position);
        state.local.central = Some(after);
        assert!(prepare(&state, &keys, &signer, None)
            .unwrap()
            .records
            .is_empty());
        accept(&mut state, &keys, prepared.records[0].clone());
        assert!(!state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending
            .contains_key(id));
        assert_eq!(
            prepare(&state, &keys, &signer, None).unwrap().records[0]
                .header
                .kind,
            "key"
        );
    }
    #[test]
    fn incomplete_duplicate_unknown_or_impossible_successes_preserve_the_entire_owner() {
        let (state, keys, signer, _) = fixture();
        let prepared = prepare(&state, &keys, &signer, None).unwrap();
        let owner = prepared.owner;
        let valid = reply(
            &prepared.records,
            &owner.replica.as_ref().unwrap().checkpoint,
        );
        for index in 0..9 {
            let mut value = valid.clone();
            match index {
                0 => value["receipts"] = serde_json::json!([]),
                1 => {
                    let duplicate = value["receipts"][0].clone();
                    value["receipts"].as_array_mut().unwrap().push(duplicate);
                }
                2 => value["receipts"][0]["operation_id"] = "0".repeat(32).into(),
                3 => value["receipts"][0]["record_id"] = "0".repeat(64).into(),
                4 => value["receipts"][0]["digest"] = "0".repeat(64).into(),
                5 => value["receipts"][0]["revision"] = "99".into(),
                6 => value["sequence"] = "0".into(),
                7 => value["history_hash"] = "b".repeat(64).into(),
                _ => value["receipts"][0]["sequence"] = "99999".into(),
            }
            let original = owner.clone();
            let response: PushReply = serde_json::from_value(value).unwrap();
            assert!(
                candidate(&owner, &prepared.records, &response).is_err(),
                "case {index}"
            );
            assert_eq!(owner, original);
        }
        let mut wrong = prepared.records.clone();
        wrong[0].header.operation_id = "0".repeat(32);
        let response: PushReply = serde_json::from_value(valid).unwrap();
        assert!(candidate(&owner, &wrong, &response).is_err());
    }
    #[test]
    fn response_to_sent_a_preserves_later_local_b_after_restart() {
        let (mut state, keys, signer, id) = fixture();
        let sent = prepare(&state, &keys, &signer, None).unwrap();
        state.local.central = Some(sent.owner);
        let public = state.local.keys[&id].public.clone();
        let renamed =
            crate::sync::record_repository::rename_key(&state, &id, &public, "local_b", 600)
                .unwrap();
        let captured =
            crate::sync::central::projection_capture::public_candidate(&renamed, &keys, &signer)
                .unwrap();
        let saved = serde_json::to_vec(&captured).unwrap();
        let restored: SyncStateV3 = serde_json::from_slice(&saved).unwrap();
        let before = restored.local.central.as_ref().unwrap();
        let response: PushReply = serde_json::from_value(reply(
            &sent.records,
            &before.replica.as_ref().unwrap().checkpoint,
        ))
        .unwrap();
        let after = candidate(before, &sent.records, &response).unwrap();
        let opaque = &sent.records[0].header.record_id;
        assert_eq!(
            after.replica.as_ref().unwrap().pending[opaque].latest,
            before.replica.as_ref().unwrap().pending[opaque].latest
        );
        assert_eq!(
            after.replica.as_ref().unwrap().pending[opaque].sent,
            before.replica.as_ref().unwrap().pending[opaque].sent
        );
        assert_ne!(
            after.replica.as_ref().unwrap().pending[opaque].latest,
            after.replica.as_ref().unwrap().pending[opaque]
                .sent
                .clone()
                .unwrap()
        );
    }

    #[test]
    fn atomic_batch_allows_reordered_receipts_but_no_duplicate_or_partial_success() {
        let (mut state, keys, signer, _) = fixture();
        let mut host = state.local.hosts.values().next().unwrap().clone();
        host.record.id = "00000000000000cc".into();
        host.record.payload["alias"] = "second_claim".into();
        state.local.hosts.insert(
            crate::sync::record::record_key(crate::sync::record::RecordKind::Host, &host.record.id),
            host,
        );
        let captured =
            crate::sync::central::projection_capture::public_candidate(&state, &keys, &signer)
                .unwrap();
        let prepared = prepare(&captured, &keys, &signer, None).unwrap();
        assert_eq!(prepared.records.len(), 2);
        let mut body = reply(
            &prepared.records,
            &prepared.owner.replica.as_ref().unwrap().checkpoint,
        );
        body["receipts"].as_array_mut().unwrap().reverse();
        let parsed: PushReply = serde_json::from_value(body.clone()).unwrap();
        let claimed = candidate(&prepared.owner, &prepared.records, &parsed).unwrap();
        assert_eq!(
            claimed
                .replica
                .as_ref()
                .unwrap()
                .pending
                .values()
                .filter(|p| p.claimed.is_some())
                .count(),
            2
        );
        let mut duplicate = body.clone();
        duplicate["receipts"][1] = duplicate["receipts"][0].clone();
        assert!(candidate(
            &prepared.owner,
            &prepared.records,
            &serde_json::from_value(duplicate).unwrap()
        )
        .is_err());
        body["receipts"].as_array_mut().unwrap().pop();
        assert!(candidate(
            &prepared.owner,
            &prepared.records,
            &serde_json::from_value(body).unwrap()
        )
        .is_err());
    }
}
