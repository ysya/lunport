//! Native plan ciphertext codec. Complete verification before restore; no migration authority.
use super::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
const MAX_PLAN_BYTES: usize = 36 * 1024 * 1024;
pub(super) fn target(
    before: &Workspace,
    keys: &VaultKeys,
    signer: &DeviceKeys,
) -> Result<super::super::trust::VerifiedChain, AppError> {
    before.validate()?;
    before.require_key_recipients()?;
    let replica = before.replica.as_ref().ok_or_else(invalid)?;
    let chain = before.control.verified_chain()?;
    if before.control.cutover
        || before.control.phase != Phase::Enrolled
        || signer.public() != before.control.device.keys
        || before.bootstrap.is_some()
        || before.replacement.is_some()
        || !before.replacement_archives.is_empty()
        || before.rotation.is_some()
        || before.recovery.is_some()
        || !before.epochs.is_empty()
        || !before.observed_epochs.is_empty()
        || replica.checkpoint.epoch != 1
        || replica.checkpoint.sequence != 0
        || replica.checkpoint.history_hash != ZERO
        || !replica.current.is_empty()
        || !replica.pending.is_empty()
        || !replica.conflicts.is_empty()
        || !replica.baseline_ready()
    {
        return Err(invalid());
    }
    replica.verify_write_authority(&chain, before.control.auth_epoch, 1, &before.epochs)?;
    let own = before
        .own_wraps
        .iter()
        .find(|wrap| wrap.header.key_epoch == "1")
        .ok_or_else(invalid)?;
    let author = chain
        .author_at(&own.header.membership_head, &own.header.author)
        .ok_or_else(invalid)?;
    let opened = own.open(signer, &own.header, &author.signing)?;
    opened.verify_same(keys)?;
    Ok(chain)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    before: Workspace,
    manifest: SignedMigration,
    rows: Vec<Version>,
    wraps: Vec<WrappedKeys>,
    #[serde(default)]
    source_cursor: Option<super::super::source_cursor::Cursor>,
}
impl Plan {
    pub fn encode_local(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        self.encode_bound(None)
    }
    pub fn encode_with_source(
        &self,
        source: &super::super::source_cursor::Cursor,
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        source.validate(&self.before)?;
        if source.receipt().operation() != self.manifest.body.migration_id
            || source.receipt().ciphertext_hash != self.manifest.body.inventory_digest
        {
            return Err(invalid());
        }
        self.encode_bound(Some(source))
    }
    fn encode_bound(
        &self,
        source_cursor: Option<&super::super::source_cursor::Cursor>,
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        #[derive(Serialize)]
        struct Stored<'a> {
            version: u32,
            before: &'a Workspace,
            manifest: &'a SignedMigration,
            rows: &'a [Version],
            wraps: &'a [WrappedKeys],
            #[serde(skip_serializing_if = "Option::is_none")]
            source_cursor: Option<&'a super::super::source_cursor::Cursor>,
        }
        let mut bytes = Zeroizing::new(Vec::new());
        serde_json::to_writer(
            &mut *bytes,
            &Stored {
                version: 1,
                before: &self.before,
                manifest: &self.manifest,
                rows: &self.rows,
                wraps: &self.wraps,
                source_cursor,
            },
        )
        .map_err(|_| invalid())?;
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
    /// Metadata peek only; callers must validate the parent against protected child progress.
    pub fn source_cursor(bytes: &[u8]) -> Result<super::super::source_cursor::Cursor, AppError> {
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(invalid());
        }
        #[derive(Deserialize)]
        struct Bound {
            source_cursor: super::super::source_cursor::Cursor,
        }
        serde_json::from_slice::<Bound>(bytes)
            .map(|bound| bound.source_cursor)
            .map_err(|_| invalid())
    }
    pub fn matches_history(
        &self,
        keys: &VaultKeys,
        history: &[(Identity, Data)],
    ) -> Result<(), AppError> {
        if self.rows.len() != history.len() {
            return Err(invalid());
        }
        let chain = self.before.control.verified_chain()?;
        for (row, (identity, data)) in self.rows.iter().zip(history) {
            let header = &row.envelope.header;
            if header.record_id != identity.opaque(keys)?
                || header.kind != identity.kind
                || header.deleted != matches!(data, Data::Deleted)
            {
                return Err(invalid());
            }
            let author = chain
                .author_at(&header.membership_head, &header.author)
                .ok_or_else(invalid)?;
            let actual = row.envelope.verify(&author.signing)?.open(keys)?;
            if actual.as_slice() != payload::encode(identity, data)?.as_slice() {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn decode_local(
        bytes: &[u8],
        before: &Workspace,
        keys: &VaultKeys,
        signer: &DeviceKeys,
        expected: &Context,
    ) -> Result<Self, AppError> {
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(invalid());
        }
        let stored: Stored = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if stored.version != 1
            || &stored.before != before
            || stored.rows.is_empty()
            || stored.rows.len() > 16384
            || stored.wraps.len() > 65
            || stored.manifest.body.migration_id != expected.operation
            || stored.manifest.body.inventory_digest != expected.inventory_digest
            || stored.manifest.body.sources != expected.sources
        {
            return Err(invalid());
        }
        if let Some(source) = &stored.source_cursor {
            source.validate(before)?;
            if source.receipt().operation() != expected.operation
                || source.receipt().ciphertext_hash != expected.inventory_digest
            {
                return Err(invalid());
            }
        }
        let chain = target(before, keys, signer)?;
        let member = chain.current();
        let replica = before.replica.as_ref().ok_or_else(invalid)?;
        stored.manifest.verify(
            member,
            before.control.auth_epoch,
            1,
            &replica.vault,
            &before.control.device.id,
        )?;
        let body = &stored.manifest.body;
        if super::super::wire::number(&body.target_sequence, false)? != stored.rows.len() as u64
            || rekey::wraps_digest(&stored.wraps)? != body.wraps_digest
        {
            return Err(invalid());
        }
        let mut recipients = member.devices().clone();
        recipients.insert("recovery".into(), member.recovery().clone());
        if recipients.len() != stored.wraps.len() {
            return Err(invalid());
        }
        for wrap in &stored.wraps {
            let h = &wrap.header;
            let recipient = recipients.remove(&h.recipient).ok_or_else(invalid)?;
            if h.origin != body.origin
                || h.account_id != body.account_id
                || h.genesis_hash != body.genesis_hash
                || h.vault_id != body.vault_id
                || h.key_epoch != body.key_epoch
                || h.membership_head != body.membership_head
                || h.author != body.author
                || h.recipient_key != recipient.encryption
            {
                return Err(invalid());
            }
            wrap.verify_author(&before.control.device.keys.signing)?;
            if h.recipient == before.control.device.id {
                wrap.open(signer, h, &before.control.device.keys.signing)?
                    .verify_same(keys)?;
            }
        }
        let mut total = 0usize;
        let mut pages = vec![];
        let mut start = 0usize;
        let mut page_bytes = 0usize;
        for (index, row) in stored.rows.iter().enumerate() {
            let size = serde_json::to_vec(&row.envelope)
                .map_err(|_| invalid())?
                .len();
            total = total.checked_add(size).ok_or_else(invalid)?;
            if total > MAX_HISTORY_BYTES || size > MAX_PAGE_BYTES {
                return Err(invalid());
            }
            if index > start && (index - start >= 32 || page_bytes + size > MAX_PAGE_BYTES) {
                pages.push(start..index);
                start = index;
                page_bytes = 0;
            }
            page_bytes += size;
        }
        pages.push(start..stored.rows.len());
        let checkpoint = Checkpoint {
            epoch: 1,
            sequence: stored.rows.len() as u64,
            history_hash: body.target_history_hash.clone(),
        };
        let mut verified = before.clone();
        for range in &pages {
            let page = verified
                .replica
                .as_ref()
                .ok_or_else(invalid)?
                .prepare_page(&chain, keys, &stored.rows[range.clone()], &checkpoint)?;
            for opened in page.opened {
                payload::admit(keys, &opened.version.envelope.header, &opened.plaintext)?;
            }
            verified.replica = Some(page.next);
        }
        if verified.replica.as_ref().ok_or_else(invalid)?.checkpoint != checkpoint
            || !projection::Plan::inventory(verified, keys)?.complete()
        {
            return Err(invalid());
        }
        Ok(Self {
            before: stored.before,
            manifest: stored.manifest,
            rows: stored.rows,
            wraps: stored.wraps,
            pages,
        })
    }
}

#[cfg(test)]
mod tests;
