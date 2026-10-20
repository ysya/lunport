//! Durable pre-plan freeze/fetch progress. No consent or publication authority.
use super::{
    crypto::{self, DeviceKeys},
    migration_freeze::{Progress, SignedFreeze},
    migration_sources::{Fetching, FrozenSnapshot, Sources, MAX_BOOK_BYTES, MAX_FROZEN_BYTES},
    source_archive::{self, Outputs, Receipt},
    source_cursor::{Cursor, Restored},
    source_package::Package,
    wire::invalid,
    workspace::Workspace,
};
use crate::{error::AppError, sync::env::SyncEnv};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
use std::sync::MutexGuard;
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"LPCAPT1\0";
const CAP: usize = MAX_FROZEN_BYTES + 2 * MAX_BOOK_BYTES + 1024 * 1024;
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn encode_secret<S: Serializer>(s: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(s)
}
fn pending<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(d).map(|s| s.map(Zeroizing::new))
}
fn encode_pending<S: Serializer>(
    s: &Option<Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    s.as_deref().map(|s| s.as_str()).serialize(serializer)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    version: u32,
    revision: u64,
    source: Receipt,
    ancestors: Vec<Receipt>,
    #[serde(deserialize_with = "secret", serialize_with = "encode_secret")]
    book: Zeroizing<String>,
    #[serde(deserialize_with = "pending", serialize_with = "encode_pending")]
    pending_book: Option<Zeroizing<String>>,
    intent: SignedFreeze,
    fetching: Option<Fetching>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    inherited: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inherited_book: Option<String>,
}
pub(super) struct Loaded {
    pub cursor: Cursor,
    journal: Journal,
    pub package: Package,
    pub outputs: Outputs,
}
fn book(sources: &Sources) -> Result<Zeroizing<String>, AppError> {
    Ok(Zeroizing::new(
        std::str::from_utf8(&sources.encode_local()?)
            .map_err(|_| invalid())?
            .to_owned(),
    ))
}
impl Journal {
    pub fn pending_progress(bytes: &[u8]) -> Result<Progress, AppError> {
        Ok(Self::decode(bytes)?
            .fetching
            .ok_or_else(invalid)?
            .progress()
            .clone())
    }
    pub fn pending_snapshot(
        bytes: &[u8],
        sources: &Sources,
        state: &crate::sync::records_v3::SyncStateV3,
        chain: &str,
    ) -> Result<FrozenSnapshot, AppError> {
        Self::decode(bytes)?
            .fetching
            .ok_or_else(invalid)?
            .snapshot_for(sources, state, chain)
    }
    pub fn matches_bytes(&self, bytes: &[u8]) -> Result<bool, AppError> {
        Ok(self.encode()?.as_slice() == bytes)
    }
    pub fn begin(
        cursor: &Cursor,
        package: &Package,
        signer: &DeviceKeys,
    ) -> Result<Self, AppError> {
        if cursor.revision() != 1 {
            return Err(invalid());
        }
        let owner = package.state.local.central.as_ref().ok_or_else(invalid)?;
        let result = Self {
            version: 2,
            revision: 2,
            source: cursor.receipt().clone(),
            ancestors: vec![cursor.receipt().clone()],
            book: book(&package.sources)?,
            pending_book: None,
            intent: package.sources.intent(
                owner,
                signer,
                cursor.receipt().operation(),
                &cursor.receipt().ciphertext_hash,
                None,
            )?,
            fetching: None,
            inherited: vec![],
            inherited_book: None,
        };
        result.before(cursor, owner)?;
        Ok(result)
    }
    fn lineage(&self, owner: &Workspace) -> Result<(), AppError> {
        if !matches!(self.version, 1 | 2)
            || self.version == 1 && (!self.inherited.is_empty() || self.inherited_book.is_some())
            || self.inherited.len() > 65
            || self.inherited.windows(2).any(|pair| pair[0] >= pair[1])
            || self.ancestors.is_empty()
            || self.ancestors.len() > 254
            || self.revision != self.ancestors.len() as u64 + 1
            || self.ancestors.first() != Some(&self.source)
        {
            return Err(invalid());
        }
        let mut hashes = std::collections::BTreeSet::new();
        for receipt in &self.ancestors {
            receipt.matches_selected(owner)?;
            if !hashes.insert(&receipt.ciphertext_hash) {
                return Err(invalid());
            }
        }
        for pair in self.ancestors.windows(2) {
            if !pair[1].follows(&pair[0])? {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn before(&self, cursor: &Cursor, owner: &Workspace) -> Result<(), AppError> {
        self.lineage(owner)?;
        if self.revision != cursor.revision().checked_add(1).ok_or_else(invalid)?
            || self.ancestors.last() != Some(cursor.receipt())
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn current(&self, cursor: &Cursor, owner: &Workspace) -> Result<(), AppError> {
        self.lineage(owner)?;
        cursor.receipt().matches_selected(owner)?;
        if self.revision != cursor.revision()
            || self.ancestors.last() != cursor.previous()
            || !cursor
                .receipt()
                .follows(self.ancestors.last().ok_or_else(invalid)?)?
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn frame(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC)
    }
    fn encode_full(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let mut bytes = Zeroizing::new(MAGIC.to_vec());
        serde_json::to_writer(&mut *bytes, self).map_err(|_| invalid())?;
        if bytes.len() > CAP {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        if self.version == 1 {
            return self.encode_full();
        }
        let fetching = self
            .fetching
            .as_ref()
            .map(|fetching| fetching.encode_delta(&self.inherited))
            .transpose()?;
        #[derive(Serialize)]
        struct Delta<'a> {
            version: u32,
            revision: u64,
            source: &'a Receipt,
            ancestors: &'a [Receipt],
            book: &'a str,
            pending_book: Option<&'a str>,
            intent: &'a SignedFreeze,
            fetching: Option<&'a RawValue>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            inherited: &'a Vec<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            inherited_book: &'a Option<String>,
        }
        let fetching = fetching
            .as_ref()
            .map(|bytes| serde_json::from_slice::<&RawValue>(bytes).map_err(|_| invalid()))
            .transpose()?;
        let delta = Delta {
            version: self.version,
            revision: self.revision,
            source: &self.source,
            ancestors: &self.ancestors,
            book: if self
                .inherited_book
                .as_ref()
                .is_some_and(|hash| *hash == crypto::hash(self.book.as_bytes()))
            {
                ""
            } else {
                &self.book
            },
            pending_book: self.pending_book.as_ref().map(|value| value.as_str()),
            intent: &self.intent,
            fetching,
            inherited: &self.inherited,
            inherited_book: &self.inherited_book,
        };
        let mut bytes = Zeroizing::new(MAGIC.to_vec());
        serde_json::to_writer(&mut *bytes, &delta).map_err(|_| invalid())?;
        if bytes.len() > CAP {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn inherit(
        &mut self,
        previous: Option<Fetching>,
        previous_book: Option<Zeroizing<String>>,
    ) -> Result<(), AppError> {
        if self.version == 1 {
            return if self.inherited.is_empty() {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if let Some(expected) = &self.inherited_book {
            let previous = previous_book.as_ref().ok_or_else(invalid)?;
            if crypto::hash(previous.as_bytes()) != *expected {
                return Err(invalid());
            }
            if self.book.is_empty() {
                self.book = previous.clone();
            }
        } else if self.book.is_empty() {
            return Err(invalid());
        }
        match &mut self.fetching {
            Some(fetching) => fetching.inherit(&self.inherited, previous),
            None if self.inherited.is_empty() && previous.is_none() => Ok(()),
            _ => Err(invalid()),
        }
    }
    fn decode(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > CAP || !bytes.starts_with(MAGIC) {
            return Err(invalid());
        }
        serde_json::from_slice(&bytes[8..]).map_err(|_| invalid())
    }
    fn inputs(
        &mut self,
        env: &SyncEnv,
        owner: &Workspace,
        signer: &DeviceKeys,
        outputs: Outputs,
    ) -> Result<(Package, Outputs, Option<Fetching>), AppError> {
        let profile = owner.control.profile.profile()?;
        let mut outputs = Some(outputs);
        let (package, parent) = self.captured_inputs(owner, Some(signer), |receipt| {
            let (bytes, proof) = source_archive::restore_with_outputs(env, &profile, receipt)?;
            outputs = Some(outputs.take().ok_or_else(invalid)?.merge(proof)?);
            Ok(bytes)
        })?;
        Ok((package, outputs.ok_or_else(invalid)?, parent))
    }
    fn captured_inputs(
        &mut self,
        owner: &Workspace,
        signer: Option<&DeviceKeys>,
        mut read: impl FnMut(&Receipt) -> Result<Zeroizing<Vec<u8>>, AppError>,
    ) -> Result<(Package, Option<Fetching>), AppError> {
        self.lineage(owner)?;
        let mut package = None;
        let mut previous = None;
        let mut previous_book = None;
        for (index, receipt) in self.ancestors.iter().enumerate() {
            let bytes = read(receipt)?;
            if receipt == &self.source {
                package = Some(Package::decode_local(&bytes)?);
            } else {
                let mut prior = Self::decode(&bytes)?;
                prior.lineage(owner)?;
                if prior.source != self.source
                    || prior.ancestors != self.ancestors[..index]
                    || prior.revision != index as u64 + 1
                {
                    return Err(invalid());
                }
                prior.inherit(previous, previous_book)?;
                // A captured ancestor may not hide an unreadable book or invalid intent just
                // because its successor supplied a replacement book instead of a delta.
                if signer.is_none() {
                    drop(prior.checked_sources(
                        owner,
                        None,
                        package.as_ref().ok_or_else(invalid)?,
                    )?);
                }
                previous_book = Some(prior.book);
                previous = prior.fetching;
            }
        }
        let parent_fetching = previous.clone();
        self.inherit(previous, previous_book)?;
        let mut package = package.ok_or_else(invalid)?;
        let sources = self.checked_sources(owner, signer, &package)?;
        package.sources = sources;
        Ok((package, parent_fetching))
    }
    fn checked_sources(
        &self,
        owner: &Workspace,
        signer: Option<&DeviceKeys>,
        package: &Package,
    ) -> Result<Sources, AppError> {
        if package.state.local.central.as_ref() != Some(owner)
            || !self
                .intent
                .body
                .preview_digest
                .eq(&self.source.ciphertext_hash)
            || self.intent.body.migration_id != self.source.operation()
            || self.book.len() > MAX_BOOK_BYTES
            || self
                .pending_book
                .as_ref()
                .is_some_and(|b| b.len() > MAX_BOOK_BYTES)
        {
            return Err(invalid());
        }
        let original_book = crypto::hash(&package.sources.encode_local()?);
        let sources = Sources::decode_local(self.book.as_bytes(), &package.state)?;
        if !sources.follows_book(&original_book)? {
            return Err(invalid());
        }
        if let Some(fetching) = &self.fetching {
            drop(Fetching::decode_local(
                &fetching.encode_local()?,
                &sources,
                &package.state,
            )?);
        }
        let pending_sources = self
            .pending_book
            .as_ref()
            .map(|b| Sources::decode_local(b.as_bytes(), &package.state))
            .transpose()?;
        let effective = pending_sources.as_ref().unwrap_or(&sources);
        if !effective.follows_book(&crypto::hash(&sources.encode_local()?))? {
            return Err(invalid());
        }
        let expected = effective.intent_body(
            owner,
            self.source.operation(),
            &self.source.ciphertext_hash,
            self.fetching.as_ref().map(Fetching::progress),
        )?;
        if expected != self.intent.body {
            return Err(invalid());
        }
        if let Some(signer) = signer {
            if effective.intent(
                owner,
                signer,
                self.source.operation(),
                &self.source.ciphertext_hash,
                self.fetching.as_ref().map(Fetching::progress),
            )? != self.intent
            {
                return Err(invalid());
            }
        } else {
            self.intent.verify(
                owner.control.verified_chain()?.current(),
                owner.control.auth_epoch,
                owner.replica.as_ref().ok_or_else(invalid)?.checkpoint.epoch,
                owner
                    .control
                    .personal_vault
                    .as_deref()
                    .ok_or_else(invalid)?,
                &owner.control.device.id,
            )?;
        }
        Ok(sources)
    }
    fn restored(
        env: &SyncEnv,
        owner: &Workspace,
        signer: &DeviceKeys,
        saved: Restored,
    ) -> Result<Loaded, AppError> {
        let mut journal = Self::decode(&saved.bytes)?;
        journal.current(&saved.cursor, owner)?;
        let (package, outputs, _) = journal.inputs(env, owner, signer, saved.outputs)?;
        Ok(Loaded {
            cursor: saved.cursor,
            journal,
            package,
            outputs,
        })
    }
    /// A protected complete-source cursor pins this predecessor and all of its ancestry.
    /// Re-derive exact complete bytes; this creates no historical cursor or publication permit.
    pub fn completed_source(
        env: &SyncEnv,
        owner: &Workspace,
        signer: &DeviceKeys,
        saved: Restored,
    ) -> Result<(Package, Vec<Receipt>, Cursor, Outputs), AppError> {
        if Self::frame(&saved.bytes) {
            return Self::restored(env, owner, signer, saved)?.into_complete();
        }
        let parent = saved.cursor.previous().ok_or_else(invalid)?.clone();
        let (bytes, proof) =
            source_archive::restore_with_outputs(env, &owner.control.profile.profile()?, &parent)?;
        let mut journal = Self::decode(&bytes)?;
        journal.lineage(owner)?;
        if journal.pending_book.is_some()
            || journal.revision.checked_add(1) != Some(saved.cursor.revision())
            || !parent.follows(journal.ancestors.last().ok_or_else(invalid)?)?
        {
            return Err(invalid());
        }
        let (package, outputs, _) =
            journal.inputs(env, owner, signer, saved.outputs.merge(proof)?)?;
        let fetching = journal.fetching.ok_or_else(invalid)?;
        if fetching
            .discovered_sources(&package.sources, &package.state)?
            .is_some()
        {
            return Err(invalid());
        }
        let complete = package.finish_fetching(fetching)?;
        if complete.encode_local()?.as_slice() != saved.bytes.as_slice() {
            return Err(invalid());
        }
        let mut ancestors = journal.ancestors;
        ancestors.push(parent);
        ancestors.push(saved.cursor.receipt().clone());
        if ancestors.len() as u64 != saved.cursor.revision() {
            return Err(invalid());
        }
        Ok((complete, ancestors, saved.cursor, outputs))
    }
    pub fn load(
        env: &SyncEnv,
        life: &MutexGuard<'_, ()>,
        owner: &Workspace,
        signer: &DeviceKeys,
    ) -> Result<Option<Loaded>, AppError> {
        Cursor::load(env, life, owner)?
            .map(|s| Self::restored(env, owner, signer, s))
            .transpose()
    }
    pub fn store(
        mut self,
        env: &SyncEnv,
        life: &MutexGuard<'_, ()>,
        owner: &Workspace,
        signer: &DeviceKeys,
        before: &Cursor,
        generation: u64,
    ) -> Result<Loaded, AppError> {
        let current = Cursor::load(env, life, owner)?.ok_or_else(invalid)?;
        let encoded = self.encode()?;
        if current.cursor.revision() == self.revision
            && current.bytes.as_slice() == encoded.as_slice()
        {
            return Self::restored(env, owner, signer, current);
        }
        if &current.cursor != before {
            return Err(invalid());
        }
        self.before(before, owner)?;
        let (package, outputs, parent_fetching) =
            self.inputs(env, owner, signer, current.outputs)?;
        if current.bytes.starts_with(MAGIC) {
            let mut old = Self::decode(&current.bytes)?;
            old.fetching = parent_fetching;
            old.current(before, owner)?;
            if self.source != old.source
                || self.ancestors[..self.ancestors.len() - 1] != old.ancestors
            {
                return Err(invalid());
            }
            if self.intent != old.intent {
                self.intent
                    .body
                    .extends(&old.intent.body, &old.intent.digest()?)?;
            }
            if let Some(previous) = &old.fetching {
                self.fetching.as_ref().ok_or_else(invalid)?.require_after(
                    &package.sources,
                    &package.state,
                    previous,
                )?;
            }
        } else if before.receipt() != &self.source
            || self.fetching.is_some()
            || self.pending_book.is_some()
        {
            return Err(invalid());
        }
        let pending = source_archive::resume_next(
            env,
            owner,
            before.receipt(),
            generation,
            &encoded,
            &outputs,
        )?;
        let (archived, outputs) = match pending {
            Some((archived, proof)) => (Some(archived), outputs.merge(proof)?),
            None => (None, outputs),
        };
        package.files.require_unchanged_after_archive(
            env,
            package.state.legacy_v1_backup.as_deref(),
            &outputs,
        )?;
        let archived = match archived {
            Some(archived) => archived,
            None => {
                outputs.require_room_for_snapshot(encoded.len())?;
                source_archive::next(env, life, owner, generation, before.receipt(), &encoded)?
            }
        };
        let saved = before.advance(env, life, owner, &archived)?;
        Self::restored(env, owner, signer, saved)
    }
}
impl Loaded {
    fn successor(&self, owner: &Workspace) -> Result<Journal, AppError> {
        self.journal.current(&self.cursor, owner)?;
        let mut next = Journal::decode(&self.journal.encode_full()?)?;
        next.version = 2;
        next.inherited_book = Some(crypto::hash(self.journal.book.as_bytes()));
        next.inherited = self
            .journal
            .fetching
            .as_ref()
            .map_or_else(Vec::new, Fetching::response_chains);
        next.revision = next.revision.checked_add(1).ok_or_else(invalid)?;
        next.ancestors.push(self.cursor.receipt().clone());
        next.before(&self.cursor, owner)?;
        Ok(next)
    }
    pub(super) fn compact(&self) -> bool {
        self.journal.version == 2
    }
    pub fn intent(&self) -> &SignedFreeze {
        &self.journal.intent
    }
    pub fn pending_discovery(&self) -> bool {
        self.journal.pending_book.is_some()
    }
    pub fn effective_sources(&self) -> Result<Sources, AppError> {
        let encoded = match &self.journal.pending_book {
            Some(book) => Zeroizing::new(book.as_bytes().to_vec()),
            None => self.package.sources.encode_local()?,
        };
        Sources::decode_local(&encoded, &self.package.state)
    }
    pub fn fetching(&self) -> Option<&Fetching> {
        self.journal.fetching.as_ref()
    }
    pub fn with_progress(
        &self,
        owner: &Workspace,
        progress: &Progress,
    ) -> Result<Journal, AppError> {
        if progress
            .proof
            .last()
            .is_none_or(|p| p.intent != self.journal.intent)
        {
            return Err(invalid());
        }
        let mut next = self.successor(owner)?;
        if let Some(pending) = next.pending_book.take() {
            next.book = pending;
        }
        let sources = Sources::decode_local(next.book.as_bytes(), &self.package.state)?;
        if let Some(fetching) = &mut next.fetching {
            fetching.advance(&sources, &self.package.state, progress)?;
        } else {
            next.fetching = Some(Fetching::new(
                &sources,
                &self.package.state,
                self.journal.source.operation(),
                progress,
            )?);
        }
        Ok(next)
    }
    pub fn with_snapshot(
        &self,
        owner: &Workspace,
        snapshot: FrozenSnapshot,
    ) -> Result<Journal, AppError> {
        let mut next = self.successor(owner)?;
        next.fetching.as_mut().ok_or_else(invalid)?.insert(
            &self.package.sources,
            &self.package.state,
            snapshot,
        )?;
        Ok(next)
    }
    pub fn with_discovery(
        &self,
        owner: &Workspace,
        signer: &DeviceKeys,
        sources: Sources,
    ) -> Result<Journal, AppError> {
        let mut next = self.successor(owner)?;
        if next.pending_book.is_some()
            || next.fetching.is_none()
            || !sources.follows_book(&crypto::hash(&self.package.sources.encode_local()?))?
        {
            return Err(invalid());
        }
        next.intent = sources.intent(
            owner,
            signer,
            self.journal.source.operation(),
            &self.journal.source.ciphertext_hash,
            next.fetching.as_ref().map(Fetching::progress),
        )?;
        next.pending_book = Some(book(&sources)?);
        Ok(next)
    }
    pub fn require_unchanged(&self, env: &SyncEnv) -> Result<(), AppError> {
        self.package.files.require_unchanged_after_archive(
            env,
            self.package.state.legacy_v1_backup.as_deref(),
            &self.outputs,
        )
    }
    /// Consumption yields a passive complete source, never a publication or consent permit.
    pub fn into_complete(self) -> Result<(Package, Vec<Receipt>, Cursor, Outputs), AppError> {
        if self.journal.pending_book.is_some() {
            return Err(invalid());
        }
        let complete = self
            .package
            .finish_fetching(self.journal.fetching.ok_or_else(invalid)?)?;
        let mut ancestors = self.journal.ancestors;
        ancestors.push(self.cursor.receipt().clone());
        Ok((complete, ancestors, self.cursor, self.outputs))
    }
}
mod captured;
#[cfg(all(test, unix))]
mod tests;

pub(super) fn is_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}
