//! Native-only recovery admission. A kit proof alone cannot authorize authority replacement:
//! first decrypt and admit the complete pinned retained history under committed content keys.
use super::{
    client_state::Phase,
    crypto::{VaultKeys, WrappedKeys},
    membership::{personal_vault_id, Enrollment},
    payload,
    recovery::RecoveryKit,
    rekey::{self, Checkpoint, SignedRekey, Version},
    replica::Replica,
    trust::{ControlProof, VerifiedChain},
    wire::{hex, invalid, number},
    workspace::Workspace,
};
use crate::error::AppError;
use serde::Deserialize;
use std::collections::BTreeSet;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochBundle {
    pub manifest: SignedRekey,
    pub wraps: Vec<WrappedKeys>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryVault {
    pub vault: String,
    pub epoch: u64,
    pub phase: String,
    pub wrap: WrappedKeys,
    pub committed: Option<EpochBundle>,
    pub commits: Vec<SignedRekey>,
    pub sequence: String,
    pub history_hash: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReply {
    pub membership_head: String,
    pub auth_epoch: u64,
    pub results: Vec<RecoveryVault>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub records: Vec<Version>,
    pub sequence: String,
    pub history_hash: String,
    pub membership_head: String,
    pub epoch: u64,
    pub phase: String,
}
/// No Debug/Serialize and no plaintext publication. Every page commits only after full admission.
pub struct ReadSession {
    before: Workspace,
    chain: VerifiedChain,
    proof: ControlProof,
    request: Enrollment,
    auth_epoch: u64,
    keys: VaultKeys,
    source: RecoveryVault,
    target: Checkpoint,
    replica: Replica,
    required_prefixes: Vec<Checkpoint>,
    operations: BTreeSet<String>,
    bytes: usize,
}
/// Only a completed read mints this capability. Neither a server DTO nor a saved receipt can.
pub struct VerifiedRecovery {
    session: ReadSession,
}
fn epochs(chain: &VerifiedChain, vault: &RecoveryVault, auth_epoch: u64) -> Result<(), AppError> {
    if vault.epoch == 0 || vault.epoch > 65 || vault.commits.len() as u64 + 1 != vault.epoch {
        return Err(invalid());
    }
    let mut revision = 0;
    let mut authorization = 1;
    let mut sequence = 0;
    let mut rotations = BTreeSet::new();
    for (index, commit) in vault.commits.iter().enumerate() {
        commit.verify_historical(chain, &vault.vault)?;
        let body = &commit.body;
        let next = chain
            .revision_of(&body.membership_head)
            .ok_or_else(invalid)?;
        let next_auth = number(&body.authorization_epoch, false)?;
        let next_sequence = number(&body.source_sequence, true)?;
        if number(&body.from_epoch, false)? != index as u64 + 1
            || next < revision
            || next_auth <= authorization
            || next_auth > auth_epoch
            || next_sequence < sequence
            || !rotations.insert(&body.rotation_id)
        {
            return Err(invalid());
        }
        revision = next;
        authorization = next_auth;
        sequence = next_sequence;
    }
    match (&vault.committed, vault.commits.last()) {
        (None, None) if vault.epoch == 1 => Ok(()),
        (Some(bundle), Some(last)) if &bundle.manifest == last => {
            rekey::verify_committed_wraps(chain, last, &bundle.wraps)
        }
        _ => Err(invalid()),
    }
}
impl ReadSession {
    /// This entry point is restricted to a fresh pending owner. Existing device replacement
    /// additionally needs archived local bytes and cross-epoch checkpoint continuity.
    pub fn begin_fresh(
        before: &Workspace,
        kit: &RecoveryKit,
        proof: ControlProof,
        mut response: RecoveryReply,
        now: u64,
    ) -> Result<Self, AppError> {
        before.validate()?;
        let control = &before.control;
        if control.phase != Phase::AwaitingApproval
            || control.anchor.is_some()
            || control.cutover
            || control.library.is_some()
            || before.replica.is_some()
            || before.recovery.is_some()
            || !before.epochs.is_empty()
            || !before.observed_epochs.is_empty()
            || before.bootstrap.is_some()
            || !before.own_wraps.is_empty()
        {
            return Err(invalid());
        }
        let request = control.pending_request.clone().ok_or_else(invalid)?;
        let auth_epoch = control.auth_epoch;
        request.verify_live(now)?;
        let anchor = kit.anchor();
        if request.origin != anchor.origin
            || request.account_id != anchor.account_id
            || request.genesis_hash != anchor.genesis_hash
            || auth_epoch < 2
            || response.auth_epoch != auth_epoch
            || response.results.len() != 1
        {
            return Err(invalid());
        }
        let chain = proof.verify(anchor, None)?;
        let authority = kit.current_keys(&chain)?;
        if response.membership_head != chain.current().head()
            || chain.current().devices().contains_key(&request.device.id)
        {
            return Err(invalid());
        }
        let source = response.results.pop().ok_or_else(invalid)?;
        if source.vault != personal_vault_id(anchor)?
            || !["ready", "rekey_pending"].contains(&source.phase.as_str())
        {
            return Err(invalid());
        }
        epochs(&chain, &source, auth_epoch)?;
        let target = Checkpoint {
            epoch: source.epoch,
            sequence: number(&source.sequence, true)?,
            history_hash: source.history_hash.clone(),
        };
        if target.sequence > 16384
            || !hex(&target.history_hash, 64)
            || target.sequence == 0 && target.history_hash != ZERO
        {
            return Err(invalid());
        }
        let h = &source.wrap.header;
        let wrap_revision = chain.revision_of(&h.membership_head).ok_or_else(invalid)?;
        if h.origin != anchor.origin
            || h.account_id != anchor.account_id
            || h.genesis_hash != anchor.genesis_hash
            || h.vault_id != source.vault
            || h.recipient != "recovery"
            || h.recipient_key != authority.public().encryption
            || number(&h.key_epoch, false)? != target.epoch
        {
            return Err(invalid());
        }
        kit.keys_at(&chain, &h.membership_head)?;
        let author = chain
            .author_at(&h.membership_head, &h.author)
            .ok_or_else(invalid)?;
        let keys = source.wrap.open(&authority, h, &author.signing)?;
        if let Some(bundle) = &source.committed {
            let body = &bundle.manifest.body;
            if wrap_revision
                < chain
                    .revision_of(&body.membership_head)
                    .ok_or_else(invalid)?
                || target.sequence < number(&body.source_sequence, true)?
            {
                return Err(invalid());
            }
            // A kit may have changed since this content epoch. When it can open the committed
            // key pair, compare both keys even for an empty history. Otherwise the next-head
            // authority bridge must decrypt every retained row before Recover can be prepared.
            if let Ok(old_authority) = kit.keys_at(&chain, &body.membership_head) {
                let committed_keys = rekey::open_committed_keys(
                    &chain,
                    &bundle.manifest,
                    &bundle.wraps,
                    "recovery",
                    &old_authority,
                )?;
                keys.verify_same(&committed_keys)?;
            }
        }
        let replica = Replica::join(
            source.vault.clone(),
            anchor.genesis_hash.clone(),
            2,
            target.clone(),
        )?;
        Ok(Self {
            before: before.clone(),
            chain,
            proof,
            request,
            auth_epoch,
            keys,
            source,
            target,
            replica,
            required_prefixes: vec![],
            operations: BTreeSet::new(),
            bytes: 0,
        })
    }
    pub(super) fn chain(&self) -> &VerifiedChain {
        &self.chain
    }
    pub(super) fn epochs(&self) -> &[SignedRekey] {
        &self.source.commits
    }
    pub(super) fn pin_prefixes(&mut self, minimums: Vec<Checkpoint>) -> Result<(), AppError> {
        if self.position() != 0 || minimums.len() > 4 {
            return Err(invalid());
        }
        for minimum in &minimums {
            if minimum.epoch != self.target.epoch
                || minimum.sequence > self.target.sequence
                || !hex(&minimum.history_hash, 64)
                || minimum.sequence == 0 && minimum.history_hash != ZERO
                || minimum.sequence == self.target.sequence
                    && minimum.history_hash != self.target.history_hash
            {
                return Err(invalid());
            }
        }
        self.required_prefixes = minimums;
        Ok(())
    }
    pub fn total(&self) -> u64 {
        self.target.sequence
    }
    pub fn vault(&self) -> &str {
        &self.source.vault
    }
    pub fn position(&self) -> u64 {
        self.replica.checkpoint.sequence
    }
    pub fn append(&mut self, page: HistoryPage) -> Result<(), AppError> {
        if page.epoch != self.target.epoch
            || page.membership_head != self.chain.current().head()
            || number(&page.sequence, true)? != self.target.sequence
            || page.history_hash != self.target.history_hash
            || !["ready", "rekey_pending"].contains(&page.phase.as_str())
        {
            return Err(invalid());
        }
        let prepared =
            self.replica
                .prepare_page(&self.chain, &self.keys, &page.records, &self.target)?;
        let mut operations = self.operations.clone();
        let mut bytes = self.bytes;
        for opened in prepared.opened {
            let row = &opened.version;
            if self.required_prefixes.iter().any(|minimum| {
                minimum.sequence.to_string() == row.sequence
                    && minimum.history_hash != row.history_hash
            }) {
                return Err(invalid());
            }
            payload::admit(&self.keys, &row.envelope.header, &opened.plaintext)?;
            if !operations.insert(row.envelope.header.operation_id.clone()) {
                return Err(invalid());
            }
            bytes += serde_json::to_vec(row).map_err(|_| invalid())?.len();
            if bytes > 32 * 1024 * 1024 {
                return Err(invalid());
            }
            if let Some(bundle) = &self.source.committed {
                let body = &bundle.manifest.body;
                let sequence = number(&row.sequence, false)?;
                let count = number(&body.source_sequence, true)?;
                if sequence <= count
                    && (row.envelope.header.membership_head != body.membership_head
                        || row.envelope.header.author != body.author)
                    || sequence == count && row.history_hash != body.target_history_hash
                {
                    return Err(invalid());
                }
            }
        }
        self.replica = prepared.next;
        self.operations = operations;
        self.bytes = bytes;
        Ok(())
    }
    pub fn finish(self) -> Result<VerifiedRecovery, AppError> {
        if self.replica.checkpoint != self.target || !self.replica.baseline_ready() {
            return Err(invalid());
        }
        Ok(VerifiedRecovery { session: self })
    }
}
impl VerifiedRecovery {
    pub fn previous_owner(&self) -> &Workspace {
        &self.session.before
    }
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.session.target
    }
    pub fn chain(&self) -> &VerifiedChain {
        &self.session.chain
    }
    pub fn proof(&self) -> &ControlProof {
        &self.session.proof
    }
    pub fn request(&self) -> &Enrollment {
        &self.session.request
    }
    pub fn auth_epoch(&self) -> u64 {
        self.session.auth_epoch
    }
    pub fn keys(&self) -> &VaultKeys {
        &self.session.keys
    }
    pub fn replica(&self) -> &Replica {
        &self.session.replica
    }
    pub fn epochs(&self) -> &[SignedRekey] {
        &self.session.source.commits
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::{
        client_state::{ProfileData, State},
        credentials::Profile,
        crypto::{self, DeviceKeys},
        membership::{Action, Genesis, SignedMembership},
        oidc::OidcConfig,
        pairing::PendingPairing,
        payload::{Data, Identity},
        recovery::RecoverySeed,
        wire::{canonical, RecordHeader, WrapHeader},
    };
    use super::*;
    use crate::sync::records_v3::HostScope;
    struct Case {
        kit: RecoveryKit,
        proof: ControlProof,
        signer: DeviceKeys,
        keys: VaultKeys,
        before: Workspace,
        identity: DeviceKeys,
        response: RecoveryReply,
        rows: Vec<Version>,
    }
    fn owner(kit: &RecoveryKit, auth: u64) -> Workspace {
        owner_keys(kit, auth).0
    }
    fn owner_keys(kit: &RecoveryKit, auth: u64) -> (Workspace, DeviceKeys) {
        let profile = Profile::new(&kit.anchor().origin, "https://id.test", "subject").unwrap();
        let device = DeviceKeys::generate().unwrap();
        let pending = PendingPairing::begin(kit.anchor(), &"2".repeat(32), &device, 1000).unwrap();
        let state = State::new(
            ProfileData {
                origin: profile.origin,
                issuer: profile.issuer.clone(),
                subject: profile.subject,
                locator: profile.locator,
                oidc: OidcConfig {
                    issuer: profile.issuer,
                    client_id: "native".into(),
                    scopes: vec![],
                    audience: Some("api".into()),
                },
            },
            kit.anchor().account_id.clone(),
            pending.request().device.clone(),
            auth,
        )
        .unwrap()
        .begin_pairing(&pending)
        .unwrap();
        (Workspace::new(state).unwrap(), device)
    }
    fn wrapped(
        chain: &VerifiedChain,
        signer: &DeviceKeys,
        keys: &VaultKeys,
        epoch: u64,
    ) -> WrappedKeys {
        let a = chain.current().anchor();
        crypto::wrap_keys(
            keys,
            signer,
            WrapHeader {
                origin: a.origin.clone(),
                account_id: a.account_id.clone(),
                genesis_hash: a.genesis_hash.clone(),
                vault_id: personal_vault_id(a).unwrap(),
                key_epoch: epoch.to_string(),
                membership_head: chain.current().head().into(),
                author: "1".repeat(32),
                recipient: "recovery".into(),
                recipient_key: chain.current().recovery().encryption.clone(),
            },
        )
        .unwrap()
    }
    fn row(c: &Case, seq: u64, previous: &str, valid: bool) -> Version {
        let id = Identity {
            kind: "host".into(),
            id: format!("{seq:016x}"),
            scope: Some(HostScope::Local),
        };
        let value = serde_json::json!({"schema":2,"alias":format!("host-{seq}"),"hostname":"fixture.invalid","auth":"password"});
        let bytes = if valid {
            payload::encode(&id, &Data::Host(serde_json::from_value(value).unwrap())).unwrap()
        } else {
            zeroize::Zeroizing::new(
                serde_json::to_vec(&serde_json::json!({"schema":1,"id":id.id,
                "scope":id.scope,"payload":{"schema":2,"alias":"bad","hostname":"fixture.invalid",
                    "auth":"password","password":"PRIVATE-LOCAL-SENTINEL"}}))
                .unwrap(),
            )
        };
        let a = c.kit.anchor();
        let envelope = crypto::seal_record(
            &c.keys,
            &c.signer,
            RecordHeader {
                origin: a.origin.clone(),
                account_id: a.account_id.clone(),
                genesis_hash: a.genesis_hash.clone(),
                vault_id: personal_vault_id(a).unwrap(),
                record_id: id.opaque(&c.keys).unwrap(),
                key_epoch: "1".into(),
                membership_head: a.genesis_hash.clone(),
                author: "1".repeat(32),
                operation_id: format!("{seq:032x}"),
                expected_revision: "0".into(),
                kind: "host".into(),
                deleted: false,
            },
            &bytes,
        )
        .unwrap();
        let digest = rekey::envelope_digest(&envelope).unwrap();
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
    fn case(count: u64) -> Case {
        let signer = DeviceKeys::generate().unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let recovery = seed.keys("https://relay.test", &"a".repeat(64)).unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://relay.test",
            &"a".repeat(64),
            &"1".repeat(32),
            &signer,
            &recovery,
        )
        .unwrap();
        let proof = ControlProof {
            genesis,
            nodes: vec![],
        };
        let chain = proof.verify(&anchor, None).unwrap();
        let kit = seed.bind(&chain).unwrap();
        let (before, identity) = owner_keys(&kit, 2);
        let keys = VaultKeys::generate().unwrap();
        let response = RecoveryReply {
            membership_head: chain.current().head().into(),
            auth_epoch: 2,
            results: vec![RecoveryVault {
                vault: personal_vault_id(&anchor).unwrap(),
                epoch: 1,
                phase: "rekey_pending".into(),
                wrap: wrapped(&chain, &signer, &keys, 1),
                committed: None,
                commits: vec![],
                sequence: "0".into(),
                history_hash: ZERO.into(),
            }],
        };
        let mut c = Case {
            kit,
            proof,
            signer,
            keys,
            before,
            identity,
            response,
            rows: vec![],
        };
        for seq in 1..=count {
            let previous = c.rows.last().map_or(ZERO, |row| row.history_hash.as_str());
            c.rows.push(row(&c, seq, previous, true));
        }
        c.response.results[0].sequence = count.to_string();
        c.response.results[0].history_hash = c
            .rows
            .last()
            .map_or(ZERO, |row| row.history_hash.as_str())
            .into();
        c
    }
    fn read(c: &Case) -> Result<ReadSession, AppError> {
        ReadSession::begin_fresh(&c.before, &c.kit, c.proof.clone(), c.response.clone(), 1000)
    }
    fn page(c: &Case, rows: &[Version]) -> HistoryPage {
        let source = &c.response.results[0];
        HistoryPage {
            records: rows.to_vec(),
            sequence: source.sequence.clone(),
            history_hash: source.history_hash.clone(),
            membership_head: c.response.membership_head.clone(),
            epoch: source.epoch,
            phase: "ready".into(),
        }
    }
    fn rotate(c: &mut Case) -> rekey::Plan {
        let chain = c.proof.verify(c.kit.anchor(), None).unwrap();
        let source = Checkpoint {
            epoch: 1,
            sequence: c.rows.len() as u64,
            history_hash: c.response.results[0].history_hash.clone(),
        };
        let zero = Checkpoint {
            epoch: 1,
            sequence: 0,
            history_hash: ZERO.into(),
        };
        let plan = rekey::prepare(
            &chain,
            &"1".repeat(32),
            &c.signer,
            &c.response.results[0].vault,
            3,
            &c.keys,
            &source,
            &zero,
            &c.rows,
        )
        .unwrap();
        c.before.control.auth_epoch = 3;
        c.response.auth_epoch = 3;
        let target = &mut c.response.results[0];
        target.epoch = 2;
        target.wrap = plan
            .wraps
            .iter()
            .find(|w| w.header.recipient == "recovery")
            .unwrap()
            .clone();
        target.committed = Some(EpochBundle {
            manifest: plan.manifest.clone(),
            wraps: plan.wraps.clone(),
        });
        target.commits = vec![plan.manifest.clone()];
        target.history_hash = plan.manifest.body.target_history_hash.clone();
        plan
    }
    pub(crate) fn verified_fresh_case(
        count: u64,
        rotated: bool,
    ) -> (VerifiedRecovery, RecoveryKit, DeviceKeys) {
        let mut c = case(count);
        let rows = if rotated {
            rotate(&mut c).rows
        } else {
            c.rows.clone()
        };
        let mut session = read(&c).unwrap();
        for rows in rows.chunks(32) {
            session.append(page(&c, rows)).unwrap();
        }
        (session.finish().unwrap(), c.kit, c.identity)
    }
    pub(crate) fn revalidation_fixture(
        rotated: bool,
    ) -> (Workspace, Workspace, RecoveryKit, RecoveryKit) {
        use super::super::{
            recovery_revalidation::{Bridge, Evidence},
            recovery_state::{PreparedRecovery, RecoveryState},
        };
        let mut c = case(1);
        let mut initial = read(&c).unwrap();
        initial.append(page(&c, &c.rows)).unwrap();
        let original = PreparedRecovery::create(
            initial.finish().unwrap(),
            &c.kit,
            &c.identity,
            RecoverySeed::generate().unwrap(),
            "c".repeat(32),
            1000,
        )
        .unwrap();
        let mut old = original.package.clone();
        old.backup_confirmed = true;
        old.submitted = true;
        let mut before = c.before.clone();
        before.recovery = Some(RecoveryState::Pending {
            package: Box::new(old.clone()),
        });
        before.validate().unwrap();
        let next = row(&c, 2, &c.rows[0].history_hash, true);
        c.response.results[0].history_hash = next.history_hash.clone();
        c.response.results[0].sequence = "2".into();
        c.rows.push(next);
        let (rows, bridges) = if rotated {
            let source_suffix = c
                .rows
                .iter()
                .skip(1)
                .map(|row| super::super::rekey::SourceDigest {
                    sequence: row.sequence.clone(),
                    digest: row.digest.clone(),
                })
                .collect();
            let plan = rotate(&mut c);
            (
                plan.rows,
                vec![Bridge {
                    epoch: 2,
                    digests: source_suffix,
                }],
            )
        } else {
            (c.rows.clone(), vec![])
        };
        let pending = PendingPairing::begin(
            c.kit.anchor(),
            &c.before.control.device.id,
            &c.identity,
            2000,
        )
        .unwrap();
        c.before.control.pending_request = Some(pending.request().clone());
        let mut session = read(&c).unwrap();
        for rows in rows.chunks(32) {
            session.append(page(&c, rows)).unwrap();
        }
        let mut replacement = PreparedRecovery::create(
            session.finish().unwrap(),
            &c.kit,
            &c.identity,
            original.kit.resume_seed(c.kit.anchor()).unwrap(),
            old.operation.clone(),
            2000,
        )
        .unwrap();
        replacement.package.attempt = 1;
        replacement.package.backup_confirmed = old.backup_confirmed;
        replacement.package.revalidation = Some(Evidence {
            previous: old.admission.clone(),
            node: old.node.clone(),
            bridges,
            tail: if rotated {
                vec![]
            } else {
                rows.iter()
                    .skip(1)
                    .map(|row| super::super::rekey::SourceDigest {
                        sequence: row.sequence.clone(),
                        digest: row.digest.clone(),
                    })
                    .collect()
            },
        });
        let mut after = c.before;
        after.recovery = Some(RecoveryState::Pending {
            package: Box::new(replacement.package),
        });
        assert_eq!(
            original.kit.encode_secret().unwrap().as_str(),
            replacement.kit.encode_secret().unwrap().as_str()
        );
        (before, after, original.kit, c.kit)
    }
    #[test]
    fn full_history_is_required_and_pages_keep_plaintext_inside_native_admission() {
        let c = case(33);
        assert!(read(&c).unwrap().finish().is_err());
        let mut r = read(&c).unwrap();
        assert!(r.append(page(&c, &c.rows)).is_err());
        assert_eq!(r.position(), 0);
        r.append(page(&c, &c.rows[..32])).unwrap();
        assert_eq!(r.position(), 32);
        let mut changed = page(&c, &c.rows[32..]);
        changed.sequence = "34".into();
        assert!(r.append(changed).is_err());
        assert_eq!(r.position(), 32);
        r.append(page(&c, &c.rows[32..])).unwrap();
        let verified = r.finish().unwrap();
        assert_eq!(verified.checkpoint().sequence, 33);
        assert_eq!(verified.replica().current.len(), 33);
        assert_eq!(verified.previous_owner(), &c.before);
        assert!(!serde_json::to_string(verified.replica())
            .unwrap()
            .contains("fixture.invalid"));
    }
    #[test]
    fn a_semantically_invalid_later_row_cannot_admit_an_earlier_valid_prefix() {
        let mut c = case(1);
        let bad = row(&c, 2, &c.rows[0].history_hash, false);
        c.response.results[0].sequence = "2".into();
        c.response.results[0].history_hash = bad.history_hash.clone();
        c.rows.push(bad);
        let mut r = read(&c).unwrap();
        assert!(r.append(page(&c, &c.rows)).is_err());
        assert_eq!(r.position(), 0);
        assert!(r.operations.is_empty());
        assert_eq!(r.bytes, 0);
        assert!(r.finish().is_err());
    }
    #[test]
    fn a_signed_cancelled_wrap_cannot_replace_the_committed_key_even_for_empty_history() {
        for count in [0, 1] {
            let mut c = case(count);
            let plan = rotate(&mut c);
            let chain = c.proof.verify(c.kit.anchor(), None).unwrap();
            let cancelled = wrapped(&chain, &c.signer, &c.keys.next_epoch().unwrap(), 2);
            let correct = c.response.results[0].wrap.clone();
            c.response.results[0].wrap = cancelled;
            assert!(read(&c).is_err());
            c.response.results[0].wrap = correct;
            let mut r = read(&c).unwrap();
            r.append(page(&c, &plan.rows)).unwrap();
            assert_eq!(r.finish().unwrap().checkpoint().epoch, 2);
            c.response.results[0]
                .committed
                .as_mut()
                .unwrap()
                .wraps
                .pop();
            assert!(read(&c).is_err());
        }
    }
    #[test]
    fn the_manifest_target_prefix_is_verified_before_recovery_capability_is_minted() {
        let mut c = case(1);
        let plan = rotate(&mut c);
        let body = &mut c.response.results[0]
            .committed
            .as_mut()
            .unwrap()
            .manifest
            .body;
        body.target_history_hash = "9".repeat(64);
        let changed = super::super::rekey::SignedRekey::sign(body.clone(), &c.signer).unwrap();
        c.response.results[0].committed.as_mut().unwrap().manifest = changed.clone();
        c.response.results[0].commits = vec![changed];
        let mut r = read(&c).unwrap();
        assert!(r.append(page(&c, &plan.rows)).is_err());
        assert_eq!(r.position(), 0);
        assert!(r.finish().is_err());
    }
    #[test]
    fn a_new_kit_bridge_must_open_all_history_and_old_kit_cannot_authorize_a_new_read() {
        let mut c = case(1);
        let plan = rotate(&mut c);
        let chain = c.proof.verify(c.kit.anchor(), None).unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let new_keys = seed
            .keys(&c.kit.anchor().origin, &c.kit.anchor().account_id)
            .unwrap();
        let node = SignedMembership::sign(
            chain.current().proposal(
                &"1".repeat(32),
                Action::Recovery,
                None,
                chain.current().devices().clone(),
                new_keys.public(),
                1001,
            ),
            &c.signer,
        )
        .unwrap();
        c.proof.nodes.push(node);
        let next = c.proof.verify(c.kit.anchor(), None).unwrap();
        assert!(c.kit.current_keys(&next).is_err());
        let new_kit = seed.bind(&next).unwrap();
        c.response.membership_head = next.current().head().into();
        c.response.auth_epoch = 4;
        c.response.results[0].wrap = wrapped(&next, &c.signer, &plan.keys, 2);
        c.before = owner(&new_kit, 4);
        assert!(read(&c).is_err());
        c.kit = new_kit;
        let correct = c.response.results[0].wrap.clone();
        c.response.results[0].wrap = wrapped(&next, &c.signer, &plan.keys.next_epoch().unwrap(), 2);
        let mut bad = read(&c).unwrap();
        assert!(bad.append(page(&c, &plan.rows)).is_err());
        assert!(bad.finish().is_err());
        c.response.results[0].wrap = correct;
        let mut r = read(&c).unwrap();
        r.append(page(&c, &plan.rows)).unwrap();
        assert_eq!(
            r.finish().unwrap().chain().current().recovery(),
            next.current().recovery()
        );
    }
    #[test]
    fn fresh_recovery_cannot_reset_an_existing_owner_or_accept_scope_or_epoch_substitution() {
        let mut c = case(1);
        let old = c.before.clone();
        c.before = super::super::workspace::tests::enrolled();
        assert!(read(&c).is_err());
        c.before = old;
        c.response.results[0].vault = "f".repeat(64);
        assert!(read(&c).is_err());
        c.response.results[0].vault = personal_vault_id(c.kit.anchor()).unwrap();
        c.response.auth_epoch = 1;
        assert!(read(&c).is_err());
        c.response.auth_epoch = 2;
        assert!(ReadSession::begin_fresh(
            &c.before,
            &c.kit,
            c.proof.clone(),
            c.response.clone(),
            1000000
        )
        .is_err());
        let left = VaultKeys::from_bytes(&[3; 64]).unwrap();
        let mut altered = [3; 64];
        altered[0] = 4;
        assert!(left
            .verify_same(&VaultKeys::from_bytes(&altered).unwrap())
            .is_err());
        assert!(left.verify_same(&left.next_epoch().unwrap()).is_err());
        left.verify_same(&VaultKeys::from_bytes(&[3; 64]).unwrap())
            .unwrap();
    }
}
