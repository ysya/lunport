//! Bounded native rotation executor. Journal persistence always precedes public key-wrap upload.
use super::{
    api::{AccountOverview, Api, Control, RekeyAction, Reply, VaultResource},
    client_state::Phase,
    controller,
    crypto::{VaultKeys, WrappedKeys},
    rekey::{self, Checkpoint, SignedRekey, SourceDigest, Version},
    rotation::{self, Journal},
    round::{self, Report},
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::Deserialize;
use std::time::{Duration, Instant};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteJournal {
    manifest: SignedRekey,
    staged: String,
    history_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteStatus {
    phase: String,
    epoch: u64,
    sequence: String,
    history_hash: String,
    journal: Option<RemoteJournal>,
    commits: Vec<SignedRekey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    manifest: SignedRekey,
    wraps: Vec<WrappedKeys>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    records: Vec<Version>,
    sequence: String,
    history_hash: String,
    membership_head: String,
    epoch: u64,
    phase: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofPage {
    manifest: SignedRekey,
    digests: Vec<SourceDigest>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Staged {
    staged: String,
    history_hash: String,
}
enum Step {
    Again,
    Idle,
    Renew,
    RemoveDenied {
        device: String,
        head: String,
        epoch: String,
        fingerprint: String,
    },
}
fn save(env: &SyncEnv, before: &Workspace, next: Workspace) -> Result<(), AppError> {
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut records = records.clone();
        records.local.central = Some(next.clone());
        Ok(records)
    })?;
    Ok(())
}
fn checked(env: &SyncEnv, report: &mut Report, reply: Reply) -> Result<Reply, AppError> {
    report.requests += 1;
    round::require_success(env, &reply)?;
    Ok(reply)
}
fn open_keys(
    workspace: &Workspace,
    identity: &super::credentials::DeviceIdentity,
    epoch: u64,
) -> Result<VaultKeys, AppError> {
    let chain = workspace.control.verified_chain()?;
    let own = workspace
        .own_wraps
        .iter()
        .find(|w| number(&w.header.key_epoch, false).ok() == Some(epoch))
        .ok_or_else(invalid)?;
    let author = chain
        .author_at(&own.header.membership_head, &own.header.author)
        .ok_or_else(invalid)?;
    own.open(&identity.keys, &own.header, &author.signing)
}
fn admit_rows(workspace: &Workspace, keys: &VaultKeys, rows: &[Version]) -> Result<(), AppError> {
    let chain = workspace.control.verified_chain()?;
    for row in rows {
        let h = &row.envelope.header;
        let author = chain
            .author_at(&h.membership_head, &h.author)
            .ok_or_else(invalid)?;
        let plain = row.envelope.verify(&author.signing)?.open(keys)?;
        super::payload::admit(keys, h, &plain)?;
    }
    Ok(())
}
fn staged_position(rows: &[Version], staged: &Staged) -> Result<u64, AppError> {
    let count = number(&staged.staged, true)?;
    if count > rows.len() as u64
        || staged.history_hash
            != if count == 0 {
                rotation::ZERO
            } else {
                rows[count as usize - 1].history_hash.as_str()
            }
    {
        return Err(invalid());
    }
    Ok(count)
}
fn check_page(page: &Page, workspace: &Workspace, epoch: u64) -> Result<(), AppError> {
    if page.epoch != epoch
        || page.records.len() > 32
        || number(&page.sequence, true)? > 16384
        || !["ready", "rekey_pending"].contains(&page.phase.as_str())
        || workspace
            .control
            .highwater
            .as_ref()
            .is_none_or(|h| h.head != page.membership_head)
    {
        return Err(invalid());
    }
    Ok(())
}
/// Returns whether another bounded round is required. No UI prompt or plaintext publication.
pub fn advance(env: &SyncEnv, report: &mut Report) -> Result<bool, AppError> {
    round::check_cooldown(env)?;
    if !controller::resume(env, false)? {
        return Ok(false);
    }
    let started = Instant::now();
    let mut renewed = false;
    loop {
        if report.requests + 8 > 32 || started.elapsed() >= Duration::from_secs(30) {
            return Ok(true);
        }
        let outcome = {
            let _lifecycle = env.runtime.lifecycle.lock().unwrap();
            step(env, report)?
        };
        match outcome {
            Step::Idle=>return Ok(false), Step::Again=>{},
            Step::RemoveDenied {device,head,epoch,fingerprint} => {
                report.requests+=7;
                super::devices::revoke(env,&device,&head,&epoch,&fingerprint)?;
            },
            Step::Renew if !renewed=>{controller::resume(env,true)?; report.requests+=2; renewed=true;},
            Step::Renew=>return Err(AppError::Other("The account changed during encryption key rotation. Local data and the saved plan are retained; refresh the account.".into())),
        }
    }
}
fn step(env: &SyncEnv, report: &mut Report) -> Result<Step, AppError> {
    let before = record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)?;
    if before.control.phase != Phase::Rekey {
        return Ok(Step::Idle);
    }
    let replica = before.replica.as_ref().ok_or_else(invalid)?;
    let session = controller::context(env)?;
    let device = session.device.as_ref().ok_or_else(invalid)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let api = Api::new(&before.control.profile.origin)?;
    // Observe and persist all new denials before a potential wrap can leave this device.
    let reply = api.account(device)?;
    report.requests += 1;
    if matches!(reply.status, 401 | 403) {
        return Ok(Step::Renew);
    }
    round::require_success(env, &reply)?;
    let account: AccountOverview = reply.decode()?;
    account.validate(device)?;
    if account.proof.as_ref() != before.control.proof.as_ref()
        || account.auth_epoch != before.control.auth_epoch
    {
        return Ok(Step::Renew);
    }
    let public = before
        .control
        .remember_denials(account.denied.iter().map(String::as_str))?;
    if public != before.control {
        let mut next = before.clone();
        next.control = public;
        save(env, &before, next)?;
        return Ok(Step::Again);
    }
    if account.phase != "ready" || account.barrier.is_some() {
        checked(
            env,
            report,
            api.control(device, Control::ResumeBarrier, &serde_json::json!({}))?,
        )?;
        return Ok(Step::Idle);
    }
    // Complete existing revocation intent before generating or uploading any new wraps.
    let chain = before.control.verified_chain()?;
    if let Some((id, keys)) = chain
        .current()
        .devices()
        .iter()
        .find(|(id, _)| before.control.denied_devices.contains(*id))
    {
        if id == &before.control.device.id {
            return Err(invalid());
        }
        return Ok(Step::RemoveDenied {
            device: id.clone(),
            head: chain.current().head().into(),
            epoch: before.control.auth_epoch.to_string(),
            fingerprint: super::crypto::hash(keys.signing.as_bytes()),
        });
    }
    before.control.require_key_recipients()?;
    let remote: RemoteStatus = checked(
        env,
        report,
        api.vault(device, &replica.vault, VaultResource::Rekey)?,
    )?
    .decode()?;
    if remote.epoch < replica.checkpoint.epoch
        || remote.epoch > 65
        || remote.commits.len() != remote.epoch as usize - 1
        || !["ready", "rekey_pending"].contains(&remote.phase.as_str())
    {
        return Err(invalid());
    }
    let advertised = Checkpoint {
        epoch: remote.epoch,
        sequence: number(&remote.sequence, true)?,
        history_hash: remote.history_hash.clone(),
    };
    if advertised.sequence > 16384
        || !super::wire::hex(&advertised.history_hash, 64)
        || advertised.sequence == 0 && advertised.history_hash != rotation::ZERO
    {
        return Err(invalid());
    }
    let chain = before.control.verified_chain()?;
    for (index, manifest) in remote.commits.iter().enumerate() {
        manifest.verify_historical(&chain, &replica.vault)?;
        if number(&manifest.body.to_epoch, false)? != index as u64 + 2
            || before.epochs.get(index).is_some_and(|m| m != manifest)
        {
            return Err(invalid());
        }
    }
    if !remote.commits.starts_with(&before.observed_epochs) {
        return Err(invalid());
    }
    if remote.commits != before.observed_epochs {
        let mut next = before.clone();
        next.observed_epochs = remote.commits.clone();
        save(env, &before, next)?;
        return Ok(Step::Again);
    }
    if remote.epoch > replica.checkpoint.epoch {
        let manifest = &remote.commits[replica.checkpoint.epoch as usize - 1];
        let existing = match &before.rotation {
            Some(Journal::Sending { manifest: m, .. })
            | Some(Journal::Receiving { manifest: m, .. }) => Some(m),
            _ => None,
        };
        if existing != Some(manifest) {
            let bundle: Bundle = checked(
                env,
                report,
                api.vault(
                    device,
                    &replica.vault,
                    VaultResource::EpochWraps {
                        epoch: replica.checkpoint.epoch + 1,
                    },
                )?,
            )?
            .decode()?;
            if &bundle.manifest != manifest {
                return Err(invalid());
            }
            rekey::verify_committed_wraps(&chain, manifest, &bundle.wraps)?;
            let mut next = before.clone();
            next.rotation = Some(Journal::Receiving {
                manifest: bundle.manifest,
                wraps: bundle.wraps,
                from: replica.checkpoint.clone(),
                source_suffix: vec![],
                rows: vec![],
            });
            save(env, &before, next)?;
            return Ok(Step::Again);
        }
        return receive(env, report, &api, device, identity, &before, &remote);
    }
    if let Some(Journal::Sending { manifest, .. }) = &before.rotation {
        if manifest.body.membership_head != chain.current().head()
            || number(&manifest.body.authorization_epoch, false)? != before.control.auth_epoch
        {
            if number(&manifest.body.authorization_epoch, false)? >= before.control.auth_epoch {
                return Err(invalid());
            }
            if remote
                .journal
                .as_ref()
                .is_some_and(|j| j.manifest == *manifest)
            {
                checked(
                    env,
                    report,
                    api.rekey(
                        device,
                        &replica.vault,
                        RekeyAction::Abort,
                        &serde_json::json!({"rotation":manifest.body.rotation_id}),
                    )?,
                )?;
            }
            let mut next = before.clone();
            next.rotation = None;
            save(env, &before, next)?;
            return Ok(Step::Again);
        }
    }
    if remote.phase != "rekey_pending" {
        if before.rotation.is_some() {
            return Err(AppError::Other("The service no longer exposes this rotation. Its saved ciphertext plan is retained for reconciliation.".into()));
        }
        replica.verify_write_authority(
            &chain,
            before.control.auth_epoch,
            replica.checkpoint.epoch,
            &before.epochs,
        )?;
        let mut next = before.clone();
        next.control.phase = if next.control.cutover && next.control.library.is_some() {
            Phase::Active
        } else {
            Phase::Enrolled
        };
        save(env, &before, next)?;
        return Ok(Step::Idle);
    }
    match &before.rotation {
        None => {
            if remote.journal.is_some() {
                return Err(AppError::Other("Another device has an unfinished encryption key rotation. Resume it on that device.".into()));
            }
            let mut next = before.clone();
            next.rotation = Some(Journal::Source {
                membership_head: chain.current().head().into(),
                authorization_epoch: before.control.auth_epoch,
                source: advertised,
                rows: vec![],
            });
            save(env, &before, next)?;
            Ok(Step::Again)
        }
        Some(Journal::Source {
            membership_head,
            authorization_epoch,
            source,
            rows,
        }) => {
            if membership_head != chain.current().head()
                || *authorization_epoch != before.control.auth_epoch
                || source != &advertised
            {
                let mut next = before.clone();
                next.rotation = None;
                save(env, &before, next)?;
                return Ok(Step::Again);
            }
            let keys = open_keys(&before, identity, source.epoch)?;
            if rows.len() as u64 == source.sequence {
                let plan = rekey::prepare(
                    &chain,
                    &identity.id,
                    &identity.keys,
                    &replica.vault,
                    before.control.auth_epoch,
                    &keys,
                    source,
                    &replica.checkpoint,
                    rows,
                )?;
                let mut next = before.clone();
                next.rotation = Some(Journal::sending(&before, plan, rows)?);
                save(env, &before, next)?;
                return Ok(Step::Again);
            }
            let page: Page = checked(
                env,
                report,
                api.vault(
                    device,
                    &replica.vault,
                    VaultResource::Records {
                        since: rows.len() as u64,
                    },
                )?,
            )?
            .decode()?;
            check_page(&page, &before, source.epoch)?;
            if number(&page.sequence, true)? != source.sequence
                || page.history_hash != source.history_hash
                || page.phase != "rekey_pending"
                || page.records.is_empty()
            {
                return Err(invalid());
            }
            admit_rows(&before, &keys, &page.records)?;
            let mut next = before.clone();
            let tail: Vec<_> = page
                .records
                .iter()
                .filter(|r| {
                    number(&r.sequence, false).is_ok_and(|seq| seq > replica.checkpoint.sequence)
                })
                .cloned()
                .collect();
            if !tail.is_empty() {
                // Authenticated source rows are already known history. Persist their highwater in
                // the replica so a later control change cannot discard this verified prefix when
                // invalidating an unfinished preparation journal. Phase::Rekey prohibits release.
                next.replica = Some(replica.prepare_page(&chain, &keys, &tail, source)?.next);
            }
            if let Some(Journal::Source { rows, .. }) = &mut next.rotation {
                rows.extend(page.records);
            }
            save(env, &before, next)?;
            Ok(Step::Again)
        }
        Some(Journal::Sending {
            manifest,
            wraps,
            rows,
            ..
        }) => {
            manifest.verify(
                chain.current(),
                before.control.auth_epoch,
                &replica.vault,
                &advertised,
                &identity.id,
            )?;
            if let Some(journal) = &remote.journal {
                staged_position(
                    rows,
                    &Staged {
                        staged: journal.staged.clone(),
                        history_hash: journal.history_hash.clone(),
                    },
                )?;
                if journal.manifest != *manifest {
                    return Err(AppError::Other("Another encryption key rotation is in progress. This device's plan is retained.".into()));
                }
            }
            let staged: Staged = checked(
                env,
                report,
                api.rekey(
                    device,
                    &replica.vault,
                    RekeyAction::Begin,
                    &serde_json::json!({"manifest":manifest,"wraps":wraps}),
                )?,
            )?
            .decode()?;
            let count = staged_position(rows, &staged)?;
            if count < rows.len() as u64 {
                // The immutable local plan is already persisted. Exact retries after an uncertain
                // response send the same nonce, ciphertext, signature and operation identifiers.
                let end = (count as usize + 32).min(rows.len());
                let ack:Staged=checked(env,report,api.rekey(device,&replica.vault,RekeyAction::Stage,&serde_json::json!({"rotation":manifest.body.rotation_id,"after":count.to_string(),"rows":&rows[count as usize..end]}))?)?.decode()?;
                if staged_position(rows, &ack)? < end as u64 {
                    return Err(invalid());
                }
            } else {
                checked(
                    env,
                    report,
                    api.rekey(
                        device,
                        &replica.vault,
                        RekeyAction::Commit,
                        &serde_json::json!({"rotation":manifest.body.rotation_id}),
                    )?,
                )?;
            }
            Ok(Step::Again)
        }
        Some(Journal::Receiving { .. }) => Err(invalid()),
    }
}
fn receive(
    env: &SyncEnv,
    report: &mut Report,
    api: &Api,
    device: &super::api::DeviceSession,
    identity: &super::credentials::DeviceIdentity,
    before: &Workspace,
    remote: &RemoteStatus,
) -> Result<Step, AppError> {
    let replica = before.replica.as_ref().ok_or_else(invalid)?;
    let (manifest, wraps, from, suffix, rows, verified) =
        match before.rotation.as_ref().ok_or_else(invalid)? {
            Journal::Sending {
                manifest,
                wraps,
                from,
                source_suffix,
                rows,
                verified,
            } => (manifest, wraps, from, source_suffix, rows, Some(*verified)),
            Journal::Receiving {
                manifest,
                wraps,
                from,
                source_suffix,
                rows,
            } => (manifest, wraps, from, source_suffix, rows, None),
            _ => return Err(invalid()),
        };
    let epoch = number(&manifest.body.to_epoch, false)?;
    let total = number(&manifest.body.source_sequence, true)?;
    let source_done = rotation::verify_source(before, manifest, from, suffix)?;
    if !source_done {
        let page: ProofPage = checked(
            env,
            report,
            api.vault(
                device,
                &replica.vault,
                VaultResource::SourceProof {
                    epoch,
                    after: from.sequence + suffix.len() as u64,
                },
            )?,
        )?
        .decode()?;
        if page.manifest != *manifest || page.digests.is_empty() || page.digests.len() > 256 {
            return Err(invalid());
        }
        let mut next = before.clone();
        if let Some(Journal::Receiving { source_suffix, .. }) = &mut next.rotation {
            source_suffix.extend(page.digests);
        } else {
            return Err(invalid());
        }
        save(env, before, next)?;
        return Ok(Step::Again);
    }
    if epoch < remote.epoch {
        let next = rotation::bridge(before, manifest, wraps, suffix)?;
        save(env, before, next)?;
        return Ok(Step::Again);
    }
    let count = verified.unwrap_or(rows.len() as u64);
    if count < total {
        let page: Page = checked(
            env,
            report,
            api.vault(
                device,
                &replica.vault,
                VaultResource::Records { since: count },
            )?,
        )?
        .decode()?;
        check_page(&page, before, epoch)?;
        if number(&page.sequence, true)? < total || page.records.is_empty() {
            return Err(invalid());
        }
        let prefix: Vec<_> = page
            .records
            .into_iter()
            .take_while(|r| number(&r.sequence, false).is_ok_and(|s| s <= total))
            .collect();
        if prefix.is_empty() {
            return Err(invalid());
        }
        let chain = before.control.verified_chain()?;
        let keys =
            rekey::open_committed_keys(&chain, manifest, wraps, &identity.id, &identity.keys)?;
        admit_rows(before, &keys, &prefix)?;
        let mut next = before.clone();
        match &mut next.rotation {
            Some(Journal::Sending { rows, verified, .. }) => {
                let end = count as usize + prefix.len();
                if rows.get(count as usize..end) != Some(prefix.as_slice()) {
                    return Err(invalid());
                }
                *verified = end as u64;
            }
            Some(Journal::Receiving { rows, .. }) => rows.extend(prefix),
            _ => return Err(invalid()),
        }
        save(env, before, next)?;
        return Ok(Step::Again);
    }
    let chain = before.control.verified_chain()?;
    let keys = rekey::open_committed_keys(&chain, manifest, wraps, &identity.id, &identity.keys)?;
    let next = rotation::activate(before, manifest, wraps, suffix, rows, &keys)?;
    save(env, before, next)?;
    checked(
        env,
        report,
        api.rekey(
            device,
            &replica.vault,
            RekeyAction::Reconcile,
            &serde_json::json!({}),
        )?,
    )?;
    Ok(Step::Again)
}
