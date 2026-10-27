//! Inert initial cache/ledger/delta candidate. Never a Core/runtime or publication permit.
use super::{
    crypto::VaultKeys,
    migration_history,
    migration_verify::Committed,
    projection,
    projection_cache::Cache,
    projection_delta::Delta,
    projection_state::Ledger,
    wire::{invalid, MAX_SAFE_INTEGER},
};
use crate::{
    error::AppError,
    sync::{
        records_v3::{self, SyncStateV3},
        transports,
    },
};
use std::collections::BTreeMap;
pub(in crate::sync) struct Candidate {
    source: SyncStateV3,
    shadow: SyncStateV3,
    delta: Delta,
    manifest: String,
    observed: u64,
    reconciliation: bool,
    /// The ids an adoption or a replacement gives the hosts that routes and grant memory name (old → new,
    /// `adoption::merge::route_host_ids`); `None` for a first publication, which keeps every host's id.
    host_ids: Option<BTreeMap<String, String>>,
}
/// Verified material mappings only. Still no consent or Core publication authority.
pub(in crate::sync) struct Prepared {
    source: SyncStateV3,
    candidate: SyncStateV3,
    manifest: String,
}
impl Prepared {
    pub fn source(&self) -> &SyncStateV3 {
        &self.source
    }
    pub fn candidate(&self) -> &SyncStateV3 {
        &self.candidate
    }
    pub fn manifest(&self) -> &str {
        &self.manifest
    }
}
/// The state version of an initial projection's candidate: central sync's, unless it holds what routes need, then the version of the
/// library's route rows: the account's rows themselves (R19), the routes this device keeps for the publish step to turn into such rows
/// (R64a), or what its grant requests taught it (R8). The initial publication requires exactly this version.
pub(in crate::sync) fn candidate_version(candidate: &SyncStateV3) -> u32 {
    if crate::sync::pam_records::has_data(candidate) {
        crate::sync::pam_records::STATE_VERSION
    } else if transports::needs_sync_version(candidate) || transports::has_data(candidate) {
        transports::SYNC_STATE_VERSION
    } else {
        records_v3::CENTRAL_STATE_VERSION
    }
}

/// What this device keeps by host id, which the shadow leaves out (`Candidate::from_owner`), back in the final candidate (R8, design
/// 2026-10-26, Existing routes move in): its routes, which the publish step moves into the library while it has their hosts (R64a), and
/// what its grant requests taught it.
/// - A first publication (`host_ids` is `None`) keeps every host's id, so it keeps both as they are.
/// - An adoption or a replacement gives the hosts new ids (`host_ids`): every route that applies on the source, a replaced library's
///   included (R22), follows its host as this device's own, with its grant memory; one whose host does not survive goes
///   (`transports::follow_hosts`).
///
/// A route whose host the library's Catalog already holds a route for gives way to it, as a delta projection decides. The candidate
/// gets the state version they need.
fn keep_routes(
    source: &SyncStateV3,
    candidate: &mut SyncStateV3,
    host_ids: Option<&BTreeMap<String, String>>,
    now: u64,
) -> Result<(), AppError> {
    match host_ids {
        None => {
            candidate.local.transports = source.local.transports.clone();
            candidate.local.transport_grants = source.local.transport_grants.clone();
        }
        Some(host_ids) => {
            transports::follow_hosts(source, candidate, host_ids, now).map_err(|_| invalid())?
        }
    }
    // Search scopes and grant memory name no host: they stay as they are, for the publish step to move in (design 2026-10-27). The
    // library's own, from its Catalog, give way to none of them: a memory or scope of the same id the library holds wins.
    crate::sync::pam_records::preserve_on_leave(source, candidate, now).map_err(|_| invalid())?;
    if let Some(account) = &candidate.account {
        candidate.local.pam_records.retain(|key, _| !account.records.contains_key(key));
    }
    // The account's route rows are the Catalog's routes, keyed as this device's own are.
    if let Some(account) = &candidate.account {
        candidate
            .local
            .transports
            .retain(|key, _| !account.records.contains_key(key));
    }
    candidate.version = candidate_version(candidate);
    Ok(())
}
impl Candidate {
    pub fn prepare(
        source: &SyncStateV3,
        plan: &migration_history::Plan,
        committed: Committed,
        keys: &VaultKeys,
        observed: u64,
    ) -> Result<Self, AppError> {
        records_v3::validate_state(source)
            .map_err(|_| AppError::Other("Initial projection source is invalid.".into()))?;
        if observed > MAX_SAFE_INTEGER
            || source.local.central_projection.is_some()
            || source.local.central.as_ref() != Some(plan.before())
            || committed.manifest() != plan.manifest.digest()?
            || committed.workspace().control.cutover
            || committed
                .workspace()
                .replica
                .as_ref()
                .ok_or_else(invalid)?
                .checkpoint
                .sequence
                != plan.rows.len() as u64
            || committed
                .workspace()
                .replica
                .as_ref()
                .ok_or_else(invalid)?
                .checkpoint
                .history_hash
                != plan.manifest.body.target_history_hash
        {
            return Err(invalid());
        }
        let mut owner = committed.workspace().clone();
        owner.control.cutover = true;
        // Proposed approval metadata is inert here. The initial writer must independently
        // require durable human consent for this exact inventory; this value is no permit.
        owner.control = owner.control.approve_library(
            plan.manifest.body.inventory_digest.clone(),
            &owner.control.highwater.as_ref().ok_or_else(invalid)?.head,
        )?;
        Self::from_owner(
            source,
            owner,
            keys,
            plan.manifest.digest()?,
            observed,
            None,
            false,
        )
    }
    fn from_owner(
        source: &SyncStateV3,
        owner: super::workspace::Workspace,
        keys: &VaultKeys,
        manifest: String,
        observed: u64,
        selections_override: Option<&BTreeMap<String, bool>>,
        reconciliation: bool,
    ) -> Result<Self, AppError> {
        records_v3::validate_state(source).map_err(|_| invalid())?;
        if observed > MAX_SAFE_INTEGER
            || !super::wire::hex(&manifest, 64)
            || source.local.central_projection.is_some() && !reconciliation
            || reconciliation
                && !source
                    .local
                    .central
                    .as_ref()
                    .is_some_and(super::replacement_reconciliation::required)
        {
            return Err(invalid());
        }
        let projected = projection::Plan::current(owner.clone(), keys)
            .map_err(|_| AppError::Other("Initial projection history is invalid.".into()))?;
        if !projected.complete() {
            return Err(invalid());
        }
        let selections: BTreeMap<_, _> = source
            .spaces
            .iter()
            .map(|(id, space)| (id.clone(), space.selected))
            .collect();
        let cache = Cache::initial(
            &projected,
            observed,
            selections_override.unwrap_or(&selections),
        )
        .map_err(|_| AppError::Other("Initial projection cache is invalid.".into()))?;
        let mut shadow = source.clone();
        shadow.version = records_v3::CENTRAL_STATE_VERSION;
        shadow.account = Some(cache.account);
        shadow.spaces = cache.spaces;
        shadow.local.hosts = cache.hosts;
        shadow.local.groups = cache.groups;
        shadow.local.group_order = cache.group_order;
        shadow.local.tunnel_rules.clear();
        // This device's routes and what its grant requests taught it stay out of the shadow (R8): with the owner cut over, the delta
        // rebuilt from the shadow would take a route whose host the library has for a change left to capture, and the version above
        // is below theirs. `finish` keeps them in the final candidate, under the host ids an adoption gives (`keep_routes`).
        shadow.local.transports.clear();
        shadow.local.transport_grants.clear();
        shadow.local.pam_records.clear();
        // All source pointers and files remain in source. A native stage supplies new verified mappings.
        shadow.local.keys.clear();
        shadow.local.credential_approvals.clear();
        shadow.local.central = Some(owner);
        shadow.local.central_projection = None;
        shadow.local.central_cache_source = None;
        shadow.pending_account = None;
        shadow.rotation = None;
        shadow.migration_gate = None;
        shadow.legacy_v1_backup = None;
        shadow.shared_writes_blocked = false;
        // The library's routes are rows of the account now (R19).
        shadow.version = candidate_version(&shadow);
        let ledger = Ledger::initial(&projected, &shadow, keys)
            .map_err(|_| AppError::Other("Initial projection ledger is invalid.".into()))?;
        if ledger.storage != cache.key_storage {
            return Err(invalid());
        }
        shadow.local.central_projection = Some(ledger);
        records_v3::validate_state(&shadow)
            .map_err(|_| AppError::Other("Initial projection candidate is invalid.".into()))?;
        let delta = Delta::prepare(&shadow, keys, observed)
            .map_err(|_| AppError::Other("Initial projection material delta is invalid.".into()))?;
        Ok(Self {
            source: source.clone(),
            shadow,
            delta,
            manifest,
            observed,
            reconciliation,
            host_ids: None,
        })
    }
    /// `host_ids`: the ids the merge gives the hosts that routes and grant memory name (`adoption::merge::route_host_ids`).
    pub(super) fn adopt(
        source: &SyncStateV3,
        read: &super::active_read::VerifiedLibrary,
        commitment: &str,
        observed: u64,
        selections: &BTreeMap<String, bool>,
        host_ids: BTreeMap<String, String>,
    ) -> Result<Self, AppError> {
        Self::adopt_inner(
            source, read, commitment, observed, selections, host_ids, false,
        )
    }
    pub(super) fn reconcile(
        source: &SyncStateV3,
        read: &super::active_read::VerifiedLibrary,
        commitment: &str,
        observed: u64,
        selections: &BTreeMap<String, bool>,
        host_ids: BTreeMap<String, String>,
    ) -> Result<Self, AppError> {
        Self::adopt_inner(
            source, read, commitment, observed, selections, host_ids, true,
        )
    }
    fn adopt_inner(
        source: &SyncStateV3,
        read: &super::active_read::VerifiedLibrary,
        commitment: &str,
        observed: u64,
        selections: &BTreeMap<String, bool>,
        host_ids: BTreeMap<String, String>,
        reconciliation: bool,
    ) -> Result<Self, AppError> {
        let before = source.local.central.as_ref().ok_or_else(invalid)?;
        if before != read.previous_owner()
            || before.control.cutover && !reconciliation
            || reconciliation && !super::replacement_reconciliation::required(before)
            || !reconciliation && !before.replacement_archives.is_empty()
            || read.checkpoint().sequence == 0
            || read.phase() != "ready"
        {
            return Err(invalid());
        }
        let mut owner = before.clone();
        owner.control.proof = Some(read.proof().clone());
        owner.control.highwater = Some(read.chain().highwater());
        owner.control.auth_epoch = read.auth_epoch();
        owner.control.cutover = true;
        if owner.control.phase == super::client_state::Phase::Enrolled {
            owner.control = owner
                .control
                .approve_library(commitment.into(), read.chain().current().head())?;
        } else if !reconciliation
            || owner.control.phase != super::client_state::Phase::Active
            || owner.control.library.is_none()
        {
            return Err(invalid());
        }
        // An active account keeps its original cutover approval. This new whole-source consent
        // is independently bound by the protected reconciliation operation and stage manifest.
        owner.replica = Some(read.replica().clone());
        owner.last_epoch_acceptance = read.epoch_acceptance().cloned();
        owner.epochs = read.epochs().to_vec();
        owner.observed_epochs.clear();
        owner
            .own_wraps
            .retain(|w| w.header.key_epoch != read.checkpoint().epoch.to_string());
        owner.own_wraps.push(read.wrap().clone());
        if reconciliation {
            for archive in &mut owner.replacement_archives {
                archive.needs_reconciliation = false;
            }
        }
        owner.validate()?;
        let mut candidate = Self::from_owner(
            source,
            owner,
            read.keys(),
            commitment.into(),
            observed,
            Some(selections),
            reconciliation,
        )?;
        candidate.host_ids = Some(host_ids);
        Ok(candidate)
    }
    pub(in crate::sync) fn reconciliation(&self) -> bool {
        self.reconciliation
    }
    pub fn finish(
        self,
        vault: &crate::vault::store::ReadOnlyVault,
        mapping: &BTreeMap<String, String>,
        operation: &str,
    ) -> Result<Prepared, AppError> {
        let verified = self.delta.finish(vault, mapping, operation)?;
        Self::finish_verified(
            self.source,
            &self.shadow,
            self.manifest,
            verified,
            self.host_ids.as_ref(),
            self.observed,
        )
    }
    /// Rebuild the delta from the exact immutable shadow so the original preparation remains
    /// available for the final filesystem verification.
    pub fn finish_readback(
        &self,
        keys: &VaultKeys,
        vault: &crate::vault::store::ReadOnlyVault,
        mapping: &BTreeMap<String, String>,
        operation: &str,
    ) -> Result<Prepared, AppError> {
        let verified =
            Delta::prepare(&self.shadow, keys, self.observed)?.finish(vault, mapping, operation)?;
        Self::finish_verified(
            self.source.clone(),
            &self.shadow,
            self.manifest.clone(),
            verified,
            self.host_ids.as_ref(),
            self.observed,
        )
    }
    /// The final candidate: the shadow's verified delta, with what this device keeps by host id back in it (`keep_routes`), written
    /// at `observed`.
    fn finish_verified(
        source: SyncStateV3,
        shadow: &SyncStateV3,
        manifest: String,
        verified: super::projection_delta::Verified,
        host_ids: Option<&BTreeMap<String, String>>,
        observed: u64,
    ) -> Result<Prepared, AppError> {
        if verified.before() != shadow {
            return Err(invalid());
        }
        let mut candidate = crate::sync::record_groups::invalidate_changed_pins(
            &source,
            verified.candidate().clone(),
        )
        .map_err(|_| invalid())?;
        keep_routes(&source, &mut candidate, host_ids, observed)?;
        records_v3::validate_state(&candidate).map_err(|_| invalid())?;
        Ok(Prepared {
            source,
            candidate,
            manifest,
        })
    }
    pub fn source(&self) -> &SyncStateV3 {
        &self.source
    }
    pub fn shadow(&self) -> &SyncStateV3 {
        &self.shadow
    }
    pub fn delta(&self) -> &Delta {
        &self.delta
    }
    pub fn observed(&self) -> u64 {
        self.observed
    }
    pub fn manifest(&self) -> &str {
        &self.manifest
    }
}

#[cfg(test)]
pub(in crate::sync) mod tests {
    use super::*;
    use crate::sync::{
        central::{
            migration_history::tests::{context, initial, library},
            migration_progress::Progress,
            migration_verify::{Page, Verifier},
            payload::{Catalog, Collection, Data, Identity},
        },
        fake_relay::FakeRelay,
        record::{record_key, LocalRecord, Record, RecordKind},
        record_runtime::{self, StartupProbe},
        records_v3::HostScope,
        testkit::{TestClock, TestDevice},
        transports::{
            tests::{iap, saved_on_this_device, with_pam, with_zone},
            GrantMemory, HostTransport,
        },
    };
    pub(in crate::sync::central) fn fixture(
    ) -> (SyncStateV3, migration_history::Plan, VaultKeys, Committed) {
        fixture_kind(false)
    }
    fn fixture_kind(empty: bool) -> (SyncStateV3, migration_history::Plan, VaultKeys, Committed) {
        let mut history = library();
        if empty {
            history.truncate(1);
        }
        history[0].1 = Data::Catalog(unselected_catalog());
        fixture_of(&history)
    }
    /// A Catalog of one collection, which the fixtures' source holds unselected.
    fn unselected_catalog() -> Catalog {
        Catalog { pam_scopes: vec![], pam_requests: vec![],
            tunnels: vec![],
            transports: vec![],
            collections: vec![Collection {
                id: "e".repeat(64),
                name: "unselected".into(),
            }],
            group_orders: vec![],
        }
    }
    /// The verified first publication of `history`, and the enrolled source it was built from, which holds `unselected_catalog`'s
    /// collection unselected.
    fn fixture_of(
        history: &[(Identity, Data)],
    ) -> (SyncStateV3, migration_history::Plan, VaultKeys, Committed) {
        let (owner, keys, signer) = initial();
        let plan = migration_history::prepare(&owner, &keys, &signer, context(), history).unwrap();
        let progress: Progress = serde_json::from_value(serde_json::json!({
            "manifest":plan.manifest,"manifest_digest":plan.manifest.digest().unwrap(),
            "phase":"retired","staged":plan.rows.len().to_string(),
            "history_hash":plan.manifest.body.target_history_hash,"retired":"0"
        }))
        .unwrap();
        let floor = progress.verify(&plan, None).unwrap();
        let mut verifier = Verifier::new(&plan, &floor).unwrap();
        for rows in plan.rows.chunks(32) {
            let page: Page = serde_json::from_value(serde_json::json!({
                "records":rows,"sequence":plan.rows.len().to_string(),
                "history_hash":plan.manifest.body.target_history_hash,
                "membership_head":owner.control.highwater.as_ref().unwrap().head,
                "epoch":1,"phase":"ready"
            }))
            .unwrap();
            verifier.admit(&plan, &keys, page).unwrap();
        }
        let committed = verifier.finish(&plan, &keys).unwrap();
        let device = TestDevice::new("initial-projection", &FakeRelay::new(), &TestClock::new());
        let StartupProbe::Records { mut state, .. } =
            record_runtime::probe_startup(&device.env().state_path, "initial")
        else {
            panic!()
        };
        state.version = records_v3::CENTRAL_STATE_VERSION;
        state.local.central = Some(owner);
        state.account = Some(crate::sync::state_v2::AccountState::new(&"a".repeat(64)));
        state.spaces.insert(
            "e".repeat(64),
            crate::sync::records_v3::SpaceStateV3 {
                selected: false,
                ..Default::default()
            },
        );
        (*state, plan, keys, committed)
    }
    pub(in crate::sync::central) fn empty() -> (Candidate, VaultKeys) {
        let (state, plan, keys, committed) = fixture_kind(true);
        (
            Candidate::prepare(&state, &plan, committed, &keys, 100).unwrap(),
            keys,
        )
    }
    #[test]
    fn verified_history_builds_only_an_inert_cache_and_requires_current_managed_material() {
        let (state, plan, keys, committed) = fixture();
        let original = state.clone();
        let result = Candidate::prepare(&state, &plan, committed, &keys, 100).unwrap();
        assert!(state == original && result.source() == &original);
        assert!(!state.local.central.as_ref().unwrap().control.cutover);
        assert!(state.local.central_projection.is_none());
        assert!(
            result
                .shadow()
                .local
                .central
                .as_ref()
                .unwrap()
                .control
                .cutover
        );
        assert!(!result.shadow().spaces[&"e".repeat(64)].selected);
        assert!(result.shadow().local.keys.is_empty());
        assert!(result.shadow().local.credential_approvals.is_empty());
        assert_eq!(
            result.delta().required_material(),
            &std::collections::BTreeSet::from(["1".repeat(32)])
        );
        assert_eq!(result.manifest(), plan.manifest.digest().unwrap());
        assert!(result.delta().before() == result.shadow());
        result
            .shadow()
            .local
            .central_projection
            .as_ref()
            .unwrap()
            .verify_native(result.shadow().local.central.as_ref().unwrap(), &keys)
            .unwrap();
    }
    #[test]
    fn wrong_owner_keys_or_clock_never_produce_an_initial_candidate() {
        for case in ["owner", "keys", "clock"] {
            let (mut state, plan, keys, committed) = fixture();
            if case == "owner" {
                state.local.central.as_mut().unwrap().identity_slot = Some("c".repeat(32));
            }
            let actual_keys = if case == "keys" {
                VaultKeys::generate().unwrap()
            } else {
                keys
            };
            let observed = if case == "clock" {
                MAX_SAFE_INTEGER + 1
            } else {
                100
            };
            assert!(
                Candidate::prepare(&state, &plan, committed, &actual_keys, observed).is_err(),
                "{case}"
            );
            assert!(!state.local.central.as_ref().unwrap().control.cutover);
            assert!(state.local.central_projection.is_none());
        }
    }

    // ---- This device's routes and grant memory (design 2026-10-26, Existing routes move in; R8) ----

    /// The host the routes below name; `fixture_with_host`'s library holds it.
    const HOST: &str = "0000000000000001";
    /// A host the library does not hold.
    const OTHER: &str = "0000000000000002";

    /// The first publication of a library holding `host` in this device's own scope and `routes` in its Catalog, and its source, which
    /// holds the host too: a first publication builds the library from the device's own data, under the same host ids. The history
    /// needs no material.
    fn fixture_with_host(
        host: &str,
        routes: Vec<HostTransport>,
    ) -> (SyncStateV3, migration_history::Plan, VaultKeys, Committed) {
        let payload = serde_json::json!({"schema":2,"alias":"jump","hostname":"jump.invalid","auth":"password"});
        let history = [
            (
                Identity {
                    kind: "meta".into(),
                    id: "catalog".into(),
                    scope: None,
                },
                Data::Catalog(Catalog {
                    transports: routes,
                    ..unselected_catalog()
                }),
            ),
            (
                Identity {
                    kind: "host".into(),
                    id: host.into(),
                    scope: Some(HostScope::Local),
                },
                Data::Host(serde_json::from_value(payload.clone()).unwrap()),
            ),
        ];
        let (mut state, plan, keys, committed) = fixture_of(&history);
        let record = Record {
            kind: RecordKind::Host,
            id: host.into(),
            version: 1,
            updated_at_ms: 1,
            device_id: state.device_id.clone(),
            deleted: false,
            payload,
        };
        state.local.hosts.insert(
            record_key(RecordKind::Host, host),
            LocalRecord {
                record,
                seq: 0,
                dirty: false,
            },
        );
        (state, plan, keys, committed)
    }
    /// The candidate the initial publication saves for `initial`, which reads back a Vault holding no material.
    fn finished(initial: &Candidate, keys: &VaultKeys) -> SyncStateV3 {
        let device = TestDevice::new("initial-readback", &FakeRelay::new(), &TestClock::new());
        let vault = crate::vault::store::read_vault(
            &crate::vault::store::vault_path(&device.env().state_path),
            &device.keychain,
        )
        .unwrap();
        initial
            .finish_readback(keys, &vault, &BTreeMap::new(), &"c".repeat(32))
            .unwrap()
            .candidate()
            .clone()
    }

    /// Design 2026-10-26 (Existing routes move in): the first publication keeps the routes this device saved, as its own, for the
    /// publish step to move into the library (R64a); the shadow, from which the delta is rebuilt, holds none (R8).
    #[test]
    fn first_publication_keeps_the_devices_routes_local_for_the_publish_step() {
        let (source, plan, keys, committed) = fixture_with_host(HOST, vec![]);
        let source = saved_on_this_device(&source, &iap(HOST));
        let initial = Candidate::prepare(&source, &plan, committed, &keys, 100).unwrap();
        assert!(
            transports::view(initial.shadow()).is_empty(),
            "the shadow's delta finds no route left to capture"
        );
        let projected = finished(&initial, &keys);
        assert_eq!(transports::get(&projected, HOST), Some(iap(HOST)));
        assert!(
            !transports::synced(&projected, HOST),
            "it is this device's until the publish step moves it in"
        );
        assert!(projected.version >= transports::STATE_VERSION);
        assert_eq!(
            projected.version,
            candidate_version(&projected),
            "the version the initial publication requires"
        );
        records_v3::validate_state(&projected).unwrap();
        assert_eq!(
            transports::local_routes(&projected).unwrap().fit,
            [iap(HOST)],
            "the publish step takes it: the library has its host"
        );
        let ledger = projected.local.central_projection.as_ref().unwrap();
        assert!(
            !ledger.public_changes(&projected, &keys).unwrap().iter().any(
                |change| matches!(change.data, Data::Catalog(_))
            ),
            "a capture alone leaves it out"
        );
    }

    /// R8: what grant requests taught this device stays through the first publication, which used to refuse such a source.
    #[test]
    fn first_publication_keeps_what_grant_requests_taught_this_device() {
        let (source, plan, keys, committed) = fixture_with_host(HOST, vec![]);
        let source = transports::remember_grant_request(
            &saved_on_this_device(&source, &with_pam(HOST)),
            HOST,
            "restart app-api",
            1800,
            2,
        )
        .unwrap();
        let initial = Candidate::prepare(&source, &plan, committed, &keys, 100).unwrap();
        assert!(initial.shadow().local.transport_grants.is_empty());
        let projected = finished(&initial, &keys);
        assert_eq!(
            transports::grant_memory(&projected, HOST),
            Some(GrantMemory {
                justification: "restart app-api".into(),
                duration_secs: 1800
            })
        );
        assert_eq!(projected.version, transports::SYNC_STATE_VERSION);
        assert_eq!(projected.version, candidate_version(&projected));
        records_v3::validate_state(&projected).unwrap();
    }

    /// R8: a kept route gives way to the route the library's Catalog already holds for its host, as a delta projection decides (an
    /// adopted library may hold one); a route for a host the Catalog holds none for stays.
    #[test]
    fn a_kept_route_gives_way_to_the_librarys_route_for_its_host() {
        let (source, plan, keys, committed) = fixture_with_host(HOST, vec![iap(HOST)]);
        let source = saved_on_this_device(
            &saved_on_this_device(&source, &with_zone(iap(HOST), "asia-east1-a")),
            &iap(OTHER),
        );
        let initial = Candidate::prepare(&source, &plan, committed, &keys, 100).unwrap();
        let projected = finished(&initial, &keys);
        assert_eq!(transports::get(&projected, HOST), Some(iap(HOST)));
        assert!(transports::synced(&projected, HOST));
        assert_eq!(transports::get(&projected, OTHER), Some(iap(OTHER)));
        assert_eq!(
            projected.local.transports.keys().collect::<Vec<_>>(),
            [&record_key(RecordKind::Meta, &transports::wire_id(OTHER))]
        );
        assert_eq!(projected.version, transports::SYNC_STATE_VERSION);
        records_v3::validate_state(&projected).unwrap();
    }
}

#[cfg(test)]
pub(in crate::sync) fn fixture_for_stage() -> (Candidate, VaultKeys) {
    let (mut state, plan, keys, committed) = tests::fixture();
    let projected = projection::Plan::inventory(committed.workspace().clone(), &keys).unwrap();
    let public = projected.materials()[&"1".repeat(32)]
        .metadata
        .public
        .clone();
    state.local.keys.insert(
        "1".repeat(32),
        crate::sync::records_v3::LocalKeyMetadata {
            vault_id: "3".repeat(32),
            public,
        },
    );
    (
        Candidate::prepare(&state, &plan, committed, &keys, 100).unwrap(),
        keys,
    )
}

#[cfg(test)]
pub(in crate::sync) fn empty_fixture_for_stage() -> (Candidate, VaultKeys) {
    tests::empty()
}

#[cfg(test)]
pub(in crate::sync) fn fresh_fixture_for_stage() -> Candidate {
    let (state, plan, keys, committed) = tests::fixture();
    Candidate::prepare(&state, &plan, committed, &keys, 100).unwrap()
}
