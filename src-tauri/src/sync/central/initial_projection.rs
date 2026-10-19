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
    sync::records_v3::{self, SyncStateV3},
};
use std::collections::BTreeMap;
pub(in crate::sync) struct Candidate {
    source: SyncStateV3,
    shadow: SyncStateV3,
    delta: Delta,
    manifest: String,
    observed: u64,
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
        let cache = Cache::initial(&projected, observed, &selections)
            .map_err(|_| AppError::Other("Initial projection cache is invalid.".into()))?;
        let mut shadow = source.clone();
        shadow.version = records_v3::CENTRAL_STATE_VERSION;
        shadow.account = Some(cache.account);
        shadow.spaces = cache.spaces;
        shadow.local.hosts = cache.hosts;
        shadow.local.groups = cache.groups;
        shadow.local.group_order = cache.group_order;
        // All source pointers and files remain in source. A native stage supplies new verified mappings.
        shadow.local.keys.clear();
        shadow.local.credential_approvals.clear();
        shadow.local.central = Some(owner);
        shadow.local.central_projection = None;
        shadow.pending_account = None;
        shadow.rotation = None;
        shadow.migration_gate = None;
        shadow.legacy_v1_backup = None;
        shadow.shared_writes_blocked = false;
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
            manifest: plan.manifest.digest()?,
            observed,
        })
    }
    pub fn finish(
        self,
        vault: &crate::vault::store::ReadOnlyVault,
        mapping: &BTreeMap<String, String>,
        operation: &str,
    ) -> Result<Prepared, AppError> {
        let verified = self.delta.finish(vault, mapping, operation)?;
        if verified.before() != &self.shadow {
            return Err(invalid());
        }
        let candidate = crate::sync::record_groups::invalidate_changed_pins(
            &self.source,
            verified.candidate().clone(),
        )
        .map_err(|_| invalid())?;
        records_v3::validate_state(&candidate).map_err(|_| invalid())?;
        Ok(Prepared {
            source: self.source,
            candidate,
            manifest: self.manifest,
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
            payload::{Catalog, Collection, Data},
        },
        fake_relay::FakeRelay,
        record_runtime::{self, StartupProbe},
        testkit::{TestClock, TestDevice},
    };
    pub(in crate::sync::central) fn fixture(
    ) -> (SyncStateV3, migration_history::Plan, VaultKeys, Committed) {
        fixture_kind(false)
    }
    fn fixture_kind(empty: bool) -> (SyncStateV3, migration_history::Plan, VaultKeys, Committed) {
        let (owner, keys, signer) = initial();
        let mut history = library();
        if empty {
            history.truncate(1);
        }
        history[0].1 = Data::Catalog(Catalog {
            collections: vec![Collection {
                id: "e".repeat(64),
                name: "unselected".into(),
            }],
            group_orders: vec![],
        });
        let plan = migration_history::prepare(&owner, &keys, &signer, context(), &history).unwrap();
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
    let (state,plan,keys,committed)=tests::fixture();
    Candidate::prepare(&state,&plan,committed,&keys,100).unwrap()
}
