//! Historical copies contribute only retained versions and stronger observed source minima.
use super::*;
impl Inventory {
    /// Ancestors normalize against their own captured files and retain their complete logical
    /// history separately. Transport must also meet every stronger ancestor checkpoint.
    pub(in crate::sync::central) fn with_retained_requirements(
        mut self,
        sources: &Sources,
        historical_sources: &Sources,
        historical: Self,
    ) -> Result<Self, AppError> {
        sources.require_retained_subset(historical_sources)?;
        if self.keybook != super::super::super::crypto::hash(&sources.encode_local()?) {
            return Err(invalid());
        }
        for (chain, minimum) in historical.minima {
            if !sources.keys.contains_key(&chain)
                || self.frozen_context.is_some()
                    && self.frozen.get(&chain).is_none_or(|known| {
                        super::super::super::wire::number(&known.sequence, true)
                            .map_or(true, |n| n < minimum)
                    })
            {
                return Err(invalid());
            }
            self.minima
                .entry(chain)
                .and_modify(|n| *n = (*n).max(minimum))
                .or_insert(minimum);
        }
        Ok(self)
    }

    pub fn with_retained_state(
        mut self,
        sources: &Sources,
        state: &SyncStateV3,
    ) -> Result<Self, AppError> {
        if self.keybook != super::super::super::crypto::hash(&sources.encode_local()?) {
            return Err(invalid());
        }
        let subset = sources.historical_subset(state)?;
        let historical = Self::from_state(&subset, state)?;
        if historical.target.as_ref().is_some_and(|target| {
            self.target
                .as_ref()
                .is_none_or(|selected| !target.same_account(selected))
        }) {
            return Err(invalid());
        }
        for (chain, minimum) in historical.minima {
            if !sources.keys.contains_key(&chain)
                || self.frozen_context.is_some()
                    && self.frozen.get(&chain).is_none_or(|known| {
                        super::super::super::wire::number(&known.sequence, true)
                            .map_or(true, |sequence| sequence < minimum)
                    })
            {
                return Err(invalid());
            }
            self.minima
                .entry(chain)
                .and_modify(|known| *known = (*known).max(minimum))
                .or_insert(minimum);
        }
        for row in historical.rows {
            let mut location = row.location;
            location.position = Position::Retained;
            location.index = self.rows.len();
            self.append(location, row.sequence, row.dirty, row.opened)?;
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::record::{Record, SpaceKeyPayload};
    #[test]
    fn every_historical_scope_tombstone_and_conflict_side_is_retained_without_becoming_current() {
        let (state, parent, _) = super::super::super::records::tests::fixture();
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let original = Inventory::from_state(&sources, &state).unwrap();
        let count = original.rows().len();
        let combined = original.with_retained_state(&sources, &state).unwrap();
        assert_eq!(combined.rows().len(), 2 * count);
        assert!(combined.rows()[count..]
            .iter()
            .all(|row| row.location.position == Position::Retained));
        assert!(combined.rows()[count..]
            .iter()
            .any(|row| matches!(&row.location.scope, Scope::Space(_))));
        for index in 0..count {
            let before = combined.rows()[index].view().unwrap();
            let after = combined.rows()[count + index].view().unwrap();
            assert!(
                before.kind == after.kind
                    && before.id == after.id
                    && before.version == after.version
                    && before.payload.get() == after.payload.get()
            );
        }
        // This fixture intentionally contains authenticated future private schemas. Retaining
        // them is not permission to omit them from later strict semantic admission.
        assert!(combined.admit_known().is_err());
    }
    #[test]
    fn historical_ciphertext_and_child_credentials_are_reauthenticated_before_admission() {
        for case in ["ciphertext", "child-credential"] {
            let (state, parent, child) = super::super::super::records::tests::fixture();
            let sources = Sources::discover(&state, Some(&parent)).unwrap();
            let mut historical = state.clone();
            if case == "ciphertext" {
                historical
                    .spaces
                    .get_mut(&child.chain_id)
                    .unwrap()
                    .sealed
                    .values_mut()
                    .next()
                    .unwrap()
                    .envelope
                    .ciphertext = "A".repeat(32);
            } else {
                let mut public = SpaceKeyPayload::from_keys(&child);
                public.auth_token = "f".repeat(64);
                let row = SealedRecord::seal(
                    &parent,
                    &Record {
                        kind: RecordKind::SpaceKey,
                        id: child.chain_id.clone(),
                        version: 1,
                        updated_at_ms: 1,
                        device_id: state.device_id.clone(),
                        deleted: false,
                        payload: serde_json::to_value(public).unwrap(),
                    },
                    0,
                )
                .unwrap();
                historical
                    .account
                    .as_mut()
                    .unwrap()
                    .sealed
                    .insert(row.key(), row);
            }
            assert!(
                Inventory::from_state(&sources, &state)
                    .unwrap()
                    .with_retained_state(&sources, &historical)
                    .is_err(),
                "{case}"
            );
        }
    }
}
