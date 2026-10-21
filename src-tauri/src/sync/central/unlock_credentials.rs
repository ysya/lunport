//! Public anti-rollback highwater kept outside restorable workspace files. No unlock secrets.
use super::{
    credentials::Profile,
    membership::TrustAnchor,
    unlock_registry::{Highwater, VerifiedRegistry},
    wire::{hex, invalid, MAX_SAFE_INTEGER},
};
use crate::{error::AppError, sync::env::Keychain};
use serde::{Deserialize, Serialize};
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    anchor: TrustAnchor,
    highwater: Highwater,
}
fn load(
    keychain: &dyn Keychain,
    profile: &Profile,
    anchor: &TrustAnchor,
) -> Result<Option<Stored>, AppError> {
    if anchor.origin != profile.origin {
        return Err(invalid());
    }
    keychain
        .get(&profile.slot("unlock-highwater"))?
        .map(|encoded| {
            if encoded.len() > 2048 {
                return Err(invalid());
            }
            let stored: Stored = serde_json::from_str(&encoded).map_err(|_| invalid())?;
            if stored.version != 1
                || &stored.anchor != anchor
                || stored.highwater.revision == 0
                || stored.highwater.revision > MAX_SAFE_INTEGER
                || !hex(&stored.highwater.digest, 64)
            {
                return Err(invalid());
            }
            Ok(stored)
        })
        .transpose()
}
pub(super) fn minimum(
    keychain: &dyn Keychain,
    profile: &Profile,
    anchor: &TrustAnchor,
) -> Result<Option<Highwater>, AppError> {
    Ok(load(keychain, profile, anchor)?.map(|s| s.highwater))
}
/// Must run under the existing lifecycle lock, before accepting or replacing unlock data.
pub(super) fn remember(
    keychain: &dyn Keychain,
    profile: &Profile,
    registry: &VerifiedRegistry,
) -> Result<(), AppError> {
    let anchor = &registry.signed().body.anchor;
    let next = registry.highwater();
    if let Some(before) = load(keychain, profile, anchor)? {
        if before.highwater.revision > next.revision
            || before.highwater.revision == next.revision && before.highwater.digest != next.digest
        {
            return Err(invalid());
        }
        if before.highwater == *next {
            return Ok(());
        }
    }
    let stored = Stored {
        version: 1,
        anchor: anchor.clone(),
        highwater: next.clone(),
    };
    let encoded = serde_json::to_string(&stored).map_err(|_| invalid())?;
    keychain.set(&profile.slot("unlock-highwater"), &encoded)?;
    if load(keychain, profile, anchor)?.as_ref() != Some(&stored) {
        return Err(invalid());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::central::{trust::ControlProof, unlock_registry::SignedRegistry};
    use std::{collections::BTreeMap, sync::Mutex};
    #[derive(Default)]
    struct Memory(Mutex<BTreeMap<String, String>>);
    impl Keychain for Memory {
        fn get(&self, key: &str) -> Result<Option<String>, AppError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
            self.0.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<(), AppError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }
    #[test]
    fn workspace_restore_cannot_lower_unlock_highwater_or_replace_its_root() {
        let source: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-unlock-v1.json"))
                .unwrap();
        let registry: SignedRegistry = serde_json::from_value(golden["registry"].clone()).unwrap();
        let anchor = &registry.body.anchor;
        let chain = ControlProof {
            genesis: serde_json::from_value(source["genesis"].clone()).unwrap(),
            nodes: vec![],
        }
        .verify(anchor, None)
        .unwrap();
        let verified = registry.verify(&chain, None).unwrap();
        let memory = Memory::default();
        let profile = Profile::new(
            &anchor.origin,
            "https://identity.example",
            "synthetic-account",
        )
        .unwrap();
        assert!(minimum(&memory, &profile, anchor).unwrap().is_none());
        remember(&memory, &profile, &verified).unwrap();
        remember(&memory, &profile, &verified).unwrap();
        assert_eq!(
            minimum(&memory, &profile, anchor).unwrap().as_ref(),
            Some(verified.highwater())
        );
        let mut changed = anchor.clone();
        changed.genesis_hash = "a".repeat(64);
        assert!(minimum(&memory, &profile, &changed).is_err());
        let higher = Stored {
            version: 1,
            anchor: anchor.clone(),
            highwater: Highwater {
                revision: 2,
                digest: "b".repeat(64),
            },
        };
        memory
            .set(
                &profile.slot("unlock-highwater"),
                &serde_json::to_string(&higher).unwrap(),
            )
            .unwrap();
        assert!(remember(&memory, &profile, &verified).is_err());
        memory
            .set(&profile.slot("unlock-highwater"), "corrupt")
            .unwrap();
        assert!(minimum(&memory, &profile, anchor).is_err());
        assert!(remember(&memory, &profile, &verified).is_err());
    }
}
