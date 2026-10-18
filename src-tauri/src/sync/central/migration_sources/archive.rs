//! Explicit plaintext only for the protected local source capsule, never for transport or a DTO.
use super::*;
use crate::sync::{record::Envelope, relay::PullResponse};
const MAX_BYTES: usize = 65536;
/// One immutable frozen parent can discover additional children. Never recursively nest books.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Discovery {
    #[serde(deserialize_with = "secret", serialize_with = "serialize_secret")]
    base: Zeroizing<String>,
    local_context: String,
    progress: Progress,
    latest_seq: u64,
    records: Vec<Envelope>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    chain_id: String,
    #[serde(deserialize_with = "secret")]
    auth_token: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    encryption_key: Zeroizing<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    version: u32,
    relay: Option<String>,
    parent: String,
    keys: Vec<Key>,
    #[serde(default, deserialize_with = "discovery")]
    discovery: Option<Discovery>,
}
fn serialize_secret<S: serde::Serializer>(
    value: &Zeroizing<String>,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(value)
}
fn discovery<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Discovery>, D::Error> {
    Discovery::deserialize(d).map(Some)
}
impl Sources {
    pub fn encode_local(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        if self.keys.len() > MAX_SOURCES
            || self.legacy_origin.as_ref().is_some_and(|v| v.len() > 2048)
        {
            return Err(invalid());
        }
        #[derive(Serialize)]
        struct RefKey<'a> {
            chain_id: &'a str,
            auth_token: &'a str,
            encryption_key: &'a str,
        }
        #[derive(Serialize)]
        struct RefBody<'a> {
            version: u32,
            relay: Option<&'a str>,
            parent: &'a str,
            keys: Vec<RefKey<'a>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            discovery: Option<&'a Discovery>,
        }
        let body = RefBody {
            version: if self.discovery.is_some() { 2 } else { 1 },
            relay: self.legacy_origin.as_deref(),
            parent: &self.parent,
            keys: self
                .keys
                .iter()
                .map(|(id, key)| RefKey {
                    chain_id: id,
                    auth_token: &key.token,
                    encryption_key: &key.encryption,
                })
                .collect(),
            discovery: self.discovery.as_deref(),
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES));
        serde_json::to_writer(&mut *bytes, &body).map_err(|_| invalid())?;
        if bytes.len()
            > if self.discovery.is_some() {
                MAX_BOOK_BYTES
            } else {
                MAX_BYTES
            }
        {
            return Err(invalid());
        }
        Ok(bytes)
    }
    /// Restore by rederiving every credential, including remote discoveries, from original evidence.
    pub fn decode_local(bytes: &[u8], state: &SyncStateV3) -> Result<Self, AppError> {
        Self::decode_book(bytes, state, true)
    }
    fn decode_book(
        bytes: &[u8],
        state: &SyncStateV3,
        allow_discovery: bool,
    ) -> Result<Self, AppError> {
        if bytes.len()
            > if allow_discovery {
                MAX_BOOK_BYTES
            } else {
                MAX_BYTES
            }
        {
            return Err(invalid());
        }
        let body: Body = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if body.keys.len() > MAX_SOURCES
            || !matches!(
                (body.version, body.discovery.is_some()),
                (1, false) | (2, true)
            )
            || body.version == 1 && bytes.len() > MAX_BYTES
            || body.version == 2 && !allow_discovery
        {
            return Err(invalid());
        }
        let mut keys = BTreeMap::new();
        for key in body.keys {
            if !hex(&key.chain_id, 64) || !hex(&key.auth_token, 64) {
                return Err(invalid());
            }
            let _decoded =
                Zeroizing::new(super::super::crypto::decode(&key.encryption_key, 32, 32)?);
            if keys
                .insert(
                    key.chain_id,
                    SourceKey {
                        token: key.auth_token,
                        encryption: key.encryption_key,
                    },
                )
                .is_some()
            {
                return Err(invalid());
            }
        }
        let expected = if let Some(discovery) = body.discovery {
            let base = Self::decode_book(discovery.base.as_bytes(), state, false)?;
            let owner = state.local.central.as_ref().ok_or_else(invalid)?;
            if discovery.local_context != super::frozen::Target::current(owner)?.binding()? {
                return Err(invalid());
            }
            let operation = &discovery
                .progress
                .proof
                .last()
                .ok_or_else(invalid)?
                .intent
                .body
                .migration_id;
            let snapshot = base.admit_frozen(
                owner,
                operation,
                &discovery.progress,
                None,
                &base.parent,
                PullResponse {
                    records: discovery.records,
                    latest_seq: discovery.latest_seq,
                },
            )?;
            base.with_parent_discovery(owner, &snapshot)?
        } else if body.parent.is_empty() {
            if !keys.is_empty() || body.relay.is_some() {
                return Err(invalid());
            }
            Self::discover(state, None)?
        } else {
            let parent = keys.get(&body.parent).ok_or_else(invalid)?;
            let temporary = Temporary(
                ChainKeys::from_parts(&body.parent, &parent.token, &parent.encryption)
                    .map_err(|_| invalid())?,
            );
            Self::discover(state, Some(&temporary.0))?
        };
        if expected.parent != body.parent
            || expected.legacy_origin != body.relay
            || expected.keys.len() != keys.len()
            || keys
                .iter()
                .any(|(id, key)| expected.keys.get(id).is_none_or(|known| !known.same(key)))
        {
            return Err(invalid());
        }
        Ok(expected)
    }
    /// Consume a verified parent, retaining both its proof and the exact original keybook.
    pub fn with_parent_discovery(
        mut self,
        owner: &Workspace,
        snapshot: &super::frozen::FrozenSnapshot,
    ) -> Result<Self, AppError> {
        let context = snapshot.context();
        if self.discovery.is_some()
            || self.parent.is_empty()
            || snapshot.checkpoint().chain_id != self.parent
            || context.keybook != super::super::crypto::hash(&self.encode_local()?)
            || context.target != super::frozen::Target::current(owner)?
        {
            return Err(invalid());
        }
        let base = Zeroizing::new(
            std::str::from_utf8(&self.encode_local()?)
                .map_err(|_| invalid())?
                .to_owned(),
        );
        let parent = self.keys.get(&self.parent).ok_or_else(invalid)?;
        let temporary = Temporary(
            ChainKeys::from_parts(&self.parent, &parent.token, &parent.encryption)
                .map_err(|_| invalid())?,
        );
        for envelope in snapshot.records() {
            let row = SealedRecord {
                envelope: envelope.clone(),
                dirty: false,
                public_identity: None,
            };
            let opened = self.open(&self.parent, &row)?;
            let view = opened.view()?;
            if view.kind == "space" {
                if !hex(view.id, 64) || view.id == self.parent {
                    return Err(invalid());
                }
                self.expected.insert(view.id.into());
            }
            self.sealed(&row, &temporary.0)?;
        }
        if self.expected.iter().any(|id| !self.keys.contains_key(id)) {
            return Err(invalid());
        }
        self.discovery = Some(Box::new(Discovery {
            base,
            local_context: context.target.binding()?,
            progress: snapshot.progress().clone(),
            latest_seq: super::super::wire::number(&snapshot.checkpoint().sequence, true)?,
            records: snapshot.records().to_vec(),
        }));
        drop(self.encode_local()?);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        record::{Record, RecordKind, SpaceKeyPayload},
        state_v2::AccountState,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde_json::json;
    pub(super) fn fixture() -> (SyncStateV3, ChainKeys, ChainKeys, SealedRecord) {
        let parent = ChainKeys::generate().unwrap();
        let child = ChainKeys::generate().unwrap();
        let mut state:SyncStateV3=serde_json::from_value(json!({"version":3,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap();
        let mut account = AccountState::new(&parent.chain_id);
        let space = SealedRecord::seal(
            &parent,
            &Record {
                kind: RecordKind::SpaceKey,
                id: child.chain_id.clone(),
                version: 1,
                updated_at_ms: 1,
                device_id: state.device_id.clone(),
                deleted: false,
                payload: serde_json::to_value(SpaceKeyPayload::from_keys(&child)).unwrap(),
            },
            0,
        )
        .unwrap();
        account.sealed.insert(space.key(), space);
        let secret = SealedRecord::seal(
            &parent,
            &Record {
                kind: RecordKind::Key,
                id: "1".repeat(32),
                version: 1,
                updated_at_ms: 1,
                device_id: state.device_id.clone(),
                deleted: false,
                payload: json!({"schema":1,"private_key":"PRIVATE_SOURCE_SENTINEL"}),
            },
            0,
        )
        .unwrap();
        account.sealed.insert(secret.key(), secret.clone());
        state.account = Some(account);
        (state, parent, child, secret)
    }
    #[test]
    fn protected_local_book_restores_secret_rows_after_the_original_keys_are_dropped() {
        let (state, parent, child, secret) = fixture();
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let bytes = sources.encode_local().unwrap();
        let parent_id = parent.chain_id.clone();
        let child_id = child.chain_id.clone();
        drop(parent);
        drop(child);
        drop(sources);
        let restored = Sources::decode_local(&bytes, &state).unwrap();
        assert_eq!(restored.chains().len(), 2);
        assert!(restored.keys.contains_key(&child_id));
        let key = &restored.keys[&parent_id];
        let temporary =
            Temporary(ChainKeys::from_parts(&parent_id, &key.token, &key.encryption).unwrap());
        assert_eq!(
            secret.open(&temporary.0).unwrap().payload["private_key"],
            "PRIVATE_SOURCE_SENTINEL"
        );
        assert_eq!(
            restored.encode_local().unwrap().as_slice(),
            bytes.as_slice()
        );
        let mut changed = state.clone();
        changed.relay_url = "https://different.example".into();
        assert!(Sources::decode_local(&bytes, &changed).is_err());
    }
    #[test]
    fn incomplete_extra_duplicate_altered_child_and_unknown_books_never_weaken_discovery() {
        let (state, parent, child, _) = fixture();
        let bytes = Sources::discover(&state, Some(&parent))
            .unwrap()
            .encode_local()
            .unwrap();
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for case in [
            "missing",
            "extra",
            "duplicate",
            "alter-child",
            "schema",
            "unknown",
            "bad-key",
            "bad-parent",
        ] {
            let mut value = original.clone();
            let keys = value["keys"].as_array_mut().unwrap();
            match case {
                "missing"=>{keys.retain(|key|key["chain_id"]!=child.chain_id);},
                "extra"=>keys.push(json!({"chain_id":"f".repeat(64),"auth_token":"8".repeat(64),"encryption_key":B64.encode([9u8;32])})),
                "duplicate"=>keys.push(keys[0].clone()),
                "alter-child"=>{keys.iter_mut().find(|key|key["chain_id"]==child.chain_id).unwrap()["auth_token"]="8".repeat(64).into();},
                "schema"=>value["version"]=2.into(),"unknown"=>value["other"]="PRIVATE_SENTINEL".into(),
                "bad-key"=>keys[0]["encryption_key"]="PRIVATE_SENTINEL".into(),
                _=>value["parent"]="f".repeat(64).into(),
            }
            assert!(
                Sources::decode_local(&serde_json::to_vec(&value).unwrap(), &state).is_err(),
                "{case}"
            );
        }
        assert!(Sources::decode_local(&vec![b' '; MAX_BYTES + 1], &state).is_err());
        let mut changed = state.clone();
        changed
            .account
            .as_mut()
            .unwrap()
            .sealed
            .values_mut()
            .next()
            .unwrap()
            .envelope
            .ciphertext = "AAAA".into();
        // Discovery always authenticates the retained space-key envelope, regardless of unrelated secret ordering.
        let account = changed.account.as_mut().unwrap();
        let row = account
            .sealed
            .values_mut()
            .find(|row| row.envelope.kind == "spacekey")
            .unwrap();
        row.envelope.ciphertext = "AAAA".into();
        assert!(Sources::decode_local(&bytes, &changed).is_err());
    }
    #[test]
    fn an_explicit_empty_local_book_cannot_hide_a_legacy_account() {
        let (mut state, _, _, _) = fixture();
        let joined = state.clone();
        state.account = None;
        let bytes = Sources::discover(&state, None)
            .unwrap()
            .encode_local()
            .unwrap();
        let empty = Sources::decode_local(&bytes, &state).unwrap();
        assert!(empty.chains().is_empty());
        assert!(Sources::decode_local(&bytes, &joined).is_err());
    }
}

#[cfg(test)]
mod discovery_tests;
