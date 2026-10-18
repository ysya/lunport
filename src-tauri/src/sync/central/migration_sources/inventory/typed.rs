//! Known source schemas only. Old metadata never grants central account/device authority.
use super::*;
use crate::sync::{
    central::payload::PrivateMaterial,
    record_merge::MetaPayloadV3,
    records_v3::{
        self, GroupPayload, GroupRecord, HostPayload, HostRecord, HostScope, KeySlotPayload,
    },
};
use serde::de::DeserializeOwned;
#[derive(Deserialize)]
struct Schema {
    schema: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct LegacyHost {
    pub schema: u32,
    #[serde(deserialize_with = "super::super::secret")]
    pub text: Zeroizing<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct LegacySlot {
    pub schema: u32,
    pub name: String,
    pub mode: crate::sync::slot_rules::SlotMode,
    pub origin_device_id: String,
    pub created_at_ms: u64,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
    pub key_type: Option<String>,
    pub has_passphrase: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct LegacyDeviceSlot {
    pub slot_id: String,
    pub fingerprint: Option<String>,
    pub synced_copy: bool,
    #[serde(default)]
    pub in_vault: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct LegacyDevice {
    pub schema: u32,
    pub name: String,
    pub platform: String,
    pub joined_at_ms: u64,
    pub last_seen_ms: u64,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub spaces: Vec<String>,
    #[serde(default)]
    pub slots: Vec<LegacyDeviceSlot>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct Collection {
    pub schema: u32,
    pub name: String,
    pub slug: String,
    pub created_at_ms: u64,
    #[serde(default)]
    pub previous_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct Rotation {
    pub rotated_at_ms: u64,
    pub by_device_id: String,
    pub by_device_name: String,
}
pub(in crate::sync::central) enum KnownData {
    Deleted,
    Host(HostPayload),
    LegacyHost(LegacyHost),
    Group(GroupPayload),
    Keyslot(KeySlotPayload),
    LegacySlot(LegacySlot),
    Key(Option<PrivateMaterial>),
    Collection(Collection),
    Device(LegacyDevice),
    Account(MetaPayloadV3),
    Navigation(crate::sync::group_order::GroupOrder),
    Rotation(Rotation),
    LegacySpaceKey,
}
pub(in crate::sync::central) struct KnownInput {
    pub location: Location,
    pub sequence: u64,
    pub dirty: bool,
    pub kind: String,
    pub id: String,
    pub version: u64,
    pub updated_at_ms: u64,
    pub device_id: String,
    pub deleted: bool,
    pub data: KnownData,
}
pub(in crate::sync::central) struct Known {
    rows: Vec<KnownInput>,
}
impl Known {
    pub fn rows(&self) -> &[KnownInput] {
        &self.rows
    }
    pub fn into_keys(self) -> Vec<KeyInput> {
        self.rows
            .into_iter()
            .filter_map(|row| {
                let KnownData::Key(material) = row.data else {
                    return None;
                };
                Some(KeyInput {
                    location: row.location,
                    id: row.id,
                    sequence: row.sequence,
                    dirty: row.dirty,
                    deleted: row.deleted,
                    version: row.version,
                    updated_at_ms: row.updated_at_ms,
                    device_id: row.device_id,
                    material,
                })
            })
            .collect()
    }
}
fn parse<T: DeserializeOwned>(raw: &str) -> Result<T, AppError> {
    serde_json::from_str(raw).map_err(|_| invalid())
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn host_scope(scope: &Scope) -> Result<HostScope, AppError> {
    match scope {
        Scope::Local => Ok(HostScope::Local),
        Scope::Space(id) => Ok(HostScope::Space {
            space_id: id.clone(),
        }),
        _ => Err(invalid()),
    }
}
fn identity(scope: &Scope, view: &View<'_>) -> Result<(), AppError> {
    let account = matches!(scope, Scope::Account(_));
    let valid = match view.kind {
        "host" => {
            matches!(scope, Scope::Local | Scope::Space(_))
                && (!matches!(scope, Scope::Local) || hex(view.id, 16))
        }
        "group" => matches!(scope, Scope::Local | Scope::Space(_)) && hex(view.id, 16),
        "keyslot" | "key" | "device" => account && hex(view.id, 32),
        "space" | "spacekey" => account && hex(view.id, 64),
        "password" => account,
        "meta" if view.id == crate::sync::group_order::RECORD_ID => true,
        "meta" if view.id == crate::sync::record::ACCOUNT_META_ID => account,
        "meta" => {
            account
                && view
                    .id
                    .strip_prefix(crate::sync::record::ROTATION_META_PREFIX)
                    .is_some_and(|id| hex(id, 32))
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn admit(scope: &Scope, view: &View<'_>) -> Result<KnownData, AppError> {
    identity(scope, view)?;
    let raw = view.payload.get();
    if view.kind == "key" {
        return keys::payload(raw, view.deleted).map(KnownData::Key);
    }
    if view.deleted && raw == "null" {
        return Ok(KnownData::Deleted);
    }
    match view.kind {
        "host" => match parse::<Schema>(raw)?.schema {
            1 => {
                let host: LegacyHost = parse(raw)?;
                if host.schema != 1 || host.text.is_empty() {
                    return Err(invalid());
                }
                Ok(KnownData::LegacyHost(host))
            }
            2 | 3 => {
                let host: HostPayload = parse(raw)?;
                records_v3::validate_host_shape(&HostRecord {
                    id: view.id.into(),
                    scope: host_scope(scope)?,
                    payload: host.clone(),
                })
                .map_err(|_| invalid())?;
                Ok(KnownData::Host(host))
            }
            _ => Err(invalid()),
        },
        "group" => {
            let group: GroupPayload = parse(raw)?;
            records_v3::validate_group(&GroupRecord {
                id: view.id.into(),
                scope: host_scope(scope)?,
                payload: group.clone(),
            })
            .map_err(|_| invalid())?;
            Ok(KnownData::Group(group))
        }
        "keyslot" => match parse::<Schema>(raw)?.schema {
            2 => {
                let slot: KeySlotPayload = parse(raw)?;
                records_v3::validate_keyslot(view.id, &slot).map_err(|_| invalid())?;
                Ok(KnownData::Keyslot(slot))
            }
            1 => {
                let slot: LegacySlot = parse(raw)?;
                let original = crate::sync::slot_rules::KeySlotPayload {
                    schema: slot.schema,
                    name: slot.name.clone(),
                    mode: slot.mode,
                    origin_device_id: slot.origin_device_id.clone(),
                    created_at_ms: slot.created_at_ms,
                    public_key: slot.public_key.clone(),
                    fingerprint: slot.fingerprint.clone(),
                    key_type: slot.key_type.clone(),
                    has_passphrase: slot.has_passphrase,
                };
                if !crate::sync::slot_rules::valid_slot_payload(&original)
                    || slot.created_at_ms > MAX_SAFE_INTEGER
                    || !text(&slot.origin_device_id, 1024)
                {
                    return Err(invalid());
                }
                Ok(KnownData::LegacySlot(slot))
            }
            _ => Err(invalid()),
        },
        "space" => {
            let value: Collection = parse(raw)?;
            if value.schema != 1
                || !text(&value.name, 1024)
                || !text(&value.slug, 1024)
                || value.created_at_ms > MAX_SAFE_INTEGER
                || value.previous_id.as_ref().is_some_and(|id| !hex(id, 64))
            {
                return Err(invalid());
            }
            Ok(KnownData::Collection(value))
        }
        "spacekey" => {
            let secret: super::super::SpaceSecret = parse(raw)?;
            if secret.schema != 1 {
                return Err(invalid());
            }
            drop(Temporary(
                ChainKeys::from_parts(view.id, &secret.auth_token, &secret.enc_key)
                    .map_err(|_| invalid())?,
            ));
            Ok(KnownData::LegacySpaceKey)
        }
        "device" => {
            let value: LegacyDevice = parse(raw)?;
            if value.schema != 1
                || !text(&value.name, 128)
                || !text(&value.platform, 128)
                || value.joined_at_ms > MAX_SAFE_INTEGER
                || value.last_seen_ms > MAX_SAFE_INTEGER
                || value.keys.len() > 4096
                || value.keys.iter().any(|id| !hex(id, 32))
                || value.spaces.len() > 64
                || value.spaces.iter().any(|id| !hex(id, 64))
                || value.slots.len() > 4096
                || value.slots.iter().any(|slot| {
                    !hex(&slot.slot_id, 32)
                        || slot
                            .fingerprint
                            .as_ref()
                            .is_some_and(|fingerprint| !text(fingerprint, 128))
                })
            {
                return Err(invalid());
            }
            if value
                .slots
                .iter()
                .map(|slot| &slot.slot_id)
                .collect::<BTreeSet<_>>()
                .len()
                != value.slots.len()
            {
                return Err(invalid());
            }
            Ok(KnownData::Device(value))
        }
        "meta" if view.id == crate::sync::group_order::RECORD_ID => {
            let value: crate::sync::group_order::GroupOrder = parse(raw)?;
            if value.schema != 1 || !crate::sync::group_order::valid_ids(&value.ids) {
                return Err(invalid());
            }
            Ok(KnownData::Navigation(value))
        }
        "meta" if view.id == crate::sync::record::ACCOUNT_META_ID => {
            let value: MetaPayloadV3 = parse(raw)?;
            if !(1..=records_v3::ACCOUNT_SCHEMA).contains(&value.schema_version)
                || !text(&value.created_by_app_version, 128)
            {
                return Err(invalid());
            }
            if let Some(gate) = &value.migration {
                records_v3::validate_migration_gate(gate).map_err(|_| invalid())?;
            }
            Ok(KnownData::Account(value))
        }
        "meta" => {
            let value: Rotation = parse(raw)?;
            if value.rotated_at_ms > MAX_SAFE_INTEGER
                || !hex(&value.by_device_id, 32)
                || !text(&value.by_device_name, 128)
            {
                return Err(invalid());
            }
            Ok(KnownData::Rotation(value))
        }
        _ => Err(invalid()),
    }
}
impl Inventory {
    /// Every input frame is explicitly understood or the whole local result is dropped.
    pub fn admit_known(&self) -> Result<Known, AppError> {
        let mut rows = vec![];
        for item in self.rows() {
            let view = item.view()?;
            let data = admit(&item.location.scope, &view)?;
            rows.push(KnownInput {
                location: item.location.clone(),
                sequence: item.sequence,
                dirty: item.dirty,
                kind: view.kind.into(),
                id: view.id.into(),
                version: view.version,
                updated_at_ms: view.updated_at_ms,
                device_id: view.device_id.into(),
                deleted: view.deleted,
                data,
            });
        }
        Ok(Known { rows })
    }
}
#[cfg(test)]
mod tests;
