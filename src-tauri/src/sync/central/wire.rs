use crate::error::AppError;
use serde::{Deserialize, Serialize};

pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;
pub(crate) fn invalid() -> AppError {
    AppError::Other("Invalid central sync protocol data.".into())
}
pub fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn number(value: &str, zero: bool) -> Result<u64, AppError> {
    if value.is_empty()
        || value.len() > 16
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let value = value.parse::<u64>().map_err(|_| invalid())?;
    if value > MAX_SAFE_INTEGER || !zero && value == 0 {
        return Err(invalid());
    }
    Ok(value)
}
pub fn origin(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    let transport = url.scheme() == "https"
        || cfg!(any(test, feature = "development-profile"))
            && url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    transport
        && url.username().is_empty()
        && url.password().is_none()
        && url.origin().ascii_serialization() == value
}
/// Fixed UTF-8 JSON array of strings. No object sorting, numbers, floats or optional slots.
/// The Worker emits the identical array; field order and domain are protocol constants.
pub(crate) fn canonical(fields: &[&str]) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(fields).map_err(|_| invalid())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordHeader {
    pub origin: String,
    pub account_id: String,
    pub genesis_hash: String,
    pub vault_id: String,
    pub record_id: String,
    pub key_epoch: String,
    pub membership_head: String,
    pub author: String,
    pub operation_id: String,
    pub expected_revision: String,
    pub kind: String,
    pub deleted: bool,
}
impl RecordHeader {
    pub fn validate(&self) -> Result<(), AppError> {
        if !origin(&self.origin)
            || ![
                &self.account_id,
                &self.genesis_hash,
                &self.vault_id,
                &self.record_id,
                &self.membership_head,
            ]
            .into_iter()
            .all(|s| hex(s, 64))
            || !hex(&self.author, 32)
            || !hex(&self.operation_id, 32)
            || !matches!(
                self.kind.as_str(),
                "host" | "group" | "keyslot" | "key" | "password" | "meta"
            )
        {
            return Err(invalid());
        }
        number(&self.key_epoch, false)?;
        number(&self.expected_revision, true)?;
        Ok(())
    }
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        self.validate()?;
        canonical(&[
            "lunport-record-v2",
            &self.origin,
            &self.account_id,
            &self.genesis_hash,
            &self.vault_id,
            &self.record_id,
            &self.key_epoch,
            &self.membership_head,
            &self.author,
            &self.operation_id,
            &self.expected_revision,
            &self.kind,
            if self.deleted { "1" } else { "0" },
        ])
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrapHeader {
    pub origin: String,
    pub account_id: String,
    pub genesis_hash: String,
    pub vault_id: String,
    pub key_epoch: String,
    pub membership_head: String,
    pub recipient: String,
    pub recipient_key: String,
    pub author: String,
}
impl WrapHeader {
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if !origin(&self.origin)
            || ![
                &self.account_id,
                &self.genesis_hash,
                &self.vault_id,
                &self.membership_head,
            ]
            .into_iter()
            .all(|s| hex(s, 64))
            || self.recipient != "recovery" && !hex(&self.recipient, 32)
            || !hex(&self.author, 32)
        {
            return Err(invalid());
        }
        number(&self.key_epoch, false)?;
        super::crypto::decode(&self.recipient_key, 32, 32)?;
        canonical(&[
            "lunport-vault-wrap-v2",
            &self.origin,
            &self.account_id,
            &self.genesis_hash,
            &self.vault_id,
            &self.key_epoch,
            &self.membership_head,
            &self.recipient,
            &self.recipient_key,
            &self.author,
        ])
    }
}
