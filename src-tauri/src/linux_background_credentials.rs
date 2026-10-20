//! https://specifications.freedesktop.org/secret-service/latest-single/
//! SearchItems returns locked items separately. Do not call Unlock, ensure_unlocked, Prompt,
//! CreateItem or Delete here. Foreground setup creates slots; background only updates existing ones.
use crate::{error::AppError, secrets::SERVICE};
use secret_service::{blocking::SecretService, EncryptionType};
use std::collections::HashMap;
use zeroize::Zeroizing;
fn error() -> AppError {
    AppError::Other("needs interaction: unlock the account's secure credentials in Lunport".into())
}
fn query<'a>(account: &'a str) -> Result<HashMap<&'a str, &'a str>, AppError> {
    if account.is_empty() || account.len() > 4096 || account.contains('\0') {
        return Err(error());
    }
    Ok(HashMap::from([("service", SERVICE), ("username", account)]))
}
pub(super) fn get(account: &str) -> Result<Option<String>, AppError> {
    let ss = SecretService::connect(EncryptionType::Dh).map_err(|_| error())?;
    let found = ss.search_items(query(account)?).map_err(|_| error())?;
    if !found.locked.is_empty() || found.unlocked.len() > 1 {
        return Err(error());
    }
    let Some(item) = found.unlocked.first() else {
        return Ok(None);
    };
    let value = Zeroizing::new(item.get_secret().map_err(|_| error())?);
    if value.len() > 1024 * 1024 {
        return Err(error());
    }
    std::str::from_utf8(&value)
        .map(|value| Some(value.to_owned()))
        .map_err(|_| error())
}
pub(super) fn set(account: &str, value: &str) -> Result<(), AppError> {
    if value.len() > 1024 * 1024 {
        return Err(error());
    }
    let ss = SecretService::connect(EncryptionType::Dh).map_err(|_| error())?;
    let found = ss.search_items(query(account)?).map_err(|_| error())?;
    if !found.locked.is_empty() || found.unlocked.len() != 1 {
        return Err(error());
    }
    // Item.SetSecret has no prompt result and returns IsLocked if locking raced this search.
    found.unlocked[0]
        .set_secret(value.as_bytes(), "text/plain")
        .map_err(|_| error())
}
