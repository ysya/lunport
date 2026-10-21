//! Whole-library public preview and protected explicit consent. No network or cutover.
use super::super::{
    crypto,
    payload::{Data, Identity},
    wire::hex,
};
use super::*;
use serde::{Deserialize, Serialize};
const POLICY: &str = "personal-whole-library-v1";
const CAP: usize = 32768;
#[derive(Serialize)]
pub(super) struct KeyVersion {
    name: String,
    fingerprint: String,
    key_type: String,
    has_passphrase: bool,
    storage: &'static str,
    retained: bool,
}
#[derive(Serialize)]
pub(super) struct Summary {
    hosts: usize,
    groups: usize,
    collections: usize,
    history_records: usize,
    private_key_versions: usize,
    key_versions: Vec<KeyVersion>,
}
#[derive(Serialize)]
pub struct Preview {
    pub(in crate::sync::central) ticket: String,
    approved: bool,
    summary: Summary,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    policy: String,
    selection: Option<String>,
    source: Receipt,
    plan: Receipt,
    manifest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    version: u32,
    binding: Binding,
    ticket: String,
    accepted: bool,
}
/// Native evidence only. Callers must freshly check source/session/cursor and protected storage
/// before every remote effect and before the dedicated initial publication transaction.
pub(in crate::sync::central) struct Approval {
    binding: Binding,
}
impl Binding {
    fn current(loaded: &Loaded) -> Result<Self, AppError> {
        Ok(Self {
            policy: POLICY.into(),
            selection: loaded.plan.before().identity_slot.clone(),
            source: loaded.journal.source.clone(),
            plan: loaded.journal.plan.clone(),
            manifest: loaded.plan.manifest.digest()?,
        })
    }
}
fn role(loaded: &Loaded) -> Result<String, AppError> {
    let owner = loaded.plan.before();
    owner
        .control
        .profile
        .profile()?
        .device_slot("source-migration-review", owner.identity_slot.as_deref())
}
fn read(env: &SyncEnv, loaded: &Loaded) -> Result<Option<Review>, AppError> {
    let Some(value) = env
        .keychain
        .get_noninteractive(&role(loaded)?)?
        .map(Zeroizing::new)
    else {
        return Ok(None);
    };
    if value.len() > CAP {
        return Err(invalid());
    }
    let review: Review = serde_json::from_str(&value).map_err(|_| invalid())?;
    if review.version != 1
        || !hex(&review.ticket, 64)
        || review.binding != Binding::current(loaded)?
    {
        return Err(invalid());
    }
    Ok(Some(review))
}
fn save(env: &SyncEnv, loaded: &Loaded, review: Review) -> Result<Review, AppError> {
    if review.version != 1
        || !hex(&review.ticket, 64)
        || review.binding != Binding::current(loaded)?
    {
        return Err(invalid());
    }
    let encoded = Zeroizing::new(serde_json::to_string(&review).map_err(|_| invalid())?);
    if encoded.len() > CAP {
        return Err(invalid());
    }
    env.keychain.set_noninteractive(&role(loaded)?, &encoded)?;
    let checked = read(env, loaded)?.ok_or_else(invalid)?;
    if checked != review {
        return Err(invalid());
    }
    Ok(checked)
}
impl Approval {
    pub fn require_current(&self, env: &SyncEnv, loaded: &Loaded) -> Result<(), AppError> {
        let review = read(env, loaded)?.ok_or_else(invalid)?;
        if !review.accepted || review.binding != self.binding {
            return Err(invalid());
        }
        Ok(())
    }
}
pub(in crate::sync::central) fn accepted(
    env: &SyncEnv,
    loaded: &Loaded,
) -> Result<Approval, AppError> {
    let review = read(env, loaded)?.ok_or_else(|| {
        AppError::Other(
            "Review and confirm the complete library before migration can upload any material."
                .into(),
        )
    })?;
    if !review.accepted {
        return Err(AppError::Other(
            "Confirm the complete library review before migration can upload any material.".into(),
        ));
    }
    Ok(Approval {
        binding: review.binding,
    })
}
fn summary(history: &[(Identity, Data)]) -> Result<Summary, AppError> {
    let identities: Vec<String> = history
        .iter()
        .map(|(id, _)| serde_json::to_string(&(&id.kind, &id.id, &id.scope)).map_err(|_| invalid()))
        .collect::<Result<_, _>>()?;
    let mut latest = BTreeMap::new();
    for (index, id) in identities.iter().enumerate() {
        latest.insert(id, index);
    }
    let mut result = Summary {
        hosts: 0,
        groups: 0,
        collections: 0,
        history_records: history.len(),
        private_key_versions: 0,
        key_versions: vec![],
    };
    for (index, (_, data)) in history.iter().enumerate() {
        let current = latest.get(&identities[index]) == Some(&index);
        match data {
            Data::Host(_) if current => result.hosts += 1,
            Data::Group(_) if current => result.groups += 1,
            Data::Catalog(catalog) if current => result.collections = catalog.collections.len(),
            Data::Key(_) => result.private_key_versions += 1,
            Data::Keyslot(slot) => result.key_versions.push(KeyVersion {
                name: slot.public.name.clone(),
                fingerprint: slot.public.fingerprint.clone(),
                key_type: slot.public.key_type.clone(),
                has_passphrase: slot.public.has_passphrase,
                storage: match slot.storage {
                    KeyStorage::Managed { .. } => "managed",
                    KeyStorage::Hardware => "hardware",
                    KeyStorage::ExternalAgent => "external_agent",
                },
                retained: !current,
            }),
            _ => {}
        }
    }
    Ok(result)
}
fn with_current<T>(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
    action: impl FnOnce(&Loaded) -> Result<T, AppError>,
) -> Result<T, AppError> {
    let loaded = ensure(env, keys, references)?;
    let life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (state, generation) = crate::sync::record_runtime::snapshot(env)?;
    let session = controller::context(env)?;
    source_complete::check(env, &state, generation, &session, keys)?;
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    if loaded.package.state != state
        || Cursor::load(env, &life, owner)?.ok_or_else(invalid)?.cursor != loaded.cursor
    {
        return Err(crate::sync::runtime::superseded());
    }
    loaded.require_unchanged(env)?;
    let result = action(&loaded)?;
    source_complete::check(env, &state, generation, &session, keys)?;
    loaded.require_unchanged(env)?;
    Ok(result)
}
pub(in crate::sync::central) fn preview(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
) -> Result<Preview, AppError> {
    with_current(env, keys, references, |loaded| {
        let summary = summary(
            &loaded
                .package
                .structured_history(keys, references)?
                .into_rows(),
        )?;
        let review = match read(env, loaded)? {
            Some(review) => review,
            None => save(
                env,
                loaded,
                Review {
                    version: 1,
                    binding: Binding::current(loaded)?,
                    ticket: crypto::random_id(32)?,
                    accepted: false,
                },
            )?,
        };
        Ok(Preview {
            ticket: review.ticket,
            approved: review.accepted,
            summary,
        })
    })
}
pub(in crate::sync::central) fn confirm(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
    ticket: &str,
) -> Result<(), AppError> {
    if !hex(ticket, 64) {
        return Err(invalid());
    }
    with_current(env, keys, references, |loaded| {
        let mut review = read(env, loaded)?.ok_or_else(invalid)?;
        if review.ticket != ticket {
            return Err(invalid());
        }
        if !review.accepted {
            review.accepted = true;
            save(env, loaded, review)?;
        }
        accepted(env, loaded)?.require_current(env, loaded)
    })
}
#[cfg(all(test, any(unix, windows)))]
mod tests;

pub(in crate::sync::central) fn is_approved(
    env: &SyncEnv,
    loaded: &Loaded,
) -> Result<bool, AppError> {
    Ok(read(env, loaded)?.is_some_and(|r| r.accepted))
}

pub(in crate::sync::central) fn from_history(ticket:String,approved:bool,history:&[(Identity,Data)])->Result<Preview,AppError>{
    if !hex(&ticket,64){return Err(invalid());}
    Ok(Preview{ticket,approved,summary:summary(history)?})
}
