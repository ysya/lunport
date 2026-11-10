//! The way around helper v1 for saved credentials it may not hand over without asking (`credentials_helper`): helper v2's adopt reads
//! the earlier service's item itself, saves it under this version's service, reads it back and only then deletes the old item, and
//! macOS asks the user once for each. It runs only when the user chose Continue in the window that says how many items need their
//! permission (`identity_migration_adopt_credentials`), vault keys first; then the credential step runs again for whatever helper v1
//! can hand over now.
//!
//! A refusal leaves the old item as it was, and the item waits for the next time Lunport asks. A conflict goes the way the core settles
//! one: the current value stays and the old item is kept for good, unless the old value wins (a vault key, or the user chose the old
//! data, `credentials::Conflicts`). Then the current value is set aside and read back, its set-aside name recorded, and only then
//! deleted, so that adopt can move the old value into its place.

use super::credentials::{kept_reason, note_set_aside, record_in, restart_helps, set_aside, set_hidden, CurrentCredentials};
use super::data_root::Occupied;
use super::journal::{self, Journal, Unreadable};
use super::{locked, migrate, save, Entry, Report, Roots, Step, Waits};
use crate::error::AppError;
use crate::secrets::macos_helper::Adoption;
use crate::vault::store::is_vault_key_account;

/// Helper v2's adopt, as far as the fallback needs it.
pub(super) trait Adopter {
    /// Asks helper v2 to move `account` from the earlier service to the current one; macOS may ask the user, and the request waits for
    /// the answer.
    fn adopt(&self, account: &str) -> Result<Adoption, AppError>;
}

/// What one adopt run did with the items that waited for the user's permission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Adopted {
    /// Under the current service only now, in the order they moved.
    pub moved: Vec<String>,
    /// Those of `moved` that were not usable under the current service before (an item helper v1 could read but not delete had its
    /// copy there already, and only lost its old copy): what the running app may not have had.
    pub made_usable: Vec<String>,
    /// The user did not allow them: each old item is as it was, and waits for the next time Lunport asks.
    pub denied: Vec<String>,
    /// Left for a later run, each with why.
    pub failed: Vec<(String, String)>,
    /// Left under the earlier service for good, each with why.
    pub kept: Vec<(String, String)>,
    /// Why the run stopped before it got to every item: helper v2 could not be reached or asked, or this build is misconfigured.
    pub stopped: Option<String>,
}

/// What the journal says of a conflict that adopt keeps on the current value.
const SETTLED: &str = "another value is saved under the new name, and stays";

#[cfg(not(test))]
static UNUSABLE_SEEN: std::sync::Mutex<std::collections::BTreeSet<String>> = std::sync::Mutex::new(std::collections::BTreeSet::new());
#[cfg(test)]
thread_local! {
    static UNUSABLE_SEEN: std::cell::RefCell<std::collections::BTreeSet<String>> = const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

/// Whether `account` counts as usable under the current service for the running app, `held` saying whether the service holds it now:
/// not when an adopt in this process found it missing earlier. A copy an earlier adopt left there (its old item would not delete, say)
/// appeared after this process started, so completing that item later still makes it usable for the running app.
fn usable_since_start(account: &str, held: bool) -> bool {
    #[cfg(not(test))]
    let mut seen = UNUSABLE_SEEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    #[cfg(not(test))]
    let usable = remember(&mut seen, account, held);
    #[cfg(test)]
    let usable = UNUSABLE_SEEN.with(|seen| remember(&mut seen.borrow_mut(), account, held));
    usable
}

fn remember(seen: &mut std::collections::BTreeSet<String>, account: &str, held: bool) -> bool {
    if !held {
        seen.insert(account.to_string());
    }
    held && !seen.contains(account)
}

/// Moves the items `journal` says wait for the user's permission with `adopter` (helper v2's adopt), vault keys first, `current` being
/// helper v2's ordinary requests (for a conflict the old value wins), and records the outcome in `journal`: what moved or is gone from
/// the earlier service waits no more, what stays for good is kept, what the user denied keeps waiting. `record` writes the journal
/// down at once, which a conflict asks for before it deletes the value it set aside.
pub(super) fn adopt_with(
    adopter: &dyn Adopter,
    current: &dyn CurrentCredentials,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
) -> Adopted {
    // The old value wins a vault key's conflict, and every conflict once the user chose the old data (`Conflicts::PreferOld`).
    let old_wins = |account: &str| journal.use_old_data || is_vault_key_account(account);
    let progress = &journal.credential_progress;
    let (vault_keys, others): (Vec<String>, Vec<String>) = progress
        .needs_permission
        .iter()
        .filter(|account| !progress.kept.contains_key(*account))
        .cloned()
        .partition(|account| is_vault_key_account(account));
    let prefers_old: Vec<bool> = vault_keys.iter().chain(&others).map(|account| old_wins(account)).collect();
    let mut adopted = Adopted::default();
    let mut settled = Vec::new();
    for (account, prefers_old) in vault_keys.into_iter().chain(others).zip(prefers_old) {
        let usable_before = usable_since_start(&account, matches!(current.read(&account), Ok(Some(_))));
        let mut replaced = false;
        let first = match adopter.adopt(&account) {
            Ok(adoption) => adoption,
            Err(error) => {
                adopted.stopped = Some(error.to_string());
                break;
            }
        };
        let outcome = match first {
            Adoption::Conflict if prefers_old => match give_way(adopter, current, journal, record, &account) {
                Ok(Ok(adoption)) => {
                    replaced = true;
                    adoption
                }
                // Helper v2 could not be reached for the second adopt: the run stops, as for the first.
                Ok(Err(error)) => {
                    adopted.stopped = Some(error.to_string());
                    break;
                }
                Err(why) => {
                    adopted.failed.push((account, why));
                    continue;
                }
            },
            adoption => adoption,
        };
        match outcome {
            Adoption::Moved => {
                settled.push(account.clone());
                if !usable_before || replaced {
                    adopted.made_usable.push(account.clone());
                }
                adopted.moved.push(account);
            }
            // Nothing is under the earlier name any more.
            Adoption::NoOldItem => settled.push(account),
            Adoption::Refused(_) => adopted.denied.push(account),
            Adoption::Conflict if !prefers_old => {
                settled.push(account.clone());
                adopted.kept.push((account, SETTLED.into()));
            }
            Adoption::Conflict => adopted.failed.push((account, "another value was saved under the new name meanwhile".into())),
            Adoption::TooLarge => {
                settled.push(account.clone());
                adopted.kept.push((account, "it holds more than 1 MiB".into()));
            }
            Adoption::NotVerified => {
                adopted.failed.push((account, "its copy under the new name did not read back as it was saved".into()))
            }
            Adoption::Failed(status) => adopted.failed.push((account, format!("macOS could not move it (OSStatus {status})"))),
            Adoption::Misconfigured => {
                adopted.stopped = Some("this build names one credential service for both sides; nothing was touched".into());
                break;
            }
        }
    }
    let progress = &mut journal.credential_progress;
    for account in &settled {
        progress.needs_permission.remove(account);
    }
    // Kept by name, so that no later attempt asks helper v1 for them again (the core skips what it keeps for good).
    for (account, why) in &adopted.kept {
        progress.kept.insert(account.clone(), kept_reason(why));
    }
    if restart_helps(&adopted.made_usable) {
        progress.start_credential_moves = progress.start_credential_moves.saturating_add(1);
    }
    adopted
}

/// Makes way under the current service for the old value of `account`, which wins its conflict, and adopts it again: the current value
/// is set aside and read back (`credentials::set_aside`), its set-aside name recorded in the journal before anything else, and only
/// then deleted. Returns the second adopt's answer (an error when helper v2 could not be reached), or why the current value could not
/// make way (it is then where it was).
fn give_way(
    adopter: &dyn Adopter,
    current: &dyn CurrentCredentials,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
    account: &str,
) -> Result<Result<Adoption, AppError>, String> {
    let value = current.read(account).map_err(|error| format!("the value saved under the new name could not be read: {error}"))?;
    if let Some(value) = value {
        let name = set_aside(current, account, &value)?;
        note_set_aside(journal, account, &name);
        record(journal).map_err(|error| format!("{name}, which keeps the value saved under the new name, could not be recorded: {error}"))?;
        current.delete(account).map_err(|error| format!("the value saved under the new name could not make way: {error}"))?;
    }
    Ok(adopter.adopt(account))
}

/// The adopt run the user asked for in the window (`identity_migration_adopt_credentials`), on this computer: helper v2 moves the items
/// that wait for the user's permission, then the migration runs again for the desktop, the credential step with it. Returns the run's
/// report, which says a restart helps when the adopt moved a vault key or the sync code, and why the adopt run stopped early, if it did.
pub(crate) fn adopt_credentials(roots: &Roots, waits: &Waits) -> (Report, Option<String>) {
    adopt_credentials_with(roots, waits, &native::Asking, &super::credentials_helper::HelperV2)
}

/// `adopt_credentials` with `adopter` and `current` for helper v2.
///
/// The run holds the migration's lock, and `secrets::access_guard` while helper v2 adopts, all the while macOS asks (each request waits
/// up to 305 seconds for the user's answer). Meanwhile the app's own credential requests (an MCP `ssh_exec` that needs a password, say)
/// wait for it, and another start of Lunport gives up waiting for the migration's lock and shows why. The window's sheet is modal and
/// the user is answering macOS, so that is acceptable; it ends with the last answer.
pub(super) fn adopt_credentials_with(
    roots: &Roots,
    waits: &Waits,
    adopter: &dyn Adopter,
    current: &dyn CurrentCredentials,
) -> (Report, Option<String>) {
    // The user asked for it in the window: this process counts as one the user sees from now on.
    set_hidden(false);
    let mut stopped = None;
    let report = locked(roots, waits, |roots, waits| {
        let mut journal = match journal::read(&roots.data.new) {
            Ok(Some(journal)) => journal,
            // A journal this version cannot read in full (a later version's, say): what can still be read of it is what the adopt runs
            // on, as the migration itself would.
            Err(Unreadable::Damaged) => match journal::salvage(&roots.data.new) {
                Ok(journal) => journal,
                Err(error) => {
                    let error = format!("cannot set the damaged migration journal aside, or write back what could be read of it: {error}");
                    return Report::failed(Step::DataRoot, error);
                }
            },
            Err(error @ Unreadable::Io(_)) => {
                return Report::failed(Step::DataRoot, format!("{error} (in {})", roots.data.new.display()));
            }
            Ok(None) => {
                stopped = Some("nothing was asked: the record of the move is missing".to_string());
                return migrate(Entry::Desktop, roots, waits, Occupied::Refuse);
            }
        };
        let adopted = {
            // A request that asks the user waits for the one before it to be answered, as every keychain request of this process does.
            let _access = crate::secrets::access_guard();
            adopt_with(adopter, current, &mut journal, &record_in(roots))
        };
        stopped = adopted.stopped.clone();
        if let Err(report) = save(roots, Step::Credentials, &journal) {
            return report;
        }
        let mut report = migrate(Entry::Desktop, roots, waits, Occupied::Refuse);
        report.restart_helps |= restart_helps(&adopted.made_usable);
        report
    });
    (report, stopped)
}

/// Helper v2's adopt on this computer, never reached by a test.
mod native {
    use super::Adopter;
    use crate::error::AppError;
    use crate::secrets::macos_helper::{self, Adoption};

    /// Helper v2's adopt, letting macOS ask the user, and waiting for the answer as long as the helper does.
    pub(super) struct Asking;

    impl Adopter for Asking {
        fn adopt(&self, account: &str) -> Result<Adoption, AppError> {
            assert!(!cfg!(test), "a test reached this computer's keychain, which holds the owner's own items");
            macos_helper::adopt(account, false)
        }
    }
}

#[cfg(test)]
#[path = "credentials_adopt_tests.rs"]
mod tests;
