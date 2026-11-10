//! macOS Production: versions before 2.0.0 kept saved credentials with helper v1, under their credential service, and helper v1 hands
//! an item only to a parent signed as the app was then. The app reaches it through the bridge (`secrets::macos_helper::bridge`) and
//! saves each item with helper v2 under this version's service; the core moves them (`credentials::run_step`), vault keys first. The
//! accounts come from the default keychain's attributes (`credentials_macos`). No request lets macOS ask the user anything, so the step
//! runs before the window opens, in a start hidden for a client as well.
//!
//! An item helper v1 may not hand over without asking stays where it is, left for a later attempt, and the journal says it waits for
//! the user's permission (`CredentialProgress::needs_permission`): helper v2's adopt moves it once the user agrees in the window, one
//! macOS prompt each (`credentials_adopt`). So that the window asks once for everything, an attempt that a vault key waiting for
//! permission stopped also asks helper v1 about the items it did not get to, and drops what it reads; an item an earlier attempt found
//! to need permission, or to be handed over without it (`CredentialProgress::probed_readable`), is not asked about again, so that the
//! starts while the vault key waits do not each read every such item. A bridge that gets no answer from helper v1 (each request waits
//! up to the bridge's timeout) costs an attempt one wait at most: after the first request without an answer, the attempt asks the
//! bridge nothing more, and what it did not ask stays as if not reached. A bridge that gets no answer at all, attempt after attempt, in
//! a way that may pass, would leave the vault waiting forever: from the third such attempt in a row, what is left waits for the user's
//! permission too, and later starts do not ask that bridge at all, until a version with another bridge starts the count again.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

use zeroize::Zeroizing;

use super::credentials::{run_step_reporting, step_state, CredentialReport, CurrentCredentials, LegacyCredentials};
use super::credentials_macos::unless_locked;
use super::journal::{CredentialProgress, Journal};
use super::StepState;
use crate::error::AppError;
use crate::vault::store::is_vault_key_account;

/// Helper v1, reached through the bridge, as far as the move needs it.
pub(super) trait EarlierHelper {
    /// Every account saved under the earlier service, from the keychain's attributes.
    fn accounts(&self) -> Result<Vec<String>, AppError>;
    /// What helper v1 holds for `account`; `None` when it holds nothing.
    fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError>;
    /// Asks helper v1 to delete what it holds for `account`; nothing there is fine.
    fn delete(&self, account: &str) -> Result<(), AppError>;
    /// Whether `error`, from `get` or `delete`, means the item needs the user's permission to move (helper v2's adopt).
    fn needs_permission(&self, error: &AppError) -> bool;
    /// Whether `error`, from `get` or `delete`, means no answer came from helper v1 through the bridge, in a way that may pass.
    fn chain_failed(&self, error: &AppError) -> bool;
    /// Whether `error`, from `get`, means the item can never be read here.
    fn unreadable_for_good(&self, error: &AppError) -> bool;
    /// The bridge helper v1 is reached through: its pinned SHA-256. The count of attempts without an answer belongs to it.
    fn bridge(&self) -> String;
}

/// What an attempt says of an item it did not ask the bridge about, a request without an answer having come first: it is left for a
/// later attempt, as if not reached.
const NOT_ASKED: &str = "credential bridge: not asked: helper v1 did not answer an earlier request of this attempt";

/// The most bytes of account names the journal keeps among the items that wait for the user's permission, so that it stays small;
/// more are only counted (`CredentialProgress::needs_permission_unnamed`). What room they leave holds the items helper v1 handed over
/// without asking (`remember_readable`).
pub(super) const MAX_PERMISSION_NAMES: usize = 16 * 1024;

/// How many attempts in a row may get no answer from helper v1 through the bridge, in a way that may pass, before what is left waits
/// for the user's permission instead (`CredentialProgress::chain_failures`).
pub(super) const CHAIN_FAILURES_BEFORE_ADOPT: u32 = 3;

/// Helper v1 as the credential step sees it, remembering what it listed, which accounts the step read, which of them need the user's
/// permission, which the probes were handed without asking, and whether any request got an answer through the bridge or failed to.
/// After the first request without an answer it sends nothing more (`unanswered`): each would wait as long again.
struct Watched<'a, E: ?Sized> {
    earlier: &'a E,
    listed: RefCell<Option<Vec<String>>>,
    read: RefCell<BTreeSet<String>>,
    refused: RefCell<BTreeSet<String>>,
    handed: RefCell<BTreeSet<String>>,
    answered: Cell<bool>,
    unanswered: Cell<bool>,
}

impl<'a, E: EarlierHelper + ?Sized> Watched<'a, E> {
    fn new(earlier: &'a E) -> Self {
        Self {
            earlier,
            listed: RefCell::new(None),
            read: RefCell::default(),
            refused: RefCell::default(),
            handed: RefCell::default(),
            answered: Cell::new(false),
            unanswered: Cell::new(false),
        }
    }

    /// `result` of a request about `account`, remembering the account when the result says it needs the user's permission, and
    /// whether helper v1 answered through the bridge.
    fn noting<T>(&self, account: &str, result: Result<T, AppError>) -> Result<T, AppError> {
        match &result {
            Err(error) if self.earlier.chain_failed(error) => self.unanswered.set(true),
            Err(error) if self.earlier.needs_permission(error) => {
                self.refused.borrow_mut().insert(account.to_string());
                self.answered.set(true);
            }
            _ => self.answered.set(true),
        }
        result
    }

    /// Asks helper v1 about `account`, which the core did not reach, for whether it needs the user's permission (what it reads is
    /// dropped, and the account noted as handed over); nothing once a request of this attempt got no answer.
    fn probe(&self, account: &str) {
        if !self.unanswered.get() && matches!(self.noting(account, self.earlier.get(account)), Ok(Some(_))) {
            self.handed.borrow_mut().insert(account.to_string());
        }
    }
}

impl<E: EarlierHelper + ?Sized> LegacyCredentials for Watched<'_, E> {
    fn accounts(&self) -> Result<Vec<String>, AppError> {
        let accounts = self.earlier.accounts()?;
        *self.listed.borrow_mut() = Some(accounts.clone());
        Ok(accounts)
    }
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        if self.unanswered.get() {
            return Err(AppError::Other(NOT_ASKED.into()));
        }
        self.read.borrow_mut().insert(account.to_string());
        self.noting(account, self.earlier.get(account))
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        if self.unanswered.get() {
            return Err(AppError::Other(NOT_ASKED.into()));
        }
        self.noting(account, self.earlier.delete(account))
    }
    fn unreadable_for_good(&self, error: &AppError) -> bool {
        self.earlier.unreadable_for_good(error)
    }
}

/// The credential step with helper v1 through the bridge (`earlier`) and helper v2 (`current`), unless the default keychain is locked
/// (`locked`, `credentials_macos::unless_locked`). Afterwards the journal says which items wait for the user's permission.
pub(super) fn move_with(
    earlier: &impl EarlierHelper,
    current: &dyn CurrentCredentials,
    locked: Result<bool, AppError>,
    journal: &mut Journal,
    record: &dyn Fn(&Journal) -> Result<(), AppError>,
) -> StepState {
    unless_locked(locked, journal, |journal| {
        let bridge = earlier.bridge();
        let progress = &mut journal.credential_progress;
        // The count belongs to the bridge it was made with: another one (an update) gets a fresh chance.
        if progress.chain_failures > 0 && progress.chain_failures_bridge != bridge {
            progress.chain_failures = 0;
        }
        if progress.chain_failures >= CHAIN_FAILURES_BEFORE_ADOPT {
            return without_the_bridge(earlier, journal);
        }
        let watched = Watched::new(earlier);
        let (state, report) = run_step_reporting(&watched, current, journal, record);
        // An attempt that could not list the earlier service says nothing new of what waits.
        let Some(listed) = watched.listed.take() else { return state };
        let progress = &mut journal.credential_progress;
        // What the attempt did not get to: a vault key stopped it, or the bridge stopped answering.
        let unreached: BTreeSet<String> = listed
            .iter()
            .filter(|account| !watched.read.borrow().contains(*account) && !progress.kept.contains_key(*account))
            .cloned()
            .collect();
        // So that the window asks once for everything: when a vault key that needs permission stopped the core, what it did not reach
        // is asked about (`Watched::probe`), unless an earlier attempt found it needs permission or is handed over without it.
        if watched.refused.borrow().iter().any(|account| is_vault_key_account(account)) {
            let known = |account: &&String| progress.needs_permission.contains(*account) || progress.probed_readable.contains(*account);
            for account in unreached.iter().filter(|account| !known(account)) {
                watched.probe(account);
            }
        }
        let Watched { read, refused, handed, answered, unanswered, .. } = watched;
        let (read, mut refused) = (read.into_inner(), refused.into_inner());
        // Once per attempt: an answer starts the count again, an attempt without any counts once.
        if answered.get() {
            progress.chain_failures = 0;
        } else if unanswered.get() {
            progress.chain_failures = progress.chain_failures.saturating_add(1);
            progress.chain_failures_bridge = bridge;
        }
        if progress.chain_failures >= CHAIN_FAILURES_BEFORE_ADOPT {
            // No answer, attempt after attempt: nothing moved, and helper v2's adopt goes around the bridge.
            refused.extend(listed.iter().filter(|account| !progress.kept.contains_key(*account)).cloned());
        }
        let waiting = waiting_for_permission(progress, &listed, &read, refused);
        remember_readable(progress, &unreached, handed.into_inner(), &waiting);
        // Left for a later attempt: what failed and what was not reached, apart from what waits for permission.
        let failed = report.failed.iter().map(|(account, _)| account).filter(|account| !account.is_empty());
        let later: BTreeSet<&String> = failed.clone().chain(&unreached).filter(|account| !waiting.contains(*account)).collect();
        progress.retrying = later.len();
        // Whether only the user's permission holds the vault back, which a retry cannot give (`LeftBehind::retry_helps`).
        let vault_keys: Vec<&String> = failed.filter(|account| is_vault_key_account(account)).collect();
        progress.vault_waits_for_permission = !vault_keys.is_empty() && vault_keys.iter().all(|account| waiting.contains(*account));
        state
    })
}

/// The credential step once the bridge has got no answer `CHAIN_FAILURES_BEFORE_ADOPT` attempts in a row: nothing is asked of the
/// bridge (or of helper v2), and every item left under the earlier name, as the keychain's attributes list them, waits for the user's
/// permission straight away. Helper v2's adopt moves them; the step is done once nothing is left.
fn without_the_bridge(earlier: &impl EarlierHelper, journal: &mut Journal) -> StepState {
    let listed = match earlier.accounts() {
        Ok(listed) => listed,
        Err(error) => {
            let failed = vec![(String::new(), format!("they could not be listed: {error}"))];
            return step_state(&CredentialReport { failed, vault_key_ok: false, ..CredentialReport::default() });
        }
    };
    let progress = &mut journal.credential_progress;
    progress.waiting_for_the_user = false;
    // As the core does: an item kept for good that is gone from the earlier service is not left behind any more.
    progress.kept.retain(|account, _| listed.contains(account));
    let left: BTreeSet<String> = listed.iter().filter(|account| !progress.kept.contains_key(*account)).cloned().collect();
    let waiting = waiting_for_permission(progress, &listed, &BTreeSet::new(), left);
    // Everything left waits for permission now, what helper v1 handed over before included.
    progress.probed_readable.clear();
    let vault_keys = waiting.iter().filter(|account| is_vault_key_account(account)).count();
    progress.retrying = 0;
    progress.vault_waits_for_permission = vault_keys > 0;
    progress.vault_keys_moved |= vault_keys == 0;
    journal.moved_credentials.clear();
    let why = format!(
        "helper v1 could not be reached through the bridge {} attempts in a row, so it waits for your permission instead",
        progress.chain_failures
    );
    let failed = waiting.into_iter().map(|account| (account, why.clone())).collect();
    step_state(&CredentialReport { failed, vault_key_ok: vault_keys == 0, ..CredentialReport::default() })
}

/// Records in `progress` the items helper v1 hands over without asking, as far as the probes found (`CredentialProgress::probed_readable`):
/// those earlier attempts found, and those this attempt's probes did (`handed`), as long as the attempt did not reach them (`unreached`:
/// one it read says what it is now, and one gone from the earlier service or kept there for good is not among them) and they do not
/// wait for the user's permission (`waiting`). They are named in the room `MAX_PERMISSION_NAMES` leaves beside the items that wait for
/// permission; one not named is asked about again.
pub(super) fn remember_readable(
    progress: &mut CredentialProgress,
    unreached: &BTreeSet<String>,
    handed: BTreeSet<String>,
    waiting: &BTreeSet<String>,
) {
    let mut bytes: usize = progress.needs_permission.iter().map(String::len).sum();
    let readable: BTreeSet<String> = std::mem::take(&mut progress.probed_readable)
        .into_iter()
        .chain(handed)
        .filter(|account| unreached.contains(account) && !waiting.contains(account))
        .collect();
    for account in readable {
        if bytes + account.len() <= MAX_PERMISSION_NAMES {
            bytes += account.len();
            progress.probed_readable.insert(account);
        }
    }
}

/// Records in `progress` which items wait for the user's permission after an attempt that listed `listed` under the earlier service,
/// read `read` and found `refused` needing it: an account the attempt read says what it is now, one gone from the earlier service or
/// kept there for good waits for nothing, and one the attempt did not get to keeps waiting. Vault keys are always named, the rest up to
/// `MAX_PERMISSION_NAMES` bytes, and counted beyond. Once none waits, what the user put off is forgotten
/// (`CredentialProgress::permission_put_off`). Returns every account that waits.
pub(super) fn waiting_for_permission(
    progress: &mut CredentialProgress,
    listed: &[String],
    read: &BTreeSet<String>,
    refused: BTreeSet<String>,
) -> BTreeSet<String> {
    let listed: BTreeSet<&String> = listed.iter().collect();
    let mut waiting: BTreeSet<String> = std::mem::take(&mut progress.needs_permission)
        .into_iter()
        .filter(|account| !read.contains(account) && listed.contains(account))
        .collect();
    waiting.extend(refused);
    waiting.retain(|account| !progress.kept.contains_key(account));
    let (vault_keys, others): (Vec<String>, Vec<String>) = waiting.iter().cloned().partition(|account| is_vault_key_account(account));
    let (mut bytes, mut unnamed) = (0, 0);
    for account in vault_keys.into_iter().chain(others) {
        if is_vault_key_account(&account) || bytes + account.len() <= MAX_PERMISSION_NAMES {
            bytes += account.len();
            progress.needs_permission.insert(account);
        } else {
            unnamed += 1;
        }
    }
    progress.needs_permission_unnamed = unnamed;
    // What the user put off is forgotten once nothing waits: what waits later on is asked for at start again.
    if waiting.is_empty() {
        progress.permission_put_off = 0;
    }
    waiting
}

pub(super) use native::HelperV2;
#[cfg_attr(test, allow(unused_imports))]
pub(super) use native::{legacy_accounts, move_credentials};

/// This computer's helpers and keychain, never reached by a test.
mod native {
    use std::cell::OnceCell;

    use zeroize::Zeroizing;

    use super::super::credentials::{record_in, CurrentCredentials};
    use super::super::credentials_macos::{accounts_metadata_only, default_keychain_locked};
    use super::super::journal::Journal;
    use super::super::{Roots, StepState};
    use super::{move_with, EarlierHelper};
    use crate::error::AppError;
    use crate::legacy_identity;
    use crate::secrets::macos_helper::{self, bridge};

    /// Helper v1 through the bridge, both installed in the data root when the move first reads an item.
    #[derive(Default)]
    struct Bridged(OnceCell<Result<bridge::Session, String>>);

    impl Bridged {
        fn session(&self) -> Result<&bridge::Session, AppError> {
            self.0
                .get_or_init(|| {
                    // A session that cannot be opened got no answer from helper v1 either (`EarlierHelper::chain_failed`).
                    bridge::Session::open(&macos_helper::bridge(), &macos_helper::helper_v1())
                        .map_err(|error| bridge::unreachable(error).to_string())
                })
                .as_ref()
                .map_err(|message| AppError::Other(message.clone()))
        }
    }

    impl EarlierHelper for Bridged {
        fn accounts(&self) -> Result<Vec<String>, AppError> {
            accounts_metadata_only(legacy_identity::current().credential_service)
        }
        fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            self.session()?.get(account)
        }
        fn delete(&self, account: &str) -> Result<(), AppError> {
            self.session()?.delete(account)
        }
        fn needs_permission(&self, error: &AppError) -> bool {
            bridge::needs_permission(error)
        }
        fn chain_failed(&self, error: &AppError) -> bool {
            bridge::chain_failed(error)
        }
        fn unreadable_for_good(&self, error: &AppError) -> bool {
            bridge::unreadable_for_good(error)
        }
        fn bridge(&self) -> String {
            macos_helper::bridge().sha256().to_string()
        }
    }

    /// Helper v2, which keeps this version's credentials. None of the move's requests lets macOS ask anything.
    pub(in crate::identity_migration) struct HelperV2;

    impl CurrentCredentials for HelperV2 {
        fn write(&self, account: &str, value: &str) -> Result<(), AppError> {
            macos_helper::set_noninteractive(account, value)
        }
        fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, AppError> {
            Ok(macos_helper::get_noninteractive(account)?.map(Zeroizing::new))
        }
        fn delete(&self, account: &str) -> Result<(), AppError> {
            macos_helper::delete_noninteractive(account)
        }
    }

    /// The credential step on this computer: every desktop start, before the window opens, hidden or not (`credentials::runs`).
    #[cfg_attr(test, allow(dead_code))]
    pub(in crate::identity_migration) fn move_credentials(roots: &Roots, journal: &mut Journal) -> StepState {
        assert!(!cfg!(test), "a test reached this computer's keychain, which holds the owner's own items");
        // Nothing else in this process reads or writes a credential meanwhile.
        let _access = crate::secrets::access_guard();
        move_with(&Bridged::default(), &HelperV2, default_keychain_locked(), journal, &record_in(roots))
    }

    /// The accounts under the earlier version's service.
    #[cfg_attr(test, allow(dead_code))]
    pub(in crate::identity_migration) fn legacy_accounts() -> Result<Vec<String>, AppError> {
        assert!(!cfg!(test), "a test reached this computer's keychain, which holds the owner's own items");
        accounts_metadata_only(legacy_identity::current().credential_service)
    }
}

#[cfg(test)]
#[path = "credentials_helper_tests.rs"]
pub(super) mod tests;
