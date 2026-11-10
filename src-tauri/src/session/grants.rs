//! One Privileged Access Manager grant request at a time for each grant that several connections may need at once.
//! The in-app terminal reconnects every prod tab when the network returns, a saved tunnel and a tab start together:
//! the first connection to need a grant asks the person and requests it; the others wait for how that comes out instead of asking again.
//! A gate is keyed by what names the grant (account, project, location, entitlement) and lives as long as the request; a connection that
//! needs the grant after the request came out finds no gate and leads anew (a grant that is active never gets this far: `prepare` passes).
//!
//! The steps of a request are here too, so that a saved host and a saved database take the same ones: the look for a grant in flight
//! (`current_grant`), the question in Lunport's window with the request that follows it (`ask_and_request`, `request_active_grant`),
//! and the waits both share.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use super::auth::{Owner, Reply};
use super::connect::{local_hhmm, CancelToken};
use super::directory::{GrantNeed, GrantReceipt};
use super::protocol::{GrantAnswer, GrantPrompt, QuestionKind};
use crate::gcp::pam::{self, EntitlementName};
use crate::gcp::rest::{GcpClient, GcpError};
use crate::sync::transports::PamCheck;

/// How long the person has to answer the Request-a-grant question: five minutes, the window's own limit.
const GRANT_QUESTION_WAIT: Duration = Duration::from_secs(300);
/// How long a connection waits for another connection's grant request to come out: the question, the request and the minute of
/// polling for the grant to become active, with room.
const GATE_WAIT: Duration = Duration::from_secs(7 * 60);
/// How often a requested grant is read back while it activates.
pub(crate) const POLL_EVERY: Duration = Duration::from_secs(2);
/// How long a requested grant is given to become active.
pub(crate) const ACTIVE_WITHIN: Duration = Duration::from_secs(60);
/// How long after it was given a grant still counts as recent: the service that checks it may not have seen it yet (IAP can take about
/// 1½ minutes to see one).
const RECENT_GRANT: Duration = Duration::from_secs(120);

/// What names a grant: the connections that need the same one share a gate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GateKey {
    pub account: Option<String>,
    pub project: String,
    pub location: String,
    pub entitlement: String,
}

impl GateKey {
    pub fn of(need: &GrantNeed) -> GateKey {
        GateKey { account: need.account.clone(), project: need.project.clone(), location: need.location.clone(), entitlement: need.entitlement.clone() }
    }
}

/// How a request came out, for the connections that waited on it: the grant, or the sentence the connection that asked failed with.
pub type Outcome = Result<GrantReceipt, String>;

#[derive(Default)]
struct Gate {
    outcome: Mutex<Option<Outcome>>,
    settled: Condvar,
    waiting: AtomicUsize,
}

/// The gates of one app: one for each grant a connection is requesting right now.
#[derive(Default)]
pub struct GrantGates {
    gates: Mutex<HashMap<GateKey, Arc<Gate>>>,
}

/// What `enter` gives a connection: the lead, who asks and requests and then settles the gate for the others, or the outcome the lead
/// settled.
pub enum Entry<'a> {
    Lead(Lease<'a>),
    Outcome(Outcome),
}

/// The lead's hold on a gate: `settle` it with how the request came out. A lease dropped unsettled (a panic on the way) settles the gate
/// with a sentence of its own, so that nobody waits on it.
pub struct Lease<'a> {
    gates: &'a GrantGates,
    key: GateKey,
    gate: Arc<Gate>,
    settled: bool,
}

/// The sentence a connection gets when the lead's request took longer than `wait`.
pub const TOO_LONG: &str = "Another connection's grant request did not finish in time; connect again.";
const UNSETTLED: &str = "The grant request did not finish; connect again.";
const CANCELLED: &str = "The connection was cancelled.";

impl GrantGates {
    /// Takes the gate of `key`: the first connection to come gets `Lead`; every later one waits until the lead settles the gate, `cancel`
    /// is set or `wait` has passed, and gets the `Outcome` (a sentence, in the latter two cases; a cancelled connection checks `cancel`
    /// itself).
    pub fn enter(&self, key: GateKey, cancel: &CancelToken, wait: Duration) -> Entry<'_> {
        let gate = {
            let mut gates = locked(&self.gates);
            match gates.get(&key) {
                Some(gate) => Arc::clone(gate),
                None => {
                    let gate = Arc::new(Gate::default());
                    gates.insert(key.clone(), Arc::clone(&gate));
                    return Entry::Lead(Lease { gates: self, key, gate, settled: false });
                }
            }
        };
        gate.waiting.fetch_add(1, Ordering::SeqCst);
        let deadline = Instant::now() + wait;
        let mut outcome = locked(&gate.outcome);
        let result = loop {
            if let Some(outcome) = outcome.as_ref() {
                break outcome.clone();
            }
            if cancel.is_cancelled() {
                break Err(CANCELLED.to_string());
            }
            let now = Instant::now();
            if now >= deadline {
                break Err(TOO_LONG.to_string());
            }
            // Woken by the lead, or every so often to look at `cancel`.
            let (guard, _) = gate.settled.wait_timeout(outcome, (deadline - now).min(Duration::from_millis(250))).unwrap_or_else(PoisonError::into_inner);
            outcome = guard;
        };
        drop(outcome);
        gate.waiting.fetch_sub(1, Ordering::SeqCst);
        Entry::Outcome(result)
    }

    /// Gets the grant `key` names through its gate, so that connections needing the same grant at once ask the person once: the one that
    /// leads runs `request` (it asks the person and requests the grant) and settles the gate, the others take its outcome. `refusal` is
    /// what the others are told when the lead went away before the grant was had: that is nothing to them, and how to request a grant
    /// themselves is.
    pub(crate) fn obtain<E: GrantFailure>(&self, key: GateKey, cancel: &CancelToken, refusal: &str, request: impl FnOnce() -> Result<GrantReceipt, E>) -> Result<(), E> {
        match self.enter(key, cancel, GATE_WAIT) {
            Entry::Lead(lease) => {
                let outcome = request();
                let for_the_others = outcome.clone().map_err(|failure| if cancel.is_cancelled() { refusal.to_string() } else { failure.sentence() });
                lease.settle(for_the_others);
                outcome.map(|_| ())
            }
            Entry::Outcome(Ok(_)) => Ok(()),
            Entry::Outcome(Err(sentence)) => Err(E::waited_on(sentence)),
        }
    }

    /// How many connections are waiting on a lead right now.
    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        locked(&self.gates).values().map(|gate| gate.waiting.load(Ordering::SeqCst)).sum()
    }

    /// Gates for a test's connector: shared by every test, which is fine while a test's grants have a project of their own.
    #[cfg(test)]
    pub fn for_tests() -> &'static GrantGates {
        static GATES: std::sync::OnceLock<GrantGates> = std::sync::OnceLock::new();
        GATES.get_or_init(GrantGates::default)
    }
}

impl Lease<'_> {
    /// How the request came out: the gate is taken down (a connection that needs the grant from now on leads anew) and everyone waiting
    /// on it gets `outcome`.
    pub fn settle(mut self, outcome: Outcome) {
        self.finish(outcome);
    }

    fn finish(&mut self, outcome: Outcome) {
        if self.settled {
            return;
        }
        self.settled = true;
        {
            let mut gates = locked(&self.gates.gates);
            if gates.get(&self.key).is_some_and(|gate| Arc::ptr_eq(gate, &self.gate)) {
                gates.remove(&self.key);
            }
        }
        *locked(&self.gate.outcome) = Some(outcome);
        self.gate.settled.notify_all();
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.finish(Err(UNSETTLED.to_string()));
    }
}

/// A failure to get a grant, as the connections that waited on its request are told of it (`GrantGates::obtain`).
pub(crate) trait GrantFailure: Clone {
    /// The sentence the connections waiting on the request are told when it failed with this.
    fn sentence(&self) -> String;
    /// The failure of a connection that waited on a request that failed with `sentence`.
    fn waited_on(sentence: String) -> Self;
}

/// A grace for a service that is slow to see a new grant: for how long after a grant became active a refusal that the grant's absence
/// may explain is tried again rather than reported (IAP can take about 1½ minutes to see a grant), and how long between tries.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Grace {
    pub span: Duration,
    pub step: Duration,
}

impl Default for Grace {
    fn default() -> Grace {
        Grace { span: Duration::from_secs(120), step: Duration::from_secs(10) }
    }
}

/// Waits `span`, looking at `cancel` every so often: `false` when the connection was cancelled meanwhile.
pub(crate) fn pause(cancel: &CancelToken, span: Duration) -> bool {
    let end = Instant::now() + span;
    loop {
        if cancel.is_cancelled() {
            return false;
        }
        let now = Instant::now();
        if now >= end {
            return true;
        }
        std::thread::sleep((end - now).min(Duration::from_millis(250)));
    }
}

/// The lead's part of a grant request: asks the person for a justification and a length (Lunport's Request-a-grant window, five
/// minutes), has `request` ask for the grant with what they answered, and tells them what was got. Cancel, no answer in time, a client
/// that went away or an answer that is not one end with `refused`. Blocks until the person has answered and the grant is had.
pub(crate) fn ask_and_request<E>(
    owner: &dyn Owner,
    prompt: &GrantPrompt,
    refused: impl FnOnce() -> E,
    request: impl FnOnce(&GrantAnswer) -> Result<GrantReceipt, E>,
) -> Result<GrantReceipt, E> {
    let answer = match owner.ask(QuestionKind::Grant, &prompt.to_text(), true, Some(Instant::now() + GRANT_QUESTION_WAIT)) {
        Reply::Answer(text) => GrantAnswer::decode(&text),
        Reply::Cancelled | Reply::TimedOut | Reply::Gone => None,
    };
    let Some(answer) = answer else { return Err(refused()) };
    let receipt = request(&answer)?;
    owner.host_key_notice(&format!(
        "Requested a {}-minute {} grant on {}; active until {}.",
        answer.minutes,
        prompt.entitlement,
        prompt.project,
        local_hhmm(receipt.active_until)
    ));
    Ok(receipt)
}

/// Requests the grant on `place` (or takes the one already in flight there: PAM refuses a second request with the same scope), waits
/// for it to become active, and answers when it was given and when it ends. `entitlement` is the id the receipt names. `remember` is
/// told once a request was made. A grant that waits for an approver is a failure: a connection does not wait for one. Blocks while it
/// polls, at most `wait`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn request_active_grant(
    gcp: &dyn GcpClient,
    place: &pam::Entitlement<'_>,
    entitlement: &str,
    justification: &str,
    duration_secs: u32,
    remember: &dyn Fn(),
    cancel: &CancelToken,
    poll_every: Duration,
    wait: Duration,
) -> Result<GrantReceipt, pam::RequestError> {
    let grant = pam::request_and_wait(gcp, place, justification, duration_secs, remember, poll_every, wait, &|| cancel.is_cancelled(), false)?;
    let (granted_at, active_until) = pam::active_span(&grant, SystemTime::now(), duration_secs);
    Ok(GrantReceipt { entitlement: entitlement.to_string(), granted_at, active_until })
}

/// The grant an account holds in flight on a route's entitlements, as a connection needs to know it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CurrentGrant {
    /// When the freshest grant in flight was given, as this computer counts it (`pam::granted_at`); `None` for a grant PAM did not date.
    pub granted_at: Option<SystemTime>,
    /// Whether it was given within `RECENT_GRANT` of `now`.
    pub recent: bool,
}

/// The first of the route's entitlements (`pam`, in `project`) that `account` holds a grant in flight on, and what the freshest of that
/// entitlement's grants says; `None` when no entitlement has one. The freshest in-flight grant dates it: one still activating, or timed
/// by a clock ahead of this one, is as fresh as `now`. Blocks on a Google call for each entitlement it looks at.
pub(crate) fn current_grant(gcp: &dyn GcpClient, account: Option<&str>, project: &str, pam: &PamCheck, now: SystemTime) -> Result<Option<CurrentGrant>, GcpError> {
    for entitlement in &pam.entitlements {
        let name = EntitlementName::in_project(project, &pam.location, entitlement).full();
        let grants = gcp.grants(account, &name)?;
        let current = pam::in_flight(&grants);
        if current.is_empty() {
            continue;
        }
        let granted_at = current.iter().filter_map(|grant| pam::granted_at(grant, now)).max();
        let recent = granted_at.is_some_and(|granted| now.duration_since(granted).map_or(true, |age| age <= RECENT_GRANT));
        return Ok(Some(CurrentGrant { granted_at, recent }));
    }
    Ok(None)
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::HostId;
    use std::time::SystemTime;

    fn key(project: &str) -> GateKey {
        GateKey { account: None, project: project.into(), location: "global".into(), entitlement: "prod-operate".into() }
    }

    fn receipt() -> GrantReceipt {
        let now = SystemTime::now();
        GrantReceipt { entitlement: "prod-operate".into(), granted_at: now, active_until: now + Duration::from_secs(1800) }
    }

    #[test]
    fn the_first_leads_the_others_wait_for_its_outcome_and_the_next_one_leads_anew() {
        let gates = GrantGates::default();
        let cancel = CancelToken::default();
        let Entry::Lead(lease) = gates.enter(key("p"), &cancel, Duration::from_secs(5)) else { panic!("the first leads") };
        let outcome = std::thread::scope(|scope| {
            let waiter = scope.spawn(|| gates.enter(key("p"), &cancel, Duration::from_secs(5)));
            let end = Instant::now() + Duration::from_secs(3);
            while gates.waiting() == 0 {
                assert!(Instant::now() < end, "the second waits");
                std::thread::sleep(Duration::from_millis(2));
            }
            lease.settle(Ok(receipt()));
            waiter.join().unwrap()
        });
        assert!(matches!(outcome, Entry::Outcome(Ok(_))));
        assert_eq!(gates.waiting(), 0);
        assert!(matches!(gates.enter(key("p"), &cancel, Duration::from_secs(5)), Entry::Lead(_)), "the gate is gone with the outcome");
        assert!(matches!(gates.enter(key("q"), &cancel, Duration::from_secs(5)), Entry::Lead(_)), "another grant has a gate of its own");
    }

    #[test]
    fn a_dropped_lease_a_cancelled_wait_and_a_long_wait_each_end_with_a_sentence() {
        let gates = GrantGates::default();
        let cancel = CancelToken::default();
        let Entry::Lead(lease) = gates.enter(key("dropped"), &cancel, Duration::from_secs(5)) else { panic!() };
        drop(lease);
        assert!(matches!(gates.enter(key("dropped"), &cancel, Duration::from_secs(5)), Entry::Lead(_)), "a dropped lease takes its gate down");
        let Entry::Lead(_lead) = gates.enter(key("slow"), &cancel, Duration::from_secs(5)) else { panic!() };
        assert!(matches!(gates.enter(key("slow"), &cancel, Duration::from_millis(20)), Entry::Outcome(Err(text)) if text == TOO_LONG));
        let cancelled = CancelToken::default();
        cancelled.cancel();
        assert!(matches!(gates.enter(key("slow"), &cancelled, Duration::from_secs(5)), Entry::Outcome(Err(text)) if text == CANCELLED));
        assert_eq!(gates.waiting(), 0);
        let _ = HostId::from("unused");
    }
}
