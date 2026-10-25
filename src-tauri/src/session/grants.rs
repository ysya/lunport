//! One Privileged Access Manager grant request at a time for each grant that several connections may need at once (design 2026-10-25,
//! PAM grant requests). The in-app terminal reconnects every prod tab when the network returns, a saved tunnel and a tab start together:
//! the first connection to need a grant asks the person and requests it; the others wait for how that comes out instead of asking again.
//! A gate is keyed by what names the grant (account, project, location, entitlement) and lives as long as the request; a connection that
//! needs the grant after the request came out finds no gate and leads anew (a grant that is active never gets this far: `prepare` passes).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::connect::CancelToken;
use super::directory::{GrantNeed, GrantReceipt};

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
