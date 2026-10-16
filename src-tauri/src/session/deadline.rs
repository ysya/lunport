//! Request deadlines pair a monotonic bound with UTC so suspend cannot extend a prompt.
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Copy)]
pub(crate) struct InteractionDeadline {
    pub monotonic: Instant,
    pub utc: SystemTime,
}
impl InteractionDeadline {
    pub fn after(timeout: Duration) -> Self {
        let utc = SystemTime::now() + timeout;
        Self {
            monotonic: Instant::now() + timeout,
            utc,
        }
    }
    pub fn from_instant(monotonic: Instant) -> Self {
        let utc = SystemTime::now() + monotonic.saturating_duration_since(Instant::now());
        Self { monotonic, utc }
    }
    pub fn remaining_at(self, monotonic: Instant, utc: SystemTime) -> Duration {
        self.monotonic
            .saturating_duration_since(monotonic)
            .min(self.utc.duration_since(utc).unwrap_or_default())
    }
    pub fn remaining(self) -> Duration {
        self.remaining_at(Instant::now(), SystemTime::now())
    }
    pub fn expired(self) -> bool {
        self.remaining().is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_backward_wall_clock_cannot_extend_the_monotonic_bound() {
        let now = Instant::now();
        let utc = SystemTime::now();
        let deadline = InteractionDeadline {
            monotonic: now + Duration::from_secs(120),
            utc: utc + Duration::from_secs(120),
        };
        assert!(deadline
            .remaining_at(
                now + Duration::from_secs(121),
                utc - Duration::from_secs(3600)
            )
            .is_zero());
        assert_eq!(
            deadline.remaining_at(
                now + Duration::from_secs(119),
                utc - Duration::from_secs(3600)
            ),
            Duration::from_secs(1)
        );
    }
}
