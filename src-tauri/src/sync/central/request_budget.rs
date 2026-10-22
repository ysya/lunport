//! Explicit per-round network bounds, shared by account transport and OIDC HTTP.
use crate::error::AppError;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
const EXHAUSTED: &str =
    "The synchronization round reached its request or time limit; remaining data is retained.";
#[derive(Clone)]
pub(super) struct Budget(Arc<Inner>);
struct Inner {
    started: Instant,
    duration: Duration,
    limit: usize,
    used: AtomicUsize,
    refused: AtomicBool,
}
impl Budget {
    pub fn new() -> Self {
        Self::with_limits(32, Duration::from_secs(30))
    }
    fn with_limits(limit: usize, duration: Duration) -> Self {
        Self(Arc::new(Inner {
            started: Instant::now(),
            duration,
            limit,
            used: AtomicUsize::new(0),
            refused: AtomicBool::new(false),
        }))
    }
    pub(super) fn note_refusal(&self) {
        self.0.refused.store(true, Ordering::SeqCst);
    }
    pub(super) fn take_refusal(&self) -> bool {
        self.0.refused.swap(false, Ordering::SeqCst)
    }
    pub fn used(&self) -> usize {
        self.0.used.load(Ordering::SeqCst)
    }
    pub fn remaining(&self) -> Result<Duration, AppError> {
        let remaining = self.0.duration.saturating_sub(self.0.started.elapsed());
        if self.used() >= self.0.limit || remaining.is_zero() {
            return Err(AppError::Other(EXHAUSTED.into()));
        }
        Ok(remaining)
    }
    /// Reserve once immediately before starting HTTP, including failed attempts and refresh calls.
    pub fn reserve(&self) -> Result<Duration, AppError> {
        let remaining = self.remaining()?;
        self.0
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.0.limit).then_some(n + 1)
            })
            .map_err(|_| AppError::Other(EXHAUSTED.into()))?;
        Ok(remaining)
    }
    pub fn exhausted(error: &AppError) -> bool {
        error.to_string() == EXHAUSTED
    }
    #[cfg(test)]
    pub(super) fn limited(limit: usize, duration: Duration) -> Self {
        Self::with_limits(limit, duration)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clones_share_the_request_limit_and_deadline_without_resetting_it() {
        let budget = Budget::new();
        let other = budget.clone();
        for n in 0..32 {
            assert!(other.reserve().unwrap() <= Duration::from_secs(30));
            assert_eq!(budget.used(), n + 1);
        }
        assert!(Budget::exhausted(&budget.reserve().unwrap_err()));
        assert_eq!(other.used(), 32);
        let expired = Budget::limited(32, Duration::ZERO);
        assert!(Budget::exhausted(&expired.reserve().unwrap_err()));
        assert_eq!(expired.used(), 0);
    }
    #[test]
    fn actual_transport_errors_consume_a_request_and_exhaustion_starts_no_request() {
        let mut server = mockito::Server::new();
        let route = server
            .mock("GET", "/v1/info")
            .with_status(503)
            .expect(1)
            .create();
        let budget = Budget::limited(1, Duration::from_secs(30));
        let api = super::super::api::Api::bounded(&server.url(), &budget).unwrap();
        assert!(api.info().is_err());
        assert_eq!(budget.used(), 1);
        assert!(Budget::exhausted(&api.info().err().unwrap()));
        route.assert();
    }
    #[test]
    fn transport_timeout_is_capped_by_the_remaining_round_deadline() {
        use super::super::api::{DeviceSession, DeviceState};
        let mut server = mockito::Server::new();
        let route = server
            .mock("GET", "/v1/account")
            .with_body_from_request(|_| {
                std::thread::sleep(Duration::from_secs(3));
                b"{}".to_vec()
            })
            .expect(1)
            .create();
        let budget = Budget::limited(32, Duration::from_secs(2));
        let api = super::super::api::Api::bounded(&server.url(), &budget).unwrap();
        let session = DeviceSession::synthetic_for_test(
            "a".repeat(64),
            DeviceState::Active,
            1,
            Duration::from_secs(30),
        );
        assert!(api.account(&session).is_err());
        assert_eq!(budget.used(), 1);
        assert!(Budget::exhausted(&budget.remaining().unwrap_err()));
        route.assert();
    }
    #[test]
    fn oidc_and_account_http_share_one_explicit_allowance() {
        use openidconnect::SyncHttpClient;
        let mut server = mockito::Server::new();
        let route = server
            .mock("GET", "/metadata")
            .with_status(503)
            .expect(1)
            .create();
        let budget = Budget::limited(1, Duration::from_secs(30));
        let http = super::super::oidc::BoundedHttp::bounded(&budget).unwrap();
        let request = openidconnect::http::Request::builder()
            .uri(format!("{}/metadata", server.url()))
            .body(vec![])
            .unwrap();
        assert_eq!(http.call(request).unwrap().status(), 503);
        let api = super::super::api::Api::bounded(&server.url(), &budget).unwrap();
        assert!(Budget::exhausted(&api.info().err().unwrap()));
        assert_eq!(budget.used(), 1);
        route.assert();
    }
}
