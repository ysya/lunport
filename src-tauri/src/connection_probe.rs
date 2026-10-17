//! Explicit, bounded TCP reachability checks for saved hosts. No login, trust or credential IO.
use crate::{
    error::AppError,
    sync::{engine, record_repository as repo, record_runtime},
};
use serde::Serialize;
use std::{
    io::ErrorKind,
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::AppHandle;
use tokio::{net::TcpStream, sync::Semaphore, task::JoinSet, time::timeout};

static CHECKS: Semaphore = Semaphore::const_new(4);
const DEADLINE: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    hostname: String,
    port: u16,
    jump: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Reachable,
    Refused,
    TimedOut,
    DnsFailed,
    Failed,
    RequiresJump,
    SettingsChanged,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProbeResult {
    host_id: String,
    hostname: String,
    port: u16,
    status: ProbeStatus,
    latency_ms: Option<u64>,
    elapsed_ms: u64,
    checked_at_ms: u64,
}
fn elapsed(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn target(app: &AppHandle, id: &str) -> Result<Target, AppError> {
    engine::with_env(app, |env| {
        let state = record_runtime::snapshot(env)?.0;
        let view = repo::get_host(&state, id).map_err(|e| AppError::Other(e.to_string()))?;
        if view.group_error.is_some() {
            return Err(AppError::Other(
                "Review the host’s group settings before checking its address.".into(),
            ));
        }
        Ok(Target {
            hostname: view.effective_payload.hostname,
            port: view.effective_payload.port,
            jump: view.effective_payload.jump,
        })
    })?
}

async fn connect_addresses(addresses: Vec<SocketAddr>) -> (ProbeStatus, Option<u64>) {
    let start = Instant::now();
    let mut attempts = JoinSet::new();
    // Try both address families without letting an unreachable IPv6 route mask IPv4.
    for address in addresses.into_iter().take(8) {
        attempts.spawn(async move {
            TcpStream::connect(address).await.map(|stream| {
                drop(stream);
            })
        });
    }
    let mut refused = false;
    let mut other = false;
    while let Some(result) = attempts.join_next().await {
        match result {
            Ok(Ok(())) => return (ProbeStatus::Reachable, Some(elapsed(start))),
            Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => refused = true,
            _ => other = true,
        }
    }
    (
        if refused && !other {
            ProbeStatus::Refused
        } else {
            ProbeStatus::Failed
        },
        None,
    )
}

async fn probe(hostname: &str, port: u16) -> (ProbeStatus, Option<u64>) {
    let hostname = hostname
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(hostname);
    let work = async {
        let addresses = match tokio::net::lookup_host((hostname, port)).await {
            Ok(addresses) => addresses.take(8).collect(),
            Err(_) => return (ProbeStatus::DnsFailed, None),
        };
        connect_addresses(addresses).await
    };
    timeout(DEADLINE, work)
        .await
        .unwrap_or((ProbeStatus::TimedOut, None))
}

#[tauri::command]
pub async fn records_host_probe(app: AppHandle, host_id: String) -> Result<ProbeResult, AppError> {
    let _permit = CHECKS.try_acquire().map_err(|_| {
        AppError::Other("Four connection checks are already running. Try again shortly.".into())
    })?;
    let before = target(&app, &host_id)?;
    let start = Instant::now();
    let (mut status, mut latency_ms) = if before.jump.is_empty() {
        probe(&before.hostname, before.port).await
    } else {
        (ProbeStatus::RequiresJump, None)
    };
    if target(&app, &host_id).map_or(true, |current| current != before) {
        status = ProbeStatus::SettingsChanged;
        latency_ms = None;
    }
    Ok(ProbeResult {
        host_id,
        hostname: before.hostname,
        port: before.port,
        status,
        latency_ms,
        elapsed_ms: elapsed(start),
        checked_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn saved_port_reachability_uses_a_disposable_loopback_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = probe("127.0.0.1", port).await;
        assert_eq!(result.0, ProbeStatus::Reachable);
        assert!(result.1.is_some());
        drop(listener);
        assert_eq!(probe("127.0.0.1", port).await.0, ProbeStatus::Refused);
    }
    #[tokio::test]
    async fn a_refused_address_does_not_hide_a_reachable_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad = closed.local_addr().unwrap();
        drop(closed);
        assert_eq!(
            connect_addresses(vec![bad, good]).await.0,
            ProbeStatus::Reachable
        );
        assert_eq!(connect_addresses(vec![]).await.0, ProbeStatus::Failed);
    }
}
