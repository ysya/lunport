//! Port forwarding is owned by a live SSH session, independently of shell channels.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum ForwardKind {
    Local,
    Remote,
    Dynamic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ForwardSpec {
    pub kind: ForwardKind,
    pub bind_address: String,
    /// Zero asks the listening side to allocate a free port.
    pub port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl ForwardSpec {
    pub fn validate(&self) -> Result<(), String> {
        self.bind_address
            .parse::<std::net::IpAddr>()
            .map_err(|_| "Enter an IPv4 or IPv6 listening address.")?;
        if self.kind == ForwardKind::Dynamic {
            if !self.target_host.is_empty() || self.target_port != 0 {
                return Err("A SOCKS5 tunnel chooses its destination for each connection.".into());
            }
        } else if self.target_host.is_empty()
            || self.target_host.len() > 253
            || self
                .target_host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || self.target_port == 0
        {
            return Err("Enter a destination host and a port between 1 and 65535.".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct ForwardStatus {
    pub running: bool,
    pub port: u16,
    pub connections: u32,
    /// The most recent connection error; the listener can still be running.
    pub error: Option<String>,
}

/// Stop closes the listener and its streams. Like Session, calls belong on plain threads.
pub trait Forwarder: Send + Sync {
    fn status(&self) -> ForwardStatus;
    fn stop(&self);
}
