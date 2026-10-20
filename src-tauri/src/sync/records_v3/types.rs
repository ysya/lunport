use serde::{Deserialize, Serialize};

pub const HOST_SCHEMA: u32 = 2;
pub const KEYSLOT_SCHEMA: u32 = 2;
pub const ACCOUNT_SCHEMA: u32 = 4;
pub const MIN_ACCOUNT_SCHEMA: u32 = 3;
pub const GROUP_SCHEMA: u32 = 1;
pub const GROUPED_HOST_SCHEMA: u32 = 3;
pub const GROUP_STATE_VERSION: u32 = 4;
pub const NAVIGATION_STATE_VERSION: u32 = 5;
pub const STATE_VERSION: u32 = 3;
pub const LOCAL_CREDENTIAL_STATE_VERSION: u32 = 6;
pub const LOCAL_CONFLICT_STATE_VERSION: u32 = 7;
pub const CENTRAL_STATE_VERSION: u32 = 8;
pub const MAX_JUMPS: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationPhase {
    #[serde(rename = "account-gated")]
    AccountGated,
    #[serde(rename = "publishing")]
    Publishing,
    #[serde(rename = "active")]
    Active,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationGate {
    pub id: String,
    pub source_digest: String,
    pub phase: MigrationPhase,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostScope {
    Local,
    Space { space_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    Key,
    Password,
    Interactive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPayload {
    pub schema: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherit: Vec<InheritedField>,
    pub alias: String,
    pub hostname: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    pub auth: AuthKind,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub jump: Vec<String>,
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u32,
    #[serde(default = "default_missed")]
    pub keepalive_max_missed: u32,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u32,
    #[serde(default)]
    pub host_key: Option<StoredHostKey>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub imported: Option<ImportedSettings>,
}

fn default_port() -> u16 {
    22
}
fn default_keepalive() -> u32 {
    30
}
fn default_missed() -> u32 {
    3
}
fn default_connect_timeout() -> u32 {
    15
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecord {
    pub id: String,
    pub scope: HostScope,
    pub payload: HostPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredHostKey {
    pub algorithm: String,
    /// SSH public key blob, base64 encoded (not an OpenSSH public key line).
    pub public_key: String,
    pub fingerprint: String,
    pub pinned_at_ms: u64,
    pub pinned_by_device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedSettings {
    pub source: String,
    pub at_ms: u64,
    pub unsupported: Vec<UnsupportedSetting>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedSetting {
    pub keyword: String,
    pub value: String,
    /// Old previews did not distinguish harmless annotations: conservatively require review.
    #[serde(default = "requires_review")]
    pub requires_review: bool,
}
fn requires_review() -> bool {
    true
}

/// Account metadata is authoritative. The private key retains the existing sealed key transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySlotPayload {
    pub schema: u32,
    pub name: String,
    /// A complete OpenSSH public key line.
    pub public_key: String,
    pub fingerprint: String,
    pub key_type: String,
    pub has_passphrase: bool,
    pub created_at_ms: u64,
    pub origin_device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypedRecord<T> {
    Live(T),
    Tombstone { id: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionReadiness {
    Ready,
    NeedsKey(String),
    NeedsReview,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordValidationError {
    UnsupportedSchema {
        kind: &'static str,
        found: u32,
    },
    Invalid {
        field: &'static str,
        id: String,
        reason: String,
    },
    Decode {
        kind: &'static str,
        reason: String,
    },
    WrongKind {
        expected: &'static str,
        found: String,
    },
    DuplicateId(String),
    AliasConflict {
        alias: String,
        scope: HostScope,
    },
    AmbiguousAlias(String),
    HostNotFound(String),
    MissingJump {
        host_id: String,
        jump_id: String,
    },
    JumpCycle(String),
    RepeatedJump {
        host_id: String,
        jump_id: String,
    },
    JumpDepth(String),
    PublicKeyMismatch(String),
    MigrationCollision {
        id: String,
        first: String,
        second: String,
    },
}

impl std::fmt::Display for RecordValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RecordValidationError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InheritedField {
    Port,
    User,
    Authentication,
    Jump,
    KeepaliveSecs,
    KeepaliveMaxMissed,
    ConnectTimeoutSecs,
}
impl InheritedField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::User => "user",
            Self::Authentication => "authentication",
            Self::Jump => "jump",
            Self::KeepaliveSecs => "keepalive_secs",
            Self::KeepaliveMaxMissed => "keepalive_max_missed",
            Self::ConnectTimeoutSecs => "connect_timeout_secs",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupAuthentication {
    pub auth: AuthKind,
    pub key_id: Option<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDefaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<GroupAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_max_missed: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPayload {
    pub schema: u32,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub defaults: GroupDefaults,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRecord {
    pub id: String,
    pub scope: HostScope,
    pub payload: GroupPayload,
}
