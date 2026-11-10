use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Tauri-managed app state.
pub struct AppState {
    /// A hidden client-started host must not unlock credentials before a human opens its UI.
    pub background_credentials_only: AtomicBool,
    /// Desired menubar tray visibility; `rebuild_tray` re-applies it so a hidden tray stays hidden.
    pub tray_visible: AtomicBool,
    /// When true, closing the main window hides it to the tray instead of quitting.
    pub close_to_tray: AtomicBool,
    /// Local MCP bridge policy, pending approvals, and recent audit events.
    pub mcp: crate::mcp::McpRuntime,
    /// 同步執行期狀態:generation/狀態/帳戶金鑰同一把鎖(`SyncCore`)、lifecycle 互斥鎖、同步中旗標。
    pub sync: crate::sync::runtime::SyncRuntime,
    /// The session broker: its host key window, its sessions.
    pub session: crate::session::SessionRuntime,
    /// The one client for Google's APIs: its token cache and its library clients serve the connections and the
    /// Google Cloud panel alike, so a grant check costs one search, not a sign-in.
    pub gcp: Arc<crate::gcp::rest::RestClient>,
    /// The Cloud SQL Admin API for the databases. It signs with `gcp`'s token source, so a database connection and the Google Cloud page share
    /// one token cache.
    pub sqladmin: Arc<dyn crate::gcp::cloudsql::SqlAdmin>,
}

impl Default for AppState {
    fn default() -> Self {
        let gcp = Arc::new(crate::gcp::rest::RestClient::new(Arc::new(crate::gcp::auth::FileStore::from_environment())));
        let sqladmin = Arc::new(crate::gcp::cloudsql::RestSqlAdmin::new(gcp.tokens()));
        Self {
            background_credentials_only: AtomicBool::new(false),
            tray_visible: AtomicBool::new(true),
            close_to_tray: AtomicBool::new(false),
            mcp: crate::mcp::McpRuntime::default(),
            sync: crate::sync::runtime::SyncRuntime::default(),
            session: crate::session::SessionRuntime::default(),
            gcp,
            sqladmin,
        }
    }
}
