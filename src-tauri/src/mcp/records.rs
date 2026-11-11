//! Records execution service shared by the OS-authenticated broker and native UI.
use super::*;
use crate::session::{
    auth::{KeyStore, Owner},
    connect::{CancelToken, Connector, HostKeyConfirmer, HostKeyDecision, HostKeyQuestion},
    protocol::{AiAsker, HostQuery, Unreviewed},
};
#[cfg(test)]
use crate::session::{auth::Reply, protocol::QuestionKind};
use crate::ssh::{
    AuthMethod, AuthSource, ConnectError, Ended, HostKeyPolicy, Session, SshEngine, Target,
};
use super::activity::{reason_text, review_of, stop_for, Declines, NotingOwner};

#[derive(Default)]
pub(super) struct AuditLog {
    pub path: Option<PathBuf>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RequestContext {
    pub id: String,
    pub requested_by: Vec<String>,
    pub requester_id: Option<String>,
    pub client_info: McpClientInfo,
}
impl RequestContext {
    pub fn from_peer(pid: Option<u32>, info: Option<&Value>) -> Self {
        let own = std::env::current_exe()
            .ok()
            .map(|p| std::fs::canonicalize(&p).unwrap_or(p));
        let program = pid.and_then(|pid| {
            crate::ipc::peer::identify(&crate::session::broker::without_own_executable(
                crate::ipc::peer::process_chain(pid),
                own.as_deref(),
            ))
        });
        Self {
            id: String::new(),
            requested_by: program
                .as_ref()
                .map(|p| p.chain.clone())
                .unwrap_or_else(|| vec!["Unknown".into()]),
            requester_id: program.map(|p| p.identity),
            client_info: McpClientInfo::sanitize(info),
        }
    }
}

/// Public identity captured independently of the mutable key ID. Pins may legitimately be added by this connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedTarget {
    target: Target,
    keys: Vec<(String, Vec<u8>)>,
}
impl ApprovedTarget {
    pub fn capture(target: &Target, keys: &dyn KeyStore) -> Result<Self, String> {
        let mut target = target.clone();
        let mut identities = Vec::new();
        for hop in &mut target.hops {
            hop.pinned = None;
            if let AuthMethod::Key { key_id } = &hop.auth {
                let key = keys.key(key_id).ok_or("The approved key is unavailable.")?;
                let public = crate::ssh::HostKey::from_openssh_line(&key.public_key)
                    .ok_or("The approved key identity is invalid.")?;
                identities.push((key_id.clone(), public.public_key));
            }
        }
        Ok(Self {
            target,
            keys: identities,
        })
    }
    pub fn check(&self, connector: &Connector<'_>, query: &HostQuery) -> Result<(), String> {
        let target = connector
            .directory
            .resolve_public(query)
            .map_err(|e| e.to_string())?;
        self.check_resolved(&target, connector.keys)
    }
    /// Bind the exact snapshot returned by resolution, not another read of current state.
    pub(crate) fn check_resolved(
        &self,
        target: &Target,
        keys: &dyn KeyStore,
    ) -> Result<(), String> {
        self.check_identity(Self::capture(target, keys)?)
    }
    /// Connector may learn pins and, after a human password answer, retry Interactive as Password.
    /// Initial resolution is checked strictly before those connector-owned adaptations are allowed.
    pub(crate) fn check_connected(
        &self,
        target: &Target,
        keys: &dyn KeyStore,
    ) -> Result<(), String> {
        let mut actual = Self::capture(target, keys)?;
        for (actual_hop, approved_hop) in actual.target.hops.iter_mut().zip(&self.target.hops) {
            if approved_hop.auth == AuthMethod::Interactive
                && actual_hop.auth == AuthMethod::Password
            {
                actual_hop.auth = AuthMethod::Interactive;
            }
        }
        self.check_identity(actual)
    }
    fn check_identity(&self, actual: Self) -> Result<(), String> {
        if *self != actual {
            return Err(
                "The approved destination, route or key changed; request approval again.".into(),
            );
        }
        Ok(())
    }
}
/// What ended a server key question of an AI client's call without trust, for the client's answer. Each names the host
/// by its alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KeyOutcome {
    /// The person refused the key (Cancel, Refuse) or closed the window; `changed`: the window showed it as a changed key.
    Refused { alias: String, changed: bool },
    /// Nobody answered the window before it gave up.
    Unanswered { alias: String, changed: bool },
}

impl KeyOutcome {
    /// The client's answer; `stopped` says what did not happen when the call ends here ("the command did not run").
    pub(crate) fn sentence(&self, stopped: Option<&str>) -> String {
        let tail = stopped.map(|stopped| format!(" and {stopped}")).unwrap_or_default();
        let key = |alias: &str, changed: bool| format!("{}server key of {alias}", if changed { "changed " } else { "" });
        match self {
            KeyOutcome::Refused { alias, changed } => {
                format!("The {} was denied in Lunport's trust window; nothing was saved{tail}.", key(alias, *changed))
            }
            KeyOutcome::Unanswered { alias, changed } => format!(
                "Lunport's trust window for the {} timed out after {} minutes; nothing was saved{tail}.",
                key(alias, *changed),
                crate::session::hostkey_window::HOSTKEY_TIMEOUT.as_secs() / 60
            ),
        }
    }
}

/// What `ssh_exec` says when a server key question stopped it.
const COMMAND_STOPPED: &str = "the command did not run";

/// The AI client as Lunport observed it (the requester chain), never what the client says of itself: who started a tunnel in the Tunnels
/// panel, and who asks in Lunport's windows.
pub(crate) fn client_label(context: &RequestContext) -> String {
    let observed: Vec<&str> = context.requested_by.iter().map(String::as_str).filter(|name| *name != "Unknown").collect();
    if observed.is_empty() {
        "An unidentified AI client".into()
    } else {
        observed.join(" → ")
    }
}

/// Who asks in Lunport's windows for an AI client's request in `mode`: the client, and in Auto-log what goes ahead without per-command
/// review once the person agrees (`then`).
pub(crate) fn asker(context: &RequestContext, mode: ApprovalMode, then: Unreviewed) -> AiAsker {
    AiAsker { client: client_label(context), unreviewed: (mode == ApprovalMode::AutoLog).then_some(then) }
}

/// Lunport's host key window as an AI client's call asks it: every question goes to the window, a changed key in
/// Auto-log too, and names the client (`asker`). The connect path asks a key that differs from the one
/// another device saved for the host (a pin this device has not approved yet) as a changed key. It remembers the first question that ended
/// without trust, for the client's answer.
pub(crate) struct ClientConfirmer<'a> {
    window: &'a dyn HostKeyConfirmer,
    asker: AiAsker,
    outcome: Mutex<Option<KeyOutcome>>,
}
impl<'a> ClientConfirmer<'a> {
    pub(crate) fn new(window: &'a dyn HostKeyConfirmer, asker: AiAsker) -> Self {
        Self { window, asker, outcome: Mutex::new(None) }
    }
    /// The client's answer when a question ended without trust (`stopped`: what did not happen); `None` when none did.
    pub(crate) fn answer(&self, stopped: Option<&str>) -> Option<String> {
        self.outcome.lock().unwrap().as_ref().map(|outcome| outcome.sentence(stopped))
    }
    /// The first question that ended without trust, as the activity page shows what stopped the request: refused, or not answered.
    pub(crate) fn declined(&self) -> Option<(McpStopKind, McpWindow)> {
        self.outcome.lock().unwrap().as_ref().map(|outcome| match outcome {
            KeyOutcome::Refused { .. } => (McpStopKind::Refused, McpWindow::ServerKey),
            KeyOutcome::Unanswered { .. } => (McpStopKind::NoAnswer, McpWindow::ServerKey),
        })
    }
    fn note(&self, outcome: KeyOutcome) {
        self.outcome.lock().unwrap().get_or_insert(outcome);
    }
}
impl HostKeyConfirmer for ClientConfirmer<'_> {
    fn confirm(&self, question: &HostKeyQuestion, cancel: &CancelToken) -> Option<String> {
        match self.decide(question, cancel) {
            HostKeyDecision::Trusted(fingerprint) => Some(fingerprint),
            HostKeyDecision::Refused | HostKeyDecision::Unanswered => None,
        }
    }
    fn decide(&self, question: &HostKeyQuestion, cancel: &CancelToken) -> HostKeyDecision {
        let alias = crate::session::auth::printable(&question.alias).replace(['\n', '\t'], "?");
        let changed = question.changed.is_some();
        let asked = HostKeyQuestion { ai: Some(self.asker.clone()), ..question.clone() };
        let decision = self.window.decide(&asked, cancel);
        match decision {
            HostKeyDecision::Trusted(_) => {}
            HostKeyDecision::Refused => self.note(KeyOutcome::Refused { alias, changed }),
            // Withdrawn because the client went away: the call is cancelled, not timed out.
            HostKeyDecision::Unanswered if cancel.is_cancelled() => {}
            HostKeyDecision::Unanswered => self.note(KeyOutcome::Unanswered { alias, changed }),
        }
        decision
    }
}

/// `verify_host_key`'s handshake for the host `query` names, along `route` (the route the request was approved for): Lunport's host key
/// window for each hop whose key needs the person, the pin written on trust, and no login to the destination (jump hosts log in).
/// `ssh_exec` and `start_tunnel` run it before they use a server key this device has not verified. `guard` is the request's
/// own check (its policy and permission); every route the handshake resolves must be `route`, its destination only met.
pub(crate) fn verify_route(
    connector: &Connector<'_>,
    query: &HostQuery,
    route: &Target,
    owner: &dyn Owner,
    cancel: &CancelToken,
    guard: &(dyn Fn() -> Result<(), String> + Sync),
    confirmer: &dyn HostKeyConfirmer,
) -> Result<crate::session::verify::VerifiedHostKey, String> {
    // The route as `resolve_host_key` gives it: the destination is met, never logged in to.
    let mut met = route.clone();
    if let Some(destination) = met.hops.last_mut() {
        destination.auth = AuthMethod::Interactive;
    }
    let approved = ApprovedTarget::capture(&met, connector.keys)?;
    let check = || {
        guard()?;
        let current = connector.directory.resolve_host_key(query).map_err(|e| e.to_string())?;
        approved.check_resolved(&current, connector.keys)
    };
    let check_resolved = |target: &Target| approved.check_resolved(target, connector.keys);
    let directory = PublicDirectory(connector.directory, &check, &check_resolved);
    let probe = Connector {
        directory: &directory,
        engine: connector.engine,
        keys: connector.keys,
        keychain: connector.keychain,
        confirmer,
        grants: connector.grants,
    };
    check()?;
    let verified = crate::session::verify::verify_for_ai(&probe, query, owner, cancel)?;
    check()?;
    Ok(verified)
}

/// The audit entry of a trust decision an AI client's request asked for, as `verify_host_key` writes it: the handshake started at `at_ms`,
/// and `stop` is what kept the key from being trusted (`None`: it was verified). No approval window reviews it; the trust window is the
/// person's decision.
pub(crate) fn trust_entry(
    context: &RequestContext,
    host_id: &str,
    alias: &str,
    mode: ApprovalMode,
    at_ms: u64,
    stop: Option<McpStop>,
) -> McpAuditEntry {
    McpAuditEntry {
        at_ms,
        completed_at_ms: unix_ms(),
        id: context.id.clone(),
        client: "mcp".into(),
        host_id: Some(host_id.into()),
        alias: alias.into(),
        mode,
        requested_by: context.requested_by.clone(),
        requester_id: context.requester_id.clone(),
        client_info: context.client_info.clone(),
        outcome: if stop.is_none() { "host_key_verified" } else { "host_key_not_verified" }.into(),
        review: Some(McpReview::NotAsked),
        stop,
        ..Default::default()
    }
}

/// Before an AI client's call connects through a hop whose server key this device has not verified, the person
/// decides on it in Lunport's host key window, as `verify_host_key` asks: no credential for the destination is asked before that. The
/// hops are those of `target`, the route the request was approved for, and their keys are looked at as they are now (the person may
/// have verified one while an approval was open). The decision is audited; `declines` holds the credential and grant questions `owner`
/// noted, for what stopped it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_unverified(
    runtime: &McpRuntime,
    connector: &Connector<'_>,
    query: &HostQuery,
    target: &Target,
    owner: &dyn Owner,
    declines: &Declines,
    cancel: &CancelToken,
    guard: &(dyn Fn() -> Result<(), String> + Sync),
    confirmer: &ClientConfirmer<'_>,
    audit: (&RequestContext, ApprovalMode),
    stopped: &str,
) -> Result<(), String> {
    let unverified = || -> Result<bool, String> {
        for hop in &target.hops {
            if connector.directory.pinned_for(&hop.reference()).map_err(|e| e.to_string())?.is_none() {
                return Ok(true);
            }
        }
        Ok(false)
    };
    if !unverified()? {
        return Ok(());
    }
    let (context, mode) = audit;
    let destination = target.hops.last().ok_or("No destination.")?;
    let started = unix_ms();
    let verified = verify_route(connector, query, target, owner, cancel, guard, confirmer);
    let stop = verified.as_ref().err().map(|error| {
        stop_for(error, None, declines.first().or_else(|| confirmer.declined()), runtime.withdrawn(mode, cancel))
    });
    runtime.record(trust_entry(context, destination.id.as_str(), &destination.alias, mode, started, stop));
    verified.map_err(|error| confirmer.answer(Some(stopped)).unwrap_or(error))?;
    // A key that is not verified by the time the call connects (another device changed the pin in between) is the connection's to ask
    // about, in its own window, in both modes.
    Ok(())
}
pub(crate) struct CheckedEngine<'a> {
    pub(crate) inner: &'a dyn SshEngine,
    pub(crate) check: &'a (dyn Fn(&Target) -> Result<(), String> + Sync),
}
impl SshEngine for CheckedEngine<'_> {
    fn connect(
        &self,
        t: &Target,
        p: &dyn HostKeyPolicy,
        a: &dyn AuthSource,
    ) -> Result<Box<dyn Session>, ConnectError> {
        (self.check)(t).map_err(|reason| ConnectError::BadJumpChain { why: reason })?;
        self.inner.connect(t, p, a)
    }
}

/// Uses public resolution; private material is verified by KeyStore immediately before authentication. A Privileged Access Manager grant
/// the target needs is passed on, so that the connection asks for it in Lunport's window, for an AI client's request too.
pub(crate) struct PublicDirectory<'a>(
    pub(crate) &'a dyn crate::session::directory::HostDirectory,
    pub(crate) &'a (dyn Fn() -> Result<(), String> + Sync),
    pub(crate) &'a (dyn Fn(&Target) -> Result<(), String> + Sync),
);
impl crate::session::directory::HostDirectory for PublicDirectory<'_> {
    fn resolve_host_key(
        &self,
        q: &HostQuery,
    ) -> Result<Target, crate::session::directory::DirectoryError> {
        let target = self.0.resolve_host_key(q)?;
        (self.2)(&target).map_err(crate::session::directory::DirectoryError::Failed)?;
        Ok(target)
    }
    fn resolve(&self, q: &HostQuery) -> Result<Target, crate::session::directory::DirectoryError> {
        let target = self.0.resolve_public(q)?;
        (self.2)(&target).map_err(crate::session::directory::DirectoryError::Failed)?;
        Ok(target)
    }
    fn pinned(
        &self,
        h: &crate::ssh::HostId,
    ) -> Result<
        Option<crate::session::directory::PinnedKey>,
        crate::session::directory::DirectoryError,
    > {
        self.0.pinned(h)
    }
    fn pin(
        &self,
        h: &crate::ssh::HostId,
        k: &crate::ssh::HostKey,
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.pin(h, k)
    }
    fn replace_pin(
        &self,
        h: &crate::ssh::HostId,
        p: &crate::ssh::HostKey,
        k: &crate::ssh::HostKey,
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.replace_pin(h, p, k)
    }
    fn pinned_for(
        &self,
        h: &crate::ssh::HopRef,
    ) -> Result<
        Option<crate::session::directory::PinnedKey>,
        crate::session::directory::DirectoryError,
    > {
        self.0.pinned_for(h)
    }
    fn saved_for(
        &self,
        h: &crate::ssh::HopRef,
    ) -> Result<
        Option<crate::session::directory::PinnedKey>,
        crate::session::directory::DirectoryError,
    > {
        self.0.saved_for(h)
    }
    fn pin_for(
        &self,
        h: &crate::ssh::HopRef,
        k: &crate::ssh::HostKey,
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.pin_for(h, k)
    }
    fn replace_pin_for(
        &self,
        h: &crate::ssh::HopRef,
        p: &crate::ssh::HostKey,
        k: &crate::ssh::HostKey,
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.replace_pin_for(h, p, k)
    }
    fn pin_confirmed(
        &self,
        hop: &crate::ssh::HopRef,
        previous: Option<&crate::ssh::HostKey>,
        key: &crate::ssh::HostKey,
        cancel: &CancelToken,
        guard: &(dyn Fn() -> Result<(), crate::session::directory::DirectoryError> + Sync),
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.pin_confirmed(hop, previous, key, cancel, &|| {
            guard()?;
            (self.1)().map_err(crate::session::directory::DirectoryError::Failed)
        })
    }
    fn password_authorized(&self, hop: &crate::ssh::HopRef, server_key: Option<&crate::ssh::HostKey>) -> Result<bool, crate::session::directory::DirectoryError> {
        (self.1)().map_err(crate::session::directory::DirectoryError::Failed)?;
        self.0.password_authorized(hop, server_key)
    }
    fn saved_password(&self, hop:&crate::ssh::HopRef, keychain:&dyn crate::sync::env::Keychain)->Result<Option<crate::ssh::Secret>,crate::session::directory::DirectoryError>{
        (self.1)().map_err(crate::session::directory::DirectoryError::Failed)?;
        let password=self.0.saved_password(hop,keychain)?;
        (self.1)().map_err(crate::session::directory::DirectoryError::Failed)?;
        Ok(password)
    }
    fn password_account(&self, h: &crate::ssh::HostId) -> String {
        self.0.password_account(h)
    }
    fn prepare(&self, target: &Target, public_key: &dyn Fn(&str) -> Option<String>, cancel: &CancelToken) -> Result<crate::session::directory::Prepared, crate::session::directory::DirectoryError> {
        self.0.prepare(target, public_key, cancel)
    }
    fn request_grant(&self, need: &crate::session::directory::GrantNeed, justification: &str, duration_secs: u32, cancel: &CancelToken) -> Result<crate::session::directory::GrantReceipt, crate::session::directory::DirectoryError> {
        (self.1)().map_err(crate::session::directory::DirectoryError::Failed)?;
        self.0.request_grant(need, justification, duration_secs, cancel)
    }
}

#[cfg(test)]
pub(super) fn execute(
    runtime: &McpRuntime,
    connector: &Connector<'_>,
    alias: &str,
    command: &str,
    timeout: u64,
    cancel: &CancelToken,
    owner: &dyn Owner,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    execute_context(
        runtime,
        connector,
        alias,
        command,
        timeout,
        cancel,
        owner,
        approve,
        RequestContext::default(),
        &ensure_allowed,
    )
}
pub(super) fn execute_context(
    runtime: &McpRuntime,
    connector: &Connector<'_>,
    alias: &str,
    command: &str,
    timeout: u64,
    cancel: &CancelToken,
    owner: &dyn Owner,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    mut context: RequestContext,
    authorize: &(dyn Fn(&McpPolicy, &str) -> Result<(), String> + Sync),
) -> Result<Value, String> {
    if !display_safe_command(command) {
        return Err("Command is empty, unsafe to display, or exceeds 16384 bytes.".into());
    }
    if !(1..=300).contains(&timeout) {
        return Err("timeout_seconds must be an integer from 1 to 300.".into());
    }
    if cancel.is_cancelled() {
        return Err("MCP request was canceled".into());
    }
    let target = connector
        .directory
        .resolve_public(&HostQuery::Id(alias.into()))
        .or_else(|_| {
            connector
                .directory
                .resolve_public(&HostQuery::Alias(alias.into()))
        })
        .map_err(|e| e.to_string())?;
    let destination = target.hops.last().ok_or("No destination.")?;
    let host_id = destination.id.as_str().to_string();
    let query = HostQuery::Id(host_id.clone());
    let approved = ApprovedTarget::capture(&target, connector.keys)?;
    let policy = runtime.policy.lock().unwrap().clone();

    if context.id.is_empty() {
        context.id = format!(
            "records-{}",
            runtime.next_request_id.fetch_add(1, Ordering::Relaxed)
        );
    }
    struct Active<'a> {
        runtime: &'a McpRuntime,
        id: String,
    }
    impl Drop for Active<'_> {
        fn drop(&mut self) {
            self.runtime.records_active.lock().unwrap().remove(&self.id);
        }
    }
    {
        let mut active = runtime.records_active.lock().unwrap();
        if active.contains_key(&context.id) {
            return Err("duplicate MCP request id".into());
        }
        active.insert(context.id.clone(), (host_id.clone(), cancel.clone()));
    }
    let _active = Active {
        runtime,
        id: context.id.clone(),
    };
    let request = McpPendingRequest {
        host_proposal: None,
        id: context.id.clone(),
        alias: destination.alias.clone(),
        host_id: Some(host_id.clone()),
        command: command.into(),
        hostname: Some(destination.hostname.clone()),
        user: Some(destination.user.clone()),
        port: Some(destination.port.to_string()),
        route: target
            .hops
            .iter()
            .map(|h| format!("{}@{}:{} ({})", h.user, h.hostname, h.port, h.alias))
            .collect(),
        requested_by: context.requested_by.clone(),
        requester_id: context.requester_id.clone(),
        client_info: context.client_info.clone(),
        requested_at_ms: unix_ms(),
    };
    let mode = policy.approval_mode;
    let check = || {
        if cancel.is_cancelled() {
            return Err("MCP request was canceled".into());
        }
        let current = runtime.policy.lock().unwrap().clone();
        if !current.enabled || current.approval_mode != mode {
            return Err("MCP policy changed; request approval again.".into());
        }
        authorize(&current, &host_id)?;
        approved.check(connector, &query)
    };
    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let done = AtomicBool::new(false);
    // A request the policy already denies is audited as denied, never as canceled by the watcher.
    let allowed = policy.enabled && authorize(&policy, &host_id).is_ok();
    // What the request's windows decided, for its audit entry: the approval window's decision, the credential and grant questions the
    // person declined or left unanswered, and the server key questions.
    let mut decision = None;
    let declines = Declines::default();
    let owner = NotingOwner { inner: owner, declines: &declines };
    let confirmer = ClientConfirmer::new(connector.confirmer, asker(&context, mode, Unreviewed::Command));
    let result = std::thread::scope(|scope| {
        // Revoke/disable and disconnect wake native authentication and approval while the worker waits.
        scope.spawn(|| {
            while allowed && !done.load(Ordering::SeqCst) {
                let p = runtime.policy.lock().unwrap().clone();
                if !p.enabled || p.approval_mode != mode || authorize(&p, &host_id).is_err()
                {
                    cancel.cancel();
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let _stop = Stop(&done);
        let result = (|| {
            if !policy.enabled || authorize(&policy, &host_id).is_err() {
                return Err("MCP request was denied by host policy".into());
            }
            if mode == ApprovalMode::Ask {
                let decided = approve(&request);
                decision = Some(decided);
                match decided {
                    ApprovalDecision::Allow => {}
                    ApprovalDecision::Deny => return Err("MCP request was denied".into()),
                    ApprovalDecision::TimedOut => return Err("MCP approval timed out".into()),
                    ApprovalDecision::Cancel => {
                        cancel.cancel();
                        return Err("MCP request was canceled".into());
                    }
                }
            }
            check()?;
            verify_unverified(runtime, connector, &query, &target, &owner, &declines, cancel, &check, &confirmer, (&context, mode), COMMAND_STOPPED)?;
            let check_resolved = |actual: &Target| approved.check_resolved(actual, connector.keys);
            let check_connected = |actual: &Target| {
                check()?;
                approved.check_connected(actual, connector.keys)
            };
            let engine = CheckedEngine {
                inner: connector.engine,
                check: &check_connected,
            };
            let directory = PublicDirectory(connector.directory, &check, &check_resolved);
            let guarded = Connector {
                engine: &engine,
                confirmer: &confirmer,
                keys: connector.keys,
                keychain: connector.keychain,
                directory: &directory,
                grants: connector.grants,
            };
            let connected = guarded
                .connect(&query, &owner, cancel)
                .map_err(|e| confirmer.answer(Some(COMMAND_STOPPED)).unwrap_or(e.text))?;
            if let Some(answer) = confirmer.answer(Some(COMMAND_STOPPED)) {
                connected.session.close();
                return Err(answer);
            }
            if let Err(error) = check_connected(&connected.target) {
                connected.session.close();
                return Err(error);
            }
            let over = AtomicBool::new(false);
            let output = std::thread::scope(|scope| {
                scope.spawn(|| {
                    while !over.load(Ordering::SeqCst) {
                        if cancel.is_cancelled() {
                            connected.session.close();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                });
                let _stop = Stop(&over);
                let output =
                    connected
                        .session
                        .exec(command, Duration::from_secs(timeout), 128 * 1024);
                over.store(true, Ordering::SeqCst);
                output
            });
            connected.session.close();
            if cancel.is_cancelled() && output.is_err() {
                return Ok(
                    json!({"stdout":"","stderr":"","ended":"canceled","exit_code":null,"signal":null,"truncated":false}),
                );
            }
            let output =
                output.map_err(|_| "Remote execution failed; it was not retried.".to_string())?;
            Ok(
                json!({"stdout":String::from_utf8_lossy(&output.stdout),"stderr":String::from_utf8_lossy(&output.stderr),"ended":if cancel.is_cancelled(){"canceled"}else{match output.ended {Ended::Exited=>"exited",Ended::Signaled=>"signaled",Ended::TimedOut=>"timed_out",Ended::Truncated=>"truncated",Ended::Disconnected=>"disconnected"}},"exit_code":output.exit_code,"signal":output.signal,"truncated":output.truncated}),
            )
        })();
        done.store(true, Ordering::SeqCst);
        result
    });
    let value = result.as_ref().ok();
    let review = if !allowed {
        None
    } else if mode == ApprovalMode::AutoLog {
        Some(McpReview::AutoLog)
    } else {
        decision.and_then(review_of)
    };
    let stop = match &result {
        Ok(_) => None,
        Err(error) if !allowed => Some(McpStop { kind: McpStopKind::NotAllowed, window: None, reason: Some(reason_text(error)) }),
        Err(error) => Some(stop_for(error, decision, declines.first().or_else(|| confirmer.declined()), runtime.withdrawn(mode, cancel))),
    };
    runtime.record(McpAuditEntry {
        id: context.id,
        alias: destination.alias.clone(),
        command: command.into(),
        client: "mcp".into(),
        host_id: Some(host_id),
        mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        at_ms: request.requested_at_ms,
        completed_at_ms: unix_ms(),
        outcome: if cancel.is_cancelled() {
            "canceled"
        } else if result.is_ok() {
            "allowed"
        } else if result
            .as_ref()
            .err()
            .is_some_and(|e: &String| e.contains("timed out"))
        {
            "timed_out"
        } else if result
            .as_ref()
            .err()
            .is_some_and(|e: &String| e.contains("denied"))
        {
            "denied"
        } else {
            "error"
        }
        .into(),
        ended: value.and_then(|v| v["ended"].as_str().map(str::to_owned)),
        exit_code: value
            .and_then(|v| v["exit_code"].as_u64())
            .and_then(|n| i64::try_from(n).ok()),
        signal: value.and_then(|v| v["signal"].as_str().map(str::to_owned)),
        detail: None,
        review,
        stop,
        ..Default::default()
    });
    match result {
        Ok(mut value) => {
            if let Some(error) = runtime.audit.lock().unwrap().error.clone() {
                value["audit_error"] = json!(error);
            }
            Ok(value)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::grants::GrantGates;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::{
        fake::{default_server_key, FakeEngine, FakeEvent},
        AuthMethod, Ended, ExecResult,
    };
    use crate::sync::testkit::MemKeychain;

    /// An AI request that needs a Privileged Access Manager grant asks for one in Lunport's Request-a-grant window, in both modes:
    /// the grant is requested with the person's justification and length, and the command
    /// runs once it is active.
    #[test]
    fn an_ai_request_asks_for_a_grant_in_lunports_window_and_runs_once_it_is_active() {
        use crate::session::testing::{grant_answer, grant_need, NeedsGrant};
        for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
            let runtime = McpRuntime::default();
            {
                let mut policy = runtime.policy.lock().unwrap();
                policy.enabled = true;
                policy.approval_mode = mode;
                policy.allowed_hosts.insert("id-web".into());
            }
            let engine = FakeEngine::new();
            let inner = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
            let directory = NeedsGrant::new(&inner, grant_need("web", "acme-exec-302030"));
            let owner = FakeOwner::typing(&[&grant_answer(45, "restart app-api after the deploy")]);
            let connector = Connector {
                engine: &engine,
                directory: &directory,
                keys: &FakeKeys::new(),
                keychain: &MemKeychain::default(),
                confirmer: &FakeConfirmer::default(),
                grants: GrantGates::for_tests(),
            };
            let output = execute(&runtime, &connector, "id-web", "uptime", 60, &CancelToken::default(), &owner, &|_| ApprovalDecision::Allow).unwrap();
            assert_eq!(output["ended"], "exited", "{mode:?}");
            assert_eq!(owner.asked().iter().map(|asked| asked.kind).collect::<Vec<_>>(), [QuestionKind::Grant], "{mode:?}");
            assert_eq!(directory.requested(), [("restart app-api after the deploy".to_string(), 45 * 60)], "{mode:?}");
        }
    }

    /// Cancel in the Request-a-grant window, or no answer, ends an AI request with the refusal that names the gcloud command: no grant is
    /// requested and nothing connects.
    #[test]
    fn a_grant_the_person_does_not_request_ends_an_ai_request_with_the_refusal() {
        use crate::session::testing::{grant_need, NeedsGrant};
        let runtime = McpRuntime::default();
        runtime.policy.lock().unwrap().enabled = true;
        runtime.policy.lock().unwrap().allowed_hosts.insert("id-web".into());
        let engine = FakeEngine::new();
        let inner = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let directory = NeedsGrant::new(&inner, grant_need("web", "acme-cancel-302040"));
        let owner = FakeOwner::default();
        let connector = Connector {
            engine: &engine,
            directory: &directory,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
            grants: GrantGates::for_tests(),
        };
        let error = execute(&runtime, &connector, "id-web", "uptime", 60, &CancelToken::default(), &owner, &|_| ApprovalDecision::Allow).unwrap_err();
        assert_eq!(error, grant_need("web", "acme-cancel-302040").refusal_sentence());
        assert_eq!(owner.asked().iter().map(|asked| asked.kind).collect::<Vec<_>>(), [QuestionKind::Grant]);
        assert!(directory.requested().is_empty(), "no grant was requested");
        assert!(!engine.events().iter().any(|event| matches!(event, FakeEvent::Connect { .. })), "nothing connected");
    }

    #[test]
    fn allowed_id_executes_without_pty_and_preserves_disconnected_null_status() {
        let runtime = McpRuntime::default();
        runtime.policy.lock().unwrap().enabled = true;
        runtime
            .policy
            .lock()
            .unwrap()
            .allowed_hosts
            .insert("id-web".into());
        let engine = FakeEngine::new().with_exec(
            "uptime",
            ExecResult {
                ended: Ended::Disconnected,
                exit_code: None,
                signal: None,
                stdout: b"partial".to_vec(),
                stderr: vec![],
                truncated: false,
            },
        );
        let directory = FakeDirectory::new()
            .with_host(
                "web",
                AuthMethod::Key {
                    key_id: "k-plain".into(),
                },
            )
            .with_pin("web", default_server_key());
        let keys = FakeKeys::new();
        let keychain = MemKeychain::default();
        let confirmer = FakeConfirmer::default();
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &directory,
            keys: &keys,
            keychain: &keychain,
            confirmer: &confirmer,
        };
        let value = execute(
            &runtime,
            &connector,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| ApprovalDecision::Allow,
        )
        .unwrap();
        assert_eq!(value["ended"], "disconnected");
        assert!(value["exit_code"].is_null());
        assert!(engine.events().contains(&FakeEvent::Exec {
            command: "uptime".into(),
            timeout: Duration::from_secs(60),
            output_cap: 128 * 1024
        }));
        assert!(!engine
            .events()
            .iter()
            .any(|e| matches!(e, FakeEvent::ShellOpened { .. })));
    }
}

pub(super) fn validate_method(method: &str) -> Result<(), String> {
    if method == "run" {
        Err("run was renamed to ssh_exec".into())
    } else if matches!(
        method,
        "list_hosts"
            | "get_host"
            | "get_effective_config"
            | "ssh_exec"
            | "scp_upload"
            | "scp_download"
            | "create_host"
            | "verify_host_key"
            | "update_host"
            | "set_transport"
            | "remove_transport"
            | "list_tunnels"
            | "create_tunnel"
            | "update_tunnel"
            | "delete_tunnel"
            | "start_tunnel"
            | "stop_tunnel"
            | "list_databases"
            | "create_database"
            | "update_database"
            | "delete_database"
            | "start_database"
            | "stop_database"
    ) {
        Ok(())
    } else {
        Err("Unknown MCP method".into())
    }
}

pub(crate) fn dispatch(
    app: &AppHandle,
    connector: &Connector<'_>,
    method: &str,
    params: &Value,
    context: RequestContext,
    cancel: &CancelToken,
) -> Result<Value, String> {
    use crate::sync::{record_repository as repo, record_runtime::RuntimeFormat};
    let state = app.state::<AppState>();
    let records = {
        let _lifecycle = state.sync.lifecycle.lock().unwrap();
        let core = state.sync.core.lock().unwrap();
        match core.format {
            RuntimeFormat::Records => core.records.clone().ok_or("Records workspace is unavailable")?,
            _ => return Err("Choose a workspace or resolve the blocked state first.".into()),
        }
    };
    if method == "mode" {
        return Ok(json!({"mode":"records"}));
    }
    validate_method(method)?;
    let policy = state.mcp.policy.lock().unwrap().clone();
    if !policy.enabled {
        return Err("MCP access is disabled in Lunport Settings → AI Access".into());
    }
    state
        .mcp
        .last_client_at_ms
        .store(unix_ms(), Ordering::Relaxed);
    match method {
        "create_host" => crate::sync::engine::with_env(app, |env| {
            super::management::create(env, &state.mcp, params, context, cancel, &|request| {
                state
                    .mcp
                    .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                        crate::show_main_window(app);
                        let _ = app.emit("mcp://approval-requested", request);
                    })
            })
        })
        .map_err(|e| e.to_string())?,
        "update_host" => crate::sync::engine::with_env(app, |env| {
            super::management::update(env, &state.mcp, params, context, cancel, &|request| {
                state
                    .mcp
                    .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                        crate::show_main_window(app);
                        let _ = app.emit("mcp://approval-requested", request);
                    })
            })
        })
        .map_err(|e| e.to_string())?,
        "set_transport" | "remove_transport" => crate::sync::engine::with_env(app, |env| {
            let tool = if method == "set_transport" { super::management::set_transport } else { super::management::remove_transport };
            tool(env, &state.mcp, params, context, cancel, &|request| {
                state
                    .mcp
                    .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                        crate::show_main_window(app);
                        let _ = app.emit("mcp://approval-requested", request);
                    })
            })
        })
        .map_err(|e| e.to_string())?,
        "list_tunnels" => crate::sync::engine::with_env(app, |env| super::tunnels::list(env, &state.mcp, &state.session.tunnels))
            .map_err(|e| e.to_string())?,
        "create_tunnel" | "update_tunnel" | "delete_tunnel" => crate::sync::engine::with_env(app, |env| {
            let tool = match method {
                "create_tunnel" => super::tunnels::create,
                "update_tunnel" => super::tunnels::update,
                _ => super::tunnels::delete,
            };
            tool(env, &state.mcp, &state.session.tunnels, params, context, cancel, &|request| {
                state
                    .mcp
                    .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                        crate::show_main_window(app);
                        let _ = app.emit("mcp://approval-requested", request);
                    })
            })
        })
        .map_err(|e| e.to_string())?,
        "start_tunnel" => crate::sync::engine::with_env(app, |env| {
            // Lunport's native windows for what verifying the route's server keys may ask (a jump host's login, a grant), naming the AI
            // client.
            let owner = crate::session::auth_window::NativeOwner {
                ai: Some(asker(&context, policy.approval_mode, Unreviewed::Tunnel)),
                hub: state.session.auth_questions.clone(),
                surface: Arc::new(crate::session::auth_window::TauriAuthSurface {
                    app: app.clone(),
                }),
                request_id: context.id.clone(),
                cancel: cancel.clone(),
            };
            super::tunnels::start(
                env,
                &state.mcp,
                &state.session.tunnels,
                connector,
                &owner,
                params,
                context,
                cancel,
                &|request| {
                    state
                        .mcp
                        .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                            crate::show_main_window(app);
                            let _ = app.emit("mcp://approval-requested", request);
                        })
                },
                &super::tunnels::launcher(app),
            )
        })
        .map_err(|e| e.to_string())?,
        "stop_tunnel" => crate::sync::engine::with_env(app, |env| {
            super::tunnels::stop(env, &state.mcp, &state.session.tunnels, params, context, cancel)
        })
        .map_err(|e| e.to_string())?,
        "list_databases" => crate::sync::engine::with_env(app, |env| super::databases::list(env, &state.mcp, &state.session.databases))
            .map_err(|e| e.to_string())?,
        "create_database" | "update_database" => crate::sync::engine::with_env(app, |env| {
            let tool = if method == "create_database" { super::databases::create } else { super::databases::update };
            tool(env, &state.mcp, &state.session.databases, params, context, cancel, &|request| {
                state
                    .mcp
                    .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                        crate::show_main_window(app);
                        let _ = app.emit("mcp://approval-requested", request);
                    })
            })
        })
        .map_err(|e| e.to_string())?,
        "delete_database" => crate::sync::engine::with_env(app, |env| {
            // The port password goes from the keychain the Databases page keeps it in, as the page's delete takes it.
            super::databases::delete(env, &state.mcp, &state.session.databases, &crate::sync::env::OsKeychain, params, context, cancel, &|request| {
                state
                    .mcp
                    .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                        crate::show_main_window(app);
                        let _ = app.emit("mcp://approval-requested", request);
                    })
            })
        })
        .map_err(|e| e.to_string())?,
        "start_database" => crate::sync::engine::with_env(app, |env| {
            // Lunport's native windows for what verifying the route host's server keys may ask (a jump host's login, a grant), naming
            // the AI client.
            let owner = crate::session::auth_window::NativeOwner {
                ai: Some(asker(&context, policy.approval_mode, Unreviewed::Database)),
                hub: state.session.auth_questions.clone(),
                surface: Arc::new(crate::session::auth_window::TauriAuthSurface {
                    app: app.clone(),
                }),
                request_id: context.id.clone(),
                cancel: cancel.clone(),
            };
            super::databases::start(
                env,
                &state.mcp,
                &state.session.databases,
                connector,
                &owner,
                params,
                context,
                cancel,
                &|request| {
                    state
                        .mcp
                        .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                            crate::show_main_window(app);
                            let _ = app.emit("mcp://approval-requested", request);
                        })
                },
                &super::databases::starter(app),
                super::databases::START_WAIT,
            )
        })
        .map_err(|e| e.to_string())?,
        "stop_database" => crate::sync::engine::with_env(app, |env| {
            super::databases::stop(env, &state.mcp, &state.session.databases, params, context, cancel)
        })
        .map_err(|e| e.to_string())?,
        "verify_host_key" => {
            if params
                .as_object()
                .is_none_or(|p| p.len() != 1 || !p.contains_key("alias"))
            {
                return Err("verify_host_key accepts only an AI-approved host ID or alias; it never accepts a trust answer from the client.".into());
            }
            let owner = crate::session::auth_window::NativeOwner {
                // Nothing runs after a verification: the windows only name the AI client.
                ai: Some(AiAsker { client: client_label(&context), unreviewed: None }),
                hub: state.session.auth_questions.clone(),
                surface: Arc::new(crate::session::auth_window::TauriAuthSurface {
                    app: app.clone(),
                }),
                request_id: context.id.clone(),
                cancel: cancel.clone(),
            };
            super::management::verify(
                &state.mcp,
                connector,
                string_param(params, "alias")?,
                context,
                cancel,
                &owner,
                &|policy, id| permissions::authorize(&state, policy, id),
            )
        }
        "list_hosts" => {
            let hosts = repo::list_hosts(&records)
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|v| permissions::record_allowed(&policy, &records, v))
                .map(|v| metadata(&records, &v))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({"hosts":hosts}))
        }
        "get_host" | "get_effective_config" => {
            let alias = string_param(params, "alias")?;
            let host = repo::get_host(&records, alias)
                .or_else(|_| repo::find_by_alias(&records, alias))
                .map_err(|e| e.to_string())?;
            permissions::ensure_record(&policy, &records, &host.host.id)?;
            metadata(&records, &host)
        }
        "ssh_exec" => {
            let alias = string_param(params, "alias")?;
            let command = params
                .get("command")
                .and_then(Value::as_str)
                .ok_or("missing command")?;
            let timeout = match params.get("timeout_seconds") {
                None => 60,
                Some(v) => v
                    .as_u64()
                    .filter(|n| (1..=300).contains(n))
                    .ok_or("timeout_seconds must be an integer from 1 to 300")?,
            };
            let owner = crate::session::auth_window::NativeOwner {
                ai: Some(asker(&context, policy.approval_mode, Unreviewed::Command)),
                hub: state.session.auth_questions.clone(),
                surface: Arc::new(crate::session::auth_window::TauriAuthSurface {
                    app: app.clone(),
                }),
                request_id: context.id.clone(),
                cancel: cancel.clone(),
            };
            execute_context(
                &state.mcp,
                connector,
                alias,
                command,
                timeout,
                cancel,
                &owner,
                &|request| {
                    state
                        .mcp
                        .wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                            crate::show_main_window(app);
                            let _ = app.emit("mcp://approval-requested", request);
                        })
                },
                context,
                &|policy, id| permissions::authorize(&state, policy, id),
            )
        }
        "scp_upload" | "scp_download" => {
            let kind = if method == "scp_upload" { super::transfers::TransferKind::Upload } else { super::transfers::TransferKind::Download };
            let alias = string_param(params, "alias")?;
            let local_path = params.get("local_path").and_then(Value::as_str).ok_or("missing local_path")?;
            let remote_path = params.get("remote_path").and_then(Value::as_str).ok_or("missing remote_path")?;
            let timeout = match params.get("timeout_seconds") {
                None => 300,
                Some(value) => value.as_u64().filter(|seconds| (1..=3600).contains(seconds)).ok_or("timeout_seconds must be an integer from 1 to 3600")?,
            };
            let owner = crate::session::auth_window::NativeOwner {
                ai: Some(asker(&context, policy.approval_mode, Unreviewed::Transfer)),
                hub: state.session.auth_questions.clone(),
                surface: Arc::new(crate::session::auth_window::TauriAuthSurface { app: app.clone() }),
                request_id: context.id.clone(),
                cancel: cancel.clone(),
            };
            super::transfers::execute_context(
                &state.mcp, connector, kind, alias, local_path, remote_path, timeout, cancel, &owner,
                &|request| state.mcp.wait_approval(request, cancel, APPROVAL_TIMEOUT, || {
                    crate::show_main_window(app);
                    let _ = app.emit("mcp://approval-requested", request);
                }),
                context, &|current, id| permissions::authorize(&state, current, id),
            )
        }
        _ => Err(format!("Unknown MCP method: {method}")),
    }
}
pub(super) fn metadata(
    state: &crate::sync::records_v3::SyncStateV3,
    view: &crate::sync::record_repository::HostView,
) -> Result<Value, String> {
    if view.group_error.is_some() {
        return Err("Host Group inheritance needs review.".into());
    }
    let p = &view.effective_payload;
    let path =
        crate::sync::record_groups::ancestor_path(state, &view.host.scope, p.group_id.as_deref())
            .map_err(|e| e.to_string())?;
    let user = if p.user.is_empty() {
        crate::session::os_identity::current_username()
            .map_err(|_| "Cannot read OS username".to_string())?
    } else {
        p.user.clone()
    };
    let safe = |s: &str| crate::session::auth::printable(s).replace(['\n', '\t'], "?");
    // The host's Google Cloud IAP transport, when it has one: what the client would change.
    let transport = crate::sync::transports::get(state, &view.host.id).map(|transport| transport_view(&transport));
    Ok(
        json!({"id":view.host.id,"alias":safe(&p.alias),"hostname":safe(&p.hostname),"user":safe(&user),"port":p.port,"auth":p.auth,"key_id":p.key_id,"jump_ids":p.jump,"tags":p.tags.iter().map(|t|safe(t)).collect::<Vec<_>>(),"scope":view.host.scope,"group_path":path.iter().rev().map(|g|json!({"id":g.id,"name":safe(&g.payload.name)})).collect::<Vec<_>>(),"inherited_from":view.inherited_from,"transport":transport}),
    )
}

/// A transport as the client reads it: its connection settings and the PAM check's shape, never the justification the person last
/// sent (that is theirs; the client sends its own when it requests).
pub(super) fn transport_view(transport: &crate::sync::transports::HostTransport) -> Value {
    let crate::sync::transports::TransportKind::GcpIap { project, zone, instance, interface, account, os_login, pam } = &transport.kind;
    json!({
        "project": project,
        "zone": zone,
        "instance": instance,
        "interface": interface,
        "account": account,
        "os_login": os_login,
        "pam": pam.as_ref().map(|pam| json!({"entitlements": pam.entitlements, "location": pam.location, "duration_minutes": pam.duration_secs / 60})),
    })
}

#[cfg(test)]
mod behavior_tests {
    use super::*;

    /// The host view the AI reads carries the host's transport, so the client can see what it would
    /// change; the justification the person last sent stays theirs.
    #[test]
    fn the_host_view_carries_the_transport_without_its_justification() {
        use crate::sync::record_repository as repo;
        use crate::sync::records_v3::{HostScope, SyncStateV3};
        use crate::sync::transports::{self, HostTransport, PamCheck, TransportKind};
        let state: SyncStateV3 = serde_json::from_value(json!({"version":4,"device_id":"d".repeat(32),"device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap();
        let payload = serde_json::from_value(json!({"schema":2,"alias":"web-1","hostname":"192.0.2.8","user":"frank","auth":"password"})).unwrap();
        let state = repo::create_host(&state, "0000000000000001", HostScope::Local, payload, 2).unwrap();
        let without = metadata(&state, &repo::get_host(&state, "0000000000000001").unwrap()).unwrap();
        assert!(without.as_object().unwrap().contains_key("transport"), "{without}");
        assert_eq!(without["transport"], Value::Null);
        let transport = HostTransport {
            host_id: "0000000000000001".into(),
            kind: TransportKind::GcpIap {
                project: "acme-prod-123456".into(),
                zone: "asia-east1-b".into(),
                instance: "jumpbox".into(),
                interface: "nic0".into(),
                account: Some("frank@example.com".into()),
                os_login: false,
                pam: Some(PamCheck { entitlements: vec!["prod-operate".into(), "prod-admin".into()], location: "global".into(), duration_secs: 1800, justification: Some("restart app-api".into()) }),
            },
        };
        let state = transports::set(&state, "0000000000000001", None, Some(transport), 3).unwrap();
        let with = metadata(&state, &repo::get_host(&state, "0000000000000001").unwrap()).unwrap();
        assert_eq!(
            with["transport"],
            json!({"project":"acme-prod-123456","zone":"asia-east1-b","instance":"jumpbox","interface":"nic0","account":"frank@example.com","os_login":false,"pam":{"entitlements":["prod-operate","prod-admin"],"location":"global","duration_minutes":30}})
        );
        assert!(!with.to_string().contains("restart app-api"), "the justification is the person's, not the client's");
    }
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::{
        fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods},
        ExecResult,
    };
    use crate::sync::testkit::MemKeychain;
    fn runtime(mode: ApprovalMode) -> McpRuntime {
        let r = McpRuntime::default();
        *r.policy.lock().unwrap() = McpPolicy {
            enabled: true,
            allowed_hosts: BTreeSet::from(["id-web".into()]),
            approval_mode: mode,
            ..Default::default()
        };
        r
    }
    fn directory(auth: AuthMethod, pinned: bool) -> FakeDirectory {
        let d = FakeDirectory::new().with_host("web", auth);
        if pinned {
            d.with_pin("web", default_server_key())
        } else {
            d
        }
    }
    fn run(
        r: &McpRuntime,
        e: &FakeEngine,
        d: &FakeDirectory,
        owner: &FakeOwner,
        approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    ) -> Result<Value, String> {
        execute(
            r,
            &Connector {
                grants: crate::session::grants::GrantGates::for_tests(),
                engine: e,
                directory: d,
                keys: &FakeKeys::new(),
                keychain: &MemKeychain::default(),
                confirmer: &FakeConfirmer::default(),
            },
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            owner,
            approve,
        )
    }
    #[test]
    fn denied_host_never_reaches_engine_and_is_audited() {
        let r = runtime(ApprovalMode::Ask);
        r.policy.lock().unwrap().allowed_hosts.clear();
        let e = FakeEngine::new();
        assert!(run(
            &r,
            &e,
            &directory(AuthMethod::Password, true),
            &FakeOwner::default(),
            &|_| panic!("denied hosts never ask")
        )
        .is_err());
        assert!(e.events().is_empty());
        assert_eq!(r.status().recent[0].outcome, "denied");
    }
    #[test]
    fn denied_host_is_audited_as_denied_even_when_the_watcher_checks_first() {
        let r = runtime(ApprovalMode::Ask);
        r.policy.lock().unwrap().allowed_hosts.clear();
        let e = FakeEngine::new();
        let d = directory(AuthMethod::Password, true);
        let caller = thread::current().id();
        let watched = AtomicBool::new(false);
        let cancel = CancelToken::default();
        // Each check on the request's own thread waits for the policy watcher to check first.
        let authorize = |policy: &McpPolicy, id: &str| {
            if thread::current().id() == caller {
                let end = Instant::now() + Duration::from_millis(200);
                while !watched.load(Ordering::SeqCst) && Instant::now() < end {
                    thread::sleep(Duration::from_millis(1));
                }
            } else {
                watched.store(true, Ordering::SeqCst);
            }
            ensure_allowed(policy, id)
        };
        let error = execute_context(
            &r,
            &Connector {
                grants: crate::session::grants::GrantGates::for_tests(),
                engine: &e,
                directory: &d,
                keys: &FakeKeys::new(),
                keychain: &MemKeychain::default(),
                confirmer: &FakeConfirmer::default(),
            },
            "id-web",
            "uptime",
            60,
            &cancel,
            &FakeOwner::default(),
            &|_| panic!("denied hosts never ask"),
            RequestContext::default(),
            &authorize,
        )
        .unwrap_err();
        assert_eq!(error, "MCP request was denied by host policy");
        assert!(!cancel.is_cancelled());
        assert!(e.events().is_empty());
        assert_eq!(r.status().recent[0].outcome, "denied");
    }
    #[test]
    fn auto_log_requests_authentication_without_command_approval() {
        for (auth, login, answer, kind) in [
            (
                AuthMethod::Password,
                FakeLogin::Server(FakeMethods::password("secret")),
                "secret",
                QuestionKind::Password,
            ),
            (
                AuthMethod::Key {
                    key_id: "k-enc".into(),
                },
                FakeLogin::Server(FakeMethods::key()),
                crate::session::testing::TEST_PASSPHRASE,
                QuestionKind::Passphrase,
            ),
            (
                AuthMethod::Interactive,
                FakeLogin::Server(FakeMethods::interactive("2FA:", "code")),
                "code",
                QuestionKind::Interactive,
            ),
        ] {
            let r = runtime(ApprovalMode::AutoLog);
            let e = FakeEngine::new().with_login(login);
            let owner = FakeOwner::typing(&[answer]);
            let d = directory(auth, true);
            let result = run(&r, &e, &d, &owner, &|_| {
                panic!("auto-log never asks approval")
            })
            .unwrap();
            assert_eq!(result["exit_code"], 0);
            assert_eq!(owner.asked().len(), 1);
            assert_eq!(owner.asked()[0].kind, kind);
            assert!(e
                .events()
                .iter()
                .any(|e| matches!(e, FakeEvent::Exec { .. })));
            assert_eq!(r.status().recent[0].mode, ApprovalMode::AutoLog);
        }
    }
    #[test]
    fn auto_log_authentication_cancellation_never_executes_a_command() {
        for reply in [Reply::Cancelled, Reply::TimedOut, Reply::Gone] {
            let r = runtime(ApprovalMode::AutoLog);
            let e = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("secret")));
            let owner = FakeOwner::answering(vec![reply]);
            let result = run(
                &r, &e, &directory(AuthMethod::Password, true), &owner, &|_| panic!()
            );
            assert!(result.is_err());
            assert_eq!(owner.asked().len(), 1);
            assert!(!e.events().iter().any(|event| matches!(event, FakeEvent::Exec { .. })));
        }
    }
    #[test]
    fn auto_log_rechecks_host_access_after_authentication() {
        struct RevokingOwner<'a>(&'a McpRuntime);
        impl Owner for RevokingOwner<'_> {
            fn ask(&self, _: QuestionKind, _: &str, _: bool, _: Option<Instant>) -> Reply {
                self.0.policy.lock().unwrap().allowed_hosts.clear();
                Reply::Answer(zeroize::Zeroizing::new("secret".into()))
            }
            fn host_key_notice(&self, _: &str) {}
            fn banner(&self, _: &str) {}
        }
        let r = runtime(ApprovalMode::AutoLog);
        let e = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("secret")));
        let d = directory(AuthMethod::Password, true);
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &e,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        assert!(execute(
            &r, &connector, "id-web", "uptime", 60, &CancelToken::default(),
            &RevokingOwner(&r), &|_| panic!()
        ).is_err());
        assert!(!e.events().iter().any(|event| matches!(event, FakeEvent::Exec { .. })));
    }
    #[test]
    fn auto_log_uses_the_request_scoped_native_authentication_window() {
        use crate::session::auth_window::{AuthHub, AuthRequest, AuthSurface, NativeOwner};
        struct AuthorizingSurface(Arc<AuthHub>);
        impl AuthSurface for AuthorizingSurface {
            fn changed(&self, requests: &[AuthRequest]) {
                for request in requests {
                    assert_eq!(request.request_id, "native-exec");
                    assert_eq!(request.kind, "password");
                    assert_eq!(request.hop.as_ref().unwrap().alias, "web");
                    self.0.resolve(
                        &request.id, Some(zeroize::Zeroizing::new("secret".into()))
                    ).unwrap();
                }
            }
        }
        let r = runtime(ApprovalMode::AutoLog);
        let e = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("secret")));
        let d = directory(AuthMethod::Password, true);
        let hub = Arc::new(AuthHub::default());
        let cancel = CancelToken::default();
        let owner = NativeOwner {
            ai: None,
            hub: Arc::clone(&hub),
            surface: Arc::new(AuthorizingSurface(Arc::clone(&hub))),
            request_id: "native-exec".into(),
            cancel: cancel.clone(),
        };
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &e,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &r, &connector, "id-web", "uptime", 60, &cancel, &owner, &|_| panic!()
        ).unwrap();
        assert_eq!(result["exit_code"], 0);
        assert!(hub.pending().is_empty());
        assert!(!result.to_string().contains("secret"));
    }
    #[test]
    fn changed_target_after_approval_never_connects() {
        use crate::session::directory::{DirectoryError, HostDirectory, PinnedKey};
        use crate::ssh::{HostId, HostKey};
        struct Mutable(Mutex<FakeDirectory>);
        impl HostDirectory for Mutable {
            fn resolve(&self, q: &HostQuery) -> Result<Target, DirectoryError> {
                self.0.lock().unwrap().resolve(q)
            }
            fn pinned(&self, h: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
                self.0.lock().unwrap().pinned(h)
            }
            fn pin(&self, h: &HostId, k: &HostKey) -> Result<(), DirectoryError> {
                self.0.lock().unwrap().pin(h, k)
            }
            fn replace_pin(
                &self,
                h: &HostId,
                p: &HostKey,
                k: &HostKey,
            ) -> Result<(), DirectoryError> {
                self.0.lock().unwrap().replace_pin(h, p, k)
            }
            fn password_account(&self, h: &HostId) -> String {
                self.0.lock().unwrap().password_account(h)
            }
        }
        let d = Mutable(Mutex::new(directory(AuthMethod::Password, true)));
        let e = FakeEngine::new();
        let r = runtime(ApprovalMode::Ask);
        let c = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &e,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let error = execute(
            &r,
            &c,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| {
                *d.0.lock().unwrap() = directory(AuthMethod::Password, true).with_address(
                    "web",
                    "changed.example",
                    2200,
                );
                ApprovalDecision::Allow
            },
        )
        .unwrap_err();
        assert!(error.contains("changed"));
        assert!(e.events().is_empty());
    }
    #[test]
    fn all_engine_endings_and_combined_cap_are_retained() {
        for ended in [
            Ended::Exited,
            Ended::Signaled,
            Ended::TimedOut,
            Ended::Truncated,
            Ended::Disconnected,
        ] {
            let e = FakeEngine::new().with_exec(
                "uptime",
                ExecResult {
                    ended,
                    exit_code: (ended == Ended::Exited).then_some(7),
                    signal: (ended == Ended::Signaled).then(|| "TERM".into()),
                    stdout: b"out".to_vec(),
                    stderr: b"err".to_vec(),
                    truncated: ended == Ended::Truncated,
                },
            );
            let value = run(
                &runtime(ApprovalMode::AutoLog),
                &e,
                &directory(
                    AuthMethod::Key {
                        key_id: "k-plain".into(),
                    },
                    true,
                ),
                &FakeOwner::default(),
                &|_| panic!(),
            )
            .unwrap();
            assert_eq!(value["stdout"], "out");
            assert_eq!(value["stderr"], "err");
            assert_eq!(value["truncated"], ended == Ended::Truncated);
            assert_eq!(value["exit_code"].is_null(), ended != Ended::Exited);
        }
        let e = FakeEngine::new().with_exec(
            "uptime",
            ExecResult {
                ended: Ended::Exited,
                exit_code: Some(0),
                signal: None,
                stdout: vec![b'a'; 100000],
                stderr: vec![b'b'; 100000],
                truncated: false,
            },
        );
        let value = run(
            &runtime(ApprovalMode::AutoLog),
            &e,
            &directory(
                AuthMethod::Key {
                    key_id: "k-plain".into(),
                },
                true,
            ),
            &FakeOwner::default(),
            &|_| panic!(),
        )
        .unwrap();
        assert_eq!(
            value["stdout"].as_str().unwrap().len() + value["stderr"].as_str().unwrap().len(),
            128 * 1024
        );
        assert_eq!(value["ended"], "truncated");
    }
    #[test]
    fn saved_password_auto_log_never_prompts_and_persists_no_secret_output() {
        use crate::sync::env::Keychain;
        let r = runtime(ApprovalMode::AutoLog);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session-log.jsonl");
        r.load_audit(path.clone());
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "AUTH_SECRET_SENTINEL").unwrap();
        let engine = FakeEngine::new()
            .with_login(FakeLogin::Server(FakeMethods::password(
                "AUTH_SECRET_SENTINEL",
            )))
            .with_exec(
                "uptime",
                ExecResult {
                    stdout: b"STDOUT_SECRET_SENTINEL".to_vec(),
                    stderr: b"STDERR_SECRET_SENTINEL".to_vec(),
                    ended: Ended::Exited,
                    exit_code: Some(0),
                    signal: None,
                    truncated: false,
                },
            );
        let d = directory(AuthMethod::Password, true);
        let owner = FakeOwner::default();
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &keychain,
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &r,
            &connector,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &owner,
            &|_| panic!(),
        )
        .unwrap();
        assert_eq!(result["stdout"], "STDOUT_SECRET_SENTINEL");
        assert!(owner.asked().is_empty());
        let bytes = std::fs::read_to_string(path).unwrap();
        for secret in [
            "AUTH_SECRET_SENTINEL",
            "STDOUT_SECRET_SENTINEL",
            "STDERR_SECRET_SENTINEL",
        ] {
            assert!(!bytes.contains(secret));
        }
    }
    #[test]
    fn approval_timeout_and_denial_never_connect_and_are_audited() {
        for (decision, outcome) in [
            (ApprovalDecision::TimedOut, "timed_out"),
            (ApprovalDecision::Deny, "denied"),
            (ApprovalDecision::Cancel, "canceled"),
        ] {
            let r = runtime(ApprovalMode::Ask);
            let e = FakeEngine::new();
            assert!(run(
                &r,
                &e,
                &directory(AuthMethod::Password, true),
                &FakeOwner::default(),
                &|_| decision
            )
            .is_err());
            assert!(e.events().is_empty());
            assert_eq!(r.status().recent[0].outcome, outcome);
        }
    }
    #[test]
    fn audit_restart_cap_partial_tail_and_failure_are_visible_without_output_or_auth() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session-log.jsonl");
        let r = runtime(ApprovalMode::Ask);
        r.load_audit(path.clone());
        // Set up the cap without 1000 redundant atomic writes.
        {
            let mut recent = r.recent.lock().unwrap();
            for n in 0..1000 {
                recent.push_back(McpAuditEntry {
                    id: n.to_string(),
                    ..Default::default()
                });
            }
        }
        r.record(McpAuditEntry {
            id: "new".into(),
            command: "uptime".into(),
            detail: Some("OUTPUT_SECRET_SENTINEL".into()),
            ..Default::default()
        });
        assert_eq!(r.recent.lock().unwrap().len(), 1000);
        assert!(r.status().recent[0].detail.is_none());
        let bytes = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("OUTPUT_SECRET_SENTINEL"));
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{partial")
            .unwrap();
        let restarted = McpRuntime::default();
        restarted.load_audit(path);
        assert_eq!(restarted.status().recent[0].id, "new");
        assert_eq!(restarted.status().recent.len(), 10);
        assert!(restarted.status().audit_error.unwrap().contains("Partial"));
        r.audit.lock().unwrap().path = Some(
            dir.path()
                .join("missing")
                .join("blocked")
                .join("session-log.jsonl"),
        );
        // Atomic writes can create missing parents, so a file used as parent is the deterministic I/O failure.
        let bad = dir.path().join("file");
        std::fs::write(&bad, b"not a directory").unwrap();
        r.audit.lock().unwrap().path = Some(bad.join("log"));
        r.record(McpAuditEntry::default());
        assert!(r.status().audit_error.is_some());
    }

    // ---- A server key the AI meets for the first time ----

    use crate::session::connect::{HostKeyConfirmer, HostKeyQuestion};
    use crate::session::testing::{Decision, TEST_PASSPHRASE};

    fn run_with(
        r: &McpRuntime,
        e: &FakeEngine,
        d: &dyn crate::session::directory::HostDirectory,
        owner: &FakeOwner,
        window: &dyn HostKeyConfirmer,
        approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    ) -> Result<Value, String> {
        let keys = FakeKeys::new();
        let keychain = MemKeychain::default();
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: e,
            directory: d,
            keys: &keys,
            keychain: &keychain,
            confirmer: window,
        };
        execute(r, &connector, "id-web", "uptime", 60, &CancelToken::default(), owner, approve)
    }
    fn pin_of(d: &FakeDirectory) -> Option<crate::ssh::HostKey> {
        d.pins().get(&crate::ssh::HostId::from("id-web")).map(|pin| pin.key.clone())
    }
    fn executed(e: &FakeEngine) -> bool {
        e.events().iter().any(|event| matches!(event, FakeEvent::Exec { .. }))
    }
    fn outcomes(r: &McpRuntime) -> Vec<String> {
        r.status().recent.iter().map(|entry| entry.outcome.clone()).collect()
    }
    fn other_key() -> crate::ssh::HostKey {
        crate::ssh::HostKey::from_openssh_line(crate::sync::slot_rules::test_keys::ECDSA_PUBLIC).unwrap()
    }

    /// Auto-log asks Lunport's trust window about a server key this device has not verified, and the same call runs the command once the
    /// person trusts it: the key is pinned and no command approval is asked. The trust decision is audited before the command.
    #[test]
    fn auto_log_asks_about_a_new_server_key_and_runs_the_command_once_it_is_trusted() {
        let r = runtime(ApprovalMode::AutoLog);
        let e = FakeEngine::new();
        let d = directory(AuthMethod::Password, false);
        let window = FakeConfirmer::deciding(vec![Decision::Trust]);
        let value = run_with(&r, &e, &d, &FakeOwner::typing(&["secret"]), &window, &|_| panic!("auto-log never asks approval")).unwrap();
        assert_eq!(value["exit_code"], 0);
        let asked = window.asked();
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert_eq!(
            (asked[0].alias.as_str(), asked[0].fingerprint.as_str(), asked[0].changed.is_none()),
            ("web", crate::sync::slot_rules::test_keys::PLAIN_FINGERPRINT, true)
        );
        assert_eq!(pin_of(&d), Some(default_server_key()));
        assert!(executed(&e));
        assert_eq!(outcomes(&r), ["allowed", "host_key_verified"]);
    }

    /// A key the person verified elsewhere while the command waited for approval needs no second look: no handshake of its own, no
    /// window and no trust decision in the log.
    #[test]
    fn a_key_verified_while_the_approval_was_open_is_not_verified_again() {
        let r = runtime(ApprovalMode::Ask);
        let e = FakeEngine::new();
        let d = directory(AuthMethod::Password, false);
        let window = FakeConfirmer::default();
        let verify_meanwhile = |_: &McpPendingRequest| {
            crate::session::directory::HostDirectory::pin(&d, &crate::ssh::HostId::from("id-web"), &default_server_key()).unwrap();
            ApprovalDecision::Allow
        };
        run_with(&r, &e, &d, &FakeOwner::typing(&["secret"]), &window, &verify_meanwhile).unwrap();
        assert!(window.asked().is_empty());
        assert_eq!(outcomes(&r), ["allowed"]);
        assert!(executed(&e));
    }

    /// The person decides on the destination's key before Lunport asks them for its password or its key's passphrase, in both modes.
    #[test]
    fn the_server_key_is_decided_before_any_credential_prompt_for_the_destination() {
        struct Watching<'a> {
            owner: &'a FakeOwner,
            window: FakeConfirmer,
            prompts_before: Mutex<Vec<usize>>,
        }
        impl HostKeyConfirmer for Watching<'_> {
            fn confirm(&self, q: &HostKeyQuestion, c: &CancelToken) -> Option<String> {
                self.prompts_before.lock().unwrap().push(self.owner.asked().len());
                self.window.confirm(q, c)
            }
        }
        for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
            for (auth, answer) in [(AuthMethod::Password, "secret"), (AuthMethod::Key { key_id: "k-enc".into() }, TEST_PASSPHRASE)] {
                let r = runtime(mode);
                let e = FakeEngine::new();
                let d = directory(auth.clone(), false);
                let owner = FakeOwner::typing(&[answer]);
                let window = Watching { owner: &owner, window: FakeConfirmer::deciding(vec![Decision::Trust]), prompts_before: Mutex::new(Vec::new()) };
                let value = run_with(&r, &e, &d, &owner, &window, &|_| ApprovalDecision::Allow).unwrap();
                assert_eq!(value["exit_code"], 0, "{mode:?} {auth:?}");
                assert_eq!(*window.prompts_before.lock().unwrap(), [0], "the window came before any prompt ({mode:?}, {auth:?})");
                assert_eq!(owner.asked().len(), 1, "then the credential ({mode:?}, {auth:?})");
            }
        }
    }

    /// Refusing the key, closing the window or not answering ends the call with a sentence that says which: nothing is pinned, no
    /// credential is asked and nothing runs, in both modes.
    #[test]
    fn a_new_server_key_refused_or_unanswered_saves_nothing_and_runs_nothing() {
        for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
            for (decision, sentence, outcome) in [
                (Decision::Refuse, "The server key of web was denied in Lunport's trust window; nothing was saved and the command did not run.", "denied"),
                (Decision::Unanswered, "Lunport's trust window for the server key of web timed out after 2 minutes; nothing was saved and the command did not run.", "timed_out"),
            ] {
                let r = runtime(mode);
                let e = FakeEngine::new();
                let d = directory(AuthMethod::Password, false);
                let owner = FakeOwner::typing(&["secret"]);
                let window = FakeConfirmer::deciding(vec![decision]);
                let error = run_with(&r, &e, &d, &owner, &window, &|_| ApprovalDecision::Allow).unwrap_err();
                assert_eq!(error, sentence, "{mode:?}");
                assert_eq!(window.asked().len(), 1, "{mode:?}");
                assert!(owner.asked().is_empty(), "no credential was asked ({mode:?})");
                assert_eq!(pin_of(&d), None);
                assert!(!executed(&e));
                assert_eq!(outcomes(&r), [outcome, "host_key_not_verified"], "{mode:?}");
            }
        }
    }

    /// A changed server key opens the warning window in both modes: after Accept new
    /// key the same call replaces the saved key and runs the command; a refusal or no answer says the key had changed, keeps the saved key
    /// and runs nothing.
    #[test]
    fn a_changed_server_key_opens_the_warning_window_in_both_modes() {
        for mode in [ApprovalMode::AutoLog, ApprovalMode::Ask] {
            let r = runtime(mode);
            let e = FakeEngine::new();
            let d = directory(AuthMethod::Password, false).with_pin("web", other_key());
            let window = FakeConfirmer::deciding(vec![Decision::Trust]);
            run_with(&r, &e, &d, &FakeOwner::typing(&["secret"]), &window, &|_| ApprovalDecision::Allow).unwrap();
            let asked = window.asked();
            assert_eq!(asked.len(), 1, "{mode:?}");
            assert_eq!(asked[0].changed.as_ref().map(|pinned| pinned.fingerprint.clone()), Some(other_key().fingerprint), "{mode:?}");
            assert_eq!(pin_of(&d), Some(default_server_key()), "{mode:?}");
            assert!(executed(&e), "{mode:?}");

            for (decision, sentence) in [
                (Decision::Refuse, "The changed server key of web was denied in Lunport's trust window; nothing was saved and the command did not run."),
                (
                    Decision::Unanswered,
                    "Lunport's trust window for the changed server key of web timed out after 2 minutes; nothing was saved and the command did not run.",
                ),
            ] {
                let r = runtime(mode);
                let e = FakeEngine::new();
                let d = directory(AuthMethod::Password, false).with_pin("web", other_key());
                let window = FakeConfirmer::deciding(vec![decision]);
                let error = run_with(&r, &e, &d, &FakeOwner::typing(&["secret"]), &window, &|_| ApprovalDecision::Allow).unwrap_err();
                assert_eq!(error, sentence, "{mode:?}");
                assert_eq!(window.asked().len(), 1, "{mode:?}");
                assert_eq!(pin_of(&d), Some(other_key()), "the saved key stays ({mode:?})");
                assert!(!executed(&e), "{mode:?}");
            }
        }
    }

    /// A key the verification step trusted is not refused afterwards by a check of Auto-log's own:
    /// the connection decides with its own window, as in Ask mode. Here this device's approval never shows (`pinned_for`
    /// says nothing, as when another device keeps changing the pin), and the connection, which meets the pinned key, runs the command.
    #[test]
    fn auto_log_leaves_a_key_still_unverified_after_the_verification_to_the_connection() {
        use crate::session::directory::{DirectoryError, HostDirectory, PinnedKey};
        struct NoApproval<'a>(&'a FakeDirectory);
        impl HostDirectory for NoApproval<'_> {
            fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
                self.0.resolve(query)
            }
            fn pinned(&self, host: &crate::ssh::HostId) -> Result<Option<PinnedKey>, DirectoryError> {
                self.0.pinned(host)
            }
            fn pinned_for(&self, _: &crate::ssh::HopRef) -> Result<Option<PinnedKey>, DirectoryError> {
                Ok(None)
            }
            fn saved_for(&self, hop: &crate::ssh::HopRef) -> Result<Option<PinnedKey>, DirectoryError> {
                self.0.saved_for(hop)
            }
            fn pin(&self, host: &crate::ssh::HostId, key: &crate::ssh::HostKey) -> Result<(), DirectoryError> {
                self.0.pin(host, key)
            }
            fn replace_pin(&self, host: &crate::ssh::HostId, previous: &crate::ssh::HostKey, key: &crate::ssh::HostKey) -> Result<(), DirectoryError> {
                self.0.replace_pin(host, previous, key)
            }
            fn password_account(&self, host: &crate::ssh::HostId) -> String {
                self.0.password_account(host)
            }
        }
        let r = runtime(ApprovalMode::AutoLog);
        let e = FakeEngine::new();
        let d = directory(AuthMethod::Password, false);
        let window = FakeConfirmer::deciding(vec![Decision::Trust]);
        let value = run_with(&r, &e, &NoApproval(&d), &FakeOwner::typing(&["secret"]), &window, &|_| panic!("auto-log never asks approval")).unwrap();
        assert_eq!(value["exit_code"], 0);
        assert_eq!(window.asked().len(), 1, "the verification asked; the connection met the pinned key");
        assert!(executed(&e));
    }

    /// Every host key window an AI request opens names the AI client as Lunport observed it, and in Auto-log says that the command runs
    /// without per-command review once the key is trusted.
    #[test]
    fn the_host_key_window_names_the_ai_client_and_says_what_runs_unreviewed() {
        use crate::session::protocol::{AiAsker, Unreviewed};
        for (mode, requested_by, asker) in [
            (
                ApprovalMode::AutoLog,
                vec!["claude".to_string(), "node".to_string()],
                AiAsker { client: "claude → node".into(), unreviewed: Some(Unreviewed::Command) },
            ),
            (ApprovalMode::Ask, vec!["claude".to_string()], AiAsker { client: "claude".into(), unreviewed: None }),
            (ApprovalMode::AutoLog, vec![], AiAsker { client: "An unidentified AI client".into(), unreviewed: Some(Unreviewed::Command) }),
        ] {
            let r = runtime(mode);
            let e = FakeEngine::new();
            let d = directory(AuthMethod::Password, false);
            let window = FakeConfirmer::deciding(vec![Decision::Trust]);
            let (keys, keychain) = (FakeKeys::new(), MemKeychain::default());
            let connector = Connector {
                grants: crate::session::grants::GrantGates::for_tests(),
                engine: &e,
                directory: &d,
                keys: &keys,
                keychain: &keychain,
                confirmer: &window,
            };
            let context = RequestContext { requested_by, ..Default::default() };
            let owner = FakeOwner::typing(&["secret"]);
            execute_context(&r, &connector, "id-web", "uptime", 60, &CancelToken::default(), &owner, &|_| ApprovalDecision::Allow, context, &ensure_allowed)
                .unwrap();
            assert_eq!(window.asked().into_iter().map(|question| question.ai).collect::<Vec<_>>(), [Some(asker)], "{mode:?}");
        }
    }

    /// A key that differs from the one another device saved for the host (a pin this device has not approved) is a changed key, as the
    /// connect path asks it: both modes warn about it in the window, with the saved key, and the call goes
    /// on after Accept new key. The very key another device saved is asked about as new, says when it was saved, and is trusted here in
    /// both modes.
    #[test]
    fn a_key_that_differs_from_another_devices_saved_key_is_a_changed_key_in_both_modes() {
        let web = crate::ssh::HostId::from("id-web");
        for mode in [ApprovalMode::AutoLog, ApprovalMode::Ask] {
            let r = runtime(mode);
            let e = FakeEngine::new();
            let d = directory(AuthMethod::Password, false).with_saved_pin("web", other_key());
            let window = FakeConfirmer::deciding(vec![Decision::Trust]);
            run_with(&r, &e, &d, &FakeOwner::typing(&["secret"]), &window, &|_| ApprovalDecision::Allow).unwrap();
            let asked = window.asked();
            assert_eq!(asked.len(), 1, "{mode:?}");
            assert_eq!(
                asked[0].changed.as_ref().map(|pinned| pinned.fingerprint.clone()),
                Some(other_key().fingerprint),
                "warned about as changed ({mode:?})"
            );
            assert_eq!(pin_of(&d), Some(default_server_key()), "{mode:?}");
            assert!(d.approved(&web), "{mode:?}");
            assert!(executed(&e), "{mode:?}");
        }

        for mode in [ApprovalMode::AutoLog, ApprovalMode::Ask] {
            let r = runtime(mode);
            let e = FakeEngine::new();
            let d = directory(AuthMethod::Password, false).with_saved_pin("web", default_server_key());
            let window = FakeConfirmer::deciding(vec![Decision::Trust]);
            run_with(&r, &e, &d, &FakeOwner::typing(&["secret"]), &window, &|_| ApprovalDecision::Allow).unwrap();
            let asked = window.asked();
            assert_eq!(asked.len(), 1, "{mode:?}");
            assert!(asked[0].changed.is_none(), "asked about as new ({mode:?})");
            assert_eq!(asked[0].saved.as_ref().map(|saved| saved.fingerprint.clone()), Some(default_server_key().fingerprint), "{mode:?}");
            assert!(d.approved(&web), "{mode:?}");
            assert!(executed(&e), "{mode:?}");
        }
    }

    // ---- What the AI activity page reads of a command: when it was requested, how its review went and what stopped it ----

    use crate::mcp::{McpReview, McpStopKind, McpWindow};

    fn last(r: &McpRuntime) -> McpAuditEntry {
        r.recent.lock().unwrap()[0].clone()
    }
    fn stop_of(entry: &McpAuditEntry) -> Option<(McpStopKind, Option<McpWindow>)> {
        entry.stop.as_ref().map(|stop| (stop.kind, stop.window))
    }

    #[test]
    fn a_command_records_when_it_was_requested_and_its_review() {
        let r = runtime(ApprovalMode::Ask);
        let requested = AtomicU64::new(0);
        run(&r, &FakeEngine::new(), &directory(AuthMethod::Password, true), &FakeOwner::typing(&["secret"]), &|request| {
            requested.store(request.requested_at_ms, Ordering::SeqCst);
            // The person takes a moment to approve: the entry's start is the request, not the end.
            thread::sleep(Duration::from_millis(20));
            ApprovalDecision::Allow
        })
        .unwrap();
        let entry = last(&r);
        assert_eq!(entry.at_ms, requested.load(Ordering::SeqCst));
        assert!(entry.completed_at_ms >= entry.at_ms + 20, "{} {}", entry.at_ms, entry.completed_at_ms);
        assert_eq!(entry.review, Some(McpReview::Approved));
        assert_eq!(entry.stop, None);
        assert_eq!(entry.outcome, "allowed");

        let r = runtime(ApprovalMode::AutoLog);
        run(&r, &FakeEngine::new(), &directory(AuthMethod::Password, true), &FakeOwner::typing(&["secret"]), &|_| panic!("auto-log never asks approval"))
            .unwrap();
        assert_eq!(last(&r).review, Some(McpReview::AutoLog));
        assert_eq!(last(&r).stop, None);
    }

    #[test]
    fn approval_decisions_are_stops_in_the_approval_window() {
        for (decision, review, stop, outcome) in [
            (ApprovalDecision::Deny, Some(McpReview::Refused), (McpStopKind::Refused, Some(McpWindow::Approval)), "denied"),
            (ApprovalDecision::TimedOut, Some(McpReview::NoAnswer), (McpStopKind::NoAnswer, Some(McpWindow::Approval)), "timed_out"),
            (ApprovalDecision::Cancel, None, (McpStopKind::Canceled, Some(McpWindow::Approval)), "canceled"),
        ] {
            let r = runtime(ApprovalMode::Ask);
            assert!(run(&r, &FakeEngine::new(), &directory(AuthMethod::Password, true), &FakeOwner::default(), &|_| decision).is_err());
            let entry = last(&r);
            assert_eq!(entry.review, review, "{decision:?}");
            assert_eq!(stop_of(&entry), Some(stop), "{decision:?}");
            assert!(entry.stop.as_ref().and_then(|stop| stop.reason.as_ref()).is_some(), "{decision:?}");
            assert_eq!(entry.outcome, outcome, "{decision:?}");
        }
    }

    #[test]
    fn a_host_ai_access_does_not_allow_is_not_allowed() {
        let r = runtime(ApprovalMode::Ask);
        r.policy.lock().unwrap().allowed_hosts.clear();
        assert!(run(&r, &FakeEngine::new(), &directory(AuthMethod::Password, true), &FakeOwner::default(), &|_| panic!("never asks")).is_err());
        let entry = last(&r);
        assert_eq!(stop_of(&entry), Some((McpStopKind::NotAllowed, None)));
        assert_eq!(entry.review, None);
        assert_eq!(entry.outcome, "denied");
    }

    #[test]
    fn a_refused_or_unanswered_server_key_is_a_stop_not_an_error() {
        for refuse in [true, false] {
            let (decision, kind) = if refuse { (Decision::Refuse, McpStopKind::Refused) } else { (Decision::Unanswered, McpStopKind::NoAnswer) };
            let r = runtime(ApprovalMode::AutoLog);
            let window = FakeConfirmer::deciding(vec![decision]);
            assert!(run_with(&r, &FakeEngine::new(), &directory(AuthMethod::Password, false), &FakeOwner::default(), &window, &|_| panic!("auto-log never asks approval"))
                .is_err());
            let recent = r.recent.lock().unwrap().clone();
            let (command, trust) = (&recent[0], &recent[1]);
            assert_eq!(stop_of(command), Some((kind, Some(McpWindow::ServerKey))), "refuse: {refuse}");
            assert!(command.stop.as_ref().and_then(|stop| stop.reason.as_deref()).unwrap().contains("server key of web"), "refuse: {refuse}");
            assert_eq!(trust.outcome, "host_key_not_verified");
            assert_eq!(trust.review, Some(McpReview::NotAsked));
            assert_eq!(stop_of(trust), Some((kind, Some(McpWindow::ServerKey))), "refuse: {refuse}");
        }
    }

    #[test]
    fn a_declined_or_unanswered_password_is_a_stop_not_an_error() {
        for (reply, kind) in [(Reply::Cancelled, McpStopKind::Refused), (Reply::TimedOut, McpStopKind::NoAnswer)] {
            let r = runtime(ApprovalMode::AutoLog);
            let owner = FakeOwner::answering(vec![reply]);
            let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("secret")));
            assert!(run(&r, &engine, &directory(AuthMethod::Password, true), &owner, &|_| panic!("auto-log never asks approval")).is_err());
            assert_eq!(stop_of(&last(&r)), Some((kind, Some(McpWindow::Credentials))), "{kind:?}");
        }
    }

    #[test]
    fn a_declined_or_unanswered_grant_is_a_stop() {
        use crate::session::testing::{grant_need, NeedsGrant};
        for (reply, kind) in [(Reply::Cancelled, McpStopKind::Refused), (Reply::TimedOut, McpStopKind::NoAnswer)] {
            let r = runtime(ApprovalMode::AutoLog);
            let engine = FakeEngine::new();
            let inner = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
            let directory = NeedsGrant::new(&inner, grant_need("web", "acme-prod-123456"));
            let owner = FakeOwner::answering(vec![reply]);
            let connector = Connector {
                engine: &engine,
                directory: &directory,
                keys: &FakeKeys::new(),
                keychain: &MemKeychain::default(),
                confirmer: &FakeConfirmer::default(),
                grants: crate::session::grants::GrantGates::for_tests(),
            };
            assert!(execute(&r, &connector, "id-web", "uptime", 60, &CancelToken::default(), &owner, &|_| panic!("auto-log never asks approval")).is_err());
            assert_eq!(stop_of(&last(&r)), Some((kind, Some(McpWindow::Grant))), "{kind:?}");
        }
    }

    #[test]
    fn a_connection_failure_is_an_error_with_its_reason() {
        let r = runtime(ApprovalMode::AutoLog);
        let hop = crate::ssh::HopRef { id: "id-web".into(), alias: "web".into(), hostname: "web.example.com".into(), port: 22, user: "frank".into() };
        let engine = FakeEngine::new().failing_with(ConnectError::Unreachable { hop, reason: "connection refused".into() });
        let error = run(&r, &engine, &directory(AuthMethod::Password, true), &FakeOwner::typing(&["secret"]), &|_| panic!("auto-log never asks approval"))
            .unwrap_err();
        let entry = last(&r);
        assert_eq!(stop_of(&entry), Some((McpStopKind::Error, None)));
        assert_eq!(entry.stop.as_ref().and_then(|stop| stop.reason.clone()), Some(crate::mcp::activity::reason_text(&error)));
        assert_eq!(entry.review, Some(McpReview::AutoLog));
    }

    /// A guard: output stays out of the audit, also when the command fails.
    #[test]
    fn output_never_reaches_the_audit_even_when_the_command_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session-log.jsonl");
        let r = runtime(ApprovalMode::AutoLog);
        r.load_audit(path.clone());
        let engine = FakeEngine::new().with_exec(
            "uptime",
            ExecResult {
                ended: Ended::Exited,
                exit_code: Some(1),
                signal: None,
                stdout: b"OUTPUT_SECRET_SENTINEL".to_vec(),
                stderr: b"OUTPUT_SECRET_SENTINEL".to_vec(),
                truncated: false,
            },
        );
        let value = run(&r, &engine, &directory(AuthMethod::Password, true), &FakeOwner::typing(&["secret"]), &|_| panic!("auto-log never asks approval"))
            .unwrap();
        assert_eq!(value["exit_code"], 1);
        let entry = last(&r);
        assert_eq!(entry.stop, None);
        assert_eq!(entry.exit_code, Some(1));
        assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains("OUTPUT_SECRET_SENTINEL"));
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use crate::session::{
        directory::DirectoryError,
        record_directory::{RecordDirectory, RecordSources},
        testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
    };
    use crate::ssh::{
        fake::{default_server_key, FakeEngine, FakeEvent},
        AuthMethod,
    };
    use crate::sync::{
        record_groups as groups, record_repository as repo, records_v3::*, testkit::MemKeychain,
    };
    #[test]
    fn group_derived_port_change_during_approval_cancels_without_changing_host_revision() {
        let state:SyncStateV3=serde_json::from_value(json!({"version":3,"device_id":"a".repeat(32),"device_name":"fixture","relay_url":"http://127.0.0.1:8787","account":null,"spaces":{},"local":{"hosts":{},"keys":{}},"rotation":null,"relay_features":null,"legacy_v1_backup":null,"phrase_cleanup_pending":false,"migration_gate":null,"shared_writes_blocked":false,"pending_account":null,"notices":[],"last_sync_ms":null,"last_error":null})).unwrap();
        let state = groups::create_group(
            &state,
            "0000000000000031",
            HostScope::Local,
            serde_json::from_value(
                json!({"schema":1,"name":"Ops","defaults":{"port":2222,"user":"ops"}}),
            )
            .unwrap(),
            true,
            1,
        )
        .unwrap();
        let payload=serde_json::from_value(json!({"schema":3,"alias":"web","hostname":"web.example.test","auth":"password","group_id":"0000000000000031","inherit":["port","user"]})).unwrap();
        let state = Arc::new(Mutex::new(
            repo::create_host(&state, "0000000000000001", HostScope::Local, payload, 2).unwrap(),
        ));
        let read = state.clone();
        let directory = RecordDirectory::new(RecordSources {
            snapshot: Box::new(move || Ok(read.lock().unwrap().clone())),
            material: Box::new(|_| {
                panic!("public target resolution must never read vault material")
            }),
            username: Box::new(|| Ok("local".into())),
            pin: Box::new(|_, _, _, _| panic!("stale target never pins")),
        });
        let runtime = McpRuntime::default();
        {
            let mut p = runtime.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("0000000000000001".into());
        }
        let engine = FakeEngine::new();
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &directory,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let error = execute(
            &runtime,
            &connector,
            "0000000000000001",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|request| {
                assert_eq!(request.port.as_deref(), Some("2222"));
                let mut s = state.lock().unwrap();
                let before = repo::get_host(&s, "0000000000000001").unwrap().revision;
                let group = groups::list_groups(&s).unwrap().remove(0);
                let mut payload = group.group.payload;
                payload.defaults.port = Some(2223);
                *s =
                    groups::update_group(&s, &group.group.id, &group.revision, payload, 3).unwrap();
                assert_eq!(
                    repo::get_host(&s, "0000000000000001").unwrap().revision,
                    before
                );
                ApprovalDecision::Allow
            },
        )
        .unwrap_err();
        assert!(error.contains("changed"), "{error}");
        assert!(engine.events().is_empty());
    }
    #[test]
    fn replacing_public_identity_under_same_key_id_invalidates_approval() {
        struct Keys {
            key: Mutex<crate::session::auth::VaultKey>,
            fake: FakeKeys,
        }
        impl KeyStore for Keys {
            fn key(&self, _: &str) -> Option<crate::session::auth::VaultKey> {
                Some(self.key.lock().unwrap().clone())
            }
            fn private_text(&self, id: &str) -> Result<Option<zeroize::Zeroizing<String>>, String> {
                self.fake.private_text(id)
            }
        }
        let fake = FakeKeys::new();
        let keys = Keys {
            key: Mutex::new(fake.key("k-plain").unwrap()),
            fake,
        };
        let engine = FakeEngine::new();
        let directory = FakeDirectory::new()
            .with_host(
                "web",
                AuthMethod::Key {
                    key_id: "k-plain".into(),
                },
            )
            .with_pin("web", default_server_key());
        let r = McpRuntime::default();
        {
            let mut p = r.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
        }
        let c = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &directory,
            keys: &keys,
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &r,
            &c,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| {
                keys.key.lock().unwrap().public_key =
                    crate::sync::slot_rules::test_keys::ECDSA_PUBLIC.into();
                ApprovalDecision::Allow
            },
        );
        assert!(result.unwrap_err().contains("changed"));
        assert!(!engine
            .events()
            .iter()
            .any(|e| matches!(e, FakeEvent::Exec { .. })));
    }
    #[test]
    fn auto_log_reads_credentials_from_interactive_providers() {
        struct ForegroundKeys(FakeKeys);
        impl KeyStore for ForegroundKeys {
            fn key(&self, id: &str) -> Option<crate::session::auth::VaultKey> {
                self.0.key(id)
            }
            fn private_text(&self, id: &str) -> Result<Option<zeroize::Zeroizing<String>>, String> {
                self.0.private_text(id)
            }
        }
        struct ForegroundCredentials;
        impl crate::sync::env::Keychain for ForegroundCredentials {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(Some("secret".into()))
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                panic!()
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!()
            }
        }
        let keys = ForegroundKeys(FakeKeys::new());
        let keychain = ForegroundCredentials;
        let r = McpRuntime::default();
        {
            let mut p = r.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
            p.approval_mode = ApprovalMode::AutoLog;
        }
        for auth in [
            AuthMethod::Key {
                key_id: "k-plain".into(),
            },
            AuthMethod::Password,
        ] {
            let engine = FakeEngine::new().with_login(crate::ssh::fake::FakeLogin::Server(
                if auth == AuthMethod::Password {
                    crate::ssh::fake::FakeMethods::password("secret")
                } else {
                    crate::ssh::fake::FakeMethods::key()
                },
            ));
            let d = FakeDirectory::new()
                .with_host("web", auth)
                .with_pin("web", default_server_key());
            let c = Connector {
                grants: crate::session::grants::GrantGates::for_tests(),
                engine: &engine,
                directory: &d,
                keys: &keys,
                keychain: &keychain,
                confirmer: &FakeConfirmer::default(),
            };
            let result = execute(
                &r,
                &c,
                "id-web",
                "uptime",
                60,
                &CancelToken::default(),
                &FakeOwner::default(),
                &|_| panic!(),
            )
            .unwrap();
            assert_eq!(result["exit_code"], 0);
        }
        let _ = DirectoryError::Failed(String::new());
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::{
        fake::default_server_key, DisconnectReason, ExecResult, Pty, SessionError, ShellChannel,
    };
    use crate::sync::testkit::MemKeychain;
    struct Waiting {
        entered: Arc<AtomicBool>,
        closed: Arc<AtomicBool>,
    }
    impl SshEngine for Waiting {
        fn connect(
            &self,
            _: &Target,
            _: &dyn HostKeyPolicy,
            _: &dyn AuthSource,
        ) -> Result<Box<dyn Session>, ConnectError> {
            Ok(Box::new(Self {
                entered: self.entered.clone(),
                closed: self.closed.clone(),
            }))
        }
    }
    impl Session for Waiting {
        fn shell(&self, _: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
            panic!("MCP never allocates a PTY")
        }
        fn exec(&self, _: &str, _: Duration, _: usize) -> Result<ExecResult, SessionError> {
            self.entered.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(3);
            while !self.closed.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(2));
            }
            Err(SessionError::Closed)
        }
        fn is_alive(&self) -> bool {
            !self.closed.load(Ordering::SeqCst)
        }
        fn disconnect_reason(&self) -> Option<DisconnectReason> {
            None
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }
    #[test]
    fn cancellation_and_revoke_during_exec_close_session_and_audit_once() {
        for revoke in [false, true] {
            let r = McpRuntime::default();
            {
                let mut p = r.policy.lock().unwrap();
                p.enabled = true;
                p.allowed_hosts.insert("id-web".into());
            }
            let cancel = CancelToken::default();
            let engine = Waiting {
                entered: Arc::new(AtomicBool::new(false)),
                closed: Arc::new(AtomicBool::new(false)),
            };
            let directory = FakeDirectory::new()
                .with_host(
                    "web",
                    AuthMethod::Key {
                        key_id: "k-plain".into(),
                    },
                )
                .with_pin("web", default_server_key());
            let connector = Connector {
                grants: crate::session::grants::GrantGates::for_tests(),
                engine: &engine,
                directory: &directory,
                keys: &FakeKeys::new(),
                keychain: &MemKeychain::default(),
                confirmer: &FakeConfirmer::default(),
            };
            thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    execute(
                        &r,
                        &connector,
                        "id-web",
                        "sleep 99",
                        60,
                        &cancel,
                        &FakeOwner::default(),
                        &|_| ApprovalDecision::Allow,
                    )
                });
                let end = Instant::now() + Duration::from_secs(3);
                while !engine.entered.load(Ordering::SeqCst) {
                    assert!(Instant::now() < end);
                    thread::sleep(Duration::from_millis(2));
                }
                if revoke {
                    r.policy.lock().unwrap().allowed_hosts.clear();
                } else {
                    cancel.cancel();
                }
                let output = worker.join().unwrap().unwrap();
                assert_eq!(output["ended"], "canceled");
                assert!(output["exit_code"].is_null());
            });
            assert!(engine.closed.load(Ordering::SeqCst));
            assert_eq!(r.status().recent.len(), 1);
            assert_eq!(r.status().recent[0].outcome, "canceled");
            assert!(r.records_active.lock().unwrap().is_empty());
        }
    }
    #[test]
    fn old_run_is_rejected_with_the_exact_rename_error() {
        assert_eq!(
            validate_method("run"),
            Err("run was renamed to ssh_exec".into())
        );
        assert!(validate_method("ssh_exec").is_ok());
        assert!(validate_method("get_effective_config").is_ok());
    }
}

#[cfg(test)]
mod approval_deadline_tests {
    use super::*;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::fake::{default_server_key, FakeEngine};
    use crate::sync::testkit::MemKeychain;
    #[test]
    fn expired_pending_allow_is_rejected_without_connect_and_audited_timed_out() {
        let r = McpRuntime::default();
        {
            let mut p = r.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
        }
        let e = FakeEngine::new();
        let d = FakeDirectory::new()
            .with_host("web", AuthMethod::Password)
            .with_pin("web", default_server_key());
        let c = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &e,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &r,
            &c,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|request| {
                r.wait_approval(
                    request,
                    &CancelToken::default(),
                    Duration::from_millis(1),
                    || {
                        thread::sleep(Duration::from_millis(5));
                        assert!(
                            r.pending.lock().unwrap().contains_key(&request.id),
                            "simulate a suspended waiter with pending still registered"
                        );
                        assert!(
                            r.resolve_approval(&request.id, true).is_err(),
                            "late resolve must fail at the command boundary"
                        );
                    },
                )
            },
        );
        assert!(result.unwrap_err().contains("timed out"));
        assert!(e.events().is_empty());
        assert_eq!(r.status().recent[0].outcome, "timed_out");
    }
    #[test]
    fn queued_allow_after_deadline_is_not_consumed() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(ApprovalDecision::Allow).unwrap();
        let start = Instant::now();
        let calls = AtomicU64::new(0);
        let decision = receive_approval(
            &rx,
            &CancelToken::default(),
            InteractionDeadline::from_instant(start + Duration::from_secs(1)),
            &|| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    (start, SystemTime::now())
                } else {
                    (start + Duration::from_secs(2), SystemTime::now())
                }
            },
        );
        assert!(matches!(decision, ApprovalDecision::TimedOut));
    }
    #[test]
    fn wall_expiry_rejects_late_allow_with_live_monotonic_deadline() {
        let runtime = McpRuntime::default();
        {
            let mut p = runtime.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
        }
        let engine = FakeEngine::new();
        let directory = FakeDirectory::new()
            .with_host("web", AuthMethod::Password)
            .with_pin("web", default_server_key());
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &directory,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &runtime,
            &connector,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|request| {
                runtime.wait_approval(
                    request,
                    &CancelToken::default(),
                    Duration::from_secs(120),
                    || {
                        {
                            let mut pending = runtime.pending.lock().unwrap();
                            let deadline = &mut pending.get_mut(&request.id).unwrap().deadline;
                            assert!(deadline.monotonic > Instant::now());
                            deadline.utc = SystemTime::now() - Duration::from_secs(1);
                        }
                        assert!(
                            runtime.resolve_approval(&request.id, true).is_err(),
                            "UTC-expired Allow must fail even while monotonic clock is live"
                        );
                    },
                )
            },
        );
        assert!(result.unwrap_err().contains("timed out"));
        assert!(engine.events().is_empty());
        assert_eq!(runtime.status().recent[0].outcome, "timed_out");
    }
    #[test]
    fn wall_expiry_discards_queued_allow_after_clock_advances() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(ApprovalDecision::Allow).unwrap();
        let now = Instant::now();
        let utc = SystemTime::now();
        let calls = AtomicU64::new(0);
        let deadline = InteractionDeadline {
            monotonic: now + Duration::from_secs(120),
            utc: utc + Duration::from_secs(120),
        };
        let decision = receive_approval(&rx, &CancelToken::default(), deadline, &|| {
            (
                now,
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    utc
                } else {
                    utc + Duration::from_secs(121)
                },
            )
        });
        assert!(matches!(decision, ApprovalDecision::TimedOut));
    }
}

#[cfg(test)]
#[path = "target_binding_tests.rs"]
pub(crate) mod target_binding_tests;
