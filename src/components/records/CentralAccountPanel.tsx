import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Cloud, CloudCheck, LoaderCircle, LockKeyhole } from "lucide-react";
import { CentralAccountAccess } from "./CentralAccountAccess";
import { CentralLibraryMigration } from "./CentralLibraryMigration";
import { WorkspaceTransfer } from "./WorkspaceTransfer";
import { CentralConflicts } from "./CentralConflicts";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import type { RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { syncSummary, syncProblem, newerCentralStatus } from "@/lib/central-status";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { CentralDevices } from "./CentralDevices";
import { RecordField } from "./form";
import { centralStatus, centralStatusKey, centralSignIn, centralChangeServer, centralCancelSignIn,
  centralRefresh, centralSignOut, centralAutomaticStatus, centralAutomaticStart, centralAutomaticStep,
  centralUnlockPassword, centralServerCapabilities, automaticSyncKey, type CentralStatus, type AutomaticSyncProgress } from "@/lib/central-sync";

export function CentralAccountSection({
  disabled = false,
  onBusyChange,
  overview,
  onOpenImport,
}: {
  disabled?: boolean;
  overview?: RecordOverview;
  onOpenImport?: () => void;
  onBusyChange?: (busy: boolean) => void;
}) {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: centralStatusKey,
    queryFn: async () => { const incoming = await centralStatus(); return newerCentralStatus(client.getQueryData<CentralStatus>(centralStatusKey), incoming); },
    retry: false,
    refetchOnWindowFocus: false,
  });
  if (!query.data) return <section className="app-notice max-w-3xl space-y-3" aria-label="Sync status">
    <p role={query.isError ? "alert" : "status"}>{query.isError ? "Could not load sync status. Your local library is still available." : "Checking account and sync status…"}</p>
    {query.isError && <Button variant="outline" onClick={() => void query.refetch()}>Retry loading sync status</Button>}
  </section>;
  if (!query.data.available) {
    return <p className="text-sm text-muted-foreground">Central account sync is unavailable in this build. Your local library remains available without signing in.</p>;
  }
  return (
    <CentralAccountPanel
      key={`${query.data.service}:${query.data.account_id}:${query.data.device_id}`}
      overview={overview}
      onOpenImport={onOpenImport}
      status={query.data}
      disabled={disabled}
      onBusyChange={onBusyChange}
      update={(status) => client.setQueryData<CentralStatus>(centralStatusKey, (previous) => newerCentralStatus(previous, status))}
    />
  );
}
const phaseText = {
  signed_out: "Use your own server to sync hosts, Groups, tunnels, saved SSH passwords and all managed SSH keys.",
  sign_in_required: "Sign in again to resume automatic sync.",
  password_setup: "Set your sync unlock password once to protect your encrypted library.",
  password_recovery: "Reconnect this device with your sync password. Your existing local library is retained.",
  password_unlock: "Enter the sync unlock password you set on your first device.",
  connecting: "Unlocking and connecting this device…",
  syncing: "Preparing and syncing your encrypted library…",
  ready: "Your encrypted library syncs automatically.",
  needs_attention: "Sync needs your attention.",
} as const;
function fallbackPhase(status: CentralStatus): keyof typeof phaseText {
  if (status.reconnect_available !== false && status.account_authenticated && (status.needs_recovery || status.phase === "revoked" || status.replacement_pending)) return status.connecting ? "connecting" : "password_recovery";
  if (!status.configured || status.phase === "signed_out") return "signed_out";
  if (status.needs_recovery) return "needs_attention";
  if (!status.has_session) return "sign_in_required";
  if (status.connecting) return "connecting";
  if (status.phase === "setup" || status.phase === "backup_required") return "password_setup";
  if (status.phase === "awaiting_approval") return "password_unlock";
  if (status.phase === "active") return "ready";
  return status.phase === "enrolled" ? "syncing" : "needs_attention";
}
export function CentralAccountPanel({ status, disabled = false, onBusyChange, update, overview, onOpenImport }: {
  onOpenImport?: () => void; overview?: RecordOverview; status: CentralStatus; disabled?: boolean; onBusyChange?: (busy: boolean) => void; update: (status: CentralStatus) => void;
}) {
  const [service, setService] = useState(status.service ?? "");
  const [accountSettingsOpen, setAccountSettingsOpen] = useState(false);
  const [encryptionDetailsOpen, setEncryptionDetailsOpen] = useState(false);
  const [changeOpen, setChangeOpen] = useState(false);
  const [transferOpen, setTransferOpen] = useState(false);
  const [discoveryOrigin, setDiscoveryOrigin] = useState("");
  const [cooldown, setCooldown] = useState(status.cooldown_seconds ?? 0);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [deviceBusy, setDeviceBusy] = useState(false);
  const [signingIn, setSigningIn] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(false), inFlight = useRef(false);
  const client = useQueryClient();
  const automatic = useQuery({ queryKey: automaticSyncKey, queryFn: centralAutomaticStatus,
    enabled: status.configured && !status.login_pending, retry: false, refetchOnWindowFocus: true,
    refetchInterval: status.configured ? 2000 : false });
  const result = automatic.data;
  const current = result && result.status.service === status.service && result.status.account_id === status.account_id && result.status.device_id === status.device_id &&
    result.status.phase === status.phase && result.status.has_session === status.has_session ? result : undefined;
  const attention = status.needs_recovery || status.replacement_pending || status.needs_reconciliation || status.phase === "revoked" || status.phase === "rekey";
  const recovering = status.reconnect_available !== false && !!status.account_authenticated && (status.needs_recovery || status.replacement_pending || status.phase === "revoked");
  const phase = recovering ? fallbackPhase(status) : attention ? "needs_attention" : current?.phase ?? fallbackPhase(status);
  const setup = phase === "password_setup", unlock = phase === "password_unlock" || phase === "password_recovery";
  const login = signingIn || status.login_pending;
  const blocked = disabled || busy || deviceBusy;
  const networkBlocked = blocked || cooldown > 0;
  const serviceOrigin = service.trim().replace(/\/$/, "");
  const changed = !!status.service && serviceOrigin !== status.service;
  const summary = syncSummary(status);
  const discovery = useQuery({ queryKey: ["central-server-capabilities", discoveryOrigin],
    queryFn: () => centralServerCapabilities(discoveryOrigin), enabled: !status.configured && !!discoveryOrigin,
    retry: false, staleTime: 60000, refetchOnWindowFocus: false });
  useEffect(() => {
    setDiscoveryOrigin("");
    const timer = setTimeout(() => { try { const url = new URL(serviceOrigin); if (url.protocol === "https:" && url.origin === serviceOrigin) setDiscoveryOrigin(serviceOrigin); } catch { /* Incomplete URL while typing. */ } }, 500);
    return () => clearTimeout(timer);
  }, [serviceOrigin]);
  useEffect(() => {
    const deadline = Date.now() + (status.cooldown_seconds ?? 0) * 1000;
    const tick = () => setCooldown(Math.max(0, Math.ceil((deadline - Date.now()) / 1000)));
    tick(); const timer = setInterval(tick, 1000); return () => clearInterval(timer);
  }, [status.cooldown_seconds]);
  useEffect(() => { setService(status.service ?? ""); }, [status.service]);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { onBusyChange?.(busy || deviceBusy); return () => onBusyChange?.(false); }, [busy, deviceBusy, onBusyChange]);
  useEffect(() => { setPassword(""); setConfirmation(""); }, [status.service, status.account_id, status.device_id, phase]);
  useEffect(() => {
    const hide = () => { if (document.hidden) { setPassword(""); setConfirmation(""); } };
    document.addEventListener("visibilitychange", hide);
    return () => document.removeEventListener("visibilitychange", hide);
  }, []);
  const publish = (value: AutomaticSyncProgress) => {
    if (!mounted.current) return;
    client.setQueryData(automaticSyncKey, value); update(value.status);
    void client.invalidateQueries({ queryKey: ["records"] });
  };
  const run = async (action: () => Promise<void>) => {
    if (inFlight.current || blocked) return;
    inFlight.current = true; setBusy(true); setError(null);
    try { await action(); } catch (value) {
      if (mounted.current) setError(typeof value === "string" ? value : "Could not complete sync. Try again.");
    } finally {
      inFlight.current = false;
      if (mounted.current) { setBusy(false); setSigningIn(false); }
    }
  };
  const signIn = (method?: "passkey" | "oidc") => run(async () => {
    setSigningIn(true);
    await centralSignIn(serviceOrigin, method);
    publish(await centralAutomaticStart());
  });
  const serviceField = <RecordField label="Account service"><Input type="url" value={service} onChange={(e) => setService(e.target.value)}
    placeholder="https://sync.example.com" autoComplete="off" spellCheck={false} disabled={blocked || login} /></RecordField>;
  const StatusIcon = setup || unlock ? LockKeyhole : phase === "ready" ? CloudCheck : phase === "connecting" || phase === "syncing" ? LoaderCircle : Cloud;
  const heading = recovering ? phase === "connecting" ? "Reconnecting this device" : "Reconnect this device" : setup ? "Create your sync password" : unlock ? "Unlock your library" : phase === "ready" ? "Automatic sync" : "Sync across your devices";
  return <section className="app-notice w-full max-w-3xl space-y-5" aria-label="Sync account">
    <div className="flex items-start gap-3">
      <span className="rounded-xl bg-primary/10 p-2.5 text-primary"><StatusIcon className={`size-5 ${phase === "connecting" || phase === "syncing" ? "animate-spin motion-reduce:animate-none" : ""}`} aria-hidden="true" /></span>
      <div className="min-w-0"><h2 className="font-medium">{heading}</h2>
        <p className="mt-1 text-sm text-muted-foreground" role="status">{attention || phase === "ready" ? summary.text : phaseText[phase]}</p>
        {status.service && <p className="mt-1 break-all text-xs text-muted-foreground">{status.service}</p>}
      </div>
    </div>
    {!status.configured && serviceField}
    {!status.configured && discoveryOrigin === serviceOrigin && discovery.isError && <p className="text-sm text-muted-foreground">Could not read this server’s sign-in methods. Check the HTTPS address and server version, or retry sign-in.</p>}
    {status.account_id && <p className="text-xs text-muted-foreground">Account {status.account_id.slice(0,12)}… · This device</p>}
    {attention && <div className="space-y-3 rounded-lg border p-3">
      <p className="text-sm">{recovering ? phase === "connecting" ? "Verifying your encrypted library. Keep Lunport open; your local data and unsynced changes are retained." : "Enter your sync password to reconnect this library. Hosts, Groups, SSH keys and unsynced changes are retained." : status.phase === "revoked" ? "This device no longer has access to the encrypted library. Its saved local data has been retained." : status.replacement_pending ? "An older device recovery is incomplete. Its original files and progress are retained. If its original credentials are unavailable, export host and Group settings before rebuilding the library." : status.needs_recovery ? "Lunport cannot use this device’s saved credentials. Your local data is retained. Sign in to the same account and enter your sync password to reconnect here. Hosts, Groups, SSH keys and unsynced changes stay in this library." : status.needs_reconciliation ? "Review the restored local history before merging it into the encrypted library." : "A device access change requires encryption key rotation. Keep an authorized device online and refresh to finish."}</p>

      {status.phase === "rekey" && <Button variant="outline" disabled={networkBlocked} onClick={() => void run(async () => { update(await centralRefresh()); await client.invalidateQueries({queryKey:automaticSyncKey}); })}>Refresh and finish rotation</Button>}
      <Button variant="ghost" disabled={blocked} onClick={() => setTransferOpen(true)}>Export retained host and Group settings…</Button>
    </div>}
    {status.needs_reconciliation && !status.needs_recovery && !status.replacement_pending && <CentralLibraryMigration status={status} disabled={blocked} update={update} onBusyChange={setDeviceBusy} />}
    {status.conflicts > 0 && status.can_sync && <CentralConflicts key={`${status.root_fingerprint}:${status.membership_head}:${status.authorization_epoch}`} overview={overview} status={status} disabled={blocked} onBusyChange={setDeviceBusy} update={update} />}
    {phase === "ready" && status.conflicts === 0 && <p className="text-sm text-muted-foreground">{status.pending > 0 ? `${status.pending} changes waiting to sync.` : "Hosts, Groups, tunnels, saved SSH passwords and managed SSH keys sync across your devices."}</p>}
    {!status.configured && <p className="text-sm text-muted-foreground">Create an account in your browser using an email as its name and a Passkey. Email verification and email recovery are not used.</p>}
    {!status.service && <p className="text-sm text-muted-foreground">Deploy your own sync server with Cloudflare Workers or Docker, then enter its HTTPS URL. Local mode works without an account.</p>}
    {(setup || unlock) && !login && !changed && <form className="max-w-lg space-y-3" onSubmit={(e) => {
      e.preventDefault();
      if (setup && password !== confirmation) { setError("The passwords do not match."); return; }
      const value = password; setPassword(""); setConfirmation("");
      void run(async () => { publish(await centralUnlockPassword(value)); });
    }}>
      <RecordField label="Sync unlock password"><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
        autoComplete={setup ? "new-password" : "current-password"} disabled={networkBlocked} maxLength={1024} required minLength={setup ? 12 : undefined} /></RecordField>
      {setup && <RecordField label="Confirm sync unlock password"><Input type="password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)}
        autoComplete="new-password" disabled={networkBlocked} maxLength={1024} minLength={12} required /></RecordField>}
      <p className="text-sm text-muted-foreground">{setup ? "Use at least 12 characters. Enter this same password once on each new device. It is processed in Lunport and never sent to your server." : recovering ? "Your local library stays here. If local changes need merging, you can review them before sync resumes." : "After unlocking, this device will sync automatically."}</p>
      {setup && <p className="text-xs text-muted-foreground">Save this password in a password manager. Passkey sign-in cannot recover a forgotten sync password.</p>}
      <Button type="submit" disabled={networkBlocked || !password || (setup && (password.length < 12 || password !== confirmation))}>{setup ? "Set password and sync" : recovering ? "Reconnect and sync" : "Unlock and sync"}</Button>
    </form>}
    {cooldown > 0 && <p role="status" className="rounded-lg border p-3 text-sm">Server cooldown: retry in {cooldown} seconds. Local changes are retained; automatic sync will resume.</p>}
    {(error || status.error || automatic.isError) && <div className="space-y-2" role="alert">
      <p className="app-error">{syncProblem(error ?? status.error ?? String(automatic.error))}</p>
      <details className="text-xs text-muted-foreground"><summary className="cursor-pointer">Technical details</summary><pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap select-text">{revealHidden(error ?? status.error ?? String(automatic.error))}</pre></details>
    </div>}
    <div className="flex flex-wrap gap-2">
      {login ? <Button variant="outline" onClick={() => void centralCancelSignIn().then(centralStatus).then(update).catch(() => setError("Could not cancel sign-in."))}>Cancel sign-in</Button> : <>
        {((!status.has_session && !status.account_authenticated) || (attention && status.account_authenticated === false) || phase === "signed_out" || phase === "sign_in_required") && <Button disabled={networkBlocked || changed || !serviceOrigin} onClick={() => void signIn(status.configured ? undefined : "passkey")}>{status.configured ? "Sign in again" : "Sign in and sync with Passkey"}</Button>}
        {status.has_session && !attention && (phase === "ready" || error || status.error) && <Button variant="outline" disabled={networkBlocked} onClick={() => void run(async () => publish(await centralAutomaticStep()))}>{phase === "ready" && !error && !status.error ? "Sync now" : "Retry sync"}</Button>}
        {status.configured && <Button variant="outline" disabled={blocked} onClick={() => void run(async () => { update(await centralSignOut()); client.removeQueries({ queryKey: automaticSyncKey }); })}>Sign out</Button>}
      </>}
    </div>
    {!status.has_session && !status.configured && !login && <p className="text-sm text-muted-foreground">Signing in enables automatic sync for this library, saved SSH passwords and all managed SSH private keys.</p>}
    <details className="space-y-3" onToggle={event => setAccountSettingsOpen(event.currentTarget.open)}><summary className="cursor-pointer text-sm text-muted-foreground">Account and device settings</summary>
      {status.configured && serviceField}
      {status.account_id && <p className="break-all text-xs text-muted-foreground">Account ID: {status.account_id}</p>}
      {status.device_id && <p className="break-all text-xs text-muted-foreground">Device ID: {status.device_id}</p>}
      {status.configured && !status.has_session && !login && !changed && <div className="space-y-2">
        <p className="text-sm text-muted-foreground">To register a new account on this server, open an empty local library. Lunport restarts and open terminal sessions close.</p>
        <Button variant="outline" disabled={blocked || !serviceOrigin} onClick={() => setChangeOpen(true)}>Use a separate account…</Button>
      </div>}
      {changed && <div className="space-y-2"><p className="text-sm text-muted-foreground">Changing servers restarts Lunport and opens an empty local library. Open terminal sessions will close.</p>
        <Button disabled={blocked || login || !serviceOrigin} onClick={() => setChangeOpen(true)}>Change server…</Button></div>}
      {!status.configured && !login && discoveryOrigin === serviceOrigin && discovery.data?.oidc && <Button variant="outline" disabled={networkBlocked || changed || !serviceOrigin} onClick={() => void signIn("oidc")}>Use external sign-in provider</Button>}
      {(status.has_session || status.account_authenticated) && <Button variant="outline" disabled={networkBlocked} onClick={() => void run(async () => { update(await centralRefresh()); await client.invalidateQueries({ queryKey: automaticSyncKey }); })}>Refresh account</Button>}
      {accountSettingsOpen && (status.account_authenticated || status.has_session) && <CentralAccountAccess status={status} disabled={networkBlocked} update={update} onBusyChange={setDeviceBusy} />}
      {status.root_fingerprint && status.has_session && <details className="space-y-3" onToggle={event => setEncryptionDetailsOpen(event.currentTarget.open)}><summary className="cursor-pointer text-sm text-muted-foreground">Encryption membership details</summary>{accountSettingsOpen && encryptionDetailsOpen && <CentralDevices status={status} disabled={networkBlocked} update={update} onBusyChange={setDeviceBusy} />}</details>}
      <Button variant="outline" disabled={blocked} onClick={() => setTransferOpen(true)}>Saved workspaces and exports…</Button>
    </details>
    <WorkspaceTransfer open={transferOpen} onOpenChange={setTransferOpen} onImport={onOpenImport ? () => { setTransferOpen(false); onOpenImport(); } : undefined} />
    <Dialog open={changeOpen} onOpenChange={(open) => { if (!busy) setChangeOpen(open); }}><DialogContent>
      <DialogHeader><DialogTitle>Open a separate local library?</DialogTitle><DialogDescription>Lunport will restart and close open terminal sessions. The current library stays saved on this device, including its account and key files. The new library starts empty and does not reuse its credentials.</DialogDescription></DialogHeader>
      <p className="break-all text-sm">Server: {revealHidden(serviceOrigin)}</p>
      {overview && <p className="text-sm">Retained: {overview.hosts.length} hosts · {overview.groups.length} Groups · {overview.keys.length} key references</p>}
      <p className="text-sm text-muted-foreground">After restarting, sign in to the intended account. You can export host and Group settings from Saved workspaces and import them after review.</p>
      <DialogFooter><Button variant="outline" disabled={busy} onClick={() => setChangeOpen(false)}>Cancel</Button><Button disabled={blocked || !serviceOrigin} onClick={() => void run(async () => { await centralChangeServer(serviceOrigin); })}>Open separate library and restart</Button></DialogFooter>
    </DialogContent></Dialog>
  </section>;
}
