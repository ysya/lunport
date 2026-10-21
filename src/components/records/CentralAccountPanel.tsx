import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Cloud, CloudCheck, LoaderCircle, LockKeyhole } from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { CentralDevices } from "./CentralDevices";
import { RecordField } from "./form";
import { centralStatus, centralStatusKey, centralSignIn, centralChangeServer, centralCancelSignIn,
  centralRefresh, centralSignOut, centralAutomaticStatus, centralAutomaticStart, centralAutomaticStep,
  centralUnlockPassword, automaticSyncKey, type CentralStatus, type AutomaticSyncProgress } from "@/lib/central-sync";

export function CentralAccountSection({
  disabled = false,
  onBusyChange,
}: {
  disabled?: boolean;
  onBusyChange?: (busy: boolean) => void;
}) {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: centralStatusKey,
    queryFn: centralStatus,
    retry: false,
    refetchOnWindowFocus: false,
  });
  useEffect(() => {
    let disposed = false;
    const pending = listen<CentralStatus>("central://status", ({ payload }) => {
      if (!disposed) client.setQueryData(centralStatusKey, payload);
    });
    return () => {
      disposed = true;
      void pending.then((unlisten) => unlisten()).catch(() => {});
    };
  }, [client]);
  if (!query.data) return null;
  if (!query.data.available) {
    return <p className="text-sm text-muted-foreground">Central account sync is unavailable in this build. Your local library remains available without signing in.</p>;
  }
  return (
    <CentralAccountPanel
      status={query.data}
      disabled={disabled}
      onBusyChange={onBusyChange}
      update={(status) => client.setQueryData(centralStatusKey, status)}
    />
  );
}
const phaseText = {
  signed_out: "Use your own server to sync hosts, Groups, tunnels and all managed SSH keys.",
  sign_in_required: "Sign in again to resume automatic sync.",
  password_setup: "Set your sync unlock password once to protect your encrypted library.",
  password_unlock: "Enter the sync unlock password you set on your first device.",
  connecting: "Unlocking and connecting this device…",
  syncing: "Preparing and syncing your encrypted library…",
  ready: "Your encrypted library syncs automatically.",
  needs_attention: "Sync needs your attention.",
} as const;
function fallbackPhase(status: CentralStatus): keyof typeof phaseText {
  if (!status.configured || status.phase === "signed_out") return "signed_out";
  if (status.needs_recovery) return "needs_attention";
  if (!status.has_session) return "sign_in_required";
  if (status.phase === "setup" || status.phase === "backup_required") return "password_setup";
  if (status.phase === "awaiting_approval") return "password_unlock";
  if (status.phase === "active") return "ready";
  return status.phase === "enrolled" ? "syncing" : "needs_attention";
}
export function CentralAccountPanel({ status, disabled = false, onBusyChange, update }: {
  status: CentralStatus; disabled?: boolean; onBusyChange?: (busy: boolean) => void; update: (status: CentralStatus) => void;
}) {
  const [service, setService] = useState(status.service ?? "");
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
  const phase = current?.phase ?? fallbackPhase(status);
  const setup = phase === "password_setup", unlock = phase === "password_unlock";
  const login = signingIn || status.login_pending;
  const blocked = disabled || busy || deviceBusy;
  const serviceOrigin = service.trim().replace(/\/$/, "");
  const changed = !!status.service && serviceOrigin !== status.service;
  useEffect(() => { setService(status.service ?? ""); }, [status.service]);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { onBusyChange?.(busy || deviceBusy); return () => onBusyChange?.(false); }, [busy, deviceBusy, onBusyChange]);
  useEffect(() => { setPassword(""); setConfirmation(""); }, [status.service, status.account_id, status.device_id, phase]);
  useEffect(() => {
    const hide = () => { if (document.hidden) { setPassword(""); setConfirmation(""); } };
    document.addEventListener("visibilitychange", hide);
    return () => document.removeEventListener("visibilitychange", hide);
  }, []);
  useEffect(() => {
    if (result && result.status.service === status.service && result.status.account_id === status.account_id && result.status.device_id === status.device_id) update(result.status);
  }, [result, status.service, status.account_id, status.device_id, update]);
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
  const heading = setup ? "Create your sync password" : unlock ? "Unlock your library" : phase === "ready" ? "Automatic sync" : "Sync across your devices";
  return <section className="app-notice w-full max-w-3xl space-y-5" aria-label="Sync account">
    <div className="flex items-start gap-3">
      <span className="rounded-xl bg-primary/10 p-2.5 text-primary"><StatusIcon className={`size-5 ${phase === "connecting" || phase === "syncing" ? "animate-spin motion-reduce:animate-none" : ""}`} aria-hidden="true" /></span>
      <div className="min-w-0"><h2 className="font-medium">{heading}</h2>
        <p className="mt-1 text-sm text-muted-foreground" role="status">{phaseText[phase]}</p>
        {status.service && <p className="mt-1 break-all text-xs text-muted-foreground">{status.service}</p>}
      </div>
    </div>
    {!status.configured && serviceField}
    {phase === "ready" && <p className="text-sm text-muted-foreground">{status.conflicts > 0 ? `${status.conflicts} conflicts need review in your library.` : status.pending > 0 ? `${status.pending} changes waiting to sync.` : "Hosts, Groups, tunnels and managed SSH keys sync across your devices."}</p>}
    {!status.configured && <p className="text-sm text-muted-foreground">Create an account in your browser using an email as its name and a Passkey. Email verification and email recovery are not used.</p>}
    {!status.service && <p className="text-sm text-muted-foreground">Deploy your own sync server with Cloudflare Workers or Docker, then enter its HTTPS URL. Local mode works without an account.</p>}
    {(setup || unlock) && !login && !changed && <form className="max-w-lg space-y-3" onSubmit={(e) => {
      e.preventDefault();
      if (setup && password !== confirmation) { setError("The passwords do not match."); return; }
      const value = password; setPassword(""); setConfirmation("");
      void run(async () => { publish(await centralUnlockPassword(value)); });
    }}>
      <RecordField label="Sync unlock password"><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
        autoComplete={setup ? "new-password" : "current-password"} disabled={blocked} maxLength={1024} required minLength={setup ? 12 : undefined} /></RecordField>
      {setup && <RecordField label="Confirm sync unlock password"><Input type="password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)}
        autoComplete="new-password" disabled={blocked} maxLength={1024} minLength={12} required /></RecordField>}
      <p className="text-sm text-muted-foreground">{setup ? "Use at least 12 characters. Enter this same password once on each new device. It is processed in Lunport and never sent to your server." : "After unlocking, this device will sync automatically."}</p>
      {setup && <p className="text-xs text-muted-foreground">Save this password in a password manager. Passkey sign-in cannot recover a forgotten sync password.</p>}
      <Button type="submit" disabled={blocked || !password || (setup && (password.length < 12 || password !== confirmation))}>{setup ? "Set password and sync" : "Unlock and sync"}</Button>
    </form>}
    {(error || status.error) && <p className="app-error" role="alert">{error ?? status.error}</p>}
    <div className="flex flex-wrap gap-2">
      {login ? <Button variant="outline" onClick={() => void centralCancelSignIn().then(centralStatus).then(update).catch(() => setError("Could not cancel sign-in."))}>Cancel sign-in</Button> : <>
        {(!status.has_session || phase === "signed_out" || phase === "sign_in_required") && <Button disabled={blocked || changed || !serviceOrigin} onClick={() => void signIn(status.configured ? undefined : "passkey")}>{status.configured ? "Sign in again" : "Sign in and sync with Passkey"}</Button>}
        {status.has_session && (phase === "ready" || error || status.error || phase === "needs_attention") && <Button variant="outline" disabled={blocked} onClick={() => void run(async () => publish(await centralAutomaticStep()))}>{phase === "ready" && !error && !status.error ? "Sync now" : "Retry sync"}</Button>}
        {status.configured && <Button variant="outline" disabled={blocked} onClick={() => void run(async () => { update(await centralSignOut()); client.removeQueries({ queryKey: automaticSyncKey }); })}>Sign out</Button>}
      </>}
    </div>
    {!status.has_session && !status.configured && !login && <p className="text-sm text-muted-foreground">Signing in enables automatic sync for this library and all managed SSH private keys.</p>}
    <details className="space-y-3"><summary className="cursor-pointer text-sm text-muted-foreground">Account and device settings</summary>
      {status.configured && serviceField}
      {status.configured && !status.has_session && !login && !changed && <div className="space-y-2">
        <p className="text-sm text-muted-foreground">To register a new account on this server, open an empty local library. Lunport restarts and open terminal sessions close.</p>
        <Button variant="outline" disabled={blocked || !serviceOrigin} onClick={() => void run(async () => { await centralChangeServer(serviceOrigin); })}>Start with a new account and restart</Button>
      </div>}
      {changed && <div className="space-y-2"><p className="text-sm text-muted-foreground">Changing servers restarts Lunport and opens an empty local library. Open terminal sessions will close.</p>
        <Button disabled={blocked || login || !serviceOrigin} onClick={() => void run(async () => { await centralChangeServer(serviceOrigin); })}>Change server and restart</Button></div>}
      {!status.configured && !login && <Button variant="outline" disabled={blocked || changed || !serviceOrigin} onClick={() => void signIn("oidc")}>Use external sign-in provider</Button>}
      {status.has_session && <Button variant="outline" disabled={blocked} onClick={() => void run(async () => { update(await centralRefresh()); await client.invalidateQueries({ queryKey: automaticSyncKey }); })}>Refresh account</Button>}
      {status.root_fingerprint && status.has_session && <CentralDevices status={status} disabled={blocked} update={update} onBusyChange={setDeviceBusy} />}
    </details>
  </section>;
}
