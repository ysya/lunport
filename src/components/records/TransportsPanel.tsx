import "./transports.css";
import { useEffect, useRef, useState } from "react";
import { Cloud, LoaderCircle, PencilLine, Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/app/PageHeader";
import { Dialog, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { TaskDialogContent, TaskDialogBody } from "@/components/app/TaskDialog";
import { GrantRequestDialog } from "./GrantRequestDialog";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { RecordField, selectClass } from "./form";
import { TransportFields } from "./TransportFields";
import { revealHidden } from "@/lib/sync-approvals";
import { updateRecordHost, type RecordOverview } from "@/lib/records";
import {
  deleteTransport,
  fetchOsLoginProfile,
  newIapTransport,
  osLoginUsernameUpdate,
  saveTransport,
  transportLabel,
  transportProblem,
  type HostTransport,
  fetchPamStatus,
  pamStatusLine,
  type PamStatusView,
} from "@/lib/transports";

/** The sentence of a failure, without a thrown Error's "Error: " prefix. */
const describe = (failure: unknown) => revealHidden(failure instanceof Error ? failure.message : String(failure));

/**
 * Hosts reached through a Google Cloud IAP tunnel (design 2026-10-25). One transport per host, saved on this device only (so account
 * write blocks do not apply); the editor dialog also saves the OS Login username into the host's record, so the username check at
 * connect time passes.
 */
export function TransportsPanel({ overview, accept }: { overview: RecordOverview; accept: (overview: RecordOverview) => RecordOverview }) {
  const transports = overview.transports ?? [];
  const hostOf = (id: string) => overview.hosts.find((host) => host.id === id);
  const free = overview.hosts.filter((host) => !transports.some((transport) => transport.host_id === host.id));
  const [draft, setDraft] = useState<HostTransport | null>(null);
  const [original, setOriginal] = useState<HostTransport | null>(null);
  const [busy, setBusy] = useState(false);
  const flight = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<HostTransport | null>(null);
  // The PAM grant of each transport that needs one (design 2026-10-25, PAM grant requests): read when the panel opens and every minute.
  const [grants, setGrants] = useState<Record<string, PamStatusView>>({});
  const [requesting, setRequesting] = useState<HostTransport | null>(null);
  const pamHosts = transports.filter((transport) => transport.kind.pam).map((transport) => transport.host_id).join(",");
  useEffect(() => {
    if (!pamHosts) return;
    let live = true;
    const refresh = () => {
      for (const hostId of pamHosts.split(",")) {
        fetchPamStatus(hostId).then(
          (view) => { if (live) setGrants((known) => ({ ...known, [hostId]: view })); },
          (failure) => { if (live) setGrants((known) => ({ ...known, [hostId]: { entitlement: null, state: "error", active_until_ms: null, message: describe(failure) } })); },
        );
      }
    };
    refresh();
    const timer = setInterval(refresh, 60_000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [pamHosts]);
  const grantLine = (transport: HostTransport) => (transport.kind.pam ? (grants[transport.host_id] ? pamStatusLine(grants[transport.host_id]) : "checking the grant…") : null);
  const grantHeld = (transport: HostTransport) => ["active", "activating"].includes(grants[transport.host_id]?.state ?? "");

  const edit = (transport: HostTransport | null) => {
    setOriginal(transport);
    setDraft(transport ? structuredClone(transport) : newIapTransport(free[0]?.id ?? ""));
    setEditorError(null);
    setNote(null);
  };
  /** Runs a save or a removal; a failure is shown where the person is looking: in the editor, in the Remove dialog, or on the panel. */
  const action = async (run: () => Promise<RecordOverview>, where: "editor" | "remove" | "panel") => {
    if (flight.current) return;
    flight.current = true;
    setBusy(true);
    setError(null);
    setEditorError(null);
    setRemoveError(null);
    try {
      accept(await run());
      if (where === "editor") setDraft(null);
      setDeleting(null);
    } catch (failure) {
      ({ editor: setEditorError, remove: setRemoveError, panel: setError })[where](describe(failure));
    } finally {
      flight.current = false;
      setBusy(false);
    }
  };
  /** Asks OS Login for the account's username and saves it into the host record, so the host is saved as OS Login knows it. */
  const applyOsLoginUsername = async () => {
    const host = draft && hostOf(draft.host_id);
    if (!draft || !host || flight.current) return;
    flight.current = true;
    setBusy(true);
    setEditorError(null);
    setNote(null);
    try {
      const update = osLoginUsernameUpdate(host, await fetchOsLoginProfile(draft.kind.account, draft.kind.project, host.effective_payload.key_id));
      if (update.error) throw new Error(update.error);
      if (update.payload) accept(await updateRecordHost(host.id, host.revision, update.payload));
      setNote(update.note);
    } catch (failure) {
      setEditorError(describe(failure));
    } finally {
      flight.current = false;
      setBusy(false);
    }
  };
  const draftHost = draft ? hostOf(draft.host_id) : undefined;
  const inheritsUser = draftHost?.payload.inherit?.includes("user") ?? false;
  const problem = draft ? transportProblem(draft) : null;

  return (
    <div className="transports-panel space-y-5">
      <PageHeader
        title="Google Cloud"
        count={transports.length}
        description="Reach Compute Engine hosts through IAP tunnels, with OS Login, using gcloud's sign-in on this device."
        actions={
          <Button id="new-transport-button" disabled={busy || !free.length} onClick={() => edit(null)}>
            <Plus className="size-4" />
            New transport
          </Button>
        }
      />
      <p className="text-xs text-muted-foreground">Transports stay on this computer and are not synced.</p>
      {error && (
        <p role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">
          {error}
        </p>
      )}
      {transports.length === 0 ? (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-14 text-center">
          <Cloud className="size-7 text-muted-foreground" />
          <h2 className="font-medium">No host uses a Google Cloud IAP tunnel yet</h2>
          <p className="max-w-sm text-sm text-muted-foreground">
            Choose a saved host and enter its project, zone and instance. On this device the tunnel then replaces the host&apos;s address.
          </p>
          {!overview.hosts.length && <p className="text-sm text-muted-foreground">Add an SSH host first to connect through IAP.</p>}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-left text-sm">
            <thead className="border-b bg-muted/30 text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-3 font-medium">Host</th>
                <th className="px-4 py-3 font-medium">Tunnel</th>
                <th className="transport-wide px-4 py-3 font-medium">Account</th>
                <th className="transport-wide px-4 py-3 font-medium">Checks</th>
                <th className="px-4 py-3">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {transports.map((transport) => {
                const host = hostOf(transport.host_id);
                const checks = [transport.kind.os_login ? "OS Login" : null, transport.kind.pam ? `PAM: ${transport.kind.pam.entitlements.join(", ")}` : null].filter(Boolean);
                const grant = grantLine(transport);
                return (
                  <tr key={transport.host_id} className="border-b last:border-0 hover:bg-muted/20">
                    <td className="max-w-60 px-4 py-3">
                      <button className="block max-w-full truncate text-left font-medium hover:text-primary disabled:cursor-default" disabled={busy} onClick={() => edit(transport)}>
                        {host ? revealHidden(host.payload.alias) : "Host unavailable"}
                      </button>
                      {/* The username and port the connection uses: a Group may supply them. */}
                      <span className="mt-1 block truncate text-xs text-muted-foreground">
                        {host ? `${revealHidden(host.effective_payload.user || "Terminal default")} · port ${host.effective_payload.port}` : transport.host_id}
                      </span>
                    </td>
                    <td className="max-w-80 px-4 py-3">
                      <span className="block truncate text-xs" title={transportLabel(transport)}>
                        {transportLabel(transport)}
                      </span>
                      <span className="mt-1 block text-xs text-muted-foreground">interface {transport.kind.interface}</span>
                      {/* On a narrow panel the Account and Checks columns fold into this line. */}
                      <span className="transport-compact mt-1 text-xs text-muted-foreground">
                        {transport.kind.account ?? "gcloud's active account"} · {checks.length ? checks.join(" · ") : "no checks"}
                        {grant ? ` · ${grant}` : ""}
                      </span>
                    </td>
                    <td className="transport-wide px-4 py-3 text-xs">{transport.kind.account ?? "gcloud's active account"}</td>
                    <td className="transport-wide px-4 py-3 text-xs">
                      {checks.length ? checks.join(" · ") : "None"}
                      {grant && <span className="mt-1 block text-muted-foreground">{grant}</span>}
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center justify-end gap-1">
                        {transport.kind.pam && (
                          <Button size="sm" variant="outline" className="mr-1" disabled={busy || grantHeld(transport)} onClick={() => setRequesting(transport)}>
                            Request grant
                          </Button>
                        )}
                        <Button size="icon-sm" variant="ghost" aria-label={`Edit the transport of ${host?.payload.alias ?? transport.host_id}`} disabled={busy} onClick={() => edit(transport)}>
                          <PencilLine className="size-3.5" />
                        </Button>
                        <Button size="icon-sm" variant="ghost" aria-label={`Remove the transport of ${host?.payload.alias ?? transport.host_id}`} disabled={busy} onClick={() => { setRemoveError(null); setDeleting(transport); }}>
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <Dialog
        open={!!draft}
        onOpenChange={(open) => {
          if (!open && !flight.current) setDraft(null);
        }}
      >
        <TaskDialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{original ? "Edit transport" : "New transport"}</DialogTitle>
            <DialogDescription>The host is reached through Google Cloud IAP on this device; its saved address is not used.</DialogDescription>
          </DialogHeader>
          {draft && (
            <TaskDialogBody>
              <fieldset disabled={busy} className="space-y-4">
                {editorError && (
                  <p role="alert" className="text-sm text-destructive">
                    {editorError}
                  </p>
                )}
                <RecordField label="SSH host">
                  <select className={selectClass} value={draft.host_id} disabled={!!original} onChange={(e) => setDraft({ ...draft, host_id: e.target.value })}>
                    {(original ? overview.hosts.filter((host) => host.id === draft.host_id) : free).map((host) => (
                      <option key={host.id} value={host.id}>
                        {revealHidden(host.payload.alias)} · {revealHidden(host.payload.hostname)}
                      </option>
                    ))}
                  </select>
                </RecordField>
                <TransportFields kind={draft.kind} onChange={(kind) => setDraft({ ...draft, kind })} disabled={busy} />
                {draft.kind.os_login && (
                  <div className="space-y-1 rounded-lg bg-muted/50 p-3 text-sm">
                    <p>
                      The connection logs in as <span className="font-mono">{revealHidden(draftHost?.effective_payload.user || "(terminal default)")}</span>; OS Login decides the username, and the connection checks that they agree.
                    </p>
                    <Button type="button" variant="outline" size="sm" disabled={busy || !draftHost || inheritsUser || !draft.kind.project} onClick={() => void applyOsLoginUsername()}>
                      Use OS Login username
                    </Button>
                    {inheritsUser && <p className="text-xs text-muted-foreground">This host takes its username from its Group; change it there, or stop inheriting it in the host editor.</p>}
                    {note && <p className="text-xs text-muted-foreground">{note}</p>}
                  </div>
                )}
              </fieldset>
            </TaskDialogBody>
          )}
          <DialogFooter>
            <Button variant="outline" disabled={busy} onClick={() => setDraft(null)}>
              Cancel
            </Button>
            <Button disabled={busy || !draft || !draftHost || problem !== null} onClick={() => draft && void action(() => saveTransport(draft, original), "editor")}>
              {busy && <LoaderCircle className="size-3 animate-spin" />}
              Save transport
            </Button>
          </DialogFooter>
        </TaskDialogContent>
      </Dialog>
      {requesting && (
        <GrantRequestDialog
          key={requesting.host_id}
          transport={requesting}
          alias={hostOf(requesting.host_id)?.payload.alias ?? requesting.host_id}
          onClose={() => setRequesting(null)}
          onRequested={(view) => setGrants((known) => ({ ...known, [requesting.host_id]: view }))}
        />
      )}
      <AlertDialog
        open={!!deleting}
        onOpenChange={(open) => {
          if (!open && !busy) setDeleting(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove the transport of {deleting ? hostOf(deleting.host_id)?.payload.alias ?? deleting.host_id : ""}?</AlertDialogTitle>
            <AlertDialogDescription>The host is then reached at its saved address again. The host record itself stays.</AlertDialogDescription>
          </AlertDialogHeader>
          {removeError && (
            <p role="alert" className="text-sm text-destructive">
              {removeError}
            </p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <Button variant="destructive" disabled={busy} onClick={() => deleting && void action(() => deleteTransport(deleting), "remove")}>
              Remove transport
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
