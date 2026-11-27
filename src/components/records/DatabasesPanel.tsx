import "./databases.css";
import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient, type QueryKey, type UseQueryResult } from "@tanstack/react-query";
import { ChevronDown, ChevronUp, Cloud, Database, LoaderCircle, LockKeyhole, PencilLine, Play, Plus, Search, Square, SquareTerminal, Trash2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/app/PageHeader";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogAction, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { Dialog, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { TaskDialogBody, TaskDialogContent } from "@/components/app/TaskDialog";
import { toast } from "sonner";
import { useTerminalStore } from "@/stores/terminals";
import { revealHidden } from "@/lib/reveal-hidden";
import { cn, errorMessage } from "@/lib/utils";
import { recordKeyDestinationKey, type RecordOverview } from "@/lib/records";
import { useLastNonNull } from "@/lib/use-last-non-null";
import { useNow } from "@/lib/use-now";
import { gcloudAccountsQuery, pamStatusQuery, type PamCheck, type PamStatusView } from "@/lib/transports";
import {
  HOST_UNAVAILABLE,
  connectionsLine,
  databaseBusy,
  databaseDetailsId,
  databaseGrantLine,
  databasePamStatusKey,
  databasePamStatusQuery,
  databasePhases,
  databaseRoute,
  databasesQuery,
  deleteDatabase,
  hasConnectionDetails,
  iamUserFor,
  localAddress,
  newDatabase,
  otherDatabases,
  requestDatabaseGrant,
  requestRouteGrant,
  routeHost,
  routeHostGrant,
  routeSummary,
  runDatabaseAction,
  saveDatabase,
  startDatabase,
  stepSentence,
  stopDatabase,
  type DatabaseDraft,
  type DatabaseView,
  type RouteHostGrant,
  type RouteSummary,
  type SavedDatabase,
} from "@/lib/databases";
import { DatabaseAccessCard, WritesOnMarker } from "./DatabaseAccessCard";
import { useMcpStatus } from "@/lib/mcp";
import { useUiStore } from "@/stores/ui";
import { McpDatabaseAccessSummary } from "@/components/McpDatabaseAccess";
import { EnvironmentBadge } from "./DatabaseBadges";
import { DatabaseEditor } from "./DatabaseEditor";
import { StandardPostgresEditor } from "./StandardPostgresEditor";
import { deleteStandardPostgres, postgresAddress, postgresRouteHost, saveStandardPostgres, standardPostgresQuery,
  type StandardPostgresDraft, type StandardPostgresProfile } from "@/lib/standard-postgres";

/**
 * A grant line in a database's details, from the grant `read` found: the line itself, in the warning color when the grant is missing or
 * about to end, Request grant beside it when one can be requested, and under it what else it has to say (`databaseGrantLine`). `led`
 * leads the line, and `subject` is what the button names. A read that fails shows its error in place of whatever an earlier read found,
 * as a host's details pane does.
 */
function GrantLine({ read, pam, subject, led = "", busy, request }: { read: UseQueryResult<PamStatusView>; pam: PamCheck; subject: string; led?: string; busy: boolean; request: () => void }) {
  const now = useNow(1000);
  const status = read.isError ? null : (read.data ?? null);
  const grant = status ? databaseGrantLine(status, pam, now) : null;
  const line = revealHidden(led + (grant ? grant.text : read.isError ? errorMessage(read.error) : "Checking the grant…"));
  const tone = grant?.tone === "held" ? "text-primary" : grant?.tone === "warning" ? "text-warning" : "text-muted-foreground";
  return <>
    <span className={`mt-1 flex min-w-0 items-center gap-1 text-xs ${tone}`}>
      <LockKeyhole className="size-3 shrink-0" aria-hidden="true" /><span className="truncate" title={line}>{line}</span>
      {grant?.request && <Button size="xs" variant="outline" className="ml-1 shrink-0 text-foreground" aria-label={`Request grant for ${revealHidden(subject)}`} disabled={busy} onClick={request}>Request grant</Button>}
    </span>
    {grant?.note && <span className="mt-0.5 block text-xs text-muted-foreground">{grant.note}</span>}
  </>;
}

/**
 * The grant a database needs, read while its details are shown and every minute through the database's `databasePamStatusQuery`.
 * Drawn only for a database with a grant check. A grant that is missing is in the warning color and comes with Request grant; one that
 * ends within five minutes is in the warning color too, and says that a new one can be requested when it ends, since PAM takes no request
 * while a grant is active.
 */
function DatabaseGrant({ id, name, pam, busy, request }: { id: string; name: string; pam: PamCheck; busy: boolean; request: () => void }) {
  const read = useQuery(databasePamStatusQuery(id));
  return <GrantLine read={read} pam={pam} subject={name} busy={busy} request={request} />;
}

/** The grant of the host a database is reached through, with the request that its button makes. */
type RouteGrantRequest = RouteHostGrant & { request: () => void };
const detailsPanelId = (id: string) => `${databaseDetailsId(id)}-panel`;

/**
 * The grant the host a database is reached through needs, beside the database's own and read the same way, through the
 * `pamStatusQuery` of the host's first hop: the host's details pane and the tunnels through it share that read. It says what the
 * database's line does, led by the host's alias, and comes with a Request grant of its own, since the host's grant is not the database's.
 * Drawn only for a host whose first hop has a route with a grant check (`routeHostGrant`).
 */
export function RouteGrant({ hostId, alias, pam, busy, request }: RouteGrantRequest & { busy: boolean }) {
  const read = useQuery(pamStatusQuery(hostId));
  return <GrantLine read={read} pam={pam} subject={alias} led={`${alias}: `} busy={busy} request={request} />;
}

function DatabaseAiAccess({ row, overview }: { row: DatabaseView; overview: RecordOverview }) {
  const status = useMcpStatus();
  const manage = useUiStore((state) => state.openDatabaseAiSettings);
  return <section className="space-y-2 rounded-lg border p-3" aria-label="AI access">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="text-sm font-medium">AI access</h3>
      <Button size="sm" variant="outline" onClick={(event) => {
        event.currentTarget.focus();
        manage(row.database.id);
      }}>Manage AI access</Button>
    </div>
    <McpDatabaseAccessSummary row={row} overview={overview} status={status.isError ? undefined : status.data} />
  </section>;
}

/** Opens a read-only console tab for the database in the workspace; a refusal (too many tabs) is shown as a toast. The console connects on its own, so the local port is not involved. */
export function openDatabaseConsole(row: DatabaseView) {
  const { database } = row;
  try {
    useTerminalStore.getState().open({
      kind: "database", databaseId: database.id, name: database.name, address: `${database.instance} · ${database.project}`,
      environment: row.environment, readOnly: "locked",
    });
  } catch (error) {
    toast.error(errorMessage(error));
  }
}

export function openStandardPostgresConsole(profile: StandardPostgresProfile) {
  try {
    useTerminalStore.getState().open({
      kind: "database", databaseId: profile.id, name: profile.name, address: postgresAddress(profile),
      environment: null, readOnly: "standard", postgresRevision: profile.revision,
    });
  } catch (error) {
    toast.error(errorMessage(error));
  }
}

function StandardPostgresRow({ profile, hostAlias, open, toggle }: {
  profile: StandardPostgresProfile; hostAlias: string | null; open: boolean; toggle: () => void;
}) {
  const name = revealHidden(profile.name);
  const address = postgresAddress(profile);
  const unavailable = (profile.via_host !== null || profile.route_unavailable === true) && hostAlias === null;
  return <tr className={cn("border-b last:border-0 hover:bg-muted/20", open && "bg-primary/5")}>
    <td className="max-w-72 px-4 py-3">
      <button type="button" className="block max-w-full truncate text-left font-medium hover:text-primary" title={name}
        aria-expanded={open} aria-controls={detailsPanelId(profile.id)} onClick={toggle}>{name}</button>
      <span className="mt-1 block truncate text-xs text-muted-foreground">PostgreSQL{hostAlias ? ` · via ${revealHidden(hostAlias)}` : ""}</span>
      <span className="database-address-compact mt-1 truncate font-mono text-xs text-muted-foreground" title={address}>{address}</span>
    </td>
    <td className="database-address-column max-w-60 px-4 py-3">
      <span className="block truncate font-mono text-xs" title={address}>{address}</span>
      <span className="mt-1 block text-xs text-muted-foreground">On this device</span>
    </td>
    <td className={cn("px-4 py-3", unavailable && "text-warning")}>
      {unavailable ? HOST_UNAVAILABLE : profile.has_password ? "Password saved" : "Password required"}
    </td>
    <td className="px-3 py-3"><div className="flex items-center justify-end gap-1">
      <Button size="icon-sm" variant="ghost" aria-label={`Connection details for ${name}`} aria-expanded={open} aria-controls={detailsPanelId(profile.id)} onClick={toggle}>
        {open ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
      </Button>
      <Button size="sm" variant="outline" aria-label={`Open console for ${name}`} disabled={unavailable} onClick={() => openStandardPostgresConsole(profile)}>
        <SquareTerminal className="size-3" />Open console
      </Button>
    </div></td>
  </tr>;
}

export function NewDatabaseType({ cloudBlocked, onChoose, onCancel }: {
  cloudBlocked: boolean; onChoose: (type: "cloud" | "postgres") => void; onCancel: () => void;
}) {
  return <>
    <TaskDialogBody className="grid gap-3 sm:grid-cols-2">
      <Button type="button" variant="outline" className="h-auto min-h-18 justify-start gap-3 whitespace-normal py-3 text-left" onClick={() => onChoose("postgres")}>
        <Database aria-hidden="true" /><span>PostgreSQL<span className="block text-xs font-normal text-muted-foreground">Connect directly or through an SSH host.</span></span>
      </Button>
      <div className="space-y-2">
        <Button type="button" variant="outline" className="h-auto min-h-18 w-full justify-start gap-3 whitespace-normal py-3 text-left"
          disabled={cloudBlocked} onClick={() => onChoose("cloud")}>
          <Cloud aria-hidden="true" /><span>Google Cloud SQL (IAM)<span className="block text-xs font-normal text-muted-foreground">Sign in with your Google account.</span></span>
        </Button>
        {cloudBlocked && <p className="text-xs text-warning">Resolve the library's sync issues before adding Cloud SQL.</p>}
      </div>
    </TaskDialogBody>
    <DialogFooter><Button type="button" variant="outline" onClick={onCancel}>Cancel</Button></DialogFooter>
  </>;
}

/**
 * One saved database. Its name and detail button select its details. A database that runs here although its record is gone (deleted on
 * another device) is shown by its name and Stop alone: there is nothing to change in it, no grant to read for it, and stopping it is what
 * removes it from the list. A row given `details` can select or close the details beside the list. A prod database whose writable window is
 * open says so in its Status, with the time left, whether its details are open or not. A database that runs here as it was saved before
 * another device changed it says that its port applies the change once it is started again, and its badge and its lock follow the
 * environment its port locks by (`row.environment`), which stays prod until then. A database reached
 * through a host names it after where it is, by `hostAlias`; one whose host is not in the library (no alias) says that the host is
 * unavailable, in the warning color. Every row that is not removed has Open console, whatever its port is doing. While a database starts its Status says the step its start is at. No hooks: exported for the tests.
 */
export function DatabaseRow({ row, hostAlias, busy, toggle, details }: { row: DatabaseView; hostAlias: string | null; busy: boolean; toggle: () => void; details?: { open: boolean; toggle: () => void } }) {
  const { database, live } = row;
  const name = revealHidden(database.name);
  const route = `Google Cloud SQL (IAM) · ${revealHidden(databaseRoute(database, hostAlias))}`;
  const unavailable = routeHost(database) !== null && hostAlias === null;
  const address = localAddress(row);
  const active = databaseBusy(row);
  const changing = live.phase === "starting" || live.phase === "stopping";
  // A port that runs can be stopped whatever the record holds now (another device may have cleared its port); starting needs a saved one.
  const controllable = active || database.local_port !== null;
  const verb = active ? "Stop" : live.phase === "error" ? "Retry" : "Start";
  const note =
    live.phase === "running" ? connectionsLine(live.connections)
    : live.phase === "starting" && live.step ? revealHidden(stepSentence(live.step, hostAlias))
    : row.blocked && !row.removed ? "Sync review needed"
    : "\u00a0";
  return <tr className={cn("border-b last:border-0 hover:bg-muted/20", details?.open && "bg-primary/5")}>
    <td className="max-w-72 px-4 py-3">
      <div className="flex min-w-0 items-center gap-2">
        {row.removed ? <span className="truncate font-medium" title={name}>{name}</span> : <button type="button" className="min-w-0 truncate text-left font-medium hover:text-primary" title={name} aria-expanded={details?.open} aria-controls={detailsPanelId(database.id)} onClick={details?.toggle}>{name}</button>}
        {!row.removed && <EnvironmentBadge environment={row.environment} />}
      </div>
      {row.removed ? <span className="mt-1 block text-xs text-warning">Deleted on another device. Stop this running database to remove it here.</span> : <>
        <span className="mt-1 block truncate text-xs text-muted-foreground" title={route}>{route}</span>
        {unavailable && <span className="mt-1 block text-xs text-warning">{HOST_UNAVAILABLE}</span>}
        {row.changed && <span className="mt-1 block text-xs text-warning">The database changed on another device. Stop and start it again to apply it.</span>}
      </>}
      <span className="database-address-compact mt-1 truncate font-mono text-xs text-muted-foreground" title={address}>{address}</span>
    </td>
    <td className="database-address-column max-w-60 px-4 py-3">
      <span className="block truncate font-mono text-xs" title={address}>{address}</span>
      <span className="mt-1 block text-xs text-muted-foreground">{row.removed ? "Removed elsewhere" : row.synced ? "Synced database" : "On this computer"}</span>
    </td>
    <td className="whitespace-nowrap px-4 py-3">
      <span className="inline-flex items-center gap-1.5">
        {changing ? <LoaderCircle className="size-3 animate-spin" /> : <span className={`size-1.5 rounded-full ${live.phase === "running" ? "bg-success" : live.phase === "error" ? "bg-destructive" : "bg-muted-foreground/50"}`} />}
        {databasePhases[live.phase]}
      </span>
      {live.phase === "error" && live.error ? <span className="mt-1 block max-w-64 whitespace-normal text-xs text-destructive">{revealHidden(live.error)}</span> : <span className="mt-1 block text-xs text-muted-foreground">{note}</span>}
      {row.environment === "prod" && live.writable_until_ms !== null && <WritesOnMarker until={live.writable_until_ms} />}
    </td>
    <td className="px-3 py-3"><div className="flex items-center justify-end gap-1">
      {details && <Button size="icon-sm" variant="ghost" aria-label={`Connection details for ${name}`} aria-expanded={details.open} aria-controls={detailsPanelId(database.id)} onClick={details.toggle}>{details.open ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}</Button>}
      {!row.removed && <Button size="sm" variant="outline" aria-label={`Open console for ${name}`} onClick={() => openDatabaseConsole(row)}><SquareTerminal className="size-3" />Open console</Button>}
      {controllable && <Button size="sm" variant={active ? "outline" : "secondary"} aria-label={`${verb} ${name}`} disabled={busy || live.phase === "stopping"} onClick={toggle}>{active ? <Square className="size-3" /> : <Play className="size-3" />}{verb}</Button>}
    </div></td>
  </tr>;
}

/**
 * The question Stop asks before it stops a database that has connections open through its port, which close with it: open while `row` is
 * the database asked about. Cancel and Escape close it, except while a change is under way. No hooks: exported for the tests.
 */
export function StopDatabaseDialog({ row, busy, onCancel, onStop }: { row: DatabaseView | null; busy: boolean; onCancel: () => void; onStop: (row: DatabaseView) => void }) {
  return <AlertDialog open={row !== null} onOpenChange={(open) => { if (!open && !busy) onCancel(); }}><AlertDialogContent>
    <AlertDialogHeader><AlertDialogTitle>Stop {row && revealHidden(row.database.name)}?</AlertDialogTitle><AlertDialogDescription>{row && `${connectionsLine(row.live.connections)} will close.`}</AlertDialogDescription></AlertDialogHeader>
    <AlertDialogFooter><AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel><Button variant="destructive" disabled={busy} onClick={() => { if (row) onStop(row); }}>Stop database</Button></AlertDialogFooter>
  </AlertDialogContent></AlertDialog>;
}

/**
 * The connection details of a database that is offered on a port, with the database user its address names (`iamUserFor`): the database's
 * own account, else the one gcloud is signed in as, and the way to the instance (`route`). gcloud's accounts are read only for a database
 * that names no account of its own, and only while its details are open.
 */
export function DatabaseAccess({ row, route }: { row: DatabaseView; route: RouteSummary }) {
  const accounts = useQuery({ ...gcloudAccountsQuery, enabled: row.database.account === null });
  return <DatabaseAccessCard view={row} iamUser={iamUserFor(row.database.account, accounts.data?.active ?? null)} route={route} />;
}

/** The Databases page. `createIapHost` opens the host editor for a new host that connects through IAP, which the editor's New IAP host asks for. */
export function DatabasesPanel({ overview, createIapHost }: { overview: RecordOverview; createIapHost: () => void }) {
  const query = useQuery(databasesQuery);
  const postgresQuery = useQuery(standardPostgresQuery);
  const client = useQueryClient();
  const routeSource = JSON.stringify([recordKeyDestinationKey(overview), overview.generation]);
  const previousRouteSource = useRef(routeSource);
  useEffect(() => {
    if (previousRouteSource.current === routeSource) return;
    previousRouteSource.current = routeSource;
    void client.invalidateQueries({ queryKey: standardPostgresQuery.queryKey });
  }, [client, routeSource]);
  const workspaceRef = useRef<HTMLDivElement>(null);
  const detailRef = useRef<HTMLElement>(null);
  const savedFocus = useRef<string | null>(null);
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  const flight = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<DatabaseView | StandardPostgresProfile | null>(null);
  // The running database whose Stop asks first, because connections are open through its port.
  const [stopping, setStopping] = useState<DatabaseView | null>(null);
  // The selected database has its connection details beside the list. Undefined selects the first row; null closes the details.
  const [selectedId, setSelectedId] = useState<string | null | undefined>(undefined);
  const [focusAfterSelection, setFocusAfterSelection] = useState<string | null>(null);
  // The database in the editor, the one it is compared against when saved (none for a new one) and which opening of the dialog this is,
  // while the dialog is open. The opening keys the editor, so that one that is still mounted never shows the draft of an earlier opening.
  type Editor = { kind: "choose" } |
    { kind: "cloud"; key: number; initial: DatabaseDraft; expected: SavedDatabase | null } |
    { kind: "postgres"; key: number; profile: StandardPostgresProfile | null };
  const [editing, setEditing] = useState<Editor | null>(null);
  const openings = useRef(0);
  const [editorError, setEditorError] = useState<string | null>(null);
  // Whether what is in the editor differs from what it opened with, and whether closing it is being asked about.
  const [dirty, setDirty] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  // What follows once the changes are discarded and the editor is closed: the host editor, for New IAP host.
  const afterDiscard = useRef<(() => void) | null>(null);
  // The dialog takes a moment to animate out once `editing` is null; its title and body keep what they showed until then.
  const shown = useLastNonNull(editing);
  const rows = query.data ?? [];
  const profiles = postgresQuery.data ?? [];
  const count = rows.length + profiles.length;
  const cloudBlocked = !!overview.account && overview.shared_writes_blocked;
  const needle = search.trim().toLowerCase();
  const visible = rows.filter((r) => `${r.database.name} ${r.database.project} ${r.database.region} ${r.database.instance}`.toLowerCase().includes(needle));
  const selectable = visible.filter((row) => !row.removed);
  const visiblePostgres = profiles.filter((profile) => `${profile.name} ${profile.host} ${profile.database} ${profile.username}`.toLowerCase().includes(needle));
  const preferredVisible = selectable.some((row) => row.database.id === selectedId) || visiblePostgres.some((profile) => profile.id === selectedId);
  const shownId = selectedId === null || preferredVisible ? selectedId : selectable[0]?.database.id ?? visiblePostgres[0]?.id ?? null;
  const selected = selectable.find((row) => row.database.id === shownId);
  const selectedPostgres = visiblePostgres.find((profile) => profile.id === shownId);
  const selectedVia = selected ? routeHostGrant(overview, selected.database) : null;
  useEffect(() => {
    if (focusAfterSelection !== null && shownId === focusAfterSelection) {
      if (workspaceRef.current && workspaceRef.current.clientWidth < 1100) {
        detailRef.current?.focus();
        detailRef.current?.scrollIntoView({ block: "start" });
      }
      setFocusAfterSelection(null);
    }
  }, [focusAfterSelection, shownId]);
  // One change at a time. Whatever came of it the list is read again, and the sentence it failed with is shown: in the dialog for a
  // save, which stays open with what was typed, and on the page for the rest. A save that worked closes the dialog.
  const action = async (run: () => Promise<void>, inEditor = false, queryKey?: QueryKey) => {
    if (flight.current) return;
    flight.current = true; setBusy(true); setError(null); setEditorError(null);
    const failure = await runDatabaseAction(client, run, queryKey);
    if (!inEditor) setError(failure);
    else if (failure === null) { setEditing(null); setDirty(false); }
    else setEditorError(failure);
    flight.current = false; setBusy(false);
  };
  // A new database, or a saved one, which is also what its save is compared against: nothing is saved over a version the list does not show.
  const edit = (row: DatabaseView | null) => {
    setEditorError(null);
    setDirty(false);
    openings.current += 1;
    setEditing({ kind: "cloud", key: openings.current, ...(row ? { initial: row.database, expected: row.database } : { initial: newDatabase(), expected: null }) });
  };
  const editPostgres = (profile: StandardPostgresProfile | null) => {
    setEditorError(null);
    setDirty(false);
    openings.current += 1;
    setEditing({ kind: "postgres", key: openings.current, profile });
  };
  // Cancel, the X, Escape and a click outside all close the dialog from here: not while a save is under way, and only once the person
  // has said that changes may be lost. New IAP host closes it the same way, and `then` opens the host editor once it is closed: never over
  // it, and not at all when the person keeps editing.
  const closeEditor = (then?: () => void) => {
    if (flight.current) return;
    if (dirty) { afterDiscard.current = then ?? null; setDiscarding(true); }
    else { setEditing(null); then?.(); }
  };
  const discard = () => {
    const then = afterDiscard.current;
    afterDiscard.current = null;
    setDiscarding(false); setDirty(false); setEditing(null);
    then?.();
  };
  const save = (next: SavedDatabase) => { if (editing?.kind === "cloud") void action(async () => {
    const saved = await saveDatabase(next, editing.expected);
    setSearch("");
    setSelectedId(saved.id);
    savedFocus.current = saved.id;
  }, true); };
  const savePostgres = (draft: StandardPostgresDraft, password: string | null, forgetPassword: boolean, expectedRoute?: string) => {
    if (editing?.kind !== "postgres") return;
    void action(async () => {
      const saved = await saveStandardPostgres(editing.profile, draft, password, forgetPassword, expectedRoute);
      setSearch("");
      setSelectedId(saved.id);
      savedFocus.current = saved.id;
    }, true, standardPostgresQuery.queryKey);
  };
  // The grant is read again so that the selected details show what was requested.
  const requestGrant = (id: string) => void action(async () => {
    try { await requestDatabaseGrant(id); }
    finally { await client.invalidateQueries({ queryKey: databasePamStatusKey(id) }); }
  });
  // The same for the grant of the host the database is reached through, which its first hop's query holds.
  const requestHostGrant = (id: string, hostId: string) => void action(async () => {
    try { await requestRouteGrant(id); }
    finally { await client.invalidateQueries({ queryKey: pamStatusQuery(hostId).queryKey }); }
  });
  const toggleDetails = (id: string) => {
    const closing = shownId === id;
    setSelectedId(closing ? null : id);
    setFocusAfterSelection(closing ? null : id);
  };
  // A delete can fail once the record is gone, and a dialog that stayed open would offer to delete it again: it closes either way, and
  // the failure is shown on the page beside the list that was read again.
  const remove = (row: DatabaseView | StandardPostgresProfile) => void action(async () => {
    try {
      if ("live" in row) await deleteDatabase(row.database);
      else await deleteStandardPostgres(row);
    } finally { setDeleting(null); }
  }, false, "live" in row ? undefined : standardPostgresQuery.queryKey);
  // Start starts at once. Stop asks first while connections are open through the port, since they close with it, and stops at once
  // otherwise. The question closes once the stop is done, whether it worked or not.
  const toggle = (row: DatabaseView) => {
    if (databaseBusy(row) && row.live.connections > 0) setStopping(row);
    else void action(() => databaseBusy(row) ? stopDatabase(row.database.id) : startDatabase(row.database.id));
  };
  const stop = (row: DatabaseView) => void action(async () => {
    try { await stopDatabase(row.database.id); }
    finally { setStopping(null); }
  });
  // The question counts the connections the list shows now, which may have changed since Stop was pressed.
  const askedToStop = stopping && (rows.find((row) => row.database.id === stopping.database.id) ?? stopping);
  const postgresHost = selectedPostgres ? postgresRouteHost(overview, selectedPostgres) : null;
  const deleteName = deleting && ("live" in deleting ? deleting.database.name : deleting.name);
  const dialogTitle = shown?.kind === "postgres" ? (shown.profile ? "Edit PostgreSQL" : "New PostgreSQL database")
    : shown?.kind === "cloud" && shown.expected ? "Edit database" : "New database";
  const refresh = () => void Promise.all([query.refetch(), postgresQuery.refetch()]);
  return <div className="databases-panel space-y-5">
    <PageHeader title="Databases" count={count}
      actions={<Button id="new-database-button" onClick={() => setEditing({ kind: "choose" })} disabled={busy}><Plus className="size-4" />New database</Button>} />
    <div className="flex flex-wrap items-center gap-3">
      <div className="relative min-w-48 flex-1"><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><Input id="databases-search" aria-label="Search databases" placeholder="Search databases or projects…" className="pl-9" value={search} onChange={(e) => setSearch(e.target.value)} /></div>
    </div>
    {(error || query.error) && <p role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error ?? revealHidden(String(query.error))}<Button variant="ghost" size="sm" onClick={error ? refresh : () => void query.refetch()}>Refresh</Button></p>}
    {postgresQuery.error && <p role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">
      {revealHidden(errorMessage(postgresQuery.error))}<Button variant="ghost" size="sm" onClick={() => void postgresQuery.refetch()}>Refresh PostgreSQL</Button>
    </p>}
    {count === 0 && (query.isPending || postgresQuery.isPending) ? <p role="status" className="py-12 text-center text-sm text-muted-foreground">Loading databases…</p> : count === 0 ?
      <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-14 text-center">
        <Database className="size-7 text-muted-foreground" /><h2 className="font-medium">No databases saved</h2>
        <p className="max-w-sm text-sm text-muted-foreground">Add a PostgreSQL or Google Cloud SQL connection to browse tables and run queries.</p>
      </div> : <div ref={workspaceRef} className={cn("database-workspace", shownId && "has-details")}>
      <div className="database-list overflow-x-auto rounded-lg border">
      <table className="w-full text-left text-sm"><thead className="border-b bg-muted/30 text-xs text-muted-foreground"><tr><th className="px-4 py-3 font-medium">Database</th><th className="database-address-column px-4 py-3 font-medium">Address</th><th className="px-4 py-3 font-medium">Status</th><th className="px-4 py-3"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>{visible.map((row) => {
          const id = row.database.id;
          const open = selected?.database.id === id;
          const route = routeSummary(overview, row.database);
          return <DatabaseRow key={id} row={row} hostAlias={route.alias} busy={busy}
              toggle={() => toggle(row)}
              details={!row.removed ? { open, toggle: () => toggleDetails(id) } : undefined} />;
        })}
        {visiblePostgres.map((profile) => <StandardPostgresRow key={profile.id} profile={profile}
          hostAlias={postgresRouteHost(overview, profile)?.payload.alias ?? null} open={shownId === profile.id} toggle={() => toggleDetails(profile.id)} />)}
        </tbody></table>
      {!visible.length && !visiblePostgres.length && <p className="p-8 text-center text-sm text-muted-foreground">No databases match this search.</p>}
      </div>
      {selected && <aside ref={detailRef} id={detailsPanelId(selected.database.id)} tabIndex={-1} className="database-detail space-y-4" aria-label="Database details">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <h2 className="break-words text-base font-semibold">{revealHidden(selected.database.name)}</h2>
            <p className="text-xs text-muted-foreground">Google Cloud SQL (IAM)</p>
            <p className="text-xs text-muted-foreground">{revealHidden(databaseRoute(selected.database, routeSummary(overview, selected.database).alias))}</p>
          </div>
          <Button size="icon-sm" variant="ghost" aria-label="Close database details" onClick={() => setSelectedId(null)}><X className="size-4" /></Button>
        </div>
        {(selected.database.pam || selectedVia) && <section className="space-y-2 rounded-lg border p-3" aria-label="Access grants">
          <h3 className="text-xs font-medium text-muted-foreground">Access grants</h3>
          {selected.database.pam && <DatabaseGrant id={selected.database.id} name={selected.database.name} pam={selected.database.pam} busy={busy} request={() => requestGrant(selected.database.id)} />}
          {selectedVia && <RouteGrant {...selectedVia} busy={busy} request={() => requestHostGrant(selected.database.id, selectedVia.hostId)} />}
        </section>}
        {!selected.removed && <DatabaseAiAccess row={selected} overview={overview} />}
        {selected.database.local_port !== null && (
          selected.live.phase === "stopped" || selected.live.phase === "error"
            ? <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-primary/5 p-3 text-sm">
                <p>{selected.live.phase === "error" ? "Retry this database, then copy its connection URL and password." : "Start this database, then copy its connection URL and password."}</p>
                <Button size="sm" disabled={busy} onClick={() => toggle(selected)}>{selected.live.phase === "error" ? "Retry" : "Start"}</Button>
              </div>
            : selected.live.phase === "running"
              ? <p className="rounded-lg bg-primary/5 p-3 text-sm">Copy the connection URL and password to use this database.</p>
              : null
        )}
        {hasConnectionDetails(selected)
          ? <DatabaseAccess row={selected} route={routeSummary(overview, selected.database)} />
          : <div id={databaseDetailsId(selected.database.id)} className="rounded-lg border bg-muted/30 p-4 text-sm text-muted-foreground">
              {selected.removed ? "This database was deleted on another device. Stop it to remove it here." : "No local port is shared. Edit this database to let other apps connect."}
            </div>}
        {!selected.removed && <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" aria-label={`Edit ${revealHidden(selected.database.name)}`} disabled={databaseBusy(selected) || busy || selected.blocked} onClick={() => edit(selected)}><PencilLine className="size-3.5" />Edit</Button>
          <Button variant="outline" size="sm" aria-label={`Delete ${revealHidden(selected.database.name)}`} disabled={databaseBusy(selected) || busy || selected.blocked} onClick={() => setDeleting(selected)}><Trash2 className="size-3.5" />Delete</Button>
        </div>}
      </aside>}
      {selectedPostgres && <aside ref={detailRef} id={detailsPanelId(selectedPostgres.id)} tabIndex={-1} className="database-detail space-y-4" aria-label="Database details">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <h2 className="break-words text-base font-semibold">{revealHidden(selectedPostgres.name)}</h2>
            <p className="text-xs text-muted-foreground">PostgreSQL · On this device</p>
          </div>
          <Button size="icon-sm" variant="ghost" aria-label="Close database details" onClick={() => setSelectedId(null)}><X className="size-4" /></Button>
        </div>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-2 rounded-lg border p-3 text-sm">
          <dt className="text-muted-foreground">Address</dt><dd className="break-words font-mono">{postgresAddress(selectedPostgres)}</dd>
          <dt className="text-muted-foreground">Database</dt><dd className="break-words">{revealHidden(selectedPostgres.database)}</dd>
          <dt className="text-muted-foreground">Username</dt><dd className="break-words">{revealHidden(selectedPostgres.username)}</dd>
          <dt className="text-muted-foreground">Route</dt><dd className="break-words">{postgresHost ? `via ${revealHidden(postgresHost.payload.alias)}`
            : selectedPostgres.via_host !== null || selectedPostgres.route_unavailable ? HOST_UNAVAILABLE : "Direct"}</dd>
        </dl>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" aria-label={`Edit ${revealHidden(selectedPostgres.name)}`} disabled={busy} onClick={() => editPostgres(selectedPostgres)}><PencilLine className="size-3.5" />Edit</Button>
          <Button variant="outline" size="sm" aria-label={`Delete ${revealHidden(selectedPostgres.name)}`} disabled={busy} onClick={() => setDeleting(selectedPostgres)}><Trash2 className="size-3.5" />Delete</Button>
        </div>
      </aside>}
    </div>}
    <Dialog open={editing !== null} onOpenChange={(open) => { if (!open) closeEditor(); }}><TaskDialogContent className="sm:max-w-xl" onCloseAutoFocus={(event) => {
      const id = savedFocus.current;
      savedFocus.current = null;
      if (id === null || !workspaceRef.current || workspaceRef.current.clientWidth >= 1100) return;
      if (detailRef.current?.id === detailsPanelId(id)) {
        event.preventDefault();
        detailRef.current.focus();
        detailRef.current.scrollIntoView({ block: "start" });
      } else setFocusAfterSelection(id);
    }}>
      <DialogHeader><DialogTitle>{dialogTitle}</DialogTitle><DialogDescription>{shown?.kind === "cloud"
        ? "Lunport signs in with your Google account and can open a local port for your other apps."
        : shown?.kind === "postgres" ? "This profile is saved on this device. PostgreSQL connections require verified TLS."
        : "Choose how to connect."}</DialogDescription></DialogHeader>
      {shown?.kind === "choose" && <NewDatabaseType cloudBlocked={cloudBlocked} onChoose={(type) => type === "cloud" ? edit(null) : editPostgres(null)} onCancel={() => closeEditor()} />}
      {shown?.kind === "cloud" && <DatabaseEditor key={shown.key} initial={shown.initial} existing={otherDatabases(rows, shown.initial.id)} overview={overview} busy={busy} error={editorError} onSave={save} onCancel={() => closeEditor()} createIapHost={() => closeEditor(createIapHost)} onDirty={setDirty} />}
      {editing?.kind === "postgres" && <StandardPostgresEditor key={editing.key} initial={editing.profile} overview={overview} busy={busy}
        error={editorError} onSave={savePostgres} onCancel={() => closeEditor()} onDirty={setDirty} />}
    </TaskDialogContent></Dialog>
    <AlertDialog open={discarding} onOpenChange={setDiscarding}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Discard database changes?</AlertDialogTitle><AlertDialogDescription>Your unsaved changes will be lost.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Keep editing</AlertDialogCancel><AlertDialogAction onClick={discard}>Discard</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
    <StopDatabaseDialog row={askedToStop} busy={busy} onCancel={() => setStopping(null)} onStop={stop} />
    <AlertDialog open={!!deleting} onOpenChange={(open) => { if (!open && !busy) setDeleting(null); }}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Delete {deleteName && revealHidden(deleteName)}?</AlertDialogTitle><AlertDialogDescription>{deleting && "live" in deleting && deleting.synced ? "This removes the saved database from your synced devices. A database already running on another device keeps running there until it is stopped." : deleting && !("live" in deleting) ? "This removes the local profile and its saved password." : "This removes the saved database."}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel><Button variant="destructive" disabled={busy} onClick={() => { if (deleting) remove(deleting); }}>Delete database</Button></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </div>;
}
