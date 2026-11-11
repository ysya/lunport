import "./databases.css";
import { Fragment, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronUp, Database, LoaderCircle, LockKeyhole, PencilLine, Play, Plus, Search, Square, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/app/PageHeader";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogAction, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { Dialog, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { TaskDialogContent } from "@/components/app/TaskDialog";
import { revealHidden } from "@/lib/reveal-hidden";
import { cn, errorMessage } from "@/lib/utils";
import type { RecordOverview } from "@/lib/records";
import { useLastNonNull } from "@/lib/use-last-non-null";
import { useNow } from "@/lib/use-now";
import { gcloudAccountsQuery, type PamCheck } from "@/lib/transports";
import {
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
  runDatabaseAction,
  saveDatabase,
  startDatabase,
  stopDatabase,
  type DatabaseDraft,
  type DatabaseView,
  type SavedDatabase,
} from "@/lib/databases";
import { DatabaseAccessCard, WritesOnMarker } from "./DatabaseAccessCard";
import { EnvironmentBadge } from "./DatabaseBadges";
import { DatabaseEditor } from "./DatabaseEditor";

/**
 * The grant a database needs, on its row: read when the row shows and every minute through the database's `databasePamStatusQuery`.
 * Drawn only for a database with a grant check. A grant that is missing is in the warning color and comes with Request grant; one that
 * ends within five minutes is in the warning color too, and says that a new one can be requested when it ends, since PAM takes no request
 * while a grant is active. A read that fails shows its error in place of whatever an earlier read found, as a host's details pane does.
 */
function DatabaseGrant({ id, name, pam, busy, request }: { id: string; name: string; pam: PamCheck; busy: boolean; request: () => void }) {
  const now = useNow(1000);
  const read = useQuery(databasePamStatusQuery(id));
  const status = read.isError ? null : (read.data ?? null);
  const grant = status ? databaseGrantLine(status, pam, now) : null;
  const line = revealHidden(grant ? grant.text : read.isError ? errorMessage(read.error) : "Checking the grant…");
  const tone = grant?.tone === "held" ? "text-primary" : grant?.tone === "warning" ? "text-warning" : "text-muted-foreground";
  return <>
    <span className={`mt-1 flex min-w-0 items-center gap-1 text-xs ${tone}`}>
      <LockKeyhole className="size-3 shrink-0" aria-hidden="true" /><span className="truncate" title={line}>{line}</span>
      {grant?.request && <Button size="xs" variant="outline" className="ml-1 shrink-0 text-foreground" aria-label={`Request grant for ${revealHidden(name)}`} disabled={busy} onClick={request}>Request grant</Button>}
    </span>
    {grant?.note && <span className="mt-0.5 block text-xs text-muted-foreground">{grant.note}</span>}
  </>;
}

/**
 * One saved database. Its name and its Edit button open the editor, and both are held back while its port starts, runs or stops, while a
 * change is under way, and while its library's writes are blocked. A database that runs here although its record is gone (deleted on
 * another device) is shown by its name and Stop alone: there is nothing to change in it, no grant to read for it, and stopping it is what
 * removes it from the list. A row given `details` has a button that shows or hides its connection details, which the page draws under
 * the row; the row's bottom line is left out while they are open, so that the two read as one. A prod database whose writable window is
 * open says so in its Status, with the time left, whether its details are open or not. A database that runs here as it was saved before
 * another device changed it says that its port applies the change once it is started again, and its badge and its lock follow the
 * environment its port locks by (`row.environment`), which stays prod until then. No hooks: exported for the tests.
 */
export function DatabaseRow({ row, busy, toggle, requestGrant, ask, edit, details }: { row: DatabaseView; busy: boolean; toggle: () => void; requestGrant: () => void; ask: () => void; edit: () => void; details?: { open: boolean; toggle: () => void } }) {
  const { database, live } = row;
  const name = revealHidden(database.name);
  const route = revealHidden(databaseRoute(database));
  const address = localAddress(row);
  const active = databaseBusy(row);
  const changing = live.phase === "starting" || live.phase === "stopping";
  // A port that runs can be stopped whatever the record holds now (another device may have cleared its port); starting needs a saved one.
  const controllable = active || database.local_port !== null;
  const verb = active ? "Stop" : live.phase === "error" ? "Retry" : "Start";
  const note = live.phase === "running" ? connectionsLine(live.connections) : row.blocked && !row.removed ? "Sync review needed" : "\u00a0";
  return <tr className={cn("border-b last:border-0 hover:bg-muted/20", details?.open && "border-b-0")}>
    <td className="max-w-72 px-4 py-3">
      <div className="flex min-w-0 items-center gap-2">
        {row.removed ? <span className="truncate font-medium" title={name}>{name}</span> : <button className="min-w-0 truncate text-left font-medium hover:text-primary disabled:cursor-default" title={name} disabled={active || busy || row.blocked} onClick={edit}>{name}</button>}
        {!row.removed && <EnvironmentBadge environment={row.environment} />}
      </div>
      {row.removed ? <span className="mt-1 block text-xs text-warning">Deleted on another device. Stop this running database to remove it here.</span> : <>
        <span className="mt-1 block truncate text-xs text-muted-foreground" title={route}>{route}</span>
        {row.changed && <span className="mt-1 block text-xs text-warning">The database changed on another device. Stop and start it again to apply it.</span>}
        {database.pam && <DatabaseGrant id={database.id} name={database.name} pam={database.pam} busy={busy} request={requestGrant} />}
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
      {details && <Button size="icon-sm" variant="ghost" aria-label={`Connection details for ${name}`} aria-expanded={details.open} aria-controls={databaseDetailsId(database.id)} onClick={details.toggle}>{details.open ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}</Button>}
      {controllable && <Button size="sm" variant={active ? "outline" : "secondary"} aria-label={`${verb} ${name}`} disabled={busy || live.phase === "stopping"} onClick={toggle}>{active ? <Square className="size-3" /> : <Play className="size-3" />}{verb}</Button>}
      {!row.removed && <>
        <Button size="icon-sm" variant="ghost" aria-label={`Edit ${name}`} disabled={active || busy || row.blocked} onClick={edit}><PencilLine className="size-3.5" /></Button>
        <Button size="icon-sm" variant="ghost" aria-label={`Delete ${name}`} disabled={active || busy || row.blocked} onClick={ask}><Trash2 className="size-3.5" /></Button>
      </>}
    </div></td>
  </tr>;
}

/**
 * The question Stop asks before it stops a database that has connections open through its port, which close with it: open while `row` is
 * the database asked about. Cancel, Escape and a click outside close it, except while a change is under way. No hooks: exported for the
 * tests.
 */
export function StopDatabaseDialog({ row, busy, onCancel, onStop }: { row: DatabaseView | null; busy: boolean; onCancel: () => void; onStop: (row: DatabaseView) => void }) {
  return <AlertDialog open={row !== null} onOpenChange={(open) => { if (!open && !busy) onCancel(); }}><AlertDialogContent>
    <AlertDialogHeader><AlertDialogTitle>Stop {row && revealHidden(row.database.name)}?</AlertDialogTitle><AlertDialogDescription>{row && `${connectionsLine(row.live.connections)} will close.`}</AlertDialogDescription></AlertDialogHeader>
    <AlertDialogFooter><AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel><Button variant="destructive" disabled={busy} onClick={() => { if (row) onStop(row); }}>Stop database</Button></AlertDialogFooter>
  </AlertDialogContent></AlertDialog>;
}

/**
 * The connection details of a database that is offered on a port, with the database user its address names (`iamUserFor`): the database's
 * own account, else the one gcloud is signed in as. gcloud's accounts are read only for a database that names no account of its own, and
 * only while its details are open.
 */
export function DatabaseAccess({ row }: { row: DatabaseView }) {
  const accounts = useQuery({ ...gcloudAccountsQuery, enabled: row.database.account === null });
  return <DatabaseAccessCard view={row} iamUser={iamUserFor(row.database.account, accounts.data?.active ?? null)} />;
}

export function DatabasesPanel({ overview }: { overview: RecordOverview }) {
  const query = useQuery(databasesQuery);
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  const flight = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<DatabaseView | null>(null);
  // The running database whose Stop asks first, because connections are open through its port.
  const [stopping, setStopping] = useState<DatabaseView | null>(null);
  // The databases whose connection details are open: none until asked, and several may be, so that a lock that is on stays in view.
  const [opened, setOpened] = useState<ReadonlySet<string>>(new Set());
  // The database in the editor, the one it is compared against when saved (none for a new one) and which opening of the dialog this is,
  // while the dialog is open. The opening keys the editor, so that one that is still mounted never shows the draft of an earlier opening.
  const [editing, setEditing] = useState<{ key: number; initial: DatabaseDraft; expected: SavedDatabase | null } | null>(null);
  const openings = useRef(0);
  const [editorError, setEditorError] = useState<string | null>(null);
  // Whether what is in the editor differs from what it opened with, and whether closing it is being asked about.
  const [dirty, setDirty] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  // The dialog takes a moment to animate out once `editing` is null; its title and body keep what they showed until then.
  const shown = useLastNonNull(editing);
  const rows = query.data ?? [];
  const needle = search.trim().toLowerCase();
  const visible = rows.filter((r) => `${r.database.name} ${r.database.project} ${r.database.region} ${r.database.instance}`.toLowerCase().includes(needle));
  // One change at a time. Whatever came of it the list is read again, and the sentence it failed with is shown: in the dialog for a
  // save, which stays open with what was typed, and on the page for the rest. A save that worked closes the dialog.
  const action = async (run: () => Promise<void>, inEditor = false) => {
    if (flight.current) return;
    flight.current = true; setBusy(true); setError(null); setEditorError(null);
    const failure = await runDatabaseAction(client, run);
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
    setEditing({ key: openings.current, ...(row ? { initial: row.database, expected: row.database } : { initial: newDatabase(), expected: null }) });
  };
  // Cancel, the X, Escape and a click outside all close the dialog from here: not while a save is under way, and only once the person
  // has said that changes may be lost.
  const closeEditor = () => {
    if (flight.current) return;
    if (dirty) setDiscarding(true);
    else setEditing(null);
  };
  const discard = () => { setDiscarding(false); setDirty(false); setEditing(null); };
  const save = (next: SavedDatabase) => { if (editing) void action(async () => { await saveDatabase(next, editing.expected); }, true); };
  // The grant is read again too, so that the row shows what was requested.
  const requestGrant = (id: string) => void action(async () => {
    try { await requestDatabaseGrant(id); }
    finally { await client.invalidateQueries({ queryKey: databasePamStatusKey(id) }); }
  });
  const toggleDetails = (id: string) => setOpened((current) => {
    const next = new Set(current);
    if (!next.delete(id)) next.add(id);
    return next;
  });
  // A delete can fail once the record is gone, and a dialog that stayed open would offer to delete it again: it closes either way, and
  // the failure is shown on the page beside the list that was read again.
  const remove = (row: DatabaseView) => void action(async () => {
    try { await deleteDatabase(row.database); }
    finally { setDeleting(null); }
  });
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
  return <div className="databases-panel space-y-5">
    <PageHeader title="Databases" count={rows.length} description="Cloud SQL connections that Lunport signs in to for your other apps."
      actions={<Button id="new-database-button" onClick={() => edit(null)} disabled={busy || !!overview.account && overview.shared_writes_blocked}><Plus className="size-4" />New database</Button>} />
    <div className="flex flex-wrap items-center gap-3">
      <div className="relative min-w-48 flex-1"><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><Input id="databases-search" aria-label="Search databases" placeholder="Search databases or projects…" className="pl-9" value={search} onChange={(e) => setSearch(e.target.value)} /></div>
      <span className="text-xs text-muted-foreground">{overview.account ? "Databases sync · Start separately on each device" : "Databases sync when you connect an account"}</span>
    </div>
    {(error || query.error) && <p role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error ?? revealHidden(String(query.error))}<Button variant="ghost" size="sm" onClick={() => void query.refetch()}>Refresh</Button></p>}
    {query.isPending ? <p role="status" className="py-12 text-center text-sm text-muted-foreground">Loading databases…</p> : rows.length === 0 ?
      <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-14 text-center">
        <Database className="size-7 text-muted-foreground" /><h2 className="font-medium">Your Cloud SQL databases, within reach</h2>
        <p className="max-w-sm text-sm text-muted-foreground">Save a PostgreSQL instance and Lunport offers it to your other apps on a local port, signed in with your Google account.</p>
      </div> : <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-left text-sm"><thead className="border-b bg-muted/30 text-xs text-muted-foreground"><tr><th className="px-4 py-3 font-medium">Database</th><th className="database-address-column px-4 py-3 font-medium">Local address</th><th className="px-4 py-3 font-medium">Status</th><th className="px-4 py-3"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>{visible.map((row) => {
          const id = row.database.id;
          // A database that is not offered on a port, or whose record is gone, has no details to give; if it loses its port while open, they close.
          const offered = hasConnectionDetails(row);
          const open = offered && opened.has(id);
          return <Fragment key={id}>
            <DatabaseRow row={row} busy={busy}
              toggle={() => toggle(row)}
              requestGrant={() => requestGrant(id)} ask={() => setDeleting(row)} edit={() => edit(row)}
              details={offered ? { open, toggle: () => toggleDetails(id) } : undefined} />
            {open && <tr className="border-b last:border-0"><td colSpan={4} className="px-4 pb-4"><div className="database-details"><DatabaseAccess row={row} /></div></td></tr>}
          </Fragment>;
        })}</tbody></table>
      {!visible.length && <p className="p-8 text-center text-sm text-muted-foreground">No databases match this search.</p>}
    </div>}
    <Dialog open={editing !== null} onOpenChange={(open) => { if (!open) closeEditor(); }}><TaskDialogContent className="sm:max-w-xl">
      <DialogHeader><DialogTitle>{shown?.expected ? "Edit database" : "New database"}</DialogTitle><DialogDescription>Lunport signs in with your Google account, asks for a PAM grant when the database needs one, and can open a local port for your other apps.</DialogDescription></DialogHeader>
      {shown && <DatabaseEditor key={shown.key} initial={shown.initial} existing={otherDatabases(rows, shown.initial.id)} busy={busy} error={editorError} onSave={save} onCancel={closeEditor} onDirty={setDirty} />}
    </TaskDialogContent></Dialog>
    <AlertDialog open={discarding} onOpenChange={setDiscarding}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Discard database changes?</AlertDialogTitle><AlertDialogDescription>Your unsaved changes will be lost.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Keep editing</AlertDialogCancel><AlertDialogAction onClick={discard}>Discard</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
    <StopDatabaseDialog row={askedToStop} busy={busy} onCancel={() => setStopping(null)} onStop={stop} />
    <AlertDialog open={!!deleting} onOpenChange={(open) => { if (!open && !busy) setDeleting(null); }}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Delete {deleting && revealHidden(deleting.database.name)}?</AlertDialogTitle><AlertDialogDescription>{deleting?.synced ? "This removes the saved database from your synced devices. A database already running on another device keeps running there until it is stopped." : "This removes the saved database."}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel><Button variant="destructive" disabled={busy} onClick={() => { if (deleting) remove(deleting); }}>Delete database</Button></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </div>;
}
