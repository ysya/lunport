import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { LoaderCircle, Plus } from "lucide-react";
import { RadioGroup } from "radix-ui";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { TaskDialogBody } from "@/components/app/TaskDialog";
import type { RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/reveal-hidden";
import { useDebounced } from "@/lib/use-debounced";
import { cn, errorMessage } from "@/lib/utils";
import {
  HOST_UNAVAILABLE,
  connectionName,
  databaseInstancesQuery,
  jumpHostCandidates,
  libraryHosts,
  parseConnectionName,
  routeHost,
  suggestPort,
  type DatabaseDraft,
  type DatabaseEnvironment,
  type InstanceSummary,
  type JumpHost,
  type SavedDatabase,
} from "@/lib/databases";
import { isProjectId, newPamCheck } from "@/lib/transports";
import { RecordField } from "./form";
import { groupPath, recordHostSearchText } from "./group-tree";
import { choice, EntitlementsInput, EntitlementSuggestions, GoogleAccountField, segmented } from "./IapRouteFields";

/*
 * The dialog that adds a Cloud SQL database to the library or changes one: where the instance is (picked from the list Google gives
 * for a project, or typed as its connection name), the way it is reached (over its public IP, or over its private IP through a host of
 * the library), which Google account signs in, what it is called, what it is used for, whether connecting needs a PAM grant, and whether
 * other apps may connect on a local port. The backend judges the values when the database is saved and says why in a sentence, which the
 * dialog shows; the dialog only keeps a database from being saved before it is anywhere, and says to choose a host for one that goes
 * through none.
 *
 * `DatabaseEditor` keeps the state and reads what the view shows; `DatabaseEditorView` is the dialog's body and footer without hooks,
 * and decides every change to the draft, so that the tests can press it.
 */

/** How the instance is chosen: from the instances Google lists for a project, or by typing its connection name. */
export type Mode = "pick" | "manual";

/** Where the list of instances stands. */
export type InstancesRead =
  | { state: "waiting" }
  | { state: "loading" }
  | { state: "failed"; message: string }
  | { state: "listed"; instances: InstanceSummary[] };

/**
 * The list as its query left it for `project`: nothing to read until the project reads as one; then loading; the sentence the read
 * failed with, in place of any list an earlier read found; or the instances. While typing in the project or account is still going on
 * (`settled` is false) the query holds the answer for what was typed before, which is not shown as this project's: the list is loading.
 */
export function instancesRead(project: string, query: { data: InstanceSummary[] | undefined; isError: boolean; error: unknown }, settled = true): InstancesRead {
  if (!isProjectId(project)) return { state: "waiting" };
  if (!settled) return { state: "loading" };
  if (query.isError) return { state: "failed", message: revealHidden(errorMessage(query.error)) };
  return query.data ? { state: "listed", instances: query.data } : { state: "loading" };
}

const IAM_OFF = "IAM sign-in is off on this instance.";
/** What Save says of a database over its private IP that goes through no host yet. */
const NO_HOST = "Choose a host to connect through.";

/**
 * Why an instance is listed but cannot be chosen, or null when it can. An instance without a public IP can be chosen: it is reached
 * through a host of the library, and its start says so when it has no private IP either.
 */
export function instanceProblem(instance: InstanceSummary): string | null {
  return instance.iam_authentication ? null : IAM_OFF;
}

/** A project, a region and an instance: where a database is. */
type Place = { project: string; region: string; instance: string };
const nowhere = (project = ""): Place => ({ project, region: "", instance: "" });

/** Whether the database is somewhere: it has a project, a region and an instance. */
const located = (draft: DatabaseDraft) => draft.project !== "" && draft.region !== "" && draft.instance !== "";

/**
 * `draft` moved to `place`. Its name follows the instance for as long as it is empty or still the name of the instance it was at, so
 * that picking or typing another instance renames it, and a name that was typed over it stays.
 */
function placed(draft: DatabaseDraft, place: Place): DatabaseDraft {
  const follows = draft.name.trim() === "" || draft.name === draft.instance;
  return { ...draft, ...place, name: follows ? place.instance : draft.name };
}

/**
 * `draft` over its public IP, naming no host. The field stays, empty, where the draft has it, so that a host chosen again lands in the
 * same place and the draft reads as unchanged (`changed`); `finished` leaves it out of the saved database.
 */
const overPublicIp = (draft: DatabaseDraft): DatabaseDraft => ({ ...draft, network: "public", via_host: undefined });
/** `draft` over its private IP through the library host `host`, or through none yet. */
const throughHost = (draft: DatabaseDraft, host: string | undefined): DatabaseDraft => ({ ...draft, network: "private", via_host: host });

/** The host `draft` goes through, or none: over its public IP, or over its private IP before a host is chosen. */
const chosenHost = (draft: DatabaseDraft): string | null => routeHost(draft) || null;
/** Whether `draft` is over its private IP and goes through no host yet, which it cannot be saved as. */
const hostless = (draft: DatabaseDraft) => draft.network === "private" && chosenHost(draft) === null;

/**
 * `draft` at the instance picked from the list, which starts again from the database `postgres` and goes the way the instance is
 * reached: over its public IP when it has one, else through the one jump host of its project (`candidates`), or through none yet when
 * there are several to choose from, or none.
 */
export function pickInstance(draft: DatabaseDraft, instance: InstanceSummary, candidates: JumpHost[] = []): DatabaseDraft {
  const moved = { ...placed(draft, { project: draft.project, region: instance.region, instance: instance.name }), default_database: "postgres" };
  if (instance.public_ip) return overPublicIp(moved);
  return throughHost(moved, candidates.length === 1 ? candidates[0].id : undefined);
}

/** `draft` with the project typed in the list's project field: an instance picked in another project is no longer picked. */
export function withProject(draft: DatabaseDraft, project: string): DatabaseDraft {
  return project === draft.project ? draft : placed(draft, nowhere(project));
}

/** `draft` at the connection name as typed, or nowhere while the text is not a project, a region and an instance. */
export function withConnectionName(draft: DatabaseDraft, text: string): DatabaseDraft {
  return placed(draft, parseConnectionName(text) ?? nowhere());
}

const withPam = (draft: DatabaseDraft, on: boolean): DatabaseDraft => ({ ...draft, pam: on ? newPamCheck() : null });
const withEntitlements = (draft: DatabaseDraft, entitlements: string[]): DatabaseDraft => ({ ...draft, pam: draft.pam && { ...draft.pam, entitlements } });
const withSharing = (draft: DatabaseDraft, on: boolean, used: number[]): DatabaseDraft => ({ ...draft, local_port: on ? suggestPort(used) : null });

/** Whether the draft is no longer the database the dialog opened with: any field that differs, typed and typed back counting as none. */
export function changed(draft: DatabaseDraft, opened: DatabaseDraft): boolean {
  return JSON.stringify(draft) !== JSON.stringify(opened);
}

/**
 * The database as it is saved: its typed names without the spaces around them, and the host it goes through only when it is over its
 * private IP. None while no environment is chosen, which a record needs.
 */
function finished(draft: DatabaseDraft): SavedDatabase | null {
  if (draft.environment === null) return null;
  const { via_host: host, ...fields } = draft;
  const saved: SavedDatabase = { ...fields, environment: draft.environment, name: draft.name.trim(), default_database: draft.default_database.trim() };
  return draft.network === "private" && host !== undefined ? { ...saved, via_host: host } : saved;
}

/** The local ports the other databases hold. */
const usedPorts = (existing: SavedDatabase[]) => existing.flatMap((database) => database.local_port ?? []);

/**
 * The draft a dialog opens with: the database as it is, except a new one (it has no identity yet), which starts offered to other apps on
 * the first free port from 6543, since the local port is the only way to use a saved database in this release. A saved database keeps
 * its own setting.
 */
export function opening(initial: DatabaseDraft, existing: SavedDatabase[]): DatabaseDraft {
  return initial.id === "" ? { ...initial, local_port: suggestPort(usedPorts(existing)) } : initial;
}

/** What the version of an instance reads as in the list: `POSTGRES_16` is PostgreSQL 16; a version in another form is shown as Google gives it. */
const versionName = (version: string) => {
  const major = /^POSTGRES_(\d+)$/.exec(version)?.[1];
  return major ? `PostgreSQL ${major}` : version || "PostgreSQL";
};

const addresses = (instance: InstanceSummary) =>
  instance.public_ip && instance.private_ip ? "Public IP and private IP" : instance.public_ip ? "Public IP" : instance.private_ip ? "Private IP only" : "No IP address";

const environments: [DatabaseEnvironment, string][] = [["dev", "Dev"], ["staging", "Staging"], ["prod", "Prod"]];

/** The alias of the library host `id`, or none when this computer has not got it. */
const aliasOf = (overview: RecordOverview, id: string) => overview.hosts.find((host) => host.id === id)?.payload.alias ?? null;

/**
 * What the list says, after the addresses of an instance without a public IP, of the host it goes through. The instance picked says the
 * draft's way: the host chosen (or that it is unavailable), else that a host is to be chosen or that a jump host is needed; over the
 * public IP, nothing. Any other says what picking it does: the one jump host of the project it takes, else that there are several to
 * choose from, or none.
 */
function hostNote(instance: InstanceSummary, chosen: boolean, draft: DatabaseDraft, candidates: JumpHost[], overview: RecordOverview): string | null {
  if (instance.public_ip) return null;
  const unchosen = candidates.length === 0 ? "Needs a jump host" : "Choose a host";
  if (!chosen) return candidates.length === 1 ? `via ${revealHidden(candidates[0].alias)}` : unchosen;
  const host = chosenHost(draft);
  if (host === null) return draft.network === "private" ? unchosen : null;
  const alias = aliasOf(overview, host);
  return alias === null ? HOST_UNAVAILABLE : `via ${revealHidden(alias)}`;
}

/*
 * The two drawings of the instance list below are plain functions rather than components: they hold no state and no hooks, and the
 * view's tests read the controls straight from the view's element tree.
 */

/**
 * One instance of the list: a radio that cannot be chosen when the instance cannot be connected to, with the reason under it. One that
 * can be says, after its addresses, the `note` of the host it goes through (`hostNote`).
 */
function instanceRow(instance: InstanceSummary, chosen: boolean, note: string | null, onPick: () => void) {
  const problem = instanceProblem(instance);
  const facts = [instance.region, addresses(instance), ...(problem === null && note !== null ? [note] : []), ...(problem ? [] : ["IAM sign-in on"])];
  return (
    <label key={`${instance.region}/${instance.name}`} className={cn("flex items-start gap-3 px-3 py-2.5 text-sm", problem ? "cursor-not-allowed" : "cursor-pointer hover:bg-muted/40", chosen && "bg-primary/5")}>
      <input type="radio" name="database-instance" className="mt-1 accent-primary" checked={chosen} disabled={problem !== null} onChange={onPick} />
      <span className={cn("min-w-0 flex-1", problem && "text-muted-foreground")}>
        <span className="flex flex-wrap items-center gap-1.5 font-medium">
          {instance.name}
          <Badge variant="secondary">{versionName(instance.database_version)}</Badge>
        </span>
        <span className="block text-xs text-muted-foreground">{facts.join(" · ")}</span>
        {problem && <span className="block text-xs text-warning">{problem}</span>}
      </span>
    </label>
  );
}

/** The instances of the project, to choose from, or why there are none to show yet; `candidates` are the jump hosts of the project. */
function instanceList(draft: DatabaseDraft, instances: InstancesRead, candidates: JumpHost[], overview: RecordOverview, onDraft: (next: DatabaseDraft) => void) {
  const rows = instances.state === "listed" ? instances.instances : [];
  return (
    <fieldset className="min-w-0 space-y-2">
      <legend className="mb-2 p-0 text-sm font-medium">{isProjectId(draft.project) ? `Cloud SQL instances in ${draft.project}` : "Cloud SQL instances"}</legend>
      {rows.length > 0 && (
        <div className="divide-y overflow-hidden rounded-lg border">
          {rows.map((instance) => {
            const chosen = instance.name === draft.instance && instance.region === draft.region;
            return instanceRow(instance, chosen, hostNote(instance, chosen, draft, candidates, overview), () => onDraft(pickInstance(draft, instance, candidates)));
          })}
        </div>
      )}
      {instances.state === "waiting" && <p className="text-xs text-muted-foreground">Enter a project id to list its Cloud SQL instances.</p>}
      {instances.state === "loading" && (
        <p role="status" className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <LoaderCircle className="size-3 animate-spin" aria-hidden="true" />
          Loading instances…
        </p>
      )}
      {instances.state === "failed" && (
        <p role="alert" className="text-sm text-destructive">
          {instances.message}
        </p>
      )}
      {instances.state === "listed" && rows.length === 0 && <p className="text-xs text-muted-foreground">No PostgreSQL instances in {draft.project}.</p>}
      {rows.length > 0 && <p className="text-xs text-muted-foreground">Listed from the Cloud SQL Admin API with your Google account. Choosing one fills in the settings below.</p>}
    </fieldset>
  );
}

export type DatabaseEditorViewProps = {
  draft: DatabaseDraft;
  mode: Mode;
  /** The connection name as typed, which may not read as one yet. */
  connection: string;
  instances: InstancesRead;
  /** The account and project Google is asked about for the grant check's suggestions: the draft's, once typing in them has paused. */
  lookup: { account: string | null; project: string };
  /** The local ports the other databases hold. */
  used: number[];
  busy: boolean;
  /** The sentence the last save failed with. */
  error: string | null;
  /** The library: the hosts the Route field offers, and the jump hosts of the draft's project. */
  overview: RecordOverview;
  /** Whether Save was pressed while the draft went through no host, so that the dialog says to choose one while it still does. */
  hostMissing: boolean;
  routeSearch: string;
  onRouteSearch: (text: string) => void;
  onDraft: (next: DatabaseDraft) => void;
  onMode: (next: Mode) => void;
  onConnection: (text: string) => void;
  onSave: (next: SavedDatabase) => void;
  /** Told when Save is pressed while the draft is over its private IP and goes through no host. */
  onHostMissing: () => void;
  onCancel: () => void;
  /** New IAP host: the page closes the dialog as Cancel does and opens the host editor for a host that connects through IAP. */
  createIapHost: () => void;
};

/**
 * The dialog's body and its buttons, drawn from the draft. No hooks: exported for the tests. Every control hands the whole next draft
 * to `onDraft`. Saving is held back while the database is nowhere and while no environment is chosen, which a new database starts
 * without, and while a save is under way every control is off. Save on a database over its private IP that goes through no host saves
 * nothing and says to choose one; with no jump host in the project the Route field offers New IAP host.
 */
export function DatabaseEditorView(props: DatabaseEditorViewProps) {
  const { draft, mode, connection, instances, lookup, used, busy, error, overview, hostMissing, routeSearch, onRouteSearch, onDraft, onMode, onConnection, onSave, onHostMissing, onCancel, createIapHost } = props;
  const patch = (changes: Partial<DatabaseDraft>) => onDraft({ ...draft, ...changes });
  const ready = located(draft) && draft.environment !== null;
  const unreadable = connection.trim() !== "" && parseConnectionName(connection) === null;
  const candidates = jumpHostCandidates(overview, draft.project);
  const hosts = libraryHosts(overview);
  const host = chosenHost(draft);
  const selectedEntry = overview.hosts.find((entry) => entry.id === host);
  const selectedPath = selectedEntry ? groupPath(overview, selectedEntry.payload.group_id, selectedEntry.scope) : "";
  const routeWords = routeSearch.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
  const initialSuggested = candidates.slice(0, 6);
  const initialIds = new Set(initialSuggested.map((candidate) => candidate.id));
  const selectedOther = hosts.find((candidate) => candidate.id === host && !initialIds.has(candidate.id));
  const matchingHosts = routeWords.length ? hosts.filter((candidate) => {
    const entry = overview.hosts.find((item) => item.id === candidate.id);
    return entry && routeWords.every((word) => recordHostSearchText(overview, entry).toLocaleLowerCase().includes(word));
  }) : [];
  const routeSections = routeWords.length
    ? [{ label: "Matching hosts", hosts: matchingHosts }]
    : [
      { label: "Selected host", hosts: selectedOther ? [selectedOther] : [] },
      { label: "Suggested for this project", hosts: initialSuggested },
    ];
  const missing = hostless(draft);
  // A host the library no longer has stays the route until another is chosen, and the field shows it as unavailable.
  const unavailable = host !== null && !hosts.some((candidate) => candidate.id === host);
  const alert = hostMissing && missing ? NO_HOST : error;
  const chooseMode = (next: Mode) => {
    onMode(next);
    // The field shows the connection name of the instance picked, or nothing: never a name typed before that pick was taken back.
    if (next === "manual") onConnection(located(draft) ? connectionName(draft) : "");
  };
  return (
    <>
      <form
        id="database-editor"
        className="contents"
        onSubmit={(event) => {
          event.preventDefault();
          const saved = finished(draft);
          if (!located(draft) || !saved) return;
          if (missing) onHostMissing();
          else onSave(saved);
        }}
      >
        <TaskDialogBody>
          <fieldset disabled={busy} className="min-w-0 space-y-4">
            <div className="space-y-2">
              <p className="text-sm font-medium">Instance</p>
              {/* Its two choices are long: on a narrow screen they stack rather than push the dialog wider than it is. */}
              <RadioGroup.Root aria-label="How to choose the instance" value={mode} onValueChange={(next) => chooseMode(next as Mode)} className={cn(segmented, "flex-col sm:flex-row")}>
                <RadioGroup.Item value="pick" className={choice}>
                  Pick from Google Cloud
                </RadioGroup.Item>
                <RadioGroup.Item value="manual" className={choice}>
                  Enter a connection name
                </RadioGroup.Item>
              </RadioGroup.Root>
            </div>
            <GoogleAccountField account={draft.account} onChange={(account) => patch({ account })} disabled={busy} />
            {mode === "pick" ? (
              <>
                <RecordField label="Project">
                  <Input value={draft.project} placeholder="my-project-123456" onChange={(event) => onDraft(withProject(draft, event.target.value.trim()))} />
                </RecordField>
                {instanceList(draft, instances, candidates, overview, onDraft)}
              </>
            ) : (
              <RecordField label="Connection name">
                <Input
                  className="font-mono"
                  value={connection}
                  placeholder="my-project-123456:asia-east1:my-instance"
                  onChange={(event) => {
                    onConnection(event.target.value);
                    onDraft(withConnectionName(draft, event.target.value));
                  }}
                />
                <p className={cn("text-xs", unreadable ? "text-destructive" : "text-muted-foreground")}>
                  {unreadable ? "Enter the project, region and instance, separated by colons." : "As the Google Cloud console shows it: project:region:instance."}
                </p>
              </RecordField>
            )}
            {located(draft) && <>
              <div className="border-t pt-4">
                <h3 className="text-sm font-medium">Connection</h3>
                <p className="text-xs text-muted-foreground">Name this connection and choose how Lunport reaches it.</p>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-medium">Route</p>
                <RadioGroup.Root aria-label="Route" value={draft.network} disabled={busy}
                  onValueChange={(network) => { onRouteSearch(""); onDraft(network === "public" ? overPublicIp(draft) : throughHost(draft, host ?? undefined)); }}
                  className={segmented}>
                  <RadioGroup.Item value="public" className={choice}>Public IP</RadioGroup.Item>
                  <RadioGroup.Item value="private" className={choice}>Through a host</RadioGroup.Item>
                </RadioGroup.Root>
                {draft.network === "private" && <div className="space-y-2">
                  <p className={cn("text-xs", unavailable ? "text-warning" : "text-muted-foreground")}>
                    {unavailable ? HOST_UNAVAILABLE : host ? `Selected host: ${revealHidden([selectedEntry?.payload.alias, selectedPath].filter(Boolean).join(" · "))}` : "Choose a host to connect through."}
                  </p>
                  <Command shouldFilter={false} className="h-auto rounded-lg border bg-background">
                    <CommandInput aria-label="Search route hosts" placeholder="Search hosts by name, address or Group…" disabled={busy}
                      value={routeSearch} onValueChange={onRouteSearch} />
                    <CommandList className="max-h-60">
                      <CommandEmpty>{routeWords.length ? "No matching hosts." : hosts.length ? "Search to find other hosts." : "No hosts available."}</CommandEmpty>
                      {routeSections.map((section) => section.hosts.length > 0 && <CommandGroup key={section.label} heading={section.label}>
                        {section.hosts.map((candidate) => {
                          const entry = overview.hosts.find((item) => item.id === candidate.id)!;
                          const group = groupPath(overview, entry.payload.group_id, entry.scope);
                          return <CommandItem key={candidate.id} value={recordHostSearchText(overview, entry)} data-checked={host === candidate.id} disabled={busy}
                            onSelect={() => { onDraft(throughHost(draft, candidate.id)); onRouteSearch(""); }}>
                            <span className="min-w-0 flex-1">
                              <span className="block truncate font-medium">{revealHidden(candidate.alias)}</span>
                              <span className="block truncate text-xs text-muted-foreground">{revealHidden([entry.effective_payload.hostname, group].filter(Boolean).join(" · "))}</span>
                            </span>
                          </CommandItem>;
                        })}
                      </CommandGroup>)}
                    </CommandList>
                  </Command>
                  {!routeWords.length && hosts.length > initialSuggested.length + (selectedOther ? 1 : 0) &&
                    <p className="text-xs text-muted-foreground">Search to find other hosts by name, address, or Group path.</p>}
                  {missing && candidates.length === 0 && <Button type="button" variant="outline" size="sm" className="w-fit" onClick={createIapHost}>
                    <Plus />New IAP host
                  </Button>}
                </div>}
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <RecordField label="Name">
                  <Input value={draft.name} maxLength={128} required placeholder="Orders" onChange={(event) => patch({ name: event.target.value })} />
                </RecordField>
                <RecordField label="Default database">
                  <Input value={draft.default_database} maxLength={63} required placeholder="postgres" onChange={(event) => patch({ default_database: event.target.value })} />
                </RecordField>
              </div>
              <div className="space-y-2">
                <p className="text-sm font-medium">Environment</p>
                <RadioGroup.Root
                  aria-label="Environment"
                  value={draft.environment}
                  onValueChange={(environment) => patch({ environment: environment as DatabaseEnvironment })}
                  className={segmented}
                >
                  {environments.map(([value, label]) => (
                    <RadioGroup.Item key={value} value={value} className={choice}>
                      {label}
                    </RadioGroup.Item>
                  ))}
                </RadioGroup.Root>
                {draft.environment === null && <p className="text-xs text-muted-foreground">Choose Dev, Staging or Prod.</p>}
                <p className="text-xs text-muted-foreground">Prod is marked in red, and connections through the local port open read-only.</p>
              </div>
              <div className="border-t pt-4">
                <h3 className="text-sm font-medium">Local access</h3>
              </div>
              <div className="space-y-3 rounded-lg border p-3">
                <label className="flex items-start gap-3 text-sm">
                  <Switch className="mt-0.5" checked={draft.local_port !== null} onCheckedChange={(on) => onDraft(withSharing(draft, on, used))} />
                  <span>
                    Let other apps connect
                    <span className="block text-xs text-muted-foreground">
                      Other apps on this computer, such as psql, connect to 127.0.0.1 with a password Lunport makes and keeps in the keychain.
                    </span>
                  </span>
                </label>
                {draft.local_port !== null && (
                  <RecordField label="Port on 127.0.0.1">
                    {/* A cleared field shows nothing rather than a 0 to delete; the backend says what it thinks of the port. */}
                    <Input
                      className="max-w-32 font-mono"
                      type="number"
                      min={1024}
                      max={65535}
                      value={draft.local_port || ""}
                      onChange={(event) => patch({ local_port: Number(event.target.value) })}
                    />
                  </RecordField>
                )}
              </div>
              <details open={draft.pam !== null} className="rounded-lg border p-3">
                <summary className="cursor-pointer text-sm font-medium">Advanced access</summary>
                <div className="mt-3 space-y-3">
                  <label className="flex items-start gap-3 text-sm">
                    <Switch className="mt-0.5" checked={draft.pam !== null} onCheckedChange={(on) => onDraft(withPam(draft, on))} />
                    <span>
                      Requires a PAM grant
                      <span className="block text-xs text-muted-foreground">When no grant is active, connecting asks for one first.</span>
                    </span>
                  </label>
                  {draft.pam && (
                    <RecordField label="Entitlements">
                      <EntitlementsInput value={draft.pam.entitlements} disabled={busy} onChange={(entitlements) => onDraft(withEntitlements(draft, entitlements))} />
                      <EntitlementSuggestions
                        account={lookup.account}
                        project={lookup.project}
                        pam={draft.pam}
                        disabled={busy}
                        onAdd={(id) => onDraft(withEntitlements(draft, [...(draft.pam?.entitlements ?? []), id]))}
                      />
                    </RecordField>
                  )}
                </div>
              </details>
            </>}
          </fieldset>
        </TaskDialogBody>
      </form>
      <DialogFooter>
        {alert && (
          <p role="alert" className="min-w-0 flex-1 basis-60 self-center text-sm text-destructive">
            {alert}
          </p>
        )}
        <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" form="database-editor" disabled={busy || !ready}>
          {busy && <LoaderCircle className="size-3 animate-spin" />}
          Save database
        </Button>
      </DialogFooter>
    </>
  );
}

export type DatabaseEditorProps = {
  /** The database to start from: a new one, or the saved one that is being changed. */
  initial: DatabaseDraft;
  /** The other saved databases, whose local ports a port proposed here skips. */
  existing: SavedDatabase[];
  /** The library, whose hosts a database can be reached through. */
  overview: RecordOverview;
  busy: boolean;
  /** The sentence the last save failed with, if it did. */
  error: string | null;
  onSave: (next: SavedDatabase) => void;
  onCancel: () => void;
  /** New IAP host: closes the dialog as Cancel does, then opens the host editor for a host that connects through IAP. */
  createIapHost: () => void;
  /** Told after every change whether the draft now differs from the database the dialog opened with, so that closing it can ask first. */
  onDirty?: (dirty: boolean) => void;
};

/** How long typing in the project or account must pause before Google is asked about what was typed. */
const LOOKUP_DELAY_MS = 400;

/**
 * The body and buttons of the New database / Edit database dialog, over `initial`. A saved database opens as it is saved, at its
 * connection name; a new one at the list of instances, offered to other apps (`opening`). The instances are read only while the list is
 * shown. Google is asked about the account and project the draft holds once typing in them has paused (`LOOKUP_DELAY_MS`), not about
 * every start of a project id typed by hand; the dialog opens with what it was given, without waiting.
 */
export function DatabaseEditor({ initial, existing, overview, busy, error, onSave, onCancel, createIapHost, onDirty }: DatabaseEditorProps) {
  const [opened] = useState(() => opening(initial, existing));
  const [draft, setDraft] = useState(opened);
  const [mode, setMode] = useState<Mode>(() => (initial.instance === "" ? "pick" : "manual"));
  const [connection, setConnection] = useState(() => (located(initial) ? connectionName(initial) : ""));
  const [hostMissing, setHostMissing] = useState(false);
  const [routeSearch, setRouteSearch] = useState("");
  const project = useDebounced(draft.project, LOOKUP_DELAY_MS);
  const account = useDebounced(draft.account, LOOKUP_DELAY_MS);
  const settled = project === draft.project && account === draft.account;
  // Every change to the draft comes through here, and says whether the draft still is what the dialog opened with.
  const change = (next: DatabaseDraft) => {
    setDraft(next);
    onDirty?.(changed(next, opened));
  };
  const list = useQuery({ ...databaseInstancesQuery(account, project), enabled: mode === "pick" && isProjectId(project) });
  return (
    <DatabaseEditorView
      draft={draft}
      mode={mode}
      connection={connection}
      instances={instancesRead(draft.project, list, settled)}
      lookup={{ account, project }}
      used={usedPorts(existing)}
      busy={busy}
      error={error}
      overview={overview}
      hostMissing={hostMissing}
      routeSearch={routeSearch}
      onRouteSearch={setRouteSearch}
      onDraft={change}
      onMode={setMode}
      onConnection={setConnection}
      onSave={onSave}
      onHostMissing={() => setHostMissing(true)}
      onCancel={onCancel}
      createIapHost={createIapHost}
    />
  );
}
