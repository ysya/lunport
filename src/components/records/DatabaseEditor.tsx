import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { RadioGroup } from "radix-ui";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { TaskDialogBody } from "@/components/app/TaskDialog";
import { revealHidden } from "@/lib/reveal-hidden";
import { useDebounced } from "@/lib/use-debounced";
import { cn, errorMessage } from "@/lib/utils";
import {
  connectionName,
  databaseInstancesQuery,
  parseConnectionName,
  suggestPort,
  type DatabaseEnvironment,
  type InstanceSummary,
  type SavedDatabase,
} from "@/lib/databases";
import { isProjectId, newPamCheck } from "@/lib/transports";
import { RecordField } from "./form";
import { choice, EntitlementsInput, EntitlementSuggestions, GoogleAccountField, segmented } from "./IapRouteFields";

/*
 * The dialog that adds a Cloud SQL database to the library or changes one: where the instance is (picked from the list Google gives
 * for a project, or typed as its connection name), which Google account signs in, what it is called, what it is used for, whether
 * connecting needs a PAM grant, and whether other apps may connect on a local port. The backend judges the values when the database is
 * saved and says why in a sentence, which the dialog shows; the dialog only keeps a database from being saved before it is anywhere.
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
const NO_PUBLIC_IP = "This instance has no public IP. Lunport connects over public IP in this release.";

/** Why an instance is listed but cannot be chosen, or null when it can. Without a public address nothing else about it matters. */
export function instanceProblem(instance: InstanceSummary): string | null {
  if (!instance.public_ip) return NO_PUBLIC_IP;
  return instance.iam_authentication ? null : IAM_OFF;
}

/** A project, a region and an instance: where a database is. */
type Place = { project: string; region: string; instance: string };
const nowhere = (project = ""): Place => ({ project, region: "", instance: "" });

/** Whether the database is somewhere: it has a project, a region and an instance. */
const located = (draft: SavedDatabase) => draft.project !== "" && draft.region !== "" && draft.instance !== "";

/**
 * `draft` moved to `place`. Its name follows the instance for as long as it is empty or still the name of the instance it was at, so
 * that picking or typing another instance renames it, and a name that was typed over it stays.
 */
function placed(draft: SavedDatabase, place: Place): SavedDatabase {
  const follows = draft.name.trim() === "" || draft.name === draft.instance;
  return { ...draft, ...place, name: follows ? place.instance : draft.name };
}

/** `draft` at the instance picked from the list, which starts again from the database `postgres`. */
export function pickInstance(draft: SavedDatabase, instance: InstanceSummary): SavedDatabase {
  return { ...placed(draft, { project: draft.project, region: instance.region, instance: instance.name }), default_database: "postgres" };
}

/** `draft` with the project typed in the list's project field: an instance picked in another project is no longer picked. */
export function withProject(draft: SavedDatabase, project: string): SavedDatabase {
  return project === draft.project ? draft : placed(draft, nowhere(project));
}

/** `draft` at the connection name as typed, or nowhere while the text is not a project, a region and an instance. */
export function withConnectionName(draft: SavedDatabase, text: string): SavedDatabase {
  return placed(draft, parseConnectionName(text) ?? nowhere());
}

const withPam = (draft: SavedDatabase, on: boolean): SavedDatabase => ({ ...draft, pam: on ? newPamCheck() : null });
const withEntitlements = (draft: SavedDatabase, entitlements: string[]): SavedDatabase => ({ ...draft, pam: draft.pam && { ...draft.pam, entitlements } });
const withSharing = (draft: SavedDatabase, on: boolean, used: number[]): SavedDatabase => ({ ...draft, local_port: on ? suggestPort(used) : null });

/** The database as it is saved: its typed names without the spaces around them. */
const finished = (draft: SavedDatabase): SavedDatabase => ({ ...draft, name: draft.name.trim(), default_database: draft.default_database.trim() });

/** The local ports the other databases hold. */
const usedPorts = (existing: SavedDatabase[]) => existing.flatMap((database) => database.local_port ?? []);

/** What the version of an instance reads as in the list: `POSTGRES_16` is PostgreSQL 16; a version in another form is shown as Google gives it. */
const versionName = (version: string) => {
  const major = /^POSTGRES_(\d+)$/.exec(version)?.[1];
  return major ? `PostgreSQL ${major}` : version || "PostgreSQL";
};

const addresses = (instance: InstanceSummary) =>
  instance.public_ip && instance.private_ip ? "Public IP and private IP" : instance.public_ip ? "Public IP" : instance.private_ip ? "Private IP only" : "No IP address";

const environments: [DatabaseEnvironment, string][] = [["dev", "Dev"], ["staging", "Staging"], ["prod", "Prod"]];

/*
 * The two drawings of the instance list below are plain functions rather than components: they hold no state and no hooks, and the
 * view's tests read the controls straight from the view's element tree.
 */

/** One instance of the list: a radio that cannot be chosen when the instance cannot be connected to, with the reason under it. */
function instanceRow(instance: InstanceSummary, chosen: boolean, onPick: () => void) {
  const problem = instanceProblem(instance);
  return (
    <label key={`${instance.region}/${instance.name}`} className={cn("flex items-start gap-3 px-3 py-2.5 text-sm", problem ? "cursor-not-allowed" : "cursor-pointer hover:bg-muted/40", chosen && "bg-primary/5")}>
      <input type="radio" name="database-instance" className="mt-1 accent-primary" checked={chosen} disabled={problem !== null} onChange={onPick} />
      <span className={cn("min-w-0 flex-1", problem && "text-muted-foreground")}>
        <span className="flex flex-wrap items-center gap-1.5 font-medium">
          {instance.name}
          <Badge variant="secondary">{versionName(instance.database_version)}</Badge>
        </span>
        <span className="block text-xs text-muted-foreground">{[instance.region, addresses(instance), ...(problem ? [] : ["IAM sign-in on"])].join(" · ")}</span>
        {problem && <span className="block text-xs text-warning">{problem}</span>}
      </span>
    </label>
  );
}

/** The instances of the project, to choose from, or why there are none to show yet. */
function instanceList(draft: SavedDatabase, instances: InstancesRead, onDraft: (next: SavedDatabase) => void) {
  const rows = instances.state === "listed" ? instances.instances : [];
  return (
    <fieldset className="min-w-0 space-y-2">
      <legend className="mb-2 p-0 text-sm font-medium">{isProjectId(draft.project) ? `Cloud SQL instances in ${draft.project}` : "Cloud SQL instances"}</legend>
      {rows.length > 0 && (
        <div className="divide-y overflow-hidden rounded-lg border">
          {rows.map((instance) =>
            instanceRow(instance, instance.name === draft.instance && instance.region === draft.region, () => onDraft(pickInstance(draft, instance))),
          )}
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
  draft: SavedDatabase;
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
  onDraft: (next: SavedDatabase) => void;
  onMode: (next: Mode) => void;
  onConnection: (text: string) => void;
  onSave: (next: SavedDatabase) => void;
  onCancel: () => void;
};

/**
 * The dialog's body and its buttons, drawn from the draft. No hooks: exported for the tests. Every control hands the whole next draft
 * to `onDraft`. Saving is held back while the database is nowhere, and while a save is under way every control is off.
 */
export function DatabaseEditorView({ draft, mode, connection, instances, lookup, used, busy, error, onDraft, onMode, onConnection, onSave, onCancel }: DatabaseEditorViewProps) {
  const patch = (changes: Partial<SavedDatabase>) => onDraft({ ...draft, ...changes });
  const ready = located(draft);
  const unreadable = connection.trim() !== "" && parseConnectionName(connection) === null;
  const chooseMode = (next: Mode) => {
    onMode(next);
    // The field shows the connection name of the instance picked, or nothing: never a name typed before that pick was taken back.
    if (next === "manual") onConnection(ready ? connectionName(draft) : "");
  };
  return (
    <>
      <form
        id="database-editor"
        className="contents"
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) onSave(finished(draft));
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
                {instanceList(draft, instances, onDraft)}
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
              <p className="text-xs text-muted-foreground">Prod is marked in red, and connections through the local port open read-only.</p>
            </div>
            <div className="space-y-3 rounded-lg border p-3">
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
          </fieldset>
        </TaskDialogBody>
      </form>
      <DialogFooter>
        {error && (
          <p role="alert" className="min-w-0 flex-1 basis-60 self-center text-sm text-destructive">
            {error}
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
  initial: SavedDatabase;
  /** The other saved databases, whose local ports a port proposed here skips. */
  existing: SavedDatabase[];
  busy: boolean;
  /** The sentence the last save failed with, if it did. */
  error: string | null;
  onSave: (next: SavedDatabase) => void;
  onCancel: () => void;
};

/** How long typing in the project or account must pause before Google is asked about what was typed. */
const LOOKUP_DELAY_MS = 400;

/**
 * The body and buttons of the New database / Edit database dialog, over `initial`. A saved database opens at its connection name, a new
 * one at the list of instances. The instances are read only while the list is shown. Google is asked about the account and project the
 * draft holds once typing in them has paused (`LOOKUP_DELAY_MS`), not about every start of a project id typed by hand; the dialog opens
 * with what it was given, without waiting.
 */
export function DatabaseEditor({ initial, existing, busy, error, onSave, onCancel }: DatabaseEditorProps) {
  const [draft, setDraft] = useState(initial);
  const [mode, setMode] = useState<Mode>(() => (initial.instance === "" ? "pick" : "manual"));
  const [connection, setConnection] = useState(() => (located(initial) ? connectionName(initial) : ""));
  const project = useDebounced(draft.project, LOOKUP_DELAY_MS);
  const account = useDebounced(draft.account, LOOKUP_DELAY_MS);
  const settled = project === draft.project && account === draft.account;
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
      onDraft={setDraft}
      onMode={setMode}
      onConnection={setConnection}
      onSave={onSave}
      onCancel={onCancel}
    />
  );
}
