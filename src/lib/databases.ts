import { queryOptions, type QueryClient } from "@tanstack/react-query";
import { tauriInvoke } from "./ipc";
import { grantHeld, isProjectId, pamStatusOptions, tunnelGrantLine, type PamCheck, type PamStatusView } from "./transports";
import { revealHidden } from "./reveal-hidden";
import { errorMessage } from "./utils";
import type { SavedDatabase } from "@/bindings/SavedDatabase";
import type { DatabaseView } from "@/bindings/DatabaseView";
import type { DatabaseLive } from "@/bindings/DatabaseLive";
import type { DatabasePhase } from "@/bindings/DatabasePhase";
import type { DatabaseEnvironment } from "@/bindings/DatabaseEnvironment";
import type { DatabaseEngine } from "@/bindings/DatabaseEngine";
import type { InstanceSummary } from "@/bindings/InstanceSummary";
import type { UnlockMethod } from "@/bindings/UnlockMethod";
export type { SavedDatabase, DatabaseView, DatabaseLive, DatabasePhase, DatabaseEnvironment, InstanceSummary, UnlockMethod };

export const databasesKey = ["databases"] as const;
export const listDatabases = () => tauriInvoke<DatabaseView[]>("databases_list");
/** The saved databases and what this device runs for them, read when the page opens and every 1.5 seconds while it stays open. */
export const databasesQuery = queryOptions({ queryKey: databasesKey, queryFn: listDatabases, refetchInterval: 1500 });
/** Saves the database (a new one when its id is empty) and answers it as the list shows it from then on: pass that as the next `expected`. */
export const saveDatabase = (database: SavedDatabase, expected: SavedDatabase | null) => tauriInvoke<SavedDatabase>("databases_save", { database, expected });
export const deleteDatabase = (expected: SavedDatabase) => tauriInvoke<void>("databases_delete", { expected });
/** Offers the database on its local port. */
export const startDatabase = (id: string) => tauriInvoke<void>("databases_start", { id });
/** Closes the database's local port and its connections. */
export const stopDatabase = (id: string) => tauriInvoke<void>("databases_stop", { id });
/** Opens the Request-a-grant window for the grant the database needs and answers when the grant is active, or fails with the sentence of why not. */
export const requestDatabaseGrant = (id: string) => tauriInvoke<void>("databases_request_grant", { id });
/** The password apps sign in to the database's local port with; the first ask makes it, so it is there before the database starts. */
export const databasePassword = (id: string) => tauriInvoke<string>("databases_port_password", { id });
/** Replaces the port's password and answers the new one. Connections that are open go on; new ones need it. */
export const rotateDatabasePassword = (id: string) => tauriInvoke<string>("databases_rotate_port_password", { id });
/** How this computer confirms an unlock: "system" asks for Touch ID or the Mac's password itself; "dialog" needs the page's own confirmation first. */
export const unlockMethod = () => tauriInvoke<UnlockMethod>("os_unlock_method");
/** Unlocks writes on a running prod database's local port for 15 minutes and answers when they lock again, in milliseconds since the Unix epoch. Pass `confirmedInApp` once the page's own dialog was confirmed; where the system asks, it is not enough. */
export const unlockDatabaseWrites = (id: string, confirmedInApp: boolean) => tauriInvoke<number>("databases_unlock_writes", { id, confirmedInApp });
/** Locks writes on the database's local port again before the 15 minutes are up. */
export const lockDatabaseWrites = (id: string) => tauriInvoke<void>("databases_lock_writes", { id });
/** Closes the database's idle locked connections, so that their apps connect again (unlocked while writes are), and answers how many it closed. */
export const reconnectLockedConnections = (id: string) => tauriInvoke<number>("databases_reconnect_locked", { id });

/** A database to fill in: PostgreSQL over the public address, labelled dev, offered on no local port. */
export function newDatabase(): SavedDatabase {
  return {
    id: "",
    name: "",
    engine: "postgres",
    project: "",
    region: "",
    instance: "",
    environment: "dev",
    network: "public",
    account: null,
    default_database: "postgres",
    pam: null,
    local_port: null,
  };
}

/** What Cloud SQL calls the instance: `project:region:instance`. */
export function connectionName(d: SavedDatabase): string {
  return `${d.project}:${d.region}:${d.instance}`;
}

/** The three parts of a pasted connection name, each trimmed, or null when the text is not exactly three parts with something in each. Their values are judged when the database is saved. */
export function parseConnectionName(text: string): { project: string; region: string; instance: string } | null {
  const parts = text.split(":").map((part) => part.trim());
  if (parts.length !== 3 || parts.some((part) => part === "")) return null;
  const [project, region, instance] = parts;
  return { project, region, instance };
}

/**
 * The PostgreSQL instances `account` (none: gcloud's active account) can list in `project`, for the New database dialog's picker. Read
 * once the project reads as one, and kept for a minute. Not retried, and read even when the webview thinks it is offline, as the
 * accounts are: the answer comes from this app's backend, which says in its own sentence when Google cannot be reached or the Cloud SQL
 * Admin API is not enabled in the project.
 */
export const databaseInstancesQuery = (account: string | null, project: string) =>
  queryOptions({
    queryKey: ["gcp", "sql-instances", account, project],
    queryFn: () => tauriInvoke<InstanceSummary[]>("databases_list_instances", { account, project }),
    enabled: isProjectId(project),
    staleTime: 60_000,
    retry: false,
    networkMode: "always",
  });

/** The first local port from 6543 up that none of `used` holds: what the editor proposes when a database is offered to other apps. */
export function suggestPort(used: number[]): number {
  const taken = new Set(used);
  let port = 6543;
  while (taken.has(port)) port += 1;
  return port;
}

/** The databases of `rows` other than the one with identity `id`, which hold the ports its editor must not propose. A new database has no row of its own. */
export const otherDatabases = (rows: DatabaseView[], id: string): SavedDatabase[] => rows.filter((row) => row.database.id !== id).map((row) => row.database);

/** The query key of the grant a database needs, under the keys of the hosts' grants. */
export const databasePamStatusKey = (id: string) => ["gcp", "pam-status", "database", id] as const;
/** A database's grant as its row keeps it: read when the row shows, and kept as a host's grant is (`pamStatusOptions`). */
export const databasePamStatusQuery = (id: string) =>
  queryOptions({
    queryKey: databasePamStatusKey(id),
    queryFn: () => tauriInvoke<PamStatusView>("databases_pam_status", { id }),
    ...pamStatusOptions,
  });

/** How a phase reads in the Status column. */
export const databasePhases: Record<DatabasePhase, string> = { stopped: "Stopped", starting: "Starting", running: "Running", stopping: "Stopping", error: "Failed" };
const engines: Record<DatabaseEngine, string> = { postgres: "PostgreSQL" };

/** Whether the database's port is starting, running or stopping on this computer: it is not changed then. */
export const databaseBusy = (row: DatabaseView) => ["starting", "running", "stopping"].includes(row.live.phase);

/** Where the database comes from, as the row names it: `PostgreSQL · project · region · instance`. */
export const databaseRoute = (d: SavedDatabase) => `${engines[d.engine]} · ${d.project} · ${d.region} · ${d.instance}`;

/** The port apps reach the database on: the one that runs, else the one saved; none for a database that is not offered on a port. */
export const databasePort = (row: DatabaseView): number | null => row.live.port ?? row.database.local_port;

/** Where apps reach the database on this computer: the port that runs, else the one saved; "Not shared" for a database with none. */
export function localAddress(row: DatabaseView): string {
  const port = databasePort(row);
  return port === null ? "Not shared" : `127.0.0.1:${port}`;
}

/** Whether the page has connection details to give for the database: it is offered on a port, and its record is not gone. */
export const hasConnectionDetails = (row: DatabaseView): boolean => !row.removed && databasePort(row) !== null;

/** What the address names as the database user while no Google account is known. Lunport signs in as the real user whatever an app sends. */
export const UNKNOWN_IAM_USER = "your-google-account";
const SERVICE_ACCOUNT_SUFFIX = ".gserviceaccount.com";

/**
 * The database user the address names, as the backend names the IAM user of an account: the email, and for a service account the email
 * without a trailing `.gserviceaccount.com`. The account is the database's own, else the one gcloud is signed in as (`active`); with
 * neither known it is `UNKNOWN_IAM_USER`, so that the address still copies.
 */
export function iamUserFor(account: string | null, active: string | null): string {
  const email = account ?? active;
  if (!email) return UNKNOWN_IAM_USER;
  return email.endsWith(SERVICE_ACCOUNT_SUFFIX) ? email.slice(0, -SERVICE_ACCOUNT_SUFFIX.length) : email;
}

/**
 * The address apps connect to: `postgresql://user@127.0.0.1:port/database`, with the user and the database encoded. It holds no password:
 * that is copied on its own. The database must have a local port (`hasConnectionDetails`); the card draws no address for one without.
 */
export const connectionUrl = (db: SavedDatabase, iamUser: string): string =>
  `postgresql://${encodeURIComponent(iamUser)}@127.0.0.1:${db.local_port}/${encodeURIComponent(db.default_database)}`;

/**
 * How many whole seconds of the writable window are left at `now`, rounded up so that the last part of a second still counts as one
 * (the countdown never reads zero while writes are on). None while writes are locked, once the window has ended, and for a time that
 * is not one. Both times are in milliseconds since the Unix epoch.
 */
export function writableSecondsLeft(untilMs: number | null, now: number): number | null {
  if (untilMs === null || !(untilMs > now)) return null;
  return Math.ceil((untilMs - now) / 1000);
}

/** The time left of the writable window as `mm:ss`, such as `14:59`; none while writes are locked or once the window has ended. */
export function writableLeft(untilMs: number | null, now: number): string | null {
  const seconds = writableSecondsLeft(untilMs, now);
  if (seconds === null) return null;
  return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}

/** The id of the card that holds a database's connection details, which the button that shows or hides it controls. */
export const databaseDetailsId = (databaseId: string) => `database-details-${databaseId}`;

/** The connections open through the port, as the Status column counts them. */
export const connectionsLine = (count: number) => `${count} active connection${count === 1 ? "" : "s"}`;

/** How long before a grant ends a database's row starts to warn that it is ending. */
export const GRANT_ENDING_SOON_MS = 5 * 60_000;

/** What a database's row says of its grant, how it is drawn, whether it offers Request grant and what else it says under the line. */
export type DatabaseGrantLine = {
  text: string;
  /** `held`: in force; `warning`: missing or about to end; `plain`: nothing to act on (waiting for an approver, could not be checked). */
  tone: "held" | "warning" | "plain";
  request: boolean;
  note?: string;
};

/**
 * The grant line of a database whose grant check is `pam`, from the grant that was read. A held grant reads as a tunnel's row says it
 * (`tunnelGrantLine`) until it has `GRANT_ENDING_SOON_MS` left, then as how many minutes are left, rounded up, in the warning color.
 * PAM takes no request with the scope of a grant that is still active, so a grant that is held offers no request, however little
 * time it has left: the line says that a new one can be requested when it ends. A grant that is missing, or whose end has passed (so it
 * is no longer held), is in the warning color and offers the request. One that waits for its approver, or could not be read, offers
 * none: PAM refuses a second request while one waits, and a read that failed says why.
 */
export function databaseGrantLine(status: PamStatusView, pam: PamCheck, now = Date.now()): DatabaseGrantLine {
  const text = tunnelGrantLine(status, pam, now);
  if (grantHeld(status, now)) {
    const left = status.state === "active" && status.active_until_ms != null ? status.active_until_ms - now : null;
    if (left !== null && left <= GRANT_ENDING_SOON_MS) {
      return { text: `Grant ends in ${Math.ceil(left / 60_000)} min`, tone: "warning", request: false, note: "You can request a new grant when this one ends." };
    }
    return { text, tone: "held", request: false };
  }
  const missing = status.state !== "approval_awaited" && status.state !== "error";
  return { text, tone: missing ? "warning" : "plain", request: missing };
}

/**
 * Runs one change the Databases page makes and answers the sentence it failed with, or null. Whatever came of it the list is read
 * again: a delete can fail once the record is already gone (its password could not be removed from the keychain), and a row that still
 * showed the deleted database would only be refused when tried again.
 */
export async function runDatabaseAction(client: QueryClient, run: () => Promise<void>): Promise<string | null> {
  try {
    await run();
    return null;
  } catch (failure) {
    return revealHidden(errorMessage(failure));
  } finally {
    await client.invalidateQueries({ queryKey: databasesKey, refetchType: "all" });
  }
}
