import { queryOptions, type QueryClient } from "@tanstack/react-query";
import { tauriInvoke } from "./ipc";
import { grantHeld, pamStatusOptions, tunnelGrantLine, type PamCheck, type PamStatusView } from "./transports";
import { revealHidden } from "./reveal-hidden";
import { errorMessage } from "./utils";
import type { SavedDatabase } from "@/bindings/SavedDatabase";
import type { DatabaseView } from "@/bindings/DatabaseView";
import type { DatabaseLive } from "@/bindings/DatabaseLive";
import type { DatabasePhase } from "@/bindings/DatabasePhase";
import type { DatabaseEnvironment } from "@/bindings/DatabaseEnvironment";
import type { DatabaseEngine } from "@/bindings/DatabaseEngine";
import type { UnlockMethod } from "@/bindings/UnlockMethod";
export type { SavedDatabase, DatabaseView, DatabaseLive, DatabasePhase, DatabaseEnvironment, UnlockMethod };

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

/** Where apps reach the database on this computer: the port that runs, else the one saved; "Not shared" for a database with none. */
export function localAddress(row: DatabaseView): string {
  const port = row.live.port ?? row.database.local_port;
  return port === null ? "Not shared" : `127.0.0.1:${port}`;
}

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
