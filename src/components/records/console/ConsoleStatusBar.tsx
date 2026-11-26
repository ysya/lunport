import { LockKeyhole } from "lucide-react";
import type { DatabaseEnvironment } from "@/bindings/DatabaseEnvironment";
import type { ReadOnlyMode } from "@/bindings/ReadOnlyMode";
import { HOST_UNAVAILABLE, type DatabaseGrantLine, type RouteSummary, type SavedDatabase } from "@/lib/databases";
import { revealHidden } from "@/lib/reveal-hidden";

const ENVIRONMENT_LABELS: Record<DatabaseEnvironment, string> = { prod: "PROD", staging: "STAGING", dev: "DEV" };

export function readOnlyLabel(mode: ReadOnlyMode): string {
  return mode === "locked" ? "Read-only (locked)" : "Read-only (not locked)";
}

/** How the console reaches the instance: its public IP, or the library host it goes through. */
function routeLabel(database: SavedDatabase, route: RouteSummary): string {
  if (database.network === "public") return "Public IP";
  return route.alias ? `via ${revealHidden(route.alias)}` : HOST_UNAVAILABLE;
}

/**
 * The line under a console: its environment, the instance, the account signed in, the read-only mode, the grant when the database
 * needs one, and the route. Its colors follow the environment.
 */
export function ConsoleStatusBar({ environment, database, route, iamUser, readOnly, grant }: {
  environment: DatabaseEnvironment;
  database: SavedDatabase | null;
  route: RouteSummary;
  /** The account the session signed in as; none until it has. */
  iamUser: string | null;
  readOnly: ReadOnlyMode;
  /** The grant line, for a database with a grant check whose grant has been read. */
  grant: DatabaseGrantLine | null;
}) {
  return <footer className="console-status" data-environment={environment} aria-label="Console status">
    <span className="console-status-environment">{ENVIRONMENT_LABELS[environment]}</span>
    {database && <span>{revealHidden(`${database.instance} · ${database.project}`)}</span>}
    {iamUser && <span>{revealHidden(`${iamUser} · IAM`)}</span>}
    <span>{readOnlyLabel(readOnly)}</span>
    {grant && <span className="console-status-grant" data-tone={grant.tone} title={grant.note}>
      <LockKeyhole className="size-3" aria-hidden="true" />{revealHidden(grant.text)}
    </span>}
    {database && <span className="console-status-route">{routeLabel(database, route)}</span>}
  </footer>;
}
