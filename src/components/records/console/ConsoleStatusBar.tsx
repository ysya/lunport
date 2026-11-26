import { ChevronDown, LockKeyhole } from "lucide-react";
import { Popover } from "radix-ui";
import type { DatabaseEnvironment } from "@/bindings/DatabaseEnvironment";
import type { ReadOnlyMode } from "@/bindings/ReadOnlyMode";
import { HOST_UNAVAILABLE, type DatabaseGrantLine, type RouteSummary, type SavedDatabase } from "@/lib/databases";
import { revealHidden } from "@/lib/reveal-hidden";

const ENVIRONMENT_LABELS: Record<DatabaseEnvironment, string> = { prod: "PROD", staging: "STAGING", dev: "DEV" };

function routeLabel(database: SavedDatabase, route: RouteSummary): string {
  if (database.network === "public") return "Public IP";
  return route.alias ? "via " + revealHidden(route.alias) : HOST_UNAVAILABLE;
}

export function ConsoleStatusBar({ environment, database, route, iamUser, readOnly, grant }: {
  environment: DatabaseEnvironment;
  database: SavedDatabase | null;
  route: RouteSummary;
  iamUser: string | null;
  readOnly: ReadOnlyMode | null;
  grant: DatabaseGrantLine | null;
}) {
  const label = ENVIRONMENT_LABELS[environment];
  const lock = readOnly === "locked" ? "Read-only (locked)" : readOnly === "not_locked" ? "Read-only (not locked)" : null;
  return <div className="console-status" data-environment={environment}>
    {grant?.tone === "warning" && <span className="console-status-grant" title={grant.note}>{revealHidden(grant.text)}</span>}
    <Popover.Root>
      <Popover.Trigger asChild>
        <button type="button" className="console-status-trigger" data-mode={readOnly ?? undefined} aria-label={["Connection details", label, lock].filter(Boolean).join(", ")}>
          <span className="console-status-environment">{label}</span>
          {lock && <span className="console-lock"><LockKeyhole className="size-3" aria-hidden="true" />{lock}</span>}
          <ChevronDown className="size-3" aria-hidden="true" />
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content className="console-connection-details" aria-label="Connection details" align="end" sideOffset={6} collisionPadding={8}>
          <dl>
            {database && <>
              <dt>Instance</dt><dd>{revealHidden(database.instance)}</dd>
              <dt>Project</dt><dd>{revealHidden(database.project)}</dd>
            </>}
            <dt>IAM account</dt><dd>{iamUser ? revealHidden(iamUser) : "Not signed in"}</dd>
            {database && <><dt>Route</dt><dd>{routeLabel(database, route)}</dd></>}
            {grant && <><dt>Grant</dt><dd>{revealHidden(grant.text)}{grant.note && <p>{revealHidden(grant.note)}</p>}</dd></>}
          </dl>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  </div>;
}
