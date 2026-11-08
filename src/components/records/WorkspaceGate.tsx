import type { ReactNode } from "react";
import type { RecordsStatus } from "@/lib/records";
import { Button } from "@/components/ui/button";
import { BrandMark } from "@/components/app/BrandMark";
import { UpdatesPane } from "@/components/UpdatesPane";
import { revealHidden } from "@/lib/reveal-hidden";

/**
 * What the workspace status opens: the Records library, the import landing for a saved OpenSSH
 * workspace (Legacy mode is retired; its files stay on disk until the migration review copies
 * them), or the reason the workspace cannot open yet.
 */
export function WorkspaceGate({
  status,
  error,
  retry,
  records,
  legacyImport,
}: {
  status?: RecordsStatus;
  error?: boolean;
  retry: () => void;
  records: () => ReactNode;
  legacyImport: () => ReactNode;
}) {
  if (!error && status?.format === "records" && status.overview) return records();
  if (!error && status?.format === "legacy") return legacyImport();
  const message =
    status?.format === "blocked"
      ? (status.blocked_reason ?? "The workspace could not be opened.")
      : error
        ? "The workspace status is unavailable."
        : status?.format === "records"
          ? "The records snapshot is unavailable."
          : "Opening workspace…";
  return (
    <div className="app-shell flex min-h-screen items-center justify-center p-8">
      <div className="w-full max-w-md space-y-4 text-center">
        <BrandMark className="mx-auto h-12 w-14 text-primary" />
        <h1 className="app-inspector-title">{status || error ? "Workspace unavailable" : "Lunport"}</h1>
        <p className="text-sm text-muted-foreground whitespace-pre-wrap">{revealHidden(message)}</p>
        {(status || error) && (
          <Button variant="outline" onClick={retry}>
            Retry
          </Button>
        )}
        {(status || error) && (
          <div className="pt-4 text-left">
            <UpdatesPane />
          </div>
        )}
      </div>
    </div>
  );
}
