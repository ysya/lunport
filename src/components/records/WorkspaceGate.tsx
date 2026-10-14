import type { ReactNode } from "react";
import type { RecordsStatus } from "@/lib/records";
import { Button } from "@/components/ui/button";
import { revealHidden } from "@/lib/sync-approvals";
export function WorkspaceGate({
  status,
  error,
  retry,
  useLegacy,
  legacy,
  records,
  pausedLegacy,
  resuming = false,
}: {
  status?: RecordsStatus;
  error?: boolean;
  resuming?: boolean;
  retry: () => void;
  useLegacy: () => void;
  legacy: () => ReactNode;
  pausedLegacy?: () => ReactNode;
  records: () => ReactNode;
}) {
  if (!error && status?.format === "records" && status.overview)
    return records();
  if (!error && status?.format === "legacy" && !status.legacy_paused)
    return legacy();
  const paused = !error && status?.format === "legacy" && status.legacy_paused;
  if (paused && pausedLegacy) return pausedLegacy();
  const message =
    status?.format === "blocked"
      ? (status.blocked_reason ?? "The workspace could not be opened.")
      : error
        ? "The workspace status is unavailable."
        : status?.format === "records"
          ? "The records snapshot is unavailable."
          : paused
            ? "Choose how to open your existing SSH configuration. Migration to the records workspace requires a reviewed import."
            : "Opening workspace…";
  return (
    <div className="app-shell flex h-screen items-center justify-center p-8">
      <div className="max-w-md space-y-4 text-center">
        <h1 className="text-xl font-semibold">
          {paused
            ? "Your existing workspace"
            : status || error
              ? "Workspace unavailable"
              : "SSHelter"}
        </h1>
        <p className="text-sm text-muted-foreground whitespace-pre-wrap">
          {revealHidden(message)}
        </p>
        {paused && (
          <>
            <p className="text-sm text-muted-foreground">
              Continuing enables the existing SSH configuration workspace and
              its sync behavior.
            </p>
            <Button disabled={resuming} onClick={useLegacy}>
              Use existing SSH configuration
            </Button>
          </>
        )}
        {(status || error) && (
          <Button variant="outline" onClick={retry}>
            Retry
          </Button>
        )}
      </div>
    </div>
  );
}
