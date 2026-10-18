import { useEffect, useState } from "react";
import { revealHidden } from "@/lib/sync-approvals";
export function RecordSyncStatus({
  lastSyncMs,
  error,
  connected = true,
  pending = false,
  pendingChanges = 0,
  syncing = false,
  conflicts = 0,
}: {
  lastSyncMs: number | null;
  error: string | null;
  connected?: boolean;
  pending?: boolean;
  pendingChanges?: number;
  syncing?: boolean;
  conflicts?: number;
}) {
  // An authenticated account check can clear the backend error before child
  // downloads finish. Keep the known prior failure until this whole attempt ends.
  const [previousError, setPreviousError] = useState(error);
  useEffect(() => {
    if (!syncing || error) setPreviousError(error);
  }, [syncing, error]);
  const retryError = error ?? previousError;
  const date = lastSyncMs === null ? null : new Date(lastSyncMs);
  const validDate = date !== null && Number.isFinite(date.getTime());
  return (
    <div className="min-w-0 text-xs text-muted-foreground" role="status">
      <p>
        {syncing ? (
          pending ? (
            "Setting up sync…"
          ) : (
            "Syncing…"
          )
        ) : pending ? (
          "Sync setup pending"
        ) : !connected ? (
          "Sync not set up"
        ) : conflicts > 0 ? (
          `${conflicts} saved sync conflicts need review`
        ) : pendingChanges > 0 ? (
          `${pendingChanges} changes saved, waiting to sync`
        ) : lastSyncMs === null ? (
          "Not synced yet"
        ) : validDate ? (
          <>
            Last sync:{" "}
            <time dateTime={date.toISOString()}>{date.toLocaleString()}</time>
          </>
        ) : (
          "Last sync time unavailable"
        )}
      </p>
      {retryError && syncing ? (
        <span className="mt-1 block max-h-20 overflow-y-auto whitespace-pre-wrap">
          Previous attempt: {revealHidden(retryError)}
        </span>
      ) : error ? (
        <p
          className="mt-1 max-h-20 overflow-y-auto text-destructive whitespace-pre-wrap"
          role="alert"
        >
          {revealHidden(error)}
        </p>
      ) : null}
    </div>
  );
}
