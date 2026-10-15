import { revealHidden } from "@/lib/sync-approvals";
export function RecordSyncStatus({
  lastSyncMs,
  error,
  connected = true,
  pending = false,
  pendingChanges = 0,
}: {
  lastSyncMs: number | null;
  error: string | null;
  connected?: boolean;
  pending?: boolean;
  pendingChanges?: number;
}) {
  const date = lastSyncMs === null ? null : new Date(lastSyncMs);
  const validDate = date !== null && Number.isFinite(date.getTime());
  return (
    <div className="min-w-0 text-xs text-muted-foreground" role="status">
      <p>
        {pending ? (
          "Sync setup pending"
        ) : !connected ? (
          "Sync not set up"
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
      {error && (
        <p
          className="mt-1 max-h-20 overflow-y-auto text-destructive whitespace-pre-wrap"
          role="alert"
        >
          {revealHidden(error)}
        </p>
      )}
    </div>
  );
}
