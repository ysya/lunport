import { revealHidden } from "@/lib/sync-approvals";
export function RecordSyncStatus({
  lastSyncMs,
  error,
}: {
  lastSyncMs: number | null;
  error: string | null;
}) {
  const date = lastSyncMs === null ? null : new Date(lastSyncMs);
  const validDate = date !== null && Number.isFinite(date.getTime());
  return (
    <div
      className="shrink-0 space-y-1 border-b p-3 text-xs text-muted-foreground"
      role="status"
    >
      <p>
        {lastSyncMs === null ? (
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
        <p className="text-destructive whitespace-pre-wrap" role="alert">
          {revealHidden(error)}
        </p>
      )}
    </div>
  );
}
