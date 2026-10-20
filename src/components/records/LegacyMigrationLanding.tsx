import { Button } from "@/components/ui/button";
import { usePendingRecordMigrations } from "@/lib/records";
export function LegacyMigrationLanding({
  useLegacy,
  previewMigration,
  retry,
  busy,
}: {
  useLegacy: () => void;
  previewMigration: () => void;
  retry: () => void;
  busy: boolean;
}) {
  const pending = usePendingRecordMigrations();
  return (
    <div className="app-shell flex h-screen items-center justify-center overflow-y-auto p-8">
      <div className="max-w-lg space-y-4 text-center">
        <h1 className="app-inspector-title">Your existing workspace</h1>
        <p className="text-sm text-muted-foreground">
          Review the saved workspace before switching to records. You can
          preview migration without opening the legacy configuration editor.
        </p>
        <Button disabled={busy} onClick={previewMigration}>
          {(pending.data ?? []).length > 0
            ? "Review pending migrations"
            : "Preview migration"}
        </Button>
        <p className="text-sm text-muted-foreground">
          Using the existing workspace enables its SSH configuration editor and
          local editing.
        </p>
        <div className="flex flex-wrap justify-center gap-2">
          <Button variant="outline" disabled={busy} onClick={useLegacy}>
            Use existing SSH configuration
          </Button>
          <Button variant="outline" disabled={busy} onClick={retry}>
            Retry
          </Button>
        </div>
        {pending.isError && (
          <p role="status" className="text-sm text-destructive">
            Pending migration status is unavailable. Open migration to retry.
          </p>
        )}
      </div>
    </div>
  );
}
