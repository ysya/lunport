import { Button } from "@/components/ui/button";
import { usePendingRecordMigrations } from "@/lib/records";

/** The page a saved OpenSSH workspace opens on: Legacy mode is retired, the migration review is the way into the library. */
export function LegacyMigrationLanding({ previewMigration, retry }: { previewMigration: () => void; retry: () => void }) {
  const pending = usePendingRecordMigrations();
  return (
    <div className="app-shell flex h-screen items-center justify-center overflow-y-auto p-8">
      <div className="max-w-lg space-y-4 text-center">
        <h1 className="app-inspector-title">Your existing workspace</h1>
        <p className="text-sm text-muted-foreground">
          Lunport now keeps hosts, keys and Groups in its own library. Review the saved OpenSSH
          workspace and copy the hosts and keys you still use; the original files stay where they are.
        </p>
        <Button onClick={previewMigration}>
          {(pending.data ?? []).length > 0 ? "Review pending migrations" : "Preview migration"}
        </Button>
        <div className="flex flex-wrap justify-center gap-2">
          <Button variant="outline" onClick={retry}>
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
