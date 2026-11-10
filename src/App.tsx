import { useState } from "react";

import { CredentialsPendingNotice } from "@/components/IdentityMigration";
import { InstallationRenameNotice } from "@/components/InstallationRename";
import { McpApprovalDialog } from "@/components/McpApprovalDialog";
import { LegacyMigrationLanding } from "@/components/records/LegacyMigrationLanding";
import { RecordsMigrationPanel } from "@/components/records/MigrationPanel";
import { RecordsWorkspace } from "@/components/records/RecordsWorkspace";
import { WorkspaceGate } from "@/components/records/WorkspaceGate";
import { Toaster } from "@/components/ui/sonner";
import { useSyncBackendSettings } from "@/lib/backend-settings";
import { useRecordsStatus } from "@/lib/records";
import { useApplyTheme } from "@/lib/theme";

/**
 * App shell: the Records workspace behind the workspace gate. A saved OpenSSH workspace from
 * the retired Legacy mode gets the import landing instead, and the migration review copies
 * its hosts and keys into the library.
 */
function App() {
  useApplyTheme();
  // Keep preferences and update checks alive even when the workspace cannot open.
  useSyncBackendSettings();
  const status = useRecordsStatus();
  const [migrationOpen, setMigrationOpen] = useState(false);
  return (
    <>
      <WorkspaceGate
        status={status.data}
        error={status.isError}
        retry={() => void status.refetch()}
        legacyImport={() => (
          <LegacyMigrationLanding retry={() => void status.refetch()} previewMigration={() => setMigrationOpen(true)} />
        )}
        records={() => (
          <>
            <RecordsWorkspace overview={status.data!.overview!} reload={() => void status.refetch()} />
            <McpApprovalDialog />
          </>
        )}
      />
      {migrationOpen && (
        <div className="app-shell fixed inset-0 z-50 overflow-y-auto pt-11">
          <RecordsMigrationPanel onClose={() => setMigrationOpen(false)} />
        </div>
      )}
      <Toaster />
      <InstallationRenameNotice />
      <CredentialsPendingNotice />
    </>
  );
}

export default App;
