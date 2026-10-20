import { PageHeader } from "@/components/app/PageHeader";
import type { RecordOverview } from "@/lib/records";
import { CentralAccountSection } from "./CentralAccountPanel";

export function RecordsAccountPanel({ overview, onBusyChange }: { overview: RecordOverview; onBusyChange?: (busy: boolean) => void }) {
  return <div className="library-page-scroll min-h-0 flex-1 overflow-y-auto">
    <PageHeader title="Sync" />
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">Sync is optional. Manage hosts, keys, Groups and tunnel rules locally without an account. Sign in only when you want to connect your devices.</p>
      <CentralAccountSection disabled={!!overview.syncing} onBusyChange={onBusyChange} />
    </div>
  </div>;
}
