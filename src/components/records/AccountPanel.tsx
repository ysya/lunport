import { PageHeader } from "@/components/app/PageHeader";
import type { RecordOverview } from "@/lib/records";
import { CentralAccountSection } from "./CentralAccountPanel";

export function RecordsAccountPanel({ overview, onBusyChange }: { overview: RecordOverview; onBusyChange?: (busy: boolean) => void }) {
  return <div className="app-workflow-page space-y-6">
    <PageHeader
      title="Sync"
      description="Sync is optional. Manage hosts, keys, Groups and tunnel rules locally without an account. Sign in only when you want to connect your devices."
    />
    <CentralAccountSection disabled={!!overview.syncing} onBusyChange={onBusyChange} />
  </div>;
}
