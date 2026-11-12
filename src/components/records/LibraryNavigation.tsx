import { useEffect, useState, type ReactNode } from "react";
import { ArrowLeftRight, Bot, Cloud, Database, KeyRound, Server } from "lucide-react";
import type { RecordOverview } from "@/lib/records";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/stores/ui";
import { CLOUD_PROVIDERS } from "@/lib/cloud";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import type { LibraryFilter } from "./library-view";

export type WorkspacePanel = "hosts" | "keys" | "account" | "import" | "tunnels" | "databases" | "transports" | "activity";
export const LIBRARY_NAVIGATION_ID = "library-navigation";

function NavigationItem({ label, icon, active, action, count, collapsed }: {
  label: string; icon: ReactNode; active: boolean; action: () => void;
  count?: number; collapsed: boolean;
}) {
  const [tooltipOpen, setTooltipOpen] = useState(false);
  useEffect(() => { if (!collapsed) setTooltipOpen(false); }, [collapsed]);
  return (
    <Tooltip open={collapsed && tooltipOpen} onOpenChange={setTooltipOpen}>
      <TooltipTrigger asChild>
        <button
          type="button"
          className={cn("library-nav-item", active && "is-active")}
          aria-current={active ? "page" : undefined}
          onClick={(event) => { event.currentTarget.focus(); action(); }}
          aria-label={count === undefined ? label : `${label} (${count})`}
          title={collapsed ? undefined : label}
        >
          {icon}
          <span className="library-nav-label">{label}</span>
          {count !== undefined && <span className="library-nav-count">{count}</span>}
        </button>
      </TooltipTrigger>
      <TooltipContent side="right" sideOffset={8}>
        {label}{count !== undefined ? ` (${count})` : ""}
      </TooltipContent>
    </Tooltip>
  );
}

export function LibraryNavigation({ overview, panel, navigate, changeFilter }: {
  overview: RecordOverview; panel: WorkspacePanel;
  navigate: (panel: WorkspacePanel) => void; changeFilter: (filter: LibraryFilter) => void;
}) {
  const collapsed = useUiStore((s) => s.librarySidebarCollapsed);
  const row = (label: string, icon: ReactNode, active: boolean, action: () => void, count?: number) => (
    <NavigationItem label={label} icon={icon} active={active} action={action} count={count} collapsed={collapsed} />
  );
  return (
    <TooltipProvider delayDuration={300}>
      <aside id={LIBRARY_NAVIGATION_ID} className="library-navigation" aria-label="Library navigation" data-collapsed={collapsed}>
        <div className="library-nav-heading library-workspace-label" aria-hidden={collapsed}>Library</div>
        <nav aria-label="Workspace sections" className="space-y-1">
          {row("Hosts", <Server className="size-4" />, panel === "hosts", () => { changeFilter({ kind: "all" }); navigate("hosts"); }, overview.hosts.length)}
          {row("Keys", <KeyRound className="size-4" />, panel === "keys", () => navigate("keys"), overview.keys.filter((key) => key.status !== "deleted").length)}
          {row("AI activity", <Bot className="size-4" />, panel === "activity", () => navigate("activity"))}
        </nav>
        <div className="library-nav-heading library-workspace-label" aria-hidden={collapsed}>Connections</div>
        <nav aria-label="Connections" className="space-y-1">
          {row("Tunnels", <ArrowLeftRight className="size-4" />, panel === "tunnels", () => navigate("tunnels"))}
          {row("Cloud SQL", <Database className="size-4" />, panel === "databases", () => navigate("databases"))}
        </nav>
        <div className="library-nav-heading library-workspace-label" aria-hidden={collapsed}>Cloud</div>
        <nav aria-label="Cloud providers" className="space-y-1">
          {CLOUD_PROVIDERS.map((provider) => (
            <span key={provider.id} className="contents">
              {row(provider.label, <Cloud className="size-4" />, panel === provider.panel, () => navigate(provider.panel))}
            </span>
          ))}
        </nav>
      </aside>
    </TooltipProvider>
  );
}
