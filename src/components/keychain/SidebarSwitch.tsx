import { cn } from "@/lib/utils";
import { useUiStore, type SidebarView } from "@/stores/ui";

/** The sidebar's Hosts | Keychain switch (key vault spec §7.1). No hooks: exported for the tests. */
export function SidebarSwitchView({ view, onView }: { view: SidebarView; onView: (view: SidebarView) => void }) {
  return (
    <div className="flex shrink-0 gap-1 border-b p-2" role="group" aria-label="Sidebar">
      {(["hosts", "keychain"] as const).map((v) => (
        <button
          key={v}
          type="button"
          aria-pressed={view === v}
          className={cn(
            "h-6 flex-1 rounded-[6px] text-xs font-medium select-none focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
            view === v ? "bg-primary/12 text-foreground" : "text-muted-foreground hover:bg-muted/70",
          )}
          onClick={() => onView(v)}
        >
          {v === "hosts" ? "Hosts" : "Keychain"}
        </button>
      ))}
    </div>
  );
}

/** The switch, remembered across restarts (`sidebarView`). */
export function SidebarSwitch() {
  const view = useUiStore((s) => s.sidebarView);
  const setView = useUiStore((s) => s.setSidebarView);
  return <SidebarSwitchView view={view} onView={setView} />;
}
