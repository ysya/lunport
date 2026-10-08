import { useState } from "react";
import { ChevronRight, Search } from "lucide-react";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { MoveFailure } from "@/bindings/MoveFailure";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { GenerateKeyFileDialog } from "@/components/keychain/dialogs";
import { BADGE_CLASS } from "@/components/keychain/KeyDetail";
import { KeychainBanners } from "@/components/keychain/KeychainBanners";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { keychainSlots, otherKeyFiles, slotBadges, type KeychainSelection } from "@/lib/keychain";
import { useKeys } from "@/lib/queries";
import { useSyncOverview } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/stores/ui";

const ROW =
  "flex w-full flex-col items-start gap-0.5 rounded-[6px] px-2 py-1.5 text-left select-none hover:bg-muted/70 focus-visible:bg-muted/70 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none";
const ACTIVE = "bg-primary/12 hover:bg-primary/15";
const SMALL_BADGE = "h-4 px-1.5 text-[0.625rem]";

/** A row of "In SSHelter". A plain function, so a test sees the button in the tree. */
function slotRow(slot: SyncKeySlotView, active: boolean, failure: string | null, onSelect: () => void) {
  return (
    <button
      key={slot.id}
      type="button"
      aria-current={active ? "true" : undefined}
      title={failure ? `Couldn't move into SSHelter: ${revealHidden(failure)}` : undefined}
      className={cn(ROW, active && ACTIVE)}
      onClick={onSelect}
    >
      <span className="w-full truncate font-mono text-[0.8125rem]">{revealHidden(slot.name)}</span>
      <span className="flex flex-wrap items-center gap-1">
        {slotBadges(slot).map((b) => (
          <Badge key={b.label} variant="outline" className={cn(SMALL_BADGE, BADGE_CLASS[b.tone])}>
            {b.label}
          </Badge>
        ))}
        {slot.key_type && <span className="font-mono text-[0.625rem] text-muted-foreground">{revealHidden(slot.key_type)}</span>}
      </span>
    </button>
  );
}

/** A row of "Other key files in ~/.ssh". */
function fileRow(file: KeyInfo, active: boolean, onSelect: () => void) {
  return (
    <button key={file.private_path} type="button" aria-current={active ? "true" : undefined} className={cn(ROW, active && ACTIVE)} onClick={onSelect}>
      <span className="w-full truncate font-mono text-[0.8125rem]">{revealHidden(file.name)}</span>
      <span className="flex flex-wrap items-center gap-1">
        <span className="font-mono text-[0.625rem] text-muted-foreground">{file.key_type}</span>
        {file.in_agent && (
          <Badge variant="outline" className={SMALL_BADGE}>
            in ssh-agent
          </Badge>
        )}
      </span>
    </button>
  );
}

/**
 * The Keychain's list (key vault spec §7.2): a search, "In SSHelter", then "Other key files in ~/.ssh" (closed until opened, or
 * while searching). `slots` and `files` arrive filtered and in order (`keychainSlots`, `otherKeyFiles`). No hooks: exported for
 * the tests.
 */
export function KeychainListView({
  slots,
  files,
  filesOpen,
  selection,
  moveFailures,
  query,
  onQuery,
  onSelect,
  onToggleFiles,
  onGenerate,
}: {
  slots: SyncKeySlotView[];
  files: KeyInfo[];
  filesOpen: boolean;
  selection: KeychainSelection | null;
  moveFailures: MoveFailure[];
  query: string;
  onQuery: (query: string) => void;
  onSelect: (selection: KeychainSelection) => void;
  onToggleFiles: () => void;
  onGenerate: () => void;
}) {
  const searching = query.trim() !== "";
  const showFiles = filesOpen || searching;
  const failureOf = (slot: SyncKeySlotView) => (slot.file_for_now ? (moveFailures.find((f) => f.slot_id === slot.id)?.message ?? null) : null);
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 border-b p-2">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input type="search" placeholder="Search keys…" value={query} onChange={(e) => onQuery(e.target.value)} aria-label="Search keys" className="h-7 pl-8 text-sm" />
        </div>
      </div>
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-2">
        <section className="space-y-0.5">
          <h3 className="section-label px-1">In SSHelter</h3>
          {slots.length > 0 ? (
            slots.map((slot) => slotRow(slot, selection?.kind === "slot" && selection.id === slot.id, failureOf(slot), () => onSelect({ kind: "slot", id: slot.id })))
          ) : searching ? (
            <p className="px-1 py-2 text-xs text-muted-foreground">No keys match.</p>
          ) : (
            <div className="space-y-0.5 px-1 py-2 text-xs">
              <p className="font-medium">No keys in SSHelter yet</p>
              <p className="text-muted-foreground">Keys used by synced hosts appear here.</p>
            </div>
          )}
        </section>
        <section className="space-y-0.5">
          <div className="flex items-center justify-between gap-2 px-1">
            <button type="button" className="section-label flex min-w-0 items-center gap-1 px-0" aria-expanded={showFiles} onClick={onToggleFiles}>
              <ChevronRight className={cn("size-3 shrink-0 transition-transform", showFiles && "rotate-90")} aria-hidden />
              <span className="truncate">Other key files in ~/.ssh</span>
            </button>
            <Button type="button" size="sm" variant="ghost" className="h-6 shrink-0 px-1.5 text-xs" onClick={onGenerate}>
              Generate a key file…
            </Button>
          </div>
          {showFiles &&
            (files.length > 0 ? (
              files.map((f) => fileRow(f, selection?.kind === "file" && selection.path === f.private_path, () => onSelect({ kind: "file", path: f.private_path })))
            ) : (
              <p className="px-1 py-2 text-xs text-muted-foreground">{searching ? "No key files match." : "No other key files."}</p>
            ))}
        </section>
      </div>
    </div>
  );
}

/** The Keychain in the sidebar: its banners, then its list. */
export function KeychainList() {
  const overview = useSyncOverview();
  const keys = useKeys({ enabled: true });
  const selection = useUiStore((s) => s.keychainSelection);
  const selectKey = useUiStore((s) => s.selectKey);
  const moveFailures = useUiStore((s) => s.moveFailures);
  const [query, setQuery] = useState("");
  const [filesOpen, setFilesOpen] = useState(false);
  const [generating, setGenerating] = useState(false);
  const slots = overview.data?.joined ? overview.data.key_slots : [];
  const files = keys.data ?? [];
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <KeychainBanners />
      <KeychainListView
        slots={keychainSlots(slots, query)}
        files={otherKeyFiles(files, slots, query)}
        filesOpen={filesOpen}
        selection={selection}
        moveFailures={moveFailures}
        query={query}
        onQuery={setQuery}
        onSelect={selectKey}
        onToggleFiles={() => setFilesOpen((open) => !open)}
        onGenerate={() => setGenerating(true)}
      />
      <GenerateKeyFileDialog open={generating} onOpenChange={setGenerating} existingNames={files.map((k) => k.name)} />
    </div>
  );
}
