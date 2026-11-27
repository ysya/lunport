import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { HOST_UNAVAILABLE, libraryHosts, type JumpHost } from "@/lib/databases";
import type { RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/reveal-hidden";
import { cn } from "@/lib/utils";
import { groupPath, recordHostSearchText } from "./group-tree";

export type DatabaseRouteHostPickerProps = {
  overview: RecordOverview;
  selectedId: string | null;
  needsReselection?: boolean;
  suggested?: JumpHost[];
  query: string;
  onQuery: (query: string) => void;
  onSelect: (id: string) => void;
  busy: boolean;
};

export function DatabaseRouteHostPicker({ overview, selectedId, needsReselection = false, suggested, query, onQuery, onSelect, busy }: DatabaseRouteHostPickerProps) {
  const hosts = libraryHosts(overview);
  const entries = new Map(overview.hosts.map((host) => [host.id, host]));
  const selected = selectedId && !needsReselection ? entries.get(selectedId) : undefined;
  const path = (entry: RecordOverview["hosts"][number]) => groupPath(overview, entry.payload.group_id, entry.scope);
  const words = query.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
  const initial = (suggested ?? hosts).slice(0, 6);
  const extra = selected && !initial.some((host) => host.id === selected.id) ? hosts.find((host) => host.id === selected.id) : undefined;
  const sections = words.length ? [{
    label: "Matching hosts",
    hosts: hosts.filter((host) => {
      const value = recordHostSearchText(overview, entries.get(host.id)!).toLocaleLowerCase();
      return words.every((word) => value.includes(word));
    }),
  }] : [
    { label: "Selected host", hosts: extra ? [extra] : [] },
    { label: suggested ? "Suggested for this project" : "Saved hosts", hosts: initial },
  ];
  const unavailable = needsReselection || selectedId !== null && !selected;
  return <>
    <p className={cn("text-xs", unavailable ? "text-warning" : "text-muted-foreground")}>
      {unavailable ? HOST_UNAVAILABLE : selected ? `Selected host: ${revealHidden([selected.payload.alias, path(selected)].filter(Boolean).join(" · "))}` : "Choose a host to connect through."}
    </p>
    <Command shouldFilter={false} className="h-auto rounded-lg border bg-background">
      <CommandInput aria-label="Search route hosts" placeholder="Search hosts by name, address or Group…" disabled={busy} value={query} onValueChange={onQuery} />
      <CommandList className="max-h-60">
        <CommandEmpty>{words.length ? "No matching hosts." : hosts.length ? "Search to find other hosts." : "No hosts available."}</CommandEmpty>
        {sections.map((section) => section.hosts.length > 0 && <CommandGroup key={section.label} heading={section.label}>
          {section.hosts.map((host) => {
            const entry = entries.get(host.id)!;
            return <CommandItem key={host.id} value={recordHostSearchText(overview, entry)} data-checked={selected?.id === host.id} disabled={busy}
              onSelect={() => { onSelect(host.id); onQuery(""); }}>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{revealHidden(host.alias)}</span>
                <span className="block truncate text-xs text-muted-foreground">{revealHidden([entry.effective_payload.hostname, path(entry)].filter(Boolean).join(" · "))}</span>
              </span>
            </CommandItem>;
          })}
        </CommandGroup>)}
      </CommandList>
    </Command>
    {!words.length && hosts.length > initial.length + (extra ? 1 : 0) &&
      <p className="text-xs text-muted-foreground">Search to find other hosts by name, address, or Group path.</p>}
  </>;
}
