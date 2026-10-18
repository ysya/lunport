import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { ArrowUpRight, Server } from "lucide-react";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { useUiStore } from "@/stores/ui";
import { revealHidden } from "@/lib/sync-approvals";
import type { RecordOverview } from "@/lib/records";
import { selectHost } from "./editor";
import { connectSavedHost } from "./operations";
import { readinessLabel } from "./HostList";
import { recordHostSearchText } from "./group-tree";
import { useSettingsStore } from "@/stores/settings";
import { recentHostKey } from "./library-view";
import { isImeKey } from "@/lib/ime";

export function RecordsCommandPalette({
  overview,
  terminalId,
  newTab,
  editorBusy,
  edit,
  create,
  connectHost,
}: {
  overview: RecordOverview;
  terminalId: string | null;
  newTab: boolean;
  editorBusy: boolean;
  edit: (id: string) => void;
  create: () => void;
  connectHost?: (id: string) => Promise<void>;
}) {
  const open = useUiStore((state) => state.paletteOpen);
  const setOpen = useUiStore((state) => state.setPaletteOpen);
  const setSettingsOpen = useUiStore((state) => state.setSettingsOpen);
  const setSettingsCategory = useUiStore((state) => state.setSettingsCategory);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const list = useRef<HTMLDivElement>(null);
  const recent = useSettingsStore((state) => state.recentConnections);
  const available = overview.hosts
    .filter((host) => selectHost(overview.hosts, host.id))
    .sort((a, b) => a.payload.alias.localeCompare(b.payload.alias));
  const recentHosts = available
    .filter((host) => recent[recentHostKey(host.id)])
    .sort((a, b) => recent[recentHostKey(b.id)] - recent[recentHostKey(a.id)])
    .slice(0, 5);
  const recentIds = new Set(recentHosts.map((host) => host.id));
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (
        (event.metaKey || event.ctrlKey) &&
        event.key.toLowerCase() === "k" &&
        !event.altKey
      ) {
        event.preventDefault();
        setOpen(!useUiStore.getState().paletteOpen);
      }
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [setOpen]);
  const connect = async (id: string) => {
    if (inFlight.current || editorBusy) return;
    inFlight.current = true;
    setBusy(true);
    try {
      if (connectHost) await connectHost(id);
      else await connectSavedHost(overview, id, terminalId, newTab);
      setOpen(false);
    } catch (error) {
      toast.error("Could not connect", {
        description: revealHidden(String(error)),
      });
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  return (
    <CommandDialog
      open={open}
      onOpenChange={setOpen}
      title="Quick connect"
      description="Enter connects; Command or Control Enter opens the host editor."
    >
      <Command
        onKeyDownCapture={(event) => {
          if (isImeKey(event)) return;
          if (
            event.key !== "Enter" ||
            !(event.metaKey || event.ctrlKey) ||
            busy ||
            editorBusy
          )
            return;
          const id = list.current?.querySelector<HTMLElement>(
            '[cmdk-item][aria-selected="true"]',
          )?.dataset.hostId;
          if (!id) return;
          event.preventDefault();
          event.stopPropagation();
          setOpen(false);
          edit(id);
        }}
      >
        <CommandInput placeholder="Search hosts or settings…" />
        <CommandList ref={list}>
          <CommandEmpty>No matching hosts or commands.</CommandEmpty>
          {[
            { heading: "Recent", hosts: recentHosts },
            {
              heading: "All hosts",
              hosts: available.filter((host) => !recentIds.has(host.id)),
            },
          ].map(
            (group) =>
              !!group.hosts.length && (
                <CommandGroup key={group.heading} heading={group.heading}>
                  {group.hosts.map((host) => (
                    <CommandItem
                      key={host.id}
                      data-host-id={host.id}
                      value={recordHostSearchText(overview, host)}
                      disabled={busy || editorBusy}
                      onSelect={() => {
                        if (
                          host.readiness.kind === "ready" &&
                          !host.group_error
                        )
                          void connect(host.id);
                        else {
                          setOpen(false);
                          edit(host.id);
                        }
                      }}
                    >
                      <Server className="size-4 shrink-0 text-muted-foreground" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-medium">
                          {revealHidden(host.payload.alias)}
                        </span>
                        <span className="block truncate font-mono text-xs text-muted-foreground">
                          {revealHidden(host.effective_payload.user)}@
                          {revealHidden(host.effective_payload.hostname)}:
                          {host.effective_payload.port}
                        </span>
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {host.group_error ? (
                          "Needs review"
                        ) : host.readiness.kind !== "ready" ? (
                          readinessLabel[host.readiness.kind]
                        ) : (
                          <ArrowUpRight className="size-3.5" />
                        )}
                      </span>
                    </CommandItem>
                  ))}
                </CommandGroup>
              ),
          )}
          <CommandGroup heading="Workspace">
            <CommandItem
              disabled={busy || editorBusy}
              onSelect={() => {
                setOpen(false);
                create();
              }}
            >
              New host
            </CommandItem>
            <CommandItem
              onSelect={() => {
                setOpen(false);
                setSettingsCategory("general");
                setSettingsOpen(true);
              }}
            >
              Settings
            </CommandItem>
            <CommandItem
              onSelect={() => {
                setOpen(false);
                setSettingsCategory("ai");
                setSettingsOpen(true);
              }}
            >
              AI access (MCP)
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </Command>
    </CommandDialog>
  );
}
