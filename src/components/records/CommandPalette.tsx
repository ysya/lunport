import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
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
import { connectSavedHost, scopeLabel } from "./operations";
import { readinessLabel } from "./HostList";

export function RecordsCommandPalette({
  overview,
  terminalId,
  newTab,
  editorBusy,
  edit,
  create,
}: {
  overview: RecordOverview;
  terminalId: string | null;
  newTab: boolean;
  editorBusy: boolean;
  edit: (id: string) => void;
  create: () => void;
}) {
  const open = useUiStore((state) => state.paletteOpen);
  const setOpen = useUiStore((state) => state.setPaletteOpen);
  const setSettingsOpen = useUiStore((state) => state.setSettingsOpen);
  const setSettingsCategory = useUiStore((state) => state.setSettingsCategory);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const list = useRef<HTMLDivElement>(null);
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
      await connectSavedHost(overview, id, terminalId, newTab);
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
          <CommandGroup heading="Hosts">
            {overview.hosts
              .filter((host) => selectHost(overview.hosts, host.id))
              .map((host) => (
                <CommandItem
                  key={host.id}
                  data-host-id={host.id}
                  value={`${host.payload.alias} ${host.payload.hostname} ${scopeLabel(overview, host.scope)} ${host.id}`}
                  disabled={busy || editorBusy}
                  onSelect={() => {
                    if (host.readiness.kind === "ready") void connect(host.id);
                    else {
                      setOpen(false);
                      edit(host.id);
                    }
                  }}
                >
                  <span className="min-w-0 flex-1 truncate">
                    {revealHidden(host.payload.alias)}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {revealHidden(scopeLabel(overview, host.scope))}
                    {host.readiness.kind !== "ready" &&
                      ` · ${readinessLabel[host.readiness.kind]}`}
                  </span>
                </CommandItem>
              ))}
          </CommandGroup>
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
