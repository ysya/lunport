import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { ArrowUpRight, Server, SquareTerminal } from "lucide-react";
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
import { revealHidden } from "@/lib/reveal-hidden";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { readTmuxWorkspace, type TmuxWorkspaceLocation } from "@/lib/tmux-workspace-state";
import { selectHost } from "./editor";
import { connectSavedHost } from "./operations";
import { readinessLabel } from "./HostList";
import { recordHostSearchText } from "./group-tree";
import { useSettingsStore } from "@/stores/settings";
import { recentHostKey } from "./library-view";
import { isImeKey } from "@/lib/ime";
import { useTerminalStore } from "@/stores/terminals";

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
  const recentTmux = open ? available.flatMap((host) => {
    if (host.readiness.kind !== "ready" || host.group_error) return [];
    const key = recentHostKey(host.id);
    const workspace = readTmuxWorkspace(key);
    return workspace ? [{ host, workspace, updatedAt: workspace.updatedAt ?? recent[key] ?? 0 }] : [];
  }).sort((a, b) => b.updatedAt - a.updatedAt) : [];
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || (useTerminalStore.getState().activeId && event.ctrlKey && !event.metaKey && !event.shiftKey)) return;
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
  const connect = async (id: string, tmux?: { resume?: TmuxWorkspaceLocation }) => {
    if (inFlight.current || editorBusy) return;
    inFlight.current = true;
    setBusy(true);
    try {
      if (connectHost && !tmux) await connectHost(id);
      else await connectSavedHost(overview, id, terminalId, newTab, tmux);
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
  const hostGroup = (heading: string, hosts: RecordHostView[]) => hosts.length > 0 && (
    <CommandGroup heading={heading}>
      {hosts.map((host) => {
        const ready = host.readiness.kind === "ready" && !host.group_error;
        return (
          <CommandItem
            key={host.id}
            data-host-id={host.id}
            data-tmux-ready={ready}
            value={recordHostSearchText(overview, host)}
            disabled={busy || editorBusy}
            onSelect={() => {
              if (ready) void connect(host.id);
              else {
                setOpen(false);
                edit(host.id);
              }
            }}
          >
            <Server className="size-4 shrink-0 text-muted-foreground" />
            <span className="min-w-0 flex-1">
              <span className="block truncate font-medium">{revealHidden(host.payload.alias)}</span>
              <span className="block truncate font-mono text-xs text-muted-foreground">
                {revealHidden(host.effective_payload.user)}@{revealHidden(host.effective_payload.hostname)}:{host.effective_payload.port}
              </span>
            </span>
            <span className="text-xs text-muted-foreground">
              {host.group_error ? "Needs review" : host.readiness.kind !== "ready" ? readinessLabel[host.readiness.kind] : <ArrowUpRight className="size-3.5" />}
            </span>
          </CommandItem>
        );
      })}
    </CommandGroup>
  );
  return (
    <CommandDialog
      open={open}
      onOpenChange={setOpen}
      title="Quick connect"
      description="Press Enter to connect or resume a tmux workspace. Shift Enter opens the tmux picker for a host. Command or Control Enter edits the host."
    >
      <Command
        onKeyDownCapture={(event) => {
          if (isImeKey(event) || event.key !== "Enter" || busy || editorBusy) return;
          const editHost = event.metaKey || event.ctrlKey;
          const openTmux = event.shiftKey && !event.altKey && !editHost;
          if (!editHost && !openTmux) return;
          const selected = list.current?.querySelector<HTMLElement>(
            '[cmdk-item][aria-selected="true"]',
          );
          const id = selected?.dataset.hostId;
          if (!id) return;
          if (openTmux && selected?.dataset.tmuxResume === "true") return;
          event.preventDefault();
          event.stopPropagation();
          if (openTmux) {
            if (selected?.dataset.tmuxReady === "true") void connect(id, {});
            return;
          }
          setOpen(false);
          edit(id);
        }}
      >
        <CommandInput placeholder="Search hosts, tmux sessions, or settings…" />
        <CommandList ref={list}>
          <CommandEmpty>No matching hosts, tmux workspaces, or commands.</CommandEmpty>
          {hostGroup("Recent", recentHosts)}
          {recentTmux.length > 0 && <CommandGroup heading="Recent tmux workspaces">
            {recentTmux.map(({ host, workspace }) => {
              const label = `${host.payload.alias} / ${workspace.session.name}`;
              return <CommandItem
                key={host.id}
                data-host-id={host.id}
                data-tmux-resume="true"
                value={`${label} tmux ${host.id}`}
                keywords={[recordHostSearchText(overview, host)]}
                disabled={busy || editorBusy}
                onSelect={() => void connect(host.id, { resume: workspace })}
              >
                <SquareTerminal className="size-4 shrink-0 text-muted-foreground" />
                <span className="min-w-0 flex-1 truncate font-medium" title={revealHidden(label)}>{revealHidden(label)}</span>
                <ArrowUpRight className="size-3.5 text-muted-foreground" />
              </CommandItem>;
            })}
          </CommandGroup>}
          {hostGroup("All hosts", available.filter((host) => !recentIds.has(host.id)))}
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
        <p className="border-t px-3 py-2 text-xs text-muted-foreground"><kbd>Shift</kbd> + <kbd>Enter</kbd> to connect with tmux</p>
      </Command>
    </CommandDialog>
  );
}
