import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Moon,
  Pencil,
  Plus,
  RotateCw,
  Server,
  Sun,
  TerminalSquare,
} from "lucide-react";

import {
  useHostsQuery,
  useConnect,
  useLoadConfig,
} from "@/lib/queries";
import { useUiStore } from "@/stores/ui";

import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";

/**
 * The ⌘K / Ctrl+K command palette. Mounted once (in App).
 *
 * Hosts group: cmdk fuzzy-filters host aliases / targets. The highlighted item
 * responds to two routes:
 *   - plain **Enter** → connect (cmdk's default `onSelect`)
 *   - **⌘/Ctrl+Enter** → open in editor
 *
 * Enter-vs-⌘Enter handling: cmdk's `onSelect` cannot see modifier keys, so we
 * add a `keydown` *capture* listener on the dialog. When it sees
 * `Enter && (metaKey || ctrlKey)` it reads the currently-highlighted item's
 * `data-alias` (cmdk marks it `aria-selected="true"`), routes to edit, and
 * `preventDefault()`s so cmdk's plain-Enter connect path never fires. Plain
 * Enter is left untouched and falls through to `onSelect` (= connect).
 */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const { data } = useHostsQuery();
  const hosts = data?.hosts ?? [];

  const connect = useConnect();
  const reload = useLoadConfig();
  const queryClient = useQueryClient();

  const terminalId = useUiStore((s) => s.terminalId);
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);
  const setAddHostOpen = useUiStore((s) => s.setAddHostOpen);
  const toggleTheme = useUiStore((s) => s.toggleTheme);

  // Global ⌘K / Ctrl+K toggle.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const doConnect = useCallback(
    (alias: string) => {
      connect.mutate({ alias, terminalOverride: terminalId });
      setOpen(false);
    },
    [connect, terminalId],
  );

  const doEdit = useCallback(
    (alias: string) => {
      setSelectedAlias(alias);
      setOpen(false);
    },
    [setSelectedAlias],
  );

  const doNewHost = useCallback(() => {
    setOpen(false);
    setAddHostOpen(true);
  }, [setAddHostOpen]);

  const doReload = useCallback(() => {
    setOpen(false);
    reload.mutate(undefined, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ["config"] });
        toast.success("Reloaded from disk");
      },
    });
  }, [reload, queryClient]);

  const doToggleTheme = useCallback(() => {
    toggleTheme();
    setOpen(false);
  }, [toggleTheme]);

  // ⌘/Ctrl+Enter on the highlighted host → edit instead of connect.
  const onKeyDownCapture = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (e.key !== "Enter" || !(e.metaKey || e.ctrlKey)) return;
      const selected = listRef.current?.querySelector<HTMLElement>(
        '[cmdk-item][aria-selected="true"]',
      );
      const alias = selected?.dataset.alias;
      if (alias) {
        e.preventDefault();
        e.stopPropagation();
        doEdit(alias);
      }
    },
    [doEdit],
  );

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <Command onKeyDownCapture={onKeyDownCapture}>
        <CommandInput placeholder="Search hosts or run a command…" />
        <CommandList ref={listRef}>
          <CommandEmpty>No results.</CommandEmpty>

          {hosts.length > 0 && (
            <CommandGroup heading="Hosts">
              {hosts.map((host) => {
                const target =
                  host.user && host.hostname
                    ? `${host.user}@${host.hostname}`
                    : host.hostname || host.user || host.source_file;
                return (
                  <CommandItem
                    key={`${host.source_file}::${host.alias}`}
                    // cmdk filters on `value`; include the secondary text so a
                    // search for the hostname/user also matches.
                    value={`${host.alias} ${target} ${host.tags.join(" ")}`}
                    data-alias={host.alias}
                    onSelect={() => doConnect(host.alias)}
                  >
                    <Server className="text-muted-foreground" />
                    <span className="font-mono">{host.alias}</span>
                    <span className="ml-auto truncate pl-3 text-xs text-muted-foreground">
                      {target}
                    </span>
                  </CommandItem>
                );
              })}
            </CommandGroup>
          )}

          <CommandSeparator />

          <CommandGroup heading="Actions">
            <CommandItem value="new host create add" onSelect={doNewHost}>
              <Plus className="text-muted-foreground" />
              New host
            </CommandItem>
            <CommandItem value="toggle theme dark light" onSelect={doToggleTheme}>
              <span className="flex size-4 items-center justify-center text-muted-foreground">
                <Sun className="size-4 dark:hidden" />
                <Moon className="hidden size-4 dark:block" />
              </span>
              Toggle theme
            </CommandItem>
            <CommandItem value="reload refresh disk" onSelect={doReload}>
              <RotateCw className="text-muted-foreground" />
              Reload from disk
            </CommandItem>
          </CommandGroup>
        </CommandList>

        {/* Footer hint — connect vs edit affordance. */}
        <div className="flex items-center gap-3 border-t px-3 py-2 text-[0.6875rem] text-muted-foreground select-none">
          <span className="flex items-center gap-1">
            <TerminalSquare className="size-3" />
            <kbd className="font-mono">↵</kbd> connect
          </span>
          <span className="text-muted-foreground/40">·</span>
          <span className="flex items-center gap-1">
            <Pencil className="size-3" />
            <kbd className="font-mono">⌘↵</kbd> edit
          </span>
        </div>
      </Command>
    </CommandDialog>
  );
}

export default CommandPalette;
