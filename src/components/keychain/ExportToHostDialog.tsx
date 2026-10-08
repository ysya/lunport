import { useMemo, useState } from "react";
import { toast } from "sonner";

import type { HostSummary } from "@/bindings/HostSummary";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { isWildcardOnly } from "@/lib/host-display";
import { useDeployKey, useHostsQuery, usePlatform } from "@/lib/queries";
import { revealHidden } from "@/lib/sync-approvals";
import { useLastNonNull } from "@/lib/use-last-non-null";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";

/** The key Export to host exports: its name, its public key file, and whether it is a key in SSHelter. */
export interface ExportTarget {
  name: string;
  publicPath: string;
  inSSHelter: boolean;
}

export type ExportMode = "app" | "terminal";

/**
 * Export to host's host picker (key vault spec §7.3.1). `terminal` = the Terminal way is offered. No hooks: exported for the tests.
 */
export function ExportToHostView({
  name,
  hosts,
  mode,
  terminal,
  busy,
  onMode,
  onPick,
}: {
  name: string;
  hosts: HostSummary[];
  mode: ExportMode;
  terminal: boolean;
  busy: boolean;
  onMode: (mode: ExportMode) => void;
  onPick: (alias: string) => void;
}) {
  return (
    <>
      <DialogHeader>
        <DialogTitle>Export {revealHidden(name)} to a host</DialogTitle>
        <DialogDescription>{"Adds the public key to the host's authorized_keys, then sets the host to use this key."}</DialogDescription>
      </DialogHeader>
      {terminal && (
        <div className="flex gap-1" role="group" aria-label="How to export">
          {(["app", "terminal"] as const).map((m) => (
            <Button key={m} type="button" size="sm" variant={mode === m ? "secondary" : "ghost"} className="h-7" aria-pressed={mode === m} onClick={() => onMode(m)}>
              {m === "app" ? "In the app" : "In Terminal (ssh-copy-id)"}
            </Button>
          ))}
        </div>
      )}
      {terminal && mode === "terminal" && <p className="text-xs text-muted-foreground">{"The terminal deploy doesn't change the host's settings."}</p>}
      <Command className="rounded-lg border">
        <CommandInput placeholder="Search hosts…" autoFocus />
        <CommandList className="max-h-[40vh]">
          <CommandEmpty>No hosts found.</CommandEmpty>
          {hosts.map((h) => (
            <CommandItem key={`${h.source_file}::${h.alias}`} value={`${h.alias} ${h.hostname ?? ""}`} disabled={busy} onSelect={() => onPick(h.alias)}>
              <span className="truncate font-mono text-sm">{revealHidden(h.alias)}</span>
              {h.hostname && (
                <span className="ml-auto truncate pl-3 font-mono text-xs text-muted-foreground">
                  {h.user ? `${revealHidden(h.user)}@` : ""}
                  {revealHidden(h.hostname)}
                </span>
              )}
            </CommandItem>
          ))}
        </CommandList>
      </Command>
    </>
  );
}

/**
 * Export to host. In the app, the deploy dialog takes over: it deploys, then points the host at the key. In Terminal, ssh-copy-id
 * runs and the host's settings stay as they are. It is offered only for a key file, and not on Windows (no ssh-copy-id there).
 * ssh-copy-id refuses a .pub whose private key file isn't next to it, and a key in SSHelter has no such file.
 */
export function ExportToHostDialog({ target, onClose }: { target: ExportTarget | null; onClose: () => void }) {
  const [mode, setMode] = useState<ExportMode>("app");
  const platform = usePlatform();
  const deploy = useDeployKey();
  const terminalId = useSettingsStore((s) => s.terminalId);
  const setDeployKeyAlias = useUiStore((s) => s.setDeployKeyAlias);
  const setDeployKeyInitialPub = useUiStore((s) => s.setDeployKeyInitialPub);
  const setDeployKeyInitialName = useUiStore((s) => s.setDeployKeyInitialName);
  const { data } = useHostsQuery();
  // Real hosts only: wildcard blocks (`Host *`) are defaults.
  const hosts = useMemo(() => (data?.hosts ?? []).filter((h) => !isWildcardOnly(h)), [data]);
  // What the dialog shows while it animates out (`target` is already null by then).
  const shown = useLastNonNull(target);
  const terminal = shown !== null && !shown.inSSHelter && platform.data !== undefined && platform.data !== "windows";
  const pick = (alias: string) => {
    if (!target) return;
    if (terminal && mode === "terminal") {
      deploy.mutate(
        { alias, publicPath: target.publicPath, terminalOverride: terminalId },
        {
          onSuccess: () => {
            toast.success("Opening terminal…", { description: `ssh-copy-id ${revealHidden(target.name)} → ${revealHidden(alias)}` });
            onClose();
          },
        },
      );
      return;
    }
    onClose();
    setDeployKeyInitialPub(target.publicPath);
    setDeployKeyInitialName(target.name);
    setDeployKeyAlias(alias);
  };
  return (
    <Dialog open={target !== null} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="sm:max-w-md">
        {shown && (
          <ExportToHostView name={shown.name} hosts={hosts} mode={mode} terminal={terminal} busy={deploy.isPending} onMode={setMode} onPick={pick} />
        )}
      </DialogContent>
    </Dialog>
  );
}
