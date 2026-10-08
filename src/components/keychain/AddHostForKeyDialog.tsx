import { useMemo, useState } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import type { HostFieldChange } from "@/bindings/HostFieldChange";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { initialAddHostTarget } from "@/lib/add-host-target";
import { hostAliasProblem } from "@/lib/keychain";
import { useAddHost, useHostsQuery } from "@/lib/queries";
import { syncOverviewKey } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { useFileLabels } from "@/lib/sync-labels";
import { basename } from "@/lib/utils";
import { useUiStore } from "@/stores/ui";

/** The key a new host is made for: its name, and the IdentityFile value the host gets (a key in SSHelter's slot path, or a key file's `~/` path). */
export interface AddHostForKeyTarget {
  name: string;
  value: string;
}

export interface AddHostForKeyState {
  alias: string;
  hostName: string;
  user: string;
  file: string;
}

/**
 * Add a host for this key (key vault spec §6, §7.3): a new host block whose IdentityFile is the key. No hooks: exported for the tests.
 * The key's name and value, the file labels and the aliases that exist come from the disk or the config: shown through `revealHidden`.
 */
export function AddHostForKeyView({
  target,
  state,
  files,
  labels,
  existing,
  busy,
  onChange,
  onAdd,
  onCancel,
}: {
  target: AddHostForKeyTarget;
  state: AddHostForKeyState;
  files: string[];
  labels: Map<string, string>;
  existing: ReadonlySet<string>;
  busy: boolean;
  onChange: (patch: Partial<AddHostForKeyState>) => void;
  onAdd: () => void;
  onCancel: () => void;
}) {
  const problem = state.alias === "" ? null : hostAliasProblem(state.alias, existing);
  const ready = state.alias.trim() !== "" && problem === null && state.file !== "";
  return (
    <>
      <DialogHeader>
        <DialogTitle>{`Add a host for ${revealHidden(target.name)}`}</DialogTitle>
        <DialogDescription>{`The new host uses this key: IdentityFile ${revealHidden(target.value)}`}</DialogDescription>
      </DialogHeader>
      <div className="space-y-3">
        <div className="space-y-1.5">
          <Label htmlFor="key-host-alias">Host</Label>
          <Input id="key-host-alias" className="font-mono" placeholder="github.com" value={state.alias} disabled={busy} onChange={(e) => onChange({ alias: e.target.value })} />
          {problem && <p className="text-xs text-destructive">{problem}</p>}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="key-host-hostname">HostName</Label>
          <Input id="key-host-hostname" className="font-mono" placeholder="optional" value={state.hostName} disabled={busy} onChange={(e) => onChange({ hostName: e.target.value })} />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="key-host-user">User</Label>
          <Input id="key-host-user" className="font-mono" placeholder="git" value={state.user} disabled={busy} onChange={(e) => onChange({ user: e.target.value })} />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="key-host-file">File</Label>
          <Select value={state.file || undefined} onValueChange={(file) => onChange({ file })} disabled={busy}>
            <SelectTrigger id="key-host-file" className="w-full">
              <SelectValue placeholder="Select a config file" />
            </SelectTrigger>
            <SelectContent>
              {files.map((f) => (
                <SelectItem key={f} value={f} title={revealHidden(f)} className="font-mono">
                  {revealHidden(labels.get(f) ?? basename(f))}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>
          Cancel
        </Button>
        <Button type="button" disabled={busy || !ready} onClick={onAdd}>
          Add host
        </Button>
      </DialogFooter>
    </>
  );
}

/**
 * A key path as ssh_config needs it: ssh splits an unquoted value at whitespace, so a key file named "id work" would be two arguments
 * and ssh would reject the whole config; in double quotes it is one. A path that already has a double quote is written as it is
 * (the backend's `quote_spaced_path` has the same rule for the IdentityFile it sets). `config_add_host` writes values as given.
 */
function sshPathValue(path: string): string {
  return /\s/.test(path) && !path.includes('"') ? `"${path}"` : path;
}

/** The new host's lines: HostName and User when they were typed, and always IdentityFile, the key. Exported for the tests. */
export function newHostFields(state: AddHostForKeyState, identityFile: string): HostFieldChange[] {
  const fields: HostFieldChange[] = [];
  const push = (keyword: string, value: string) => fields.push({ keyword, value, remove: false });
  if (state.hostName.trim() !== "") push("HostName", state.hostName.trim());
  if (state.user.trim() !== "") push("User", state.user.trim());
  push("IdentityFile", sshPathValue(identityFile));
  return fields;
}

/**
 * After the host was written: refresh the hosts the key's detail lists (the key files' and the key slots'), ask the Sync key dialog
 * about the key (a host in a synced space may now use a key only on this computer, spec §4.3; the dialog opens only when there is
 * something to ask), and say the host was added. Exported for the tests.
 */
export function afterHostAdded(queryClient: QueryClient, alias: string): void {
  void queryClient.invalidateQueries({ queryKey: ["keys"] });
  void queryClient.invalidateQueries({ queryKey: syncOverviewKey });
  useUiStore.getState().setKeySetup({ aliases: [alias], reason: "saved" });
  toast.success(`Added ${revealHidden(alias)}`);
}

/**
 * The dialog; its form is mounted only while open (keyed by the key), so it starts empty each time. The write is held here, not in
 * the form: closing the dialog while the host is written would drop the callbacks that refresh the key's hosts and ask the Sync key
 * dialog, so the dialog stays open until the write is done.
 */
export function AddHostForKeyDialog({ target, onClose }: { target: AddHostForKeyTarget | null; onClose: () => void }) {
  const addHost = useAddHost();
  const busy = addHost.isPending;
  return (
    <Dialog open={target !== null} onOpenChange={(next) => !next && !busy && onClose()}>
      <DialogContent className="sm:max-w-md" showCloseButton={!busy}>
        {target && <AddHostForKeyFlow key={target.value} target={target} addHost={addHost} onClose={onClose} />}
      </DialogContent>
    </Dialog>
  );
}

function AddHostForKeyFlow({ target, addHost, onClose }: { target: AddHostForKeyTarget; addHost: ReturnType<typeof useAddHost>; onClose: () => void }) {
  const hosts = useHostsQuery();
  const files = useMemo(() => hosts.data?.files ?? [], [hosts.data]);
  const labels = useFileLabels(files);
  const fileScope = useUiStore((s) => s.fileScope);
  const existing = useMemo(() => new Set((hosts.data?.hosts ?? []).flatMap((h) => h.patterns)), [hosts.data]);
  const queryClient = useQueryClient();
  // The file the sidebar is scoped to, else none: Add host stays off until one is chosen.
  const [state, setState] = useState<AddHostForKeyState>(() => ({ alias: "", hostName: "", user: "", file: initialAddHostTarget(null, fileScope, files) }));
  const add = () => {
    const alias = state.alias.trim();
    addHost.mutate(
      { targetFile: state.file, alias, fields: newHostFields(state, target.value) },
      {
        onSuccess: () => {
          afterHostAdded(queryClient, alias);
          onClose();
        },
      },
    );
  };
  return (
    <AddHostForKeyView
      target={target}
      state={state}
      files={files}
      labels={labels}
      existing={existing}
      busy={addHost.isPending}
      onChange={(patch) => setState((s) => ({ ...s, ...patch }))}
      onAdd={add}
      onCancel={onClose}
    />
  );
}
