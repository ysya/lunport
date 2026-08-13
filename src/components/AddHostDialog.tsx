import { useEffect, useMemo, useState } from "react";
import { FilePlus2, Plus } from "lucide-react";
import { toast } from "sonner";

import type { HostFieldChange } from "@/bindings/HostFieldChange";
import { useHostsQuery, useAddHost } from "@/lib/queries";
import { useUiStore } from "@/stores/ui";
import { useSettingsStore } from "@/stores/settings";
import { labelsFor } from "@/lib/host-display";
import { basename } from "@/lib/utils";
import { initialAddHostTarget } from "@/lib/add-host-target";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/** Sentinel Select value: opens the New-config-file dialog instead of picking. */
const NEW_FILE = "__new-file__";

export interface AddHostDialogProps {
  /**
   * `"icon"` (default) renders the compact `+` toolbar button; `"labeled"`
   * renders a full "New host" button for the empty-state CTA.
   */
  variant?: "icon" | "labeled";
}

export function AddHostDialog({ variant = "icon" }: AddHostDialogProps) {
  const { data } = useHostsQuery();
  const files = useMemo(() => data?.files ?? [], [data]);
  // Same display names as the sidebar: auto short labels + user file aliases.
  const fileAliases = useSettingsStore((s) => s.fileAliases);
  const labels = useMemo(() => labelsFor(files, fileAliases), [files, fileAliases]);
  const addHost = useAddHost();
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);
  const setNewFileIntent = useUiStore((s) => s.setNewFileIntent);

  // The toolbar (icon) instance — always mounted — owns the store-driven open
  // flag so the command palette's "New host" action can open it. The labeled
  // empty-state instance keeps purely-local state to avoid two dialogs sharing
  // one flag (both are mounted when there are zero hosts).
  const storeOpen = useUiStore((s) => s.addHostOpen);
  const setStoreOpen = useUiStore((s) => s.setAddHostOpen);
  const [localOpen, setLocalOpen] = useState(false);
  const open = variant === "icon" ? storeOpen : localOpen;
  const setOpen = variant === "icon" ? setStoreOpen : setLocalOpen;
  const [targetFile, setTargetFile] = useState<string>("");
  const [alias, setAlias] = useState("");
  const [hostName, setHostName] = useState("");
  const [user, setUser] = useState("");
  const [port, setPort] = useState("");

  // Sidebar file scope: when the user has scoped the list to ONE file, that
  // file is the natural default target for a new host. Only seed the choice
  // while the picker is still untouched — never fight an explicit selection.
  const fileScope = useUiStore((s) => s.fileScope);
  const addHostTargetFile = useUiStore((s) => s.addHostTargetFile);
  const setAddHostTargetFile = useUiStore((s) => s.setAddHostTargetFile);
  useEffect(() => {
    if (open && targetFile === "") {
      const seeded = initialAddHostTarget(addHostTargetFile, fileScope, files);
      if (seeded) setTargetFile(seeded);
    }
  }, [open, targetFile, addHostTargetFile, fileScope, files]);

  function resetForm() {
    setTargetFile("");
    setAlias("");
    setHostName("");
    setUser("");
    setPort("");
    setAddHostTargetFile(null);
  }

  const canSubmit = targetFile !== "" && alias.trim() !== "" && !addHost.isPending;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;

    const fields: HostFieldChange[] = [];
    const push = (keyword: string, value: string) => {
      const v = value.trim();
      if (v !== "") fields.push({ keyword, value: v, remove: false });
    };
    push("HostName", hostName);
    push("User", user);
    push("Port", port);

    const newAlias = alias.trim();
    addHost.mutate(
      { targetFile, alias: newAlias, fields },
      {
        onSuccess: () => {
          setOpen(false);
          resetForm();
          setSelectedAlias(newAlias);
          toast.success(`Added ${newAlias}`);
        },
      },
    );
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) resetForm();
      }}
    >
      <DialogTrigger asChild>
        {variant === "labeled" ? (
          <Button type="button" size="sm" variant="outline">
            <Plus className="size-4" /> New host
          </Button>
        ) : (
          <Button
            type="button"
            size="icon"
            variant="ghost"
            className="size-7"
            aria-label="New host"
            title="New host"
          >
            <Plus className="size-4" />
          </Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>New host</DialogTitle>
            <DialogDescription>
              Create a new SSH host block in the chosen config file.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="add-target-file">Target file</Label>
              <Select
                value={targetFile || undefined}
                onValueChange={(v) => {
                  if (v === NEW_FILE) {
                    // Hand off to the create dialog; it reopens Add host with
                    // the fresh file preselected (via addHostTargetFile).
                    setOpen(false);
                    resetForm();
                    setNewFileIntent({ kind: "addHost" });
                    return;
                  }
                  setTargetFile(v);
                }}
              >
                <SelectTrigger id="add-target-file" className="w-full">
                  <SelectValue placeholder="Select a config file" />
                </SelectTrigger>
                <SelectContent>
                  {files.map((f) => (
                    <SelectItem key={f} value={f} title={f} className="font-mono">
                      {labels.get(f) ?? basename(f)}
                    </SelectItem>
                  ))}
                  <SelectSeparator />
                  <SelectItem value={NEW_FILE}>
                    <FilePlus2 className="size-3.5" /> New config file…
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="add-alias">Alias</Label>
              <Input
                id="add-alias"
                value={alias}
                onChange={(e) => setAlias(e.target.value)}
                placeholder="my-server"
                className="font-mono"
                autoFocus
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="add-hostname">HostName</Label>
              <Input
                id="add-hostname"
                value={hostName}
                onChange={(e) => setHostName(e.target.value)}
                placeholder="example.com"
                className="font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="add-user">User</Label>
                <Input
                  id="add-user"
                  value={user}
                  onChange={(e) => setUser(e.target.value)}
                  placeholder="root"
                  className="font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="add-port">Port</Label>
                <Input
                  id="add-port"
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder="22"
                  className="font-mono"
                />
              </div>
            </div>
          </div>

          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={!canSubmit}>
              {addHost.isPending ? "Adding…" : "Create host"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default AddHostDialog;
