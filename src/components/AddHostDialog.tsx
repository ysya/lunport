import { useState } from "react";
import { Plus } from "lucide-react";

import type { HostFieldChange } from "@/bindings/HostFieldChange";
import { useHostsQuery, useAddHost } from "@/lib/queries";
import { useUiStore } from "@/stores/ui";

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
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/** Last path segment of a (possibly `/`- or `\`-separated) file path. */
function basename(p: string): string {
  const norm = p.replace(/\\/g, "/");
  const parts = norm.split("/");
  return parts[parts.length - 1] || p;
}

export function AddHostDialog() {
  const { data } = useHostsQuery();
  const files = data?.files ?? [];
  const addHost = useAddHost();
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);

  const [open, setOpen] = useState(false);
  const [targetFile, setTargetFile] = useState<string>("");
  const [alias, setAlias] = useState("");
  const [hostName, setHostName] = useState("");
  const [user, setUser] = useState("");
  const [port, setPort] = useState("");

  function resetForm() {
    setTargetFile("");
    setAlias("");
    setHostName("");
    setUser("");
    setPort("");
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
        <Button size="sm" variant="default">
          <Plus className="size-4" /> Add host
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Add host</DialogTitle>
            <DialogDescription>
              Create a new SSH host block in the chosen config file.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="add-target-file">Target file</Label>
              <Select value={targetFile || undefined} onValueChange={setTargetFile}>
                <SelectTrigger id="add-target-file" className="w-full">
                  <SelectValue placeholder="Select a config file" />
                </SelectTrigger>
                <SelectContent>
                  {files.map((f) => (
                    <SelectItem key={f} value={f}>
                      {basename(f)}
                    </SelectItem>
                  ))}
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
              {addHost.isPending ? "Adding…" : "Add host"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default AddHostDialog;
