import { useEffect, useState } from "react";
import { FilePlus2, Loader2 } from "lucide-react";
import { toast } from "sonner";

import {
  useCreateConfigFile,
  useMoveHost,
  usePlanNewFile,
} from "@/lib/queries";
import { useUiStore, type NewFileIntent } from "@/stores/ui";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/**
 * "New config file…" — reachable from every file picker (sidebar scope,
 * Add-host target, Move-to-file). Shows live where the file will land and
 * whether the main config gains an Include line, then continues the flow it
 * was opened from: scope to the new file, preselect it for a new host, or
 * move the pending hosts into it.
 */
export function NewConfigFileDialog() {
  const intent = useUiStore((s) => s.newFileIntent);
  const setNewFileIntent = useUiStore((s) => s.setNewFileIntent);

  return (
    <Dialog
      open={intent !== null}
      onOpenChange={(next) => {
        if (!next) setNewFileIntent(null);
      }}
    >
      <DialogContent className="sm:max-w-md">
        {intent !== null && (
          <NewFileFlow intent={intent} onClose={() => setNewFileIntent(null)} />
        )}
      </DialogContent>
    </Dialog>
  );
}

function NewFileFlow({
  intent,
  onClose,
}: {
  intent: NewFileIntent;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const plan = usePlanNewFile();
  const create = useCreateConfigFile();
  const moveHost = useMoveHost();
  const setFileScope = useUiStore((s) => s.setFileScope);
  const setGroupMode = useUiStore((s) => s.setGroupMode);
  const setAddHostTargetFile = useUiStore((s) => s.setAddHostTargetFile);
  const setAddHostOpen = useUiStore((s) => s.setAddHostOpen);

  // Live plan preview, lightly debounced — the command is pure computation.
  const planMutate = plan.mutate;
  useEffect(() => {
    const trimmed = name.trim();
    if (trimmed === "") return;
    const t = window.setTimeout(() => planMutate({ name: trimmed }), 150);
    return () => window.clearTimeout(t);
  }, [name, planMutate]);

  const trimmed = name.trim();
  const planned = trimmed !== "" && !plan.isPending ? plan.data : undefined;
  const planError =
    trimmed === ""
      ? null
      : plan.error !== null
        ? String(plan.error)
        : planned?.alreadyExists
          ? `${planned.path} already exists.`
          : null;

  async function runIntent(path: string) {
    switch (intent.kind) {
      case "scope":
        // Show the new (empty) file where it will live: the file view.
        setGroupMode("file");
        setFileScope(path);
        break;
      case "addHost":
        setAddHostTargetFile(path);
        setAddHostOpen(true);
        break;
      case "move": {
        let moved = 0;
        for (const alias of intent.aliases) {
          try {
            await moveHost.mutateAsync({ alias, targetFile: path });
            moved += 1;
          } catch {
            // Per-host failures already toast via the mutation; keep going.
          }
        }
        toast.success(`Moved ${moved}/${intent.aliases.length} into the new file`);
        break;
      }
    }
  }

  function handleCreate() {
    if (trimmed === "" || planError !== null) return;
    create.mutate(
      { name: trimmed },
      {
        onSuccess: async (path) => {
          toast.success(`Created ${path}`);
          await runIntent(path);
          onClose();
        },
      },
    );
  }

  const intentHint =
    intent.kind === "addHost"
      ? "The new host will be placed in this file."
      : intent.kind === "move"
        ? `${intent.aliases.length} ${intent.aliases.length === 1 ? "host" : "hosts"} will move into this file.`
        : null;

  return (
    <>
      <DialogHeader>
        <DialogTitle>New config file</DialogTitle>
        <DialogDescription>
          A separate file for a group of hosts — ssh loads it through{" "}
          <span className="font-mono">Include</span>.
        </DialogDescription>
      </DialogHeader>

      <div className="space-y-3">
        <div className="space-y-1.5">
          <Label htmlFor="new-file-name">File name</Label>
          <Input
            id="new-file-name"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="work"
            className="font-mono"
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                handleCreate();
              }
            }}
          />
        </div>

        {planError !== null && (
          <p className="text-xs text-destructive">{planError}</p>
        )}
        {planError === null && planned && (
          <div className="space-y-1 rounded-md border bg-muted/40 p-3 text-xs">
            <p className="font-mono break-all">{planned.path}</p>
            {planned.finalName !== trimmed && (
              <p className="text-muted-foreground">
                Saved as <span className="font-mono">{planned.finalName}</span>{" "}
                to match the Include pattern.
              </p>
            )}
            {planned.coveredBy !== null ? (
              <p className="text-muted-foreground">
                Loaded automatically by{" "}
                <span className="font-mono">Include {planned.coveredBy}</span>{" "}
                — your main config is not touched.
              </p>
            ) : (
              <p className="text-muted-foreground">
                SSHelter will add{" "}
                <span className="font-mono">
                  Include {planned.includeValue}
                </span>{" "}
                near the top of your main config (backed up first).
              </p>
            )}
            {intentHint && <p className="text-muted-foreground">{intentHint}</p>}
          </div>
        )}
      </div>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button
          type="button"
          onClick={handleCreate}
          disabled={
            trimmed === "" || plan.isPending || planError !== null || create.isPending
          }
        >
          {create.isPending ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <FilePlus2 className="size-4" />
          )}
          Create
        </Button>
      </DialogFooter>
    </>
  );
}
