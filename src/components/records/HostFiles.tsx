import { useCallback, useEffect, useRef, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { listen } from "@tauri-apps/api/event";
import { confirm, open as chooseFile, save as chooseDestination } from "@tauri-apps/plugin-dialog";
import { ArrowDownToLine, ArrowUpFromLine, File, Folder, RotateCw, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TaskDialogBody, TaskDialogContent } from "@/components/app/TaskDialog";
import { recordsFilesCancel, recordsFilesList, recordsFilesTransfer, type RecordHostView, type RemoteFileEntry, type RemoteListing } from "@/lib/records";
import { errorMessage } from "@/lib/utils";
import { revealHidden } from "@/lib/reveal-hidden";
import { useUiStore } from "@/stores/ui";

type Progress = { id: string; bytes: number; total: number | null };
type Active = { id: string; direction: "upload" | "download"; name: string; bytes: number; total: number | null };

function child(parent: string, name: string) {
  return `${parent.replace(/\/+$/, "")}/${name}`;
}

function breadcrumbs(path: string) {
  if (!path.startsWith("/")) {
    const [drive, ...parts] = path.split("/").filter(Boolean);
    return [{ name: `${drive}/`, path: `${drive}/` }, ...parts.map((name, index) => ({ name, path: `${drive}/${parts.slice(0, index + 1).join("/")}` }))];
  }
  const parts = path.split("/").filter(Boolean);
  return [{ name: "/", path: "/" }, ...parts.map((name, index) => ({ name, path: `/${parts.slice(0, index + 1).join("/")}` }))];
}

function sizeLabel(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function HostFiles({ host, open, onOpenChange }: { host: RecordHostView; open: boolean; onOpenChange: (open: boolean) => void }) {
  const [path, setPath] = useState(".");
  const [listing, setListing] = useState<RemoteListing | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [active, setActive] = useState<Active | null>(null);
  const [dragging, setDragging] = useState(false);
  const busy = useRef(false);
  const setSettingsOpen = useUiStore((state) => state.setSettingsOpen);
  const setSettingsCategory = useUiStore((state) => state.setSettingsCategory);
  const uploadRef = useRef<(filePath: string) => Promise<void>>(async () => {});

  useEffect(() => {
    if (!open) return;
    let live = true;
    setLoading(true);
    setError(null);
    recordsFilesList(host.id, path).then((result) => {
      if (live) setListing(result);
    }).catch((cause) => {
      if (live) { setListing(null); setError(errorMessage(cause)); }
    }).finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [host.id, open, path, refresh]);

  useEffect(() => {
    if (!open) return;
    let live = true;
    const stop = listen<Progress>("files://progress", (event) => {
      if (live) setActive((current) => current?.id === event.payload.id ? { ...current, bytes: event.payload.bytes, total: event.payload.total } : current);
    });
    return () => { live = false; void stop.then((unlisten) => unlisten()); };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    let live = true;
    const stop = getCurrentWebview().onDragDropEvent((event) => {
      if (!live) return;
      if (event.payload.type === "over") setDragging(true);
      if (event.payload.type === "leave") setDragging(false);
      if (event.payload.type === "drop") {
        setDragging(false);
        if (event.payload.paths.length !== 1) {
          toast.error("Choose one file at a time");
        } else {
          void uploadRef.current(event.payload.paths[0]);
        }
      }
    });
    return () => { live = false; void stop.then((unlisten) => unlisten()); };
  }, [open]);

  const transfer = useCallback(async (direction: "upload" | "download", localPath: string, remotePath: string, name: string, overwrite = false, total: number | null = null) => {
    if (busy.current) return;
    busy.current = true;
    const id = crypto.randomUUID();
    setError(null);
    setActive({ id, direction, name, bytes: 0, total });
    try {
      await recordsFilesTransfer({ id, hostId: host.id, direction, localPath, remotePath, overwrite });
      toast.success(direction === "upload" ? "File uploaded" : "File downloaded", { description: revealHidden(name) });
      setRefresh((value) => value + 1);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      busy.current = false;
      setActive(null);
    }
  }, [host.id]);

  const upload = async (filePath: string) => {
    if (!listing || loading) { setError("Wait for the remote folder to load, then drop the file again."); return; }
    if (busy.current) { setError("Finish the current transfer before uploading another file."); return; }
    const name = filePath.split(/[/\\]/).pop();
    if (!name) { setError("Choose a file with a name."); return; }
    const existing = listing.entries.find((entry) => entry.name === name);
    if (existing && existing.kind !== "file") {
      setError("A remote folder or link already has this name.");
      return;
    }
    const overwrite = !!existing;
    if (overwrite) {
      try {
        if (!await confirm(`Replace ${revealHidden(name)} on ${revealHidden(host.payload.alias)}?`, { title: "Replace remote file", kind: "warning" })) return;
      } catch (cause) { setError(errorMessage(cause)); return; }
    }
    await transfer("upload", filePath, child(listing.path, name), name, overwrite);
  };
  uploadRef.current = upload;

  const pickUpload = async () => {
    try {
      const chosen = await chooseFile({ multiple: false, directory: false, title: "Choose a file to upload" });
      if (typeof chosen === "string") await upload(chosen);
    } catch (cause) { setError(errorMessage(cause)); }
  };

  const download = async (entry: RemoteFileEntry) => {
    if (!listing || busy.current) return;
    try {
      const destination = await chooseDestination({ defaultPath: entry.name, title: `Download ${entry.name}` });
      if (destination) await transfer("download", destination, child(listing.path, entry.name), entry.name, false, entry.size);
    } catch (cause) { setError(errorMessage(cause)); }
  };

  const navigate = (next: string) => {
    if (!active && !loading && next !== listing?.path) setPath(next);
  };

  return <Dialog open={open} onOpenChange={(next) => {
    if (!next && active) { toast.message("Finish or cancel the transfer before closing Files"); return; }
    onOpenChange(next);
  }}>
    <TaskDialogContent className="sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle>Files on {revealHidden(host.payload.alias)}</DialogTitle>
        <DialogDescription>Browse the server, then upload a local file or download one file. Drag a file here to upload it.</DialogDescription>
      </DialogHeader>
      <TaskDialogBody className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <nav aria-label="Remote folder" className="flex min-w-0 flex-wrap items-center gap-1 text-sm">
            {breadcrumbs(listing?.path ?? "/").map((crumb) =>
              <Button key={crumb.path} size="sm" variant="ghost" disabled={!!active || loading} onClick={() => navigate(crumb.path)}>{revealHidden(crumb.name)}</Button>)}
          </nav>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" aria-label="Refresh files" disabled={loading || !!active} onClick={() => setRefresh((value) => value + 1)}><RotateCw className="size-4" /></Button>
            <Button size="sm" disabled={!listing || loading || !!active} onClick={() => void pickUpload()}><ArrowUpFromLine className="size-4" />Upload…</Button>
          </div>
        </div>
        <div className={`min-h-56 rounded-lg border ${dragging ? "border-primary bg-primary/5" : ""}`} aria-label="Remote files">
          {loading && <p role="status" className="p-4 text-sm text-muted-foreground">Loading remote folder…</p>}
          {!loading && listing?.entries.length === 0 && <p className="p-4 text-sm text-muted-foreground">This folder is empty. Drag a file here or choose Upload.</p>}
          {!loading && listing?.entries.map((entry) => <div key={entry.name} className="flex items-center gap-3 border-b px-3 py-2 last:border-0">
            {entry.kind === "directory" ? <Folder className="size-4 shrink-0 text-muted-foreground" /> : <File className="size-4 shrink-0 text-muted-foreground" />}
            {entry.kind === "directory" ? <button type="button" className="min-w-0 flex-1 truncate text-left text-sm hover:underline" disabled={!!active} onClick={() => navigate(child(listing.path, entry.name))}>{revealHidden(entry.name)}</button>
              : <span className="min-w-0 flex-1 truncate text-sm">{revealHidden(entry.name)}</span>}
            {entry.kind === "file" && <><span className="text-xs text-muted-foreground">{sizeLabel(entry.size)}</span><Button size="sm" variant="outline" disabled={!!active} onClick={() => void download(entry)}><ArrowDownToLine className="size-3.5" />Download…</Button></>}
            {entry.kind === "symlink" && <span className="text-xs text-muted-foreground">Link</span>}
            {entry.kind === "other" && <span className="text-xs text-muted-foreground">Other</span>}
          </div>)}
        </div>
        {active && <div role="status" className="rounded-lg border p-3 text-sm">
          <div className="flex items-center justify-between gap-2"><span>{active.direction === "upload" ? "Uploading" : "Downloading"} {revealHidden(active.name)}</span><Button size="sm" variant="outline" onClick={() => void recordsFilesCancel(active.id).catch((cause) => setError(errorMessage(cause)))}><X className="size-3.5" />Cancel</Button></div>
          <p className="mt-1 text-xs text-muted-foreground">{sizeLabel(active.bytes)}{active.total !== null ? ` / ${sizeLabel(active.total)}` : ""}</p>
          {active.total !== null && <progress className="mt-2 w-full" max={Math.max(active.total, 1)} value={Math.min(active.bytes, active.total)} aria-label="Transfer progress" />}
        </div>}
        {error && <div role="alert" className="app-error whitespace-pre-wrap"><p>{revealHidden(error)}</p>{!listing && <Button size="sm" variant="outline" className="mt-2" onClick={() => { setPath("."); setRefresh((value) => value + 1); }}>Back to home folder</Button>}</div>}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>Single files only. Downloads never replace an existing local file.</span>
          <Button size="sm" variant="link" disabled={!!active} onClick={() => { onOpenChange(false); setSettingsCategory("ai"); setSettingsOpen(true); }}>Change transfer limit</Button>
        </div>
      </TaskDialogBody>
    </TaskDialogContent>
  </Dialog>;
}
