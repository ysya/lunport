import { useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { open } from "@tauri-apps/plugin-dialog";
import { KeyRound, Search, Plus, Upload, ArrowUpRight, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { TaskDialogContent as DialogContent, TaskDialogBody } from "@/components/app/TaskDialog";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogAction, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { PageHeader } from "@/components/app/PageHeader";
import { DetailPresence } from "@/components/app/DetailPresence";
import { applyRecordOverview, downloadRecordKey, setRecordKeySync, type RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { copyText } from "@/lib/clipboard";
import { isValidSlotName } from "@/lib/key-slots";
import { clearKeyDraft, hasKeyImportSource, submitKeyDraft } from "./panel-actions";
import { basename } from "@/lib/utils";
import { KeyImportFields } from "./KeyImportFields";
import { RecordField } from "./form";
import { DetailPane } from "./DetailPane";
import { RecordsDeployKeyDialog } from "./DeployKeyDialog";

export const KEYS_SEARCH_INPUT_ID = "records-key-search";
export const GENERATE_KEY_BUTTON_ID = "records-generate-key";

export function RecordsKeysPanel({ overview }: { overview: RecordOverview }) {
  const client = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(overview.keys[0]?.id ?? null);
  const [search, setSearch] = useState("");
  const [deployKeyId, setDeployKeyId] = useState<string | null>(null);
  const [mode, setMode] = useState<"import" | "generate" | null>(null);
  const [draft, setDraft] = useState(clearKeyDraft);
  const [discarding, setDiscarding] = useState(false);
  const [confirming, setConfirming] = useState<{ id: string; enabled: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const collection = useRef<HTMLDivElement>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const editorTrigger = useRef<HTMLButtonElement | null>(null);
  const update = (patch: Partial<typeof draft>) => setDraft((current) => ({ ...current, ...patch }));
  const reset = () => { setDraft(clearKeyDraft()); setMode(null); setDiscarding(false); };
  const requestClose = () => {
    if (draft.busy || inFlight.current) return;
    if (draft.name || draft.privateText || draft.path) setDiscarding(true);
    else reset();
  };
  const submit = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      if (await submitKeyDraft(client, draft, update, mode === "generate")) reset();
    } finally { inFlight.current = false; }
  };
  const chooseFile = async () => {
    if (inFlight.current || draft.busy) return;
    inFlight.current = true;
    update({ busy: true, error: null });
    try {
      const path = await open({ multiple: false, directory: false, title: "Choose an OpenSSH private key" });
      if (typeof path === "string") setDraft((current) => ({
        ...current, path, source: "file",
        name: current.name || (isValidSlotName(basename(path)) ? basename(path) : ""),
      }));
    } catch {
      update({ error: "Could not open the file picker. Try again or paste the private key." });
    } finally {
      inFlight.current = false;
      update({ busy: false });
    }
  };
  const publicAction = async (action: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true); setError(null);
    try { await action(); }
    catch { setError("The key action could not be completed. Refresh the workspace and retry."); }
    finally { inFlight.current = false; setBusy(false); }
  };
  const key = overview.keys.find((item) => item.id === selectedId);
  const visible = overview.keys.filter((item) => `${item.public?.name ?? item.id} ${item.public?.fingerprint ?? ""} ${item.public?.key_type ?? ""}`.toLowerCase().includes(search.toLowerCase().trim()));
  const closeDetails = () => {
    const id = selectedId;
    setSelectedId(null); setConfirming(null);
    requestAnimationFrame(() => {
      const target = collection.current?.querySelector<HTMLButtonElement>(`[data-key-id="${CSS.escape(id ?? "")}"]`);
      (target ?? document.getElementById(KEYS_SEARCH_INPUT_ID))?.focus();
    });
  };
  return (
    <div className="library-key-workspace library-detail-layout flex min-h-0 flex-1" data-inspecting={!!key}>
      {deployKeyId && <RecordsDeployKeyDialog
        overview={overview}
        keyId={deployKeyId}
        onClose={() => setDeployKeyId(null)}
      />}
      <div
        className="library-main library-key-collection flex min-h-0 min-w-0 flex-1 flex-col"
        ref={collection}
      >
        <PageHeader
          className="library-page-header"
          title="Keys"
          count={overview.keys.length}
          actions={<>
            <Button
              variant="outline"
              disabled={busy}
              onClick={(event) => { editorTrigger.current = event.currentTarget; reset(); setMode("import"); }}
            >
              <Upload className="size-3.5" />
              Import private key</Button>
            <Button
              id={GENERATE_KEY_BUTTON_ID}
              disabled={busy}
              onClick={(event) => { editorTrigger.current = event.currentTarget; reset(); setMode("generate"); }}
            >
              <Plus className="size-3.5" />
              Generate key</Button>
          </>}
        />
        <div className="library-catalog-toolbar">
          <div className="library-search">
            <Search className="size-4" />
            <Input
              id={KEYS_SEARCH_INPUT_ID}
              aria-label="Search keys"
              placeholder="Search name, fingerprint or type…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
        </div>
        <div className="library-catalog-scroll min-h-0 flex-1 overflow-y-auto">
          {error && <p role="alert" className="app-task-error mb-4">
            {error}
          </p>}
          <div className="library-key-list">
            {visible.map((item) => <button
              type="button"
              key={item.id}
              data-key-id={item.id}
              className="library-key-row"
              aria-pressed={item.id === selectedId}
              disabled={busy || draft.busy}

              onClick={() => { setSelectedId(item.id); setConfirming(null); }}
            >
              <KeyRound className="size-4" />
              <span className="library-key-identity">
                <strong>
                  {revealHidden(item.public?.name ?? item.id)}
                </strong>
                <span>
                  {item.public ? revealHidden(item.public.key_type) : "Key reference"}
                  {" · "}
                  {item.authority === "account" ? "Account key" : "Local key"}
                </span>
              </span>
              <span className="library-key-status" data-attention={item.status !== "available"}>
                {item.status === "available" ? (typeof item.synced !== "boolean" ? "Sharing unknown" : item.synced ? "Sync enabled" : "This device only") : item.status.replace(/_/g, " ")}
              </span>
            </button>)}
          </div>
          {!visible.length && <div className="app-empty-state">
            <KeyRound className="size-5" />
            <h2>
              {search ? "No matching keys" : "No key references yet."}
            </h2>
            <p>
              {search ? "Try another name, fingerprint or key type." : "Generate a key or import one into this device. New keys stay here until you choose to sync them."}
            </p>
            {search && <Button variant="outline" onClick={() => setSearch("")}>Clear search</Button>}
          </div>}
        </div>
      </div>
      <DetailPresence>{key ? <DetailPane itemId={key.id} title="Key details" label="Key details" close={closeDetails}>
        <h2>
          {revealHidden(key.public?.name ?? key.id)}
        </h2>
        <p className="library-preview-address">
          {key.authority === "account" ? "Account key" : "Local key"}
          {" · "}
          {key.status.replace(/_/g, " ")}
        </p>
        <div className="library-preview-buttons flex-wrap">
          {key.status === "available" && key.public && <Button variant="outline" disabled={busy || draft.busy} onClick={() => setDeployKeyId(key.id)}>
            <ArrowUpRight className="size-3.5" />
            Deploy public key</Button>}
          {key.public && <Button
            variant="outline"
            disabled={busy || draft.busy}
            onClick={() => publicAction(() => copyText(key.public!.public_key))}
          >
            <Copy className="size-3.5" />
            Copy public key</Button>}
          {key.status === "needs_material" && key.authority === "account" && <Button
            disabled={busy || draft.busy || overview.shared_writes_blocked}
            onClick={() => publicAction(async () => { applyRecordOverview(client, await downloadRecordKey(key.id)); })}
          >Download synced key</Button>}
        </div>
        {key.status === "conflict" && <p role="status" className="app-task-error">Local and account key metadata conflict. Connecting and downloading are blocked until the conflict is reviewed.</p>}
        {key.status === "deleted" && <p className="text-sm text-muted-foreground">This account key was deleted. A local copy cannot replace its account identity.</p>}
        <section className="library-preview-section">
          <h3>Availability and sharing</h3>
          <dl>
            <div>
              <dt>Type</dt>
              <dd>
                {key.public ? revealHidden(key.public.key_type) : "Unavailable"}
              </dd>
            </div>
            <div>
              <dt>Sharing</dt>
              <dd>
                {typeof key.synced !== "boolean" ? "Sync state unavailable" : key.synced ? "Sync enabled" : "Sync disabled"}
              </dd>
            </div>
          </dl>
          {key.status === "available" && <p className="mt-3 text-muted-foreground">Private key availability is checked when connecting.</p>}
          <p className="mt-3 text-muted-foreground">Sync changes may be waiting for the relay.</p>
          {key.status === "available" && overview.account && <Button
            className="mt-3"
            size="sm"
            variant="outline"
            disabled={busy || draft.busy || overview.shared_writes_blocked || typeof key.synced !== "boolean"}
            onClick={() => { if (typeof key.synced === "boolean") setConfirming({ id: key.id, enabled: !key.synced }); }}
          >
            {typeof key.synced !== "boolean" ? "Sync state unavailable" : key.synced ? "Stop syncing" : "Sync key"}
          </Button>}
          {confirming?.id === key.id && <div className="space-y-3 mt-4 border-t pt-3">
            <p className="text-sm">
              {confirming.enabled ? "Sync this key to your other computers? The encrypted private key will be uploaded to your account." : "Stop syncing this key? Copies already downloaded on other computers remain there."}
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                disabled={busy || draft.busy || overview.shared_writes_blocked || typeof key.synced !== "boolean" || key.status !== "available" || confirming.enabled === key.synced}
                onClick={() => publicAction(async () => {
                  if (typeof key.synced !== "boolean" || key.status !== "available" || confirming.enabled === key.synced) return;
                  applyRecordOverview(client, await setRecordKeySync(key.id, confirming.enabled)); setConfirming(null);
                })}
              >
                {confirming.enabled ? "Confirm sync" : "Confirm stop"}
              </Button>
              <Button variant="outline" disabled={busy || draft.busy} onClick={() => setConfirming(null)}>Cancel</Button>
            </div>
          </div>}
        </section>
        {key.public && <>
          <section className="library-preview-section">
            <h3>Fingerprint</h3>
            <p className="font-mono break-all">
              {revealHidden(key.public.fingerprint)}
            </p>
          </section>
          <section className="library-preview-section">
            <h3>Public key</h3>
            <p className="font-mono break-all text-muted-foreground">
              {revealHidden(key.public.public_key)}
            </p>
          </section>
        </>}
        <section className="library-preview-section">
          <h3>Used by</h3>
          {overview.hosts.filter((host) => host.effective_payload.key_id === key.id).map((host) => <p key={host.id}>
            {revealHidden(host.payload.alias)}
          </p>)}
          {!overview.hosts.some((host) => host.effective_payload.key_id === key.id) && <p className="text-muted-foreground">No hosts use this key yet.</p>}
        </section>
      </DetailPane> : null}</DetailPresence>
      <Dialog open={mode !== null} onOpenChange={(open) => { if (!open) requestClose(); }}>
        <DialogContent
          className="sm:max-w-lg"
          showCloseButton={!draft.busy}
          onEscapeKeyDown={(event) => { if (draft.busy) event.preventDefault(); }}

          onCloseAutoFocus={(event) => { event.preventDefault(); editorTrigger.current?.focus(); }}
        >
          <form onSubmit={(event) => { event.preventDefault(); void submit(); }}>
            <DialogHeader>
              <DialogTitle>
                {mode === "import" ? "Import private key" : "Generate Ed25519 key"}
              </DialogTitle>
              <DialogDescription>
                {mode === "import" ? "Copy a private key into this device’s vault. The source key stays in place." : "Create an Ed25519 key in this device’s vault. It stays here until you choose to sync it."}
              </DialogDescription>
            </DialogHeader>
            <TaskDialogBody><fieldset disabled={draft.busy} className="space-y-4">
              <RecordField label="Key name">
                <Input
                  ref={nameInput}
                  autoFocus
                  value={draft.name}
                  placeholder="work_key"
                  onChange={(event) => update({ name: event.target.value })}
                />
              </RecordField>
              {mode === "import" && <KeyImportFields draft={draft} update={update} choose={chooseFile} />}
              {draft.error && <p role="alert" className="app-task-error">
                {draft.error}
              </p>}
            </fieldset></TaskDialogBody>
            <DialogFooter>
              <Button type="button" variant="outline" disabled={draft.busy} onClick={requestClose}>Cancel</Button>
              <Button
                type="submit"
                disabled={draft.busy || !isValidSlotName(draft.name) || (mode === "import" && !hasKeyImportSource(draft))}
              >
                {draft.busy ? "Working…" : mode === "import" ? "Import key" : "Generate"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <AlertDialog open={discarding} onOpenChange={setDiscarding}>
        <AlertDialogContent
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            if (mode !== null) nameInput.current?.focus();
            else editorTrigger.current?.focus();
          }}
        >
          <AlertDialogHeader>
            <AlertDialogTitle>Discard key draft?</AlertDialogTitle>
            <AlertDialogDescription>Your unsaved key name, file selection and private key input will be cleared. The source file stays in place.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep editing</AlertDialogCancel>
            <AlertDialogAction onClick={reset}>Discard draft</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
