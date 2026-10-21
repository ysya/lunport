import { useId, useLayoutEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { open } from "@tauri-apps/plugin-dialog";
import { KeyRound, Search, Plus, Upload, ArrowUpRight, Copy, PencilLine, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { TaskDialogContent as DialogContent, TaskDialogBody } from "@/components/app/TaskDialog";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogAction, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { PageHeader } from "@/components/app/PageHeader";
import { DetailPresence } from "@/components/app/DetailPresence";
import { applyRecordOverview, recordKeyDestinationKey, renameRecordKey, deleteRecordKey, type KeySlotPayload, type RecordKeyView, type RecordOverview } from "@/lib/records";
import type { CentralStatus } from "@/lib/central-sync";
import { syncSummary } from "@/lib/central-status";
import { revealHidden } from "@/lib/sync-approvals";
import { copyText } from "@/lib/clipboard";
import { isValidSlotName } from "@/lib/key-slots";
import { clearKeyDraft, hasKeyImportSource, keyActionError, submitKeyDraft } from "./panel-actions";
import { basename } from "@/lib/utils";
import { KeyImportFields } from "./KeyImportFields";
import { RecordField } from "./form";
import { DetailPane } from "./DetailPane";
import { RecordsDeployKeyDialog } from "./DeployKeyDialog";

export const KEYS_SEARCH_INPUT_ID = "records-key-search";
export const GENERATE_KEY_BUTTON_ID = "records-generate-key";

function keyStatusLabel(key: RecordKeyView, central: boolean) {
  if (key.status !== "available") {
    if (central && key.status === "needs_material") return key.storage === "hardware" ? "Hardware key required" : key.storage === "external_agent" ? "SSH agent required" : "Private key unavailable";
    return key.status.replace(/_/g, " ");
  }
  return central ? "Ready" : "Local library";
}

export function RecordsKeysPanel({ overview, openSync, syncStatus }: { overview: RecordOverview; openSync?: () => void; syncStatus?: CentralStatus }) {
  const central = overview.central_mode === true;
  const client = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [deployKeyId, setDeployKeyId] = useState<string | null>(null);
  const [mode, setMode] = useState<"import" | "generate" | null>(null);
  const [draft, setDraft] = useState(clearKeyDraft);
  const [discarding, setDiscarding] = useState(false);
  const [renaming, setRenaming] = useState<{ id: string; expected: KeySlotPayload } | null>(null);
  const [renameName, setRenameName] = useState("");
  const [renameError, setRenameError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<{ id: string; expected: KeySlotPayload; snapshot: string; generation: string } | null>(null);
  const [forceDelete, setForceDelete] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const destination = recordKeyDestinationKey(overview);
  const lifetime = useRef({ destination, version: 0 });
  if (lifetime.current.destination !== destination) lifetime.current = { destination, version: lifetime.current.version + 1 };
  const mounted = useRef(false);
  const renderedLifetime = lifetime.current.version;
  const lease = () => () => mounted.current && lifetime.current.destination === destination && lifetime.current.version === renderedLifetime;
  const inFlight = useRef(false);
  const collection = useRef<HTMLDivElement>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const editorTrigger = useRef<HTMLButtonElement | null>(null);
  const renameTrigger = useRef<HTMLButtonElement | null>(null);
  const renameInput = useRef<HTMLInputElement>(null);
  const renameHintId = useId();
  const update = (patch: Partial<typeof draft>) => setDraft((current) => ({ ...current, ...patch }));
  const reset = () => { setDraft(clearKeyDraft()); setMode(null); setDiscarding(false); };
  useLayoutEffect(() => {
    mounted.current = true;
    inFlight.current = false;
    reset(); setSelectedId(null); setDeployKeyId(null); setRenaming(null);
    setRenameName(""); setRenameError(null); setDeleting(null); setForceDelete(false); setDeleteError(null); setBusy(false); setError(null); setSearch("");
    return () => { mounted.current = false; };
  }, [destination]);
  const requestClose = () => {
    if (draft.busy || inFlight.current) return;
    if (draft.name || draft.privateText || draft.path) setDiscarding(true);
    else reset();
  };
  const submit = async () => {
    const current = lease();
    if (!current() || inFlight.current) return;
    if (central && !overview.key_scope) { update({ error: "Refresh this account before adding a key." }); return; }
    inFlight.current = true;
    try {
      if (await submitKeyDraft(client, draft, update, mode === "generate", { invocation: overview.key_scope, destination, current }) && current()) reset();
    } finally { if (current()) inFlight.current = false; }
  };
  const chooseFile = async () => {
    const current = lease();
    if (!current() || inFlight.current || draft.busy) return;
    inFlight.current = true;
    update({ busy: true, error: null });
    try {
      const path = await open({ multiple: false, directory: false, title: "Choose an OpenSSH private key" });
      if (current() && typeof path === "string") setDraft((current) => ({
        ...current, path, source: "file",
        name: current.name || (isValidSlotName(basename(path)) ? basename(path) : ""),
      }));
    } catch {
      if (current()) update({ error: "Could not open the file picker. Try again or paste the private key." });
    } finally {
      if (current()) { inFlight.current = false; update({ busy: false }); }
    }
  };
  const publicAction = async (action: (current: () => boolean) => Promise<void>) => {
    const current = lease();
    if (!current() || inFlight.current) return;
    inFlight.current = true;
    setBusy(true); setError(null);
    try { await action(current); }
    catch (error) { if (current()) setError(keyActionError(error)); }
    finally { if (current()) { inFlight.current = false; setBusy(false); } }
  };
  const rename = async () => {
    const current = lease();
    if (!current() || inFlight.current || !renaming || !isValidSlotName(renameName.trim())) return;
    inFlight.current = true;
    setBusy(true); setRenameError(null);
    try {
      const result = await renameRecordKey(renaming.id, renaming.expected, renameName.trim(), overview.key_scope);
      if (!current() || recordKeyDestinationKey(result) !== destination) return;
      applyRecordOverview(client, result);
      setSearch("");
      setRenaming(null);
    } catch {
      if (current()) setRenameError("Could not rename this key. It may have changed on another device. Refresh the workspace and try again.");
    } finally { if (current()) { inFlight.current = false; setBusy(false); } }
  };
  const remove = async () => {
    const current = lease();
    if (!current() || inFlight.current || !deleting) return;
    inFlight.current = true;
    setBusy(true); setDeleteError(null);
    try {
      const result = await deleteRecordKey(deleting.id, deleting.expected, deleting.snapshot, forceDelete, deleting.generation, overview.key_scope);
      if (!current() || recordKeyDestinationKey(result) !== destination) return;
      applyRecordOverview(client, result);
      setDeleting(null); setSelectedId(null);
      requestAnimationFrame(() => { if (current()) document.getElementById(KEYS_SEARCH_INPUT_ID)?.focus(); });
    } catch (error) {
      if (current()) setDeleteError(keyActionError(error));
    } finally { if (current()) { inFlight.current = false; setBusy(false); } }
  };
  const activeKeys = overview.keys.filter((item) => item.status !== "deleted");
  const key = activeKeys.find((item) => item.id === selectedId);
  const deleteHosts = overview.hosts.filter((host) => host.effective_payload.key_id === deleting?.id);
  const visible = activeKeys.filter((item) => `${item.public?.name ?? item.id} ${item.public?.fingerprint ?? ""} ${item.public?.key_type ?? ""}`.toLowerCase().includes(search.toLowerCase().trim()));
  const closeDetails = () => {
    const id = selectedId;
    setSelectedId(null);
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
          count={activeKeys.length}
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
          {syncStatus?.configured && <p className="mb-4 text-sm text-muted-foreground" role="status">{syncSummary(syncStatus).text} <Button size="sm" variant="ghost" onClick={openSync}>Open sync</Button></p>}
          {!central && <section className="app-notice mb-4 space-y-3" aria-label="Automatic key sync">
            <h2 className="font-medium">Sync all keys automatically</h2>
            <p className="text-sm text-muted-foreground">Sign in with Passkey and unlock with your sync password. Hosts, Groups and all managed SSH private keys then sync automatically across your devices.</p>
            <p className="text-sm text-muted-foreground">You can keep using your keys locally without signing in.</p>
            {openSync && <Button variant="outline" disabled={busy || draft.busy} onClick={openSync}>Set up automatic sync</Button>}
          </section>}
          <div className="library-key-list">
            {visible.map((item) => <button
              type="button"
              key={item.id}
              data-key-id={item.id}
              className="library-key-row"
              aria-pressed={item.id === selectedId}
              disabled={busy || draft.busy}

              onClick={() => { setSelectedId(item.id); }}
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
              <span className="library-key-status" data-attention={item.status === "conflict" || (!central && item.status !== "available")}>
                {keyStatusLabel(item, central)}
              </span>
            </button>)}
          </div>
          {!visible.length && <div className="app-empty-state">
            <KeyRound className="size-5" />
            <h2>
              {search ? "No matching keys" : "No key references yet."}
            </h2>
            <p>
              {search ? "Try another name, fingerprint or key type." : central ? "Generate or import a key to sync it automatically with your approved devices." : "Generate a key or import one into this device. Sign in and unlock to sync all managed keys automatically."}
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
          {keyStatusLabel(key, central)}
        </p>
        <div className="library-preview-buttons flex-wrap">
          {key.public && (key.status === "available" || key.status === "needs_material") && <Button
            variant="outline"
            disabled={busy || draft.busy || (key.authority === "account" && overview.shared_writes_blocked)}
            onClick={(event) => {
              renameTrigger.current = event.currentTarget;
              setRenaming({ id: key.id, expected: key.public! });
              setRenameName(key.public!.name); setRenameError(null);
            }}
          >
            <PencilLine className="size-3.5" />
            Rename</Button>}
          {key.public && (key.status === "available" || key.status === "needs_material") && <Button
            variant="outline"
            disabled={busy || draft.busy || (key.authority === "account" && overview.shared_writes_blocked)}
            onClick={() => {
              setDeleting({ id: key.id, expected: key.public!, snapshot: overview.group_deletion_token, generation: overview.generation });
              setForceDelete(false); setDeleteError(null);
            }}
          >
            <Trash2 className="size-3.5" />
            Delete key</Button>}
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
        </div>
        {key.status === "conflict" && <p role="status" className="app-task-error">{central ? "Review this key’s identity conflict before connecting." : "Local and account key metadata conflict. Review the key identity before connecting or migrating this library."}</p>}
        {central && key.status === "needs_material" && <p role="status" className="text-sm text-muted-foreground">{key.storage === "hardware" ? "Connect this key’s hardware device to use it on this computer." : key.storage === "external_agent" ? "Connect the SSH agent that holds this key to use it on this computer." : "The matching private key is not available on this device. Check sync, or import the matching key and select it in the host’s authentication settings."}</p>}
        {key.status === "deleted" && <p className="text-sm text-muted-foreground">This account key was deleted. A local copy cannot replace its account identity.</p>}
        <section className="library-preview-section">
          {key.status === "needs_material" && key.storage !== "hardware" && key.storage !== "external_agent" && <div className="mb-3 flex flex-wrap gap-2">
            <Button variant="outline" size="sm" disabled={busy || draft.busy} onClick={openSync}>Check sync</Button>
            <Button variant="outline" size="sm" disabled={busy || draft.busy} onClick={() => setMode("import")}>Import matching key…</Button>
          </div>}
          <h3>Availability and sync</h3>
          <dl>
            <div>
              <dt>Type</dt>
              <dd>
                {key.public ? revealHidden(key.public.key_type) : "Unavailable"}
              </dd>
            </div>
            <div>
              <dt>Sync</dt>
              <dd>
                {central ? (key.storage === "hardware" || key.storage === "external_agent" ? "Key reference syncs automatically" : "Automatic encrypted sync") : "Local library"}
              </dd>
            </div>
          </dl>
          {key.status === "available" && <p className="mt-3 text-muted-foreground">Private key availability is checked when connecting.</p>}
          {central && <p className="mt-3 text-muted-foreground">All managed keys sync automatically to approved devices.</p>}
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
      <Dialog open={deleting !== null} onOpenChange={(open) => { if (!open && !inFlight.current) setDeleting(null); }}>
        <DialogContent className="sm:max-w-md" showCloseButton={!busy}
          onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }}>
          <form onSubmit={(event) => { event.preventDefault(); void remove(); }}>
            <DialogHeader>
              <DialogTitle>Delete key</DialogTitle>
              <DialogDescription>Remove “{revealHidden(deleting?.expected.name ?? "") }” from your library. With encrypted library sync enabled, this deletion also syncs to your approved devices.</DialogDescription>
            </DialogHeader>
            <TaskDialogBody className="space-y-3">
              <p className="text-sm">Hosts and Groups are kept. Those using this key will need a different key before connecting.</p>
              {deleteHosts.length > 0 && <div className="text-sm"><p>Hosts currently using this key:</p><ul>{deleteHosts.map((host) => <li key={host.id}>{revealHidden(host.payload.alias)}</li>)}</ul></div>}
              <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={forceDelete} disabled={busy} onChange={(event) => setForceDelete(event.target.checked)} />
                Force deletion even if hosts or Groups use this key, including other libraries.
              </label>
              <p className="text-xs text-muted-foreground">Imported source files, retained encrypted history and backups are kept. This does not remove the public key from your servers.</p>
              {deleteError && <p role="alert" className="app-task-error">{deleteError}</p>}
            </TaskDialogBody>
            <DialogFooter>
              <Button type="button" variant="outline" disabled={busy} onClick={() => setDeleting(null)}>Cancel</Button>
              <Button type="submit" variant="destructive" disabled={busy || (deleteHosts.length > 0 && !forceDelete)}>{busy ? "Deleting…" : forceDelete ? "Force delete key" : "Delete key"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog open={renaming !== null} onOpenChange={(open) => { if (!open && !inFlight.current) setRenaming(null); }}>
        <DialogContent
          className="sm:max-w-md"
          showCloseButton={!busy}
          onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }}
          onOpenAutoFocus={(event) => { event.preventDefault(); renameInput.current?.focus(); renameInput.current?.select(); }}
          onCloseAutoFocus={(event) => { event.preventDefault(); renameTrigger.current?.focus(); }}
        >
          <form onSubmit={(event) => { event.preventDefault(); void rename(); }}>
            <DialogHeader>
              <DialogTitle>Rename key</DialogTitle>
              <DialogDescription>Hosts keep using this key. Synced key names also update on your other devices.</DialogDescription>
            </DialogHeader>
            <TaskDialogBody>
              <RecordField label="Key name">
                <Input ref={renameInput} value={renameName} maxLength={64} disabled={busy}
                  aria-describedby={renameHintId}
                  onChange={(event) => setRenameName(event.target.value)} />
              </RecordField>
              <p id={renameHintId} className="mt-2 text-xs text-muted-foreground">Start with a letter or number. Use up to 64 letters, numbers, dots, dashes or underscores; names cannot end in .pub.</p>
              {renameError && <p role="alert" className="app-task-error mt-3">{renameError}</p>}
            </TaskDialogBody>
            <DialogFooter>
              <Button type="button" variant="outline" disabled={busy} onClick={() => setRenaming(null)}>Cancel</Button>
              <Button type="submit" disabled={busy || !isValidSlotName(renameName.trim()) || renameName.trim() === renaming?.expected.name}>
                {busy ? "Saving…" : "Save name"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
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
                {central ? (mode === "import" ? "Copy a private key into your encrypted account vault. The source key stays in place." : "Create an Ed25519 key in your encrypted account vault.") : mode === "import" ? "Copy a private key into this device’s vault. The source key stays in place." : "Create an Ed25519 key in this device’s vault. Signing in and unlocking includes all managed keys automatically."}
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
