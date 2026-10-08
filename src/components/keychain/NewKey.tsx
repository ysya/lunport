import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { toast } from "sonner";

import type { KeyAlgorithm } from "@/bindings/KeyAlgorithm";
import type { KeyFilePreview } from "@/bindings/KeyFilePreview";
import { MoveKeyConfirm } from "@/components/keychain/dialogs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { listNames } from "@/lib/format";
import { isValidSlotName } from "@/lib/key-slots";
import { KEY_TYPES, slotFingerprint, type KeychainSelection } from "@/lib/keychain";
import { applyNewKey, errorMessage, generateKey, importKeyFile, importKeyText, previewKeyFile } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { useFileDrop } from "@/lib/use-file-drop";
import { basename } from "@/lib/utils";
import { useUiStore } from "@/stores/ui";

const NAME_RULE = "Use letters, digits, '.', '_' or '-'; start with a letter or digit; don't end with .pub.";

/** What Generate key starts with: the first kind and the name it suggests. */
const DEFAULT_KIND = KEY_TYPES[0];

/** Pressed buttons for one choice (the app has no radio group; Export to host does the same). A plain function, so a test sees the buttons. */
function choices<T extends string>(label: string, options: [T, string][], value: T, onChange: (value: T) => void, busy: boolean) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {options.map(([option, caption]) => (
        <Button
          key={option}
          type="button"
          size="sm"
          variant={option === value ? "secondary" : "ghost"}
          className="h-7"
          aria-pressed={option === value}
          disabled={busy}
          onClick={() => onChange(option)}
        >
          {caption}
        </Button>
      ))}
    </div>
  );
}

function nameField(name: string, busy: boolean, onName: (name: string) => void) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor="new-key-name">Name</Label>
      <Input id="new-key-name" aria-label="Key name" className="font-mono" value={name} disabled={busy} onChange={(e) => onName(e.target.value)} />
      {name !== "" && !isValidSlotName(name) && <p className="text-xs text-destructive">{NAME_RULE}</p>}
    </div>
  );
}

export interface ImportKeyState {
  source: "paste" | "file";
  text: string;
  path: string | null;
  preview: KeyFilePreview | null;
  name: string;
  keepFile: boolean;
  busy: boolean;
  /** The Move confirm is open (see `needsMoveConfirm`). The form stays as it is under it. */
  asking: boolean;
}

/**
 * New key (spec §7.5): paste a private key or choose (or drop) a file; for a file, Move into SSHelter or Keep the file too. No hooks:
 * exported for the tests. What comes from the config or the disk (host names, the reason a file can't be added, the file's name) is
 * shown through `revealHidden`.
 */
export function ImportKeyView({
  state,
  onSource,
  onText,
  onChoose,
  onName,
  onKeepFile,
  onAdd,
  onCancel,
}: {
  state: ImportKeyState;
  onSource: (source: "paste" | "file") => void;
  onText: (text: string) => void;
  onChoose: () => void;
  onName: (name: string) => void;
  onKeepFile: (keep: boolean) => void;
  onAdd: () => void;
  onCancel: () => void;
}) {
  const preview = state.source === "file" ? state.preview : null;
  const ready = state.source === "paste" ? state.text.trim() !== "" : state.path !== null && preview !== null && preview.problem === null;
  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h2 className="text-lg font-semibold">New key</h2>
        <p className="text-sm text-muted-foreground">SSHelter keeps the key in its vault. Programs ask before they use it.</p>
      </header>
      {choices<"paste" | "file">("Where the key comes from", [["paste", "Paste"], ["file", "From a file"]], state.source, onSource, state.busy)}
      {state.source === "paste" ? (
        <Textarea
          aria-label="Private key"
          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          spellCheck={false}
          autoComplete="off"
          className="h-40 font-mono text-xs"
          value={state.text}
          disabled={state.busy}
          onChange={(e) => onText(e.target.value)}
        />
      ) : (
        <div className="space-y-1.5">
          <div className="flex min-w-0 items-center gap-2">
            <Button type="button" size="sm" variant="outline" className="h-7 shrink-0" disabled={state.busy} onClick={onChoose}>
              Choose a file…
            </Button>
            <span className="min-w-0 truncate font-mono text-xs text-muted-foreground">
              {state.path !== null ? revealHidden(state.path) : "No file chosen. You can also drop a key file here."}
            </span>
          </div>
          {preview?.problem && <p className="text-xs text-destructive">{revealHidden(preview.problem)}</p>}
          {preview && !preview.problem && preview.fingerprint && (
            <p className="font-mono text-xs text-muted-foreground">{`${revealHidden(preview.key_type ?? "")} · ${preview.fingerprint}`}</p>
          )}
        </div>
      )}
      {nameField(state.name, state.busy, onName)}
      {preview && preview.problem === null && state.path && (
        <div className="space-y-2">
          {choices<"move" | "keep">(
            "What happens to the file",
            [["move", "Move into SSHelter"], ["keep", "Keep the file too"]],
            state.keepFile ? "keep" : "move",
            (choice) => onKeepFile(choice === "keep"),
            state.busy,
          )}
          {state.keepFile ? (
            <p className="text-xs text-muted-foreground">The file stays. Any program can use it without asking.</p>
          ) : (
            <div className="space-y-1 text-xs text-muted-foreground">
              <p>SSHelter keeps the only copy on this computer and removes the file. Export private key… gets a file back.</p>
              {preview.hosts.length > 0 && <p>{`${listNames(preview.hosts.map((host) => revealHidden(host)))} will use the key in SSHelter.`}</p>}
              {preview.default_identity && (
                <p>{`ssh also tries ~/.ssh/${revealHidden(basename(state.path))} for hosts that don't name a key. After the move, those hosts won't find it.`}</p>
              )}
            </div>
          )}
        </div>
      )}
      <div className="flex gap-1.5">
        <Button type="button" size="sm" variant="outline" className="h-7" disabled={state.busy} onClick={onCancel}>
          Cancel
        </Button>
        <Button type="button" size="sm" className="h-7" disabled={state.busy || !isValidSlotName(state.name) || !ready} onClick={onAdd}>
          {state.busy ? "Adding…" : "Add to SSHelter"}
        </Button>
      </div>
    </div>
  );
}

export interface GenerateKeyState {
  algorithm: KeyAlgorithm;
  name: string;
  passphrase: string;
  repeat: string;
  busy: boolean;
}

/** Generate key (spec §7.5): the kind, a name and an optional passphrase typed twice. No hooks: exported for the tests. */
export function GenerateKeyView({
  state,
  onAlgorithm,
  onName,
  onPassphrase,
  onRepeat,
  onGenerate,
  onCancel,
}: {
  state: GenerateKeyState;
  onAlgorithm: (algorithm: KeyAlgorithm) => void;
  onName: (name: string) => void;
  onPassphrase: (passphrase: string) => void;
  onRepeat: (repeat: string) => void;
  onGenerate: () => void;
  onCancel: () => void;
}) {
  const passphraseOk = state.passphrase === "" || state.passphrase === state.repeat;
  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h2 className="text-lg font-semibold">Generate key</h2>
        <p className="text-sm text-muted-foreground">A new key made in SSHelter. It exists only in SSHelter until you export it.</p>
      </header>
      {choices<KeyAlgorithm>("Key type", KEY_TYPES.map((t): [KeyAlgorithm, string] => [t.algorithm, t.label]), state.algorithm, onAlgorithm, state.busy)}
      {state.algorithm.startsWith("rsa") && <p className="text-xs text-muted-foreground">An RSA key takes a few seconds to make.</p>}
      {nameField(state.name, state.busy, onName)}
      <div className="space-y-1.5">
        <Label htmlFor="new-key-passphrase">Passphrase (optional)</Label>
        <Input id="new-key-passphrase" type="password" autoComplete="new-password" value={state.passphrase} disabled={state.busy} onChange={(e) => onPassphrase(e.target.value)} />
      </div>
      {state.passphrase !== "" && (
        <div className="space-y-1.5">
          <Label htmlFor="new-key-passphrase-repeat">Repeat the passphrase</Label>
          <Input id="new-key-passphrase-repeat" type="password" autoComplete="new-password" value={state.repeat} disabled={state.busy} onChange={(e) => onRepeat(e.target.value)} />
        </div>
      )}
      <div className="flex gap-1.5">
        <Button type="button" size="sm" variant="outline" className="h-7" disabled={state.busy} onClick={onCancel}>
          Cancel
        </Button>
        <Button type="button" size="sm" className="h-7" disabled={state.busy || !isValidSlotName(state.name) || !passphraseOk} onClick={onGenerate}>
          {state.busy ? "Generating…" : "Generate"}
        </Button>
      </div>
    </div>
  );
}

/**
 * The toast's second line after adding a key file (spec §7.5). The reason a move kept the file names hosts from the config, and the
 * path comes from the disk: both are shown through `revealHidden`. Exported for the tests.
 */
export function importedNote(result: { removed_file: boolean; file_kept: string | null }, path: string, keepFile: boolean): string {
  if (result.file_kept) return revealHidden(result.file_kept);
  if (result.removed_file) return `Removed ${revealHidden(path)}.`;
  return keepFile ? "The file stays: any program can use it without asking." : "";
}

/**
 * Add the pasted key or the chosen file (New key's "Add to SSHelter"), and tell the user how it went. Resolves to the new key's slot
 * id, or null after a toast said why nothing was added. Plain calls, not mutations: the key text must not stay in TanStack's cache.
 * Exported for the tests.
 */
export async function submitImport(queryClient: QueryClient, state: ImportKeyState): Promise<string | null> {
  try {
    if (state.source === "paste") {
      const result = await importKeyText(state.name, state.text);
      applyNewKey(queryClient, result.overview);
      toast.success(`${state.name} is in SSHelter`);
      return result.slot_id;
    }
    if (state.path === null) return null;
    const result = await importKeyFile(state.name, state.path, state.keepFile);
    applyNewKey(queryClient, result.overview);
    const note = importedNote(result, state.path, state.keepFile);
    toast.success(`${state.name} is in SSHelter`, note ? { description: note } : undefined);
    // Hosts now pointing at a key only on this computer: the Sync key dialog asks about the synced ones (spec §4.3). A move that
    // stopped halfway lists the hosts it did switch.
    if (result.rewritten_hosts.length > 0) useUiStore.getState().setKeySetup({ aliases: result.rewritten_hosts, reason: "saved" });
    return result.slot_id;
  } catch (error) {
    // The message can name a key or a host from elsewhere ("This key is already in SSHelter as {name}.").
    toast.error("Could not add the key", { description: revealHidden(errorMessage(error)) });
    return null;
  }
}

/**
 * Make the key (Generate key's "Generate"), and tell the user how it went. Resolves to the new key's slot id, or null after a toast said
 * why nothing was made. The key's name is also its comment: the form has no Comment field, because the comment lives only inside the
 * private key (the .pub, Copy public key, Export to host and the agent's identity list never show it). Plain calls, as `submitImport`.
 * Exported for the tests.
 */
export async function submitGenerate(queryClient: QueryClient, state: GenerateKeyState): Promise<string | null> {
  try {
    const result = await generateKey(state.name, state.algorithm, state.name, state.passphrase === "" ? null : state.passphrase);
    applyNewKey(queryClient, result.overview);
    const slot = result.overview.key_slots.find((s) => s.id === result.slot_id);
    const fingerprint = slot ? slotFingerprint(slot) : null;
    toast.success(`Generated ${state.name}`, fingerprint ? { description: fingerprint } : undefined);
    return result.slot_id;
  } catch (error) {
    toast.error("Could not generate the key", { description: revealHidden(errorMessage(error)) });
    return null;
  }
}

/**
 * Whether "Add to SSHelter" has to ask first (spec §7.5): a chosen file that would be moved is removed, so the user confirms it. Keep
 * the file too and a pasted key remove no file and are added at once. Exported for the tests.
 */
export function needsMoveConfirm(state: ImportKeyState): boolean {
  return state.source === "file" && state.path !== null && !state.keepFile;
}

/**
 * What the New key form's buttons do, apart from React (spec §7.5). `state` is the form as last drawn, `update` merges into it, and
 * `show` is told the slot id of the key once it was added. "Add to SSHelter" opens the Move confirm for a Move and adds anything else at
 * once; nothing is sent until the user confirms, and Cancel leaves the form exactly as it was. Exported for the tests.
 */
export function importActions({
  state,
  update,
  queryClient,
  show,
}: {
  state: ImportKeyState;
  update: (patch: Partial<ImportKeyState>) => void;
  queryClient: QueryClient;
  show: (slotId: string) => void;
}) {
  const send = async () => {
    update({ busy: true });
    const slotId = await submitImport(queryClient, state);
    if (slotId === null) update({ busy: false });
    else show(slotId);
  };
  return {
    add: () => (needsMoveConfirm(state) ? update({ asking: true }) : send()),
    confirm: () => {
      update({ asking: false });
      // The dialog stays on screen while it fades out: pressing its button again must not send the key a second time.
      return state.busy ? undefined : send();
    },
    cancel: () => update({ asking: false }),
  };
}

/** The Keychain's main pane for New key or Generate key. Keyed by the caller per selection, so typed text and passphrases go with it. */
export function NewKeyPane({ selection }: { selection: Extract<KeychainSelection, { kind: "new" }> }) {
  return selection.mode === "generate" ? <GenerateKeyPane /> : <ImportKeyPane initialPath={selection.path} />;
}

function ImportKeyPane({ initialPath }: { initialPath: string | null }) {
  const queryClient = useQueryClient();
  const selectKey = useUiStore((s) => s.selectKey);
  const [state, setState] = useState<ImportKeyState>({
    source: initialPath ? "file" : "paste",
    text: "",
    path: initialPath,
    preview: null,
    name: "key",
    keepFile: false,
    busy: false,
    asking: false,
  });
  const nameEdited = useRef(false);
  const update = (patch: Partial<ImportKeyState>) => setState((s) => ({ ...s, ...patch }));
  // A chosen (or dropped) file: read what adding it would do. An answer for a file that is no longer the chosen one is dropped.
  const choose = useCallback((path: string) => {
    setState((s) => ({ ...s, source: "file", path, preview: null }));
    previewKeyFile(path).then(
      (preview) => setState((s) => (s.path === path ? { ...s, preview, name: nameEdited.current ? s.name : preview.default_name } : s)),
      (error: unknown) =>
        setState((s) =>
          s.path === path
            ? { ...s, preview: { default_name: s.name, fingerprint: null, key_type: null, has_passphrase: null, hosts: [], default_identity: false, problem: errorMessage(error) } }
            : s,
        ),
    );
  }, []);
  useEffect(() => {
    if (initialPath) choose(initialPath);
  }, [initialPath, choose]);
  // Not while a key is being added or the Move confirm is open: a file dropped then must not change what the user is confirming.
  useFileDrop(!state.busy && !state.asking, choose);
  const pick = async () => {
    const picked = await openFileDialog({ multiple: false, directory: false, title: "Choose a private key" });
    if (typeof picked === "string") choose(picked);
  };
  const actions = importActions({ state, update, queryClient, show: (slotId) => selectKey({ kind: "slot", id: slotId }) });
  return (
    <>
      <ImportKeyView
        state={state}
        onSource={(source) => update({ source })}
        onText={(text) => update({ text })}
        onChoose={() => void pick()}
        onName={(name) => {
          nameEdited.current = true;
          update({ name });
        }}
        onKeepFile={(keepFile) => update({ keepFile })}
        onAdd={() => void actions.add()}
        onCancel={() => selectKey(null)}
      />
      <MoveKeyConfirm path={state.path} open={state.asking} onCancel={actions.cancel} onConfirm={() => void actions.confirm()} />
    </>
  );
}

function GenerateKeyPane() {
  const queryClient = useQueryClient();
  const selectKey = useUiStore((s) => s.selectKey);
  const [state, setState] = useState<GenerateKeyState>({ algorithm: DEFAULT_KIND.algorithm, name: DEFAULT_KIND.name, passphrase: "", repeat: "", busy: false });
  const nameEdited = useRef(false);
  const update = (patch: Partial<GenerateKeyState>) => setState((s) => ({ ...s, ...patch }));
  const run = async () => {
    update({ busy: true });
    const slotId = await submitGenerate(queryClient, state);
    if (slotId === null) update({ busy: false });
    else selectKey({ kind: "slot", id: slotId });
  };
  return (
    <GenerateKeyView
      state={state}
      onAlgorithm={(algorithm) =>
        update(nameEdited.current ? { algorithm } : { algorithm, name: KEY_TYPES.find((t) => t.algorithm === algorithm)?.name ?? state.name })
      }
      onName={(name) => {
        nameEdited.current = true;
        update({ name });
      }}
      // The repeat goes with an empty passphrase (as in Export private key).
      onPassphrase={(passphrase) => update(passphrase === "" ? { passphrase, repeat: "" } : { passphrase })}
      onRepeat={(repeat) => update({ repeat })}
      onGenerate={() => void run()}
      onCancel={() => selectKey(null)}
    />
  );
}
