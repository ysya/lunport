import { QueryClient } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { toast } from "sonner";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { KeyFilePreview } from "@/bindings/KeyFilePreview";
import { syncOverviewKey } from "@/lib/sync";
import { keySlot, overview, SLOT_FINGERPRINT, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { stubBackend } from "@/lib/test-ipc";
import { useUiStore } from "@/stores/ui";
import {
  GenerateKeyView,
  ImportKeyView,
  importedNote,
  submitGenerate,
  submitImport,
  type GenerateKeyState,
  type ImportKeyState,
} from "./NewKey";
import { buttonTag, buttonsIn, DISABLED, HIDDEN_CHARS, text, textIn } from "./test-markup";

const preview = (overrides: Partial<KeyFilePreview> = {}): KeyFilePreview => ({
  default_name: "id_work",
  fingerprint: "SHA256:abc",
  key_type: "ssh-ed25519",
  has_passphrase: false,
  hosts: [],
  default_identity: false,
  problem: null,
  ...overrides,
});
const importState = (overrides: Partial<ImportKeyState> = {}): ImportKeyState => ({
  source: "paste",
  text: "",
  path: null,
  preview: null,
  name: "key",
  keepFile: false,
  busy: false,
  ...overrides,
});
const noop = () => {};
const importTree = (state: ImportKeyState, on: Partial<Parameters<typeof ImportKeyView>[0]> = {}) =>
  ImportKeyView({ state, onSource: noop, onText: noop, onChoose: noop, onName: noop, onKeepFile: noop, onAdd: noop, onCancel: noop, ...on });
const importHtml = (state: ImportKeyState) => renderToStaticMarkup(importTree(state));
/** A key file chosen from ~/.ssh, previewed without a problem. */
const chosenFile = (overrides: Partial<ImportKeyState> = {}, previewed: Partial<KeyFilePreview> = {}) =>
  importState({ source: "file", path: "/home/f/.ssh/id_work", preview: preview(previewed), name: "id_work", ...overrides });

describe("New key", () => {
  it("says what it does, and adds a pasted key once there is text and a valid name", () => {
    const empty = importHtml(importState());
    expect(text(empty)).toContain("SSHelter keeps the key in its vault. Programs ask before they use it.");
    expect(buttonTag(empty, "Add to SSHelter")).toContain(DISABLED);
    expect(buttonTag(importHtml(importState({ text: "-----BEGIN OPENSSH PRIVATE KEY-----" })), "Add to SSHelter")).not.toContain(DISABLED);
    const badName = importHtml(importState({ text: "x", name: "my key" }));
    expect(text(badName)).toContain("Use letters, digits, '.', '_' or '-'; start with a letter or digit; don't end with .pub.");
    expect(buttonTag(badName, "Add to SSHelter")).toContain(DISABLED);
  });

  it("switches between Paste and From a file", () => {
    const asked: string[] = [];
    for (const b of buttonsIn(importTree(importState(), { onSource: (s) => asked.push(s) }))) {
      if (textIn(b) === "Paste" || textIn(b) === "From a file") b.props.onClick!();
    }
    expect(asked).toEqual(["paste", "file"]);
    expect(text(importHtml(importState({ source: "file" })))).toContain("No file chosen. You can also drop a key file here.");
  });

  it("asks what happens to a chosen file, and says which hosts move with it", () => {
    const file = importState({ source: "file", path: "/home/f/.ssh/id_ed25519", preview: preview({ hosts: ["web", "db"], default_identity: true }) });
    const moving = text(importHtml(file));
    for (const part of [
      "Move into SSHelter",
      "Keep the file too",
      "SSHelter keeps the only copy on this computer and removes the file. Export private key… gets a file back.",
      "web and db will use the key in SSHelter.",
      "ssh also tries ~/.ssh/id_ed25519 for hosts that don't name a key. After the move, those hosts won't find it.",
    ]) {
      expect(moving).toContain(part);
    }
    expect(text(importHtml({ ...file, keepFile: true }))).toContain("The file stays. Any program can use it without asking.");
  });

  it("shows why a file can't be added, and doesn't add it", () => {
    const html = importHtml(importState({ source: "file", path: "/tmp/x", preview: preview({ problem: "This file isn't a private key." }) }));
    expect(text(html)).toContain("This file isn't a private key.");
    expect(buttonTag(html, "Add to SSHelter")).toContain(DISABLED);
  });

  it("waits for the preview of a chosen file before it adds it", () => {
    const waiting = importHtml(importState({ source: "file", path: "/home/f/.ssh/id_work", preview: null }));
    expect(text(waiting)).toContain("/home/f/.ssh/id_work");
    expect(buttonTag(waiting, "Add to SSHelter")).toContain(DISABLED);
    expect(buttonTag(importHtml(chosenFile()), "Add to SSHelter")).not.toContain(DISABLED);
  });

  it("shows the key's type and fingerprint once a file is previewed", () => {
    expect(text(importHtml(chosenFile()))).toContain("ssh-ed25519 · SHA256:abc");
  });

  it("presses through to its handlers: Choose a file, Move or Keep, Add and Cancel", () => {
    const asked: string[] = [];
    const tree = importTree(chosenFile(), {
      onChoose: () => asked.push("choose"),
      onKeepFile: (keep) => asked.push(keep ? "keep" : "move"),
      onAdd: () => asked.push("add"),
      onCancel: () => asked.push("cancel"),
    });
    // In drawing order: the file, what happens to it, then Cancel and Add.
    const pressed = ["Choose a file…", "Move into SSHelter", "Keep the file too", "Cancel", "Add to SSHelter"];
    for (const b of buttonsIn(tree)) if (pressed.includes(textIn(b))) b.props.onClick!();
    expect(asked).toEqual(["choose", "move", "keep", "cancel", "add"]);
  });

  it("marks the chosen source and the chosen fate of the file", () => {
    const file = chosenFile();
    expect(buttonTag(importHtml(file), "From a file")).toContain('aria-pressed="true"');
    expect(buttonTag(importHtml(file), "Paste")).toContain('aria-pressed="false"');
    expect(buttonTag(importHtml(file), "Move into SSHelter")).toContain('aria-pressed="true"');
    expect(buttonTag(importHtml({ ...file, keepFile: true }), "Keep the file too")).toContain('aria-pressed="true"');
  });

  it("turns everything off while a key is being added", () => {
    const html = importHtml(chosenFile({ busy: true }));
    for (const label of ["Paste", "From a file", "Choose a file…", "Move into SSHelter", "Keep the file too", "Cancel", "Adding…"]) {
      expect(buttonTag(html, label), label).toContain(DISABLED);
    }
  });

  it("names the toast's second line after adding a file", () => {
    expect(importedNote({ removed_file: true, file_kept: null }, "/home/f/.ssh/id_work", false)).toBe("Removed /home/f/.ssh/id_work.");
    expect(importedNote({ removed_file: false, file_kept: null }, "/home/f/.ssh/id_work", true)).toBe("The file stays: any program can use it without asking.");
    expect(importedNote({ removed_file: false, file_kept: "The file stays: web are in a space that hasn't finished its first sync." }, "/x", false)).toBe(
      "The file stays: web are in a space that hasn't finished its first sync.",
    );
  });
});

describe("New key and what comes from the config or the disk", () => {
  it("reveals hidden characters in the hosts that move with a file, and in the file's name", () => {
    const html = importHtml(
      importState({
        source: "file",
        path: `/home/f/Downloads/${SPOOFED_NAME}`,
        preview: preview({ hosts: [SPOOFED_NAME, "db"], default_identity: true }),
      }),
    );
    expect(html).not.toMatch(HIDDEN_CHARS);
    const t = text(html);
    expect(t).toContain(`${SPOOFED_NAME_SHOWN} and db will use the key in SSHelter.`);
    expect(t).toContain(`ssh also tries ~/.ssh/${SPOOFED_NAME_SHOWN} for hosts that don't name a key.`);
    // The path itself, the host and the default file.
    expect(t.split(SPOOFED_NAME_SHOWN).length - 1).toBe(3);
  });

  it("shows a wildcard or a negated pattern as it is: either can be the first pattern of a block", () => {
    const t = text(importHtml(chosenFile({}, { hosts: ["*", "!staging", "web"] })));
    expect(t).toContain("*, !staging and web will use the key in SSHelter.");
  });

  it("reveals hidden characters in why a file can't be added: it can name a key already in SSHelter", () => {
    const html = importHtml(chosenFile({}, { problem: `This key is already in SSHelter as ${SPOOFED_NAME}.` }));
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(text(html)).toContain(`This key is already in SSHelter as ${SPOOFED_NAME_SHOWN}.`);
  });

  it("reveals hidden characters in the key's type", () => {
    const html = importHtml(chosenFile({}, { key_type: SPOOFED_NAME }));
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(text(html)).toContain(`${SPOOFED_NAME_SHOWN} · SHA256:abc`);
  });

  it("reveals hidden characters in the toast's second line: the reason a move kept the file names hosts from the config", () => {
    const kept = (hosts: string) => `The file stays: ${hosts} are in a space that hasn't finished its first sync.`;
    const note = importedNote({ removed_file: false, file_kept: kept(`${SPOOFED_NAME} and db`) }, "/x", false);
    expect(note).toBe(kept(`${SPOOFED_NAME_SHOWN} and db`));
    expect(note).not.toMatch(HIDDEN_CHARS);
    expect(importedNote({ removed_file: true, file_kept: null }, `/home/f/${SPOOFED_NAME}`, false)).toBe(`Removed /home/f/${SPOOFED_NAME_SHOWN}.`);
  });
});

const generateState = (overrides: Partial<GenerateKeyState> = {}): GenerateKeyState => ({
  algorithm: "ed25519",
  name: "id_ed25519",
  passphrase: "",
  repeat: "",
  busy: false,
  ...overrides,
});
const generateTree = (state: GenerateKeyState, on: Partial<Parameters<typeof GenerateKeyView>[0]> = {}) =>
  GenerateKeyView({ state, onAlgorithm: noop, onName: noop, onPassphrase: noop, onRepeat: noop, onGenerate: noop, onCancel: noop, ...on });
const generateHtml = (state: GenerateKeyState) => renderToStaticMarkup(generateTree(state));

describe("Generate key", () => {
  it("offers the four kinds, and warns that RSA takes a few seconds", () => {
    const asked: string[] = [];
    for (const b of buttonsIn(generateTree(generateState(), { onAlgorithm: (a) => asked.push(a) }))) {
      if (["Ed25519", "RSA 3072", "RSA 4096", "ECDSA P-256"].includes(textIn(b))) b.props.onClick!();
    }
    expect(asked).toEqual(["ed25519", "rsa3072", "rsa4096", "ecdsa_p256"]);
    expect(text(generateHtml(generateState()))).not.toContain("An RSA key takes a few seconds to make.");
    expect(text(generateHtml(generateState({ algorithm: "rsa4096" })))).toContain("An RSA key takes a few seconds to make.");
  });

  it("marks the chosen kind", () => {
    expect(buttonTag(generateHtml(generateState({ algorithm: "rsa3072" })), "RSA 3072")).toContain('aria-pressed="true"');
    expect(buttonTag(generateHtml(generateState({ algorithm: "rsa3072" })), "Ed25519")).toContain('aria-pressed="false"');
  });

  it("says what it makes, and asks only for a name and a passphrase: the key's name is also its comment", () => {
    const t = text(generateHtml(generateState()));
    expect(t).toContain("A new key made in SSHelter. It exists only in SSHelter until you export it.");
    expect(t).toContain("Name");
    expect(t).toContain("Passphrase (optional)");
    expect(t).not.toContain("Comment");
  });

  it("asks for a passphrase twice, and generates only when both match", () => {
    expect(text(generateHtml(generateState()))).not.toContain("Repeat the passphrase");
    const typed = generateState({ passphrase: "pw" });
    expect(text(generateHtml(typed))).toContain("Repeat the passphrase");
    expect(buttonTag(generateHtml(typed), "Generate")).toContain(DISABLED);
    expect(buttonTag(generateHtml({ ...typed, repeat: "pw" }), "Generate")).not.toContain(DISABLED);
    expect(buttonTag(generateHtml(generateState({ busy: true })), "Generating…")).toContain(DISABLED);
  });

  it("generates only with a valid name", () => {
    expect(buttonTag(generateHtml(generateState()), "Generate")).not.toContain(DISABLED);
    const bad = generateHtml(generateState({ name: "my key" }));
    expect(text(bad)).toContain("Use letters, digits, '.', '_' or '-'; start with a letter or digit; don't end with .pub.");
    expect(buttonTag(bad, "Generate")).toContain(DISABLED);
  });

  it("presses through to Generate and Cancel, and turns everything off while it works", () => {
    const asked: string[] = [];
    const tree = generateTree(generateState(), { onGenerate: () => asked.push("generate"), onCancel: () => asked.push("cancel") });
    for (const b of buttonsIn(tree)) if (["Generate", "Cancel"].includes(textIn(b))) b.props.onClick!();
    expect(asked).toEqual(["cancel", "generate"]);
    const busy = generateHtml(generateState({ busy: true }));
    for (const label of ["Ed25519", "RSA 3072", "RSA 4096", "ECDSA P-256", "Cancel", "Generating…"]) expect(buttonTag(busy, label), label).toContain(DISABLED);
  });
});

describe("adding and generating a key", () => {
  const KEY_TEXT = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n";
  const added = (extra: Record<string, unknown> = {}) => ({
    overview: overview({ last_sync_ms: 1 }),
    slot_id: "s",
    rewritten_hosts: [],
    removed_file: false,
    file_kept: null,
    ...extra,
  });
  /** What the toasts on screen say (`getToasts` also lists the ones being dismissed, which say nothing). */
  const toasts = () => toast.getToasts().flatMap((t) => ("title" in t ? [{ title: t.title, description: t.description }] : []));

  beforeEach(() => {
    // sonner's `toast.dismiss` schedules through requestAnimationFrame, which Node lacks.
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });
  });
  afterEach(() => {
    for (const t of toast.getToasts()) toast.dismiss(t.id);
    vi.unstubAllGlobals();
    useUiStore.setState({ keySetup: null });
  });

  it("adds a pasted key with a plain call, puts the new overview in place, and hands back the new key", async () => {
    const calls = stubBackend(async () => added());
    const queryClient = new QueryClient();
    expect(await submitImport(queryClient, importState({ text: KEY_TEXT, name: "laptop" }))).toBe("s");
    expect(calls).toEqual([["sync_key_import_text", { name: "laptop", text: KEY_TEXT }]]);
    expect(toasts()).toEqual([{ title: "laptop is in SSHelter", description: undefined }]);
    expect(queryClient.getQueryData(syncOverviewKey)).toEqual(added().overview);
    expect(useUiStore.getState().keySetup).toBeNull();
    // TanStack's caches keep what a query or a mutation was given and answered: the key text must be in neither.
    const cached = [...queryClient.getQueryCache().getAll().map((q) => q.state.data), ...queryClient.getMutationCache().getAll().map((m) => m.state.variables)];
    expect(JSON.stringify(cached)).not.toContain("b3BlbnNzaC1rZXk=");
  });

  it("moves a file, says it was removed, and asks the Sync key dialog about the hosts that now use the key", async () => {
    const calls = stubBackend(async () => added({ rewritten_hosts: ["web", "db"], removed_file: true }));
    expect(await submitImport(new QueryClient(), chosenFile({ name: "work" }))).toBe("s");
    expect(calls).toEqual([["sync_key_import_file", { name: "work", path: "/home/f/.ssh/id_work", keepFile: false }]]);
    expect(toasts()).toEqual([{ title: "work is in SSHelter", description: "Removed /home/f/.ssh/id_work." }]);
    expect(useUiStore.getState().keySetup).toEqual({ aliases: ["web", "db"], reason: "saved" });
  });

  it("keeps the file when asked to, says any program can still use it, and changes no host", async () => {
    const calls = stubBackend(async () => added());
    expect(await submitImport(new QueryClient(), chosenFile({ name: "work", keepFile: true }))).toBe("s");
    expect(calls).toEqual([["sync_key_import_file", { name: "work", path: "/home/f/.ssh/id_work", keepFile: true }]]);
    expect(toasts()).toEqual([{ title: "work is in SSHelter", description: "The file stays: any program can use it without asking." }]);
    expect(useUiStore.getState().keySetup).toBeNull();
  });

  it("adds the key and says why the file stays when a move couldn't remove it, with hidden characters revealed", async () => {
    const reason = (hosts: string) => `The file stays: ${hosts} are in a space that hasn't finished its first sync.`;
    stubBackend(async () => added({ file_kept: reason(`${SPOOFED_NAME} and db`) }));
    expect(await submitImport(new QueryClient(), chosenFile({ name: "work" }))).toBe("s");
    expect(toasts()).toEqual([{ title: "work is in SSHelter", description: reason(`${SPOOFED_NAME_SHOWN} and db`) }]);
  });

  it("still asks about the hosts a move did switch before it stopped", async () => {
    stubBackend(async () => added({ rewritten_hosts: ["web"], file_kept: "The file stays: db couldn't be switched (disk full)." }));
    await submitImport(new QueryClient(), chosenFile({ name: "work" }));
    expect(useUiStore.getState().keySetup).toEqual({ aliases: ["web"], reason: "saved" });
  });

  it("says why a key couldn't be added, with hidden characters revealed, and changes nothing", async () => {
    stubBackend(async () => {
      throw `This key is already in SSHelter as ${SPOOFED_NAME}.`;
    });
    const queryClient = new QueryClient();
    expect(await submitImport(queryClient, importState({ text: KEY_TEXT, name: "laptop" }))).toBeNull();
    expect(toasts()).toEqual([{ title: "Could not add the key", description: `This key is already in SSHelter as ${SPOOFED_NAME_SHOWN}.` }]);
    expect(queryClient.getQueryData(syncOverviewKey)).toBeUndefined();
    expect(useUiStore.getState().keySetup).toBeNull();
  });

  it("shows the backend's message when a move is refused because the config changed on disk", async () => {
    const refusal = "Your SSH config changed on disk since SSHelter loaded it. Reload it, then try again.";
    stubBackend(async () => {
      throw new Error(refusal);
    });
    expect(await submitImport(new QueryClient(), chosenFile({ name: "work" }))).toBeNull();
    expect(toasts()).toEqual([{ title: "Could not add the key", description: refusal }]);
  });

  it("asks for nothing when a file form has no file", async () => {
    const calls = stubBackend(async () => added());
    expect(await submitImport(new QueryClient(), importState({ source: "file", path: null }))).toBeNull();
    expect(calls).toEqual([]);
    expect(toasts()).toEqual([]);
  });

  it("generates a key with its name as the comment, and shows its fingerprint", async () => {
    const slot = keySlot({
      id: "s",
      name: "id_work",
      mode: "own",
      fingerprint: null,
      local_only: true,
      in_account: false,
      in_vault: true,
      status: { kind: "ready", file: "", synced_copy: false, fingerprint: SLOT_FINGERPRINT },
    });
    const calls = stubBackend(async () => ({ overview: overview({ key_slots: [slot] }), slot_id: "s" }));
    const queryClient = new QueryClient();
    expect(await submitGenerate(queryClient, generateState({ algorithm: "rsa4096", name: "id_work" }))).toBe("s");
    expect(calls).toEqual([["sync_key_generate", { name: "id_work", algorithm: "rsa4096", comment: "id_work", passphrase: null }]]);
    expect(toasts()).toEqual([{ title: "Generated id_work", description: SLOT_FINGERPRINT }]);
    expect(queryClient.getQueryData(syncOverviewKey)).toEqual(overview({ key_slots: [slot] }));
  });

  it("sends the passphrase when there is one, and never shows it", async () => {
    const calls = stubBackend(async () => ({ overview: overview(), slot_id: "s" }));
    await submitGenerate(new QueryClient(), generateState({ passphrase: "correct horse", repeat: "correct horse" }));
    expect(calls).toEqual([["sync_key_generate", { name: "id_ed25519", algorithm: "ed25519", comment: "id_ed25519", passphrase: "correct horse" }]]);
    expect(JSON.stringify(toasts())).not.toContain("correct horse");
  });

  it("says why a key couldn't be generated", async () => {
    stubBackend(async () => {
      throw "no room for the key";
    });
    expect(await submitGenerate(new QueryClient(), generateState())).toBeNull();
    expect(toasts()).toEqual([{ title: "Could not generate the key", description: "no room for the key" }]);
  });
});
