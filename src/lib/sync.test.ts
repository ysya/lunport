import { readFileSync } from "node:fs";
import { QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";

import { queryKeys } from "./queries";
import {
  RELAY_DEPLOY_URL,
  RELAY_UPDATE_URL,
  applyNewKey,
  applyResolved,
  approveVersions,
  createAccount,
  exportPrivateKey,
  fetchKeyCandidates,
  generateKey,
  importKeyFile,
  importKeyText,
  joinAccount,
  keyArgs,
  keyCandidatesKey,
  leaveFailureTitle,
  openRelayDeploy,
  openRelayUpdateGuide,
  previewKeyFile,
  rejectVersions,
  rejoinAccount,
  showWords,
  syncApprovalsKey,
  syncDuplicatesKey,
  syncOverviewKey,
  syncUnmovableKey,
  useKeyDeleteCopy,
  useKeyMoveAllIntoVault,
  useKeyPick,
  useKeySetDelivery,
  useKeySetMode,
  useKeyUseSynced,
  useSetupKeys,
} from "./sync";
import { overview, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "./sync-fixtures";
import { renderHook, stubBackend } from "./test-ipc";

beforeEach(() => {
  // sonner's `toast.dismiss` schedules through requestAnimationFrame, which Node lacks.
  vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
    cb(0);
    return 0;
  });
});

afterEach(() => {
  // Dismissing by id drops a toast from `getToasts()` at once; a bare `dismiss()` does not.
  for (const t of toast.getToasts()) toast.dismiss(t.id);
  vi.unstubAllGlobals();
});

describe("the relay deploy link", () => {
  it("starts Cloudflare's deploy flow for this repository's relay folder", () => {
    const target = new URL(RELAY_DEPLOY_URL);
    expect(target.origin).toBe("https://deploy.workers.cloudflare.com");
    expect(target.searchParams.get("url")).toBe("https://github.com/ysya/sshelter/tree/main/relay");
  });

  it("is the same link as the README buttons", () => {
    for (const readme of ["README.md", "relay/README.md"]) {
      expect(readFileSync(readme, "utf8"), readme).toContain(`(${RELAY_DEPLOY_URL})`);
    }
  });

  it("opens it in the default browser", async () => {
    const calls = stubBackend(async () => undefined);
    await openRelayDeploy();
    expect(calls).toEqual([["plugin:opener|open_url", { url: RELAY_DEPLOY_URL, with: undefined }]]);
    expect(toast.getToasts()).toEqual([]);
  });

  it("says so when the browser cannot be opened", async () => {
    stubBackend(async () => {
      throw "opener refused";
    });
    await openRelayDeploy();
    expect(toast.getToasts()).toEqual([
      expect.objectContaining({ title: "Could not open your browser", description: "opener refused" }),
    ]);
  });
});

describe("the relay update guide link", () => {
  it("points at the relay README's \"Updating your relay\" section", () => {
    expect(RELAY_UPDATE_URL).toBe("https://github.com/ysya/sshelter/blob/main/relay/README.md#updating-your-relay");
    // GitHub derives the anchor from the heading: keep the heading where the link expects it.
    expect(readFileSync("relay/README.md", "utf8")).toMatch(/^## Updating your relay$/m);
    expect(readFileSync("README.md", "utf8")).toContain("relay/README.md#updating-your-relay");
  });

  it("opens it in the default browser", async () => {
    const calls = stubBackend(async () => undefined);
    await openRelayUpdateGuide();
    expect(calls).toEqual([["plugin:opener|open_url", { url: RELAY_UPDATE_URL, with: undefined }]]);
  });
});

describe("sync-code commands", () => {
  const WORDS = "abandon ".repeat(23) + "art";
  const OVERVIEW = { joined: true };

  it("send the words and device name as the backend's camelCase arguments", async () => {
    const calls = stubBackend(async (cmd) => (cmd === "sync_create_account" || cmd === "sync_show_words" ? WORDS : OVERVIEW));
    expect(await createAccount("MacBook-A")).toBe(WORDS);
    expect(await joinAccount(WORDS, "MacBook-B")).toEqual(OVERVIEW);
    expect(await rejoinAccount(WORDS)).toEqual(OVERVIEW);
    expect(await showWords()).toBe(WORDS);
    expect(calls).toEqual([
      ["sync_create_account", { deviceName: "MacBook-A" }],
      ["sync_join_account", { words: WORDS, deviceName: "MacBook-B" }],
      ["sync_rejoin_account", { words: WORDS }],
      ["sync_show_words", {}],
    ]);
  });

  it("pass backend errors through untouched and never toast (a toast could carry the words)", async () => {
    stubBackend(async () => {
      throw "no sync account matches this sync code";
    });
    await expect(joinAccount(WORDS, "MacBook-B")).rejects.toBe("no sync account matches this sync code");
    await expect(rejoinAccount(WORDS)).rejects.toBe("no sync account matches this sync code");
    expect(toast.getToasts()).toEqual([]);
  });
});

describe("review commands", () => {
  const SPACE = "a".repeat(64);

  it("send exactly the reviewed versions as { spaceId, approvals: [{ alias, digest }] } and return the outcome", async () => {
    const outcome = { applied: 1, changed: ["db"], overview: { joined: true } };
    const calls = stubBackend(async () => outcome);
    const shown = [
      { alias: "web", digest: "d1" },
      { alias: "db", digest: "d2" },
    ];
    expect(await approveVersions(SPACE, shown)).toEqual(outcome);
    expect(await rejectVersions(SPACE, [{ alias: "web", digest: "d1" }])).toEqual(outcome);
    expect(calls).toEqual([
      ["sync_approve", { spaceId: SPACE, approvals: shown }],
      ["sync_reject", { spaceId: SPACE, approvals: [{ alias: "web", digest: "d1" }] }],
    ]);
  });
});

describe("key slot commands", () => {
  it("call the backend with its camelCase arguments", async () => {
    const calls = stubBackend(async () => ({ keys: [], unsupported: [] }));
    expect(await fetchKeyCandidates()).toEqual({ keys: [], unsupported: [] });
    expect(calls).toEqual([["sync_key_candidates", {}]]);
    const choices = [{ path: "/home/f/.ssh/id_mac", decision: { kind: "keep" as const, name: "id_mac" } }];
    expect(keyArgs.setup({ choices })).toEqual({ choices });
    expect(keyArgs.setMode({ slotId: "s", mode: "own" })).toEqual({ slotId: "s", mode: "own" });
    expect(keyArgs.pick({ slotId: "s", path: "/k" })).toEqual({ slotId: "s", path: "/k" });
    expect(keyArgs.slot({ slotId: "s" })).toEqual({ slotId: "s" });
    expect(keyArgs.delivery({ slotId: "s", vault: true })).toEqual({ slotId: "s", vault: true });
    expect(keyArgs.delivery({ slotId: "s", vault: false })).toEqual({ slotId: "s", vault: false });
  });
});

describe("a failed key slot command", () => {
  it("shows the backend's message with hidden characters revealed: it can name another computer", async () => {
    // `sync_key_set_mode` refuses on a computer without the key, naming the one that has it (the name comes from that computer).
    const refusal = (device: string) => `Do this on a computer that has this key, such as ${device}.`;
    stubBackend(async () => {
      throw refusal(SPOOFED_NAME);
    });
    const { mutateAsync } = renderHook(new QueryClient(), useKeySetMode);
    await expect(mutateAsync({ slotId: "s", mode: "synced" })).rejects.toBe(refusal(SPOOFED_NAME));
    expect(toast.getToasts()).toEqual([
      expect.objectContaining({ title: "Could not change how the key is shared", description: refusal(SPOOFED_NAME_SHOWN) }),
    ]);
  });

  it("leaves an ordinary message as it is", async () => {
    const inTheWay = "A file SSHelter didn't create is in the way: /home/f/.ssh/sshelter/keys/id_mac-3fa2c1d9. Move it, then sync again.";
    stubBackend(async () => {
      throw inTheWay;
    });
    const { mutateAsync } = renderHook(new QueryClient(), useKeyPick);
    await expect(mutateAsync({ slotId: "s", path: "/home/f/.ssh/id_mac" })).rejects.toBe(inTheWay);
    expect(toast.getToasts()).toEqual([expect.objectContaining({ title: "Could not use that key", description: inTheWay })]);
  });

  it("reports a key that was set up in the meantime as a failure, and reads the keys again", async () => {
    // A Sync key / Keep choice for a key that is no longer listed: the backend changes nothing and says so. The row's own
    // success toast runs only when the call succeeds.
    const meantime = "This key was set up in the meantime; nothing changed.";
    stubBackend(async () => {
      throw meantime;
    });
    const queryClient = new QueryClient();
    queryClient.setQueryData(keyCandidatesKey, { keys: [], unsupported: [] });
    const { mutateAsync } = renderHook(queryClient, useSetupKeys);
    const choices = [{ path: "/home/f/.ssh/id_mac", decision: { kind: "sync" as const, name: "id_mac" } }];
    await expect(mutateAsync({ choices })).rejects.toBe(meantime);
    expect(toast.getToasts()).toEqual([expect.objectContaining({ title: "Could not set up the key", description: meantime })]);
    expect(queryClient.getQueryState(keyCandidatesKey)?.isInvalidated).toBe(true);
  });

  it("asks the backend to move the key and says what could not be moved", async () => {
    const calls = stubBackend(async () => {
      throw "The key in SSHelter's vault doesn't match this slot.";
    });
    const { mutateAsync } = renderHook(new QueryClient(), useKeySetDelivery);
    await expect(mutateAsync({ slotId: "s", vault: false })).rejects.toBe("The key in SSHelter's vault doesn't match this slot.");
    expect(calls).toEqual([["sync_key_set_delivery", { slotId: "s", vault: false }]]);
    expect(toast.getToasts()).toEqual([
      expect.objectContaining({ title: "Could not change where the key is kept", description: "The key in SSHelter's vault doesn't match this slot." }),
    ]);
  });

  it("titles a failed deletion as its caller asks: Delete key… deletes a key, Delete copy a copy", async () => {
    const inUse = "Hosts on this computer still use this key; change them first.";
    const calls = stubBackend(async () => {
      throw inUse;
    });
    const deleteKey = renderHook(new QueryClient(), () => useKeyDeleteCopy("Could not delete the key"));
    await expect(deleteKey.mutateAsync({ slotId: "s" })).rejects.toBe(inUse);
    const deleteCopy = renderHook(new QueryClient(), () => useKeyDeleteCopy());
    await expect(deleteCopy.mutateAsync({ slotId: "s" })).rejects.toBe(inUse);
    expect(calls).toEqual([
      ["sync_key_delete_copy", { slotId: "s" }],
      ["sync_key_delete_copy", { slotId: "s" }],
    ]);
    expect(toast.getToasts()).toEqual([
      expect.objectContaining({ title: "Could not delete the key", description: inUse }),
      expect.objectContaining({ title: "Could not delete the copy", description: inUse }),
    ]);
  });

  it("re-reads the views after a failed pick or use of the synced key, which can fail after the slot's key was moved aside", async () => {
    stubBackend(async () => {
      throw "boom";
    });
    /** Which of the overview, the approvals and a config view (the key candidates) the failed command marked for a re-read. */
    const reread = async (run: (queryClient: QueryClient) => Promise<unknown>) => {
      const queryClient = new QueryClient();
      queryClient.setQueryData(syncOverviewKey, overview());
      queryClient.setQueryData(syncApprovalsKey, []);
      queryClient.setQueryData(keyCandidatesKey, { keys: [], unsupported: [] });
      await expect(run(queryClient)).rejects.toBe("boom");
      return [syncOverviewKey, syncApprovalsKey, keyCandidatesKey].map((key) => queryClient.getQueryState(key)?.isInvalidated);
    };
    expect(await reread((qc) => renderHook(qc, useKeyPick).mutateAsync({ slotId: "s", path: "/k" }))).toEqual([true, true, true]);
    expect(await reread((qc) => renderHook(qc, useKeyUseSynced).mutateAsync({ slotId: "s" }))).toEqual([true, true, true]);
    // Moving a key into the vault or out of it writes files and the vault before the state changes: it re-reads, too.
    expect(await reread((qc) => renderHook(qc, useKeySetDelivery).mutateAsync({ slotId: "s", vault: true }))).toEqual([true, true, true]);
    // The mode change and the copy delete keep the cached views on a failure, as they did.
    expect(await reread((qc) => renderHook(qc, useKeySetMode).mutateAsync({ slotId: "s", mode: "own" }))).toEqual([false, false, false]);
    expect(await reread((qc) => renderHook(qc, useKeyDeleteCopy).mutateAsync({ slotId: "s" }))).toEqual([false, false, false]);
  });
});

describe("leaving", () => {
  const LEFT = "Left the sync account on this computer";
  const FAILED = "Could not leave the sync account";
  const readRust = () => readFileSync("src-tauri/src/sync/account.rs", "utf8");

  it("titles every error that came after this computer already left as such (account.rs)", () => {
    const rust = readRust();
    const replaced = /const LEAVE_REPLACED_MESSAGE: &str =\s*"([^"]*)"/.exec(rust)?.[1] ?? "";
    const abandoned = /fn leave_abandoned_message[\s\S]*?format!\(\s*"([^"]*)\{\}"/.exec(rust)?.[1] ?? "";
    for (const text of [replaced, abandoned]) expect(text).not.toBe("");
    expect(leaveFailureTitle(replaced)).toBe(LEFT);
    expect(leaveFailureTitle(abandoned)).toBe(LEFT);
    expect(leaveFailureTitle(`${abandoned}. The sync account was not deleted from the relay`)).toBe(LEFT);
    // After it cleared the account, `leave_account` itself answers with an error when the keychain or the
    // state file could not be cleaned up: every "left the sync account…" literal in its body.
    const start = rust.indexOf("pub fn leave_account(");
    expect(start).toBeGreaterThan(-1);
    const body = rust.slice(start, rust.indexOf("\n}\n", start));
    const cleanup = [...body.matchAll(/"(left the sync account(?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\"/g, '"'));
    expect(cleanup.length).toBeGreaterThanOrEqual(2);
    for (const text of cleanup) expect(leaveFailureTitle(text), text).toBe(LEFT);
  });

  it("keeps the failure title for the errors where this computer did not leave (account.rs)", () => {
    const rust = readRust();
    const refused = /const LEAVE_ROTATING_MESSAGE: &str =\s*"([^"]*)"/.exec(rust)?.[1] ?? "";
    const kept = /fn kept_error\([^)]*\)[\s\S]*?format!\(\s*"([^"]*)"/.exec(rust)?.[1] ?? "";
    const remoteDeleted = /fn remote_deleted_error[\s\S]*?format!\(\s*"([^"]*)"/.exec(rust)?.[1] ?? "";
    for (const text of [refused, kept, remoteDeleted]) {
      expect(text).not.toBe("");
      expect(leaveFailureTitle(text), text).toBe(FAILED);
    }
  });
});

describe("the shadow list's place in the query cache", () => {
  const invalidated = (queryClient: QueryClient, key: readonly unknown[]) => queryClient.getQueryState(key)?.isInvalidated;

  /** A cache with the config views the app keeps, each marked fresh by `setQueryData`. */
  function seeded(): QueryClient {
    const queryClient = new QueryClient();
    queryClient.setQueryData(queryKeys.hosts, { files: [], hosts: [] });
    queryClient.setQueryData(queryKeys.host("web"), null);
    queryClient.setQueryData(queryKeys.host("syncDuplicates"), null); // an alias that is spelled like a part of the key
    queryClient.setQueryData(queryKeys.fileText("/home/f/.ssh/config"), "");
    queryClient.setQueryData(syncDuplicatesKey, [{ alias: "web", local_file: "/home/f/.ssh/config" }]);
    queryClient.setQueryData(syncUnmovableKey, []);
    return queryClient;
  }

  it("is under the hosts' key, so the app's own add, save, rename, move and removal refresh it with the hosts", () => {
    expect(syncDuplicatesKey.slice(0, queryKeys.hosts.length)).toEqual([...queryKeys.hosts]);
    const queryClient = seeded();
    // What `useAddHost`, `useSaveHost`, `useRemoveHost`, `useRenameHost` and `useMoveHost` invalidate.
    void queryClient.invalidateQueries({ queryKey: queryKeys.hosts });
    expect(invalidated(queryClient, syncDuplicatesKey)).toBe(true);
    expect(invalidated(queryClient, queryKeys.hosts)).toBe(true);
    // A host's detail is a different key: the hosts' invalidation leaves it alone, as it always did.
    expect(invalidated(queryClient, queryKeys.host("web"))).toBe(false);
  });

  it("is refreshed by a config reload (everything under [\"config\"]) like every other config view", () => {
    const queryClient = seeded();
    void queryClient.invalidateQueries({ queryKey: ["config"] });
    for (const key of [syncDuplicatesKey, syncUnmovableKey, queryKeys.hosts, queryKeys.host("web")]) expect(invalidated(queryClient, key), String(key)).toBe(true);
  });

  it("keeps the list a resolved copy answered with, and refreshes everything else under config", () => {
    const queryClient = seeded();
    applyResolved(queryClient, []);
    expect(queryClient.getQueryData(syncDuplicatesKey)).toEqual([]);
    expect(invalidated(queryClient, syncDuplicatesKey)).toBe(false);
    for (const key of [queryKeys.hosts, queryKeys.host("web"), queryKeys.fileText("/home/f/.ssh/config"), syncUnmovableKey]) {
      expect(invalidated(queryClient, key), String(key)).toBe(true);
    }
    // The key is compared whole: a host whose alias is a part of it is refreshed too.
    expect(invalidated(queryClient, queryKeys.host("syncDuplicates"))).toBe(true);
  });
});

describe("Move and Export private key", () => {
  it("Move puts the new overview in place and hands back the keys that could not move", async () => {
    const failed = [{ slot_id: "s", name: "id_work", message: "The key this slot points to is gone: /home/f/.ssh/id_work." }];
    const moved = overview({ last_sync_ms: 1 });
    const calls = stubBackend(async () => ({ overview: moved, failed }));
    const queryClient = new QueryClient();
    queryClient.setQueryData(syncOverviewKey, overview());
    const result = await renderHook(queryClient, useKeyMoveAllIntoVault).mutateAsync();
    expect(calls).toEqual([["sync_key_move_all_into_vault", {}]]);
    expect(result.failed).toEqual(failed);
    expect(queryClient.getQueryData(syncOverviewKey)).toEqual(moved);
  });

  it("a failed Move says so and re-reads everything", async () => {
    stubBackend(async () => {
      throw "boom";
    });
    const queryClient = new QueryClient();
    queryClient.setQueryData(syncOverviewKey, overview());
    await expect(renderHook(queryClient, useKeyMoveAllIntoVault).mutateAsync()).rejects.toBe("boom");
    expect(toast.getToasts()).toEqual([expect.objectContaining({ title: "Could not move the keys into SSHelter", description: "boom" })]);
    expect(queryClient.getQueryState(syncOverviewKey)?.isInvalidated).toBe(true);
  });

  it("a failed Move shows the backend's message with hidden characters revealed: it can name a key from another computer", async () => {
    const refusal = (name: string) => `Could not move ${name}: SSHelter's vault is not available.`;
    stubBackend(async () => {
      throw refusal(SPOOFED_NAME);
    });
    await expect(renderHook(new QueryClient(), useKeyMoveAllIntoVault).mutateAsync()).rejects.toBe(refusal(SPOOFED_NAME));
    expect(toast.getToasts()).toEqual([
      expect.objectContaining({ title: "Could not move the keys into SSHelter", description: refusal(SPOOFED_NAME_SHOWN) }),
    ]);
  });

  it("Move refreshes what every command that answers with the overview refreshes: the config views and the approvals", async () => {
    stubBackend(async () => ({ overview: overview(), failed: [] }));
    const queryClient = new QueryClient();
    const views = [keyCandidatesKey, syncApprovalsKey];
    for (const key of views) queryClient.setQueryData(key, []);
    await renderHook(queryClient, useKeyMoveAllIntoVault).mutateAsync();
    expect(views.map((key) => queryClient.getQueryState(key)?.isInvalidated)).toEqual([true, true]);
  });

  it("Export private key sends the passphrase, or null, and gives back where the file was saved", async () => {
    const calls = stubBackend(async () => "/home/f/Desktop/id_mac");
    expect(await exportPrivateKey("s", "correct horse")).toBe("/home/f/Desktop/id_mac");
    expect(await exportPrivateKey("s", null)).toBe("/home/f/Desktop/id_mac");
    expect(calls).toEqual([
      ["sync_key_export_private", { slotId: "s", passphrase: "correct horse" }],
      ["sync_key_export_private", { slotId: "s", passphrase: null }],
    ]);
  });
});

describe("New key and Generate key", () => {
  it("adds and generates keys with plain calls (no key text in the query cache)", async () => {
    const calls = stubBackend(async () => ({ overview: overview(), slot_id: "s" }));
    await importKeyText("laptop", "-----BEGIN OPENSSH PRIVATE KEY-----\n…");
    await importKeyFile("work", "/home/f/.ssh/id_work", true);
    await previewKeyFile("/home/f/.ssh/id_work");
    // The Generate key form has no Comment field: it passes the key's name as the comment.
    await generateKey("id_ed25519", "ed25519", "id_ed25519", null);
    expect(calls).toEqual([
      ["sync_key_import_text", { name: "laptop", text: "-----BEGIN OPENSSH PRIVATE KEY-----\n…" }],
      ["sync_key_import_file", { name: "work", path: "/home/f/.ssh/id_work", keepFile: true }],
      ["sync_key_preview_file", { path: "/home/f/.ssh/id_work" }],
      ["sync_key_generate", { name: "id_ed25519", algorithm: "ed25519", comment: "id_ed25519", passphrase: null }],
    ]);
  });

  it("puts the new overview in place and re-reads what a new key changed: the config views and the key files", () => {
    const queryClient = new QueryClient();
    queryClient.setQueryData(syncOverviewKey, overview());
    const views = [queryKeys.hosts, queryKeys.keys];
    for (const key of views) queryClient.setQueryData(key, []);
    const added = overview({ last_sync_ms: 1 });
    applyNewKey(queryClient, added);
    expect(queryClient.getQueryData(syncOverviewKey)).toEqual(added);
    expect(queryClient.getQueryState(syncOverviewKey)?.isInvalidated).toBe(false);
    expect(views.map((key) => queryClient.getQueryState(key)?.isInvalidated)).toEqual([true, true]);
  });
});
