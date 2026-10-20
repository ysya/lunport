import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import { recordKeyDestinationKey, recordsStatusKey } from "@/lib/records";
import {
  clearAccountDraft,
  clearKeyDraft,
  keyActionError,
  submitAccountDraft,
  submitImportConsent,
  submitKeyDraft,
  resumeImport,
  type KeyDraft,
} from "./panel-actions";
import { importPreview, recordOverview, recordsStatus } from "./fixtures";
afterEach(() => vi.unstubAllGlobals());
const client = () => {
  const cache = new QueryClient();
  cache.setQueryData(recordsStatusKey, recordsStatus());
  return cache;
};
const cacheText = (cache: QueryClient) =>
  JSON.stringify(
    cache
      .getQueryCache()
      .getAll()
      .map((query) => query.state),
  );
describe("secret form boundary", () => {
  it("imports exact private input directly, clears it after success and caches only public metadata", async () => {
    const cache = client();
    const calls = stubBackend(async () =>
      recordOverview({ generation: "9007199254740994" }),
    );
    let state: KeyDraft = {
      ...clearKeyDraft(),
      name: "work",
      source: "paste" as const,
      privateText: "PRIVATE fixture text",
    };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await submitKeyDraft(cache, state, update)).toBe(true);
    expect(calls).toEqual([
      [
        "records_key_import",
        { name: "work", privateText: "PRIVATE fixture text" },
      ],
    ]);
    expect(state.privateText).toBe("");
    expect(cache.getMutationCache().getAll()).toEqual([]);
    expect(cacheText(cache)).not.toContain("PRIVATE fixture text");
  });
  it("retains a failed key draft but never reflects private input in the error", async () => {
    const cache = client();
    stubBackend(async () => {
      throw "PRIVATE fixture text could not parse";
    });
    let state: KeyDraft = {
      ...clearKeyDraft(),
      name: "work",
      source: "paste" as const,
      privateText: "PRIVATE fixture text",
    };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await submitKeyDraft(cache, state, update)).toBe(false);
    expect(state.privateText).toBe("PRIVATE fixture text");
    expect(state.error).not.toContain("PRIVATE");
    expect(state.busy).toBe(false);
    expect(cache.getMutationCache().getAll()).toEqual([]);
  });
  it("keeps generated account words only in the account component draft", async () => {
    const cache = client();
    stubBackend(async () => ({
      words: "SECRET sync fixture words",
      overview: recordOverview(),
    }));
    let state = { ...clearAccountDraft(), deviceName: "Laptop" };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await submitAccountDraft(cache, state, update, true)).toBe(true);
    expect(state.createdWords).toBe("SECRET sync fixture words");
    expect(state.words).toBe("");
    expect(cacheText(cache)).not.toContain("SECRET");
    expect(cache.getMutationCache().getAll()).toEqual([]);
  });
  it("retains code and exposes pending setup when remote publication was incomplete", async () => {
    const cache = client();
    const overview = recordOverview({
      pending_account: {
        id: "a".repeat(32),
        kind: "create_account",
        phase: "prepared",
      },
    });
    stubBackend(async () => ({
      words: "SECRET partial code",
      overview,
      complete: false,
      pending_error: "Relay is unavailable",
      operation_id: "a".repeat(32),
    }));
    let state = { ...clearAccountDraft(), deviceName: "Laptop" };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await submitAccountDraft(cache, state, update, true)).toBe(true);
    expect(state.createdWords).toBe("SECRET partial code");
    expect(state.error).toContain("Relay is unavailable");
    expect(cacheText(cache)).not.toContain("SECRET");
  });
  it("retains a refused old-account code and offers authoritative migration preview", async () => {
    const cache = client();
    stubBackend(async () => {
      throw "this account needs explicit migration before joining records mode";
    });
    let state = {
      ...clearAccountDraft(),
      deviceName: "Laptop",
      words: "SECRET older fixture words",
    };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await submitAccountDraft(cache, state, update, false)).toBe(false);
    expect(state.words).toBe("SECRET older fixture words");
    expect(state).toMatchObject({ migrationOffered: true });
    expect(cacheText(cache)).not.toContain("SECRET");
    expect(state.error).not.toContain("SECRET");
  });
  it("clears join words on success without leaving mutation variables in cache", async () => {
    const cache = client();
    const calls = stubBackend(async () => recordOverview());
    let state = {
      ...clearAccountDraft(),
      deviceName: "Laptop",
      words: "SECRET join fixture words",
    };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await submitAccountDraft(cache, state, update, false)).toBe(true);
    expect(calls).toEqual([
      [
        "records_account_join",
        { words: "SECRET join fixture words", deviceName: "Laptop" },
      ],
    ]);
    expect(state.words).toBe("");
    expect(state.createdWords).toBe("");
    expect(cacheText(cache)).not.toContain("SECRET");
    expect(cache.getMutationCache().getAll()).toEqual([]);
  });
  it("clears every secret when cancelled and refuses invalid or busy forms before IPC", async () => {
    const cache = client();
    const calls = stubBackend(async () => undefined);
    const update = vi.fn();
    expect(clearKeyDraft().privateText).toBe("");
    expect(clearAccountDraft().words).toBe("");
    expect(clearAccountDraft().createdWords).toBe("");
    expect(await submitKeyDraft(cache, clearKeyDraft(), update)).toBe(false);
    expect(
      await submitAccountDraft(
        cache,
        { ...clearAccountDraft(), busy: true },
        update,
        true,
      ),
    ).toBe(false);
    expect(calls).toEqual([]);
  });
  it("generates a local key using only its public name", async () => {
    const cache = client();
    const calls = stubBackend(async () => recordOverview());
    let state = { ...clearKeyDraft(), name: "new_key" };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await submitKeyDraft(cache, state, update, true)).toBe(true);
    expect(calls).toEqual([["records_key_generate", { name: "new_key" }]]);
  });
  it("imports the selected file by path, ignores inactive pasted text and clears both drafts on success", async () => {
    const cache = client();
    const calls = stubBackend(async () => recordOverview());
    let state: KeyDraft = { ...clearKeyDraft(), name: "work", path: "/fixture/id_work", privateText: "INACTIVE_PRIVATE_SENTINEL" };
    const update = (patch: Partial<typeof state>) => { state = { ...state, ...patch }; };
    expect(await submitKeyDraft(cache, state, update)).toBe(true);
    expect(calls).toEqual([["records_key_import_file", { name: "work", path: "/fixture/id_work" }]]);
    expect(state).toMatchObject({ privateText: "", path: null, name: "", busy: false });
    expect(cache.getMutationCache().getAll()).toEqual([]);
    expect(cacheText(cache)).not.toContain("INACTIVE_PRIVATE_SENTINEL");
    expect(cacheText(cache)).not.toContain("/fixture/id_work");
  });
  it("requires the active source and keeps a failed file selection without echoing backend details", async () => {
    const cache = client();
    const calls = stubBackend(async () => { throw "PRIVATE_SENTINEL file read failed"; });
    let state = { ...clearKeyDraft(), name: "work", privateText: "inactive pasted text" };
    const update = (patch: Partial<typeof state>) => { state = { ...state, ...patch }; };
    expect(await submitKeyDraft(cache, state, update)).toBe(false);
    expect(calls).toEqual([]);
    state.path = "/fixture/id_work";
    expect(await submitKeyDraft(cache, state, update)).toBe(false);
    expect(state.path).toBe("/fixture/id_work");
    expect(state.busy).toBe(false);
    expect(state.error).not.toContain("PRIVATE_SENTINEL");
    expect(cacheText(cache)).not.toContain("PRIVATE_SENTINEL");
  });
});
describe("reviewed file import", () => {
  it("copies no keys by default, including preview entries marked will_copy", async () => {
    const cache = client();
    const preview = importPreview();
    preview.preview.key_references[0].will_copy = true;
    const result = {
      receipt: {
        import_id: "i".repeat(32),
        host_ids: ["0000000000000002"],
        copied_key_ids: [],
      },
      overview: recordOverview(),
    };
    const calls = stubBackend(async () => result);
    expect(await submitImportConsent(cache, preview, [])).toEqual(result);
    expect(calls).toEqual([
      ["records_import_confirm", { token: preview.token, copyKeyIds: [] }],
    ]);
  });
  it("confirms only selected references from this preview and retains review after a failed write", async () => {
    const cache = client();
    const preview = importPreview();
    const before = structuredClone(preview);
    const calls = stubBackend(async () => {
      throw "state save failed";
    });
    await expect(
      submitImportConsent(cache, preview, [
        "a".repeat(32),
        "stale",
        "a".repeat(32),
      ]),
    ).rejects.toBe("state save failed");
    expect(calls).toEqual([
      [
        "records_import_confirm",
        { token: preview.token, copyKeyIds: ["a".repeat(32)] },
      ],
    ]);
    expect(preview).toEqual(before);
  });
  it("resumes an existing receipt without requesting new key copies", async () => {
    const cache = client();
    const result = {
      receipt: { import_id: "a".repeat(32), host_ids: [], copied_key_ids: [] },
      overview: recordOverview(),
    };
    const calls = stubBackend(async () => result);
    expect(await resumeImport(cache, "a".repeat(32))).toEqual(result);
    expect(calls).toEqual([
      ["records_import_resume", { importId: "a".repeat(32) }],
    ]);
  });
});

const keyInvocation = {
  generation: "7",
  profile: "1".repeat(64), account: "2".repeat(64), genesis: "3".repeat(64),
  vault: "4".repeat(64), device: "5".repeat(32), identity_slot: null,
};
describe("key destination fence", () => {
  it("sends the exact public destination and caches only a matching reply", async () => {
    const cache = client();
    const overview = recordOverview({ central_mode: true, key_scope: keyInvocation });
    const calls = stubBackend(async () => overview);
    const update = vi.fn();
    expect(await submitKeyDraft(cache, { ...clearKeyDraft(), name: "work", source: "paste", privateText: "PRIVATE synthetic input" }, update, false,
      { invocation: keyInvocation, destination: recordKeyDestinationKey(overview), current: () => true })).toBe(true);
    expect(calls).toEqual([["records_key_import", { name: "work", privateText: "PRIVATE synthetic input", invocation: keyInvocation }]]);
    expect(cacheText(cache)).not.toContain("PRIVATE synthetic input");
    expect(cache.getMutationCache().getAll()).toEqual([]);
  });
  it("ignores late success or failure after a form lifetime changes without touching the new draft", async () => {
    for (const failure of [false, true]) {
      const cache = client();
      const overview = recordOverview({ central_mode: true, key_scope: keyInvocation });
      let settle!: (value: unknown) => void;
      let reject!: (reason: unknown) => void;
      stubBackend(() => new Promise((resolve, fail) => { settle = resolve; reject = fail; }));
      let current = true;
      const update = vi.fn();
      const pending = submitKeyDraft(cache, { ...clearKeyDraft(), name: "work", source: "paste", privateText: "PRIVATE old draft" }, update, false,
        { invocation: keyInvocation, destination: recordKeyDestinationKey(overview), current: () => current });
      expect(update).toHaveBeenCalledWith({ busy: true, error: null });
      update.mockClear(); current = false;
      if (failure) reject("PRIVATE old draft failure"); else settle(overview);
      expect(await pending).toBe(false);
      expect(update).not.toHaveBeenCalled();
      expect(cacheText(cache)).not.toContain(keyInvocation.profile);
      expect(cacheText(cache)).not.toContain("PRIVATE");
    }
  });
  it("discards a mismatched native reply even before an account change is rendered", async () => {
    const cache = client();
    const overview = recordOverview({ central_mode: true, key_scope: keyInvocation });
    const wrong = recordOverview({ central_mode: true, key_scope: { ...keyInvocation, device: "f".repeat(32) } });
    stubBackend(async () => wrong);
    const update = vi.fn();
    expect(await submitKeyDraft(cache, { ...clearKeyDraft(), name: "work" }, update, true,
      { invocation: keyInvocation, destination: recordKeyDestinationKey(overview), current: () => true })).toBe(false);
    expect(update).not.toHaveBeenCalledWith({ privateText: "", name: "", path: null });
    expect(cacheText(cache)).not.toContain(wrong.key_scope!.device);
  });
});

describe("safe key action diagnostics", () => {
  it("distinguishes missing material, mismatched identity and credential access", () => {
    expect(keyActionError("The key material is unavailable on this device.")).toContain("private key is missing");
    expect(keyActionError(new Error("The vault key does not match its authoritative public identity."))).toContain("does not match");
    expect(keyActionError("The vault is unavailable; its original file was retained.")).toContain("credential store");
    expect(keyActionError("The saved SSH private key could not be parsed.")).toContain("not readable OpenSSH");
    expect(keyActionError("The saved private key's passphrase state does not match this key reference.")).toContain("passphrase state");
    expect(keyActionError("record account is not writable")).toContain("Account sync is blocked");
    expect(keyActionError("synced private material is unavailable")).toContain("no synced private copy");
  });
  it("never reflects unexpected messages or private input", () => {
    for (const error of ["PRIVATE fixture content", new Error("PRIVATE fixture content"), { message: "PRIVATE fixture content" }, null]) {
      expect(keyActionError(error)).toBe("The key action could not be completed. Refresh the workspace and retry.");
    }
  });
});
