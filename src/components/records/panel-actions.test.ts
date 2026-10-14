import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import { recordsStatusKey } from "@/lib/records";
import {
  clearAccountDraft,
  clearKeyDraft,
  submitAccountDraft,
  submitImportConsent,
  submitKeyDraft,
  resumeImport,
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
    let state = {
      ...clearKeyDraft(),
      name: "work",
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
    let state = {
      ...clearKeyDraft(),
      name: "work",
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
