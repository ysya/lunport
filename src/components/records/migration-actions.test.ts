import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, stubBackend } from "@/lib/test-ipc";
import * as api from "@/lib/records";
import {
  clearMigrationDraft,
  previewMigrationDraft,
  confirmMigrationDraft,
  resumeMigrationDraft,
  applyMigrationStatus,
  pauseLegacyForMigration,
  discardMigrationPreview,
  type MigrationDraft,
} from "./migration-actions";
import { migrationPreview, recordOverview, recordsStatus } from "./fixtures";
afterEach(() => vi.unstubAllGlobals());
const result = (complete = false): api.MigrationResult => ({
  receipt: {
    migration_id: "a".repeat(32),
    phase: complete ? "active" : "publishing",
    complete,
  },
  status: complete
    ? recordsStatus()
    : recordsStatus({ format: "legacy", legacy_paused: true, overview: null }),
});
const client = () => {
  const cache = new QueryClient();
  cache.setQueryData(
    api.recordsStatusKey,
    recordsStatus({ format: "legacy", legacy_paused: true, overview: null }),
  );
  return cache;
};
describe("migration direct native contract", () => {
  it("uses exact optional-code, consent, stored-id, pending and cancel arguments", async () => {
    const calls = stubBackend(async () => null);
    await api.previewRecordMigration();
    await api.previewRecordMigration("SECRET older fixture words");
    await api.confirmRecordMigration("token", true);
    await api.resumeRecordMigration("a".repeat(32));
    await api.pendingRecordMigrations();
    await api.cancelRecordMigration("token");
    expect(calls).toEqual([
      ["records_migration_preview", { words: null }],
      ["records_migration_preview", { words: "SECRET older fixture words" }],
      [
        "records_migration_confirm",
        { token: "token", oldClientsStoppedOrCompatible: true },
      ],
      [
        "records_migration_resume",
        { migrationId: "a".repeat(32), words: null },
      ],
      ["records_migration_pending", {}],
      ["records_migration_cancel", { token: "token" }],
    ]);
  });
});
describe("component-only migration draft", () => {
  it("clears previewed words and resets consent without putting a token in QueryClient", async () => {
    const cache = client();
    const calls = stubBackend(async () => migrationPreview());
    let state: MigrationDraft = {
      ...clearMigrationDraft("SECRET older fixture words"),
      consent: true,
    };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await previewMigrationDraft(state, update)).toBe(true);
    expect(state.words).toBe("");
    expect(state.preview).toEqual(migrationPreview());
    expect(state.consent).toBe(false);
    expect(state.busy).toBe(false);
    expect(calls).toEqual([
      ["records_migration_preview", { words: "SECRET older fixture words" }],
    ]);
    const cached = JSON.stringify(
      cache
        .getQueryCache()
        .getAll()
        .map((q) => q.state),
    );
    expect(cached).not.toContain("SECRET");
    expect(cached).not.toContain("migration-fixture-token");
    expect(cache.getMutationCache().getAll()).toEqual([]);
  });
  it("keeps a failed preview code only in the component and never reflects it in errors", async () => {
    stubBackend(async () => {
      throw "SECRET older fixture words bad code";
    });
    let state: MigrationDraft = clearMigrationDraft(
      "SECRET older fixture words",
    );
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await previewMigrationDraft(state, update)).toBe(false);
    expect(state.words).toBe("SECRET older fixture words");
    expect(state.error).not.toContain("SECRET");
  });
  it("refuses confirm before explicit old-client consent or an eligible preview", async () => {
    const cache = client();
    const calls = stubBackend(async () => result());
    const update = vi.fn();
    for (const state of [
      clearMigrationDraft(),
      { ...clearMigrationDraft(), preview: migrationPreview() },
      {
        ...clearMigrationDraft(),
        preview: {
          ...migrationPreview(),
          preview: { ...migrationPreview().preview, can_confirm: false },
        },
        consent: true,
      },
    ])
      expect(await confirmMigrationDraft(cache, state, update)).toBe(false);
    expect(calls).toEqual([]);
  });
  it("preserves a partial receipt as pending and does not infer Records activation", async () => {
    const cache = client();
    stubBackend(async () => result());
    let state: MigrationDraft = {
      ...clearMigrationDraft(),
      preview: migrationPreview(),
      consent: true,
    };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await confirmMigrationDraft(cache, state, update)).toBe(true);
    expect(state.receipt?.complete).toBe(false);
    expect(state.receipt?.phase).toBe("publishing");
    expect(state.preview).toBeNull();
    expect(
      cache.getQueryData<api.RecordsStatus>(api.recordsStatusKey)?.format,
    ).toBe("legacy");
    expect(cache.getMutationCache().getAll()).toEqual([]);
  });
  it("marks a failed submitted token consumed and leaves review data for recovery", async () => {
    const cache = client();
    const calls = stubBackend(async () => {
      throw "failed after publishing";
    });
    let state: MigrationDraft = {
      ...clearMigrationDraft(),
      preview: migrationPreview(),
      consent: true,
    };
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await confirmMigrationDraft(cache, state, update)).toBe(false);
    expect(state.consumed).toBe(true);
    expect(state.preview).toEqual(migrationPreview());
    expect(await confirmMigrationDraft(cache, state, update)).toBe(false);
    expect(calls).toHaveLength(1);
    expect(
      cache.getQueryData<api.RecordsStatus>(api.recordsStatusKey)?.format,
    ).toBe("legacy");
  });
  it("resumes a persisted operation ID and applies only returned public status", async () => {
    const cache = client();
    const calls = stubBackend(async () => result(true));
    let state: MigrationDraft = clearMigrationDraft();
    const update = (patch: Partial<typeof state>) => {
      state = { ...state, ...patch };
    };
    expect(await resumeMigrationDraft(cache, "a".repeat(32), update)).toBe(
      true,
    );
    expect(state.receipt?.complete).toBe(true);
    expect(
      cache.getQueryData<api.RecordsStatus>(api.recordsStatusKey)?.format,
    ).toBe("records");
    expect(calls).toEqual([
      [
        "records_migration_resume",
        { migrationId: "a".repeat(32), words: null },
      ],
    ]);
  });
  it("requires saved-edits acknowledgment before stopping the legacy writer", async () => {
    const cache = client();
    const paused = recordsStatus({
      format: "legacy",
      legacy_paused: true,
      overview: null,
    });
    const calls = stubBackend(async () => paused);
    expect(await pauseLegacyForMigration(cache, false)).toBe(false);
    expect(calls).toEqual([]);
    expect(await pauseLegacyForMigration(cache, true)).toBe(true);
    expect(calls).toEqual([["records_pause_legacy", {}]]);
    expect(cache.getQueryData(api.recordsStatusKey)).toEqual(paused);
  });
  it("cancels a status reply captured before pausing so it cannot remount Legacy", async () => {
    const cache = client();
    const unpaused = recordsStatus({
      format: "legacy",
      legacy_paused: false,
      overview: null,
    });
    const paused = { ...unpaused, legacy_paused: true };
    cache.setQueryData(api.recordsStatusKey, unpaused);
    let resolve!: (value: api.RecordsStatus) => void;
    stubBackend(async (command) =>
      command === "records_status"
        ? new Promise<api.RecordsStatus>((complete) => {
            resolve = complete;
          })
        : paused,
    );
    const hook = renderHook(cache, api.useRecordsStatus);
    const inFlight = hook.refetch();
    await pauseLegacyForMigration(cache, true);
    resolve(unpaused);
    await inFlight;
    expect(cache.getQueryData(api.recordsStatusKey)).toEqual(paused);
  });
  it("disposes a preview with only the memory-cache cancellation RPC", async () => {
    const cache = client();
    const current = cache.getQueryData(api.recordsStatusKey);
    const calls = stubBackend(async () => null);
    await discardMigrationPreview(null);
    await discardMigrationPreview("preview-token");
    expect(calls).toEqual([
      ["records_migration_cancel", { token: "preview-token" }],
    ]);
    expect(cache.getQueryData(api.recordsStatusKey)).toEqual(current);
    expect(clearMigrationDraft().words).toBe("");
    expect(clearMigrationDraft().preview).toBeNull();
  });
  it("cancels a Legacy status request captured before migration activation", async () => {
    const cache = client();
    const legacy = recordsStatus({
      format: "legacy",
      legacy_paused: false,
      overview: null,
    });
    cache.setQueryData(api.recordsStatusKey, legacy);
    let resolve!: (value: api.RecordsStatus) => void;
    stubBackend(
      async () =>
        new Promise<api.RecordsStatus>((complete) => {
          resolve = complete;
        }),
    );
    const hook = renderHook(cache, api.useRecordsStatus);
    const inFlight = hook.refetch();
    await applyMigrationStatus(cache, result(true));
    resolve(legacy);
    await inFlight;
    expect(
      cache.getQueryData<api.RecordsStatus>(api.recordsStatusKey)?.format,
    ).toBe("records");
  });
  it("cannot downgrade a newer active Records cache from a late partial Legacy result", async () => {
    const cache = client();
    const current = recordsStatus({
      overview: recordOverview({ generation: "18446744073709551615" }),
    });
    cache.setQueryData(api.recordsStatusKey, current);
    await applyMigrationStatus(cache, result());
    expect(cache.getQueryData(api.recordsStatusKey)).toEqual(current);
    await applyMigrationStatus(cache, result(true));
    expect(cache.getQueryData(api.recordsStatusKey)).toEqual(current);
  });
});

describe("migration staged-key recovery words", () => {
  it("passes recovery words directly, clears them after resume and never caches them", async () => {
    const cache = client();
    const calls = stubBackend(async () => result(true));
    let state = clearMigrationDraft("SECRET recovery fixture words");
    const update = (patch: Partial<MigrationDraft>) => {
      state = { ...state, ...patch };
    };
    expect(
      await resumeMigrationDraft(cache, "a".repeat(32), update, state.words),
    ).toBe(true);
    expect(calls).toEqual([
      [
        "records_migration_resume",
        { migrationId: "a".repeat(32), words: "SECRET recovery fixture words" },
      ],
    ]);
    expect(state.words).toBe("");
    expect(
      JSON.stringify(
        cache
          .getQueryCache()
          .getAll()
          .map((q) => q.state),
      ),
    ).not.toContain("SECRET");
    expect(cache.getMutationCache().getAll()).toEqual([]);
  });
  it("retains failed recovery input without reflecting it in errors", async () => {
    const cache = client();
    stubBackend(async () => {
      throw "SECRET recovery fixture words invalid";
    });
    let state = clearMigrationDraft("SECRET recovery fixture words");
    const update = (patch: Partial<MigrationDraft>) => {
      state = { ...state, ...patch };
    };
    expect(
      await resumeMigrationDraft(cache, "a".repeat(32), update, state.words),
    ).toBe(false);
    expect(state.words).toBe("SECRET recovery fixture words");
    expect(state.error).not.toContain("SECRET");
  });
});
