import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import * as api from "@/lib/records";
import {
  clearLifecycleDraft,
  retireLifecycleAttempt,
  submitLifecycleDraft,
  type LifecycleDraft,
} from "./account-lifecycle-actions";
import { recordOverview, recordsStatus } from "./fixtures";
afterEach(() => vi.unstubAllGlobals());
const cache = () => {
  const client = new QueryClient();
  client.setQueryData(api.recordsStatusKey, recordsStatus());
  return client;
};
const leave = (complete: boolean): api.AccountLeaveResult => ({
  receipt: {
    operation_id: "a".repeat(32),
    complete,
    copied_hosts: 2,
    mappings: [
      {
        source_space_id: "space",
        source_host_id: "0000000000000001",
        local_host_id: "0000000000000002",
        alias: "work",
      },
    ],
    pending_error: complete ? null : "Relay unavailable",
  },
  overview: recordOverview({
    account: null,
    pending_account: complete
      ? null
      : { id: "a".repeat(32), kind: "leave_account", phase: "publishing" },
  }),
});
const textCache = (client: QueryClient) =>
  JSON.stringify(
    client
      .getQueryCache()
      .getAll()
      .map((q) => q.state),
  );
describe("account lifecycle native and draft contract", () => {
  it("uses actual direct leave and camelCase rotation arguments", async () => {
    const calls = stubBackend(async () => null);
    await api.leaveRecordAccount();
    await api.rotateRecordAccount("Laptop");
    expect(calls).toEqual([
      ["records_account_leave", {}],
      ["records_account_rotate", { deviceName: "Laptop" }],
    ]);
  });
  it("refuses unacknowledged, busy, or unnamed rotation before IPC", async () => {
    const calls = stubBackend(async () => null);
    const update = vi.fn();
    const client = cache();
    for (const state of [
      clearLifecycleDraft("leave"),
      { ...clearLifecycleDraft("rotate"), consent: true },
      { ...clearLifecycleDraft("leave"), consent: true, busy: true },
    ])
      expect(await submitLifecycleDraft(client, state, update)).toBe(false);
    expect(calls).toEqual([]);
  });
  it("retains a partial leave receipt and public recovery state without claiming completion", async () => {
    const client = cache();
    stubBackend(async () => leave(false));
    let state: LifecycleDraft = {
      ...clearLifecycleDraft("leave"),
      consent: true,
    };
    const update = (patch: Partial<LifecycleDraft>) => {
      state = { ...state, ...patch };
    };
    expect(await submitLifecycleDraft(client, state, update)).toBe(true);
    expect(state.leaveReceipt?.complete).toBe(false);
    expect(state.leaveReceipt?.copied_hosts).toBe(2);
    expect(state.error).toContain("Relay unavailable");
    expect(state.mode).toBeNull();
    expect(state.busy).toBe(false);
    expect(
      client.getQueryData<api.RecordsStatus>(api.recordsStatusKey)?.overview
        ?.pending_account?.kind,
    ).toBe("leave_account");
  });
  it("shows completed leave only from the receipt and preserves host mappings", async () => {
    const client = cache();
    stubBackend(async () => leave(true));
    let state: LifecycleDraft = {
      ...clearLifecycleDraft("leave"),
      consent: true,
    };
    const update = (patch: Partial<LifecycleDraft>) => {
      state = { ...state, ...patch };
    };
    await submitLifecycleDraft(client, state, update);
    expect(state.leaveReceipt?.complete).toBe(true);
    expect(state.leaveReceipt?.mappings[0].local_host_id).toBe(
      "0000000000000002",
    );
    expect(state.error).toBeNull();
  });
  it("keeps a partially published rotation code in component memory and cache only public overview", async () => {
    const client = cache();
    const overview = recordOverview({
      pending_account: {
        id: "b".repeat(32),
        kind: "rotate_account",
        phase: "prepared",
      },
    });
    const calls = stubBackend(async () => ({
      words: "SECRET new fixture code",
      overview,
      complete: false,
      pending_error: "Publication pending",
      operation_id: "b".repeat(32),
    }));
    let state: LifecycleDraft = {
      ...clearLifecycleDraft("rotate", "Laptop"),
      consent: true,
    };
    const update = (patch: Partial<LifecycleDraft>) => {
      state = { ...state, ...patch };
    };
    await submitLifecycleDraft(client, state, update);
    expect(calls).toEqual([
      ["records_account_rotate", { deviceName: "Laptop" }],
    ]);
    expect(state.words).toBe("SECRET new fixture code");
    expect(state.rotation?.complete).toBe(false);
    expect(state.error).toContain("Publication pending");
    expect(textCache(client)).not.toContain("SECRET");
    expect(textCache(client)).not.toContain("words");
    expect(client.getMutationCache().getAll()).toEqual([]);
  });
  it("keeps consent after failure but never reflects an IPC error that may contain code", async () => {
    const client = cache();
    stubBackend(async () => {
      throw "SECRET code vault failure";
    });
    let state: LifecycleDraft = {
      ...clearLifecycleDraft("rotate", "Laptop"),
      consent: true,
    };
    const update = (patch: Partial<LifecycleDraft>) => {
      state = { ...state, ...patch };
    };
    expect(await submitLifecycleDraft(client, state, update)).toBe(false);
    expect(state.error).not.toContain("SECRET");
    expect(state.consent).toBe(true);
    expect(state.busy).toBe(false);
    expect(clearLifecycleDraft().words).toBe("");
    expect(clearLifecycleDraft().rotation).toBeNull();
  });
});

it("retires a retry receipt while preserving a new code until explicit acknowledgment", () => {
  const state: LifecycleDraft = {
    ...clearLifecycleDraft(),
    words: "SECRET unsaved fixture code",
    rotation: { operation_id: "a".repeat(32), complete: false },
    error: "Pending",
  };
  const retired = retireLifecycleAttempt(state);
  expect(retired.words).toBe(state.words);
  expect(retired.rotation).toBeNull();
  expect(retired.error).toBeNull();
  expect(state.rotation).not.toBeNull();
  expect(clearLifecycleDraft().words).toBe("");
});
