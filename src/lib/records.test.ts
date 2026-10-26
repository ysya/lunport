import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, stubBackend } from "@/lib/test-ipc";
import type { RouteChange } from "@/bindings/RouteChange";
import {
  hostPayload,
  hostView,
  recordOverview,
  recordsStatus,
} from "@/components/records/fixtures";
import * as api from "./records";
afterEach(() => vi.unstubAllGlobals());
describe("records native client", () => {
  it("binds key deletion consent to the reviewed snapshot and exact native generation", async () => {
    const overview = recordOverview();
    const calls = stubBackend(async () => overview);
    const expected: api.KeySlotPayload = { schema: 2, name: "work", public_key: "ssh-ed25519 fixture", fingerprint: "SHA256:fixture", key_type: "ssh-ed25519", has_passphrase: false, created_at_ms: 1, origin_device_id: "d".repeat(32) };
    await api.deleteRecordKey("a".repeat(32), expected, "reviewed-hosts", true, "18446744073709551614");
    expect(calls).toEqual([["records_key_delete", { keyId: "a".repeat(32), expected, snapshotToken: "reviewed-hosts", force: true, generation: "18446744073709551614" }]]);
  });

  it("keeps large optimistic tokens intact and sends exact host CRUD arguments", async () => {
    const overview = recordOverview();
    const calls = stubBackend(async () => overview);
    const host = hostView();
    await api.createRecordHost({ kind: "local" }, host.payload);
    await api.updateRecordHost(host.id, host.revision, host.payload);
    await api.deleteRecordHost(host.id, host.revision);
    await api.moveRecordHost(host.id, host.revision, {
      kind: "space",
      space_id: "a".repeat(64),
    });
    expect(calls).toEqual([
      [
        "records_host_create",
        { scope: { kind: "local" }, payload: host.payload },
      ],
      [
        "records_host_update",
        {
          id: host.id,
          revision: {
            version: "9007199254740993",
            updated_at_ms: "18446744073709551614",
            device_id: "d".repeat(32),
          },
          payload: host.payload,
        },
      ],
      ["records_host_delete", { id: host.id, revision: host.revision }],
      [
        "records_host_move",
        {
          id: host.id,
          revision: host.revision,
          destination: { kind: "space", space_id: "a".repeat(64) },
        },
      ],
    ]);
  });
  it("sends a route change with a host save, and no route key without one", async () => {
    const calls = stubBackend(async () => recordOverview());
    const host = hostView();
    const route: RouteChange = {
      expected: null,
      kind: { type: "gcp_iap", project: "eng-dev-396409", zone: "asia-east1-b", instance: "jumpbox", interface: "nic0", account: null, os_login: true, pam: null },
    };
    await api.createRecordHost({ kind: "local" }, host.payload, undefined, route);
    await api.updateRecordHost(host.id, host.revision, host.payload, true, route);
    await api.createRecordHost({ kind: "local" }, host.payload, true);
    await api.updateRecordHost(host.id, host.revision, host.payload);
    expect(calls).toEqual([
      ["records_host_create", { scope: { kind: "local" }, payload: host.payload, route }],
      ["records_host_update", { id: host.id, revision: host.revision, payload: host.payload, upgradeConfirmed: true, route }],
      ["records_host_create", { scope: { kind: "local" }, payload: host.payload, upgradeConfirmed: true }],
      ["records_host_update", { id: host.id, revision: host.revision, payload: host.payload }],
    ]);
    // An omitted route is a missing key: the backend then leaves the host's route untouched.
    expect(calls.map(([, args]) => Object.keys(args as object))).toEqual([
      ["scope", "payload", "route"],
      ["id", "revision", "payload", "upgradeConfirmed", "route"],
      ["scope", "payload", "upgradeConfirmed"],
      ["id", "revision", "payload"],
    ]);
  });
  it("connects a stable ID with terminal preference and never substitutes its alias", async () => {
    const calls = stubBackend(async () => null);
    await api.connectRecordHost("0000000000000002", "iterm2");
    await api.connectRecordHost("0000000000000001", null, true);
    expect(calls).toEqual([
      [
        "records_connect",
        { hostId: "0000000000000002", terminalId: "iterm2", newTab: false },
      ],
      [
        "records_connect",
        { hostId: "0000000000000001", terminalId: null, newTab: true },
      ],
    ]);
  });
  it("uses explicit preview consent and receipt identity for resume", async () => {
    const calls = stubBackend(async () => null);
    await api.previewRecordImport("/fixture/config");
    await api.confirmRecordImport("verified-token", ["a".repeat(32)]);
    await api.resumeRecordImport("receipt-id");
    await api.useLegacyWorkspace();
    expect(calls).toEqual([
      ["records_import_preview", { source: "/fixture/config" }],
      [
        "records_import_confirm",
        { token: "verified-token", copyKeyIds: ["a".repeat(32)] },
      ],
      ["records_import_resume", { importId: "receipt-id" }],
      ["records_use_legacy", {}],
    ]);
  });
  it("does not replace a newer public cache with late snapshots or mutate the old data", () => {
    const client = new QueryClient();
    const current = recordsStatus({
      overview: recordOverview({ generation: "18446744073709551614" }),
    });
    client.setQueryData(api.recordsStatusKey, current);
    api.applyRecordOverview(
      client,
      recordOverview({ generation: "9007199254740993", hosts: [] }),
    );
    expect(client.getQueryData(api.recordsStatusKey)).toEqual(current);
    const incoming = recordsStatus({
      overview: recordOverview({
        generation: "18446744073709551615",
        hosts: [],
      }),
    });
    expect(api.acceptStatus(current, incoming)).toEqual(incoming);
    expect(current.overview?.hosts).toHaveLength(1);
  });
  it("compares a polled response to the latest cache after the request completes", async () => {
    const client = new QueryClient();
    const old = recordsStatus();
    const newer = recordsStatus({
      overview: recordOverview({ generation: "18446744073709551615" }),
    });
    client.setQueryData(api.recordsStatusKey, old);
    let resolve!: (status: api.RecordsStatus) => void;
    stubBackend(
      async () =>
        new Promise<api.RecordsStatus>((complete) => {
          resolve = complete;
        }),
    );
    const hook = renderHook(client, api.useRecordsStatus);
    const pending = hook.refetch();
    client.setQueryData(api.recordsStatusKey, newer);
    resolve(old);
    await pending;
    expect(client.getQueryData(api.recordsStatusKey)).toEqual(newer);
  });
  it("preserves explicit blocked mode instead of promoting it from a late mutation reply", () => {
    const client = new QueryClient();
    const blocked = recordsStatus({
      format: "blocked",
      overview: null,
      blocked_reason: "future state retained",
    });
    client.setQueryData(api.recordsStatusKey, blocked);
    api.applyRecordOverview(client, recordOverview());
    expect(client.getQueryData(api.recordsStatusKey)).toEqual(blocked);
  });
  it("reads public mode without loading legacy config or credentials", async () => {
    const status = recordsStatus();
    const calls = stubBackend(async () => status);
    expect(await api.fetchRecordsStatus()).toEqual(status);
    expect(calls).toEqual([["records_status", {}]]);
  });
  it("uses direct secret/account/key/space calls and sends only public overview to cache", async () => {
    const overview = recordOverview();
    const calls = stubBackend(async (command) =>
      command === "records_account_create"
        ? { words: "private-fixture-code", overview }
        : overview,
    );
    const client = new QueryClient();
    client.setQueryData(api.recordsStatusKey, recordsStatus());
    api.applyRecordOverview(
      client,
      await api.importRecordKey("Work", "private-fixture-key"),
    );
    await api.generateRecordKey("Generated");
    const created = await api.createRecordAccount("Laptop");
    api.applyRecordOverview(client, created.overview);
    await api.joinRecordAccount("private-fixture-code", "Laptop");
    await api.createRecordSpace("Production");
    await api.selectRecordSpace("a".repeat(64), true);
    await api.setRecordKeySync("a".repeat(32), true);
    await api.syncRecordsNow();
    expect(calls).toEqual([
      [
        "records_key_import",
        { name: "Work", privateText: "private-fixture-key" },
      ],
      ["records_key_generate", { name: "Generated" }],
      ["records_account_create", { deviceName: "Laptop" }],
      [
        "records_account_join",
        { words: "private-fixture-code", deviceName: "Laptop" },
      ],
      ["records_space_create", { name: "Production" }],
      ["records_space_select", { spaceId: "a".repeat(64), selected: true }],
      ["records_key_sync", { keyId: "a".repeat(32), enabled: true }],
      ["records_sync_now", {}],
    ]);
    expect(
      JSON.stringify(
        client
          .getQueryCache()
          .getAll()
          .map((query) => query.state.data),
      ),
    ).not.toContain("private-fixture");
    expect(client.getMutationCache().getAll()).toEqual([]);
  });
  it("uses public recovery identifiers, explicit code reveal, key download and relay update", async () => {
    const calls = stubBackend(async () => null);
    await api.cancelRecordImport("token");
    await api.pendingRecordImports();
    await api.downloadRecordKey("a".repeat(32));
    await api.resumeRecordAccount();
    await api.resumeRecordAccount("private-code");
    await api.recordAccountWords();
    await api.setRecordRelayUrl("https://relay.fixture.invalid");
    expect(calls).toEqual([
      ["records_import_cancel", { token: "token" }],
      ["records_import_pending", {}],
      ["records_key_download", { keyId: "a".repeat(32) }],
      ["records_account_resume", { words: null }],
      ["records_account_resume", { words: "private-code" }],
      ["records_account_words", {}],
      ["records_set_relay_url", { url: "https://relay.fixture.invalid" }],
    ]);
  });
  it("retains authenticated sync intent and saved sync diagnostics from public DTOs", async () => {
    const key = {
      id: "a".repeat(32),
      authority: "account" as const,
      synced: false,
      public: null,
      status: "available" as const,
    };
    const status = recordsStatus({
      overview: recordOverview({
        keys: [key],
        last_sync_ms: 1700000000000,
        last_error: "Relay unavailable",
      }),
    });
    stubBackend(async () => status);
    const incoming = await api.fetchRecordsStatus();
    const client = new QueryClient();
    client.setQueryData(api.recordsStatusKey, recordsStatus());
    api.applyRecordOverview(client, incoming.overview!);
    expect(client.getQueryData(api.recordsStatusKey)).toEqual(status);
    const unknown = { ...incoming.overview!, keys: [{ ...key, synced: null }] };
    api.applyRecordOverview(client, unknown);
    expect(
      client.getQueryData<api.RecordsStatus>(api.recordsStatusKey)?.overview
        ?.keys[0].synced,
    ).toBeNull();
  });
  it("keeps rejected host input and revision objects unchanged", async () => {
    stubBackend(async () => {
      throw "revision conflict";
    });
    const payload = hostPayload();
    const before = structuredClone(payload);
    const revision = hostView().revision;
    await expect(
      api.updateRecordHost("0000000000000001", revision, payload),
    ).rejects.toBe("revision conflict");
    expect(payload).toEqual(before);
    expect(revision.version).toBe("9007199254740993");
  });
});
