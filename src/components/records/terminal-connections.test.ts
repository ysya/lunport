import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import { useTerminalStore } from "@/stores/terminals";
import { useSettingsStore } from "@/stores/settings";
import { IN_APP_TERMINAL } from "@/lib/settings-logic";
import { connectSavedHost } from "./operations";
import { hostView, recordOverview } from "./fixtures";
afterEach(() => { useTerminalStore.getState().reset(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
describe("saved-host terminal destination", () => {
  it("docks a host beside the active database and reuses its live shell even with an external preference", async () => {
    const backend = vi.fn(); stubBackend(backend);
    const host = hostView();
    const overview = recordOverview({ hosts: [host] });
    const databaseId = useTerminalStore.getState().open({ kind: "database", databaseId: "db-1", name: "orders", address: "orders-pg", environment: "prod", readOnly: "locked" });

    await connectSavedHost(overview, host.id, "external", true, undefined, "dock");
    const sshId = useTerminalStore.getState().dockedId;
    expect(sshId).toEqual(expect.any(String));
    expect(useTerminalStore.getState()).toMatchObject({ activeId: databaseId });
    useTerminalStore.getState().hideDock();
    await connectSavedHost(overview, host.id, "external", true, undefined, "dock");
    expect(useTerminalStore.getState()).toMatchObject({ activeId: databaseId, dockedId: sshId });
    expect(useTerminalStore.getState().tabs).toHaveLength(2);
    expect(backend).not.toHaveBeenCalled();
  });
  it("opens a tmux workspace in the app even when an external terminal is selected", async () => {
    const backend = vi.fn(); stubBackend(backend);
    const host = hostView();
    await connectSavedHost(recordOverview({ hosts: [host] }), host.id, "external", true, {});
    expect(backend).not.toHaveBeenCalled();
    expect(useTerminalStore.getState().tabs).toEqual([expect.objectContaining({ host: { id: host.id }, mode: "tmux", state: "connecting" })]);
  });
  it("opens a stable-ID app session without launching an external terminal or recording premature success", async () => {
    const backend = vi.fn(); stubBackend(backend);
    const host = hostView();
    const recent = useSettingsStore.getState().recentConnections;
    await connectSavedHost(recordOverview({ hosts: [host] }), host.id, IN_APP_TERMINAL, false);
    expect(backend).not.toHaveBeenCalled();
    expect(useSettingsStore.getState().recentConnections).toBe(recent);
    expect(useTerminalStore.getState().tabs).toEqual([expect.objectContaining({ host: { id: host.id }, name: host.effective_payload.alias, historyKey: `records:${host.id}`, state: "connecting" })]);
  });
  it("keeps readiness and ambiguous-ID checks in front of the app terminal", async () => {
    const host = hostView(); host.readiness = { kind: "needs_key" };
    await expect(connectSavedHost(recordOverview({ hosts: [host] }), host.id, IN_APP_TERMINAL, false)).rejects.toThrow("Resolve");
    host.readiness = { kind: "ready" };
    await expect(connectSavedHost(recordOverview({ hosts: [host, structuredClone(host)] }), host.id, IN_APP_TERMINAL, false)).rejects.toThrow("ambiguous");
    expect(useTerminalStore.getState().tabs).toEqual([]);
  });
});
