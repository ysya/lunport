import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import { useTerminalStore } from "@/stores/terminals";
import { useSettingsStore } from "@/stores/settings";
import { IN_APP_TERMINAL } from "@/lib/settings-logic";
import { connectSavedHost } from "./operations";
import { hostView, recordOverview } from "./fixtures";
afterEach(() => { useTerminalStore.getState().reset(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
describe("saved-host terminal destination", () => {
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
