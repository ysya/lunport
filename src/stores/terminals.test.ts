import { beforeEach, describe, expect, it } from "vitest";
import { useTerminalStore } from "./terminals";
const input = { host: { id: "saved-host" }, name: "web", address: "deploy@web:22", historyKey: "records:saved-host" };
beforeEach(() => useTerminalStore.getState().reset());
describe("terminal workspace", () => {
  it("retains independent session tabs while Library is selected", () => {
    const store = useTerminalStore.getState();
    const first = store.open(input); const second = store.open(input);
    expect(first).not.toBe(second);
    expect(useTerminalStore.getState().tabs.map((tab) => tab.name)).toEqual(["web", "web (2)"]);
    store.updateState(first, "open"); store.activate(null);
    expect(useTerminalStore.getState().tabs.map((tab) => tab.state)).toEqual(["open", "connecting"]);
    store.activate(first); expect(useTerminalStore.getState().activeId).toBe(first);
  });
  it("closes only the requested tab and picks an adjacent surviving session", () => {
    const store = useTerminalStore.getState();
    const first = store.open(input); const second = store.open(input); const third = store.open(input);
    store.close(second); expect(useTerminalStore.getState().activeId).toBe(third);
    store.close(third); expect(useTerminalStore.getState().activeId).toBe(first);
    store.close(first); expect(useTerminalStore.getState().activeId).toBeNull();
    expect(useTerminalStore.getState().tabs).toEqual([]);
  });
  it("enforces the session budget synchronously, even for rapid open calls", () => {
    const store = useTerminalStore.getState();
    for (let index = 0; index < 8; index++) store.open(input);
    expect(() => store.open(input)).toThrow("maximum 8");
    expect(useTerminalStore.getState().tabs).toHaveLength(8);
  });
  it("does not reactivate a closed tab or restore sessions after reset", () => {
    const store = useTerminalStore.getState(); const id = store.open(input);
    store.close(id); store.activate(id); store.updateState(id, "open");
    expect(useTerminalStore.getState().tabs).toEqual([]);
    expect(useTerminalStore.getState().activeId).toBeNull();
    store.open({ ...input, host: { alias: "legacy-web" } }); store.reset();
    expect(useTerminalStore.getState().tabs).toEqual([]);
  });
});
