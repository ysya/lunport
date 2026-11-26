import { beforeEach, describe, expect, it } from "vitest";
import { useTerminalStore } from "./terminals";
const input = { kind: "terminal" as const, host: { id: "saved-host" }, name: "web", address: "deploy@web:22", historyKey: "records:saved-host" };
const database = { kind: "database" as const, databaseId: "db-1", name: "orders", address: "orders-pg · acme-prod-123456", environment: "prod" as const, readOnly: "locked" as const };
beforeEach(() => useTerminalStore.getState().reset());
describe("terminal workspace", () => {
  it("resumes a matching open tmux tab even when every tab slot is in use", () => {
    const store = useTerminalStore.getState();
    const session = { id: "$1", name: "build", created: "1740000000", server: "427:1740000000", destroyUnattached: false };
    const openId = store.open({ ...input, mode: "tmux" });
    store.claimTmuxSession(openId, session);
    store.updateState(openId, "open");
    for (let index = 0; index < 7; index++) store.open(input);
    const resumed = store.open({ ...input, mode: "tmux", tmuxResume: { session: { ...session, name: "renamed" }, windowId: "@0", paneId: "%0" } });
    expect(resumed).toBe(openId);
    expect(useTerminalStore.getState().activeId).toBe(openId);
    expect(useTerminalStore.getState().tabs).toHaveLength(8);
  });

  it("activates the existing workspace for the same host and tmux session", () => {
    const store = useTerminalStore.getState();
    const first = store.open({ ...input, mode: "tmux" });
    const second = store.open({ ...input, mode: "tmux" });
    const session = { id: "$1", name: "build", created: "1740000000", server: "427:1740000000", destroyUnattached: false };
    expect(store.claimTmuxSession(first, session)).toBe(true);
    expect(store.claimTmuxSession(second, { ...session, name: "renamed" })).toBe(false);
    expect(useTerminalStore.getState().activeId).toBe(first);
    expect(useTerminalStore.getState().tabs).toHaveLength(1);

    const replacement = store.open({ ...input, mode: "tmux" });
    expect(store.claimTmuxSession(replacement, { ...session, server: "724:1740000000" })).toBe(true);
    expect(useTerminalStore.getState().tabs).toHaveLength(2);
  });
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
  it("a_database_tab_counts_toward_the_limit", () => {
    const store = useTerminalStore.getState();
    for (let index = 0; index < 7; index++) store.open(input);
    store.open(database);
    expect(() => store.open(input)).toThrow("Close a tab before opening another (maximum 8).");
    expect(useTerminalStore.getState().tabs).toHaveLength(8);
  });
  it("database_tabs_are_named_apart", () => {
    const store = useTerminalStore.getState();
    store.open(database); store.open(database);
    expect(useTerminalStore.getState().tabs.map((tab) => tab.name)).toEqual(["orders", "orders (2)"]);
  });
  it("changes the lock only on a database tab", () => {
    const store = useTerminalStore.getState();
    const db = store.open(database); const term = store.open(input);
    store.setReadOnly(db, "not_locked"); store.setReadOnly(term, "not_locked"); store.setReadOnly("missing", "not_locked");
    const [first, second] = useTerminalStore.getState().tabs;
    expect(first).toMatchObject({ kind: "database", readOnly: "not_locked" });
    expect(second).not.toHaveProperty("readOnly");
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
