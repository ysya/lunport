import { afterEach, describe, expect, it, vi } from "vitest";

import { useUiStore } from "./ui";

afterEach(() => {
  useUiStore.setState({ selectedAlias: null, selectedFile: null, sidebarView: "hosts" });
});

describe("the host selection", () => {
  it("remembers the file of the row that was clicked, so the copies of one alias can be told apart", () => {
    useUiStore.getState().selectHost("web", "/home/f/.ssh/sshelter/work-8b01e4aa.config");
    expect(useUiStore.getState()).toEqual(
      expect.objectContaining({ selectedAlias: "web", selectedFile: "/home/f/.ssh/sshelter/work-8b01e4aa.config" }),
    );
  });

  it("forgets the file when an alias is selected from somewhere that has none: no copy is picked for the user", () => {
    useUiStore.getState().selectHost("web", "/home/f/.ssh/config");
    useUiStore.getState().setSelectedAlias("db");
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ selectedAlias: "db", selectedFile: null }));
    useUiStore.getState().selectHost("web", "/home/f/.ssh/config");
    useUiStore.getState().setSelectedAlias(null);
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ selectedAlias: null, selectedFile: null }));
  });

  // The main pane shows a key's detail while the sidebar shows the Keychain, so a host selected from anywhere (the palette, a lint
  // issue, a host just added, a key's detail) must bring the host list back, or the selection would not show.
  it("shows Hosts when a host is selected by its alias", () => {
    useUiStore.setState({ sidebarView: "keychain" });
    useUiStore.getState().setSelectedAlias("web");
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ selectedAlias: "web", sidebarView: "hosts" }));
  });

  it("shows Hosts when a host row is selected", () => {
    useUiStore.setState({ sidebarView: "keychain" });
    useUiStore.getState().selectHost("web", "/home/f/.ssh/config");
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ selectedAlias: "web", selectedFile: "/home/f/.ssh/config", sidebarView: "hosts" }));
  });

  it("keeps the sidebar's view when the selection is cleared", () => {
    useUiStore.setState({ sidebarView: "keychain", selectedAlias: "web" });
    useUiStore.getState().setSelectedAlias(null);
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ selectedAlias: null, sidebarView: "keychain" }));
  });
});

describe("the Keychain", () => {
  afterEach(() => {
    useUiStore.setState({ sidebarView: "hosts", keychainSelection: null, launchHintDismissed: false, moveFailures: [] });
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("opens on the key it was asked for, and keeps the selection when it is opened without one", () => {
    const slot = { kind: "slot" as const, id: "a".repeat(32) };
    useUiStore.getState().openKeychain(slot);
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ sidebarView: "keychain", keychainSelection: slot }));
    useUiStore.getState().setSidebarView("hosts");
    useUiStore.getState().openKeychain();
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ sidebarView: "keychain", keychainSelection: slot }));
  });

  it("remembers the sidebar's view and a dismissed launch hint across restarts, and not the selection or the Move results", async () => {
    // zustand's persist reads `window.localStorage` and, without one (node), sets up no `persist` at all: use a fresh store over an
    // in-memory one, as lib/sidebar-width.test.ts does.
    vi.stubGlobal("window", { localStorage: { getItem: () => null, setItem: () => undefined, removeItem: () => undefined } });
    vi.resetModules();
    const { useUiStore: store } = await import("./ui");
    store.getState().openKeychain({ kind: "file", path: "/home/f/.ssh/id_ed25519" });
    store.getState().dismissLaunchHint();
    store.getState().setMoveFailures([{ slot_id: "s", name: "id_work", message: "gone" }]);
    const saved = store.persist.getOptions().partialize?.(store.getState()) as Record<string, unknown>;
    expect(saved).toEqual(expect.objectContaining({ sidebarView: "keychain", launchHintDismissed: true }));
    expect(saved).not.toHaveProperty("keychainSelection");
    expect(saved).not.toHaveProperty("moveFailures");
  });
});
