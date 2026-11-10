import { afterEach, describe, expect, it, vi } from "vitest";

import { LEGACY_SETTINGS_KEY, LEGACY_THEME_KEY, LEGACY_UI_KEY, migrateLegacyStorage } from "./legacy-identity";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.resetModules();
});

/** A `Storage` that lives in memory, standing in for the WebView's localStorage. */
function memoryStorage(saved: Record<string, string> = {}): Storage {
  const items = new Map(Object.entries(saved));
  return {
    get length() {
      return items.size;
    },
    clear: () => items.clear(),
    getItem: (key) => items.get(key) ?? null,
    key: (index) => [...items.keys()][index] ?? null,
    removeItem: (key) => void items.delete(key),
    setItem: (key, value) => void items.set(key, value),
  };
}

/** Every key the storage holds, with its value. */
function contents(storage: Storage): Record<string, string | null> {
  const keys = Array.from({ length: storage.length }, (_, index) => storage.key(index)!);
  return Object.fromEntries(keys.map((key) => [key, storage.getItem(key)]));
}

/** Preferences as a Beta-channel user's last build saved them. */
const betaSettings = JSON.stringify({
  state: {
    theme: "dark",
    fontSize: 16,
    updateChannel: "beta",
    trayVisible: false,
    closeToTray: true,
    globalHotkey: true,
    recentConnections: { "web-1": 1_700_000_000_000 },
  },
  version: 1,
});

/** Sidebar state as the last build saved it. */
const sidebar = JSON.stringify({
  state: { librarySidebarCollapsed: true, collapsedRecordGroups: ["acme-prod"], hostPreviewWidth: 480 },
  version: 0,
});

describe("migrateLegacyStorage", () => {
  it("moves settings and ui state and removes the old keys", () => {
    const storage = memoryStorage({ [LEGACY_SETTINGS_KEY]: betaSettings, [LEGACY_UI_KEY]: sidebar });

    const { moved } = migrateLegacyStorage(storage);

    expect(moved).toEqual([LEGACY_SETTINGS_KEY, LEGACY_UI_KEY]);
    // The values travel untouched, and nothing but the two new keys is left behind.
    expect(contents(storage)).toEqual({ "lunport-settings": betaSettings, "lunport-ui": sidebar });
  });

  it("keeps the beta update channel", () => {
    const storage = memoryStorage({ [LEGACY_SETTINGS_KEY]: betaSettings });

    migrateLegacyStorage(storage);

    const { state } = JSON.parse(storage.getItem("lunport-settings")!);
    expect(state).toMatchObject({ updateChannel: "beta", trayVisible: false, closeToTray: true, globalHotkey: true });
  });

  it("seeds theme from the legacy theme key once", () => {
    const storage = memoryStorage({ [LEGACY_THEME_KEY]: "dark" });

    expect(migrateLegacyStorage(storage).moved).toEqual([LEGACY_THEME_KEY]);
    // Version 0: the schema of the time the theme was kept on its own, so every settings migration still applies to it.
    expect(contents(storage)).toEqual({ "lunport-settings": JSON.stringify({ state: { theme: "dark" }, version: 0 }) });

    // A choice made since then is never overwritten by the seed on a later launch.
    storage.setItem("lunport-settings", JSON.stringify({ state: { theme: "light" }, version: 1 }));
    expect(migrateLegacyStorage(storage).moved).toEqual([]);
    expect(JSON.parse(storage.getItem("lunport-settings")!).state.theme).toBe("light");
  });

  it("does nothing when the new keys already exist", () => {
    const current = JSON.stringify({ state: { updateChannel: "stable" }, version: 1 });
    const storage = memoryStorage({
      "lunport-settings": current,
      "lunport-ui": sidebar,
      [LEGACY_SETTINGS_KEY]: betaSettings,
      [LEGACY_UI_KEY]: "{}",
      [LEGACY_THEME_KEY]: "light",
    });
    const before = contents(storage);

    expect(migrateLegacyStorage(storage).moved).toEqual([]);
    expect(contents(storage)).toEqual(before);
  });

  it("carries over only what has no new key yet", () => {
    const current = JSON.stringify({ state: { updateChannel: "stable" }, version: 1 });
    const storage = memoryStorage({ "lunport-settings": current, [LEGACY_SETTINGS_KEY]: betaSettings, [LEGACY_UI_KEY]: sidebar });

    expect(migrateLegacyStorage(storage).moved).toEqual([LEGACY_UI_KEY]);
    expect(contents(storage)).toEqual({ "lunport-settings": current, "lunport-ui": sidebar, [LEGACY_SETTINGS_KEY]: betaSettings });
  });

  it("lets the saved settings replace the legacy theme key, which they were built on", () => {
    const storage = memoryStorage({ [LEGACY_SETTINGS_KEY]: betaSettings, [LEGACY_THEME_KEY]: "light" });

    expect(migrateLegacyStorage(storage).moved).toEqual([LEGACY_SETTINGS_KEY]);
    expect(contents(storage)).toEqual({ "lunport-settings": betaSettings });
  });

  it("leaves a legacy theme that is not an explicit light or dark choice alone", () => {
    const storage = memoryStorage({ [LEGACY_THEME_KEY]: "solarized" });

    expect(migrateLegacyStorage(storage).moved).toEqual([]);
    expect(contents(storage)).toEqual({ [LEGACY_THEME_KEY]: "solarized" });
  });

  it("finds nothing to do on a fresh install or a second run", () => {
    const fresh = memoryStorage();
    expect(migrateLegacyStorage(fresh).moved).toEqual([]);
    expect(contents(fresh)).toEqual({});

    const storage = memoryStorage({ [LEGACY_SETTINGS_KEY]: betaSettings, [LEGACY_UI_KEY]: sidebar });
    migrateLegacyStorage(storage);
    const after = contents(storage);
    expect(migrateLegacyStorage(storage).moved).toEqual([]);
    expect(contents(storage)).toEqual(after);
  });

  describe("when storage misbehaves", () => {
    const quiet = () => vi.spyOn(console, "warn").mockImplementation(() => {});

    it("keeps the old keys when the new key cannot be written", () => {
      const warn = quiet();
      const storage = memoryStorage({ [LEGACY_SETTINGS_KEY]: betaSettings, [LEGACY_UI_KEY]: sidebar });
      storage.setItem = () => {
        throw new Error("the storage is full");
      };

      expect(migrateLegacyStorage(storage).moved).toEqual([]);
      expect(contents(storage)).toEqual({ [LEGACY_SETTINGS_KEY]: betaSettings, [LEGACY_UI_KEY]: sidebar });
      expect(warn).toHaveBeenCalledTimes(2);
    });

    it("keeps the old key when the new value does not read back", () => {
      const warn = quiet();
      const storage = memoryStorage({ [LEGACY_SETTINGS_KEY]: betaSettings });
      storage.setItem = () => {};

      expect(migrateLegacyStorage(storage).moved).toEqual([]);
      expect(contents(storage)).toEqual({ [LEGACY_SETTINGS_KEY]: betaSettings });
      expect(warn).toHaveBeenCalledTimes(1);
    });

    it("still carries the sidebar over when the settings cannot be moved", () => {
      quiet();
      const storage = memoryStorage({ [LEGACY_SETTINGS_KEY]: betaSettings, [LEGACY_UI_KEY]: sidebar });
      const write = storage.setItem.bind(storage);
      storage.setItem = (key, value) => {
        if (key === "lunport-settings") throw new Error("the storage is full");
        write(key, value);
      };

      expect(migrateLegacyStorage(storage).moved).toEqual([LEGACY_UI_KEY]);
      expect(contents(storage)).toEqual({ [LEGACY_SETTINGS_KEY]: betaSettings, "lunport-ui": sidebar });
    });

    it("never throws when the storage cannot be read", () => {
      const storage = memoryStorage();
      storage.getItem = () => {
        throw new Error("access to the storage is denied");
      };

      expect(migrateLegacyStorage(storage)).toEqual({ moved: [] });
    });
  });
});

describe("when the app starts", () => {
  /** The page as the WebView loads it: localStorage holds `saved`, and the stores are imported fresh, as a launch does. */
  async function launch(saved: Record<string, string>) {
    const storage = memoryStorage(saved);
    vi.stubGlobal("window", { localStorage: storage });
    vi.resetModules();
    const { useSettingsStore } = await import("@/stores/settings");
    const { useUiStore } = await import("@/stores/ui");
    return { storage, settings: useSettingsStore, ui: useUiStore };
  }

  it("hands a Beta user's update channel, tray and hotkey settings to the settings store", async () => {
    const { settings, ui, storage } = await launch({ [LEGACY_SETTINGS_KEY]: betaSettings, [LEGACY_UI_KEY]: sidebar });

    expect(settings.getState()).toMatchObject({
      updateChannel: "beta",
      trayVisible: false,
      closeToTray: true,
      globalHotkey: true,
      theme: "dark",
      fontSize: 16,
      recentConnections: { "web-1": 1_700_000_000_000 },
    });
    expect(ui.getState()).toMatchObject({ librarySidebarCollapsed: true, collapsedRecordGroups: ["acme-prod"], hostPreviewWidth: 480 });
    expect(storage.getItem(LEGACY_SETTINGS_KEY)).toBeNull();
    expect(storage.getItem(LEGACY_UI_KEY)).toBeNull();
  });

  it("starts the settings store from the legacy theme key when nothing else was saved", async () => {
    const { settings, storage } = await launch({ [LEGACY_THEME_KEY]: "light" });

    expect(settings.getState()).toMatchObject({ theme: "light", terminalId: "lunport", updateChannel: "stable" });
    expect(storage.getItem(LEGACY_THEME_KEY)).toBeNull();
  });

  it("writes nothing on a fresh install", async () => {
    const { settings, storage } = await launch({});

    expect(settings.getState()).toMatchObject({ theme: "system", updateChannel: "stable" });
    expect(contents(storage)).toEqual({});
  });

  it("starts with the defaults where the browser blocks localStorage", async () => {
    vi.stubGlobal("window", {
      get localStorage(): Storage {
        throw new Error("access to the storage is denied");
      },
    });
    vi.resetModules();

    const { useSettingsStore } = await import("@/stores/settings");
    const { useUiStore } = await import("@/stores/ui");

    expect(useSettingsStore.getState()).toMatchObject({ theme: "system", updateChannel: "stable" });
    expect(useUiStore.getState()).toMatchObject({ librarySidebarCollapsed: false, hostPreviewWidth: 400 });
  });
});
