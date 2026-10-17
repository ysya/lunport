import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules(); });

function storage(state: Record<string, unknown>) {
  let saved = JSON.stringify({ state, version: 0 });
  vi.stubGlobal("window", { localStorage: {
    getItem: (key: string) => key === "sshelter-settings" ? saved : null,
    setItem: (_key: string, value: string) => { saved = value; },
    removeItem: () => {},
  } });
  vi.resetModules();
}

describe("appearance preferences", () => {
  it("keeps an older user's light/dark choice and starts with the original palette", async () => {
    storage({ theme: "dark", fontSize: 17 });
    const { useSettingsStore } = await import("./settings");
    expect(useSettingsStore.getState()).toMatchObject({ theme: "dark", fontSize: 17, colorTheme: "lunport" });
  });

  it("remembers the palette across reloads independently of light/dark/system mode", async () => {
    storage({ theme: "system" });
    const { useSettingsStore: first } = await import("./settings");
    first.getState().setColorTheme("catppuccin");
    expect(first.getState().theme).toBe("system");
    first.getState().setTheme("light");
    vi.resetModules();
    const { useSettingsStore: restored } = await import("./settings");
    expect(restored.getState()).toMatchObject({ theme: "light", colorTheme: "catppuccin" });
    restored.getState().toggleTheme();
    expect(restored.getState()).toMatchObject({ theme: "dark", colorTheme: "catppuccin" });
  });
});
