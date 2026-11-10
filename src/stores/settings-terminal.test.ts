import { afterEach, describe, expect, it, vi } from "vitest";

import { LEGACY_THEME_KEY } from "@/lib/legacy-identity";

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules(); });

/** Persisted preferences as an older build wrote them (`version` 0), beside the standalone keys that came before the settings store. */
function storage(state: Record<string, unknown> | null, standalone: Record<string, string> = {}) {
  let saved = state === null ? null : JSON.stringify({ state, version: 0 });
  vi.stubGlobal("window", { localStorage: {
    getItem: (key: string) => (key === "lunport-settings" ? saved : standalone[key] ?? null),
    setItem: (_key: string, value: string) => { saved = value; },
    removeItem: () => {},
  } });
  vi.resetModules();
}

describe("the preferred terminal", () => {
  it("is Lunport's own terminal for everyone, once, even where an external terminal was chosen before", async () => {
    storage({ terminalId: "iterm2", theme: "dark", newTabConnect: true });
    const { useSettingsStore } = await import("./settings");
    expect(useSettingsStore.getState()).toMatchObject({ terminalId: "lunport", theme: "dark", newTabConnect: true });
  });

  it("keeps an external terminal chosen after that across reloads", async () => {
    storage({ terminalId: "iterm2" });
    const { useSettingsStore: first } = await import("./settings");
    expect(first.getState().terminalId).toBe("lunport");
    first.getState().setTerminalId("iterm2");
    vi.resetModules();
    const { useSettingsStore: restored } = await import("./settings");
    expect(restored.getState().terminalId).toBe("iterm2");
  });

  it("starts from the standalone theme of builds before the settings store, in Lunport's own terminal", async () => {
    storage(null, { [LEGACY_THEME_KEY]: "dark" });
    const { useSettingsStore } = await import("./settings");
    expect(useSettingsStore.getState()).toMatchObject({ terminalId: "lunport", theme: "dark" });
  });
});
