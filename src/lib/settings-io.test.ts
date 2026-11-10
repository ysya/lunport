import { afterEach, describe, expect, it, vi } from "vitest";

import { SETTINGS_VERSION } from "@/stores/settings";

import { parseSettingsEnvelope } from "./settings-io";

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules(); });

describe("parseSettingsEnvelope", () => {
  it("accepts a persist envelope with state and version", () => {
    const env = parseSettingsEnvelope(
      JSON.stringify({ state: { theme: "dark", fontSize: 15 }, version: 0 }),
    );
    expect(env.state).toEqual({ theme: "dark", fontSize: 15 });
    expect(env.version).toBe(0);
  });

  it("accepts a missing version (treated as current)", () => {
    const env = parseSettingsEnvelope(JSON.stringify({ state: {} }));
    expect(env.version).toBeUndefined();
  });

  it("rejects non-JSON input", () => {
    expect(() => parseSettingsEnvelope("Host web\n  HostName example.com")).toThrow(
      /not valid JSON/,
    );
  });

  it("rejects JSON that is not an object envelope", () => {
    expect(() => parseSettingsEnvelope("[1,2,3]")).toThrow(/not a Lunport settings export/);
    expect(() => parseSettingsEnvelope('"hello"')).toThrow(/not a Lunport settings export/);
    expect(() => parseSettingsEnvelope("null")).toThrow(/not a Lunport settings export/);
  });

  it("rejects envelopes without a state object", () => {
    expect(() => parseSettingsEnvelope("{}")).toThrow(/missing settings data/);
    expect(() => parseSettingsEnvelope('{"state": "dark"}')).toThrow(/missing settings data/);
    expect(() => parseSettingsEnvelope('{"state": [1]}')).toThrow(/missing settings data/);
  });

  it("rejects envelopes from a newer settings schema", () => {
    expect(() =>
      parseSettingsEnvelope(JSON.stringify({ state: {}, version: SETTINGS_VERSION + 1 })),
    ).toThrow(/newer Lunport/);
  });

  it("rejects a non-numeric version", () => {
    expect(() => parseSettingsEnvelope('{"state": {}, "version": "two"}')).toThrow(
      /invalid settings version/,
    );
  });
});

/**
 * A window where localStorage keeps what the settings store persists, and the backend's native save and open dialogs write one
 * settings file and read it back. The returned function reads that file as the last export wrote it.
 */
function stubWindow(): () => string | null {
  const stored = new Map<string, string>();
  let file: string | null = null;
  vi.stubGlobal("window", {
    localStorage: {
      getItem: (key: string) => stored.get(key) ?? null,
      setItem: (key: string, value: string) => { stored.set(key, value); },
      removeItem: (key: string) => { stored.delete(key); },
    },
    __TAURI_INTERNALS__: {
      invoke: async (cmd: string, args: { json?: string }) => {
        if (cmd === "settings_export") {
          file = args.json ?? null;
          return "lunport-settings.json";
        }
        if (cmd === "settings_import") return file;
        return undefined; // the tray preferences an import sends to the backend again
      },
    },
  });
  vi.resetModules();
  return () => file;
}

describe("a settings export", () => {
  it("imports back into the build that exported it, every preference as it was", async () => {
    stubWindow();
    const { useSettingsStore } = await import("@/stores/settings");
    const { applySettingsImport, exportSettings, pickSettingsImport } = await import("./settings-io");
    // Chosen after version 1 made Lunport's own terminal everyone's default, so an import keeps it instead of resetting it as it
    // does for a file from an older version.
    useSettingsStore.getState().setTerminalId("iterm2");
    useSettingsStore.getState().setFontSize(15);
    await exportSettings();
    useSettingsStore.getState().setFontSize(13);

    const envelope = await pickSettingsImport();
    await applySettingsImport(envelope!);

    expect(useSettingsStore.getState()).toMatchObject({ fontSize: 15, terminalId: "iterm2" });
  });

  it("of untouched preferences carries the store's version, as persist would write it", async () => {
    const exported = stubWindow();
    const { useSettingsStore } = await import("@/stores/settings");
    const { exportSettings } = await import("./settings-io");

    await exportSettings();

    expect(JSON.parse(exported()!).version).toBe(useSettingsStore.persist.getOptions().version);
  });
});
