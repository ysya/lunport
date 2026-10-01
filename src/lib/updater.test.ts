import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";

import { useSettingsStore } from "@/stores/settings";
import { checkForUpdates } from "./updater";

/**
 * The real settings store and the real sonner, with only the edges stubbed:
 * the backend (every `tauriInvoke` ends in `window.__TAURI_INTERNALS__.invoke`)
 * and `requestAnimationFrame`, which sonner's `toast.dismiss(id)` calls and Node
 * lacks. `toast.getToasts()` lists what is on screen; dismissed ids drop out at once.
 */
function stubBackend(invoke: (cmd: string) => Promise<unknown>) {
  vi.stubGlobal("window", { __TAURI_INTERNALS__: { invoke } });
}

/** Versions of the "Update available" prompts currently on screen. */
function promptedVersions(): string[] {
  const prefix = "Update available: v";
  return toast
    .getToasts()
    .flatMap((t) =>
      "title" in t && typeof t.title === "string" && t.title.startsWith(prefix)
        ? [t.title.slice(prefix.length)]
        : [],
    );
}

/** What `updater_check_beta` answers when a beta is available. */
const BETA_FOUND = { version: "0.16.1-1", body: null };

describe("update prompts follow the selected channel", () => {
  beforeEach(() => {
    vi.stubGlobal("requestAnimationFrame", (callback: () => void) => {
      callback();
      return 0;
    });
    useSettingsStore.setState(useSettingsStore.getInitialState(), true);
  });

  afterEach(() => {
    for (const t of toast.getToasts()) toast.dismiss(t.id);
    vi.unstubAllGlobals();
  });

  it("drops a Beta result that arrives after the user switched back to Stable", async () => {
    let deliver!: (answer: unknown) => void;
    stubBackend(() => new Promise((resolve) => (deliver = resolve)));
    useSettingsStore.setState({ updateChannel: "beta" });

    const inFlight = checkForUpdates({ silent: false });
    useSettingsStore.setState({ updateChannel: "stable" });
    deliver(BETA_FOUND);
    await inFlight;

    expect(promptedVersions()).toEqual([]);
  });

  it("shows nothing when a manual check loses the race, not even 'up to date'", async () => {
    let deliver!: (answer: unknown) => void;
    stubBackend(() => new Promise((resolve) => (deliver = resolve)));

    const inFlight = checkForUpdates({ silent: false }); // Stable: the default channel
    useSettingsStore.setState({ updateChannel: "beta" });
    deliver(null); // the plugin's "no update" answer
    await inFlight;

    expect(toast.getToasts()).toEqual([]);
  });

  it("retires the visible prompt when the channel changes", async () => {
    stubBackend(async () => BETA_FOUND);
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });
    expect(promptedVersions()).toEqual(["0.16.1-1"]);

    useSettingsStore.setState({ updateChannel: "stable" });

    expect(promptedVersions()).toEqual([]);
  });

  it("keeps the prompt when an unrelated setting changes", async () => {
    stubBackend(async () => BETA_FOUND);
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });

    useSettingsStore.setState({ fontSize: 16 });

    expect(promptedVersions()).toEqual(["0.16.1-1"]);
  });
});
