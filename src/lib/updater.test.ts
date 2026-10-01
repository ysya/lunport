import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";

import type { UpdateChannel } from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";
import { checkForUpdates } from "./updater";

/**
 * The real settings store, the real sonner and the real updater/process plugins, with only the
 * edges stubbed: the backend and `requestAnimationFrame`, which sonner's `toast.dismiss(id)` calls
 * and Node lacks. `toast.getToasts()` lists what is on screen; dismissed ids drop out at once.
 *
 * Every command, whether `tauriInvoke` sends it or a plugin does (`check()`, `downloadAndInstall()`,
 * `relaunch()`), ends in `window.__TAURI_INTERNALS__.invoke`: that one function is the backend. It
 * logs each command name, in order, and answers from `answers` laid over DEFAULT_ANSWERS (a
 * function answers lazily, so a test can hold a reply back). A command nobody listed rejects.
 */
const DEFAULT_ANSWERS: Record<string, unknown> = {
  "plugin:updater|check": null,
  "plugin:updater|download_and_install": undefined,
  "plugin:process|restart": undefined,
  updater_check_beta: null,
  updater_install_beta: undefined,
};

function stubBackend(answers: Record<string, unknown> = {}): string[] {
  const replies = { ...DEFAULT_ANSWERS, ...answers };
  const calls: string[] = [];
  vi.stubGlobal("window", {
    __TAURI_INTERNALS__: {
      invoke: async (cmd: string) => {
        calls.push(cmd);
        if (!(cmd in replies)) throw new Error(`unexpected command: ${cmd}`);
        const reply = replies[cmd];
        return typeof reply === "function" ? reply() : reply;
      },
      // The plugin's `downloadAndInstall()` opens a `Channel`, which registers its callback here.
      transformCallback: () => 1,
    },
  });
  return calls;
}

const PROMPT_TITLE = "Update available: v";

/** Versions of the "Update available" prompts currently on screen. */
function promptedVersions(): string[] {
  return toast
    .getToasts()
    .flatMap((t) =>
      "title" in t && typeof t.title === "string" && t.title.startsWith(PROMPT_TITLE)
        ? [t.title.slice(PROMPT_TITLE.length)]
        : [],
    );
}

/** Press the on-screen prompt's "Install & restart" button, as the Toaster would. */
function pressInstall(): void {
  const prompt = toast
    .getToasts()
    .find((t) => "title" in t && typeof t.title === "string" && t.title.startsWith(PROMPT_TITLE));
  const action = prompt && "action" in prompt ? prompt.action : undefined;
  if (!action || typeof action !== "object" || !("onClick" in action)) {
    throw new Error("no update prompt with an install button is on screen");
  }
  action.onClick(undefined as never); // the handler ignores the click event
}

/** What `updater_check_beta` answers when a beta is available. */
const BETA_FOUND = { version: "0.16.1-1", body: null };

/** What `plugin:updater|check` answers when a stable update is available (the plugin wraps it in an `Update`). */
const STABLE_FOUND = {
  rid: 7,
  currentVersion: "0.16.0",
  version: "0.16.1",
  date: "2026-10-01T00:00:00Z",
  body: "Bug fixes",
  rawJson: {},
};

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

describe("each channel talks only to its own backend", () => {
  it("defaults to Stable, so existing installs keep the pre-channel path until they opt in", () => {
    expect(useSettingsStore.getInitialState().updateChannel).toBe("stable");
  });

  it("Stable checks and installs through the updater plugin and never reaches the Beta commands", async () => {
    const calls = stubBackend({ "plugin:updater|check": STABLE_FOUND });

    await checkForUpdates({ silent: false }); // default settings: the channel was never chosen
    expect(calls).toEqual(["plugin:updater|check"]);
    expect(promptedVersions()).toEqual(["0.16.1"]);

    pressInstall();
    await vi.waitFor(() => expect(calls).toContain("plugin:process|restart"));

    expect(calls.filter((cmd) => cmd.startsWith("updater_"))).toEqual([]); // the Beta commands
    expect(calls).toEqual(["plugin:updater|check", "plugin:updater|download_and_install", "plugin:process|restart"]);
  });

  it("Beta checks and installs through the backend commands and never reaches the updater plugin", async () => {
    const calls = stubBackend({ updater_check_beta: BETA_FOUND });
    useSettingsStore.setState({ updateChannel: "beta" });

    await checkForUpdates({ silent: false });
    expect(calls).toEqual(["updater_check_beta"]);
    expect(promptedVersions()).toEqual(["0.16.1-1"]);

    pressInstall();
    await vi.waitFor(() => expect(calls).toContain("plugin:process|restart"));

    expect(calls.filter((cmd) => cmd.startsWith("plugin:updater|"))).toEqual([]);
    expect(calls).toEqual(["updater_check_beta", "updater_install_beta", "plugin:process|restart"]);
  });
});

describe("update prompts follow the selected channel", () => {
  it("drops a Beta result that arrives after the user switched back to Stable", async () => {
    let deliver!: (answer: unknown) => void;
    stubBackend({ updater_check_beta: () => new Promise((resolve) => (deliver = resolve)) });
    useSettingsStore.setState({ updateChannel: "beta" });

    const inFlight = checkForUpdates({ silent: false });
    useSettingsStore.setState({ updateChannel: "stable" });
    deliver(BETA_FOUND);
    await inFlight;

    expect(promptedVersions()).toEqual([]);
  });

  it("shows nothing when a manual check loses the race, not even 'up to date'", async () => {
    let deliver!: (answer: unknown) => void;
    stubBackend({ "plugin:updater|check": () => new Promise((resolve) => (deliver = resolve)) });

    const inFlight = checkForUpdates({ silent: false }); // Stable: the default channel
    useSettingsStore.setState({ updateChannel: "beta" });
    deliver(null); // the plugin's "no update" answer
    await inFlight;

    expect(toast.getToasts()).toEqual([]);
  });

  it("retires the visible prompt when the channel changes", async () => {
    stubBackend({ updater_check_beta: BETA_FOUND });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });
    expect(promptedVersions()).toEqual(["0.16.1-1"]);

    useSettingsStore.setState({ updateChannel: "stable" });

    expect(promptedVersions()).toEqual([]);
  });

  it("keeps the prompt when an unrelated setting changes", async () => {
    stubBackend({ updater_check_beta: BETA_FOUND });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });

    useSettingsStore.setState({ fontSize: 16 });

    expect(promptedVersions()).toEqual(["0.16.1-1"]);
  });

  // A settings import or a newer build can leave any string here, and only "beta" means Beta, so
  // moving between "stable" and such a value is not a channel change.
  it.each([
    ["stable", "nightly"],
    ["nightly", "stable"],
  ])("keeps the prompt when the channel goes from %s to %s, both of which mean Stable", async (from, to) => {
    stubBackend({ "plugin:updater|check": STABLE_FOUND });
    useSettingsStore.setState({ updateChannel: from as UpdateChannel });
    await checkForUpdates({ silent: false });
    expect(promptedVersions()).toEqual(["0.16.1"]);

    useSettingsStore.setState({ updateChannel: to as UpdateChannel });

    expect(promptedVersions()).toEqual(["0.16.1"]);
  });
});
