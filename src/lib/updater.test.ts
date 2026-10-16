import type { Channel } from "@tauri-apps/api/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";
import { type DownloadEvent, STALL_AFTER_MS } from "@/lib/download-progress";
import type { UpdateChannel } from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";
import {
  PROGRESS_REFRESH_MS,
  checkForUpdates,
  installAvailableUpdate,
  restartAfterUpdate,
  useUpdaterState,
} from "./updater";

const DEFAULT_ANSWERS: Record<string, unknown> = {
  "plugin:updater|check": null,
  "plugin:updater|download_and_install": undefined,
  "plugin:process|restart": undefined,
  updater_check_beta: null,
  updater_install_beta: undefined,
  "plugin:resources|close": undefined,
};

function stubBackend(answers: Record<string, unknown> = {}): string[] {
  const replies = { ...DEFAULT_ANSWERS, ...answers };
  const calls: string[] = [];
  vi.stubGlobal("window", {
    __TAURI_INTERNALS__: {
      invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push(cmd);
        if (!(cmd in replies)) throw new Error(`unexpected command: ${cmd}`);
        const reply = replies[cmd];
        return typeof reply === "function" ? reply(args) : reply;
      },
      // The plugin's `downloadAndInstall()` opens a `Channel`, which registers its callback here.
      transformCallback: () => 1,
    },
  });
  return calls;
}

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

const pendingInstalls: (() => void)[] = [];

/** An install command that stays open until the test ends it, and hands over the channel its progress goes through. */
function heldInstall() {
  const held: {
    channel?: Channel<DownloadEvent>;
    finish: () => void;
    fail: (error: Error) => void;
  } = {
    finish: () => {},
    fail: () => {},
  };
  const reply = (args?: Record<string, unknown>) => {
    held.channel = args?.onEvent as Channel<DownloadEvent>;
    return new Promise<void>((resolve, reject) => {
      held.finish = resolve;
      held.fail = reject;
      pendingInstalls.push(resolve);
    });
  };
  const send = (event: DownloadEvent) => {
    if (!held.channel)
      throw new Error("the install command got no progress channel");
    held.channel.onmessage(event);
  };
  return { held, reply, send };
}

beforeEach(() => {
  stubBackend();
  useUpdaterState.setState(useUpdaterState.getInitialState(), true);
  useSettingsStore.setState({ updateChannel: "beta" });
  useSettingsStore.setState(useSettingsStore.getInitialState(), true);
  useUiStore.setState({ settingsOpen: false, settingsCategory: "general" });
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(async () => {
  for (const finish of pendingInstalls.splice(0)) finish();
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(toast.getToasts()).toEqual([]);
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
const state = () => useUpdaterState.getState();
const withoutCleanup = (calls: string[]) =>
  calls.filter((command) => command !== "plugin:resources|close");

describe("inline checks and channel isolation", () => {
  it("defaults to Stable and stores a manual up-to-date result without a notification", async () => {
    expect(useSettingsStore.getState().updateChannel).toBe("stable");
    await checkForUpdates({ silent: false });
    expect(state()).toMatchObject({
      phase: "current",
      channel: "stable",
      version: null,
    });
    expect(state().checkedAt).toEqual(expect.any(Number));
  });
  it.each([
    {
      channel: "stable",
      found: { "plugin:updater|check": STABLE_FOUND },
      commands: [
        "plugin:updater|check",
        "plugin:updater|download_and_install",
        "plugin:process|restart",
      ],
      version: "0.16.1",
    },
    {
      channel: "beta",
      found: { updater_check_beta: BETA_FOUND },
      commands: [
        "updater_check_beta",
        "updater_install_beta",
        "plugin:process|restart",
      ],
      version: "0.16.1-1",
    },
  ] as const)(
    "$channel uses only its own signed-update backend",
    async ({ channel, found, commands, version }) => {
      const calls = stubBackend(found);
      useSettingsStore.setState({ updateChannel: channel });
      await checkForUpdates({ silent: false });
      expect(state()).toMatchObject({ phase: "available", channel, version });
      await installAvailableUpdate();
      expect(withoutCleanup(calls)).toEqual(commands);
      expect(state().phase).toBe("restarting");
    },
  );
  it("an automatic discovery never opens Settings or a toast", async () => {
    stubBackend({ updater_check_beta: BETA_FOUND });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: true });
    await checkForUpdates({ silent: true });
    expect(state()).toMatchObject({
      phase: "available",
      version: BETA_FOUND.version,
    });
    expect(useUiStore.getState().settingsOpen).toBe(false);
  });
  it.each([false, true])(
    "keeps check failures inline (silent=%s)",
    async (silent) => {
      stubBackend({
        "plugin:updater|check": () => {
          throw new Error("offline");
        },
      });
      await checkForUpdates({ silent });
      expect(state()).toMatchObject({
        phase: "error",
        errorStage: "check",
        error: "offline",
      });
    },
  );
  it.each([BETA_FOUND, null])(
    "drops old-channel results, including up-to-date replies",
    async (reply) => {
      let deliver!: (answer: unknown) => void;
      stubBackend({
        updater_check_beta: () =>
          new Promise((resolve) => {
            deliver = resolve;
            pendingInstalls.push(() => resolve(null));
          }),
      });
      useSettingsStore.setState({ updateChannel: "beta" });
      const checking = checkForUpdates({ silent: false });
      useSettingsStore.setState({ updateChannel: "stable" });
      deliver(reply);
      await checking;
      expect(state()).toMatchObject({
        phase: "idle",
        channel: "stable",
        version: null,
      });
    },
  );
  it("retires an available installer on channel changes", async () => {
    const calls = stubBackend({ updater_check_beta: BETA_FOUND });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });
    useSettingsStore.setState({ updateChannel: "stable" });
    await installAvailableUpdate();
    expect(calls).toEqual(["updater_check_beta"]);
    expect(state().phase).toBe("idle");
  });
  it.each([
    ["stable", "nightly"],
    ["nightly", "stable"],
  ])(
    "ignores unrelated settings and normalized %s → %s changes",
    async (from, to) => {
      stubBackend({ "plugin:updater|check": STABLE_FOUND });
      useSettingsStore.setState({ updateChannel: from as UpdateChannel });
      await checkForUpdates({ silent: false });
      useSettingsStore.setState({
        fontSize: 16,
        updateChannel: to as UpdateChannel,
      });
      expect(state()).toMatchObject({
        phase: "available",
        version: STABLE_FOUND.version,
      });
    },
  );
  it("deduplicates simultaneous automatic and manual checks", async () => {
    let deliver!: (answer: unknown) => void;
    const calls = stubBackend({
      "plugin:updater|check": () =>
        new Promise((resolve) => {
          deliver = resolve;
          pendingInstalls.push(() => resolve(null));
        }),
    });
    const automatic = checkForUpdates({ silent: true });
    const manual = checkForUpdates({ silent: false });
    expect(state().phase).toBe("checking");
    deliver(STABLE_FOUND);
    await Promise.all([automatic, manual]);
    expect(calls).toEqual(["plugin:updater|check"]);
    expect(state().phase).toBe("available");
  });
  it("queues a new channel behind an old check without overlapping backend requests", async () => {
    let deliver!: (answer: unknown) => void;
    const calls = stubBackend({
      "plugin:updater|check": () =>
        new Promise((resolve) => {
          deliver = resolve;
          pendingInstalls.push(() => resolve(null));
        }),
      updater_check_beta: BETA_FOUND,
    });
    const stable = checkForUpdates({ silent: false });
    useSettingsStore.setState({ updateChannel: "beta" });
    const beta = checkForUpdates({ silent: false });
    expect(calls).toEqual(["plugin:updater|check"]);
    deliver(null);
    await Promise.all([stable, beta]);
    expect(calls).toEqual(["plugin:updater|check", "updater_check_beta"]);
    expect(state()).toMatchObject({ phase: "available", channel: "beta" });
  });
  it("drops a stale reply even when the user switched away and back", async () => {
    let deliver!: (answer: unknown) => void;
    stubBackend({
      updater_check_beta: () =>
        new Promise((resolve) => {
          deliver = resolve;
          pendingInstalls.push(() => resolve(null));
        }),
    });
    useSettingsStore.setState({ updateChannel: "beta" });
    const checking = checkForUpdates({ silent: false });
    useSettingsStore.setState({ updateChannel: "stable" });
    useSettingsStore.setState({ updateChannel: "beta" });
    deliver(BETA_FOUND);
    await checking;
    expect(state().phase).toBe("idle");
  });
});

describe("inline installation state", () => {
  beforeEach(() =>
    vi.useFakeTimers({
      toFake: ["setInterval", "clearInterval", "performance"],
    }),
  );
  it.each([
    {
      channel: "stable",
      found: { "plugin:updater|check": STABLE_FOUND },
      command: "plugin:updater|download_and_install",
      version: "0.16.1",
    },
    {
      channel: "beta",
      found: { updater_check_beta: BETA_FOUND },
      command: "updater_install_beta",
      version: "0.16.1-1",
    },
  ] as const)(
    "$channel keeps progress through download, install and restart and ignores late events",
    async ({ channel, found, command, version }) => {
      const install = heldInstall();
      const calls = stubBackend({ ...found, [command]: install.reply });
      useSettingsStore.setState({ updateChannel: channel });
      await checkForUpdates({ silent: false });
      const installing = installAvailableUpdate();
      expect(state()).toMatchObject({
        phase: "installing",
        progress: { title: `Downloading v${version}…`, line: "Connecting…" },
      });
      install.send({ event: "Started", data: { contentLength: 4_000_000 } });
      install.send({ event: "Progress", data: { chunkLength: 1_000_000 } });
      vi.advanceTimersByTime(PROGRESS_REFRESH_MS);
      expect(state().progress).toMatchObject({
        line: "1.0 MB of 4.0 MB",
        fraction: 0.25,
      });
      install.send({ event: "Progress", data: { chunkLength: 3_000_000 } });
      install.send({ event: "Finished" });
      expect(state().progress).toMatchObject({
        title: `Installing v${version}…`,
        fraction: 1,
      });
      install.held.finish();
      await installing;
      expect(calls).toContain("plugin:process|restart");
      install.send({ event: "Finished" });
      vi.advanceTimersByTime(STALL_AFTER_MS);
      expect(state()).toMatchObject({ phase: "restarting", progress: null });
    },
  );
  it("shows stalled downloads and blocks duplicate installs and checks", async () => {
    const install = heldInstall();
    const calls = stubBackend({
      updater_check_beta: BETA_FOUND,
      updater_install_beta: install.reply,
    });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });
    const installing = installAvailableUpdate();
    await installAvailableUpdate();
    await checkForUpdates({ silent: false });
    install.send({ event: "Started", data: { contentLength: 4_000_000 } });
    install.send({ event: "Progress", data: { chunkLength: 1_000_000 } });
    vi.advanceTimersByTime(STALL_AFTER_MS);
    expect(state().progress?.warning).toContain("No data for 10 s");
    expect(calls).toEqual(["updater_check_beta", "updater_install_beta"]);
    install.held.finish();
    await installing;
  });
  it("prevents installation while a newer check is pending", async () => {
    let deliver!: (answer: unknown) => void;
    let checks = 0;
    const calls = stubBackend({
      updater_check_beta: () =>
        ++checks === 1
          ? BETA_FOUND
          : new Promise((resolve) => {
              deliver = resolve;
              pendingInstalls.push(() => resolve(null));
            }),
    });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });
    const checking = checkForUpdates({ silent: false });
    await installAvailableUpdate();
    expect(calls).toEqual(["updater_check_beta", "updater_check_beta"]);
    deliver(BETA_FOUND);
    await checking;
    expect(state().phase).toBe("available");
  });
  it("stops failed progress and requires a fresh check before retrying installation", async () => {
    const install = heldInstall();
    const calls = stubBackend({
      updater_check_beta: BETA_FOUND,
      updater_install_beta: install.reply,
    });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });
    const installing = installAvailableUpdate();
    install.held.fail(new Error("connection reset"));
    await installing;
    vi.advanceTimersByTime(STALL_AFTER_MS);
    expect(state()).toMatchObject({
      phase: "error",
      errorStage: "install",
      error: "connection reset",
      progress: null,
    });
    await installAvailableUpdate();
    expect(calls.filter((c) => c === "updater_install_beta")).toHaveLength(1);
    await checkForUpdates({ silent: false });
    expect(state().phase).toBe("available");
    expect(calls.filter((c) => c === "updater_check_beta")).toHaveLength(2);
  });
  it("retries a failed restart without downloading or installing again", async () => {
    let attempts = 0;
    const calls = stubBackend({
      updater_check_beta: BETA_FOUND,
      "plugin:process|restart": () => {
        if (++attempts === 1) throw new Error("restart denied");
      },
    });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });
    await installAvailableUpdate();
    expect(state()).toMatchObject({
      phase: "restart_required",
      error: "restart denied",
    });
    await checkForUpdates({ silent: false });
    await restartAfterUpdate();
    expect(calls).toEqual([
      "updater_check_beta",
      "updater_install_beta",
      "plugin:process|restart",
      "plugin:process|restart",
    ]);
  });
  it("keeps the active install visible when imported settings change the preferred channel", async () => {
    const install = heldInstall();
    const calls = stubBackend({
      updater_check_beta: BETA_FOUND,
      updater_install_beta: install.reply,
    });
    useSettingsStore.setState({ updateChannel: "beta" });
    await checkForUpdates({ silent: false });
    const installing = installAvailableUpdate();
    useSettingsStore.setState({ updateChannel: "stable" });
    expect(state()).toMatchObject({
      phase: "installing",
      channel: "beta",
      version: BETA_FOUND.version,
    });
    await checkForUpdates({ silent: false });
    install.held.finish();
    await installing;
    expect(calls).not.toContain("plugin:updater|check");
  });
});
