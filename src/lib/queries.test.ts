import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";

import { tauriInvoke } from "@/lib/ipc";
import { SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { useSettingsStore } from "@/stores/settings";
import { queryKeys, useSetIdentityFile, useTurnOnLaunchAtLogin } from "./queries";
import { syncOverviewKey } from "./sync";
import { renderHook, stubBackend } from "./test-ipc";

beforeEach(() => {
  // sonner's `toast.dismiss` schedules through requestAnimationFrame, which Node lacks.
  vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
    cb(0);
    return 0;
  });
});

afterEach(() => {
  for (const t of toast.getToasts()) toast.dismiss(t.id);
  vi.unstubAllGlobals();
  useSettingsStore.setState({ closeToTray: false, trayVisible: true });
});

describe("pointing a host at one key", () => {
  it("replaces the host's IdentityFile lines and refreshes the host, its key checks, the key list and the key slots", async () => {
    const calls = stubBackend(async () => null);
    const queryClient = new QueryClient();
    // The sync overview is what shows the key slots, whose state and hosts are worked out from the live config.
    const keys = [queryKeys.host("web"), queryKeys.hosts, queryKeys.keyHygiene("web"), queryKeys.keys, syncOverviewKey];
    for (const key of keys) queryClient.setQueryData(key, []);
    await renderHook(queryClient, useSetIdentityFile).mutateAsync({ alias: "web", value: "~/.ssh/sshelter/keys/id_mac-3fa2c1d9" });
    expect(calls).toEqual([["config_set_identity_file", { alias: "web", value: "~/.ssh/sshelter/keys/id_mac-3fa2c1d9" }]]);
    expect(keys.map((key) => queryClient.getQueryState(key)?.isInvalidated)).toEqual([true, true, true, true, true]);
  });

  it("shows a failure with hidden characters revealed: the backend's message names the host, whose alias comes from the config", async () => {
    const message = `host '${SPOOFED_NAME}' not found`;
    stubBackend(async () => {
      throw message;
    });
    const { mutateAsync } = renderHook(new QueryClient(), useSetIdentityFile);
    await expect(mutateAsync({ alias: SPOOFED_NAME, value: "~/.ssh/sshelter/keys/id_mac-3fa2c1d9" })).rejects.toBe(message);
    const [shown, ...others] = toast.getToasts();
    expect(others).toEqual([]);
    expect(shown).toEqual(expect.objectContaining({ title: "Failed to save host", description: expect.stringContaining(SPOOFED_NAME_SHOWN) }));
    // Not even the right-to-left override (U+202E) that SPOOFED_NAME carries is left in what is shown.
    expect(shown).toEqual(expect.objectContaining({ description: expect.not.stringContaining(String.fromCodePoint(0x202e)) }));
  });

  it("reads the config again after a failed write, so that Use this key works next time: a Conflict means the file changed under us", async () => {
    const calls = stubBackend(async (cmd) => {
      if (cmd === "config_set_identity_file") throw "file changed on disk since it was loaded: /home/f/.ssh/config";
      return { files: [], hosts: [] };
    });
    const queryClient = new QueryClient();
    // The host list as the app and the deploy dialog keep it (`useHostsQuery`): its `config_load` reloads the backend's copy from disk.
    const hosts = new QueryObserver(queryClient, { queryKey: queryKeys.hosts, queryFn: () => tauriInvoke("config_load") });
    const stop = hosts.subscribe(() => {});
    await vi.waitFor(() => expect(hosts.getCurrentResult().isSuccess).toBe(true));
    calls.length = 0;

    const { mutateAsync } = renderHook(queryClient, useSetIdentityFile);
    await expect(mutateAsync({ alias: "web", value: "~/.ssh/sshelter/keys/id_mac-3fa2c1d9" })).rejects.toMatch("changed on disk");
    await vi.waitFor(() => expect(calls.map(([cmd]) => cmd)).toEqual(["config_set_identity_file", "config_load"]));
    expect(toast.getToasts()).toEqual([expect.objectContaining({ title: "Failed to save host" })]);
    stop();
  });
});

describe("the launch hint's button", () => {
  it("turns on launch at login, shows the menu bar icon and keeps SSHelter running there", async () => {
    useSettingsStore.setState({ trayVisible: false });
    const calls = stubBackend(async () => undefined);
    await renderHook(new QueryClient(), useTurnOnLaunchAtLogin).mutateAsync();
    expect(calls).toEqual([
      ["plugin:autostart|enable", {}],
      ["tray_set_visible", { visible: true }],
      ["app_set_close_to_tray", { enabled: true }],
    ]);
    expect(useSettingsStore.getState()).toEqual(expect.objectContaining({ trayVisible: true, closeToTray: true }));
  });

  it("does not hide the window into the menu bar when the icon can't be shown: nothing would bring the window back", async () => {
    const calls = stubBackend(async (cmd) => {
      if (cmd === "tray_set_visible") throw "no tray";
    });
    await expect(renderHook(new QueryClient(), useTurnOnLaunchAtLogin).mutateAsync()).rejects.toBe("no tray");
    expect(calls.map(([cmd]) => cmd)).toEqual(["plugin:autostart|enable", "tray_set_visible"]);
    expect(useSettingsStore.getState().closeToTray).toBe(false);
    expect(toast.getToasts()).toEqual([expect.objectContaining({ title: "Could not turn on launch at login", description: "no tray" })]);
  });
});
