import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";

import { SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { useSettingsStore } from "@/stores/settings";
import { queryKeys, useSetIdentityFile, useTurnOnLaunchAtLogin } from "./queries";

/** Stub the backend: every command, the plugins' too, ends in `window.__TAURI_INTERNALS__.invoke`. */
function stubBackend(reply: (cmd: string) => Promise<unknown>): Array<[string, unknown]> {
  const calls: Array<[string, unknown]> = [];
  vi.stubGlobal("window", {
    __TAURI_INTERNALS__: {
      invoke: (cmd: string, args: unknown) => {
        calls.push([cmd, args]);
        return reply(cmd);
      },
    },
  });
  return calls;
}

/** Run a hook the way a component does and hand back what it returned (a server render: no effects run, nothing subscribes). */
function renderHook<T>(queryClient: QueryClient, useHook: () => T): T {
  let result!: T;
  const Probe = () => {
    result = useHook();
    return null;
  };
  renderToStaticMarkup(createElement(QueryClientProvider, { client: queryClient }, createElement(Probe)));
  return result;
}

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
  useSettingsStore.setState({ closeToTray: false });
});

describe("pointing a host at one key", () => {
  it("replaces the host's IdentityFile lines and refreshes the host, its key checks and the key list", async () => {
    const calls = stubBackend(async () => null);
    const queryClient = new QueryClient();
    const keys = [queryKeys.host("web"), queryKeys.hosts, queryKeys.keyHygiene("web"), queryKeys.keys];
    for (const key of keys) queryClient.setQueryData(key, []);
    await renderHook(queryClient, useSetIdentityFile).mutateAsync({ alias: "web", value: "~/.ssh/sshelter/keys/id_mac-3fa2c1d9" });
    expect(calls).toEqual([["config_set_identity_file", { alias: "web", value: "~/.ssh/sshelter/keys/id_mac-3fa2c1d9" }]]);
    expect(keys.map((key) => queryClient.getQueryState(key)?.isInvalidated)).toEqual([true, true, true, true]);
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
});

describe("the launch hint's button", () => {
  it("turns on launch at login and keeps SSHelter running in the menu bar", async () => {
    const calls = stubBackend(async () => undefined);
    await renderHook(new QueryClient(), useTurnOnLaunchAtLogin).mutateAsync();
    expect(calls).toEqual([
      ["plugin:autostart|enable", {}],
      ["app_set_close_to_tray", { enabled: true }],
    ]);
    expect(useSettingsStore.getState().closeToTray).toBe(true);
  });
});
