import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useConnect, useDeployKey } from "./queries";
import { renderHook, stubBackend } from "./test-ipc";
import { IN_APP_TERMINAL } from "./settings-logic";
import { useTerminalStore } from "@/stores/terminals";
import { useSettingsStore } from "@/stores/settings";
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
const initial = useSettingsStore.getState();
const client = () => new QueryClient({ defaultOptions: { mutations: { gcTime: 0 } } });
afterEach(() => { useTerminalStore.getState().reset(); useSettingsStore.setState(initial); vi.unstubAllGlobals(); });
describe("terminal destination boundaries", () => {
  it("routes Legacy app sessions by saved alias without launching a system process", async () => {
    const calls = stubBackend(async () => undefined);
    const query = client(); const connect = renderHook(query, useConnect);
    await connect.mutateAsync({ alias: "legacy-web", terminalOverride: IN_APP_TERMINAL });
    expect(calls).toEqual([]);
    expect(useTerminalStore.getState().tabs).toEqual([expect.objectContaining({ host: { alias: "legacy-web" }, historyKey: "legacy-web" })]);
    expect(useSettingsStore.getState().recentConnections).toBe(initial.recentConnections);
    query.clear();
  });
  it("honors an explicit system-default override when the app terminal is the global choice", async () => {
    const calls = stubBackend(async () => undefined);
    useSettingsStore.getState().setTerminalId(IN_APP_TERMINAL);
    const query = client(); const connect = renderHook(query, useConnect);
    await connect.mutateAsync({ alias: "legacy-web", terminalOverride: null, newTab: false });
    expect(calls).toEqual([["connect_launch", { alias: "legacy-web", terminalOverride: null, newTab: false }]]);
    expect(useTerminalStore.getState().tabs).toEqual([]);
    query.clear();
  });
  it("keeps external-only ssh-copy-id working when the global preference is Lunport", async () => {
    const calls = stubBackend(async () => undefined);
    const query = client(); const deploy = renderHook(query, useDeployKey);
    await deploy.mutateAsync({ alias: "web", publicPath: "/fixture/key.pub", terminalOverride: IN_APP_TERMINAL });
    await deploy.mutateAsync({ alias: "web", publicPath: "/fixture/key.pub", terminalOverride: "iterm2" });
    expect(calls).toEqual([
      ["keys_deploy", { alias: "web", publicPath: "/fixture/key.pub", terminalOverride: null }],
      ["keys_deploy", { alias: "web", publicPath: "/fixture/key.pub", terminalOverride: "iterm2" }],
    ]);
    query.clear();
  });
  it("records the launched destination even if the preference changes while an external launch is pending", async () => {
    let finish!: () => void;
    let started!: () => void;
    const launching = new Promise<void>((resolve) => { started = resolve; });
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    stubBackend(async () => { started(); await pending; });
    const query = client(); const connect = renderHook(query, useConnect);
    const result = connect.mutateAsync({ alias: "pending-external", terminalOverride: "iterm2" });
    await launching;
    useSettingsStore.getState().setTerminalId(IN_APP_TERMINAL);
    finish();
    await result;
    expect(useSettingsStore.getState().recentConnections["pending-external"]).toEqual(expect.any(Number));
    expect(useTerminalStore.getState().tabs).toEqual([]);
    query.clear();
  });
});
