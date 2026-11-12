import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionTabBar, completeTerminalClose, requestTerminalClose } from "./TerminalWorkspace";
import type { TerminalTab } from "@/stores/terminals";
import { useTerminalStore } from "@/stores/terminals";
import { useSettingsStore } from "@/stores/settings";

const tab: TerminalTab = { id: "t1", host: {} as TerminalTab["host"], name: "web-1", address: "frank@192.0.2.8:22", historyKey: "k", state: "open" };

describe("the session tab strip in the title bar", () => {
  it("drags the window from the strip, between and around the tabs, but not from the tabs' buttons", () => {
    const html = renderToStaticMarkup(<SessionTabBar tabs={[tab]} activeId={null} activate={() => {}} requestClose={() => {}} strip={{ current: null }} />);
    const opening = (cls: string) => [...html.matchAll(/<(?:div|nav)\b[^>]*>/g)].map((m) => m[0]).find((t) => t.includes(`class="${cls}"`)) ?? `missing ${cls}`;
    // Tauri looks for the attribute's presence on the pressed element itself, whatever its value.
    expect(opening("embedded-tabbar")).toContain("data-tauri-drag-region");
    expect(opening("embedded-tabs")).toContain("data-tauri-drag-region");
    expect(opening("embedded-tab")).toContain("data-tauri-drag-region");
    for (const button of html.matchAll(/<button\b[^>]*>/g)) expect(button[0]).not.toContain("data-tauri-drag-region");
    expect(html).toContain("web-1");
  });
});

afterEach(() => {
  useTerminalStore.getState().reset();
  useSettingsStore.getState().setConfirmTerminalClose(true);
});

describe("closing a terminal tab", () => {
  const openTab = () => useTerminalStore.getState().open({ host: tab.host, name: tab.name, address: tab.address, historyKey: tab.historyKey });

  it("asks before closing an active session until a confirmed close opts out", () => {
    const id = openTab();
    useTerminalStore.getState().updateState(id, "open");
    const onConfirm = vi.fn();

    requestTerminalClose(id, onConfirm);
    expect(onConfirm).toHaveBeenCalledWith(id);
    expect(useTerminalStore.getState().tabs).toHaveLength(1);
    expect(useSettingsStore.getState().confirmTerminalClose).toBe(true);

    completeTerminalClose(id, true);
    expect(useTerminalStore.getState().tabs).toHaveLength(0);
    expect(useSettingsStore.getState().confirmTerminalClose).toBe(false);

    const next = openTab();
    requestTerminalClose(next, onConfirm);
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(useTerminalStore.getState().tabs).toHaveLength(0);
  });

  it("keeps the preference when a close is confirmed without opting out", () => {
    const id = openTab();
    completeTerminalClose(id, false);
    expect(useSettingsStore.getState().confirmTerminalClose).toBe(true);
  });

  it("closes an ended session without asking even when confirmation is enabled", () => {
    const id = openTab();
    useTerminalStore.getState().updateState(id, "ended");
    const onConfirm = vi.fn();
    requestTerminalClose(id, onConfirm);
    expect(onConfirm).not.toHaveBeenCalled();
    expect(useTerminalStore.getState().tabs).toHaveLength(0);
  });
});
