import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SessionTabBar } from "./TerminalWorkspace";
import type { TerminalTab } from "@/stores/terminals";

const tab: TerminalTab = { id: "t1", host: {} as TerminalTab["host"], name: "jumpbox-prod", address: "frank@10.20.0.8:22", historyKey: "k", state: "open" };

describe("the session tab strip in the title bar", () => {
  it("drags the window from the strip, between and around the tabs, but not from the tabs' buttons", () => {
    const html = renderToStaticMarkup(<SessionTabBar tabs={[tab]} activeId={null} activate={() => {}} requestClose={() => {}} strip={{ current: null }} />);
    const opening = (cls: string) => [...html.matchAll(/<(?:div|nav)\b[^>]*>/g)].map((m) => m[0]).find((t) => t.includes(`class="${cls}"`)) ?? `missing ${cls}`;
    // Tauri looks for the attribute's presence on the pressed element itself, whatever its value.
    expect(opening("embedded-tabbar")).toContain("data-tauri-drag-region");
    expect(opening("embedded-tabs")).toContain("data-tauri-drag-region");
    expect(opening("embedded-tab")).toContain("data-tauri-drag-region");
    for (const button of html.matchAll(/<button\b[^>]*>/g)) expect(button[0]).not.toContain("data-tauri-drag-region");
    expect(html).toContain("jumpbox-prod");
  });
});
