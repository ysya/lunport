import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clampHostPreviewWidth,
  hostPreviewLimit,
  hostPreviewNeedsCompact,
  hostPreviewWidthAfterDrag,
  hostPreviewWidthAfterKey,
} from "./host-preview-width";

describe("connection details width policy", () => {
  it("normalizes invalid and out-of-range preferences", () => {
    for (const value of [null, undefined, "500", NaN, Infinity])
      expect(clampHostPreviewWidth(value)).toBe(400);
    expect(clampHostPreviewWidth(-1)).toBe(320);
    expect(clampHostPreviewWidth(900)).toBe(640);
    expect(clampHostPreviewWidth(420.4)).toBe(420);
  });
  it("uses a single pane when two minimum widths no longer fit", () => {
    expect(hostPreviewNeedsCompact(639.5)).toBe(true);
    expect(hostPreviewNeedsCompact(634.5)).toBe(true);
    expect(hostPreviewNeedsCompact(640)).toBe(false);
    expect(hostPreviewNeedsCompact(900)).toBe(false);
    expect(hostPreviewNeedsCompact(Infinity)).toBe(false);
  });
  it("reserves list space while keeping the preferred width independent", () => {
    expect(hostPreviewLimit(800)).toBe(480);
    expect(hostPreviewLimit(897.5)).toBe(577);
    expect(hostPreviewLimit(1600)).toBe(640);
    expect(hostPreviewLimit(600)).toBe(320);
    expect(hostPreviewLimit(NaN)).toBe(640);
    const preferred = 600;
    expect(Math.min(preferred, hostPreviewLimit(800))).toBe(480);
    expect(Math.min(preferred, hostPreviewLimit(1600))).toBe(600);
  });
  it("grows the right pane when its left divider moves left and respects available space", () => {
    expect(hostPreviewWidthAfterDrag(400, -80, 640)).toBe(480);
    expect(hostPreviewWidthAfterDrag(400, 80, 640)).toBe(320);
    expect(hostPreviewWidthAfterDrag(400, -1000, 480)).toBe(480);
    expect(hostPreviewWidthAfterDrag(400, NaN, 640)).toBe(400);
  });
  it("moves the divider in the keyboard direction and stops at both bounds", () => {
    expect(hostPreviewWidthAfterKey(400, "ArrowLeft", 640)).toBe(416);
    expect(hostPreviewWidthAfterKey(400, "ArrowRight", 640)).toBe(384);
    expect(hostPreviewWidthAfterKey(400, "Home", 480)).toBe(320);
    expect(hostPreviewWidthAfterKey(400, "End", 480)).toBe(480);
    expect(hostPreviewWidthAfterKey(320, "ArrowRight", 640)).toBe(320);
    expect(hostPreviewWidthAfterKey(480, "ArrowLeft", 480)).toBe(480);
    expect(hostPreviewWidthAfterKey(400, "Tab", 640)).toBeNull();
  });
});

describe("persisted connection details width", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });
  async function launch(saved?: Record<string, unknown>) {
    const items = new Map<string, string>();
    if (saved)
      items.set("sshelter-ui", JSON.stringify({ state: saved, version: 0 }));
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (key: string) => items.get(key) ?? null,
        setItem: (key: string, value: string) => void items.set(key, value),
        removeItem: (key: string) => void items.delete(key),
      },
    });
    vi.resetModules();
    const { useUiStore: store } = await import("@/stores/ui");
    return { store, items };
  }
  it("remembers an independently bounded preference across launches", async () => {
    const first = await launch();
    expect(first.store.getState().hostPreviewWidth).toBe(400);
    first.store.getState().setHostPreviewWidth(600);
    expect(first.store.getState().sidebarWidth).toBe(24);
    const second = await launch(
      JSON.parse(first.items.get("sshelter-ui")!).state,
    );
    expect(second.store.getState().hostPreviewWidth).toBe(600);
    second.store.getState().setHostPreviewWidth(1000);
    expect(second.store.getState().hostPreviewWidth).toBe(640);
    second.store.getState().setHostPreviewWidth(NaN);
    expect(second.store.getState().hostPreviewWidth).toBe(400);
  });
  it("keeps old settings envelopes valid", async () => {
    const { store } = await launch({
      sidebarWidth: 20,
      collapsedGroups: ["work"],
    });
    expect(store.getState().hostPreviewWidth).toBe(400);
    expect(store.getState().sidebarWidth).toBe(20);
  });
});
