import { afterEach, describe, expect, it, vi } from "vitest";

import { UI_STORAGE_KEY, useUiStore } from "@/stores/ui";
import {
  DEFAULT_SIDEBAR_WIDTH,
  MAX_SIDEBAR_WIDTH,
  MIN_SIDEBAR_WIDTH,
  clampSidebarWidth,
  widthAfterDrag,
  widthAfterKey,
} from "./sidebar-width";

describe("clampSidebarWidth", () => {
  it("keeps a width inside the range", () => {
    expect(clampSidebarWidth(20)).toBe(20);
  });

  it("clamps to the minimum and the maximum", () => {
    expect(clampSidebarWidth(4)).toBe(MIN_SIDEBAR_WIDTH);
    expect(clampSidebarWidth(400)).toBe(MAX_SIDEBAR_WIDTH);
  });

  it("falls back to the default for anything that is not a finite number", () => {
    for (const bad of [undefined, null, "20", Number.NaN, Number.POSITIVE_INFINITY, {}]) {
      expect(clampSidebarWidth(bad)).toBe(DEFAULT_SIDEBAR_WIDTH);
    }
  });

  it("rounds to whole pixels at the default text size", () => {
    expect(clampSidebarWidth(17.03)).toBe(17);
    expect(clampSidebarWidth(17.04)).toBe(17.0625);
  });
});

describe("widthAfterDrag", () => {
  it("converts the dragged pixels to rem at the current text size", () => {
    expect(widthAfterDrag(256, 64, 16)).toBe(20);
    expect(widthAfterDrag(240, 60, 15)).toBe(20);
  });

  it("stops at the limits", () => {
    expect(widthAfterDrag(256, -1000, 16)).toBe(MIN_SIDEBAR_WIDTH);
    expect(widthAfterDrag(256, 1000, 16)).toBe(MAX_SIDEBAR_WIDTH);
  });
});

describe("widthAfterKey", () => {
  it("steps with the arrow keys and jumps with Home and End", () => {
    expect(widthAfterKey(16, "ArrowRight")).toBe(17);
    expect(widthAfterKey(16, "ArrowLeft")).toBe(15);
    expect(widthAfterKey(16, "Home")).toBe(MIN_SIDEBAR_WIDTH);
    expect(widthAfterKey(16, "End")).toBe(MAX_SIDEBAR_WIDTH);
  });

  it("stays inside the range", () => {
    expect(widthAfterKey(MIN_SIDEBAR_WIDTH, "ArrowLeft")).toBe(MIN_SIDEBAR_WIDTH);
    expect(widthAfterKey(MAX_SIDEBAR_WIDTH, "ArrowRight")).toBe(MAX_SIDEBAR_WIDTH);
  });

  it("ignores other keys", () => {
    expect(widthAfterKey(16, "Enter")).toBeNull();
    expect(widthAfterKey(16, "a")).toBeNull();
  });
});

describe("the stored sidebar width", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  /** A fresh UI store over an in-memory localStorage, optionally holding state saved by an earlier run. */
  async function launch(saved?: Record<string, unknown>) {
    const items = new Map<string, string>();
    if (saved) items.set(UI_STORAGE_KEY, JSON.stringify({ state: saved, version: 0 }));
    // zustand's persist reads `window.localStorage`.
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

  it("starts at the former fixed width", () => {
    expect(useUiStore.getInitialState().sidebarWidth).toBe(DEFAULT_SIDEBAR_WIDTH);
    expect(DEFAULT_SIDEBAR_WIDTH).toBe(16);
  });

  it("is clamped when set", () => {
    useUiStore.getState().setSidebarWidth(400);
    expect(useUiStore.getState().sidebarWidth).toBe(MAX_SIDEBAR_WIDTH);
    useUiStore.getState().setSidebarWidth(Number.NaN);
    expect(useUiStore.getState().sidebarWidth).toBe(DEFAULT_SIDEBAR_WIDTH);
  });

  it("is remembered across launches", async () => {
    const first = await launch();
    first.store.getState().setSidebarWidth(20);
    const saved = JSON.parse(first.items.get(UI_STORAGE_KEY) ?? "{}").state;
    const second = await launch(saved);
    expect(second.store.getState().sidebarWidth).toBe(20);
  });

  it("uses the default when the saved state predates it", async () => {
    const { store } = await launch({ collapsedGroups: [], fileScope: null, groupMode: "file" });
    expect(store.getState().sidebarWidth).toBe(DEFAULT_SIDEBAR_WIDTH);
  });
});
