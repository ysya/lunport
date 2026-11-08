import { beforeEach, describe, expect, it } from "vitest";

import { useUiStore } from "./ui";

describe("the ui store", () => {
  beforeEach(() => useUiStore.setState({ search: "", settingsOpen: false, paletteOpen: false, librarySidebarCollapsed: false, collapsedRecordGroups: [], hostPreviewWidth: 400 }));

  it("toggles a Group's collapsed state and the Library sidebar", () => {
    useUiStore.getState().toggleRecordGroup("a");
    useUiStore.getState().toggleRecordGroup("b");
    expect(useUiStore.getState().collapsedRecordGroups).toEqual(["a", "b"]);
    useUiStore.getState().toggleRecordGroup("a");
    expect(useUiStore.getState().collapsedRecordGroups).toEqual(["b"]);
    useUiStore.getState().toggleLibrarySidebar();
    expect(useUiStore.getState().librarySidebarCollapsed).toBe(true);
  });

  it("clamps the details width it is given", () => {
    useUiStore.getState().setHostPreviewWidth(10);
    expect(useUiStore.getState().hostPreviewWidth).toBeGreaterThan(10);
  });
});
