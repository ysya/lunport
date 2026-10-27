import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "@/stores/ui";
import { renderHook } from "@/lib/test-ipc";
import { buttonsIn } from "./keychain/test-markup";
import { recordOverview } from "./records/fixtures";
import { SettingsPage } from "./SettingsPage";

// Server rendering normally reads Zustand's initial snapshot; these cases exercise the current page state.
vi.mock("@/stores/ui", async load => {
  const original = await load<typeof import("@/stores/ui")>();
  return { ...original, useUiStore: Object.assign(<T,>(selector: (state: ReturnType<typeof original.useUiStore.getState>) => T) => selector(original.useUiStore.getState()), original.useUiStore) };
});
vi.mock("@/lib/queries", async load => ({
  ...await load<typeof import("@/lib/queries")>(), usePlatform: () => ({ data: "macos" }),
}));
afterEach(() => useUiStore.setState({ settingsOpen: false, settingsCategory: "general" }));

describe("Settings page", () => {
  it("shows an accessible page with a return action instead of a modal", () => {
    useUiStore.setState({ settingsOpen: true, settingsCategory: "general" });
    const html = renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}><SettingsPage recordOverview={recordOverview()} /></QueryClientProvider>);
    expect(html).toContain('<main class="app-shell settings-page is-macos" aria-labelledby="settings-page-title"');
    expect(html).toContain('aria-label="Back to workspace"');
    expect(html).toContain('aria-label="Search settings"');
    expect(html).toContain('aria-label="Settings categories"');
    expect(html).not.toContain('role="dialog"');
    expect(html).not.toContain('aria-modal="true"');
  });

  it("returns to the workspace through Back and leaves the selected settings category available", () => {
    useUiStore.setState({ settingsOpen: true, settingsCategory: "appearance" });
    const page = renderHook(new QueryClient(), () => SettingsPage({ recordOverview: recordOverview() }));
    const back = buttonsIn(page).find(button => (button.props as { "aria-label"?: string })["aria-label"] === "Back to workspace");
    expect(back).toBeDefined();
    back!.props.onClick!();
    expect(useUiStore.getState()).toMatchObject({ settingsOpen: false, settingsCategory: "appearance" });
    expect(renderHook(new QueryClient(), () => SettingsPage({ recordOverview: recordOverview() }))).toBeNull();
  });
});
