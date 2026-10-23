import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { UpdateStatusCard, openUpdates } from "./UpdatesPane";
import { type UpdaterState } from "@/lib/updater";
import { useUiStore } from "@/stores/ui";

const snapshot = (values: Partial<UpdaterState> = {}): UpdaterState => ({
  phase: "idle",
  channel: "beta",
  version: null,
  body: null,
  checkedAt: null,
  error: null,
  errorStage: null,
  progress: null,
  ...values,
});
const view = (values: Partial<UpdaterState>, allowed = true) =>
  renderToStaticMarkup(
    <UpdateStatusCard
      state={snapshot(values)}
      allowed={allowed}
      onCheck={vi.fn()}
      onInstall={vi.fn()}
      onRestart={vi.fn()}
    />,
  );

describe("updates stay in the update page", () => {
  it("keeps check feedback in an accessible status beside its disabled action", () => {
    const html = view({ phase: "checking" });
    expect(html).toContain('role="status"');
    expect(html).toContain("Checking for updates…");
    expect(html).toMatch(/<button[^>]*disabled/);
    expect(html).not.toContain("Install and restart");
  });
  it("explains channel-specific up-to-date results without promising a downgrade", () => {
    expect(view({ phase: "current", channel: "stable" })).toContain(
      "No newer release is available on the Stable channel.",
    );
  });
  it("offers a deliberate install and renders release notes as safe text", () => {
    const html = view({
      phase: "available",
      version: "1.0.0-8",
      body: "## Changes\n- Better updates\n<script>alert(1)</script>",
    });
    expect(html).toContain("Version 1.0.0-8 is available");
    expect(html).toContain("Install and restart");
    expect(html).toContain("Installing restarts Lunport and ends active SSH sessions.");
    expect(html).toContain("What’s new in");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
  });
  it("keeps downloading progress on the page without another install or check action", () => {
    const html = view({
      phase: "installing",
      progress: {
        title: "Downloading v1.0.0-8…",
        line: "12.0 MB of 48.0 MB",
        fraction: 0.25,
        warning: null,
      },
    });
    expect(html).toContain('aria-valuenow="25"');
    expect(html).toContain("Keep this window open");
    expect(html).not.toContain("Check for updates</button>");
    expect(html).not.toContain("Install and restart");
  });
  it("keeps errors and retry actions together", () => {
    const html = view({
      phase: "error",
      errorStage: "install",
      error: "Connection reset",
    });
    expect(html).toContain("Couldn’t install the update");
    expect(html).toContain('role="alert"');
    expect(html).toContain("Connection reset");
    expect(html).toContain("Try again");
  });
  it("offers restart recovery without offering another download", () => {
    const html = view({
      phase: "restart_required",
      version: "1.0.0-8",
      error: "Restart denied",
    });
    expect(html).toContain("The update is installed.");
    expect(html).toContain("Restart Lunport</button>");
    expect(html).not.toContain("Try again");
    expect(html).not.toContain("Install and restart");
  });
  it("does not offer update actions in development builds", () => {
    const html = view({ phase: "available", version: "1.0.0-8" }, false);
    expect(html).toContain("Updates are unavailable in development builds");
    expect(html).not.toContain("<button");
  });
  it("routes the update entry directly to the Updates page", () => {
    useUiStore.setState({ settingsOpen: false, settingsCategory: "general" });
    openUpdates();
    expect(useUiStore.getState()).toMatchObject({
      settingsOpen: true,
      settingsCategory: "updates",
    });
  });
});
