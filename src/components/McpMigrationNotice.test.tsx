import { isValidElement, type ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toast } from "sonner";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { McpMigration } from "@/bindings/McpMigration";
import { stubBackend } from "@/lib/test-ipc";
import { useUiStore } from "@/stores/ui";
import { buttonsIn, text, textIn } from "./keychain/test-markup";
import { mcpMigrationKey, McpMigrationNotice, McpMigrationToast, mcpNoticeHost, shouldShowMcpNotice, showMcpMigrationNotice } from "./McpMigrationNotice";

const LINK = "Its settings file is a symbolic link, which Lunport does not change. Set it up by hand in Settings → AI access.";
const UNCHECKED = "Lunport could not check the AI tools' settings: cannot determine home directory";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  useUiStore.setState({ settingsOpen: false, settingsCategory: "general" });
});

describe("MCP notice after the move to the new program", () => {
  it("asks to add Lunport to Cursor and VS Code again, and to export configurations again", () => {
    const html = renderToStaticMarkup(<McpMigrationNotice />);
    expect(html).toContain("Add Lunport to Cursor and VS Code again");
    expect(html).toContain("Cursor and VS Code keep the setup they installed from a link, which still starts the earlier program.");
    expect(html).toContain("In Settings → AI access, choose Cursor or VS Code and add Lunport again.");
    expect(html).toContain("Export or copy MCP configurations you made earlier again, too.");
  });

  it("names the clients whose settings Lunport updated, asks to restart them, and claims none when it updated none", () => {
    const html = renderToStaticMarkup(<McpMigrationNotice updated={["codex", "claude_code", "claude_desktop"]} />);
    expect(html).toContain("Lunport updated Codex, Claude Code and Claude Desktop to start the new program.");
    // A session that is already running keeps the adapter it started with.
    expect(html).toContain("Restart them: a session that is already running keeps the earlier program until it restarts.");
    const one = renderToStaticMarkup(<McpMigrationNotice updated={["claude_code"]} />);
    expect(one).toContain("Lunport updated Claude Code to start the new program. Restart it: a session that is already running keeps the earlier program until it restarts.");
    for (const updated of [undefined, []]) {
      const html = renderToStaticMarkup(<McpMigrationNotice updated={updated} />);
      expect(html).not.toContain("Lunport updated");
      expect(html).not.toContain("Restart");
    }
  });

  it("names the clients it could not update, with why, and says it checks them again", () => {
    const html = renderToStaticMarkup(<McpMigrationNotice updated={["codex"]} failed={[
      { client: "claude_code", reason: LINK },
      { client: "claude_desktop", reason: "Its settings file could not be read: Permission denied (os error 13)." },
    ]} />);
    const words = text(html);
    expect(words).toContain("Some AI tools still start the earlier program");
    expect(words).not.toContain("Add Lunport to Cursor and VS Code again");
    expect(words).toContain("Lunport updated Codex to start the new program.");
    expect(words).toContain(`Lunport could not update these: Claude Code: ${LINK} Claude Desktop: Its settings file could not be read: Permission denied (os error 13).`);
    expect(words).toContain("Lunport checks them again the next time it starts.");
    expect(words).toContain("In Settings → AI access, choose Cursor or VS Code and add Lunport again.");
    for (const failed of [undefined, []]) expect(renderToStaticMarkup(<McpMigrationNotice failed={failed} />)).not.toContain("could not update");
  });

  it("says why it could not look at any AI tool's settings, without a client to name", () => {
    const words = text(renderToStaticMarkup(<McpMigrationNotice failed={[{ client: null, reason: UNCHECKED }]} />));
    expect(words).toContain("Lunport could not check your AI tools");
    expect(words).not.toContain("Some AI tools still start the earlier program");
    expect(words).toContain(UNCHECKED);
    expect(words).not.toContain("could not update these");
    expect(words).toContain("Lunport checks them again the next time it starts.");
  });

  it("closes with its Dismiss button and opens AI access from its button", () => {
    const onDismiss = vi.fn();
    const onOpenSettings = vi.fn();
    const buttons = buttonsIn(McpMigrationNotice({ updated: ["codex"], onDismiss, onOpenSettings }));
    const dismiss = buttons.find(button => (button.props as { "aria-label"?: string })["aria-label"] === "Dismiss");
    expect(dismiss).toBeDefined();
    dismiss!.props.onClick!();
    expect(onDismiss).toHaveBeenCalledTimes(1);
    const open = buttons.find(button => textIn(button) === "Open AI access");
    expect(open).toBeDefined();
    open!.props.onClick!();
    expect(onOpenSettings).toHaveBeenCalledTimes(1);
    expect(onDismiss).toHaveBeenCalledTimes(1);
    // Without the handlers there is nothing to press.
    const html = renderToStaticMarkup(<McpMigrationNotice updated={["codex"]} />);
    expect(html).not.toContain('aria-label="Dismiss"');
    expect(html).not.toContain("Open AI access");
  });
});

describe("shouldShowMcpNotice", () => {
  const busy = (client: McpMigration["failed"][number]["client"]) => ({ client, reason: "busy" });

  it("shows whatever the backend says until it was dismissed here, then only what newly fails", () => {
    for (const nothing of [null, undefined]) expect(shouldShowMcpNotice(nothing, null)).toBe(false);
    expect(shouldShowMcpNotice({ updated: [], failed: [] }, null)).toBe(true);
    expect(shouldShowMcpNotice({ updated: ["codex"], failed: [] }, [])).toBe(false);
    expect(shouldShowMcpNotice({ updated: [], failed: [busy("claude_code")] }, ["claude_code"])).toBe(false);
    expect(shouldShowMcpNotice({ updated: [], failed: [busy("claude_code"), busy("codex")] }, ["claude_code"])).toBe(true);
    expect(shouldShowMcpNotice({ updated: [], failed: [busy(null)] }, ["claude_code"])).toBe(true);
    expect(shouldShowMcpNotice({ updated: [], failed: [busy(null)] }, [null])).toBe(false);
  });
});

/** The toast `show` was asked for at call `index`: what it renders for its id, and its options. */
function shown(show: ReturnType<typeof vi.fn>, index = 0) {
  const [render, options] = show.mock.calls[index] as [(id: string) => ReactElement, { id: string; duration: number; onDismiss?: () => void }];
  const notice = render(options.id);
  expect(isValidElement(notice) && notice.type).toBe(McpMigrationNotice);
  return { options, props: notice.props as Parameters<typeof McpMigrationNotice>[0] };
}

describe("showMcpMigrationNotice", () => {
  const moved: McpMigration = { updated: ["codex"], failed: [{ client: "claude_code", reason: LINK }] };

  it("shows the notice as a toast that stays until it is dismissed, the reminder alone included", () => {
    for (const shownMove of [{ updated: [], failed: [] }, moved] satisfies McpMigration[]) {
      const show = vi.fn();
      const onDismiss = vi.fn();
      showMcpMigrationNotice(shownMove, onDismiss, show);
      const { options, props } = shown(show);
      expect(options.duration).toBe(Infinity);
      expect([props.updated, props.failed]).toEqual([shownMove.updated, shownMove.failed]);
      const dismiss = vi.spyOn(toast, "dismiss").mockImplementation(() => options.id);
      props.onDismiss!();
      expect(dismiss).toHaveBeenCalledWith(options.id);
      expect(onDismiss).toHaveBeenCalledWith(shownMove.failed.map(failed => failed.client));
      props.onOpenSettings!();
      expect(useUiStore.getState()).toMatchObject({ settingsOpen: true, settingsCategory: "ai" });
    }
  });

  it("records a swipe as a dismissal, and the close button once, though the toaster then reports it again", () => {
    const show = vi.fn();
    const onDismiss = vi.fn();
    showMcpMigrationNotice(moved, onDismiss, show);
    // A swipe or flick: the toaster calls only the toast's own `onDismiss`.
    shown(show).options.onDismiss!();
    expect(onDismiss).toHaveBeenCalledExactlyOnceWith(["claude_code"]);

    const pressed = vi.fn();
    showMcpMigrationNotice(moved, pressed, show);
    const { options, props } = shown(show, 1);
    vi.spyOn(toast, "dismiss").mockImplementation(() => options.id);
    props.onDismiss!();
    // `toast.dismiss` ends in the same `onDismiss` once the toaster removes the toast.
    options.onDismiss!();
    expect(pressed).toHaveBeenCalledExactlyOnceWith(["claude_code"]);
  });
});

describe("mcpNoticeHost", () => {
  const moved: McpMigration = { updated: ["codex"], failed: [{ client: "claude_code", reason: LINK }] };

  it("records a dismissal for later starts, and does not show the notice again in this window unless something newly fails", () => {
    const show = vi.fn();
    const remember = vi.fn(() => Promise.resolve());
    const host = mcpNoticeHost(remember, show);
    host.update(undefined);
    host.update(null);
    expect(show).not.toHaveBeenCalled();
    host.update(moved);
    expect(show).toHaveBeenCalledTimes(1);
    vi.spyOn(toast, "dismiss").mockImplementation(() => "");
    shown(show).props.onDismiss!();
    expect(remember).toHaveBeenCalledWith(["claude_code"]);
    // The window comes back: the same client still fails, for another reason, in a new answer.
    host.update({ ...moved, failed: [{ client: "claude_code", reason: "Its settings file changed while Lunport was updating it." }] });
    host.update(null);
    expect(show).toHaveBeenCalledTimes(1);
    host.update({ updated: [], failed: [...moved.failed, { client: "codex", reason: "busy" }] });
    expect(show).toHaveBeenCalledTimes(2);
  });

  it("keeps a swiped notice dismissed here and records it for later starts", () => {
    const show = vi.fn();
    const remember = vi.fn(() => Promise.resolve());
    const host = mcpNoticeHost(remember, show);
    host.update(moved);
    shown(show).options.onDismiss!();
    expect(remember).toHaveBeenCalledExactlyOnceWith(["claude_code"]);
    host.update({ ...moved });
    expect(show).toHaveBeenCalledTimes(1);
  });

  it("keeps a dismissal in this window when it could not be recorded", async () => {
    const show = vi.fn();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const host = mcpNoticeHost(() => Promise.reject(new Error("Another Lunport is moving its data right now.")), show);
    host.update(moved);
    vi.spyOn(toast, "dismiss").mockImplementation(() => "");
    shown(show).props.onDismiss!();
    await vi.waitFor(() => expect(warn).toHaveBeenCalled());
    host.update(moved);
    expect(show).toHaveBeenCalledTimes(1);
  });
});

describe("McpMigrationToast", () => {
  it("asks the backend once the app opens, and again whenever the window comes back", async () => {
    const calls = stubBackend(async () => null);
    const client = new QueryClient();
    renderToStaticMarkup(<QueryClientProvider client={client}><McpMigrationToast /></QueryClientProvider>);
    const query = client.getQueryCache().find({ queryKey: mcpMigrationKey });
    expect((query?.options as { refetchOnWindowFocus?: unknown } | undefined)?.refetchOnWindowFocus).toBe("always");
    await query!.fetch();
    expect(calls.map(([command]) => command)).toEqual(["identity_migration_mcp_settings"]);
  });
});
