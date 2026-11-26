import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { ConsoleState } from "@/lib/database-console-session";
import type { DatabaseTab } from "@/stores/terminals";
import { DISABLED, buttonTag, text } from "@/components/keychain/test-markup";
import { ConsoleView, type ConsoleActions } from "./DatabaseConsolePane";

const TAB: DatabaseTab = {
  kind: "database",
  id: "tab-1",
  databaseId: "00000000000000a1",
  name: "Orders",
  address: "orders-pg · acme-prod-123456",
  environment: "prod",
  readOnly: "locked",
  state: "open",
};
const state = (patch: Partial<ConsoleState> = {}): ConsoleState => ({
  status: "open",
  message: null,
  opened: { read_only: "locked", iam_user: "frank@example.com", server_version: "16.3" },
  running: false,
  results: [],
  messages: [],
  activeResult: null,
  schema: { schemas: [], truncated: false },
  schemaError: null,
  preview: null,
  ...patch,
});
const actions = (): ConsoleActions => ({
  run: vi.fn(),
  browse: vi.fn(),
  cancel: vi.fn(),
  reconnect: vi.fn(),
  openNotLocked: vi.fn(),
  close: vi.fn(),
  refreshSchema: vi.fn(),
  showResult: vi.fn(),
  showPage: vi.fn(),
  exportResult: vi.fn(),
});

function render(current: ConsoleState, { mac = true, notice = null as string | null } = {}) {
  return renderToStaticMarkup(
    <ConsoleView tab={TAB} state={current} mac={mac} notice={notice} viewRef={{ current: null }} statusBar={null} actions={actions()} />,
  );
}

describe("ConsoleView", () => {
  it("a_session_without_the_lock_offers_to_open_without_it", () => {
    const html = render(state({ status: "lock_unsupported", opened: null, message: "This instance does not support Cloud SQL's read-only lock." }));
    const words = text(html);
    expect(words).toContain("This instance does not support Cloud SQL's read-only lock.");
    expect(words).toContain(
      "You can open it read-only without the lock: Lunport sets default_transaction_read_only, which a statement in the session could turn off.",
    );
    expect(buttonTag(html, "Open read-only (not locked)")).not.toContain(DISABLED);
    expect(buttonTag(html, "Close")).not.toContain(DISABLED);
  });

  it("an_ended_session_offers_to_reconnect_and_keeps_the_editor", () => {
    const html = render(state({ status: "ended", message: "The connection ended. Reconnect to go on." }));
    expect(text(html)).toContain("The connection ended. Reconnect to go on.");
    expect(buttonTag(html, "Reconnect")).not.toContain(DISABLED);
    expect(html).toContain('class="console-editor"');
  });

  it("a_failed_open_offers_to_reconnect", () => {
    const html = render(state({ status: "error", opened: null, message: "Sign-in to Cloud SQL timed out." }));
    expect(text(html)).toContain("Sign-in to Cloud SQL timed out.");
    expect(buttonTag(html, "Reconnect")).not.toContain(DISABLED);
  });

  it("the_toolbar_has_run_run_all_and_cancel_only", () => {
    const html = render(state());
    const words = text(html);
    expect(words).toContain("Run ⌘↩");
    expect(words).toContain("Run all ⇧⌘↩");
    expect(words).toContain("Read-only (locked)");
    expect(words).not.toMatch(/History|Format|Copy/);
    expect(buttonTag(html, "Run ⌘↩")).not.toContain(DISABLED);
    expect(buttonTag(html, "Cancel")).toContain(DISABLED);
  });

  it("off_macos_the_keys_read_ctrl", () => {
    const words = text(render(state(), { mac: false }));
    expect(words).toContain("Run Ctrl+↩");
    expect(words).toContain("Run all Shift+Ctrl+↩");
  });

  it("while_running_only_cancel_is_on", () => {
    const html = render(state({ running: true }));
    expect(buttonTag(html, "Run ⌘↩")).toContain(DISABLED);
    expect(buttonTag(html, "Run all ⇧⌘↩")).toContain(DISABLED);
    expect(buttonTag(html, "Cancel")).not.toContain(DISABLED);
  });

  it("run_waits_for_an_open_session", () => {
    const html = render(state({ status: "opening", opened: null }));
    expect(buttonTag(html, "Run ⌘↩")).toContain(DISABLED);
    expect(buttonTag(html, "Run all ⇧⌘↩")).toContain(DISABLED);
  });

  it("a_not_locked_session_says_so_in_the_pill", () => {
    const html = render(state({ opened: { read_only: "not_locked", iam_user: "frank@example.com", server_version: "16.3" } }));
    expect(text(html)).toContain("Read-only (not locked)");
  });

  it("gives a table preview the workspace and keeps the SQL editor mounted", () => {
    const html = render(state({
      preview: { schema: "public", relation: "orders" },
    }));
    expect(text(html)).toContain("public.orders");
    expect(buttonTag(html, "Data")).toContain('aria-pressed="true"');
    expect(buttonTag(html, "Columns")).toContain('aria-pressed="false"');
    expect(buttonTag(html, "SQL editor")).toContain('aria-expanded="false"');
    expect(html).toMatch(/class="console-editor" hidden=""/);
    expect(text(html)).toContain("Read-only (locked)");
  });

  it("a_notice_shows_why_nothing_ran", () => {
    expect(text(render(state(), { notice: "Place the cursor in a statement." }))).toContain("Place the cursor in a statement.");
  });
});
