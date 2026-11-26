import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { ConsoleState } from "@/lib/database-console-session";
import { DISABLED, buttonTag, text } from "@/components/keychain/test-markup";
import { ConsoleView, type ConsoleActions } from "./DatabaseConsolePane";
import { ConsoleStatusBar } from "./ConsoleStatusBar";

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
    <ConsoleView state={current} mac={mac} notice={notice} viewRef={{ current: null }} actions={actions()}
      connectionStatus={<ConsoleStatusBar environment="prod" database={null} route={{ alias: null, iap: false }}
        iamUser={current.opened?.iam_user ?? null} readOnly={current.opened?.read_only ?? null} grant={null} />} />,
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

  it("the_toolbar_hides_cancel_until_a_query_runs", () => {
    const html = render(state());
    const words = text(html);
    expect(words).toContain("Run ⌘↩");
    expect(words).toContain("Run all ⇧⌘↩");
    expect(words).toContain("Read-only (locked)");
    expect(words).not.toMatch(/History|Format|Copy/);
    expect(buttonTag(html, "Run ⌘↩")).not.toContain(DISABLED);
    expect(words).not.toContain("Cancel");
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

  it("keeps the schema toggle and table operations on the same toolbar", () => {
    const html = render(state({ preview: { schema: "public", relation: "orders" } }));
    const toolbar = html.slice(html.indexOf('class="console-toolbar"'), html.indexOf('class="console-editor"'));
    expect(toolbar).toContain('aria-label="Hide schema"');
    expect(toolbar).toContain("public.orders");
    expect(toolbar).toContain("Columns");
    expect(toolbar).toContain("SQL editor");
  });

  it("a_notice_shows_why_nothing_ran", () => {
    expect(text(render(state(), { notice: "Place the cursor in a statement." }))).toContain("Place the cursor in a statement.");
  });
});
