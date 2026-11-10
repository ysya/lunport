import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DatabaseRow, DatabasesPanel } from "./DatabasesPanel";
import { EnvironmentBadge } from "./DatabaseBadges";
import { LibraryNavigation, type WorkspacePanel } from "./LibraryNavigation";
import { recordOverview } from "./fixtures";
import { DISABLED, buttonTag, buttonsIn, elementsOf, text, textIn } from "@/components/keychain/test-markup";
import { Dialog } from "@/components/ui/dialog";
import { AlertDialog } from "@/components/ui/alert-dialog";
import { PageHeader } from "@/components/app/PageHeader";
import { renderHook } from "@/lib/test-ipc";
import { tauriInvoke } from "@/lib/ipc";
import { databasesKey, type DatabasePhase, type DatabaseView, type SavedDatabase } from "@/lib/databases";
import type { PamStatusView } from "@/lib/transports";

const ui = vi.hoisted(() => ({ librarySidebarCollapsed: false, collapsedRecordGroups: [] as string[], toggleRecordGroup: () => {} }));
vi.mock("@/lib/ipc", () => ({ tauriInvoke: vi.fn() }));
vi.mock("@/stores/ui", () => ({ useUiStore: (selector: (state: typeof ui) => unknown) => selector(ui) }));

const MINUTE = 60_000;
const AT = new Date(2027, 0, 15, 10, 0).getTime(); // 10:00 on this computer's clock
const PAM = { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 1800, justification: null };
const ORDERS: SavedDatabase = {
  id: "00000000000000a1",
  name: "Orders",
  engine: "postgres",
  project: "acme-prod-123456",
  region: "asia-east1",
  instance: "orders-pg",
  environment: "prod",
  network: "public",
  account: "frank@example.com",
  default_database: "postgres",
  pam: PAM,
  local_port: 6543,
};
const live = (phase: DatabasePhase, patch: Partial<DatabaseView["live"]> = {}): DatabaseView["live"] => ({ phase, port: phase === "stopped" || phase === "error" ? null : 6543, connections: 0, writable_until_ms: null, error: null, ...patch });
/** A saved database as the list shows it: stopped, synced, held by nothing. */
function row(patch: Partial<DatabaseView> = {}, database: Partial<SavedDatabase> = {}): DatabaseView {
  return { database: { ...ORDERS, ...database }, live: live("stopped"), synced: true, blocked: false, removed: false, ...patch };
}
const status = (patch: Partial<PamStatusView>): PamStatusView => ({ entitlement: "prod-operate", state: "active", active_until_ms: AT + 30 * MINUTE, message: null, ...patch });

const invoke = vi.mocked(tauriInvoke);
const lastInvoke = (command: string) => invoke.mock.calls.filter(([name]) => name === command).slice(-1)[0]?.[1] as Record<string, unknown>;
const grantQueries = (client: QueryClient) => client.getQueryCache().findAll({ queryKey: ["gcp", "pam-status", "database"] });

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(AT);
  invoke.mockReset();
});
afterEach(() => vi.restoreAllMocks());

/** The panel over `rows` (none: the list is still loading), as a server render draws it: the grants its rows read are not read yet. */
function render(rows?: DatabaseView[], overview = recordOverview()) {
  const client = new QueryClient();
  if (rows) client.setQueryData(databasesKey, rows);
  return renderToStaticMarkup(<QueryClientProvider client={client}><DatabasesPanel overview={overview} /></QueryClientProvider>);
}

/**
 * The panel once the grants its rows read are answered. A server render never reads them: this draws the panel once, which makes the
 * grant queries its rows hold, runs those through the real fetcher against the mocked command, and draws it again with what they found.
 */
async function renderWithGrants(rows: DatabaseView[], answer: PamStatusView | Error = status({})) {
  invoke.mockImplementation(async (command: string) => {
    if (command !== "databases_pam_status") throw new Error(`unexpected command ${command}`);
    if (answer instanceof Error) throw answer;
    return answer;
  });
  // A mounting row reads again whatever the last read found; this one draws what that read left, even a failure.
  const client = new QueryClient({ defaultOptions: { queries: { retryOnMount: false } } });
  client.setQueryData(databasesKey, rows);
  const draw = () => renderToStaticMarkup(<QueryClientProvider client={client}><DatabasesPanel overview={recordOverview()} /></QueryClientProvider>);
  draw();
  await Promise.all(grantQueries(client).map((query) => query.fetch().catch(() => undefined)));
  return { client, html: draw() };
}

/** The opening tag of the icon button labelled `label`. */
function iconButton(html: string, label: string): string {
  const tag = html.match(new RegExp(`<button[^>]*aria-label="${label}"[^>]*>`));
  if (!tag) throw new Error(`no ${label} button`);
  return tag[0];
}

/** The opening tag of the grant line of the first row that has one. */
const grantLineTag = (html: string) => html.match(/<span class="mt-1 flex[^"]*"[^>]*>/)?.[0] ?? "";

/** The class names of the first element in `html`. */
const classesOf = (html: string) => new Set((html.match(/class="([^"]*)"/)?.[1] ?? "").split(/\s+/));

describe("the Databases page", () => {
  it("renders_a_prod_database_with_its_badge_route_and_grant_line", async () => {
    const { html } = await renderWithGrants([row()]);
    const shown = text(html);
    expect(shown).toContain("Databases 1");
    expect(shown).toContain("Cloud SQL connections that Lunport signs in to for your other apps.");
    expect(shown).toMatch(/Orders\s+PROD/);
    expect(shown).toContain("PostgreSQL · acme-prod-123456 · asia-east1 · orders-pg");
    expect(shown).toContain("127.0.0.1:6543");
    // The grant its row needs, read for this database as a host's is read for its route.
    expect(shown).toContain("prod-operate · Active until 10:30");
    expect(lastInvoke("databases_pam_status")).toEqual({ id: ORDERS.id });
    expect(invoke.mock.calls.map(([command]) => command)).toEqual(["databases_pam_status"]);
  });

  it("shows_the_header_the_search_and_the_columns", () => {
    const html = render([row()]);
    expect(html).toContain('id="new-database-button"');
    expect(buttonTag(html, "New database")).not.toContain(DISABLED);
    expect(html).toContain('id="databases-search"');
    expect(html).toContain('placeholder="Search databases or projects…"');
    expect(text(html)).toMatch(/Database\s+Local address\s+Status\s+Actions/);
  });

  it("loads_before_it_lists_and_explains_an_empty_list", () => {
    expect(text(render())).toContain("Loading databases…");
    expect(text(render([]))).toContain("Your Cloud SQL databases, within reach");
    expect(render([])).toContain('id="new-database-button"');
  });

  it("holds_back_a_new_database_while_the_library_is_paused", () => {
    const paused = recordOverview({ account: { chain_id: "c".repeat(32), device_name: "laptop" }, shared_writes_blocked: true });
    expect(buttonTag(render([row()], paused), "New database")).toContain(DISABLED);
    // Without an account nothing is shared, so nothing is paused.
    expect(buttonTag(render([row()], recordOverview({ shared_writes_blocked: true })), "New database")).not.toContain(DISABLED);
  });

  it("a_database_without_a_local_port_has_no_start_button", () => {
    const html = render([row({}, { local_port: null, pam: null })]);
    expect(text(html)).toContain("Not shared");
    expect(html).not.toContain("127.0.0.1");
    expect(html).not.toMatch(/>(Start|Stop|Retry)<\/button>/);
    // It can still be edited and deleted.
    expect(iconButton(html, "Edit Orders")).not.toContain(DISABLED);
    expect(iconButton(html, "Delete Orders")).not.toContain(DISABLED);
    // The same database with a port can be started.
    expect(render([row({}, { pam: null })])).toContain(">Start</button>");
  });

  it("edit_and_delete_are_disabled_while_running", () => {
    const stopped = render([row({}, { pam: null })]);
    expect(iconButton(stopped, "Edit Orders")).not.toContain(DISABLED);
    expect(iconButton(stopped, "Delete Orders")).not.toContain(DISABLED);
    expect(buttonTag(stopped, "Start")).not.toContain(DISABLED);
    for (const phase of ["starting", "running", "stopping"] as const) {
      const html = render([row({ live: live(phase, { connections: 2 }) }, { pam: null })]);
      expect(iconButton(html, "Edit Orders"), phase).toContain(DISABLED);
      expect(iconButton(html, "Delete Orders"), phase).toContain(DISABLED);
      expect(html, phase).toContain(">Stop</button>");
      expect(html, phase).not.toContain(">Start</button>");
    }
    // A running database is stopped; one that is already stopping cannot be asked again.
    expect(buttonTag(render([row({ live: live("running") }, { pam: null })]), "Stop")).not.toContain(DISABLED);
    expect(buttonTag(render([row({ live: live("stopping") }, { pam: null })]), "Stop")).toContain(DISABLED);
    // A library whose writes are blocked changes no database, a running one or not.
    const blocked = render([row({ blocked: true }, { pam: null })]);
    expect(iconButton(blocked, "Edit Orders")).toContain(DISABLED);
    expect(iconButton(blocked, "Delete Orders")).toContain(DISABLED);
  });

  it("names_start_stop_and_retry_by_their_database", () => {
    const sentence = "Port 6543 is already in use on this computer.";
    expect(buttonTag(render([row({}, { pam: null })]), "Start")).toContain('aria-label="Start Orders"');
    expect(buttonTag(render([row({ live: live("running") }, { pam: null })]), "Stop")).toContain('aria-label="Stop Orders"');
    expect(buttonTag(render([row({ live: live("error", { error: sentence }) }, { pam: null })]), "Retry")).toContain('aria-label="Retry Orders"');
    // A row names its own button among several, and a name's hidden characters show as codes in the label too.
    const two = render([row({}, { pam: null }), row({ live: live("running") }, { id: "00000000000000a2", name: "Ord\u202eers", pam: null })]);
    expect(two).toContain('aria-label="Start Orders"');
    expect(two).toContain('aria-label="Stop Ord⟨U+202E⟩ers"');
    expect(two).not.toContain("\u202e");
    // The removed row's Stop is named too.
    expect(buttonTag(render([row({ live: live("running"), removed: true, blocked: true })]), "Stop")).toContain('aria-label="Stop Orders"');
  });

  it("a_running_database_whose_saved_port_was_cleared_can_still_be_stopped", () => {
    // Another device cleared the port from the record while this computer's port went on running.
    const cleared = { local_port: null, pam: null };
    for (const phase of ["starting", "running"] as const) {
      const html = render([row({ live: live(phase, { connections: 1 }) }, cleared)]);
      expect(buttonTag(html, "Stop"), phase).not.toContain(DISABLED);
      expect(html, phase).not.toMatch(/>(Start|Retry)<\/button>/);
      // The address shown is the port that runs, not the one the record no longer holds.
      expect(text(html), phase).toContain("127.0.0.1:6543");
    }
    // A port that is already stopping waits.
    expect(buttonTag(render([row({ live: live("stopping") }, cleared)]), "Stop")).toContain(DISABLED);
    // Once it has stopped there is no port to offer: neither Start nor Stop, and a failed start has no port to retry on.
    expect(render([row({}, cleared)])).not.toMatch(/>(Start|Stop|Retry)<\/button>/);
    expect(render([row({ live: live("error", { error: "Port 6543 is already in use on this computer." }) }, cleared)])).not.toMatch(/>(Start|Stop|Retry)<\/button>/);
  });

  it("the_library_navigation_lists_databases_after_tunnels", () => {
    const navigation = (panel: WorkspacePanel) => renderToStaticMarkup(
      <LibraryNavigation overview={recordOverview()} panel={panel} filter={{ kind: "all" }} navigate={vi.fn()} changeFilter={vi.fn()} createGroup={vi.fn()} />,
    );
    const html = navigation("hosts");
    const library = html.slice(html.indexOf('aria-label="Workspace sections"'), html.indexOf('aria-label="Cloud providers"'));
    const order = ["All hosts (1)", "Keys (0)", "Tunnels", "Databases"].map((label) => library.indexOf(`aria-label="${label}"`));
    expect(order.every((at) => at >= 0), "every row is there").toBe(true);
    expect(order, "in this order").toEqual([...order].sort((a, b) => a - b));
    // It shows no count, as Tunnels shows none, and is the current page only on its own page.
    expect(html).not.toContain('aria-label="Databases (');
    expect(html).not.toContain('aria-current="page" aria-label="Databases"');
    expect(navigation("databases")).toContain('aria-current="page" aria-label="Databases"');
    expect(navigation("databases")).not.toContain('aria-current="page" aria-label="Tunnels"');
  });

  it("a_grant_ending_within_five_minutes_warns_without_a_request_button", async () => {
    // Four minutes left: the minutes, in the warning color, and when a new grant can be requested. PAM takes no second request while
    // one is active, so there is no button.
    const ending = await renderWithGrants([row()], status({ active_until_ms: AT + 4 * MINUTE }));
    expect(text(ending.html)).toContain("Grant ends in 4 min");
    expect(text(ending.html)).toContain("You can request a new grant when this one ends.");
    expect(text(ending.html)).not.toContain("Active until");
    expect(grantLineTag(ending.html)).toContain("text-warning");
    expect(ending.html).not.toContain("Request grant");
    // Five minutes exactly still warns.
    const edge = await renderWithGrants([row()], status({ active_until_ms: AT + 5 * MINUTE }));
    expect(text(edge.html)).toContain("Grant ends in 5 min");
    expect(edge.html).not.toContain("Request grant");
    // More than five minutes left: held, in the primary color, with nothing to add and nothing to request.
    const held = await renderWithGrants([row()], status({ active_until_ms: AT + 5 * MINUTE + 1 }));
    expect(text(held.html)).toContain("prod-operate · Active until 10:05");
    expect(text(held.html)).not.toContain("You can request a new grant");
    expect(grantLineTag(held.html)).toContain("text-primary");
    expect(held.html).not.toContain("Request grant");
  });

  it("a_missing_or_ended_grant_offers_request_grant", async () => {
    const none = status({ state: "none", entitlement: null, active_until_ms: null });
    // An end that is now, or has passed some time ago, is an ended grant.
    for (const [what, answer] of [["none", none], ["ended just now", status({ active_until_ms: AT })], ["ended earlier", status({ active_until_ms: AT - 3 * MINUTE })]] as const) {
      const { html } = await renderWithGrants([row()], answer);
      expect(text(html), what).toContain("Needs a grant: prod-operate, prod-admin");
      expect(grantLineTag(html), what).toContain("text-warning");
      expect(buttonTag(html, "Request grant"), what).toContain('aria-label="Request grant for Orders"');
      expect(buttonTag(html, "Request grant"), what).not.toContain(DISABLED);
      expect(text(html), what).not.toContain("You can request a new grant");
    }
    // Each database that lacks a grant offers a button of its own, named for it.
    const two = await renderWithGrants([row(), row({}, { id: "00000000000000a2", name: "Analytics" })], none);
    expect(two.html.match(/>Request grant<\/button>/g)).toHaveLength(2);
    expect(two.html).toContain('aria-label="Request grant for Analytics"');
  });

  it("a_grant_whose_end_has_passed_reads_as_missing_not_as_a_negative_number", async () => {
    const { html } = await renderWithGrants([row()], status({ active_until_ms: AT - 2 * MINUTE }));
    expect(text(html)).toContain("Needs a grant: prod-operate, prod-admin");
    expect(text(html)).not.toMatch(/ends in -|-\d+ min/);
    expect(html).toContain(">Request grant</button>");
  });

  it("offers_no_request_for_a_grant_that_is_on_its_way_waits_for_its_approver_or_could_not_be_read", async () => {
    const activating = await renderWithGrants([row()], status({ state: "activating", entitlement: "prod-admin", active_until_ms: null }));
    expect(text(activating.html)).toContain("prod-admin · Activating…");
    expect(activating.html).not.toContain("Request grant");
    const awaiting = await renderWithGrants([row()], status({ state: "approval_awaited", entitlement: "prod-admin", active_until_ms: null }));
    expect(text(awaiting.html)).toContain("prod-admin · Awaiting approval");
    expect(awaiting.html).not.toContain("Request grant");
    // The API's own sentence, and the command failing, are said instead of a missing grant.
    const refusal = "Privileged Access Manager refused the request: quota exceeded.";
    const refused = await renderWithGrants([row()], status({ state: "error", entitlement: null, active_until_ms: null, message: refusal }));
    expect(text(refused.html)).toContain(refusal);
    expect(text(refused.html)).not.toContain("Needs a grant");
    expect(refused.html).not.toContain("Request grant");
    const failed = await renderWithGrants([row()], new Error("Google did not answer."));
    expect(text(failed.html)).toContain("Google did not answer.");
    expect(text(failed.html)).not.toContain("Needs a grant");
    expect(failed.html).not.toContain("Request grant");
    // Until the first read is back the line says so.
    expect(text(render([row()]))).toContain("Checking the grant…");
  });

  it("shows_a_grant_line_only_for_a_database_that_asks_for_a_grant", async () => {
    const { client, html } = await renderWithGrants([row({}, { pam: null })]);
    expect(html).not.toContain("grant");
    expect(grantQueries(client)).toHaveLength(0);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("reads_each_databases_grant_once_and_by_its_own_identity", async () => {
    const other = { id: "00000000000000a2", name: "Analytics", environment: "staging" as const };
    const { client, html } = await renderWithGrants([row(), row({}, other)]);
    expect(grantQueries(client)).toHaveLength(2);
    expect(invoke.mock.calls.map(([command, args]) => [command, args])).toEqual([
      ["databases_pam_status", { id: ORDERS.id }],
      ["databases_pam_status", { id: other.id }],
    ]);
    expect(text(html).match(/prod-operate · Active until 10:30/g)).toHaveLength(2);
  });

  it("names_each_phase_and_counts_the_connections_of_a_running_database", () => {
    const phases: [DatabasePhase, string][] = [["stopped", "Stopped"], ["starting", "Starting"], ["running", "Running"], ["stopping", "Stopping"], ["error", "Failed"]];
    for (const [phase, label] of phases) expect(text(render([row({ live: live(phase) }, { pam: null })])), phase).toContain(label);
    expect(text(render([row({ live: live("running", { connections: 1 }) }, { pam: null })]))).toContain("1 active connection");
    expect(text(render([row({ live: live("running", { connections: 0 }) }, { pam: null })]))).toContain("0 active connections");
    expect(text(render([row({ live: live("running", { connections: 3 }) }, { pam: null })]))).toContain("3 active connections");
    // A port that is not running has no connections to count.
    expect(text(render([row({ live: live("stopped") }, { pam: null })]))).not.toContain("active connection");
    expect(text(render([row({ live: live("stopping", { connections: 3 }) }, { pam: null })]))).not.toContain("active connection");
  });

  it("a_failed_database_says_why_under_failed_and_can_be_started_again", () => {
    const sentence = "Port 6543 is already in use on this computer.";
    const html = render([row({ live: live("error", { error: sentence }) }, { pam: null })]);
    expect(text(html)).toMatch(/Failed\s+Port 6543 is already in use on this computer\./);
    expect(html).toContain(">Retry</button>");
    expect(buttonTag(html, "Retry")).not.toContain(DISABLED);
    // It stays editable and deletable: nothing runs.
    expect(iconButton(html, "Edit Orders")).not.toContain(DISABLED);
    expect(iconButton(html, "Delete Orders")).not.toContain(DISABLED);
    // The sentence is shown with its invisible characters as codes.
    expect(text(render([row({ live: live("error", { error: "Port 6543\u202e is in use." }) }, { pam: null })]))).toContain("Port 6543⟨U+202E⟩ is in use.");
  });

  it("a_removed_row_shows_its_name_and_a_stop_button_only", async () => {
    const gone = row({ live: live("running", { connections: 2 }), removed: true, blocked: true, synced: false });
    const { client, html } = await renderWithGrants([gone]);
    const shown = text(html);
    expect(shown).toContain("Orders");
    expect(shown).toContain("Deleted on another device. Stop this running database to remove it here.");
    expect(html).toContain(">Stop</button>");
    expect(buttonTag(html, "Stop")).not.toContain(DISABLED);
    // Nothing else can be done with it, and nothing is asked of Google for a record that is gone.
    expect(html).not.toMatch(/>(Start|Retry|Request grant)<\/button>/);
    expect(html).not.toContain('aria-label="Edit Orders"');
    expect(html).not.toContain('aria-label="Delete Orders"');
    expect(shown).not.toContain("PROD");
    expect(shown).not.toContain("PostgreSQL");
    expect(shown).not.toContain("prod-operate");
    expect(grantQueries(client)).toHaveLength(0);
    expect(invoke).not.toHaveBeenCalled();
    // Once it is stopping the only button waits.
    expect(buttonTag(render([{ ...gone, live: live("stopping") }]), "Stop")).toContain(DISABLED);
  });

  it("marks_a_database_that_needs_a_sync_review_and_one_that_is_kept_on_this_computer", () => {
    const html = text(render([row({ blocked: true }, { pam: null }), row({ synced: false }, { id: "00000000000000a2", name: "Scratch", pam: null })]));
    expect(html).toContain("Sync review needed");
    expect(html).toContain("Synced database");
    expect(html).toContain("On this computer");
  });

  it("shows_a_names_hidden_characters_as_codes", () => {
    const html = render([row({}, { name: "Ord\u202eers", pam: null })]);
    expect(text(html)).toContain("Ord⟨U+202E⟩ers");
    expect(html).not.toContain("\u202e");
  });

  it("never_asks_for_a_port_password_or_keeps_one_in_the_cache", async () => {
    const { client } = await renderWithGrants([row()]);
    expect(invoke.mock.calls.map(([command]) => command).filter((command) => /password/.test(command))).toEqual([]);
    const cached = JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data));
    expect(cached).not.toMatch(/password/i);
  });
});

describe("opening the editor from the page", () => {
  const labelOf = (button: { props: unknown }) => (button.props as { "aria-label"?: string })["aria-label"];

  it("a_rows_name_and_edit_button_both_open_the_editor_for_that_row", () => {
    const [toggle, requestGrant, ask, edit] = [vi.fn(), vi.fn(), vi.fn(), vi.fn()];
    const buttons = buttonsIn(DatabaseRow({ row: row({}, { pam: null }), busy: false, toggle, requestGrant, ask, edit }));
    buttons.find((button) => textIn(button) === "Orders")!.props.onClick!();
    expect(edit).toHaveBeenCalledTimes(1);
    buttons.find((button) => labelOf(button) === "Edit Orders")!.props.onClick!();
    expect(edit).toHaveBeenCalledTimes(2);
    // Neither starts, stops, deletes or asks for a grant.
    expect([toggle, ask, requestGrant].map((fn) => fn.mock.calls.length)).toEqual([0, 0, 0]);
  });

  it("the_name_is_a_button_that_is_held_back_when_the_edit_button_is", () => {
    const stopped = render([row({}, { pam: null })]);
    expect(buttonTag(stopped, "Orders")).not.toContain(DISABLED);
    for (const phase of ["starting", "running", "stopping"] as const) expect(buttonTag(render([row({ live: live(phase) }, { pam: null })]), "Orders"), phase).toContain(DISABLED);
    expect(buttonTag(render([row({ blocked: true }, { pam: null })]), "Orders")).toContain(DISABLED);
    // A row that is only listed to be stopped has nothing to edit: its name is words, not a button.
    const gone = render([row({ live: live("running"), removed: true, blocked: true })]);
    expect(() => buttonTag(gone, "Orders")).toThrow("no Orders button");
    expect(text(gone)).toContain("Orders");
    // The name keeps its tooltip and its hidden characters as codes.
    expect(render([row({}, { name: "Ord\u202eers", pam: null })])).toContain("Ord⟨U+202E⟩ers");
  });

  it("the_header_opens_the_editor_and_nothing_is_open_until_it_is_asked", () => {
    const client = new QueryClient();
    client.setQueryData(databasesKey, [row()]);
    const tree = renderHook(client, () => DatabasesPanel({ overview: recordOverview() }));
    const header = elementsOf(tree, PageHeader)[0].props as unknown as { actions: ReactNode };
    expect(buttonsIn(header.actions).find((button) => textIn(button) === "New database")?.props.onClick).toBeTypeOf("function");
    expect((elementsOf(tree, Dialog)[0].props as unknown as { open: boolean }).open).toBe(false);
    expect(elementsOf(tree, DatabaseRow)).toHaveLength(1);
    expect(typeof (elementsOf(tree, DatabaseRow)[0].props as unknown as { edit: unknown }).edit).toBe("function");
  });

  it("closing_the_dialog_with_changes_asks_with_the_words_the_tunnels_page_uses", () => {
    const client = new QueryClient();
    client.setQueryData(databasesKey, [row()]);
    const tree = renderHook(client, () => DatabasesPanel({ overview: recordOverview() }));
    // The delete confirmation is the other one; the dialog that asks about discarding is closed until a changed dialog is closed.
    const asking = elementsOf(tree, AlertDialog).filter((dialog) => textIn(dialog).includes("Discard database changes?"));
    expect(asking).toHaveLength(1);
    expect(elementsOf(tree, AlertDialog)).toHaveLength(2);
    expect((asking[0].props as unknown as { open: boolean }).open).toBe(false);
    expect(textIn(asking[0])).toContain("Your unsaved changes will be lost.");
    const answers = buttonsIn(asking[0]).map((button) => textIn(button));
    expect(answers).toContain("Discard");
    expect(textIn(asking[0])).toContain("Keep editing");
    // Escape, a click outside and the X all go to the same place as Cancel: the editor dialog's own close handler.
    expect(typeof (elementsOf(tree, Dialog)[0].props as unknown as { onOpenChange: unknown }).onOpenChange).toBe("function");
  });
});

describe("the environment badge", () => {
  const badge = (environment: Parameters<typeof EnvironmentBadge>[0]["environment"]) => renderToStaticMarkup(<EnvironmentBadge environment={environment} />);

  it("draws_prod_solid_staging_in_a_warning_tint_and_dev_muted", () => {
    const prod = classesOf(badge("prod"));
    expect(text(badge("prod")).trim()).toBe("PROD");
    expect(prod.has("bg-destructive")).toBe(true);
    expect(prod.has("text-background")).toBe(true);
    const staging = classesOf(badge("staging"));
    expect(text(badge("staging")).trim()).toBe("STAGING");
    expect(staging.has("bg-warning/10")).toBe(true);
    expect(staging.has("text-warning")).toBe(true);
    expect(staging.has("bg-destructive")).toBe(false);
    const dev = classesOf(badge("dev"));
    expect(text(badge("dev")).trim()).toBe("DEV");
    expect(dev.has("bg-muted")).toBe(true);
    expect(dev.has("text-muted-foreground")).toBe(true);
    expect(dev.has("bg-destructive")).toBe(false);
    expect(dev.has("text-warning")).toBe(false);
  });
});
