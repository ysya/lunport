import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DatabaseAccess, DatabaseRow, DatabasesPanel } from "./DatabasesPanel";
import { EnvironmentBadge } from "./DatabaseBadges";
import { LibraryNavigation, type WorkspacePanel } from "./LibraryNavigation";
import { recordOverview } from "./fixtures";
import { DISABLED, buttonTag, buttonsIn, elementsOf, text, textIn } from "@/components/keychain/test-markup";
import { Dialog } from "@/components/ui/dialog";
import { AlertDialog } from "@/components/ui/alert-dialog";
import { PageHeader } from "@/components/app/PageHeader";
import { renderHook } from "@/lib/test-ipc";
import { tauriInvoke } from "@/lib/ipc";
import { useNow } from "@/lib/use-now";
import { databasesKey, type DatabasePhase, type DatabaseView, type SavedDatabase } from "@/lib/databases";
import { gcloudAccountsKey, type GcloudAccountsView, type PamStatusView } from "@/lib/transports";

const ui = vi.hoisted(() => ({ librarySidebarCollapsed: false, collapsedRecordGroups: [] as string[], toggleRecordGroup: () => {} }));
vi.mock("@/lib/ipc", () => ({ tauriInvoke: vi.fn() }));
vi.mock("@/lib/use-now", () => ({ useNow: vi.fn() }));
vi.mock("@/stores/ui", () => ({ useUiStore: (selector: (state: typeof ui) => unknown) => selector(ui) }));

const SECOND = 1000;
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
/** A saved database as the list shows it: stopped, synced, held by nothing, and shown in the environment it is saved in. */
function row(patch: Partial<DatabaseView> = {}, database: Partial<SavedDatabase> = {}): DatabaseView {
  const saved = { ...ORDERS, ...database };
  return { database: saved, live: live("stopped"), synced: true, blocked: false, removed: false, changed: false, environment: saved.environment, ...patch };
}
const status = (patch: Partial<PamStatusView>): PamStatusView => ({ entitlement: "prod-operate", state: "active", active_until_ms: AT + 30 * MINUTE, message: null, ...patch });

const invoke = vi.mocked(tauriInvoke);
const lastInvoke = (command: string) => invoke.mock.calls.filter(([name]) => name === command).slice(-1)[0]?.[1] as Record<string, unknown>;
const grantQueries = (client: QueryClient) => client.getQueryCache().findAll({ queryKey: ["gcp", "pam-status", "database"] });

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(AT);
  invoke.mockReset();
  // The clock the countdowns and the grant lines re-render by; its value is the time of the last tick, which a test may set behind the time now.
  vi.mocked(useNow).mockReset();
  vi.mocked(useNow).mockImplementation(() => Date.now());
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

describe("the marker of a prod row whose writes are on", () => {
  /** A running prod database, offered on a port, whose writes lock again `left` milliseconds after 10:00. */
  const writable = (left: number, patch: Partial<DatabaseView> = {}, database: Partial<SavedDatabase> = {}) => row({ live: live("running", { writable_until_ms: AT + left }), ...patch }, { pam: null, ...database });
  /** The marker of the first row that has one: the classes of the element that says Writes on, and its words. */
  const marker = (html: string) => {
    const found = html.match(/<span class="([^"]*)">(?:<svg[\s\S]*?<\/svg>)?(Writes on · \d\d:\d\d)<\/span>/);
    return found ? { classes: new Set(found[1].split(/\s+/)), words: found[2] } : null;
  };

  it("a_collapsed_prod_row_whose_writes_are_on_shows_the_time_left_in_the_destructive_style", () => {
    const html = render([writable(14 * MINUTE + 59 * SECOND)]);
    // The details are closed: the danger state is on the row itself.
    expect(html).not.toContain("<section");
    expect(marker(html)?.words).toBe("Writes on · 14:59");
    expect(marker(html)?.classes.has("text-destructive")).toBe(true);
    expect(marker(html)?.classes.has("bg-destructive/10")).toBe(true);
    expect(html).toMatch(/lucide-lock-open/);
  });

  it("a_locked_row_or_one_that_is_not_prod_shows_no_marker", () => {
    // Locked: no window, and a window that has ended by the clock is none, though the list may still hold it for a moment.
    expect(text(render([row({ live: live("running") }, { pam: null })]))).not.toContain("Writes on");
    expect(text(render([writable(0)]))).not.toContain("Writes on");
    expect(text(render([writable(-SECOND)]))).not.toContain("Writes on");
    // Only prod is locked, so only prod has a window, whatever the list says of another.
    for (const environment of ["dev", "staging"] as const) expect(text(render([writable(MINUTE, {}, { environment })])), environment).not.toContain("Writes on");
    // A database that does not run holds no window.
    expect(text(render([row({ live: live("stopped") }, { pam: null })]))).not.toContain("Writes on");
    expect(render([row({ live: live("running") }, { pam: null })])).not.toMatch(/lucide-lock-open/);
  });

  it("marks_each_row_by_its_own_window", () => {
    const html = render([
      writable(5 * MINUTE, {}, { id: "00000000000000a1", name: "Orders" }),
      row({ live: live("running") }, { id: "00000000000000a2", name: "Billing", pam: null }),
      writable(30 * SECOND, {}, { id: "00000000000000a3", name: "Reports" }),
    ]);
    expect(html.match(/Writes on · \d\d:\d\d/g)).toEqual(["Writes on · 05:00", "Writes on · 00:30"]);
  });

  it("a_row_that_runs_although_its_record_is_gone_still_says_that_writes_are_on", () => {
    // It is listed only to be stopped, and stopping it is what ends the window.
    const html = render([writable(10 * MINUTE, { removed: true, blocked: true, synced: false })]);
    expect(marker(html)?.words).toBe("Writes on · 10:00");
    expect(html).toContain(">Stop</button>");
  });

  it("counts_down_from_the_time_at_its_own_render_not_the_one_kept_in_state", () => {
    // The clock keeps its time in state, a second behind; the end of a window that was just unlocked is fresh. Worked out from the two,
    // fifteen minutes would read 15:01 until the next tick.
    vi.mocked(Date.now).mockReturnValue(AT + 900);
    vi.mocked(useNow).mockReturnValue(AT);
    const html = render([row({ live: live("running", { writable_until_ms: AT + 900 + 15 * MINUTE }) }, { pam: null })]);
    expect(marker(html)?.words).toBe("Writes on · 15:00");
    expect(html).not.toContain("15:01");
    expect(vi.mocked(useNow)).toHaveBeenCalledWith(1000);
  });

  it("holds_no_clock_for_a_row_without_a_window", () => {
    // Only a row whose window is open counts down: the grant line of a database with a grant check is the one that asks for the clock.
    render([row({ live: live("running") }, { pam: null }), writable(MINUTE, {}, { id: "00000000000000a2", name: "Reports", environment: "dev" })]);
    expect(vi.mocked(useNow)).not.toHaveBeenCalled();
    render([writable(MINUTE)]);
    expect(vi.mocked(useNow)).toHaveBeenCalledTimes(1);
  });
});

describe("a database another device changed while it runs here", () => {
  const CHANGED = "The database changed on another device. Stop and start it again to apply it.";

  it("says_that_starting_it_again_applies_the_change", () => {
    const html = render([row({ live: live("running", { connections: 1 }), changed: true }, { pam: null })]);
    expect(text(html)).toContain(CHANGED);
    expect(html).toContain(">Stop</button>");
    // One that runs as it is saved, and one that does not run, say nothing of it.
    expect(text(render([row({ live: live("running") }, { pam: null })]))).not.toContain(CHANGED);
    expect(text(render([row({}, { pam: null })]))).not.toContain(CHANGED);
  });

  it("is_badged_and_marked_by_the_environment_its_port_locks_by", () => {
    // Saved as dev elsewhere while its port runs as prod: still PROD, with its writes on marked, until it is started again.
    const html = render([row({ live: live("running", { writable_until_ms: AT + MINUTE }), changed: true, environment: "prod" }, { environment: "dev", pam: null })]);
    expect(text(html)).toMatch(/Orders\s+PROD/);
    expect(text(html)).not.toContain("DEV");
    expect(text(html)).toContain("Writes on · 01:00");
    // Saved as prod elsewhere while its port runs as dev: PROD at once.
    const promoted = render([row({ live: live("running"), changed: true, environment: "prod" }, { environment: "prod", pam: null })]);
    expect(text(promoted)).toMatch(/Orders\s+PROD/);
    // A port that does not lock as prod has no window to mark, whatever the record says.
    expect(text(render([row({ live: live("running", { writable_until_ms: AT + MINUTE }), environment: "dev" }, { pam: null })]))).not.toContain("Writes on");
  });
});

describe("the connection details under a row", () => {
  const labelOf = (button: { props: unknown }) => (button.props as { "aria-label"?: string })["aria-label"];
  const noDetails = { pam: null };
  const shared = (name: string, id: string, patch: Partial<DatabaseView> = {}, database: Partial<SavedDatabase> = {}) => row(patch, { id, name, ...noDetails, ...database });

  it("a_database_with_a_port_has_a_details_button_that_is_closed_until_asked", () => {
    const html = render([row({}, noDetails)]);
    const toggle = iconButton(html, "Connection details for Orders");
    expect(toggle).toContain('aria-expanded="false"');
    expect(toggle).not.toContain(DISABLED);
    // Nothing of the details is drawn, asked for or read until then.
    expect(html).not.toContain("<section");
    expect(text(html)).not.toMatch(/Copy URL|Copy password|Rotate password|postgresql:\/\//);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("the_details_button_controls_the_card_that_carries_its_id", () => {
    const toggle = (open: boolean) => iconButton(renderToStaticMarkup(<table><tbody>{DatabaseRow({ row: row({}, noDetails), busy: false, toggle: vi.fn(), requestGrant: vi.fn(), ask: vi.fn(), edit: vi.fn(), details: { open, toggle: vi.fn() } })}</tbody></table>), "Connection details for Orders");
    // Closed or open, it names the card it opens, which is drawn under the row with that id.
    for (const open of [false, true]) expect(toggle(open), String(open)).toContain('aria-controls="database-details-00000000000000a1"');
    const client = new QueryClient();
    const card = renderToStaticMarkup(<QueryClientProvider client={client}><DatabaseAccess row={row({ live: live("running") }, noDetails)} /></QueryClientProvider>);
    expect(card).toContain(`id="${toggle(true).match(/aria-controls="([^"]*)"/)?.[1]}"`);
    // The card is labelled for what it holds: not with the name of the button that opens it.
    expect(card).toContain('aria-label="Local connection to Orders"');
    expect(card).not.toContain("Connection details for Orders");
    // Each database's toggle controls its own card.
    expect(iconButton(render([row({}, { id: "00000000000000a2", name: "Analytics", pam: null })]), "Connection details for Analytics")).toContain('aria-controls="database-details-00000000000000a2"');
  });

  it("the_details_button_follows_whether_the_details_are_open_and_presses_through", () => {
    const [toggle, requestGrant, ask, edit, details] = [vi.fn(), vi.fn(), vi.fn(), vi.fn(), vi.fn()];
    const drawn = (open: boolean) => DatabaseRow({ row: row({}, noDetails), busy: false, toggle, requestGrant, ask, edit, details: { open, toggle: details } });
    const html = (open: boolean) => renderToStaticMarkup(<table><tbody>{drawn(open)}</tbody></table>);
    expect(iconButton(html(false), "Connection details for Orders")).toContain('aria-expanded="false"');
    expect(iconButton(html(true), "Connection details for Orders")).toContain('aria-expanded="true"');
    // Open, the row leaves out its bottom line so that it and its details read as one.
    expect(html(false).match(/<tr class="([^"]*)"/)?.[1].split(/\s+/)).toContain("border-b");
    expect(html(true).match(/<tr class="([^"]*)"/)?.[1].split(/\s+/)).not.toContain("border-b");
    expect(html(true).match(/<tr class="([^"]*)"/)?.[1].split(/\s+/)).toContain("border-b-0");
    buttonsIn(drawn(false)).find((button) => labelOf(button) === "Connection details for Orders")!.props.onClick!();
    expect(details).toHaveBeenCalledTimes(1);
    // It starts, stops, edits, deletes and asks for nothing.
    expect([toggle, requestGrant, ask, edit].map((fn) => fn.mock.calls.length)).toEqual([0, 0, 0, 0]);
  });

  it("a_row_given_no_details_has_no_details_button", () => {
    const html = renderToStaticMarkup(<table><tbody>{DatabaseRow({ row: row({}, noDetails), busy: false, toggle: vi.fn(), requestGrant: vi.fn(), ask: vi.fn(), edit: vi.fn() })}</tbody></table>);
    expect(html).not.toContain("Connection details");
    // The shared Button's class names carry `aria-expanded:` variants, so only the attribute itself says a button opens something.
    expect(html).not.toContain('aria-expanded="');
  });

  it("only_a_database_offered_on_a_port_with_a_record_gives_details", () => {
    const html = render([
      shared("Orders", "00000000000000a1"),
      shared("Scratch", "00000000000000a2", {}, { local_port: null }),
      shared("Old", "00000000000000a3", { live: live("running"), removed: true, blocked: true }),
      // Another device cleared its port while this one's went on running: the port that runs has details.
      shared("Moved", "00000000000000a4", { live: live("running") }, { local_port: null }),
    ]);
    expect(html).toContain('aria-label="Connection details for Orders"');
    expect(html).not.toContain('aria-label="Connection details for Scratch"');
    expect(html).not.toContain('aria-label="Connection details for Old"');
    expect(html).toContain('aria-label="Connection details for Moved"');
  });

  it("names_each_details_button_by_its_database_with_hidden_characters_as_codes", () => {
    const html = render([shared("Ord\u202eers", "00000000000000a1"), shared("Analytics", "00000000000000a2")]);
    expect(html).toContain('aria-label="Connection details for Ord⟨U+202E⟩ers"');
    expect(html).toContain('aria-label="Connection details for Analytics"');
    expect(html).not.toContain("\u202e");
  });

  describe("and the database user they name", () => {
    const accounts = (active: string | null): GcloudAccountsView => ({ config_found: true, active, accounts: [] });
    /** The details of `database` as a server render draws them, with gcloud's accounts as they were read (none: not read). */
    function details(database: Partial<SavedDatabase>, read?: GcloudAccountsView) {
      const client = new QueryClient();
      if (read) client.setQueryData(gcloudAccountsKey, read);
      return text(renderToStaticMarkup(<QueryClientProvider client={client}><DatabaseAccess row={row({ live: live("running") }, { pam: null, ...database })} /></QueryClientProvider>));
    }

    it("is_the_databases_account_else_the_one_gcloud_is_signed_in_as", () => {
      expect(details({ account: "frank@example.com" }, accounts("ops@example.com"))).toContain("postgresql://frank%40example.com@127.0.0.1:6543/postgres");
      expect(details({ account: null }, accounts("ops@example.com"))).toContain("postgresql://ops%40example.com@127.0.0.1:6543/postgres");
    });

    it("drops_the_service_account_suffix_as_the_backend_does", () => {
      const account = "orders-sa@acme-prod-123456.iam.gserviceaccount.com";
      expect(details({ account })).toContain("postgresql://orders-sa%40acme-prod-123456.iam@127.0.0.1:6543/postgres");
      expect(details({ account: null }, accounts(account))).toContain("postgresql://orders-sa%40acme-prod-123456.iam@127.0.0.1:6543/postgres");
    });

    it("is_a_placeholder_while_no_account_is_known_and_the_address_still_shows", () => {
      expect(details({ account: null })).toContain("postgresql://your-google-account@127.0.0.1:6543/postgres");
      expect(details({ account: null }, accounts(null))).toContain("postgresql://your-google-account@127.0.0.1:6543/postgres");
      expect(details({ account: null })).toContain("Copy URL");
    });

    it("keeps_the_passwords_off_the_page_and_out_of_the_cache", () => {
      const client = new QueryClient();
      const html = renderToStaticMarkup(<QueryClientProvider client={client}><DatabaseAccess row={row({ live: live("running") }, noDetails)} /></QueryClientProvider>);
      expect(invoke).not.toHaveBeenCalled();
      expect(html).not.toContain("<input");
      expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data))).not.toMatch(/password/i);
    });
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
