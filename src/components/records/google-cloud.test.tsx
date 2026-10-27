import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement, ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Dialog } from "@/components/ui/dialog";
import { AlertDialogAction } from "@/components/ui/alert-dialog";
import { buttonsIn, buttonTag, DISABLED, elementsOf, HIDDEN_CHARS, text, textIn } from "@/components/keychain/test-markup";
import { SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { renderHook, stubBackend } from "@/lib/test-ipc";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import type { TransportSyncView } from "@/bindings/TransportSyncView";
import {
  gcloudAccountsQuery,
  gcloudCliQuery,
  pamOverviewKey,
  pamOverviewQuery,
  type GcloudAccountsView,
  type GcloudCliView,
  type HostTransport,
  type PamEntitlementView,
  type PamOverview,
  type PamScopeView,
  type PamStatusView,
} from "@/lib/transports";
import { FormSection } from "@/components/app/Workflow";
import { PageHeader } from "@/components/app/PageHeader";
import { hostPayload, hostTransport, hostView, recordOverview } from "./fixtures";
import { GoogleCloudPageView, IapHostsTab, type GoogleCloudTab } from "./GoogleCloudPanel";
import { AccountsTabView, confirmation, GoogleAccountsTab, runningLine, type AccountsTabViewProps, type Confirming, type Running } from "./GoogleAccountsTab";
import { AccessTabView, PamAccessTab, ScopeDialog, newScopeDraft, scopeLine, type AccessTabViewProps, type ScopeDraft } from "./PamAccessTab";
import { AWAITING_APPROVER, EntitlementGrantDialog, GrantRequestCardView, type GrantRequestCardViewProps } from "./GrantRequestDialog";

afterEach(() => vi.unstubAllGlobals());

/*
 * There is no DOM here, so each tab is drawn two ways: as static markup (its words), and as the element tree of its hook-free view,
 * whose callbacks the tests press. The views' own state (a confirmation, a running action, a request, a scope draft) is kept by the
 * helper the way the tab keeps it.
 */

const AT = new Date(2026, 9, 27, 10, 0).getTime(); // 10:00 on this computer's clock
const LATER = new Date(2026, 9, 27, 11, 30).getTime();
const grant = { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 2700, justification: null };

const host = (n: number, alias: string): RecordHostView => hostView({ id: String(n).padStart(16, "0"), payload: hostPayload({ alias, hostname: `10.0.0.${n}` }) });
const web = host(1, "web-1");
const ops = host(2, "ops-1");
const db = host(3, "db-1");
const db2 = host(4, "db-2");
const ghost = host(9, "ghost-1"); // a host this overview has not got
const webRoute = hostTransport({ instance: "web-1" }, web.id); // no account: gcloud's active one
const opsRoute = hostTransport({ instance: "ops-1", zone: "asia-east1-c", account: "ops@example.com" }, ops.id);
const dbRoute = hostTransport({ instance: "db-1", account: "frank@example.com", pam: grant }, db.id);
const db2Route = hostTransport({ instance: "db-2", account: "frank@example.com", pam: grant }, db2.id);
const ghostRoute = hostTransport({ instance: "ghost-1", account: "old@example.com" }, ghost.id);

const library = { central_mode: true, account: { chain_id: "c".repeat(64), device_name: "Laptop" } } satisfies Partial<RecordOverview>;
const overviewOf = (hosts: RecordHostView[], routes: HostTransport[], patch: Partial<RecordOverview> = {}): RecordOverview =>
  recordOverview({ hosts, transports: routes, ...patch });

const accounts: GcloudAccountsView = {
  config_found: true,
  active: "frank@example.com",
  accounts: [
    { account: "frank@example.com", state: "signed_in", message: null },
    { account: "late@example.com", state: "unknown", message: "Google's token service could not be reached: offline." },
    { account: "old@example.com", state: "expired", message: null },
  ],
};
const found: GcloudCliView = { path: "/opt/homebrew/bin/gcloud" };
const missing: GcloudCliView = { path: null };

const OPERATE = "projects/acme-prod-123456/locations/global/entitlements/prod-operate";
const ADMIN = "projects/acme-prod-123456/locations/global/entitlements/prod-admin";
const GLASS = "folders/123456789012/locations/global/entitlements/break-glass";
const entitlement = (patch: Partial<PamEntitlementView>): PamEntitlementView => ({
  account: "frank@example.com",
  name: OPERATE,
  parent: "projects/acme-prod-123456",
  location: "global",
  entitlement: "prod-operate",
  max_duration_secs: 3600,
  needs_approval: false,
  roles: [{ role: "roles/compute.osAdminLogin", resource: "projects/acme-prod-123456" }],
  state: "none",
  active_until_ms: null,
  message: null,
  host_ids: [db.id, db2.id],
  memory: null,
  default_duration_secs: 2700,
  ...patch,
});
const operate = entitlement({ state: "active", active_until_ms: AT });
const admin = entitlement({ name: ADMIN, entitlement: "prod-admin", max_duration_secs: null, roles: [] });
const glass = entitlement({
  account: "ops@example.com",
  name: GLASS,
  parent: "folders/123456789012",
  entitlement: "break-glass",
  needs_approval: true,
  max_duration_secs: 7200,
  roles: [{ role: "roles/owner", resource: "folders/123456789012" }],
  host_ids: [],
  default_duration_secs: 1800,
});
const routeScope: PamScopeView = { id: null, parent: "projects/acme-prod-123456", location: "global", account: "frank@example.com", from_routes: true, host_ids: [db.id, db2.id], message: null };
const addedScope: PamScopeView = { id: "00000000000000a1", parent: "folders/123456789012", location: "global", account: "ops@example.com", from_routes: false, host_ids: [], message: null };
const pamOverview: PamOverview = { scopes: [routeScope, addedScope], entitlements: [operate, admin, glass] };

type Answers = { accounts?: GcloudAccountsView | Error; cli?: GcloudCliView | Error; pam?: PamOverview | Error; reply?: (command: string, args: unknown) => unknown };

/** The page's backend, answered as `answers` says, and a client that has read it (or, with `settled: false`, has not yet). */
async function backend(answers: Answers = {}, settled = true) {
  const calls = stubBackend(async (command, args) => {
    const answer = answers.reply?.(command, args) ?? { gcp_accounts: answers.accounts ?? accounts, gcp_cli_status: answers.cli ?? found, gcp_pam_overview: answers.pam ?? pamOverview }[command];
    if (answer instanceof Error) throw answer;
    return answer;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retryOnMount: false } } });
  if (settled) {
    await client.prefetchQuery(gcloudAccountsQuery);
    await client.prefetchQuery(gcloudCliQuery);
    await client.prefetchQuery(pamOverviewQuery);
  }
  calls.length = 0;
  return { calls, client };
}

/** The words of the markup. A command is code, which sits inline in its sentence and so adds no space of its own. */
const pageText = (html: string) => text(html.replace(/<\/?code[^>]*>/g, "")).trim();

/** The page on `tab` as markup, its props, and what pressing the tab bar does. */
async function renderPage(overview: RecordOverview, tab: GoogleCloudTab, answers: Answers = {}, settled = true) {
  const { calls, client } = await backend(answers, settled);
  const props = { overview, tab, onTab: vi.fn(), accept: vi.fn(), createIapHost: vi.fn(), editHost: vi.fn() };
  const html = renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <GoogleCloudPageView {...props} />
    </QueryClientProvider>,
  );
  return { calls, client, props, html, text: pageText(html), tree: GoogleCloudPageView(props) };
}

const last = <T,>(items: T[]): T | undefined => items[items.length - 1];

/** The sections of a tree, by title. */
const sectionOf = (tree: ReactNode, title: string) => {
  const found = elementsOf(tree, FormSection).find((element) => (element.props as unknown as { title: string }).title === title);
  if (!found) throw new Error(`no ${title} section`);
  return found;
};
const rowsOf = (tree: ReactNode, title: string) => elementsOf(sectionOf(tree, title), "li");
const rowText = (element: ReactElement) => pageText(renderToStaticMarkup(element));
const rowFor = (tree: ReactNode, title: string, label: string) => {
  const found = rowsOf(tree, title).find((element) => textIn(element).includes(label));
  if (!found) throw new Error(`no ${label} row in ${title}`);
  return found;
};
const buttonIn = (node: ReactNode, label: string) => {
  const button = buttonsIn(node).find((element) => textIn(element).trim() === label);
  if (!button) throw new Error(`no ${label} button`);
  return button;
};
const actionsOf = (tree: ReactNode, title: string) => (sectionOf(tree, title).props as unknown as { actions?: ReactNode }).actions;

describe("the Google Cloud page", () => {
  it("sits in the workspace's page frame like the Tunnels panel, so its content is inset and never clipped", async () => {
    expect((await renderPage(overviewOf([web], [webRoute]), "hosts")).html).toMatch(/^<div class="transports-panel /);
  });

  it("says what the page is for and offers New IAP host whatever the tab", async () => {
    const view = await renderPage(overviewOf([], []), "access");
    expect(view.text).toContain("Google accounts, access grants and IAP hosts on this computer.");
    const header = elementsOf(view.tree, PageHeader)[0];
    buttonIn((header.props as unknown as { actions: ReactNode }).actions, "New IAP host").props.onClick!();
    expect(view.props.createIapHost).toHaveBeenCalledTimes(1);
  });

  it("has three tabs, and draws only the open one", async () => {
    const accountsTab = await renderPage(overviewOf([web], [webRoute]), "accounts");
    expect(accountsTab.text).toContain("Accounts");
    expect(accountsTab.text).toContain("Access");
    expect(accountsTab.text).toContain("IAP hosts");
    expect(accountsTab.text).toContain("Google accounts");
    expect(accountsTab.text).not.toContain("Hosts through IAP");
    expect(accountsTab.calls.map(([command]) => command)).not.toContain("gcp_pam_overview");
    const hostsTab = await renderPage(overviewOf([web], [webRoute]), "hosts");
    expect(hostsTab.text).toContain("Hosts through IAP");
    expect(hostsTab.text).not.toContain("Accounts come from gcloud");
  });
});

/** The Accounts tab's view, with the state the tab would keep, kept here. */
async function accountsTab(overview: RecordOverview, answers: Answers = {}, settled = true) {
  const { calls, client } = await backend(answers, settled);
  const routes = (overview.transports ?? []).filter((route) => overview.hosts.some((host) => host.id === route.host_id));
  const wrapped = () => (renderHook(client, () => GoogleAccountsTab({ overview, routes })) as ReactElement<AccountsTabViewProps>).props;
  let confirming: Confirming | null = null;
  let running: Running | null = null;
  const asked: Confirming[] = [];
  const confirmed: Confirming[] = [];
  const tree = () =>
    AccountsTabView({
      ...wrapped(),
      confirming,
      running,
      onAsk: (ask) => {
        asked.push(ask);
        confirming = ask;
      },
      onConfirm: (ask) => confirmed.push(ask),
      onCloseConfirm: () => {
        confirming = null;
      },
    });
  return {
    calls,
    wrapped,
    tree,
    asked,
    confirmed,
    setRunning: (next: Running | null) => {
      running = next;
    },
    rows: () => rowsOf(tree(), "Google accounts").map(rowText),
    row: (label: string) => rowText(rowFor(tree(), "Google accounts", label)),
    press: (label: string, row?: string) => buttonIn(row ? rowFor(tree(), "Google accounts", row) : tree(), label).props.onClick!(),
    disabled: (label: string, row: string) => buttonTag(renderToStaticMarkup(rowFor(tree(), "Google accounts", row)), label).includes(DISABLED),
    text: () => pageText(renderToStaticMarkup(<QueryClientProvider client={client}>{tree()}</QueryClientProvider>)),
  };
}

describe("the Accounts tab", () => {
  const routes = [webRoute, opsRoute, dbRoute];
  const overview = overviewOf([web, ops, db], routes);

  it("lists this computer's gcloud accounts with their state, the active badge and the routes that use each", async () => {
    const view = await accountsTab(overview);
    expect(view.text()).toContain("Accounts come from gcloud on this computer and are not synced. Changes here change gcloud for every tool on this computer.");
    expect(view.rows().map((line) => line.split(" ")[0])).toEqual(["frank@example.com", "late@example.com", "old@example.com", "ops@example.com"]);
    expect(view.row("frank@example.com")).toContain("Signed in · 2 routes");
    expect(view.row("frank@example.com")).toContain("gcloud active");
    expect(view.row("old@example.com")).toContain("Sign-in expired · No routes");
    expect(view.row("late@example.com")).toContain("Google's token service could not be reached: offline.");
    expect(view.row("ops@example.com")).toContain("Not signed in on this computer · 1 route");
  });

  it("says where gcloud is, and offers the actions in place of the commands", async () => {
    const view = await accountsTab(overview);
    expect(view.text()).toContain("gcloud found at /opt/homebrew/bin/gcloud");
    expect(view.row("old@example.com")).not.toContain("gcloud auth login");
    // Every account can sign in again; the active one is not offered to become active; an account only a route names cannot be removed.
    expect(view.row("frank@example.com")).toContain("Sign in again");
    expect(view.row("frank@example.com")).not.toContain("Make active");
    expect(view.row("old@example.com")).toContain("Make active");
    expect(view.row("old@example.com")).toContain("Remove…");
    expect(view.row("ops@example.com")).not.toContain("Remove…");
    expect(view.disabled("Sign in again", "old@example.com")).toBe(false);
  });

  it("without gcloud, says how to get it, keeps the commands and turns the actions off", async () => {
    const view = await accountsTab(overview, { cli: missing });
    // The install link sits inside the sentence (the markup's words are spaced at each element).
    expect(view.text()).toContain("Lunport could not find gcloud on this computer. Install the Google Cloud CLI , then press Check again.");
    expect(view.row("old@example.com")).toContain("gcloud auth login old@example.com");
    expect(view.row("ops@example.com")).toContain("gcloud auth login ops@example.com");
    expect(view.disabled("Sign in again", "old@example.com")).toBe(true);
    expect(view.disabled("Remove…", "old@example.com")).toBe(true);
    expect(buttonTag(renderToStaticMarkup(<>{actionsOf(view.tree(), "Google accounts")}</>), "Add account")).toContain(DISABLED);
  });

  it("signs in again at once, and confirms every other change first, in words that say what it changes", async () => {
    const view = await accountsTab(overview);
    view.press("Sign in again", "old@example.com");
    expect(last(view.asked)).toEqual({ action: { kind: "sign_in", account: "old@example.com" }, routes: 0, active: false });
    expect(confirmation(last(view.asked)!)).toBeNull();
    view.press("Remove…", "frank@example.com");
    const removal = confirmation(last(view.asked)!)!;
    expect(removal.title).toBe("Remove frank@example.com from gcloud on this computer?");
    expect(removal.body).toEqual([
      "gcloud revokes this sign-in at Google and deletes its credentials here. Every tool on this computer that uses gcloud loses this account, and the routes that use it (2) cannot connect until you sign in again. Google may also end this account's gcloud sign-in on your other computers.",
      "gcloud will have no active account until you choose one.",
    ]);
    expect([removal.button, removal.destructive]).toEqual(["Remove account", true]);
    // The confirmation's button confirms that very action.
    elementsOf(view.tree(), AlertDialogAction)[0].props.onClick!();
    expect(view.confirmed).toEqual([last(view.asked)]);
    view.press("Make active", "old@example.com");
    expect(confirmation(last(view.asked)!)).toMatchObject({
      title: "Make old@example.com gcloud's active account?",
      body: ["gcloud, kubectl, Terraform and every other tool on this computer that uses gcloud's active account will use old@example.com. Routes that name no account connect as it too."],
      button: "Make active",
      destructive: false,
    });
    expect(confirmation({ action: { kind: "remove", account: "old@example.com" }, routes: 0, active: false })!.body).toEqual([
      "gcloud revokes this sign-in at Google and deletes its credentials here. Every tool on this computer that uses gcloud loses this account. Google may also end this account's gcloud sign-in on your other computers.",
    ]);
  });

  it("adds an account without a confirmation", async () => {
    const view = await accountsTab(overview);
    buttonIn(actionsOf(view.tree(), "Google accounts"), "Add account").props.onClick!();
    expect(last(view.asked)?.action).toEqual({ kind: "add" });
    expect(confirmation(last(view.asked)!)).toBeNull();
  });

  it("runs an action through gcloud as the tab asks for it", async () => {
    const view = await accountsTab(overview, { reply: (command) => (command === "gcp_account_action" ? { account: "old@example.com", message: "Signed in as old@example.com." } : undefined) });
    view.wrapped().onAsk({ action: { kind: "sign_in", account: "old@example.com" }, routes: 0, active: false });
    await vi.waitFor(() => expect(view.calls).toContainEqual(["gcp_account_action", { action: { kind: "sign_in", account: "old@example.com" } }]));
    // A removal waits for its confirmation: asking makes no call.
    view.calls.length = 0;
    view.wrapped().onAsk({ action: { kind: "remove", account: "old@example.com" }, routes: 0, active: false });
    expect(view.calls).toEqual([]);
  });

  it("while gcloud waits for the browser, says so, offers the sign-in page and a way to stop", async () => {
    const view = await accountsTab(overview);
    view.setRunning({ action: { kind: "sign_in", account: "old@example.com" }, url: null, done: null, error: null });
    expect(textIn(view.tree())).toContain("Finish signing in to old@example.com in your browser.");
    expect(textIn(view.tree())).not.toContain("Open the sign-in page");
    const url = "https://accounts.google.com/o/oauth2/auth?state=1";
    view.setRunning({ action: { kind: "sign_in", account: "old@example.com" }, url, done: null, error: null });
    const opened = vi.fn();
    AccountsTabView({ ...view.wrapped(), running: { action: { kind: "sign_in", account: "old@example.com" }, url, done: null, error: null }, onOpenUrl: opened, confirming: null });
    buttonIn(view.tree(), "Open the sign-in page");
    expect(textIn(view.tree())).toContain("Browser did not open?");
    buttonIn(view.tree(), "Cancel");
    // Every account action is off while one runs.
    expect(view.disabled("Sign in again", "frank@example.com")).toBe(true);
    view.setRunning({ action: { kind: "add" }, url: null, done: { account: "new@example.com", message: "Signed in as new@example.com." }, error: null });
    expect(textIn(view.tree())).toContain("Signed in as new@example.com.");
    buttonIn(view.tree(), "Close");
    expect(runningLine({ kind: "add" })).toBe("Finish signing in to the new account in your browser.");
    expect(runningLine({ kind: "remove", account: "old@example.com" })).toBe("Removing old@example.com from gcloud…");
  });

  it("says why there are no accounts, and waits for the first answer", async () => {
    const empty = await accountsTab(overviewOf([web], [webRoute]), { accounts: { config_found: false, active: null, accounts: [] } });
    expect(empty.text()).toContain("gcloud has no Google account on this computer yet.");
    expect(empty.rows()).toEqual([]);
    const without = await accountsTab(overviewOf([web], [webRoute]), { accounts: { config_found: false, active: null, accounts: [] }, cli: missing });
    expect(without.text()).toContain("gcloud has no signed-in Google account on this computer. Run gcloud auth login to sign in.");
    const waiting = await accountsTab(overview, {}, false);
    expect(waiting.text()).toContain("Checking Google sign-ins…");
    expect(waiting.text()).toContain("Looking for gcloud…");
    const failed = await accountsTab(overview, { accounts: new Error(`Reading gcloud's folder took too long ${SPOOFED_NAME}`) });
    expect(failed.text()).toContain(`Reading gcloud's folder took too long ${SPOOFED_NAME_SHOWN}`);
  });

  it("reads a state this release does not know as one that could not be checked", async () => {
    const mystery = { ...accounts, accounts: [{ account: "new@example.com", state: "something-new", message: "A state from a later release." }] };
    const view = await accountsTab(overviewOf([web], [webRoute]), { accounts: mystery });
    expect(view.row("new@example.com")).toContain("Could not be checked");
  });
});

/** The Access tab's view, with the state the tab would keep, kept here. */
async function accessTab(overview: RecordOverview, answers: Answers = {}, settled = true) {
  const { calls, client } = await backend(answers, settled);
  const accept = vi.fn();
  const wrapped = () => (renderHook(client, () => PamAccessTab({ overview, accept })) as ReactElement<AccessTabViewProps>).props;
  let requesting: PamEntitlementView | null = null;
  let draft: ScopeDraft | null = null;
  const tree = () =>
    AccessTabView({
      ...wrapped(),
      requesting,
      draft,
      onRequest: (row) => {
        requesting = row;
      },
      onCloseRequest: () => {
        requesting = null;
      },
      onOpenScope: () => {
        draft = newScopeDraft();
      },
    });
  return {
    calls,
    client,
    accept,
    wrapped,
    tree,
    rows: (title: string) => rowsOf(tree(), title).map(rowText),
    row: (title: string, label: string) => rowText(rowFor(tree(), title, label)),
    press: (label: string, scope?: { title: string; row: string }) => buttonIn(scope ? rowFor(tree(), scope.title, scope.row) : tree(), label).props.onClick!(),
    disabled: (label: string, title: string, row: string) => buttonTag(renderToStaticMarkup(rowFor(tree(), title, row)), label).includes(DISABLED),
    text: () => pageText(renderToStaticMarkup(<QueryClientProvider client={client}>{tree()}</QueryClientProvider>)),
    get dialog() {
      return elementsOf(tree(), EntitlementGrantDialog)[0] ?? null;
    },
    get scopeDialog() {
      return elementsOf(tree(), ScopeDialog)[0] ?? null;
    },
  };
}

describe("the Access tab", () => {
  const overview = overviewOf([web, db, db2], [webRoute, dbRoute, db2Route]);

  it("lists every entitlement with where it lives, what it gives, its limits and the hosts that need it", async () => {
    const view = await accessTab(overview);
    expect(view.text()).toContain("Privileged Access Manager grants for your Google accounts. A grant gives its roles to every tool that uses the account until it ends; Lunport never ends one early.");
    const line = view.row("Entitlements", "prod-operate");
    expect(line).toContain("project acme-prod-123456 · global · frank@example.com");
    expect(line).toContain("roles/compute.osAdminLogin on projects/acme-prod-123456");
    expect(line).toContain("Up to 1 hour · Used by db-1, db-2");
    expect(line).toContain("Active until 10:00");
    const glassLine = view.row("Entitlements", "break-glass");
    expect(glassLine).toContain("folder 123456789012 · global · ops@example.com");
    expect(glassLine).toContain("Up to 2 hours · Needs approval");
    expect(glassLine).not.toContain("Used by");
    expect(view.row("Entitlements", "prod-admin")).toContain("No active grant");
  });

  it("keeps Request grant off while a grant is active, activating or waiting for its approver", async () => {
    const view = await accessTab(overview, {
      pam: { scopes: [], entitlements: [operate, entitlement({ name: ADMIN, entitlement: "prod-admin", state: "activating" }), { ...glass, state: "approval_awaited" }, entitlement({ name: `${OPERATE}-2`, entitlement: "prod-deploy" })] },
    });
    expect(view.disabled("Request grant", "Entitlements", "prod-operate")).toBe(true);
    expect(view.disabled("Request grant", "Entitlements", "prod-admin")).toBe(true);
    expect(view.disabled("Request grant", "Entitlements", "break-glass")).toBe(true);
    expect(view.row("Entitlements", "break-glass")).toContain("Awaiting approval");
    expect(view.disabled("Request grant", "Entitlements", "prod-deploy")).toBe(false);
  });

  it("requests on the entitlement clicked, as its account, from its memory and within its maximum, and takes the answer into its row", async () => {
    const remembered = { ...admin, memory: { name: ADMIN, justification: "Deploy hotfix", duration_secs: 5400 }, max_duration_secs: 3600 };
    const granted: PamStatusView = { entitlement: "prod-admin", state: "active", active_until_ms: LATER, message: null };
    const view = await accessTab(overview, { pam: { scopes: [], entitlements: [operate, remembered] }, reply: (command) => (command === "gcp_pam_request" ? granted : undefined) });
    view.press("Request grant", { title: "Entitlements", row: "prod-admin" });
    const row = (view.dialog!.props as unknown as { row: PamEntitlementView }).row;
    expect(row.name).toBe(ADMIN);
    const card = elementsOf(renderHook(new QueryClient(), () => EntitlementGrantDialog({ row, onClose: () => {}, onRequested: () => {} })), GrantRequestCardView)[0].props as unknown as GrantRequestCardViewProps;
    expect(card).toMatchObject({ entitlement: "prod-admin", justification: "Deploy hotfix", minutes: "60", maxMinutes: 60, subject: { parent: "projects/acme-prod-123456", account: "frank@example.com" } });
    card.onRequest();
    await vi.waitFor(() => expect(view.calls).toEqual([["gcp_pam_request", { account: "frank@example.com", name: ADMIN, justification: "Deploy hotfix", durationSecs: 3600 }]]));
    view.wrapped().onRequested(row, granted);
    expect(view.row("Entitlements", "prod-admin")).toContain("Active until 11:30");
    expect(view.row("Entitlements", "prod-operate")).toContain("Active until 10:00");
    expect(view.client.getQueryData<PamOverview>(pamOverviewKey)?.entitlements[1].state).toBe("active");
  });

  it("starts a request without a memory from the entitlement's default length, and says when it waits for an approver", async () => {
    const card = (row: PamEntitlementView) =>
      elementsOf(renderHook(new QueryClient(), () => EntitlementGrantDialog({ row, onClose: () => {}, onRequested: () => {} })), GrantRequestCardView)[0].props as unknown as GrantRequestCardViewProps;
    expect(card(glass)).toMatchObject({ justification: "", minutes: "30", maxMinutes: 120 });
    expect(card(admin)).toMatchObject({ minutes: "45", maxMinutes: 480 });
    const waiting = pageText(
      renderToStaticMarkup(
        <Dialog open>
          <GrantRequestCardView {...card(glass)} result={{ entitlement: "break-glass", state: "approval_awaited", active_until_ms: null, message: null }} />
        </Dialog>,
      ),
    );
    expect(waiting).toContain(AWAITING_APPROVER);
    expect(waiting).toContain("A Privileged Access Manager grant on break-glass (folder 123456789012), requested as ops@example.com.");
  });

  it("lists where it looks: the routes' projects with their hosts, and the scopes added, which can be removed", async () => {
    const view = await accessTab(overview, { reply: (command) => (command === "gcp_pam_scope_remove" ? recordOverview({ pam_scopes: [] }) : undefined) });
    expect(view.rows("Where Lunport looks")).toEqual([
      "project acme-prod-123456 · global · frank@example.com From routes Used by db-1, db-2",
      "folder 123456789012 · global · ops@example.com Remove",
    ]);
    view.press("Remove", { title: "Where Lunport looks", row: "folder 123456789012" });
    await vi.waitFor(() => expect(view.accept).toHaveBeenCalled());
    expect(view.calls).toContainEqual(["gcp_pam_scope_remove", { id: "00000000000000a1" }]);
    expect(scopeLine({ parent: "projects/acme-dev-654321", location: "global", account: null })).toBe("project acme-dev-654321 · global · gcloud's active account");
  });

  it("says a scope's search failed on its row", async () => {
    const view = await accessTab(overview, { pam: { scopes: [{ ...addedScope, message: `ops@example.com may not call the Privileged Access Manager API (HTTP 403) ${SPOOFED_NAME}` }], entitlements: [] } });
    expect(view.row("Where Lunport looks", "folder")).toContain(`(HTTP 403) ${SPOOFED_NAME_SHOWN}`);
  });

  it("adds a scope from the dialog, checked as the backend checks it", async () => {
    const view = await accessTab(overview, { reply: (command) => (command === "gcp_pam_scope_save" ? recordOverview() : undefined) });
    buttonIn(actionsOf(view.tree(), "Where Lunport looks"), "Add scope").props.onClick!();
    expect(view.scopeDialog).not.toBeNull();
    const dialog = (draft: ScopeDraft) => renderHook(new QueryClient(), () => ScopeDialog({ draft, error: null, busy: false, accounts, onDraft: () => {}, onSave: () => {}, onClose: () => {} }));
    const words = (draft: ScopeDraft) => textIn(dialog(draft));
    expect(words({ ...newScopeDraft(), id: "acme" })).toContain("Enter a project ID, or a folder or organization number.");
    expect(words({ ...newScopeDraft(), kind: "folders", id: "123456789012", location: "Global" })).toContain("Enter the PAM location, such as global.");
    expect(words({ ...newScopeDraft(), kind: "folders", id: "123456789012" })).not.toContain("Enter");
    view.wrapped().onSaveScope({ kind: "folders", id: " 123456789012 ", location: "global", account: "ops@example.com" });
    await vi.waitFor(() => expect(view.calls).toContainEqual(["gcp_pam_scope_save", { parent: "folders/123456789012", location: "global", account: "ops@example.com" }]));
    view.calls.length = 0;
    view.wrapped().onSaveScope({ kind: "projects", id: "Acme", location: "global", account: "" });
    expect(view.calls).toEqual([]);
  });

  it("waits for the first answer, says why there is none, and says when there is nothing to show", async () => {
    expect((await accessTab(overview, {}, false)).text()).toContain("Looking for entitlements…");
    const failed = await accessTab(overview, { pam: new Error(`Google said ${SPOOFED_NAME}`) });
    expect(failed.text()).toContain(`Google said ${SPOOFED_NAME_SHOWN}`);
    expect(failed.text()).not.toMatch(HIDDEN_CHARS);
    const none = await accessTab(overview, { pam: { scopes: [], entitlements: [] } });
    expect(none.text()).toContain("No entitlement found. Add a scope where your Google account can request a grant, or require a grant in a host's Google Cloud options.");
    expect(none.text()).toContain("Lunport looks nowhere yet.");
  });

  it("shows hidden and direction-changing characters in aliases and Google's sentences as visible escapes", async () => {
    const odd = hostView({ id: db.id, payload: hostPayload({ alias: SPOOFED_NAME }) });
    const failing = entitlement({ state: "error", message: `quota exceeded for ${SPOOFED_NAME}`, host_ids: [odd.id] });
    const view = await accessTab(overviewOf([odd], [{ ...dbRoute, host_id: odd.id }]), { pam: { scopes: [], entitlements: [failing] } });
    expect(view.row("Entitlements", "prod-operate")).toContain(`Used by ${SPOOFED_NAME_SHOWN}`);
    expect(view.row("Entitlements", "prod-operate")).toContain(`quota exceeded for ${SPOOFED_NAME_SHOWN}`);
    expect(view.text()).not.toMatch(HIDDEN_CHARS);
  });
});

describe("the IAP hosts tab", () => {
  const hostsTab = (overview: RecordOverview) => {
    const editHost = vi.fn();
    const tree = IapHostsTab({ overview, editHost });
    return { editHost, rows: () => rowsOf(tree, "Hosts through IAP").map(rowText), row: (label: string) => rowText(rowFor(tree, "Hosts through IAP", label)), tree, text: pageText(renderToStaticMarkup(tree)) };
  };

  it("opens a host from the list and skips orphans", () => {
    const view = hostsTab(overviewOf([web, ops], [webRoute, ghostRoute]));
    expect(view.text).not.toContain("ghost-1");
    buttonIn(rowFor(view.tree, "Hosts through IAP", "web-1"), "web-1").props.onClick!();
    expect(view.editHost).toHaveBeenCalledWith(web.id);
    expect(view.rows()).toHaveLength(1);
  });

  it("shows each host's target, zone and account, by alias", () => {
    expect(hostsTab(overviewOf([web, ops, db], [webRoute, opsRoute, dbRoute].reverse())).rows()).toEqual([
      "db-1 acme-prod-123456 / db-1 · asia-east1-b frank@example.com",
      "ops-1 acme-prod-123456 / ops-1 · asia-east1-c ops@example.com",
      "web-1 acme-prod-123456 / web-1 · asia-east1-b gcloud's active account",
    ]);
  });

  it("says when no host connects through IAP", () => {
    expect(hostsTab(overviewOf([web], [])).text).toContain("No host connects through IAP yet. Open a host and choose Google Cloud IAP under Connect via, or create one with New IAP host.");
    expect(hostsTab(overviewOf([web], [ghostRoute])).text).toContain("No host connects through IAP yet.");
    expect(hostsTab(recordOverview({ hosts: [web], transports: undefined })).text).toContain("No host connects through IAP yet.");
  });

  it("sets apart the routes a central library keeps on this computer, after the others, with no room as their reason only when it is", () => {
    const sync: TransportSyncView[] = [
      { host_id: web.id, synced: true, reason: null },
      { host_id: ops.id, synced: false, reason: "no_room" },
    ];
    const view = hostsTab(overviewOf([web, ops], [webRoute, opsRoute], { ...library, transport_sync: sync }));
    expect(view.rows().map((line) => line.split(" ")[0])).toEqual(["web-1", "ops-1"]);
    expect(view.row("ops-1")).toContain("Saved on this computer only: the library has no room for this route");
    const alone = hostsTab(overviewOf([web, ops], [webRoute, opsRoute], { transport_sync: sync }));
    expect(alone.text).not.toContain("Saved on this computer only");
  });

  it("shows a spoofed alias as visible escapes", () => {
    const odd = hostView({ id: db.id, payload: hostPayload({ alias: SPOOFED_NAME }) });
    const view = hostsTab(overviewOf([odd], [{ ...dbRoute, host_id: odd.id }]));
    expect(view.text).toContain(SPOOFED_NAME_SHOWN);
    expect(view.text).not.toMatch(HIDDEN_CHARS);
  });
});
