import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactElement, ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Dialog } from "@/components/ui/dialog";
import { buttonsIn, buttonTag, DISABLED, elementsOf, HIDDEN_CHARS, text, textIn } from "@/components/keychain/test-markup";
import { SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { renderHook, stubBackend } from "@/lib/test-ipc";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import {
  gcloudAccountsQuery,
  pamGrantsKey,
  pamGrantsQuery,
  type GcloudAccountsView,
  type HostTransport,
  type PamGrantView,
  type PamStatusView,
} from "@/lib/transports";
import { PageHeader } from "@/components/app/PageHeader";
import { FormSection } from "@/components/app/Workflow";
import { hostPayload, hostTransport, hostView, recordOverview } from "./fixtures";
import { GoogleCloudPageView, GoogleCloudPanel, type GoogleCloudPageViewProps, type GrantAsk } from "./GoogleCloudPanel";
import { GrantRequestCardView, GrantRequestDialog, type GrantRequestCardViewProps } from "./GrantRequestDialog";

afterEach(() => vi.unstubAllGlobals());

/*
 * There is no DOM here, so the page is drawn two ways: as static markup (its words), and as the element tree of the hook-free
 * `GoogleCloudPageView`, whose callbacks the tests press. The view's one state, the grant being requested, is kept by the helper the
 * way the panel keeps it.
 */

const AT = new Date(2026, 9, 27, 10, 0).getTime(); // 10:00 on this computer's clock
const LATER = new Date(2026, 9, 27, 11, 30).getTime();
const grant = { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 1800, justification: null };

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
const row = (patch: Partial<PamGrantView>): PamGrantView => ({
  account: "frank@example.com",
  project: "acme-prod-123456",
  location: "global",
  entitlement: "prod-operate",
  state: "none",
  active_until_ms: null,
  message: null,
  host_ids: [db.id],
  ...patch,
});
const operate = row({ state: "active", active_until_ms: AT, host_ids: [db.id, db2.id] });
const admin = row({ entitlement: "prod-admin", host_ids: [db.id, db2.id] });

type Answers = { accounts?: GcloudAccountsView | Error; grants?: PamGrantView[] | Error; request?: PamStatusView };
type PageProps = Parameters<typeof GoogleCloudPanel>[0];

/** The page as the person sees it once the backend has answered (or, with `settled: false`, while it has not). */
async function renderPage(overview: RecordOverview, options: { answers?: Answers; settled?: boolean; props?: Partial<PageProps> } = {}) {
  const answers = options.answers ?? {};
  const calls = stubBackend(async (command) => {
    const answer = { gcp_accounts: answers.accounts ?? accounts, gcp_pam_grants: answers.grants ?? [operate, admin], transports_pam_request: answers.request }[command];
    if (answer instanceof Error) throw answer;
    return answer;
  });
  // A mounting pane reads again whatever the last read found; this one draws what the read left, even a failure.
  const client = new QueryClient({ defaultOptions: { queries: { retryOnMount: false } } });
  if (options.settled !== false) {
    await client.prefetchQuery(gcloudAccountsQuery);
    await client.prefetchQuery(pamGrantsQuery);
  }
  calls.length = 0;
  const props: PageProps = { overview, createIapHost: vi.fn(), editHost: vi.fn(), ...options.props };
  const panel = () => renderHook(client, () => GoogleCloudPanel(props)) as ReactElement<GoogleCloudPageViewProps>;
  let requesting: GrantAsk | null = null;
  /** The element tree of the page, with the grant being requested kept here instead of in the panel's state. */
  const tree = () =>
    GoogleCloudPageView({
      ...panel().props,
      requesting,
      onRequest: (ask) => { requesting = ask; },
      onCloseRequest: () => { requesting = null; },
    });
  const html = () =>
    renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <GoogleCloudPanel {...props} />
      </QueryClientProvider>,
    );
  const section = (title: string) => {
    const found = elementsOf(tree(), FormSection).find((element) => (element.props as unknown as { title: string }).title === title);
    if (!found) throw new Error(`no ${title} section`);
    return found;
  };
  const rowsOf = (title: string) => elementsOf(section(title), "li");
  const rowTextOf = (element: ReactElement) => pageText(renderToStaticMarkup(element));
  const rowFor = (title: string, label: string) => {
    const found = rowsOf(title).find((element) => textIn(element).includes(label));
    if (!found) throw new Error(`no ${label} row in ${title}`);
    return found;
  };
  /** The button labelled `label`, in the row that names `row` when given; else on the page, its header's actions included. */
  const buttonFor = (label: string, scope?: { row: string; in?: string }) => {
    const within = scope ? rowFor(scope.in ?? "Access grants", scope.row) : tree();
    const header = scope ? [] : elementsOf(within, PageHeader).flatMap((element) => buttonsIn((element.props as unknown as { actions?: ReactNode }).actions));
    const button = [...buttonsIn(within), ...header].find((element) => textIn(element).trim() === label);
    if (!button) throw new Error(`no ${label} button`);
    return button;
  };
  return {
    calls,
    client,
    props,
    get html() {
      return html();
    },
    get text() {
      return pageText(html());
    },
    rows: (title: string) => rowsOf(title).map(rowTextOf),
    row: (title: string, label: string) => rowTextOf(rowFor(title, label)),
    sectionTitles: () => elementsOf(tree(), FormSection).map((element) => (element.props as unknown as { title: string }).title),
    click: (label: string, scope?: { row: string; in?: string }) => buttonFor(label, scope).props.onClick!(),
    /** Whether the button is off in the markup the person gets, not only in the props it was given. */
    disabled: (label: string, scope: { row: string; in?: string }) => buttonTag(renderToStaticMarkup(rowFor(scope.in ?? "Access grants", scope.row)), label).includes(DISABLED),
    /** The request dialog the page has open, if any: what it was given, and what it says. */
    get dialog() {
      const open = elementsOf(tree(), GrantRequestDialog)[0];
      if (!open) return null;
      const given = open.props as unknown as Parameters<typeof GrantRequestDialog>[0];
      const card = elementsOf(renderHook(new QueryClient(), () => GrantRequestDialog(given)), GrantRequestCardView)[0].props as unknown as GrantRequestCardViewProps;
      return { given, card, key: open.key, text: pageText(renderToStaticMarkup(<Dialog open><GrantRequestCardView {...card} /></Dialog>)) };
    },
  };
}

/** The words of the page's markup. A command is code, which sits inline in its sentence and so adds no space of its own. */
const pageText = (html: string) => text(html.replace(/<\/?code[^>]*>/g, "")).trim();
const renderPageText = async (overview: RecordOverview, options?: Parameters<typeof renderPage>[1]) => (await renderPage(overview, options)).text;

describe("the Google Cloud page", () => {
  it("sits in the workspace's page frame like the Tunnels panel, so its content is inset and never clipped", async () => {
    // The workspace main pads nothing; each tool panel brings its own inset (`.tunnels-panel`, `.transports-panel`).
    expect((await renderPage(overviewOf([web], [webRoute]))).html).toMatch(/^<div class="transports-panel /);
  });

  it("says what the page is for and offers New IAP host", async () => {
    const view = await renderPage(overviewOf([], []));
    expect(view.text).toContain("Google sign-in and access grants on this computer. A host connects through IAP when its Connect via is set to Google Cloud IAP.");
    expect(view.text).not.toContain("transport");
    view.click("New IAP host");
    expect(view.props.createIapHost).toHaveBeenCalledTimes(1);
  });

  it("shows the sections its routes call for", async () => {
    expect((await renderPage(overviewOf([web], [webRoute]))).sectionTitles()).toEqual(["Google sign-in", "Hosts through IAP"]);
    expect((await renderPage(overviewOf([web, db], [webRoute, dbRoute]))).sectionTitles()).toEqual(["Google sign-in", "Access grants", "Hosts through IAP"]);
  });
});

describe("Google sign-in", () => {
  const routes = [webRoute, opsRoute, dbRoute];

  it("lists this computer's gcloud accounts with their state", async () => {
    const view = await renderPage(overviewOf([web, ops, db], routes)); // gcp_accounts: frank@ active and signed in, old@ expired
    expect(view.text).toContain("Accounts come from gcloud on this computer. Sign-ins are per computer and are not synced.");
    expect(view.text).toContain("gcloud active");
    expect(view.text).toContain("gcloud auth login old@example.com");
    expect(view.text).toContain("Not signed in on this computer"); // ops@ is named by a route only: this computer has no sign-in for it
    expect(view.text).toContain("gcloud auth login ops@example.com");
    expect(view.rows("Google sign-in").map((line) => line.split(" ")[0])).toEqual(["frank@example.com", "late@example.com", "old@example.com", "ops@example.com"]);
  });

  it("gives each state its dot and its words", async () => {
    const view = await renderPage(overviewOf([web, ops, db], routes));
    const signedIn = view.row("Google sign-in", "frank@example.com");
    expect(signedIn).toContain("Signed in");
    expect(signedIn).not.toContain("gcloud auth login");
    expect(view.row("Google sign-in", "old@example.com")).toContain("Sign-in expired");
    // The service gave no sentence for an expired sign-in: the page words it, and shows the command that fixes it.
    expect(view.row("Google sign-in", "old@example.com")).toContain("gcloud auth login old@example.com");
    const unknown = view.row("Google sign-in", "late@example.com");
    expect(unknown).toContain("Could not be checked");
    expect(unknown).toContain("Google's token service could not be reached: offline.");
    expect(unknown).not.toContain("gcloud auth login");
    expect(view.row("Google sign-in", "ops@example.com")).toContain("Not signed in on this computer");
    const dots = [...view.html.matchAll(/data-sign-in="([a-z_]+)"/g)].map((match) => match[1]);
    expect(dots).toEqual(["signed_in", "unknown", "expired", "missing"]);
  });

  it("marks the active account, and counts the routes that use each (a route without an account counts for the active one)", async () => {
    const view = await renderPage(overviewOf([web, ops, db], routes));
    // web-1 names no account and db-1 names frank@: both are frank@'s.
    expect(view.row("Google sign-in", "frank@example.com")).toContain("gcloud active");
    expect(view.row("Google sign-in", "frank@example.com")).toContain("2 routes");
    expect(view.row("Google sign-in", "old@example.com")).toContain("No routes");
    expect(view.row("Google sign-in", "old@example.com")).not.toContain("gcloud active");
    expect(view.row("Google sign-in", "ops@example.com")).toContain("1 route");
    expect(view.row("Google sign-in", "ops@example.com")).not.toContain("1 routes");
  });

  it("counts only the routes the page lists, and an account-less route only for the active account", async () => {
    // ghost-1's route names old@, but its host is gone: it is listed nowhere and counts for nobody.
    const view = await renderPage(overviewOf([web], [webRoute, ghostRoute]));
    expect(view.row("Google sign-in", "old@example.com")).toContain("No routes");
    expect(view.row("Google sign-in", "frank@example.com")).toContain("1 route");
    // With no active account, a route that names none counts for no one.
    const idle = await renderPage(overviewOf([web], [webRoute]), { answers: { accounts: { ...accounts, active: null } } });
    expect(idle.row("Google sign-in", "frank@example.com")).toContain("No routes");
    expect(idle.text).not.toContain("gcloud active");
    // A route names an account gcloud lacks only when it names one at all.
    expect(idle.text).not.toContain("Not signed in on this computer");
  });

  it("adds a row for each account only routes name, once, in the order of their names", async () => {
    // The hosts' aliases order them db-1, ops-1, web-1: the accounts they name come out in their own order, not the hosts'.
    const twice = hostTransport({ instance: "web-1", account: "ops@example.com" }, web.id);
    const later = hostTransport({ instance: "db-1", account: "zed@example.com" }, db.id);
    const view = await renderPage(overviewOf([ops, db, web], [later, opsRoute, twice]));
    const lacking = view.rows("Google sign-in").filter((line) => line.includes("Not signed in on this computer"));
    expect(lacking.map((line) => line.split(" ")[0])).toEqual(["ops@example.com", "zed@example.com"]);
    expect(lacking[0]).toContain("2 routes");
    expect(lacking[1]).toContain("1 route");
  });

  it("reads a state this release does not know as one that could not be checked", async () => {
    const mystery = { ...accounts, accounts: [{ account: "new@example.com", state: "something-new", message: "A state from a later release." }] };
    const view = await renderPage(overviewOf([web], [webRoute]), { answers: { accounts: mystery } });
    expect(view.row("Google sign-in", "new@example.com")).toContain("Could not be checked");
    expect(view.row("Google sign-in", "new@example.com")).toContain("A state from a later release.");
    expect(view.html).toContain('data-sign-in="unknown"');
  });

  it("says when gcloud is missing, in place of the accounts", async () => {
    const view = await renderPage(overviewOf([web, ops], [webRoute, opsRoute]), { answers: { accounts: { config_found: false, active: null, accounts: [] } } });
    expect(view.text).toContain("gcloud was not found on this computer. Install the Google Cloud CLI, then run gcloud auth login.");
    expect(view.rows("Google sign-in")).toEqual([]);
    expect(view.text).not.toContain("Not signed in on this computer");
    // The command in that sentence is code.
    expect(view.html).toContain("<code");
  });

  it("says when gcloud holds no sign-in", async () => {
    const empty = { config_found: true, active: null, accounts: [] };
    expect(await renderPageText(overviewOf([web], [webRoute]), { answers: { accounts: empty } })).toContain("gcloud has no signed-in Google account on this computer. Run gcloud auth login to sign in.");
    // The account a route names is still offered a sign-in, and that is then what the section has to say.
    const view = await renderPage(overviewOf([ops], [opsRoute]), { answers: { accounts: empty } });
    expect(view.row("Google sign-in", "ops@example.com")).toContain("Not signed in on this computer");
    expect(view.text).not.toContain("gcloud has no signed-in Google account");
  });

  it("waits for the answer, and says why there is none", async () => {
    const waiting = await renderPage(overviewOf([web], [webRoute]), { settled: false });
    expect(waiting.text).toContain("Checking Google sign-ins…");
    expect(waiting.text).not.toContain("gcloud was not found");
    const failed = await renderPage(overviewOf([web], [webRoute]), { answers: { accounts: new Error("Reading gcloud's folder took too long.") } });
    expect(failed.text).toContain("Reading gcloud's folder took too long.");
    expect(failed.html).toContain('role="alert"');
    expect(failed.text).not.toContain("gcloud was not found");
  });
});

describe("Access grants", () => {
  const overview = overviewOf([web, db, db2], [webRoute, dbRoute, db2Route]);
  const memory = { host_id: db.id, justification: "Deploy hotfix", duration_secs: 2700 };

  it("lists grants per entitlement and requests the one clicked", async () => {
    const view = await renderPage(overview); // gcp_pam_grants: prod-operate active, prod-admin none
    expect(view.text).toContain("Privileged Access Manager grants your hosts require. A grant ends on its own; Lunport never revokes one.");
    expect(view.row("Access grants", "prod-operate")).toContain("Active until 10:00");
    expect(view.row("Access grants", "prod-admin")).toContain("No active grant");
    expect(view.dialog).toBeNull();
    view.click("Request grant", { row: "prod-admin" });
    expect(view.dialog?.text).toContain("prod-admin");
    expect(view.dialog?.text).not.toContain("prod-operate");
  });

  it("shows where each entitlement lives, who it is for, and the hosts that require it", async () => {
    const view = await renderPage(overview);
    const line = view.row("Access grants", "prod-operate");
    expect(line).toContain("acme-prod-123456 · global");
    expect(line).toContain("frank@example.com");
    expect(line).toContain("Required by db-1, db-2");
    // The same entitlement id for another project or account is another row, told apart by what it says.
    const other = row({ project: "acme-dev-654321", account: "ops@example.com", host_ids: [db2.id] });
    const several = await renderPage(overview, { answers: { grants: [operate, other] } });
    expect(several.rows("Access grants")).toHaveLength(2);
    expect(several.rows("Access grants")[1]).toContain("acme-dev-654321 · global");
    expect(several.rows("Access grants")[1]).toContain("ops@example.com");
    expect(several.rows("Access grants")[1]).toContain("Required by db-2");
  });

  it("requests through the row's first host: its route, its alias, what this computer remembers of it, and the entitlement clicked", async () => {
    const granted: PamStatusView = { entitlement: "prod-admin", state: "active", active_until_ms: LATER, message: null };
    const view = await renderPage({ ...overview, grant_memory: [memory, { host_id: db2.id, justification: "Rotate keys", duration_secs: 900 }] }, { answers: { request: granted } });
    view.click("Request grant", { row: "prod-admin" });
    expect(view.dialog?.given).toMatchObject({ transport: dbRoute, entitlement: "prod-admin", memory, alias: "db-1" });
    expect(view.dialog?.card).toMatchObject({ entitlement: "prod-admin", justification: "Deploy hotfix", minutes: "45" });
    // The request itself goes through that host's id, for that entitlement; the row then shows the grant it got.
    view.dialog!.card.onRequest();
    await vi.waitFor(() => expect(view.row("Access grants", "prod-admin")).toContain("Active until 11:30"));
    expect(view.calls).toEqual([["transports_pam_request", { hostId: db.id, justification: "Deploy hotfix", durationSecs: 2700, entitlement: "prod-admin" }]]);
  });

  it("keys the request dialog by the row it is for, so a request for another row starts it afresh", async () => {
    const other = row({ entitlement: "prod-deploy", host_ids: [db2.id] });
    const view = await renderPage(overview, { answers: { grants: [admin, other] } });
    view.click("Request grant", { row: "prod-admin" });
    const keyed = view.dialog!.key;
    expect(keyed).not.toBeNull();
    view.click("Request grant", { row: "prod-deploy" });
    expect(view.dialog!.key).not.toBe(keyed);
  });

  it("starts a request from the route's default length when this computer remembers none", async () => {
    const view = await renderPage(overview);
    view.click("Request grant", { row: "prod-admin" });
    expect(view.dialog?.given.memory).toBeNull();
    expect(view.dialog?.card).toMatchObject({ justification: "", minutes: "30" });
  });

  it("keeps Request grant off while a grant is active or activating", async () => {
    const view = await renderPage(overview, { answers: { grants: [operate, admin, row({ entitlement: "prod-deploy", state: "activating" })] } });
    expect(view.disabled("Request grant", { row: "prod-operate" })).toBe(true);
    expect(view.disabled("Request grant", { row: "prod-deploy" })).toBe(true);
    expect(view.disabled("Request grant", { row: "prod-admin" })).toBe(false);
    expect(view.row("Access grants", "prod-deploy")).toContain("Activating…");
  });

  it("asks nothing for a row whose first host has no route here (yet)", async () => {
    const bare = overviewOf([web, db], [dbRoute]);
    const view = await renderPage(bare, { answers: { grants: [row({ entitlement: "prod-gone", host_ids: [web.id, db.id] })] } });
    expect(view.disabled("Request grant", { row: "prod-gone" })).toBe(true);
    view.click("Request grant", { row: "prod-gone" });
    expect(view.dialog).toBeNull();
  });

  it("says why a grant could not be read instead of saying there is none", async () => {
    const refused = "Privileged Access Manager refused the request: quota exceeded.";
    const view = await renderPage(overview, { answers: { grants: [row({ entitlement: "prod-admin", state: "error", message: refused })] } });
    expect(view.row("Access grants", "prod-admin")).toContain(refused);
    expect(view.row("Access grants", "prod-admin")).not.toContain("No active grant");
    expect(view.disabled("Request grant", { row: "prod-admin" })).toBe(false);
  });

  it("takes the answer of a request into its row at once, and into no other", async () => {
    // The same entitlement id in another project is another row.
    const other = row({ entitlement: "prod-admin", project: "acme-dev-654321", host_ids: [db2.id], state: "active", active_until_ms: AT });
    const view = await renderPage(overview, { answers: { grants: [admin, other] } });
    view.click("Request grant", { row: "acme-prod-123456" });
    expect(view.dialog?.given.entitlement).toBe("prod-admin");
    view.dialog!.given.onRequested({ entitlement: "prod-admin", state: "active", active_until_ms: LATER, message: null });
    expect(view.row("Access grants", "acme-prod-123456")).toContain("Active until 11:30");
    expect(view.disabled("Request grant", { row: "acme-prod-123456" })).toBe(true);
    expect(view.row("Access grants", "acme-dev-654321")).toContain("Active until 10:00");
    expect(view.client.getQueryData(pamGrantsKey)).toEqual([{ ...admin, state: "active", active_until_ms: LATER }, other]);
  });

  it("closes the request dialog when asked", async () => {
    const view = await renderPage(overview);
    view.click("Request grant", { row: "prod-admin" });
    expect(view.dialog).not.toBeNull();
    view.dialog!.given.onClose();
    expect(view.dialog).toBeNull();
  });

  it("is shown when a listed route requires a grant, and not otherwise", async () => {
    expect((await renderPage(overviewOf([web], [webRoute]))).sectionTitles()).not.toContain("Access grants");
    // db-2's route requires a grant but its host is gone: it is listed nowhere.
    expect((await renderPage(overviewOf([web], [webRoute, db2Route]))).sectionTitles()).not.toContain("Access grants");
    expect((await renderPage(overview)).sectionTitles()).toContain("Access grants");
  });

  it("leaves out a grant whose hosts are all gone, and names only the hosts that are here", async () => {
    const gone = row({ entitlement: "prod-gone", host_ids: [ghost.id] });
    const view = await renderPage(overview, { answers: { grants: [gone, row({ host_ids: [ghost.id, db2.id] })] } });
    expect(view.rows("Access grants")).toHaveLength(1);
    expect(view.rows("Access grants")[0]).toContain("Required by db-2");
    expect(view.text).not.toContain(ghost.id);
    expect(view.text).not.toContain("prod-gone");
  });

  it("waits for the first answer, says why there is none, and says when there is nothing to show", async () => {
    expect((await renderPage(overview, { settled: false })).text).toContain("Checking grants…");
    const failed = await renderPage(overview, { answers: { grants: new Error("Privileged Access Manager could not be reached.") } });
    expect(failed.text).toContain("Privileged Access Manager could not be reached.");
    expect(failed.rows("Access grants")).toEqual([]);
    expect((await renderPage(overview, { answers: { grants: [] } })).text).toContain("No grants to show.");
  });

  it("reads the grants only while a listed route requires one, and reads nothing while drawing", async () => {
    const enabled = (shown: RecordOverview) => {
      const client = new QueryClient();
      const calls = stubBackend(async () => []);
      renderHook(client, () => GoogleCloudPanel({ overview: shown, createIapHost: vi.fn(), editHost: vi.fn() }));
      expect(calls).toEqual([]);
      // The query is built with the options of the page that first asked for it, `enabled` among them (the type of `options` leaves it out).
      return (client.getQueryCache().find({ queryKey: pamGrantsKey })?.options as { enabled?: boolean } | undefined)?.enabled;
    };
    expect(enabled(overviewOf([web], [webRoute]))).toBe(false);
    expect(enabled(overviewOf([web], [webRoute, db2Route]))).toBe(false); // the route that requires a grant has no host here
    expect(enabled(overview)).toBe(true);
  });
});

describe("Hosts through IAP", () => {
  it("opens a host from the list, creates a new IAP host, and skips orphans", async () => {
    const view = await renderPage(overviewOf([web, ops], [webRoute, ghostRoute])); // ghost-1's route has no host here: an orphan
    expect(view.text).not.toContain(ghostRoute.host_id);
    expect(view.text).not.toContain("ghost-1");
    view.click("web-1", { row: "web-1", in: "Hosts through IAP" });
    expect(view.props.editHost).toHaveBeenCalledWith(web.id);
    view.click("New IAP host");
    expect(view.props.createIapHost).toHaveBeenCalled();
    expect(view.props.editHost).toHaveBeenCalledTimes(1);
    expect(view.rows("Hosts through IAP")).toHaveLength(1); // ops-1 has no route
  });

  it("shows each host's target, zone and account, by alias", async () => {
    const view = await renderPage(overviewOf([web, ops, db], [webRoute, opsRoute, dbRoute].reverse()));
    expect(view.rows("Hosts through IAP")).toEqual([
      "db-1 acme-prod-123456 / db-1 · asia-east1-b frank@example.com",
      "ops-1 acme-prod-123456 / ops-1 · asia-east1-c ops@example.com",
      "web-1 acme-prod-123456 / web-1 · asia-east1-b gcloud's active account",
    ]);
  });

  it("says when no host connects through IAP", async () => {
    expect(await renderPageText(overviewOf([web], []))).toContain(
      "No host connects through IAP yet. Open a host and choose Google Cloud IAP under Connect via, or create one with New IAP host.",
    );
    // Neither does an overview that lists no routes at all, nor one whose only route has lost its host.
    expect(await renderPageText(overviewOf([web], [ghostRoute]))).toContain("No host connects through IAP yet.");
    expect(await renderPageText(recordOverview({ hosts: [web], transports: undefined }))).toContain("No host connects through IAP yet.");
    expect(await renderPageText(overviewOf([web], [webRoute]))).not.toContain("No host connects through IAP yet.");
  });

  it("sets apart the routes a central library has no room for, after the others", async () => {
    const sync = [
      { host_id: web.id, synced: true },
      { host_id: ops.id, synced: false },
      { host_id: ghost.id, synced: false },
    ];
    const view = await renderPage(overviewOf([web, ops], [webRoute, opsRoute, ghostRoute], { ...library, transport_sync: sync }));
    // ops-1 sorts before web-1, but sits after it: it is the one the library has no room for.
    expect(view.rows("Hosts through IAP").map((line) => line.split(" ")[0])).toEqual(["web-1", "ops-1"]);
    expect(view.row("Hosts through IAP", "ops-1")).toContain("Saved on this computer only: the library has no room for this route");
    expect(view.row("Hosts through IAP", "web-1")).not.toContain("Saved on this computer only");
    // ghost-1's host is not here, so its route is listed nowhere.
    expect(view.text).not.toContain("ghost-1");
    // A route the library holds, and one it says nothing of, are not set apart.
    const quiet = await renderPage(overviewOf([web, ops], [webRoute, opsRoute], { ...library, transport_sync: [{ host_id: web.id, synced: true }] }));
    expect(quiet.text).not.toContain("Saved on this computer only");
  });

  it("does not set routes apart outside a central library, where every route stays on this computer by design", async () => {
    const sync = [{ host_id: ops.id, synced: false }, { host_id: web.id, synced: false }];
    const alone = await renderPage(overviewOf([web, ops], [webRoute, opsRoute], { transport_sync: sync }));
    expect(alone.text).not.toContain("Saved on this computer only");
    expect(alone.rows("Hosts through IAP").map((line) => line.split(" ")[0])).toEqual(["ops-1", "web-1"]);
    const chain = await renderPage(overviewOf([web], [webRoute], { account: library.account, transport_sync: sync }));
    expect(chain.text).not.toContain("Saved on this computer only");
    // Central sync is the library's own mode, which an account alone does not make and which needs an account to hold anything.
    const accountless = await renderPage(overviewOf([web], [webRoute], { central_mode: true, transport_sync: sync }));
    expect(accountless.text).not.toContain("Saved on this computer only");
  });
});

describe("words that come from outside", () => {
  it("shows hidden and direction-changing characters in aliases and Google's sentences as visible escapes", async () => {
    const odd = hostView({ id: db.id, payload: hostPayload({ alias: SPOOFED_NAME }) });
    const failing = row({ entitlement: "prod-admin", state: "error", message: `quota exceeded for ${SPOOFED_NAME}`, host_ids: [odd.id] });
    const unknown = { ...accounts, accounts: [{ account: "late@example.com", state: "unknown", message: `offline ${SPOOFED_NAME}` }] };
    const view = await renderPage(overviewOf([odd], [{ ...dbRoute, host_id: odd.id }]), { answers: { grants: [failing], accounts: unknown } });
    expect(view.row("Hosts through IAP", SPOOFED_NAME_SHOWN)).toContain(SPOOFED_NAME_SHOWN);
    expect(view.row("Access grants", "prod-admin")).toContain(`Required by ${SPOOFED_NAME_SHOWN}`);
    expect(view.row("Access grants", "prod-admin")).toContain(`quota exceeded for ${SPOOFED_NAME_SHOWN}`);
    expect(view.row("Google sign-in", "late@example.com")).toContain(`offline ${SPOOFED_NAME_SHOWN}`);
    expect(view.html).not.toMatch(HIDDEN_CHARS);
    view.click("Request grant", { row: "prod-admin" });
    expect(view.dialog?.text).toContain(SPOOFED_NAME_SHOWN);
    expect(view.dialog?.text).not.toMatch(HIDDEN_CHARS);
  });

  it("shows them in the sentence of a read that failed, too", async () => {
    const failed = await renderPage(overviewOf([db], [dbRoute]), {
      answers: { accounts: new Error(`gcloud said ${SPOOFED_NAME}`), grants: new Error(`Google said ${SPOOFED_NAME}`) },
    });
    expect(failed.text).toContain(`gcloud said ${SPOOFED_NAME_SHOWN}`);
    expect(failed.text).toContain(`Google said ${SPOOFED_NAME_SHOWN}`);
    expect(failed.html).not.toMatch(HIDDEN_CHARS);
  });
});
