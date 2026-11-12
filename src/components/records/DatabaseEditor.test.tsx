import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { RadioGroup } from "radix-ui";
import type { ReactElement, ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Input } from "@/components/ui/input";
import { CommandGroup, CommandInput, CommandItem } from "@/components/ui/command";
import { Switch } from "@/components/ui/switch";
import { buttonsIn, buttonTag, DISABLED, elementsOf, text, textIn } from "@/components/keychain/test-markup";
import { tauriInvoke } from "@/lib/ipc";
import type { RecordOverview } from "@/lib/records";
import { renderHook } from "@/lib/test-ipc";
import { databaseInstancesQuery, newDatabase, suggestPort, type DatabaseDraft, type InstanceSummary, type SavedDatabase } from "@/lib/databases";
import { gcloudAccountsKey, newPamCheck, pamSuggestionsQuery, type GcloudAccountsView, type TransportKind } from "@/lib/transports";
import {
  changed,
  DatabaseEditor,
  DatabaseEditorView,
  instanceProblem,
  instancesRead,
  opening,
  pickInstance,
  withConnectionName,
  withProject,
  type DatabaseEditorViewProps,
  type InstancesRead,
  type Mode,
} from "./DatabaseEditor";
import { groupView, hostPayload, hostTransport, hostView, recordOverview } from "./fixtures";
import { RecordField } from "./form";
import { EntitlementsInput, EntitlementSuggestions, EntitlementSuggestionsView, GoogleAccountField, IapRouteFields, segmented } from "./IapRouteFields";

vi.mock("@/lib/ipc", () => ({ tauriInvoke: vi.fn() }));
beforeEach(() => vi.mocked(tauriInvoke).mockReset());

/*
 * There is no DOM here, so the dialog is drawn two ways: as static markup (its words and the state of its controls), and as the
 * element tree of its hook-free view, whose callbacks the tests press. The state the dialog keeps (the draft, the way the instance is
 * chosen, the connection name as typed) is kept by `editor` below, the way the dialog keeps it.
 */

const PROD = "acme-prod-123456";
const DEV = "acme-dev-654321";
const CONNECTION = `${PROD}:asia-east1:orders-pg`;
const IAM_OFF = "IAM sign-in is off on this instance.";
const NO_PUBLIC_IP = "This instance has no public IP. Lunport connects over public IP in this release.";

const instance = (patch: Partial<InstanceSummary> = {}): InstanceSummary => ({
  name: "orders-pg",
  region: "asia-east1",
  database_version: "POSTGRES_16",
  public_ip: true,
  private_ip: true,
  iam_authentication: true,
  ...patch,
});
const ORDERS_PG = instance();
const NEW_LOCATED = pickInstance({ ...newDatabase(), project: PROD }, ORDERS_PG);
/** Reachable over its private address only. */
const BILLING_PG = instance({ name: "billing-pg", public_ip: false });
/** Signs nobody in with Google. */
const REPORTS_PG = instance({ name: "reports-pg", database_version: "POSTGRES_15", private_ip: false, iam_authentication: false });
const listed = (instances: InstanceSummary[]): InstancesRead => ({ state: "listed", instances });

/** A prod database as the list holds it: two entitlements, a grant of 45 minutes, its own port. */
const SAVED: SavedDatabase = {
  id: "00000000000000a1",
  name: "Orders",
  engine: "postgres",
  project: PROD,
  region: "asia-east1",
  instance: "orders-pg",
  environment: "prod",
  network: "public",
  account: "frank@example.com",
  default_database: "orders",
  pam: { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 2700, justification: null },
  local_port: 6543,
};

const accounts: GcloudAccountsView = {
  config_found: true,
  active: "frank@example.com",
  accounts: [
    { account: "frank@example.com", state: "signed_in", message: null },
    { account: "old@example.com", state: "expired", message: null },
  ],
};

type Options = {
  mode?: Mode;
  connection?: string;
  instances?: InstancesRead;
  used?: number[];
  busy?: boolean;
  error?: string | null;
  /** What the account field and the suggestions read; by default a client that has read gcloud's accounts. */
  client?: QueryClient;
  /** What Google is asked about; by default the draft's account and project, as when typing has paused. */
  lookup?: { account: string | null; project: string };
  /** The library the Route field lists the hosts of; by default one host, `web`, with no route. */
  overview?: RecordOverview;
};

/** The view of the dialog over `initial`, with the state the dialog keeps for it: pressing a control changes `kept` as the dialog's state setters do. */
function editor(initial: DatabaseDraft, options: Options = {}) {
  const kept = { draft: initial, mode: options.mode ?? (initial.instance === "" ? "pick" : "manual"), connection: options.connection ?? "", hostMissing: false };
  const onSave = vi.fn();
  const onCancel = vi.fn();
  const createIapHost = vi.fn();
  const overview = options.overview ?? recordOverview();
  const props = (): DatabaseEditorViewProps => ({
    draft: kept.draft,
    mode: kept.mode,
    connection: kept.connection,
    instances: options.instances ?? { state: "waiting" },
    lookup: options.lookup ?? { account: kept.draft.account, project: kept.draft.project },
    used: options.used ?? [],
    busy: options.busy ?? false,
    error: options.error ?? null,
    onDraft: (next) => {
      kept.draft = next;
    },
    onMode: (next) => {
      kept.mode = next;
    },
    onConnection: (next) => {
      kept.connection = next;
    },
    onSave,
    onCancel,
    overview,
    hostMissing: kept.hostMissing,
    onHostMissing: () => {
      kept.hostMissing = true;
    },
    createIapHost,
  });
  const tree = () => DatabaseEditorView(props());
  const markup = () => renderToStaticMarkup(<QueryClientProvider client={options.client ?? cache()}>{tree()}</QueryClientProvider>);
  return { kept, onSave, onCancel, createIapHost, tree, markup };
}

const propsOf = <T,>(element: ReactElement) => element.props as unknown as T;

/** The control inside the field labelled `label`. */
function controlOf(tree: ReactNode, label: string): ReactElement {
  const field = elementsOf(tree, RecordField).find((element) => propsOf<{ label: string }>(element).label === label);
  if (!field) throw new Error(`no ${label} field`);
  const control = [Input, "select", EntitlementsInput].flatMap((type) => elementsOf(field, type))[0];
  if (!control) throw new Error(`no control in the ${label} field`);
  return control;
}
const hasField = (tree: ReactNode, label: string) => elementsOf(tree, RecordField).some((element) => propsOf<{ label: string }>(element).label === label);
/** Types `value` into the field labelled `label`. */
const typeInto = (tree: ReactNode, label: string, value: string) =>
  propsOf<{ onChange: (event: { target: { value: string } }) => void }>(controlOf(tree, label)).onChange({ target: { value } });
const valueOf = (tree: ReactNode, label: string) => propsOf<{ value: unknown }>(controlOf(tree, label)).value;

/** The switch in the row whose words include `label`. */
function switchOf(tree: ReactNode, label: string) {
  const row = elementsOf(tree, "label").find((element) => textIn(element).includes(label));
  const found = row && elementsOf(row, Switch)[0];
  if (!found) throw new Error(`no ${label} switch`);
  return propsOf<{ checked: boolean; onCheckedChange: (on: boolean) => void }>(found);
}

/** A segmented control by its accessible name. */
function groupOf(tree: ReactNode, label: string) {
  const found = elementsOf(tree, RadioGroup.Root).find((element) => propsOf<Record<string, unknown>>(element)["aria-label"] === label);
  if (!found) throw new Error(`no ${label} control`);
  return propsOf<{ value: string; onValueChange: (value: string) => void }>(found);
}

/** The radio of the instance row that starts with `name`. */
function radioOf(tree: ReactNode, name: string) {
  const row = elementsOf(tree, "label").find((element) => elementsOf(element, "input").length > 0 && textIn(element).startsWith(name));
  if (!row) throw new Error(`no ${name} instance`);
  return propsOf<{ checked: boolean; disabled: boolean; onChange: () => void }>(elementsOf(row, "input")[0]);
}

/** The opening tag of the radio of the instance row that starts with `name`, from markup. */
function radioTag(html: string, name: string): string {
  const row = [...html.matchAll(/<label\b[^>]*>(?:(?!<\/label>)[\s\S])*<\/label>/g)]
    .map((match) => match[0])
    .find((markup) => markup.includes('type="radio"') && text(markup).trim().startsWith(name));
  if (!row) throw new Error(`no ${name} instance`);
  return row.match(/<input\b[^>]*>/)![0];
}

/** Presses Save database as a browser does: the form is submitted. */
function submit(tree: ReactNode) {
  const preventDefault = vi.fn();
  propsOf<{ onSubmit: (event: { preventDefault: () => void }) => void }>(elementsOf(tree, "form")[0]).onSubmit({ preventDefault });
  expect(preventDefault, "the page is not reloaded").toHaveBeenCalledTimes(1);
}

describe("the New database dialog", () => {
  it("shows instance selection before connection settings", () => {
    const dialog = editor({ ...newDatabase(), project: PROD }, { instances: listed([ORDERS_PG]) });
    expect(text(dialog.markup())).toContain("Cloud SQL instances in acme-prod-123456");
    expect(hasField(dialog.tree(), "Name")).toBe(false);
    expect(elementsOf(dialog.tree(), RadioGroup.Root).some((item) => propsOf<{ "aria-label": string }>(item)["aria-label"] === "Route")).toBe(false);
    radioOf(dialog.tree(), "orders-pg").onChange();
    expect(hasField(dialog.tree(), "Name")).toBe(true);
    expect(groupOf(dialog.tree(), "Route").value).toBe("public");
    expect(text(dialog.markup())).toContain("Local access");
  });

  it("keeps advanced access collapsed unless a saved record uses PAM", () => {
    const fresh = editor(pickInstance({ ...newDatabase(), project: PROD }, ORDERS_PG));
    const advanced = elementsOf(fresh.tree(), "details")[0];
    expect(propsOf<{ open?: boolean }>(advanced).open).toBe(false);
    expect(textIn(advanced)).toContain("Advanced access");
    expect(propsOf<{ open?: boolean }>(elementsOf(editor(SAVED).tree(), "details")[0]).open).toBe(true);
  });

  it("suggestPort_skips_ports_in_use", () => {
    expect(suggestPort([])).toBe(6543);
    expect(suggestPort([6543])).toBe(6544);
    expect(suggestPort([6543, 6544, 6546])).toBe(6545);
    // Whatever order they come in, and a gap below the first stays free.
    expect(suggestPort([6545, 6543, 6544])).toBe(6546);
    expect(suggestPort([6544, 6545])).toBe(6543);
    // Ports below where it starts are nobody's business, and a port in use twice counts once.
    expect(suggestPort([5432, 80, 6000])).toBe(6543);
    expect(suggestPort([6543, 6543, 6544])).toBe(6545);
  });

  it("iam_off_instances_cannot_be_picked", () => {
    const dialog = editor({ ...newDatabase(), account: "frank@example.com", project: PROD }, { instances: listed([ORDERS_PG, REPORTS_PG]) });
    const html = dialog.markup();
    // Both are listed; the one with IAM sign-in off is disabled and says why, once.
    expect(text(html)).toContain("orders-pg");
    expect(text(html)).toContain("reports-pg");
    expect(text(html).match(/IAM sign-in is off on this instance\./g)).toHaveLength(1);
    expect(radioTag(html, "reports-pg")).toContain(DISABLED);
    expect(radioTag(html, "orders-pg")).not.toContain(DISABLED);
    expect(radioOf(dialog.tree(), "reports-pg").disabled).toBe(true);
    expect(radioOf(dialog.tree(), "orders-pg").disabled).toBe(false);
    // The other one can be chosen.
    radioOf(dialog.tree(), "orders-pg").onChange();
    expect(dialog.kept.draft).toMatchObject({ project: PROD, region: "asia-east1", instance: "orders-pg" });
    expect(instanceProblem(REPORTS_PG)).toBe(IAM_OFF);
    expect(instanceProblem(ORDERS_PG)).toBeNull();
  });

  it("an_instance_without_a_public_ip_can_be_picked", () => {
    const dialog = editor({ ...newDatabase(), project: PROD }, { instances: listed([ORDERS_PG, BILLING_PG, REPORTS_PG]) });
    const html = dialog.markup();
    // It is reached through a host of the library: nothing says it cannot be connected to, and its radio is on.
    expect(text(html)).not.toContain(NO_PUBLIC_IP);
    expect(radioTag(html, "billing-pg")).not.toContain(DISABLED);
    expect(radioOf(dialog.tree(), "billing-pg").disabled).toBe(false);
    expect(instanceProblem(BILLING_PG)).toBeNull();
    radioOf(dialog.tree(), "billing-pg").onChange();
    expect(dialog.kept.draft).toMatchObject({ region: "asia-east1", instance: "billing-pg" });
    // The instance with IAM sign-in off is still held back, and says why, once, whatever addresses it has.
    expect(text(html).match(/IAM sign-in is off on this instance\./g)).toHaveLength(1);
    expect(radioTag(html, "reports-pg")).toContain(DISABLED);
    expect(instanceProblem(instance({ public_ip: false, private_ip: false, iam_authentication: false }))).toBe(IAM_OFF);
  });

  it("describes_each_instance_by_its_region_addresses_and_version", () => {
    const html = text(editor({ ...newDatabase(), project: PROD }, { instances: listed([ORDERS_PG, BILLING_PG, REPORTS_PG]) }).markup());
    expect(html).toContain("orders-pg PostgreSQL 16 asia-east1 · Public IP and private IP · IAM sign-in on");
    expect(html).toContain("billing-pg PostgreSQL 16 asia-east1 · Private IP only");
    expect(html).toContain("reports-pg PostgreSQL 15 asia-east1 · Public IP");
    expect(text(editor({ ...newDatabase(), project: PROD }, { instances: listed([instance({ database_version: "POSTGRES_9_6" })]) }).markup())).toContain("POSTGRES_9_6");
  });

  it("manual_mode_parses_the_connection_name", () => {
    const dialog = editor({ ...newDatabase(), account: "frank@example.com", environment: "dev" }, { mode: "manual" });
    expect(text(dialog.markup())).toContain("Connection name");
    expect(hasField(dialog.tree(), "Project")).toBe(false);
    // The three parts are read from the text, each trimmed, and the text stays as it was typed.
    typeInto(dialog.tree(), "Connection name", ` ${PROD} : asia-east1 : orders-pg `);
    expect(dialog.kept.connection).toBe(` ${PROD} : asia-east1 : orders-pg `);
    expect(dialog.kept.draft).toMatchObject({ project: PROD, region: "asia-east1", instance: "orders-pg" });
    expect(buttonTag(dialog.markup(), "Save database")).not.toContain(DISABLED);
    // Text that is not three parts places the database nowhere, so there is nothing to save.
    typeInto(dialog.tree(), "Connection name", `${PROD}:asia-east1`);
    expect(dialog.kept.draft).toMatchObject({ project: "", region: "", instance: "" });
    expect(text(dialog.markup())).toContain("Enter the project, region and instance, separated by colons.");
    expect(buttonTag(dialog.markup(), "Save database")).toContain(DISABLED);
    // Nothing typed yet is not an error.
    typeInto(dialog.tree(), "Connection name", "");
    expect(text(dialog.markup())).not.toContain("separated by colons");
    expect(withConnectionName(newDatabase(), CONNECTION)).toMatchObject({ project: PROD, region: "asia-east1", instance: "orders-pg" });
    expect(withConnectionName(newDatabase(), "orders-pg")).toMatchObject({ project: "", region: "", instance: "" });
  });

  it("manual_entry_names_the_database_after_its_instance_until_a_name_is_typed", () => {
    const dialog = editor(newDatabase(), { mode: "manual" });
    // Typed character by character, the name follows the instance as long as nobody typed over it.
    typeInto(dialog.tree(), "Connection name", `${PROD}:asia-east1:o`);
    expect(dialog.kept.draft.name).toBe("o");
    typeInto(dialog.tree(), "Connection name", `${PROD}:asia-east1:orders-pg`);
    expect(dialog.kept.draft.name).toBe("orders-pg");
    typeInto(dialog.tree(), "Name", "Orders (prod)");
    typeInto(dialog.tree(), "Connection name", `${PROD}:asia-east1:orders-pg-2`);
    expect(dialog.kept.draft).toMatchObject({ name: "Orders (prod)", instance: "orders-pg-2" });
  });

  it("switching_to_the_connection_name_shows_the_instance_picked_and_never_a_stale_name", () => {
    const dialog = editor({ ...newDatabase(), project: PROD }, { instances: listed([ORDERS_PG]) });
    radioOf(dialog.tree(), "orders-pg").onChange();
    groupOf(dialog.tree(), "How to choose the instance").onValueChange("manual");
    expect(dialog.kept.mode).toBe("manual");
    expect(dialog.kept.connection).toBe(CONNECTION);
    // Back to the list, with nothing lost.
    groupOf(dialog.tree(), "How to choose the instance").onValueChange("pick");
    expect(dialog.kept.mode).toBe("pick");
    expect(dialog.kept.draft).toMatchObject({ project: PROD, instance: "orders-pg" });
    // Nothing picked, nothing typed: the field starts empty, and the text that was typed before does not come back.
    const bare = editor(newDatabase(), { connection: "acme" });
    groupOf(bare.tree(), "How to choose the instance").onValueChange("manual");
    expect(bare.kept.connection).toBe("");
  });

  it("a_connection_name_typed_before_the_pick_was_taken_back_does_not_come_back", () => {
    // Typed as a name, then the list, then another project in the list (which takes the pick back), then the name again.
    const dialog = editor({ ...newDatabase(), account: "frank@example.com" }, { mode: "manual", instances: listed([ORDERS_PG]) });
    typeInto(dialog.tree(), "Connection name", CONNECTION);
    expect(dialog.kept.draft).toMatchObject({ project: PROD, region: "asia-east1", instance: "orders-pg" });
    groupOf(dialog.tree(), "How to choose the instance").onValueChange("pick");
    typeInto(dialog.tree(), "Project", DEV);
    expect(dialog.kept.draft).toMatchObject({ project: DEV, region: "", instance: "" });
    groupOf(dialog.tree(), "How to choose the instance").onValueChange("manual");
    expect(dialog.kept.mode).toBe("manual");
    // The draft is nowhere, so the field says nothing; it does not keep naming an instance the draft no longer holds.
    expect(dialog.kept.connection).toBe("");
    expect(valueOf(dialog.tree(), "Connection name")).toBe("");
    expect(buttonTag(dialog.markup(), "Save database")).toContain(DISABLED);
    // Picking again in the list shows as that instance's name.
    groupOf(dialog.tree(), "How to choose the instance").onValueChange("pick");
    typeInto(dialog.tree(), "Project", PROD);
    radioOf(dialog.tree(), "orders-pg").onChange();
    groupOf(dialog.tree(), "How to choose the instance").onValueChange("manual");
    expect(dialog.kept.connection).toBe(CONNECTION);
    expect(valueOf(dialog.tree(), "Connection name")).toBe(CONNECTION);
  });

  it("saving_a_prod_database_sends_its_entitlement", () => {
    const dialog = editor({ ...newDatabase(), account: "frank@example.com", project: PROD }, { instances: listed([ORDERS_PG]) });
    radioOf(dialog.tree(), "orders-pg").onChange();
    groupOf(dialog.tree(), "Environment").onValueChange("prod");
    switchOf(dialog.tree(), "Requires a PAM grant").onCheckedChange(true);
    propsOf<{ onChange: (next: string[]) => void }>(elementsOf(dialog.tree(), EntitlementsInput)[0]).onChange(["prod-operate"]);
    typeInto(dialog.tree(), "Name", "  Orders ");
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenCalledTimes(1);
    // The grant check is the entitlement typed, in the global location, for 30 minutes; nothing else is made up.
    expect(dialog.onSave).toHaveBeenCalledWith({
      id: "",
      name: "Orders",
      engine: "postgres",
      project: PROD,
      region: "asia-east1",
      instance: "orders-pg",
      environment: "prod",
      network: "public",
      account: "frank@example.com",
      default_database: "postgres",
      pam: { entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: null },
      local_port: null,
    });
  });

  it("saving_an_unchanged_database_sends_it_back_as_it_is", () => {
    // Opened to look at, or to change one thing: nothing it holds (two entitlements, 45 minutes, its port) is lost on the way.
    const dialog = editor(SAVED);
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenCalledWith(SAVED);
    typeInto(dialog.tree(), "Name", "Orders (prod)");
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenLastCalledWith({ ...SAVED, name: "Orders (prod)" });
  });

  it("nothing_is_saved_until_an_instance_is_chosen", () => {
    const empty = editor({ ...newDatabase(), project: PROD, environment: "dev" }, { instances: listed([ORDERS_PG]) });
    expect(buttonTag(empty.markup(), "Save database")).toContain(DISABLED);
    submit(empty.tree());
    expect(empty.onSave).not.toHaveBeenCalled();
    radioOf(empty.tree(), "orders-pg").onChange();
    expect(buttonTag(empty.markup(), "Save database")).not.toContain(DISABLED);
    submit(empty.tree());
    expect(empty.onSave).toHaveBeenCalledTimes(1);
  });

  it("holds_every_control_while_a_save_is_under_way_and_shows_why_one_failed", () => {
    const busy = editor(SAVED, { busy: true });
    expect(busy.markup()).toMatch(/<fieldset[^>]*disabled=""/);
    expect(buttonTag(busy.markup(), "Save database")).toContain(DISABLED);
    expect(buttonTag(busy.markup(), "Cancel")).toContain(DISABLED);
    const idle = editor(SAVED);
    expect(idle.markup()).not.toMatch(/<fieldset[^>]*disabled=""/);
    expect(buttonTag(idle.markup(), "Cancel")).not.toContain(DISABLED);
    expect(idle.markup()).not.toContain('role="alert"');
    // The sentence the save failed with, where the person can see it beside the buttons.
    const failed = editor(SAVED, { error: "Enter at least one PAM entitlement." });
    expect(failed.markup()).toMatch(/<p[^>]*role="alert"[^>]*>Enter at least one PAM entitlement\.<\/p>/);
    buttonsIn(failed.tree()).find((button) => textIn(button) === "Cancel")!.props.onClick!();
    expect(failed.onCancel).toHaveBeenCalledTimes(1);
  });

  it("picking_an_instance_fills_the_name_the_region_the_instance_and_the_default_database", () => {
    const typed = { ...newDatabase(), project: PROD, name: "Orders", default_database: "orders" };
    expect(pickInstance(newDatabase(), ORDERS_PG)).toMatchObject({ name: "orders-pg", region: "asia-east1", instance: "orders-pg", default_database: "postgres", project: "" });
    // The project stays; a name that was typed stays; the default database starts again from postgres.
    expect(pickInstance(typed, ORDERS_PG)).toMatchObject({ project: PROD, name: "Orders", region: "asia-east1", instance: "orders-pg", default_database: "postgres" });
  });

  it("picking_replaces_a_name_only_when_it_is_empty_or_the_last_instance_picked", () => {
    const first = pickInstance({ ...newDatabase(), project: PROD }, ORDERS_PG);
    expect(first.name).toBe("orders-pg");
    // Still the instance's own name: it follows the next pick.
    expect(pickInstance(first, instance({ name: "analytics-pg", region: "us-central1" })).name).toBe("analytics-pg");
    // A name of spaces is no name.
    expect(pickInstance({ ...newDatabase(), project: PROD, name: "   " }, ORDERS_PG).name).toBe("orders-pg");
    // A name that was typed over it stays, for this pick and for the ones after.
    const renamed = { ...first, name: "Orders (prod)" };
    const second = pickInstance(renamed, instance({ name: "analytics-pg" }));
    expect(second.name).toBe("Orders (prod)");
    expect(pickInstance(second, ORDERS_PG).name).toBe("Orders (prod)");
  });

  it("a_new_project_takes_back_the_instance_picked_in_the_old_one", () => {
    const picked = pickInstance({ ...newDatabase(), project: PROD }, ORDERS_PG);
    expect(withProject(picked, DEV)).toMatchObject({ project: DEV, region: "", instance: "", name: "" });
    // The same project again changes nothing; a name that was typed stays.
    expect(withProject(picked, PROD)).toBe(picked);
    expect(withProject({ ...picked, name: "Orders (prod)" }, DEV)).toMatchObject({ project: DEV, region: "", instance: "", name: "Orders (prod)" });
    // Through the dialog: the pick goes, Save is off, and the list asks for the new project.
    const dialog = editor({ ...newDatabase(), project: PROD }, { instances: listed([ORDERS_PG]) });
    radioOf(dialog.tree(), "orders-pg").onChange();
    typeInto(dialog.tree(), "Project", ` ${DEV} `);
    expect(dialog.kept.draft).toMatchObject({ project: DEV, region: "", instance: "" });
    expect(buttonTag(dialog.markup(), "Save database")).toContain(DISABLED);
  });

  it("marks_the_instance_that_is_saved_as_the_one_chosen", () => {
    const dialog = editor({ ...SAVED, name: "Orders" }, { mode: "pick", instances: listed([ORDERS_PG, REPORTS_PG]) });
    expect(radioOf(dialog.tree(), "orders-pg").checked).toBe(true);
    expect(radioOf(dialog.tree(), "reports-pg").checked).toBe(false);
    expect(radioTag(dialog.markup(), "orders-pg")).toContain('checked=""');
    // The same name in another region is another instance.
    const elsewhere = editor({ ...SAVED, region: "us-central1" }, { mode: "pick", instances: listed([ORDERS_PG]) });
    expect(radioOf(elsewhere.tree(), "orders-pg").checked).toBe(false);
  });

  it("says_where_the_instance_list_stands", () => {
    const says = (instances: InstancesRead, project = DEV) => text(editor({ ...newDatabase(), project }, { instances }).markup());
    expect(says({ state: "waiting" }, "")).toContain("Enter a project id to list its Cloud SQL instances.");
    expect(says({ state: "loading" })).toContain("Loading instances…");
    expect(says(listed([]))).toContain(`No PostgreSQL instances in ${DEV}.`);
    expect(says(listed([ORDERS_PG]))).toContain(`Cloud SQL instances in ${DEV}`);
    expect(says(listed([ORDERS_PG]))).not.toContain("No PostgreSQL instances");
    // Why the list is empty, in the API's own sentence, as an alert.
    const sentence = `Cloud SQL Admin refused the request: The Cloud SQL Admin API is not enabled in ${DEV}. Enable it in the Google Cloud console, then try again.`;
    const html = editor({ ...newDatabase(), project: DEV }, { instances: { state: "failed", message: sentence } }).markup();
    expect(html).toMatch(/<p[^>]*role="alert"[^>]*>Cloud SQL Admin refused the request:/);
    expect(text(html)).toContain(sentence);
    expect(html).not.toContain("Loading instances");
  });

  it("reads_the_instance_list_from_what_the_query_found", () => {
    const found = [ORDERS_PG];
    expect(instancesRead("", { data: found, isError: false, error: null })).toEqual({ state: "waiting" });
    expect(instancesRead("acme", { data: found, isError: false, error: null })).toEqual({ state: "waiting" });
    expect(instancesRead(DEV, { data: undefined, isError: false, error: null })).toEqual({ state: "loading" });
    expect(instancesRead(DEV, { data: found, isError: false, error: null })).toEqual(listed(found));
    expect(instancesRead(DEV, { data: [], isError: false, error: null })).toEqual(listed([]));
    // A read that failed says so in place of an earlier list, as the sentence the backend gave (a string, or an Error).
    expect(instancesRead(DEV, { data: found, isError: true, error: "Sign in again." })).toEqual({ state: "failed", message: "Sign in again." });
    expect(instancesRead(DEV, { data: undefined, isError: true, error: new Error("Google did not answer.") })).toEqual({ state: "failed", message: "Google did not answer." });
    expect(instancesRead(DEV, { data: undefined, isError: true, error: `Sign in\u202e again.` })).toEqual({ state: "failed", message: "Sign in⟨U+202E⟩ again." });
  });

  it("reads_the_list_as_loading_while_the_project_or_account_is_still_being_typed", () => {
    const found = [ORDERS_PG];
    // What the query holds is for the project the dialog settled on, which is not the one typed now: not shown as this project's.
    expect(instancesRead(DEV, { data: found, isError: false, error: null }, false)).toEqual({ state: "loading" });
    expect(instancesRead(DEV, { data: undefined, isError: true, error: "Sign in again." }, false)).toEqual({ state: "loading" });
    expect(instancesRead(DEV, { data: found, isError: false, error: null }, true)).toEqual(listed(found));
    // A text that is not a project is not waited for: nothing will be asked about it.
    expect(instancesRead("acme", { data: found, isError: false, error: null }, false)).toEqual({ state: "waiting" });
    expect(instancesRead("", { data: found, isError: false, error: null }, false)).toEqual({ state: "waiting" });
  });

  it("offers_the_three_environments_as_one_choice_with_none_chosen_for_a_new_database", () => {
    const dialog = editor(NEW_LOCATED);
    const html = dialog.markup();
    expect(text(html)).toMatch(/Environment\s+Dev\s+Staging\s+Prod/);
    expect(groupOf(dialog.tree(), "Environment").value).toBeNull();
    expect(html).not.toMatch(/aria-checked="true"[^>]*>(Dev|Staging|Prod)</);
    expect(text(html)).toContain("Choose Dev, Staging or Prod.");
    expect(html).toMatch(/aria-label="Environment"/);
    groupOf(dialog.tree(), "Environment").onValueChange("staging");
    expect(dialog.kept.draft.environment).toBe("staging");
    expect(text(dialog.markup())).not.toContain("Choose Dev, Staging or Prod.");
    groupOf(dialog.tree(), "Environment").onValueChange("prod");
    expect(dialog.kept.draft.environment).toBe("prod");
    expect(text(html)).toContain("connections through the local port open read-only");
    // A saved database opens with its own environment chosen.
    expect(groupOf(editor(SAVED).tree(), "Environment").value).toBe("prod");
    expect(text(editor(SAVED).markup())).not.toContain("Choose Dev, Staging or Prod.");
  });

  it("a_new_database_is_saved_only_once_its_environment_is_chosen", () => {
    const dialog = editor({ ...newDatabase(), account: "frank@example.com", project: PROD }, { instances: listed([ORDERS_PG]) });
    radioOf(dialog.tree(), "orders-pg").onChange();
    // Everything else is there: only the environment holds Save back.
    expect(buttonTag(dialog.markup(), "Save database")).toContain(DISABLED);
    submit(dialog.tree());
    expect(dialog.onSave).not.toHaveBeenCalled();
    groupOf(dialog.tree(), "Environment").onValueChange("dev");
    expect(buttonTag(dialog.markup(), "Save database")).not.toContain(DISABLED);
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ instance: "orders-pg", environment: "dev" }));
  });

  it("the_pam_switch_asks_for_thirty_minutes_in_the_global_location_and_off_forgets_the_check", () => {
    const dialog = editor(NEW_LOCATED);
    expect(switchOf(dialog.tree(), "Requires a PAM grant").checked).toBe(false);
    expect(hasField(dialog.tree(), "Entitlements")).toBe(false);
    switchOf(dialog.tree(), "Requires a PAM grant").onCheckedChange(true);
    expect(dialog.kept.draft.pam).toEqual({ entitlements: [], location: "global", duration_secs: 1800, justification: null });
    expect(switchOf(dialog.tree(), "Requires a PAM grant").checked).toBe(true);
    expect(hasField(dialog.tree(), "Entitlements")).toBe(true);
    propsOf<{ onChange: (next: string[]) => void }>(elementsOf(dialog.tree(), EntitlementsInput)[0]).onChange(["prod-operate", "prod-admin"]);
    expect(dialog.kept.draft.pam?.entitlements).toEqual(["prod-operate", "prod-admin"]);
    switchOf(dialog.tree(), "Requires a PAM grant").onCheckedChange(false);
    expect(dialog.kept.draft.pam).toBeNull();
    expect(hasField(dialog.tree(), "Entitlements")).toBe(false);
    // The justification of a request is never typed here, and nothing in the dialog asks for one.
    expect(text(editor(SAVED).markup())).not.toMatch(/justification/i);
  });

  it("draws_the_entitlement_suggestions_for_the_drafts_account_project_and_check_and_adds_the_one_pressed", () => {
    const check = { entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: null };
    const dialog = editor({ ...NEW_LOCATED, account: "frank@example.com", pam: check });
    const suggestions = elementsOf(dialog.tree(), EntitlementSuggestions);
    expect(suggestions).toHaveLength(1);
    expect(propsOf(suggestions[0])).toMatchObject({ account: "frank@example.com", project: PROD, pam: check, disabled: false });
    propsOf<{ onAdd: (id: string) => void }>(suggestions[0]).onAdd("prod-admin");
    expect(dialog.kept.draft.pam).toEqual({ ...check, entitlements: ["prod-operate", "prod-admin"] });
    // Nothing is drawn while the check is off, and nothing is pressed while a save is under way.
    expect(elementsOf(editor(newDatabase()).tree(), EntitlementSuggestions)).toHaveLength(0);
    expect(propsOf(elementsOf(editor({ ...NEW_LOCATED, pam: check }, { busy: true }).tree(), EntitlementSuggestions)[0])).toMatchObject({ disabled: true });
  });

  it("a_new_database_opens_offered_to_other_apps_on_the_first_free_port_and_a_saved_one_keeps_its_own_setting", () => {
    const other = (id: string, local_port: number | null): SavedDatabase => ({ ...SAVED, id, local_port });
    // A new database has no identity yet: it is shared from the first port the other databases leave free.
    expect(opening(newDatabase(), [])).toEqual({ ...newDatabase(), local_port: 6543 });
    expect(opening(newDatabase(), [other("00000000000000a2", 6543), other("00000000000000a3", null), other("00000000000000a4", 6544)])).toEqual({ ...newDatabase(), local_port: 6545 });
    expect(opening(newDatabase(), [other("00000000000000a2", 6544)]).local_port).toBe(6543);
    // A saved database is opened as it is saved: not shared stays not shared, and its own port stays its own.
    const unshared = { ...SAVED, local_port: null };
    expect(opening(unshared, [other("00000000000000a2", 6543)])).toBe(unshared);
    expect(opening(SAVED, [other("00000000000000a2", 6543)])).toBe(SAVED);
  });

  it("the_dialog_of_a_new_database_shows_sharing_on_with_the_port_proposed_and_a_saved_one_as_it_is", () => {
    const client = cache();
    const other = (id: string, local_port: number | null): SavedDatabase => ({ ...SAVED, id, local_port });
    const shown = (initial: DatabaseDraft, existing: SavedDatabase[] = []) => {
      const tree = DatabaseEditorView(viewOf(client, { initial, existing }).props);
      return { sharing: switchOf(tree, "Let other apps connect").checked, port: hasField(tree, "Port on 127.0.0.1") ? valueOf(tree, "Port on 127.0.0.1") : null };
    };
    expect(shown(NEW_LOCATED)).toEqual({ sharing: true, port: 6543 });
    expect(shown(NEW_LOCATED, [other("00000000000000a2", 6543), other("00000000000000a3", 6544)])).toEqual({ sharing: true, port: 6545 });
    expect(shown({ ...SAVED, local_port: null }, [other("00000000000000a2", 6543)])).toEqual({ sharing: false, port: null });
    expect(shown(SAVED, [other("00000000000000a2", 6544)])).toEqual({ sharing: true, port: 6543 });
  });

  it("changed_tells_whether_the_draft_is_still_the_database_the_dialog_opened_with", () => {
    const opened = opening(newDatabase(), []);
    expect(changed(opened, opened)).toBe(false);
    // A copy is no change.
    expect(changed({ ...opened }, opened)).toBe(false);
    expect(changed(JSON.parse(JSON.stringify(SAVED)), SAVED)).toBe(false);
    // Every field the dialog sets counts.
    const edits: Partial<SavedDatabase>[] = [
      { name: "Orders" },
      { project: PROD },
      { region: "asia-east1" },
      { instance: "orders-pg" },
      { environment: "prod" },
      { account: "frank@example.com" },
      { default_database: "orders" },
      { pam: newPamCheck() },
      { local_port: null },
      { local_port: 6544 },
      { network: "private", via_host: "00000000000000b1" },
      { network: "private" },
    ];
    for (const edit of edits) expect(changed({ ...opened, ...edit }, opened), JSON.stringify(edit)).toBe(true);
    expect(changed({ ...SAVED, pam: null }, SAVED)).toBe(true);
    expect(changed({ ...SAVED, pam: { ...SAVED.pam!, entitlements: ["prod-operate"] } }, SAVED)).toBe(true);
    expect(changed({ ...SAVED, pam: { ...SAVED.pam!, duration_secs: 3600 } }, SAVED)).toBe(true);
    // Changed and changed back is not a change.
    expect(changed({ ...SAVED, name: "Orders (prod)", local_port: 6544 }, SAVED)).toBe(true);
    expect(changed({ ...SAVED, name: "Orders", local_port: 6543 }, SAVED)).toBe(false);
  });

  it("typing_a_name_and_typing_it_back_leaves_the_dialog_unchanged", () => {
    const dialog = editor(SAVED);
    typeInto(dialog.tree(), "Name", "Orders (prod)");
    expect(changed(dialog.kept.draft, SAVED)).toBe(true);
    typeInto(dialog.tree(), "Name", "Orders");
    expect(changed(dialog.kept.draft, SAVED)).toBe(false);
    // The PAM check switched off and on again is a new check, and that is a change from one with two entitlements.
    switchOf(dialog.tree(), "Requires a PAM grant").onCheckedChange(false);
    switchOf(dialog.tree(), "Requires a PAM grant").onCheckedChange(true);
    expect(changed(dialog.kept.draft, SAVED)).toBe(true);
  });

  it("sharing_proposes_the_first_free_port_and_off_offers_none", () => {
    const dialog = editor(NEW_LOCATED, { used: [6543, 6544] });
    expect(switchOf(dialog.tree(), "Let other apps connect").checked).toBe(false);
    expect(hasField(dialog.tree(), "Port on 127.0.0.1")).toBe(false);
    switchOf(dialog.tree(), "Let other apps connect").onCheckedChange(true);
    expect(dialog.kept.draft.local_port).toBe(6545);
    expect(switchOf(dialog.tree(), "Let other apps connect").checked).toBe(true);
    expect(valueOf(dialog.tree(), "Port on 127.0.0.1")).toBe(6545);
    expect(controlOf(dialog.tree(), "Port on 127.0.0.1").props).toMatchObject({ type: "number", min: 1024, max: 65535 });
    typeInto(dialog.tree(), "Port on 127.0.0.1", "7000");
    expect(dialog.kept.draft.local_port).toBe(7000);
    // A cleared field shows nothing, rather than a 0 to delete, and the backend says what it thinks of the port.
    typeInto(dialog.tree(), "Port on 127.0.0.1", "");
    expect(valueOf(dialog.tree(), "Port on 127.0.0.1")).toBe("");
    expect(dialog.kept.draft.local_port).toBe(0);
    switchOf(dialog.tree(), "Let other apps connect").onCheckedChange(false);
    expect(dialog.kept.draft.local_port).toBeNull();
    expect(hasField(dialog.tree(), "Port on 127.0.0.1")).toBe(false);
  });

  it("asks_about_the_settled_project_and_account_not_every_keystroke_but_shows_the_account_as_it_is", () => {
    const check = { entitlements: [], location: "global", duration_secs: 1800, justification: null };
    // The project typed so far, and the one typing last paused on.
    const dialog = editor({ ...NEW_LOCATED, account: "ops@example.com", project: "acme-prod-1234", pam: check }, { lookup: { account: "frank@example.com", project: PROD } });
    expect(propsOf(elementsOf(dialog.tree(), EntitlementSuggestions)[0])).toMatchObject({ account: "frank@example.com", project: PROD, pam: check });
    // The account field shows what was chosen or typed, whatever Google was last asked about.
    expect(propsOf(elementsOf(dialog.tree(), GoogleAccountField)[0])).toMatchObject({ account: "ops@example.com" });
    // Without a lookup that differs from the draft, it is the draft's.
    const same = editor({ ...NEW_LOCATED, account: "frank@example.com", pam: check });
    expect(propsOf(elementsOf(same.tree(), EntitlementSuggestions)[0])).toMatchObject({ account: "frank@example.com", project: PROD });
  });

  it("hands_the_google_account_field_the_drafts_account_and_takes_its_choice_back", () => {
    const dialog = editor({ ...newDatabase(), account: "ops@example.com" });
    const field = () => propsOf<{ account: string | null; disabled: boolean; onChange: (next: string | null) => void }>(elementsOf(dialog.tree(), GoogleAccountField)[0]);
    expect(elementsOf(dialog.tree(), GoogleAccountField)).toHaveLength(1);
    expect(field()).toMatchObject({ account: "ops@example.com", disabled: false });
    field().onChange("old@example.com");
    expect(dialog.kept.draft.account).toBe("old@example.com");
    expect(field().account).toBe("old@example.com");
    field().onChange(null);
    expect(dialog.kept.draft.account).toBeNull();
    expect(propsOf<{ disabled: boolean }>(elementsOf(editor(SAVED, { busy: true }).tree(), GoogleAccountField)[0]).disabled).toBe(true);
  });

  it("draws_its_segmented_controls_like_connect_via", () => {
    const groups = elementsOf(editor(NEW_LOCATED).tree(), RadioGroup.Root).map((element) => propsOf<{ className: string; "aria-label": string }>(element));
    expect(groups.map((group) => group["aria-label"])).toEqual(["How to choose the instance", "Route", "Environment"]);
    expect(groups[1].className).toBe(segmented);
    expect(groups[2].className).toBe(segmented);
    // The two long choices stack on a narrow screen.
    expect(groups[0].className).toContain(segmented);
    expect(groups[0].className).toContain("flex-col sm:flex-row");
  });

  it("fills_the_name_and_the_default_database_by_hand", () => {
    const dialog = editor(SAVED);
    expect(controlOf(dialog.tree(), "Name").props).toMatchObject({ value: "Orders", maxLength: 128, required: true });
    expect(controlOf(dialog.tree(), "Default database").props).toMatchObject({ value: "orders", maxLength: 63, required: true });
    typeInto(dialog.tree(), "Default database", " reports ");
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenLastCalledWith({ ...SAVED, default_database: "reports" });
  });
});

/** The Route field: how the database is reached, and the host an instance without a public IP goes through. */
describe("the route of a database in the dialog", () => {
  const [WEB_1, WEB_2, WEB_3, GONE] = ["00000000000000b1", "00000000000000b2", "00000000000000b3", "00000000000000b9"];
  const host = (id: string, alias: string) => hostView({ id, payload: hostPayload({ alias }) });
  const LIBRARY = recordOverview({
    hosts: [host(WEB_3, "web-3"), host(WEB_2, "web-2"), host(WEB_1, "web-1")],
    transports: [hostTransport({ project: DEV }, WEB_1), hostTransport({ project: PROD }, WEB_2)],
  });
  const newInDev: DatabaseDraft = { ...newDatabase(), account: "frank@example.com", project: DEV, environment: "dev" };
  const items = (tree: ReactNode) => elementsOf(tree, CommandItem);
  const hostItem = (tree: ReactNode, id: string) => {
    const found = items(tree).find((item) => String(propsOf<{ value: string }>(item).value).includes(id));
    if (!found) throw new Error(`no ${id} host`);
    return propsOf<{ onSelect: () => void; "data-checked": boolean; value: string }>(found);
  };
  const chooseHost = (tree: ReactNode, id: string) => hostItem(tree, id).onSelect();
  const press = (tree: ReactNode, label: string) => buttonsIn(tree).find((button) => textIn(button) === label)!.props.onClick!();

  it("separates the route type from a searchable, bounded host list", () => {
    const dialog = editor(SAVED, { overview: LIBRARY });
    expect(groupOf(dialog.tree(), "Route").value).toBe("public");
    expect(elementsOf(dialog.tree(), CommandInput)).toHaveLength(0);
    groupOf(dialog.tree(), "Route").onValueChange("private");
    expect(dialog.kept.draft.network).toBe("private");
    expect(elementsOf(dialog.tree(), CommandInput)).toHaveLength(1);
    expect(dialog.markup()).toContain("max-h-60");
    expect(items(dialog.tree()).map((item) => textIn(item))).toEqual(expect.arrayContaining([expect.stringContaining("web-1"), expect.stringContaining("web-2")]));
  });

  it("a private-only instance with one matching IAP host chooses it and shows the choice", () => {
    const dialog = editor(newInDev, { overview: LIBRARY, instances: listed([ORDERS_PG, BILLING_PG]) });
    expect(text(dialog.markup())).toContain("billing-pg PostgreSQL 16 asia-east1 · Private IP only · via web-1 · IAM sign-in on");
    radioOf(dialog.tree(), "billing-pg").onChange();
    expect(dialog.kept.draft).toMatchObject({ instance: "billing-pg", network: "private", via_host: WEB_1 });
    expect(text(dialog.markup())).toContain("Selected host: web-1");
    expect(hostItem(dialog.tree(), WEB_1)["data-checked"]).toBe(true);
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ instance: "billing-pg", network: "private", via_host: WEB_1 }));
  });

  it("a private-only instance with several matching hosts waits for one", () => {
    const both = recordOverview({ ...LIBRARY, transports: [hostTransport({ project: DEV }, WEB_1), hostTransport({ project: DEV }, WEB_2)] });
    const dialog = editor(newInDev, { overview: both, instances: listed([BILLING_PG]) });
    radioOf(dialog.tree(), "billing-pg").onChange();
    expect(dialog.kept.draft).toMatchObject({ network: "private", via_host: undefined });
    expect(groupOf(dialog.tree(), "Route").value).toBe("private");
    expect(text(dialog.markup())).toContain("Private IP only · Choose a host");
    expect(text(dialog.markup())).toContain("Choose a host to connect through.");
    const groups = elementsOf(dialog.tree(), CommandGroup);
    expect(propsOf<{ heading: string }>(groups[0]).heading).toBe("Suggested for this project");
    expect(elementsOf(groups[0], CommandItem)).toHaveLength(2);
    submit(dialog.tree());
    expect(dialog.onSave).not.toHaveBeenCalled();
    chooseHost(dialog.tree(), WEB_2);
    expect(dialog.kept.draft).toMatchObject({ network: "private", via_host: WEB_2 });
    expect(text(dialog.markup())).toContain("Selected host: web-2");
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ network: "private", via_host: WEB_2 }));
  });

  it("a missing route host replaces an earlier save error", () => {
    const dialog = editor({ ...newInDev, region: "asia-east1", instance: "billing-pg", name: "billing-pg", network: "private" }, { error: "Enter a database name (up to 128 characters)." });
    submit(dialog.tree());
    expect(dialog.onSave).not.toHaveBeenCalled();
    expect(dialog.markup()).toMatch(/<p[^>]*role="alert"[^>]*>Choose a host to connect through\.<\/p>/);
  });

  it("offers a new IAP host when none match while other hosts stay selectable", () => {
    const bare = recordOverview({ hosts: [host(WEB_3, "web-3")], transports: [] });
    const dialog = editor(newInDev, { overview: bare, instances: listed([BILLING_PG]) });
    radioOf(dialog.tree(), "billing-pg").onChange();
    expect(text(dialog.markup())).toContain("Private IP only · Needs a jump host");
    expect(buttonTag(dialog.markup(), "New IAP host")).not.toContain(DISABLED);
    chooseHost(dialog.tree(), WEB_3);
    expect(dialog.kept.draft).toMatchObject({ network: "private", via_host: WEB_3 });
    expect(text(dialog.markup())).not.toContain("New IAP host");
    const unchosen = editor(newInDev, { overview: bare, instances: listed([BILLING_PG]) });
    radioOf(unchosen.tree(), "billing-pg").onChange();
    press(unchosen.tree(), "New IAP host");
    expect(unchosen.createIapHost).toHaveBeenCalledTimes(1);
  });

  it("a public-IP instance resets the proposed private route and allows a new host choice", () => {
    const dialog = editor(newInDev, { overview: LIBRARY, instances: listed([ORDERS_PG, BILLING_PG]) });
    radioOf(dialog.tree(), "billing-pg").onChange();
    expect(dialog.kept.draft.via_host).toBe(WEB_1);
    radioOf(dialog.tree(), "orders-pg").onChange();
    expect(dialog.kept.draft).toMatchObject({ network: "public", via_host: undefined });
    groupOf(dialog.tree(), "Route").onValueChange("private");
    chooseHost(dialog.tree(), WEB_2);
    expect(dialog.kept.draft).toMatchObject({ instance: "orders-pg", network: "private", via_host: WEB_2 });
    const one = [{ id: WEB_1, alias: "web-1" }];
    const two = [...one, { id: WEB_2, alias: "web-2" }];
    const route = ({ network, via_host }: DatabaseDraft) => [network, via_host];
    expect(route(pickInstance({ ...newDatabase(), network: "private", via_host: WEB_1 }, ORDERS_PG, one))).toEqual(["public", undefined]);
    expect(route(pickInstance(newDatabase(), BILLING_PG, one))).toEqual(["private", WEB_1]);
    expect(route(pickInstance({ ...newDatabase(), network: "private", via_host: WEB_2 }, BILLING_PG, two))).toEqual(["private", undefined]);
    expect(route(pickInstance(newDatabase(), BILLING_PG))).toEqual(["private", undefined]);
  });

  it("searches all hosts by alias, hostname and group without hiding nonmatching-project hosts", () => {
    const ops = groupView({ payload: { schema: 1, name: "Operations", parent_id: null, defaults: {} } });
    const grouped = hostView({ id: WEB_3, payload: hostPayload({ alias: "web-3", hostname: "reporting.internal", group_id: ops.id }) });
    const overview = recordOverview({ hosts: [host(WEB_1, "web-1"), grouped], groups: [ops], transports: [hostTransport({ project: PROD }, WEB_1)] });
    const dialog = editor({ ...SAVED, network: "private", via_host: WEB_1 }, { overview });
    const groups = elementsOf(dialog.tree(), CommandGroup);
    expect(propsOf<{ heading: string }>(groups[0]).heading).toBe("Suggested for this project");
    expect(propsOf<{ heading: string }>(groups[1]).heading).toBe("All other hosts");
    expect(hostItem(dialog.tree(), WEB_3).value).toContain("reporting.internal");
    expect(hostItem(dialog.tree(), WEB_3).value).toContain("Operations");
    expect(hostItem(dialog.tree(), WEB_3).value).toContain("web-3");
    chooseHost(dialog.tree(), WEB_3);
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenLastCalledWith({ ...SAVED, network: "private", via_host: WEB_3 });
    groupOf(dialog.tree(), "Route").onValueChange("public");
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenLastCalledWith(SAVED);
    const spoofed = recordOverview({ hosts: [host(WEB_1, "web‮-1")], transports: [] });
    const spoofedDialog = editor({ ...SAVED, network: "private", via_host: WEB_1 }, { overview: spoofed });
    expect(text(spoofedDialog.markup())).toContain("web⟨U+202E⟩-1");
    expect(spoofedDialog.markup()).not.toContain("‮");
  });

  it("keeps a missing saved host until the person replaces it", () => {
    const gone: SavedDatabase = { ...SAVED, network: "private", via_host: GONE };
    const dialog = editor(gone, { overview: LIBRARY });
    expect(text(dialog.markup())).toContain("Host unavailable");
    submit(dialog.tree());
    expect(dialog.onSave).toHaveBeenLastCalledWith(gone);
    chooseHost(dialog.tree(), WEB_1);
    expect(text(dialog.markup())).not.toContain("Host unavailable");
    expect(dialog.kept.draft.via_host).toBe(WEB_1);
  });

  it("a route chosen and chosen back is no change", () => {
    const dialog = editor(SAVED, { overview: LIBRARY });
    groupOf(dialog.tree(), "Route").onValueChange("private");
    chooseHost(dialog.tree(), WEB_1);
    expect(changed(dialog.kept.draft, SAVED)).toBe(true);
    groupOf(dialog.tree(), "Route").onValueChange("public");
    expect(changed(dialog.kept.draft, SAVED)).toBe(false);
    const { account, default_database, pam, local_port, ...where } = SAVED;
    const routed: SavedDatabase = { ...where, network: "private", via_host: WEB_1, account, default_database, pam, local_port };
    const again = editor(routed, { overview: LIBRARY });
    chooseHost(again.tree(), WEB_2);
    expect(changed(again.kept.draft, routed)).toBe(true);
    groupOf(again.tree(), "Route").onValueChange("public");
    expect(changed(again.kept.draft, routed)).toBe(true);
    groupOf(again.tree(), "Route").onValueChange("private");
    chooseHost(again.tree(), WEB_1);
    expect(changed(again.kept.draft, routed)).toBe(false);
  });
});

/** A client that has read gcloud's accounts, and whatever else `seed` puts in its cache: a server render uses the cache and reads nothing. */
function cache(seed: (client: QueryClient) => void = () => {}) {
  const client = new QueryClient();
  client.setQueryData(gcloudAccountsKey, accounts);
  seed(client);
  return client;
}

const dialogProps = (patch: Partial<Parameters<typeof DatabaseEditor>[0]> = {}) => ({
  initial: newDatabase(),
  existing: [],
  overview: recordOverview(),
  busy: false,
  error: null,
  onSave: vi.fn(),
  onCancel: vi.fn(),
  createIapHost: vi.fn(),
  ...patch,
});

/** What the dialog hands its view when it mounts over `client`. */
const viewOf = (client: QueryClient, patch: Partial<Parameters<typeof DatabaseEditor>[0]> = {}) =>
  renderHook(client, () => DatabaseEditor(dialogProps(patch))) as ReactElement<DatabaseEditorViewProps>;

describe("the dialog as the Databases page mounts it", () => {
  const newInProd = { ...newDatabase(), account: "frank@example.com", project: PROD };

  it("lists_the_instances_the_account_may_see_in_the_project", () => {
    const client = cache((c) => c.setQueryData(databaseInstancesQuery("frank@example.com", PROD).queryKey, [ORDERS_PG, REPORTS_PG]));
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <DatabaseEditor {...dialogProps({ initial: newInProd })} />
      </QueryClientProvider>,
    );
    expect(text(html)).toContain(`Cloud SQL instances in ${PROD}`);
    expect(radioTag(html, "orders-pg")).not.toContain(DISABLED);
    expect(radioTag(html, "reports-pg")).toContain(DISABLED);
    expect(text(html)).toContain("IAM sign-in is off on this instance.");
    // The account is chosen from gcloud's, the project is typed, and nothing was asked of the backend to draw this.
    expect(text(html)).toContain("gcloud's active account (frank@example.com)");
    expect(html).toContain(`value="${PROD}"`);
    expect(vi.mocked(tauriInvoke)).not.toHaveBeenCalled();
    expect(viewOf(client, { initial: newInProd }).props.instances).toEqual(listed([ORDERS_PG, REPORTS_PG]));
  });

  it("reads_the_list_for_the_account_and_project_it_is_given_and_none_for_a_name_that_is_not_a_project", () => {
    const client = cache((c) => {
      c.setQueryData(databaseInstancesQuery("frank@example.com", PROD).queryKey, [ORDERS_PG]);
      c.setQueryData(databaseInstancesQuery(null, PROD).queryKey, [REPORTS_PG]);
    });
    expect(viewOf(client, { initial: newInProd }).props.instances).toEqual(listed([ORDERS_PG]));
    expect(viewOf(client, { initial: { ...newInProd, account: null } }).props.instances).toEqual(listed([REPORTS_PG]));
    // Another account has not been read; a project that is not one is not asked about.
    expect(viewOf(client, { initial: { ...newInProd, account: "ops@example.com" } }).props.instances).toEqual({ state: "loading" });
    expect(viewOf(client, { initial: { ...newInProd, project: "acme" } }).props.instances).toEqual({ state: "waiting" });
    expect(viewOf(client, { initial: newDatabase() }).props.instances).toEqual({ state: "waiting" });
  });

  it("starts_a_new_database_by_picking_and_a_saved_one_at_its_connection_name", () => {
    const client = cache();
    const fresh = viewOf(client).props;
    expect(fresh.mode).toBe("pick");
    expect(fresh.connection).toBe("");
    expect(fresh.draft).toEqual({ ...newDatabase(), local_port: 6543 });
    const saved = viewOf(client, { initial: SAVED }).props;
    expect(saved.mode).toBe("manual");
    expect(saved.connection).toBe(CONNECTION);
    expect(saved.draft).toEqual(SAVED);
    expect(text(renderToStaticMarkup(<QueryClientProvider client={client}><DatabaseEditor {...dialogProps({ initial: SAVED })} /></QueryClientProvider>))).toContain("Connection name");
    expect(renderToStaticMarkup(<QueryClientProvider client={client}><DatabaseEditor {...dialogProps({ initial: SAVED })} /></QueryClientProvider>)).toContain(`value="${CONNECTION}"`);
  });

  it("looks_up_the_account_and_project_it_opens_with_at_once_and_lists_while_the_rest_is_typed", () => {
    const client = cache((c) => c.setQueryData(databaseInstancesQuery("frank@example.com", PROD).queryKey, [ORDERS_PG]));
    // Nothing is waited for at mount: the list is the one for the project and account the dialog opened with.
    const opened = viewOf(client, { initial: newInProd }).props;
    expect(opened.lookup).toEqual({ account: "frank@example.com", project: PROD });
    expect(opened.instances).toEqual(listed([ORDERS_PG]));
    expect(viewOf(client, { initial: newDatabase() }).props.lookup).toEqual({ account: null, project: "" });
    expect(viewOf(client, { initial: SAVED }).props.lookup).toEqual({ account: SAVED.account, project: SAVED.project });
  });

  it("tells_the_page_after_every_change_whether_the_draft_differs_from_what_the_dialog_opened_with", () => {
    const onDirty = vi.fn();
    const saved = viewOf(cache(), { initial: SAVED, onDirty }).props;
    // Nothing is reported before something changes.
    expect(onDirty).not.toHaveBeenCalled();
    saved.onDraft({ ...SAVED, name: "Orders (prod)" });
    expect(onDirty).toHaveBeenLastCalledWith(true);
    // Typed back to what it opened with: not changed.
    saved.onDraft({ ...saved.draft, name: SAVED.name });
    expect(onDirty).toHaveBeenLastCalledWith(false);
    // A new database opens shared on its first free port, and that is not a change; the first thing typed is.
    const fresh = viewOf(cache(), { initial: newDatabase(), existing: [{ ...SAVED, id: "00000000000000a2", local_port: 6543 }], onDirty }).props;
    expect(fresh.draft.local_port).toBe(6544);
    fresh.onDraft({ ...fresh.draft });
    expect(onDirty).toHaveBeenLastCalledWith(false);
    fresh.onDraft({ ...fresh.draft, name: "Orders" });
    expect(onDirty).toHaveBeenLastCalledWith(true);
    fresh.onDraft({ ...fresh.draft, local_port: null });
    expect(onDirty).toHaveBeenLastCalledWith(true);
    expect(onDirty).toHaveBeenCalledTimes(5);
  });

  it("changes_without_anyone_listening_for_the_dirt", () => {
    const view = viewOf(cache(), { initial: SAVED }).props;
    expect(() => view.onDraft({ ...SAVED, name: "Orders (prod)" })).not.toThrow();
  });

  it("hands_its_view_the_library_and_the_new_iap_host_it_was_given_and_asks_for_no_host_until_save_is_pressed", () => {
    const overview = recordOverview({ hosts: [] });
    const createIapHost = vi.fn();
    const props = viewOf(cache(), { overview, createIapHost }).props;
    expect(props.overview).toBe(overview);
    expect(props.createIapHost).toBe(createIapHost);
    expect(props.hostMissing).toBe(false);
    expect(() => props.onHostMissing()).not.toThrow();
  });

  it("skips_the_ports_of_the_other_databases_and_hands_over_what_it_was_given", () => {
    const client = cache();
    const other = (id: string, local_port: number | null): SavedDatabase => ({ ...SAVED, id, local_port });
    const onSave = vi.fn();
    const onCancel = vi.fn();
    const props = viewOf(client, { initial: newDatabase(), existing: [other("00000000000000a2", 6544), other("00000000000000a3", null), other("00000000000000a4", 6545)], busy: true, error: "Enter a database name (up to 128 characters).", onSave, onCancel }).props;
    expect(props.used).toEqual([6544, 6545]);
    expect(suggestPort(props.used)).toBe(6543);
    expect([props.busy, props.error, props.onSave, props.onCancel]).toEqual([true, "Enter a database name (up to 128 characters).", onSave, onCancel]);
  });

  it("offers_the_entitlements_of_the_project_in_the_checks_location", () => {
    const client = cache((c) => {
      c.setQueryData(pamSuggestionsQuery("frank@example.com", PROD, "global").queryKey, ["prod-admin", "prod-operate"]);
      c.setQueryData(pamSuggestionsQuery("frank@example.com", PROD, "europe-west1").queryKey, ["eu-operate"]);
    });
    const check = { entitlements: [], location: "global", duration_secs: 1800, justification: null };
    const drawn = (initial: DatabaseDraft) => renderToStaticMarkup(<QueryClientProvider client={client}><DatabaseEditor {...dialogProps({ initial })} /></QueryClientProvider>);
    const global = drawn({ ...newInProd, region: "asia-east1", instance: "orders-pg", pam: check });
    expect(text(global)).toContain("You may request:");
    expect(global).toContain('aria-label="Add prod-admin"');
    expect(global).toContain('aria-label="Add prod-operate"');
    expect(global).not.toContain('aria-label="Add eu-operate"');
    // A check kept in another location asks for that location's.
    const europe = drawn({ ...newInProd, region: "asia-east1", instance: "orders-pg", pam: { ...check, location: "europe-west1" } });
    expect(europe).toContain('aria-label="Add eu-operate"');
    expect(europe).not.toContain('aria-label="Add prod-admin"');
    // Without a grant check there is nothing to suggest, and without a project nothing to ask.
    expect(drawn(newInProd)).not.toContain("You may request");
    expect(drawn({ ...newDatabase(), pam: check })).not.toContain("You may request");
  });
});

/** The two parts of the dialog that the host editor draws too: the Google account field and the suggestions under the entitlements. */
describe("the parts both editors share", () => {
  const draw = (client: QueryClient, element: ReactElement) => renderToStaticMarkup(<QueryClientProvider client={client}>{element}</QueryClientProvider>);
  type Typed = { onChange: (event: { target: { value: string } }) => void };

  it("the_google_account_field_lists_gcloud_accounts_the_way_the_host_editor_does", () => {
    const client = cache();
    const html = draw(client, <GoogleAccountField account={null} onChange={vi.fn()} disabled={false} />);
    expect(text(html)).toContain("Google account");
    expect(text(html)).toContain("gcloud's active account (frank@example.com)");
    expect(text(html)).toContain("old@example.com · sign-in expired");
    expect(text(html)).toContain("Accounts come from gcloud on this computer; each computer signs in on its own.");
    expect(html).toMatch(/<select/);
    // With no account the active one is chosen.
    expect(html).toMatch(/<option value="" selected/);
    // An account that is kept but this computer is not signed in to is still listed, and chosen.
    const away = draw(client, <GoogleAccountField account="ops@example.com" onChange={vi.fn()} disabled={false} />);
    expect(text(away)).toContain("ops@example.com · not signed in on this computer");
    expect(away).toMatch(/<option value="ops@example\.com" selected/);
  });

  it("the_google_account_field_hands_the_choice_up_and_none_for_the_active_account", () => {
    const onChange = vi.fn();
    const tree = renderHook(cache(), () => GoogleAccountField({ account: "frank@example.com", onChange, disabled: false }));
    const select = propsOf<Typed & { value: string }>(elementsOf(tree, "select")[0]);
    expect(select.value).toBe("frank@example.com");
    select.onChange({ target: { value: "old@example.com" } });
    expect(onChange).toHaveBeenLastCalledWith("old@example.com");
    select.onChange({ target: { value: "" } });
    expect(onChange).toHaveBeenLastCalledWith(null);
  });

  it("the_google_account_field_is_typed_where_gcloud_accounts_cannot_be_read", () => {
    for (const unread of [undefined, { ...accounts, config_found: false }]) {
      const client = new QueryClient();
      if (unread) client.setQueryData(gcloudAccountsKey, unread);
      const html = draw(client, <GoogleAccountField account="ops@example.com" onChange={vi.fn()} disabled={false} />);
      expect(html).not.toMatch(/<select/);
      expect(html).toContain('value="ops@example.com"');
      expect(html).toContain("placeholder=\"gcloud&#x27;s active account\"");
      const onChange = vi.fn();
      const field = propsOf<Typed>(elementsOf(renderHook(client, () => GoogleAccountField({ account: null, onChange, disabled: false })), Input)[0]);
      field.onChange({ target: { value: " frank@example.com " } });
      expect(onChange).toHaveBeenLastCalledWith("frank@example.com");
      field.onChange({ target: { value: "  " } });
      expect(onChange).toHaveBeenLastCalledWith(null);
    }
  });

  it("the_google_account_field_is_off_while_disabled", () => {
    expect(draw(cache(), <GoogleAccountField account={null} onChange={vi.fn()} disabled />)).toMatch(/<select[^>]*disabled=""/);
    expect(draw(cache(), <GoogleAccountField account={null} onChange={vi.fn()} disabled={false} />)).not.toMatch(/<select[^>]*disabled=""/);
    expect(draw(new QueryClient(), <GoogleAccountField account={null} onChange={vi.fn()} disabled />)).toMatch(/<input[^>]*disabled=""/);
  });

  const check = { entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: null };
  const withSuggestions = () =>
    cache((c) => {
      c.setQueryData(pamSuggestionsQuery("frank@example.com", PROD, "global").queryKey, ["prod-admin", "prod-deploy", "prod-operate"]);
      c.setQueryData(pamSuggestionsQuery(null, PROD, "global").queryKey, ["gcloud-active-only"]);
    });
  /** What the suggestions hand their view: the ids to offer, whether they are off, and what a press does. */
  const suggested = (client: QueryClient, patch: Partial<Parameters<typeof EntitlementSuggestions>[0]> = {}) =>
    renderHook(client, () => EntitlementSuggestions({ account: "frank@example.com", project: PROD, pam: check, disabled: false, onAdd: vi.fn(), ...patch })) as ReactElement<{
      offered: string[];
      disabled: boolean;
      onAdd: (id: string) => void;
    }>;

  it("the_suggestions_offer_what_the_account_may_request_in_the_project_except_what_the_check_lists", () => {
    const client = withSuggestions();
    expect(suggested(client).props.offered).toEqual(["prod-admin", "prod-deploy"]);
    // Asked for the account given, and for gcloud's active one when there is none.
    expect(suggested(client, { account: null }).props.offered).toEqual(["gcloud-active-only"]);
    const html = draw(client, <EntitlementSuggestions account="frank@example.com" project={PROD} pam={check} disabled={false} onAdd={vi.fn()} />);
    expect(text(html)).toContain("You may request:");
    expect(html).toContain('aria-label="Add prod-admin"');
    expect(html).not.toContain('aria-label="Add prod-operate"');
    // A check lists eight entitlements at most, and nothing is offered past them.
    const eight = Array.from({ length: 8 }, (_, index) => `prod-${index}a`);
    expect(suggested(client, { pam: { ...check, entitlements: eight } }).props.offered).toEqual([]);
  });

  it("the_suggestions_cope_with_no_check_at_all", () => {
    expect(suggested(withSuggestions(), { pam: null }).props.offered).toEqual([]);
    expect(draw(withSuggestions(), <EntitlementSuggestions account="frank@example.com" project={PROD} pam={null} disabled={false} onAdd={vi.fn()} />)).toBe("");
  });

  it("the_suggestions_hand_the_one_pressed_up_and_go_off_with_the_dialog", () => {
    const onAdd = vi.fn();
    const view = suggested(withSuggestions(), { onAdd, disabled: true });
    // The host editor draws the same view.
    expect(view.type).toBe(EntitlementSuggestionsView);
    expect(view.props.disabled).toBe(true);
    view.props.onAdd("prod-admin");
    expect(onAdd).toHaveBeenCalledWith("prod-admin");
    const html = draw(withSuggestions(), <EntitlementSuggestions account="frank@example.com" project={PROD} pam={check} disabled onAdd={vi.fn()} />);
    const tag = [...html.matchAll(/<button\b[^>]*>/g)].map((match) => match[0]).find((markup) => markup.includes('aria-label="Add prod-admin"'));
    expect(tag).toContain(DISABLED);
  });
});

/** The host editor's route fields are the other user of those two parts: what they are handed, and what a choice does to the route. */
describe("the host editor's route fields use the shared parts", () => {
  const route = (patch: Partial<TransportKind> = {}): TransportKind => ({
    type: "gcp_iap",
    project: PROD,
    zone: "asia-east1-b",
    instance: "jumpbox",
    interface: "nic0",
    account: "frank@example.com",
    os_login: true,
    pam: null,
    ...patch,
  });
  const fields = (kind: TransportKind, onChange = vi.fn(), disabled = false) => IapRouteFields({ kind, onChange, disabled, port: null });
  const check = { entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: null };

  it("hands_the_account_field_the_routes_account_and_takes_its_choice_back_into_the_route", () => {
    const onChange = vi.fn();
    const field = (tree: ReactNode) => propsOf<{ account: string | null; disabled: boolean; onChange: (next: string | null) => void }>(elementsOf(tree, GoogleAccountField)[0]);
    expect(elementsOf(fields(route()), GoogleAccountField)).toHaveLength(1);
    expect(field(fields(route()))).toMatchObject({ account: "frank@example.com", disabled: false });
    field(fields(route(), onChange)).onChange("old@example.com");
    expect(onChange).toHaveBeenLastCalledWith(route({ account: "old@example.com" }));
    // gcloud's active account is no account: the route keeps null, not an empty text.
    field(fields(route(), onChange)).onChange(null);
    expect(onChange).toHaveBeenLastCalledWith(route({ account: null }));
    expect(field(fields(route({ account: null }))).account).toBeNull();
    expect(field(fields(route(), onChange, true)).disabled).toBe(true);
  });

  it("hands_the_suggestions_the_routes_account_project_and_check_and_adds_the_one_pressed", () => {
    const onChange = vi.fn();
    const suggestions = elementsOf(fields(route({ pam: check }), onChange), EntitlementSuggestions);
    expect(suggestions).toHaveLength(1);
    expect(propsOf(suggestions[0])).toMatchObject({ account: "frank@example.com", project: PROD, pam: check, disabled: false });
    propsOf<{ onAdd: (id: string) => void }>(suggestions[0]).onAdd("prod-admin");
    expect(onChange).toHaveBeenLastCalledWith(route({ pam: { ...check, entitlements: ["prod-operate", "prod-admin"] } }));
    // No grant check, nothing to suggest for; a disabled route offers nothing to press.
    expect(elementsOf(fields(route()), EntitlementSuggestions)).toHaveLength(0);
    expect(propsOf(elementsOf(fields(route({ pam: check }), onChange, true), EntitlementSuggestions)[0])).toMatchObject({ disabled: true });
  });
});
