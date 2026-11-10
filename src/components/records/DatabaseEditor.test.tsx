import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { RadioGroup } from "radix-ui";
import type { ReactElement, ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { buttonsIn, buttonTag, DISABLED, elementsOf, text, textIn } from "@/components/keychain/test-markup";
import { tauriInvoke } from "@/lib/ipc";
import { renderHook } from "@/lib/test-ipc";
import { databaseInstancesQuery, newDatabase, suggestPort, type InstanceSummary, type SavedDatabase } from "@/lib/databases";
import { gcloudAccountsKey, pamSuggestionsQuery, type GcloudAccountsView } from "@/lib/transports";
import {
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
import { RecordField } from "./form";
import { EntitlementsInput, EntitlementSuggestions, EntitlementSuggestionsView, GoogleAccountField, segmented } from "./IapRouteFields";

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
};

/** The view of the dialog over `initial`, with the state the dialog keeps for it: pressing a control changes `kept` as the dialog's state setters do. */
function editor(initial: SavedDatabase, options: Options = {}) {
  const kept = { draft: initial, mode: options.mode ?? (initial.instance === "" ? "pick" : "manual"), connection: options.connection ?? "" };
  const onSave = vi.fn();
  const onCancel = vi.fn();
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
  });
  const tree = () => DatabaseEditorView(props());
  const markup = () => renderToStaticMarkup(<QueryClientProvider client={options.client ?? cache()}>{tree()}</QueryClientProvider>);
  return { kept, onSave, onCancel, tree, markup };
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

  it("an_instance_without_a_public_ip_is_listed_disabled_with_its_own_sentence", () => {
    const dialog = editor({ ...newDatabase(), project: PROD }, { instances: listed([ORDERS_PG, BILLING_PG, REPORTS_PG]) });
    const html = dialog.markup();
    expect(text(html).match(/This instance has no public IP\. Lunport connects over public IP in this release\./g)).toHaveLength(1);
    expect(radioTag(html, "billing-pg")).toContain(DISABLED);
    expect(radioOf(dialog.tree(), "billing-pg").disabled).toBe(true);
    // Each disabled row says its own reason, and the instance that can be chosen says none.
    expect(text(html).match(/IAM sign-in is off on this instance\./g)).toHaveLength(1);
    expect(instanceProblem(BILLING_PG)).toBe(NO_PUBLIC_IP);
    // Without a public address the IAM flag is beside the point: that is the reason given.
    expect(instanceProblem(instance({ public_ip: false, private_ip: false, iam_authentication: false }))).toBe(NO_PUBLIC_IP);
  });

  it("describes_each_instance_by_its_region_addresses_and_version", () => {
    const html = text(editor({ ...newDatabase(), project: PROD }, { instances: listed([ORDERS_PG, BILLING_PG, REPORTS_PG]) }).markup());
    expect(html).toContain("orders-pg PostgreSQL 16 asia-east1 · Public IP and private IP · IAM sign-in on");
    expect(html).toContain("billing-pg PostgreSQL 16 asia-east1 · Private IP only");
    expect(html).toContain("reports-pg PostgreSQL 15 asia-east1 · Public IP");
    expect(text(editor({ ...newDatabase(), project: PROD }, { instances: listed([instance({ database_version: "POSTGRES_9_6" })]) }).markup())).toContain("POSTGRES_9_6");
  });

  it("manual_mode_parses_the_connection_name", () => {
    const dialog = editor({ ...newDatabase(), account: "frank@example.com" }, { mode: "manual" });
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
    const empty = editor({ ...newDatabase(), project: PROD }, { instances: listed([ORDERS_PG]) });
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

  it("offers_the_three_environments_as_one_choice", () => {
    const dialog = editor(newDatabase());
    const html = dialog.markup();
    expect(text(html)).toMatch(/Environment\s+Dev\s+Staging\s+Prod/);
    expect(groupOf(dialog.tree(), "Environment").value).toBe("dev");
    expect(html).toMatch(/aria-label="Environment"/);
    groupOf(dialog.tree(), "Environment").onValueChange("staging");
    expect(dialog.kept.draft.environment).toBe("staging");
    groupOf(dialog.tree(), "Environment").onValueChange("prod");
    expect(dialog.kept.draft.environment).toBe("prod");
    expect(text(html)).toContain("connections through the local port open read-only");
  });

  it("the_pam_switch_asks_for_thirty_minutes_in_the_global_location_and_off_forgets_the_check", () => {
    const dialog = editor(newDatabase());
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
    const dialog = editor({ ...newDatabase(), account: "frank@example.com", project: PROD, pam: check });
    const suggestions = elementsOf(dialog.tree(), EntitlementSuggestions);
    expect(suggestions).toHaveLength(1);
    expect(propsOf(suggestions[0])).toMatchObject({ account: "frank@example.com", project: PROD, pam: check, disabled: false });
    propsOf<{ onAdd: (id: string) => void }>(suggestions[0]).onAdd("prod-admin");
    expect(dialog.kept.draft.pam).toEqual({ ...check, entitlements: ["prod-operate", "prod-admin"] });
    // Nothing is drawn while the check is off, and nothing is pressed while a save is under way.
    expect(elementsOf(editor(newDatabase()).tree(), EntitlementSuggestions)).toHaveLength(0);
    expect(propsOf(elementsOf(editor({ ...newDatabase(), pam: check }, { busy: true }).tree(), EntitlementSuggestions)[0])).toMatchObject({ disabled: true });
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
    const shown = (initial: SavedDatabase, existing: SavedDatabase[] = []) => {
      const tree = DatabaseEditorView(viewOf(client, { initial, existing }).props);
      return { sharing: switchOf(tree, "Let other apps connect").checked, port: hasField(tree, "Port on 127.0.0.1") ? valueOf(tree, "Port on 127.0.0.1") : null };
    };
    expect(shown(newDatabase())).toEqual({ sharing: true, port: 6543 });
    expect(shown(newDatabase(), [other("00000000000000a2", 6543), other("00000000000000a3", 6544)])).toEqual({ sharing: true, port: 6545 });
    expect(shown({ ...SAVED, local_port: null }, [other("00000000000000a2", 6543)])).toEqual({ sharing: false, port: null });
    expect(shown(SAVED, [other("00000000000000a2", 6544)])).toEqual({ sharing: true, port: 6543 });
  });

  it("sharing_proposes_the_first_free_port_and_off_offers_none", () => {
    const dialog = editor(newDatabase(), { used: [6543, 6544] });
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
    const dialog = editor({ ...newDatabase(), account: "ops@example.com", project: "acme-prod-1234", pam: check }, { lookup: { account: "frank@example.com", project: PROD } });
    expect(propsOf(elementsOf(dialog.tree(), EntitlementSuggestions)[0])).toMatchObject({ account: "frank@example.com", project: PROD, pam: check });
    // The account field shows what was chosen or typed, whatever Google was last asked about.
    expect(propsOf(elementsOf(dialog.tree(), GoogleAccountField)[0])).toMatchObject({ account: "ops@example.com" });
    // Without a lookup that differs from the draft, it is the draft's.
    const same = editor({ ...newDatabase(), account: "frank@example.com", project: PROD, pam: check });
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
    const groups = elementsOf(editor(newDatabase()).tree(), RadioGroup.Root).map((element) => propsOf<{ className: string; "aria-label": string }>(element));
    expect(groups.map((group) => group["aria-label"])).toEqual(["How to choose the instance", "Environment"]);
    expect(groups[1].className).toBe(segmented);
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

/** A client that has read gcloud's accounts, and whatever else `seed` puts in its cache: a server render uses the cache and reads nothing. */
function cache(seed: (client: QueryClient) => void = () => {}) {
  const client = new QueryClient();
  client.setQueryData(gcloudAccountsKey, accounts);
  seed(client);
  return client;
}

const dialogProps = (patch: Partial<Parameters<typeof DatabaseEditor>[0]> = {}) => ({ initial: newDatabase(), existing: [], busy: false, error: null, onSave: vi.fn(), onCancel: vi.fn(), ...patch });

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
    const drawn = (initial: SavedDatabase) => renderToStaticMarkup(<QueryClientProvider client={client}><DatabaseEditor {...dialogProps({ initial })} /></QueryClientProvider>);
    const global = drawn({ ...newInProd, pam: check });
    expect(text(global)).toContain("You may request:");
    expect(global).toContain('aria-label="Add prod-admin"');
    expect(global).toContain('aria-label="Add prod-operate"');
    expect(global).not.toContain('aria-label="Add eu-operate"');
    // A check kept in another location asks for that location's.
    const europe = drawn({ ...newInProd, pam: { ...check, location: "europe-west1" } });
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
