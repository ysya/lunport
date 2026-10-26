import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { useState } from "react";
import { RadioGroup } from "radix-ui";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { buttonTag, buttonsIn, DISABLED, elementsOf, text, textIn } from "@/components/keychain/test-markup";
import { tauriInvoke } from "@/lib/ipc";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import {
  gcloudAccountsKey,
  listGcloudAccounts,
  newPamCheck,
  type GcloudAccountsView,
  type HostTransport,
  type TransportKind,
} from "@/lib/transports";
import { beginDuplicateEditor, beginEditor, saveEditor, type EditorState } from "./editor";
import { hostPayload, hostView, recordOverview } from "./fixtures";
import { RecordHostEditor } from "./HostEditor";
import { applyOsLoginUsername, ConnectVia, connectViaDescription, IapRouteFields, OsLoginUsername, osLoginNoteStale } from "./IapRouteFields";
import {
  beginRouteState,
  routeChangedElsewhere,
  routeUnsaved,
  routeWritesBlocked,
  SYNC_PAUSED,
  type RouteState,
  type Via,
} from "./route";

vi.mock("@/lib/ipc", () => ({ tauriInvoke: vi.fn() }));
// The editor's draft is its first state: a test sets it to draw the editor as a press left it (as markup.test.tsx does).
vi.mock("react", async (original) => {
  const actual = await original<typeof import("react")>();
  return { ...actual, useState: vi.fn(actual.useState) };
});

const HOST = "0000000000000001";
const SYNCED = "Saved with the host, so it syncs wherever the host does.";
const LOCAL = "Saved on this computer only.";
const iap = (patch: Partial<TransportKind> = {}): TransportKind => ({
  type: "gcp_iap",
  project: "eng-dev-396409",
  zone: "asia-east1-b",
  instance: "jumpbox",
  interface: "nic0",
  account: "frank@example.com",
  os_login: true,
  pam: null,
  ...patch,
});

/** Each fixture host's saved route, as the library's overview lists it in `transports`. */
const routes = new Map<RecordHostView, HostTransport>();
const withRoute = (host: RecordHostView, patch: Partial<TransportKind> = {}) => {
  routes.set(host, { host_id: host.id, kind: iap(patch) });
  return host;
};
const savedRoute = (host: RecordHostView) => routes.get(host) ?? null;
const jumpbox = (payload: Partial<RecordHostView["payload"]> = {}) =>
  hostView({ id: HOST, payload: hostPayload({ alias: "jumpbox-dev", hostname: "10.0.0.8", user: "frank", ...payload }) });
const iapHost = withRoute(jumpbox());
const hostWithAccount = (account: string) => withRoute(jumpbox(), { account });

/** A library that uses central sync, with the host and its route (synced, unless `local`). */
function libraryOf(host: RecordHostView | null, patch: Partial<RecordOverview> = {}, local = false): RecordOverview {
  const route = host ? savedRoute(host) : null;
  return recordOverview({
    hosts: host ? [host] : [],
    transports: route ? [route] : [],
    transport_sync: route ? [{ host_id: route.host_id, synced: !local }] : [],
    central_mode: true,
    account: { chain_id: "c".repeat(64), device_name: "Laptop" },
    ...patch,
  });
}

type EditorOptions = { initialVia?: Via; duplicateSource?: RecordHostView; overview?: RecordOverview };
const renderEditor = (host: RecordHostView | null, options: EditorOptions = {}, client = new QueryClient()) =>
  renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <RecordHostEditor
        host={host}
        hostId={host?.id ?? null}
        overview={options.overview ?? libraryOf(host ?? options.duplicateSource ?? null)}
        initialVia={options.initialVia}
        duplicateSource={options.duplicateSource}
        terminalId={null}
        newTab={false}
        accept={(overview) => overview}
        onSaved={() => {}}
        onDeleted={() => {}}
        onDirty={() => {}}
      />
    </QueryClientProvider>,
  );

/** The editor drawn with `route` as its Connect via state, as an edit or another device left it: the one state that begins as a route. */
function renderWithRoute(host: RecordHostView, route: RouteState, options: EditorOptions = {}): string {
  const real = vi.mocked(useState).getMockImplementation() as typeof useState;
  vi.mocked(useState).mockImplementation(((initial: unknown) => {
    const begun = typeof initial === "function" ? (initial as () => unknown)() : initial;
    return begun !== null && typeof begun === "object" && "draft" in begun && "saved" in begun ? [route, vi.fn()] : real(initial);
  }) as typeof useState);
  try {
    return renderEditor(host, options);
  } finally {
    vi.mocked(useState).mockImplementation(real);
  }
}
/** The label of the Connect via choice drawn checked. */
const checkedVia = (html: string) =>
  text(html.match(/<button\b[^>]*role="radio"[^>]*aria-checked="true"[^>]*>((?:(?!<\/button>)[\s\S])*)<\/button>/)![1]).trim();
/** The opening tag of the input that follows the label `label`. */
const inputAfter = (html: string, label: string) => html.split(`>${label}</label>`)[1].match(/<input\b[^>]*>/)![0];

const accounts: GcloudAccountsView = {
  config_found: true,
  active: "frank@example.com",
  accounts: [
    { account: "frank@example.com", state: "signed_in", message: null },
    { account: "old@example.com", state: "expired", message: null },
  ],
};
/** What `gcp_accounts` answers: gcloud's accounts on this computer, or the error reading them. */
let gcloud: GcloudAccountsView | Error = accounts;
beforeEach(() => {
  gcloud = accounts;
  vi.mocked(tauriInvoke).mockReset();
  vi.mocked(tauriInvoke).mockImplementation(async (command: string) => {
    if (command === "gcp_accounts") {
      if (gcloud instanceof Error) throw gcloud;
      return gcloud;
    }
    if (command === "transports_oslogin_profile") return { account: "frank@example.com", username: "frank_example_com", key_registered: true };
    if (command === "records_host_update" || command === "records_host_create") return libraryOf(null);
    throw new Error(`unexpected command ${command}`);
  });
});
const invoked = (command: string) => vi.mocked(tauriInvoke).mock.calls.some(([name]) => name === command);
const lastInvoke = (command: string) =>
  vi.mocked(tauriInvoke).mock.calls.filter(([name]) => name === command).slice(-1)[0]?.[1] as Record<string, unknown>;

/** The Google account field and what follows it, as the editor draws it once `gcp_accounts` answered (or failed). */
async function accountField(host: RecordHostView): Promise<string> {
  const client = new QueryClient();
  await client.prefetchQuery({ queryKey: gcloudAccountsKey, queryFn: listGcloudAccounts, retry: false });
  return renderEditor(host, {}, client).split(">Google account</label>")[1];
}
/** The labels of the Google account select, as the editor draws it once gcloud's accounts are read. */
async function accountOptions(host: RecordHostView): Promise<string[]> {
  const select = (await accountField(host)).match(/^<select\b[\s\S]*?<\/select>/)![0];
  return [...select.matchAll(/<option\b[^>]*>([\s\S]*?)<\/option>/g)].map((option) => text(option[1]).trim());
}

/** The editor's draft after the last press, and the host it edits. */
let pressed: { host: RecordHostView; state: EditorState } | null = null;
/** Presses Use OS Login username under the Username field, as the editor wires it: the username goes into the draft. */
async function clickUseOsLoginUsername(host: RecordHostView) {
  const route = beginRouteState(libraryOf(host), host.id);
  let state = beginEditor(host);
  let use: Promise<unknown> = Promise.resolve();
  const view = OsLoginUsername({
    disabled: false,
    inherited: false,
    note: null,
    onUse: () => {
      use = applyOsLoginUsername(route.draft.iap, null, (change) => (state = change(state)));
    },
  });
  buttonsIn(view).find((button) => textIn(button) === "Use OS Login username")!.props.onClick!();
  await use;
  pressed = { host, state };
}
/** The Username field of the editor drawn with the draft the last press left. */
function usernameField(): string {
  vi.mocked(useState).mockReturnValueOnce([pressed!.state, vi.fn()]);
  const html = renderEditor(pressed!.host);
  return html.split(">Username</label>")[1].match(/<input\b[^>]*\bvalue="([^"]*)"/)![1];
}

/** The Connect via block drawn for `route`, handing each change to `onDraft`. */
const connectVia = (route: RouteState, onDraft: (draft: RouteState["draft"]) => void, locked = false) =>
  ConnectVia({ draft: route.draft, onDraft, description: "", hostname: "", onHostname: () => {}, port: null, disabled: false, locked });
/** Chooses `via` in the Connect via block drawn for `route`, and hands back the route it leaves. */
function choose(route: RouteState, via: Via): RouteState {
  let next = route;
  const group = elementsOf(connectVia(route, (draft) => (next = { ...route, draft })), RadioGroup.Root)[0].props as unknown as {
    onValueChange: (value: string) => void;
  };
  group.onValueChange(via);
  return next;
}
/** Opens the host, chooses Address in Connect via and saves, nothing else edited. */
async function switchToAddressAndSave(host: RecordHostView) {
  const overview = libraryOf(host);
  await saveEditor(beginEditor(host), choose(beginRouteState(overview, host.id), "address"), overview);
}

describe("Connect via in the host editor", () => {
  it("puts the instance where the hostname was and keeps the port", () => {
    const html = renderEditor(iapHost);
    expect(html).toContain("Instance");
    expect(html).toContain('value="jumpbox"');
    expect(html).not.toContain("Hostname or IP");
    expect(text(html)).toContain("Port");
    expect(html).toContain(SYNCED);
    expect(checkedVia(html)).toBe("Google Cloud IAP");
  });

  it("shows the grant fields only while a grant is required, with the entitlements as the route has them", () => {
    const plain = renderEditor(iapHost);
    expect(text(plain)).toContain("Network interface");
    expect(text(plain)).not.toContain("Entitlements");
    expect(text(plain)).not.toContain("Default grant (minutes)");
    const grant = { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 1800, justification: null };
    const html = renderEditor(withRoute(jumpbox(), { pam: grant }));
    expect(text(html)).toContain("Entitlements");
    expect(html).toContain('value="prod-operate, prod-admin"');
    expect(text(html)).toContain("Default grant (minutes)");
    expect(inputAfter(html, "Default grant (minutes)")).toContain('value="30"');
    expect(inputAfter(html, "Location")).toContain('value="global"');
  });

  it("dials an address host at its hostname, as before", () => {
    const html = renderEditor(hostView({ id: HOST, payload: hostPayload({ hostname: "server.example.com" }) }));
    expect(html).toContain("Hostname or IP");
    expect(html).toContain('value="server.example.com"');
    expect(html).not.toContain("Instance");
    expect(html).toContain("The hostname or IP address this host is dialed at.");
    expect(checkedVia(html)).toBe("Address");
  });

  it("opens a new IAP host without a validation sentence", () => {
    const html = renderEditor(null, { initialVia: "iap" });
    expect(html).toContain("Instance");
    expect(html).not.toContain("Enter the Google Cloud project id.");
    // Nothing typed is not saveable yet either.
    expect(buttonTag(html, "Create host")).toContain(DISABLED);
  });

  it("names what is missing once the host is edited", () => {
    vi.mocked(useState).mockReturnValueOnce([{ ...beginEditor(null), dirty: true }, vi.fn()]);
    const html = renderEditor(null, { initialVia: "iap" });
    expect(html).toContain("Enter the Google Cloud project id.");
    expect(buttonTag(html, "Create host")).toContain(DISABLED);
  });

  it("checks a new IAP host with its instance as the hostname it does not show", () => {
    // A new host that starts on IAP without a hostname (a duplicate of one, here): the record takes the instance's name, so it is saveable.
    const html = renderEditor(null, { duplicateSource: withRoute(jumpbox({ hostname: "" })) });
    expect(text(html)).not.toContain("Enter a hostname or IP address");
    expect(buttonTag(html, "Create host")).not.toContain(DISABLED);
  });

  it("offers gcloud's accounts and keeps one this computer lacks", async () => {
    const options = await accountOptions(hostWithAccount("ops@example.com")); // gcp_accounts answers frank@ (active) and old@ (expired)
    expect(options).toEqual([
      "gcloud's active account (frank@example.com)",
      "frank@example.com",
      "old@example.com · sign-in expired",
      "ops@example.com · not signed in on this computer",
    ]);
  });

  it("lets the account be typed where gcloud has no folder on this computer, or cannot be read", async () => {
    const host = hostWithAccount("ops@example.com");
    gcloud = { config_found: false, active: null, accounts: [] };
    expect(await accountField(host)).toMatch(/^<input\b[^>]*value="ops@example.com"/);
    gcloud = new Error("Reading gcloud's folder took too long.");
    expect(await accountField(host)).toMatch(/^<input\b[^>]*value="ops@example.com"/);
    // A folder without accounts is still read: the select offers gcloud's active account and keeps the route's.
    gcloud = { config_found: true, active: null, accounts: [] };
    expect(await accountOptions(host)).toEqual(["gcloud's active account", "ops@example.com · not signed in on this computer"]);
  });

  it("fills the OS Login username without saving the host", async () => {
    await clickUseOsLoginUsername(iapHost); // transports_oslogin_profile answers frank_example_com
    expect(usernameField()).toBe("frank_example_com");
    expect(invoked("records_host_update")).toBe(false);
    // It asks for the route's account in the route's project.
    expect(lastInvoke("transports_oslogin_profile")).toEqual({ account: "frank@example.com", project: "eng-dev-396409", keyId: null });
  });

  it("keeps Use OS Login username off while the host takes its username from its Group", () => {
    const inherited = withRoute(jumpbox({ user: "", group_id: "0000000000000009", inherit: ["user"] }));
    const html = renderEditor(inherited);
    expect(buttonTag(html, "Use OS Login username")).toContain(DISABLED);
    expect(text(html)).toContain("This host takes its username from its Group; change it there, or stop inheriting it in the host editor.");
    expect(buttonTag(renderEditor(iapHost), "Use OS Login username")).not.toContain(DISABLED);
    // Address has no OS Login to ask.
    expect(renderEditor(jumpbox())).not.toContain("Use OS Login username");
  });

  it("removes the route when saved with Address", async () => {
    await switchToAddressAndSave(iapHost);
    expect(lastInvoke("records_host_update").route).toEqual({ expected: savedRoute(iapHost), kind: null });
  });

  it("stores the instance as a new IAP host's hostname, and a duplicate keeps its source's hostname and route", async () => {
    const fresh: EditorState = { ...beginEditor(null), payload: { ...beginEditor(null).payload, alias: "jumpbox-2" }, dirty: true };
    const typed: RouteState = { draft: { via: "iap", iap: iap({ instance: "jumpbox-2" }) }, saved: null };
    await saveEditor(fresh, typed, libraryOf(null));
    expect(lastInvoke("records_host_create")).toMatchObject({ payload: { hostname: "jumpbox-2" }, route: { expected: null, kind: typed.draft.iap } });

    const overview = libraryOf(iapHost);
    const copy = beginRouteState(overview, null, undefined, iapHost.id);
    expect(copy).toEqual({ draft: { via: "iap", iap: savedRoute(iapHost)!.kind }, saved: null });
    await saveEditor(beginDuplicateEditor(iapHost, overview.hosts), copy, overview);
    expect(lastInvoke("records_host_create")).toMatchObject({ payload: { hostname: "10.0.0.8" }, route: { expected: null, kind: savedRoute(iapHost)!.kind } });
    expect(renderEditor(null, { duplicateSource: iapHost })).toContain('value="jumpbox"');
  });

  it("says where an IAP route is kept, as the pending save would leave it", () => {
    const saved = beginRouteState(libraryOf(iapHost), HOST);
    const edited: RouteState = { ...saved, draft: { ...saved.draft, iap: { ...saved.draft.iap, zone: "asia-east1-c" } } };
    expect(connectViaDescription(saved, libraryOf(iapHost), HOST)).toBe(SYNCED);
    // A route kept on this computer in a library that syncs stays there until it is saved again, which moves it into the library.
    expect(connectViaDescription(saved, libraryOf(iapHost, {}, true), HOST)).toBe(LOCAL);
    expect(connectViaDescription(edited, libraryOf(iapHost, {}, true), HOST)).toBe(SYNCED);
    // Without central sync, routes stay on each computer.
    const unsynced = libraryOf(iapHost, { central_mode: false }, true);
    expect(connectViaDescription(edited, unsynced, HOST)).toBe(LOCAL);
    expect(connectViaDescription(beginRouteState(libraryOf(null, { account: null }), null, "iap"), libraryOf(null, { account: null }), null)).toBe(LOCAL);
    expect(connectViaDescription({ ...saved, draft: { ...saved.draft, via: "address" } }, libraryOf(iapHost), HOST)).toBe(
      "The hostname or IP address this host is dialed at.",
    );
  });
});

describe("the route in the host editor's state", () => {
  it("knows when the library's writes keep the route as it is", () => {
    expect(routeWritesBlocked(libraryOf(iapHost, { shared_writes_blocked: true }))).toBe(true);
    expect(routeWritesBlocked(libraryOf(iapHost))).toBe(false);
    // Without central sync a route stays on this computer, and its writes are not the library's.
    expect(routeWritesBlocked(libraryOf(iapHost, { shared_writes_blocked: true, central_mode: false }))).toBe(false);
    expect(routeWritesBlocked(libraryOf(iapHost, { shared_writes_blocked: true, account: null }))).toBe(false);
  });

  it("turns off the route's controls while the library's writes are blocked, and leaves the host's own fields", () => {
    const blocked = libraryOf(iapHost, { shared_writes_blocked: true });
    const html = renderEditor(iapHost, { overview: blocked });
    expect(text(html)).toContain(SYNC_PAUSED);
    const radios = html.match(/<button\b[^>]*role="radio"[^>]*>/g)!;
    expect(radios).toHaveLength(2);
    for (const radio of radios) expect(radio).toContain(DISABLED);
    expect(inputAfter(html, "Instance")).toContain(DISABLED);
    expect(inputAfter(html, "Project")).toContain(DISABLED);
    // A local host's port and username are its own record, which the library's review does not hold back.
    expect(inputAfter(html, "Port")).not.toContain(DISABLED);
    expect(inputAfter(html, "Username")).not.toContain(DISABLED);
    const address = jumpbox();
    expect(inputAfter(renderEditor(address, { overview: libraryOf(address, { shared_writes_blocked: true }) }), "Hostname or IP")).not.toContain(DISABLED);
    // The block itself: the choice and the IAP fields go off together, the hostname stays.
    const locked = connectVia(beginRouteState(blocked, HOST), () => {}, true);
    expect((elementsOf(locked, RadioGroup.Root)[0].props as { disabled?: boolean }).disabled).toBe(true);
    expect((elementsOf(locked, IapRouteFields)[0].props as { disabled?: boolean }).disabled).toBe(true);
    // A duplicate cannot be created with the route it copied.
    expect(buttonTag(renderEditor(null, { duplicateSource: iapHost, overview: blocked }), "Create host")).toContain(DISABLED);
  });

  it("refuses a route change on Save while the library's writes are blocked, and still saves the host alone", async () => {
    const blocked = libraryOf(iapHost, { shared_writes_blocked: true });
    await expect(saveEditor(beginEditor(iapHost), choose(beginRouteState(blocked, HOST), "address"), blocked)).rejects.toThrow(SYNC_PAUSED);
    expect(invoked("records_host_update")).toBe(false);
    const renamed: EditorState = { ...beginEditor(iapHost), payload: { ...iapHost.payload, alias: "jumpbox-2" }, dirty: true };
    await saveEditor(renamed, beginRouteState(blocked, HOST), blocked);
    expect(lastInvoke("records_host_update")).not.toHaveProperty("route");
  });

  it("counts a saved host switched to Google Cloud IAP as a change, and says what the route still needs", () => {
    const host = jumpbox();
    const begun = beginRouteState(libraryOf(host), HOST);
    const switched: RouteState = { ...begun, draft: { ...begun.draft, via: "iap" } };
    expect(routeUnsaved(switched, HOST)).toBe(true);
    // For a new host the same untouched route is no edit yet.
    expect(routeUnsaved(switched, null)).toBe(false);
    expect(routeUnsaved(begun, HOST)).toBe(false);
    const html = renderWithRoute(host, switched);
    expect(checkedVia(html)).toBe("Google Cloud IAP");
    expect(text(html)).toContain("Unsaved changes");
    expect(text(html)).toContain("Enter the Google Cloud project id.");
    expect(buttonTag(html, "Discard changes")).not.toContain(DISABLED);
    expect(buttonTag(html, "Save changes")).toContain(DISABLED);
  });

  it("says when the route changed elsewhere, and keeps saving against the route the draft began from", async () => {
    const before = libraryOf(iapHost);
    const begun = beginRouteState(before, HOST);
    const moved = libraryOf(null, { hosts: [iapHost], transports: [{ host_id: HOST, kind: iap({ zone: "asia-east1-c" }) }] });
    expect(routeChangedElsewhere(begun, before, HOST)).toBe(false);
    expect(routeChangedElsewhere(begun, structuredClone(before), HOST)).toBe(false);
    expect(routeChangedElsewhere(begun, moved, HOST)).toBe(true);
    expect(routeChangedElsewhere(begun, libraryOf(null, { hosts: [iapHost] }), HOST)).toBe(true);
    expect(routeChangedElsewhere(beginRouteState(before, null, "iap"), moved, null)).toBe(false);
    const html = renderWithRoute(iapHost, begun, { overview: moved });
    expect(text(html)).toContain("This host changed or became unavailable.");
    expect(buttonTag(html, "Reload saved settings")).not.toContain(DISABLED);
    // The editor still shows, and saves against, the route it began from: reloading is the person's choice.
    expect(html).toContain('value="asia-east1-b"');
    const edited: RouteState = { ...begun, draft: { ...begun.draft, iap: { ...begun.draft.iap, instance: "jumpbox-2" } } };
    await saveEditor(beginEditor(iapHost), edited, moved);
    expect(lastInvoke("records_host_update").route).toEqual({ expected: savedRoute(iapHost), kind: edited.draft.iap });
  });

  it("forgets the OS Login note once it would speak of another account, project or OS Login setting", () => {
    const kind = iap();
    expect(osLoginNoteStale(kind, { ...kind, account: "ops@example.com" })).toBe(true);
    expect(osLoginNoteStale(kind, { ...kind, account: null })).toBe(true);
    expect(osLoginNoteStale(kind, { ...kind, project: "other-project-1" })).toBe(true);
    expect(osLoginNoteStale(kind, { ...kind, os_login: false })).toBe(true);
    // The instance, the zone and the grant settings change nothing OS Login said.
    expect(osLoginNoteStale(kind, { ...kind, instance: "jumpbox-2", zone: "asia-east1-c", pam: newPamCheck() })).toBe(false);
  });
});
