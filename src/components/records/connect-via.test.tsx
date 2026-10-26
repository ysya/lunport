import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { useState } from "react";
import { RadioGroup } from "radix-ui";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { buttonTag, buttonsIn, DISABLED, elementsOf, text, textIn } from "@/components/keychain/test-markup";
import { tauriInvoke } from "@/lib/ipc";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { gcloudAccountsKey, listGcloudAccounts, type GcloudAccountsView, type HostTransport, type TransportKind } from "@/lib/transports";
import { beginDuplicateEditor, beginEditor, saveEditor, type EditorState } from "./editor";
import { hostPayload, hostView, recordOverview } from "./fixtures";
import { RecordHostEditor } from "./HostEditor";
import { applyOsLoginUsername, ConnectVia, connectViaDescription, OsLoginUsername } from "./IapRouteFields";
import { beginRouteState, type RouteState, type Via } from "./route";

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

const accounts: GcloudAccountsView = {
  config_found: true,
  active: "frank@example.com",
  accounts: [
    { account: "frank@example.com", state: "signed_in", message: null },
    { account: "old@example.com", state: "expired", message: null },
  ],
};
beforeEach(() => {
  vi.mocked(tauriInvoke).mockReset();
  vi.mocked(tauriInvoke).mockImplementation(async (command: string) => {
    if (command === "gcp_accounts") return accounts;
    if (command === "transports_oslogin_profile") return { account: "frank@example.com", username: "frank_example_com", key_registered: true };
    if (command === "records_host_update" || command === "records_host_create") return libraryOf(null);
    throw new Error(`unexpected command ${command}`);
  });
});
const invoked = (command: string) => vi.mocked(tauriInvoke).mock.calls.some(([name]) => name === command);
const lastInvoke = (command: string) =>
  vi.mocked(tauriInvoke).mock.calls.filter(([name]) => name === command).slice(-1)[0]?.[1] as Record<string, unknown>;

/** The labels of the Google account select, as the editor draws it once gcloud's accounts are read. */
async function accountOptions(host: RecordHostView): Promise<string[]> {
  const client = new QueryClient();
  await client.prefetchQuery({ queryKey: gcloudAccountsKey, queryFn: listGcloudAccounts });
  const select = renderEditor(host, {}, client).split(">Google account</label>")[1].match(/<select\b[\s\S]*?<\/select>/)![0];
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

/** Chooses `via` in the Connect via block drawn for `route`, and hands back the route it leaves. */
function choose(route: RouteState, via: Via): RouteState {
  let next = route;
  const block = ConnectVia({
    draft: route.draft,
    onDraft: (draft) => (next = { ...route, draft }),
    description: "",
    hostname: "",
    onHostname: () => {},
    port: null,
    disabled: false,
  });
  const group = elementsOf(block, RadioGroup.Root)[0].props as unknown as { onValueChange: (value: string) => void };
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
    expect(html).toMatch(/<button[^>]*role="radio"[^>]*aria-checked="true"[^>]*>[\s\S]*?Google Cloud IAP<\/button>/);
  });

  it("dials an address host at its hostname, as before", () => {
    const html = renderEditor(hostView({ id: HOST, payload: hostPayload({ hostname: "server.example.com" }) }));
    expect(html).toContain("Hostname or IP");
    expect(html).toContain('value="server.example.com"');
    expect(html).not.toContain("Instance");
    expect(html).toContain("The hostname or IP address this host is dialed at.");
    expect(html).toMatch(/<button[^>]*role="radio"[^>]*aria-checked="true"[^>]*>[\s\S]*?Address<\/button>/);
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
