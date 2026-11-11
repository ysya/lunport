import { QueryClient } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "./test-ipc";
import { pamStatusOptions, pamStatusQuery, type PamStatusView } from "./transports";
import { hostPayload, hostTransport, hostView, recordOverview } from "@/components/records/fixtures";
import {
  GRANT_ENDING_SOON_MS,
  HOST_UNAVAILABLE,
  connectionName,
  connectionsLine,
  databaseBusy,
  databaseGrantLine,
  databaseInstancesQuery,
  databasePamStatusQuery,
  databasePassword,
  databaseRoute,
  databasesKey,
  databasesQuery,
  deleteDatabase,
  jdbcUrl,
  jumpHostCandidates,
  libraryHosts,
  listDatabases,
  localAddress,
  lockDatabaseWrites,
  newDatabase,
  otherDatabases,
  parseConnectionName,
  reconnectLockedConnections,
  requestDatabaseGrant,
  requestRouteGrant,
  rotateDatabasePassword,
  routeHost,
  routeHostGrant,
  routeParts,
  routeSummary,
  runDatabaseAction,
  saveDatabase,
  startDatabase,
  stepSentence,
  stopDatabase,
  unlockDatabaseWrites,
  unlockMethod,
  type DatabaseLive,
  type DatabasePhase,
  type DatabaseView,
  type InstanceSummary,
  type RoutePartState,
  type RouteSummary,
  type SavedDatabase,
} from "./databases";

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
  pam: null,
  local_port: 6543,
};

describe("saved databases", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("starts a new database as a public PostgreSQL instance with nothing filled in and no environment chosen", () => {
    expect(newDatabase()).toEqual({
      id: "",
      name: "",
      engine: "postgres",
      project: "",
      region: "",
      instance: "",
      environment: null,
      network: "public",
      account: null,
      default_database: "postgres",
      pam: null,
      local_port: null,
    });
    expect(newDatabase()).not.toBe(newDatabase());
  });

  it("writes the connection name as project:region:instance", () => {
    expect(connectionName(ORDERS)).toBe("acme-prod-123456:asia-east1:orders-pg");
    expect(connectionName(newDatabase())).toBe("::");
  });

  it("reads a connection name into its project, region and instance", () => {
    expect(parseConnectionName("acme-prod-123456:asia-east1:orders-pg")).toEqual({ project: "acme-prod-123456", region: "asia-east1", instance: "orders-pg" });
    expect(parseConnectionName(`  \n acme-dev-654321:us-central1:orders-pg\t `)).toEqual({ project: "acme-dev-654321", region: "us-central1", instance: "orders-pg" });
    expect(parseConnectionName(connectionName(ORDERS))).toEqual({ project: ORDERS.project, region: ORDERS.region, instance: ORDERS.instance });
  });

  it("trims each part of what was pasted", () => {
    expect(parseConnectionName(" acme-prod-123456 : asia-east1 : orders-pg ")).toEqual({ project: "acme-prod-123456", region: "asia-east1", instance: "orders-pg" });
    expect(parseConnectionName("acme-prod-123456\t:\tasia-east1\n:\u00a0orders-pg")).toEqual({ project: "acme-prod-123456", region: "asia-east1", instance: "orders-pg" });
  });

  it("rejects text that is not exactly three non-empty parts", () => {
    expect(parseConnectionName("acme-prod-123456: :orders-pg")).toBeNull();
    expect(parseConnectionName(" : asia-east1 : orders-pg")).toBeNull();
    expect(parseConnectionName("acme-prod-123456 : asia-east1 :  ")).toBeNull();
    expect(parseConnectionName("acme-prod-123456:orders-pg")).toBeNull();
    expect(parseConnectionName("acme-prod-123456:asia-east1:orders-pg:extra")).toBeNull();
    expect(parseConnectionName("acme-prod-123456::orders-pg")).toBeNull();
    expect(parseConnectionName(":asia-east1:orders-pg")).toBeNull();
    expect(parseConnectionName("acme-prod-123456:asia-east1:")).toBeNull();
    expect(parseConnectionName("::")).toBeNull();
    expect(parseConnectionName("orders-pg")).toBeNull();
    expect(parseConnectionName("")).toBeNull();
    expect(parseConnectionName("   ")).toBeNull();
  });

  it("keeps the databases under one query key", () => {
    expect(databasesKey).toEqual(["databases"]);
  });

  it("calls the backend with the command and argument names it registers", async () => {
    const view: DatabaseView = {
      database: ORDERS,
      live: { phase: "stopped", port: null, connections: 0, writable_until_ms: null, error: null, step: null, address: null },
      synced: true,
      blocked: false,
      removed: false,
      changed: false,
      environment: "prod",
    };
    const renamed = { ...ORDERS, name: "Orders (prod)" };
    const replies: Record<string, unknown> = { databases_list: [view], databases_save: renamed, databases_delete: null };
    const calls = stubBackend(async (cmd) => replies[cmd]);
    expect(await listDatabases()).toEqual([view]);
    expect(await saveDatabase({ ...ORDERS, id: "" }, null)).toBe(renamed);
    expect(await saveDatabase(renamed, ORDERS)).toBe(renamed);
    await deleteDatabase(renamed);
    expect(calls).toEqual([
      ["databases_list", {}],
      ["databases_save", { database: { ...ORDERS, id: "" }, expected: null }],
      ["databases_save", { database: renamed, expected: ORDERS }],
      ["databases_delete", { expected: renamed }],
    ]);
  });

  it("asks for and rotates a port password by the database's identity", async () => {
    const replies: Record<string, unknown> = {
      databases_port_password: "c3RvcmVkLXBvcnQtcGFzc3dvcmQtMDEy",
      databases_rotate_port_password: "bmV3LXBvcnQtcGFzc3dvcmQtZm9yLWFu",
    };
    const calls = stubBackend(async (cmd) => replies[cmd]);
    expect(await databasePassword(ORDERS.id)).toBe("c3RvcmVkLXBvcnQtcGFzc3dvcmQtMDEy");
    expect(await rotateDatabasePassword(ORDERS.id)).toBe("bmV3LXBvcnQtcGFzc3dvcmQtZm9yLWFu");
    expect(calls).toEqual([
      ["databases_port_password", { id: ORDERS.id }],
      ["databases_rotate_port_password", { id: ORDERS.id }],
    ]);
  });

  it("unlocks, locks and reconnects by the database's identity, and asks how this computer confirms", async () => {
    const until = 1_800_000_900_000;
    const replies: Record<string, unknown> = {
      os_unlock_method: "system",
      databases_unlock_writes: until,
      databases_lock_writes: null,
      databases_reconnect_locked: 2,
    };
    const calls = stubBackend(async (cmd) => replies[cmd]);
    expect(await unlockMethod()).toBe("system");
    expect(await unlockDatabaseWrites(ORDERS.id, false)).toBe(until);
    expect(await unlockDatabaseWrites(ORDERS.id, true)).toBe(until);
    await lockDatabaseWrites(ORDERS.id);
    expect(await reconnectLockedConnections(ORDERS.id)).toBe(2);
    expect(calls).toEqual([
      ["os_unlock_method", {}],
      ["databases_unlock_writes", { id: ORDERS.id, confirmedInApp: false }],
      ["databases_unlock_writes", { id: ORDERS.id, confirmedInApp: true }],
      ["databases_lock_writes", { id: ORDERS.id }],
      ["databases_reconnect_locked", { id: ORDERS.id }],
    ]);
  });
});

const MINUTE = 60_000;
const NOW = new Date(2027, 0, 15, 10, 0).getTime();
const PAM = { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 1800, justification: null };

function view(patch: Partial<DatabaseView> = {}): DatabaseView {
  return { database: ORDERS, live: { phase: "stopped", port: null, connections: 0, writable_until_ms: null, error: null, step: null, address: null }, synced: true, blocked: false, removed: false, changed: false, environment: ORDERS.environment, ...patch };
}

describe("the Databases page's reads and actions", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("starts and stops a database, and asks for its grant, by its identity", async () => {
    const calls = stubBackend(async () => null);
    await startDatabase(ORDERS.id);
    await stopDatabase(ORDERS.id);
    await requestDatabaseGrant(ORDERS.id);
    await requestRouteGrant(ORDERS.id);
    expect(calls).toEqual([
      ["databases_start", { id: ORDERS.id }],
      ["databases_stop", { id: ORDERS.id }],
      ["databases_request_grant", { id: ORDERS.id }],
      ["databases_request_route_grant", { id: ORDERS.id }],
    ]);
  });

  it("reads the list every 1.5 seconds and a database's grant every minute, once", async () => {
    expect(databasesQuery.queryKey).toEqual(databasesKey);
    expect(databasesQuery.refetchInterval).toBe(1500);
    const grant = databasePamStatusQuery(ORDERS.id);
    expect(grant.queryKey).toEqual(["gcp", "pam-status", "database", ORDERS.id]);
    expect(grant.refetchInterval).toBe(60_000);
    // Not retried (the next minute reads it again) and read whether or not the webview thinks it is online, as a host's grant is.
    expect(grant.retry).toBe(false);
    expect(grant.networkMode).toBe("always");
    const status: PamStatusView = { entitlement: "prod-operate", state: "active", active_until_ms: NOW, message: null };
    const calls = stubBackend(async () => status);
    expect(await new QueryClient().fetchQuery(grant)).toEqual(status);
    expect(calls).toEqual([["databases_pam_status", { id: ORDERS.id }]]);
    expect(databasePamStatusQuery("00000000000000a2").queryKey).not.toEqual(grant.queryKey);
  });

  it("keeps a database's grant exactly as a host's is kept", () => {
    expect(databasePamStatusQuery(ORDERS.id)).toMatchObject(pamStatusOptions);
    const kept = ({ queryKey, queryFn, ...options }: { queryKey: unknown; queryFn?: unknown }) => options;
    expect(kept(databasePamStatusQuery(ORDERS.id))).toEqual(kept(pamStatusQuery("0000000000000001")));
  });

  it("calls a database busy while its port starts, runs or stops", () => {
    const busy = (phase: DatabasePhase) => databaseBusy(view({ live: { phase, port: 6543, connections: 0, writable_until_ms: null, error: null, step: null, address: null } }));
    expect(["starting", "running", "stopping"].map((phase) => busy(phase as DatabasePhase))).toEqual([true, true, true]);
    expect(["stopped", "error"].map((phase) => busy(phase as DatabasePhase))).toEqual([false, false]);
  });

  it("words a database's route, its local address and its connections", () => {
    expect(databaseRoute(ORDERS)).toBe("PostgreSQL · acme-prod-123456 · asia-east1 · orders-pg");
    expect(localAddress(view())).toBe("127.0.0.1:6543");
    expect(localAddress(view({ database: { ...ORDERS, local_port: null } }))).toBe("Not shared");
    // The port that runs is the one shown; a port that failed to open falls back to the one saved.
    expect(localAddress(view({ live: { phase: "running", port: 6544, connections: 0, writable_until_ms: null, error: null, step: null, address: null } }))).toBe("127.0.0.1:6544");
    expect(localAddress(view({ live: { phase: "error", port: null, connections: 0, writable_until_ms: null, error: "Port 6543 is already in use on this computer.", step: null, address: null } }))).toBe("127.0.0.1:6543");
    expect([0, 1, 2].map(connectionsLine)).toEqual(["0 active connections", "1 active connection", "2 active connections"]);
  });
});

describe("the New database dialog's reads", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("lists the instances of a project for an account, kept for a minute and not asked again on a failure", async () => {
    const found: InstanceSummary[] = [{ name: "orders-pg", region: "asia-east1", database_version: "POSTGRES_16", public_ip: true, private_ip: true, iam_authentication: true }];
    const query = databaseInstancesQuery("frank@example.com", "acme-prod-123456");
    expect(query.queryKey).toEqual(["gcp", "sql-instances", "frank@example.com", "acme-prod-123456"]);
    expect(query.staleTime).toBe(60_000);
    expect(query.retry).toBe(false);
    // The answer comes from this app's backend, which says in its own sentence when Google cannot be reached, so it is read when the webview thinks it is offline too.
    expect(query.networkMode).toBe("always");
    const calls = stubBackend(async () => found);
    expect(await new QueryClient().fetchQuery(query)).toEqual(found);
    // No account asks for gcloud's active one.
    expect(await new QueryClient().fetchQuery(databaseInstancesQuery(null, "acme-dev-654321"))).toEqual(found);
    expect(calls).toEqual([
      ["databases_list_instances", { account: "frank@example.com", project: "acme-prod-123456" }],
      ["databases_list_instances", { account: null, project: "acme-dev-654321" }],
    ]);
    // Each account and each project is read, and kept, on its own.
    expect(databaseInstancesQuery("ops@example.com", "acme-prod-123456").queryKey).not.toEqual(query.queryKey);
    expect(databaseInstancesQuery("frank@example.com", "acme-dev-654321").queryKey).not.toEqual(query.queryKey);
    expect(databaseInstancesQuery(null, "acme-prod-123456").queryKey).toEqual(["gcp", "sql-instances", null, "acme-prod-123456"]);
  });

  it("is read only once the project reads as one", () => {
    for (const project of ["", "acme", "ACME-PROD-123456", "acme-prod-", "-acme-prod", "acme prod 123456", "acme:prod"]) {
      expect(databaseInstancesQuery(null, project).enabled, project).toBe(false);
    }
    for (const project of ["acme-prod-123456", "acme-dev-654321", "123456"]) {
      expect(databaseInstancesQuery(null, project).enabled, project).toBe(true);
    }
  });

  it("leaves out the database being edited, and no other, from the ones whose ports are skipped", () => {
    const second = { ...ORDERS, id: "00000000000000a2", name: "Analytics", local_port: 6544 };
    const gone = { ...ORDERS, id: "00000000000000a3", name: "Old", local_port: null };
    const rows = [view(), view({ database: second }), view({ database: gone, removed: true, blocked: true })];
    // A database that is only listed to be stopped still holds the port it runs on.
    expect(otherDatabases(rows, ORDERS.id)).toEqual([second, gone]);
    expect(otherDatabases(rows, second.id)).toEqual([ORDERS, gone]);
    // A new database has no row of its own.
    expect(otherDatabases(rows, "")).toEqual([ORDERS, second, gone]);
    expect(otherDatabases([], ORDERS.id)).toEqual([]);
  });
});

describe("the grant line of a database", () => {
  const status = (patch: Partial<PamStatusView>): PamStatusView => ({ entitlement: "prod-operate", state: "active", active_until_ms: null, message: null, ...patch });
  const line = (patch: Partial<PamStatusView>, now = NOW) => databaseGrantLine(status(patch), PAM, now);

  it("warns without a request when the grant ends within five minutes, and says when a new one can be requested", () => {
    // PAM takes no second request with the scope of a grant that is still active, so there is nothing to ask for before it ends.
    const note = "You can request a new grant when this one ends.";
    expect(GRANT_ENDING_SOON_MS).toBe(5 * MINUTE);
    expect(line({ active_until_ms: NOW + 4 * MINUTE })).toEqual({ text: "Grant ends in 4 min", tone: "warning", request: false, note });
    // Rounded up: the last seconds still read as a minute.
    expect(line({ active_until_ms: NOW + 1 })).toEqual({ text: "Grant ends in 1 min", tone: "warning", request: false, note });
    expect(line({ active_until_ms: NOW + MINUTE + 1 }).text).toBe("Grant ends in 2 min");
    // Five minutes exactly is within five minutes; a moment more is not.
    expect(line({ active_until_ms: NOW + 5 * MINUTE })).toEqual({ text: "Grant ends in 5 min", tone: "warning", request: false, note });
    expect(line({ active_until_ms: NOW + 5 * MINUTE + 1 })).toEqual({ text: "prod-operate · Active until 10:05", tone: "held", request: false });
  });

  it("shows a grant with time to spare, or without an end, as held and offers no request", () => {
    expect(line({ active_until_ms: NOW + 30 * MINUTE })).toEqual({ text: "prod-operate · Active until 10:30", tone: "held", request: false });
    expect(line({ active_until_ms: null })).toEqual({ text: "prod-operate · Active", tone: "held", request: false });
    expect(line({ state: "activating", entitlement: "prod-admin", active_until_ms: null })).toEqual({ text: "prod-admin · Activating…", tone: "held", request: false });
  });

  it("says a grant is missing, in the warning color, when none is held or the one held has ended", () => {
    const missing = { text: "Needs a grant: prod-operate, prod-admin", tone: "warning", request: true };
    expect(line({ state: "none", entitlement: null })).toEqual(missing);
    // An end that has passed is no negative number of minutes: PAM may not have ended the grant yet, but it is no grant now.
    expect(line({ active_until_ms: NOW })).toEqual(missing);
    expect(line({ active_until_ms: NOW - 3 * MINUTE })).toEqual(missing);
    expect(line({ active_until_ms: NOW - 3 * MINUTE }).text).not.toMatch(/-\d/);
  });

  it("offers no request for a grant that waits for its approver or could not be checked", () => {
    expect(line({ state: "approval_awaited", entitlement: "prod-admin" })).toEqual({ text: "prod-admin · Awaiting approval", tone: "plain", request: false });
    const refused = "Privileged Access Manager refused the request: quota exceeded.";
    expect(line({ state: "error", entitlement: null, message: refused })).toEqual({ text: refused, tone: "plain", request: false });
    expect(line({ state: "error", entitlement: null, message: null }).text).toBe("The grant could not be checked.");
  });
});

describe("the grant of the host a database is reached through", () => {
  const [WEB, JUMP] = ["00000000000000b1", "00000000000000b2"];
  const GRANT = { entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: null };
  /** A saved host that connects through the hosts of `jump`. */
  const host = (id: string, alias: string, jump: string[] = []) => hostView({ id, payload: hostPayload({ alias, jump }) });
  /** `ORDERS` over its private address, through the library host `via`. */
  const through = (via: string): SavedDatabase => ({ ...ORDERS, network: "private", via_host: via });

  it("is_the_route_of_the_hosts_first_hop_named_by_the_host", () => {
    // The host itself holds the route that asks for the grant.
    const direct = recordOverview({ hosts: [host(WEB, "web-1")], transports: [hostTransport({ pam: GRANT }, WEB)] });
    expect(routeHostGrant(direct, through(WEB))).toEqual({ hostId: WEB, alias: "web-1", pam: GRANT });
    // A host behind a jump host is reached through the jump host's route: the grant is read for it, the line names the host.
    const behind = recordOverview({ hosts: [host(WEB, "web-1", [JUMP]), host(JUMP, "jump-1")], transports: [hostTransport({ pam: GRANT }, JUMP)] });
    expect(routeHostGrant(behind, through(WEB))).toEqual({ hostId: JUMP, alias: "web-1", pam: GRANT });
  });

  it("is_none_for_a_database_on_its_public_address", () => {
    const overview = recordOverview({ hosts: [host(WEB, "web-1")], transports: [hostTransport({ pam: GRANT }, WEB)] });
    expect(routeHostGrant(overview, ORDERS)).toBeNull();
    // A record that names a host while public, or private without one, goes through none.
    expect(routeHostGrant(overview, { ...ORDERS, via_host: WEB })).toBeNull();
    expect(routeHostGrant(overview, { ...ORDERS, network: "private" })).toBeNull();
  });

  it("is_none_when_the_host_is_missing_or_its_first_hop_asks_for_no_grant", () => {
    const route = (pam: typeof GRANT | null) => recordOverview({ hosts: [host(WEB, "web-1")], transports: [hostTransport({ pam }, WEB)] });
    expect(routeHostGrant(route(null), through(WEB))).toBeNull();
    expect(routeHostGrant(recordOverview({ hosts: [host(WEB, "web-1")], transports: [] }), through(WEB))).toBeNull();
    expect(routeHostGrant(recordOverview({ hosts: [], transports: [hostTransport({ pam: GRANT }, WEB)] }), through(WEB))).toBeNull();
    // Jump hosts that go round in a circle have no first hop; the route of a host that is not the first hop is not the one that applies.
    const loop = recordOverview({ hosts: [host(WEB, "web-1", [JUMP]), host(JUMP, "jump-1", [WEB])], transports: [hostTransport({ pam: GRANT }, WEB)] });
    expect(routeHostGrant(loop, through(WEB))).toBeNull();
    const notFirst = recordOverview({ hosts: [host(WEB, "web-1", [JUMP]), host(JUMP, "jump-1")], transports: [hostTransport({ pam: GRANT }, WEB)] });
    expect(routeHostGrant(notFirst, through(WEB))).toBeNull();
  });
});

describe("the route of a database", () => {
  const [WEB_1, WEB_2, WEB_3] = ["00000000000000b1", "00000000000000b2", "00000000000000b3"];
  const host = (id: string, alias: string, jump: string[] = []) => hostView({ id, payload: hostPayload({ alias, jump }) });
  /** `ORDERS` over its private address, through the library host `via`. */
  const through = (via: string): SavedDatabase => ({ ...ORDERS, network: "private", via_host: via });
  const ADDRESS = "198.51.100.7:3307";

  it("goes through the host a private database names, and through none over the public IP", () => {
    expect(routeHost(ORDERS)).toBeNull();
    expect(routeHost(through(WEB_1))).toBe(WEB_1);
    // A record that names a host while public, or is private without one, goes through none.
    expect(routeHost({ network: "public", via_host: WEB_1 })).toBeNull();
    expect(routeHost({ network: "private" })).toBeNull();
  });

  it("offers as jump hosts the hosts whose own IAP route is in the project", () => {
    const overview = recordOverview({
      hosts: [host(WEB_1, "web-1"), host(WEB_2, "web-2"), host(WEB_3, "web-3")],
      transports: [hostTransport({ project: "acme-dev-654321" }, WEB_1), hostTransport({ project: "acme-prod-123456" }, WEB_2)],
    });
    expect(jumpHostCandidates(overview, "acme-dev-654321")).toEqual([{ id: WEB_1, alias: "web-1" }]);
    expect(jumpHostCandidates(overview, "acme-prod-123456")).toEqual([{ id: WEB_2, alias: "web-2" }]);
    expect(jumpHostCandidates(overview, "")).toEqual([]);
  });

  it("judges a jump host by its own route, not by its first hop's, and lists them by alias, then by id", () => {
    const BEHIND = "00000000000000b4";
    const overview = recordOverview({
      // web-2 is reached through web-1 and has no route of its own; a route whose host is not here is no host's. Two hosts share an alias.
      hosts: [host(WEB_3, "web-3"), host(BEHIND, "web-2", [WEB_1]), host(WEB_2, "web-1"), host(WEB_1, "web-1")],
      transports: [
        hostTransport({ project: "acme-dev-654321" }, WEB_3),
        hostTransport({ project: "acme-dev-654321" }, WEB_2),
        hostTransport({ project: "acme-dev-654321" }, WEB_1),
        hostTransport({ project: "acme-dev-654321" }, "00000000000000b9"),
      ],
    });
    expect(jumpHostCandidates(overview, "acme-dev-654321")).toEqual([
      { id: WEB_1, alias: "web-1" },
      { id: WEB_2, alias: "web-1" },
      { id: WEB_3, alias: "web-3" },
    ]);
    // Every host of the library, a route or not, in the same order.
    expect(libraryHosts(overview)).toEqual([
      { id: WEB_1, alias: "web-1" },
      { id: WEB_2, alias: "web-1" },
      { id: BEHIND, alias: "web-2" },
      { id: WEB_3, alias: "web-3" },
    ]);
  });

  it("names the host and whether the way to it begins with IAP, by the route of its first hop", () => {
    const overview = recordOverview({ hosts: [host(WEB_1, "web-1"), host(WEB_2, "web-2", [WEB_1]), host(WEB_3, "web-3")], transports: [hostTransport({}, WEB_1)] });
    expect(routeSummary(overview, through(WEB_1))).toEqual({ alias: "web-1", iap: true });
    // web-2 is reached through web-1, whose route is the one that applies; its own alias is the one named.
    expect(routeSummary(overview, through(WEB_2))).toEqual({ alias: "web-2", iap: true });
    expect(routeSummary(overview, through(WEB_3))).toEqual({ alias: "web-3", iap: false });
    // A host this computer has not got, and a database on its public IP, name none.
    expect(routeSummary(overview, through("00000000000000b9"))).toEqual({ alias: null, iap: false });
    expect(routeSummary(overview, ORDERS)).toEqual({ alias: null, iap: false });
  });

  it("words the route after where the database is", () => {
    expect(databaseRoute(through(WEB_1), "web-1")).toBe("PostgreSQL · acme-prod-123456 · asia-east1 · orders-pg · via web-1");
    // A host whose alias is not known, and a database on its public IP, say where the database is and nothing more.
    expect(databaseRoute(through(WEB_1), null)).toBe("PostgreSQL · acme-prod-123456 · asia-east1 · orders-pg");
    expect(databaseRoute(through(WEB_1))).toBe("PostgreSQL · acme-prod-123456 · asia-east1 · orders-pg");
    expect(databaseRoute(ORDERS, "web-1")).toBe("PostgreSQL · acme-prod-123456 · asia-east1 · orders-pg");
  });

  it("says what a start is doing at each step", () => {
    expect(stepSentence("grant", "web-1")).toBe("Requesting grant…");
    expect(stepSentence("connect", "web-1")).toBe("Connecting through web-1…");
    expect(stepSentence("connect", null)).toBe("Connecting through the host…");
    expect(stepSentence("certificate", "web-1")).toBe("Getting the Cloud SQL certificate…");
    expect(stepSentence("certificate", null)).toBe("Getting the Cloud SQL certificate…");
  });

  it("writes the JDBC URL with the database and the user encoded", () => {
    expect(jdbcUrl({ ...ORDERS, default_database: "app" }, 6543, "frank@example.com")).toBe("jdbc:postgresql://127.0.0.1:6543/app?user=frank%40example.com");
    expect(jdbcUrl({ ...ORDERS, default_database: "orders db/2" }, 6544, "orders-sa@acme-prod-123456.iam")).toBe(
      "jdbc:postgresql://127.0.0.1:6544/orders%20db%2F2?user=orders-sa%40acme-prod-123456.iam",
    );
  });

  describe("drawn as its parts", () => {
    const live = (phase: DatabasePhase, patch: Partial<DatabaseLive> = {}): DatabaseLive => ({ phase, port: null, connections: 0, writable_until_ms: null, error: null, step: null, address: null, ...patch });
    const WEB = { alias: "web-1", iap: true };
    const PUBLIC: RouteSummary = { alias: null, iap: false };
    const FIVE = ["Lunport", "IAP", "web-1", ADDRESS, "Cloud SQL (TLS, IAM)"];
    const cases: [string, SavedDatabase, DatabaseLive, RouteSummary, string[], RoutePartState[]][] = [
      ["running through web-1", through(WEB_1), live("running", { address: ADDRESS }), WEB, FIVE, ["done", "done", "done", "done", "done"]],
      ["starting at grant", through(WEB_1), live("starting", { step: "grant", address: ADDRESS }), WEB, FIVE, ["active", "idle", "idle", "idle", "idle"]],
      ["starting at connect", through(WEB_1), live("starting", { step: "connect", address: ADDRESS }), WEB, FIVE, ["done", "active", "active", "idle", "idle"]],
      ["starting at certificate", through(WEB_1), live("starting", { step: "certificate", address: ADDRESS }), WEB, FIVE, ["done", "done", "done", "done", "active"]],
      ["failed at grant", through(WEB_1), live("error", { step: "grant", address: ADDRESS }), WEB, FIVE, ["failed", "idle", "idle", "idle", "idle"]],
      ["failed at connect", through(WEB_1), live("error", { step: "connect", address: ADDRESS }), WEB, FIVE, ["done", "failed", "failed", "idle", "idle"]],
      ["failed at certificate", through(WEB_1), live("error", { step: "certificate", address: ADDRESS }), WEB, FIVE, ["done", "done", "done", "done", "failed"]],
      ["failed before a step", through(WEB_1), live("error", { address: ADDRESS }), WEB, FIVE, ["failed", "idle", "idle", "idle", "idle"]],
      ["stopping", through(WEB_1), live("stopping", { address: ADDRESS }), WEB, FIVE, ["idle", "idle", "idle", "idle", "idle"]],
      // Until a start fetched the address, and once a dial that was refused cleared it, the part says which address it is.
      ["stopped through web-1", through(WEB_1), live("stopped"), WEB, ["Lunport", "IAP", "web-1", "Private IP", "Cloud SQL (TLS, IAM)"], ["idle", "idle", "idle", "idle", "idle"]],
      ["running with its address cleared", through(WEB_1), live("running"), WEB, ["Lunport", "IAP", "web-1", "Private IP", "Cloud SQL (TLS, IAM)"], ["done", "done", "done", "done", "done"]],
      // A first hop without an IAP route draws no IAP; the host alone is at the connect step.
      ["through a host without IAP", through(WEB_1), live("starting", { step: "connect" }), { alias: "web-1", iap: false }, ["Lunport", "web-1", "Private IP", "Cloud SQL (TLS, IAM)"], ["done", "active", "idle", "idle"]],
      ["through a host that is not here", through(WEB_1), live("stopped"), PUBLIC, ["Lunport", HOST_UNAVAILABLE, "Private IP", "Cloud SQL (TLS, IAM)"], ["idle", "idle", "idle", "idle"]],
      ["public while stopped", ORDERS, live("stopped"), PUBLIC, ["Lunport", "Public IP", "Cloud SQL (TLS, IAM)"], ["idle", "idle", "idle"]],
      ["public at certificate", ORDERS, live("starting", { step: "certificate" }), PUBLIC, ["Lunport", "Public IP", "Cloud SQL (TLS, IAM)"], ["done", "done", "active"]],
      ["public while running", ORDERS, live("running", { address: "203.0.113.5:3307" }), PUBLIC, ["Lunport", "203.0.113.5:3307", "Cloud SQL (TLS, IAM)"], ["done", "done", "done"]],
      // A database on its public IP goes through no host, whatever it is handed.
      ["public handed a host", ORDERS, live("stopped"), WEB, ["Lunport", "Public IP", "Cloud SQL (TLS, IAM)"], ["idle", "idle", "idle"]],
    ];

    it.each(cases)("%s", (_case, database, state, route, labels, states) => {
      const parts = routeParts(database, state, route);
      expect(parts.map((part) => part.label)).toEqual(labels);
      expect(parts.map((part) => part.state)).toEqual(states);
    });

    it("names an unavailable host as the row does", () => {
      expect(HOST_UNAVAILABLE).toBe("Host unavailable");
    });
  });
});

describe("running an action of the Databases page", () => {
  afterEach(() => vi.unstubAllGlobals());

  /** A client whose list was read once, so that it can read it again. */
  async function listed() {
    const client = new QueryClient();
    const calls = stubBackend(async () => []);
    await client.fetchQuery(databasesQuery);
    const reads = () => calls.filter(([command]) => command === "databases_list").length;
    return { client, reads };
  }

  it("reads the list again after it worked", async () => {
    const { client, reads } = await listed();
    expect(reads()).toBe(1);
    expect(await runDatabaseAction(client, async () => {})).toBeNull();
    expect(reads()).toBe(2);
  });

  it("reads the list again after a delete that failed once the record was gone, and answers the sentence", async () => {
    const { client, reads } = await listed();
    // The backend deleted the record, then could not remove the database's password from the keychain: the command fails all the same.
    const sentence = "The database was deleted, but its password could not be removed from the keychain: keychain error: denied";
    expect(await runDatabaseAction(client, () => Promise.reject(sentence))).toBe(sentence);
    expect(reads()).toBe(2);
    // Whatever else goes wrong is read again just the same, and an Error says its message.
    expect(await runDatabaseAction(client, () => Promise.reject(new Error("This database changed on another device. Refresh and try again.")))).toBe("This database changed on another device. Refresh and try again.");
    expect(reads()).toBe(3);
  });

  it("shows hidden characters of a failure as codes", async () => {
    const { client } = await listed();
    expect(await runDatabaseAction(client, () => Promise.reject("Stop Orders\u202e before you change it."))).toBe("Stop Orders⟨U+202E⟩ before you change it.");
  });
});
