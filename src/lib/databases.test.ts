import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "./test-ipc";
import {
  connectionName,
  databasesKey,
  deleteDatabase,
  listDatabases,
  newDatabase,
  parseConnectionName,
  saveDatabase,
  type DatabaseView,
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

  it("starts a new database as a public PostgreSQL dev instance with nothing filled in", () => {
    expect(newDatabase()).toEqual({
      id: "",
      name: "",
      engine: "postgres",
      project: "",
      region: "",
      instance: "",
      environment: "dev",
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
      live: { phase: "stopped", port: null, connections: 0, writable_until_ms: null, error: null },
      synced: true,
      blocked: false,
      removed: false,
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
});
