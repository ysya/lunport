import { describe, expect, it, vi } from "vitest";
import {
  confirmMigration,
  continueMigration,
  migrationKey,
  migrationScope,
  migrationStatus,
  prepareMigration,
} from "./central-migration";
import type { CentralStatus } from "./central-sync";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("@/lib/ipc", () => ({ tauriInvoke: invoke }));
const status = {
  service: "https://sync.test",
  account_id: "account",
  device_id: "device",
  root_fingerprint: "root",
  membership_head: "head",
  authorization_epoch: "2",
} as CentralStatus;
describe("scoped library migration calls", () => {
  it("sends the immutable public account/device fence with every operation", async () => {
    invoke.mockReset().mockResolvedValue({});
    const expected = migrationScope(status);
    await migrationStatus(expected);
    await prepareMigration(expected);
    await confirmMigration(expected, "a".repeat(64));
    await continueMigration(expected);
    expect(invoke.mock.calls).toEqual([
      ["central_migration_status", { expected }],
      ["central_migration_prepare", { expected }],
      ["central_migration_confirm", { expected, ticket: "a".repeat(64) }],
      ["central_migration_continue", { expected }],
    ]);
    expect(JSON.stringify(expected)).not.toMatch(
      /token|credential|private|vault_key|inventory_digest/,
    );
  });
  it("separates progress by service, root, device and membership without including a review ticket", () => {
    for (const field of [
      "service",
      "account_id",
      "device_id",
      "root_fingerprint",
      "membership_head",
      "authorization_epoch",
    ] as const)
      expect(migrationKey({ ...status, [field]: "changed" })).not.toEqual(
        migrationKey(status),
      );
    expect(JSON.stringify(migrationKey(status))).not.toContain("ticket");
  });
});
