import { describe, expect, it, vi } from "vitest";
import type { CentralStatus } from "./central-sync";
import {
  replacementKey,
  reserveReplacement,
  type ReplacementInvocation,
} from "./central-replacement";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("@/lib/ipc", () => ({ tauriInvoke: invoke }));
const lease: ReplacementInvocation = {
  generation: "a".repeat(32),
  scope: "b".repeat(64),
  route: "recovery_kit",
  operation: null,
};
const status: CentralStatus = {
  available: true,
  configured: true,
  phase: "enrolled",
  service: "https://sync.test",
  account_id: "a",
  device_id: "b",
  root_fingerprint: "root",
  membership_head: "head",
  authorization_epoch: "2",
  has_session: false,
  needs_recovery: true,
  replacement_pending: false,
  login_pending: false,
  can_sync: false,
  pending: 0,
  conflicts: 0,
  error: null,
};
describe("replacement metadata and dedicated secret calls", () => {
  it("serializes only metadata reservations across component lifecycles", async () => {
    let release!: (value: ReplacementInvocation) => void;
    invoke
      .mockReset()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            release = resolve;
          }),
      )
      .mockResolvedValueOnce({ ...lease, generation: "c".repeat(32) });
    const first = reserveReplacement("recovery_kit");
    const second = reserveReplacement("trusted_device");
    await Promise.resolve();
    expect(invoke).toHaveBeenCalledTimes(1);
    release(lease);
    expect(await first).toEqual(lease);
    await second;
    expect(invoke.mock.calls.map((call) => call[1])).toEqual([
      { route: "recovery_kit" },
      { route: "trusted_device" },
    ]);
  });
  it("scopes metadata to immutable account and device identity while accepting newer authorization", () => {
    expect(replacementKey(status)).toEqual(
      replacementKey({ ...status, authorization_epoch: "3" }),
    );
    for (const next of [
      { service: "https://other.test" },
      { account_id: "other" },
      { device_id: "other" },
      { root_fingerprint: "other" },
    ]) {
      expect(replacementKey({ ...status, ...next })).not.toEqual(
        replacementKey(status),
      );
    }
  });
});
