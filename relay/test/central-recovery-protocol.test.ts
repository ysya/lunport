import { describe, expect, it } from "vitest";
import fixture from "../../fixtures/central-sync-v2.json";
import { trustGenesis } from "../src/v2/membership";
import { verifyRecoveryRead } from "../src/v2/recovery";
describe("recovery read proof interoperability", () => {
  it("matches independent Noble/Rust signing and rejects scope, epoch, authority and expired-request substitutions", async () => {
    const state = (await trustGenesis(fixture.genesis, fixture.anchor))!;
    const proof = {
      request_id: fixture.enrollment.request_id,
      membership_head: fixture.anchor.genesis_hash,
      auth_epoch: "2",
      signature:
        "Hew0YHcd5iC9IMlFAR7eVr4AupLij37GR36JonaHmWwDIgzg9e6s9n+5GsA1CCK2sAR4IKzFQAgnmJp/lUBCBw==",
    };
    expect(
      await verifyRecoveryRead(
        state,
        fixture.enrollment,
        proof,
        2,
        1700000001000,
      ),
    ).toBe(true);
    expect(
      await verifyRecoveryRead(
        state,
        fixture.enrollment,
        { ...proof, auth_epoch: "3" },
        2,
        1700000001000,
      ),
    ).toBe(false);
    expect(
      await verifyRecoveryRead(
        state,
        fixture.enrollment,
        { ...proof, membership_head: "9".repeat(64) },
        2,
        1700000001000,
      ),
    ).toBe(false);
    expect(
      await verifyRecoveryRead(
        state,
        { ...fixture.enrollment, account_id: "9".repeat(64) },
        proof,
        2,
        1700000001000,
      ),
    ).toBe(false);
    expect(
      await verifyRecoveryRead(
        state,
        fixture.enrollment,
        proof,
        2,
        1700001000000,
      ),
    ).toBe(false);
    expect(
      await verifyRecoveryRead(
        state,
        fixture.enrollment,
        { ...proof, secret: "extra" } as any,
        2,
        1700000001000,
      ),
    ).toBe(false);
  });
});
