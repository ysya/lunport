import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import fixture from "../../fixtures/central-sync-v2.json";
import golden from "../../fixtures/central-unlock-v1.json";
import { base64 } from "../src/v2/protocol";
import { trustGenesis } from "../src/v2/membership";
import { envelopeCanonical, unlockCanonical, unlockDigest, verifyUnlockUpdate, type SignedUnlock, type UnlockEnvelope } from "../src/v2/unlock";
const sign = (value: SignedUnlock) => ({ ...value, signature: base64(ed25519.sign(unlockCanonical(value.body), new Uint8Array(32).fill(1))) });
async function initial() {
  const member = (await trustGenesis(fixture.genesis, fixture.anchor))!;
  const envelope: UnlockEnvelope = {
    header: { version: 1, anchor: member.anchor, generation: "1", binding: { kind: "password" }, salt: base64(new Uint8Array(32).fill(3)) },
    nonce: base64(new Uint8Array(24).fill(4)), ciphertext: base64(new Uint8Array(64).fill(5)),
  };
  const registry = sign({ body: { version: 1, anchor: member.anchor, revision: "1", previous_digest: "",
    membership_head: member.head, authorization_epoch: "2", author: fixture.genesis.first.id,
    recovery: member.recovery, slots: [envelope] }, signature: "" });
  return { member, registry };
}
describe("signed encrypted account-unlock registry", () => {
  it("matches the shared native/Worker encoding, signature and digest", async () => {
    const { member } = await initial();
    const registry = golden.registry as SignedUnlock;
    expect(base64(unlockCanonical(registry.body))).toBe(golden.canonical_base64);
    expect(await unlockDigest(registry)).toBe(golden.digest);
    expect(await verifyUnlockUpdate(member, null, registry, 2, fixture.genesis.first.id)).toBe(true);
  });
  it("authenticates the complete slots and only allows monotonic current-authority changes", async () => {
    const { member, registry } = await initial(), actor = fixture.genesis.first.id;
    expect(await verifyUnlockUpdate(member, null, registry, 2, actor)).toBe(true);
    for (const change of [
      (v: SignedUnlock) => { v.body.slots[0].ciphertext = base64(new Uint8Array(64).fill(6)); },
      (v: SignedUnlock) => { v.body.anchor.account_id = "b".repeat(64); },
      (v: SignedUnlock) => { v.body.recovery = fixture.genesis.first.keys; },
      (v: SignedUnlock) => { v.body.authorization_epoch = "1"; },
      (v: SignedUnlock) => { v.body.author = "a".repeat(32); },
    ]) {
      const bad = structuredClone(registry); change(bad);
      expect(await verifyUnlockUpdate(member, null, bad, 2, actor)).toBe(false);
    }
    const next = structuredClone(registry);
    next.body.revision = "2"; next.body.previous_digest = await unlockDigest(registry);
    expect(await verifyUnlockUpdate(member, registry, sign(next), 2, actor)).toBe(true);
    next.body.slots[0].nonce = base64(new Uint8Array(24).fill(8));
    expect(await verifyUnlockUpdate(member, registry, sign(next), 2, actor)).toBe(false);
    next.body.slots[0].header.generation = "2";
    expect(await verifyUnlockUpdate(member, registry, sign(next), 2, actor)).toBe(true);
    expect(await verifyUnlockUpdate(member, registry, registry, 2, actor)).toBe(false);
  });
  it("bounds untrusted slots, fields and KDF identifiers before any decryption", async () => {
    const { member, registry } = await initial(), actor = fixture.genesis.first.id;
    const envelope = registry.body.slots[0];
    for (const mutate of [
      (v: SignedUnlock) => { v.body.slots = Array(9).fill(envelope); },
      (v: SignedUnlock) => { v.body.slots = [envelope, envelope]; },
      (v: SignedUnlock) => { v.body.slots[0].header.generation = "2"; },
      (v: SignedUnlock) => { (v.body.slots[0].header.binding as any).memory = 1; },
      (v: SignedUnlock) => { v.body.slots[0].ciphertext = base64(new Uint8Array(4113)); },
      (v: SignedUnlock) => { (v.body as any).password = "must-not-be-accepted"; },
    ]) {
      const bad = structuredClone(registry); mutate(bad);
      expect(await verifyUnlockUpdate(member, null, bad, 2, actor)).toBe(false);
    }
    expect(() => envelopeCanonical({ ...envelope, nonce: "bad" })).toThrow();
  });
});
