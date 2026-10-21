import { describe, expect, it } from "vitest";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import fixture from "../../fixtures/central-sync-v2.json";
import { base64 } from "../src/v2/protocol";
import {
  applyMembership,
  enrollmentCanonical,
  genesisCanonical,
  membershipCanonical,
  trustGenesis,
  verifyEnrollment,
  verifyCurrentWrite,
  verifyCurrentWrap,
  type MembershipBody,
  type SignedMembership,
  type Enrollment,
} from "../src/v2/membership";
const sign = (body: MembershipBody, seed = 1): SignedMembership => ({
  body,
  signature: base64(
    ed25519.sign(membershipCanonical(body), new Uint8Array(32).fill(seed)),
  ),
});
const nodes = fixture.membership_nodes as SignedMembership[];
async function current() {
  let state = await trustGenesis(fixture.genesis, fixture.anchor);
  if (!state) throw new Error("root rejected");
  for (const node of nodes) {
    const next = await applyMembership(state, node);
    if (!next) throw new Error("chain rejected");
    state = next;
  }
  return state;
}
function pending(deviceId = "2".repeat(32), seed = 6): Enrollment {
  const keys = {
    signing: base64(ed25519.getPublicKey(new Uint8Array(32).fill(seed))),
    encryption: base64(x25519.getPublicKey(new Uint8Array(32).fill(seed))),
  };
  const request: Enrollment = {
    ...fixture.enrollment,
    device: { id: deviceId, keys },
    request_id: "2".repeat(32),
    nonce: "3".repeat(64),
    created_at_ms: "1700000002000",
    expires_at_ms: "1700000602000",
    signature: "",
  };
  request.signature = base64(
    ed25519.sign(enrollmentCanonical(request), new Uint8Array(32).fill(seed)),
  );
  return request;
}
describe("signed central membership", () => {
  it("matches Rust genesis, enrollment and every membership byte and head", async () => {
    expect(base64(genesisCanonical(fixture.genesis))).toBe(
      fixture.genesis_canonical_base64,
    );
    expect(base64(enrollmentCanonical(fixture.enrollment))).toBe(
      fixture.enrollment_canonical_base64,
    );
    for (let i = 0; i < nodes.length; i++) {
      expect(base64(membershipCanonical(nodes[i].body))).toBe(
        fixture.membership_canonical_base64[i],
      );
      expect(sign(nodes[i].body).signature).toBe(nodes[i].signature);
    }
    expect((await current()).head).toBe(fixture.current_membership_head);
    expect(Object.keys((await current()).devices)).toEqual(["f".repeat(32)]);
  });
  it("requires the independently supplied root and refuses pending self-approval", async () => {
    expect(
      await trustGenesis(fixture.genesis, {
        ...fixture.anchor,
        genesis_hash: "0".repeat(64),
      }),
    ).toBeNull();
    const first = await trustGenesis(fixture.genesis, fixture.anchor);
    expect(first).not.toBeNull();
    const forged = structuredClone(nodes[0].body);
    forged.author = "d".repeat(32);
    expect(await applyMembership(first!, sign(forged, 2))).toBeNull();
    const replaced = structuredClone(nodes[0]);
    replaced.body.devices["d".repeat(32)].encryption =
      fixture.author_public.encryption;
    expect(await applyMembership(first!, replaced)).toBeNull();
  });
  it("keeps accepted historical approval valid after expiry while live enrollment expires", async () => {
    expect(await verifyEnrollment(fixture.enrollment, 1700000001000)).toBe(
      true,
    );
    expect(await verifyEnrollment(fixture.enrollment, Date.now())).toBe(false);
    expect(await current()).not.toBeNull();
  });
  it("rejects revoked authors, replay, forks and reuse of a retired device identity", async () => {
    const state = await current();
    expect(await applyMembership(state, nodes[0])).toBeNull();
    const request = pending("d".repeat(32));
    const body: MembershipBody = {
      ...nodes[0].body,
      revision: "3",
      previous_head: state.head,
      issued_at_ms: "1700000003000",
      enrollment: request,
      devices: { ...state.devices, [request.device.id]: request.device.keys },
    };
    expect(await applyMembership(state, sign(body))).toBeNull(); // old ID even with new key material
    const fresh = pending();
    body.enrollment = fresh;
    body.devices = { ...state.devices, [fresh.device.id]: fresh.device.keys };
    body.author = "d".repeat(32);
    expect(await applyMembership(state, sign(body, 2))).toBeNull();
    body.author = "f".repeat(32);
    body.previous_head = fixture.anchor.genesis_hash;
    expect(await applyMembership(state, sign(body))).toBeNull();
  });
  it("requires the current recovery authority to restore a lost-device account", async () => {
    const state = await current(),
      request = pending();
    const body: MembershipBody = {
      ...nodes[0].body,
      revision: "3",
      previous_head: state.head,
      issued_at_ms: "1700000003000",
      action: "recover",
      author: "recovery",
      enrollment: request,
      devices: { [request.device.id]: request.device.keys },
    };
    expect(await applyMembership(state, sign(body, 6))).toBeNull();
    const restored = await applyMembership(state, sign(body, 4));
    expect(restored).not.toBeNull();
    expect(Object.keys(restored!.devices)).toEqual([request.device.id]);
  });
  it("allows account unlock only to append a fresh device using the current recovery authority", async () => {
    const state = await current(), request = pending();
    const body: MembershipBody = {
      ...nodes[0].body, revision: "3", previous_head: state.head,
      issued_at_ms: "1700000003000", action: "unlock", author: "recovery",
      enrollment: request, devices: { ...state.devices, [request.device.id]: request.device.keys },
      recovery: state.recovery,
    };
    expect(await applyMembership(state, sign(body, 1))).toBeNull();
    expect(await applyMembership(state, sign(body, 6))).toBeNull();
    const approved = sign(body, 4), next = await applyMembership(state, approved);
    expect(next).not.toBeNull();
    expect(next!.devices).toEqual(body.devices);
    expect(next!.recovery).toEqual(state.recovery);
    expect(await applyMembership(next!, approved)).toBeNull();
    for (const patch of [
      { devices: { [request.device.id]: request.device.keys } },
      { author: "f".repeat(32) },
      { previous_head: "0".repeat(64) },
      { issued_at_ms: "1700000603000" },
      { recovery: request.device.keys },
    ]) expect(await applyMembership(state, sign({ ...body, ...patch }, 4))).toBeNull();
  });
  it("binds current writes and key recipients to routed vault, epoch and authenticated actor", async () => {
    const first = await trustGenesis(fixture.genesis, fixture.anchor);
    const approved = await applyMembership(first!, nodes[0]);
    expect(
      await verifyCurrentWrite(
        approved!,
        fixture.record,
        fixture.record.header.vault_id,
        1,
        fixture.record.header.author,
      ),
    ).toBe(true);
    expect(
      await verifyCurrentWrite(
        approved!,
        fixture.record,
        fixture.record.header.vault_id,
        2,
        fixture.record.header.author,
      ),
    ).toBe(false);
    expect(
      await verifyCurrentWrite(
        approved!,
        fixture.record,
        "9".repeat(64),
        1,
        fixture.record.header.author,
      ),
    ).toBe(false);
    expect(
      await verifyCurrentWrite(
        approved!,
        fixture.record,
        fixture.record.header.vault_id,
        1,
        "d".repeat(32),
      ),
    ).toBe(false);
    expect(
      await verifyCurrentWrap(
        approved!,
        fixture.wrap,
        fixture.wrap.header.vault_id,
        1,
      ),
    ).toBe(true);
    expect(
      await verifyCurrentWrap(
        approved!,
        fixture.wrap,
        fixture.wrap.header.vault_id,
        2,
      ),
    ).toBe(false);
    const revoked = await current();
    expect(
      await verifyCurrentWrite(
        revoked,
        fixture.record,
        fixture.record.header.vault_id,
        1,
        fixture.record.header.author,
      ),
    ).toBe(false);
    expect(
      await verifyCurrentWrap(
        revoked,
        fixture.wrap,
        fixture.wrap.header.vault_id,
        1,
      ),
    ).toBe(false);
  });
});
