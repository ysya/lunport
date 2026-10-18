import { env } from "cloudflare:workers";
import {
  createExecutionContext,
  evictDurableObject,
  runInDurableObject,
} from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import fixture from "../../fixtures/central-sync-v2.json";
import {
  deviceProof,
  verifyIdentity,
  type IdentityConfig,
  type Principal,
} from "../src/v2/auth";
import {
  enrollmentCanonical,
  genesisCanonical,
  membershipCanonical,
  type Device,
  type Enrollment,
  type Genesis,
  type MembershipBody,
  type SignedMembership,
  type TrustedMembership,
} from "../src/v2/membership";
import { applyMembership, trustGenesis } from "../src/v2/membership";
import {
  authorBytes,
  base64,
  hash,
  recordCanonical,
  wrapCanonical,
  type RecordEnvelope,
  type WrappedKeys,
} from "../src/v2/protocol";
import { rekeyCanonical, wrapsDigest, type SignedRekey } from "../src/v2/rekey";
import { centralFetch } from "../src/v2/routes";
import { CentralSyncBackend } from "../src/index";
import { REGISTRY_WITNESS } from "../src/security/floor";
import { freezeCanonical, type SignedFreeze } from "../src/v2/migration-freeze";
import { migrationCanonical, type SignedMigration } from "../src/v2/migration";
import { envelopeDigest } from "../src/v2/store";
import { canonical } from "../src/v2/protocol";
const origin = "https://relay.test";
const random = (bytes = 32) =>
  Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (v) =>
    v.toString(16).padStart(2, "0"),
  ).join("");
const sign = (bytes: Uint8Array, seed = 1) =>
  base64(ed25519.sign(bytes, new Uint8Array(32).fill(seed)));
function device(seed = 6): Device {
  return {
    id: random(16),
    keys: {
      signing: base64(ed25519.getPublicKey(new Uint8Array(32).fill(seed))),
      encryption: base64(x25519.getPublicKey(new Uint8Array(32).fill(seed))),
    },
  };
}
async function wraps(
  state: TrustedMembership,
  vault: string,
  epoch = 1,
  author = fixture.genesis.first.id,
  authorSeed = 1,
): Promise<WrappedKeys[]> {
  const result: WrappedKeys[] = [];
  for (const [recipient, keys] of Object.entries({
    ...state.devices,
    recovery: state.recovery,
  })) {
    // Opaque fixture ciphertext: the relay can authenticate authors, never inspect plaintext.
    const wrapped: WrappedKeys = {
      ...fixture.wrap,
      header: {
        ...fixture.wrap.header,
        origin,
        account_id: state.anchor.account_id,
        genesis_hash: state.anchor.genesis_hash,
        vault_id: vault,
        key_epoch: String(epoch),
        membership_head: state.head,
        recipient,
        recipient_key: keys.encryption,
        author,
      },
    };
    wrapped.signature = sign(
      await authorBytes(
        "lunport-wrap-author-v2",
        wrapCanonical(wrapped.header),
        wrapped.encapsulated_key,
        Uint8Array.from(atob(wrapped.ciphertext), (c) => c.charCodeAt(0)),
      ),
      authorSeed,
    );
    result.push(wrapped);
  }
  return result;
}
async function record(
  state: TrustedMembership,
  vault: string,
  expected = "0",
  id = random(),
  operation = random(16),
): Promise<RecordEnvelope> {
  const result: RecordEnvelope = {
    ...fixture.record,
    header: {
      ...fixture.record.header,
      origin,
      account_id: state.anchor.account_id,
      genesis_hash: state.anchor.genesis_hash,
      vault_id: vault,
      key_epoch: "1",
      membership_head: state.head,
      author: fixture.genesis.first.id,
      expected_revision: expected,
      record_id: id,
      operation_id: operation,
    },
  };
  result.signature = sign(
    await authorBytes(
      "lunport-record-author-v2",
      recordCanonical(result.header),
      result.nonce,
      Uint8Array.from(atob(result.ciphertext), (c) => c.charCodeAt(0)),
    ),
  );
  return result;
}
async function setup() {
  const locator = random(),
    identity = { locator, authenticatedAt: Date.now() },
    account = env.ACCOUNT.getByName(locator);
  const credential = random(),
    first = fixture.genesis.first;
  const renew = async (d = first, c = credential) => {
    const sessionSecret = random();
    const proof = (await deviceProof(d.id, c, random(16), sessionSecret))!;
    const response = await account.register(
      identity,
      origin,
      proof,
      d,
      "Test device",
    );
    const actor = await account.authorize(proof.session, false);
    const text = await response.text();
    const info = text ? JSON.parse(text) : null;
    return {
      proof,
      response,
      actor,
      info,
      bearer: `v2.${locator}.${proof.session.id}.${sessionSecret}`,
    };
  };
  const registered = await renew();
  expect(registered.response.status).toBe(200);
  const accountId = registered.info.account_id as string;
  const genesis: Genesis = {
    ...fixture.genesis,
    origin,
    account_id: accountId,
  };
  const bytes = genesisCanonical(genesis);
  genesis.device_signature = sign(bytes);
  genesis.recovery_signature = sign(bytes, 4);
  const anchor = {
    origin,
    account_id: accountId,
    genesis_hash: await hash(bytes),
  };
  const trusted = (await trustGenesis(genesis, anchor))!,
    vault = random();
  const boot = await account.bootstrap(
    registered.actor!,
    genesis,
    vault,
    await wraps(trusted, vault),
  );
  expect(boot.status).toBe(200);
  await boot.arrayBuffer();
  const active = await renew();
  expect(active.response.status).toBe(200);
  return {
    locator,
    identity,
    account,
    credential,
    first,
    renew,
    genesis,
    trusted,
    vault,
    actor: active.actor!,
    proof: active.proof,
  };
}
async function add(s: Awaited<ReturnType<typeof setup>>) {
  const added = device(),
    credential = random(),
    registered = await s.renew(added, credential);
  expect(registered.response.status).toBe(200);
  const now = Date.now(),
    request: Enrollment = {
      origin,
      account_id: s.trusted.anchor.account_id,
      genesis_hash: s.trusted.anchor.genesis_hash,
      request_id: random(16),
      device: added,
      nonce: random(),
      created_at_ms: String(now - 100),
      expires_at_ms: String(now + 600000),
      signature: "",
    };
  request.signature = sign(enrollmentCanonical(request), 6);
  expect((await s.account.enrollment(registered.actor!, request)).status).toBe(
    204,
  );
  const body: MembershipBody = {
    origin,
    account_id: s.trusted.anchor.account_id,
    genesis_hash: s.trusted.anchor.genesis_hash,
    revision: "1",
    previous_head: s.trusted.head,
    author: s.first.id,
    action: "add",
    issued_at_ms: String(now),
    enrollment: request,
    devices: { ...s.trusted.devices, [added.id]: added.keys },
    recovery: s.trusted.recovery,
  };
  const node: SignedMembership = {
    body,
    signature: sign(membershipCanonical(body)),
  };
  const next = (await applyMembership(s.trusted, node))!;
  expect(
    (
      await s.account.control(s.actor, node, {
        [s.vault]: await wraps(next, s.vault),
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await s.account.control(
        s.actor,
        node,
        { [s.vault]: await wraps(next, s.vault) },
        {
          request_id: request.request_id,
          approved_head: "9".repeat(64),
          personal_vault: s.vault,
          minimums: [
            {
              vault: s.vault,
              creation_head: s.trusted.head,
              creation_authorization_epoch: "2",
              key_epoch: "1",
              sequence: "0",
              history_hash: "0".repeat(64),
            },
          ],
          mac: base64(new Uint8Array(32).fill(42)),
        },
      )
    ).status,
  ).toBe(400);
  const approved = await s.account.control(
    s.actor,
    node,
    { [s.vault]: await wraps(next, s.vault) },
    {
      request_id: request.request_id,
      approved_head: next.head,
      personal_vault: s.vault,
      minimums: [
        {
          vault: s.vault,
          creation_head: s.trusted.head,
          creation_authorization_epoch: "2",
          key_epoch: "1",
          sequence: "0",
          history_hash: "0".repeat(64),
        },
      ],
      mac: base64(new Uint8Array(32).fill(42)),
    },
  );
  expect(approved.status).toBe(200);
  await approved.arrayBuffer();
  const own = (await s.renew(added, credential)).actor!;
  const overview = (await (await s.account.overview(own)).json()) as any;
  expect(overview.pairing_confirmation).toMatchObject({
    request_id: request.request_id,
    approved_head: next.head,
  });
  return {
    added,
    credential,
    node,
    trusted: next,
    actor: (await s.renew(added, credential)).actor!,
    firstActor: (await s.renew()).actor!,
  };
}
describe("central device authorization and durable data", () => {
  it("retains a renewed pending device and a live enrollment when cleaning old pending identities", async () => {
    for (const liveRequest of [false, true]) {
      const s = await setup(),
        pendingDevice = device(),
        secret = random();
      const pending = await s.renew(pendingDevice, secret);
      expect(pending.response.status).toBe(200);
      await runInDurableObject(s.account, async (_instance, state) => {
        const stored = JSON.parse(
          state.storage.sql
            .exec<{ value: string }>("SELECT value FROM account_state")
            .one().value,
        );
        stored.registrations[pendingDevice.id].created =
          Date.now() - 16 * 60 * 1000;
        delete stored.registrations[pendingDevice.id].last_activity;
        state.storage.sql.exec(
          "UPDATE account_state SET value=?",
          JSON.stringify(stored),
        );
      });
      let current = pending;
      if (liveRequest) {
        const now = Date.now();
        const request: Enrollment = {
          origin,
          account_id: s.actor.account,
          genesis_hash: s.trusted.anchor.genesis_hash,
          request_id: random(16),
          device: pendingDevice,
          nonce: random(),
          created_at_ms: String(now - 100),
          expires_at_ms: String(now + 600000),
          signature: "",
        };
        request.signature = sign(enrollmentCanonical(request), 6);
        expect(
          (await s.account.enrollment(pending.actor!, request)).status,
        ).toBe(204);
        // Old durable versions did not have last_activity; a live signed request is still retained.
        await runInDurableObject(s.account, async (_instance, state) => {
          const stored = JSON.parse(
            state.storage.sql
              .exec<{ value: string }>("SELECT value FROM account_state")
              .one().value,
          );
          delete stored.registrations[pendingDevice.id].last_activity;
          state.storage.sql.exec(
            "UPDATE account_state SET value=?",
            JSON.stringify(stored),
          );
        });
      } else {
        current = await s.renew(pendingDevice, secret);
        expect(current.response.status).toBe(200);
      }
      expect((await s.renew(device(8), random())).response.status).toBe(200);
      expect(
        await s.account.authorize(current.proof.session, false),
      ).not.toBeNull();
      const overview = await s.account.overview(current.actor!);
      expect(overview.status).toBe(200);
    }
  });

  it("keeps login-only devices pending, requires their independent credential and expires opaque sessions", async () => {
    const s = await setup(),
      added = device(),
      secret = random(),
      pending = await s.renew(added, secret);
    expect(await s.account.authorize(pending.proof.session, true)).toBeNull();
    const extra = device(8),
      extraProof = (await deviceProof(
        extra.id,
        random(),
        random(16),
        random(),
      ))!;
    expect(
      (
        await s.account.register(
          s.identity,
          origin,
          extraProof,
          { ...extra, private_key: "must not be stored" } as any,
          "Invalid DTO",
        )
      ).status,
    ).toBe(400);

    const proof = (await deviceProof(
      added.id,
      random(),
      random(16),
      random(),
    ))!;
    expect(
      (await s.account.register(s.identity, origin, proof, added, "Impostor"))
        .status,
    ).toBe(403);
    expect(
      await s.account.authorize(s.proof.session, true, Date.now() + 300001),
    ).toBeNull();
    const vault = env.VAULT.getByName(s.actor.account + ":" + s.vault);
    expect((await vault.pull(pending.actor!, 0)).status).toBe(403);
    expect((await vault.wrap(pending.actor!)).status).toBe(403);
    expect(
      (await vault.pull({ ...s.actor, account: random() }, 0)).status,
    ).toBe(403);
    expect(
      (await vault.pull({ ...s.actor, expires: Date.now() - 1 }, 0)).status,
    ).toBe(403);
    expect(
      (
        await s.account.bootstrap(
          s.actor,
          s.genesis,
          s.vault,
          await wraps(s.trusted, s.vault),
        )
      ).status,
    ).toBe(409);
  });
  it("logout cannot reactivate the same bearer through an unexpired registration retry", async () => {
    const s = await setup();
    expect((await s.account.logout(s.actor)).status).toBe(204);
    expect(await s.account.authorize(s.proof.session, false)).toBeNull();
    expect(
      (
        await s.account.register(
          s.identity,
          origin,
          s.proof,
          s.first,
          "Test device",
        )
      ).status,
    ).toBe(401);
    expect((await s.renew()).response.status).toBe(200);
  });
  it("fresh account login can resume a failed revocation after the last active device is stopped", async () => {
    const s = await setup(),
      vault = env.VAULT.getByName(s.actor.account + ":" + s.vault);
    const original = await runInDurableObject(vault, (_instance, ctx) => {
      const encoded = ctx.storage.sql
        .exec<{ value: string }>("SELECT value FROM vault_state WHERE id=1")
        .one().value;
      const state = JSON.parse(encoded);
      state.epoch = 999;
      ctx.storage.sql.exec(
        "UPDATE vault_state SET value=? WHERE id=1",
        JSON.stringify(state),
      );
      return encoded;
    });
    const first = await s.account.revokeAccess(s.identity, s.first.id);
    expect(first.status).toBe(202);
    expect(await first.json()).toMatchObject({ access_revoked: false });
    expect((await s.renew()).response.status).toBe(403);
    await evictDurableObject(s.account);
    await runInDurableObject(vault, (_instance, ctx) => {
      ctx.storage.sql.exec(
        "UPDATE vault_state SET value=? WHERE id=1",
        original,
      );
    });
    const retried = await s.account.revokeAccess(
      { ...s.identity, authenticatedAt: Date.now() },
      s.first.id,
    );
    expect(retried.status).toBe(200);
    expect(await retried.json()).toMatchObject({
      access_revoked: true,
      rekey_pending: true,
    });
    expect((await vault.pull(s.actor, 0)).status).toBe(403);
  });
  it("uses exact revision, persists conflicts/history and returns an unchanged receipt after response-loss retry", async () => {
    const s = await setup(),
      vault = env.VAULT.getByName(s.actor.account + ":" + s.vault),
      first = await record(s.trusted, s.vault);
    const r1 = await vault.push(s.actor, [first]);
    expect(r1.status).toBe(200);
    const receipt = (await r1.json()) as any;
    await evictDurableObject(vault);
    const retry = await vault.push(s.actor, [first]);
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual(receipt);
    const stale = await record(s.trusted, s.vault, "0", first.header.record_id);
    const conflict = await vault.push(s.actor, [stale]);
    expect(conflict.status).toBe(409);
    expect(
      ((await conflict.json()) as any).conflicts[0].current.envelope,
    ).toEqual(first);
    const future = await record(
      s.trusted,
      s.vault,
      "99",
      first.header.record_id,
    );
    expect((await vault.push(s.actor, [future])).status).toBe(409);
    const second = await record(
      s.trusted,
      s.vault,
      "1",
      first.header.record_id,
    );
    expect((await vault.push(s.actor, [second])).status).toBe(200);
    const history = (await (await vault.pull(s.actor, 0)).json()) as any;
    expect(history.records.map((r: any) => r.revision)).toEqual(["1", "2"]);
    const reused = await record(
      s.trusted,
      s.vault,
      "2",
      first.header.record_id,
      first.header.operation_id,
    );
    expect((await vault.push(s.actor, [reused])).status).toBe(409);
  });
  it("rejects signed writes for another vault, author, epoch and stale membership", async () => {
    const s = await setup(),
      vault = env.VAULT.getByName(s.actor.account + ":" + s.vault);
    expect(
      (await vault.push(s.actor, [await record(s.trusted, random())])).status,
    ).toBe(403);
    const envelope = await record(s.trusted, s.vault);
    envelope.header.key_epoch = "2";
    expect((await vault.push(s.actor, [envelope])).status).toBe(403);
    const enrolled = await add(s);
    expect(await s.account.authorize(s.proof.session, true)).toBeNull();
    expect(
      (
        await vault.push(enrolled.firstActor, [
          await record(s.trusted, s.vault),
        ])
      ).status,
    ).toBe(403);
    expect(
      (
        await vault.push(enrolled.actor, [
          await record(enrolled.trusted, s.vault),
        ])
      ).status,
    ).toBe(403);
  });
  it("installs revocation in every vault before acknowledging it, invalidates cached principals and freezes old-key writes", async () => {
    const s = await setup(),
      second = random();
    expect(
      (
        await s.account.createVault(
          s.actor,
          second,
          await wraps(s.trusted, second),
        )
      ).status,
    ).toBe(200);
    const pending = await s.renew(device(), random());
    expect(await s.account.authorize(pending.proof.session, true)).toBeNull();
    const stop = await s.account.revokeAccess(s.identity, s.first.id);
    expect(stop.status).toBe(200);
    expect(await stop.json()).toMatchObject({
      access_revoked: true,
      rekey_pending: true,
    });
    for (const id of [s.vault, second]) {
      const vault = env.VAULT.getByName(s.actor.account + ":" + id);
      expect((await vault.pull(s.actor, 0)).status).toBe(403);
      expect((await vault.wrap(s.actor)).status).toBe(403);
      expect(
        (await vault.push(s.actor, [await record(s.trusted, id)])).status,
      ).toBe(403);
    }
    expect((await s.renew()).response.status).toBe(403);
  });
  it("fences delayed recovery attempts and cannot reinstall an older enrollment nonce", async () => {
    const s = await setup(),
      d = device(6),
      credential = random(),
      registered = await s.renew(d, credential),
      now = Date.now();
    const enrollment = (created: number): Enrollment => {
      const request: Enrollment = {
        origin,
        account_id: s.actor.account,
        genesis_hash: s.trusted.anchor.genesis_hash,
        request_id: random(16),
        device: d,
        nonce: random(),
        created_at_ms: String(created),
        expires_at_ms: String(now + 600000),
        signature: "",
      };
      request.signature = sign(enrollmentCanonical(request), 6);
      return request;
    };
    const old = enrollment(now - 200),
      current = enrollment(now - 100);
    expect((await s.account.enrollment(registered.actor!, old)).status).toBe(
      204,
    );
    const recover = async (request: Enrollment) => {
      const body: MembershipBody = {
        origin,
        account_id: s.actor.account,
        genesis_hash: s.trusted.anchor.genesis_hash,
        revision: "1",
        previous_head: s.trusted.head,
        author: "recovery",
        action: "recover",
        issued_at_ms: String(now),
        enrollment: request,
        devices: { [d.id]: d.keys },
        recovery: device(8).keys,
      };
      const node: SignedMembership = {
        body,
        signature: sign(membershipCanonical(body), 4),
      };
      const next = (await applyMembership(s.trusted, node))!;
      return {
        node,
        wraps: { [s.vault]: await wraps(next, s.vault, 1, d.id, 6) },
      };
    };
    const abandoned = await recover(old);
    expect(
      (await s.account.enrollment(registered.actor!, current)).status,
    ).toBe(204);
    expect(
      (await s.account.enrollment(registered.actor!, current)).status,
    ).toBe(204);
    expect((await s.account.enrollment(registered.actor!, old)).status).toBe(
      409,
    );
    expect(
      (await s.account.enrollment(registered.actor!, enrollment(now - 100)))
        .status,
    ).toBe(409);
    expect(
      (
        await s.account.recover(
          registered.actor!,
          abandoned.node,
          abandoned.wraps,
        )
      ).status,
    ).toBe(400);
    expect((await s.account.overview(registered.actor!)).status).toBe(200);
    const next = await recover(current);
    expect(
      (await s.account.recover(registered.actor!, next.node, next.wraps))
        .status,
    ).toBe(200);
    const active = await s.renew(d, credential);
    expect(active.response.status).toBe(200);
    expect((await s.account.enrollment(active.actor!, old)).status).toBe(403);
  });
  it("requires the current kit for pending recovery wraps and bridges to the new kit before enabling the fresh device", async () => {
    const s = await setup(),
      d = device(6),
      credential = random();
    const child = env.VAULT.getByName(s.actor.account + ":" + s.vault);
    const rows = await Promise.all(
      Array.from({ length: 33 }, () => record(s.trusted, s.vault)),
    );
    expect((await child.push(s.actor, rows.slice(0, 32))).status).toBe(200);
    expect((await child.push(s.actor, rows.slice(32))).status).toBe(200);
    let enrolled = await s.renew(d, credential);
    const now = Date.now();
    const request: Enrollment = {
      origin,
      account_id: s.actor.account,
      genesis_hash: s.trusted.anchor.genesis_hash,
      request_id: random(16),
      device: d,
      nonce: random(),
      created_at_ms: String(now - 100),
      expires_at_ms: String(now + 600000),
      signature: "",
    };
    request.signature = sign(enrollmentCanonical(request), 6);
    expect((await s.account.enrollment(enrolled.actor!, request)).status).toBe(
      204,
    );
    const makeProof = (
      req: Enrollment,
      head: string,
      epoch: number,
      seed: number,
    ) => ({
      request_id: req.request_id,
      membership_head: head,
      auth_epoch: String(epoch),
      signature: sign(
        new TextEncoder().encode(
          JSON.stringify([
            "lunport-recovery-read-v2",
            origin,
            s.actor.account,
            s.trusted.anchor.genesis_hash,
            head,
            String(epoch),
            base64(enrollmentCanonical(req)),
            req.signature,
          ]),
        ),
        seed,
      ),
    });
    const proof = makeProof(request, s.trusted.head, enrolled.actor!.epoch, 4);
    expect(
      (
        await s.account.recoveryWraps(enrolled.actor!, {
          ...proof,
          signature: base64(new Uint8Array(64)),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await s.account.recoveryWraps(enrolled.actor!, {
          ...proof,
          auth_epoch: "999",
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await s.account.recoveryWraps(enrolled.actor!, {
          ...proof,
          request_id: random(16),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await s.account.recoveryHistory(
          enrolled.actor!,
          { ...proof, signature: base64(new Uint8Array(64)) },
          s.vault,
          0,
        )
      ).status,
    ).toBe(403);
    expect((await child.pull(enrolled.actor!, 0)).status).toBe(403);
    expect(
      (await s.account.recoveryHistory(enrolled.actor!, proof, random(), 0))
        .status,
    ).toBe(403);
    expect(
      (await s.account.recoveryHistory(enrolled.actor!, proof, s.vault, -1))
        .status,
    ).toBe(400);
    const firstPage = await s.account.recoveryHistory(
      enrolled.actor!,
      proof,
      s.vault,
      0,
    );
    expect(firstPage.status).toBe(200);
    const firstHistory = (await firstPage.json()) as any;
    expect(firstHistory.records).toHaveLength(32);
    expect(firstHistory).toMatchObject({
      sequence: "33",
      epoch: 1,
      membership_head: s.trusted.head,
    });
    const lastPage = await s.account.recoveryHistory(
      enrolled.actor!,
      proof,
      s.vault,
      32,
    );
    expect(lastPage.status).toBe(200);
    const lastHistory = (await lastPage.json()) as any;
    expect(lastHistory.records).toHaveLength(1);
    expect(lastHistory.records[0].sequence).toBe("33");
    expect(lastHistory.records[0].history_hash).toBe(firstHistory.history_hash);
    // Change account authorization after the child has produced a valid page. No ciphertext
    // from that page may escape through an account snapshot that is no longer authorized.
    const raced = await runInDurableObject(s.account, async (instance, ctx) => {
      const bindings = (instance as unknown as { env: Env }).env;
      const original = bindings.VAULT;
      const saved = ctx.storage.sql
        .exec<{ value: string }>("SELECT value FROM account_state")
        .one().value;
      const changed = JSON.parse(saved);
      const delegate = original.getByName.bind(original);
      bindings.VAULT = {
        getByName: (name: string) => ({
          recoveryHistoryForGrant: async (grant: any, since: number) => {
            const response = await delegate(name).recoveryHistoryForGrant(
              grant,
              since,
            );
            changed.version += 1;
            changed.epoch += 1;
            ctx.storage.sql.exec(
              "UPDATE account_state SET value=?",
              JSON.stringify(changed),
            );
            return response;
          },
        }),
      } as unknown as typeof original;
      try {
        return (
          await instance.recoveryHistory(enrolled.actor!, proof, s.vault, 0)
        ).status;
      } finally {
        bindings.VAULT = original;
        ctx.storage.sql.exec("UPDATE account_state SET value=?", saved);
      }
    });
    expect(raced).toBe(409);
    const before = await s.account.recoveryWraps(enrolled.actor!, proof);
    expect(before.status).toBe(200);
    const beforeBody = (await before.json()) as any;
    expect(beforeBody.results[0].wrap.header.recipient).toBe("recovery");
    expect(beforeBody.results[0].committed).toBeNull();
    const vault = env.VAULT.getByName(s.actor.account + ":" + s.vault);
    const cachedGrant = {
      kind: "recovery_read" as const,
      locator: s.locator,
      account: s.actor.account,
      device: d.id,
      epoch: enrolled.actor!.epoch,
      head: s.trusted.head,
      expires: enrolled.actor!.expires,
    };
    expect(
      (
        await vault.recoveryHistoryForGrant(
          { ...cachedGrant, expires: Date.now() - 1 },
          0,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await vault.recoveryHistoryForGrant(
          { ...cachedGrant, head: "0".repeat(64) },
          0,
        )
      ).status,
    ).toBe(403);
    const stopped = await s.account.revokeAccess(s.identity, s.first.id);
    expect(stopped.status).toBe(200);
    await stopped.arrayBuffer();
    expect((await vault.recoveryForGrant(cachedGrant)).status).toBe(403);
    expect((await vault.recoveryHistoryForGrant(cachedGrant, 0)).status).toBe(
      403,
    );
    expect(
      (await s.account.recoveryHistory(enrolled.actor!, proof, s.vault, 0))
        .status,
    ).toBe(403);
    enrolled = await s.renew(d, credential);
    expect((await s.account.recoveryWraps(enrolled.actor!, proof)).status).toBe(
      403,
    );
    const newRecovery = device(8).keys;
    const body: MembershipBody = {
      origin,
      account_id: s.actor.account,
      genesis_hash: s.trusted.anchor.genesis_hash,
      revision: "1",
      previous_head: s.trusted.head,
      author: "recovery",
      action: "recover",
      issued_at_ms: String(Date.now()),
      enrollment: request,
      devices: { [d.id]: d.keys },
      recovery: newRecovery,
    };
    const node: SignedMembership = {
        body,
        signature: sign(membershipCanonical(body), 4),
      },
      next = (await applyMembership(s.trusted, node))!;
    const bridge = await wraps(next, s.vault, 1, d.id, 6);
    expect(
      (
        await s.account.recover(
          enrolled.actor!,
          { ...node, signature: sign(membershipCanonical(body), 1) },
          { [s.vault]: bridge },
        )
      ).status,
    ).toBe(400);
    expect((await s.account.recover(enrolled.actor!, node, {})).status).toBe(
      400,
    );
    const savedVault = await runInDurableObject(vault, (_instance, ctx) => {
      const encoded = ctx.storage.sql
        .exec<{ value: string }>("SELECT value FROM vault_state WHERE id=1")
        .one().value;
      const data = JSON.parse(encoded);
      data.epoch = 999;
      ctx.storage.sql.exec(
        "UPDATE vault_state SET value=? WHERE id=1",
        JSON.stringify(data),
      );
      return encoded;
    });
    const recovered = await s.account.recover(enrolled.actor!, node, {
      [s.vault]: bridge,
    });
    expect(recovered.status).toBe(202);
    expect(await recovered.json()).toMatchObject({
      access_revoked: false,
      barrier_pending: true,
    });
    await evictDurableObject(s.account);
    await runInDurableObject(vault, (_instance, ctx) => {
      ctx.storage.sql.exec(
        "UPDATE vault_state SET value=? WHERE id=1",
        savedVault,
      );
    });
    // Another loss before content rekey: a fresh pending device must recover using the NEW kit.
    const another = device(9),
      anotherLogin = await s.renew(another, random()),
      later: Enrollment = {
        ...request,
        request_id: random(16),
        device: another,
        nonce: random(),
        created_at_ms: String(Date.now() - 100),
        expires_at_ms: String(Date.now() + 600000),
        signature: "",
      };
    later.signature = sign(enrollmentCanonical(later), 9);
    expect(
      (await s.account.enrollment(anotherLogin.actor!, later)).status,
    ).toBe(204);
    expect(
      (
        await s.account.recoveryWraps(
          anotherLogin.actor!,
          makeProof(later, next.head, anotherLogin.actor!.epoch, 4),
        )
      ).status,
    ).toBe(403);
    const usable = await s.account.recoveryWraps(
      anotherLogin.actor!,
      makeProof(later, next.head, anotherLogin.actor!.epoch, 8),
    );
    expect(usable.status).toBe(200);
    expect(
      ((await usable.json()) as any).results[0].wrap.header.recipient_key,
    ).toBe(newRecovery.encryption);
    const active = await s.renew(d, credential);
    expect(
      await s.account.authorize(active.proof.session, true),
    ).not.toBeNull();
    const ownWrap = (await (await vault.wrap(active.actor!)).json()) as any;
    expect(ownWrap.header.recipient).toBe(d.id);
    expect(ownWrap.header.membership_head).toBe(next.head);
    expect(
      (await vault.push(active.actor!, [await record(next, s.vault)])).status,
    ).toBe(423);
  });
  it("requires recovery bridge wraps before rotating authority and keeps writes frozen until content rekey", async () => {
    const s = await setup(),
      keys = device(8).keys,
      now = Date.now();
    const body: MembershipBody = {
      origin,
      account_id: s.trusted.anchor.account_id,
      genesis_hash: s.trusted.anchor.genesis_hash,
      revision: "1",
      previous_head: s.trusted.head,
      author: s.first.id,
      action: "recovery",
      issued_at_ms: String(now),
      enrollment: null,
      devices: s.trusted.devices,
      recovery: keys,
    };
    const node: SignedMembership = {
        body,
        signature: sign(membershipCanonical(body)),
      },
      next = (await applyMembership(s.trusted, node))!;
    expect((await s.account.control(s.actor, node, {})).status).toBe(400);
    const result = await s.account.control(s.actor, node, {
      [s.vault]: await wraps(next, s.vault),
    });
    expect(result.status).toBe(200);
    expect(await result.json()).toMatchObject({ rekey_pending: true });
    const fresh = (await s.renew()).actor!,
      vault = env.VAULT.getByName(fresh.account + ":" + s.vault);
    const recovery = await runInDurableObject(vault, (_instance, ctx) => {
      const state = JSON.parse(
        ctx.storage.sql
          .exec<{ value: string }>("SELECT value FROM vault_state WHERE id=1")
          .one().value,
      );
      return state.wraps.find((w: any) => w.header.recipient === "recovery");
    });
    expect(recovery.header.recipient_key).toBe(keys.encryption);
    expect(recovery.header.membership_head).toBe(next.head);
    expect(recovery.header.key_epoch).toBe("1");
    expect(
      (await vault.push(fresh, [await record(next, s.vault)])).status,
    ).toBe(423);
  });
  it("separates signed membership revocation from content rekey completion", async () => {
    const s = await setup(),
      a = await add(s),
      now = Date.now();
    const body: MembershipBody = {
      ...a.node.body,
      revision: "2",
      previous_head: a.trusted.head,
      action: "revoke",
      issued_at_ms: String(now),
      enrollment: null,
      devices: { [s.first.id]: s.first.keys },
    };
    const node: SignedMembership = {
      body,
      signature: sign(membershipCanonical(body)),
    };
    const response = await s.account.control(a.firstActor, node, {});
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      access_revoked: true,
      rekey_pending: true,
    });
    const vault = env.VAULT.getByName(s.actor.account + ":" + s.vault);
    expect((await vault.pull(a.actor, 0)).status).toBe(403);
    const fresh = (await s.renew()).actor!;
    expect((await vault.metadata(fresh)).status).toBe(200);
    expect((await s.account.control(fresh, node, {})).status).toBe(200);
    expect(
      (
        await vault.push(fresh, [
          await record((await applyMembership(a.trusted, node))!, s.vault),
        ])
      ).status,
    ).toBe(423);
    expect((await s.renew(a.added, a.credential)).response.status).toBe(403);
  });
  it("reconciles a committed child after registry response loss and preserves a later freeze", async () => {
    const s = await setup(),
      a = await add(s);
    const body: MembershipBody = {
      ...a.node.body,
      revision: "2",
      previous_head: a.trusted.head,
      action: "revoke",
      issued_at_ms: String(Date.now()),
      enrollment: null,
      devices: { [s.first.id]: s.first.keys },
    };
    const node: SignedMembership = {
      body,
      signature: sign(membershipCanonical(body)),
    };
    const next = (await applyMembership(a.trusted, node))!;
    const revoked = await s.account.control(a.firstActor, node, {});
    expect(revoked.status).toBe(200);
    await revoked.arrayBuffer();
    const actor = (await s.renew()).actor!,
      child = env.VAULT.getByName(actor.account + ":" + s.vault);
    const target = await wraps(next, s.vault, 2);
    const manifest: SignedRekey = {
      body: {
        origin,
        account_id: actor.account,
        genesis_hash: next.anchor.genesis_hash,
        vault_id: s.vault,
        rotation_id: random(16),
        authorization_epoch: String(actor.epoch),
        from_epoch: "1",
        to_epoch: "2",
        membership_head: next.head,
        author: actor.device,
        source_sequence: "0",
        source_history_hash: "0".repeat(64),
        target_history_hash: "0".repeat(64),
        wraps_digest: await wrapsDigest(target),
      },
      signature: "",
    };
    manifest.signature = sign(rekeyCanonical(manifest.body));
    expect((await child.beginRekey(actor, manifest, target)).status).toBe(200);
    const committed = await child.commitRekey(actor, manifest.body.rotation_id);
    expect(committed.status).toBe(200);
    await committed.arrayBuffer();
    // The child commit succeeded, but no account ACK was saved before the restart.
    await evictDurableObject(s.account);
    // No old trusted device is needed to repair the lost registry ACK: a pending device
    // first proves the CURRENT kit, then the account observes the child's committed epoch.
    const pendingRecovery = device(10),
      pendingGrant = await s.renew(pendingRecovery, random());
    const recoveryEnrollment: Enrollment = {
      origin,
      account_id: actor.account,
      genesis_hash: next.anchor.genesis_hash,
      request_id: random(16),
      device: pendingRecovery,
      nonce: random(),
      created_at_ms: String(Date.now() - 100),
      expires_at_ms: String(Date.now() + 600000),
      signature: "",
    };
    recoveryEnrollment.signature = sign(
      enrollmentCanonical(recoveryEnrollment),
      10,
    );
    expect(
      (await s.account.enrollment(pendingGrant.actor!, recoveryEnrollment))
        .status,
    ).toBe(204);
    const recoveryProof = {
      request_id: recoveryEnrollment.request_id,
      membership_head: next.head,
      auth_epoch: String(pendingGrant.actor!.epoch),
      signature: sign(
        new TextEncoder().encode(
          JSON.stringify([
            "lunport-recovery-read-v2",
            origin,
            actor.account,
            next.anchor.genesis_hash,
            next.head,
            String(pendingGrant.actor!.epoch),
            base64(enrollmentCanonical(recoveryEnrollment)),
            recoveryEnrollment.signature,
          ]),
        ),
        4,
      ),
    };
    expect(
      (
        await s.account.recoveryWraps(pendingGrant.actor!, {
          ...recoveryProof,
          signature: base64(new Uint8Array(64)),
        })
      ).status,
    ).toBe(403);
    const staleRegistry = await runInDurableObject(
      s.account,
      (_instance, ctx) =>
        JSON.parse(
          ctx.storage.sql
            .exec<{ value: string }>("SELECT value FROM account_state")
            .one().value,
        ),
    );
    expect(staleRegistry.vaults[s.vault]).toEqual({ epoch: 1, rekey: true });
    const recoveryRead = await s.account.recoveryWraps(
      pendingGrant.actor!,
      recoveryProof,
    );
    expect(recoveryRead.status).toBe(200);
    expect(await recoveryRead.json()).toMatchObject({
      results: [{ epoch: 2, phase: "ready", committed: { manifest } }],
    });
    expect(
      (
        await s.account.recoverySource(
          pendingGrant.actor!,
          { ...recoveryProof, signature: base64(new Uint8Array(64)) },
          s.vault,
          2,
          0,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await s.account.recoverySource(
          pendingGrant.actor!,
          recoveryProof,
          random(),
          2,
          0,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await s.account.recoverySource(
          pendingGrant.actor!,
          recoveryProof,
          s.vault,
          66,
          0,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await s.account.recoverySource(
          pendingGrant.actor!,
          recoveryProof,
          s.vault,
          2,
          1,
        )
      ).status,
    ).toBe(400);
    const sourceRead = await s.account.recoverySource(
      pendingGrant.actor!,
      recoveryProof,
      s.vault,
      2,
      0,
    );
    expect(sourceRead.status).toBe(200);
    expect(await sourceRead.json()).toEqual({ manifest, digests: [] });
    const finished = await s.account.finishRekey(
      actor,
      s.vault,
      manifest.body.rotation_id,
    );
    expect(finished.status).toBe(200);
    expect(await finished.json()).toMatchObject({
      registry_pending: false,
      manifest,
    });
    const view = await runInDurableObject(s.account, (_instance, ctx) =>
      JSON.parse(
        ctx.storage.sql
          .exec<{ value: string }>("SELECT value FROM account_state")
          .one().value,
      ),
    );
    expect(view.vaults[s.vault]).toEqual({ epoch: 2, rekey: false });
    // Simulate a lost registry ACK again, then a newer cloud-access barrier.
    await runInDurableObject(s.account, (_instance, ctx) => {
      const state = JSON.parse(
        ctx.storage.sql
          .exec<{ value: string }>("SELECT value FROM account_state")
          .one().value,
      );
      state.vaults[s.vault] = { epoch: 1, rekey: true };
      ctx.storage.sql.exec(
        "UPDATE account_state SET value=?",
        JSON.stringify(state),
      );
    });
    const pending = await s.renew(device(9), random());
    const freeze = await s.account.revokeAccess(
      s.identity,
      pending.actor!.device,
    );
    expect(freeze.status).toBe(200);
    await freeze.arrayBuffer();
    const fresh = (await s.renew()).actor!;
    const reconciled = await s.account.reconcileVault(fresh, s.vault);
    expect(await reconciled.json()).toEqual({ epoch: 2, rekey_pending: true });
    expect(
      (await child.push(fresh, [await record(next, s.vault)])).status,
    ).toBe(423);
    expect((await s.account.reconcileVault(actor, s.vault)).status).toBe(403);
  });
  it("resumes an interrupted bootstrap barrier after account restart without claiming premature completion", async () => {
    const locator = random(),
      identity = { locator, authenticatedAt: Date.now() },
      account = env.ACCOUNT.getByName(locator),
      first = fixture.genesis.first,
      credential = random();
    const register = async () => {
      const proof = (await deviceProof(
        first.id,
        credential,
        random(16),
        random(),
      ))!;
      const response = await account.register(
        identity,
        origin,
        proof,
        first,
        "First",
      );
      expect(response.status).toBe(200);
      return {
        proof,
        actor: (await account.authorize(proof.session, false))!,
        info: (await response.json()) as any,
      };
    };
    const before = await register(),
      genesis: Genesis = {
        ...fixture.genesis,
        origin,
        account_id: before.info.account_id,
      },
      vault = random();
    let bytes = genesisCanonical(genesis);
    genesis.device_signature = sign(bytes);
    genesis.recovery_signature = sign(bytes, 4);
    const trusted = (await trustGenesis(genesis, {
      origin,
      account_id: genesis.account_id,
      genesis_hash: await hash(bytes),
    }))!;
    const wrong: Genesis = { ...genesis, nonce: random() };
    bytes = genesisCanonical(wrong);
    wrong.device_signature = sign(bytes);
    wrong.recovery_signature = sign(bytes, 4);
    const wrongTrust = (await trustGenesis(wrong, {
      origin,
      account_id: wrong.account_id,
      genesis_hash: await hash(bytes),
    }))!;
    const store = env.VAULT.getByName(genesis.account_id + ":" + vault);
    expect(
      await store.install({
        locator,
        account: genesis.account_id,
        vault,
        epoch: 1,
        proof: { genesis: wrong, nodes: [] },
        wraps: await wraps(wrongTrust, vault),
        freeze: false,
        denied: [],
      }),
    ).toBe(200);
    const blocked = await account.bootstrap(
      before.actor,
      genesis,
      vault,
      await wraps(trusted, vault),
    );
    expect(blocked.status).toBe(202);
    expect(await blocked.json()).toMatchObject({
      access_revoked: false,
      barrier_pending: true,
    });
    await evictDurableObject(account);
    const after = await register();
    expect(await account.authorize(after.proof.session, true)).toBeNull();
    await runInDurableObject(store, async (_instance, ctx) => {
      await ctx.storage.deleteAll();
    });
    expect((await account.resume(after.actor)).status).toBe(200);
    expect(await account.authorize(after.proof.session, true)).not.toBeNull();
  });
});
const config: IdentityConfig = {
  origin,
  issuer: "https://id.test",
  jwks: "https://id.test/jwks",
  audience: "lunport-api",
  clientId: "lunport-native",
  scope: "lunport:sync",
};
describe("OIDC resource-token profile", () => {
  it("rejects ID tokens, wrong issuer/audience/client/scope, bad signature, expired tokens and excess lifetime", async () => {
    const pair = await generateKeyPair("ES256"),
      other = await generateKeyPair("ES256"),
      jwk = await exportJWK(pair.publicKey);
    jwk.kid = "test";
    jwk.alg = "ES256";
    const resolver = createLocalJWKSet({ keys: [jwk] }),
      now = Math.floor(Date.now() / 1000);
    const token = async (
      claims: Record<string, any> = {},
      typ = "at+jwt",
      key = pair.privateKey,
    ) =>
      new SignJWT({
        iss: config.issuer,
        aud: config.audience,
        sub: "opaque-user",
        client_id: config.clientId,
        jti: random(),
        scope: config.scope,
        iat: now,
        exp: now + 300,
        ...claims,
      })
        .setProtectedHeader({ alg: "ES256", kid: "test", typ })
        .sign(key);
    const valid = await verifyIdentity(await token(), config, resolver);
    expect(valid).not.toBeNull();
    expect(
      (
        await verifyIdentity(
          await token({ email: "new@example.test" }),
          config,
          resolver,
        )
      )?.locator,
    ).toBe(valid!.locator);
    for (const claims of [
      { iss: "https://other.test" },
      { aud: config.clientId },
      { client_id: "other-client" },
      { scope: "openid" },
      { exp: now - 20 },
      { exp: now + 7200 },
      { sub: "" },
      { jti: "" },
    ])
      expect(
        await verifyIdentity(await token(claims), config, resolver),
      ).toBeNull();
    expect(
      await verifyIdentity(await token({}, "JWT"), config, resolver),
    ).toBeNull();
    expect(
      await verifyIdentity(
        await token({}, "at+jwt", other.privateKey),
        config,
        resolver,
      ),
    ).toBeNull();
    expect(
      await verifyIdentity(
        await token(),
        { ...config, audience: config.clientId },
        resolver,
      ),
    ).toBeNull();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });
  it("bounds streamed identity keys and refuses redirects without leaking provider errors", async () => {
    const pair = await generateKeyPair("ES256"),
      now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      iss: config.issuer,
      aud: config.audience,
      sub: "stream-user",
      client_id: config.clientId,
      jti: random(),
      scope: config.scope,
      iat: now,
      exp: now + 300,
    })
      .setProtectedHeader({ alg: "ES256", kid: "stream", typ: "at+jwt" })
      .sign(pair.privateKey);
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(65536));
      },
      cancel() {
        cancelled = true;
      },
    });
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(stream));
    expect(
      await verifyIdentity(token, {
        ...config,
        jwks: "https://id-stream.test/" + random(),
      }),
    ).toBeNull();
    expect(cancelled).toBe(true);
    spy.mockResolvedValueOnce(
      new Response("private provider error", {
        status: 302,
        headers: { location: "https://attacker.test" },
      }),
    );
    expect(
      await verifyIdentity(token, {
        ...config,
        jwks: "https://id-stream.test/" + random(),
      }),
    ).toBeNull();
    expect(spy.mock.calls[1][1]).toMatchObject({ redirect: "manual" });
  });
  it("uses the real JWT route for pending enrollment and never falls back to shared-code authentication", async () => {
    const pair = await generateKeyPair("ES256"),
      jwk = await exportJWK(pair.publicKey);
    jwk.kid = "route";
    jwk.alg = "ES256";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ keys: [jwk] }),
    );
    const cfg = {
      ...config,
      issuer: "https://id-route.test",
      jwks: "https://id-route.test/jwks",
    };
    const bindings: Env = {
      ...env,
      CENTRAL_ENABLED: "1",
      CENTRAL_ORIGIN: origin,
      OIDC_ISSUER: cfg.issuer,
      OIDC_JWKS_URL: cfg.jwks,
      OIDC_API_AUDIENCE: cfg.audience,
      OIDC_NATIVE_CLIENT_ID: cfg.clientId,
    };
    const now = Math.floor(Date.now() / 1000),
      jwt = await new SignJWT({
        iss: cfg.issuer,
        aud: cfg.audience,
        sub: random(),
        client_id: cfg.clientId,
        jti: random(),
        scope: cfg.scope,
        iat: now,
        exp: now + 300,
      })
        .setProtectedHeader({ alg: "ES256", kid: "route", typ: "at+jwt" })
        .sign(pair.privateKey);
    const d = device(),
      session_id = random(16),
      session_secret = random();
    const response = await centralFetch(
      new Request(origin + "/v2/register", {
        method: "POST",
        headers: {
          authorization: "Bearer " + jwt,
          "content-type": "application/json",
          "cf-connecting-ip": random(),
        },
        body: JSON.stringify({
          device: d,
          name: "New device",
          credential: random(),
          session_id,
          session_secret,
        }),
      }),
      bindings,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ device_state: "pending" });
    const management = await centralFetch(
      new Request(origin + "/v2/device-access", {
        headers: { authorization: "Bearer " + jwt },
      }),
      bindings,
    );
    expect(management.status).toBe(200);
    const listed = (await management.json()) as any;
    expect(listed.devices[0]).toMatchObject({ id: d.id, state: "pending" });
    expect(listed.proof).toBeUndefined();
    expect(listed.wraps).toBeUndefined();
    const identity = (await verifyIdentity(jwt, cfg))!,
      bearer = `v2.${identity.locator}.${session_id}.${session_secret}`;
    expect(
      (
        await centralFetch(
          new Request(origin + "/v2/vaults/" + random() + "/wrap", {
            headers: { authorization: "Bearer " + bearer },
          }),
          bindings,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await centralFetch(
          new Request(origin + "/v2/account", {
            headers: { authorization: "Bearer " + "b".repeat(64) },
          }),
          bindings,
        )
      ).status,
    ).toBe(401);
    expect(
      (
        await centralFetch(new Request(origin + "/v2/info"), {
          ...bindings,
          CENTRAL_ENABLED: "0",
        })
      ).status,
    ).toBe(503);
  });
});

/** The private RPC is exercised here with the same real account grants as ordinary routes. */
describe("private authenticated initial migration transport", () => {
  const bindings = (): Env => ({
    ...env,
    CENTRAL_ENABLED: "1",
    CENTRAL_PRIVATE_CORE: "1",
    CENTRAL_ORIGIN: origin,
    OIDC_ISSUER: config.issuer,
    OIDC_JWKS_URL: config.jwks,
    OIDC_API_AUDIENCE: config.audience,
    OIDC_NATIVE_CLIENT_ID: config.clientId,
  });
  const registry = () =>
    env.LEGACY_RETIREMENT.idFromName(REGISTRY_WITNESS).toString();
  async function prepare() {
    const s = await setup(),
      active = await s.renew(),
      operation = random(16);
    const core = new CentralSyncBackend(createExecutionContext(), bindings());
    const request = (
      suffix: string,
      method = "GET",
      value?: unknown,
      token = active.bearer,
    ) =>
      new Request(`${origin}/v2/vaults/${s.vault}/${suffix}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "cf-connecting-ip": random(),
        },
        body: value === undefined ? undefined : JSON.stringify(value),
      });
    const call = (
      suffix: string,
      method = "GET",
      value?: unknown,
      token = active.bearer,
    ) => core.forward(1, registry(), request(suffix, method, value, token));
    const body = {
      origin,
      account_id: s.actor.account,
      genesis_hash: s.trusted.anchor.genesis_hash,
      vault_id: s.vault,
      migration_id: operation,
      authorization_epoch: String(active.actor!.epoch),
      key_epoch: "1",
      membership_head: s.trusted.head,
      author: s.first.id,
      preview_digest: random(),
      parent_chain: "",
      revision: "1",
      previous_digest: "",
      chains: [] as string[],
    };
    const intent: SignedFreeze = {
      body,
      signature: sign(freezeCanonical(body)),
    };
    const rows = [await record(s.trusted, s.vault)],
      zero = "0".repeat(64);
    const manifest: SignedMigration = {
      body: {
        origin,
        account_id: s.actor.account,
        genesis_hash: s.trusted.anchor.genesis_hash,
        vault_id: s.vault,
        migration_id: operation,
        authorization_epoch: String(active.actor!.epoch),
        key_epoch: "1",
        membership_head: s.trusted.head,
        author: s.first.id,
        inventory_digest: random(),
        target_sequence: "1",
        target_history_hash: await hash(
          canonical([
            "lunport-history-v2",
            zero,
            "1",
            await envelopeDigest(rows[0]),
          ]),
        ),
        wraps_digest: await wrapsDigest(await wraps(s.trusted, s.vault)),
        sources: [],
      },
      signature: "",
    };
    manifest.signature = sign(migrationCanonical(manifest.body));
    return {
      s,
      active,
      operation,
      core,
      call,
      request,
      intent,
      rows,
      manifest,
      targetWraps: await wraps(s.trusted, s.vault),
    };
  }
  it("requires a complete freeze journal before staging and preserves exact retries through commit and retirement", async () => {
    const t = await prepare(),
      begin = () =>
        t.call("migration/begin", "POST", {
          manifest: t.manifest,
          wraps: t.targetWraps,
        });
    expect((await begin()).status).toBe(409);
    expect((await t.call("migration", "GET")).status).toBe(404);
    expect(
      (
        await t.call("migration/freeze", "POST", {
          intent: t.intent,
          credentials: [],
        })
      ).status,
    ).toBe(200);
    const progress = await t.call("migration/freeze");
    expect(await progress.json()).toMatchObject({
      phase: "frozen",
      sources: [],
      next: [],
    });
    expect((await t.call("metadata")).status).toBe(423);
    expect((await begin()).status).toBe(200);
    expect((await begin()).status).toBe(200);
    const stage = () =>
      t.call("migration/stage", "POST", {
        migration: t.operation,
        after: "0",
        rows: t.rows,
      });
    expect((await stage()).status).toBe(200);
    expect((await stage()).status).toBe(200);
    expect(
      (await t.call("migration/commit", "POST", { migration: t.operation }))
        .status,
    ).toBe(200);
    expect(
      (await t.call("migration/commit", "POST", { migration: t.operation }))
        .status,
    ).toBe(200);
    expect(
      (await t.call("migration/retire", "POST", { migration: t.operation }))
        .status,
    ).toBe(200);
    const completed = await t.call("migration");
    expect(await completed.json()).toMatchObject({
      phase: "retired",
      staged: "1",
      manifest: t.manifest,
    });
    expect((await t.call("metadata")).status).toBe(200);
  });
  it("never admits migration through compatibility HTTP, spoofed headers or a failed same-invocation floor", async () => {
    const t = await prepare();
    for (const suffix of [
      "migration",
      "migration/freeze",
      "migration/begin",
      "migration/stage",
      "migration/commit",
      "migration/retire",
    ]) {
      const request = t.request(suffix);
      request.headers.set("x-lunport-private-ingress", "1");
      expect((await centralFetch(request, bindings())).status).toBe(404);
      expect(
        (await t.core.forward(2, registry(), t.request(suffix))).status,
      ).toBe(503);
      expect(
        (await t.core.forward(1, random(), t.request(suffix))).status,
      ).toBe(503);
    }
    const publicMode = new CentralSyncBackend(createExecutionContext(), {
      ...bindings(),
      CENTRAL_PRIVATE_CORE: "0",
    });
    expect(
      (await publicMode.forward(1, registry(), t.request("migration/freeze")))
        .status,
    ).toBe(503);
    const info = await t.core.forward(
      1,
      registry(),
      new Request(origin + "/v2/info"),
    );
    expect(
      ((await info.json()) as any).features.some((name: string) =>
        name.includes("migration"),
      ),
    ).toBe(false);
  });
  it("requires independent active device authorization and never treats an old bearer as central login", async () => {
    const t = await prepare(),
      pending = await t.s.renew(device(), random());
    expect(
      (
        await t.call(
          "migration/freeze",
          "POST",
          { intent: t.intent, credentials: [] },
          pending.bearer,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await t.call(
          "migration/freeze",
          "POST",
          { intent: t.intent, credentials: [] },
          "b".repeat(64),
        )
      ).status,
    ).toBe(401);
    const other = await setup(),
      stranger = await other.renew();
    expect(
      (
        await t.call(
          "migration/freeze",
          "POST",
          { intent: t.intent, credentials: [] },
          stranger.bearer,
        )
      ).status,
    ).toBe(403);
    expect((await t.s.account.logout(t.active.actor!)).status).toBe(204);
    expect(
      (
        await t.call("migration/freeze", "POST", {
          intent: t.intent,
          credentials: [],
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await env.VAULT.getByName(
          t.s.actor.account + ":" + t.s.vault,
        ).freezeStatus(t.s.actor)
      ).status,
    ).toBe(404);
  });
  it("rejects wrong methods, unexpected fields, credential excess and oversized streaming bodies", async () => {
    const t = await prepare();
    expect((await t.call("migration/begin")).status).toBe(405);
    expect((await t.call("migration/freeze", "DELETE")).status).toBe(405);
    expect(
      (
        await t.call("migration/freeze", "POST", {
          intent: t.intent,
          credentials: [],
          token: random(),
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await t.call("migration/freeze", "POST", {
          intent: t.intent,
          credentials: Array.from({ length: 9 }, () => ({
            chain: random(),
            token: random(),
          })),
        })
      ).status,
    ).toBe(400);
    const oversized = t.request(
      "migration/freeze",
      "POST",
      "x".repeat(4 * 1024 * 1024),
    );
    expect((await t.core.forward(1, registry(), oversized)).status).toBe(413);
    expect((await t.call("migration/freeze")).status).toBe(404);
  });
});
