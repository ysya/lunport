import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { setup, random, sign } from "./helpers/migration";
import { base64, hash } from "../src/v2/protocol";
import fixture from "../../fixtures/central-source-freeze-v2.json";
import genesis from "../../fixtures/central-sync-v2.json";
import { trustGenesis } from "../src/v2/membership";
import {
  canExtendFreeze,
  verifyFreeze,
  freezeCanonical,
  freezeDigest,
  sourceOrder,
  type SignedFreeze,
} from "../src/v2/migration-freeze";
import { migrationCanonical, migrationScope } from "../src/v2/migration";
const TOKEN = "c".repeat(64);
const json = async (response: Response) => {
  expect(response.status).toBe(200);
  return (await response.json()) as any;
};
async function source() {
  const chain = random(),
    tokenHash = await hash(new TextEncoder().encode(TOKEN));
  const stub = env.CHAIN.getByName(chain);
  expect(await stub.create(tokenHash, chain)).toBe(201);
  expect(
    (
      await stub.push(
        tokenHash,
        [
          {
            idHash: random(),
            kind: "host",
            nonce: "bm9uY2U=",
            ciphertext: "Y2lwaGVy",
            deleted: false,
            baseSeq: 0,
          },
        ],
        chain,
      )
    ).status,
  ).toBe(200);
  return { chain, token: TOKEN };
}
function intent(
  s: Awaited<ReturnType<typeof setup>>,
  chains: string[],
  parent = "",
): SignedFreeze {
  const m = s.manifest.body;
  const body = {
    origin: m.origin,
    account_id: m.account_id,
    genesis_hash: m.genesis_hash,
    vault_id: m.vault_id,
    migration_id: m.migration_id,
    authorization_epoch: m.authorization_epoch,
    key_epoch: m.key_epoch,
    membership_head: m.membership_head,
    author: m.author,
    preview_digest: "8".repeat(64),
    parent_chain: parent,
    revision: "1",
    previous_digest: "",
    chains: [...chains].sort(),
  };
  return { body, signature: sign(freezeCanonical(body)) };
}
function extension(
  prior: SignedFreeze,
  digest: string,
  changed: Partial<SignedFreeze["body"]>,
): SignedFreeze {
  const body = {
    ...prior.body,
    revision: String(Number(prior.body.revision) + 1),
    previous_digest: digest,
    ...changed,
  };
  return { body, signature: sign(freezeCanonical(body)) };
}
function bind(s: Awaited<ReturnType<typeof setup>>, sources: any[]) {
  s.manifest.body.sources = sources;
  s.manifest.signature = sign(migrationCanonical(s.manifest.body));
}

describe("durable complete-source migration freeze", () => {
  it("records the security registry fence after a private core returns its snapshot", async () => {
    const s = await setup(0),
      old = await source(),
      signed = intent(s, [old.chain]),
      tokenHash = await hash(new TextEncoder().encode(TOKEN));
    const frozen = await runInDurableObject(
      env.CHAIN.getByName(old.chain),
      async (instance) => {
        const bindings = (instance as any).env as Env;
        const originalMode = bindings.CENTRAL_PRIVATE_CORE;
        const originalRegistry = bindings.LEGACY_RETIREMENT;
        bindings.CENTRAL_PRIVATE_CORE = "1";
        delete (bindings as any).LEGACY_RETIREMENT;
        try {
          return await instance.freezeForMigration(
            old.chain,
            tokenHash,
            migrationScope(signed.body),
          );
        } finally {
          bindings.CENTRAL_PRIVATE_CORE = originalMode;
          bindings.LEGACY_RETIREMENT = originalRegistry;
        }
      },
    );
    expect(frozen.status).toBe(200);
    const snapshot = frozen.snapshot!;
    expect(
      await env.LEGACY_RETIREMENT.getByName(old.chain).check(old.chain, tokenHash, true),
    ).toBe(200);
    const result = await runInDurableObject(s.child, async (instance) => {
      const bindings = (instance as any).env as Env;
      const original = bindings.CHAIN;
      bindings.CHAIN = {
        getByName: (chain: string) => ({
          freezeForMigration: async () => {
            expect(chain).toBe(old.chain);
            return frozen;
          },
        }),
      } as any;
      try {
        return await instance.freezeSources(s.actor, signed, [old]);
      } finally {
        bindings.CHAIN = original;
      }
    });
    expect(result.status).toBe(200);
    expect(
      await env.LEGACY_RETIREMENT.getByName(old.chain).confirmFrozen(
        old.chain,
        migrationScope(signed.body),
        snapshot,
      ),
    ).toBe(true);
    expect(
      await env.LEGACY_RETIREMENT.getByName(old.chain).check(old.chain, tokenHash, true),
    ).toBe(409);
  });
  it("matches the native golden signature, canonical bytes and extension chain", async () => {
    const member = (await trustGenesis(genesis.genesis, genesis.anchor))!;
    const first = fixture.first.proof[0],
      next = fixture.extended.proof[1];
    expect(base64(freezeCanonical(first.intent.body))).toBe(
      fixture.canonical_base64,
    );
    for (const step of [first, next]) {
      expect(await freezeDigest(step.intent)).toBe(step.digest);
      expect(
        await verifyFreeze(
          member,
          step.intent,
          1,
          1,
          step.intent.body.vault_id,
          step.intent.body.author,
        ),
      ).toBe(true);
    }
    expect(canExtendFreeze(first.intent, first.digest, next.intent)).toBe(true);
    expect(canExtendFreeze(next.intent, next.digest, first.intent)).toBe(false);
    expect(sourceOrder(next.intent.body)).toEqual([
      "3".repeat(64),
      "1".repeat(64),
      "2".repeat(64),
    ]);
  });

  it("freezes the parent first in bounded resumable batches without persisting old bearers", async () => {
    const s = await setup(0),
      all = await Promise.all(Array.from({ length: 10 }, source));
    const parent = [...all]
      .sort((a, b) => a.chain.localeCompare(b.chain))
      .at(-1)!.chain;
    const signed = intent(
        s,
        all.map((v) => v.chain),
        parent,
      ),
      order = sourceOrder(signed.body);
    const credentials = order.map((chain) =>
      all.find((v) => v.chain === chain)!,
    );
    expect(
      (await s.child.freezeSources(s.actor, signed, [credentials[1]])).status,
    ).toBe(400);
    expect((await s.child.freezeStatus(s.actor)).status).toBe(404);
    const started = await json(
      await s.child.freezeSources(s.actor, signed, []),
    );
    expect(started.next[0]).toBe(parent);
    for (const response of [
      await s.child.metadata(s.actor),
      await s.child.pull(s.actor, 0),
      await s.child.wrap(s.actor),
      await s.child.push(s.actor, [s.records[0]]),
    ]) {
      expect(response.status).toBe(423);
      await response.body?.cancel();
    }
    expect(
      (await s.child.freezeSources(s.actor, signed, credentials.slice(0, 9)))
        .status,
    ).toBe(400);
    const partial = await json(
      await s.child.freezeSources(s.actor, signed, credentials.slice(0, 8)),
    );
    expect(partial.phase).toBe("freezing");
    expect(partial.sources).toHaveLength(8);
    expect(partial.next).toEqual(order.slice(8));
    expect(
      await json(
        await s.child.freezeSources(s.actor, signed, credentials.slice(0, 8)),
      ),
    ).toEqual(partial);
    expect(
      (
        await s.child.freezeSources(s.actor, signed, [
          { ...credentials[8], token: "d".repeat(64) },
        ])
      ).status,
    ).toBe(404);
    expect(
      (await json(await s.child.freezeStatus(s.actor))).sources,
    ).toHaveLength(8);
    const finished = await json(
      await s.child.freezeSources(s.actor, signed, credentials.slice(8)),
    );
    expect(finished.phase).toBe("frozen");
    expect(finished.sources).toHaveLength(10);
    const stored = await runInDurableObject(
      s.child,
      (_instance, ctx) =>
        ctx.storage.sql
          .exec<{ value: string }>("SELECT value FROM migration_freeze")
          .one().value,
    );
    expect(stored.includes(TOKEN) || stored.includes('"token"')).toBe(false);
    bind(s, finished.sources);
    await json(await s.child.beginMigration(s.actor, s.manifest));
    expect((await s.child.freezeSources(s.actor, signed, [])).status).toBe(409);
    await json(
      await s.child.stageMigration(s.actor, s.operation, "0", s.records),
    );
    await json(await s.child.commitMigration(s.actor, s.operation));
    expect(
      (await json(await s.child.retireMigration(s.actor, s.operation))).retired,
    ).toBe("8");
    expect(
      (await json(await s.child.retireMigration(s.actor, s.operation))).phase,
    ).toBe("retired");
    expect((await s.child.metadata(s.actor)).status).toBe(200);
    for (const value of all)
      expect(
        await env.LEGACY_RETIREMENT.getByName(value.chain).check(
          value.chain,
          await hash(new TextEncoder().encode(TOKEN)),
          false,
        ),
      ).toBe(410);
  });

  it("can add a newly discovered child but never omit known sources or replay an older intent", async () => {
    const s = await setup(0),
      parent = await source(),
      child = await source();
    const first = intent(s, [parent.chain], parent.chain);
    const frozen = await json(
      await s.child.freezeSources(s.actor, first, [parent]),
    );
    expect(frozen.phase).toBe("frozen");
    const expanded = extension(first, frozen.proof.at(-1).digest, {
      chains: [parent.chain, child.chain].sort(),
    });
    const pending = await json(
      await s.child.freezeSources(s.actor, expanded, []),
    );
    expect(pending.phase).toBe("freezing");
    expect(pending.next).toEqual([child.chain]);
    expect((await s.child.freezeSources(s.actor, first, [])).status).toBe(409);
    for (const changed of [
      { chains: [parent.chain] },
      { parent_chain: child.chain },
      { preview_digest: random() },
      { previous_digest: random() },
      { revision: "4" },
    ]) {
      const bad = extension(expanded, pending.proof.at(-1).digest, changed);
      expect((await s.child.freezeSources(s.actor, bad, [])).status).toBe(409);
    }
    bind(s, frozen.sources);
    expect((await s.child.beginMigration(s.actor, s.manifest)).status).toBe(
      409,
    );
    const finished = await json(
      await s.child.freezeSources(s.actor, expanded, [child]),
    );
    expect(finished.sources).toHaveLength(2);
    expect(finished.proof).toHaveLength(2);
    bind(s, finished.sources);
    await json(await s.child.beginMigration(s.actor, s.manifest));
  });

  it("keeps a successful source fence if authorization changes before progress acknowledgement", async () => {
    const s = await setup(0),
      parent = await source(),
      child = await source();
    const signed = intent(s, [parent.chain, child.chain], parent.chain),
      seen: string[] = [];
    const code = await runInDurableObject(s.child, async (instance, ctx) => {
      const bindings = (instance as any).env as Env,
        original = bindings.CHAIN;
      bindings.CHAIN = {
        idFromName: original.idFromName.bind(original),
        getByName: (chain: string) => ({
          freezeForMigration: async (...args: any[]) => {
            seen.push(chain);
            const response = await (
              original.getByName(chain).freezeForMigration as any
            )(...args);
            const state = JSON.parse(
              ctx.storage.sql
                .exec<{ value: string }>("SELECT value FROM vault_state")
                .one().value,
            );
            state.epoch = 2;
            state.version++;
            ctx.storage.sql.exec(
              "UPDATE vault_state SET value=?",
              JSON.stringify(state),
            );
            return response;
          },
        }),
      } as any;
      try {
        return (await instance.freezeSources(s.actor, signed, [parent, child]))
          .status;
      } finally {
        bindings.CHAIN = original;
      }
    });
    expect(code).toBe(403);
    expect(seen).toEqual([parent.chain]);
    expect(
      await env.LEGACY_RETIREMENT.getByName(parent.chain).confirmFrozen(
        parent.chain,
        migrationScope(signed.body),
        (
          await env.CHAIN.getByName(parent.chain).freezeForMigration(
            parent.chain,
            await hash(new TextEncoder().encode(TOKEN)),
            migrationScope(signed.body),
          )
        ).snapshot!,
      ),
    ).toBe(true);
    const fresh = { ...s.actor, epoch: 2 };
    const status = await json(await s.child.freezeStatus(fresh));
    expect(status.sources).toEqual([]);
    const resumed = extension(signed, status.proof.at(-1).digest, {
      authorization_epoch: "2",
    });
    const finished = await json(
      await s.child.freezeSources(fresh, resumed, [parent, child]),
    );
    expect(finished.phase).toBe("frozen");
    expect(finished.sources).toHaveLength(2);
  });

  it("awaits validation of every retained signature and refuses corrupt proof even with a matching digest", async () => {
    const s = await setup(0),
      old = await source(),
      signed = intent(s, [old.chain]);
    await json(await s.child.freezeSources(s.actor, signed, []));
    await runInDurableObject(s.child, async (_instance, ctx) => {
      const j = JSON.parse(
        ctx.storage.sql
          .exec<{ value: string }>("SELECT value FROM migration_freeze")
          .one().value,
      );
      const bytes = Uint8Array.from(
        atob(j.proof[0].intent.signature),
        (c: string) => c.charCodeAt(0),
      );
      bytes[0] ^= 1;
      j.proof[0].intent.signature = btoa(String.fromCharCode(...bytes));
      j.proof[0].digest = await freezeDigest(j.proof[0].intent);
      ctx.storage.sql.exec(
        "UPDATE migration_freeze SET value=?",
        JSON.stringify(j),
      );
    });
    expect((await s.child.freezeStatus(s.actor)).status).toBe(503);
    expect((await s.child.freezeSources(s.actor, signed, [old])).status).toBe(
      503,
    );
    expect(
      await env.LEGACY_RETIREMENT.getByName(old.chain).check(
        old.chain,
        await hash(new TextEncoder().encode(TOKEN)),
        true,
      ),
    ).toBe(200);
  });

  it("rejects wrong signatures, counters, roots and extra credential data before source side effects", async () => {
    const s = await setup(0),
      old = await source(),
      signed = intent(s, [old.chain]);
    for (const changed of [
      { account_id: random() },
      { genesis_hash: random() },
      { vault_id: random() },
      { membership_head: random() },
      { author: random(16) },
      { authorization_epoch: "2" },
      { key_epoch: "2" },
    ]) {
      const body = { ...signed.body, ...changed },
        altered = { body, signature: sign(freezeCanonical(body)) };
      expect(
        (await s.child.freezeSources(s.actor, altered, [old])).status,
      ).toBe(403);
    }
    expect(
      (await s.child.freezeSources({ ...s.actor, expires: 0 }, signed, [old]))
        .status,
    ).toBe(403);
    expect(
      (
        await s.child.freezeSources(s.actor, signed, [
          { ...old, secret: "synthetic" } as any,
        ])
      ).status,
    ).toBe(400);
    expect((await s.child.freezeStatus(s.actor)).status).toBe(404);
    expect((await s.child.metadata(s.actor)).status).toBe(200);
    for (const body of [
      { ...signed.body, chains: [old.chain, old.chain] },
      { ...signed.body, chains: Array(66).fill(old.chain) },
      { ...signed.body, revision: "66", previous_digest: random() },
      { ...signed.body, parent_chain: random() },
      { ...signed.body, preview_digest: "not-a-commitment" },
    ])
      expect(() => freezeCanonical(body)).toThrow();
  });

  it("binds an empty source set without inventing a bearer or reopening the normal target", async () => {
    const s = await setup(0),
      signed = intent(s, []);
    expect(
      (await json(await s.child.freezeSources(s.actor, signed, []))).phase,
    ).toBe("frozen");
    await json(await s.child.beginMigration(s.actor, s.manifest));
    await json(
      await s.child.stageMigration(s.actor, s.operation, "0", s.records),
    );
    expect(
      (await json(await s.child.commitMigration(s.actor, s.operation))).phase,
    ).toBe("retired");
  });
});
