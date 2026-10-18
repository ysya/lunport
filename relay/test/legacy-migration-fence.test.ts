import { env, exports } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import type { LegacyMigrationScope } from "../src/legacy-retirement";

const TOKEN = "b".repeat(64),
  OTHER = "c".repeat(64);
const random = (n = 32) =>
  Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const hash = async (s: string) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
const row = (n: number) => ({
  idHash: n.toString(16).padStart(64, "0"),
  kind: "host",
  nonce: "bm9uY2U=",
  ciphertext: "Y2lwaGVy",
  deleted: false,
  baseSeq: 0,
});
let chain: string,
  scope: LegacyMigrationScope,
  tokenHash: string,
  ip = 0;
beforeEach(async () => {
  chain = random();
  tokenHash = await hash(TOKEN);
  ip++;
  scope = {
    operation: random(16),
    origin: "https://relay.test",
    account: random(),
    genesis: random(),
    vault: random(),
  };
});
function request(suffix = "", method = "GET", token = TOKEN, body?: unknown) {
  return exports.default.fetch(
    new Request(`https://relay.test/v1/chains/${chain}${suffix}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "cf-connecting-ip": `192.0.2.${ip}`,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
}
const source = () => env.CHAIN.getByName(chain);
const registry = () => env.LEGACY_RETIREMENT.getByName(chain);
const seed = async () => {
  expect((await request("", "PUT", TOKEN, {})).status).toBe(201);
  expect((await request("/records", "POST", TOKEN, [row(1)])).status).toBe(200);
};
const freeze = () => source().freezeForMigration(chain, tokenHash, scope);
const batch = () =>
  exports.default.fetch(
    new Request("https://relay.test/v1/pull", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "cf-connecting-ip": `192.0.2.${ip}`,
      },
      body: JSON.stringify([{ chain, token: TOKEN, since: 0 }]),
    }),
  );

describe("independent legacy migration fence", () => {
  it("keeps a stable ciphertext snapshot through retries, alarms and eviction", async () => {
    await seed();
    const first = await freeze();
    expect(first.status).toBe(200);
    const body = (await (await request("/records?since=0")).json()) as any;
    expect(first.snapshot).toEqual({
      latestSeq: 1,
      count: 1,
      digest: await hash(
        JSON.stringify(["lunport-legacy-snapshot-v1", chain, 1, body.records]),
      ),
    });
    expect(await freeze()).toEqual(first);
    await runInDurableObject(source(), async (instance, state) => {
      await instance.alarm();
      expect(await state.storage.getAlarm()).toBeNull();
    });
    await evictDurableObject(source());
    expect(await freeze()).toEqual(first);
    for (const [path, method, body] of [
      ["", "PUT", {}],
      ["", "DELETE", undefined],
      ["/freeze", "POST", undefined],
      ["/records", "POST", [row(2)]],
    ] as const) {
      expect((await request(path, method, TOKEN, body)).status).toBe(409);
      expect((await request(path, method, OTHER, body)).status).toBe(404);
    }
    expect(await (await request("/records?since=0")).json()).toEqual(body);
    expect(
      await runInDurableObject(registry(), (_instance, state) =>
        state.storage.getAlarm(),
      ),
    ).toBeNull();
  });

  it("cannot move a frozen source to another operation or target", async () => {
    await seed();
    const first = await freeze();
    for (const changed of [
      { operation: random(16) },
      { vault: random() },
      { genesis: random() },
      { account: random() },
      { origin: "https://other.test" },
    ]) {
      expect(
        (
          await source().freezeForMigration(chain, tokenHash, {
            ...scope,
            ...changed,
          })
        ).status,
      ).toBe(409);
      expect(
        await registry().freeze(
          chain,
          tokenHash,
          { ...scope, ...changed },
          first.snapshot!,
        ),
      ).toBe(409);
    }
    expect(
      await registry().freeze(chain, tokenHash, scope, {
        ...first.snapshot!,
        digest: random(),
      }),
    ).toBe(409);
    expect(await freeze()).toEqual(first);
  });

  it("checks the logical chain against its actual object before freezing or admitting", async () => {
    await seed();
    const other = random();
    expect(
      (await source().freezeForMigration(other, tokenHash, scope)).status,
    ).toBe(503);
    expect(await source().create(tokenHash, other)).toBe(503);
    expect(await registry().check(other, tokenHash, false)).toBe(503);
    expect((await request("/records", "POST", TOKEN, [row(2)])).status).toBe(
      200,
    );
    expect(
      (await source().freezeForMigration(chain, await hash(OTHER), scope))
        .status,
    ).toBe(404);
  });

  it("retains the local fence if the independent acknowledgement fails, then resumes the same operation", async () => {
    await seed();
    const failed = await runInDurableObject(source(), async (instance) => {
      const bindings = (instance as any).env as Env,
        original = bindings.LEGACY_RETIREMENT;
      bindings.LEGACY_RETIREMENT = {
        ...original,
        getByName: () => ({
          freeze: async () => {
            throw new Error("synthetic offline");
          },
        }),
      } as any;
      try {
        return await instance.freezeForMigration(chain, tokenHash, scope);
      } finally {
        bindings.LEGACY_RETIREMENT = original;
      }
    });
    expect(failed.status).toBe(503);
    // Registry has no entry yet, so only the durable local fence can deny these.
    expect(await registry().check(chain, tokenHash, true)).toBe(200);
    expect((await request("/records", "POST", TOKEN, [row(2)])).status).toBe(
      409,
    );
    expect((await request("", "DELETE")).status).toBe(409);
    await runInDurableObject(source(), async (instance) => {
      await instance.alarm();
    });
    await evictDurableObject(source());
    expect((await freeze()).snapshot?.latestSeq).toBe(1);
  });

  it("rechecks the local fence after an in-flight mutation's asynchronous admission", async () => {
    await seed();
    const result = await runInDurableObject(source(), async (instance) => {
      const bindings = (instance as any).env as Env,
        original = bindings.LEGACY_RETIREMENT;
      bindings.LEGACY_RETIREMENT = {
        idFromName: original.idFromName.bind(original),
        getByName: (id: string) => ({
          check: async () => {
            expect(
              (await instance.freezeForMigration(chain, tokenHash, scope))
                .status,
            ).toBe(200);
            return 200;
          },
          freeze: (...args: any[]) =>
            (original.getByName(id).freeze as any)(...args),
        }),
      } as any;
      try {
        return await instance.push(tokenHash, [row(2)], chain);
      } finally {
        bindings.LEGACY_RETIREMENT = original;
      }
    });
    expect(result.status).toBe(409);
    expect((await freeze()).snapshot?.latestSeq).toBe(1);
  });

  it("keeps the registry outside source deleteAll and never permits recreation", async () => {
    await seed();
    const first = await freeze();
    await runInDurableObject(source(), async (_instance, state) => {
      await state.storage.deleteAll();
    });
    await evictDurableObject(source());
    expect((await request("", "PUT", TOKEN, {})).status).toBe(409);
    expect((await request("", "PUT", OTHER, {})).status).toBe(404);
    expect(
      await registry().freeze(chain, tokenHash, scope, first.snapshot!),
    ).toBe(200);
    expect(await source().exists()).toBe(false);
  });

  it("denies every endpoint for synthetic retired metadata even if the source was wiped", async () => {
    await seed();
    await freeze();
    // Transition authority is not implemented yet. This fixture verifies only the read guard.
    await runInDurableObject(registry(), async (_instance, state) => {
      const fence = await state.storage.get<any>("fence");
      await state.storage.put("fence", { ...fence, phase: "retired" });
    });
    await runInDurableObject(source(), async (_instance, state) => {
      await state.storage.deleteAll();
    });
    for (const [path, method, body] of [
      ["", "PUT", {}],
      ["", "DELETE", undefined],
      ["/freeze", "POST", undefined],
      ["/records", "GET", undefined],
      ["/records", "POST", [row(2)]],
    ] as const) {
      expect((await request(path, method, TOKEN, body)).status).toBe(410);
      expect((await request(path, method, OTHER, body)).status).toBe(404);
    }
    expect(((await (await batch()).json()) as any).results[0].status).toBe(
      "retired",
    );
  });

  it("fails closed for corrupt security metadata, including batch reads", async () => {
    await seed();
    await freeze();
    await runInDurableObject(registry(), async (_instance, state) => {
      await state.storage.put("fence", { version: 999 });
    });
    const denied = await request("/records");
    expect(denied.status).toBe(503);
    expect(denied.headers.get("retry-after")).toBe("5");
    expect((await request("/records", "POST", TOKEN, [row(2)])).status).toBe(
      503,
    );
    expect(((await (await batch()).json()) as any).results[0].status).toBe(
      "unavailable",
    );
    expect((await freeze()).status).toBe(503);
  });

  it("never falls back when the registry binding is unavailable", async () => {
    await seed();
    const statuses = await runInDurableObject(source(), async (instance) => {
      const bindings = (instance as any).env as Env,
        original = bindings.LEGACY_RETIREMENT;
      bindings.LEGACY_RETIREMENT = undefined as any;
      try {
        return [
          await instance.create(tokenHash, chain),
          (await instance.push(tokenHash, [row(2)], chain)).status,
          (await instance.pull(tokenHash, 0, chain)).status,
          await instance.destroy(tokenHash, chain),
          await instance.freeze(tokenHash, chain),
        ];
      } finally {
        bindings.LEGACY_RETIREMENT = original;
      }
    });
    expect(statuses).toEqual([503, 503, 503, 503, 503]);
    expect(((await (await request("/records")).json()) as any).latestSeq).toBe(
      1,
    );
  });

  it("captures rows and the pull cursor before asynchronous idle bookkeeping", async () => {
    await seed();
    const result = await runInDurableObject(source(), async (instance) => {
      const mutable = instance as any,
        original = mutable.touch;
      let injected = false;
      mutable.touch = async (force: boolean) => {
        if (!injected) {
          injected = true;
          expect((await instance.push(tokenHash, [row(2)], chain)).status).toBe(
            200,
          );
        }
        return original.call(instance, force);
      };
      try {
        return await instance.pull(tokenHash, 0, chain);
      } finally {
        mutable.touch = original;
      }
    });
    expect(result.body?.records.map((r) => r.seq)).toEqual([1]);
    expect(result.body?.latestSeq).toBe(1);
    const next = (await (await request("/records?since=1")).json()) as any;
    expect(next.records.map((r: any) => r.seq)).toEqual([2]);
    expect(next.latestSeq).toBe(2);
  });

  it("does not advertise complete migration or expose private freeze over HTTP", async () => {
    await seed();
    expect((await request("/migration", "POST", TOKEN, scope)).status).toBe(
      404,
    );
    const info = (await (
      await exports.default.fetch(new Request("https://relay.test/v1/info"))
    ).json()) as any;
    expect(info.features).toEqual(["pull-batch", "freeze"]);
  });
});
