import { AUTHORITY_HEADER, authorityWitness } from "../src/security/authority";
import { env, exports } from "cloudflare:workers";
import {
  createExecutionContext,
  evictDurableObject,
  runInDurableObject,
} from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import gateway, { type GatewayEnv } from "../src/security/gateway";
import { REGISTRY_WITNESS } from "../src/security/floor";
import { CentralSyncBackend } from "../src/index";
const random = (n = 32) =>
  Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const origin = "https://relay.test",
  token = "b".repeat(64);
const hash = async (s: string) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
let installation: string,
  ip = 0;
beforeEach(() => {
  installation = random(16);
  ip++;
});
const floor = () => env.SECURITY_FLOOR.getByName("floor:" + installation);
const identity = () =>
  env.LEGACY_RETIREMENT.idFromName(REGISTRY_WITNESS).toString();
const provision = (minimum = 2) =>
  floor().provision(installation, minimum, identity());
function configuration(core?: GatewayEnv["CORE"]): GatewayEnv {
  return {
    ...env,
    CORE: core ?? exports.CentralSyncBackend,
    SECURITY_INSTALLATION: installation,
    CENTRAL_ORIGIN: origin,
  };
}
function request(
  path = "/v1/info",
  method = "GET",
  body?: string | ReadableStream<Uint8Array>,
) {
  return new Request(origin + path, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      [AUTHORITY_HEADER]: authorityWitness(env),
      "cf-connecting-ip": `198.51.100.${ip}`,
      "content-type": "application/json",
    },
    body,
  });
}
const accepting = (calls: number[]) =>
  ({
    forward: async (minimum: number) => {
      calls.push(minimum);
      return new Response(null, { status: 204 });
    },
  }) as unknown as GatewayEnv["CORE"];
async function frozenSource() {
  const chain = random(),
    scope = {
      operation: random(16),
      origin,
      account: random(),
      genesis: random(),
      vault: random(),
    },
    snapshot = { latestSeq: 1, count: 1, digest: random() };
  expect(
    await env.LEGACY_RETIREMENT.getByName(chain).freeze(
      chain,
      await hash(token),
      scope,
      snapshot,
    ),
  ).toBe(200);
  return chain;
}

describe("independent ingress and persistent backend floor", () => {
  it("requires explicit provisioning and never traffic-creates a floor", async () => {
    const calls: number[] = [];
    expect((await floor().authorize(installation)).status).toBe(503);
    expect(
      (await gateway.fetch(request(), configuration(accepting(calls)))).status,
    ).toBe(503);
    expect(calls).toEqual([]);
    expect(
      await runInDurableObject(floor(), (_instance, state) =>
        state.storage.get("floor"),
      ),
    ).toBeUndefined();
    expect((await provision()).status).toBe(200);
    expect(
      (await gateway.fetch(request(), configuration(accepting(calls)))).status,
    ).toBe(204);
    expect(calls).toEqual([2]);
    expect(
      (
        await gateway.fetch(
          request("/v1/provision", "POST", "{}"),
          configuration(accepting(calls)),
        )
      ).status,
    ).toBe(404);
    expect(calls).toEqual([2]);
  });

  it("never lowers its floor when an older gateway or deployment returns", async () => {
    await provision();
    expect(await floor().authorize(installation, 3)).toEqual({
      status: 200,
      minimum: 3,
      registry: identity(),
      authority: authorityWitness(env),
    });
    expect((await provision(2)).status).toBe(409);
    await evictDurableObject(floor());
    expect(await floor().authorize(installation, 1)).toEqual({
      status: 200,
      minimum: 3,
      registry: identity(),
      authority: authorityWitness(env),
    });
    const calls: number[] = [];
    expect(
      (await gateway.fetch(request(), configuration(accepting(calls)))).status,
    ).toBe(204);
    expect(calls).toEqual([3]);
    expect(
      await runInDurableObject(floor(), (_instance, state) =>
        state.storage.getAlarm(),
      ),
    ).toBeNull();
    expect((await floor().provision(random(16), 3, identity())).status).toBe(
      503,
    );
  });

  it("rejects a replacement registry namespace and corrupt or missing floor state", async () => {
    await provision();
    const changed = await runInDurableObject(floor(), async (instance) => {
      const bindings = (instance as any).env,
        original = bindings.LEGACY_RETIREMENT;
      bindings.LEGACY_RETIREMENT = env.CHAIN;
      try {
        return (await instance.authorize(installation)).status;
      } finally {
        bindings.LEGACY_RETIREMENT = original;
      }
    });
    expect(changed).toBe(503);
    expect((await floor().provision(installation, 1, random())).status).toBe(
      503,
    );
    await runInDurableObject(floor(), async (_instance, state) => {
      await state.storage.put("floor", { version: 999 });
    });
    expect((await floor().authorize(installation)).status).toBe(503);
    expect((await provision()).status).toBe(503);
    const calls: number[] = [];
    expect(
      (await gateway.fetch(request(), configuration(accepting(calls)))).status,
    ).toBe(503);
    expect(calls).toEqual([]);
  });

  it("keeps old unbound floors unavailable until a scoped private authority handoff", async () => {
    await runInDurableObject(floor(), (_instance, state) =>
      state.storage.put("floor", {
        version: 1,
        installation,
        minimum: 1,
        registry: identity(),
      }),
    );
    expect((await floor().authorize(installation)).status).toBe(503);
    expect((await provision()).status).toBe(409);
    expect(await floor().inspect(installation)).toMatchObject({
      present: true,
      status: 503,
      minimum: 1,
      pinned: false,
    });
    const receipt = random();
    expect(
      (
        await floor().bindAuthority(
          installation,
          2,
          identity(),
          "wrong",
          receipt,
        )
      ).status,
    ).toBe(503);
    expect(
      (
        await floor().bindAuthority(
          installation,
          2,
          identity(),
          authorityWitness(env),
          receipt,
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await floor().bindAuthority(
          installation,
          2,
          identity(),
          authorityWitness(env),
          receipt,
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await floor().bindAuthority(
          installation,
          2,
          identity(),
          authorityWitness(env),
          random(),
        )
      ).status,
    ).toBe(409);
    await evictDurableObject(floor());
    expect(await floor().authorize(installation)).toMatchObject({
      status: 200,
      minimum: 2,
      authority: authorityWitness(env),
    });
  });
  it("rejects replacement central namespaces without rewriting the authority pin", async () => {
    await provision();
    for (const role of ["ACCOUNT", "VAULT", "PASSKEY"] as const) {
      const code = await runInDurableObject(floor(), async (instance) => {
        const bindings = (instance as any).env,
          original = bindings[role];
        bindings[role] = env.CHAIN;
        try {
          return (await instance.authorize(installation)).status;
        } finally {
          bindings[role] = original;
        }
      });
      expect(code).toBe(503);
    }
    expect((await floor().authorize(installation)).status).toBe(200);
  });
  it("replaces client-supplied authority headers with the pinned witness", async () => {
    await provision();
    const incoming = request();
    incoming.headers.set(AUTHORITY_HEADER, "spoofed");
    const core = {
      forward: async (
        minimum: number,
        registry: string,
        forwarded: Request,
      ) => {
        expect(minimum).toBe(2);
        expect(registry).toBe(identity());
        expect(forwarded.headers.get(AUTHORITY_HEADER)).toBe(
          authorityWitness(env),
        );
        return new Response(null, { status: 204 });
      },
    } as unknown as GatewayEnv["CORE"];
    expect((await gateway.fetch(incoming, configuration(core))).status).toBe(
      204,
    );
  });

  it("independently prevents frozen writes and retired reads even when a backend would accept", async () => {
    await provision();
    const chain = await frozenSource(),
      calls: number[] = [],
      configured = configuration(accepting(calls));
    for (const [suffix, method, body] of [
      ["", "PUT", "{}"],
      ["", "DELETE", undefined],
      ["/freeze", "POST", undefined],
      ["/records", "POST", "[]"],
    ] as const)
      expect(
        (
          await gateway.fetch(
            request(`/v1/chains/${chain}${suffix}`, method, body),
            configured,
          )
        ).status,
      ).toBe(409);
    expect(calls).toEqual([]);
    expect(
      (await gateway.fetch(request(`/v1/chains/${chain}/records`), configured))
        .status,
    ).toBe(204);
    expect(calls).toEqual([2]);
    await runInDurableObject(
      env.LEGACY_RETIREMENT.getByName(chain),
      async (_instance, state) => {
        const value = await state.storage.get<any>("fence");
        await state.storage.put("fence", { ...value, phase: "retired" });
      },
    );
    expect(
      (await gateway.fetch(request(`/v1/chains/${chain}/records`), configured))
        .status,
    ).toBe(410);
    expect(
      (
        await gateway.fetch(
          request(
            "/v1/pull",
            "POST",
            JSON.stringify([{ chain, token, since: 0 }]),
          ),
          configured,
        )
      ).status,
    ).toBe(410);
    expect(calls).toEqual([2]);
  });

  it("fails closed without the named private backend RPC and never falls back to fetch", async () => {
    await provision();
    const calls: number[] = [];
    const old = {
      fetch: async () => {
        calls.push(99);
        return new Response(null, { status: 204 });
      },
    } as unknown as GatewayEnv["CORE"];
    expect((await gateway.fetch(request(), configuration(old))).status).toBe(
      503,
    );
    expect(calls).toEqual([]);
    expect(
      (await exports.CentralSyncBackend.forward(1, identity(), request()))
        .status,
    ).toBe(503); // public compatibility mode cannot claim a private backend
  });

  it("checks floor and registry in the same backend invocation before any route", async () => {
    const core = new CentralSyncBackend(createExecutionContext(), {
      ...env,
      CENTRAL_PRIVATE_CORE: "1",
    });
    const chain = random(),
      create = () => request(`/v1/chains/${chain}`, "PUT", "{}");
    expect((await core.forward(3, identity(), create())).status).toBe(503);
    expect((await core.forward(0, identity(), create())).status).toBe(503);
    expect((await core.forward(2, random(), create())).status).toBe(503);
    expect(await env.CHAIN.getByName(chain).exists()).toBe(false);
    const wrong = create();
    wrong.headers.set(AUTHORITY_HEADER, "0".repeat(64));
    expect((await core.forward(2, identity(), wrong)).status).toBe(503);
    expect((await core.forward(1, identity(), create())).status).toBe(503);
    const accepted = await core.forward(2, identity(), create());
    expect(accepted.status).toBe(201);
    await accepted.body?.cancel();
    expect(await env.CHAIN.getByName(chain).exists()).toBe(true);
  });

  it("disables default HTTP in private mode while preserving the checked named RPC", async () => {
    const compatibility = await exports.default.fetch(request());
    expect(compatibility.status).toBe(200);
    await compatibility.body?.cancel();
    const original = env.CENTRAL_PRIVATE_CORE;
    env.CENTRAL_PRIVATE_CORE = "1";
    try {
      expect((await exports.default.fetch(request())).status).toBe(404);
    } finally {
      if (original === undefined) delete env.CENTRAL_PRIVATE_CORE;
      else env.CENTRAL_PRIVATE_CORE = original;
    }
  });

  it("rejects wrong origins, malformed batches and streaming oversized bodies", async () => {
    await provision();
    const calls: number[] = [],
      configured = configuration(accepting(calls));
    expect(
      (
        await gateway.fetch(
          new Request("https://other.test/v1/info"),
          configured,
        )
      ).status,
    ).toBe(421);
    expect(
      (await gateway.fetch(request("/v1/pull", "POST", "[{}]"), configured))
        .status,
    ).toBe(400);
    const chain = random(),
      item = { chain, token, since: 0 };
    expect(
      (
        await gateway.fetch(
          request("/v1/pull", "POST", JSON.stringify([item, item])),
          configured,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await gateway.fetch(
          request("/v1/pull", "POST", JSON.stringify([{ ...item, since: -1 }])),
          configured,
        )
      ).status,
    ).toBe(400);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(65537));
        controller.close();
      },
    });
    expect(
      (await gateway.fetch(request("/v1/pull", "POST", stream), configured))
        .status,
    ).toBe(413);
    expect(calls).toEqual([]);
  });

  it("rate limits before querying missing security metadata", async () => {
    const configured = configuration(accepting([]));
    let allowedCalls = 0;
    const limiter = {
      allowMany: async () => {
        allowedCalls++;
        return false;
      },
    };
    configured.IP_LIMIT = { getByName: () => limiter } as any;
    configured.SECURITY_FLOOR = {
      getByName: () => {
        throw new Error("must not be queried after rate denial");
      },
    } as any;
    expect((await gateway.fetch(request(), configured)).status).toBe(429);
    expect(allowedCalls).toBe(1);
  });
});
