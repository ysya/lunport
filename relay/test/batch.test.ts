import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import pkg from "../package.json";

const TOKEN = "b".repeat(64);
const OTHER_TOKEN = "c".repeat(64);
const NONCE = "bm9uY2U="; // base64("nonce")

function newChainId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hid(n: number): string {
  return n.toString(16).padStart(64, "0");
}

function request(path: string, init: RequestInit = {}, ip = "203.0.113.20") {
  const headers = new Headers(init.headers);
  headers.set("cf-connecting-ip", ip);
  return exports.default.fetch(new Request(`https://relay.test${path}`, { ...init, headers }));
}

const create = (id: string, token = TOKEN) =>
  request(`/v1/chains/${id}`, { method: "PUT", headers: { authorization: `Bearer ${token}` }, body: "{}" });
const push = (id: string, items: unknown[], token = TOKEN) =>
  request(`/v1/chains/${id}/records`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(items),
  });
const pull = (id: string, since = 0, token = TOKEN) =>
  request(`/v1/chains/${id}/records?since=${since}`, { headers: { authorization: `Bearer ${token}` } });
const batch = (items: unknown, ip?: string) =>
  request("/v1/pull", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(items) }, ip);

function record(n: number, ciphertext = "Y2lwaGVy") {
  return { idHash: hid(n), kind: "host", nonce: NONCE, ciphertext, deleted: false, baseSeq: 0 };
}

type Entry = { chain: string; status: string; records?: Array<{ idHash: string; seq: number }>; latestSeq?: number };
type BatchBody = { results: Entry[] };

describe("POST /v1/pull", () => {
  it("returns every chain's records in request order", async () => {
    const a = newChainId();
    const b = newChainId();
    await create(a);
    await create(b);
    await push(a, [record(1)]);
    await push(b, [record(2), record(3)]);
    const res = await batch([
      { chain: b, token: TOKEN, since: 0 },
      { chain: a, token: TOKEN, since: 0 },
    ]);
    expect(res.status).toBe(200);
    const body = (await res.json()) as BatchBody;
    expect(body.results.map((r) => [r.chain, r.status, r.latestSeq])).toEqual([
      [b, "ok", 2],
      [a, "ok", 1],
    ]);
    expect(body.results[0].records?.map((r) => r.idHash)).toEqual([hid(2), hid(3)]);
    expect(body.results[1].records?.map((r) => r.idHash)).toEqual([hid(1)]);
  });

  it("pulls each chain since its own cursor", async () => {
    const a = newChainId();
    await create(a);
    await push(a, [record(1), record(2)]);
    const body = (await (await batch([{ chain: a, token: TOKEN, since: 1 }])).json()) as BatchBody;
    expect(body.results[0].records?.map((r) => r.seq)).toEqual([2]);
    expect(body.results[0].latestSeq).toBe(2);
  });

  it("answers not_found for unknown chains and wrong tokens without allocating storage", async () => {
    const known = newChainId();
    const unknown = newChainId();
    await create(known);
    const body = (await (
      await batch([
        { chain: known, token: OTHER_TOKEN, since: 0 },
        { chain: unknown, token: TOKEN, since: 0 },
      ])
    ).json()) as BatchBody;
    expect(body.results).toEqual([
      { chain: known, status: "not_found" },
      { chain: unknown, status: "not_found" },
    ]);
    expect(await env.CHAIN.getByName(unknown).exists()).toBe(false);
  });

  it("reports a chain's own rate limit per item and still serves the others", async () => {
    const busy = newChainId();
    const calm = newChainId();
    await create(busy); // 第 1 次
    await create(calm);
    for (let i = 0; i < 119; i++) {
      expect((await pull(busy)).status).toBe(200); // 第 2..120 次
    }
    const body = (await (
      await batch([
        { chain: busy, token: TOKEN, since: 0 },
        { chain: calm, token: TOKEN, since: 0 },
      ])
    ).json()) as BatchBody;
    expect(body.results.map((r) => r.status)).toEqual(["rate_limited", "ok"]);
  });

  it("rejects malformed batches", async () => {
    const a = newChainId();
    const ok = { chain: a, token: TOKEN, since: 0 };
    expect((await batch({ chain: a })).status).toBe(400);
    expect((await batch([])).status).toBe(400);
    expect((await batch(Array.from({ length: 65 }, () => ({ ...ok, chain: newChainId() })))).status).toBe(400);
    expect((await batch([{ ...ok, chain: a.toUpperCase() }])).status).toBe(400);
    expect((await batch([{ ...ok, token: TOKEN.toUpperCase() }])).status).toBe(400);
    expect((await batch([{ ...ok, since: -1 }])).status).toBe(400);
    expect((await batch([{ ...ok, since: 1.5 }])).status).toBe(400);
    expect((await batch([ok, ok])).status).toBe(400);
    expect((await request("/v1/pull", { method: "POST", body: "not json" })).status).toBe(400);
    expect((await request("/v1/pull", { method: "POST", body: "[" + " ".repeat(70_000) + "]" })).status).toBe(413);
    expect((await request("/v1/pull")).status).toBe(404);
  });

  it("defers the remaining items once the response passes the 2 MiB budget", async () => {
    // 每條 chain 15 筆、每筆 65,532 字元密文:約 0.98 MB,低於每 chain 1 MiB 的額度。
    const big = "A".repeat(65_532);
    const chains = [newChainId(), newChainId(), newChainId()];
    for (const id of chains) {
      await create(id);
      expect((await push(id, Array.from({ length: 15 }, (_, i) => record(i + 1, big)))).status).toBe(200);
    }
    const small = newChainId();
    await create(small);
    await push(small, [record(1)]);
    const body = (await (
      await batch([...chains, small].map((chain) => ({ chain, token: TOKEN, since: 0 })))
    ).json()) as BatchBody;
    // 前兩條後累計約 1.97 MB(< 2 MiB)所以第三條照做;做完超過預算,第四條延後。
    expect(body.results.map((r) => r.status)).toEqual(["ok", "ok", "ok", "deferred"]);
    expect(body.results[3]).toEqual({ chain: small, status: "deferred" });
  });

  it("charges the pull bucket per item and refuses the whole batch when it runs out", async () => {
    const ip = "198.51.100.77";
    const a = newChainId();
    const b = newChainId();
    await create(a);
    await create(b);
    const limiter = env.IP_LIMIT.getByName(`ip:${ip}`);
    expect(await limiter.allow("pull", 11_999)).toBe(true);
    const items = [
      { chain: a, token: TOKEN, since: 0 },
      { chain: b, token: TOKEN, since: 0 },
    ];
    expect((await batch(items, ip)).status).toBe(429);
    expect((await batch(items, "198.51.100.78")).status).toBe(200);
  });
});

describe("GET /v1/info", () => {
  it("reports the relay version and its features", async () => {
    const res = await request("/v1/info");
    expect(res.status).toBe(200);
    // 版本常數不能從 Worker 主模組 export(workerd 只收 class 與 handler),所以直接比對 package.json。
    expect(await res.json()).toEqual({ relay: "sshelter-relay", version: pkg.version, features: ["pull-batch", "freeze"] });
    expect((await request("/v1/info", { method: "POST" })).status).toBe(404);
  });
});
