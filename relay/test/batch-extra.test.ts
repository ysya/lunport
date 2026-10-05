import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

// 審查時補上的批次查詢測試:每 IP 的桶怎麼計、剛好 64 項、安全整數、每項自己的 since、延後的項目不執行、
// 凍結的 chain、刷新閒置期限。獨立成一個檔案,每 IP 的限流計數不會與 batch.test.ts 混在一起。

const TOKEN = "b".repeat(64);
const NONCE = "bm9uY2U="; // base64("nonce")
const HOUR = 60 * 60 * 1000;
const IDLE_TTL = 180 * 24 * HOUR; // 與 src/index.ts 的 IDLE_TTL_MS 相同(Worker 主模組不能 export 常數)

function newChainId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hid(n: number): string {
  return n.toString(16).padStart(64, "0");
}

/** 每個測試各用一個來源 IP:IpLimiter 的儲存在同一個檔案的測試之間不會重置。 */
let ip = "";
let ipSeq = 0;
beforeEach(() => {
  ipSeq += 1;
  ip = `203.0.113.${100 + ipSeq}`;
});

function request(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("cf-connecting-ip", ip);
  return exports.default.fetch(new Request(`https://relay.test${path}`, { ...init, headers }));
}

const auth = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };
const create = (id: string) => request(`/v1/chains/${id}`, { method: "PUT", headers: auth, body: "{}" });
const freeze = (id: string) => request(`/v1/chains/${id}/freeze`, { method: "POST", headers: auth });
const destroy = (id: string) => request(`/v1/chains/${id}`, { method: "DELETE", headers: auth });
/** 推 n 筆(idHash 1..n)。 */
const push = (id: string, n: number, ciphertext = "Y2lwaGVy") =>
  request(`/v1/chains/${id}/records`, {
    method: "POST",
    headers: auth,
    body: JSON.stringify(
      Array.from({ length: n }, (_, i) => ({ idHash: hid(i + 1), kind: "host", nonce: NONCE, ciphertext, deleted: false, baseSeq: 0 })),
    ),
  });
const batch = (items: unknown) =>
  request("/v1/pull", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(items) });
const info = () => request("/v1/info");

type Windows = Partial<Record<"create" | "request" | "pull", { start: number; count: number }>>;
const limiter = () => env.IP_LIMIT.getByName(`ip:${ip}`);
const windows = () => runInDurableObject(limiter(), async (_instance, state) => (await state.storage.get<Windows>("windows")) ?? {});

type Body = { results: { chain: string; status: string; records?: { seq: number }[]; latestSeq?: number }[] };

describe("POST /v1/pull: per-IP buckets", () => {
  it("charges the batch to the request bucket and every item to the pull bucket in one call", async () => {
    const items = [newChainId(), newChainId(), newChainId()].map((chain) => ({ chain, token: TOKEN, since: 0 }));
    expect((await batch(items)).status).toBe(200);
    const w = await windows();
    expect([w.request?.count, w.pull?.count, w.create]).toEqual([1, 3, { start: 0, count: 0 }]);
  });

  it("charges a malformed batch only to the request bucket", async () => {
    expect((await batch([])).status).toBe(400);
    expect((await request("/v1/pull", { method: "POST", body: "[" + " ".repeat(70_000) + "]" })).status).toBe(413);
    const w = await windows();
    expect([w.request?.count, w.pull]).toEqual([2, { start: 0, count: 0 }]);
  });

  it("counts a batch and an info call in the request bucket, and then refuses even malformed batches with 429", async () => {
    expect(await limiter().allow("request", 1_198)).toBe(true);
    expect((await batch([{ chain: newChainId(), token: TOKEN, since: 0 }])).status).toBe(200); // 第 1199 次
    expect((await info()).status).toBe(200); // 第 1200 次
    expect((await info()).status).toBe(429); // 第 1201 次
    // 超限時格式錯誤的批次回 429,不是 400。
    expect((await batch([])).status).toBe(429);
  });

  it("answers 429 for the whole batch once the request bucket is spent, still counting its items", async () => {
    expect(await limiter().allow("request", 1_200)).toBe(true);
    expect((await batch([{ chain: newChainId(), token: TOKEN, since: 0 }])).status).toBe(429);
    // 兩個桶在同一次呼叫裡計入:超限照計,與單筆相同。
    const w = await windows();
    expect([w.request?.count, w.pull?.count]).toEqual([1_201, 1]);
  });
});

describe("POST /v1/pull: items", () => {
  it("accepts exactly 64 items", async () => {
    const items = Array.from({ length: 64 }, () => ({ chain: newChainId(), token: TOKEN, since: 0 }));
    const res = await batch(items);
    expect(res.status).toBe(200);
    expect(((await res.json()) as Body).results).toHaveLength(64);
  });

  it("rejects a since beyond the safe integer range", async () => {
    expect((await batch([{ chain: newChainId(), token: TOKEN, since: 2 ** 53 }])).status).toBe(400);
    expect((await batch([{ chain: newChainId(), token: TOKEN, since: 2 ** 53 - 1 }])).status).toBe(200);
  });

  it("applies each item's own cursor", async () => {
    const a = newChainId();
    const b = newChainId();
    await create(a);
    await create(b);
    await push(a, 2);
    await push(b, 3);
    const body = (await (
      await batch([
        { chain: a, token: TOKEN, since: 1 },
        { chain: b, token: TOKEN, since: 2 },
      ])
    ).json()) as Body;
    expect(body.results.map((r) => r.records?.map((x) => x.seq))).toEqual([[2], [3]]);
  });

  it("does not execute deferred items", async () => {
    // 每條 chain 15 筆、每筆 65,532 字元密文:三條之後回應超過 2 MiB 預算,第四條延後。
    const big = "A".repeat(65_532);
    const chains = [newChainId(), newChainId(), newChainId()];
    for (const id of chains) {
      await create(id);
      expect((await push(id, 15, big)).status).toBe(200);
    }
    const small = newChainId();
    await create(small); // 計 1 次
    await push(small, 1); // 計 1 次
    const body = (await (await batch([...chains, small].map((chain) => ({ chain, token: TOKEN, since: 0 })))).json()) as Body;
    expect(body.results.map((r) => r.status)).toEqual(["ok", "ok", "ok", "deferred"]);
    const minuteCount = await runInDurableObject(env.CHAIN.getByName(small), async (instance) =>
      (instance as unknown as { minuteCount: number }).minuteCount,
    );
    expect(minuteCount).toBe(2); // 延後的項目沒有被執行,所以沒有多計一次
  });

  it("serves a frozen chain, also after it was deleted", async () => {
    const a = newChainId();
    await create(a);
    await push(a, 1);
    expect((await freeze(a)).status).toBe(204);
    let body = (await (await batch([{ chain: a, token: TOKEN, since: 0 }])).json()) as Body;
    expect(body.results[0].status).toBe("ok");
    expect(body.results[0].records?.map((r) => r.seq)).toEqual([1]);
    expect(body.results[0].latestSeq).toBe(1);
    // 刪除凍結的 chain 只清記錄:同一個權杖重建回 200、仍然凍結,序號不會從 1 重來。
    expect((await destroy(a)).status).toBe(204);
    expect((await create(a)).status).toBe(200);
    expect((await push(a, 1)).status).toBe(409);
    body = (await (await batch([{ chain: a, token: TOKEN, since: 0 }])).json()) as Body;
    expect(body.results[0]).toEqual({ chain: a, status: "ok", records: [], latestSeq: 1 });
  });

  it("refreshes the idle deadline of the chains it pulls once the last refresh is old", async () => {
    const a = newChainId();
    await create(a);
    const stub = env.CHAIN.getByName(a);
    // alarm 只剩一天:早已超過 6 小時的節流,批次查詢必須重設。
    await runInDurableObject(stub, (_instance, state) => state.storage.setAlarm(Date.now() + 24 * HOUR));
    expect((await batch([{ chain: a, token: TOKEN, since: 0 }])).status).toBe(200);
    const alarm = await runInDurableObject(stub, (_instance, state) => state.storage.getAlarm());
    expect(alarm! - Date.now()).toBeGreaterThan(IDLE_TTL - HOUR);
  });
});
