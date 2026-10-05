import { env, exports } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

const TOKEN = "b".repeat(64);
const OTHER_TOKEN = "c".repeat(64);
const base = "https://relay.test";
const SMALL = "YQ=="; // base64("a"),4 字元
const NONCE = "bm9uY2U="; // base64("nonce"),8 字元
const HOUR = 60 * 60 * 1000;
const IDLE_TTL = 180 * 24 * HOUR; // 與 src/index.ts 的 IDLE_TTL_MS 相同(Worker 主模組不能 export 常數)

/** 64-hex chain id,每個測試一條新 chain。 */
function newChainId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** 64-hex idHash fixture:必須通過 Worker 自己的格式驗證。 */
function hid(n: number): string {
  return n.toString(16).padStart(64, "0");
}

/**
 * 每個測試各用一個來源 IP。IpLimiter 的 Durable Object 儲存不會在測試之間重置,
 * 共用同一個 IP 會讓「每 IP 每小時 20 次建鏈」被整個檔案的測試耗盡,之後的 PUT 就一律 429。
 */
let ip = "";
let ipSeq = 0;

function auth(token = TOKEN): HeadersInit {
  return { authorization: `Bearer ${token}`, "content-type": "application/json", "cf-connecting-ip": ip };
}

function relay(path: string, init?: RequestInit) {
  return exports.default.fetch(new Request(`${base}${path}`, init));
}

function item(idHash: string, baseSeq = 0, ciphertext = "Y2lwaGVy", deleted = false) {
  return { idHash, kind: "host", nonce: NONCE, ciphertext, deleted, baseSeq };
}

let chain = "";
beforeEach(() => {
  chain = newChainId();
  ipSeq += 1;
  ip = `203.0.113.${ipSeq}`;
});

const create = (token = TOKEN, id = chain) => relay(`/v1/chains/${id}`, { method: "PUT", headers: auth(token), body: "{}" });
const push = (items: unknown, token = TOKEN, id = chain) =>
  relay(`/v1/chains/${id}/records`, { method: "POST", headers: auth(token), body: JSON.stringify(items) });
const pull = (since: string | number, token = TOKEN, id = chain) => relay(`/v1/chains/${id}/records?since=${since}`, { headers: auth(token) });
const destroy = (token = TOKEN, id = chain) => relay(`/v1/chains/${id}`, { method: "DELETE", headers: auth(token) });
const freeze = (token = TOKEN, id = chain) => relay(`/v1/chains/${id}/freeze`, { method: "POST", headers: auth(token) });

type PushBody = { results: { status: string; seq?: number; current?: { seq: number; ciphertext: string; deleted: boolean } }[]; latestSeq: number };
type PullBody = { records: { idHash: string; seq: number; ciphertext: string; deleted: boolean }[]; latestSeq: number };

describe("chain lifecycle", () => {
  it("creates once, then reports existing for the same token", async () => {
    expect((await create()).status).toBe(201);
    expect((await create()).status).toBe(200);
  });

  it("hides the chain from a different token and leaves its data alone", async () => {
    await create();
    await push([item(hid(1))]);
    expect((await create(OTHER_TOKEN)).status).toBe(404);
    expect((await pull(0, OTHER_TOKEN)).status).toBe(404);
    expect((await push([item(hid(2))], OTHER_TOKEN)).status).toBe(404);
    expect((await destroy(OTHER_TOKEN)).status).toBe(404);
    const mine = (await (await pull(0)).json()) as PullBody;
    expect(mine.records.map((r) => r.idHash)).toEqual([hid(1)]);
  });

  it("rejects missing or malformed auth, unknown chains and bad ids", async () => {
    expect((await relay(`/v1/chains/${chain}/records?since=0`)).status).toBe(404);
    expect((await relay(`/v1/chains/${chain}/records?since=0`, { headers: { authorization: "Bearer not-hex" } })).status).toBe(404);
    expect((await pull(0, TOKEN, newChainId())).status).toBe(404);
    expect((await pull(0, TOKEN, "not-hex")).status).toBe(400);
    expect((await relay("/v2/nope", { headers: auth() })).status).toBe(404);
  });

  it("does not allocate storage for chains that were never created", async () => {
    const id = newChainId();
    expect((await pull(0, TOKEN, id)).status).toBe(404);
    expect((await push([item(hid(1))], TOKEN, id)).status).toBe(404);
    expect((await destroy(TOKEN, id)).status).toBe(404);
    // 讀過三次,DO 仍然沒有 schema(沒寫任何東西 → 關閉後就不存在)。
    expect(await env.CHAIN.getByName(id).exists()).toBe(false);
    expect((await create(TOKEN, id)).status).toBe(201);
    expect(await env.CHAIN.getByName(id).exists()).toBe(true);
  });

  it("deletes everything and lets the same instance be created again", async () => {
    await create();
    await push([item(hid(1))]);
    expect((await destroy()).status).toBe(204);
    // 同一個 DO instance(同名)之後的請求不可變成 missing-table 500。
    expect((await pull(0)).status).toBe(404);
    expect(await env.CHAIN.getByName(chain).exists()).toBe(false);
    expect((await create()).status).toBe(201);
    const r = (await (await push([item(hid(2))])).json()) as PushBody;
    expect(r.results[0]).toEqual({ status: "ok", seq: 1 });
    const all = (await (await pull(0)).json()) as PullBody;
    expect(all.records.map((x) => x.idHash)).toEqual([hid(2)]);
  });
});

describe("records", () => {
  it("assigns increasing seqs and pulls since a cursor", async () => {
    await create();
    const r1 = (await (await push([item(hid(1)), item(hid(2))])).json()) as PushBody;
    expect(r1.results.map((r) => r.status)).toEqual(["ok", "ok"]);
    expect(r1.results.map((r) => r.seq)).toEqual([1, 2]);
    expect(r1.latestSeq).toBe(2);

    const all = (await (await pull(0)).json()) as PullBody;
    expect(all.records.map((r) => r.idHash)).toEqual([hid(1), hid(2)]);
    const later = (await (await pull(1)).json()) as PullBody;
    expect(later.records.map((r) => r.idHash)).toEqual([hid(2)]);
    const none = (await (await pull(99)).json()) as PullBody;
    expect(none.records).toEqual([]);
    expect(none.latestSeq).toBe(2);
  });

  it("reports a conflict when baseSeq is stale and returns the current envelope", async () => {
    await create();
    await push([item(hid(1))]); // seq 1
    await push([item(hid(1), 1, "bmV3")]); // seq 2, from device A
    const stale = (await (await push([item(hid(1), 1, "b2xk")])).json()) as PushBody;
    expect(stale.results[0].status).toBe("conflict");
    expect(stale.results[0].current?.seq).toBe(2);
    expect(stale.results[0].current?.ciphertext).toBe("bmV3");
    expect(stale.latestSeq).toBe(2);
    // 帶正確 baseSeq 重送就成功。
    const ok = (await (await push([item(hid(1), 2, "b2xk")])).json()) as PushBody;
    expect(ok.results[0]).toEqual({ status: "ok", seq: 3 });
  });

  it("keeps tombstones pullable and counts them toward the quota", async () => {
    await create();
    await push([item(hid(1), 0, "x".repeat(1000))]);
    await push([item(hid(1), 1, "dG9tYg==", true)]);
    const all = (await (await pull(0)).json()) as PullBody;
    expect(all.records).toHaveLength(1);
    expect(all.records[0].deleted).toBe(true);
    expect(all.records[0].ciphertext).toBe("dG9tYg==");
    // 既有的 tombstone 佔 8 + 8 = 16 bytes;15 筆 64 KiB 把用量吃到 16 + 983,160 = 983,176;
    // 再來一筆 64 KiB 的 tombstone → 1,048,720 > 1 MiB,一樣越界。
    const big = "y".repeat(65_536);
    const fifteen = Array.from({ length: 15 }, (_, i) => item(hid(100 + i), 0, big));
    expect((await push(fifteen)).status).toBe(200);
    expect((await push([item(hid(200), 0, big, true)])).status).toBe(413);
  });

  it("validates bodies without leaking them", async () => {
    await create();
    const bad = [
      "",
      "{}",
      "[]",
      "[1]",
      JSON.stringify([{ idHash: "h" }]),
      JSON.stringify([item("nothex")]),
      JSON.stringify([item(hid(1), 0, "abc")]), // 長度不是 4 的倍數
      JSON.stringify([item(hid(1), 0, "AA\u0000A")]), // NUL:SQLite LENGTH() 會在這裡停
      JSON.stringify([item(hid(1), 0, "Y2lw中")]), // 非 ASCII
      JSON.stringify([item(hid(1), 0, "")]), // 空密文
      JSON.stringify([{ ...item(hid(1)), nonce: "not base64!" }]),
    ];
    for (const body of bad) {
      const res = await relay(`/v1/chains/${chain}/records`, { method: "POST", headers: auth(), body });
      expect(res.status, body).toBe(400);
      expect(await res.text()).not.toContain('idHash":');
    }
    // 同一批重複 idHash:拒絕(否則第二筆的 baseSeq 判定會依賴第一筆的寫入順序)。
    expect((await push([item(hid(1)), item(hid(1))])).status).toBe(400);
    // 超過 200 筆。
    expect((await push(Array.from({ length: 201 }, (_, i) => item(hid(i))))).status).toBe(400);
    expect((await pull("abc")).status).toBe(400);
    expect((await pull(-1)).status).toBe(400);
  });

  it("refuses oversize records, oversize bodies and chain quota overflow atomically", async () => {
    await create();
    expect((await push([item(hid(1), 0, "z".repeat(65_540))])).status).toBe(413);
    // body 超過 1 MiB:串流讀到上限就取消,不解析。分別測有宣告長度(string body)與沒有(stream body)。
    const oversized = "[" + "x".repeat(1_048_600);
    expect((await relay(`/v1/chains/${chain}/records`, { method: "POST", headers: auth(), body: oversized })).status).toBe(413);
    const stream = new Blob([oversized]).stream();
    expect((await relay(`/v1/chains/${chain}/records`, { method: "POST", headers: auth(), body: stream, duplex: "half" } as RequestInit)).status).toBe(413);
    // 15 × (65536 + 8) = 983,160 可以;第 16 筆會到 1,048,704 > 1 MiB → 整批 413,原本 15 筆都在。
    const big = "y".repeat(65_536);
    const fifteen = Array.from({ length: 15 }, (_, i) => item(hid(i), 0, big));
    expect((await push(fifteen)).status).toBe(200);
    expect((await push([item(hid(15), 0, big), item(hid(16), 0, SMALL)])).status).toBe(413);
    const all = (await (await pull(0)).json()) as PullBody;
    expect(all.records).toHaveLength(15);
  });

  it("charges replacements net of the old row and never charges conflicting items", async () => {
    await create();
    const big = "y".repeat(65_536);
    const fifteen = Array.from({ length: 15 }, (_, i) => item(hid(i), 0, big));
    await push(fifteen); // seq 1..15,用量 983,160
    // 替換 hid(0)(baseSeq 正確):先扣舊列再加新列,總量不變 → 接受。
    expect((await push([item(hid(0), 1, big)])).status).toBe(200);
    // hid(1) 帶過期 baseSeq → conflict(不寫入、不佔配額);hid(99) 很小 → 接受。
    const r = (await (await push([item(hid(1), 0, big), item(hid(99), 0, SMALL)])).json()) as PushBody;
    expect(r.results.map((x) => x.status)).toEqual(["conflict", "ok"]);
    const all = (await (await pull(0)).json()) as PullBody;
    expect(all.records).toHaveLength(16);
  });

  it("caps the number of records per chain", async () => {
    await create();
    for (let batch = 0; batch < 20; batch++) {
      const items = Array.from({ length: 200 }, (_, i) => item(hid(batch * 200 + i), 0, SMALL));
      expect((await push(items)).status).toBe(200);
    }
    // 4000 筆之後再 100 筆 → 4100 > 4096:整批 413。
    expect((await push(Array.from({ length: 100 }, (_, i) => item(hid(5000 + i), 0, SMALL)))).status).toBe(413);
  });

  it("rate-limits a chain to 120 requests per minute on every endpoint", async () => {
    await create(); // 第 1 次(建鏈那一次也計數)
    for (let i = 0; i < 119; i++) {
      expect((await pull(0)).status).toBe(200);
    }
    // 第 121 次起,已授權的任何端點一律 429(不是 404、不是靜默成功)。
    expect((await pull(0)).status).toBe(429);
    expect((await create()).status).toBe(429);
    expect((await push([item(hid(1))])).status).toBe(429);
    expect((await destroy()).status).toBe(429);
  });

  it("keeps counting across delete and re-create within the same minute", async () => {
    await create(); // 第 1 次
    for (let i = 0; i < 118; i++) {
      expect((await pull(0)).status).toBe(200); // 第 2..119 次
    }
    expect((await destroy()).status).toBe(204); // 第 120 次
    // 同一個 instance、同一分鐘:DELETE 不把計數歸零,重建是第 121 次 → 429,且沒有建出 schema。
    expect((await create()).status).toBe(429);
    expect(await env.CHAIN.getByName(chain).exists()).toBe(false);
  });
});

describe("freeze", () => {
  it("refuses every push after a freeze and writes nothing", async () => {
    await create();
    await push([item(hid(1))]);
    expect((await freeze()).status).toBe(204);
    const refused = await push([item(hid(2))]);
    expect(refused.status).toBe(409);
    expect(await refused.json()).toEqual({ status: "frozen" });
    // 已存在的記錄被「更新」也一樣被擋。
    expect((await push([item(hid(1), 1, "bmV3")])).status).toBe(409);
    const all = (await (await pull(0)).json()) as PullBody;
    expect(all.records.map((r) => r.idHash)).toEqual([hid(1)]);
    expect(all.latestSeq).toBe(1);
  });

  it("keeps a frozen chain readable; deleting it removes the records but cannot reopen it", async () => {
    await create();
    await push([item(hid(1))]);
    await freeze();
    expect((await pull(0)).status).toBe(200);
    expect((await create()).status).toBe(200);
    expect((await push([item(hid(2))])).status).toBe(409);
    expect((await destroy()).status).toBe(204);
    // 同一個權杖 DELETE 再 PUT:chain 還在(200 不是 201)、仍然凍結,記錄清空但 latestSeq 保留。
    expect((await create()).status).toBe(200);
    expect((await push([item(hid(3))])).status).toBe(409);
    const after = await pull(0);
    expect(after.status).toBe(200);
    expect(await after.json()).toEqual({ records: [], latestSeq: 1 });
    // token hash 也保留:別的權杖不能接手這個 chain id。
    expect((await create(OTHER_TOKEN)).status).toBe(404);
    expect(await env.CHAIN.getByName(chain).exists()).toBe(true);
  });

  it("still deletes a chain that was never frozen completely", async () => {
    await create();
    await push([item(hid(1))]);
    expect((await destroy()).status).toBe(204);
    expect(await env.CHAIN.getByName(chain).exists()).toBe(false);
    expect((await create()).status).toBe(201);
    const r = (await (await push([item(hid(2))])).json()) as PushBody;
    expect(r.results[0]).toEqual({ status: "ok", seq: 1 });
  });

  it("is idempotent and needs the chain's own token", async () => {
    await create();
    expect((await freeze(OTHER_TOKEN)).status).toBe(404);
    expect((await push([item(hid(1))])).status).toBe(200);
    expect((await freeze()).status).toBe(204);
    expect((await freeze()).status).toBe(204);
    const id = newChainId();
    expect((await freeze(TOKEN, id)).status).toBe(404);
    expect(await env.CHAIN.getByName(id).exists()).toBe(false);
  });

  it("stays frozen after the chain's Durable Object is evicted", async () => {
    await create();
    await freeze();
    // 驅逐會丟掉 instance 的記憶體、保留儲存:凍結旗標必須在 meta 表裡,不能只是記憶體裡的欄位。
    await evictDurableObject(env.CHAIN.getByName(chain));
    expect((await push([item(hid(1))])).status).toBe(409);
  });
});

describe("idle deadline", () => {
  const alarmOf = (id = chain) => runInDurableObject(env.CHAIN.getByName(id), (_instance, state) => state.storage.getAlarm());
  const setAlarm = (at: number) => runInDurableObject(env.CHAIN.getByName(chain), (_instance, state) => state.storage.setAlarm(at));

  it("leaves the alarm alone on pulls within six hours of the last refresh, even after the object was evicted", async () => {
    await create();
    // 一小時前刷新過。驅逐(與休眠一樣)會丟掉 instance 的記憶體:節流必須看儲存裡的 alarm,否則每次輪詢都多寫一列。
    const armed = Date.now() + IDLE_TTL - HOUR;
    await setAlarm(armed);
    await evictDurableObject(env.CHAIN.getByName(chain));
    expect((await pull(0)).status).toBe(200);
    expect((await pull(0)).status).toBe(200);
    expect(await alarmOf()).toBe(armed);
  });

  it("refreshes the alarm on a pull once the last refresh is more than six hours old, or when there is none", async () => {
    await create();
    const stale = Date.now() + IDLE_TTL - 7 * HOUR;
    await setAlarm(stale);
    const before = Date.now();
    expect((await pull(0)).status).toBe(200);
    expect(await alarmOf()).toBeGreaterThan(before + IDLE_TTL - HOUR);
    await runInDurableObject(env.CHAIN.getByName(chain), (_instance, state) => state.storage.deleteAlarm());
    expect((await pull(0)).status).toBe(200);
    expect(await alarmOf()).toBeGreaterThan(before + IDLE_TTL - HOUR);
  });

  it("refreshes the alarm on every write", async () => {
    await create();
    const armed = Date.now() + IDLE_TTL - HOUR;
    await setAlarm(armed);
    expect((await push([item(hid(1))])).status).toBe(200);
    expect(await alarmOf()).toBeGreaterThan(armed);
  });
});
