import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";

const TOKEN = "d".repeat(64);
const IP = "198.51.100.9";
const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

type Windows = Partial<Record<"create" | "request" | "pull", { start: number; count: number }>>;
type Limiter = ReturnType<typeof env.IP_LIMIT.getByName>;

const windowsOf = (limiter: Limiter) =>
  runInDurableObject(limiter, async (_instance, state) => (await state.storage.get<Windows>("windows")) ?? {});
const alarmOf = (limiter: Limiter) => runInDurableObject(limiter, (_instance, state) => state.storage.getAlarm());

function newChainId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function create(id: string) {
  return exports.default.fetch(
    new Request(`https://relay.test/v1/chains/${id}`, {
      method: "PUT",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json", "cf-connecting-ip": IP },
      body: "{}",
    }),
  );
}

// 建鏈桶計的是 PUT 嘗試(不論 201/200/404),不是成功建立的 chain 數(spec §5)。
it("allows 20 chain-creation requests per IP per hour, then answers 429", async () => {
  const first = newChainId();
  expect((await create(first)).status).toBe(201);
  for (let i = 1; i < 20; i++) {
    expect((await create(newChainId())).status).toBe(201);
  }
  expect((await create(newChainId())).status).toBe(429);
  // 已建立的 chain 不受建鏈限制影響(GET 只計入總請求桶)。
  const pull = await exports.default.fetch(
    new Request(`https://relay.test/v1/chains/${first}/records?since=0`, {
      headers: { authorization: `Bearer ${TOKEN}`, "cf-connecting-ip": IP },
    }),
  );
  expect(pull.status).toBe(200);
});

it("allows 1200 requests per IP per hour on the request bucket", async () => {
  const limiter = env.IP_LIMIT.getByName("ip:unit-test");
  for (let i = 0; i < 1200; i++) {
    expect(await limiter.allow("request")).toBe(true);
  }
  expect(await limiter.allow("request")).toBe(false);
  // 桶彼此獨立:建鏈桶還沒用過。
  expect(await limiter.allow("create")).toBe(true);
});

it("allows 12000 pulled chains per IP per hour on the pull bucket, charged by cost", async () => {
  const limiter = env.IP_LIMIT.getByName("ip:unit-test-pull");
  expect(await limiter.allow("pull", 11_990)).toBe(true);
  expect(await limiter.allow("pull", 10)).toBe(true);
  expect(await limiter.allow("pull")).toBe(false);
  // 其他桶不受影響。
  expect(await limiter.allow("request")).toBe(true);
});

it("starts the pull bucket for limiters stored by an older relay and keeps their counts", async () => {
  const limiter = env.IP_LIMIT.getByName("ip:unit-test-legacy");
  const now = Date.now();
  await runInDurableObject(limiter, async (_instance, state) => {
    // 0.1.0 的儲存格式:只有 create 與 request 兩個桶。
    await state.storage.put("windows", { create: { start: now, count: 3 }, request: { start: now, count: 5 } });
  });
  expect(await limiter.allow("pull", 5)).toBe(true);
  expect(await limiter.allow("create")).toBe(true);
  const windows = await windowsOf(limiter);
  // 舊的計數照留(視窗還開著),缺的 pull 桶從 0 開始;開了新視窗所以 alarm 也設好了。
  expect(windows.create).toEqual({ start: now, count: 4 });
  expect(windows.request).toEqual({ start: now, count: 5 });
  expect(windows.pull?.count).toBe(5);
  expect(await alarmOf(limiter)).not.toBeNull();
});

it("charges several buckets in one call and refuses when any of them is over", async () => {
  const limiter = env.IP_LIMIT.getByName("ip:unit-test-many");
  expect(await limiter.allowMany([["request", 1], ["pull", 11_999]])).toBe(true);
  // pull 會超過(12001 > 12000):整次拒絕,但兩個桶都照計(與單筆相同,超限也計)。
  expect(await limiter.allowMany([["request", 1], ["pull", 2]])).toBe(false);
  const windows = await windowsOf(limiter);
  expect([windows.request?.count, windows.pull?.count, windows.create]).toEqual([2, 12_001, { start: 0, count: 0 }]);
});

it("moves the cleanup alarm only when a window starts, so it never wipes an open window", async () => {
  const limiter = env.IP_LIMIT.getByName("ip:unit-test-alarm");
  const now = Date.now();
  // request 視窗 10 分鐘前開始:alarm 在它開始後一小時。
  await runInDurableObject(limiter, async (_instance, state) => {
    await state.storage.put("windows", { request: { start: now - 10 * MINUTE, count: 1 } });
    await state.storage.setAlarm(now + 50 * MINUTE);
  });
  expect(await limiter.allow("request")).toBe(true);
  // 視窗還開著:alarm 不動,計數接著加。
  expect(await alarmOf(limiter)).toBe(now + 50 * MINUTE);
  expect((await windowsOf(limiter)).request).toEqual({ start: now - 10 * MINUTE, count: 2 });

  // request 視窗 61 分鐘前開始(已過期),pull 視窗 30 分鐘前開始:alarm 在 pull 開始後一小時。
  await runInDurableObject(limiter, async (_instance, state) => {
    await state.storage.put("windows", {
      request: { start: now - 61 * MINUTE, count: 9 },
      pull: { start: now - 30 * MINUTE, count: 4 },
    });
    await state.storage.setAlarm(now + 30 * MINUTE);
  });
  expect(await limiter.allow("request")).toBe(true);
  // 這次開了新的 request 視窗:alarm 移到新視窗開始後一小時;pull 視窗不受影響。
  expect(await alarmOf(limiter)).toBeGreaterThan(now + 50 * MINUTE);
  const windows = await windowsOf(limiter);
  expect(windows.request?.count).toBe(1);
  expect(windows.request?.start).toBeGreaterThanOrEqual(now);
  expect(windows.pull).toEqual({ start: now - 30 * MINUTE, count: 4 });
});

it("writes all three buckets, so a relay rolled back to 0.1.0 can still read the record", async () => {
  const ip = "198.51.100.11";
  const limiter = env.IP_LIMIT.getByName(`ip:${ip}`);
  const res = await exports.default.fetch(
    new Request(`https://relay.test/v1/chains/${newChainId()}/records?since=0`, {
      headers: { authorization: `Bearer ${TOKEN}`, "cf-connecting-ip": ip },
    }),
  );
  expect(res.status).toBe(404); // 沒有這條 chain,但請求照樣計入
  const windows = await windowsOf(limiter);
  // 0.1.0 的 allow 直接讀 windows[bucket].start:三個桶都要在,沒用到的是已過期的 { start: 0, count: 0 }。
  expect(Object.keys(windows).sort()).toEqual(["create", "pull", "request"]);
  expect(windows.create).toEqual({ start: 0, count: 0 });
  expect(windows.pull).toEqual({ start: 0, count: 0 });
  expect(windows.request?.count).toBe(1);
  // 只有 request 開了新視窗,alarm 只設這一次:在它開始後一小時。
  expect(await alarmOf(limiter)).toBe(windows.request!.start + HOUR);
});

it("charges a chain request with one limiter call: PUT counts request and create, other methods only request", async () => {
  const ip = "198.51.100.10";
  const limiter = env.IP_LIMIT.getByName(`ip:${ip}`);
  const id = newChainId();
  const headers = { authorization: `Bearer ${TOKEN}`, "cf-connecting-ip": ip };
  const put = await exports.default.fetch(new Request(`https://relay.test/v1/chains/${id}`, { method: "PUT", headers, body: "{}" }));
  expect(put.status).toBe(201);
  let windows = await windowsOf(limiter);
  expect([windows.request?.count, windows.create?.count]).toEqual([1, 1]);
  const get = await exports.default.fetch(new Request(`https://relay.test/v1/chains/${id}/records?since=0`, { headers }));
  expect(get.status).toBe(200);
  windows = await windowsOf(limiter);
  expect([windows.request?.count, windows.create?.count, windows.pull]).toEqual([2, 1, { start: 0, count: 0 }]);
  // 建鏈桶用完時 PUT 回 429(同一次呼叫裡 request 也照計)。
  await limiter.allow("create", 19);
  const refused = await exports.default.fetch(new Request(`https://relay.test/v1/chains/${newChainId()}`, { method: "PUT", headers, body: "{}" }));
  expect(refused.status).toBe(429);
  windows = await windowsOf(limiter);
  expect([windows.request?.count, windows.create?.count]).toEqual([3, 21]);
});
