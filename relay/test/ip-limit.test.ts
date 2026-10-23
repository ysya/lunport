import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { expect, it, vi } from "vitest";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

type Windows = Partial<Record<"create" | "request" | "pull", { start: number; count: number }>>;
type Limiter = ReturnType<typeof env.IP_LIMIT.getByName>;

const windowsOf = (limiter: Limiter) =>
  runInDurableObject(limiter, async (_instance, state) => (await state.storage.get<Windows>("windows")) ?? {});
const alarmOf = (limiter: Limiter) => runInDurableObject(limiter, (_instance, state) => state.storage.getAlarm());

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

it("does not mutate durable counters or alarms after a bucket is blocked", async () => {
  const limiter = env.IP_LIMIT.getByName("ip:bounded-denials");
  expect(await limiter.allowMany([["request", 1201], ["create", 1]])).toBe(false);
  const before = await windowsOf(limiter);
  const alarm = await alarmOf(limiter);
  for (let i = 0; i < 100; i++) {
    expect(await limiter.allowMany([["request", 1], ["create", 1]])).toBe(false);
  }
  expect(await windowsOf(limiter)).toEqual(before);
  expect(await alarmOf(limiter)).toBe(alarm);
  // The persisted blocked state survives the next request; other buckets remain usable.
  expect(await limiter.allow("pull", 1)).toBe(true);
  expect((await windowsOf(limiter)).create).toEqual(before.create);
});

it("caps over-limit costs and permits requests again after the fixed window expires", async () => {
  const limiter = env.IP_LIMIT.getByName("ip:bounded-cost");
  expect(await limiter.allow("pull", 1000000)).toBe(false);
  expect((await windowsOf(limiter)).pull?.count).toBe(12001);
  await runInDurableObject(limiter, async (_instance, state) => {
    const windows = (await state.storage.get<Windows>("windows"))!;
    windows.pull!.start = Date.now() - HOUR - 1;
    await state.storage.put("windows", windows);
  });
  expect(await limiter.allow("pull", 1)).toBe(true);
  expect((await windowsOf(limiter)).pull?.count).toBe(1);
});


it("performs no persistent put for requests against a blocked window", async () => {
  const limiter = env.IP_LIMIT.getByName("ip:no-denial-writes");
  expect(await limiter.allow("request", 1201)).toBe(false);
  await runInDurableObject(limiter, async (instance, state) => {
    const put = vi.spyOn(state.storage, "put");
    try {
      for (let i = 0; i < 100; i++) expect(await instance.allow("request")).toBe(false);
      expect(put).not.toHaveBeenCalled();
    } finally { put.mockRestore(); }
  });
});
