import { env, exports } from "cloudflare:workers";
import { expect, it } from "vitest";

const TOKEN = "d".repeat(64);
const IP = "198.51.100.9";

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
