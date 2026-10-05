import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

// relay.test.ts 的 freeze 測試涵蓋基本行為;這裡釘住的是「改錯了也不會讓那些測試失敗」的部分:
// 路由(只有 POST 能凍結)、檢查順序(權杖 → 速率 → 凍結)、凍結計入每 chain 速率。
// 獨立成一個檔案,並使用自己的 IP 區段(192.0.2.x),不與其他檔案的 IP 重疊。

const TOKEN = "b".repeat(64);
const OTHER_TOKEN = "c".repeat(64);
const NONCE = "bm9uY2U="; // base64("nonce")

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
 * 每個測試各用一個來源 IP。IpLimiter 的 Durable Object 儲存不會在同一個檔案的測試之間重置,
 * 共用同一個 IP 會讓「每 IP 每小時 20 次建鏈」被耗盡(不同檔案之間的儲存則是分開的)。
 */
let ip = "";
let ipSeq = 0;
let chain = "";
beforeEach(() => {
  chain = newChainId();
  ipSeq += 1;
  ip = `192.0.2.${ipSeq}`;
});

function relay(path: string, method: string, token = TOKEN, body?: unknown) {
  return exports.default.fetch(
    new Request(`https://relay.test${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "cf-connecting-ip": ip },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
}

const create = (token = TOKEN) => relay(`/v1/chains/${chain}`, "PUT", token, {});
const freeze = (token = TOKEN) => relay(`/v1/chains/${chain}/freeze`, "POST", token);
const pull = () => relay(`/v1/chains/${chain}/records?since=0`, "GET");
const push = (n: number, token = TOKEN) =>
  relay(`/v1/chains/${chain}/records`, "POST", token, [
    { idHash: hid(n), kind: "host", nonce: NONCE, ciphertext: "Y2lwaGVy", deleted: false, baseSeq: 0 },
  ]);

describe("freeze: routing, check order and rate limit", () => {
  it("tells a wrong token nothing about a frozen chain: still 404, never 409", async () => {
    await create();
    await freeze();
    // 權杖檢查先於凍結檢查:錯誤的權杖不能從 409 得知「這條 chain 存在而且已凍結」。
    expect((await push(1, OTHER_TOKEN)).status).toBe(404);
    // 對照組:正確的權杖才看得到 409(證明上面的 404 不是因為 chain 沒被凍結)。
    expect((await push(1)).status).toBe(409);
  });

  it("is POST-only: other methods on /freeze are 404 and neither create, delete nor freeze", async () => {
    // 不存在的 chain:PUT /freeze 不可以建出 chain。
    expect((await relay(`/v1/chains/${chain}/freeze`, "PUT", TOKEN, {})).status).toBe(404);
    expect(await env.CHAIN.getByName(chain).exists()).toBe(false);
    await create();
    expect((await relay(`/v1/chains/${chain}/freeze`, "PUT", TOKEN, {})).status).toBe(404);
    expect((await relay(`/v1/chains/${chain}/freeze`, "DELETE")).status).toBe(404);
    expect((await relay(`/v1/chains/${chain}/freeze`, "GET")).status).toBe(404);
    // chain 還在、沒有被凍結。
    expect(await env.CHAIN.getByName(chain).exists()).toBe(true);
    expect((await push(1)).status).toBe(200);
  });

  it("counts a freeze toward the chain's 120 requests per minute", async () => {
    await create(); // 第 1 次
    for (let i = 0; i < 119; i++) {
      expect((await freeze()).status).toBe(204); // 第 2..120 次
    }
    expect((await freeze()).status).toBe(429); // 第 121 次
  });

  it("answers 429, not 409, to a push over the chain's rate limit", async () => {
    await create(); // 第 1 次
    await freeze(); // 第 2 次
    for (let i = 0; i < 118; i++) {
      expect((await pull()).status).toBe(200); // 第 3..120 次
    }
    expect((await push(1)).status).toBe(429); // 第 121 次:速率限制先於凍結檢查
  });
});
