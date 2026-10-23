import { AUTHORITY_HEADER, authorityWitness } from "../src/security/authority";
import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import gateway, { type GatewayEnv } from "../src/security/gateway";
import { REGISTRY_WITNESS } from "../src/security/floor";

const random = (n = 32) =>
  Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const origin = "https://relay.test";
let installation: string;
let ip = 0;
beforeEach(() => {
  installation = random(16);
  ip++;
});
const configured = (): GatewayEnv => ({
  ...env,
  SECURITY_INSTALLATION: installation,
  CENTRAL_ORIGIN: origin,
  CENTRAL_ENABLED: "1",
  PASSKEY_ENABLED: "1",
});
const provision = () =>
  env.SECURITY_FLOOR.getByName("floor:" + installation).provision(
    installation,
    2,
    env.LEGACY_RETIREMENT.idFromName(REGISTRY_WITNESS).toString(),
  );
function request(path: string, method = "GET", body?: string | ReadableStream<Uint8Array>) {
  return new Request(origin + path, {
    method,
    headers: {
      [AUTHORITY_HEADER]: authorityWitness(env),
      "cf-connecting-ip": `198.51.100.${ip}`,
      "content-type": "application/json",
    },
    body,
  });
}

describe("central ingress", () => {
  it("serves account routes after authorization and ignores client authority headers", async () => {
    await provision();
    const info = await gateway.fetch(request("/v1/info"), configured());
    expect(info.status).toBe(200);
    expect((await info.json() as { protocol: number }).protocol).toBe(2);
    expect((await gateway.fetch(request("/v1/register", "POST", "{}"), configured())).status).toBe(401);
  });

  it("rejects every legacy chain route before calling a backend", async () => {
    await provision();
    const chain = random();
    for (const [path, method, body] of [
      ["/legacy/v1/info", "GET", undefined],
      ["/legacy/v1/pull", "POST", "[]"],
      [`/legacy/v1/chains/${chain}`, "PUT", "{}"],
      [`/legacy/v1/chains/${chain}/records`, "GET", undefined],
      [`/legacy/v1/chains/${chain}/records`, "POST", "[]"],
      [`/legacy/v1/chains/${chain}/freeze`, "POST", undefined],
    ] as const) {
      expect((await gateway.fetch(request(path, method, body), configured())).status).toBe(404);
    }
    expect((await exports.CentralSyncBackend.forward(2, random(), request("/legacy/v1/info"))).status).toBe(404);
    expect((await exports.default.fetch(request("/legacy/v1/info"))).status).toBe(404);
  });

  it("rejects wrong origins, unavailable security authority and oversized bodies", async () => {
    expect((await gateway.fetch(request("/v1/info"), configured())).status).toBe(503);
    await provision();
    expect((await gateway.fetch(new Request("https://other.test/v1/info"), configured())).status).toBe(421);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(4 * 1024 * 1024 + 1));
        controller.close();
      },
    });
    expect((await gateway.fetch(request("/v1/register", "POST", stream), configured())).status).toBe(413);
  });
});
