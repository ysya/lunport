import { AUTHORITY_HEADER } from "./authority";
/** Independently deployed ingress. Never retries a private RPC through a public URL. */
import type { CentralSyncBackend } from "../index";
import { MINIMUM_BACKEND_FLOOR, type FloorEnv } from "./floor";
import { centralPrivateFetch, type CentralRouteEnv } from "../v2/routes";
export { SecurityFloorStore } from "./floor";
export { LegacyRetirementStore } from "../legacy-retirement";
export { IpLimiter } from "../ip-limit";
export { AccountStore } from "../v2/account";
export { VaultStore } from "../v2/store";
export { PasskeyStore } from "../v2/passkeys/store";
export type GatewayEnv = FloorEnv & CentralRouteEnv & {
  CORE: Service<CentralSyncBackend>;
  IP_LIMIT: Env["IP_LIMIT"];
  SECURITY_INSTALLATION: string;
  CENTRAL_ORIGIN: string;
};
const HEX64 = /^[0-9a-f]{64}$/;
function failure(status = 503): Response {
  return new Response(null, {
    status,
    headers: {
      "cache-control": "no-store",
      ...(status === 503 ? { "retry-after": "5" } : {}),
    },
  });
}
async function cappedBody(
  request: Request,
  maximum: number,
): Promise<Uint8Array | null> {
  if (Number(request.headers.get("content-length") ?? 0) > maximum) return null;
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.length;
    }
    return body;
  } catch {
    return null;
  }
}
async function tokenHash(token: string): Promise<string> {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
}
export default {
  async fetch(request: Request, env: GatewayEnv): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" || url.origin !== env.CENTRAL_ORIGIN)
        return failure(421);
      const isCentral = url.pathname.startsWith("/v1/"),
        isInfo = url.pathname === "/legacy/v1/info",
        isBatch = url.pathname === "/legacy/v1/pull";
      const match = /^\/legacy\/v1\/chains\/([0-9a-f]{64})(\/records|\/freeze)?$/.exec(
        url.pathname,
      );
      if (!isCentral && !isInfo && !isBatch && !match) return failure(404);
      if (
        (isInfo && request.method !== "GET") ||
        (isBatch && request.method !== "POST")
      )
        return failure(404);
      const limiter = env.IP_LIMIT.getByName(
        "ip:" + (request.headers.get("cf-connecting-ip") ?? "unknown"),
      );
      const creating = !!match && !match[2] && request.method === "PUT";
      if (
        !(await limiter.allowMany(
          creating
            ? [
                ["request", 1],
                ["create", 1],
              ]
            : [["request", 1]],
        ))
      )
        return failure(429);
      const floor = await env.SECURITY_FLOOR.getByName(
        "floor:" + env.SECURITY_INSTALLATION,
      ).authorize(env.SECURITY_INSTALLATION, MINIMUM_BACKEND_FLOOR);
      if (floor.status !== 200) return failure();
      const body = await cappedBody(
        request,
        isBatch ? 65536 : isCentral ? 4 * 1024 * 1024 : 1048576,
      );
      if (!body) return failure(413);
      if (isBatch) {
        let items: unknown;
        try {
          items = JSON.parse(
            new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
              body,
            ),
          );
        } catch {
          return failure(400);
        }
        if (
          !Array.isArray(items) ||
          !items.length ||
          items.length > 64 ||
          new Set(items.map((v) => v?.chain)).size !== items.length
        )
          return failure(400);
        if (!(await limiter.allow("pull", items.length))) return failure(429);
        for (const item of items) {
          if (
            !item ||
            typeof item !== "object" ||
            typeof item.chain !== "string" ||
            !HEX64.test(item.chain) ||
            typeof item.token !== "string" ||
            !HEX64.test(item.token) ||
            !Number.isSafeInteger(item.since) ||
            item.since < 0
          )
            return failure(400);
          const code = await env.LEGACY_RETIREMENT.getByName(item.chain).check(
            item.chain,
            await tokenHash(item.token),
            false,
          );
          // Stop the whole old-client batch rather than forwarding a retired bearer.
          if (code !== 200) return failure(code);
        }
      } else if (match) {
        const [, chain, suffix] = match;
        if (!(
          (suffix === "/records" && ["GET", "POST"].includes(request.method)) ||
          (suffix === "/freeze" && request.method === "POST") ||
          (!suffix && ["PUT", "DELETE"].includes(request.method))
        ))
          return failure(404);
        const token = /^Bearer\s+([0-9a-f]{64})$/i
          .exec(request.headers.get("authorization") ?? "")?.[1]
          .toLowerCase();
        if (!token) return failure(404);
        const code = await env.LEGACY_RETIREMENT.getByName(chain).check(
          chain,
          await tokenHash(token),
          request.method !== "GET",
        );
        if (code !== 200) return failure(code);
      }
      const forwarded = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body:
          ["GET", "HEAD"].includes(request.method) || !body.byteLength
            ? undefined
            : body,
      });
      if (isCentral) {
        forwarded.headers.delete(AUTHORITY_HEADER);
        return await centralPrivateFetch(forwarded, env);
      }
      forwarded.headers.set(AUTHORITY_HEADER, floor.authority);
      return await env.CORE.forward(floor.minimum, floor.registry, forwarded);
    } catch {
      return failure();
    }
  },
} satisfies ExportedHandler<GatewayEnv>;
