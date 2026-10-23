/** Independently deployed ingress. Never retries a private RPC through a public URL. */
import { AUTHORITY_HEADER } from "./authority";
import { MINIMUM_BACKEND_FLOOR, type FloorEnv } from "./floor";
import { centralPrivateFetch, type CentralRouteEnv } from "../v2/routes";
export { SecurityFloorStore } from "./floor";
export { LegacyRetirementStore } from "../legacy-retirement";
export { IpLimiter } from "../ip-limit";
export { AccountStore } from "../v2/account";
export { VaultStore } from "../v2/store";
export { PasskeyStore } from "../v2/passkeys/store";
export type GatewayEnv = FloorEnv & CentralRouteEnv & {
  IP_LIMIT: Env["IP_LIMIT"];
  SECURITY_INSTALLATION: string;
  CENTRAL_ORIGIN: string;
};
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
export default {
  async fetch(request: Request, env: GatewayEnv): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" || url.origin !== env.CENTRAL_ORIGIN)
        return failure(421);
      if (!url.pathname.startsWith("/v1/")) return failure(404);
      const limiter = env.IP_LIMIT.getByName(
        "ip:" + (request.headers.get("cf-connecting-ip") ?? "unknown"),
      );
      if (!(await limiter.allowMany([["request", 1]]))) return failure(429);
      const floor = await env.SECURITY_FLOOR.getByName(
        "floor:" + env.SECURITY_INSTALLATION,
      ).authorize(env.SECURITY_INSTALLATION, MINIMUM_BACKEND_FLOOR);
      if (floor.status !== 200) return failure();
      const body = await cappedBody(request, 4 * 1024 * 1024);
      if (!body) return failure(413);
      const forwarded = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body:
          ["GET", "HEAD"].includes(request.method) || !body.byteLength
            ? undefined
            : body,
      });
      forwarded.headers.delete(AUTHORITY_HEADER);
      return await centralPrivateFetch(forwarded, env);
    } catch {
      return failure();
    }
  },
} satisfies ExportedHandler<GatewayEnv>;
