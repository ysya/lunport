/** Private Caddy HTTP hop only. Managed Workers keep the gateway's original HTTPS entry. */
import gateway, { type GatewayEnv } from "./gateway";
import { validOrigin } from "../v2/protocol";
export {
  SecurityFloorStore,
  LegacyRetirementStore,
  IpLimiter,
  AccountStore,
  VaultStore,
  PasskeyStore,
} from "./gateway";
export type SelfhostEnv = GatewayEnv & { SELFHOST_PROXY_KEY: string };
const HEX64 = /^[0-9a-f]{64}$/;
function sameKey(expected: string, supplied: string): boolean {
  if (!HEX64.test(supplied)) return false;
  let mismatch = 0;
  for (let i = 0; i < 64; i++)
    mismatch |= expected.charCodeAt(i) ^ supplied.charCodeAt(i);
  return mismatch === 0;
}
export function configured(
  env: Pick<SelfhostEnv, "CENTRAL_ORIGIN" | "SELFHOST_PROXY_KEY">,
): boolean {
  return (
    typeof env.CENTRAL_ORIGIN === "string" &&
    validOrigin(env.CENTRAL_ORIGIN) &&
    typeof env.SELFHOST_PROXY_KEY === "string" &&
    HEX64.test(env.SELFHOST_PROXY_KEY)
  );
}
/** Configuration supplies the public origin; client forwarding headers never select it. */
export function trustedRequest(
  request: Request,
  env: Pick<SelfhostEnv, "CENTRAL_ORIGIN" | "SELFHOST_PROXY_KEY">,
): Request | null {
  if (
    !configured(env) ||
    !sameKey(
      env.SELFHOST_PROXY_KEY,
      request.headers.get("x-lunport-proxy-key") ?? "",
    )
  )
    return null;
  const incoming = new URL(request.url),
    origin = new URL(env.CENTRAL_ORIGIN);
  if (
    incoming.protocol !== "http:" ||
    incoming.host !== origin.host ||
    incoming.username ||
    incoming.password ||
    request.headers.get("x-forwarded-proto") !== "https"
  )
    return null;
  const normalized = new Request(
    origin.origin + incoming.pathname + incoming.search,
    request,
  );
  for (const header of [
    "x-lunport-proxy-key",
    "forwarded",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
  ])
    normalized.headers.delete(header);
  return normalized;
}
export default {
  async fetch(request: Request, env: SelfhostEnv): Promise<Response> {
    if (!configured(env))
      return new Response(null, {
        status: 503,
        headers: { "cache-control": "no-store" },
      });
    const normalized = trustedRequest(request, env);
    if (!normalized)
      return new Response(null, {
        status: 403,
        headers: { "cache-control": "no-store" },
      });
    return gateway.fetch(normalized, env);
  },
} satisfies ExportedHandler<SelfhostEnv>;
