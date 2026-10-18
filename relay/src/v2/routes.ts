import {
  deviceProof,
  parseSession,
  sessionProof,
  validIdentityConfig,
  verifyIdentity,
  type IdentityConfig,
} from "./auth";
import { exactObject, hex, safeNumber } from "./protocol";
import type { Result } from "./store";

function configured(env: Env): IdentityConfig | null {
  const config = {
    origin: env.CENTRAL_ORIGIN ?? "",
    issuer: env.OIDC_ISSUER ?? "",
    jwks: env.OIDC_JWKS_URL ?? "",
    audience: env.OIDC_API_AUDIENCE ?? "",
    clientId: env.OIDC_NATIVE_CLIENT_ID ?? "",
    scope: env.OIDC_SYNC_SCOPE ?? "lunport:sync",
  };
  return env.CENTRAL_ENABLED === "1" && validIdentityConfig(config)
    ? config
    : null;
}
function response(result: Result | Response): Response {
  if (result instanceof Response) return result;
  const headers = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...(result.status === 429 || result.status === 202 || result.status === 503
      ? { "retry-after": "5" }
      : {}),
  };
  return result.body === undefined
    ? new Response(null, { status: result.status, headers })
    : Response.json(result.body, { status: result.status, headers });
}
async function body(request: Request): Promise<Record<string, any> | Response> {
  if (
    !request.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  )
    return response({ status: 415 });
  if (Number(request.headers.get("content-length") ?? 0) > 4 * 1024 * 1024)
    return response({ status: 413 });
  const reader = request.body?.getReader();
  if (!reader) return response({ status: 400 });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 4 * 1024 * 1024) {
        await reader.cancel();
        return response({ status: 413 });
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    const value: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes),
    );
    return value !== null && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, any>)
      : response({ status: 400 });
  } catch {
    return response({ status: 400 });
  }
}
const paths = new Set([
  "/v2/info",
  "/v2/register",
  "/v2/session",
  "/v2/account",
  "/v2/bootstrap",
  "/v2/enrollment",
  "/v2/membership",
  "/v2/vaults",
  "/v2/barrier/resume",
  "/v2/device-access/revoke",
  "/v2/logout",
  "/v2/pull",
  "/v2/recovery/wraps",
  "/v2/recovery/commit",
  "/v2/device-access",
]);
/** No v2 authentication error ever retries a v1 bearer path. */
export async function centralFetch(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url),
    match = /^\/v2\/vaults\/([0-9a-f]{64})\/(records|wrap|metadata)$/.exec(
      url.pathname,
    );
  if (!paths.has(url.pathname) && !match) return response({ status: 404 });
  const limiter = env.IP_LIMIT.getByName(
    "ip:" + (request.headers.get("cf-connecting-ip") ?? "unknown"),
  );
  if (!(await limiter.allow("request"))) return response({ status: 429 });
  const config = configured(env);
  if (!config) return response({ status: 503 });
  if (url.origin !== config.origin) return response({ status: 421 });
  if (url.pathname === "/v2/info")
    return request.method === "GET"
      ? response({
          status: 200,
          body: {
            protocol: 2,
            features: [
              "central-accounts",
              "anchored-membership",
              "exact-revision",
              "operation-receipts",
              "paged-history",
            ],
            oidc: {
              issuer: config.issuer,
              client_id: config.clientId,
              audience: config.audience,
              scopes: ["openid", config.scope, "offline_access"],
            },
          },
        })
      : response({ status: 405 });
  const raw = request.headers.get("authorization"),
    token = raw?.startsWith("Bearer ") ? raw.slice(7) : null;
  if (!token || token.length > 16384) return response({ status: 401 });
  if (
    [
      "/v2/register",
      "/v2/session",
      "/v2/device-access/revoke",
      "/v2/device-access",
    ].includes(url.pathname)
  ) {
    if (
      request.method !== (url.pathname === "/v2/device-access" ? "GET" : "POST")
    )
      return response({ status: 405 });
    const identity = await verifyIdentity(token, config);
    if (!identity) return response({ status: 401 });
    const account = env.ACCOUNT.getByName(identity.locator);
    if (url.pathname === "/v2/device-access")
      return account.deviceAccess(identity);
    const parsed = await body(request);
    if (parsed instanceof Response) return parsed;
    if (url.pathname === "/v2/device-access/revoke") {
      return exactObject(parsed, ["device"]) && hex(parsed.device, 32)
        ? response(await account.revokeAccess(identity, parsed.device))
        : response({ status: 400 });
    }
    if (
      !exactObject(parsed, [
        "device",
        "name",
        "credential",
        "session_id",
        "session_secret",
      ])
    )
      return response({ status: 400 });
    const proof = await deviceProof(
      (parsed.device as any)?.id,
      parsed.credential,
      parsed.session_id,
      parsed.session_secret,
    );
    if (!proof) return response({ status: 400 });
    return response(
      await account.register(
        identity,
        config.origin,
        proof,
        parsed.device as any,
        parsed.name as string,
      ),
    );
  }
  const parsedSession = parseSession(token);
  if (!parsedSession) return response({ status: 401 });
  const proof = await sessionProof(parsedSession.id, parsedSession.secret);
  if (!proof) return response({ status: 401 });
  const account = env.ACCOUNT.getByName(parsedSession.locator);
  const data = !!match || url.pathname === "/v2/pull";
  const actor = await account.authorize(proof, data);
  if (!actor) return response({ status: 403 });
  if (url.pathname === "/v2/account" && request.method === "GET")
    return response(await account.overview(actor));
  if (match) {
    const vault = env.VAULT.getByName(actor.account + ":" + match[1]);
    if (request.method === "GET") {
      if (match[2] === "metadata") return response(await vault.metadata(actor));
      if (match[2] === "wrap") return response(await vault.wrap(actor));
      let since: number;
      try {
        since = safeNumber(url.searchParams.get("since") ?? "0", true);
      } catch {
        return response({ status: 400 });
      }
      return response(await vault.pull(actor, since));
    }
    if (request.method === "POST" && match[2] === "records") {
      const parsed = await body(request);
      return parsed instanceof Response
        ? parsed
        : exactObject(parsed, ["records"])
          ? response(await vault.push(actor, parsed.records as any))
          : response({ status: 400 });
    }
    return response({ status: 405 });
  }
  if (request.method !== "POST") return response({ status: 405 });
  const parsed = await body(request);
  if (parsed instanceof Response) return parsed;
  switch (url.pathname) {
    case "/v2/recovery/wraps":
      return exactObject(parsed, ["proof"])
        ? response(await account.recoveryWraps(actor, parsed.proof as any))
        : response({ status: 400 });
    case "/v2/recovery/commit":
      return exactObject(parsed, ["node", "wraps"])
        ? response(
            await account.recover(
              actor,
              parsed.node as any,
              parsed.wraps as any,
            ),
          )
        : response({ status: 400 });
    case "/v2/bootstrap":
      return exactObject(parsed, ["genesis", "vault", "wraps"])
        ? response(
            await account.bootstrap(
              actor,
              parsed.genesis as any,
              parsed.vault as string,
              parsed.wraps as any,
            ),
          )
        : response({ status: 400 });
    case "/v2/enrollment":
      return exactObject(parsed, ["request"])
        ? response(await account.enrollment(actor, parsed.request as any))
        : response({ status: 400 });
    case "/v2/membership":
      return exactObject(parsed, ["node", "wraps", "confirmation"])
        ? response(
            await account.control(
              actor,
              parsed.node as any,
              parsed.wraps as any,
              parsed.confirmation as any,
            ),
          )
        : response({ status: 400 });
    case "/v2/vaults":
      return exactObject(parsed, ["vault", "wraps"])
        ? response(
            await account.createVault(
              actor,
              parsed.vault as string,
              parsed.wraps as any,
            ),
          )
        : response({ status: 400 });
    case "/v2/barrier/resume":
      return exactObject(parsed, [])
        ? response(await account.resume(actor))
        : response({ status: 400 });
    case "/v2/logout":
      return exactObject(parsed, [])
        ? response(await account.logout(actor))
        : response({ status: 400 });
    case "/v2/pull": {
      if (
        !exactObject(parsed, ["items"]) ||
        !Array.isArray(parsed.items) ||
        parsed.items.length < 1 ||
        parsed.items.length > 64 ||
        parsed.items.some(
          (i) => !exactObject(i, ["vault", "since"]) || !hex(i.vault, 64),
        ) ||
        new Set(parsed.items.map((i) => i.vault)).size !== parsed.items.length
      )
        return response({ status: 400 });
      if (!(await limiter.allowMany([["pull", parsed.items.length]])))
        return response({ status: 429 });
      const results: unknown[] = [];
      let bytes = 0;
      for (const item of parsed.items) {
        let since: number;
        try {
          since = safeNumber(item.since, true);
        } catch {
          return response({ status: 400 });
        }
        if (bytes >= 2 * 1024 * 1024) {
          results.push({ vault: item.vault, status: 202, deferred: true });
          continue;
        }
        const result = await env.VAULT.getByName(
          actor.account + ":" + item.vault,
        ).pull(actor, since);
        const entry = {
          vault: item.vault,
          status: result.status,
          body: result.body ? await result.json() : undefined,
        };
        bytes += JSON.stringify(entry).length;
        results.push(entry);
      }
      return response({ status: 200, body: { results } });
    }
    default:
      return response({ status: 404 });
  }
}
