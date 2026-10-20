/** Resource access tokens are separate from native ID tokens. No email-derived identity. */
import {
  createRemoteJWKSet,
  customFetch,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";
import { canonical, hash, hex, validOrigin } from "./protocol";

export type IdentityConfig = {
  origin: string;
  issuer: string;
  jwks: string;
  audience: string;
  clientId: string;
  scope: string;
};
export type Identity = { locator: string; authenticatedAt: number | null };
export type Principal = {
  locator: string;
  account: string;
  device: string;
  epoch: number;
  session: string;
  expires: number;
};
export type SessionProof = { id: string; hash: string };
export type DeviceProof = {
  id: string;
  credential: string;
  session: SessionProof;
};
const resolvers = new Map<string, JWTVerifyGetKey>();

function secureEndpoint(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !u.username && !u.password && !u.hash;
  } catch {
    return false;
  }
}
export function validIdentityConfig(c: IdentityConfig): boolean {
  return (
    validOrigin(c.origin) &&
    secureEndpoint(c.issuer) &&
    !new URL(c.issuer).search &&
    secureEndpoint(c.jwks) &&
    c.audience.length > 0 &&
    c.audience.length <= 1024 &&
    c.clientId.length > 0 &&
    c.clientId.length <= 256 &&
    c.audience !== c.clientId &&
    /^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/.test(c.scope)
  );
}
/** Identity response bounds apply to actual streamed bytes, including missing Content-Length. */
async function boundedKeys(
  url: string,
  options: {
    headers: Headers;
    method: "GET";
    redirect: "manual";
    signal: AbortSignal;
  },
): Promise<Response> {
  const response = await fetch(url, options);
  if (
    response.status !== 200 ||
    Number(response.headers.get("content-length") ?? 0) > 262144
  ) {
    await response.body?.cancel();
    throw new Error("Identity keys unavailable.");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Identity keys unavailable.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 262144) {
      await reader.cancel();
      throw new Error("Identity keys unavailable.");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return new Response(bytes, {
    headers: { "content-type": "application/json" },
  });
}
export async function verifyIdentity(
  token: string,
  config: IdentityConfig,
  resolver?: JWTVerifyGetKey,
  now = new Date(),
): Promise<Identity | null> {
  try {
    if (!validIdentityConfig(config) || token.length > 16384) return null;
    if (!resolver) {
      resolver = resolvers.get(config.jwks);
      if (!resolver) {
        if (resolvers.size >= 4) resolvers.clear();
        resolver = createRemoteJWKSet(new URL(config.jwks), {
          timeoutDuration: 5000,
          cooldownDuration: 30000,
          cacheMaxAge: 600000,
          [customFetch]: boundedKeys,
        });
        resolvers.set(config.jwks, resolver);
      }
    }
    const { payload, protectedHeader } = await jwtVerify(token, resolver, {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: ["RS256", "ES256"],
      typ: "at+jwt",
      requiredClaims: ["iss", "aud", "exp", "iat", "sub", "client_id", "jti"],
      maxTokenAge: "1h",
      clockTolerance: 5,
      currentDate: now,
    });
    if (
      protectedHeader.typ?.toLowerCase() !== "at+jwt" ||
      payload.client_id !== config.clientId ||
      typeof payload.sub !== "string" ||
      !payload.sub ||
      payload.sub.length > 512 ||
      typeof payload.jti !== "string" ||
      !payload.jti ||
      payload.jti.length > 256 ||
      typeof payload.scope !== "string" ||
      payload.scope.length > 4096 ||
      !payload.scope.split(" ").includes(config.scope) ||
      payload.exp! <= payload.iat! ||
      payload.exp! - payload.iat! > 3600
    )
      return null;
    const authenticatedAt =
      typeof payload.auth_time === "number" &&
      Number.isSafeInteger(payload.auth_time) &&
      payload.auth_time > 0 &&
      payload.auth_time <= now.getTime() / 1000 + 5
        ? payload.auth_time * 1000
        : null;
    return {
      locator: await hash(
        canonical([
          "lunport-account-locator-v2",
          config.origin,
          config.issuer,
          payload.sub,
        ]),
      ),
      authenticatedAt,
    };
  } catch {
    return null;
  }
}
export function parseSession(
  value: string,
): { locator: string; id: string; secret: string } | null {
  const parts = value.split(".");
  if (
    parts.length !== 4 ||
    parts[0] !== "v2" ||
    !hex(parts[1], 64) ||
    !hex(parts[2], 32) ||
    !hex(parts[3], 64)
  )
    return null;
  // Hashing is async, so parse only supplies the untrusted format. Never authorize this directly.
  return { locator: parts[1], id: parts[2], secret: parts[3] };
}
export async function sessionProof(
  id: unknown,
  secret: unknown,
): Promise<SessionProof | null> {
  if (!hex(id, 32) || !hex(secret, 64)) return null;
  return {
    id,
    hash: await hash(canonical(["lunport-session-v2", id, secret])),
  };
}
export async function deviceProof(
  id: unknown,
  credential: unknown,
  sessionId: unknown,
  sessionSecret: unknown,
): Promise<DeviceProof | null> {
  if (!hex(id, 32) || !hex(credential, 64)) return null;
  const session = await sessionProof(sessionId, sessionSecret);
  if (!session) return null;
  return {
    id,
    credential: await hash(
      canonical(["lunport-device-credential-v2", id, credential]),
    ),
    session,
  };
}
