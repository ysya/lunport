import { exactObject, hex } from "../protocol";
import { page } from "./page";
import type { Result } from "../store";
export const PREFIX = "/v1/auth/passkey/";
export function reply(result: Result): Response {
  const headers = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...(result.status === 429 ? { "retry-after": "60" } : {}),
  };
  return result.body === undefined
    ? new Response(null, { status: result.status, headers })
    : Response.json(result.body, { status: result.status, headers });
}
async function body(request: Request): Promise<Record<string, any> | null> {
  if (
    request.headers.get("content-type")?.split(";")[0].trim().toLowerCase() !==
    "application/json"
  )
    return null;
  if (Number(request.headers.get("content-length") ?? 0) > 32768) return null;
  const reader = request.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 32768) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const c of chunks) {
      bytes.set(c, offset);
      offset += c.length;
    }
    const value = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes),
    );
    return value && typeof value === "object" && !Array.isArray(value)
      ? value
      : null;
  } catch {
    return null;
  }
}
export async function route(
  request: Request,
  env: Pick<Env, "PASSKEY">,
  origin: string,
): Promise<Response> {
  const url = new URL(request.url),
    action = url.pathname.slice(PREFIX.length);
  if (["page", "script"].includes(action)) {
    if (request.method !== "GET") return reply({ status: 405 });
    if (
      action === "page" &&
      (!hex(url.searchParams.get("flow"), 32) ||
        Array.from(url.searchParams.keys()).some((k) => k !== "flow"))
    )
      return reply({ status: 400 });
    return page(action === "script");
  }
  if (
    ![
      "authorize",
      "context",
      "options",
      "finish",
      "management",
      "remove",
      "complete",
      "exchange",
      "refresh",
      "logout",
    ].includes(action)
  )
    return reply({ status: 404 });
  if (request.method !== "POST") return reply({ status: 405 });
  const browser = [
    "context",
    "options",
    "finish",
    "management",
    "remove",
    "complete",
  ].includes(action);
  if (
    browser
      ? request.headers.get("origin") !== origin
      : request.headers.has("origin") &&
        request.headers.get("origin") !== origin
  )
    return reply({ status: 403 });
  const parsed = await body(request);
  if (!parsed) return reply({ status: 400 });
  const store = env.PASSKEY.getByName("passkeys");
  if (action === "authorize") {
    if (
      !exactObject(
        parsed,
        parsed.expected_locator === undefined
          ? ["code_challenge", "redirect_uri", "state"]
          : ["code_challenge", "redirect_uri", "state", "expected_locator"],
      )
    )
      return reply({ status: 400 });
    return reply(await store.begin(origin, parsed as any));
  }
  if (browser) {
    const key = request.headers.get("x-lunport-flow") ?? "";
    const managementKey = request.headers.get("x-lunport-management") ?? "";
    if (!hex(parsed.flow, 32) || !hex(key, 64)) return reply({ status: 403 });
    if (action === "context")
      return exactObject(parsed, ["flow"])
        ? reply(await store.context(origin, parsed.flow, key))
        : reply({ status: 400 });
    if (action === "options")
      return exactObject(parsed, parsed.kind === "register" ? ["flow", "kind", "email"] : ["flow", "kind"]) &&
        ["login", "register", "manage", "add"].includes(parsed.kind as string) &&
        (parsed.kind !== "register" || typeof parsed.email === "string")
        ? reply(
            await store.options(
              origin,
              parsed.flow as string,
              key,
              parsed.kind as "login" | "register" | "manage" | "add",
              managementKey,
              Date.now(),
              parsed.kind === "register" ? parsed.email as string : undefined,
            ),
          )
        : reply({ status: 400 });
    if (action === "management" || action === "complete")
      return exactObject(parsed, ["flow"])
        ? reply(
            action === "complete"
              ? await store.complete(origin, parsed.flow, key, managementKey)
              : await store.management(origin, parsed.flow, key, managementKey),
          )
        : reply({ status: 400 });
    if (action === "remove")
      return exactObject(parsed, ["flow", "credential"]) &&
        typeof parsed.credential === "string" &&
        parsed.credential.length <= 2048
        ? reply(
            await store.remove(
              origin,
              parsed.flow,
              key,
              parsed.credential,
              managementKey,
            ),
          )
        : reply({ status: 400 });
    return exactObject(parsed, ["flow", "response"]) &&
      parsed.response &&
      typeof parsed.response === "object"
      ? reply(
          await store.finish(
            origin,
            parsed.flow as string,
            key,
            parsed.response as any,
            managementKey,
          ),
        )
      : reply({ status: 400 });
  }
  if (action === "exchange")
    return exactObject(parsed, ["code", "verifier", "redirect_uri"]) &&
      [parsed.code, parsed.verifier, parsed.redirect_uri].every(
        (s) => typeof s === "string" && s.length <= 2048,
      )
      ? reply(
          await store.exchange(
            origin,
            parsed.code as string,
            parsed.verifier as string,
            parsed.redirect_uri as string,
          ),
        )
      : reply({ status: 400 });
  const field = action === "refresh" ? "refresh_token" : "token";
  if (
    !exactObject(parsed, [field]) ||
    typeof parsed[field] !== "string" ||
    parsed[field].length > 512
  )
    return reply({ status: 400 });
  return reply(
    action === "refresh"
      ? await store.refresh(origin, parsed[field])
      : await store.logout(origin, parsed[field]),
  );
}
