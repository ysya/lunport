import { canonical, hash, hex, validOrigin } from "../protocol";
export const FLOW_MS = 5 * 60_000;
export const CODE_MS = 60_000;
export const ACCESS_MS = 5 * 60_000;
export const FAMILY_MS = 30 * 24 * 60 * 60_000;
export type Config = { origin: string; rpId: string };
export function configuration(origin: string): Config | null {
  if (!validOrigin(origin)) return null;
  const host = new URL(origin).hostname;
  if (
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host) ||
    /^[0-9.]+$/.test(host)
  )
    return null;
  return { origin, rpId: host };
}
export function random(bytes = 32): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (v) =>
    v.toString(16).padStart(2, "0"),
  ).join("");
}
export function encode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
export function decode(
  s: unknown,
  maximum: number,
): Uint8Array<ArrayBuffer> | null {
  if (
    typeof s !== "string" ||
    !/^[A-Za-z0-9_-]+$/.test(s) ||
    s.length > Math.ceil((maximum * 4) / 3)
  )
    return null;
  try {
    const b = Uint8Array.from(
      atob(s.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );
    return b.length <= maximum && encode(b) === s ? b : null;
  } catch {
    return null;
  }
}
export type Begin = {
  code_challenge: string;
  redirect_uri: string;
  state: string;
  expected_locator?: string;
};
export function validBegin(value: Begin): boolean {
  try {
    const u = new URL(value.redirect_uri);
    return (
      !!decode(value.code_challenge, 32) &&
      decode(value.code_challenge, 32)!.length === 32 &&
      /^[A-Za-z0-9_-]{32,128}$/.test(value.state) &&
      u.protocol === "http:" &&
      u.hostname === "127.0.0.1" &&
      !!u.port &&
      Number(u.port) > 0 &&
      u.pathname === "/passkey/callback" &&
      !u.username &&
      !u.password &&
      !u.search &&
      !u.hash &&
      (value.expected_locator === undefined || hex(value.expected_locator, 64))
    );
  } catch {
    return false;
  }
}
export async function locator(
  origin: string,
  subject: string,
): Promise<string> {
  return hash(
    canonical([
      "lunport-account-locator-v2",
      origin,
      origin + "/v2/auth/passkey",
      subject,
    ]),
  );
}
export function token(
  value: string,
  prefix: string,
): { family: string; secret: string } | null {
  const parts = value.split(".");
  return parts.length === 3 &&
    parts[0] === prefix &&
    hex(parts[1], 32) &&
    hex(parts[2], 64)
    ? { family: parts[1], secret: parts[2] }
    : null;
}
export async function pkce(
  verifier: unknown,
  challenge: string,
): Promise<boolean> {
  if (
    typeof verifier !== "string" ||
    !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
  )
    return false;
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  );
  return encode(digest) === challenge;
}
