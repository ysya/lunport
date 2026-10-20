import { passkeyScript } from "./browser.generated";
const headers = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "content-security-policy":
    "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "permissions-policy":
    "publickey-credentials-get=(self), publickey-credentials-create=(self)",
};
export function page(script = false): Response {
  return new Response(
    script
      ? passkeyScript
      : `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lunport sign-in</title><style>body{font:16px system-ui;max-width:440px;margin:12vh auto;padding:24px;background:#10151d;color:#e5edf7}h1{font-size:28px}p{line-height:1.6;color:#b9c6d8}button{display:block;width:100%;margin:12px 0;padding:14px;border:1px solid #40516a;border-radius:8px;background:#253c60;color:white;font:inherit;cursor:pointer}button:disabled{opacity:.5}button[hidden]{display:none}small{color:#94a6be}#message{min-height:3em}</style><h1>Sign in to Lunport</h1><p>Use your passkey to sign in to the desktop app.</p><button data-kind="login">Sign in with a passkey</button><button data-kind="register">Create an account with a passkey</button><button data-kind="manage">Manage passkeys, then sign in</button><div id="credentials"></div><button data-kind="add" hidden>Add a backup passkey</button><button data-kind="complete" hidden>Continue to Lunport</button><p id="message" role="status" aria-live="polite">Your device may ask for a fingerprint, face, PIN, or security key.</p><small>Signing in does not approve a new device to decrypt your encrypted library.</small><script defer src="/v2/auth/passkey/script"></script></html>`,
    {
      headers: {
        ...headers,
        "content-type": script
          ? "text/javascript; charset=utf-8"
          : "text/html; charset=utf-8",
      },
    },
  );
}
