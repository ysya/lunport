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
      : `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lunport sign-in</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{font:16px system-ui;margin:0;min-height:100vh;display:grid;place-items:center;padding:32px 20px;background:#21222c;color:#eeeef5}main{width:100%;max-width:440px;padding:32px;border:1px solid #484a60;border-radius:18px;background:#2a2c39;box-shadow:0 20px 80px #0002}.brand{color:#bf98f7;font-weight:650;letter-spacing:.02em}h1{font-size:27px;margin:24px 0 8px}p{line-height:1.6;color:#b9bbd1;overflow-wrap:anywhere}button,input{width:100%;padding:13px 14px;border:1px solid #656c96;border-radius:9px;font:inherit}button{display:block;margin:12px 0;background:#bf98f7;color:#211c30;font-weight:550;cursor:pointer}button.secondary{background:transparent;color:#ddd9ec}button:disabled{opacity:.5;cursor:default}input{margin:8px 0 4px;background:#222430;color:#f4f1fa}input:focus-visible,button:focus-visible{outline:2px solid #c9a4ff;outline-offset:3px}label{display:block;margin-top:20px;font-size:14px}small{display:block;line-height:1.6;color:#a6a8c1}[hidden]{display:none!important}#message{min-height:3em;font-size:14px}#account-name{color:#d3b8fa}
</style><main><div class="brand">Lunport</div><h1>Sign in to Lunport</h1><p id="account-name">Your self-hosted sync account</p><div id="sign-in"><button data-kind="login">Sign in with a passkey</button><button class="secondary" data-kind="manage">Manage passkeys, then sign in</button></div><form id="signup" hidden><label for="email">Email (account name)</label><input id="email" name="email" type="email" autocomplete="username webauthn" maxlength="254" required placeholder="you@example.com"><p><small>Your email is not verified and cannot be used to recover your account.</small></p><button type="button" data-kind="register">Create an account with a passkey</button></form><div id="switcher"><button class="secondary" data-view="signup">Create an account</button><button class="secondary" data-view="login" hidden>Back to sign in</button></div><div id="credentials"></div><button data-kind="add" hidden>Add a backup passkey</button><button data-kind="complete" hidden>Continue to Lunport</button><p id="message" role="status" aria-live="polite">Your device may ask for a fingerprint, face, PIN, or security key.</p><small>After signing in, enter your sync password in the app to unlock your encrypted library.</small><script defer src="/v1/auth/passkey/script"></script></main></html>`,
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
