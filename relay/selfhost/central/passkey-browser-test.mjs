/** Optional synthetic browser check, called only by the disposable Compose smoke test. */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
export async function checkPasskeyBrowser({
  address,
  origin,
  playwrightPath,
  executablePath,
}) {
  const { chromium } = await import(pathToFileURL(playwrightPath).href);
  const browser = await chromium.launch({ executablePath, headless: true });
  const listener = createServer((request, response) => {
    const url = new URL(
      request.url,
      `http://127.0.0.1:${listener.address().port}`,
    );
    if (url.pathname !== "/passkey/callback") {
      response.writeHead(404).end();
      return;
    }
    callbacks.push(url);
    response
      .writeHead(200, {
        "content-type": "text/html",
        "cache-control": "no-store",
      })
      .end("<!doctype html><p>Returned to synthetic native listener.</p>");
  });
  const callbacks = [];
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const redirect = `http://127.0.0.1:${listener.address().port}/passkey/callback`;
  const call = async (path, body, extraHeaders = {}) =>
    fetch(`http://${address}/v2/auth/passkey/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...extraHeaders },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
  try {
    const context = await browser.newContext();
    await context.route(`${origin}/**`, async (route) => {
      const request = route.request(),
        url = new URL(request.url());
      const headers = { ...request.headers() };
      delete headers.host;
      delete headers["content-length"];
      delete headers["accept-encoding"];
      const response = await fetch(
        `http://${address}${url.pathname}${url.search}`,
        {
          method: request.method(),
          headers,
          ...(request.postDataBuffer()
            ? { body: request.postDataBuffer() }
            : {}),
          redirect: "manual",
          signal: AbortSignal.timeout(10_000),
        },
      );
      const replyHeaders = Object.fromEntries(response.headers);
      delete replyHeaders["content-encoding"];
      delete replyHeaders["content-length"];
      await route.fulfill({
        status: response.status,
        headers: replyHeaders,
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const addAuthenticator = async () =>
      (
        await cdp.send("WebAuthn.addVirtualAuthenticator", {
          options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
          },
        })
      ).authenticatorId;
    const primary = await addAuthenticator();
    const begin = async () => {
      const verifier = randomBytes(32).toString("hex"),
        state = randomBytes(32).toString("hex");
      const response = await call("authorize", {
        code_challenge: createHash("sha256")
          .update(verifier)
          .digest("base64url"),
        redirect_uri: redirect,
        state,
      });
      assert.equal(response.status, 201);
      const body = await response.json();
      await page.goto(body.url);
      await page
        .getByRole("button", { name: "Sign in with a passkey", exact: true })
        .waitFor();
      await page.waitForFunction(
        () => !document.querySelector('[data-kind="login"]').disabled,
      );
      assert.equal(await page.evaluate(() => isSecureContext), true);
      assert.equal(new URL(page.url()).hash, "");
      const authUrl = new URL(body.url);
      return {
        verifier,
        state,
        index: callbacks.length,
        flow: authUrl.searchParams.get("flow"),
        key: new URLSearchParams(authUrl.hash.slice(1)).get("key"),
      };
    };
    const exchange = async (flow) => {
      await page.waitForURL(redirect + "?**", { timeout: 20_000 });
      const callback = callbacks[flow.index];
      assert.equal(callback.searchParams.get("state"), flow.state);
      const response = await call("exchange", {
        code: callback.searchParams.get("code"),
        verifier: flow.verifier,
        redirect_uri: redirect,
      });
      assert.equal(response.status, 200);
      return response.json();
    };
    const first = await begin();
    await page
      .getByRole("button", {
        name: "Create an account with a passkey",
        exact: true,
      })
      .click();
    const firstGrant = await exchange(first);
    const manage = await begin();
    await page
      .getByRole("button", {
        name: "Manage passkeys, then sign in",
        exact: true,
      })
      .click();
    await page
      .getByRole("button", { name: "Add a backup passkey", exact: true })
      .waitFor();
    await page.waitForFunction(
      () => !document.querySelector('[data-kind="add"]').disabled,
    );
    // A remote link initiator can forge Origin but cannot see the browser's verification response.
    const linkHeaders = { origin, "x-lunport-flow": manage.key };
    assert.equal(
      (await call("options", { flow: manage.flow, kind: "add" }, linkHeaders))
        .status,
      403,
    );
    assert.equal(
      (await call("management", { flow: manage.flow }, linkHeaders)).status,
      403,
    );
    assert.equal(
      (await call("complete", { flow: manage.flow }, linkHeaders)).status,
      403,
    );
    await cdp.send("WebAuthn.removeVirtualAuthenticator", {
      authenticatorId: primary,
    });
    await addAuthenticator();
    await page
      .getByRole("button", { name: "Add a backup passkey", exact: true })
      .click();
    await page.getByText(/2 passkey\(s\)/).waitFor();
    await page
      .getByRole("button", { name: "Continue to Lunport", exact: true })
      .click();
    assert.equal((await exchange(manage)).subject, firstGrant.subject);
    const backup = await begin();
    await page
      .getByRole("button", {
        name: "Manage passkeys, then sign in",
        exact: true,
      })
      .click();
    await page.getByText(/2 passkey\(s\)/).waitFor();
    const removal = page.getByRole("button", {
      name: "Remove this passkey",
      exact: true,
    });
    assert.equal(await removal.count(), 2);
    const available = await removal.evaluateAll((buttons) =>
      buttons.findIndex((button) => !button.disabled),
    );
    assert.ok(available >= 0);
    await removal.nth(available).click();
    await page.getByText(/1 passkey\(s\)/).waitFor();
    assert.equal(
      (await call("refresh", { refresh_token: firstGrant.refresh_token }))
        .status,
      401,
    );
    await page
      .getByRole("button", { name: "Continue to Lunport", exact: true })
      .click();
    const last = await exchange(backup);
    assert.equal(last.subject, firstGrant.subject);
    assert.equal(
      (await call("logout", { token: last.refresh_token })).status,
      200,
    );
    assert.equal(
      (await call("refresh", { refresh_token: last.refresh_token })).status,
      401,
    );
    console.log(
      "Actual Chromium virtual Passkey registration, backup, removal, loopback PKCE and logout passed (HTTPS origin is test-intercepted; no real TLS assertion).",
    );
  } finally {
    await browser.close();
    await new Promise((resolve) => listener.close(resolve));
  }
}
