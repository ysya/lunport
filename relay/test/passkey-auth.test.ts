import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import {
  encode,
  decode,
  random,
  configuration,
} from "../src/v2/passkeys/protocol";
const origin = "https://passkey.test";
const bytes = (...parts: Uint8Array[]) => {
  const b = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    b.set(p, o);
    o += p.length;
  }
  return b;
};
const sha = async (s: string | Uint8Array) =>
  new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      typeof s === "string" ? new TextEncoder().encode(s) : s,
    ),
  );
function der(raw: Uint8Array): Uint8Array {
  const integer = (b: Uint8Array) => {
    while (b.length > 1 && b[0] === 0) b = b.slice(1);
    return b[0] & 128 ? bytes(new Uint8Array([0]), b) : b;
  };
  const r = integer(raw.slice(0, 32)),
    s = integer(raw.slice(32));
  return bytes(
    new Uint8Array([48, 4 + r.length + s.length, 2, r.length]),
    r,
    new Uint8Array([2, s.length]),
    s,
  );
}
async function authenticator() {
  const pair = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey(
      "jwk",
      pair.publicKey,
    )) as JsonWebKey,
    id = crypto.getRandomValues(new Uint8Array(32));
  const cose = isoCBOR.encode(
    new Map<number, any>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, decode(jwk.x!, 32)!],
      [-3, decode(jwk.y!, 32)!],
    ]),
  );
  return {
    async registration(
      challenge: string,
      options: { origin?: string; rp?: string; uv?: boolean } = {},
    ): Promise<RegistrationResponseJSON> {
      const client = new TextEncoder().encode(
        JSON.stringify({
          type: "webauthn.create",
          challenge,
          origin: options.origin ?? origin,
          crossOrigin: false,
        }),
      );
      const data = bytes(
        await sha(options.rp ?? "passkey.test"),
        new Uint8Array([0x41 | (options.uv === false ? 0 : 4)]),
        new Uint8Array(4),
        new Uint8Array(16),
        new Uint8Array([0, id.length]),
        id,
        cose,
      );
      return {
        id: encode(id),
        rawId: encode(id),
        type: "public-key",
        response: {
          clientDataJSON: encode(client),
          attestationObject: encode(
            isoCBOR.encode(
              new Map<string, any>([
                ["fmt", "none"],
                ["attStmt", new Map()],
                ["authData", data],
              ]),
            ),
          ),
          transports: ["internal"],
        },
        clientExtensionResults: { credProps: { rk: true } },
      };
    },
    async assertion(
      challenge: string,
      user: string,
      options: {
        origin?: string;
        rp?: string;
        uv?: boolean;
        counter?: number;
      } = {},
    ): Promise<AuthenticationResponseJSON> {
      const client = new TextEncoder().encode(
        JSON.stringify({
          type: "webauthn.get",
          challenge,
          origin: options.origin ?? origin,
          crossOrigin: false,
        }),
      );
      const counter = new Uint8Array(4);
      new DataView(counter.buffer).setUint32(0, options.counter ?? 1);
      const data = bytes(
        await sha(options.rp ?? "passkey.test"),
        new Uint8Array([1 | (options.uv === false ? 0 : 4)]),
        counter,
      );
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        bytes(data, await sha(client)),
      );
      return {
        id: encode(id),
        rawId: encode(id),
        type: "public-key",
        response: {
          clientDataJSON: encode(client),
          authenticatorData: encode(data),
          signature: encode(der(new Uint8Array(signature))),
          userHandle: user,
        },
        clientExtensionResults: {},
      };
    },
  };
}
async function begin(
  store: DurableObjectStub<import("../src/v2/passkeys/store").PasskeyStore>,
  expected?: string,
) {
  const verifier = "a".repeat(64),
    redirect = "http://127.0.0.1:38171/passkey/callback";
  const result = await store.begin(origin, {
    code_challenge: encode(await sha(verifier)),
    redirect_uri: redirect,
    state: random(),
    ...(expected ? { expected_locator: expected } : {}),
  });
  expect(result.status).toBe(201);
  const url = new URL((result.body as any).url);
  return {
    id: url.searchParams.get("flow")!,
    key: new URLSearchParams(url.hash.slice(1)).get("key")!,
    verifier,
    redirect,
  };
}
async function enroll(email = `${random()}@homelab.test`) {
  const store = env.PASSKEY.getByName(random()),
    virtual = await authenticator(),
    flow = await begin(store);
  const options = await store.options(origin, flow.id, flow.key, "register", "", Date.now(), email);
  expect(options.status).toBe(200);
  const challenge = (options.body as any).options.challenge,
    user = (options.body as any).options.user.id;
  const response = await virtual.registration(challenge);
  const finished = await store.finish(origin, flow.id, flow.key, response);
  expect(finished.status).toBe(200);
  const code = new URL((finished.body as any).redirect).searchParams.get(
    "code",
  )!;
  const exchanged = await store.exchange(
    origin,
    code,
    flow.verifier,
    flow.redirect,
  );
  expect(exchanged.status).toBe(200);
  return {
    store,
    virtual,
    email,
    flow,
    response,
    code,
    user,
    tokens: exchanged.body as any,
  };
}
describe("built-in Passkey authentication on actual workerd", () => {
  it("registers, logs in, consumes the PKCE code once and keeps account auth separate from Vault data", async () => {
    const { store, virtual, flow, response, code, user, tokens } =
      await enroll();
    const identity = await store.identity(origin, tokens.access_token);
    expect(identity?.locator).toMatch(/^[0-9a-f]{64}$/);
    expect(identity?.authenticatedAt).toBeGreaterThan(0);
    expect(
      (await store.exchange(origin, code, flow.verifier, flow.redirect)).status,
    ).toBe(401);
    expect(
      (await store.finish(origin, flow.id, flow.key, response)).status,
    ).not.toBe(200);
    const login = await begin(store, identity!.locator),
      options = await store.options(origin, login.id, login.key, "login");
    const assertion = await virtual.assertion(
      (options.body as any).options.challenge,
      user,
    );
    const finished = await store.finish(origin, login.id, login.key, assertion);
    expect(finished.status).toBe(200);
    const again = await store.exchange(
      origin,
      new URL((finished.body as any).redirect).searchParams.get("code")!,
      login.verifier,
      login.redirect,
    );
    expect(again.status).toBe(200);
    expect(
      (await store.identity(origin, (again.body as any).access_token))?.locator,
    ).toBe(identity!.locator);
    expect(JSON.stringify(again)).not.toMatch(
      /private_key|ciphertext|vault_key/,
    );
  });
  it("rejects bad registration origin, RP, challenge and missing user verification", async () => {
    for (const bad of ["origin", "rp", "challenge", "uv"]) {
      const store = env.PASSKEY.getByName(random()),
        virtual = await authenticator(),
        flow = await begin(store);
      const options = await store.options(origin, flow.id, flow.key, "register", "", Date.now(), `${random()}@homelab.test`),
        challenge = (options.body as any).options.challenge;
      const response = await virtual.registration(
        bad === "challenge" ? encode(new Uint8Array(32)) : challenge,
        {
          ...(bad === "origin" ? { origin: "https://evil.test" } : {}),
          ...(bad === "rp" ? { rp: "evil.test" } : {}),
          ...(bad === "uv" ? { uv: false } : {}),
        },
      );
      expect(
        (await store.finish(origin, flow.id, flow.key, response)).status,
      ).toBe(403);
      expect(
        (await store.finish(origin, flow.id, flow.key, response)).status,
      ).not.toBe(200);
    }
  });
  it("rejects wrong user handle, authentication origin/RP/challenge, missing UV and expected account mismatch", async () => {
    const { store, virtual, user } = await enroll();
    for (const bad of [
      "origin",
      "rp",
      "challenge",
      "uv",
      "handle",
      "account",
    ]) {
      const flow = await begin(
        store,
        bad === "account" ? "0".repeat(64) : undefined,
      );
      const options = await store.options(origin, flow.id, flow.key, "login"),
        challenge = (options.body as any).options.challenge;
      const assertion = await virtual.assertion(
        bad === "challenge" ? encode(new Uint8Array(32)) : challenge,
        bad === "handle" ? encode(new Uint8Array(32)) : user,
        {
          ...(bad === "origin" ? { origin: "https://evil.test" } : {}),
          ...(bad === "rp" ? { rp: "evil.test" } : {}),
          ...(bad === "uv" ? { uv: false } : {}),
          counter: 1,
        },
      );
      expect(
        (await store.finish(origin, flow.id, flow.key, assertion)).status,
      ).toBe(403);
    }
  });
  it("rotates refresh families, treats refresh as non-fresh and revokes on actual spent-token replay only", async () => {
    const { store, tokens } = await enroll(),
      now = Date.now() + 20_000;
    const wrong = tokens.refresh_token.slice(0, -64) + "0".repeat(64);
    expect((await store.refresh(origin, wrong, now)).status).toBe(401);
    expect(
      await store.identity(origin, tokens.access_token, now),
    ).not.toBeNull();
    const renewed = await store.refresh(origin, tokens.refresh_token, now);
    expect(renewed.status).toBe(200);
    expect(await store.identity(origin, tokens.access_token, now)).toBeNull();
    const next = renewed.body as any;
    expect(
      (await store.identity(origin, next.access_token, now))?.authenticatedAt,
    ).toBeNull();
    expect(
      (await store.refresh(origin, tokens.refresh_token, now + 20_000)).status,
    ).toBe(401);
    expect(
      await store.identity(origin, next.access_token, now + 20_000),
    ).toBeNull();
    expect(
      (await store.refresh(origin, next.refresh_token, now + 40_000)).status,
    ).toBe(401);
  });
  it("binds flow capabilities and exact loopback redirect and checks PKCE before consumption", async () => {
    expect(configuration("http://passkey.test")).toBeNull();
    expect(configuration("https://127.0.0.1")).toBeNull();
    const { store, flow, code } = await enroll();
    expect(
      (await store.options(origin, flow.id, "0".repeat(64), "login")).status,
    ).toBe(403);
    expect(
      (
        await store.begin(origin, {
          code_challenge: encode(await sha("b".repeat(64))),
          redirect_uri: "https://evil.test/callback",
          state: random(),
        })
      ).status,
    ).toBe(400);
    const another = await begin(store),
      virtual = await authenticator(),
      options = await store.options(origin, another.id, another.key, "register", "", Date.now(), `${random()}@homelab.test`);
    const finished = await store.finish(
      origin,
      another.id,
      another.key,
      await virtual.registration((options.body as any).options.challenge),
    );
    const freshCode = new URL((finished.body as any).redirect).searchParams.get(
      "code",
    )!;
    expect(
      (
        await store.exchange(
          origin,
          freshCode,
          "b".repeat(64),
          another.redirect,
        )
      ).status,
    ).toBe(401);
    expect(
      (
        await store.exchange(
          origin,
          freshCode,
          another.verifier,
          another.redirect + "?other",
        )
      ).status,
    ).toBe(401);
    expect(
      (
        await store.exchange(
          origin,
          freshCode,
          another.verifier,
          another.redirect,
        )
      ).status,
    ).toBe(200);
    expect(
      (await store.exchange(origin, code, flow.verifier, flow.redirect)).status,
    ).toBe(401);
  });
});

it("serves built-in login through the private ingress without an OIDC provider", async () => {
  const { centralPrivateFetch, centralFetch } =
    await import("../src/v2/routes");
  const settings = {
    ...env,
    CENTRAL_ENABLED: "1",
    CENTRAL_PRIVATE_CORE: "1",
    CENTRAL_ORIGIN: origin,
    OIDC_ISSUER: "",
    OIDC_JWKS_URL: "",
  };
  const call = (
    path: string,
    body?: object,
    headers: Record<string, string> = {},
  ) =>
    centralPrivateFetch(
      new Request(origin + path, {
        method: body ? "POST" : "GET",
        headers: {
          ...(body ? { "content-type": "application/json" } : {}),
          ...headers,
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      }),
      settings,
    );
  const info = await call("/v2/info");
  expect(info.status).toBe(200);
  expect(await info.json()).toMatchObject({
    default_auth: "passkey",
    passkey: { origin, rp_id: "passkey.test" },
    oidc: null,
  });
  const verifier = "c".repeat(64),
    redirect = "http://127.0.0.1:38172/passkey/callback",
    state = random();
  const begun = await call("/v2/auth/passkey/authorize", {
    code_challenge: encode(await sha(verifier)),
    redirect_uri: redirect,
    state,
  });
  expect(begun.status).toBe(201);
  const url = new URL(((await begun.json()) as any).url),
    flow = url.searchParams.get("flow")!,
    key = new URLSearchParams(url.hash.slice(1)).get("key")!;
  const page = await call(url.pathname + url.search);
  expect(page.status).toBe(200);
  expect(page.headers.get("content-security-policy")).toContain(
    "frame-ancestors 'none'",
  );
  expect(await page.text()).not.toContain(key);
  expect(
    (
      await call(
        "/v2/auth/passkey/options",
        { flow, kind: "register", email: "browser@homelab.test" },
        { origin: "https://evil.test", "x-lunport-flow": key },
      )
    ).status,
  ).toBe(403);
  const options = await call(
    "/v2/auth/passkey/options",
    { flow, kind: "register", email: "browser@homelab.test" },
    { origin, "x-lunport-flow": key },
  );
  expect(options.status).toBe(200);
  const virtual = await authenticator(),
    response = await virtual.registration(
      ((await options.json()) as any).options.challenge,
    );
  const completed = await call(
    "/v2/auth/passkey/finish",
    { flow, response },
    { origin, "x-lunport-flow": key },
  );
  expect(completed.status).toBe(200);
  const callback = new URL(((await completed.json()) as any).redirect);
  expect(callback.searchParams.get("state")).toBe(state);
  const grant = await call("/v2/auth/passkey/exchange", {
    code: callback.searchParams.get("code"),
    verifier,
    redirect_uri: redirect,
  });
  expect(grant.status).toBe(200);
  const tokens = (await grant.json()) as any;
  const fixture = (await import("../../fixtures/central-sync-v2.json")).default;
  const registered = await call(
    "/v2/register",
    {
      device: fixture.genesis.first,
      name: "Synthetic Passkey client",
      credential: random(),
      session_id: random(16),
      session_secret: random(),
    },
    { authorization: "Bearer " + tokens.access_token },
  );
  expect(registered.status).toBe(200);
  expect(await registered.json()).toMatchObject({
    account_locator: expect.stringMatching(/^[0-9a-f]{64}$/),
  });
  expect(
    (
      await centralFetch(
        new Request(origin + "/v2/auth/passkey/page?flow=" + flow),
        settings,
      )
    ).status,
  ).not.toBe(200);
});

it("requires fresh Passkey proof to manage backups, preserves the signing credential and revokes login families on removal", async () => {
  const { store, virtual, user, tokens, response: primary } = await enroll();
  const flow = await begin(store);
  expect((await store.management(origin, flow.id, flow.key)).status).toBe(403);
  expect((await store.options(origin, flow.id, flow.key, "add")).status).toBe(
    403,
  );
  expect((await store.complete(origin, flow.id, flow.key)).status).toBe(403);
  const options = await store.options(origin, flow.id, flow.key, "manage");
  const finished = await store.finish(
    origin,
    flow.id,
    flow.key,
    await virtual.assertion((options.body as any).options.challenge, user),
  );
  expect(finished.status).toBe(200);
  const managementKey = (finished.body as any).management_key;
  expect(managementKey).toMatch(/^[0-9a-f]{64}$/);
  expect(finished.body).toMatchObject({
    managing: true,
    credentials: [{ id: primary.id, current: true }],
  });
  expect((finished.body as any).redirect).toBeUndefined();
  expect(
    (await store.remove(origin, flow.id, flow.key, primary.id, managementKey))
      .status,
  ).toBe(409);
  expect(
    (await store.options(origin, flow.id, flow.key, "register", "", Date.now(), `${random()}@homelab.test`)).status,
  ).toBe(403);
  const backup = await authenticator(),
    add = await store.options(origin, flow.id, flow.key, "add", managementKey);
  expect((add.body as any).options.user.id).toBe(user);
  expect((add.body as any).options.excludeCredentials).toEqual([
    { id: primary.id, type: "public-key" },
  ]);
  const backupResponse = await backup.registration(
    (add.body as any).options.challenge,
  );
  expect(
    (
      await store.finish(
        origin,
        flow.id,
        flow.key,
        backupResponse,
        managementKey,
      )
    ).body,
  ).toMatchObject({ managing: true });
  expect(
    (await store.management(origin, flow.id, "0".repeat(64), managementKey))
      .status,
  ).toBe(403);
  expect(
    (
      await store.management(
        origin,
        flow.id,
        flow.key,
        managementKey,
        Date.now() + 300_001,
      )
    ).status,
  ).toBe(403);
  const otherFlow = await begin(store),
    otherOptions = await store.options(origin, otherFlow.id, otherFlow.key, "register", "", Date.now(), `${random()}@homelab.test`),
    other = await authenticator();
  const otherResponse = await other.registration(
    (otherOptions.body as any).options.challenge,
  );
  expect(
    (await store.finish(origin, otherFlow.id, otherFlow.key, otherResponse))
      .status,
  ).toBe(200);
  expect(
    (
      await store.remove(
        origin,
        flow.id,
        flow.key,
        otherResponse.id,
        managementKey,
      )
    ).status,
  ).toBe(409);
  const login = await begin(store),
    loginOptions = await store.options(origin, login.id, login.key, "login");
  const backupLogin = await store.finish(
    origin,
    login.id,
    login.key,
    await backup.assertion((loginOptions.body as any).options.challenge, user),
  );
  expect(backupLogin.status).toBe(200);
  const pendingCode = new URL(
    (backupLogin.body as any).redirect,
  ).searchParams.get("code")!;
  expect(
    (
      await store.remove(
        origin,
        flow.id,
        flow.key,
        backupResponse.id,
        managementKey,
      )
    ).status,
  ).toBe(200);
  expect(await store.identity(origin, tokens.access_token)).toBeNull();
  expect(
    (await store.exchange(origin, pendingCode, login.verifier, login.redirect))
      .status,
  ).toBe(401);
  const completed = await store.complete(
    origin,
    flow.id,
    flow.key,
    managementKey,
  );
  expect(completed.status).toBe(200);
  expect((await store.complete(origin, flow.id, flow.key)).status).toBe(403);
  const exchanged = await store.exchange(
    origin,
    new URL((completed.body as any).redirect).searchParams.get("code")!,
    flow.verifier,
    flow.redirect,
  );
  expect(exchanged.status).toBe(200);
  expect(
    (await store.logout(origin, (exchanged.body as any).refresh_token)).status,
  ).toBe(200);
  expect(
    await store.identity(origin, (exchanged.body as any).access_token),
  ).toBeNull();
  expect(
    (
      await store.refresh(
        origin,
        (exchanged.body as any).refresh_token,
        Date.now() + 20_000,
      )
    ).status,
  ).toBe(401);
});

it("allows only one concurrent code exchange and expires codes, access tokens and absolute refresh families", async () => {
  const { store, tokens } = await enroll();
  expect(
    await store.identity(origin, tokens.access_token, Date.now() + 300_001),
  ).toBeNull();
  const flow = await begin(store),
    virtual = await authenticator(),
    options = await store.options(origin, flow.id, flow.key, "register", "", Date.now(), `${random()}@homelab.test`);
  const result = await store.finish(
    origin,
    flow.id,
    flow.key,
    await virtual.registration((options.body as any).options.challenge),
  );
  const code = new URL((result.body as any).redirect).searchParams.get("code")!;
  const exchanged = await Promise.all([
    store.exchange(origin, code, flow.verifier, flow.redirect),
    store.exchange(origin, code, flow.verifier, flow.redirect),
  ]);
  expect(exchanged.map((r) => r.status).sort()).toEqual([200, 401]);
  const next = exchanged.find((r) => r.status === 200)!.body as any;
  expect(
    (
      await store.refresh(
        origin,
        next.refresh_token,
        Date.now() + 30 * 86400_000 + 1,
      )
    ).status,
  ).toBe(401);
  const expired = await begin(store),
    expiredOptions = await store.options(origin, expired.id, expired.key, "register", "", Date.now(), `${random()}@homelab.test`);
  const completed = await store.finish(
    origin,
    expired.id,
    expired.key,
    await (
      await authenticator()
    ).registration((expiredOptions.body as any).options.challenge),
  );
  const expiredCode = new URL(
    (completed.body as any).redirect,
  ).searchParams.get("code")!;
  expect(
    (
      await store.exchange(
        origin,
        expiredCode,
        expired.verifier,
        expired.redirect,
        Date.now() + 60_001,
      )
    ).status,
  ).toBe(401);
});

it("does not grant credential management to a party that only knows the pre-authentication flow link", async () => {
  const { store, virtual, user } = await enroll();
  const flow = await begin(store),
    options = await store.options(origin, flow.id, flow.key, "manage");
  const verified = await store.finish(
    origin,
    flow.id,
    flow.key,
    await virtual.assertion((options.body as any).options.challenge, user),
  );
  expect(verified.status).toBe(200);
  const managementKey = (verified.body as any).management_key;
  expect(managementKey).toMatch(/^[0-9a-f]{64}$/);
  // The link initiator knows flow.id and flow.key but cannot observe the user's same-origin
  // verification response. Those original link credentials must not manage the account.
  expect((await store.options(origin, flow.id, flow.key, "add")).status).toBe(
    403,
  );
  expect((await store.management(origin, flow.id, flow.key)).status).toBe(403);
  expect((await store.complete(origin, flow.id, flow.key)).status).toBe(403);
  expect(
    (await store.options(origin, flow.id, flow.key, "add", "0".repeat(64)))
      .status,
  ).toBe(403);
  const state = await store.management(
    origin,
    flow.id,
    flow.key,
    managementKey,
  );
  expect(state.status).toBe(200);
  expect((state.body as any).management_key).toBeUndefined();
  const added = await store.options(
    origin,
    flow.id,
    flow.key,
    "add",
    managementKey,
  );
  expect(added.status).toBe(200);
  const response = await (
    await authenticator()
  ).registration((added.body as any).options.challenge);
  expect((await store.finish(origin, flow.id, flow.key, response)).status).toBe(
    403,
  );
  const completed = await store.finish(
    origin,
    flow.id,
    flow.key,
    response,
    managementKey,
  );
  expect(completed.status).toBe(200);
  expect((completed.body as any).management_key).toBeUndefined();
});


it("uses a normalized email as an unverified name while keeping the opaque identity and Passkey authentication", async () => {
  const {store, email, tokens, flow} = await enroll("  Owner+Lab@Example.Test  ");
  const rows = await runInDurableObject(store, (_instance, state) => state.storage.sql.exec<{email:string,subject:string}>("SELECT email,subject FROM auth_accounts").toArray());
  expect(rows).toEqual([{email:"owner+lab@example.test",subject:tokens.subject}]);
  expect(tokens.subject).toMatch(/^[0-9a-f]{64}$/);
  expect(JSON.stringify(tokens)).not.toContain(email);
  const fresh = await begin(store);
  expect((await store.options(origin,fresh.id,fresh.key,"register","",Date.now(),"OWNER+LAB@example.test")).status).toBe(409);
  expect((await store.context(origin, fresh.id, fresh.key)).body).toMatchObject({account_name:null});
  const identity = await store.identity(origin,tokens.access_token);
  const pinned = await begin(store,identity!.locator);
  expect((await store.context(origin,pinned.id,pinned.key)).body).toMatchObject({existing_only:true,account_name:"owner+lab@example.test"});
  expect((await store.options(origin,pinned.id,pinned.key,"register","",Date.now(),"another@example.test")).status).toBe(403);
  expect((await store.context(origin,flow.id,flow.key)).status).toBe(403);
});
it("requires a valid email for registration and never exposes password or email-based recovery endpoints", async () => {
  const store=env.PASSKEY.getByName(random()), flow=await begin(store);
  for (const email of [undefined, "", "name", "a@b@c.test", "x\r\nBcc: other@example.test", ".a@example.test", "a..b@example.test", "a@-bad.test", "a@bad..test", "x".repeat(65)+"@example.test"]) {
    expect((await store.options(origin,flow.id,flow.key,"register","",Date.now(),email)).status).toBe(400);
  }
  const options=await store.options(origin,flow.id,flow.key,"register","",Date.now(),"owner@example.test");
  expect((options.body as any).options.user.name).toBe("owner@example.test");
  expect((options.body as any).options.user.id).not.toContain("owner");
});
it("atomically binds only one account to a name when registration ceremonies race", async () => {
  const store=env.PASSKEY.getByName(random());
  const flows=await Promise.all([begin(store),begin(store)]), authenticators=await Promise.all([authenticator(),authenticator()]);
  const options=await Promise.all(flows.map((f)=>store.options(origin,f.id,f.key,"register","",Date.now(),"same@example.test")));
  const responses=await Promise.all(authenticators.map((a,i)=>a.registration((options[i].body as any).options.challenge)));
  const results=await Promise.all(flows.map((f,i)=>store.finish(origin,f.id,f.key,responses[i])));
  expect(results.map(r=>r.status).sort()).toEqual([200,409]);
  const counts=await runInDurableObject(store, (_instance,state)=>({accounts:state.storage.sql.exec<{n:number}>("SELECT count(*) n FROM auth_accounts").one().n,credentials:state.storage.sql.exec<{n:number}>("SELECT count(*) n FROM passkeys").one().n}));
  expect(counts).toEqual({accounts:1,credentials:1});
});
