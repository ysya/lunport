/** Built-in account authentication only. This store never holds device/Vault/SSH private keys. */
import { DurableObject } from "cloudflare:workers";
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import { hash, hex } from "../protocol";
import type { Identity } from "../auth";
import { accountName } from "./account";
// A concrete RPC-serializable object boundary; unknown would erase the DO stub return type.
type Result = { status: number; body?: object };
import {
  configuration,
  random,
  encode,
  decode,
  validBegin,
  locator,
  pkce,
  token,
  FLOW_MS,
  CODE_MS,
  ACCESS_MS,
  FAMILY_MS,
  type Begin,
  type Config,
} from "./protocol";
type Flow = Begin & {
  id: string;
  browser: string;
  expires: number;
  options: number;
  subject: string | null;
  email?: string;
  kind: "register" | "login" | "manage" | "add" | null;
  manager?: { subject: string; witness: string; at: number; key_hash: string };
  challenge: string | null;
  consumed: boolean;
  completed: boolean;
};
type Credential = {
  id: string;
  subject: string;
  public_key: string;
  counter: number;
  device_type: string;
  backed_up: number;
  version: number;
};
type Family = {
  id: string;
  subject: string;
  refresh_hash: string;
  access_hash: string;
  access_expires: number;
  expires: number;
  revoked: number;
  authenticated_at: number | null;
  renewed: number;
};
const SCHEMA = `CREATE TABLE IF NOT EXISTS auth_meta(id INTEGER PRIMARY KEY CHECK(id=1),origin TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_accounts(subject TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,locator TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS passkeys(id TEXT PRIMARY KEY,subject TEXT NOT NULL,public_key TEXT NOT NULL,counter INTEGER NOT NULL,device_type TEXT NOT NULL,backed_up INTEGER NOT NULL,version INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS passkey_subject ON passkeys(subject);
CREATE TABLE IF NOT EXISTS flows(id TEXT PRIMARY KEY,value TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS codes(id TEXT PRIMARY KEY,secret_hash TEXT NOT NULL,subject TEXT NOT NULL,challenge TEXT NOT NULL,redirect TEXT NOT NULL,expires INTEGER NOT NULL,authenticated_at INTEGER NOT NULL,credential TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS auth_families(id TEXT PRIMARY KEY,subject TEXT NOT NULL,refresh_hash TEXT NOT NULL,access_hash TEXT NOT NULL,access_expires INTEGER NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL,authenticated_at INTEGER,renewed INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS spent_refresh(family TEXT NOT NULL,secret_hash TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(family,secret_hash));`;
function failed(status = 400): Result {
  return { status };
}
export class PasskeyStore extends DurableObject<Env> {
  private open(origin: string): Config {
    const cfg = configuration(origin);
    if (!cfg) throw new Error("Invalid authentication origin.");
    this.ctx.storage.sql.exec(SCHEMA);
    const old = this.ctx.storage.sql
      .exec<{ origin: string }>("SELECT origin FROM auth_meta WHERE id=1")
      .toArray()[0];
    if (old && old.origin !== origin)
      throw new Error(
        "Authentication origin changed; preserve the existing store.",
      );
    if (!old)
      this.ctx.storage.sql.exec("INSERT INTO auth_meta VALUES(1,?)", origin);
    return cfg;
  }
  private clean(now: number) {
    this.ctx.storage.sql.exec("DELETE FROM flows WHERE expires<=?", now);
    this.ctx.storage.sql.exec("DELETE FROM codes WHERE expires<=?", now);
    this.ctx.storage.sql.exec(
      "DELETE FROM spent_refresh WHERE expires<=?",
      now,
    );
    this.ctx.storage.sql.exec(
      "DELETE FROM auth_families WHERE expires<=?",
      now,
    );
  }
  private count(table: "flows" | "auth_families"): number {
    return this.ctx.storage.sql
      .exec<{ n: number }>(`SELECT count(*) n FROM ${table}`)
      .one().n;
  }
  private readFlow(id: string): Flow | null {
    const row = this.ctx.storage.sql
      .exec<{ value: string }>("SELECT value FROM flows WHERE id=?", id)
      .toArray()[0];
    return row ? (JSON.parse(row.value) as Flow) : null;
  }
  private saveFlow(flow: Flow) {
    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO flows VALUES(?,?,?)",
      flow.id,
      JSON.stringify(flow),
      flow.expires,
    );
  }
  private async flow(
    id: string,
    key: string,
    now: number,
  ): Promise<Flow | null> {
    if (!hex(id, 32) || !hex(key, 64)) return null;
    const digest = await hash(new TextEncoder().encode(key));
    const flow = this.readFlow(id);
    return flow &&
      !flow.completed &&
      flow.expires > now &&
      flow.browser === digest
      ? flow
      : null;
  }
  async begin(origin: string, input: Begin, now = Date.now()): Promise<Result> {
    this.open(origin);
    this.clean(now);
    if (!validBegin(input)) return failed();
    if (this.count("flows") >= 4096) return failed(429);
    const id = random(16),
      key = random(),
      browser = await hash(new TextEncoder().encode(key));
    this.ctx.storage.transactionSync(() => {
      if (this.count("flows") >= 4096)
        throw new Error("Authentication capacity reached.");
      this.saveFlow({
        ...input,
        id,
        browser,
        expires: now + FLOW_MS,
        options: 0,
        subject: null,
        kind: null,
        challenge: null,
        consumed: false,
        completed: false,
      });
    });
    return {
      status: 201,
      body: {
        url: `${origin}/v1/auth/passkey/page?flow=${id}#key=${key}`,
        expires_in: FLOW_MS / 1000,
      },
    };
  }
  async context(origin: string, id: string, key: string): Promise<Result> {
    this.open(origin);
    const flow = await this.flow(id, key, Date.now());
    return flow
      ? { status: 200, body: { existing_only: !!flow.expected_locator, account_name: flow.expected_locator ? this.ctx.storage.sql.exec<{email:string}>("SELECT email FROM auth_accounts WHERE locator=?", flow.expected_locator).toArray()[0]?.email ?? null : null } }
      : failed(403);
  }
  async options(
    origin: string,
    id: string,
    key: string,
    kind: "register" | "login" | "manage" | "add",
    managementKey = "",
    now = Date.now(),
    email?: string,
  ): Promise<Result> {
    const cfg = this.open(origin),
      flow = await this.flow(id, key, now),
      managementHash = await this.managementHash(managementKey);
    if (
      !flow ||
      !["register", "login", "manage", "add"].includes(kind) ||
      flow.options >= 12 ||
      (kind === "add"
        ? !this.manager(flow, now, managementHash)
        : !!flow.manager) ||
      (kind === "register" && flow.expected_locator)
    )
      return failed(403);
    const name = kind === "register" ? accountName(email) : null;
    if (kind === "register" && !name) return failed();
    if (name && this.ctx.storage.sql.exec("SELECT subject FROM auth_accounts WHERE email=?", name).toArray().length)
      return { status: 409, body: { error: "account_exists" } };
    const subject =
      kind === "register"
        ? random()
        : kind === "add"
          ? flow.manager!.subject
          : null;
    if (kind === "add" && this.credentials(subject!).length >= 8)
      return failed(409);
    const options =
      kind === "register" || kind === "add"
        ? await generateRegistrationOptions({
            rpName: "Lunport",
            rpID: cfg.rpId,
            userID: Uint8Array.from(subject!.match(/../g)!, (b) =>
              parseInt(b, 16),
            ),
            userName: name ?? this.ctx.storage.sql.exec<{email:string}>("SELECT email FROM auth_accounts WHERE subject=?", subject!).toArray()[0]?.email ?? `Lunport ${subject!.slice(0, 12)}`,
            excludeCredentials: this.credentials(subject!).map((c) => ({
              id: c.id,
            })),
            attestationType: "none",
            supportedAlgorithmIDs: [-7],
            authenticatorSelection: {
              residentKey: "required",
              userVerification: "required",
            },
            timeout: 120_000,
          })
        : await generateAuthenticationOptions({
            rpID: cfg.rpId,
            userVerification: "required",
            timeout: 120_000,
          });
    const accepted = this.ctx.storage.transactionSync(() => {
      const current = this.readFlow(id);
      if (
        !current ||
        current.expires <= Math.max(now, Date.now()) ||
        current.completed ||
        current.options !== flow.options ||
        (kind === "add"
          ? !this.manager(current, Math.max(now, Date.now()), managementHash)
          : !!current.manager)
      )
        return false;
      this.saveFlow({
        ...current,
        options: current.options + 1,
        subject,
        ...(name ? { email: name } : {}),
        kind,
        challenge: options.challenge,
        consumed: false,
      });
      return true;
    });
    return accepted ? { status: 200, body: { options } } : failed(409);
  }
  async finish(
    origin: string,
    id: string,
    key: string,
    response: RegistrationResponseJSON | AuthenticationResponseJSON,
    managementKey = "",
    now = Date.now(),
  ): Promise<Result> {
    const cfg = this.open(origin),
      flow = await this.flow(id, key, now),
      managementHash = await this.managementHash(managementKey);
    if (
      !flow ||
      !flow.challenge ||
      !flow.kind ||
      flow.consumed ||
      (flow.kind === "register" && !accountName(flow.email)) ||
      (flow.kind === "add" && !this.manager(flow, now, managementHash)) ||
      JSON.stringify(response).length > 32768
    )
      return failed(403);
    // Consume before asynchronous signature verification. A failed ceremony needs a new challenge.
    const claimed = this.ctx.storage.transactionSync(() => {
      const current = this.readFlow(id);
      if (
        !current ||
        current.completed ||
        current.expires <= now ||
        current.consumed ||
        current.challenge !== flow.challenge ||
        (flow.kind === "add" &&
          !this.manager(current, Math.max(now, Date.now()), managementHash))
      )
        return false;
      this.saveFlow({ ...current, consumed: true });
      return true;
    });
    if (!claimed) return failed(409);
    let subject: string,
      credential: Credential | undefined,
      previous: Credential | undefined;
    try {
      const raw = decode(response.response.clientDataJSON, 8192);
      if (!raw) return failed();
      const client = JSON.parse(
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(raw),
      );
      if (
        (client.crossOrigin !== undefined && client.crossOrigin !== false) ||
        client.topOrigin !== undefined
      )
        return failed(403);
      if (flow.kind === "register" || flow.kind === "add") {
        if (flow.kind === "add" && !this.manager(flow, now, managementHash))
          return failed(403);
        const verified = await verifyRegistrationResponse({
          response: response as RegistrationResponseJSON,
          expectedChallenge: flow.challenge,
          expectedOrigin: origin,
          expectedRPID: cfg.rpId,
          requireUserVerification: true,
          supportedAlgorithmIDs: [-7],
        });
        if (
          !verified.verified ||
          !verified.registrationInfo.userVerified ||
          !flow.subject
        )
          return failed(403);
        const info = verified.registrationInfo;
        if (
          !decode(info.credential.id, 1024) ||
          info.credential.publicKey.length > 4096
        )
          return failed();
        subject = flow.subject;
        credential = {
          id: info.credential.id,
          subject,
          public_key: encode(info.credential.publicKey),
          counter: info.credential.counter,
          device_type: info.credentialDeviceType,
          backed_up: info.credentialBackedUp ? 1 : 0,
          version: 1,
        };
      } else {
        if (typeof response.id !== "string" || !decode(response.id, 1024))
          return failed();
        previous = this.ctx.storage.sql
          .exec<Credential>("SELECT * FROM passkeys WHERE id=?", response.id)
          .toArray()[0];
        if (!previous) return failed(403);
        const assertion = response as AuthenticationResponseJSON;
        const user = decode(assertion.response.userHandle, 32);
        if (
          !user ||
          Array.from(user, (b) => b.toString(16).padStart(2, "0")).join("") !==
            previous.subject
        )
          return failed(403);
        const verified = await verifyAuthenticationResponse({
          response: assertion,
          expectedChallenge: flow.challenge,
          expectedOrigin: origin,
          expectedRPID: cfg.rpId,
          requireUserVerification: true,
          credential: {
            id: previous.id,
            publicKey: decode(previous.public_key, 4096)!,
            counter: previous.counter,
          },
        });
        if (
          !verified.verified ||
          !verified.authenticationInfo.userVerified ||
          verified.authenticationInfo.credentialDeviceType !==
            previous.device_type
        )
          return failed(403);
        subject = previous.subject;
        credential = {
          ...previous,
          counter: verified.authenticationInfo.newCounter,
          backed_up: verified.authenticationInfo.credentialBackedUp ? 1 : 0,
          version: previous.version + 1,
        };
      }
      if (
        flow.expected_locator &&
        (await locator(origin, subject)) !== flow.expected_locator
      )
        return failed(403);
    } catch {
      return failed(403);
    }
    const accountLocator = await locator(origin, subject);
    const codeId = random(16),
      codeSecret = random(),
      digest = await hash(new TextEncoder().encode(codeSecret));
    const managerSecret = flow.kind === "manage" ? random() : managementKey;
    const managerSecretHash =
      flow.kind === "manage"
        ? await this.managementHash(managerSecret)
        : managementHash;
    const accepted = this.ctx.storage.transactionSync(() => {
      const current = this.readFlow(id);
      if (
        !current ||
        !current.consumed ||
        current.completed ||
        current.challenge !== flow.challenge ||
        current.email !== flow.email ||
        current.expires <= Math.max(now, Date.now())
      )
        return false;
      if (flow.kind === "register") {
        if (this.ctx.storage.sql.exec("SELECT subject FROM auth_accounts WHERE email=?", flow.email!).toArray().length) return false;
        // Commit the name and first credential together, after verified WebAuthn and all capacity checks below.
      }
      if (previous) {
        const live = this.ctx.storage.sql
          .exec<Credential>("SELECT * FROM passkeys WHERE id=?", previous.id)
          .toArray()[0];
        if (!live || live.version !== previous.version) return false;
        this.ctx.storage.sql.exec(
          "UPDATE passkeys SET counter=?,backed_up=?,version=? WHERE id=?",
          credential!.counter,
          credential!.backed_up,
          credential!.version,
          credential!.id,
        );
      } else {
        if (
          this.ctx.storage.sql
            .exec("SELECT id FROM passkeys WHERE id=?", credential!.id)
            .toArray().length ||
          this.ctx.storage.sql
            .exec<{ n: number }>("SELECT count(*) n FROM passkeys")
            .one().n >= 16384 ||
          this.credentials(subject).length >= 8 ||
          (flow.kind === "add" &&
            !this.manager(current, Math.max(now, Date.now()), managementHash))
        )
          return false;
        if (flow.kind === "register")
          this.ctx.storage.sql.exec("INSERT INTO auth_accounts VALUES(?,?,?)", subject, flow.email!, accountLocator);
        this.ctx.storage.sql.exec(
          "INSERT INTO passkeys VALUES(?,?,?,?,?,?,?)",
          credential!.id,
          subject,
          credential!.public_key,
          credential!.counter,
          credential!.device_type,
          credential!.backed_up,
          credential!.version,
        );
      }
      if (flow.kind === "manage" || flow.kind === "add") {
        this.saveFlow({
          ...current,
          manager: current.manager ?? {
            subject,
            witness: credential!.id,
            at: now,
            key_hash: managerSecretHash,
          },
        });
        return true;
      }
      this.saveFlow({ ...current, completed: true });
      this.ctx.storage.sql.exec(
        "INSERT INTO codes VALUES(?,?,?,?,?,?,?,?)",
        codeId,
        digest,
        subject,
        flow.code_challenge,
        flow.redirect_uri,
        now + CODE_MS,
        now,
        credential!.id,
      );
      return true;
    });
    if (!accepted) return failed(409);
    if (flow.kind === "manage" || flow.kind === "add") {
      const result = await this.management(origin, id, key, managerSecret, now);
      if (flow.kind === "manage" && result.status === 200)
        return {
          status: 200,
          body: { ...result.body, management_key: managerSecret },
        };
      return result;
    }
    const callback = new URL(flow.redirect_uri);
    callback.searchParams.set("code", `lpkc1.${codeId}.${codeSecret}`);
    callback.searchParams.set("state", flow.state);
    return { status: 200, body: { redirect: callback.href } };
  }
  private credentials(subject: string): Credential[] {
    return this.ctx.storage.sql
      .exec<Credential>(
        "SELECT * FROM passkeys WHERE subject=? ORDER BY id",
        subject,
      )
      .toArray();
  }
  private async managementHash(key: string): Promise<string> {
    return hex(key, 64) ? hash(new TextEncoder().encode(key)) : "";
  }
  private manager(flow: Flow, now: number, digest: string): boolean {
    return (
      !!flow.manager &&
      flow.manager.key_hash === digest &&
      flow.expires > now &&
      flow.manager.at <= now &&
      now - flow.manager.at < FLOW_MS &&
      this.credentials(flow.manager.subject).some(
        (c) => c.id === flow.manager!.witness,
      )
    );
  }
  async management(
    origin: string,
    id: string,
    key: string,
    managementKey = "",
    now = Date.now(),
  ): Promise<Result> {
    this.open(origin);
    const flow = await this.flow(id, key, now),
      managementHash = await this.managementHash(managementKey);
    if (!flow || !this.manager(flow, now, managementHash)) return failed(403);
    return {
      status: 200,
      body: {
        managing: true,
        account: this.ctx.storage.sql.exec<{email:string}>("SELECT email FROM auth_accounts WHERE subject=?", flow.manager!.subject).toArray()[0]?.email ?? flow.manager!.subject.slice(0, 12),
        credentials: this.credentials(flow.manager!.subject).map((c) => ({
          id: c.id,
          current: c.id === flow.manager!.witness,
          backed_up: !!c.backed_up,
        })),
      },
    };
  }
  async remove(
    origin: string,
    id: string,
    key: string,
    credential: string,
    managementKey = "",
    now = Date.now(),
  ): Promise<Result> {
    this.open(origin);
    const flow = await this.flow(id, key, now),
      managementHash = await this.managementHash(managementKey);
    if (
      !flow ||
      !this.manager(flow, now, managementHash) ||
      !decode(credential, 1024)
    )
      return failed(403);
    const removed = this.ctx.storage.transactionSync(() => {
      const current = this.readFlow(id);
      if (
        !current ||
        current.completed ||
        !this.manager(current, Math.max(now, Date.now()), managementHash) ||
        credential === current.manager!.witness
      )
        return false;
      if (
        !this.credentials(current.manager!.subject).some(
          (c) => c.id === credential,
        )
      )
        return false;
      this.ctx.storage.sql.exec(
        "DELETE FROM passkeys WHERE id=? AND subject=?",
        credential,
        current.manager!.subject,
      );
      // Removing a credential also invalidates existing account-login families. Device/Vault authority is separate.
      this.ctx.storage.sql.exec(
        "UPDATE auth_families SET revoked=1 WHERE subject=?",
        current.manager!.subject,
      );
      this.ctx.storage.sql.exec(
        "DELETE FROM codes WHERE credential=?",
        credential,
      );
      return true;
    });
    return removed
      ? this.management(origin, id, key, managementKey, now)
      : failed(409);
  }
  async complete(
    origin: string,
    id: string,
    key: string,
    managementKey = "",
    now = Date.now(),
  ): Promise<Result> {
    this.open(origin);
    const flow = await this.flow(id, key, now),
      managementHash = await this.managementHash(managementKey);
    if (!flow || !this.manager(flow, now, managementHash)) return failed(403);
    const codeId = random(16),
      codeSecret = random(),
      digest = await hash(new TextEncoder().encode(codeSecret));
    const accepted = this.ctx.storage.transactionSync(() => {
      const current = this.readFlow(id);
      if (
        !current ||
        current.completed ||
        !this.manager(current, Math.max(now, Date.now()), managementHash)
      )
        return false;
      this.saveFlow({ ...current, completed: true });
      this.ctx.storage.sql.exec(
        "INSERT INTO codes VALUES(?,?,?,?,?,?,?,?)",
        codeId,
        digest,
        current.manager!.subject,
        current.code_challenge,
        current.redirect_uri,
        now + CODE_MS,
        current.manager!.at,
        current.manager!.witness,
      );
      return true;
    });
    if (!accepted) return failed(409);
    const callback = new URL(flow.redirect_uri);
    callback.searchParams.set("code", `lpkc1.${codeId}.${codeSecret}`);
    callback.searchParams.set("state", flow.state);
    return { status: 200, body: { redirect: callback.href } };
  }
  async exchange(
    origin: string,
    code: string,
    verifier: string,
    redirect: string,
    now = Date.now(),
  ): Promise<Result> {
    this.open(origin);
    this.clean(now);
    const parsed = token(code, "lpkc1");
    if (!parsed) return failed(401);
    const row = this.ctx.storage.sql
      .exec<{
        secret_hash: string;
        subject: string;
        challenge: string;
        redirect: string;
        expires: number;
        authenticated_at: number;
        credential: string;
      }>("SELECT * FROM codes WHERE id=?", parsed.family)
      .toArray()[0];
    if (
      !row ||
      row.expires <= now ||
      row.redirect !== redirect ||
      row.secret_hash !==
        (await hash(new TextEncoder().encode(parsed.secret))) ||
      !(await pkce(verifier, row.challenge))
    )
      return failed(401);
    const family = random(16),
      refresh = random(),
      access = random();
    const rh = await hash(new TextEncoder().encode(refresh)),
      ah = await hash(new TextEncoder().encode(access));
    const accepted = this.ctx.storage.transactionSync(() => {
      const live = this.ctx.storage.sql
        .exec(
          "SELECT id FROM codes WHERE id=? AND expires>?",
          parsed.family,
          now,
        )
        .toArray()[0];
      if (
        !live ||
        !this.credentials(row.subject).some((c) => c.id === row.credential)
      )
        return false;
      this.ctx.storage.sql.exec("DELETE FROM codes WHERE id=?", parsed.family);
      const count = this.ctx.storage.sql
        .exec<{ n: number }>(
          "SELECT count(*) n FROM auth_families WHERE subject=? AND revoked=0",
          row.subject,
        )
        .one().n;
      if (count >= 64 || this.count("auth_families") >= 16384) return false;
      this.ctx.storage.sql.exec(
        "INSERT INTO auth_families VALUES(?,?,?,?,?,?,?,?,?)",
        family,
        row.subject,
        rh,
        ah,
        now + ACCESS_MS,
        now + FAMILY_MS,
        0,
        row.authenticated_at,
        now,
      );
      return true;
    });
    return accepted
      ? this.tokens(origin, row.subject, family, access, refresh)
      : failed(401);
  }
  private tokens(
    origin: string,
    subject: string,
    family: string,
    access: string,
    refresh: string,
  ): Result {
    return {
      status: 200,
      body: {
        issuer: origin + "/v1/auth/passkey",
        subject,
        access_token: `lpka1.${family}.${access}`,
        refresh_token: `lpkr1.${family}.${refresh}`,
        expires_in: ACCESS_MS / 1000,
      },
    };
  }
  async identity(
    origin: string,
    value: string,
    now = Date.now(),
  ): Promise<Identity | null> {
    this.open(origin);
    const parsed = token(value, "lpka1");
    if (!parsed) return null;
    const secret = await hash(new TextEncoder().encode(parsed.secret));
    const family = this.ctx.storage.sql
      .exec<Family>("SELECT * FROM auth_families WHERE id=?", parsed.family)
      .toArray()[0];
    if (!family) return null;
    const accountLocator = await locator(origin, family.subject);
    // Re-read after hashing so a completed logout/removal/refresh wins over an in-flight identity lookup.
    const live = this.ctx.storage.sql
      .exec<Family>("SELECT * FROM auth_families WHERE id=?", parsed.family)
      .toArray()[0];
    const checkedNow = Math.max(now, Date.now());
    return live &&
      live.subject === family.subject &&
      !live.revoked &&
      live.expires > checkedNow &&
      live.access_expires > checkedNow &&
      live.access_hash === secret
      ? { locator: accountLocator, authenticatedAt: live.authenticated_at }
      : null;
  }
  async refresh(
    origin: string,
    value: string,
    now = Date.now(),
  ): Promise<Result> {
    this.open(origin);
    this.clean(now);
    const parsed = token(value, "lpkr1");
    if (!parsed) return failed(401);
    const digest = await hash(new TextEncoder().encode(parsed.secret)),
      access = random(),
      refresh = random();
    const ah = await hash(new TextEncoder().encode(access)),
      rh = await hash(new TextEncoder().encode(refresh));
    const subject = this.ctx.storage.transactionSync(() => {
      const family = this.ctx.storage.sql
        .exec<Family>("SELECT * FROM auth_families WHERE id=?", parsed.family)
        .toArray()[0];
      if (!family || family.revoked || family.expires <= now) return null;
      if (family.refresh_hash !== digest) {
        if (
          this.ctx.storage.sql
            .exec(
              "SELECT family FROM spent_refresh WHERE family=? AND secret_hash=?",
              parsed.family,
              digest,
            )
            .toArray().length
        )
          this.ctx.storage.sql.exec(
            "UPDATE auth_families SET revoked=1 WHERE id=?",
            parsed.family,
          );
        return null;
      }
      if (
        now - family.renewed < 15_000 ||
        this.ctx.storage.sql
          .exec<{ n: number }>(
            "SELECT count(*) n FROM spent_refresh WHERE family=?",
            parsed.family,
          )
          .one().n >= 10000 ||
        this.ctx.storage.sql
          .exec<{ n: number }>("SELECT count(*) n FROM spent_refresh")
          .one().n >= 262144
      )
        return null;
      this.ctx.storage.sql.exec(
        "INSERT INTO spent_refresh VALUES(?,?,?)",
        parsed.family,
        digest,
        family.expires,
      );
      this.ctx.storage.sql.exec(
        "UPDATE auth_families SET refresh_hash=?,access_hash=?,access_expires=?,authenticated_at=NULL,renewed=? WHERE id=?",
        rh,
        ah,
        now + ACCESS_MS,
        now,
        parsed.family,
      );
      return family.subject;
    });
    return subject
      ? this.tokens(origin, subject, parsed.family, access, refresh)
      : failed(401);
  }
  async logout(origin: string, value: string): Promise<Result> {
    this.open(origin);
    const parsed = token(value, "lpka1") ?? token(value, "lpkr1");
    if (!parsed) return failed(401);
    const digest = await hash(new TextEncoder().encode(parsed.secret));
    this.ctx.storage.sql.exec(
      "UPDATE auth_families SET revoked=1 WHERE id=? AND (access_hash=? OR refresh_hash=?)",
      parsed.family,
      digest,
      digest,
    );
    return { status: 200, body: { signed_out: true } };
  }
}
