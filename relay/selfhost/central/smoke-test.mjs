/** Disposable Docker test only: unique project, synthetic settings, owned volume cleanup. */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
const here = dirname(fileURLToPath(import.meta.url));
const project = "lunport-central-test-" + randomBytes(4).toString("hex");
const temporary = mkdtempSync(join(tmpdir(), project + "-"));
const installation = randomBytes(16).toString("hex"),
  proxyKey = randomBytes(32).toString("hex");
const host = "central-test.invalid";
const targetSecurityImage =
  process.env.SELFHOST_TEST_SECURITY_IMAGE ?? "lunport-central-security:local";
const targetCoreImage =
  process.env.SELFHOST_TEST_CORE_IMAGE ?? "lunport-central-core:local";
let securityImage =
  process.env.SELFHOST_TEST_SOURCE_SECURITY_IMAGE ?? targetSecurityImage;
let coreImage = process.env.SELFHOST_TEST_SOURCE_CORE_IMAGE ?? targetCoreImage;
let initialFloor = process.env.SELFHOST_TEST_SOURCE_SECURITY_IMAGE ? 1 : 2;
const settings = join(temporary, "test.env");
writeFileSync(
  settings,
  `RELAY_DOMAIN=${host}
SECURITY_INSTALLATION=${installation}
SELFHOST_PROXY_KEY=${proxyKey}
CENTRAL_ENABLED=1
SECURITY_IMAGE=${securityImage}
CORE_IMAGE=${coreImage}
`,
  { mode: 0o600 },
);
const base = [
  "compose",
  "-p",
  project,
  "--env-file",
  settings,
  "-f",
  join(here, "compose.yaml"),
];
function docker(args, success = true) {
  const result = spawnSync("docker", args, {
    encoding: "utf8",
    env: {
      ...process.env,
      RELAY_DOMAIN: host,
      SECURITY_INSTALLATION: installation,
      SELFHOST_PROXY_KEY: proxyKey,
      CENTRAL_ENABLED: "1",
      PASSKEY_ENABLED: "1",
      OIDC_ISSUER: "",
      OIDC_JWKS_URL: "",
      OIDC_API_AUDIENCE: "lunport-sync",
      OIDC_NATIVE_CLIENT_ID: "lunport-native",
      OIDC_SYNC_SCOPE: "lunport:sync",
      SECURITY_IMAGE: securityImage,
      CORE_IMAGE: coreImage,
      AUTHORITY_OPERATOR_IMAGE:
        process.env.SELFHOST_TEST_OPERATOR_IMAGE ??
        "lunport-central-authority-operator:local",
      SELFHOST_EXPECTED_REGISTRY: "",
      SELFHOST_CONFIRM_NEW_INSTALLATION: "",
      SELFHOST_MINIMUM_FLOOR: String(initialFloor),
    },
    timeout: 180_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (success && result.status !== 0)
    throw new Error(`Docker action failed (${args[0]}): ${result.stderr}
${result.stdout}`);
  return result;
}
function compose(args, success = true) {
  return docker([...base, ...args], success);
}
function control(action, extra = [], success = true) {
  return compose(
    [
      "--profile",
      "setup",
      "run",
      "--rm",
      ...extra.flatMap(([k, v]) => ["-e", `${k}=${v}`]),
      "control",
      action,
    ],
    success,
  );
}
function json(output) {
  const line = output.stdout
    .split(/\r?\n/)
    .findLast((line) => line.startsWith("{"));
  assert.ok(line, "operator command must return public identity metadata");
  return JSON.parse(line);
}
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function healthy() {
  for (let n = 0; n < 90; n++) {
    const id = compose(["ps", "-q", "gateway"]).stdout.trim();
    if (id) {
      const result = docker([
        "inspect",
        "--format",
        "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
        id,
      ]).stdout.trim();
      if (result === "running healthy") return id;
      if (/restarting|exited|dead/.test(result))
        throw new Error(compose(["logs", "--tail", "60", "gateway"]).stdout);
    }
    await pause(1000);
  }
  throw new Error(
    "Gateway did not become healthy: " +
      compose(["logs", "--tail", "60", "gateway"]).stdout,
  );
}
function request(path, options = {}) {
  const headers = {
    Host: host,
    "X-Forwarded-Proto": "https",
    "X-Lunport-Proxy-Key": proxyKey,
    ...options.headers,
  };
  const args = [
    "exec",
    "-T",
    "gateway",
    "curl",
    "--silent",
    "--show-error",
    "--max-time",
    "5",
    "--write-out",
    "\n%{http_code}",
    "--request",
    options.method ?? "GET",
  ];
  for (const [name, value] of Object.entries(headers))
    args.push("--header", `${name}: ${value}`);
  if (options.body !== undefined) args.push("--data-binary", options.body);
  args.push("http://127.0.0.1:8080" + path);
  const result = compose(args, false);
  const lines = result.stdout.trimEnd().split("\n");
  return {
    code: result.status,
    status: Number(lines.pop()),
    body: lines.join("\n"),
  };
}
// Snapshot only this disposable project's stopped volumes; preserve binary tar framing.
function volumeArchive(restore, archive, appOnly = false, oldLayout = false) {
  const id = compose(["ps", "-a", "-q", "gateway"]).stdout.trim();
  assert.ok(id);
  assert.equal(
    docker(["inspect", "--format", "{{.State.Running}}", id]).stdout.trim(),
    "false",
  );
  const roots = appOnly ? "data" : "data security-data";
  const script = restore
    ? `cat > /tmp/test-backup.tar && tar -tf /tmp/test-backup.tar >/dev/null && find ${roots
        .split(" ")
        .map((v) => "/" + v)
        .join(
          " ",
        )} -mindepth 1 -delete && tar -xf /tmp/test-backup.tar -C / ${roots}`
    : oldLayout
      ? `tar -C / -cf /tmp/test-backup.tar data; for role in accounts vaults passkeys; do ns=lunport-${installation}-$role; if [ -d /security-data/$ns ]; then tar -C /security-data --transform='s,^lunport-,data/lunport-,' -rf /tmp/test-backup.tar $ns; fi; done; cat /tmp/test-backup.tar`
      : `tar -C / -cf - ${roots}`;
  const result = spawnSync(
    "docker",
    [
      ...base,
      "--profile",
      "setup",
      "run",
      "--rm",
      "--no-deps",
      "-T",
      "--entrypoint",
      "/bin/sh",
      "control",
      "-c",
      script,
    ],
    {
      env: { ...process.env },
      input: restore ? archive : undefined,
      timeout: 180_000,
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  assert.equal(result.status, 0, String(result.stderr));
  return result.stdout;
}
let proxy = null;
const oldApplicationBackups = [];
async function checkpointBeforeChange(kind) {
  console.log(
    `Saving an old application-layout snapshot before ${kind} security changes`,
  );
  compose(["stop", "gateway"]);
  oldApplicationBackups.push(volumeArchive(false, undefined, true, true));
  compose(["up", "-d", "gateway"]);
  await healthy();
}
function checkCurrentAuthority() {
  for (const refresh of browserProof?.revokedRefreshTokens ?? []) {
    assert.equal(
      request("/v1/auth/passkey/refresh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: refresh }),
      }).status,
      401,
      "old application backups must never revive login families",
    );
  }
  const proof = browserProof?.protocolProof;
  if (proof?.positive) {
    const page = request(proof.positive.path, {
      headers: { Authorization: "Bearer " + proof.positive.token },
    });
    assert.equal(page.status, 200);
    const body = JSON.parse(page.body);
    assert.equal(body.sequence, proof.positive.sequence);
    assert.ok(
      body.records.every(
        (row) => row.envelope.header.key_epoch === proof.positive.key_epoch,
      ),
    );
    assert.equal(body.history_hash, proof.positive.history_hash);
    assert.deepEqual(
      body.records.map((row) => row.envelope),
      proof.positive.envelopes,
    );
    const wrapped = request(proof.wrapped.path, {
      headers: { Authorization: "Bearer " + proof.wrapped.token },
    });
    assert.equal(wrapped.status, 200);
    assert.deepEqual(JSON.parse(wrapped.body), proof.wrapped.value);
  }
  for (const proof of browserProof?.protocolProof?.denials ?? [])
    assert.equal(
      request(proof.path, {
        headers: { Authorization: "Bearer " + proof.token },
      }).status,
      proof.status,
    );
}
let browserProof = null;
try {
  console.log("Checking isolated Compose configuration and private inspection");
  compose(["config", "--quiet"]);
  const inspected = json(control("inspect"));
  assert.equal(inspected.status, 503);
  assert.equal(inspected.installation, installation);
  assert.match(inspected.registry, /^[0-9a-f]{64}$/);
  const expected = [["SELFHOST_EXPECTED_REGISTRY", inspected.registry]];
  assert.notEqual(control("provision-new", expected, false).status, 0);
  assert.equal(json(control("inspect")).status, 503);
  const confirmed = [
    ...expected,
    ["SELFHOST_CONFIRM_NEW_INSTALLATION", installation],
  ];
  assert.equal(json(control("provision-new", confirmed)).minimum, initialFloor);
  console.log(
    "Starting gateway with shared backend and independent security storage",
  );
  compose(["up", "-d", "gateway"]);
  const gateway = await healthy();
  assert.deepEqual(
    JSON.parse(
      docker([
        "inspect",
        "--format",
        "{{json .HostConfig.PortBindings}}",
        gateway,
      ]).stdout,
    ),
    {},
  );
  assert.equal(request("/legacy/v1/info").status, 200);
  assert.equal(
    request("/legacy/v1/info", { headers: { "X-Lunport-Proxy-Key": "" } }).status,
    403,
  );
  assert.equal(
    request("/legacy/v1/info", { headers: { Host: "attacker.invalid" } }).status,
    403,
  );
  assert.equal(
    request("/legacy/v1/info", { headers: { "X-Forwarded-Proto": "http" } }).status,
    403,
  );
  assert.equal(request("/provision").status, 404);
  assert.notEqual(
    control("inspect", [], false).status,
    0,
    "operator access must stop before opening live security storage",
  );
  console.log(
    "Checking real Caddy header replacement on a loopback-only test listener",
  );
  const caddyfile = join(temporary, "Caddyfile");
  writeFileSync(
    caddyfile,
    `{
 admin off
 auto_https off
}
http://:8080 {
 reverse_proxy gateway:8080 {
 header_up Host ${host}
 header_up CF-Connecting-IP {remote_host}
 header_up X-Forwarded-Proto https
 header_up X-Lunport-Proxy-Key {$SELFHOST_PROXY_KEY}
 }
}
`,
    { mode: 0o600 },
  );
  const launched = compose([
    "run",
    "--no-deps",
    "-d",
    "--name",
    project + "-proxy",
    "--entrypoint",
    "caddy",
    "-p",
    "127.0.0.1::8080",
    "-v",
    `${caddyfile}:/tmp/test.Caddyfile:ro`,
    "caddy",
    "run",
    "--config",
    "/tmp/test.Caddyfile",
    "--adapter",
    "caddyfile",
  ]);
  proxy = launched.stdout
    .trim()
    .split(/\r?\n/)
    .findLast((line) => /^[0-9a-f]{12,64}$/.test(line));
  assert.ok(proxy);
  const address = docker(["port", proxy, "8080/tcp"])
    .stdout.trim()
    .split(/\r?\n/)[0];
  let response;
  for (let n = 0; n < 30; n++) {
    try {
      response = await fetch("http://" + address + "/legacy/v1/info", {
        headers: {
          "X-Lunport-Proxy-Key": "client-forgery",
          "X-Forwarded-Proto": "http",
        },
      });
      break;
    } catch {
      await pause(500);
    }
  }
  assert.equal(response?.status, 200);
  assert.ok(!(await response.text()).includes(proxyKey));
  const info = request("/v1/info");
  assert.equal(info.status, 200);
  assert.equal(JSON.parse(info.body).default_auth, "passkey");
  assert.equal(JSON.parse(info.body).oidc, null);
  const authorize = request("/v1/auth/passkey/authorize", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code_challenge: randomBytes(32).toString("base64url"),
      redirect_uri: "http://127.0.0.1:38173/passkey/callback",
      state: randomBytes(32).toString("hex"),
    }),
  });
  assert.equal(authorize.status, 201);
  const authUrl = new URL(JSON.parse(authorize.body).url);
  assert.equal(request(authUrl.pathname + authUrl.search).status, 200);
  assert.equal(request("/v1/auth/passkey/script").status, 200);
  if (
    process.env.SELFHOST_TEST_BROWSER_MODULE &&
    process.env.SELFHOST_TEST_BROWSER_EXECUTABLE
  ) {
    const { checkPasskeyBrowser } = await import("./passkey-browser-test.mjs");
    browserProof = await checkPasskeyBrowser({
      address,
      origin: `https://${host}`,
      playwrightPath: process.env.SELFHOST_TEST_BROWSER_MODULE,
      executablePath: process.env.SELFHOST_TEST_BROWSER_EXECUTABLE,
      checkpointBeforeChange,
    });
  }
  if (process.env.SELFHOST_TEST_SOURCE_SECURITY_IMAGE) {
    console.log(
      "Migrating a real older installation with unchanged namespace IDs and retained original application data",
    );
    compose(["stop", "gateway"]);
    securityImage = targetSecurityImage;
    coreImage = targetCoreImage;
    initialFloor = 2;
    compose(["run", "--rm", "core-bundle"]);
    const operator = (args) =>
      compose([
        "--profile",
        "setup",
        "run",
        "--rm",
        "--no-deps",
        "authority-operator",
        ...args,
      ]);
    const plan = json(operator(["plan"]));
    assert.match(plan.sha256, /^[0-9a-f]{64}$/);
    const imported = json(operator(["import", "--expected", plan.sha256]));
    assert.equal(imported.receipt, plan.sha256);
    const unbound = json(control("inspect"));
    assert.equal(unbound.status, 503);
    assert.equal(unbound.pinned, false);
    assert.equal(unbound.present, true);
    assert.notEqual(
      control("provision-new", confirmed, false).status,
      0,
      "an existing old floor cannot be reinitialized as a fresh installation",
    );
    const handoff = [
      ...expected,
      ["SELFHOST_EXPECTED_AUTHORITY", unbound.authority],
      ["SELFHOST_AUTHORITY_RECEIPT", plan.sha256],
    ];
    assert.equal(json(control("bind-authority", handoff)).minimum, 2);
    assert.equal(json(control("inspect")).pinned, true);
    assert.equal(
      json(operator(["plan"])).sha256,
      plan.sha256,
      "original namespaces must remain byte-identical after handoff",
    );
    compose(["up", "-d", "gateway"]);
    await healthy();
    checkCurrentAuthority();
  }
  const chain = randomBytes(32).toString("hex"),
    token = randomBytes(32).toString("hex");
  assert.equal(
    request("/legacy/v1/chains/" + chain, {
      method: "PUT",
      headers: { Authorization: "Bearer " + token },
    }).status,
    201,
  );
  compose(["restart", "gateway"]);
  await healthy();
  assert.equal(
    request("/legacy/v1/chains/" + chain + "/records", {
      headers: { Authorization: "Bearer " + token },
    }).status,
    200,
  );
  console.log(
    "Checking stopped-volume backup/restore and retained login revocations",
  );
  compose(["stop", "gateway"]);
  const backup = volumeArchive(false);
  assert.ok(backup.length > 1024);
  compose(["up", "-d", "gateway"]);
  await healthy();
  const laterChain = randomBytes(32).toString("hex");
  assert.equal(
    request("/legacy/v1/chains/" + laterChain, {
      method: "PUT",
      headers: { Authorization: "Bearer " + token },
    }).status,
    201,
  );
  compose(["stop", "gateway"]);
  volumeArchive(true, backup);
  compose(["up", "-d", "gateway"]);
  await healthy();
  assert.equal(
    request("/legacy/v1/chains/" + chain + "/records", {
      headers: { Authorization: "Bearer " + token },
    }).status,
    200,
  );
  assert.equal(
    request("/legacy/v1/chains/" + laterChain + "/records", {
      headers: { Authorization: "Bearer " + token },
    }).status,
    404,
    "restore must actually replace application storage",
  );
  for (const refresh of browserProof?.revokedRefreshTokens ?? []) {
    assert.equal(
      request("/v1/auth/passkey/refresh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refresh_token: refresh }),
      }).status,
      401,
      "removed Passkey/logout revocations must survive a consistent restore",
    );
  }
  const positive = browserProof?.protocolProof?.positive;
  if (positive) {
    const restored = request(positive.path, {
      headers: { Authorization: "Bearer " + positive.token },
    });
    assert.equal(
      restored.status,
      200,
      "active encrypted history must survive restore",
    );
    const page = JSON.parse(restored.body);
    assert.equal(page.sequence, positive.sequence);
    assert.equal(page.history_hash, positive.history_hash);
    assert.deepEqual(
      page.records.map((row) => row.envelope),
      positive.envelopes,
    );
    const wrapProof = browserProof.protocolProof.wrapped;
    const wrapped = request(wrapProof.path, {
      headers: { Authorization: "Bearer " + wrapProof.token },
    });
    assert.equal(wrapped.status, 200);
    assert.deepEqual(
      JSON.parse(wrapped.body),
      wrapProof.value,
      "the exact previously decrypted key wrap must survive restore",
    );
  }
  for (const proof of browserProof?.protocolProof?.denials ?? []) {
    assert.equal(
      request(proof.path, {
        headers: { Authorization: "Bearer " + proof.token },
      }).status,
      proof.status,
      "device revocation and permanent retirement must survive restore",
    );
  }
  for (const backup of oldApplicationBackups) {
    console.log(
      "Restoring an older application-layout backup while retaining current independent authority",
    );
    compose(["stop", "gateway"]);
    volumeArchive(true, backup, true);
    assert.equal(json(control("inspect")).pinned, true);
    compose(["up", "-d", "gateway"]);
    await healthy();
    checkCurrentAuthority();
  }
  console.log(
    "Checking persistent floor increase and refusal to reopen an older backend",
  );
  compose(["stop", "gateway"]);
  assert.equal(json(control("inspect")).minimum, 2);
  assert.equal(
    json(control("raise-floor", [...expected, ["SELFHOST_MINIMUM_FLOOR", "3"]]))
      .minimum,
    3,
  );
  assert.notEqual(
    control(
      "raise-floor",
      [...expected, ["SELFHOST_MINIMUM_FLOOR", "2"]],
      false,
    ).status,
    0,
  );
  assert.notEqual(control("provision-new", confirmed, false).status, 0);
  volumeArchive(true, backup, true);
  assert.equal(
    json(control("inspect")).minimum,
    3,
    "an application-only restore cannot lower the independent security floor",
  );
  compose(["up", "-d", "gateway"]);
  let denied;
  for (let n = 0; n < 30; n++) {
    denied = request("/legacy/v1/info");
    if (denied.code === 0) break;
    await pause(500);
  }
  assert.equal(denied.status, 503);
  console.log(
    "PASS: private provisioning, proxy capability, Caddy, persistence, consistent backup/restore, retained login revocations, lock, and independent rollback floor",
  );
} finally {
  if (proxy) docker(["rm", "--force", proxy], false);
  compose(
    ["--profile", "setup", "down", "--volumes", "--remove-orphans"],
    false,
  );
  rmSync(temporary, { recursive: true, force: true });
}
