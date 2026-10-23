import { test } from "node:test";
import assert from "node:assert/strict";
import { prepareAuthorityTransfer } from "./prepare-authority-transfer.mjs";
function fixture(central = false) {
  const roles = {
    CHAIN: "ChainStore",
    IP_LIMIT: "IpLimiter",
    ...(central
      ? {
          ACCOUNT: "AccountStore",
          VAULT: "VaultStore",
          PASSKEY: "PasskeyStore",
          LEGACY_RETIREMENT: "LegacyRetirementStore",
        }
      : {}),
  };
  const source = {
    name: "original-relay",
    main: "src/index.ts",
    compatibility_date: "2026-08-20",
    workers_dev: true,
    routes: ["existing.example/*"],
    durable_objects: {
      bindings: Object.entries(roles).map(([name, class_name]) => ({
        name,
        class_name,
      })),
    },
    migrations: [
      { tag: "v1", new_sqlite_classes: Object.values(roles) },
      { tag: "not-yet-deployed", new_sqlite_classes: ["SecurityFloorStore"] },
    ],
    vars: { CENTRAL_ENABLED: "0" },
  };
  const live = {
    version: 1,
    account_id: "d".repeat(32),
    script_name: source.name,
    private_script_absent: true,
    origin: "https://original-relay.example.workers.dev",
    migration_tag: "v1",
    namespaces: Object.values(roles).map((class_name, i) => ({
      class_name,
      storage: "sqlite",
      id: (i + 1).toString(16).padStart(32, "0"),
    })),
  };
  return {
    source,
    live,
    options: {
      installation: "a".repeat(32),
      privateCore: "original-relay-core",
    },
  };
}
test("retains the original public worker and existing central namespace IDs and transfers only the legacy chain", () => {
  const f = fixture(true),
    r = prepareAuthorityTransfer(f.source, f.live, f.options);
  assert.equal(r.security.name, f.source.name);
  assert.equal(
    r.plan.expected_private_chain_namespace,
    f.live.namespaces[0].id,
  );
  for (const cls of [
    "AccountStore",
    "VaultStore",
    "PasskeyStore",
    "LegacyRetirementStore",
  ]) {
    assert.ok(r.plan.expected_preserved_security_namespaces[cls]);
    assert.ok(!r.plan.new_security_classes.includes(cls));
  }
  assert.deepEqual(r.coreBootstrap.migrations[0].transferred_classes, [
    { from: "ChainStore", from_script: f.source.name, to: "ChainStore" },
  ]);
  assert.deepEqual(
    r.security.migrations.slice(0, 1),
    f.source.migrations.slice(0, 1),
  );
  assert.equal(r.security.workers_dev, false);
  assert.equal(r.security.build.command, "node scripts/build-passkey-page.mjs");
  assert.deepEqual(r.security.routes, []);
  assert.deepEqual(
    r.core.durable_objects.bindings.map((v) => v.name),
    ["CHAIN", "IP_LIMIT"],
  );
  assert.equal(r.core.vars.CENTRAL_ENABLED, undefined);
  assert.equal(r.security.vars.CENTRAL_ENABLED, "0");
  assert.equal(f.source.workers_dev, true);
});
test("creates only absent security classes for a verified legacy-only installation", () => {
  const f = fixture(),
    r = prepareAuthorityTransfer(f.source, f.live, f.options);
  assert.deepEqual(r.plan.new_security_classes, [
    "AccountStore",
    "VaultStore",
    "PasskeyStore",
    "LegacyRetirementStore",
    "SecurityFloorStore",
  ]);
  assert.equal(r.security.migrations.length, 2);
  assert.equal(r.coreBootstrap.durable_objects.bindings.length, 2);
});
test("rejects incomplete ownership, missing class IDs, tag drift, conflicting targets and unknown classes", () => {
  for (const mutate of [
    (f) => f.live.namespaces.pop(),
    (f) => (f.live.migration_tag = "unknown"),
    (f) => (f.live.namespaces[0].storage = "legacy-kv"),
    (f) => (f.options.privateCore = f.source.name),
    (f) => (f.live.private_script_absent = false),
    (f) => (f.source.durable_objects.bindings[0].script_name = "another-owner"),
    (f) => (f.live.namespaces[0].id = "bad"),
    (f) => (f.live.namespaces[1].class_name = "UnknownStore"),
    (f) => (f.live.origin = "http://unsafe.test"),
  ]) {
    const f = fixture(true);
    mutate(f);
    assert.throws(() => prepareAuthorityTransfer(f.source, f.live, f.options));
  }
});
