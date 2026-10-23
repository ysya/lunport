import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripJsonComments } from "./json-comments.mjs";
import {
  checkExamples,
  validateSecurityDeployment,
} from "./check-deployment.mjs";
const read = (name) =>
  JSON.parse(
    stripJsonComments(
      readFileSync(
        new URL(`../wrangler.${name}.example.jsonc`, import.meta.url),
        "utf8",
      ),
    ),
  );
const fresh = () => [
  read("private-core"),
  read("security"),
  read("security-bootstrap"),
];
test("closed deployment examples remain internally consistent", () =>
  assert.deepEqual(checkExamples(), []));
test("self-hosted private core has no security service or namespace binding", () => {
  const template = readFileSync(
    new URL("../selfhost/central/services.capnp.in", import.meta.url),
    "utf8",
  );
  const core = template.split("const core :Workerd.Service =")[1]?.split(
    "const securityStorage :Workerd.Service =",
  )[0];
  assert.ok(core);
  assert.doesNotMatch(core, /serviceName\s*=\s*"security"/);
  const bound = [...core.matchAll(/\(name = "([A-Z_]+)",/g)].map((match) => match[1]);
  assert.deepEqual(bound, ["CHAIN", "IP_LIMIT", "CENTRAL_PRIVATE_CORE"]);
  assert.match(template, /\(name = "CENTRAL_ENABLED", fromEnvironment = "CENTRAL_ENABLED"\)/);
});
test("rejects accidentally public or unchecked backend paths", () => {
  for (const mutate of [
    (c, s, b) => {
      c.workers_dev = true;
    },
    (c, s, b) => {
      c.preview_urls = true;
    },
    (c, s, b) => {
      c.routes.push("public.test/*");
    },
    (c, s, b) => {
      c.vars.CENTRAL_PRIVATE_CORE = "0";
    },
    (c, s, b) => {
      s.services = [{ binding: "CORE", service: c.name }];
    },
    (c, s, b) => {
      s.durable_objects.bindings.push({ name: "CHAIN", class_name: "ChainStore", script_name: c.name });
    },
    (c, s, b) => {
      s.build = undefined;
    },
  ]) {
    const values = fresh();
    mutate(...values);
    assert.ok(validateSecurityDeployment(...values).length);
  }
});
test("rejects core access to security namespaces or installation changes", () => {
  for (const mutate of [
    (c, s, b) => {
      c.durable_objects.bindings.push({
        name: "LEGACY_RETIREMENT",
        class_name: "LegacyRetirementStore",
        script_name: s.name,
      });
    },
    (c, s, b) => {
      s.durable_objects.bindings.find(
        (v) => v.name === "SECURITY_FLOOR",
      ).script_name = c.name;
    },
    (c, s, b) => {
      s.durable_objects.bindings.find((v) => v.name === "VAULT").script_name =
        "wrong-target";
    },
    (c, s, b) => {
      c.durable_objects.bindings.push({
        name: "ACCOUNT",
        class_name: "AccountStore",
        script_name: s.name,
      });
    },
    (c, s, b) => {
      c.services = [{ binding: "SECURITY", service: s.name }];
    },
    (c, s, b) => {
      c.durable_objects.bindings.find((v) => v.name === "CHAIN").class_name =
        "VaultStore";
    },
    (c, s, b) => {
      s.durable_objects.bindings.find((v) => v.name === "PASSKEY").script_name =
        c.name;
    },
    (c, s, b) => {
      b.vars.SECURITY_INSTALLATION = "f".repeat(32);
    },
    (c, s, b) => {
      b.migrations = [];
    },
    (c, s, b) => {
      s.vars.CENTRAL_ORIGIN = "http://insecure.test";
    },
    (c, s, b) => {
      c.vars.CENTRAL_ENABLED = "1";
    },
  ]) {
    const values = fresh();
    mutate(...values);
    assert.ok(validateSecurityDeployment(...values).length);
  }
});
