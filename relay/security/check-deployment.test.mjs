import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { stripJsonComments } from "../.github/scripts/update-relay.mjs";
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
      s.services[0].entrypoint = undefined;
    },
    (c, s, b) => {
      s.services[0].service = "old-core";
    },
    (c, s, b) => {
      b.services = s.services;
    },
  ]) {
    const values = fresh();
    mutate(...values);
    assert.ok(validateSecurityDeployment(...values).length);
  }
});
test("rejects security namespace or installation ownership changes", () => {
  for (const mutate of [
    (c, s, b) => {
      c.durable_objects.bindings.find(
        (v) => v.name === "LEGACY_RETIREMENT",
      ).script_name = "empty-copy";
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
      b.vars.SECURITY_INSTALLATION = "f".repeat(32);
    },
    (c, s, b) => {
      b.migrations = [];
    },
    (c, s, b) => {
      s.vars.CENTRAL_ORIGIN = "http://insecure.test";
    },
  ]) {
    const values = fresh();
    mutate(...values);
    assert.ok(validateSecurityDeployment(...values).length);
  }
});
