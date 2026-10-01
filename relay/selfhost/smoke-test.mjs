// End-to-end check of a running relay over HTTP. Node ≥ 18, no dependencies.
//   node smoke-test.mjs <base-url> <state-file> write  — create a chain, push, hit a conflict; save its credentials
//   node smoke-test.mjs <base-url> <state-file> read   — the record is still there (restart the relay first); delete the chain
//   node smoke-test.mjs <base-url> spoof               — through the proxy, a forged CF-Connecting-IP header is ignored:
//                                                        the 21st chain created within the hour is refused
import { deepStrictEqual } from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const [base, ...rest] = process.argv.slice(2);
const phase = rest.at(-1);
const stateFile = rest.length === 2 ? rest[0] : undefined;
if (!base || !["write", "read", "spoof"].includes(phase) || (phase !== "spoof" && !stateFile)) {
  console.error("usage: node smoke-test.mjs <base-url> <state-file> write|read, or node smoke-test.mjs <base-url> spoof");
  process.exit(2);
}

const hex = (bytes) => randomBytes(bytes).toString("hex");
const base64 = (bytes) => randomBytes(bytes).toString("base64");

async function call(method, path, token, { body, headers = {} } = {}) {
  const res = await fetch(new URL(path, base), {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { "content-type": "application/json" } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
    redirect: "manual",
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

function check(label, actual, expected) {
  try {
    deepStrictEqual(actual, expected);
  } catch {
    console.error(`✗ ${label}\n  expected ${JSON.stringify(expected)}\n  got      ${JSON.stringify(actual)}`);
    process.exit(1);
  }
  console.log(`✓ ${label}`);
}

if (phase === "write") {
  const chain = hex(32);
  const token = hex(32);
  const record = { idHash: hex(32), kind: "host", nonce: base64(24), ciphertext: base64(48), deleted: false };
  check("create a chain", (await call("PUT", `/v1/chains/${chain}`, token)).status, 201);
  check("creating it again is idempotent", (await call("PUT", `/v1/chains/${chain}`, token)).status, 200);
  check("another token cannot see it", (await call("PUT", `/v1/chains/${chain}`, hex(32))).status, 404);
  const pushed = await call("POST", `/v1/chains/${chain}/records`, token, { body: [{ ...record, baseSeq: 0 }] });
  check("push a record", pushed, { status: 200, json: { results: [{ status: "ok", seq: 1 }], latestSeq: 1 } });
  const stale = await call("POST", `/v1/chains/${chain}/records`, token, {
    body: [{ ...record, ciphertext: base64(48), baseSeq: 0 }],
  });
  check("a push based on an old version conflicts", stale, {
    status: 200,
    json: { results: [{ status: "conflict", current: { ...record, seq: 1 } }], latestSeq: 1 },
  });
  writeFileSync(stateFile, JSON.stringify({ chain, token, record }));
} else if (phase === "read") {
  const { chain, token, record } = JSON.parse(readFileSync(stateFile, "utf8"));
  const pulled = await call("GET", `/v1/chains/${chain}/records?since=0`, token);
  check("the record is still there", pulled, { status: 200, json: { records: [{ ...record, seq: 1 }], latestSeq: 1 } });
  check("delete the chain", (await call("DELETE", `/v1/chains/${chain}`, token)).status, 204);
  check("a deleted chain is gone", (await call("GET", `/v1/chains/${chain}/records?since=0`, token)).status, 404);
} else {
  const statuses = [];
  for (let i = 1; i <= 21; i++) {
    const res = await call("PUT", `/v1/chains/${hex(32)}`, hex(32), { headers: { "cf-connecting-ip": `203.0.113.${i}` } });
    statuses.push(res.status);
  }
  check("20 chains per hour from one address, whatever CF-Connecting-IP says", statuses, [...Array(20).fill(201), 429]);
}
