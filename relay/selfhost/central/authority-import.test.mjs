import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  checkpoint,
  importAuthority,
  reconcileAuthority,
} from "./authority-import.mjs";
const install = "a".repeat(32),
  id = "b".repeat(64),
  name = `lunport-${install}-accounts`;
function setup(t) {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "lunport-authority-test-"),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const app = path.join(root, "app"),
    security = path.join(root, "security");
  fs.mkdirSync(app);
  fs.mkdirSync(security);
  fs.mkdirSync(path.join(app, name));
  const db = new DatabaseSync(path.join(app, name, id + ".sqlite"));
  db.exec(
    "CREATE TABLE security_state(id INTEGER PRIMARY KEY,revoked INTEGER); INSERT INTO security_state VALUES(1,0)",
  );
  db.close();
  const metadata = new DatabaseSync(path.join(app, name, "metadata.sqlite"));
  metadata.exec(
    "CREATE TABLE objects(id TEXT PRIMARY KEY); INSERT INTO objects VALUES('synthetic')",
  );
  metadata.close();
  return { root, app, security, plan: checkpoint(app, install) };
}
test("imports exact namespace files and IDs, preserves source and is idempotent", (t) => {
  const f = setup(t);
  assert.equal(
    importAuthority(f.app, f.security, install, f.plan.sha256).receipt,
    f.plan.sha256,
  );
  assert.deepEqual(checkpoint(f.security, install), f.plan);
  assert.deepEqual(checkpoint(f.app, install), f.plan);
  assert.equal(
    importAuthority(f.app, f.security, install, f.plan.sha256).status,
    "imported",
  );
  assert.equal(
    reconcileAuthority(f.app, f.security, install, f.plan.sha256).status,
    "matching",
  );
});
test("requires the pinned current digest and never imports over later revocation state", (t) => {
  const f = setup(t);
  assert.throws(() =>
    importAuthority(f.app, f.security, install, "f".repeat(64)),
  );
  assert.deepEqual(fs.readdirSync(f.security), []);
  importAuthority(f.app, f.security, install, f.plan.sha256);
  const db = new DatabaseSync(path.join(f.security, name, id + ".sqlite"));
  db.exec("UPDATE security_state SET revoked=1");
  db.close();
  const latest = checkpoint(f.security, install);
  assert.throws(() =>
    importAuthority(f.app, f.security, install, f.plan.sha256),
  );
  assert.throws(() =>
    reconcileAuthority(f.app, f.security, install, f.plan.sha256),
  );
  assert.deepEqual(
    reconcileAuthority(f.app, f.security, install, latest.sha256).differences,
    ["accounts"],
  );
  const retained = new DatabaseSync(
    path.join(f.security, name, id + ".sqlite"),
    { readOnly: true },
  );
  try {
    assert.equal(
      retained.prepare("SELECT revoked FROM security_state").get().revoked,
      1,
    );
  } finally {
    retained.close();
  }
  assert.deepEqual(checkpoint(f.app, install), f.plan);
});
test("resumes exact partial staged files and stops on unknown or corrupted staging bytes", (t) => {
  for (const corrupt of [false, true]) {
    const f = setup(t),
      ns = f.plan.value.namespaces[0],
      stage = path.join(
        f.security,
        `.authority-${name}-${f.plan.sha256}.staging`,
      );
    fs.mkdirSync(stage);
    const source = fs.readFileSync(path.join(f.app, name, id + ".sqlite")),
      partial = source.subarray(0, 100);
    if (corrupt) partial[20] ^= 1;
    fs.writeFileSync(path.join(stage, id + ".sqlite.part"), partial);
    if (corrupt) {
      assert.throws(() =>
        importAuthority(f.app, f.security, install, f.plan.sha256),
      );
      assert.ok(fs.existsSync(path.join(stage, id + ".sqlite.part")));
    } else {
      importAuthority(f.app, f.security, install, f.plan.sha256);
      assert.deepEqual(checkpoint(f.security, install), f.plan);
    }
  }
});
test("a partial namespace publication resumes but a wrong prior receipt never changes storage", (t) => {
  const f = setup(t);
  fs.cpSync(path.join(f.app, name), path.join(f.security, name), {
    recursive: true,
  });
  fs.writeFileSync(
    path.join(f.security, "central-authority-import.json"),
    "{}",
  );
  const before = checkpoint(f.security, install);
  assert.throws(() =>
    importAuthority(f.app, f.security, install, f.plan.sha256),
  );
  assert.deepEqual(checkpoint(f.security, install), before);
  fs.unlinkSync(path.join(f.security, "central-authority-import.json"));
  importAuthority(f.app, f.security, install, f.plan.sha256);
  assert.deepEqual(checkpoint(f.security, install), f.plan);
});
test("source/destination links, extra entries, incomplete WAL and wrong installations fail closed", (t) => {
  for (const mode of [
    "source-link",
    "dest-link",
    "hardlink",
    "extra",
    "orphan-wal",
    "installation",
    "receipt-link",
  ]) {
    const f = setup(t),
      source = path.join(f.app, name, id + ".sqlite");
    switch (mode) {
      case "source-link":
        fs.renameSync(source, source + ".saved");
        fs.symlinkSync(source + ".saved", source);
        break;
      case "dest-link":
        fs.symlinkSync(path.join(f.app, name), path.join(f.security, name));
        break;
      case "hardlink":
        fs.linkSync(source, path.join(f.root, "link"));
        break;
      case "extra":
        fs.writeFileSync(path.join(f.app, name, "unknown"), "PRIVATE_SENTINEL");
        break;
      case "orphan-wal":
        fs.writeFileSync(
          path.join(f.app, name, "c".repeat(64) + ".sqlite-wal"),
          "uncommitted",
        );
        break;
      case "installation":
        assert.throws(() =>
          importAuthority(f.app, f.security, "../bad", f.plan.sha256),
        );
        continue;
      case "receipt-link":
        fs.writeFileSync(path.join(f.root, "receipt"), JSON.stringify(f.plan));
        fs.symlinkSync(
          path.join(f.root, "receipt"),
          path.join(f.security, "central-authority-import.json"),
        );
        break;
    }
    assert.throws(() =>
      importAuthority(f.app, f.security, install, f.plan.sha256),
    );
  }
});
test("a malformed SQLite database cannot be published or become a handoff receipt", (t) => {
  const f = setup(t);
  fs.writeFileSync(path.join(f.app, name, id + ".sqlite"), "not a database");
  const plan = checkpoint(f.app, install);
  assert.throws(() => importAuthority(f.app, f.security, install, plan.sha256));
  assert.equal(
    fs.existsSync(path.join(f.security, "central-authority-import.json")),
    false,
  );
  assert.equal(fs.existsSync(path.join(f.security, name)), false);
});
