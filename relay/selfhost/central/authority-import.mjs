/** Offline, byte-preserving authority handoff. Run under the installation runtime lock. */
import * as fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";
const HEX32 = /^[0-9a-f]{32}$/,
  HEX64 = /^[0-9a-f]{64}$/;
const ROLES = ["accounts", "vaults", "passkeys"];
const FILE = /^(?:[0-9a-f]{64}|metadata)\.sqlite(?:-wal|-shm)?$/;
const MAX_BYTES = 64 * 1024 ** 3,
  MAX_FILES = 8192;
const hash = (value) => createHash("sha256").update(value).digest("hex");
const fail = () => {
  throw new Error(
    "Authority input is incomplete, changed, unsafe, or differs from the expected checkpoint. Preserve all storage; do not provision replacement authority.",
  );
};
function directory(name, optional = false) {
  let stat;
  try {
    stat = fs.lstatSync(name);
  } catch (error) {
    if (optional && error.code === "ENOENT") return false;
    throw error;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail();
  return true;
}
function fileDigest(name) {
  const fd = fs.openSync(
    name,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
  );
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || before.size > MAX_BYTES)
      fail();
    const digest = createHash("sha256"),
      buffer = Buffer.alloc(65536);
    let count = 0;
    for (;;) {
      const n = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!n) break;
      digest.update(buffer.subarray(0, n));
      count += n;
    }
    const after = fs.fstatSync(fd);
    if (
      count !== before.size ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      fail();
    return { bytes: count, sha256: digest.digest("hex") };
  } finally {
    fs.closeSync(fd);
  }
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function inventory(root, installation) {
  if (!HEX32.test(installation)) fail();
  directory(root);
  let total = 0,
    count = 0;
  const namespaces = ROLES.map((role) => {
    const name = `lunport-${installation}-${role}`,
      location = path.join(root, name);
    const files = directory(location, true)
      ? fs
          .readdirSync(location)
          .sort()
          .map((name) => {
            if (!FILE.test(name) || ++count > MAX_FILES) fail();
            const value = fileDigest(path.join(location, name));
            total += value.bytes;
            if (total > MAX_BYTES) fail();
            return { name, ...value };
          })
      : [];
    for (const file of files)
      if (file.name.endsWith("-wal") || file.name.endsWith("-shm")) {
        const base = file.name.replace(/-(wal|shm)$/, "");
        if (!files.some((value) => value.name === base)) fail();
      }
    return { role, name, files };
  });
  return { version: 1, installation, namespaces };
}
export function checkpoint(root, installation) {
  const value = inventory(root, installation);
  return { value, sha256: hash(JSON.stringify(value)) };
}
function syncDirectory(location) {
  const fd = fs.openSync(
    location,
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
  );
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
function sqliteCheck(root, files) {
  const scratch = fs.mkdtempSync(
    path.join(os.tmpdir(), "lunport-authority-check-"),
  );
  try {
    for (const file of files)
      fs.copyFileSync(
        path.join(root, file.name),
        path.join(scratch, file.name),
        fs.constants.COPYFILE_EXCL,
      );
    for (const file of files.filter((file) => file.name.endsWith(".sqlite"))) {
      const db = new DatabaseSync(path.join(scratch, file.name), {
        readOnly: true,
        allowExtension: false,
      });
      try {
        const result = db.prepare("PRAGMA quick_check").all();
        if (result.length !== 1 || result[0].quick_check !== "ok") fail();
      } finally {
        db.close();
      }
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}
function copyFile(source, target, expected) {
  if (fs.existsSync(target)) {
    if (
      !same(fileDigest(target), {
        bytes: expected.bytes,
        sha256: expected.sha256,
      })
    )
      fail();
    return;
  }
  const partial = target + ".part",
    input = fs.openSync(
      source,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
  let output;
  try {
    try {
      output = fs.openSync(
        partial,
        fs.constants.O_RDWR |
          fs.constants.O_CREAT |
          fs.constants.O_EXCL |
          fs.constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      output = fs.openSync(
        partial,
        fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
      );
    }
    const stat = fs.fstatSync(output);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > expected.bytes)
      fail();
    const left = Buffer.alloc(65536),
      right = Buffer.alloc(65536);
    let offset = 0;
    while (offset < stat.size) {
      const size = Math.min(left.length, stat.size - offset);
      if (
        fs.readSync(input, left, 0, size, offset) !== size ||
        fs.readSync(output, right, 0, size, offset) !== size ||
        !left.subarray(0, size).equals(right.subarray(0, size))
      )
        fail();
      offset += size;
    }
    while (offset < expected.bytes) {
      const n = fs.readSync(
        input,
        left,
        0,
        Math.min(left.length, expected.bytes - offset),
        offset,
      );
      if (!n) fail();
      let written = 0;
      while (written < n)
        written += fs.writeSync(
          output,
          left,
          written,
          n - written,
          offset + written,
        );
      offset += n;
    }
    fs.fsyncSync(output);
    fs.closeSync(output);
    output = undefined;
    if (
      !same(fileDigest(partial), {
        bytes: expected.bytes,
        sha256: expected.sha256,
      })
    )
      fail();
    fs.renameSync(partial, target);
  } finally {
    if (output !== undefined) fs.closeSync(output);
    fs.closeSync(input);
  }
}
const receiptName = "central-authority-import.json";
export function importAuthority(app, security, installation, expected) {
  if (!HEX64.test(expected)) fail();
  directory(app);
  directory(security);
  const appRoot = fs.realpathSync(app),
    securityRoot = fs.realpathSync(security);
  if (
    appRoot === securityRoot ||
    appRoot.startsWith(securityRoot + path.sep) ||
    securityRoot.startsWith(appRoot + path.sep)
  )
    fail();
  const plan = checkpoint(app, installation);
  if (plan.sha256 !== expected) fail();
  const receipt = path.join(security, receiptName);
  if (fs.existsSync(receipt)) {
    const fd = fs.openSync(
      receipt,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 4 * 1024 * 1024)
        fail();
      if (!same(JSON.parse(fs.readFileSync(fd, "utf8")), plan)) fail();
    } finally {
      fs.closeSync(fd);
    }
  }
  const existing = checkpoint(security, installation);
  // Check every destination before creating any stage; never replace newer authority.
  for (let i = 0; i < ROLES.length; i++)
    if (
      existing.value.namespaces[i].files.length &&
      !same(existing.value.namespaces[i], plan.value.namespaces[i])
    )
      fail();
  for (const ns of plan.value.namespaces) {
    const source = path.join(app, ns.name),
      target = path.join(security, ns.name);
    if (
      directory(target, true) &&
      same(
        checkpoint(security, installation).value.namespaces.find(
          (v) => v.role === ns.role,
        ),
        ns,
      )
    )
      continue;
    const stage = path.join(
      security,
      `.authority-${ns.name}-${expected}.staging`,
    );
    if (!directory(stage, true)) fs.mkdirSync(stage, { mode: 0o700 });
    const allowed = new Set(
      ns.files.flatMap((v) => [v.name, v.name + ".part"]),
    );
    if (fs.readdirSync(stage).some((name) => !allowed.has(name))) fail();
    for (const file of ns.files)
      copyFile(path.join(source, file.name), path.join(stage, file.name), file);
    if (
      fs.readdirSync(stage).sort().join("\0") !==
      ns.files
        .map((file) => file.name)
        .sort()
        .join("\0")
    )
      fail();
    sqliteCheck(stage, ns.files);
    for (const file of ns.files)
      if (
        !same(fileDigest(path.join(stage, file.name)), {
          bytes: file.bytes,
          sha256: file.sha256,
        })
      )
        fail();
    if (checkpoint(app, installation).sha256 !== expected) fail();
    if (directory(target, true) && fs.readdirSync(target).length) fail();
    syncDirectory(stage);
    fs.renameSync(stage, target);
    syncDirectory(security);
  }
  if (
    checkpoint(app, installation).sha256 !== expected ||
    checkpoint(security, installation).sha256 !== expected
  )
    fail();
  if (!fs.existsSync(receipt)) {
    const temporary = receipt + "." + randomBytes(16).toString("hex") + ".tmp";
    const fd = fs.openSync(
      temporary,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      fs.writeFileSync(fd, JSON.stringify(plan));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    // An existing receipt is immutable; link publication cannot replace it.
    fs.linkSync(temporary, receipt);
    fs.unlinkSync(temporary);
    syncDirectory(security);
  }
  return { status: "imported", installation, receipt: expected };
}
export function reconcileAuthority(
  candidate,
  current,
  installation,
  expectedCurrent,
) {
  if (!HEX64.test(expectedCurrent)) fail();
  const latest = checkpoint(current, installation);
  if (latest.sha256 !== expectedCurrent) fail();
  const older = checkpoint(candidate, installation);
  const differences = latest.value.namespaces
    .filter((ns, i) => !same(ns, older.value.namespaces[i]))
    .map((ns) => ns.role);
  if (checkpoint(current, installation).sha256 !== expectedCurrent) fail();
  return {
    status: differences.length ? "retain-current-authority" : "matching",
    installation,
    current: expectedCurrent,
    differences,
  };
}
function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (args.length % 2) fail();
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (
      !["--installation", "--app", "--security", "--expected"].includes(
        args[i],
      ) ||
      args[i] in options
    )
      fail();
    options[args[i]] = args[i + 1];
  }
  const installation =
      options["--installation"] ?? process.env.SECURITY_INSTALLATION,
    app = options["--app"] ?? "/data",
    security = options["--security"] ?? "/security-data",
    expected = options["--expected"];
  if (!HEX32.test(installation ?? "")) fail();
  const result =
    mode === "plan"
      ? checkpoint(app, installation)
      : mode === "checkpoint"
        ? checkpoint(security, installation)
        : mode === "import"
          ? importAuthority(app, security, installation, expected ?? "")
          : mode === "reconcile"
            ? reconcileAuthority(app, security, installation, expected ?? "")
            : fail();
  console.log(JSON.stringify(result));
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  try {
    main();
  } catch (error) {
    console.error(
      "Authority reconciliation failed. Preserve all original storage and verify the expected current checkpoint; no replacement authority was provisioned.",
    );
    process.exitCode = 1;
  }
}
