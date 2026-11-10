import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import test from "node:test";
import { CONSOLE_HELPER_CRATE, REPOSITORY, readProfiles } from "./identity.mjs";
import { BINARIES, builtExecutable, bundleArgument, bundledName, hostTriple, installedName, main, place } from "./windows-console-helper.mjs";

const scratch = t => {
  const root = mkdtempSync(join(tmpdir(), "console-helper-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
};

test("the tauri argument bundles the helper by its name from src-tauri/binaries", () => {
  assert.equal(bundleArgument("lunport-cli"), `--config '{"bundle":{"externalBin":["binaries/lunport-cli"]}}'`);
  assert.equal(bundleArgument(readProfiles().production.consoleHelper), bundleArgument("lunport-cli"));
});

test("a name that could not reach tauri unchanged through cmd is refused", () => {
  for (const name of ["", "-cli", "lunport cli", "lunport\\cli", "lunport/cli", "a%b", "a&b", "a^b", "a|b", "a<b", "a>b", "a(b", "a)b", "a'b", 'a"b', "a.exe"]) {
    assert.throws(() => bundleArgument(name), /cannot be passed to tauri/, name);
  }
});

test("tauri build looks for the helper under its name, the target triple and .exe on Windows", () => {
  assert.equal(bundledName("lunport-cli", "x86_64-pc-windows-msvc"), "lunport-cli-x86_64-pc-windows-msvc.exe");
  assert.equal(bundledName("lunport-cli", "aarch64-pc-windows-msvc"), "lunport-cli-aarch64-pc-windows-msvc.exe");
  assert.equal(bundledName("lunport-cli", "aarch64-apple-darwin"), "lunport-cli-aarch64-apple-darwin");
  assert.equal(installedName("lunport-cli", "x86_64-pc-windows-msvc"), "lunport-cli.exe");
  assert.equal(installedName("lunport-cli", "aarch64-apple-darwin"), "lunport-cli");
  const rustc = "rustc 1.90.0 (1159e78c4 2025-09-14)\nbinary: rustc\r\nhost: x86_64-pc-windows-msvc\r\nrelease: 1.90.0\r\n";
  assert.equal(hostTriple(rustc), "x86_64-pc-windows-msvc");
  assert.throws(() => hostTriple("rustc 1.90.0\nrelease: 1.90.0\n"), /names no host/);
});

test("the built helper is copied into src-tauri/binaries, which is created first", t => {
  const root = scratch(t);
  const from = join(root, "built.exe");
  writeFileSync(from, "helper bytes");
  const destination = place({ root, from, helper: "lunport-cli", triple: "x86_64-pc-windows-msvc" });
  assert.equal(destination, join(root, BINARIES, "lunport-cli-x86_64-pc-windows-msvc.exe"));
  assert.equal(readFileSync(destination, "utf8"), "helper bytes");
  assert.throws(() => place({ root, from: join(root, "missing.exe"), helper: "lunport-cli", triple: "x86_64-pc-windows-msvc" }), /no built console helper/);
});

test("the helper's executable is the one cargo reports for its bin target", () => {
  const artifact = (name, kind, executable) => JSON.stringify({ reason: "compiler-artifact", target: { name, kind: [kind] }, executable });
  const messages = [
    artifact("lunport_cli", "lib", null),
    artifact("lunport-cli", "bin", "C:\\work\\target\\release\\lunport-cli.exe"),
    JSON.stringify({ reason: "build-finished", success: true }),
    "",
  ].join("\n");
  assert.equal(builtExecutable(messages, "lunport-cli"), "C:\\work\\target\\release\\lunport-cli.exe");
  assert.throws(() => builtExecutable(messages, "other-cli"), /built 0 executables named other-cli/);
  assert.throws(() => builtExecutable(`${messages}\n${artifact("lunport-cli", "bin", "/again")}`, "lunport-cli"), /built 2 executables/);
});

test("a helper built before is placed for tauri, copied beside the main executable, and its argument becomes the step's output", t => {
  const root = scratch(t);
  mkdirSync(join(root, "src-tauri/cli-helper"), { recursive: true });
  writeFileSync(join(root, CONSOLE_HELPER_CRATE), '[package]\nname = "acme-cli"\n');
  const from = join(root, "built.exe");
  writeFileSync(from, "helper bytes");
  mkdirSync(join(root, "debug"));
  const output = join(root, "step-output");
  const said = [];
  const argv = ["--root", root, "--from", from, "--copy-to", join(root, "debug")];
  const argument = main(argv, { host: () => "x86_64-pc-windows-msvc", env: { GITHUB_OUTPUT: output }, log: line => said.push(line) });
  assert.equal(argument, bundleArgument("acme-cli"));
  assert.equal(readFileSync(join(root, BINARIES, "acme-cli-x86_64-pc-windows-msvc.exe"), "utf8"), "helper bytes");
  assert.equal(readFileSync(join(root, "debug", "acme-cli.exe"), "utf8"), "helper bytes");
  assert.equal(readFileSync(output, "utf8"), `args=${argument}\n`);
  assert.equal(said.length, 2);
  assert.throws(() => main(["--root", root, "--from", from, "--target", "x"], { host: () => "x86_64-pc-windows-msvc", env: {} }), /Unknown option '--target'/);
});

const workflows = join(REPOSITORY, ".github/workflows");
const workflow = name => readFileSync(join(workflows, name), "utf8");
// A workflow's steps, each as its text: the items of a job's `steps:` list, six spaces in.
const steps = text => text.split(/^(?= {6}- )/m).slice(1);

// The helper's name lives in its crate; a workflow that wrote the argument again would bundle a name this step did not build, and a
// tauri build that dropped the step's output would ship an installer without the helper.
test("every Windows tauri build bundles the helper with the argument this script gave", () => {
  for (const name of readdirSync(workflows).filter(file => file.endsWith(".yml"))) {
    assert.ok(!workflow(name).includes('"externalBin"'), `${name} writes bundle.externalBin`);
  }
  for (const name of ["release.yml", "beta.yml", "build-platform.yml", "windows-bundle-check.yml"]) {
    const all = steps(workflow(name));
    const runsTheScript = id => all.some(step => new RegExp(`^ {8}id: ${id}$`, "m").test(step) && /node \S*scripts\/windows-console-helper\.mjs/.test(step));
    const builds = all.filter(step => step.includes("uses: tauri-apps/tauri-action@") || step.includes("tauri.js bundle"));
    assert.ok(builds.length > 0, `${name} has no tauri build`);
    for (const build of builds) {
      const outputs = [...build.matchAll(/\$\{\{ steps\.([\w-]+)\.outputs\.args \}\}/g)].map(match => match[1]);
      assert.equal(outputs.length, 1, `a tauri build in ${name} does not pass one console helper argument:\n${build}`);
      assert.ok(runsTheScript(outputs[0]), `the step ${outputs[0]} in ${name} does not run scripts/windows-console-helper.mjs`);
    }
  }
  // The Windows test suite runs the helper this script builds, beside its debug build.
  assert.match(workflow("test-windows.yml"), /node \.\.\/scripts\/windows-console-helper\.mjs --copy-to target\/debug/);
});

// The local modules a script loads, itself included, as paths from the repository root.
function loads(file, found = new Set()) {
  if (found.has(file)) return found;
  found.add(file);
  for (const [, specifier] of readFileSync(join(REPOSITORY, file), "utf8").matchAll(/\bfrom\s+"(\.{1,2}\/[^"]+)"/g)) {
    loads(posix.join(posix.dirname(file), specifier), found);
  }
  return found;
}

// build-platform.yml checks out only these scripts beside an older tag's tree; a module they import and it left out would fail there.
test("the recovery build checks out exactly the scripts the helper step loads", () => {
  const listed = /^ {10}sparse-checkout: \|\n((?: {12}\S.*\n)+)/m.exec(workflow("build-platform.yml"))?.[1].trim().split(/\s+/);
  assert.ok(listed, "build-platform.yml has no sparse checkout list");
  assert.deepEqual(listed.sort(), [...loads("scripts/windows-console-helper.mjs")].sort());
});
