#!/usr/bin/env node
// Puts the console helper where `tauri build` bundles it from, and prints the tauri argument that bundles it. The helper (crate
// src-tauri/cli-helper, std only) is the console program a Windows terminal runs for Connect: it runs the GUI main executable and waits
// for it. Windows builds bundle it through `tauri build --config` with bundle.externalBin, which installs it next to the main
// executable; plain cargo builds never look for it, so no Tauri configuration names it. Every Windows build runs this step, and so does
// the Windows test suite:
//
//   node scripts/windows-console-helper.mjs [--root <dir>] [--from <helper.exe>] [--copy-to <dir>]
//
// It builds the helper in release mode and, for an MSVC target, with the C runtime linked in (+crt-static), as tauri build links the
// main executable (STATIC_VCRUNTIME): the installer carries no VC++ runtime. --from takes a helper built before instead (repackaging a
// verified build). Either goes into src-tauri/binaries under the name tauri build looks for there: the helper's name, a dash, the
// target triple (rustc's host: Windows builds pass no --target) and `.exe` on Windows. --copy-to also copies it into a directory under
// the name the installers give it beside the main executable, where the test suite runs it next to a debug build.
//
// The argument goes to stdout and, in a GitHub Actions step, to the step's output `args`. Its JSON reaches tauri whole only because it
// has no backslash and no cmd metacharacter: tauri-action runs pnpm.cmd, that is cmd /d /s /c after cross-spawn's escaping, so the name
// is checked to hold nothing but letters, digits, `-` and `_`.
//
// The helper's name is its crate's package name in the tree being built, --root (default: this script's checkout). A workflow that
// builds an older tag runs this script from its own commit against the tag's tree, where the helper may have had another name: that
// workflow (build-platform.yml) checks out only this script and the modules it imports, and a test keeps its list complete.
import { appendFileSync, copyFileSync, existsSync, mkdirSync, realpathSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { CONSOLE_HELPER_CRATE, REPOSITORY, consoleHelper } from "./identity.mjs";

/** Where tauri build takes bundle.externalBin programs from, relative to the tree's root. */
export const BINARIES = "src-tauri/binaries";

/** The tauri argument that bundles `helper`, refusing a name that could not reach tauri unchanged. */
export function bundleArgument(helper) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(helper)) throw new Error(`the console helper's name ${JSON.stringify(helper)} cannot be passed to tauri`);
  return `--config '${JSON.stringify({ bundle: { externalBin: [`binaries/${helper}`] } })}'`;
}

/** The host triple in `rustc -vV`'s output. */
export function hostTriple(rustcVersion) {
  const triple = /^host: (\S+)$/m.exec(rustcVersion)?.[1];
  if (!triple) throw new Error("rustc -vV names no host");
  return triple;
}

const executableSuffix = triple => (triple.includes("-windows-") ? ".exe" : "");

/** The file name tauri build looks for in src-tauri/binaries for `helper` on `triple`. */
export const bundledName = (helper, triple) => `${helper}-${triple}${executableSuffix(triple)}`;

/** The file name the installers give `helper` on `triple`, beside the main executable. */
export const installedName = (helper, triple) => `${helper}${executableSuffix(triple)}`;

/** Copies the built helper `from` into `root`'s src-tauri/binaries under its bundled name, and returns that path. */
export function place({ root, from, helper, triple }) {
  if (!existsSync(from)) throw new Error(`there is no built console helper at ${from}`);
  const directory = join(root, BINARIES);
  mkdirSync(directory, { recursive: true });
  const destination = join(directory, bundledName(helper, triple));
  copyFileSync(from, destination);
  return destination;
}

/** The executable cargo built for the bin target `name`, from cargo's JSON messages (one per line). */
export function builtExecutable(messages, name) {
  const executables = messages
    .split("\n")
    .filter(line => line.startsWith("{"))
    .map(line => JSON.parse(line))
    .filter(message => message.reason === "compiler-artifact" && message.executable && message.target?.name === name)
    .map(message => message.executable);
  if (executables.length !== 1) throw new Error(`cargo built ${executables.length} executables named ${name}`);
  return executables[0];
}

// Builds the helper of the tree at `root` for `triple`, in an environment based on `env`, and returns the executable's path.
function build(root, helper, triple, env) {
  const buildEnv = { ...env };
  if (triple.endsWith("-windows-msvc")) buildEnv.RUSTFLAGS = "-C target-feature=+crt-static";
  const manifest = join(root, CONSOLE_HELPER_CRATE);
  const messages = execFileSync(
    "cargo",
    ["build", "--release", "--locked", "--manifest-path", manifest, "--message-format=json-render-diagnostics"],
    { cwd: root, env: buildEnv, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], maxBuffer: 64 * 1024 * 1024 },
  );
  return builtExecutable(messages, helper);
}

const rustcHost = () => hostTriple(execFileSync("rustc", ["-vV"], { encoding: "utf8" }));

/**
 * The command, with `argv` as described above; returns the tauri argument. `host` gives the target triple (rustc's host), `env` the
 * environment (GITHUB_OUTPUT and the build's), `log` takes what it says about the files it wrote.
 */
export function main(argv, { host = rustcHost, env = process.env, log = message => console.error(message) } = {}) {
  const options = { root: { type: "string" }, from: { type: "string" }, "copy-to": { type: "string" } };
  const { values } = parseArgs({ args: argv, options });
  const root = resolve(values.root ?? REPOSITORY);
  const helper = consoleHelper(root);
  const argument = bundleArgument(helper);
  const triple = host();
  const from = values.from === undefined ? build(root, helper, triple, env) : resolve(values.from);
  log(`${from} is bundled as ${place({ root, from, helper, triple })}`);
  if (values["copy-to"] !== undefined) {
    const copy = join(resolve(values["copy-to"]), installedName(helper, triple));
    copyFileSync(from, copy);
    log(`${from} is copied to ${copy}`);
  }
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `args=${argument}\n`);
  return argument;
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  try {
    console.log(main(process.argv.slice(2)));
  } catch (error) {
    console.error(`windows-console-helper.mjs: ${error.message}`);
    process.exit(1);
  }
}
