import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { setCargoPackageVersion, setJsonVersion } from "./set-app-version.mjs";

const CARGO = `[package]
name = "sshelter"
version = "0.16.0"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }

[dependencies.tauri]
version = "2"
`;

describe("setCargoPackageVersion", () => {
  it("changes only the [package] version", () => {
    const out = setCargoPackageVersion(CARGO, "0.16.1-1");
    expect(out).toContain('[package]\nname = "sshelter"\nversion = "0.16.1-1"\n');
    expect(out).toContain('serde = { version = "1", features = ["derive"] }');
    expect(out).toContain('[dependencies.tauri]\nversion = "2"\n');
  });

  it("fails loudly when there is no [package] version", () => {
    expect(() => setCargoPackageVersion('[dependencies]\nversion = "1"\n', "0.16.1-1")).toThrow(/\[package\] version/);
  });

  it("fails loudly when the [package] version is not a double-quoted string", () => {
    const toml = `[package]\nname = "x"\nversion = '0.1.0'\n`;
    expect(() => setCargoPackageVersion(toml, "0.16.1-1")).toThrow(/not a double-quoted string/);
  });

  it("writes the version literally, even when it contains replacement patterns", () => {
    const out = setCargoPackageVersion(CARGO, "1.0.0-$&");
    expect(out).toContain('[package]\nname = "sshelter"\nversion = "1.0.0-$&"\n');
  });

  it("accepts stamping the version that is already there", () => {
    expect(setCargoPackageVersion(CARGO, "0.16.0")).toBe(CARGO);
  });
});

describe("setJsonVersion", () => {
  it("replaces the top-level version and keeps the other keys", () => {
    const out = JSON.parse(setJsonVersion('{"name":"sshelter","version":"0.16.0","private":true}', "0.16.1-1"));
    expect(out).toEqual({ name: "sshelter", version: "0.16.1-1", private: true });
  });

  it("fails loudly when there is no top-level version", () => {
    expect(() => setJsonVersion('{"name":"sshelter"}', "0.16.1-1")).toThrow(/version/);
  });
});

// `main` is not exported: the version check and the `::error::` output are only reachable by running the CLI.
describe("CLI", () => {
  const script = fileURLToPath(new URL("./set-app-version.mjs", import.meta.url));
  const dirs = [];

  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  function workspace() {
    const dir = mkdtempSync(join(tmpdir(), "set-app-version-"));
    dirs.push(dir);
    mkdirSync(join(dir, "src-tauri"));
    writeFileSync(join(dir, "package.json"), '{"name":"sshelter","version":"0.16.0"}\n');
    writeFileSync(join(dir, "src-tauri", "tauri.conf.json"), '{"productName":"SSHelter","version":"0.16.0"}\n');
    writeFileSync(join(dir, "src-tauri", "Cargo.toml"), CARGO);
    return dir;
  }

  const run = (cwd, ...args) => spawnSync(process.execPath, [script, ...args], { cwd, encoding: "utf8" });

  it("stamps the version into all three files", () => {
    const dir = workspace();
    const result = run(dir, "0.16.1-1");
    expect(result.status).toBe(0);
    expect(JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version).toBe("0.16.1-1");
    expect(JSON.parse(readFileSync(join(dir, "src-tauri", "tauri.conf.json"), "utf8")).version).toBe("0.16.1-1");
    expect(readFileSync(join(dir, "src-tauri", "Cargo.toml"), "utf8")).toContain('[package]\nname = "sshelter"\nversion = "0.16.1-1"\n');
  });

  it("rejects anything but X.Y.Z-N before touching a file", () => {
    for (const bad of ["0.16.1-01", "0.16.01-1", "0.16.1", "v0.16.1-1", "0.16.1-beta.1"]) {
      const dir = workspace();
      const result = run(dir, bad);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`::error::invalid version "${bad}" (expected X.Y.Z-N)`);
      expect(readFileSync(join(dir, "package.json"), "utf8")).toContain('"version":"0.16.0"');
      expect(readFileSync(join(dir, "src-tauri", "tauri.conf.json"), "utf8")).toContain('"version":"0.16.0"');
      expect(readFileSync(join(dir, "src-tauri", "Cargo.toml"), "utf8")).toBe(CARGO);
    }
  });

  it("asks for a version when none is given", () => {
    const result = run(workspace());
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("::error::usage: set-app-version.mjs <version>");
  });
});
