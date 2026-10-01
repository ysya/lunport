import { describe, expect, it } from "vitest";

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
