import { describe, expect, it } from "vitest";

import { compareVersions, parseVersion, shouldReplace, validateBetaVersion } from "./beta-channel.mjs";

describe("compareVersions", () => {
  it("orders numeric pre-releases below their release and by number", () => {
    expect(compareVersions("0.16.1-1", "0.16.1")).toBeLessThan(0);
    expect(compareVersions("0.16.1", "0.16.1-1")).toBeGreaterThan(0);
    expect(compareVersions("0.16.1-2", "0.16.1-1")).toBeGreaterThan(0);
    expect(compareVersions("0.16.1-10", "0.16.1-9")).toBeGreaterThan(0);
  });

  it("compares each part as a number and ignores a leading v", () => {
    expect(compareVersions("0.16.10", "0.16.9")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0", "0.99.99")).toBeGreaterThan(0);
    expect(compareVersions("v0.16.0", "0.16.0")).toBe(0);
  });

  it("rejects versions the Windows MSI bundle cannot use", () => {
    expect(() => parseVersion("0.16.1-beta.1")).toThrow(/unsupported version/);
    expect(() => parseVersion("0.16")).toThrow(/unsupported version/);
  });
});

describe("shouldReplace", () => {
  it("seeds an empty channel", () => {
    expect(shouldReplace(null, "0.16.0")).toBe(true);
  });

  it("moves forward to a newer beta or release", () => {
    expect(shouldReplace("0.16.0", "0.16.1-1")).toBe(true);
    expect(shouldReplace("0.16.1-1", "0.16.1")).toBe(true);
  });

  it("never moves the channel backwards or rewrites the same version", () => {
    expect(shouldReplace("0.17.0-1", "0.16.2")).toBe(false);
    expect(shouldReplace("0.16.1", "0.16.1")).toBe(false);
  });
});

describe("validateBetaVersion", () => {
  it("accepts X.Y.Z-N newer than the current release", () => {
    expect(() => validateBetaVersion("0.16.1-1", "0.16.0")).not.toThrow();
  });

  it("rejects a non-numeric pre-release before anything is published", () => {
    expect(() => validateBetaVersion("0.16.1-beta.1", "0.16.0")).toThrow(/unsupported version/);
  });

  it("rejects a version without a pre-release suffix", () => {
    expect(() => validateBetaVersion("0.16.1", "0.16.0")).toThrow(/pre-release suffix/);
  });

  it("rejects a beta that is not newer than the current release", () => {
    expect(() => validateBetaVersion("0.16.0-1", "0.16.0")).toThrow(/must be newer/);
    expect(() => validateBetaVersion("0.15.1-1", "0.16.0")).toThrow(/must be newer/);
  });
});
