import { describe, expect, it } from "vitest";

import {
  BETA_VERSION_RE,
  canonicalJson,
  compareVersions,
  inspectChannelRelease,
  parseVersion,
  shouldReplace,
  skipMessage,
  validateBetaVersion,
  validateManifest,
  workflowCommandMessage,
} from "./beta-channel.mjs";

/** A parsed latest.json for `version`; `signature` stands in for what a rebuild replaces. */
function latestJson(version, signature = "sig") {
  const entry = (platform) => ({ signature, url: `https://example.test/${version}/${platform}` });
  return {
    version,
    pub_date: "2026-10-01T00:00:00Z",
    platforms: {
      "linux-x86_64": entry("linux-x86_64"),
      "linux-aarch64": entry("linux-aarch64"),
      "windows-x86_64": entry("windows-x86_64"),
      "darwin-universal": entry("darwin-universal"),
    },
  };
}

/** What `shouldReplace` takes for one side: the version and its parsed manifest. */
function offer(version, signature) {
  return { version, manifest: latestJson(version, signature) };
}

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

describe("canonicalJson", () => {
  it("sorts object keys at every depth and keeps array order", () => {
    expect(canonicalJson({ b: 1, a: { d: [{ z: 1, y: 2 }, 3], c: null } })).toBe('{"a":{"c":null,"d":[{"y":2,"z":1},3]},"b":1}');
  });
});

describe("shouldReplace", () => {
  it("seeds an empty channel", () => {
    expect(shouldReplace(null, offer("0.16.0"))).toBe(true);
  });

  it("moves forward to a newer beta or release", () => {
    expect(shouldReplace(offer("0.16.0"), offer("0.16.1-1"))).toBe(true);
    expect(shouldReplace(offer("0.16.1-1"), offer("0.16.1"))).toBe(true);
  });

  it("never moves the channel backwards, whatever the older manifest holds", () => {
    expect(shouldReplace(offer("0.17.0-1"), offer("0.16.2"))).toBe(false);
    expect(shouldReplace(offer("0.16.1", "new"), offer("0.16.0", "old"))).toBe(false);
  });

  it("does not rewrite an identical manifest", () => {
    expect(shouldReplace(offer("0.16.1"), offer("0.16.1"))).toBe(false);
  });

  it("compares manifests by content, not by key order or formatting", () => {
    const compact = JSON.parse('{"version":"0.16.1","platforms":{"linux-x86_64":{"url":"u","signature":"s"}}}');
    const pretty = JSON.parse(`{
      "platforms": { "linux-x86_64": { "signature": "s", "url": "u" } },
      "version": "0.16.1"
    }`);
    expect(shouldReplace({ version: "0.16.1", manifest: compact }, { version: "0.16.1", manifest: pretty })).toBe(false);
  });

  it("refreshes an equal version whose signature changed", () => {
    // A rebuilt or republished release carries new signatures; the channel's old copy would fail them.
    expect(shouldReplace(offer("0.16.1", "old"), offer("0.16.1", "new"))).toBe(true);
  });
});

describe("validateManifest", () => {
  it("accepts a complete manifest for the tag", () => {
    expect(() => validateManifest(latestJson("0.16.0"), "v0.16.0")).not.toThrow();
    expect(() => validateManifest(latestJson("0.16.1-1"), "v0.16.1-1")).not.toThrow();
    expect(() => validateManifest(latestJson("0.16.0"), "0.16.0")).not.toThrow();
  });

  it("matches platforms by prefix, so installer-specific keys are fine", () => {
    const withExtras = latestJson("0.16.0");
    withExtras.platforms["windows-x86_64-nsis"] = withExtras.platforms["windows-x86_64"];
    withExtras.platforms["darwin-aarch64-app"] = withExtras.platforms["darwin-universal"];
    expect(() => validateManifest(withExtras, "v0.16.0")).not.toThrow();

    const entry = { signature: "s", url: "u" };
    const onlySpecific = {
      version: "0.16.0",
      platforms: { "linux-x86_64-appimage": entry, "linux-aarch64-deb": entry, "windows-x86_64-nsis": entry, "darwin-aarch64-app": entry },
    };
    expect(() => validateManifest(onlySpecific, "v0.16.0")).not.toThrow();
  });

  it("rejects a manifest that carries another version than the tag", () => {
    expect(() => validateManifest(latestJson("0.16.1"), "v0.16.0")).toThrow(/says version "0\.16\.1", expected 0\.16\.0/);
    expect(() => validateManifest(latestJson("0.16.0"), "v0.16.0-1")).toThrow(/expected 0\.16\.0-1/);
    expect(() => validateManifest({ ...latestJson("0.16.0"), version: "v0.16.0" }, "v0.16.0")).toThrow(/expected 0\.16\.0/);
    expect(() => validateManifest({ platforms: latestJson("0.16.0").platforms }, "v0.16.0")).toThrow(/expected 0\.16\.0/);
  });

  it.each(["linux-x86_64", "linux-aarch64", "windows-x86_64", "darwin-"])("rejects a manifest with no %s entry", (prefix) => {
    const manifest = latestJson("0.16.0");
    for (const key of Object.keys(manifest.platforms)) {
      if (key.startsWith(prefix)) delete manifest.platforms[key];
    }
    expect(() => validateManifest(manifest, "v0.16.0")).toThrow(`no entry for ${prefix} (`);
  });

  it("does not count a key that only contains a platform name", () => {
    const manifest = latestJson("0.16.0");
    manifest.platforms["x-darwin-universal"] = manifest.platforms["darwin-universal"];
    delete manifest.platforms["darwin-universal"];
    expect(() => validateManifest(manifest, "v0.16.0")).toThrow(/no entry for darwin-/);
  });

  it("names every missing platform at once, and copes with a manifest without any", () => {
    expect(() => validateManifest({ version: "0.16.0" }, "v0.16.0")).toThrow(
      "no entry for linux-x86_64, linux-aarch64, windows-x86_64, darwin- (it lists: nothing)",
    );
  });
});

describe("inspectChannelRelease", () => {
  it("reports whether the prerelease already holds the manifest", () => {
    expect(inspectChannelRelease({ isPrerelease: true, assets: [{ name: "latest.json" }] })).toEqual({ hasManifest: true });
    expect(inspectChannelRelease({ isPrerelease: true, assets: [] })).toEqual({ hasManifest: false });
    expect(inspectChannelRelease({ isPrerelease: true, assets: [{ name: "notes.txt" }] })).toEqual({ hasManifest: false });
  });

  it("refuses a channel release that is not a prerelease", () => {
    // A full release can become releases/latest, which is where Stable users read their manifest.
    expect(() => inspectChannelRelease({ isPrerelease: false, assets: [{ name: "latest.json" }] })).toThrow(
      "updater-beta must stay a prerelease (otherwise releases/latest could serve the Beta manifest to Stable users)",
    );
  });

  it("refuses when gh does not say it is a prerelease", () => {
    expect(() => inspectChannelRelease({ assets: [] })).toThrow(/must stay a prerelease/);
  });
});

describe("skipMessage", () => {
  it("warns when the channel is newer than the source, so the skip shows in the run summary", () => {
    const line = skipMessage(offer("0.17.0-1"), offer("0.16.2"), "v0.16.2");
    expect(line.startsWith("::warning::")).toBe(true);
    expect(line).toContain("updater-beta stays on 0.17.0-1");
    expect(line).toContain("v0.16.2 carries 0.16.2");
  });

  it("only logs when the channel already has the same manifest, which is a plain re-run", () => {
    const line = skipMessage(offer("0.16.1"), offer("0.16.1"), "v0.16.1");
    expect(line.startsWith("::")).toBe(false);
    expect(line).toContain("already offers 0.16.1");
  });

  it("escapes the warning like any workflow command", () => {
    const line = skipMessage(offer("0.17.0-1"), offer("0.16.2"), "v0.16.2\n::error::100%");
    expect(line).not.toMatch(/[\r\n]/);
    expect(line).toContain("v0.16.2%0A::error::100%25 carries");
  });
});

describe("BETA_VERSION_RE", () => {
  it("matches exactly X.Y.Z-N: digits only, no leading zeros", () => {
    for (const ok of ["0.16.1-1", "0.0.0-0", "10.20.30-40"]) expect(BETA_VERSION_RE.test(ok)).toBe(true);
    for (const bad of ["0.16.1-01", "0.16.01-1", "00.16.1-1", "v0.16.1-1", " 0.16.1-1", "0.16.1-1\n", "0.16.1", "0.16.1-1-2", "0.16.1-beta.1"]) {
      expect(BETA_VERSION_RE.test(bad)).toBe(false);
    }
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

  it("rejects a version with a v prefix", () => {
    expect(() => validateBetaVersion("v0.16.1-1", "0.16.0")).toThrow(/unsupported beta version/);
  });

  it("rejects a version with whitespace", () => {
    expect(() => validateBetaVersion(" 0.16.1-1", "0.16.0")).toThrow(/unsupported beta version/);
  });

  it("rejects leading zeros, which cargo refuses only after the prerelease and tag exist", () => {
    expect(() => validateBetaVersion("0.16.1-01", "0.16.0")).toThrow(/unsupported beta version/);
    expect(() => validateBetaVersion("0.16.01-1", "0.16.0")).toThrow(/unsupported beta version/);
  });

  it("rejects versions the Windows MSI bundle cannot represent, before anything is published", () => {
    expect(() => validateBetaVersion("0.16.1-65536", "0.16.0")).toThrow(/Windows MSI limits/);
    expect(() => validateBetaVersion("256.0.0-1", "0.16.0")).toThrow(/Windows MSI limits/);
    expect(() => validateBetaVersion("0.256.0-1", "0.16.0")).toThrow(/Windows MSI limits/);
    expect(() => validateBetaVersion("0.16.65536-1", "0.16.0")).toThrow(/Windows MSI limits/);
  });

  it("accepts versions right at the Windows MSI limits", () => {
    expect(() => validateBetaVersion("0.16.1-65535", "0.16.0")).not.toThrow();
    expect(() => validateBetaVersion("255.255.65535-65535", "0.16.0")).not.toThrow();
  });
});

describe("workflowCommandMessage", () => {
  it("escapes special characters for GitHub Actions workflow commands", () => {
    expect(workflowCommandMessage("a%b\r\n::warning::x")).toBe("a%25b%0D%0A::warning::x");
  });
});
