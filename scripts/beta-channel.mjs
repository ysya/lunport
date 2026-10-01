#!/usr/bin/env node
// Beta update channel helpers for CI (spec: docs/superpowers/specs/2026-10-01-update-channels-design.md).
//
//   node scripts/beta-channel.mjs check-version <version>
//     Fails unless <version> is X.Y.Z-N (numeric pre-release: the Windows MSI rule) and newer
//     than the current release in .release-please-manifest.json.
//
//   node scripts/beta-channel.mjs update-manifest <source-tag>
//     Points the Beta channel (the `latest.json` asset on the `updater-beta` prerelease) at the
//     source release, but only when that release is newer than what the channel already offers,
//     so an older stable patch never moves beta users backwards. Creates `updater-beta` on first
//     use. Needs GH_TOKEN (and GH_REPO outside a checkout).
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const CHANNEL_TAG = "updater-beta";
const MANIFEST = "latest.json";
const CHANNEL_NOTES =
  "Maintained by CI: holds the Beta update channel's latest.json (Settings → General → Update channel). Not a release.";

const VERSION_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-(\d+))?$/;

/** Parse `X.Y.Z` or `X.Y.Z-N` (an optional leading `v` is ignored). */
export function parseVersion(text) {
  const match = VERSION_RE.exec(String(text).trim());
  if (!match) throw new Error(`unsupported version "${text}" (expected X.Y.Z or X.Y.Z-N)`);
  const [, major, minor, patch, pre] = match;
  return { major: Number(major), minor: Number(minor), patch: Number(patch), pre: pre === undefined ? null : Number(pre) };
}

/** Sort-style comparison; a release outranks every pre-release of the same X.Y.Z. */
export function compareVersions(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  for (const key of ["major", "minor", "patch"]) {
    if (x[key] !== y[key]) return x[key] - y[key];
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  return x.pre - y.pre;
}

/** Whether the channel should move to `next`; `current` is null when it has no manifest yet. */
export function shouldReplace(current, next) {
  return current === null || compareVersions(next, current) > 0;
}

/** A beta is X.Y.Z-N and newer than the current release (otherwise no one would be offered it). */
export function validateBetaVersion(version, stableVersion) {
  if (parseVersion(version).pre === null) {
    throw new Error(`beta version "${version}" needs a numeric pre-release suffix (X.Y.Z-N, e.g. 0.16.1-1)`);
  }
  if (compareVersions(version, stableVersion) <= 0) {
    throw new Error(`beta version ${version} must be newer than the current release ${stableVersion}`);
  }
}

function gh(args) {
  return execFileSync("gh", args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
}

function manifestVersion(file) {
  const version = JSON.parse(readFileSync(file, "utf8")).version;
  parseVersion(version); // refuse to publish a manifest we could not compare later
  return version;
}

function checkVersion(version) {
  const stable = JSON.parse(readFileSync(".release-please-manifest.json", "utf8"))["."];
  validateBetaVersion(version, stable);
  console.log(`beta ${version} is newer than the current release ${stable}`);
}

function updateManifest(sourceTag) {
  const work = mkdtempSync(join(tmpdir(), "beta-channel-"));
  const sourceDir = join(work, "source");
  gh(["release", "download", sourceTag, "--pattern", MANIFEST, "--dir", sourceDir]);
  const next = manifestVersion(join(sourceDir, MANIFEST));

  const tags = JSON.parse(gh(["release", "list", "--limit", "1000", "--json", "tagName"])).map((r) => r.tagName);
  let current = null;
  if (!tags.includes(CHANNEL_TAG)) {
    const target = process.env.GITHUB_SHA ?? "main";
    gh(["release", "create", CHANNEL_TAG, "--prerelease", "--title", "Beta update channel", "--notes", CHANNEL_NOTES, "--target", target]);
  } else {
    const assets = JSON.parse(gh(["release", "view", CHANNEL_TAG, "--json", "assets"])).assets.map((a) => a.name);
    if (assets.includes(MANIFEST)) {
      const currentDir = join(work, "current");
      gh(["release", "download", CHANNEL_TAG, "--pattern", MANIFEST, "--dir", currentDir]);
      current = manifestVersion(join(currentDir, MANIFEST));
    }
  }

  if (!shouldReplace(current, next)) {
    console.log(`${CHANNEL_TAG} stays on ${current} (${sourceTag} carries ${next}, which is not newer)`);
    return;
  }
  gh(["release", "upload", CHANNEL_TAG, join(sourceDir, MANIFEST), "--clobber"]);
  console.log(`${CHANNEL_TAG} now offers ${next}${current ? ` (was ${current})` : ""}`);
}

function main([command, arg]) {
  if (command === "check-version" && arg) return checkVersion(arg);
  if (command === "update-manifest" && arg) return updateManifest(arg);
  throw new Error("usage: beta-channel.mjs check-version <version> | update-manifest <source-tag>");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`::error::${error.message}`);
    process.exit(1);
  }
}
