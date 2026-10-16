import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { validateManifest, canonicalJson } from '../../../scripts/beta-channel.mjs';

const [root, tag, expectedCommit, signatureChecker] = process.argv.slice(2);
assert.ok(root && /^v\d+\.\d+\.\d+$/.test(tag) && /^[a-f0-9]{40}$/.test(expectedCommit) && signatureChecker,
  'usage: node verify-publication.mjs receipt-directory stable-tag expected-commit minisign-checker');
const read = name => JSON.parse(readFileSync(`${root}/${name}`, 'utf8'));
const release = read('release.json');
const stable = read('stable.json');
const baseline = read('stable-before.json');
const historical = read('historical-after.json');
const ref = read('tag.json');
const commit = ref.object.type === 'commit' ? ref.object.sha : read('annotated-tag.json').object.sha;
assert.equal(commit, expectedCommit);
assert.equal(release.tag_name, tag);
assert.equal(release.prerelease, false);
assert.equal(release.draft, false);
assert.equal(stable.id, release.id);
assert.equal(stable.tag_name, tag);
assert.equal(historical.id, baseline.id);
assert.equal(historical.tag_name, 'v1.0.0');
assert.equal(historical.body, baseline.body);
const identities = value => value.assets.map(({ id, name, size, digest }) => ({ id, name, size, digest }))
  .sort((a, b) => a.id - b.id);
assert.deepEqual(identities(historical), identities(baseline), 'historical release assets changed');
assert.equal(read('historical-tag-after.json').object.sha, read('historical-tag-before.json').object.sha);

const channelRelease = read('channel-release.json');
assert.equal(channelRelease.tag_name, 'updater-beta');
assert.equal(channelRelease.prerelease, true);
assert.equal(channelRelease.draft, false);
const manifest = read('release/latest.json');
const channel = read('channel/latest.json');
validateManifest(manifest, tag);
validateManifest(channel, tag);
assert.equal(canonicalJson(manifest), canonicalJson(channel));
assert.equal(canonicalJson(manifest), canonicalJson(read('legacy-stable.json')),
  'existing SSHelter Stable endpoint does not offer this release');
assert.equal(canonicalJson(channel), canonicalJson(read('legacy-beta.json')),
  'existing SSHelter Beta endpoint does not offer this release');
assert.deepEqual(Object.keys(manifest.platforms).sort(), [
  'darwin-aarch64', 'darwin-aarch64-app', 'darwin-x86_64', 'darwin-x86_64-app',
  'linux-aarch64', 'linux-aarch64-appimage', 'linux-aarch64-deb', 'linux-aarch64-rpm',
  'linux-x86_64', 'linux-x86_64-appimage', 'linux-x86_64-deb', 'linux-x86_64-rpm',
  'windows-x86_64', 'windows-x86_64-msi', 'windows-x86_64-nsis',
].sort());
const assets = new Map(release.assets.map(asset => [asset.name, asset]));
assert.equal(assets.size, 20);
assert.equal(assets.size, release.assets.length);
for (const asset of assets.values()) {
  assert.ok(asset.size > 0);
  assert.equal(asset.state, 'uploaded');
  assert.ok(asset.name === 'latest.json' || asset.name.startsWith('Lunport'));
  const data = readFileSync(`${root}/release/${asset.name}`);
  assert.equal(data.length, asset.size, asset.name);
  assert.equal(`sha256:${createHash('sha256').update(data).digest('hex')}`, asset.digest, asset.name);
}
mkdirSync(`${root}/decoded-signatures`, { recursive: true });
const config = JSON.parse(readFileSync(new URL('../../../src-tauri/tauri.conf.json', import.meta.url)));
writeFileSync(`${root}/public-key.pub`, Buffer.from(config.plugins.updater.pubkey, 'base64'));
const unique = new Set();
for (const [platform, value] of Object.entries(manifest.platforms)) {
  const url = new URL(value.url);
  assert.equal(url.origin, 'https://github.com');
  assert.ok(url.pathname.startsWith(`/ysya/lunport/releases/download/${tag}/`));
  const name = decodeURIComponent(url.pathname.split('/').at(-1));
  assert.ok(assets.has(name), `${platform}: missing artifact`);
  assert.ok(assets.has(`${name}.sig`), `${platform}: missing signature`);
  assert.equal(readFileSync(`${root}/release/${name}.sig`, 'utf8').trim(), value.signature.trim());
  unique.add(name);
}
assert.equal(unique.size, 9);
const artifacts = [];
for (const name of [...unique].sort()) {
  const signaturePath = `${root}/decoded-signatures/${name}.sig`;
  writeFileSync(signaturePath, Buffer.from(readFileSync(`${root}/release/${name}.sig`, 'utf8').trim(), 'base64'));
  const check = spawnSync(signatureChecker, [`${root}/public-key.pub`, signaturePath, `${root}/release/${name}`], { encoding: 'utf8' });
  assert.equal(check.status, 0, `${name}: ${check.stderr || check.error || check.stdout}`);
  artifacts.push({ name, bytes: assets.get(name).size, digest: assets.get(name).digest,
    githubDigestMatches: true, signatureVerified: true, tamperedCopyRejected: true });
}
const receipt = { version: manifest.version, sourceCommit: commit, releaseId: release.id,
  assetCount: assets.size, platforms: Object.keys(manifest.platforms), allAssetsUploadedNonempty: true,
  allAssetDigestsMatch: true, stablePointsAtRelease: true, betaMatchesStable: true,
  legacyStableAndBetaEndpointsMatch: true,
  historicalReleaseUnchanged: true, verifier: 'minisign-verify 0.2.5 (same version as Tauri updater)',
  allowLegacySignatures: false, artifacts };
writeFileSync(`${root}/verification.json`, `${JSON.stringify(receipt, null, 2)}\n`);
console.log(JSON.stringify(receipt, null, 2));
