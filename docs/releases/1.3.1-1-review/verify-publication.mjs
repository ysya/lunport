import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { canonicalJson, validateManifest } from '../../../scripts/beta-channel.mjs';

const [root, tag, expectedCommit, signatureChecker] = process.argv.slice(2);
assert.ok(root && /^v\d+\.\d+\.\d+-\d+$/.test(tag)
  && /^[a-f0-9]{40}$/.test(expectedCommit) && signatureChecker,
  'usage: node verify-publication.mjs receipts beta-tag source-commit minisign-checker');
const read = name => JSON.parse(readFileSync(`${root}/${name}`, 'utf8'));
const release = read('release.json');
const stable = read('stable-after.json');
const before = read('stable-before.json');
const ref = read('tag.json');
const commit = ref.object.type === 'commit' ? ref.object.sha : read('annotated-tag.json').object.sha;
assert.equal(commit, expectedCommit);
assert.equal(release.tag_name, tag);
assert.equal(release.prerelease, true);
assert.equal(release.draft, false);
assert.equal(stable.id, before.id);
assert.equal(stable.tag_name, 'v1.3.0');
assert.equal(stable.prerelease, false);
const identities = value => value.assets
  .map(({ id, name, size, digest }) => ({ id, name, size, digest }))
  .sort((a, b) => a.id - b.id);
for (const version of ['1.0.0', '1.1.0', '1.2.0', '1.3.0']) {
  const baseline = read(`baseline-${version}.json`);
  const historical = read(`historical-${version}-after.json`);
  assert.equal(baseline.tag_name, `v${version}`);
  for (const key of ['id', 'tag_name', 'name', 'body', 'draft', 'prerelease', 'published_at']) {
    assert.deepEqual(historical[key], baseline[key], `v${version} ${key} changed`);
  }
  assert.deepEqual(identities(historical), identities(baseline), `v${version} assets changed`);
  assert.deepEqual(read(`historical-${version}-tag-after.json`).object,
    read(`baseline-${version}-tag.json`).object, `v${version} tag changed`);
}

for (const name of ['workflow.json', 'engine-ci.json']) {
  const run = read(name);
  assert.equal(run.headSha, expectedCommit, name);
  assert.equal(run.status, 'completed', name);
  assert.equal(run.conclusion, 'success', name);
  assert.ok(run.jobs.every(job => job.conclusion === 'success'), name);
}
const channelRelease = read('channel-release.json');
assert.equal(channelRelease.tag_name, 'updater-beta');
assert.equal(channelRelease.prerelease, true);
assert.equal(channelRelease.draft, false);
const manifest = read('release/latest.json');
validateManifest(manifest, tag);
for (const name of ['channel/latest.json', 'beta-manifest.json', 'legacy-beta.json']) {
  assert.equal(canonicalJson(manifest), canonicalJson(read(name)), name);
}
const stableManifest = read('stable-manifest-after.json');
assert.equal(stableManifest.version, '1.3.0');
assert.equal(canonicalJson(stableManifest), canonicalJson(read('stable-manifest-before.json')));
assert.equal(canonicalJson(stableManifest), canonicalJson(read('legacy-stable.json')));
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
  const check = spawnSync(signatureChecker,
    [`${root}/public-key.pub`, signaturePath, `${root}/release/${name}`], { encoding: 'utf8' });
  assert.equal(check.status, 0, `${name}: ${check.stderr || check.error || check.stdout}`);
  artifacts.push({ name, bytes: assets.get(name).size, digest: assets.get(name).digest,
    githubDigestMatches: true, signatureVerified: true, tamperedCopyRejected: true });
}
const receipt = { version: manifest.version, sourceCommit: commit, releaseId: release.id,
  prerelease: true, assetCount: assets.size, platforms: Object.keys(manifest.platforms),
  allAssetsUploadedNonempty: true, allAssetDigestsMatch: true, betaMatchesRelease: true,
  stableUnchanged: true, stableVersion: '1.3.0', legacyEndpointsMatchTheirChannels: true,
  historicalReleasesUnchanged: ['v1.0.0', 'v1.1.0', 'v1.2.0', 'v1.3.0'],
  verifier: 'minisign-verify 0.2.5 (same version as Tauri updater)', allowLegacySignatures: false,
  artifacts };
writeFileSync(`${root}/verification.json`, `${JSON.stringify(receipt, null, 2)}\n`);
console.log(JSON.stringify(receipt, null, 2));
