import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';

const root = process.argv[2];
assert.equal(process.argv[3], 'v1.4.0');
const read = name => JSON.parse(readFileSync(`${root}/${name}`, 'utf8'));
const assets = release => release.assets
  .map(({ id, name, size, digest }) => ({ id, name, size, digest }))
  .sort((a, b) => a.id - b.id);

for (const version of ['1.1.0', '1.2.0', '1.3.0', '1.3.1-1']) {
  const before = read(`baseline-${version}.json`);
  const after = read(`historical-${version}-after.json`);
  assert.equal(before.tag_name, `v${version}`);
  for (const key of ['id', 'tag_name', 'name', 'body', 'draft', 'prerelease', 'published_at']) {
    assert.deepEqual(after[key], before[key], `v${version} ${key} changed`);
  }
  assert.deepEqual(assets(after), assets(before), `v${version} assets changed`);
  assert.deepEqual(read(`historical-${version}-tag-after.json`).object,
    read(`baseline-${version}-tag.json`).object, `v${version} tag changed`);
}

// Reuse all artifact, digest, manifest, signature and tamper checks, including v1.0.0.
await import('../1.1.0-review/verify-publication.mjs');
const receipt = read('verification.json');
receipt.historicalReleasesUnchanged = ['v1.0.0', 'v1.1.0', 'v1.2.0', 'v1.3.0', 'v1.3.1-1'];
writeFileSync(`${root}/verification.json`, `${JSON.stringify(receipt, null, 2)}\n`);
console.log('Historical stable releases and the v1.3.1-1 beta retain their assets and tag targets.');
